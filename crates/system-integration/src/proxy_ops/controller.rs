//! 接管/释放状态机：marker 生命周期 + 防自指 + 失败兜底回滚 + 崩溃恢复。
//!
//! `enable`/`disable`/`recover_from_marker`/`ensure_cleared` 与 `points_to_us` 是同一个
//! marker 事务的 owner（设计文档 T1），整体留在本模块，不拆。

use super::model::ProxyEnableRequest;
use super::ops::{ProxySnapshotRelation, SystemProxyOps};
use crate::error::SystemIntegrationError;
use crate::proxy::{
    MarkerFs, ProxyMarker, ProxyMarkerBeginOutcome, ProxyMarkerData, ProxyMarkerMutationOutcome,
    ProxyMarkerPhase, ProxyMarkerRead, ProxyMarkerReplaceOutcome, ProxyOriginalSettings,
    ProxyTransactionSnapshot, SystemProxyStatus,
};
use std::time::Instant;

// ── 接管/释放状态机（marker + 防自指 + 失败兜底 + 崩溃恢复）──

/// 系统代理控制器：编排 enable/disable + marker 生命周期。
/// 1:1 移植 上游 `SystemProxyBase` + 三平台 enable/disable 的 marker 编排逻辑。
pub struct SystemProxyController<Ops: SystemProxyOps, Fs: MarkerFs> {
    pub(super) ops: Ops,
    pub(super) marker: ProxyMarker<Fs>,
    /// enable 前保存的原始代理快照（disable 恢复用）。
    original: Option<ProxyOriginalSettings>,
}

impl<Ops: SystemProxyOps, Fs: MarkerFs> SystemProxyController<Ops, Fs> {
    pub fn new(ops: Ops, marker: ProxyMarker<Fs>) -> Self {
        Self {
            ops,
            marker,
            original: None,
        }
    }

    /// 当前保存的原始代理快照（测试 / 诊断用）。
    pub fn original_snapshot(&self) -> Option<&SystemProxyStatus> {
        self.original
            .as_ref()
            .and_then(|snapshot| snapshot.fallback.as_ref())
    }

    /// 完整快照（macOS 原生事务测试/诊断用）。
    pub fn complete_original_snapshot(&self) -> Option<&ProxyOriginalSettings> {
        self.original.as_ref()
    }

    /// 启用系统代理（接管）。exact-capable 平台使用 V2 marker + whole-marker CAS；没有
    /// exact capability 的部署继续走 legacy 命令路径，但只允许从 Missing marker 开始。
    pub fn enable(&mut self, req: &ProxyEnableRequest) -> Result<(), SystemIntegrationError> {
        let marker = self.marker.read_checked();
        if self.ops.exact_transaction_available()? {
            self.enable_exact(req, marker)
        } else {
            self.enable_legacy(req, marker)
        }
    }

    fn enable_exact(
        &mut self,
        req: &ProxyEnableRequest,
        marker: ProxyMarkerRead,
    ) -> Result<(), SystemIntegrationError> {
        let (original, apply_base, applied, transaction) = match marker {
            ProxyMarkerRead::Missing => {
                let current = self.ops.capture_transaction_snapshot()?;
                let applied = self.ops.build_applied_snapshot(req, &current)?;
                let begun =
                    self.marker
                        .begin_if_absent(&req.our_host_port(), &current, &current, &applied);
                let ProxyMarkerBeginOutcome::Begun(transaction) = begun else {
                    return Err(SystemIntegrationError::proxy(match begun {
                        ProxyMarkerBeginOutcome::Occupied(_) => {
                            "系统代理 marker 在接管前已被并发事务占用"
                        }
                        ProxyMarkerBeginOutcome::PersistFailed => {
                            "持久化系统代理 V2 恢复 marker 失败，已在修改系统前终止"
                        }
                        ProxyMarkerBeginOutcome::Begun(_) => unreachable!(),
                    }));
                };
                (current.clone(), current, applied, transaction)
            }
            ProxyMarkerRead::CurrentValidated(previous)
                if previous.phase == ProxyMarkerPhase::Owned =>
            {
                let Some(old_txn_id) = previous.txn_id.as_deref() else {
                    return Err(SystemIntegrationError::proxy(
                        "系统代理 V2 marker 缺少事务身份",
                    ));
                };
                let (Some(original), Some(old_apply_base), Some(old_applied)) = (
                    previous.exact_original.as_ref(),
                    previous.exact_apply_base.as_ref(),
                    previous.exact_applied.as_ref(),
                ) else {
                    return Err(SystemIntegrationError::proxy(
                        "系统代理 V2 marker 缺少 exact 快照",
                    ));
                };
                let current = self.ops.capture_transaction_snapshot()?;
                if self
                    .ops
                    .snapshot_relation(old_apply_base, old_applied, &current)
                    != ProxySnapshotRelation::Exact
                {
                    return Err(SystemIntegrationError::proxy(
                        "系统代理当前状态不再精确匹配 Owned marker，拒绝覆盖",
                    ));
                }
                let applied = self.ops.build_applied_snapshot(req, &current)?;
                let replaced = self.marker.replace_if_current(
                    old_txn_id,
                    &req.our_host_port(),
                    &current,
                    &applied,
                );
                let ProxyMarkerReplaceOutcome::Replaced(transaction) = replaced else {
                    return Err(SystemIntegrationError::proxy(match replaced {
                        ProxyMarkerReplaceOutcome::Mismatch => {
                            "系统代理 marker 在重接管前已变化，拒绝陈旧写入"
                        }
                        ProxyMarkerReplaceOutcome::PersistFailed => {
                            "持久化系统代理重接管 marker 失败，已在修改系统前终止"
                        }
                        ProxyMarkerReplaceOutcome::Replaced(_) => unreachable!(),
                    }));
                };
                (original.clone(), current, applied, *transaction)
            }
            ProxyMarkerRead::CurrentValidated(_) => {
                return Err(SystemIntegrationError::proxy(
                    "系统代理 V2 marker 尚未处于 Owned，拒绝开启新写入",
                ));
            }
            other => {
                return Err(SystemIntegrationError::proxy(format!(
                    "系统代理 marker 不允许开启 V2 接管：{other:?}"
                )));
            }
        };

        self.original = original.original_settings();
        let txn_id = transaction
            .txn_id
            .as_deref()
            .expect("validated V2 marker always has txn_id");
        if let Err(apply_error) = self.ops.apply_transaction(req, &apply_base) {
            self.rollback_failed_exact_apply(txn_id, &apply_base, &applied);
            return Err(apply_error);
        }

        match self.marker.update_current_phase(
            txn_id,
            ProxyMarkerPhase::Applying,
            ProxyMarkerPhase::Owned,
        ) {
            ProxyMarkerMutationOutcome::Updated => Ok(()),
            ProxyMarkerMutationOutcome::Mismatch => Err(SystemIntegrationError::proxy(
                "系统代理已应用，但 marker 阶段 CAS 已失效；保留现有 marker 供恢复",
            )),
            ProxyMarkerMutationOutcome::PersistFailed => Err(SystemIntegrationError::proxy(
                "系统代理已应用，但持久化 Owned 阶段失败；保留 Applying marker 供恢复",
            )),
        }
    }

    fn rollback_failed_exact_apply(
        &self,
        txn_id: &str,
        apply_base: &ProxyTransactionSnapshot,
        applied: &ProxyTransactionSnapshot,
    ) {
        if !matches!(
            self.marker.read_checked(),
            ProxyMarkerRead::CurrentValidated(ref marker)
                if marker.txn_id.as_deref() == Some(txn_id)
                    && marker.phase == ProxyMarkerPhase::Applying
        ) {
            log::warn!("系统代理接管失败后 marker 已变化，拒绝陈旧回滚");
            return;
        }
        let current = match self.ops.capture_transaction_snapshot() {
            Ok(current) => current,
            Err(error) => {
                log::warn!("系统代理接管失败后无法捕获当前状态，保留 Applying marker：{error}");
                return;
            }
        };
        match self.ops.snapshot_relation(apply_base, applied, &current) {
            ProxySnapshotRelation::Exact | ProxySnapshotRelation::Prefix => {
                if let Err(error) = self.ops.restore_transaction(apply_base, &current) {
                    log::warn!(
                        "系统代理接管失败后的 exact 回滚也失败，保留 Applying marker：{error}"
                    );
                }
            }
            // 没有 mutation 成员落地；保留 Applying marker，让统一恢复状态机按 fresh apply 与
            // System→System replacement 的不同 original/apply_base 语义收口。
            ProxySnapshotRelation::Unchanged => {}
            ProxySnapshotRelation::Foreign => {
                log::warn!("系统代理接管失败后检测到外部改动，拒绝回滚并保留 Applying marker");
            }
        }
    }

    fn enable_legacy(
        &mut self,
        req: &ProxyEnableRequest,
        marker: ProxyMarkerRead,
    ) -> Result<(), SystemIntegrationError> {
        if marker != ProxyMarkerRead::Missing {
            return Err(SystemIntegrationError::proxy(format!(
                "系统代理 marker 已存在或不可严格读取，legacy 接管拒绝覆盖：{marker:?}"
            )));
        }
        let total_started = Instant::now();
        let marker_read_ms = 0;

        // 1. 保存原始（防自指）。macOS 生产路径以稳定 service ID 捕获所有
        // 已启用网络服务的完整 Proxies property-list；Win/Linux 与跨平台模拟仍复用
        // `capture_original_status` 投影。二者的分工见 trait 方法文档。
        let capture_started = Instant::now();
        match self.ops.capture_original_settings() {
            Ok(snapshot) => {
                let snapshot =
                    snapshot.strip_self(&req.address, req.http_port, req.socks_port, None, None);
                self.original = (!snapshot.is_empty()).then_some(snapshot);
            }
            Err(error) => {
                // macOS 原生逐服务写必须可逆：快照失败时还没有修改系统，立即失败，
                // 绝不写入一份无法原样恢复的配置。
                if self.ops.requires_original_snapshot() {
                    log::info!(
                        "系统代理接管分段耗时：marker读取={marker_read_ms}ms，原值捕获失败于{}ms，\
                         端到端={}ms",
                        capture_started.elapsed().as_millis(),
                        total_started.elapsed().as_millis()
                    );
                    return Err(error);
                }
                // 其他平台保持既有兼容语义：无原始快照仍接管，释放时只关闭。
                log::warn!("捕获系统代理原始配置失败，将在释放时只关闭 Polaris 代理：{error}");
            }
        }
        let capture_ms = capture_started.elapsed().as_millis();

        // 2. marker 必须早于系统修改。锁竞争、IO 或持久化失败都必须在任何 OS 写前终止；
        // 无 marker 的接管无法在崩溃后安全恢复，不能再沿用历史 best-effort 写入。
        let marker_write_started = Instant::now();
        match self
            .marker
            .begin_legacy_if_absent(&req.our_host_port(), self.original.as_ref())
        {
            ProxyMarkerBeginOutcome::Begun(_) => {}
            ProxyMarkerBeginOutcome::Occupied(_) => {
                self.original = None;
                return Err(SystemIntegrationError::proxy(
                    "系统代理 marker 在 legacy 接管前已被并发事务占用",
                ));
            }
            ProxyMarkerBeginOutcome::PersistFailed => {
                self.original = None;
                let marker_write_ms = marker_write_started.elapsed().as_millis();
                log::info!(
                    "系统代理接管分段耗时：marker读取={marker_read_ms}ms，原值捕获={capture_ms}ms，\
                     marker写入失败于{marker_write_ms}ms，端到端={}ms",
                    total_started.elapsed().as_millis()
                );
                return Err(SystemIntegrationError::proxy(
                    "持久化系统代理恢复 marker 失败，已在修改系统前终止",
                ));
            }
        }
        let marker_write_ms = marker_write_started.elapsed().as_millis();

        // 3. 设代理。
        let set_started = Instant::now();
        let set_result = self
            .ops
            .set_proxy_from_snapshot(req, self.original.as_ref());
        let set_ms = set_started.elapsed().as_millis();
        if let Err(e) = set_result {
            // 4. 失败兜底（fail-closed）：经 disable 统一收口。
            if let Err(rollback_error) = self.disable() {
                // rollback 也失败时保留 marker + 完整快照；删掉它会让下一次启动失去唯一恢复依据。
                log::warn!("系统代理接管失败后的回滚也失败，保留 marker 供重试：{rollback_error}");
            }
            log::info!(
                "系统代理接管分段耗时：marker读取={marker_read_ms}ms，原值捕获={capture_ms}ms，\
                 marker写入={marker_write_ms}ms，系统写入失败于{set_ms}ms，端到端={}ms",
                total_started.elapsed().as_millis()
            );
            return Err(e);
        }

        log::info!(
            "系统代理接管分段耗时：marker读取={marker_read_ms}ms，原值捕获={capture_ms}ms，\
             marker写入={marker_write_ms}ms，系统写入={set_ms}ms，端到端={}ms",
            total_started.elapsed().as_millis()
        );
        Ok(())
    }

    /// 禁用系统代理（释放）。所有释放入口都复用严格 marker 状态机；Missing 是幂等 no-op。
    pub fn disable(&mut self) -> Result<(), SystemIntegrationError> {
        let mut restored_os = false;
        self.reconcile_marker(&mut restored_os).map(|_| ())
    }

    /// **维度7 #8：marker 崩溃恢复**。
    /// 启动时调用：读 marker，若存在（上次崩溃/强杀残留）→ 清除残留代理（防死端口断网）→ 清 marker。
    /// 返回 `Ok(Some(marker))` 表示恢复成功，`Ok(None)` 表示无残留；恢复失败显式返回错误并保留 marker。
    ///
    /// Polaris 启动恢复路径（marker 残留 → disableProxy 清理）。本方法是 #8 的可测入口。
    pub fn recover_from_marker(
        &mut self,
    ) -> Result<Option<ProxyMarkerData>, SystemIntegrationError> {
        let mut restored_os = false;
        self.reconcile_marker(&mut restored_os).map_err(|error| {
            log::warn!("启动恢复系统代理失败，保留 marker 供后续重试：{error}");
            error
        })
    }

    /// **维度7 #8：终态统一清系统代理**（`ensureSystemProxyCleared` 等价物）。
    ///
    /// ## 不变量（为什么必须有）
    ///
    /// 重启 / 切模式 / 起核失败时，**旧会话的系统代理仍指向现已死的端口 → 全网断**。
    /// 故所有「核已死」终态点都必须过这里。上游 `ProxyManager.ts:592-607`：start 的 public 包装
    /// catch 腿统一收口，覆盖全部 start 入口（IPC / 托盘 / 自动连接）与 restart 的 start 腿。
    ///
    /// ## 门控（三层，缺一不可）
    ///
    /// 1. **marker 在**才动手 —— 杜绝误清**用户自配**的代理（marker = 「这代理是我们设的」的唯一凭证）。
    /// 2. **实查仍指向我们**（`points_to_us`：精确 `host:port` 或 `host` 匹配 —— 后者兜 mac
    ///    socks 端口与 http 端口不同的情形）才 disable；否则只清失真 marker。
    /// 3. **marker 删除竞态防护**：清失真 marker 前重读，若期间已被新一轮 enable 写了**新** marker
    ///    （`our_host_port` 变了）则保留 —— 否则会删掉新会话的 marker 致其兜底全瞎（上游 C1）。
    ///
    /// ## 幂等
    ///
    /// 无 marker → no-op（**fresh start 无 marker，故正常启动路径调它零副作用**）。
    /// 已清过 → marker 已删 → 再调仍 no-op。故可在每个终态点无脑调，重复调用安全。
    ///
    /// ## 边界：`stopping` 守卫不在此
    ///
    /// 上游 `ensureSystemProxyCleared` 首行是 `if (this.stopping) return`（主动停止/重启中跳过，
    /// 避免清了又被 start reconcile 设回的 C1 竞态）。那是 **lifecycle 状态**，属调用方
    /// （`ProxyRuntime` / `LifecycleGate`）的知识，本 crate 不持有 → **调用方须在非 stopping 语境调用**。
    /// 同理「单飞」（上游 `clearingSystemProxy`）也属调用方：本方法自身幂等，重复调用只是多读一次
    /// marker，不会重复 disable（第一次已清 marker → 第二次门控 1 即返）。
    ///
    /// 返回 `true` = 真的执行了 disable（曾指向我们）；`false` = 无需动作 / 仅清失真 marker。
    pub fn ensure_cleared(&mut self) -> bool {
        let mut restored_os = false;
        if let Err(error) = self.reconcile_marker(&mut restored_os) {
            log::warn!("终态清理系统代理失败，保留 marker 供重试：{error}");
        }
        restored_os
    }

    /// 是否存在接管 marker（终态清理门控用）。
    pub fn has_marker(&self) -> bool {
        !matches!(self.marker.read_checked(), ProxyMarkerRead::Missing)
    }

    /// 检测「**不是我们设的**系统代理」，返回其 `host:port`（无则 `None`）。
    ///
    /// TUN 模式下另有系统代理开着 → 遵循系统代理的应用会绕开 TUN 走那个代理（它可能是别的工具设的、
    /// 也可能是用户自配的），表现为「连上了但部分应用异常」。上层据此发一次性提示（**只提示不动手**：
    /// 动手清用户自配的代理正是 marker 门控立意要禁的 stomp）。
    ///
    /// 判定与 [`ensure_cleared`](Self::ensure_cleared) 的门控 1 **互补而非重复**：
    /// - 有 marker → 系统代理是我们设的 → 不是「别人的」，`None`（此时该管的是 `ensure_cleared`）。
    /// - 无 marker + 实查确有代理 → 别人的，报出去。
    ///
    /// 读不到状态（exec 失败）→ `None`：**宁可不提示，也不拿猜测吓用户**。
    pub fn detect_foreign_proxy(&self) -> Option<String> {
        if !matches!(self.marker.read_checked(), ProxyMarkerRead::Missing) {
            return None;
        }
        let status = self.ops.get_proxy_status().ok()?;
        // `enabled` 与 `has_any_proxy()` **都要**：三平台 get_proxy_status 目前已各自早退（Win 的
        // ProxyEnable=0 / mac 的 !st.enabled / Linux 的三 host 全空），故此处理论上冗余——但那是
        // **它们的**不变式，不是本函数的。显式再判一次，将来任一腿改成「回填 server 但 enabled=false」
        // （Win 注册表 ProxyServer 在 ProxyEnable=0 时依然留值，正是这个形态）也不会退化成误报。
        if !status.enabled || !status.has_any_proxy() {
            return None;
        }
        // 展示优先级 http → https → socks（与 marker 记 `address:http_port` 同口径，取首个非空即可）。
        status
            .http_proxy
            .or(status.https_proxy)
            .or(status.socks_proxy)
    }

    /// disable/recover/ensure 的唯一释放状态机。`restored_os` 只在一次 OS restore/clear 真正成功后置位，
    /// 因而 ensure 的 bool 不会把 marker-only 清理或失败尝试误报成系统写入。
    fn reconcile_marker(
        &mut self,
        restored_os: &mut bool,
    ) -> Result<Option<ProxyMarkerData>, SystemIntegrationError> {
        match self.marker.read_checked() {
            ProxyMarkerRead::Missing => Ok(None),
            ProxyMarkerRead::Legacy(marker) => self.reconcile_legacy_marker(marker, restored_os),
            ProxyMarkerRead::CurrentValidated(marker) => {
                self.reconcile_current_marker(marker, restored_os)
            }
            ProxyMarkerRead::UnsupportedVersion(version) => Err(SystemIntegrationError::proxy(
                format!("系统代理 marker 版本 {version} 不受支持，拒绝恢复"),
            )),
            ProxyMarkerRead::Invalid(error) => Err(SystemIntegrationError::proxy(format!(
                "系统代理 marker 无效，拒绝恢复：{error}"
            ))),
            ProxyMarkerRead::IoError(error) => Err(SystemIntegrationError::proxy(format!(
                "读取系统代理 marker 失败，拒绝恢复：{error}"
            ))),
        }
    }

    fn reconcile_legacy_marker(
        &mut self,
        marker: ProxyMarkerData,
        restored_os: &mut bool,
    ) -> Result<Option<ProxyMarkerData>, SystemIntegrationError> {
        let status = self.ops.get_proxy_status()?;
        if points_to_us(Some(&status), &marker.our_host_port) {
            self.original = marker.original_snapshot();
            match self.original.as_ref() {
                Some(original) => self.ops.restore_original_settings(original)?,
                None => self.ops.clear_proxy()?,
            }
            *restored_os = true;
        }
        self.clear_legacy_marker(&marker)?;
        self.original = None;
        Ok(Some(marker))
    }

    fn reconcile_current_marker(
        &mut self,
        marker: ProxyMarkerData,
        restored_os: &mut bool,
    ) -> Result<Option<ProxyMarkerData>, SystemIntegrationError> {
        if !self.ops.exact_transaction_available()? {
            return Err(SystemIntegrationError::proxy(
                "当前系统代理 marker 需要 exact 恢复能力，但该能力现不可用",
            ));
        }
        let txn_id = marker
            .txn_id
            .as_deref()
            .expect("strict current marker always has txn_id");
        let original = marker
            .exact_original
            .as_ref()
            .expect("strict current marker always has exact_original");
        let apply_base = marker
            .exact_apply_base
            .as_ref()
            .expect("strict current marker always has exact_apply_base");
        let applied = marker
            .exact_applied
            .as_ref()
            .expect("strict current marker always has exact_applied");

        match marker.phase {
            ProxyMarkerPhase::RestoredPendingClear => {
                self.clear_current_marker(txn_id, ProxyMarkerPhase::RestoredPendingClear)?;
            }
            ProxyMarkerPhase::Restoring => {
                let current = self.ops.capture_transaction_snapshot()?;
                match self.ops.snapshot_relation(applied, original, &current) {
                    ProxySnapshotRelation::Exact => {
                        self.advance_current_phase(
                            txn_id,
                            ProxyMarkerPhase::Restoring,
                            ProxyMarkerPhase::RestoredPendingClear,
                        )?;
                        self.clear_current_marker(txn_id, ProxyMarkerPhase::RestoredPendingClear)?;
                    }
                    ProxySnapshotRelation::Unchanged | ProxySnapshotRelation::Prefix => {
                        self.restore_current_transaction(txn_id, original, &current, restored_os)?;
                    }
                    ProxySnapshotRelation::Foreign => {
                        return Err(SystemIntegrationError::proxy(
                            "Restoring 系统代理状态已被外部修改，保留 marker 并拒绝覆盖",
                        ));
                    }
                }
            }
            ProxyMarkerPhase::Applying | ProxyMarkerPhase::Owned => {
                let current = self.ops.capture_transaction_snapshot()?;
                let relation = self.ops.snapshot_relation(apply_base, applied, &current);
                let may_restore = match marker.phase {
                    ProxyMarkerPhase::Applying => match relation {
                        ProxySnapshotRelation::Exact | ProxySnapshotRelation::Prefix => true,
                        ProxySnapshotRelation::Unchanged => apply_base != original,
                        ProxySnapshotRelation::Foreign => false,
                    },
                    ProxyMarkerPhase::Owned => relation == ProxySnapshotRelation::Exact,
                    ProxyMarkerPhase::Restoring | ProxyMarkerPhase::RestoredPendingClear => {
                        unreachable!()
                    }
                };
                if !may_restore {
                    self.clear_current_marker(txn_id, marker.phase)?;
                } else {
                    self.advance_current_phase(txn_id, marker.phase, ProxyMarkerPhase::Restoring)?;
                    self.restore_current_transaction(txn_id, original, &current, restored_os)?;
                }
            }
        }
        self.original = None;
        Ok(Some(marker))
    }

    fn restore_current_transaction(
        &self,
        txn_id: &str,
        original: &ProxyTransactionSnapshot,
        current: &ProxyTransactionSnapshot,
        restored_os: &mut bool,
    ) -> Result<(), SystemIntegrationError> {
        self.ops.restore_transaction(original, current)?;
        *restored_os = true;
        self.advance_current_phase(
            txn_id,
            ProxyMarkerPhase::Restoring,
            ProxyMarkerPhase::RestoredPendingClear,
        )?;
        self.clear_current_marker(txn_id, ProxyMarkerPhase::RestoredPendingClear)
    }

    fn advance_current_phase(
        &self,
        txn_id: &str,
        expected: ProxyMarkerPhase,
        next: ProxyMarkerPhase,
    ) -> Result<(), SystemIntegrationError> {
        match self.marker.update_current_phase(txn_id, expected, next) {
            ProxyMarkerMutationOutcome::Updated => Ok(()),
            ProxyMarkerMutationOutcome::Mismatch => Err(SystemIntegrationError::proxy(
                "系统代理 marker 阶段 CAS 已失效，停止陈旧恢复",
            )),
            ProxyMarkerMutationOutcome::PersistFailed => Err(SystemIntegrationError::proxy(
                "持久化系统代理恢复阶段失败，保留 marker 供重试",
            )),
        }
    }

    fn clear_current_marker(
        &self,
        txn_id: &str,
        expected: ProxyMarkerPhase,
    ) -> Result<(), SystemIntegrationError> {
        match self.marker.clear_current(txn_id, expected) {
            ProxyMarkerMutationOutcome::Updated => Ok(()),
            ProxyMarkerMutationOutcome::Mismatch => Err(SystemIntegrationError::proxy(
                "系统代理 marker 清理 CAS 已失效，停止陈旧清理",
            )),
            ProxyMarkerMutationOutcome::PersistFailed => Err(SystemIntegrationError::proxy(
                "删除系统代理 marker 失败，保留 marker 供重试",
            )),
        }
    }

    fn clear_legacy_marker(&self, marker: &ProxyMarkerData) -> Result<(), SystemIntegrationError> {
        match self.marker.clear_legacy_if_current(marker) {
            ProxyMarkerMutationOutcome::Updated => Ok(()),
            ProxyMarkerMutationOutcome::Mismatch => Err(SystemIntegrationError::proxy(
                "legacy 系统代理 marker 已变化，停止陈旧清理",
            )),
            ProxyMarkerMutationOutcome::PersistFailed => Err(SystemIntegrationError::proxy(
                "删除 legacy 系统代理 marker 失败，保留 marker 供重试",
            )),
        }
    }
}

/// 当前系统代理是否仍指向 marker 记录的我们（`host:port` 精确匹配，或 `host` 匹配）。
///
/// **为什么也认 host 匹配**：mac 的 socks 端口与 http 端口不同（`socks_port` ≠ `http_port`），
/// 而 marker 只记 `address:http_port` → 仅按 `host:port` 精确匹配会漏判 socks 腿的残留。
/// 与启动期 marker 恢复同口径（上游 `ensureSystemProxyCleared` 的 `pointsToUs`）。
pub(super) fn points_to_us(status: Option<&SystemProxyStatus>, marker_host_port: &str) -> bool {
    let Some(status) = status else {
        return false;
    };
    if !status.enabled {
        return false;
    }
    let marker_host = marker_host_port
        .split(':')
        .next()
        .unwrap_or(marker_host_port);
    let hit = |p: &Option<String>| -> bool {
        match p {
            Some(proxy) => {
                proxy == marker_host_port
                    || proxy.split(':').next().unwrap_or(proxy.as_str()) == marker_host
            }
            None => false,
        }
    };
    hit(&status.http_proxy) || hit(&status.https_proxy) || hit(&status.socks_proxy)
}
