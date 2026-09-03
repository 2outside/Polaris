//! 待应用节点差集（pull `proxy:getPendingChanges` + push `event:proxyPendingChanges`）与
//! 延迟配置删除 journal 消费。

use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::runtime::config::DeferredConfigDeletion;
use crate::runtime::node_fingerprints;

use super::startup::server_ids;
use super::ProxyRuntime;

/// **待应用差集**（前端契约 `PendingNodeChanges`，camelCase 单词字段无需 rename）。
///
/// pull（`proxy:getPendingChanges`）与 push（`event:proxyPendingChanges`）**返回同一个结构**——
/// 没有适配层，两路同构是类型级事实而非靠测试维持（设计 SoT §2.3.2 / T2-7）。
///
/// 三字段的语义（SoT §2.3.1，旧契约 `{added, updated, deleted}` 已废，理由见 Q6）：
///
/// | 字段 | 定义 | 为什么不是旧的那个 |
/// |---|---|---|
/// | `added` | `new_ids − old_ids`：磁盘 config 有、起核快照无 = 未入运行核的新节点 | 语义本就正确，原样保留 |
/// | `modified` | 两侧都有、但 [`modified_fingerprint`]（**全维**）不等 = 核里跑的已不是当前配置 | 旧的 `updated` 是 `old ∩ new` = **全部存活 id**，与「改没改过」无关；id-only diff 在原理上就测不出「改」。修语义 = 换实现，那就该换名字 |
/// | `removed` | `old_ids − new_ids`：起核快照有、磁盘 config 无 = 已删但运行核仍持有 | 原 `deleted` 改名。旧字段语义正确但前端从不消费，通道先接好；U-2（Defer 腿是否扩到「未引用节点的增/改/删均 defer」）未拍板前它多为瞬态 |
///
/// `modified` 与测速 dirty 集的关系是 **`dirty ⊆ modified`**（全维 ⊇ 5 维），不是相等 ——
/// 二者回答的是两个问题，见 [`node_fingerprints`] 模块文档。
/// 这条包含关系正是「测速说 dirty、bar 上却没有那个节点」在结构上不可能再发生的保证。
///
/// [`modified_fingerprint`]: crate::runtime::node_fingerprints::modified_fingerprint
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingChangesSummary {
    pub added: Vec<String>,
    pub modified: Vec<String>,
    pub removed: Vec<String>,
    /// 本次运行核起来之后，是否有被「保存只持久化」延后、因而**没进核**的结构性变更。
    ///
    /// 三个节点数组回答不了这件事：`mixedPort` / TUN / DNS 这类改动一个节点都不动，
    /// 差集恒空却确实需要重启才生效。少了这一位，「保存」在条上就是完全无痕的
    /// —— 与本仓刚收口的「第四类重启」同一种静默。
    ///
    /// 真值来源是 `switch_mode` 的记账（`ProxyRuntime::restart_deferred`），不是现算的 norm 对比
    /// （后者在 kind=rules 热切后恒真，理由见该字段注释）。
    pub restart_deferred: bool,
}

impl ProxyRuntime {
    /// **R2 待应用差集 PUSH**：把 [`pending_changes`](Self::pending_changes) 原样推给 UI
    /// （`event:proxyPendingChanges`）。
    ///
    /// **无适配层**（SoT §2.3.2 / T2-7）：pull 与 push 返回同一个 [`PendingChangesSummary`]，
    /// 「两路同构」是类型级事实而非靠测试维持。收口前这里曾丢弃 `updated`/`deleted` 并把 `modified`
    /// 硬编码成空 —— 那正是「测速说这个节点已编辑未生效，而 pending-bar 上根本没有它」的成因。
    ///
    /// # 接线不变式：差集有**两侧**，两侧都得推
    ///
    /// `pending_changes()` = f(分子: `config.current()`，分母: `startup_snapshot` + `switch_snapshot`
    /// + `restart_deferred`)。**任一侧被改写都改变差集**，故 PUSH 必须挂在两侧各自的写入点上：
    ///
    /// - **分子**（配置变了）→ [`switch_mode_with`](Self::switch_mode_with) 尾。
    /// - **分母**（运行核换了）→ [`start`](Self::start) 成功收口与 [`stop_inner`](Self::stop_inner)
    ///   拆除腿。启动侧刻意等完整接管事务落定再推，避免 UI 在系统代理写入期间提前探活。
    ///
    /// 只挂分子那一侧曾是本缺陷的根因：后端自驱的重启（去抖 / 「立即应用」/ drain / 崩溃自愈）
    /// 落地后差集其实已清，但没人说 —— 而前端的 pull 兜底挂在 `event:proxyStarted`/`Stopped`，
    /// 那两个事件**只由命令层**发（`commands/proxy.rs`），内部驱动的重启一个都不发。
    /// 由 `pending_changes_push_is_wired_on_both_sides_of_the_diff` 钉住。
    ///
    /// emitter 未接线（单测 / setup 前极早期）→ 静默跳过，绝不打断调用腿（同 [`invalidate_unlock_cache`] 范式）。
    ///
    /// [`invalidate_unlock_cache`]: Self::invalidate_unlock_cache
    pub(super) fn push_pending_changes(&self) {
        if let Some(emitter) = self.error_emitter.get() {
            emitter.emit_pending_changes(&self.pending_changes());
        }
    }

    /// 取待应用节点差集（`proxy:getPendingChanges`）：当前 config 相对**起核快照**的增 / 改 / 删。
    ///
    /// 契约 = [`PendingChangesSummary`]（`{added, modified, removed}`），pull 与 push 同一个结构。
    ///
    /// # 基准与投影
    ///
    /// - **基准**：`startup_snapshot`（id 集）与 `switch_snapshot`（指纹表）—— 二者在起核就绪腿相隔 8 行
    ///   同置、停核腿相隔 8 行同清，是同一刻同一份配置的**孪生投影**，不是两个基准。
    ///   `modified` 的「旧」侧取 `switch_snapshot.fingerprints`（**不重算**）：重算等于把「运行核起于什么」
    ///   换成「磁盘上现在是什么」，那就恒等于空集了。
    /// - **投影**：`added`/`removed` 是 id 集差；`modified` 是**全维**指纹比对
    ///   （[`modified_fingerprint`](crate::runtime::node_fingerprints::modified_fingerprint)）。
    ///
    /// # 各腿的降级方向（全部保守：少显示，不虚报）
    ///
    /// - 核未运行 / 无 `startup_snapshot` → 全空差集（没有「运行核」这个分母，谈不上待应用）。
    /// - 有 `startup_snapshot` 但无 `switch_snapshot`（孪生对理论上不可能只剩一半）→ `added`/`removed`
    ///   照给，`modified` 空：拿不到起核那刻的指纹表就没有比对基准，宁可漏报也不猜。
    /// - 读当前 config 失败 → 回落到快照自身 ⇒ 三个集合全空（自己跟自己比）。
    ///
    /// 三个集合都**排序**后返回：`HashSet` 的迭代序每次进程都不同，不排序会让 UI 明细列表无故重排、
    /// 也让单测只能写成集合比较。排序成本 O(n log n)、n = 节点数，可忽略。
    pub fn pending_changes(&self) -> PendingChangesSummary {
        // 无起核快照 = 核没在跑（或快照不可信）⇒ 没有「运行核」这个分母 ⇒ 谈不上待应用。
        // `restart_deferred` 在此同样为 false：停核腿已把它复位，这里只是把该不变式写死在返回值上。
        let empty = || PendingChangesSummary {
            added: Vec::new(),
            modified: Vec::new(),
            removed: Vec::new(),
            restart_deferred: false,
        };
        let Some(snap) = self.startup_snapshot.read().ok().and_then(|g| g.clone()) else {
            return empty();
        };
        let current = self.config.current().unwrap_or_else(|_| snap.clone());
        let old_ids: std::collections::HashSet<String> = server_ids(&snap);
        let new_ids: std::collections::HashSet<String> = server_ids(&current);

        let mut added: Vec<_> = new_ids.difference(&old_ids).cloned().collect();
        let mut removed: Vec<_> = old_ids.difference(&new_ids).cloned().collect();

        // `modified` ⊂ old ∩ new：只在一侧存在的 id 属 added/removed，不属 modified。
        let snap_fps = self
            .switch_snapshot
            .read()
            .ok()
            .and_then(|g| g.as_ref().map(|s| s.fingerprints.clone()))
            .unwrap_or_default();
        let current_fps = node_fingerprints::modified_table_json(&current);
        let mut modified: Vec<_> = old_ids
            .intersection(&new_ids)
            .filter(|id| match (snap_fps.get(*id), current_fps.get(*id)) {
                (Some(old), Some(new)) => old != new,
                // 任一侧取不到指纹（快照缺失 / 节点解析不出）⇒ 没有比对基准 ⇒ 不判 modified。
                _ => false,
            })
            .cloned()
            .collect();

        added.sort();
        modified.sort();
        removed.sort();
        PendingChangesSummary {
            added,
            modified,
            removed,
            restart_deferred: self.restart_deferred.load(Ordering::SeqCst),
        }
    }

    /// 强制应用待应用变更（上游 `proxy:applyPendingChanges`）：force-restart 入核。
    ///
    /// 1:1 对齐 上游 `applyConfigForcingRestart`（:1723-1740）的**判定顺序**：
    /// 1. lifecycle 在飞（depth>0）→ 置 pending 专用配置 + restart_pending → `deferred`
    ///    （**必须先于句柄判空**：restart 的 stop→start 空窗内句柄暂空，以句柄早退会静默丢弃本次强制重启，
    ///    复现 H-1 死循环）
    /// 2. 真未运行 → `skipped`（下次 start 从磁盘纳入）
    /// 3. depth=0 且运行中 → 去抖重启排程 → `applied`
    ///
    /// **边界**：上游的 `coreSwapInProgress` 轴（换核窗口 → deferred）在 Polaris 无对应 actor，
    /// 该轴不存在（非省略）。
    pub async fn apply_pending(self: &Arc<Self>) -> &'static str {
        let new_config = match self.config.current() {
            Ok(c) => c,
            Err(e) => {
                log::warn!("applyPendingChanges 读配置失败: {e} → skipped");
                return "skipped";
            }
        };
        let id = self.force_restart_seq.fetch_add(1, Ordering::SeqCst);

        // 1. lifecycle 在飞 → 排入 drain（由 end() depth 归零时排空一次）。
        if self.gate.is_busy() {
            if let Ok(mut g) = self.pending_force_restart.write() {
                *g = Some((id, new_config));
            }
            self.gate.set_force_restart(id);
            self.gate.set_restart_pending();
            log::info!("applyPendingChanges：lifecycle 在飞（depth>0）→ deferred（排入 drain）");
            return "deferred";
        }
        // 2. 真未运行 → 下次 start 从磁盘纳入新节点。
        if !self.core_running() {
            // 无活核可保护时，Apply 本身就是安全事务点；不必强迫用户再启动一次才能完成物理删除。
            self.process_deferred_config_deletions();
            log::info!("applyPendingChanges：核未运行 → skipped");
            return "skipped";
        }
        // 3. depth=0 且运行中 → 去抖重启（drain 亦读专用字段，绕开潜在覆盖）。
        if let Ok(mut g) = self.pending_force_restart.write() {
            *g = Some((id, new_config));
        }
        self.gate.set_force_restart(id);
        self.schedule_restart();
        log::info!("applyPendingChanges：运行中 + 非在飞 → applied（已排程去抖重启）");
        "applied"
    }

    /// 消费由暂存保存腿写下的不可逆删除意图。失败条目保留在 journal，下次 Apply/启动重试。
    pub(crate) fn process_deferred_config_deletions(&self) {
        let config_dir = self.config.dir().to_path_buf();
        let result = self
            .config
            .process_deferred_deletions(|entry, current| match entry {
                DeferredConfigDeletion::RuleResource { file_name } => {
                    if crate::commands::rules::rule_resource_file_is_referenced(current, file_name)
                    {
                        Ok(())
                    } else {
                        crate::commands::rules::remove_rule_resource_file(&config_dir, file_name)
                    }
                }
                DeferredConfigDeletion::BuiltinRuleResource { file_name, .. } => {
                    crate::commands::rules::remove_builtin_rule_resource_files(
                        &config_dir,
                        file_name,
                    )
                }
                DeferredConfigDeletion::AppIcon { app_id } => crate::icon_cache::remove_app_icon(
                    &crate::icon_cache::icons_dir(&config_dir),
                    app_id,
                ),
                DeferredConfigDeletion::TailscaleState { server_id } => {
                    match self.mesh.tailscale_logout(server_id) {
                        Ok(()) => Ok(()),
                        // 旧版恶意/损坏配置可能把不安全 id 留进 journal；它不可能对应受管目录，
                        // 安全丢弃该删除意图，避免每次启动永久重试。
                        Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
                            log::warn!(
                                "忽略不安全的 Tailscale state 删除意图（server_id={server_id:?}）"
                            );
                            Ok(())
                        }
                        Err(error) => Err(format!("清理 Tailscale state 失败: {error}")),
                    }
                }
                DeferredConfigDeletion::WarpDevice {
                    device_id, token, ..
                } => self.mesh.try_enqueue_warp_deregister(device_id, token),
            });
        match result {
            Ok(summary) if summary.applied > 0 || summary.cancelled > 0 || summary.retrying > 0 => {
                log::info!(
                    "延迟配置删除完成：applied={} cancelled={} retrying={}",
                    summary.applied,
                    summary.cancelled,
                    summary.retrying
                );
            }
            Ok(_) => {}
            Err(error) => log::warn!("延迟配置删除 journal 读取/回写失败: {error}"),
        }
    }
}
