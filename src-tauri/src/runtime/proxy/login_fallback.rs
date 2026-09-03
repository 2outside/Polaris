//! A4 组网登录期出口让位域（零重启 selector 编排）。
//!
//! 选中出口 = 正登录的账号制 TS 全隧道节点时，其隧道 `Running` 前把默认路由（`proxy-selector`）
//! 临时热切 `direct`，`Running` 后切回。**不**重生成 config、**不**重启核（重启 = 断流，正是此腿
//! 规避的）。`engaged` flag 只在 PUT 成功后翻转，杜绝「flag 与 selector 脱节永卡 direct」。
//!
//! 单飞由 [`ReconcileGuard`] 的 Drop 复位（含任一 early-return / panic），杜绝「在飞标志卡死 →
//! 让位永不再对账」。

use std::sync::atomic::{AtomicBool, Ordering};

use polaris_config_engine::builder::route::mesh_selected_exit_falls_back_to_direct;
use polaris_config_engine::user_config::app_config::UserConfig;
use polaris_config_engine::user_config::dns_constants::{DIRECT_TAG, PROXY_SELECTOR_TAG};
use polaris_config_engine::user_config::proxy_mode::ProxyMode;
use polaris_config_engine::user_config::server_config::Protocol;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::MutexGuard as AsyncMutexGuard;

use crate::runtime::mesh::{mesh_login_fallback_should_engage, MeshLoginFallbackInput};

use super::ProxyRuntime;

/// A4 登录期出口让位内存态。engaged ⟺ selector 实指 direct（仅 PUT 成功后置，flag 不与 selector 脱节）。
#[derive(Debug, Clone, Default)]
pub(super) struct LoginFallbackState {
    engaged: bool,
    server_id: Option<String>,
}

/// reconcile 单飞守卫：退场（含任一 early-return / panic）必把 `login_fallback_reconciling` 复位，
/// 杜绝「在飞标志卡死 → 让位永不再对账」。
struct ReconcileGuard<'a>(&'a AtomicBool);
impl Drop for ReconcileGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl ProxyRuntime {
    // ════════════════ A4：组网登录期出口让位（零重启热切 selector 编排）════════════════
    //
    // 机制（1:1 移植 上游 `reconcileLoginFallback`/`loginFallbackEligible`/`markLoginFallbackEngaged`）：
    // 选中出口=正登录的账号制 TS 全隧道节点时，其隧道 Running 前把默认路由（proxy-selector）临时**热切** direct
    // （`select_outbound`，**零重启**、`direct` 恒是 proxy-selector 成员），Running 后切回。**不**重生成 config、
    // **不**重启核（重启=断流，正是此腿规避的）。见复审队列 R26。

    /// A4 让位态读侧：当前是否处于登录期出口让位态（推送经 `EVENT_MESH_LOGIN_FALLBACK`）。
    #[must_use]
    pub fn login_fallback_engaged(&self) -> bool {
        self.login_fallback
            .lock()
            .map(|g| g.engaged)
            .unwrap_or(false)
    }

    /// A4 早退闸的**廉价一半**：选中出口在**原始配置 JSON** 上是否为 Tailscale 协议。
    ///
    /// # 为什么读 raw `Value` 而不是 `UserConfig`
    ///
    /// 这个判据存在的唯一理由，是省掉 [`reconcile_login_fallback`](Self::reconcile_login_fallback)
    /// 每帧那两份整配置分配（`current_config` 的深拷贝 + 反序列化出的 `UserConfig`，两者都含全部
    /// 节点）。为判它再反序列化一次就等于白做。本实现只在读锁内对**借来的** `Value` 做两次 `&str`
    /// 比较：**零堆分配**，代价 = 一次 `RwLock` 读 + 对 `servers` 数组的一次线性扫描。
    ///
    /// # 与 [`login_fallback_eligible`](Self::login_fallback_eligible) 的等价性
    ///
    /// 那条判据经 `UserConfig` 走 `selected_server_id` → `servers.iter().find(id)` →
    /// `protocol == Protocol::Tailscale`。三处键名与取法在此**逐字对齐**：`selectedServerId`
    /// （`UserConfig` 的 `#[serde(rename)]`）、`servers[].id`、`servers[].protocol`。
    /// 同样用 `find` 而非 `any`：id 重复时两条路必须取到同一个元素。
    ///
    /// 🔴 **等价性依赖一条本函数管不到的外部性质**：`Protocol` 的反序列化严格小写、无别名
    /// （`#[serde(rename_all = "lowercase")]` 且未手写宽容 `Deserialize`）⇒ 线上字面量恒为
    /// `"tailscale"`。它并非天然如此 —— 同一个文件里的 `SecurityMode` 就是大小写不敏感解析的活先例。
    /// 若有人照抄着给 `Protocol` 加宽容解析，`"Tailscale"` 会让完整判据说「符合」、本判据说「不符合」
    /// ⇒ **engage 帧被早退闸吃掉**，未登录的 TS 出口永不让位，而本模块的等价性测试（只喂现存形态）
    /// 不会转红。绊线落在定义侧：`config-engine` 的 `protocol_deserialization_is_case_strict`。
    /// **要给 `Protocol` 加宽容解析，先来改这里**（改成走 `Protocol::deserialize` 或对齐新口径）。
    ///
    /// 任何让 `UserConfig::deserialize` 失败的形态（缺 `protocol`、大小写不符、类型不对）在本判据
    /// 下同样落 `false`，而 `reconcile_login_fallback` 遇反序列化失败本就 `return` ⇒ 两条路的可观测
    /// 结果一致（都无效果）。空 `selectedServerId` 亦然（对账里 `sel_id` 同样按非空过滤）。
    pub(super) fn selected_exit_is_tailscale(&self) -> bool {
        let Ok(guard) = self.current_config.read() else {
            return false;
        };
        let Some(raw) = guard.as_ref() else {
            return false;
        };
        let Some(selected) = raw
            .get("selectedServerId")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        else {
            return false;
        };
        raw.get("servers")
            .and_then(Value::as_array)
            .and_then(|servers| {
                servers
                    .iter()
                    .find(|s| s.get("id").and_then(Value::as_str) == Some(selected))
            })
            .and_then(|s| s.get("protocol").and_then(Value::as_str))
            == Some("tailscale")
    }

    /// 内存态写：置/清 `(engaged, server_id)`。
    pub(super) fn set_login_fallback(&self, engaged: bool, server_id: Option<String>) {
        if let Ok(mut g) = self.login_fallback.lock() {
            g.engaged = engaged;
            g.server_id = server_id;
        }
    }

    /// A4：选中出口在【配置层】是否符合让位形态（账号制 TS 全隧道出口 + 开关开 + 非 direct 模式 + 无 authKey）。
    ///
    /// 就绪与否的【动态】判断不在此（`tunnel_ready` 恒传 false，只为「配置符合」时返 true）；由 reconcile 按
    /// backendState 决策。`raw` 供读 `meshLoginFallbackDirect`（**非 UserConfig 结构体字段**，同 `restartOnNodeChange`
    /// 只在原始 JSON 里，见 switch_mode 注）。上游 `loginFallbackEligible`。
    pub(super) fn login_fallback_eligible(&self, config: &UserConfig, raw: &Value) -> bool {
        let selected = config
            .selected_server_id
            .as_deref()
            .and_then(|id| config.servers.iter().find(|s| s.id == id));
        let input = MeshLoginFallbackInput {
            // `meshLoginFallbackDirect !== false`（缺键/true → 开；显式 false → 关）。
            fallback_enabled: raw.get("meshLoginFallbackDirect").and_then(Value::as_bool)
                != Some(false),
            proxy_mode_direct: config.proxy_mode == ProxyMode::Direct,
            selected_exit_falls_back_direct: mesh_selected_exit_falls_back_to_direct(config),
            selected_is_tailscale: selected
                .map(|s| s.protocol == Protocol::Tailscale)
                .unwrap_or(false),
            selected_has_auth_key: selected
                .and_then(|s| s.tailscale_settings.as_ref())
                .and_then(|t| t.auth_key.as_deref())
                .map(|k| !k.trim().is_empty())
                .unwrap_or(false),
            selected_tunnel_ready: false,
        };
        mesh_login_fallback_should_engage(&input)
    }

    /// A4：发射让位态变事件（emitter 未接线 = 单测/setup 前 → 静默跳过）。
    fn emit_mesh_login_fallback(&self, engaged: bool, server_name: Option<&str>) {
        if let Some(emitter) = self.error_emitter.get() {
            emitter.emit_mesh_login_fallback(engaged, server_name);
        }
    }

    /// A4：置让位 flag（PUT 成功后调，flag 与 selector 一致）。幂等，仅首次 emit engaged:true。
    /// 上游 `markLoginFallbackEngaged`。
    pub(super) fn mark_login_fallback_engaged(&self, server_id: &str, config: &UserConfig) {
        let first = {
            let mut g = match self.login_fallback.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            if g.engaged && g.server_id.as_deref() == Some(server_id) {
                return; // 幂等：同出口已让位，不重复 emit
            }
            let first = !g.engaged;
            g.engaged = true;
            g.server_id = Some(server_id.to_string());
            first
        };
        if first {
            let name = config
                .servers
                .iter()
                .find(|s| s.id == server_id)
                .map(|s| s.name.clone());
            log::info!(
                "组网出口「{}」尚未登录，登录期默认路由让位直连",
                name.as_deref().unwrap_or(server_id)
            );
            self.emit_mesh_login_fallback(true, name.as_deref());
        }
    }

    /// A4：复位让位内存态 + 撤销 UI 提示（若在让位中）。停核/崩溃调用；**不切 selector**（核已停/将停）。
    /// 上游 `resetLoginFallbackState`。
    pub(super) fn reset_login_fallback_state(&self) {
        let was_engaged = {
            let mut g = match self.login_fallback.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            if !g.engaged && g.server_id.is_none() {
                return;
            }
            g.engaged = false;
            g.server_id = None;
            true
        };
        if was_engaged {
            self.emit_mesh_login_fallback(false, None);
        }
    }

    /// A4 登录期出口让位【对账】（单一入口，幂等可重入；PUT 成功才翻 flag → 杜绝「flag 与 selector 脱节永卡 direct」）。
    ///
    /// 三态决策（按选中出口 backendState）。engage：符合条件 且 `NeedsLogin`（含 key 过期）→ 热切
    /// proxy-selector→direct，成功才置 flag、失败下次 tick 重试。disengage：已让位 且（不再符合条件[关开关/
    /// 切非 TS/direct/authKey] 或 已就绪 `Running`）——同一选中出口则 PUT 切回其 tag（关开关切回=用户明确「宁可
    /// 授权失败也不直连」），切走出口则仅清 flag（不 PUT）。其余过渡态（NoState/Starting/Stopped/无帧）维持现状
    /// 不翻转（避免过渡期抖动 / 已登录节点起核闪直连）。由 STATUS 帧 / switchMode 非重启腿 / 起核预置后共同驱动；
    /// 核未起时 hotSwitch 返 false → 不改 flag。上游 `reconcileLoginFallback`。
    ///
    /// 开头有一道**早退闸**（谓词 `!engaged && !选中出口是 TS`），只跳过「结构性无任何可观测效果」的那
    /// 一格，决策矩阵与谓词推导见函数体内注释。非 TS 用户的每帧成本由此归零。
    pub(super) async fn reconcile_login_fallback(&self) {
        // 单飞：抢占失败（已在飞）→ 丢弃后来者（下一帧/tick 幂等收敛）。
        if self.login_fallback_reconciling.swap(true, Ordering::SeqCst) {
            return;
        }
        let _guard = ReconcileGuard(&self.login_fallback_reconciling);
        let switch_guard = self.switch_serial.lock().await;
        self.reconcile_login_fallback_locked(&switch_guard).await;
    }

    /// 调用方已持有 [`Self::switch_serial`] 的 fallback 执行半边；拆开是为了让普通 switch/auto
    /// 在同一 selector 事务末尾复用而不重入 Tokio Mutex。
    pub(super) async fn reconcile_login_fallback_locked(
        &self,
        switch_guard: &AsyncMutexGuard<'_, ()>,
    ) {
        let generation = self.gate.generation();
        let intent_generation = self.selector_reconcile.intent_generation();

        // ── 早退闸：本帧结构性不可能有任何可观测效果时，跳过下面两份整配置分配 ──
        //
        // 三态决策矩阵（`eligible` = 配置层符合让位形态，**蕴含**「选中出口是 TS 协议」；
        // `state` = 选中出口 STATUS 末帧 backendState；`engaged` = 当前让位 flag）：
        //
        // | # | eligible | state       | engaged | 本帧动作                                              |
        // |---|----------|-------------|---------|-------------------------------------------------------|
        // | 1 | true     | NeedsLogin  | 任意    | **engage**：PUT selector→direct，成功才置 flag/emit    |
        // | 2 | true     | Running     | true    | **disengage**：同出口 → PUT 回其 tag；已切走 → 仅清 flag |
        // | 3 | true     | Running     | false   | 维持（本就没让位）                                     |
        // | 4 | true     | 其它 / 无帧 | 任意    | 维持（过渡态不翻转，避免抖动 / 已登录节点起核闪直连）   |
        // | 5 | false    | 任意        | true    | **disengage**：关开关 / 切非 TS / authKey / direct 模式 |
        // | 6 | false    | 任意        | false   | **无任何效果** ← 本闸的射程，且**仅此一行**             |
        //
        // ⚠️ 上表是**过了下面两条前置早退之后**的决策图，不是本函数的全图：`current_config` 为空、
        // 或 `UserConfig` 反序列化失败时（见下方两条 `else { return; }`），函数在读到 `eligible` 之
        // 前就退场 —— `engaged=true` 时这**同样吞掉 disengage**（既存行为，本批未改：那两条是「连
        // 真值都读不出来」，此时按旧状态维持比按残缺配置翻转更保守）。本闸只在 `!engaged` 时开火，
        // 与这两条早退不相交，故上面的论证不受影响；但别把这张表当成函数全图。
        //
        // 谓词必须是两条的合取：`eligible ⇒ 选中是 TS`（`mesh_login_fallback_should_engage` 的必要
        // 条件之一），故 `!选中是 TS` 单独就排除第 1 行；第 2/5 行则一律以 `engaged` 为前提，故
        // `!engaged` 排除它们。**只判「选中是不是 TS」会杀掉第 5 行**——用户从 TS 出口切走后
        // `eligible` 立刻为假，而那一帧恰恰必须跑完才能清 flag + 撤让位横幅
        // （`emit_mesh_login_fallback(false)`）；早退会让 engaged 态永不收敛、横幅永不撤。
        //
        // 与 `mesh.rs::has_ts_status` 的范式差别（**别照抄那条**）：那条安全，是因为「无 TS 帧 ⇒ 结论
        // 恒为无告警」；本函数在 engaged 态下结论会变，不满足该前提，故必须把 `engaged` 并进谓词。
        //
        // 竞态：`engaged` 由假翻真只发生在本函数与 `reassert_selector_selection`，而后者置 flag 的
        // 前提同样是「选中出口为 TS」⇒ 那条腿下本闸第二个合取项亦为假、不会早退。配置在本闸与下面
        // 那次读之间被改写只影响本帧取舍，STATUS 每帧驱动 ⇒ 下一帧即收敛。
        if !self.login_fallback_engaged() && !self.selected_exit_is_tailscale() {
            return;
        }

        let Some(raw) = self.current_config.read().ok().and_then(|g| g.clone()) else {
            return;
        };
        // 借用反序列化而非 `from_value(raw.clone())`：`raw` 在下一行的 `login_fallback_eligible`
        // 里还要用，所以上面那份 clone 省不掉；但 `from_value` 要的是 owned `Value` ⇒ 只能再深拷
        // 一整棵配置树（含全部节点），拷完立刻丢。`UserConfig` 无 borrow 字段，两条路等价：
        // 反序列化失败仍落同一条 `else { return; }`。
        let Ok(config) = UserConfig::deserialize(&raw) else {
            return;
        };
        let sel_id = config.selected_server_id.clone().filter(|s| !s.is_empty());
        let eligible = sel_id.is_some() && self.login_fallback_eligible(&config, &raw);
        let backend_state = sel_id
            .as_deref()
            .and_then(|id| self.mesh.selected_exit_backend_state(id));

        // engage：符合条件 且 明确需要交互登录（NeedsLogin / 过期）。**不**因「已 engaged」提前 return——每次
        // NeedsLogin 帧都重 PUT direct（gRPC 选同成员=核侧 no-op，无害）→ 与起核预置这个独立写者脱节时能自愈；
        // markEngaged 的 first 守卫保证 UI 只 emit 一次。
        if eligible && backend_state.as_deref() == Some("NeedsLogin") {
            if !self
                .hot_switch_selector_locked(switch_guard, PROXY_SELECTOR_TAG, DIRECT_TAG)
                .await
            {
                return; // PUT 失败：不改 flag，下次 tick 重试
            }
            if !self.selector_operation_is_current(generation, intent_generation) {
                self.selector_reconcile.mark_required();
                return;
            }
            // sel_id 必 Some（eligible 蕴含）。
            if let Some(id) = sel_id.as_deref() {
                self.mark_login_fallback_engaged(id, &config);
            }
            return;
        }

        // disengage 条件：已让位 且（不再符合条件 或 已就绪 Running）。过渡态一律维持现状。
        let (engaged_now, engaged_id) = self
            .login_fallback
            .lock()
            .map(|g| (g.engaged, g.server_id.clone()))
            .unwrap_or((false, None));
        let should_disengage =
            engaged_now && (!eligible || backend_state.as_deref() == Some("Running"));
        if !should_disengage {
            return;
        }

        match engaged_id {
            // 同一选中出口撤销让位（就绪 或 用户关开关）→ PUT 切回其 tag（成功才清 flag）。
            Some(eid) if Some(eid.as_str()) == sel_id.as_deref() => {
                let tag = self
                    .switch_snapshot
                    .read()
                    .ok()
                    .and_then(|g| g.as_ref().and_then(|s| s.id_to_tag.get(&eid).cloned()));
                if let Some(tag) = tag {
                    if !self
                        .hot_switch_selector_locked(switch_guard, PROXY_SELECTOR_TAG, &tag)
                        .await
                    {
                        return; // PUT 失败：不改 flag，下次 tick 重试
                    }
                    if !self.selector_operation_is_current(generation, intent_generation) {
                        self.selector_reconcile.mark_required();
                        return;
                    }
                } else {
                    // tag 缺失（罕见：核停/gate 剔除）→ 无法 PUT 回；清 flag 避免永卡，selector 由起核预置兜底。
                    log::warn!("组网出口让位撤销：找不到出口 tag（{eid}），跳过 selector 切回");
                }
                let name = config
                    .servers
                    .iter()
                    .find(|s| s.id == eid)
                    .map(|s| s.name.clone());
                self.set_login_fallback(false, None);
                log::info!(
                    "组网出口「{}」让位撤销，默认路由切回该出口",
                    name.as_deref().unwrap_or(&eid)
                );
                self.emit_mesh_login_fallback(false, name.as_deref());
            }
            // 切走出口：selector 已由 planHotSwitch/config default PUT 到新目标，仅清 flag + 撤 UI（不 PUT，避免打架）。
            _ => {
                self.set_login_fallback(false, None);
                self.emit_mesh_login_fallback(false, None);
            }
        }
    }
}
