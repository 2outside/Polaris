//! C3 自动换节点域：专用出口心跳 → 决策机 → 已加载 clean 候选的零重启热切事务。
//!
//! 决策全在 [`crate::runtime::auto_switch`]（`AutoSwitchMachine` + 纯选择函数，真值表 + 变异锁死）；
//! 本模块只做 I/O 编排与**单一提交事务**：D 侧只改 `selectedServerId`、R 侧只做可证明的 selector
//! 热切，两侧任一不自证即整笔回退（见 [`AutoHotSwitchOutcome`]）。与崩溃恢复解耦——进程崩溃由
//! `spawn_crash_monitor` 原地重启同节点兜底，本腿只对「核活着但代理链不通」换节点。

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use polaris_config_engine::builder::endpoint_routes::mesh_node_carries_full_tunnel;
use polaris_config_engine::builder::hotswitch::HotSwitchPlan;
use polaris_config_engine::user_config::app_config::UserConfig;
use polaris_config_engine::user_config::server_config::is_mesh_node;
use polaris_switch_engine::{HotSwitchOutcome, SwitchDecision, SwitchExecutor};

use crate::commands::speedtest::{
    current_server_fingerprints, probe_runtime_candidates, resolve_speed_test_url,
    RuntimeProbeBatch,
};
use crate::runtime::auto_switch::{
    decide_tick, plan_runtime_candidates, select_best_candidate, switch_blocked_by_restart,
    switch_payload, AutoSwitchMachine, CandidateLatency, HeartbeatOutcome, RuntimeCandidate,
    RuntimeCandidatePlan, SwitchGate, TickAction, TickInput, CONNECTIVITY_TIMEOUT_MS,
    CONNECTIVITY_URLS, HEARTBEAT_INTERVAL_MS,
};
use crate::runtime::config::Decision;
use crate::runtime::tailscale_status::TailscaleStatusEvent;

use super::hot_switch::{selected_server_present, ClassifiedSwitch, RuntimeSelectionApi};
use super::lifecycle::monotonic_now_ms;
use super::{code, ProxyRuntime};

/// 「自动切换落空、只能请用户手动换节点」的诊断文案 —— [`ProxyRuntime::do_switch_io`] 的两个上报点
/// 共用一份，防两处措辞漂移。**用户可见文案不由它决定**：渲染端按稳定码
/// [`code::AUTO_SWITCH_NEEDS_RESTART`] 选 locale（`ui/src/domain/proxy-error-text.ts`），本串只进
/// 日志与 wire 诊断字段。
///
/// 措辞刻意不说「可用的节点」：被剔掉的那些候选**一个都没被探测过**（剔除发生在探测之前），
/// 「可用」是未核实的断言。也刻意不建议「重启代理」：走到上报点时 D 与 R 的选中节点已确证相同，
/// 同配置重启只会世代 +1、锁存复位、同情形再报一次 —— 用户照做就进循环。
const RESTART_BLOCKED_MESSAGE: &str =
    "自动切换已触发，但本轮未能换成节点：有候选节点需要重启内核才能切换过去";

/// 自动故障切换的热切事务结果。它刻意没有 `Restarting`：后台故障治理只允许操作当前运行核已加载的
/// clean selector 成员；管理 API 不可用就失败，不得借一次整核重启把 D 中其他待 Apply 修改带进去。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum AutoHotSwitchOutcome {
    Applied,
    Busy,
    Superseded,
    NotEligible,
    /// D 已提交目标，但目标与旧 selector 均无法自证；后台受限对账 actor 已获恢复所有权。
    ReconcilePending {
        intent_generation: u64,
    },
    Failed,
}

/// 一个候选「切过去」的三态裁定（[`ProxyRuntime::candidate_switch_plan`] 的产物）。
///
/// **三态而不是 `Option`**：`Option::None` 会把「这个候选切过去要整核重启」和「本轮根本无从判定」
/// 压成同一个值。后者（核已停 / 基准过期）是**运行时**的属性，对每个候选都成立 ⇒ 压扁之后停核
/// 窗口里「全部候选都需要重启」，于是往刚被 `ProxyStatus::default()` 清零的状态里写一条非致命
/// 错误，被渲染端判成终态故障 —— 而用户刚点的是停止。
pub(super) enum CandidateSwitchPlan {
    /// 可零重启热切过去；三个载荷交给提交腿直接消费。
    HotSwitchable {
        switched: Value,
        plan: HotSwitchPlan,
        new_cfg: Box<UserConfig>,
    },
    /// 切过去必须整核重启：route 投影 guard（force-route engaged / 全隧道兜底翻转）、目标未入
    /// selector、目标 dirty、TUN 未规划的自动物理出口。**这一桶是上报判据的唯一区分项**。
    NeedsRestart,
    /// 本轮无从判定（核已停、运行核基准已过期）。整轮作废，一个候选都不许记账。
    Void,
}

impl ProxyRuntime {
    /// 候选**能否零重启切过去**的单一判据：拿运行核基准配置 clone 一份、把 `selectedServerId` 换成
    /// 候选 id，重跑 [`Self::classify_switch`]；要求落在热切腿，且 `puts` 里确有一条
    /// `proxy-selector → 候选 tag`。
    ///
    /// [`HotSwitchable`](CandidateSwitchPlan::HotSwitchable) 的三个载荷都是判定的**副产物**，
    /// 交给提交腿直接消费（它要把 `switched` 提交为 R 的新 `current_config`、按 `plan` 执行 PUT、
    /// 从 `new_cfg` 读 `interrupt_connections_on_switch` 与出口路由对账入参）。不这么交、让提交腿
    /// 自己再算一遍，就等于又开了一个可与判定分歧的读点。
    ///
    /// # 为什么两个消费点共用它，而不是各写一份
    ///
    /// 消费点是[提交事务](Self::auto_hot_switch_transaction_with_api)（非热切 ⇒ `NotEligible`）与
    /// [探测前的候选剔除](Self::retain_hot_switchable_candidates)（非热切 ⇒ 根本不探）。两处判据**必须
    /// 逐字相同**：探测前放行、提交时才拒 = 整轮全量探测白跑，且 `do_switch_io` 返 false 不计熔断 ⇒
    /// 约 90 秒后原样重来一轮，永不成功 —— 而那正是用户真需要切换的时刻。
    ///
    /// 另立一份翻转谓词还会漏：切不过去不止来自 `plan_hot_switch` 的 route 投影 guard，
    /// `classify_switch` 自己的 TUN 绑定根 `Fallback`（`hot_switch.rs` 的
    /// 「目标包含本核未规划的自动物理出口」）同样会让候选切不过去，而那条腿在 config-engine 里没有
    /// 对应谓词可抄。共用整条判定链是唯一覆盖得全的做法。
    ///
    /// 仓内既定做法就是**复用而非复写**：`classify_staged`（`hot_switch.rs`，理由写在它头注的
    /// 「预告与实际在构造上不可能分歧」）直接复用 `classify_switch` 而不另写一份预告判据，
    /// 本方法是同一条推理在候选剔除上的应用。
    ///
    /// 代价如实记：剔除腿会对每个候选各跑一次完整判定（两次 `UserConfig` 解析 + 两次 norm +
    /// 一次 `plan_hot_switch`）。它比它替掉的东西便宜若干个数量级 —— 替掉的是同一批候选的**真实
    /// 协议链探测**（K 槽分波、每槽 CONNECT + warm-TTFB，含超时），且整条腿每 30 秒才可能触发一次。
    pub(super) fn candidate_switch_plan(
        &self,
        runtime_config: &Value,
        candidate: &RuntimeCandidate,
    ) -> CandidateSwitchPlan {
        let mut switched = runtime_config.clone();
        let Some(object) = switched.as_object_mut() else {
            return CandidateSwitchPlan::Void;
        };
        object.insert(
            "selectedServerId".to_string(),
            Value::String(candidate.id.clone()),
        );
        match self.classify_switch(&switched, false) {
            // 核已停 —— 这是**运行时**的属性，对每个候选都一样，不是「这个候选要重启」。
            ClassifiedSwitch::NotRunning => CandidateSwitchPlan::Void,
            // 候选恒 ≠ 当前出口（`plan_runtime_candidates` 保证），故「与运行核配置逐字节全等」
            // 只可能是运行核在本轮读到基准之后被换掉了 ⇒ 本轮的基准已过期。
            ClassifiedSwitch::Unchanged => CandidateSwitchPlan::Void,
            // 能走到这里的 `Fallback` 只剩「目标包含本核未规划的自动物理出口」，那确实要整核重启。
            // 另外三条都不是候选的属性，各有整轮判掉的地方：无 `current_config` 基准由调用方
            // [`Self::do_switch_io`] 取基准时挡下；解析失败与无热切基准快照由
            // [`Self::retain_hot_switchable_candidates`] 在循环外挡下（理由见那里）。
            ClassifiedSwitch::Fallback(_) => CandidateSwitchPlan::NeedsRestart,
            ClassifiedSwitch::Decided {
                decision: SwitchDecision::HotSwitch(plan),
                new_cfg,
            } => {
                let puts_the_candidate = plan.puts.iter().any(|put| {
                    put.selector_tag == "proxy-selector" && put.member_tag == candidate.tag
                });
                if puts_the_candidate {
                    CandidateSwitchPlan::HotSwitchable {
                        switched,
                        plan,
                        new_cfg,
                    }
                } else {
                    CandidateSwitchPlan::NeedsRestart
                }
            }
            ClassifiedSwitch::Decided { .. } => CandidateSwitchPlan::NeedsRestart,
        }
    }

    /// 探测**之前**把切不过去的候选剔掉并**分两个桶**记账；返回 `false` = 本轮无从判定，
    /// 调用方必须直接早退且**不做任何上报**。
    ///
    /// 两个桶的分界就是「这件事该不该告诉用户」：
    ///  - [`not_exit`](RuntimeCandidatePlan::not_exit)：候选**自身**是只走内网的组网节点
    ///    （`is_mesh_node && !mesh_node_carries_full_tunnel` —— TS 无 exit node / WG 关
    ///    `allowInternet` / OpenVPN 关 `redirect_gateway` 且 `meshRoutes` 非空）。自动切换永远不该
    ///    切到它：切过去公网流量就整体兜底直连，那是把用户静默推去明文直连，不是「换了个能用的
    ///    节点」。静默排除，与 TS 未就绪的 `not_ready` 同类，**不入上报判据**。
    ///  - [`needs_restart`](RuntimeCandidatePlan::needs_restart)：判据即
    ///    [`Self::candidate_switch_plan`]，与提交事务同一份。装的是真的「切过去要整核重启」者。
    ///
    /// 返回 `false` 的三个来源全是**运行时**属性、不是候选属性：运行核基准解析不了、任一候选判到
    /// [`CandidateSwitchPlan::Void`]、剔除期间世代跃迁或核停（末尾复查 —— 停在最后一个候选判完
    /// 之后，前面那些裁定虽各自成立，此刻也已无人需要）。把它们记进 `needs_restart` 就是把
    /// 「用户刚点了停止」报成「自动切换帮不上忙」。
    ///
    /// **射程自曝**：末尾那道复查**没有行为门** —— 要构造「循环最后一个候选判完之后才停核」得在
    /// 本方法内部插手，本机造不出来。停核窗口整体与 per-candidate 那条腿各有门
    /// （`stop_window_voids_the_round_…` / `stale_runtime_baseline_voids_the_round_…`）。
    ///
    /// # 当前出口本身是只走内网的组网节点时
    ///
    /// 那时**每个**普通候选都不可热切（方向相反、同样要重下发段规则），于是全员进 `needs_restart`。
    /// 这条腿在**生产上不可达**：心跳层的停摆守卫
    /// （[`auto_switch_blocked_for_generation`](crate::runtime::auto_switch::auto_switch_blocked_for_generation)）
    /// 用的正是同一个谓词，那样的世代压根不会跑到这里；只有单测直接调本方法时可达
    /// （`mesh_only_current_exit_drops_every_plain_candidate`）。保留是因为本方法的正确性不该
    /// 依赖调用方的守卫。
    ///
    /// 之所以不落在 `plan_runtime_candidates` 里：那是只看 `&Value` 的纯函数，而本判据要
    /// `UserConfig` 与运行核快照。
    pub(super) fn retain_hot_switchable_candidates(
        &self,
        generation: u64,
        runtime_config: &Value,
        plan: &mut RuntimeCandidatePlan,
    ) -> bool {
        let Ok(runtime_cfg) = serde_json::from_value::<UserConfig>(runtime_config.clone()) else {
            return false;
        };
        // 热切基准快照缺失是**运行时**属性，对每个候选都一样。不在这里整轮判掉的话，
        // `classify_switch` 会对每个候选各返一次 `Fallback("无热切换基准快照")` ⇒ 全部计入
        // `needs_restart` ⇒ 候选清零 + `needs_restart > 0` ⇒ 向用户误报一次「需手动切换」，
        // 而真相是本轮压根无从判断。与上面那条解析失败同理，作废整轮。
        if self
            .switch_snapshot
            .read()
            .ok()
            .and_then(|guard| guard.clone())
            .is_none()
        {
            return false;
        }
        let mut kept: Vec<RuntimeCandidate> = Vec::with_capacity(plan.candidates.len());
        let mut not_exit = 0usize;
        let mut needs_restart = 0usize;
        for candidate in &plan.candidates {
            let mesh_only = runtime_cfg
                .servers
                .iter()
                .find(|server| server.id == candidate.id)
                .is_some_and(|server| {
                    is_mesh_node(server) && !mesh_node_carries_full_tunnel(server)
                });
            if mesh_only {
                not_exit += 1;
                continue;
            }
            match self.candidate_switch_plan(runtime_config, candidate) {
                CandidateSwitchPlan::HotSwitchable { .. } => kept.push(candidate.clone()),
                CandidateSwitchPlan::NeedsRestart => needs_restart += 1,
                CandidateSwitchPlan::Void => return false,
            }
        }
        if self.core_generation() != generation || !self.core_running() {
            return false;
        }
        plan.candidates = kept;
        plan.not_exit = not_exit;
        plan.needs_restart = needs_restart;
        true
    }

    /// 自动故障切换的单一提交事务：D 只改 `selectedServerId`，R 只做可证明的 selector 热切。
    ///
    /// 与普通 `switch_mode` 的关键差异是**禁止失败回退整核重启**。普通用户 Apply 的目标就是把完整 D
    /// 入核，失败回退重启正确；后台 failover 只获授权切出口，若沿用同一回退会把 DNS/TUN/规则等
    /// 已保存未 Apply 的修改一起带入核，破坏 Save/Apply 边界。
    pub(super) async fn auto_hot_switch_transaction(
        self: &Arc<Self>,
        generation: u64,
        expected_current_id: &str,
        candidate: &RuntimeCandidate,
        expected_candidate_fingerprint: &str,
    ) -> AutoHotSwitchOutcome {
        let api = self.management_api().await;
        self.auto_hot_switch_transaction_with_api(
            generation,
            expected_current_id,
            candidate,
            expected_candidate_fingerprint,
            &api,
        )
        .await
    }

    /// 可注入管理面的事务本体。所有 generation/lifecycle/config CAS 均在拿到 `switch_serial` 后重验，
    /// 因此生产侧在锁外建立 lazy gRPC channel 不会把陈旧客户端变成一次陈旧提交。
    pub(super) async fn auto_hot_switch_transaction_with_api(
        self: &Arc<Self>,
        generation: u64,
        expected_current_id: &str,
        candidate: &RuntimeCandidate,
        expected_candidate_fingerprint: &str,
        api: &dyn RuntimeSelectionApi,
    ) -> AutoHotSwitchOutcome {
        let switch_guard = self.switch_serial.lock().await;
        if self.gate.generation() != generation || !self.core_running() {
            return AutoHotSwitchOutcome::Superseded;
        }
        let starting_intent_generation = self.selector_reconcile.intent_generation();
        if self.gate.is_busy() {
            return AutoHotSwitchOutcome::Busy;
        }
        if self.selector_reconcile.is_required() {
            return AutoHotSwitchOutcome::NotEligible;
        }
        let staged = self.config.staged_node_mask();
        if staged.pending
            && (!staged.scope_known || staged.node_ids.contains(candidate.id.as_str()))
        {
            return AutoHotSwitchOutcome::Superseded;
        }

        let Some(old_runtime) = self
            .current_config
            .read()
            .ok()
            .and_then(|guard| guard.clone())
        else {
            return AutoHotSwitchOutcome::NotEligible;
        };
        if old_runtime.get("selectedServerId").and_then(Value::as_str) != Some(expected_current_id)
        {
            return AutoHotSwitchOutcome::Superseded;
        }
        let old_tag = self.switch_snapshot.read().ok().and_then(|guard| {
            guard
                .as_ref()
                .and_then(|snapshot| snapshot.id_to_tag.get(expected_current_id).cloned())
        });
        let Some(old_tag) = old_tag else {
            return AutoHotSwitchOutcome::NotEligible;
        };

        // 资格判定与 `do_switch_io` 的探测前剔除**同一份**（见 [`Self::candidate_switch_plan`]）：
        // 两处分歧的形态是「探了一整轮、提交时才拒、不计熔断、90 秒后重来」。三态里只有
        // `HotSwitchable` 放行，另两态同归 `NotEligible`（本腿不区分「要重启」与「判不了」：
        // 两者都是不许在这里提交，而重试由下一轮心跳负责）。
        let CandidateSwitchPlan::HotSwitchable {
            switched: new_runtime,
            plan: hot_plan,
            new_cfg,
        } = self.candidate_switch_plan(&old_runtime, candidate)
        else {
            return AutoHotSwitchOutcome::NotEligible;
        };
        let new_cfg = *new_cfg;

        // 在持有 switch_serial 时原子复核并只写 selectedServerId。其它 writer 仍可先写盘，但其广播会
        // 排在本事务之后；闭包再次核对当前选择、候选仍存在且连接指纹未变，任何一项漂移即让位。
        let target_id = candidate.id.clone();
        let expected_fingerprint = expected_candidate_fingerprint.to_string();
        let persisted = self.config.update(|latest| {
            // 显式用户选择也在同一个 ConfigManager 写事务内 bump；因此本检查到 claim 之间没有
            // “同目标但更新意图”可穿过。只比较 selectedServerId 无法分辨这种所有权交接。
            if self.selector_reconcile.intent_generation() != starting_intent_generation {
                return Decision::Skip(None);
            }
            if latest.get("selectedServerId").and_then(Value::as_str) != Some(expected_current_id)
                || current_server_fingerprints(latest).get(&target_id)
                    != Some(&expected_fingerprint)
            {
                return Decision::Skip(None);
            }
            let Some(object) = latest.as_object_mut() else {
                return Decision::Skip(None);
            };
            let intent_generation = self.register_selector_intent();
            object.insert(
                "selectedServerId".to_string(),
                Value::String(target_id.clone()),
            );
            Decision::Write(Some(intent_generation))
        });
        let intent_generation = match persisted {
            Ok((Some(intent_generation), Some(_))) => intent_generation,
            Ok((None, None)) => return AutoHotSwitchOutcome::Superseded,
            Ok(_) => unreachable!("auto failover persistence decision must agree"),
            Err(error) => {
                log::warn!("自动故障切换：保存目标出口失败：{error}");
                return AutoHotSwitchOutcome::Failed;
            }
        };

        let interrupt = new_cfg.interrupt_connections_on_switch == Some(true);
        let applied_disconnects = match SwitchExecutor.execute(api, &hot_plan, interrupt).await {
            HotSwitchOutcome::Applied { disconnect } => {
                Some(disconnect.map_or(0, |result| result.closed_ids.len()))
            }
            other => {
                log::warn!("自动故障切换：selector 热切失败（{other:?}），禁止回退整核重启");
                None
            }
        };
        if !self.selector_operation_is_current(generation, intent_generation) {
            self.selector_reconcile.mark_required();
            log::info!("自动故障切换：target PUT 后 selector 所有权已交接 → 不恢复、不回滚 D");
            return AutoHotSwitchOutcome::Superseded;
        }

        // PUT 回执不是最终真值：读回 sing-box 当前 group，只有实际指向目标成员才提交成功事件。
        let groups_after_target = if applied_disconnects.is_some() {
            api.groups_snapshot().await.ok()
        } else {
            None
        };
        if !self.selector_operation_is_current(generation, intent_generation) {
            self.selector_reconcile.mark_required();
            log::info!("自动故障切换：target 自证后 selector 所有权已交接 → 不恢复、不回滚 D");
            return AutoHotSwitchOutcome::Superseded;
        }
        let attested = groups_after_target.is_some_and(|groups| {
            groups
                .iter()
                .any(|group| group.tag == "proxy-selector" && group.selected == candidate.tag)
        });
        // PUT 在 await 期间配置 writer 仍可前进；因此自证不只读 selector，还要再次核对目标指纹与
        // staged 遮罩。候选若恰被订阅替换/用户编辑，哪怕 PUT 已成功也必须恢复旧出口，不能把运行核
        // 里的旧参数成员冒充成磁盘里的新节点。
        let staged_after = self.config.staged_node_mask();
        let target_still_clean = !(staged_after.pending
            && (!staged_after.scope_known
                || staged_after.node_ids.contains(candidate.id.as_str())))
            && self
                .config
                .with_current(|latest| {
                    latest.get("selectedServerId").and_then(Value::as_str)
                        == Some(candidate.id.as_str())
                        && current_server_fingerprints(latest).get(&candidate.id)
                            == Some(&expected_fingerprint)
                })
                .unwrap_or(false);
        if attested && target_still_clean {
            // 只有管理面回读与配置 CAS 双重自证后，才把候选提交为 R 的真实选择并刷新依赖出口的
            // 派生状态。PUT 成功但随后回滚的瞬态不应污染 current_config / 解锁 / 出口 IP 缓存。
            self.commit_applied(&new_runtime);
            self.mesh
                .exit_route_reconcile(&new_cfg, new_cfg.enable_ipv6.unwrap_or(false))
                .await;
            if !self.selector_operation_is_current(generation, intent_generation) {
                log::info!("自动故障切换：出口路由对账期间 selector 所有权已交接 → 抑制旧成功通知");
                return AutoHotSwitchOutcome::Superseded;
            }
            self.invalidate_unlock_cache(true, false);
            self.schedule_exit_ip_refresh(true);
            self.reconcile_login_fallback_locked(&switch_guard).await;
            if !self.selector_operation_is_current(generation, intent_generation) {
                return AutoHotSwitchOutcome::Superseded;
            }
            self.push_pending_changes();
            log::info!(
                "自动故障切换：selector 已热切并通过运行态回读，精准断连 {} 条",
                applied_disconnects.unwrap_or_default()
            );
            return AutoHotSwitchOutcome::Applied;
        }

        // 未自证成功则 best-effort 恢复旧 selector。恢复也只走管理 API，不以重启“兜底”。只有运行态
        // 确认回到旧成员后才把 D 的 selectedServerId 回滚，避免盘面声称旧节点而核仍实际指向新节点。
        log::warn!("自动故障切换：目标 selector 未通过运行态回读，尝试恢复原出口");
        let restore_put_ok = api
            .select_outbound("proxy-selector", &old_tag)
            .await
            .is_ok();
        if !self.selector_operation_is_current(generation, intent_generation) {
            self.selector_reconcile.mark_required();
            log::info!("自动故障切换：restore PUT 后 selector 所有权已交接 → 禁止回滚 D");
            return AutoHotSwitchOutcome::Superseded;
        }
        let groups_after_restore = if restore_put_ok {
            api.groups_snapshot().await.ok()
        } else {
            None
        };
        if !self.selector_operation_is_current(generation, intent_generation) {
            self.selector_reconcile.mark_required();
            log::info!("自动故障切换：restore 自证后 selector 所有权已交接 → 禁止回滚 D");
            return AutoHotSwitchOutcome::Superseded;
        }
        let restored = groups_after_restore.is_some_and(|groups| {
            groups
                .iter()
                .any(|group| group.tag == "proxy-selector" && group.selected == old_tag)
        });
        if restored {
            let rollback_target = candidate.id.clone();
            let old_id = expected_current_id.to_string();
            let _ = self.config.update(|latest| {
                if self.selector_reconcile.intent_generation() != intent_generation {
                    return Decision::Skip(false);
                }
                if latest.get("selectedServerId").and_then(Value::as_str)
                    != Some(rollback_target.as_str())
                {
                    return Decision::Skip(false);
                }
                let Some(object) = latest.as_object_mut() else {
                    return Decision::Skip(false);
                };
                object.insert(
                    "selectedServerId".to_string(),
                    Value::String(old_id.clone()),
                );
                Decision::Write(true)
            });
            self.push_pending_changes();
        } else {
            let message = "自动故障切换未能确认目标出口，恢复原出口也失败；正在后台对账运行出口";
            self.set_nonfatal_error(message, code::EXIT_MISMATCH);
            self.push_pending_changes();
            log::error!("{message}");
            return AutoHotSwitchOutcome::ReconcilePending { intent_generation };
        }
        if !self.selector_operation_is_current(generation, intent_generation) {
            AutoHotSwitchOutcome::Superseded
        } else {
            AutoHotSwitchOutcome::Failed
        }
    }

    // ════════════════ C3：自动换节点（节点不可达 → 已加载 clean 候选零重启热切）════════════════
    //
    // 决策全在 [`AutoSwitchMachine`] + 纯选择函数（`runtime/auto_switch.rs`，真值表 + 变异锁死）；
    // 本层只做「专用出口心跳 → 喂决策机 → 复用主核探测池 → selector 热切并回读 → emit」的 I/O。
    // **与崩溃恢复解耦**：
    // 进程崩溃由 `spawn_crash_monitor` 原地重启同节点兜底，本腿只对「核活着但代理链不通」换节点
    // （1:1 移植 上游 AutoSwitchService 的职责边界）。
    //
    // 当前出口经 `probe-proxy-in → proxy-selector` 钉死，不受用户流量规则影响；候选经
    // `probe-in-k → probe-selector-k` 的 CONNECT+warm-TTFB 验证完整协议链。两者均真碰宿主网络，
    // 编排/资格/结果状态用离线测试覆盖，真实数值留 bundled-core 门。

    /// **C3**：核就绪后挂自动换节点心跳（`spawn_tailscale_status_relay` 的世代范式）。
    ///
    /// **无条件挂**（与崩溃监测同接线点），开关在循环内每 tick 读原始配置 `autoSwitchNode` 动态判
    /// （对齐 上游 config-change-handler 的运行期 enable/disable，轮询版——避免动命令层加事件驱动，
    /// 本批禁区 commands/config.rs）。**世代守卫**：核被停/接管（stop/restart 先 bump 世代）→ 退场，
    /// 绝不让旧核的心跳污染新核（探测/切换均先复查世代）。
    ///
    /// `generation_blocked`：本世代自动切换是否整体停摆（`true` ⇒ 不判、不切）。它在**起核处**对本次
    /// 入核的那份配置求得，是**世代常量**而非每 tick 读配置 —— 判据、理由与那道禁 `.current()` 的门见
    /// [`auto_switch_blocked_for_generation`](crate::runtime::auto_switch::auto_switch_blocked_for_generation)。
    ///
    /// 每 tick 的分支裁决在纯函数 [`decide_tick`]（真值表 + 变异锁死）；本方法只做「睡 → 查世代 →
    /// 同步开关 → 喂裁决 → 执行 I/O」。
    pub(super) fn spawn_auto_switch_heartbeat(
        self: &Arc<Self>,
        my_gen: u64,
        probe_proxy_port: Option<u16>,
        generation_blocked: bool,
    ) {
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let mut machine = AutoSwitchMachine::new();
            let tick = Duration::from_millis(HEARTBEAT_INTERVAL_MS);
            log::debug!("自动换节点心跳起（世代 {my_gen}，专用出口探针端口={probe_proxy_port:?}）");
            // 世代常量、**只打一行**（不是每 tick）：停摆是本世代的固定事实，重复播报无新信息。
            if generation_blocked {
                log::info!(
                    "自动换节点本世代不工作：选中的组网节点已关闭外网访问，用户流量整体兜底直连\
                     （而心跳探针恒钉死走 proxy-selector，探的不是用户在走的那条路）"
                );
            }
            loop {
                tokio::time::sleep(tick).await;
                // 世代守卫：核被停/接管 → 退场。
                if me.gate.generation() != my_gen {
                    return;
                }
                // 动态开关（上游 config-change-handler，轮询版）：autoSwitchNode 真才启用。
                let want_enabled = me.auto_switch_enabled();
                if want_enabled && !machine.is_enabled() {
                    machine.enable();
                    log::info!("自动换节点已启用（应用层连通性检测）");
                } else if !want_enabled && machine.is_enabled() {
                    machine.disable();
                    log::info!("自动换节点已禁用");
                }
                // 分支裁决全在纯函数（各腿的理由与「复位/不复位」的分界见 [`decide_tick`] 文档）。
                // 两处运行态在此**无条件求值**：`decide_tick` 的优先级保证前几道拦下时它们的值不被读到，
                // 求值本身则各是一次持锁投影（无深拷贝，同 `auto_switch_enabled` 已有的每 tick 读），
                // 未改任何决策语义。
                let probe_proxy_port = match decide_tick(TickInput {
                    enabled: machine.is_enabled(),
                    switching: machine.is_switching(),
                    core_running: me.core_running(),
                    selected_server_is_real: me.selected_server_is_real(),
                    generation_blocked,
                    probe_proxy_port,
                }) {
                    TickAction::Skip(_) => continue,
                    TickAction::SkipAfterResettingFailures(_) => {
                        machine.reset_failures_only();
                        continue;
                    }
                    TickAction::Probe { probe_proxy_port } => probe_proxy_port,
                };
                // 应用层连通性探测（真机门：真起核 + 碰网络）。
                let alive = probe_proxy_connectivity(probe_proxy_port).await;
                // 探测耗时窗口内可能已被接管 → 复查世代。
                if me.gate.generation() != my_gen {
                    return;
                }
                match machine.on_heartbeat(alive) {
                    HeartbeatOutcome::Trigger => {
                        log::warn!(
                            "连通性连续 {} 次失败 → 触发自动换节点",
                            crate::runtime::auto_switch::MAX_CONSECUTIVE_FAILURES
                        );
                        me.run_auto_switch(&mut machine, "connectivity").await;
                    }
                    HeartbeatOutcome::Recovered { prior } => {
                        log::info!("连通性恢复正常（此前连续失败 {prior} 次）");
                    }
                    HeartbeatOutcome::Failing { failures } => {
                        log::warn!(
                            "连通性检测失败 [{failures}/{}]",
                            crate::runtime::auto_switch::MAX_CONSECUTIVE_FAILURES
                        );
                    }
                    HeartbeatOutcome::Stable => {}
                }
            }
        });
    }

    /// 原始配置 `autoSwitchNode === true`（上游 index.ts:1846 门控）。**从原始 JSON 读**——该字段不在
    /// `UserConfig` 结构体（同 `restartOnNodeChange` / `meshLoginFallbackDirect`，见 `switch_mode` 注）。
    ///
    /// 走 [`ConfigManager::with_current`](crate::runtime::config::ConfigManager::with_current) 而非 `current()`：本方法由自动换节点心跳**每 tick 无条件**
    /// 调用（`HEARTBEAT_INTERVAL_MS`，核在跑就一直跑），而它只要一个 bool —— 为此深拷贝整份配置
    /// （含 200 节点级 `servers`）纯属常驻浪费。闭包内只取字段，不回调任何子系统。
    ///
    fn auto_switch_enabled(&self) -> bool {
        self.config
            .with_current(|c| c.get("autoSwitchNode").and_then(Value::as_bool))
            .ok()
            .flatten()
            .unwrap_or(false)
    }

    /// **自动换节点心跳守卫**（上游 `AutoSwitchService.runHeartbeat`:113-116）：当前选中节点是否真实
    /// 存在于 `servers`。委托纯谓词 [`selected_server_present`]（无选中 / direct 哨兵 `__direct__` 不在
    /// servers / 选中被删 → false）。读配置失败 → false（保守跳过心跳，绝不误切）。
    ///
    /// 与 [`auto_switch_enabled`](Self::auto_switch_enabled) 同属心跳**每 tick 的无条件调用**，故同样走
    /// [`ConfigManager::with_current`](crate::runtime::config::ConfigManager::with_current)：谓词本体只需 `&Value`，不需要 owned 快照。
    fn selected_server_is_real(&self) -> bool {
        self.config
            .with_current(selected_server_present)
            .unwrap_or(false)
    }

    /// **C3 换节点执行体**。闸门（熔断/冷却/在飞）决策全在
    /// [`AutoSwitchMachine::evaluate_switch`]；放行后只测运行核 clean 候选 → 选最优 →
    /// [`Self::auto_hot_switch_transaction`] 做零重启提交并回读自证 → emit。**真机门**（真起核 + 碰网络）。
    async fn run_auto_switch(self: &Arc<Self>, machine: &mut AutoSwitchMachine, reason: &str) {
        match machine.evaluate_switch(monotonic_now_ms()) {
            SwitchGate::Proceed => {}
            SwitchGate::InFlight => return,
            SwitchGate::Breaker { remaining_ms } => {
                log::warn!(
                    "自动切换已熔断（连续切换未恢复连通），{}s 内暂停切换，请检查网络/订阅",
                    remaining_ms.div_ceil(1000)
                );
                return;
            }
            SwitchGate::Cooldown { remaining_ms } => {
                log::info!(
                    "自动换节点冷却中，{}s 后可再次触发",
                    remaining_ms.div_ceil(1000)
                );
                return;
            }
        }
        // 放行 → 进入在飞态（提前置 lastSwitchTime → 失败/无候选也进冷却，防空转，上游 :180-181）。
        machine.begin_switch(monotonic_now_ms());
        let switched = self.do_switch_io(machine, reason).await;
        // 真发生了切换 → 记账熔断窗口（上游 :233-236）；候选空/全不可达的早退不记（对齐 上游 两个 return）。
        if switched {
            machine.record_switch_success(monotonic_now_ms());
        }
        // finally：退出在飞态（上游 :257-259）。
        machine.end_switch();
    }

    /// 换节点的纯 I/O 段：取 D/R/S 快照 → 规划运行核 clean 候选 → 经主核 probe pool 做真实协议链探测
    /// → 只热切 selector → 运行态回读 → emit。返回 `true` 仅表示整条事务已自证成功。
    ///
    /// # 为什么要把 `machine` 借进来（而不是让调用方按返回值决定）
    ///
    /// 唯一的用途是「候选全被『需要重启』剔光」这条告警的**每世代一次**锁存（见
    /// [`AutoSwitchMachine::claim_restart_blocked_report`]）。另一条路是把返回值从 `bool` 换成结局
    /// 枚举、由已持有 machine 的 [`run_auto_switch`](Self::run_auto_switch) 决定报不报 —— 但本方法有
    /// 十余处 `return false` 早退，它们彼此并无语义差别（调用方只关心「切没切成」），为一条腿把它们
    /// 全部变成具名变体，是为一个锁存位付一次全函数改写。锁存位本身又恰恰是**世代作用域的决策态**，
    /// 与 `is_switching` / `last_switch_time` 同类，`AutoSwitchMachine` 就是它的归宿。故取「多借一个
    /// `&mut`」这条更小的改动面，判据与锁存两者仍都是决策层的纯逻辑（各自有真值表锁死）。
    async fn do_switch_io(self: &Arc<Self>, machine: &mut AutoSwitchMachine, reason: &str) -> bool {
        let generation = self.core_generation();
        let config = match self.config.current() {
            Ok(c) => c,
            Err(e) => {
                log::warn!("自动换节点：读配置失败 → 跳过：{e}");
                return false;
            }
        };
        let Some(runtime_config) = self
            .current_config
            .read()
            .ok()
            .and_then(|guard| guard.clone())
        else {
            log::warn!("自动故障切换：运行核缺少 current_config 基准 → 跳过");
            return false;
        };
        let current_id = runtime_config
            .get("selectedServerId")
            .and_then(Value::as_str)
            .map(str::to_string);
        let Some(current_id) = current_id else {
            return false;
        };
        // D 与 R 的当前选择不同意味着已有保存/广播/切换在排队。自动治理不得在这个缝里另立第三个意图。
        if config.get("selectedServerId").and_then(Value::as_str) != Some(current_id.as_str()) {
            log::info!("自动故障切换：磁盘期望出口与运行核出口不同 → 让位给既有待应用事务");
            return false;
        }
        let staged = self.config.staged_node_mask();
        if staged.pending && !staged.scope_known {
            log::info!("自动故障切换：存在范围未知的未保存草稿 → 保守跳过本轮");
            return false;
        }
        let Some(targets) = self.speed_probe_targets() else {
            log::warn!("自动故障切换：主核探测池未就绪，拒绝回退裸 TCP 候选探测");
            return false;
        };
        let current_fingerprints = current_server_fingerprints(&config);
        let not_ready_ids: BTreeSet<String> = config
            .get("servers")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|server| {
                let id = server.get("id").and_then(Value::as_str)?;
                let is_tailscale =
                    server.get("protocol").and_then(Value::as_str) == Some("tailscale");
                (is_tailscale
                    && !self
                        .mesh
                        .ts_status_event(id)
                        .as_ref()
                        .is_some_and(TailscaleStatusEvent::exit_ready))
                .then(|| id.to_string())
            })
            .collect();
        let mut candidate_plan = plan_runtime_candidates(
            &config,
            Some(&current_id),
            &targets.id_to_tag,
            &targets.fingerprints,
            &current_fingerprints,
            &staged.node_ids,
            &not_ready_ids,
        );
        // 探测**之前**剔除切不过去的候选（判据同提交事务）。放在这里而不是让它们探完再被最后一道门
        // 拒：被拒的那轮 `do_switch_io` 返 false 不计熔断，整轮全量探测白跑、90 秒后原样重来。
        //
        // 返 false = 本轮无从判定（核已停/被接管、运行核基准过期）⇒ **直接早退且不上报**：那时
        // `status` 刚被 `ProxyStatus::default()` 清零，往里写一条非致命错误会被渲染端判成终态故障，
        // 而用户刚点的是停止。
        if !self.retain_hot_switchable_candidates(generation, &runtime_config, &mut candidate_plan)
        {
            log::info!("自动故障切换：候选资格判定期间内核已停或被接管 → 本轮作废");
            return false;
        }
        if candidate_plan.candidates.is_empty() {
            log::warn!(
                "自动故障切换：无可验证的运行态候选（草稿={} 未入核={} 参数脏={} 未就绪={} 不可作出口={} 需重启={}）",
                candidate_plan.staged,
                candidate_plan.not_loaded,
                candidate_plan.dirty,
                candidate_plan.not_ready,
                candidate_plan.not_exit,
                candidate_plan.needs_restart
            );
            // 自动切换**真的触发了**（连通性连续 3 次失败）、候选也规划出来了，却被上一行那道剔除
            // 剃光 ⇒ 故障切换实际什么也没做，而用户完全无感。这是可行动的（手动换节点 / 重启代理让
            // 新配置入核），故上屏；候选为空的另外四因不上屏（判据与理由见 `switch_blocked_by_restart`）。
            //
            // **两个合取项的顺序是判据的一部分**：先问「这轮该不该报」（纯函数、无副作用），
            // 再认领上报权（有副作用）。反过来写会让任何一轮候选为空的早退都吃掉本世代唯一那次
            // 上报权，真该报的那轮反而静默 —— 那是把锁存装反。
            if switch_blocked_by_restart(&candidate_plan) && machine.claim_restart_blocked_report()
            {
                self.set_nonfatal_error(RESTART_BLOCKED_MESSAGE, code::AUTO_SWITCH_NEEDS_RESTART);
            }
            return false;
        }
        log::info!(
            "[{reason}] 经主核探测池验证 {} 个 clean 候选（排除：草稿={} 未入核={} 参数脏={} 未就绪={} 不可作出口={} 需重启={}）",
            candidate_plan.candidates.len(),
            candidate_plan.staged,
            candidate_plan.not_loaded,
            candidate_plan.dirty,
            candidate_plan.not_ready,
            candidate_plan.not_exit,
            candidate_plan.needs_restart
        );
        let probe_input: Vec<(String, String)> = candidate_plan
            .candidates
            .iter()
            .map(|candidate| (candidate.id.clone(), candidate.tag.clone()))
            .collect();
        let url = resolve_speed_test_url(&config);
        let latencies = match probe_runtime_candidates(self, &targets, &probe_input, &url).await {
            RuntimeProbeBatch::Completed(latencies) => latencies,
            RuntimeProbeBatch::Busy => {
                log::info!("自动故障切换：用户测速正在占用 probe pool → 本轮让位");
                return false;
            }
            RuntimeProbeBatch::Interrupted => {
                log::info!("自动故障切换：候选探测期间内核世代变化 → 本轮作废");
                return false;
            }
        };
        if self.core_generation() != generation || !self.core_running() {
            return false;
        }
        let measured: Vec<CandidateLatency> = candidate_plan
            .candidates
            .iter()
            .map(|candidate| CandidateLatency {
                id: candidate.id.clone(),
                name: candidate.name.clone(),
                latency_ms: latencies.get(&candidate.id).copied().flatten(),
            })
            .collect();

        let Some(best) = select_best_candidate(&measured) else {
            log::warn!("所有运行态 clean 候选均未通过真实代理链探测，无法自动切换");
            // 与「候选被剃光」那条**同码同锁存**：对用户而言两种现场的可行动性完全相同 —— 有
            // `needs_restart` 个节点本来能救场，只是被切换门挡在探测之外，而他无从得知。
            // 区分项仍只有 `needs_restart > 0` 这一条，故不会因为「探测全败」本身多报一条
            // （那件事用户下不了手，只该进日志）。
            if candidate_plan.needs_restart > 0 && machine.claim_restart_blocked_report() {
                self.set_nonfatal_error(RESTART_BLOCKED_MESSAGE, code::AUTO_SWITCH_NEEDS_RESTART);
            }
            return false;
        };
        let best_latency = best.latency_ms.unwrap_or(0);
        log::info!("选中最优节点: {} ({best_latency}ms)", best.name);

        let Some(payload) = switch_payload(best, reason) else {
            log::warn!("自动换节点：候选缺少有效延迟 → 跳过");
            return false;
        };
        let Some(candidate) = candidate_plan
            .candidates
            .iter()
            .find(|candidate| candidate.id == best.id)
        else {
            return false;
        };
        let Some(expected_fingerprint) = current_fingerprints.get(&candidate.id) else {
            return false;
        };
        match self
            .auto_hot_switch_transaction(generation, &current_id, candidate, expected_fingerprint)
            .await
        {
            AutoHotSwitchOutcome::Applied => {}
            AutoHotSwitchOutcome::Busy => {
                log::info!("自动故障切换：生命周期事务在飞 → 本轮让位");
                return false;
            }
            AutoHotSwitchOutcome::Superseded => {
                log::info!("自动故障切换：配置、草稿或内核世代已变化 → 本轮作废");
                return false;
            }
            AutoHotSwitchOutcome::NotEligible => {
                log::warn!("自动故障切换：目标不再满足零重启热切条件 → 跳过");
                return false;
            }
            AutoHotSwitchOutcome::ReconcilePending { intent_generation } => {
                self.spawn_selector_reconciliation(generation, intent_generation);
                return false;
            }
            AutoHotSwitchOutcome::Failed => return false,
        }
        log::info!("自动换节点已自证成功: {}", payload.new_server_name);

        // emit（未接线 emitter：单测 / setup 前 → 静默跳过，对齐既有 emit 腿）。
        if let Some(emitter) = self.error_emitter.get() {
            emitter.emit_auto_node_switched(&payload);
        }
        true
    }
}

/// **C3**：应用层连通性检测：只经钉死到 `proxy-selector` 的专用 HTTP 入站，以绝对 URI GET
/// generate_204，任一端点返回 2xx/3xx → 判通。该入口不经过用户路由规则，因此结果只描述当前代理出口，
/// 不会被一条 direct 分流伪装成“节点健康”。**真机门**：需真起核 + 碰网络。
async fn probe_proxy_connectivity(probe_proxy_port: u16) -> bool {
    for url in CONNECTIVITY_URLS {
        if probe_through_proxy(probe_proxy_port, url).await {
            return true;
        }
    }
    false
}

/// 经指定的本地 HTTP 探针入口以绝对 URI GET 目标，判是否拿到 2xx/3xx。调用方负责保证该入口
/// 固定路由到待测出口；这里仅实现通用 HTTP 代理握手。**真机门**：需真起核 + 碰网络，禁本机单测。
async fn probe_through_proxy(proxy_port: u16, target_url: &str) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // 取 Host 头（`http://<host>/path` → `<host>`）。
    let host = target_url
        .strip_prefix("http://")
        .and_then(|rest| rest.split('/').next())
        .unwrap_or("");
    if host.is_empty() {
        return false;
    }
    let request = format!(
        "GET {target_url} HTTP/1.1\r\nHost: {host}\r\nProxy-Connection: close\r\nConnection: close\r\n\r\n"
    );
    let addr = format!("127.0.0.1:{proxy_port}");
    let probe = async {
        let mut stream = tokio::net::TcpStream::connect(&addr).await.ok()?;
        stream.write_all(request.as_bytes()).await.ok()?;
        // 只需状态行（`HTTP/1.1 204 No Content`）；读一小段即可解析首行。
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.ok()?;
        let text = std::str::from_utf8(&buf[..n]).ok()?;
        let code: u32 = text.split_whitespace().nth(1)?.parse().ok()?;
        Some((200..400).contains(&code))
    };
    matches!(
        tokio::time::timeout(Duration::from_millis(CONNECTIVITY_TIMEOUT_MS), probe).await,
        Ok(Some(true))
    )
}
