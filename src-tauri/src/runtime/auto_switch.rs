//! **C3 自动换节点决策层**（上游 `AutoSwitchService` 的纯逻辑镜像）。
//!
//! # 职责边界（与崩溃恢复解耦——1:1 移植 上游 头注）
//! 只负责「当前节点不可达」时换到更优节点。**进程崩溃由 [`ProxyRuntime`](crate::runtime::proxy) 的
//! 崩溃监测「原地重启同节点」兜底，绝不触发换节点**——崩溃多为瞬时/配置问题，换节点既不对症又会丢失
//! 用户选中节点（上游 AutoSwitchService.ts:4-6）。故本层**不消费** `spawn_crash_monitor`，只消费
//! 「应用层连通性」这个独立信号。
//!
//! # 为什么把决策抽成纯状态机
//! 「别过度触发（一次瞬断不该切）也别欠触发」+「重试阈值/冷却/熔断」是本任务的核心正确性，而它们
//! 全是**与网络 I/O 无关的时序决策**。抽成纯 [`AutoSwitchMachine`] + 纯选择函数 → 触发判定 / 冷却 /
//! 熔断 / 下一节点选择全部可用真值表单测 + 变异验证锁死，**无需真起核、不碰宿主网络**（网络探测 I/O
//! 留在 `proxy.rs` 驱动层，真机门）。范式对齐同仓 `CrashRecoveryMachine`（决策在 crate、I/O 在 runtime）。
//!
//! # 常量（逐一对齐 上游 AutoSwitchService.ts:29-40）
//! 阈值/冷却/熔断窗口全部照搬，偏离即语义漂移。

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use polaris_config_engine::builder::route::mesh_selected_exit_falls_back_to_direct;
use polaris_config_engine::user_config::app_config::UserConfig;

/// 心跳检测间隔（上游 `HEARTBEAT_INTERVAL_MS`，:29）。
pub const HEARTBEAT_INTERVAL_MS: u64 = 30_000;
/// 连续失败触发换节点的阈值（上游 `MAX_CONSECUTIVE_FAILURES`，:30）。
/// **别过度触发的核心**：单次瞬断只累加计数，连续 3 次才切。
pub const MAX_CONSECUTIVE_FAILURES: u32 = 3;
/// 换节点冷却窗口（上游 `SWITCH_COOLDOWN_MS`，:32）。防频繁切换。
pub const SWITCH_COOLDOWN_MS: u64 = 60_000;
/// 应用层连通性探测超时（上游 `CONNECTIVITY_TIMEOUT_MS`，:33）。
pub const CONNECTIVITY_TIMEOUT_MS: u64 = 5_000;
/// 熔断阈值：连续自动切换达此数仍未恢复 → 暂停（上游 `MAX_AUTO_SWITCHES`，:34）。
pub const MAX_AUTO_SWITCHES: u32 = 3;
/// 熔断冷却：触发后暂停切换的时长，10 分钟后放行一次重试（上游 `BREAKER_COOLDOWN_MS`，:35）。
pub const BREAKER_COOLDOWN_MS: u64 = 10 * 60_000;
/// 经代理请求的连通性探测端点（返回 204）：海外可达即证明代理链通；多个互为兜底
/// （上游 `CONNECTIVITY_URLS`，:37-40）。
pub const CONNECTIVITY_URLS: [&str; 2] = [
    "http://cp.cloudflare.com/generate_204",
    "http://www.gstatic.com/generate_204",
];

/// 一次心跳连通性检测喂入决策机后的结论（上游 `runHeartbeat` 的分支）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatOutcome {
    /// 连通且此前无失败 → 稳态，无动作。
    Stable,
    /// 连通但此前有连续失败 → 复位计数（连通性恢复正常）。`prior` = 复位前的失败次数（供日志）。
    Recovered { prior: u32 },
    /// 未连通但未达阈值 → 累加失败计数，暂不切。`failures` = 累加后的连续失败次数。
    Failing { failures: u32 },
    /// 连续失败达阈值 → 触发换节点（失败计数已在内部复位，对齐 上游 :142）。
    Trigger,
}

/// 换节点前的闸门评估结果（上游 `triggerSwitch` 前半：isSwitching / 熔断 / 冷却）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchGate {
    /// 放行——可执行换节点。
    Proceed,
    /// 已有换节点在飞 → 跳过（上游 isSwitching 守卫）。
    InFlight,
    /// 熔断中（连续切换未恢复）→ 暂停。`remaining_ms` = 距放行剩余时间。
    Breaker { remaining_ms: u64 },
    /// 冷却中 → 暂停。`remaining_ms` = 距可再触发剩余时间。
    Cooldown { remaining_ms: u64 },
}

/// 自动换节点决策状态机（上游 `AutoSwitchService` 的时序态，纯逻辑无 I/O）。
///
/// 每个运行核世代一个实例（随核就绪 `enable`、随核停/接管退场丢弃）——对齐 上游 单例但按世代重置。
#[derive(Debug)]
pub struct AutoSwitchMachine {
    enabled: bool,
    /// 连续连通性失败次数（上游 `consecutiveFailures`）。
    consecutive_failures: u32,
    /// 换节点在飞标志（上游 `isSwitching`）：同一时刻只允许一个换节点操作。
    is_switching: bool,
    /// 上次换节点的单调时钟刻度（ms）；`None` = 本世代尚未切换。
    last_switch_time: Option<u64>,
    /// 连续自动切换次数（上游 `consecutiveSwitches`），熔断计数。
    consecutive_switches: u32,
    /// 熔断触发的单调时钟刻度（ms）。
    breaker_tripped_at: Option<u64>,
    /// 本世代是否已上报过「候选全被『切过去要整核重启』剔光」（见
    /// [`claim_restart_blocked_report`](Self::claim_restart_blocked_report)）。
    restart_blocked_reported: bool,
}

impl Default for AutoSwitchMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl AutoSwitchMachine {
    #[must_use]
    pub fn new() -> Self {
        Self {
            enabled: false,
            consecutive_failures: 0,
            is_switching: false,
            last_switch_time: None,
            consecutive_switches: 0,
            breaker_tripped_at: None,
            restart_blocked_reported: false,
        }
    }

    /// 认领本世代**唯一一次**「候选全被『切过去要整核重启』剔光」的上报权：首次调返 `true`，
    /// 其后恒 `false`。判据本身是纯函数 [`switch_blocked_by_restart`]，本方法只管「报几次」。
    ///
    /// # 锁存为什么必须在这里
    ///
    /// 上报走 `set_nonfatal_error`，而 `status.error` 是**单槽覆盖**、每次落值都 `log::error` +
    /// emit `event:proxyError`。触发面每约 90 秒（3 次心跳失败）就原样复现一次 ⇒ 不锁存 = 用户每
    /// 90 秒吃一次 toast + 桌面通知，而事实一条都没变。
    ///
    /// **「本世代」正好是这个事实的有效期**：候选切不过去，是因为运行核**这一份**配置装不下它们；
    /// 换一份配置只能靠整核重启，而重启即换世代。本机每世代新建一个实例
    /// （`proxy/auto_switch.rs` 的 `spawn_auto_switch_heartbeat` 里 `AutoSwitchMachine::new()`），
    /// 故复位不需要任何显式代码，也不存在「忘了复位」的形态。
    ///
    /// **[`enable`](Self::enable) 刻意不复位它**：那是开关的运行期切换（用户在设置里关了又开），
    /// 不是新世代；让它跟着复位等于给「关一下再开」留了一条重复报警的路。同理 `disable` 也不动它。
    pub fn claim_restart_blocked_report(&mut self) -> bool {
        if self.restart_blocked_reported {
            return false;
        }
        self.restart_blocked_reported = true;
        true
    }

    /// 启用（上游 `enable`，:63-71）：复位失败/熔断计数。幂等（已启用则 no-op）。
    pub fn enable(&mut self) {
        if self.enabled {
            return;
        }
        self.enabled = true;
        self.consecutive_failures = 0;
        self.consecutive_switches = 0;
        self.breaker_tripped_at = None;
    }

    /// 禁用（上游 `disable`，:73-78）。幂等。
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    #[must_use]
    pub fn is_switching(&self) -> bool {
        self.is_switching
    }

    /// 核未运行时只复位失败计数、**不动熔断计数**（上游 `runHeartbeat` 的 `!running` 分支，:107-110）。
    pub fn reset_failures_only(&mut self) {
        self.consecutive_failures = 0;
    }

    /// 喂一次心跳连通性结果 → 决策（上游 `runHeartbeat` 的 alive/失败分支，:122-145）。
    ///
    /// - `alive=true`：复位连续失败 **且** 复位熔断计数（恢复联通即视为已稳定，上游 :130-132）。
    /// - `alive=false`：累加失败；达 [`MAX_CONSECUTIVE_FAILURES`] → 复位失败计数并返 [`Trigger`]
    ///   （上游 :141-143：先 `consecutiveFailures = 0` 再 `triggerSwitch`）。
    ///
    /// [`Trigger`]: HeartbeatOutcome::Trigger
    pub fn on_heartbeat(&mut self, alive: bool) -> HeartbeatOutcome {
        if alive {
            let prior = self.consecutive_failures;
            self.consecutive_failures = 0;
            // 恢复联通即视为已稳定，复位熔断计数（上游 :132）。
            self.consecutive_switches = 0;
            if prior > 0 {
                HeartbeatOutcome::Recovered { prior }
            } else {
                HeartbeatOutcome::Stable
            }
        } else {
            self.consecutive_failures += 1;
            if self.consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                self.consecutive_failures = 0;
                HeartbeatOutcome::Trigger
            } else {
                HeartbeatOutcome::Failing {
                    failures: self.consecutive_failures,
                }
            }
        }
    }

    /// 换节点前闸门（上游 `triggerSwitch` :151-178）：**顺序即语义**——
    /// 1. 在飞 → [`InFlight`]（上游 :151-154）。
    /// 2. 熔断：连续切换达 [`MAX_AUTO_SWITCHES`] 且仍在 [`BREAKER_COOLDOWN_MS`] 内 → [`Breaker`]；
    ///    冷却结束 → 复位 `consecutive_switches` 放行一次重试（上游 :157-170）。
    /// 3. 冷却：距上次换节点 < [`SWITCH_COOLDOWN_MS`] → [`Cooldown`]（上游 :173-178）。
    /// 4. 否则 [`Proceed`]。
    ///
    /// **有副作用**（熔断冷却结束的复位），故 `&mut self`——与 上游 在 triggerSwitch 内联复位同构。
    ///
    /// [`InFlight`]: SwitchGate::InFlight
    /// [`Breaker`]: SwitchGate::Breaker
    /// [`Cooldown`]: SwitchGate::Cooldown
    /// [`Proceed`]: SwitchGate::Proceed
    pub fn evaluate_switch(&mut self, now: u64) -> SwitchGate {
        if self.is_switching {
            return SwitchGate::InFlight;
        }
        // 熔断检查（先于冷却，对齐 上游 顺序）。
        if self.consecutive_switches >= MAX_AUTO_SWITCHES {
            let since_trip = self
                .breaker_tripped_at
                .map_or(BREAKER_COOLDOWN_MS, |at| now.saturating_sub(at));
            if since_trip < BREAKER_COOLDOWN_MS {
                return SwitchGate::Breaker {
                    remaining_ms: BREAKER_COOLDOWN_MS - since_trip,
                };
            }
            // 冷却结束，复位熔断，放行一次重试（上游 :169）。
            self.consecutive_switches = 0;
        }
        // 冷却检查。
        if let Some(last_switch_time) = self.last_switch_time {
            let since_last = now.saturating_sub(last_switch_time);
            if since_last < SWITCH_COOLDOWN_MS {
                return SwitchGate::Cooldown {
                    remaining_ms: SWITCH_COOLDOWN_MS - since_last,
                };
            }
        }
        SwitchGate::Proceed
    }

    /// 闸门放行后进入换节点在飞态（上游 `triggerSwitch` :180-181：置 `isSwitching` + `lastSwitchTime`）。
    /// **无论成功与否都提前置 `lastSwitchTime`** → 失败/无候选也进入冷却，防在节点间空转（上游 同构）。
    pub fn begin_switch(&mut self, now: u64) {
        self.is_switching = true;
        self.last_switch_time = Some(now);
    }

    /// 换节点**真正执行了一次切换**后记账（上游 `triggerSwitch` :233-236）：
    /// `consecutive_switches++`，达 [`MAX_AUTO_SWITCHES`] → 记熔断触发时刻。
    ///
    /// **只在真发生切换时调**（候选空 / 全不可达的早退不调，对齐 上游 那两个 `return` 不增计数）。
    pub fn record_switch_success(&mut self, now: u64) {
        self.consecutive_switches += 1;
        if self.consecutive_switches >= MAX_AUTO_SWITCHES {
            self.breaker_tripped_at = Some(now);
        }
    }

    /// 换节点结束，退出在飞态（上游 `triggerSwitch` finally :257-259：`isSwitching = false`）。
    /// 成功/失败/早退都必须调（对齐 finally 语义）。
    pub fn end_switch(&mut self) {
        self.is_switching = false;
    }
}

// ════════════════ 本世代整体停摆的判据（选中节点关外网）════════════════

/// 本世代自动故障切换是否整体停摆（`true` ⇒ 不判、不切）。
///
/// **判据只此一条**：[`mesh_selected_exit_falls_back_to_direct`] —— 选中的组网节点关了外网，
/// 用户流量整体兜底 `direct`。判据不在这里重写，直接复用生成侧那个谓词（与 `route.rs` 决定
/// `user_exit_tag` 的是同一个调用）。
///
/// # 为什么是「不判」而不是「判了切不动」
///
/// 此时心跳探的**不是用户在走的那条路**：探针经 `probe-proxy-in` **恒钉死**到 `proxy-selector`
/// （`config-engine/src/builder/route.rs` 的 A2 探针钉死路由），而用户流量的 `user_exit_tag` 已被
/// 兜底成 `direct`。探针结论与用户体验无关 ⇒ 拿它切节点是用假信号做真动作。
///
/// 仓内**完全同构的先例**：`ui/src/domain/endpoint-routes.ts` 的 `isSpeedTestable` 用
/// `isMeshNode(s) && !meshAllowsInternet(s)` 恒排除测速，理由是「无公网出口 = 探测必进黑洞、必假
/// 超时」。本函数是同一条推理在**心跳**上的对称补齐：测速与心跳都是「经公网探一下」，被排除的
/// 节点集合必须一致，否则同一个节点会「不给测速、却照样被心跳判死并切走」。
///
/// # 曾经有第二条判据，是方向性错误（撤回登记）
///
/// 2026-09 一度把 `config-engine` 的 `sel_only_forces_subnets`（组网资格 ×
/// `alwaysRouteSubnets=false` × 段非空）也算作停摆原因。那三项里**没有** `allow_internet`：一个
/// `allowInternet=true` 且填了 `meshRoutes` 的 WireGuard 节点会命中它 —— 而那是承载公网的全隧道
/// 节点，隧道死了用户就断网，探针路径正是用户路径。把它整条心跳静音，等于亲手造出本批要消灭的
/// 那类盲区：心跳不探 ⇒ 探不到故障 ⇒ 不上报 ⇒ 前端的组网隧道健康总门也判无异常，三面静默。
/// `sel_only_forces_subnets` 表达的是**热切可行性**（切到/离开它要增删段规则 ⇒ 退回重启），
/// 不是「探针无意义」，两者不可互推。这类节点的正确处置是：心跳照跑 → 探到故障 → 热切守卫把
/// 候选全部剔掉 → [`switch_blocked_by_restart`] 上报「需手动换节点」。
///
/// # 为什么必须是世代常量，而不是每 tick 读配置
///
/// 1. **语义上就该取生成时的值**：用户流量走哪由 `route.final` 决定，而 `final` 是核启动时那份配置
///    烘死的，同世代内不可能变。每 tick 去读磁盘期望态 D 反而会错 —— 「已保存未 Apply」窗口里 D
///    与运行核已脱节，读 D 得到的是一个还没生效的判据。
/// 2. **判据翻转即重启**：`config-engine/src/builder/hotswitch.rs` 的 route 投影 guard 一见
///    [`mesh_selected_exit_falls_back_to_direct`] 两侧翻转就返回 `HotSwitchPlan::none()` ⇒ 走整核
///    重启 ⇒ 世代 +1 ⇒ 旧心跳退场、新心跳带新判据起。故「世代内常量」不是近似，是结构性事实。
/// 3. **硬约束**：`runtime/proxy/tests/ts_exit.rs` 的
///    `periodic_legs_read_config_by_projection_not_full_clone` 明禁常驻周期腿出现 `.current()`。
///    per-tick 反序列化成 [`UserConfig`] 需要 owned `Value` ⇒ 直接撞门；改在 `with_current` 闭包里
///    clone 整份配置 ⇒ 正是那道门要禁的深拷贝换个形态。
#[must_use]
pub fn auto_switch_blocked_for_generation(config: &UserConfig) -> bool {
    mesh_selected_exit_falls_back_to_direct(config)
}

// ════════════════ 每 tick 决策（纯函数 + 动作枚举）════════════════

/// 一次心跳 tick 的输入快照（全部布尔/常量，无 I/O）。
///
/// `enabled` / `switching` 取自 [`AutoSwitchMachine`]（`enabled` 是**已同步过** `want_enabled`
/// 之后的值）；`core_running` / `selected_server_is_real` 取自运行时；`generation_blocked` 是
/// [`auto_switch_blocked_for_generation`] 在起核时求得的**世代常量**；`probe_proxy_port` 同为世代常量。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TickInput {
    pub enabled: bool,
    pub switching: bool,
    pub core_running: bool,
    pub selected_server_is_real: bool,
    pub generation_blocked: bool,
    pub probe_proxy_port: Option<u16>,
}

/// 本 tick 被跳过的原因（只用于真值表断言与诊断，生产腿不打日志——每 30s 一条噪声）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// `autoSwitchNode` 关（或刚被关掉）。
    Disabled,
    /// 换节点在飞中（上游 `runHeartbeat` 的 `isSwitching` 守卫）。
    Switching,
    /// 核未运行 → 等退场或恢复（复位失败计数但**不动熔断**，上游 `runHeartbeat` :107-110）。
    CoreNotRunning,
    /// 选中节点不在 `servers`：direct（`__direct__` 不在 servers）/ block 哨兵 / 选中被删 / 无选中
    /// （上游 `AutoSwitchService.runHeartbeat`:113-116）。不探测/不计失败/不切走 —— 否则 direct 下
    /// 的网络抖动会被当成「当前节点不通」→ 自动切到某代理节点（用户明明选的是直连），把「换节点」
    /// 误用到一个根本不是节点的选择上。
    SelectionNotReal,
    /// 本世代整体停摆（见 [`auto_switch_blocked_for_generation`]）。原因只有一条，
    /// 由心跳起处**打一行**日志播报，故本变体不带载荷。
    GenerationBlocked,
    /// 专用出口探针端口未分配。这是本世代的固定事实；保持启用态但**不伪造 mixed 口为等价探针**
    /// （mixed 口走用户流量规则，探到的不是钉死出口）。
    NoProbePort,
}

/// 一次 tick 的裁决。**跳过分两类**，区别就是失败计数复不复位 —— 这正是本模块出过的那类缺陷：
/// 不复位会把停摆期间的陈旧计数留到恢复之后，一次失败即触发切换。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickAction {
    /// 跳过本 tick，**保留**连续失败计数。
    Skip(SkipReason),
    /// 跳过本 tick，先 [`AutoSwitchMachine::reset_failures_only`] 再跳过。
    SkipAfterResettingFailures(SkipReason),
    /// 执行连通性探测（端口已确证）。
    Probe { probe_proxy_port: u16 },
}

/// 每 tick 的决策（纯函数，逐字保持 2026-09 前循环体内那串 `if … continue` 的分支与优先级）。
///
/// 优先级即原顺序：`Disabled → Switching → CoreNotRunning → SelectionNotReal →
/// GenerationBlocked → NoProbePort → Probe`。新增的 `GenerationBlocked` 插在
/// `SelectionNotReal` 之后、端口解构之前。
///
/// # 复位失败计数的分界（为什么 `SelectionNotReal` 与 `GenerationBlocked` 不同类）
///
/// `GenerationBlocked` 对齐的是 `NoProbePort` / `CoreNotRunning` 那两条**复位**腿：本世代结构性
/// 探不了 ⇒ 停摆期间不该攒失败计数。**不**对齐 `SelectionNotReal` 的裸跳过 —— 那条腿不复位，
/// 而切到 `__direct__` 是**热切、不换世代** ⇒ 决策机实例存活 ⇒ 计数被冻结在切走前的值 ⇒ 切回真实
/// 节点后一次失败即达阈值触发。那是**同根因的姊妹腿**，本批不修（改它要连带重算 direct 期间的
/// 语义），在此登记以免下一个读者以为两条腿的差异是刻意取舍。
///
/// # 世代守卫与 enable/disable 不在本函数里
///
/// 前者是 `return`（退出整个 task，不是一次 tick 的动作）、后者是对状态机的写操作且带日志，
/// 两者都留在驱动层；本函数只裁决「本 tick 探不探、跳过要不要复位」。
#[must_use]
pub fn decide_tick(input: TickInput) -> TickAction {
    if !input.enabled {
        return TickAction::Skip(SkipReason::Disabled);
    }
    if input.switching {
        return TickAction::Skip(SkipReason::Switching);
    }
    if !input.core_running {
        return TickAction::SkipAfterResettingFailures(SkipReason::CoreNotRunning);
    }
    if !input.selected_server_is_real {
        return TickAction::Skip(SkipReason::SelectionNotReal);
    }
    if input.generation_blocked {
        return TickAction::SkipAfterResettingFailures(SkipReason::GenerationBlocked);
    }
    match input.probe_proxy_port {
        Some(probe_proxy_port) => TickAction::Probe { probe_proxy_port },
        None => TickAction::SkipAfterResettingFailures(SkipReason::NoProbePort),
    }
}

/// 候选节点及其测得延迟（上游 `{ server, latency }`）。`latency_ms=None` = 不可达。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateLatency {
    pub id: String,
    pub name: String,
    pub latency_ms: Option<u32>,
}

/// 当前运行核中可做端到端探测、且参数与磁盘期望态一致的候选。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeCandidate {
    pub id: String,
    pub name: String,
    pub tag: String,
}

/// 候选规划结果。**每个被排除的节点只落进一个计数**（按 staged → 未入核 → 参数脏 → 运行态未就绪
/// → 不可作出口 → 需重启的顺序裁定，先命中先归属）—— 互斥是按**节点**说的；一轮里多个计数同时为正
/// 完全正常（见 [`switch_blocked_by_restart`]）。只用于诊断，不把节点详情写日志。
///
/// 各计数之和与 `servers` 长度**不构成恒等式**：`plan_runtime_candidates` 对没有 `id` 的条目直接
/// 跳过且不计数，而「减去当前出口」也只在当前出口确实在 `servers` 里时才成立。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeCandidatePlan {
    pub candidates: Vec<RuntimeCandidate>,
    pub staged: usize,
    pub not_loaded: usize,
    pub dirty: usize,
    pub not_ready: usize,
    /// **自动切换永远不该切过去**而被静默排除的候选数：候选自身是只走内网的组网节点
    /// （`is_mesh_node && !mesh_node_carries_full_tunnel`）。切过去公网流量就整体兜底直连 ——
    /// 那不是「换了个能用的节点」，是把用户静默推去明文直连。
    ///
    /// 与 [`not_ready`](Self::not_ready)（TS 未登录/过期）同类：不是「系统帮不上忙」，是「这个节点
    /// 本来就不是出口候选」，故**不入** [`switch_blocked_by_restart`] 的判据。回填侧同
    /// [`needs_restart`](Self::needs_restart)。
    pub not_exit: usize,
    /// 「切过去必须整核重启」而被剔除的候选数。**不由 [`plan_runtime_candidates`] 产生**：
    /// 该判据要拿运行核基准配置重跑一次热切判定（需 `UserConfig` + 运行核快照），而本模块的规划
    /// 函数是只看 `&Value` 的纯函数。故本字段恒由 I/O 侧
    /// （`runtime::proxy::auto_switch` 的 `retain_hot_switchable_candidates`）在探测前回填，
    /// 与它同时把对应候选从 `candidates` 里摘掉。
    ///
    /// **只装「真的需要重启才能切过去」的候选**。「本轮无从判定」（核已停 / 无运行核基准 /
    /// 无热切基准快照 / 基准配置解析不了）不进这里 —— 那些是运行时的属性、不是候选的属性，整轮
    /// 作废即可；把它们记进来就是把「用户刚点了停止」报成「自动切换帮不上忙」。本计数是
    /// [`switch_blocked_by_restart`] 的唯一区分项，掺进别的成因即误报。
    pub needs_restart: usize,
}

/// 从磁盘期望态 D 与运行核快照 R 的交集生成自动故障切换候选。
///
/// 只有同时满足以下条件的节点才进入候选：
/// - 不是当前出口；
/// - 不在渲染端未保存的节点草稿遮罩里；
/// - 已作为当前核 selector 成员加载；
/// - D 的连接指纹与起核快照一致（未编辑、未被订阅替换）；
/// - 协议运行态已就绪（目前用于排除未登录/过期的 Tailscale endpoint）。
///
/// 这样候选可以经主核 probe-selector 做真实协议链探测并只走 `SelectOutbound`；D-only/dirty 节点
/// 绝不会靠裸 TCP 猜测可用，也不会为了自动切换把未 Apply 的配置带进一次整核重启。
#[must_use]
pub fn plan_runtime_candidates(
    config: &Value,
    current_id: Option<&str>,
    id_to_tag: &BTreeMap<String, String>,
    running_fingerprints: &BTreeMap<String, String>,
    current_fingerprints: &BTreeMap<String, String>,
    staged_node_ids: &BTreeSet<String>,
    not_ready_ids: &BTreeSet<String>,
) -> RuntimeCandidatePlan {
    let Some(servers) = config.get("servers").and_then(Value::as_array) else {
        return RuntimeCandidatePlan::default();
    };
    let mut plan = RuntimeCandidatePlan::default();
    for server in servers {
        let Some(id) = server.get("id").and_then(Value::as_str) else {
            continue;
        };
        if Some(id) == current_id {
            continue;
        }
        if staged_node_ids.contains(id) {
            plan.staged += 1;
            continue;
        }
        let Some(tag) = id_to_tag.get(id) else {
            plan.not_loaded += 1;
            continue;
        };
        let clean = running_fingerprints
            .get(id)
            .zip(current_fingerprints.get(id))
            .is_some_and(|(running, current)| running == current);
        if !clean {
            plan.dirty += 1;
            continue;
        }
        if not_ready_ids.contains(id) {
            plan.not_ready += 1;
            continue;
        }
        plan.candidates.push(RuntimeCandidate {
            id: id.to_string(),
            name: server
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or(id)
                .to_string(),
            tag: tag.clone(),
        });
    }
    plan
}

/// 本轮自动故障切换是否**恰恰只因「切过去要整核重启」而落空** —— 也就是这件事该不该告诉用户。
///
/// # 两个合取项，缺一不可
///
/// - `candidates.is_empty()`：只要还剩候选，本轮就真去探、真去切了 —— 那条路上「探测全败但
///   `needs_restart > 0`」另有一处同码同锁存的上报（`do_switch_io` 的 `select_best_candidate`
///   早退），不归本判据管。
/// - `needs_restart > 0`：候选为空的成因共六种，另外五种里草稿 / 未入核 / 参数脏 / 未就绪都是
///   **用户自己刚编辑过配置**的可预期后果，不可作出口（[`RuntimeCandidatePlan::not_exit`]）则是
///   「那个节点本来就不该被切过去」—— 都不是「系统帮不上忙」，报出去是噪音。只有本项为正才证明
///   「确实有节点本来能救场，只是切过去得整核重启」，而那正好是用户能动手的地方（手动换一次节点）。
///
/// 去掉后半个合取项，症状是**每次编辑节点草稿都收到一条「自动切换帮不上忙」** —— 把可预期的状态
/// 报成故障，比不报更糟。故 [`RuntimeCandidatePlan::needs_restart`] 与其余五个计数在此**不对称**，
/// 不许被「候选为空就报」这种更短的写法合并掉。
///
/// 六个计数**按节点**互斥，但一轮里可以多项同时为正（草稿与需重启并存很常见），故本判据只问
/// 「需重启这一项有没有份额」，不问它是不是**最大**的那一项：只要有一个节点是被重启挡住的，
/// 那条可行动的路就真实存在。
#[must_use]
pub fn switch_blocked_by_restart(plan: &RuntimeCandidatePlan) -> bool {
    plan.candidates.is_empty() && plan.needs_restart > 0
}

/// 选最优候选（上游 :208-218：过滤不可达 → 按延迟升序 → 取 `available[0]`）。
///
/// 纯函数。入参**已排除当前节点**（由 [`plan_runtime_candidates`] 保证）。全不可达 → `None`。
/// 延迟并列取**首个**（`min_by_key` 稳定返回首元 = 上游 稳定排序取 `[0]`，保候选原序优先）。
#[must_use]
pub fn select_best_candidate(candidates: &[CandidateLatency]) -> Option<&CandidateLatency> {
    candidates
        .iter()
        .filter(|c| c.latency_ms.is_some())
        .min_by_key(|c| c.latency_ms.unwrap_or(u32::MAX))
}

/// 前端 `autoNodeSwitched` 事件 payload（上游 :243-247 `{ reason, newServerName, latency }`）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutoNodeSwitchedPayload {
    /// 触发原因（如「连通性检测」）。
    pub reason: String,
    /// 切到的目标节点显示名。
    pub new_server_name: String,
    /// 目标节点测得延迟（ms）。
    pub latency: u32,
}

/// 由选中的最优候选 + reason 构造切换成功事件（纯函数，上游 :243-247）。
///
/// 配置写入已由运行时 selector 事务单点负责，此处不得再克隆、改写整份配置。
/// `best.latency_ms` 必为 `Some`（[`select_best_candidate`] 已过滤不可达）；理论不可达的 `None`
/// 仍返回 `None`，避免发出伪造的 0ms 成功事件。
#[must_use]
pub fn switch_payload(best: &CandidateLatency, reason: &str) -> Option<AutoNodeSwitchedPayload> {
    let latency = best.latency_ms?;
    Some(AutoNodeSwitchedPayload {
        reason: reason.to_string(),
        new_server_name: best.name.clone(),
        latency,
    })
}

#[cfg(test)]
mod tests;
