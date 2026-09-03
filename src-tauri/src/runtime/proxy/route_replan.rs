//! 路由重规划域：TUN 出口夺取硬闸（起核前 baseline / 就绪后差分 / 适配器存在性）、旧 TUN 路由
//! 退场等待、网卡事实观测与显式/推断绑定失效判定。
//!
//! L2：只依赖 [`super::platform_contracts`] 与 façade 定义的公共项，被 `network_monitor` /
//! `startup` / `lifecycle` 反向消费（依赖方向见设计 §B.4）。

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use polaris_config_engine::builder::outbounds::required_bind_interfaces;
use polaris_config_engine::user_config::app_config::UserConfig;
use polaris_config_engine::user_config::tun_config::resolve_win_tun_interface_name;
use polaris_config_engine::user_config::ProxyModeType;
use polaris_helper_proto::Platform;
use polaris_platform_events::{route_replan_needed, NetworkChangeImpact, RuntimeBindingPlan};
use polaris_system_integration::error::SystemIntegrationError;
#[cfg(not(target_os = "windows"))]
use polaris_system_integration::route_ops::SystemRouteOps;
use polaris_system_integration::route_ops::{
    verify_exit_captured, ExitCaptureOutcome, PROBE_IP as ROUTE_PROBE_IP,
};

use crate::runtime::route_binding::automatic_runtime_binding_root_ids;

use super::platform_contracts::platform_tag;
// `TUN_ROUTE_NOT_CAPTURED_MSG` 是 façade 的 `*_MSG` 兜底文案（§C 例外①：五条 `*_MSG` 与 `mod code`
// 一并钉死在 façade，不随本域外移），故这一条回掏是**永久面**，见 `tests/module_boundary.rs` 白名单。
use super::{code, ProxyRuntime, TUN_ROUTE_NOT_CAPTURED_MSG};

/// 网卡绑定 fail-closed 的无 i18n 环境兜底；正常 UI 按结构化码显示本地化文案。
/// TUN 出口夺取 post-flight 的 grace 探测次数（复用 ~4s 收敛窗，`route -n get` 每次成本极低）。
/// 与 [`TUN_ROUTE_POLL_INTERVAL`] 相乘 ≈ grace 窗口。**真机门**：sing-box 装路由到出口切换的真实耗时
/// 须 macOS 实测校准（设计 §6），此值为首版保守取。
const TUN_ROUTE_GRACE_POLLS: usize = 8;

/// TUN 出口夺取 post-flight 相邻两次探测间隔。8 × 500ms ≈ 3.5s grace（末次不 sleep）。
const TUN_ROUTE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// TUN 出口夺取硬闸是否适用于本模式。
///
/// **仅 TUN 模式适用**：TUN 装内核 tun + `auto_route` 捕获全部流量 → 成功接管必然把「应走代理的公网
/// 目的」的出口切到我方 utun；systemProxy/manual **不接管 tun**，出口恒在物理网卡 → baseline 差分永不
/// 成立，设闸必误判（假阳性拦掉正常起核）。故这两类列 caveat 不闸（设计 §4.7 分流行）。
pub(super) fn tun_route_gate_applies(mode: ProxyModeType) -> bool {
    mode.is_tun()
}

/// 一张网卡的身份。
///
/// 别名（配置里的 TUN 名 / `route`、`ip` 查出的接口名）与 ifindex（Windows best-route 索引）是**同一张
/// 网卡的两种表示**，哪种可得取决于平台与观测来源：Windows 的出口探测走 ifindex（见
/// [`tun_exit_interface_for_probe`]），配置侧与 macOS/Linux 探测只有别名。
///
/// **为什么必须收进一个类型**：这两种表示此前都装在 `Option<String>` 里，其中一种还被编码成
/// `"ifindex:42"` 这样的伪名字 —— 类型上完全可比、语义上完全不可比。`wait_for_retiring_tun_route`
/// 拿配置别名 `polaris-tun0` 去 `!=` 探测出的 `"ifindex:42"`，首轮必真，等待在 Windows 上从未生效，
/// 且不留任何日志。身份合一后，跨来源的判定只能经 [`Self::same_interface`]，「两种表示互相冒充」在
/// 调用点写不出来。
///
/// `PartialEq`（`==`）的语义是**逐字表示相等**，只用于同一探测通道前后两次观测的差分
/// （[`polaris_system_integration::route_ops::verify_exit_captured`]）；跨来源判同一张网卡一律走
/// [`Self::same_interface`]。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ExitInterfaceId {
    pub(super) alias: Option<String>,
    pub(super) ifindex: Option<u32>,
}

impl ExitInterfaceId {
    /// 空/全空白别名不是身份，返回 `None`（等价于「没观测到」）。
    pub(super) fn from_alias(alias: impl AsRef<str>) -> Option<Self> {
        let alias = alias.as_ref().trim();
        (!alias.is_empty()).then(|| Self {
            alias: Some(alias.to_owned()),
            ifindex: None,
        })
    }

    #[cfg(target_os = "windows")]
    fn from_ifindex(ifindex: u32) -> Self {
        Self {
            alias: None,
            ifindex: Some(ifindex),
        }
    }

    pub(super) fn alias(&self) -> Option<&str> {
        self.alias.as_deref()
    }

    /// 两侧是否指同一张网卡。
    ///
    /// `None` = 两侧没有共同表示 ⇒ **不可比**。调用方不得把它当成「不同」——正是那次静默的
    /// 「不同」把 Windows 的退场等待整条废掉。
    pub(super) fn same_interface(&self, other: &Self) -> Option<bool> {
        if let (Some(mine), Some(theirs)) = (self.ifindex, other.ifindex) {
            return Some(mine == theirs);
        }
        match (self.alias(), other.alias()) {
            (Some(mine), Some(theirs)) => Some(mine == theirs),
            _ => None,
        }
    }

    /// 用**同一张网卡**的另一次观测补齐本身份缺失的表示；已有的表示不被覆盖。
    pub(super) fn merged_with(mut self, other: Option<Self>) -> Self {
        let Some(other) = other else {
            return self;
        };
        if self.alias.is_none() {
            self.alias = other.alias;
        }
        if self.ifindex.is_none() {
            self.ifindex = other.ifindex;
        }
        self
    }
}

/// 查询 TUN 接管判据使用的当前出口接口身份。
///
/// macOS/Linux 沿用 [`polaris_system_integration::route_ops::SystemRouteOps`] 的 `route`/`ip` 查询；
/// Windows 复用 helper crate 已有的 `windows-sys` + IP Helper API，直接取 best-interface index。
/// 旧实现每次都冷启 PowerShell `Find-NetRoute`，真机单次约 1.3–1.7s，而 TUN 健康启动必查起核前/后
/// 两次，单这条诊断链就占约 3s。接口索引是内核稳定身份，且本判据只比较前后是否变化，比本地化的
/// `InterfaceAlias` 更窄、更可靠。
///
/// 返回结构化的 [`ExitInterfaceId`] 而非字符串：索引一旦被 `format!` 成 `"ifindex:N"`，它与别名在
/// 类型上就再也分不开了（根因见该类型文档）。
fn tun_exit_interface_for_probe() -> Result<Option<ExitInterfaceId>, SystemIntegrationError> {
    #[cfg(target_os = "windows")]
    {
        let std::net::IpAddr::V4(ip) = ROUTE_PROBE_IP else {
            return Err(SystemIntegrationError::route(
                "TUN route probe requires an IPv4 destination",
            ));
        };
        polaris_helper::platform::windows::wintun::best_route_interface_index(ip)
            .map(|index| Some(ExitInterfaceId::from_ifindex(index)))
            .map_err(|e| SystemIntegrationError::route(e.to_string()))
    }
    #[cfg(not(target_os = "windows"))]
    {
        polaris_system_integration::production_route_ops()
            .exit_interface_for(ROUTE_PROBE_IP)
            .map(|alias| alias.and_then(ExitInterfaceId::from_alias))
    }
}

const RETIRING_TUN_ROUTE_POLL_INTERVAL: Duration = Duration::from_millis(25);
const RETIRING_TUN_ROUTE_MAX_POLLS: usize = 40;

/// 旧 TUN 路由退场等待的结局。三态各自可辨，缺一就会让「没等」冒充「等到了」。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RetiringTunRouteOutcome {
    /// 探到出口已不再是退场中的旧 TUN（`polls` = 达成时的累计探测次数）。
    Retired { polls: usize },
    /// 界内每一次探测都仍指向旧 TUN。
    TimedOut { polls: usize },
    /// 压根没进入等待，附原因。
    Skipped(&'static str),
}

/// 退场等待的判定本体（与系统探测解耦，便于离线覆盖三态）。
///
/// `probe` 返回本次观测到的出口身份，`None` = 探测不可读。判据用
/// [`ExitInterfaceId::same_interface`]：
/// - `Some(false)`（确知不是旧 TUN）与 `None`（探测不可读）都算退场 —— 后者沿用旧行为，
///   读不到出口时不再空等满界；
/// - 身份不可比（两侧没有共同表示）不是「不同」，直接 `Skipped`，绝不伪装成一次成功的等待。
pub(super) async fn wait_for_retiring_tun_route_outcome<P, F>(
    retiring_interface: Option<&ExitInterfaceId>,
    max_polls: usize,
    poll_interval: Duration,
    mut probe: P,
) -> RetiringTunRouteOutcome
where
    P: FnMut() -> F,
    F: std::future::Future<Output = Option<ExitInterfaceId>>,
{
    let Some(retiring_interface) = retiring_interface else {
        return RetiringTunRouteOutcome::Skipped("no_managed_tun_interface");
    };
    let polls = max_polls.max(1);
    for poll in 0..polls {
        let observed = probe().await;
        let Some(observed) = observed else {
            return RetiringTunRouteOutcome::Retired { polls: poll + 1 };
        };
        match retiring_interface.same_interface(&observed) {
            Some(true) => {}
            Some(false) => return RetiringTunRouteOutcome::Retired { polls: poll + 1 },
            // 别名 vs ifindex 这类跨表示比较无解：等下去只会等满界再谎称超时。
            None => return RetiringTunRouteOutcome::Skipped("incomparable_interface_identity"),
        }
        if poll + 1 < polls {
            tokio::time::sleep(poll_interval).await;
        }
    }
    RetiringTunRouteOutcome::TimedOut { polls }
}

pub(super) fn managed_tun_interface_for_network_watcher(
    config: &UserConfig,
    platform: Platform,
) -> Option<String> {
    if !config.proxy_mode_type.is_tun() {
        return None;
    }
    match platform {
        Platform::Win => Some(resolve_win_tun_interface_name(
            config
                .tun_config
                .as_ref()
                .and_then(|tun| tun.interface_name.as_deref()),
        )),
        Platform::Linux => Some(polaris_helper_proto::linux_dns::TUN_INTERFACE_NAME.to_owned()),
        // macOS utunN 由内核动态分配，本层没有可靠名字；其 watcher 在核完成路由安装后才订阅。
        Platform::Mac | Platform::Other => None,
    }
}

/// 本次会话实际由 Polaris 管理的 TUN 接口。
///
/// Windows/Linux 有稳定配置名，别名一律以它为准（watcher 订阅与文本匹配只认这个名字）；macOS 的
/// `utunN` 只能在 post-flight 路由闸成功后得知，故整份身份都由捕获值给出。非 TUN 模式即使误传了
/// 捕获值也必须返回 `None`。
///
/// **两种表示在此合流**：`captured` 是路由闸判定「出口已切到我方」之后的那次探测，Windows 上它就是
/// 本会话 TUN 的 ifindex。把它并进配置别名，退场等待才能在探测口径（ifindex）上直接比较，而不必
/// 拿别名去撞索引。捕获值不可读时身份只剩别名，比较会诚实地报「不可比」。
///
/// # `captured` 是差分结果，不是身份断言（已知假设，故意不在这里修）
///
/// [`ExitCaptureOutcome::Captured`] 的判据是 `crates/system-integration/src/route_ops.rs` 的
/// `exit_changed`：**出口从 baseline 变了**，仅此而已。它**不断言**「变成的是我方 TUN」——
/// 那条腿连我方 TUN 叫什么都不知道（macOS 的 `utunN` 正是因为不可命名才用差分）。
///
/// 于是有一条明确的误并路径：grace 窗
/// （[`TUN_ROUTE_GRACE_POLLS`] × [`TUN_ROUTE_POLL_INTERVAL`]）内若第三方 VPN 抢先夺走默认路由，
/// 差分照样成立、`Captured` 照样返回，被并进「我方 TUN 身份」的就是**别人的 ifindex**。
///
/// **为什么仍然合并**：不合并的代价是确定的且更大 —— Windows 的配置别名与探测口径（ifindex）
/// 互不可比，`ExitInterfaceId::same_interface` 会一路返回 `None`，退场等待整条失效（那正是
/// [`ExitInterfaceId`] 类型文档记的那次静默失效）。误并的代价则是有界的：
/// 合并后的身份只有两个消费点，
/// ① [`wait_for_retiring_tun_route`](ProxyRuntime::wait_for_retiring_tun_route) —— 最坏是拿错
/// 对象比一轮、空等满
/// [`RETIRING_TUN_ROUTE_MAX_POLLS`] × [`RETIRING_TUN_ROUTE_POLL_INTERVAL`]（40 × 25ms = 1s）后走
/// 超时腿继续，不改变任何后续判定；
/// ② watcher 订阅只取 `alias`（见 `spawn_network_watcher` 调用点），根本不读 ifindex。
///
/// **根治需要新功能面，不属本注释射程**：要消除误并，得让路由闸把「出口是不是我方 TUN」变成
/// **正面断言**（例如按我方 TUN 的 LUID/ifindex 正向比对）而不是 baseline 差分；那会改变
/// `ExitCaptureOutcome` 的判据本身，是新的行为面。在那之前，本函数的前置条件写在这里：
/// **`captured` 只保证「出口变了」，不保证「变成了我方」**。
pub(super) fn managed_tun_interface_for_session(
    config: &UserConfig,
    platform: Platform,
    captured: Option<ExitInterfaceId>,
) -> Option<ExitInterfaceId> {
    if !config.proxy_mode_type.is_tun() {
        return None;
    }
    match managed_tun_interface_for_network_watcher(config, platform) {
        Some(alias) => Some(ExitInterfaceId::from_alias(alias)?.merged_with(captured)),
        None => captured,
    }
}

pub(super) type InterfaceFingerprint = BTreeMap<String, (bool, Vec<String>)>;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct InterfaceUnavailability {
    pub(super) missing: BTreeSet<String>,
    pub(super) down: BTreeSet<String>,
}

impl InterfaceUnavailability {
    pub(super) fn is_empty(&self) -> bool {
        self.missing.is_empty() && self.down.is_empty()
    }

    pub(super) fn diagnostic(&self) -> String {
        format!(
            "{}: missing=[{}], down=[{}]",
            code::OUTBOUND_INTERFACE_UNAVAILABLE,
            self.missing.iter().cloned().collect::<Vec<_>>().join(","),
            self.down.iter().cloned().collect::<Vec<_>>().join(",")
        )
    }
}

#[derive(Debug, Clone, Default)]
pub(super) struct RuntimeBindingState {
    pub(super) plan: RuntimeBindingPlan,
    pub(super) interface_fingerprint: Option<InterfaceFingerprint>,
    pub(super) explicit_unavailable: InterfaceUnavailability,
    /// 本会话实际创建的主 TUN 接口身份。macOS 为动态 utunN；Windows/Linux 为稳定配置名，Windows
    /// 另带路由闸捕获到的 ifindex（退场等待按索引比较）。
    pub(super) managed_tun_interface: Option<ExitInterfaceId>,
}

fn interface_fingerprint(
    interfaces: &[crate::commands::system::NetworkInterfaceInfo],
) -> InterfaceFingerprint {
    interfaces
        .iter()
        .map(|interface| {
            let mut addresses = interface.addresses.clone();
            addresses.sort();
            addresses.dedup();
            (interface.name.clone(), (interface.is_up, addresses))
        })
        .collect()
}

pub(super) fn interface_availability(fingerprint: &InterfaceFingerprint) -> BTreeMap<String, bool> {
    fingerprint
        .iter()
        .map(|(name, (is_up, _))| (name.clone(), *is_up))
        .collect()
}

pub(super) fn required_interfaces_unavailable(
    required: &BTreeSet<String>,
    fingerprint: &InterfaceFingerprint,
) -> InterfaceUnavailability {
    let mut unavailable = InterfaceUnavailability::default();
    for name in required {
        match fingerprint.get(name) {
            Some((true, _)) => {}
            Some((false, _)) => {
                unavailable.down.insert(name.clone());
            }
            None => {
                unavailable.missing.insert(name.clone());
            }
        }
    }
    unavailable
}

fn relevant_interface_fingerprint(
    fingerprint: &InterfaceFingerprint,
    plan: &RuntimeBindingPlan,
) -> InterfaceFingerprint {
    let names: BTreeSet<&str> = plan.bindings.values().map(String::as_str).collect();
    fingerprint
        .iter()
        .filter(|(name, _)| names.contains(name.as_str()))
        .map(|(name, state)| (name.clone(), state.clone()))
        .collect()
}

fn interface_fingerprints_differ(
    previous: &InterfaceFingerprint,
    current: &InterfaceFingerprint,
    ignored_interface: Option<&str>,
) -> bool {
    previous
        .iter()
        .filter(|(name, _)| ignored_interface != Some(name.as_str()))
        .ne(current
            .iter()
            .filter(|(name, _)| ignored_interface != Some(name.as_str())))
}

pub(super) fn inferred_binding_replan_needed(
    impact: &NetworkChangeImpact,
    plan: &RuntimeBindingPlan,
    previous: Option<&InterfaceFingerprint>,
    current: Option<&InterfaceFingerprint>,
    ignored_interface: Option<&str>,
) -> bool {
    // 与默认出口一致的根没有写 `bind_interface`，由 sing-box 原生接口监控关闭旧连接并让新连接
    // 跟随默认路由；Polaris 不应为它们整核重启。只有特殊逐目的绑定或上次无法判定的根需要在
    // 物理路由事件后撤 TUN 重算。事件源能给出目标前缀时，先按本会话 probe IP 做相关性过滤；
    // 只有事件源无法给出前缀时才保守沿用“存在特殊/未解析根即重算”。
    let bound_interface_unavailable = current.is_some_and(|fingerprint| {
        plan.bindings
            .values()
            .any(|interface| match fingerprint.get(interface) {
                Some((is_up, _)) => !is_up,
                None => true,
            })
    });
    if route_replan_needed(impact, plan) || bound_interface_unavailable {
        return true;
    }
    if !impact.interface {
        return false;
    }
    let (Some(previous), Some(current)) = (previous, current) else {
        return false;
    };
    if !plan.unresolved_roots.is_empty() {
        interface_fingerprints_differ(previous, current, ignored_interface)
    } else {
        relevant_interface_fingerprint(current, plan)
            != relevant_interface_fingerprint(previous, plan)
    }
}

pub(super) fn runtime_binding_roots_covered(
    config: &UserConfig,
    plan: &RuntimeBindingPlan,
) -> bool {
    automatic_runtime_binding_root_ids(config).is_subset(&plan.covered_roots)
}

/// **#327**：本次起核是否该做 wintun 适配器探测（纯谓词，供单测 + 变异）。
///
/// 唯一消费者是起核就绪后的存在性探测 [`ProxyRuntime::probe_tun_adapter_present`]。抽成独立谓词而不是
/// 内联进那个 `async fn`：判定本身与 Windows API、tokio 都无关，抽出来才跑得进本机单测（见下方平台入参）。
///
/// 两条都必须成立：
/// - **TUN 模式**：只有 TUN 会建 wintun 适配器；systemProxy/manual 根本不碰它，探了必然恒 `Absent`
///   —— 那不是白等，是把一次完全正常的起核判成失败。
/// - **Windows**：wintun 是 Windows 专属，`WinAdapterProbe` 枚举的也只是 Windows 适配器
///   （mac 用 utun、Linux 用 tun 设备，创建语义与命名谱系都不同，由各自的腿处理——mac 的双 utun
///   竞态走的是 `resolve_start_retry_budget` 放宽预算那条）。
///
/// 平台从 [`platform_tag`] 取（`win32`，Node 约定）而非 `cfg!(windows)`：让判定在**任何 host 上都可测**，
/// 而不是变成本机永远跑不到的 cfg 死代码（同 `resolve_start_retry_budget` 收平台入参的手法）。
#[must_use]
pub(super) fn should_probe_wintun_adapter(mode: ProxyModeType, platform: &str) -> bool {
    mode.is_tun() && platform == "win32"
}

/// **#327**：一条起核腿对「TUN 适配器是否已建出」的观测结果（判定的**唯一输入**，不含运行期状态）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TunAdapterObservation {
    /// 枚举到了本次配置的适配器名。
    Present,
    /// 有界轮询内始终没枚举到。
    #[cfg(any(windows, test))]
    Absent,
    /// **不可断言**：非 TUN@Windows / 接口名不在可枚举前缀面内 / 枚举 API 报错 / 探测任务 join 失败。
    /// 一律按放行处理 —— 判据坏掉时误拦一次正常起核，比漏检一次假连接更糟（同
    /// [`ProxyRuntime::verify_tun_route_captured`] 的 `Indeterminate` 纪律）。
    Indeterminate,
}

/// **#327**：单条起核腿的 TUN 适配器判定（纯函数，形态对齐既有的 `classify_child_exit`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TunAdapterVerdict {
    /// 放行（见到适配器 / 不可断言）。
    Proceed,
    /// 本腿失败，但预算还有 → 计入重试预算，杀核后重来一腿。
    RetryLeg,
    /// 预算耗尽，且**整个起核过程中一次都没见过**适配器 → 终态 [`code::TUN_ADAPTER_MISSING`]。
    TerminalNeverAppeared,
    /// 预算耗尽，但**中途见过**适配器（建出来又消失/反复）→ 终态，但**不冒充**「网卡建不出来」。
    #[cfg(any(windows, test))]
    TerminalAfterFlap,
}

/// **#327**：起核就绪后的适配器存在性判定（纯函数：吃观测值 + 累积事实 + 预算，不现查任何运行期状态）。
///
/// # 为什么是「逐腿判 + 计入重试预算」，而不是就绪门里多一条判据，也不是循环后单次硬闸
///
/// - **不塞进就绪门**（`core-supervisor::wait_for_core_ready`）：那是纯轮询骨架、跨平台共用，塞一条
///   Windows 专属的网卡判据进去，等于让所有平台的就绪语义为一个平台的怪癖买单；且它拿不到本次
///   config 解出的接口名。
/// - **不学 `verify_tun_route_captured` 放到循环之后单次执行**：那条的失败是「他方 VPN 占路由」，
///   重试同一件事没有意义，故硬终止是对的。本条的失败恰恰**是重试能治的**——网卡挂载失败多为瞬态
///   （驱动/句柄尚未就位），而重试腿开头的 `kill_core` 会把这一次的核连同它半建的网卡一并清掉，
///   下一腿是干净的重来。放循环外 = 把一个可自愈的瞬态判成终态。
/// - **`ever_seen` 必须跨腿累积**：只看本腿会把「第 1 腿建出来了、第 3 腿抖没了」误报成
///   「wintun 根本建不出来」，把用户导向「重装驱动」这条错误的下一步。见过一次就永远不是那条结论。
///
/// 重试条件 `attempt <= max_retries` 与 Dead/Timeout 两腿逐字一致（预算的定义在
/// [`StartRetryBudget::max_retries`](super::startup::StartRetryBudget::max_retries)：总尝试 = max_retries + 1）。
#[must_use]
pub(super) fn classify_tun_adapter_leg(
    observation: TunAdapterObservation,
    ever_seen: bool,
    attempt: u32,
    max_retries: u32,
) -> TunAdapterVerdict {
    #[cfg(not(any(windows, test)))]
    let _ = (ever_seen, attempt, max_retries);
    match observation {
        TunAdapterObservation::Present | TunAdapterObservation::Indeterminate => {
            TunAdapterVerdict::Proceed
        }
        #[cfg(any(windows, test))]
        TunAdapterObservation::Absent if attempt <= max_retries => TunAdapterVerdict::RetryLeg,
        #[cfg(any(windows, test))]
        TunAdapterObservation::Absent if ever_seen => TunAdapterVerdict::TerminalAfterFlap,
        #[cfg(any(windows, test))]
        TunAdapterObservation::Absent => TunAdapterVerdict::TerminalNeverAppeared,
    }
}

impl ProxyRuntime {
    /// 读取系统接口事实。观测失败返回 `None`，调用方必须 fail-open：它不能被解释成“所有接口都消失”。
    pub(super) async fn observe_network_interfaces(&self) -> Option<InterfaceFingerprint> {
        match tokio::task::spawn_blocking(crate::commands::system::list_network_interfaces_blocking)
            .await
        {
            Ok(observed) if !observed.is_empty() => Some(interface_fingerprint(&observed)),
            Ok(_) => {
                log::warn!("网卡事实观测未取得任何接口 → 不据此改变绑定状态");
                None
            }
            Err(error) => {
                log::warn!("网卡事实观测任务失败: {error} → 不据此改变绑定状态");
                None
            }
        }
    }

    /// 重启的 helper stop 回包只保证旧核已收割；TUN 路由从内核表退场仍可能晚几十毫秒。若立刻规划，
    /// 节点目标与默认探针会同时命中旧 TUN，于是被误判为 native，恢复后也不会再绑定真实 VPN 网卡。
    /// 这里按事实轮询“公网探针已不再走旧 TUN”，健康路径首查即过，不引入固定 sleep。
    ///
    /// 结局三态全部落日志（判定见 [`wait_for_retiring_tun_route_outcome`]）：此前 `matched` 只在
    /// `polls>0` 时记、`skipped` 一行不记，于是「等到了」与「压根没等」在日志上不可区分 —— Windows
    /// 上每次都是后者，却没人看得出来。
    pub(super) async fn wait_for_retiring_tun_route(
        &self,
        retiring_interface: Option<&ExitInterfaceId>,
    ) {
        let outcome = wait_for_retiring_tun_route_outcome(
            retiring_interface,
            RETIRING_TUN_ROUTE_MAX_POLLS,
            RETIRING_TUN_ROUTE_POLL_INTERVAL,
            || async {
                tokio::task::spawn_blocking(|| tun_exit_interface_for_probe().ok().flatten())
                    .await
                    .unwrap_or(None)
            },
        )
        .await;
        match outcome {
            RetiringTunRouteOutcome::Retired { polls } => log::info!(
                "旧 TUN 路由已退场：matched interface={retiring_interface:?} polls={polls}"
            ),
            RetiringTunRouteOutcome::TimedOut { polls } => log::warn!(
                "旧 TUN 路由退场等待超时：timeout interface={retiring_interface:?} polls={polls} \
                 界值={}ms → 后续规划保守降级，起核重试继续兜底",
                RETIRING_TUN_ROUTE_POLL_INTERVAL.as_millis() * polls as u128
            ),
            RetiringTunRouteOutcome::Skipped(reason) => log::info!(
                "旧 TUN 路由退场等待跳过：skipped(reason={reason}) interface={retiring_interface:?}"
            ),
        }
    }

    /// command 持久化前的同步网卡门。仅 selector 写事务使用：先从**候选配置**算活跃显式接口，
    /// 无要求时零系统调用；有要求才枚举系统事实。枚举失败沿用起核门的契约——不把“观测不到”误判成
    /// “接口不存在”，后续 sing-box 仍会自身 fail-closed。
    pub(crate) fn validate_required_bind_interfaces_blocking(
        &self,
        user_config: &UserConfig,
    ) -> Result<(), String> {
        let required = required_bind_interfaces(user_config);
        if required.is_empty() {
            return Ok(());
        }
        let observed = crate::commands::system::list_network_interfaces_blocking();
        if observed.is_empty() {
            log::warn!("网卡事实观测未取得任何接口 → 不据此拒绝 selector 持久化");
            return Ok(());
        }
        let fingerprint = interface_fingerprint(&observed);
        let unavailable = required_interfaces_unavailable(&required, &fingerprint);
        unavailable
            .is_empty()
            .then_some(())
            .ok_or_else(|| unavailable.diagnostic())
    }

    /// 校验 config-engine 本次生成实际会引用的 `bind_interface`。
    ///
    /// 生成侧优先级由 [`required_bind_interfaces`] 单点给出；本层只对照系统事实，不复制策略。接口枚举
    /// 失败（空结果 / task join 失败）时跳过前置门，让 sing-box 自己 fail-closed，绝不能因为观测失败
    /// 就把用户配置清空或改走系统默认出口。
    pub(super) async fn validate_required_bind_interfaces(
        &self,
        user_config: &UserConfig,
    ) -> Result<(), String> {
        let required = required_bind_interfaces(user_config);
        if required.is_empty() {
            return Ok(());
        }
        let Some(observed) = self.observe_network_interfaces().await else {
            return Ok(());
        };
        let unavailable = required_interfaces_unavailable(&required, &observed);
        unavailable
            .is_empty()
            .then_some(())
            // message 是诊断载荷，不承担用户文案；渲染端按结构化 errorCode 走 locale。
            .ok_or_else(|| unavailable.diagnostic())
    }

    /// C-tun-conflict：起核**前**快照「应走代理的公网目的」出口接口（post-flight 差分锚点）。
    ///
    /// 非 TUN 模式 → `None`（不设闸，见 [`tun_route_gate_applies`]）。TUN 模式经 `spawn_blocking` 跑
    /// [`tun_exit_interface_for_probe`]（同步系统查询不阻塞 async runtime）；读失败 → `None`
    /// （判定层按「不可断言」不闸，避免假阳性）。**必须在任何 spawn 之前**：此刻我方 utun 尚未上线，
    /// 查到的是「Polaris 起核前」的出口（物理网卡或他方 VPN 的 utun）——差分的基准。
    pub(super) async fn capture_tun_route_baseline(
        &self,
        mode: ProxyModeType,
    ) -> Option<ExitInterfaceId> {
        if !tun_route_gate_applies(mode) {
            return None;
        }
        let iface = tokio::task::spawn_blocking(|| tun_exit_interface_for_probe().ok().flatten())
            .await
            .unwrap_or(None);
        log::info!("TUN 出口 baseline（起核前 {ROUTE_PROBE_IP} 出口）= {iface:?}");
        iface
    }

    /// C-tun-conflict：起核就绪**后**的出口归属硬闸（方向①后验；设计 §4.2）。
    ///
    /// 就绪门只验「进程活 + 管理 API 环回口可连」，**不验默认路由归属** → 其他 VPN 占着默认路由时，
    /// 我方 utun 抢不到流量却照样判就绪 = 假报「已连接」。此处在 grace 窗口内轮询出口接口，按 baseline
    /// 差分判定是否真夺到路由：
    /// - 非 TUN 模式 / baseline 不可读 / grace 内探到出口切走 → `Ok(interface)`（放行；可读时同时
    ///   返回本会话实际 TUN 接口，供启动期快照与网络 watcher 排除自身事件）。
    /// - grace 耗尽出口仍 == baseline（他方 VPN 占路由 / 我方路由装失败，一网打尽）→ `Err(msg)`
    ///   （调用方 `kill_core` + `set_error(TUN_ROUTE_NOT_CAPTURED)` 拒绝标 running；设计 D1 硬闸 / D2 延后标）。
    ///
    /// 探测 + grace sleep 全在 `spawn_blocking`（同步 CommandRunner + `thread::sleep`），不占 async runtime。
    pub(super) async fn verify_tun_route_captured(
        &self,
        mode: ProxyModeType,
        baseline: Option<ExitInterfaceId>,
    ) -> Result<Option<ExitInterfaceId>, String> {
        if !tun_route_gate_applies(mode) {
            return Ok(None);
        }
        let outcome = tokio::task::spawn_blocking(move || {
            verify_exit_captured(
                baseline,
                TUN_ROUTE_GRACE_POLLS,
                tun_exit_interface_for_probe,
                || std::thread::sleep(TUN_ROUTE_POLL_INTERVAL),
            )
        })
        .await
        .unwrap_or(ExitCaptureOutcome::Indeterminate);

        match outcome {
            ExitCaptureOutcome::Captured { interface } => {
                log::info!("TUN 出口夺取成功：{ROUTE_PROBE_IP} 出口已切到 {interface:?}");
                Ok(interface)
            }
            // 不可断言（baseline/探测不可读）→ 不闸：宁可漏检也不误拦正常起核（设计 §4.7）。
            ExitCaptureOutcome::Indeterminate => {
                log::warn!(
                    "TUN 出口 post-flight 不可断言（baseline/探测不可读）→ 不闸，按 caveat 放行"
                );
                Ok(None)
            }
            ExitCaptureOutcome::NotCaptured { baseline, last } => {
                log::error!(
                    "TUN 出口未夺到：grace 内 {ROUTE_PROBE_IP} 出口始终未从 baseline 切走\
                     （baseline={baseline:?} last={last:?}）→ 硬闸拒绝标 connected"
                );
                Err(TUN_ROUTE_NOT_CAPTURED_MSG.to_string())
            }
        }
    }

    /// **#327**：起核**就绪后**正向验证本次 TUN 适配器真被建出来（每条重试腿各验一次）。
    ///
    /// # 缺陷原形
    ///
    /// 就绪门（[`wait_ready`](Self::wait_ready) → `core-supervisor::wait_for_core_ready`）的三条判据
    /// —— 管理 API 环回口可连、进程活、未被接管 —— 没有一条与 TUN 网卡有关。于是「sing-box 活着、
    /// mixed 入站正常、wintun 适配器从未创建」会被判成起核成功：用户看到「已连接」，TUN 却完全没生效
    /// （上游侧的同一形态表现为无限「正在自动重试」）。
    ///
    /// # 与 [`verify_tun_route_captured`](Self::verify_tun_route_captured) 的分工（两者互不重叠，别合并）
    ///
    /// | 层 | 时机 | 判据 | 失败处置 |
    /// |---|---|---|---|
    /// | **本方法** | 就绪**后**、逐腿 | 这一张建出来没（正向枚举） | 计入重试预算，耗尽报 [`code::TUN_ADAPTER_MISSING`] |
    /// | [`verify_tun_route_captured`](Self::verify_tun_route_captured) | 全部重试**之后**一次 | 默认路由归属差分 | 硬终止，报 [`code::TUN_ROUTE_NOT_CAPTURED`] |
    ///
    /// （曾经还有第三层「spawn 前等上一张 wintun 释放」，#159。已删：sing-tun 的 `New()` 撞
    /// `os.ErrExist` 会 `OpenAdapter` 复用同名网卡，残留适配器本就不阻断起核，那条腿只是白等。）
    ///
    /// 顺序也不能对调：网卡都没有时去问「默认路由切走了没」，答案必然是「没切」，于是用户拿到
    /// 「其他 VPN 占用默认路由，请先断开」——一条与现场毫无关系的指引。先验存在性，才轮得到问归属。
    ///
    /// # `iface` 不在可枚举前缀面内 ⇒ 不可断言（这条漏了会杀正常核）
    ///
    /// `AdapterProbe::list_matching_adapters` 只返回
    /// `PROBE_PREFIXES`（`polaris_helper::platform::windows::wintun`）命中的适配器。用户把
    /// TUN 接口名改成 `my-tun`（`resolve_win_tun_interface_name` 允许）时，我方**永远**枚举不到那张网卡
    /// → 若据此判「没建出来」，就会把一次完全正常的起核杀掉。故先过
    /// `adapter_name_is_probeable`（`polaris_helper::platform::windows::wintun`）
    /// （与枚举实现共用同一谓词），看不见就整条跳过。
    ///
    /// 复用起核前那对超时/间隔常量（3s / 200ms）：健康路径上网卡在就绪前就挂好了 ⇒ 首次枚举即命中、
    /// 零 sleep；异常路径给内核留 3s 挂载余量。为同一件事再引入第二组可调参数不会换来任何东西。
    pub(super) async fn probe_tun_adapter_present(
        &self,
        mode: ProxyModeType,
        iface: &str,
        attempt: u32,
    ) -> TunAdapterObservation {
        if !should_probe_wintun_adapter(mode, platform_tag()) {
            return TunAdapterObservation::Indeterminate; // 非 TUN / 非 Windows → 零系统调用
        }
        log::debug!("起核后验证 wintun 适配器存在性：iface={iface}（第 {attempt} 次尝试）");
        #[cfg(windows)]
        {
            use polaris_helper::platform::windows::wintun::{
                adapter_name_is_probeable, probe_adapter_present, PresenceOutcome, StdSleep,
                WinAdapterProbe, DEFAULT_POLL_INTERVAL, DEFAULT_PROBE_TIMEOUT,
            };
            if !adapter_name_is_probeable(iface) {
                log::info!(
                    "TUN 适配器存在性：接口名 {iface} 不在可枚举前缀面内（自定义名）→ 不可断言，不闸"
                );
                return TunAdapterObservation::Indeterminate;
            }
            // 有界轮询内含 `std::thread::sleep`（最长 DEFAULT_PROBE_TIMEOUT=3s）→ 必须挪出 async worker。
            let expected = iface.to_owned();
            let outcome = tokio::task::spawn_blocking(move || {
                probe_adapter_present(
                    &WinAdapterProbe,
                    &expected,
                    DEFAULT_PROBE_TIMEOUT,
                    DEFAULT_POLL_INTERVAL,
                    &StdSleep,
                )
            })
            .await;
            match outcome {
                Ok(PresenceOutcome::Present) => {
                    log::info!("TUN 适配器已建出：{iface}");
                    TunAdapterObservation::Present
                }
                Ok(PresenceOutcome::Absent { seen }) => {
                    log::error!(
                        "TUN 适配器未建出：{iface} 在 {DEFAULT_PROBE_TIMEOUT:?} 内始终未出现\
                         （同前缀可见适配器：{}）",
                        if seen.is_empty() {
                            "无".to_owned()
                        } else {
                            seen.join(", ")
                        }
                    );
                    TunAdapterObservation::Absent
                }
                // 枚举 API 坏了 / 任务 join 失败 → 判据本身不可用，绝不据此杀核。
                Ok(PresenceOutcome::Error(e)) => {
                    log::warn!("TUN 适配器枚举失败（{e}）→ 不可断言，不闸");
                    TunAdapterObservation::Indeterminate
                }
                Err(e) => {
                    log::warn!("TUN 适配器探测任务 join 失败：{e} → 不可断言，不闸");
                    TunAdapterObservation::Indeterminate
                }
            }
        }
        // 非 Windows 编译单元：上面的 `should_probe_wintun_adapter` 已恒假早退，此处仅作类型收口。
        #[cfg(not(windows))]
        TunAdapterObservation::Indeterminate
    }
}
