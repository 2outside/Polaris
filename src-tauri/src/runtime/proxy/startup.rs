//! 起核编排（`proxy.rs` §A 拆分的 `startup` 域，L4 顶层）。
//!
//! 收纳「从用户配置到一个跑起来的 sing-box 进程」这条链的全部编排：内核闸门缓存、config 生成与
//! `sing-box check` 剥除、端口解析、helper 提权门、spawn 与就绪等待、起核后的状态提交与后台腿挂载、
//! 出口自证。本模块只是**换了个文件**——B9 批的验收判据是逐行内容与拆分前一致（§E-R5）。

use super::code;
use super::core_binary::resolve_dashboard_serve_dir;
// `resolve_core_binary` 只被 `core_binary_for_start` 的 `cfg(not(test))` 腿消费（单测态那腿刻意
// deny-by-default，不回落解析器）⇒ 不 gate 即测试编译单元的 `unused_imports`。
#[cfg(not(test))]
use super::core_binary::resolve_core_binary;
use super::core_log::{
    config_log, config_on_degraded, log_axes_from_config, pipe_to_log, settle_start_failure,
    CoreFatalSlot, CoreLogHandoff,
};
use super::dns_takeover::dns_takeover_enabled;
use super::lifecycle::{now_ms, sleep_unless_superseded_on};
use super::platform_contracts::{enumerate_own_lan_cidrs, platform_tag};
use super::process_supervision::pid_alive;
use super::route_replan::{
    classify_tun_adapter_leg, inferred_binding_replan_needed, interface_availability,
    managed_tun_interface_for_session, required_interfaces_unavailable, ExitInterfaceId,
    InterfaceFingerprint, RuntimeBindingState, TunAdapterObservation, TunAdapterVerdict,
};
use super::PROBE_POOL_SIZE;
use super::{ProxyRuntime, ProxyStatus, StartError};
use super::{HELPER_GATE_ABORTED_MSG, HELPER_NOT_INSTALLED_MSG, TUN_ADAPTER_MISSING_MSG};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use polaris_config_engine::builder::custom_rule_files::{
    build_custom_rule_files, is_custom_rule_orphan_file,
};
use polaris_config_engine::builder::endpoint_routes::{
    mesh_system_supported_on_platform, mesh_uses_system_interface,
};
use polaris_config_engine::builder::helpers::ServerLike;
use polaris_config_engine::builder::outbounds::required_bind_interfaces;
use polaris_config_engine::builder::{
    build_id_to_tag_map, generate_sing_box_config_with_report_and_runtime_bindings,
    GenerateConfigDeps, GenerateOutcome, InvalidNode,
};
use polaris_config_engine::singbox::SingBoxConfig;
use polaris_config_engine::user_config::app_config::UserConfig;
use polaris_config_engine::user_config::dns_constants::{is_direct_selection, DIRECT_TAG};
use polaris_config_engine::user_config::proxy_mode::ProxyMode;
use polaris_config_engine::user_config::proxy_ports::{control_api_port, local_proxy_port};
use polaris_config_engine::user_config::server_config::ServerConfig;
use polaris_config_engine::user_config::tun_config::resolve_win_tun_interface_name;
use polaris_config_engine::user_config::ProxyModeType;
use polaris_core_supervisor::port_bookkeeping::{FreePortProvider, TokioPortProvider};
use polaris_core_supervisor::{
    core_ready_budget_ms, core_startup_estimate_ms, decide_peel, run_config_check,
    wait_for_core_ready, CoreReadyDeps, CoreReadyOutcome, KernelRejection, PeelStep, PortAllocator,
    PortExclusions, RejectedArray, SingBoxSpawner, SpawnRequest, StdioPolicy, TokioSpawner,
    WaitForCoreReadyOptions, CORE_STARTUP_PER_NAIVE_MS, INVALID_REASON_KERNEL_REJECTED,
    PEEL_TIME_BUDGET,
};
use polaris_helper_proto::Platform;
use polaris_platform_events::NetworkChangeImpact;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::logging::SING_BOX_TARGET;
use crate::runtime::helper::{HelperStatusSnapshot, HelperStopOps};
use crate::runtime::route_binding::plan_runtime_bindings;

/// 就绪等待预算的**下限**（ms）——上游 `ProxyManager.CORE_READY_TIMEOUT_MS`（:524）那个固定门的原值。
///
/// # 它从「总超时」降级成「下限」，但**这个数一格都不许动**
///
/// 真正的总超时现在由 [`main_core_ready_timeout_ms`] 按本次下发配置的规模算（naive 出站每个都是一个
/// 独立 Cronet Engine，内核在 bind 入站之前串行创建 ⇒ 起核时间随 naive 数线性涨）。本值退化成那条
/// 公式的下限，职责变了、**语义没变**：它仍然是「慢机器上核到底还起不起得来」的容忍度，调小仍然会
/// 把冷启动 / 杀软扫描拖慢的正常起核误判成失败。轮询间隔只决定「就绪后多久发现」，与本值正交
/// （见 [`CORE_READY_POLL_MS`]）。
///
/// # 它是「今天能连上的订阅不受影响」这条承诺的**唯一**锚点
///
/// 本改动在时间维度上的空操作性完全由它承载：只要它还是那个已发布、已在真机上跑过的值，任何今天能
/// 在 12s 内就绪的起核在本改动之后拿到的门都 ≥ 12s ⇒ 等待行为逐字不变。把它调小 = 在没有任何新证据
/// 的前提下把门收窄到一个从未跑过的取值上，而收窄的失败面正是本改动要消灭的那个（正在正常启动的核
/// 被判死 ⇒ 用户点连接直接连不上 ⇒ 报错指向网络/端口）。
pub(super) const CORE_READY_TIMEOUT_FLOOR_MS: u64 = 12_000;

/// 主核起核耗时估算的**固定项**（ms）：与本次下发规模无关的那一段。
///
/// # 为什么不能用 `polaris_core_supervisor::CORE_STARTUP_BASELINE_FIXED_MS`（90ms）
///
/// 那 90ms 是「缓存已热、0 naive、什么资源都不加载」的核**自报**值（`sing-box started (0.09s)`），
/// 只覆盖核自己 bind 完成前的那一段。主核这条腿上，就绪窗口里还压着 rule_set / geo 资源加载、
/// 可能的 TUN 网卡创建、以及经 helper 提权起核的 IPC 往返 —— 一项都不在那 90ms 里。照抄 = 把门收窄
/// 到一个**从未验证过**的取值上。（`sing-box check` 不在窗口内：它跑在 spawn 之前，不能重复计。）
///
/// # 4000ms 怎么来的：一个区间里的保守取值，**不是**回归拟合值
///
/// 取值被两侧夹住，4000 落在区间中偏下、朝安全方向：
///
/// · **下界 = 3200ms**，来自主核真机样本里 0 naive 时最慢的那一档：Windows TUN 端到端 p50 3002ms /
///   50 次连续启停 p95 3562ms，其中「剩余约 2.0–3.2s 是内核/TUN ready」；同批样本里 macOS TUN p50
///   953ms、Windows System ready p50 635ms、macOS 冷启动 spawn→ready 1510ms 都更小。
///   固定项必须盖住这一档最慢的，否则公式一上来就低估。
///   （旧 Windows 包那条 `wait_ready=9831ms` **不计入**：同一会话核自报 `started (1.59s)`，
///   9831ms 是当时探活每轮同步起 `tasklist` 造成的应用侧阻塞，已被 Win32 原生探活修掉，
///   它不是核的启动耗时。）
/// · **上界 = 6000ms**，由 `CORE_READY_SAFETY_FACTOR × 本值 ≤ [`CORE_READY_TIMEOUT_FLOOR_MS`]` 定：
///   只要满足它，固定项在 m = 0 时被下限整个吸收 ⇒ **这个常量在结构上不可能把门收得比今天窄**，
///   无论它取多大都只会放宽。这条比「取值准不准」重要得多，故它是硬边界。
///
/// # 保守取值，未经隔离实测（如实记账）
///
/// 上面那些是**端到端 p50/p95 样本**，不是「固定项」这一项的隔离测量 —— 本仓从未做过
/// 「主核 0 naive、逐项拆分 spawn→ready」的多点实测。故 4000 是按「宁可偏大」的方向取的保守值，
/// 不是拟合值。补测法：同一台机器上固定 m = 0，分别在 systemProxy / TUN、冷 / 热态各取若干次
/// `起核耗时：就绪等待=` 日志值，取上分位数回来改本常量。
///
/// # 交叉点（改本值前先算一遍）
///
/// 门 = `max(12000, 2 × (4000 + 0.105·n + 41·m))` ⇒ m ≤ 48 时门恒为 12000ms（与今天逐字一致），
/// m = 49 起才开始放宽。本值取得越大，开始放宽的 m 越小 —— 那是安全方向。
pub(super) const MAIN_CORE_STARTUP_FIXED_MS: u64 = 4_000;

/// 本次**下发给核的那一份** config 里的 naive 出站数（= Cronet Engine 数）。
///
/// # 为什么从生成产物的 `outbounds[].type` 数，而不是从用户节点列表推
///
/// 建 engine 的判据在**核**那边，它看的就是这份 JSON 的 `type` 字段。而节点列表到下发配置之间隔着
/// 协议开关、订阅筛选、内核闸门剥离（`generate_and_gate_with_runtime_bindings` 会把内核拒收的节点
/// 摘掉后重新生成）、以及 endpoint 归类 —— 从节点列表推必然与核实际拿到的那份漂移，而漂移的表现
/// 正是最难归因的那一种（门算小 ⇒ 正在正常启动的核被判死 ⇒ 报错指向网络）。
///
/// 传进来的 `config` 就是 `GateOutcome::config`，即 `generate_and_gate_with_runtime_bindings` 序列化后
/// 写进 `config_path`、随即交给内核的那一份，两侧同源。
///
/// # 三条不进计数的（都不是疏漏）
///
/// · `selector` / `urltest` 的成员只是 tag 字符串数组，不是 `outbounds[]` 的条目 ⇒ 天然不计
///   （本函数数的是条目，不是引用）；
/// · WireGuard / Tailscale 走顶层 `endpoints[]`，不建 engine ⇒ 不计入本函数（但计入
///   [`main_core_parse_unit_count`]，且其同步初始化成本属已登记的模型盲区，见
///   [`core_startup_estimate_ms`]）；
/// · `direct` / `block` / ShadowTLS 外层等附属出站同理不建 engine。
pub(super) fn main_core_naive_count(config: &SingBoxConfig) -> usize {
    config
        .outbounds
        .iter()
        .filter(|o| o.type_field == "naive")
        .count()
}

/// 本次下发配置的**解析单元数**（[`core_startup_estimate_ms`] 的 `n`）= 出站数 + 端点数。
///
/// 每节点项量级只有 0.105ms（2000 个也才 210ms），相对下限可忽略；计它是为了让公式在超大订阅上
/// 仍朝偏大的方向走，而不是为了精度。入站不计：主核的入站是固定的那几个（mixed / TUN / 管理口），
/// 不随订阅规模变化。
pub(super) fn main_core_parse_unit_count(config: &SingBoxConfig) -> usize {
    config.outbounds.len() + config.endpoints.as_ref().map_or(0, Vec::len)
}

/// 本次下发配置 → 主核就绪等待预算（ms）。
///
/// = `max(CORE_READY_TIMEOUT_FLOOR_MS, 安全系数 × (固定项 + 每节点项 + 每 naive 项))`，
/// 公式与系数的单一真值在 [`core_ready_budget_ms`]。
///
/// # 主核**没有**上界，也没有「规模超限就不起核」那条腿（与测速临时核的**刻意分歧**）
///
/// 测速临时核给预算加了 60s 硬上限，越界当场 `Err`、一个端口都不烧。那条腿在本处是**错的**：
///
/// · 测速被拒可以重试，用户损失的是一批测速结果；**连接被拒 = 不让用户上网**，而拒绝的理由还是
///   一个由推导系数算出来的估算值。用一个未经多点实测的公式去否决用户的连接请求，代价与置信度
///   完全不匹配；
/// · 临时核那条上限的判据是「等一个可能永远不会 bind 的核，且这段时间里进程级单飞闸挡住一切后续
///   测速请求，而僵核形态没有取消按钮」。主核这三条**都不成立**：核崩掉由 `CoreReadyDeps::is_alive`
///   当场接住；用户中途点停止/重连由 `is_superseded` 接住，且轮询 sleep 本身可被世代变化打断
///   （见 [`ProxyRuntime::wait_ready`]）⇒ 等待随时可取消，用户不需要一个替他做主的上限。
///
/// 于是主核这条腿上「预算大」的唯一代价是：一个真起不来的核多等一会儿才被判死，而那次判死的报错
/// 会**指名道姓说清是规模**（见 [`main_core_ready_timeout_message`]）。这是可接受的，静默失败不是。
///
/// 算术全程 `saturating_*`（在 [`core_ready_budget_ms`] 内），故不存在「订阅大到把预算算回一个小数」
/// 的回绕面。
pub(super) fn main_core_ready_timeout_ms(config: &SingBoxConfig) -> u64 {
    core_ready_budget_ms(
        MAIN_CORE_STARTUP_FIXED_MS,
        CORE_READY_TIMEOUT_FLOOR_MS,
        main_core_parse_unit_count(config),
        main_core_naive_count(config),
    )
}

/// 就绪等待走满预算仍未就绪时的报错原文。
///
/// # 这句话里每一段都不是装饰
///
/// 原样保留「管理 API 未就绪」= 把一个**规模**问题报成一个**网络/端口**问题，那正是本改动要消灭的
/// 误诊。故原文按「结论 → 推导输入 → 机制 → 可执行的数 → 下一步」排，缺任何一段用户要么不知道是
/// 自己 naive 节点太多，要么知道了也只能二分猜要砍到多少。
///
/// 分两支而不是一句话套模板：naive 为 0 时规模**确实不是**成因（门就等于下限），此时还谈规模是
/// 把用户往错误的下一步引 —— 与只报「未就绪」是同一类错误，只是方向相反。
pub(super) fn main_core_ready_timeout_message(
    api_port: u16,
    config: &SingBoxConfig,
    budget_ms: u64,
) -> String {
    let naive = main_core_naive_count(config);
    let units = main_core_parse_unit_count(config);
    if naive == 0 {
        return format!(
            "sing-box 起核超时：管理 API {api_port} 在 {budget_ms}ms 内未就绪。\
             本次下发 {units} 个出站/端点、其中 naive 出站 0 个 ⇒ 就绪门就是最低的 \
             {CORE_READY_TIMEOUT_FLOOR_MS}ms，与订阅规模无关。\
             请转查端口占用、TUN 网卡/提权，以及内核日志里的启动错误。"
        );
    }
    let estimate_ms = core_startup_estimate_ms(MAIN_CORE_STARTUP_FIXED_MS, units, naive);
    let engine_ms = (naive as u64).saturating_mul(CORE_STARTUP_PER_NAIVE_MS);
    format!(
        "sing-box 起核超时：管理 API {api_port} 在 {budget_ms}ms 内未就绪。\
         本次下发 {units} 个出站/端点，其中 {naive} 个是 naive —— 每个 naive 出站都是一个独立 \
         Cronet Engine，内核在绑定入站之前逐个串行创建，估算本次起核需 {estimate_ms}ms\
         （其中 naive 一项就占 {engine_ms}ms），故就绪门已按本次规模从 \
         {CORE_READY_TIMEOUT_FLOOR_MS}ms 放宽到 {budget_ms}ms，仍未等到。\
         naive 节点每少一个省约 {CORE_STARTUP_PER_NAIVE_MS}ms：请减少本次启用的 naive 节点数、\
         或改选其他协议的节点后重试；若 naive 节点本就不多，再转查端口占用、TUN 网卡/提权与内核日志。"
    )
}

/// Adds one exclusion to the fixed-size core-supervisor port book without
/// changing its public contract. Used only for the optional probe pool after
/// the essential subscription port has already been allocated.
struct PortProviderExcluding {
    excluded: u16,
}

impl FreePortProvider for PortProviderExcluding {
    fn try_allocate(&self) -> Option<u16> {
        let port = FreePortProvider::try_allocate(&TokioPortProvider)?;
        (port != self.excluded).then_some(port)
    }
}
/// 就绪轮询间隔。
///
/// # 为什么是 50 而非 上游的 500（**刻意分歧**，非移植疏漏）
///
/// 本值只决定**发现就绪的延迟**，不决定能等多久（那是 [`CORE_READY_TIMEOUT_FLOOR_MS`] 起算的
/// [`main_core_ready_timeout_ms`]）。实测管理 API 口
/// 在 97–221ms 就已 listen，而 500ms 的栅格把「已经就绪」的事实压到下一个刻度才发现 → 平均白等
/// ~250ms、最坏 ~500ms，纯粹是采样精度造成的启动延迟。降到 50ms 后该项 ≤50ms（省 ~0.3s）。
///
/// **CPU 无虞**：每轮只是一次 loopback TCP connect（就绪前是即时 ECONNREFUSED），且一旦可连即
/// 短路返回 —— 典型只多跑几轮，不是忙等。
///
/// **总预算不变**：`max_polls = ceil(timeout/poll)` 随之 24 → 240，覆盖的仍是同一个 12s 窗口
/// （naive 出站多的批会按规模拿到更大的 `timeout`，轮数随之变多；间隔本身不变）。
pub(super) const CORE_READY_POLL_MS: u64 = 50;
/// 单次 loopback TCP 就绪探测超时。
///
/// 这是对 `127.0.0.1` 管理端口的采样，不是一次允许跑满 1s 的外网连接。Windows 在端口尚未
/// listen 时可能让 connect 挂到超时；1s 会令每个失败样本遮住随后已经就绪的端口。250ms 只提高
/// 重采样频率，是否最终判失败仍由独立的 [`main_core_ready_timeout_ms`] 总窗口（下限
/// [`CORE_READY_TIMEOUT_FLOOR_MS`] = 12s）决定。
pub(super) const READY_PROBE_TIMEOUT: Duration = Duration::from_millis(250);
/// **C6-5**：helper 起核时 daemon 侧 sing-box 早期 stdout/stderr 重定向的日志文件名（app 无法捕获 root
/// 受管核的管道，故经 helper 落文件；对齐 上游 `singbox_startup.log`）。落 `<configDir>/`。
pub(super) const SINGBOX_STARTUP_LOG: &str = "singbox-startup.log";
/// `sing-box check` 成功缓存。只缓存“同一核二进制 + 除运行期随机端口外完全相同的生成配置”；
/// 任一结构字段或核身份变化都重新真跑 check。
pub(super) const KERNEL_GATE_CACHE_FILE: &str = "singbox-check-cache.json";
pub(super) const KERNEL_GATE_CACHE_SCHEMA: u32 = 1;

/// 一次已成功 `sing-box check` 的可持久身份。
///
/// 缓存是纯性能提示，不是信任根：缺失、损坏、元数据读不到一律 miss；真正起核仍保留既有
/// readiness / FATAL / 出口自证链。`config_sha256` 来自**最终生成配置**，只抹去每轮必变、但不改变
/// schema 接受性的本地随机端口，避免用过宽的用户配置投影冒充内核实际收下的 JSON。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct KernelGateCacheRecord {
    pub(super) schema: u32,
    pub(super) binary_path: String,
    pub(super) binary_len: u64,
    pub(super) binary_modified_ns: u64,
    pub(super) config_sha256: String,
}

/// 一次完整 SHA256 对账通过后记住的两侧 payload 身份（仅进程内）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProtectedCoreCacheRecord {
    pub(super) active: crate::runtime::core_promote::PayloadStamp,
    pub(super) protected: crate::runtime::core_promote::PayloadStamp,
}

pub(super) fn protected_core_cache_hit(
    cached: Option<&ProtectedCoreCacheRecord>,
    active: &crate::runtime::core_promote::PayloadStamp,
    protected: Option<&crate::runtime::core_promote::PayloadStamp>,
) -> bool {
    protected.is_some_and(|protected| {
        cached.is_some_and(|cached| cached.active == *active && cached.protected == *protected)
    })
}

#[derive(Debug)]
enum ProtectedCoreReconcileOutcome {
    Cached,
    Verified,
    Promoted(String),
}

pub(super) fn attestation_commit_allowed(
    current_generation: u64,
    expected_generation: u64,
    status: &ProxyStatus,
    pid: u32,
) -> bool {
    current_generation == expected_generation && status.running && status.pid == pid
}

/// 抹去每轮起核必重新分配的本地端口；其余字段（含用户 mixed 端口、节点、规则、路径、secret）全保留。
pub(super) fn normalize_kernel_gate_config(value: &mut Value) {
    if let Some(inbounds) = value.get_mut("inbounds").and_then(Value::as_array_mut) {
        for inbound in inbounds {
            let dynamic = inbound
                .get("tag")
                .and_then(Value::as_str)
                .is_some_and(|tag| {
                    tag == "update-in"
                        || tag == "subscription-update-in"
                        || tag.starts_with("probe-in-")
                });
            if dynamic {
                if let Some(obj) = inbound.as_object_mut() {
                    obj.insert("listen_port".into(), Value::from(0));
                }
            }
        }
    }
    if let Some(services) = value.get_mut("services").and_then(Value::as_array_mut) {
        for service in services {
            if service.get("type").and_then(Value::as_str) == Some("api") {
                if let Some(obj) = service.as_object_mut() {
                    obj.insert("listen_port".into(), Value::from(0));
                }
            }
        }
    }
    if let Some(servers) = value
        .get_mut("dns")
        .and_then(|dns| dns.get_mut("servers"))
        .and_then(Value::as_array_mut)
    {
        for server in servers {
            if server.get("tag").and_then(Value::as_str) == Some("dns-node-race") {
                if let Some(obj) = server.as_object_mut() {
                    obj.insert("server_port".into(), Value::from(0));
                }
            }
        }
    }
}

fn kernel_gate_cache_record(
    binary: &Path,
    config: &SingBoxConfig,
) -> Option<KernelGateCacheRecord> {
    let metadata = std::fs::metadata(binary).ok()?;
    let modified = metadata
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    let modified_ns = u64::try_from(modified.as_nanos()).ok()?;
    let binary_path = binary
        .canonicalize()
        .unwrap_or_else(|_| binary.to_path_buf())
        .to_string_lossy()
        .into_owned();
    let mut normalized = serde_json::to_value(config).ok()?;
    normalize_kernel_gate_config(&mut normalized);
    let normalized = serde_json::to_vec(&normalized).ok()?;
    Some(KernelGateCacheRecord {
        schema: KERNEL_GATE_CACHE_SCHEMA,
        binary_path,
        binary_len: metadata.len(),
        binary_modified_ns: modified_ns,
        config_sha256: polaris_updater::verify::sha256_hex(&normalized),
    })
}

pub(super) fn load_kernel_gate_cache(path: &Path) -> Option<KernelGateCacheRecord> {
    let raw = std::fs::read_to_string(path).ok()?;
    let record: KernelGateCacheRecord = serde_json::from_str(&raw).ok()?;
    (record.schema == KERNEL_GATE_CACHE_SCHEMA).then_some(record)
}

pub(super) fn persist_kernel_gate_cache(
    path: &Path,
    record: &KernelGateCacheRecord,
) -> Result<(), String> {
    let content = serde_json::to_string(record)
        .map_err(|e| format!("序列化 sing-box check 缓存失败: {e}"))?;
    let suffix = polaris_store::fs::random_tmp_suffix();
    polaris_store::atomic_write_plan(path, &suffix, &content)
        .execute(&polaris_store::StdFs)
        .map_err(|e| format!("持久化 sing-box check 缓存失败 {}: {e}", path.display()))
}

/// [`ProxyErrorEmitter::prompt_helper_gate`](super::ProxyErrorEmitter::prompt_helper_gate) 的用户决策（移植 上游 `'proceed' | 'abort'`）。
///
/// **刻意只有两值**：上游的第三个选项「本次用系统授权启动」对应 osascript/UAC/setcap 回退路径，
/// Polaris 尚未移植该回退（见交付说明）。给一个点了没用的按钮比不给更糟 —— 值域忠实反映**本仓真有的
/// 能力**，而不是照抄上游的按钮数。
/// `Default` = [`Abort`](HelperGateDecision::Abort)：任何「没能真问到用户」的路径都必须落在
/// **不装、不起核**这一侧。默认 `Proceed` 会让缺省值悄悄替用户按下「安装」（弹系统授权框）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HelperGateDecision {
    /// 用户确认 → 已就地尝试授权安装。**不代表安装成功**：成败由调用方复检 helper 状态裁定
    /// （安装失败 → 仍落 [`code::HELPER_NOT_INSTALLED`]，不冒充成功继续 spawn）。
    Proceed,
    /// 用户取消 → 干净终态 [`code::HELPER_GATE_ABORTED`]，本次不起核。
    #[default]
    Abort,
}

/// **C6-5 起核路由决策（纯函数）**：是否经提权 helper 起核（而非 [`TokioSpawner`] 直起）。
///
/// 判据 = TUN 模式 **且** 平台有 helper 实现。根因（对齐 上游 `startViaHelper` 门控）：
/// - **TUN 需提权**：mac/Win 建 utun/wintun 需 root/SYSTEM；linux 建 tun 需 CAP_NET_ADMIN（经 helper 的
///   AmbientCaps + setuid 降权拉核）。三平台 TUN 一律经 helper（上游 `isTunMode` → helper）。
/// - **systemProxy/manual 不接管 TUN**：核只在本地端口截流，app 直接 spawn 即可（无需 root）→ [`TokioSpawner`]。
/// - **平台无 helper**（`Platform::Other`）：无 daemon 可连 → 退回直起（best-effort；TUN 在未知平台本就无解）。
///
/// 变异锚点：删 `is_tun()` → 全模式经 helper（systemProxy 也弹提权，回归）；删平台判 → Other 平台起核必失败。
///
/// DESIGN-REVIEW(c6-5-src-tauri-helper-wiring)：`Platform::Other` 的 TUN 判 false → 退回直起（无 helper
/// 可连）；但直起也建不了 TUN——是否该改「Other+TUN→显式报错」由复审裁（R27.1，目标平台仅 mac/win/linux，低风险）。
pub(super) fn should_start_via_helper(mode: ProxyModeType, platform: Platform) -> bool {
    mode.is_tun() && matches!(platform, Platform::Mac | Platform::Win | Platform::Linux)
}

/// **已装 helper「该不该提示升级」的纯判定**（与 [`should_start_via_helper`] 同层，形态照
/// `startup_tasks::should_notify_helper_upgradeable`）。
///
/// 判据 = 本次起核确实要经 helper（TUN + 有实现的平台）**且** helper 已装 **且** 可升级。
/// 三个合取项各有各的牙：
/// - 删 `should_start_via_helper` → systemProxy/manual 起核也弹升级框（用户这次根本没用到 helper）；
/// - 删 `installed` → 未装时也命中，与 [`ProxyRuntime::run_helper_gate`] 的「去装」腿撞车
///   （用户连点两个框，且第二个框问的是一件此刻无意义的事）；
/// - 删 `upgradeable` → 每次 TUN 起核都弹，已装且最新的绝大多数用户被恒骚扰。
///
/// `ready` **刻意不再查一遍**（同 `should_notify_helper_upgradeable` 的理由）：`upgradeable` 在
/// `helper-client::compute_status` 里已经合取 `ready`，在这里重复只会制造「两处判据、改一处漏一处」。
#[must_use]
pub(super) fn should_prompt_helper_upgrade(
    mode: ProxyModeType,
    platform: Platform,
    status: &HelperStatusSnapshot,
) -> bool {
    should_start_via_helper(mode, platform) && status.installed && status.upgradeable
}

/// 一次性闸门的**领取**动作：`true` = 本次领到（可以做那件只做一次的事），`false` = 已被领走。
///
/// 抽成自由函数而不是就地写 `swap`，是为了让「第二次必须领不到」这条属性能被**直接**证伪 ——
/// 埋在 `maybe_prompt_helper_upgrade` 里的一句 `swap` 只能靠端到端观测间接推断，而
/// 「没弹第二次」与「压根没弹过」在那种观测下长得一样。
pub(super) fn claim_once(flag: &AtomicBool) -> bool {
    !flag.swap(true, Ordering::SeqCst)
}

tokio::task_local! {
    /// **本次起核的交互性**（移植 上游 `start(config, {interactive:false})`，`ProxyManager.ts:1475`）。
    ///
    /// 未设置 ⟺ 交互式（默认）：[`ProxyRuntime::run_helper_gate`] 该弹框就弹框。
    /// 设为 `false` ⟺ 非交互：不弹框，直接落 [`code::HELPER_NOT_INSTALLED`] 终态。
    /// **唯一置位者是崩溃自愈重启腿**（[`ProxyRuntime::run_crash_recovery`]）：崩溃循环里凭空弹系统
    /// 授权框（最多连弹 `MAX_RESTART_COUNT` 次）比断流更糟 —— 用户没做任何操作，却被反复索要密码。
    ///
    /// **为什么是 task-local 而不是 runtime 上的 `AtomicBool` 字段**（根因，A2）：交互性是**这一次调用
    /// 的属性**，不是运行时的属性。挂成运行时全局字段有两个必然缺陷：
    /// 1. **跨调用污染**：`LifecycleGate` 只是深度计数器、不是互斥锁，并发 `start` 完全可能同时在飞。
    ///    崩溃自愈的 `restart()`（stop + start + 最多 3 轮重试与就绪等待，可达数十秒）整段置位期间，
    ///    用户**手动点连接**会读到同一个标记 → 门被误抑制、直接落 `HELPER_NOT_INSTALLED`，用户的显式
    ///    交互请求被当成非交互自愈处理（正是本门要消灭的行为）。
    /// 2. **嵌套解除**：字段版用 `Drop` 无条件 `store(false)` 而非计数递减，两个抑制作用域重叠时内层
    ///    退场会提前解除外层。
    ///
    /// task-local 天然随调用链传递、随作用域嵌套、且**不跨任务泄漏** —— 别的任务里的 `start` 读不到，
    /// 上面两条缺陷从物理上不再存在。`tokio::spawn` 出去的任务不继承（正确：那已是另一次调用）。
    static HELPER_GATE_INTERACTIVE: bool;
}

/// 当前调用链是否为交互式起核。**未设置 = 交互式**（默认放行弹框）：绝大多数入口（IPC / 托盘 /
/// 启动自动连接 / switchMode 去抖重启）都不显式声明，它们全是用户驱动的，默认必须能弹框。
fn helper_gate_interactive() -> bool {
    HELPER_GATE_INTERACTIVE.try_with(|v| *v).unwrap_or(true)
}

/// 单测态未注入假核时，[`ProxyRuntime::core_binary_for_start`] 的固定错误文案。
///
/// **必须是固定文案**（而非复用解析器的 "未找到 sing-box 二进制…"）：守这道门的回归测试断言的正是
/// 这句话。若断言只写 `is_err()`，那么在 `resources/` 为空的机器上，门被删掉后测试依然绿
/// （解析器自己也返 Err）—— 门就成了只在装了核的机器上才有牙的门，而那恰恰是最不会被本地跑到的环境。
#[cfg(test)]
pub(super) const TEST_CORE_NOT_INJECTED: &str =
    "单测态禁止解析真实核二进制：请经 ProxyRuntime::core_binary_override 注入假核（防单测漏出真 sing-box 进程）";

/// 在**非交互**语境下跑一段起核/重启（崩溃自愈专用）：本调用链全程抑制 TUN 提权引导弹框。
///
/// 作用域即 future 本身：`fut` 内（含其 `await` 出去的任意深度）读到 `false`，`fut` 一结束（含中途
/// `return` / panic 展开）作用域随栈销毁 —— 没有「忘了复位 → 标记永久粘住 → 此后所有入口的引导门静默
/// 失效」这类形态可言。嵌套调用天然是栈式的，内层退场绝不会解除外层（旧的 `AtomicBool` + 无条件
/// `Drop::store(false)` 版本会）。
pub(super) async fn with_helper_gate_suppressed<F, T>(fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    HELPER_GATE_INTERACTIVE.scope(false, fut).await
}

impl ProxyRuntime {
    /// 本次起核要 spawn 的核二进制（生产）= [`resolve_core_binary`] 逐字不变。
    #[cfg(not(test))]
    pub(super) fn core_binary_for_start(&self) -> Result<PathBuf, String> {
        resolve_core_binary()
    }

    /// 本次起核要 spawn 的核二进制（**单测态：注入才给，否则拒**）。
    ///
    /// 单测只认 `core_binary_override` 注入的假核；**未注入即 Err，绝不回落 [`resolve_core_binary`]**。
    /// 根因（本 fn 存在的全部理由）：起核路径是单测里唯一会真 `Command::spawn` 出核进程的地方，而
    /// [`TokioSpawner`] 造出的 `Child` **没有 `kill_on_drop`**（见 `core_supervisor::stale_core` 的边界
    /// 声明：孤儿核靠下次启动的收割器兜，不靠 Drop）。于是「单测解析到真核」必然长成漏进程：
    /// 测试跑完 → tokio runtime 与 `ProxyRuntime` 一起销毁 → 没人调 `stop()` → 真 sing-box 继续跑，
    /// 而它的临时配置目录已被 fixture 删掉（实测形态：`sing-box run -c <已删目录>/singbox-runtime.json`）。
    ///
    /// **为什么必须堵在这里、而不是让 `resolve_core_binary` 测试态返假核**：返假核只是把「漏真核」换成
    /// 「漏假核」，spawn 这一步还在；而这里 deny-by-default 是把「单测起核进程」整类消灭。
    ///
    /// **为什么不是「哪条测试写错了就改哪条」**：那条测试（`helper_gate_never_prompts_for_non_tun_mode`）
    /// 的注释白纸黑字写着「起核会继续往下走并因**本机无核二进制**失败」—— 假设的是开发机 `resources/`
    /// 是空的。装了核的机器（mac 真机 / 跑过 `fetch-core.mjs` 的 CI）上该假设当场失效，而测试**照常全绿**，
    /// 只是多漏一个进程。这类「绿而带副作用」的坑不可能靠逐条 review 兜住，只能靠这道门。
    #[cfg(test)]
    pub(super) fn core_binary_for_start(&self) -> Result<PathBuf, String> {
        self.core_binary_override
            .lock()
            .ok()
            .and_then(|g| g.clone())
            .ok_or_else(|| TEST_CORE_NOT_INJECTED.to_string())
    }

    /// 起核失败腿的竞速 sidecar 收口。守卫与
    /// [`maybe_clear_system_proxy_on_start_failure`](Self::maybe_clear_system_proxy_on_start_failure)
    /// 完全同构（success 守卫 + `stopping` 守卫），理由也同构：
    /// - `Ok`（含让位）不收 —— 正在跑（或将被接管方拉起）的核正指着这个端口；
    /// - 世代已变 = 被更新的 stop/start 接管 —— 接管方**已经**用新配置重起过 sidecar，
    ///   此时收口会把**别人的** sidecar 停掉，比不收更糟。
    ///
    /// 世代守卫**下放到 DNS race owner 的复合临界区内**（而非在此先判后清）：
    /// 判完到清之间隔着
    /// 一次函数调用，接管方完全可以在这条缝里提交它的 sidecar —— 那是 check-then-act，不是守卫。
    pub(super) fn maybe_stop_race_sidecar_on_start_failure(
        &self,
        r: &Result<ProxyStatus, StartError>,
        my_gen: u64,
    ) {
        if r.is_ok() {
            return;
        }
        self.dns_race.clear_owned(Some(my_gen));
    }

    /// TUN 经 helper 起核的前置校验（R27.3）：当前模式需要提权 helper（TUN@mac/win/linux）**且** helper
    /// 尚未安装 → `true`（阻断起核，回结构化 [`code::HELPER_NOT_INSTALLED`]）。systemProxy/manual 或
    /// helper 已装 → `false`（放行走正常起核）。
    ///
    /// **为什么必须前置**（根因）：未装 helper 时直起 `spawn_core_via_helper` → `helper.start_core` →
    /// `UnixConnector::connect` 拿到 `ENOENT`，用户只看到裸 `connect .../helper.sock: No such file
    /// (os error 2)`——不可操作。前置判定把它换成「helper 未装，去装」的可操作提示。
    ///
    /// **本机安全 / 不连 socket**：未安装态 `helper.status()` 经 `compute_status_with_client` 先判
    /// `is_installed` 短路，绝不触碰 socket（见 `runtime/helper.rs`）。
    ///
    /// **唯一生产调用点 = [`run_helper_gate`](Self::run_helper_gate) 的复检腿**（用户确认安装后
    /// 「到底装上没有」那一问）。门的入口短路已改为直接判
    /// [`should_start_via_helper`] + 复用同一份 `status()` 快照 —— 因为「已装但可升级」这一格也要
    /// 读同一份快照，而 `status()` 是一次系统调用，取两次既多付一次开销，又会让两条腿看到不一致的
    /// 世界。command 层曾另有一份同谓词的前置拦截，**已删** —— 它只守住
    /// 「点连接按钮」一条腿，托盘切模式 / 启动自动连接 / switchMode 去抖重启全绕过它（§K7「门开在别处
    /// 却当全域门」）。别再据本注释以为命令层还有一道门：门只有 `start_inner` 汇流点那一道。
    pub(super) fn tun_helper_missing(&self, mode: ProxyModeType) -> bool {
        should_start_via_helper(mode, self.helper.platform()) && !self.helper.status().installed
    }

    /// **TUN 提权引导门**（起核汇流点；移植 上游 `ProxyManager.maybePromptHelperGate`，:1475-1497）。
    ///
    /// 判定 → 弹框 → 就地授权安装 → **复检** → 原地放行/终态，一次调用走完 上游的第 2/5/6/7/9 步：
    ///
    /// | 情形 | 结果 |
    /// |---|---|
    /// | 非 TUN / 平台无 helper 实现 | `Ok(())` 放行（零弹框、零系统调用） |
    /// | 已装且是随包那一版 | `Ok(())` 放行（一次 `status()`，零弹框） |
    /// | **已装但可升级** | 温和提示腿（[`maybe_prompt_helper_upgrade`](Self::maybe_prompt_helper_upgrade)），**恒 `Ok(())`** |
    /// | 需要门但被非交互抑制（崩溃自愈） | `Err` + [`code::HELPER_NOT_INSTALLED`] |
    /// | 需要门但 emitter 未接线（单测 / setup 前） | `Err` + [`code::HELPER_NOT_INSTALLED`] |
    /// | 用户取消 | `Err` + [`code::HELPER_GATE_ABORTED`] |
    /// | 用户确认 → 装上了 | `Ok(())`，**原地继续起核**（不要求用户再点一次连接） |
    /// | 用户确认 → 没装上 | `Err` + [`code::HELPER_NOT_INSTALLED`] |
    ///
    /// **确认后必须复检、不得直接放行**（这是本方法最容易被写错的一行）：`prompt_helper_gate` 返回
    /// `Proceed` 只代表「用户点了安装」，不代表装成功（授权框可被系统拒绝、脚本可失败）。不复检就直接
    /// 往下走，会拿着仍不存在的 helper 去 `spawn_core_via_helper`，用户拿到的又是裸 socket ENOENT ——
    /// 正是本门当初要消灭的东西。
    ///
    /// **`spawn_blocking`**：`prompt_helper_gate` 内含原生模态 `blocking_show` + osascript 授权
    /// （可阻塞 30s+）。在 async runtime 线程上直调会阻塞整个 worker；在 Tauri 主线程上调
    /// `blocking_show` 会死锁。故整段挪进阻塞线程池。
    ///
    /// **已知边界：本门无超时上限（A3，刻意不做）**。用户把系统模态晾在后台不点 ⇒ 本门不返回 ⇒
    /// `LifecycleGate` 深度长期 >0 ⇒ 此期间 `switch_mode` / 去抖重启只置 pending 不执行（托盘切档位
    /// 表现为「点了排队但不动」）。**不加超时的理由**：`blocking_show` 与 `install()` 的系统授权框都
    /// 无法从别的线程取消，`spawn_blocking` 的任务也不因丢弃 JoinHandle 而中止。加超时只会得到
    /// 「运行时已判 `HELPER_GATE_ABORTED`，模态却还挂在用户屏幕上，点了『安装』照样装、装完却没核起来」
    /// 外加一条永久占用的阻塞池线程 —— 比排队更坏，且最可能命中的正是「用户正在输管理员密码」那一刻。
    /// 死锁风险已排除：`blocking_show` 跑在 tokio 阻塞池线程而非 Tauri 主线程，`panic=unwind` 下守卫的
    /// `Drop` 可靠。故这是**体验降级而非卡死**，等真机确认为高频痛点再动。
    pub(super) async fn run_helper_gate(
        self: &Arc<Self>,
        mode: ProxyModeType,
    ) -> Result<(), StartError> {
        // 非 TUN / 平台无 helper 实现 → 绝大多数起核走这条：零系统调用、零弹框。
        if !should_start_via_helper(mode, self.helper.platform()) {
            return Ok(());
        }

        // `status()` 是一次系统调用（已装时还会 ping 一次 helper socket）。**只取这一份快照**，
        // 下面两条腿共用：分两次取不仅多付一次调用，还会让两条腿看到不一致的世界
        // （例如「判未装 → 弹安装框」与「判已装 → 弹升级框」同时成立）。
        let status = self.helper.status();

        // ── 腿 2：**已装** → 起核本身没有障碍，唯一可能要做的是「可升级」的温和提示。
        //
        // 本腿的返回类型是 `()`，结构上产不出 `Err` —— 那正是「永不阻断」这条决策的落点：
        // 把一次本来能成功的 TUN 起核变成失败，比「继续用旧 helper 起核」这个原缺陷严重得多。
        if status.installed {
            self.maybe_prompt_helper_upgrade(mode, &status).await;
            return Ok(());
        }

        // ── 腿 1：**未装** → 阻断式引导门（判定 → 弹框 → 就地授权安装 → 复检）。
        // 非交互（崩溃自愈）→ 退回本门引入前的行为：类型化终态，不打扰用户。
        // 读 task-local：只有**当前调用链**被 `with_helper_gate_suppressed` 包住才为真；并发的用户手动
        // 起核跑在另一个任务里，读不到本标记 ⇒ 照常弹引导（A2 修的正是这条）。
        if !helper_gate_interactive() {
            log::info!(
                "TUN 提权引导：非交互启动（崩溃自愈）→ 不弹引导，直接落 HELPER_NOT_INSTALLED"
            );
            self.set_error(HELPER_NOT_INSTALLED_MSG, code::HELPER_NOT_INSTALLED);
            return Err(StartError::coded(
                HELPER_NOT_INSTALLED_MSG,
                code::HELPER_NOT_INSTALLED,
            ));
        }

        // emitter 未接线（单测 / setup 前极早期）→ 同上。**绝不因为「没法问用户」就放行去 spawn**。
        if self.error_emitter.get().is_none() {
            log::debug!("TUN 提权引导：emitter 未接线 → 直接落 HELPER_NOT_INSTALLED");
            self.set_error(HELPER_NOT_INSTALLED_MSG, code::HELPER_NOT_INSTALLED);
            return Err(StartError::coded(
                HELPER_NOT_INSTALLED_MSG,
                code::HELPER_NOT_INSTALLED,
            ));
        }

        let me = Arc::clone(self);
        let decision = tokio::task::spawn_blocking(move || {
            me.error_emitter
                .get()
                .map(|e| e.prompt_helper_gate(&status))
                // 上面已判非 None；真取不到时按「用户取消」处理（不装、不起核）比按放行安全。
                .unwrap_or(HelperGateDecision::Abort)
        })
        .await
        .map_err(|e| format!("TUN 提权引导任务 join 失败：{e}"))?;

        if decision == HelperGateDecision::Abort {
            self.set_error(HELPER_GATE_ABORTED_MSG, code::HELPER_GATE_ABORTED);
            return Err(StartError::coded(
                HELPER_GATE_ABORTED_MSG,
                code::HELPER_GATE_ABORTED,
            ));
        }

        // 复检（见方法文档）：装上了才原地继续。
        if self.tun_helper_missing(mode) {
            log::warn!("TUN 提权引导：用户已确认但 helper 仍不可用 → 落 HELPER_NOT_INSTALLED");
            self.set_error(HELPER_NOT_INSTALLED_MSG, code::HELPER_NOT_INSTALLED);
            return Err(StartError::coded(
                HELPER_NOT_INSTALLED_MSG,
                code::HELPER_NOT_INSTALLED,
            ));
        }
        log::info!("TUN 提权引导：helper 已就位 → 原地继续起核（无需用户重新点连接）");
        Ok(())
    }

    /// **「helper 已装但可升级」的温和提示腿**（[`run_helper_gate`](Self::run_helper_gate) 的腿 2）。
    ///
    /// # 修的是什么（根因）
    ///
    /// 「可升级」此前只有一条出口：`startup_tasks::spawn_helper_upgradeable_probe` 在 T+7s 广播一次
    /// `event:helperUpgradeable`。而那条事件全仓唯一的消费者是**设置›助手页**的页面级订阅 ——
    /// 用户不站在那一页时没有任何人在听。真正依赖 helper 的那一刻（TUN 起核）则从头到尾**没读过**
    /// `upgradeable`：`tun_helper_missing` 只问「装没装」。于是真机形态是：TUN 照常用旧 helper 起核，
    /// 升级这件事只有主动点开设置页才会被发现。**一个状态只以事件形态广播、且唯一消费者是页面级的，
    /// 就等于没有消费者。**
    ///
    /// # 返回 `()` 是判据本身，不是省事
    ///
    /// 既定决策：**永不阻断**。用户选「直接继续」、或选了升级但升级失败，起核都照常继续 ——
    /// 把一次本来能成功的 TUN 启动变成失败，比原缺陷严重得多。用 `()` 而不是
    /// `Result<(), StartError>`，这条约束就由**类型**兜住：想让它阻断必须先改签名，改不动就漏不出去。
    ///
    /// # 四道闸的顺序（每一道都必须在，且顺序不可换）
    ///
    /// 1. [`should_prompt_helper_upgrade`]：非 TUN / 未装 / 已是随包版 → 不弹；
    /// 2. [`helper_gate_interactive`]：崩溃自愈重启腿一律不弹（用户没做任何操作却被凭空索要授权，
    ///    且崩溃循环里最多连弹 `MAX_RESTART_COUNT` 次）；
    /// 3. emitter 未接线（单测 / setup 前极早期）→ 静默（没法问用户，也不该假装问过）；
    /// 4. **一次性闸门**（[`claim_once`] + [`helper_upgrade_prompted`](ProxyRuntime::helper_upgrade_prompted)）：
    ///    本方法挂在**每次 TUN 起核**都跑的汇流点上（托盘切模式 / 启动自动连接 / switchMode 去抖重启 /
    ///    崩溃自愈重启），不去重 = 每次重启弹一次原生模态。
    ///
    /// 闸 4 **必须最后领**：前三道任一不过就不该消耗掉这唯一一次机会 —— 否则崩溃自愈腿（闸 2 拦下的
    /// 那条）会把名额领走，用户随后手动起核时反而一个字都看不到。
    async fn maybe_prompt_helper_upgrade(
        self: &Arc<Self>,
        mode: ProxyModeType,
        status: &HelperStatusSnapshot,
    ) {
        if !should_prompt_helper_upgrade(mode, self.helper.platform(), status) {
            return;
        }
        if !helper_gate_interactive() {
            log::info!("helper 可升级提示：非交互启动（崩溃自愈）→ 不打扰用户");
            return;
        }
        if self.error_emitter.get().is_none() {
            log::debug!("helper 可升级提示：emitter 未接线 → 静默跳过");
            return;
        }
        if !claim_once(&self.helper_upgrade_prompted) {
            log::debug!("helper 可升级提示：本进程已提示过一次 → 不重复打扰");
            return;
        }

        let snapshot = status.clone();
        let me = Arc::clone(self);
        // `spawn_blocking` 的理由与 `run_helper_gate` 的未装腿逐字相同：`prompt_helper_upgrade` 内含
        // 原生模态 `blocking_show` + 可能的系统授权安装（可阻塞 30s+）。在 async worker 上直调会阻塞
        // 整个 worker；在 Tauri 主线程上调 `blocking_show` 会死锁。
        let upgraded = tokio::task::spawn_blocking(move || {
            me.error_emitter
                .get()
                .is_some_and(|e| e.prompt_helper_upgrade(&snapshot))
        })
        .await
        // join 失败**照样不阻断**（本腿的全部约束）：记一句就继续起核。这里刻意不用 `?` ——
        // 本方法压根没有 `Err` 可返回，那正是「永不阻断」由类型兜住的意思。
        .unwrap_or_else(|e| {
            log::warn!("helper 可升级提示任务 join 失败：{e} → 照常继续起核");
            false
        });
        if upgraded {
            log::info!("helper 可升级提示：用户选择升级并继续 → 继续起核");
        } else {
            log::info!("helper 可升级提示：用户选择直接继续 → 继续起核");
        }
    }

    /// start 主体（错误路径统一由 [`Self::start`] 收口 `end`）。
    pub(super) async fn start_inner(
        self: &Arc<Self>,
        config: Value,
        my_gen: u64,
    ) -> Result<ProxyStatus, StartError> {
        // 早退让位（#176）：入口即被更新的 start/stop 接管 → 别白做 config 生成/写盘/端口解析。
        // 这只是省功，**不是**孤儿防线——真正的防线是下方 spawn 临界区内的持锁判世代。
        if self.gate.generation() != my_gen {
            log::info!("起核入口即被接管（世代 {my_gen}）→ 让位");
            return Ok(self.status());
        }

        // 分段耗时测量（仅测量，不影响任何判定/控制流）：入口墙钟 + 各段累加器。
        // 重试轮内的段按**所有尝试累计**，否则总计在发生重试时会漏掉前腿的真实成本。
        let t_total = std::time::Instant::now();
        let mut config_gen_ms: u128 = 0;
        let mut spawn_ms: u128 = 0;
        let mut ready_ms: u128 = 0;
        let mut mesh_baseline_ms: u128 = 0;
        let mut tun_adapter_ms: u128 = 0;
        let mut retry_backoff_ms: u128 = 0;

        let t_preflight = std::time::Instant::now();
        let user_config: UserConfig = serde_json::from_value(config.clone())
            .map_err(|e| format!("配置解析失败（UserConfig）: {e}"))?;
        if let Err(message) = self.validate_required_bind_interfaces(&user_config).await {
            self.set_error(&message, code::OUTBOUND_INTERFACE_UNAVAILABLE);
            return Err(StartError::coded(
                message,
                code::OUTBOUND_INTERFACE_UNAVAILABLE,
            ));
        }
        // C7 门的第二条轴：`dnsConfig.takeoverSystemDns` 用户开关（**必须在此取**——`config` 在就绪段
        // 会被 move 进 `startup_snapshot`）。三态：`Some(false)` = 用户显式关，其余（缺省 / true / 非布尔）
        // 一律视作开（对齐 上游 `takeoverSystemDns !== false` 与 `validateConfig` 的布尔口径）。
        let dns_takeover = dns_takeover_enabled(&config);
        let preflight_ms = t_preflight.elapsed().as_millis();
        log::info!("起核耗时：配置解析+网卡绑定前置校验={preflight_ms}ms");

        // ── C6-5 TUN 提权引导门（**全入口唯一汇流点**，移植 上游 `maybePromptHelperGate`）──────
        // 置于 config 生成/写盘/端口解析之前（最早 bail，未装时零副作用）。**必须在此、不可在命令层**：
        // 起核入口不止 IPC —— 托盘切模式 / 启动自动连接 / switchMode 去抖重启 / 崩溃自愈 全部直调
        // `self.start`，门开在 `commands::proxy_start` 就只守住了「点连接按钮」一条腿（§K7「门开在别处
        // 却当全域门」）。这也是 systemProxy→TUN 切档位会静默停在停止态的直接成因：重启腿的 stop 跑完，
        // start 腿撞上无人值守的 preflight 直接 bail。
        let t_helper_gate = std::time::Instant::now();
        self.run_helper_gate(user_config.proxy_mode_type).await?;
        let helper_gate_ms = t_helper_gate.elapsed().as_millis();
        log::info!("起核耗时：helper提权门={helper_gate_ms}ms");

        // ── 端口两轴常量（单一真值复用 config-engine::proxy_ports）。mixed/control 由 config 决定、
        //    跨重试不变；管理 API / update-in 是动态空闲口，每次尝试重解析（见 resolve_start_ports）──
        let mixed_port = local_proxy_port(&user_config);
        let control_port = control_api_port(&user_config);

        // 3.1 起核前落盘外化自定义规则文件 + 孤儿对账清扫（**必须在 generate 前**：generate 的 route/DNS
        //     ext 分支按文件真存在性 `ext_rule_file_exists` 决定走 ext 引用还是 inline 降级；文件不在 →
        //     ext 分支 100% 不可达）。移植 上游 start :750 `writeCustomRuleFiles`。一次（重试腿不重清孤儿）。
        let t_rules_prep = std::time::Instant::now();
        self.write_custom_rule_files(&user_config).await;

        // ── 内置 geo 规则集播种（调用点 2/2：**每次起核前**；对齐 上游 `ProxyManager.ts:6375`）──
        // 与上面的 writeCustomRuleFiles 同理，**必须在 generate 之前**：route builder 按
        // `is_valid_srs_fn(<rules>/x.srs)` 的真存在性决定注不注入 rule_set，文件不在 → 规则 100% 被剪。
        // 启动时已种过一轮，这里兜住「运行期被删/被外部清理/首启时目录尚未就绪」。幂等，已有有效副本零开销。
        // 默认选项 = **只补缺失**：出厂态刷新只在启动那次开（运行中可能有并发的规则资源更新，
        // 此处刷新会与之争抢同一个 dest）。见 `geo_seed::SeedOptions::refresh_out_of_box`。
        crate::runtime::geo_seed::seed_builtin_rule_sets_into(
            self.config.dir(),
            "起核前",
            &crate::runtime::geo_seed::SeedOptions::default(),
        );

        let config_path = self.runtime_config_path();
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("创建配置目录失败 {}: {e}", parent.display()))?;
        }
        let rules_prep_ms = t_rules_prep.elapsed().as_millis();
        log::info!("起核耗时：规则文件+内置规则集预置={rules_prep_ms}ms");
        // C6-5 起核路由：TUN + 有 helper 的平台 → 经提权 helper 起 root/SYSTEM 受管核；
        // systemProxy/manual（不接管 TUN）→ TokioSpawner 直起（见 `should_start_via_helper`）。
        let via_helper =
            should_start_via_helper(user_config.proxy_mode_type, self.helper.platform());

        // ── #159/#176 起核外层重试预算（移植 上游 `runStartWithRetry`，:859）──
        // 起核期未就绪/退出（wintun 适配器未释放 / 双 utun 抢占 / 管理口慢绑）→ 单次即终态太脆。按预算
        // 重试：**每次尝试重解析空闲端口 + 重生成配置 = 端口重分配自愈**（osascript 授权窗口/竞态被抢占 →
        // 换口重写盘，对齐 上游 onRetry allocateProbePorts）；退避给内核留足异步回收适配器的时间。
        // system_interface（reverseMesh）节点建第二张内核 TUN → 双 TUN 释放慢，预算放宽（见 resolve_start_retry_budget）。
        //
        // DESIGN-REVIEW(fx-proxy-a-runstart-retry-partial)：**不含** 上游 onRetry 的两条增强腿——(a) run 阶段
        //   `dependency[X] not found` 的 pruneTagsClosure 幽灵引用修正（需 config-engine gate-invalid-node 内部机制，
        //   属 config-engine 只读禁区）；(b) libcronet 缺库 strong-heal 重拷闭环（需 resourceManager.ensureCronetHealthy
        //   子系统）。二者靠现有「generate 期 invalid-node 剔除 + has_cronet 生成期报错」部分覆盖；完整移植列 review-queue。
        let budget = resolve_start_retry_budget(
            user_config.proxy_mode_type.is_tun(),
            &user_config.servers,
            platform_tag(),
        );
        let mut attempt: u32 = 0;
        // 内核闸门累计剥掉的节点 id。**必须在重试循环之外**：内核对某个节点的拒收是确定性的
        //（同一节点、同一个核，判定不会变），第 2 腿起沿用即可；再叠加已接受配置缓存后，
        // 同一核/配置的就绪重试腿连确认 check 也无需重复起进程。
        let mut kernel_peeled: BTreeMap<String, InvalidNode> = BTreeMap::new();
        // C-tun-conflict：起核**前**抓「应走代理的公网目的」出口 baseline（仅 TUN 模式；post-flight 差分锚点）。
        // 必须在任何 spawn 之前 —— 我方 utun 尚未上线，此刻查到的是「Polaris 起核前」的出口（物理网卡或
        // 他方 VPN 的 utun）。重试腿间 `kill_core` 会让路由回落 baseline，故只在进循环前抓一次即准。
        let t_tun_baseline = std::time::Instant::now();
        let tun_route_baseline = self
            .capture_tun_route_baseline(user_config.proxy_mode_type)
            .await;
        let tun_baseline_ms = t_tun_baseline.elapsed().as_millis();
        log::info!("起核耗时：TUN路由基线采集={tun_baseline_ms}ms");

        // #327：本次起核**期望**的 TUN 接口名（起核后逐腿正向验证适配器存在性的比对目标）。
        // 经 config-engine 同一个 `resolve_win_tun_interface_name` 解出 —— 生成侧
        //（`builder/inbounds.rs` win32 分支）烧进 config 的就是它，两侧同源 ⇒ 不可能出现「验的名字
        // 与核实际用的名字不是一个」。在循环外算一次即可：接口名不随重试腿变化（变的只有端口）。
        let tun_adapter_name = resolve_win_tun_interface_name(
            user_config
                .tun_config
                .as_ref()
                .and_then(|t| t.interface_name.as_deref()),
        );
        // #327：**跨腿累积**的事实——整个起核过程里是否**曾经**见过该适配器。终态诊断按它分岔：
        // 一次都没见过 = wintun 建不出来（TUN_ADAPTER_MISSING）；见过又没了 = 抖动，不冒充前者。
        let mut tun_adapter_ever_seen = false;

        // stderr 转发腿 ⇄ `SubscribeLog` 流的交接闸（见 [`CoreLogHandoff`] / [`pipe_to_log`]）。
        // **`None` = 经 helper 起核、根本没有管道**（helper 把核 stdout/stderr 重定向进启动日志文件），
        // 此时核日志 relay 要把首帧那份历史收下——那是起核到订阅之间唯一的日志来源。
        // 直起腿在下面置成 `Some`，relay 据此改为「置位交接 + 丢弃首帧历史」。
        //
        // **声明在重试循环之外**：循环是个 `let (…) = loop { … break (…) }` 表达式，就绪处的接线点在它
        // 之外。`via_helper` 在进循环前就定了（上方），故不存在「某腿直起、某腿 helper 起」的混合形态；
        // 直起时每腿都会覆写成本腿的新闸（上一腿的核已被 kill，其管道任务随之结束）。
        let mut log_pipe_handoff: Option<CoreLogHandoff> = None;

        // C11 节点域名解析多源竞速（对齐 上游 start 步骤 3.9 `startNodeDnsRaceServer`）：
        // 节点 outbound.server 恒是域名，由内核运行期解析多 A → DialSerial 逐 IP 重试；这里给内核
        // 提供一个只听回环的竞速解析上游，把「单上游被投毒 = 该节点连不上」变成「多上游竞速 + 剔 decoy」。
        //
        // **位置不可挪**：必须在重试循环**之外、之前**。
        // - 在 `generate_deps` 之前 → 端口先拿到才能烧进 config（生成侧只认 `race_server_port > 0`）；
        // - 在循环之外 → 每次重试重生成 config 时端口保持同一个。放进循环会每轮换口重绑，
        //   而失败重试正是内核可能已经拿着上一轮 config 的时候，端口漂移 = 解析静默打到死口。
        let dns_race = async {
            let started = std::time::Instant::now();
            self.dns_race
                .start(&user_config, self.config.dir(), my_gen)
                .await;
            started.elapsed().as_millis()
        };
        let route_binding = async {
            let started = std::time::Instant::now();
            let plan = plan_runtime_bindings(&user_config).await;
            (plan, started.elapsed().as_millis())
        };
        let parallel_prestart = std::time::Instant::now();
        let (dns_race_ms, (mut runtime_binding_plan, route_binding_ms)) =
            tokio::join!(dns_race, route_binding);
        let mut runtime_binding_fingerprint: Option<InterfaceFingerprint> = None;
        let parallel_prestart_ms = parallel_prestart.elapsed().as_millis();
        log::info!("起核耗时：节点DNS竞速sidecar预置={dns_race_ms}ms");
        log::info!("起核耗时：节点逐目的网卡规划={route_binding_ms}ms");

        let (
            pid,
            api_port,
            update_in_port,
            subscription_update_in_port,
            singbox_config,
            deps,
            pruned_rule_set_tags,
            binary,
            effective_user_config,
        ) = loop {
            attempt += 1;
            // 轮首让位：退避已可中断，但被唤醒的腿仍会走到这里 —— 在**重新生成配置 / 写盘 / 重解析端口**
            // 之前就退场，别拿已被接管的世代去动共享的 runtime config 文件。这是「省功 + 早退」，
            // **不是**取消的实现（真正的取消在退避与就绪等待的 select 里）：只留这一条、把等待改回裸
            // sleep，就退回「等本轮走完才生效」的老形态。
            if self.gate.generation() != my_gen {
                log::info!(
                    "起核重试轮首被接管（世代 {my_gen} → {}）→ 让位，不再重生成/重起",
                    self.gate.generation()
                );
                return Ok(self.status());
            }

            // 每次尝试重解析空闲端口（端口重分配自愈）+ 重生成配置（端口嵌入 config，必须同刷写盘）。
            let t_config_gen = std::time::Instant::now();
            let (
                api_port,
                update_in_port,
                subscription_update_in_port,
                probe_proxy_port,
                pool_ports,
            ) = self.resolve_start_ports(&user_config, control_port);
            let deps = self.generate_deps(
                api_port,
                update_in_port,
                subscription_update_in_port,
                probe_proxy_port,
                &pool_ports,
                &config,
            );
            // 核二进制解析（**移到闸门之前**：闸门要拿它跑 `sing-box check`）。**此处刻意不 `?`** ——
            // 保住既有次序不变式「解析失败是终态 Err，但 gate 剔除结果须已推给渲染端」：先把 Result
            // 拿在手上，闸门按 `Ok` 与否决定跑不跑（解析不到 ⇒ 无核可问 ⇒ failOpen 跳过闸门），
            // emit 之后才在下面 `?`。每尝试解析（字面路径，成本极低）；解析不到 = 终态，不重试（非竞态失败）。
            let binary_res = self.core_binary_for_start();
            // 起核前的内核闸门：生成 → 写盘 → check → 剥掉内核点名拒收的节点 → 重来，直到内核收下。
            // 首次/结构变更仍真跑 check；同一核 + 同一最终生成配置命中已接受身份时为 0 次。
            let gate = match self
                .generate_and_gate_with_runtime_bindings(
                    &user_config,
                    &deps,
                    &config_path,
                    binary_res.as_deref().ok(),
                    &mut kernel_peeled,
                    &runtime_binding_plan.bindings,
                )
                .await
            {
                Ok(g) => g,
                // 🔴 生成失败也要先把「闸门此前剥掉了谁」推给渲染端，再走终态。
                //
                // 这条腿真会被走到：`PeelTarget::Blocked` 只挡「被拒的**就是**选中节点」，挡不住
                // 「剥掉的那个是选中节点代理链上的一跳」—— 后者剥完，下一轮 generate 直接 Err。
                // 裸 `?` 的话 `emit_invalid_nodes` 永远发不出去，用户拿到的是一句「配置生成失败」，
                // 而**完全不知道有节点被摘掉了**，更无从知道是哪个。这正是本闸门反复在防的
                // 「节点消失而不告知」，只是发生在失败路径上。
                Err(e) => {
                    if !kernel_peeled.is_empty() {
                        let peeled_so_far: Vec<InvalidNode> =
                            kernel_peeled.values().cloned().collect();
                        log::error!(
                            "起核内核闸门剥掉 {} 个节点后配置生成失败（很可能剥到了选中节点代理链上的一跳）：{e}",
                            peeled_so_far.len()
                        );
                        self.emit_invalid_nodes(&peeled_so_far);
                    }
                    return Err(e.into());
                }
            };
            // 起核 gate 剔除结果推渲染端（标灰 + 原因 tooltip）。发在 runtime 而非 command（入口不止 IPC：
            // 托盘/自动连接/restart 直调 self.start/崩溃自愈重启）。恒发（含空数组）：空 = 无非法节点 → 清陈旧标灰。
            // **闸门剥掉的、以及被拒的那个选中节点，都在这一份里**（走同一条通道，不另开机制；
            // 后者为什么也要进见 `GateOutcome::assemble`）。
            self.emit_invalid_nodes(&gate.invalid_nodes);
            // 内核拒的正是用户选中的节点 → 终态，不 spawn（理由见 `classify_peel_target`）。
            // **emit 必须在本判定之前**（上一行）：这条腿要 `return Err`，emit 排在后面就永远发不出去，
            // 于是恰恰是「唯一让起核失败的那个节点」拿不到标灰 —— 最需要可视标记的一次反而没有。
            // 用户由此同时拿到：持久标灰的那张卡 + 一句指名道姓的错误，而不是今天那句无从下手的「启动失败」。
            if let Some((blocked, detail)) = gate.blocked {
                let msg = format!(
                    "选中的节点「{}」被 sing-box 内核拒收，已跳过起核（请修正该节点或改选其他节点）：{detail}",
                    blocked.tag
                );
                self.set_error(&msg, code::STARTUP_FAILED);
                return Err(StartError::coded(msg, code::STARTUP_FAILED));
            }
            // 因本地 .srs 缺失被 fail-closed 剪枝的 rule_set tag（空 = 规则集完整）。随本次尝试的
            // config 一起带出循环：出口自证与用户可见信号都必须对账**这一次**生成的产物。
            let pruned_rule_set_tags = gate.pruned_rule_set_tags;
            let singbox_config = gate.config;
            let effective_user_config = gate.effective_user_config;
            let config_gen_attempt_ms = t_config_gen.elapsed().as_millis();
            config_gen_ms += config_gen_attempt_ms;
            log::info!(
                "起核耗时：配置生成+内核闸门={config_gen_attempt_ms}ms（第{attempt}次尝试，check {} 次，累计剥除 {} 个节点）",
                gate.checks_run,
                kernel_peeled.len()
            );

            // 规划与 spawn 之间网卡仍可能被拔除。对推断绑定做一次 JIT 事实复核：陈旧项从 plan
            // 剔除后重新生成配置，降级到 TUN 全局 auto-detect；显式绑定已由前置门 fail-closed，绝不进本表。
            if runtime_binding_plan.candidate_count > 0 {
                if let Some(fingerprint) = self.observe_network_interfaces().await {
                    let removed = runtime_binding_plan
                        .retain_available(&interface_availability(&fingerprint));
                    runtime_binding_fingerprint = Some(fingerprint);
                    if removed > 0 {
                        log::warn!(
                            "起核前发现 {removed} 个推断绑定接口已不可用 → 剔除陈旧绑定并重新生成配置"
                        );
                        // 这不是 spawn 失败，不消耗既有重试预算；plan 只会收缩，故最多按候选数重来。
                        attempt = attempt.saturating_sub(1);
                        continue;
                    }
                }
            }

            let binary = binary_res?;
            // C5：起核前快照 utun 基线（每尝试；macOS 时序 diff 锚点）——须在核创建 TS 内核接口**前**。
            let t_mesh_baseline = std::time::Instant::now();
            self.mesh.exit_route_snapshot_baseline().await;
            mesh_baseline_ms += t_mesh_baseline.elapsed().as_millis();
            log::info!(
                "起核（第 {attempt} 次尝试）：bin={} config={} mixedPort={mixed_port} apiPort={api_port} viaHelper={via_helper}",
                binary.display(),
                config_path.display()
            );

            // #332：本腿的核 FATAL 真因收集口。**每腿一个新槽**：重试腿之间不共享，否则第 1 腿的地址
            // 冲突会被扣到第 3 腿头上（真因错配比没有真因更糟）。
            let fatal_slot: CoreFatalSlot = Arc::new(Mutex::new(None));
            // helper 起核走的是**文件**而非 app 管道（helper 把核 stdout/stderr 经受管
            // writer 收进 `SINGBOX_STARTUP_LOG`）。新 helper fresh-rotate，旧 helper append：同时记文件身份
            // 与长度，失败时才能只扫本腿，不把上一次会话的 FATAL 误当本次真因。
            let startup_log_cursor = self.startup_log_cursor(via_helper);

            let t_spawn = std::time::Instant::now();
            let pid = if via_helper {
                // 经 helper 起（阻塞 IPC 挪 spawn_blocking；helper 核无本地 child 句柄）。
                // 让位 → Ok(None) → 静默返回（接管方拥有已提交 pid + core_via_helper 标记，负责收口）。
                match self
                    .spawn_core_via_helper(&binary, &config_path, &user_config, my_gen)
                    .await
                {
                    Ok(Some(pid)) => pid,
                    Ok(None) => return Ok(self.status()),
                    // helper 起核失败 = R27.3 已决策终态（前端 SettingsHelper 引导先装 helper），**不重试**。
                    Err(e) => {
                        self.set_error(&e, code::STARTUP_FAILED);
                        return Err(StartError::coded(e, code::STARTUP_FAILED));
                    }
                }
            } else {
                // ── 直起临界区（与 stop 的「取 child」互斥）──
                // 竞态不变式：stop() 先 bump 世代、再取 child 锁；本处在**持锁期间**判世代。
                //   · 本判定先于 stop 的 bump → 本腿 spawn 并存 child；stop 随后取到 child 并杀 → 无孤儿。
                //   · stop 的 bump 先于本判定 → 本腿直接让位、**根本不 spawn** → 无孤儿。
                self.core_via_helper.store(false, Ordering::SeqCst);
                let mut guard = self
                    .child
                    .lock()
                    .map_err(|e| format!("child lock poisoned: {e}"))?;
                if self.gate.generation() != my_gen {
                    log::info!(
                        "起核在 spawn 前被接管（世代 {my_gen} → {}）→ 让位",
                        self.gate.generation()
                    );
                    return Ok(self.status());
                }
                // stdout/stderr → 日志 sink（logging.rs 已装 log::Log 实现）。**排空接线写在请求里**：
                // spawner 在返回之前就把两个读端交给这个闭包，核从起来的第一毫秒起就有人读它，
                // 「起了核却忘记排空」在类型上写不出来（见 `StdioPolicy`）。
                // stdout 不接真因收集：sing-box 的 `log.Fatal` 走包级 `std` logger，其 writer 恒是
                // **os.Stderr**（`log/export.go` 的 `init()`；`--disable-color` 分支 `cmd/sing-box/cmd.go:55`
                // 换的也仍是 os.Stderr）。给 stdout 也接一份 = 白扫每一行。
                // 两条腿共用同一个交接闸：核就绪后日志改由 `SubscribeLog` 流承担，本腿只剩起核期与
                // FATAL 分类（见 `pipe_to_log` 文档）。
                let handoff: CoreLogHandoff = Arc::new(AtomicBool::new(false));
                let sink_handoff = Arc::clone(&handoff);
                let sink_fatal = Arc::clone(&fatal_slot);
                let mut req = SpawnRequest::new(
                    &binary,
                    &config_path,
                    StdioPolicy::drain(move |stdout, stderr| {
                        pipe_to_log(
                            stdout,
                            SING_BOX_TARGET,
                            None,
                            Some(Arc::clone(&sink_handoff)),
                        );
                        pipe_to_log(
                            stderr,
                            SING_BOX_TARGET,
                            Some(sink_fatal),
                            Some(sink_handoff),
                        );
                    }),
                );
                // 核输出恒进日志 sink（非 TTY）；sing-box 不自行关色，不加 flag 会混入 ANSI 转义。
                req.extra_args = vec!["--disable-color".to_string()];
                // CWD = 可写 config 目录：GUI 从 Finder/launchd 拉起时父进程 CWD=`/`，核对 dashboard 下载兜底的
                // 相对目录按 CWD 解析会落 `/dashboard`（只读 mkdir 噪音）。Polaris 生成的其余路径全绝对，不受影响。
                req.working_dir = Some(self.config.dir().to_path_buf());
                let spawned = match TokioSpawner::new().spawn(req) {
                    Ok(s) => s,
                    Err(e) => {
                        // spawn launch 失败：释放 child 锁再判重试。端口/资源竞态可重试；权限/enoent/配置无效
                        // 等确定失败 → 终态（is_retryable_start_error）。已在锁前置 core_via_helper=false，无核可孤。
                        drop(guard);
                        let msg = format!("{e}");
                        if attempt <= budget.max_retries && is_retryable_start_error(&msg) {
                            log::warn!("sing-box spawn 失败（第 {attempt} 次，可重试）→ 预算内自动重试：{msg}");
                            // 退避期被接管 → 让位（本腿 spawn 就没成，无核可孤；不 set_error、不重试）。
                            let t_backoff = std::time::Instant::now();
                            let superseded =
                                self.sleep_start_backoff(&budget, attempt, my_gen).await;
                            retry_backoff_ms += t_backoff.elapsed().as_millis();
                            if superseded {
                                return Ok(self.status());
                            }
                            continue;
                        }
                        self.set_error(&msg, code::STARTUP_FAILED);
                        return Err(StartError::coded(msg, code::STARTUP_FAILED));
                    }
                };
                let pid = spawned.pid().unwrap_or(0);
                log_pipe_handoff = Some(handoff);
                *guard = Some(spawned.child);
                pid
            };
            let spawn_attempt_ms = t_spawn.elapsed().as_millis();
            spawn_ms += spawn_attempt_ms;
            log::info!("起核耗时：spawn子进程={spawn_attempt_ms}ms（viaHelper={via_helper}）");
            // helper 腿已经在 IPC 回包后立即提交 pid 并完成存活探测；这里只提交直起腿，避免同一 pid
            // 连续写两次同一把锁。该微段单独记账，验证它是否值得继续优化，而不是凭感觉删安全检查。
            if !via_helper {
                let pid_commit_started = std::time::Instant::now();
                if let Ok(mut g) = self.pid.lock() {
                    *g = Some(pid);
                }
                log::info!(
                    "起核耗时：直起pid提交={}us",
                    pid_commit_started.elapsed().as_micros()
                );
            }
            log::info!("sing-box 已 spawn：pid={pid}（viaHelper={via_helper}）");

            // ── 就绪门（core-supervisor 既有轮询逻辑；本层只注入真实 I/O）──
            //
            // 预算按**本次真正下发给核的那一份 config** 的规模算（naive 出站每个都是一个独立
            // Cronet Engine，内核在 bind 入站之前串行创建）。取材必须是 `singbox_config` 而不是
            // `user_config.servers`：两者之间隔着协议开关、订阅筛选与内核闸门剥离，从后者推必然与核
            // 实际拿到的那份漂移。**每腿重算**：闸门剥离是跨腿累积的，第 2 腿的 naive 数可能更少。
            let ready_budget_ms = main_core_ready_timeout_ms(&singbox_config);
            log::info!(
                "就绪门预算：{ready_budget_ms}ms（下限 {CORE_READY_TIMEOUT_FLOOR_MS}ms，本次下发 {} 个出站/端点、其中 naive {} 个）",
                main_core_parse_unit_count(&singbox_config),
                main_core_naive_count(&singbox_config)
            );
            let t_ready = std::time::Instant::now();
            let ready_outcome = self.wait_ready(api_port, my_gen, ready_budget_ms).await;
            ready_ms += t_ready.elapsed().as_millis();
            match ready_outcome {
                CoreReadyOutcome::Ready => {
                    // #327：就绪 ≠ TUN 网卡建出来了（就绪门只验管理口 + 进程活）。**逐腿**正向验证适配器
                    // 存在性；缺失 = 本腿失败，走重试预算而非直接硬终止 —— 网卡挂载失败多为瞬态，而重试
                    // 腿开头的 kill_core 会把这一次的核连同它半建的网卡一并清掉，下一腿是干净的重来。
                    let t_tun_adapter = std::time::Instant::now();
                    let observation = self
                        .probe_tun_adapter_present(
                            user_config.proxy_mode_type,
                            &tun_adapter_name,
                            attempt,
                        )
                        .await;
                    tun_adapter_ms += t_tun_adapter.elapsed().as_millis();
                    if observation == TunAdapterObservation::Present {
                        tun_adapter_ever_seen = true;
                    }
                    let verdict = classify_tun_adapter_leg(
                        observation,
                        tun_adapter_ever_seen,
                        attempt,
                        budget.max_retries,
                    );
                    if verdict == TunAdapterVerdict::Proceed {
                        break (
                            pid,
                            api_port,
                            update_in_port,
                            subscription_update_in_port,
                            singbox_config,
                            deps,
                            pruned_rule_set_tags,
                            // 本次真正解析出的核路径 —— 起核后的内核自证要对账的正是**这一次**的期望值
                            //（每次尝试都重解析，故必须随本轮结果带出循环，不能在循环外重算）。
                            binary,
                            // 🔴 内核闸门剥除之后、**真正生成这份 config 的那套 servers**。
                            // 循环外紧接着就用它遮蔽 `user_config`，让出口自证 / 热切快照 / TS 逆表
                            // 三处按 id 反算 tag 时，算的是运行核里真实存在的那套 tag。
                            effective_user_config,
                        );
                    }
                    // 探测最长 3s，期间可能被接管 → 与 Dead/Timeout 两腿同款复查：世代变了就静默让位
                    //（不 kill、不 set_error、不重试；接管方拥有该进程的所有权）。
                    if self.gate.generation() != my_gen {
                        log::info!("TUN 适配器验证期被接管（世代 {my_gen}）→ 让位，不闸");
                        return Ok(self.status());
                    }
                    // 核确实活着（就绪门刚判过），但它没有 TUN ⇒ 标 connected 是虚报，先拆掉再谈重试。
                    self.kill_core().await?;
                    if verdict == TunAdapterVerdict::RetryLeg {
                        log::warn!(
                            "TUN 适配器未建出（第 {attempt} 次，iface={tun_adapter_name}）→ 预算内自动重试"
                        );
                        // 同 Dead/Timeout 腿：已 `kill_core()` → 取消腿无孤儿。
                        let t_backoff = std::time::Instant::now();
                        let superseded = self.sleep_start_backoff(&budget, attempt, my_gen).await;
                        retry_backoff_ms += t_backoff.elapsed().as_millis();
                        if superseded {
                            return Ok(self.status());
                        }
                        continue;
                    }
                    // 预算耗尽的两条终态：**必须分开**（用户的下一步动作不同，见 code 模块该项文档）。
                    let (msg, error_code) = if verdict == TunAdapterVerdict::TerminalNeverAppeared {
                        (
                            TUN_ADAPTER_MISSING_MSG.to_string(),
                            code::TUN_ADAPTER_MISSING,
                        )
                    } else {
                        // 曾见过又消失：wintun 本身建得出来，故不发 TUN_ADAPTER_MISSING（那会把用户
                        // 导向「重装驱动」这条错误的下一步）。message 载明现场，走 STARTUP_FAILED
                        // 的第 2 段原文送达（该码在前端覆盖门里正是按「message 才是诊断」豁免的）。
                        (
                            format!(
                                "TUN 虚拟网卡 {tun_adapter_name} 反复消失（起核期建出后又不见），已重试 {attempt} 次仍失败"
                            ),
                            code::STARTUP_FAILED,
                        )
                    };
                    self.set_error(&msg, error_code);
                    return Err(StartError::coded(msg, error_code));
                }
                CoreReadyOutcome::Superseded => {
                    // #176：被接管 → 静默让位，**绝不清理/绝不重试**（接管方拥有进程/端口所有权）。
                    log::info!("起核就绪等待期被接管（世代 {my_gen}）→ 静默让位，不清理");
                    return Ok(self.status());
                }
                // Dead/Timeout 腿在报错前**必须复查世代**：`wait_for_core_ready` 每轮只在轮首判一次
                // supersede，故存在「本轮已过 supersede 检查 → 用户点停止（bump 世代 + kill_core 取走
                // child）→ 同轮 is_ready 失败、is_alive 见 child=None 判进程死」的窗口 → 返 Dead 而非
                // Superseded。世代不等即等价让位腿：静默返回，不 kill、不 set_error、不重试。
                CoreReadyOutcome::Dead => {
                    if self.gate.generation() != my_gen {
                        log::info!("起核就绪期被接管（世代 {my_gen}，判定 Dead 系接管方拆核所致）→ 静默让位");
                        return Ok(self.status());
                    }
                    self.kill_core().await?;
                    let msg = "sing-box 启动期退出".to_string();
                    // #332：核自己吐的 FATAL 才知道**为什么**退出（就绪门只看得到「没了」）。
                    let fatal =
                        self.observe_core_fatal(via_helper, startup_log_cursor, &fatal_slot);
                    // #159/#176：起核期退出（CoreStartRetryError 等价，恒可重试）→ 预算内静默重起（届时
                    // wintun 适配器/双 utun 已释放，新尝试重解析端口+重生成盘）。上面已 kill_core → 无孤儿核。
                    if attempt <= budget.max_retries {
                        log::warn!("sing-box 起核期退出（第 {attempt} 次）→ 预算内自动重试");
                        // 退避期被接管 → 让位。**此处已 `kill_core()`**（上一行）⇒ 取消腿落的是干净终态：
                        // 无残留进程、无半启动状态（status 仍是上一稳定值，由接管方的 stop 清）。
                        let t_backoff = std::time::Instant::now();
                        let superseded = self.sleep_start_backoff(&budget, attempt, my_gen).await;
                        retry_backoff_ms += t_backoff.elapsed().as_millis();
                        if superseded {
                            return Ok(self.status());
                        }
                        continue;
                    }
                    let (msg, error_code) = settle_start_failure(msg, fatal);
                    self.set_error(&msg, error_code);
                    return Err(StartError::coded(msg, error_code));
                }
                CoreReadyOutcome::Timeout => {
                    if self.gate.generation() != my_gen {
                        log::info!("起核就绪期被接管（世代 {my_gen}，判定 Timeout 系接管方拆核所致）→ 静默让位");
                        return Ok(self.status());
                    }
                    self.kill_core().await?;
                    // 文案必须说得清「是不是规模导致的」：门已经按规模放宽过，只报「管理 API 未就绪」
                    // 会把用户导向端口/网络这条错误的下一步（见 `main_core_ready_timeout_message`）。
                    let msg =
                        main_core_ready_timeout_message(api_port, &singbox_config, ready_budget_ms);
                    // #332：超时腿同样可能是核已 FATAL 退出、只是就绪门先走完了预算（真因照样在 stderr 里）。
                    let fatal =
                        self.observe_core_fatal(via_helper, startup_log_cursor, &fatal_slot);
                    if attempt <= budget.max_retries {
                        log::warn!("sing-box 起核超时（第 {attempt} 次）→ 预算内自动重试");
                        // 同 Dead 腿：已 `kill_core()` → 取消腿无孤儿。
                        let t_backoff = std::time::Instant::now();
                        let superseded = self.sleep_start_backoff(&budget, attempt, my_gen).await;
                        retry_backoff_ms += t_backoff.elapsed().as_millis();
                        if superseded {
                            return Ok(self.status());
                        }
                        continue;
                    }
                    let (msg, error_code) = settle_start_failure(msg, fatal);
                    self.set_error(&msg, error_code);
                    return Err(StartError::coded(msg, error_code));
                }
            }
        };

        // 就绪后再判一次世代：轮询末次判定与本处之间仍有窗口，接管方可能已拆核。
        if self.gate.generation() != my_gen {
            log::info!("起核就绪后被接管（世代 {my_gen}）→ 让位");
            return Ok(self.status());
        }

        // C-tun-conflict：post-flight 出口归属硬闸（仅 TUN 模式；设计 §4.2 方向①后验，D1/D2）。就绪 ≠ 夺到
        // 默认路由 —— 他方 VPN 仍占默认出口时我方 utun 抢不到流量，标 connected 是虚报（真机复现 2026-07-22）。
        // grace 内轮询出口接口，仍未从 baseline 切走 → 不标 running：kill_core + 报 TUN_ROUTE_NOT_CAPTURED。
        // 置于 running:true **之前**（D2 延后标，不做「先标再降级」的闪烁）。
        let t_tun_route = std::time::Instant::now();
        let captured_tun_interface = match self
            .verify_tun_route_captured(user_config.proxy_mode_type, tun_route_baseline)
            .await
        {
            Ok(interface) => interface,
            Err(msg) => {
                // grace（数秒）内可能被接管：先复查世代，被接管则静默让位（不 kill、不 set_error，同 Dead/Timeout 腿）。
                if self.gate.generation() != my_gen {
                    log::info!("TUN 出口 post-flight 期被接管（世代 {my_gen}）→ 让位，不闸");
                    return Ok(self.status());
                }
                self.kill_core().await?;
                self.set_error(&msg, code::TUN_ROUTE_NOT_CAPTURED);
                return Err(StartError::coded(msg, code::TUN_ROUTE_NOT_CAPTURED));
            }
        };
        let tun_route_ms = t_tun_route.elapsed().as_millis();
        log::info!("起核耗时：TUN路由校验={tun_route_ms}ms");

        // 🔴 **自此往下 `user_config` 一律指剥除后的那份。**
        //
        // 下面三处都要按 `serverId` 反算运行核里的 outbound tag：
        //   `build_switch_snapshot`（规则热切 PUT 的目标出站）
        //   `endpoint_tag_to_id`（端点 STATUS 帧的逆映射）
        //   `attest_selected_exit`（出口自证 —— `code::EXIT_MISMATCH` 是「用户以为走代理、实则
        //     明文直连」的唯一告警通道）
        // 而 `build_id_to_tag_map` 按**名字**去重、撞名追加 `(n)` ⇒ tag 是整个集合的函数。
        // 内核闸门剥掉「HK」之后，原本的「HK (1)」在运行核里就叫「HK」；这三处若拿未剥的全量
        // servers 算，得到的 tag 在运行核里根本不存在 —— 后果不是报错而是**静默错**：
        // 出口完全正确却打 EXIT_MISMATCH 假警报（告警一旦有假就会被整体无视），
        // 热切 PUT 打到不存在的出站上无声失败。
        //
        // 用遮蔽而不是逐处换参：遮蔽之后**任何**新增的下游消费点都自动拿到正确的那份，
        // 逐处换参则要求每个后来者都记得这件事。
        let user_config = effective_user_config;

        let new_status = ProxyStatus {
            running: true,
            // 读时投影字段，存储态恒 false（真值 = `start_inflight` 计数，见字段文档）。
            starting: false,
            pid,
            // 起核就绪时刻 = 运行时长的零点。**取就绪后而非 spawn 时**：就绪前核还没在服务，
            // 把 12s 就绪门算进「已运行」是虚报。与 running 同生共死（stop/set_error 经 Default 清回 None）。
            start_time: Some(now_ms()),
            // 读时投影，存储态恒 None（见 ProxyStatus 文档）。
            uptime: None,
            mixed_port,
            clash_api_port: api_port,
            // C19：暴露给更新链路消费方（resolve_update_proxy_target 据此选走 update-in 口 vs 直连）。
            update_in_port,
            subscription_update_in_port,
            // C6-5：据实际走哪条路由落面向前端的标记（helper 提权 vs 直起）。
            started_via_helper: via_helper,
            error: None,
            error_code: None,
        };
        // 热切换基准：**与 running 状态同生共死**（此处置、stop 清）→「快照在 ⟺ 核在跑」。
        // 上游 在生成期就回填，但那样起核失败时会留下描述「不存在的核」的快照；此处收紧到就绪后。
        if let Ok(mut g) = self.switch_snapshot.write() {
            *g = Some(Self::build_switch_snapshot(
                &user_config,
                &singbox_config,
                &deps,
            ));
        }
        if let Ok(mut g) = self.current_config.write() {
            *g = Some(config.clone());
        }
        if let Ok(mut snap) = self.startup_snapshot.write() {
            *snap = Some(config);
        }
        // 核刚按磁盘配置生成并起来 ⇒ 一切「保存但没进核」的欠账在这一刻结清。
        // 清点必须与 `startup_snapshot` 同刻：这两者一起定义了「运行核吃进去的是什么」。
        self.restart_deferred.store(false, Ordering::SeqCst);
        if let Ok(mut g) = self.status.write() {
            *g = new_status.clone();
        }
        // A1：systemProxy 模式把 OS 系统代理指向本地 mixed 入站（127.0.0.1:mixedPort），否则流量不经核
        // = 表现「选直连也没启动」。放在**核已就绪之后**：核未就绪就设代理会把流量导向尚未服务的端口。
        // 与下方 residual 提示互斥（前者只在 systemProxy 生效、后者只在 tun 生效，见各自门控）。
        //
        // **必须早于 ready 生命周期 PUSH**：`App.tsx` 收到 ready 会立即重拉 `running:true`，继而触发
        // `system_proxy_get_status` 活态查询。若先 PUSH 再 await Windows `reg`，渲染端会在这段真实的启动事务
        // 中读到旧注册表、误报「系统代理未生效」，且把误报保留到 15s 后的下一拍。这里等待的是既有系统
        // 代理写入本身，不加延时；失败腿也会先落 `SYSTEM_PROXY_FAILED`，随后 ready 刷到的是诚实降级态。
        let t_system_proxy = std::time::Instant::now();
        self.maybe_enable_system_proxy(&user_config, mixed_port)
            .await;
        let system_proxy_ms = t_system_proxy.elapsed().as_millis();
        log::info!("起核耗时：系统代理设置={system_proxy_ms}ms");
        // 差集分母已换新，但此处**不提前 PUSH**：系统代理/DNS 等接管腿尚未落定，UI 收到同点配对的
        // ready 后会立刻探活。成功 PUSH 统一收在 `start` 包装的终态腿（先归还 `starting` 计数，再相邻发布
        // 差集 + ready）；失败/让位则各走自己的终态，不把“核端口已监听”冒充“接管事务已完成”。
        // **H3 修复接线点**：核就绪 → 后台把各 selector 的选择校正回本次 config 的意图（压过 cache_file
        // 持久化的旧选择），校正完成/放弃后才失效解锁缓存。三条时序都是承重的，见
        // [`spawn_reassert_selector_selection`](Self::spawn_reassert_selector_selection) 的方法文档：
        //  ① **spawn 而非 await**：校正最长 10×300ms ≈ 3s，挂在主链上等于给已经偏慢的起核再加 3s；
        //  ② **无条件跑**（不套「配置里有 TS 节点」的门）：cache_file 覆盖 default 与 TS 无关，任何
        //     协议的选中节点都会被上一轮的残留选择顶掉（真机血证：盘上选 Hk01、核实走 Tailscale）；
        //  ③ **失效解锁缓存 + 重探出口 IP + 连接 flush 三条一并挪进续延**（上游 F-C 与「时序修 E」）：
        //     校正可能真翻转 selector，boot 窗口内起跑的解锁轮/出口探测量的都是**旧出口**，其结果会被
        //     当新鲜数据 commit 污染缓存；而 flush 的无差别 RST 会让全部连接**立刻按旧 selector 重连** ——
        //     三条都必须等校正落定（各自的具体理由见 `after_selector_reasserted`）。
        self.spawn_reassert_selector_selection(user_config.clone(), my_gen, api_port);
        // 核就绪 → 挂后台崩溃监测（**唯一**接线点：只在真正 running 后起，让位/失败腿不挂）。
        // 监测「核意外退出」并触发崩溃自愈；主动 stop/restart 由世代区分不误触（见 `spawn_crash_monitor`）。
        self.spawn_crash_monitor(my_gen);
        // 核就绪 → 挂核日志 relay（`SubscribeLog`，同世代范式）。**无条件挂**：这是 TUN/helper 腿上
        // 日志页唯一的核日志来源，也是「改级别立刻生效、不必重启核」的承载（见方法文档）。
        // `log_pipe_handoff` 区分直起（有 stderr 管道，需交接 + 丢首帧历史）与 helper 起（无管道，收历史）。
        self.spawn_core_log_relay(my_gen, api_port, log_pipe_handoff.clone());
        // C3：核就绪 → 挂自动换节点心跳（同世代范式）。**无条件挂**，开关在循环内每 tick 读 `autoSwitchNode`
        // 动态判（对齐 上游 运行期 enable/disable）。与崩溃监测解耦：崩溃原地重启同节点，本腿只对「核活着
        // 但代理链不通」换节点。世代守卫退场同 relay。
        //
        // **停摆判据在此求值、作为世代常量传下去**（不是每 tick 读配置）：`user_config` 就是核实际
        // 启动的那份，`route.final` 由它烘死，同世代内不可能变；而这条判据一旦翻转，`hotswitch.rs`
        // 的 route 投影 guard 就返回 none ⇒ 整核重启 ⇒ 世代 +1 ⇒ 旧心跳退场。
        // 完整理由（含「per-tick 读 D 反而会错」与 `ts_exit.rs` 那道禁 `.current()` 的门）见
        // [`auto_switch_blocked_for_generation`](crate::runtime::auto_switch::auto_switch_blocked_for_generation)。
        self.spawn_auto_switch_heartbeat(
            my_gen,
            deps.probe_proxy_port,
            crate::runtime::auto_switch::auto_switch_blocked_for_generation(&user_config),
        );
        // A3：核就绪 → 挂 Tailscale STATUS relay（同世代范式）。tag→id 从**核实际启动的这份配置**构建
        // （核发的 endpointTag 恒是它启动时的 tag）。仅当配置含 tailscale 节点时才起（无 TS 节点 = 无端点帧，
        // 白建订阅纯浪费）。停核/接管由世代守卫退场 + `stop_inner`/崩溃腿清缓存。
        let has_tailscale = user_config.servers.iter().any(|server| {
            server.protocol
                == polaris_config_engine::user_config::server_config::Protocol::Tailscale
        });
        let has_openconnect = user_config.servers.iter().any(|server| {
            server.protocol
                == polaris_config_engine::user_config::server_config::Protocol::Openconnect
        });
        let has_openvpn = user_config.servers.iter().any(|server| {
            server.protocol
                == polaris_config_engine::user_config::server_config::Protocol::OpenvpnClient
        });
        // 三种 endpoint STATUS 共用一次逆映射构建。命令提交时仍会经
        // `management_target_for(serverId)` 重新解出本会话 endpoint tag。
        let endpoint_tag_to_id = (has_tailscale || has_openconnect || has_openvpn)
            .then(|| Arc::new(Self::endpoint_tag_to_id(&user_config)));
        if has_tailscale {
            self.spawn_tailscale_status_relay(
                my_gen,
                api_port,
                Arc::clone(endpoint_tag_to_id.as_ref().expect("endpoint map exists")),
            );
        }
        // rc.2 原生端点状态：只为实际存在的协议挂对应流。tag 逆映射与 Tailscale 共用同一份运行配置
        // 真值；命令提交时仍会经 `management_target_for(serverId)` 重新解出本会话 endpoint tag。
        if has_openconnect {
            self.spawn_openconnect_status_relay(
                my_gen,
                api_port,
                Arc::clone(endpoint_tag_to_id.as_ref().expect("endpoint map exists")),
            );
        }
        if has_openvpn {
            self.spawn_openvpn_status_relay(
                my_gen,
                api_port,
                endpoint_tag_to_id.expect("endpoint map exists"),
            );
        }
        // A4 触发点③（起核预置）**已折入上面的 selector 校正 stage 1**（上游 同款：`wantDirect` 时 PUT
        // `direct` 而非节点 tag）。此处不再单独预置 —— 两个独立写者对同一个 `proxy-selector` 各写一次，
        // 谁最后落地取决于调度，正是「flag 说已让位、selector 却指着未登录的 TS 出口」这类脱节的来源。
        log::info!("sing-box 已就绪：pid={pid} apiPort={api_port}");
        // **规则资源缺失告知**（T3）：本次生成真有 rule_set 被 fail-closed 剪掉 → 分流规则整段没了，
        // 用户看到的「智能分流」名不副实。放在出口自证**之前**：这是根因，出口自证是后果，后者若也
        // 命中应由它覆写 status（更贴近用户观感的「走错出口」）。两条都各自 emit 事件，互不遮蔽。
        // 空清单（资源齐全）→ 不发，零噪音。
        self.warn_pruned_rule_resources(&pruned_rule_set_tags);
        // **出口自证**：核已就绪 → 校验「实际生效出口 == 选中节点」，不一致即告警，绝不静默显示「已连接」。
        // 放在 A1 之后：二者是正交的两条降级轴（A1 = OS 没把流量导进核；本检查 = 核内部出口指错了），
        // 各自独立 emit，互不遮蔽。纯静态、零 I/O、微秒级 → 不给已经偏慢的起核路径增加任何延迟。
        self.attest_selected_exit(&user_config, &singbox_config);
        // **内核自证**：核已就绪 → 问系统「这个 pid 实际在跑哪个文件、那个文件是什么版本」，
        // 与本次期望的核对账，不一致即告警。与上面的出口自证是两条正交轴，且**判据形态刻意不同**：
        // 出口自证纯静态（意图 vs 意图），本条只吃事实（内核记账 + 真跑一次 version）——
        // 因为「app 请求 bin=A / helper 实跑 bin=B」这类分叉，静态对账天然看不见（见方法文档血证）。
        self.spawn_running_core_binary_attestation(pid, binary.clone(), my_gen);
        // TUN 起来了 → 后台查一次「别人设的系统代理」并提示（只读不动手，见下方方法文档）。
        // 这只是 advisory、不是起核成立条件；Windows 真机首次 `reg query` 曾因系统冷态/安全软件扫描
        // 阻塞约 12s，把它 await 在主链会让网卡与路由早已就绪却仍显示「连接中」。后台腿带世代 +
        // running 守卫，停核/重连后不会补发陈旧提示。
        self.spawn_system_proxy_residual_warning(user_config.proxy_mode_type, my_gen);
        // C5：核就绪后对齐 mesh 出口路由。契约 #37「绝不抢 sing-box 路由」的让位判定在 crate 内建
        // （仅 TS System + 承载全隧道出口才装单条 ifscope default，其余 None=让位）。**OS 路由操作已全链
        // 接线**（`HelperExitRouteOp`：mac/win 经 helper `route -ifscope`、Linux `ip rule/route` 表 7732）
        // → 生产下是真手术（真机门），测试构造 `enabled=false` 诚实 no-op，见 `runtime/mesh.rs`。
        let t_mesh_route = std::time::Instant::now();
        self.mesh
            .exit_route_reconcile(&user_config, user_config.enable_ipv6.unwrap_or(false))
            .await;
        let mesh_route_ms = t_mesh_route.elapsed().as_millis();
        log::info!("起核耗时：mesh路由接线={mesh_route_ms}ms");
        // C7：TUN 起核尾接管系统 DNS（mac networksetup；Linux helper→resolved；Windows no-op）。
        // 门 = **TUN 模式 且 用户未关 `dnsConfig.takeoverSystemDns`**（1:1 上游 `ProxyManager.ts:1103`
        // `proxyModeType === 'tun' && config.dnsConfig?.takeoverSystemDns !== false`）。
        //
        // 两条门是**合取而非冲突**：TUN 是「什么时候技术上需要接管」（on-link 的 LAN/ISP DNS 不进 TUN →
        // hijack-dns 看不到），开关是「用户是否同意我们动系统解析器」（企业内网/自管 DNS 的用户会关）。
        // 此前开关在 Rust 侧无消费者 = 装饰开关：用户关掉后系统 DNS 照样被改写，且**关不掉也还不回来**。
        //
        // else 腿（非 TUN / 用户关了）只还原可能残留的受控 DNS（对齐 上游 同处 else 分支）：覆盖
        // 「TUN→其它模式」与「开→关」两种切换。通用网络 watcher 不归 DNS 开关管，见分支后的统一启动。
        let t_dns = std::time::Instant::now();
        if user_config.proxy_mode_type.is_tun() && dns_takeover != Some(false) {
            self.set_system_dns_best_effort().await;
        } else {
            self.restore_system_dns_best_effort().await;
        }
        // 会话级绑定事实与 watcher 同刻接管。推断候选为空但存在显式绑定时也补一份快照，保证首次
        // 热插拔就能识别“失效”而不是把当前不可用状态误当基线。
        let explicit_interfaces = required_bind_interfaces(&user_config);
        let managed_tun_interface = managed_tun_interface_for_session(
            &user_config,
            Platform::current(),
            captured_tun_interface,
        );
        let pre_ready_fingerprint = runtime_binding_fingerprint.clone();
        if runtime_binding_plan.candidate_count > 0 || !explicit_interfaces.is_empty() {
            if let Some(latest) = self.observe_network_interfaces().await {
                runtime_binding_fingerprint = Some(latest);
            }
        }
        let inferred_binding_changed_while_starting = inferred_binding_replan_needed(
            &NetworkChangeImpact {
                interface: true,
                ..Default::default()
            },
            &runtime_binding_plan,
            pre_ready_fingerprint.as_ref(),
            runtime_binding_fingerprint.as_ref(),
            managed_tun_interface
                .as_ref()
                .and_then(ExitInterfaceId::alias),
        );
        let explicit_unavailable = runtime_binding_fingerprint
            .as_ref()
            .map(|fingerprint| required_interfaces_unavailable(&explicit_interfaces, fingerprint))
            .unwrap_or_default();
        if !explicit_unavailable.is_empty() {
            let message = explicit_unavailable.diagnostic();
            log::warn!("起核后显式绑定网卡已不可用：{message}");
            self.set_nonfatal_error(&message, code::OUTBOUND_INTERFACE_UNAVAILABLE);
        }
        if let Ok(mut state) = self.runtime_binding_state.lock() {
            *state = RuntimeBindingState {
                plan: runtime_binding_plan.clone(),
                interface_fingerprint: runtime_binding_fingerprint.clone(),
                explicit_unavailable,
                managed_tun_interface: managed_tun_interface.clone(),
            };
        }
        // 网络恢复探测是所有接管模式的公共能力，不能挂在「TUN 且 DNS 接管成功」这个窄门下。
        // DNS 热插拔重灌仍由 handle_network_change → dns_reconcile_should_run 独立门控。
        // watcher 只消费别名：Windows 订阅按别名解 LUID，macOS/Linux 按别名做文本匹配。
        self.spawn_network_watcher(
            managed_tun_interface
                .as_ref()
                .and_then(ExitInterfaceId::alias)
                .map(str::to_owned),
        );
        if inferred_binding_changed_while_starting {
            log::warn!("起核就绪前推断绑定接口事实发生变化 → 调度一次受控重启重新规划");
            self.schedule_restart();
        }
        let dns_ms = t_dns.elapsed().as_millis();
        log::info!("起核耗时：DNS接管={dns_ms}ms");
        // C7：核就绪尾刷 OS DNS 缓存（fire-and-forget，对齐 上游 `flushOsDnsCacheBestEffort('start')`）。
        self.flush_os_dns_cache_best_effort("start");
        // **#9** 的连接 flush 已挪进 [`after_selector_reasserted`]（selector 校正的续延），不在主链上。
        // 它本身的立意没变（app 早于 TUN 建立、已泄漏成真实 IP 的旧连接若不 RST 会继续走物理网卡直出，
        // 而用户看到的是「已连接」），只是**开枪时机**必须晚于 selector 校正：被 RST 的连接会立刻重连，
        // 重连按重连那一刻的 selector 走 —— 早于校正就等于把用户所有连接亲手踢到 cache_file 的旧出口上。
        // 「running:true 落定之后」这条原有约束依然成立且更强：续延只可能更晚。
        // 总计：分段累计 + 未归因墙钟。未归因值把后续仍值得拆分的同步边角直接暴露出来，避免“段和看似
        // 很快、用户却仍等很久”；后台二进制自证不在主链，故不计入本总计。
        let segments_ms = preflight_ms
            + helper_gate_ms
            + rules_prep_ms
            + tun_baseline_ms
            // DNS sidecar 与逐目的网卡规划并行执行；归因总计只能计一次墙钟，不能把两条子耗时相加。
            + parallel_prestart_ms
            + config_gen_ms
            + mesh_baseline_ms
            + spawn_ms
            + ready_ms
            + tun_adapter_ms
            + retry_backoff_ms
            + tun_route_ms
            + system_proxy_ms
            + mesh_route_ms
            + dns_ms;
        let total_ms = t_total.elapsed().as_millis();
        let unattributed_ms = total_ms.saturating_sub(segments_ms);
        log::info!(
            "起核耗时：总计={total_ms}ms（已归因={segments_ms}ms 未归因={unattributed_ms}ms：\
             前置校验={preflight_ms}ms helper提权门={helper_gate_ms}ms 规则预置={rules_prep_ms}ms \
             TUN基线={tun_baseline_ms}ms 并行预置墙钟={parallel_prestart_ms}ms \
             [DNS竞速={dns_race_ms}ms 节点逐目的网卡={route_binding_ms}ms] 配置生成累计={config_gen_ms}ms \
             mesh基线累计={mesh_baseline_ms}ms spawn累计={spawn_ms}ms 就绪等待累计={ready_ms}ms \
             TUN适配器累计={tun_adapter_ms}ms 重试退避累计={retry_backoff_ms}ms \
             TUN路由校验={tun_route_ms}ms 系统代理设置={system_proxy_ms}ms \
             mesh路由接线={mesh_route_ms}ms DNS接管={dns_ms}ms）"
        );
        Ok(new_status)
    }

    /// **C6-5**：经提权 helper 起 root/SYSTEM 受管核（TUN 路由）。移植自 上游 `startViaHelper`。
    ///
    /// 返回 `Ok(Some(pid))` = 已起（daemon 报告受管核 pid）；`Ok(None)` = 起核前被接管 → 让位；
    /// `Err` = 通信/起核失败。
    ///
    /// DESIGN-REVIEW(c6-5-src-tauri-helper-wiring)：(R27.3) 不实现 上游 #159「helper 起核失败→回退
    /// UAC/osascript 直起重试」增强腿——失败直接报错（前端 SettingsHelper 引导先装 helper）。
    /// (R27.2) 孤儿残余微竞态（stop 的 Stop 与本 Start 在 daemon 单 mu 到达序）= 真机门，与 上游 同形。
    ///
    /// **孤儿不变式**：`core_via_helper` 标记先于 IPC 置、pid 于 `start_core` 返回即提交（对齐 上游 在
    /// `startCore` 返回即置 `singboxPid`，:4430）——这样任何随后 bump 世代的 stop 的 [`kill_core`](ProxyRuntime::kill_core) 都能据
    /// 标记走 helper stop（daemon 摘其受管 child，无需 app 传 pid），封死「app 让位但 root 核残留」。
    /// **残余微竞态**（stop 的 Stop 与本 Start 在 daemon 单 mu 上的到达序）= 真机门（与 上游 同形）。
    pub(super) async fn spawn_core_via_helper(
        self: &Arc<Self>,
        binary: &Path,
        config_path: &Path,
        user_config: &UserConfig,
        my_gen: u64,
    ) -> Result<Option<u32>, String> {
        // 让位早退（与直起临界区的「持锁判世代」同义；helper 核无本地 child 锁可持，靠世代 + 标记守）。
        if self.gate.generation() != my_gen {
            log::info!("helper 起核前被接管（世代 {my_gen}）→ 让位");
            return Ok(None);
        }
        // **受保护核对账**（换核在本条腿上真正生效的唯一途径）：helper 只会 exec 它安装期锁定的那个
        // 路径，故必须先把现役核的**内容**推进去。幂等——hash 相同即零动作、零 IPC。
        // 放在置 `core_via_helper` 标记与 IPC 之前：此刻还没有受管核，失败也不产生孤儿。
        self.reconcile_protected_core(binary).await;
        // 先于 IPC 置标记：racing stop 的 kill_core 据此走 helper stop（child 恒 None）。
        self.core_via_helper.store(true, Ordering::SeqCst);
        let log_path = self.config.join(SINGBOX_STARTUP_LOG);
        // fwd = allowLan（helper 侧开 IP 转发；上游 `forward = !!currentConfig.allowLan`）。
        let fwd = user_config.allow_lan.unwrap_or(false);
        // 父死看护：把 app pid 交 helper，app 崩溃时 helper 收割受管核（防孤儿）。
        let ppid = Some(std::process::id());
        let helper = Arc::clone(&self.helper);
        let config_path = config_path.to_path_buf();
        // HelperClient::send 是同步阻塞 IPC → 挪出 async worker 线程。
        // **不传 bin**：helper 单方面决定跑哪个二进制（见 `HelperRuntime::start_core` 文档），
        // 传了也只会被丢掉——正是本缺陷的成因。
        let started = tokio::task::spawn_blocking(move || {
            helper.start_core(&config_path, &log_path, fwd, ppid)
        })
        .await
        .map_err(|e| format!("helper 起核任务 join 失败：{e}"))?;
        let pid = match started {
            Ok(pid) => pid,
            Err(e) => {
                self.core_via_helper.store(false, Ordering::SeqCst);
                return Err(e);
            }
        };
        // 提交 pid（先于就绪等待——接管方/崩溃监测/就绪门据此探活；上游 singboxPid 于 startCore 返回即置）。
        let pid_commit_started = std::time::Instant::now();
        if let Ok(mut g) = self.pid.lock() {
            *g = Some(pid);
        }
        let pid_commit_us = pid_commit_started.elapsed().as_micros();
        // 上游：helper 报告已启动但进程不存在 → 判失败。
        let pid_probe_started = std::time::Instant::now();
        let alive = pid_alive(pid);
        let pid_probe_us = pid_probe_started.elapsed().as_micros();
        log::info!("起核耗时：helper回包后pid提交={pid_commit_us}us，存活探测={pid_probe_us}us");
        if !alive {
            self.core_via_helper.store(false, Ordering::SeqCst);
            if let Ok(mut g) = self.pid.lock() {
                *g = None;
            }
            return Err(Self::reject_helper_start(
                Arc::clone(&self.helper) as Arc<dyn HelperStopOps>,
                pid,
            )
            .await);
        }
        log::info!("helper 已起 sing-box：pid={pid}（TUN 提权路径）");
        Ok(Some(pid))
    }

    /// **受保护核对账**：把现役核推进 helper 锁定的受保护核目录（幂等；内容相同则零动作）。
    ///
    /// # 为什么在**每次**经 helper 起核前做，而不是「换核成功后推一次」
    ///
    /// 受保护核与现役核至少有四条独立的漂移路径，挂在换核事件上只能堵住第一条：
    ///  1. 在线换核 / 手动上传 / 回滚 / reset-factory；
    ///  2. **app 升级触发的重播种**（`core_paths` 的 reseed 写新随包基线进 `core_update/`）——
    ///     p101 实测正是这条：2026-07-30 12:46 重播种到 1.14.0-beta.3，而受保护核停在 7-29 装 helper
    ///     时播下的 1.14.0-alpha.45；
    ///  3. helper 装得比核晚（安装脚本的播种被 `if [ ! -x "$COREDIR/sing-box" ]` 守着，**已存在就不覆盖**，
    ///     故重装 helper 也修不好已漂移的受保护核）；
    ///  4. 用户换机器/迁移配置目录。
    ///
    /// 起核前对账把这四条一次性收口，且天然覆盖「helper 早就在跑」这个常态（不需要重启 helper：
    /// 路径不变、内容变新，helper 每次 `start` 现 spawn）。
    ///
    /// # 失败处置：只告警不阻断 —— 判定权交给下游的**事实**自证
    ///
    /// 本方法失败（IPC 挂了 / hash 不符 / 磁盘满）**不**中止起核：此刻核还没起，中止只会把
    /// 「版本可能旧」升级成「彻底连不上」。真正该不该向用户报警，由起核后的
    /// [`attest_running_core_binary`](Self::attest_running_core_binary) 按**实跑二进制**判 ——
    /// 提升失败但受保护核本来就已是新版（例如上一轮已推成功）时，报警才是噪音。
    /// 这是刻意的分工：**本方法是机制，自证是判据**。
    async fn reconcile_protected_core(&self, active_core: &Path) {
        use crate::runtime::core_promote as promote;

        if !promote::platform_has_protected_core(self.helper.platform()) {
            return; // Windows：核走 app 侧，helper 的 --singbox 即 app 侧核路径，无受保护目录。
        }
        let Some(src_dir) = active_core.parent().map(Path::to_path_buf) else {
            log::warn!(
                "现役核路径无父目录，跳过受保护核对账：{}",
                active_core.display()
            );
            return;
        };
        let core_dir = self.helper.protected_core_dir_path();
        let dest = promote::protected_core_path_in(&core_dir, std::env::consts::OS);
        let protected_payload_dir = core_dir.clone();
        let staged_dir = self.config.join(promote::CORE_PROMOTE_DIR_NAME);
        let helper = Arc::clone(&self.helper);
        let active_core = active_core.to_path_buf();
        let core_filename = crate::runtime::core_paths::core_filename().to_owned();
        let cache = Arc::clone(&self.protected_core_cache);
        let started = std::time::Instant::now();

        // 全程同步 FS + 阻塞 IPC（sha256 两个 80MB 量级文件 + 可能的 30s install-core）→ spawn_blocking。
        let outcome = tokio::task::spawn_blocking(move || {
            // 首次完整对账通过后，同一会话内只做廉价 metadata 对账。两侧必须同时可观测且与缓存
            // 完全一致才命中；任一读取失败/变化都清缓存并回到 SHA256，不把“观测不到”当“没变化”。
            let active_before = promote::payload_stamp(&src_dir, &core_filename)?;
            let protected_before =
                promote::payload_stamp(&protected_payload_dir, &core_filename).ok();
            let cache_hit = cache.lock().ok().is_some_and(|cached| {
                protected_core_cache_hit(cached.as_ref(), &active_before, protected_before.as_ref())
            });
            if cache_hit {
                return Ok(ProtectedCoreReconcileOutcome::Cached);
            }
            if let Ok(mut cached) = cache.lock() {
                *cached = None;
            }

            let src_hash = promote::sha256_file(&active_core)?;
            // 受保护核读不到（不存在 / 无权限）→ None ⇒ 判「要推」。**不吞成"已最新"**。
            let dest_hash = promote::sha256_file(&dest).ok();
            // 核同版但 Cronet 缺失/漂移也必须推：Linux helper 真正执行的是 root 受保护目录，
            // 只比 sing-box hash 会让旧安装永久缺 libcronet.so，Naive/H3 继续报依赖缺失。
            let sidecars_match = promote::sidecar_payload_matches(&src_dir, &protected_payload_dir);
            if promote::decide_promote(&src_hash, dest_hash.as_deref(), sidecars_match)
                == promote::PromoteDecision::UpToDate
            {
                // 只在完整 hash 前后两侧身份均稳定时记缓存。若校验过程中刚好发生换核，当前轮仍沿用
                // 既有 hash 结论，但下一次连接必须重验，绝不能把竞态后的 metadata 误记成已验证。
                let active_after = promote::payload_stamp(&src_dir, &core_filename)?;
                let protected_after =
                    promote::payload_stamp(&protected_payload_dir, &core_filename)?;
                if active_before == active_after
                    && protected_before.as_ref() == Some(&protected_after)
                {
                    if let Ok(mut cached) = cache.lock() {
                        *cached = Some(ProtectedCoreCacheRecord {
                            active: active_after,
                            protected: protected_after,
                        });
                    }
                }
                return Ok(ProtectedCoreReconcileOutcome::Verified);
            }
            let names = promote::promote_names(&promote::list_file_names(&src_dir), &core_filename);
            if names.is_empty() {
                return Err(format!("现役核目录没有可提升的文件：{}", src_dir.display()));
            }
            promote::stage_promote_dir(&src_dir, &staged_dir, &names)?;
            let r = helper.install_core(&staged_dir, &src_hash);
            // 暂存目录用完即清（硬链不占额外空间，但留着会让下一轮的"先清后建"多做一次 I/O，
            // 且用户目录里躺一个 80MB 影子核容易被误读为"又一份核"）。
            let _ = std::fs::remove_dir_all(&staged_dir);
            // 提升成功也不立即把 metadata 当作“完整对账通过”：helper 对核心做了 hash 校验，但 sidecar
            // 复制没有独立摘要。下一次连接完整验一次后再进入热路径，避免扩大信任假设。
            r.map(|()| ProtectedCoreReconcileOutcome::Promoted(src_hash))
        })
        .await;

        let elapsed_ms = started.elapsed().as_millis();
        match outcome {
            Ok(Ok(ProtectedCoreReconcileOutcome::Cached)) => {
                log::info!("受保护核元数据缓存命中 → 跳过重复 SHA256（{elapsed_ms}ms）")
            }
            Ok(Ok(ProtectedCoreReconcileOutcome::Verified)) => {
                log::info!("受保护核已与现役核一致（完整校验，{elapsed_ms}ms）→ 跳过提升")
            }
            Ok(Ok(ProtectedCoreReconcileOutcome::Promoted(h))) => log::info!(
                "受保护核已提升到现役核（sha256={}…，{elapsed_ms}ms）：{}",
                &h[..h.len().min(12)],
                core_dir.display()
            ),
            // 只警告不中止：判据在下游的实跑自证（见方法文档）。
            Ok(Err(e)) => log::warn!(
                "受保护核提升失败（{elapsed_ms}ms；起核继续，由起核后自证判定是否告警）：{e}"
            ),
            Err(e) => {
                log::warn!("受保护核提升任务 join 失败（{elapsed_ms}ms；起核继续）：{e}")
            }
        }
    }

    /// **规则资源缺失** → 用户可见信号（`RULE_RESOURCES_MISSING`）。
    ///
    /// 入参是剪枝点交回的悬空 tag 清单（[`polaris_config_engine::builder::route::RouteConfigOutcome`]）——
    /// **不是**猜出来的：资源齐全时它恒空，故「只在真的发生剪枝时发」由数据本身保证，无需另加门控。
    ///
    /// 非终态（核确在跑，只是分流退化）→ `set_nonfatal_error`，保留 `running/pid/端口`。
    ///
    /// **文案里的「到「规则资源」页下载」对内置 tag 也成立**，靠的是 `builder/route.rs` 内置注入腿在
    /// `<userData>/rules/` 缺失时回落 `<userData>/rule-resource/`（catalog id 与 builtin tag 同形）。
    /// 那条回落腿若被删，本文案对 `geosite-cn`/`geoip-cn` 就重新变成死路——两者必须一起改。
    pub(super) fn warn_pruned_rule_resources(&self, pruned: &[String]) {
        if pruned.is_empty() {
            return;
        }
        self.set_nonfatal_error(
            &format!(
                "规则资源 {} 缺少本地副本，引用它们的分流规则本次已被跳过（分流将不完整）。请到「规则资源」页下载后重连恢复。",
                pruned.join("、")
            ),
            code::RULE_RESOURCES_MISSING,
        );
    }

    /// **出口自证**：核就绪后校验「实际生效出口 == 用户选中节点」，不一致即经同一 error/warn 通道告警。
    ///
    /// 判据与「为什么不用探针 / 不查 selector」见 [`attest_effective_exit`] 上方的模块级说明。
    ///
    /// **不增启动延迟**：本方法是纯函数 + 一次 `ConfigManager::current()`（命中内存缓存的 RwLock 读，
    /// 不碰磁盘、不碰网络、不 spawn、不 await），耗时微秒量级 → 直接内联在就绪后调用即可，既无需
    /// 放后台也无需超时兜底。这是选静态对账而非探针的**直接收益**：探针要一整个网络 RTT，本检查不要。
    ///
    /// **绝不静默**：`Match` 以外的每个变体都落 `set_nonfatal_error`（非终态——核确在跑），从而
    /// 同时落 `status.error/errorCode` 与广播 `event:proxyError`。
    pub(super) fn attest_selected_exit(
        &self,
        user_config: &UserConfig,
        singbox_config: &SingBoxConfig,
    ) {
        // 落盘的用户意图（单一真值）。读不到（首启/损坏）→ None → 退化为「只做配置内部自洽对账」，
        // 而**不是**跳过整个自证：拿不到意图不等于出口没问题。
        let persisted = self.config.current().ok().and_then(|c| {
            c.get("selectedServerId")
                .and_then(Value::as_str)
                .map(str::to_string)
        });
        match attest_effective_exit(user_config, singbox_config, persisted.as_deref()) {
            ExitAttestation::Match => {
                log::info!("出口自证通过：实际生效出口 == 选中节点");
            }
            other => self.set_nonfatal_error(&other.user_message(), code::EXIT_MISMATCH),
        }
    }

    /// 就绪门接线：把真实 I/O（TCP 探测 / 子进程存活 / sleep / 世代比对）注入 core-supervisor 的
    /// [`wait_for_core_ready`]。**轮询/判定顺序/boundary check 全在 crate 内，本处不重写**。
    ///
    /// `timeout_ms` 由调用方按本次下发配置的规模算（[`main_core_ready_timeout_ms`]），**不在本函数里
    /// 取常量**：本函数拿不到那份 config，就地取一个固定值就等于把「按规模算」这件事悄悄绕过去。
    ///
    /// **诊断慢起轴喂数点**（维度7 #11）：本次 start 的就绪重试经 `on_retry` 逐次
    /// [`StartAttempt::record_retry`](polaris_stats_engine::StartAttempt)，成功（`Ready`）后
    /// [`finish_start`](polaris_stats_engine::diagnostic::DiagnosticCounters::finish_start) 落库到 `last_start_ready_retries`
    /// （上游 :906/:1012）。失败/让位腿不落库 → 保留上次成功值（该字段义为「最近一次成功起核的就绪重试数」）。
    pub(super) async fn wait_ready(
        &self,
        api_port: u16,
        my_gen: u64,
        timeout_ms: u64,
    ) -> CoreReadyOutcome {
        // 分段耗时测量：本函数总耗时 + TCP 探测轮询轮数（`is_ready` 每被调一次计一轮）。
        // 纯观测计数器，不改判定/不改返回值——与下方既有 `on_retry` 诊断喂数点同一手法。
        let t_wait_ready = std::time::Instant::now();
        let ready_poll_count = Arc::new(AtomicU32::new(0));
        let alive_probe_count = Arc::new(AtomicU32::new(0));
        let alive_probe_elapsed_us = Arc::new(AtomicU64::new(0));
        let child = self.child.clone();
        let gate = self.gate.clone();
        // 轮询 sleep 的取消腿：与 `is_superseded` 同一个 gate（同一真值），外加唤醒边沿。
        let gate_for_sleep = self.gate.clone();
        let signal_for_sleep = self.gen_changed.clone();
        // C6-5：helper 起核无本地 child 句柄 → 就绪门探活改用 pid（对齐 上游 `isAlive:()=>isProcessAlive(pid)`）。
        // 直起路径 child.try_wait 不变。pid 已在 spawn（两路径）提交 → 此处读定值。
        let via_helper = self.core_via_helper.load(Ordering::SeqCst);
        let helper_pid = if via_helper {
            self.pid.lock().ok().and_then(|g| *g)
        } else {
            None
        };
        // 慢起轴：本次 start 的就绪重试累计句柄（begin_start → on_retry 累计 → 成功 finish_start 落库）。
        let attempt = Arc::new(Mutex::new(self.diag_lock().begin_start()));
        let attempt_cb = Arc::clone(&attempt);
        #[cfg(test)]
        let ready_retry_count = Arc::clone(&self.ready_retry_count);
        let deps = CoreReadyDeps {
            // 子进程存活：直起走 try_wait 非阻塞收割（Ok(None)=仍在跑；child 被 stop 取走→不活）；
            // helper 核走 pid 探活（kill(pid,0)，root 核跨用户 EPERM 亦判活）。
            is_alive: Box::new({
                let alive_probe_count = Arc::clone(&alive_probe_count);
                let alive_probe_elapsed_us = Arc::clone(&alive_probe_elapsed_us);
                move || {
                    let started = std::time::Instant::now();
                    let alive = if via_helper {
                        helper_pid.is_some_and(pid_alive)
                    } else if let Ok(mut g) = child.lock() {
                        match g.as_mut() {
                            Some(c) => matches!(c.try_wait(), Ok(None)),
                            None => false,
                        }
                    } else {
                        false
                    };
                    alive_probe_count.fetch_add(1, Ordering::Relaxed);
                    alive_probe_elapsed_us.fetch_add(
                        started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
                        Ordering::Relaxed,
                    );
                    alive
                }
            }),
            // 就绪信号：管理 API 端口 TCP 可连（core-readiness.ts 原义；该口是 h2c gRPC，无 REST 可判）。
            is_ready: Box::new({
                let ready_poll_count = Arc::clone(&ready_poll_count);
                move || {
                    ready_poll_count.fetch_add(1, Ordering::Relaxed);
                    Box::pin(async move {
                        matches!(
                            tokio::time::timeout(
                                READY_PROBE_TIMEOUT,
                                tokio::net::TcpStream::connect(("127.0.0.1", api_port)),
                            )
                            .await,
                            Ok(Ok(_))
                        )
                    })
                }
            }),
            // 轮询间隔 sleep **可被取消中断**：睡到一半世代变了就立刻醒，下一轮轮首的 `is_superseded`
            // 当场判 Superseded。「等待本身可中断」这条不变式在此处也要成立，不能只守退避那一处。
            //
            // **诚实标注射程**：`CORE_READY_POLL_MS` 现为 50ms，所以这一处今天只省下 ≤50ms —— 变异实测
            // （换回裸 `tokio::time::sleep`）**杀不动任何测试**，本改动是不变式对齐 + 防将来把 poll 调大，
            // 不是当前那 35s 的成因。真正的成因是退避那一处（2s/4s，有测锁死）。
            sleep: Box::new(move |d| {
                let gate = Arc::clone(&gate_for_sleep);
                let signal = Arc::clone(&signal_for_sleep);
                Box::pin(async move {
                    sleep_unless_superseded_on(&gate, &signal, my_gen, d).await;
                })
            }),
            // #176 让位判据：世代变了即被更新的 start/stop 接管。
            is_superseded: Some(Box::new(move || gate.generation() != my_gen)),
            // 慢起轴喂数：每次就绪重试累计一次（上游 onRetry，:906）。纯观测，不改就绪判定。
            on_retry: Some(Box::new(move || {
                if let Ok(mut a) = attempt_cb.lock() {
                    a.record_retry();
                }
                #[cfg(test)]
                ready_retry_count.fetch_add(1, Ordering::SeqCst);
            })),
        };
        let outcome = wait_for_core_ready(
            WaitForCoreReadyOptions {
                timeout_ms,
                poll_ms: CORE_READY_POLL_MS,
            },
            &deps,
        )
        .await;
        // 轮询类段：只记总等待时长 + 轮询轮数，不逐轮打点刷屏。
        log::info!(
            "起核耗时：就绪等待={}ms TCP轮询轮数={} 存活探测次数={} 存活探测累计={}us 结果={outcome:?}",
            t_wait_ready.elapsed().as_millis(),
            ready_poll_count.load(Ordering::Relaxed),
            alive_probe_count.load(Ordering::Relaxed),
            alive_probe_elapsed_us.load(Ordering::Relaxed)
        );
        // 成功起核 → 把本次累计的就绪重试落库（上游 :1012）。失败/让位不落库（保留上次成功值）。
        if outcome == CoreReadyOutcome::Ready {
            if let Ok(a) = attempt.lock() {
                self.diag_lock().finish_start(&a);
            }
        }
        outcome
    }

    /// **起核收口腿**：helper 报了 pid 但本侧探活判死 → **先请 daemon 停掉它自己的受管 child**，
    /// 再返回失败消息。
    ///
    /// **为什么必须 stop（结构保证，不是修当前 bug）**：原实现在此只清 `core_via_helper` 标记和
    /// `pid` 就返回，理由是「进程已死，无需再 stop」——而那个前提**正是被 EPERM 误判打破的那条**。
    /// 一旦探活判错，daemon 手里那个活着的 root 核就此失联：标记已清 ⇒ 之后 `kill_core` 不走 helper 腿，
    /// child 又恒 `None` ⇒ 停核彻底变 no-op，孤儿就此诞生（本次真机事故的成因）。
    ///
    /// 让 daemon 收口它自己的 child，把「不会漏下孤儿」从**对探活正确性的推理**降格成**结构保证**：
    /// 探活对不对，这条腿都不留残留。与 T1 的探活修复是两道独立防线，将来任何探活缺陷都不会
    /// 再复制这次事故。stop 失败不改判（核确实可能真死了）——照实记日志，错误消息原样返回。
    pub(super) async fn reject_helper_start(ops: Arc<dyn HelperStopOps>, pid: u32) -> String {
        // stop 是同步阻塞 IPC → 挪出 async worker 线程（同 start_core/stop_core/cleanup_cores）。
        // **带上 pid**：本腿要收口的是 daemon 刚报给我们的这一个（helper 报活但探活判死的那个），
        // 不是「daemon 此刻手里的随便哪个」——本方法整段可能与新会话并发。
        match tokio::task::spawn_blocking(move || ops.stop_managed_core(Some(pid))).await {
            Ok(Ok(())) => log::info!("起核收口：已请 daemon 停掉其受管 child（pid={pid}）"),
            Ok(Err(e)) => log::warn!("起核收口：请 daemon 停核失败（pid={pid}）：{e}"),
            Err(e) => log::error!("起核收口：停核任务 join 失败（pid={pid}）：{e}"),
        }
        format!("helper 报告已启动但进程不存在（pid={pid}）")
    }

    /// sing-box 临时配置文件路径（写 generate_sing_box_config 输出，供 spawner 读）。
    #[must_use]
    pub fn runtime_config_path(&self) -> PathBuf {
        self.config.join("singbox-runtime.json")
    }

    /// 外化规则目录（`<configDir>/custom-rules`）——与 `generate_deps` 的 `custom_rules_dir` 及
    /// config-engine route/DNS ext 分支 `ext_rule_file_exists` 探测路径同源（单一真值）。
    pub(super) fn custom_rules_dir(&self) -> PathBuf {
        self.config.dir().join("custom-rules")
    }

    /// 外化自定义规则落盘是否处于降级态（`customRuleFilesDegraded`）。
    pub(super) fn custom_rule_files_degraded(&self) -> bool {
        self.custom_rule_files_degraded.load(Ordering::SeqCst)
    }

    /// 起核期两轴动态空闲端口解析（管理 API + update-in），**每次起核尝试重解析**（端口重分配自愈）。
    ///
    /// 抽出以便 retry 每次拿新口：osascript 授权窗口 / 竞态被抢占 → 换口重生成，对齐 上游 onRetry
    /// `allocateProbePorts`（:913）。`control_port` / `mixed_port` 由 config 决定、跨重试不变，故不在此解析。
    ///
    /// **§15**：额外分配 K 个测速探测池端口（`probe-in-k`）——排除 api/update-in/control/http/mixed 及池内互异；
    /// 专用代理出口探针与 K 个测速槽一次性分配，确保彼此不撞；整批原子失败则两项能力都不注入，
    /// 但不阻断代理本身启动。返回 `(api, update_in, subscription_update_in, probe_proxy, pool_ports)`。
    pub(super) fn resolve_start_ports(
        &self,
        user_config: &UserConfig,
        control_port: u16,
    ) -> (u16, u16, u16, Option<u16>, Vec<u16>) {
        // 管理 API 端口（上游 resolveTailscaleApiPort，:3006）。
        let exclusions = PortExclusions::for_primary_api(
            Some(control_port),
            user_config.http_port,
            None, // UserConfig 增量子集无 socksPort 字段 → 不排除（与 config-engine 现状一致）
            user_config.mixed_port,
        );
        let resolved =
            PortAllocator::new(TokioPortProvider).resolve_tailscale_api_port(&exclusions);
        let api_port = resolved.port;
        if resolved.used_fallback {
            log::warn!("管理 API 端口 5 次解析均撞排除集 → 回落 {api_port}");
        }
        // C19 update-in 端口：额外排除已占的 api_port，fallback = control_api+3（避与 api/login 的 +1/+2 撞）。
        let update_in_excl = PortExclusions::for_login_api(
            api_port,
            Some(control_port),
            user_config.http_port,
            None,
            user_config.mixed_port,
        );
        let update_in_resolved = PortAllocator::new(TokioPortProvider)
            .resolve_free_local_port(&update_in_excl, control_port.wrapping_add(3));
        let update_in_port = update_in_resolved.port;
        if update_in_resolved.used_fallback {
            log::warn!("update-in 端口 5 次解析均撞排除集 → 回落 {update_in_port}");
        }
        // 独立分配订阅专用入口。它是安全边界，不得与可选测速池共用「整批失败」命运。
        let subscription_excl = PortExclusions::for_login_api(
            api_port,
            Some(control_port),
            user_config.http_port,
            None,
            user_config.mixed_port,
        );
        let subscription_excl = PortExclusions {
            socks: update_in_port,
            ..subscription_excl
        };
        let subscription_resolved = PortAllocator::new(TokioPortProvider)
            .resolve_free_local_port(&subscription_excl, control_port.wrapping_add(4));
        let subscription_update_in_port = subscription_resolved.port;
        if subscription_resolved.used_fallback {
            log::warn!(
                "subscription-update-in 端口 5 次解析均撞排除集 → 回落 {subscription_update_in_port}"
            );
        }

        // §15 可选测速池：固定排除集中用 socks 槽放 subscription 口；额外 provider
        // 再剔除共享 update-in，故 api/update/subscription/control/http/mixed 与池内均互异。
        let pool_excl = PortExclusions {
            socks: subscription_update_in_port,
            ..subscription_excl
        };
        let mut probe_ports = PortAllocator::new(PortProviderExcluding {
            excluded: update_in_port,
        })
        .resolve_distinct_free_ports(&pool_excl, PROBE_POOL_SIZE + 1);
        let probe_proxy_port = (!probe_ports.is_empty()).then(|| probe_ports.remove(0));
        let pool_ports = probe_ports;
        if probe_proxy_port.is_none() {
            log::warn!(
                "代理出口探针 + 测速池共 {} 个端口分配失败 → 自动故障探测停用、测速回退活跃出口",
                PROBE_POOL_SIZE + 1
            );
        }
        (
            api_port,
            update_in_port,
            subscription_update_in_port,
            probe_proxy_port,
            pool_ports,
        )
    }

    /// 起核重试退避 sleep（第 `attempt` 次失败后、下一次尝试前）。**可被取消中断**。
    /// 指数：`delay * 2^(attempt-1)`；恒定：`delay`（对齐 上游 retry util `delay * 2^attempt`，其 attempt 0-based）。
    ///
    /// 返回 `true` = 退避期内被接管（用户点停止 / 更新的 start），调用方**必须立即走让位腿、不得
    /// `continue`**：再起一次核就是在接管方的核之上叠第二个进程。返回 `false` = 睡满，照常重试。
    ///
    /// 走 [`sleep_unless_superseded`](Self::sleep_unless_superseded) 而非裸 `tokio::time::sleep`：
    /// 退避是这条腿上**最长的单次阻塞**（TUN 预算下 2s→4s），裸 sleep 会把取消延迟抬到一个退避周期。
    async fn sleep_start_backoff(
        &self,
        budget: &StartRetryBudget,
        attempt: u32,
        my_gen: u64,
    ) -> bool {
        let delay = if budget.exponential_backoff {
            // attempt 1-based → 移位 attempt-1（clamp 上限防溢出，实际预算远不达）。
            budget
                .delay_ms
                .saturating_mul(1u64 << (attempt.saturating_sub(1)).min(16))
        } else {
            budget.delay_ms
        };
        log::info!("起核失败，将在 {delay}ms 后进行第 {} 次尝试", attempt + 1);
        if self
            .sleep_unless_superseded(my_gen, Duration::from_millis(delay))
            .await
        {
            log::info!(
                "起核退避期被接管（世代 {my_gen} → {}）→ 就地中断退避、让位，不等睡满 {delay}ms",
                self.gate.generation()
            );
            return true;
        }
        false
    }

    /// 起核前落盘外化自定义规则文件 + 孤儿对账清扫（`start_inner` 在 generate 前调用）。移植 上游
    /// `writeCustomRuleFiles`（:1636）：① 清降级标记；② mkdir；③ 删孤儿（`is_custom_rule_orphan_file` 命中
    /// 且不在期望集——删规则/禁用/转 inline/改 id/direct 切换的遗留 + 原子写残留 `.tmp`）；④ 期望集内容变才
    /// 原子写。逐文件写失败 → 删旧副本回退 inline + 置降级标记（缺文件触发 route/DNS ext 分支 `existsSync`
    /// 降级走 inline，用内存态值，功能不损），仅 warn 不抛。
    ///
    /// **必须在 generate 前**：generate 的 route/DNS ext 分支按文件真存在性（`ext_rule_file_exists`）决定走
    /// ext 引用还是 inline 降级；文件不在则 ext 分支 100% 不可达。非 smart 模式 `build_custom_rule_files` 返
    /// 空集 → 已存在的外化文件被当孤儿全清（route 侧无消费者）。
    pub(super) async fn write_custom_rule_files(&self, config: &UserConfig) {
        let dir = self.custom_rules_dir();
        let expected = build_custom_rule_files(config); // fileName → JSON
        self.custom_rule_files_degraded
            .store(false, Ordering::SeqCst);
        if let Err(e) = std::fs::create_dir_all(&dir) {
            self.custom_rule_files_degraded
                .store(true, Ordering::SeqCst);
            log::warn!(
                "落盘外化规则文件失败（回退 inline）：创建目录 {} 失败：{e}",
                dir.display()
            );
            return;
        }
        // 孤儿清扫：is_custom_rule_orphan_file 命中且不在期望集 → unlink（含裸 .json + .tmp 变体）。
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if is_custom_rule_orphan_file(&name) && !expected.contains_key(&name) {
                    let _ = std::fs::remove_file(dir.join(&name));
                }
            }
        }
        // 期望集落盘（内容未变跳过）。写失败 → 删旧副本回退 inline + 置降级标记。
        for (name, content) in &expected {
            let file_path = dir.join(name);
            let cur = std::fs::read_to_string(&file_path).ok();
            if cur.as_deref() == Some(content.as_str()) {
                continue;
            }
            if let Err(e) = atomic_write_custom_rule(&file_path, content) {
                let _ = std::fs::remove_file(&file_path);
                self.custom_rule_files_degraded
                    .store(true, Ordering::SeqCst);
                log::warn!("外化规则文件写失败，已删旧副本回退 inline：{name}（{e}）");
            }
        }
    }

    /// 运行中外化规则「值」热更：仅原子替换内容变化的文件（rename-over 触发 sing-box fswatch 热重载），
    /// **绝不删文件**（运行中删被挂载文件会致 sing-box reload 报错；删除只在起核 `write_custom_rule_files`
    /// 清扫）。移植 上游 `syncCustomRuleFiles`（:1688）。任一写失败 → 退回去抖重启兜底。
    pub(super) async fn sync_custom_rule_files(self: &Arc<Self>, config: &UserConfig) {
        let dir = self.custom_rules_dir();
        let expected = build_custom_rule_files(config);
        for (name, content) in &expected {
            let file_path = dir.join(name);
            let cur = std::fs::read_to_string(&file_path).ok();
            if cur.as_deref() == Some(content.as_str()) {
                continue;
            }
            if let Err(e) = atomic_write_custom_rule(&file_path, content) {
                log::warn!("热更外化规则文件失败，退回去抖重启：{name}（{e}）");
                self.schedule_restart();
                return;
            }
        }
    }

    /// 装配 [`GenerateConfigDeps`]（上游侧所有 `this.*` 实例态的真值注入）。
    ///
    /// **边界（未接线的轴一律取保守值，非静默省略）**：
    /// - `race_server_port` / `race_upstream_ips` 由 `DnsRaceRuntime` 运行期投影注入，
    ///   该 owner 在本函数**之前**起好 sidecar 并原子提交投影（竞速关 /
    ///   起 sidecar 失败 → 恒 (0, []) = race off）。
    /// - `probe_direct_port` 仍留空；`probe_proxy_port` 是本次起核独占的健康检查入口，路由固定到
    ///   `proxy-selector`，不经过用户规则。端口分配失败时保持空，自动故障切换按 fail-closed 跳过。
    /// - **§15**：`probe_pool_ports` 由 `resolve_start_ports` 分配的 K 个空闲口注入（非空 → config-engine 建
    ///   probe-in-k 入站 + probe-selector-k + 路由 + dns-probe-exit-k；测速经此按波热切量延迟）。空 = 分配失败/回滚。
    /// - `has_cronet` 经 [`cronet_available`]：linux/win 按 libcronet 落盘探测；macOS（arm64+x64）cronet
    ///   已静态编入内核（无 dylib）→ 恒可用。缺库 + 选中 naive 节点 → 生成期报错（符合 上游 语义）。
    ///
    /// **C12**：`own_lan_cidrs` 由 [`enumerate_own_lan_cidrs`] 真枚举本机非回环接口（unix getifaddrs，
    /// 只读非破坏性）。**C19**：`update_in_port` 由 `start` 分配的空闲口注入（>0 时生成 update-in 入站+路由）。
    pub(super) fn generate_deps(
        &self,
        api_port: u16,
        update_in_port: u16,
        subscription_update_in_port: u16,
        probe_proxy_port: Option<u16>,
        pool_ports: &[u16],
        config: &Value,
    ) -> GenerateConfigDeps {
        let dir = self.config.dir();
        // A2/C13：日志两轴跟随 config（此前硬编码 Info + 不落 disableLogFile）。
        let (log_level, disable_log_file) = log_axes_from_config(config);
        // C11：race sidecar 运行期状态注入。port>0 才生成 dns-node-race + 放行上游直连。
        // IP 与端口**两轴同源**（都来自 sidecar 起好时提交的 `ResolvedUpstreams`）：route 的直连放行按
        // `ip_cidr × port` 叉乘匹配，只下发 IP 会让非标端口的自定义上游在 TUN 下经代理出站（issue #147）。
        let (race_server_port, race_upstream_ips, race_upstream_ports) =
            self.dns_race.config_projection();
        GenerateConfigDeps {
            platform: platform_tag().to_string(),
            arch: std::env::consts::ARCH.to_string(),
            race_server_port,
            probe_direct_port: None,
            probe_proxy_port,
            // C19：>0 才注入（0 = 分配失败/未接线，退化为不生成 update-in，对齐 上游 `deps.updateInPort` 真值判定）。
            update_in_port: (update_in_port > 0).then_some(update_in_port),
            subscription_update_in_port: (subscription_update_in_port > 0)
                .then_some(subscription_update_in_port),
            // §15：起核分配的 K 个测速探测池端口（空 = 分配失败/回滚 → 池不注入，测速回退活跃出口）。
            probe_pool_ports: pool_ports.to_vec(),
            lan_resolver_for_dns: None,
            race_upstream_ips,
            race_upstream_ports,
            // macOS(arm64+x64) cronet 静态编入内核（无 dylib 文件）→ 不能只看落盘，否则误拦所有 naive 节点。
            has_cronet: cronet_available(
                self.cronet_lib_exists_for_start(),
                platform_tag(),
                std::env::consts::ARCH,
            ),
            cronet_copy_failed: false,
            // 随包核恒 pin 在 1.14 带（具体版本见 src-tauri/core-manifest.json 的 bundledCoreVersion，
            // **勿在此抄具体 alpha/beta 号**：抄一次就漂一次）→ 恒有 services schema。
            // 换核后若允许 <1.14 需按 coreVersionAtLeast 门控（上游 hasManagementApi）——见边界声明。
            has_management_api: true,
            // B1：隐私模式**活态**（读单一真值 = `commands::config` 的 `PRIVACY_MODE` 进程状态机，
            // 经 emitter 的 `privacy_mode()` 取，见该方法文档解释为何走 emitter 而非另存一份）。
            // 下游 `build_log_config` 据此 `effective()` 把核日志级别抬到 ≥warn —— 隐私期 relay 才
            // 不再把连接明细（含用户访问的域名）写进受管核日志。此前硬编码 false ⇒ 隐私模式只在
            // 前端遮蔽，盘上仍是明文域名 —— 而前端遮蔽只管显示，管不到磁盘，那不是防线。
            //
            // ⚠️ **延迟生效口径（与 上游 一致，别当即时开关读）**：活态只在**本函数（config 生成）**
            // 被读一次，而 config 只在起核时写盘 ⇒ 运行中切隐私模式**不改变已在跑的那个核**的日志级别，
            // 要**下次起核**才生效（上游 `main/index.ts:222` 同款注释：「sing-box 连接日志级别在下次
            // 核心重启时按新隐私」；app.log / UI 侧才是即时收敛）。要即时，得走管理 API 改核日志级别，
            // 那是另一件事、不在本注入面。
            privacy_mode: self.privacy_mode_active(),
            log_level,
            disable_log_file,
            // dashboard #55 回归修复：此前硬编码 None → 面板开关 on 时核无 path → 联网下载兜底 → CWD 相对 mkdir 噪音。
            // 改为解析「运行时下载覆盖 > 随包内置 resources/dashboard」（对齐 上游）→ 命中则核 serve 本地、零下载。
            dashboard_serve_dir: resolve_dashboard_serve_dir(dir),
            tailscale_api_port: api_port,
            cache_path: dir.join("cache.db").to_string_lossy().into_owned(),
            // B3/W26：不再让 sing-box 自己持有固定 output fd。子进程不会响应外部轮转：Unix rename
            // 后继续写旧 inode，Windows 还可能拒绝 rename，均无法形成运行期硬上限。核日志由既有
            // SubscribeLog / 起核 stderr 管道进入 `logging.rs` 的 shared bounded writer；helper 腿的
            // pre-ready/FATAL stderr 则由 helper 同一 writer 收进 `singbox-startup.log`。
            log_file_path: None,
            runtime_rules_dir: dir.join("rules").to_string_lossy().into_owned(),
            rule_resources_path: rule_resource_dir(dir).to_string_lossy().into_owned(),
            custom_rules_dir: dir.join("custom-rules").to_string_lossy().into_owned(),
            tailscale_state_dir_prefix: dir.join("tailscale").to_string_lossy().into_owned(),
            is_valid_srs_fn: is_valid_srs_file,
            // C12：真枚举本机所有非回环接口 CIDR（连入来源排除 guard / bypassLAN carve guard / mesh 重叠告警）。
            own_lan_cidrs: enumerate_own_lan_cidrs(),
            log: config_log,
            on_degraded: config_on_degraded,
        }
    }

    fn kernel_gate_cache_hit(&self, record: &KernelGateCacheRecord) -> bool {
        self.kernel_gate_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            == Some(record)
    }

    /// 只在真实 `check` 返回 Accepted 后调用。先更新内存态，再原子落盘；落盘失败只影响
    /// 下次 app 重启后的命中率，不能把本次已通过的起核变成失败。
    fn remember_kernel_gate_cache(&self, record: KernelGateCacheRecord) {
        {
            let mut cache = self
                .kernel_gate_cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if cache.as_ref() == Some(&record) {
                return;
            }
            *cache = Some(record.clone());
        }
        let path = self.config.dir().join(KERNEL_GATE_CACHE_FILE);
        if let Err(error) = persist_kernel_gate_cache(&path, &record) {
            log::warn!("{error}");
        }
    }

    /// 生成配置 → 写盘 → **内核闸门**（`sing-box check`），把内核点名拒收的节点剥掉后重来一轮，
    /// 直到内核收下这份配置（或按 fail-open 停下来）。返回**已落盘的那一份**。
    ///
    /// # 为什么闸门放在这一层而不是生成侧
    ///
    /// 判据是「**内核**认不认」，取证方式是拿**即将下发的那个文件**问**本次解析出的那个核**——两个
    /// 输入都只在运行时层才存在（config-engine 是纯逻辑 crate，既没有核也没有落盘路径）。放生成侧就
    /// 只能退回静态白名单，而那正是已定口径明确排除的做法（逃生舱不得变回白名单，且必与内核版本漂移）。
    ///
    /// # 剥离靠「重新生成」而不是「从数组里删掉那一项」
    ///
    /// 直接从 `outbounds[]` 里 `remove(index)` 会留下一地悬空引用（selector 成员、`route.rules`、
    /// `dns.rules` 还指着那个 tag），而 `check` **抓不到**悬空引用（实测 selector 指向不存在的 tag
    /// 时 `check` rc=0，真起核才 `dependency[X] not found`）⇒ 剥完照样炸，还炸得更难查。
    /// 改成「把该节点从 `servers` 里去掉后重跑 `generate_sing_box_config_with_report`」，
    /// 选择器成员清理 / detour 级联剪枝 / 死引用修正**全部复用生成侧既有机制**，不新造第二份。
    ///
    /// # 剥掉的集合跨重试腿累积（`peeled` 由调用方持有）
    ///
    /// 外层起核重试（端口重分配自愈）会重跑本函数。内核对某个节点的拒收是**确定性**的（同一个节点、
    /// 同一个核，判定不会变），故第 2 腿起无需重新发现，直接沿用 ⇒ 重试腿恒只付 1 次 check。
    async fn generate_and_gate_with_runtime_bindings(
        &self,
        user_config: &UserConfig,
        deps: &GenerateConfigDeps,
        config_path: &Path,
        binary: Option<&Path>,
        peeled: &mut BTreeMap<String, InvalidNode>,
        runtime_bind_interfaces: &BTreeMap<String, String>,
    ) -> Result<GateOutcome, String> {
        let started = std::time::Instant::now();
        let mut checks_run: u32 = 0;
        loop {
            // 已剥的节点从 `servers` 摘掉后重新生成（空集合时等价于原配置）。
            let mut effective = user_config.clone();
            effective.servers.retain(|s| !peeled.contains_key(&s.id));
            let gen_out = generate_sing_box_config_with_report_and_runtime_bindings(
                &effective,
                &BTreeMap::new(),
                deps,
                runtime_bind_interfaces,
            )
            .map_err(|e| format!("sing-box 配置生成失败: {e}"))?;
            let json = serde_json::to_string_pretty(&gen_out.config)
                .map_err(|e| format!("sing-box 配置序列化失败: {e}"))?;
            std::fs::write(config_path, &json)
                .map_err(|e| format!("写 sing-box 配置失败 {}: {e}", config_path.display()))?;

            // 核解析不到（首启未落核 / 单测未注入）→ 闸门无从判定，照原样下发（failOpen）。
            let Some(bin) = binary else {
                return Ok(GateOutcome::assemble(
                    gen_out, effective, peeled, checks_run, None,
                ));
            };
            let cache_record = kernel_gate_cache_record(bin, &gen_out.config);
            if cache_record
                .as_ref()
                .is_some_and(|record| self.kernel_gate_cache_hit(record))
            {
                log::info!("起核内核闸门命中已接受的核/配置身份，跳过重复 sing-box check");
                return Ok(GateOutcome::assemble(
                    gen_out, effective, peeled, checks_run, None,
                ));
            }
            checks_run += 1;
            let verdict = run_config_check(bin, config_path).await;
            let rejection = match decide_peel(&verdict, started.elapsed(), PEEL_TIME_BUDGET) {
                PeelStep::Proceed => {
                    if let Some(record) = cache_record {
                        self.remember_kernel_gate_cache(record);
                    }
                    return Ok(GateOutcome::assemble(
                        gen_out, effective, peeled, checks_run, None,
                    ));
                }
                PeelStep::Stop(why) => {
                    log::warn!("起核内核闸门停止剥离（放行到 spawn，由内核自己报错）：{why}");
                    return Ok(GateOutcome::assemble(
                        gen_out, effective, peeled, checks_run, None,
                    ));
                }
                PeelStep::Peel(r) => r,
            };

            // 下标 → tag → 节点 id。tag→id 反表必须由**本轮**那份 `effective.servers` 现算：
            // `build_id_to_tag_map` 的撞名去重会让 tag 随集合变化（剥掉「HK」后，原本的「HK (1)」
            // 就变成「HK」），拿上一轮的表查这一轮的 tag 会张冠李戴。
            let wrappers: Vec<ServerLikeRef> =
                effective.servers.iter().map(ServerLikeRef).collect();
            let tag_to_id: BTreeMap<String, String> = build_id_to_tag_map(&wrappers)
                .into_iter()
                .map(|(id, tag)| (tag, id))
                .collect();
            // `classify_peel_target` 是纯函数，刻意只认「哪些 id 已剥」这个最小输入，不认
            // `InvalidNode`——上报形态是编排层的事。这里给它一个由 `peeled` 现导的视图，
            // 而不是在别处另存一份 id 集合（另存的那份迟早与 `peeled` 漂）。
            let already_peeled: BTreeSet<String> = peeled.keys().cloned().collect();
            match classify_peel_target(
                &rejection,
                &gen_out.config,
                &tag_to_id,
                user_config.selected_server_id.as_deref(),
                &already_peeled,
            ) {
                PeelTarget::Unattributable => {
                    log::warn!(
                        "起核内核闸门：内核拒收但该下标不对应任何节点，放行到 spawn —— {}",
                        rejection.detail
                    );
                    return Ok(GateOutcome::assemble(
                        gen_out, effective, peeled, checks_run, None,
                    ));
                }
                PeelTarget::Stalled { tag } => {
                    log::warn!(
                        "起核内核闸门：节点「{tag}」已剥除却仍被内核点名，停止剥离并放行 —— {}",
                        rejection.detail
                    );
                    return Ok(GateOutcome::assemble(
                        gen_out, effective, peeled, checks_run, None,
                    ));
                }
                PeelTarget::Blocked { id, tag } => {
                    log::error!(
                        "起核内核闸门：内核拒收的正是选中节点「{tag}」（id={id}）→ 终态，不 spawn —— {}",
                        rejection.detail
                    );
                    let blocked = InvalidNode {
                        id,
                        tag,
                        reason: INVALID_REASON_KERNEL_REJECTED.to_string(),
                    };
                    return Ok(GateOutcome::assemble(
                        gen_out,
                        effective,
                        peeled,
                        checks_run,
                        Some((blocked, rejection.detail)),
                    ));
                }
                PeelTarget::Peel { id, tag } => {
                    log::warn!(
                        "起核内核闸门：内核拒收节点「{tag}」（id={id}），已剔除并上报，其余节点照常起核 —— {}",
                        rejection.detail
                    );
                    // 剥除集合与上报清单是**同一次插入**：分成两个容器写就会漂，而漂的方向恰好是
                    // 「节点从配置里消失、用户侧却没有任何标记」——本仓明文判定它比报错更坏。
                    peeled.insert(
                        id.clone(),
                        InvalidNode {
                            id,
                            tag,
                            reason: INVALID_REASON_KERNEL_REJECTED.to_string(),
                        },
                    );
                }
            }
        }
    }

    /// 单测保持既有调用面；生产必须显式给出本次会话的运行时绑定，防止新增调用点悄悄漏接。
    #[cfg(all(test, unix))]
    pub(super) async fn generate_and_gate(
        &self,
        user_config: &UserConfig,
        deps: &GenerateConfigDeps,
        config_path: &Path,
        binary: Option<&Path>,
        peeled: &mut BTreeMap<String, InvalidNode>,
    ) -> Result<GateOutcome, String> {
        self.generate_and_gate_with_runtime_bindings(
            user_config,
            deps,
            config_path,
            binary,
            peeled,
            &BTreeMap::new(),
        )
        .await
    }

    /// 本次实际要启动的核心旁是否有 cronet 动态库。
    ///
    /// 必须与 [`Self::core_binary_for_start`] 同源：环境覆盖、可写核、随包核三条优先级任一变化时，
    /// 依赖探测都跟着实际 spawn 路径走，不能再固定查配置目录根部。
    pub(super) fn cronet_lib_exists_for_start(&self) -> bool {
        self.core_binary_for_start()
            .ok()
            .is_some_and(|core| cronet_lib_exists_beside_core(&core, std::env::consts::OS))
    }
}

/// `ProxyRuntime::generate_and_gate` 的产物：**已落盘**的那份配置 + 本次全部剔除报告。
pub(super) struct GateOutcome {
    pub(super) config: SingBoxConfig,
    pub(super) pruned_rule_set_tags: Vec<String>,
    /// 生成侧 gate 剔除的 ∪ 内核闸门剥掉的（走同一条 `EVENT_PROXY_INVALID_NODES` 通道）。
    pub(super) invalid_nodes: Vec<InvalidNode>,
    /// 本次真跑了几次 `sing-box check`（缓存命中 0、首次健康 1、剥除腿可 >1）；
    /// 只用于日志和测试，不参与判定。
    pub(super) checks_run: u32,
    /// `Some` = 被内核拒收的正是用户选中的节点（附内核原话）→ 调用方落终态错误，不 spawn。
    pub(super) blocked: Option<(InvalidNode, String)>,
    /// 🔴 **`config` 真正由哪一份 servers 生成** —— 剥除之后的那份，不是调用方手里的 `user_config`。
    ///
    /// 为什么必须带出来：`build_id_to_tag_map` 按**名字**去重、撞名追加 `(n)` 后缀 ⇒ tag 是
    /// **整个集合**的函数，不是单个节点的函数。剥掉「HK」之后，原本的「HK (1)」在重新生成的配置里
    /// 就叫「HK」。而起核后有三处要按 id 反算 tag：
    ///   `attest_selected_exit`（出口自证，`code::EXIT_MISMATCH` 是「以为走代理、实则明文直连」的
    ///   唯一告警通道）、`build_switch_snapshot`（规则热切的 PUT 目标）、`endpoint_tag_to_id`（端点帧逆映射）。
    /// 这三处若拿未剥的全量 servers 算，得到的 tag 在运行核里**根本不存在** ⇒ 出口完全正确却误报
    /// EXIT_MISMATCH、热切 PUT 打空、TS 端点认不出来。
    ///
    /// 所以「剥后集合」只在这里构造一次、由调用方原样接手，**不给第二处重算的机会** ——
    /// 重算出来的第二份判据迟早与这里漂移，而漂移的表现是静默的假告警。
    pub(super) effective_user_config: UserConfig,
}

impl GateOutcome {
    /// 把「生成侧 gate 的剔除」+「内核闸门剥掉的」+「被拒的选中节点」并成一份上报清单。
    ///
    /// **`blocked` 那一个也必须进 `invalid_nodes`**：它是本次唯一让起核失败的节点，用户最需要看见的
    /// 就是它。只放进 `blocked`（终态错误文案）而不进上报清单，卡片就不会标灰 —— 而 toast 会消失、
    /// 卡片不会，持久的可视标记正是用户回头去修那个节点时唯一还在的线索。
    ///
    /// tooltip 文案（`servers.nodeInvalid`「节点配置无效，已在启动时跳过」）对这一条略有偏差 ——
    /// 本次是**整个没启动**、而非「启动时跳过了它」。取「标灰 + 略偏的后半句」而非「不标灰」：
    /// 前者的错处只在措辞，后者丢的是「哪个节点坏了」这个唯一可行动信息。
    ///
    /// 独立成关联函数而非循环里的闭包：闭包会在整个循环体上按引用捕获 `checks_run` / `peeled`，
    /// 与随后的 `checks_run += 1` / `peeled.insert` 直接借用冲突（编译器实测拦下）。
    ///
    /// `peeled` 直接当上报清单用（而不是另攒一份 `Vec<InvalidNode>`）：二者本就是同一件事的两种
    /// 表示，分开存就会漂 —— 起核重试腿第一次踩的正是这个（剥除集合跨腿累积、上报清单每腿新建
    /// ⇒ 第 2 腿 emit 一份空数组，节点仍被剥出配置而卡片上的标灰被前端整表替换掉了）。
    fn assemble(
        outcome: GenerateOutcome,
        effective_user_config: UserConfig,
        peeled: &BTreeMap<String, InvalidNode>,
        checks_run: u32,
        blocked: Option<(InvalidNode, String)>,
    ) -> Self {
        Self {
            config: outcome.config,
            pruned_rule_set_tags: outcome.pruned_rule_set_tags,
            invalid_nodes: outcome
                .invalid_nodes
                .into_iter()
                .chain(peeled.values().cloned())
                .chain(blocked.iter().map(|(n, _)| n.clone()))
                .collect(),
            checks_run,
            blocked,
            effective_user_config,
        }
    }
}

/// `build_id_to_tag_map` 要的最小投影（同 `generate.rs` 内部那份 `SrvLike`：`ServerConfig` 本身没实现
/// `ServerLike`，两处都得薄包一层）。
pub(super) struct ServerLikeRef<'a>(pub(super) &'a ServerConfig);

impl ServerLike for ServerLikeRef<'_> {
    fn id(&self) -> &str {
        &self.0.id
    }
    fn name(&self) -> &str {
        &self.0.name
    }
}

/// 内核点名一项之后，闸门对它的处置。[`classify_peel_target`] 的产物。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum PeelTarget {
    /// 剥掉这个节点、上报、再来一轮。
    Peel { id: String, tag: String },
    /// 它是用户**选中**的节点 → 不剥，落终态错误（理由见 [`classify_peel_target`]）。
    Blocked { id: String, tag: String },
    /// 已剥过却又被点名 = 剥了没生效 → 停（推进不变式）。
    Stalled { tag: String },
    /// 下标不对应任何节点 → 停（fail-open）。
    Unattributable,
}

/// 内核点名的下标 → 闸门该拿它怎么办。**纯函数**（不改 `already_peeled`，不碰进程/FS/时钟；
/// 单测直接喂结构体，不需要核也不需要落盘）。
///
/// 三条判据的**顺序是语义的一部分**，不可换：
///
/// 1. **先归因**：连是哪个节点都说不出，后两条无从谈起。
/// 2. **再判选中**：选中节点必须在「剥」之前被拦下 —— 一旦先剥了，`servers` 里就没有它，下一轮
///    `generate_sing_box_config_with_report` 直接返回 `Selected server not found`，用户拿到的又是
///    一句和现场无关的话。
/// 3. **最后判推进**：只有确定「该剥、且能剥」了，才问「上一轮是不是已经剥过它」。
///
/// # 为什么选中节点不静默剥掉换一个
///
/// 剥了就等于替用户改出口。而「实际生效出口 ≠ 选中节点」在本仓是**要专门告警**的一类事故
/// （[`code::EXIT_MISMATCH`]，见其文档：「用户以为走代理、实则明文直连」的唯一告警通道）——
/// 闸门自己去制造那个状态是自相矛盾。故落终态：用户看到的是「哪个节点、内核说了什么」，
/// 比今天那句无从下手的「启动失败」严格更好，且他的出口选择没有被人背着改掉。
pub(super) fn classify_peel_target(
    rejection: &KernelRejection,
    config: &SingBoxConfig,
    tag_to_id: &BTreeMap<String, String>,
    selected_server_id: Option<&str>,
    already_peeled: &BTreeSet<String>,
) -> PeelTarget {
    let Some((id, tag)) = attribute_rejected_node(rejection, config, tag_to_id) else {
        return PeelTarget::Unattributable;
    };
    if selected_server_id == Some(id.as_str()) {
        return PeelTarget::Blocked { id, tag };
    }
    if already_peeled.contains(&id) {
        return PeelTarget::Stalled { tag };
    }
    PeelTarget::Peel { id, tag }
}

/// 把内核点名的「第几项」翻回「哪个节点」。**纯函数**。
///
/// 返回 `None` 的三种情形，调用方一律 fail-open：
/// 1. 下标越界（内核与我方对同一份 JSON 的编号不该错位，真错位了说明前提已失效 —— 此时猜比不猜坏）；
/// 2. 该项是内置出站（`direct` / `block` / `proxy-selector`）—— 它们不在 `id_to_tag` 里，也没有节点可剥；
/// 3. 该项是**由节点派生但不等于节点**的出站，典型是 shadowTLS 后处理造出的外层 `stls-out-<id>`。
///    刻意**不**按 `stls-out-` 前缀反解：那等于把 `outbounds.rs` 的命名约定抄第二份，命名一改这里就
///    悄悄失效（而且是「静默剥错节点」这种最难查的失效），不如老实归到「归因不到」。
fn attribute_rejected_node(
    rejection: &KernelRejection,
    config: &SingBoxConfig,
    tag_to_id: &BTreeMap<String, String>,
) -> Option<(String, String)> {
    let tag = match rejection.array {
        RejectedArray::Outbounds => &config.outbounds.get(rejection.index)?.tag,
        RejectedArray::Endpoints => &config.endpoints.as_ref()?.get(rejection.index)?.tag,
    };
    Some((tag_to_id.get(tag)?.clone(), tag.clone()))
}

/// 规则资源目录（`<data>/rule-resource/`）。**目录名的唯一定义点** —— config 生成侧的
/// `rule_resources_path` 与 decoy 覆盖清单都取这里，各写一遍字面量就是第二份真值源。
pub(super) fn rule_resource_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("rule-resource")
}

// ── 曾经的「C9 诊断采集会话」（`diagnosticCapture`）已整体删除 ───────────────────────
//
// 它做的事是：临时把 `config.logLevel` 拉到 `debug`（快照原级别）→ 落盘 → 广播 → 重启运行核，
// 事后还原，外加一条启动期崩溃自愈。**存在的唯一理由**是「想看核的 debug 行就必须让核以 debug 跑」。
//
// 这个前提是错的：核的 `SubscribeLog` 流恒是全级别（喂它的 platform writer 分发不受 `log.level`
// 过滤，见 crate `polaris-singbox-grpc` 的 `subscribe_logs` 文档），级别筛在客户端。接上该流之后
// （[`ProxyRuntime::spawn_core_log_relay`]），把日志页级别拨到 debug 就**立刻**能看到核的 debug 行 ——
// 零磁盘写、零核重启、也就无所谓「还原」与「崩溃自愈」。故整条链（两个 command、三个纯函数、
// `BACKEND_AUTHORITATIVE_KEYS` 特例、备份排除位、前端采集条与按钮）一并撤掉；旧配置里残留的键由
// `polaris_store::migrate::migrate_diagnostic_capture` 还原级别后清除，不留孤儿键。

/// `.srs` 规则集有效性（上游 `isValidSrsFile`，builtin-geo-rulesets.ts:142）：
/// 读头 3 字节判魔数 `SRS`。任何 IO 失败 → false（fail-closed，缺文件时 builder 自行降级）。
pub(super) fn is_valid_srs_file(path: &str) -> bool {
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut buf = [0u8; 3];
    f.read_exact(&mut buf).is_ok() && &buf == b"SRS"
}

/// NaiveProxy 可用性判定（抽纯函数便于单测 + 变异验证）。`generate_deps` 的 `has_cronet` 经此。
///
/// **为什么不能只看 libcronet 落盘**（真机 bug 根因）：macOS 的 sing-box 二进制已把 cronet **静态编入**
/// （CGO + `with_naive_outbound`），naive 内核原生支持、**不需要动态库文件**。strings 二进制坐实
/// **mac-arm64 与 mac-x64 两架构都编入**：tags 逐字同含 `with_naive_outbound`，cronet 符号计数均 1588，
/// 二进制体积 73/78MB（远大于走动态库的 linux 70/win 71MB）。故 macOS 无 `libcronet.dylib` 时
/// `lib_exists=false`，但 naive 仍可用 —— 若只看文件会误判 `has_cronet=false` → `generate.rs` 的
/// `is_node_usable` 丢弃所有 naive 节点 + 报「macOS 核心未内置 cronet」。这是 上游 时代「naive 靠外部
/// libcronet」前提，换核后前提变了，判定必须跟上。
///
/// - macOS（`darwin`，arm64 与 x64 皆然）：静态编入 → true（不看文件；arch 不参与判定）。
/// - linux/win：看 libcronet 动态库落盘 `lib_exists`。
///
/// `arch` 目前不参与判定（macOS 两架构一致），保留入参把「(platform, arch)」两轴显式带进单测四象限，
/// 并为将来若某架构的核回退动态库时收窄留 seam。
pub(super) fn cronet_available(lib_exists: bool, platform: &str, arch: &str) -> bool {
    let _ = arch;
    lib_exists || platform == "darwin"
}

/// 指定核心旁是否存在本平台的 cronet 动态库（路径纯函数在 `core_paths`，这里仅做 FS 探测）。
pub(super) fn cronet_lib_exists_beside_core(core: &Path, os: &str) -> bool {
    crate::runtime::core_paths::core_sidecar_path_for(core, os).is_some_and(|p| p.is_file())
}

/// 起核重试预算（上游 start-retry-policy.ts `resolveStartRetryBudget`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct StartRetryBudget {
    /// retry 次数（总尝试 = max_retries + 1）。
    pub(super) max_retries: u32,
    /// 基础退避（ms）。
    pub(super) delay_ms: u64,
    /// 指数退避 vs 恒定间隔。
    pub(super) exponential_backoff: bool,
}

/// 起核重试预算（移植 上游 `resolveStartRetryBudget`，start-retry-policy.ts:26）。
///
/// system_interface（reverseMesh）节点在 TUN 下建第二张内核 TUN，双 TUN 同时 stop→start 时旧接口内核侧
/// 释放慢 → 起核撞「TUN 初始化未完成」退出（macOS 双 utun 抢占）。默认 2 次+指数退避（~6s）打不过释放 →
/// 放宽为 10 次+恒定 3s（给内核留足异步回收双 utun/适配器的时间）。Windows 禁 System（`mesh_system_
/// supported_on_platform` false）→ reverseMesh 强制 gVisor 不建第二张 TUN、无竞态 → 沿用默认。
pub(super) fn resolve_start_retry_budget(
    is_tun: bool,
    servers: &[ServerConfig],
    platform: &str,
) -> StartRetryBudget {
    let has_system_interface_node = is_tun
        && mesh_system_supported_on_platform(platform)
        && servers.iter().any(mesh_uses_system_interface);
    if has_system_interface_node {
        StartRetryBudget {
            max_retries: 10,
            delay_ms: 3000,
            exponential_backoff: false,
        }
    } else {
        StartRetryBudget {
            max_retries: 2,
            delay_ms: 2000,
            exponential_backoff: true,
        }
    }
}

/// 起核 spawn **launch** 失败是否可重试（移植 上游 retry `shouldRetry` 的 `nonRetryableErrors` 反面，:882）。
///
/// 权限/找不到/enoent/eacces/eperm/配置无效 → 确定性失败，不重试；其余（端口/资源竞态）→ 可重试。
/// 起核期**就绪**失败（Dead/Timeout = CoreStartRetryError 等价）恒可重试、不经本谓词（其文案本不含关键词）。
pub(super) fn is_retryable_start_error(message: &str) -> bool {
    let m = message.to_lowercase();
    const NON_RETRYABLE: &[&str] = &[
        "找不到",
        "权限",
        "permission",
        "enoent",
        "eacces",
        "eperm",
        "配置文件格式错误",
        "invalid config",
    ];
    !NON_RETRYABLE.iter().any(|&p| m.contains(p))
}

/// 外化规则文件原子写（tmp→rename，rename-over 触发 sing-box fswatch 热重载）。
///
/// 复用 store 的 `<base>.<12hex>.tmp` 唯一后缀命名——其形态被 `is_custom_rule_orphan_file` 的 `.tmp` 分支
/// 识别，故起核清扫能回收断电/强杀留下的半写 tmp（对齐 上游 atomicWrite 用 `writeFileAtomic`，:1711）。
fn atomic_write_custom_rule(path: &Path, content: &str) -> Result<(), String> {
    polaris_store::fs::atomic_write_plan(path, &polaris_store::fs::random_tmp_suffix(), content)
        .execute(&polaris_store::fs::StdFs)
        .map_err(|e| format!("{e:?}"))
}

// ════════════════ 出口自证：「实际生效出口 == 选中节点」的静态对账 ════════════════
//
// **根因**：从「用户选中节点」到「实际出口」之间，此前没有任何一处校验二者相等。起核的成功判据只有
// 「进程起来了 + 管理 API 可连」，不含「流量真的从选中节点出去」。于是 selector 降级、`route.final=direct`、
// mesh 出口回落、渲染端传错 `selectedServerId` —— 多条互不相关的路径，用户看到的都是同一个「已连接」绿灯，
// 实则明文直连。**安全定级**：用户以为流量加密走代理、实则未加密，且无任何信号。
//
// **为什么走静态对账，而不是探针 / 管理 API 查 selector**（两条备选都实测过，均不可行）：
//  1. **复用 `probe_proxy_connectivity`/`probe_through_proxy`**：二者自陈「真机门：需真起核 + 碰网络」，
//     每次探测是一趟**真实外网往返**（`CONNECTIVITY_TIMEOUT_MS` 量级）。挂进起核路径 = 直接给已经偏慢的
//     启动再加一个网络 RTT；且它只能答「通不通」，答不出「从**哪个**节点出去」——对本不变式根本不是判据。
//  2. **查管理 API 的 selector 实际 `selected`**：本仓的核是 sing-box 1.14，**`clash_api` 已移除**
//     （见 `singbox/config.rs` `services` 字段注释），管理面只剩 `daemon.StartedService` gRPC，而该 proto
//     **只有 `SelectOutbound`（写），没有任何读 selector 状态的 RPC**（见 `started_service.proto`）。
//     即「查 selector 实际值」这条路在当前核上**不存在可调的接口**，要走得先给核加 RPC + grpcurl 反射核对。
//
// **本实现取的判据**：核实际启动用的那份 sing-box config 就是出口的**权威真值**——`route.final` 与 selector
// `default` 决定了第一个包从哪出去。把它与用户**落盘**的 `selectedServerId` 对账，即可静态拆穿全部降级路径。
//
// **零启动延迟**：整条链是纯函数 + 一次内存缓存读（`ConfigManager::current()` 命中 RwLock 缓存，不碰磁盘），
// 无 I/O、无网络、无 spawn、无 await —— 耗时在微秒量级，故直接内联在就绪后调用，既不阻塞也不需要超时。
// 这也**强于**任何探针：探针只在探测那一刻采样，静态对账覆盖的是「核启动时装的是什么」这一确定事实。

/// 出口自证判定结果。`Match` 以外的每个变体都对应一条**用户必须知道**的降级路径。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ExitAttestation {
    /// 实际生效出口 == 用户意图（含「用户自己选了直连」「模式语义本就直连」两种放行）。
    Match,
    /// 用户选中真实节点，实际默认出口却是 `direct` —— **明文直连**，最高危。
    SilentDirect { expected_tag: String },
    /// 实际默认出口是**另一个** tag（走错节点）。仍加密，但不是用户选的出口。
    WrongExit {
        expected_tag: String,
        actual_tag: String,
    },
    /// 核实际启动用的选中节点 ≠ 用户落盘意图（渲染端传了陈旧 config 快照）。
    StaleSelection {
        persisted: String,
        started_with: String,
    },
    /// 选中 id 在本次 tag 映射里查无对应（generate 侧本应已拦，留作兜底可见性）。
    UnknownSelection { selected_id: String },
    /// 配置里解不出默认出口（无 `route.final`）→ 无法自证，按「不确定即告警」处理。
    UnresolvedExit { expected_tag: String },
}

impl ExitAttestation {
    /// 用户可见文案。**统一以「流量未按预期走选中节点」开头**——用户要的第一信息是「我不安全」，
    /// 而不是内部 tag 名；tag/id 作为定位细节跟在后面。
    pub(super) fn user_message(&self) -> String {
        match self {
            Self::Match => String::new(),
            Self::SilentDirect { expected_tag } => format!(
                "流量未走选中节点「{expected_tag}」，实际出口为直连（未加密）。请检查该节点配置或重新选择节点。"
            ),
            Self::WrongExit {
                expected_tag,
                actual_tag,
            } => format!(
                "流量未走选中节点「{expected_tag}」，实际出口为「{actual_tag}」。"
            ),
            Self::StaleSelection {
                persisted,
                started_with,
            } => format!(
                "启动用的节点（{started_with}）与当前选中节点（{persisted}）不一致，流量可能未走选中节点。请重新连接。"
            ),
            Self::UnknownSelection { selected_id } => format!(
                "选中节点（{selected_id}）不在本次启动的节点表中，流量可能未走该节点。"
            ),
            Self::UnresolvedExit { expected_tag } => format!(
                "无法确认流量是否走选中节点「{expected_tag}」（配置未指定默认出口）。"
            ),
        }
    }
}

/// 从**核实际启动的那份** sing-box config 解出「实际默认出口 tag」。
///
/// `route.final` 是第一跳：它要么直接是某个出站 tag，要么指向 selector —— 后者的实际出口是其 `default`
/// 成员（热切换发生前，`default` 就是核启动时选中的那个）。两级都解开才是真正的出口。
fn effective_exit_tag(singbox_config: &SingBoxConfig) -> Option<String> {
    let final_tag = singbox_config.route.as_ref()?.final_outbound.as_deref()?;
    if final_tag == DIRECT_TAG {
        return Some(DIRECT_TAG.to_string());
    }
    // final 指向 selector → 实际出口 = 它的 default；非 selector（无 default）→ final 自身即出口。
    Some(
        singbox_config
            .outbounds
            .iter()
            .find(|o| o.tag == final_tag)
            .and_then(|o| o.default.clone())
            .unwrap_or_else(|| final_tag.to_string()),
    )
}

/// 出口自证（**纯函数、零 I/O**）：对账「核实际启动的配置解出的出口」与「用户落盘的选中节点」。
///
/// `persisted_selected_id` = 用户**已提交**的意图（`config.json` 的 `selectedServerId`）。之所以以它为准
/// 而非只看 `user_config`：`user_config` 来自渲染端传来的 config 快照，**它本身就可能是错的**（陈旧快照 →
/// 起核按旧值落直连，而 UI 已显示新节点）。落盘值才是用户点过的那一下——`server:switch` 与自动换节点
/// 都是**先 `save_full` 再入核**，故「落盘值 ≠ 起核值」⟺ 渲染端传了陈旧快照，不存在合法的第三种解释。
/// 门② 的前置条件：**地区反向（回国）模式的「→代理」腿真的还在**。
///
/// 纯函数、零 I/O：判据全部取自「核实际启动的这份 config」——本地地区 geo tag（`region_local_geo`，
/// cn = `geosite-cn`/`geoip-cn`）是否仍有 `route.rule_set` 定义。定义在 ⟺ 引用它的规则没被
/// [`apply_rule_set_prune`](polaris_config_engine::builder::helpers::apply_rule_set_prune) 剪掉
/// ⟺ 国内流量确实还会被送去代理。
///
/// **为什么查 rule_set 定义而不是查规则条目**：剪枝是「定义缺失 → 连规则一起剪」，定义是因、规则是果，
/// 查因不会被规则形态的后续改动带偏。越界 region（手改 JSON）→ `region_local_geo` 返 None → 判定不完整
/// → 不放行（fail-safe：判不准就告警，不静默放行）。
pub(super) fn region_reverse_rule_sets_intact(
    user_config: &UserConfig,
    singbox_config: &SingBoxConfig,
) -> bool {
    use polaris_config_engine::user_config::region_local_geo;
    let Some(rr) = user_config.region_routing.as_ref() else {
        return false;
    };
    let Some(local) = region_local_geo(&rr.region) else {
        return false;
    };
    let defined: BTreeSet<&str> = singbox_config
        .route
        .as_ref()
        .and_then(|r| r.rule_set.as_deref())
        .unwrap_or(&[])
        .iter()
        .map(|rs| rs.tag.as_str())
        .collect();
    local
        .geosite
        .iter()
        .chain(local.geoip.iter())
        .all(|t| defined.contains(t.as_str()))
}

pub(super) fn attest_effective_exit(
    user_config: &UserConfig,
    singbox_config: &SingBoxConfig,
    persisted_selected_id: Option<&str>,
) -> ExitAttestation {
    // 门①：用户显式选「全直连」模式 → `final=direct` 是设计语义，不是降级。
    if user_config.proxy_mode == ProxyMode::Direct {
        return ExitAttestation::Match;
    }
    // 门②：smart + 地区反向（回国：本地走代理·海外直连）→ `final=direct` 同为设计语义。
    // 这两门不放行就会对**用户自己选的模式**天天误报，告警一旦有假就会被整体无视。
    //
    // **但白名单的是「reverse 且规则集完整」，不是「reverse」**：reverse 下唯一把流量送去代理的就是
    // 本地地区 geo 那两条 rule_set 规则（`geosite-cn`/`geoip-cn`），它们的 rule_set 定义若因本地 `.srs`
    // 缺失被 fail-closed 剪掉，「回国」就已经退化成全量明文直连——那是**真故障**，不是设计语义。
    // 旧粒度把这个故障一并放行，于是真机全量直连时零告警、日志还打「出口自证通过」。
    //
    // ⚠️ **不可达性登记（别照着它设计真机验收）**：这条收紧在**当前生产链路上已构造不出来**。
    // 同一场景下 `builder/route.rs` 的 T2 fail-safe 先一步把 `final` 从 direct 翻成 `proxy-selector`，
    // `effective_exit_tag` 解到 selector 的 `default` = 选中节点 ⇒ 本函数拿到的从来不是 `direct`，
    // 结论恒 `Match`。**曾经**还剩一条能让生产 config 带着 `final=direct` 走到这里的路 —— D4/D7
    // 组网出口回退（`user_exit_tag == "direct"`，T2 明确不改写）—— 但那条路现在由**下方的门③**
    // 提前放行了：它不再落到本条判据上，也不再需要靠「回落成 SilentDirect」被间接观测到。
    // 故：「手删 `<userData>/rules/*.srs` 后起核应出现 `EXIT_MISMATCH`」这类真机门**依旧不可能达成**
    // （现在是零条路径，而非一条误报路径），谁再提出来请先读这段。本收紧与下面三条测试保留的理由
    // 是 defense-in-depth（T2 若被改坏 / 未来新增绕过 T2 的 config 来源时，这里仍是最后一道），
    // **不是**因为它当前会触发。同类登记见 golden_config_snapshot.rs 对偶用例里的 mesh-exit-fallback 边界。
    if user_config.proxy_mode == ProxyMode::Smart
        && user_config
            .region_routing
            .as_ref()
            .is_some_and(|r| r.enabled && r.reverse)
        && region_reverse_rule_sets_intact(user_config, singbox_config)
    {
        return ExitAttestation::Match;
    }
    // 门③：选中的组网节点关外网（D4/D7）→ `builder/route.rs` 把 `user_exit_tag` 整体兜底成
    // `direct`，`final=direct` 同样是**设计语义**，不是「流量未按预期经代理」。
    //
    // 不放行的后果是一条**必然发生**的假警报：兜底态下门①②都不命中 ⇒ `effective_exit_tag` 解到
    // direct ⇒ `SilentDirect` ⇒ `set_nonfatal_error(EXIT_MISMATCH)` ⇒ 用户每次起核都收到
    // toast.warning + 桌面通知。而这正是他自己在节点上关掉「允许访问外网」换来的行为，且起核时
    // `route.rs` 已经用一条 Warn 日志说明过（「外网流量已回退直连」）。
    //
    // 判据**直接复用 route 侧兜底的同一个谓词**，不在这里重写：兜底与放行同真同假，天然单一真源。
    // 2026-09 该谓词从协议字面量白名单换成 `is_mesh_node`（OpenVPN 也进兜底）⇒ 假警报的触发面随之
    // 扩大，本门必须与那次扩面同批落地。
    if polaris_config_engine::builder::route::mesh_selected_exit_falls_back_to_direct(user_config) {
        return ExitAttestation::Match;
    }

    let started_with = user_config.selected_server_id.as_deref();

    // 轴①（渲染端竞态）：起核用的选中节点 ≠ 落盘意图。**必须先判**——此腿下 `user_config` 整体不可信，
    // 再拿它去推「期望 tag」只会得出「配置自洽」的假绿（配置确实自洽，只是自洽于一个错的意图）。
    if let Some(persisted) = persisted_selected_id {
        if started_with != Some(persisted) {
            return ExitAttestation::StaleSelection {
                persisted: persisted.to_string(),
                started_with: started_with.unwrap_or("<none>").to_string(),
            };
        }
    }

    // 轴②：用户选了直连哨兵 → 出口本就该是 direct。
    if is_direct_selection(started_with) {
        return ExitAttestation::Match;
    }
    // 未选中任何节点 → 无可对账的意图（generate 侧另有校验）。
    let Some(selected_id) = started_with else {
        return ExitAttestation::Match;
    };

    // 期望 tag：复用 outbounds/selector 构建用的**同一个** `build_id_to_tag_map`（撞名去重规则一致），
    // 不另写一份——自己算一遍 tag 就等于用一份可能不同的规则去校验，撞名场景必假。
    struct SrvLike<'a>(&'a ServerConfig);
    impl ServerLike for SrvLike<'_> {
        fn id(&self) -> &str {
            &self.0.id
        }
        fn name(&self) -> &str {
            &self.0.name
        }
    }
    let wrappers: Vec<SrvLike> = user_config.servers.iter().map(SrvLike).collect();
    let id_to_tag = build_id_to_tag_map(&wrappers);
    let Some(expected_tag) = id_to_tag.get(selected_id) else {
        return ExitAttestation::UnknownSelection {
            selected_id: selected_id.to_string(),
        };
    };

    match effective_exit_tag(singbox_config) {
        Some(actual) if actual == *expected_tag => ExitAttestation::Match,
        Some(actual) if actual == DIRECT_TAG => ExitAttestation::SilentDirect {
            expected_tag: expected_tag.clone(),
        },
        Some(actual) => ExitAttestation::WrongExit {
            expected_tag: expected_tag.clone(),
            actual_tag: actual,
        },
        None => ExitAttestation::UnresolvedExit {
            expected_tag: expected_tag.clone(),
        },
    }
}

/// 从 config Value 抽 server id 集（差集用）。
pub(super) fn server_ids(config: &Value) -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();
    if let Some(servers) = config.get("servers").and_then(Value::as_array) {
        for s in servers {
            if let Some(id) = s.get("id").and_then(Value::as_str) {
                set.insert(id.to_string());
            }
        }
    }
    set
}
