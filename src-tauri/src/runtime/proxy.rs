//! 代理运行时：sing-box 进程编排（上游 `ProxyManager` 等价物）。
//!
//! 装配既有 domain crate（本层只做**接线**，状态机/门控逻辑一律不在此重写）：
//! - [`polaris_core_supervisor`]：`TokioSpawner`（真 spawn）+ `LifecycleGate`（起停竞态单飞）
//!   + `wait_for_core_ready`（就绪门）+ `ProcessKiller`（SIGTERM→宽限→SIGKILL）+ `PortAllocator`（端口簿记）。
//! - [`polaris_switch_engine`]：`DebouncedRestart`（去抖重启 timer + 世代守卫，内部复用 LifecycleGate）。
//! - [`polaris_config_engine`]：`generate_sing_box_config`（config 生成）+ `proxy_ports`（端口单一真值）。
//!
//! 状态：运行标志 + sing-box 子进程句柄 + 管理 API 端点。
//! 启动/停止语义对齐 上游 ProxyManager.start/stop。
//!
//! # 管理 API 是 gRPC，不是 clash REST（实测结论）
//!
//! 上游 `ProxyManager.ts:2360` 明载「clash_api 已移除」；1.14 起管理面走 `services:[{type:'api'}]`
//! 的 **h2c gRPC**（daemon.StartedService），由 [`polaris_singbox_grpc`] 客户端消费。本机对真核
//! 实测（取证于 1.14.0-alpha.44，结论按 1.14 带记，非随包版本号）：该端口对 HTTP/1.1 GET 返回 404，对 HTTP/2 prior-knowledge 返回 h2 帧
//! —— 故就绪判据只能是「TCP 可连」（`core-readiness.ts` 原义），不能是「REST 200」。
//!
//! # 端口三轴（勿混）
//! - `mixed_port`：混合入站（HTTP/SOCKS），`local_proxy_port` 解析。
//! - `control_api_port`：历史 clash 控制端口（9090），仅作端口排除项，**核不再监听它**。
//! - `api_port`：1.14 管理 API 实际监听端口，`PortAllocator` 每次 start 动态解析（对齐 上游
//!   `resolveTailscaleApiPort`：排除 control/http/socks/mixed，fallback = control+1）。

#![forbid(unsafe_code)]

mod auto_switch;
mod connection_flush;
mod core_binary;
// `pub(crate)`：`pipe_to_log` 是全 app 唯一一份子进程排空实现，瞬态登录核
// （`runtime::tailscale_login_core`）与测速临时核（`runtime::speedtest`）都用它。
pub(crate) mod core_log;
mod dns_race;
mod dns_takeover;
mod hot_switch;
mod lifecycle;
mod login_fallback;
mod management_api;
mod network_monitor;
mod network_settle;
mod pending_changes;
mod platform_contracts;
mod process_supervision;
mod recovery;
mod route_replan;
mod selector_reconcile;
mod startup;
pub(crate) mod system_takeover;
mod third_party_vpn;
mod ts_exit;
mod unlock_refresh;

pub(crate) use core_binary::{
    bundle_resource_candidates, bundle_resource_roots, core_binary_env_override, dev_manifest_dir,
    first_existing_bundle_candidate, resolve_bundled_core_binary, resolve_core_binary,
};
// B9 跟随面：`resolve_dashboard_serve_dir` 的**唯一**消费者是 `start_inner`，本批随它进
// `startup.rs`（改走 `super::core_binary::` 直取）⇒ façade 侧再导出零命中。§B.3 把它列进「必须
// 原样保住」的 7 个跨模块自由函数（`commands/misc/dashboard.rs`），但全仓实测该消费点今天不存在
// （见回报「登记缺陷」）⇒ 保留再导出以守住 §B.3 的路径承诺，用 allow 标注它现在没有 crate 内命中。
#[allow(unused_imports)]
pub(crate) use core_binary::resolve_dashboard_serve_dir;
use dns_race::DnsRaceRuntime;
// B9 跟随面：`dns_takeover_enabled` 的生产消费点是 `start_inner` 的起核 DNS 接管闸，随本批进
// `startup.rs`；façade 只剩 `proxy/tests/` 经 `use super::*;` 取用 —— 不 gate 即非测试编译单元的
// `unused_imports`（同 B4 / B7 / B8 的既有形态，下同）。
#[cfg(test)]
use dns_takeover::dns_takeover_enabled;
// B7：`hot_switch` 域搬出后，façade 侧仍在消费的三项——`StagedClassification` 是
// `commands::config` 经 `crate::runtime::proxy::StagedClassification` 取用的公开契约面（§B.3 零
// 调用方改动），`SwitchSnapshot` / `TestPutSink` 是 `ProxyRuntime` 的字段类型（结构体定义按
// §A.5 钉死在 façade）。
pub use hot_switch::StagedClassification;
use hot_switch::SwitchSnapshot;
#[cfg(test)]
use hot_switch::TestPutSink;
// B8：`ProxyLifecycleEvent` 是 `ProxyErrorEmitter::emit_lifecycle` 的载荷类型（trait 定义按
// §C 例外② 钉死在 façade），按 §A.3 由 façade `pub use` 再导出。
// B9：同批注释里的 `now_ms` / `sleep_unless_superseded_on` 随 `start_inner` / `wait_ready`
// 进 `startup.rs`，façade 侧已如期下线。
pub use lifecycle::ProxyLifecycleEvent;
use login_fallback::LoginFallbackState;
use network_settle::NetworkSettleGate;
pub use pending_changes::PendingChangesSummary;
#[cfg(test)]
use platform_contracts::enumerate_own_lan_cidrs;
use platform_contracts::platform_tag;
pub(crate) use process_supervision::{pid_alive, send_signal};
use route_replan::RuntimeBindingState;
// B7 跟随面：生产消费点随本批搬进 `hot_switch`/`auto_switch`，façade 只剩 `proxy/tests/` 用它
// 构造期望值/输入 —— 不 gate 即非测试编译单元的 `unused_imports`（同 `RoutePrefix` 的既有形态）。
#[cfg(test)]
use route_replan::runtime_binding_roots_covered;
use selector_reconcile::SelectorReconcileOwner;
// B7 跟随面：同上，仅 `proxy/tests/` 消费。
#[cfg(test)]
use selector_reconcile::SelectorReconcileOutcome;
// B9：`startup` 域搬出后 façade 侧仍在消费的六项——`HelperGateDecision` 是
// `ProxyErrorEmitter::prompt_helper_gate` 的返回类型（trait 定义按 §C 例外② 钉死在 façade），
// 按 §A.3 由 façade `pub use` 再导出；`KernelGateCacheRecord` / `ProtectedCoreCacheRecord` 是
// `ProxyRuntime` 的字段类型、`load_kernel_gate_cache` / `KERNEL_GATE_CACHE_FILE` / `cronet_available`
// 供仍留在 façade 的 `new` / `core_build_env` 使用（结构体与这 6 个方法按 §A.5 钉死在 façade）。
pub use startup::HelperGateDecision;
use startup::{
    cronet_available, load_kernel_gate_cache, KernelGateCacheRecord, ProtectedCoreCacheRecord,
    KERNEL_GATE_CACHE_FILE,
};
use std::collections::BTreeMap;
#[cfg(test)]
use std::collections::BTreeSet;
#[cfg(test)]
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::Ordering;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize};
use std::sync::{Arc, Mutex, RwLock};
#[cfg(test)]
use std::time::Duration;
use system_takeover::{SystemProxyClearer, SystemProxyTakeover};

use tokio::sync::{Mutex as AsyncMutex, Notify};

// B7 跟随面：同上，仅 `proxy/tests/` 消费。
#[cfg(test)]
use polaris_config_engine::builder::hotswitch::RuleTargetEntry;
// B7 跟随面：同上，仅 `proxy/tests/` 消费。
// 本项的消费者全在 `proxy/tests/startup.rs` 的 `#[cfg(unix)]` 测试里（`generate_and_gate` 本身就是
// `#[cfg(all(test, unix))]`）⇒ 只 gate `test` 会在 win-gnu 腿变成 `unused_imports`。
#[cfg(all(test, unix))]
use polaris_config_engine::builder::build_id_to_tag_map;
#[cfg(test)]
use polaris_config_engine::builder::custom_rule_files::build_custom_rule_files;
#[cfg(test)]
use polaris_config_engine::builder::orchestration::config_generation_norm;
use polaris_config_engine::builder::InvalidNode;
// B7 跟随面：同上，仅 `proxy/tests/` 消费。
#[cfg(test)]
use polaris_config_engine::singbox::SingBoxConfig;
#[cfg(test)]
use polaris_config_engine::user_config::app_config::UserConfig;
#[cfg(test)]
use polaris_config_engine::user_config::dns_constants::{DIRECT_TAG, PROXY_SELECTOR_TAG};
#[cfg(test)]
use polaris_config_engine::user_config::proxy_mode::ProxyMode;
#[cfg(test)]
use polaris_config_engine::user_config::server_config::ServerConfig;
#[cfg(test)]
use polaris_config_engine::user_config::ProxyModeType;
// B8 跟随面：`LifecycleEndResult` / `LifecycleKind` 的生产消费点（`finish_lifecycle` 等）随本批
// 搬进 `proxy::lifecycle`（它自己 `use` 了这两个），façade 只剩 `proxy/tests/` 经 `use super::*;`
// 取用 —— 不 gate 即非测试编译单元的 `unused_imports`（同 `RoutePrefix` / B4 / B7 的既有形态）。
// `LifecycleEndResult` 未在 crate root 再导出（其兄弟类型 LifecycleGate/LifecycleKind 有）→ 走模块路径。
#[cfg(test)]
use polaris_core_supervisor::lifecycle_gate::LifecycleEndResult;
#[cfg(test)]
use polaris_core_supervisor::LifecycleKind;
// B4：这五个只被 `proxy/tests/` 用作期望值/输入构造器（被测对象 `spawn_crash_monitor` /
// `drive_crash_decision` / `send_signal` 等已随 B4 搬进 `recovery` / `process_supervision`，
// 生产侧本文件不再消费），故降为 cfg(test)——同 `RoutePrefix` 的既有形态。
#[cfg(test)]
use polaris_core_supervisor::{
    AutoRestartOutcome, ChildObservation, CoreReadyOutcome, ExitClassification, KernelRejection,
    RejectedArray, RestartFate, Signal,
};
// 同上：`INVALID_REASON_KERNEL_REJECTED` 只被 `#[cfg(unix)]` 的内核剥除测试消费。
#[cfg(all(test, unix))]
use polaris_core_supervisor::INVALID_REASON_KERNEL_REJECTED;
use polaris_core_supervisor::{CrashRecoveryMachine, LifecycleGate};
use polaris_dns_race::DohPost;
// 双侧搬出跟随面：façade 的最后消费者（TS/核日志 relay）随 B6 搬进 `ts_exit.rs`/`core_log.rs`，
// 仅 `proxy/tests/hot_switch.rs` 经 `use super::*` 仍用这两名；`ReconnectConfig` 已无消费者。
#[cfg(test)]
use polaris_singbox_grpc::{Endpoint, SingBoxApiClient};
use polaris_stats_engine::DiagnosticCounters;
use polaris_switch_engine::DebouncedRestart;
// B7 跟随面：同上，仅 `proxy/tests/` 消费。
#[cfg(test)]
use polaris_switch_engine::{ManagementApi, ManagementError};
use serde_json::Value;
use tokio::process::Child;

// B7 跟随面：同上，仅 `proxy/tests/` 消费。
#[cfg(test)]
use crate::commands::speedtest::current_server_fingerprints;
use crate::runtime::auto_switch::AutoNodeSwitchedPayload;
// B7 跟随面：同上，仅 `proxy/tests/` 消费。
#[cfg(test)]
use crate::runtime::auto_switch::RuntimeCandidate;
use crate::runtime::config::ConfigManager;
// B7 跟随面：同上，仅 `proxy/tests/` 消费。
#[cfg(test)]
use crate::runtime::config::Decision;
#[cfg(test)]
use crate::runtime::helper::HelperStopOps;
use crate::runtime::helper::{HelperLinuxResolvedOps, HelperRuntime, HelperStatusSnapshot};
// B7 跟随面：同上，仅 `proxy/tests/` 消费。
#[cfg(test)]
use crate::runtime::management_api::GroupSelection;
use crate::runtime::mesh::MeshRuntime;
// B7 跟随面：同上，仅 `proxy/tests/` 消费。
#[cfg(test)]
use crate::runtime::node_fingerprints;
// `RoutePrefix` 只被留在本文件的 `runtime_binding_replan_matrix_filters_noise_and_keeps_failover_safe`
// 用作期望值构造器（被测对象 `inferred_binding_replan_needed` 留在 src-tauri），故仍是 cfg(test)。
#[cfg(test)]
use polaris_helper_proto::Platform;
#[cfg(test)]
use polaris_platform_events::NetworkChangeImpact;
#[cfg(test)]
use polaris_platform_events::RoutePrefix;
// `RuntimeBindingPlan` 同理：生产侧的消费点随 `inferred_binding_replan_needed` 一起进了
// `proxy/route_replan.rs`（B5），façade 只剩 `proxy/tests/route_replan.rs` 用它构造期望值，
// 故与上一条同款 cfg(test) 收窄——不 gate 就是非测试编译单元里的 `unused_imports`。
#[cfg(test)]
use polaris_platform_events::RuntimeBindingPlan;

use crate::runtime::tailscale_status::TailscaleStatusEvent;
use crate::runtime::vpn_status::{OpenConnectStatusEvent, OpenVpnStatusEvent};

/// **§15 主核测速探测池槽数 K**（上游 `shared/speed-test.ts PROBE_POOL_SIZE`，单一真值）。
///
/// 起核时分配 K 个空闲回环端口注入 `probe_pool_ports` → config-engine 据此建 K 个 `probe-in-k`（http 入站）
/// `probe-selector-k`（成员=全量 nodeTags）、`probe-in-k→probe-selector-k` 路由、`dns-probe-exit-k`。
/// 测速时按波经 gRPC `select_outbound` 把各槽热切到被测节点、经 `probe-in-k` 端口量 warm-TTFB（同核单会话，
/// 结构性消除 WG/WARP 双会话超时）。K=16 对齐 上游；**分配失败 → 空池（回退当前活跃出口测速）**，`=0` 为回滚锚点。
const PROBE_POOL_SIZE: usize = 16;

/// sing-box 运行态快照（上游 `ProxyStatus` 镜像，序列化字段名与前端一致）。
///
/// 上游 `shared/types/runtime.ts ProxyStatus`：`{ running, pid?, startTime?, uptime?, error?, errorCode? }`。
/// 另携带 mixedPort/clashApiPort（非 上游 ProxyStatus 字段，但 dashboard / 内部端口探测用）。
///
/// # `startTime` 是运行时长的唯一真值，`uptime` 是它的读时投影
///
/// 起核时刻只有后端知道 → `start_time` 由 [`start_inner`](ProxyRuntime::start_inner) 在**就绪后**
/// 落一次（与 `running` 同生共死：`set_error`/`stop` 都经 `..Default::default()` 清回 None）。
/// `uptime` **不存**：存了就会在快照里瞬间过期（快照写于起核那一刻，读可能在几小时后）。
/// 它由 [`status()`](ProxyRuntime::status) **每次读时**从 `start_time` 现算 —— 故存储态恒 `None`，
/// **禁止直接读 `self.status` 里的该字段**，一律经 `status()` 取。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ProxyStatus {
    /// 是否运行中。
    pub running: bool,
    /// **是否有起核腿在飞**（`running:false` 期间也可能正在起核——重试预算内一轮可达数十秒）。
    ///
    /// **读时投影**（同 `uptime`）：存储态恒 `false`，真值是 [`ProxyRuntime::start_inflight`] 计数，
    /// 由 [`status()`](ProxyRuntime::status) 在应答那一刻现算。故 `*status.write() = ProxyStatus{..}`
    /// 的各处赋值不必也不应写它。
    ///
    /// **为什么必须暴露给渲染端**：托盘浮层是独立窗口、不共享主窗 store，只能从本快照得知「此刻正在
    /// 启动」。缺了它，托盘在起核期看到的是 `running:false` ⇒ 点击走 start 分支 ⇒ 在已有起核腿之上
    /// **再叠一次启动**（TrayMenu.tsx 原 :219-236 的缺陷）。
    #[serde(default, skip_serializing_if = "is_false")]
    pub starting: bool,
    /// sing-box 进程 pid（未运行=0）。
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub pid: u32,
    /// 起核就绪时刻（epoch ms）；未运行 = None。前端「运行时长」的真值源。
    #[serde(rename = "startTime", default, skip_serializing_if = "Option::is_none")]
    pub start_time: Option<u64>,
    /// 已运行秒数 —— `start_time` 的**读时投影**（见结构体文档）。存储态恒 None，勿写。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uptime: Option<u64>,
    /// mixedPort（运行期 HTTP/SOCKS 混合入站；未运行=0）。
    #[serde(rename = "mixedPort", default)]
    pub mixed_port: u16,
    /// 管理 API 端口（sing-box 1.14 `services:[{type:'api'}]` 的 h2c gRPC 监听口；未运行=0）。
    ///
    /// 字段名保留 `clashApiPort` 与前端契约一致（前端仍用此名取 dashboard 端口），但**语义已是
    /// 管理 API 端口**——与 上游 `getTailscaleApiPort()` 同源（:2369），非历史 clash REST 端口。
    #[serde(rename = "clashApiPort", default)]
    pub clash_api_port: u16,
    /// updateInPort（运行期更新链路 update-in socks 入站口；未运行/未分配=0）。
    ///
    /// **C19**：更新链路（App/资源/图标抓取）「经代理」时，流量 pin 到此 loopback socks 口，由 route
    /// 头部按 proxyMode 钉死出站（global/smart→出口 / direct→直连）。消费方经
    /// [`resolve_update_proxy_target`](crate::runtime::http::resolve_update_proxy_target) 决策走此口 vs 直连。
    /// = 上游 `ProxyManager.updateInPort`（allocateProbePorts 产出，UpdateNetwork/icon-protocol 消费）。
    #[serde(rename = "updateInPort", default)]
    pub update_in_port: u16,
    /// Subscription-only SOCKS inbound. Its route resolves through dns-remote,
    /// rejects local address ranges, then pins the reviewed IP to the update exit.
    #[serde(rename = "subscriptionUpdateInPort", default)]
    pub subscription_update_in_port: u16,
    /// 是否经 helper 启动（macOS 提权路径）。
    #[serde(rename = "startedViaHelper", default)]
    pub started_via_helper: bool,
    /// 最近一次错误的诊断消息（启动失败 / 运行期崩溃）。仅供脱敏日志/协议兼容，
    /// **禁止直接展示或用于分类**；用户文案与分类均用 `error_code`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// 最近一次错误的结构化码（前端 `ProxyErrorCode`）。与 `error` 同点落值（[`set_error`](ProxyRuntime::set_error)），
    /// 也同点经 `event:proxyError` 推送 —— 快照与事件同源，错过事件的 UI 仍能从状态读到码。
    ///
    /// 值域限于[`code`] 模块的常量：**只用控制流位置能诚实断言的码**（如「起核腿失败」⇒ `STARTUP_FAILED`），
    /// 绝不靠猜 message/退出码反推（本仓尚无核错误分类器，猜=伪造分类）。
    #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

/// 代理错误码（前端 `ui/src/contracts/types/runtime.ts` 的 `ProxyErrorCode` string enum 子集镜像）。
///
/// **只收录本层能从控制流位置诚实断言的成员**：本仓无「核 stderr / 退出码 → 错误码」分类器，
/// 补全其余成员就只能靠猜 message 关键字 = 伪造分类。故此处刻意只有 3 个 —— 缺的不是漏了，是**没有依据**。
pub mod code {
    /// 起核腿失败（就绪门判定核已死 / 就绪超时）——「启动失败」轴。
    pub const STARTUP_FAILED: &str = "STARTUP_FAILED";
    /// 核**意外**退出且无法自愈（无可用配置重启）——「运行中崩了」轴。
    pub const PROCESS_EXITED: &str = "PROCESS_EXITED";
    /// 崩溃自愈达上限放弃（反复崩溃 / 自愈重启反复失败）——「运行中崩了」轴的终态。
    pub const AUTO_RESTART_FAILED: &str = "AUTO_RESTART_FAILED";
    /// TUN 经提权 helper 起核，但 helper 未安装（起核前置校验拦截）——「权限/环境」轴。控制流位置可
    /// 诚实断言（判定点直接读到 helper 未装），非猜 message；渲染端据此引导去「设置 › Helper」安装。
    pub const HELPER_NOT_INSTALLED: &str = "HELPER_NOT_INSTALLED";
    /// **T3 终态**：上个会话遗留的 **root 孤儿核清不掉**（用户态 EPERM 杀不动，且 helper 不可用/清扫失败）
    /// ——「权限/环境」轴。对齐 上游 `ROOT_ORPHAN_BLOCKED` 语义。
    ///
    /// **为什么必须是一个诚实终态而不是继续起核**：活着的孤儿核一直独占 `cache.db`，此时起任何新核
    /// 都会 `initialize cache-file: timeout` 而失败，且**连切回 systemProxy 模式也起不来**。若在此静默
    /// 放行，用户看到的是一串莫名其妙的启动失败、无从下手；报出本码才能指向真正的动作
    /// （装/修 helper，或手动 `sudo kill` 掉残留 pid）。控制流位置可诚实断言（清扫腿直接观察到
    /// 「杀过了、仍存活、且提权腿不可用」），非猜 message。
    pub const ROOT_ORPHAN_BLOCKED: &str = "ROOT_ORPHAN_BLOCKED";
    /// **A1**：核已就绪，但把 OS 系统代理指向本地 mixed 入站失败（`networksetup`/`gsettings`/`reg` 报错）
    /// ——「流量不经核」轴。控制流位置可诚实断言（`enable_system_proxy` 直接返 `Err`），非猜 message。
    ///
    /// **非终态**：核确在运行，故经 [`set_nonfatal_error`](super::ProxyRuntime::set_nonfatal_error) 落值
    /// （保留 `running/pid/端口`），**绝不**走 `set_error`（那会把活核标成 not-running = 虚报）。
    /// 与前端 `ProxyErrorCode.SYSTEM_PROXY_FAILED` 逐字对齐（已在 `error-handler.ts` 归入 `System` 类）。
    pub const SYSTEM_PROXY_FAILED: &str = "SYSTEM_PROXY_FAILED";
    /// Linux 核已就绪，但 `systemd-resolved` 未能接到 Polaris TUN 链路。非终态：保留活核，明确提示
    /// DNS 接管降级；判据来自 helper 命令/读回自证的直接失败，不解析自由文本猜测。
    pub const SYSTEM_DNS_TAKEOVER_FAILED: &str = "SYSTEM_DNS_TAKEOVER_FAILED";
    /// **出口自证**：核已就绪，但「实际生效出口」≠「用户选中节点」——「静默直连 / 走错节点」轴。
    ///
    /// 判据是**纯静态**的：拿核实际启动的那份 sing-box config（`route.final` + selector `default`）解出
    /// 实际默认出口，与用户落盘的 `selectedServerId` 对账（见 [`attest_effective_exit`](super::startup::attest_effective_exit)）。
    /// 非终态（核在跑），同走 `set_nonfatal_error`。这是「用户以为走代理、实则明文直连」的唯一告警通道。
    pub const EXIT_MISMATCH: &str = "EXIT_MISMATCH";
    /// **内核自证**：核已就绪，但**实际跑起来的那个二进制**不是本次期望的核——「换核没生效」轴。
    ///
    /// 与 [`EXIT_MISMATCH`] 的判据形态**刻意相反**：那一条是纯静态对账（两个输入都源自「意图」），
    /// 本条只吃**事实**——`running` 取自内核对该 pid 的记账（linux `/proc/<pid>/exe`、mac `ps -o comm=`），
    /// 版本取自**对那个文件真跑一次 `sing-box version`**。理由是血证：TUN 提权路径上
    /// 「app 请求 bin=A、helper 实跑 bin=B」持续一天多而全链零告警（p101，A=1.14.0-beta.3、
    /// B=1.14.0-alpha.45），静态对账在此天然瞎——两侧根本不共享同一个「意图」。
    ///
    /// 非终态（核确在跑，只是版本不对），同走 `set_nonfatal_error`。
    pub const CORE_BINARY_MISMATCH: &str = "CORE_BINARY_MISMATCH";
    /// **规则资源缺失**：本次生成有 rule_set tag 因本地 `.srs` 缺失/损坏被 fail-closed 剪枝
    /// ——「分流规则整段没了」轴。控制流位置可诚实断言（剪枝点直接交回悬空 tag 清单，见
    /// `RouteConfigOutcome::pruned_rule_set_tags`），非猜 message；**资源齐全时该清单恒空 ⇒ 不发 = 零噪音**。
    ///
    /// 非终态（核确在跑，只是分流退化），同走 `set_nonfatal_error`。渲染端据此引导去「规则资源」页下载。
    pub const RULE_RESOURCES_MISSING: &str = "RULE_RESOURCES_MISSING";
    /// **自动故障切换落空**：连通性连续失败已**真的触发**了自动换节点、候选也规划出来了，但有节点
    /// 因为「切过去要整核重启」（`needs_restart`）被挡在切换门外，本轮没能换成 ——「无感自愈」在这里
    /// 退化成「无感地什么都没发生」，用户就一直干等在一条不通的代理里。
    ///
    /// 控制流位置可诚实断言：判据是候选规划的**直接读数**（`needs_restart`），非猜 message。
    /// 两个上报点，同码同锁存：
    ///  - 候选被剃光 —— [`switch_blocked_by_restart`](crate::runtime::auto_switch::switch_blocked_by_restart)
    ///    = `candidates` 空 **且** `needs_restart > 0`；
    ///  - 候选还剩几个但**探测全败** —— 此时 `needs_restart > 0` 意味着另有 N 个节点根本没被探过，
    ///    用户的可行动性与上一种完全相同。
    ///
    /// 候选为空的另外五因（草稿 / 未入核 / 参数脏 / 未就绪 / 不可作出口）刻意**不**报：前四种是用户
    /// 自己刚编辑过配置的可预期后果，第五种是「那个节点本来就不该被切过去」（只走内网的组网节点），
    /// 报了都是噪音；只有本因是「用户什么也没做、系统这条自愈腿却帮不上忙」，且**可行动**
    /// （手动换一个节点）。
    ///
    /// **文案里不许出现「重启代理」**：走到上报点时 `do_switch_io` 已确证 D 与 R 的选中节点相同，
    /// 同配置重启只会世代 +1 → 锁存复位 → 同情形再报一次，用户照做就进循环。
    ///
    /// **非终态**（核确在跑，只是自动换节点这轮没救成），故经
    /// [`set_nonfatal_error`](super::ProxyRuntime::set_nonfatal_error) 落值，**绝不**走 `set_error`
    /// （那会把活核标成 not-running = 虚报）。
    ///
    /// **每世代最多报一次**：`status.error` 是单槽覆盖，每次落值都 `log::error` + emit ⇒ 不锁存就会
    /// 每约 90 秒（3 次心跳失败）原样重发一次 toast + 桌面通知，而事实一条都没变。锁存点在
    /// [`AutoSwitchMachine`](crate::runtime::auto_switch::AutoSwitchMachine) ——
    /// 它每世代新建一个实例，核重启即自然复位。
    ///
    /// **别复用 [`EXIT_MISMATCH`]**：那条的用户文案是「流量未按预期经代理」，与本码的现场正相反
    /// （流量确实在走代理，只是那条代理不通）；且它会被 selector 对账腿
    /// `clear_nonfatal_error_if(EXIT_MISMATCH)` 清掉，而本码与 selector 归属无关，被那条腿顺手清掉
    /// 就是静默丢失。
    pub const AUTO_SWITCH_NEEDS_RESTART: &str = "AUTO_SWITCH_NEEDS_RESTART";
    /// 配置要求绑定的物理网卡在本机不存在或当前未启用。该判据来自起核 / 热切换前的系统接口枚举，
    /// 不依赖解析 sing-box 错误文案。终态起核腿会 fail-closed；运行核热切腿保留旧配置并进入待应用态，
    /// 两者都禁止静默改走其它网卡。
    pub const OUTBOUND_INTERFACE_UNAVAILABLE: &str = "OUTBOUND_INTERFACE_UNAVAILABLE";
    /// **TUN 提权引导被用户取消**：起核汇流点的 helper 引导门弹出后用户选了「取消」——「用户明确
    /// 拒绝」轴。控制流位置可诚实断言（门直接收到 [`HelperGateDecision::Abort`](super::HelperGateDecision)），
    /// 非猜 message。
    ///
    /// **与 [`HELPER_NOT_INSTALLED`] 的分工（别合并）**：后者 = 「没装、也没能装上」→ 用户下一步是
    /// **去装**（可操作引导指向「设置 › Helper」）；本码 = 「用户刚刚亲口说了不装」→ 下一步是**什么都
    /// 不做**，再催一遍等于无视用户的选择。文案与告警等级都不同，合并会把两条相反的指引冲成一条。
    ///
    /// 终态（核未起，走 [`set_error`](super::ProxyRuntime::set_error)）。
    /// [`is_unrecoverable_restart_error`](super::recovery::is_unrecoverable_restart_error) 按**本码本身**判终态
    /// （用户取消不是瞬时故障，崩溃自愈重试它 = 无视用户刚做出的选择）。注意别退回「按码的字面量在
    /// message 里搜关键字」——实际落进错误的是中文文案 [`HELPER_GATE_ABORTED_MSG`](super::HELPER_GATE_ABORTED_MSG)，
    /// 搜 `"helper_gate_aborted"` 恒不命中。
    pub const HELPER_GATE_ABORTED: &str = "HELPER_GATE_ABORTED";
    /// **TUN 出口未夺到**：TUN 模式起核就绪后，post-flight 出口归属判定发现「本应走代理的公网目的」的
    /// 出口接口 grace 内始终未从 baseline 切走（其他 VPN 占着默认路由 / 我方路由装失败）——「假报已连接」轴。
    ///
    /// 控制流位置可诚实断言（[`verify_tun_route_captured`](super::ProxyRuntime::verify_tun_route_captured)
    /// 直接观测到出口自始至终 == baseline），非猜 message。**终态硬闸**（设计 D1）：核已就绪但流量抢不到
    /// 我方 utun，标 connected 是虚报，故 `kill_core` + [`set_error`](super::ProxyRuntime::set_error) 拒绝
    /// 标 running（设计 §4.2 方向①后验；`polaris-tun-conflict-detect-design-2026-07-22.md`）。
    pub const TUN_ROUTE_NOT_CAPTURED: &str = "TUN_ROUTE_NOT_CAPTURED";
    /// **#327 TUN 网卡从未建出来**：TUN@Windows 起核就绪后，逐腿正向验证在整个重试预算内**一次**都没
    /// 枚举到本次配置的 wintun 适配器 —— 「假报已连接」轴的另一半。
    ///
    /// 控制流位置可诚实断言（[`probe_tun_adapter_present`](super::ProxyRuntime::probe_tun_adapter_present)
    /// 经 `GetAdaptersAddresses` 直接枚举到「这张网卡不在」），非猜 message。
    ///
    /// **与 [`TUN_ROUTE_NOT_CAPTURED`] 的分工（别合并）**：那条是「网卡建出来了、但默认路由被别人占着」
    /// → 用户下一步是**断开另一个 VPN**；本码是「网卡压根没建出来」→ 用户下一步是**查 wintun 驱动是否
    /// 被安全软件拦截 / 重启**。判据来源也相反：那条靠路由归属差分（间接，且他方 VPN 一撤就自愈），
    /// 本码靠适配器存在性正向枚举（直接）。合并等于把两条相反的可操作指引冲成一句谁也用不上的话。
    ///
    /// 终态（本腿判失败即 `kill_core` 并计入重试预算，预算耗尽后走
    /// [`set_error`](super::ProxyRuntime::set_error)）。
    pub const TUN_ADAPTER_MISSING: &str = "TUN_ADAPTER_MISSING";
    /// **#332 TUN 地址无法分配**：核自己的 FATAL 行指明失败发生在「给 TUN 网卡装地址」这一步
    /// （地址被残留网卡/他方 VPN 占用，或系统拒绝分配）——「真因不上屏」轴。
    ///
    /// 控制流位置可诚实断言：判据是**核 stderr 的 FATAL 行内容**，经
    /// [`classify_core_fatal_line`](super::core_log::classify_core_fatal_line) 匹配 sing-box/sing-tun 的**源码字面量**
    /// （`configure tun interface` + `set ipv4/ipv6 address` / `add address`），不是猜我方 message 的关键字。
    /// 取证与匹配面（含为什么**不**匹配 errno 文案）见该函数文档。
    ///
    /// **为什么值得一个专属码**：重试预算耗尽后用户此前只看到「sing-box 起核超时/启动期退出」这种
    /// 与现场无关的话，而真正可操作的信息（地址被占了、去断开另一个 VPN 或重启清残留网卡）明明就写在
    /// 核吐出来的那一行里，只是没人读它。
    ///
    /// 终态（核已自行退出，走 [`set_error`](super::ProxyRuntime::set_error)）。
    pub const TUN_ADDRESS_UNAVAILABLE: &str = "TUN_ADDRESS_UNAVAILABLE";
}

/// [`code::HELPER_NOT_INSTALLED`] 的用户可见兜底文案（zh）。command 前置拦截与 runtime preflight
/// 共用同一串 → 「点连接」与「托盘/自动连接」两路给出一致提示。渲染端另有 i18n key
/// (`errors.helperNotInstalled*`) 覆写多语，此常量为无 emitter / 极早期失败时的兜底。
pub const HELPER_NOT_INSTALLED_MSG: &str =
    "TUN 模式需要提权 helper，但 helper 尚未安装。请到「设置 › Helper」安装后重试。";

/// [`code::HELPER_GATE_ABORTED`] 的用户可见兜底文案（zh）。渲染端另有 i18n key
/// (`errors.helperGateAborted`) 覆写多语，此常量为无 emitter / 极早期失败时的兜底。
pub const HELPER_GATE_ABORTED_MSG: &str = "已取消安装提权助手，本次未启动 TUN 模式代理。";

/// [`code::TUN_ROUTE_NOT_CAPTURED`] 的用户可见兜底文案（zh）。渲染端另有 i18n key
/// (`errors.tunRouteNotCaptured`) 覆写多语，此常量为无 emitter / 极早期失败时的兜底。
pub const TUN_ROUTE_NOT_CAPTURED_MSG: &str = "检测到其他 VPN 占用默认路由，请先断开后重试。";

/// [`code::TUN_ADAPTER_MISSING`] 的协议兼容诊断（zh）；渲染端只按稳定码取
/// i18n 键 `errors.tunAdapterMissing`，本串只在 Rust 单独出声/旧协议路径上保留。
///
/// 措辞刻意**不**提「其他 VPN」—— 那是 [`TUN_ROUTE_NOT_CAPTURED_MSG`] 的场景。本码的现场是网卡根本没
/// 建出来，最常见成因是 wintun 驱动被安全软件拦/驱动没装上/上一张网卡卡在半释放态。
pub const TUN_ADAPTER_MISSING_MSG: &str =
    "TUN 虚拟网卡未能创建，请检查 wintun 驱动是否被安全软件拦截，或重启系统后重试。";

/// [`code::TUN_ADDRESS_UNAVAILABLE`] 的用户可见兜底文案（zh；渲染端另有 i18n 键
/// `errors.tunAddressUnavailable`）。
///
/// **不逐字转述核的原话**：那一行的尾巴是 OS 的 errno 文案（Windows 上经 `FormatMessage` 出来，
/// 是**系统语言**的 —— 中文系统上是「对象已存在。」），把它拼进面向用户的句子只会得到一句半英半中、
/// 且在不同机器上长得不一样的话。码负责分类、文案负责指路，原始行仍完整落在日志里供导出诊断。
pub const TUN_ADDRESS_UNAVAILABLE_MSG: &str =
    "TUN 虚拟网卡地址无法分配，可能被残留网卡或其他 VPN 占用。请断开其他 VPN，或重启系统后重试。";

/// 起核/重启失败的**类型化错误**：用户可见消息 + 本次失败**自己的**结构化码（[`code`] 常量之一）。
///
/// **为什么必须让错误自带码，而不是让命令层回读 `status().error_code`**（根因）：
/// [`ProxyRuntime::set_error`] 只覆盖一部分失败腿（见其文档「不覆盖的腿及理由」：config 生成 / 写盘 /
/// spawn 前的解析失败一律不经它）。命令层若回读全局状态，拿到的可能是**上一次**失败留下的陈旧码 ——
/// 全局 `error_code` 只有 `stop()` 会清，而「门弹出 → 用户取消」这条路径**根本不经过 stop**。
/// 实际后果：取消后 `HELPER_GATE_ABORTED` 粘在全局，用户装好 helper 再点连接、这次栽在「配置生成失败」
/// 腿上，命令层却把它贴上 `HELPER_GATE_ABORTED` 回给渲染端 → `HomeScreen` 命中「用户取消」分支，弹
/// 中性 info、跳过 `setConnectError`，**真实错误被整条吞掉**。
///
/// 结果与来源在此重新耦合：码随**这一次**的 Err 值一起出栈，不存在「读到别人的码」的物理可能。
/// `code: None` = 本腿没有可诚实断言的分类（不是「忘了填」），命令层照实回落无码错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartError {
    /// 用户可见消息（等价于此前的裸 `String` 错误，`Display`/`Into<String>` 均返回它）。
    pub message: String,
    /// 本次失败的结构化码（[`code`] 模块常量）。`None` = 无可诚实断言的分类。
    pub code: Option<&'static str>,
}

impl StartError {
    /// 带码构造（调用点须与 [`ProxyRuntime::set_error`] 落的码逐字一致：同一次失败对渲染端与对
    /// `event:proxyError` 订阅者必须是同一个分类，两处分叉 = 又一个「结果与来源解耦」）。
    fn coded(message: impl Into<String>, code: &'static str) -> Self {
        Self {
            message: message.into(),
            code: Some(code),
        }
    }
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for StartError {}

/// 无码腿的零成本升格：`start_inner` 内既有的 `.map_err(|e| format!(...))?` 经此自动转型，
/// 不必逐条改写（它们本就没有码，`None` 是**诚实**的默认，不是丢信息）。
impl From<String> for StartError {
    fn from(message: String) -> Self {
        Self {
            message,
            code: None,
        }
    }
}

/// 让 `ApiResponse::err(e)`（`impl Into<String>`）与既有 `format!("{e}")` 调用方零改动继续工作。
impl From<StartError> for String {
    fn from(e: StartError) -> Self {
        e.message
    }
}

/// `event:proxyError` 发射抽象（同 `tailscale_login_core::AuthUrlEmitter` 范式）。
///
/// **为什么是 trait 而非直接持 `AppHandle`**：崩溃自愈跑在后台 task（无 command 上下文、无人 await），
/// 而 `AppHandle` 只在 Tauri `setup` 之后才有 → 运行时必须能「先构造、后接线」。trait 同时让单测能
/// 捕获发射记录断言「这条失败腿真发了事件」——§K7.1 的教训：光测函数、光测失败都不够，要测**组合路径**。
/// **名字为何仍是 `...ErrorEmitter` 而不含后加的两个通道**：接线点在 `main.rs`
/// （`set_error_emitter(Box::new(AppHandleProxyErrorEmitter{..}))`），改名要动 `main.rs`——本批次
/// 不碰它。语义上它已是「ProxyRuntime 的事件出口」，重命名留作纯机械的后续项。
pub trait ProxyErrorEmitter: Send + Sync {
    /// 发射一条代理错误事件（payload 对齐前端 `ProxyErrorEvent`）。
    fn emit_proxy_error(&self, message: &str, error_code: &str);

    /// 发射启动 gate 剔除的非法节点（payload = `InvalidNodeInfo[]`）。
    ///
    /// **空数组不是「没事发生」**：前端据此清陈旧标灰（上次起核剔了、本次没剔 → 必须让灰掉的节点复原），
    /// 故每次起核都发，调用方不得自行短路空集。
    fn emit_invalid_nodes(&self, nodes: &[InvalidNode]);

    /// 发射「TUN 启动后检测到无 marker 的系统代理残留」提示（payload = `{proxy}`）。
    fn emit_system_proxy_residual(&self, proxy: &str);

    /// **A3**：发射一条 Tailscale 端点状态（`event:tailscaleStatus`，逐 endpoint 一条，payload =
    /// 前端 `TailscaleStatusEvent`）。由 STATUS relay 每收一帧对每个在册端点各发一次。
    ///
    /// 未接线（单测 / setup 前）→ relay 侧 `error_emitter.get()` 取不到即静默跳过；本方法只负责「有 emitter
    /// 时怎么发」。之所以复用本 trait（而非新加一个 emitter + main.rs 接线点）：`AppHandleProxyErrorEmitter`
    /// 已持 `AppHandle`、已在 `main.rs` setup 期 `set_error_emitter` 一次接线，扩一个方法**无需动 main.rs**
    /// （本批禁区）；语义上它本就是「ProxyRuntime 的事件出口」（见 trait 头注）。
    fn emit_tailscale_status(&self, event: &TailscaleStatusEvent);

    /// 发射 OpenConnect/OpenVPN 原生端点状态。认证材料仅在事件载荷与提交 RPC 间流转，禁止写日志。
    fn emit_openconnect_status(&self, event: &OpenConnectStatusEvent);
    fn emit_openvpn_status(&self, event: &OpenVpnStatusEvent);

    /// **A4**：发射「组网登录期出口让位」态变（`event:meshLoginFallback`，payload =
    /// `{engaged, serverName?}`）。engage（进入让位）/ disengage（就绪切回 / 关开关 / 停核复位）各发一次。
    ///
    /// 复用本 trait 同 [`emit_tailscale_status`](Self::emit_tailscale_status) 的理由：`AppHandleProxyErrorEmitter` 已持 `AppHandle`、
    /// 已在 `main.rs` setup 一次接线，扩方法**无需动 main.rs**（本批禁区）。
    fn emit_mesh_login_fallback(&self, engaged: bool, server_name: Option<&str>);

    /// **C3**：发射「自动换节点成功」通知（`event:autoNodeSwitched`，payload = 前端
    /// `{ reason, newServerName, latency }`）。由自动换节点心跳在 selector 热切并回读自证后发一次。
    ///
    /// 复用本 trait 同 [`emit_tailscale_status`](Self::emit_tailscale_status) / [`emit_mesh_login_fallback`](Self::emit_mesh_login_fallback) 的理由：
    /// `AppHandleProxyErrorEmitter` 已持 `AppHandle`、已在 `main.rs` setup 一次接线，扩方法**无需动
    /// main.rs**（本批禁区）；语义上它本就是「ProxyRuntime 的事件出口」（见 trait 头注）。
    fn emit_auto_node_switched(&self, payload: &AutoNodeSwitchedPayload);

    /// 只发“磁盘配置/运行投影需重拉”信号，不再次进入普通 config switch 流水线。用于 selector
    /// 双不自证后的受限对账完成通知；若走普通广播会把 D 中未 Apply 的其它字段夹带入核。
    fn emit_config_changed(&self);

    /// **unlock（核 start/stop 缓存失效）**：核起停即出口隧道换了一次 → 解锁快照必须失效，否则 30min TTL
    /// 内会复用停核前的陈旧解锁快照（对齐 上游 `ProxyManager` start/stop → `unlockService.invalidate()`）。
    ///
    /// 递增 epoch（作废在飞轮）+ 清缓存 + 广播 `EVENT_UNLOCK_INVALIDATED{running,exitBlocked}`。`running`
    /// 带核真态（start=true / stop=false）供渲染端决定「显检测中 vs 复位 idle」。
    ///
    /// 复用本 trait 同 [`emit_tailscale_status`](Self::emit_tailscale_status) / [`emit_auto_node_switched`](Self::emit_auto_node_switched) 的理由：
    /// `AppHandleProxyErrorEmitter` 已持 `AppHandle`、已在 `main.rs` setup 一次接线，扩方法**无需动
    /// main.rs**（本批禁区）。`UnlockRuntime` 经 `AppHandle` 的 `State<AppRuntime>` 取（生产接线点，
    /// 单测 emitter 记录参数即可、不触 Tauri）。
    fn invalidate_unlock(&self, running: bool, exit_blocked: bool);

    /// **出口 IP / 延迟自动重探排程**（移植 上游 `IpInfoService` 的事件驱动触发表；上游 **无周期轮询**，
    /// 本腿同样纯事件驱动）。核起停 / 热切 = 出口换了一次 ⇒ 状态栏那格出口 IP、以及它下游的伴测延迟
    /// 都必须重探，否则要么显示上一个出口的陈旧值、要么（冷启动）恒 `—` 直到用户亲手点「网络检测」。
    ///
    /// `running` = 事件语义（起核 / 热切 = true，停核 = false），实现据此决定是否等选路收敛
    /// （上游 `whenSelectorSettled(4000)`）。**与 [`invalidate_unlock`](Self::invalidate_unlock) 同三点触发
    /// 但不合并进它**：那条是「解锁快照作废」，这条是「出口 IP 重探」，两件事的失效语义、下游、延迟策略
    /// 都不同；合成一个方法会让日后任一侧改触发条件时误伤另一侧。
    ///
    /// 复用本 trait 同 [`emit_tailscale_status`](Self::emit_tailscale_status) 等的理由：
    /// `AppHandleProxyErrorEmitter` 已持 `AppHandle`、已在 `main.rs` setup 一次接线，扩方法**无需动 main.rs**。
    fn schedule_exit_ip_refresh(&self, running: bool);

    /// OS 网络变化后的恢复探测：先跑出口探测，成功后再由 command 层按旧快照/能力置信度决定是否补跑
    /// 解锁检测。与起停/热切的普通出口刷新分开，避免所有出口刷新都被误读成「网络恢复」。
    fn schedule_network_recovery_refresh(&self);

    /// **R2 出口无效直判终态**（移植 上游 `IpInfoService.markProxyBlocked`）：选中 TS 出口被 API 直判
    /// 无效（未选出口设备 / exit peer 离线 / 在线但未广告出口）时，**不探测**直接把出口 IP 快照落成
    /// 「出口无效」终态并广播 —— 探测在这种形态下必然打空转（重试预算 20s 全耗尽后仍是 null），
    /// 用户看到的是「一直在检测」而不是「出口无效」。
    ///
    /// `reason` = `ui/src/contracts/types/runtime.ts` 的 `ProxyExitBlock` 值域
    /// （`ts-needs-auth` / `ts-no-exit-device` / `ts-exit-device-offline` / `ts-exit-not-advertised`），由
    /// [`ts_exit_block_reason`](ProxyRuntime::ts_exit_block_reason) 从纯谓词 `TsExitWarning` 投影而来（值域单一真值，不在此处重复拼串）。
    ///
    /// **与 [`schedule_exit_ip_refresh`](Self::schedule_exit_ip_refresh) 是同一物理事实的两条互斥出口**：
    /// 出口换了 ⇒ 要么「重探」（出口有效，值待测），要么「落无效终态」（出口已知无效，不必测）。
    /// `exit_ip_wiring_guard` 因此把两者都算作合法的「出口 IP 腿」。
    ///
    /// 复用本 trait 的理由同 [`invalidate_unlock`](Self::invalidate_unlock)（emitter 已持 `AppHandle`，
    /// 扩方法无需动 `main.rs`）。
    fn mark_exit_blocked(&self, reason: &str);

    /// **R2 待应用差集 PUSH**：发一条差集摘要（`event:proxyPendingChanges`，payload = 前端 `{added, modified}`）。
    /// 由 [`switch_mode_with`](ProxyRuntime::switch_mode_with) 落盘后单点推，前端据此渲染 Home 待应用操作条（「N 项待应用」
    /// +「立即应用」）。契约适配依据见 [`PendingChangesSummary`]。
    ///
    /// 复用本 trait 同 [`emit_auto_node_switched`](Self::emit_auto_node_switched) 等的理由：
    /// `AppHandleProxyErrorEmitter` 已持 `AppHandle`、已在 `main.rs` setup 一次接线，扩方法**无需动 main.rs**
    /// （本批禁区）。
    fn emit_pending_changes(&self, summary: &PendingChangesSummary);

    /// **runtime 生命周期结局 PUSH**（`event:proxyLifecycle`，载荷 [`ProxyLifecycleEvent`]）。
    ///
    /// 与 [`emit_pending_changes`](Self::emit_pending_changes) 是**同刻同点的一对**：那条说
    /// 「差集变成什么了」，这条说「核这一次到底起来没起来」。前者判不了后者 —— 起核**失败**时
    /// `startup_snapshot` 同样是 `None`、差集同样为空，拿「差集变空」当成功信号会把失败误报成成功。
    ///
    /// 复用本 trait 的理由同 [`emit_pending_changes`](Self::emit_pending_changes)：
    /// `AppHandleProxyErrorEmitter` 已持 `AppHandle`、已在 `main.rs` setup 一次接线，扩方法无需动 main.rs。
    fn emit_lifecycle(&self, event: &ProxyLifecycleEvent);

    /// **TUN 提权引导门**（移植 上游 `promptHelperGate`，`src/main/index.ts:370-500`）：TUN 起核前
    /// helper 不可用时，**同步**弹一次原生对话框问用户；用户确认 → 在本调用内**就地**执行授权安装
    /// （macOS `SMAppService` / Windows UAC / Linux `pkexec`，各弹一次系统授权框），返回
    /// [`HelperGateDecision::Proceed`] 让起核**原地继续**；用户取消 → [`HelperGateDecision::Abort`]。
    ///
    /// **为什么安装动作在 emitter 内、而不是让 runtime 拿着决策自己去装**：安装要经
    /// `AppRuntime::helper()`，而 runtime 层持有的是 `Arc<HelperRuntime>` —— 两者是同一个实例，
    /// 本可任选。选这里是因为「弹框 → 授权 → 轮询就绪」是**一段不可分割的同步交互**（中途返回
    /// 给异步调用方再回调，会在两次系统弹框之间插入一个可被 lifecycle 抢占的缝）。
    ///
    /// **同步签名**：`blocking_show` 与 `install()`（osascript 可阻塞 30s+）都是阻塞调用，调用方
    /// [`ProxyRuntime::run_helper_gate`] 负责在 `spawn_blocking` 里调它，绝不阻塞 async runtime，
    /// 也绝不在 Tauri 主线程上调（`blocking_show` 在主线程会死锁）。
    ///
    /// 复用本 trait 同 [`emit_tailscale_status`](Self::emit_tailscale_status) 等的理由：
    /// `AppHandleProxyErrorEmitter` 已持 `AppHandle`、已在 `main.rs` setup 一次接线，扩方法**无需动
    /// main.rs**（本批禁区）。
    ///
    /// `status` = 弹框时刻的 helper 快照（供文案分流「安装」vs「修复」）。
    fn prompt_helper_gate(&self, status: &HelperStatusSnapshot) -> HelperGateDecision;

    /// **helper「可升级」的温和提示**（TUN 起核汇流点的第二条腿，
    /// [`ProxyRuntime::run_helper_gate`] 调）：helper 已装、能用，但不是随包那一版时，
    /// 弹一次原生框问用户「现在升级还是直接继续」。
    ///
    /// # 为什么**不复用** [`prompt_helper_gate`](Self::prompt_helper_gate)
    ///
    /// 那条的值域里有 [`HelperGateDecision::Abort`]，语义是「**不起核**」；而本腿的既定决策是
    /// **永不阻断** —— 把一个能表达「别起核」的值域接进一条不许阻断的腿，日后任何一次误用都是
    /// 比原缺陷严重得多的回归（原缺陷只是少提示一次，误用是把一次本来能成功的 TUN 启动变成失败）。
    /// 故另起一个只有 bool 的方法：想让它阻断，得先改签名。
    ///
    /// 返回值 = **用户是否选了「升级并继续」**。升级动作本身在实现方内就地完成（理由同
    /// `prompt_helper_gate`：「弹框 → 授权 → 轮询就绪」是一段不可分割的同步交互），
    /// 失败只记日志、**不抛**；调用方无论拿到哪个值都照常继续起核，本返回值只用于日志分流。
    ///
    /// **同步签名**：内含 `blocking_show` 与 `install()`（osascript/UAC/pkexec 可阻塞 30s+），
    /// 调用方负责在 `spawn_blocking` 里调它，绝不在 async worker 或 Tauri 主线程上直调。
    ///
    /// `status` = 弹框时刻的 helper 快照（供日志记录当前 proto / build 身份）。
    fn prompt_helper_upgrade(&self, status: &HelperStatusSnapshot) -> bool;

    /// **B1 隐私模式活态**（`generate_deps` 注入 `GenerateConfigDeps::privacy_mode` 用）。
    ///
    /// # 为什么读它要经 emitter，而不是 `ProxyRuntime` 自己存一份
    ///
    /// 隐私模式的**单一真值**是 `commands::config` 的进程状态机（`PRIVACY_MODE: AtomicBool`，由
    /// `config:setPrivacyMode` 翻转 + emit `EVENT_ENTER/EXIT_PRIVACY_MODE`）。若在 runtime 侧再存一份
    /// 镜像（哪怕靠事件同步），就有了两个真相源 —— 而这条轴的失效方式恰恰是**静默**的：镜像漏更新时
    /// 隐私模式看起来开着、核却继续按用户级别把域名写进 helper stderr，没有任何可见症状。故读取一律
    /// 回到那一份 flag。`AppHandleProxyErrorEmitter` 已持 `AppHandle`（`main.rs` setup 一次接线，扩方法
    /// **无需动 main.rs** —— 同 [`invalidate_unlock`](Self::invalidate_unlock) 的既定手法）。
    ///
    /// 未接线（单测 / setup 前极早期）→ 实现方返 `false`：**保守方向正确**——不抬级 = 与本方法接线前
    /// 的行为逐字节一致，绝不会因为「读不到 flag」就误把用户的 debug 日志静默降级掉。
    fn privacy_mode(&self) -> bool;
}

/// 出口 IP 重探的延迟策略（[`ProxyErrorEmitter::schedule_exit_ip_refresh`] 的全部决策，抽成纯函数供单测）。
///
/// - 起核 / 热切（`running=true`）→ 等选路收敛（上游 `whenSelectorSettled(4000)`）：此刻 selector 的 PUT
///   才刚落，出口隧道未必已能跑流量，立刻探会打到旧出口或直接失败。
/// - 停核（`running=false`）→ 出口是**确定性消失**而非切换，没有「收敛」这回事，零延迟直接重探直连出口；
///   白等 4s 只会让状态栏多显示 4s 的陈旧代理出口 IP。
#[must_use]
fn exit_ip_refresh_delay_ms(running: bool) -> u64 {
    if running {
        crate::commands::misc::IPINFO_SETTLE_DELAY_MS
    } else {
        0
    }
}

/// 生产实现：经 [`AppHandle`](tauri::AppHandle) 广播 `event:proxyError`。
pub struct AppHandleProxyErrorEmitter {
    /// Tauri 应用句柄（`setup` 期注入）。
    pub app: tauri::AppHandle,
}

impl ProxyErrorEmitter for AppHandleProxyErrorEmitter {
    fn emit_proxy_error(&self, message: &str, error_code: &str) {
        // payload 逐字段对齐前端 `ProxyErrorEvent`：message 必给（兼容旧渲染端），errorCode 结构化分类。
        // errorParams/code/signal/error 不发 —— 本层没有可诚实填充它们的依据，宁缺勿造。
        crate::events::broadcast(
            &self.app,
            crate::events::channel::EVENT_PROXY_ERROR,
            serde_json::json!({ "message": message, "errorCode": error_code }),
        );
    }

    fn emit_invalid_nodes(&self, nodes: &[InvalidNode]) {
        // 直接发数组（前端 `onInvalidNodes` 签名即 `InvalidNodeInfo[]`，不再套一层对象）。
        crate::events::broadcast(
            &self.app,
            crate::events::channel::EVENT_PROXY_INVALID_NODES,
            nodes,
        );
    }

    fn emit_system_proxy_residual(&self, proxy: &str) {
        crate::events::broadcast(
            &self.app,
            crate::events::channel::EVENT_SYSTEM_PROXY_RESIDUAL,
            serde_json::json!({ "proxy": proxy }),
        );
    }

    fn emit_tailscale_status(&self, event: &TailscaleStatusEvent) {
        // 直接发单条事件（前端 `onTailscaleStatus` 签名即 `TailscaleStatusEvent`，serde camelCase 对齐契约）。
        crate::events::broadcast(
            &self.app,
            crate::events::channel::EVENT_TAILSCALE_STATUS,
            event,
        );
    }

    fn emit_openconnect_status(&self, event: &OpenConnectStatusEvent) {
        crate::events::broadcast(
            &self.app,
            crate::events::channel::EVENT_OPENCONNECT_STATUS,
            event,
        );
    }

    fn emit_openvpn_status(&self, event: &OpenVpnStatusEvent) {
        crate::events::broadcast(
            &self.app,
            crate::events::channel::EVENT_OPENVPN_STATUS,
            event,
        );
    }

    fn emit_mesh_login_fallback(&self, engaged: bool, server_name: Option<&str>) {
        // payload 对齐前端 `onMeshLoginFallback` 签名 `{engaged, serverName?}`：serverName 缺省则省略键。
        let mut payload = serde_json::json!({ "engaged": engaged });
        if let Some(name) = server_name {
            payload["serverName"] = serde_json::Value::String(name.to_string());
        }
        crate::events::broadcast(
            &self.app,
            crate::events::channel::EVENT_MESH_LOGIN_FALLBACK,
            payload,
        );
    }

    fn emit_auto_node_switched(&self, payload: &AutoNodeSwitchedPayload) {
        // 自动事务只改了 D.selectedServerId，且已自行完成 R 的热切与回读；这里只发 signal-only 配置
        // 失效通知，让主窗/自绘托盘/原生托盘重拉选中态。不能走普通 broadcast_config_changed：后者
        // 还会把整份 D 送进 switch_mode，可能夹带其它已保存未 Apply 的结构变更触发重启。
        crate::commands::config::emit_config_changed_signal(&self.app);
        // 直接发 payload（前端 `onAutoNodeSwitched` 签名即 `{reason, newServerName, latency}`，
        // serde camelCase 已对齐契约）。
        crate::events::broadcast(
            &self.app,
            crate::events::channel::EVENT_AUTO_NODE_SWITCHED,
            payload,
        );
    }

    fn emit_config_changed(&self) {
        crate::commands::config::emit_config_changed_signal(&self.app);
    }

    fn invalidate_unlock(&self, running: bool, exit_blocked: bool) {
        use tauri::Manager;
        // `UnlockRuntime` 的失效编排（bump epoch + 清缓存 + 广播）在 `AppRuntime.unlock`；经 `AppHandle` 的
        // managed State 取（manage 之后才有 → `try_state`：setup 前极早期失败取不到即静默跳过，绝不 panic）。
        // 广播出口用 unlock 自己的 `BroadcastSink`（持同一 `AppHandle`），事件键/载荷与 command 层一致。
        if let Some(rt) = self.app.try_state::<crate::runtime::AppRuntime>() {
            let sink = crate::runtime::unlock::BroadcastSink::new(&self.app);
            rt.unlock.invalidate(&sink, running, exit_blocked);
        }
    }

    fn schedule_exit_ip_refresh(&self, running: bool) {
        crate::commands::misc::schedule_ipinfo_refresh(
            &self.app,
            exit_ip_refresh_delay_ms(running),
        );
    }

    fn schedule_network_recovery_refresh(&self) {
        crate::commands::misc::schedule_network_recovery_refresh(&self.app);
    }

    fn mark_exit_blocked(&self, reason: &str) {
        // 上游 `IpInfoService.markProxyBlocked`：不探测、直接落终态 —— 代理出口清空 + `proxyBlocked`
        // 置原因 + `loading:false`（blocked 与 error 互斥语义：blocked = 已知无效、根本没探）。
        //
        // **经 `commands::misc` 的权威缓存写入腿，而不是就地 broadcast**：`EVENT_IP_INFO_UPDATED` 只喂
        // 订阅方（状态栏），而 `ipinfo:get(peek)` 型消费方（托盘浮层 / 窗口重建水合）**不订阅**、只读
        // `IPINFO_CACHE` —— 只广播不写缓存 ⇒ 那两处继续吐上一次探到的（此刻已知无效的）代理出口 IP。
        // 载荷折叠（含 direct 保留、error 删键）与广播都由那一侧单点收口，此处零重复实现。
        crate::commands::misc::mark_ipinfo_proxy_blocked(&self.app, reason);
    }

    fn privacy_mode(&self) -> bool {
        use tauri::Manager;
        // 直接读单一真值（`commands::config` 的进程状态机），不镜像。`config_get_privacy_mode` 是普通
        // `pub fn`（`#[tauri::command]` 只生成旁路 wrapper，不改函数本身），故可直调。
        // `try_state`：setup 前极早期取不到 → 保守 false（同上方 `invalidate_unlock` 的取态手法）。
        self.app
            .try_state::<crate::runtime::AppRuntime>()
            .and_then(|s| crate::commands::config::config_get_privacy_mode(s).data)
            .unwrap_or(false)
    }

    fn emit_pending_changes(&self, summary: &PendingChangesSummary) {
        // 直接发 payload（前端 `onPendingChanges` 签名即 `{added, modified}`，serde camelCase 已对齐契约）。
        crate::events::broadcast(
            &self.app,
            crate::events::channel::EVENT_PROXY_PENDING_CHANGES,
            summary,
        );
    }

    fn emit_lifecycle(&self, event: &ProxyLifecycleEvent) {
        crate::events::broadcast(
            &self.app,
            crate::events::channel::EVENT_PROXY_LIFECYCLE,
            event,
        );
    }

    fn prompt_helper_gate(&self, status: &HelperStatusSnapshot) -> HelperGateDecision {
        use tauri::Manager;
        use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};

        // 上游 `promptHelperGate` 首件事：把主窗拉到前台。门可由**托盘切模式 / 启动自动连接 / 去抖
        // 重启**触发，此时主窗常已收进托盘 —— 不拉前台则原生弹框可能出现在用户看不到的层级，表现为
        // 「点了没反应」（正是本次真机反馈的形态之一）。失败不阻断（无窗口时照样弹应用级模态）。
        if let Some(w) = self.app.get_webview_window("main") {
            let _ = w.show();
            let _ = w.set_focus();
        }

        // 文案分流：已装但不可用 = 修复（多为 proto 升级 / 描述符失效），未装 = 安装。
        // **不提供「本次用系统授权启动」**：Polaris 尚无 osascript/UAC/setcap 回退腿，给这个按钮 = 撒谎。
        //
        // 语言从 `config.language` 来（[`crate::i18n::app_lang`]）而**不是**由前端传下来：本门的
        // 发起方包含 `startup_tasks::spawn_auto_connect`（启动 2s 后 Rust 自己调 `proxy_start`）
        // 与托盘原生菜单的 `tray_toggle` —— 两条都没有前端在场，前端手上那份 i18next 递不进来。
        use crate::i18n::{key, t};
        let lang = crate::i18n::app_lang(&self.app);
        let (message, detail, confirm) = if status.installed {
            (
                key::NATIVE_HELPER_REPAIR_TITLE,
                key::NATIVE_HELPER_REPAIR_BODY,
                key::NATIVE_HELPER_REPAIR_CONFIRM,
            )
        } else {
            (
                key::NATIVE_HELPER_INSTALL_TITLE,
                key::NATIVE_HELPER_INSTALL_BODY,
                key::NATIVE_HELPER_INSTALL_CONFIRM,
            )
        };

        let confirmed = self
            .app
            .dialog()
            .message(t(lang, detail))
            .title(t(lang, message))
            .kind(MessageDialogKind::Info)
            .buttons(MessageDialogButtons::OkCancelCustom(
                t(lang, confirm),
                t(lang, key::NATIVE_CANCEL),
            ))
            .blocking_show();
        if !confirmed {
            log::info!("TUN 提权引导：用户取消 → 本次不起核（HELPER_GATE_ABORTED）");
            return HelperGateDecision::Abort;
        }

        // 就地授权安装（上游 `await helperManager.install().catch(() => {})` —— 失败**不抛**：由调用方
        // 复检 helper 状态统一裁定，装不上就落 HELPER_NOT_INSTALLED，绝不在这里替它决定终态）。
        // `HelperRuntime::install` 内部已含「弹一次系统授权 + 装后轮询 daemon 就绪」（上游 第 6 步）。
        match self.app.try_state::<crate::runtime::AppRuntime>() {
            Some(rt) => {
                let r = rt.helper().install();
                if r.success {
                    log::info!("TUN 提权引导：helper 安装成功 → 原地继续起核");
                } else {
                    log::warn!(
                        "TUN 提权引导：helper 安装未成功（{}）→ 交由起核门复检裁定",
                        r.reason_for_log()
                    );
                }
            }
            // setup 前的极早期（AppRuntime 尚未 manage）：装不了，照样返回 Proceed —— 复检会发现
            // helper 仍未装并落 HELPER_NOT_INSTALLED。此处**不得**返回 Abort：用户明明点了「安装」，
            // 报「用户已取消」是伪造用户意图。
            None => log::warn!("TUN 提权引导：AppRuntime 尚未装配 → 无法安装 helper"),
        }
        HelperGateDecision::Proceed
    }

    fn prompt_helper_upgrade(&self, status: &HelperStatusSnapshot) -> bool {
        use tauri::Manager;
        use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};

        // 同 `prompt_helper_gate` 的首件事：先把主窗拉到前台。本腿的发起方同样包含**托盘切模式 /
        // 启动自动连接 / 去抖重启**，此时主窗常已收进托盘 —— 不拉前台则原生弹框可能出现在用户看不到的
        // 层级，表现为「点了没反应」。失败不阻断（无窗口时照样弹应用级模态）。
        if let Some(w) = self.app.get_webview_window("main") {
            let _ = w.show();
            let _ = w.set_focus();
        }
        log::info!(
            "helper 可升级提示：当前 proto {:?} / build {:?}，随包期望 build {}",
            status.version,
            status.helper_build_id,
            status.expected_build_id
        );

        // 文案走 Rust 侧文案表（`crate::i18n`）而**不是**由前端传下来：理由同 `prompt_helper_gate`
        // —— 本门的发起方包含 `startup_tasks::spawn_auto_connect` 与托盘原生菜单的 `tray_toggle`，
        // 两条都没有前端在场，前端手上那份 i18next 递不进来。
        use crate::i18n::{key, t};
        let lang = crate::i18n::app_lang(&self.app);
        let confirmed = self
            .app
            .dialog()
            .message(t(lang, key::NATIVE_HELPER_UPGRADE_BODY))
            .title(t(lang, key::NATIVE_HELPER_UPGRADE_TITLE))
            .kind(MessageDialogKind::Info)
            .buttons(MessageDialogButtons::OkCancelCustom(
                t(lang, key::NATIVE_HELPER_UPGRADE_CONFIRM),
                // 取消键是「直接继续」而**不是**「取消」：本腿不阻断起核，写「取消」会让用户以为
                // 点了就不连接了 —— 按钮文案必须与真实后果一致（见 `NATIVE_HELPER_UPGRADE_SKIP`）。
                t(lang, key::NATIVE_HELPER_UPGRADE_SKIP),
            ))
            .blocking_show();
        if !confirmed {
            log::info!("helper 可升级提示：用户选择直接继续 → 用现有 helper 起核");
            return false;
        }

        // 就地授权升级（= 重装随包 helper；`HelperRuntime::install` 内部已含「弹一次系统授权 +
        // 装后轮询 daemon 就绪」）。**失败不抛、不阻断**：起核照常继续，用户下次仍会在设置页
        // 看到可升级卡片。这与 `prompt_helper_gate` 的未装腿刻意不同 —— 那条装不上就没核可起，
        // 这条装不上还有一个能用的旧 helper。
        match self.app.try_state::<crate::runtime::AppRuntime>() {
            Some(rt) => {
                let r = rt.helper().install();
                if r.success {
                    log::info!("helper 可升级提示：升级成功 → 继续起核");
                } else {
                    log::warn!(
                        "helper 可升级提示：升级未成功（{}）→ 仍用现有 helper 继续起核",
                        r.reason_for_log()
                    );
                }
            }
            // setup 前的极早期（AppRuntime 尚未 manage）：升不了，仍返回 true —— 用户确实选了升级，
            // 谎报成「他选了直接继续」是伪造用户意图（同 `prompt_helper_gate` 的 None 腿）。
            None => log::warn!("helper 可升级提示：AppRuntime 尚未装配 → 无法升级，仍继续起核"),
        }
        true
    }
}

/// serde skip_if 助手：pid=0 时省略（对齐 上游 `pid?`）。
fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

/// `skip_serializing_if` 谓词：false 即省略（`ProxyStatus::starting` 的默认态不占线）。
fn is_false(v: &bool) -> bool {
    !*v
}

/// **核构建环境快照**（[`ProxyRuntime::core_build_env`] 产出，`runtime::speedtest` 的临时核消费）。
///
/// 三项与 [`GenerateConfigDeps`](polaris_config_engine::builder::GenerateConfigDeps) 的同名字段同源：临时核用 config-engine 的**同一批**出站构造函数
/// （`build_proxy_outbound` / `build_wireguard_endpoint`），故必须喂同一套 (platform, arch, cronet)，
/// 否则同一个节点在两个核里被构成不同形状的出站，而测速值却被当作可比。
#[derive(Debug, Clone)]
pub struct CoreBuildEnv {
    /// Node 约定的平台 tag（`darwin` / `win32` / `linux`），见 [`platform_tag`]。
    pub platform: String,
    /// `std::env::consts::ARCH`。
    pub arch: String,
    /// libcronet 是否可用（naive 协议的前置条件；macOS 静态编入 → 恒真）。
    pub has_cronet: bool,
}

/// **§15**：主核测速探测池目标（[`ProxyRuntime::speed_probe_targets`] 产出，`server_speed_test` 消费）。
///
/// = 上游 `MainCoreProbe` 的 Polaris 最小投影。`pool_ports[k]`（`probe-in-k` 的 http 代理口）与
/// `probe-selector-k`（第 k 槽）1:1；`id_to_tag` 是运行核 `probe-selector-k` 的成员命名空间——`id ∈ id_to_tag`
/// 即「已入运行核池」（`hasTag`），据此分流「可测（分波热切）」vs「未入池（notInPool，如实缺席）」。
#[derive(Debug, Clone)]
pub struct SpeedProbeTargets {
    /// K 个 `probe-in-k` 的 http 代理端口（`pool_ports[k] ↔ probe-selector-k`）。
    pub pool_ports: Vec<u16>,
    /// 运行核 id → outbound tag（`probe-selector-k` 成员）。
    pub id_to_tag: BTreeMap<String, String>,
    /// **起核那一刻**运行核各节点的 **5 维** dirty 判据指纹
    /// （= `SwitchSnapshot::dirty_fingerprints` 的只读投影，**不是**全维的 `SwitchSnapshot::fingerprints`）。
    ///
    /// 供测速侧做 dirty 波前预筛：把当前配置的指纹与本表逐 id 比对，**不等 ⇒ 该节点的连接参数已改、
    /// 而池里那个出口还是旧的**（测它量到的是旧参数出口的 RTT），据此标脏免测。
    ///
    /// ⚠️ **两侧必须是同一个公式**（[`dirty_fingerprint`]，= `commands/speedtest::current_server_fingerprints`
    /// 用的那一个）。收口前这里带出的是全维表、而「新」侧算的是 5 维串 —— 两种串永不相等
    /// ⇒ 凡在快照里的节点一律判 dirty ⇒ **整个波前恒被免测**。现在两侧同源，该失败模式在结构上消失。
    ///
    /// ⚠️ **不可用 `pending_changes()` 的 `modified` 代替**：那条是**全维**判据（回答「核里跑的还是不是
    /// 当前配置」），比 dirty 粗一档 —— 只改了 `name` 的节点该进 `modified`，但它的出口没变、测速值仍准，
    /// 判它 dirty 拒测是白白不测一个本可测的节点。两条判据的包含关系（dirty ⊆ modified）见
    /// [`node_fingerprints`](crate::runtime::node_fingerprints) 模块文档。
    ///
    /// [`dirty_fingerprint`]: crate::runtime::node_fingerprints::dirty_fingerprint
    pub fingerprints: BTreeMap<String, String>,
}

/// 代理运行时（`State`-managed，单实例）。
///
/// 持有 config / helper / mesh 引用（跨运行时协作：启动需读 config + 可能经 helper 提权 + mesh exit route）。
pub struct ProxyRuntime {
    config: Arc<ConfigManager>,
    /// 提权 helper（C6-5 接线）：TUN 模式经它起停 root/SYSTEM 受管核（见 [`should_start_via_helper`](startup::should_start_via_helper)）。
    helper: Arc<HelperRuntime>,
    /// C5：mesh 出口路由生命周期接线（起核前 snapshot / 就绪+切换 reconcile / 停核 clear / 崩溃 reset /
    /// 出口恢复 reassert）。OS 路由真操作经 `HelperExitRouteOp`（**已全链接线**：mac/win 经 root helper
    /// `route -ifscope`、Linux 自身 `ip rule/route` 独立表 7732）——生产构造 `MeshRuntime::new_with_helper`
    /// 下是真手术（真机门）；测试构造 `MeshRuntime::new` 下 `enabled=false` 诚实 no-op。见 `runtime/mesh.rs`。
    mesh: Arc<MeshRuntime>,
    status: RwLock<ProxyStatus>,
    /// 运行核启动时的配置快照（待应用差集基准，上游 ProxyManager.startupSnapshot）。
    startup_snapshot: RwLock<Option<Value>>,
    /// 生命周期单飞守卫（core-supervisor 既有状态机；起停竞态/世代/pending 全在其中）。
    gate: Arc<LifecycleGate>,
    /// **世代变更唤醒边沿**（起核腿的取消信号）。
    ///
    /// **不是第二个真值源**：谁当权仍然只看 `gate.generation()`，本 [`Notify`] 只负责把「世代已变」
    /// 这一事实**立刻推醒**正在 sleep 的起核腿。没有它，让位检查点只在**迭代边界**生效：用户点停止时
    /// 若本腿正卡在退避 sleep（2s/4s）里，取消要静默等睡满才被发现 —— 真机上「点连接锁死 UI ≈35s、
    /// 启动卡死阶段无法关闭启动过程」的后半截成因。
    ///
    /// [`notify_waiters`](Notify::notify_waiters) **不留 permit**（无等待者时通知即丢），故所有等待点
    /// 一律「注册 → 复查世代 → select」三步（见 [`sleep_unless_superseded_on`](lifecycle::sleep_unless_superseded_on)），靠复查覆盖注册前的
    /// bump、靠注册覆盖复查后的 bump，两侧夹住不漏边沿。唯一发信点是
    /// [`bump_generation`](Self::bump_generation)，与世代同点落值 ⇒ 信号与真值不会分叉。
    gen_changed: Arc<Notify>,
    /// 在飞起核腿计数（[`ProxyStatus::starting`] 的读时投影源）。
    ///
    /// 由 [`start`](Self::start) 全程持有（含 `?` 早退——`lifecycle::InflightGuard` 的 `Drop` 兜底），故覆盖
    /// 「stale 清扫 → 提权门 → config 生成 → spawn → 就绪等待 → 重试退避」整条起核腿，而不只是
    /// spawn 之后那一段。计数而非布尔：崩溃自愈/去抖重启也直调 `start`，可与用户发起的腿重叠。
    start_inflight: Arc<AtomicU32>,
    /// 后台网络任务的起核稳定门：覆盖整个 start，并在 TUN 成功后延续到 selector 校正与单次连接
    /// flush 结束。订阅自动更新复用它，避免自身请求被 post-start `CloseAllConnections` 误杀。
    network_settle: Arc<NetworkSettleGate>,
    /// 去抖重启调度器（switch-engine 既有 timer + 世代守卫，内部复用同一 `gate`）。
    debounced: DebouncedRestart,
    /// sing-box 子进程句柄。std `Mutex`：就绪门的 `is_alive` 是**同步**闭包（`Fn()->bool`），
    /// 必须能在其中即时 `try_wait`；guard 绝不跨 await 持有（否则 !Send 编译即拒）。
    child: Arc<Mutex<Option<Child>>>,
    /// spawn 出的 pid（child 被 stop 取走后仍可用于日志/诊断；helper 起核时 = daemon 报告的受管核 pid）。
    pid: Arc<Mutex<Option<u32>>>,
    /// **C6-5**：当前运行核是否经 helper 提权起（TUN 路由）。运行期内部真值源（≠ 面向前端的
    /// `ProxyStatus.started_via_helper`，后者仅就绪成功后落）——驱动 [`kill_core`](Self::kill_core) 走
    /// helper stop（child 恒 None）+ 崩溃监测/就绪门改用 pid 探活（helper 核无本地 [`Child`] 句柄）。
    /// 起核提交时置、停核/直起时清。
    core_via_helper: Arc<AtomicBool>,
    /// H-1 强制重启专用配置快照（`(id, config)`）。
    ///
    /// **不可用 currentConfig 替代**：in-flight start 腿会覆盖 currentConfig，drain 必须读本字段
    /// 才能重启到 apply 当时那份 cfg（上游 `pendingForceRestartConfig`，:1729-1730）。
    pending_force_restart: RwLock<Option<(u64, Value)>>,
    /// force-restart 快照 id 发号器（LifecycleGate 只存不透明 id，载荷由本层关联）。
    force_restart_seq: AtomicU64,
    /// 最后**已应用**到运行核的配置（上游 `ProxyManager.currentConfig`）。
    ///
    /// **不可用 `startup_snapshot` 替代**：后者是起核时的快照（待应用差集基准，热切/defer 腿不刷）；
    /// 本字段被热切/no-op/defer 三条非结构腿逐次对账 → 是 `plan_hot_switch` 的 `old` 入参真值。
    /// 也**不可用 `config.current()` 替代**：那是磁盘上的**新**配置（switchMode 的 `new` 入参）。
    current_config: RwLock<Option<Value>>,
    /// 起核时刻的热切换基准（id→tag / rule-sel / 节点指纹）。None = 核未起或快照不可信 → 全部退回重启。
    switch_snapshot: RwLock<Option<SwitchSnapshot>>,
    /// lifecycle 在飞时暂存的 switchMode 配置（上游 `pendingSwitchConfig`，:1753）。
    /// `(id, config, defer_restart)`：id 与 `LifecycleGate::set_switch_pending` 对齐，排空时按 id 认领。
    ///
    /// **`defer_restart` 必须跟着一起暂存**：它是「本次落盘由谁触发」的意图，不是配置内容的一部分。
    /// 若排空重放时丢掉它，用户在核重启窗口内点的那次「保存」会在几秒后自己触发一次重启 ——
    /// 恰是「保存不重启」承诺的反面，且现象是延迟的、极难归因。
    pending_switch: RwLock<Option<(u64, Value, bool)>>,
    /// switch 快照 id 发号器（与 force_restart_seq 同构，各自独立编号）。
    switch_seq: AtomicU64,
    /// 配置入核单飞锁。正常热切换含管理 API I/O；没有这把锁时，快速连续切节点会让多个
    /// `switch_mode` 同时基于同一份 `current_config` 规划，较慢的旧 PUT/commit 可在新请求之后落地，
    /// 表现为最后一次点击被盖回、继而由错误快照触发多余重启。Tokio Mutex 按等待顺序放行，且锁只护
    /// 配置入核流水线，不与同步 [`LifecycleGate`] / 配置写锁混用。
    switch_serial: AsyncMutex<()>,
    /// selector 意图代次、强制重申脏位与后台单飞交接的唯一 owner。
    /// 它与 `switch_serial` 正交：前者给出跨 await 的所有权事实，后者仍串行真实入核 I/O。
    selector_reconcile: Arc<SelectorReconcileOwner>,
    /// 「保存不重启」欠下的账：本次运行核起来之后，是否发生过被 `defer_restart` 降级的结构性变更。
    ///
    /// # 为什么是一个记账标记而不是现算的差集
    ///
    /// 待应用差集（[`Self::pending_changes`]）是**节点**差集，看不见 `mixedPort` / TUN / DNS 这类
    /// 非节点结构性变更 —— 「保存」把它们降成 Defer 后，条上会显示 0 项待应用，用户看到的是
    /// 「保存了、什么也没发生、也没人说还差一步」。那正是本仓刚收口的「第四类重启」同一种形态。
    ///
    /// 现算的候选判据（`norm(起核快照) != norm(磁盘)`）**不可用**：kind=rules 的热切换会 PUT 掉
    /// 规则目标而不刷起核快照 ⇒ 两侧 norm 从此长期不等 ⇒ 恒真的假阳性。真正知道「这次落盘没进核」
    /// 的只有 switch_mode 自己，所以由它记账。
    ///
    /// 清账点**只有核真正按磁盘配置起来那一刻**（与 `startup_snapshot` 同刻）+ 停核复位。
    /// 后续的 NoOp / 热切腿都**不清**：它们没有把先前欠下的那份配置送进核。
    restart_deferred: AtomicBool,
    /// 崩溃自愈状态机（core-supervisor 既有决策机：退避 / 上限 / 让位 / 补发全在其中）。
    ///
    /// 后台崩溃监测任务检测到核**意外**退出时喂它决策，本层只执行「退避 sleep + restart」的 I/O。
    /// 与运行核不同生命周期：跨 start/stop 持久（restart_count 靠 60s 冷却复位，不随每次 start 清零——
    /// 否则崩溃→重启→崩溃 的紧密循环永远达不到上限）。std `Mutex`：决策同步、绝不跨 await 持锁。
    crash_recovery: Mutex<CrashRecoveryMachine>,
    /// 诊断分轴计数器（维度7 #11 慢起 vs 核崩，喂给 `diagnostic_export` 报告）。
    ///
    /// **本运行时只在此持有并喂「慢起轴」**（`last_start_ready_retries`）——它是全仓唯一该产生这数的地方
    /// （起核就绪门的重试累计），此前无人喂 → 报告恒零（§O1）。
    ///
    /// **「核崩轴」不在这里并行记**：`restart_count` 的单一真值是上面的 [`CrashRecoveryMachine`]
    /// （它已按 上游 :548 计数且自带「诊断用」getter `restart_count()`）。`diagnostic_counters()`
    /// 在**读时**把它投影进快照，而非在 `run_crash_recovery` 里再 `record_restart` 一遍——同一崩溃事件
    /// 绝不记两遍（否则两计数器的复位时机会分叉，报告数与控制数打架）。故 `DiagnosticCounters` 的核崩轴
    /// API（`record_restart`/`reset_if_past_cooldown`）在本运行时不被生产调用，仅由 stats-engine 自测覆盖。
    /// std `Mutex`：慢起轴更新同步、绝不跨 await 持锁。
    diagnostics: Mutex<DiagnosticCounters>,
    /// 上一份已被同一内核真实 `check` 接受的生成配置身份。
    ///
    /// 持久化是为了让 app 重启后的第一次连接也能复用；内存态则避免每次连接都重读小文件。
    /// 它是 fail-open 的性能提示而非信任根：未命中或损坏只会多跑一次 check；真起核后的
    /// readiness / FATAL / 出口自证不依赖此字段。
    kernel_gate_cache: Mutex<Option<KernelGateCacheRecord>>,
    /// 受保护核完整 hash 对账的进程内热缓存。任何 payload 元数据变化即 miss；app 重启后首次连接必重验。
    protected_core_cache: Arc<Mutex<Option<ProtectedCoreCacheRecord>>>,
    /// 单测同步屏障：记录就绪探测已经真实失败并进入 `on_retry` 的次数。
    ///
    /// 不能用固定 sleep 代替：Windows hosted runner 上 PowerShell 占位核启动/任务调度可能超过监听延时，
    /// 使监听器先上线、首探即成功，原本要验证的重试接线因此偶发读到 0。生产不携带该字段。
    #[cfg(test)]
    ready_retry_count: Arc<AtomicU32>,
    /// stale-core 清扫**禁用**开关（仅单测置位，用于跳过 `/proc` / `ps` 扫描聚焦被测腿）。
    ///
    /// **原先是「一会话只清一次」的门闩，已废——那个前提是错的**：它假设「孤儿只来自上个 app
    /// 会话崩溃」，而本次真机事故的孤儿恰恰产生于**会话中途**（一次失败的 TUN 起核把 root 核留在了
    /// 后台），于是同一会话的后续 start 全都不再清扫 ⇒ 那个孤儿永远落在清扫射程外，一直占着
    /// `cache.db` 把用户彻底卡死。**清扫缺陷自己就能造出它声称不可能存在的孤儿**，故门闩必须去掉。
    ///
    /// 现语义 = 每次 `start` 都清（对齐 上游 `ProxyManager.ts:700`）。成本：无孤儿时仅一次进程扫描
    /// （Linux 读 `/proc`，macOS 一次 `ps` exec），相对一次用户发起的起核可忽略；有孤儿才进入
    /// SIGTERM/宽限腿。**不选「仅在 start 失败时复位门闩」**：起核成功后核也可能中途崩成孤儿
    /// （正是崩溃自愈路径），那条只覆盖失败腿，仍会漏掉同一类事故。
    stale_sweep_disabled: AtomicBool,
    /// 「helper 可升级」提示的**一次性闸门**（`false` = 本进程尚未提示过）。
    ///
    /// [`run_helper_gate`](Self::run_helper_gate) 是**每次 TUN 起核**都要跑的汇流点（托盘切模式 /
    /// 启动自动连接 / switchMode 去抖重启 / 崩溃自愈重启），而「可升级」是一条**一次性告知**、
    /// 不是状态推送。不去重就是「每次重启弹一次原生模态」，比它要修的缺陷坏得多
    /// （语义同 `startup_tasks::BASELINE_WARNED`）。
    ///
    /// **挂在运行时实例上而不是写成 `static`**：生产进程里 `AppRuntime` 只造一个 `ProxyRuntime`
    /// （`runtime.rs` 的 `AppRuntime::new`），两者在生产上完全等价；而 `static` 在单测里是
    /// **跨用例共享**的 —— 第一个跑到这条腿的用例把它领走，其余用例观测到的恒是「没弹」，
    /// 于是「只弹一次」这条不变式**反而永远无法被证伪**（反向对照没有对象）。
    helper_upgrade_prompted: AtomicBool,
    /// stale-core 清扫的**实跑次数**（诊断 + 「每次 start 都清」这条不变式的唯一可观测量）。
    ///
    /// 没有它，「门闩有没有退回一次性」只能靠读代码推理——而这正是本次事故里失守的那类推理。
    stale_sweep_runs: AtomicUsize,
    /// 外化自定义规则文件落盘降级标记（上游 `customRuleFilesDegraded`，:423）。
    ///
    /// [`write_custom_rule_files`](Self::write_custom_rule_files)（起核前）逐文件写失败 → 置位（缺文件
    /// 触发 route/DNS ext 分支 `existsSync` 降级走 inline，用内存态值，功能不损）；成功清位。运行中
    /// `switch_mode` 三条非结构腿（热切/no-op/defer）据此决定「值热更（[`sync_custom_rule_files`]）还是
    /// 改走去抖重启重落盘」——降级态文件无消费者，改走重启才能让新值生效（否则「写了没人消费」的值陈旧）。
    ///
    /// [`sync_custom_rule_files`]: Self::sync_custom_rule_files
    custom_rule_files_degraded: AtomicBool,
    /// 系统代理 controller + marker 生命周期 + residual 会话门闩的唯一 owner。
    /// 同步 OS 操作的 blocking 隔离与幂等门控全部收敛在 `proxy/system_takeover.rs`。
    system_proxy: SystemProxyTakeover,
    /// `event:proxyError` 发射器（[`set_error`](Self::set_error) 的出口）。
    ///
    /// **`OnceLock` 而非构造参数**：`AppHandle` 要到 Tauri `setup` 才存在，而本运行时在
    /// `AppRuntime::new(config_dir)` 里就得造出来 → 只能「先构造、后接线」（`main.rs` setup 内
    /// [`set_error_emitter`](Self::set_error_emitter)）。未接线（单测 / setup 前的极早期失败）→
    /// `set_error` 只记日志 + 落状态码，不 panic：**发不出事件绝不能反过来打断错误处理本身**。
    error_emitter: std::sync::OnceLock<Box<dyn ProxyErrorEmitter>>,
    /// A4 登录期出口让位内存态（上游 `bootstrapFallbackEngaged` + `bootstrapFallbackServerId`）。
    ///
    /// engaged=当前 proxy-selector 是否被临时热切到 direct；server_id=让位所服务的选中出口 id（用户中途
    /// 切走出口时据此判 stale 复位）。仅运行期内存态，随停核/崩溃复位（[`reset_login_fallback_state`]）。
    /// 单锁护 `(engaged, server_id)` 对，杜绝命令读到撕裂态。
    ///
    /// [`reset_login_fallback_state`]: Self::reset_login_fallback_state
    login_fallback: Mutex<LoginFallbackState>,
    /// A4 reconcile 单飞守卫（上游 `loginFallbackReconciling`）。多驱动源（STATUS 帧 / switchMode / 起核预置）
    /// 可重入；在飞对账中丢弃后来者（下一帧/tick 幂等收敛）。`swap(true)` 抢占、`ReconcileGuard` 保证退场必复位。
    login_fallback_reconciling: AtomicBool,
    /// **R2 TS 出口无效直判的翻转对账缓存**（上游 `lastTsExitBlock`）。`Some(reason)` = 上次对账判定
    /// 出口无效及其原因；`None` = 上次判定有效 / 不适用。
    ///
    /// **存的是「上次值」而不是「当前值」**：对账是**跨态**触发（`cur != prev` 才动作），不是每帧 level
    /// 触发 —— STATUS relay 每秒量级推帧，按当前值动作就成了每秒一次的重探 + 每秒一次解锁失效
    /// （与 [`ts_exit_became_ready`](ts_exit::ts_exit_became_ready) 挡住的是同一种轮询退化）。停核复位（见
    /// [`reset_ts_exit_block_state`](Self::reset_ts_exit_block_state)）。
    last_ts_exit_block: Mutex<Option<&'static str>>,
    /// **R2 出口恢复腿单飞守卫**（上游 `tsExitRecovering`）。恢复腿含 gRPC EditPrefs + reassert
    /// （macOS resolveIface 轮询最长 ~18s），必须串行。
    ts_exit_recovering: AtomicBool,
    /// **R2 出口恢复腿的补跑标记**（上游 `tsExitRecoverPending`）。
    ///
    /// **为什么恢复腿要 pending 而登录让位对账不要**：让位对账是 level 触发（每帧都跑，被丢的那次下一帧
    /// 自愈）；恢复腿是**边沿**触发（只有 blocked→none 跨态才调），在飞期间发生的
    /// `none→blocked→none` flap 若被单飞直接丢弃，**下一帧同态早退**（`cur == prev`）⇒ 那条边沿永远
    /// 不会重来 ⇒ 卡在「出口已恢复但没人去重探」直到下一次真跨态或用户手点。故在飞期间记 pending，
    /// 收尾若仍是 `none` 则补跑一轮。
    ts_exit_recover_pending: AtomicBool,
    /// C11 DNS race sidecar 的唯一 owner：活 sidecar、config 投影与 DoH transport
    /// 在子模块内按固定锁序同刻翻转，并共享本 facade 的 lifecycle generation。
    dns_race: Arc<DnsRaceRuntime>,
    /// C7 系统 DNS 接管控制器（生产装 `production_dns_controller(<userData>/system-dns.marker.json)`）。
    ///
    /// **装配（本机可验）**：在 `new` 里从 `config.dir()` 构造；该字段负责 macOS/Windows，Linux 由
    /// 紧邻的 `linux_resolved_controller` 负责。
    /// `set_dns`/`restore_dns` 是 `&mut self` 同步 API（mac 会 exec `networksetup`/`scutil`），故 `Mutex` 护、
    /// async 里经 `spawn_blocking` 持锁调用、绝不跨 await。接管/恢复经 [`Self::set_system_dns_locked`] /
    /// [`Self::restore_system_dns_locked`]，由 TUN 起核/停核生命周期驱动（marker 单一真值）。
    ///
    /// **真机门**：真正的 mac `networksetup` 与 Linux helper→`resolvectl` 都触碰宿主 DNS，只能在明确
    /// 授权后真机验证；普通 gate 只跑 mock/只读检查。
    dns_controller: Mutex<polaris_system_integration::ProdDnsController>,
    /// Linux `systemd-resolved` per-link 生命周期；实际 root 写入全部经共享 helper，marker 独立于 macOS
    /// 物理网卡 DNS 快照，避免两种恢复语义互相污染。
    linux_resolved_controller: Mutex<
        polaris_system_integration::linux_resolved::LinuxResolvedController<
            HelperLinuxResolvedOps,
            polaris_system_integration::StdMarkerFs,
        >,
    >,
    /// 起核用的核二进制路径覆盖（**仅单测置位**，同 `stale_sweep_disabled` 的先例；生产恒 `None`）。
    ///
    /// 「起核可取消」的门必须有个**真能 spawn 的**假核（起来就死 / 起来但永不就绪），否则退避中断与
    /// 孤儿收割都测不到。唯一的现成注入点 `POLARIS_SINGBOX_PATH` 是**进程级**的：并发跑的其它单测会
    /// 读到它（`runtime::updater` 那条 `core_binary_path().is_none()` 就被这样打红过），等于把测试间
    /// 耦合做成 flaky 源。故改用 per-runtime 覆盖 —— 作用域随实例，绝不外溢到别的测试。
    #[cfg(test)]
    core_binary_override: Mutex<Option<PathBuf>>,
    /// 管理 API PUT 的落点桩（**仅单测置位**，同 `core_binary_override` 的先例；生产恒 `None`）。
    ///
    /// 生产的 PUT 出口是 [`ProxyRuntime::management_api`] → 真 gRPC；单测里核不起、`clash_api_port` 为 0
    /// ⇒ 恒 `NotReady`，于是「谁被 PUT 成了什么、按什么顺序」这类**序列**不变式全都断言不到 —— H3 校正
    /// 的每一条不变式恰好都是序列不变式。这个桩只替换 [`ProxyRuntime::put_outbound`] 里最末端的那次
    /// 调用，其余（成败→bool 的映射、日志、上层决策）全走生产同一条码路。
    #[cfg(test)]
    management_api_stub: Mutex<Option<Arc<TestPutSink>>>,
    /// 通用网络变化 watcher 任务句柄。
    ///
    /// macOS 复用 `route -n monitor`，Linux 复用 `ip monitor`，Windows 用
    /// `NotifyIpInterfaceChange`。所有接管模式在核就绪后都启动；DNS 重灌仍由 marker + TUN + 用户开关
    /// 独立门控，故 System/manual 只触发出口恢复探测，不会越权修改系统 DNS。
    /// 停核 / 崩溃复位时 `abort`；子进程事件源用 `kill_on_drop` 保证无宿主残留。
    network_watcher: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// 当前核会话的逐目的绑定与接口事实。只用于判断网络变化后的降级/重规划，不写回用户配置。
    /// 停核、崩溃及新核接管时整体替换，禁止跨会话沿用陈旧接口名。
    runtime_binding_state: Mutex<RuntimeBindingState>,
}

/// 单测用 DoH 桩：**永远 FAIL**。
///
/// 单测绝不许碰宿主网络（禁向真实 DoH 上游发查询），故这里不是「假成功」而是「明确失败」——
/// 竞速层对 FAIL 的处置本身就有覆盖（Tier2 兜底 / 全 FAIL → SERVFAIL），假成功反而会掩盖问题。
/// 真 DoH 端到端属**真机门**。
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct NoNetworkDoh;

#[cfg(test)]
#[async_trait::async_trait]
impl DohPost for NoNetworkDoh {
    async fn post_dns_message(&self, _url: &str, _body: Vec<u8>) -> Result<Vec<u8>, String> {
        Err("单测桩：不发真实 DoH".into())
    }
}

/// `RecordingErrorEmitter` 的解锁失效记录句柄（与 tests 模块的 `UnlockInvalidations` 同型）。
#[cfg(test)]
type UnlockInvalidationProbe = Arc<Mutex<Vec<(bool, bool)>>>;

impl ProxyRuntime {
    /// 新建（注入 config / helper / mesh 运行时 + 系统代理清理收口器）。
    ///
    /// `proxy_clearer` 生产传 `production_proxy_controller(...)`（见 `runtime.rs`），测试传 mock。
    /// `doh` 生产传 `HttpRuntime`（唯一真实 HTTP/TLS 客户端），测试传 stub。
    /// **二者皆必传**：见各自字段文档（编译期强制接线）。
    pub(crate) fn new(
        config: Arc<ConfigManager>,
        helper: Arc<HelperRuntime>,
        mesh: Arc<MeshRuntime>,
        proxy_clearer: Box<dyn SystemProxyClearer>,
        doh: Arc<dyn DohPost>,
    ) -> Self {
        let gate = Arc::new(LifecycleGate::default());
        // C7：DNS marker 路径锚 `<userData>/system-dns.marker.json`（对齐 上游 `SystemDnsBase.getMarkerPath`）。
        // 在构造前算好（`config` 随后被 move 进 Self）。无 marker（fresh start）→ 控制器全惰性。
        let dns_marker_path = config
            .dir()
            .join(polaris_system_integration::DNS_MARKER_FILENAME)
            .to_string_lossy()
            .into_owned();
        let linux_resolved_marker_path = config
            .dir()
            .join(polaris_system_integration::LINUX_RESOLVED_MARKER_FILENAME)
            .to_string_lossy()
            .into_owned();
        let linux_resolved_controller =
            polaris_system_integration::linux_resolved::LinuxResolvedController::new(
                HelperLinuxResolvedOps(Arc::clone(&helper)),
                polaris_system_integration::StdMarkerFs,
                linux_resolved_marker_path,
            );
        let kernel_gate_cache = load_kernel_gate_cache(&config.dir().join(KERNEL_GATE_CACHE_FILE));
        let dns_race = Arc::new(DnsRaceRuntime::new(Arc::clone(&gate), doh));
        Self {
            config,
            helper,
            mesh,
            status: RwLock::new(ProxyStatus::default()),
            startup_snapshot: RwLock::new(None),
            debounced: DebouncedRestart::new(gate.clone()),
            gate,
            gen_changed: Arc::new(Notify::new()),
            start_inflight: Arc::new(AtomicU32::new(0)),
            network_settle: Arc::new(NetworkSettleGate::default()),
            child: Arc::new(Mutex::new(None)),
            pid: Arc::new(Mutex::new(None)),
            core_via_helper: Arc::new(AtomicBool::new(false)),
            pending_force_restart: RwLock::new(None),
            force_restart_seq: AtomicU64::new(1),
            current_config: RwLock::new(None),
            switch_snapshot: RwLock::new(None),
            pending_switch: RwLock::new(None),
            switch_seq: AtomicU64::new(1),
            switch_serial: AsyncMutex::new(()),
            selector_reconcile: Arc::new(SelectorReconcileOwner::default()),
            restart_deferred: AtomicBool::new(false),
            crash_recovery: Mutex::new(CrashRecoveryMachine::default()),
            diagnostics: Mutex::new(DiagnosticCounters::new()),
            kernel_gate_cache: Mutex::new(kernel_gate_cache),
            protected_core_cache: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            ready_retry_count: Arc::new(AtomicU32::new(0)),
            stale_sweep_disabled: AtomicBool::new(false),
            helper_upgrade_prompted: AtomicBool::new(false),
            stale_sweep_runs: AtomicUsize::new(0),
            custom_rule_files_degraded: AtomicBool::new(false),
            system_proxy: SystemProxyTakeover::new(proxy_clearer),
            error_emitter: std::sync::OnceLock::new(),
            login_fallback: Mutex::new(LoginFallbackState::default()),
            login_fallback_reconciling: AtomicBool::new(false),
            last_ts_exit_block: Mutex::new(None),
            ts_exit_recovering: AtomicBool::new(false),
            ts_exit_recover_pending: AtomicBool::new(false),
            dns_race,
            dns_controller: Mutex::new(polaris_system_integration::production_dns_controller(
                dns_marker_path,
            )),
            linux_resolved_controller: Mutex::new(linux_resolved_controller),
            network_watcher: Mutex::new(None),
            runtime_binding_state: Mutex::new(RuntimeBindingState::default()),
            #[cfg(test)]
            core_binary_override: Mutex::new(None),
            #[cfg(test)]
            management_api_stub: Mutex::new(None),
        }
    }

    /// 为显式 opt-in 的真核测试注入本次实例使用的二进制。
    ///
    /// 仅在 `cfg(test)` 下存在，且不会读取/修改进程级环境变量；普通单测仍保持
    /// [`Self::core_binary_for_start`] 的 deny-by-default 安全语义。跨模块的 stats 真核测试也经此
    /// 注入，避免为了测试恢复到会意外 spawn 本机真核的全局回落路径。
    #[cfg(test)]
    pub(crate) fn inject_real_core_for_test(&self, binary: PathBuf) {
        *self
            .core_binary_override
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(binary);
    }

    // ── 通用网络变化监听（watcher → DNS 门控重灌 + 出口恢复探测）──────────────────────────────
    //
    // 背景：TUN 接管系统 DNS 后，插拔坞站 / 切 WiFi / VPN 上下线会带出**新接口**并把系统解析器改回
    // 物理网卡的 DHCP DNS → DNS 逃逸绕过 TUN（劫持/污染重现）。故长驻 `route -n monitor` 监听链路变化，
    // 去抖后把「新出现 / 仍未受控」的服务重新接管为受控 IP（`reconcile_dns` 幂等，只补未受控项）。

    /// 接线 `event:proxyError` 发射器（`main.rs` setup 内调用一次，见 [`error_emitter`](Self::error_emitter) 字段文档）。
    ///
    /// 幂等：已接线则忽略重复接线（`OnceLock::set` 的 Err 腿）——重复接线是编程错误而非运行期状况，
    /// 记 warn 让它可见，但不 panic（不为一个诊断通道搭上 App 启动）。
    pub fn set_error_emitter(&self, emitter: Box<dyn ProxyErrorEmitter>) {
        if self.error_emitter.set(emitter).is_err() {
            log::warn!("proxy error emitter 重复接线 → 忽略（保留首次）");
        }
    }

    /// **§15**：主核测速探测池目标快照（`server_speed_test` 消费）——运行核的池端口 + id→tag 映射。
    ///
    /// 返回 `Some` ⟺ 核运行且起核时成功注入了探测池（`probe_pool_ports` 非空）；否则 `None`（测速回退活跃出口）。
    /// 与 `switch_snapshot` 同源（起核就绪置、停核清）→ 池端口与运行核 config 逐槽一致，`id_to_tag` 即
    /// `probe-selector-k` 的成员命名空间（`hasTag(id)` = `id ∈ id_to_tag` = 已入运行核池；新增未重启的节点不在其中）。
    pub fn speed_probe_targets(&self) -> Option<SpeedProbeTargets> {
        if !self.status().running {
            return None;
        }
        let snap = self.switch_snapshot.read().ok()?.clone()?;
        if snap.probe_pool_ports.is_empty() {
            return None;
        }
        Some(SpeedProbeTargets {
            pool_ports: snap.probe_pool_ports,
            id_to_tag: snap.id_to_tag,
            // dirty 波前预筛的唯一诚实判据（见字段文档）：起核那刻的 **5 维**指纹表，与 id_to_tag 同源同刻。
            // **必须是 dirty_fingerprints 而非 fingerprints** —— 后者是全维表（喂重启判据 + pending
            // modified），与测速「新」一侧的 5 维公式不同 ⇒ 恒不等 ⇒ 全员恒 dirty、整个波前恒被免测。
            fingerprints: snap.dirty_fingerprints,
        })
    }

    /// **临时测速核**的构建环境快照（platform / arch / cronet 可用性）。
    ///
    /// 三项与 [`generate_deps`](Self::generate_deps) 喂给主核 config 生成的**同名字段逐字同源**（同一个
    /// `platform_tag()` / `std::env::consts::ARCH` / `cronet_available(...)`）。抽这个只读面而不是让
    /// `runtime::speedtest` 自己再算一遍：三项里任一算法漂了，表现都是**静默**的 —— 临时核按另一套
    /// 平台/架构判定构出的出站与主核不同（如 macOS 的 cronet 静态编入判定漂了 ⇒ naive 节点被临时核
    /// 无谓剔掉、或反过来进核 FATAL 拖垮整批），而两边都「能跑」。
    #[must_use]
    pub fn core_build_env(&self) -> CoreBuildEnv {
        CoreBuildEnv {
            platform: platform_tag().to_string(),
            arch: std::env::consts::ARCH.to_string(),
            has_cronet: cronet_available(
                self.cronet_lib_exists_for_start(),
                platform_tag(),
                std::env::consts::ARCH,
            ),
        }
    }

    /// **§15**：把第 `k` 槽 `probe-selector-k` 热切到被测节点出站 `member_tag`（gRPC `select_outbound`，live 生效）。
    ///
    /// = 上游 `MainCoreProbe.selectSlot`。复用 [`hot_switch_selector`](Self::hot_switch_selector)（同 PUT 原语，
    /// 核未就绪 → false）。`interrupt_exist_connections:true` 由 config-engine 挂在 selector 上 → 同槽跨波重指前断残留、防串味。
    pub async fn probe_select_slot(&self, k: usize, member_tag: &str) -> bool {
        self.hot_switch_selector(&format!("probe-selector-{k}"), member_tag)
            .await
    }
}

#[cfg(test)]
mod tests;
