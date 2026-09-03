//! polaris-system-integration — 系统接管层（§B.2 / §H B4）。
//!
//! 1:1 移植自 上游 `src/main/services/`：
//! - [`exec`]：命令执行缝（`trait CommandRunner` + 生产 `StdCommandRunner`）—— 命令型 OS 交互的单一入口。
//! - [`proxy`]：系统代理状态 + ProxyMarker（marker 崩溃恢复，维度7 #8 纯逻辑）+ stripSelf / restorePlan。
//! - [`proxy_ops`]：`trait SystemProxyOps`（三平台代理设置/清除）+ 接管/释放状态机 + 命令构造。
//! - [`bypass`]：Windows ProxyOverride 串构造（`format_bypass_for_windows`，H2 补）。
//! - [`dns`]：系统 DNS marker + 纯解析/防自指计算（`SystemDns` 共享逻辑）。
//! - [`dns_ops`]：`trait SystemDnsOps`（三平台 DNS 设置/恢复）+ setDns/restoreDns/reconcileDns 编排。
//! - [`dns_watcher`]：DNS 接口热插拔 watcher（纯逻辑，事件源 trait 注入）+ `should_reconcile_dns`。
//! - [`dns_route_events`]：macOS `route -n monitor` 输出行判定（纯函数）。
//! - [`dns_flush`]：OS DNS 缓存刷新命令构造（三平台）。
//!
//! ## 移植纪律
//!
//! 1. **平台操作 trait 抽象**：系统命令走 `trait`（`SystemProxyOps` / `SystemDnsOps` / `FlushExec`），
//!    命令回退按运行时 `Platform` 分派并可在 Linux mock 三平台。唯一例外是 macOS 系统代理的
//!    SystemConfiguration 原生事务：编译期隔离在 `macos_proxy`，生产构造才启用，测试指定 Mac 仍走 mock。
//! 2. **marker 纯逻辑**：marker 写/读/崩溃恢复判定是纯逻辑，FS 经 `trait MarkerFs` 注入。
//! 3. **维度7 #8 必须可测**：崩溃后 marker 残留 → 重启清除（mock FS + 状态机）。
//! 4. 默认 `deny(unsafe_code)`；仅 `macos_proxy` 的具体 ABI item 局部放开，每个调用写明安全依据。
//! 5. 命令构造（argv / registry 行 / gsettings 元组）与输出解析全是纯函数，跨平台可单测。
//!
//! ## 平台真差异 / 假差异分界（接线时的判据）
//!
//! | | 真差异（**保留隔离**：各平台一份） | 假差异（**共用**） |
//! |---|---|---|
//! | 代理 | `reg.exe`+`netsh` / `networksetup` / `gsettings` 三套工具与 argv；三套输出格式的解析 | `Command`/`CommandRunner` 执行缝、`SystemProxyStatus` 类型、marker 生命周期、`strip_self` 防自指、控制器状态机、`ensure_cleared` 终态收口 |
//! | DNS | mac `networksetup`+`scutil`；Linux 经 root helper 写 `systemd-resolved` per-link；Windows 写路径 no-op | marker 生命周期、reconcile 幂等判定 |
//! | flush | `dscacheutil`(+mac helper root 通道) / `ipconfig` / `resolvectl` | best-effort「永不抛」编排、3s 硬超时 |
//!
//! 见 `~/docs/polaris/design/polaris-system-design.md` §B.2（crate 边界）+ §H B4（验收门）。

#![deny(unsafe_code)]

pub mod bypass;
pub mod dns;
pub mod dns_flush;
pub mod dns_ops;
pub mod dns_route_events;
pub mod dns_watcher;
pub mod error;
pub mod exec;
pub mod linux_resolved;
#[cfg(target_os = "macos")]
mod macos_proxy;
pub mod proxy;
pub mod proxy_ops;
pub mod route_ops;
#[cfg(test)]
mod test_support;

pub use exec::{Command, CommandOutput, CommandRunner, StdCommandRunner};
pub use proxy::{StdMarkerFs, SystemProxyStatus};

// ── 生产装配（调用方一行拿到接好线的控制器）──

/// 生产系统代理控制器类型（本机平台 + 真实命令执行 + 真实 FS marker）。
pub type ProdProxyController =
    proxy_ops::SystemProxyController<proxy_ops::SystemProxyOpsImpl<StdCommandRunner>, StdMarkerFs>;

/// 生产系统 DNS 控制器类型。
pub type ProdDnsController =
    dns_ops::SystemDnsController<dns_ops::SystemDnsOpsImpl<StdCommandRunner>, StdMarkerFs>;

/// 生产路由出口探测类型（本机平台 + 真实命令执行）。无 marker/状态 → 直接是 ops 本身。
pub type ProdRouteOps = route_ops::SystemRouteOpsImpl<StdCommandRunner>;

/// 装配生产路由出口探测器（TUN 出口夺取 post-flight 判定用；见 [`route_ops`]）。
pub fn production_route_ops() -> ProdRouteOps {
    route_ops::SystemRouteOpsImpl::new(StdCommandRunner)
}

/// marker 文件名（上游 `SystemProxyBase.getMarkerPath`：`userData/system-proxy.marker.json`）。
pub const PROXY_MARKER_FILENAME: &str = "system-proxy.marker.json";

/// 系统 DNS marker 文件名（上游 `SystemDnsBase`）。
pub const DNS_MARKER_FILENAME: &str = "system-dns.marker.json";

/// Linux `systemd-resolved` per-link 接管 marker 文件名。
pub const LINUX_RESOLVED_MARKER_FILENAME: &str = "linux-resolved.marker.json";

/// 装配生产系统代理控制器。`marker_path` 建议 `<userData>/system-proxy.marker.json`
/// （见 [`PROXY_MARKER_FILENAME`]）。
///
/// 调用方须知（**这两条不在本 crate 内，必须由调用方落实**）：
/// - **`stopping` 守卫**：`ensure_cleared` 只在**非主动停止/重启**语境调用，否则会清掉紧随的
///   start 要设的代理（上游 C1 竞态）。lifecycle 状态属调用方。
/// - **async 语境**：本控制器是同步的（内部 `std::process::Command`），在 async 里须 `spawn_blocking`。
pub fn production_proxy_controller(marker_path: impl Into<String>) -> ProdProxyController {
    proxy_ops::SystemProxyController::new(
        proxy_ops::SystemProxyOpsImpl::new(StdCommandRunner),
        proxy::ProxyMarker::new(StdMarkerFs, marker_path),
    )
}

/// Windows 生产装配：系统代理三值经 App crate 的原生 HKCU 窄 writer 一次完成；旧 QUIC 规则已由
/// App setup 提前预热时，enable 热路径不再重复执行 `netsh`。未走此入口的库调用方保持原回退行为。
pub fn production_proxy_controller_with_windows_writer(
    marker_path: impl Into<String>,
    writer: std::sync::Arc<dyn proxy_ops::WindowsProxyRegistryWriter>,
    quic_cleanup_prewarmed: bool,
) -> ProdProxyController {
    proxy_ops::SystemProxyController::new(
        proxy_ops::SystemProxyOpsImpl::new(StdCommandRunner)
            .with_windows_registry_writer(writer, quic_cleanup_prewarmed),
        proxy::ProxyMarker::new(StdMarkerFs, marker_path),
    )
}

/// macOS 生产装配：只读快照仍由 App 内原生 SystemConfiguration 完成，写事务经已安装的
/// root helper 执行；helper 明确未安装/不支持时由 ops 安全回落 networksetup。
pub fn production_proxy_controller_with_macos_writer(
    marker_path: impl Into<String>,
    writer: std::sync::Arc<dyn proxy_ops::MacProxyTransactionWriter>,
) -> ProdProxyController {
    proxy_ops::SystemProxyController::new(
        proxy_ops::SystemProxyOpsImpl::new(StdCommandRunner).with_macos_writer(writer),
        proxy::ProxyMarker::new(StdMarkerFs, marker_path),
    )
}

/// root helper 的窄执行入口。payload 由本 crate 生成并在这里重新校验；helper-proto 只负责
/// 鉴权后的不透明传输，不获得任意 SystemConfiguration 写能力。
#[cfg(target_os = "macos")]
pub fn execute_macos_proxy_transaction(payload_hex: &str) -> Result<(), String> {
    macos_proxy::execute_transaction(payload_hex)
}

/// **活态查询**：当前 OS 代理是否仍指向本进程的 mixed 入站（`address:mixed_port`）。
///
/// 无状态、无 marker、**只读不写** —— 故不经 [`ProdProxyController`]（那条持有接管状态机与 marker），
/// 直接现造一次性 ops。语义与三平台读取面见
/// [`SystemProxyOpsImpl::live_status`](proxy_ops::SystemProxyOpsImpl::live_status)。
///
/// **同步**（内部 exec `networksetup`/`gsettings`/`reg`）：async 语境须 `spawn_blocking`。
/// 读失败返回 `Err`（**不折成「未生效」**）——读不到 ≠ 没生效，见 `read_active_proxy` 文档。
pub fn production_system_proxy_live_status(
    address: &str,
    mixed_port: u16,
) -> Result<proxy_ops::SystemProxyLiveStatus, error::SystemIntegrationError> {
    proxy_ops::SystemProxyOpsImpl::new(StdCommandRunner).live_status(address, mixed_port)
}

/// 装配生产系统 DNS 控制器。`marker_path` 建议 `<userData>/system-dns.marker.json`。
///
/// 注：该控制器承接 macOS（Windows 自动 no-op）；Linux 使用独立的 [`linux_resolved`] 控制器，因为
/// per-link revert 与“保存物理网卡原始 DNS”是两种不同恢复语义。
pub fn production_dns_controller(marker_path: impl Into<String>) -> ProdDnsController {
    dns_ops::SystemDnsController::new(
        dns_ops::SystemDnsOpsImpl::new(StdCommandRunner),
        dns_ops::DnsMarker::new(StdMarkerFs, marker_path),
    )
}

/// 刷 OS DNS 缓存（生产入口）：本机平台 + 真实执行器，best-effort 永不抛。
///
/// `helper_flush` 为 mac root helper 通道（`None` = 不可用 → 走用户级 `dscacheutil` 降级）。
pub fn production_flush_os_dns_cache(
    helper_flush: dns_flush::HelperFlushFn,
    on_warn: &mut dyn FnMut(&str),
) -> bool {
    dns_flush::flush_os_dns_cache(
        polaris_helper_proto::Platform::current(),
        &StdCommandRunner,
        helper_flush,
        on_warn,
    )
}

#[cfg(test)]
mod tests;
