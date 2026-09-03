//! 系统代理平台操作抽象 + 接管/释放状态机。
//!
//! 1:1 移植自 上游 `SystemProxyManager.ts` 三平台实现：
//! - [`SystemProxyOps`] trait：读状态 / 设代理 / 清代理 / 恢复原始 / 同步清（紧急退出）。
//! - 三平台命令回退全平台可测；macOS 生产写路径经独立 SystemConfiguration 原生事务模块。
//! - 命令构造（argv / registry 行 / gsettings 元组）抽为纯函数，跨平台可单测（`#[cfg(test)]` mock ops）。
//! - [`SystemProxyController`]：编排 enable/disable + 完整 marker 先于系统修改/成功清 + 防自指 + 失败兜底回滚 +
//!   **维度7 #8 marker 崩溃恢复**（`recover_from_marker`）。
//!
//! ## 状态机（对齐 Polaris）
//!
//! ```text
//! enable:  captureOriginal(stripSelf) → persistMarker(snapshot) → ops.set → 成功 / 失败兜底 disable
//! disable: ops.restore(original) | ops.clear → 成功 clearMarker；失败保留 marker
//! 启动:    recover_from_marker → restore(snapshot) | clear → 成功 clearMarker；失败保留 marker
//! ```

#![forbid(unsafe_code)]

use std::time::Duration;

mod controller;
mod linux;
mod live_status;
mod macos_cli;
mod model;
mod ops;
mod retry;
mod windows;

pub use controller::SystemProxyController;
pub use linux::{
    linux_disable_command, linux_enable_commands, linux_gsettings_get_command,
    linux_gsettings_mode_get_command, linux_restore_schema_commands, linux_set_mode_manual_command,
    parse_gsettings_host, parse_gsettings_mode, parse_gsettings_port,
};
pub use macos_cli::{
    mac_default_route_command, mac_list_manageable_services, mac_list_service_order_command,
    mac_list_services_command, mac_read_proxy_command, mac_service_disable_commands,
    mac_service_enable_commands, mac_service_restore_commands, parse_mac_bypass_domains,
    parse_mac_network_services, parse_mac_service_order, parse_mac_service_proxy,
    MAC_BYPASS_EMPTY_SENTINEL, MAC_BYPASS_READ_SUB, MAC_PROXY_READ_SUBS,
};
pub use model::{
    points_to_mixed_inbound, MacProxyTransactionWriter, MacProxyWriterError, ProxyEnableRequest,
    SystemProxyLiveStatus, WindowsProxyRegistryValues, WindowsProxyRegistryWriter,
    WindowsProxyWriterError,
};
#[cfg(target_os = "macos")]
pub(crate) use ops::mac_snapshot_relation;
pub use ops::{ProxySnapshotRelation, SystemProxyOps, SystemProxyOpsImpl};
#[allow(unused_imports)]
pub(crate) use retry::PERMISSION_DENIED_NEEDLES;
pub(crate) use retry::{is_permission_denied, retry_op, RetryConfig};
pub use windows::{
    parse_win_proxy_enable, parse_win_proxy_server, start_windows_quic_cleanup_prewarm,
    windows_clear_quic_command, windows_disable_commands, windows_enable_commands,
    windows_enable_values, windows_query_command, windows_quic_cleanup_prewarmed,
    windows_restore_commands, WIN_REG_PATH,
};

/// 单条系统代理命令硬超时。上游用 `execFileAsync` 默认无超时，但挂起的 `networksetup`/`gsettings`
/// 会把同步的接管流程钉死 → 统一给 10s 上限（远宽于这些命令的正常耗时，仅防挂起）。
pub const PROXY_EXEC_TIMEOUT: Duration = Duration::from_secs(10);

// `Command` 的单一真值在 `exec`（此前 proxy_ops::Command 与 dns_flush::FlushCommand 是两份逐字相同的
// `{program, args}` —— 典型假差异，已合并）。此处重导出保持既有路径可用。
pub use crate::exec::Command;

#[cfg(test)]
mod tests;
