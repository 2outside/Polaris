//! 杂项 command 的领域入口。
//!
//! Tauri command 仍从本模块导出，保持既有 IPC 注册、序列化和错误语义；实现分别归日志、dashboard、
//! 备份、autostart 与出口 IP/recovery owner。

mod autostart;
mod backup;
mod dashboard;
mod ipinfo;
mod logs;
mod support;

pub use autostart::{auto_start_get_status, auto_start_set};
pub use backup::{backup_export, backup_get_info, backup_import_apply, backup_import_pick};
pub use dashboard::{
    get_singbox_dashboard_connection, open_singbox_dashboard, refresh_singbox_dashboard,
};
pub use ipinfo::ipinfo_get;
pub use ipinfo::IPINFO_SETTLE_DELAY_MS;
pub(crate) use ipinfo::{
    ipinfo_probe_is_current, mark_ipinfo_proxy_blocked, schedule_ipinfo_refresh,
    schedule_network_recovery_refresh,
};
pub(crate) use logs::clear_log_stream_window;
pub use logs::{
    diagnostic_export, logs_archive_legacy, logs_clear, logs_delete_legacy, logs_diagnostic_state,
    logs_export, logs_get, logs_legacy_info, logs_open_dir, logs_runtime_level, logs_search,
    logs_set_diagnostic, logs_unsubscribe, shell_open_external,
};
