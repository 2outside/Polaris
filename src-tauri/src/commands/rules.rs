//! 路由规则 command 的领域入口。
//!
//! IPC 函数名仍由本模块重导出，因而 Tauri 注册、前端 channel、序列化和错误信封保持不变。
//! 实现按规则 CRUD、规则资源与图标图库分属各自 owner；共享依赖只留在这里，避免三份漂移。

mod crud;
pub(crate) mod icons;
mod resources;

pub use crud::{app_presets_list, rules_add, rules_delete, rules_reorder, rules_update};
pub use icons::{rule_resources_icon_galleries, rule_resources_refresh_icon_galleries};
pub(crate) use resources::{
    remove_builtin_rule_resource_files, remove_rule_resource_file,
    rule_resource_file_is_referenced, rule_resources_redownload_silent,
    rule_resources_update_builtin_silent,
};
pub use resources::{
    rule_resources_cancel, rule_resources_delete, rule_resources_download,
    rule_resources_get_cached_catalog, rule_resources_get_catalog, rule_resources_list,
    rule_resources_redownload, rule_resources_refresh_catalog, rule_resources_reset_builtin,
    rule_resources_update_all, rule_resources_update_builtin,
};

/// 规则与资源都需要的本地 id；保持原有时间戳格式和碰撞规避语义。
pub(super) fn new_uuid() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("pol-{nanos:032x}")
}
