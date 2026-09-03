use crate::response::{ok_void, ApiResponse};
use crate::runtime::AppRuntime;
use tauri::{AppHandle, Manager, State};

#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn auto_start_set(
    app: AppHandle,
    _state: State<'_, AppRuntime>,
    enabled: bool,
) -> ApiResponse<()> {
    let autostart = app.state::<tauri_plugin_autostart::AutoLaunchManager>();
    let res = if enabled {
        autostart.enable()
    } else {
        autostart.disable()
    };
    match res {
        Ok(()) => ok_void(),
        Err(e) => ApiResponse::err(format!("{e}")),
    }
}

/// 上游 `AUTO_START_GET_STATUS`：自启状态。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn auto_start_get_status(app: AppHandle) -> ApiResponse<bool> {
    let autostart = app.state::<tauri_plugin_autostart::AutoLaunchManager>();
    ApiResponse::ok(autostart.is_enabled().unwrap_or(false))
}
