//! Application bootstrap state and pure startup/window policy helpers.

use std::sync::atomic::AtomicBool;
#[cfg(not(target_os = "macos"))]
use std::sync::atomic::Ordering;

use tauri::Manager;

use crate::runtime::AppRuntime;

pub(crate) struct QuitState(pub(crate) AtomicBool);
pub(crate) struct LightweightState(pub(crate) AtomicBool);
pub(crate) struct RestartState(pub(crate) AtomicBool);

#[derive(Clone, Copy, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartupConfigFlags {
    pub hardware_acceleration: bool,
    pub window_effects: bool,
    pub remember_window_size: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum StartupAction {
    Version,
    Help,
    HeadlessExit,
    Run { hidden: bool },
}

pub(crate) fn resolve_startup(args: &[String], has_display: bool) -> StartupAction {
    let has = |flags: &[&str]| args.iter().any(|a| flags.contains(&a.as_str()));
    if has(&["-V", "--version"]) {
        return StartupAction::Version;
    }
    if has(&["-h", "--help"]) {
        return StartupAction::Help;
    }
    if !has_display {
        return StartupAction::HeadlessExit;
    }
    StartupAction::Run {
        hidden: has(&["--hidden"]),
    }
}

pub(crate) fn cli_help_text() -> String {
    format!(
        "Polaris {}\n\nUsage: polaris [options]\n  -V, --version   Show version and exit\n  -h, --help      Show this help and exit\n  --hidden        Start hidden to the system tray\n",
        env!("CARGO_PKG_VERSION")
    )
}

pub(crate) fn config_silent_start(raw: Option<&str>) -> bool {
    raw.and_then(|t| serde_json::from_str::<serde_json::Value>(t).ok())
        .and_then(|v| v.get("silentStart").and_then(serde_json::Value::as_bool))
        .unwrap_or(false)
}

pub(crate) fn config_remember_window_size(raw: Option<&str>) -> bool {
    raw.and_then(|t| serde_json::from_str::<serde_json::Value>(t).ok())
        .and_then(|v| {
            v.get("rememberWindowSize")
                .and_then(serde_json::Value::as_bool)
        })
        .unwrap_or(true)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn commit_maximized_observation(state: &AtomicBool, current: bool) -> bool {
    state.swap(current, Ordering::SeqCst) != current
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CloseAction {
    AllowClose,
    EnterLightweight,
    QuitApp,
}

pub(crate) fn resolve_close_action(
    quitting: bool,
    tray_present: bool,
    minimize_to_tray: bool,
) -> CloseAction {
    if quitting {
        return CloseAction::AllowClose;
    }
    if minimize_to_tray && tray_present {
        return CloseAction::EnterLightweight;
    }
    CloseAction::QuitApp
}

pub(crate) fn config_minimize_to_tray(app: &tauri::AppHandle) -> bool {
    app.try_state::<AppRuntime>()
        .and_then(|rt| rt.config().load_full().ok())
        .and_then(|v| v.get("minimizeToTray").and_then(serde_json::Value::as_bool))
        .unwrap_or(true)
}

pub(crate) fn refresh_stats_visibility(app: &tauri::AppHandle) {
    if let Some(rt) = app.try_state::<AppRuntime>() {
        rt.stats().refresh_window_visible(app);
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn set_macos_dock_visible(app: &tauri::AppHandle, visible: bool) {
    if let Err(e) = app.set_dock_visibility(visible) {
        log::warn!("macOS Dock 图标显隐切换失败（visible={visible}，非致命）：{e}");
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn set_macos_dock_visible(_app: &tauri::AppHandle, _visible: bool) {}

#[cfg(test)]
mod tests;
