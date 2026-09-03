//! C16 轻量转场的**唯一 owner**：销毁主窗 webview 释放内存、保托盘与核活，以 destroy 成功为
//! 事务提交点。从 `tray.rs` 整段搬出（Phase 4A 批 B8）。
//!
//! 与 command 壳（`commands.rs`）分家的理由 = 设计 SoT §A.4 T5：三个入口（托盘浮层按钮的排回腿、
//! 窗口驻留巡检的 idle 腿、`CloseRequested` 的延后腿）共用同一段四步事务，其顺序被 3 条 Rust 守卫
//! 与 1 条 TS 守卫按方法体切片钉死，必须整段留在一处。

use std::sync::atomic::Ordering;

use tauri::{AppHandle, Manager};

use super::lifecycle::{rollback_owned_exit_guard, should_arm_last_webview_exit_guard};
use super::window::hide_overlay;

/// 轻量转场本体：**销毁主窗 webview 释放内存，保托盘 + 核活**（≠ 关窗到托盘的 `hide()`——那只隐藏、
/// renderer 进程仍活=内存未释放）。三个入口共用：托盘浮层「进入轻量模式」command（排回腿）+
/// 主进程窗口驻留巡检（idle 腿）+ `CloseRequested` 的轻量分流（延后腿）。
/// 对齐 上游 `releaseWindowMemory` + `markLightweightModeTransition`。
///
/// **调用契约**：主线程、且不在任何窗口/WebView2 事件回调分发栈内（close 消息栈 / IPC
/// WebResourceRequested 栈都不行——帧内销毁 = W18 死锁形态）。三个调用点各自负责跳帧后
/// 再调本函数；本函数自身不再排队（主线程内再 `run_on_main_thread` 是内联直执，排了个寂寞）。
///
/// 顺序（以 destroy 成功为事务提交点）：
///  1. 只收起浮层；是否常驻完全由 `keepTrayMenuWarm` 决定，主窗口轻量态不得替它做主。
///  2. 先把主窗生命周期标成“销毁中”，再在**最后一个 WebView**时 CAS 武装 `LightweightState`，最后
///     `destroy()`（**force**：绕过 `CloseRequested` 的拦截）。ExitRequested 守卫只在可能实际退出时置位，
///     不给浮层常驻/其它窗口留下陈旧状态。这道
///     显式状态挡住 Tauri registry 过渡期仍返回的失效 WebView，stats/logs 不再跨线程探测旧句柄。
///  3. destroy 成功才提交 main 的 stats + logs 订阅清理；失败则只回滚本调用者武装的
///     LightweightState，并回滚生命周期，保留
///     原页面订阅。webview 销毁不触发 `on_page_load`，成功后不清账会让 gRPC/log emitter 永续工作。
///
/// 用户经托盘浮层内明确入口、Linux 原生菜单或 Dock/任务栏唤出时，`show_main_window` 走
/// `create_main_window` 重建。
pub(crate) fn enter_lightweight_transition(app: AppHandle) {
    hide_overlay(&app);
    if let Some(rt) = app.try_state::<crate::runtime::AppRuntime>() {
        rt.stats().mark_main_window_destroying();
    }
    if let Some(win) = app.get_webview_window("main") {
        // 只有销毁最后一个 WebView 才可能触发 ExitRequested；浮层仍在或还有其它窗口时置位会留下
        // 陈旧守卫。CAS 成功才归本调用者所有，失败回滚也只能撤销自己亲手武装的那一位。
        let armed = should_arm_last_webview_exit_guard(
            app.webview_windows().len(),
            app.tray_by_id("main").is_some(),
        ) && app
            .state::<crate::LightweightState>()
            .0
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok();
        let result = win.destroy();
        rollback_owned_exit_guard(
            &app.state::<crate::LightweightState>().0,
            result.is_err(),
            armed,
        );
        match result {
            Ok(()) => {
                if let Some(rt) = app.try_state::<crate::runtime::AppRuntime>() {
                    rt.stats().clear_window("main");
                }
                crate::commands::misc::clear_log_stream_window("main");
                crate::set_macos_dock_visible(&app, false);
            }
            Err(e) => {
                if let Some(rt) = app.try_state::<crate::runtime::AppRuntime>() {
                    rt.stats().mark_main_window_created();
                    rt.stats().refresh_window_visible(&app);
                }
                log::warn!("轻量模式销毁主窗失败（已回滚窗口与订阅状态；托盘/核不受影响）：{e}");
            }
        }
    } else {
        // 窗已被另一条腿释放：把这次操作视为幂等成功，并兜底清掉按 label 持有的旧订阅账。
        if let Some(rt) = app.try_state::<crate::runtime::AppRuntime>() {
            rt.stats().clear_window("main");
        }
        crate::commands::misc::clear_log_stream_window("main");
        crate::set_macos_dock_visible(&app, false);
    }
}
