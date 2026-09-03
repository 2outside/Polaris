//! 进程级真实退出生命周期。
//!
//! 此模块拥有轻量驻留的退出豁免、一次性退出门、正常退出标记与停核清理。
//! `main` 仅在 Tauri `RunEvent` 装配处执行返回的动作，避免这些相互依赖的
//! 退出不变量散落在 bootstrap 里。

use std::sync::atomic::{AtomicBool, Ordering};

use tauri::Manager;

use crate::runtime::AppRuntime;
use crate::startup::{LightweightState, QuitState, RestartState};

pub(crate) struct ExitCleanupState(pub(crate) AtomicBool);

/// `ExitRequested` 的唯一分流：轻量驻留继续运行，或进入真实退出收尾。
pub(crate) enum ExitRequestedAction {
    PreserveLightweight,
    Exit,
}

/// C1 / C16：按轻量驻留状态与显式退出意图决定是否允许进程退出。
///
/// `LightweightState` 必须用 `swap(false, ...)` 消费，避免一次轻量转场的陈旧置位
/// 阻断后续真实退出；显式退出已先置 `QuitState`，因此始终落到清理腿。
pub(crate) fn exit_requested_action(app: &tauri::AppHandle) -> ExitRequestedAction {
    let lightweight = app
        .state::<LightweightState>()
        .0
        .swap(false, Ordering::SeqCst);
    let quitting = app.state::<QuitState>().0.load(Ordering::SeqCst);
    if lightweight && !quitting && app.tray_by_id("main").is_some() {
        ExitRequestedAction::PreserveLightweight
    } else {
        ExitRequestedAction::Exit
    }
}

/// C1 退出清理：任何真实退出都**阻塞**跑
/// [`ProxyRuntime::stop`](crate::runtime::proxy::ProxyRuntime::stop)（停核 + 清系统代理，marker 门控幂等）。
///
/// **为什么安全关键**：`systemProxy` 模式 start 成功后会把 OS 系统代理指向本地 mixedPort（A1）。若退出不清，
/// 系统代理仍指向刚被杀的死端口 → 用户全网断连、需手动改回。这与 start 失败腿 / 主动 stop 的清理同一
/// marker 门控收口点（`ProxyRuntime::clear_system_proxy`），不误清用户自配的第三方代理。
///
/// **覆盖面与兜底**：正常退出（含 OS 关机/logout 若经窗口关闭）走这里。**崩溃 / 强杀 / panic 不经此路径**
/// → 靠启动期 [`recover_system_proxy_on_startup`](crate::runtime::proxy::ProxyRuntime::recover_system_proxy_on_startup)
/// 在下次启动清残留 marker。**刻意不加清系统代理的 panic hook**：本仓 `panic=unwind`，任一后台 tokio task
/// 的 panic 都会触发进程级 hook，会误清一个仍在服务的活代理 → 见 review-queue `DESIGN-REVIEW(c1-panic-hook)`。
///
/// `block_on` 在 RunEvent 回调（主线程、非 tokio worker）内安全；退出路径慢一点可接受，但绝不能带着
/// 死端口系统代理离开。
fn run_exit_cleanup(app: &tauri::AppHandle) {
    // 在飞的**测速临时核**先收：它不在 `ProxyRuntime` 的任何生命周期槽里（刻意隔离），`proxy.stop()`
    // 碰不到它；而测速在飞时退出，那条 tokio task 不会被 drop ⇒ child 的 Drop 守卫也够不着 ⇒ 留下
    // 持有 N 个回环端口 + WG peer 会话的孤儿 sing-box（Windows 无 stale sweep，永不被清）。
    // 不依赖 `AppRuntime`（进程级 pid 表），故放在 try_state 早退之前。
    let killed = crate::runtime::speedtest::kill_inflight_temp_cores();
    if killed > 0 {
        log::warn!("退出清理：强杀了 {killed} 个在飞测速临时核");
    }
    let Some(rt) = app.try_state::<AppRuntime>() else {
        return; // 运行时未装配（极早期退出）→ 无可清。
    };
    let proxy = rt.proxy.clone();
    tauri::async_runtime::block_on(async move {
        if let Err(e) = proxy.stop().await {
            log::error!("退出清理：停核失败（不阻断退出）: {e}");
        }
    });
}

/// 真实退出的统一汇流点：正常退出标记先落，再阻塞停核/清系统代理；`ExitRequested` 与最终 `Exit`
/// 可能连续到达，故由 [`ExitCleanupState`] 保证整段只跑一次。
pub(crate) fn run_real_exit_once(app: &tauri::AppHandle) {
    if app
        .state::<ExitCleanupState>()
        .0
        .swap(true, Ordering::SeqCst)
    {
        return;
    }
    mark_clean_exit(app);
    run_exit_cleanup(app);
}

/// Q1-b ④：正常退出腿落标记（目录 = `<userData>/`，与 `system-proxy.marker.json` 同处）。
///
/// 目录取自 `AppRuntime`（唯一持有 config dir 的地方）。运行时未装配 = 极早期退出，
/// 那时任何 webview 都还没起、不可能有 staged ⇒ 无标记可落，直接跳过。
///
/// `RestartState` 置位（`app:restart` 发起）⇒ **不落标记**：那不是「用户结束了这次使用」，
/// 而是用户几秒内就回来的一次重启，清掉 staged = 吃掉用户的工作。判定腿在
/// [`clean_exit::mark_unless_restarting`](crate::clean_exit::mark_unless_restarting)（有单测），本函数只负责把那个 bit 取出来喂给它。
/// `try_state` 而非 `state`：极早期退出时 `RestartState` 还没 manage，`state` 会 panic 在退出路径上。
fn mark_clean_exit(app: &tauri::AppHandle) {
    let restarting = app
        .try_state::<RestartState>()
        .is_some_and(|s| s.0.swap(false, Ordering::SeqCst));
    if let Some(rt) = app.try_state::<AppRuntime>() {
        crate::clean_exit::mark_unless_restarting(rt.config.dir(), restarting);
    }
}

#[cfg(test)]
mod tests;
