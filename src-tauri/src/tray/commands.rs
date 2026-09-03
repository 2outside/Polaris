//! 托盘浮层的 IPC 命令壳：8 个 `#[tauri::command]`（尺寸回报 / renderer-ready 回执 / 收起 /
//! 显示主窗 / 取货待导航屏 / 检查更新 / 退出 / 进入轻量模式）+ 它们的纯函数与状态存取辅助。
//! 从 `tray.rs` 整段搬出（Phase 4A 批 B8）。
//!
//! **只做壳，不持有事务**：`tray_enter_lightweight` 只把转场排回主线程事件循环帧外，转场本体
//! 由兄弟模块 `transition.rs` 独家持有（设计 SoT §A.4 T5：「转场只由一个 owner 持有」）。
//!
//! `main.rs` 的 `generate_handler![tray::tray_*]` 按**路径**取 `tray::__cmd__*` /
//! `tray::__tauri_command_name_*` 两个包装宏（`tauri-macros` 的 `Handler::parse` 只替换路径末段），
//! 故 façade 必须整体 `pub use commands::*;` 把它们一并再导出——invoke_handler 里的路径因此零改动。

use std::sync::atomic::Ordering;

use serde_json::Value;
use tauri::{AppHandle, Manager};

use crate::i18n::{app_lang, key, t};
use crate::response::{ok_void, ApiResponse};

use super::model::normalize_tray_screen;
use super::placement::{overlay_placement, reposition, set_overlay_size};
use super::transition::enter_lightweight_transition;
use super::window::{
    anchor, hide_overlay, log_open_probe, show_ready_overlay, TRAY_MAX_HEIGHT_LOGICAL, TRAY_WIDTH,
};
use super::{TrayOverlay, TRAY_LABEL};

/// 浮层量出内容高度后回报 → 设窗高（宽固定 [`TRAY_WIDTH`]）并重定位（自适应高）。
#[tauri::command]
pub fn tray_resize(app: AppHandle, height: f64) -> ApiResponse<()> {
    if let Some(win) = app.get_webview_window(TRAY_LABEL) {
        let h = height.clamp(80.0, TRAY_MAX_HEIGHT_LOGICAL);
        let scale_factor = overlay_placement(&app, anchor(&app))
            .map(|placement| placement.scale_factor)
            .or_else(|| win.scale_factor().ok())
            .unwrap_or(1.0);
        if let Err(e) = set_overlay_size(&win, TRAY_WIDTH, h, scale_factor) {
            log::warn!("托盘浮层尺寸设置失败：{e}");
        }
        reposition(&win);
    }
    ok_void()
}

/// 托盘 renderer 完成 React commit 后的代次化 ready 回执。冷建窗口在此之前始终 hidden；命令声明为
/// async，使兑现腿不在 WebKit IPC 分发栈内直接 show，而是排回下一轮主线程事件循环。
#[tauri::command]
pub async fn tray_renderer_ready(app: AppHandle, generation: u64) -> ApiResponse<()> {
    let should_show = app.try_state::<TrayOverlay>().is_some_and(|state| {
        state
            .lifecycle
            .lock()
            .ok()
            .is_some_and(|mut lifecycle| lifecycle.mark_ready(generation))
    });
    if !should_show {
        return ok_void();
    }
    log_open_probe(&app, "renderer-ready", false);
    let callback_app = app.clone();
    let _ = app.run_on_main_thread(move || {
        let still_requested = callback_app
            .try_state::<TrayOverlay>()
            .is_some_and(|state| {
                state
                    .lifecycle
                    .lock()
                    .ok()
                    .is_some_and(|lifecycle| lifecycle.should_show(generation))
            });
        if !still_requested {
            return;
        }
        if let Some(win) = callback_app.get_webview_window(TRAY_LABEL) {
            show_ready_overlay(&callback_app, &win);
        }
    });
    ok_void()
}

/// 收起浮层（连接/断开/切节点等动作后关闭菜单）。
#[tauri::command]
pub fn tray_hide(app: AppHandle) -> ApiResponse<()> {
    hide_overlay(&app);
    ok_void()
}

/// 显示主窗（「打开主窗口」/「在主窗口管理」/「打开设置」）并收起浮层。复用 `crate::show_main_window`
/// （与托盘图标点击 / 菜单「显示」/ dock 重开同一路径）。
///
/// `screen`：可选目标屏，经 [`normalize_tray_screen`] 白名单归一。**不传 = 今天的行为逐字节不变**
/// （既有 `invoke('tray_show_main')` 无参调用点零改动，Tauri 对 `Option<_>` 形参把缺失键解析成 `None`）。
/// 通道选型理由见 [`normalize_tray_screen`] 上方注释。
///
/// # 三条投递腿，**互补而非互斥**
///
/// 意图的目的地是「主窗的 nav-store」，而它可能处在三种状态，每种只有一条腿够得着：
///
/// 1. **窗在、订阅已挂**（常态）→ 事件腿：`emit_to_main(EVENT_TRAY_OPEN_SCREEN)`，即到即导航。
/// 2. **窗已销毁**（C16 轻量模式）→ 首帧种子腿：`create_main_window` 建窗时把
///    [`TrayOverlay::pending_screen`] 注入 `initialization_script`（`window.__POLARIS_TRAY_SCREEN__`），
///    前端 boot 时同步读一次。事件腿在这里必丢（emit 发生在 webview 装载之前）。
/// 3. **窗在、但 webview 还没挂上订阅**（冷启动/重载后的那一小段）→ **两条都够不着**：
///    种子腿只在建窗那一刻注入（窗已经建好了，不会再注入一次），事件腿 emit 出去没人听 ⇒
///    intent **静默丢失**（窗开了、屏没跳）。这正是 2026-07-28 复审标 NEEDS-REPRO 的那条竞态。
///
/// 修法：**pending 恒写**（不再只在 `!main_alive` 时写），并给前端一条主动取货的通道
/// [`tray_take_pending_screen`]：nav-store 装配时取一发。于是第 3 种状态由「前端就绪后自己来取」覆盖。
///
/// 陈旧意图怎么防：`pending` 是 **take 一次即清**，且事件腿命中的那一路，前端在 `applyTrayScreenIntent`
/// 之后**也会调一次取货**把它清掉（"消费后清"）——不清的话，下次因任何别的原因重建主窗都会被送去设置页。
#[tauri::command]
pub fn tray_show_main(app: AppHandle, screen: Option<String>) -> ApiResponse<()> {
    let target = screen.as_deref().and_then(normalize_tray_screen);
    // 必须在 `show_main_window` **之前**问：它会把销毁的主窗重建出来，之后就分不出是哪条腿了。
    let main_alive = app.get_webview_window("main").is_some();
    let legs = tray_show_main_legs(target.is_some(), main_alive);
    if let Some(t) = target {
        if legs.write_pending {
            set_pending_screen(&app, t);
        }
    }
    hide_overlay(&app);
    crate::show_main_window(&app);
    if let (Some(t), true) = (target, legs.emit_event) {
        crate::events::emit_to_main(&app, crate::events::channel::EVENT_TRAY_OPEN_SCREEN, t);
    }
    ok_void()
}

/// [`tray_show_main`] 该点亮哪几条投递腿。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TrayShowMainLegs {
    /// 写 [`TrayOverlay::pending_screen`]（供首帧种子腿注入 / 前端 [`tray_take_pending_screen`] 取货）。
    pub write_pending: bool,
    /// 单播 `EVENT_TRAY_OPEN_SCREEN`（只有主窗已存在时才有意义）。
    pub emit_event: bool,
}

/// 折出投递腿（纯函数，可单测）。
///
/// **`write_pending` 恒真**（只要有目标屏）—— 这正是 2026-07-28 复审那条竞态的修法。
/// 此前是 `if !main_alive { set_pending_screen(...) }`：两条腿互斥 ⇒ 「主窗存在但 webview 还没挂上
/// `EVENT_TRAY_OPEN_SCREEN` 订阅」这一格里，事件腿 emit 出去没人听、种子腿又因为窗已存在而根本没写
/// ⇒ intent 静默丢失（窗开了、屏没跳）。恒写之后这一格由前端的取货腿兜住。
///
/// 陈旧意图由「take 一次即清 + 前端事件腿命中后也调一次取货」防住，不靠这里少写。
#[must_use]
pub fn tray_show_main_legs(has_target: bool, main_alive: bool) -> TrayShowMainLegs {
    TrayShowMainLegs {
        write_pending: has_target,
        emit_event: has_target && main_alive,
    }
}

/// 记下「主窗要跳到哪一屏」（见 [`tray_show_main`] 的三条腿）。
fn set_pending_screen(app: &AppHandle, screen: &'static str) {
    if let Some(state) = app.try_state::<TrayOverlay>() {
        if let Ok(mut g) = state.pending_screen.lock() {
            *g = Some(screen);
        }
    }
}

/// **取走**待导航目标屏（一次性；`create_main_window` 建窗时调）。
///
/// take 语义是刚需：留着的话，用户下次因任何别的原因重建主窗（轻量模式再进再出）都会被送去设置页 ——
/// 一条陈旧意图变成反复发作的跳屏。
pub fn take_pending_screen(app: &AppHandle) -> Option<&'static str> {
    app.try_state::<TrayOverlay>()
        .and_then(|s| s.pending_screen.lock().ok().and_then(|mut g| g.take()))
}

/// 前端主动取货口 —— [`tray_show_main`] 第 3 条腿（窗在、订阅还没挂）的收货端，兼「消费后清」。
///
/// 主窗 nav-store 装配时调一次：
///  - 有值（事件腿丢了 / 冷启动期间点的托盘）→ 前端据此导航，竞态被补上；
///  - 无值（常态）→ 返回 `None`，零成本。
/// 事件腿命中之后前端**也调一次**，把 `tray_show_main` 恒写下的那份余量清掉，避免它以陈旧意图的
/// 形式活到下一次建窗。
///
/// 返回的是 [`normalize_tray_screen`] 白名单里的 `'static` 串，值域与另两条腿逐字相同。
#[tauri::command]
pub fn tray_take_pending_screen(app: AppHandle) -> ApiResponse<Option<&'static str>> {
    ApiResponse::ok(take_pending_screen(&app))
}

/// 主窗首帧「托盘目标屏」种子脚本（与 [`theme_boot_script`](super::model::theme_boot_script) 同款注入手法）。
///
/// 值域已由 [`normalize_tray_screen`] 钉死为白名单里的 `'static` 串 ⇒ 这里拼进 JS 字面量不存在注入面
/// （不是前端传什么就拼什么）。
#[must_use]
pub fn tray_screen_boot_script(screen: &str) -> String {
    format!("window.__POLARIS_TRAY_SCREEN__ = '{screen}';\n")
}

/// 「检查更新」（A1）：托盘浮层与**原生兜底菜单**共用的唯一实现。
///
/// 返回 `true` = 有更新且提醒窗已弹出；`false` = 已是最新。失败返 `Err`（**绝不**把失败伪装成
/// 「已是最新」——那是 B5 反伪造里点名的形态，后端 `update_check` 自己也是这个语义）。
///
/// # 为什么这条链落在 Rust 而不是浮层的 JS 里
///
/// 弹提醒窗要的是 `update_popup_show(version, currentVersion)`，其中 `currentVersion` 的真值是
/// `app.package_info().version` —— 在主进程手里。放前端就得先绕一趟 `version_get_info` 再拼参数，
/// 平白多一条可能与 `startup_tasks` 那条链读出不同值的路径。
///
/// 链本身与 `startup_tasks::spawn_update_check` 逐段相同（check → hasUpdate → version → popup），
/// 含「`hasUpdate:true` 却缺 version = 后端契约破损，宁可不弹也不弹个空版本号」这条边界。
/// 预发布口径从 `config.appUpdateChannel` 读取，并随本次提醒写进弹窗会话；用户点“更新”时按
/// 会话里记录的口径复查，不受期间配置变化影响。
///
/// 错误串随 [`crate::i18n::app_lang`] 分档（浮层把它原样显示在 notice 行、原生菜单腿把它发进
/// 系统通知）—— 2026-07-31 前先是硬编码中文、后是 zh/en 二态，俄语 / 波斯语 / 繁中用户拿到的
/// 都不是自己的语言。
#[tauri::command]
pub async fn tray_check_update(app: AppHandle) -> ApiResponse<bool> {
    let lang = app_lang(&app);
    let state = app.state::<crate::runtime::AppRuntime>();
    let include_prerelease = state
        .config()
        .load_full()
        .map(|config| crate::commands::updater::app_update_channel_is_prerelease(&config))
        .unwrap_or(false);
    let resp =
        match crate::commands::update_check(app.clone(), state, Some(include_prerelease), None)
            .await
        {
            Ok(r) => r,
            Err(()) => return ApiResponse::err(t(lang, key::TRAY_UPDATE_CHECK_FAILED)),
        };
    if !resp.success {
        return ApiResponse::err(
            resp.error
                .unwrap_or_else(|| t(lang, key::TRAY_UPDATE_CHECK_FAILED)),
        );
    }
    let data = resp.data.unwrap_or(Value::Null);
    if data.get("hasUpdate").and_then(Value::as_bool) != Some(true) {
        return ApiResponse::ok(false);
    }
    let Some(version) = data
        .pointer("/updateInfo/version")
        .and_then(Value::as_str)
        .map(str::to_string)
    else {
        log::warn!("托盘检查更新：hasUpdate 为真但缺 updateInfo.version，跳过弹窗");
        return ApiResponse::err(t(lang, key::NATIVE_UPDATE_INFO_INCOMPLETE));
    };
    let current = app.package_info().version.to_string();
    let r = crate::commands::update_popup_show(
        app.clone(),
        app.state::<crate::runtime::AppRuntime>(),
        version,
        current,
        Some(include_prerelease),
    );
    if r.success {
        ApiResponse::ok(true)
    } else {
        ApiResponse::err(
            r.error
                .unwrap_or_else(|| t(lang, key::NATIVE_UPDATE_POPUP_FAILED)),
        )
    }
}

/// 退出 Polaris：置 `QuitState`（放行 `CloseRequested`，不被 close-to-tray 卡）+ `app.exit(0)`。
/// 与 `main.rs` 托盘原生菜单「退出」/ 应用菜单 ⌘Q 逐字节相同的退出路径。
#[tauri::command]
pub fn tray_quit(app: AppHandle) -> ApiResponse<()> {
    app.state::<crate::QuitState>()
        .0
        .store(true, Ordering::SeqCst);
    app.exit(0);
    ok_void()
}

/// C16 进入轻量模式（command 壳）：**只做排队，不做转场**。
///
/// W18/F1（评审，2026-08-20）：本命令经托盘浮层按钮 invoke。**同步** command 由 tauri-macros 的
/// Blocking 路生成，在 WebView2 `WebResourceRequested` 分发栈（主线程）内直跑——若帧内执行转场，
/// 销毁的恰是**正在处理这条 IPC 的浮层自身**（deferral 未 Complete）+ 主窗，与 W18 真机证实的
/// CloseRequested 帧内销毁死锁同构。`async fn` command 被 tauri spawn 到 tokio worker（帧外，
/// tokio worker 恒非主线程），再经 `run_on_main_thread` 排回主线程**事件循环帧外**执行转场本体
/// （注意：`run_on_main_thread` 从主线程调用是内联直执——async command 保证了调用点不在主线程）。
#[tauri::command]
pub async fn tray_enter_lightweight(app: AppHandle) -> ApiResponse<()> {
    let h = app.clone();
    let h2 = h.clone();
    if let Err(e) = h.run_on_main_thread(move || enter_lightweight_transition(h2)) {
        log::warn!("轻量转场排队失败（事件循环已关闭？主窗/浮层保持原状，托盘唤出可用）：{e}");
    }
    ok_void()
}
