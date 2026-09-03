//! 托盘浮层窗的生命周期与运行期状态存取：锚点/去抖/开窗探针、冷建与预热排队、renderer-ready
//! 展示、统一收起、隐藏后延迟回收与末窗退出守卫。从 `tray.rs` 整段搬出（Phase 4A 批 B7）。
//!
//! 回指 façade 的只有 [`super::TrayOverlay`]（app-managed 状态 owner）与 [`super::TRAY_LABEL`]；
//! 平台相关腿（mac non-activating 宿主、原生聚焦、全局鼠标 monitor）在兄弟模块 `platform.rs`。

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use serde_json::Value;
use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindowBuilder, WindowEvent};

use super::lifecycle::{
    overlay_retention_action, rollback_owned_exit_guard, should_arm_last_webview_exit_guard,
    OverlayOpenAction, OverlayOpenProbe, OverlayRetentionAction,
};
#[cfg(target_os = "linux")]
use super::model::{native_dark, surface_color};
use super::placement::{
    default_tray_edge, overlay_placement, physical_tray_rect, reposition, tray_edge_boot_script,
    PhysicalRect,
};
use super::platform::focus_overlay;
#[cfg(target_os = "macos")]
use super::platform::{configure_nonactivating_overlay, remove_mouse_monitor};
use super::{TrayOverlay, TRAY_LABEL};

/// 浮层页面入口（vite 多入口产物；dev 态由 devUrl 提供 `/tray.html`）。
const TRAY_PAGE: &str = "tray.html";

/// 浮层「点击窗外即收起」的**替代 dismiss**（defect#3a）。
///
/// 根因：mac 上这个 frameless/辅助窗的 Rust 侧 `WindowEvent::Focused(false)` 递送不可靠（Tauri 已知
/// 类：次级窗口 Focused 事件在 macOS 偶发不触发）→ 只靠它则点窗外不收。DOM 层的 `window.blur` 由
/// WKWebView 在宿主 NSWindow resignKey 时可靠派发（与 `TrayMenu` 已依赖的 `focus` 事件对称）→ 作独立
/// 兜底：失焦即 invoke `tray_hide`（内含 `mark_hidden`，与图标点击去抖一致，不会闪关又弹回）。
///
/// 走 `initialization_script`（主进程注入，先于页面脚本、不受页面 CSP `script-src` 限制；与
/// `update_popup` 同款注入手法）——故**无需**改前端 TS。防御式取 `__TAURI_INTERNALS__.invoke`
/// （Tauri v2 注入的 IPC 桥；缺失即静默不动，非 Tauri 预览态不报错）。
const TRAY_BLUR_DISMISS_JS: &str = r#"
(function () {
  window.addEventListener('blur', function () {
    try {
      var i = window.__TAURI_INTERNALS__;
      if (i && typeof i.invoke === 'function') { i.invoke('tray_hide'); }
    } catch (e) {}
  });
})();
"#;

/// 浮层窗逻辑宽度（固定；高度由前端量内容后经 [`tray_resize`](super::commands::tray_resize) 自适应）。
/// 卡片 `.tray-menu` 宽 246 + 浮层 CSS 左右各 ~11 外边距（让圆角/1px 边框不贴窗沿被裁）≈ 268。
pub(super) const TRAY_WIDTH: f64 = 268.0;

/// Windows 11 普通托盘弹窗的**可见窗体**与任务栏工作区边界保留 12 逻辑像素。
/// 真机物理点击对照 OneDrive：其 UIA 窗体底边为 `rcWork.bottom - 12`。Polaris 透明宿主还有一段
/// 由高度上限留下的窗内透明尾部，不能把宿主外框的 4px 误当成可见卡片间距。
#[cfg(target_os = "windows")]
pub(super) const TRAY_EDGE_GAP_LOGICAL: f64 = 12.0;
#[cfg(not(target_os = "windows"))]
pub(super) const TRAY_EDGE_GAP_LOGICAL: f64 = 1.0;

/// Windows 的主视图卡片实测为约 688 逻辑像素高，底部任务栏形态还要加 12px 远侧 margin。
/// 700 上限让超长视图在卡片内滚；宿主的精确尺寸由 [`set_overlay_size`] 保证，不能再走 TAO
/// `set_inner_size`（透明无装饰窗会多出 20px，并被 ResizeObserver 正反馈放大到上限）。
#[cfg(target_os = "windows")]
pub(super) const TRAY_MAX_HEIGHT_LOGICAL: f64 = 700.0;
#[cfg(not(target_os = "windows"))]
pub(super) const TRAY_MAX_HEIGHT_LOGICAL: f64 = 720.0;

/// 浮层「刚被隐藏」的去抖窗口：托盘图标点击会先让浮层失焦（→ 自动隐藏），
/// 若紧接着的 Click 事件在此窗口内到达，视为「点击图标关闭」，不再重开（否则闪一下又弹回）。
const REOPEN_DEBOUNCE_MS: u128 = 300;

/// 用户关闭 `keepTrayMenuWarm` 后，托盘浮层隐藏至此时限才自动回收。
const TRAY_IDLE_RECLAIM_SECS: u64 = 120;

/// 应用级偏好键：true/缺失 = 日常隐藏后保持 WebView warm（默认）；false = 120s 后冷态回收。
const KEEP_TRAY_MENU_WARM_KEY: &str = "keepTrayMenuWarm";

/// 冷建后 renderer 最晚应回报 ready 的时间。超时不把空壳漏给用户，而是回收这次坏实例；下一次点击
/// 可重新创建。正常真机冷建约 237ms，这里留出数量级余量只兜白屏/IPC 断路，不参与日常体验时序。
const TRAY_READY_TIMEOUT_SECS: u64 = 5;

fn store_anchor(app: &AppHandle, rect: tauri::Rect) {
    let Some(rect) = physical_tray_rect(rect) else {
        return;
    };
    if let Some(state) = app.try_state::<TrayOverlay>() {
        if let Ok(mut guard) = state.anchor.lock() {
            *guard = Some(rect);
        }
    }
}

pub(super) fn anchor(app: &AppHandle) -> Option<PhysicalRect> {
    app.try_state::<TrayOverlay>()
        .and_then(|state| state.anchor.lock().ok().and_then(|g| *g))
}

fn mark_hidden(app: &AppHandle) {
    if let Some(state) = app.try_state::<TrayOverlay>() {
        if let Ok(mut guard) = state.last_hidden.lock() {
            *guard = Some(Instant::now());
        }
    }
}

fn recently_hidden(app: &AppHandle) -> bool {
    app.try_state::<TrayOverlay>()
        .and_then(|state| state.last_hidden.lock().ok().and_then(|g| *g))
        .is_some_and(|t| t.elapsed().as_millis() < REOPEN_DEBOUNCE_MS)
}

fn begin_open_probe(app: &AppHandle, cold: bool) {
    if let Some(state) = app.try_state::<TrayOverlay>() {
        if let Ok(mut probe) = state.open_probe.lock() {
            probe.get_or_insert(OverlayOpenProbe {
                started: Instant::now(),
                cold,
            });
        }
    }
}

fn clear_open_probe(app: &AppHandle) {
    if let Some(state) = app.try_state::<TrayOverlay>() {
        if let Ok(mut probe) = state.open_probe.lock() {
            *probe = None;
        }
    }
}

pub(super) fn log_open_probe(app: &AppHandle, stage: &str, take: bool) {
    let probe = app.try_state::<TrayOverlay>().and_then(|state| {
        state
            .open_probe
            .lock()
            .ok()
            .and_then(|mut probe| if take { probe.take() } else { *probe })
    });
    if let Some(probe) = probe {
        log::info!(
            "托盘浮层时延: stage={stage}, cold={}, elapsed_ms={}",
            probe.cold,
            probe.started.elapsed().as_millis()
        );
    }
}

/// 统一收起浮层：隐藏窗口 + 记隐藏时刻（去抖）+（mac）拆掉全局鼠标监听器。所有「收起」入口
/// （Focused(false) / 点图标 toggle / tray_hide / tray_show_main / tray_enter_lightweight / 全局 monitor
/// handler）都走此函数，保证 monitor 与浮层可见性同生命周期（show 装、任一 hide 拆），不泄漏。
pub(super) fn hide_overlay(app: &AppHandle) {
    let should_reclaim = app.get_webview_window(TRAY_LABEL).is_some_and(|w| {
        let was_visible = w.is_visible().unwrap_or(false);
        if was_visible {
            #[cfg(target_os = "macos")]
            let _ = w.eval("window.__POLARIS_NATIVE_HOVER__?.(-1, -1);");
            let _ = w.hide();
        }
        was_visible
    });
    // 冷建阶段的 Focused(false)/DOM blur 属于宿主装配噪声：窗口从未显示，不能据此取消首击请求，
    // 更不能写 last_hidden 让随后真正的托盘点击落入 300ms 去抖。只有可见→隐藏才是一次菜单 dismiss。
    if !should_reclaim {
        return;
    }
    if let Some(state) = app.try_state::<TrayOverlay>() {
        if let Ok(mut lifecycle) = state.lifecycle.lock() {
            lifecycle.hide();
        }
    }
    clear_open_probe(app);
    mark_hidden(app);
    #[cfg(target_os = "macos")]
    remove_mouse_monitor(app);
    if should_reclaim && !overlay_keeps_warm(app) {
        schedule_overlay_reclaim(app);
    }
}

/// 创建一代浮层窗。调用方保证它已跳出托盘点击分发帧；`generation` 同时注入 renderer，ready 回执
/// 必须携带同一代次才有资格上屏。**非致命**：失败返回 `None`，不自作主张唤出主窗。
fn build_overlay(app: &AppHandle, generation: u64) -> Option<tauri::WebviewWindow> {
    if let Some(win) = app.get_webview_window(TRAY_LABEL) {
        return Some(win); // 已建（幂等）
    }

    let initial_edge = overlay_placement(app, anchor(app))
        .map(|placement| placement.edge)
        .unwrap_or_else(default_tray_edge);
    let edge_script = tray_edge_boot_script(initial_edge);
    let initialization_script = format!(
        "window.__POLARIS_TRAY_GENERATION__ = {generation};\n{edge_script}\n{TRAY_BLUR_DISMISS_JS}"
    );
    let mut builder = WebviewWindowBuilder::new(app, TRAY_LABEL, WebviewUrl::App(TRAY_PAGE.into()))
        .title("Polaris")
        // DOM `blur` → tray_hide 的替代 dismiss（defect#3a，mac Rust 侧 Focused 递送不可靠时兜底）。
        .initialization_script(initialization_script)
        .inner_size(TRAY_WIDTH, 420.0)
        .resizable(false)
        .minimizable(false)
        .maximizable(false)
        .decorations(false)
        .always_on_top(true)
        .skip_taskbar(true)
        .visible(false);

    // non-activating 浮层会在 Polaris 不是前台 app 时接收用户的第一次点击。Wry 的 WKWebView 默认
    // `acceptsFirstMouse:` 为 false，因此这里复用 Tauri 开关把首击交给 WebView。注意：它只管“首击是否
    // click-through”，不负责 AppKit first responder；后者在 `configure_nonactivating_overlay` 改 style mask
    // 后按 Tao 自身的同一不变式恢复。仍不调用 `set_focus()`，因此不会顺带激活 Polaris 主窗。
    #[cfg(target_os = "macos")]
    {
        builder = builder.accept_first_mouse(true);
    }

    // mac/win：透明窗 + **关系统窗口阴影**。阴影沿的是**窗口矩形**（不是卡片圆角），透明窗上就成了卡片外
    // 那圈灰边/「波纹」——真机实拍确认，故恒关。无箭头「面板风」质感改由前端承担：卡片 1px 边框定边 +
    // 贴菜单栏 native 间隙（`tray-overlay.css`），**不再画 CSS box-shadow**（defect#2「不该有的阴影」——
    // 透明窗上的 CSS 阴影会被 body overflow:hidden 裁成硬边=「截断」观感，一并去掉）。
    // 且此处**不设 background_color**：它会给 webview 铺一层实底，压掉 transparent。
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        builder = builder.transparent(true).shadow(false);
    }
    // Linux 恒不透明（透明窗在无合成器/部分 WM 下=黑块或穿透）：卡片 surface 同色实底兜底。
    // 底色按 `config.uiTheme` 折算（B）——此前硬编码深色 surface，浅色用户每次弹浮层都先闪一格深色底
    // （浮层 WebView 在 120s 保温期内复用、show 即上屏，webview 重绘在其后）。运行期改主题由
    // [`toggle_overlay`] 的 `set_background_color` 跟进（同一代窗口不重建，建窗时这一次只管首次）。
    #[cfg(target_os = "linux")]
    {
        builder = builder
            .transparent(false)
            .background_color(surface_color(native_dark(app)));
    }

    let win = match builder.build() {
        Ok(w) => w,
        Err(e) => {
            log::warn!("托盘浮层窗创建失败（主窗仍可从 Dock/任务栏唤出）：{e}");
            return None;
        }
    };

    #[cfg(target_os = "macos")]
    if let Err(e) = configure_nonactivating_overlay(&win) {
        log::warn!("托盘浮层 non-activating 宿主配置失败，本代窗口不展示：{e}");
        if let Err(destroy_err) = destroy_overlay_preserving_tray_residency(app, &win) {
            log::warn!("托盘浮层宿主配置失败后的回收也失败：{destroy_err}");
        }
        return None;
    }

    // 失焦即收起（点窗外 / 切到别的 app）：菜单语义。走 hide_overlay 统一拆 mac 全局监听器（defect#3）。
    // （W13 的明暗信号源不挂这里：本窗限时存活——轻量转场与 120s 空闲回收都会销毁它；
    // Win 直读注册表真值、Linux 留窗口探测链，均见 main.rs 的 system_dark_bg。）
    let app_handle = app.clone();
    win.on_window_event(move |event| {
        if let WindowEvent::Focused(false) = event {
            hide_overlay(&app_handle);
        }
    });
    Some(win)
}

/// 把冷建排到托盘点击回调返回之后：W18 已证实 WebView 建/销不能跑在 OS 消息分发栈内；同一纪律
/// 适用于托盘 `Click` 回调。renderer 未 ready 前窗口保持 hidden，避免空壳和加载期 blur 竞态。
fn queue_overlay_build(app: &AppHandle, generation: u64) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let callback_app = app.clone();
        let _ = app.run_on_main_thread(move || {
            let still_current = callback_app
                .try_state::<TrayOverlay>()
                .is_some_and(|state| {
                    state.lifecycle.lock().ok().is_some_and(|lifecycle| {
                        lifecycle.generation == generation && lifecycle.build_queued
                    })
                });
            if !still_current {
                return;
            }

            let win = build_overlay(&callback_app, generation);
            if let Some(state) = callback_app.try_state::<TrayOverlay>() {
                if let Ok(mut lifecycle) = state.lifecycle.lock() {
                    lifecycle.build_finished(generation, win.is_some());
                }
            }
            if win.is_none() {
                clear_open_probe(&callback_app);
                return;
            }
            schedule_overlay_ready_timeout(&callback_app, generation);
        });
    });
}

fn schedule_overlay_ready_timeout(app: &AppHandle, generation: u64) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_secs(TRAY_READY_TIMEOUT_SECS)).await;
        let callback_app = app.clone();
        let _ = app.run_on_main_thread(move || {
            let timed_out = callback_app
                .try_state::<TrayOverlay>()
                .is_some_and(|state| {
                    state.lifecycle.lock().ok().is_some_and(|lifecycle| {
                        lifecycle.generation == generation && !lifecycle.renderer_ready
                    })
                });
            if timed_out {
                log::warn!(
                    "托盘浮层 renderer 在 {TRAY_READY_TIMEOUT_SECS}s 内未就绪，回收本代 WebView"
                );
                destroy_overlay(&callback_app);
            }
        });
    });
}

pub(super) fn show_ready_overlay(app: &AppHandle, win: &tauri::WebviewWindow) {
    invalidate_overlay_reclaim(app);
    #[cfg(target_os = "linux")]
    {
        let _ = win.set_background_color(Some(surface_color(native_dark(app))));
    }
    reposition(win);
    if let Err(e) = win.show() {
        log::warn!("托盘浮层显示失败：{e}");
        return;
    }
    reposition(win);
    focus_overlay(win);
    log_open_probe(app, "shown", true);
}

/// macOS/Windows 托盘左/右键入口（由 `main.rs` 的 `on_tray_icon_event` 调）。
///
/// 可见 → 隐藏（toggle off）；不可见 → 定位到托盘所在屏角 + 显示 + 聚焦。
/// 浮层创建失败 → 本次点击 no-op；不把「托盘菜单」意图突然放大成主窗。
pub fn toggle_overlay(app: &AppHandle, rect: Option<tauri::Rect>) {
    // 事件 rect 自身就是物理像素，不依赖浮层窗是否已建、当前落在哪块屏。先存锚点，冷建与热开共用；
    // 即便本次点击是关闭，下次打开也从最新托盘位置起步。
    if let Some(rect) = rect {
        store_anchor(app, rect);
    }
    let existing = app.get_webview_window(TRAY_LABEL);
    if existing
        .as_ref()
        .is_some_and(|win| win.is_visible().unwrap_or(false))
    {
        hide_overlay(app);
        return;
    }
    // 刚因本次点击导致失焦隐藏（<300ms）→ 视为「点击图标关闭」，不重开。
    if recently_hidden(app) {
        return;
    }
    let action = app.try_state::<TrayOverlay>().and_then(|state| {
        state
            .lifecycle
            .lock()
            .ok()
            .map(|mut lifecycle| lifecycle.request_open(existing.is_some()))
    });
    let Some(action) = action else {
        return;
    };
    begin_open_probe(app, !matches!(action, OverlayOpenAction::ShowNow));
    invalidate_overlay_reclaim(app);
    match action {
        OverlayOpenAction::ShowNow => {
            if let Some(win) = existing {
                show_ready_overlay(app, &win);
            }
        }
        OverlayOpenAction::AwaitReady => {}
        OverlayOpenAction::QueueBuild { generation } => {
            queue_overlay_build(app, generation);
        }
    }
}

/// 使所有已排队的隐藏回收任务失效。Relaxed 足够：代次只承担去重，不承载其他内存可见性。
fn invalidate_overlay_reclaim(app: &AppHandle) -> u64 {
    app.try_state::<TrayOverlay>()
        .map(|state| state.reclaim_generation.fetch_add(1, Ordering::Relaxed) + 1)
        .unwrap_or(0)
}

/// 当前托盘浮层是否按用户偏好保持 warm。状态尚未 manage 时回落出厂默认 true。
fn overlay_keeps_warm(app: &AppHandle) -> bool {
    app.try_state::<TrayOverlay>()
        .is_none_or(|state| state.keep_warm.load(Ordering::Relaxed))
}

/// warm 开启时在托盘就绪后后台预建隐藏 renderer。复用冷开同一套代次、主线程建窗和 ready 超时机制；
/// 唯一差异是 `show_requested=false`，所以预热完成不会抢焦点或露出窗口。
pub(crate) fn prewarm_overlay_if_enabled(app: &AppHandle) {
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = app;
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        if !overlay_keeps_warm(app) || app.tray_by_id("main").is_none() {
            return;
        }
        let window_exists = app.get_webview_window(TRAY_LABEL).is_some();
        let generation = app.try_state::<TrayOverlay>().and_then(|state| {
            state
                .lifecycle
                .lock()
                .ok()
                .and_then(|mut lifecycle| lifecycle.request_prewarm(window_exists))
        });
        if let Some(generation) = generation {
            log::debug!("托盘浮层 warm 开启：后台预建隐藏 renderer（generation={generation}）");
            queue_overlay_build(app, generation);
        }
    }
}

/// 从 ConfigManager 的原始配置缓存同步 `keepTrayMenuWarm`，并即时兑现开关变化。
///
/// 复用 `event:configChanged` 的 Rust 监听，不新增 IPC/第二份持久化状态。调用点只有启动初始化与配置变更
/// 事件；不能挂进 30s 托盘自愈轮询，否则 warm=false 时会不断重排计时器、WebView 永不回收。
pub(crate) fn reconcile_overlay_retention(app: &AppHandle) {
    let next = app
        .try_state::<crate::runtime::AppRuntime>()
        .and_then(|rt| {
            rt.config()
                .with_current(|cfg| {
                    cfg.get(KEEP_TRAY_MENU_WARM_KEY)
                        .and_then(Value::as_bool)
                        .unwrap_or(true)
                })
                .ok()
        })
        .unwrap_or(true);
    let Some(state) = app.try_state::<TrayOverlay>() else {
        return;
    };
    let previous = state.keep_warm.swap(next, Ordering::Relaxed);
    let overlay_hidden = app
        .get_webview_window(TRAY_LABEL)
        .is_some_and(|win| !win.is_visible().unwrap_or(false));
    // 用户可能恰在启动预热的建窗窗口内关掉 warm：此刻 WebView 尚不存在，但 120s 回收任务仍须挂上，
    // 否则 build 随后完成后会成为永不回收的隐藏 renderer。
    let overlay_building = state
        .lifecycle
        .lock()
        .ok()
        .is_some_and(|lifecycle| lifecycle.build_queued);
    match overlay_retention_action(previous, next, overlay_hidden || overlay_building) {
        OverlayRetentionAction::None => {}
        OverlayRetentionAction::CancelReclaim => {
            invalidate_overlay_reclaim(app);
            log::debug!("托盘浮层保持 warm：已取消隐藏回收任务");
        }
        OverlayRetentionAction::ScheduleReclaim => {
            schedule_overlay_reclaim(app);
            log::debug!("托盘浮层关闭 warm：已恢复隐藏回收任务");
        }
    }
    if next {
        prewarm_overlay_if_enabled(app);
    }
}

/// 隐藏后延迟回收托盘 WebView。任务到点后回主线程复核「代次未变化 + 仍隐藏」才销毁；期间任何
/// reopen/hide/destroy 都会换代，因此不会出现旧计时器把刚打开的菜单关掉。
fn schedule_overlay_reclaim(app: &AppHandle) {
    let generation = invalidate_overlay_reclaim(app);
    if generation == 0 {
        return;
    }
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_secs(TRAY_IDLE_RECLAIM_SECS)).await;
        let callback_app = app.clone();
        let _ = app.run_on_main_thread(move || {
            let is_current = callback_app
                .try_state::<TrayOverlay>()
                .is_some_and(|state| {
                    state.reclaim_generation.load(Ordering::Relaxed) == generation
                });
            if !is_current {
                return;
            }
            // 配置事件正常会使 generation 失效；这里再读一次运行期镜像，兜事件递送失败/竞态，
            // 绝不在用户已开启 warm 后销毁浮层。
            if overlay_keeps_warm(&callback_app) {
                return;
            }
            let Some(win) = callback_app.get_webview_window(TRAY_LABEL) else {
                return;
            };
            if win.is_visible().unwrap_or(false) {
                return;
            }
            if destroy_overlay(&callback_app) {
                log::debug!("托盘浮层隐藏超时，已回收 WebView");
            }
        });
    });
}

/// 销毁托盘浮层前，若它已是**最后一个原生窗口**且托盘仍在，则武装一次 C16 退出守卫。
///
/// Tauri 会把末窗 `destroy()` 折成一次 `RunEvent::ExitRequested`。主窗已进入轻量态后，托盘浮层的
/// 2 分钟空闲回收正好会成为「销毁末窗」：若只在主窗销毁前武装 [`crate::LightweightState`]，那次守卫
/// 早已被消费，浮层回收便会把整个应用（连同托盘/代理）一起退出。这里把**每一次有意的末窗回收**都接到
/// 同一条一次性守卫上；显式退出仍先置 `QuitState`，不会被它拦住。
///
/// Polaris 的窗口宿主全部由 `WebviewWindowBuilder` 创建，故按 `webview_windows()` 计数；若还有主窗、更新
/// 提示或仪表盘，本次销毁不会触发退出，提前置位会留下陈旧守卫，可能误拦后续 OS 退出。
fn destroy_overlay_preserving_tray_residency(
    app: &AppHandle,
    win: &tauri::WebviewWindow,
) -> tauri::Result<()> {
    let armed = should_arm_last_webview_exit_guard(
        app.webview_windows().len(),
        app.tray_by_id("main").is_some(),
    ) && app
        .state::<crate::LightweightState>()
        .0
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok();

    let result = win.destroy();
    // destroy 失败不会产生 ExitRequested；只撤销本函数亲自置的那一位，不能误清别的轻量转场。
    rollback_owned_exit_guard(
        &app.state::<crate::LightweightState>().0,
        result.is_err(),
        armed,
    );
    result
}

/// 立即销毁浮层。仅 renderer-ready 超时与关闭 warm 后的隐藏超时调用；主窗口轻量转场不得调用，
/// 否则 `keepTrayMenuWarm=true` 会被另一个无关开关静默覆盖。
fn destroy_overlay(app: &AppHandle) -> bool {
    invalidate_overlay_reclaim(app);
    #[cfg(target_os = "macos")]
    remove_mouse_monitor(app);
    let destroyed = if let Some(win) = app.get_webview_window(TRAY_LABEL) {
        match destroy_overlay_preserving_tray_residency(app, &win) {
            Ok(()) => true,
            Err(e) => {
                log::warn!("托盘浮层 WebView 提前回收失败：{e}");
                false
            }
        }
    } else {
        true
    };
    if destroyed {
        if let Some(state) = app.try_state::<TrayOverlay>() {
            if let Ok(mut lifecycle) = state.lifecycle.lock() {
                lifecycle.reset();
            }
        }
        clear_open_probe(app);
    }
    destroyed
}
