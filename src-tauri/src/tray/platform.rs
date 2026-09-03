//! 托盘的平台专属腿：macOS 的 non-activating 浮层宿主配置、绕开 app 激活的原生聚焦、全局鼠标
//! monitor 与非激活 hover 桥接，以及菜单栏位置持久化（`NSStatusItem.autosaveName`，#313b）。
//! 从 `tray.rs` 整段搬出（Phase 4A 批 B7）。
//!
//! **同一谓词的两条 cfg 腿必须留在本文件内且 macOS 腿在前**：守卫 `top_level_fn_body` 取首个命中
//! 且不校验唯一性（设计 SoT §A.4 T11），顺序颠倒会让它切到非 mac 腿——那条腿的正向对照
//! `makeKeyAndOrderFront(None)` 随之落空并转红，不会静默。

use tauri::AppHandle;
#[cfg(target_os = "macos")]
use tauri::Manager;

#[cfg(target_os = "macos")]
use super::window::hide_overlay;
#[cfg(target_os = "macos")]
use super::{TrayOverlay, TRAY_LABEL};

/// 把 Tauri 创建的 borderless NSWindow 切成 AppKit 的 non-activating panel 语义。
///
/// 无需另建/重挂 WKWebView：`NSWindowStyleMaskNonactivatingPanel` 可在宿主创建后补入。macOS 26.6.2
/// 真机探针验证了“先 borderless 建窗、再 setStyleMask”这一精确序列：首个按钮点击可交互，同时前台
/// app 保持不变。若配置失败，本代窗口宁可不展示，也不退回会抢焦点的旧语义。
#[cfg(target_os = "macos")]
pub(super) fn configure_nonactivating_overlay(win: &tauri::WebviewWindow) -> Result<(), String> {
    use objc2_app_kit::NSWindowStyleMask;

    let raw_window = win.ns_window().map_err(|e| e.to_string())?;
    if raw_window.is_null() {
        return Err("NSWindow handle is null".to_string());
    }
    // SAFETY: Tauri 的 `ns_window()` 返回该 WebviewWindow 持有、且当前主线程有效的 NSWindow 指针；
    // 本函数只在 build() 紧接着的主线程调用，不越过窗口生命周期保存引用。
    let ns_window = unsafe { &*raw_window.cast::<objc2_app_kit::NSWindow>() };
    ns_window.setStyleMask(ns_window.styleMask() | NSWindowStyleMask::NonactivatingPanel);

    // Wry 0.55.1 的非 child WebView 层级固定为：
    //   NSWindow.contentView = WryWebViewParent；parent.subviews[0] = WryWebView(WKWebView)。
    // `win.ns_view()` 只会拿到前者。把 parent 设成 first responder 会覆盖 Wry 构建时对真实
    // WKWebView 的设置，真机表现正是「第一下只激活浮层、第二下按钮才执行」。style mask 修改后须同步
    // 恢复**实际 WebView**，而不是照搬 Tao 针对纯窗口的 content-view 恢复逻辑。
    let content_view = ns_window
        .contentView()
        .ok_or_else(|| "tray NSWindow content view is missing".to_string())?;
    let webview = content_view
        .subviews()
        .firstObject()
        .ok_or_else(|| "tray WKWebView is missing from content view".to_string())?;
    if !ns_window.makeFirstResponder(Some(&webview)) {
        return Err("tray WKWebView rejected first responder".to_string());
    }
    Ok(())
}

/// 让 non-activating 浮层取得键盘焦点，但不激活整个 Polaris app。
///
/// Tauri/tao 的 macOS `set_focus()` 在 `makeKeyAndOrderFront:` 后还会无条件调用
/// `activateIgnoringOtherApps:YES`，正是 W25 的抢焦点源。这里绕开那层封装，直接调用原生方法；
/// 全局鼠标 monitor 继续负责窗外收起，无需在 hide 时猜测并恢复旧 app（那会与用户点击第三个 app 竞态）。
#[cfg(target_os = "macos")]
pub(super) fn focus_overlay(win: &tauri::WebviewWindow) {
    use objc2_app_kit::NSWindow;

    if let Ok(raw) = win.ns_window() {
        if !raw.is_null() {
            // SAFETY: 与 configure_nonactivating_overlay 同一宿主指针；本函数由主线程 show 路径调用，
            // 引用不逃逸。直接调原生方法是为了绕开 tao `set_focus()` 内附带的 app activation。
            let ns_window = unsafe { &*raw.cast::<NSWindow>() };
            ns_window.makeKeyAndOrderFront(None);
        }
    }
    // show 后装全局点击监听器：点其它菜单栏状态项 / 桌面 / 别的窗即收起浮层（defect#3）。
    install_mouse_monitor(win.app_handle());
}

/// 非 mac：仅聚焦（Win/Linux 辅助窗 `Focused(false)` 递送与 mac borderless-key 坑无关）。
#[cfg(not(target_os = "macos"))]
pub(super) fn focus_overlay(win: &tauri::WebviewWindow) {
    let _ = win.set_focus();
}

/// 把全局指针位置桥接到非激活的托盘 WebView（W32）。
///
/// WebKit 在 app/宿主窗都非激活时不会向页面派发 `mousemove`，所以 `accept_first_mouse` 能让首击直达，
/// CSS `:hover` 却仍没有背景反馈。这里复用托盘窗口与既有 global monitor：把 AppKit 屏幕坐标换成
/// WebView 的 client 坐标后交给页面做 `elementFromPoint`。只传有限数值，不拼用户数据/文案；窗口隐藏即拆
/// monitor，因此不会成为常驻采样。真实 DOM mousemove 恢复后，前端会主动清掉桥接 class、回归原生 :hover。
#[cfg(target_os = "macos")]
fn forward_native_hover(app: &AppHandle) {
    use objc2_app_kit::{NSEvent, NSWindow};

    let Some(win) = app.get_webview_window(TRAY_LABEL) else {
        return;
    };
    if !win.is_visible().unwrap_or(false) {
        return; // hide→removeMonitor 排回主线程的短窗口内，也不得给 warm WebView 重新挂陈旧 hover。
    }
    let Ok(raw) = win.ns_window() else {
        return;
    };
    if raw.is_null() {
        return;
    }
    // SAFETY: 指针是该 Tauri window 的 NSWindow 宿主；global monitor handler 在 AppKit 主线程派发，
    // 引用只活到本函数返回。borderless 窗的 contentView 坐标原点在左下，Web client 原点在左上。
    let (client_x, client_y) = unsafe {
        let ns_window = &*raw.cast::<NSWindow>();
        let point = ns_window.convertPointFromScreen(NSEvent::mouseLocation());
        let Some(content_view) = ns_window.contentView() else {
            return;
        };
        (point.x, content_view.bounds().size.height - point.y)
    };
    if !client_x.is_finite() || !client_y.is_finite() {
        return;
    }
    let _ = win.eval(format!(
        "window.__POLARIS_NATIVE_HOVER__?.({client_x:.2}, {client_y:.2});"
    ));
}

/// 装全局鼠标监听器（defect#3：点**另一个菜单栏状态项**不收起；W32：非前台 hover 不丢）。
///
/// # 根因
/// borderless/辅助浮层在 mac 上，点另一个菜单栏状态项是**系统状态栏**的点击、不切本 app 的 active 态 →
/// 浮层宿主 NSWindow 不 resignKey → `WindowEvent::Focused(false)` 与 DOM `blur` 都不触发 → 浮层赖着不走。
/// non-activating 宿主的 `Focused(false)`/DOM blur 兜的是键窗迁移，兜不住所有状态栏宿主事件。
///
/// # 修法（Apple 文档的状态栏 popover 标准式）
/// show 时装 `NSEvent addGlobalMonitorForEventsMatchingMask:handler:`（MouseMoved + 三类 MouseDown）——
/// **本 app 之外**任意点击都派发（含点另一状态项、点桌面、点别的窗），handler 里 [`hide_overlay`] 收起。
/// MouseMoved 只走 [`forward_native_hover`]，绝不误收起；global monitor 观察到的正是 WebKit 丢弃的非激活腿。
/// 全局 monitor 只观察不吞事件（不影响被点目标），主线程派发。与 `Focused(false)` 互补并存（切 app 仍
/// 走那条）。hide 时 [`remove_mouse_monitor`] 拆掉。
///
/// ⚠️ 本机（Linux）编不到、验不了（objc2 NSEvent 首次编译在 mac，H-5）→ 真机（mac）待行为确认。
#[cfg(target_os = "macos")]
fn install_mouse_monitor(app: &AppHandle) {
    use block2::RcBlock;
    use core::ptr::NonNull;
    use objc2::rc::Retained;
    use objc2_app_kit::{NSEvent, NSEventMask, NSEventType};

    let Some(state) = app.try_state::<TrayOverlay>() else {
        return;
    };
    let Ok(mut guard) = state.mouse_monitor.lock() else {
        return;
    };
    if guard.is_some() {
        return; // 幂等：已装不重复装（避免多个 monitor 泄漏 / 多次收起）
    }
    let app_handle = app.clone();
    // handler 在主线程派发（AppKit 全局 monitor 契约）：移动只补 hover，点击本 app 外才收起。
    let handler: RcBlock<dyn Fn(NonNull<NSEvent>)> =
        RcBlock::new(move |event: NonNull<NSEvent>| {
            // SAFETY: AppKit 保证 handler 调用期间 event 有效；引用不逃逸本次回调。
            if unsafe { event.as_ref() }.r#type() == NSEventType::MouseMoved {
                forward_native_hover(&app_handle);
            } else {
                hide_overlay(&app_handle);
            }
        });
    let mask = NSEventMask::MouseMoved
        | NSEventMask::LeftMouseDown
        | NSEventMask::RightMouseDown
        | NSEventMask::OtherMouseDown;
    // 安全 fn（objc2 生成，method_family=none → 返回 +1 owned 的 monitor 对象）。into_raw 存指针地址，
    // 由 remove_mouse_monitor 在主线程 removeMonitor + from_raw 释放那 +1。addGlobalMonitor 内部会 copy
    // 本 block（RcBlock），故本地 `handler` 随后 drop 无碍——AppKit 持有副本至 removeMonitor。
    if let Some(monitor) = NSEvent::addGlobalMonitorForEventsMatchingMask_handler(mask, &handler) {
        *guard = Some(Retained::into_raw(monitor) as usize);
    }
}

/// 拆全局鼠标监听器（defect#3/W32）。任一收起路径经 [`hide_overlay`] 调用。`removeMonitor:` 必须在**主
/// 线程**，故经 `run_on_main_thread` 调度（同步 command 在 WebView2 IPC 分发栈=主线程内直跑、
/// `async fn` command 才被 spawn 到异步 runtime；Focused(false)/toggle_overlay/monitor handler 在
/// 主线程跑——统一调度都安全）。`take()` 去重，保证同一 monitor 只 remove
/// 一次。非 mac 不编译（无此函数）。
#[cfg(target_os = "macos")]
pub(super) fn remove_mouse_monitor(app: &AppHandle) {
    let raw = app
        .try_state::<TrayOverlay>()
        .and_then(|s| s.mouse_monitor.lock().ok().and_then(|mut g| g.take()));
    if let Some(raw) = raw {
        let _ = app.run_on_main_thread(move || {
            let ptr = raw as *mut objc2::runtime::AnyObject;
            // SAFETY: ptr 来自 Retained::into_raw（+1 owned 的 monitor）；take() 保证只 remove 一次；
            // removeMonitor / from_raw 都在主线程执行；from_raw 收回 Retained，drop 时释放那 +1。
            unsafe {
                objc2_app_kit::NSEvent::removeMonitor(&*ptr);
                let _ = objc2::rc::Retained::from_raw(ptr);
            }
        });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// macOS 菜单栏位置持久化（#313b）
// ─────────────────────────────────────────────────────────────────────────────

/// `NSStatusItem.autosaveName` —— **一次性拍定，跨版本永不变更**。
///
/// 系统按 `NSStatusItem Preferred Position <autosaveName>` 这个键把用户拖好的菜单栏位置存进
/// 本 app 的 preferences domain。改这个字面量 = 换一把钥匙 = **所有用户已拖好的位置当场全丢**，
/// 且丢完还不会有任何报错。故它有一道专门的棘轮测试钉着（`tray_autosave_name_is_frozen`）。
#[cfg(target_os = "macos")]
pub const TRAY_AUTOSAVE_NAME: &str = "com.polaris.app.tray";

/// 给托盘的 `NSStatusItem` 钉上 `autosaveName`，让菜单栏位置在**应用更新后**仍然保留（#313b）。
///
/// # 缺陷机制
///
/// AppKit 只有在 `NSStatusItem.autosaveName` 非空时，才把该状态项的位置写进 app 的 preferences
/// domain（键 `NSStatusItem Preferred Position <autosaveName>`）。Polaris 的托盘是**声明式**建的
/// （`tauri.conf.json` 的 `trayIcon` + 运行期 `app.tray_by_id("main")`），而 Tauri **不暴露**这个属性
/// ⇒ 全仓零 `autosaveName` ⇒ 位置没有稳定键可存，用户每次更新完都要重新拖一遍。
///
/// # 与 上游的对照
///
/// 上游 走的是 Electron 的 `new Tray(icon, guid)`：darwin 上 Electron 把 guid 赋给
/// `NSStatusItem.autosaveName`（`electron_api_tray.cc` 的 `SetAutoSaveName`），机制与这里同源，
/// 只是它有现成参数可传。Tauri 没有，只能自己摸到对象。
///
/// # 怎么摸到 NSStatusItem
///
/// `tauri::tray::TrayIcon::with_inner_tray_icon` 是唯一出口（它保证在主线程跑），
/// 拿到底层 `tray_icon::TrayIcon` 后走它的 `ns_status_item()`。**不新增依赖**：闭包返回 `bool`，
/// 故不必在本仓命名 `tray_icon` 那个 crate；`objc2-app-kit` 只是多开一个 `NSStatusItem` feature。
///
/// # 真机实测（2026-08-13，SwayMacBook-Pro / macOS 26.6.1 arm64）—— 两条预判都被证伪
///
/// **① 「不设 autosaveName 就不持久化」是错的。** AppKit 在没有 autosaveName 时会用
/// **按状态项序号编的默认键** `NSStatusItem Preferred Position Item-0`。实测那台机器上该键
/// 值为 549、写入时间 7-31，而 `.app` 在 8-10 被换过一次 —— **位置跨过一次真实更新存活了**。
/// 也就是说 `#313b` 想修的症状（更新后位置重置）在**单状态项**的 app 上根本不复现：
/// 只有一个状态项时 `Item-0` 这个序号天然稳定。
///
/// **② 「老用户会再重置一次」也是错的**（本注释此前就是这么写的，一并更正）。
/// 实测装上带 autosaveName 的版本后：
/// ```text
/// "NSStatusItem Preferred Position Item-0"               = 549;
/// "NSStatusItem Preferred Position com.polaris.app.tray" = 549;   ← 新键，同值
/// ```
/// 新键是带着**当时的实际位置**建的，不是默认值 —— `setAutosaveName` 发生在状态项已按旧键
/// 落好位之后，AppKit 把当前位置存进了新名字。迁移是免费的，没有一次性丢失。
///
/// # 所以这段代码的定位要说准：**保险，不是修复**
///
/// 今天它不解决任何已复现的症状；它买的是「将来若增加第二个状态项，位置不会因序号漂移而串位」，
/// 以及一个显式、可读的键名。代价实测为零，故保留；但**别把它当成 #313b 的『修复』记账**。
///
/// # 验证边界
///
/// 本机（Linux）编不了这条腿，编译验证靠 CI 的 macOS 矩阵腿。上面的键值是真机 SSH 只读取证
/// （起 GUI → 读 `defaults` → 退出，两轮一致）。**没验的一格**：拖动图标后新键是否随之更新
/// —— 那要人手拖，SSH 下做不了。
#[cfg(target_os = "macos")]
pub fn pin_tray_autosave_name(app: &AppHandle) {
    use objc2_foundation::NSString;

    let Some(tray) = app.tray_by_id("main") else {
        return; // 托盘没建出来 → 无对象可设，上游已有告警
    };
    let applied = tray.with_inner_tray_icon(|inner| match inner.ns_status_item() {
        Some(item) => {
            item.setAutosaveName(Some(&NSString::from_str(TRAY_AUTOSAVE_NAME)));
            true
        }
        None => false,
    });
    match applied {
        Ok(true) => {
            log::debug!("托盘 autosaveName 已钉为 {TRAY_AUTOSAVE_NAME}（菜单栏位置将跨更新保留）")
        }
        // 两种失败都不影响任何业务功能，只是位置不再持久 ⇒ 记日志、不打断启动。
        Ok(false) => log::warn!("拿不到 NSStatusItem —— 菜单栏位置不会跨更新保留（#313b）"),
        Err(e) => log::warn!("设置托盘 autosaveName 失败：{e}"),
    }
}

/// 非 macOS：Windows 任务栏与 Linux StatusNotifier 都没有「用户可拖动的状态项位置」这个概念。
#[cfg(not(target_os = "macos"))]
pub fn pin_tray_autosave_name(_app: &AppHandle) {}
