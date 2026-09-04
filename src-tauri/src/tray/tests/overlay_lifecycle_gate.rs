//! 托盘浮层的结构性契约：warm 启动期后台预建、关闭 warm 后跳出点击帧冷建、renderer-ready 后才
//! 允许展示、普通隐藏独立定时回收。任一条漂移都会重新引入首击滞后、空壳或违背偏好的常驻。

use super::super::lifecycle::{
    rollback_owned_exit_guard, should_arm_last_webview_exit_guard, OverlayLifecycle,
    OverlayOpenAction,
};
use crate::test_support::{crate_code, module_code};

/// 取材面 = **模块** `tray`（`tray.rs` 根文件 + `tray/**` 递归，剔除 `tests/`）。
///
/// 本文件 9 个 `top_level_fn_body` 锚点分属未来的 `window.rs` / `platform.rs` / `commands.rs` /
/// `transition.rs`；写死 `crate_source("tray.rs")` 会在拆分那天把取材面砍成根文件一份，
/// 切片锚点当场 panic、而 `tray_rs.contains(..)` 那两条全文正面断言会静默失去它们的证据源。
/// 换成模块取材后，新增的任何 `tray/**.rs` 自动进面（`module_source` 递归），不需要改一个字符。
///
/// `main.rs` 仍走 `crate_source`：它是单文件，没有同名模块目录。
/// **剥注释**取材（[`module_code`]）：本文件两条全文正面断言（`schedule_overlay_reclaim(app);`
/// 与 `TRAY_IDLE_RECLAIM_SECS`）的针都是单行代码文本，写进任何一行 `//` / `//!` 注释就够替
/// 生产调用点作证。实测：`tray.rs:25` 的模块文档写着 `window::TRAY_IDLE_RECLAIM_SECS`，把常量的
/// **全部代码位**改名后本门仍绿。切片腿（`top_level_fn_body`）内部本就再剥一次，幂等无副作用。
fn tray_rs() -> String {
    module_code("tray")
}

/// 同上：`main.rs` 侧的 `matches(..).count() == 1` 同样可被注释充数 —— 生产接线删掉、注释里
/// 留一处，计数仍是 1。
fn main_rs() -> String {
    crate_code("main.rs")
}

#[test]
fn warm_overlay_is_prebuilt_after_tray_setup_and_cold_build_stays_off_click_frame() {
    let tray_rs = tray_rs();
    let main_rs = main_rs();
    assert!(
        !main_rs.contains("tray::build_overlay("),
        "启动 setup 不得同步 build 托盘 WebView；预热也必须排队跳出当前分发帧"
    );
    assert_eq!(
        main_rs
            .matches("tray::prewarm_overlay_if_enabled(app.handle());")
            .count(),
        1,
        "托盘创建成功后必须恰好发起一次启动预热"
    );
    let tray_ready = main_rs
        .find("let tray_present =")
        .expect("找不到托盘创建结果锚点");
    let prewarm = main_rs
        .find("tray::prewarm_overlay_if_enabled(app.handle());")
        .expect("找不到启动预热接线");
    assert!(tray_ready < prewarm, "预热必须晚于托盘锚点创建结果");
    // 🔴 切片形状：**函数自己的作用域**，不是「到下一个函数名为止」。
    //
    // 旧形态用 `split_once("pub fn toggle_overlay")` → `split_once("fn invalidate_overlay_reclaim")`
    // 取两个函数之间的文本 —— 判据依赖的是这两个函数的**书写相邻性**，不是 `toggle_overlay`
    // 的作用域。一旦有人在两者之间插入第三个函数，切片静默变宽，「Click 帧只许排冷建」
    // 就由邻居函数替它作证：真把 `queue_overlay_build` 从 toggle_overlay 里搬走也照绿。
    // `top_level_fn_body` 按**列 0 的 `}`** 封顶，射程锁死在 toggle_overlay 自己体内；
    // 顺带剥掉整行注释 ⇒ 正面断言不能被一行注释顶绿、否定断言不会被注释误红。
    let toggle_body =
        crate::commands::guard_scan::top_level_fn_body(&tray_rs, "pub fn toggle_overlay(");
    assert!(
        !toggle_body.contains("show_main_window"),
        "托盘浮层创建失败时应保持 no-op，不得回退打开主窗"
    );
    assert!(
        toggle_body.contains("queue_overlay_build(app, generation)")
            && !toggle_body.contains("build_overlay("),
        "托盘 Click 帧只许排冷建任务，不能同步 build WebView"
    );
    let queue_body =
        crate::commands::guard_scan::top_level_fn_body(&tray_rs, "fn queue_overlay_build(");
    let spawn = queue_body
        .find("tauri::async_runtime::spawn")
        .expect("冷建必须先跳离托盘点击线程");
    let main = queue_body
        .find("run_on_main_thread")
        .expect("WebView build 必须排回主线程");
    let build = queue_body
        .find("build_overlay(&callback_app, generation)")
        .expect("排回主线程后必须执行按需 build");
    assert!(
        spawn < main && main < build,
        "冷建次序必须是 spawn → 排回主线程 → build"
    );
}

#[test]
fn prewarm_commits_hidden_renderer_without_showing_until_first_click() {
    let mut lifecycle = OverlayLifecycle::default();
    let generation = lifecycle
        .request_prewarm(false)
        .expect("warm 启动必须排一代隐藏 renderer");
    assert_eq!(generation, 1);
    assert_eq!(
        lifecycle.request_prewarm(false),
        None,
        "在飞预热不得叠第二代 WebView"
    );
    lifecycle.build_finished(generation, true);
    assert!(
        !lifecycle.mark_ready(generation),
        "预热 ready 只能提交热开状态，绝不能自行展示"
    );
    assert!(!lifecycle.should_show(generation));
    assert_eq!(
        lifecycle.request_open(true),
        OverlayOpenAction::ShowNow,
        "首次点击应直接消费已 ready 的隐藏 renderer"
    );
}

#[test]
fn cold_overlay_waits_for_matching_renderer_generation() {
    let mut lifecycle = OverlayLifecycle::default();
    assert_eq!(
        lifecycle.request_open(false),
        OverlayOpenAction::QueueBuild { generation: 1 }
    );
    // 加载期间的重复点击合并成同一次打开意图，不让“用户因迟疑再点一下”反向取消首开。
    assert_eq!(lifecycle.request_open(false), OverlayOpenAction::AwaitReady);
    lifecycle.build_finished(1, true);
    assert!(lifecycle.mark_ready(1));
    assert!(lifecycle.should_show(1));

    lifecycle.hide();
    assert!(!lifecycle.should_show(1));
    assert_eq!(lifecycle.request_open(true), OverlayOpenAction::ShowNow);
}

#[test]
fn destroyed_overlay_rejects_stale_renderer_ready() {
    let mut lifecycle = OverlayLifecycle::default();
    let OverlayOpenAction::QueueBuild { generation } = lifecycle.request_open(false) else {
        panic!("首次冷开必须排 build");
    };
    lifecycle.build_finished(generation, true);
    lifecycle.reset();
    let OverlayOpenAction::QueueBuild {
        generation: next_generation,
    } = lifecycle.request_open(false)
    else {
        panic!("销毁后的下一次打开必须创建新一代");
    };
    lifecycle.build_finished(next_generation, true);
    assert!(!lifecycle.mark_ready(generation));
    assert!(!lifecycle.should_show(generation));
    assert_eq!(
        lifecycle.request_open(true),
        OverlayOpenAction::AwaitReady,
        "旧 ready 不得把当前新窗污染成 ready"
    );
}

#[test]
fn mac_overlay_contract_is_nonactivating_and_never_uses_tauri_focus() {
    let tray_rs = tray_rs();
    let build = crate::commands::guard_scan::top_level_fn_body(&tray_rs, "fn build_overlay(");
    assert!(
        build.contains("builder.accept_first_mouse(true)"),
        "mac 托盘 WebView 必须接收非前台 app 的首击，不能把第一次点击吃成窗口激活"
    );
    let configure = crate::commands::guard_scan::top_level_fn_body(
        &tray_rs,
        "fn configure_nonactivating_overlay(",
    );
    assert!(
        configure.contains("NSWindowStyleMask::NonactivatingPanel")
            && configure.contains("setStyleMask(")
            && configure.contains("contentView()")
            && configure.contains("subviews()")
            && configure.contains("firstObject()")
            && configure.contains("makeFirstResponder(Some(&webview))")
            && !configure.contains("win.ns_view()"),
        "mac 托盘宿主改 non-activating mask 后必须恢复实际 WKWebView，而非 Wry parent first responder"
    );
    let focus = crate::commands::guard_scan::top_level_fn_body(
        &tray_rs,
        "#[cfg(target_os = \"macos\")]\npub(super) fn focus_overlay(",
    );
    assert!(
        focus.contains("makeKeyAndOrderFront(None)")
            && !focus.contains("activateIgnoringOtherApps")
            && !focus.contains("win.set_focus()"),
        "mac focus 腿必须绕开 tao 附带 app activation 的 set_focus 封装"
    );
    let monitor =
        crate::commands::guard_scan::top_level_fn_body(&tray_rs, "fn install_mouse_monitor(");
    assert!(
        monitor.contains("NSEventMask::MouseMoved")
            && monitor.contains("NSEventType::MouseMoved")
            && monitor.contains("forward_native_hover(&app_handle)")
            && monitor.contains("hide_overlay(&app_handle)"),
        "mac global monitor 必须分流：移动只补非激活 hover，窗外点击才收起"
    );
    let hover =
        crate::commands::guard_scan::top_level_fn_body(&tray_rs, "fn forward_native_hover(");
    assert!(
        hover.contains("NSEvent::mouseLocation()")
            && hover.contains("convertPointFromScreen")
            && hover.contains("content_view.bounds().size.height - point.y")
            && hover.contains("__POLARIS_NATIVE_HOVER__"),
        "mac 非激活 hover 必须按实际 contentView 高度完成 AppKit 左下角到 Web client 左上角的坐标换算"
    );
}

#[test]
fn renderer_ready_is_the_only_cold_show_commit_point() {
    let tray_rs = tray_rs();
    let build = crate::commands::guard_scan::top_level_fn_body(&tray_rs, "fn build_overlay(");
    assert!(
        !build.contains(".show()"),
        "冷建函数不得在 renderer ready 前展示窗口"
    );
    let ready = crate::commands::guard_scan::top_level_fn_body(
        &tray_rs,
        "pub async fn tray_renderer_ready(",
    );
    assert!(
        ready.contains("lifecycle.mark_ready(generation)")
            && ready.contains("run_on_main_thread")
            && ready.contains("show_ready_overlay"),
        "renderer ready 必须代次校验后、跳出 IPC 帧排回主线程再 show"
    );
}

/// 每次展开都必须叫 renderer 重量窗高 —— 「托盘菜单的『退出』要往下拉才看得见」那条缺陷的防线。
///
/// # 为什么判据只能是源码级
///
/// 现象只在 mac/Windows 的**自绘** WebView 浮层上（Linux 走的是原生 AppIndicator 级联菜单，
/// 见 `app_tray.rs`），本机连复现都做不到；而缺陷本身就是「`show_ready_overlay` 一个字节都没往
/// renderer 推」—— 判据正是这个调用点在不在，不是任何可在 Linux 上跑出来的运行期行为。
///
/// # 为什么顺序也要断言
///
/// `keepTrayMenuWarm` 默认开启 ⇒ 隐藏只收起浮层、不回收 WebView，前端那把「首次量到就锁死」的
/// 高度锁因此活到整个进程结束。把重量通知排在 `win.show()` 之前，量到的仍是上一次展开时的布局，
/// 这条腿就退化成「调了但没用」——恰是本仓「门在但没牙」那一类。
#[test]
fn every_overlay_show_tells_the_renderer_to_remeasure() {
    let tray_rs = tray_rs();
    let show = crate::commands::guard_scan::top_level_fn_body(
        &tray_rs,
        "pub(super) fn show_ready_overlay(",
    );
    let show_call = show
        .find("win.show()")
        .expect("`show_ready_overlay` 里找不到 `win.show()` —— 顺序判据的锚点已过期，先修判据");
    let bridge = show.find("__POLARIS_TRAY_REMEASURE__").expect(
        "每次展开都必须叫 renderer 重量：warm 的 WebView 隐藏期间不重建，前端高度锁一旦合上就活到\
         进程结束 —— 首次量偏矮就一直矮（「退出」被挤进滚动区），中途换屏/改分辨率则可能高到出屏",
    );
    assert!(
        show.contains("win.eval("),
        "重量通知必须走既有 eval 桥（同 `hide_overlay` 里的 `__POLARIS_NATIVE_HOVER__`），不新开 IPC 通道"
    );
    assert!(
        show_call < bridge,
        "重量必须排在 `win.show()` 之后：隐藏态 WebView 量到的仍是上一次展开的布局"
    );
    assert_eq!(
        show.matches("__POLARIS_TRAY_REMEASURE__").count(),
        1,
        "重量桥在本函数里只该有一处调用点（多处 = 一次展开被要求量好几轮）"
    );
}

/// 腿 B 的**宿主**半边：屏幕参数变了必须由宿主推给 renderer，且走腿 A 那条既有 eval 桥。
///
/// # 为什么判据只能是源码级
///
/// 同 [`every_overlay_show_tells_the_renderer_to_remeasure`]：现象只在 mac/Windows 的自绘浮层上
/// （Linux 走原生 AppIndicator 级联菜单），本机连复现都做不到；而缺陷形态本身就是「宿主一个字节
/// 都没往 renderer 推」—— 判据正是这些调用点在不在。mac 腿还多一层：`#[cfg(target_os = "macos")]`
/// 的代码 Linux 编译单元根本不含，判据若也只能在 mac 上跑，本地对它就是全盲（同
/// `autosave_name_gate` 的取舍）。
///
/// # 为什么「窗不在时 no-op」也要钉
///
/// 屏幕换代与「用户想看菜单」无关。为一条状态通知去冷建 WebView，等于把一次系统通知变成一次建窗
/// 开销，还会把 `keepTrayMenuWarm=false` 用户刚回收掉的窗又拉回来 —— 那是把修复变成新缺陷。
#[test]
fn screen_change_is_pushed_by_the_host_over_the_existing_eval_bridge() {
    let tray_rs = tray_rs();

    // ① mac 权威源：AppKit 的屏幕参数通知（显示器增删/分辨率/缩放/重排全从这里发），
    //    不是我们自己那个窗的任何事件。
    let observer = crate::commands::guard_scan::top_level_fn_body(
        &tray_rs,
        "pub(super) fn install_screen_change_observer(",
    );
    assert!(
        observer.contains("NSApplicationDidChangeScreenParametersNotification")
            && observer.contains("addObserverForName_object_queue_usingBlock"),
        "mac 的屏幕换代腿必须挂在 AppKit 的屏幕参数通知上：`ScaleFactorChanged` 只跟 backing scale 走，\
         同 DPI 下改分辨率/插拔扩展屏一律不发，而 mac 侧前端 media query 腿在 WKWebView 上未核实 —— \
         这一半没有第二个人守"
    );
    assert!(
        observer.contains("notify_screen_change_remeasure"),
        "观察者回调必须汇到既有的重量出口，不得另起一条通知路径（新通道/新全局都是净亏）"
    );

    // ② 实现写了还得真接上：`build_overlay` 是浮层唯一的建窗点，两条腿都必须挂在这里。
    let build = crate::commands::guard_scan::top_level_fn_body(&tray_rs, "fn build_overlay(");
    assert_eq!(
        build
            .matches("install_screen_change_observer(app);")
            .count(),
        1,
        "mac 屏幕观察者必须在建窗点恰好接一次 —— 实现写了没接线 = 静默零执行，\
         而这类腿失效时不会报错，只会让用户看到按旧屏算出来的窗"
    );
    assert!(
        build.contains("WindowEvent::ScaleFactorChanged { .. } => notify_screen_change_remeasure("),
        "Windows 腿必须接 `ScaleFactorChanged`：tao 把 `WM_DPICHANGED` 归一到它，\
         那正是「主屏 150% + 副屏 100% 拖窗过去」这一档 —— Windows 上最常见的混合 DPI 形态"
    );

    // ③ 出口：走既有 eval 桥，窗不在即 no-op，不建窗、不开新通道。
    let notify = crate::commands::guard_scan::top_level_fn_body(
        &tray_rs,
        "pub(super) fn notify_screen_change_remeasure(",
    );
    assert!(
        notify.contains("win.eval(") && notify.contains("__POLARIS_TRAY_REMEASURE__"),
        "重量通知必须走腿 A 那条既有 eval 桥（同一个全局），不新开 IPC 通道、不新增第二个全局"
    );
    assert!(
        notify.contains("app.get_webview_window(TRAY_LABEL)") && notify.contains("return"),
        "必须先查浮层窗在不在，不在就直接返回"
    );
    assert!(
        !notify.contains("build_overlay(") && !notify.contains("queue_overlay_build("),
        "不得为了推一条状态通知去建窗：屏幕换代与「用户想看菜单」无关，\
         下一次展开的腿 A 本来就会量"
    );
    assert!(
        !notify.contains(".emit(") && !notify.contains("IPC_CHANNELS"),
        "这是一次单向、无载荷的通知，通道的注册/契约/双侧维护成本全是净亏"
    );

    // ④ 反向：不许改成监听自己这个窗的尺寸/位置 —— 那是「改尺寸 → 收事件 → 重量 → 改尺寸」
    //    的正反馈环，`TRAY_MAX_HEIGHT_LOGICAL` 的注释里记着一次被 ResizeObserver 推到上限的实例。
    assert!(
        !build.contains("WindowEvent::Resized") && !build.contains("WindowEvent::Moved"),
        "浮层窗的 Resized/Moved 正是我们自己经 tray_resize 改出来的，拿它触发重量 = 正反馈环"
    );
}

#[test]
fn tray_retention_is_independent_from_main_lightweight_setting() {
    let tray_rs = tray_rs();
    let hide =
        crate::commands::guard_scan::top_level_fn_body(&tray_rs, "pub(super) fn hide_overlay(");
    let reclaim_branch = hide
        .split_once("if should_reclaim && !overlay_keeps_warm(app) {")
        .and_then(|(_, rest)| rest.split_once("\n    }"))
        .map(|(branch, _)| branch)
        .expect("普通 hide 必须有 !overlay_keeps_warm 守卫的回收分支");
    assert_eq!(
        hide.matches("if should_reclaim && !overlay_keeps_warm(app) {")
            .count(),
        1,
        "普通 hide 的 warm=false 回收守卫必须唯一，不能由其他分支替它作证"
    );
    assert!(
        reclaim_branch.contains("schedule_overlay_reclaim(app);"),
        "普通 hide 在 warm=false 时必须自行排程回收，不能只靠配置变更腿或主窗轻量模式顺带清理"
    );
    let schedule =
        crate::commands::guard_scan::top_level_fn_body(&tray_rs, "fn schedule_overlay_reclaim(");
    assert_eq!(
        schedule
            .matches("Duration::from_secs(TRAY_IDLE_RECLAIM_SECS)")
            .count(),
        1,
        "回收排程必须在自身延时任务里消费 TRAY_IDLE_RECLAIM_SECS，定义或其他调用点不能顶绿"
    );
    let body = crate::commands::guard_scan::top_level_fn_body(
        &tray_rs,
        "pub(crate) fn enter_lightweight_transition(",
    );
    assert!(
        body.contains("hide_overlay(&app);") && !body.contains("destroy_overlay(&app);"),
        "主窗口轻量转场只能收起托盘；销毁与否必须继续服从独立 warm 偏好"
    );
}

#[test]
fn main_window_destroy_is_a_transactional_lifecycle_boundary() {
    let tray_rs = tray_rs();
    let body = crate::commands::guard_scan::top_level_fn_body(
        &tray_rs,
        "pub(crate) fn enter_lightweight_transition(",
    );
    let destroying = body
        .find("mark_main_window_destroying()")
        .expect("destroy 前必须先关闭主窗口生命周期门");
    let destroy = body
        .find("let result = win.destroy();")
        .expect("轻量态必须真正销毁主 WebView");
    let owner_rollback = body
        .find("rollback_owned_exit_guard(")
        .expect("destroy 失败必须交 shared owner-aware helper 回滚退出守卫");
    let success = body
        .split_once("match result {")
        .and_then(|(_, arms)| arms.split_once("Ok(()) => {"))
        .and_then(|(_, success_and_rest)| success_and_rest.split_once("Err(e) => {"))
        .map(|(success, _)| success)
        .expect("destroy 必须显式区分 Ok(()) 成功提交与 Err(e) 回滚分支");
    let failure = body
        .split_once("match result {")
        .and_then(|(_, arms)| arms.split_once("Err(e) => {"))
        .map(|(_, failure)| failure)
        .expect("destroy 失败分支消失");
    assert_eq!(
        body.matches("Ok(()) => {").count(),
        1,
        "destroy 成功分支必须唯一，不能由别的 match arm 伪造提交点"
    );
    assert_eq!(
        body.matches("Err(e) => {").count(),
        1,
        "destroy 失败回滚分支必须唯一，才能封住成功提交分支"
    );
    assert!(destroying < destroy, "生命周期门必须先于平台 destroy 关闭");
    assert!(
        destroy < owner_rollback,
        "owner-aware rollback 只能在 destroy 返回失败结果后决定，不能预先清状态"
    );
    assert!(
        !body[..destroy].contains("rt.stats().clear_window(\"main\")"),
        "订阅清理不得早于 destroy；提前清会让失败回滚后的活页面永久断流"
    );
    assert!(
        success.contains("rt.stats().clear_window(\"main\")"),
        "stats 订阅清理必须在 destroy 成功分支提交；else 的幂等清理不能替它作证"
    );
    assert!(
        failure.contains("rt.stats().mark_main_window_created()")
            && failure.contains("rt.stats().refresh_window_visible(&app)"),
        "destroy 失败必须恢复窗口生命周期并刷新可见性"
    );
    assert!(
        body[owner_rollback..].contains("result.is_err(),")
            && body[owner_rollback..].contains("armed,"),
        "destroy 失败时必须把本调用者所有权交给 owner-aware rollback helper"
    );
}

/// W18（2026-08-19 真机）：CloseRequested 帧内不得同步调 `tray_enter_lightweight`（内含
/// 主窗+浮层两个 WebView 的 `destroy()`）——Windows 上在窗口自身 close 消息分发栈里销毁
/// WebView2 会楔死消息泵（首实例托盘全死、双击再起第二进程双图标）。帧内只许轻操作
/// （hide），转场必须「跳离主线程 → run_on_main_thread 排回帧外」。
///
/// 次序即语义：`win.hide()`（帧内即时视觉关闭）→ `async_runtime::spawn`（跳离）→
/// `run_on_main_thread`（排回）→ `tray_enter_lightweight`（帧外销毁）。任何一步次序倒换
/// （尤其把 tray_enter_lightweight 挪回 spawn 之前 = 帧内直调）本条转红。
#[test]
fn lightweight_transition_is_deferred_out_of_close_frame() {
    let main_rs = main_rs();
    let arm = main_rs
        .split_once("CloseAction::EnterLightweight => {")
        .and_then(|(_, rest)| rest.split_once("CloseAction::QuitApp => {"))
        .map(|(arm, _)| arm)
        .expect("必须能切出 CloseRequested 的 EnterLightweight 分支");
    // 针带语法特征（限定路径/点调用/实参形态），避免命中写进 arm 注释里的裸词。
    let hide_at = arm
        .find("win.hide()")
        .expect("帧内必须先隐藏（即时关闭视觉）");
    let spawn_at = arm
        .find("tauri::async_runtime::spawn")
        .expect("必须跳离主线程（run_on_main_thread 从主线程调用是内联直执）");
    let queue_at = arm
        .find(".run_on_main_thread(")
        .expect("必须经 run_on_main_thread 排回主线程");
    let enter_at = arm
        .find("enter_lightweight_transition(h2)")
        .expect("转场入口必须在位（帧外闭包内，以 h2 实参形态）");
    // F2（评审）：排回闭包内、销毁之前必须复核主窗未被重新唤出（排队饥饿时用户可能已唤回）。
    let recheck_at = arm
        .find("win.is_visible()")
        .expect("销毁前必须复核主窗可见性（迟到销毁不得杀用户刚唤出的窗）");
    assert!(
        hide_at < spawn_at
            && spawn_at < queue_at
            && queue_at < recheck_at
            && recheck_at < enter_at,
        "轻量转场次序必须为 hide → spawn → run_on_main_thread → is_visible 复核 → enter（帧内直调即 W18 死锁形态）"
    );
}

/// W18/F1（评审）：`tray_enter_lightweight` command 是托盘浮层按钮的 invoke 入口——
/// 同步 command 跑在 WebView2 IPC 分发栈（主线程）内，帧内销毁浮层自身即 W18 死锁
/// 同构形态。command 必须是 `async fn`（tauri spawn 到 tokio worker = 帧外）且体内
/// 只排队（`run_on_main_thread` → `enter_lightweight_transition`），不得直跑销毁。
/// 变异锁：改回同步直调 / 删排队直调本体 → 本条红。
#[test]
fn lightweight_command_defers_out_of_ipc_frame() {
    let tray_rs = tray_rs();
    let body = crate::commands::guard_scan::top_level_fn_body(
        &tray_rs,
        "pub async fn tray_enter_lightweight(",
    );
    assert!(
        !body.contains("win.destroy()"),
        "command 体内不得直跑销毁（IPC 分发栈内）"
    );
    let queue_at = body
        .find(".run_on_main_thread(")
        .expect("command 必须经 run_on_main_thread 排回主线程帧外");
    let enter_at = body
        .find("enter_lightweight_transition(h")
        .expect("转场必须经本体 fn（帧外闭包内）");
    assert!(queue_at < enter_at, "次序必须是排队在先、转场在排回闭包内");
}

#[test]
fn last_overlay_reclaim_preserves_tray_residency_only_for_the_last_window() {
    assert!(should_arm_last_webview_exit_guard(1, true));
    assert!(!should_arm_last_webview_exit_guard(0, true));
    assert!(!should_arm_last_webview_exit_guard(2, true));
    assert!(!should_arm_last_webview_exit_guard(1, false));
}

#[test]
fn owned_exit_guard_rollback_truth_table_preserves_other_callers_state() {
    use std::sync::atomic::{AtomicBool, Ordering};

    for (destroy_failed, armed_by_this_caller, expected_after) in [
        (true, true, false),
        (true, false, true),
        (false, true, true),
        (false, false, true),
    ] {
        let guard = AtomicBool::new(true);
        rollback_owned_exit_guard(&guard, destroy_failed, armed_by_this_caller);
        assert_eq!(
            guard.load(Ordering::SeqCst),
            expected_after,
            "destroy_failed={destroy_failed}, armed_by_this_caller={armed_by_this_caller}"
        );
    }
}

#[test]
fn last_webview_destroys_delegate_owner_rollback_to_the_shared_helper() {
    let tray_rs = tray_rs();
    let main = crate::commands::guard_scan::top_level_fn_body(
        &tray_rs,
        "pub(crate) fn enter_lightweight_transition(",
    );
    let overlay = crate::commands::guard_scan::top_level_fn_body(
        &crate_code("tray/window.rs"),
        "fn destroy_overlay_preserving_tray_residency(",
    );

    for (name, body) in [("主窗", main.as_str()), ("浮层", overlay.as_str())] {
        assert_eq!(
            body.matches("rollback_owned_exit_guard(").count(),
            1,
            "{name} destroy 必须恰好委托一次 owner-aware rollback helper"
        );
        assert!(
            !body.contains(".store(false, Ordering::SeqCst)"),
            "{name} 不得绕过 shared helper 自己回滚 LightweightState"
        );
        let compact = body.split_whitespace().collect::<String>();
        assert!(
            compact.contains("result.is_err(),armed,"),
            "{name} 必须把本次 destroy 失败与本调用者的 armed 所有权原样交给 helper"
        );
    }

    let armed = main
        .find("should_arm_last_webview_exit_guard(")
        .expect("主窗 destroy 前必须复用末 WebView 判据");
    let destroy = main
        .find("let result = win.destroy();")
        .expect("轻量转场必须仍以 destroy 成功为提交点");
    assert!(armed < destroy, "退出守卫必须在 destroy 前武装");
    let pre_destroy = &main[..destroy];
    for required in [
        "app.webview_windows().len()",
        "app.tray_by_id(\"main\").is_some()",
        ".compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)",
    ] {
        assert!(
            pre_destroy.contains(required),
            "主窗 guard 缺少 `{required}`"
        );
    }
    assert_eq!(
        main.matches("should_arm_last_webview_exit_guard(").count(),
        1,
        "主窗转场只能有一个按末窗判据的武装点"
    );
    let no_main = main
        .split_once("} else {")
        .map(|(_, rest)| rest)
        .expect("无 main 的幂等分支消失");
    assert!(
        !no_main.contains("compare_exchange"),
        "无 main 的幂等清账不得武装退出守卫"
    );
}
