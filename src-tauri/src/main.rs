//! Polaris — Tauri 2 主进程入口。
//!
//! 装配：17 个 domain crate（经 `runtime::AppRuntime` 注入真实 I/O 实现）+ Tauri 2 原生插件
//! （single-instance / shell / dialog / notification / autostart / os / process / fs）+ 全部 IPC command 注册。
//!
//! 架构 / 进程模型见 `docs/polaris/design/polaris-system-design.md` §B.1。
//! IPC 命令 / 事件映射见 §B.3（Polaris IPC channels → Tauri commands，语义不变）。
//!
//! 命令面：`commands` 模块按 上游 `main/ipc/handlers/` 文件划分组织，统一返回
//! `response::ApiResponse<T>`（上游 `{ success, data, error, code }` 信封）。

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app_language;
mod app_tray;
mod clean_exit;
mod commands;
mod events;
mod exit_lifecycle;
mod graphics_compat;
mod i18n;
mod icon_cache;
mod idle_lightweight;
mod logging;
mod response;
mod runtime;
mod startup;
#[cfg(test)]
mod test_support;
mod tray;
mod window_health;
#[cfg(target_os = "windows")]
mod windows_single_instance;

use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(not(target_os = "macos"))]
use std::sync::Arc;

use polaris_helper_proto::Platform;
use tauri::{Manager, WebviewWindowBuilder};
use tauri_plugin_autostart::MacosLauncher;

use crate::app_tray::*;
use crate::commands::*;
use crate::runtime::AppRuntime;
#[cfg(not(target_os = "macos"))]
use crate::startup::commit_maximized_observation;
pub(crate) use crate::startup::{
    cli_help_text, config_minimize_to_tray, config_remember_window_size, config_silent_start,
    refresh_stats_visibility, resolve_close_action, resolve_startup, set_macos_dock_visible,
    CloseAction,
};
pub(crate) use crate::startup::{
    LightweightState, QuitState, RestartState, StartupAction, StartupConfigFlags,
};
use crate::window_health::{MountGateEvent, WindowHealth};

/// macOS 只驻托盘时隐藏 Dock 图标；主窗重新呈现前恢复。其它平台保持 no-op，调用点无需散落 cfg。
/// 把**已存在**的主窗真正推上屏：unminimize + show + focus。
///
/// 失败静默——窗可能已析构，非致命。unminimize 先行：窗若只被最小化而仍存在，只 show 不够，
/// 得先出最小化态才会真正可见（dock/任务栏重开路径尤其需要）；未最小化时 unminimize 是 no-op。
///
/// **只负责「呈现」，绝不建窗**（建窗归 [`show_main_window`]）：本函数还被 `window_health` 的兑现腿
/// （ready / 兜底期限）异步调用，而那时窗口可能已被轻量模式销毁 —— 那种情况下必须安静地什么都不做，
/// 绝不能凭一个几秒前的上屏意图凭空重建一个用户没要的窗。
fn present_main_window(app: &tauri::AppHandle) {
    let Some(w) = app.get_webview_window("main") else {
        return;
    };
    // macOS 收托盘时会隐藏 Dock 图标；先恢复再上屏，避免窗口已出现而 Dock 仍缺席的一帧错位。
    set_macos_dock_visible(app, true);
    let _ = w.unminimize();
    let show_result = w.show();
    let _ = w.set_focus();
    // 显隐写入点：主窗刚变可见 → 立刻刷 stats 降流门（park 中的三条 poller 由此即刻恢复，
    // 不必等它们各自的 1s 兜底拍）。`Focused` 事件在部分平台/路径上不保证跟着 show 发。
    refresh_stats_visibility(app);
    window_health::log_show_probe(
        app,
        if show_result.is_ok() {
            "shown"
        } else {
            "show-failed"
        },
        true,
    );
}

/// 唤出主窗（托盘浮层的明确入口 / Linux 托盘「显示」菜单 / macOS dock 重开 共用）。
///
/// 上屏时机交 [`window_health::show_timing`] 判：窗在且内容已就绪 → 立刻呈现（常态，零延迟）；
/// 窗在但当前文档还没 mount 成功（启动期 / webview 崩溃后 Tauri 内置 reload 在途）→ **不把空窗推给
/// 用户**，扣在隐藏态等 `renderer:ready`（超期有兜底，见 `window_health::defer_show`）。
///
/// 所有调用先统一投到主线程，再由 [`show_main_window_on_main_thread`] 执行。这个边界不能只包
/// `apply_vibrancy`：重建窗的 builder、原生材质和窗口事件装配是一项不可拆的主线程事务。托盘 WebView
/// command 会从异步 IPC 线程进入；若直接在那条线程重建，macOS 会拒绝 vibrancy，而前端仍按“材质已开”
/// 让侧栏透明，最终露出桌面。首建在 setup 主线程、重建在 IPC 线程的分叉必须在入口处消掉。
fn show_main_window(app: &tauri::AppHandle) {
    // W18 第二层（2026-08-20 真机翻案）：本函数的调用方会从**主线程的消息分发帧**进来——
    // single-instance 插件的 WM_COPYDATA WndProc（跨进程 `SendMessageW` 同步栈内）、托盘
    // 浮层 command 的 IPC 分发栈。`run_on_main_thread` 从主线程调用是**内联直执**——帧内
    // 直接重建主窗（WebView2 创建）会把同步对端卡死（真机实证：关窗后双击 = 第二实例
    // 永不退出 + 首实例重建卡在 WndProc 里）。故先跳 async 线程（脱离分发帧）再排回主
    // 线程执行；从非主线程进来的调用方只多一跳（µs 级），行为不变。
    window_health::begin_show_probe(app, app.get_webview_window("main").is_none());
    let app_for_main = app.clone();
    tauri::async_runtime::spawn(async move {
        let h = app_for_main.clone();
        if let Err(error) = app_for_main.run_on_main_thread(move || {
            window_health::log_show_probe(&h, "main-thread", false);
            show_main_window_on_main_thread(&h);
        }) {
            log::error!("主窗唤出投递主线程失败：{error}");
            window_health::log_show_probe(&app_for_main, "dispatch-failed", true);
        }
    });
}

/// 主线程内完成“复用现有主窗或完整重建”的唯一实现。
fn show_main_window_on_main_thread(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        match window_health::show_timing(app, Some(&w)) {
            window_health::ShowTiming::Now => present_main_window(app),
            window_health::ShowTiming::WhenReady => window_health::defer_show(app),
        }
    } else {
        // C16 轻量模式已**销毁**主窗 webview（`get_webview_window` 返 None）→ 重建（可见）。所有 per-window
        // 装配（特效 / 白屏自愈门 / 关闭进轻量事件）都在 `create_main_window` 一处，故重建与首建等价。
        // 失败仅记日志（托盘 / 核仍在，用户可重试唤出）；`start_hidden=false`——用户显式唤出即要可见。
        window_health::log_show_probe(app, "build-start", false);
        if let Err(e) = create_main_window(app, false) {
            log::error!("主窗重建失败（轻量模式返回）：{e}");
            window_health::log_show_probe(app, "build-failed", true);
        }
    }
}

/// 按代理连接态切托盘图标；连接/断开靠**形态**区分（实心 vs 空心），三平台**全单色自适应**（不再彩色）。
/// 图标在编译期内嵌（`include_image!`，走 `image-png` feature），运行期零文件 IO。托盘可能整体缺失
/// （Linux 无 StatusNotifier）→ `tray_by_id` 返 None 时静默跳过。
///
/// # 图标策略（R15：用户已裁决「全自适应、丢彩色」）
///
/// 「彩色品牌」与「系统自适应」在 macOS template 机制下不可兼得（template 只吃 alpha、由系统自动反色，
/// 保不住彩色），用户拍板**全自适应**。连接/断开不靠颜色、靠**形态**区分：连接=**实心星**、断开=**空心
/// 描边星**（都单色、随明暗反色），实心/空心一眼区分——macOS 惯例（VPN app 连=实心盾 / 断=空心盾）。
/// 素材从 `icons/polaris-logo.svg` 星形派生（`tray-star-{filled,outline}.svg` → 四张
/// `tray-{on,off}-{black,white}.png`，alpha 即形状，无外部素材）。
///   · **macOS**：`template=true`（conf `iconAsTemplate:true` + 此处），系统按菜单栏明暗**自动反色**
///     （深=白、浅=黑）。template 只取 alpha 忽略 RGB → 用黑色变体即可（连=on-black / 断=off-black）。
///   · **Win/Linux**：**无** template 自动反色机制 → 靠 [`tauri::Window::theme`] 检测系统明暗，深色任务栏
///     用白变体、浅色用黑变体；并监听 `WindowEvent::ThemeChanged` 实时换（见主窗 `on_window_event`）。
///     检测取不到 → 默认深色任务栏用白，避免深底黑星融入。
///
/// # 四态（A2：此前只有 connected 二态）
///
/// 形态轴从「实心 / 空心」扩到四种**轮廓可辨**的图形（16px 下二值可分，不靠粗细微差）：
/// 连接=实心星+厚环 / 起核中=**实心星无环** / 未连接=空心星+细环+**单斜杠** / 异常=空心星+细环+**双斜杠**。
/// 未连接那道斜杠是 2026-07-29 真机加的：「实心 vs 空心」在 22pt 菜单栏几乎不可分，斜杠才是二值特征；
/// 异常态随之从单斜杠升双斜杠，否则两态撞形（22px 实测比选，见 `icons/tray-star-error.svg` 头注）。
/// 素材同源派生（`tray-star-{connecting,error}.svg` → `tray-{connecting,error}-{black,white}.png`）。
/// 对齐 上游 `TrayManager.ts:54` 的三态 + `:265` 的 `hasError` 分支（Polaris 侧此前二者都缺）。
///
/// ⚠️ macOS 反色、Windows 任务栏主题、Linux portal 主题检测本机（Linux）均验不全 → 待真机（R15）。
/// Win/Linux 托盘图标黑/白变体的**系统真值**读取（W13 正解，复审修法②）。
///
/// - **Windows**：直读注册表 `Personalize`（任务栏跟随系统主题，故取 `SystemUsesLightTheme`，
///   缺失时退应用档 `AppsUseLightTheme`）。零窗口依赖——主窗/浮层窗全销毁的轻量态恒可用，
///   且不受显式 uiTheme 的 `set_theme` 钉窗失真影响（复审 Med-1：窗口 `theme()` 读的是应用外观）。
///   实时性：无窗时收不到 `WM_SETTINGCHANGE`，由既有 30s 自愈轮询（[`TRAY_ICON_POLL`]）兜住。
/// - **Linux**：portal 读法需要窗口在场（tao 实现），无窗口时返回 `None` 落回窗口探测链——
///   已知缺口如实记录（Linux 侧本就标 R15 待真机）。
#[cfg(target_os = "windows")]
fn system_dark_bg() -> Option<bool> {
    use std::os::windows::ffi::OsStrExt;
    const PERSONALIZE: &str = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";
    fn wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }
    fn read_dword(value: &str) -> Option<u32> {
        use windows_sys::Win32::Foundation::ERROR_SUCCESS;
        use windows_sys::Win32::System::Registry::{
            RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_DWORD,
        };
        let subkey = wide(PERSONALIZE);
        let val = wide(value);
        let mut data: u32 = 0;
        let mut size: u32 = 4;
        // SAFETY: subkey/value 是调用期间存活且 NUL 终止的 UTF-16；RRF_RT_REG_DWORD 把成功结果
        // 限定为 4 字节 DWORD，data/size 都是可写本栈对象且长度精确。
        let rc = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                val.as_ptr(),
                RRF_RT_REG_DWORD,
                std::ptr::null_mut(),
                &mut data as *mut u32 as *mut std::ffi::c_void,
                &mut size,
            )
        };
        (rc == ERROR_SUCCESS).then_some(data)
    }
    let light = read_dword("SystemUsesLightTheme").or_else(|| read_dword("AppsUseLightTheme"))?;
    Some(light != 1) // 1 = 浅色；0（或它值）= 深色
}

/// 非 Windows 侧（仅 Linux；mac 走 template 反色不进本链）：未引入零窗口真值源（portal/gsettings
/// 直读需新依赖），返回 `None` 落回窗口探测链。门控与调用点 `not(macos)` 同构——若写成
/// `not(windows)`，mac 展开下本 fn 零引用，clippy -D warnings 的 macos CI 腿必红（二审 High-1）。
#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
fn system_dark_bg() -> Option<bool> {
    None
}

/// Win/Linux 托盘图标黑/白变体的明暗探测（W13 抽出的纯函数）。
///
/// `primary` 依序取第一个 `Some`：注册表真值（Win，未引入时为 None）→ 主窗（显式 uiTheme 下被
/// `set_theme` 钉住、读到的是应用外观而非任务栏明暗——已知失真，Linux 侧至今靠本句记录）。
/// `fallback` = 托盘浮层窗（限时存活：轻量转场与 120s 空闲回收都会销毁它，聊胜于无的末位兜底）。
/// 全部取不到 → 默认深色任务栏用白（沿用原取向：深底黑星融入不可辨）。
#[cfg(not(target_os = "macos"))]
fn dark_bg_from_probe(primary: Option<bool>, fallback: Option<bool>) -> bool {
    primary.or(fallback).unwrap_or(true)
}

fn create_main_window(
    app: &tauri::AppHandle,
    start_hidden: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // 窗口特效总门控（与首建同源：读 config.json 原文本，不依赖 store 具体 API）。
    // `windowEffects` / `hardwareAcceleration` 任一显式 false → 不上特效。判定收在 graphics_compat 的纯函数里
    // （可单测）；**别在这儿重写这个 OR** —— 建窗代码在 cfg 门内，单测够不着，逻辑放这儿等于没门。
    let config_dir = app
        .path()
        .app_config_dir()
        .map(|p| p.join("polaris"))
        .unwrap_or_else(|_| std::path::PathBuf::from("./polaris"));
    let raw_config = graphics_compat::read_config_raw(&config_dir);
    let apply_effects = graphics_compat::should_apply_window_effects(raw_config.as_deref());

    // 用官方文档化的 `WebviewWindowBuilder::from_config` 复用同一份 conf 声明（`tauri-utils/src/config.rs`
    // 的 doc 示例即此模式），零字段重复、行为与 conf 直建逐字节相同。保留建窗模式（而非 conf create:true）是为
    // **B6 窗口铬**：mac `hiddenInset`+vibrancy / Windows Mica 需要 per-platform 的 `transparent`（builder-only、
    // 运行期不可改），单条 conf window 声明表达不了。
    let window_config = app
        .config()
        .app
        .windows
        .first()
        .cloned()
        .ok_or_else(|| "tauri.conf.json 未声明主窗".to_string())?;
    // per-platform 窗口铬（B6）：先 from_config 复用 conf 声明，再按平台覆盖 transparent，最后 build，再挂特效。
    //   · mac/win：开 transparent（配合前端 `.win` 圆角 + 半透底，让圆角内容成为可见轮廓）。
    //   · Linux：**恒不开** transparent、**不调用任何特效**——transparent:false 是白屏逃生门路径，绝不翻转。
    #[allow(unused_mut)]
    let mut builder = WebviewWindowBuilder::from_config(app, &window_config)?;

    // ── B：主题接线（此前后端零读 `uiTheme`，三处原生面全硬编码深色）──
    //
    // ① **首帧预解析脚本**：`initialization_script` 先于页面任何脚本执行、且不受页面 CSP `script-src 'self'`
    //    限制（与 `tray::window::TRAY_BLUR_DISMISS_JS` / `update_popup` 的 init_script 同款手法）。它把 `data-theme`
    //    在第一帧之前就播种到 `<html>` 上 —— 而**能同步读到 `uiTheme` 真值的只有主进程**（它在 config.json
    //    里，前端拿到它已经是 IPC 之后）。只播种不接管，运行期真值仍归 `AppShell.tsx` 那个 effect。
    // ② **窗口原生底色**：`from_config` 用的是 conf 里写死的 `#0B0F14`。显式选浅色的用户，窗口原生底
    //    （webview 出图之前就在屏上的那一层）会先闪一格深色。按 `uiTheme` 覆写掉。
    //
    // ⚠️ `uiTheme='system'` 且**当前一个窗都没有**（首次建主窗）时探不到系统明暗（Tauri 2.11 无 app 级
    //    theme getter，只有 `Window::theme()`）→ `resolve_native_dark` 回落深色 = 与本改动前逐字节相同。
    //    这条缺口只影响 system 档的**冷启动首帧**；显式 light 档（真正会抱怨闪深色的那批人）已完整修好。
    let dark = tray::native_dark(app);
    builder = builder
        .initialization_script(tray::theme_boot_script(dark))
        // **必须在下面 mac/win 特效分支之前**：那一支要把底色覆写成全透明，builder 是后写胜出。
        // 放这里也让 **Linux** 覆盖到 —— 特效分支整个在 `cfg(any(macos, windows))` 门内，
        // Linux 根本进不去，若把主题底色写进那个 else，Linux 主窗会继续吃 conf 的写死深色。
        .background_color(tray::window_bg_color(dark));
    // A1 首帧种子腿：轻量模式销毁主窗后经托盘「打开设置」重建时，事件腿必丢（订阅还没挂上）→
    // 目标屏随文档注入。take 语义 ⇒ 消费一次即清，不会在后续重建里反复跳屏。
    if let Some(screen) = tray::take_pending_screen(app) {
        builder = builder.initialization_script(tray::tray_screen_boot_script(screen));
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    if apply_effects {
        // mac/win：真透明窗。transparent(true) 覆盖 conf 的 transparent:false；并把 conf 的方形不透明
        // backgroundColor(#0B0F14) 覆盖成**全透明**——否则该纯色底铺满方形 rect，会在前端 `.win` 14px 圆角**外**
        // 露方角。清背景后圆角轮廓由 vibrancy/Mica（radius=14）+ 前端 `.win`（--r-lg:14px）共同构成。
        builder = builder
            .transparent(true)
            .background_color(tauri::window::Color(0, 0, 0, 0));
    } else {
        // 特效关（windowEffects=false 或图形逃生门开）→ 保持 conf 的 transparent:false 实色底，但底色
        // **按主题覆写**（conf 里写死的是深色 #0B0F14）——不做上面的透明覆盖。
        // 这一支是必需的、不是可省的优化：前端 `.side`（mac）与 `.win`/`.stage`（mac 且特效开）在 CSS 里是
        // `background:transparent`，指望原生特效当底。若这里仍建透明窗而不上特效，
        // 侧栏会直接透出桌面 = 半透明穿透窗，与开关文案承诺的「纯色背景」相反。透明只为透出特效而存在，
        // 没特效就不该透明。此时不透明窗的方角由 mac 原生 decorations(true) 圆角收边；Windows 无原生圆角，
        // 关特效即方角窗——这正是 Mica 关掉后该有的样子，不再自绘伪圆角。
        log::info!(
            "窗口特效已关（windowEffects=false 或 hardwareAcceleration=false）→ 建不透明窗，实色底按 uiTheme 折算（dark={dark}）"
        );
    }
    // ── macOS 原生窗口铬（P1：交通灯点击无反应 + 窗口拖不动 根因修复）──
    // conf 的 `decorations:false` 会剥掉 mac 原生窗口控制的**功能**（styleMask 全被剥），此处翻回 true：
    // 重挂交通灯功能 + 原生标题栏拖动 + 四角原生圆角；titleBarStyle:Overlay + hiddenTitle:true 仍由 conf 套上。
    #[cfg(target_os = "macos")]
    {
        // ⚠️ 这里**不再重复设尺寸**：`from_config`（:942）已把 conf 的 width/height/minWidth/minHeight
        // 套上，mac 分支曾另写一份 `inner_size(925,740)` + `min_inner_size(760,560)` 覆盖掉它 ——
        // 于是 conf 里那四个值在 mac 上恒为死值，改 conf 不生效（陈先生 2026-07-29 真机报「没有锁定
        // 最小限制」，实测最小可缩到 760×560 而非 conf 写的值）。尺寸单一真值收回 conf。
        builder = builder
            .decorations(true)
            .resizable(true)
            // 交通灯 inset 到侧栏 .side-chrome(36px 净空)内，别贴窗角（默认 ~7,7 太贴边）。真机微调。
            .traffic_light_position(tauri::LogicalPosition::new(13.0, 18.0));
    }
    // C15/C16：start_hidden（--hidden / silentStart / 轻量前的隐藏建窗）→ 建成隐藏窗，覆盖 conf 的可见默认。
    // 靠托盘浮层的明确入口/Dock 唤出（`show_main_window`）；托盘缺失时 setup 末尾兜底显示（见 setup 无锚点分支）。
    //
    // **非 start_hidden 也一律建成隐藏窗**（门武装时）：conf 未声明 `visible` ⇒ 默认 true ⇒ 此前
    // `builder.build()` 返回那一刻窗口就在屏上，而 webview 那时才刚开始加载文档、解析 bundle、挂 React
    // —— 中间那段**空白窗**在 mac 真机实测 345–2467ms（用户报的「点图标先白屏一会儿」正是长尾那几次）。
    // 改由 `renderer:ready` 决定上屏时机（`defer_show`，超期有兜底），窗口出现即有内容。
    // 传 `None` 而非查门状态：轻量模式重建时门里还躺着被销毁那个旧文档的 ready=true。
    let defer_show = !start_hidden
        && window_health::show_timing(app, None) == window_health::ShowTiming::WhenReady;
    if start_hidden || defer_show {
        builder = builder.visible(false);
    }
    let window = builder.build()?;
    window_health::log_show_probe(app, "window-built", false);
    // Tauri 的窗口 registry 在 destroy/create 过渡期不等同于“可用 WebView”。把建窗成功作为明确的
    // 生命周期提交点，供 stats/logs 的非阻塞可见性门共享；窗口此刻仍隐藏，renderer ready 后再翻可见。
    if let Some(rt) = app.try_state::<AppRuntime>() {
        rt.stats().mark_main_window_created();
    }

    // ── 原生窗口外观跟随 `config.uiTheme`（不是跟随系统）──
    // vibrancy/Mica 的明暗由 **NSWindow/HWND 的 appearance** 决定，而不是网页里的 `data-theme`。
    // 此前从未设过窗口外观 ⇒ 原生面恒跟系统：系统深色 + 应用内选浅色时，`NSVisualEffectMaterial::Sidebar`
    // 渲染深色变体，表现为「浅色模式下侧栏透明效果是黑的」（陈先生 2026-07-29 真机报）。
    // 判定复用 [`crate::tray::native_theme_override`] —— 托盘原生面已在用同一条判据，两处各写一份必然分叉。
    // `uiTheme=system` 时显式传 `None`：交回给系统跟随，而不是把当下探到的值钉死（否则用户改系统
    // 明暗后窗口外观不跟）。
    {
        let ui_theme = tray::ui_theme(app);
        let native_theme = tray::native_theme_override(ui_theme.as_deref());
        if let Err(e) = window.set_theme(native_theme) {
            log::warn!("主窗原生外观设置失败（vibrancy 明暗可能与应用内主题不一致）：{e}");
        }
    }

    // 特效仅 mac/win；任何失败绝不 fatal——窗背景已在建窗时清成全透明，失败即无 blur，可见底改由前端 `.win`
    // 自绘兜底。特效门控：hardwareAcceleration=false（图形逃生门开启）→ 跳过，与逃生门联动一致。
    #[cfg(target_os = "macos")]
    {
        if !apply_effects {
            log::info!("窗口特效已关 → 跳过 macOS vibrancy；窗口已建为不透明实色底（见上）");
        } else {
            use window_vibrancy::{apply_vibrancy, NSVisualEffectMaterial, NSVisualEffectState};
            if let Err(e) = apply_vibrancy(
                &window,
                NSVisualEffectMaterial::Sidebar,
                Some(NSVisualEffectState::Active),
                Some(14.0),
            ) {
                log::warn!("macOS vibrancy 失败，降级纯色底：{e}");
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        if !apply_effects {
            log::info!("窗口特效已关 → 跳过 Windows Mica；窗口已建为不透明实色底（见上）");
        } else {
            use window_vibrancy::apply_mica;
            if let Err(e) = apply_mica(&window, None) {
                log::warn!("Windows Mica 失败（非 Win11），降级纯色底：{e}");
            }
        }
    }
    // Linux：不 transparent、不调用任何特效 —— WebKitGTK 无 vibrancy/Mica 等价物，特效分支根本不编译进
    // Linux 目标。故 windowEffects 在 Linux 是结构性 no-op，UI 侧同步隐藏该行（不留死开关）。
    let _ = apply_effects; // Linux：apply_effects 仅 mac/win 特效分支读

    // ── 武装 mount 健康门 ──
    // 记录应用真实 URL（任何导航发生前），供超时 reload / fatal_retry 导航回真实应用。
    if let Some(health) = app.try_state::<WindowHealth>() {
        match window.url() {
            Ok(url) => health.set_app_url(url),
            Err(e) => log::warn!("主窗 URL 捕获失败 {e}：超时重载将回退 reload()"),
        }
        if health.gate_enabled() {
            log::info!("mount 健康门已武装（等待 renderer:ready）");
        }
    }
    // 登记「等就绪再上屏」**必须早于** PageStarted 武装：兑现腿挂在 `renderer:ready` 上，意图晚于 ready
    // 到达就再也没人来兑现 = 窗口永不出现。二者都在主线程同步段内、webview 的 JS 此刻还跑不起来，本无
    // 竞态可言；这里排在前面是把「不可能」写成「结构上不可能」。
    if defer_show {
        window_health::defer_show(app);
    }
    // 窗口创建即武装：这是唯一不依赖任何平台信号的武装点（macOS/Linux 加载失败时 Started 也不触发）。
    window_health::dispatch(app, MountGateEvent::PageStarted);

    // 窗口可见性 → stats relay 门控（stats-worker 据此降流）+ 关窗语义（放行退出 / 收托盘 / 真退出）。
    // Win/Linux 另桥接原生 maximize 变化：双击拖动带 / 系统菜单 / 拖顶不会经过自绘按钮 command，
    // 只能从 WindowEvent::Resized 回读真值；AtomicBool 只在值变化时发事件，普通 resize 零噪音。
    #[cfg(not(target_os = "macos"))]
    let maximized_state = Arc::new(AtomicBool::new(window.is_maximized().unwrap_or(false)));
    #[cfg(not(target_os = "macos"))]
    let event_window = window.clone();
    let app_handle = app.clone();
    window.on_window_event(move |event| match event {
        tauri::WindowEvent::Focused(_) => {
            // **不取 focused 的值**：失焦 ≠ 隐藏。窗口失焦但仍在屏上时依然有 UI 消费者，按 focused
            // 降流会让用户看着的首页拓扑/连接明细直接冻住。Tauri 2 的 `WindowEvent` 又没有 show/hide
            // 变体，故这里只把 Focused 当「显隐可能刚变」的**即时触发器**：真值由 stats 侧回读窗口实况
            //（`is_visible() && !is_minimized()`）派生，并在变化时立刻唤醒降流中的 poller（恢复不等整拍）。
            // 不发 Focused 的显隐（如托盘在窗口本就失焦时隐藏它）由 poller 每拍的实况回读兜底。
            refresh_stats_visibility(&app_handle);
        }
        #[cfg(not(target_os = "macos"))]
        tauri::WindowEvent::Resized(_) => match event_window.is_maximized() {
            Ok(maximized) => {
                if commit_maximized_observation(&maximized_state, maximized) {
                    commands::window::emit_window_maximize_changed(&app_handle, maximized);
                }
            }
            Err(e) => log::warn!("回读主窗最大化状态失败，标题栏图标可能暂时不同步：{e}"),
        },
        // 关闭主窗语义：判定收在纯函数 [`resolve_close_action`]（含 #10 的 `config.minimizeToTray`
        // 门控），此处只执行。托盘存在与否 + minimizeToTray **都动态查**：本闭包在托盘 setup 前也可能
        // 装上（首建），且设置改完须即时生效——不捕获任何陈旧快照。
        tauri::WindowEvent::CloseRequested { api, .. } => {
            let quitting = app_handle.state::<QuitState>().0.load(Ordering::SeqCst);
            let tray_present = app_handle.tray_by_id("main").is_some();
            match resolve_close_action(quitting, tray_present, config_minimize_to_tray(&app_handle))
            {
                CloseAction::AllowClose => {}
                CloseAction::EnterLightweight => {
                    api.prevent_close();
                    // 明确点“关闭”与最小化分流：前者进入轻量驻留，后者仍只 minimize。暂存层已经
                    // 持久化到 localStorage，可跨 WebView 重建恢复；正在编辑但尚未提交的弹窗草稿按
                    // 关闭窗口语义丢弃。自动轻量开关只控制 idle 触发，不控制本条显式关闭腿。
                    //
                    // W18（2026-08-19 真机）：**不得在本回调帧内同步销毁 WebView2**。Windows 上
                    // CloseRequested 跑在窗口自身 close 消息的分发栈里，帧内 `destroy()` 主窗 +
                    // 托盘浮层两个 WebView 会把消息泵楔死——症状：首实例托盘全无响应，双击桌面
                    // 再起一个进程、双托盘图标、主窗谁也弹不出，只能任务管理器全杀。帧内只做两件
                    // 轻事：挡关闭 + 立即隐藏（视觉即时关闭）；转场销毁排到帧外——先跳 async
                    // 线程再 `run_on_main_thread` 排回事件循环（注意：从主线程调
                    // `run_on_main_thread` 是内联直执，不跳线程等于没排）。排队失败只 warn：主窗
                    // 已隐藏、可经托盘唤出重建，不比不修差。
                    if let Some(win) = app_handle.get_webview_window("main") {
                        let _ = win.hide();
                    }
                    let h = app_handle.clone();
                    tauri::async_runtime::spawn(async move {
                        let h2 = h.clone();
                        if let Err(e) = h.run_on_main_thread(move || {
                            // F2 复核（评审）：排队期间（极端调度饥饿下）用户可能已把主窗唤回
                            // （show_main_window 对未销毁的窗走 present）。此刻可见 = 用户意图
                            // 已翻盘，放弃本轮销毁——LightweightState 由转场本体置位，跳过即
                            // 无需回滚。idle 巡检腿对同一函数有同款复核，这里补齐对称。
                            if let Some(win) = h2.get_webview_window("main") {
                                if win.is_visible().unwrap_or(false) {
                                    log::info!(
                                        "轻量转场复核：主窗在排队期间被重新唤出，放弃本轮销毁"
                                    );
                                    return;
                                }
                            }
                            crate::tray::enter_lightweight_transition(h2);
                        }) {
                            log::warn!("轻量转场排队失败（主窗已隐藏，可经托盘唤出重建）：{e}");
                        }
                    });
                }
                CloseAction::QuitApp => {
                    // 置 QuitState 再退：这条腿现在也会在**托盘在**时触发（用户选了「退出应用」），
                    // 而 `ExitRequested` 的 C16 轻量守卫判据是 `lightweight && !quitting && 托盘在`
                    // —— 不置位的话，一个陈旧的 lightweight 置位会把用户的真退出 `prevent_exit` 掉。
                    app_handle
                        .state::<QuitState>()
                        .0
                        .store(true, Ordering::SeqCst);
                    app_handle.exit(0);
                }
            }
        }
        // 系统明暗切换 → Win/Linux 按新主题重选黑/白托盘图标（无 template 自动反色机制）。
        // 经汇流点（回读真值），故主题切换顺带也修正一次可能已漂移的连接态图标。
        #[cfg(not(target_os = "macos"))]
        tauri::WindowEvent::ThemeChanged(_) => {
            reconcile_tray(&app_handle);
        }
        _ => {}
    });
    Ok(())
}

/// Tauri command 注册表：Polaris IPC channels → `#[tauri::command]`。
///
/// 语法：Tauri 2 的 `generate_handler![]`（与 Tauri 1 一致；插件 API 改了，handler 宏未变）。
/// 命令名 = Rust fn 名（snake_case），前端经 `invoke('proxy_start', { config })` 调用（camelCase 自动转换）。
fn main() {
    // ── C15 CLI 早退 + 启动模式（在起 Tauri GUI 之前）──
    // version/help/headless 早退在 Tauri GUI 初始化之前跑（对齐 上游：早于 requestSingleInstanceLock/whenReady），
    // 避免 headless 环境（SSH/CI 无 DISPLAY）走到 WebKitGTK 初始化崩溃/segfault。
    let args: Vec<String> = std::env::args().collect();
    #[cfg(target_os = "linux")]
    let has_display =
        std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some();
    #[cfg(not(target_os = "linux"))]
    let has_display = true;
    let arg_hidden = match resolve_startup(&args, has_display) {
        StartupAction::Version => {
            println!("Polaris {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        StartupAction::Help => {
            print!("{}", cli_help_text());
            return;
        }
        StartupAction::HeadlessExit => {
            eprintln!(
                "Polaris requires a graphical display (no DISPLAY/WAYLAND_DISPLAY found). Start it from a desktop session."
            );
            std::process::exit(1);
        }
        StartupAction::Run { hidden } => hidden,
    };

    // ── 原生对话框语言对账（macOS-only；**必须早于 `tauri::Builder`**）──
    //
    // 把 `config.language` 写进本应用 UserDefaults 域的 `AppleLanguages`，让 NSOpenPanel /
    // NSAlert 等 AppKit 自绘的原生 UI 跟随**应用内**语言而非系统语言。为什么这个位置不可挪、
    // 挪到 `setup` 会让用户要重启两次 —— 见 `app_language` 模块文档；顺序由 `main.rs` 的
    // `native_dialog_language_is_applied_before_appkit_boots` 守卫钉住。
    //
    // `generate_context!()` 提到这里（原先内联在 `.build()` 的实参位）**只为拿 identifier**：
    // 配置路径要用它，而在 `AppHandle` 存在之前只有 context 认得这个值。写死一份
    // "com.polaris.app" 也能跑，但 identifier 一改就静默读空 —— 那正是本模块最难发现的失效形态。
    // 放在 CLI 早退**之后**：`--version` / `--help` / headless 不该为此多做任何事。
    let ctx = tauri::generate_context!();
    app_language::apply_process_language(&ctx.config().identifier);

    // tauri-plugin-single-instance 2.4.3 的 Windows mutex→监听窗之间有 TOCTOU：并发第二实例可在
    // `FindWindowW == null` 时直接穿过插件并完整启动。仅 Windows 在 build 前取一把短生命周期闸门，
    // 插件 setup 完成且官方监听窗已验证后才释放；Linux/macOS 的官方后端不走这条实现。
    #[cfg(target_os = "windows")]
    let single_instance_identifier = ctx.config().identifier.clone();
    #[cfg(target_os = "windows")]
    let single_instance_startup_gate =
        match windows_single_instance::StartupGate::acquire(&single_instance_identifier) {
            Ok(gate) => gate,
            Err(error) => {
                eprintln!("Polaris single-instance startup gate failed: {error}");
                return;
            }
        };

    let app = tauri::Builder::default()
        // ── C2 单实例锁 ──
        // **必须第一个注册**：第二次启动的进程要在其它插件初始化前把 argv 交给首实例并自退，避免双开
        // 双核抢 TUN/端口。回调在**已存在的首实例**里触发（不在第二实例里）→ 召回并聚焦主窗，
        // 让「再点一次图标」表现为「把窗拉回前台」。
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            show_main_window(app);
        }))
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec!["--autostart"]),
        ))
        // ── 自定义应用图标 scheme（polaris-icon://）──
        //
        // 缓存路由 `c/<file>` 读 `<userData>/icons/` 本地副本（正常渲染零出站，隐私第一性）；
        // 远端路由 `i/<enc-url>` 经传输层单点拉取（URL 面板预览 / 未迁移旧 remote iconUrl，一次性）。
        // 见 `icon_cache` 模块文档。内置 / 解锁图标是随包 SVG，不经此 scheme。
        .register_asynchronous_uri_scheme_protocol(
            icon_cache::ICON_PROXY_SCHEME,
            |ctx, request, responder| {
                icon_cache::handle_scheme_request(
                    ctx.app_handle().clone(),
                    request.uri().clone(),
                    responder,
                );
            },
        )
        // ── mount 健康门的页面事件接线（C 类白屏侦测）──
        //
        // 只用 `Started`（= 新文档开始加载 → 重新武装），**刻意不用 `Finished`**：Windows 上 wry 丢弃了
        // NavigationCompleted 的 IsSuccess/WebErrorStatus（`wry/src/webview2/mod.rs:659-670`），加载失败
        // 照样上报 Finished → 用它判成功会误判。武装的**主**入口在 setup 内（窗口创建即武装），因为
        // macOS/Linux 上加载失败连 Started 都不触发（挂在 didCommitNavigation / LoadEvent::Committed）。
        .on_page_load(|webview, payload| {
            if webview.label() == "main"
                && payload.event() == tauri::webview::PageLoadEvent::Started
            {
                window_health::dispatch(webview.app_handle(), MountGateEvent::PageStarted);
                // 导航开始 = 旧 JS 上下文连同它的 stats / logs 页面订阅一起作废，但它已经没机会再发
                // unsubscribe 了。而 registry 按 **webview label** 记账，reload 后 label 仍是
                // "main" → 旧 token 无人退订 → 订阅计数永远 ≥1 → `stop_*_poller` 的计数闸门恒拦 →
                // poller 永久 1s gRPC 轮询、日志 emitter 永续拉环。故在此主动清两类账；新上下文
                // mount 后会按当前页面自行重订。
                // 触发面：白屏自愈 reload / 用户手动刷新 / dev 热重载。
                if let Some(rt) = webview.app_handle().try_state::<AppRuntime>() {
                    rt.stats().clear_window("main");
                }
                commands::misc::clear_log_stream_window("main");
            }
        })
        .setup(move |app| {
            // 配置目录：<app_config_dir>/polaris/（对齐 上游 `app.getPath('userData')`）。
            let config_dir = app
                .path()
                .app_config_dir()
                .map(|p| p.join("polaris"))
                .unwrap_or_else(|e| {
                    log::warn!("app_config_dir 解析失败 {e}，回落 cwd/polaris");
                    std::path::PathBuf::from("./polaris")
                });
            // 确保目录存在（首次启动）。
            let _ = std::fs::create_dir_all(&config_dir);
            // 日志 sink 必须最先装：在此之前所有 log::* 都是静默 no-op（`log` 只是门面）。
            logging::init(&config_dir);
            log::info!(
                "polaris 启动：config_dir={}, platform={:?}",
                config_dir.display(),
                Platform::current()
            );
            // Windows 旧版 QUIC 防火墙规则是一次性迁移残件，不是每次连接的成立条件。尽早在后台
            // 清理，让 System 模式 enable 只承担注册表事务；stop/restore 仍保留同一清理兜底。
            let quic_cleanup_prewarmed =
                polaris_system_integration::proxy_ops::start_windows_quic_cleanup_prewarm();
            if quic_cleanup_prewarmed {
                log::info!("Windows QUIC 旧规则清理已移入启动预热");
            }
            // 原生对话框语言对账的结果补报（它跑在 `logging::init` 之前，那时 `log::*` 还是
            // 静默 no-op）。它的失败形态全是「悄悄什么都没做」，没有这一句真机上就没有任何证据。
            app_language::log_startup_outcome();

            // ── 图形兼容逃生门（D 类合成层白屏自救）──
            // 必须在**首个 webview 创建之前**：各平台 runtime 只在创建 webview 那一刻读 GPU 环境变量。
            // 读 config.json 原文本而非走 store：此刻 store 尚未装配，且逃生门必须在「配置损坏到 store
            // 都加载不了」时仍能工作。容错第一 —— 任何异常一律回落「默认全开 = 行为不变」。
            let raw_config = graphics_compat::read_config_raw(&config_dir);
            // ── U-7 判据基线：本次进程**启动时真正读到的**三个值 ──
            // 必须在这里定格，而不是让渲染端拿「上一次保存值」当基线。反例：进程以 hardwareAcceleration=true
            // 起来 → 用户关掉（弹窗，点「稍后」）→ 又打开 ⇒ 若与上次保存值比就再弹一次，可此刻磁盘值已等于
            // 启动值、重启什么都不会变。用户要么白重启一次（**会断代理**），要么学会无视这个弹窗 —— 后者
            // 直接废掉 U-7 的全部价值。
            // 语义方向统一为 `UserConfig` 的「该功能是否开」（与渲染端 `effectiveValue` 同口径），
            // 而非各自判定函数的「是否禁用/是否上特效」，避免两侧各记一次反相。
            app.manage(StartupConfigFlags {
                hardware_acceleration: !graphics_compat::should_disable_hardware_acceleration(
                    raw_config.as_deref(),
                ),
                window_effects: graphics_compat::should_apply_window_effects(raw_config.as_deref()),
                remember_window_size: config_remember_window_size(raw_config.as_deref()),
            });
            // 图形逃生门：hardwareAcceleration=false → 设 GPU 环境变量（软件渲染）。必须在**首个 webview 创建
            // 之前**：各平台 runtime 只在建 webview 那一刻读 GPU 环境变量。窗口 vibrancy/Mica 的同一判定在
            // `create_main_window` 内按同源 raw config 重算（特效关时**不** apply，避免与逃生门叠加合成负担）。
            graphics_compat::apply_hardware_acceleration_escape(
                graphics_compat::should_disable_hardware_acceleration(raw_config.as_deref()),
            );

            // ── 可写现役核基目录注入（**必须早于任何起核路径**）──
            // `resolve_core_binary()` 是自由函数（无 AppHandle），故基目录经进程级 OnceLock 注入。
            // 未注入时它恒回落随包种子 —— 行为安全，但换核/回滚会报 CORE_DIR_UNAVAILABLE。
            runtime::core_paths::init_base_dir(config_dir.clone());

            // ── 内置 geo 规则集播种（调用点 1/2：应用启动；对齐 上游 `index.ts:1834`）──
            // 不种 → `<userData>/rules` 恒空 → route builder 一个 rule_set 都不注入 → 全部 geo 规则被
            // fail-closed 剪掉。**必须早于任何起核路径**（自动连接就在 setup 尾巴上）。
            // 幂等 + best-effort：已有有效副本跳过，失败只记日志不阻断启动。
            //
            // **启动这次（且只有这次）开出厂态刷新**（`refresh_out_of_box`，对齐 上游
            // `index.ts:1834` 的 `refreshOutOfBox: true`）：此刻无并发的规则资源更新，刷新落地无竞态。
            // 不开这条，「装 v1 → 播种 → 升 v2（随包带新 geo 数据）」的出厂态用户会永久冻结在 v1。
            // 出厂态判据取自同一份 raw config 的 `builtinGeoMeta`（上面图形逃生门已读过，不重复 IO）。
            runtime::geo_seed::seed_builtin_rule_sets_into(
                &config_dir,
                "启动",
                &runtime::geo_seed::SeedOptions {
                    network_updated_tags: runtime::geo_seed::network_updated_tags_from_raw(
                        raw_config.as_deref(),
                    ),
                    refresh_out_of_box: true,
                },
            );

            // 装配 18 crate 运行时（注入 tokio / std::fs / 真 socket / 真 HTTP client）。
            // 传输层 client 建不起来 = 网络栈残缺 → 报错退出（? 冒泡给 setup），不带病硬跑。
            let app_runtime = AppRuntime::new(config_dir)?;

            // ── 版本感知 reseed：随包核 → 可写现役核（幂等；**失败不 fatal**）──
            // 失败即回落随包种子照常起核（`resolve_core_binary` 第 3 级）⇒ 首启/迁移永不 brick。
            // 覆盖判据是纯函数 `decide_reseed`（fork/unknown/更新的核**绝不覆盖**），见 core_paths。
            match runtime::core_paths::ensure_writable_core(
                app_runtime.updater().bundled_core_version(),
            ) {
                Ok(p) => {
                    // 把现役核路径注入 UpdaterRuntime（版本双读法的探测目标；此前只认
                    // POLARIS_SINGBOX_PATH，导致非开发态恒报「未知版本」）。
                    app_runtime.updater().with_core_binary(p);
                }
                Err(e) => log::warn!("可写现役核播种失败（{e}）：回落随包核，换核功能将不可用"),
            }
            // ── C1 启动期系统代理崩溃恢复 ──
            // 上次若带系统代理退出却未清（崩溃/强杀/panic → marker 残留），早期清掉「仍指向上个已死端口的
            // 系统代理」，防本次启动前用户全网断连。marker 门控：正常 fresh start 无 marker → 零系统调用、
            // 即时返回；只有崩溃恢复路径付 exec 代价。**阻塞**跑在 UI 加载前，确保用户不带残留断网态入场。
            tauri::async_runtime::block_on(app_runtime.proxy.recover_system_proxy_on_startup());
            // ── C4 WARP 待注销队列 drain ──
            // 启动清上次会话遗留的孤儿 WARP 设备 + 定时 drain，防孤儿计费。装配点即此（AppRuntime::new
            // 之后、manage 之前）；`mesh`/`http` 是 pub Arc 字段。
            app_runtime
                .mesh
                .clone()
                .spawn_warp_drain(app_runtime.http.clone());
            // `event:proxyError` 接线：崩溃自愈跑在后台 task（无人 await），失败只能靠事件告知渲染端；
            // 而 `AppHandle` 要到此刻才有 → 运行时「先构造、后接线」（见 ProxyRuntime::error_emitter）。
            // **必须在 manage 之前**：manage 移走所有权后就只能经 State 再借，绕一圈无谓。
            app_runtime.proxy.set_error_emitter(Box::new(
                runtime::proxy::AppHandleProxyErrorEmitter {
                    app: app.handle().clone(),
                },
            ));
            app.manage(app_runtime);
            app.manage(WindowHealth::new());
            // 退出意图标记（关窗语义分流用），默认 false = 关窗按 hide/兜底走。
            app.manage(QuitState(AtomicBool::new(false)));
            // C16 轻量模式转场标记，默认 false = 非轻量销毁；进轻量前置真，供 ExitRequested 守卫保核。
            app.manage(LightweightState(AtomicBool::new(false)));
            // Q1-b ④：「本次退出是 app:restart 发起的」，默认 false = 真退出（照落正常退出标记）。
            app.manage(RestartState(AtomicBool::new(false)));
            // 正常 ExitRequested + 最终 Exit（以及 macOS 仅最终 Exit）共用的一次性退出收尾门。
            app.manage(exit_lifecycle::ExitCleanupState(AtomicBool::new(false)));
            // 托盘运行期状态（自绘浮层去抖 + 轻量重建时的待导航目标；Linux 虽不建浮层仍要后者）。
            app.manage(tray::TrayOverlay::default());
            // 同步托盘 warm 偏好。必须在 TrayOverlay manage 后执行；缺省 true，待托盘创建成功后后台预建。
            tray::reconcile_overlay_retention(app.handle());

            // ── 订阅自动更新调度器（启动补更 8s + 周期巡检 30min + 代理就绪补更）──
            // 装在 AppRuntime manage 之后（运行期经 State 取 config/proxy/http）。managed 保活；
            // 内部定时器/事件接线为薄壳，决策逻辑纯函数单测覆盖。UI autoUpdate 开关据此生效（否则死装饰）。
            let scheduler =
                std::sync::Arc::new(runtime::subscription_scheduler::SubscriptionScheduler::new());
            scheduler.start(app.handle().clone());
            app.manage(scheduler);

            // ── 规则资源自动更新调度器（启动补更 12s + 周期巡检 30min）──
            // 装法与订阅调度器同构；12s 刻意错开订阅的 8s 启动高峰。UI 的
            // ruleResourceAutoUpdate / ruleResourceUpdateIntervalHours 据此生效（此前零消费者 = 死开关）。
            let rule_res_scheduler =
                std::sync::Arc::new(runtime::rule_resource_scheduler::RuleResourceScheduler::new());
            rule_res_scheduler.start(app.handle().clone());
            app.manage(rule_res_scheduler);

            // ── 内核自动更新调度器（启动 30s + 6h 巡检 + 24h due + 代理停止后 5s 落位）──
            // 装法与上面两个调度器同构。**30s 启动延迟刻意最靠后**：错开 startup_tasks 的
            // 2s 自动连接 / 3s 出口 IP / 5s App 更新检查 / 6s 内核基线 / 7s helper 可升级，
            // 以及订阅 8s、规则资源 12s（= 上游 `CoreUpdateScheduler.STARTUP_DELAY_MS` 的原始理由）。
            // 它是唯一会**替换内核二进制**的后台腿，总开关 `autoUpdateCore` **缺省关**；
            // 落位只在代理未运行时发生（绝不主动断流），跨带只提示不自动更新。
            let core_update_scheduler =
                std::sync::Arc::new(runtime::core_update_scheduler::CoreUpdateScheduler::new());
            core_update_scheduler.start(app.handle().clone());
            app.manage(core_update_scheduler);

            // ── 自动轻量模式窗口驻留巡检（隐藏 / 最小化 10 分钟，30s 一拍）──
            // 计时**必须在主进程**：原实现挂在主窗 renderer 里，等于让那个正要被回收的 webview
            // 自己判断自己该不该被回收 —— 隐藏窗的 visibilityState 依平台、定时器又被 WKWebView
            // 节流，mac 上因此两条腿全断（根因见 `idle_lightweight` 头注）。
            // 无需 manage：它不持外部可见状态，句柄只在自己的 task 里。
            idle_lightweight::start(app.handle().clone());

            // ── 记忆窗口大小（#11：config.rememberWindowSize）──
            // **按配置 gate 的运行期插件注册**（`AppHandle::plugin`，tauri 2.11 支持）：开启才注册，
            // 关闭时**完全不注册** → 窗口尺寸行为逐字节保持现状（而不是注册后再想办法让它别生效）。
            // 必须在 `create_main_window` 之前：插件靠 `on_window_ready` 钩子恢复尺寸，窗口建完才注册就赶不上。
            // denylist 排掉全部非主窗（托盘自绘浮层 / 更新 mini 弹窗 / sing-box 面板外链窗）——它们的
            // 尺寸位置由各自逻辑精确控制（浮层要贴托盘图标、弹窗按四态高度自适应），被插件恢复会错位。
            if config_remember_window_size(raw_config.as_deref()) {
                use tauri_plugin_window_state::StateFlags;
                let plugin = tauri_plugin_window_state::Builder::new()
                    .with_state_flags(StateFlags::SIZE | StateFlags::POSITION)
                    .with_denylist(&[
                        tray::TRAY_LABEL,
                        runtime::update_popup::POPUP_LABEL,
                        // `commands::misc` 里的 DASHBOARD_WINDOW_LABEL 是私有常量，此处按字面同步；
                        // 改那边的 label 需一并改这里（两处都只此一份引用）。
                        "singbox-dashboard",
                    ])
                    .build();
                if let Err(e) = app.handle().plugin(plugin) {
                    log::warn!("window-state 插件注册失败，窗口尺寸不记忆（非致命）：{e}");
                }
            }

            // ── 建主窗（C15 start_hidden）──
            // 建窗全流程（per-platform 窗口铬 / vibrancy·Mica 特效 / 白屏自愈门 / 可见性·关窗事件接线）收在
            // `create_main_window` 一处——供 C16 轻量模式**销毁 webview 后重建**复用（重建与首建逐字节等价）。
            // start_hidden = `--hidden`（argv）或 `config.silentStart`（读原文本，与逃生门同源）：启动即隐藏、
            // 只驻托盘，靠托盘浮层明确入口/原生菜单/Dock 唤出；托盘缺失时 setup 末尾兜底显示（见下方分支）。
            let start_hidden = arg_hidden || config_silent_start(raw_config.as_deref());
            if start_hidden {
                log::info!(
                    "start_hidden 启动（--hidden 或 silentStart）：主窗建成隐藏，靠托盘浮层入口/Dock 唤出"
                );
            }
            create_main_window(app.handle(), start_hidden)?;

            // ── 启动期延迟任务（#9 自动连接 2s / 自动检查更新 5s + #17 内核基线提醒 6s）──
            // 挂在建窗**之后**（对齐 上游 whenReady 内的两个 setTimeout：窗口/服务先就位再连）。
            // 三条腿全 fire-and-forget，任何失败只记日志，绝不阻断启动。
            runtime::startup_tasks::spawn(app.handle().clone());

            // ── 主窗应用菜单：仅 macOS 交给系统顶栏 ──
            // macOS 系统菜单提供 ⌘Q，并补 Edit 子菜单保住文本框 ⌘Z/⌘X/⌘C/⌘V/⌘A
            //（set_menu 会替换 Tauri 默认 mac 菜单）。Win/Linux 若挂同一棵菜单，GTK/窗口系统会在
            // 自绘主窗内额外生成「Polaris」横栏；故这两个平台根本不创建 app menu，Ctrl+Q 由
            // `AppShell` 复用 `tray_quit` 处理。Linux 原生托盘菜单属于下方 tray 分支，不受此决策影响。
            if main_window_menu_owner(Platform::current())
                == MainWindowMenuOwner::NativeApplicationMenu
            {
                use tauri::menu::{Menu, MenuItem, Submenu};
                let h = app.handle();
                // 应用菜单在 `setup` 里**只建一次**、不随语言重建（托盘菜单有 30s 汇流点，它没有）。
                // 改语言后这一项要下次启动才跟上 —— 与 `app_language.rs` 承诺的「改语言重启一次」
                // 同一档语义，不另立一条更强的承诺。
                let quit = MenuItem::with_id(
                    h,
                    "app_quit",
                    crate::i18n::t(crate::i18n::app_lang(h), crate::i18n::key::TRAY_QUIT),
                    true,
                    Some("CmdOrCtrl+Q"),
                )?;
                let app_menu = Submenu::with_items(h, "Polaris", true, &[&quit])?;
                let menu = {
                    use tauri::menu::PredefinedMenuItem;
                    let edit = Submenu::with_items(
                        h,
                        "Edit",
                        true,
                        &[
                            &PredefinedMenuItem::undo(h, None)?,
                            &PredefinedMenuItem::redo(h, None)?,
                            &PredefinedMenuItem::separator(h)?,
                            &PredefinedMenuItem::cut(h, None)?,
                            &PredefinedMenuItem::copy(h, None)?,
                            &PredefinedMenuItem::paste(h, None)?,
                            &PredefinedMenuItem::select_all(h, None)?,
                        ],
                    )?;
                    Menu::with_items(h, &[&app_menu, &edit])?
                };
                h.set_menu(menu)?;
                h.on_menu_event(|app, event| {
                    if event.id.as_ref() == "app_quit" {
                        app.state::<QuitState>().0.store(true, Ordering::SeqCst);
                        app.exit(0);
                    }
                });
            }

            // ── 系统托盘（mac/win：左/右键统一切换自绘浮层；Linux：完整原生菜单）──
            // conf.trayIcon 已在 setup 前自动建好**单个**托盘（id "main" / 默认图标 tray-off-black.png=断开态空心星+单斜杠 /
            // iconAsTemplate:true=mac 断开态首帧即走系统自适应反色·Win/Linux 忽略 / tooltip）；
            // 此处取回它挂接点击行为与原生菜单，而非再 build 第二个——Tauri 每次 build 各向 OS 推一枚
            // 图标（tray/mod.rs push 非按 id 覆盖），双 build 会出现两枚。
            // `tray_present` 决定关窗语义：托盘在 → hide 收纳；托盘缺失 → 关窗即真退出（不留僵尸）。
            let handle = app.handle();
            let tray_present = if let Some(tray) = handle.tray_by_id("main") {
                use tauri::tray::TrayIconEvent;

                match tray_interaction_mode(Platform::current()) {
                    TrayInteractionMode::NativeMenu => {
                        // Linux AppIndicator 不派发可靠的左右键事件，完整原生菜单是唯一稳定功能面。
                        // 菜单树只由 reconcile_tray_menu 构建，状态/语言变化仍走统一汇流点，setup 不另造副本。
                        reconcile_tray_menu(handle);
                        tray.on_menu_event(|app, event| {
                            if let Some(action) = parse_menu_action(event.id.as_ref()) {
                                run_menu_action(app, action);
                            }
                        });
                    }
                    TrayInteractionMode::DirectClicks => {
                        // macOS/Windows 的左/右键必须只归自绘浮层所有。Tauri 没暴露「禁用右键菜单」开关，
                        // 但底层在 menu=None 时不会弹 NSMenu/HMENU，右键事件仍照常派发；同时关闭 mac 默认的
                        // 左键菜单行为。两步都做，避免未来配置误挂菜单后重新抢走事件。
                        if let Err(e) = tray.set_menu(None::<tauri::menu::Menu<tauri::Wry>>) {
                            log::warn!("移除非 Linux 托盘原生菜单失败（自绘浮层可能被抢占）：{e}");
                        }
                        if let Err(e) = tray.set_show_menu_on_left_click(false) {
                            log::warn!("关闭托盘左键原生菜单失败（自绘浮层点击可能被抢占）：{e}");
                        }
                    }
                }

                // macOS/Windows：左键、右键（mac 双指辅助点按同样归为 Right）抬起都
                // toggle 自绘浮层，不再把托盘图标点击解读为突然唤出主窗。主窗只由浮层里的明确入口唤出。
                // Linux 即使某个 host 偶发派发事件，判定也会拒绝，避免与原生菜单叠开。
                // `rect` 是图标真实屏幕矩形，用于浮层定位。
                //
                // 「拖动托盘图标 → 浮层跟隐藏」为何不在此接：`TrayIconEvent` 只有 Click/DoubleClick/Enter/
                // Move/Leave，**无专门的拖动事件**；Move/Leave 在**普通 hover**（鼠标从图标移到浮层）时也照
                // 触发，且不带按钮状态无法区分「拖动」与「划过」→ 拿来 hide 会误关浮层。故不接（避免又一个
                // 不可靠通道）。点窗外的隐藏由浮层 `Focused(false)` 覆盖（见 tray::window::build_overlay）；「mac 上
                // Cmd 拖动菜单栏图标时浮层是否失焦」本机（Linux）验不了 → 列入真机待验（见 review-queue）。
                tray.on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button,
                        button_state,
                        rect,
                        ..
                    } = event
                    {
                        if tray_click_toggles_overlay(
                            Platform::current(),
                            button,
                            button_state,
                        ) {
                            crate::tray::toggle_overlay(tray.app_handle(), Some(rect));
                        }
                    }
                });

                // ── 托盘图标 + Linux 原生菜单随状态刷新（图标四态见 set_tray_state）──
                // 全部驱动源收敛到 `reconcile_tray` 这一个叫醒入口（内部两个汇流点各自回读真值 + 幂等短路，
                // 不信事件携带的布尔）——见 `reconcile_tray_icon` / `wire_tray_icon_sync` 的文档：此前只订
                // STARTED/STOPPED 并传字面量，崩溃腿（只发 ERROR）与零 emit 腿（restart 失败 / updater 停核 /
                // 休眠唤醒）会把图标永久卡在实心，必须等用户下一次手动启停才回正。
                //
                // 三个入口：① setup 初始化一次（autostart 已起核则纠正为实心）；② 四条同步事件
                // （三条代理终态 + CONFIG_CHANGED，后者喂菜单的勾选与语言）；③ 30s 自愈轮询（兜未知缺口，
                // 对齐主窗 App.tsx:210-213 的同款网）。
                {
                    use tauri::Listener;
                    // macOS 菜单栏位置持久化（#313b）：给 NSStatusItem 钉 autosaveName。
                    // 必须在托盘已存在之后、且**只做一次** —— 放这里而不是 `reconcile_tray` 里面，
                    // 因为那两个汇流点挂着 30s 自愈轮询与四条事件，每次都重设是纯浪费；
                    // 而这个属性一旦设上就跟着 NSStatusItem 活到进程退出，没有被谁改回去的路径。
                    crate::tray::pin_tray_autosave_name(handle);
                    reconcile_tray(handle);
                    wire_tray_icon_sync(
                        // `listen_any` 捕获 `emit` 广播（不限 target），任何发射点都触发。
                        |ev| {
                            let h = handle.clone();
                            handle.listen_any(ev, move |_| {
                                // 只在配置变更事件同步 warm 偏好；不能放进下面 30s 自愈轮询，否则会不断
                                // 重排隐藏回收计时器。其它托盘视觉/菜单仍统一走 reconcile_tray。
                                if ev == crate::events::channel::EVENT_CONFIG_CHANGED {
                                    crate::tray::reconcile_overlay_retention(&h);
                                }
                                reconcile_tray(&h);
                            });
                        },
                        |every| {
                            let h = handle.clone();
                            // 常驻自愈任务：随 app 生命周期存活（无退出信号——进程退出即随之消亡）。
                            tauri::async_runtime::spawn(async move {
                                loop {
                                    tokio::time::sleep(every).await;
                                    reconcile_tray(&h);
                                }
                            });
                        },
                    );
                }
                true
            } else {
                log::warn!(
                    "系统托盘未创建（conf.trayIcon 缺失 / StatusNotifier 或 appindicator 不可用）"
                );
                false
            };

            // 默认 warm：托盘锚点存在后立即后台预建 hidden renderer，ready 后仍不展示/不抢焦点，首次点击
            // 直接热开；用户关掉 `keepTrayMenuWarm` 才恢复首次按需冷建 + 隐藏 2 分钟后回收。偏好与主窗口
            // 轻量模式完全独立。Linux 的点击归原生菜单所有，不创建这块 WebView。
            if tray_present {
                tray::prewarm_overlay_if_enabled(app.handle());
            }

            // C15：start_hidden 但托盘缺失（Linux 无 StatusNotifier）→ 无唤出锚点，**必须**显示主窗，否则
            // 窗口永远隐藏且无处唤起 = 死界面。托盘在则保持隐藏（靠主激活/原生菜单/dock 唤出）。窗口可见性 → stats
            // 门控 + 关窗语义的接线已在 `create_main_window::on_window_event`（首建/重建同一处）。
            if start_hidden && !tray_present {
                log::info!("start_hidden 但托盘缺失 → 显示主窗（无隐藏唤出锚点，否则死界面）");
                // 走 `show_main_window` 而非直接 show：与托盘/dock 唤出同一条上屏时机判定（内容没就绪
                // 就等 `renderer:ready`），别在这条兜底腿上把空窗漏出去。窗此刻必存在，不会触发重建腿。
                show_main_window(app.handle());
            } else if start_hidden {
                // 有托盘唤出锚点时才进入真正的「只驻托盘」形态；否则上方兜底必须保留 Dock。
                set_macos_dock_visible(app.handle(), false);
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // ── 配置类（config:get/save/setValue/updateMode + privacy）──
            config_get,
            config_save,
            config_patch,
            config_mutate_entities,
            config_classify_staged,
            config_set_staged_pending,
            // D14：IPC 通道 config:updateMode 已随 D12 从前端退役，但本命令仍被
            // app_tray.rs 的 MenuAction::Routing 分支直接 Rust 内部调用 → 不删，保留注册。
            config_update_mode,
            config_set_value,
            config_get_privacy_mode,
            config_set_privacy_mode,
            privacy_has_password,
            privacy_set_password,
            privacy_unlock,
            // ── 节点类（server:add/update/delete/deleteBatch/switch/generateUrl）──
            server_add,
            server_add_bulk,
            server_update,
            server_delete,
            server_delete_batch,
            server_switch,
            server_generate_url,
            // ── mesh 节点（warp + tailscale）──
            warp_register,
            warp_apply_license,
            tailscale_login,
            tailscale_login_cancel,
            tailscale_logout,
            tailscale_state_exists,
            tailscale_get_status,
            // ── OpenConnect / OpenVPN rc.2 原生状态与认证 ──
            vpn_get_status,
            openconnect_submit_auth_form,
            openconnect_submit_auth_browser,
            openconnect_cancel_auth,
            openvpn_submit_challenge,
            openvpn_cancel_challenge,
            // ── Taildrop 收件箱（sing-box 1.14.0-beta.15）──────────────────────
            taildrop_list,
            taildrop_mark_read,
            taildrop_delete,
            taildrop_cancel,
            taildrop_send,
            taildrop_tasks,
            taildrop_task_cancel,
            taildrop_save,
            // ── 代理控制（proxy:start/stop/getStatus + pending + connections）──
            proxy_start,
            proxy_stop,
            proxy_get_status,
            proxy_get_pending_changes,
            proxy_apply_pending_changes,
            kernel_probe_outbound,
            connections_close,
            connections_close_all,
            system_proxy_disable,
            system_proxy_get_status,
            // ── 订阅（原子 create/update/delete/updateServers/preview + localImport）──
            subscription_update,
            subscription_delete,
            subscription_update_servers,
            subscription_preview,
            subscription_create_start,
            subscription_create_status,
            subscription_create_list,
            subscription_create_cancel,
            local_import_parse,
            local_import_pick_file,
            // ── 路由规则（rules:add/update/delete/reorder）──
            rules_add,
            rules_update,
            rules_delete,
            rules_reorder,
            // ── 应用分流预设（内置表 Rust SoT 下发）──
            app_presets_list,
            // ── 自定义应用图标缓存（设定即下载到 userData，渲染零出站）──
            cache_app_icon,
            // ── 规则资源（ruleResources:*）──
            rule_resources_list,
            rule_resources_download,
            rule_resources_redownload,
            rule_resources_cancel,
            rule_resources_delete,
            rule_resources_get_catalog,
            rule_resources_refresh_catalog,
            rule_resources_get_cached_catalog,
            rule_resources_update_all,
            rule_resources_reset_builtin,
            rule_resources_update_builtin,
            rule_resources_icon_galleries,
            rule_resources_refresh_icon_galleries,
            // ── stats 订阅（stats:subscribe/unsubscribe）──
            stats_subscribe,
            stats_unsubscribe,
            stats_project_topology,
            stats_closed_clear,
            // ── 系统能力（system:listProcesses）──
            system_list_processes,
            system_list_network_interfaces,
            // ── helper（helper:getStatus/install/uninstall）──
            helper_get_status,
            helper_install,
            helper_uninstall,
            // ── 解锁检测（unlock:run/get）──
            unlock_run,
            unlock_get,
            // ── 测速（server:speedTest）──
            server_speed_test,
            // ── 更新（version + app update + core update）──
            version_get_info,
            update_check,
            update_download,
            update_install,
            update_skip,
            // D14：IPC 通道 update:openReleases 已随 D12 从前端退役，但本命令仍被
            // updater/app_update.rs 的 PopupAction::ViewLog / ManualDownload 分支直接 Rust 内部
            // 调用 → 不删，保留注册。
            update_open_releases,
            update_popup_action,
            update_popup_show,
            core_update_check,
            core_update_run,
            core_get_version_info,
            core_rollback,
            core_replace_manual,
            core_update_get_auto_status,
            core_update_apply_staged,
            core_update_ack_version_change,
            core_reset_factory,
            app_uninstall_all,
            // ── 窗口控制（window:* + app + renderer/fatal）──
            window_minimize,
            window_maximize_toggle,
            window_close,
            window_is_maximized,
            app_restart,
            app_startup_config_flags,
            app_take_clean_exit_flag,
            // ── 托盘自绘浮层（独立窗口生命周期 + 显示主窗 + 退出）──
            tray::tray_renderer_ready,
            tray::tray_resize,
            tray::tray_hide,
            tray::tray_show_main,
            tray::tray_take_pending_screen,
            tray::tray_quit,
            tray::tray_enter_lightweight,
            tray::tray_check_update,
            renderer_ready,
            fatal_retry,
            // ── 杂项（logs/shell/singbox-dashboard/backup/diagnostic/autostart/ipinfo）──
            logs_get,
            logs_search,
            logs_unsubscribe,
            logs_clear,
            logs_runtime_level,
            logs_diagnostic_state,
            logs_set_diagnostic,
            logs_export,
            logs_open_dir,
            logs_legacy_info,
            logs_archive_legacy,
            logs_delete_legacy,
            shell_open_external,
            open_singbox_dashboard,
            refresh_singbox_dashboard,
            get_singbox_dashboard_connection,
            backup_export,
            backup_import_pick,
            backup_import_apply,
            backup_get_info,
            diagnostic_export,
            auto_start_set,
            auto_start_get_status,
            ipinfo_get,
            // ── 主窗白屏自愈（mount 健康门 / 终局页重试 / renderer 日志转发）──
            // 注：renderer_ready / fatal_retry 已在上方「窗口控制」段注册，此处不重复列。
            renderer_log
        ])
        .build(ctx)
        .expect("error while building Polaris");

    #[cfg(target_os = "windows")]
    {
        if let Err(error) = windows_single_instance::verify_listener(&single_instance_identifier) {
            eprintln!("Polaris single-instance listener verification failed: {error}");
            drop(app);
            return;
        }
        drop(single_instance_startup_gate);
    }

    // RunEvent 循环：① macOS dock 图标重开 ② C1 退出清理（停核 + 清系统代理）。关窗语义仍由
    // on_window_event + QuitState 决定，未改动；本回调只在**进程级真实退出**时兜安全清理。
    app.run(|app_handle, event| match event {
        // macOS：点 dock 图标（NSApplicationDelegate applicationShouldHandleReopen）→ RunEvent::Reopen。
        // 主窗关闭进入轻量驻留后，Dock 重开是 macOS 上召回/重建窗口的路径；Windows 靠任务栏
        // 或托盘浮层的明确入口，Linux 靠原生菜单「显示」。show_main_window 会按存在性选择呈现或重建。
        // Reopen 是 **macOS-only** 的 RunEvent 变体 → cfg 门控该 arm；Linux/Windows 上 cargo check 覆盖
        // 不到它（需 mac 编译验证）。
        #[cfg(target_os = "macos")]
        tauri::RunEvent::Reopen { .. } => show_main_window(app_handle),
        // C1：任何退出请求（托盘/菜单「退出」→ app.exit、末窗关闭时托盘缺失 → exit、OS 关机/logout）
        // → 阻塞清理。不 `prevent_exit`（清完照常退出）。安全关键：见 `run_exit_cleanup` 文档。
        //
        // C16 守卫：轻量驻留中有意销毁**末窗**（主 WebView，或主窗已销毁后的空闲托盘 WebView）若触发
        // spurious ExitRequested，则必须保核——轻量语义恒不退出、代理连接不中断（对齐 上游）。判据：
        // LightweightState 由销毁方前置真（swap 消费）且非显式退出（`!QuitState`）且托盘在（有唤出锚点）
        // → `prevent_exit` + **跳过停核清理**。陈旧置位不阻断真实退出：真退出置 QuitState → 落到清理。
        tauri::RunEvent::ExitRequested { api, .. } => {
            if matches!(
                exit_lifecycle::exit_requested_action(app_handle),
                exit_lifecycle::ExitRequestedAction::PreserveLightweight
            ) {
                api.prevent_exit();
                return;
            }
            // **必须在 C16 守卫之后**：被 `prevent_exit` 的那条腿进程根本没退（轻量模式销毁主窗
            // 而已），在那儿收尾会停核，并让重建出来的 webview 把自己的编辑当「上次退出过」清掉。
            if let Some(runtime) = app_handle.try_state::<AppRuntime>() {
                // Keep create's precommit state linearizable across exit: first close its commit
                // gate and cancel it, then discard parser queue work, then wait for workers.
                // Reversing the first two lets a parser completion cross begin_commit in between.
                runtime.subscription_create().shutdown_begin();
                runtime.subscription_parse().shutdown();
                runtime.subscription_create().shutdown_wait();
            }
            exit_lifecycle::run_real_exit_once(app_handle);
        }
        // macOS 原生 `NSApplication` 终止可不经过上面的 ExitRequested；最终 Exit 是不可阻止的
        // 真实退出兜底。常规退出也会来到这里，由一次性门幂等短路，不能二次消费 RestartState。
        tauri::RunEvent::Exit => {
            if let Some(runtime) = app_handle.try_state::<AppRuntime>() {
                runtime.subscription_create().shutdown_begin();
                runtime.subscription_parse().shutdown();
                runtime.subscription_create().shutdown_wait();
            }
            exit_lifecycle::run_real_exit_once(app_handle);
        }
        _ => {}
    });
}

#[cfg(test)]
mod tests;
