//! 托盘上下文自定义 HTML 浮层（`.tray-menu` 原型的独立 WebviewWindow 宿主）。
//!
//! macOS/Windows 以它替代原生上下文菜单：托盘左键或右键（macOS 双指辅助点按归为右键）都弹出/收起这个
//! 独立窗口渲染的自绘浮层（连接状态卡 + 断开/连接 + 节点切换 + 模式 + 打开主窗 + 退出）。
//! 主窗只由浮层内的明确入口唤出。Linux AppIndicator 不派发可靠点击事件，仍由 `main.rs` 保留完整原生菜单兜底。
//!
//! # 窗口形态（对齐 `runtime::update_popup` 的独立 mini 窗模式）
//!
//! - 独立 `label`（[`TRAY_LABEL`]）+ 独立页面入口（`tray.html`），**不复用主窗 `index.html`**——
//!   否则整个 React 主应用（i18n/路由/全部 provider）会挂进这个小浮层，且主窗白屏自愈门
//!   （`window_health.rs` 只认 `label=="main"`）会对着浮层误判。
//! - frameless（`decorations:false`）+ `always_on_top` + `skip_taskbar` + 不可 resize + 初始 hidden。
//! - **透明**仅 mac/win（配合卡片圆角 + 1px 边框 + 贴菜单栏 native 间隙，无箭头「面板风」、无阴影）；**Linux 恒不透明**（透明窗在无合成器/部分 WM 下
//!   =黑块或鼠标穿透，与主窗 `transparent:false` 白屏逃生门同一顾虑）——用卡片 surface 同色实底兜底，
//!   方角可接受（对齐主窗「Linux 方窗 + 前端小圆角」既定取舍）。
//!
//! # 生命周期
//!
//! `keepTrayMenuWarm` 开启时，托盘创建完成后即在后台排队 `window::build_overlay`，renderer-ready 前始终
//! hidden；因此首次点击也只需定位+显示+聚焦。关闭 warm 时仍由首次点击登记展示意图并跳出事件帧，
//! 随后按需冷建（再点=隐藏）→
//! 点窗外/切他 app 收起：Rust `Focused(false)` + DOM `window.blur`→`tray_hide` **双路** dismiss（后者
//! 经 `initialization_script` 注入，兜 mac 上次级窗 Focused 递送不可靠，见 `window::TRAY_BLUR_DISMISS_JS`）。
//! `keepTrayMenuWarm` 默认开启：日常隐藏只收起、不自动回收，换取后续点击热开；用户关闭后，隐藏超过
//! `window::TRAY_IDLE_RECLAIM_SECS` 才销毁 WebView。此偏好与主窗口 `autoLightweightMode` 完全独立：主窗进入
//! 轻量态只释放主 WebView，不替用户改变托盘 renderer 的驻留选择。
//!
//! # 与主进程的契约（专用 command 均薄封装，供浮层 React 端 invoke）
//!
//! - [`tray_renderer_ready`]：React 首次 commit 后携冷建代次回执，只有当前代 renderer 可触发展示。
//! - [`tray_resize`]：浮层量出内容高度后回报 → 主进程设窗高（宽固定）并重定位（自适应高）。
//! - [`tray_hide`]：连接/断开/切节点后收起浮层（原生菜单选项即关的等价）。
//! - [`tray_show_main`]：显示主窗（打开主窗口/在主窗口管理）——复用 `crate::show_main_window`。
//! - [`tray_quit`]：置 `QuitState` + `app.exit(0)`——与 `main.rs` 托盘/菜单「退出」路径逐字节相同。

use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Mutex;
use std::time::Instant;

mod commands;
mod lifecycle;
mod model;
mod placement;
mod platform;
mod transition;
mod window;

// 整体 glob 再导出：8 个 `#[tauri::command]` 各自还带 `__cmd__*` / `__tauri_command_name_*` 两个
// 包装宏，而 `main.rs` 的 `generate_handler![tray::tray_*]` 是**按路径**取包装宏的（`tauri-macros`
// 的 `Handler::parse` 只替换路径末段）⇒ 逐项具名再导出会漏掉 16 个宏名。glob 与 `commands.rs`
// 顶层项一一对应，且私有的 `set_pending_screen` 不在其中。
pub use commands::*;
use lifecycle::{OverlayLifecycle, OverlayOpenProbe};
// `normalize_tray_screen` 随 `tray_show_main` 一起离开 façade 后**不再**门面再导出：全仓唯一生产
// 消费点在 `commands::tray_show_main` 自己域内（`use super::model::…`），测试直取 `super::model::…`。
// `tray` 是私有 mod，无消费者的 `pub use` 在 `-D warnings` 下是死导入红——同 `TRAY_AUTOSAVE_NAME`。
pub use model::{
    apply_fake_ip_tun_entry, native_dark, native_theme_override, resolve_tray_state, routing_key,
    surface_color, takeover_key, theme_boot_script, tooltip_text, ui_theme, window_bg_color,
    TrayState, ROUTING_MODES, TAKEOVER_KINDS,
};
use placement::PhysicalRect;
// `TRAY_AUTOSAVE_NAME`（macOS 专属 `pub const`）**不在**门面再导出：全仓零消费点（唯一真实用法
// 在 `platform::pin_tray_autosave_name` 自己体内，守卫 `tray_autosave_name_is_frozen` 走的是
// `module_code("tray")` 源码取材而非符号路径）。加一行无消费者的 `pub use` 会在 **macOS 上**触发
// `-D warnings` 的 unused_imports——本机 Linux 与 win-gnu 两条腿都看不见（R6 盲区）。
pub use platform::pin_tray_autosave_name;
pub(crate) use transition::enter_lightweight_transition;
pub use window::toggle_overlay;
pub(crate) use window::{prewarm_overlay_if_enabled, reconcile_overlay_retention};

// ── 托盘原生文案（Linux 原生菜单 + 三平台 tooltip）────────────────────────────────
//
// 浮层（webview）文案走前端 `labels.ts`（`i18n/auxiliary.ts` 的键查找，`locales/auxiliary/*.json` 的 `tray.*`）；
// **原生**托盘图标 tooltip 与 Linux 兜底菜单在 Rust 侧构建，前端 i18n 够不着 —— 故本模块经
// [`crate::i18n`] 读**同一批 `tray.*` 键**：同一个字符串，两个入口想分叉都分叉不了
// （此前靠一句「文案与浮层逐字一致」的散文约束守着）。语言真值源同为 `config.language`，
// 见 [`crate::i18n::app_lang`]。
//
// 2026-07-31 之前这里是一张 zh/en **二态**表（旧 `TrayLang` + `native_menu_*` 一族）：产品出
// 5 语种，俄语 / 波斯语 / 繁中用户的原生菜单与 tooltip 一律落英文（繁中还落简体的对立面——英文）。
// 现已随 [`crate::i18n::Lang`] 五语齐备，那一族常量包装函数随之删除：它们每个只是
// `match lang { Zh => "…", En => "…" }`，改成键查找后再留一层转发没有信息量，
// 调用点直接写 `i18n::t(lang, key::TRAY_X)` 反而让「这条文案是哪个键」在现场可见。

// ── 托盘四态（图标 / tooltip / 浮层状态点共用的单一状态轴）──────────────────────
//
// 此前托盘只有 `connected: bool` 二态（`main.rs::set_tray_connected`），对齐 上游
// `TrayManager.ts:54` 的 `TrayIconState = 'idle' | 'connected' | 'connecting'` 缺一态；且 上游的
// `TrayMenuData.hasError`（`TrayManager.ts:58/265`）在 Polaris 侧完全没有对应物 —— `main.rs` 收到
// `EVENT_PROXY_ERROR` 只是叫醒汇流点，汇流点回读 `running=false` ⇒ **崩溃与用户主动断开在托盘上完全同形**。
// 本枚举把两个缺口一次补齐：起核中可见反馈、异常终态可辨。

/// 浮层窗 label（Tauri 内唯一；主窗为 `"main"`，更新弹窗为 `"update-popup"`）。
pub const TRAY_LABEL: &str = "tray";

/// 浮层运行期状态（app-managed）：记录最近一次隐藏时刻（供 [`toggle_overlay`] 去抖）+ 最近一次
/// 托盘图标屏幕矩形（供 [`reposition`](placement::reposition) 对齐图标；[`tray_resize`] 改高后重定位也复用它）。
pub struct TrayOverlay {
    last_hidden: Mutex<Option<Instant>>,
    anchor: Mutex<Option<PhysicalRect>>,
    lifecycle: Mutex<OverlayLifecycle>,
    /// 点击到 renderer-ready / show 的真机时延探针。只记录运行期指标，不参与状态机判定。
    open_probe: Mutex<Option<OverlayOpenProbe>>,
    /// A1「打开设置」的**首帧种子腿**：主窗已被 C16 轻量模式销毁时，目标屏存在这里，等
    /// `create_main_window` 重建时注入首帧脚本（事件腿此刻必丢，见 [`tray_show_main`]）。
    /// `'static` 串 = [`normalize_tray_screen`](model::normalize_tray_screen) 的白名单产物。
    pending_screen: Mutex<Option<&'static str>>,
    /// 隐藏回收任务代次：每次 show/hide/destroy 都递增，过期任务只在代次仍匹配时销毁窗口。
    reclaim_generation: AtomicU64,
    /// `config.keepTrayMenuWarm` 的运行期镜像。只由启动同步与 CONFIG_CHANGED 事件更新；hide 热路径
    /// 直接读原子值，不为一次菜单收起克隆整份配置。
    keep_warm: AtomicBool,
    /// mac 全局鼠标监听器（NSEvent global monitor）句柄的**原始指针地址**（defect#3/W32）。存 `usize`
    /// 而非 `Retained<AnyObject>`：后者 `!Send`，进不了 Tauri app-managed state（要求 `Send + Sync`）；
    /// monitor 仅在主线程 add/remove，跨线程只传指针地址是安全的。`None` = 未装。
    /// 见 `platform::install_mouse_monitor` / [`remove_mouse_monitor`](platform::remove_mouse_monitor)。
    #[cfg(target_os = "macos")]
    mouse_monitor: Mutex<Option<usize>>,
}

impl Default for TrayOverlay {
    fn default() -> Self {
        Self {
            last_hidden: Mutex::default(),
            anchor: Mutex::default(),
            lifecycle: Mutex::default(),
            open_probe: Mutex::default(),
            pending_screen: Mutex::default(),
            reclaim_generation: AtomicU64::default(),
            // 与 store 的缺省值同口径；启动同步尚未执行时也不能短暂排下一条冷态回收任务。
            keep_warm: AtomicBool::new(true),
            #[cfg(target_os = "macos")]
            mouse_monitor: Mutex::default(),
        }
    }
}

#[cfg(test)]
mod tests;
