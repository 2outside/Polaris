use std::sync::atomic::Ordering;

use tauri::Manager;

use crate::{commands, i18n, show_main_window, tray, AppRuntime, Platform, QuitState};
#[cfg(not(target_os = "macos"))]
use crate::{dark_bg_from_probe, system_dark_bg};

pub(crate) fn set_tray_state(app: &tauri::AppHandle, state: crate::tray::TrayState) {
    let Some(tray) = app.tray_by_id("main") else {
        return; // 托盘整体缺失（Linux 无 StatusNotifier / appindicator 不可用）→ 静默跳过
    };
    // macOS：template 由系统按菜单栏明暗**自动反色** ⇒ 明暗根本不是输入，恒 false 占位（不进视觉态）。
    #[cfg(target_os = "macos")]
    let dark_bg = false;
    // Win/Linux：无 template 自动反色 → 探测链（W13）：注册表真值（Win）→ 主窗（显式 uiTheme
    // 下被钉、读到应用外观）→ 浮层窗（限时存活兜底）。
    // 旧实现只探主窗，主窗一关取不到就回落白变体，浅色任务栏上图标直接隐身。
    #[cfg(not(target_os = "macos"))]
    let dark_bg = dark_bg_from_probe(
        system_dark_bg().or_else(|| {
            app.get_webview_window("main")
                .and_then(|w| w.theme().ok())
                .map(|t| t == tauri::Theme::Dark)
        }),
        app.get_webview_window(crate::tray::TRAY_LABEL)
            .and_then(|w| w.theme().ok())
            .map(|t| t == tauri::Theme::Dark),
    );

    // tooltip 语言：config.language（`ConfigManager` 缓存读），auto 回落系统 locale。
    let next = TrayVisual {
        state,
        dark_bg,
        lang: crate::i18n::app_lang(app),
    };

    // 幂等闸门：托盘上真正要落的字节完全由 `next` 决定 ⇒ 未变即不碰托盘（见 `reconcile_tray_visual`）。
    // 锁跨越 apply 是刻意的：多驱动源（事件监听 / 自愈轮询 / 主题变化）并发调本函数时，串行化避免两次
    // set_icon 交错落成陈旧终态。中毒锁不致命（托盘不是安全边界）→ `into_inner` 继续用，不 panic。
    let mut cache = TRAY_VISUAL.lock().unwrap_or_else(|e| e.into_inner());
    reconcile_tray_visual(&mut cache, next, |v| {
        // macOS：原子设「图标+template」免闪烁（先 set_icon 再 set_icon_as_template 会二次渲染，
        // 见 tauri `tray/mod.rs` set_icon_with_as_template）；template 只取 alpha → 黑变体即可。
        #[cfg(target_os = "macos")]
        let icon_res = {
            let icon = match v.state {
                crate::tray::TrayState::Connected => {
                    tauri::include_image!("icons/tray-on-black.png")
                }
                crate::tray::TrayState::Connecting => {
                    tauri::include_image!("icons/tray-connecting-black.png")
                }
                crate::tray::TrayState::Error => {
                    tauri::include_image!("icons/tray-error-black.png")
                }
                crate::tray::TrayState::Idle => tauri::include_image!("icons/tray-off-black.png"),
            };
            tray.set_icon_with_as_template(Some(icon), true)
        };
        #[cfg(not(target_os = "macos"))]
        let icon_res = {
            use crate::tray::TrayState;
            let icon = match (v.state, v.dark_bg) {
                (TrayState::Connected, true) => tauri::include_image!("icons/tray-on-white.png"),
                (TrayState::Connected, false) => tauri::include_image!("icons/tray-on-black.png"),
                (TrayState::Connecting, true) => {
                    tauri::include_image!("icons/tray-connecting-white.png")
                }
                (TrayState::Connecting, false) => {
                    tauri::include_image!("icons/tray-connecting-black.png")
                }
                (TrayState::Error, true) => tauri::include_image!("icons/tray-error-white.png"),
                (TrayState::Error, false) => tauri::include_image!("icons/tray-error-black.png"),
                (TrayState::Idle, true) => tauri::include_image!("icons/tray-off-white.png"),
                (TrayState::Idle, false) => tauri::include_image!("icons/tray-off-black.png"),
            };
            tray.set_icon(Some(icon))
        };
        if let Err(e) = &icon_res {
            log::warn!("托盘图标切换失败（{v:?}）：{e}");
        }

        // 托盘 tooltip 随连接态动态刷新（审查 MED）：tauri.conf 静态 "Polaris" → hover 恒固定文案；此处按
        // 连接态 + 语言设。与图标切换同源（本函数在 init/start/stop/主题变化都调），tooltip 与图标态天然
        // 同步。mac/win 显示；Linux appindicator 无 tooltip = 静默 Ok(()) no-op（`tray-icon` gtk 后端
        // `set_tooltip` 直接返 Ok）→ 不会把 Linux 的缓存永久打成 None（真机门：呈现只在 mac/win 验得到）。
        let tip_res = tray.set_tooltip(Some(crate::tray::tooltip_text(v.lang, v.state)));
        icon_res.is_ok() && tip_res.is_ok()
    });
}

/// 落到托盘上的**全部**视觉输入 —— 汇流点幂等短路的比较键。
///
/// - `state`：图标形态（四态，见 [`crate::tray::TrayState`]）+ tooltip 文案分支
/// - `dark_bg`：Win/Linux 的黑 / 白变体选择（macOS 走 template 由系统反色 ⇒ 恒 `false`，不参与）
/// - `lang`：tooltip 文案语言
///
/// 这三者之外没有任何输入能改变托盘上的字节 ⇒ 键相等 ⇒ 重设是纯浪费（见 [`reconcile_tray_visual`]）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct TrayVisual {
    state: crate::tray::TrayState,
    dark_bg: bool,
    lang: crate::i18n::Lang,
}

/// 上次**成功落到托盘上**的视觉态。`None` = 未知（进程刚起 / 上次落盘失败）→ 下次无条件重设。
pub(crate) static TRAY_VISUAL: std::sync::Mutex<Option<TrayVisual>> = std::sync::Mutex::new(None);

/// 托盘视觉态的**幂等闸门**（纯函数，副作用经 `apply` 注入 → 可单测）：与上次成功落盘的态相同则
/// **不碰托盘**并返 `false`；否则 apply 并按结果更新缓存，返 `true`。
///
/// # 为什么必须短路
///
/// 汇流点被 30s 自愈轮询（[`TRAY_ICON_POLL`]）无条件叫醒，而绝大多数轮次状态根本没变（代理长期未
/// 运行 = 每一轮都没变）。Linux 侧代价最实：`tray-icon` 的 gtk 后端 `set_icon`
/// （`platform_impl/gtk/mod.rs:52-71`）每次都**删旧临时 PNG → counter+1 → 往
/// `$XDG_RUNTIME_DIR/tray-icon/` 写一张新 PNG → `set_icon_theme_path` + `set_icon_full`** ——
/// 磁盘写 + indicator 重载每 30s 一次、伴随整个进程生命周期，多数 StatusNotifier host 上表现为
/// 图标周期性闪一下。轮询本身不动（自愈网要留着），把「叫醒」与「重画」解耦即可。
///
/// # 为什么落盘失败要作废缓存，而不是照存
///
/// 存进去就等于宣称「托盘上现在长这样」。`set_icon` 失败时托盘上其实是**旧图**，若照存，之后每一
/// 轮自愈轮询都会短路、再也不重试 —— 自愈网被自己的缓存关掉，恰好在最需要它的时候。故失败置
/// `None`，下一轮无条件重设。
///
/// # 短路不会被绕过
///
/// 落盘动作（`set_icon` / `set_tooltip`）只存在于传进来的 `apply` 闭包里，本函数自身
/// 没有第二条通往托盘的路径 ⇒ 想跳过闸门必须重写该函数体，而不是漏调一行。
pub(crate) fn reconcile_tray_visual(
    cache: &mut Option<TrayVisual>,
    next: TrayVisual,
    apply: impl FnOnce(TrayVisual) -> bool,
) -> bool {
    if *cache == Some(next) {
        return false;
    }
    *cache = apply(next).then_some(next);
    true
}

/// 托盘图标 / tooltip 的**唯一汇流点**：回读 proxy 真值 → 刷新。所有驱动源（setup 初始化、代理生命
/// 周期事件、自愈轮询、系统明暗切换）一律经此，不再有第二处决定「图标该显示什么」。
///
/// # 为什么必须回读真值，而不是由事件携带布尔
///
/// 图标此前只订阅 `EVENT_PROXY_STARTED` / `EVENT_PROXY_STOPPED` 并各自传 `true`/`false` 字面量，于是
/// 「哪些腿会改变连接态」与「哪些腿会发这两个事件」被绑成了同一个问题 —— 而它们并不相等：
///
/// | 终态腿 | 发的事件 | 旧图标 |
/// |---|---|---|
/// | 用户主动断开 | `STOPPED` | ✅ |
/// | 核异常退出 / 自动重启失败 | 仅 `ERROR` | ❌ 停在实心 |
/// | `proxy_restart` 失败（核已停） | **零 emit** | ❌ 停在实心 |
/// | updater 换核前停核 | **零 emit** | ❌ 停在实心 |
/// | 休眠唤醒后失效 | **零 emit** | ❌ |
///
/// 回读真值把问题收敛回「当下核在不在跑」这一个可直接观测的事实（`ProxyRuntime::status().running`，
/// 与主窗 `refreshProxyStatus()` / 托盘浮层 `hydrate()` 同一真值源），于是**零 emit 的腿也能被兜住**
/// —— 只要有任何一个触发点把汇流点叫醒。触发点清单见 [`wire_tray_icon_sync`]。
///
/// # 四态从哪读（A2）
///
/// 三个位全部出自**同一个** `ProxyStatus` 快照，不新造任何 latch：
/// - `running` / `starting` —— 快照现成字段（`starting` 是读时投影，正是浮层用来判「起核中」的那个）。
/// - `errored` = `error_code.is_some()`（`set_error` 落值时与 `EVENT_PROXY_ERROR` **同点**写，见
///   `ProxyStatus::error_code` 文档「快照与事件同源，错过事件的 UI 仍能从状态读到码」）。
///
/// **刻意不用「收到 ERROR 事件就置个 flag」**：那等于给同一事实造第二个真值源，且必须自己想清楚何时清
/// 标记（start 成功？stop？超时？）——每一个都是新的漏清风险。读快照则天然自洽：`start()` 成功会整体
/// 覆写 status（error 归 None）、`stop()` 写 `ProxyStatus::default()`（同样归 None），清除路径**已经**
/// 由 runtime 层保证，托盘不必也不该复述一遍。这与本函数「回读真值而非信事件」的整体取向是同一条理由。
///
/// 便宜（一次 `RwLock` 读快照，无 IO / 无 syscall），故可放心让轮询按秒级频率调。
pub(crate) fn reconcile_tray_icon(app: &tauri::AppHandle) {
    let state = app
        .try_state::<AppRuntime>()
        .map(|rt| {
            let s = rt.proxy().status();
            crate::tray::resolve_tray_state(s.running, s.starting, s.error_code.is_some())
        })
        .unwrap_or(crate::tray::TrayState::Idle);
    set_tray_state(app, state);
}

/// 触发托盘汇流点（[`reconcile_tray_icon`] + [`reconcile_tray_menu`]）的事件全集。
///
/// `ERROR` 是补上的那条边：`runtime/proxy.rs` 的 `set_error()` 会把 `running=false` 落盘、却只发
/// `EVENT_PROXY_ERROR`（`ProxyErrorEmitter` trait 结构上就没有 `emit_proxy_stopped`）→ 崩溃腿此前对
/// 托盘完全不可见。对齐 上游 `index.ts:1895-1902`（`ProxyManager` `emit('error')` → 汇流点）。
///
/// `CONFIG_CHANGED` 是随 A7 原生菜单补上的：菜单要显示当前的**接管方式 / 分流策略勾选**与**语言**，
/// 而这三样只随配置变，不随代理生命周期变。少了它，用户在主窗切完分流策略，右键托盘看到的还是旧勾选
/// —— 且最长要等 30s 轮询才回正（Linux 上原生菜单是主交互面，那 30s 是实打实的错误信息）。
pub(crate) const TRAY_SYNC_EVENTS: [&str; 4] = [
    crate::events::channel::EVENT_PROXY_STARTED,
    crate::events::channel::EVENT_PROXY_STOPPED,
    crate::events::channel::EVENT_PROXY_ERROR,
    crate::events::channel::EVENT_CONFIG_CHANGED,
];

/// 托盘图标自愈轮询周期。
///
/// 存在的理由是**已知有腿零 emit**（restart 失败 / updater 停核 / 休眠唤醒），事件订阅无论补多全都
/// 只覆盖「已知会发事件的腿」；轮询覆盖的是**未知缺口**。主窗 `App.tsx:210-213` 正是靠同款 30s 轮询
/// 兜住这些腿才没出现同类 bug，托盘图标此前一道网都没有 → 对齐取 30s。
///
/// 30s ≠ 用户可感延迟的上限：有事件的腿仍是即时的（事件腿先到），轮询只负责封顶「最坏多久回正」。
pub(crate) const TRAY_ICON_POLL: std::time::Duration = std::time::Duration::from_secs(30);

/// 装配托盘图标汇流点的**全部驱动源**——两道网，缺一道就会退回「图标卡在实心」。
///
/// 副作用经 `subscribe` / `spawn_poll` 两个闭包注入，装配逻辑本身成纯函数 → 可在无 `AppHandle` 的
/// 单测里断言「三条终态事件全订 + 轮询网确实挂上」（见本模块 tests）。这是本修复唯一可自动验的部分：
/// 图标像素只能真机看，但「哪些源被接上」是纯装配决策，必须自动断言，否则又是一条无测试的腿。
///
/// # 为什么选「回读真值 + 自愈网」，而不是在 runtime 层补 emit
///
/// 另一条路是照 上游 在核状态每次变化处补 `emit_proxy_stopped`（`runtime/proxy.rs` 的 `set_error`、
/// `commands/proxy.rs` 的 restart 失败腿、`commands/updater.rs` 的停核腿各补一处）。不选它，因为那是
/// **逐腿补 emit**：正确性取决于「有没有漏掉某条腿」，而本 bug 的成因恰恰就是漏了一条 —— 同一类错误
/// 会随新增终态腿反复发生（updater 那两处就是 started/stopped 搬全之后新长出来的）。回读真值把
/// 正确性条件从「所有腿都记得发事件」降级为「任一触发点叫醒汇流点」，是**结构上**更难写错的形态。
pub(crate) fn wire_tray_icon_sync(
    mut subscribe: impl FnMut(&'static str),
    mut spawn_poll: impl FnMut(std::time::Duration),
) {
    for ev in TRAY_SYNC_EVENTS {
        subscribe(ev);
    }
    spawn_poll(TRAY_ICON_POLL);
}

// ── 托盘交互策略：macOS/Windows 直派点击，Linux 由原生菜单承接 ─────────────────────
//
// 这不是视觉偏好分支，而是平台能力边界：Tauri 的 tray-icon 在 macOS/Windows 会派发左右键事件；
// Linux AppIndicator 明确不派发 `TrayIconEvent`，且菜单一旦挂上也不能移除。故把平台差异收敛成一个
// 策略判据，调用方只消费「主窗口 / 自绘浮层 / 原生菜单」三种既定所有权，不再靠散落的 cfg 和注释猜。

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TrayInteractionMode {
    /// 应用直接接收鼠标事件：左/右键都切换自绘浮层。
    DirectClicks,
    /// 桌面托盘宿主接管点击并展示原生菜单（Linux AppIndicator）。
    NativeMenu,
}

// ── 主窗应用菜单所有权：macOS 系统顶栏 / Win·Linux 自绘窗口 ───────────────────────────
//
// Tauri/GTK 的 app menu 会在 Linux **主窗内**生成一条独立菜单栏；`hide_menu()` 对这条
// widget 并不是可靠的跨桌面契约。而 Polaris 在 Win/Linux 已经自绘标题区，故不应先挂一棵
// 仅含「退出」的原生菜单、再寄希望于把它藏住。非 macOS 的 Ctrl+Q 由主 WebView 处理，并复用
// `tray_quit` 同一条退出命令；Linux AppIndicator 的原生**托盘**菜单仍由 `TrayInteractionMode`
// 独立管理，与本判据无关。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MainWindowMenuOwner {
    /// 系统顶部菜单栏（macOS），同时提供 ⌘Q 和标准 Edit 动作。
    NativeApplicationMenu,
    /// 无边框自绘主窗（Windows/Linux/未知平台），由渲染层提供 Ctrl+Q。
    RendererShortcut,
}

#[must_use]
pub(crate) const fn main_window_menu_owner(platform: Platform) -> MainWindowMenuOwner {
    match platform {
        Platform::Mac => MainWindowMenuOwner::NativeApplicationMenu,
        Platform::Win | Platform::Linux | Platform::Other => MainWindowMenuOwner::RendererShortcut,
    }
}

#[must_use]
pub(crate) const fn tray_interaction_mode(platform: Platform) -> TrayInteractionMode {
    match platform {
        Platform::Mac | Platform::Win => TrayInteractionMode::DirectClicks,
        Platform::Linux | Platform::Other => TrayInteractionMode::NativeMenu,
    }
}

/// macOS/Windows 的左/右键是否应切换托盘浮层。只在按键抬起时执行，
/// 避免一次点击的 down/up 两帧各触发一次；macOS 双指辅助点按由系统归为 Right，与左键同语义。
/// Linux/未知平台由原生菜单持有事件，任何偶发派发都忽略，防止两个菜单叠开。
#[must_use]
pub(crate) fn tray_click_toggles_overlay(
    platform: Platform,
    button: tauri::tray::MouseButton,
    state: tauri::tray::MouseButtonState,
) -> bool {
    if tray_interaction_mode(platform) != TrayInteractionMode::DirectClicks
        || state != tauri::tray::MouseButtonState::Up
    {
        return false;
    }
    matches!(
        button,
        tauri::tray::MouseButton::Left | tauri::tray::MouseButton::Right
    )
}

// ── A7：Linux 原生兜底菜单（AppIndicator 不递送点击时唯一够得着功能面的入口）───────────
//
// AppIndicator 下 `set_show_menu_on_left_click(false)` 是 **no-op**，Tauri 也明确不派发 Linux
// `TrayIconEvent`；因此 Linux 的稳定入口只有桌面宿主展示的原生菜单。它此前只有「显示 / 退出」两项：
// 连接开关、接管方式、分流策略、设置、检查更新**全部够不着**。
//
// macOS/Windows 不再装这棵菜单：右键的唯一所有者是自绘浮层，若同时挂原生菜单，系统会先消费右键并
// 弹 NSMenu/HMENU，应用即使收到事件也只能得到两个重叠表面。菜单代码仍跨平台可编译和单测，但运行期
// 仅 [`TrayInteractionMode::NativeMenu`] 会装载。

/// 落到**原生托盘菜单**上的全部输入 —— 菜单幂等重建的比较键（与 [`TrayVisual`] 同款闸门思路）。
///
/// 菜单项文案随 `lang` 变；连接项随启动态变；出口、分流和接管子菜单分别随配置投影变。
/// 节点只保留原生级联菜单真正要显示的稳定字段，避免把整份含协议密钥的配置带进长生命周期缓存。
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct TrayMenuModel {
    pub(crate) running: bool,
    pub(crate) starting: bool,
    pub(crate) mode: String,
    pub(crate) mode_type: String,
    pub(crate) selected_server_id: Option<String>,
    pub(crate) has_real_nodes: bool,
    pub(crate) node_groups: Vec<TrayMenuGroup>,
    pub(crate) lang: crate::i18n::Lang,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct TrayMenuNode {
    id: String,
    name: String,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum TrayMenuGroupLabel {
    Manual,
    Mesh,
    Subscription(String),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct TrayMenuGroup {
    label: TrayMenuGroupLabel,
    nodes: Vec<TrayMenuNode>,
}

pub(crate) struct TrayMenuNodeProjection {
    node: TrayMenuNode,
    subscription_id: Option<String>,
    lands_in_endpoints: bool,
}

/// `with_current` 内的最小 owned 投影。菜单要显示节点名，故这些字符串不可借用到读锁之外；但协议设置、
/// 凭据、订阅 URL 等一律不复制。
#[derive(Default)]
pub(crate) struct TrayMenuConfigProjection {
    mode: Option<String>,
    mode_type: Option<String>,
    selected_server_id: Option<String>,
    has_real_nodes: bool,
    node_groups: Vec<TrayMenuGroup>,
}

/// Linux AppIndicator 不派发托盘点击事件、也不给图标矩形，无法把自绘 WebView 稳定锚到托盘旁；
/// 因而完整出口选择直接投影成 GTK 原生级联菜单：节点 → 自建/组网/各订阅 → 节点。分组口径与
/// `ui/src/domain/server-grouping.ts` 一致，协议凭据、订阅 URL 等字段不进入长生命周期菜单缓存。
pub(crate) fn tray_menu_config_projection(config: &serde_json::Value) -> TrayMenuConfigProjection {
    let subscriptions = config
        .get("subscriptions")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|subscription| {
            let id = subscription.get("id")?.as_str()?.trim();
            if id.is_empty() {
                return None;
            }
            let name = subscription
                .get("name")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .unwrap_or(id);
            Some((id.to_string(), name.to_string()))
        })
        .collect::<Vec<_>>();
    let known_subscription_ids = subscriptions
        .iter()
        .map(|(id, _)| id.as_str())
        .collect::<std::collections::HashSet<_>>();

    let nodes = config
        .get("servers")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|server| {
            let id = server.get("id")?.as_str()?.trim();
            if id.is_empty() {
                return None;
            }
            let name = server
                .get("name")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .unwrap_or(id);
            let subscription_id = server
                .get("subscriptionId")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|id| !id.is_empty())
                .map(str::to_string);
            let lands_in_endpoints = server
                .get("protocol")
                .and_then(serde_json::Value::as_str)
                .and_then(|protocol| {
                    serde_json::from_value::<
                        polaris_config_engine::user_config::server_config::Protocol,
                    >(serde_json::Value::String(protocol.to_string()))
                    .ok()
                })
                .is_some_and(polaris_config_engine::user_config::server_config::lands_in_endpoints);
            Some(TrayMenuNodeProjection {
                node: TrayMenuNode {
                    id: id.to_string(),
                    name: name.to_string(),
                },
                subscription_id,
                lands_in_endpoints,
            })
        })
        .collect::<Vec<_>>();

    let mut manual = Vec::new();
    let mut mesh = Vec::new();
    for projected in &nodes {
        let belongs_to_known_subscription = projected
            .subscription_id
            .as_deref()
            .is_some_and(|id| known_subscription_ids.contains(id));
        if belongs_to_known_subscription {
            continue;
        }
        if projected.lands_in_endpoints {
            mesh.push(projected.node.clone());
        } else {
            manual.push(projected.node.clone());
        }
    }
    let mut node_groups = Vec::new();
    if !manual.is_empty() {
        node_groups.push(TrayMenuGroup {
            label: TrayMenuGroupLabel::Manual,
            nodes: manual,
        });
    }
    if !mesh.is_empty() {
        node_groups.push(TrayMenuGroup {
            label: TrayMenuGroupLabel::Mesh,
            nodes: mesh,
        });
    }
    for (subscription_id, subscription_name) in subscriptions {
        let group_nodes = nodes
            .iter()
            .filter(|node| node.subscription_id.as_deref() == Some(subscription_id.as_str()))
            .map(|node| node.node.clone())
            .collect::<Vec<_>>();
        if !group_nodes.is_empty() {
            node_groups.push(TrayMenuGroup {
                label: TrayMenuGroupLabel::Subscription(subscription_name),
                nodes: group_nodes,
            });
        }
    }

    let selected_server_id = config
        .get("selectedServerId")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);

    TrayMenuConfigProjection {
        mode: config
            .get("proxyMode")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        mode_type: config
            .get("proxyModeType")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        selected_server_id,
        has_real_nodes: !nodes.is_empty(),
        node_groups,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum TrayProxyAction {
    Start,
    Stop,
    Cancel,
}

/// 与主窗/自绘托盘的连接按钮同一优先级：`starting` 压过 `running`，起核中点击必须走 stop 取消。
pub(crate) fn tray_proxy_action(running: bool, starting: bool) -> TrayProxyAction {
    if starting {
        TrayProxyAction::Cancel
    } else if running {
        TrayProxyAction::Stop
    } else {
        TrayProxyAction::Start
    }
}

/// 上次**成功装到托盘上**的菜单模型。`None` = 未知 → 下次无条件重建。
pub(crate) static TRAY_MENU: std::sync::Mutex<Option<TrayMenuModel>> = std::sync::Mutex::new(None);

/// 菜单幂等闸门（纯函数，副作用经 `apply` 注入 → 可单测）。与 [`reconcile_tray_visual`] 逐字同构，
/// 理由也同构：汇流点被 30s 轮询无条件叫醒，而 GTK 侧每次 `set_menu` 都要重建整棵 widget 树 ——
/// 用户正把菜单**打开着**时重建，多数 StatusNotifier host 上表现为菜单闪一下甚至收起。
///
/// 失败置 `None`（不照存）的理由同 [`reconcile_tray_visual`]：存了就等于宣称托盘上现在长这样，
/// 之后每一轮都短路、再也不重试 = 自愈网被自己的缓存关掉。
pub(crate) fn reconcile_tray_menu_model(
    cache: &mut Option<TrayMenuModel>,
    next: TrayMenuModel,
    apply: impl FnOnce(&TrayMenuModel) -> bool,
) -> bool {
    if cache.as_ref() == Some(&next) {
        return false;
    }
    *cache = apply(&next).then_some(next);
    true
}

/// 菜单项 id → 前缀常量。子菜单项 id 形如 `tray_takeover:tun` / `tray_routing:global`，
/// 由 [`parse_menu_action`] 解析回动作（纯函数，可单测）。
pub(crate) const MENU_ID_TAKEOVER: &str = "tray_takeover:";
pub(crate) const MENU_ID_ROUTING: &str = "tray_routing:";
pub(crate) const MENU_ID_SELECT: &str = "tray_select:";

/// 原生菜单项点击 → 动作（纯函数：id 字符串是菜单与 handler 之间唯一的契约面，解析必须可单测，
/// 否则「子菜单 id 拼错 → 点了没反应」这类错只能真机撞）。
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum MenuAction {
    Show,
    Quit,
    ToggleProxy,
    OpenSettings,
    CheckUpdate,
    SpeedTest,
    Lock,
    EnterLightweight,
    /// 选择真实节点或两个受支持的出口哨兵；真实节点 id 最终仍由 `server_switch` 校验。
    SelectExit(String),
    /// 切接管方式（`config.proxyModeType`）。载荷已由 [`crate::tray::TAKEOVER_KINDS`] 白名单归一。
    Takeover(&'static str),
    /// 切分流策略（`config.proxyMode`）。载荷已由 [`crate::tray::ROUTING_MODES`] 白名单归一。
    Routing(&'static str),
}

/// 菜单 id → [`MenuAction`]。未登记 id 返 `None`（handler 静默忽略，不猜）。
///
/// 子菜单载荷**回查白名单常量**再返 `'static` 串，而不是把 id 里的尾巴直接透传去写配置：
/// 写进 `config.proxyMode` 的值域必须由本文件钉死，不能取决于「谁拼的这个菜单 id」。
pub(crate) fn parse_menu_action(id: &str) -> Option<MenuAction> {
    match id {
        "tray_show" => return Some(MenuAction::Show),
        "tray_quit" => return Some(MenuAction::Quit),
        "tray_toggle" => return Some(MenuAction::ToggleProxy),
        "tray_settings" => return Some(MenuAction::OpenSettings),
        "tray_check_update" => return Some(MenuAction::CheckUpdate),
        "tray_speed_test" => return Some(MenuAction::SpeedTest),
        "tray_lock" => return Some(MenuAction::Lock),
        "tray_lightweight" => return Some(MenuAction::EnterLightweight),
        _ => {}
    }
    if let Some(server_id) = id.strip_prefix(MENU_ID_SELECT) {
        return (!server_id.trim().is_empty())
            .then(|| MenuAction::SelectExit(server_id.to_string()));
    }
    if let Some(kind) = id.strip_prefix(MENU_ID_TAKEOVER) {
        return crate::tray::TAKEOVER_KINDS
            .into_iter()
            .find(|k| *k == kind)
            .map(MenuAction::Takeover);
    }
    if let Some(mode) = id.strip_prefix(MENU_ID_ROUTING) {
        return crate::tray::ROUTING_MODES
            .into_iter()
            .find(|m| *m == mode)
            .map(MenuAction::Routing);
    }
    None
}

/// 用户内容放进原生菜单前转义 `&`。GTK/Windows 菜单把单个 `&` 当快捷键标记；不转义会吞掉
/// 订阅名/节点名里的字符，且同一名称在自绘与原生菜单显示不同。
pub(crate) fn native_menu_user_text(text: &str) -> String {
    text.replace('&', "&&")
}

pub(crate) fn native_menu_group_text(
    lang: crate::i18n::Lang,
    label: &TrayMenuGroupLabel,
) -> String {
    let text = match label {
        TrayMenuGroupLabel::Manual => crate::i18n::t(lang, crate::i18n::key::TRAY_GROUP_MANUAL),
        TrayMenuGroupLabel::Mesh => crate::i18n::t(lang, crate::i18n::key::TRAY_GROUP_MESH),
        TrayMenuGroupLabel::Subscription(name) => name.clone(),
    };
    native_menu_user_text(&text)
}

/// 按模型建整棵 Linux 原生托盘菜单（动作集合对齐自绘 `TrayMenu.tsx`）。
///
/// 项序：连接 → 出口 → 分流/接管 → 测速 → 主窗/设置/更新 → 锁定/轻量 → 退出。
/// 原生菜单只承载动作与勾选态；状态卡、国旗、延迟等视觉信息仍归自绘浮层。
pub(crate) fn build_tray_menu(
    app: &tauri::AppHandle,
    m: &TrayMenuModel,
) -> tauri::Result<tauri::menu::Menu<tauri::Wry>> {
    use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};

    let lang = m.lang;
    let proxy_action = tray_proxy_action(m.running, m.starting);
    let has_real_nodes = m.has_real_nodes;
    let has_startable_exit = has_real_nodes
        || matches!(
            m.selected_server_id.as_deref(),
            Some(
                polaris_config_engine::user_config::dns_constants::DIRECT_SERVER_ID
                    | polaris_config_engine::user_config::dns_constants::BLOCK_SERVER_ID
            )
        );
    let toggle = MenuItem::with_id(
        app,
        "tray_toggle",
        crate::i18n::t(
            lang,
            match proxy_action {
                TrayProxyAction::Start => crate::i18n::key::TRAY_CONNECT,
                TrayProxyAction::Stop => crate::i18n::key::TRAY_DISCONNECT,
                TrayProxyAction::Cancel => crate::i18n::key::TRAY_CANCEL_STARTUP,
            },
        ),
        proxy_action != TrayProxyAction::Start || has_startable_exit,
        None::<&str>,
    )?;

    use polaris_config_engine::user_config::dns_constants::{BLOCK_SERVER_ID, DIRECT_SERVER_ID};
    let nodes = Submenu::new(
        app,
        crate::i18n::t(lang, crate::i18n::key::TRAY_NODES),
        true,
    )?;
    nodes.append(&CheckMenuItem::with_id(
        app,
        format!("{MENU_ID_SELECT}{DIRECT_SERVER_ID}"),
        crate::i18n::t(lang, crate::i18n::key::TRAY_MODE_DIRECT),
        true,
        m.selected_server_id.as_deref() == Some(DIRECT_SERVER_ID),
        None::<&str>,
    )?)?;
    nodes.append(&CheckMenuItem::with_id(
        app,
        format!("{MENU_ID_SELECT}{BLOCK_SERVER_ID}"),
        crate::i18n::t(lang, crate::i18n::key::TRAY_BLOCKED),
        m.mode != "direct",
        m.selected_server_id.as_deref() == Some(BLOCK_SERVER_ID),
        None::<&str>,
    )?)?;
    if !m.node_groups.is_empty() {
        nodes.append(&PredefinedMenuItem::separator(app)?)?;
    }
    for group in &m.node_groups {
        let group_menu = Submenu::new(app, native_menu_group_text(lang, &group.label), true)?;
        for node in &group.nodes {
            group_menu.append(&CheckMenuItem::with_id(
                app,
                format!("{MENU_ID_SELECT}{}", node.id),
                native_menu_user_text(&node.name),
                true,
                m.selected_server_id.as_deref() == Some(node.id.as_str()),
                None::<&str>,
            )?)?;
        }
        nodes.append(&group_menu)?;
    }

    let takeover_items = crate::tray::TAKEOVER_KINDS
        .iter()
        .map(|k| {
            CheckMenuItem::with_id(
                app,
                format!("{MENU_ID_TAKEOVER}{k}"),
                crate::i18n::t(lang, crate::tray::takeover_key(k)),
                true,
                *k == m.mode_type,
                None::<&str>,
            )
        })
        .collect::<tauri::Result<Vec<_>>>()?;
    let takeover = Submenu::with_items(
        app,
        crate::i18n::t(lang, crate::i18n::key::TRAY_GROUP_TAKEOVER),
        true,
        &takeover_items
            .iter()
            .map(|i| i as &dyn tauri::menu::IsMenuItem<tauri::Wry>)
            .collect::<Vec<_>>(),
    )?;

    let routing_items = crate::tray::ROUTING_MODES
        .iter()
        .map(|v| {
            CheckMenuItem::with_id(
                app,
                format!("{MENU_ID_ROUTING}{v}"),
                crate::i18n::t(lang, crate::tray::routing_key(v)),
                true,
                *v == m.mode,
                None::<&str>,
            )
        })
        .collect::<tauri::Result<Vec<_>>>()?;
    let routing = Submenu::with_items(
        app,
        crate::i18n::t(lang, crate::i18n::key::TRAY_GROUP_MODE),
        true,
        &routing_items
            .iter()
            .map(|i| i as &dyn tauri::menu::IsMenuItem<tauri::Wry>)
            .collect::<Vec<_>>(),
    )?;

    let speed_test = MenuItem::with_id(
        app,
        "tray_speed_test",
        crate::i18n::t(lang, crate::i18n::key::TRAY_SPEEDTEST),
        has_real_nodes && !m.starting,
        None::<&str>,
    )?;

    let settings = MenuItem::with_id(
        app,
        "tray_settings",
        crate::i18n::t(lang, crate::i18n::key::TRAY_OPEN_SETTINGS),
        true,
        None::<&str>,
    )?;
    let check_update = MenuItem::with_id(
        app,
        "tray_check_update",
        crate::i18n::t(lang, crate::i18n::key::TRAY_CHECK_UPDATE),
        true,
        None::<&str>,
    )?;
    let show = MenuItem::with_id(
        app,
        "tray_show",
        crate::i18n::t(lang, crate::i18n::key::TRAY_OPEN_MAIN),
        true,
        None::<&str>,
    )?;
    let lock = MenuItem::with_id(
        app,
        "tray_lock",
        crate::i18n::t(lang, crate::i18n::key::TRAY_LOCK_NOW),
        true,
        None::<&str>,
    )?;
    let lightweight = MenuItem::with_id(
        app,
        "tray_lightweight",
        crate::i18n::t(lang, crate::i18n::key::TRAY_LIGHTWEIGHT),
        true,
        None::<&str>,
    )?;
    let quit = MenuItem::with_id(
        app,
        "tray_quit",
        crate::i18n::t(lang, crate::i18n::key::TRAY_QUIT),
        true,
        None::<&str>,
    )?;

    Menu::with_items(
        app,
        &[
            &toggle,
            &PredefinedMenuItem::separator(app)?,
            &nodes,
            &routing,
            &takeover,
            &speed_test,
            &PredefinedMenuItem::separator(app)?,
            &show,
            &settings,
            &check_update,
            &PredefinedMenuItem::separator(app)?,
            &lock,
            &lightweight,
            &PredefinedMenuItem::separator(app)?,
            &quit,
        ],
    )
}

/// Linux 原生托盘菜单的**唯一汇流点**（与 [`reconcile_tray_icon`] 并列，同一批驱动源叫醒）：
/// 回读 proxy / config 真值 → 模型变了才重建菜单。macOS/Windows 不调用本函数，右键由自绘浮层独占。
pub(crate) fn reconcile_tray_menu(app: &tauri::AppHandle) {
    let Some(tray) = app.tray_by_id("main") else {
        return; // 托盘整体缺失 → 无菜单可装
    };
    let rt = app.try_state::<AppRuntime>();
    // `ConfigManager::with_current` 持读锁做菜单专用投影，不产整份 owned `Value`：本汇流点挂着 30s
    // 自愈轮询，节点菜单虽必须复制 id/name，但协议凭据、订阅 URL、规则等大字段仍保持零复制。
    // ⚠️ `app_lang(app)` 自己也要读配置 —— 必须留在闭包**外**（嵌套读锁是 `with_current` 的禁忌）。
    let projection = rt
        .as_ref()
        .and_then(|r| {
            // 闭包只做一次读锁内投影；语言解析在下方平铺执行，禁止递归取得同一把读锁。
            r.config().with_current(tray_menu_config_projection).ok()
        })
        .unwrap_or_default();
    let status = rt
        .as_ref()
        .map(|runtime| runtime.proxy().status())
        .unwrap_or_default();
    let next = TrayMenuModel {
        running: status.running,
        starting: status.starting,
        // 缺省与前端一致：`TrayMenu.tsx` 的 `config?.proxyMode ?? 'smart'` /
        // `config?.proxyModeType ?? 'systemProxy'`（两个入口显示同一档，不许分叉）。
        mode: projection.mode.unwrap_or_else(|| "smart".to_string()),
        mode_type: projection
            .mode_type
            .unwrap_or_else(|| "systemProxy".to_string()),
        selected_server_id: projection.selected_server_id,
        has_real_nodes: projection.has_real_nodes,
        node_groups: projection.node_groups,
        lang: crate::i18n::app_lang(app),
    };
    let mut cache = TRAY_MENU.lock().unwrap_or_else(|e| e.into_inner());
    reconcile_tray_menu_model(&mut cache, next, |m| match build_tray_menu(app, m) {
        Ok(menu) => match tray.set_menu(Some(menu)) {
            Ok(()) => true,
            Err(e) => {
                log::warn!("托盘原生菜单装载失败：{e}");
                false
            }
        },
        Err(e) => {
            log::warn!("托盘原生菜单构建失败：{e}");
            false
        }
    });
}

/// 托盘汇流点的统一叫醒入口：三平台都刷新图标；仅 Linux 刷新原生菜单。两者各自幂等短路，多叫无害。
pub(crate) fn reconcile_tray(app: &tauri::AppHandle) {
    reconcile_tray_icon(app);
    if tray_interaction_mode(Platform::current()) == TrayInteractionMode::NativeMenu {
        reconcile_tray_menu(app);
    }
}

/// 主进程侧系统通知（`tauri-plugin-notification`）。
///
/// **只给「没有任何 UI 表面可回显」的腿用** —— Linux 原生菜单动作完成或失败后，菜单本身没有
/// notice/toast 层；浮层和主窗仍走各自的应用内反馈，不调用这里。
/// 别把它当通用提示出口：应用内能看见的地方一律走 toast，系统通知会进通知中心/锁屏，成本高得多。
///
/// 失败静默（只记日志）：用户没给通知权限 / 平台不支持时，**通知发不出去不该反过来影响业务动作**
/// ——检查更新本身已经跑完了。
pub(crate) fn notify_user(app: &tauri::AppHandle, title: &str, body: &str) {
    use tauri_plugin_notification::NotificationExt;
    if let Err(e) = app.notification().builder().title(title).body(body).show() {
        log::warn!("系统通知发送失败（已忽略）: {e}");
    }
}

/// 原生菜单动作失败的统一反馈。`detail` 必须已经是当前语言的用户文案；原始后端/OS 诊断只写日志，
/// 不得混进本地化通知。
pub(crate) fn notify_menu_action_error(
    app: &tauri::AppHandle,
    lang: crate::i18n::Lang,
    action_key: &str,
    detail: &str,
) {
    let action = crate::i18n::t(lang, action_key);
    let body = crate::i18n::t(lang, crate::i18n::key::TRAY_ACTION_FAILED)
        .replace("{{action}}", &action)
        .replace("{{detail}}", detail);
    notify_user(app, &action, &body);
}

/// `ApiResponse` 失败信封 → 系统通知；成功返回 false，供动作腿继续处理成功结果。
pub(crate) fn notify_menu_response_failure<T>(
    app: &tauri::AppHandle,
    lang: crate::i18n::Lang,
    action_key: &str,
    response: &crate::response::ApiResponse<T>,
) -> bool {
    if response.success {
        return false;
    }
    let diagnostic = response
        .error
        .clone()
        .unwrap_or_else(|| "no diagnostic detail".to_string());
    log::warn!("托盘原生菜单动作失败（{action_key}）: {diagnostic}");
    let user_detail = crate::i18n::t(lang, crate::i18n::key::NATIVE_UNKNOWN_ERROR);
    notify_menu_action_error(app, lang, action_key, &user_detail);
    true
}

/// Linux 原生菜单动作执行（副作用腿）。
///
/// 业务动作**复用 `commands::*` 里那几个 `#[tauri::command]` 函数本体**，不另写一份：它们同时也是浮层
/// 与主窗走的那条路径（`proxy_start` 的「只在核真起来了才广播 proxyStarted」、`config_save` 的
/// 隐私 hash 回填 + 后端权威字段兜底都在里面）。绕过它们直接调 runtime 就会得到一条**语义不同**的
/// 第二实现 —— 那正是本仓反复出现的分叉源。
pub(crate) fn run_menu_action(app: &tauri::AppHandle, action: MenuAction) {
    match action {
        MenuAction::Show => show_main_window(app),
        MenuAction::Quit => {
            app.state::<QuitState>().0.store(true, Ordering::SeqCst);
            app.exit(0);
        }
        MenuAction::OpenSettings => {
            // 与浮层「打开设置」逐字节同一条路径（含轻量模式重建时的首帧种子腿）。
            let lang = i18n::app_lang(app);
            let response = tray::tray_show_main(app.clone(), Some("settings".into()));
            notify_menu_response_failure(app, lang, i18n::key::TRAY_OPEN_SETTINGS, &response);
        }
        MenuAction::ToggleProxy => {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                let lang = i18n::app_lang(&app);
                let state = app.state::<AppRuntime>();
                let status = state.proxy().status();
                let action = tray_proxy_action(status.running, status.starting);
                let (response, action_key) = match action {
                    TrayProxyAction::Start => (
                        // 起核载荷由 `proxy_start` 自己读盘（见其头注），不消费菜单构建时快照。
                        commands::proxy::proxy_start(app.clone(), state).await,
                        i18n::key::TRAY_CONNECT,
                    ),
                    TrayProxyAction::Stop => (
                        commands::proxy::proxy_stop(app.clone(), state).await,
                        i18n::key::TRAY_DISCONNECT,
                    ),
                    // 起核期 `running=false`，仍必须走 stop；这是自绘托盘已经建立的取消契约。
                    TrayProxyAction::Cancel => (
                        commands::proxy::proxy_stop(app.clone(), state).await,
                        i18n::key::TRAY_CANCEL_STARTUP,
                    ),
                };
                match response {
                    Ok(response) => {
                        notify_menu_response_failure(&app, lang, action_key, &response);
                    }
                    Err(()) => notify_menu_action_error(
                        &app,
                        lang,
                        action_key,
                        &i18n::t(lang, i18n::key::NATIVE_UNKNOWN_ERROR),
                    ),
                }
            });
        }
        // Routing / Takeover 都要**落盘 + 触发配置评估**（可能连带重启内核）。菜单事件回调跑在
        // **主线程**（Linux 上就是 GTK 主线程）⇒ 同步跑完整条链会把 UI 卡一拍：菜单项按下去不弹回、
        // 托盘图标不重绘。同文件的 ToggleProxy / CheckUpdate 早就 spawn 了，这两条是漏网的
        // （2026-07-28 复审 LOW）。
        //
        // 用 `spawn_blocking` 而非 `spawn`：这两个 command 是**同步阻塞**函数（文件写 + 规则评估），
        // 丢进异步 worker 会占着 tokio 的协作式线程不还。reviewer 写的是 `spawn`——这里的出入只在
        // 「丢到哪个池」，「离开主线程」这个根因两者相同，而 blocking 池才是同步阻塞工作的正确去处。
        MenuAction::Routing(mode) => {
            let app = app.clone();
            tauri::async_runtime::spawn_blocking(move || {
                let lang = i18n::app_lang(&app);
                let state = app.state::<AppRuntime>();
                let response = commands::config::config_update_mode(
                    app.clone(),
                    state,
                    serde_json::Value::String(mode.to_string()),
                );
                notify_menu_response_failure(&app, lang, i18n::key::TRAY_GROUP_MODE, &response);
            });
        }
        MenuAction::Takeover(kind) => {
            let app = app.clone();
            tauri::async_runtime::spawn_blocking(move || {
                let lang = i18n::app_lang(&app);
                let state = app.state::<AppRuntime>();
                let Ok(mut cfg) = state.config().current() else {
                    notify_menu_action_error(
                        &app,
                        lang,
                        i18n::key::TRAY_GROUP_TAKEOVER,
                        &i18n::t(lang, i18n::key::NATIVE_UNKNOWN_ERROR),
                    );
                    return;
                };
                cfg["proxyModeType"] = serde_json::Value::String(kind.to_string());
                // 与浮层 / 主窗同源：切到 TUN 时消费「FakeIP-TUN 待纠正」快照（见 tray::apply_fake_ip_tun_entry）。
                // 纠正涉及 proxyModeType + dnsConfig/dnsDefaults，作为一个顶层补丁原子落盘；不能拆成
                // 多次 set_value（会广播/重启多次），也不能拿托盘打开时的旧快照整份覆盖。
                if crate::tray::apply_fake_ip_tun_entry(&mut cfg) {
                    log::info!(
                        "托盘原生菜单进入 TUN：已自动回填 enableFakeIp=true（消费迁移期待纠正快照）"
                    );
                }
                // `defer_restart=None`：托盘切接管方式是**用户此刻要它生效**的动作，不是「保存」，
                // 不得降级到待应用差集（降了 = 点了切 TUN 却什么都没发生）。
                // `base_version=None`：托盘不产生 staged（spec §Q8-b 闸 2），它永远是「被合并方」
                // 而非「冲突方」——挂上乐观并发只会让托盘操作在别人写盘时莫名失败。
                let mut patch = serde_json::Map::new();
                for key in ["proxyModeType", "dnsConfig", "dnsDefaults"] {
                    if let Some(value) = cfg.get(key).cloned() {
                        patch.insert(key.to_string(), value);
                    }
                }
                let response = commands::config::config_patch(
                    app.clone(),
                    state,
                    serde_json::Value::Object(patch),
                );
                notify_menu_response_failure(&app, lang, i18n::key::TRAY_GROUP_TAKEOVER, &response);
            });
        }
        MenuAction::SelectExit(server_id) => {
            use polaris_config_engine::user_config::dns_constants::{
                BLOCK_SERVER_ID, DIRECT_SERVER_ID,
            };

            let app = app.clone();
            tauri::async_runtime::spawn_blocking(move || {
                let lang = i18n::app_lang(&app);
                let state = app.state::<AppRuntime>();
                let (response, action_key) = if server_id == DIRECT_SERVER_ID {
                    (
                        commands::config::config_set_value(
                            app.clone(),
                            state,
                            "selectedServerId".to_string(),
                            serde_json::Value::String(server_id),
                        ),
                        i18n::key::TRAY_MODE_DIRECT,
                    )
                } else if server_id == BLOCK_SERVER_ID {
                    // 菜单打开后配置仍可能被别的窗口改成 direct；执行腿二次守门，不能只信旧菜单的 disabled。
                    let direct = state
                        .config()
                        .with_current(|config| {
                            config.get("proxyMode").and_then(serde_json::Value::as_str)
                                == Some("direct")
                        })
                        .unwrap_or(false);
                    if direct {
                        notify_menu_action_error(
                            &app,
                            lang,
                            i18n::key::TRAY_BLOCKED,
                            &i18n::t(lang, i18n::key::TRAY_NO_EFFECT_IN_DIRECT),
                        );
                        return;
                    }
                    (
                        commands::config::config_set_value(
                            app.clone(),
                            state,
                            "selectedServerId".to_string(),
                            serde_json::Value::String(server_id),
                        ),
                        i18n::key::TRAY_BLOCKED,
                    )
                } else {
                    (
                        commands::server::server_switch(app.clone(), state, server_id),
                        i18n::key::TRAY_NODES,
                    )
                };
                notify_menu_response_failure(&app, lang, action_key, &response);
            });
        }
        MenuAction::SpeedTest => {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                let lang = i18n::app_lang(&app);
                let state = app.state::<AppRuntime>();
                match commands::speedtest::server_speed_test(app.clone(), state, None).await {
                    Ok(response) => {
                        if !notify_menu_response_failure(
                            &app,
                            lang,
                            i18n::key::TRAY_SPEEDTEST,
                            &response,
                        ) {
                            notify_user(
                                &app,
                                &i18n::t(lang, i18n::key::TRAY_SPEEDTEST),
                                &i18n::t(lang, i18n::key::NATIVE_SPEED_TEST_COMPLETE),
                            );
                        }
                    }
                    Err(()) => notify_menu_action_error(
                        &app,
                        lang,
                        i18n::key::TRAY_SPEEDTEST,
                        &i18n::t(lang, i18n::key::NATIVE_UNKNOWN_ERROR),
                    ),
                }
            });
        }
        MenuAction::Lock => {
            let app = app.clone();
            tauri::async_runtime::spawn_blocking(move || {
                let lang = i18n::app_lang(&app);
                let state = app.state::<AppRuntime>();
                let response = commands::config::config_set_privacy_mode(app.clone(), state, true);
                notify_menu_response_failure(&app, lang, i18n::key::TRAY_LOCK_NOW, &response);
            });
        }
        MenuAction::EnterLightweight => {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                let lang = i18n::app_lang(&app);
                let response = tray::tray_enter_lightweight(app.clone()).await;
                notify_menu_response_failure(&app, lang, i18n::key::TRAY_LIGHTWEIGHT, &response);
            });
        }
        MenuAction::CheckUpdate => {
            let app = app.clone();
            // 与浮层「检查更新」**同一个** command 本体（tray::tray_check_update）：两个入口共用一条链，
            // 不会出现「菜单查到的和浮层查到的不一样」。
            //
            // 结果经系统通知回显（2026-07-28 复审 MED）：此前「已是最新」与「失败」都只入日志 ⇒
            // 用户零反馈。而 **Linux 上原生菜单就是主交互面**（左键递送不可靠，`set_show_menu_on_left_click`
            // 在 appindicator 下是 no-op），点了没动静与按钮坏了完全不可分辨。浮层有 notice 行、
            // 主窗有 toast，原生菜单**没有任何 UI 表面** → `tauri-plugin-notification`（已在 builder
            // 注册 + capability `notification:default` 已授权）是唯一送达路径。
            //
            // `hasUpdate == true` 那一支**刻意不发通知**：提醒窗已经弹在屏幕上了，再叠一条系统通知
            // 就是同一件事说两遍。
            tauri::async_runtime::spawn(async move {
                let lang = i18n::app_lang(&app);
                let r = tray::tray_check_update(app.clone()).await;
                let body = if r.success {
                    if r.data == Some(true) {
                        return; // 有更新 → 提醒窗自己就是反馈
                    }
                    i18n::t(lang, i18n::key::TRAY_UP_TO_DATE)
                } else {
                    let why = r
                        .error
                        .unwrap_or_else(|| i18n::t(lang, i18n::key::NATIVE_UNKNOWN_ERROR));
                    log::warn!("托盘原生菜单检查更新失败: {why}");
                    format!(
                        "{}: {why}",
                        i18n::t(lang, i18n::key::TRAY_UPDATE_CHECK_FAILED)
                    )
                };
                notify_user(
                    &app,
                    &i18n::t(lang, i18n::key::NATIVE_UPDATE_NOTIFY_TITLE),
                    &body,
                );
            });
        }
    }
}

#[cfg(test)]
mod tests;
