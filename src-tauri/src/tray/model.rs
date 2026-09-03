//! 托盘状态轴 / 文案键映射 / 原生面主题 / FakeIP-TUN 待纠正快照（纯函数与纯类型，零 tauri 副作用
//! 除 [`ui_theme`]/[`os_dark`]/[`native_dark`] 三个 app 侧薄封装读）。
//! 从 `tray.rs` 整段搬出（Phase 4A 批 B6），`use super::TRAY_LABEL` 是本模块唯一回指 façade 的项。

use serde_json::Value;
use tauri::{AppHandle, Manager};

use crate::i18n::{key, t, Lang};

use super::TRAY_LABEL;

/// 托盘视觉状态（四态）。图标形态与 tooltip 都由它单点决定。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TrayState {
    /// 未连接（用户主动断开 / 从未启动）。
    Idle,
    /// 起核腿在飞（`ProxyStatus.starting`，重试预算内可达数十秒）。
    Connecting,
    /// 核在跑。
    Connected,
    /// 异常终态：核崩溃 / 起核失败（`ProxyStatus.error` 有值且核未跑），**非**用户主动断开。
    Error,
}

// ── 为什么原生图标**没有**浮层那个 `degraded` 第五态（2026-07-28 复审 LOW-2，如实登记）────
//
// 浮层的 `trayStatusTone`（`ui/src/tray/tray-status-tone.ts`）比本枚举多一个 `degraded`
// （核在跑但 systemProxy 被手改 ⇒ 流量没经核）。原生图标**刻意不跟进**，登记在此免得被反复重开。
//
// # 拦路的不是「加一个 enum 分支」，是这个位的真值从哪来
//
// 判据是 `system_proxy_get_status` 的 `pointsToUs` —— 它**只能**靠 exec
// `networksetup` / `gsettings` / `reg` 现查（无内核事件、无缓存，`commands/proxy.rs` 每次调用现造
// 一次性 ops）。而图标汇流点 `app_tray.rs::reconcile_tray_icon` 的立身之本正是「一次 `RwLock` 读快照、
// 无 IO 无 syscall」，故可以被四个事件源 + 30s 轮询随便叫醒。往那条腿里塞 exec ⇒ 每次代理状态
// 变化、每次 configChanged 都拖一次子进程，代价与收益完全不成比例（这条已在上一批复审判过）。
//
// # 那「让前端把已取到的活态回传给 Rust」呢——**也不成立**，理由是数据到不了现场
//
// 前端确实已经有一份活态（`ui/src/store/use-system-proxy-live.ts`），但它的两个产出点都覆盖不到
// 「需要看图标」的那个时刻：
//  - **主窗轮询**（15s 一发）硬门控在 `document.visibilityState === 'visible'`，隐藏即整条链停摆
//    （连 timer 都不留）。而主窗关闭 = `hide()` 收进托盘是本应用的默认关窗语义
//    （`startup.rs::resolve_close_action` + `config.minimizeToTray`）⇒ 托盘图标成为唯一状态面的场景，
//    恰恰就是该轮询**一发都不发**的场景。
//  - **浮层 hydrate**（弹出即取一发）发生在用户已经打开浮层之后，而浮层自己那颗点此刻就显示着
//    正确结论 ⇒ 图标晚一步翻过来，对用户是零增量信息。
// 即：这条链能让图标「在浮层/主窗已经说了实话的时候跟着说一遍」，唯独不能在只剩图标的时候说话。
// 代价却是一条新的跨窗状态推送通道（新 command + 契约 + 前端接线）**外加一套陈旧度策略**
// （报文停了之后那个位算真还是算假、多久算陈旧——没有原则性的取值）。
//
// # tooltip 先行也不是更便宜的路
//
// tooltip 与图标共用同一个 `TrayVisual` 输入，缺的同样是那个位的真值 ⇒ 数据源的代价一分不少，
// 只省下了「换个图标」这点几乎为零的成本；且 Linux appindicator 根本没有 tooltip
// （`set_tooltip` 直接返 Ok = no-op），缺口最大的平台一点都补不到。
//
// # 结论与现状
//
// 判定为**不做**：现有形态下没有一条路径能把这个位在「需要它」的时刻送到图标上。缺口不是没有代偿——
// 主窗状态栏琥珀点 + 首页降级横幅 + 托盘浮层琥珀点三处都已如实呈现，独缺不接受输入的原生图标那一格。
// 真要补，前置条件是**后端自己有一份低成本的活态**（例如系统代理接管腿在写侧维护一个带 TTL 的
// `points_to_us` 缓存，由已有的接管/重申动作顺带刷新），那时本枚举加第五态才只是「加一个分支」。
// 在那之前，`reconcile_tray_icon` 的无 IO 不变式由 `main.rs` 的
// `tray_icon_reconcile_stays_io_free` 守住 —— 防的就是有人为了补这一格把 exec 塞进图标腿。

/// 由 proxy 状态快照的三个位折出托盘状态（纯函数，可单测）。
///
/// 优先级 **Connected > Connecting > Error > Idle**，每一级都有理由：
/// - `running` 压过一切：核确实在跑时，任何陈旧的 error 字段都不该把托盘打成红叉（`set_nonfatal_error`
///   会在**活核**上留 `error`，如 A1 的 `SYSTEM_PROXY_FAILED` —— 那不是「没连上」）。
/// - `starting` 压过 `errored`：新一轮起核已经在飞，上一轮的失败不该盖住「正在重试」这个更新的事实。
/// - `errored` 压过 Idle：这正是本轮要补的那条边（崩溃腿此前与主动断开同形）。
#[must_use]
pub fn resolve_tray_state(running: bool, starting: bool, errored: bool) -> TrayState {
    if running {
        TrayState::Connected
    } else if starting {
        TrayState::Connecting
    } else if errored {
        TrayState::Error
    } else {
        TrayState::Idle
    }
}

/// 托盘图标 tooltip 文案（随状态动态刷新；tauri.conf 静态 "Polaris" → hover 恒固定的替代）。
///
/// Linux appindicator 无 tooltip（`tray-icon` gtk 后端 `set_tooltip` 直接返 Ok）→ 那里状态全靠图标形态
/// 与原生菜单，故错误态**必须**在图标上可辨，不能只写进 tooltip（见 [`TrayState`]）。
pub fn tooltip_text(lang: Lang, state: TrayState) -> String {
    // `Polaris — <状态>`：品牌名不进 locale（五语种同名），分隔符是排版而非文案。
    // fa（RTL）下的左右次序由系统 bidi 算法定，不在此处硬编码方向。
    format!("Polaris — {}", t(lang, tooltip_status_key(state)))
}

/// 四态 → `tray.status*` 键。与浮层状态卡取同一批键（同一状态两个入口不得措辞分叉）。
///
/// 浮层比这里多一个 `statusProxyInactive`（degraded 第五态），原生图标刻意不跟进 —— 理由见
/// [`TrayState`] 上方那段登记。
#[must_use]
pub fn tooltip_status_key(state: TrayState) -> &'static str {
    match state {
        TrayState::Connected => key::TRAY_STATUS_CONNECTED,
        TrayState::Connecting => key::TRAY_STATUS_CONNECTING,
        TrayState::Error => key::TRAY_STATUS_ERROR,
        TrayState::Idle => key::TRAY_STATUS_DISCONNECTED,
    }
}

// ── 原生兜底菜单文案（A7：Linux 不递送点击事件时，这是唯一够得着功能面的入口）──────────
//
// Tauri 的 AppIndicator 后端不支持切换菜单点击键，且明确不派发 Linux `TrayIconEvent` ⇒ Linux 用户
// 只能依赖桌面宿主展示的原生菜单。
// 它此前只有「显示 / 退出」两项 ⇒ 模式、接管方式、节点、连接开关**全部够不着**。
// 故原生菜单必须自带完整功能面（对齐 上游 `TrayManager.ts:392-441` 的 contextMenu 项集）。
//
// 菜单项文案由 `app_tray.rs::build_tray_menu` 直接 `i18n::t(lang, key::TRAY_*)` 取；只有下面两个
// **值 → 键**的映射留在此处（它们有真实逻辑：`config` 里的取值域要对到显示序与文案上）。

/// 接管方式三档的文案键。`kind` 取 [`TAKEOVER_KINDS`] 之一（`config.proxyModeType` 值域）。
/// 与浮层 `TrayMenu.tsx` 的 `TAKEOVERS` 表**共用同一批键**（不再是「靠人守的逐字一致」）。
#[must_use]
pub fn takeover_key(kind: &str) -> &'static str {
    match kind {
        "tun" => key::TRAY_TAKEOVER_TUN,
        "manual" => key::TRAY_TAKEOVER_MANUAL,
        _ => key::TRAY_TAKEOVER_SYSTEM_PROXY,
    }
}

/// 分流策略三档的文案键。`mode` 取 [`ROUTING_MODES`] 之一（`config.proxyMode` 值域）。
/// 与浮层 `TrayMenu.tsx` 的 `MODES` 表共用同一批键。
#[must_use]
pub fn routing_key(mode: &str) -> &'static str {
    match mode {
        "global" => key::TRAY_MODE_GLOBAL,
        "direct" => key::TRAY_MODE_DIRECT,
        _ => key::TRAY_MODE_SMART,
    }
}

/// `config.proxyModeType` 值域（顺序 = 菜单显示序，与浮层 `TAKEOVERS` 同序）。
pub const TAKEOVER_KINDS: [&str; 3] = ["systemProxy", "tun", "manual"];
/// `config.proxyMode` 值域（顺序 = 菜单显示序，与浮层 `MODES` 同序）。
pub const ROUTING_MODES: [&str; 3] = ["smart", "global", "direct"];

// ── 跨窗导航（A1「打开设置」）────────────────────────────────────────────────────
//
// # 选型：给 `tray_show_main` 加**受限**目标屏参数 + 一条窄事件，而不是复活 `EVENT_NAVIGATE`
//
// `events.rs:66-72` 已把 上游的 `navigate` 通道删净并写明理由（Polaris 托盘是同源 webview 浮层，
// 自己渲染子视图，**没有**任何路径需要「跨窗令主窗跳到第 N 屏」）。「打开设置」是那条论证的**唯一反例**：
// 设置屏在主窗里，浮层里没有也不该有。但反例只有一个 ⇒ 不该为它重开一条**任意字符串路由**的通用通道
// （那正是 上游 那条通道会长出 `/server` `/settings` `/logs` 一堆消费点、最后没人说得清谁在用的成因）。
//
// 故取窄形态：
//  1. 复用既有 `tray_show_main` command（不新增 command），加一个 `Option<String>` 目标屏参数——
//     缺省不传 = 今天的行为逐字节不变（既有 `invoke('tray_show_main')` 调用点零改动）。
//  2. 参数经 [`normalize_tray_screen`] **白名单**归一，只有登记过的屏名才会被发出去；未知值一律降级为
//     「只显示主窗、不导航」——通道的值域由 Rust 侧枚举钉死，不是「前端传什么就发什么」。
//  3. 事件 `EVENT_TRAY_OPEN_SCREEN` 单播给主窗（`emit_to_main`），不广播。
//
// 想加第二个目标屏必须同时改白名单 + 补测试，成本恰好落在该落的地方。

/// 托盘可导航的目标屏**白名单**（纯函数，可单测）。
///
/// 返回 `'static` 串而非透传入参：发出去的值域被本函数钉死 ⇒ 前端传任意字符串也只能命中登记项，
/// 通道不会退化成通用路由。当前只有 `settings` 一项（A1「打开设置」）。
#[must_use]
pub fn normalize_tray_screen(screen: &str) -> Option<&'static str> {
    match screen.trim() {
        "settings" => Some("settings"),
        _ => None,
    }
}

// ── 原生面主题（B：后端此前零读 `uiTheme`）──────────────────────────────────────

/// 浅色 / 深色的**窗口背景色**（原生面用，webview 首帧之前就已经在屏上）。
///
/// 取值 = `ui/src/styles/tokens.css` 的 `--bg`（深 `220 40% 6%` = #0B0F14，与 `tauri.conf.json` 主窗
/// `backgroundColor` 同值；浅 `210 30% 96%` ≈ #F2F5F8）。
#[must_use]
pub fn window_bg_color(dark: bool) -> tauri::window::Color {
    if dark {
        tauri::window::Color(0x0B, 0x0F, 0x14, 0xFF)
    } else {
        tauri::window::Color(0xF2, 0xF5, 0xF8, 0xFF)
    }
}

/// 浅色 / 深色的**卡片面背景色**（托盘浮层 Linux 实底 / 更新弹窗防白闪）。
/// = tokens 的 `--surface`（深 #161C24，沿用既有取值；浅 #FFFFFF）。
#[must_use]
pub fn surface_color(dark: bool) -> tauri::window::Color {
    if dark {
        tauri::window::Color(0x16, 0x1C, 0x24, 0xFF)
    } else {
        tauri::window::Color(0xFF, 0xFF, 0xFF, 0xFF)
    }
}

/// `config.uiTheme` 对原生窗口外观的显式覆盖。只有 light/dark 钉住窗口；system、空白与
/// 非法值一律交回系统，避免创建时的原生面与运行期 config 更新使用两套解析口径。
#[must_use]
pub fn native_theme_override(ui_theme: Option<&str>) -> Option<tauri::Theme> {
    match ui_theme.map(str::trim) {
        Some("dark") => Some(tauri::Theme::Dark),
        Some("light") => Some(tauri::Theme::Light),
        _ => None,
    }
}

/// `config.uiTheme` + 系统明暗 → 原生面该用深色吗（纯函数，与前端 `tray-theme.ts::resolveDark`
/// 逐分支同构：显式 light/dark 直接定，其余跟随系统）。
///
/// `os_dark` 为 `None`（拿不到系统明暗，见 [`os_dark`]）时回落 **true** —— tokens 默认深色，
/// 且这正是本改动之前的既有行为，取不到信号时不制造新的观感跳变。
#[must_use]
pub fn resolve_native_dark(ui_theme: Option<&str>, os_dark: Option<bool>) -> bool {
    match native_theme_override(ui_theme) {
        Some(tauri::Theme::Dark) => true,
        Some(tauri::Theme::Light) => false,
        // `Theme` 是 non-exhaustive；helper 目前只构造两种显式值，未来变体也按 system 档保守回退。
        Some(_) | None => os_dark.unwrap_or(true),
    }
}

/// 读 `config.uiTheme`（`ConfigManager` 缓存，与 [`crate::i18n::app_lang`] 同款便宜读）。
pub fn ui_theme(app: &AppHandle) -> Option<String> {
    app.try_state::<crate::runtime::AppRuntime>()
        .and_then(|rt| rt.config().current().ok())
        .and_then(|c| c.get("uiTheme").and_then(Value::as_str).map(str::to_string))
}

/// 系统明暗探测。**Tauri 2.11 没有 app 级 theme getter**（只有 `Window::theme()`，见
/// `tauri-runtime/src/lib.rs:787`），故只能借任一现存窗口去问 OS。
///
/// 按 主窗 → 托盘浮层 → 更新弹窗 顺序探（C16 轻量模式**销毁**主窗后仍能从浮层拿到答案）；
/// 一个窗都没有（首建主窗之前）→ `None`，由 [`resolve_native_dark`] 回落深色。
///
/// 与 `app_tray.rs` 里那份 `dark_bg` 探测（模块头 `TrayVisual` 一带）**刻意不合并**：那问的是「**任务栏**底色深浅」
/// （决定托盘图标用黑变体还是白变体），本函数问的是「**UI 主题**该深该浅」。两者今天都由系统明暗回答，
/// 但语义不同轴——合并会让「以后想让托盘图标跟任务栏、UI 跟 uiTheme」这类分叉无处落脚。
pub fn os_dark(app: &AppHandle) -> Option<bool> {
    for label in [
        "main",
        TRAY_LABEL,
        crate::runtime::update_popup::POPUP_LABEL,
    ] {
        if let Some(w) = app.get_webview_window(label) {
            if let Ok(t) = w.theme() {
                return Some(t == tauri::Theme::Dark);
            }
        }
    }
    None
}

/// `config.uiTheme` + 现存窗口探到的系统明暗 → 原生面深色否（[`resolve_native_dark`] 的 app 侧薄封装）。
pub fn native_dark(app: &AppHandle) -> bool {
    resolve_native_dark(ui_theme(app).as_deref(), os_dark(app))
}

/// 主窗 FOUC 预解析脚本（`initialization_script` 注入，**先于页面任何脚本、且不受页面 CSP
/// `script-src 'self'` 限制** —— 与 `window::TRAY_BLUR_DISMISS_JS` / `update_popup` 的 `init_script` 同款手法）。
///
/// # 为什么必须是注入脚本，而不是 `index.html` 里的内联 `<script>`
///
/// `ui/index.html` 的 CSP 是 `script-src 'self'`，内联脚本会被直接拦掉；放宽成 `'unsafe-inline'`
/// 为一句主题赋值换掉整页的脚本注入防线，不划算。而**能同步读到 `uiTheme` 真值的只有主进程**
/// （它在 config.json 里，前端拿到它已经是 IPC 之后、第一帧早过去了）——真值源与执行时机在这里天然重合。
///
/// # 语义：只**播种**，不接管
///
/// `hasAttribute` 守卫 ⇒ 属性已存在就不写。`AppShell.tsx` 的主题 effect 才是运行期真值的持有者
/// （用户在设置里改主题即时生效走它），本脚本只负责把「第一帧之前」这段空窗填上，绝不与它抢。
#[must_use]
pub fn theme_boot_script(dark: bool) -> String {
    let theme = if dark { "dark" } else { "light" };
    format!(
        r#"(function () {{
  var t = '{theme}';
  window.__POLARIS_INITIAL_THEME__ = t;
  function apply() {{
    var el = document.documentElement;
    if (el && !el.hasAttribute('data-theme')) el.setAttribute('data-theme', t);
  }}
  apply();
  document.addEventListener('readystatechange', apply);
  document.addEventListener('DOMContentLoaded', apply);
}})();
"#
    )
}

// ── FakeIP-TUN 待纠正快照（A7 原生菜单切接管方式要用）────────────────────────────

/// 消费「FakeIP-TUN 待纠正」快照 —— `ui/.../home/fakeip-tun-entry.ts::applyFakeIpTunEntry` 的 Rust 同构体。
///
/// 仅当目标模式为 `tun` 且 `dnsConfig.fakeIpTunAutoEnable === true` 时，把迁移期冻结的
/// `enableFakeIp:false` 回 `true` 并**一次性消费** flag（置 false）；其余一律不动。
/// flag 由 `crates/store/src/migrate.rs::migrate_fake_ip_tun_pending` 写入。
///
/// # 为什么要在 Rust 侧也有一份
///
/// 浮层与主窗切接管方式走前端那份；**原生兜底菜单**（A7，Linux 左键不递送时的唯一入口）在 Rust 侧
/// 落盘，够不着前端函数。若这条腿直接写 `proxyModeType` 而跳过纠正，Linux 用户从原生菜单进 TUN 就会
/// 带着 `enableFakeIp:false` 起核 —— 与另两个入口行为分叉。两份实现由**同一组用例**钉住（本模块 tests
/// 与 `fakeip-tun-entry` 的前端单测覆盖同样的四个分支）。
///
/// 返回 `true` 表示**真把 false 改成了 true**（供调用方决定要不要告知用户；flag 开着但值本就是 true
/// 时只消费 flag、返 false）。
pub fn apply_fake_ip_tun_entry(config: &mut Value) -> bool {
    let mode_type = config
        .get("proxyModeType")
        .and_then(Value::as_str)
        .unwrap_or("systemProxy")
        .to_ascii_lowercase();
    if mode_type != "tun" {
        return false;
    }
    let pending = config
        .get("dnsConfig")
        .and_then(|d| d.get("fakeIpTunAutoEnable"))
        .and_then(Value::as_bool)
        == Some(true);
    if !pending {
        return false;
    }
    let schema_v2 = config
        .get("configSchemaVersion")
        .and_then(Value::as_u64)
        .is_some_and(|version| version >= 2);
    let corrected = {
        let Some(dns) = config.get_mut("dnsConfig").and_then(Value::as_object_mut) else {
            return false; // 上面已确认 dnsConfig 里有该 flag ⇒ 不可达；防御式返回，不 panic
        };
        let corrected = dns.get("enableFakeIp").and_then(Value::as_bool) == Some(false);
        if corrected {
            dns.insert("enableFakeIp".into(), Value::Bool(true));
        }
        dns.insert("fakeIpTunAutoEnable".into(), Value::Bool(false));
        corrected
    };
    // v2 的 config-engine 以根 dnsDefaults 为一等真值；只在真正纠正 legacy 镜像时同步。
    // 不重建已有对象：自定义默认项必须原样保留，缺失的 builtin 回退与前端同口径补齐。
    if corrected && schema_v2 {
        let root = config
            .as_object_mut()
            .expect("FakeIP-TUN 仅处理 JSON object config");
        let defaults = root
            .entry("dnsDefaults")
            .or_insert_with(|| Value::Object(Default::default()));
        if !defaults.is_object() {
            *defaults = Value::Object(Default::default());
        }
        let defaults = defaults
            .as_object_mut()
            .expect("dnsDefaults 已规范化为 object");
        defaults
            .entry("directServerId")
            .or_insert_with(|| Value::String("builtin-domestic".into()));
        defaults
            .entry("proxyServerId")
            .or_insert_with(|| Value::String("builtin-remote".into()));
        defaults.insert(
            "unmatchedAction".into(),
            serde_json::json!({ "type": "fakeIp" }),
        );
    }
    corrected
}
