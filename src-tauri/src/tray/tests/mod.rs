use super::lifecycle::{overlay_retention_action, OverlayRetentionAction};
use super::model::{
    native_theme_override, normalize_tray_screen, resolve_native_dark, tooltip_status_key,
};
use super::placement::{
    overlay_physical_size, overlay_xy, physical_tray_rect, resolve_tray_edge,
    tray_edge_boot_script, ScreenArea, TrayEdge,
};
use super::window::{TRAY_EDGE_GAP_LOGICAL, TRAY_MAX_HEIGHT_LOGICAL, TRAY_WIDTH};
use super::*;
use crate::i18n::{t, Lang};
use tauri::{PhysicalPosition, PhysicalSize};

mod autosave_name_gate;
mod overlay_lifecycle_gate;

// 取材面 = 模块（`tray.rs` 根文件 + `tray/**` 递归，剔除 `tests/`）而非单文件：
// `tray.rs` 正在按域拆成 `tray/{model,lifecycle,window,placement,platform,commands,transition}.rs`，
// 写死 `crate_source("tray.rs")` 的门在函数搬进子模块的那一刻**只剩半张判据面**——
// 下面的 `top_level_fn_body` 锚点会 panic（还算体面），而同文件里的否定型断言会恒真。
use crate::test_support::{crate_code, module_code};

fn rect(x: f64, y: f64, w: f64, h: f64) -> PhysicalRect {
    PhysicalRect { x, y, w, h }
}
// 单显示器 2000×1200@原点，浮层 536×700，gap=4。
const SCREEN: ScreenArea = ScreenArea {
    left: 0,
    top: 0,
    right: 2000,
    bottom: 1200,
};
const WIN: (u32, u32) = (536, 700);
const GAP: i32 = 4;

#[test]
fn overlay_retention_switch_only_changes_the_active_timer_when_needed() {
    use OverlayRetentionAction::{CancelReclaim, None, ScheduleReclaim};

    // 任意无关配置保存都不能续期现有回收计时器。
    assert_eq!(overlay_retention_action(false, false, true), None);
    assert_eq!(overlay_retention_action(true, true, true), None);
    // 开启 warm 必须取消在飞回收，无论浮层当前是否存在/可见。
    assert_eq!(overlay_retention_action(false, true, false), CancelReclaim);
    assert_eq!(overlay_retention_action(false, true, true), CancelReclaim);
    // 关闭 warm：隐藏态立即恢复计时，可见态交给下一次 hide 挂计时。
    assert_eq!(overlay_retention_action(true, false, true), ScheduleReclaim);
    assert_eq!(overlay_retention_action(true, false, false), None);
}

#[test]
fn tray_event_rect_is_already_physical() {
    let event_rect = tauri::Rect {
        position: PhysicalPosition::new(-1180, 2160).into(),
        size: PhysicalSize::new(32, 32).into(),
    };
    assert_eq!(
        physical_tray_rect(event_rect),
        Some(rect(-1180.0, 2160.0, 32.0, 32.0))
    );
}

#[test]
fn top_edge_centers_on_icon_and_hugs_menu_bar() {
    // 图标在菜单栏中右：x=1000 w=44，y=0 h=48。
    let work = ScreenArea { top: 48, ..SCREEN };
    let (x, y) = overlay_xy(
        Some(rect(1000.0, 0.0, 44.0, 48.0)),
        work,
        WIN,
        GAP,
        TrayEdge::Top,
    );
    assert_eq!(x, 1022 - 268); // icon_cx(1022) - win_w/2(268) = 754，水平居中图标
    assert_eq!(y, 48 + GAP); // 图标下沿 + gap，紧贴菜单栏（不是屏顶+28）
}

#[test]
fn bottom_edge_places_above_icon() {
    let work = ScreenArea {
        bottom: 1160,
        ..SCREEN
    };
    let (_, y) = overlay_xy(
        Some(rect(1000.0, 1160.0, 40.0, 40.0)),
        work,
        WIN,
        GAP,
        TrayEdge::Bottom,
    );
    assert_eq!(y, 1160 - 700 - GAP);
}

#[test]
fn bottom_overflow_anchor_still_uses_taskbar_work_edge() {
    let work = ScreenArea {
        bottom: 1160,
        ..SCREEN
    };
    // Windows 隐藏图标面板位于工作区内部；锚点上沿比任务栏边界高 72px。
    // 浮层只沿 x 轴跟随图标，底边仍须与普通系统托盘浮层处于同一高度。
    let (_, y) = overlay_xy(
        Some(rect(1500.0, 1088.0, 40.0, 40.0)),
        work,
        WIN,
        GAP,
        TrayEdge::Bottom,
    );
    assert_eq!(y, work.bottom - 700 - GAP);
}

#[test]
fn platform_tray_gap_scales_from_logical_pixels() {
    let expected = if cfg!(target_os = "windows") { 12 } else { 1 };
    assert_eq!(TRAY_EDGE_GAP_LOGICAL.round() as i32, expected);
    assert_eq!((TRAY_EDGE_GAP_LOGICAL * 2.0).round() as i32, expected * 2);
}

#[test]
fn platform_tray_height_cap_leaves_no_windows_transparent_tail() {
    let expected = if cfg!(target_os = "windows") {
        700.0
    } else {
        720.0
    };
    assert_eq!(TRAY_MAX_HEIGHT_LOGICAL, expected);
}

#[test]
fn overlay_size_conversion_adds_no_hidden_window_chrome() {
    assert_eq!(
        overlay_physical_size(TRAY_WIDTH, 700.0, 1.0),
        PhysicalSize::new(268, 700)
    );
    assert_eq!(
        overlay_physical_size(TRAY_WIDTH, 700.0, 1.25),
        PhysicalSize::new(335, 875)
    );
}

#[test]
fn left_edge_places_right_of_icon() {
    let work = ScreenArea { left: 48, ..SCREEN };
    let (x, y) = overlay_xy(
        Some(rect(0.0, 500.0, 48.0, 40.0)),
        work,
        WIN,
        GAP,
        TrayEdge::Left,
    );
    assert_eq!(x, 48 + GAP);
    assert_eq!(y, 520 - 350);
}

#[test]
fn right_edge_places_left_of_icon() {
    let work = ScreenArea {
        right: 1952,
        ..SCREEN
    };
    let (x, y) = overlay_xy(
        Some(rect(1952.0, 500.0, 48.0, 40.0)),
        work,
        WIN,
        GAP,
        TrayEdge::Right,
    );
    assert_eq!(x, 1952 - 536 - GAP);
    assert_eq!(y, 520 - 350);
}

#[test]
fn degenerate_anchor_falls_back_to_edge_corner() {
    let (x, y) = overlay_xy(
        Some(rect(0.0, 0.0, 0.0, 0.0)),
        SCREEN,
        WIN,
        GAP,
        TrayEdge::Top,
    );
    assert_eq!(x, 2000 - 536 - GAP);
    assert_eq!(y, GAP);
}

#[test]
fn clamps_to_same_negative_coordinate_work_area() {
    let work = ScreenArea {
        left: -2520,
        top: 40,
        right: -48,
        bottom: 1400,
    };
    let (x, y) = overlay_xy(
        Some(rect(-60.0, 1360.0, 40.0, 40.0)),
        work,
        WIN,
        GAP,
        TrayEdge::Bottom,
    );
    assert_eq!(x, -48 - 536);
    assert_eq!(y, work.bottom - 700 - GAP);
}

#[test]
fn reserved_work_edge_breaks_vertical_taskbar_corner_tie() {
    let work = ScreenArea { left: 48, ..SCREEN };
    assert_eq!(
        resolve_tray_edge(
            Some(rect(0.0, 1160.0, 48.0, 40.0)),
            SCREEN,
            work,
            TrayEdge::Bottom,
        ),
        TrayEdge::Left
    );
}

#[test]
fn auto_hidden_taskbar_uses_anchor_with_platform_tie_break() {
    assert_eq!(
        resolve_tray_edge(
            Some(rect(1960.0, 1160.0, 40.0, 40.0)),
            SCREEN,
            SCREEN,
            TrayEdge::Bottom,
        ),
        TrayEdge::Bottom
    );
    assert_eq!(
        resolve_tray_edge(
            Some(rect(1960.0, 0.0, 40.0, 40.0)),
            SCREEN,
            SCREEN,
            TrayEdge::Bottom,
        ),
        TrayEdge::Top
    );
}

#[test]
fn edge_boot_script_sets_stable_css_contract() {
    let script = tray_edge_boot_script(TrayEdge::Right);
    assert!(script.contains("window.__POLARIS_TRAY_EDGE__ = 'right'"));
    assert!(script.contains("data-tray-edge"));
    assert!(script.contains("__POLARIS_SET_TRAY_EDGE__"));
}

#[test]
fn placement_uses_anchor_monitor_and_work_area_not_overlay_current_screen() {
    let tray_rs = module_code("tray");
    let store = crate::commands::guard_scan::top_level_fn_body(&tray_rs, "fn store_anchor(");
    assert!(!store.contains("current_monitor"));
    assert!(!store.contains("to_physical"));

    let placement =
        crate::commands::guard_scan::top_level_fn_body(&tray_rs, "fn overlay_placement(");
    assert!(placement.contains("app.monitor_from_point("));
    assert!(placement.contains("monitor.work_area()"));

    let reposition = crate::commands::guard_scan::top_level_fn_body(&tray_rs, "fn reposition(");
    assert!(!reposition.contains("current_monitor"));
    assert!(reposition.contains("placement.work_area"));
}

// ── 托盘原生文案：五语齐备 + 值→键映射 ─────────────────────────────────────
//
// 语言**解析**的门在 `crate::i18n`（那是纯函数、与托盘无关）。这里只守托盘自己的两件事：
// ① tooltip 的拼装形状；② `config` 取值域 → 文案键的映射不得塌成同一档。

#[test]
fn tooltip_is_brand_plus_localized_status() {
    assert_eq!(
        tooltip_text(Lang::ZhCN, TrayState::Connected),
        "Polaris — 已连接"
    );
    assert_eq!(
        tooltip_text(Lang::EnUS, TrayState::Idle),
        "Polaris — Disconnected"
    );
    assert_eq!(
        tooltip_text(Lang::Ru, TrayState::Error),
        "Polaris — Ошибка подключения"
    );
    // 繁中此前与简中同归一档（旧 TrayLang 二态），这条钉住它现在是**独立**的一档。
    assert_ne!(
        tooltip_text(Lang::ZhTW, TrayState::Connecting),
        tooltip_text(Lang::EnUS, TrayState::Connecting)
    );
    // 五语种四态：一条都不许回落成键名（回落 = 那一格漏译）。
    for lang in crate::i18n::SUPPORTED {
        for st in [
            TrayState::Idle,
            TrayState::Connecting,
            TrayState::Connected,
            TrayState::Error,
        ] {
            let tip = tooltip_text(lang, st);
            assert!(
                tip.starts_with("Polaris — ") && !tip.contains("tray.status"),
                "{lang:?}/{st:?} 的 tooltip 回落成了键名：{tip}"
            );
        }
    }
}

/// 四态必须映射到**四个不同**的键：塌成一个的症状是「连接中 / 连接异常 / 未连接」在 tooltip 上
/// 长得一样，而图标是对的 ⇒ 功能「正常」、纯 UI 撒谎。
#[test]
fn tooltip_status_keys_are_four_distinct_keys() {
    let mut keys: Vec<&str> = [
        TrayState::Idle,
        TrayState::Connecting,
        TrayState::Connected,
        TrayState::Error,
    ]
    .into_iter()
    .map(tooltip_status_key)
    .collect();
    keys.sort_unstable();
    keys.dedup();
    assert_eq!(keys.len(), 4, "托盘四态的文案键塌了");
}

/// 子菜单三档若有两档文案相同，用户根本分不出点的是哪个（而 id 是对的 ⇒ 功能"正常"、纯 UI 撒谎）。
/// 五语种逐个查——旧版本只查 zh/en，ru/fa 的漏译在那道门下恒绿。
#[test]
fn takeover_and_routing_labels_are_distinct_per_value_in_all_languages() {
    for lang in crate::i18n::SUPPORTED {
        for (name, vals, f) in [
            (
                "接管方式",
                TAKEOVER_KINDS,
                takeover_key as fn(&str) -> &'static str,
            ),
            (
                "分流策略",
                ROUTING_MODES,
                routing_key as fn(&str) -> &'static str,
            ),
        ] {
            let mut labels: Vec<String> = vals.iter().map(|v| t(lang, f(v))).collect();
            let n = labels.len();
            assert!(
                labels.iter().all(|l| !l.starts_with("tray.")),
                "{name} 有一档回落成了键名（{lang:?}）：{labels:?}"
            );
            labels.sort_unstable();
            labels.dedup();
            assert_eq!(labels.len(), n, "{name}三档文案必须两两不同（{lang:?}）");
        }
    }
}

/// 值域外的取值必须落到与浮层同一个默认档（`smart` / `systemProxy`），**不得**回落成别的档 ——
/// 那会让托盘显示的当前档与真实配置不符。
#[test]
fn unknown_config_values_fall_back_to_the_same_default_as_the_overlay() {
    assert_eq!(takeover_key("no-such-kind"), takeover_key("systemProxy"));
    assert_eq!(routing_key("no-such-mode"), routing_key("smart"));
}

// ── A1：跨窗导航白名单 ───────────────────────────────────────────────────────

#[test]
fn tray_screen_whitelist_only_admits_registered_targets() {
    assert_eq!(normalize_tray_screen("settings"), Some("settings"));
    assert_eq!(
        normalize_tray_screen(" settings "),
        Some("settings"),
        "容忍空白"
    );
    // 通道**不是**通用路由：未登记值一律拒绝（拒绝 = 只显示主窗、不导航，而不是把串透传出去）。
    for evil in ["", "home", "/settings", "Settings", "nodes", "../settings"] {
        assert_eq!(normalize_tray_screen(evil), None, "{evil} 不该被放行");
    }
}

#[test]
fn tray_screen_boot_script_only_ever_carries_whitelisted_values() {
    // 种子脚本是拼进 JS 字面量的 ⇒ 载荷必须是白名单产物。这条把「有人改成透传入参」钉死：
    // 透传后 `normalize_tray_screen` 的返回类型就不再是 `&'static str`，本断言的形态即失效。
    let s = normalize_tray_screen("settings").expect("白名单里有 settings");
    assert_eq!(
        tray_screen_boot_script(s),
        "window.__POLARIS_TRAY_SCREEN__ = 'settings';\n"
    );
}

// ── 投递腿：种子腿与事件腿**不互斥**（2026-07-28 复审的早启动竞态）──────────────

#[test]
fn pending_is_always_written_when_a_target_screen_is_given() {
    // 被守的缺陷：原状是 `if !main_alive { set_pending_screen(...) }`。于是
    // 「主窗存在但 webview 还没挂上 EVENT_TRAY_OPEN_SCREEN 订阅」这一格里两条腿都够不着 ——
    // 事件 emit 出去没人听、pending 又没写 ⇒ 窗开了、屏没跳，且**静默**。
    // 把 write_pending 改回 `!main_alive` 这条即转红。
    assert!(tray_show_main_legs(true, true).write_pending);
    assert!(tray_show_main_legs(true, false).write_pending);
}

#[test]
fn event_leg_only_fires_when_the_main_window_already_exists() {
    // 窗不存在时 emit 必丢（emit 发生在 webview 装载之前），发了也只是噪声。
    assert!(tray_show_main_legs(true, true).emit_event);
    assert!(!tray_show_main_legs(true, false).emit_event);
}

#[test]
fn no_target_screen_lights_no_leg() {
    // 无参 `tray_show_main()`（「显示主窗口」）必须与本改动前逐字节相同：不写 pending、不 emit。
    // 少了这条，每次点「显示主窗口」都会往 pending 里塞东西 → 下次建窗被送去设置页。
    assert_eq!(
        tray_show_main_legs(false, true),
        TrayShowMainLegs {
            write_pending: false,
            emit_event: false
        }
    );
    assert_eq!(
        tray_show_main_legs(false, false),
        TrayShowMainLegs {
            write_pending: false,
            emit_event: false
        }
    );
}

// ── 「检查更新」结果文案：五语齐备 + 成功/失败不得同形 ────────────────────────

#[test]
fn update_result_labels_are_localized_and_distinguishable() {
    use crate::i18n::key as k;
    for lang in crate::i18n::SUPPORTED {
        for key in [
            k::NATIVE_UPDATE_NOTIFY_TITLE,
            k::TRAY_UP_TO_DATE,
            k::TRAY_UPDATE_CHECK_FAILED,
            k::NATIVE_UNKNOWN_ERROR,
            k::NATIVE_UPDATE_INFO_INCOMPLETE,
            k::NATIVE_UPDATE_POPUP_FAILED,
        ] {
            let s = t(lang, key);
            assert!(!s.trim().is_empty(), "{lang:?} 的 {key} 是空串");
            assert_ne!(s, key, "{lang:?} 的 {key} 回落成了键名 = 那一格漏译");
        }
        // B5 反伪造：失败绝不能显示成「已是最新」。
        assert_ne!(
            t(lang, k::TRAY_UP_TO_DATE),
            t(lang, k::TRAY_UPDATE_CHECK_FAILED)
        );
    }
}

// ── B：原生面主题折算 ────────────────────────────────────────────────────────

#[test]
fn explicit_theme_wins_over_system() {
    // 显式档不看系统（这正是「设置里选了浅色、启动仍闪深色」的修复点）。
    assert!(!resolve_native_dark(Some("light"), Some(true)));
    assert!(resolve_native_dark(Some("dark"), Some(false)));
    assert!(
        !resolve_native_dark(Some(" light "), Some(true)),
        "容忍空白"
    );
}

#[test]
fn system_theme_follows_os_and_falls_back_to_dark() {
    assert!(resolve_native_dark(Some("system"), Some(true)));
    assert!(!resolve_native_dark(Some("system"), Some(false)));
    assert!(!resolve_native_dark(None, Some(false)), "未设 = 跟随系统");
    // 探不到系统明暗（首次建主窗时一个窗都没有）→ 深色，= 本改动前的既有行为，不制造新跳变。
    assert!(resolve_native_dark(Some("system"), None));
    assert!(resolve_native_dark(None, None));
    assert!(resolve_native_dark(Some("weird-value"), None));
}

#[test]
fn native_theme_override_is_the_single_explicit_theme_parser() {
    assert!(matches!(
        native_theme_override(Some("dark")),
        Some(tauri::Theme::Dark)
    ));
    assert!(matches!(
        native_theme_override(Some(" light ")),
        Some(tauri::Theme::Light)
    ));
    for input in [Some("system"), Some("   "), Some("invalid"), None] {
        assert!(
            native_theme_override(input).is_none(),
            "{input:?} 必须交回系统主题"
        );
    }

    let main = crate::commands::guard_scan::top_level_fn_body(
        &crate_code("main.rs"),
        "fn create_main_window(",
    );
    let config = crate::commands::guard_scan::top_level_fn_body(
        &crate_code("commands/config.rs"),
        "fn apply_process_config_projections(",
    );
    let model = crate::commands::guard_scan::top_level_fn_body(
        &crate_code("tray/model.rs"),
        "pub fn resolve_native_dark(",
    );
    assert!(main.contains("tray::native_theme_override(ui_theme.as_deref())"));
    assert!(config.contains("crate::tray::native_theme_override("));
    assert!(model.contains("native_theme_override(ui_theme)"));
    assert!(
        !model.contains("Some(\"dark\")") && !model.contains("Some(\"light\")"),
        "resolve_native_dark 不得另写显式主题 match"
    );
}

#[test]
fn theme_colors_differ_between_light_and_dark() {
    // 变异锁：把 light/dark 映射到同一个色（例如"先都用深色，回头再说"）必须转红 —— 那等于 B 没做。
    assert_ne!(window_bg_color(true).0, window_bg_color(false).0);
    assert_ne!(surface_color(true).0, surface_color(false).0);
    // 深色底必须真的比浅色底暗（防把两个色写反）。
    assert!(window_bg_color(true).0 < window_bg_color(false).0);
    assert!(surface_color(true).0 < surface_color(false).0);
}

#[test]
fn theme_boot_script_seeds_but_does_not_override() {
    let dark = theme_boot_script(true);
    assert!(dark.contains("var t = 'dark';"));
    assert!(theme_boot_script(false).contains("var t = 'light';"));
    // 只播种不接管：属性已存在就不写 —— 否则 DOMContentLoaded 那次回调会把 AppShell 刚设的
    // 运行期真值覆盖回启动值（用户在设置里改主题后，切回主窗会闪回旧主题）。
    assert!(
        dark.contains("!el.hasAttribute('data-theme')"),
        "缺 hasAttribute 守卫 = 会与 AppShell 的主题 effect 抢写"
    );
    // 首帧之前就要落属性：只挂 DOMContentLoaded 而不立即执行一次 = FOUC 照旧。
    assert!(
        dark.contains("apply();\n"),
        "必须立即执行一次，不能只挂事件"
    );
}

// ── A7：FakeIP-TUN 待纠正快照（与前端 applyFakeIpTunEntry 同一组分支）───────────

#[test]
fn fake_ip_tun_entry_corrects_only_when_entering_tun_with_pending_flag() {
    use serde_json::json;
    let mut cfg = json!({
        "proxyModeType": "tun",
        "dnsConfig": { "enableFakeIp": false, "fakeIpTunAutoEnable": true }
    });
    assert!(
        apply_fake_ip_tun_entry(&mut cfg),
        "真把 false 改回 true → 返 true"
    );
    assert_eq!(cfg["dnsConfig"]["enableFakeIp"], json!(true));
    assert_eq!(
        cfg["dnsConfig"]["fakeIpTunAutoEnable"],
        json!(false),
        "flag 一次性消费"
    );
}

#[test]
fn fake_ip_tun_entry_v2_updates_root_defaults_without_shrinking_them() {
    use serde_json::json;
    let mut cfg = json!({
        "proxyModeType": "tun",
        "configSchemaVersion": 2,
        "dnsConfig": { "enableFakeIp": false, "fakeIpTunAutoEnable": true },
        "dnsDefaults": {
            "directServerId": "custom-direct",
            "proxyServerId": "custom-proxy",
            "cacheStrategy": "prefer-cache",
            "unmatchedAction": { "type": "server", "serverId": "custom-direct" }
        }
    });
    assert!(apply_fake_ip_tun_entry(&mut cfg));
    assert_eq!(cfg["dnsConfig"]["enableFakeIp"], json!(true));
    assert_eq!(cfg["dnsDefaults"]["directServerId"], json!("custom-direct"));
    assert_eq!(cfg["dnsDefaults"]["proxyServerId"], json!("custom-proxy"));
    assert_eq!(cfg["dnsDefaults"]["cacheStrategy"], json!("prefer-cache"));
    assert_eq!(
        cfg["dnsDefaults"]["unmatchedAction"],
        json!({ "type": "fakeIp" })
    );

    let mut fallback = json!({
        "proxyModeType": "tun",
        "configSchemaVersion": 2,
        "dnsConfig": { "enableFakeIp": false, "fakeIpTunAutoEnable": true },
        "dnsDefaults": { "custom": true }
    });
    assert!(apply_fake_ip_tun_entry(&mut fallback));
    assert_eq!(fallback["dnsDefaults"]["custom"], json!(true));
    assert_eq!(
        fallback["dnsDefaults"]["directServerId"],
        json!("builtin-domestic")
    );
    assert_eq!(
        fallback["dnsDefaults"]["proxyServerId"],
        json!("builtin-remote")
    );
}

#[test]
fn fake_ip_tun_entry_consumes_flag_without_reporting_correction() {
    use serde_json::json;
    // flag 开着但 enableFakeIp 本就是 true → 只消费 flag，不报"纠正过"（不打扰用户）。
    let mut cfg = json!({
        "proxyModeType": "tun",
        "configSchemaVersion": 2,
        "dnsConfig": { "enableFakeIp": true, "fakeIpTunAutoEnable": true },
        "dnsDefaults": { "unmatchedAction": { "type": "server", "serverId": "keep" } }
    });
    assert!(!apply_fake_ip_tun_entry(&mut cfg));
    assert_eq!(cfg["dnsConfig"]["fakeIpTunAutoEnable"], json!(false));
    assert_eq!(
        cfg["dnsDefaults"]["unmatchedAction"],
        json!({ "type": "server", "serverId": "keep" }),
        "没有真正纠正 legacy 开关时不得改 v2 一等动作"
    );
}

#[test]
fn fake_ip_tun_entry_leaves_non_tun_and_unflagged_configs_untouched() {
    use serde_json::json;
    // 非 tun：flag 存续到真进 TUN 才消费（systemProxy→manual→tun 的绕行仍应纠正）。
    let mut cfg = json!({
        "proxyModeType": "manual",
        "dnsConfig": { "enableFakeIp": false, "fakeIpTunAutoEnable": true }
    });
    let before = cfg.clone();
    assert!(!apply_fake_ip_tun_entry(&mut cfg));
    assert_eq!(cfg, before, "非 tun 一律不动（含不得提前消费 flag）");

    // 无 flag（用户手改过 DNS 开关 = 撤销意图）：进 TUN 也不得自动开回来。
    let mut cfg = json!({
        "proxyModeType": "tun",
        "dnsConfig": { "enableFakeIp": false, "fakeIpTunAutoEnable": false }
    });
    let before = cfg.clone();
    assert!(!apply_fake_ip_tun_entry(&mut cfg));
    assert_eq!(cfg, before, "flag 已撤销 → 不得误纠正");

    // 连 dnsConfig 都没有：不 panic、不凭空造字段。
    let mut cfg = json!({ "proxyModeType": "tun" });
    assert!(!apply_fake_ip_tun_entry(&mut cfg));
    assert_eq!(cfg, json!({ "proxyModeType": "tun" }));

    // legacy schema：仍纠正旧镜像和消费 flag，但不得凭空改 v2 根默认动作。
    let mut legacy = json!({
        "proxyModeType": "tun",
        "configSchemaVersion": 1,
        "dnsConfig": { "enableFakeIp": false, "fakeIpTunAutoEnable": true },
        "dnsDefaults": { "unmatchedAction": { "type": "server", "serverId": "legacy" } }
    });
    assert!(apply_fake_ip_tun_entry(&mut legacy));
    assert_eq!(
        legacy["dnsDefaults"]["unmatchedAction"],
        json!({ "type": "server", "serverId": "legacy" })
    );
}
