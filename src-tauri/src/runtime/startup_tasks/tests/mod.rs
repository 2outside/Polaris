use super::*;
use serde_json::json;

// ── decide_auto_connect ───────────────────────────────────────────────────
#[test]
fn auto_connect_enabled_with_selected_server() {
    let cfg = json!({ "autoConnect": true, "selectedServerId": "srv-1" });
    assert_eq!(
        decide_auto_connect(&cfg),
        AutoConnectDecision::Connect {
            server_id: "srv-1".to_string()
        }
    );
}

#[test]
fn auto_connect_enabled_without_server_is_warn_branch() {
    // 开关开但没选 → NoServerSelected（对齐 上游 warn 日志分支，不静默当 Disabled）。
    assert_eq!(
        decide_auto_connect(&json!({ "autoConnect": true })),
        AutoConnectDecision::NoServerSelected
    );
    assert_eq!(
        decide_auto_connect(&json!({ "autoConnect": true, "selectedServerId": "" })),
        AutoConnectDecision::NoServerSelected,
        "空串视同未选"
    );
    assert_eq!(
        decide_auto_connect(&json!({ "autoConnect": true, "selectedServerId": 42 })),
        AutoConnectDecision::NoServerSelected,
        "非字符串视同未选"
    );
}

#[test]
fn auto_connect_disabled_by_default_and_on_bad_types() {
    assert_eq!(
        decide_auto_connect(&json!({})),
        AutoConnectDecision::Disabled,
        "缺字段 → 关"
    );
    assert_eq!(
        decide_auto_connect(&json!({ "autoConnect": false, "selectedServerId": "s" })),
        AutoConnectDecision::Disabled
    );
    assert_eq!(
        decide_auto_connect(&json!({ "autoConnect": "true", "selectedServerId": "s" })),
        AutoConnectDecision::Disabled,
        "非 bool → 关（不做字符串 truthy 推断）"
    );
}

// ── should_auto_check_update ──────────────────────────────────────────────
#[test]
fn auto_check_update_defaults_to_true() {
    assert!(should_auto_check_update(&json!({})), "缺字段 → 开");
    assert!(should_auto_check_update(
        &json!({ "autoCheckUpdate": true })
    ));
    assert!(
        should_auto_check_update(&json!({ "autoCheckUpdate": "no" })),
        "非 bool → 开（!== false 语义）"
    );
    assert!(!should_auto_check_update(
        &json!({ "autoCheckUpdate": false })
    ));
}

// ── should_warn_core_baseline ─────────────────────────────────────────────
const BUNDLED: &str = "1.13.13";

#[test]
fn baseline_warning_never_for_official_core() {
    // 官方核无论版本高低都不提醒。
    assert!(!should_warn_core_baseline(
        CoreBuildKind::Official,
        "1.0.0",
        BUNDLED
    ));
    assert!(!should_warn_core_baseline(
        CoreBuildKind::Official,
        BUNDLED,
        BUNDLED
    ));
}

#[test]
fn baseline_warning_for_fork_at_or_below_bundled() {
    // fork 主版本低于基线 → 提醒。
    assert!(should_warn_core_baseline(
        CoreBuildKind::Fork,
        "1.12.8-reF1nd",
        BUNDLED
    ));
    // fork 与基线同主版本（带 fork 尾段 → 规范化后是 prerelease，序低于正式版）→ 提醒。
    assert!(should_warn_core_baseline(
        CoreBuildKind::Fork,
        "1.13.13-reF1nd",
        BUNDLED
    ));
}

#[test]
fn baseline_warning_not_for_fork_above_bundled() {
    assert!(!should_warn_core_baseline(
        CoreBuildKind::Fork,
        "1.14.0-reF1nd",
        BUNDLED
    ));
    assert!(!should_warn_core_baseline(
        CoreBuildKind::Fork,
        "2.0.0-nekolsd",
        BUNDLED
    ));
}

#[test]
fn baseline_warning_for_unknown_equal_to_bundled() {
    // unknown 且恰等基线 → 提醒（`<=` 含等号）。
    assert!(should_warn_core_baseline(
        CoreBuildKind::Unknown,
        BUNDLED,
        BUNDLED
    ));
}

#[test]
fn baseline_warning_suppressed_on_unparsable_versions() {
    // 版本串不可解析 → 一律不提醒（compare_semver 会把它当 0.0.0 判「远低于基线」→ 误报）。
    assert!(!should_warn_core_baseline(
        CoreBuildKind::Unknown,
        "garbage-output",
        BUNDLED
    ));
    assert!(!should_warn_core_baseline(
        CoreBuildKind::Unknown,
        "",
        BUNDLED
    ));
    assert!(!should_warn_core_baseline(
        CoreBuildKind::Fork,
        "sing-box",
        BUNDLED
    ));
    // 基线侧不可解析（理论上不该发生）同样不提醒。
    assert!(!should_warn_core_baseline(
        CoreBuildKind::Fork,
        "1.0.0",
        "not-a-version"
    ));
}

#[test]
fn kind_label_maps_fork_and_unknown() {
    assert_eq!(kind_label(CoreBuildKind::Fork), "fork");
    assert_eq!(kind_label(CoreBuildKind::Unknown), "unknown");
}

// ── should_auto_download_update ───────────────────────────────────────────
#[test]
fn auto_download_defaults_to_off_and_needs_explicit_true() {
    assert!(
        !should_auto_download_update(&json!({})),
        "缺字段 → 关（几十 MB 流量不能替用户做主）"
    );
    assert!(!should_auto_download_update(
        &json!({ "autoDownloadUpdate": false })
    ));
    assert!(
        !should_auto_download_update(&json!({ "autoDownloadUpdate": "true" })),
        "非 bool → 关（不做字符串 truthy 推断）"
    );
    assert!(should_auto_download_update(
        &json!({ "autoDownloadUpdate": true })
    ));
}

/// 🟡 **`autoDownloadUpdate` 与 `autoCheckUpdate` 方向相反，且前者不得越过后者。**
///
/// 「不得越过」是结构性的（下载腿挂在检查腿内部），此处钉住的是两个缺省方向不同这件事 ——
/// 把 `should_auto_download_update` 抄成 `!= Some(false)` 的形态会让它转红。
#[test]
fn auto_download_and_auto_check_defaults_point_opposite_ways() {
    let empty = json!({});
    assert!(should_auto_check_update(&empty), "检查缺省开（只读、免费）");
    assert!(
        !should_auto_download_update(&empty),
        "下载缺省关（几十 MB，可能在计费网络上）"
    );
}

// ── auto_download_applicable（复用安装侧同一判定）─────────────────────────
#[test]
fn auto_download_skips_assets_that_could_never_be_installed_here() {
    let exe = std::path::Path::new("/opt/polaris/polaris");
    // Linux 安装态（无 APPIMAGE）+ .deb → 装得上。
    assert!(auto_download_applicable("linux", "polaris_1.2.3_amd64.deb", exe, None, None).is_ok());
    // Linux 安装态 + AppImage 资产 → 形态错配，跳过（下了也只能交系统）。
    assert!(
        auto_download_applicable("linux", "Polaris-1.2.3.AppImage", exe, None, None).is_err(),
        "deb 安装态拿到 AppImage 属错配，不该白下"
    );
    // AppImage 运行态 + .deb → **安全闸**（绝不自动提权装 deb）→ 跳过。
    let appimage = std::path::Path::new("/home/u/Polaris.AppImage");
    assert!(auto_download_applicable(
        "linux",
        "polaris_1.2.3_amd64.deb",
        exe,
        Some(appimage),
        None
    )
    .is_err());
    // 不认识的资产后缀 → 跳过。
    assert!(auto_download_applicable("linux", "polaris-1.2.3.tar.gz", exe, None, None).is_err());
    // 空文件名 → 跳过（不猜）。
    assert!(auto_download_applicable("linux", "", exe, None, None).is_err());
    // macOS dmg / Windows exe → 装得上。
    assert!(auto_download_applicable(
        "macos",
        "Polaris-1.2.3.dmg",
        std::path::Path::new("/Applications/Polaris.app/Contents/MacOS/polaris"),
        None,
        None
    )
    .is_ok());
    assert!(auto_download_applicable(
        "windows",
        "Polaris-Setup-1.2.3.exe",
        std::path::Path::new("C:\\Program Files\\Polaris\\polaris.exe"),
        None,
        None
    )
    .is_ok());
}

// ── should_notify_helper_upgradeable ──────────────────────────────────────
fn helper_status(installed: bool, ready: bool, upgradeable: bool) -> HelperStatusSnapshot {
    HelperStatusSnapshot {
        supported: true,
        installed,
        ready,
        upgradeable,
        ..HelperStatusSnapshot::default()
    }
}

#[test]
fn helper_upgradeable_notified_only_when_installed_and_upgradeable() {
    assert!(should_notify_helper_upgradeable(&helper_status(
        true, true, true
    )));
    assert!(
        !should_notify_helper_upgradeable(&helper_status(true, true, false)),
        "已是最新 → 不发（白发会让前端白拉一次 status）"
    );
    assert!(
        !should_notify_helper_upgradeable(&helper_status(false, false, false)),
        "未安装 → 不发（该引导用户「安装」而非「升级」）"
    );
    assert!(
        !should_notify_helper_upgradeable(&HelperStatusSnapshot::default()),
        "缺省态（不支持/未装）一律不发"
    );
}

/// 🟡 **五条启动腿必须各占各的时刻**——本文件自己立的错峰约定（见 `CORE_BASELINE_DELAY_MS`
/// 「错开上面 2s/5s 两个高峰」），此前出口 IP 首探与自动连接双双 2s、正面违反。
///
/// 撞点的后果不止是启动瞬间的资源峰值：自动连接会起核，起核腿随即排一发 4s 后的重探，与同刻起跑
/// 的首探腿形成竞态（落地顺序另由 `commands::misc` 的世代闸兜底，但两条腿本就不该同刻发车）。
///
/// **变异锁**：把 `EXIT_IP_PROBE_DELAY_MS` 改回 `2_000`、或把 helper 探测排到 6s → 本条转红。
#[test]
fn startup_leg_delays_are_all_distinct() {
    let delays = [
        ("自动连接", AUTO_CONNECT_DELAY_MS),
        ("出口 IP 首探", EXIT_IP_PROBE_DELAY_MS),
        ("自动检查更新", AUTO_CHECK_UPDATE_DELAY_MS),
        ("内核基线提醒", CORE_BASELINE_DELAY_MS),
        ("helper 可升级探测", HELPER_UPGRADEABLE_DELAY_MS),
    ];
    for (i, (name_a, a)) in delays.iter().enumerate() {
        for (name_b, b) in &delays[i + 1..] {
            assert_ne!(
                a, b,
                "「{name_a}」与「{name_b}」都排在 {a}ms —— 违反本文件的启动腿错峰约定"
            );
        }
    }
}
