use super::*;
use crate::runtime::core_update_scheduler::method_scan::method_body;
use crate::test_support::crate_code;
use serde_json::json;
use std::time::Duration;

/// 本文件源码（调用点守卫共用）。
fn src() -> String {
    crate_code("runtime/core_update_scheduler.rs")
}

// ── 总开关（变异锁：任何把它改成 `!= Some(false)` 的变异都会转红）─────────────
#[test]
fn auto_update_core_defaults_to_off_and_needs_explicit_true() {
    assert!(
        !auto_update_core_enabled(&json!({})),
        "缺字段必须视为关 —— 静默换核不能是默认行为"
    );
    assert!(!auto_update_core_enabled(
        &json!({ "autoUpdateCore": false })
    ));
    assert!(
        !auto_update_core_enabled(&json!({ "autoUpdateCore": "true" })),
        "非 bool 一律关（不做字符串 truthy 推断）"
    );
    assert!(!auto_update_core_enabled(&json!({ "autoUpdateCore": 1 })));
    assert!(auto_update_core_enabled(&json!({ "autoUpdateCore": true })));
}

fn check(
    has_update: bool,
    current: &str,
    latest: &str,
    cross_band: bool,
    url: &str,
) -> serde_json::Value {
    json!({
        "hasUpdate": has_update,
        "currentVersion": current,
        "latestVersion": latest,
        "downloadUrl": url,
        "sha256": "a".repeat(64),
        "crossBand": cross_band,
    })
}

// ── decide_cycle 真值表 ──────────────────────────────────────────────────
#[test]
fn in_band_update_downloads() {
    let d = decide_cycle(
        &check(true, "1.13.13", "1.13.14", false, "https://x/core.tar.gz"),
        None,
        None,
    );
    assert_eq!(
        d.action,
        CycleAction::Download {
            latest: "1.13.14".into(),
            url: "https://x/core.tar.gz".into(),
            sha256: Some("a".repeat(64)),
        }
    );
    assert!(!d.clear_cross_band_notice);
}

/// 🟡 **变异锁：跨带必须 stage 都不 stage —— 连下载都不许发生。**
///
/// 把 `if cross_band` 分支删掉 ⇒ 本条转红（会变成 Download）。
#[test]
fn cross_band_never_downloads_only_notifies_once() {
    let c = check(true, "1.13.13", "1.14.0", true, "https://x/core.tar.gz");
    // 首次：提示。
    let d = decide_cycle(&c, None, None);
    assert_eq!(
        d.action,
        CycleAction::CrossBand {
            latest: "1.14.0".into(),
            notify: true
        },
        "跨带只能提示，绝不下载/暂存"
    );
    // 已提示过同一版本 → 不重复提示（仍不下载）。
    let d2 = decide_cycle(&c, None, Some("1.14.0"));
    assert_eq!(
        d2.action,
        CycleAction::CrossBand {
            latest: "1.14.0".into(),
            notify: false
        }
    );
}

#[test]
fn cross_band_with_staged_same_version_still_does_not_apply() {
    // 跨带闸优先于「同版本 staged 直落位」：跨带的 staged 绝不能被自动落位。
    let c = check(true, "1.13.13", "1.14.0", true, "https://x/core.tar.gz");
    let d = decide_cycle(&c, Some("1.14.0"), None);
    assert!(
        matches!(d.action, CycleAction::CrossBand { .. }),
        "跨带时即便有同版本 staged 也不得走落位分支，实得 {:?}",
        d.action
    );
}

#[test]
fn staged_same_version_applies_without_redownload() {
    let d = decide_cycle(
        &check(true, "1.13.13", "1.13.14", false, "https://x/core.tar.gz"),
        Some("1.13.14"),
        None,
    );
    assert_eq!(d.action, CycleAction::ApplyStaged);
}

#[test]
fn no_update_or_missing_url_is_idle() {
    // 无 latest。
    assert_eq!(
        decide_cycle(&json!({ "hasUpdate": false }), None, None).action,
        CycleAction::Idle
    );
    // 带内但已是最新。
    assert_eq!(
        decide_cycle(
            &check(false, "1.13.14", "1.13.14", false, "https://x/c"),
            None,
            None
        )
        .action,
        CycleAction::Idle
    );
    // 有更新但缺下载地址（后端契约破损）→ Idle，**不**编一个空 URL 去下载。
    assert_eq!(
        decide_cycle(&check(true, "1.13.13", "1.13.14", false, ""), None, None).action,
        CycleAction::Idle
    );
}

#[test]
fn stale_cross_band_notice_is_cleared_once_caught_up() {
    // 当前核已升到 1.14.0（≥ 提示的 1.14.0）→ 清提示。
    let d = decide_cycle(
        &check(false, "1.14.0", "1.14.0", false, ""),
        None,
        Some("1.14.0"),
    );
    assert!(d.clear_cross_band_notice, "已追上 → 清跨带提示");
    // 同带（1.14.3 vs 提示的 1.14.0）也算消化。
    let d2 = decide_cycle(
        &check(false, "1.14.3", "1.14.3", false, ""),
        None,
        Some("1.14.0"),
    );
    assert!(d2.clear_cross_band_notice);
    // 仍落后 → 不清。
    let d3 = decide_cycle(
        &check(true, "1.13.13", "1.14.0", true, "https://x/c"),
        None,
        Some("1.14.0"),
    );
    assert!(!d3.clear_cross_band_notice);
}

// ── 事件 payload ─────────────────────────────────────────────────────────
#[test]
fn auto_status_payload_matches_frontend_contract() {
    let mut st = UpdateStateFile::default();
    assert_eq!(
        build_auto_status_payload(&st, None),
        json!({ "lastCheckAt": null, "staged": null, "crossBandLatest": null })
    );
    st.last_check_at = Some(1_700_000_000_000);
    st.staged = Some(StagedRecord {
        version: "1.13.14".into(),
        dir: "/tmp/core-staged".into(),
        staged_at: "2026-07-28T00:00:00.000Z".into(),
    });
    st.cross_band_notified_version = Some("1.14.0".into());
    let p = build_auto_status_payload(&st, None);
    assert_eq!(p["lastCheckAt"], json!(1_700_000_000_000u64));
    assert_eq!(p["staged"]["version"], json!("1.13.14"));
    assert_eq!(p["staged"]["stagedAt"], json!("2026-07-28T00:00:00.000Z"));
    assert_eq!(p["crossBandLatest"], json!("1.14.0"));
    // payload **不得**含 autoUpdateEnabled（= 上游 M3：占位会覆盖渲染端从快照拿到的真值）。
    assert!(p.get("autoUpdateEnabled").is_none());
    // staged 只投 version/stagedAt（dir 是本地路径，无需外泄给渲染端）。
    assert!(p["staged"].get("dir").is_none());
}

#[test]
fn auto_status_payload_override_clears_or_sets_cross_band() {
    let st = UpdateStateFile {
        cross_band_notified_version: Some("1.14.0".into()),
        ..UpdateStateFile::default()
    };
    assert_eq!(
        build_auto_status_payload(&st, Some(None))["crossBandLatest"],
        json!(null),
        "显式清除须立刻反映到事件里（否则 UI 旧提示常驻）"
    );
    assert_eq!(
        build_auto_status_payload(&st, Some(Some("1.15.0")))["crossBandLatest"],
        json!("1.15.0")
    );
}

// ── staged 生产端适配器 ──────────────────────────────────────────────────
#[test]
fn prepared_bytes_source_refuses_foreign_urls() {
    // 结构性防线：这个 downloader 只交付「已解归档的裸核字节」，绝不能被当成通用下载器
    // 去「下载」一个真 URL（那会把归档字节原样暂存成 sing-box）。
    let src = PreparedCoreBytes(b"raw-core".to_vec());
    assert_eq!(src.download(PREPARED_BYTES_URL).unwrap(), b"raw-core");
    let err = src
        .download("https://github.com/SagerNet/sing-box/releases/download/v1/x.tar.gz")
        .unwrap_err();
    assert!(matches!(err, DownloadError::Other(_)));
}

/// 🟡 **调用点守卫：总开关必须早退在 `core_update_check` 之前。**
///
/// 前身 `disabled_switch_short_circuits_before_any_network` **名不副实**：它只断言了两个纯函数
/// （`auto_update_core_enabled(false) == false` 与 `decide_cycle` 不看总开关），
/// 而「闸 1 早退于任何网络请求之前」这条**接线顺序**零锁 —— 把 enabled 判定挪到
/// `core_update_check` 之后（= 关着开关也照打 GitHub）时，那个测试全绿。
///
/// 现在按本仓 guard_scan 模式锁 `run_cycle` 体内的实际出现顺序。
/// **变异探针**：把 `if !auto_update_core_enabled(&config) { return false; }` 挪到
/// `core_update_check` 调用之后（或整段删掉）⇒ 本条转红。
#[test]
fn disabled_switch_short_circuits_before_any_network() {
    let src = src();
    let body = method_body(&src, "async fn run_cycle(");
    let gate_at = body
        .find("auto_update_core_enabled(&config)")
        .expect("总开关闸被删了 —— 关着开关也会打 GitHub 并静默换核");
    let network_at = body
        .find("core_update_check(")
        .expect("锚点消失：守卫已失去判据（run_cycle 不再调 core_update_check？）");
    assert!(
        gate_at < network_at,
        "总开关判定必须出现在 core_update_check **之前** —— 否则「关掉自动更新」这句话是假的：\
             每 6h tick 照样向 GitHub 发一次请求"
    );
    // fork 硬闸同理：零网络早退（第三方核绝不被官方核覆盖）。
    let fork_at = body
        .find("CoreBuildKind::Fork")
        .expect("fork 硬闸被删了 —— 官方 release 会覆盖用户明确选择的特性分支核");
    assert!(fork_at < network_at, "fork 闸也必须前置于网络请求");

    // 判定本体（纯函数）的真值另有 `auto_update_core_defaults_to_off_and_needs_explicit_true` 锁；
    // 这里顺带确认职责分离：决策层自己不看总开关。
    let d = decide_cycle(
        &check(true, "1.13.13", "1.13.14", false, "https://x/c"),
        None,
        None,
    );
    assert!(
        matches!(d.action, CycleAction::Download { .. }),
        "决策层本身不看总开关（职责分离）；总开关的牙齿在 run_cycle 的早退"
    );
}

/// 🟡 **变异锁：`running` 闩在 panic 后必须已释放。**
///
/// 不释放 ⇒ [`UpdateScheduler::should_check`] 永假 ⇒ 内核自动更新静默死亡到进程重启，
/// 且零自曝。**变异探针**：把 [`RunGuard`] 的 `Drop` 实现删掉 / 让它在 `finished` 为 false 时
/// 也直接 return ⇒ 本条转红。
#[test]
fn run_guard_releases_running_even_on_panic() {
    let cfg = ScheduleConfig {
        startup_delay: Duration::ZERO, // 让 should_check 只受 running 影响
        ..ScheduleConfig::default()
    };
    let inner = Mutex::new(UpdateScheduler::new(cfg, SystemClock));
    {
        let mut s = inner.lock().unwrap();
        s.start();
        s.mark_running();
        assert!(!s.should_check(), "前提：running 置位时 should_check 为假");
    }

    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = RunGuard::new(&inner);
        panic!("run_cycle 链上的 panic");
    }));
    assert!(panicked.is_err(), "前提：闭包确实 panic 了");

    assert!(
        inner.lock().unwrap().should_check(),
        "panic 后 running 闩仍占着 —— 自动更新会静默死亡到下次重启"
    );
}

/// 正常收尾：`finish(true)` 刷 `last_check` 并释放闩；`finish(false)` 只释放不刷
/// （失败轮保留旧值让 6h tick 下轮重试，而不是把整 24h due 推迟）。
#[test]
fn run_guard_finish_refreshes_last_check_only_on_success() {
    let cfg = ScheduleConfig {
        startup_delay: Duration::ZERO,
        ..ScheduleConfig::default()
    };
    let inner = Mutex::new(UpdateScheduler::new(cfg, SystemClock));
    inner.lock().unwrap().start();

    // 失败轮：last_check 不动（仍是 0 = 从未检查）。
    inner.lock().unwrap().mark_running();
    assert_eq!(RunGuard::new(&inner).finish(false), 0);
    assert!(inner.lock().unwrap().should_check(), "失败轮也必须释放闩");

    // 成功轮：last_check 被刷成「刚刚」→ 24h due 闸随即生效。
    inner.lock().unwrap().mark_running();
    let last = RunGuard::new(&inner).finish(true);
    assert!(last > 0, "成功检查必须刷新 lastCheckAt，实得 {last}");
    assert!(
        !inner.lock().unwrap().should_check(),
        "刚成功检查过 → 24h due 闸必须挡住下一轮"
    );
}

/// 🟡 **调用点守卫：`cycle_if_due` 必须把 `RunGuard` 持在 `run_cycle` 两侧。**
///
/// **变异探针**：删掉 `RunGuard::new(` / 把它挪到 `self.run_cycle(` 之后 / 在方法体里
/// 直接手写 `mark_done`（绕过 guard）⇒ 逐条转红。
#[test]
fn cycle_if_due_holds_a_run_guard_across_the_cycle() {
    let src = src();
    let body = method_body(&src, "async fn cycle_if_due(");
    let guard_at = body
        .find("RunGuard::new(")
        .expect("running 闩的 RAII 守卫被删了 —— panic 一次自动更新就静默死亡");
    let cycle_at = body
        .find("self.run_cycle(")
        .expect("锚点消失：守卫已失去判据");
    assert!(
        guard_at < cycle_at,
        "RunGuard 必须在 run_cycle **之前**建立 —— 建在后面就覆盖不到 run_cycle 的 panic"
    );
    assert!(
        !body.contains("mark_done("),
        "mark_done 必须只在 RunGuard 内调用 —— 方法体里手写一份就又有了「panic 时跳过」的路径"
    );
}

/// 🟡 **调用点守卫：自动落位必须走「绝不断流」的那个入口。**
///
/// 走 `core_update_apply_staged`（手动入口）⇒ 命令层的 `swap_core_with_restart` 会在
/// `was_running == true` 时照常 stop→swap→restart，把「先判后停」之间几百 ms 的 TOCTOU
/// 变成一次用户从未同意的断流。**变异探针**：把 `_auto` 后缀去掉 ⇒ 本条转红。
#[test]
fn apply_staged_auto_uses_the_no_interrupt_entry_point() {
    let src = src();
    let body = method_body(&src, "async fn apply_staged_auto(");
    assert!(
        body.contains("core_update_apply_staged_auto("),
        "自动落位腿必须调 `core_update_apply_staged_auto`（SwapInterrupt::Forbidden），\
             不能调用户手动入口 —— 那条会在代理运行中停核"
    );
}

/// 🟡 **调用点守卫：暂存成功后必须记下裸核 sha256（供落位前复核）。**
///
/// **变异探针**：删掉 `staged_core_sha_path` 那段写入 ⇒ 本条转红；
/// 把它挪到 `stage(...)` 之前 ⇒ 也转红（`stage` 会 `remove_dir_all` 暂存目录，先写必被删掉）。
#[test]
fn stage_records_the_bare_core_digest_after_staging() {
    let src = src();
    let body =
        crate::commands::guard_scan::top_level_fn_body(&src, "async fn run_download_and_stage(");
    let stage_at = body.find(".stage(").expect("锚点消失：守卫已失去判据");
    let sha_at = body
        .find("staged_core_sha_path(")
        .expect("暂存核摘要没记 —— 落位时没有任何基准可对，位腐/篡改的核会被原样换入");
    assert!(
        stage_at < sha_at,
        "摘要必须写在 stage() **之后** —— stage 会先 remove_dir_all 暂存目录，写在前面必被删掉"
    );
    assert!(
        body.contains("ApplyOutcome::Applied"),
        "只有真暂存成功（Applied）才该写摘要：Discarded/Deferred 时目录里没有本次的核"
    );
}

#[test]
fn scheduler_constants_match_upstream() {
    // 上游 CoreUpdateScheduler.ts:26-29 的四个常量（本调度器直接取 ScheduleConfig::default）。
    let c = ScheduleConfig::default();
    assert_eq!(c.startup_delay, Duration::from_secs(30));
    assert_eq!(c.tick_interval, Duration::from_secs(6 * 60 * 60));
    assert_eq!(c.check_interval, Duration::from_secs(24 * 60 * 60));
    assert_eq!(c.stopped_apply_delay, Duration::from_secs(5));
    // 错峰：30s 启动延迟不得与其它任何启动腿撞点（2/3/5/6/7s + 订阅 8s + 规则资源 12s）。
    for other in [2u64, 3, 5, 6, 7, 8, 12] {
        assert_ne!(
            c.startup_delay.as_secs(),
            other,
            "内核更新启动腿与其它启动腿撞在 {other}s"
        );
    }
}

#[test]
fn busy_guard_releases_on_drop() {
    let flag = AtomicBool::new(false);
    {
        assert!(!flag.swap(true, Ordering::SeqCst));
        let _g = BusyGuard(&flag);
        assert!(flag.load(Ordering::SeqCst));
    }
    assert!(!flag.load(Ordering::SeqCst), "guard drop 必须复位 busy 闸");
}

#[test]
fn current_iso_is_parseable_rfc3339() {
    let iso = current_iso();
    assert!(!iso.is_empty(), "stagedAt 不得为空串");
    // 与订阅调度器的解析器互逆（同一 civil 算法）。
    assert!(
        crate::runtime::subscription_scheduler::rfc3339_to_epoch_ms(&iso).is_some(),
        "stagedAt 必须是可解析的 RFC3339，实得 {iso}"
    );
}
