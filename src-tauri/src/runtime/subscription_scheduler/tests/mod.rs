use super::*;
use crate::test_support::crate_code;
use serde_json::json;

#[test]
fn poisoned_scheduler_lock_recovers_and_running_guard_still_resets() {
    let scheduler = SubscriptionScheduler::new();
    let poisoned = Arc::clone(&scheduler.inner);
    assert!(std::thread::spawn(move || {
        let _guard = poisoned.lock().unwrap();
        panic!("poison subscription scheduler lock");
    })
    .join()
    .is_err());

    lock_inner(&scheduler.inner).is_running = true;
    drop(RunningGuard {
        inner: Arc::clone(&scheduler.inner),
    });
    assert!(!lock_inner(&scheduler.inner).is_running);
}

fn base_cfg(subs: Value) -> Value {
    json!({
        "autoUpdateSubscriptionOnStart": true,
        "subscriptionUpdateIntervalHours": 12,
        "subscriptions": subs,
    })
}

// ── BackoffTracker ─────────────────────────────────────────────────────────
#[test]
fn backoff_exponential_capped_and_reset() {
    let mut b = BackoffTracker::new(BACKOFF_BASE_MS, BACKOFF_MAX_MS);
    assert!(b.is_eligible("s", 0), "无记录 → 可尝试");
    let (f1, d1) = b.record_failure("s", 1000);
    assert_eq!(f1, 1);
    assert_eq!(d1, BACKOFF_BASE_MS, "首败 = base");
    assert!(!b.is_eligible("s", 1000), "退避中不可尝试");
    assert!(
        b.is_eligible("s", 1000 + BACKOFF_BASE_MS),
        "过退避窗 → 可尝试"
    );
    let (f2, d2) = b.record_failure("s", 2000);
    assert_eq!(f2, 2);
    assert_eq!(d2, BACKOFF_BASE_MS * 2, "二败 = base*2");
    // 上限封顶。
    for _ in 0..20 {
        b.record_failure("s", 0);
    }
    let (_, d) = b.record_failure("s", 0);
    assert_eq!(d, BACKOFF_MAX_MS, "封顶 6h");
    // 成功复位。
    b.record_success("s");
    assert!(b.is_eligible("s", 0));
}

#[test]
fn backoff_prune_removes_inactive() {
    let mut b = BackoffTracker::new(BACKOFF_BASE_MS, BACKOFF_MAX_MS);
    b.record_failure("keep", 0);
    b.record_failure("drop", 0);
    b.prune(&std::collections::HashSet::from(["keep".to_string()]));
    assert!(!b.is_eligible("keep", 0), "keep 保留退避");
    assert!(b.is_eligible("drop", 0), "drop 被剪 → 无记录");
}

#[test]
fn backoff_and_persisted_staleness_fail_open_on_clock_rollback() {
    let mut b = BackoffTracker::new(BACKOFF_BASE_MS, BACKOFF_MAX_MS);
    b.record_failure("s", 10_000);
    assert!(
        b.is_eligible("s", 9_000),
        "墙钟回拨到失败记录之前时不能冻结进程内退避"
    );
    assert!(elapsed_or_clock_rollback(9_000, 10_000, 60_000));
    assert!(!elapsed_or_clock_rollback(10_500, 10_000, 60_000));
}

// ── autoupdate 事件 payload ───────────────────────────────────────────────
#[test]
fn autoupdate_payload_failure_carries_real_error() {
    // 失败结果（perform_subscription_update 的 update_failure 形态）→ success:false + 透传 error。
    let result = json!({
        "success": false,
        "addedServers": 0,
        "updatedServers": 0,
        "deletedServers": 0,
        "error": "DNS 解析失败",
    });
    let p = build_autoupdate_payload("sub-1", "机场A", &result);
    assert_eq!(p["subscriptionId"], json!("sub-1"));
    assert_eq!(p["name"], json!("机场A"));
    assert_eq!(p["success"], json!(false));
    assert_eq!(
        p["error"],
        json!("DNS 解析失败"),
        "失败态须透传后端真实 error，不用笼统兜底"
    );
    assert!(p.get("addedServers").is_none(), "失败态不带计数字段");
}

#[test]
fn autoupdate_payload_failure_keeps_structured_error_metadata() {
    let result = json!({
        "success": false,
        "error": "sanitized transport diagnostic",
        "errorKind": "http",
        "httpStatus": 429,
    });
    let p = build_autoupdate_payload("sub-1", "provider", &result);
    assert_eq!(p["errorKind"], "http");
    assert_eq!(p["httpStatus"], 429);
    assert_eq!(p["error"], "sanitized transport diagnostic");
}

#[test]
fn autoupdate_payload_success_carries_counts() {
    let result = json!({
        "success": true,
        "addedServers": 3,
        "updatedServers": 1,
        "deletedServers": 2,
        "unchanged": false,
    });
    let p = build_autoupdate_payload("sub-2", "机场B", &result);
    assert_eq!(p["success"], json!(true));
    assert_eq!(p["addedServers"], json!(3));
    assert_eq!(p["updatedServers"], json!(1));
    assert_eq!(p["deletedServers"], json!(2));
    assert_eq!(p["unchanged"], json!(false));
    assert!(p.get("error").is_none(), "成功态无 error 字段");
}

#[test]
fn autoupdate_payload_failure_falls_back_when_error_missing() {
    // error 字段缺失（异常返回）→ 兜底文案，绝不 panic / 绝不留空。
    let p = build_autoupdate_payload("x", "", &json!({ "success": false }));
    assert_eq!(p["error"], json!("订阅更新失败"));
}

#[test]
fn sub_name_lookup_by_id() {
    let cfg = json!({ "subscriptions": [
        { "id": "a", "name": "Alpha" },
        { "id": "b", "name": "Beta" },
    ]});
    assert_eq!(sub_name(&cfg, "b"), "Beta");
    assert_eq!(sub_name(&cfg, "missing"), "", "缺失订阅 → 空串（不 panic）");
}

// ── rfc3339 解析 ──────────────────────────────────────────────────────────
#[test]
fn rfc3339_parse_roundtrip_with_stats_engine() {
    // 与 stats-engine created_at_to_rfc3339 互逆（同 civil 算法）。
    let ms: u64 = 1_700_000_000_123;
    let iso = polaris_stats_engine::created_at_to_rfc3339(ms as i64).unwrap();
    assert_eq!(rfc3339_to_epoch_ms(&iso), Some(ms), "iso={iso}");
    // epoch 起点。
    assert_eq!(rfc3339_to_epoch_ms("1970-01-01T00:00:00.000Z"), Some(0));
    // 无毫秒段容忍。
    assert_eq!(rfc3339_to_epoch_ms("1970-01-01T00:00:01Z"), Some(1000));
    // 坏输入 → None。
    assert_eq!(rfc3339_to_epoch_ms("not-a-date"), None);
    assert_eq!(rfc3339_to_epoch_ms(""), None);
}

// ── select_due 决策 ───────────────────────────────────────────────────────
#[test]
fn select_due_respects_master_switch() {
    let mut cfg = base_cfg(json!([{"id":"a","autoUpdate":true}]));
    cfg["autoUpdateSubscriptionOnStart"] = json!(false);
    let b = BackoffTracker::new(BACKOFF_BASE_MS, BACKOFF_MAX_MS);
    // 打断总开关 → 空（无论陈旧）。
    assert!(
        select_due(&cfg, 0, &b, true, true).due_ids.is_empty(),
        "总开关关 → 不更"
    );
}

// 现实 epoch-ms 基准（>1e11，避开 created_at_to_rfc3339 对小值按「秒」的量级分档）。
const NOW: u64 = 1_700_000_000_000; // 2023-11-14

#[test]
fn select_due_stale_and_autoupdate_gate() {
    let cfg = base_cfg(json!([
        {"id":"stale","autoUpdate":true,"lastUpdated":"1970-01-01T00:00:00.000Z"}, // 远超 12h → 陈旧
        {"id":"fresh","autoUpdate":true,"lastUpdated": polaris_stats_engine::created_at_to_rfc3339((NOW - 3_600_000) as i64)}, // 1h 前 → 不陈旧
        {"id":"off","autoUpdate":false,"lastUpdated":"1970-01-01T00:00:00.000Z"} // autoUpdate 关
    ]));
    let b = BackoffTracker::new(BACKOFF_BASE_MS, BACKOFF_MAX_MS);
    let sel = select_due(&cfg, NOW, &b, true, false);
    assert_eq!(
        sel.due_ids,
        vec!["stale".to_string()],
        "仅陈旧且 autoUpdate 开"
    );
}

#[test]
fn select_due_treats_future_timestamp_as_clock_rollback() {
    let future = polaris_stats_engine::created_at_to_rfc3339((NOW + 3_600_000) as i64);
    let cfg = base_cfg(json!([{"id":"a","autoUpdate":true,"lastUpdated":future}]));
    let b = BackoffTracker::new(BACKOFF_BASE_MS, BACKOFF_MAX_MS);
    assert_eq!(select_due(&cfg, NOW, &b, true, false).due_ids, vec!["a"]);
}

#[test]
fn select_due_ignore_staleness_uses_min_gap() {
    // 距上次 5min（< 12h interval 但也 < 10min 地板）→ ignore_staleness 下仍不更。
    let recent = polaris_stats_engine::created_at_to_rfc3339((NOW - 5 * 60_000) as i64);
    let cfg = base_cfg(json!([{"id":"a","autoUpdate":true,"lastUpdated": recent}]));
    let b = BackoffTracker::new(BACKOFF_BASE_MS, BACKOFF_MAX_MS);
    assert!(
        select_due(&cfg, NOW, &b, true, true).due_ids.is_empty(),
        "5min < 10min 地板 → 不更"
    );
    // 距上次 15min（> 10min 地板）→ ignore_staleness 下更。
    let older = polaris_stats_engine::created_at_to_rfc3339((NOW - 15 * 60_000) as i64);
    let cfg2 = base_cfg(json!([{"id":"a","autoUpdate":true,"lastUpdated": older}]));
    assert_eq!(
        select_due(&cfg2, NOW, &b, true, true).due_ids,
        vec!["a".to_string()]
    );
}

#[test]
fn select_due_backoff_skips() {
    let cfg =
        base_cfg(json!([{"id":"a","autoUpdate":true,"lastUpdated":"1970-01-01T00:00:00.000Z"}]));
    let mut b = BackoffTracker::new(BACKOFF_BASE_MS, BACKOFF_MAX_MS);
    b.record_failure("a", 1000); // 退避到 1000+base
    assert!(
        select_due(&cfg, 1000, &b, true, false).due_ids.is_empty(),
        "退避中跳过"
    );
    assert_eq!(
        select_due(&cfg, 1000 + BACKOFF_BASE_MS, &b, true, false).due_ids,
        vec!["a".to_string()],
        "退避过 → 更"
    );
}

#[test]
fn select_due_interval_zero_is_manual_only_for_periodic_tick() {
    // #18：UI「仅手动」= interval 0。周期巡检腿一律不选；启动补更腿不受影响（独立开关）。
    let mut cfg = base_cfg(json!([
        {"id":"a","autoUpdate":true,"lastUpdated":"1970-01-01T00:00:00.000Z"}
    ]));
    cfg["subscriptionUpdateIntervalHours"] = json!(0);
    let b = BackoffTracker::new(BACKOFF_BASE_MS, BACKOFF_MAX_MS);
    assert!(
        select_due(&cfg, NOW, &b, true, false).due_ids.is_empty(),
        "interval=0 → 周期巡检不选任何订阅（旧实现会当成 12h 照更）"
    );
    assert_eq!(
        select_due(&cfg, NOW, &b, true, true).due_ids,
        vec!["a".to_string()],
        "interval=0 不影响启动补更腿（仍守 10min 地板）"
    );
}

#[test]
fn select_due_missing_or_bad_interval_still_falls_back_to_default() {
    // 缺字段 / 非数 → 仍回落 12h（存量行为不变，只有显式 0 才是「仅手动」）。
    let mut cfg = base_cfg(json!([
        {"id":"a","autoUpdate":true,"lastUpdated":"1970-01-01T00:00:00.000Z"}
    ]));
    cfg.as_object_mut()
        .unwrap()
        .remove("subscriptionUpdateIntervalHours");
    let b = BackoffTracker::new(BACKOFF_BASE_MS, BACKOFF_MAX_MS);
    assert_eq!(
        select_due(&cfg, NOW, &b, true, false).due_ids,
        vec!["a".to_string()]
    );
    cfg["subscriptionUpdateIntervalHours"] = json!("12");
    assert_eq!(
        select_due(&cfg, NOW, &b, true, false).due_ids,
        vec!["a".to_string()]
    );
}

#[test]
fn select_due_via_proxy_pending_when_proxy_down() {
    // 全局 proxy 策略 + 代理未起 → 跳过 + pending；直连订阅照常。
    let mut cfg = base_cfg(json!([
        {"id":"proxied","autoUpdate":true,"lastUpdated":"1970-01-01T00:00:00.000Z"},
        {"id":"direct","autoUpdate":true,"updateViaProxy":false,"lastUpdated":"1970-01-01T00:00:00.000Z"}
    ]));
    cfg["subscriptionProxyPolicy"] = json!("proxy"); // 全强制经代理
    let b = BackoffTracker::new(BACKOFF_BASE_MS, BACKOFF_MAX_MS);
    let sel = select_due(&cfg, 100 * 3_600_000, &b, false, false); // 代理未起
    assert!(sel.pending_proxy_catchup, "经代理订阅被跳过 → 挂起");
    assert!(
        sel.due_ids.is_empty(),
        "proxy 策略下两订阅都经代理 → 全跳过"
    );
    // 代理起了 → 两个都更。
    let sel2 = select_due(&cfg, 100 * 3_600_000, &b, true, false);
    assert_eq!(sel2.due_ids.len(), 2);
    assert!(!sel2.pending_proxy_catchup);
}

/// 启动补更/周期补更/代理就绪补更最终都汇流 `run_due_updates`；稳定门必须在读配置与真 HTTP 更新
/// 之前。结构门防后续“只给启动 timer 加 sleep”而让另外两条触发腿重新绕过。
///
/// # 取材面是 [`crate_code`]（剥注释面），封顶用共用的 `impl_method_body`
///
/// 三条锚点全是**正面** `find()`，在未剥注释的面上一句行尾注释就能替生产调用点作证
/// （把 `wait_for_network_settled().await` 删掉、行尾留一句提它的注释 ⇒ 顺序断言照绿）。
/// 旧写法的**终点锚**还是下一项的文档注释 `/// 清 is_running` —— 那句话被改一个字，门要么 panic
/// 要么切成超宽片（射程由书写顺序决定）。改用按 `"\n    }\n"` 封顶的共用取材器后两处都消失。
#[test]
fn every_autoupdate_trigger_waits_for_proxy_network_settle_before_http() {
    let body = crate::commands::guard_scan::impl_method_body(
        &crate_code("runtime/subscription_scheduler.rs"),
        "    async fn run_due_updates(self: &Arc<Self>, app: &AppHandle, ignore_staleness: bool) {",
    );
    let body = body.as_str();
    let wait = body
        .find("wait_for_network_settled().await")
        .expect("自动更新汇流点必须等待代理网络稳定");
    let load = body
        .find("state.config().load_full()")
        .expect("配置读取锚必须存在");
    let request = body
        .find("let result = perform_subscription_update")
        .expect("订阅 HTTP 更新锚必须存在");
    assert!(
        wait < load && load < request,
        "稳定门必须先于选订阅与真 HTTP 请求"
    );
}
