use super::*;
use crate::test_support::crate_code;
use serde_json::json;

#[test]
fn poisoned_scheduler_lock_recovers_and_running_guard_still_resets() {
    let scheduler = RuleResourceScheduler::new();
    let poisoned = Arc::clone(&scheduler.inner);
    assert!(std::thread::spawn(move || {
        let _guard = poisoned.lock().unwrap();
        panic!("poison rule resource scheduler lock");
    })
    .join()
    .is_err());

    lock_inner(&scheduler.inner).is_running = true;
    drop(RunningGuard {
        inner: Arc::clone(&scheduler.inner),
    });
    assert!(!lock_inner(&scheduler.inner).is_running);
}

const NOW: u64 = 1_700_000_000_000; // 2023-11-14
const HOUR: u64 = 3_600_000;

/// 全部文件都在（默认注入）。
fn all_present(_: &str) -> bool {
    true
}
/// 全部文件都缺。
fn all_missing(_: &str) -> bool {
    false
}

fn iso(ms: u64) -> String {
    polaris_stats_engine::created_at_to_rfc3339(ms as i64).unwrap()
}

fn cfg_with(resources: Value) -> Value {
    json!({ "ruleResources": resources })
}

fn fresh(id: &str) -> Value {
    json!({ "id": id, "fileName": format!("{id}.srs"), "downloadedAt": iso(NOW - HOUR) })
}
fn stale(id: &str) -> Value {
    json!({ "id": id, "fileName": format!("{id}.srs"), "downloadedAt": iso(NOW - 24 * HOUR) })
}

fn tracker() -> BackoffTracker {
    BackoffTracker::new(BACKOFF_BASE_MS, BACKOFF_MAX_MS)
}

#[test]
fn master_switch_only_stops_when_explicitly_false() {
    let mut cfg = cfg_with(json!([stale("a")]));
    cfg["ruleResourceAutoUpdate"] = json!(false);
    assert!(
        select_due_resources(&cfg, NOW, &tracker(), &all_present).is_empty(),
        "显式 false → 停"
    );
    // 缺省（老配置 undefined）→ 照跑。这是与本仓 UI `!!config.ruleResourceAutoUpdate` 的已知
    // 不一致点，代码按 上游 语义（缺省=开）。
    let cfg_default = cfg_with(json!([stale("a")]));
    assert_eq!(
        select_due_resources(&cfg_default, NOW, &tracker(), &all_present),
        vec!["a".to_string()]
    );
    // 显式 true 同样跑。
    let mut cfg_on = cfg_with(json!([stale("a")]));
    cfg_on["ruleResourceAutoUpdate"] = json!(true);
    assert_eq!(
        select_due_resources(&cfg_on, NOW, &tracker(), &all_present),
        vec!["a".to_string()]
    );
}

#[test]
fn stale_and_fresh_are_split() {
    let cfg = cfg_with(json!([stale("old"), fresh("new")]));
    assert_eq!(
        select_due_resources(&cfg, NOW, &tracker(), &all_present),
        vec!["old".to_string()],
        "仅超间隔的进入本轮"
    );
}

#[test]
fn future_resource_timestamp_after_clock_rollback_is_due() {
    let cfg = cfg_with(json!([{
        "id": "future",
        "fileName": "future.srs",
        "downloadedAt": iso(NOW + HOUR)
    }]));
    assert_eq!(
        select_due_resources(&cfg, NOW, &tracker(), &all_present),
        vec!["future".to_string()]
    );
}

#[test]
fn never_downloaded_is_always_due() {
    // 无 downloadedAt / 空串 → 从未记录 → 立即到期。
    let cfg = cfg_with(json!([
        { "id": "a", "fileName": "a.srs" },
        { "id": "b", "fileName": "b.srs", "downloadedAt": "" },
    ]));
    assert_eq!(
        select_due_resources(&cfg, NOW, &tracker(), &all_present),
        vec!["a".to_string(), "b".to_string()]
    );
}

#[test]
fn missing_file_forces_update_even_when_fresh() {
    // 1h 前刚下过（远未到 12h），但磁盘文件不在 → 强制补更。
    let cfg = cfg_with(json!([fresh("a")]));
    assert!(
        select_due_resources(&cfg, NOW, &tracker(), &all_present).is_empty(),
        "文件在 + 新鲜 → 不更"
    );
    assert_eq!(
        select_due_resources(&cfg, NOW, &tracker(), &all_missing),
        vec!["a".to_string()],
        "文件缺失 → 即便新鲜也补更"
    );
}

#[test]
fn missing_filename_field_treated_as_missing_file() {
    // fileName 缺失 = 条目损坏 → 按文件缺失处理（进入本轮，由命令层如实报 BAD_ITEM）。
    let cfg = cfg_with(json!([{ "id": "a", "downloadedAt": iso(NOW - HOUR) }]));
    assert_eq!(
        select_due_resources(&cfg, NOW, &tracker(), &all_present),
        vec!["a".to_string()]
    );
}

#[test]
fn backoff_skips_then_recovers() {
    let cfg = cfg_with(json!([stale("a")]));
    let mut b = tracker();
    b.record_failure("a", NOW);
    assert!(
        select_due_resources(&cfg, NOW, &b, &all_present).is_empty(),
        "退避中跳过"
    );
    assert_eq!(
        select_due_resources(&cfg, NOW + BACKOFF_BASE_MS, &b, &all_present),
        vec!["a".to_string()],
        "退避过期 → 恢复"
    );
    // 退避对「文件缺失」同样生效：故障源不因缺文件被高频重试。
    assert!(
        select_due_resources(&cfg, NOW, &b, &all_missing).is_empty(),
        "退避中即便文件缺失也跳过"
    );
}

#[test]
fn interval_falls_back_to_default_on_illegal_values() {
    // 13h 前下过：默认 12h 下算陈旧；若非法值被当成别的数就会判错。
    let res = json!([{ "id": "a", "fileName": "a.srs", "downloadedAt": iso(NOW - 13 * HOUR) }]);
    for bad in [json!(null), json!("12"), json!(-1), json!(1.5)] {
        let mut cfg = cfg_with(res.clone());
        cfg["ruleResourceUpdateIntervalHours"] = bad.clone();
        assert_eq!(
            select_due_resources(&cfg, NOW, &tracker(), &all_present),
            vec!["a".to_string()],
            "非法值 {bad} 应回落 12h"
        );
    }
    // 合法自定义间隔被尊重：24h 间隔下 13h 前的资源不陈旧。
    let mut cfg = cfg_with(res);
    cfg["ruleResourceUpdateIntervalHours"] = json!(24);
    assert!(select_due_resources(&cfg, NOW, &tracker(), &all_present).is_empty());
}

#[test]
fn interval_zero_is_manual_only() {
    // #18 的 0 语义：本调度器只有一条腿 → 0 = 彻底不自动跑（含文件缺失的强制补更）。
    let mut cfg = cfg_with(json!([stale("a")]));
    cfg["ruleResourceUpdateIntervalHours"] = json!(0);
    assert!(select_due_resources(&cfg, NOW, &tracker(), &all_present).is_empty());
    assert!(
        select_due_resources(&cfg, NOW, &tracker(), &all_missing).is_empty(),
        "仅手动优先于文件缺失补更（用户显式要求别动网）"
    );
}

#[test]
fn missing_or_bad_resources_array_is_empty() {
    assert!(select_due_resources(&json!({}), NOW, &tracker(), &all_present).is_empty());
    assert!(select_due_resources(
        &json!({"ruleResources": "x"}),
        NOW,
        &tracker(),
        &all_present
    )
    .is_empty());
    // 无 id 的条目跳过（无退避键可记，也无法调 redownload）。
    let cfg = cfg_with(json!([{ "fileName": "a.srs" }]));
    assert!(select_due_resources(&cfg, NOW, &tracker(), &all_missing).is_empty());
}

/* ── 资源库目录（catalog）刷新腿 ─────────────────────────────────────────────────── */

/// 空配置（总开关缺省=开、间隔缺省 12h）。
fn cfg_empty() -> Value {
    json!({})
}

#[test]
fn catalog_refresh_due_when_never_fetched() {
    // 从未拉过（缓存无 fetchedAt）+ 本进程未尝试过 → 立即到期（对齐 上游的 `?? 0`）。
    assert!(catalog_refresh_due(&cfg_empty(), NOW, 0, 0));
}

#[test]
fn catalog_refresh_throttled_by_cached_fetched_at() {
    // **节流的第一条腿**：上次成功拉取在间隔内 → 跳过；跨过间隔 → 到期。
    // 删掉 `cached_fetched_at_ms` 这一项（或整个节流）→ 本用例第一条断言转红。
    assert!(
        !catalog_refresh_due(&cfg_empty(), NOW, NOW - 11 * HOUR, 0),
        "11h < 12h 间隔 → 不刷（每 30min 一 tick，不节流就是每 30min 白打一次 GitHub）"
    );
    assert!(catalog_refresh_due(&cfg_empty(), NOW, NOW - 13 * HOUR, 0));
    // 边界：恰好到点即刷（`>=`，与 上游 同）。
    assert!(catalog_refresh_due(&cfg_empty(), NOW, NOW - 12 * HOUR, 0));
}

#[test]
fn catalog_refresh_throttled_by_last_attempt_even_when_never_fetched() {
    // **节流的第二条腿**：远程一直拉不到 ⇒ 缓存 fetchedAt 恒 0，只靠它会每 tick 重拉。
    // 「上次尝试」把失败也算一次配额 → 离线/限流下不再高频重打。
    assert!(
        !catalog_refresh_due(&cfg_empty(), NOW, 0, NOW - HOUR),
        "1h 前刚尝试过（虽然失败了）→ 本轮跳过"
    );
    assert!(
        catalog_refresh_due(&cfg_empty(), NOW, 0, NOW - 13 * HOUR),
        "尝试也过期 → 重试"
    );
}

#[test]
fn catalog_refresh_takes_the_later_of_the_two_marks() {
    // 取较晚者：任一条在间隔内就该跳过（取较早者会让另一条形同虚设）。
    assert!(!catalog_refresh_due(
        &cfg_empty(),
        NOW,
        NOW - 20 * HOUR,
        NOW - HOUR
    ));
    assert!(!catalog_refresh_due(
        &cfg_empty(),
        NOW,
        NOW - HOUR,
        NOW - 20 * HOUR
    ));
}

#[test]
fn catalog_refresh_shares_the_master_switch_and_interval() {
    // 总开关显式 false → 目录也不刷（否则「我关了自动更新」是假话）。
    let mut off = cfg_empty();
    off["ruleResourceAutoUpdate"] = json!(false);
    assert!(!catalog_refresh_due(&off, NOW, 0, 0));
    // 「仅手动」(0) → 彻底不自动动网，目录同样不刷（与 select_due_resources 同一道门）。
    let mut manual = cfg_empty();
    manual["ruleResourceUpdateIntervalHours"] = json!(0);
    assert!(!catalog_refresh_due(&manual, NOW, 0, 0));
    // 自定义间隔被尊重：24h 下 13h 前拉过的不到期（12h 下则到期，见上一用例）。
    let mut long = cfg_empty();
    long["ruleResourceUpdateIntervalHours"] = json!(24);
    assert!(!catalog_refresh_due(&long, NOW, NOW - 13 * HOUR, 0));
    assert!(catalog_refresh_due(&long, NOW, NOW - 25 * HOUR, 0));
}

#[test]
fn cached_catalog_fetched_at_reads_zero_on_any_defect() {
    // 目录不存在 / 文件不是 JSON / 无 fetchedAt / fetchedAt 非正整数 → 一律 0（=立即到期）。
    // 这是「宁可多刷一次，也不因缓存损坏永久停刷」的取向。
    let dir = std::env::temp_dir().join(format!("polaris-cat-{}", now_ms()));
    assert_eq!(cached_catalog_fetched_at(&dir), 0, "目录不存在");
    std::fs::create_dir_all(&dir).unwrap();
    for (body, why) in [
        ("not json", "非 JSON"),
        ("{}", "无 fetchedAt"),
        (r#"{"fetchedAt":"x"}"#, "fetchedAt 非数"),
        (r#"{"fetchedAt":-1}"#, "fetchedAt 负数"),
    ] {
        std::fs::write(dir.join(CATALOG_CACHE_FILE), body).unwrap();
        assert_eq!(cached_catalog_fetched_at(&dir), 0, "{why}");
    }
    std::fs::write(
        dir.join(CATALOG_CACHE_FILE),
        r#"{"fetchedAt":1700000000000}"#,
    )
    .unwrap();
    assert_eq!(cached_catalog_fetched_at(&dir), 1_700_000_000_000);
    std::fs::remove_dir_all(&dir).ok();
}

/* ── 接线守卫（变异锁）：纯函数全对、但没人调它 = 用户拿不到刷新 ───────────────── */

/// 取具名函数体（从签名起到下一个同缩进的 `\n    }` 为止，够本文件用）。
fn fn_body(sig: &str) -> String {
    let src = crate_code("runtime/rule_resource_scheduler.rs");
    let start = src.find(sig).unwrap_or_else(|| panic!("找不到 {sig}"));
    let rest = &src[start..];
    let end = rest.find("\n    }").unwrap_or(rest.len());
    rest[..end].to_string()
}

#[test]
fn scheduler_actually_wires_the_catalog_refresh_leg() {
    // 变异锁：删掉这条腿（或只留纯函数不调）→ 转红。
    let body = fn_body("async fn run_due_updates(");
    assert!(
        body.contains("self.refresh_catalog_if_due("),
        "每轮更新必须带上资源库目录刷新（上游 RuleResourceScheduler.ts:110-123）"
    );
    let leg = fn_body("async fn refresh_catalog_if_due(");
    assert!(
        leg.contains("catalog_refresh_due("),
        "变异锁：删掉节流判定 = 每 30min 白打一次 GitHub 三跳"
    );
    assert!(
        leg.contains("last_catalog_refresh_attempt = now"),
        "变异锁：不记『上次尝试』则失败态每 tick 重打（fetchedAt 在未成功时恒 0）"
    );
    assert!(
        leg.contains("rule_resources_refresh_catalog("),
        "必须复用刷新命令本体，不得另拼一套下载/落缓存"
    );
}

/// 🔴 **一轮保鲜只准给核一次配置变更**（真机实证 2026-08-02）。
///
/// 逐条广播时一轮启动补更打出 33 次 `broadcast_config_changed` ⇒ 33 次 `switch_mode`
/// （日志实测 11 秒内 35 条）。核未跑时只是刷屏，**核在跑时是连砸 33 次热切/去抖重启判定**。
///
/// 守两件事，缺一即回归：
/// ① 两条后台静默腿必须传 `BroadcastMode::Deferred`（改回 `Immediate` 或删掉参数 → 转红）；
/// ② 批次收尾必须有且只有一处广播，且**门控在「本轮真有成功」上**（去掉 `ok_count`/`builtin_ok`
///    门 → 转红：一条都没更新还广播，等于凭空给核一次无谓的 `switch_mode`）。
#[test]
fn one_refresh_round_broadcasts_exactly_once() {
    let rules = crate_code("commands/rules/resources.rs");
    for silent_fn in [
        "pub async fn rule_resources_redownload_silent(",
        "pub async fn rule_resources_update_builtin_silent(",
    ] {
        let at = rules
            .find(silent_fn)
            .unwrap_or_else(|| panic!("找不到 {silent_fn}"));
        let body = &rules[at..at + 400];
        assert!(
            body.contains("BroadcastMode::Deferred"),
            "{silent_fn} 是后台批量腿，必须延后广播，否则一轮 33 次 switch_mode"
        );
    }

    let body = fn_body("async fn run_due_updates(");
    assert_eq!(
        body.matches("broadcast_config_changed(").count(),
        1,
        "整批只准广播一次（多于一次 = 风暴回归；零次 = 变更永远进不了运行中的核）"
    );
    let at = body
        .find("broadcast_config_changed(")
        .expect("上一条断言已保证存在");
    let head = &body[..at];
    assert!(
        head.contains("if ok_count > 0 || builtin_ok > 0"),
        "收尾广播必须门控在『本轮真有成功』上，否则空轮也白给核一次 switch_mode"
    );
}

#[test]
fn catalog_leg_cannot_short_circuit_the_resource_leg() {
    // 变异锁：目录刷新失败**不得**打断 `.srs` 重下载腿。守的是形态——它必须是一条独立语句
    // （结果不被消费、不被 `?` 传播），这正是 上游 那圈 try/catch 的等价物。
    let body = fn_body("async fn run_due_updates(");
    let at = body
        .find("self.refresh_catalog_if_due(")
        .expect("上一个用例已保证存在");
    let head = &body[..at];
    let line_start = head.rfind('\n').map_or(0, |p| p + 1);
    assert!(
        head[line_start..].trim().is_empty(),
        "目录刷新腿的返回值不得被消费（`let x = ...` / `if ...` 都意味着它能左右后续流程）"
    );
    let stmt_end = body[at..].find(';').expect("语句必有分号");
    assert!(
        !body[at..at + stmt_end].contains('?'),
        "目录刷新腿不得用 `?` 传播——那会让一次目录刷新失败吞掉整轮资源更新"
    );
    // 且必须排在资源选取之前（同 上游的顺序：目录先刷新，随后按新目录做资源判定）。
    let sel = body.find("select_due_resources(").expect("资源腿仍在");
    assert!(at < sel, "目录刷新应在资源选取之前");
}

/// 🟡 **调用点守卫：目录缓存的读盘 + JSON parse 必须发生在拿 `inner` 锁之前。**
///
/// 原实现把 [`cached_catalog_fetched_at`]（同步 `read` + `serde_json` parse）写在
/// `catalog_refresh_due(...)` 的实参位置上 ⇒ 整个读盘都在持锁期间、且在 async fn 里。
/// 缓存文件几百 KB 且落在用户配置目录（可能是网络盘 / 正被备份软件锁住），
/// 那段时间 `run_due_updates` 的防重入判定与退避记账全部排队等它。
///
/// **变异探针**：把 `cached_catalog_fetched_at(res_dir)` 挪回 `catalog_refresh_due` 的实参位
/// （即挪到 `lock_inner(&self.inner)` 之后）⇒ 本条转红。
#[test]
fn catalog_refresh_reads_disk_before_taking_the_lock() {
    use crate::runtime::core_update_scheduler::method_scan::method_body;
    let src = crate_code("runtime/rule_resource_scheduler.rs");
    let body = method_body(&src, "    async fn refresh_catalog_if_due(");
    let read_at = body
        .find("cached_catalog_fetched_at(res_dir)")
        .expect("锚点消失：守卫已失去判据");
    let lock_at = body
        .find("lock_inner(&self.inner)")
        .expect("锚点消失：守卫已失去判据");
    assert!(
        read_at < lock_at,
        "读盘 + JSON parse 必须在锁外完成（实得 read@{read_at} / lock@{lock_at}）—— \
             锁内只留判定与记 attempt 两步纯内存操作"
    );
    // 锁内不得再出现任何读盘。
    let in_lock = &body[lock_at..];
    assert!(
        !in_lock.contains("cached_catalog_fetched_at("),
        "持锁期间又读了一次盘"
    );
}

#[test]
fn catalog_cache_file_name_mirrors_rules_rs() {
    // 本文件只读 peek `fetchedAt`，文件名是 `commands/rules/resources.rs` 那份写入口的镜像。
    // 那边改名而这边没跟 → 节流基准恒 0 → 每轮重打远端。此断言让重命名当场转红。
    let rules = crate_code("commands/rules/resources.rs");
    assert!(
        rules.contains(&format!(
            r#"CATALOG_CACHE_FILE: &str = "{CATALOG_CACHE_FILE}""#
        )),
        "commands/rules/resources.rs 的 catalog 缓存文件名已变，本文件的只读镜像常量必须同步"
    );
}
