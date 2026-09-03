use super::*;

/// 🔴 出口 IP 自动重探的排程腿不得用 `tokio::spawn` —— 2026-07-21 真机 `SIGABRT` 的同款守卫。
///
/// # 为什么必须是源码扫描，而不是行为测试
///
/// [`schedule_ipinfo_refresh_inner`] 的调用链可自**同步 command / 主线程**路径进入（`ProxyErrorEmitter` 的
/// 实现被同步 command 间接触达），而 `tokio::spawn` 要求调用处已在 Tokio runtime 上下文内，否则 panic
/// ⇒ Tauri IPC 回调里无处可 catch ⇒ `abort()` ⇒ 整个应用崩溃。
///
/// **单测结构性抓不到**：`#[tokio::test]` 自带 runtime 上下文，两种 spawn 在测试里行为完全一致、都能过
/// （`runtime::unlock` 那次 14/14 变异全杀 + 5 门全绿照样放进了生产）。唯一能在本层锁住的判据就是
/// 「源码里不许出现那个 API」。
///
/// # ⚠️ 本守卫的逃逸面（已知取舍，别高估它的射程 —— 也别低估）
///
/// 射程**只有 [`schedule_ipinfo_refresh_inner`] 这一个函数体**（`top_level_fn_body` 按列 0 的右花括号封顶），
/// 本文件之外的任何 `tokio::spawn` 一概看不见。
///
/// 但**「整个 `spawn` 挪进 helper fn」并不是逃逸**：正向断言（1564 行的
/// `assert!(body.contains("tauri::async_runtime::spawn"))`）会因为函数体里再也找不到合规 spawn 而**转红**。
/// 2026-07-21 第三轮复审前，这里写的正是「挪进 helper 则守卫不转红」—— 那句话是从**负向**守卫的逃逸面
/// 抄过来的，与本守卫的实际行为相反。
///
/// **真正够得着的逃逸只有一种**：函数体内**保留**这句合规的 `tauri::async_runtime::spawn`（正向断言过），
/// 另外再调一个内部含裸 `tokio::spawn` 的 helper fn（负向断言扫不到 helper 的体）—— 崩溃条件一字未变。
///
/// 接受这个取舍是因为：真正的判据（「调用链有没有 runtime 上下文」）跨函数、跨文件、跨线程，静态扫描
/// 本就够不着；本守卫只承诺钉住**历史上真的出过事的那一处**。要扩射程得换成全仓 lint，不在本批范围。
mod ipinfo_spawn_guard;

/// 🟠 **两条探测腿必须共用同一条世代线**——手点「网络检测」（[`ipinfo_get`]）与事件驱动排程
/// （[`schedule_ipinfo_refresh_inner`]）都必须经 [`next_ipinfo_epoch`] 领世代、并把它交给
/// [`probe_publish_ipinfo`]。
///
/// # 为什么是源码扫描，而不是行为测试
///
/// [`ipinfo_get`] 是 `#[tauri::command]`，要 `AppHandle` + `State<AppRuntime>` 才能调，单测里造不出来。
/// 而「它有没有领世代」是个纯结构事实：领了就参与「后来者胜」；没领（旧实现）则两条线互不作废——用户
/// 在起核 4s 收敛窗口内点一下检测，两条探测并行打网，谁先落地纯看网络抖动，**后落地的可能反而是先发起
/// 的那条**，状态栏于是显示已经切走的出口。
///
/// 落地顺序本身的行为验证在 `tests::stale_probe_leg_must_not_overwrite_newer_leg`（直接驱动世代闸）；
/// 本守卫只负责钉住「两条腿都接在那条线上」这个接线事实。
///
/// # ⚠️ 逃逸面
///
/// 射程限于被锚定的那几个函数体（`top_level_fn_body` 按列 0 的右花括号封顶）。
///
/// 本模块的断言全是**正向**的（`assert!(body.contains(…))` / `find().expect()`）⇒ **fail-closed**：
/// 把领世代的动作挪进 helper fn，函数体里就找不到 `next_ipinfo_epoch()` 了，守卫**转红**。
/// 2026-07-21 第三轮复审前这里写的是「挪进 helper 则守卫不转红」—— 那是从负向守卫抄来的措辞，
/// 与本模块的实际行为相反；**在这个仓里逃逸面自述是复审者据以判断覆盖的依据，写反会让后人误判射程**。
///
/// **真正够得着的逃逸**：在函数体内用**等价写法**冒充，让正向 `contains` 落空而语义不变 —— 例如把
/// `next_ipinfo_epoch()` 内联成 `IPINFO_REFRESH_EPOCH.fetch_add(1, Ordering::SeqCst) + 1`，或把
/// `probe_publish_ipinfo(` 换成别名调用。这类逃逸静态扫描本就够不着，只能靠落地语义的行为测试
/// （`tests::stale_probe_leg_must_not_overwrite_newer_leg`）兜底。
mod ipinfo_epoch_guard;

/// 带 direct + proxy + error 的既有缓存帧（折叠的取材面）。
fn cached_frame_with_error() -> Value {
    json!({
        "direct": { "ip": "9.9.9.9", "countryCode": "CN" },
        "proxy": { "ip": "1.1.1.1", "countryCode": "HK" },
        "updatedAt": 1,
        "error": "上一轮探测超时",
    })
}

/// **代理出口清空、直连出口保留**（上游 `{...this.snapshot, proxy:null}` 的 spread 语义）。
///
/// **变异锁**：把折叠改成「整帧重建」（`empty_ipinfo_snapshot()` 起手，丢掉 `cached`）→ direct
/// 断言转红。那等于代理出口无效时把状态栏那格已探到的**本机**出口一并抹成 `—`，用户读到的是
/// 「网络全挂」而不是「代理出口无效」——两者的下一步动作完全不同。
#[test]
fn fold_proxy_blocked_clears_proxy_but_keeps_direct() {
    let out = fold_proxy_blocked(Some(cached_frame_with_error()), "ts-exit-device-offline");
    assert!(out["proxy"].is_null(), "已知无效的代理出口必须清空");
    assert_eq!(
        out["direct"]["ip"],
        json!("9.9.9.9"),
        "直连出口与代理出口无效互不相干，不得被一并抹掉"
    );
}

/// **`proxyBlocked` 置原因 + `loading:false`**（终态，不是「还在探」）。
///
/// **变异锁**：漏 `loading:false` → 缓存里留着上一帧的 `loading:true` ⇒ peek 型消费方永远读到
/// 「检测中」，而实际上根本没有任何探测在飞、也永远不会有。
#[test]
fn fold_proxy_blocked_marks_terminal_state_with_reason() {
    let out = fold_proxy_blocked(Some(json!({ "loading": true })), "ts-no-exit-device");
    assert_eq!(out["proxyBlocked"], json!("ts-no-exit-device"));
    assert_eq!(out["loading"], json!(false), "直判终态不得留在「检测中」");
    assert_eq!(out["proxyReachability"], json!("blocked"));
}

/// **`error` 必须删键，不是置 null**：`blocked`（已知无效、压根没探）与 `error`（探了但失败）是
/// 互斥语义，同帧并存会让 UI 同时收到两个终态。
///
/// **变异锁**：把 `obj.remove("error")` 改成 `insert("error", Null)` → `get("error")` 变
/// `Some(Null)` ⇒ `is_none()` 转红（前端 `error !== undefined` 的判据会被 null 骗过）。
#[test]
fn fold_proxy_blocked_drops_stale_error_key() {
    let out = fold_proxy_blocked(Some(cached_frame_with_error()), "ts-exit-not-advertised");
    assert!(
        out.get("error").is_none(),
        "blocked 与 error 互斥：上一轮的 error 必须删键而非置 null"
    );
}

/// **从未探过（缓存空）也要落成完整终态帧**，而不是 panic / 回半截帧。
///
/// 真实可达：冷启动后用户还没点过「网络检测」，选中的 TS 出口即被直判无效。
#[test]
fn fold_proxy_blocked_handles_empty_cache() {
    let out = fold_proxy_blocked(None, "ts-no-exit-device");
    assert!(out["direct"].is_null() && out["proxy"].is_null());
    assert_eq!(out["proxyBlocked"], json!("ts-no-exit-device"));
    assert_eq!(out["loading"], json!(false));
    assert!(out["updatedAt"].as_u64().is_some(), "updatedAt 须为数字");
}

/// 缓存被写坏成非 object（防御面）→ 从空快照重建，绝不 panic、也绝不把坏值当基底往下发。
#[test]
fn fold_proxy_blocked_recovers_from_non_object_cache() {
    let out = fold_proxy_blocked(Some(json!("garbage")), "ts-no-exit-device");
    assert_eq!(out["proxyBlocked"], json!("ts-no-exit-device"));
    assert!(out["direct"].is_null());
}

/// `updatedAt` 必须**刷新**（不能沿用缓存里的旧值）——前端/托盘按它判新旧帧，不刷新 ⇒ 终态帧
/// 会被当成陈旧帧丢弃。**变异锁**：删掉 `updatedAt` 的 insert → 沿用 `1` → 转红。
#[test]
fn fold_proxy_blocked_refreshes_updated_at() {
    let out = fold_proxy_blocked(Some(cached_frame_with_error()), "ts-no-exit-device");
    assert!(
        out["updatedAt"].as_u64().is_some_and(|t| t > 1),
        "updatedAt 必须刷成当前时刻，不得沿用缓存里的旧值"
    );
}

/// **「检测中」占位快照的形状**：延迟腿睡之前发的这一帧，必须把 direct/proxy **双双置 null**。
///
/// 只发 `loading:true` 而留着旧 direct/proxy 是最坏解：状态栏会在起核/热切后的 4s 收敛窗口里
/// 继续显示**上一个出口**的 IP 与旗面，等于用旧出口冒充新出口（与「不得用入口域名派生出口位置」
/// 是同一条纪律）。
///
/// **变异锁**：任一字段改回沿用旧值 / 漏掉 `loading` → 转红。
#[test]
fn pending_snapshot_blanks_both_exits() {
    let snap = pending_ipinfo_snapshot();
    assert!(snap["direct"].is_null(), "收敛窗口内不得留着上一个直连出口");
    assert!(
        snap["proxy"].is_null(),
        "收敛窗口内不得留着上一个代理出口——那正是「旧出口冒充新出口」"
    );
    assert_eq!(
        snap["loading"],
        json!(true),
        "须显式标注「检测中」，与「探完了但没探到」区分开"
    );
    assert_eq!(snap["proxyReachability"], json!("checking"));
    assert!(
        snap["updatedAt"].as_u64().is_some(),
        "updatedAt 须为数字（前端/托盘按它判新旧帧）"
    );
}

#[test]
fn proxy_reachability_reports_only_observed_probe_state() {
    let stopped = ProxyStatus::default();
    assert_eq!(proxy_reachability(&stopped, &Value::Null), "unknown");

    let running = ProxyStatus {
        running: true,
        mixed_port: 7890,
        ..Default::default()
    };
    assert_eq!(proxy_reachability(&running, &Value::Null), "unreachable");
    assert_eq!(
        proxy_reachability(&running, &json!({ "ip": "1.1.1.1" })),
        "reachable"
    );
}

#[test]
fn ipinfo_retry_requires_a_real_selected_node() {
    let config = |selected: Option<&str>| {
        json!({
            "selectedServerId": selected,
            "servers": [{ "id": "node-1" }]
        })
    };
    assert!(ipinfo_config_has_real_exit(&config(Some("node-1"))));
    assert!(!ipinfo_config_has_real_exit(&config(None)));
    assert!(!ipinfo_config_has_real_exit(&config(Some(
        DIRECT_SERVER_ID
    ))));
    assert!(!ipinfo_config_has_real_exit(&config(Some(BLOCK_SERVER_ID))));
    assert!(!ipinfo_config_has_real_exit(&config(Some("missing-node"))));
}

#[test]
fn exit_recovery_unlock_gate_requires_a_reachable_current_exit() {
    let unreachable = json!({
        "proxy": Value::Null,
        "proxyReachability": "unreachable"
    });
    let reachable = json!({
        "proxy": { "ip": "1.1.1.1" },
        "proxyReachability": "reachable"
    });
    assert!(should_recheck_unlock_after_exit_recovery(
        Some(&unreachable),
        &reachable,
        false,
    ));
    assert!(!should_recheck_unlock_after_exit_recovery(
        Some(&reachable),
        &json!({ "proxy": Value::Null, "proxyReachability": "unreachable" }),
        true,
    ));
}

#[test]
fn exit_recovery_unlock_gate_detects_exit_change_or_degraded_unlock() {
    let before = json!({
        "proxy": { "ip": "1.1.1.1" },
        "proxyReachability": "reachable"
    });
    let same = json!({
        "proxy": { "ip": "1.1.1.1" },
        "proxyReachability": "reachable"
    });
    let changed = json!({
        "proxy": { "ip": "8.8.8.8" },
        "proxyReachability": "reachable"
    });
    assert!(!should_recheck_unlock_after_exit_recovery(
        Some(&before),
        &same,
        false,
    ));
    assert!(should_recheck_unlock_after_exit_recovery(
        Some(&before),
        &changed,
        false,
    ));
    assert!(should_recheck_unlock_after_exit_recovery(
        Some(&before),
        &same,
        true,
    ));
}

#[test]
fn unreachable_retry_backoff_caps_without_overflow() {
    assert_eq!(
        next_unreachable_retry_delay_ms(IPINFO_UNREACHABLE_RETRY_INITIAL_MS),
        30_000
    );
    assert_eq!(next_unreachable_retry_delay_ms(30_000), 60_000);
    assert_eq!(next_unreachable_retry_delay_ms(60_000), 60_000);
    assert_eq!(next_unreachable_retry_delay_ms(u64::MAX), 60_000);
}

#[test]
fn unreachable_retry_claim_is_atomic_and_rejects_stale_legs() {
    let seq = AtomicU64::new(7);
    assert_eq!(claim_schedule_seq(&seq, 7), Some(8));
    assert_eq!(seq.load(Ordering::SeqCst), 8);
    assert_eq!(claim_schedule_seq(&seq, 7), None);
    assert_eq!(seq.load(Ordering::SeqCst), 8);
}

// ── 探测重试（1:1 移植 上游 `IpInfoService.withRetry`）──
//
// 时间用 `start_paused = true`：`sleep` / `timeout` 由 tokio 自动推进虚拟时钟 ⇒ 断言的是**真实
// 的间隔与预算算术**，且零墙钟耗时、不碰宿主网络。

/// 调用计数器（每个测试各持一份，互不干扰）。
type Calls = std::rc::Rc<std::cell::Cell<usize>>;

/// 造一个「前 `fail_times` 次失败、之后成功」的尝试动作，调用次数记进 `calls`。
fn flaky_attempt(
    calls: Calls,
    fail_times: usize,
) -> impl FnMut() -> std::future::Ready<Result<Value, String>> {
    move || {
        let n = calls.get();
        calls.set(n + 1);
        std::future::ready(if n < fail_times {
            Err(format!("第 {} 次失败", n + 1))
        } else {
            Ok(json!({ "ip": "203.0.113.1" }))
        })
    }
}

/// **成功即止**：第一次就成功时不得再试第二次（重试是补救，不是加压）。
#[tokio::test(start_paused = true)]
async fn retry_stops_at_first_success() {
    let calls: Calls = Default::default();
    let out = with_ipinfo_retry(
        flaky_attempt(calls.clone(), 0),
        IPINFO_DIRECT_ATTEMPTS,
        IPINFO_DIRECT_RETRY_MS,
    )
    .await;
    assert!(out.is_ok(), "首次成功却回了失败");
    assert_eq!(
        calls.get(),
        1,
        "首次成功后仍继续重试 ⇒ 每次探测都在给出口 IP 端点做无谓加压"
    );
}

/// **失败会重试**（本轮要根治的症状）：一次失败不再是终局。
///
/// 变异锁：把重试删成单次（`attempts` 恒 1 / 循环体 `break`）→ 转红。
#[tokio::test(start_paused = true)]
async fn retry_recovers_from_transient_failure() {
    let calls: Calls = Default::default();
    let out = with_ipinfo_retry(
        flaky_attempt(calls.clone(), 2),
        IPINFO_DIRECT_ATTEMPTS,
        IPINFO_DIRECT_RETRY_MS,
    )
    .await;
    assert!(
        out.is_ok(),
        "3 次预算内第 3 次成功，却回了失败 ⇒ 起核瞬间的一次抖动就把状态栏 IP/旗面/延迟三格一起打空，\
             即使按需自愈稍后兜底，用户也会先经历一轮无意义的失败态"
    );
    assert_eq!(calls.get(), 3, "定额 3 次应恰好用满到成功那次");
}

/// **额度用尽回最后一次的错**：诊断要看终态，不是首次抖动。
#[tokio::test(start_paused = true)]
async fn retry_exhausts_budget_and_reports_last_error() {
    let calls: Calls = Default::default();
    let out = with_ipinfo_retry(
        flaky_attempt(calls.clone(), usize::MAX),
        IPINFO_PROXY_ATTEMPTS,
        IPINFO_PROXY_RETRY_MS,
    )
    .await;
    assert_eq!(
        out.unwrap_err(),
        "第 2 次失败",
        "应冒泡**最后**一次的错误（回首次错会把「一直没好」误报成「一开始没好」）"
    );
    assert_eq!(
        calls.get(),
        IPINFO_PROXY_ATTEMPTS as usize,
        "常规 proxy 腿定额 2 次"
    );
}

/// **总预算封顶**：间隔 × 次数超出 [`IPINFO_PROBE_BUDGET_MS`] 时，到点即止，不跑满次数。
///
/// 这是 post-connect 腿（4×4s = 12s > 10s 预算）的真实形态 —— 上游 同款截断
/// （`IpInfoService.ts:257-290` 的 deadline 检查 + 赛跑 `setTimeout`）。
///
/// 变异锁：去掉 `tokio::time::timeout` 封顶 → 调用次数变 4、转红。
#[tokio::test(start_paused = true)]
async fn retry_is_capped_by_the_total_budget() {
    let calls: Calls = Default::default();
    let started = tokio::time::Instant::now();
    let out = with_ipinfo_retry(
        flaky_attempt(calls.clone(), usize::MAX),
        IPINFO_PROXY_POST_CONNECT_ATTEMPTS,
        IPINFO_PROXY_POST_CONNECT_RETRY_MS,
    )
    .await;
    let elapsed = started.elapsed();
    assert!(out.is_err(), "全程失败却回了成功");
    assert!(
        elapsed <= Duration::from_millis(IPINFO_PROBE_BUDGET_MS),
        "跑过了总预算（{elapsed:?}）⇒ 在飞窗口无界拉长，peek 型消费方（托盘/水合腿）跟着空更久"
    );
    assert!(
        calls.get() < IPINFO_PROXY_POST_CONNECT_ATTEMPTS as usize,
        "4×4s = 12s 超出 10s 预算，必须被截断在第 4 次之前（实际 {} 次）",
        calls.get()
    );
}

/// 读当前缓存快照（`commit_ipinfo_snapshot` 的落地结果）。
fn cached_snapshot() -> Value {
    ipinfo_cache()
        .lock()
        .unwrap()
        .clone()
        .expect("前置：本测试已至少落地过一次快照")
}

/// 造一份带代理出口的快照（`cc` = 代理出口地区码）。
fn snap_with_proxy(ip: &str, cc: &str) -> Value {
    json!({
        "direct": { "ip": "9.9.9.9", "countryCode": "CN" },
        "proxy": { "ip": ip, "countryCode": cc },
        "updatedAt": 1,
    })
}

/// 造一份**没有**代理出口的快照（核未起 / 已停 ⇒ proxy=null）。
fn snap_direct_only() -> Value {
    json!({
        "direct": { "ip": "9.9.9.9", "countryCode": "CN" },
        "proxy": Value::Null,
        "updatedAt": 1,
    })
}

/// 一条腿**开探那一刻**取的完整判据（世代 + 排程线快照）—— 与生产代码里 `let epoch = …;
/// let seq = …;` 那两行同刻同序。测试里所有「开探」都必须走它，否则模型与实现就漂了。
/// 排程（[`next_ipinfo_schedule_seq`]）则由各段按事件时刻**单独**调，那才是本轮修的那一维。
fn probe_start() -> (u64, u64) {
    (next_ipinfo_epoch(), current_ipinfo_schedule_seq())
}

/// 🔴 **回归**：被更新的腿超越的旧腿，绝不许落地（不写缓存、不广播、不伴测）。
///
/// # 缺陷长相
///
/// 世代闸原先**只在探测「之前」查一次**，而 [`build_ipinfo_snapshot`] 最长跑
/// `IPINFO_PROBE_BUDGET_MS × 2 = 20s`（direct + proxy 两腿串行，各含定额重试），排程间隔却只有 4s ——
/// **探测窗口远大于排程间隔**，先发起的慢腿完全可能在后发起的快腿之后落地，同时污染
/// `IPINFO_CACHE` 与广播。且 `delay_ms == 0` 的停核腿连那一次都不查。
///
/// # 时刻口径：两条时间线，各段按**真实事件顺序**逐个调
///
/// - [`next_ipinfo_schedule_seq`] = 一次**排程 / 事件**（起核就绪、停核、热切、启动腿、手点）；
/// - [`probe_start`] = 一次**开探**（睡满之后领世代 + 快照排程线，与读 status/config 同刻）。
///
/// 故段内的调用先后 == 真机上的事件/开探先后。段 (a)/(b)/(c)/(d) 的开探先后是
/// startup t=3s < ready t≈6.5s、stop t=0 < restart t≈5.5s、B t=4s < C t=5s、手点 t≈2 < 收敛 t=4，
/// 四条的排程都落在两腿开探之前 ⇒ 排程线同值、**由世代定序**，四段原样成立。
/// 段 (f) 是唯一「排程夹在两次开探之间」的形态 —— 世代闸对它天生失明，只有排程线认得出。
///
/// # 为什么各段挤在同一个 `#[test]` 里
///
/// 各段共用 `IPINFO_REFRESH_EPOCH` / `IPINFO_CACHE` / `IPINFO_INFLIGHT` 三个**进程级 static**；
/// 拆成多个测试会被 cargo 的并行 runner 交错执行而互相污染（一段领的世代把另一段的腿作废掉、
/// 一段置的在飞标记让另一段的 peek 吐置空帧），从而变成随机假红。
///
/// ⚠️ 本测试是全仓**唯一**碰这三个 static 的测试，这一点必须保持：将来再加动世代 / 动缓存 /
/// 动在飞标记的测试，要么并进本函数，要么给它们配一把测试锁 —— 另起一个 `#[test]` 会让两边都变
/// 成随机红。
///
/// **变异锁**：删掉 [`commit_ipinfo_snapshot`] 里的世代比对 → 段 (a)–(d) 转红；删掉排程线比对
/// → 段 (f) 转红（段 (a)–(d) **全绿**，这正是第三轮复审逮到的那一半）。
#[test]
fn stale_probe_leg_must_not_overwrite_newer_leg() {
    // ── 前提：世代**严格单调递增且互不相等** ──
    // 若两条腿能领到同一个号，「后来者胜」就退化成「两条都算最新」，下面整道闸形同虚设。
    // **变异锁**：把 `next_ipinfo_epoch` 的 `fetch_add(1, …) + 1` 改成 `load(…) + 1` → 此处转红。
    let (e1, e2, e3) = (
        next_ipinfo_epoch(),
        next_ipinfo_epoch(),
        next_ipinfo_epoch(),
    );
    assert!(e1 < e2 && e2 < e3, "世代号必须严格递增：{e1} / {e2} / {e3}");
    // 排程线同理：两次事件领到同一个号 ⇒ 「我开探后世界又变了」这件事无从表达。
    let (s1, s2) = (next_ipinfo_schedule_seq(), next_ipinfo_schedule_seq());
    assert!(s1 < s2, "排程线必须严格递增：{s1} / {s2}");

    // ── 序列 (a) 冷启动：startup 腿 t=3s 开探（慢），起核就绪腿 t≈6.5s 开探（快，先落地）──
    // 两次排程（startup_tasks t≈1、autoconnect 起核就绪 t≈2.5）都发生在两腿开探**之前**
    // ⇒ 两腿快照到同一个排程线值，本序列纯由世代定序。
    next_ipinfo_schedule_seq(); // t≈1 startup_tasks 排程
    next_ipinfo_schedule_seq(); // t≈2.5 起核就绪 → 排程
    let (startup, startup_seq) = probe_start(); // t=3
    let (started, started_seq) = probe_start(); // t≈6.5
    assert_eq!(
        startup_seq, started_seq,
        "两腿都在最后一次排程之后开探 ⇒ 排程线同值，本序列的判据只剩世代"
    );

    let fresh = snap_with_proxy("1.1.1.1", "HK");
    assert!(
        commit_ipinfo_snapshot(started, started_seq, &fresh),
        "最新一腿必须能落地，否则这道闸就成了「谁都别想发布」的死规则"
    );
    // startup 腿 t≈10s 才探完，此刻核还没起 ⇒ 它手里是 proxy=null。
    assert!(
        !commit_ipinfo_snapshot(startup, startup_seq, &snap_direct_only()),
        "冷启动慢腿必须退场：它一落地就把代理出口盖成 null ⇒ 状态栏回退 '—'、旗面消失"
    );
    assert_eq!(
        cached_snapshot()["proxy"]["countryCode"],
        json!("HK"),
        "缓存被旧腿盖回 direct-only ⇒ 序列 (a) 复现"
    );

    // ── 序列 (b) 停核 → 1.5s 后起核：停核腿零延迟、t=0 就开探；起核腿 t≈5.5s 才开探 ──
    next_ipinfo_schedule_seq(); // t=0 停核事件（零延迟腿：排程与开探同刻）
    let (stopped, stopped_seq) = probe_start();
    next_ipinfo_schedule_seq(); // t≈1.5 起核就绪 → 排程（睡 4s）
    let (restarted, restarted_seq) = probe_start(); // t≈5.5 开探
    assert!(commit_ipinfo_snapshot(
        restarted,
        restarted_seq,
        &snap_with_proxy("2.2.2.2", "JP")
    ));
    assert!(
        !commit_ipinfo_snapshot(stopped, stopped_seq, &snap_direct_only()),
        "零延迟停核腿完全跳过睡前那道闸，只能靠探测**之后**这道闸挡住"
    );
    assert_eq!(
        cached_snapshot()["proxy"]["countryCode"],
        json!("JP"),
        "停核腿把刚起的新出口盖成 null ⇒ 序列 (b) 复现"
    );

    // ── 序列 (c) 连点热切 B→C（间隔 <4s）：两次排程都落在两腿开探之前 ⇒ 排程线同值，
    // 由世代定序。B 腿 t=4s 开探（慢），C 腿 t=5s 开探（快）先落地。
    // 间隔 >4s 的那个变体（世代闸认不出）见段 (f)。
    next_ipinfo_schedule_seq(); // t=0 切到 B
    next_ipinfo_schedule_seq(); // t=1 切到 C
    let (node_b, node_b_seq) = probe_start(); // t=4
    let (node_c, node_c_seq) = probe_start(); // t=5
    assert_eq!(
        node_b_seq, node_c_seq,
        "连点（<4s）两腿快照到同一个排程线值"
    );
    assert!(commit_ipinfo_snapshot(
        node_c,
        node_c_seq,
        &snap_with_proxy("3.3.3.3", "SG")
    ));
    assert!(
        !commit_ipinfo_snapshot(node_b, node_b_seq, &snap_with_proxy("4.4.4.4", "HK")),
        "B 腿后到必须退场，否则状态栏长期显示已经切走的 B 的出口 IP 与旗面"
    );
    let cached = cached_snapshot();
    assert_eq!(
        cached["proxy"]["ip"],
        json!("3.3.3.3"),
        "序列 (c) 复现：显示的是切走的那个节点"
    );
    assert_eq!(cached["proxy"]["countryCode"], json!("SG"));

    // ── 🟠 序列 (d) 收敛窗口内手点「网络检测」：**新增的回归段** ──
    //
    // 真机路径：t=0 起核就绪 → 排程 4s 收敛腿；t≈2 用户点首页「网络检测」（按钮此刻可点：
    // `disabled={!connected || unlockCooldown}`，而 `unlockCooldown` 派生自解锁 `lastRunAt`，
    // 重连后通常 >15s ⇒ 不置灰）→ `ipinfoApi.get(true, true)` force 绕过 TTL 立刻开探。
    // 选路尚未收敛 ⇒ 这一次**大概率拿回 `proxy=null`**（这正是那 4s 存在的全部理由）。
    //
    // 旧实现在**排程时**（t=0）就领了号 ⇒ 手点腿（t=2）领到更大的号 ⇒ t=4 收敛腿醒来一比对即
    // 判过期、**原地退场、永不开探**；赢的是设计自己判定为不可信的那次探测。按需复查至少要再等
    // 一轮退避，期间状态栏 `—`、两处旗面消失、`proxy_probed=false` 连伴测都不跑。
    //
    // 改成**开探时**领号后，先后关系颠倒过来：手点腿 t=2 先领，收敛腿 t=4 后领 ⇒ 收敛腿胜。
    next_ipinfo_schedule_seq(); // t=0 起核就绪 → 排程收敛腿（睡 4s）
    next_ipinfo_schedule_seq(); // t≈2 用户手点：force 腿的排程与开探同刻
    let (manual_click, manual_seq) = probe_start(); // t≈2 开探
    assert!(
        commit_ipinfo_snapshot(manual_click, manual_seq, &snap_direct_only()),
        "手点腿此刻是最新的一条，它自己必须能落地（否则用户点了按钮什么都不会发生）"
    );
    let (settled, settled_seq) = probe_start(); // t=4：收敛腿睡满后才领号、才开探
    assert!(
        settled > manual_click,
        "🟠 号必须按**开探**顺序发：排程时领号会让 t=0 排上的收敛腿(号 {settled})\
             反而旧于 t≈2 的手点腿(号 {manual_click})，收敛腿于是永不开探"
    );
    assert_eq!(
        settled_seq, manual_seq,
        "手点腿的排程发生在收敛腿开探**之前** ⇒ 两腿快照到同一个排程线值，本序列仍由世代定序；\
             若排程线在这里把收敛腿判过期，本轮新加的那一半判据就把 round-2 修好的洞又打开了"
    );
    assert!(
        commit_ipinfo_snapshot(settled, settled_seq, &snap_with_proxy("6.6.6.6", "JP")),
        "收敛后那条重探腿必须能落地 —— 它才是唯一能拿到真出口的一次探测"
    );
    assert_eq!(
        cached_snapshot()["proxy"]["ip"],
        json!("6.6.6.6"),
        "序列 (d) 复现：收敛腿被窗口内的手点腿静默作废，状态栏停在 proxy=null（`—` + 无旗面）"
    );

    // ── 🔴 序列 (f) 两次热切间隔 >4s：**世代闸对它天生失明**（第三轮复审的回归段）──
    //
    // 真机路径（间隔 >4s 完全常规）：
    //   t=0   热切到 B → L1 置在飞 + 广播置空，睡到 t=4；
    //   t=4.0 L1 醒 → 领世代 → 读 status/config（selected=B）→ 经 B 的隧道开探；
    //   t=4.1 热切到 C → L2 排程，睡到 t=8.1 —— **它要到 t=8.1 才领世代**；
    //   t=5.0 L1 探完落地：`IPINFO_REFRESH_EPOCH` 仍是 L1 自己的号 ⇒ 过闸。
    //
    // 后果两条、性质不同：广播 B 的出口（状态栏 + 两处旗面显示已切走的节点，~4s 后自愈），
    // 以及 `spawn_warm_rtt_probe` 把**经 C 的隧道量到的 RTT** 写进 B 的延迟徽标 ——
    // 后者**持久**（`latencyMap[B]` 保留错值到下次测 B 为止），而那道复查存在的全部理由
    // 就是「记错比不记更糟」。
    //
    // 根因：一个计数器兼了两件事 ——「谁最新」（该在**排程**时宣告）与「谁的世界快照最新」
    // （该在**开探**时取号）。round-1 用排程时刻做后者、round-2 用开探时刻做前者，两边都只对一半。
    next_ipinfo_schedule_seq(); // t=0 热切到 B → L1 排程
    let (l1, l1_seq) = probe_start(); // t=4.0 L1 领世代 + 快照排程线 → 开探（走 B）
    next_ipinfo_schedule_seq(); // t=4.1 热切到 C → L2 排程（尚未领世代）
    assert_eq!(
        IPINFO_REFRESH_EPOCH.load(Ordering::SeqCst),
        l1,
        "前置：L2 还在睡、尚未领号 ⇒ 世代仍是 L1 自己的 —— 这正是世代闸在本序列里失明的原因，\
             也是为什么本段的红/绿完全取决于排程线那一半判据"
    );
    assert!(
        !commit_ipinfo_snapshot(l1, l1_seq, &snap_with_proxy("8.8.8.8", "HK")),
        "🔴 睡眠中的新腿必须能作废在飞的旧腿：L1 落地会广播已切走的 B 的出口，\
             并把经 C 隧道量到的 RTT 持久写进 B 的延迟徽标"
    );
    assert_eq!(
        cached_snapshot()["proxy"]["ip"],
        json!("6.6.6.6"),
        "序列 (f) 复现：缓存被 B 腿盖掉（peek 型消费方随即吐已切走的节点）"
    );
    let (l2, l2_seq) = probe_start(); // t=8.1 L2 醒 → 领世代开探
    assert!(
        commit_ipinfo_snapshot(l2, l2_seq, &snap_with_proxy("5.5.5.5", "SG")),
        "L2 是最新的一条，它自己必须能落地（否则这道闸又成了「谁都别想发布」）"
    );
    assert_eq!(cached_snapshot()["proxy"]["ip"], json!("5.5.5.5"));

    // ── 🔵 段 (e) 在飞**计数**：谁排的位谁归还，落地一律不清位 ──
    //
    // 缓存里此刻是段 (f) 落地的 5.5.5.5/SG（= 上一个出口）。起核/热切排程腿一排位，peek 型消费方
    // （托盘浮层每次弹出即 peek、主窗窗口重建水合）就必须与订阅方看到同一帧「置空」，否则同屏两处
    // 对「我现在从哪出去」给出互相矛盾的答案，且错的那个是用旧出口冒充新出口。
    //
    // **变异锁**：① 删掉 `peek_ipinfo_snapshot` 的在飞分支（退回「无条件读缓存」）→ 转红；
    // ② 把计数退回 `AtomicBool` 的 `store(true)/store(false)`（L1 归还即清掉 L2 的位）→ 转红；
    // ③ 把归还搬回 `commit_ipinfo_snapshot`（落地即清位）→ 转红。
    assert_eq!(IPINFO_INFLIGHT.load(Ordering::SeqCst), 0, "前置：无腿在飞");
    assert_eq!(
        peek_ipinfo_snapshot()["proxy"]["ip"],
        json!("5.5.5.5"),
        "前置：未在飞时 peek 读缓存（这条同时钉住「别把 peek 改成恒回置空帧」）"
    );

    IPINFO_INFLIGHT.fetch_add(1, Ordering::SeqCst); // L1 排程（切到 B）
    let peeked = peek_ipinfo_snapshot();
    assert!(
        peeked["proxy"].is_null() && peeked["direct"].is_null(),
        "在飞时 peek 仍吐上一个出口 ⇒ 托盘浮层/水合腿把旧出口冒充成新出口"
    );
    assert_eq!(
        peeked["loading"],
        json!(true),
        "在飞帧须与订阅方那一帧同形（含 loading 标记）"
    );

    // 缓存**不得**被 pending 帧污染：非 force 的 TTL 短路读的是同一份缓存，写进去会让收敛窗口后
    // 15s 内的每次 `ipinfo_get` 都短路拿到双 null（把「正在探」固化成「探完了没探到」）。
    // 这正是 reviewer 点名「不能靠把 pending 写进缓存解决」的那条。
    assert_eq!(
        cached_snapshot()["proxy"]["ip"],
        json!("5.5.5.5"),
        "在飞标记绝不许顺手写缓存 —— 那会毒化 fresh_cached_snapshot"
    );

    IPINFO_INFLIGHT.fetch_add(1, Ordering::SeqCst); // L2 排程（切到 C，L1 仍在飞）
                                                    // L1 落地（哪怕它这一次真的过了闸）**不得**清位 —— 位是排程腿自己排的。
    let (landed, landed_seq) = probe_start();
    assert!(commit_ipinfo_snapshot(
        landed,
        landed_seq,
        &snap_with_proxy("7.7.7.7", "SG")
    ));
    assert_eq!(
        IPINFO_INFLIGHT.load(Ordering::SeqCst),
        2,
        "落地不得清位：`AtomicBool` 时代 L1 一落地就把 L2 排的位也清了 —— \
             L2 剩下的 3s 收敛窗口里 peek 型消费方照吐已切走节点的缓存值"
    );
    IPINFO_INFLIGHT.fetch_sub(1, Ordering::SeqCst); // L1 跑完归还自己那一格
    assert!(
        peek_ipinfo_snapshot()["proxy"].is_null(),
        "L2 仍在收敛窗口里 ⇒ peek 必须继续置空，绝不许因为 L1 跑完就提前开窗"
    );

    IPINFO_INFLIGHT.fetch_sub(1, Ordering::SeqCst); // L2 跑完归还
    assert_eq!(
        IPINFO_INFLIGHT.load(Ordering::SeqCst),
        0,
        "全部归还后计数须归零"
    );
    assert_eq!(
        peek_ipinfo_snapshot()["proxy"]["ip"],
        json!("7.7.7.7"),
        "归还后 peek 须回到读缓存，且读到的是最后落地的那个出口"
    );

    // ── 🔴 段 (g) 出口**直判无效终态**：mark 必须宣告排程线，否则在飞探测腿把终态盖回去 ──
    //
    // 真机路径：
    //   t=0    TS 隧道就绪边沿 → 排一次 refresh（收敛 4s）；
    //   t=4    腿醒来领世代 + 快照排程线 → 开探（proxy 侧预算最长 20s）；
    //   t=5    exit peer 掉线 → `reconcile_ts_exit_block` 跨态 → `mark_exit_blocked`
    //          → `mark_ipinfo_proxy_blocked` 直落 `proxyBlocked` 终态；
    //   t=15   探测腿落地。不宣告时**两个计数器在整段无人自增** ⇒ 恒过闸 ⇒ 用一个对已知无效出口
    //          的探测结果（`proxy:null` + `error`）覆盖 `proxyBlocked`。
    //
    // 为什么覆盖了就回不来：`reconcile_ts_exit_block` 是**边沿**触发、同态帧直接早退 ⇒ 终态
    // **不会重落**；按需复查只认“不可达”、不知道丢失的 TS API 直判原因，不能重建这个终态。
    //
    // **变异锁**：删掉 `commit_proxy_blocked_snapshot` 体首那行 `next_ipinfo_schedule_seq();`
    // → 本段转红（这一段调的就是生产函数本体，不是复刻）。
    next_ipinfo_schedule_seq(); // t=0 TS 隧道就绪 → 排 refresh（睡 4s）
    let (blocked_probe, blocked_probe_seq) = probe_start(); // t=4 腿醒来开探
                                                            // t=5 直判终态落地（= `mark_ipinfo_proxy_blocked` 去掉广播的那一半，见该函数文档）。
    commit_proxy_blocked_snapshot("ts-exit-device-offline");
    assert_eq!(
        cached_snapshot()["proxyBlocked"],
        json!("ts-exit-device-offline"),
        "前置：终态已落进权威缓存（peek 型消费方就是从这里读的）"
    );
    // t=15 在飞腿落地 —— 必须退场。
    assert!(
        !commit_ipinfo_snapshot(blocked_probe, blocked_probe_seq, &snap_direct_only()),
        "🔴 直判终态之后落地的在飞腿必须退场：它探的是一个**已知无效**的出口，结果只可能是 \
             null/error，而覆盖掉 proxyBlocked 之后终态不会重落（reconcile 同态早退）"
    );
    assert_eq!(
        cached_snapshot()["proxyBlocked"],
        json!("ts-exit-device-offline"),
        "段 (g) 复现：状态栏从「出口无效」被改写成「检测失败」，并一直挂到下一次真跨态"
    );
}
