use super::*;

/// 🔴 `invalidate` 的排程腿不得用 `tokio::spawn` —— 2026-07-21 真机崩溃（`SIGABRT`）的守卫。
///
/// # 为什么必须是源码扫描，而不是行为测试
///
/// 崩溃形态：`tokio::spawn` 要求调用处已在 Tokio runtime 上下文内，否则 panic。`invalidate` 的调用方
/// **全是同步 command**（Tauri 对 `pub fn` command 在主线程直接调用，无 runtime 上下文）⇒ 切一次节点
/// 就 `abort()`，射程覆盖 `server_switch` / `server_delete` / `server_delete_batch` /
/// `subscription_delete` / `config_save` / `config_set_value`。
///
/// **这个 bug 单测抓不到，而且是结构性抓不到**：`#[tokio::test]` 自带 runtime 上下文，`tokio::spawn`
/// 与 `tauri::async_runtime::spawn` 在测试里行为完全一致、都能过。当初 14/14 变异全杀、5 门全绿，
/// 照样把它放进了生产 —— **测试环境比生产环境「更宽容」时，测试的绿是没有信息量的**。
/// 唯一能在本层锁住的判据就是「源码里不许出现那个 API」。
mod spawn_guard;

use std::collections::VecDeque;
use std::sync::Mutex as StdMutex;

use polaris_unlock::http::{RedirectHop, UnlockRequest, UnlockResponse};

// ── 事件记录 sink（组合面门：证「事件真 emit」而无需 Tauri 运行时）──────────────
#[derive(Default)]
struct RecordingSink {
    progress: StdMutex<Vec<(String, UnlockResult)>>,
    updated: StdMutex<Vec<UnlockSnapshot>>,
    invalidated: StdMutex<Vec<(bool, bool)>>,
    /// 自跑排程 token 流水（每次 invalidate 一条）——去抖合并的可断言面。
    self_runs: StdMutex<Vec<u64>>,
}
impl RecordingSink {
    fn progress_count(&self) -> usize {
        self.progress.lock().unwrap().len()
    }
    fn updated(&self) -> Vec<UnlockSnapshot> {
        self.updated.lock().unwrap().clone()
    }
    fn invalidated(&self) -> Vec<(bool, bool)> {
        self.invalidated.lock().unwrap().clone()
    }
    fn self_runs(&self) -> Vec<u64> {
        self.self_runs.lock().unwrap().clone()
    }
}
impl UnlockEventSink for RecordingSink {
    fn progress(&self, service_id: &str, result: &UnlockResult) {
        self.progress
            .lock()
            .unwrap()
            .push((service_id.to_string(), result.clone()));
    }
    fn updated(&self, snapshot: &UnlockSnapshot) {
        self.updated.lock().unwrap().push(snapshot.clone());
    }
    fn invalidated(&self, running: bool, exit_blocked: bool) {
        self.invalidated
            .lock()
            .unwrap()
            .push((running, exit_blocked));
    }
    fn schedule_self_run(&self, token: u64) {
        self.self_runs.lock().unwrap().push(token);
    }
}

/// 预算足够大 = 不受 deadline 干扰（对齐 上游「单测以冻结注入时钟绕过 deadline」的手法）。
const BUDGET_UNBOUNDED_MS: u64 = 10 * 60 * 1_000;

#[test]
fn network_recovery_rechecks_only_degraded_snapshots() {
    let runtime = UnlockRuntime::default();
    assert!(
        !runtime.should_recheck_after_connectivity_recovery(),
        "从未检测过时由既有启动自跑负责，网络事件不应凭空叠一轮"
    );

    let mut healthy = UnlockSnapshot::default();
    healthy
        .results
        .insert("chatgpt".to_string(), UnlockResult::new(UnlockStatus::Ok));
    runtime.set_last_snapshot(Some(healthy));
    assert!(
        !runtime.should_recheck_after_connectivity_recovery(),
        "高置信快照不应被普通接口 burst 反复作废"
    );

    let mut timeout = UnlockSnapshot::default();
    timeout.results.insert(
        "chatgpt".to_string(),
        UnlockResult::new(UnlockStatus::Timeout),
    );
    runtime.set_last_snapshot(Some(timeout));
    assert!(runtime.should_recheck_after_connectivity_recovery());

    runtime.set_last_snapshot(Some(UnlockSnapshot {
        not_ready: Some(true),
        ..Default::default()
    }));
    assert!(runtime.should_recheck_after_connectivity_recovery());

    runtime.set_last_snapshot(Some(UnlockSnapshot {
        low_confidence: Some(true),
        ..Default::default()
    }));
    assert!(runtime.should_recheck_after_connectivity_recovery());
}

// ── mock UnlockHttp（按 URL 子串脚本 + egress trace 分序列 + 可选每请求 hook）─────
struct MockHttp {
    scripts: Vec<(String, UnlockResponse)>,
    /// 出口 egress trace（`cloudflare.com/cdn-cgi/trace`）的**逐次**响应：
    /// probe_egress 轮首/轮尾各一次，可造「出口漂移」（bracket 用）。空 = 用 scripts。
    trace_seq: StdMutex<VecDeque<UnlockResponse>>,
    /// 每请求 hook（如 mid-round invalidate）；返回后再走脚本。
    on_request: Option<Box<dyn Fn() + Send + Sync>>,
}
impl MockHttp {
    fn new() -> Self {
        Self {
            scripts: Vec::new(),
            trace_seq: StdMutex::new(VecDeque::new()),
            on_request: None,
        }
    }
    fn on(mut self, pat: &str, resp: UnlockResponse) -> Self {
        self.scripts.push((pat.to_string(), resp));
        self
    }
    fn egress_seq(self, seq: Vec<UnlockResponse>) -> Self {
        *self.trace_seq.lock().unwrap() = seq.into();
        self
    }
    fn hook(mut self, f: impl Fn() + Send + Sync + 'static) -> Self {
        self.on_request = Some(Box::new(f));
        self
    }
}
#[async_trait::async_trait]
impl UnlockHttp for MockHttp {
    async fn request(&self, req: &UnlockRequest) -> UnlockResponse {
        if let Some(h) = &self.on_request {
            h();
        }
        // 出口 egress trace 走独立序列（轮首/轮尾可不同 → 造出口漂移）。
        if req.url.contains("cloudflare.com/cdn-cgi/trace") {
            let mut seq = self.trace_seq.lock().unwrap();
            if !seq.is_empty() {
                // 用完保留末值（后续 probe 复用最后一个响应）。
                return if seq.len() == 1 {
                    seq[0].clone()
                } else {
                    seq.pop_front().unwrap()
                };
            }
        }
        for (pat, resp) in &self.scripts {
            if req.url.contains(pat) {
                return resp.clone();
            }
        }
        UnlockResponse::err("no-script")
    }
}

fn ok(status: u16, body: &str) -> UnlockResponse {
    UnlockResponse::ok(status, body)
}

/// 全服务 Ok 的脚本集（1:1 复用 detector.rs `detect_aggregates` 的已证夹具）。egress=US。
fn all_ok_mock() -> MockHttp {
    MockHttp::new()
        .egress_seq(vec![ok(200, "ip=1.1.1.1\nloc=US\n")])
        .on(
            "chat.openai.com/cdn-cgi/trace",
            ok(200, "ip=1.1.1.1\nloc=US\n"),
        )
        .on("api.openai.com", ok(200, "{}"))
        .on("ios.chat.openai.com", ok(200, "<html>welcome</html>"))
        .on(
            "claude.ai/",
            UnlockResponse {
                status: 200,
                body: String::new(),
                truncated: false,
                redirect_chain: vec![RedirectHop {
                    status: 302,
                    location: "https://claude.ai/login".to_string(),
                }],
                error: None,
                ..Default::default()
            },
        )
        .on("claude.ai/cdn-cgi/trace", ok(200, "ip=1.1.1.1\nloc=US\n"))
        .on("gemini.google.com", ok(200, "blah 45631641,null,true blah"))
        // grok：**当前不在上线集**（`ServiceId::PENDING_CALIBRATION`，待真机哨兵标定）→ 本轮不会被请求。
        // 仍预置脚本：开关一翻（`types.rs` 把 Grok 移回 `ServiceId::ALL`）这批测试不会因为「mock 漏脚本
        // → Timeout → 走 TIMEOUT_TTL/settle-retry」莫名转红。trace 须排首页脚本**之前**（首个子串匹配即返回）。
        .on("grok.com/cdn-cgi/trace", ok(200, "ip=1.1.1.1\nloc=US\n"))
        .on("grok.com", ok(200, "<html>cdn.grok.com/_next</html>"))
        .on("netflix.com/title/81280792", ok(200, "watchable content"))
        .on("netflix.com/title/70143836", ok(200, "watchable content"))
        .on("bamgrid.com/devices", ok(200, r#"{"assertion":"A"}"#))
        .on("bamgrid.com/token", ok(200, r#"{"refresh_token":"R"}"#))
        .on(
            "bamgrid.com/graph",
            ok(200, r#"{"countryCode":"JP","inSupportedLocation":true}"#),
        )
        .on("disneyplus.com", ok(200, ""))
        // tiktok：store_region 须排在首页脚本**之前**（mock 首个子串匹配即返回，`www.tiktok.com/`
        // 会先吃掉 passport 请求）。首页无跳转 → 停在 feed → Ok。
        .on(
            "tiktok.com/passport/web/store_region/",
            ok(200, r#"{"data":{"store_region":"us"},"message":"success"}"#),
        )
        .on("www.tiktok.com/", ok(200, "<html>feed</html>"))
        .on(
            "spotify.com",
            ok(
                200,
                r#"{"status":1,"country":"US","is_country_launched":true}"#,
            ),
        )
}

fn runtime() -> UnlockRuntime {
    UnlockRuntime::default()
}

/// gating SoT 全矩阵（item6）：核未运行/无端口 → ProxyNotRunning；running 但 exit_blocked → ExitInvalid；
/// running + 端口 + 未 blocked → 放行（None）。优先级 ProxyNotRunning > ExitInvalid。
///
/// 变异有牙：删「exit_blocked → ExitInvalid」分支 → case (true,X,true) 返 None → 转红（ExitInvalid 复归 dead）；
/// 删「!running → ProxyNotRunning」分支 → case (false,..) 返 None 或 ExitInvalid → 转红。
#[test]
fn unlock_gate_reason_matrix() {
    // 核未运行 → ProxyNotRunning（无视 exit_blocked，优先级最高）。
    assert_eq!(
        unlock_gate_reason(false, 0, false),
        Some(UnlockBlockedReason::ProxyNotRunning)
    );
    assert_eq!(
        unlock_gate_reason(false, 1080, true),
        Some(UnlockBlockedReason::ProxyNotRunning)
    );
    // running 但无 mixed 入站 → ProxyNotRunning。
    assert_eq!(
        unlock_gate_reason(true, 0, false),
        Some(UnlockBlockedReason::ProxyNotRunning)
    );
    // running + 端口 + 出口失效 → ExitInvalid（本项接线的核心：不再 dead）。
    assert_eq!(
        unlock_gate_reason(true, 1080, true),
        Some(UnlockBlockedReason::ExitInvalid)
    );
    // running + 端口 + 出口有效 → 放行。
    assert_eq!(unlock_gate_reason(true, 1080, false), None);
}

// ── 组合面门（§K7.1）：真调 run → 快照真存 → 事件真 emit ─────────────────────
#[tokio::test]
async fn combination_gate_run_stores_snapshot_and_emits_progress_and_updated() {
    let rt = runtime();
    let sink = RecordingSink::default();
    let http = all_ok_mock();
    let snap = rt.run(&http, &sink, false, || 1_000).await;

    // 快照真存：peek 在 TTL 内取得。
    assert!(
        rt.peek(1_000).is_some(),
        "commit 后 peek 必须取得快照（快照真存）"
    );
    assert_eq!(snap.results.len(), ServiceId::ALL.len());
    for (id, r) in &snap.results {
        assert_eq!(r.status, UnlockStatus::Ok, "service {id} 应 Ok");
    }
    // 事件真 emit：逐服务 progress + 一次 updated。
    assert_eq!(
        sink.progress_count(),
        ServiceId::ALL.len(),
        "每服务 settle 各一次 progress"
    );
    assert_eq!(sink.updated().len(), 1, "一轮完成一次 updated");
    assert_eq!(sink.updated()[0].results.len(), ServiceId::ALL.len());
    assert!(sink.invalidated().is_empty(), "正常轮不应 invalidate");
    assert_eq!(snap.egress.as_ref().unwrap().region.as_deref(), Some("US"));
}

// ── 淬火不变式 · 出口归属 bracket（#7）：结果标错出口 → 丢弃 ──────────────────
#[tokio::test]
async fn egress_bracket_discards_when_exit_moves_midround() {
    let rt = runtime();
    let sink = RecordingSink::default();
    // 轮首 egress = IP-A，轮尾 = IP-B（出口在检测中途翻转）→ 结果不属任一确定出口。
    let http = all_ok_mock().egress_seq(vec![
        ok(200, "ip=1.1.1.1\nloc=US\n"),
        ok(200, "ip=9.9.9.9\nloc=US\n"),
    ]);
    let snap = rt.run(&http, &sink, false, || 1_000).await;

    // **决不把 A 出口的结果标给 B 出口**：丢弃，不 commit，不 emit UPDATED，改 emit INVALIDATED。
    assert!(
        rt.peek(1_000).is_none(),
        "出口漂移 → 结果不得入缓存（否则标错出口）"
    );
    assert!(sink.updated().is_empty(), "丢弃轮不得 emit UPDATED");
    assert_eq!(
        sink.invalidated().len(),
        1,
        "出口漂移应 emit INVALIDATED（自动重跑）"
    );
    assert!(snap.checked_at.is_none(), "丢弃轮返回空快照");
}

// ── 淬火不变式 · 出口归属 bracket（#7）：并发 invalidate → 丢弃（epoch 腿）─────
#[tokio::test]
async fn epoch_bracket_discards_when_invalidated_midround() {
    let rt = Arc::new(runtime());
    let sink = Arc::new(RecordingSink::default());
    // hook：检测请求飞行期间发生一次 invalidate（切节点）→ epoch 变。
    let rt_hook = rt.clone();
    let sink_hook = sink.clone();
    let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let fired2 = fired.clone();
    let http = all_ok_mock().hook(move || {
        // 只触发一次，模拟轮中一次切节点。
        if !fired2.swap(true, Ordering::SeqCst) {
            rt_hook.invalidate(&*sink_hook, true, false);
        }
    });
    let snap = rt.run(&http, &*sink, false, || 1_000).await;

    assert!(
        rt.peek(1_000).is_none(),
        "并发 invalidate → 结果不得 commit（epoch 作废）"
    );
    assert!(sink.updated().is_empty(), "epoch 作废轮不得 emit UPDATED");
    assert!(snap.checked_at.is_none());
}

// ── 淬火不变式 · TTL（#65/#6）：过期不再 serve ──────────────────────────────
#[tokio::test]
async fn ttl_expired_snapshot_is_not_served() {
    let rt = runtime();
    let sink = RecordingSink::default();
    // 全 Ok → 无 timeout → 30min FRESH TTL。commit 于 T0=1000。
    rt.run(&all_ok_mock(), &sink, false, || 1_000).await;
    assert!(rt.peek(1_000).is_some(), "刚存应可取");
    assert!(rt.peek(1_000 + FRESH_TTL_MS - 1).is_some(), "TTL 内应可取");
    assert!(
        rt.peek(1_000 + FRESH_TTL_MS).is_none(),
        "过 TTL 必须失效（否则陈旧快照永久 serve）"
    );
}

// ── 淬火不变式 · invalidate 契约（#7）：切节点/起停 → 清缓存 + 递增 epoch ────
#[tokio::test]
async fn invalidate_clears_cache_and_bumps_epoch_and_emits() {
    let rt = runtime();
    let sink = RecordingSink::default();
    rt.run(&all_ok_mock(), &sink, false, || 1_000).await;
    assert!(rt.peek(1_000).is_some(), "前提：已有缓存");
    let e0 = rt.epoch();

    rt.invalidate(&sink, true, false);

    assert!(
        rt.peek(1_000).is_none(),
        "invalidate 必须清缓存（切节点不清缓存 = 陈旧污染）"
    );
    assert_eq!(
        rt.epoch(),
        e0 + 1,
        "invalidate 必须递增 epoch（作废在飞轮）"
    );
    assert_eq!(
        sink.invalidated().last(),
        Some(&(true, false)),
        "带核真态广播"
    );
}

// ── 淬火不变式 · 受限地区收敛（#8）：CN 全超按高置信终态收敛（正常 30min TTL）──
#[tokio::test]
async fn restricted_cn_all_timeout_converges_not_low_confidence() {
    let rt = runtime();
    let sink = RecordingSink::default();
    // egress CN + 所有 checker 无脚本 → 全 timeout。
    let http = MockHttp::new().egress_seq(vec![ok(200, "ip=1.2.3.4\nloc=CN\n")]);
    let snap = rt.run(&http, &sink, false, || 1_000).await;

    assert!(
        snap.results
            .values()
            .all(|r| r.status == UnlockStatus::Timeout),
        "CN 出口海外服务全超（结构性预期）"
    );
    assert_eq!(
        snap.low_confidence, None,
        "受限地区全超**不**置 low_confidence（高置信终态）"
    );
    // 收敛 = 正常 30min TTL（非 2min churn）：3min 后仍在缓存。
    assert!(rt.peek(1_000).is_some(), "受限终态应入缓存");
    assert!(
        rt.peek(1_000 + 3 * 60 * 1_000).is_some(),
        "受限用 30min TTL（非 2min）→ 3min 后仍 serve，不 churn 重扫"
    );
}

// 对照：非受限（US）全超 = 低置信瞬态 → 置 low_confidence + **不入缓存**（避免垃圾快照锁 30min）。
// `start_paused`：非受限全超会触发 settle-retry 退避（2s+4s），暂停时钟使其瞬时（不真睡）。
#[tokio::test(start_paused = true)]
async fn nonrestricted_all_timeout_is_low_confidence_and_not_cached() {
    let rt = runtime();
    let sink = RecordingSink::default();
    let http = MockHttp::new().egress_seq(vec![ok(200, "ip=1.1.1.1\nloc=US\n")]);
    let snap = rt.run(&http, &sink, false, || 1_000).await;

    assert!(snap
        .results
        .values()
        .all(|r| r.status == UnlockStatus::Timeout));
    assert_eq!(snap.low_confidence, Some(true), "非受限全超 = 低置信瞬态");
    assert!(
        rt.peek(1_000).is_none(),
        "低置信全超不写缓存（下一真触发即重检）"
    );
    assert_eq!(
        sink.updated().len(),
        1,
        "仍 emit UPDATED（UI 如实显），只是不入缓存"
    );
}

// ── 淬火不变式 · warm 补测（#6）：重打 timeout 项并 merge ──────────────────
// `start_paused`：首轮 partial-timeout 触发轮内 settle-retry 退避，暂停时钟使其瞬时。
#[tokio::test(start_paused = true)]
async fn warm_recheck_reruns_timeout_services_and_merges() {
    let rt = runtime();
    let sink = RecordingSink::default();
    // 首轮：netflix 两片无脚本 → netflix timeout；其余 Ok（partial-timeout）。
    let mut partial = all_ok_mock();
    partial
        .scripts
        .retain(|(p, _)| !p.contains("netflix.com/title"));
    rt.run(&partial, &sink, false, || 1_000).await;
    let first = rt.peek(1_000).expect("partial-timeout 含非超项 → 入缓存");
    assert_eq!(first.results["netflix"].status, UnlockStatus::Timeout);

    // warm 补测：netflix 恢复可看 → run_recheck 应把 netflix merge 成 Ok。
    let epoch0 = rt.epoch();
    let healed = all_ok_mock();
    let committed = rt.run_recheck(&healed, &sink, epoch0, || 2_000).await;
    assert!(committed, "有 timeout 项 + epoch 未变 → 补测应 commit");
    let after = rt.peek(2_000).expect("补测后仍有缓存");
    assert_eq!(
        after.results["netflix"].status,
        UnlockStatus::Ok,
        "netflix 应被补测点亮"
    );
    assert_eq!(after.checked_at, Some(2_000), "补测刷新 checkedAt");
}

// warm 补测 epoch 守卫：补测期间 invalidate（epoch 变）→ 丢弃，不改缓存。
// `start_paused`：首轮 partial-timeout 触发轮内 settle-retry 退避，暂停时钟使其瞬时。
#[tokio::test(start_paused = true)]
async fn warm_recheck_epoch_guard_discards_after_invalidate() {
    let rt = runtime();
    let sink = RecordingSink::default();
    let mut partial = all_ok_mock();
    partial
        .scripts
        .retain(|(p, _)| !p.contains("netflix.com/title"));
    rt.run(&partial, &sink, false, || 1_000).await;
    let stale_epoch = rt.epoch();
    // 补测调度后、执行前发生 invalidate（切节点）：epoch 变 + 缓存清。
    rt.invalidate(&sink, true, false);
    let committed = rt
        .run_recheck(&all_ok_mock(), &sink, stale_epoch, || 2_000)
        .await;
    assert!(
        !committed,
        "epoch 变（invalidate 过）→ 补测丢弃（别测旧出口）"
    );
    assert!(
        rt.peek(2_000).is_none(),
        "补测不得复活被 invalidate 清掉的缓存"
    );
}

// ── force 绕缓存 ────────────────────────────────────────────────────────────
#[tokio::test]
async fn force_bypasses_fresh_cache_and_redetects() {
    let rt = runtime();
    let sink = RecordingSink::default();
    rt.run(&all_ok_mock(), &sink, false, || 1_000).await;
    assert_eq!(sink.updated().len(), 1);
    // 非 force + 新鲜缓存 → 快路（不重跑 checker，但仍 emit updated 让新监听者点亮）。
    rt.run(&all_ok_mock(), &sink, false, || 1_100).await;
    assert_eq!(sink.updated().len(), 2, "快路仍 emit updated");
    assert_eq!(
        sink.progress_count(),
        ServiceId::ALL.len(),
        "快路不重跑 checker（progress 不增）"
    );
    // force → 重跑（progress 再增一轮）。**须越过 force 硬下限（item 5，15s）**——首跑于 T=1_000，故
    // 用 `1_000 + FORCE_MIN_MS` 让 15s 硬下限放行（否则 force<15s 会被 item 5 挡住，见 force_min_* 测）。
    rt.run(&all_ok_mock(), &sink, true, || 1_000 + FORCE_MIN_MS)
        .await;
    assert_eq!(
        sink.progress_count(),
        ServiceId::ALL.len() * 2,
        "force 重跑 checker"
    );
}

#[test]
fn peek_none_when_empty() {
    assert!(runtime().peek(0).is_none());
}

// ── A7 · 出口变判准（四写腿共用谓词）：old != new 各组合，含 →null ────────────────
// 打断（恒 true / 恒 false）→ 对应断言转红：
//   恒 true → 「重选同一节点 / 始终无选中不失效」转红（白刷探测）；
//   恒 false → 「换节点 / 首次选中 / →null 失效」转红（陈旧 30min 角标）。
#[test]
fn selected_exit_changed_covers_all_option_combos() {
    assert!(selected_exit_changed(Some("a"), Some("b")), "换节点 → 变");
    assert!(
        !selected_exit_changed(Some("a"), Some("a")),
        "重选同一节点 → 不变（防白刷）"
    );
    assert!(
        selected_exit_changed(None, Some("a")),
        "首次选中（旧 None）→ 变"
    );
    assert!(
        selected_exit_changed(Some("a"), None),
        "→null：删当前选中 / 订阅刷没了选中 → 变（必须失效）"
    );
    assert!(!selected_exit_changed(None, None), "始终无选中 → 不变");
}

// ══════════════════════════════════════════════════════════════════════════════
// item 2 · 就绪门退避（probe_ready：核起→路由前探针重试 7 次 + B1 flap）+ S-gate
// ══════════════════════════════════════════════════════════════════════════════

/// **item 2 · 就绪门耗尽 → notReady 终态**：egress 始终探不到（inbound 未就绪）→ 7 攻全败 → 提交
/// notReady（checkedAt=null，一个 checker 都不跑，不污染成假 timeout）。`start_paused` 使 19.6s 退避瞬时。
///
/// **预算放大到 [`BUDGET_UNBOUNDED_MS`]**：整轮 deadline 落地后，默认 10s 预算下第 5 攻即越界收口
/// （见 `round_deadline_truncates_readiness_gate`），7 攻全跑只在预算充裕时可达。此处验的是**退避
/// schedule 本身完整**，故绕开 deadline —— 对齐 上游 同一处注释「单测以冻结注入时钟绕过 deadline
/// 验证全 7 攻仍可达」。
///
/// **变异锁**：删就绪门（改回单探 `probe_egress` 无退避）→ 首探失败即被当结果（全 timeout / 假快照），
/// `not_ready==Some(true)` 与 `results.is_empty()` 转红。
#[tokio::test(start_paused = true)]
async fn readiness_gate_exhausts_to_not_ready_when_egress_never_probes() {
    let rt = runtime();
    let sink = RecordingSink::default();
    // cloudflare trace 恒 503 → probe_egress 恒 None → 就绪门 7 攻全败。计探测次数验「真跑满退避重试」。
    let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let c2 = count.clone();
    let http = MockHttp::new().egress_seq(vec![ok(503, "")]).hook(move || {
        c2.fetch_add(1, Ordering::SeqCst);
    });
    let snap = rt
        .run_with_budget(&http, &sink, false, || 1_000, BUDGET_UNBOUNDED_MS)
        .await;

    assert_eq!(snap.not_ready, Some(true), "就绪门耗尽 → notReady 终态");
    assert!(
        snap.checked_at.is_none(),
        "notReady 不伪造 checkedAt（本轮没跑 checker）"
    );
    assert!(
        snap.results.is_empty(),
        "就绪门未过 → 一个 checker 都不跑（不污染成假 timeout）"
    );
    assert_eq!(
        count.load(Ordering::SeqCst),
        READINESS_MAX_ATTEMPTS,
        "就绪门跑满 7 攻退避重试（非单探即弃 → 冷启动首轮探测失败不被当结果）"
    );
    assert_eq!(sink.progress_count(), 0, "未就绪 → 零 checker progress");
    assert_eq!(
        sink.updated().len(),
        1,
        "notReady 终态仍 emit UPDATED（前端复位）"
    );
    assert!(
        rt.peek(1_000).is_none(),
        "notReady 不入 TTL 缓存（egress=null）"
    );
}

/// **item 2 · S-gate**：已提交 notReady 终态 → 非 force 再触发直接返终态，不再重扫 7 攻就绪门（progress 仍 0）；
/// force 越过 15s 硬下限才解除重扫。
///
/// **变异锁**：删 S-gate（`last_snapshot().not_ready` 分支）→ 第二次非 force 会重跑就绪门 → `progress_count`
/// 断言（仍 0）转红（退回「mount/切 tab 反复重扫死出口数十秒」）。
#[tokio::test(start_paused = true)]
async fn s_gate_returns_not_ready_terminal_without_rescan() {
    let rt = runtime();
    let sink = RecordingSink::default();
    // 计网络探测：S-gate 命中的第二次非 force 应零网络（否则重扫 7 攻就绪门）。
    let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let c2 = count.clone();
    let http = MockHttp::new().egress_seq(vec![ok(503, "")]).hook(move || {
        c2.fetch_add(1, Ordering::SeqCst);
    });
    rt.run(&http, &sink, false, || 1_000).await; // 就绪门耗尽 → notReady
    let after_first = count.load(Ordering::SeqCst); // ≈7 攻
    let updated_after_first = sink.updated().len();

    // 非 force 再跑：S-gate 命中 → 直接返 notReady，**零网络**（不重扫 7 攻就绪门）。
    let snap2 = rt.run(&http, &sink, false, || 2_000).await;
    assert_eq!(snap2.not_ready, Some(true), "S-gate 返 notReady 终态");
    assert_eq!(
        count.load(Ordering::SeqCst),
        after_first,
        "S-gate：第二次非 force 零网络探测（不重扫死出口就绪门数十秒）"
    );
    assert_eq!(
        sink.progress_count(),
        0,
        "S-gate 不跑 checker（零 progress）"
    );
    assert_eq!(
        sink.updated().len(),
        updated_after_first + 1,
        "S-gate 仍 emit UPDATED（水合）"
    );

    // force 越过 15s 硬下限 → 解除 S-gate，重扫（egress 仍探不到 → 仍 notReady，网络计数增加）。
    let snap3 = rt.run(&http, &sink, true, || 1_000 + FORCE_MIN_MS).await;
    assert_eq!(
        snap3.not_ready,
        Some(true),
        "force 重扫仍 notReady（egress 仍 503）"
    );
    assert!(
        count.load(Ordering::SeqCst) > after_first,
        "force 解除 S-gate → 重扫（网络计数增加，证明 S-gate 只挡非 force）"
    );
}

/// **item 2 · B1 自适应确认**：曾失败过（疑似 flap）→ 成功探测后需连续 2 成才判就绪。egress 序列
/// 失败→成功→确认成功 → 就绪 → 跑 checker（全 ok）。`start_paused` 使退避/确认间隔瞬时。
///
/// **变异锁**：删 B1（成功即 return，不追加确认）→ 第 2 攻单次成功即就绪，与本序列结果同（弱），故辅以
/// 「就绪需吃到第 3 个 egress 响应」——若无 B1 确认，第 3 个 US 会留给轮尾 bracket，egress 消费序不同；
/// 主锁仍是就绪成功 → checkedAt 非空。
#[tokio::test(start_paused = true)]
async fn readiness_b1_confirm_requires_two_success_after_flap() {
    let rt = runtime();
    let sink = RecordingSink::default();
    // 序列：attempt0 失败(503) → attempt1 成功(US) → B1 确认探成功(US) → 就绪 → 轮尾 egress(US)。
    let http = all_ok_mock().egress_seq(vec![
        ok(503, ""),
        ok(200, "ip=1.1.1.1\nloc=US\n"),
        ok(200, "ip=1.1.1.1\nloc=US\n"),
        ok(200, "ip=1.1.1.1\nloc=US\n"),
    ]);
    let snap = rt.run(&http, &sink, false, || 1_000).await;
    assert!(snap.checked_at.is_some(), "B1 2 连成 → 就绪 → 提交终态");
    assert_eq!(
        snap.results.len(),
        ServiceId::ALL.len(),
        "就绪后跑全部 checker"
    );
    assert_eq!(snap.egress.as_ref().unwrap().region.as_deref(), Some("US"));
}

// ══════════════════════════════════════════════════════════════════════════════
// item 3 · 单 checker 总预算封顶（CHECKER_BUDGET_MS）
// ══════════════════════════════════════════════════════════════════════════════

/// **item 3 · 单 checker 超预算 → timeout**：chatgpt 的每个请求卡死 > `CHECKER_BUDGET_MS` → 该 checker 被
/// `tokio::time::timeout` 封顶落 timeout；其余服务立即返回不受影响。`start_paused` 使预算推进瞬时。
///
/// **变异锁**：删预算（改回裸 `run_checker`）→ chatgpt 请求各睡满后返 `ok(200,"{}")` → checker 判非 timeout
/// → `chatgpt==Timeout` 断言转红（退回「Disney/多连请求 checker 无兜底、最坏 32s+」）。
#[tokio::test(start_paused = true)]
async fn checker_budget_caps_hung_checker_to_timeout() {
    struct SlowChatgpt;
    #[async_trait::async_trait]
    impl UnlockHttp for SlowChatgpt {
        async fn request(&self, req: &UnlockRequest) -> UnlockResponse {
            if req.url.contains("cloudflare.com/cdn-cgi/trace") {
                return ok(200, "ip=1.1.1.1\nloc=US\n"); // egress 立即就绪
            }
            if req.url.contains("openai.com") {
                // chatgpt 三请求（cookie/ios/trace）各卡死超预算 → 整 checker 超 CHECKER_BUDGET_MS。
                tokio::time::sleep(Duration::from_millis(CHECKER_BUDGET_MS + 5_000)).await;
                return ok(200, "{}");
            }
            ok(200, "{}") // 其余服务立即返回（不 hang）
        }
    }
    let rt = runtime();
    let sink = RecordingSink::default();
    let snap = rt.run(&SlowChatgpt, &sink, false, || 1_000).await;
    assert_eq!(
        snap.results["chatgpt"].status,
        UnlockStatus::Timeout,
        "chatgpt 卡死超预算 → CHECKER_BUDGET_MS 封顶为 timeout"
    );
}

// ══════════════════════════════════════════════════════════════════════════════
// item 4 · 轮内 settle-retry（commit 前对 timeout 项退避补测 ≤2 轮）
// ══════════════════════════════════════════════════════════════════════════════

/// **item 4 · settle-retry 愈合冷隧道首轮 timeout**：netflix 首轮（前 2 个 title 请求）冷隧道失败 → timeout，
/// 补测轮恢复 watchable → 最终 ok 合入 commit。`start_paused` 使 2s+4s 退避瞬时。
///
/// **变异锁**：删 settle-retry 循环 → netflix 停在首轮 timeout → `netflix==Ok` 转红（首轮瞬态 timeout 被当结果）。
#[tokio::test(start_paused = true)]
async fn settle_retry_heals_cold_tunnel_first_round_timeout() {
    struct NetflixHeals {
        inner: MockHttp,
        calls: StdMutex<usize>,
    }
    #[async_trait::async_trait]
    impl UnlockHttp for NetflixHeals {
        async fn request(&self, req: &UnlockRequest) -> UnlockResponse {
            if req.url.contains("netflix.com/title") {
                let mut c = self.calls.lock().unwrap();
                *c += 1;
                // 首轮 2 个 title 请求 → 冷隧道失败（→ netflix timeout）；补测轮 → watchable（→ ok）。
                return if *c <= 2 {
                    UnlockResponse::err("cold-tunnel")
                } else {
                    ok(200, "watchable content")
                };
            }
            self.inner.request(req).await // 其余服务（含 egress）恒 ok
        }
    }
    let rt = runtime();
    let sink = RecordingSink::default();
    let http = NetflixHeals {
        inner: all_ok_mock(),
        calls: StdMutex::new(0),
    };
    let snap = rt.run(&http, &sink, false, || 1_000).await;
    assert_eq!(
        snap.results["netflix"].status,
        UnlockStatus::Ok,
        "settle-retry 补测轮 netflix 恢复 → 最终 ok（首轮冷隧道 timeout 不落定）"
    );
    // 补测中 netflix 灰点翻回 checking（视觉诚实）。
    let saw_checking = sink
        .progress
        .lock()
        .unwrap()
        .iter()
        .any(|(id, r)| id == "netflix" && r.status == UnlockStatus::Checking);
    assert!(
        saw_checking,
        "settle-retry 补测须对 timeout 项重发 checking"
    );
}

/// **item 4 · settle-retry 只重打灰的、不碰高置信项**：netflix 恒 timeout（无脚本），chatgpt 恒 ok。
/// 断言 chatgpt 从不收到 checking（不被 settle-retry 重扫），netflix 收到 checking（被补测）。
#[tokio::test(start_paused = true)]
async fn settle_retry_only_reprobes_timeout_services() {
    let rt = runtime();
    let sink = RecordingSink::default();
    let mut partial = all_ok_mock();
    partial
        .scripts
        .retain(|(p, _)| !p.contains("netflix.com/title")); // netflix 恒 timeout
    rt.run(&partial, &sink, false, || 1_000).await;

    let progress = sink.progress.lock().unwrap().clone();
    let netflix_checking = progress
        .iter()
        .any(|(id, r)| id == "netflix" && r.status == UnlockStatus::Checking);
    let chatgpt_checking = progress
        .iter()
        .any(|(id, r)| id == "chatgpt" && r.status == UnlockStatus::Checking);
    assert!(
        netflix_checking,
        "timeout 项 netflix 被 settle-retry 重打（checking）"
    );
    assert!(!chatgpt_checking, "高置信项 chatgpt 不被 settle-retry 重扫");
}

// ══════════════════════════════════════════════════════════════════════════════
// item 5 · force 硬下限（FORCE_MIN_MS=15s 防连点限频）
// ══════════════════════════════════════════════════════════════════════════════

/// **item 5 · force 15s 硬下限**：15s 内连点 force → 返上次快照、不重打 checker；≥15s 才放行重跑。
///
/// **变异锁**：删 force-min 判断 → 5s 后的 force 也重跑 → `progress_count`（仍 6）转红（连点强刷更快触发对端限频）。
#[tokio::test]
async fn force_min_blocks_rapid_reforce() {
    let rt = runtime();
    let sink = RecordingSink::default();
    rt.run(&all_ok_mock(), &sink, true, || 10_000).await; // 首次 force → 真跑（lastRunAt=10_000）
    assert_eq!(
        sink.progress_count(),
        ServiceId::ALL.len(),
        "首次 force 真跑"
    );

    // 5s 后再 force（<15s）→ 硬下限挡住：返上次快照，不重打。
    let snap = rt.run(&all_ok_mock(), &sink, true, || 15_000).await;
    assert_eq!(
        sink.progress_count(),
        ServiceId::ALL.len(),
        "force<15s 被挡 → 不重跑 checker（progress 不增）"
    );
    assert!(snap.checked_at.is_some(), "被挡时返上次终态快照（非空）");

    // 15s 后 force → 放行重跑。
    rt.run(&all_ok_mock(), &sink, true, || 10_000 + FORCE_MIN_MS)
        .await;
    assert_eq!(
        sink.progress_count(),
        ServiceId::ALL.len() * 2,
        "force≥15s 放行重跑"
    );
}

// ══════════════════════════════════════════════════════════════════════════════
// item 7 · 单飞（并发 run 串行化，第二者命中缓存零重扫）
// ══════════════════════════════════════════════════════════════════════════════

/// **item 7 · 单飞**：并发两 run（同冻结时钟）→ run_lock 串行 → 第一者 commit 缓存 → 第二者走 TTL 快路，
/// 只跑一轮 checker（6 progress，非 12）。
///
/// **变异锁**：删 run_lock（去掉 `_run_guard`）→ 两轮各跑一遍 → `progress_count==6` 转红（并发 run 各跑
/// 一遍网络往返，资源浪费）。
#[tokio::test]
async fn single_flight_serializes_concurrent_runs() {
    // 每请求前 `yield_now` 制造 await 让出点，暴露并发交错——否则同步 mock 会让首轮在单次 poll 内跑完，
    // 第二轮永远走快路，测不出锁的作用（去锁也 6 progress，假绿）。
    struct Yielding(MockHttp);
    #[async_trait::async_trait]
    impl UnlockHttp for Yielding {
        async fn request(&self, req: &UnlockRequest) -> UnlockResponse {
            tokio::task::yield_now().await;
            self.0.request(req).await
        }
    }
    let rt = runtime();
    let sink = RecordingSink::default();
    let h1 = Yielding(all_ok_mock());
    let h2 = Yielding(all_ok_mock());
    let (s1, s2) = tokio::join!(
        rt.run(&h1, &sink, false, || 1_000),
        rt.run(&h2, &sink, false, || 1_000),
    );
    assert_eq!(
        sink.progress_count(),
        ServiceId::ALL.len(),
        "单飞：只一轮 checker（6 progress，非并发双跑的 12）"
    );
    assert!(s1.checked_at.is_some());
    assert!(s2.checked_at.is_some(), "第二者命中第一者缓存（新鲜快照）");
    assert_eq!(s1.results.len(), ServiceId::ALL.len());
    assert_eq!(s2.results.len(), ServiceId::ALL.len());
}

// ══════════════════════════════════════════════════════════════════════════════
// T1 · invalidate → 去抖自跑（驱动层在 Rust 侧，不依赖渲染端 hook）
// ══════════════════════════════════════════════════════════════════════════════

/// **每次 invalidate 都排一轮自跑**，且 token 恒等于排程后的当前世代。
///
/// 这条锁的是本批修的缺陷本体：迁移时只搬了 invalidate 的「作废 + 广播」半边，没搬「主进程自跑」半边
/// ⇒ 六个徽章被置成检测中后无人调 run，永久转圈。
///
/// **变异锁**：删 `invalidate` 末尾的 `sink.schedule_self_run(token)` → `self_runs` 恒空 → 转红
///（正是缺陷前的状态：广播了失效、没人重跑）。
#[test]
fn invalidate_schedules_self_run_with_current_token() {
    let rt = runtime();
    let sink = RecordingSink::default();

    rt.invalidate(&sink, true, false);
    assert_eq!(sink.self_runs().len(), 1, "invalidate 必须排一轮自跑");
    assert!(
        rt.self_run_token_current(sink.self_runs()[0]),
        "刚排的 token 必须是最新（否则定时器到点就会误判让位 → 一轮都不跑）"
    );

    rt.invalidate(&sink, true, false);
    let tokens = sink.self_runs();
    assert_eq!(tokens.len(), 2, "第二次 invalidate 再排一轮");
    assert!(
        tokens[1] > tokens[0],
        "token 必须单调递增（否则无法区分新旧排程）"
    );
}

/// **去抖合并**：窗内多次 invalidate → 只有**最后一次**的 token 仍是最新 → 只跑一轮。
///
/// 「多次 invalidate 只跑一轮」在纯逻辑层等价于「只有最后一个 token 通过
/// `self_run_token_current`」；生产 sink 另外 abort 旧 timer，本判据保留为取消/睡眠同时就绪时
/// 的二次守卫。
///
/// **变异锁**：把 `self_run_token_current` 改成恒 `true`（等价于「去抖被删成直接跑」）→ 下方
/// 「只有最后一个 token 当选」转红；把递增去掉（token 恒 0）→ 同样转红。
#[test]
fn self_run_debounce_coalesces_burst_of_invalidates() {
    let rt = runtime();
    let sink = RecordingSink::default();

    // 模拟起代理风暴：起核就绪 + 热切换 + 切节点连发三条 invalidate（真机上落在同一 1500ms 窗内）。
    for _ in 0..3 {
        rt.invalidate(&sink, true, false);
    }
    let tokens = sink.self_runs();
    assert_eq!(
        tokens.len(),
        3,
        "三次 invalidate 各排一轮（排程廉价，合并发生在到点复核）"
    );

    let survivors: Vec<u64> = tokens
        .iter()
        .copied()
        .filter(|t| rt.self_run_token_current(*t))
        .collect();
    assert_eq!(
        survivors,
        vec![*tokens.last().unwrap()],
        "去抖合并：只有最后一次 invalidate 排的那一轮真正开跑，其余到点让位"
    );
}

#[tokio::test]
async fn self_run_task_slot_aborts_old_and_rejects_late_stale_install() {
    let rt = runtime();
    rt.self_run_seq.store(1, Ordering::SeqCst);
    let old = tokio::spawn(std::future::pending::<()>());
    rt.install_self_run_task(1, old.abort_handle());

    rt.self_run_seq.store(2, Ordering::SeqCst);
    let newest = tokio::spawn(std::future::pending::<()>());
    rt.install_self_run_task(2, newest.abort_handle());
    assert!(old.await.unwrap_err().is_cancelled());

    // 模拟 token=1 的 schedule 乱序到达：必须取消自己，不能反向 abort token=2。
    let stale = tokio::spawn(std::future::pending::<()>());
    rt.install_self_run_task(1, stale.abort_handle());
    assert!(stale.await.unwrap_err().is_cancelled());
    assert!(!newest.is_finished());

    drop(rt);
    assert!(newest.await.unwrap_err().is_cancelled());
}

/// **epoch × 去抖的交互**：出口漂移丢弃腿必须**自带**一轮自跑排程，否则「修了触发还是不出终态」。
///
/// 丢弃腿是唯一不 emit UPDATED 的返回路径（`run` 内 `self.invalidate(...)` 后返空快照）。若它不排自跑，
/// 前端就停在检测中等一个永不到来的终态 —— 与本批修的主缺陷同形态，只是触发源不同。
///
/// **变异锁**：把丢弃腿的 `self.invalidate(sink, ...)` 换成只 `bump_epoch()`（不走 invalidate）→
/// `self_runs` 为空 → 转红。
#[tokio::test]
async fn discarded_round_schedules_a_rerun_and_next_round_emits_terminal() {
    let rt = runtime();
    let sink = RecordingSink::default();
    // 轮首 IP-A / 轮尾 IP-B → 归属校验失败 → 丢弃。
    let drift = all_ok_mock().egress_seq(vec![
        ok(200, "ip=1.1.1.1\nloc=US\n"),
        ok(200, "ip=9.9.9.9\nloc=US\n"),
    ]);
    let discarded = rt.run(&drift, &sink, false, || 1_000).await;
    assert!(discarded.checked_at.is_none(), "前提：本轮被丢弃");
    assert!(sink.updated().is_empty(), "前提：丢弃轮不 emit 终态");
    assert_eq!(
        sink.self_runs().len(),
        1,
        "丢弃腿必须排一轮自跑（否则前端永远等不到终态）"
    );
    assert!(
        rt.self_run_token_current(sink.self_runs()[0]),
        "该 token 应是最新 → 到点会真跑"
    );

    // 模拟自跑落地：出口稳定的一轮 → **必须真的 emit 出去**（「让最后一轮真的 emit」）。
    let snap = rt.run(&all_ok_mock(), &sink, false, || 2_000).await;
    assert!(snap.checked_at.is_some(), "重跑轮落终态");
    assert_eq!(
        sink.updated().len(),
        1,
        "重跑轮 emit UPDATED（终态送达前端）"
    );
    assert_eq!(sink.updated()[0].results.len(), ServiceId::ALL.len());
}

// ══════════════════════════════════════════════════════════════════════════════
// T1b · 出口漂移熔断（MAX_CONSECUTIVE_DRIFT）：掐断「丢弃 → 排自跑 → 再丢弃」的无界自持循环
// ══════════════════════════════════════════════════════════════════════════════

/// 出口**每次探测都换 IP** 的 http：轮首/轮尾必然不符 ⇒ **每一轮**都触发漂移丢弃腿。
///
/// 真机对应形态：负载均衡 / urltest / WARP / 多 IP 出口 —— 出口 IP 轮换快过一轮检测。
/// 复用 [`all_ok_mock`] 的 checker 脚本（checker 全 Ok），只接管 egress trace。
struct EverDriftingHttp {
    inner: MockHttp,
    traces: std::sync::atomic::AtomicUsize,
}
impl EverDriftingHttp {
    fn new() -> Self {
        Self {
            inner: all_ok_mock(),
            traces: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}
#[async_trait::async_trait]
impl UnlockHttp for EverDriftingHttp {
    async fn request(&self, req: &UnlockRequest) -> UnlockResponse {
        // 只接管**出口** trace（`cloudflare.com/cdn-cgi/trace`）；checker 自带的
        // `chat.openai.com/cdn-cgi/trace` / `claude.ai/cdn-cgi/trace` 不含 "cloudflare.com"，不误伤。
        if req.url.contains("cloudflare.com/cdn-cgi/trace") {
            let n = self.traces.fetch_add(1, Ordering::SeqCst);
            return ok(200, &format!("ip=10.0.0.{}\nloc=US\n", n + 1));
        }
        self.inner.request(req).await
    }
}

/// **本轮最重要的一条**：出口持续漂移 → 连续 N 轮后熔断，**停止再排程且落终态**。
///
/// 缺陷形态（熔断前）：丢弃腿调 `invalidate` → 排 1500ms 后自跑 → 那一轮重新探测、再次漂移、再次
/// 丢弃 —— 永不收敛。每次迭代是完整 10s 预算的真实网络流量（6 个解锁端点 + 2 次 CF trace），且每次
/// invalidate 广播 `{running:true}` → 前端 `beginUnlockCheck()` ⇒ **UI 永久钉在「检测中」**。
///
/// **变异锁（逐条覆盖逃逸面，非单点 KILL）**：
///  - 删熔断整段（`streak >= MAX_CONSECUTIVE_DRIFT` 分支）→ 第 N 轮照旧丢弃 → ①②③ 三组断言转红；
///  - 把 `drift_streak` 的递增删掉（恒 0）→ 永不触发 → 同上转红；
///  - 在 `invalidate` 里清零 `drift_streak`（丢弃腿自己调 invalidate ⇒ 计数恒为 1）→ 永不触发 → 转红；
///  - 熔断轮漏掉 `sink.updated(&snapshot)` → ① 的「emit UPDATED」转红（UI 仍钉检测中，缺陷未修）；
///  - 熔断轮仍调 `invalidate`（继续排自跑）→ ② 转红（自持循环照旧）；
///  - 熔断快照标上 `egress`（把抖动中的某个 IP 当归属）→ ① 的 `egress.is_none()` 转红（归属不变式破）；
///  - 熔断快照落进 TTL 缓存 → ③ 转红（熔断变永久闩锁，下次真触发也读到垃圾快照）。
#[tokio::test]
async fn drift_circuit_breaker_commits_terminal_and_stops_self_run_loop() {
    let rt = runtime();
    let sink = RecordingSink::default();
    let http = EverDriftingHttp::new();
    // force + 每轮推进 20s：绕开 TTL 快路与 15s 硬下限，让每一轮都真跑到 bracket（本测的射程是
    // bracket 之后的熔断，不该被前面的早退路径挡住）。
    let clock = |round: u64| move || 20_000 * round;

    // ── 前 N-1 轮：照旧丢弃 + 排自跑（漂移多半是瞬态，值得重试；熔断不该提前开火）──
    for round in 1..MAX_CONSECUTIVE_DRIFT {
        let snap = rt.run(&http, &sink, true, clock(round)).await;
        assert!(
            snap.checked_at.is_none(),
            "第 {round} 轮（未到阈值 {MAX_CONSECUTIVE_DRIFT}）应照旧丢弃"
        );
        assert!(sink.updated().is_empty(), "第 {round} 轮不得 emit 终态");
        assert_eq!(
            sink.self_runs().len() as u64,
            round,
            "第 {round} 轮应照旧排一轮自跑（重试仍是对的）"
        );
    }

    // ── 第 N 轮：熔断 ──
    let snap = rt
        .run(&http, &sink, true, clock(MAX_CONSECUTIVE_DRIFT))
        .await;

    // ① 落终态 —— UI 脱离「检测中」的唯一出口。
    assert!(
        snap.checked_at.is_some(),
        "熔断轮必须落终态（否则 UI 永远钉在检测中，缺陷根本没修）"
    );
    assert_eq!(
        snap.results.len(),
        ServiceId::ALL.len(),
        "熔断轮如实带上已测到的结果（测了就是测了）"
    );
    assert_eq!(snap.low_confidence, Some(true), "熔断终态必须标低置信");
    assert!(
        snap.egress.is_none(),
        "归属不变式不得因熔断而破：出口在抖 → 结果不标给任何一个出口"
    );
    assert_eq!(
        sink.updated().len(),
        1,
        "熔断轮必须 emit UPDATED（前端据此收口）"
    );
    assert_eq!(
        sink.updated()[0].checked_at,
        snap.checked_at,
        "emit 出去的与返回的是同一份终态"
    );

    // ② 停止再排程 —— 熔断的核心：掐断自持循环。
    assert_eq!(
        sink.self_runs().len() as u64,
        MAX_CONSECUTIVE_DRIFT - 1,
        "熔断轮不得再排自跑（否则循环照旧无界自持，UI 照旧永钉检测中）"
    );

    // ③ 低置信不入 TTL 缓存 → 下一次真触发照常重检（熔断掐的是循环，不是把检测永久闩死）。
    assert!(
        rt.peek(20_000 * MAX_CONSECUTIVE_DRIFT).is_none(),
        "低置信终态不得入缓存（否则熔断变成 30min 永久闩锁）"
    );

    // ④ 计数已随落定清零：出口恢复稳定的下一轮照常 commit，不受熔断残留影响。
    let stable = rt
        .run(&all_ok_mock(), &sink, true, || {
            20_000 * (MAX_CONSECUTIVE_DRIFT + 1)
        })
        .await;
    assert!(stable.checked_at.is_some(), "熔断后出口转稳 → 照常落终态");
    assert!(stable.egress.is_some(), "出口稳定 → 正常归属");
    assert_eq!(stable.low_confidence, None, "稳定轮不是低置信");
}

/// **间歇漂移不得触发熔断**：漂移被任一次成功 commit 打断后计数清零，「连续 N 轮」按字面算。
///
/// 没有这条，熔断会退化成「累计 N 次漂移就闭嘴」——偶发漂移的健康出口用久了也会被误熔断。
///
/// **变异锁**：删掉 bracket 通过后的 `drift_streak.store(0, ...)` → 三次分散漂移累加到 3 → 末轮
/// 变成熔断轮（`low_confidence==Some(true)` 且 `egress` 为 None）→ 转红。
#[tokio::test]
async fn intermittent_drift_never_trips_the_breaker() {
    let rt = runtime();
    let sink = RecordingSink::default();
    let mut t = 0u64;
    let mut next = || {
        t += 20_000; // 每轮推进 20s：绕 TTL 与 15s 硬下限
        t
    };

    // 漂移 → 稳定 → 漂移 → 漂移 → 稳定：漂移总数 3（= 阈值），但从未**连续** 3 轮。
    for stable in [false, true, false, false, true] {
        let at = next();
        let snap = if stable {
            rt.run(&all_ok_mock(), &sink, true, || at).await
        } else {
            rt.run(&EverDriftingHttp::new(), &sink, true, || at).await
        };
        if stable {
            assert!(snap.checked_at.is_some(), "稳定轮应正常 commit");
            assert!(snap.egress.is_some(), "稳定轮正常归属");
            assert_eq!(snap.low_confidence, None, "稳定轮不是低置信");
        } else {
            assert!(
                snap.checked_at.is_none(),
                "漂移轮应丢弃，而非被误判成熔断终态"
            );
        }
    }
}

/// **#2 · 丢弃腿保留 `last_run_at`** ⇒ force 15s 硬下限在漂移出口上仍然武装。
///
/// 缺陷形态：丢弃腿调**裸** `invalidate` → `last_run_at` 归零 ⇒ force 硬下限的 `last_at != 0` 守卫失效；
/// 且丢弃腿不 emit UPDATED ⇒ 前端 `unlock.lastRunAt` 停在陈旧/null ⇒ `unlockCooldown` 也永不武装。
/// 于是在漂移出口上刷新按钮**两侧都不受限流** —— 恰好是后端已在自跑、对端限频风险最高的时候。
///
/// **变异锁（两处逃逸面各一条）**：
///  - 把 `invalidate_keep_run_at` 换回裸 `self.invalidate(...)` → `last_at==0` → 5s 后的 force 被放行
///    重跑 → `progress_count` 增长 → 转红；
///  - 把 force 硬下限改回「无 `last_snapshot` 就落空放行」（丢弃腿已清 last_snapshot，正是此形态）
///    → 同样放行重跑 → 同一条断言转红。
#[tokio::test]
async fn discard_leg_keeps_force_min_armed() {
    let rt = runtime();
    let sink = RecordingSink::default();
    let drift = all_ok_mock().egress_seq(vec![
        ok(200, "ip=1.1.1.1\nloc=US\n"),
        ok(200, "ip=9.9.9.9\nloc=US\n"),
    ]);

    // 首轮 force：真跑一整轮（就绪门 + 6 checker + 2 trace）后因出口漂移丢弃。
    let discarded = rt.run(&drift, &sink, true, || 10_000).await;
    assert!(discarded.checked_at.is_none(), "前提：本轮被丢弃");
    let after_first = sink.progress_count();
    assert_eq!(
        after_first,
        ServiceId::ALL.len(),
        "前提：本轮真跑过 checker（不是零网络早退）"
    );

    // 5s 后连点 force（<15s）→ 必须被硬下限挡住：**丢弃 ≠ 没跑过网络**。
    rt.run(&all_ok_mock(), &sink, true, || 15_000).await;
    assert_eq!(
        sink.progress_count(),
        after_first,
        "丢弃腿必须保留 lastRunAt 且限流不依赖 last_snapshot：否则漂移出口上刷新钮永不限流"
    );

    // ≥15s 后照常放行 —— 保留 lastRunAt 只是不清零，不是把闸门焊死。
    rt.run(&all_ok_mock(), &sink, true, || 10_000 + FORCE_MIN_MS)
        .await;
    assert_eq!(
        sink.progress_count(),
        after_first * 2,
        "≥15s 照常放行重跑（闸门是限流，不是熔断）"
    );
}

// ══════════════════════════════════════════════════════════════════════════════
// T2 · 整轮 deadline（10s，就绪门 + 主轮 + settle-retry 共享）
// ══════════════════════════════════════════════════════════════════════════════

/// **deadline 截断就绪门**：egress 恒探不到时，默认 10s 预算在第 5 攻越界收口，**不跑满 7 攻 19.6s**。
///
/// 算术（`start_paused` 虚拟时钟，mock 探测零耗时）：attempt0 @0 → 1 @1.2s → 2 @2.4s → 3 @3.6s →
/// 4 @7.6s；attempt5 需再退避 4s（7.6+4=11.6s ≥ 10s）⇒ 停。共 **5** 次探测。
///
/// **变异锁**：删 deadline（`probe_ready` 里去掉两处 deadline 判）→ 跑满 7 攻 → 计数与耗时双双转红。
#[tokio::test(start_paused = true)]
async fn round_deadline_truncates_readiness_gate() {
    let rt = runtime();
    let sink = RecordingSink::default();
    let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let c2 = count.clone();
    let http = MockHttp::new().egress_seq(vec![ok(503, "")]).hook(move || {
        c2.fetch_add(1, Ordering::SeqCst);
    });

    let t0 = tokio::time::Instant::now();
    let snap = rt.run(&http, &sink, false, || 1_000).await;
    let elapsed = t0.elapsed();

    assert_eq!(
        count.load(Ordering::SeqCst),
        5,
        "10s 预算下就绪门在第 5 攻越界收口（不空等到 19.6s）"
    );
    assert!(
        elapsed < Duration::from_millis(TOTAL_DETECTION_BUDGET_MS),
        "整轮不得超过 deadline（实测 {elapsed:?}）"
    );
    // **deadline 到点写终态**，不是撒手不管。
    assert_eq!(
        snap.not_ready,
        Some(true),
        "预算耗尽 → notReady 终态（不留检测中挂着）"
    );
    assert_eq!(sink.updated().len(), 1, "终态必须 emit（前端据此复位）");
}

/// **deadline 到点写终态（核心）**：所有 checker 卡死远超预算 → 整轮在 deadline 处收口，
/// **六项全部落 `Timeout` 终态**、快照照常 commit + emit —— 绝不留 `Checking` 挂着。
///
/// 这条正面锁住用户报的症状：「一直在检测中没有最终结果」。
///
/// **变异锁**（假绿形态）：
/// - 把 `run_checkers_budgeted` 的 `timeout_at(cap, …)` 改回 `timeout(CHECKER_BUDGET_MS, …)`
///   → 耗时 15s+ → `elapsed` 断言转红；
/// - deadline 到点直接 `return` 不 commit → `updated` 为空 + `results` 不足 6 → 转红。
#[tokio::test(start_paused = true)]
async fn round_deadline_writes_terminal_results_never_leaves_checking() {
    /// egress trace 秒回（就绪门立刻过），其余 checker 全部卡死远超整轮预算。
    struct AllHang;
    #[async_trait::async_trait]
    impl UnlockHttp for AllHang {
        async fn request(&self, req: &UnlockRequest) -> UnlockResponse {
            if req.url.contains("cloudflare.com/cdn-cgi/trace") {
                return ok(200, "ip=1.1.1.1\nloc=US\n");
            }
            tokio::time::sleep(Duration::from_secs(600)).await;
            ok(200, "{}")
        }
    }
    let rt = runtime();
    let sink = RecordingSink::default();

    let t0 = tokio::time::Instant::now();
    let snap = rt.run(&AllHang, &sink, false, || 1_000).await;
    let elapsed = t0.elapsed();

    assert_eq!(
        snap.results.len(),
        ServiceId::ALL.len(),
        "六项都要有终态（不缺席）"
    );
    for (id, r) in &snap.results {
        assert_eq!(
            r.status,
            UnlockStatus::Timeout,
            "service {id} 必须落 Timeout 终态，绝不停在 Checking"
        );
    }
    assert_eq!(
        sink.updated().len(),
        1,
        "deadline 到点仍 commit + emit 终态快照"
    );
    // 上限 = deadline + MIN_OP_BUDGET_MS（轮尾确认探的 floor）+ 少量调度余量。
    assert!(
        elapsed < Duration::from_millis(TOTAL_DETECTION_BUDGET_MS + 2 * MIN_OP_BUDGET_MS),
        "整轮须在 deadline(+MIN_OP floor) 内收口，实测 {elapsed:?}（无 deadline 时单 checker 就要 15s）"
    );
}

/// **deadline 不误伤健康轮**：预算充裕时行为与加 deadline 前逐项一致（全 Ok、正常 commit、入缓存）。
/// 防「为了限时把正常路径也砍了」的过度修复。
#[tokio::test]
async fn round_deadline_does_not_affect_fast_healthy_round() {
    let rt = runtime();
    let sink = RecordingSink::default();
    let snap = rt.run(&all_ok_mock(), &sink, false, || 1_000).await;
    assert_eq!(snap.results.len(), ServiceId::ALL.len());
    assert!(snap.results.values().all(|r| r.status == UnlockStatus::Ok));
    assert!(rt.peek(1_000).is_some(), "健康轮照常入缓存");
}
