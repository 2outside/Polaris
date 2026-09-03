use super::*;

// ── Fix 2：崩溃自愈 supersede-crash 补发（M-2′-G1）传真实在途世代 ──

/// `drive_crash_decision` seam 读回**真实在途世代**喂 handle_crash（非硬编码 None）。
/// 变异（把 seam 里 `m.restarting_gen()` 换回 `None`）→ crash_while_superseded 不置 → replay=false → 转红。
#[test]
fn drive_crash_decision_feeds_real_inflight_gen_for_supersede_replay() {
    const NOW: u64 = 1_000_000;
    let mut m = CrashRecoveryMachine::default();
    // 第一条腿 attempt（gen=5）→ is_restarting + restarting_gen=5。
    let r = drive_crash_decision(&mut m, NOW, 5);
    assert!(matches!(r, AutoRestartOutcome::Attempt { .. }));
    // 接管会话（gen=6）崩溃：seam 读回在途世代 5（≠6）→ 置 crash_while_superseded；本崩溃被 dedup 吞掉。
    let r2 = drive_crash_decision(&mut m, NOW + 1, 6);
    assert_eq!(r2, AutoRestartOutcome::Dedup);
    // 第一条腿退避完 → Superseded{replay:true}（若 seam 传 None 则 replay:false → 断言红）。
    let fate = m.post_backoff(5, 6);
    assert_eq!(fate, RestartFate::Superseded { replay: true });
}

// ── Fix 4：崩溃遇不可恢复错误立即终态判定 ──

#[test]
fn is_unrecoverable_restart_error_classifies_terminal_failures() {
    // 确定性失败 → 终态（不再空耗退避）。
    assert!(is_unrecoverable_restart_message("Permission denied")); // ASCII 大写经小写归一
    assert!(is_unrecoverable_restart_message("提权助手不可用"));
    assert!(is_unrecoverable_restart_message("clash_api 端口被占用"));
    assert!(is_unrecoverable_restart_message("HELPER_GATE_ABORTED"));
    assert!(is_unrecoverable_restart_message("检测到 root 残留孤儿核"));
    // 慢起/瞬态 → 非终态（否则慢起被误判放弃）。
    assert!(!is_unrecoverable_restart_message("sing-box 起核超时"));
    assert!(!is_unrecoverable_restart_message("sing-box 启动期退出"));
}

/// **本缺陷的复现锚**：helper 门的两条终态腿实际落进 `StartError` 的是**中文文案**，而 message
/// 关键字表里一个都不命中 —— 先把这条「keyword 腿看不见它俩」钉死，再断言码腿把它们捞回来。
///
/// 变异有牙（逃逸面穷举）：
/// - 删 `is_unrecoverable_restart_error` 的码腿（`coded_terminal` 恒 `false`）= 退回纯 message
///   匹配 → 下方两条 `assert!(is_unrecoverable_restart_error(..))` **双红**（本缺陷复现）。
/// - 码腿只留 `HELPER_GATE_ABORTED`（漏 `HELPER_NOT_INSTALLED`）→ 第二条红；反之第一条红。
/// - 把两条 `assert!(!is_unrecoverable_restart_message(..))` 的前置删掉 → 无法区分「码腿生效」
///   与「keyword 恰好命中」，测试失去指向性（故保留为前置断言）。
#[test]
fn helper_gate_terminal_codes_are_unrecoverable_though_messages_match_no_keyword() {
    // 前置：两串中文文案对 keyword 腿是**完全不可见**的（缺陷根因）。
    assert!(
        !is_unrecoverable_restart_message(HELPER_GATE_ABORTED_MSG),
        "取消文案不含任何关键词 → 纯 message 匹配判不出终态"
    );
    assert!(
        !is_unrecoverable_restart_message(HELPER_NOT_INSTALLED_MSG),
        "未装文案不含任何关键词（“提权 helper”里没有“权限”）→ 纯 message 匹配判不出终态"
    );

    // 码腿把它们捞回终态：用户亲口取消 / 前置条件缺失，重试多少轮都不会自己变好。
    assert!(
        is_unrecoverable_restart_error(&StartError::coded(
            HELPER_GATE_ABORTED_MSG,
            code::HELPER_GATE_ABORTED
        )),
        "用户取消提权门 → 立即终态，不得再烧退避重试"
    );
    assert!(
        is_unrecoverable_restart_error(&StartError::coded(
            HELPER_NOT_INSTALLED_MSG,
            code::HELPER_NOT_INSTALLED
        )),
        "helper 未装（非交互自愈弹不了引导，每轮必然同样失败）→ 立即终态"
    );
}

/// **反向失效面**：码腿不得「改过头」把瞬态失败也判成终态 —— 那会让慢起/接管期退出的核**一次都
/// 不重试**，比原缺陷更糟（原缺陷只是多烧几轮）。
///
/// 变异有牙：把码腿放宽成 `err.code.is_some()`（任何带码错误即终态）→ 下方 `STARTUP_FAILED`
/// 两条**双红**；把码腿写成 `!matches!(..)` 之类的取反 → 同样红。
#[test]
fn transient_start_failures_remain_retryable_regardless_of_code() {
    for msg in ["sing-box 起核超时", "sing-box 启动期退出"] {
        // 带 STARTUP_FAILED 码的瞬态失败：码腿不认，keyword 腿也不认 → 继续重试。
        assert!(
            !is_unrecoverable_restart_error(&StartError::coded(msg, code::STARTUP_FAILED)),
            "{msg}（STARTUP_FAILED）是瞬态失败，必须仍然重试"
        );
        // 无码腿（`From<String>` 升格，start_inner 里绝大多数失败腿）→ 同样继续重试。
        assert!(
            !is_unrecoverable_restart_error(&StartError::from(msg.to_string())),
            "{msg}（无码）必须仍然重试"
        );
    }
}

/// **keyword 腿不得被码腿挤掉**：spawn launch 失败把**原始 OS 错误**塞进 message 后贴
/// `STARTUP_FAILED`（:1699-1702），EACCES 的 "Permission denied" 正从那儿来。若实现写成
/// 「有码就 `return matches!(code, ..)`、不再看 message」，权限拒绝会退回烧满 3 轮退避。
///
/// 变异有牙：把 `coded_terminal || is_unrecoverable_restart_message(..)` 改成
/// `if let Some(c) = err.code { return c == ...HELPER_GATE_ABORTED || c == ...HELPER_NOT_INSTALLED }`
/// （严格码优先）→ 本测**红**，而上面两测仍绿 ⇒ 只有这条守得住这个逃逸面。
#[test]
fn keyword_leg_still_applies_to_coded_errors() {
    assert!(
        is_unrecoverable_restart_error(&StartError::coded(
            "spawn sing-box 失败：Permission denied (os error 13)",
            code::STARTUP_FAILED
        )),
        "带 STARTUP_FAILED 码的权限拒绝仍须由 keyword 腿判终态（码腿不表达终态性 ≠ 可重试）"
    );
    // 无码的权限拒绝（既有行为）不得被回归破坏。
    assert!(is_unrecoverable_restart_error(&StartError::from(
        "Permission denied".to_string()
    )));
}

#[test]
fn is_retryable_start_error_separates_transient_from_terminal() {
    // 端口/资源竞态 / 起核期退出 → 可重试。
    assert!(is_retryable_start_error("address already in use"));
    assert!(is_retryable_start_error("sing-box 启动期退出"));
    // 权限/找不到/配置无效 → 不重试（确定性失败）。
    assert!(!is_retryable_start_error("Permission denied (EACCES)"));
    assert!(!is_retryable_start_error("ENOENT: no such file"));
    assert!(!is_retryable_start_error("权限不足"));
    assert!(!is_retryable_start_error("invalid config: bad field"));
}

// ══════════════════════════════════════════════════════════════════════════════
// 诊断两轴计数喂数（§O1 缺口修复）——**组合面门**（§K7.1）
//
// 不测「DiagnosticCounters 函数」也不测「proxy 起核」，而是打生产路径的缝：
//   慢起轴：真起就绪门（带真实重试）→ ProxyRuntime 累计 → diagnostic_counters() → build_diagnostic_report 渲染非零行。
//   核崩轴：崩溃自愈机计数 → diagnostic_counters() **投影** → 报告渲染非零行。
// 两轴各自单一来源、绝不互写（维度7 #11：慢起 ≠ 核崩，混为一谈会误报核崩）。
// ══════════════════════════════════════════════════════════════════════════════

/// 用给定两轴计数造一份最小诊断报告（组合面：真调 `build_diagnostic_report`，验证行是否渲染）。
fn report_with_counters(counters: DiagnosticCounters) -> String {
    use polaris_stats_engine::{build_diagnostic_report, DiagnosticReportInput, RuntimeSection};
    let input = DiagnosticReportInput {
        runtime: RuntimeSection {
            counters,
            ..RuntimeSection::default()
        },
        ..DiagnosticReportInput::default()
    };
    build_diagnostic_report(&input)
}

/// 组合面·慢起轴：真起就绪门（带重试）→ 慢起轴真被喂 → 报告读到非零「就绪重试」行。
///
/// 不经真核（无需 sing-box 二进制）：放一个真·存活子进程（`sleep`）满足 `is_alive`，
/// 管理 API 端口在观测到首轮真实失败后才监听 → 至少一次真实重试 → 监听起来后 `Ready`。
/// 全程仅 127.0.0.1，不触碰宿主网络。**变异门**：去掉 `on_retry`→record_retry 接线 → 慢起轴恒 0 → 本测转红。
#[tokio::test(flavor = "multi_thread")]
async fn diagnostic_slow_start_axis_fed_and_rendered() {
    let (rt, _dir) = test_runtime();
    let my_gen = rt.gate.generation();

    // 真·存活子进程当「核」（is_alive 靠它）；用完只杀我们自己起的这个。
    // Windows 无 sleep.exe（sleep 只是 PS cmdlet）→ 按平台选常驻占位进程。
    let mut cmd = if cfg!(windows) {
        let mut c = tokio::process::Command::new("powershell");
        c.args(["-NoProfile", "-Command", "Start-Sleep -Seconds 30"]);
        c
    } else {
        let mut c = tokio::process::Command::new("sleep");
        c.arg("30");
        c
    };
    let child = cmd.spawn().expect("spawn 占位核");
    *rt.child.lock().unwrap() = Some(child);

    // 管理 API 端口：先取空闲口但不监听。把 wait_ready 放到独立任务中，等其 `on_retry` 屏障
    // 明确证明首探已经失败后才 bind。固定 700ms 在 Windows hosted runner 上并不构成先后关系：
    // 占位 PowerShell/任务调度可能更慢，监听器会抢先上线，首探即成功而假红。
    let port = free_port();
    rt.ready_retry_count.store(0, Ordering::SeqCst);
    let wait_rt = Arc::clone(&rt);
    let mut waiter = tokio::spawn(async move {
        wait_rt
            .wait_ready(port, my_gen, CORE_READY_TIMEOUT_FLOOR_MS)
            .await
    });

    let retry_barrier = async {
        while rt.ready_retry_count.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    };
    tokio::pin!(retry_barrier);
    let ended_before_retry = tokio::select! {
        () = &mut retry_barrier => None,
        early = &mut waiter => Some(early.expect("wait_ready 任务不应 panic")),
    };
    if let Some(early) = ended_before_retry {
        rt.kill_core().await.expect("清理占位核应成功");
        panic!("监听器尚未创建，wait_ready 不应先结束：{early:?}");
    }

    // 监听但不 accept：TcpStream::connect 成功即「就绪」。持有到 wait_ready 返回。
    let listener = match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
        Ok(listener) => listener,
        Err(e) => {
            rt.kill_core().await.expect("清理占位核应成功");
            panic!("首轮失败后监听管理端口应成功：{e}");
        }
    };

    let outcome = waiter.await.expect("wait_ready 任务不应 panic");
    drop(listener);
    assert_eq!(outcome, CoreReadyOutcome::Ready, "延迟监听后必最终就绪");

    let counters = rt.diagnostic_counters();
    assert!(
        counters.last_start_ready_retries >= 1,
        "慢起轴必须真被喂（延迟就绪 → ≥1 次重试）；实得 {}",
        counters.last_start_ready_retries
    );

    // 组合面收口：喂进真实报告构建器，断言「就绪重试」行真渲染（非零才渲染）。
    let md = report_with_counters(counters);
    assert!(
        md.contains("次就绪重试才成功"),
        "诊断报告必须渲染慢起轴行（生产路径读到非零）"
    );
    assert!(
        !md.contains("核崩溃自动重启"),
        "无崩溃 → 核崩轴行不应出现（两轴独立）"
    );

    rt.kill_core().await.expect("清理占位核应成功"); // 只杀我们起的 sleep 占位核
}

/// 组合面·核崩轴：`restart_count` 从 [`CrashRecoveryMachine`] **读时投影** → 报告渲染「核崩溃自动重启」行。
///
/// 无需真崩溃：直接驱动崩溃自愈机计数（与 `run_crash_recovery` 同一 `attempt_crash` 入口）。
/// 锁死投影接线（去掉 `diagnostic_counters` 里的投影 → 本测转红），也证明**没有**在本地并行 record_restart
/// （核崩轴的唯一真值就是崩溃机）。
#[test]
fn diagnostic_crash_axis_projected_from_recovery_machine_and_rendered() {
    let (rt, _dir) = test_runtime();

    // 初始两轴皆 0 → 报告无任一行。
    let c0 = rt.diagnostic_counters();
    assert_eq!(c0.restart_count, 0);
    assert_eq!(c0.last_start_ready_retries, 0);
    assert!(!report_with_counters(c0).contains("核崩溃自动重启"));

    // 驱动崩溃自愈机计数两次（真实自愈路径同一 attempt 入口；期间不动慢起轴）。
    let now = now_ms();
    let gen = rt.gate.generation();
    rt.crash_lock().attempt_crash(now, gen); // restart_count=1，in-flight
    rt.crash_lock().post_start_failure(false); // 复位 in-flight，计数保留
    rt.crash_lock().attempt_crash(now, gen); // restart_count=2

    let c = rt.diagnostic_counters();
    assert_eq!(
        c.restart_count, 2,
        "核崩轴必须从 CrashRecoveryMachine 投影进快照（单一真值）"
    );
    assert_eq!(c.last_start_ready_retries, 0, "驱动崩溃机不得污染慢起轴");
    let md = report_with_counters(c);
    assert!(
        md.contains("核崩溃自动重启：2 次"),
        "报告必须渲染核崩轴行（读到非零投影值）"
    );
    assert!(!md.contains("次就绪重试才成功"), "慢起轴 0 → 该行不渲染");
}

/// 组合面·两轴独立同现：慢起轴（`diagnostics`）+ 核崩轴（`crash_recovery`）各自来源，
/// `diagnostic_counters()` 合并后两行都渲染，且互不写入对方（维度7 #11 两轴不混）。
#[test]
fn diagnostic_two_axes_combine_independently_in_snapshot() {
    let (rt, _dir) = test_runtime();

    // 慢起轴：喂 2 次就绪重试（与 wait_ready 同一 begin/record/finish API）。
    {
        let mut a = rt.diag_lock().begin_start();
        a.record_retry();
        a.record_retry();
        rt.diag_lock().finish_start(&a);
    }
    // 核崩轴：崩溃自愈机计数 1 次。
    rt.crash_lock()
        .attempt_crash(now_ms(), rt.gate.generation());

    let c = rt.diagnostic_counters();
    assert_eq!(c.last_start_ready_retries, 2, "慢起轴来自 diagnostics");
    assert_eq!(c.restart_count, 1, "核崩轴来自 crash_recovery（投影）");

    let md = report_with_counters(c);
    assert!(md.contains("2 次就绪重试才成功"), "慢起轴行");
    assert!(md.contains("核崩溃自动重启：1 次"), "核崩轴行");
}

/// ⑦ 崩溃自愈：`kill -9` 掉核（模拟崩溃）→ 世代未变 → 崩溃监测检出 → 退避后自愈重启（ps 实证新 pid）。
#[tokio::test(flavor = "multi_thread")]
#[ignore = "真机验证：需 POLARIS_SINGBOX_PATH 指向真实 sing-box；非 CI 门"]
async fn real_core_crash_triggers_auto_restart() {
    let _real_core_guard = lock_real_core_tests().await;
    let (rt, dir, _core) = real_core_runtime();
    crate::logging::init(&dir);
    let mixed = free_port();
    // 直接传 config 给 start（不经 save_full：其 validate 要求 tunConfig，而 manual+direct 用不到；
    // start 的 from_value::<UserConfig> 里 tun_config 是 Option → 缺省即可。崩溃自愈重启读 current_config
    // （start 就绪时已置），无需磁盘配置）。
    let st = rt
        .start(local_only_config(mixed))
        .await
        .expect("起核应成功");
    let pid1 = st.pid;
    assert!(ps_alive(pid1), "[⑦] 起核后 pid={pid1} 应在跑");
    println!("[⑦] 起核 pid={pid1}");

    // 模拟崩溃：SIGKILL（绕过 rt.stop → 世代不变 → 崩溃监测判为**意外**退出）。
    send_signal(pid1, Signal::Sigkill);
    println!("[⑦] 已 SIGKILL pid={pid1}（模拟崩溃），等待自愈重启...");

    // 检出（≤1s）+ 退避（第 1 次 2s）+ 起核就绪 → 20s 内必换出新 pid。
    let pid2 = wait_pid_change(&rt, pid1, 20)
        .await
        .expect("[⑦] 崩溃后必须自愈重启并换出新 pid（自愈未生效）");
    assert_ne!(pid2, pid1, "[⑦] 自愈后必须是新进程");
    assert!(ps_alive(pid2), "[⑦] 自愈重启的新核必须在跑（ps 实证）");
    assert!(rt.status().running, "[⑦] 自愈后 status 必须 running");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !ps_alive(pid1),
        "[⑦] 崩溃的旧核 pid={pid1} 必须已被收割（无僵尸/孤儿）"
    );
    println!("[⑦] 崩溃自愈生效：pid {pid1} → {pid2}，旧核已收割 ✓");

    rt.stop().await.expect("停核应成功");
}

/// ⑦b 真机·核崩轴：真核崩溃 → 自愈重启 → `diagnostic_counters().restart_count` 非零 →
/// 诊断报告渲染「核崩溃自动重启」行（§O1 组合面在真核上再实证一次）。
#[tokio::test(flavor = "multi_thread")]
#[ignore = "真机验证：需 POLARIS_SINGBOX_PATH 指向真实 sing-box；非 CI 门"]
async fn real_core_crash_feeds_diagnostic_restart_axis() {
    let _real_core_guard = lock_real_core_tests().await;
    let (rt, dir, _core) = real_core_runtime();
    crate::logging::init(&dir);
    let mixed = free_port();

    let st = rt
        .start(local_only_config(mixed))
        .await
        .expect("起核应成功");
    let pid1 = st.pid;
    // 崩溃前核崩轴应为 0（尚无崩溃）。
    assert_eq!(
        rt.diagnostic_counters().restart_count,
        0,
        "[⑦b] 起核后未崩溃 → 核崩轴应为 0"
    );

    send_signal(pid1, Signal::Sigkill); // 模拟崩溃（世代不变 → 判为意外退出）
    let pid2 = wait_pid_change(&rt, pid1, 20)
        .await
        .expect("[⑦b] 崩溃后必须自愈重启");
    assert_ne!(pid2, pid1);

    // 自愈重启后：核崩轴（从 CrashRecoveryMachine 投影）必非零。
    let counters = rt.diagnostic_counters();
    assert!(
        counters.restart_count >= 1,
        "[⑦b] 真核崩溃自愈后核崩轴必非零；实得 {}",
        counters.restart_count
    );

    // 组合面：喂进真实报告构建器，断言「核崩溃自动重启」行真渲染。
    let md = report_with_counters(counters);
    assert!(
        md.contains("核崩溃自动重启"),
        "[⑦b] 诊断报告必须渲染核崩轴行（真核崩溃 → 非零）"
    );
    println!(
        "[⑦b] 真核崩溃自愈 → restart_count={} → 报告核崩轴行已渲染 ✓",
        counters.restart_count
    );

    rt.stop().await.expect("停核应成功");
}

/// ⑧ 主动 stop → **不**触发自愈（ps 实证无重启）。这是崩溃自愈最易出的 bug：把主动杀核当崩溃。
///
/// 变异对照：若把「主动 stop」也当崩溃（去掉世代判据），则 stop 后 status 会被自愈拉回 running。
/// 单测 `classify_child_exit` 的 `intentional_stop_bumped_generation_is_retire` 已在 CI 层锁死此判据，
/// 本条在真机层再实证一次。
#[tokio::test(flavor = "multi_thread")]
#[ignore = "真机验证：需 POLARIS_SINGBOX_PATH 指向真实 sing-box；非 CI 门"]
async fn real_core_intentional_stop_does_not_restart() {
    let _real_core_guard = lock_real_core_tests().await;
    let (rt, dir, _core) = real_core_runtime();
    crate::logging::init(&dir);
    let mixed = free_port();
    // 直接传 config 给 start（不经 save_full：其 validate 要求 tunConfig，而 manual+direct 用不到；
    // start 的 from_value::<UserConfig> 里 tun_config 是 Option → 缺省即可。崩溃自愈重启读 current_config
    // （start 就绪时已置），无需磁盘配置）。
    let st = rt
        .start(local_only_config(mixed))
        .await
        .expect("起核应成功");
    let pid1 = st.pid;
    assert!(ps_alive(pid1), "[⑧] 起核后 pid={pid1} 应在跑");
    println!("[⑧] 起核 pid={pid1}");

    // 主动 stop：入口先 bump 世代再杀核 → 崩溃监测应 Retire（不触发自愈）。
    rt.stop().await.expect("停核应成功");
    assert!(!rt.status().running, "[⑧] stop 后 running 必须为 false");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!ps_alive(pid1), "[⑧] stop 后旧核 pid={pid1} 必须退出");

    // 关键：等足够久（超过 poll 1s + 退避 2s + 余量）确认**绝无**自愈重启。
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(
        !rt.status().running,
        "[⑧] 主动 stop 绝不能触发崩溃自愈（status 必须仍未运行）—— 世代判据失效即此处转红"
    );
    assert_eq!(rt.status().pid, 0, "[⑧] 主动 stop 后不得有任何新核 pid");
    println!("[⑧] 主动 stop 后 5s 无任何重启（status 未运行）→ 世代判据正确 ✓");
}

/// ⑨ 超阈值崩溃 → 放弃自愈并报错，**绝不无限重启**。
///
/// `MAX_RESTART_COUNT=3` / 60s 冷却：连续崩溃 3 次自愈成功，第 4 次崩溃 → `GiveUp` → 置 error、不再重启。
#[tokio::test(flavor = "multi_thread")]
#[ignore = "真机验证：需 POLARIS_SINGBOX_PATH 指向真实 sing-box；非 CI 门（含 2+5+15s 退避，耗时较长）"]
async fn real_core_crash_loop_gives_up_without_infinite_restart() {
    let _real_core_guard = lock_real_core_tests().await;
    let (rt, dir, _core) = real_core_runtime();
    crate::logging::init(&dir);
    let mixed = free_port();
    // 直接传 config 给 start（不经 save_full：其 validate 要求 tunConfig，而 manual+direct 用不到；
    // start 的 from_value::<UserConfig> 里 tun_config 是 Option → 缺省即可。崩溃自愈重启读 current_config
    // （start 就绪时已置），无需磁盘配置）。
    let st = rt
        .start(local_only_config(mixed))
        .await
        .expect("起核应成功");
    let mut pid = st.pid;
    println!("[⑨] 起核 pid={pid}");

    // 崩溃 3 次，每次都应自愈（退避 2s/5s/15s）。
    for i in 1..=3 {
        send_signal(pid, Signal::Sigkill);
        let next = wait_pid_change(&rt, pid, 30)
            .await
            .unwrap_or_else(|| panic!("[⑨] 第 {i} 次崩溃应自愈换出新 pid"));
        println!("[⑨] 第 {i} 次崩溃自愈：pid {pid} → {next}");
        pid = next;
        // 让新核稳定一小会儿（但远小于 60s 冷却，确保计数不复位）。
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    // 第 4 次崩溃 → 达上限 → 放弃自愈（不再换 pid）。
    send_signal(pid, Signal::Sigkill);
    println!("[⑨] 第 4 次 SIGKILL pid={pid}，应放弃自愈（不无限重启）...");
    let extra = wait_pid_change(&rt, pid, 8).await;
    assert!(
        extra.is_none(),
        "[⑨] 第 4 次崩溃必须放弃自愈，绝不无限重启（实得新 pid {extra:?}）"
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!ps_alive(pid), "[⑨] 第 4 次崩溃的核已死、无自愈");
    assert!(
        rt.status().error.is_some(),
        "[⑨] 放弃自愈必须置 error 供 UI 上报（实得 {:?}）",
        rt.status()
    );
    println!(
        "[⑨] 第 4 次崩溃已放弃自愈，error={:?}，未无限重启 ✓",
        rt.status().error
    );
}

// ── C2：崩溃自愈 GiveUp 腿不得在已有更具体终态码时叠发 AUTO_RESTART_FAILED ──
//
// 断言的是**发射条数**（缺陷的可观测症状本身：前端两码各自 toast.error + notifyDesktop，且
// 崩溃自愈两腿无人 await ⇒ 认领闸门不抑制 ⇒ 用户背靠背吃 2 toast + 2 桌面通知），不是布尔判定。

/// **本缺陷的复现锚**：`run_helper_gate` 非交互腿已 `set_error(HELPER_NOT_INSTALLED)` 发过一条，
/// GiveUp 腿不得再叠一条 `AUTO_RESTART_FAILED`。
///
/// **变异有牙（逃逸面穷举）**：
/// - 删 `report_auto_restart_giveup` 的 `if let Some(code) { return }` 早退（退回无条件 set_error）
///   = **缺陷复现**（双发）→ 三个码族各自 `len()==2` → 转红。
/// - 早退只判 `HELPER_NOT_INSTALLED`（漏 GATE_ABORTED / STARTUP_FAILED）→ 后两轮转红
///   （故此处对**全部三个码族**各跑一轮，而非只钉 helper 一条腿）。
/// - 判据换成回读全局 `status().error_code` → 本测仍绿（状态确实刚落），但那是 A1 陈旧读，
///   由下一条 `..._still_reports_when_no_specific_code` 的无码腿把它钉住：无码腿不写全局，
///   回读拿到的是**上一次**失败的残留码 ⇒ 误判「已播报」⇒ 变静默 ⇒ 那一条转红。
#[test]
fn auto_restart_giveup_does_not_stack_code_when_specific_terminal_already_emitted() {
    for (msg, specific) in [
        (HELPER_NOT_INSTALLED_MSG, code::HELPER_NOT_INSTALLED),
        (HELPER_GATE_ABORTED_MSG, code::HELPER_GATE_ABORTED),
        ("sing-box 启动期退出", code::STARTUP_FAILED),
    ] {
        let (rt, _dir, events) = test_runtime_recording_errors();
        // 失败腿自己那条（`StartError::coded` 构造点恒紧邻的同码 set_error）。
        rt.set_error(msg, specific);
        // 同一个 e 出栈到 GiveUp 腿 → 不得再发第二条。
        rt.report_auto_restart_giveup(&StartError::coded(msg, specific));

        let got = events.lock().unwrap().clone();
        assert_eq!(
            got.len(),
            1,
            "{specific}：GiveUp 腿叠发 AUTO_RESTART_FAILED ⇒ 前端 2 toast + 2 桌面通知（本缺陷）"
        );
        assert_eq!(got[0].1, specific, "留下的必须是**更具体**的那条码");
    }
}

/// **反向失效锁（防修过头）**：无码腿（config 解析/生成/建目录/写盘 —— `From<String>` 升格，
/// 自身**从不** set_error）放弃时**必须**发 `AUTO_RESTART_FAILED`，否则前端一条提示都收不到。
///
/// **变异有牙**：
/// - `report_auto_restart_giveup` 改成无条件早退（“修过头”）→ 零发射 → 转红（变静默）。
/// - 早退条件写反（`e.code.is_none()` 时早退）→ 本条 + 上一条**双红**。
/// - 发错码（如沿用 STARTUP_FAILED）→ 码断言转红。
/// - 丢掉原始错因（只发一句固定文案）→ message 包含断言转红：放弃时用户至少得看到**为什么**。
#[test]
fn auto_restart_giveup_still_reports_when_no_specific_code() {
    let (rt, _dir, events) = test_runtime_recording_errors();
    // 无码腿：`From<String> for StartError` → code == None，且这条腿此前没有任何 set_error。
    rt.report_auto_restart_giveup(&StartError::from(
        "生成 sing-box 配置失败：invalid json".to_string(),
    ));

    let got = events.lock().unwrap().clone();
    assert_eq!(
        got.len(),
        1,
        "无更具体的码时仍不发 ⇒ 崩溃自愈放弃全静默（比双报更坏）"
    );
    assert_eq!(got[0].1, code::AUTO_RESTART_FAILED);
    assert!(
        got[0].0.contains("invalid json"),
        "终态播报须带上原始错因，否则用户只知道“放弃了”不知道为什么：{}",
        got[0].0
    );
}
