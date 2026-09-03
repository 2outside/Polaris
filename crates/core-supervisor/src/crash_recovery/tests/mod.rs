#![allow(clippy::too_many_lines)]

use super::*;

const NOW: u64 = 1_000_000; // 任意 epoch ms 基线。

#[test]
fn backoff_table_matches_polaris_constants() {
    // #5：第 1 次 2s / 第 2 次 5s / 第 3 次 15s（:5968）。
    assert_eq!(restart_backoff_ms(1), 2_000);
    assert_eq!(restart_backoff_ms(2), 5_000);
    assert_eq!(restart_backoff_ms(3), 15_000);
    // 第 4 次（若 max 调高）仍 15s（capped）。
    assert_eq!(restart_backoff_ms(4), 15_000);
    // 无效 0 → 兜底 15s（match _）。
    assert_eq!(restart_backoff_ms(0), 15_000);
}

#[test]
fn dedup_second_crash_during_inflight_returns_dedup() {
    // #5：进程 exit 事件与健康检查双触发 → 只跑一次。
    let mut m = CrashRecoveryMachine::default();
    let r1 = m.attempt_crash(NOW, 1);
    let AutoRestartOutcome::Attempt { attempt, .. } = r1 else {
        panic!("expected Attempt, got {r1:?}")
    };
    assert_eq!(attempt, 1);
    assert!(m.is_restarting());

    // 第二次触发：dedup。
    let r2 = m.attempt_crash(NOW, 1);
    assert_eq!(r2, AutoRestartOutcome::Dedup);
    assert!(m.is_restarting()); // 仍在途
}

#[test]
fn aborted_by_user_short_circuits_before_attempt() {
    // M-3：用户已停 → 终态，不起核。auto_restart_aborted 保持置位直到新 start 复位
    // （Polaris finalizeUserAbortedRestart 不清该标志；由下次 start() 入口 reset）。
    let mut m = CrashRecoveryMachine::default();
    m.mark_user_aborted();
    assert!(m.auto_restart_aborted());
    let r = m.attempt_crash(NOW, 1);
    assert_eq!(r, AutoRestartOutcome::AbortedByUser);
    assert!(!m.is_restarting());
    // 标志保持（仅 reset_user_aborted / 新 start 复位）。
    assert!(m.auto_restart_aborted());

    // 后续崩溃仍走 AbortedByUser（不重启）。
    let r2 = m.attempt_crash(NOW, 1);
    assert_eq!(r2, AutoRestartOutcome::AbortedByUser);

    // 新 start 复位后恢复自动重启。
    m.reset_user_aborted();
    assert!(!m.auto_restart_aborted());
    let r3 = m.attempt_crash(NOW, 1);
    assert!(matches!(r3, AutoRestartOutcome::Attempt { .. }));
}

#[test]
fn give_up_when_disabled() {
    let cfg = CrashRecoveryConfig {
        auto_restart_enabled: false,
        ..CrashRecoveryConfig::default()
    };
    let mut m = CrashRecoveryMachine::new(cfg);
    let r = m.attempt_crash(NOW, 1);
    assert_eq!(r, AutoRestartOutcome::GiveUp);
}

#[test]
fn give_up_when_suppressed_during_core_update_window() {
    // :5893 核心更新待验证窗口内禁止自动重启。
    let cfg = CrashRecoveryConfig {
        auto_restart_suppressed: true,
        ..CrashRecoveryConfig::default()
    };
    let mut m = CrashRecoveryMachine::new(cfg);
    let r = m.attempt_crash(NOW, 1);
    assert_eq!(r, AutoRestartOutcome::GiveUp);
}

/// ⚠️ 上面那条测试**绕过了写入口**（直接造 `auto_restart_suppressed: true` 的 config），
/// 所以在「全仓没有任何生产代码能置起这个位」的整段时期里它照样绿 —— 它验的是判据，
/// 不是「这条腿真的能被打开」。本条走 [`CrashRecoveryMachine::set_auto_restart_suppressed`]
/// 这个真实写入口，且验来回两个方向。
#[test]
fn suppression_toggles_through_the_real_setter() {
    // 每次崩溃后必须把在途重启腿收尾（post_backoff + post_start），否则 `is_restarting`
    // 仍为真，下一次 attempt_crash 会先命中幂等去重返回 Dedup、**根本到不了**
    // should_auto_restart —— 抑制位是否生效就无从断言。
    fn crash_and_settle(m: &mut CrashRecoveryMachine) -> AutoRestartOutcome {
        let outcome = m.attempt_crash(NOW, 1);
        if let AutoRestartOutcome::Attempt { generation, .. } = outcome {
            assert!(matches!(m.post_backoff(generation, 1), RestartFate::Start));
            let _ = m.post_start(false);
        }
        outcome
    }

    let mut m = CrashRecoveryMachine::default();
    assert!(!m.auto_restart_suppressed(), "默认不抑制");
    assert!(
        matches!(crash_and_settle(&mut m), AutoRestartOutcome::Attempt { .. }),
        "未抑制时崩溃应走自愈重启"
    );

    // 置起 → 下一次崩溃必须 GiveUp（不再退避空转 3 次把首次失败信号淹掉）。
    m.set_auto_restart_suppressed(true);
    assert!(m.auto_restart_suppressed());
    assert_eq!(crash_and_settle(&mut m), AutoRestartOutcome::GiveUp);

    // 撤下 → 自愈能力必须完整回来（回滚回去的老核要照常受崩溃保护）。
    m.set_auto_restart_suppressed(false);
    assert!(!m.auto_restart_suppressed());
    assert!(
        matches!(crash_and_settle(&mut m), AutoRestartOutcome::Attempt { .. }),
        "撤下抑制后自愈必须恢复，否则回滚回去的老核将失去崩溃保护"
    );
}

#[test]
fn max_restart_count_enforced_across_attempts() {
    // #5：达 MAX_RESTART_COUNT=3 后 GiveUp。
    let mut m = CrashRecoveryMachine::default();
    let gen = 1u64;
    for expected_attempt in 1..=3 {
        let r = m.attempt_crash(NOW, gen);
        let AutoRestartOutcome::Attempt { attempt, .. } = r else {
            panic!("attempt {expected_attempt}: expected Attempt, got {r:?}")
        };
        assert_eq!(attempt, expected_attempt);
        // 模拟 start 失败 → Retry（除最后一次）。
        let fate = m.post_start_failure(false);
        if expected_attempt < 3 {
            assert_eq!(fate, FailureOutcome::Retry);
        } else {
            assert_eq!(fate, FailureOutcome::GiveUp); // 达上限
        }
    }
    // 第 4 次崩溃 → GiveUp（计数已到 3）。
    let r = m.attempt_crash(NOW, gen);
    assert_eq!(r, AutoRestartOutcome::GiveUp);
}

#[test]
fn cooldown_resets_restart_count() {
    // #5：距上次重启超 cooldown(60s) → 复位 restart_count。
    let mut m = CrashRecoveryMachine::default();
    m.attempt_crash(NOW, 1);
    m.post_start_failure(false); // Retry → is_restarting 复位
    assert_eq!(m.restart_count(), 1);

    // 60s+ 后 → should_auto_restart 复位计数。
    let later = NOW + 61_000;
    assert!(m.should_auto_restart(later));
    assert_eq!(m.restart_count(), 0); // 已复位
}

#[test]
fn post_backoff_aborted_by_user_after_grace() {
    // M-3：退避期间用户停止 → 放弃。
    let mut m = CrashRecoveryMachine::default();
    let r = m.attempt_crash(NOW, 5);
    let AutoRestartOutcome::Attempt { generation, .. } = r else {
        panic!("expected Attempt")
    };
    // 退避期间用户停。
    m.mark_user_aborted();
    let fate = m.post_backoff(generation, 5);
    assert_eq!(fate, RestartFate::AbortedByUser);
    assert!(!m.is_restarting());
}

#[test]
fn post_backoff_superseded_no_replay_when_clean_takeover() {
    // M-2′：退避期间被 start 接管（generation 变化）→ 让位，无崩溃则不补发。
    let mut m = CrashRecoveryMachine::default();
    let r = m.attempt_crash(NOW, 5);
    let AutoRestartOutcome::Attempt { generation, .. } = r else {
        panic!("expected Attempt")
    };
    // 接管：generation 已变（用户手动 start）。
    let fate = m.post_backoff(generation, 6);
    assert_eq!(fate, RestartFate::Superseded { replay: false });
    assert!(!m.is_restarting());
}

#[test]
fn post_backoff_superseded_replays_when_takeover_session_crashed() {
    // #6 M-2′-G1：接管 start 在退避期内崩溃 → crash_while_superseded 置位 → 补发。
    let mut m = CrashRecoveryMachine::default();
    // 第一条腿：attempt 起核（gen=5）。
    let r = m.attempt_crash(NOW, 5);
    let AutoRestartOutcome::Attempt {
        generation: my_gen, ..
    } = r
    else {
        panic!("expected Attempt")
    };
    assert_eq!(my_gen, 5);

    // 退避期内：接管 start 发生（generation 变 6），且接管会话崩溃。
    // handle_crash 检测到在途腿（gen=5）已被接管（current=6）→ 置 crash_while_superseded。
    m.handle_crash(NOW + 100, 6, Some(my_gen));
    assert!(m.is_restarting()); // 第一条腿仍在退避中（dedup 吞掉本次崩溃）

    // 第一条腿退避完 → post_backoff 判 supersede + replay=true。
    let fate = m.post_backoff(my_gen, 6);
    assert_eq!(fate, RestartFate::Superseded { replay: true });
    assert!(!m.is_restarting());
}

#[test]
fn replay_double_guard_generation_and_core_running() {
    // #6：补发前 schedGen + refs 双守卫（:6004-6008）。
    let m = CrashRecoveryMachine::default();
    let sched_gen = 6u64;
    // 世代未变 + 核未起来 → 可补发。
    assert!(m.should_replay_crash(sched_gen, 6, false));
    // 世代已变（又被接管）→ 不补。
    assert!(!m.should_replay_crash(sched_gen, 7, false));
    // 核已起来 → 不补。
    assert!(!m.should_replay_crash(sched_gen, 6, true));
}

#[test]
fn post_start_superseded_does_not_report_success() {
    // #5：start 后 lastStartSuperseded=true → 直接退场，不报成功（:6021）。
    let mut m = CrashRecoveryMachine::default();
    m.attempt_crash(NOW, 1);
    let out = m.post_start(true);
    assert_eq!(out, PostStartOutcome::Superseded);
    assert!(!m.is_restarting());
}

#[test]
fn post_start_restarted_reports_success() {
    let mut m = CrashRecoveryMachine::default();
    m.attempt_crash(NOW, 1);
    let out = m.post_start(false);
    assert_eq!(out, PostStartOutcome::Restarted);
    assert!(!m.is_restarting());
}

#[test]
fn post_start_failure_unrecoverable_gives_up_immediately() {
    // :6043：不可恢复错误 → 立即终态（即使未达上限）。
    let mut m = CrashRecoveryMachine::default();
    m.attempt_crash(NOW, 1);
    let fate = m.post_start_failure(true);
    assert_eq!(fate, FailureOutcome::GiveUp);
}

#[test]
fn can_retry_only_when_not_inflight_and_under_max() {
    let mut m = CrashRecoveryMachine::default();
    assert!(m.can_retry());
    m.attempt_crash(NOW, 1);
    assert!(!m.can_retry()); // in-flight
    m.post_start_failure(false);
    assert!(m.can_retry());
}

#[test]
fn restarting_gen_getter_exposes_inflight_generation() {
    // M-2′-G1 补发依赖本 getter 返回真实在途世代（此前无 getter → 上层硬编码 None）。
    let mut m = CrashRecoveryMachine::default();
    // 无在途腿 → None（供 handle_crash 判「无接管、不补发」）。
    assert_eq!(m.restarting_gen(), None);
    // 进入 attempt（gen=5）→ 暴露 Some(5)。
    let _ = m.attempt_crash(NOW, 5);
    assert!(m.is_restarting());
    assert_eq!(m.restarting_gen(), Some(5));
    // in-flight 结束（post_start_failure Retry → finalize_inflight）→ 复位 None。
    let _ = m.post_start_failure(false);
    assert!(!m.is_restarting());
    assert_eq!(m.restarting_gen(), None);
}

#[test]
fn handle_crash_with_no_inflight_does_not_set_replay_flag() {
    // 无在途腿时崩溃 → 不触 crash_while_superseded（语义：仅「接管会话死」才补发）。
    let mut m = CrashRecoveryMachine::default();
    let r = m.handle_crash(NOW, 5, None);
    // 无在途腿 → 直接进 attempt（非 dedup）。
    assert!(matches!(r, AutoRestartOutcome::Attempt { .. }));
}

#[test]
fn handle_crash_inflight_same_generation_does_not_set_replay() {
    // 在途腿与崩溃同代（未接管）→ 不置 crash_while_superseded（正常重入，dedup 吞掉）。
    let mut m = CrashRecoveryMachine::default();
    m.attempt_crash(NOW, 5); // 在途腿 gen=5
    let r = m.handle_crash(NOW + 50, 5, Some(5)); // 同代崩溃
    assert_eq!(r, AutoRestartOutcome::Dedup);
}

#[test]
fn finalize_for_stop_clears_all_inflight_state() {
    let mut m = CrashRecoveryMachine::default();
    m.attempt_crash(NOW, 1);
    m.mark_user_aborted();
    m.finalize_for_stop();
    assert!(!m.is_restarting());
    assert!(!m.auto_restart_aborted());
}

#[test]
fn reset_user_aborted_allows_takeover_start() {
    // 接管 start 复位 abort（:5993 注释：用户手动 start 会 reset autoRestartAborted 绕过 abort 检查）。
    let mut m = CrashRecoveryMachine::default();
    m.mark_user_aborted();
    assert!(m.auto_restart_aborted());
    m.reset_user_aborted();
    let r = m.attempt_crash(NOW, 1);
    assert!(matches!(r, AutoRestartOutcome::Attempt { .. }));
}

// ── classify_child_exit：主动 stop vs 意外崩溃的判据（本任务最易出 bug 处的门）──

#[test]
fn crash_when_generation_unchanged_and_child_exited() {
    // 世代未变 + 句柄仍在 + 进程已退 = 无生命周期操作在飞却死了 → 崩溃。
    assert_eq!(
        classify_child_exit(5, 5, ChildObservation::Exited),
        ExitClassification::Crash
    );
}

#[test]
fn intentional_stop_bumped_generation_is_retire() {
    // **变异门**：stop/restart 入口先 bump 世代（5→6）再杀核；即便观察到进程已退，
    // 世代已变 ⟹ 主动杀核 ⟹ Retire，绝不能判 Crash（否则主动 stop 会触发自愈、与重启打架）。
    assert_eq!(
        classify_child_exit(5, 6, ChildObservation::Exited),
        ExitClassification::Retire
    );
    // 让位（就绪期被接管等）同理。
    assert_eq!(
        classify_child_exit(5, 6, ChildObservation::Alive),
        ExitClassification::Retire
    );
}

#[test]
fn child_handle_taken_is_retire_even_same_generation() {
    // 防御性冗余：句柄被 kill_core 取走 → 主动停止在跑 → Retire（不判崩溃）。
    assert_eq!(
        classify_child_exit(5, 5, ChildObservation::Absent),
        ExitClassification::Retire
    );
}

#[test]
fn healthy_core_keeps_watching() {
    assert_eq!(
        classify_child_exit(5, 5, ChildObservation::Alive),
        ExitClassification::KeepWatching
    );
}

#[test]
fn full_crash_loop_converges_to_giveup_within_max() {
    // 端到端：3 次崩溃均失败 → GiveUp，不无限循环（:6040 limio 修复）。
    let mut m = CrashRecoveryMachine::default();
    for i in 0..5 {
        // 试图 attempt，但第 4 次起应 GiveUp。
        let r = m.attempt_crash(NOW + i * 10, 1);
        if i < 3 {
            assert!(
                matches!(r, AutoRestartOutcome::Attempt { .. }),
                "iter {i}: expected Attempt, got {r:?}"
            );
            m.post_start_failure(false);
        } else {
            assert_eq!(r, AutoRestartOutcome::GiveUp, "iter {i}: expected GiveUp");
        }
    }
}
