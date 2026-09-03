#![allow(clippy::too_many_lines)]

use super::*;

#[test]
fn begin_end_pairs_track_depth_and_busy() {
    let g = LifecycleGate::default();
    assert!(!g.is_busy());
    assert_eq!(g.depth(), 0);

    g.begin();
    assert!(g.is_busy());
    assert_eq!(g.depth(), 1);

    // restart 内嵌 stop+start：depth 到 2（:1519-1521 重入语义）。
    g.begin();
    assert_eq!(g.depth(), 2);
    assert!(g.is_busy());

    // 内层 end：depth=1，StillBusy，不排空。
    let r = g.end(LifecycleKind::Start);
    assert!(matches!(r, LifecycleEndResult::StillBusy(1)));
    assert!(g.is_busy());

    // 外层 end：depth=0，Drained（无 pending）。
    let r = g.end(LifecycleKind::Restart);
    assert!(matches!(r, LifecycleEndResult::Drained(_)));
    assert!(!g.is_busy());
    assert_eq!(g.depth(), 0);
}

#[test]
fn end_clamps_depth_at_zero_on_unbalanced_call() {
    // end 不配对 begin（防御）：clamp 0 不下溢（:1534 Math.max(0, depth-1)）。
    let g = LifecycleGate::default();
    let r = g.end(LifecycleKind::Stop);
    assert!(matches!(r, LifecycleEndResult::Stopped(_)));
    assert_eq!(g.depth(), 0);
}

#[test]
fn stop_terminal_discards_all_three_pending_axes() {
    // #1：kind=Stop depth 归 0 → 必须丢弃全部三个 pending（停止优先，:1536-1540）。
    let g = LifecycleGate::default();
    g.set_restart_pending();
    g.set_force_restart(42);
    g.set_switch_pending(7);

    g.begin();
    let r = g.end(LifecycleKind::Stop);
    let LifecycleEndResult::Stopped(discard) = r else {
        panic!("expected Stopped, got {r:?}");
    };
    assert!(discard.discarded_restart);
    assert_eq!(discard.discarded_force_restart_id, Some(42));
    assert_eq!(discard.discarded_switch_id, Some(7));

    // pending 已清空。
    let p = g.pending();
    assert!(p.is_empty());
}

#[test]
fn start_drains_pending_exactly_once_at_depth_zero() {
    // #1：kind=Start depth 归 0 → 恰好排空一次（重放 switch + 调度重启）。
    let g = LifecycleGate::default();
    g.set_restart_pending();
    g.set_switch_pending(7);

    g.begin();
    let r = g.end(LifecycleKind::Start);
    let LifecycleEndResult::Drained(drain) = r else {
        panic!("expected Drained, got {r:?}");
    };
    assert_eq!(drain.replay_switch_id, Some(7));
    assert!(drain.schedule_restart);

    // 排空后 pending 清空（恰好一次，不重复）。
    assert!(g.pending().is_empty());

    // 再次 end（无 pending）→ 空 drain。
    g.begin();
    let r = g.end(LifecycleKind::Start);
    let LifecycleEndResult::Drained(drain) = r else {
        panic!("expected Drained, got {r:?}");
    };
    assert_eq!(drain.replay_switch_id, None);
    assert!(!drain.schedule_restart);
}

#[test]
fn nested_end_does_not_drain_until_outermost() {
    // depth=2 时内层 end → StillBusy，不排空；pending 留给最外层。
    let g = LifecycleGate::default();
    g.set_restart_pending();
    g.begin(); // depth=1
    g.begin(); // depth=2

    let r = g.end(LifecycleKind::Start);
    assert!(matches!(r, LifecycleEndResult::StillBusy(1)));
    // pending 仍在（未被排空）。
    assert!(g.pending().restart_pending);

    let r = g.end(LifecycleKind::Restart);
    let LifecycleEndResult::Drained(drain) = r else {
        panic!("expected Drained, got {r:?}")
    };
    assert!(drain.schedule_restart);
}

#[test]
fn force_restart_id_drives_schedule_restart_when_no_restart_pending() {
    // #4：force_restart_id Some 时 schedule_restart=true（即使 restart_pending=false）。
    let g = LifecycleGate::default();
    g.set_force_restart(99);
    g.begin();
    let r = g.end(LifecycleKind::Start);
    let LifecycleEndResult::Drained(drain) = r else {
        panic!("expected Drained, got {r:?}")
    };
    assert!(drain.schedule_restart);
    assert_eq!(drain.replay_switch_id, None);
}

#[test]
fn clear_force_restart_for_structural_restart_leg() {
    // #4：结构性重启腿必须清 force_restart（newer 胜，:1894-1895）。
    let g = LifecycleGate::default();
    g.set_force_restart(99);
    g.clear_force_restart();
    assert!(g.pending().force_restart_id.is_none());
}

#[test]
fn generation_is_monotonic_per_bump() {
    let g = LifecycleGate::default();
    assert_eq!(g.generation(), 0);
    let a = g.bump_generation();
    assert_eq!(a, 1);
    assert_eq!(g.generation(), 1);
    let b = g.bump_generation();
    assert_eq!(b, 2);
    assert!(b > a);
}

#[test]
fn debounced_defer_when_busy_overrides_core_state() {
    // #3：depth>0 必须先判（置 pending），即使核已停也不能进 CoreStopped 分支（顺序不可颠倒）。
    let g = LifecycleGate::default();
    g.begin();
    let d = g.debounced_restart_decision(false); // core_running=false 但 busy
    assert!(matches!(d, DebouncedDecision::Defer));
    assert!(g.pending().restart_pending); // 已置 pending
}

#[test]
fn debounced_core_stopped_clears_force_restart_snapshot() {
    // #3/#4：depth=0 且核已停 → CoreStopped + 清 force-restart 快照（H-1 陈旧防护）。
    let g = LifecycleGate::default();
    g.set_force_restart(42);
    let d = g.debounced_restart_decision(false);
    assert!(matches!(d, DebouncedDecision::CoreStopped));
    assert!(g.pending().force_restart_id.is_none()); // 已清
}

#[test]
fn debounced_proceed_returns_force_restart_id_when_set() {
    let g = LifecycleGate::default();
    g.set_force_restart(77);
    let d = g.debounced_restart_decision(true);
    assert!(matches!(d, DebouncedDecision::Proceed(Some(77))));
}

/// **一次「立即应用」只排一次整核重启**（陈先生 2026-07-30 真机：每点一次核重启两遍）。
///
/// 走完整时序：`apply_pending` 置 force id → 去抖 trailing 命中 `Proceed` → 调用方开始重启
/// （depth>0）→ 重启收尾 `end(Restart)` 在 depth 归 0 时**不得**再排一次。
///
/// 变异对照：把 `debounced_restart_decision` 第 3 腿的 `.take()` 改回读取
/// （`g.pending.force_restart_id`）→ `drain.schedule_restart` 变 true → 本条转红。
/// 这正是真机日志里「depth 归零 → 排空一次尾随重启」紧跟首次就绪的那一行。
#[test]
fn proceed_consumes_force_restart_so_the_restart_is_not_drained_a_second_time() {
    let g = LifecycleGate::default();
    // ① apply_pending 非在飞腿：记下「必须用这份 config 重启」。
    g.set_force_restart(42);
    // ② 去抖 trailing：depth=0 且核在跑 → 授权执行，且**消费**该待决项。
    let d = g.debounced_restart_decision(true);
    assert!(
        matches!(d, DebouncedDecision::Proceed(Some(42))),
        "调用方仍须拿到 id 才能取对那份 config 快照，got {d:?}"
    );
    assert!(
        g.pending().is_empty(),
        "Proceed = 这条待决重启已被执行，pending 必须清空；留着它 = 同一条腿被数第二遍"
    );
    // ③ 调用方执行重启：depth 抬起再落回 0。
    g.begin();
    let r = g.end(LifecycleKind::Restart);
    let LifecycleEndResult::Drained(drain) = r else {
        panic!("expected Drained, got {r:?}")
    };
    assert!(
        !drain.schedule_restart,
        "已执行的那次重启不得被 end() 再排一遍 —— 否则每次 apply 都是两次整核重启"
    );
}

#[test]
fn debounced_proceed_returns_none_when_only_current_config() {
    let g = LifecycleGate::default();
    let d = g.debounced_restart_decision(true);
    assert!(matches!(d, DebouncedDecision::Proceed(None)));
}

#[test]
fn busy_gate_does_not_let_debounced_through_even_if_core_running() {
    // #3 顺序门核心：busy 时绝不 Proceed（杜绝「就绪等待中又来重启」风暴根因）。
    let g = LifecycleGate::default();
    g.set_force_restart(1);
    g.begin();
    let d = g.debounced_restart_decision(true);
    assert!(matches!(d, DebouncedDecision::Defer));
    // end 排空时仍能消费 force_restart（未被 debounced 清掉）。
    let r = g.end(LifecycleKind::Start);
    let LifecycleEndResult::Drained(drain) = r else {
        panic!("expected Drained, got {r:?}")
    };
    assert!(drain.schedule_restart);
}

#[test]
fn stop_terminal_drops_force_restart_set_during_busy_window() {
    // bug#5：停止终态丢弃暂存 switch（已落盘，下次 start 读盘应用）。
    let g = LifecycleGate::default();
    g.begin();
    g.set_switch_pending(123);
    g.set_force_restart(456);
    let r = g.end(LifecycleKind::Stop);
    let LifecycleEndResult::Stopped(d) = r else {
        panic!("expected Stopped, got {r:?}")
    };
    assert_eq!(d.discarded_switch_id, Some(123));
    assert_eq!(d.discarded_force_restart_id, Some(456));
    assert!(g.pending().is_empty());
}
