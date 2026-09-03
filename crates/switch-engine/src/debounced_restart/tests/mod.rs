#![allow(clippy::too_many_lines)]

use super::*;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

fn new_engine() -> DebouncedRestart {
    DebouncedRestart::new(Arc::new(LifecycleGate::default()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn schedule_proceeds_when_idle_and_core_running() {
    // depth=0 + 核运行 → Proceed(None)（用 currentConfig 重启）。
    let engine = new_engine();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let handle = engine.schedule(true, move |o| {
        let _ = tx.send(o);
    });
    let outcome = rx.await.unwrap();
    assert!(matches!(outcome, DebouncedOutcome::Proceed(None)));
    // task 完成。
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(handle.is_finished());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn schedule_returns_force_restart_id_when_set() {
    // force_restart_id Some → Proceed(Some(id))。
    let engine = new_engine();
    engine.set_force_restart(42);
    let (tx, rx) = tokio::sync::oneshot::channel();
    engine.schedule(true, move |o| {
        let _ = tx.send(o);
    });
    let outcome = rx.await.unwrap();
    assert!(matches!(outcome, DebouncedOutcome::Proceed(Some(42))));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn schedule_defers_when_lifecycle_busy() {
    // depth>0 → Defer（置 pending，不并发起重启）。
    let engine = new_engine();
    engine.begin_lifecycle();
    let (tx, rx) = tokio::sync::oneshot::channel();
    engine.schedule(true, move |o| {
        let _ = tx.send(o);
    });
    let outcome = rx.await.unwrap();
    assert!(matches!(outcome, DebouncedOutcome::Defer));
    // pending 已置。
    assert!(engine.gate.pending().restart_pending);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn schedule_core_stopped_clears_force_restart() {
    // depth=0 + 核停 → CoreStopped + 清 force-restart 快照。
    let engine = new_engine();
    engine.set_force_restart(99);
    let (tx, rx) = tokio::sync::oneshot::channel();
    engine.schedule(false, move |o| {
        let _ = tx.send(o);
    });
    let outcome = rx.await.unwrap();
    assert!(matches!(outcome, DebouncedOutcome::CoreStopped));
    assert!(engine.gate.pending().force_restart_id.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn schedule_superseded_when_generation_changed() {
    // 世代变了（窗口内 start/stop 接管）→ Superseded。
    let engine = new_engine();
    let gen0 = engine.generation();
    // 模拟窗口内 start 接管：bump_generation。
    let (tx, rx) = tokio::sync::oneshot::channel();
    let gate = engine.gate.clone();
    engine.schedule(true, move |o| {
        let _ = tx.send(o);
    });
    // 在 sleep 窗口内 bump 世代。
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert_eq!(gate.bump_generation(), gen0 + 1);
    let outcome = rx.await.unwrap();
    assert!(matches!(outcome, DebouncedOutcome::Superseded));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_prevents_callback() {
    // cancel 后 on_fire 不被调用。
    let engine = new_engine();
    let called = Arc::new(AtomicU32::new(0));
    let called_clone = called.clone();
    let handle = engine.schedule(true, move |_| {
        called_clone.fetch_add(1, Ordering::SeqCst);
    });
    handle.cancel();
    // 等 debounce 窗口过去，确认回调没被调用。
    tokio::time::sleep(RESTART_DEBOUNCE + Duration::from_millis(50)).await;
    assert_eq!(called.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multiple_schedules_collapse_to_single_restart() {
    // 连改 3 条配置（schedule 3 次）→ 前两只 timer 立即取消，只有最后一只回调。
    let engine = new_engine();
    engine.set_force_restart(7);
    let called = Arc::new(AtomicU32::new(0));

    let mut handles = Vec::new();
    for _ in 0..3 {
        let called = Arc::clone(&called);
        handles.push(engine.schedule(true, move |_| {
            called.fetch_add(1, Ordering::SeqCst);
        }));
    }
    // 等所有 task 完成。
    tokio::time::sleep(RESTART_DEBOUNCE + Duration::from_millis(50)).await;
    for h in &handles {
        assert!(h.is_finished());
    }
    assert_eq!(
        called.load(Ordering::SeqCst),
        1,
        "去抖窗口只能有最后一只 timer 回调"
    );
    assert!(!engine.is_lifecycle_busy());
    // 头注那句「第一个 Proceed 清 force_restart_id」如今是真的：`debounced_restart_decision`
    // 在 Proceed 腿 `take()` 该 id。此前它只读不清，于是 id 活到重启收尾的 `end()`，被当成
    // 「还有一条待决重启」再排一次 —— 真机上每点一次「立即应用」核重启两遍。
    //
    // 变异对照：把 `lifecycle_gate.rs` Proceed 腿的 `.take()` 改回读取 → 本条转红。
    assert!(
        engine.gate.pending().is_empty(),
        "Proceed 必须消费 force_restart_id，否则 end() 会把已执行的重启再排一遍"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn busy_gate_defers_even_if_core_running() {
    // #3 顺序门核心：busy 时绝不 Proceed（杜绝「就绪等待中又来重启」风暴根因）。
    let engine = new_engine();
    engine.set_force_restart(1);
    engine.begin_lifecycle();
    let (tx, rx) = tokio::sync::oneshot::channel();
    engine.schedule(true, move |o| {
        let _ = tx.send(o);
    });
    let outcome = rx.await.unwrap();
    assert!(matches!(outcome, DebouncedOutcome::Defer));
    // end 排空时仍能消费 force_restart（未被 debounced 清掉）。
    let drain = engine.drain_pending(LifecycleKind::Start);
    assert!(drain.is_some());
    let drain = drain.unwrap();
    assert!(drain.schedule_restart);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_terminal_discards_pending() {
    // kind=Stop 终态 → 丢弃全部 pending（停止优先）。
    let engine = new_engine();
    engine.set_force_restart(10);
    engine.set_switch_pending(20);
    engine.set_restart_pending();
    engine.begin_lifecycle();
    let result = engine.end_lifecycle(LifecycleKind::Stop);
    match result {
        LifecycleEndResult::Stopped(d) => {
            assert!(d.discarded_restart);
            assert_eq!(d.discarded_force_restart_id, Some(10));
            assert_eq!(d.discarded_switch_id, Some(20));
        }
        _ => panic!("expected Stopped"),
    }
    assert!(engine.gate.pending().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_drains_pending_exactly_once() {
    // kind=Start depth 归 0 → 恰好排空一次。
    let engine = new_engine();
    engine.set_switch_pending(5);
    engine.set_restart_pending();
    engine.begin_lifecycle();
    let drain = engine.drain_pending(LifecycleKind::Start);
    let drain = drain.expect("expected drain");
    assert_eq!(drain.replay_switch_id, Some(5));
    assert!(drain.schedule_restart);
    // 排空后 pending 清空（恰好一次）。
    assert!(engine.gate.pending().is_empty());
    // 再次 end（无 pending）→ 空 drain。
    engine.begin_lifecycle();
    assert!(engine.drain_pending(LifecycleKind::Start).is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nested_lifecycle_does_not_drain_until_outermost() {
    // depth=2 时内层 end → StillBusy，不排空；pending 留给最外层。
    let engine = new_engine();
    engine.set_restart_pending();
    engine.begin_lifecycle(); // depth=1
    engine.begin_lifecycle(); // depth=2
    let r = engine.end_lifecycle(LifecycleKind::Start);
    assert!(matches!(r, LifecycleEndResult::StillBusy(1)));
    // pending 仍在。
    assert!(engine.gate.pending().restart_pending);
    // 最外层 end → drain。
    let drain = engine.drain_pending(LifecycleKind::Restart);
    assert!(drain.is_some_and(|d| d.schedule_restart));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn decide_now_is_immediate_without_timer() {
    // decide_now 不经 timer，立即返回决策。
    let engine = new_engine();
    let o = engine.decide_now(true, false);
    assert!(matches!(o, DebouncedOutcome::Proceed(None)));
    engine.begin_lifecycle();
    let o = engine.decide_now(true, false);
    assert!(matches!(o, DebouncedOutcome::Defer));
    let o = engine.decide_now(false, true);
    assert!(matches!(o, DebouncedOutcome::Superseded)); // 世代守卫优先
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn debounce_delay_is_500ms() {
    // 验证去抖窗口 ≈ 500ms：保留合并语义，但不把显式模式切换拖过 5s。
    let engine = new_engine();
    let start = std::time::Instant::now();
    let (tx, rx) = tokio::sync::oneshot::channel();
    engine.schedule(true, move |_| {
        let _ = tx.send(());
    });
    let _ = rx.await;
    let elapsed = start.elapsed();
    // 允许 -100/+300ms 抖动（tokio timer 精度 + CI 调度）。
    assert!(
        elapsed >= Duration::from_millis(400) && elapsed <= Duration::from_millis(800),
        "debounce elapsed {elapsed:?} not within the 500ms window"
    );
}
