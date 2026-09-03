use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use super::*;

#[test]
fn started_jobs_hold_worker_capacity_after_caller_cancels() {
    let executor = SubscriptionParseExecutor::new(2, 4);
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let release_rx = Arc::new(Mutex::new(release_rx));
    let mut tasks = Vec::new();
    for _ in 0..3 {
        let active = Arc::clone(&active);
        let peak = Arc::clone(&peak);
        let release_rx = Arc::clone(&release_rx);
        tasks.push(
            executor
                .submit(move || {
                    let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    let _ = release_rx.lock().unwrap().recv();
                    active.fetch_sub(1, Ordering::SeqCst);
                })
                .unwrap(),
        );
    }
    std::thread::sleep(Duration::from_millis(30));
    for task in tasks {
        task.cancel();
    }
    assert_eq!(peak.load(Ordering::SeqCst), 2);
    assert_eq!(active.load(Ordering::SeqCst), 2);
    let _ = release_tx.send(());
    let _ = release_tx.send(());
    std::thread::sleep(Duration::from_millis(30));
    assert_eq!(peak.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn queued_cancel_is_skipped() {
    let executor = SubscriptionParseExecutor::new(1, 2);
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let first = executor
        .submit(move || {
            let _ = release_rx.recv();
            1usize
        })
        .unwrap();
    let ran = Arc::new(AtomicBool::new(false));
    let ran_job = Arc::clone(&ran);
    let second = executor
        .submit(move || {
            ran_job.store(true, Ordering::Release);
            2usize
        })
        .unwrap();
    second.cancel();
    let _ = release_tx.send(());
    assert_eq!(first.result().await.unwrap(), 1);
    std::thread::sleep(Duration::from_millis(30));
    assert!(!ran.load(Ordering::Acquire));
}

#[tokio::test]
async fn weighted_queued_cancel_releases_its_reservation() {
    let executor = SubscriptionParseExecutor::new_with_limits(1, 2, 8);
    let (started_tx, started_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let first = executor
        .submit_weighted(5, move || {
            let _ = started_tx.send(());
            let _ = release_rx.recv();
            1usize
        })
        .unwrap();
    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    let ran = Arc::new(AtomicBool::new(false));
    let ran_second = Arc::clone(&ran);
    let second = executor
        .submit_weighted(3, move || {
            ran_second.store(true, Ordering::Release);
            2usize
        })
        .unwrap();
    second.cancel();
    let _ = release_tx.send(());
    assert_eq!(first.result().await.unwrap(), 1);
    assert!(
        second.result().await.is_err(),
        "cancelled job must drop its sender"
    );
    assert!(!ran.load(Ordering::Acquire));
    wait_for_reserved_input_bytes(&executor, 0);
    assert_eq!(
        executor
            .submit_weighted(8, || 3usize)
            .unwrap()
            .result()
            .await
            .unwrap(),
        3
    );
}

#[tokio::test]
async fn dropped_receiver_sender_failure_does_not_poison_the_worker() {
    let executor = SubscriptionParseExecutor::new_with_limits(1, 2, 8);
    let (started_tx, started_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let task = executor
        .submit_weighted(8, move || {
            let _ = started_tx.send(());
            let _ = release_rx.recv();
            1usize
        })
        .unwrap();
    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    drop(task);
    let _ = release_tx.send(());
    wait_for_reserved_input_bytes(&executor, 0);
    assert_eq!(
        executor.submit(|| 2usize).unwrap().result().await.unwrap(),
        2
    );
}

#[tokio::test]
async fn panic_drops_the_failed_result_but_the_worker_survives() {
    let executor = SubscriptionParseExecutor::new(1, 2);
    let panicked = executor
        .submit::<usize, _>(|| panic!("parser test panic"))
        .unwrap();
    assert!(
        panicked.result().await.is_err(),
        "panic must close the result channel"
    );
    assert_eq!(
        executor.submit(|| 7usize).unwrap().result().await.unwrap(),
        7,
        "the fixed parser worker must continue after an isolated panic"
    );
}

#[test]
fn shutdown_never_waits_for_started_cpu_job() {
    let executor = SubscriptionParseExecutor::new(1, 1);
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let _task = executor
        .submit(move || {
            let _ = release_rx.recv();
        })
        .unwrap();
    std::thread::sleep(Duration::from_millis(20));
    let started = std::time::Instant::now();
    executor.shutdown();
    assert!(started.elapsed() < Duration::from_millis(50));
    let _ = release_tx.send(());
}

#[tokio::test]
async fn input_budget_stays_reserved_until_actual_job_finishes() {
    let executor = SubscriptionParseExecutor::new_with_limits(1, 4, 8);
    let (started_tx, started_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let first = executor
        .submit_weighted(6, move || {
            let _ = started_tx.send(());
            let _ = release_rx.recv();
            1usize
        })
        .unwrap();
    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    first.cancel();
    assert!(matches!(
        executor.submit_weighted(3, || 2usize),
        Err(SubscriptionParseSubmitError::Busy)
    ));
    let _ = release_tx.send(());
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        executor
            .submit_weighted(3, || 3usize)
            .unwrap()
            .result()
            .await
            .unwrap(),
        3
    );
}

#[test]
fn oversized_single_submission_keeps_the_parse_limit_classification() {
    let executor = SubscriptionParseExecutor::new_with_limits(1, 2, 8);
    assert!(matches!(
        executor.submit_weighted(9, || 1usize),
        Err(SubscriptionParseSubmitError::InputBudgetExceeded)
    ));
}

#[tokio::test]
async fn shutdown_releases_exactly_the_discarded_queue_budget() {
    let executor = SubscriptionParseExecutor::new_with_limits(1, 2, 8);
    let (started_tx, started_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let first = executor
        .submit_weighted(5, move || {
            let _ = started_tx.send(());
            let _ = release_rx.recv();
            1usize
        })
        .unwrap();
    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    let _queued = executor.submit_weighted(3, || 2usize).unwrap();
    assert_eq!(reserved_input_bytes(&executor), 8);

    executor.shutdown();
    assert_eq!(
        reserved_input_bytes(&executor),
        5,
        "shutdown must release only the discarded queued job, not an active parser job"
    );
    let _ = release_tx.send(());
    assert_eq!(first.result().await.unwrap(), 1);
    wait_for_reserved_input_bytes(&executor, 0);
}

fn reserved_input_bytes(executor: &SubscriptionParseExecutor) -> usize {
    executor
        .inner
        .queue
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .reserved_input_bytes
}

fn wait_for_reserved_input_bytes(executor: &SubscriptionParseExecutor, expected: usize) {
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while reserved_input_bytes(executor) != expected {
        assert!(
            std::time::Instant::now() < deadline,
            "parser input reservation did not reach {expected}; actual={}",
            reserved_input_bytes(executor)
        );
        std::thread::yield_now();
    }
}
