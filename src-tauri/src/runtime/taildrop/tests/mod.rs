use super::*;
use std::sync::Mutex as StdMutex;

#[derive(Default)]
struct RecordingSink(StdMutex<Vec<TaildropTaskSnapshot>>);

impl TaildropTaskEventSink for RecordingSink {
    fn updated(&self, snapshot: &TaildropTaskSnapshot) {
        self.0.lock().unwrap().push(snapshot.clone());
    }
}

fn start(runtime: &TaildropRuntime, name: &str, size: u64) -> StartedTaildropTask {
    runtime
        .start_task(
            "server-a".into(),
            "peer-a".into(),
            vec![(name.into(), size)],
        )
        .unwrap()
}

#[test]
fn progress_is_monotonic_clamped_and_completion_is_a_full_terminal_snapshot() {
    let runtime = TaildropRuntime::default();
    let sink = RecordingSink::default();
    let task = start(&runtime, "a.bin", 10);
    runtime.mark_sending(&task.snapshot.task_id, &sink);
    runtime.record_progress(&task.snapshot.task_id, 0, 7, false, &sink);
    runtime.record_progress(&task.snapshot.task_id, 0, 3, false, &sink);
    runtime.record_progress(&task.snapshot.task_id, 0, 99, true, &sink);
    runtime.record_acknowledged(&task.snapshot.task_id, 4, &sink);
    runtime.record_acknowledged(&task.snapshot.task_id, 9, &sink);
    runtime.complete(&task.snapshot.task_id, &sink);

    let snapshot = runtime.snapshots(None).pop().unwrap();
    assert_eq!(snapshot.phase, TaildropTaskPhase::Completed);
    assert_eq!(snapshot.sent_bytes, 10);
    assert_eq!(snapshot.acknowledged_bytes, 10);
    assert_eq!(snapshot.files[0].sent_bytes, 10);
    assert!(snapshot.files[0].completed);
    assert!(snapshot.revision >= 5);
}

#[test]
fn cancellation_is_idempotent_and_signals_the_owned_task() {
    let runtime = TaildropRuntime::default();
    let sink = RecordingSink::default();
    let mut task = start(&runtime, "a.bin", 10);
    let first = runtime.cancel(&task.snapshot.task_id, &sink).unwrap();
    let second = runtime.cancel(&task.snapshot.task_id, &sink).unwrap();
    assert_eq!(first, second);
    assert!(task.cancel.has_changed().unwrap());
    assert!(*task.cancel.borrow_and_update());
    runtime.canceled(&task.snapshot.task_id, &sink);
    assert_eq!(
        runtime.snapshots(None)[0].phase,
        TaildropTaskPhase::Canceled
    );
}

#[test]
fn active_and_terminal_snapshots_are_strictly_bounded() {
    let runtime = TaildropRuntime::default();
    let sink = RecordingSink::default();
    let mut first_id = String::new();
    for i in 0..(MAX_TAILDROP_TASKS + 5) {
        let task = start(&runtime, &format!("{i}.bin"), 1);
        if i == 0 {
            first_id = task.snapshot.task_id.clone();
        }
        runtime.complete(&task.snapshot.task_id, &sink);
    }
    let snapshots = runtime.snapshots(None);
    assert_eq!(snapshots.len(), MAX_TAILDROP_TASKS);
    assert!(!snapshots
        .iter()
        .any(|snapshot| snapshot.task_id == first_id));

    let active = TaildropRuntime::default();
    let _tasks: Vec<_> = (0..MAX_ACTIVE_TAILDROP_TASKS)
        .map(|i| start(&active, &format!("active-{i}"), 1))
        .collect();
    assert_eq!(
        active
            .start_task(
                "server-a".into(),
                "peer-a".into(),
                vec![("extra".into(), 1)]
            )
            .err(),
        Some(TaildropTaskStartError::Busy)
    );
}

#[test]
fn dropping_the_owner_signals_every_active_task() {
    let mut receivers = {
        let runtime = TaildropRuntime::default();
        vec![
            start(&runtime, "a", 1).cancel,
            start(&runtime, "b", 1).cancel,
        ]
    };
    for receiver in &mut receivers {
        // sender 随 owner 一起 drop 时 `has_changed` 可回 RecvError；最后一个已发送的 true 仍可读。
        let _ = receiver.has_changed();
        assert!(*receiver.borrow_and_update());
    }
}

#[test]
fn file_count_is_bounded_before_any_task_enters_the_registry() {
    let runtime = TaildropRuntime::default();
    let files = (0..=MAX_TAILDROP_FILES_PER_TASK)
        .map(|i| (format!("{i}.bin"), 1))
        .collect();
    assert_eq!(
        runtime
            .start_task("server-a".into(), "peer-a".into(), files)
            .err(),
        Some(TaildropTaskStartError::TooManyFiles)
    );
    assert!(runtime.snapshots(None).is_empty());
}
