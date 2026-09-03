use std::sync::{mpsc, Arc, Mutex};

use serde_json::{json, Value};

use crate::runtime::subscription_create::{
    StartedSubscriptionCreate, SubscriptionCreateEventSink, SubscriptionCreatePhase,
    SubscriptionCreateRegistration, SubscriptionCreateRuntime, SubscriptionCreateSnapshot,
    SubscriptionCreateStartError, MAX_SUBSCRIPTION_CREATE_OPERATIONS,
};
use crate::runtime::{config::ConfigManager, config::Decision};
use crate::test_support::TestDir;

use super::super::create::{
    append_subscription, classified_create_error, persisted_matches_request,
    sanitize_create_request,
};

#[derive(Default)]
struct RecordingSink(Mutex<Vec<SubscriptionCreateSnapshot>>);

impl SubscriptionCreateEventSink for RecordingSink {
    fn updated(&self, snapshot: &SubscriptionCreateSnapshot) {
        self.0.lock().unwrap().push(snapshot.clone());
    }
}

fn started(
    runtime: &SubscriptionCreateRuntime,
    id: &str,
    request: Value,
) -> StartedSubscriptionCreate {
    match runtime.register(id.to_owned(), request).unwrap() {
        SubscriptionCreateRegistration::Started(started) => started,
        SubscriptionCreateRegistration::Existing(_) => panic!("expected a new operation"),
    }
}

#[test]
fn operation_id_is_idempotent_but_cannot_be_reused_for_another_request() {
    let runtime = SubscriptionCreateRuntime::default();
    let request = json!({"url":"https://example.com/a"});
    let first = started(&runtime, "op-a", request.clone());
    let second = runtime.register("op-a".into(), request).unwrap();
    let SubscriptionCreateRegistration::Existing(second) = second else {
        panic!("retry must reattach")
    };
    assert_eq!(first.snapshot, second);
    assert!(matches!(
        runtime.register("op-a".into(), json!({"url":"https://example.com/b"})),
        Err(SubscriptionCreateStartError::IdempotencyConflict)
    ));
}

#[test]
fn cancel_before_commit_is_terminal_and_blocks_the_commit_point() {
    let runtime = SubscriptionCreateRuntime::default();
    let sink = RecordingSink::default();
    let mut task = started(&runtime, "op-a", json!({"url":"https://example.com"}));
    runtime.advance("op-a", SubscriptionCreatePhase::Fetching, &sink);
    let cancelled = runtime.cancel("op-a", &sink).unwrap();
    assert_eq!(cancelled.phase, SubscriptionCreatePhase::Cancelled);
    assert!(cancelled.terminal);
    assert!(task.cancel.has_changed().unwrap());
    assert!(*task.cancel.borrow_and_update());
    assert!(runtime.begin_commit("op-a", &sink).is_none());
}

#[test]
fn cancellation_after_commit_point_never_claims_cancelled() {
    let runtime = SubscriptionCreateRuntime::default();
    let sink = RecordingSink::default();
    let _task = started(&runtime, "op-a", json!({"url":"https://example.com"}));
    runtime.advance("op-a", SubscriptionCreatePhase::Fetching, &sink);
    runtime.advance("op-a", SubscriptionCreatePhase::Parsing, &sink);
    let committing = runtime.begin_commit("op-a", &sink).unwrap();
    assert_eq!(committing.phase, SubscriptionCreatePhase::Committing);
    assert_eq!(runtime.cancel("op-a", &sink).unwrap(), committing);
    let success = runtime.succeed("op-a", json!({"subscriptionId":"op-a"}), &sink);
    assert_eq!(success.unwrap().phase, SubscriptionCreatePhase::Succeeded);
}

#[test]
fn shutdown_rejects_new_work_and_waits_for_a_precommit_worker() {
    let runtime = Arc::new(SubscriptionCreateRuntime::default());
    let mut task = started(&runtime, "op-a", json!({"url":"https://example.com"}));
    let guard = runtime.worker_guard("op-a".into());
    runtime.shutdown_begin();
    while !task.cancel.has_changed().unwrap() {
        std::thread::yield_now();
    }
    assert!(*task.cancel.borrow_and_update());
    assert!(
        runtime
            .snapshot("op-a")
            .is_some_and(|snapshot| snapshot.terminal),
        "shutdown begin must make a pre-commit operation terminal before parser queues close"
    );
    let runtime_for_wait = Arc::clone(&runtime);
    let waiter = std::thread::spawn(move || runtime_for_wait.shutdown_wait());
    assert!(
        !waiter.is_finished(),
        "shutdown wait must protect an active worker"
    );
    drop(guard);
    waiter.join().unwrap();
    assert!(matches!(
        runtime.register("op-b".into(), json!({"url":"https://example.com/b"})),
        Err(SubscriptionCreateStartError::ShuttingDown)
    ));
}

#[test]
fn dropped_never_polled_future_releases_registered_worker_before_shutdown_waits() {
    let runtime = Arc::new(SubscriptionCreateRuntime::default());
    let _started = started(&runtime, "op-a", json!({"url":"https://example.com"}));
    let guard = runtime.worker_guard("op-a".into());

    // This mirrors the production spawn boundary: the guard is a capture, but the future is
    // dropped before its first poll. Dropping the future must still release worker_active.
    let never_polled = async move {
        let _worker = guard;
        std::future::pending::<()>().await;
    };
    drop(never_polled);

    let (done_tx, done_rx) = mpsc::channel();
    let runtime_for_shutdown = Arc::clone(&runtime);
    std::thread::spawn(move || {
        runtime_for_shutdown.shutdown_and_wait();
        let _ = done_tx.send(());
    });
    done_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("a never-polled create future must not leave shutdown waiting forever");
}

#[test]
fn terminal_snapshots_are_bounded_and_recoverable_in_newest_first_order() {
    let runtime = Arc::new(SubscriptionCreateRuntime::default());
    let sink = RecordingSink::default();
    for index in 0..(MAX_SUBSCRIPTION_CREATE_OPERATIONS + 3) {
        let id = format!("op-{index}");
        let _task = started(&runtime, &id, json!({"url":format!("https://{index}")}));
        let guard = runtime.worker_guard(id.clone());
        runtime.fail(&id, json!({"code":"test"}), &sink);
        drop(guard);
    }
    let snapshots = runtime.snapshots();
    assert_eq!(snapshots.len(), MAX_SUBSCRIPTION_CREATE_OPERATIONS);
    assert_eq!(
        snapshots
            .first()
            .map(|snapshot| snapshot.operation_id.as_str()),
        Some("op-66")
    );
    assert!(snapshots.iter().all(|snapshot| snapshot.terminal));
}

#[test]
fn sanitization_makes_operation_id_the_authoritative_subscription_id() {
    let request = sanitize_create_request(
        "operation-123",
        json!({
            "id":"attacker-id",
            "name":"  Example subscription  ",
            "url":"https://example.com/sub",
            "createdAt":"old",
            "etag":"stale"
        }),
    )
    .unwrap();
    assert_eq!(request["id"], "operation-123");
    assert_eq!(request["name"], "Example subscription");
    assert!(request.get("createdAt").is_none());
    assert!(request.get("etag").is_none());
}

#[test]
fn missing_or_blank_name_is_rejected_before_any_config_write() {
    let dir = TestDir::new("polaris-subscription-create-name-validation-");
    let manager = ConfigManager::new(dir.clone());
    let before = manager.load_full().unwrap();

    for invalid in [
        json!({"url":"https://example.com/sub"}),
        json!({"name":"   ","url":"https://example.com/sub"}),
        json!({"name":42,"url":"https://example.com/sub"}),
    ] {
        assert_eq!(
            sanitize_create_request("operation-123", invalid),
            Err("subscription.name is required")
        );
        assert_eq!(
            manager.load_full().unwrap(),
            before,
            "invalid input must be rejected before the atomic subscription+nodes transaction"
        );
    }
}

#[test]
fn persisted_retry_matches_only_the_original_request_fields() {
    let request = json!({"id":"operation-123","url":"https://example.com/sub","name":"A"});
    let persisted = json!({
        "id":"operation-123",
        "url":"https://example.com/sub",
        "name":"A",
        "createdAt":"now",
        "lastUpdated":"now"
    });
    assert!(persisted_matches_request(&persisted, &request));
    assert!(!persisted_matches_request(
        &persisted,
        &json!({"id":"operation-123","url":"https://example.com/other","name":"A"})
    ));
}

#[test]
fn precommit_candidate_is_zero_write_until_the_single_transaction_runs() {
    let disk = json!({"subscriptions":[],"servers":[]});
    let mut candidate = disk.clone();
    append_subscription(
        &mut candidate,
        json!({"id":"operation-123","url":"https://example.com/sub"}),
    );
    assert_eq!(disk["subscriptions"], json!([]));
    assert_eq!(candidate["subscriptions"][0]["id"], "operation-123");
}

#[test]
fn config_manager_skip_is_zero_write_and_write_persists_subscription_and_nodes_together() {
    let dir = TestDir::new("polaris-subscription-create-atomic-");
    let manager = ConfigManager::new(dir.clone());
    let before = manager.load_full().unwrap();
    let subscription =
        json!({"id":"operation-123","name":"subscription","url":"https://example.com/sub"});
    let node = json!({
        "id":"node-1",
        "name":"node",
        "protocol":"http",
        "address":"example.com",
        "port":443,
        "subscriptionId":"operation-123"
    });

    let (_, skipped) = manager
        .update(|candidate| {
            append_subscription(candidate, subscription.clone());
            candidate
                .get_mut("servers")
                .and_then(Value::as_array_mut)
                .unwrap()
                .push(node.clone());
            Decision::Skip(())
        })
        .unwrap();
    assert!(skipped.is_none());
    assert_eq!(manager.load_full().unwrap(), before);

    let (_, saved) = manager
        .update(|candidate| {
            append_subscription(candidate, subscription);
            candidate
                .get_mut("servers")
                .and_then(Value::as_array_mut)
                .unwrap()
                .push(node);
            Decision::Write(())
        })
        .unwrap();
    let saved = saved.unwrap();
    assert_eq!(saved["subscriptions"][0]["id"], "operation-123");
    assert_eq!(saved["servers"][0]["subscriptionId"], "operation-123");
    assert_eq!(manager.load_full().unwrap(), saved);
}

#[test]
fn classified_error_preserves_structured_fetch_metadata() {
    let error = classified_create_error(&json!({
        "message":"HTTP 403",
        "errorKind":"http",
        "httpStatus":403
    }));
    assert_eq!(error["errorKind"], "http");
    assert_eq!(error["httpStatus"], 403);
    assert_eq!(error["code"], "SUBSCRIPTION_CREATE_FETCH_FAILED");
}

#[test]
fn classified_error_preserves_the_pipeline_operation_timeout_code() {
    let error = classified_create_error(&json!({
        "message":"订阅操作超过总时限",
        "errorKind":"operation_timeout",
        "code":"SUBSCRIPTION_OPERATION_TIMEOUT"
    }));
    assert_eq!(error["errorKind"], "operation_timeout");
    assert_eq!(error["code"], "SUBSCRIPTION_OPERATION_TIMEOUT");
}
