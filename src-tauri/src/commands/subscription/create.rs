//! Atomic, backend-owned subscription creation commands.

use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use futures::FutureExt;
use serde_json::{json, Map, Value};
use tauri::{AppHandle, Manager, State};
use tokio::sync::watch;

use crate::commands::config::broadcast_config_changed;
use crate::response::ApiResponse;
use crate::runtime::config::Decision;
use crate::runtime::http::SystemDnsLookup;
use crate::runtime::subscription_create::{
    BroadcastSubscriptionCreateSink, SubscriptionCreateEventSink, SubscriptionCreatePhase,
    SubscriptionCreateRegistration, SubscriptionCreateRuntime, SubscriptionCreateSnapshot,
    SubscriptionCreateStartError,
};
use crate::runtime::unlock::{selected_exit_changed, BroadcastSink};
use crate::runtime::AppRuntime;
use polaris_net_stack::subscription::ProviderResolveControl;

use super::{
    fetch_parse_resolve, find_subscription, reconcile_subscription_servers,
    resolve_subscription_ua, select_fetch_client, want_proxy_for_sub, write_sub_metadata,
    FetchOutcome, UpdateProgressSink,
};

const ERR_INVALID_OPERATION_ID: &str = "SUBSCRIPTION_CREATE_INVALID_OPERATION_ID";
const ERR_INVALID_SUBSCRIPTION: &str = "SUBSCRIPTION_CREATE_INVALID_SUBSCRIPTION";
const ERR_IDEMPOTENCY_CONFLICT: &str = "SUBSCRIPTION_CREATE_IDEMPOTENCY_CONFLICT";
const ERR_BUSY: &str = "SUBSCRIPTION_CREATE_BUSY";
const ERR_SHUTTING_DOWN: &str = "SUBSCRIPTION_CREATE_SHUTTING_DOWN";
const ERR_CONFIG_CHANGED: &str = "SUBSCRIPTION_CREATE_CONFIG_CHANGED";
const ERR_PROXY_CHANGED: &str = "SUBSCRIPTION_CREATE_PROXY_CHANGED";
const ERR_PROXY_REQUIRED: &str = "SUBSCRIPTION_CREATE_PROXY_REQUIRED";
const ERR_NOT_FOUND: &str = "SUBSCRIPTION_CREATE_NOT_FOUND";
const ERR_EMPTY: &str = "SUBSCRIPTION_CREATE_EMPTY";
const ERR_INTERNAL: &str = "SUBSCRIPTION_CREATE_INTERNAL";

/// Start or idempotently re-attach to an atomic create operation.
///
/// `operation_id` is also the persisted subscription id. This makes a retry after process restart
/// discover the already committed record instead of allocating a duplicate id.
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn subscription_create_start(
    app: AppHandle,
    state: State<'_, AppRuntime>,
    operation_id: String,
    subscription: Value,
) -> ApiResponse<SubscriptionCreateSnapshot> {
    if !valid_operation_id(&operation_id) {
        return ApiResponse::err_with_code(
            "operationId must be a UUID-like identifier",
            ERR_INVALID_OPERATION_ID,
        );
    }
    let request = match sanitize_create_request(&operation_id, subscription) {
        Ok(request) => request,
        Err(message) => return ApiResponse::err_with_code(message, ERR_INVALID_SUBSCRIPTION),
    };

    match state
        .subscription_create()
        .register(operation_id.clone(), request.clone())
    {
        Ok(SubscriptionCreateRegistration::Existing(snapshot)) => ApiResponse::ok(snapshot),
        Ok(SubscriptionCreateRegistration::Started(started)) => {
            let snapshot = started.snapshot.clone();
            let sink = BroadcastSubscriptionCreateSink::new(app.clone());
            sink.updated(&snapshot);
            let operations = Arc::clone(state.subscription_create());
            // Construct the completion guard before handing the future to the runtime. If the
            // runtime drops the future before its first poll, Rust drops this capture too and
            // releases the active-worker slot instead of making real exit wait forever.
            let worker = operations.worker_guard(operation_id.clone());
            tauri::async_runtime::spawn(async move {
                let _worker = worker;
                let task =
                    run_create_operation(&app, &operations, &operation_id, request, started.cancel);
                if AssertUnwindSafe(task).catch_unwind().await.is_err() {
                    let sink = BroadcastSubscriptionCreateSink::new(app);
                    operations.fail(
                        &operation_id,
                        create_error(ERR_INTERNAL, "订阅创建任务异常终止"),
                        &sink,
                    );
                }
            });
            ApiResponse::ok(snapshot)
        }
        Err(SubscriptionCreateStartError::IdempotencyConflict) => ApiResponse::err_with_code(
            "operationId 已被另一份订阅创建请求使用",
            ERR_IDEMPOTENCY_CONFLICT,
        ),
        Err(SubscriptionCreateStartError::Busy) => {
            ApiResponse::err_with_code("同时创建的订阅过多，请稍后重试", ERR_BUSY)
        }
        Err(SubscriptionCreateStartError::ShuttingDown) => {
            ApiResponse::err_with_code("应用正在退出，不再接受订阅创建任务", ERR_SHUTTING_DOWN)
        }
    }
}

/// Pull one operation snapshot after subscribing to the progress event.
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn subscription_create_status(
    state: State<'_, AppRuntime>,
    operation_id: String,
) -> ApiResponse<SubscriptionCreateSnapshot> {
    state
        .subscription_create()
        .snapshot(&operation_id)
        .map_or_else(
            || {
                ApiResponse::err_with_code(
                    format!("订阅创建任务不存在: {operation_id}"),
                    ERR_NOT_FOUND,
                )
            },
            ApiResponse::ok,
        )
}

/// Recover all active and bounded recent terminal snapshots after renderer recreation.
#[tauri::command]
pub fn subscription_create_list(
    state: State<'_, AppRuntime>,
) -> ApiResponse<Vec<SubscriptionCreateSnapshot>> {
    ApiResponse::ok(state.subscription_create().snapshots())
}

/// Cancel only before the commit point. During commit this idempotently returns the current
/// non-terminal snapshot, so the renderer can never mistake an uninterruptible write for cancel.
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn subscription_create_cancel(
    app: AppHandle,
    state: State<'_, AppRuntime>,
    operation_id: String,
) -> ApiResponse<SubscriptionCreateSnapshot> {
    let sink = BroadcastSubscriptionCreateSink::new(app);
    state
        .subscription_create()
        .cancel(&operation_id, &sink)
        .map_or_else(
            || {
                ApiResponse::err_with_code(
                    format!("订阅创建任务不存在: {operation_id}"),
                    ERR_NOT_FOUND,
                )
            },
            ApiResponse::ok,
        )
}

async fn run_create_operation(
    app: &AppHandle,
    operations: &Arc<SubscriptionCreateRuntime>,
    operation_id: &str,
    request: Value,
    mut cancel: watch::Receiver<bool>,
) {
    let operation_deadline = std::time::Instant::now() + super::SUBSCRIPTION_OPERATION_TIMEOUT;
    let sink = BroadcastSubscriptionCreateSink::new(app.clone());
    if cancellation_requested(&cancel) {
        return;
    }
    let state = app.state::<AppRuntime>();
    let initial_config = match state.config().load_full() {
        Ok(config) => config,
        Err(error) => {
            operations.fail(
                operation_id,
                create_error(ERR_INTERNAL, format!("{error}")),
                &sink,
            );
            return;
        }
    };

    // Process-restart idempotency: operationId is the persisted subscription id.
    if let Some(existing) = find_subscription(&initial_config, operation_id) {
        if persisted_matches_request(&existing, &request) {
            let result = recovered_result(&initial_config, &existing, operation_id);
            operations.succeed(operation_id, result, &sink);
        } else {
            operations.fail(
                operation_id,
                create_error(
                    ERR_IDEMPOTENCY_CONFLICT,
                    "operationId 已对应另一条已持久化订阅",
                ),
                &sink,
            );
        }
        return;
    }

    let url = request
        .get("url")
        .and_then(Value::as_str)
        .expect("sanitize_create_request validated url")
        .to_owned();
    let user_agent = resolve_subscription_ua(&initial_config, &request);
    let want_proxy = want_proxy_for_sub(&initial_config, &request);
    let forced_proxy = initial_config
        .get("subscriptionProxyPolicy")
        .and_then(Value::as_str)
        == Some("proxy");
    let proxy_before = proxy_generation(&state);
    let (client, via_effective) = select_fetch_client(&state, &initial_config, want_proxy);
    if forced_proxy && !via_effective {
        operations.fail(
            operation_id,
            create_error(
                ERR_PROXY_REQUIRED,
                "全局策略要求订阅经代理创建，但当前代理不可用或后端路由实际直连；已中止且未写入配置",
            ),
            &sink,
        );
        return;
    }

    if operations
        .advance(operation_id, SubscriptionCreatePhase::Fetching, &sink)
        .is_none()
    {
        return;
    }
    let progress: Arc<dyn UpdateProgressSink> = Arc::new(CreatePipelineProgress {
        operations: Arc::clone(operations),
        operation_id: operation_id.to_owned(),
        app: app.clone(),
    });
    let lookup = SystemDnsLookup;
    let provider_control = ProviderResolveControl::default();
    let pipeline = fetch_parse_resolve(
        client,
        &lookup,
        &url,
        operation_id,
        via_effective,
        user_agent.as_deref(),
        None,
        Some(&progress),
        Some(&provider_control),
        Arc::clone(state.subscription_parse()),
        operation_deadline,
    );
    let pipeline = tokio::time::timeout_at(operation_deadline.into(), pipeline);
    tokio::pin!(pipeline);
    let outcome = tokio::select! {
        biased;
        () = wait_for_cancellation(&mut cancel) => {
            provider_control.cancel();
            return;
        },
        outcome = &mut pipeline => outcome,
    };
    let outcome = match outcome {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(classified)) => {
            operations.fail(operation_id, classified_create_error(&classified), &sink);
            return;
        }
        Err(_) => {
            operations.fail(
                operation_id,
                classified_create_error(&super::operation_timeout_error()),
                &sink,
            );
            return;
        }
    };

    if outcome.not_modified {
        operations.fail(
            operation_id,
            create_error(ERR_INTERNAL, "新订阅意外返回 304，未写入配置"),
            &sink,
        );
        return;
    }
    if outcome.servers.is_empty() {
        let message = outcome
            .warnings
            .first()
            .cloned()
            .unwrap_or_else(|| "解析得到 0 个可用节点".to_owned());
        operations.fail(operation_id, create_error(ERR_EMPTY, message), &sink);
        return;
    }

    // Pre-commit revalidation. Any config generation change means the fetch used a stale global
    // UA/proxy-policy snapshot; retrying is safer than silently committing against new policy.
    let latest_config = match state.config().load_full() {
        Ok(config) => config,
        Err(error) => {
            operations.fail(
                operation_id,
                create_error(ERR_INTERNAL, format!("{error}")),
                &sink,
            );
            return;
        }
    };
    if latest_config != initial_config {
        operations.fail(
            operation_id,
            create_error(
                ERR_CONFIG_CHANGED,
                "拉取期间配置已变化，请按最新配置重试订阅创建",
            ),
            &sink,
        );
        return;
    }
    let latest_want_proxy = want_proxy_for_sub(&latest_config, &request);
    let latest_forced_proxy = latest_config
        .get("subscriptionProxyPolicy")
        .and_then(Value::as_str)
        == Some("proxy");
    let (_, latest_via_effective) = select_fetch_client(&state, &latest_config, latest_want_proxy);
    if latest_forced_proxy && !latest_via_effective {
        operations.fail(
            operation_id,
            create_error(
                ERR_PROXY_REQUIRED,
                "提交前代理已不可用或后端路由实际直连；强制代理策略下不会写入直连拉取结果",
            ),
            &sink,
        );
        return;
    }
    if latest_via_effective != via_effective
        || (via_effective && proxy_generation(&state) != proxy_before)
    {
        operations.fail(
            operation_id,
            create_error(
                ERR_PROXY_CHANGED,
                "拉取期间代理运行代次已变化，请重试订阅创建",
            ),
            &sink,
        );
        return;
    }

    // This transition is the final cancel check. From here through ConfigManager::update there is
    // deliberately no await and cancel returns `committing`, never a false cancelled terminal.
    if operations.begin_commit(operation_id, &sink).is_none() {
        return;
    }
    commit_create(
        app,
        &state,
        operations,
        operation_id,
        request,
        initial_config,
        outcome,
        &sink,
    );
}

#[allow(clippy::too_many_arguments)]
fn commit_create(
    app: &AppHandle,
    state: &AppRuntime,
    operations: &SubscriptionCreateRuntime,
    operation_id: &str,
    request: Value,
    initial_config: Value,
    outcome: FetchOutcome,
    sink: &BroadcastSubscriptionCreateSink,
) {
    let FetchOutcome {
        servers,
        warnings,
        user_info,
        etag,
        last_modified,
        partial,
        failed_providers,
        has_providers,
        ..
    } = outcome;
    let transaction = state.config().update_deferred_cleanup(|config| {
        // Recheck under ConfigManager's single writer lock to close the gap after preflight.
        if config != &initial_config {
            return Decision::Skip(Err(create_error(
                ERR_CONFIG_CHANGED,
                "提交前配置代次已变化，未写入订阅",
            )));
        }
        let old_selected = config
            .get("selectedServerId")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let mut subscription = request;
        subscription["createdAt"] = json!(super::current_iso());
        append_subscription(config, subscription);
        let recon = reconcile_subscription_servers(
            config,
            operation_id,
            servers,
            partial,
            &failed_providers,
        );
        write_sub_metadata(
            config,
            operation_id,
            user_info.as_ref(),
            etag.as_deref(),
            last_modified.as_deref(),
            has_providers,
        );
        let persisted = find_subscription(config, operation_id)
            .expect("subscription was appended in this transaction");
        Decision::Write(Ok((recon, old_selected, persisted)))
    });

    let (recon, old_selected, persisted, saved) = match transaction {
        Ok((Ok((recon, old_selected, persisted)), Some(saved))) => {
            (recon, old_selected, persisted, saved)
        }
        Ok((Err(error), None)) => {
            operations.fail(operation_id, error, sink);
            return;
        }
        Ok(_) => unreachable!("subscription create transaction decision must be consistent"),
        Err(error) => {
            operations.fail(
                operation_id,
                create_error(ERR_INTERNAL, format!("{error}")),
                sink,
            );
            return;
        }
    };

    broadcast_config_changed(app, &saved);
    if selected_exit_changed(
        old_selected.as_deref(),
        saved.get("selectedServerId").and_then(Value::as_str),
    ) {
        let unlock_sink = BroadcastSink::new(app);
        state
            .unlock()
            .invalidate(&unlock_sink, state.proxy().status().running, false);
    }
    let result = create_result(
        operation_id,
        &persisted,
        recon.added,
        recon.updated,
        recon.deleted,
        user_info,
        warnings,
        partial,
        false,
    );
    operations.succeed(operation_id, result, sink);
}

struct CreatePipelineProgress {
    operations: Arc<SubscriptionCreateRuntime>,
    operation_id: String,
    app: AppHandle,
}

impl UpdateProgressSink for CreatePipelineProgress {
    fn emit(&self, frame: Value) {
        if frame.get("phase").and_then(Value::as_str) != Some("providers") {
            return;
        }
        let done = frame.get("done").and_then(Value::as_u64).unwrap_or(0) as usize;
        let total = frame.get("total").and_then(Value::as_u64).unwrap_or(0) as usize;
        let sink = BroadcastSubscriptionCreateSink::new(self.app.clone());
        self.operations
            .provider_progress(&self.operation_id, done, total, &sink);
    }

    fn primary_fetched(&self) {
        let sink = BroadcastSubscriptionCreateSink::new(self.app.clone());
        self.operations
            .advance(&self.operation_id, SubscriptionCreatePhase::Parsing, &sink);
    }
}

pub(super) fn sanitize_create_request(
    operation_id: &str,
    subscription: Value,
) -> Result<Value, &'static str> {
    let Some(mut object) = subscription.as_object().cloned() else {
        return Err("subscription must be an object");
    };
    let Some(name) = object
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
    else {
        return Err("subscription.name is required");
    };
    if object
        .get("url")
        .and_then(Value::as_str)
        .is_none_or(|url| url.trim().is_empty())
    {
        return Err("subscription.url is required");
    }
    for backend_field in [
        "createdAt",
        "lastUpdated",
        "userInfo",
        "etag",
        "lastModified",
        "hasProviders",
    ] {
        object.remove(backend_field);
    }
    object.insert("name".to_owned(), json!(name));
    object.insert("id".to_owned(), json!(operation_id));
    Ok(Value::Object(object))
}

fn valid_operation_id(operation_id: &str) -> bool {
    let len = operation_id.len();
    (8..=128).contains(&len)
        && operation_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub(super) fn append_subscription(config: &mut Value, subscription: Value) {
    if let Some(subscriptions) = config
        .get_mut("subscriptions")
        .and_then(Value::as_array_mut)
    {
        subscriptions.push(subscription);
    } else if let Some(object) = config.as_object_mut() {
        object.insert("subscriptions".to_owned(), Value::Array(vec![subscription]));
    }
}

pub(super) fn persisted_matches_request(persisted: &Value, request: &Value) -> bool {
    request.as_object().is_some_and(|request| {
        request
            .iter()
            .all(|(key, value)| persisted.get(key) == Some(value))
    })
}

fn recovered_result(config: &Value, subscription: &Value, operation_id: &str) -> Value {
    let node_count = config
        .get("servers")
        .and_then(Value::as_array)
        .map_or(0, |servers| {
            servers
                .iter()
                .filter(|server| {
                    server.get("subscriptionId").and_then(Value::as_str) == Some(operation_id)
                })
                .count()
        });
    create_result(
        operation_id,
        subscription,
        node_count,
        0,
        0,
        subscription.get("userInfo").cloned(),
        Vec::new(),
        false,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn create_result(
    operation_id: &str,
    subscription: &Value,
    added: usize,
    updated: usize,
    deleted: usize,
    user_info: Option<Value>,
    warnings: Vec<String>,
    partial: bool,
    recovered: bool,
) -> Value {
    let mut result = json!({
        "subscriptionId": operation_id,
        "subscription": subscription,
        "nodeCount": added,
        "addedServers": added,
        "updatedServers": updated,
        "deletedServers": deleted,
        "warnings": warnings,
        "partial": partial,
        "recovered": recovered,
    });
    if let Some(user_info) = user_info {
        result["userInfo"] = user_info;
    }
    result
}

fn create_error(code: &str, message: impl Into<String>) -> Value {
    json!({"code": code, "message": message.into()})
}

pub(super) fn classified_create_error(classified: &Value) -> Value {
    let mut error = Map::new();
    // Pipeline codes are stable public operation outcomes (not diagnostics). In particular,
    // preserving SUBSCRIPTION_OPERATION_TIMEOUT lets the renderer distinguish a total deadline
    // from a generic fetch failure without reverse-parsing an error message.
    error.insert(
        "code".to_owned(),
        classified
            .get("code")
            .cloned()
            .unwrap_or_else(|| json!("SUBSCRIPTION_CREATE_FETCH_FAILED")),
    );
    error.insert(
        "message".to_owned(),
        classified
            .get("message")
            .cloned()
            .unwrap_or_else(|| json!("订阅拉取失败")),
    );
    for key in ["errorKind", "httpStatus"] {
        if let Some(value) = classified.get(key) {
            error.insert(key.to_owned(), value.clone());
        }
    }
    Value::Object(error)
}

fn cancellation_requested(cancel: &watch::Receiver<bool>) -> bool {
    *cancel.borrow()
}

async fn wait_for_cancellation(cancel: &mut watch::Receiver<bool>) {
    if *cancel.borrow_and_update() {
        return;
    }
    loop {
        match cancel.changed().await {
            Ok(()) if *cancel.borrow_and_update() => return,
            Ok(()) => {}
            Err(_) => std::future::pending::<()>().await,
        }
    }
}

fn proxy_generation(state: &AppRuntime) -> (bool, u32, u16, Option<u64>) {
    let status = state.proxy().status();
    (
        status.running,
        status.pid,
        status.subscription_update_in_port,
        status.start_time,
    )
}
