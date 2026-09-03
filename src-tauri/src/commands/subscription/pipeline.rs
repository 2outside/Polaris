//! Subscription fetch/parse/provider pipeline.
//!
//! Network remains async and bounded. Every synchronous parser job owns only body/parameters and
//! runs through the runtime-owned [`SubscriptionParseExecutor`]. Resource limits are checked before
//! provider/main results are accumulated.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

use serde_json::{json, Value};

use polaris_config_engine::user_config::server_config::ServerConfig;
use polaris_net_stack::clash_parser::{default_max_providers, ClashParseResult};
use polaris_net_stack::singbox_import::ImportOrigin;
use polaris_net_stack::ssrf::DnsLookup;
use polaris_net_stack::subscription::{
    dedupe_by_fingerprint, default_subscription_user_agent, enforce_parse_output_budget_typed,
    fetch_subscription_full_capped_until, fetch_subscription_with_meta_until,
    parse_provider_request, parse_subscription_bundle_limited_typed,
    resolve_proxy_providers_controlled_with_parser, Conditional, ParseOutputMetrics,
    ProviderFatalError, ProviderFatalErrorKind, ProviderFetchError, ProviderParseRequest,
    ProviderResolveControl, ProviderResolveLimits, ProviderResolveResult, SubscriptionParseError,
    SubscriptionParseErrorKind, SubscriptionParseLimits, MAIN_FETCH_TIMEOUT_MS,
    PROVIDER_FETCH_TIMEOUT_MS,
};

use crate::runtime::http::{HttpRuntime, SystemDnsLookup};
use crate::runtime::subscription_parse::{
    SubscriptionParseExecutor, SubscriptionParseSubmitError, SUBSCRIPTION_PARSE_INPUT_BYTES,
};

use super::{
    classify_fetch_error, classify_provider_fetch_error, current_iso, new_uuid,
    primary_fetch_retry_delay, UpdateProgressSink,
};

pub(super) struct ProviderProgress {
    sink: Arc<dyn UpdateProgressSink>,
    total: usize,
    announced: AtomicBool,
    completed: std::sync::atomic::AtomicUsize,
}

impl ProviderProgress {
    pub(super) fn new(sink: Arc<dyn UpdateProgressSink>, total: usize) -> Self {
        Self {
            sink,
            total,
            announced: AtomicBool::new(false),
            completed: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub(super) fn on_fetch_start(&self) {
        if self.announced.swap(true, Ordering::Relaxed) {
            return;
        }
        self.sink.emit(json!({
            "phase": "providers",
            "done": 0,
            "total": self.total,
        }));
    }

    pub(super) fn on_fetch_finish(&self) {
        let done = self.completed.fetch_add(1, Ordering::Relaxed) + 1;
        self.sink.emit(json!({
            "phase": "providers",
            "done": done,
            "total": self.total,
        }));
    }
}

/// Pure, owned aggregation step for the parser executor. Provider resolver networking remains
/// async, but combining up to 50k nodes / 64MiB of warnings and JSON output must not monopolize a
/// Tokio worker or defer cancellation polling.
struct ProviderAggregation {
    parsed: ClashParseResult,
    partial: bool,
    failed_providers: Vec<String>,
}

fn aggregate_provider_output(
    mut inline: ClashParseResult,
    inline_output_metrics: ParseOutputMetrics,
    providers: ProviderResolveResult,
    limits: SubscriptionParseLimits,
) -> Result<ProviderAggregation, SubscriptionParseError> {
    // Preserve the pre-dedupe fail-closed budget: duplicate nodes still consume parser work and
    // must not be used to smuggle an oversized provider response through the final output cap.
    enforce_operation_output_budget(inline_output_metrics, &providers, limits)?;
    let partial = providers.any_failed;
    let failed_providers = providers.failed_providers;
    inline.warnings.extend(providers.warnings);
    let mut merged = std::mem::take(&mut inline.servers);
    merged.extend(providers.servers);
    inline.servers = dedupe_by_fingerprint(merged);
    enforce_parse_output_budget_typed(&inline, limits)?;
    Ok(ProviderAggregation {
        parsed: inline,
        partial,
        failed_providers,
    })
}

fn build_provider_fetch(
    client: Arc<HttpRuntime>,
    ua: String,
    via_proxy: bool,
    progress: Option<Arc<ProviderProgress>>,
    operation_deadline: std::time::Instant,
    max_body_bytes: usize,
) -> impl Fn(
    &str,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<String, ProviderFetchError>> + Send>,
> + Send
       + Sync {
    move |url: &str| {
        let client = Arc::clone(&client);
        let ua = ua.clone();
        let url = url.to_owned();
        if let Some(progress) = &progress {
            progress.on_fetch_start();
        }
        let progress = progress.clone();
        Box::pin(async move {
            let deadline = (std::time::Instant::now()
                + Duration::from_millis(PROVIDER_FETCH_TIMEOUT_MS))
            .min(operation_deadline);
            let result = fetch_subscription_full_capped_until(
                client.as_ref(),
                &SystemDnsLookup,
                &url,
                &ua,
                None,
                via_proxy,
                max_body_bytes,
                deadline,
            )
            .await
            .map_err(|error| classify_provider_fetch_error(&error));
            if let Some(progress) = progress {
                progress.on_fetch_finish();
            }
            result
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn fetch_parse_resolve<L: DnsLookup>(
    client: Arc<HttpRuntime>,
    lookup: &L,
    url: &str,
    subscription_id: &str,
    via_proxy: bool,
    user_agent: Option<&str>,
    conditional: Option<&Conditional>,
    progress: Option<&Arc<dyn UpdateProgressSink>>,
    provider_control: Option<&ProviderResolveControl>,
    parse_executor: Arc<SubscriptionParseExecutor>,
    operation_deadline: std::time::Instant,
) -> Result<FetchOutcome, Value> {
    let pipeline_started = std::time::Instant::now();
    let operation = if subscription_id.is_empty() {
        "preview"
    } else {
        "update"
    };
    let ua = user_agent
        .map(str::to_string)
        .unwrap_or_else(|| default_subscription_user_agent(env!("CARGO_PKG_VERSION")));
    let mut retries_done = 0;
    let main_fetch_deadline = (std::time::Instant::now()
        + Duration::from_millis(MAIN_FETCH_TIMEOUT_MS))
    .min(operation_deadline);
    let fetched = loop {
        match fetch_subscription_with_meta_until(
            client.as_ref(),
            lookup,
            url,
            &ua,
            conditional,
            via_proxy,
            main_fetch_deadline,
        )
        .await
        {
            Ok(fetched) => break fetched,
            Err(error) => {
                let Some(delay) = primary_fetch_retry_delay(error.kind, retries_done) else {
                    log::info!(
                        "subscription pipeline timing: operation={operation} outcome=fetch_failed main_fetch_ms={} retries={retries_done}",
                        pipeline_started.elapsed().as_millis()
                    );
                    return Err(classify_fetch_error(&error));
                };
                retries_done += 1;
                log::debug!(
                    "subscription primary fetch transient failure; retrying once: kind={:?}",
                    error.kind
                );
                tokio::time::sleep(delay).await;
            }
        }
    };
    let main_fetch_ms = pipeline_started.elapsed().as_millis();
    if let Some(sink) = progress {
        sink.primary_fetched();
    }
    if fetched.not_modified {
        return Ok(FetchOutcome {
            not_modified: true,
            etag: fetched.etag,
            last_modified: fetched.last_modified,
            ..Default::default()
        });
    }

    let now = current_iso();
    let parse_started = std::time::Instant::now();
    let body_bytes = fetched.text.len();
    let body = fetched.text;
    let parse_subscription_id = subscription_id.to_owned();
    let parse_now = now.clone();
    // Provider output is retained before the final aggregation task. Keep the operation's semantic
    // output cap aligned with that task's exact executor reservation, so a 32–64 MiB result is
    // rejected by the provider parser before it can accumulate and then fail at submission time.
    let parse_limits = SubscriptionParseLimits {
        max_output_bytes: SUBSCRIPTION_PARSE_INPUT_BYTES,
        ..Default::default()
    };
    let parse_task = parse_executor
        .submit_weighted(body_bytes, move || {
            let mut id_gen = new_uuid;
            parse_subscription_bundle_limited_typed(
                &body,
                &parse_subscription_id,
                &parse_now,
                &mut id_gen,
                ImportOrigin::RemoteSubscription,
                parse_limits,
            )
        })
        .map_err(classified_parse_submit_error)?;
    let bundle = parse_task
        .result()
        .await
        .map_err(|error| classified_parse_error(error.to_string()))?
        .map_err(classified_subscription_parse_error)?;
    let inline_output_metrics = bundle.output_metrics.ok_or_else(|| {
        classified_parse_error("订阅解析未生成输出度量，已拒绝执行聚合".to_string())
    })?;
    let mut parsed = bundle.parsed;
    let parse_ms = parse_started.elapsed().as_millis();
    let mut partial = false;
    let mut failed_providers = Vec::new();
    let providers_started = std::time::Instant::now();
    let mut provider_count = 0usize;
    let default_control = ProviderResolveControl::default();
    let provider_control = provider_control.unwrap_or(&default_control);
    let has_providers = if let Some(providers) = bundle.proxy_providers {
        let declared = providers.as_mapping().map_or(0, |map| map.len());
        provider_count = declared.min(default_max_providers());
        let counter = progress.map(|sink| {
            Arc::new(ProviderProgress::new(
                Arc::clone(sink),
                declared.min(default_max_providers()),
            ))
        });
        let mut provider_limits = ProviderResolveLimits {
            max_providers: default_max_providers(),
            max_total_nodes: parse_limits.max_nodes.saturating_sub(parsed.servers.len()),
            max_warnings: parse_limits
                .max_warnings
                .saturating_sub(parsed.warnings.len()),
            max_output_bytes: parse_limits.max_output_bytes,
            initial_output_metrics: inline_output_metrics,
            ..Default::default()
        };
        provider_limits.max_nodes_per_provider = provider_limits
            .max_nodes_per_provider
            .min(provider_limits.max_total_nodes);
        let fetch = build_provider_fetch(
            Arc::clone(&client),
            ua.clone(),
            via_proxy,
            counter,
            operation_deadline,
            provider_limits.max_provider_body_bytes,
        );
        let provider_executor = Arc::clone(&parse_executor);
        let mut parse_provider = move |request: ProviderParseRequest| {
            let input_bytes = request.text.len();
            let submitted = provider_executor.submit_weighted(input_bytes, move || {
                let mut id_gen = new_uuid;
                parse_provider_request(request, &mut id_gen)
            });
            async move {
                let task = submitted
                    .map_err(|error| ProviderFetchError::fatal_busy(format!("provider {error}")))?;
                task.result()
                    .await
                    .map_err(|error| ProviderFetchError::fatal_busy(format!("provider {error}")))?
            }
        };
        let providers_result = resolve_proxy_providers_controlled_with_parser(
            &providers,
            subscription_id,
            &now,
            provider_limits,
            provider_control,
            &fetch,
            &mut parse_provider,
        )
        .await;
        if providers_result.cancelled {
            return Err(json!({
                "ok": false,
                "errorKind": "unknown",
                "message": "订阅创建已取消",
                "code": "SUBSCRIPTION_CREATE_CANCELLED",
            }));
        }
        if let Some(error) = &providers_result.fatal_error {
            return Err(classified_provider_fatal_error(error));
        }
        let aggregate_input_bytes = inline_output_metrics
            .checked_add(providers_result.output_metrics)
            .and_then(|metrics| metrics.output_bytes())
            .map_err(classified_subscription_parse_error)?;
        let aggregate_task = parse_executor
            .submit_weighted(aggregate_input_bytes, move || {
                aggregate_provider_output(
                    parsed,
                    inline_output_metrics,
                    providers_result,
                    parse_limits,
                )
            })
            .map_err(classified_parse_submit_error)?;
        let aggregate = aggregate_task
            .result()
            .await
            .map_err(|error| classified_parse_error(error.to_string()))?
            .map_err(classified_subscription_parse_error)?;
        partial = aggregate.partial;
        failed_providers = aggregate.failed_providers;
        parsed = aggregate.parsed;
        true
    } else {
        false
    };
    let providers_ms = providers_started.elapsed().as_millis();
    log::info!(
        "subscription pipeline timing: operation={operation} outcome=parsed main_fetch_ms={main_fetch_ms} parse_ms={parse_ms} providers_ms={providers_ms} providers={provider_count} body_bytes={body_bytes} nodes={} retries={retries_done} total_ms={}",
        parsed.servers.len(),
        pipeline_started.elapsed().as_millis()
    );
    Ok(FetchOutcome {
        servers: parsed.servers,
        warnings: parsed.warnings,
        user_info: fetched.user_info.map(|info| info.to_json()),
        etag: fetched.etag,
        last_modified: fetched.last_modified,
        not_modified: false,
        partial,
        failed_providers,
        has_providers,
    })
}

fn classified_parse_error(message: String) -> Value {
    json!({ "ok": false, "errorKind": "parse", "message": message })
}

fn classified_parse_limit_error(message: String) -> Value {
    json!({ "ok": false, "errorKind": "parse_limit", "message": message })
}

fn classified_subscription_parse_error(error: SubscriptionParseError) -> Value {
    match error.kind {
        SubscriptionParseErrorKind::Parse => classified_parse_error(error.message),
        SubscriptionParseErrorKind::Limit => classified_parse_limit_error(error.message),
    }
}

fn classified_provider_fatal_error(error: &ProviderFatalError) -> Value {
    match error.kind {
        ProviderFatalErrorKind::ParseLimit => classified_parse_limit_error(error.message.clone()),
        ProviderFatalErrorKind::ParseBusy => {
            json!({ "ok": false, "errorKind": "parse_busy", "message": error.message })
        }
    }
}

fn classified_parse_submit_error(error: SubscriptionParseSubmitError) -> Value {
    let error_kind = match error {
        SubscriptionParseSubmitError::Busy | SubscriptionParseSubmitError::ShuttingDown => {
            "parse_busy"
        }
        SubscriptionParseSubmitError::InputBudgetExceeded => "parse_limit",
    };
    json!({ "ok": false, "errorKind": error_kind, "message": error.to_string() })
}

pub(super) fn operation_timeout_error() -> Value {
    json!({
        "ok": false,
        "errorKind": "operation_timeout",
        "message": "订阅操作超过 60 秒总时限，已取消且未提交结果",
        "code": "SUBSCRIPTION_OPERATION_TIMEOUT",
    })
}

fn enforce_operation_output_budget(
    inline_output_metrics: ParseOutputMetrics,
    providers: &polaris_net_stack::subscription::ProviderResolveResult,
    limits: SubscriptionParseLimits,
) -> Result<(), SubscriptionParseError> {
    let metrics = inline_output_metrics.checked_add(providers.output_metrics)?;
    if metrics.server_count() > limits.max_nodes {
        return Err(SubscriptionParseError::limit(format!(
            "订阅节点累计超过上限 {}，已拒绝",
            limits.max_nodes
        )));
    }
    if metrics.warning_count() > limits.max_warnings {
        return Err(SubscriptionParseError::limit(format!(
            "订阅告警累计超过上限 {}，已拒绝",
            limits.max_warnings
        )));
    }
    metrics.enforce_max_output_bytes(limits.max_output_bytes)
}

#[derive(Default)]
pub(super) struct FetchOutcome {
    pub(super) servers: Vec<ServerConfig>,
    pub(super) warnings: Vec<String>,
    pub(super) user_info: Option<Value>,
    pub(super) etag: Option<String>,
    pub(super) last_modified: Option<String>,
    pub(super) not_modified: bool,
    pub(super) partial: bool,
    pub(super) failed_providers: Vec<String>,
    pub(super) has_providers: bool,
}

#[cfg(test)]
mod tests;
