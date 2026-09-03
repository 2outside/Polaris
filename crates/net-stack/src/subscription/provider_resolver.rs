//! proxy-provider 拉取、解析与有界并发编排。
//!
//! 该模块刻意只承载 provider 子流水线；主订阅格式检测、指纹与去重仍留在父模块。

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use futures::StreamExt;
use polaris_config_engine::user_config::server_config::ServerConfig;

use crate::clash_parser::{self, ClashParseResult};

use super::{
    enforce_declared_nodes, measure_parse_output_typed, ParseOutputMetrics,
    SubscriptionParseErrorKind, SubscriptionParseLimits, MAX_BODY_BYTES,
    MAX_PROVIDER_BUFFERED_BODY_BYTES,
};

/// Stable operation classification for a provider leg that must not be downgraded to partial
/// success. It is intentionally separate from diagnostic text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderFatalErrorKind {
    ParseLimit,
    ParseBusy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderFatalError {
    pub kind: ProviderFatalErrorKind,
    pub message: String,
}

impl ProviderFatalError {
    fn parse_limit(message: impl Into<String>) -> Self {
        Self {
            kind: ProviderFatalErrorKind::ParseLimit,
            message: message.into(),
        }
    }
}

/// provider 子拉取失败 —— **带永久性分类**。
///
/// # 为什么 `Result<_, String>` 不够（这是修掉的真实缺陷）
///
/// `permanent` 决定该 provider 进不进 `failed_providers`，而 `failed_providers` 非空
/// 会让 reconcile 对**无 `providerName` 的节点**（主正文内联 `proxies` / 迁移前存量）一律保留
/// （见命令层 `leftover_survives_partial` 规则 2）。于是「provider URL **永久**坏掉」
/// （404 / 域名注销 / SSRF 拒绝）会把整条订阅钉死在 partial：
///  - 主正文里**真下架**的内联节点永不删除；
///  - 每轮更新都判「内容变了」→ 每轮 save + 广播 `config:changed` → 每轮整核评估 + 前端全量重渲染。
///
/// 分类判据（由运行时层填，那里才有 HTTP 状态/错误种类）：
///  - `permanent = true`：重试不会变好 —— 4xx（404/403/410…）、SSRF guard 拒绝、URL 非法/协议不支持。
///    仅 warn，**不**置 `any_failed` → 该 provider 名下节点按真下架正常删除（它确实拿不回来了）。
///  - `permanent = false`：瞬时 —— 超时、连不上、5xx、正文解析失败（WAF 错误页可能下轮就好）。
///    置 `any_failed` + 进 `failed_providers` → 该 provider 名下存量**保留**，防穿仓。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderFetchError {
    pub message: String,
    /// `true` = 重试不转好（不触发 merge-only 保护）；`false` = 瞬时（触发 merge-only 保护）。
    pub permanent: bool,
    /// A typed fail-closed parser/executor failure. It invalidates the whole operation rather
    /// than committing an incomplete provider set as partial success.
    fatal: Option<ProviderFatalErrorKind>,
}

impl ProviderFetchError {
    /// 瞬时失败（默认方向：**宁滞留不误删**）。
    #[must_use]
    pub fn transient(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            permanent: false,
            fatal: None,
        }
    }

    /// 永久失败（重试不转好 → 不保护存量）。
    #[must_use]
    pub fn permanent(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            permanent: true,
            fatal: None,
        }
    }

    /// Operation-wide parser/output resource failure.
    #[must_use]
    pub fn fatal_limit(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            permanent: false,
            fatal: Some(ProviderFatalErrorKind::ParseLimit),
        }
    }

    /// Parser-executor back-pressure or a worker channel failure. This is neither an upstream
    /// provider failure nor a parse-limit violation, but committing partial data is unsafe.
    #[must_use]
    pub fn fatal_busy(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            permanent: false,
            fatal: Some(ProviderFatalErrorKind::ParseBusy),
        }
    }

    fn fatal_error(&self) -> Option<ProviderFatalError> {
        self.fatal.map(|kind| ProviderFatalError {
            kind,
            message: self.message.clone(),
        })
    }
}

impl std::fmt::Display for ProviderFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// 注入的正文拉取闭包类型（返回 boxed future，便于运行时层包装 safe-redirect-fetch + read body）。
pub type FetchTextFn = Box<
    dyn Fn(
            &str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<String, ProviderFetchError>> + Send>,
        > + Send
        + Sync,
>;

/// 已取得 provider 正文后的纯解析请求。所有字段均 owned，便于运行时把 CPU job 投递到独立
/// parser executor；请求不持有网络 client、运行时状态或任何提交能力。
#[derive(Debug)]
pub struct ProviderParseRequest {
    pub text: String,
    /// Owned so parser-worker post-processing can tag server output and prefix warnings without
    /// returning a large mutable result to the Tokio coordinator.
    pub provider_name: String,
    pub filter: Option<String>,
    pub exclude_filter: Option<String>,
    pub override_value: Option<serde_yaml::Value>,
    pub subscription_id: String,
    pub now: String,
    pub source: String,
    pub limits: SubscriptionParseLimits,
}

/// A provider parser-worker result and the exact retained-output metric measured by that worker.
/// The resolver only combines these metrics with checked integer arithmetic; it never needs to
/// serialize a growing provider vector on the Tokio coordination thread.
#[derive(Debug)]
pub struct ProviderParsedOutput {
    pub parsed: ClashParseResult,
    pub output_metrics: ParseOutputMetrics,
}

/// 拉取并解析单个 proxy-provider（http type）。
///
/// Polaris resolveProxyProviders 单 provider 切片：fetch（SSRF guard）→ parse（allowProviders:false）
/// → filter/exclude-filter → override。失败返回 Err（供调用方判 partial / merge-only）。
///
/// 参数与 Polaris ProviderDeps + provider 配置项 1:1 对齐（刻意 8 参数，不强制收敛）。
/// `fetch_text` 注入正文拉取（含安全校验，由运行时层实现 safe-redirect-fetch + read body）。
#[allow(clippy::too_many_arguments)]
pub async fn fetch_and_parse_provider(
    url: &str,
    filter: Option<&str>,
    exclude_filter: Option<&str>,
    override_val: Option<&serde_yaml::Value>,
    subscription_id: &str,
    now: &str,
    fetch_text: &(impl Fn(
        &str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<String, ProviderFetchError>> + Send>,
    > + Send
          + Sync),
    id_gen: &mut impl FnMut() -> String,
) -> Result<ClashParseResult, ProviderFetchError> {
    let text = fetch_text(url).await?;
    parse_provider_text(
        &text,
        filter,
        exclude_filter,
        override_val,
        subscription_id,
        now,
        url,
        id_gen,
    )
}

/// 解析已经取得的 provider 正文。独立于网络腿，使多 provider 可以先并发拉取，再按声明序在单线程
/// 内完成解析与 ID 分配；后者保留历史顺序，也避免给 `id_gen` 外包一层共享锁。
#[allow(clippy::too_many_arguments)]
fn parse_provider_text(
    text: &str,
    filter: Option<&str>,
    exclude_filter: Option<&str>,
    override_val: Option<&serde_yaml::Value>,
    subscription_id: &str,
    now: &str,
    source: &str,
    id_gen: &mut impl FnMut() -> String,
) -> Result<ClashParseResult, ProviderFetchError> {
    let trimmed = text.trim();
    let mut parsed = clash_parser::parse_clash_proxies(
        &clash_parser::try_load_clash_doc(trimmed)
            .map_err(ProviderFetchError::transient)?
            .get(serde_yaml::Value::String("proxies".to_string()))
            .cloned()
            .unwrap_or(serde_yaml::Value::Null),
        subscription_id,
        now,
        id_gen,
    );

    if filter.is_some() || exclude_filter.is_some() {
        let mut warns = Vec::new();
        let filtered = clash_parser::apply_provider_filters(
            std::mem::take(&mut parsed.servers),
            filter,
            exclude_filter,
            &mut |m| warns.push(m),
            source,
        );
        parsed.servers = filtered;
        parsed.warnings.extend(warns);
    }

    if let Some(ov) = override_val {
        clash_parser::apply_override(&mut parsed.servers, ov);
    }

    Ok(parsed)
}

/// 纯 provider 解析入口。运行时生产路径把整个请求 move 到固定容量 CPU executor；保留显式
/// `id_gen` 注入，使 net-stack 单测仍能断言稳定顺序。
pub fn parse_provider_request(
    request: ProviderParseRequest,
    id_gen: &mut impl FnMut() -> String,
) -> Result<ProviderParsedOutput, ProviderFetchError> {
    let trimmed = request.text.trim();
    if trimmed.len() > request.limits.max_body_bytes {
        return Err(ProviderFetchError::fatal_limit(format!(
            "provider 正文超过解析上限 {} 字节",
            request.limits.max_body_bytes
        )));
    }
    let doc = clash_parser::try_load_clash_doc_limited_typed(
        trimmed,
        super::clash_document_limits(request.limits),
    )
    .map_err(|error| match error.kind {
        clash_parser::ClashDocumentErrorKind::Limit => {
            ProviderFetchError::fatal_limit(error.message)
        }
        clash_parser::ClashDocumentErrorKind::Parse => ProviderFetchError::transient(error.message),
    })?;
    let proxies = doc
        .get(serde_yaml::Value::String("proxies".to_string()))
        .cloned()
        .unwrap_or(serde_yaml::Value::Null);
    enforce_declared_nodes(&proxies, Some(request.limits))
        .map_err(ProviderFetchError::fatal_limit)?;
    let mut parsed =
        clash_parser::parse_clash_proxies(&proxies, &request.subscription_id, &request.now, id_gen);
    if request.filter.is_some() || request.exclude_filter.is_some() {
        let mut warns = Vec::new();
        parsed.servers = clash_parser::apply_provider_filters(
            std::mem::take(&mut parsed.servers),
            request.filter.as_deref(),
            request.exclude_filter.as_deref(),
            &mut |message| warns.push(message),
            &request.source,
        );
        parsed.warnings.extend(warns);
    }
    if let Some(override_value) = request.override_value.as_ref() {
        clash_parser::apply_override(&mut parsed.servers, override_value);
    }
    for server in &mut parsed.servers {
        server.provider_name = Some(request.provider_name.clone());
    }
    for warning in &mut parsed.warnings {
        *warning = format!("[{}] {warning}", request.provider_name);
    }
    let output_metrics =
        measure_parse_output_typed(&parsed, request.limits).map_err(|error| match error.kind {
            SubscriptionParseErrorKind::Limit => ProviderFetchError::fatal_limit(error.message),
            SubscriptionParseErrorKind::Parse => ProviderFetchError::transient(error.message),
        })?;
    Ok(ProviderParsedOutput {
        parsed,
        output_metrics,
    })
}

/// proxy-providers 编排产出。上游 `ResolveProvidersResult`。
#[derive(Debug, Default)]
pub struct ProviderResolveResult {
    /// 各 provider 解析出的节点（已标 `provider_name`，供调用方按 provider 精确 merge-only）。
    pub servers: Vec<ServerConfig>,
    pub warnings: Vec<String>,
    /// Exact metrics for `servers` and `warnings`. The operation's initial inline metric lives in
    /// `ProviderResolveLimits`; this field intentionally represents provider-owned retained data
    /// only, so aggregation can compose the two without serializing either vector.
    pub output_metrics: ParseOutputMetrics,
    /// 任一 provider **transient** 失败（拉取/解析异常）→ 调用方 reconcile 改 merge-only 防穿仓。
    pub any_failed: bool,
    /// transient 失败的 provider 名（供 provider 级精确 merge-only）。
    pub failed_providers: Vec<String>,
    /// 调用方请求取消；该结果必须丢弃，不得进入 reconcile/commit。
    pub cancelled: bool,
    /// Operation-wide resource budget violation. Callers must fail closed and discard all results.
    pub fatal_error: Option<ProviderFatalError>,
}

/// provider 拉取/解析的资源边界。
#[derive(Debug, Clone, Copy)]
pub struct ProviderResolveLimits {
    pub max_providers: usize,
    /// 同时 poll 的 provider 网络请求数（必须大于 0；0 按 1 处理）。
    pub max_concurrent_fetches: usize,
    /// 单 provider 正文上限。运行时传输仍应更早流式截断；这里是纵深防御。
    pub max_provider_body_bytes: usize,
    /// 同时完成、等待按声明序解析的正文预算。
    pub max_buffered_body_bytes: usize,
    /// Sum of provider bodies consumed by the operation (not merely concurrent buffered bytes).
    pub max_total_provider_body_bytes: usize,
    pub max_nodes_per_provider: usize,
    pub max_total_nodes: usize,
    pub max_warnings: usize,
    pub max_output_bytes: usize,
    /// Exact already-retained inline output for this operation. Production supplies the metric
    /// measured by the main parser worker; generic callers use the empty default.
    pub initial_output_metrics: ParseOutputMetrics,
}

impl Default for ProviderResolveLimits {
    fn default() -> Self {
        Self {
            max_providers: 8,
            max_concurrent_fetches: 3,
            max_provider_body_bytes: MAX_BODY_BYTES,
            max_buffered_body_bytes: MAX_PROVIDER_BUFFERED_BODY_BYTES,
            max_total_provider_body_bytes: MAX_PROVIDER_BUFFERED_BODY_BYTES,
            max_nodes_per_provider: 20_000,
            max_total_nodes: 50_000,
            max_warnings: 512,
            max_output_bytes: 64 * 1024 * 1024,
            initial_output_metrics: ParseOutputMetrics::default(),
        }
    }
}

#[derive(Debug, Default)]
struct ProviderResolveControlInner {
    cancelled: AtomicBool,
    notify: tokio::sync::Notify,
}

/// 可由 operation registry 持有的 provider 取消句柄。
///
/// 取消会唤醒当前等待并丢弃尚未解析的正文；resolver 返回 `cancelled=true`，调用方不得 commit。
#[derive(Debug, Clone, Default)]
pub struct ProviderResolveControl {
    inner: Arc<ProviderResolveControlInner>,
}

impl ProviderResolveControl {
    pub fn cancel(&self) {
        self.inner.cancelled.store(true, Ordering::Release);
        self.inner.notify.notify_waiters();
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire)
    }

    /// 等待取消；先注册通知再复核原子位，避免 check→wait 间丢通知。
    pub async fn cancelled(&self) {
        loop {
            let notified = self.inner.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

/// 多源 proxy-providers 编排（上游 `resolveProxyProviders` 1:1，运行时层）。
///
/// 逐 provider 验证 `type:http` + `url` 后，合法正文按资源预算**有界并发拉取**；结果按声明序即时
/// 解析、分配 ID、应用 filter/override。默认 3 并发，最多 8 项的最坏网络墙钟是三批而非 8 项串行；
/// 声明顺序、节点顺序和 `&mut id_gen` 的既有语义不变。成功节点标 `provider_name`。
///
/// # 「进不进 `failed_providers`」的唯一判据：**这一轮拿不到它的节点，是不是意味着它真下架了**
///
/// 进名单 = 该 provider 名下的存量节点本轮**不删**（宁滞留不误删）。三类必须进：
///
/// | 形态 | 为什么不能当「真下架」 |
/// |---|---|
/// | transient 拉取/解析失败 | 超时/5xx/WAF 错误页，下轮可能就好 |
/// | **被 `max_providers` 截断**（第 9+ 个） | 我们**压根没拉**它 —— 拿不到 ≠ 下架。此前不进名单 → 它名下节点**每轮都被真删**（且下轮又被截断，永远删不完/删了白删） |
/// | **0 节点** | 机场返 200 空正文 / `filter` 因上游改名临时滤尽 —— 与主正文「0 节点 → merge-only」（命令层 `perform_subscription_update` 第 4 步）**同口径**，不能一边保守一边激进 |
///
/// 不进名单的只有 permanent：配置面非法（`type` 不支持 / 缺 `url` / 配置非对象）与
/// permanent 拉取失败（4xx / SSRF 拒绝）—— 这些重试不转好，硬保留只会让下架节点无限滞留。
///
/// **残留（如实登记）**：一个**永久**变空的 provider（机场真的清空了它）会让存量节点一直留着。
/// 无 per-provider 持久状态就实现不了「宽限 N 轮」，而两害相权：误删是**不可逆**的（用户丢节点 id +
/// 选中项 + 本地编辑），滞留是**用户可见且可手动删**的。方向与主正文一致。
///
/// `fetch_text` 注入正文拉取（含安全校验，由运行时层实现 safe-redirect-fetch + read body）。
pub async fn resolve_proxy_providers<F>(
    providers: &serde_yaml::Value,
    subscription_id: &str,
    now: &str,
    max_providers: usize,
    fetch_text: &F,
    id_gen: &mut impl FnMut() -> String,
) -> ProviderResolveResult
where
    F: Fn(
            &str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<String, ProviderFetchError>> + Send>,
        > + Send
        + Sync,
{
    resolve_proxy_providers_controlled(
        providers,
        subscription_id,
        now,
        ProviderResolveLimits {
            max_providers,
            ..Default::default()
        },
        &ProviderResolveControl::default(),
        fetch_text,
        id_gen,
    )
    .await
}

/// [`resolve_proxy_providers`] 的有界并发 + 可取消版本。
///
/// `buffered` 保持声明顺序，同时只保留有限个已完成正文；因此网络仍并发，而峰值正文内存由
/// `max_concurrent_fetches × max_provider_body_bytes` 与 `max_buffered_body_bytes` 共同约束。
pub async fn resolve_proxy_providers_controlled<F>(
    providers: &serde_yaml::Value,
    subscription_id: &str,
    now: &str,
    limits: ProviderResolveLimits,
    control: &ProviderResolveControl,
    fetch_text: &F,
    id_gen: &mut impl FnMut() -> String,
) -> ProviderResolveResult
where
    F: Fn(
            &str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<String, ProviderFetchError>> + Send>,
        > + Send
        + Sync,
{
    let mut parse = |request| futures::future::ready(parse_provider_request(request, id_gen));
    resolve_proxy_providers_controlled_with_parser(
        providers,
        subscription_id,
        now,
        limits,
        control,
        fetch_text,
        &mut parse,
    )
    .await
}

/// [`resolve_proxy_providers_controlled`] 的解析器注入版本。网络请求保持有界并发；每份正文按
/// 声明顺序交给异步 callback，因此运行时可把同步 serde CPU 隔离到独立固定容量线程池。
pub async fn resolve_proxy_providers_controlled_with_parser<F, P, PFut>(
    providers: &serde_yaml::Value,
    subscription_id: &str,
    now: &str,
    limits: ProviderResolveLimits,
    control: &ProviderResolveControl,
    fetch_text: &F,
    parse_provider: &mut P,
) -> ProviderResolveResult
where
    F: Fn(
            &str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<String, ProviderFetchError>> + Send>,
        > + Send
        + Sync,
    P: FnMut(ProviderParseRequest) -> PFut,
    PFut: std::future::Future<Output = Result<ProviderParsedOutput, ProviderFetchError>>,
{
    let mut out = ProviderResolveResult::default();
    // `initial_output_metrics` was measured while parsing the main subscription on the isolated
    // worker. From here onward only checked integer arithmetic happens on Tokio.
    let mut operation_output_metrics = limits.initial_output_metrics;
    let Some(map) = providers.as_mapping() else {
        return out;
    };

    if control.is_cancelled() {
        out.cancelled = true;
        return out;
    }

    let total = map.len();
    if total > limits.max_providers {
        // 被截断的 provider **一个都没拉过** → 它们名下的存量节点本轮必须保住（见函数文档表格）。
        let truncated: Vec<String> = map
            .iter()
            .skip(limits.max_providers)
            .map(|(name_v, _)| provider_name_of(name_v))
            .collect();
        if let Err(error) = append_retained_warning(
            &mut out,
            &mut operation_output_metrics,
            format!(
                "proxy-providers 数量 {total} 超上限 {}，已截断（未拉取: {}；\
             其名下存量节点本轮保留，不作下架处理）",
                limits.max_providers,
                truncated.join(", ")
            ),
            limits,
        ) {
            out.fatal_error = Some(error);
            return out;
        }
        out.any_failed = true;
        out.failed_providers.extend(truncated);
    }

    enum PreparedProvider {
        Invalid {
            name: String,
            reason: String,
        },
        Fetch {
            name: String,
            url: String,
            filter: Option<String>,
            exclude: Option<String>,
            override_val: Option<serde_yaml::Value>,
        },
    }

    let mut prepared = Vec::with_capacity(map.len().min(limits.max_providers));
    for (name_v, prov) in map.iter().take(limits.max_providers) {
        let name = provider_name_of(name_v);
        if prov.as_mapping().is_none() {
            prepared.push(PreparedProvider::Invalid {
                name,
                reason: "配置非对象".to_string(),
            });
            continue;
        }
        let ty = prov
            .get("type")
            .and_then(serde_yaml::Value::as_str)
            .map(str::to_ascii_lowercase);
        match ty.as_deref() {
            Some("file") => {
                prepared.push(PreparedProvider::Invalid {
                    name,
                    reason: "type:file 不支持，安全面忽略".to_string(),
                });
                continue;
            }
            Some("http") => {}
            other => {
                prepared.push(PreparedProvider::Invalid {
                    name,
                    reason: format!("不支持的 type: {}", other.unwrap_or("(缺省)")),
                });
                continue;
            }
        }
        let Some(url) = prov
            .get("url")
            .and_then(serde_yaml::Value::as_str)
            .filter(|s| !s.is_empty())
        else {
            prepared.push(PreparedProvider::Invalid {
                name,
                reason: "缺 url".to_string(),
            });
            continue;
        };
        prepared.push(PreparedProvider::Fetch {
            name,
            url: url.to_string(),
            filter: prov
                .get("filter")
                .and_then(serde_yaml::Value::as_str)
                .map(str::to_string),
            exclude: prov
                .get("exclude-filter")
                .and_then(serde_yaml::Value::as_str)
                .map(str::to_string),
            override_val: prov.get("override").cloned(),
        });
    }

    enum ControlledFetchError {
        Cancelled,
        Fetch(ProviderFetchError),
    }

    let per_body_limit = limits
        .max_provider_body_bytes
        .min(limits.max_buffered_body_bytes)
        .max(1);
    let concurrency_by_bytes = limits.max_buffered_body_bytes / per_body_limit;
    let concurrency = limits
        .max_concurrent_fetches
        .max(1)
        .min(concurrency_by_bytes.max(1));
    // `buffered` 同时 poll 多个网络 future、但按输入顺序 yield；每拿到一个结果就立刻解析并释放正文，
    // 不再像 `join_all` 那样把所有 provider String 一次性留在内存。
    let fetch_futures: Vec<_> = prepared
        .iter()
        .filter_map(|entry| match entry {
            PreparedProvider::Fetch { url, .. } => {
                let future = fetch_text(url);
                let control = control.clone();
                Some(async move {
                    if control.is_cancelled() {
                        return Err(ControlledFetchError::Cancelled);
                    }
                    let cancel = Box::pin(control.cancelled());
                    let result = match futures::future::select(future, cancel).await {
                        futures::future::Either::Left((result, _)) => {
                            result.map_err(ControlledFetchError::Fetch)?
                        }
                        futures::future::Either::Right(((), _)) => {
                            return Err(ControlledFetchError::Cancelled);
                        }
                    };
                    if control.is_cancelled() {
                        return Err(ControlledFetchError::Cancelled);
                    }
                    if result.len() > per_body_limit {
                        return Err(ControlledFetchError::Fetch(ProviderFetchError::transient(
                            format!(
                            "provider 响应体积 {} 字节超过本轮内存上限 {per_body_limit}，已丢弃",
                            result.len()
                        ),
                        )));
                    }
                    Ok(result)
                })
            }
            PreparedProvider::Invalid { .. } => None,
        })
        .collect();
    let mut fetched = futures::stream::iter(fetch_futures).buffered(concurrency);

    let mut succeeded = 0usize;
    let mut total_body_bytes = 0usize;
    let attempted = prepared.len();
    let mut failures: Vec<String> = Vec::new();

    for entry in prepared {
        let (name, url, filter, exclude, override_val) = match entry {
            PreparedProvider::Invalid { name, reason } => {
                // 配置面非法是 permanent：只记 warning，不触发 merge-only。
                failures.push(format!("{name}({reason})"));
                continue;
            }
            PreparedProvider::Fetch {
                name,
                url,
                filter,
                exclude,
                override_val,
            } => (name, url, filter, exclude, override_val),
        };
        let fetched_text = fetched
            .next()
            .await
            .expect("每个合法 provider 必须恰有一个并发拉取结果");
        let fetched_text = match fetched_text {
            Ok(text) => Ok(text),
            Err(ControlledFetchError::Fetch(e)) => Err(e),
            Err(ControlledFetchError::Cancelled) => {
                out.cancelled = true;
                out.any_failed = true;
                out.warnings
                    .push("proxy-providers 已取消，未解析结果已丢弃".to_string());
                return out;
            }
        };
        if control.is_cancelled() {
            out.cancelled = true;
            out.any_failed = true;
            out.warnings
                .push("proxy-providers 已取消，未解析结果已丢弃".to_string());
            return out;
        }
        let parsed = match fetched_text {
            Ok(text) => {
                total_body_bytes = total_body_bytes.saturating_add(text.len());
                if total_body_bytes > limits.max_total_provider_body_bytes {
                    out.fatal_error = Some(ProviderFatalError::parse_limit(format!(
                        "provider 正文累计超过上限 {} 字节，已拒绝整次操作",
                        limits.max_total_provider_body_bytes
                    )));
                    return out;
                }
                // A provider may be large on its own, but it only gets the exact remaining
                // operation output budget. The array boundary credit avoids falsely rejecting a
                // legal first/small provider because `[]`/`,` are not duplicated on merge.
                let max_output_bytes = match operation_output_metrics
                    .max_next_nonempty_server_output_bytes(limits.max_output_bytes)
                {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        out.fatal_error = Some(ProviderFatalError::parse_limit(error.message));
                        return out;
                    }
                };
                let parse = parse_provider(ProviderParseRequest {
                    text,
                    provider_name: name.clone(),
                    filter,
                    exclude_filter: exclude,
                    override_value: override_val,
                    subscription_id: subscription_id.to_owned(),
                    now: now.to_owned(),
                    source: url,
                    limits: SubscriptionParseLimits {
                        max_body_bytes: limits.max_provider_body_bytes,
                        max_nodes: limits.max_nodes_per_provider,
                        max_warnings: limits.max_warnings,
                        max_output_bytes,
                        ..Default::default()
                    },
                });
                let cancel = Box::pin(control.cancelled());
                match futures::future::select(Box::pin(parse), cancel).await {
                    futures::future::Either::Left((result, _)) => result,
                    futures::future::Either::Right(((), _)) => {
                        out.cancelled = true;
                        out.any_failed = true;
                        out.warnings
                            .push("proxy-providers 已取消，未解析结果已丢弃".to_string());
                        return out;
                    }
                }
            }
            Err(error) => Err(error),
        };
        match parsed {
            Ok(ProviderParsedOutput {
                mut parsed,
                output_metrics,
            }) => {
                if parsed.servers.is_empty() {
                    // HTTP 成功但解析/过滤后 0 节点 —— **不判 permanent**（此前如此，是本条 review 的缺陷）。
                    // 机场返 200 空正文、或 `filter` 因上游改名临时滤尽，都会走到这里；判 permanent
                    // 意味着该 provider 名下**全部存量节点当场删光**，而主正文遇到同样的「0 节点」
                    // 是走 merge-only 不删的（命令层 `perform_subscription_update` 第 4 步）——
                    // 同一现象两套方向，保守的那套才对（误删不可逆，滞留可手删）。
                    out.any_failed = true;
                    out.failed_providers.push(name.clone());
                    failures.push(format!("{name}(0 节点，存量保留不作下架)"));
                    continue;
                }
                succeeded += 1;
                if out.servers.len().saturating_add(parsed.servers.len()) > limits.max_total_nodes {
                    out.fatal_error = Some(ProviderFatalError::parse_limit(format!(
                        "provider 节点累计超过上限 {}，已拒绝整次操作",
                        limits.max_total_nodes
                    )));
                    return out;
                }
                if out.warnings.len().saturating_add(parsed.warnings.len()) > limits.max_warnings {
                    out.fatal_error = Some(ProviderFatalError::parse_limit(format!(
                        "provider 告警累计超过上限 {}，已拒绝整次操作",
                        limits.max_warnings
                    )));
                    return out;
                }
                let provider_output_metrics = match out.output_metrics.checked_add(output_metrics) {
                    Ok(metrics) => metrics,
                    Err(error) => {
                        out.fatal_error = Some(ProviderFatalError::parse_limit(error.message));
                        return out;
                    }
                };
                let next_operation_output_metrics =
                    match operation_output_metrics.checked_add(output_metrics) {
                        Ok(metrics) => metrics,
                        Err(error) => {
                            out.fatal_error = Some(ProviderFatalError::parse_limit(error.message));
                            return out;
                        }
                    };
                if let Err(error) =
                    next_operation_output_metrics.enforce_max_output_bytes(limits.max_output_bytes)
                {
                    out.fatal_error = Some(ProviderFatalError::parse_limit(error.message));
                    return out;
                }
                out.warnings.append(&mut parsed.warnings);
                out.servers.append(&mut parsed.servers);
                out.output_metrics = provider_output_metrics;
                operation_output_metrics = next_operation_output_metrics;
            }
            Err(e) if e.fatal.is_some() => {
                out.fatal_error = e.fatal_error();
                return out;
            }
            // permanent（4xx / SSRF 拒绝 / URL 非法）→ 仅 warn，**不**保护存量：它确实拿不回来了，
            // 硬保留会把整条订阅永久钉在 partial（连主正文内联的真下架节点都删不掉，且每轮 save+广播）。
            Err(e) if e.permanent => {
                failures.push(format!("{name}({} · 永久失败)", e.message));
            }
            Err(e) => {
                out.any_failed = true;
                out.failed_providers.push(name.clone());
                failures.push(format!("{name}({})", e.message));
            }
        }
    }

    if !failures.is_empty() {
        if let Err(error) = append_retained_warning(
            &mut out,
            &mut operation_output_metrics,
            format!(
                "proxy-providers {succeeded}/{attempted} 成功，失败: {}",
                failures.join(", ")
            ),
            limits,
        ) {
            out.fatal_error = Some(error);
            return out;
        }
    }
    // 相邻去重：截断腿（`skip`）与失败腿（`take`）不相交，唯一的重复来源是**非字符串键**
    // 全被 [`provider_name_of`] 归一成 `(unnamed)` —— 那些恰好是相邻 push 的，`dedup` 够用。
    // （`leftover_survives_partial` 只做 `any` 匹配，重复不影响判定，只是让告警文案出现两遍同名。）
    out.failed_providers.dedup();
    out
}

/// Append a resolver-generated warning while keeping both provider-only and operation-wide
/// metrics exact. These messages are retained into the final subscription result, so they must
/// consume the same warning/output budget as parser-produced warnings.
fn append_retained_warning(
    out: &mut ProviderResolveResult,
    operation_output_metrics: &mut ParseOutputMetrics,
    message: String,
    limits: ProviderResolveLimits,
) -> Result<(), ProviderFatalError> {
    let warning = ParseOutputMetrics::warning(&message);
    let provider_next = out
        .output_metrics
        .checked_add(warning)
        .map_err(|error| ProviderFatalError::parse_limit(error.message))?;
    if provider_next.warning_count() > limits.max_warnings {
        return Err(ProviderFatalError::parse_limit(format!(
            "provider 告警累计超过上限 {}，已拒绝整次操作",
            limits.max_warnings
        )));
    }
    let operation_next = operation_output_metrics
        .checked_add(warning)
        .map_err(|error| ProviderFatalError::parse_limit(error.message))?;
    operation_next
        .enforce_max_output_bytes(limits.max_output_bytes)
        .map_err(|error| ProviderFatalError::parse_limit(error.message))?;
    out.warnings.push(message);
    out.output_metrics = provider_next;
    *operation_output_metrics = operation_next;
    Ok(())
}

/// provider 名（非字符串键 → `(unnamed)`）。截断腿与失败腿共用同一取名口径，不容许两处漂移。
fn provider_name_of(name_v: &serde_yaml::Value) -> String {
    name_v
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| "(unnamed)".to_string())
}
