//! 订阅 URL 安全校验 + 拉取 + 解析调度（Polaris SubscriptionService 的纯逻辑切片 1:1 移植）。
//!
//! 纯逻辑：真实 HTTP 请求由注入的 [`crate::safe_redirect::HttpClient`] trait 承载（测试 mock /
//! 本地 HTTP server，不触碰宿主网络）。职责：
//! - [`fetch_subscription_full`]：起始 URL 协议校验 + SSRF guard + safe-redirect-fetch（逐跳复检）
//!   + HTTP 状态校验 + 体积闸，**返回正文文本**。
//! - [`parse_subscription`]：判定格式（Clash / sing-box JSON / base64 / url-list）后分发解析；
//!   Clash 走 [`crate::clash_parser`]，其余格式由调用方（运行时层）按需扩展。
//! - 错误分类见 [`crate::subscription_error`]（审计 §C4）。
//!
//! proxy-providers 在本层完成“有界并发拉取、按声明序即时解析”的编排；真实 HTTP 与超时仍由运行时
//! 注入。这样避免串行等待，也不把最多 8 份正文同时留在内存；节点顺序与 ID 分配顺序稳定。
//!
//! **已移植**：条件 GET（`If-None-Match` / `If-Modified-Since` → 304 短路，见 [`Conditional`] 与
//! [`fetch_subscription_with_meta`]）与 `subscription-userinfo`（流量/到期元数据，见
//! [`parse_user_info`] / [`SubscriptionUserInfo`]）。304 **不再**归
//! [`SubscriptionErrorKind::Http`]，而是短路成 `not_modified=true` —— 且带 fail-safe：
//! 本次未发条件头却收 304 一律不认（见 `fetch_core` 步骤 3.5）。

#![forbid(unsafe_code)]

use std::time::{Duration, Instant};
use url::Url;

use polaris_config_engine::user_config::server_config::ServerConfig;

use crate::clash_parser::{self, ClashParseResult};
use crate::safe_redirect::{
    safe_redirect_fetch_until, HttpClient, SafeFetchRejectReason, SafeRedirectFetchOptions,
};
use crate::singbox_import::ImportOrigin;
use crate::ssrf::DnsLookup;
use crate::subscription_error::{
    classify_subscription_error, SubscriptionErrorKind, SubscriptionErrorSignal,
};

/// 订阅响应体上限（10 MB）。上游 `SubscriptionService.MAX_BODY_BYTES` 同口径，
/// 与 `local_import_parse` 的体积闸一致（同一份正文，两条入口不该有两个阈值）。
///
/// 双闸：content-length 预检（早拒）+ 读取侧字节累计（content-length 可缺失/撒谎）。
/// 兼作 YAML 锚点炸弹的输入面收窄。
pub const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

/// 主订阅拉取超时（30s）。上游 `MAIN_FETCH_TIMEOUT_MS`。
/// 防 slow-loris 挂死拉取流水线（scheduler `isRunning` 永真 → 后续更新全卡）。
pub const MAIN_FETCH_TIMEOUT_MS: u64 = 30_000;

/// proxy-provider 拉取超时（15s，比主订阅紧）。Polaris provider 编排口径。
pub const PROVIDER_FETCH_TIMEOUT_MS: u64 = 15_000;

/// provider 并发正文的默认内存预算。单正文仍受 [`MAX_BODY_BYTES`] 约束；默认最多同时保留三份
/// 10 MiB 正文，给 YAML/JSON 解析临时对象留出余量。
pub const MAX_PROVIDER_BUFFERED_BODY_BYTES: usize = 32 * 1024 * 1024;

/// End-to-end parser/output budget. JSON receives a structural preflight before `serde_json`
/// materializes its AST; YAML cannot be bounded before `serde_yaml` materializes its AST with the
/// current API, so YAML retains post-AST and post-merge limits. Neither parser is physically
/// interruptible, which is why runtime isolation supplies logical cancellation/non-blocking exit.
#[derive(Debug, Clone, Copy)]
pub struct SubscriptionParseLimits {
    pub max_body_bytes: usize,
    pub max_structure_depth: usize,
    pub max_container_items: usize,
    pub max_scalar_bytes: usize,
    pub max_merge_expansions: usize,
    pub max_nodes: usize,
    pub max_warnings: usize,
    pub max_output_bytes: usize,
}

impl Default for SubscriptionParseLimits {
    fn default() -> Self {
        Self {
            max_body_bytes: MAX_BODY_BYTES,
            max_structure_depth: 128,
            max_container_items: 200_000,
            max_scalar_bytes: 32 * 1024 * 1024,
            max_merge_expansions: 200_000,
            max_nodes: 50_000,
            max_warnings: 512,
            max_output_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Stable source category for a bounded subscription parse failure.  This deliberately carries no
/// inference over the diagnostic text: callers can serialize the category without making a UI
/// contract depend on Chinese/serde error wording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionParseErrorKind {
    Parse,
    Limit,
}

/// A bounded parse failure with its source category retained separately from the diagnostic.
#[derive(Debug, Clone)]
pub struct SubscriptionParseError {
    pub kind: SubscriptionParseErrorKind,
    pub message: String,
}

impl SubscriptionParseError {
    #[must_use]
    pub fn parse(message: impl Into<String>) -> Self {
        Self {
            kind: SubscriptionParseErrorKind::Parse,
            message: message.into(),
        }
    }

    #[must_use]
    pub fn limit(message: impl Into<String>) -> Self {
        Self {
            kind: SubscriptionParseErrorKind::Limit,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for SubscriptionParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for SubscriptionParseError {}

impl From<clash_parser::ClashDocumentError> for SubscriptionParseError {
    fn from(error: clash_parser::ClashDocumentError) -> Self {
        match error.kind {
            clash_parser::ClashDocumentErrorKind::Parse => Self::parse(error.message),
            clash_parser::ClashDocumentErrorKind::Limit => Self::limit(error.message),
        }
    }
}

/// 默认订阅 UA：中性 `Polaris/<version>`（不带 clash.meta/mihomo 标识）。
///
/// **勿用于 GitHub API / 资源下载**：带版本号会泄漏客户端指纹，那条链路应使用应用自标识 UA。
pub fn default_subscription_user_agent(version: &str) -> String {
    format!("Polaris/{version}")
}

/// 订阅流量/到期元数据（`Subscription-UserInfo` 响应头解析）。上游 `SubscriptionConfig['userInfo']`。
///
/// 字节数与到期时间戳均以 `u64` 承载（上游 用 `number`；流量总量可超 `u32`）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubscriptionUserInfo {
    /// 已上传字节。
    pub upload: Option<u64>,
    /// 已下载字节。
    pub download: Option<u64>,
    /// 总流量字节。
    pub total: Option<u64>,
    /// 到期时间（Unix 秒）。
    pub expire: Option<u64>,
}

impl SubscriptionUserInfo {
    /// 至少解出一个字段才算「有」（对齐 上游 `Object.keys(result).length > 0`）。
    fn is_present(&self) -> bool {
        self.upload.is_some()
            || self.download.is_some()
            || self.total.is_some()
            || self.expire.is_some()
    }

    /// 序列化为前端 `userInfo` 形态（缺省字段不落键，对齐 TS `skip_serializing_if`）。
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        if let Some(v) = self.upload {
            m.insert("upload".into(), v.into());
        }
        if let Some(v) = self.download {
            m.insert("download".into(), v.into());
        }
        if let Some(v) = self.total {
            m.insert("total".into(), v.into());
        }
        if let Some(v) = self.expire {
            m.insert("expire".into(), v.into());
        }
        serde_json::Value::Object(m)
    }
}

/// 解析 `Subscription-UserInfo` 头（`upload=..; download=..; total=..; expire=..`）。
///
/// 上游 `SubscriptionService.parseUserInfo` 1:1：分号分段、`key=value`、`parseInt` 容错
/// （非数字段跳过），全缺 → `None`。`parseInt` 语义 = 取前导十进制数字（`"123abc"` → 123），
/// 用 `u64` 承载（负数/溢出 → 跳过该字段，不整体失败）。
#[must_use]
pub fn parse_user_info(header: Option<&str>) -> Option<SubscriptionUserInfo> {
    let header = header?;
    let mut result = SubscriptionUserInfo::default();
    for part in header.split(';') {
        let part = part.trim();
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        let Some(num) = parse_int_prefix(value.trim()) else {
            continue;
        };
        match key.trim() {
            "upload" => result.upload = Some(num),
            "download" => result.download = Some(num),
            "total" => result.total = Some(num),
            "expire" => result.expire = Some(num),
            _ => {}
        }
    }
    result.is_present().then_some(result)
}

/// JS `parseInt(s, 10)` 的窄化：取前导十进制数字（首个非数字截断），无前导数字 → `None`。
/// 机场偶尔在 total 后带单位/注释（`"107374182400 bytes"`）；忠实 `parseInt` 只取数字段。
fn parse_int_prefix(s: &str) -> Option<u64> {
    let digits: String = s.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse::<u64>().ok()
    }
}

/// 条件 GET 验证器（上次 200 响应的 `ETag` / `Last-Modified`）。上游 `{ etag, lastModified }`。
///
/// 缓存验证器非凭据（逐跳携带无泄漏面）；缺省 = 首次/无验证器 → 全量 GET（零回归）。
#[derive(Debug, Clone, Default)]
pub struct Conditional {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

impl Conditional {
    fn has_any(&self) -> bool {
        self.etag.is_some() || self.last_modified.is_some()
    }
}

/// 订阅拉取产出（正文 + 元数据）。上游 `fetchSubscriptionText` 返回体。
///
/// `not_modified=true`（304 命中，仅当本次确实发了条件头）→ `text` 空、调用方短路 parse/reconcile。
#[derive(Debug, Clone, Default)]
pub struct FetchedSubscription {
    pub text: String,
    pub user_info: Option<SubscriptionUserInfo>,
    /// 本次 200 响应的验证器（回写 sub，下次条件 GET 用）。
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    /// 304 Not Modified（条件 GET 命中）。
    pub not_modified: bool,
}

/// 脱敏 URL 供错误文案/日志使用：**去掉 query 与 userinfo**。
///
/// 订阅 token 就在 query 里（`?token=xxx`），原样进错误文案 = 凭据进日志/上报。
/// 上游 `SubscriptionService.redactUrl` 同职责；此处额外清 userinfo（`user:pass@`），
/// 且不走 `origin`——`origin` 对非特殊 scheme（如 `ftp:`）会序列化成 `null`，
/// 而「协议不支持」的错误文案恰恰需要显示原始 scheme 才有诊断价值。
pub fn redact_url(url: &str) -> String {
    match Url::parse(url) {
        Ok(mut u) => {
            let had_query = u.query().is_some();
            u.set_query(None);
            u.set_fragment(None);
            let _ = u.set_username("");
            let _ = u.set_password(None);
            if had_query {
                format!("{u}?<redacted>")
            } else {
                u.to_string()
            }
        }
        // 非法 URL 无法结构化处理：截到 `?` 前兜底去 query。
        Err(_) => match url.find('?') {
            Some(q) => format!("{}?<redacted>", &url[..q]),
            None => url.to_string(),
        },
    }
}

/// 订阅拉取失败。`kind` 在**抛出点**即确定（不回头 re-parse 自己的字符串），
/// `http_status` 仅 [`SubscriptionErrorKind::Http`] 时有值。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionFetchError {
    pub kind: SubscriptionErrorKind,
    pub message: String,
    pub http_status: Option<u16>,
}

impl SubscriptionFetchError {
    fn new(kind: SubscriptionErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            http_status: None,
        }
    }
}

impl std::fmt::Display for SubscriptionFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for SubscriptionFetchError {}

/// 订阅内容格式探测结果。上游 `ImportFormat`（订阅侧子集）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionFormat {
    /// Clash / mihomo YAML（含 proxies 或 proxy-providers）。
    Clash,
    /// sing-box JSON outbound 数组（outbound 用扁平 `type`）。
    SingboxJson,
    /// Xray / v2ray JSON（outbound 用 `protocol`+`settings`+`streamSettings`）。
    XrayJson,
    /// base64 编码的分享链接列表。
    Base64,
    /// 纯文本分享链接列表（vless://... 等，每行一条）。
    UrlList,
    /// 无法识别。
    Unknown,
}

/// 拉取订阅正文（协议校验 → SSRF guard 逐跳复检 → HTTP 状态校验 → 体积闸 → 正文）。
///
/// **这是拉取流水线拿到正文的唯一入口**，产出直接喂 [`parse_subscription`]。
///
/// 安全与健壮性逐层（顺序即优先级）：
/// 1. **协议闸**：起始 URL 须 http(s) —— `file://`/`ftp://` 直接拒（错误文案带脱敏 URL）。
/// 2. **SSRF guard**：首跳 + **每一跳 Location** 都过 [`crate::ssrf::assert_host_allowed`]
///    （由 [`crate::safe_redirect::safe_redirect_fetch_until`] 内部执行）。首跳单独再 guard 一次是多余的——
///    旧实现那次重复调用已随本次重写移除。`exempt_fake_ip` **仅实际经代理时**传 true。
/// 3. **重定向**：`redirect: manual` 自管链，上限 5 跳（[`crate::safe_redirect::safe_redirect_fetch_until`] 默认）。
/// 4. **HTTP 状态**：非 2xx → [`SubscriptionErrorKind::Http`] 并带 status。
/// 5. **体积闸**：content-length 预检 + 正文字节复检，双闸 [`MAX_BODY_BYTES`]。
///    （实现侧还须在**流式读取**时截断，见 [`FetchInit::max_body_bytes`](crate::safe_redirect::FetchInit::max_body_bytes)——
///    到了这层 body 已在内存里，此闸只是纵深防御，防不住恶意实现。）
/// 6. **超时**：`timeout_ms` 透传实现侧（[`MAIN_FETCH_TIMEOUT_MS`] / [`PROVIDER_FETCH_TIMEOUT_MS`]）。
///
/// 上游 `SubscriptionService.fetchSubscriptionText` 的对位实现。
pub async fn fetch_subscription_full<H: HttpClient, L: DnsLookup>(
    client: &H,
    lookup: &L,
    url: &str,
    user_agent: &str,
    headers: Option<Vec<(String, String)>>,
    exempt_fake_ip: bool,
    timeout_ms: u64,
) -> Result<String, SubscriptionFetchError> {
    fetch_subscription_full_until(
        client,
        lookup,
        url,
        user_agent,
        headers,
        exempt_fake_ip,
        Instant::now() + Duration::from_millis(timeout_ms),
    )
    .await
}

/// [`fetch_subscription_full`] 的 absolute-deadline 版本。调用方可在 retry 前建立一次 deadline，
/// 所有尝试共享，保证最坏墙钟不随重试次数相乘。
pub async fn fetch_subscription_full_until<H: HttpClient, L: DnsLookup>(
    client: &H,
    lookup: &L,
    url: &str,
    user_agent: &str,
    headers: Option<Vec<(String, String)>>,
    exempt_fake_ip: bool,
    deadline: Instant,
) -> Result<String, SubscriptionFetchError> {
    fetch_subscription_full_capped_until(
        client,
        lookup,
        url,
        user_agent,
        headers,
        exempt_fake_ip,
        MAX_BODY_BYTES,
        deadline,
    )
    .await
}

/// [`fetch_subscription_full_until`] with a caller-selected streaming body cap. Provider callers
/// use this to enforce their tighter per-body budget in the transport, before aggregation/parsing.
#[allow(clippy::too_many_arguments)]
pub async fn fetch_subscription_full_capped_until<H: HttpClient, L: DnsLookup>(
    client: &H,
    lookup: &L,
    url: &str,
    user_agent: &str,
    headers: Option<Vec<(String, String)>>,
    exempt_fake_ip: bool,
    max_body_bytes: usize,
    deadline: Instant,
) -> Result<String, SubscriptionFetchError> {
    // 文本-only 入口（proxy-provider 子拉取等复用同一安全管线，不消费元数据/条件 GET）。
    // conditional=None → 不发条件头 → 304 走非 2xx Http 分支（fail-safe：无验证器不认 304）。
    fetch_core(
        client,
        lookup,
        url,
        user_agent,
        headers,
        None,
        exempt_fake_ip,
        max_body_bytes,
        deadline,
    )
    .await
    .map(|f| f.text)
}

/// 拉取订阅正文 **+ 元数据**（`Subscription-UserInfo` 流量/到期 + `ETag`/`Last-Modified` 验证器
/// + 304 条件 GET 短路）。上游 `SubscriptionService.fetchSubscriptionText` 的完整对位。
///
/// 与 [`fetch_subscription_full`] 同一安全管线（协议闸 / SSRF 逐跳 / 状态 / 体积闸），仅额外：
/// - `conditional` 非空 → 发 `If-None-Match` / `If-Modified-Since`；304（**仅当确实发了条件头**）→
///   `not_modified=true`、`text` 空，调用方短路 parse/reconcile（零节点扰动、省流省渲染）。
/// - 200 → 解析 `Subscription-UserInfo`（流量/到期）+ 回传 `etag`/`last-modified` 供回写 sub。
///
/// # Errors
///
/// 协议不支持 / SSRF 拒绝 / 非 2xx（含 304 但**未**发条件头）/ 网络错误 / 体积超限。
pub async fn fetch_subscription_with_meta<H: HttpClient, L: DnsLookup>(
    client: &H,
    lookup: &L,
    url: &str,
    user_agent: &str,
    conditional: Option<&Conditional>,
    exempt_fake_ip: bool,
    timeout_ms: u64,
) -> Result<FetchedSubscription, SubscriptionFetchError> {
    fetch_subscription_with_meta_until(
        client,
        lookup,
        url,
        user_agent,
        conditional,
        exempt_fake_ip,
        Instant::now() + Duration::from_millis(timeout_ms),
    )
    .await
}

/// [`fetch_subscription_with_meta`] 的 absolute-deadline 版本；deadline 语义同
/// [`fetch_subscription_full_until`]。
pub async fn fetch_subscription_with_meta_until<H: HttpClient, L: DnsLookup>(
    client: &H,
    lookup: &L,
    url: &str,
    user_agent: &str,
    conditional: Option<&Conditional>,
    exempt_fake_ip: bool,
    deadline: Instant,
) -> Result<FetchedSubscription, SubscriptionFetchError> {
    fetch_core(
        client,
        lookup,
        url,
        user_agent,
        None,
        conditional,
        exempt_fake_ip,
        MAX_BODY_BYTES,
        deadline,
    )
    .await
}

/// 拉取管线核心（协议闸 → SSRF 逐跳 → 条件 GET/304 → 状态 → 体积闸 → 元数据）。
///
/// `extra_headers`（provider 子拉取的透传头）与 `conditional`（条件 GET）合并后交
/// [`crate::safe_redirect::safe_redirect_fetch_until`]。`sent_conditional` 仅在实际追加了条件头时为真——用于 304 fail-safe：
/// 未发条件头却收 304（某些 CDN 违规）绝不认作 not_modified（会得空 body→0 节点→误删存量）。
#[allow(clippy::too_many_arguments)]
async fn fetch_core<H: HttpClient, L: DnsLookup>(
    client: &H,
    lookup: &L,
    url: &str,
    user_agent: &str,
    extra_headers: Option<Vec<(String, String)>>,
    conditional: Option<&Conditional>,
    exempt_fake_ip: bool,
    max_body_bytes: usize,
    deadline: Instant,
) -> Result<FetchedSubscription, SubscriptionFetchError> {
    // 1) 协议闸：仅 http(s)。非法 URL 同归 scheme（用户可见原因一致：地址不对）。
    let parsed = Url::parse(url).map_err(|_| {
        SubscriptionFetchError::new(
            SubscriptionErrorKind::Scheme,
            format!("订阅地址非法: {}", redact_url(url)),
        )
    })?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(SubscriptionFetchError::new(
            SubscriptionErrorKind::Scheme,
            format!(
                "订阅地址协议不支持（仅允许 http/https）: {}",
                redact_url(url)
            ),
        ));
    }

    // 条件 GET 头拼装（缓存验证器非凭据，逐跳携带无泄漏面）。与调用方透传头合并。
    let mut headers = extra_headers.unwrap_or_default();
    let sent_conditional = conditional.is_some_and(Conditional::has_any);
    if let Some(c) = conditional {
        if let Some(etag) = &c.etag {
            headers.push(("If-None-Match".to_string(), etag.clone()));
        }
        if let Some(lm) = &c.last_modified {
            headers.push(("If-Modified-Since".to_string(), lm.clone()));
        }
    }
    let headers = if headers.is_empty() {
        None
    } else {
        Some(headers)
    };

    // 2~3) SSRF guard（首跳 + 逐跳）+ 手动重定向链。
    let response = safe_redirect_fetch_until(
        SafeRedirectFetchOptions {
            fetch_impl: client,
            url,
            user_agent: user_agent.to_string(),
            headers,
            exempt_fake_ip,
            max_redirects: None,
            timeout_ms: None,
            max_body_bytes: Some(max_body_bytes),
            lookup,
        },
        deadline,
    )
    .await
    .map_err(|e| match e.reason {
        // 安全拒绝：原文案冒泡（含 hostname / 解析结果，诊断需要）。
        SafeFetchRejectReason::Ssrf | SafeFetchRejectReason::TooManyRedirects => {
            SubscriptionFetchError::new(SubscriptionErrorKind::Ssrf, e.message)
        }
        SafeFetchRejectReason::RedirectProtocol => {
            SubscriptionFetchError::new(SubscriptionErrorKind::Scheme, e.message)
        }
        SafeFetchRejectReason::Timeout => {
            SubscriptionFetchError::new(SubscriptionErrorKind::Timeout, e.message)
        }
        // 网络错误：message 不透明（实现侧的 io 错误串）→ 交 §C4 分类器判 dns/timeout/refused。
        SafeFetchRejectReason::Network => {
            let cls = classify_subscription_error(&SubscriptionErrorSignal {
                message: Some(e.message.clone()),
                ..Default::default()
            });
            SubscriptionFetchError {
                kind: cls.kind,
                message: e.message,
                http_status: None,
            }
        }
    })?;

    // 3.5) 条件 GET 命中（304）——**仅当本次确实发了条件头**才认（fail-safe，见函数 doc）。
    //      短路：不读 body、不 parse/reconcile（零节点扰动）；仍回传验证器供刷新。
    if response.status == 304 && sent_conditional {
        return Ok(FetchedSubscription {
            not_modified: true,
            etag: response.header("etag").map(str::to_string),
            last_modified: response.header("last-modified").map(str::to_string),
            ..Default::default()
        });
    }

    // 4) HTTP 状态校验。
    if !(200..300).contains(&response.status) {
        return Err(SubscriptionFetchError {
            kind: SubscriptionErrorKind::Http,
            message: format!("订阅服务器返回 HTTP {}", response.status),
            http_status: Some(response.status),
        });
    }

    // 5) 体积闸：content-length 预检（实现侧若已流式截断则到不了这里；此为纵深防御）。
    if let Some(cl) = response.header("content-length") {
        if let Ok(n) = cl.trim().parse::<usize>() {
            if n > max_body_bytes {
                return Err(SubscriptionFetchError::new(
                    SubscriptionErrorKind::TooLarge,
                    format!("订阅响应体积 {n} 字节超过上限 {max_body_bytes}，已拒绝"),
                ));
            }
        }
    }
    if response.body.len() > max_body_bytes {
        return Err(SubscriptionFetchError::new(
            SubscriptionErrorKind::TooLarge,
            format!(
                "订阅响应体积 {} 字节超过上限 {max_body_bytes}，已拒绝",
                response.body.len()
            ),
        ));
    }

    // 6) 元数据：Subscription-UserInfo（流量/到期）+ 验证器（下次条件 GET）。
    let user_info = parse_user_info(response.header("subscription-userinfo"));
    let etag = response.header("etag").map(str::to_string);
    let last_modified = response.header("last-modified").map(str::to_string);

    // 正文必须是 UTF-8。lossy 转换最多可把每个坏字节膨胀成三个 replacement bytes，绕过传输
    // 字节 cap 后放大 queued+active parser input；订阅的 YAML/JSON/base64/share links 都要求
    // UTF-8/ASCII，故坏编码 fail-closed。
    let text = String::from_utf8(response.body).map_err(|_| {
        SubscriptionFetchError::new(
            SubscriptionErrorKind::InvalidEncoding,
            "订阅正文不是有效 UTF-8，已拒绝",
        )
    })?;
    Ok(FetchedSubscription {
        text,
        user_info,
        etag,
        last_modified,
        not_modified: false,
    })
}

/// 探测订阅内容格式。Polaris 订阅内容格式判定（Clash YAML/JSON / sing-box JSON / xray JSON /
/// base64 / url-list）。**格式判定的单一真值**——`parse_subscription` 与 [`extract_proxy_providers`]
/// 都以它为准，不得各自另判一套（此前 `extract_proxy_providers` 单独判 `is_clash_probe` 就漏了 JSON 编码）。
pub fn detect_format(trimmed: &str) -> SubscriptionFormat {
    // BOM 必须在**任何判据之前**剥掉，且就长在既有的 trim 这一步上：U+FEFF 不属于 `White_Space`，
    // `trim` / `trim_start` 吃不掉它，而它同时破坏三条判据——base64 字母表（整份订阅落 `Unknown`
    // → 0 节点）、url-list 的 scheme 前缀匹配（首节点静默丢）、JSON/YAML 的首字符探针（issue #1）。
    let trimmed = trimmed.trim_start_matches('\u{feff}');
    let t = trimmed.trim_start();
    // Clash：proxies: 或 proxy-providers: 行。
    if clash_parser::is_clash_probe(t) {
        return SubscriptionFormat::Clash;
    }
    // JSON：sing-box（outbound 用扁平 `type`）/ xray（outbound 用 `protocol`+`settings`，无 `type`）。
    // 二者共用 `outbounds` 键，靠 [`crate::xray_import::looks_like_xray`] 区分（对齐 上游 parseLocalContent
    // 的 `looksXray` 判定）；`endpoints`（wireguard/tailscale）唯 sing-box。
    if t.starts_with('{') || t.starts_with('[') {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(t) {
            if let Some(format) = detect_json_format(&v) {
                return format;
            }
        }
        // JSON 解析失败但形似 → 保守判 sing-box（其解析分支返回 warning，不误吞进 url-list/base64）。
        if t.contains("\"outbounds\"") || t.contains("\"endpoints\"") {
            return SubscriptionFormat::SingboxJson;
        }
    }
    // url-list：**任一行**是受支持的分享链接（vless:// vmess:// ss:// trojan:// ...）。
    //
    // 此前只看首行、且判据松到「含 `://`」：机场把「剩余流量 / 到期时间」之类公告文本放在正文
    // 第一行时，整份订阅落 `Unknown` → 0 节点（issue #1）。改为全文扫描，同时把判据收紧成
    // [`crate::share_link::is_supported_share_url`] 的**前缀锚定**匹配——复用逐行解析用的同一份
    // 白名单，否则 `公告：详情见 https://…` 这类把 URL 当值内嵌的正文会被伪装成「格式已识别、
    // 0 节点」，反把 `Unknown` 的告警吞掉。base64 正文不受影响：其字母表不含 `:`，扫描恒不命中。
    if t.lines()
        .any(|line| crate::share_link::is_supported_share_url(line.trim()))
    {
        return SubscriptionFormat::UrlList;
    }
    // base64：尝试解码；含分享链 scheme 即 url-list。
    if let Ok(decoded) = base64_decode(trimmed) {
        if decoded.contains("://") {
            return SubscriptionFormat::Base64;
        }
    }
    SubscriptionFormat::Unknown
}

fn detect_json_format(v: &serde_json::Value) -> Option<SubscriptionFormat> {
    if let Some(outbounds) = v.get("outbounds").and_then(serde_json::Value::as_array) {
        return Some(if crate::xray_import::looks_like_xray(outbounds) {
            SubscriptionFormat::XrayJson
        } else {
            SubscriptionFormat::SingboxJson
        });
    }
    if v.get("endpoints").is_some() {
        return Some(SubscriptionFormat::SingboxJson);
    }
    // JSON Clash 必须在 sing-box/xray 后判，保持既有优先级。
    clash_parser::is_json_clash(v).then_some(SubscriptionFormat::Clash)
}

fn detect_json_format_hint(text: &str) -> SubscriptionFormat {
    if text.contains("\"outbounds\"") || text.contains("\"endpoints\"") {
        SubscriptionFormat::SingboxJson
    } else if text.contains("\"proxies\"") || text.contains("\"proxy-providers\"") {
        SubscriptionFormat::Clash
    } else {
        SubscriptionFormat::Unknown
    }
}

/// 解析订阅正文（按探测格式分发）。已建：Clash（YAML **与 JSON** 两种编码）/ base64 / url-list /
/// Xray JSON / sing-box JSON。
///
/// - **Clash**：走 [`crate::clash_parser`]（既有实现，不重写）。JSON 编码（`{"proxies":[…]}`）由
///   [`crate::clash_parser::try_load_clash_doc`] 转成 `serde_yaml::Value` 后复用同一条解析路径。
/// - **Base64**：解码后按 url-list 处理（多数机场订阅的实际形态）。
/// - **UrlList**：逐行 [`crate::share_link::parse_share_url`]。
/// - **XrayJson**：outbounds[] 走 [`crate::xray_import::parse_xray_outbounds`]（vmess/vless/trojan/ss）。
/// - **SingboxJson**：`outbounds[]` 走 [`crate::singbox_import::parse_singbox_outbounds`]，
///   **`endpoints[]` 走 [`crate::singbox_import::parse_singbox_endpoints`]**，两者结果合并
///   （两个数组的 type 域不相交，见后者文档）。endpoints-only 的配置（机场下发 WireGuard 组网）
///   此前恒 0 节点，现按 endpoint 建模映射入库。
///
/// `id_gen` 注入 UUID 生成（对齐 Polaris randomUUID）。
/// `origin` 决定未建模 type 是否透传 custom，见 [`ImportOrigin`]。
pub fn parse_subscription(
    trimmed: &str,
    subscription_id: &str,
    now: &str,
    id_gen: &mut impl FnMut() -> String,
    origin: ImportOrigin,
) -> ClashParseResult {
    parse_subscription_bundle(trimmed, subscription_id, now, id_gen, origin).parsed
}

/// 可组合的已映射输出体积度量。
///
/// `server_item_json_bytes` 排除了 JSON 数组的 `[]` 和元素间逗号。因此两个结果在不重新
/// 序列化节点的情况下合并后，仍可精确计算 `serde_json::to_vec(&servers).len()`。生产 provider
/// resolver 用它在 Tokio 协调层只做整数运算，把实际序列化留在 parser worker。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ParseOutputMetrics {
    server_count: usize,
    server_item_json_bytes: usize,
    warning_count: usize,
    warning_bytes: usize,
}

impl ParseOutputMetrics {
    fn from_parsed(parsed: &ClashParseResult) -> Result<Self, SubscriptionParseError> {
        let server_count = parsed.servers.len();
        let serialized_servers = serde_json::to_vec(&parsed.servers).map_err(|error| {
            SubscriptionParseError::parse(format!("订阅节点输出序列化失败: {error}"))
        })?;
        // `Vec<T>` serializes as `[` + items separated by `,` + `]`.
        let server_item_json_bytes = serialized_servers
            .len()
            .checked_sub(2)
            .and_then(|bytes| bytes.checked_sub(server_count.saturating_sub(1)))
            .ok_or_else(|| SubscriptionParseError::parse("订阅节点输出序列化长度非法"))?;
        let warning_bytes = parsed
            .warnings
            .iter()
            .try_fold(0usize, |sum, warning| sum.checked_add(warning.len()))
            .ok_or_else(|| SubscriptionParseError::limit("订阅告警输出体积溢出，已拒绝"))?;
        Ok(Self {
            server_count,
            server_item_json_bytes,
            warning_count: parsed.warnings.len(),
            warning_bytes,
        })
    }

    pub(crate) fn warning(message: &str) -> Self {
        Self {
            warning_count: 1,
            warning_bytes: message.len(),
            ..Self::default()
        }
    }

    /// Number of retained node entries.  Kept as a method so callers can combine metrics without
    /// re-opening the internal byte accounting representation.
    pub fn server_count(self) -> usize {
        self.server_count
    }

    /// Number of retained warning strings.
    pub fn warning_count(self) -> usize {
        self.warning_count
    }

    /// Exact byte count of JSON node array plus warning text bytes.
    pub fn output_bytes(self) -> Result<usize, SubscriptionParseError> {
        let server_json_bytes = if self.server_count == 0 {
            2 // `[]`
        } else {
            self.server_item_json_bytes
                .checked_add(self.server_count)
                .and_then(|bytes| bytes.checked_add(1)) // commas + brackets
                .ok_or_else(|| SubscriptionParseError::limit("订阅节点输出体积溢出，已拒绝"))?
        };
        server_json_bytes
            .checked_add(self.warning_bytes)
            .ok_or_else(|| SubscriptionParseError::limit("订阅解析输出体积溢出，已拒绝"))
    }

    /// Combine two outputs as one `Vec<ServerConfig>` plus concatenated warnings, without
    /// serializing either vector again.
    pub fn checked_add(self, other: Self) -> Result<Self, SubscriptionParseError> {
        Ok(Self {
            server_count: self
                .server_count
                .checked_add(other.server_count)
                .ok_or_else(|| SubscriptionParseError::limit("订阅节点数溢出，已拒绝"))?,
            server_item_json_bytes: self
                .server_item_json_bytes
                .checked_add(other.server_item_json_bytes)
                .ok_or_else(|| SubscriptionParseError::limit("订阅节点输出体积溢出，已拒绝"))?,
            warning_count: self
                .warning_count
                .checked_add(other.warning_count)
                .ok_or_else(|| SubscriptionParseError::limit("订阅告警数溢出，已拒绝"))?,
            warning_bytes: self
                .warning_bytes
                .checked_add(other.warning_bytes)
                .ok_or_else(|| SubscriptionParseError::limit("订阅告警输出体积溢出，已拒绝"))?,
        })
    }

    pub fn enforce_max_output_bytes(
        self,
        max_output_bytes: usize,
    ) -> Result<(), SubscriptionParseError> {
        if self.output_bytes()? > max_output_bytes {
            return Err(SubscriptionParseError::limit(format!(
                "订阅解析输出超过上限 {max_output_bytes} 字节，已拒绝"
            )));
        }
        Ok(())
    }

    /// The largest standalone metric a *non-empty* next provider may report while its merge
    /// remains within `max_output_bytes`. Joining arrays removes the current empty `[]` (2 bytes)
    /// or one comma/bracket boundary (1 byte), so this is exact rather than a conservative
    /// double-count that rejects a legal small subscription.
    pub fn max_next_nonempty_server_output_bytes(
        self,
        max_output_bytes: usize,
    ) -> Result<usize, SubscriptionParseError> {
        let remaining = max_output_bytes
            .checked_sub(self.output_bytes()?)
            .ok_or_else(|| {
                SubscriptionParseError::limit(format!(
                    "provider 聚合输出超过资源上限 {max_output_bytes} 字节，已拒绝整次操作"
                ))
            })?;
        let join_credit = if self.server_count == 0 { 2 } else { 1 };
        remaining
            .checked_add(join_credit)
            .ok_or_else(|| SubscriptionParseError::limit("provider 输出预算溢出，已拒绝"))
    }
}

/// 主订阅正文的一次结构化解析产物：inline 节点与 `proxy-providers` 来自同一个 Clash 文档。
#[derive(Debug)]
pub struct ParsedSubscriptionBundle {
    pub format: SubscriptionFormat,
    pub parsed: ClashParseResult,
    pub proxy_providers: Option<serde_yaml::Value>,
    /// Present only for the bounded production entrypoint. It was measured on the parser worker
    /// and can be combined with provider metrics without another Tokio serialization.
    pub output_metrics: Option<ParseOutputMetrics>,
}

impl Default for ParsedSubscriptionBundle {
    fn default() -> Self {
        Self {
            format: SubscriptionFormat::Unknown,
            parsed: ClashParseResult::default(),
            proxy_providers: None,
            output_metrics: None,
        }
    }
}

/// 一次解析主正文并同时产出 inline 节点与 provider 配置。
///
/// 调用方应使用本 API 代替 `parse_subscription` 后再调 [`extract_proxy_providers`]；后者仅为旧调用
/// 保留。合法 JSON 也只做一次 `serde_json::from_str`，然后复用已解析 Value。
pub fn parse_subscription_bundle(
    trimmed: &str,
    subscription_id: &str,
    now: &str,
    id_gen: &mut impl FnMut() -> String,
    origin: ImportOrigin,
) -> ParsedSubscriptionBundle {
    parse_subscription_bundle_inner(trimmed, subscription_id, now, id_gen, origin, None)
        .expect("unlimited subscription parse cannot hit a resource budget")
}

/// Production parser entry with fail-closed resource limits. Pure and deterministic; callers run
/// it on [`SubscriptionParseExecutor`](../../src-tauri/src/runtime/subscription_parse.rs).
pub fn parse_subscription_bundle_limited(
    trimmed: &str,
    subscription_id: &str,
    now: &str,
    id_gen: &mut impl FnMut() -> String,
    origin: ImportOrigin,
    limits: SubscriptionParseLimits,
) -> Result<ParsedSubscriptionBundle, String> {
    parse_subscription_bundle_limited_typed(trimmed, subscription_id, now, id_gen, origin, limits)
        .map_err(|error| error.message)
}

/// Production parser entry retaining whether a failure came from an explicit resource bound or a
/// syntax/mapping failure.  The runtime maps this directly to stable IPC kinds; it never parses
/// the diagnostic string to guess a category.
pub fn parse_subscription_bundle_limited_typed(
    trimmed: &str,
    subscription_id: &str,
    now: &str,
    id_gen: &mut impl FnMut() -> String,
    origin: ImportOrigin,
    limits: SubscriptionParseLimits,
) -> Result<ParsedSubscriptionBundle, SubscriptionParseError> {
    parse_subscription_bundle_inner(trimmed, subscription_id, now, id_gen, origin, Some(limits))
}

fn parse_subscription_bundle_inner(
    trimmed: &str,
    subscription_id: &str,
    now: &str,
    id_gen: &mut impl FnMut() -> String,
    origin: ImportOrigin,
    limits: Option<SubscriptionParseLimits>,
) -> Result<ParsedSubscriptionBundle, SubscriptionParseError> {
    if let Some(limits) = limits {
        if trimmed.len() > limits.max_body_bytes {
            return Err(SubscriptionParseError::limit(format!(
                "订阅正文 {} 字节超过解析上限 {}，已拒绝",
                trimmed.len(),
                limits.max_body_bytes
            )));
        }
    }
    // 与 [`detect_format`] 同口径剥 BOM（理由见其头注）：下游各格式分支消费的都是这个 `trimmed`，
    // 在此收口一次。**这一步真正保护的**是 base64、url-list 与 JSON（sing-box / xray）三条腿——
    // `serde_json` 拒绝前置 BOM，逐行解析器的 scheme 前缀匹配同样吃不掉它（`trim_start` 不去
    // U+FEFF）。**Clash 腿不靠这一步**：libyaml 在编码探测阶段自己吞掉 BOM，它靠的是
    // [`detect_format`] 里那次剥离（否则 `is_clash_probe` 的行首匹配失败 → `Unknown` + 0 节点）。
    // 这两处剥离点各守哪几条腿，由 `subscription/tests/mod.rs` 的 `bom_before_*` 系列**逐条变异
    // 证红**得出，不是从注释推的。
    let trimmed = trimmed.trim_start_matches('\u{feff}');
    let t = trimmed.trim_start();
    let parsed_json = if t.starts_with('{') || t.starts_with('[') {
        if let Some(limits) = limits {
            clash_parser::validate_json_document_budget(t, clash_document_limits(limits))
                .map_err(SubscriptionParseError::limit)?;
        }
        Some(serde_json::from_str::<serde_json::Value>(t))
    } else {
        None
    };
    let format = match parsed_json.as_ref() {
        Some(Ok(v)) => detect_json_format(v).unwrap_or(SubscriptionFormat::Unknown),
        Some(Err(_)) if limits.is_some() => detect_json_format_hint(t),
        _ => detect_format(trimmed),
    };
    let bundle = match format {
        SubscriptionFormat::Clash => {
            let doc = match parsed_json {
                Some(Ok(v)) => match limits {
                    Some(limits) => clash_parser::try_load_clash_json_value_limited_typed(
                        v,
                        clash_document_limits(limits),
                    )
                    .map_err(SubscriptionParseError::from),
                    None => clash_parser::try_load_clash_json_value(v)
                        .map_err(SubscriptionParseError::parse),
                },
                _ => match limits {
                    Some(limits) => clash_parser::try_load_clash_doc_limited_typed(
                        trimmed,
                        clash_document_limits(limits),
                    )
                    .map_err(SubscriptionParseError::from),
                    None => clash_parser::try_load_clash_doc(trimmed)
                        .map_err(SubscriptionParseError::parse),
                },
            };
            let doc = match doc {
                Ok(d) => d,
                Err(error) if limits.is_some() => return Err(error),
                Err(e) => {
                    return Ok(ParsedSubscriptionBundle {
                        format,
                        parsed: ClashParseResult {
                            warnings: vec![e.message],
                            ..Default::default()
                        },
                        proxy_providers: None,
                        output_metrics: None,
                    });
                }
            };
            let proxies = doc
                .get(serde_yaml::Value::String("proxies".to_string()))
                .cloned()
                .unwrap_or(serde_yaml::Value::Null);
            enforce_declared_nodes(&proxies, limits).map_err(SubscriptionParseError::limit)?;
            let proxy_providers = doc
                .get(serde_yaml::Value::String("proxy-providers".to_string()))
                .filter(|v| v.as_mapping().is_some())
                .cloned();
            ParsedSubscriptionBundle {
                format,
                parsed: clash_parser::parse_clash_proxies(&proxies, subscription_id, now, id_gen),
                proxy_providers,
                output_metrics: None,
            }
        }
        SubscriptionFormat::UrlList => {
            enforce_text_node_count(trimmed, limits).map_err(SubscriptionParseError::limit)?;
            ParsedSubscriptionBundle {
                format,
                parsed: crate::share_link::parse_url_list(trimmed, subscription_id, now, id_gen),
                proxy_providers: None,
                output_metrics: None,
            }
        }
        SubscriptionFormat::Base64 => ParsedSubscriptionBundle {
            format,
            parsed: match base64_decode(trimmed) {
                Ok(decoded) => {
                    // 解码产物本身也是一份文档：机场把 `BOM + 分享链接列表` 整体 base64 时，BOM
                    // 会随解码原样出现在首行 —— 外层剥过一次不代表内层干净，这里同口径再剥一次，
                    // 否则首节点照旧在 `parse_url_list` 里静默丢（issue #1 的同一根因、第二条路径）。
                    let decoded = decoded.trim_start_matches('\u{feff}');
                    enforce_text_node_count(decoded, limits)
                        .map_err(SubscriptionParseError::limit)?;
                    crate::share_link::parse_url_list(decoded, subscription_id, now, id_gen)
                }
                // detect_format 已试解成功才判 Base64，此分支理论不可达；仍不 panic（订阅是外部输入）。
                Err(()) => ClashParseResult {
                    warnings: vec!["订阅 base64 解码失败".to_string()],
                    ..Default::default()
                },
            },
            proxy_providers: None,
            output_metrics: None,
        },
        SubscriptionFormat::XrayJson => ParsedSubscriptionBundle {
            format,
            parsed: match parsed_json.unwrap_or_else(|| serde_json::from_str(trimmed)) {
                Ok(v) => {
                    enforce_json_node_count(&v, &["outbounds"], limits)
                        .map_err(SubscriptionParseError::limit)?;
                    crate::xray_import::parse_xray_outbounds(
                        v.get("outbounds").unwrap_or(&serde_json::Value::Null),
                        subscription_id,
                        now,
                        id_gen,
                    )
                }
                Err(e) => ClashParseResult {
                    warnings: vec![format!("Xray JSON 解析失败: {e}")],
                    ..Default::default()
                },
            },
            proxy_providers: None,
            output_metrics: None,
        },
        SubscriptionFormat::SingboxJson => ParsedSubscriptionBundle {
            format,
            parsed: match parsed_json.unwrap_or_else(|| serde_json::from_str(trimmed)) {
                // detect_format 已确认形似 sing-box JSON；`outbounds[]` 与 `endpoints[]` 各交对应解析器
                // 后合并 —— 两个数组由内核定义为不相交的 type 域（`wireguard` 作 outbound 已于 1.13 移除、
                // `tailscale` 作 outbound 即 unknown），故不存在同一节点被两条腿各数一次。
                Ok(v) => {
                    enforce_json_node_count(&v, &["outbounds", "endpoints"], limits)
                        .map_err(SubscriptionParseError::limit)?;
                    let null = serde_json::Value::Null;
                    let mut r = crate::singbox_import::parse_singbox_outbounds(
                        v.get("outbounds").unwrap_or(&null),
                        subscription_id,
                        now,
                        id_gen,
                        origin,
                    );
                    let ep = crate::singbox_import::parse_singbox_endpoints(
                        v.get("endpoints").unwrap_or(&null),
                        subscription_id,
                        now,
                        id_gen,
                        origin,
                    );
                    r.servers.extend(ep.servers);
                    r.skipped += ep.skipped;
                    r.failed += ep.failed;
                    r.warnings.extend(ep.warnings);
                    r
                }
                Err(e) => ClashParseResult {
                    warnings: vec![format!("sing-box JSON 解析失败: {e}")],
                    ..Default::default()
                },
            },
            proxy_providers: None,
            output_metrics: None,
        },
        SubscriptionFormat::Unknown => ParsedSubscriptionBundle {
            format,
            parsed: ClashParseResult {
                warnings: vec![format!("暂不支持的订阅格式: {format:?}")],
                ..Default::default()
            },
            proxy_providers: None,
            output_metrics: None,
        },
    };
    let mut bundle = bundle;
    if let Some(limits) = limits {
        bundle.output_metrics = Some(measure_parse_output_typed(&bundle.parsed, limits)?);
    }
    Ok(bundle)
}

fn enforce_text_node_count(
    text: &str,
    limits: Option<SubscriptionParseLimits>,
) -> Result<(), String> {
    let Some(limits) = limits else {
        return Ok(());
    };
    let mut count = 0usize;
    for line in text.lines() {
        if !line.trim().is_empty() {
            count = count.saturating_add(1);
            if count > limits.max_nodes {
                return Err(format!("订阅节点数超过上限 {}，已拒绝", limits.max_nodes));
            }
        }
    }
    Ok(())
}

fn enforce_json_node_count(
    value: &serde_json::Value,
    keys: &[&str],
    limits: Option<SubscriptionParseLimits>,
) -> Result<(), String> {
    let Some(limits) = limits else {
        return Ok(());
    };
    let count = keys.iter().fold(0usize, |sum, key| {
        sum.saturating_add(
            value
                .get(*key)
                .and_then(serde_json::Value::as_array)
                .map_or(0, Vec::len),
        )
    });
    if count > limits.max_nodes {
        return Err(format!("订阅节点数超过上限 {}，已拒绝", limits.max_nodes));
    }
    Ok(())
}

fn clash_document_limits(limits: SubscriptionParseLimits) -> clash_parser::ClashDocumentLimits {
    clash_parser::ClashDocumentLimits {
        max_depth: limits.max_structure_depth,
        max_container_items: limits.max_container_items,
        max_scalar_bytes: limits.max_scalar_bytes,
        max_merge_expansions: limits.max_merge_expansions,
    }
}

fn enforce_declared_nodes(
    nodes: &serde_yaml::Value,
    limits: Option<SubscriptionParseLimits>,
) -> Result<(), String> {
    let Some(limits) = limits else {
        return Ok(());
    };
    if nodes.as_sequence().map_or(0, Vec::len) > limits.max_nodes {
        return Err(format!("订阅节点数超过上限 {}，已拒绝", limits.max_nodes));
    }
    Ok(())
}

/// Validate an already-mapped parse result. Runtime callers use this from their isolated CPU
/// aggregation job after merging provider output with inline nodes.
pub fn enforce_parse_output_budget(
    parsed: &ClashParseResult,
    limits: SubscriptionParseLimits,
) -> Result<(), String> {
    enforce_parse_output_budget_typed(parsed, limits).map_err(|error| error.message)
}

/// Typed counterpart of [`enforce_parse_output_budget`].  Node/warning/output caps are explicit
/// resource-limit failures; serialization remains a parser/output failure rather than being
/// guessed from its display text.
pub fn enforce_parse_output_budget_typed(
    parsed: &ClashParseResult,
    limits: SubscriptionParseLimits,
) -> Result<(), SubscriptionParseError> {
    measure_parse_output_typed(parsed, limits).map(|_| ())
}

/// Measure and validate an already-mapped parse result. The metric deliberately retains the
/// one serialization needed to know `ServerConfig`'s exact JSON footprint, so callers can move
/// that work to a CPU worker and later combine results with integer arithmetic only.
pub fn measure_parse_output_typed(
    parsed: &ClashParseResult,
    limits: SubscriptionParseLimits,
) -> Result<ParseOutputMetrics, SubscriptionParseError> {
    if parsed.servers.len() > limits.max_nodes {
        return Err(SubscriptionParseError::limit(format!(
            "订阅节点数超过上限 {}，已拒绝",
            limits.max_nodes
        )));
    }
    if parsed.warnings.len() > limits.max_warnings {
        return Err(SubscriptionParseError::limit(format!(
            "订阅告警数超过上限 {}，已拒绝",
            limits.max_warnings
        )));
    }
    let metrics = ParseOutputMetrics::from_parsed(parsed)?;
    metrics.enforce_max_output_bytes(limits.max_output_bytes)?;
    Ok(metrics)
}

mod provider_resolver;

pub use provider_resolver::{
    fetch_and_parse_provider, parse_provider_request, resolve_proxy_providers,
    resolve_proxy_providers_controlled, resolve_proxy_providers_controlled_with_parser,
    FetchTextFn, ProviderFatalError, ProviderFatalErrorKind, ProviderFetchError,
    ProviderParseRequest, ProviderParsedOutput, ProviderResolveControl, ProviderResolveLimits,
    ProviderResolveResult,
};

/// 节点稳定指纹（对账/去重键）：`protocol|address|port|cred|network`（**排除 name/detour**）。
/// 上游 `SubscriptionService.serverFingerprint`。
///
/// 排除显示名：订阅方常改名/调顺序，用 name 做键会把同一物理节点误判「删旧增新」→ id 抖动、
/// selectedServerId 丢失、本地编辑被清。cred（uuid / password / 嵌套 ss·ssh password / username /
/// wg peerPublicKey）区分同 host:port 并列节点；network 维度区分同 host:port:cred 但传输不同
/// （tcp/ws/grpc）的节点，缺此维度会被误并静默吞节点。
///
/// **与命令层 `node_fingerprint(&Value)` 是同一公式的两侧**（typed / json），由跨类型等价单测锁定同步。
#[must_use]
pub fn server_fingerprint(s: &ServerConfig) -> String {
    let protocol = serde_json::to_value(s.protocol)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
        .to_ascii_lowercase();
    let cred = non_empty(s.uuid.clone())
        .or_else(|| non_empty(s.password.clone()))
        .or_else(|| {
            non_empty(
                s.shadowsocks_settings
                    .as_ref()
                    .map(|ss| ss.password.clone()),
            )
        })
        .or_else(|| non_empty(s.username.clone()))
        .or_else(|| non_empty(s.ssh_settings.as_ref().and_then(|ssh| ssh.password.clone())))
        .or_else(|| {
            non_empty(
                s.wireguard_settings
                    .as_ref()
                    .and_then(|w| w.peer_public_key.clone()),
            )
        })
        .unwrap_or_default();
    let network = s.network.as_deref().unwrap_or("tcp").to_ascii_lowercase();
    format!("{protocol}|{}|{}|{cred}|{network}", s.address, s.port)
}

/// `Option<String>` 里的空串归 `None`（对齐 上游 `x || ...` 的 falsy 空串语义）。
fn non_empty(v: Option<String>) -> Option<String> {
    v.filter(|s| !s.is_empty())
}

/// 同指纹去重（首见保留）。上游 `dedupeByFingerprint`：内联在前、provider 按声明序在后 →
/// 同节点多源留内联那份。
#[must_use]
pub fn dedupe_by_fingerprint(servers: Vec<ServerConfig>) -> Vec<ServerConfig> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(servers.len());
    for s in servers {
        if seen.insert(server_fingerprint(&s)) {
            out.push(s);
        }
    }
    out
}

/// 从 Clash 订阅正文提取 `proxy-providers` 映射（非 Clash / 无 providers → `None`）。
///
/// 供命令层判定「是否需 provider 编排」并取出 provider 配置（供 [`resolve_proxy_providers`]）。
/// 判定走 [`detect_format`]（**单一真值**）→ YAML 与 JSON 两种编码同覆盖，与 [`parse_subscription`]
/// 的 Clash 分支严格同口径。此前这里单独判 `is_clash_probe`（纯 YAML 行首探测），JSON 编码的
/// `{"proxy-providers":{…}}` 会被漏掉 → provider 一个都不拉、节点全丢。
///
/// **当前无生产调用方**（2026-09-03 全仓核对：仅本 crate 两处单测在调）——生产的 provider 编排
/// 走 [`parse_subscription_bundle`] 一次解析同时产出的 `proxy_providers`。故此处刻意**不**再补一份
/// BOM 剥离：那条分支在生产里跑不到、也就没有门守得住它；真有正文带 BOM，生产腿在
/// [`parse_subscription_bundle`] 里已统一剥掉（见其内部实现与 `bom_before_*` 系列用例）。
#[must_use]
pub fn extract_proxy_providers(text: &str) -> Option<serde_yaml::Value> {
    let trimmed = text.trim();
    if detect_format(trimmed) != SubscriptionFormat::Clash {
        return None;
    }
    let doc = clash_parser::try_load_clash_doc(trimmed).ok()?;
    let providers = doc.get(serde_yaml::Value::String("proxy-providers".to_string()))?;
    providers.as_mapping().is_some().then(|| providers.clone())
}

/// 轻量 base64 解码（容忍换行/空白，URL-safe 与标准均支持）。失败返回 Err。
///
/// `pub(crate)`：[`crate::share_link`] 的 vmess base64-JSON / ss base64-userinfo /
/// shadow-tls base64-JSON 三处复用同一份解码器（Node `Buffer.from(x,'base64')` 同样兼容
/// 标准与 URL-safe 两套字母表）——不另造第二份。
pub(crate) fn base64_decode(input: &str) -> Result<String, ()> {
    let clean: String = input
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            _ => c,
        })
        .collect();
    // 补齐 padding。
    let mut s = clean;
    while !s.len().is_multiple_of(4) {
        s.push('=');
    }
    base64_decode_inner(&s)
}

/// 最小 base64 解码（避免引入新依赖；订阅 base64 体量小，纯实现可接受）。
fn base64_decode_inner(s: &str) -> Result<String, ()> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = s
        .as_bytes()
        .iter()
        .filter(|&&b| b != b'=')
        .copied()
        .collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &b in &bytes {
        let v = u32::from(val(b).ok_or(())?);
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    String::from_utf8(out).map_err(|_| ())
}

#[cfg(test)]
mod tests;
