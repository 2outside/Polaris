//! 带逐跳 SSRF 复检的安全重定向 fetch（上游 `main/safe-redirect-fetch.ts` 1:1 移植）。
//!
//! 默认 `redirect: follow` 会让首 URL 过 guard 后被 30x 跳到内网而不复检，构成 SSRF 绕过；
//! 逐跳复检是安全关键。本 helper 收口「redirect: manual 自管链 + 每跳 Location 过
//! [`crate::ssrf::resolve_host_allowed`] + 重定向上限」。真实 HTTP 由注入的 [`HttpClient`] trait 承载
//! （测试 mock，不触碰宿主网络）。

#![forbid(unsafe_code)]

use std::{future::Future, net::IpAddr, time::Instant};

use url::Url;

use crate::ssrf::{resolve_host_allowed, DnsLookup};

/// 安全 fetch 拒绝原因：调用方据此映射 HTTP 状态码或区分错误类别。
/// 上游 `SafeFetchRejectReason`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafeFetchRejectReason {
    /// 重定向目标协议不支持（仅允许 http/https），或 Location 非法。
    RedirectProtocol,
    /// SSRF guard 命中（首跳或某跳解析到内网）。
    Ssrf,
    /// 重定向次数超过上限。
    TooManyRedirects,
    /// absolute network deadline 已耗尽，或单跳传输明确报告 timeout。
    Timeout,
    /// 注入的 [`HttpClient`] 冒泡的网络错误（连接被拒 / 超时 / DNS 失败…）。
    ///
    /// **与 [`Ssrf`](SafeFetchRejectReason::Ssrf) 必须分开**：二者都会让 fetch 失败，但语义相反——
    /// 前者是「拒绝访问」（安全拦截，用户改 URL 也没用），后者是「连不上」（可重试）。混为一谈会让
    /// 每个 ECONNREFUSED 都被报成「订阅地址指向内网」，把真实网络故障的排查引到错误方向。
    Network,
}

/// redirect 链中的安全拒绝（区别于 HttpClient 网络错误）。上游 `SafeFetchError`。
#[derive(Debug, Clone)]
pub struct SafeFetchError {
    pub reason: SafeFetchRejectReason,
    pub message: String,
}

impl std::fmt::Display for SafeFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for SafeFetchError {}

/// helper 容忍的最小 Response 形状（上游 `MinimalResponse` 的同构子集）。
///
/// **body 由实现侧读满后交回**（这是拉取流水线拿到正文的唯一通道）：实现侧须按
/// [`FetchInit::max_body_bytes`] **流式**累计，超限即中断连接并返回 `Err`——**不得截断后返回**
/// （截断会把超大订阅变成「解析出半截节点」的坏数据，比明确失败更糟）。
///
/// 30x 中间响应的 body 由本 helper 丢弃（不消费、体积小）；仅终态 response 的 body 有意义。
#[derive(Debug, Default)]
pub struct MinimalResponse {
    pub status: u16,
    /// location header（30x 时取）。大小写不敏感由实现保证。
    pub location: Option<String>,
    /// 全部响应头。供调用方取 content-length / etag / last-modified / subscription-userinfo。
    /// key 大小写不敏感——按名取用 [`MinimalResponse::header`]，勿直接比对。
    pub headers: Vec<(String, String)>,
    /// 已读取的响应体原始字节（是否为 UTF-8 由调用方判定）。
    pub body: Vec<u8>,
}

impl MinimalResponse {
    /// 按名取响应头（大小写不敏感，取首个命中）。
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// 绑定好会话的 fetch（上游 `fetchImpl`）。helper 固定下发 redirect:'manual' 语义：
/// 实现方返回的 Response 不得自动跟随重定向（须原样返回 30x + Location）。
pub trait HttpClient: Send + Sync {
    /// 发起一次请求（manual redirect）。失败返回 Err（网络错误原样冒泡）。
    fn fetch(
        &self,
        url: &str,
        init: &FetchInit,
    ) -> impl Future<Output = Result<MinimalResponse, String>> + Send;

    /// 使用 SSRF guard **同一次解析**得到的目标地址发起请求。
    ///
    /// 默认实现保持测试 mock / 非网络适配器兼容；真实直连实现应 override 并把 `target.addresses`
    /// pin 到 dial。SOCKS5h 等代理端解析实现可显式保留 remote-DNS，但必须在实现文档中说明其
    /// guard/dial 信任边界，不能把本方法的调用误当成已经 pin。
    fn fetch_guarded(
        &self,
        url: &str,
        init: &FetchInit,
        target: &GuardedTarget,
    ) -> impl Future<Output = Result<MinimalResponse, String>> + Send {
        let _ = target;
        self.fetch(url, init)
    }
}

/// SSRF guard 放行并交给真实 dial 的解析结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardedTarget {
    pub host: String,
    pub addresses: Vec<IpAddr>,
}

/// 单次请求参数（上游 `init`）。
#[derive(Debug, Clone, Default)]
pub struct FetchInit {
    pub user_agent: String,
    /// 附加请求头（条件 GET 验证器等非凭据，逐跳携带）。
    pub headers: Vec<(String, String)>,
    /// 本跳可使用的**剩余 absolute budget**（连接到 headers），毫秒。`None` → 实现侧默认。
    /// 整条链的最终裁决由 [`safe_redirect_fetch_until`] 外层 deadline 保证。
    pub timeout_ms: Option<u64>,
    /// 响应体上限（字节）。实现侧须**流式**累计、超限即中断并 `Err`（防 OOM）。`None` → 不限。
    pub max_body_bytes: Option<usize>,
}

/// [`safe_redirect_fetch`] 配置。上游 `SafeRedirectFetchOptions`。
pub struct SafeRedirectFetchOptions<'a, H: HttpClient, L: DnsLookup> {
    /// 绑定好会话的 fetch 实现。
    pub fetch_impl: &'a H,
    /// 起始 URL，调用方已保证为 http(s)。
    pub url: &'a str,
    pub user_agent: String,
    /// 附加请求头（与 User-Agent 合并）。
    pub headers: Option<Vec<(String, String)>>,
    /// 仅实际经代理时传 true，记录 Polaris FakeIP 的传输语义；字面 FakeIP 无条件拒绝。
    pub exempt_fake_ip: bool,
    /// 重定向上限（含首跳之外的跳数），默认 5。
    pub max_redirects: Option<usize>,
    /// 整条网络链预算。普通 [`safe_redirect_fetch`] 在入口据此建立一次 absolute deadline；
    /// [`safe_redirect_fetch_until`] 可由调用方跨 retry 共享更早的 deadline。
    pub timeout_ms: Option<u64>,
    /// 响应体上限，透传 [`FetchInit::max_body_bytes`]。
    pub max_body_bytes: Option<usize>,
    /// 注入 DNS 解析。
    pub lookup: &'a L,
}

const DEFAULT_MAX_REDIRECTS: usize = 5;

/// SSRF guard：[`crate::ssrf::resolve_host_allowed`] 报错统一归类为 [`SafeFetchError`] reason=`Ssrf`，
/// 保留原始消息（含 hostname/解析结果）。上游 `guard`。
async fn guard<L: DnsLookup>(
    url: &Url,
    lookup: &L,
    exempt_fake_ip: bool,
) -> Result<GuardedTarget, SafeFetchError> {
    let host = url.host_str().unwrap_or("");
    resolve_host_allowed(host, lookup, exempt_fake_ip)
        .await
        .map(|addresses| GuardedTarget {
            host: host.to_ascii_lowercase(),
            addresses,
        })
        .map_err(|msg| SafeFetchError {
            reason: SafeFetchRejectReason::Ssrf,
            message: msg,
        })
}

/// 首跳 + 每一跳 Location 都过 SSRF guard（含 DNS 逐 IP 判定），通过才续跳，最多 maxRedirects 跳。
///
/// 返回终态（非 30x）response；中途 30x 的 response 由本 helper 忽略（其 body 未消费、
/// 由实现侧释放）。上游 `safeRedirectFetch`。
pub async fn safe_redirect_fetch<H: HttpClient, L: DnsLookup>(
    opts: SafeRedirectFetchOptions<'_, H, L>,
) -> Result<MinimalResponse, SafeFetchError> {
    let deadline = opts
        .timeout_ms
        .map(|ms| Instant::now() + std::time::Duration::from_millis(ms));
    match deadline {
        Some(deadline) => safe_redirect_fetch_until(opts, deadline).await,
        None => safe_redirect_fetch_inner(opts, None).await,
    }
}

/// 与 [`safe_redirect_fetch`] 相同，但使用调用方提供的 absolute network deadline。
///
/// deadline 从调用方首次网络尝试前建立，可跨 retry 复用；覆盖首跳/重定向 DNS guard、每跳
/// connect+headers 以及终态 body。正文 parse 不属于 network deadline。
pub async fn safe_redirect_fetch_until<H: HttpClient, L: DnsLookup>(
    opts: SafeRedirectFetchOptions<'_, H, L>,
    deadline: Instant,
) -> Result<MinimalResponse, SafeFetchError> {
    let configured = opts
        .timeout_ms
        .map(|ms| Instant::now() + std::time::Duration::from_millis(ms));
    let deadline = configured.map_or(deadline, |d| d.min(deadline));
    tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        safe_redirect_fetch_inner(opts, Some(deadline)),
    )
    .await
    .map_err(|_| SafeFetchError {
        reason: SafeFetchRejectReason::Timeout,
        message: "request timeout: absolute network deadline exceeded".to_string(),
    })?
}

async fn safe_redirect_fetch_inner<H: HttpClient, L: DnsLookup>(
    opts: SafeRedirectFetchOptions<'_, H, L>,
    deadline: Option<Instant>,
) -> Result<MinimalResponse, SafeFetchError> {
    let max_redirects = opts.max_redirects.unwrap_or(DEFAULT_MAX_REDIRECTS);

    let mut current_url = match Url::parse(opts.url) {
        Ok(u) => u,
        Err(_) => {
            return Err(SafeFetchError {
                reason: SafeFetchRejectReason::RedirectProtocol,
                message: "起始 URL 非法，已拒绝".to_string(),
            });
        }
    };

    // 首跳 guard（起始 URL 协议由调用方保证为 http(s)）。
    let mut guarded_target = guard(&current_url, opts.lookup, opts.exempt_fake_ip).await?;

    let init = FetchInit {
        user_agent: opts.user_agent.clone(),
        headers: opts.headers.clone().unwrap_or_default(),
        timeout_ms: None,
        max_body_bytes: opts.max_body_bytes,
    };

    for hop in 0..=max_redirects {
        let mut hop_init = init.clone();
        hop_init.timeout_ms = deadline.map(|d| {
            let remaining = d.saturating_duration_since(Instant::now());
            u64::try_from(remaining.as_millis())
                .unwrap_or(u64::MAX)
                .max(1)
        });
        // 实现侧冒泡的网络错误 → reason=Network（**不是** Ssrf：见该 variant 的 doc）。
        let response = opts
            .fetch_impl
            .fetch_guarded(current_url.as_str(), &hop_init, &guarded_target)
            .await
            .map_err(|msg| {
                let lower = msg.to_ascii_lowercase();
                SafeFetchError {
                    reason: if lower.contains("timeout") || lower.contains("timed out") {
                        SafeFetchRejectReason::Timeout
                    } else {
                        SafeFetchRejectReason::Network
                    },
                    message: msg,
                }
            })?;

        let is_redirect = (300..400).contains(&response.status);
        let loc = if is_redirect {
            response.location.as_deref()
        } else {
            None
        };
        let Some(loc) = loc else {
            // 非 30x（或无 Location）→ 终态响应
            return Ok(response);
        };

        // 确认是 30x：续跳或抛错都已离开本跳响应。
        if hop >= max_redirects {
            return Err(SafeFetchError {
                reason: SafeFetchRejectReason::TooManyRedirects,
                message: format!("重定向次数超过上限（{max_redirects}），已拒绝"),
            });
        }
        // 相对 Location 以当前 URL 为基准解析。
        let next_obj = match current_url.join(loc) {
            Ok(u) => u,
            Err(_) => {
                return Err(SafeFetchError {
                    reason: SafeFetchRejectReason::RedirectProtocol,
                    message: "重定向目标非法，已拒绝".to_string(),
                });
            }
        };
        if next_obj.scheme() != "http" && next_obj.scheme() != "https" {
            return Err(SafeFetchError {
                reason: SafeFetchRejectReason::RedirectProtocol,
                message: "重定向目标协议不支持（仅允许 http/https），已拒绝".to_string(),
            });
        }
        // 重定向目标过同一 guard（含 DNS 解析）。
        guarded_target = guard(&next_obj, opts.lookup, opts.exempt_fake_ip).await?;
        current_url = next_obj;
    }

    // hop 循环 0..=max_redirects 必执行一次 fetch；理论上不会到达此处（最后一跳若无 Location
    // 已 return Ok；若有 Location 则 hop>=max_redirects 已 return Err）。
    Err(SafeFetchError {
        reason: SafeFetchRejectReason::TooManyRedirects,
        message: format!("重定向次数超过上限（{max_redirects}），已拒绝"),
    })
}

#[cfg(test)]
mod tests;
