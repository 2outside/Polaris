//! 订阅安全拉取的 DNS 解析、guard 地址 pin 与单跳传输适配。
//!
//! 父模块继续持有共享 reqwest client 与通用 body 读取 primitive；本模块只负责 net-stack 的
//! DnsLookup / HttpClient 端口，避免订阅专属解析策略挤占通用更新传输实现。

use std::{future::Future, time::Duration};

use polaris_net_stack::safe_redirect::{FetchInit, GuardedTarget, HttpClient, MinimalResponse};
use polaris_net_stack::ssrf::DnsLookup;

use super::{
    app_user_agent, collect_headers, install_ring_provider, read_body_capped, BodyReadError,
    HttpRuntime, RESPONSE_TIMEOUT, STALL_TIMEOUT,
};

// ── DnsLookup 生产实现 ─────────────────────────────────────────────────────────

/// 系统解析器（`tokio::net::lookup_host`）—— net-stack [`DnsLookup`] 的**生产实现**。
///
/// 此前全仓只有测试 mock：意味着 `assert_host_allowed` 的 SSRF guard 在生产路径上
/// **没有解析器可注入**，H1（DNS rebinding）防线是「逻辑在、接线不在」。本类型接上它。
///
/// 端口传 0：只要 A/AAAA 记录，不实际连接。
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemDnsLookup;

impl DnsLookup for SystemDnsLookup {
    fn lookup_all(&self, host: &str) -> impl Future<Output = Result<Vec<String>, String>> + Send {
        let host = host.to_string();
        async move {
            let addrs = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|e| format!("DNS 解析失败 {host}: {e}"))?;
            // 逐 IP 交给 guard 判定（**全部**返回，不只首个：rebinding 常把恶意 IP 藏在第二条）。
            let ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
            if ips.is_empty() {
                return Err(format!("DNS 解析 {host} 无结果"));
            }
            Ok(ips)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HttpResolutionMode {
    /// 系统直连：必须使用 SSRF guard 同一次解析结果 pin 真实 dial。
    DirectPinned,
    /// HTTP proxy / SOCKS5h：目标由代理端解析；保留 remote-DNS/FakeIP 语义。
    ProxyRemoteDns,
    /// 测试专用的预置 reqwest override，不再覆盖其固定解析。
    #[cfg(test)]
    TestOverride,
}

// ── 适配 ①：net-stack HttpClient（订阅拉取）──────────────────────────────────

/// reqwest 的错误 Display 即使去掉 URL，也可能只剩 `error sending request for url`；真正的
/// DNS/拒绝/超时通常藏在 source chain。这里只**读取**链做判定，绝不把链原文回传（其中可能带订阅
/// hostname）；输出稳定、无凭据的诊断 token，供 net-stack 的既有分类器识别。
pub(super) fn classify_transport_failure(
    is_timeout: bool,
    is_connect: bool,
    source_chain: &str,
) -> &'static str {
    if is_timeout {
        return "request timeout";
    }
    let chain = source_chain.to_ascii_lowercase();
    if [
        "dns",
        "getaddrinfo",
        "name resolution",
        "lookup address",
        "no such host",
        "nodename nor servname",
        "11001",
    ]
    .iter()
    .any(|needle| chain.contains(needle))
    {
        return "dns resolution failed";
    }
    if [
        "connection refused",
        "actively refused",
        "connection reset",
        "unreachable",
        "10061",
    ]
    .iter()
    .any(|needle| chain.contains(needle))
    {
        return "connection refused or unreachable";
    }
    if ["tls", "certificate", "handshake"]
        .iter()
        .any(|needle| chain.contains(needle))
    {
        return "tls handshake failed";
    }
    if is_connect {
        return "connection failed";
    }
    "request failed"
}

/// reqwest 错误 → 无 URL/hostname/token 的稳定诊断串。
fn sanitized_reqwest_error(error: &reqwest::Error) -> String {
    let mut source_chain = String::new();
    let mut source = std::error::Error::source(error);
    // source 链通常 3~5 层；双上限防第三方错误构造循环/超长 Display 把日志撑大。
    for _ in 0..8 {
        let Some(current) = source else { break };
        if source_chain.len() < 2_048 {
            let rendered = current.to_string();
            let mut end = (2_048 - source_chain.len()).min(rendered.len());
            while !rendered.is_char_boundary(end) {
                end -= 1;
            }
            source_chain.push_str(&rendered[..end]);
            if source_chain.len() < 2_048 {
                source_chain.push('\n');
            }
        }
        source = current.source();
    }
    classify_transport_failure(error.is_timeout(), error.is_connect(), &source_chain).to_string()
}

pub(super) fn sanitized_body_read_error(error: BodyReadError) -> String {
    match error {
        BodyReadError::Stalled => "request timeout while reading response body".to_string(),
        BodyReadError::TooLarge(limit) => {
            format!("response body too large (limit {limit} bytes)")
        }
        BodyReadError::Io { message, .. } => {
            classify_transport_failure(false, false, &message).to_string()
        }
        // `read_body_capped` 没有 sink，生产不可达；完整匹配保留类型未来扩展时的编译器提醒。
        BodyReadError::Sink { .. } => "response body sink failed".to_string(),
    }
}

fn build_direct_pinned_client(target: &GuardedTarget) -> Result<reqwest::Client, String> {
    install_ring_provider();
    let addrs: Vec<std::net::SocketAddr> = target
        .addresses
        .iter()
        .copied()
        .map(|ip| std::net::SocketAddr::new(ip, 0))
        .collect();
    if addrs.is_empty() {
        return Err(format!(
            "SSRF guard 未提供可拨号地址，已拒绝: {}",
            target.host
        ));
    }
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .user_agent(app_user_agent())
        // URL hostname 保持不变（Host/SNI 仍是域名），只把底层 socket 解析钉到 guard 的同一组 IP。
        .resolve_to_addrs(&target.host, &addrs)
        .build()
        .map_err(|e| format!("建 DNS-pinned HTTP 客户端失败: {e}"))
}

async fn fetch_one_hop(
    client: reqwest::Client,
    url: String,
    init: FetchInit,
) -> Result<MinimalResponse, String> {
    let mut req = client.get(url);
    if !init.user_agent.is_empty() {
        req = req.header(reqwest::header::USER_AGENT, init.user_agent);
    }
    for (k, v) in init.headers {
        req = req.header(k, v);
    }
    let response_timeout = init
        .timeout_ms
        .map_or(RESPONSE_TIMEOUT, Duration::from_millis);
    let mut resp = tokio::time::timeout(response_timeout, req.send())
        .await
        .map_err(|_| "request timeout".to_string())?
        .map_err(|e| sanitized_reqwest_error(&e))?;

    let status = resp.status().as_u16();
    let headers = collect_headers(&resp);
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let body = if (300..400).contains(&status) {
        Vec::new()
    } else {
        // absolute deadline 由 safe_redirect_fetch_until 外包整条 future；这里保留更早的 body idle 失败。
        read_body_capped(&mut resp, init.max_body_bytes, STALL_TIMEOUT)
            .await
            .map_err(sanitized_body_read_error)?
    };

    Ok(MinimalResponse {
        status,
        location,
        headers,
        body,
    })
}

impl HttpClient for HttpRuntime {
    /// 单跳 GET（manual redirect：30x 原样返回，**不跟随**）。
    ///
    /// 逐跳 SSRF 复检与链路编排归 `safe_redirect_fetch`（net-stack），本适配器**只做一跳传输**。
    fn fetch(
        &self,
        url: &str,
        init: &FetchInit,
    ) -> impl Future<Output = Result<MinimalResponse, String>> + Send {
        fetch_one_hop(self.client.clone(), url.to_string(), init.clone())
    }

    fn fetch_guarded(
        &self,
        url: &str,
        init: &FetchInit,
        target: &GuardedTarget,
    ) -> impl Future<Output = Result<MinimalResponse, String>> + Send {
        let client = match self.resolution_mode {
            HttpResolutionMode::DirectPinned => build_direct_pinned_client(target),
            // SOCKS5h/HTTP proxy 必须保留 hostname 交代理端解析；使用本地 guard 地址会破坏抗污染与
            // 外部 FakeIP。代理端最终 IP 无法由 SOCKS5 协议回传，故该模式的 TOCTOU 是显式残留。
            HttpResolutionMode::ProxyRemoteDns => Ok(self.client.clone()),
            #[cfg(test)]
            HttpResolutionMode::TestOverride => Ok(self.client.clone()),
        };
        let url = url.to_string();
        let init = init.clone();
        async move { fetch_one_hop(client?, url, init).await }
    }
}
