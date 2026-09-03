use super::super::*;
use crate::safe_redirect::{FetchInit, MinimalResponse};
use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;

/// mock DnsLookup：默认解析到公网 IP；可注入特定 hostname → 内网 IP（触发 SSRF guard）。
struct MockLookup {
    private: HashMap<String, Vec<String>>,
}
impl MockLookup {
    fn public() -> Self {
        Self {
            private: HashMap::new(),
        }
    }
}
impl DnsLookup for MockLookup {
    fn lookup_all(&self, host: &str) -> impl Future<Output = Result<Vec<String>, String>> + Send {
        let res = self
            .private
            .get(host)
            .cloned()
            .unwrap_or_else(|| vec!["93.184.216.34".to_string()]);
        async move { Ok(res) }
    }
}

/// mock HttpClient：按 url 返回预设响应；记录每次请求的 FetchInit（供断言 UA / 超时 / 体积闸透传）。
struct MockFetch {
    responses: Mutex<HashMap<String, MinimalResponse>>,
    /// 网络错误注入：url → 错误串。
    errors: Mutex<HashMap<String, String>>,
    seen: Mutex<Vec<(String, FetchInit)>>,
}
impl MockFetch {
    fn new() -> Self {
        Self {
            responses: Mutex::new(HashMap::new()),
            errors: Mutex::new(HashMap::new()),
            seen: Mutex::new(Vec::new()),
        }
    }
    fn set(&self, url: &str, resp: MinimalResponse) -> &Self {
        self.responses.lock().unwrap().insert(url.to_string(), resp);
        self
    }
    fn set_err(&self, url: &str, msg: &str) -> &Self {
        self.errors
            .lock()
            .unwrap()
            .insert(url.to_string(), msg.to_string());
        self
    }
    fn last_init(&self) -> FetchInit {
        self.seen.lock().unwrap().last().unwrap().1.clone()
    }
}
impl HttpClient for MockFetch {
    fn fetch(
        &self,
        url: &str,
        init: &FetchInit,
    ) -> impl Future<Output = Result<MinimalResponse, String>> + Send {
        self.seen
            .lock()
            .unwrap()
            .push((url.to_string(), init.clone()));
        let err = self.errors.lock().unwrap().get(url).cloned();
        let resp = self.responses.lock().unwrap().remove(url);
        async move {
            if let Some(e) = err {
                return Err(e);
            }
            Ok(resp.unwrap_or(MinimalResponse {
                status: 404,
                ..Default::default()
            }))
        }
    }
}

fn ok_body(body: &str) -> MinimalResponse {
    MinimalResponse {
        status: 200,
        body: body.as_bytes().to_vec(),
        ..Default::default()
    }
}

async fn fetch(
    client: &MockFetch,
    lookup: &MockLookup,
    url: &str,
) -> Result<String, SubscriptionFetchError> {
    fetch_subscription_full(
        client,
        lookup,
        url,
        "Polaris/0.1.0",
        None,
        false,
        MAIN_FETCH_TIMEOUT_MS,
    )
    .await
}

/// 核心回归：**正文真的被返回**（旧实现恒返回空串 / `Ok(())` —— 拉取流水线拿不到正文）。
#[tokio::test]
async fn returns_body_text() {
    let c = MockFetch::new();
    c.set("https://sub.example.com/x", ok_body("hello-subscription"));
    let r = fetch(&c, &MockLookup::public(), "https://sub.example.com/x").await;
    assert_eq!(r.unwrap(), "hello-subscription");
}

#[tokio::test]
async fn invalid_utf8_is_rejected_without_lossy_expansion() {
    let client = MockFetch::new();
    client.set(
        "https://example.com/sub",
        MinimalResponse {
            status: 200,
            body: vec![0xff, 0xfe, 0xfd],
            ..Default::default()
        },
    );
    let error = fetch(&client, &MockLookup::public(), "https://example.com/sub")
        .await
        .unwrap_err();
    assert_eq!(error.kind, SubscriptionErrorKind::InvalidEncoding);
    assert!(error.message.contains("UTF-8"));
}

/// **SSRF 变异验证的靶子**：订阅 URL 解析到内网 → 必须拒。
/// 打断 fetch_subscription_full 里的 safe_redirect_fetch guard → 本测试转红。
#[tokio::test]
async fn ssrf_guard_rejects_private_host() {
    let c = MockFetch::new();
    c.set("https://intranet.example.com/x", ok_body("leaked"));
    let lk = MockLookup {
        private: HashMap::from([(
            "intranet.example.com".to_string(),
            vec!["192.168.1.10".to_string()],
        )]),
    };
    let e = fetch(&c, &lk, "https://intranet.example.com/x")
        .await
        .expect_err("解析到内网的订阅地址必须被拒");
    assert_eq!(e.kind, SubscriptionErrorKind::Ssrf);
    // 必须真的没发出请求（不是拿到正文后才拒）。
    assert!(
        c.seen.lock().unwrap().is_empty(),
        "SSRF guard 须在发请求前拦截"
    );
}

/// SSRF：字面内网 IP 直接拒（不依赖 DNS）。
#[tokio::test]
async fn ssrf_guard_rejects_literal_private_ip() {
    let c = MockFetch::new();
    c.set("http://127.0.0.1:8080/x", ok_body("leaked"));
    let e = fetch(&c, &MockLookup::public(), "http://127.0.0.1:8080/x")
        .await
        .expect_err("字面回环地址必须被拒");
    assert_eq!(e.kind, SubscriptionErrorKind::Ssrf);
}

/// SSRF：30x 跳内网必须逐跳复检拦下（首跳公网、次跳内网）。
#[tokio::test]
async fn ssrf_guard_rejects_redirect_to_private() {
    let c = MockFetch::new();
    c.set(
        "https://sub.example.com/x",
        MinimalResponse {
            status: 302,
            location: Some("http://169.254.169.254/latest/meta-data".to_string()),
            ..Default::default()
        },
    );
    let e = fetch(&c, &MockLookup::public(), "https://sub.example.com/x")
        .await
        .expect_err("重定向到云元数据地址必须被拒");
    assert_eq!(e.kind, SubscriptionErrorKind::Ssrf);
}

/// 协议闸：非 http(s) 拒，且错误文案不含 query（token 脱敏）。
#[tokio::test]
async fn rejects_non_http_scheme_and_redacts_token() {
    let c = MockFetch::new();
    let e = fetch(
        &c,
        &MockLookup::public(),
        "file:///etc/passwd?token=secret123",
    )
    .await
    .expect_err("file:// 必须被拒");
    assert_eq!(e.kind, SubscriptionErrorKind::Scheme);
    assert!(
        !e.message.contains("secret123"),
        "错误文案泄漏了 token: {}",
        e.message
    );
}

/// HTTP 状态：非 2xx → Http + status（供 i18n `{{status}}` 插值）。
#[tokio::test]
async fn non_2xx_classified_as_http_with_status() {
    let c = MockFetch::new();
    c.set(
        "https://sub.example.com/x",
        MinimalResponse {
            status: 403,
            ..Default::default()
        },
    );
    let e = fetch(&c, &MockLookup::public(), "https://sub.example.com/x")
        .await
        .expect_err("403 必须失败");
    assert_eq!(e.kind, SubscriptionErrorKind::Http);
    assert_eq!(e.http_status, Some(403));
}

/// 体积闸：content-length 预检（早拒，不看 body）。
#[tokio::test]
async fn content_length_precheck_rejects_oversize() {
    let c = MockFetch::new();
    c.set(
        "https://sub.example.com/x",
        MinimalResponse {
            status: 200,
            headers: vec![(
                "Content-Length".to_string(),
                (MAX_BODY_BYTES + 1).to_string(),
            )],
            body: b"small".to_vec(),
            ..Default::default()
        },
    );
    let e = fetch(&c, &MockLookup::public(), "https://sub.example.com/x")
        .await
        .expect_err("content-length 超限必须拒");
    assert_eq!(e.kind, SubscriptionErrorKind::TooLarge);
}

/// 体积闸：content-length 撒谎/缺失时，正文字节复检兜底。
#[tokio::test]
async fn body_size_recheck_rejects_oversize_when_content_length_lies() {
    let c = MockFetch::new();
    c.set(
        "https://sub.example.com/x",
        MinimalResponse {
            status: 200,
            headers: vec![("content-length".to_string(), "5".to_string())],
            body: vec![b'a'; MAX_BODY_BYTES + 1],
            ..Default::default()
        },
    );
    let e = fetch(&c, &MockLookup::public(), "https://sub.example.com/x")
        .await
        .expect_err("正文超限必须拒（content-length 不可信）");
    assert_eq!(e.kind, SubscriptionErrorKind::TooLarge);
}

/// UA / **剩余 absolute budget** / 体积闸须透传到实现侧。
#[tokio::test]
async fn passes_ua_timeout_and_cap_to_client() {
    let c = MockFetch::new();
    c.set("https://sub.example.com/x", ok_body("ok"));
    fetch(&c, &MockLookup::public(), "https://sub.example.com/x")
        .await
        .unwrap();
    let init = c.last_init();
    assert_eq!(init.user_agent, "Polaris/0.1.0");
    assert!(
        init.timeout_ms
            .is_some_and(|ms| ms > 0 && ms <= MAIN_FETCH_TIMEOUT_MS),
        "实现侧应收到整链 deadline 的剩余预算，实得 {:?}",
        init.timeout_ms
    );
    assert_eq!(init.max_body_bytes, Some(MAX_BODY_BYTES));
}

/// 网络错误**不得**被误报成 SSRF（safe_redirect 曾把 client 错误一律标 reason=Ssrf）。
#[tokio::test]
async fn network_error_is_not_misclassified_as_ssrf() {
    let c = MockFetch::new();
    c.set_err(
        "https://sub.example.com/x",
        "tcp connect error: Connection refused (os error 111)",
    );
    let e = fetch(&c, &MockLookup::public(), "https://sub.example.com/x")
        .await
        .expect_err("连接被拒必须失败");
    assert_eq!(e.kind, SubscriptionErrorKind::Refused);
}

#[tokio::test]
async fn network_timeout_classified() {
    let c = MockFetch::new();
    c.set_err(
        "https://sub.example.com/x",
        "request timed out after 30000ms",
    );
    let e = fetch(&c, &MockLookup::public(), "https://sub.example.com/x")
        .await
        .expect_err("超时必须失败");
    assert_eq!(e.kind, SubscriptionErrorKind::Timeout);
}

/// 拉取 → 解析 全链（mock client）：base64 订阅正文 → 真节点。
#[tokio::test]
async fn fetch_then_parse_yields_nodes() {
    let links = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@1.2.3.4:8388#node-a\n";
    let b64 = super::super::tests::b64(links);
    let c = MockFetch::new();
    c.set("https://sub.example.com/x", ok_body(&b64));
    let text = fetch(&c, &MockLookup::public(), "https://sub.example.com/x")
        .await
        .unwrap();
    assert_eq!(detect_format(text.trim()), SubscriptionFormat::Base64);
    let mut n = 0;
    let mut id_gen = || {
        n += 1;
        format!("id-{n}")
    };
    let parsed = parse_subscription(
        text.trim(),
        "sub-1",
        "2026-07-16T00:00:00Z",
        &mut id_gen,
        ImportOrigin::RemoteSubscription,
    );
    assert_eq!(parsed.servers.len(), 1);
    assert_eq!(parsed.servers[0].address, "1.2.3.4");
    assert_eq!(parsed.servers[0].port, 8388);
}

async fn fetch_meta(
    client: &MockFetch,
    lookup: &MockLookup,
    url: &str,
    conditional: Option<&Conditional>,
) -> Result<FetchedSubscription, SubscriptionFetchError> {
    fetch_subscription_with_meta(
        client,
        lookup,
        url,
        "Polaris/0.1.0",
        conditional,
        false,
        MAIN_FETCH_TIMEOUT_MS,
    )
    .await
}

/// userInfo 解析 + 验证器回传（打断 parse_user_info / header 读取任一 → 断言转红）。
#[tokio::test]
async fn meta_parses_userinfo_and_validators() {
    let c = MockFetch::new();
    c.set(
        "https://sub.example.com/x",
        MinimalResponse {
            status: 200,
            headers: vec![
                (
                    "Subscription-UserInfo".to_string(),
                    "upload=100; download=200; total=1000; expire=1700000000".to_string(),
                ),
                ("ETag".to_string(), "\"abc123\"".to_string()),
                (
                    "Last-Modified".to_string(),
                    "Wed, 21 Oct 2025 07:28:00 GMT".to_string(),
                ),
            ],
            body: b"vless://11111111-1111-1111-1111-111111111111@a.com:443?type=tcp#n".to_vec(),
            ..Default::default()
        },
    );
    let f = fetch_meta(&c, &MockLookup::public(), "https://sub.example.com/x", None)
        .await
        .expect("200 应成功");
    let ui = f.user_info.expect("应解出 userInfo");
    assert_eq!(ui.upload, Some(100));
    assert_eq!(ui.download, Some(200));
    assert_eq!(ui.total, Some(1000));
    assert_eq!(ui.expire, Some(1_700_000_000));
    assert_eq!(f.etag.as_deref(), Some("\"abc123\""));
    assert_eq!(
        f.last_modified.as_deref(),
        Some("Wed, 21 Oct 2025 07:28:00 GMT")
    );
    assert!(!f.not_modified);
}

/// 304 + 确实发了条件头 → not_modified 短路（不读 body），回传验证器。
#[tokio::test]
async fn meta_304_with_conditional_shortcircuits() {
    let c = MockFetch::new();
    c.set(
        "https://sub.example.com/x",
        MinimalResponse {
            status: 304,
            headers: vec![("ETag".to_string(), "\"same\"".to_string())],
            ..Default::default()
        },
    );
    let cond = Conditional {
        etag: Some("\"same\"".to_string()),
        last_modified: None,
    };
    let f = fetch_meta(
        &c,
        &MockLookup::public(),
        "https://sub.example.com/x",
        Some(&cond),
    )
    .await
    .expect("304 条件命中不是错误");
    assert!(f.not_modified, "发了条件头且 304 → not_modified");
    assert!(f.text.is_empty(), "304 不读 body");
    assert_eq!(f.etag.as_deref(), Some("\"same\""));
    // 条件头必须真的发出（If-None-Match）。
    let init = c.last_init();
    assert!(
        init.headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("if-none-match") && v == "\"same\""),
        "须发 If-None-Match，实际头: {:?}",
        init.headers
    );
}

/// 304 但**未**发条件头（fail-safe）→ 归 Http 错误（绝不当 not_modified，防空 body 误删存量）。
#[tokio::test]
async fn meta_304_without_conditional_is_http_error() {
    let c = MockFetch::new();
    c.set(
        "https://sub.example.com/x",
        MinimalResponse {
            status: 304,
            ..Default::default()
        },
    );
    let e = fetch_meta(&c, &MockLookup::public(), "https://sub.example.com/x", None)
        .await
        .expect_err("未发条件头的 304 必须当失败");
    assert_eq!(e.kind, SubscriptionErrorKind::Http);
    assert_eq!(e.http_status, Some(304));
}

#[test]
fn parse_user_info_variants() {
    // 全字段。
    let ui = parse_user_info(Some("upload=1; download=2; total=3; expire=4")).unwrap();
    assert_eq!(
        (ui.upload, ui.download, ui.total, ui.expire),
        (Some(1), Some(2), Some(3), Some(4))
    );
    // 部分字段 + 非数字段跳过。
    let ui = parse_user_info(Some("total=500; expire=bad; junk=x")).unwrap();
    assert_eq!(ui.total, Some(500));
    assert_eq!(ui.expire, None);
    // parseInt 前缀语义（带单位）。
    let ui = parse_user_info(Some("total=107374182400 bytes")).unwrap();
    assert_eq!(ui.total, Some(107_374_182_400));
    // 全空 / None → None。
    assert!(parse_user_info(Some("garbage")).is_none());
    assert!(parse_user_info(None).is_none());
    // 大流量超 u32（4TB）不溢出。
    let ui = parse_user_info(Some("total=4398046511104")).unwrap();
    assert_eq!(ui.total, Some(4_398_046_511_104));
}

#[test]
fn redact_url_strips_query_and_userinfo() {
    assert_eq!(
        redact_url("https://sub.example.com/link?token=secret123"),
        "https://sub.example.com/link?<redacted>"
    );
    assert_eq!(
        redact_url("https://sub.example.com/link"),
        "https://sub.example.com/link"
    );
    // userinfo 也是凭据。
    assert!(!redact_url("https://user:pass@sub.example.com/l?t=1").contains("pass"));
    // 非法 URL 兜底截断。
    assert_eq!(redact_url("not a url?token=x"), "not a url?<redacted>");
}

#[test]
fn default_ua_is_neutral() {
    assert_eq!(default_subscription_user_agent("1.2.3"), "Polaris/1.2.3");
}
