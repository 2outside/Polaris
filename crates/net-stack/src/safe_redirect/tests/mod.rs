use super::*;
use crate::ssrf::DnsLookup;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 测试用 mock DnsLookup：默认公网，可注入特定 hostname 的内网解析。
struct MockLookup {
    private: HashMap<String, Vec<String>>,
}

impl DnsLookup for MockLookup {
    fn lookup_all(&self, host: &str) -> impl Future<Output = Result<Vec<String>, String>> + Send {
        let res = self
            .private
            .get(host)
            .cloned()
            .unwrap_or_else(|| vec!["8.8.8.8".to_string()]);
        async move { Ok(res) }
    }
}

/// 测试用 mock HttpClient：按脚本返回预设 (status, location) 序列。
#[allow(clippy::type_complexity)]
struct MockFetch {
    /// url → 重定向链脚本（按请求序逐个弹出）。Mutex 保 Sync（HttpClient: Send + Sync）。
    scripts: Mutex<HashMap<String, Vec<(u16, Option<String>)>>>,
}

impl MockFetch {
    fn new() -> Self {
        Self {
            scripts: Mutex::new(HashMap::new()),
        }
    }
    fn set(&self, url: &str, chain: Vec<(u16, Option<String>)>) {
        self.scripts.lock().unwrap().insert(url.to_string(), chain);
    }
}

impl HttpClient for MockFetch {
    fn fetch(
        &self,
        url: &str,
        _init: &FetchInit,
    ) -> impl Future<Output = Result<MinimalResponse, String>> + Send {
        let mut scripts = self.scripts.lock().unwrap();
        let chain = scripts.get_mut(url);
        let resp = if let Some(c) = chain {
            if c.is_empty() {
                MinimalResponse {
                    status: 500,
                    ..Default::default()
                }
            } else {
                let (status, location) = c.remove(0);
                MinimalResponse {
                    status,
                    location,
                    ..Default::default()
                }
            }
        } else {
            MinimalResponse {
                status: 404,
                ..Default::default()
            }
        };
        async move { Ok(resp) }
    }
}

fn opts<'a, H: HttpClient, L: DnsLookup>(
    fetch_impl: &'a H,
    lookup: &'a L,
    url: &'a str,
) -> SafeRedirectFetchOptions<'a, H, L> {
    SafeRedirectFetchOptions {
        fetch_impl,
        url,
        user_agent: "Polaris/0.1".to_string(),
        headers: None,
        exempt_fake_ip: false,
        max_redirects: None,
        timeout_ms: None,
        max_body_bytes: None,
        lookup,
    }
}

#[tokio::test]
async fn no_redirect_returns_terminal() {
    let fetch = MockFetch::new();
    fetch.set("https://example.com/sub", vec![(200, None)]);
    let lk = MockLookup {
        private: HashMap::new(),
    };
    let r = safe_redirect_fetch(opts(&fetch, &lk, "https://example.com/sub")).await;
    assert!(r.is_ok());
    assert_eq!(r.unwrap().status, 200);
}

#[tokio::test]
async fn follows_safe_redirect_chain() {
    let fetch = MockFetch::new();
    fetch.set(
        "https://example.com/a",
        vec![(302, Some("https://cdn.example.com/b".to_string()))],
    );
    fetch.set("https://cdn.example.com/b", vec![(200, None)]);
    let lk = MockLookup {
        private: HashMap::new(),
    };
    let r = safe_redirect_fetch(opts(&fetch, &lk, "https://example.com/a")).await;
    assert!(r.is_ok());
    assert_eq!(r.unwrap().status, 200);
}

#[tokio::test]
async fn relative_location_resolved() {
    let fetch = MockFetch::new();
    fetch.set(
        "https://example.com/start",
        vec![(302, Some("/next".to_string()))],
    );
    fetch.set("https://example.com/next", vec![(200, None)]);
    let lk = MockLookup {
        private: HashMap::new(),
    };
    let r = safe_redirect_fetch(opts(&fetch, &lk, "https://example.com/start")).await;
    assert!(r.is_ok());
}

#[tokio::test]
async fn redirect_to_private_ssrf_blocked() {
    let fetch = MockFetch::new();
    fetch.set(
        "https://evil.example.com/redir",
        vec![(
            302,
            Some("https://meta.evil.example.com/secret".to_string()),
        )],
    );
    let lk = MockLookup {
        private: HashMap::from([(
            "meta.evil.example.com".to_string(),
            vec!["169.254.169.254".to_string()],
        )]),
    };
    let r = safe_redirect_fetch(opts(&fetch, &lk, "https://evil.example.com/redir")).await;
    assert!(r.is_err());
    assert_eq!(r.unwrap_err().reason, SafeFetchRejectReason::Ssrf);
}

#[tokio::test]
async fn redirect_to_non_http_protocol_blocked() {
    let fetch = MockFetch::new();
    fetch.set(
        "https://example.com/f",
        vec![(302, Some("file:///etc/passwd".to_string()))],
    );
    let lk = MockLookup {
        private: HashMap::new(),
    };
    let r = safe_redirect_fetch(opts(&fetch, &lk, "https://example.com/f")).await;
    assert!(r.is_err());
    assert_eq!(
        r.unwrap_err().reason,
        SafeFetchRejectReason::RedirectProtocol
    );
}

#[tokio::test]
async fn too_many_redirects_blocked() {
    let fetch = MockFetch::new();
    // 循环重定向：a→b→a→b...（无终态）。max_redirects=3 ⇒ hop 0..3 续跳、hop=3 时触发 too-many。
    // MockFetch 每请求弹一个脚本条目，故每 URL 提供足够长度的链（4 跳：a 用 2 次、b 用 2 次）。
    let a_target = "https://loop.example.com/b".to_string();
    let b_target = "https://loop.example.com/a".to_string();
    fetch.set(
        "https://loop.example.com/a",
        vec![(302, Some(a_target.clone())), (302, Some(a_target))],
    );
    fetch.set(
        "https://loop.example.com/b",
        vec![(302, Some(b_target.clone())), (302, Some(b_target))],
    );
    let lk = MockLookup {
        private: HashMap::new(),
    };
    let mut o = opts(&fetch, &lk, "https://loop.example.com/a");
    o.max_redirects = Some(3);
    let r = safe_redirect_fetch(o).await;
    assert!(r.is_err());
    assert_eq!(
        r.unwrap_err().reason,
        SafeFetchRejectReason::TooManyRedirects
    );
}

#[tokio::test]
async fn first_hop_ssrf_blocked() {
    // 首跳 URL 本身解析到内网 → guard 首跳即拒
    let fetch = MockFetch::new();
    let lk = MockLookup {
        private: HashMap::from([(
            "internal.example.com".to_string(),
            vec!["10.0.0.5".to_string()],
        )]),
    };
    let r = safe_redirect_fetch(opts(&fetch, &lk, "https://internal.example.com/x")).await;
    assert!(r.is_err());
    assert_eq!(r.unwrap_err().reason, SafeFetchRejectReason::Ssrf);
}

#[tokio::test]
async fn max_redirects_zero_allows_one_fetch() {
    // max_redirects=0：允许首跳 fetch，但若首跳即 30x → too-many（hop>=max_redirects=0）
    let fetch = MockFetch::new();
    fetch.set("https://example.com/ok", vec![(200, None)]);
    let lk = MockLookup {
        private: HashMap::new(),
    };
    let mut o = opts(&fetch, &lk, "https://example.com/ok");
    o.max_redirects = Some(0);
    let r = safe_redirect_fetch(o).await;
    assert!(r.is_ok());
}

#[tokio::test]
async fn max_redirects_zero_blocks_redirect() {
    let fetch = MockFetch::new();
    fetch.set(
        "https://example.com/r",
        vec![(302, Some("https://cdn.example.com/x".to_string()))],
    );
    let lk = MockLookup {
        private: HashMap::new(),
    };
    let mut o = opts(&fetch, &lk, "https://example.com/r");
    o.max_redirects = Some(0);
    let r = safe_redirect_fetch(o).await;
    assert!(r.is_err());
    assert_eq!(
        r.unwrap_err().reason,
        SafeFetchRejectReason::TooManyRedirects
    );
}

struct SlowLookup;

impl DnsLookup for SlowLookup {
    async fn lookup_all(&self, _host: &str) -> Result<Vec<String>, String> {
        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok(vec!["8.8.8.8".to_string()])
    }
}

#[tokio::test]
async fn absolute_deadline_covers_initial_dns_guard() {
    let fetch = MockFetch::new();
    let result = safe_redirect_fetch_until(
        opts(&fetch, &SlowLookup, "https://slow-dns.example/sub"),
        Instant::now() + Duration::from_millis(20),
    )
    .await;
    assert_eq!(result.unwrap_err().reason, SafeFetchRejectReason::Timeout);
}

struct SlowRedirectFetch {
    calls: Arc<Mutex<usize>>,
}

impl HttpClient for SlowRedirectFetch {
    fn fetch(
        &self,
        url: &str,
        _init: &FetchInit,
    ) -> impl Future<Output = Result<MinimalResponse, String>> + Send {
        let url = url.to_string();
        let calls = Arc::clone(&self.calls);
        async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            *calls.lock().unwrap() += 1;
            Ok(if url.ends_with("/start") {
                MinimalResponse {
                    status: 302,
                    location: Some("/terminal".to_string()),
                    ..Default::default()
                }
            } else {
                MinimalResponse {
                    status: 200,
                    body: b"ok".to_vec(),
                    ..Default::default()
                }
            })
        }
    }
}

#[tokio::test]
async fn absolute_deadline_is_shared_across_redirect_hops() {
    let calls = Arc::new(Mutex::new(0));
    let fetch = SlowRedirectFetch {
        calls: Arc::clone(&calls),
    };
    let lookup = MockLookup {
        private: HashMap::new(),
    };
    let result = safe_redirect_fetch_until(
        opts(&fetch, &lookup, "https://redirect.example/start"),
        Instant::now() + Duration::from_millis(30),
    )
    .await;
    assert_eq!(result.unwrap_err().reason, SafeFetchRejectReason::Timeout);
    assert_eq!(*calls.lock().unwrap(), 1, "第二跳应被同一总 deadline 截断");
}

struct GuardTargetRecorder {
    addresses: Arc<Mutex<Vec<std::net::IpAddr>>>,
}

impl HttpClient for GuardTargetRecorder {
    async fn fetch(&self, _url: &str, _init: &FetchInit) -> Result<MinimalResponse, String> {
        panic!("safe redirect 必须调用 fetch_guarded")
    }

    fn fetch_guarded(
        &self,
        _url: &str,
        _init: &FetchInit,
        target: &GuardedTarget,
    ) -> impl Future<Output = Result<MinimalResponse, String>> + Send {
        *self.addresses.lock().unwrap() = target.addresses.clone();
        async {
            Ok(MinimalResponse {
                status: 200,
                ..Default::default()
            })
        }
    }
}

#[tokio::test]
async fn hostname_fake_ip_is_allowed_and_forwarded_to_direct_dial_pin() {
    let addresses = Arc::new(Mutex::new(Vec::new()));
    let fetch = GuardTargetRecorder {
        addresses: Arc::clone(&addresses),
    };
    let lookup = MockLookup {
        private: HashMap::from([("fake.example".to_string(), vec!["198.18.12.34".to_string()])]),
    };
    safe_redirect_fetch(opts(&fetch, &lookup, "https://fake.example/sub"))
        .await
        .expect("域名 FakeIP 应交给直连 pin/TUN，而不是 guard 拒绝");
    assert_eq!(
        *addresses.lock().unwrap(),
        vec!["198.18.12.34".parse::<std::net::IpAddr>().unwrap()]
    );
}

#[tokio::test]
async fn literal_fake_ip_is_rejected_before_dial() {
    let fetch = MockFetch::new();
    let lookup = MockLookup {
        private: HashMap::new(),
    };
    let result = safe_redirect_fetch(opts(&fetch, &lookup, "https://198.18.1.2/sub")).await;
    assert_eq!(result.unwrap_err().reason, SafeFetchRejectReason::Ssrf);
}
