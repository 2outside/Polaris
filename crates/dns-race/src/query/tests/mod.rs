use super::*;
use crate::upstream::parse_custom_upstream;
use crate::wire::{classify_dns_response, encode_dns_query, DnsResponseClass};
use polaris_config_engine::user_config::dns_config::CustomDnsUpstream;
use std::sync::Mutex;

/// 记录被请求 URL 的 mock DoH（零网络）。
struct RecordingDoh {
    urls: Mutex<Vec<String>>,
    reply: Result<Vec<u8>, String>,
}

#[async_trait]
impl DohPost for RecordingDoh {
    async fn post_dns_message(&self, url: &str, _body: Vec<u8>) -> Result<Vec<u8>, String> {
        self.urls.lock().unwrap().push(url.to_string());
        self.reply.clone()
    }
}

fn doh(reply: Result<Vec<u8>, String>) -> Arc<RecordingDoh> {
    Arc::new(RecordingDoh {
        urls: Mutex::new(Vec::new()),
        reply,
    })
}

#[tokio::test]
async fn doh_url_is_assembled_from_ip_port_path() {
    let rec = doh(Ok(vec![0u8; 12]));
    let q = DefaultUpstreamQuery::new(rec.clone());
    let up = parse_custom_upstream(&CustomDnsUpstream {
        id: "c".into(),
        spec: "https://9.9.9.9:8443/q".into(),
    })
    .unwrap();
    q.query(&up, &[0u8; 12]).await.unwrap();
    assert_eq!(
        rec.urls.lock().unwrap().as_slice(),
        ["https://9.9.9.9:8443/q"]
    );
}

#[tokio::test]
async fn per_upstream_timeout_converts_hang_to_err() {
    struct HangDoh;
    #[async_trait]
    impl DohPost for HangDoh {
        async fn post_dns_message(&self, _u: &str, _b: Vec<u8>) -> Result<Vec<u8>, String> {
            std::future::pending().await
        }
    }
    let q = DefaultUpstreamQuery::with_timeout(Arc::new(HangDoh), Duration::from_millis(20));
    let up = crate::upstream::builtin_upstream("ali").unwrap();
    let r = q.query(&up, &[0u8; 12]).await;
    assert!(r.is_err(), "挂死上游必须被单上游超时转成 FAIL");
}

/// mock UDP 上游 —— **只绑 127.0.0.1**，随测试结束即关（严禁碰宿主网络）。
/// `answer_ip` = 要回的 A 记录；`forge_id` = 是否故意用错 message id（验注入硬化）。
async fn spawn_mock_udp_upstream(
    answer_ip: [u8; 4],
    forge_id: bool,
) -> (u16, tokio::task::JoinHandle<()>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_DNS_UDP_BYTES];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            let mut resp = build_answer_response(
                &buf[..n],
                &[AnswerRecord {
                    rtype: TYPE_A,
                    rdata: answer_ip.to_vec(),
                }],
            );
            if forge_id {
                resp[0] ^= 0xff; // 伪造 id：客户端必须忽略
            }
            let _ = sock.send_to(&resp, from).await;
            if forge_id {
                continue; // 一直发坏包，逼客户端超时
            }
            break;
        }
    });
    (port, handle)
}

#[tokio::test]
async fn udp_upstream_roundtrip_over_loopback() {
    let (port, srv) = spawn_mock_udp_upstream([7, 7, 7, 7], false).await;
    let q = encode_dns_query("node.example.com", TYPE_A, 0x1357);
    let resp = udp_query("127.0.0.1", port, &q)
        .await
        .expect("回环 mock 上游应答");
    assert_eq!(classify_dns_response(&resp, TYPE_A), DnsResponseClass::Hit);
    assert_eq!(
        crate::wire::extract_answer_ip_bytes(&resp),
        vec![vec![7, 7, 7, 7]]
    );
    srv.abort();
}

#[tokio::test]
async fn udp_upstream_ignores_responses_with_wrong_message_id() {
    let (port, srv) = spawn_mock_udp_upstream([6, 6, 6, 6], true).await;
    let q = encode_dns_query("node.example.com", TYPE_A, 0x2468);
    // id 不匹配的包被忽略 → 没有合法应答 → 由超时兜（此处直接用 timeout 断言不会误收）。
    let r =
        tokio::time::timeout(Duration::from_millis(120), udp_query("127.0.0.1", port, &q)).await;
    assert!(r.is_err(), "伪造 id 的应答绝不能被当成答案");
    srv.abort();
}

#[tokio::test]
async fn system_upstream_rejects_aaaa() {
    let q = encode_dns_query("node.example.com", TYPE_AAAA, 1);
    assert!(
        system_query(&SystemInFlight::default(), &q).await.is_err(),
        "AAAA 二期 → FAIL 让 Tier1 兜"
    );
}

#[tokio::test]
async fn system_upstream_rejects_malformed_query_without_resolving() {
    assert!(system_query(&SystemInFlight::default(), &[0u8; 4])
        .await
        .is_err());
}

/// IPv6 自定义 DoH 上游的 URL 必须带方括号。
/// 变异验证：把 `query_one` 里的 `bracket_ipv6(...)` 换回裸 `up.ip` → URL 变成
/// `https://2606:4700:4700::1111:443/dns-query`（无括号）→ 本断言转红。
#[tokio::test]
async fn doh_url_brackets_ipv6_literal() {
    let rec = doh(Ok(vec![0u8; 12]));
    let q = DefaultUpstreamQuery::new(rec.clone());
    let up = parse_custom_upstream(&CustomDnsUpstream {
        id: "v6".into(),
        spec: "https://[2606:4700:4700::1111]/dns-query".into(),
    })
    .expect("config-engine 的 parse_dns_server_spec 明确接受 v6 字面量");
    q.query(&up, &[0u8; 12]).await.unwrap();
    assert_eq!(
        rec.urls.lock().unwrap().as_slice(),
        ["https://[2606:4700:4700::1111]:443/dns-query"],
        "无方括号的 URL 会被 reqwest 判非法 → 该上游恒静默 FAIL"
    );
}

/// v6 上游地址文本 → SocketAddr（纯解析，不开 socket、不碰宿主网络）。
/// 变异验证：去掉 `bracket_ipv6` → `::1:53` / `2606:...::1111:53` 均 parse 失败 → 转红。
#[test]
fn upstream_socket_addr_parses_ipv6_literals() {
    let a = upstream_socket_addr("::1", 53).expect("v6 回环字面量须可解析");
    assert!(a.is_ipv6() && a.port() == 53);
    let b = upstream_socket_addr("2606:4700:4700::1111", 5353).expect("v6 全局字面量");
    assert!(b.is_ipv6() && b.port() == 5353);
    // 已带方括号的输入不重复加括号。
    assert!(upstream_socket_addr("[::1]", 53).is_ok());
    // v4 不受影响。
    let v4 = upstream_socket_addr("8.8.8.8", 53).expect("v4");
    assert!(v4.is_ipv4());
    // 真非法仍是 Err（守住「补括号 ≠ 放宽校验」）。
    assert!(upstream_socket_addr("not-an-ip", 53).is_err());
}

/// 【机制】system 腿在飞守卫：同名互斥、异名不互斥、释放后可重入。
#[test]
fn system_in_flight_guard_is_per_qname_and_releases_on_drop() {
    let f = SystemInFlight::default();
    let g1 = f.enter("node.example.com").expect("首次占位");
    assert!(
        f.enter("node.example.com").is_none(),
        "同名在飞必须拒绝 —— 这正是 TUN 下自递归被钉死在一层的机制"
    );
    assert!(f.enter("other.example.com").is_some(), "异名互不影响");
    drop(g1);
    assert!(f.enter("node.example.com").is_some(), "释放后可重入");
}

/// 【接线】`system_query` 真的会先过守卫、且被拒时**不做任何解析**。
///
/// qname 取 `localhost`：/etc/hosts（nsswitch `files` 先于 `dns`）本地即答，
/// 即便守卫被改坏也不会把查询发到宿主网络 —— 只会让下面的断言转红。
/// 变异验证：删掉 `system_query` 里的 `in_flight.enter(...)?` → 返回 Ok → 转红。
#[tokio::test]
async fn system_query_refuses_reentrant_same_qname() {
    let f = SystemInFlight::default();
    let held = f
        .enter("localhost")
        .expect("模拟上一层 system 腿正在等 OS resolver");
    let wire = encode_dns_query("localhost", TYPE_A, 0x4242);
    let err = system_query(&f, &wire)
        .await
        .expect_err("同名重入必须立刻 FAIL，不得再问 OS resolver（否则 TUN 下逐级放大）");
    assert!(err.contains("自递归防护"), "实际: {err}");
    drop(held);
    // 守卫释放后同一 qname 可以正常走完（localhost 走 /etc/hosts，零网络）。
    assert!(
        system_query(&f, &wire).await.is_ok(),
        "守卫释放后不得留下永久占位"
    );
}
