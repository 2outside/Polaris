use super::*;

// ── IPv4 私网段穷举 ──────────────────────────────────────────────────────
#[test]
fn ipv4_loopback_and_wildcard() {
    assert!(is_private_ip("127.0.0.1"));
    assert!(is_private_ip("127.255.255.255"));
    assert!(is_private_ip("127.0.0.0"));
    assert!(is_private_ip("0.0.0.0")); // a===0 通配
    assert!(is_private_ip("0.1.2.3"));
}

#[test]
fn ipv4_rfc1918_ten() {
    assert!(is_private_ip("10.0.0.0"));
    assert!(is_private_ip("10.255.255.255"));
    assert!(is_private_ip("10.1.2.3"));
}

#[test]
fn ipv4_rfc1918_172_16_12() {
    assert!(is_private_ip("172.16.0.0"));
    assert!(is_private_ip("172.31.255.255"));
    assert!(is_private_ip("172.20.5.5"));
    // 边界外：172.15 / 172.32 非私网
    assert!(!is_private_ip("172.15.0.0"));
    assert!(!is_private_ip("172.32.0.0"));
}

#[test]
fn ipv4_rfc1918_192_168_16() {
    assert!(is_private_ip("192.168.0.0"));
    assert!(is_private_ip("192.168.1.1"));
    assert!(is_private_ip("192.168.255.255"));
}

#[test]
fn ipv4_link_local_and_cloud_metadata() {
    assert!(is_private_ip("169.254.0.0"));
    assert!(is_private_ip("169.254.169.254")); // 云元数据
    assert!(is_private_ip("169.254.255.255"));
    // 边界外
    assert!(!is_private_ip("169.253.0.0"));
    assert!(!is_private_ip("169.255.0.0"));
}

#[test]
fn ipv4_cgnat_100_64_10() {
    assert!(is_private_ip("100.64.0.0"));
    assert!(is_private_ip("100.127.255.255"));
    assert!(is_private_ip("100.100.100.100"));
    // 边界外
    assert!(!is_private_ip("100.63.255.255"));
    assert!(!is_private_ip("100.128.0.0"));
}

#[test]
fn ipv4_public_not_private() {
    assert!(!is_private_ip("1.1.1.1"));
    assert!(!is_private_ip("8.8.8.8"));
    assert!(!is_private_ip("172.32.0.1"));
    assert!(!is_private_ip("11.0.0.1"));
    assert!(!is_private_ip("198.18.0.1")); // FakeIP 段（非 isPrivateIp 管辖）
}

// ── IPv6 私网段穷举 ──────────────────────────────────────────────────────
#[test]
fn ipv6_loopback_and_unspecified() {
    assert!(is_private_ip("::1"));
    assert!(is_private_ip("::"));
}

#[test]
fn ipv6_ula_fc00_7() {
    assert!(is_private_ip("fc00::"));
    assert!(is_private_ip("fd00::1"));
    assert!(is_private_ip("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));
    // 非 ULA
    assert!(!is_private_ip("fe00::1"));
}

#[test]
fn ipv6_link_local_fe80_10() {
    assert!(is_private_ip("fe80::1"));
    assert!(is_private_ip("febf::"));
    assert!(is_private_ip("fe90::1"));
    assert!(is_private_ip("fea0::1"));
    assert!(!is_private_ip("fe7f::1")); // 边界外
    assert!(!is_private_ip("fec0::1")); // 边界外（fec0::/10 site-local 已废弃，TS 也不拦）
}

#[test]
fn ipv6_v4_mapped_loopback() {
    // ::ffff:127.0.0.1 → 递归判 IPv4 回环
    assert!(is_private_ip("::ffff:127.0.0.1"));
    assert!(is_private_ip("::ffff:7f00:1"));
    assert!(is_private_ip("0:0:0:0:0:ffff:127.0.0.1"));
    assert!(is_private_ip("::ffff:10.0.0.1"));
    assert!(is_private_ip("::ffff:192.168.1.1"));
    assert!(is_private_ip("::ffff:169.254.169.254"));
}

#[test]
fn ipv6_v4_mapped_public() {
    assert!(!is_private_ip("::ffff:1.1.1.1"));
    assert!(!is_private_ip("::ffff:8.8.8.8"));
}

#[test]
fn ipv6_brackets_normalized() {
    assert!(is_private_ip("[::1]"));
    assert!(is_private_ip("[fc00::1]"));
}

#[test]
fn ipv6_case_insensitive() {
    assert!(is_private_ip("FC00::1"));
    assert!(is_private_ip("FE80::1"));
}

#[test]
fn non_ip_returns_false() {
    assert!(!is_private_ip("example.com"));
    assert!(!is_private_ip(""));
    assert!(!is_private_ip("not an ip"));
}

// ── FakeIP 段判定 ─────────────────────────────────────────────────────────
#[test]
fn fakeip_v4_range() {
    assert!(is_polaris_fake_ip("198.18.0.0"));
    assert!(is_polaris_fake_ip("198.19.255.255"));
    assert!(is_polaris_fake_ip("198.18.123.45"));
    // 边界外
    assert!(!is_polaris_fake_ip("198.17.255.255"));
    assert!(!is_polaris_fake_ip("198.20.0.0"));
}

#[test]
fn fakeip_v6_range() {
    assert!(is_polaris_fake_ip("2001:2::"));
    assert!(is_polaris_fake_ip("2001:2:0:0:ffff:ffff:ffff:ffff")); // /48 覆盖
                                                                   // 边界外
    assert!(!is_polaris_fake_ip("2001:3::"));
}

#[test]
fn fakeip_non_literal_false() {
    assert!(!is_polaris_fake_ip("example.com"));
    assert!(!is_polaris_fake_ip(""));
    assert!(!is_polaris_fake_ip("1.1.1.1")); // 公网非假段
}

// ── expand_ipv6 内部 ──────────────────────────────────────────────────────
#[test]
fn expand_full_form() {
    assert_eq!(
        expand_ipv6("2001:db8::1"),
        Some([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1])
    );
}

#[test]
fn expand_v4_mapped() {
    assert_eq!(
        expand_ipv6("::ffff:127.0.0.1"),
        Some([0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001])
    );
}

#[test]
fn expand_invalid_too_many_double_colon() {
    assert_eq!(expand_ipv6("::1::2"), None);
}

// ── assert_host_allowed ───────────────────────────────────────────────────
/// 测试用 mock DnsLookup：按 hostname 返回预设地址表。
struct MockLookup {
    map: std::collections::HashMap<&'static str, Result<Vec<&'static str>, &'static str>>,
}

impl DnsLookup for MockLookup {
    fn lookup_all(&self, host: &str) -> impl Future<Output = Result<Vec<String>, String>> + Send {
        let res = self.map.get(host).cloned().unwrap_or(Ok(vec!["1.2.3.4"]));
        async move {
            res.map(|v| v.into_iter().map(String::from).collect())
                .map_err(String::from)
        }
    }
}

#[tokio::test]
async fn assert_localhost_rejected() {
    let lk = MockLookup {
        map: std::collections::HashMap::new(),
    };
    let r = assert_host_allowed("localhost", &lk, false).await;
    assert!(r.is_err());
    assert!(r.unwrap_err().contains("localhost"));
}

#[tokio::test]
async fn assert_literal_public_ip_ok() {
    let lk = MockLookup {
        map: std::collections::HashMap::new(),
    };
    assert!(assert_host_allowed("1.2.3.4", &lk, false).await.is_ok());
}

#[tokio::test]
async fn assert_literal_private_ip_rejected() {
    let lk = MockLookup {
        map: std::collections::HashMap::new(),
    };
    assert!(assert_host_allowed("127.0.0.1", &lk, false).await.is_err());
    assert!(assert_host_allowed("10.0.0.1", &lk, false).await.is_err());
    assert!(assert_host_allowed("169.254.169.254", &lk, false)
        .await
        .is_err());
}

#[tokio::test]
async fn assert_domain_resolves_public_ok() {
    let mut map = std::collections::HashMap::new();
    map.insert("example.com", Ok(vec!["93.184.216.34"]));
    let lk = MockLookup { map };
    assert!(assert_host_allowed("example.com", &lk, false).await.is_ok());
}

#[tokio::test]
async fn assert_dns_rebinding_to_private_rejected() {
    // 域名解析到 127.0.0.1 → rebinding 绕过拦截
    let mut map = std::collections::HashMap::new();
    map.insert("evil.example.com", Ok(vec!["127.0.0.1"]));
    let lk = MockLookup { map };
    let r = assert_host_allowed("evil.example.com", &lk, false).await;
    assert!(r.is_err());
    assert!(r.unwrap_err().contains("127.0.0.1"));
}

#[tokio::test]
async fn assert_dns_rebinding_to_metadata_rejected() {
    let mut map = std::collections::HashMap::new();
    map.insert("meta.example.com", Ok(vec!["169.254.169.254"]));
    let lk = MockLookup { map };
    assert!(assert_host_allowed("meta.example.com", &lk, false)
        .await
        .is_err());
}

#[tokio::test]
async fn assert_dns_resolve_empty_rejected() {
    let mut map = std::collections::HashMap::new();
    map.insert("empty.example.com", Ok(vec![]));
    let lk = MockLookup { map };
    let r = assert_host_allowed("empty.example.com", &lk, false).await;
    assert!(r.is_err());
}

#[tokio::test]
async fn assert_dns_resolve_failed_rejected() {
    let mut map = std::collections::HashMap::new();
    map.insert("fail.example.com", Err("ENOTFOUND"));
    let lk = MockLookup { map };
    let r = assert_host_allowed("fail.example.com", &lk, false).await;
    assert!(r.is_err());
    assert!(r.unwrap_err().contains("ENOTFOUND"));
}

#[tokio::test]
async fn assert_fakeip_exempt_when_proxied() {
    // 经代理豁免 FakeIP：域名解析到 198.18.x → exempt_fake_ip=true 放行
    let mut map = std::collections::HashMap::new();
    map.insert("fake.example.com", Ok(vec!["198.18.0.5"]));
    let lk = MockLookup { map };
    assert!(assert_host_allowed("fake.example.com", &lk, true)
        .await
        .is_ok());
    // 直连也放行域名 FakeIP：传输层 pin 该结果，外部 TUN 可按自己的映射接管。
    assert!(assert_host_allowed("fake.example.com", &lk, false)
        .await
        .is_ok());
}

#[tokio::test]
async fn assert_literal_fakeip_not_exempted_even_when_proxied() {
    // 字面 FakeIP 没有可恢复的原始域名，不能交 TUN/SOCKS 做域名映射，始终拒绝。
    let lk = MockLookup {
        map: std::collections::HashMap::new(),
    };
    assert!(assert_host_allowed("198.18.0.1", &lk, true).await.is_err());
}

#[tokio::test]
async fn assert_mixed_resolution_one_private_rejected() {
    // 多 IP 中任一内网即拒
    let mut map = std::collections::HashMap::new();
    map.insert(
        "mixed.example.com",
        Ok(vec!["8.8.8.8", "10.0.0.1", "1.1.1.1"]),
    );
    let lk = MockLookup { map };
    assert!(assert_host_allowed("mixed.example.com", &lk, false)
        .await
        .is_err());
}
