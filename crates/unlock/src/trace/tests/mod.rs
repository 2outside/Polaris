use super::*;

#[test]
fn parse_typical_trace() {
    let body = "fl=123f1\nh=cloudflare.com\nip=1.2.3.4\nloc=US\nuag=Mozilla\n";
    let info = parse_trace(body).unwrap();
    assert_eq!(info.ip, "1.2.3.4");
    assert_eq!(info.country_code.as_deref(), Some("US"));
}

#[test]
fn parse_lowercase_loc_uppercased() {
    let body = "ip=10.0.0.1\nloc=jp\n";
    let info = parse_trace(body).unwrap();
    assert_eq!(info.country_code.as_deref(), Some("JP"));
}

#[test]
fn parse_rejects_xx_loc() {
    // XX = Cloudflare 未知地区，对齐 Polaris：当作无 countryCode
    let body = "ip=1.1.1.1\nloc=XX\n";
    let info = parse_trace(body).unwrap();
    assert_eq!(info.country_code, None);
}

#[test]
fn parse_rejects_invalid_ip() {
    // 劫持页/截断响应假响应 → ip 非法 → None
    let body = "ip=not-an-ip\nloc=US\n";
    assert!(parse_trace(body).is_none());
}

#[test]
fn parse_missing_ip_returns_none() {
    let body = "loc=US\nuag=x\n";
    assert!(parse_trace(body).is_none());
}

#[test]
fn parse_trims_line_whitespace() {
    // Cloudflare trace 实际格式：行内 `key=value` 无空格，但行首/尾可能有空白/CR。
    // 对齐 Polaris：trim 整行 + trim value；key 不去 inner 空格（trace 无此形态）。
    let body = "  ip=8.8.8.8  \r\n loc=DE \r\n";
    let info = parse_trace(body).unwrap();
    assert_eq!(info.ip, "8.8.8.8");
    assert_eq!(info.country_code.as_deref(), Some("DE"));
}

#[test]
fn parse_three_letter_loc_kept_as_is() {
    // Polaris 原正则只放行恰好 2 字母；loc=USA 不应进 countryCode
    let body = "ip=1.1.1.1\nloc=USA\n";
    let info = parse_trace(body).unwrap();
    assert_eq!(info.country_code, None);
}

#[test]
fn ipv4_validity() {
    assert!(is_valid_ipv4("1.2.3.4"));
    assert!(is_valid_ipv4("255.255.255.255"));
    assert!(is_valid_ipv4("0.0.0.0"));
    assert!(!is_valid_ipv4("256.1.1.1"));
    assert!(!is_valid_ipv4("1.2.3"));
    assert!(!is_valid_ipv4("1.2.3.4.5"));
    assert!(!is_valid_ipv4("a.b.c.d"));
    assert!(!is_valid_ipv4(""));
}

#[test]
fn ipv6_validity() {
    assert!(is_valid_ipv6("::1"));
    assert!(is_valid_ipv6("2001:db8::1"));
    assert!(is_valid_ipv6("2001:db8:0:0:0:0:0:1"));
    assert!(is_valid_ipv6("fe80::1"));
    assert!(!is_valid_ipv6("2001:db8::1::2")); // 双 ::
    assert!(!is_valid_ipv6("1.2.3.4")); // 无冒号
    assert!(!is_valid_ipv6(""));
}

#[test]
fn is_valid_ip_dispatch() {
    assert!(is_valid_ip("1.2.3.4"));
    assert!(is_valid_ip("::1"));
    assert!(!is_valid_ip("garbage"));
}
