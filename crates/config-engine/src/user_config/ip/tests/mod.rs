use super::*;

#[test]
fn ipv4_strict() {
    assert!(is_ipv4("0.0.0.0"));
    assert!(is_ipv4("255.255.255.255"));
    assert!(is_ipv4("1.2.3.4"));
    assert!(is_ipv4("192.168.1.1"));
    // 非法 >255
    assert!(!is_ipv4("999.1.1.1"));
    assert!(!is_ipv4("256.0.0.0"));
    // 段数错
    assert!(!is_ipv4("1.2.3"));
    assert!(!is_ipv4("1.2.3.4.5"));
    // 非数字
    assert!(!is_ipv4("a.b.c.d"));
    assert!(!is_ipv4(""));
}

#[test]
fn ipv4_leading_zeros_allowed() {
    // Polaris 正则 `1?\d?\d` 允许前导零。
    assert!(is_ipv4("01.02.03.04"));
    assert!(is_ipv4("001.002.003.004"));
}

#[test]
fn ipv6_canonical() {
    assert!(is_ipv6_literal("::1"));
    assert!(is_ipv6_literal("2001:db8::1"));
    assert!(is_ipv6_literal("fe80::1"));
    assert!(is_ipv6_literal("[::1]")); // 带方括号
}

#[test]
fn ipv6_not_enough_colons() {
    // "::" = IPv6 unspecified，合法（canonical 全 hex+冒号）。
    assert!(is_ipv6_literal("::"));
    assert!(!is_ipv6_literal(":1")); // 1 冒号
    assert!(!is_ipv6_literal("1.2.3.4")); // IPv4 不含冒号
}

#[test]
fn ipv6_v4_mapped() {
    assert!(is_ipv6_literal("::ffff:192.168.1.1"));
    assert!(is_ipv6_literal("::ffff:1.2.3.4"));
}

#[test]
fn ip_literal_union() {
    assert!(is_ip_literal("1.2.3.4"));
    assert!(is_ip_literal("::1"));
    assert!(!is_ip_literal("example.com"));
    assert!(!is_ip_literal(""));
}
