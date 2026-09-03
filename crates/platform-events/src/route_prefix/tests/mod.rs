use super::*;

#[test]
fn route_prefix_parsing_and_masks_cover_ipv4_ipv6_and_invalid_inputs() {
    let v4 = RoutePrefix::parse("198.51.100.0/24").unwrap();
    assert!(v4.contains("198.51.100.77".parse().unwrap()));
    assert!(!v4.contains("198.51.101.1".parse().unwrap()));
    assert_eq!(v4.prefix_len(), 24);

    let v6 = RoutePrefix::from_netmask(
        "2001:db8:1234::".parse().unwrap(),
        "ffff:ffff:ffff::".parse().unwrap(),
    )
    .unwrap();
    assert!(v6.contains("2001:db8:1234::42".parse().unwrap()));
    assert!(!v6.contains("2001:db8:1235::1".parse().unwrap()));
    assert_eq!(v6.prefix_len(), 48);

    assert!(RoutePrefix::parse("0.0.0.0/0")
        .unwrap()
        .contains("203.0.113.1".parse().unwrap()));
    assert!(RoutePrefix::parse("192.0.2.1/33").is_none());
    assert!(RoutePrefix::from_netmask(
        "192.0.2.0".parse().unwrap(),
        "255.0.255.0".parse().unwrap(),
    )
    .is_none());

    // 裸 IP 补全的是**主机路由**：断言到值，`is_some()` 分不出 /32 与 /24。
    let host_v4 = RoutePrefix::parse("203.0.113.9").unwrap();
    assert_eq!(host_v4.prefix_len(), 32);
    assert!(host_v4.contains("203.0.113.9".parse().unwrap()));
    assert!(!host_v4.contains("203.0.113.10".parse().unwrap()));
    let host_v6 = RoutePrefix::parse("2001:db8::9").unwrap();
    assert_eq!(host_v6.prefix_len(), 128);
    assert!(host_v6.contains("2001:db8::9".parse().unwrap()));
    assert!(!host_v6.contains("2001:db8::a".parse().unwrap()));

    // v6 的合法上界是 128；越界必须与 v4 的 /33 一样被拒。
    assert!(RoutePrefix::parse("2001:db8::/129").is_none());
    assert_eq!(
        RoutePrefix::parse("2001:db8::/128").unwrap().prefix_len(),
        128
    );
    assert!(RoutePrefix::new("2001:db8::".parse().unwrap(), 129).is_none());

    // 跨族的地址/掩码组合无意义：`from_netmask` 必须拒，而不是按某一族硬算。
    assert!(RoutePrefix::from_netmask(
        "192.0.2.0".parse().unwrap(),
        "ffff:ffff::".parse().unwrap(),
    )
    .is_none());
    assert!(RoutePrefix::from_netmask(
        "2001:db8::".parse().unwrap(),
        "255.255.255.0".parse().unwrap(),
    )
    .is_none());

    // 跨族 `contains` 永远为假：v4 目标不落在 v6 前缀里，反之亦然。
    assert!(!RoutePrefix::parse("2001:db8::/32")
        .unwrap()
        .contains("198.51.100.77".parse().unwrap()));
    assert!(!v4.contains("2001:db8::1".parse().unwrap()));
}
