use super::*;

#[test]
fn mac_colon_valid() {
    assert!(is_valid_mac_address(Some("00:11:22:33:44:55")));
    assert!(is_valid_mac_address(Some("aa:bb:cc:dd:ee:ff")));
    assert!(is_valid_mac_address(Some("AA:BB:CC:DD:EE:FF")));
}

#[test]
fn mac_dash_valid() {
    assert!(is_valid_mac_address(Some("00-11-22-33-44-55")));
}

#[test]
fn mac_cisco_valid() {
    assert!(is_valid_mac_address(Some("0011.2233.4455")));
    assert!(is_valid_mac_address(Some("aabb.ccdd.eeff")));
}

#[test]
fn mac_invalid() {
    assert!(!is_valid_mac_address(Some("001122334455"))); // 无分隔符
    assert!(!is_valid_mac_address(Some("00:11:22:33:44"))); // 段数错
    assert!(!is_valid_mac_address(Some("00:11:22:33:44:55:66"))); // 7 段
    assert!(!is_valid_mac_address(Some("zz:11:22:33:44:55"))); // 非 hex
    assert!(!is_valid_mac_address(Some("00-11:22-33:44:55"))); // 混用分隔符
    assert!(!is_valid_mac_address(None));
    assert!(!is_valid_mac_address(Some("")));
}

#[test]
fn hostname_valid() {
    assert!(is_valid_source_hostname(Some("nas")));
    assert!(is_valid_source_hostname(Some("nas.lan")));
    assert!(is_valid_source_hostname(Some("my-host")));
    assert!(is_valid_source_hostname(Some("a.b.c")));
}

#[test]
fn hostname_invalid() {
    assert!(!is_valid_source_hostname(Some("-host"))); // 连字符开头
    assert!(!is_valid_source_hostname(Some("host-"))); // 连字符结尾
    assert!(!is_valid_source_hostname(Some(""))); // 空
    assert!(!is_valid_source_hostname(Some("a".repeat(254).as_str()))); // 过长
}

#[test]
fn neighbor_domain_normalize() {
    assert_eq!(
        normalize_neighbor_domain(Some("lan")).as_deref(),
        Some(".lan")
    );
    assert_eq!(
        normalize_neighbor_domain(Some(".lan")).as_deref(),
        Some(".lan")
    );
    assert_eq!(
        normalize_neighbor_domain(Some("..lan")).as_deref(),
        Some(".lan")
    ); // 多点收敛
    assert_eq!(normalize_neighbor_domain(Some(".")).as_deref(), Some(".")); // 纯点
    assert_eq!(normalize_neighbor_domain(Some("")).as_deref(), None);
    assert_eq!(normalize_neighbor_domain(None), None);
}

#[test]
fn neighbor_domain_valid() {
    assert!(is_valid_neighbor_domain(Some(".lan")));
    assert!(is_valid_neighbor_domain(Some("."))); // 单点
    assert!(is_valid_neighbor_domain(Some(".home.arpa"))); // 多标签
    assert!(is_valid_neighbor_domain(Some("lan"))); // 归一化加前导点 → .lan 合法
    assert!(!is_valid_neighbor_domain(Some("")));
}

#[test]
fn platform_source_device() {
    assert!(is_source_device_match_supported("linux"));
    assert!(is_source_device_match_supported("darwin"));
    assert!(!is_source_device_match_supported("win32"));
}

#[test]
fn platform_tun_mac() {
    assert!(is_tun_mac_filter_supported("linux"));
    assert!(!is_tun_mac_filter_supported("darwin"));
    assert!(!is_tun_mac_filter_supported("win32"));
}
