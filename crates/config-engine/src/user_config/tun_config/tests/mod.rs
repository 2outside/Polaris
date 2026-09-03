use super::*;

#[test]
fn win_tun_default() {
    assert_eq!(resolve_win_tun_interface_name(None), WIN_TUN_INTERFACE);
    assert_eq!(resolve_win_tun_interface_name(Some("")), WIN_TUN_INTERFACE);
    assert_eq!(
        resolve_win_tun_interface_name(Some("  ")),
        WIN_TUN_INTERFACE
    );
}

#[test]
fn win_tun_custom_valid() {
    assert_eq!(resolve_win_tun_interface_name(Some("my-tun")), "my-tun");
    assert_eq!(resolve_win_tun_interface_name(Some("wg_0")), "wg_0");
}

#[test]
fn win_tun_custom_invalid_falls_back() {
    assert_eq!(
        resolve_win_tun_interface_name(Some("my tun")),
        WIN_TUN_INTERFACE
    ); // 空格
    assert_eq!(
        resolve_win_tun_interface_name(Some("a".repeat(33).as_str())),
        WIN_TUN_INTERFACE
    ); // 过长
    assert_eq!(
        resolve_win_tun_interface_name(Some("bad!")),
        WIN_TUN_INTERFACE
    ); // 特殊字符
}

#[test]
fn fakeip_ranges() {
    assert_eq!(FAKEIP_INET4_RANGE, "198.18.0.0/15");
    assert_eq!(FAKEIP_INET6_RANGE, "2001:2::/48");
}
