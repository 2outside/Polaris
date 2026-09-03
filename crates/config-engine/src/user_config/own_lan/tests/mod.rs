use super::*;

#[test]
fn v4_netmask_to_prefix_standard_masks() {
    assert_eq!(prefix_from_netmask_v4(0xFFFF_FF00), Some(24)); // 255.255.255.0
    assert_eq!(prefix_from_netmask_v4(0xFFFF_0000), Some(16)); // 255.255.0.0
    assert_eq!(prefix_from_netmask_v4(0xFF00_0000), Some(8)); // 255.0.0.0
    assert_eq!(prefix_from_netmask_v4(0xFFFF_FFFF), Some(32)); // 单主机
    assert_eq!(prefix_from_netmask_v4(0), Some(0));
    assert_eq!(prefix_from_netmask_v4(0xFFFF_FFFC), Some(30)); // /30
}

#[test]
fn v4_non_contiguous_netmask_rejected() {
    // 非连续掩码不是合法子网掩码 → None（打断连续性校验会让本测转红）。
    assert_eq!(prefix_from_netmask_v4(0xFF00_FF00), None);
    assert_eq!(prefix_from_netmask_v4(0x00FF_0000), None); // 高位非 1
    assert_eq!(prefix_from_netmask_v4(0xFFFF_FF01), None); // 尾部有孤立 1
}

#[test]
fn v6_netmask_to_prefix() {
    assert_eq!(prefix_from_netmask_v6(u128::MAX), Some(128));
    assert_eq!(prefix_from_netmask_v6(0), Some(0));
    // /64（高 64 位 1）
    assert_eq!(prefix_from_netmask_v6(u128::MAX << 64), Some(64));
    // /48
    assert_eq!(prefix_from_netmask_v6(u128::MAX << 80), Some(48));
    // 非连续 → None
    assert_eq!(prefix_from_netmask_v6((u128::MAX << 64) | 1), None);
}

#[test]
fn own_lan_cidr_keeps_host_bits_and_drops_loopback() {
    // 主机位保留（与 os.networkInterfaces().cidr 同，非掩到网络地址）。
    assert_eq!(
        own_lan_cidr("192.168.10.5", 24, false),
        Some("192.168.10.5/24".to_string())
    );
    assert_eq!(
        own_lan_cidr("fd00::1234", 64, false),
        Some("fd00::1234/64".to_string())
    );
    // 回环剔除（对齐 !a.internal）。
    assert_eq!(own_lan_cidr("127.0.0.1", 8, true), None);
    assert_eq!(own_lan_cidr("::1", 128, true), None);
    // 空地址剔除（对齐 a.cidr 真值判定）。
    assert_eq!(own_lan_cidr("", 24, false), None);
}

/// `/0` 必须被拒：默认路由不是本机 LAN 段，它进 own_lan 会当成 carve guard 吞掉一切 mesh 段
///（后果侧的锁在 `builder::tun_route_exclude` 的
/// `win_bypass_zero_prefix_own_lan_kills_all_carve`）。
///
/// 变异锁：删掉 `own_lan_cidr` 里的 `prefix == 0` 分支 → 前两条转红；把条件误写成 `prefix <= 1`
/// 或 `prefix < 8` 之类 → 后面的边界放行条目转红。
#[test]
fn own_lan_cidr_rejects_zero_prefix_but_keeps_boundaries() {
    assert_eq!(own_lan_cidr("192.168.1.5", 0, false), None);
    assert_eq!(own_lan_cidr("fd00::1234", 0, false), None);
    // 边界仍放行（别把合法的窄/宽前缀一起误杀）。
    assert_eq!(
        own_lan_cidr("192.168.1.5", 1, false),
        Some("192.168.1.5/1".to_string())
    );
    assert_eq!(
        own_lan_cidr("192.168.1.5", 32, false),
        Some("192.168.1.5/32".to_string())
    );
    assert_eq!(
        own_lan_cidr("fd00::1234", 1, false),
        Some("fd00::1234/1".to_string())
    );
    assert_eq!(
        own_lan_cidr("fd00::1234", 128, false),
        Some("fd00::1234/128".to_string())
    );
}

#[test]
fn dedupe_preserves_first_seen_order() {
    let input = vec![
        "192.168.1.5/24".to_string(),
        "10.0.0.2/8".to_string(),
        "192.168.1.5/24".to_string(), // 重复（同一接口多地址帧）
    ];
    assert_eq!(
        dedupe_own_lan(input),
        vec!["192.168.1.5/24".to_string(), "10.0.0.2/8".to_string()]
    );
}
