use super::*;

/// v4 八位组 → 点分串（网络序即书写序）。变异：调换字节序 → 转红。
#[test]
fn v4_octets_render_dotted_quad() {
    assert_eq!(v4_octets_to_string([192, 168, 10, 5]), "192.168.10.5");
    assert_eq!(v4_octets_to_string([0, 0, 0, 0]), "0.0.0.0");
    assert_eq!(v4_octets_to_string([255, 255, 255, 255]), "255.255.255.255");
}

/// v6 十六字节 → 压缩串（`Ipv6Addr` 的标准压缩，与 `os.networkInterfaces()` 的写法同）。
#[test]
fn v6_octets_render_compressed() {
    let mut o = [0u8; 16];
    o[0] = 0xfe;
    o[1] = 0x80;
    o[15] = 0x01;
    assert_eq!(v6_octets_to_string(o), "fe80::1");
}

/// 前缀合法性：合法域 v4 `1..=32` / v6 `1..=128`；**哨兵 0 与 255 都必须被拒**。
///
/// 变异锁：
/// - 去掉校验（恒 true）→ 哨兵四条转红；
/// - 把下界放回 0（`prefix <= 32` / `prefix <= 128`）→ `prefix_is_valid(0, _)` 两条转红
///   （后果侧另有 `config-engine::builder::tun_route_exclude` 的 carve 全 skip 用例）；
/// - 把 v4 上限写成 128 → `33` 那条转红；
/// - 把下界收到 2 → `prefix_is_valid(1, _)` 两条转红。
#[test]
fn prefix_bounds_reject_sentinels() {
    assert!(prefix_is_valid(24, false));
    assert!(prefix_is_valid(32, false));
    assert!(prefix_is_valid(1, false), "下界 1 是合法前缀，别一起误杀");
    assert!(prefix_is_valid(64, true));
    assert!(prefix_is_valid(128, true));
    assert!(
        prefix_is_valid(1, true),
        "下界 1 是合法前缀，别一起误杀（v6）"
    );
    assert!(
        !prefix_is_valid(0, false),
        "哨兵 0 必须丢弃（默认路由非本机 LAN 段）"
    );
    assert!(!prefix_is_valid(0, true), "哨兵 0 必须丢弃（v6）");
    assert!(!prefix_is_valid(255, false), "哨兵 255 必须丢弃");
    assert!(!prefix_is_valid(255, true), "哨兵 255 必须丢弃（v6）");
    assert!(!prefix_is_valid(33, false), "v4 前缀不得超 32");
    assert!(!prefix_is_valid(129, true), "v6 前缀不得超 128");
}

/// 缓冲区容量换算：向上取整到 u64 槽，**容量永不缩水**（缩水 = API 往 buf 外写）。
///
/// 变异锁：把 `div_ceil` 换成整除 `/ 8` → `1 / 7 / 9` 三条转红；把槽宽写成 4 → `9` 那条转红
/// （得 3 而非 2）。u32::MAX 一条锁住无溢出。
#[test]
fn u64_cells_never_shrink_capacity() {
    assert_eq!(u64_cells_for(0), 0);
    assert_eq!(u64_cells_for(1), 1);
    assert_eq!(u64_cells_for(7), 1);
    assert_eq!(u64_cells_for(8), 1);
    assert_eq!(u64_cells_for(9), 2);
    assert_eq!(u64_cells_for(u32::MAX), 536_870_912);
    // 不变式：分配到的字节数 ≥ API 要的字节数。
    for size in [0u32, 1, 7, 8, 9, 4095, 4096, u32::MAX] {
        assert!(
            u64_cells_for(size) * 8 >= size as usize,
            "size={size} 的容量缩水了"
        );
    }
}

/// 重试预算判据：探大小与填充**共用** [`SIZE_PROBE_MAX_RETRIES`]，第 3 次用完即放弃。
///
/// 诚实说明：真 FFI（`GetAdaptersAddresses`）本机跑不到，本用例覆盖的是「第几次该放弃」这条判据，
/// 不是 FFI 行为。变异锁：把 `<` 改成 `<=`（预算多一次）→ `retries=3` 那条转红；把两条腿拆成各自
/// 预算（填充腿不再调本函数）→ 本用例照绿，但那属接线，靠 Windows 交叉编译 + 真机覆盖。
#[test]
fn overflow_retry_budget_is_shared_and_bounded() {
    assert_eq!(SIZE_PROBE_MAX_RETRIES, 3);
    assert!(should_retry_after_overflow(0));
    assert!(should_retry_after_overflow(1));
    assert!(should_retry_after_overflow(2));
    assert!(!should_retry_after_overflow(3), "预算用尽必须放弃");
    assert!(!should_retry_after_overflow(u32::MAX));
}

/// 回环 ifType 常量锁死（IANA 24）。变异：改值 → 转红（改了会让回环地址混进 own-lan，
/// 而 own_lan_cidr 正是靠 `is_loopback` 剔除它们）。
#[test]
fn loopback_if_type_is_iana_24() {
    assert_eq!(IF_TYPE_SOFTWARE_LOOPBACK, 24);
}
