use super::*;
use windows_sys::Win32::NetworkManagement::IpHelper::IP_ADDRESS_PREFIX;

/// 构造一个只用于测试的订阅：回调与读侧共享同一份 context，句柄留空（Drop 不会去注销）。
/// receiver 一并返回由调用方持有——容量 1 通道只承担唤醒，但对端提前 drop 会让 `try_send`
/// 走上与生产不同的错误腿。
fn test_subscription(pending: PendingNetworkChanges) -> (NetworkChangeSubscription, Receiver<()>) {
    let (sender, receiver) = mpsc::channel(1);
    let subscription = NetworkChangeSubscription {
        interface_handle: 0,
        route_handle: 0,
        context: Some(Box::new(CallbackContext {
            sender,
            pending: Mutex::new(pending),
            ignored_interface_index: None,
        })),
    };
    (subscription, receiver)
}

#[test]
fn pending_event_kinds_coalesce_and_are_taken_once() {
    let (subscription, _receiver) = test_subscription(PendingNetworkChanges {
        interface: true,
        route: true,
        route_prefixes: BTreeSet::from([RoutePrefix::parse("198.51.100.0/24").unwrap()]),
        route_unknown: false,
    });

    let first = subscription.take_pending();
    assert!(first.interface);
    assert!(first.route);
    assert_eq!(first.route_prefixes.len(), 1);
    assert!(!first.route_unknown);
    let second = subscription.take_pending();
    assert!(!second.interface);
    assert!(!second.route);
    assert!(second.route_prefixes.is_empty());
    assert!(!second.route_unknown);
}

#[test]
fn managed_tun_events_are_filtered_without_hiding_physical_interfaces() {
    assert!(should_ignore_interface(Some(28), 28));
    assert!(!should_ignore_interface(Some(28), 8));
    assert!(!should_ignore_interface(None, 28));
}

#[test]
#[allow(
    unsafe_code,
    reason = "constructs the same tagged SOCKADDR_INET union delivered by Windows in production"
)]
fn route_callback_preserves_ipv4_destination_prefix() {
    let (subscription, _receiver) = test_subscription(PendingNetworkChanges::default());
    // 用结构体字面量而不是「default 之后逐字段回填」：后者被 clippy 的
    // `field_reassign_with_default` 判红，而那条 lint 只在 `cfg(windows)` 编译单元里看得到
    // —— Linux 宿主的 `cargo clippy` 对它检出力恒为 0，本机唯一的对照是
    // `cargo clippy --workspace --all-targets --target x86_64-pc-windows-gnu`。
    let mut row = MIB_IPFORWARD_ROW2 {
        InterfaceIndex: 8,
        DestinationPrefix: IP_ADDRESS_PREFIX {
            PrefixLength: 24,
            ..Default::default()
        },
        ..Default::default()
    };
    // SAFETY: family 与随后写入的 Ipv4 union member 成对设置；回调只同步读取这一完整 row。
    unsafe {
        row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
        row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr =
            u32::from_ne_bytes([198, 51, 100, 0]);
        route_changed(subscription.context_ptr(), &raw const row, 0);
    }
    let pending = subscription.take_pending();
    assert!(pending.route);
    assert!(!pending.route_unknown);
    assert_eq!(pending.route_prefixes.len(), 1);
    let prefix = pending.route_prefixes.into_iter().next().unwrap();
    assert!(prefix.contains("198.51.100.77".parse().unwrap()));
    assert!(!prefix.contains("198.51.101.1".parse().unwrap()));
}

#[test]
#[allow(
    unsafe_code,
    reason = "constructs the same tagged SOCKADDR_INET union delivered by Windows in production"
)]
fn route_callback_preserves_ipv6_destination_prefix() {
    let (subscription, _receiver) = test_subscription(PendingNetworkChanges::default());
    // 结构体字面量，理由同上（`field_reassign_with_default` 只在 Windows 构型可见）。
    let mut row = MIB_IPFORWARD_ROW2 {
        InterfaceIndex: 8,
        DestinationPrefix: IP_ADDRESS_PREFIX {
            PrefixLength: 64,
            ..Default::default()
        },
        ..Default::default()
    };
    // SAFETY: family 与随后写入的 Ipv6 union member 成对设置；回调只同步读取这一完整 row。
    unsafe {
        row.DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
        row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte = [
            0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        route_changed(subscription.context_ptr(), &raw const row, 0);
    }
    let pending = subscription.take_pending();
    assert!(pending.route);
    assert!(
        !pending.route_unknown,
        "AF_INET6 臂能取到精确前缀，不得退化成未知路由事件"
    );
    assert_eq!(
        pending.route_prefixes,
        BTreeSet::from([RoutePrefix::parse("2001:db8:1234::/64").unwrap()])
    );
}

#[test]
#[allow(
    unsafe_code,
    reason = "constructs the same tagged SOCKADDR_INET union delivered by Windows in production"
)]
fn route_callback_marks_unknown_for_unsupported_address_families() {
    for family in [AF_UNSPEC, 17 /* AF_NETBIOS：既非 v4 也非 v6 */] {
        let (subscription, _receiver) = test_subscription(PendingNetworkChanges::default());
        // 结构体字面量，理由同上（`field_reassign_with_default` 只在 Windows 构型可见）。
        let mut row = MIB_IPFORWARD_ROW2 {
            InterfaceIndex: 8,
            DestinationPrefix: IP_ADDRESS_PREFIX {
                PrefixLength: 24,
                ..Default::default()
            },
            ..Default::default()
        };
        // SAFETY: si_family 是 SOCKADDR_INET 的判别式成员，单独写入合法；地址成员保持零值不被读。
        unsafe {
            row.DestinationPrefix.Prefix.si_family = family;
            route_changed(subscription.context_ptr(), &raw const row, 0);
        }
        let pending = subscription.take_pending();
        assert!(pending.route, "family={family} 仍是一次真实路由事件");
        assert!(
            pending.route_unknown,
            "family={family} 无法取前缀 → 必须按未知保守处理，不能当作无关事件"
        );
        assert!(pending.route_prefixes.is_empty());
    }
}

/// F4 回归：路由回调写入的「route 位 + 目标前缀」必须整体落进同一个去抖窗口。
///
/// 旧实现把二者拆在 `AtomicU8` 与另一把锁上，读侧插在两次写之间就会得到
/// `route=false, prefixes={P}` 与 `route=true, prefixes={}` 两个窗口——两窗都被
/// `route_replan_needed` 判为无关，路由信号整条丢失。这里让回调线程与读侧真并发地打，
/// 断言不存在任何一个撕裂窗口，且没有前缀丢失。
#[test]
#[allow(
    unsafe_code,
    reason = "drives the real Windows callback with a tagged SOCKADDR_INET from another thread"
)]
fn concurrent_take_pending_never_splits_route_flag_from_its_prefixes() {
    const ROUNDS: usize = 2_000;
    let (subscription, _receiver) = test_subscription(PendingNetworkChanges::default());
    let context_address = subscription.context_ptr() as usize;

    let writer = std::thread::spawn(move || {
        // 结构体字面量，理由同上（`field_reassign_with_default` 只在 Windows 构型可见）。
        let mut row = MIB_IPFORWARD_ROW2 {
            InterfaceIndex: 8,
            DestinationPrefix: IP_ADDRESS_PREFIX {
                PrefixLength: 32,
                ..Default::default()
            },
            ..Default::default()
        };
        for round in 0..ROUNDS {
            // SAFETY: context 由本函数栈上的 subscription 持有，join 之前不会释放；row 在本次
            // 同步调用期间完整有效，与生产回调收到的结构体同形。
            unsafe {
                row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
                row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr =
                    u32::from_ne_bytes([198, 51, 100, (round % 251) as u8]);
                route_changed(context_address as *const c_void, &raw const row, 0);
            }
            std::thread::yield_now();
        }
    });

    let mut prefixes = BTreeSet::new();
    let mut drain = || {
        let pending = subscription.take_pending();
        assert!(
            pending.route || (pending.route_prefixes.is_empty() && !pending.route_unknown),
            "取到了前缀却没有 route 位 → 前半个撕裂窗口"
        );
        assert!(
            !pending.route || !pending.route_prefixes.is_empty() || pending.route_unknown,
            "取到了 route 位却没有任何前缀事实 → 后半个撕裂窗口"
        );
        prefixes.extend(pending.route_prefixes);
    };
    while !writer.is_finished() {
        drain();
    }
    writer.join().expect("route callback thread panics never");
    drain();

    assert_eq!(
        prefixes.len(),
        ROUNDS.min(251),
        "并发取窗不得丢掉任何一个目标前缀"
    );
}
