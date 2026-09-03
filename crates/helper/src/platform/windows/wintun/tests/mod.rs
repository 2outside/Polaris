use super::*;

/// Windows 发布验收门：直接执行生产使用的 IP Helper API 链，不改路由、不创建适配器。
/// 默认测试集不能假定 runner 同时具备 IPv4/IPv6 公网路由，故只在真机验收时显式运行。
#[cfg(windows)]
#[test]
#[ignore = "requires live Windows IPv4 and IPv6 routes"]
fn live_best_route_interface_alias_supports_both_families() {
    for ip in [
        "1.1.1.1".parse().unwrap(),
        "2606:4700:4700::1111".parse().unwrap(),
    ] {
        let alias = best_route_interface_alias(ip)
            .unwrap_or_else(|error| panic!("best route lookup failed for {ip}: {error}"));
        assert!(!alias.trim().is_empty());
        eprintln!("best route for {ip}: {alias}");
    }
}

#[test]
fn ipv4_s_addr_preserves_network_octets_in_memory() {
    let encoded = ipv4_s_addr(std::net::Ipv4Addr::new(1, 2, 3, 4));
    assert_eq!(encoded.to_ne_bytes(), [1, 2, 3, 4]);
}

#[test]
fn prefixes_cover_polaris() {
    // 锁住：探测前缀覆盖 Polaris 自身命名谱系
    assert!(PROBE_PREFIXES.contains(&"polaris-"));
}

#[test]
fn present_immediately_when_adapter_already_up() {
    // 健康路径：就绪时网卡早已在 → 首次枚举即命中，零 sleep（起核热路径不得凭空多等一个间隔）。
    let probe = MockAdapterProbe::new(vec![vec!["polaris-tun0".to_owned()]]);
    let sleep = FakeSleep::default();
    let out = probe_adapter_present(
        &probe,
        "polaris-tun0",
        DEFAULT_PROBE_TIMEOUT,
        DEFAULT_POLL_INTERVAL,
        &sleep,
    );
    assert_eq!(out, PresenceOutcome::Present);
    assert_eq!(*sleep.slept.lock().unwrap(), Duration::ZERO);
}

#[test]
fn present_after_polls_when_adapter_appears_late() {
    // 就绪门过了但网卡还差几十毫秒才挂上 → 必须等，不能一次没看到就判失败。
    let probe = MockAdapterProbe::new(vec![vec![], vec!["polaris-tun0".to_owned()]]);
    let sleep = FakeSleep::default();
    let out = probe_adapter_present(
        &probe,
        "polaris-tun0",
        DEFAULT_PROBE_TIMEOUT,
        Duration::from_millis(10),
        &sleep,
    );
    assert_eq!(out, PresenceOutcome::Present);
    assert!(*sleep.slept.lock().unwrap() >= Duration::from_millis(10));
}

#[test]
fn absent_when_adapter_never_appears() {
    // #327 的靶心：核活着、管理口通，但网卡自始至终没建出来。
    let probe = MockAdapterProbe::new(vec![vec![]]);
    let sleep = FakeSleep::default();
    let out = probe_adapter_present(
        &probe,
        "polaris-tun0",
        Duration::from_millis(50),
        Duration::from_millis(10),
        &sleep,
    );
    assert_eq!(out, PresenceOutcome::Absent { seen: vec![] });
}

#[test]
fn absent_reports_other_polaris_adapters_seen() {
    // 同前缀但**不是**本次这张（如上一轮残留的 polaris-tun1）→ 仍是 Absent，且带上看到了什么，
    // 让上层日志能区分「一张都没有」与「有别的、就是没有我要的」。
    let probe = MockAdapterProbe::new(vec![vec!["polaris-tun1".to_owned()]]);
    let sleep = FakeSleep::default();
    let out = probe_adapter_present(
        &probe,
        "polaris-tun0",
        Duration::from_millis(50),
        Duration::from_millis(10),
        &sleep,
    );
    assert_eq!(
        out,
        PresenceOutcome::Absent {
            seen: vec!["polaris-tun1".to_owned()]
        }
    );
}

#[test]
fn present_matches_case_insensitively() {
    let probe = MockAdapterProbe::new(vec![vec!["Polaris-TUN0".to_owned()]]);
    let sleep = FakeSleep::default();
    let out = probe_adapter_present(
        &probe,
        "polaris-tun0",
        DEFAULT_PROBE_TIMEOUT,
        DEFAULT_POLL_INTERVAL,
        &sleep,
    );
    assert_eq!(out, PresenceOutcome::Present);
}

#[test]
fn presence_error_on_enum_failure() {
    struct ErrProbe;
    impl AdapterProbe for ErrProbe {
        fn list_matching_adapters(&self) -> std::io::Result<Vec<String>> {
            Err(std::io::Error::other("iphlpapi boom"))
        }
    }
    let sleep = FakeSleep::default();
    let out = probe_adapter_present(
        &ErrProbe,
        "polaris-tun0",
        DEFAULT_PROBE_TIMEOUT,
        DEFAULT_POLL_INTERVAL,
        &sleep,
    );
    match out {
        PresenceOutcome::Error(msg) => assert!(msg.contains("iphlpapi boom")),
        other => panic!("expected Error, got {other:?}"),
    }
}

#[test]
fn probeable_predicate_matches_enumeration_filter() {
    // 变异对照：把它写成恒 true，则用户自定义接口名（`my-tun`）会被上层当成「网卡没建出来」
    // → 杀掉一个完全正常的核。这条锁的正是那个方向。
    assert!(adapter_name_is_probeable("polaris-tun0"));
    assert!(adapter_name_is_probeable("polaris-anything"));
    assert!(!adapter_name_is_probeable("my-tun"));
    assert!(!adapter_name_is_probeable("以太网"));
    assert!(!adapter_name_is_probeable("Polaris-tun0")); // 枚举侧是 starts_with，大小写敏感
}
