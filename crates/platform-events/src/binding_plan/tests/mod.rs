use super::*;

#[test]
fn stale_inferred_bindings_fall_back_without_touching_healthy_entries() {
    let mut plan = RuntimeBindingPlan {
        bindings: BTreeMap::from([
            ("wifi-node".into(), "en0".into()),
            ("vpn-node".into(), "utun7".into()),
            ("gone-node".into(), "en9".into()),
        ]),
        native_roots: BTreeSet::from(["native-node".into()]),
        covered_roots: BTreeSet::from([
            "wifi-node".into(),
            "vpn-node".into(),
            "gone-node".into(),
            "unresolved-node".into(),
            "native-node".into(),
        ]),
        probe_ips: BTreeMap::from([
            ("wifi-node".into(), "192.0.2.1".parse().unwrap()),
            ("vpn-node".into(), "198.51.100.1".parse().unwrap()),
            ("gone-node".into(), "203.0.113.1".parse().unwrap()),
            ("native-node".into(), "1.1.1.1".parse().unwrap()),
        ]),
        candidate_count: 5,
        unresolved_roots: BTreeMap::from([(
            "unresolved-node".into(),
            "unresolved.example.com".into(),
        )]),
    };
    let observed = BTreeMap::from([("en0".into(), true), ("utun7".into(), false)]);

    assert_eq!(plan.retain_available(&observed), 2);
    assert_eq!(
        plan.bindings,
        BTreeMap::from([("wifi-node".into(), "en0".into())])
    );
    assert_eq!(
        plan.unresolved_roots,
        BTreeMap::from([
            ("unresolved-node".into(), "unresolved.example.com".into()),
            // 接口 down / 消失的两个根当场失去决策，带着已解析 IP 进未决集合——不只是计数 +2。
            ("vpn-node".into(), "198.51.100.1".into()),
            ("gone-node".into(), "203.0.113.1".into()),
        ]),
        "未决集合必须记住是谁失去了决策，供后续按前缀判相关性"
    );
}
