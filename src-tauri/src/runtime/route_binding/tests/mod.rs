use super::*;
use polaris_config_engine::user_config::proxy_mode::ProxyModeType;

fn server(id: &str, address: &str) -> ServerConfig {
    ServerConfig {
        id: id.to_owned(),
        name: id.to_owned(),
        protocol: Protocol::Vless,
        address: address.to_owned(),
        port: 443,
        ..Default::default()
    }
}

#[test]
fn host_normalization_covers_urls_ports_and_ipv6() {
    assert_eq!(
        normalize_host("vpn.example.com:443").as_deref(),
        Some("vpn.example.com")
    );
    assert_eq!(
        normalize_host("https://u@vpn.example.com:8443/path").as_deref(),
        Some("vpn.example.com")
    );
    assert_eq!(
        normalize_host("[2001:db8::1]:443").as_deref(),
        Some("2001:db8::1")
    );
    assert_eq!(
        normalize_host("2001:db8::2").as_deref(),
        Some("2001:db8::2")
    );
}

#[test]
fn candidates_collapse_detour_children_to_the_physical_root() {
    let mut child = server("child", "child.example.com");
    child.detour = Some("root".into());
    let config = UserConfig {
        proxy_mode_type: ProxyModeType::Tun,
        servers: vec![child, server("root", "root.example.com")],
        ..Default::default()
    };
    let candidates = hot_switch_runtime_binding_candidates(&config);
    assert_eq!(
        candidates,
        vec![Candidate {
            server_id: "root".into(),
            host: "root.example.com".into(),
        }]
    );
}

#[test]
fn explicit_binding_and_dynamic_tailscale_targets_are_not_inferred() {
    let mut explicit = server("explicit", "1.1.1.1");
    explicit.bind_interface = Some("en0".into());
    let mut tailscale = server("ts", "");
    tailscale.protocol = Protocol::Tailscale;
    let config = UserConfig {
        proxy_mode_type: ProxyModeType::Tun,
        servers: vec![explicit, tailscale],
        ..Default::default()
    };
    assert!(!needs_runtime_binding_plan(&config));
}

#[test]
fn active_roots_stay_minimal_while_hot_switch_plan_covers_all_nodes() {
    let config = UserConfig {
        proxy_mode_type: ProxyModeType::Tun,
        servers: vec![server("node-a", "1.1.1.1"), server("node-b", "2.2.2.2")],
        selected_server_id: Some("node-a".into()),
        ..Default::default()
    };
    assert_eq!(
        automatic_runtime_binding_root_ids(&config),
        BTreeSet::from(["node-a".to_string()]),
        "配置变更判定只看当前承流根，闲置 B 不得让订阅更新误重启"
    );
    assert_eq!(
        hot_switch_runtime_binding_candidates(&config)
            .into_iter()
            .map(|candidate| candidate.server_id)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["node-a".to_string(), "node-b".to_string()]),
        "起核前必须覆盖 selector 全集，A→B 才是真热切"
    );
}

#[test]
fn selected_naive_keeps_active_roots_minimal_but_does_not_shrink_hot_switch_coverage() {
    let mut selected = server("h3", "h3.example.com");
    selected.protocol = Protocol::Naive;
    let config = UserConfig {
        proxy_mode_type: ProxyModeType::Tun,
        servers: vec![
            server("idle-a", "1.1.1.1"),
            selected,
            server("idle-b", "2.2.2.2"),
        ],
        selected_server_id: Some("h3".into()),
        ..Default::default()
    };
    assert_eq!(
        automatic_runtime_binding_root_ids(&config),
        BTreeSet::from(["h3".to_string()]),
        "当前承流判定仍只含 H3"
    );
    assert_eq!(
        hot_switch_runtime_binding_candidates(&config)
            .into_iter()
            .map(|candidate| candidate.server_id)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["h3".to_string(), "idle-a".to_string(), "idle-b".to_string(),]),
        "H3 不能再把热切覆盖误收窄为当前节点"
    );
}

#[test]
fn duplicate_hosts_share_one_route_query_group_without_losing_roots() {
    let grouped = group_candidates_by_host(vec![
        Candidate {
            server_id: "node-a".into(),
            host: "shared.example.com".into(),
        },
        Candidate {
            server_id: "node-b".into(),
            host: "shared.example.com".into(),
        },
        Candidate {
            server_id: "node-c".into(),
            host: "other.example.com".into(),
        },
    ]);
    assert_eq!(grouped.len(), 2);
    assert_eq!(
        grouped.get("shared.example.com"),
        Some(&vec!["node-a".to_string(), "node-b".to_string()])
    );
    assert_eq!(
        grouped.get("other.example.com"),
        Some(&vec!["node-c".to_string()])
    );
}

#[test]
fn traffic_rule_target_adds_its_detour_physical_root() {
    use polaris_config_engine::user_config::proxy_mode::ProxyMode;
    use polaris_config_engine::user_config::rule::{
        Rule, RuleAction, RuleEffects, RuleRouteEffect, RuleType,
    };

    let mut child = server("child", "child.example.com");
    child.detour = Some("root".into());
    let config = UserConfig {
        proxy_mode_type: ProxyModeType::Tun,
        proxy_mode: ProxyMode::Smart,
        servers: vec![
            server("node-a", "1.1.1.1"),
            child,
            server("root", "3.3.3.3"),
        ],
        selected_server_id: Some("node-a".into()),
        traffic_rules: Some(vec![Rule {
            id: "rule-b".into(),
            type_field: RuleType::Domain,
            values: vec!["example.com".into()],
            action: RuleAction::Proxy,
            enabled: true,
            effects: Some(RuleEffects {
                route: Some(RuleRouteEffect {
                    enabled: true,
                    action: RuleAction::Proxy,
                    target_server_id: Some("child".into()),
                    destination_resolution: None,
                    resolution_only: false,
                }),
                dns: None,
            }),
            ..Default::default()
        }]),
        ..Default::default()
    };
    assert_eq!(
        automatic_runtime_binding_root_ids(&config),
        BTreeSet::from(["node-a".to_string(), "root".to_string()])
    );
}

#[test]
fn custom_outbound_uses_its_passthrough_server_not_the_placeholder_address() {
    use polaris_config_engine::user_config::protocol_settings::CustomSettings;

    let mut custom = server("custom", "unused.example");
    custom.protocol = Protocol::Custom;
    custom.custom_settings = Some(CustomSettings {
        outbound: serde_json::json!({
            "type": "socks",
            "server": "custom.example.com",
            "server_port": 1080
        }),
        is_endpoint: None,
        secret_keys: None,
    });
    let config = UserConfig {
        proxy_mode_type: ProxyModeType::Tun,
        servers: vec![custom],
        ..Default::default()
    };
    assert_eq!(
        hot_switch_runtime_binding_candidates(&config),
        vec![Candidate {
            server_id: "custom".into(),
            host: "custom.example.com".into(),
        }]
    );
}

#[test]
fn non_tun_modes_never_inject_runtime_bindings() {
    for mode in [ProxyModeType::SystemProxy, ProxyModeType::Manual] {
        let config = UserConfig {
            proxy_mode_type: mode,
            servers: vec![server("node", "1.1.1.1")],
            ..Default::default()
        };
        assert!(!needs_runtime_binding_plan(&config));
    }
}

#[test]
fn default_route_uses_native_auto_detect_and_only_exceptions_are_bound() {
    assert_eq!(
        classify_runtime_binding("en0", Some(" en0 ")),
        RuntimeBindingDecision::Native
    );
    assert_eq!(
        classify_runtime_binding("utun7", Some("en0")),
        RuntimeBindingDecision::Bind("utun7".into())
    );
    assert_eq!(
        classify_runtime_binding("eth0", None),
        RuntimeBindingDecision::Bind("eth0".into()),
        "默认出口不可读时不得猜成另一张接口"
    );
}

#[tokio::test]
async fn explicit_ipv6_literal_is_routable_even_when_dns_ipv6_is_disabled() {
    assert_eq!(
        resolve_route_probe_ip("2606:4700:4700::1111", false).await,
        Some("2606:4700:4700::1111".parse().unwrap())
    );
}

/// 只读真机门：走与生产相同的 DNS/IP → OS 路由 → 接口名链路，不改路由、不起 TUN。
/// 默认测试集不能假定 runner 有公网路由；三平台发布验证须显式执行本条。
#[tokio::test]
#[ignore = "requires a live OS route table"]
async fn live_route_planner_returns_a_real_interface() {
    let config = UserConfig {
        proxy_mode_type: ProxyModeType::Tun,
        servers: vec![server("live-route-probe", "1.1.1.1")],
        ..Default::default()
    };
    let plan = plan_runtime_bindings(&config).await;
    assert_eq!(plan.candidate_count, 1);
    assert!(plan.unresolved_roots.is_empty());
    if let Some(interface) = plan.bindings.get("live-route-probe") {
        assert!(!interface.trim().is_empty());
        eprintln!("live route planner selected exceptional interface: {interface}");
    } else {
        assert!(plan.native_roots.contains("live-route-probe"));
        eprintln!("live route planner retained native auto_detect_interface");
    }
}
