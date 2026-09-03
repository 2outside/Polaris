use super::*;
use crate::singbox::Endpoint;
use crate::user_config::app_config::UserConfig;
use crate::user_config::proxy_mode::ProxyMode;
use crate::user_config::rule::{
    AppRule, CustomAppPreset, Rule, RuleAction, RuleDnsAnswerMode, RuleDnsEffect, RuleDnsResolver,
    RuleEffects, RuleRouteEffect, RuleType,
};
use crate::user_config::{
    DestinationResolution, DestinationResolutionMode, DnsConnectionResolution, DnsPolicyDefaults,
    RoutePolicyDefaults,
};

fn noop_log(_: LogLevel, _: &str) {}
fn noop_degraded() {}

fn deps_default<'a>(pending: &'a [Endpoint]) -> RouteConfigDeps<'a> {
    RouteConfigDeps {
        probe_direct_port: Some(7890),
        probe_proxy_port: Some(7891),
        update_in_port: None,
        subscription_update_in_port: None,
        probe_pool_ports: vec![],
        lan_resolver_for_dns: None,
        pending_endpoints: pending,
        log: noop_log,
        on_degraded: noop_degraded,
        race_upstream_ips: vec![],
        race_upstream_ports: vec![],
        runtime_rules_dir: "/fake/rules".to_string(),
        rule_resources_path: "/fake/res".to_string(),
        custom_rules_dir: "/fake/custom-rules".to_string(),
        arch: "x64".to_string(),
        platform: "linux".to_string(),
        is_valid_srs_fn: |_| false,
    }
}

fn empty_id_map() -> BTreeMap<String, String> {
    BTreeMap::new()
}

#[test]
fn direct_mode_final_is_direct() {
    let mut config = UserConfig::default();
    config.proxy_mode = ProxyMode::Direct;
    config.proxy_mode_type = ProxyModeType::Tun;
    let deps = deps_default(&[]);
    let rc = build_route_config(&config, &empty_id_map(), &deps);
    assert_eq!(rc.final_outbound.as_deref(), Some("direct"));
    assert_eq!(rc.default_domain_resolver.as_deref(), Some("dns-bootstrap"));
    assert_eq!(rc.auto_detect_interface, Some(true));
    // direct 模式不注入 rule_set。
    assert!(rc.rule_set.is_none());
}

#[test]
fn global_mode_final_is_selector() {
    let mut config = UserConfig::default();
    config.proxy_mode = ProxyMode::Global;
    let deps = deps_default(&[]);
    let rc = build_route_config(&config, &empty_id_map(), &deps);
    assert_eq!(rc.final_outbound.as_deref(), Some("proxy-selector"));
}

#[test]
fn non_tun_modes_leave_per_destination_routing_to_the_os() {
    for mode in [ProxyModeType::SystemProxy, ProxyModeType::Manual] {
        let mut config = UserConfig::default();
        config.proxy_mode_type = mode;
        let rc = build_route_config(&config, &empty_id_map(), &deps_default(&[]));
        assert_eq!(
            rc.auto_detect_interface, None,
            "{mode:?} 不得把所有默认拨号器锁到单一默认网卡"
        );
    }
}

#[test]
fn smart_mode_final_is_selector() {
    let mut config = UserConfig::default();
    config.proxy_mode = ProxyMode::Smart;
    let deps = deps_default(&[]);
    let rc = build_route_config(&config, &empty_id_map(), &deps);
    assert_eq!(rc.final_outbound.as_deref(), Some("proxy-selector"));
}

#[test]
fn v2_route_default_ignores_stale_legacy_resolve_flag() {
    let mut config = UserConfig::default();
    config.config_schema_version = Some(2);
    config.resolve_before_dial = Some(true);
    config.route_defaults = Some(RoutePolicyDefaults {
        destination_resolution: DestinationResolutionMode::PreserveDomain,
    });
    assert!(!uses_dns_connection_resolution(&config));

    config.route_defaults = Some(RoutePolicyDefaults {
        destination_resolution: DestinationResolutionMode::DnsRules,
    });
    config.resolve_before_dial = Some(false);
    assert!(uses_dns_connection_resolution(&config));
}

#[test]
fn v4_dns_connection_default_is_authoritative_in_every_proxy_mode() {
    for mode in [ProxyMode::Smart, ProxyMode::Global, ProxyMode::Direct] {
        let mut config = UserConfig::default();
        config.config_schema_version = Some(4);
        config.proxy_mode = mode;
        config.resolve_before_dial = Some(false);
        config.route_defaults = Some(RoutePolicyDefaults {
            destination_resolution: DestinationResolutionMode::PreserveDomain,
        });
        config.dns_defaults = Some(DnsPolicyDefaults {
            connection_resolution: DnsConnectionResolution::DnsRules,
            ..Default::default()
        });

        assert!(uses_dns_connection_resolution(&config));
        let route = build_route_config(&config, &empty_id_map(), &deps_default(&[]));
        let resolve = route
            .rules
            .iter()
            .find(|rule| rule.action.as_deref() == Some("resolve") && rule.domain.is_none())
            .expect("DNS-owned connection resolution must compile in every proxy mode");
        assert!(
            resolve.server.is_none(),
            "internal lookup must traverse dns.rules"
        );
    }
}

#[test]
fn v4_ignores_stale_per_traffic_rule_resolution() {
    let mut config = UserConfig::default();
    config.config_schema_version = Some(4);
    config.proxy_mode = ProxyMode::Smart;
    config.dns_defaults = Some(DnsPolicyDefaults {
        connection_resolution: DnsConnectionResolution::PreserveDomain,
        ..Default::default()
    });
    config.custom_rules = vec![Rule {
        id: "stale-resolution".into(),
        type_field: RuleType::Domain,
        values: vec!["dns.example.com".into()],
        conditions: None,
        combine_mode: None,
        effects: Some(RuleEffects {
            route: Some(RuleRouteEffect {
                enabled: true,
                action: RuleAction::Block,
                target_server_id: None,
                destination_resolution: Some(DestinationResolution {
                    mode: DestinationResolutionMode::DnsRules,
                    server_id: None,
                }),
                resolution_only: false,
            }),
            dns: None,
        }),
        action: RuleAction::Block,
        enabled: true,
        bypass_fakeip: None,
        target_server_id: None,
        remarks: None,
        tls_spoof: None,
        tls_spoof_method: None,
    }];

    assert!(!uses_dns_connection_resolution(&config));
    let route = build_route_config(&config, &empty_id_map(), &deps_default(&[]));
    assert!(
        !route.rules.iter().any(|rule| {
            rule.action.as_deref() == Some("resolve")
                && rule
                    .domain
                    .as_ref()
                    .is_some_and(|domains| domains.contains(&"dns.example.com".to_string()))
        }),
        "schema v4 must not let a traffic rule reintroduce DNS ownership"
    );
}

#[test]
fn legacy_explicit_destination_resolution_survives_non_smart_mode() {
    for mode in [ProxyMode::Global, ProxyMode::Direct] {
        let mut config = UserConfig::default();
        config.config_schema_version = Some(3);
        config.proxy_mode = mode;
        config.custom_rules = vec![Rule {
            id: "mixed-effect".into(),
            type_field: RuleType::Domain,
            values: vec!["dns.example.com".into()],
            conditions: None,
            combine_mode: None,
            effects: Some(RuleEffects {
                route: Some(RuleRouteEffect {
                    enabled: true,
                    action: RuleAction::Block,
                    target_server_id: None,
                    destination_resolution: Some(DestinationResolution {
                        mode: DestinationResolutionMode::DnsRules,
                        server_id: None,
                    }),
                    resolution_only: false,
                }),
                dns: Some(RuleDnsEffect {
                    enabled: true,
                    action: None,
                    migrated_implicit_resolve: false,
                    resolver: RuleDnsResolver::Direct,
                    answer_mode: RuleDnsAnswerMode::Real,
                }),
            }),
            action: RuleAction::Block,
            enabled: true,
            bypass_fakeip: None,
            target_server_id: None,
            remarks: None,
            tls_spoof: None,
            tls_spoof_method: None,
        }];
        let route = build_route_config(&config, &empty_id_map(), &deps_default(&[]));
        let matching: Vec<_> = route
            .rules
            .iter()
            .filter(|rule| {
                rule.domain
                    .as_ref()
                    .is_some_and(|domains| domains.contains(&"dns.example.com".to_string()))
            })
            .collect();
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0].action.as_deref(), Some("resolve"));
        assert!(matching[0].outbound.is_none());
    }
}

#[test]
fn sniff_is_first_rule() {
    let config = UserConfig::default();
    let deps = deps_default(&[]);
    let rc = build_route_config(&config, &empty_id_map(), &deps);
    assert_eq!(rc.rules[0].action.as_deref(), Some("sniff"));
}

#[test]
fn probe_routes_when_ports_present() {
    let config = UserConfig::default();
    let deps = deps_default(&[]);
    let rc = build_route_config(&config, &empty_id_map(), &deps);
    // 探针钉死路由（probe-direct-in → direct, probe-proxy-in → proxy-selector）紧随 sniff。
    let probe_direct = rc.rules.iter().find(|r| {
        r.inbound.as_ref().map(|o| match o {
            OneOrMany::One(s) => s == "probe-direct-in",
            OneOrMany::Many(v) => v.iter().any(|s| s == "probe-direct-in"),
        }) == Some(true)
    });
    assert!(probe_direct.is_some());
    assert_eq!(probe_direct.unwrap().outbound.as_deref(), Some("direct"));
}

#[test]
fn proxy_health_route_does_not_require_direct_probe() {
    let config = UserConfig::default();
    let mut deps = deps_default(&[]);
    deps.probe_direct_port = None;
    let rc = build_route_config(&config, &empty_id_map(), &deps);

    assert!(!rc.rules.iter().any(|rule| {
        rule.inbound.as_ref().is_some_and(|inbound| match inbound {
            OneOrMany::One(tag) => tag == "probe-direct-in",
            OneOrMany::Many(tags) => tags.iter().any(|tag| tag == "probe-direct-in"),
        })
    }));
    let proxy = rc
        .rules
        .iter()
        .find(|rule| {
            rule.inbound.as_ref().is_some_and(|inbound| match inbound {
                OneOrMany::One(tag) => tag == "probe-proxy-in",
                OneOrMany::Many(tags) => tags.iter().any(|tag| tag == "probe-proxy-in"),
            })
        })
        .expect("proxy health route must be generated independently");
    assert_eq!(proxy.outbound.as_deref(), Some("proxy-selector"));
}

#[test]
fn probe_routes_absent_when_ports_missing() {
    let config = UserConfig::default();
    let mut deps = deps_default(&[]);
    deps.probe_direct_port = None;
    deps.probe_proxy_port = None;
    let rc = build_route_config(&config, &empty_id_map(), &deps);
    let has_probe = rc.rules.iter().any(|r| {
        r.inbound.as_ref().map(|o| match o {
            OneOrMany::One(s) => s == "probe-direct-in",
            OneOrMany::Many(v) => v.iter().any(|s| s == "probe-direct-in"),
        }) == Some(true)
    });
    assert!(!has_probe);
}

#[test]
fn hijack_dns_rule_present() {
    let config = UserConfig::default();
    let deps = deps_default(&[]);
    let rc = build_route_config(&config, &empty_id_map(), &deps);
    let hijack = rc
        .rules
        .iter()
        .find(|r| r.action.as_deref() == Some("hijack-dns"));
    assert!(hijack.is_some());
    assert_eq!(hijack.unwrap().port, Some(OneOrMany::Many(vec![53])));
}

#[test]
fn core_process_direct_rule_present() {
    let config = UserConfig::default();
    let deps = deps_default(&[]);
    let rc = build_route_config(&config, &empty_id_map(), &deps);
    let core = rc.rules.iter().find(|r| match r.process_name.as_ref() {
        Some(OneOrMany::Many(v)) => v == &["sing-box".to_string(), "sing-box.exe".to_string()],
        _ => false,
    });
    assert!(core.is_some());
    assert_eq!(core.unwrap().outbound.as_deref(), Some("direct"));
}

#[test]
fn node_domain_exclusion() {
    let mut config = UserConfig::default();
    config
        .servers
        .push(crate::user_config::server_config::ServerConfig {
            id: "s1".into(),
            name: "HK".into(),
            protocol: crate::user_config::server_config::Protocol::Vless,
            address: "hk.example.com".into(),
            port: 443,
            ..Default::default()
        });
    let mut id_map = BTreeMap::new();
    id_map.insert("s1".to_string(), "HK".to_string());
    let deps = deps_default(&[]);
    let rc = build_route_config(&config, &id_map, &deps);
    let domain_rule = rc.rules.iter().find(|r| {
        r.domain
            .as_ref()
            .map(|d| d.contains(&"hk.example.com".to_string()))
            .unwrap_or(false)
    });
    assert!(domain_rule.is_some());
    assert_eq!(domain_rule.unwrap().outbound.as_deref(), Some("direct"));
}

#[test]
fn node_ip_exclusion() {
    let mut config = UserConfig::default();
    config
        .servers
        .push(crate::user_config::server_config::ServerConfig {
            id: "s1".into(),
            name: "HK".into(),
            protocol: crate::user_config::server_config::Protocol::Vless,
            address: "1.2.3.4".into(),
            port: 443,
            ..Default::default()
        });
    let mut id_map = BTreeMap::new();
    id_map.insert("s1".to_string(), "HK".to_string());
    let deps = deps_default(&[]);
    let rc = build_route_config(&config, &id_map, &deps);
    let ip_rule = rc.rules.iter().find(|r| {
        r.ip_cidr
            .as_ref()
            .map(|c| c.contains(&"1.2.3.4/32".to_string()))
            .unwrap_or(false)
    });
    assert!(ip_rule.is_some());
    assert_eq!(ip_rule.unwrap().outbound.as_deref(), Some("direct"));
}

#[test]
fn ukey_domain_override_address() {
    let config = UserConfig::default();
    let deps = deps_default(&[]);
    let rc = build_route_config(&config, &empty_id_map(), &deps);
    let ukey = rc.rules.iter().find(|r| {
        r.domain_suffix
            .as_ref()
            .map(|d| d.contains(&".microdone.cn".to_string()))
            .unwrap_or(false)
    });
    assert!(ukey.is_some());
    assert_eq!(ukey.unwrap().override_address.as_deref(), Some("127.0.0.1"));
}

#[test]
fn icmp_fallback_direct() {
    let config = UserConfig::default();
    let deps = deps_default(&[]);
    let rc = build_route_config(&config, &empty_id_map(), &deps);
    let icmp = rc.rules.iter().find(|r| {
        r.network
            .as_ref()
            .map(|n| n.contains(&"icmp".to_string()))
            .unwrap_or(false)
    });
    assert!(icmp.is_some());
    assert_eq!(icmp.unwrap().outbound.as_deref(), Some("direct"));
}

#[test]
fn dns_protocol_direct() {
    let config = UserConfig::default();
    let deps = deps_default(&[]);
    let rc = build_route_config(&config, &empty_id_map(), &deps);
    let dns = rc
        .rules
        .iter()
        .find(|r| r.protocol.as_deref() == Some("dns") && r.outbound.as_deref() == Some("direct"));
    assert!(dns.is_some());
}

/// 🔴 出口选阻断的**行为级**断言：代理流量一条都不许出去，直连规则仍生效。
///
/// 与实现无关地写：不问「selector 的 default 是什么」，只问**产物里还有没有一条能把流量
/// 送到代理出口的路**。2026-08-13 把阻断从「selector.default = block 出站」改成规则级 reject，
/// 本条在两种实现下语义相同 —— 这正是它的价值：它钉的是承诺，不是机制。
#[test]
fn block_exit_rejects_all_proxy_bound_traffic() {
    let mut config = UserConfig::default();
    config.proxy_mode = ProxyMode::Smart;
    config.selected_server_id = Some("__block__".into());
    let deps = deps_default(&[]);
    let rc = build_route_config(&config, &empty_id_map(), &deps);

    assert!(
        !rc.rules
            .iter()
            .any(|r| r.outbound.as_deref() == Some(PROXY_SELECTOR_TAG)),
        "仍有规则把流量路由到 proxy-selector —— 用户选了阻断，这些流量会照常出网"
    );
    assert_eq!(
        rc.final_outbound.as_deref(),
        Some("direct"),
        "final 必须落在 direct：万一兜底那条被删，退化方向应是直连而不是静默走代理"
    );
    let last = rc.rules.last().expect("规则表不该为空");
    assert_eq!(last.action.as_deref(), Some("reject"), "末尾缺兜底 reject");
    assert!(
        last.domain_suffix.is_none()
            && last.domain_keyword.is_none()
            && last.ip_cidr.is_none()
            && last.port.is_none()
            && last.network.is_none()
            && last.protocol.is_none(),
        "兜底那条带了匹配器 ⇒ 匹配不到的流量会落到 final，阻断就漏了"
    );
    // 直连侧仍活着（文案承诺「代理流量已丢弃 · 直连规则仍生效」）。
    assert!(
        rc.rules
            .iter()
            .any(|r| r.outbound.as_deref() == Some("direct")),
        "一条直连规则都没剩 —— 与「直连规则仍生效」这句用户可见文案不符"
    );
}

/// 🔴 浏览器 DoH 拦截的**正向对照**：开关打开时必须真发射，且形态正确。
///
/// 与 `no_builtin_domain_reject_table`（守「关的时候没有」）配对。只有反向那条时，
/// 把发射逻辑整段删掉照样全绿 —— 那就是一个「永远不会红」的假门。
///
/// 钉四件事：① 发两条（TCP 443/853 + UDP443）；② 用 `domain_suffix` **不是** `domain_keyword`
/// （keyword 面太宽，用户填个短词就误伤一片，而后果他看不见）；③ 未编辑清单时用内置起点；
/// ④ 两条都排在**自定义规则之前** —— 排在后面的话，一条把该域名路由到代理的自定义规则
/// 就能让 DoH-over-QUIC 漏过去，用户开了开关却半通半不通。
#[test]
fn browser_doh_block_emits_only_when_switched_on() {
    let doh_rules = |cfg: &UserConfig| -> Vec<RouteRule> {
        let deps = deps_default(&[]);
        build_route_config(cfg, &empty_id_map(), &deps)
            .rules
            .into_iter()
            .filter(|r| {
                r.action.as_deref() == Some("reject")
                    && r.domain_suffix
                        .as_ref()
                        .map(|v| v.iter().any(|d| d == "dns.google"))
                        .unwrap_or(false)
            })
            .collect()
    };

    // 关（默认）：一条都不该有。
    let mut off = UserConfig::default();
    off.proxy_mode = ProxyMode::Smart;
    assert!(
        doh_rules(&off).is_empty(),
        "开关默认关，却发射了 DoH reject"
    );

    // 开 + 未编辑清单 → 内置起点，两条。
    let mut on = UserConfig::default();
    on.proxy_mode = ProxyMode::Smart;
    on.block_browser_doh = Some(true);
    let hits = doh_rules(&on);
    assert_eq!(
        hits.len(),
        2,
        "开关打开应发 TCP+UDP 两条，实为 {}",
        hits.len()
    );
    assert!(
        hits.iter().all(|r| r.domain_keyword.is_none()),
        "用了 domain_keyword —— 本清单是用户可编辑的，keyword 的误伤面用户看不见"
    );
    assert!(
        hits.iter()
            .any(|r| r.port == Some(OneOrMany::Many(vec![443, 853]))),
        "缺 DoH(443)+DoT(853) 那条"
    );
    assert!(
        hits.iter()
            .any(|r| r.network.as_deref() == Some(["udp".to_string()].as_slice())),
        "缺 DoH-over-QUIC(UDP443) 那条"
    );
    assert!(
        hits[0]
            .domain_suffix
            .as_ref()
            .is_some_and(|v| v.len() == DEFAULT_BROWSER_DOH_SUFFIXES.len()),
        "未编辑清单时应当用内置起点全量"
    );

    // 开 + 用户自定清单 → 以用户的为准（并归一化）。
    let mut custom = on.clone();
    custom.browser_doh_list = Some(vec!["  DNS.Google  ".into(), String::new()]);
    let hits = doh_rules(&custom);
    assert_eq!(hits.len(), 2);
    assert_eq!(
        hits[0].domain_suffix.as_deref(),
        Some(["dns.google".to_string()].as_slice()),
        "用户清单未被 trim/小写归一化，或没盖过内置起点"
    );

    // 开 + 用户清空清单 → 等于不拦（尊重用户把它清空这个动作）。
    let mut emptied = on.clone();
    emptied.browser_doh_list = Some(vec![]);
    assert!(doh_rules(&emptied).is_empty(), "用户清空了清单却仍在拦");

    // 次序：两条都必须排在自定义规则之前。
    use crate::user_config::rule::{Rule, RuleType};
    let mut ordered = on.clone();
    ordered.custom_rules = vec![Rule {
        id: "r-doh".into(),
        type_field: RuleType::DomainSuffix,
        values: vec!["dns.google".into()],
        conditions: None,
        combine_mode: None,
        effects: None,
        action: RuleAction::Proxy,
        enabled: true,
        bypass_fakeip: None,
        target_server_id: None,
        remarks: None,
        tls_spoof: None,
        tls_spoof_method: None,
    }];
    let deps = deps_default(&[]);
    let rules = build_route_config(&ordered, &empty_id_map(), &deps).rules;
    let last_reject = rules
        .iter()
        .rposition(|r| {
            r.action.as_deref() == Some("reject")
                && r.domain_suffix
                    .as_ref()
                    .map(|v| v.iter().any(|d| d == "dns.google"))
                    .unwrap_or(false)
        })
        .expect("开关打开却找不到 DoH reject");
    let custom_hit = rules
        .iter()
        .position(|r| {
            r.outbound.is_some()
                && r.domain_suffix
                    .as_ref()
                    .is_some_and(|v| v.iter().any(|d| d == "dns.google"))
        })
        .expect("自定义规则没发射（本用例的前提）");
    assert!(
        last_reject < custom_hit,
        "DoH reject 排到了自定义规则之后（{last_reject} vs {custom_hit}）—— \
             一条把该域名路由到代理的自定义规则会让 DoH-over-QUIC 漏过去"
    );
}

/// 🔴 **不得存在任何内置的域名 reject 表**（2026-08-13 用户裁定，整块移除三张）。
///
/// 被移除的三张：DoH 泄漏域名的 443/853 reject、同一批域名的 UDP443 reject、
/// Chrome/Edge 后台 beacon 的 14 个 Google 域名。共同点是**硬编码 + 无任何用户开关**。
///
/// # 本门守的是「不许重建」，判据取产物
///
/// 判据 = 生成的路由规则里，凡 `action == "reject"` 者**都必须由用户开关或用户自定义规则产生**，
/// 不得出现「带域名匹配器且无人可关」的 reject。默认配置（全部开关关闭、无自定义规则）下
/// 一条带域名匹配的 reject 都不该有 —— 这正是重建那三张表时必然违反的那一格。
///
/// 不用「grep 域名字面量」当判据：换一批域名就绕过去了，而问题从来不是**哪些**域名，
/// 是**有没有一张用户关不掉的表**。
#[test]
fn no_builtin_domain_reject_table() {
    for mode in [ProxyMode::Global, ProxyMode::Smart, ProxyMode::Direct] {
        let mut config = UserConfig::default();
        config.proxy_mode = mode;
        // 显式关掉两个会合法产出 reject 的开关，把剩下的任何 reject 都暴露出来。
        config.block_quic = Some(false);
        config.webrtc_leak_protection = Some("off".to_string());
        let deps = deps_default(&[]);
        let rc = build_route_config(&config, &empty_id_map(), &deps);

        let offenders: Vec<_> = rc
            .rules
            .iter()
            .filter(|r| r.action.as_deref() == Some("reject"))
            .filter(|r| {
                r.domain.is_some()
                    || r.domain_suffix.is_some()
                    || r.domain_keyword.is_some()
                    || r.domain_regex.is_some()
            })
            .collect();

        assert!(
            offenders.is_empty(),
            "{mode:?} 模式下出现了 {} 条带域名匹配器的内置 reject —— \
                 用户关不掉的域名黑名单已被重建：{offenders:#?}",
            offenders.len()
        );
    }
}

#[test]
fn block_quic_emits_fallback_reject() {
    let mut config = UserConfig::default();
    config.block_quic = Some(true);
    config.proxy_mode = ProxyMode::Global;
    config
        .servers
        .push(crate::user_config::server_config::ServerConfig {
            id: "s1".into(),
            name: "HK".into(),
            protocol: crate::user_config::server_config::Protocol::Vless,
            address: "1.2.3.4".into(),
            port: 443,
            ..Default::default()
        });
    let mut id_map = BTreeMap::new();
    id_map.insert("s1".to_string(), "HK".to_string());
    let deps = deps_default(&[]);
    let rc = build_route_config(&config, &id_map, &deps);
    // blockProxyQuic 兜底：末尾应有裸 udp443 reject（无 matcher）。
    let bare_udp443 = rc.rules.iter().any(|r| {
        r.action.as_deref() == Some("reject")
            && r.network.as_deref() == Some(["udp".to_string()].as_slice())
            && r.port.as_ref().map(|p| match p {
                OneOrMany::One(p) => *p == 443,
                OneOrMany::Many(p) => p.as_slice() == [443],
            }) == Some(true)
    });
    assert!(bare_udp443);
}

#[test]
fn webrtc_proxy_emits_stun_route() {
    let mut config = UserConfig::default();
    config.webrtc_leak_protection = Some("proxy".to_string());
    config.proxy_mode = ProxyMode::Global;
    config
        .servers
        .push(crate::user_config::server_config::ServerConfig {
            id: "s1".into(),
            name: "HK".into(),
            protocol: crate::user_config::server_config::Protocol::Vless,
            address: "1.2.3.4".into(),
            port: 443,
            ..Default::default()
        });
    let mut id_map = BTreeMap::new();
    id_map.insert("s1".to_string(), "HK".to_string());
    let deps = deps_default(&[]);
    let rc = build_route_config(&config, &id_map, &deps);
    let stun = rc.rules.iter().find(|r| {
        r.protocol.as_deref() == Some("stun") && r.outbound.as_deref() == Some("proxy-selector")
    });
    assert!(stun.is_some());
}

#[test]
fn webrtc_block_emits_stun_reject() {
    let mut config = UserConfig::default();
    config.webrtc_leak_protection = Some("block".to_string());
    let deps = deps_default(&[]);
    let rc = build_route_config(&config, &empty_id_map(), &deps);
    let stun = rc
        .rules
        .iter()
        .find(|r| r.protocol.as_deref() == Some("stun") && r.action.as_deref() == Some("reject"));
    assert!(stun.is_some());
}

#[test]
fn webrtc_off_no_stun_rule() {
    let config = UserConfig::default();
    let deps = deps_default(&[]);
    let rc = build_route_config(&config, &empty_id_map(), &deps);
    let stun = rc
        .rules
        .iter()
        .any(|r| r.protocol.as_deref() == Some("stun"));
    assert!(!stun);
}

#[test]
fn endpoint_force_route_preferred_by_wg() {
    let mut config = UserConfig::default();
    config.proxy_mode = ProxyMode::Global;
    config
        .servers
        .push(crate::user_config::server_config::ServerConfig {
            id: "w1".into(),
            name: "WG".into(),
            protocol: Protocol::Wireguard,
            address: "1.2.3.4".into(),
            port: 443,
            wireguard_settings: Some(Box::new(
                crate::user_config::server_config::WireGuardSettings {
                    allowed_ips: vec!["10.0.0.0/24".into()],
                    allow_internet: Some(true),
                    ..Default::default()
                },
            )),
            ..Default::default()
        });
    let mut id_map = BTreeMap::new();
    id_map.insert("w1".to_string(), "WG".to_string());
    let endpoint = Endpoint {
        type_field: "wireguard".into(),
        tag: "WG".into(),
        ..Default::default()
    };
    let pending = [endpoint];
    let deps = deps_default(&pending);
    let rc = build_route_config(&config, &id_map, &deps);
    // WG 非全隧道 → preferred_by（allowInternet=true 但 allowed_ips 无 0/0 → carriesFullTunnel=allowInternet=true?）。
    // 注意：mesh_node_carries_full_tunnel = allowInternet（true），故此处 usePreferredBy=false → ip_cidr 路径。
    let force = rc.rules.iter().find(|r| {
        r.ip_cidr
            .as_ref()
            .map(|c| c.contains(&"10.0.0.0/24".to_string()))
            .unwrap_or(false)
    });
    assert!(force.is_some());
    assert_eq!(force.unwrap().outbound.as_deref(), Some("WG"));
}

#[test]
fn endpoint_force_route_skipped_if_not_in_pending() {
    let mut config = UserConfig::default();
    config.proxy_mode = ProxyMode::Global;
    config
        .servers
        .push(crate::user_config::server_config::ServerConfig {
            id: "w1".into(),
            name: "WG".into(),
            protocol: Protocol::Wireguard,
            address: "1.2.3.4".into(),
            port: 443,
            wireguard_settings: Some(Box::new(
                crate::user_config::server_config::WireGuardSettings {
                    allowed_ips: vec!["10.0.0.0/24".into()],
                    ..Default::default()
                },
            )),
            ..Default::default()
        });
    let mut id_map = BTreeMap::new();
    id_map.insert("w1".to_string(), "WG".to_string());
    let deps = deps_default(&[]); // 无 pending endpoint
    let rc = build_route_config(&config, &id_map, &deps);
    let force = rc.rules.iter().any(|r| {
        r.ip_cidr
            .as_ref()
            .map(|c| c.contains(&"10.0.0.0/24".to_string()))
            .unwrap_or(false)
    });
    assert!(!force);
}

#[test]
fn local_geo_rule_set_injected_when_srs_valid() {
    let mut config = UserConfig::default();
    config.proxy_mode = ProxyMode::Smart;
    let mut deps = deps_default(&[]);
    deps.is_valid_srs_fn = |_| true; // 所有 .srs 视为存在
    let rc = build_route_config(&config, &empty_id_map(), &deps);
    let rs = rc.rule_set.expect("smart 非直连应有 rule_set");
    assert!(rs.iter().any(|r| r.tag == "geosite-cn"));
    assert!(rs.iter().any(|r| r.tag == "geoip-cn"));
    assert!(rs.iter().any(|r| r.tag == "geosite-geolocation-!cn"));
}

#[test]
fn local_geo_rule_set_absent_when_srs_invalid() {
    let mut config = UserConfig::default();
    config.proxy_mode = ProxyMode::Smart;
    let deps = deps_default(&[]); // is_valid_srs_fn 默认 false
    let rc = build_route_config(&config, &empty_id_map(), &deps);
    // 无内置注入、无自定义规则引用 → rule_set 为空（Polaris: [] 数组，所有 srs 被跳过）。
    let rs_len = rc.rule_set.as_deref().map(|v| v.len()).unwrap_or(0);
    assert_eq!(rs_len, 0);
}

// ───────── T2：规则资源缺失时 final fail-safe（真机 2026-07-20 全量明文直连的根治点）─────────

/// 构造「smart + 回国（reverse）」配置。
fn reverse_cn_config() -> UserConfig {
    let mut config = UserConfig::default();
    config.proxy_mode = ProxyMode::Smart;
    config.region_routing = Some(crate::user_config::region_routing::RegionRoutingConfig {
        enabled: true,
        region: "cn".into(),
        reverse: true,
    });
    config
}

/// **资源齐全 + reverse** → `final=direct` 是设计语义（海外直连），必须原样保留。
/// 变异锁：把 fail-safe 的 `!pruned.is_empty()` 条件删掉（无条件翻）→ 此测转红。
#[test]
fn reverse_final_stays_direct_when_rule_sets_complete() {
    let config = reverse_cn_config();
    let mut deps = deps_default(&[]);
    deps.is_valid_srs_fn = |_| true; // 资源齐全
    let out = build_route_config_with_report(&config, &empty_id_map(), &deps);
    assert!(
        out.pruned_rule_set_tags.is_empty(),
        "资源齐全不该有剪枝：{:?}",
        out.pruned_rule_set_tags
    );
    assert_eq!(
        out.route.final_outbound.as_deref(),
        Some("direct"),
        "reverse 下 final=direct 是设计语义，资源齐全时不得改动"
    );
}

/// **资源缺失 + reverse** → 唯一把流量送代理的 geosite-cn/geoip-cn 规则被剪光，
/// 若 final 仍是 direct 就是**全量明文直连**（fail-open）。必须 fail-safe 回退到 proxy-selector。
/// 变异锁：删整个 fail-safe 块 / 把回退目标写成 "direct" → 转红。
#[test]
fn reverse_final_fails_safe_to_proxy_when_rule_sets_pruned() {
    let config = reverse_cn_config();
    let deps = deps_default(&[]); // is_valid_srs_fn 默认 false = 资源全缺
    let out = build_route_config_with_report(&config, &empty_id_map(), &deps);

    assert!(
        !out.pruned_rule_set_tags.is_empty(),
        "资源全缺必须报告剪枝（否则运行时层收不到信号）"
    );
    assert!(
        out.pruned_rule_set_tags.iter().any(|t| t == "geosite-cn"),
        "回国模式的 →代理 腿 geosite-cn 必须在剪枝清单里：{:?}",
        out.pruned_rule_set_tags
    );
    assert_eq!(
        out.route.final_outbound.as_deref(),
        Some(PROXY_SELECTOR_TAG),
        "资源缺失 + reverse 叠加 = fail-open 全量明文直连；final 必须回退为代理"
    );
    // 兜底断言语义：剪枝后确实没有任何规则再指向代理 —— 正因如此 final 才是唯一防线。
    let to_proxy = out
        .route
        .rules
        .iter()
        .any(|r| r.outbound.as_deref() == Some(PROXY_SELECTOR_TAG) && r.rule_set.is_some());
    assert!(!to_proxy, "剪枝后不该还有 rule_set 规则指向代理");

    // **内部入站排除腿的变异锁**：本场景里 `probe-proxy-in` 规则确实指向代理，若 `routes_to_exit`
    // 不排除钉死内部入站的规则，它就会返回 true ⇒ fail-safe 永不触发 ⇒ 上面那条 final 断言转红。
    // 这条断言把「探针规则存在」这个前提钉住，防后人删掉排除腿时误以为无人覆盖。
    let probe_to_proxy = out
        .route
        .rules
        .iter()
        .any(|r| r.inbound.is_some() && r.outbound.as_deref() == Some(PROXY_SELECTOR_TAG));
    assert!(
        probe_to_proxy,
        "前提：本场景应有钉死内部入站（probe-proxy-in）且指向代理的规则；\
             没有它，`routes_to_exit` 的 inbound 排除腿就没被本用例覆盖"
    );
    assert!(
        !routes_to_exit(&out.route.rules, PROXY_SELECTOR_TAG),
        "用户流量已无代理腿（自家探针不算）—— 这正是 fail-safe 必须触发的判据"
    );
}

/// 造一条引用「非内置」geo 类目的自定义规则（`config.rule_resources` 里也没有 ⇒ 必悬空 ⇒ 必被剪）。
/// 用它模拟「用户装了一条引用未下载 geo 分类的规则」——真实且高频的剪枝来源。
fn dangling_custom_geo_rule() -> crate::user_config::rule::Rule {
    use crate::user_config::rule::{Rule, RuleType};
    Rule {
        id: "r-dangling".into(),
        type_field: RuleType::Geosite,
        // bilibili 不在 builtin_geo_rulesets() 表内 ⇒ 不会被随包腿注入。
        values: vec!["bilibili".into()],
        conditions: None,
        combine_mode: None,
        effects: None,
        action: RuleAction::Proxy,
        enabled: true,
        bypass_fakeip: None,
        target_server_id: None,
        remarks: None,
        tls_spoof: None,
        tls_spoof_method: None,
    }
}

/// **R4：内置 geo 在随包播种目录缺失时，必须回落「规则资源」页下载的本地副本。**
///
/// 不做这条，给用户的指引就是死路：剪枝 warn 与 `RULE_RESOURCES_MISSING` 都写「到「规则资源」页
/// 下载后重连恢复」，而下载腿一律落 `rule_resources_path`、内置基线却只读 `runtime_rules_dir`
/// ⇒ 用户下载成功、再连仍被剪。
///
/// 变异锁：删内置注入腿里的 `add_local_geo_rule_set(...)` 回落调用 → geosite-cn 重新被剪 → 转红。
#[test]
fn builtin_geo_falls_back_to_downloaded_rule_resource() {
    use crate::user_config::rule::{RuleResource, RuleResourceFormat};
    let mut config = reverse_cn_config();
    config.rule_resources = vec![RuleResource {
        id: "geosite-cn".into(), // catalog id 与 builtin tag 同形（rule_resource_catalog.rs 模块头）
        name: "geosite-cn".into(),
        category: "geosite".into(),
        source_url: "https://example.invalid/geosite-cn.srs".into(),
        file_name: "geosite-cn.srs".into(),
        format: RuleResourceFormat::Binary,
        size: 1,
        downloaded_at: "2026-07-20T00:00:00Z".into(),
    }];
    let mut deps = deps_default(&[]);
    // 随包播种目录**全空**（异常打包 / 播种失败），规则资源目录里有用户下载的那一份。
    deps.is_valid_srs_fn = |p| p.starts_with("/fake/res/");
    let out = build_route_config_with_report(&config, &empty_id_map(), &deps);

    let injected = out
        .route
        .rule_set
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .find(|r| r.tag == "geosite-cn");
    assert_eq!(
        injected.and_then(|r| r.path.as_deref()),
        Some("/fake/res/geosite-cn.srs"),
        "随包缺失时内置 tag 必须回落规则资源页的本地副本"
    );
    assert!(
        !out.pruned_rule_set_tags.iter().any(|t| t == "geosite-cn"),
        "回落成功就不该再被剪：{:?}",
        out.pruned_rule_set_tags
    );
    // 没下载的那些内置 tag 照常 fail-closed 剪掉（回落不是「无条件放行」）。
    assert!(
        out.pruned_rule_set_tags.iter().any(|t| t == "geoip-cn"),
        "未下载且随包缺失的内置 tag 仍必须被剪：{:?}",
        out.pruned_rule_set_tags
    );
}

/// `routes_to_exit` 三条腿的直测（判据本身，不经 builder）。
///
/// 递归腿单列在这里的原因：当前 builder 生成的嵌套 logical 规则（`:568` 的 udp443 配对）
/// 子规则只有 matcher、不带 `outbound` ⇒ 递归腿**按构造走不到**，只靠 builder 级用例覆盖不了它
/// （实测变异：删掉递归，builder 那批全绿）。判据是纯函数，直测比留一条无门的分支便宜得多。
#[test]
fn routes_to_exit_covers_top_level_nested_and_inbound_exclusion() {
    let plain_proxy = RouteRule {
        action: Some("route".into()),
        outbound: Some(PROXY_SELECTOR_TAG.into()),
        ..empty_matcher()
    };
    let plain_direct = RouteRule {
        action: Some("route".into()),
        outbound: Some("direct".into()),
        ..empty_matcher()
    };
    let probe_pinned = RouteRule {
        inbound: Some(OneOrMany::Many(vec!["probe-proxy-in".into()])),
        action: Some("route".into()),
        outbound: Some(PROXY_SELECTOR_TAG.into()),
        ..empty_matcher()
    };
    let nested_proxy = RouteRule {
        type_field: Some("logical".into()),
        mode: Some("and".into()),
        rules: Some(vec![plain_proxy.clone()]),
        ..empty_matcher()
    };

    assert!(
        routes_to_exit(std::slice::from_ref(&plain_proxy), PROXY_SELECTOR_TAG),
        "顶层腿"
    );
    assert!(
        routes_to_exit(std::slice::from_ref(&nested_proxy), PROXY_SELECTOR_TAG),
        "递归腿"
    );
    assert!(
        !routes_to_exit(std::slice::from_ref(&plain_direct), PROXY_SELECTOR_TAG),
        "指向别处的规则不得算数"
    );
    assert!(
        !routes_to_exit(std::slice::from_ref(&probe_pinned), PROXY_SELECTOR_TAG),
        "钉死内部入站（探针/更新）的规则不承载用户流量，不得算数"
    );
    assert!(
        !routes_to_exit(
            &[
                RouteRule {
                    inbound: Some(OneOrMany::Many(vec!["probe-proxy-in".into()])),
                    rules: Some(vec![nested_proxy]),
                    ..empty_matcher()
                },
                plain_direct,
                probe_pinned,
            ],
            PROXY_SELECTOR_TAG
        ),
        "内部入站的排除必须先于递归——否则嵌在探针规则里的代理出站会被误算成用户腿"
    );
}

/// **R2 反向门：fail-safe 不得被「任意悬空 tag」触发。**
///
/// 场景：smart + 回国 + 28 个内置 geo 全部正常，用户另有一条引用未下载 geo 分类的自定义规则。
/// 旧判据 `!pruned.is_empty()` 在此为真 ⇒ `final` 从 direct 被翻成 proxy-selector ⇒
/// **全部海外流量改走国内节点**，把回国模式的「海外直连」语义整体反转。而真正的「→代理」腿
/// （`geosite-cn`/`geoip-cn`）完好无损、根本没有 fail-open —— 这是纯粹的误伤。
///
/// 变异锁：把 T2 的 `!routes_to_exit(&rules, user_exit_tag)` 删掉（退回「有剪枝就翻」）→ 转红。
#[test]
fn reverse_final_stays_direct_when_only_unrelated_tag_pruned() {
    let mut config = reverse_cn_config();
    config.custom_rules = vec![dangling_custom_geo_rule()];
    let mut deps = deps_default(&[]);
    // 随包内置全在（`/fake/rules/...`），规则资源目录空（`/fake/res/...` 全无效）。
    deps.is_valid_srs_fn = |p| p.starts_with("/fake/rules/");
    let out = build_route_config_with_report(&config, &empty_id_map(), &deps);

    assert!(
        out.pruned_rule_set_tags
            .iter()
            .any(|t| t == "geosite-bilibili"),
        "该自定义规则引用的 geo 必须被剪（本用例的前提）：{:?}",
        out.pruned_rule_set_tags
    );
    assert!(
        !out.pruned_rule_set_tags.iter().any(|t| t == "geosite-cn"),
        "回国模式的 →代理 腿必须完好（本用例的另一半前提）：{:?}",
        out.pruned_rule_set_tags
    );
    assert_eq!(
        out.route.final_outbound.as_deref(),
        Some("direct"),
        "「→代理」腿完好时 final=direct 仍是设计语义；翻成代理 = 海外流量被误送国内节点"
    );
    // 判据自证：确实还有规则指向用户出口 —— fail-safe 正是因此才不该触发。
    assert!(
        routes_to_exit(&out.route.rules, PROXY_SELECTOR_TAG),
        "前提失守：剪枝后已无规则指向代理，那本用例就不该期望 final 保持 direct"
    );
}

/// **R3：组网出口回退（D4/D7）时 fail-safe 无处可退**，不得静默 no-op、更不得打「已回退为代理」。
///
/// `mesh_selected_exit_falls_back_to_direct` 为真 ⇒ `user_exit_tag == "direct"` ⇒ 把 direct 写成
/// direct 是 no-op，而旧代码在写之前已经打了「默认出口已回退为代理」—— 日志说谎，比不打更糟。
///
/// 变异锁：删 `user_exit_tag == "direct"` 分流腿 → 走进 `routes_to_exit(rules, "direct")`
/// （恒真：smart 模式有大量直连规则）→ 一句 warn 都不发 → 下面的日志断言转红。
#[test]
fn mesh_exit_fallback_logs_cannot_fail_safe_instead_of_lying() {
    let mut config = UserConfig::default();
    config.proxy_mode = ProxyMode::Smart;
    config.selected_server_id = Some("w1".into());
    config.custom_rules = vec![dangling_custom_geo_rule()];
    config
        .servers
        .push(crate::user_config::server_config::ServerConfig {
            id: "w1".into(),
            name: "WG".into(),
            protocol: Protocol::Wireguard,
            address: "1.2.3.4".into(),
            port: 443,
            wireguard_settings: Some(Box::new(
                crate::user_config::server_config::WireGuardSettings {
                    allowed_ips: vec!["10.0.0.0/24".into()],
                    // 关外网 ⇒ carriesFullTunnel=false ⇒ 用户出口整体回退 direct。
                    allow_internet: Some(false),
                    ..Default::default()
                },
            )),
            ..Default::default()
        });

    // `RouteConfigDeps.log` 是裸 fn 指针，闭包捕获不了 ⇒ 用 thread_local 收集（测试单线程内自洽）。
    thread_local! {
        static SINK: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
    }
    fn capture(_lvl: LogLevel, msg: &str) {
        SINK.with(|s| s.borrow_mut().push(msg.to_string()));
    }
    SINK.with(|s| s.borrow_mut().clear());

    let mut deps = deps_default(&[]);
    deps.is_valid_srs_fn = |p| p.starts_with("/fake/rules/");
    deps.log = capture;
    let out = build_route_config_with_report(&config, &empty_id_map(), &deps);
    let captured = SINK.with(|s| s.borrow().clone());

    assert!(
        mesh_selected_exit_falls_back_to_direct(&config),
        "前提：本场景必须触发组网出口回退"
    );
    assert!(
        !out.pruned_rule_set_tags.is_empty(),
        "前提：本场景必须发生剪枝"
    );
    assert_eq!(
        out.route.final_outbound.as_deref(),
        Some("direct"),
        "出口本身就是 direct，final 只能是 direct（写 direct 到 direct 是 no-op）"
    );
    assert!(
        captured.iter().any(|m| m.contains("无法回退为代理")),
        "必须如实告知「无法 fail-safe」：{captured:?}"
    );
    assert!(
        !captured.iter().any(|m| m.contains("默认出口已回退为代理")),
        "绝不能打「已回退为代理」——什么都没回退，这是日志说谎：{captured:?}"
    );
}

/// **判据换成 `is_mesh_node` 后的真值表**：`mesh_selected_exit_falls_back_to_direct` 现在是
/// `is_mesh_node(selected) && !mesh_node_carries_full_tunnel(selected)`，不再按协议字面量白名单
/// 收窄。`OpenvpnClient`/`Openconnect` 的组网资格由 `meshRoutes` 是否非空决定（[`is_mesh_node`]），
/// 故 OpenVPN 是四格：redirect_gateway(开/关/缺省) × meshRoutes(非空/空)。另覆盖 OpenConnect
/// （无该开关，落缺省 true）、以及一个非 mesh 协议（回归保护：换判据不该让普通节点开始兜底）。
/// WG/TS 既有用例（`mesh_exit_fallback_logs_cannot_fail_safe_instead_of_lying`）结论不受影响——
/// `is_mesh_protocol` 对这两者恒 true，合取式不改变它们的结果，故本处不重复覆盖。
///
/// 变异锁：把 `is_mesh_node(selected) &&` 换回 `matches!(selected.protocol, Protocol::Wireguard
/// | Protocol::Tailscale) &&`（旧判据）→ 「OpenVPN + meshRoutes 非空 + redirect_gateway=false」
/// 那条转红（旧判据下 OpenVPN 恒不匹配、结果恒 false，与本用例断言的 true 矛盾）。
#[test]
fn mesh_selected_exit_fallback_truth_table_by_protocol() {
    use crate::user_config::protocol_settings::OpenvpnClientSettings;
    use crate::user_config::server_config::ServerConfig;

    fn config_with_server(server: ServerConfig) -> UserConfig {
        let mut config = UserConfig::default();
        config.selected_server_id = Some(server.id.clone());
        config.servers.push(server);
        config
    }

    // OpenvpnClient + redirect_gateway=Some(false) + meshRoutes 非空 ⇒ true——本次要修的那格。
    let cfg = config_with_server(ServerConfig {
        id: "o1".into(),
        name: "OVPN off, mesh".into(),
        protocol: Protocol::OpenvpnClient,
        mesh_routes: vec!["10.1.0.0/24".into()],
        openvpn_client_settings: Some(Box::new(OpenvpnClientSettings {
            redirect_gateway: Some(false),
            ..Default::default()
        })),
        ..Default::default()
    });
    assert!(
        mesh_selected_exit_falls_back_to_direct(&cfg),
        "OpenVPN 组网节点显式关 redirect_gateway 现在必须兜底 direct"
    );

    // OpenvpnClient + redirect_gateway=Some(false) + meshRoutes 为空 ⇒ false——回归保护：
    // 没声明 meshRoutes 就不是组网节点，不该比 TS 更宽去兜底。
    let cfg = config_with_server(ServerConfig {
        id: "o2".into(),
        name: "OVPN off, no mesh".into(),
        protocol: Protocol::OpenvpnClient,
        openvpn_client_settings: Some(Box::new(OpenvpnClientSettings {
            redirect_gateway: Some(false),
            ..Default::default()
        })),
        ..Default::default()
    });
    assert!(
        !mesh_selected_exit_falls_back_to_direct(&cfg),
        "OpenVPN 没有 meshRoutes 就不具备组网资格，不该兜底（与 TS 一致，回归保护）"
    );

    // OpenvpnClient + redirect_gateway=Some(true) + meshRoutes 非空 ⇒ false。
    let cfg = config_with_server(ServerConfig {
        id: "o3".into(),
        name: "OVPN on, mesh".into(),
        protocol: Protocol::OpenvpnClient,
        mesh_routes: vec!["10.1.0.0/24".into()],
        openvpn_client_settings: Some(Box::new(OpenvpnClientSettings {
            redirect_gateway: Some(true),
            ..Default::default()
        })),
        ..Default::default()
    });
    assert!(
        !mesh_selected_exit_falls_back_to_direct(&cfg),
        "OpenVPN 显式开 redirect_gateway 承载全隧道，不该兜底"
    );

    // OpenvpnClient + redirect_gateway=None（缺省）+ meshRoutes 非空 ⇒ false（缺省判 true=承载全隧道）。
    let cfg = config_with_server(ServerConfig {
        id: "o4".into(),
        name: "OVPN default, mesh".into(),
        protocol: Protocol::OpenvpnClient,
        mesh_routes: vec!["10.1.0.0/24".into()],
        openvpn_client_settings: Some(Box::new(OpenvpnClientSettings::default())),
        ..Default::default()
    });
    assert!(
        !mesh_selected_exit_falls_back_to_direct(&cfg),
        "OpenVPN 缺省 redirect_gateway 落 true（承载全隧道），不该兜底"
    );

    // Openconnect + meshRoutes 非空：无该开关，落 `_ => true` ⇒ false。
    let cfg = config_with_server(ServerConfig {
        id: "oc1".into(),
        name: "OpenConnect".into(),
        protocol: Protocol::Openconnect,
        mesh_routes: vec!["10.1.0.0/24".into()],
        ..Default::default()
    });
    assert!(
        !mesh_selected_exit_falls_back_to_direct(&cfg),
        "OpenConnect 无全隧道开关，恒承载全隧道，不该兜底"
    );

    // 非 mesh 协议（Vless）：回归保护——换判据不该让普通节点开始兜底。
    let cfg = config_with_server(ServerConfig {
        id: "v1".into(),
        name: "VLESS".into(),
        protocol: Protocol::Vless,
        ..Default::default()
    });
    assert!(
        !mesh_selected_exit_falls_back_to_direct(&cfg),
        "普通协议节点不该因为换判据而开始兜底 direct"
    );
}

/// **`proxy_mode=direct`（用户显式全直连）→ final 必须保持 direct**，那是用户意图不是降级。
///
/// **本用例锁的是「让 fail-safe 在 direct 模式下不可达」的上游不变式**，而不是 fail-safe 的
/// `proxy_mode != "direct"` 守卫本身——实测确认（变异 M2）：删掉那个守卫，**没有任何测试转红**，
/// 因为 direct 模式下压根产生不出悬空引用：
///   - 内置 geo rule_set 不注入（`:951` 的 `proxy_mode != "direct"` 门），**但也没有规则引用它们**；
///   - 自定义规则 / 应用分流整块**仅 smart 模式发**（`:529` `if proxy_mode == "smart"`）；
///   - 地区分流 geo 基线同样仅 smart（`:830`）。
///
/// ⟹ direct 模式的 `dangling` 恒空 ⟹ fail-safe 恒不进入 ⟹ 那个守卫是**按构造不可达的
/// defense-in-depth**，不是被覆盖的分支。**别把它当成有牙的变异锁。** 真正守住用户意图的是本不变式：
/// 下面这条断言若哪天转红（= 有人让 direct 模式也发引用 geo 的规则），就必须回头重新审视那个守卫
/// 到底还够不够——那时它才会从「不可达」变成「唯一防线」。
#[test]
fn direct_mode_never_prunes_so_final_stays_direct() {
    use crate::user_config::rule::{Rule, RuleType};
    let mut config = UserConfig::default();
    config.proxy_mode = ProxyMode::Direct;
    // 尽最大努力制造悬空引用：挂一条引用 geosite 类目的自定义规则 + 开启回国地区分流。
    config.custom_rules = vec![Rule {
        id: "r-geo".into(),
        type_field: RuleType::Geosite,
        values: vec!["youtube".into()],
        conditions: None,
        combine_mode: None,
        effects: None,
        action: RuleAction::Proxy,
        enabled: true,
        bypass_fakeip: None,
        target_server_id: None,
        remarks: None,
        tls_spoof: None,
        tls_spoof_method: None,
    }];
    config.region_routing = Some(crate::user_config::region_routing::RegionRoutingConfig {
        enabled: true,
        region: "cn".into(),
        reverse: true,
    });
    let deps = deps_default(&[]); // 资源全缺
    let out = build_route_config_with_report(&config, &empty_id_map(), &deps);

    assert!(
        out.pruned_rule_set_tags.is_empty(),
        "不变式失守：direct 模式竟产生了悬空 rule_set 引用（{:?}）——\
             fail-safe 的 `proxy_mode != \"direct\"` 守卫从此是真防线，需重新做变异验证",
        out.pruned_rule_set_tags
    );
    assert_eq!(
        out.route.final_outbound.as_deref(),
        Some("direct"),
        "用户显式选的全直连必须原样保留"
    );
}

/// 非 reverse 的 smart（正向）资源缺失：final 本就是 proxy-selector，fail-safe 不该改变它。
/// 证明 fail-safe 只在「final 已落 direct」时出手，不是无条件覆写。
#[test]
fn forward_smart_final_unchanged_when_pruned() {
    let mut config = UserConfig::default();
    config.proxy_mode = ProxyMode::Smart;
    let deps = deps_default(&[]); // 资源全缺
    let out = build_route_config_with_report(&config, &empty_id_map(), &deps);
    assert_eq!(
        out.route.final_outbound.as_deref(),
        Some(PROXY_SELECTOR_TAG)
    );
}

#[test]
fn inactive_region_geo_excluded() {
    let mut config = UserConfig::default();
    config.proxy_mode = ProxyMode::Smart;
    config.region_routing = Some(crate::user_config::region_routing::RegionRoutingConfig {
        enabled: true,
        region: "cn".into(),
        reverse: false,
    });
    let mut deps = deps_default(&[]);
    deps.is_valid_srs_fn = |_| true;
    let rc = build_route_config(&config, &empty_id_map(), &deps);
    let rs = rc.rule_set.unwrap();
    // region=cn 时，ir/ru 地区 geo 不注入。
    assert!(!rs.iter().any(|r| r.tag == "geosite-category-ir"));
    assert!(!rs.iter().any(|r| r.tag == "geoip-ru"));
}

#[test]
fn app_rule_process_name_route() {
    let mut config = UserConfig::default();
    config.proxy_mode = ProxyMode::Smart;
    config.app_routing_enabled = Some(true);
    config.app_rules.push(AppRule {
        app_id: "custom-app".into(),
        action: RuleAction::Proxy,
        enabled: true,
        target_server_id: None,
    });
    config.custom_app_presets.push(CustomAppPreset {
        id: "custom-app".into(),
        name: "MyApp".into(),
        emoji: "".into(),
        icon_url: None,
        geosite_tags: vec![],
        geoip_tags: vec![],
        process_names: Some(vec!["myapp".into()]),
        category: None,
    });
    let deps = deps_default(&[]);
    let rc = build_route_config(&config, &empty_id_map(), &deps);
    let app_rule = rc.rules.iter().find(|r| match r.process_name.as_ref() {
        Some(OneOrMany::Many(v)) => v == &["myapp".to_string()],
        _ => false,
    });
    assert!(app_rule.is_some());
    assert_eq!(
        app_rule.unwrap().outbound.as_deref(),
        Some("rule-sel-app-custom-app")
    );
}

/// 应用分流「阻断」⇒ 规则级 `action:"reject"` + 无 outbound + **不配对 udp443 reject**。
///
/// 三条断言各锁一处（口径同 `custom_rules::block_action_emits_rule_level_reject_without_outbound`）：
///  - `action == "reject"`：退回 `"route"` 就是把该阻断的流量交给 `route.final`（proxy-selector）
///    ⇒ 静默走代理。
///  - `outbound is None`：残留 `"block"` ⇒ 引用一个已被上游废弃的 legacy special outbound。
///  - **只有一条命中 `myapp` 的规则**：`app_out_is_proxy` 若仍按 outbound 字面量反推
///    （Block 现在没有 outbound ⇒ 反推成「是代理」），就会在前面白插一条
///    `network:udp / port:443 / action:reject` 的配对规则 ⇒ 计数变 2 ⇒ 转红。
#[test]
fn app_rule_block_emits_rule_level_reject_and_no_udp443_pair() {
    let mut config = UserConfig::default();
    config.proxy_mode = ProxyMode::Smart;
    config.app_routing_enabled = Some(true);
    config.block_quic = Some(true); // 打开 udp443 配对，否则第 3 条断言恒绿
    config.app_rules.push(AppRule {
        app_id: "custom-app".into(),
        action: RuleAction::Block,
        enabled: true,
        target_server_id: None,
    });
    config.custom_app_presets.push(CustomAppPreset {
        id: "custom-app".into(),
        name: "MyApp".into(),
        emoji: "".into(),
        icon_url: None,
        geosite_tags: vec![],
        geoip_tags: vec![],
        process_names: Some(vec!["myapp".into()]),
        category: None,
    });
    let deps = deps_default(&[]);
    let rc = build_route_config(&config, &empty_id_map(), &deps);
    let hits: Vec<_> = rc
        .rules
        .iter()
        .filter(|r| match r.process_name.as_ref() {
            Some(OneOrMany::Many(v)) => v == &["myapp".to_string()],
            _ => false,
        })
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "阻断的应用规则不该被配对 udp443 reject（那是「走代理」才需要的）：{hits:?}"
    );
    assert_eq!(hits[0].action.as_deref(), Some("reject"));
    assert_eq!(
        hits[0].outbound, None,
        "reject 是规则级动作，不得再指向 legacy `block` 出站"
    );
    assert_eq!(
        hits[0].no_drop,
        Some(true),
        "阻断规则必须 no_drop:true 才与 legacy `block` 出站等价（默认会泛洪降级成 drop）"
    );
    // 反向：走代理的应用规则**不该**带 no_drop（那条是 route 动作，字段无意义）。
    let mut proxy_cfg = config.clone();
    proxy_cfg.app_rules[0].action = RuleAction::Proxy;
    let rc2 = build_route_config(&proxy_cfg, &empty_id_map(), &deps);
    let route_hit = rc2
        .rules
        .iter()
        .find(|r| {
            r.action.as_deref() == Some("route")
                && matches!(r.process_name.as_ref(), Some(OneOrMany::Many(v)) if v == &["myapp".to_string()])
        })
        .expect("走代理的应用规则应存在");
    assert_eq!(
        route_hit.no_drop, None,
        "route 动作不该带 no_drop —— 无条件加会把无意义字段撒进每条规则"
    );
}

#[test]
fn custom_domestic_dns_ip_added_to_direct_cidrs() {
    let mut config = UserConfig::default();
    config.dns_config = Some(crate::user_config::dns_config::DnsConfig {
        domestic_dns: Some("https://223.5.5.5/dns-query".into()),
        ..Default::default()
    });
    let deps = deps_default(&[]);
    let rc = build_route_config(&config, &empty_id_map(), &deps);
    // 223.5.5.5/32 应出现在 DNS 直连放行规则中（BOOTSTRAP_DIRECT_DNS_IPS 含 223.5.5.5，自定义 IP 重复也无妨）。
    let dns_direct = rc.rules.iter().find(|r| {
        r.ip_cidr
            .as_ref()
            .map(|c| c.contains(&"223.5.5.5/32".to_string()))
            .unwrap_or(false)
    });
    assert!(dns_direct.is_some());
}

/// 取 DNS 直连放行规则（`ip_cidr` 含引导 DNS + action=route→direct 的那条）。
fn dns_direct_ports(rc: &RouteConfig) -> Vec<u32> {
    let rule = rc
        .rules
        .iter()
        .find(|r| {
            r.outbound.as_deref() == Some("direct")
                && r.ip_cidr
                    .as_ref()
                    .is_some_and(|c| c.contains(&"223.5.5.5/32".to_string()))
        })
        .expect("DNS 直连放行规则必存在");
    match rule.port.as_ref().expect("该规则必带端口集") {
        OneOrMany::One(p) => vec![*p],
        OneOrMany::Many(v) => v.clone(),
    }
}

fn dns_config_with_custom_pool(pool: &[&str], custom: &[(&str, &str)]) -> UserConfig {
    let mut config = UserConfig::default();
    config.dns_config = Some(crate::user_config::dns_config::DnsConfig {
        node_resolver_pool: Some(pool.iter().map(|s| (*s).to_string()).collect()),
        node_resolver_custom: Some(
            custom
                .iter()
                .map(
                    |(id, spec)| crate::user_config::dns_config::CustomDnsUpstream {
                        id: (*id).to_string(),
                        spec: (*spec).to_string(),
                    },
                )
                .collect(),
        ),
        ..Default::default()
    });
    config
}

/// 【不变式：race 上游的 IP 与端口必须一起放行】
///
/// 端口集写死 `[53,443]` 时，`https://9.9.9.9:8443/q` 与 `udp://9.9.9.9:5353` 的流量匹配不上
/// 直连规则 → TUN 下经代理出站 → 起核自举窗内该上游恒 FAIL/回环。
///
/// **变异锁**：删掉 `build_route` 里的 `dns_ports.extend(deps.race_upstream_ports…)` → 转红。
#[test]
fn race_custom_upstream_nonstandard_ports_are_direct_allowed() {
    let config = dns_config_with_custom_pool(
        &["ali", "my-doh", "my-udp"],
        &[
            ("my-doh", "https://9.9.9.9:8443/q"),
            ("my-udp", "udp://9.9.9.9:5353"),
        ],
    );
    let mut deps = deps_default(&[]);
    // race 就绪（sidecar 已起）：两轴均由 `polaris-dns-race` 的真实上游集下发。
    deps.race_upstream_ips = vec!["9.9.9.9".to_string()];
    deps.race_upstream_ports = vec![443, 8443, 5353];
    let rc = build_route_config(&config, &empty_id_map(), &deps);

    let ports = dns_direct_ports(&rc);
    assert!(
        ports.contains(&53) && ports.contains(&443),
        "恒定端口不得丢"
    );
    assert!(
        ports.contains(&8443),
        "自定义 DoH 非标端口须放行，实际: {ports:?}"
    );
    assert!(
        ports.contains(&5353),
        "自定义 UDP 非 53 口须放行，实际: {ports:?}"
    );
    // IP 也必须在（两轴缺一不可，否则规则照样匹配不上）。
    let rule_has_ip = rc.rules.iter().any(|r| {
        r.ip_cidr
            .as_ref()
            .is_some_and(|c| c.contains(&"9.9.9.9/32".to_string()))
    });
    assert!(rule_has_ip, "自定义上游 IP 须进直连放行");
    // 端口集仍须去重（`443` 由恒定集与 race 集各贡献一次）。
    let mut sorted = ports.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), ports.len(), "端口集不得有重复项: {ports:?}");
}

/// race off（两轴皆空）→ 端口集**逐字节回现状**，金样不动。
///
/// 配置里**故意留着**一个声明了非标端口的自定义上游：race off 时它不该有任何影响
/// （sidecar 都没起，放行它的端口纯属白开口子）。
#[test]
fn race_off_leaves_dns_direct_ports_untouched() {
    let config = dns_config_with_custom_pool(&["my-doh"], &[("my-doh", "https://9.9.9.9:8443/q")]);
    let deps = deps_default(&[]); // race 两轴默认空
    let rc = build_route_config(&config, &empty_id_map(), &deps);
    assert_eq!(
        dns_direct_ports(&rc),
        vec![53, 443],
        "race off 时不得叠加任何端口"
    );
}

/// 【不变式：端口集**只**来自 `deps.race_upstream_ports`，route 不得照 `dnsConfig` 复算】
///
/// 曾经这里有一个 `race_custom_upstream_ports(config)`：就地从 `nodeResolverPool` + `nodeResolverCustom`
/// 再导出一遍端口。它与 sidecar 侧 `resolve_upstreams` 的选择逻辑（Tier 分桶 / canonical 去重 /
/// Tier1 上限 / TUN 摘 `system`）**刻意不一致**（取超集），于是同一件事有了两份真值源 —— 两边任
/// 一侧改口径都不会让另一侧转红。现在端口随 IP 由 sidecar 一路下发，本 builder 只消费。
///
/// 判据构造成「配置说一套、注入说另一套」：`dnsConfig` 里点名的是 `:9443`，注入进来的是 `:8443`。
/// 只有真的不复算，输出才会跟着注入走。
///
/// **变异锁**：把 `race_custom_upstream_ports(config)` 那行加回去 → `9443` 断言立刻转红。
#[test]
fn dns_direct_ports_come_only_from_deps_never_recomputed_from_config() {
    let config = dns_config_with_custom_pool(
        &["ali", "selected"],
        &[
            // 配置层面点名 :9443；但真实上游集（注入）里是 :8443。
            ("selected", "https://8.8.8.8:9443/q"),
            ("domain", "https://dns.google:9444/q"), // 域名 → sidecar 侧拒绝腿
            ("dot", "tls://1.1.1.1:8853"),           // DoT 二期 → sidecar 侧拒绝腿
        ],
    );
    let mut deps = deps_default(&[]);
    deps.race_upstream_ips = vec!["9.9.9.9".to_string()];
    deps.race_upstream_ports = vec![8443];
    let ports = dns_direct_ports(&build_route_config(&config, &empty_id_map(), &deps));
    assert!(
        ports.contains(&8443),
        "注入的端口必须落进规则，实际: {ports:?}"
    );
    for unwanted in [9443u32, 9444, 8853] {
        assert!(
            !ports.contains(&unwanted),
            "{unwanted} 只存在于 dnsConfig、不在注入的真实上游集里 → 不得被放行（复算复活的信号），\
                 实际: {ports:?}"
        );
    }
}

#[test]
fn udp443_reject_rule_factory() {
    let matcher = RouteRule {
        process_name: Some(OneOrMany::One("chrome".into())),
        ..empty_matcher()
    };
    let rule = udp443_reject_rule(matcher);
    assert_eq!(rule.action.as_deref(), Some("reject"));
    assert_eq!(
        rule.network.as_deref(),
        Some(["udp".to_string()].as_slice())
    );
    assert_eq!(rule.port, Some(OneOrMany::Many(vec![443])));
    assert_eq!(rule.process_name, Some(OneOrMany::One("chrome".into())));
}

#[test]
fn proxy_mode_str_mapping() {
    let mut config = UserConfig::default();
    config.proxy_mode = ProxyMode::Smart;
    assert_eq!(proxy_mode_str(&config), "smart");
    config.proxy_mode = ProxyMode::Global;
    assert_eq!(proxy_mode_str(&config), "global");
    config.proxy_mode = ProxyMode::Direct;
    assert_eq!(proxy_mode_str(&config), "direct");
}

#[test]
fn collect_refs_handles_nested_logical() {
    let rules = vec![RouteRule {
        rule_set: Some(OneOrMany::One("geosite-cn".into())),
        rules: Some(vec![RouteRule {
            rule_set: Some(OneOrMany::Many(vec![
                "geoip-cn".into(),
                "geosite-private".into(),
            ])),
            ..empty_matcher()
        }]),
        ..empty_matcher()
    }];
    let mut refs = BTreeSet::new();
    collect_refs(&rules, &mut refs);
    assert!(refs.contains("geosite-cn"));
    assert!(refs.contains("geoip-cn"));
    assert!(refs.contains("geosite-private"));
}

#[test]
fn update_in_port_route() {
    let mut config = UserConfig::default();
    config.proxy_mode = ProxyMode::Global;
    let mut deps = deps_default(&[]);
    deps.update_in_port = Some(7892);
    let rc = build_route_config(&config, &empty_id_map(), &deps);
    let update = rc.rules.iter().find(|r| {
        r.inbound.as_ref().map(|o| match o {
            OneOrMany::One(s) => s == "update-in",
            OneOrMany::Many(v) => v.iter().any(|s| s == "update-in"),
        }) == Some(true)
    });
    assert!(update.is_some());
    assert_eq!(update.unwrap().outbound.as_deref(), Some("proxy-selector"));
}

#[test]
fn subscription_update_route_is_resolve_reject_then_pin() {
    let mut config = UserConfig::default();
    config.proxy_mode = ProxyMode::Global;
    config
        .servers
        .push(crate::user_config::server_config::ServerConfig {
            id: "s1".into(),
            name: "proxy".into(),
            protocol: crate::user_config::server_config::Protocol::Http,
            address: "proxy.example".into(),
            port: 443,
            ..Default::default()
        });
    config.selected_server_id = Some("s1".into());
    let mut deps = deps_default(&[]);
    deps.subscription_update_in_port = Some(7893);
    let rc = build_route_config(&config, &empty_id_map(), &deps);
    let guarded: Vec<_> = rc
        .rules
        .iter()
        .filter(|rule| {
            rule.inbound.as_ref().is_some_and(|inbound| match inbound {
                OneOrMany::One(tag) => tag == "subscription-update-in",
                OneOrMany::Many(tags) => tags.iter().any(|tag| tag == "subscription-update-in"),
            })
        })
        .collect();
    assert_eq!(guarded.len(), 3);
    assert_eq!(guarded[0].action.as_deref(), Some("resolve"));
    assert_eq!(guarded[0].server.as_deref(), Some("dns-remote"));
    assert_eq!(guarded[1].action.as_deref(), Some("reject"));
    assert_eq!(guarded[1].no_drop, Some(true));
    let blocked = guarded[1].ip_cidr.as_ref().unwrap();
    assert!(blocked.iter().any(|cidr| cidr == "100.64.0.0/10"));
    assert!(blocked.iter().any(|cidr| cidr == "fc00::/7"));
    assert!(blocked.iter().any(|cidr| cidr == "::ffff:7f00:0/104"));
    assert!(!blocked.iter().any(|cidr| cidr == "198.18.0.0/15"));
    assert_eq!(guarded[2].action.as_deref(), Some("route"));
    assert_eq!(guarded[2].outbound.as_deref(), Some("proxy-selector"));
}

fn subscription_update_outbound(config: &UserConfig) -> Option<String> {
    let mut deps = deps_default(&[]);
    deps.subscription_update_in_port = Some(7893);
    let rc = build_route_config(config, &empty_id_map(), &deps);
    rc.rules
        .iter()
        .rev()
        .find(|rule| {
            rule.action.as_deref() == Some("route")
                && rule.inbound.as_ref().is_some_and(|inbound| match inbound {
                    OneOrMany::One(tag) => tag == "subscription-update-in",
                    OneOrMany::Many(tags) => tags.iter().any(|tag| tag == "subscription-update-in"),
                })
        })
        .and_then(|rule| rule.outbound.clone())
}

#[test]
fn subscription_update_proxy_predicate_matches_generated_route() {
    let mut config = UserConfig::default();
    config.proxy_mode = ProxyMode::Smart;
    config
        .servers
        .push(crate::user_config::server_config::ServerConfig {
            id: "s1".into(),
            name: "proxy".into(),
            protocol: crate::user_config::server_config::Protocol::Http,
            address: "proxy.example".into(),
            port: 443,
            ..Default::default()
        });
    config.selected_server_id = Some("s1".into());
    assert!(subscription_update_route_uses_proxy(&config));
    assert_eq!(
        subscription_update_outbound(&config).as_deref(),
        Some("proxy-selector")
    );

    for (mode, selected, why) in [
        (ProxyMode::Direct, Some("s1"), "direct mode"),
        (ProxyMode::Smart, Some("__direct__"), "direct sentinel"),
        (
            ProxyMode::Smart,
            Some("__block__"),
            "block management exemption",
        ),
    ] {
        config.proxy_mode = mode;
        config.selected_server_id = selected.map(str::to_owned);
        assert!(!subscription_update_route_uses_proxy(&config), "{why}");
        assert_eq!(
            subscription_update_outbound(&config).as_deref(),
            Some("direct"),
            "{why}"
        );
    }

    config.proxy_mode = ProxyMode::Smart;
    config.selected_server_id = None;
    config.servers.clear();
    assert!(!subscription_update_route_uses_proxy(&config));
    assert_eq!(
        subscription_update_outbound(&config).as_deref(),
        Some("direct")
    );
}

/// update-in 那条腿的出站（None = 没生成该规则）。
fn update_in_outbound(config: &UserConfig) -> Option<String> {
    let mut deps = deps_default(&[]);
    deps.update_in_port = Some(7892);
    let rc = build_route_config(config, &empty_id_map(), &deps);
    rc.rules
        .iter()
        .find(|r| {
            r.inbound.as_ref().map(|o| match o {
                OneOrMany::One(s) => s == "update-in",
                OneOrMany::Many(v) => v.iter().any(|s| s == "update-in"),
            }) == Some(true)
        })
        .and_then(|r| r.outbound.clone())
}

/// 【阻断出口豁免管理面】选阻断时 update-in 必须走 direct，不能跟着 proxy-selector 一起被 block。
///
/// 变异锁：把 `proxy_mode == "direct" || exit_is_block` 里的 `|| exit_is_block` 删掉 →
/// 该腿回到 "proxy-selector" → 转红。两种模式都测，因为 exit_is_block 与 proxy_mode 正交。
#[test]
fn block_exit_exempts_update_in_from_blocking() {
    for mode in [ProxyMode::Global, ProxyMode::Smart] {
        let mut config = UserConfig::default();
        config.proxy_mode = mode;
        config.selected_server_id = Some("__block__".into());
        assert_eq!(
            update_in_outbound(&config).as_deref(),
            Some("direct"),
            "proxy_mode={} 选阻断时订阅/更新腿必须豁免",
            mode.as_str()
        );
    }
}

/// 对照腿：**没选**阻断时 update-in 仍钉在 proxy-selector 上（豁免不得泄漏成无条件 direct）。
///
/// 缺了这条，把 update-in 无条件改成 direct 也能让上面那条绿——订阅更新会永久绕过代理，
/// 在墙内等于永久失效，且没有任何门会红。
#[test]
fn non_block_exit_keeps_update_in_on_proxy_selector() {
    for selected in [None, Some("__direct__"), Some("s1")] {
        let mut config = UserConfig::default();
        config.proxy_mode = ProxyMode::Global;
        config.selected_server_id = selected.map(str::to_string);
        assert_eq!(
            update_in_outbound(&config).as_deref(),
            Some("proxy-selector"),
            "selected={selected:?} 时 update-in 不该被改写"
        );
    }
}
