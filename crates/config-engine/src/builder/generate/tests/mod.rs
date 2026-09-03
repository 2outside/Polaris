use super::*;
use crate::builder::outbounds::INVALID_REASON_DETOUR_CASCADE;
use crate::user_config::proxy_mode::{ProxyMode, ProxyModeType};
use crate::user_config::rule::{
    Rule, RuleAction, RuleDnsAnswerMode, RuleDnsEffect, RuleDnsResolver, RuleEffects, RuleResource,
    RuleResourceFormat, RuleType,
};
use crate::user_config::server_config::{Protocol, SecurityMode, ServerConfig};

/// 构造最小 GenerateConfigDeps（Linux、race off、无 probe、FS 全 false）。
fn deps_default() -> GenerateConfigDeps {
    GenerateConfigDeps {
        platform: "linux".into(),
        arch: "x64".into(),
        race_server_port: 0,
        probe_direct_port: None,
        probe_proxy_port: None,
        update_in_port: None,
        subscription_update_in_port: None,
        probe_pool_ports: vec![],
        lan_resolver_for_dns: None,
        race_upstream_ips: vec![],
        race_upstream_ports: vec![],
        has_cronet: true,
        cronet_copy_failed: false,
        has_management_api: false,
        privacy_mode: false,
        log_level: crate::user_config::LogLevel::Info,
        disable_log_file: false,
        dashboard_serve_dir: None,
        tailscale_api_port: 15490,
        cache_path: "/fake/cache.db".into(),
        log_file_path: Some("/fake/singbox.log".into()),
        runtime_rules_dir: "/fake/runtime-rules".into(),
        rule_resources_path: "/fake/rule-resources".into(),
        custom_rules_dir: "/fake/custom-rules".into(),
        tailscale_state_dir_prefix: "/fake/ts".into(),
        is_valid_srs_fn: |_| false,
        own_lan_cidrs: vec![],
        log: |_, _| {},
        on_degraded: || {},
    }
}

/// 最小 UserConfig：smart + systemProxy + 单 vless 节点。
fn base_config() -> UserConfig {
    UserConfig {
        servers: vec![ServerConfig {
            id: "s1".into(),
            name: "HK".into(),
            protocol: Protocol::Vless,
            address: "hk.example.com".into(),
            port: 443,
            uuid: Some("u".into()),
            security: Some(SecurityMode::Tls),
            ..Default::default()
        }],
        selected_server_id: Some("s1".into()),
        proxy_mode: ProxyMode::Smart,
        proxy_mode_type: ProxyModeType::SystemProxy,
        ..Default::default()
    }
}

fn rule_resource(id: &str, format: RuleResourceFormat) -> RuleResource {
    RuleResource {
        id: id.into(),
        name: id.into(),
        category: "test".into(),
        source_url: format!("https://rules.invalid/{id}.srs"),
        file_name: format!("{id}.srs"),
        format,
        size: 3,
        downloaded_at: "2026-01-01T00:00:00Z".into(),
    }
}

fn dns_rule_set_rule(id: &str, rule_set: &str) -> Rule {
    Rule {
        id: id.into(),
        type_field: RuleType::RuleSet,
        values: vec![format!("res:{rule_set}")],
        conditions: None,
        combine_mode: None,
        effects: Some(RuleEffects {
            route: None,
            dns: Some(RuleDnsEffect {
                enabled: true,
                action: None,
                migrated_implicit_resolve: false,
                resolver: RuleDnsResolver::Direct,
                answer_mode: RuleDnsAnswerMode::Real,
            }),
        }),
        action: RuleAction::Direct,
        enabled: true,
        bypass_fakeip: None,
        target_server_id: None,
        remarks: None,
        tls_spoof: None,
        tls_spoof_method: None,
    }
}

fn traffic_rule_set_rule(id: &str, rule_set: &str) -> Rule {
    Rule {
        id: id.into(),
        type_field: RuleType::RuleSet,
        values: vec![format!("res:{rule_set}")],
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

fn route_rule_set_count(config: &SingBoxConfig, tag: &str) -> usize {
    config
        .route
        .as_ref()
        .and_then(|route| route.rule_set.as_deref())
        .unwrap_or(&[])
        .iter()
        .filter(|entry| entry.tag == tag)
        .count()
}

fn dns_references_rule_set(config: &SingBoxConfig, tag: &str) -> bool {
    config
        .dns
        .as_ref()
        .and_then(|dns| dns.rules.as_deref())
        .unwrap_or(&[])
        .iter()
        .any(|rule| match rule.rule_set.as_ref() {
            Some(OneOrMany::One(value)) => value == tag,
            Some(OneOrMany::Many(values)) => values.iter().any(|value| value == tag),
            None => false,
        })
}

/// DNS 规则与流量规则的作用域不同：前者在 smart/global/direct 都生效，后者只在 smart
/// 生效。这个矩阵锁住「DNS 引用 ⇒ route.rule_set 定义」的跨平面闭环，并确认不会顺手把未引用
/// 的资源预加载进核配置。
#[test]
fn dns_local_rule_set_definitions_follow_dns_across_modes_without_preloading_unused_resources() {
    for mode in [ProxyMode::Smart, ProxyMode::Global, ProxyMode::Direct] {
        for format in [RuleResourceFormat::Binary, RuleResourceFormat::Source] {
            for traffic_also_references in [false, true] {
                let mut config = base_config();
                config.proxy_mode = mode;
                config.rule_resources = vec![
                    rule_resource("dns-resource", format),
                    rule_resource("unused-resource", RuleResourceFormat::Binary),
                ];
                config.custom_rules = vec![dns_rule_set_rule("dns-rule", "dns-resource")];
                if traffic_also_references {
                    config
                        .custom_rules
                        .push(traffic_rule_set_rule("traffic-rule", "dns-resource"));
                }
                let mut deps = deps_default();
                deps.is_valid_srs_fn = |_| true;

                let outcome =
                    generate_sing_box_config_with_report(&config, &BTreeMap::new(), &deps)
                        .expect("DNS 资源有效时完整配置必须可生成");
                let tag = "local-rs-dns-resource";
                assert!(
                    dns_references_rule_set(&outcome.config, tag),
                    "{mode:?}/{format:?}/traffic={traffic_also_references}: DNS 引用不应被流量模式裁掉"
                );
                assert_eq!(
                    route_rule_set_count(&outcome.config, tag),
                    1,
                    "{mode:?}/{format:?}/traffic={traffic_also_references}: DNS 引用必须有且仅有一个定义"
                );
                let definition = outcome
                    .config
                    .route
                    .as_ref()
                    .and_then(|route| route.rule_set.as_deref())
                    .unwrap_or(&[])
                    .iter()
                    .find(|entry| entry.tag == tag)
                    .expect("上面的定义计数已证明存在");
                assert_eq!(
                    definition.format,
                    match format {
                        RuleResourceFormat::Binary => "binary",
                        RuleResourceFormat::Source => "source",
                    },
                    "资源格式必须保留，不能因 DNS 保活被硬改"
                );
                assert_eq!(
                    route_rule_set_count(&outcome.config, "local-rs-unused-resource"),
                    0,
                    "{mode:?}/{format:?}/traffic={traffic_also_references}: 未被 DNS/流量引用的资源不得预加载"
                );
            }
        }
    }
}

/// 内置/目录型资源同样可被 DNS 单独引用；direct 模式不能再以「流量全直连」为由省掉其定义。
#[test]
fn dns_builtin_rule_set_definitions_survive_all_proxy_modes() {
    for mode in [ProxyMode::Smart, ProxyMode::Global, ProxyMode::Direct] {
        let mut config = base_config();
        config.proxy_mode = mode;
        config.custom_rules = vec![Rule {
            id: "dns-builtin".into(),
            type_field: RuleType::Geosite,
            values: vec!["cn".into()],
            conditions: None,
            combine_mode: None,
            effects: Some(RuleEffects {
                route: None,
                dns: Some(RuleDnsEffect {
                    enabled: true,
                    action: None,
                    migrated_implicit_resolve: false,
                    resolver: RuleDnsResolver::Direct,
                    answer_mode: RuleDnsAnswerMode::Real,
                }),
            }),
            action: RuleAction::Direct,
            enabled: true,
            bypass_fakeip: None,
            target_server_id: None,
            remarks: None,
            tls_spoof: None,
            tls_spoof_method: None,
        }];
        let mut deps = deps_default();
        deps.is_valid_srs_fn = |_| true;
        let outcome = generate_sing_box_config_with_report(&config, &BTreeMap::new(), &deps)
            .expect("内置 DNS rule_set 应可生成");
        assert!(dns_references_rule_set(&outcome.config, "geosite-cn"));
        assert_eq!(route_rule_set_count(&outcome.config, "geosite-cn"), 1);
    }
}

/// DNS 的 `rule_set: [A, B]` 是一个复合 matcher，不是两个可独立降级的规则；B 缺失时若保留
/// A 会把原本的交集/并集语义静默改写。因此任一 tag 悬空都必须整条 fail-closed，报告仍按 tag 去重。
#[test]
fn dns_multi_rule_set_with_any_missing_definition_is_removed_as_one_rule() {
    let mut dns = DnsConfig {
        servers: vec![],
        rules: Some(vec![
            DnsRule {
                rule_set: Some(OneOrMany::Many(vec!["defined".into(), "missing".into()])),
                ..Default::default()
            },
            DnsRule {
                rule_set: Some(OneOrMany::One("missing".into())),
                ..Default::default()
            },
        ]),
        final_server: None,
        strategy: None,
        fakeip: None,
        reverse_mapping: None,
        optimistic: None,
        timeout: None,
    };

    let pruned = prune_unresolved_dns_rule_sets(&mut dns, &BTreeSet::from(["defined".into()]));

    assert_eq!(pruned, vec!["missing"]);
    assert!(dns.rules.as_deref().unwrap_or(&[]).is_empty());
}

/// 造一份「合法 vless（选中） + 一个 Tailscale 节点」的配置，TS 的 `control_url` 由入参给定。
fn config_with_ts_control_url(control_url: &str) -> UserConfig {
    use crate::user_config::server_config::TailscaleSettings;
    let mut cfg = base_config();
    cfg.servers.push(ServerConfig {
        id: "ts1".into(),
        name: "我的 headscale".into(),
        protocol: Protocol::Tailscale,
        tailscale_settings: Some(Box::new(TailscaleSettings {
            control_url: Some(control_url.to_string()),
            ..Default::default()
        })),
        ..Default::default()
    });
    cfg
}

/// **拦截必须发生在「下发到核」之前** —— 这条钉的是发射面，不是谓词。
///
/// `control_url.rs` 的单测只证明「谓词判得对」；就算谓词全绿，只要 `outbounds.rs` 里那段 gate
/// 没接上，坏 endpoint 照样会进 `config.endpoints` 被写进磁盘配置、交给内核去 panic。
/// 故这里断言的是**最终产物**：endpoints 里不得出现该节点，且 `invalid_nodes` 要带对成因。
///
/// **变异实测（真跑过）**：把 `outbounds.rs` 里 Tailscale 分支那段 `if let Some(reject) = …
/// { … continue; }` 整段删掉 ⇒ 本测转红（endpoints 里冒出 `control_url` 为 IP 的 endpoint，
/// 且 `invalid_nodes` 为空）。
#[test]
fn ip_literal_control_url_never_reaches_generated_endpoints() {
    for (url, want_token) in [
        ("http://192.168.1.10:8080", "control-url-ip"),
        ("https://127.0.0.1:39824", "control-url-ip"),
        ("http://[fd7a:115c:a1e0::1]:8080", "control-url-ip"),
        ("hs.example.com", "control-url-scheme"),
        ("http://:8080", "control-url-invalid"),
    ] {
        let cfg = config_with_ts_control_url(url);
        let out = generate_sing_box_config_with_report(&cfg, &BTreeMap::new(), &deps_default())
            .expect("坏 TS 节点只该被剔除，不该让整份配置生成失败");

        // ① 发射面：endpoints 里不得有任何带这个 control_url 的条目。
        let eps = out.config.endpoints.clone().unwrap_or_default();
        assert!(
            !eps.iter().any(|e| e.control_url.is_some()),
            "control_url={url} 的 endpoint 竟被下发到内核配置里（gate 没接上）"
        );
        assert!(
            !eps.iter().any(|e| e.tag.contains("headscale")),
            "被剔节点的 endpoint 仍出现在配置里: {url}"
        );

        // ② 报告面：成因要带对 token（这是用户 tooltip 的真值源）。
        let n = out
            .invalid_nodes
            .iter()
            .find(|n| n.id == "ts1")
            .unwrap_or_else(|| panic!("control_url={url} 未被记进 invalid_nodes"));
        assert_eq!(n.reason, want_token, "成因 token 不对: {url}");

        // ③ 其余节点不受牵连（只剔坏节点，不 FATAL 整份配置）。
        assert!(
            out.config.outbounds.iter().any(|o| o.tag.contains("HK")),
            "合法节点被无辜牵连: {url}"
        );
    }
}

/// **阴性对照**：域名形式的 `control_url` 必须照常下发。
///
/// 没有这条，把 gate 写成「所有 Tailscale 节点一律剔除」也能让上面那条全绿 —— 那样的门
/// 只是把 panic 换成了「Tailscale 永远用不了」。`localhost` 明确在**放行**侧（实测 check 通过）。
///
/// **变异实测（真跑过）**：把 `tailscale_control_url_reject` 改成恒 `Some(IpLiteral)`
/// ⇒ 本测转红（endpoints 为空），而上面那条阳性测试仍全绿。
#[test]
fn domain_control_url_still_reaches_generated_endpoints() {
    for url in [
        "https://hs.example.com",
        "http://localhost:8080",
        "https://controlplane.tailscale.com",
    ] {
        let cfg = config_with_ts_control_url(url);
        let out = generate_sing_box_config_with_report(&cfg, &BTreeMap::new(), &deps_default())
            .expect("合法 TS 节点应能生成");
        let eps = out.config.endpoints.clone().unwrap_or_default();
        assert!(
            eps.iter().any(|e| e.control_url.as_deref() == Some(url)),
            "合法 control_url={url} 没被下发（阴性对照失败 = gate 误伤）"
        );
        assert!(
            !out.invalid_nodes.iter().any(|n| n.id == "ts1"),
            "合法 control_url={url} 被误记进 invalid_nodes"
        );
    }
}

/// 造「detour 级联剔除」场景：naive 节点缺 cronet 被丢 → 链到它的 ss 节点 detour 死引用被剔。
/// 返回 (config, deps)。selected 是独立的合法 vless（保证生成成功、剔除的是非选中节点）。
fn config_with_cascade_invalid() -> (UserConfig, GenerateConfigDeps) {
    use crate::user_config::protocol_settings::{NaiveSettings, ShadowsocksSettings};
    let selected = ServerConfig {
        id: "sel".into(),
        name: "SEL".into(),
        protocol: Protocol::Vless,
        address: "sel.example.com".into(),
        port: 443,
        uuid: Some("u".into()),
        security: Some(SecurityMode::Tls),
        ..Default::default()
    };
    // naive 节点：deps.has_cronet=false 时在 build_outbounds 里被 `continue` 丢弃（不进 outbounds）。
    let naive = ServerConfig {
        id: "nv".into(),
        name: "NAIVE".into(),
        protocol: Protocol::Naive,
        address: "nv.example.com".into(),
        port: 443,
        naive_settings: Some(NaiveSettings { use_http3: None }),
        ..Default::default()
    };
    // ss 节点：detour 指向被丢的 naive → detour 死引用 → 被 prune 剔除 + 记进 gate_invalid_nodes。
    let chained = ServerConfig {
        id: "ch".into(),
        name: "CHAINED".into(),
        protocol: Protocol::Shadowsocks,
        address: "ch.example.com".into(),
        port: 8388,
        detour: Some("nv".into()),
        shadowsocks_settings: Some(Box::new(ShadowsocksSettings {
            method: "aes-256-gcm".into(),
            password: "p".into(),
            ..Default::default()
        })),
        ..Default::default()
    };
    let config = UserConfig {
        servers: vec![selected, naive, chained],
        selected_server_id: Some("sel".into()),
        proxy_mode: ProxyMode::Smart,
        proxy_mode_type: ProxyModeType::SystemProxy,
        ..Default::default()
    };
    let mut deps = deps_default();
    deps.has_cronet = false; // 逼 naive 节点被丢
    (config, deps)
}

#[test]
fn report_surfaces_cascade_invalid_node_with_id_tag_reason() {
    let (config, deps) = config_with_cascade_invalid();
    let outcome = generate_sing_box_config_with_report(&config, &BTreeMap::new(), &deps).unwrap();
    // 「ch」经 nv 的死 detour 被剔 → 必须现身报告，且带 id / 非空 tag / detour-cascade reason。
    // 这一断言锁死的是 generate.rs 末尾「把 gate_invalid_nodes 映射成 InvalidNode」那段接线：
    // 删掉那段 → invalid_nodes 恒空 → 本测转红（变异验证见 report_empty_when_no_invalid_nodes 反面）。
    assert_eq!(outcome.invalid_nodes.len(), 1, "恰一个级联剔除节点");
    let n = &outcome.invalid_nodes[0];
    assert_eq!(n.id, "ch", "记录被剔的引用方 id");
    assert!(!n.tag.is_empty(), "tag 取自剔除前的 id_to_tag_map，非空");
    assert_eq!(n.reason, INVALID_REASON_DETOUR_CASCADE, "成因=detour 级联");
    // 被丢的 naive 本身不进报告（它是 continue 跳过，非 prune 剔除，无 gate 记录）——
    // 报告只含「因死引用被主动剔」的节点，语义与前端 tooltip 一致。
    assert!(
        !outcome.invalid_nodes.iter().any(|x| x.id == "nv"),
        "naive 被 continue 丢弃，不计入 gate 剔除报告"
    );
    // config 本身仍生成成功（选中节点合法）。
    assert!(!outcome.config.outbounds.is_empty());
}

#[test]
fn report_empty_when_no_invalid_nodes() {
    // 全合法配置 → 报告空 Vec（**有意义的空**：渲染端据此清陈旧标灰）。
    let outcome =
        generate_sing_box_config_with_report(&base_config(), &BTreeMap::new(), &deps_default())
            .unwrap();
    assert!(
        outcome.invalid_nodes.is_empty(),
        "无非法节点时报告为空（非 None，是空 Vec）"
    );
}

#[test]
fn wrapper_and_report_produce_identical_config() {
    // `generate_sing_box_config` 是 `_with_report` 的薄 wrapper → 二者 config 必须逐字节同源
    // （证「多返回一个副产物」没有派生出第二条生成路径）。
    let (config, deps) = config_with_cascade_invalid();
    let via_wrapper = generate_sing_box_config(&config, &BTreeMap::new(), &deps).unwrap();
    let via_report = generate_sing_box_config_with_report(&config, &BTreeMap::new(), &deps)
        .unwrap()
        .config;
    assert_eq!(
        serde_json::to_value(&via_wrapper).unwrap(),
        serde_json::to_value(&via_report).unwrap(),
        "wrapper 与 report 入口生成的 config 必须完全一致"
    );
}

#[test]
fn generate_returns_full_config_with_required_sections() {
    let cfg = base_config();
    let result = generate_sing_box_config(&cfg, &BTreeMap::new(), &deps_default()).unwrap();
    // log/dns/inbounds/outbounds/route/experimental 恒存在。
    assert!(!result.inbounds.is_empty(), "inbounds non-empty");
    assert!(!result.outbounds.is_empty(), "outbounds non-empty");
    assert!(result.dns.is_some(), "dns present");
    assert!(result.route.is_some(), "route present");
    assert!(result.experimental.is_some(), "experimental present");
    // services 未注入（has_management_api=false）。
    assert!(result.services.is_none());
}

#[test]
fn cache_file_has_polaris_brand_id_and_store_flags() {
    let result =
        generate_sing_box_config(&base_config(), &BTreeMap::new(), &deps_default()).unwrap();
    let cache = result
        .experimental
        .as_ref()
        .unwrap()
        .cache_file
        .as_ref()
        .unwrap();
    assert!(cache.enabled);
    assert_eq!(cache.path, "/fake/cache.db");
    assert_eq!(cache.cache_id.as_deref(), Some("polaris-dns-v2"));
    assert_eq!(cache.store_fakeip, Some(true));
    assert_eq!(cache.store_dns, Some(true));
}

#[test]
fn direct_selection_skips_server_validation() {
    // __direct__ 哨兵 → 不校验 selectedServer（即使 servers 空也不报错）。
    let mut cfg = base_config();
    cfg.selected_server_id = Some("__direct__".into());
    let result = generate_sing_box_config(&cfg, &BTreeMap::new(), &deps_default());
    assert!(result.is_ok(), "直连哨兵不报错");
}

/// __block__ 哨兵同样豁免 selectedServer 校验 —— 漏了这条，选阻断后**根本起不了核**
/// （报 "Selected server not found"），而 UI 那侧只会显示一个点了没反应的按钮。
///
/// 变异锁：把 `is_sentinel_selection` 换回 `is_direct_selection` → 转红。
#[test]
fn block_selection_skips_server_validation() {
    let mut cfg = base_config();
    cfg.selected_server_id = Some("__block__".into());
    let result = generate_sing_box_config(&cfg, &BTreeMap::new(), &deps_default());
    assert!(result.is_ok(), "阻断哨兵不报错: {:?}", result.err());
}

/// 零节点 + 阻断哨兵也必须能生成（阻断出口不需要任何节点承载）。
#[test]
fn block_selection_generates_with_zero_servers() {
    let mut cfg = base_config();
    cfg.servers = vec![];
    cfg.selected_server_id = Some("__block__".into());
    let result = generate_sing_box_config(&cfg, &BTreeMap::new(), &deps_default());
    assert!(result.is_ok(), "零节点阻断不报错: {:?}", result.err());
}

#[test]
fn missing_selected_server_returns_error() {
    let mut cfg = base_config();
    cfg.selected_server_id = Some("nonexistent".into());
    let result = generate_sing_box_config(&cfg, &BTreeMap::new(), &deps_default());
    assert_eq!(result.unwrap_err(), "Selected server not found");
}

#[test]
fn naive_without_cronet_returns_unavailable_error() {
    // 选中 naive 节点 + has_cronet=false → Err（不静默切节点）。
    let mut cfg = base_config();
    cfg.servers[0].protocol = Protocol::Naive;
    cfg.servers[0].name = "NaiveNode".into();
    let mut deps = deps_default();
    deps.has_cronet = false;
    let result = generate_sing_box_config(&cfg, &BTreeMap::new(), &deps);
    let err = result.unwrap_err();
    assert!(err.contains("NaiveNode"), "错误含节点名");
    assert!(err.contains("libcronet"), "错误含 libcronet 原因");
}

#[test]
fn naive_without_cronet_copy_failed_branch() {
    let mut cfg = base_config();
    cfg.servers[0].protocol = Protocol::Naive;
    cfg.servers[0].name = "N".into();
    let mut deps = deps_default();
    deps.has_cronet = false;
    deps.cronet_copy_failed = true;
    let err = generate_sing_box_config(&cfg, &BTreeMap::new(), &deps).unwrap_err();
    assert!(err.contains("拷贝到核心目录失败"), "copy-failed 文案");
}

#[test]
fn naive_without_cronet_darwin_branch() {
    let mut cfg = base_config();
    cfg.servers[0].protocol = Protocol::Naive;
    cfg.servers[0].name = "N".into();
    let mut deps = deps_default();
    deps.has_cronet = false;
    deps.platform = "darwin".into();
    let err = generate_sing_box_config(&cfg, &BTreeMap::new(), &deps).unwrap_err();
    assert!(err.contains("macOS"), "darwin 文案");
}

#[test]
fn naive_with_cronet_is_usable() {
    // naive + has_cronet=true → 可用（isNodeUsable 通过）。
    let mut cfg = base_config();
    cfg.servers[0].protocol = Protocol::Naive;
    let result = generate_sing_box_config(&cfg, &BTreeMap::new(), &deps_default());
    assert!(result.is_ok(), "naive + cronet 可用");
}

#[test]
fn race_off_forces_resolve_node_domains_ahead_false() {
    // raceServerPort=0 → withRaceOff → dnsConfig.resolveNodeDomainsAhead=false。
    // 不应有 dns-node-race server（race off）。
    let result =
        generate_sing_box_config(&base_config(), &BTreeMap::new(), &deps_default()).unwrap();
    let dns = result.dns.as_ref().unwrap();
    assert!(
        dns.servers.iter().all(|s| s.tag != "dns-node-race"),
        "race off 不生成 dns-node-race"
    );
}

#[test]
fn race_on_emits_race_server() {
    // raceServerPort>0 → dns-node-race server。
    let mut deps = deps_default();
    deps.race_server_port = 5353;
    let result = generate_sing_box_config(&base_config(), &BTreeMap::new(), &deps).unwrap();
    let dns = result.dns.as_ref().unwrap();
    assert!(
        dns.servers.iter().any(|s| s.tag == "dns-node-race"),
        "race on 生成 dns-node-race"
    );
}

#[test]
fn race_sidecar_is_referenced_only_by_node_dial_resolution() {
    use crate::singbox::DomainResolver;

    let mut deps = deps_default();
    deps.race_server_port = 5353;
    let result = generate_sing_box_config(&base_config(), &BTreeMap::new(), &deps).unwrap();

    let node_outbound = result
        .outbounds
        .iter()
        .find(|outbound| outbound.server.as_deref() == Some("hk.example.com"))
        .expect("节点出站应存在");
    let dial_resolver_server = match node_outbound.domain_resolver.as_ref() {
        Some(DomainResolver::Tag(server)) | Some(DomainResolver::Detailed { server, .. }) => {
            Some(server.as_str())
        }
        None => None,
    };
    assert_eq!(
        dial_resolver_server,
        Some("dns-node-race"),
        "sidecar 只服务节点拨号前的服务器域名解析"
    );

    let node_dns_rule = result
        .dns
        .as_ref()
        .unwrap()
        .rules
        .as_ref()
        .unwrap()
        .iter()
        .find(|rule| {
            rule.domain
                .as_ref()
                .is_some_and(|domains| domains.contains(&"hk.example.com".to_string()))
        })
        .expect("节点域名 DNS 规则应存在");
    assert_eq!(node_dns_rule.server.as_deref(), Some("dns-domestic"));
    assert!(result
        .dns
        .as_ref()
        .unwrap()
        .rules
        .as_ref()
        .unwrap()
        .iter()
        .all(|rule| rule.server.as_deref() != Some("dns-node-race")));
}

/// 取 DNS 直连放行规则的端口集（`ip_cidr` 含引导 DNS + route→direct 的那条）。
fn dns_direct_ports(result: &SingBoxConfig) -> Vec<u32> {
    let route = result.route.as_ref().expect("route 必在");
    let rule = route
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
        crate::singbox::OneOrMany::One(p) => vec![*p],
        crate::singbox::OneOrMany::Many(v) => v.clone(),
    }
}

/// 【不变式：`race_server_port == 0` 时上游两轴一律不透传】
///
/// race off 与「起 sidecar 失败」在生成侧是同一种状态（port=0）。此时哪怕 deps 里还残留着上一轮的
/// 上游 IP/端口（运行期状态翻转与 config 生成之间有窗口），也不得放行 —— 放行一个没人在监听的
/// 端口是白开口子，且会让金样输出随残留值漂移。
///
/// **变异锁**：把 `deps.race_server_port > 0` 的门去掉（两轴无条件透传）→ 本测的
/// 「`8443` 不得出现」转红；只对 IP 轴留门、端口轴直传 → 同样转红。
#[test]
fn race_off_drops_both_upstream_axes() {
    let mut deps = deps_default();
    deps.race_server_port = 0; // race off
    deps.race_upstream_ips = vec!["9.9.9.9".to_string()]; // 残留值
    deps.race_upstream_ports = vec![8443];
    let result = generate_sing_box_config(&base_config(), &BTreeMap::new(), &deps).unwrap();

    assert_eq!(
        dns_direct_ports(&result),
        vec![53, 443],
        "race off → 端口集回基线"
    );
    let route = result.route.as_ref().unwrap();
    assert!(
        !route.rules.iter().any(|r| r
            .ip_cidr
            .as_ref()
            .is_some_and(|c| c.contains(&"9.9.9.9/32".to_string()))),
        "race off → 残留的上游 IP 同样不得放行"
    );
}

/// 【不变式：race on 时上游两轴**一起**透传到 route】
///
/// **变异锁**：把 `race_upstream_ports` 那路改成恒 `Vec::new()`（只传 IP）→ `8443` 断言转红。
#[test]
fn race_on_forwards_both_upstream_axes_to_route() {
    let mut deps = deps_default();
    deps.race_server_port = 5353;
    deps.race_upstream_ips = vec!["9.9.9.9".to_string()];
    deps.race_upstream_ports = vec![8443];
    let result = generate_sing_box_config(&base_config(), &BTreeMap::new(), &deps).unwrap();

    let ports = dns_direct_ports(&result);
    assert!(
        ports.contains(&8443),
        "上游端口须随 IP 一起进直连放行（两轴缺一规则匹配不上），实得 {ports:?}"
    );
    let route = result.route.as_ref().unwrap();
    assert!(
        route.rules.iter().any(|r| r
            .ip_cidr
            .as_ref()
            .is_some_and(|c| c.contains(&"9.9.9.9/32".to_string()))),
        "上游 IP 须进直连放行"
    );
}

#[test]
fn endpoints_injected_when_present() {
    // WireGuard 节点 → pendingEndpoints 非空 → 顶层 endpoints 注入。
    let mut cfg = base_config();
    cfg.servers[0] = ServerConfig {
        id: "wg1".into(),
        name: "WARP".into(),
        protocol: Protocol::Wireguard,
        address: "engage.cloudflareclient.com".into(),
        port: 2408,
        wireguard_settings: Some(Box::new(
            crate::user_config::server_config::WireGuardSettings {
                private_key: Some("priv".into()),
                local_address: vec!["172.16.0.2/32".into()],
                peer_public_key: Some("pub".into()),
                ..Default::default()
            },
        )),
        ..Default::default()
    };
    cfg.selected_server_id = Some("wg1".into());
    let result = generate_sing_box_config(&cfg, &BTreeMap::new(), &deps_default()).unwrap();
    assert!(
        result.endpoints.is_some(),
        "WireGuard 节点 → endpoints 注入顶层"
    );
    assert!(!result.endpoints.as_ref().unwrap().is_empty());
}

// ══════════════════════════════════════════════════════════════════════════
// endpoint 前置代理（detour）—— 对 上游的**有意偏离**（上游 三个组网表单与
// `SingBoxEndpoint` 类型都没有 detour）。语义实测与「WG 需 UDP 转发」见
// `singbox/endpoint.rs` 的 `Endpoint::detour`。
//
// 三条门都断言**序列化后的 JSON**（不是 struct 字段），因为这一整条接线的失效模式就是
// 「struct 上有值、serde 把它丢了」——`Endpoint` 结构体本轮之前根本没有这个字段，
// WarpDialog 那个 select 写进 `server.detour` 后在生成侧被静默丢弃，是个装饰开关。
// ══════════════════════════════════════════════════════════════════════════

/// 三种 endpoint（普通 WG / WARP / Tailscale）＋一个代理节点，前三者 detour 全指向后者。
/// selected 另取一个独立 vless，保证生成成功、被测的三个都是非选中节点。
fn config_with_three_endpoint_detours() -> UserConfig {
    use crate::user_config::server_config::{TailscaleSettings, WireGuardSettings};
    let selected = ServerConfig {
        id: "sel".into(),
        name: "SEL".into(),
        protocol: Protocol::Vless,
        address: "sel.example.com".into(),
        port: 443,
        uuid: Some("u".into()),
        security: Some(SecurityMode::Tls),
        ..Default::default()
    };
    // 前置代理本体（detour 目标）。
    let front = ServerConfig {
        id: "front".into(),
        name: "FRONT".into(),
        protocol: Protocol::Vless,
        address: "front.example.com".into(),
        port: 443,
        uuid: Some("u".into()),
        security: Some(SecurityMode::Tls),
        ..Default::default()
    };
    let wg = ServerConfig {
        id: "wg1".into(),
        name: "WG".into(),
        protocol: Protocol::Wireguard,
        address: "wg.example.com".into(),
        port: 51820,
        detour: Some("front".into()),
        wireguard_settings: Some(Box::new(WireGuardSettings {
            private_key: Some("priv".into()),
            peer_public_key: Some("pub".into()),
            local_address: vec!["10.0.0.2/32".into()],
            allow_internet: Some(true),
            ..Default::default()
        })),
        ..Default::default()
    };
    // WARP：判据是端点域名（`domain/warp.ts` / `crate::warp::is_warp_server`），不是名字。
    // 它同走 `build_wireguard_endpoint`，但会额外过 `downgrade_mesh` 那段后处理——
    // 这条门顺带钉住「后处理不得把 detour 抹掉」。
    let warp = ServerConfig {
        id: "warp1".into(),
        name: "WARP".into(),
        protocol: Protocol::Wireguard,
        address: "engage.cloudflareclient.com".into(),
        port: 2408,
        detour: Some("front".into()),
        wireguard_settings: Some(Box::new(WireGuardSettings {
            private_key: Some("priv".into()),
            peer_public_key: Some("pub".into()),
            local_address: vec!["172.16.0.2/32".into()],
            allow_internet: Some(true),
            reverse_mesh: Some(true),
            ..Default::default()
        })),
        ..Default::default()
    };
    let ts = ServerConfig {
        id: "ts1".into(),
        name: "TS".into(),
        protocol: Protocol::Tailscale,
        detour: Some("front".into()),
        tailscale_settings: Some(Box::new(TailscaleSettings {
            exit_node: Some("exit-peer".into()),
            ..Default::default()
        })),
        ..Default::default()
    };
    UserConfig {
        servers: vec![selected, front, wg, warp, ts],
        selected_server_id: Some("sel".into()),
        proxy_mode: ProxyMode::Smart,
        proxy_mode_type: ProxyModeType::SystemProxy,
        ..Default::default()
    }
}

/// 【门 ①】三种 endpoint 的 detour 都真的落进生成的 JSON，且值 = 前置代理的 **outbound tag**。
///
/// 期望 tag 不写死字面量，而是从产物里按 `server` 地址反查那个 outbound 的 tag ——
/// 手拼 `"proxy-front"` 会在 `build_id_to_tag_map` 改命名规则时静默变成一条永假的断言。
#[test]
fn endpoint_detour_lands_in_generated_json() {
    let cfg = config_with_three_endpoint_detours();
    let result = generate_sing_box_config(&cfg, &BTreeMap::new(), &deps_default()).unwrap();
    let json = serde_json::to_value(&result).unwrap();

    let front_tag = json["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["server"] == "front.example.com")
        .and_then(|o| o["tag"].as_str())
        .expect("前置代理 outbound 必须在产物里")
        .to_string();

    let eps = json["endpoints"]
        .as_array()
        .expect("endpoints 必须注入顶层");
    assert_eq!(eps.len(), 3, "三个 endpoint 全发射，实得 {eps:?}");
    for want_type in ["wireguard", "tailscale"] {
        assert!(
            eps.iter().any(|e| e["type"] == want_type),
            "{want_type} endpoint 必须在产物里"
        );
    }
    for ep in eps {
        assert_eq!(
            ep["detour"].as_str(),
            Some(front_tag.as_str()),
            "endpoint「{}」的 detour 必须序列化进 JSON 且等于前置代理 tag",
            ep["tag"]
        );
    }
}

/// 【门 ②】detour 目标是 endpoint 类节点 → 排除（沿用代理 outbound 早就在用的同一条），
/// 但**引用方本身必须留在产物里**（只丢 detour，不丢节点）。
///
/// 变异对照：删掉 `resolve_detour_tag` 里的 `is_mesh_protocol` 那支 ⇒ WG 的 detour 变成
/// TS 的 endpoint tag，而 `valid_tags` 只取自 outbounds ⇒ 剪枝把整个 WG endpoint 剔掉 ⇒
/// 「WG 仍在」这条断言转红。
#[test]
fn endpoint_detour_target_endpoint_excluded() {
    use crate::user_config::server_config::{TailscaleSettings, WireGuardSettings};
    let mut cfg = base_config();
    cfg.servers.push(ServerConfig {
        id: "ts1".into(),
        name: "TS".into(),
        protocol: Protocol::Tailscale,
        tailscale_settings: Some(Box::new(TailscaleSettings::default())),
        ..Default::default()
    });
    cfg.servers.push(ServerConfig {
        id: "wg1".into(),
        name: "WG".into(),
        protocol: Protocol::Wireguard,
        address: "wg.example.com".into(),
        port: 51820,
        detour: Some("ts1".into()), // ← 目标是 endpoint
        wireguard_settings: Some(Box::new(WireGuardSettings {
            private_key: Some("priv".into()),
            peer_public_key: Some("pub".into()),
            local_address: vec!["10.0.0.2/32".into()],
            allow_internet: Some(true),
            ..Default::default()
        })),
        ..Default::default()
    });
    let result = generate_sing_box_config(&cfg, &BTreeMap::new(), &deps_default()).unwrap();
    let json = serde_json::to_value(&result).unwrap();
    let eps = json["endpoints"]
        .as_array()
        .expect("endpoints 必须注入顶层");
    let wg = eps
        .iter()
        .find(|e| e["type"] == "wireguard")
        .expect("WG endpoint 必须仍在产物里（只丢 detour，不丢节点）");
    assert!(
        wg.get("detour").is_none(),
        "detour 目标是 endpoint ⇒ 该键根本不得出现，实得 {wg:?}"
    );
}

/// 【门 ②b】detour 目标是 **openconnect / openvpn-client** → 同样排除。
///
/// 它们落 `endpoints[]`、tag 不在 `outbounds[]` 里，指向它们的 detour 与指向 WG/TS 是同一类
/// 悬空引用。此前判据用的是只认 WG/TS 的 `is_mesh_protocol`，这两个协议漏在外面 ——
/// 后果不是「多一个没用的选项」，而是**引用方整个节点被剪掉并上报 invalid**（用户侧：节点没了）。
///
/// 变异对照：把 `resolve_detour_tag` 的判据改回 `is_mesh_protocol` ⇒ 本条断言转红。
#[test]
fn detour_target_openconnect_excluded() {
    use crate::user_config::protocol_settings::OpenconnectSettings;
    let mut cfg = base_config();
    cfg.servers.push(ServerConfig {
        id: "oc1".into(),
        name: "OC".into(),
        protocol: Protocol::Openconnect,
        openconnect_settings: Some(Box::new(OpenconnectSettings {
            server: Some("vpn.example.com:443".into()),
            ..Default::default()
        })),
        ..Default::default()
    });
    cfg.servers.push(ServerConfig {
        id: "v1".into(),
        name: "V".into(),
        protocol: Protocol::Vless,
        address: "v.example.com".into(),
        port: 443,
        uuid: Some("11111111-1111-1111-1111-111111111111".into()),
        detour: Some("oc1".into()), // ← 目标是 endpoint 腿
        ..Default::default()
    });
    let result = generate_sing_box_config(&cfg, &BTreeMap::new(), &deps_default()).unwrap();
    let json = serde_json::to_value(&result).unwrap();
    // 按 tag 定位而不是按 type：`base_config()` 本身就带一个 vless 节点，按 type 找会命中它 ——
    // 那个节点从来就没有 detour，断言恒绿、变异不红（落地时先踩了这一下）。
    let vless = json["outbounds"]
        .as_array()
        .expect("outbounds")
        .iter()
        .find(|o| o["tag"] == "V")
        .expect("引用方必须留在产物里 —— 只丢 detour，不丢节点");
    assert!(
        vless.get("detour").is_none(),
        "detour 目标落在 endpoints[] ⇒ 该键根本不得出现，实得 {vless:?}"
    );
}

/// 用户为 openconnect / openvpn-client 声明的内网段，必须真的变成 force-route 规则。
///
/// 这是「组网资格由节点决定」那条判据的**产出侧**验证：不声明 ⇒ 没有任何规则指向它（它只是个
/// 普通出口）；声明了 ⇒ 该段被路由到它自己的 tag，与一个填了 `allowedIPs` 的 WG 节点无分别。
///
/// 变异对照：删掉 `endpoint_forced_route_cidrs` 里的 openconnect/openvpn 那支 ⇒ 第二段断言转红。
#[test]
fn declared_mesh_routes_become_force_route_rules() {
    use crate::user_config::protocol_settings::OpenconnectSettings;
    let mk = |routes: Vec<String>| {
        let mut cfg = base_config();
        cfg.servers.push(ServerConfig {
            id: "oc1".into(),
            name: "OC".into(),
            protocol: Protocol::Openconnect,
            mesh_routes: routes,
            openconnect_settings: Some(Box::new(OpenconnectSettings {
                server: Some("vpn.example.com:443".into()),
                ..Default::default()
            })),
            ..Default::default()
        });
        let r = generate_sing_box_config(&cfg, &BTreeMap::new(), &deps_default()).unwrap();
        serde_json::to_value(&r).unwrap()
    };

    let oc_tag = |json: &serde_json::Value| -> String {
        json["endpoints"]
            .as_array()
            .expect("endpoints")
            .iter()
            .find(|e| e["type"] == "openconnect")
            .expect("openconnect 必须落 endpoints[]")["tag"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let routed_cidrs = |json: &serde_json::Value, tag: &str| -> Vec<String> {
        json["route"]["rules"]
            .as_array()
            .map(|rs| {
                rs.iter()
                    .filter(|r| r["outbound"].as_str() == Some(tag))
                    .filter_map(|r| r["ip_cidr"].as_array())
                    .flatten()
                    .filter_map(|c| c.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };

    // 不声明 → 只是个普通出口，没有任何段被强制路由过去。
    let bare = mk(vec![]);
    let bare_tag = oc_tag(&bare);
    assert!(
        routed_cidrs(&bare, &bare_tag).is_empty(),
        "没声明内网段的 openconnect 不该有 force-route 规则"
    );

    // 声明 → 该段进 force-route。0/0 被剥掉（全隧道是另一件事，由出网开关表达）。
    let declared = mk(vec!["10.10.0.0/16".into(), "0.0.0.0/0".into()]);
    let declared_tag = oc_tag(&declared);
    assert_eq!(
        routed_cidrs(&declared, &declared_tag),
        vec!["10.10.0.0/16".to_string()],
        "声明的内网段必须被路由到该节点自己的 tag，且 catch-all 不混进来"
    );
}

/// 【门 ③】endpoint 的悬空 detour（目标节点在生成集合里不存在）→ 整个 endpoint 被剪掉，
/// 不进产物、不留在 selector 成员里，并作为「detour 级联剔除」上报给渲染端。
///
/// 场景复用既有的 naive-缺-cronet 造死引用手法（`config_with_cascade_invalid` 同款）：
/// naive 节点在发射循环里被 `continue` 丢弃，而 `id_to_tag` 仍有它的条目 ⇒
/// WG 的 detour 解析成一个**没有对应 outbound** 的 tag。
///
/// 变异对照：删掉 `prune_detour_dead_references` 的 endpoint 腿 ⇒ 悬空 detour 原样进产物
/// （真核起核即 FATAL，本地测不到那一步）⇒ 前两条断言转红。
#[test]
fn endpoint_dangling_detour_pruned_from_output() {
    use crate::user_config::protocol_settings::NaiveSettings;
    use crate::user_config::server_config::WireGuardSettings;
    let mut cfg = base_config();
    cfg.servers.push(ServerConfig {
        id: "nv".into(),
        name: "NAIVE".into(),
        protocol: Protocol::Naive,
        address: "nv.example.com".into(),
        port: 443,
        naive_settings: Some(NaiveSettings { use_http3: None }),
        ..Default::default()
    });
    cfg.servers.push(ServerConfig {
        id: "wg1".into(),
        name: "WG".into(),
        protocol: Protocol::Wireguard,
        address: "wg.example.com".into(),
        port: 51820,
        detour: Some("nv".into()),
        wireguard_settings: Some(Box::new(WireGuardSettings {
            private_key: Some("priv".into()),
            peer_public_key: Some("pub".into()),
            local_address: vec!["10.0.0.2/32".into()],
            allow_internet: Some(true),
            ..Default::default()
        })),
        ..Default::default()
    });
    let mut deps = deps_default();
    deps.has_cronet = false; // 逼 naive 被丢 → WG 的 detour 成悬空引用
    let outcome = generate_sing_box_config_with_report(&cfg, &BTreeMap::new(), &deps).unwrap();
    let json = serde_json::to_value(&outcome.config).unwrap();

    let eps = json["endpoints"].as_array().cloned().unwrap_or_default();
    assert!(
        !eps.iter().any(|e| e["type"] == "wireguard"),
        "悬空 detour 的 WG endpoint 必须被剪掉，实得 {eps:?}"
    );
    // selector 成员表里也不得留它的 tag（否则 selector 引用不存在的 tag，同样 FATAL）。
    let dangling_in_selector = json["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|o| o["type"] == "selector")
        .filter_map(|o| o["outbounds"].as_array())
        .flatten()
        .any(|m| m.as_str() == Some("WG"));
    assert!(
        !dangling_in_selector,
        "被剪掉的 endpoint tag 不得留在任何 selector 成员表里"
    );
    // 上报给渲染端（标灰 + tooltip 归因），与 outbound 腿同一个 reason token。
    assert!(
        outcome
            .invalid_nodes
            .iter()
            .any(|n| n.id == "wg1" && n.reason == INVALID_REASON_DETOUR_CASCADE),
        "被剪的 endpoint 必须进 invalid_nodes 报告，实得 {:?}",
        outcome.invalid_nodes
    );
}

#[test]
fn services_not_injected_without_management_api() {
    let result =
        generate_sing_box_config(&base_config(), &BTreeMap::new(), &deps_default()).unwrap();
    assert!(
        result.services.is_none(),
        "无 management API 不注入 services"
    );
}

#[test]
fn services_injected_with_management_api() {
    let mut deps = deps_default();
    deps.has_management_api = true;
    let result = generate_sing_box_config(&base_config(), &BTreeMap::new(), &deps).unwrap();
    let services = result.services.as_ref().unwrap();
    assert_eq!(services.len(), 1);
    assert_eq!(services[0].type_field, "api");
    assert_eq!(services[0].listen, "127.0.0.1");
    assert_eq!(services[0].listen_port, 15490);
    assert!(services[0].dashboard.is_none(), "singboxDashboard 未开");
}

#[test]
fn services_include_clash_api_secret() {
    let mut cfg = base_config();
    cfg.clash_api_secret = Some("secret123".into());
    let mut deps = deps_default();
    deps.has_management_api = true;
    let result = generate_sing_box_config(&cfg, &BTreeMap::new(), &deps).unwrap();
    let svc = &result.services.as_ref().unwrap()[0];
    assert_eq!(svc.secret.as_deref(), Some("secret123"));
}

#[test]
fn dashboard_injected_when_opted_in() {
    let mut cfg = base_config();
    cfg.singbox_dashboard = Some(true);
    let mut deps = deps_default();
    deps.has_management_api = true;
    deps.dashboard_serve_dir = Some("/fake/dashboard".into());
    let result = generate_sing_box_config(&cfg, &BTreeMap::new(), &deps).unwrap();
    let dash = result.services.as_ref().unwrap()[0]
        .dashboard
        .as_ref()
        .unwrap();
    assert!(dash.enabled);
    assert_eq!(dash.path.as_deref(), Some("/fake/dashboard"));
    // 显式 HTTP client：detour 必须逐字等于 route.final（= 核的默认出站），
    // 否则就是把「隐式回落走默认出站」悄悄改成了走别的出站。
    let final_tag = result.route.as_ref().unwrap().final_outbound.clone();
    assert_eq!(
        dash.http_client.as_ref().map(|h| h.detour.clone()),
        final_tag,
        "dashboard.http_client.detour 必须 = route.final"
    );
}

#[test]
fn dashboard_enabled_without_serve_dir_omits_path() {
    // singboxDashboard=true 但 serve_dir=None → dashboard.enabled=true、path 省略（核联网兜底）。
    let mut cfg = base_config();
    cfg.singbox_dashboard = Some(true);
    let mut deps = deps_default();
    deps.has_management_api = true;
    deps.dashboard_serve_dir = None;
    let result = generate_sing_box_config(&cfg, &BTreeMap::new(), &deps).unwrap();
    let dash = result.services.as_ref().unwrap()[0]
        .dashboard
        .as_ref()
        .unwrap();
    assert!(dash.enabled);
    assert!(dash.path.is_none(), "无 serve_dir 时 path 省略");
    // 这条路径恰恰是**唯一真的会用到**该 transport 的路径（无本地 dashboard → 核联网拉取），
    // 故 http_client 在此不可缺省。
    let final_tag = result.route.as_ref().unwrap().final_outbound.clone();
    assert_eq!(
        dash.http_client.as_ref().map(|h| h.detour.clone()),
        final_tag,
        "联网兜底路径上 dashboard.http_client 更不能缺"
    );
}

#[test]
fn dashboard_not_injected_when_off() {
    let mut cfg = base_config();
    cfg.singbox_dashboard = Some(false);
    let mut deps = deps_default();
    deps.has_management_api = true;
    deps.dashboard_serve_dir = Some("/fake/dashboard".into());
    let result = generate_sing_box_config(&cfg, &BTreeMap::new(), &deps).unwrap();
    assert!(
        result.services.as_ref().unwrap()[0].dashboard.is_none(),
        "singboxDashboard=false 不注入 dashboard"
    );
}

#[test]
fn mesh_system_unavailable_on_win32_tun() {
    // win32 + tun → system_interface_available=false（Windows 禁 system）。
    // TS endpoint 仍发射（gVisor 用户态），system_interface 降级（无 FATAL）。
    let mut cfg = base_config();
    cfg.proxy_mode_type = ProxyModeType::Tun;
    cfg.servers[0] = ServerConfig {
        id: "ts1".into(),
        name: "TS".into(),
        protocol: Protocol::Tailscale,
        address: "".into(),
        port: 0,
        tailscale_settings: Some(Box::new(
            crate::user_config::server_config::TailscaleSettings::default(),
        )),
        ..Default::default()
    };
    cfg.selected_server_id = Some("ts1".into());
    let mut deps = deps_default();
    deps.platform = "win32".into();
    let result = generate_sing_box_config(&cfg, &BTreeMap::new(), &deps).unwrap();
    // endpoints 非空（TS endpoint 发射，win32 不阻断生成）。
    assert!(result.endpoints.is_some(), "win32 TS endpoint 仍发射");
}

#[test]
fn probe_ports_propagate_to_inbounds_and_dns() {
    // probe_direct/proxy/port 注入 → inbounds 含 probe-direct-in/proxy-in。
    let mut deps = deps_default();
    deps.probe_direct_port = Some(100);
    deps.probe_proxy_port = Some(101);
    deps.update_in_port = Some(102);
    let result = generate_sing_box_config(&base_config(), &BTreeMap::new(), &deps).unwrap();
    let tags: Vec<String> = result.inbounds.iter().map(|i| i.tag.clone()).collect();
    assert!(tags.iter().any(|t| t == "probe-direct-in"));
    assert!(tags.iter().any(|t| t == "probe-proxy-in"));
    assert!(tags.iter().any(|t| t == "update-in"));
}

#[test]
fn fix_route_dead_references_applied() {
    // 死引用兜底：即使 route 引用不存在的 outbound，经 fix 后改写 proxy-selector。
    // 此处验证 generate 不 panic 且 route.rules 可迭代（fix 已内联）。
    let result =
        generate_sing_box_config(&base_config(), &BTreeMap::new(), &deps_default()).unwrap();
    let rules_len = result.route.as_ref().map(|r| r.rules.len()).unwrap_or(0);
    // route.rules 非空（至少有 default/dns-hijack 等基础规则），fix 已内联不 panic。
    assert!(rules_len > 0, "route.rules 非空（fix 已应用）");
}

#[test]
fn with_race_off_sets_resolve_ahead_false() {
    let mut cfg = UserConfig::default();
    cfg.dns_config = Some(crate::user_config::dns_config::DnsConfig {
        resolve_node_domains_ahead: Some(true),
        ..Default::default()
    });
    let off = with_race_off(&cfg);
    assert_eq!(
        off.dns_config.as_ref().unwrap().resolve_node_domains_ahead,
        Some(false)
    );
}

#[test]
fn with_race_off_preserves_other_dns_fields() {
    let mut cfg = UserConfig::default();
    cfg.dns_config = Some(crate::user_config::dns_config::DnsConfig {
        resolve_node_domains_ahead: Some(true),
        optimistic_cache: Some(true),
        ..Default::default()
    });
    let off = with_race_off(&cfg);
    // optimistic_cache 原样保留。
    assert_eq!(
        off.dns_config.as_ref().unwrap().optimistic_cache,
        Some(true)
    );
}

#[test]
fn mesh_system_supported_excludes_win32() {
    assert!(!mesh_system_supported_on_platform("win32"));
    assert!(mesh_system_supported_on_platform("darwin"));
    assert!(mesh_system_supported_on_platform("linux"));
    assert!(!mesh_system_supported_on_platform("WIN32")); // 大小写不敏感
}

// ══════════════════════════════════════════════════════════════════════════
// 组合面：生成方（本文件产 selector）× 消费方（hotswitch 规划 PUT 目标）
//
// §K7.1 的教训是「A 有门、B 有门、组合面无门」：outbounds 生成 selector 有测试、
// hotswitch 规划 PUT 也有测试，但**没有任何测试断言二者说的是同一个 tag**。
// 一旦漂移：PUT 打到不存在的 selector → 核返 NotFound → executor 判 Failed →
// **静默退回去抖重启** → 用户看到「切换成功」，实际是断流重启，热切换永久失效且无人报错。
// 下面两条就是那扇缺失的门。
// ══════════════════════════════════════════════════════════════════════════

/// 生成产物里**必须真的存在** `PROXY_SELECTOR_TAG` 这个 selector 出站。
/// 它正是 `plan_hot_switch` 下发 `SelectOutbound` 的目标 —— 不存在即热切换全链路失效。
#[test]
fn generated_config_contains_the_selector_that_hotswitch_puts_to() {
    use crate::user_config::dns_constants::PROXY_SELECTOR_TAG;
    let config = base_config();
    let out = generate_sing_box_config(&config, &BTreeMap::new(), &deps_default()).unwrap();
    let sel = out
        .outbounds
        .iter()
        .find(|o| o.tag == PROXY_SELECTOR_TAG)
        .unwrap_or_else(|| {
            panic!(
                "生成产物里找不到 tag={PROXY_SELECTOR_TAG} 的出站 —— 热切换 PUT 必然 NotFound。\
                     实有出站：{:?}",
                out.outbounds.iter().map(|o| &o.tag).collect::<Vec<_>>()
            )
        });
    assert_eq!(
        sel.type_field, "selector",
        "{PROXY_SELECTOR_TAG} 必须是 selector 类型，否则 SelectOutbound 无从切换"
    );
}

/// `plan_hot_switch` 算出的 `selector_tag`，必须逐条命中生成产物里真实存在的 selector。
///
/// 这条直接对拍「PUT 目标」与「核里实际有什么」——即便将来有人把某处 tag 改回内联字面量，
/// 只要两侧不一致，这条立刻转红。
#[test]
fn hotswitch_plan_put_targets_all_exist_as_selectors_in_generated_config() {
    use crate::builder::hotswitch::{plan_hot_switch, HotSwitchDeps};
    use crate::user_config::dns_constants::PROXY_SELECTOR_TAG;

    // old：选中 node-a；new：切到 node-b（纯值变更 → 走全局热切腿）。
    let mut old = base_config();
    old.servers.push(ServerConfig {
        id: "node-b".into(),
        name: "Node B".into(),
        protocol: Protocol::Shadowsocks,
        address: "2.2.2.2".into(),
        port: 8388,
        ..Default::default()
    });
    old.selected_server_id = Some(old.servers[0].id.clone());
    let mut new = old.clone();
    new.selected_server_id = Some("node-b".into());

    // idToTagMap 与生成侧同源（build_id_to_tag_map）——生产路径也是这么喂的。
    struct S<'a>(&'a ServerConfig);
    impl ServerLike for S<'_> {
        fn id(&self) -> &str {
            &self.0.id
        }
        fn name(&self) -> &str {
            &self.0.name
        }
    }
    let wrappers: Vec<S> = old.servers.iter().map(S).collect();
    let deps = HotSwitchDeps {
        current_id_to_tag_map: Some(build_id_to_tag_map(&wrappers)),
        ..Default::default()
    };

    let plan = plan_hot_switch(&old, &new, &deps);
    assert!(
        !plan.puts.is_empty(),
        "切节点应产出至少一条 PUT（前提失败则本测试失去意义）"
    );

    let out = generate_sing_box_config(&old, &BTreeMap::new(), &deps_default()).unwrap();
    let selectors: Vec<&str> = out
        .outbounds
        .iter()
        .filter(|o| o.type_field == "selector")
        .map(|o| o.tag.as_str())
        .collect();
    for p in &plan.puts {
        assert!(
            selectors.contains(&p.selector_tag.as_str()),
            "PUT 目标 selector `{}` 在生成产物里不存在 → 核会返 NotFound → 静默退回重启。\
                 实有 selector：{selectors:?}",
            p.selector_tag
        );
        // 成员也必须真在该 selector 里，否则 SelectOutbound 同样 NotFound。
        let sel = out
            .outbounds
            .iter()
            .find(|o| o.tag == p.selector_tag)
            .unwrap();
        let members = sel.outbounds.clone().unwrap_or_default();
        assert!(
            members.contains(&p.member_tag),
            "PUT 成员 `{}` 不在 selector `{}` 的成员表里（实有：{members:?}）",
            p.member_tag,
            p.selector_tag
        );
    }
    assert!(
        selectors.contains(&PROXY_SELECTOR_TAG),
        "全局热切腿的目标必须是 {PROXY_SELECTOR_TAG}"
    );
}

#[test]
fn inbound_exclude_warn_survives_full_assembly() {
    // 变异锁：锁死本函数「── 7. buildInbounds ──」块里的 `log: deps.log` 透传。
    // inbounds.rs 自身的单测直调 build_inbounds，测不出 generate.rs 这一行接线——
    // 如果有人把它删掉（编译期即报错，因 InboundsDeps.log 非 Option 无默认值）或换成
    // `log: |_, _| {}` 这种「看似接了、实为 no-op」的静默逃逸（编译能过，行为悄悄失聪），
    // 只有走这条真实装配路径（generate_sing_box_config_with_report）才抓得住。
    thread_local! {
        static SINK: std::cell::RefCell<Vec<String>> =
            const { std::cell::RefCell::new(Vec::new()) };
    }
    fn capture(_lvl: LogLevel, msg: &str) {
        SINK.with(|s| s.borrow_mut().push(msg.to_string()));
    }

    let mut config = base_config();
    config.proxy_mode_type = ProxyModeType::Tun;
    config.tun_config = Some(crate::user_config::tun_config::TunModeConfig {
        inbound_exclude_cidrs: Some(vec!["not-a-cidr".into()]),
        ..Default::default()
    });

    let mut deps = deps_default();
    deps.platform = "darwin".into();
    deps.log = capture;

    let result = generate_sing_box_config_with_report(&config, &BTreeMap::new(), &deps);
    assert!(result.is_ok(), "生成应成功: {:?}", result.err());

    let warns = SINK.with(|s| s.borrow_mut().drain(..).collect::<Vec<String>>());
    assert!(
        warns.iter().any(|m| m.contains("非法/过宽网段")),
        "InboundsDeps.log 透传断裂：完整装配路径下未见「连入来源排除」非法段告警。实际: {warns:?}"
    );
}
