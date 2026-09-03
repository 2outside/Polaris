use super::*;
use crate::user_config::server_config::{
    Protocol, ServerConfig, TailscaleSettings, WireGuardSettings,
};

fn wg_server(id: &str, allowed: &[&str], allow_internet: Option<bool>) -> ServerConfig {
    ServerConfig {
        id: id.into(),
        name: id.into(),
        protocol: Protocol::Wireguard,
        address: "1.2.3.4".into(),
        port: 443,
        wireguard_settings: Some(Box::new(WireGuardSettings {
            allowed_ips: allowed.iter().map(|s| s.to_string()).collect(),
            allow_internet,
            ..Default::default()
        })),
        ..Default::default()
    }
}

fn ts_server(id: &str, exit_node: Option<&str>, routes: &[&str]) -> ServerConfig {
    ServerConfig {
        id: id.into(),
        name: id.into(),
        protocol: Protocol::Tailscale,
        tailscale_settings: Some(Box::new(TailscaleSettings {
            exit_node: exit_node.map(String::from),
            routes: routes.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        })),
        ..Default::default()
    }
}

#[test]
fn wg_forced_route_strips_catch_all() {
    let s = wg_server("w1", &["10.0.0.0/24", "0.0.0.0/0"], Some(true));
    assert_eq!(
        endpoint_forced_route_cidrs(&s),
        vec!["10.0.0.0/24".to_string()]
    );
}

#[test]
fn ts_forced_route_includes_tailnet() {
    let s = ts_server("t1", None, &["192.168.10.0/24"]);
    let cidrs = endpoint_forced_route_cidrs(&s);
    assert!(cidrs.contains(&TAILNET_CGNAT.to_string()));
    assert!(cidrs.contains(&TAILNET_ULA_V6.to_string()));
    assert!(cidrs.contains(&"192.168.10.0/24".to_string()));
}

#[test]
fn mesh_allows_internet_works() {
    assert!(mesh_allows_internet(&wg_server(
        "w",
        &["10.0.0.0/24"],
        Some(true)
    )));
    assert!(!mesh_allows_internet(&wg_server(
        "w",
        &["10.0.0.0/24"],
        Some(false)
    )));
    assert!(mesh_allows_internet(&wg_server(
        "w",
        &["10.0.0.0/24"],
        None
    ))); // 缺省 true
    assert!(mesh_allows_internet(&ts_server("t", Some("exit"), &[])));
    assert!(!mesh_allows_internet(&ts_server("t", None, &[])));
    assert!(!mesh_allows_internet(&ts_server("t", Some("  "), &[])));
}

#[test]
fn warp_ignores_legacy_custom_route_fields() {
    let mut s = wg_server("warp", &["10.0.0.0/24"], Some(false));
    s.address = "engage.cloudflareclient.com".into();
    assert!(mesh_allows_internet(&s), "WARP 恒为云出口");
    assert!(endpoint_forced_route_cidrs(&s).is_empty());
    assert_eq!(
        wireguard_peer_allowed_ips(&s),
        Some(
            FULL_TUNNEL_CIDRS
                .iter()
                .map(|cidr| cidr.to_string())
                .collect()
        )
    );
}

#[test]
fn force_route_always_on() {
    let s = wg_server("w", &["10.0.0.0/24"], None); // alwaysRoute 缺省 true
    let targeted = BTreeSet::new();
    assert!(should_force_route_subnets(&s, None, &targeted));
}

#[test]
fn force_route_off_engaged_by_selection() {
    let mut s = wg_server("w", &["10.0.0.0/24"], None);
    s.wireguard_settings.as_mut().unwrap().always_route_subnets = Some(false);
    let targeted = BTreeSet::new();
    assert!(!should_force_route_subnets(&s, Some("other"), &targeted));
    assert!(should_force_route_subnets(&s, Some("w"), &targeted)); // 选中
}

#[test]
fn force_route_off_engaged_by_rule() {
    let mut s = wg_server("w", &["10.0.0.0/24"], None);
    s.wireguard_settings.as_mut().unwrap().always_route_subnets = Some(false);
    let mut targeted = BTreeSet::new();
    targeted.insert("w".into());
    assert!(should_force_route_subnets(&s, None, &targeted));
}

#[test]
fn collect_targeted_from_rules() {
    use crate::user_config::rule::{CombineMode, Rule, RuleType};
    let rules = vec![
        Rule {
            id: "r1".into(),
            type_field: RuleType::Domain,
            values: vec!["a.com".into()],
            conditions: None,
            combine_mode: None,
            effects: None,
            action: RuleAction::Proxy,
            enabled: true,
            bypass_fakeip: None,
            target_server_id: Some("s2".into()),
            remarks: None,
            tls_spoof: None,
            tls_spoof_method: None,
        },
        Rule {
            id: "r2".into(),
            type_field: RuleType::Domain,
            values: vec!["b.com".into()],
            conditions: None,
            combine_mode: Some(CombineMode::And),
            effects: None,
            action: RuleAction::Direct, // 非 proxy，不含
            enabled: true,
            bypass_fakeip: None,
            target_server_id: Some("s3".into()),
            remarks: None,
            tls_spoof: None,
            tls_spoof_method: None,
        },
    ];
    let ids = collect_rule_targeted_server_ids(&rules);
    assert!(ids.contains("s2"));
    assert!(!ids.contains("s3")); // direct 不算
}

#[test]
fn mesh_forced_route_union() {
    let servers = [
        wg_server("w1", &["10.0.0.0/24"], None),
        wg_server("w2", &["10.0.0.0/24", "172.16.0.0/24"], None), // 10.0 重复
    ];
    let cidrs = mesh_forced_route_cidrs(&servers);
    assert_eq!(cidrs.len(), 2); // 去重
    assert!(cidrs.contains(&"10.0.0.0/24".to_string()));
    assert!(cidrs.contains(&"172.16.0.0/24".to_string()));
}

#[test]
fn catch_all_detection() {
    assert!(has_catch_all(&["0.0.0.0/0".into()]));
    assert!(has_catch_all(&["::/0".into(), "10.0.0.0/8".into()]));
    assert!(!has_catch_all(&["10.0.0.0/8".into()]));
    assert_eq!(
        strip_catch_all(&["0.0.0.0/0".into(), "10.0.0.0/8".into()]),
        vec!["10.0.0.0/8".to_string()]
    );
}

#[test]
fn referenced_ids_includes_selected_and_endpoint() {
    use crate::user_config::app_config::UserConfig;
    let mut config = UserConfig::default();
    config.servers = vec![
        ServerConfig {
            id: "s1".into(),
            name: "普通节点".into(),
            protocol: Protocol::Shadowsocks,
            address: "1.1.1.1".into(),
            port: 443,
            ..Default::default()
        },
        wg_server("wg1", &["10.0.0.0/24"], None),
    ];
    config.selected_server_id = Some("s1".into());
    let refs = referenced_server_ids(&config);
    // s1 选中 + wg1 是 endpoint（保守纳入）
    assert!(refs.contains("s1"));
    assert!(refs.contains("wg1"));
}

#[test]
fn referenced_ids_detour_transitive_closure() {
    use crate::user_config::app_config::UserConfig;
    // s1 经 s2 代理链（detour），s2 经 s3 → 全闭包 {s1,s2,s3}
    let mut s1 = ServerConfig {
        id: "s1".into(),
        name: "s1".into(),
        protocol: Protocol::Shadowsocks,
        address: "1.1.1.1".into(),
        port: 443,
        detour: Some("s2".into()),
        ..Default::default()
    };
    let mut s2 = ServerConfig {
        id: "s2".into(),
        name: "s2".into(),
        protocol: Protocol::Shadowsocks,
        address: "2.2.2.2".into(),
        port: 443,
        detour: Some("s3".into()),
        ..Default::default()
    };
    let s3 = ServerConfig {
        id: "s3".into(),
        name: "s3".into(),
        protocol: Protocol::Shadowsocks,
        address: "3.3.3.3".into(),
        port: 443,
        ..Default::default()
    };
    let config = UserConfig {
        servers: vec![s1.clone(), s2.clone(), s3],
        selected_server_id: Some("s1".into()),
        ..Default::default()
    };
    let refs = referenced_server_ids(&config);
    assert!(refs.contains("s1"));
    assert!(refs.contains("s2"));
    assert!(refs.contains("s3"));
    // 恢复（避免 borrow 问题，此处不再用）
    s1.detour = None;
    s2.detour = None;
}

#[test]
fn referenced_ids_direct_sentinel_excluded() {
    use crate::user_config::app_config::UserConfig;
    let config = UserConfig {
        servers: vec![ServerConfig {
            id: "s1".into(),
            name: "s1".into(),
            protocol: Protocol::Shadowsocks,
            address: "1.1.1.1".into(),
            port: 443,
            ..Default::default()
        }],
        selected_server_id: Some("__direct__".into()),
        ..Default::default()
    };
    let refs = referenced_server_ids(&config);
    // direct 哨兵剔除，s1 未被选中/规则引用 → 仅 endpoint 保守纳入（s1 非 endpoint）
    assert!(!refs.contains("__direct__"));
}

#[test]
fn referenced_ids_rule_target_included() {
    use crate::user_config::app_config::UserConfig;
    use crate::user_config::rule::{Rule, RuleAction, RuleType};
    let config = UserConfig {
        servers: vec![
            ServerConfig {
                id: "s1".into(),
                name: "s1".into(),
                protocol: Protocol::Shadowsocks,
                address: "1.1.1.1".into(),
                port: 443,
                ..Default::default()
            },
            ServerConfig {
                id: "s2".into(),
                name: "s2".into(),
                protocol: Protocol::Shadowsocks,
                address: "2.2.2.2".into(),
                port: 443,
                ..Default::default()
            },
        ],
        selected_server_id: Some("s1".into()),
        custom_rules: vec![Rule {
            id: "r1".into(),
            type_field: RuleType::Domain,
            values: vec!["example.com".into()],
            conditions: None,
            combine_mode: None,
            effects: None,
            action: RuleAction::Proxy,
            enabled: true,
            bypass_fakeip: None,
            target_server_id: Some("s2".into()),
            remarks: None,
            tls_spoof: None,
            tls_spoof_method: None,
        }],
        ..Default::default()
    };
    let refs = referenced_server_ids(&config);
    assert!(refs.contains("s1")); // 选中
    assert!(refs.contains("s2")); // 规则目标
}

#[test]
fn active_roots_follow_traffic_rules_sot_and_detour_to_physical_root() {
    use crate::user_config::proxy_mode::ProxyMode;
    use crate::user_config::rule::{
        AppRule, Rule, RuleAction, RuleEffects, RuleRouteEffect, RuleType,
    };

    let rule = |id: &str, target: &str| Rule {
        id: id.into(),
        type_field: RuleType::Domain,
        values: vec!["example.com".into()],
        action: RuleAction::Proxy,
        enabled: true,
        target_server_id: Some(target.into()),
        ..Default::default()
    };
    let mut child = ss("child", "2.2.2.2");
    child.detour = Some("root".into());
    let config = UserConfig {
        servers: vec![ss("selected", "1.1.1.1"), child, ss("root", "3.3.3.3")],
        selected_server_id: Some("selected".into()),
        proxy_mode: ProxyMode::Smart,
        // legacy 镜像故意指向 selected；一等 trafficRules 必须压过它。
        custom_rules: vec![rule("legacy", "selected")],
        traffic_rules: Some(vec![Rule {
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
            ..rule("traffic", "legacy-ignored")
        }]),
        ..Default::default()
    };

    assert_eq!(
        active_physical_root_ids(&config),
        BTreeSet::from(["root".to_string(), "selected".to_string()])
    );

    let app_targeted = UserConfig {
        servers: config.servers.clone(),
        selected_server_id: Some("selected".into()),
        proxy_mode: ProxyMode::Smart,
        app_routing_enabled: Some(true),
        app_rules: vec![AppRule {
            app_id: "browser".into(),
            action: RuleAction::Proxy,
            enabled: true,
            target_server_id: Some("child".into()),
        }],
        ..Default::default()
    };
    assert_eq!(
        active_physical_root_ids(&app_targeted),
        BTreeSet::from(["root".to_string(), "selected".to_string()]),
        "启用的 app rule 目标也必须沿 detour 收敛到物理根"
    );

    let app_disabled = UserConfig {
        app_routing_enabled: Some(false),
        ..app_targeted
    };
    assert_eq!(
        active_physical_root_ids(&app_disabled),
        BTreeSet::from(["selected".to_string()]),
        "关闭 app routing 后闲置目标不得继续阻断或触发重规划"
    );
}

#[test]
fn idle_plain_node_is_not_an_active_root_but_fallback_is_conservative() {
    let selected = UserConfig {
        servers: three_plain_nodes(),
        selected_server_id: Some("s1".into()),
        ..Default::default()
    };
    assert_eq!(
        active_physical_root_ids(&selected),
        BTreeSet::from(["s1".to_string()])
    );

    let fallback = UserConfig {
        selected_server_id: None,
        ..selected
    };
    assert_eq!(
        active_physical_root_ids(&fallback),
        BTreeSet::from(["s1".to_string(), "s2".to_string(), "s3".to_string()])
    );
}

// === selector default 兜底（proxy-selector 的 default 落到「非选中节点」）===

fn ss(id: &str, addr: &str) -> ServerConfig {
    ServerConfig {
        id: id.into(),
        name: id.into(),
        protocol: Protocol::Shadowsocks,
        address: addr.into(),
        port: 8388,
        ..Default::default()
    }
}

fn three_plain_nodes() -> Vec<ServerConfig> {
    vec![
        ss("s1", "1.1.1.1"),
        ss("s2", "2.2.2.2"),
        ss("s3", "3.3.3.3"),
    ]
}

/// 【常态不得被拖成恒重启】正常选中了一个必定被发射的普通代理节点 ⇒ 兜底不可能触发 ⇒
/// 引用集只含选中节点，未引用节点仍可 defer。
/// 本用例红 = 修复过度保守，把「正常选了节点」也拖成了「任何节点编辑都重启」。
#[test]
fn referenced_ids_normal_selection_stays_minimal() {
    use crate::user_config::app_config::UserConfig;
    let config = UserConfig {
        servers: three_plain_nodes(),
        selected_server_id: Some("s2".into()),
        ..Default::default()
    };
    let refs = referenced_server_ids(&config);
    assert!(!selector_default_may_fall_back(&config));
    assert_eq!(refs, ["s2".to_string()].into_iter().collect());
}

/// 【缺陷复现①：未选节点】`selectedServerId=None` ⇒ `build_outbounds`（outbounds.rs:262-271）
/// 的 `selected_tag` 是字面量 `"proxy"`，匹配不到任何节点 tag → default 落 `node_tags.first()`。
/// 那个节点承载**全部**代理流量，却不在任何一条播种里。
/// 本用例红 = 兜底节点又漏出引用集 → 编辑它会被判「未引用」走 defer 腿静默不重启。
#[test]
fn referenced_ids_without_selection_includes_all_nodes() {
    use crate::user_config::app_config::UserConfig;
    let config = UserConfig {
        servers: three_plain_nodes(),
        selected_server_id: None,
        ..Default::default()
    };
    assert!(selector_default_may_fall_back(&config));
    let refs = referenced_server_ids(&config);
    // 「哪个节点会被首先发射」取决于生成期跳过了谁（运行期能力），静态算不出 ⇒ 全部纳入。
    for id in ["s1", "s2", "s3"] {
        assert!(refs.contains(id), "{id} 未纳入引用集");
    }
}

/// 【缺陷复现②：悬空选中】选中 id 不在 servers 里（节点被删/订阅换了 id）⇒ id→tag 解析不到
/// → 同样落 `node_tags.first()` 兜底。
#[test]
fn referenced_ids_dangling_selection_includes_all_nodes() {
    use crate::user_config::app_config::UserConfig;
    let config = UserConfig {
        servers: three_plain_nodes(),
        selected_server_id: Some("ghost".into()),
        ..Default::default()
    };
    assert!(selector_default_may_fall_back(&config));
    let refs = referenced_server_ids(&config);
    for id in ["s1", "s2", "s3"] {
        assert!(refs.contains(id), "{id} 未纳入引用集");
    }
}

/// 选中 naive 时缺 libcronet 会被 generate 的 selected-server 前置门终止，库可用时则必定发射；
/// 两条腿都不允许 selector 静默落到其它节点。若把它重新当成 fallback，会把一次 H3 选择扩成
/// “全部订阅节点都可能承流”，进而让 TUN 逐目的路由规划无谓扫描全订阅。
#[test]
fn referenced_ids_selected_naive_stays_minimal() {
    use crate::user_config::app_config::UserConfig;
    let mut servers = three_plain_nodes();
    servers[1].protocol = Protocol::Naive;
    let config = UserConfig {
        servers,
        selected_server_id: Some("s2".into()),
        ..Default::default()
    };
    assert!(!selector_default_may_fall_back(&config));
    let refs = referenced_server_ids(&config);
    assert_eq!(refs, BTreeSet::from(["s2".to_string()]));
}

#[test]
fn selector_fallback_tracks_tailscale_control_url_gate() {
    use crate::user_config::app_config::UserConfig;

    let mut tailscale = ts_server("ts", None, &[]);
    tailscale.tailscale_settings.as_mut().unwrap().control_url = Some("https://100.64.0.1".into());
    let mut config = UserConfig {
        servers: vec![tailscale, ss("fallback", "2.2.2.2")],
        selected_server_id: Some("ts".into()),
        ..Default::default()
    };
    assert!(
        selector_default_may_fall_back(&config),
        "非法 control_url 会让选中 Tailscale 在发射期被剔除"
    );
    assert!(referenced_server_ids(&config).contains("fallback"));

    config.servers[0]
        .tailscale_settings
        .as_mut()
        .unwrap()
        .control_url = Some("https://control.example.com".into());
    assert!(!selector_default_may_fall_back(&config));
    assert_eq!(
        referenced_server_ids(&config),
        BTreeSet::from(["ts".to_string()])
    );
}

/// 【直连哨兵不触发全纳入】`__direct__` ⇒ default 恒 = `direct` 出站，没有节点承载
/// （outbounds.rs:262-263 的 `is_direct` 腿）⇒ 引用集不得被撑成全体。
#[test]
fn referenced_ids_direct_sentinel_no_blanket_inclusion() {
    use crate::user_config::app_config::UserConfig;
    let config = UserConfig {
        servers: three_plain_nodes(),
        selected_server_id: Some("__direct__".into()),
        ..Default::default()
    };
    assert!(!selector_default_may_fall_back(&config));
    assert!(referenced_server_ids(&config).is_empty());
}

/// 【WG 复用真判据】选中 WG 节点时，「会不会被发射」直接问 `build_wireguard_endpoint`：
/// 配置完整 ⇒ 必定发射（不触发兜底）；缺 privateKey ⇒ Err ⇒ 不发射 ⇒ 兜底可能触发。
/// 本用例红 = 判据与真正的发射腿漂移了。
#[test]
fn selector_fallback_tracks_wireguard_buildability() {
    use crate::user_config::app_config::UserConfig;
    let mut wg = wg_server("wg1", &["10.0.0.0/24"], Some(true));
    let s = wg.wireguard_settings.as_mut().unwrap();
    s.private_key = Some("k".into());
    s.peer_public_key = Some("p".into());
    s.local_address = vec!["10.0.0.2/32".into()];
    let mut config = UserConfig {
        servers: vec![wg.clone(), ss("s2", "2.2.2.2")],
        selected_server_id: Some("wg1".into()),
        ..Default::default()
    };
    assert!(
        !selector_default_may_fall_back(&config),
        "配置完整的 WG 必定发射"
    );
    assert!(!referenced_server_ids(&config).contains("s2"));

    config.servers[0]
        .wireguard_settings
        .as_mut()
        .unwrap()
        .private_key = None;
    assert!(
        selector_default_may_fall_back(&config),
        "缺 privateKey 的 WG 构建失败 → 不发射 → 兜底可能触发"
    );
    assert!(referenced_server_ids(&config).contains("s2"));
}

#[test]
fn custom_endpoint_carries_traffic_detects_keys() {
    use serde_json::json;
    // system 键命中
    assert!(custom_endpoint_carries_traffic(&json!({"system": true})));
    // allowed_ips 嵌套命中
    assert!(custom_endpoint_carries_traffic(&json!({
        "peers": [{"allowed_ips": ["0.0.0.0/0"]}]
    })));
    // 无语义键
    assert!(!custom_endpoint_carries_traffic(
        &json!({"tag": "x", "type": "wireguard"})
    ));
    // 数组递归
    assert!(custom_endpoint_carries_traffic(
        &json!([{"exit_node": true}])
    ));
}

/// OpenVPN 全隧道必须被判为承流 —— 语料取**真实可用**的 `openvpn-client` 端点
/// （对随包核 1.14.0-beta.12 跑 `sing-box check` rc=0 的形状：`tls` 必填，缺了报
/// `missing 'tls' options`），不是手捏一个只有目标键的空壳。
///
/// 变异靶：把 `redirect_gateway` 从 `CARRY_TRAFFIC_KEYS` 里删掉 → 第一条 assert 转红。
/// 这条**不能**只写「含 routes 的那份命中」——OpenVPN 表达全隧道的常见写法就是只给
/// `redirect_gateway: true` 而不写 `routes`，那正是原表漏掉的那一半。
#[test]
fn openvpn_full_tunnel_counts_as_carrying_traffic() {
    use serde_json::json;
    let ovpn = |extra: serde_json::Value| {
        let mut base = json!({
            "type": "openvpn-client",
            "server": "1.2.3.4",
            "server_port": 1194,
            "username": "u",
            "password": "p",
            "tls": { "certificate": ["-----BEGIN CERTIFICATE-----"] }
        });
        let map = base.as_object_mut().unwrap();
        for (k, v) in extra.as_object().unwrap() {
            map.insert(k.clone(), v.clone());
        }
        base
    };
    // 只给 redirect_gateway（不写 routes）—— 补键之前这条是 false
    assert!(custom_endpoint_carries_traffic(&ovpn(
        json!({"redirect_gateway": true})
    )));
    assert!(custom_endpoint_carries_traffic(&ovpn(
        json!({"redirect_private": true})
    )));
    assert!(custom_endpoint_carries_traffic(&ovpn(
        json!({"route_no_pull": true})
    )));
    // 不过度纳入：纯拨号型 openvpn-client（无任何路由语义键）仍判 false，
    // 否则「过度纳入只多一次重启」会退化成「每个 OpenVPN 节点必重启」。
    assert!(!custom_endpoint_carries_traffic(&ovpn(json!({}))));
    // openconnect 的路由语义键只有 system —— 原表已覆盖，这条钉住别在补键时把它漏掉。
    assert!(custom_endpoint_carries_traffic(&json!({
        "type": "openconnect", "server": "vpn.example.com:443",
        "username": "u", "password": "p", "flavor": "anyconnect", "system": true
    })));
    assert!(!custom_endpoint_carries_traffic(&json!({
        "type": "openconnect", "server": "vpn.example.com:443",
        "username": "u", "password": "p", "flavor": "anyconnect"
    })));
}

/// WG `reverseMesh:true` 的三态：普通 WG 放行 / WARP（带凭据）否决 / WARP（仅域名）否决。
///
/// 一个测试里放三条是**故意**的：把「否决」和「不过度否决」钉在同一处，
/// 免得后人只看到 WARP 那两条 assert 就把整条 WG 腿改成恒 false —— 那会让正常 WG 的
/// System 接入模式（子网路由 / 反向可达）整体失效，是个只有真机才暴露的静默回归。
#[test]
fn wg_reverse_mesh_system_vetoed_only_for_warp() {
    fn wg_reverse_mesh(address: &str, warp_device: bool) -> ServerConfig {
        ServerConfig {
            id: "w".into(),
            name: "w".into(),
            protocol: Protocol::Wireguard,
            address: address.into(),
            port: 2408,
            wireguard_settings: Some(Box::new(WireGuardSettings {
                reverse_mesh: Some(true),
                warp_device: warp_device.then(|| {
                    crate::user_config::protocol_settings::WarpDevice {
                        device_id: "d".into(),
                        token: "t".into(),
                    }
                }),
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    // 反向对照（**先写**）：普通 WG 的 System 接入模式必须照旧生效，否决不得收得过宽。
    assert!(
        mesh_uses_system_interface(&wg_reverse_mesh("vpn.example.com", false)),
        "非 WARP 的 WG reverseMesh:true 必须仍返 true —— 收宽了就是把 System 接入模式整体废掉"
    );

    // 新注册的 WARP：带自删凭据，address 是注册响应给的裸 IP。
    assert!(
        !mesh_uses_system_interface(&wg_reverse_mesh("162.159.192.1", true)),
        "WARP（warpDevice 标记）reverseMesh:true 必须被否决 —— 抢 utun ⇒ resource busy FATAL"
    );

    // 旧 / 导入 / 上游 迁移来的 WARP：无 warpDevice，只能靠端点域名兜底。
    // 这三条腿都不经渲染端，前端的否决在此无效 —— 本用例守的就是那道口子。
    assert!(
        !mesh_uses_system_interface(&wg_reverse_mesh("engage.cloudflareclient.com", false)),
        "无 warpDevice 标记的旧 WARP 必须按域名兜底否决（导入/手改/迁移绕过前端）"
    );
}
