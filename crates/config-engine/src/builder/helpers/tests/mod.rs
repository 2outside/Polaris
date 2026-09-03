use super::*;
use crate::user_config::rule::{AppRule, CustomAppPreset, RuleAction};

struct Srv {
    id: String,
    name: String,
}
impl ServerLike for Srv {
    fn id(&self) -> &str {
        &self.id
    }
    fn name(&self) -> &str {
        &self.name
    }
}

#[test]
fn id_to_tag_unique() {
    let servers = [
        Srv {
            id: "s1".into(),
            name: "HK".into(),
        },
        Srv {
            id: "s2".into(),
            name: "HK".into(),
        },
        Srv {
            id: "s3".into(),
            name: "JP".into(),
        },
    ];
    let map = build_id_to_tag_map(&servers);
    assert_eq!(map.get("s1").unwrap(), "HK");
    assert_eq!(map.get("s2").unwrap(), "HK (1)"); // 撞名追加
    assert_eq!(map.get("s3").unwrap(), "JP");
}

#[test]
fn id_to_tag_reserved_collision() {
    let servers = [Srv {
        id: "s1".into(),
        name: "direct".into(),
    }];
    let map = build_id_to_tag_map(&servers);
    assert_eq!(map.get("s1").unwrap(), "direct (1)"); // 撞保留 tag
}

#[test]
fn id_to_tag_empty_name() {
    let servers = [Srv {
        id: "s1".into(),
        name: "  ".into(),
    }];
    let map = build_id_to_tag_map(&servers);
    assert_eq!(map.get("s1").unwrap(), UNNAMED_SERVER);
}

#[test]
fn host_exclude_cidr() {
    assert_eq!(host_to_exclude_cidr("1.2.3.4"), Some("1.2.3.4/32".into()));
    assert_eq!(host_to_exclude_cidr("::1"), Some("::1/128".into()));
    assert_eq!(host_to_exclude_cidr("[::1]"), Some("::1/128".into()));
    assert_eq!(host_to_exclude_cidr("example.com"), None);
    assert_eq!(host_to_exclude_cidr(""), None);
}

#[test]
fn effective_rules_smart_only() {
    let rule = Rule {
        id: "r1".into(),
        type_field: RuleType::Domain,
        values: vec!["a.com".into()],
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
    };
    assert_eq!(
        effective_custom_rules("smart", std::slice::from_ref(&rule)).len(),
        1
    );
    assert!(effective_custom_rules("global", std::slice::from_ref(&rule)).is_empty());
    assert!(effective_custom_rules("direct", std::slice::from_ref(&rule)).is_empty());
}

#[test]
fn geo_categories_from_rules() {
    let rule = Rule {
        id: "r1".into(),
        type_field: RuleType::Geosite,
        values: vec!["CN".into(), "ADS".into()],
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
    };
    let (geosite, geoip) = get_required_geo_categories(&[rule], &[], &[]);
    assert!(geosite.contains("cn")); // lowercase
    assert!(geosite.contains("ads"));
    assert!(geoip.is_empty());
}

#[test]
fn geo_categories_from_custom_app_preset() {
    // 自定义预设（id 以 custom- 起，不与内置撞 —— seed_default_app_rules 也按此前缀保留）。
    //
    // 本测试原用 `id: "youtube"` 当自定义预设，且断言 geoip 含 youtube。它当时能过，是因为
    // `get_required_geo_categories` 走的私有 `app_preset_lookup` **只查 custom**（内置恒 None）。
    // 接上内置表后 `get_app_preset` 按「先内置、后自定义」的既定优先级返回**内置** youtube
    // （其 geoipTags 为空）→ 原断言失效。**原 fixture 是在验证一个坏实现的行为**：它靠「内置查不到」
    // 才让 custom 影子生效，而真实优先级下自定义永远盖不住内置 id。故改用不撞名的 custom-*。
    let app_rule = AppRule {
        app_id: "custom-mytube".into(),
        action: RuleAction::Proxy,
        enabled: true,
        target_server_id: None,
    };
    let preset = CustomAppPreset {
        id: "custom-mytube".into(),
        name: "MyTube".into(),
        emoji: "📺".into(),
        icon_url: None,
        geosite_tags: vec!["mytube".into()],
        geoip_tags: vec!["mytube".into()],
        process_names: None,
        category: None,
    };
    let (geosite, geoip) = get_required_geo_categories(&[], &[app_rule], &[preset]);
    assert!(geosite.contains("mytube"));
    assert!(geoip.contains("mytube"));
}

#[test]
fn geo_categories_from_builtin_app_preset() {
    // 回归门：内置预设的 geo tag 必须进 required 集。
    // 此前 `app_preset_lookup` 对全部 16 条内置预设返回 None → 本断言恒假，且**无任何测试覆盖**
    // （原测试只喂 custom preset，从没验过内置这条路）。这正是「门开在别处」的形态：
    // get_required_geo_categories 有测试、内置表有测试，两者的组合（生产路径）无门。
    let app_rule = AppRule {
        app_id: "telegram".into(),
        action: RuleAction::Proxy,
        enabled: true,
        target_server_id: None,
    };
    let (geosite, geoip) = get_required_geo_categories(&[], &[app_rule], &[]);
    assert!(
        geosite.contains("telegram"),
        "内置预设 telegram 的 geosite tag 未进 required 集"
    );
    assert!(
        geoip.contains("telegram"),
        "内置预设 telegram 的 geoip tag 未进 required 集"
    );
}

#[test]
fn geo_categories_builtin_wins_over_custom_same_id() {
    // 优先级锁死：自定义预设不得影子内置 id（get_app_preset 文档「先内置，后自定义」）。
    let app_rule = AppRule {
        app_id: "youtube".into(),
        action: RuleAction::Proxy,
        enabled: true,
        target_server_id: None,
    };
    let shadow = CustomAppPreset {
        id: "youtube".into(),
        name: "Shadow".into(),
        emoji: "📺".into(),
        icon_url: None,
        geosite_tags: vec!["evil".into()],
        geoip_tags: vec!["evil".into()],
        process_names: None,
        category: None,
    };
    let (geosite, geoip) = get_required_geo_categories(&[], &[app_rule], &[shadow]);
    assert!(geosite.contains("youtube"), "内置 youtube 应生效");
    assert!(!geosite.contains("evil"), "自定义预设影子了内置 id");
    assert!(!geoip.contains("evil"), "自定义预设影子了内置 id");
}

#[test]
fn geo_categories_skip_disabled_app_rule() {
    let app_rule = AppRule {
        app_id: "telegram".into(),
        action: RuleAction::Proxy,
        enabled: false,
        target_server_id: None,
    };
    let (geosite, geoip) = get_required_geo_categories(&[], &[app_rule], &[]);
    assert!(geosite.is_empty(), "禁用的 appRule 不该贡献 geo tag");
    assert!(geoip.is_empty());
}

#[test]
fn node_resolver_race_on() {
    // race on（resolve !== false）→ dns-node-race，无论 single/ctx。
    let tag = get_node_resolver_tag(
        Some(true),
        Some("ali"),
        None,
        "systemProxy",
        NodeResolverCtx::Dial,
    );
    assert_eq!(tag, "dns-node-race");
    let tag = get_node_resolver_tag(None, None, None, "tun", NodeResolverCtx::Rule);
    assert_eq!(tag, "dns-domestic"); // DNS rule 已迁到原生路径
}

#[test]
fn node_resolver_race_off_single() {
    // race off（=false）→ 按 single。
    let tag = get_node_resolver_tag(
        Some(false),
        Some("dnspod"),
        None,
        "systemProxy",
        NodeResolverCtx::Dial,
    );
    assert_eq!(tag, "dns-node");
}

#[test]
fn node_resolver_race_off_ali_split_dial_rule() {
    // ali 缺省：dial=dns-bootstrap / rule=dns-domestic（两路径基线）。
    let dial = get_node_resolver_tag(
        Some(false),
        Some("ali"),
        None,
        "systemProxy",
        NodeResolverCtx::Dial,
    );
    assert_eq!(dial, "dns-bootstrap");
    let rule = get_node_resolver_tag(
        Some(false),
        Some("ali"),
        None,
        "systemProxy",
        NodeResolverCtx::Rule,
    );
    assert_eq!(rule, "dns-domestic");
}

#[test]
fn node_resolver_system_tun_rule_forces_dns_node() {
    // INV-1: TUN + system + rule → dns-node（防递归）。
    let tag = get_node_resolver_tag(
        Some(false),
        Some("system"),
        None,
        "tun",
        NodeResolverCtx::Rule,
    );
    assert_eq!(tag, "dns-node");
    // 非 TUN → dns-local。
    let tag = get_node_resolver_tag(
        Some(false),
        Some("system"),
        None,
        "systemProxy",
        NodeResolverCtx::Rule,
    );
    assert_eq!(tag, "dns-local");
}

#[test]
fn node_resolver_legacy_fallback() {
    // 旧 nodeDomainResolver 单选档位迁移读取。
    let tag = get_node_resolver_tag(
        Some(false),
        None,
        Some("dnspod"),
        "systemProxy",
        NodeResolverCtx::Dial,
    );
    assert_eq!(tag, "dns-node");
    let tag = get_node_resolver_tag(
        Some(false),
        None,
        Some("system"),
        "systemProxy",
        NodeResolverCtx::Dial,
    );
    assert_eq!(tag, "dns-local");
}

#[test]
fn domestic_resolver_never_uses_node_sidecar() {
    assert_eq!(
        get_domestic_resolver_tag(Some(true), "dns-bootstrap"),
        "dns-bootstrap"
    );
    assert_eq!(
        get_domestic_resolver_tag(Some(false), "dns-bootstrap"),
        "dns-bootstrap"
    );
    assert_eq!(get_domestic_resolver_tag(None, "fallback"), "fallback");
    // 未配置 race 时也只返回调用方选择的普通解析器。
}

#[test]
fn custom_domestic_dns_ip() {
    let ep = get_custom_domestic_dns_endpoint(Some("https://223.5.5.5/dns-query"));
    assert_eq!(ep, Some(("223.5.5.5".to_string(), 443)));
    // 域名 → None。
    assert!(get_custom_domestic_dns_endpoint(Some("https://doh.pub/dns-query")).is_none());
    assert!(get_custom_domestic_dns_endpoint(None).is_none());
}
