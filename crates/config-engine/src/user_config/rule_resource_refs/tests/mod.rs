use super::*;
use crate::user_config::rule::{RuleAction, RuleCondition};

fn rule(id: &str, t: RuleType, values: &[&str], enabled: bool) -> Rule {
    Rule {
        id: id.into(),
        type_field: t,
        values: values.iter().map(|s| (*s).to_string()).collect(),
        enabled,
        action: RuleAction::Proxy,
        ..Default::default()
    }
}

fn app_rule(id: &str, enabled: bool) -> AppRule {
    AppRule {
        app_id: id.into(),
        action: RuleAction::Proxy,
        enabled,
        target_server_id: None,
    }
}

#[test]
fn geo_tag_of_strips_builtin_prefix() {
    assert_eq!(geo_tag_of("builtin:geosite-cn"), "geosite-cn");
    assert_eq!(geo_tag_of("geosite-amazon"), "geosite-amazon");
    assert_eq!(geo_tag_of("res_123"), "res_123");
}

#[test]
fn split_geo_tag_keeps_dashes_and_bang() {
    // `geolocation-!cn` 含 '-' 与 '!' → 只切首个前缀，其余原样（TS 的 `(.+)` 语义）。
    let (k, n) = split_geo_tag("geosite-geolocation-!cn").unwrap();
    assert_eq!(k, RuleType::Geosite);
    assert_eq!(n, "geolocation-!cn");
    assert!(split_geo_tag("res_123").is_none());
    assert!(split_geo_tag("geosite-").is_none(), "空 name 不算 geo tag");
}

#[test]
fn rule_type_str_matches_serde_rename() {
    // 与 RuleType 的 rename_all="camelCase" 同源（手写映射表会漂移 → 本测试锁死）。
    assert_eq!(rule_type_str(RuleType::RuleSet), "ruleSet");
    assert_eq!(rule_type_str(RuleType::DomainSuffix), "domainSuffix");
    assert_eq!(rule_type_str(RuleType::Geosite), "geosite");
}

#[test]
fn ref_via_rule_set_res_prefix() {
    let r = rule("r1", RuleType::RuleSet, &["res:geosite-amazon"], true);
    let input = RefScanInput {
        custom_rules: &[r],
        ..Default::default()
    };
    let refs = enumerate_resource_refs("geosite-amazon", &input);
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].kind, "route");
    assert_eq!(refs[0].id, "r1");
    assert_eq!(refs[0].label, "ruleSet: res:geosite-amazon");
}

#[test]
fn ref_via_bare_geosite_condition() {
    // 缺口②：geosite 类型条件的值是裸 tag（`youtube`），资源 id 是 `geosite-youtube`。
    let r = rule("r2", RuleType::Geosite, &["  YouTube "], true);
    let input = RefScanInput {
        custom_rules: &[r],
        ..Default::default()
    };
    let refs = enumerate_resource_refs("geosite-youtube", &input);
    assert_eq!(refs.len(), 1, "裸 tag 引用（trim + 大小写不敏感）应命中");
    assert_eq!(refs[0].id, "r2");
}

#[test]
fn geoip_condition_does_not_match_geosite_resource() {
    let r = rule("r3", RuleType::Geoip, &["cn"], true);
    let input = RefScanInput {
        custom_rules: &[r],
        ..Default::default()
    };
    assert!(enumerate_resource_refs("geosite-cn", &input).is_empty());
    assert_eq!(enumerate_resource_refs("geoip-cn", &input).len(), 1);
}

#[test]
fn disabled_rule_not_counted() {
    let r = rule("r4", RuleType::Geosite, &["youtube"], false);
    let input = RefScanInput {
        custom_rules: &[r],
        ..Default::default()
    };
    assert!(enumerate_resource_refs("geosite-youtube", &input).is_empty());
}

#[test]
fn remarks_win_over_condition_summary() {
    let mut r = rule("r5", RuleType::Geosite, &["youtube"], true);
    r.remarks = Some("  我的规则  ".into());
    let input = RefScanInput {
        custom_rules: &[r],
        ..Default::default()
    };
    assert_eq!(
        enumerate_resource_refs("geosite-youtube", &input)[0].label,
        "我的规则"
    );
}

#[test]
fn blank_remarks_fall_back_to_summary() {
    let mut r = rule("r6", RuleType::Geosite, &["youtube"], true);
    r.remarks = Some("   ".into()); // 全空白 = 无备注（TS `.trim() || summary`）
    let input = RefScanInput {
        custom_rules: &[r],
        ..Default::default()
    };
    assert_eq!(
        enumerate_resource_refs("geosite-youtube", &input)[0].label,
        "geosite: youtube"
    );
}

#[test]
fn summary_value_truncated_to_24() {
    let long = "a".repeat(50);
    let r = rule("r7", RuleType::RuleSet, &["res:geosite-amazon"], true);
    let mut r = r;
    r.conditions = Some(vec![
        RuleCondition {
            type_field: RuleType::Domain,
            values: vec![long],
        },
        RuleCondition {
            type_field: RuleType::RuleSet,
            values: vec!["res:geosite-amazon".into()],
        },
    ]);
    let input = RefScanInput {
        custom_rules: &[r],
        ..Default::default()
    };
    let refs = enumerate_resource_refs("geosite-amazon", &input);
    assert_eq!(refs.len(), 1, "多条件里任一命中即算引用");
    assert_eq!(refs[0].label, format!("domain: {}", "a".repeat(24)));
}

#[test]
fn ref_via_builtin_app_preset() {
    // 缺口③：appRules 经内置 preset 间接引用 geo 资源。
    let input = RefScanInput {
        app_rules: &[app_rule("youtube", true)],
        ..Default::default()
    };
    let refs = enumerate_resource_refs("geosite-youtube", &input);
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].kind, "app");
    assert_eq!(refs[0].id, "youtube");
    assert_eq!(refs[0].label, "youtube", "内置 → label 是 i18n key");
    assert_eq!(refs[0].app_builtin, Some(true));
}

#[test]
fn ref_via_builtin_app_preset_geoip() {
    // telegram 同时有 geosite 与 geoip tag。
    let input = RefScanInput {
        app_rules: &[app_rule("telegram", true)],
        ..Default::default()
    };
    assert_eq!(enumerate_resource_refs("geosite-telegram", &input).len(), 1);
    assert_eq!(enumerate_resource_refs("geoip-telegram", &input).len(), 1);
    // youtube 无 geoip tag → geoip-youtube 不该被 youtube 卡片引用。
    let input = RefScanInput {
        app_rules: &[app_rule("youtube", true)],
        ..Default::default()
    };
    assert!(enumerate_resource_refs("geoip-youtube", &input).is_empty());
}

#[test]
fn ref_via_custom_app_preset_uses_name_and_flags_non_builtin() {
    let custom = vec![CustomAppPreset {
        id: "custom-foo".into(),
        name: "我的 Foo".into(),
        emoji: "🚀".into(),
        icon_url: None,
        geosite_tags: vec!["foo".into()],
        geoip_tags: vec![],
        process_names: None,
        category: Some("tools".into()),
    }];
    let input = RefScanInput {
        app_rules: &[app_rule("custom-foo", true)],
        custom_app_presets: &custom,
        ..Default::default()
    };
    let refs = enumerate_resource_refs("geosite-foo", &input);
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].label, "我的 Foo", "自定义 → label 是 name 原文");
    assert_eq!(
        refs[0].app_builtin,
        Some(false),
        "custom- 前缀 → appBuiltin=false（渲染端据此不过 i18n）"
    );
}

#[test]
fn disabled_app_rule_not_counted() {
    let input = RefScanInput {
        app_rules: &[app_rule("youtube", false)],
        ..Default::default()
    };
    assert!(enumerate_resource_refs("geosite-youtube", &input).is_empty());
}

#[test]
fn builtin_prefixed_res_id_resolves_to_geo_tag() {
    // 资源 id 形如 `builtin:geosite-cn` 时，仍要匹配到裸 tag `cn` 的条件与 preset。
    let r = rule("r8", RuleType::Geosite, &["cn"], true);
    let input = RefScanInput {
        custom_rules: &[r],
        ..Default::default()
    };
    assert_eq!(
        enumerate_resource_refs("builtin:geosite-cn", &input).len(),
        1
    );
}

#[test]
fn route_and_app_refs_accumulate() {
    let r = rule("r9", RuleType::Geosite, &["youtube"], true);
    let input = RefScanInput {
        custom_rules: &[r],
        app_rules: &[app_rule("youtube", true)],
        custom_app_presets: &[],
    };
    let refs = enumerate_resource_refs("geosite-youtube", &input);
    assert_eq!(refs.len(), 2, "route + app 两类引用应累加");
    assert!(is_resource_referenced("geosite-youtube", &input));
    assert!(!is_resource_referenced("geosite-netflix", &input));
}

#[test]
fn unreferenced_resource_has_no_refs() {
    let input = RefScanInput::default();
    assert!(enumerate_resource_refs("geosite-amazon", &input).is_empty());
    assert!(!is_resource_referenced("geosite-amazon", &input));
}
