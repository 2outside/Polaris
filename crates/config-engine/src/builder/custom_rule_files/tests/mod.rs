use super::*;
use crate::user_config::rule::{RuleAction, RuleType};
use serde_json::json;

fn cond(t: RuleType, values: &[&str]) -> RuleCondition {
    RuleCondition {
        type_field: t,
        values: values.iter().map(|s| s.to_string()).collect(),
    }
}

fn rule_single(t: RuleType, values: &[&str]) -> Rule {
    Rule {
        id: "r1".into(),
        type_field: t,
        values: values.iter().map(|s| s.to_string()).collect(),
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

#[test]
fn ext_type_classification() {
    assert!(is_ext_type(RuleType::Domain));
    assert!(is_ext_type(RuleType::IpCidr));
    assert!(is_ext_type(RuleType::ProcessName));
    assert!(!is_ext_type(RuleType::Geosite));
    assert!(!is_ext_type(RuleType::Geoip));
    assert!(!is_ext_type(RuleType::RuleSet));
    assert!(!is_ext_type(RuleType::SourceMac));
}

#[test]
fn cond_matcher_domain() {
    let c = cond(RuleType::Domain, &["a.com", "b.com"]);
    let f = cond_matcher_fields(&c).unwrap();
    assert_eq!(f["domain"], vec![json!("a.com"), json!("b.com")]);
}

#[test]
fn cond_matcher_domain_suffix_strips_wildcard() {
    let c = cond(RuleType::DomainSuffix, &["*.example.com", "test.com"]);
    let f = cond_matcher_fields(&c).unwrap();
    assert_eq!(
        f["domain_suffix"],
        vec![json!("example.com"), json!("test.com")]
    );
}

#[test]
fn cond_matcher_port_single_and_range() {
    let c = cond(RuleType::Port, &["443", "1000-2000"]);
    let f = cond_matcher_fields(&c).unwrap();
    assert_eq!(f["port"], vec![json!(443)]);
    assert_eq!(f["port_range"], vec![json!("1000:2000")]);
}

#[test]
fn cond_matcher_port_all_invalid_returns_none() {
    let c = cond(RuleType::Port, &["abc", "0", "99999"]);
    assert!(cond_matcher_fields(&c).is_none());
}

#[test]
fn cond_matcher_non_ext_returns_none() {
    let c = cond(RuleType::Geosite, &["cn"]);
    assert!(cond_matcher_fields(&c).is_none());
}

#[test]
fn plan_inline_when_has_geosite() {
    let rule = Rule {
        id: "r1".into(),
        type_field: RuleType::Domain,
        values: vec!["a.com".into()],
        conditions: Some(vec![
            cond(RuleType::Domain, &["a.com"]),
            cond(RuleType::Geosite, &["cn"]),
        ]),
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
    assert!(matches!(plan_custom_rule(&rule), RulePlan::Inline));
}

#[test]
fn plan_ext_single_domain() {
    let rule = rule_single(RuleType::Domain, &["a.com"]);
    let plan = plan_custom_rule(&rule);
    match plan {
        RulePlan::Ext {
            file_rules,
            dns_rules,
        } => {
            assert!(dns_rules.is_none());
            assert_eq!(file_rules.len(), 1);
            assert_eq!(file_rules[0]["domain"], json!(["a.com"]));
        }
        _ => panic!("expected Ext, got {plan:?}"),
    }
}

#[test]
fn plan_ext_or_group_mergeable() {
    let rule = Rule {
        id: "r1".into(),
        type_field: RuleType::Domain,
        values: vec!["a.com".into()],
        conditions: Some(vec![
            cond(RuleType::Domain, &["a.com"]),
            cond(RuleType::IpCidr, &["1.2.3.0/24"]),
        ]),
        combine_mode: None, // OR
        effects: None,
        action: RuleAction::Proxy,
        enabled: true,
        bypass_fakeip: None,
        target_server_id: None,
        remarks: None,
        tls_spoof: None,
        tls_spoof_method: None,
    };
    let plan = plan_custom_rule(&rule);
    match plan {
        RulePlan::Ext { file_rules, .. } => {
            assert_eq!(file_rules.len(), 1); // mergeable → 单 rule
            assert_eq!(file_rules[0]["domain"], json!(["a.com"]));
            assert_eq!(file_rules[0]["ip_cidr"], json!(["1.2.3.0/24"]));
        }
        _ => panic!("expected Ext, got {plan:?}"),
    }
}

#[test]
fn plan_ext_logical_when_cross_dimension_or() {
    // domain + port 跨维度 OR → logical rule。
    let rule = Rule {
        id: "r1".into(),
        type_field: RuleType::Domain,
        values: vec!["a.com".into()],
        conditions: Some(vec![
            cond(RuleType::Domain, &["a.com"]),
            cond(RuleType::Port, &["443"]),
        ]),
        combine_mode: None, // OR
        effects: None,
        action: RuleAction::Proxy,
        enabled: true,
        bypass_fakeip: None,
        target_server_id: None,
        remarks: None,
        tls_spoof: None,
        tls_spoof_method: None,
    };
    let plan = plan_custom_rule(&rule);
    match plan {
        RulePlan::Ext { file_rules, .. } => {
            assert_eq!(file_rules.len(), 1);
            assert_eq!(file_rules[0]["type"], json!("logical"));
            assert_eq!(file_rules[0]["mode"], json!("or"));
            assert_eq!(file_rules[0]["rules"].as_array().unwrap().len(), 2);
        }
        _ => panic!("expected Ext, got {plan:?}"),
    }
}

#[test]
fn plan_ext_skip_when_all_values_empty() {
    let rule = rule_single(RuleType::Domain, &["", "  "]);
    let plan = plan_custom_rule(&rule);
    assert!(matches!(plan, RulePlan::ExtSkip { .. }));
}

#[test]
fn file_base_legal_id() {
    assert_eq!(custom_rule_file_base("r1"), "custom-rule-r1");
    assert_eq!(
        custom_rule_file_base("abc-123_def"),
        "custom-rule-abc-123_def"
    );
}

#[test]
fn uses_fake_ip_default_true() {
    assert!(uses_fake_ip(None));
    assert!(uses_fake_ip(Some(true)));
    assert!(!uses_fake_ip(Some(false)));
}

// ── Fix 3：非法字符 rule id → sha1 派生唯一名（对齐 createHash('sha1').slice(0,12)）──
#[test]
fn file_base_illegal_id_sha1() {
    // sha1("a/b") = 3ec69c85a4ff...；前 12 位十六进制。
    assert_eq!(custom_rule_file_base("a/b"), "custom-rule-h3ec69c85a4ff");
    // sha1("has space") = e42b2b98cbee...
    assert_eq!(
        custom_rule_file_base("has space"),
        "custom-rule-he42b2b98cbee"
    );
    // 空 id 也走 hash（`.+` 不匹配空）：sha1("") = da39a3ee5e6b...
    assert_eq!(custom_rule_file_base(""), "custom-rule-hda39a3ee5e6b");
}

#[test]
fn file_base_illegal_ids_no_collision() {
    // 落盘后暴露撞车：不同非法 id 派生不同文件名。
    assert_ne!(custom_rule_file_base("a/b"), custom_rule_file_base("a\\b"));
    assert_ne!(custom_rule_file_base("x.y"), custom_rule_file_base("x*y"));
}

// ── Fix 1a：build_custom_rule_files 期望集 ──
fn user_config(proxy_mode: ProxyMode, rules: Vec<Rule>, fake_ip: Option<bool>) -> UserConfig {
    let mut c = UserConfig {
        proxy_mode,
        custom_rules: rules,
        ..Default::default()
    };
    if let Some(v) = fake_ip {
        c.dns_config = Some(crate::user_config::dns_config::DnsConfig {
            enable_fake_ip: Some(v),
            ..Default::default()
        });
    }
    c
}

#[test]
fn build_files_non_smart_returns_empty() {
    let rules = vec![rule_single(RuleType::Domain, &["a.com"])];
    assert!(
        build_custom_rule_files(&user_config(ProxyMode::Global, rules.clone(), None)).is_empty()
    );
    assert!(build_custom_rule_files(&user_config(ProxyMode::Direct, rules, None)).is_empty());
}

#[test]
fn build_files_smart_ext_json() {
    let cfg = user_config(
        ProxyMode::Smart,
        vec![rule_single(RuleType::Domain, &["a.com"])],
        None,
    );
    let out = build_custom_rule_files(&cfg);
    let content = out
        .get("custom-rule-r1.json")
        .expect("ext 计划应落盘 <base>.json");
    // 2 空格缩进（对齐 JSON.stringify(x, null, 2)）。
    assert!(content.contains("\n  \""), "应为 2 空格缩进 pretty");
    let v: serde_json::Value = serde_json::from_str(content).unwrap();
    assert_eq!(v["version"], json!(1));
    assert_eq!(v["rules"], json!([{ "domain": ["a.com"] }]));
    // 无 bypassFakeIP → 无 .dns.json。
    assert!(!out.contains_key("custom-rule-r1.dns.json"));
}

#[test]
fn build_files_disabled_rule_skipped() {
    let mut r = rule_single(RuleType::Domain, &["a.com"]);
    r.enabled = false;
    assert!(build_custom_rule_files(&user_config(ProxyMode::Smart, vec![r], None)).is_empty());
}

#[test]
fn build_files_inline_rule_skipped() {
    // geosite → inline（不可 headless）→ 无外化文件。
    let cfg = user_config(
        ProxyMode::Smart,
        vec![rule_single(RuleType::Geosite, &["cn"])],
        None,
    );
    assert!(build_custom_rule_files(&cfg).is_empty());
}

#[test]
fn build_files_bypass_fakeip_emits_dns_json() {
    let mut r = rule_single(RuleType::Domain, &["a.com"]);
    r.bypass_fakeip = Some(true);
    let out = build_custom_rule_files(&user_config(ProxyMode::Smart, vec![r], Some(true)));
    assert!(out.contains_key("custom-rule-r1.json"));
    let dns = out
        .get("custom-rule-r1.dns.json")
        .expect("bypassFakeIP + fakeIp 开 → 应落盘 .dns.json");
    let v: serde_json::Value = serde_json::from_str(dns).unwrap();
    assert_eq!(v["version"], json!(1));
    assert_eq!(v["rules"], json!([{ "domain": ["a.com"] }]));
}

#[test]
fn build_files_bypass_fakeip_off_no_dns_json() {
    // FakeIP 关 → 不落 .dns.json（route 侧 ext .json 仍落）。
    let mut r = rule_single(RuleType::Domain, &["a.com"]);
    r.bypass_fakeip = Some(true);
    let out = build_custom_rule_files(&user_config(ProxyMode::Smart, vec![r], Some(false)));
    assert!(out.contains_key("custom-rule-r1.json"));
    assert!(!out.contains_key("custom-rule-r1.dns.json"));
}

// ── Fix 1b：孤儿文件谓词 ──
#[test]
fn orphan_file_matches() {
    // 裸 .json + .tmp 变体。
    assert!(is_custom_rule_orphan_file("custom-rule-r1.json"));
    assert!(is_custom_rule_orphan_file("custom-rule-r1.dns.json"));
    assert!(is_custom_rule_orphan_file("custom-rule-r1.json.tmp"));
    assert!(is_custom_rule_orphan_file(
        "custom-rule-r1.json.12345.a1b2c3.tmp"
    ));
    assert!(is_custom_rule_orphan_file("custom-rule-hdeadbeef1234.json"));
}

#[test]
fn orphan_file_rejects() {
    assert!(!is_custom_rule_orphan_file("custom-rule-.json")); // `.+` 需 ≥1 字符
    assert!(!is_custom_rule_orphan_file("custom-rule-r1.txt"));
    assert!(!is_custom_rule_orphan_file("custom-rule-r1.jsontmp"));
    assert!(!is_custom_rule_orphan_file("other-r1.json"));
    assert!(!is_custom_rule_orphan_file("custom-rule-r1.json.")); // 空 seg 结尾
    assert!(!is_custom_rule_orphan_file("custom-rule-r1.json..tmp")); // 空 seg
    assert!(!is_custom_rule_orphan_file("r1.json"));
}
