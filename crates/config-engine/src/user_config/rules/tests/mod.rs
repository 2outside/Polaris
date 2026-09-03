use super::*;
use crate::user_config::rule::RuleType;

fn rule_with_conditions(conditions: Vec<RuleCondition>) -> Rule {
    Rule {
        id: "r1".into(),
        type_field: RuleType::Domain,
        values: vec!["first.com".into()],
        conditions: Some(conditions),
        combine_mode: None,
        effects: None,
        action: crate::user_config::rule::RuleAction::Proxy,
        enabled: true,
        bypass_fakeip: None,
        target_server_id: None,
        remarks: None,
        tls_spoof: None,
        tls_spoof_method: None,
    }
}

#[test]
fn rule_conditions_uses_conditions_when_present() {
    let rule = rule_with_conditions(vec![
        RuleCondition {
            type_field: RuleType::DomainSuffix,
            values: vec![".com".into()],
        },
        RuleCondition {
            type_field: RuleType::IpCidr,
            values: vec!["1.2.3.0/24".into()],
        },
    ]);
    let conds = rule_conditions(&rule);
    assert_eq!(conds.len(), 2);
    assert_eq!(conds[0].type_field, RuleType::DomainSuffix);
}

#[test]
fn rule_conditions_falls_back_to_mirror() {
    let rule = Rule {
        id: "r1".into(),
        type_field: RuleType::Domain,
        values: vec!["single.com".into()],
        conditions: None,
        combine_mode: None,
        effects: None,
        action: crate::user_config::rule::RuleAction::Direct,
        enabled: true,
        bypass_fakeip: None,
        target_server_id: None,
        remarks: None,
        tls_spoof: None,
        tls_spoof_method: None,
    };
    let conds = rule_conditions(&rule);
    assert_eq!(conds.len(), 1);
    assert_eq!(conds[0].values, vec!["single.com".to_string()]);
}

#[test]
fn rule_conditions_empty_conditions_falls_back() {
    let rule = Rule {
        id: "r1".into(),
        type_field: RuleType::Domain,
        values: vec!["fallback.com".into()],
        conditions: Some(vec![]),
        combine_mode: None,
        effects: None,
        action: crate::user_config::rule::RuleAction::Direct,
        enabled: true,
        bypass_fakeip: None,
        target_server_id: None,
        remarks: None,
        tls_spoof: None,
        tls_spoof_method: None,
    };
    let conds = rule_conditions(&rule);
    assert_eq!(conds.len(), 1);
    assert_eq!(conds[0].values, vec!["fallback.com".to_string()]);
}

#[test]
fn parse_port_single() {
    let (ports, ranges) = parse_port_values(&["443".into(), "80".into()]);
    assert_eq!(ports, vec![443, 80]);
    assert!(ranges.is_empty());
}

#[test]
fn parse_port_range() {
    let (ports, ranges) = parse_port_values(&["1000-2000".into()]);
    assert!(ports.is_empty());
    assert_eq!(ranges, vec!["1000:2000".to_string()]);
}

#[test]
fn parse_port_mixed() {
    let (ports, ranges) = parse_port_values(&["443".into(), "8000-9000".into()]);
    assert_eq!(ports, vec![443]);
    assert_eq!(ranges, vec!["8000:9000".to_string()]);
}

#[test]
fn parse_port_invalid_filtered() {
    let (ports, ranges) = parse_port_values(&[
        "0".into(),         // < 1
        "99999".into(),     // > 65535
        "abc".into(),       // 非数字
        "2000-1000".into(), // 范围倒序
        "443".into(),       // 合法
    ]);
    assert_eq!(ports, vec![443]);
    assert!(ranges.is_empty());
}

#[test]
fn port_token_valid() {
    assert!(is_valid_port_value("443"));
    assert!(is_valid_port_value("1-65535"));
    assert!(!is_valid_port_value("0"));
    assert!(!is_valid_port_value("70000"));
    assert!(!is_valid_port_value("abc"));
    assert!(!is_valid_port_value("100-50")); // 倒序
}

#[test]
fn rule_ip_cidrs_extracts_only_ipcidr() {
    let rule = rule_with_conditions(vec![
        RuleCondition {
            type_field: RuleType::DomainSuffix,
            values: vec![".com".into()],
        },
        RuleCondition {
            type_field: RuleType::IpCidr,
            values: vec!["1.2.3.0/24".into(), " 10.0.0.0/8 ".into(), "".into()],
        },
    ]);
    let cidrs = rule_ip_cidrs(&rule);
    assert_eq!(
        cidrs,
        vec!["1.2.3.0/24".to_string(), "10.0.0.0/8".to_string()]
    );
}
