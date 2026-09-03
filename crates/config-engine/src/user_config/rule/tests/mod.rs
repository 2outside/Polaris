use super::*;

#[test]
fn rule_deserializes_from_polaris_json() {
    // 验证能反序列化 Polaris config.json 里的 Rule 结构（camelCase 键）。
    let json = r#"{
            "id": "r1",
            "type": "domain",
            "values": ["example.com"],
            "action": "proxy",
            "enabled": true,
            "targetServerId": "s2"
        }"#;
    let rule: Rule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.type_field, RuleType::Domain);
    assert_eq!(rule.action, RuleAction::Proxy);
    assert_eq!(rule.target_server_id.as_deref(), Some("s2"));
    assert_eq!(rule.route_action(), Some(RuleAction::Proxy));
    assert!(rule.effects.is_none());
    assert!(rule.conditions.is_none()); // 单条件无 conditions
}

#[test]
fn multi_condition_rule_with_and() {
    let json = r#"{
            "id": "r2",
            "type": "domain",
            "values": ["a.com"],
            "conditions": [
                {"type": "domainSuffix", "values": [".com"]},
                {"type": "ipCidr", "values": ["1.2.3.0/24"]}
            ],
            "combineMode": "and",
            "action": "direct",
            "enabled": true
        }"#;
    let rule: Rule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.combine_mode, Some(CombineMode::And));
    assert_eq!(rule.conditions.as_ref().unwrap().len(), 2);
}

#[test]
fn dns_only_effect_is_authoritative_over_legacy_route_mirror() {
    let json = r#"{
            "id":"dns-only",
            "type":"domainSuffix",
            "values":["example.com"],
            "action":"direct",
            "effects":{"dns":{"resolver":"proxy","answerMode":"fakeIp"}},
            "enabled":true
        }"#;
    let rule: Rule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.route_action(), None);
    assert_eq!(
        rule.dns_effect(),
        Some(RuleDnsEffect {
            enabled: true,
            action: None,
            migrated_implicit_resolve: false,
            resolver: RuleDnsResolver::Proxy,
            answer_mode: RuleDnsAnswerMode::FakeIp,
        })
    );
    let encoded = serde_json::to_value(&rule).unwrap();
    assert_eq!(encoded["effects"]["dns"]["answerMode"], "fakeIp");
    assert!(encoded["effects"].get("route").is_none());
}
