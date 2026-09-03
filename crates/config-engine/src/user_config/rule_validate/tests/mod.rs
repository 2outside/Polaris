use super::*;
use crate::user_config::rule::{Rule, RuleAction, RuleCondition, RuleType};

#[test]
fn strict_ipv4_rejects_leading_zeros() {
    assert!(is_valid_ip_cidr("10.0.0.0/8"));
    assert!(is_valid_ip_cidr("192.168.1.1"));
    assert!(!is_valid_ip_cidr("010.0.0.1")); // 前导零
    assert!(!is_valid_ip_cidr("10.0.0.0/40")); // 掩码超界
    assert!(!is_valid_ip_cidr("256.1.1.1")); // 八位组超界
}

#[test]
fn strict_ipv6_structure() {
    assert!(is_valid_ip_cidr("fc00::/7"));
    assert!(is_valid_ip_cidr("2001:db8::1"));
    assert!(is_valid_ip_cidr("::ffff:192.168.1.1")); // 末段内嵌 IPv4
    assert!(!is_valid_ip_cidr("12345::1")); // 段>4位
    assert!(!is_valid_ip_cidr("dead::beef::1")); // 多个 ::
    assert!(!is_valid_ip_cidr("2001:db8::1/129")); // v6 掩码超界
}

#[test]
fn rule_type_ids_in_sync() {
    // RULE_TYPE_IDS 与 RuleType::as_id 严格同源（数量 + 逐项）。
    let variants = [
        RuleType::Domain,
        RuleType::DomainSuffix,
        RuleType::DomainKeyword,
        RuleType::DomainRegex,
        RuleType::IpCidr,
        RuleType::SourceIpCidr,
        RuleType::Port,
        RuleType::SourcePort,
        RuleType::SourceMac,
        RuleType::SourceHostname,
        RuleType::ProcessName,
        RuleType::ProcessPath,
        RuleType::Geosite,
        RuleType::Geoip,
        RuleType::RuleSet,
    ];
    assert_eq!(variants.len(), RULE_TYPE_IDS.len());
    for (v, id) in variants.iter().zip(RULE_TYPE_IDS) {
        assert_eq!(v.as_id(), *id);
        assert!(is_known_rule_type(id));
    }
    assert!(!is_known_rule_type("bogusType"));
}

/// 15 类规则值：每类至少一个 accept + 一个 reject（含空串一律非法）。
#[test]
fn validate_rule_value_accept_reject_per_type() {
    let cases: &[(&str, &str, &str)] = &[
        // (type, accept, reject)
        ("domain", "example.com", "bad!domain"),
        ("domainSuffix", "sub.example.com", "exa mple.com"),
        ("domainKeyword", "anything-goes", "   "),
        ("domainRegex", "^ab.*$", "(?=lookahead)"),
        ("ipCidr", "10.0.0.0/8", "010.0.0.1"),
        ("sourceIpCidr", "192.168.1.0/24", "256.1.1.1"),
        ("port", "443", "70000"),
        ("sourcePort", "1-1024", "0"),
        ("sourceMac", "aa:bb:cc:dd:ee:ff", "zz:bb:cc:dd:ee:ff"),
        ("sourceHostname", "my-host", "-bad"),
        ("processName", "chrome.exe", "bad/name"),
        ("processPath", "/usr/bin/chrome", "relative/path"),
        ("geosite", "geolocation-!cn", "bad tag"),
        ("geoip", "us", "bad@tag"),
        ("ruleSet", "res:my-set", "ftp://x/y"),
    ];
    for (ty, ok, bad) in cases {
        assert!(validate_rule_value(ty, ok), "{ty} should accept {ok:?}");
        assert!(!validate_rule_value(ty, bad), "{ty} should reject {bad:?}");
        assert!(!validate_rule_value(ty, ""), "{ty} must reject empty");
    }
    // 未知类型一律非法
    assert!(!validate_rule_value("bogus", "x"));
    // domainRegex 反向引用 \1..\9 全拒（非仅 \1）
    assert!(!validate_rule_value("domainRegex", r"(a)\2"));
    // processPath Windows 路径
    assert!(validate_rule_value(
        "processPath",
        r"C:\Program Files\app.exe"
    ));
    // ruleSet http(s) URL
    assert!(validate_rule_value("ruleSet", "https://example.com/x.srs"));
}

fn rule(type_field: RuleType, values: Vec<&str>, conditions: Option<Vec<RuleCondition>>) -> Rule {
    Rule {
        id: "r1".into(),
        type_field,
        values: values.into_iter().map(String::from).collect(),
        conditions,
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
fn validate_rule_accepts_valid_single_condition() {
    let r = rule(RuleType::Domain, vec!["example.com"], None);
    let res = validate_rule(&r);
    assert!(res.valid, "errors: {:?}", res.errors);
    assert!(res.errors.is_empty());
}

#[test]
fn validate_rule_rejects_empty_effects_and_unsupported_dns_matchers() {
    use crate::user_config::rule::{
        RuleDnsAnswerMode, RuleDnsEffect, RuleDnsResolver, RuleEffects,
    };

    let mut empty = rule(RuleType::Domain, vec!["example.com"], None);
    empty.effects = Some(RuleEffects::default());
    let empty_result = validate_rule(&empty);
    assert!(empty_result
        .errors
        .iter()
        .any(|error| error == "RULE_EFFECTS_EMPTY"));

    let mut unsupported = rule(RuleType::IpCidr, vec!["10.0.0.0/8"], None);
    unsupported.effects = Some(RuleEffects {
        route: None,
        dns: Some(RuleDnsEffect {
            enabled: true,
            action: None,
            migrated_implicit_resolve: false,
            resolver: RuleDnsResolver::Direct,
            answer_mode: RuleDnsAnswerMode::Real,
        }),
    });
    let unsupported_result = validate_rule(&unsupported);
    assert!(unsupported_result
        .errors
        .iter()
        .any(|error| error == "RULE_DNS_MATCH_UNSUPPORTED:ipCidr"));
}

#[test]
fn validate_rule_accepts_valid_multi_condition() {
    let r = rule(
        RuleType::Domain,
        vec!["mirror.com"],
        Some(vec![
            RuleCondition {
                type_field: RuleType::DomainSuffix,
                values: vec!["example.com".into(), "cdn.example.org".into()],
            },
            RuleCondition {
                type_field: RuleType::IpCidr,
                values: vec!["1.2.3.0/24".into()],
            },
        ]),
    );
    let res = validate_rule(&r);
    assert!(res.valid, "errors: {:?}", res.errors);
}

#[test]
fn validate_rule_rejects_bad_value() {
    let r = rule(RuleType::IpCidr, vec!["010.0.0.1"], None);
    let res = validate_rule(&r);
    assert!(!res.valid);
    assert_eq!(res.errors.len(), 1);
    assert!(res.errors[0].contains("ipCidr"));
}

#[test]
fn validate_rule_rejects_empty_values() {
    let r = rule(RuleType::Domain, vec!["", "   "], None);
    let res = validate_rule(&r);
    assert!(!res.valid);
    assert!(res.errors[0].contains("缺少有效值"));
}

#[test]
fn validate_rule_rejects_when_one_condition_bad() {
    let r = rule(
        RuleType::Domain,
        vec!["ok.com"],
        Some(vec![
            RuleCondition {
                type_field: RuleType::Domain,
                values: vec!["ok.com".into()],
            },
            RuleCondition {
                type_field: RuleType::Port,
                values: vec!["99999".into()], // 越界
            },
        ]),
    );
    let res = validate_rule(&r);
    assert!(!res.valid);
    assert!(res.errors.iter().any(|e| e.contains("port")));
}

/// `domain_keyword` 是对**域名**做子串匹配，DNS 名里不可能出现 `:` ⇒ 含冒号的关键词恒不命中，
/// 且内核不报错 —— 用户填 IPv6 字面量进去得到的是一条静默失效的死规则。前端同源门在
/// `ui/src/domain/rules.test.ts` 的 `domainKeyword 拒含冒号值`，两侧必须同时改。
#[test]
fn domain_keyword_rejects_ipv6_literals() {
    for v in [
        "2001:db8::1",
        "[2001:db8::1]", // URL 写法，方括号形式同样含冒号
        "::1",
        "fe80::1%eth0",
        "::ffff:192.168.1.1",
        "2606:4700::1",
    ] {
        assert!(
            !validate_rule_value("domainKeyword", v),
            "{v} 应被拒：含冒号的关键词永不命中"
        );
    }
    // 判据是「含冒号」而非「像 IPv6」——`foo:bar` 同样永不命中。
    assert!(!validate_rule_value("domainKeyword", "foo:bar"));
    assert!(!validate_rule_value("domainKeyword", "example.com:443"));
}

/// 反向对照：闸门不得收得过宽。这条挂了说明把正常关键词误判成了 IP，砍掉了合法能力。
#[test]
fn domain_keyword_accepts_normal_keywords_including_ipv4() {
    for v in [
        "ads",
        "googlevideo",
        "example.com",
        "cdn-",
        "1.2.3.4", // `1.2.3.4.nip.io`、`4.3.2.1.in-addr.arpa` 都是真实可命中的域名
        "10.0.0.1",
        "v6", // 名字里带 v6 不等于 IPv6
    ] {
        assert!(
            validate_rule_value("domainKeyword", v),
            "{v} 应被接受：它是合法关键词"
        );
    }
    // 原有语义不变：空 / 纯空白仍然拒。
    assert!(!validate_rule_value("domainKeyword", ""));
    assert!(!validate_rule_value("domainKeyword", "   "));
}

/// 同族一致性：域名族三个字面量类型对 IPv6 口径统一（此前只有 keyword 漏）。
#[test]
fn domain_family_rejects_ipv6_uniformly() {
    for t in ["domain", "domainSuffix", "domainKeyword"] {
        assert!(!validate_rule_value(t, "2001:db8::1"), "{t} 应拒 IPv6");
        assert!(
            !validate_rule_value(t, "[2001:db8::1]"),
            "{t} 应拒方括号 IPv6"
        );
    }
}

/// 端到端：一条「关键词 = IPv6 字面量」的规则过不了提交门（`rules_add`/`rules_update` 走这里）。
#[test]
fn validate_rule_rejects_ipv6_keyword_rule() {
    let r = rule(RuleType::DomainKeyword, vec!["2001:db8::1"], None);
    let res = validate_rule(&r);
    assert!(
        !res.valid,
        "IPv6 关键词规则必须被提交门拒掉，而不是静默存成死配置"
    );
    assert!(res.errors.iter().any(|e| e.contains("domainKeyword")));
}
