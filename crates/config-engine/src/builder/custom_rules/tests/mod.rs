use super::*;
use crate::user_config::rule::{
    RuleAction, RuleDnsAnswerMode, RuleDnsEffect, RuleDnsResolver, RuleEffects, RuleRouteEffect,
    RuleType,
};
use crate::user_config::{DestinationResolution, DestinationResolutionMode};

fn deps_default() -> CustomRulesDeps {
    CustomRulesDeps {
        runtime_rules_dir: "/fake/rules".into(),
        rule_resources_path: "/fake/res".into(),
        custom_rules_dir: "/fake/custom-rules".into(),
        arch: "x64".into(),
        platform: "linux".into(),
        is_valid_srs_fn: |_| false, // res: 二进制 .srs 默认不存在
        exists_fn: |_| false,       // ext JSON 未落盘 → 回落 inline
        log: |_, _| {},
    }
}

/// 内置 `.srs` 已落盘的世界（`runtime_rules_dir` 下的 `.srs` 全有效）。
fn deps_builtin_srs_present() -> CustomRulesDeps {
    CustomRulesDeps {
        is_valid_srs_fn: |p| p.starts_with("/fake/rules/") && p.ends_with(".srs"),
        ..deps_default()
    }
}

// warn 收集器：`log` 是裸 fn 指针（闭包捕获不了）⇒ thread_local sink（测试单线程内自洽）。
// 与 route.rs 测试同手法（`route.rs:2087`）。
thread_local! {
    static WARN_SINK: std::cell::RefCell<Vec<String>> =
        const { std::cell::RefCell::new(Vec::new()) };
}
fn capture_warn(lvl: LogLevel, msg: &str) {
    assert_eq!(
        lvl,
        LogLevel::Warn,
        "剪枝告警必须是 warn 档（会被级别过滤吞掉的 info 等于没打）"
    );
    WARN_SINK.with(|s| s.borrow_mut().push(msg.to_string()));
}
fn take_warns() -> Vec<String> {
    WARN_SINK.with(|s| s.borrow_mut().drain(..).collect())
}

fn rule_ruleset(id: &str, values: &[&str]) -> Rule {
    rule_single(id, RuleType::RuleSet, values, RuleAction::Proxy)
}

fn deps_ext_present() -> CustomRulesDeps {
    // ext JSON 已落盘（exists_fn=true）；is_valid_srs_fn 保持 false 证明 ext 分支不再看它。
    CustomRulesDeps {
        exists_fn: |_| true,
        is_valid_srs_fn: |_| false,
        ..deps_default()
    }
}

fn rule_single(id: &str, t: RuleType, values: &[&str], action: RuleAction) -> Rule {
    Rule {
        id: id.into(),
        type_field: t,
        values: values.iter().map(|s| s.to_string()).collect(),
        conditions: None,
        combine_mode: None,
        effects: None,
        action,
        enabled: true,
        bypass_fakeip: None,
        target_server_id: None,
        remarks: None,
        tls_spoof: None,
        tls_spoof_method: None,
    }
}

fn empty_id_map() -> BTreeMap<String, String> {
    BTreeMap::new()
}

#[test]
fn single_domain_rule_proxy_default() {
    let rules_arr = [rule_single(
        "r1",
        RuleType::Domain,
        &["a.com"],
        RuleAction::Proxy,
    )];
    let id_map = empty_id_map();
    let result = build_custom_rules(
        &rules_arr,
        None,
        &id_map,
        "proxy-selector",
        &[],
        false,
        &deps_default(),
    );
    assert_eq!(result.rules.len(), 1);
    assert_eq!(result.rules[0].domain, Some(vec!["a.com".to_string()]));
    assert_eq!(result.rules[0].outbound.as_deref(), Some("rule-sel-r1"));
    assert_eq!(result.rules[0].action.as_deref(), Some("route"));
}

#[test]
fn direct_action_outbound() {
    let rules_arr = [rule_single(
        "r1",
        RuleType::IpCidr,
        &["10.0.0.0/8"],
        RuleAction::Direct,
    )];
    let id_map = empty_id_map();
    let result = build_custom_rules(
        &rules_arr,
        None,
        &id_map,
        "proxy-selector",
        &[],
        false,
        &deps_default(),
    );
    assert_eq!(result.rules[0].outbound.as_deref(), Some("direct"));
}

#[test]
fn migrated_dns_only_rule_keeps_legacy_non_terminal_resolve() {
    let mut rule = rule_single(
        "dns-only",
        RuleType::DomainSuffix,
        &["example.com"],
        RuleAction::Direct,
    );
    rule.effects = Some(RuleEffects {
        route: Some(RuleRouteEffect {
            enabled: true,
            action: RuleAction::Direct,
            target_server_id: None,
            destination_resolution: Some(DestinationResolution {
                mode: DestinationResolutionMode::DnsRules,
                server_id: None,
            }),
            resolution_only: true,
        }),
        dns: None,
    });
    let result = build_custom_rules(
        &[rule],
        None,
        &empty_id_map(),
        "proxy-selector",
        &[],
        false,
        &deps_default(),
    );
    assert!(result.rules.is_empty(), "DNS-only 不得生成终结流量动作");
    assert_eq!(result.resolve_rules.len(), 1);
    assert_eq!(result.resolve_rules[0].action.as_deref(), Some("resolve"));
    assert_eq!(
        result.resolve_rules[0].domain_suffix.as_deref(),
        Some(&["example.com".to_string()][..])
    );
    assert!(result.resolve_rules[0].outbound.is_none());
}

#[test]
fn ordinary_dns_only_rule_does_not_resolve_traffic_destination() {
    let mut rule = rule_single(
        "dns-only",
        RuleType::DomainSuffix,
        &["example.com"],
        RuleAction::Direct,
    );
    rule.effects = Some(RuleEffects {
        route: None,
        dns: Some(RuleDnsEffect {
            enabled: true,
            action: None,
            migrated_implicit_resolve: false,
            resolver: RuleDnsResolver::Proxy,
            answer_mode: RuleDnsAnswerMode::Real,
        }),
    });
    let result = build_custom_rules(
        &[rule],
        None,
        &empty_id_map(),
        "proxy-selector",
        &[],
        false,
        &deps_default(),
    );
    assert!(result.rules.is_empty());
    assert!(result.resolve_rules.is_empty());
}

#[test]
fn mixed_effect_rule_emits_resolve_before_independent_route_action() {
    let mut rule = rule_single(
        "mixed",
        RuleType::Domain,
        &["example.com"],
        RuleAction::Proxy,
    );
    rule.effects = Some(RuleEffects {
        route: Some(RuleRouteEffect {
            enabled: true,
            action: RuleAction::Direct,
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
            resolver: RuleDnsResolver::Proxy,
            answer_mode: RuleDnsAnswerMode::Real,
        }),
    });
    let result = build_custom_rules(
        &[rule],
        None,
        &empty_id_map(),
        "proxy-selector",
        &[],
        false,
        &deps_default(),
    );
    assert_eq!(result.resolve_rules.len(), 1);
    assert_eq!(result.rules.len(), 1);
    assert_eq!(result.resolve_rules[0].action.as_deref(), Some("resolve"));
    assert_eq!(result.rules[0].outbound.as_deref(), Some("direct"));
}

#[test]
fn unsupported_dns_condition_does_not_emit_orphan_resolve() {
    let mut rule = rule_single(
        "bad-dns",
        RuleType::IpCidr,
        &["10.0.0.0/8"],
        RuleAction::Direct,
    );
    rule.effects = Some(RuleEffects {
        route: Some(RuleRouteEffect {
            enabled: true,
            action: RuleAction::Direct,
            target_server_id: None,
            destination_resolution: None,
            resolution_only: false,
        }),
        dns: Some(RuleDnsEffect {
            enabled: true,
            action: None,
            migrated_implicit_resolve: false,
            resolver: RuleDnsResolver::Direct,
            answer_mode: RuleDnsAnswerMode::Real,
        }),
    });
    let result = build_custom_rules(
        &[rule],
        None,
        &empty_id_map(),
        "proxy-selector",
        &[],
        false,
        &deps_default(),
    );
    assert!(result.resolve_rules.is_empty());
    assert_eq!(result.rules.len(), 1, "独立的流量效果仍应保留");
}

/// 阻断动作 ⇒ 规则级 `action:"reject"` + **绝不写 outbound**。
///
/// 两条断言各锁一半，缺一不可：
///  - 只断 action ⇒ 漏 `outbound:"block"` 残留，配出的规则同时有 reject 与 outbound，
///    sing-box 会忽略后者，但下游 `is_proxy_out`（`route.rs` 的 udp443 配对）会按 outbound
///    反推成「走代理」，给阻断规则白配一条 udp443 reject。
///  - 只断 outbound is_none ⇒ 漏掉 action 覆盖，规则退化成 `action:"route"` 且无出站 ⇒
///    落到 `route.final`（= proxy-selector）⇒ **本该阻断的流量被放去代理**，静默失效。
///
/// 变异锁：把 `apply_rule_action` 的 Block 腿改回 `Some("block")` → 两条断言同时红。
#[test]
fn block_action_emits_rule_level_reject_without_outbound() {
    let rules_arr = [rule_single(
        "r1",
        RuleType::DomainKeyword,
        &["ads"],
        RuleAction::Block,
    )];
    let id_map = empty_id_map();
    let result = build_custom_rules(
        &rules_arr,
        None,
        &id_map,
        "proxy-selector",
        &[],
        false,
        &deps_default(),
    );
    assert_eq!(result.rules[0].action.as_deref(), Some("reject"));
    assert_eq!(
        result.rules[0].outbound, None,
        "reject 是规则级动作，写 outbound 会让下游把阻断规则误判成走代理"
    );
    // `no_drop:true` 不是可选装饰：缺了它 sing-box 会在 50 次/30s 后把阻断降级成静默丢包，
    // 高频命中的广告/遥测域名于是从「立刻被拒」变成「挂到超时」——与 legacy `block` 不等价。
    assert_eq!(
        result.rules[0].no_drop,
        Some(true),
        "阻断规则必须 no_drop:true 才与 legacy `block` 出站等价（默认会泛洪降级成 drop）"
    );
}

#[test]
fn disabled_rule_skipped() {
    let mut r = rule_single("r1", RuleType::Domain, &["a.com"], RuleAction::Proxy);
    r.enabled = false;
    let id_map = empty_id_map();
    let result = build_custom_rules(
        &[r],
        None,
        &id_map,
        "proxy-selector",
        &[],
        false,
        &deps_default(),
    );
    assert!(result.rules.is_empty());
}

#[test]
fn geosite_emits_rule_set_tag() {
    let rules_arr = [rule_single(
        "r1",
        RuleType::Geosite,
        &["cn", "ads"],
        RuleAction::Proxy,
    )];
    let id_map = empty_id_map();
    let result = build_custom_rules(
        &rules_arr,
        None,
        &id_map,
        "proxy-selector",
        &[],
        false,
        &deps_default(),
    );
    assert_eq!(result.rules.len(), 1);
    // geosite → rule_set: [geosite-cn, geosite-ads]
    let rs = result.rules[0].rule_set.as_ref().expect("应有 rule_set");
    match rs {
        crate::singbox::OneOrMany::Many(arr) => {
            assert_eq!(
                arr,
                &vec!["geosite-cn".to_string(), "geosite-ads".to_string()]
            );
        }
        _ => panic!("rule_set 应为数组"),
    }
}

#[test]
fn cross_dimension_or_emits_logical() {
    // domain + port 跨维度 OR → logical。
    let rule = Rule {
        id: "r1".into(),
        type_field: RuleType::Domain,
        values: vec!["a.com".into()],
        conditions: Some(vec![
            RuleCondition {
                type_field: RuleType::Domain,
                values: vec!["a.com".into()],
            },
            RuleCondition {
                type_field: RuleType::Port,
                values: vec!["443".into()],
            },
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
    let id_map = empty_id_map();
    let result = build_custom_rules(
        &[rule],
        None,
        &id_map,
        "proxy-selector",
        &[],
        false,
        &deps_default(),
    );
    assert_eq!(result.rules.len(), 1);
    assert_eq!(result.rules[0].type_field.as_deref(), Some("logical"));
    assert_eq!(result.rules[0].mode.as_deref(), Some("or"));
}

#[test]
fn ext_branch_uses_exists_fn_not_srs() {
    // exists_fn=true（ext JSON 已落盘）→ 固化 {rule_set: custom-rule-r1} + 注册 local rule_set。
    // is_valid_srs_fn 保持 false，证明 ext 分支已切到 exists_fn（变异：若仍看 srs_fn → 此测试红）。
    let rules_arr = [rule_single(
        "r1",
        RuleType::Domain,
        &["a.com"],
        RuleAction::Proxy,
    )];
    let id_map = empty_id_map();
    let result = build_custom_rules(
        &rules_arr,
        None,
        &id_map,
        "proxy-selector",
        &[],
        false,
        &deps_ext_present(),
    );
    assert!(
        result.rule_sets.iter().any(|rs| rs.tag == "custom-rule-r1"),
        "应注册 ext local rule_set"
    );
    assert_eq!(result.rules.len(), 1);
    let rule = &result.rules[0];
    assert!(rule.domain.is_none(), "ext 分支不应内联 domain");
    match rule.rule_set.as_ref().expect("应有 rule_set") {
        crate::singbox::OneOrMany::Many(arr) => {
            assert_eq!(arr, &vec!["custom-rule-r1".to_string()])
        }
        crate::singbox::OneOrMany::One(s) => assert_eq!(s, "custom-rule-r1"),
    }
    assert_eq!(rule.outbound.as_deref(), Some("rule-sel-r1"));
    assert_eq!(rule.action.as_deref(), Some("route"));
}

#[test]
fn ext_branch_falls_back_inline_when_file_absent() {
    // exists_fn=false（未落盘）→ 回落 inline（domain 内联，无 rule_set）。
    let rules_arr = [rule_single(
        "r1",
        RuleType::Domain,
        &["a.com"],
        RuleAction::Proxy,
    )];
    let id_map = empty_id_map();
    let result = build_custom_rules(
        &rules_arr,
        None,
        &id_map,
        "proxy-selector",
        &[],
        false,
        &deps_default(),
    );
    assert_eq!(result.rules.len(), 1);
    assert_eq!(result.rules[0].domain, Some(vec!["a.com".to_string()]));
    assert!(result.rules[0].rule_set.is_none());
    assert!(result.rule_sets.is_empty());
}

#[test]
fn ext_dns_registration_uses_exists_fn() {
    // bypassFakeIP + register_dns_bypass + exists_fn=true → 注册 <base>-dns rule_set。
    let mut r = rule_single("r1", RuleType::Domain, &["a.com"], RuleAction::Proxy);
    r.bypass_fakeip = Some(true);
    let id_map = empty_id_map();
    let result = build_custom_rules(
        &[r],
        None,
        &id_map,
        "proxy-selector",
        &[],
        true, // register_dns_bypass
        &deps_ext_present(),
    );
    assert!(
        result
            .rule_sets
            .iter()
            .any(|rs| rs.tag == "custom-rule-r1-dns"),
        "应注册 .dns.json rule_set"
    );
}

#[test]
fn proxy_rule_with_target_server_uses_rule_sel() {
    // 指定 targetServerId 的 proxy 规则 → rule-sel-<id>（anti-drift）。
    let mut r = rule_single(
        "rule42",
        RuleType::Domain,
        &["fixed.com"],
        RuleAction::Proxy,
    );
    r.target_server_id = Some("s2".into());
    let id_map = empty_id_map();
    let result = build_custom_rules(
        &[r],
        None,
        &id_map,
        "proxy-selector",
        &[],
        false,
        &deps_default(),
    );
    assert_eq!(result.rules[0].outbound.as_deref(), Some("rule-sel-rule42"));
}

// ── res:builtin:<tag> 内置资源引用 ────────────────────────────────────────────
//
// **变异锁**：把 `resolve_resource_rule_set` 的内置分支改回恒 `None`（原 `builtin_rule_set_file_name`
// 占位实现），下面 `builtin_ref_*` 三条会立刻转红——规则会被整条剪掉、rule_set 注册也消失。

#[test]
fn builtin_ref_emits_rule_set_and_definition() {
    // res:builtin:geosite-cn + 文件已落盘 → 规则保留 + 注册 local/binary rule_set。
    let result = build_custom_rules(
        &[rule_ruleset("r1", &["res:builtin:geosite-cn"])],
        None,
        &empty_id_map(),
        "proxy-selector",
        &[],
        false,
        &deps_builtin_srs_present(),
    );
    assert_eq!(result.rules.len(), 1, "内置资源规则不得被静默剪掉");
    match result.rules[0].rule_set.as_ref().expect("应有 rule_set") {
        crate::singbox::OneOrMany::Many(arr) => {
            assert_eq!(arr, &vec!["geosite-cn".to_string()])
        }
        crate::singbox::OneOrMany::One(s) => assert_eq!(s, "geosite-cn"),
    }
    // 引用必须有配套定义，否则 route 末尾的悬空剪枝会把它再剪一次（sing-box 侧则是 FATAL）。
    let rs = result
        .rule_sets
        .iter()
        .find(|rs| rs.tag == "geosite-cn")
        .expect("应注册 geosite-cn rule_set 定义");
    assert_eq!(rs.type_field, "local");
    assert_eq!(rs.format, "binary");
    assert_eq!(rs.path.as_deref(), Some("/fake/rules/geosite-cn.srs"));
}

#[test]
fn builtin_ref_uses_catalog_file_name_not_tag() {
    // geosite-category-ai 的落盘名是 geosite-category-ai-!cn.srs（MetaCubeX 无裸 category-ai .srs）。
    // 若有人把路径改回 `<tag>.srs` 拼接，本条会红 —— 那正是「文件名靠猜」的整类 bug。
    let result = build_custom_rules(
        &[rule_ruleset("r1", &["res:builtin:geosite-category-ai"])],
        None,
        &empty_id_map(),
        "proxy-selector",
        &[],
        false,
        &deps_builtin_srs_present(),
    );
    let rs = result
        .rule_sets
        .iter()
        .find(|rs| rs.tag == "geosite-category-ai")
        .expect("tag 仍是 geosite-category-ai");
    assert_eq!(
        rs.path.as_deref(),
        Some("/fake/rules/geosite-category-ai-!cn.srs")
    );
}

#[test]
fn builtin_ref_dedupes_repeated_tag() {
    // 同一条件里同一 builtin 引用两次 → 定义与引用都只留一份（重复 tag 会让 sing-box FATAL）。
    let result = build_custom_rules(
        &[rule_ruleset(
            "r1",
            &["res:builtin:geoip-cn", "res:builtin:geoip-cn"],
        )],
        None,
        &empty_id_map(),
        "proxy-selector",
        &[],
        false,
        &deps_builtin_srs_present(),
    );
    assert_eq!(
        result
            .rule_sets
            .iter()
            .filter(|rs| rs.tag == "geoip-cn")
            .count(),
        1,
        "rule_set 定义须按 tag 去重"
    );
    match result.rules[0].rule_set.as_ref().expect("应有 rule_set") {
        crate::singbox::OneOrMany::Many(arr) => {
            assert_eq!(arr, &vec!["geoip-cn".to_string()])
        }
        crate::singbox::OneOrMany::One(s) => assert_eq!(s, "geoip-cn"),
    }
}

#[test]
fn builtin_ref_missing_srs_is_skipped_with_warn() {
    // 文件缺失/损坏 → 整条剪掉（不引用不存在的 rule_set），且**必须**留下 warn。
    take_warns();
    let deps = CustomRulesDeps {
        log: capture_warn,
        ..deps_default() // is_valid_srs_fn=false → 内置 .srs 一个都不在
    };
    let result = build_custom_rules(
        &[rule_ruleset("r1", &["res:builtin:geosite-cn"])],
        None,
        &empty_id_map(),
        "proxy-selector",
        &[],
        false,
        &deps,
    );
    assert!(result.rules.is_empty(), "文件缺失须 fail-closed 剪掉规则");
    assert!(result.rule_sets.is_empty());
    let warns = take_warns();
    assert!(
        warns
            .iter()
            .any(|m| m.contains("内置资源文件缺失/损坏") && m.contains("geosite-cn.srs")),
        "规则被剪必须留线索（生产曾是 no-op，剪零告警）：{warns:?}"
    );
}

#[test]
fn unknown_builtin_tag_falls_through_to_resources_then_warns() {
    // catalog 未命中的 builtin: tag → 按普通资源 id 再查一次（上游 if/else 结构），查不到才报
    // 「资源不存在」。早退实现下这条 warn 永不出现。
    take_warns();
    let deps = CustomRulesDeps {
        log: capture_warn,
        ..deps_builtin_srs_present()
    };
    let result = build_custom_rules(
        &[rule_ruleset("r1", &["res:builtin:no-such-tag"])],
        None,
        &empty_id_map(),
        "proxy-selector",
        &[],
        false,
        &deps,
    );
    assert!(result.rules.is_empty());
    let warns = take_warns();
    assert!(
        warns
            .iter()
            .any(|m| m.contains("资源不存在") && m.contains("res:builtin:no-such-tag")),
        "未知 builtin tag 须落到「资源不存在」告警：{warns:?}"
    );
}

#[test]
fn remote_url_rule_set_warns() {
    // 远程 URL 已不再支持 → 跳过 + warn（第三条静音路径）。
    take_warns();
    let deps = CustomRulesDeps {
        log: capture_warn,
        ..deps_default()
    };
    let result = build_custom_rules(
        &[rule_ruleset("r1", &["https://example.com/foo.srs"])],
        None,
        &empty_id_map(),
        "proxy-selector",
        &[],
        false,
        &deps,
    );
    assert!(result.rules.is_empty());
    let warns = take_warns();
    assert!(
        warns.iter().any(|m| m.contains("远程 URL 已不再支持")),
        "远程 URL 跳过须留线索：{warns:?}"
    );
}
