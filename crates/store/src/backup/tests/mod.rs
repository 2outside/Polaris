use super::*;
use serde_json::json;

use BackupCategory as C;

fn cfg() -> Value {
    json!({
        "selectedServerId": "m1",
        "proxyMode": "rule",
        "servers": [
            { "id": "m1", "name": "手动1", "protocol": "vless" },
            { "id": "m2", "name": "手动2", "protocol": "trojan" },
            { "id": "w1", "name": "WG", "protocol": "wireguard" },
            { "id": "t1", "name": "TS", "protocol": "tailscale" },
            { "id": "s1", "name": "订阅节点", "protocol": "vless", "subscriptionId": "sub1" },
        ],
        "subscriptions": [{ "id": "sub1", "url": "https://a.example/x" }],
        "customRules": [{ "id": "r1", "type": "domain", "values": ["a.com"] }],
        "configSchemaVersion": 4,
        "policyRules": [{
            "id": "r1", "type": "domain", "values": ["a.com"], "action": "direct",
            "enabled": true, "effects": { "route": { "enabled": true, "action": "direct" } }
        }],
        "trafficRules": [{
            "id": "r1", "type": "domain", "values": ["a.com"], "action": "direct",
            "enabled": true, "effects": { "route": { "enabled": true, "action": "direct" } }
        }],
        "dnsRules": [{
            "id": "r1", "type": "domain", "values": ["a.com"], "action": "direct",
            "enabled": true, "effects": { "dns": { "enabled": true, "resolver": "direct",
            "answerMode": "real", "action": { "type": "server", "serverId": "dns-custom" } } }
        }],
        "routeRuleOrder": ["r1"],
        "dnsRuleOrder": ["r1"],
        "dnsServers": [
            { "id": "builtin-domestic", "name": "Domestic", "enabled": true, "type": "https", "outbound": { "type": "direct" } },
            { "id": "builtin-remote", "name": "Remote", "enabled": true, "type": "https", "outbound": { "type": "currentExit" } },
            { "id": "dns-custom", "name": "Custom", "enabled": true, "type": "udp", "outbound": { "type": "direct" } }
        ],
        "dnsServerGroups": [{ "id": "dns-group", "name": "Race", "enabled": true, "mode": "race", "members": ["dns-custom"] }],
        "dnsDefaults": { "directServerId": "builtin-domestic", "proxyServerId": "builtin-remote", "connectionResolution": "preserveDomain", "unmatchedAction": { "type": "fakeIp" } },
        "customRuleSets": [{ "id": "rs1" }],
        "ruleResources": [{ "id": "res1" }],
        "appRules": [{ "id": "a1", "appId": "chrome" }],
        "appRulesSeeded": true,
        "customAppPresets": [{ "id": "p1" }],
        "clashApiSecret": "SUPERSECRET",
        "privacyPassword": "hunter2",
        "privacyPasswordHash": "d34db33f$c0ffee",
    })
}

// ── 分类 ──

#[test]
fn classify_subscription_beats_endpoint() {
    // 订阅节点 > 组网节点：即便是 wireguard，只要有 subscriptionId 就归订阅类。
    let s = json!({ "protocol": "wireguard", "subscriptionId": "sub1" });
    assert_eq!(classify_server(&s), NodeCategory::Subscription);
}

#[test]
fn classify_empty_subscription_id_is_not_subscription() {
    // JS 真值语义：subscriptionId="" 是假值 → 不归订阅类。
    let s = json!({ "protocol": "vless", "subscriptionId": "" });
    assert_eq!(classify_server(&s), NodeCategory::Manual);
    let s2 = json!({ "protocol": "vless", "subscriptionId": null });
    assert_eq!(classify_server(&s2), NodeCategory::Manual);
}

#[test]
fn classify_unknown_protocol_falls_back_to_manual() {
    // isMeshProtocol(未知) = false → 手动类（宁可分错桶也不丢节点）
    assert_eq!(
        classify_server(&json!({ "protocol": "nosuchproto" })),
        NodeCategory::Manual
    );
    assert_eq!(classify_server(&json!({})), NodeCategory::Manual);
    assert_eq!(
        classify_server(&json!({ "protocol": 42 })),
        NodeCategory::Manual
    );
}

#[test]
fn classify_endpoint_protocols_are_mesh() {
    assert_eq!(
        classify_server(&json!({ "protocol": "wireguard" })),
        NodeCategory::Mesh
    );
    assert_eq!(
        classify_server(&json!({ "protocol": "tailscale" })),
        NodeCategory::Mesh
    );
}

// ── countCategory ──

#[test]
fn count_category_all_eight() {
    let c = cfg();
    assert_eq!(count_category(&c, C::ManualNodes), 2);
    assert_eq!(count_category(&c, C::MeshNodes), 2);
    assert_eq!(
        count_category(&c, C::Subscriptions),
        1,
        "计订阅源数，不计展开节点"
    );
    assert_eq!(
        count_category(&c, C::CustomRules),
        2,
        "rules(1) + ruleSets(1)"
    );
    assert_eq!(count_category(&c, C::AppRules), 1);
    assert_eq!(count_category(&c, C::DnsResources), 4);
    assert_eq!(count_category(&c, C::GeneralSettings), 1, "恒 1 = 整组");
}

#[test]
fn count_general_settings_zero_when_only_data_fields() {
    let c = json!({ "servers": [], "customRules": [] });
    assert_eq!(count_category(&c, C::GeneralSettings), 0);
}

#[test]
fn count_general_settings_zero_when_only_excluded_fields() {
    // 排除字段不算「通用设置」——否则一份只含 clashApiSecret 的 config 会诓出 generalSettings 类
    let c = json!({ "clashApiSecret": "x", "privacyPassword": "y" });
    assert_eq!(count_category(&c, C::GeneralSettings), 0);
}

#[test]
fn count_on_empty_config_is_zero() {
    let c = json!({});
    for cat in BACKUP_CATEGORIES {
        assert_eq!(count_category(&c, cat), 0, "{cat:?}");
    }
}

#[test]
fn count_tolerates_wrong_types() {
    // servers 非数组 / subscriptions 是字符串 → 不 panic，计 0
    let c = json!({ "servers": "oops", "subscriptions": 3 });
    assert_eq!(count_category(&c, C::ManualNodes), 0);
    assert_eq!(count_category(&c, C::Subscriptions), 0);
}

// ── detectCategories ──

#[test]
fn detect_returns_all_present_in_declared_order() {
    assert_eq!(
        detect_categories(&cfg()),
        vec![
            C::ManualNodes,
            C::MeshNodes,
            C::Subscriptions,
            C::CustomRules,
            C::DnsRules,
            C::DnsResources,
            C::AppRules,
            C::GeneralSettings
        ]
    );
}

#[test]
fn detect_subscriptions_via_orphan_nodes_only() {
    // 订阅源为空但存在展开节点（离线备份）→ 仍算有数据，否则那些节点永远导不回来
    let c = json!({ "servers": [{ "id": "s1", "protocol": "vless", "subscriptionId": "sub1" }] });
    assert_eq!(detect_categories(&c), vec![C::Subscriptions]);
}

#[test]
fn detect_skips_empty_categories() {
    let c = json!({ "servers": [], "subscriptions": [], "customRules": [] });
    assert_eq!(detect_categories(&c), Vec::<C>::new());
}

// ── pickCategories ──

#[test]
fn pick_only_selected_node_class() {
    let out = pick_categories(&cfg(), &[C::ManualNodes]);
    let ids: Vec<&str> = out["servers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["m1", "m2"]);
    assert!(out.get("subscriptions").is_none());
    assert!(out.get("proxyMode").is_none(), "未选通用设置 → 不带");
}

#[test]
fn pick_never_emits_excluded_secrets() {
    // 红线：clashApiSecret / privacyPassword / privacyPasswordHash 绝不入备份文件，哪怕全选
    let out = pick_categories(&cfg(), &BACKUP_CATEGORIES);
    assert!(out.get("clashApiSecret").is_none());
    assert!(out.get("privacyPassword").is_none());
    assert!(out.get("privacyPasswordHash").is_none());
    let s = serde_json::to_string(&out).unwrap();
    assert!(!s.contains("SUPERSECRET"));
    assert!(!s.contains("hunter2"));
    assert!(!s.contains("c0ffee"), "salted hash 绝不入备份");
}

#[test]
fn pick_general_settings_uses_exclusion_rule() {
    // 排除法：未来新增的未知设置键自动进 generalSettings
    let mut c = cfg();
    c["someBrandNewSetting2099"] = json!("v");
    let out = pick_categories(&c, &[C::GeneralSettings]);
    assert_eq!(out["someBrandNewSetting2099"], json!("v"));
    assert_eq!(out["proxyMode"], json!("rule"));
    assert!(out.get("servers").is_none());
    assert!(
        out.get("selectedServerId").is_none(),
        "selectedServerId 跟节点走，非通用设置"
    );
}

/// 托盘 MRU 是**本机使用痕迹**，绝不入备份：跨机搬运时外机的节点 id 在本机多半解析不出节点，
/// 却会白占「节点·最近」3 个槽位之一；且它是「后端权威」字段（前端零写入权，见 `commands/config.rs`
/// 的 `BACKEND_AUTHORITATIVE_KEYS`），不该经备份这条前端全量提交路径被改写。
///
/// 牙：把 `recentServerIds` 从 `EXCLUDED_FROM_BACKUP` 拿掉 → 它落回排除法的 generalSettings
/// （`is_general_key` 转真）→ 第一个断言转红。
#[test]
fn recent_server_ids_never_enters_backup() {
    let mut c = cfg();
    c["recentServerIds"] = json!(["n1", "n2", "n3"]);
    let out = pick_categories(&c, &[C::GeneralSettings]);
    assert!(
        out.get("recentServerIds").is_none(),
        "托盘 MRU 是本机痕迹 + 后端权威字段，绝不入备份"
    );
    // 同一份 config 里的普通通用设置照常入备份（证明上面不是因为整类没导出而空过）。
    assert_eq!(out["proxyMode"], json!("rule"), "普通通用设置照常导出");
    assert!(
        !is_general_key("recentServerIds"),
        "recentServerIds 不属通用设置"
    );
}

#[test]
fn pick_custom_rules_family_together() {
    let out = pick_categories(&cfg(), &[C::CustomRules]);
    assert!(out.get("trafficRules").is_some());
    assert!(out.get("customRules").is_some());
    assert_eq!(out["policyRules"][0]["id"], json!("r1"));
    assert_eq!(out["customRules"], out["policyRules"], "旧镜像与真值同源");
    assert_eq!(out["routeRuleOrder"], json!(["r1"]));
    assert!(out.get("dnsRuleOrder").is_none());
    assert!(out.get("customRuleSets").is_some());
    assert!(
        out.get("ruleResources").is_some(),
        "ruleResources 随规则类同进同出"
    );
    assert!(out.get("dnsServers").is_none());
    assert!(out.get("dnsServerGroups").is_none());
    assert!(out.get("dnsDefaults").is_none());
    assert_eq!(out["configSchemaVersion"], json!(4));
}

#[test]
fn pick_dns_rules_closes_over_all_matching_and_dns_resources() {
    let out = pick_categories(&cfg(), &[C::DnsRules]);
    assert_eq!(out["dnsRules"][0]["id"], json!("r1"));
    assert_eq!(out["dnsRuleOrder"], json!(["r1"]));
    assert!(out.get("trafficRules").is_none());
    assert_eq!(out["customRuleSets"][0]["id"], json!("rs1"));
    assert_eq!(out["ruleResources"][0]["id"], json!("res1"));
    assert!(out.get("dnsServers").is_some());
    assert!(out.get("dnsServerGroups").is_some());
    assert!(out.get("dnsDefaults").is_some());
}

#[test]
fn dns_only_v4_backup_round_trips_without_shared_policy_projection() {
    let current = cfg();
    let backup = pick_categories(&current, &[C::DnsRules]);
    assert!(backup.get("policyRules").is_none());

    let mut target = current.clone();
    target["dnsRules"] = json!([]);
    target["dnsRuleOrder"] = json!([]);
    let out = merge_categories(&target, &backup, &[C::DnsRules]);

    assert_eq!(out.config["dnsRules"], current["dnsRules"]);
    assert_eq!(out.config["dnsRuleOrder"], current["dnsRuleOrder"]);
    assert_eq!(out.config["customRuleSets"], current["customRuleSets"]);
    assert_eq!(out.config["ruleResources"], current["ruleResources"]);
    assert!(out.skipped.is_empty());
}

#[test]
fn pick_dns_resources_without_rules_is_supported() {
    let out = pick_categories(&cfg(), &[C::DnsResources]);
    assert_eq!(out["dnsServers"].as_array().map(Vec::len), Some(3));
    assert_eq!(out["dnsServerGroups"].as_array().map(Vec::len), Some(1));
    assert!(out.get("dnsDefaults").is_some());
    assert!(out.get("policyRules").is_none());
    assert!(out.get("routeRuleOrder").is_none());
}

#[test]
fn general_settings_excludes_policy_and_dns_data() {
    let out = pick_categories(&cfg(), &[C::GeneralSettings]);
    for key in [
        "configSchemaVersion",
        "policyRules",
        "trafficRules",
        "dnsRules",
        "customRules",
        "routeRuleOrder",
        "dnsRuleOrder",
        "dnsServers",
        "dnsServerGroups",
        "dnsDefaults",
        "routeDefaults",
    ] {
        assert!(out.get(key).is_none(), "{key} 不得偷渡进通用设置");
    }
}

#[test]
fn pick_custom_rule_sets_defaults_to_empty_array() {
    // TS: out.customRuleSets = config.customRuleSets ?? [] → 恒发射
    let c = json!({ "customRules": [{ "id": "r1" }] });
    let out = pick_categories(&c, &[C::CustomRules]);
    assert_eq!(out["customRuleSets"], json!([]));
}

#[test]
fn pick_app_rules_family_together() {
    let out = pick_categories(&cfg(), &[C::AppRules]);
    assert!(out.get("appRules").is_some());
    assert_eq!(out["appRulesSeeded"], json!(true));
    assert!(
        out.get("customAppPresets").is_some(),
        "自定义预设随应用分流同进同出"
    );
}

#[test]
fn pick_multi_node_classes_union() {
    let out = pick_categories(&cfg(), &[C::ManualNodes, C::MeshNodes]);
    let ids: Vec<&str> = out["servers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["m1", "m2", "w1", "t1"]);
}

#[test]
fn pick_nothing_selected_is_empty() {
    assert_eq!(pick_categories(&cfg(), &[]), json!({}));
}

// ── mergeCategories：整类替换 ──

#[test]
fn merge_replaces_selected_class_only() {
    let current = cfg();
    let backup = json!({ "servers": [{ "id": "nm1", "protocol": "vmess" }] });
    let out = merge_categories(&current, &backup, &[C::ManualNodes]);
    let ids: Vec<&str> = servers(&out.config)
        .iter()
        .map(|s| s["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        vec!["nm1", "w1", "t1", "s1"],
        "手动类被替换，组网/订阅节点保留"
    );
    assert!(out.skipped.is_empty());
}

#[test]
fn merge_empty_class_is_skipped_not_wiped() {
    // 红线：选了但备份该类为空 → 保留 current，记 skipped，绝不空覆盖
    let current = cfg();
    let backup = json!({ "servers": [] });
    let out = merge_categories(&current, &backup, &[C::ManualNodes, C::MeshNodes]);
    let ids: Vec<&str> = servers(&out.config)
        .iter()
        .map(|s| s["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["m1", "m2", "w1", "t1", "s1"], "全保留");
    assert_eq!(out.skipped, vec![C::ManualNodes, C::MeshNodes]);
}

#[test]
fn merge_unselected_class_untouched() {
    let current = cfg();
    let backup = json!({
        "servers": [{ "id": "nm1", "protocol": "vmess" }],
        "customRules": [{ "id": "nr1", "type": "domain" }],
    });
    let out = merge_categories(&current, &backup, &[C::ManualNodes]);
    assert_eq!(
        out.config["customRules"][0]["id"],
        json!("r1"),
        "未选规则类 → current 原样"
    );
}

#[test]
fn merge_subscriptions_source_and_nodes_together() {
    let current = cfg();
    let backup = json!({
        "servers": [{ "id": "ns1", "protocol": "vless", "subscriptionId": "nsub" }],
        "subscriptions": [{ "id": "nsub" }],
    });
    let out = merge_categories(&current, &backup, &[C::Subscriptions]);
    assert_eq!(out.config["subscriptions"][0]["id"], json!("nsub"));
    let sub_ids: Vec<&str> = servers(&out.config)
        .iter()
        .filter(|s| classify_server(s) == NodeCategory::Subscription)
        .map(|s| s["id"].as_str().unwrap())
        .collect();
    assert_eq!(sub_ids, vec!["ns1"]);
}

#[test]
fn merge_subscriptions_offline_nodes_only_still_applies() {
    // 备份只有展开节点、无订阅源 → 仍算有数据（离线恢复），subscriptions 置 []
    let current = cfg();
    let backup =
        json!({ "servers": [{ "id": "ns1", "protocol": "vless", "subscriptionId": "nsub" }] });
    let out = merge_categories(&current, &backup, &[C::Subscriptions]);
    assert_eq!(out.config["subscriptions"], json!([]));
    assert!(out.skipped.is_empty());
}

#[test]
fn merge_subscriptions_empty_is_skipped() {
    let current = cfg();
    let backup = json!({ "servers": [], "subscriptions": [] });
    let out = merge_categories(&current, &backup, &[C::Subscriptions]);
    assert_eq!(out.skipped, vec![C::Subscriptions]);
    assert_eq!(
        out.config["subscriptions"][0]["id"],
        json!("sub1"),
        "current 订阅源保留"
    );
}

#[test]
fn merge_custom_rules_family_replaced_together() {
    let current = cfg();
    let backup = json!({ "customRules": [{ "id": "nr1", "type": "domain" }] });
    let out = merge_categories(&current, &backup, &[C::CustomRules]);
    assert_eq!(out.config["customRules"][0]["id"], json!("nr1"));
    assert_eq!(
        out.config["customRuleSets"],
        json!([]),
        "同族整类替换（备份无 → 置空）"
    );
    assert_eq!(
        out.config["ruleResources"],
        json!([]),
        "同族整类替换（备份无 → 置空）"
    );
    assert_eq!(out.config["policyRules"][0]["id"], json!("nr1"));
    assert_eq!(out.config["customRules"], out.config["policyRules"]);
}

#[test]
fn merge_v2_dns_rules_and_dns_resources_together() {
    let current = cfg();
    let backup = json!({
        "configSchemaVersion": 2,
        "policyRules": [{ "id": "dns-only", "type": "domain", "values": ["x.example"], "action": "direct", "enabled": true,
            "effects": { "dns": { "enabled": true, "resolver": "direct", "answerMode": "real",
            "action": { "type": "server", "serverId": "dns-new" } } } }],
        "routeRuleOrder": [],
        "dnsRuleOrder": ["dns-only"],
        "dnsServers": [{ "id": "dns-new", "name": "New", "enabled": true, "type": "udp", "outbound": { "type": "direct" } }],
        "dnsServerGroups": [],
        "dnsDefaults": { "directServerId": "dns-new", "proxyServerId": "dns-new", "unmatchedAction": { "type": "server", "serverId": "dns-new" } },
        "customRuleSets": [{ "id": "dns-rs" }],
        "ruleResources": [{ "id": "dns-res" }],
    });
    let out = merge_categories(&current, &backup, &[C::DnsRules]);
    assert_eq!(out.config["dnsRules"][0]["id"], json!("dns-only"));
    assert_eq!(out.config["dnsRuleOrder"], json!(["dns-only"]));
    assert_eq!(out.config["trafficRules"][0]["id"], json!("r1"));
    assert_eq!(out.config["customRuleSets"][0]["id"], json!("dns-rs"));
    assert_eq!(out.config["ruleResources"][0]["id"], json!("dns-res"));
    assert_eq!(out.config["dnsServers"][0]["id"], json!("dns-new"));
    assert_eq!(
        out.config["dnsDefaults"]["directServerId"],
        json!("dns-new")
    );
    assert!(out.skipped.is_empty());
}

#[test]
fn merge_legacy_rules_migrates_policy_shape_without_overwriting_dns_resources() {
    let current = cfg();
    let backup = json!({
        "customRules": [{
            "id": "legacy", "type": "domain", "values": ["legacy.example"], "action": "direct", "enabled": true,
            "effects": { "dns": { "resolver": "proxy", "answerMode": "real" } }
        }]
    });
    let out = merge_categories(&current, &backup, &[C::DnsRules]);
    assert_eq!(out.config["dnsRules"][0]["id"], json!("legacy"));
    assert_eq!(out.config["dnsRuleOrder"], json!(["legacy"]));
    assert_eq!(
        out.config["dnsRules"][0]["effects"]["dns"]["action"]["serverId"],
        json!("builtin-remote")
    );
    assert_eq!(
        out.config["dnsServers"][2]["id"],
        json!("dns-custom"),
        "旧仅规则备份生成的默认 DNS 资源不能覆盖本机资源"
    );
}

#[test]
fn merge_custom_rules_via_rule_sets_only() {
    // 只有 ruleSets 也算有数据
    let current = cfg();
    let backup = json!({ "customRuleSets": [{ "id": "nrs1" }] });
    let out = merge_categories(&current, &backup, &[C::CustomRules]);
    assert_eq!(out.config["customRules"], json!([]));
    assert_eq!(out.config["customRuleSets"][0]["id"], json!("nrs1"));
    assert!(out.skipped.is_empty());
}

#[test]
fn merge_custom_rules_empty_is_skipped() {
    let current = cfg();
    let backup = json!({ "customRules": [], "customRuleSets": [] });
    let out = merge_categories(&current, &backup, &[C::CustomRules]);
    assert_eq!(out.skipped, vec![C::CustomRules]);
    assert_eq!(
        out.config["customRules"][0]["id"],
        json!("r1"),
        "current 规则保留"
    );
}

#[test]
fn merge_dns_resources_can_be_selected_independently() {
    let current = cfg();
    let backup = json!({
        "dnsServers": [{ "id": "only", "name": "Only", "enabled": true, "type": "udp", "outbound": { "type": "direct" } }],
        "dnsServerGroups": [],
        "dnsDefaults": { "directServerId": "only", "proxyServerId": "only", "unmatchedAction": { "type": "server", "serverId": "only" } }
    });
    let out = merge_categories(&current, &backup, &[C::DnsResources]);
    assert_eq!(out.config["dnsServers"][0]["id"], json!("only"));
    assert_eq!(out.config["policyRules"][0]["id"], json!("r1"));
    assert!(out.skipped.is_empty());
}

#[test]
fn merge_empty_dns_resources_is_skipped_not_wiped() {
    let current = cfg();
    let backup = json!({ "dnsServers": "oops", "dnsServerGroups": "oops" });
    let out = merge_categories(&current, &backup, &[C::DnsResources]);
    assert_eq!(out.skipped, vec![C::DnsResources]);
    assert_eq!(out.config["dnsServers"][2]["id"], json!("dns-custom"));
}

#[test]
fn merge_app_rules_family() {
    let current = cfg();
    let backup = json!({ "appRules": [{ "id": "na1" }], "appRulesSeeded": false });
    let out = merge_categories(&current, &backup, &[C::AppRules]);
    assert_eq!(out.config["appRules"][0]["id"], json!("na1"));
    assert_eq!(out.config["appRulesSeeded"], json!(false));
    assert_eq!(out.config["customAppPresets"], json!([]));
}

#[test]
fn merge_app_rules_empty_is_skipped() {
    let current = cfg();
    let out = merge_categories(&current, &json!({ "appRules": [] }), &[C::AppRules]);
    assert_eq!(out.skipped, vec![C::AppRules]);
    assert_eq!(out.config["appRules"][0]["id"], json!("a1"));
}

#[test]
fn merge_general_settings_by_exclusion() {
    let current = cfg();
    let backup = json!({ "proxyMode": "global", "brandNew2099": 7 });
    let out = merge_categories(&current, &backup, &[C::GeneralSettings]);
    assert_eq!(out.config["proxyMode"], json!("global"));
    assert_eq!(
        out.config["brandNew2099"],
        json!(7),
        "未知设置键自动进通用类"
    );
    assert!(out.skipped.is_empty());
}

#[test]
fn merge_general_settings_empty_is_skipped() {
    let current = cfg();
    let backup = json!({ "servers": [{ "id": "x", "protocol": "vless" }] }); // 只有数据键
    let out = merge_categories(&current, &backup, &[C::GeneralSettings]);
    assert_eq!(out.skipped, vec![C::GeneralSettings]);
    assert_eq!(
        out.config["proxyMode"],
        json!("rule"),
        "current 通用设置保留"
    );
}

#[test]
fn merge_general_settings_ignores_excluded_keys_in_backup() {
    // 手工塞了 clashApiSecret 的备份文件不应把本机凭据覆盖掉
    let current = cfg();
    let backup = json!({ "clashApiSecret": "EVIL", "proxyMode": "global" });
    let out = merge_categories(&current, &backup, &[C::GeneralSettings]);
    assert_eq!(
        out.config["clashApiSecret"],
        json!("SUPERSECRET"),
        "current 本机凭据不被备份覆盖"
    );
}

// ── mergeCategories：selectedServerId 兜底 ──

#[test]
fn merge_clears_dangling_selected_server_id() {
    // 导入手动节点后 m1 不复存在 → 归零（validate_config 对失效引用是 Err、非归零）
    let current = cfg();
    let backup = json!({ "servers": [{ "id": "nm1", "protocol": "vmess" }] });
    let out = merge_categories(&current, &backup, &[C::ManualNodes]);
    assert_eq!(out.config["selectedServerId"], Value::Null);
}

#[test]
fn merge_keeps_still_valid_selected_server_id() {
    let current = cfg();
    let backup = json!({ "servers": [{ "id": "m1", "protocol": "vmess" }] });
    let out = merge_categories(&current, &backup, &[C::ManualNodes]);
    assert_eq!(out.config["selectedServerId"], json!("m1"));
}

#[test]
fn merge_keeps_direct_sentinel() {
    // __direct__ 哨兵不是节点 id，不该被归零
    let mut current = cfg();
    current["selectedServerId"] = json!("__direct__");
    let backup = json!({ "servers": [{ "id": "nm1", "protocol": "vmess" }] });
    let out = merge_categories(&current, &backup, &[C::ManualNodes]);
    assert_eq!(out.config["selectedServerId"], json!("__direct__"));
}

#[test]
fn merge_keeps_null_selected_server_id() {
    let mut current = cfg();
    current["selectedServerId"] = Value::Null;
    let out = merge_categories(
        &current,
        &json!({ "servers": [{ "id": "n", "protocol": "vless" }] }),
        &[C::ManualNodes],
    );
    assert_eq!(out.config["selectedServerId"], Value::Null);
}

#[test]
fn merge_node_order_is_manual_mesh_subscription() {
    // servers[] 重建顺序固定：手动 → 组网 → 订阅（决定性输出，避免导入后节点乱序）
    let current = cfg();
    let out = merge_categories(&current, &json!({}), &[]);
    let ids: Vec<&str> = servers(&out.config)
        .iter()
        .map(|s| s["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["m1", "m2", "w1", "t1", "s1"]);
}

#[test]
fn merge_nothing_selected_is_identity_on_servers() {
    let current = cfg();
    let out = merge_categories(
        &current,
        &json!({ "servers": [{ "id": "x", "protocol": "vless" }] }),
        &[],
    );
    assert_eq!(servers(&out.config).len(), 5);
    assert!(out.skipped.is_empty());
}

// ── 往返：pick → merge ──

#[test]
fn roundtrip_pick_then_merge_restores_class() {
    let source = cfg();
    let exported = pick_categories(&source, &[C::ManualNodes, C::MeshNodes]);
    let empty = json!({ "servers": [], "selectedServerId": null });
    let out = merge_categories(&empty, &exported, &[C::ManualNodes, C::MeshNodes]);
    let ids: Vec<&str> = servers(&out.config)
        .iter()
        .map(|s| s["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["m1", "m2", "w1", "t1"]);
    assert!(out.skipped.is_empty());
}

// ── parseBackupContent ──

#[test]
fn parse_new_format() {
    let raw =
        r#"{"version":"1.0","appVersion":"0.1.0","platform":"darwin","config":{"servers":[]}}"#;
    let p = parse_backup_content(raw).unwrap();
    assert_eq!(p.platform.as_deref(), Some("darwin"));
    assert_eq!(p.config["servers"], json!([]));
}

#[test]
fn parse_legacy_bare_user_config() {
    let raw = r#"{"servers":[{"id":"m1","protocol":"vless"}],"proxyMode":"rule"}"#;
    let p = parse_backup_content(raw).unwrap();
    assert_eq!(p.platform, None, "旧备份无 platform → 视为同平台");
    assert_eq!(p.config["servers"][0]["id"], json!("m1"));
}

#[test]
fn parse_rejects_bad_json_and_bad_shape() {
    assert_eq!(
        parse_backup_content("not json").unwrap_err(),
        "invalid_json"
    );
    assert_eq!(
        parse_backup_content(r#"{"hello":"world"}"#).unwrap_err(),
        "invalid_format"
    );
}

#[test]
fn parse_new_format_without_platform() {
    let raw = r#"{"version":"1.0","config":{"servers":[]}}"#;
    assert_eq!(parse_backup_content(raw).unwrap().platform, None);
}

// ── 跨平台 sanitize ──

#[test]
fn cross_platform_disables_process_rules() {
    let mut c = json!({ "customRules": [
        { "id": "r1", "type": "processName", "values": ["chrome.exe"] },
        { "id": "r2", "type": "domain", "values": ["a.com"] },
        { "id": "r3", "type": "domain", "conditions": [{ "type": "processPath", "values": ["/x"] }] },
    ]});
    let n = sanitize_cross_platform_rules(&mut c, Some("win32"), "darwin");
    assert_eq!(n, 2, "首条件镜像 + 多条件承载都算");
    assert_eq!(c["customRules"][0]["enabled"], json!(false));
    assert!(
        c["customRules"][1].get("enabled").is_none(),
        "非进程规则不动"
    );
    assert_eq!(c["customRules"][2]["enabled"], json!(false));
}

#[test]
fn cross_platform_sanitizes_authoritative_policy_rules_and_syncs_mirror() {
    let mut c = json!({
        "policyRules": [{ "id": "p1", "type": "processName", "values": ["chrome.exe"] }],
        "customRules": [{ "id": "stale", "type": "domain", "values": ["stale.example"] }]
    });
    let n = sanitize_cross_platform_rules(&mut c, Some("win32"), "darwin");
    assert_eq!(n, 1);
    assert_eq!(c["policyRules"][0]["enabled"], json!(false));
    assert_eq!(c["customRules"], c["policyRules"]);
}

#[test]
fn cross_platform_noop_on_same_platform_or_legacy() {
    let base = json!({ "customRules": [{ "id": "r1", "type": "processName" }] });
    let mut a = base.clone();
    assert_eq!(
        sanitize_cross_platform_rules(&mut a, Some("darwin"), "darwin"),
        0
    );
    assert!(a["customRules"][0].get("enabled").is_none());
    let mut b = base.clone();
    assert_eq!(
        sanitize_cross_platform_rules(&mut b, None, "darwin"),
        0,
        "旧备份无 platform → 不动"
    );
    assert!(b["customRules"][0].get("enabled").is_none());
}

#[test]
fn cross_platform_skips_already_disabled() {
    let mut c = json!({ "customRules": [{ "id": "r1", "type": "processName", "enabled": false }] });
    assert_eq!(
        sanitize_cross_platform_rules(&mut c, Some("win32"), "linux"),
        0,
        "已禁用不重复计数"
    );
}

#[test]
fn cross_platform_tolerates_missing_rules() {
    let mut c = json!({});
    assert_eq!(
        sanitize_cross_platform_rules(&mut c, Some("win32"), "linux"),
        0
    );
    let mut c2 = json!({ "customRules": "oops" });
    assert_eq!(
        sanitize_cross_platform_rules(&mut c2, Some("win32"), "linux"),
        0
    );
}

#[test]
fn unavailable_interface_bindings_are_sanitized_only_in_selected_categories() {
    let mut c = json!({
        "networkInterfaces": { "direct": "en0", "proxy": "utun9" },
        "subscriptions": [
            { "id": "sub1", "proxyBindInterface": "Wi-Fi" }
        ],
        "servers": [
            { "id": "manual", "protocol": "vless", "bindInterface": "Ethernet" },
            { "id": "mesh", "protocol": "wireguard", "bindInterface": "en0" },
            {
                "id": "sub-node", "protocol": "vless", "subscriptionId": "sub1",
                "bindInterface": "Wi-Fi"
            }
        ]
    });
    let available = BTreeSet::from(["en0".to_string()]);

    let cleared = sanitize_unavailable_interface_bindings(
        &mut c,
        &available,
        &[C::GeneralSettings, C::Subscriptions],
    );

    assert_eq!(cleared, 3);
    assert_eq!(c["networkInterfaces"], json!({ "direct": "en0" }));
    assert!(c["subscriptions"][0].get("proxyBindInterface").is_none());
    assert!(c["servers"][2].get("bindInterface").is_none());
    assert_eq!(c["servers"][0]["bindInterface"], json!("Ethernet"));
    assert_eq!(c["servers"][1]["bindInterface"], json!("en0"));
}

#[test]
fn unavailable_interface_sanitizer_does_nothing_when_enumeration_failed() {
    let mut c = json!({
        "networkInterfaces": { "direct": "en0", "proxy": "Wi-Fi" },
        "servers": [{ "id": "manual", "protocol": "vless", "bindInterface": "Ethernet" }]
    });
    let before = c.clone();

    assert_eq!(
        sanitize_unavailable_interface_bindings(
            &mut c,
            &BTreeSet::new(),
            &[C::GeneralSettings, C::ManualNodes],
        ),
        0
    );
    assert_eq!(c, before);
}

// ── BackupInfo ──

#[test]
fn build_info_counts() {
    let i = build_backup_info(&cfg(), 0);
    assert_eq!(i.server_count, 5);
    assert_eq!(i.manual_server_count, 2);
    assert_eq!(i.mesh_server_count, 2);
    assert_eq!(i.subscription_count, 1);
    assert_eq!(i.rule_count, 1);
    assert_eq!(i.rule_set_count, 1);
    assert_eq!(i.app_rule_count, 1);
    assert_eq!(i.cross_platform_disabled_rules, None, "0 → 不发射");
}

#[test]
fn build_info_serializes_camel_case_and_omits_zero_cross_platform() {
    let s = serde_json::to_value(build_backup_info(&cfg(), 0)).unwrap();
    assert_eq!(s["serverCount"], json!(5));
    assert_eq!(s["manualServerCount"], json!(2));
    assert_eq!(s["meshServerCount"], json!(2));
    assert_eq!(s["subscriptionCount"], json!(1));
    assert_eq!(s["ruleCount"], json!(1));
    assert_eq!(s["ruleSetCount"], json!(1));
    assert_eq!(s["appRuleCount"], json!(1));
    assert!(s.get("crossPlatformDisabledRules").is_none());
    let s2 = serde_json::to_value(build_backup_info(&cfg(), 3)).unwrap();
    assert_eq!(s2["crossPlatformDisabledRules"], json!(3));
}

// ── 契约锁 ──

#[test]
fn backup_categories_order_matches_frontend() {
    // 顺序是契约：ui/src/shared/backup-categories.ts 的 BACKUP_CATEGORIES 同序；
    // SettingsBackup.tsx 按此序渲染勾选行、detect_categories 按此序返回。
    let names: Vec<&str> = BACKUP_CATEGORIES.iter().map(|c| c.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "manualNodes",
            "meshNodes",
            "subscriptions",
            "customRules",
            "dnsRules",
            "dnsResources",
            "appRules",
            "generalSettings"
        ]
    );
}

#[test]
fn category_str_roundtrip() {
    for cat in BACKUP_CATEGORIES {
        assert_eq!(BackupCategory::from_wire(cat.as_str()), Some(cat));
    }
    assert_eq!(BackupCategory::from_wire("nope"), None);
    assert_eq!(BackupCategory::from_wire("ManualNodes"), None, "大小写敏感");
}

#[test]
fn category_serializes_to_frontend_string() {
    assert_eq!(
        serde_json::to_value(vec![C::ManualNodes, C::GeneralSettings]).unwrap(),
        json!(["manualNodes", "generalSettings"])
    );
}

#[test]
fn data_fields_and_excluded_are_disjoint() {
    for f in DATA_FIELDS {
        assert!(
            !EXCLUDED_FROM_BACKUP.contains(&f),
            "{f} 同时在两表里，语义冲突"
        );
    }
}
