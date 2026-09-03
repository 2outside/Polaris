use super::*;

#[test]
fn bad_json_returns_parse_err() {
    let res = sanitize_config("{ not valid json");
    assert!(matches!(res, Err(crate::StoreError::Parse(_))));
}

#[test]
fn bad_field_skipped_good_field_kept() {
    // servers 是 string（坏字段）→ 删除；但 customRules 合法 → 保留。
    // 绝不因 servers 坏而丢弃整份配置（维度7 #7 核心）。
    let json = r#"{
        "proxyMode": "global",
        "proxyModeType": "systemProxy",
        "servers": "not-an-array",
        "customRules": [
            {"id":"r1","type":"domain","values":["a.com"],"action":"proxy","enabled":true}
        ],
        "mixedPort": "bad-port"
    }"#;
    let v = sanitize_config(json).unwrap();
    let obj = v.as_object().unwrap();
    // 坏字段已删
    assert!(!obj.contains_key("servers"));
    assert!(!obj.contains_key("mixedPort"));
    // 好字段保留
    assert_eq!(obj["proxyMode"], "global");
    assert_eq!(obj["customRules"].as_array().unwrap().len(), 1);
}

#[test]
fn bad_server_dropped_good_server_kept() {
    let json = r#"{
        "proxyMode": "global",
        "proxyModeType": "tun",
        "servers": [
            {"id":"good","name":"Good","protocol":"trojan","address":"1.2.3.4","port":443,"password":"pw"},
            {"id":"","name":"Bad","protocol":"trojan"},
            {"id":"unknown-proto","name":"X","protocol":"nonexistent","address":"5.6.7.8","port":80}
        ]
    }"#;
    let v = sanitize_config(json).unwrap();
    let servers = v["servers"].as_array().unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0]["id"], "good");
}

#[test]
fn bool_field_bad_removed() {
    let json = r#"{
        "proxyMode": "direct",
        "proxyModeType": "manual",
        "appRoutingEnabled": "yes",
        "singboxDashboard": 1,
        "keepTrayMenuWarm": "yes",
        "hardwareAcceleration": true
    }"#;
    let v = sanitize_config(json).unwrap();
    let obj = v.as_object().unwrap();
    assert!(!obj.contains_key("appRoutingEnabled"));
    assert!(!obj.contains_key("singboxDashboard"));
    assert!(!obj.contains_key("keepTrayMenuWarm"));
    assert_eq!(obj["hardwareAcceleration"], Value::Bool(true));
}

#[test]
fn update_channels_share_the_stable_prerelease_value_domain() {
    let valid =
        sanitize_config(r#"{"appUpdateChannel":"prerelease","coreUpdateChannel":"stable"}"#)
            .unwrap();
    assert_eq!(valid["appUpdateChannel"], "prerelease");
    assert_eq!(valid["coreUpdateChannel"], "stable");

    let invalid =
        sanitize_config(r#"{"appUpdateChannel":"nightly","coreUpdateChannel":true}"#).unwrap();
    assert!(invalid.get("appUpdateChannel").is_none());
    assert!(invalid.get("coreUpdateChannel").is_none());
}

#[test]
fn legacy_domain_rule_preserved_garbage_dropped() {
    // 项1：无 `type` + `domains` 数组的旧 DomainRule 不被 sanitize 丢弃（原样留待 migrate 转 Rule）；
    // 无 type 且**无 domains** 的纯垃圾条目仍照丢。判据复用 migrate::is_legacy_domain_rule（单一真值）。
    let json = r#"{
        "proxyMode":"global","proxyModeType":"systemProxy",
        "customRules":[
            {"id":"legacy","domains":["a.com"],"action":"proxy","enabled":true},
            {"id":"garbage","action":"proxy","enabled":true}
        ]
    }"#;
    let v = sanitize_config(json).unwrap();
    let rules = v["customRules"].as_array().unwrap();
    assert_eq!(rules.len(), 1, "旧 DomainRule 保留、纯垃圾丢弃");
    assert_eq!(rules[0]["id"], "legacy");
    assert!(
        rules[0].get("type").is_none(),
        "sanitize 不给旧规则补 type（交 migrate 处理）"
    );
}

#[test]
fn rule_effects_are_preserved_and_malformed_branches_degrade_independently() {
    let json = r#"{
        "proxyMode":"smart","proxyModeType":"tun",
        "customRules":[
            {"id":"dns-only","type":"domain","values":["a.com"],"action":"direct","enabled":true,
             "effects":{"dns":{"resolver":"proxy","answerMode":"real"}}},
            {"id":"mixed","type":"domainSuffix","values":["example.com"],"action":"proxy","enabled":true,
             "effects":{"route":{"action":"proxy","targetServerId":7},
                        "dns":{"resolver":"direct","answerMode":"fakeIp"}}},
            {"id":"fallback","type":"domain","values":["b.com"],"action":"direct","enabled":true,
             "effects":"bad"}
        ]
    }"#;
    let value = sanitize_config(json).unwrap();
    let rules = value["customRules"].as_array().unwrap();
    assert_eq!(rules[0]["effects"]["dns"]["resolver"], "proxy");
    assert_eq!(rules[1]["effects"]["route"]["action"], "proxy");
    assert!(rules[1]["effects"]["route"].get("targetServerId").is_none());
    assert_eq!(rules[1]["effects"]["dns"]["answerMode"], "fakeIp");
    assert!(rules[2].get("effects").is_none());
}

#[test]
fn dns_policy_v2_drops_bad_items_without_losing_good_resources_or_rules() {
    let json = r#"{
        "proxyMode":"smart","proxyModeType":"tun",
        "policyRules":[
            {"id":"good","type":"domain","values":["a.example"],"action":"direct","enabled":true,
             "effects":{"dns":{"resolver":"direct","answerMode":"real",
             "action":{"type":"server","serverId":"dns-good"}}}},
            {"id":"degrade","type":"domain","values":["b.example"],"action":"direct","enabled":true,
             "effects":{"dns":{"resolver":"direct","answerMode":"real",
             "action":{"type":"unknown"}}}}
        ],
        "routeRuleOrder":["good",7,"good","degrade"],
        "dnsServers":[
            {"id":"dns-good","name":"Good","enabled":true,"type":"https",
             "endpoint":{"host":"1.1.1.1","port":443,"path":"/dns-query"},
             "outbound":{"type":"direct"}},
            {"id":"dns-bad","enabled":true,"type":"https",
             "endpoint":{"host":"1.1.1.1","port":"bad"},"outbound":{"type":"direct"}},
            {"id":"dns-good","enabled":true,"type":"local","outbound":{"type":"direct"}}
        ],
        "dnsServerGroups":[
            {"id":"race","name":"Race","enabled":true,"mode":"race","members":["dns-good"]},
            {"id":"bad","name":"Bad","enabled":true,"mode":"unknown","members":[]}
        ]
    }"#;
    let value = sanitize_config(json).unwrap();
    assert_eq!(value["policyRules"].as_array().unwrap().len(), 2);
    assert_eq!(
        value["policyRules"][0]["effects"]["dns"]["action"]["serverId"],
        "dns-good"
    );
    assert!(value["policyRules"][1]["effects"]["dns"]
        .get("action")
        .is_none());
    assert_eq!(
        value["routeRuleOrder"],
        serde_json::json!(["good", "degrade"])
    );
    assert_eq!(value["dnsServers"].as_array().unwrap().len(), 1);
    assert_eq!(value["dnsServerGroups"].as_array().unwrap().len(), 1);
}

#[test]
fn root_non_object_is_error() {
    let res = sanitize_config("[1,2,3]");
    assert!(matches!(res, Err(crate::StoreError::Validation(_))));
}

#[test]
fn empty_input_is_error() {
    let res = sanitize_config("");
    assert!(matches!(res, Err(crate::StoreError::Parse(_))));
}
