use super::*;
use serde_json::json;

fn base_config() -> Value {
    json!({
        "proxyMode": "global",
        "proxyModeType": "tun",
        "logLevel": "info",
        "mixedPort": 7890,
        "tunConfig": {"mtu": 1350, "stack": "system", "autoRoute": true, "strictRoute": true}
    })
}

#[test]
fn migrate_legacy_domain_rule_produces_new_rules() {
    let mut v = base_config();
    v["customRules"] = json!([
        {"id":"old1","domains":["*.google.com","geosite:google"],"ipCidr":["10.0.0.0/8"],"action":"proxy","enabled":true}
    ]);
    migrate_custom_rules_domain_rule(&mut v);
    let rules = v["customRules"].as_array().unwrap();
    // 拆为 domainSuffix + geosite + ipCidr 三条
    assert!(rules.len() >= 2);
    let types: Vec<&str> = rules.iter().map(|r| r["type"].as_str().unwrap()).collect();
    assert!(types.contains(&"domainSuffix"));
    assert!(types.contains(&"geosite"));
    assert!(types.contains(&"ipCidr"));
}

#[test]
fn migrate_custom_rules_idempotent() {
    let mut v = base_config();
    v["customRules"] = json!([
        {"id":"old1","domains":["a.com"],"action":"proxy","enabled":true}
    ]);
    migrate_custom_rules_domain_rule(&mut v);
    let after_first = v["customRules"].clone();
    migrate_custom_rules_domain_rule(&mut v);
    assert_eq!(v["customRules"], after_first, "二次迁移不变");
}

#[test]
fn migrate_custom_rule_effects_preserves_legacy_mirrors_and_is_idempotent() {
    let mut value = base_config();
    value["customRules"] = json!([
        {"id":"dns","type":"domainSuffix","values":["example.com"],"action":"proxy",
         "targetServerId":"node-1","enabled":true,"bypassFakeIP":true},
        {"id":"network","type":"ipCidr","values":["10.0.0.0/8"],"action":"direct",
         "enabled":true,"bypassFakeIP":true},
        {"id":"new","type":"domain","values":["new.example"],"action":"direct","enabled":true,
         "effects":{"dns":{"resolver":"proxy","answerMode":"fakeIp"}}}
    ]);

    assert!(migrate_custom_rule_effects(&mut value));
    let rules = value["customRules"].as_array().unwrap();
    assert_eq!(rules[0]["effects"]["route"]["action"], "proxy");
    assert_eq!(rules[0]["effects"]["route"]["targetServerId"], "node-1");
    assert_eq!(rules[0]["effects"]["dns"]["resolver"], "inherit");
    assert_eq!(rules[0]["action"], "proxy", "旧动作镜像必须保留");
    assert!(rules[1]["effects"].get("dns").is_none());
    assert!(
        rules[2]["effects"].get("route").is_none(),
        "新模型不得被覆盖"
    );
    let once = value["customRules"].clone();
    assert!(!migrate_custom_rule_effects(&mut value));
    assert_eq!(value["customRules"], once);
}

#[test]
fn dns_policy_v2_materializes_servers_orders_and_legacy_resolve_semantics() {
    let mut value = json!({
        "proxyMode": "smart",
        "proxyModeType": "tun",
        "resolveBeforeDial": false,
        "dnsConfig": {
            "enableFakeIp": false,
            "domesticDns": "https://223.5.5.5/dns-query",
            "foreignDns": "https://1.1.1.1/dns-query"
        },
        "customRules": [
            {"id":"mixed","type":"domain","values":["mixed.example"],"action":"proxy",
             "enabled":true,"bypassFakeIP":true},
            {"id":"dns-only","type":"domainSuffix","values":["dns.example"],"action":"direct",
             "enabled":true,"effects":{"dns":{"resolver":"proxy","answerMode":"real"}}}
        ]
    });
    assert!(migrate_custom_rule_effects(&mut value));
    assert!(migrate_dns_policy_v2(&mut value));

    assert_eq!(value["configSchemaVersion"], 2);
    assert_eq!(value["routeRuleOrder"], json!(["mixed", "dns-only"]));
    assert_eq!(value["dnsRuleOrder"], json!(["mixed", "dns-only"]));
    assert_eq!(value["dnsServers"][0]["id"], "builtin-domestic");
    assert_eq!(value["dnsServers"][1]["id"], "builtin-remote");
    assert_eq!(
        value["dnsDefaults"]["unmatchedAction"],
        json!({"type":"server","serverId":"builtin-remote"}),
        "smart + 正向 + legacy FakeIP off 的未命中查询原本走远程 DNS"
    );
    assert_eq!(
        value["policyRules"][0]["effects"]["route"]["destinationResolution"]["mode"],
        "dnsRules"
    );
    assert_eq!(
        value["policyRules"][1]["effects"]["dns"]["migratedImplicitResolve"], true,
        "旧版 DNS-only 隐式 resolve 必须显式留下兼容标记"
    );
    let once = value.clone();
    assert!(!migrate_dns_policy_v2(&mut value));
    assert_eq!(value, once);
}

#[test]
fn split_policy_rules_preserves_each_plane_and_stable_order() {
    let mut value = json!({
        "configSchemaVersion": 2,
        "policyRules": [
            {"id":"both","type":"domain","values":["both.example"],"action":"proxy",
             "enabled":true,"effects":{
                "route":{"enabled":true,"action":"proxy"},
                "dns":{"enabled":true,"action":{"type":"followRouteDefault"}}
             }},
            {"id":"dns-only","type":"domainSuffix","values":["dns.example"],"action":"direct",
             "enabled":true,"effects":{"dns":{"enabled":true,
                "action":{"type":"server","serverId":"builtin-domestic"},
                "migratedImplicitResolve":true}}},
            {"id":"route-only","type":"ipCidr","values":["10.0.0.0/8"],"action":"direct",
             "enabled":true,"effects":{"route":{"enabled":true,"action":"direct"}}}
        ],
        "routeRuleOrder": ["route-only", "both"],
        "dnsRuleOrder": ["dns-only"]
    });

    assert!(migrate_split_policy_rules(&mut value));
    assert_eq!(value["configSchemaVersion"], 3);
    assert_eq!(
        value["routeRuleOrder"],
        json!(["route-only", "both", "dns-only"])
    );
    assert_eq!(value["dnsRuleOrder"], json!(["dns-only", "both"]));
    assert_eq!(value["trafficRules"].as_array().unwrap().len(), 3);
    assert_eq!(value["dnsRules"].as_array().unwrap().len(), 2);

    let traffic_both = &value["trafficRules"][0];
    assert!(traffic_both["effects"].get("dns").is_none());
    let dns_both = &value["dnsRules"][0];
    assert!(dns_both["effects"].get("route").is_none());
    assert_eq!(
        dns_both["effects"]["dns"]["action"],
        json!({"type":"server","serverId":"builtin-remote"})
    );
    let resolution_only = &value["trafficRules"][1]["effects"]["route"];
    assert_eq!(resolution_only["resolutionOnly"], true);
    assert_eq!(resolution_only["destinationResolution"]["mode"], "dnsRules");
    assert!(value["dnsRules"][1]["effects"]["dns"]
        .get("migratedImplicitResolve")
        .is_none());
    assert_eq!(value["policyRules"], value["trafficRules"]);
    assert_eq!(value["customRules"], value["trafficRules"]);

    let once = value.clone();
    assert!(!migrate_split_policy_rules(&mut value));
    assert_eq!(value, once);
}

#[test]
fn builtin_dns_migration_repairs_invalid_bootstrap_without_overwriting_other_edits() {
    let mut value = json!({
        "dnsServers": [
            {"id":"builtin-domestic","name":"My Domestic","enabled":false,"type":"udp",
             "endpoint":{"host":"192.0.2.53","port":53},"outbound":{"type":"direct"}},
            {"id":"builtin-bootstrap","name":"Invalid","enabled":true,"type":"https",
             "endpoint":{"host":"bootstrap.example","port":443,"path":"/dns-query"},
             "outbound":{"type":"direct"}}
        ]
    });

    assert!(migrate_builtin_dns_resources(&mut value));
    let servers = value["dnsServers"].as_array().unwrap();
    let domestic = servers
        .iter()
        .find(|server| server["id"] == "builtin-domestic")
        .unwrap();
    assert_eq!(domestic["name"], "My Domestic");
    assert_eq!(domestic["endpoint"]["host"], "192.0.2.53");
    assert_eq!(domestic["enabled"], true);
    let bootstrap = servers
        .iter()
        .find(|server| server["id"] == "builtin-bootstrap")
        .unwrap();
    assert_eq!(bootstrap["endpoint"]["host"], "223.5.5.5");
    assert_eq!(bootstrap["outbound"]["type"], "direct");
    assert!(servers
        .iter()
        .any(|server| server["id"] == "builtin-remote"));

    let once = value.clone();
    assert!(!migrate_builtin_dns_resources(&mut value));
    assert_eq!(value, once);
}

#[test]
fn migrate_all_runs_full_chain_idempotent() {
    // 旧格式配置：缺 dnsConfig、stack=system、未 migrated、bypassProcesses 非空、appRulesSeeded 缺
    let mut v = json!({
        "proxyMode": "smart",
        "proxyModeType": "TUN",
        "logLevel": "info",
        "tunConfig": {"mtu": 1350, "stack": "gvisor", "autoRoute": true, "strictRoute": true},
        "bypassProcesses": ["chrome", "chrome", "  "],
        "subscriptionUpdateViaProxy": true,
        "appRules": [{"appId":"apple","action":"proxy","enabled":true}]
    });
    let delta1 = migrate_all(&mut v);
    assert!(delta1.changed, "首次迁移有变更");
    // 验证迁移效果
    assert_eq!(v["tunStackMigrated"], json!(true));
    assert_eq!(v["tunConfig"]["stack"], json!("auto"));
    // MTU 一并抹掉（存量 1350 是程序写的默认，不是用户意图）→ 缺席 = 自动。
    assert_eq!(v["tunMtuMigrated"], json!(true));
    assert!(v["tunConfig"].get("mtu").is_none(), "存量 mtu 应被抹掉");
    assert_eq!(v["subscriptionProxyPolicy"], json!("proxy"));
    assert!(!v
        .as_object()
        .unwrap()
        .contains_key("subscriptionUpdateViaProxy"));
    assert_eq!(v["appRulesSeeded"], json!(true));
    // apple 已下线 → 剔除
    let app_rules = v["appRules"].as_array().unwrap();
    assert!(!app_rules.iter().any(|r| r["appId"] == "apple"));
    // bypassProcesses 已迁移为 processName 规则
    assert_eq!(v["bypassProcesses"], json!([]));
    let custom = v["customRules"].as_array().unwrap();
    assert!(custom
        .iter()
        .any(|r| r["id"] == "migrated_bypass_processes"));
    // dnsConfig 已补齐 + 标记
    assert_eq!(v["dnsConfig"]["fakeIpToggleMigrated"], json!(true));
    assert_eq!(v["dnsConfig"]["nodeResolverMigrated"], json!(true));

    // 二次跑：幂等，无变更（changed 应为 false）
    let snapshot = v.clone();
    let delta2 = migrate_all(&mut v);
    assert_eq!(v, snapshot, "二次迁移完全不变");
    assert!(!delta2.changed, "二次迁移标记无变更");
}

#[test]
fn dns_connection_ownership_moves_default_and_strips_traffic_dns_fields() {
    let mut value = json!({
        "configSchemaVersion": 3,
        "dnsDefaults": {
            "directServerId": "builtin-domestic",
            "proxyServerId": "builtin-remote",
            "unmatchedAction": { "type": "fakeIp" }
        },
        "routeDefaults": { "destinationResolution": "dnsRules" },
        "resolveBeforeDial": false,
        "trafficRules": [
            {
                "id": "route-normal",
                "type": "domain",
                "values": ["example.com"],
                "enabled": true,
                "bypassFakeIP": true,
                "effects": {
                    "route": {
                        "action": "direct",
                        "destinationResolution": { "mode": "preserveDomain" }
                    },
                    "dns": {
                        "enabled": true,
                        "action": { "type": "fakeIp" }
                    }
                }
            },
            {
                "id": "route-resolution-shadow",
                "type": "domainSuffix",
                "values": ["example.net"],
                "enabled": true,
                "effects": {
                    "route": {
                        "action": "direct",
                        "destinationResolution": { "mode": "dnsRules" },
                        "resolutionOnly": true
                    }
                }
            },
            {
                "id": "dns-only-leak",
                "type": "domain",
                "values": ["leaked.example"],
                "enabled": true,
                "effects": {
                    "dns": {
                        "enabled": true,
                        "action": { "type": "server", "serverId": "builtin-domestic" }
                    }
                }
            }
        ],
        "policyRules": [{ "id": "stale-policy" }],
        "customRules": [{ "id": "stale-custom" }],
        "dnsRules": [{
            "id": "dns-rule",
            "type": "domainSuffix",
            "values": ["example.org"],
            "enabled": true,
            "effects": { "dns": { "enabled": true, "action": { "type": "fakeIp" } } }
        }],
        "routeRuleOrder": ["route-resolution-shadow", "dns-only-leak", "missing", "route-normal"],
        "dnsRuleOrder": ["dns-rule"]
    });

    assert!(migrate_dns_connection_ownership(&mut value));
    assert_eq!(value["configSchemaVersion"], json!(4));
    assert_eq!(
        value["dnsDefaults"]["connectionResolution"],
        json!("dnsRules")
    );
    assert_eq!(
        value["dnsDefaults"]["unmatchedAction"]["type"],
        json!("fakeIp"),
        "迁移必须保全 DNS 侧其余默认项"
    );
    assert!(value.get("routeDefaults").is_none());
    assert!(value.get("resolveBeforeDial").is_none());

    let traffic = value["trafficRules"].as_array().unwrap();
    assert_eq!(traffic.len(), 1, "resolutionOnly 影子流量规则必须删除");
    assert_eq!(traffic[0]["id"], json!("route-normal"));
    assert!(traffic[0].get("bypassFakeIP").is_none());
    assert!(traffic[0]["effects"].get("dns").is_none());
    let route = traffic[0]["effects"]["route"].as_object().unwrap();
    assert_eq!(route.get("action"), Some(&json!("direct")));
    assert!(route.get("destinationResolution").is_none());
    assert!(route.get("resolutionOnly").is_none());
    assert_eq!(value["policyRules"], value["trafficRules"]);
    assert_eq!(value["customRules"], value["trafficRules"]);
    assert_eq!(value["routeRuleOrder"], json!(["route-normal"]));
    assert_eq!(value["dnsRules"][0]["id"], json!("dns-rule"));
    assert_eq!(value["dnsRuleOrder"], json!(["dns-rule"]));

    let once = value.clone();
    assert!(!migrate_dns_connection_ownership(&mut value));
    assert_eq!(value, once, "v4 迁移必须幂等");
}

#[test]
fn dns_connection_ownership_reads_v1_resolve_fallback() {
    let mut value = json!({
        "resolveBeforeDial": true,
        "dnsDefaults": { "directServerId": "builtin-domestic" }
    });
    assert!(migrate_dns_connection_ownership(&mut value));
    assert_eq!(
        value["dnsDefaults"]["connectionResolution"],
        json!("dnsRules")
    );
}

/// 🔴 「诊断采集」机制删除后的收尾：**在采集中升级**的用户不得被静默钉在 debug 级别。
///
/// 那个中间态是磁盘上真实存在的形态（`logLevel:"debug"` + `diagnosticCapture.prevLogLevel`）。
/// 少了这条迁移，用户升级后日志永远以 debug 刷屏、写盘量翻倍，而界面上再也没有任何一颗按钮
/// 能关掉它 —— 关它的那颗按钮已经随机制一起删了。
///
/// 牙：把 `migrate_diagnostic_capture` 从 `migrate_all` 链上摘掉 → 第一条断言转红；
/// 把还原值改成保留 `debug` → 第二条转红；把 null 那条早返删掉 → 第四条转红。
#[test]
fn migrate_diagnostic_capture_restores_level_and_drops_orphan_key() {
    // ① 真实中间态：采集中升级。
    let mut v = base_config();
    v["logLevel"] = json!("debug");
    v["diagnosticCapture"] = json!({ "prevLogLevel": "warn" });
    let delta = migrate_all(&mut v);
    assert!(delta.changed);
    assert!(
        v.as_object().unwrap().get("diagnosticCapture").is_none(),
        "孤儿键必须清掉（再也没有代码读它）"
    );
    assert_eq!(
        v["logLevel"],
        json!("warn"),
        "必须还原到采集前的级别，不得把用户钉在 debug"
    );

    // ② 快照损坏 / 缺失 → 兜 info，绝不留 debug。
    let mut v = base_config();
    v["logLevel"] = json!("debug");
    v["diagnosticCapture"] = json!({});
    migrate_all(&mut v);
    assert_eq!(v["logLevel"], json!("info"), "缺快照兜 info");

    let mut v = base_config();
    v["logLevel"] = json!("debug");
    v["diagnosticCapture"] = json!({ "prevLogLevel": "verbose" });
    migrate_all(&mut v);
    assert_eq!(v["logLevel"], json!("info"), "不认识的级别兜 info");

    // ③ null 在旧机制里就等于「未在采集」⇒ 只删空壳键，logLevel 是用户自己的选择，不得被顶掉。
    let mut v = base_config();
    v["logLevel"] = json!("error");
    v["diagnosticCapture"] = Value::Null;
    migrate_all(&mut v);
    assert!(v.as_object().unwrap().get("diagnosticCapture").is_none());
    assert_eq!(
        v["logLevel"],
        json!("error"),
        "null = 未在采集，不得把用户选的级别改掉"
    );

    // ④ 无该键 → 完全不碰 logLevel（绝大多数配置走这条；碰了就是每次启动改用户级别）。
    let mut v = base_config();
    v["logLevel"] = json!("error");
    migrate_all(&mut v);
    assert_eq!(v["logLevel"], json!("error"));

    // ⑤ 幂等：迁移完键就没了，二次跑无变更。
    let mut v = base_config();
    v["logLevel"] = json!("debug");
    v["diagnosticCapture"] = json!({ "prevLogLevel": "warn" });
    migrate_all(&mut v);
    let snapshot = v.clone();
    let delta2 = migrate_all(&mut v);
    assert_eq!(v, snapshot);
    assert!(!delta2.changed);
}

/// 🔴 MTU 迁移**只跑一次**：标记落定后，用户在新 UI 里设的值不得再被抹。
///
/// 没有这条锁，`migrate_tun_mtu` 退化成「每次启动都把 MTU 清成自动」——用户手设一个值、
/// 重启一次就没了，且没有任何提示。这是本迁移唯一的危险失效模式。
#[test]
fn tun_mtu_migration_runs_once_then_respects_user_value() {
    let mut v = json!({
        "tunConfig": {"mtu": 1350, "stack": "auto", "autoRoute": true, "strictRoute": true}
    });
    let mut d = MigrationDelta::default();
    migrate_tun_mtu(&mut v, &mut d);
    assert!(d.changed);
    assert!(v["tunConfig"].get("mtu").is_none(), "存量值应被抹掉");
    assert_eq!(v["tunMtuMigrated"], json!(true));

    // 用户之后在 UI 里显式设了 65535 —— 再跑迁移必须原样保留。
    v["tunConfig"]["mtu"] = json!(65535);
    let mut d2 = MigrationDelta::default();
    migrate_tun_mtu(&mut v, &mut d2);
    assert_eq!(
        v["tunConfig"]["mtu"],
        json!(65535),
        "已迁移后不得再碰用户值"
    );
    assert!(!d2.changed);
}

/// 中间构建把默认 false 持久化后，最终默认必须只纠正一次；随后用户仍可独立关闭。
#[test]
fn tray_menu_warm_default_migration_runs_once_then_respects_user_value() {
    let mut v = json!({"keepTrayMenuWarm": false});
    let mut d = MigrationDelta::default();
    migrate_tray_menu_warm_default(&mut v, &mut d);
    assert!(d.changed);
    assert_eq!(v["keepTrayMenuWarm"], json!(true));
    assert_eq!(v["keepTrayMenuWarmDefaultMigrated"], json!(true));

    // 迁移完成后用户显式关闭，二次启动不得再覆写。
    v["keepTrayMenuWarm"] = json!(false);
    let mut d2 = MigrationDelta::default();
    migrate_tray_menu_warm_default(&mut v, &mut d2);
    assert_eq!(v["keepTrayMenuWarm"], json!(false));
    assert!(!d2.changed);
}

#[test]
fn tray_menu_warm_default_migration_fills_missing_value_and_is_idempotent() {
    let mut v = json!({});
    let mut d = MigrationDelta::default();
    migrate_tray_menu_warm_default(&mut v, &mut d);
    assert!(d.changed);
    assert_eq!(v["keepTrayMenuWarm"], json!(true));
    assert_eq!(v["keepTrayMenuWarmDefaultMigrated"], json!(true));

    let snapshot = v.clone();
    let mut d2 = MigrationDelta::default();
    migrate_tray_menu_warm_default(&mut v, &mut d2);
    assert_eq!(v, snapshot);
    assert!(!d2.changed);
}

#[test]
fn migrate_bypass_processes_dedupes() {
    let mut v = base_config();
    v["bypassProcesses"] = json!(["chrome", "chrome", "firefox", "  "]);
    migrate_bypass_processes(&mut v);
    let rule = v["customRules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "migrated_bypass_processes")
        .unwrap();
    let vals = rule["values"].as_array().unwrap();
    assert_eq!(vals.len(), 2); // chrome + firefox 去重
}

#[test]
fn migrate_subscription_proxy_policy_false_leaves_default() {
    let mut v = base_config();
    v["subscriptionUpdateViaProxy"] = json!(false);
    migrate_subscription_proxy_policy(&mut v, &mut MigrationDelta::default());
    // false → 不设 policy（回落 follow 默认），但旧字段已删
    assert!(!v
        .as_object()
        .unwrap()
        .contains_key("subscriptionProxyPolicy"));
    assert!(!v
        .as_object()
        .unwrap()
        .contains_key("subscriptionUpdateViaProxy"));
}

#[test]
fn migrate_node_resolver_preserves_intent() {
    let mut v = base_config();
    v["proxyModeType"] = json!("systemProxy");
    v["dnsConfig"] = json!({"nodeDomainResolver": "dnspod"});
    migrate_node_resolver(&mut v, &mut MigrationDelta::default());
    assert_eq!(v["dnsConfig"]["nodeResolverPool"], json!(["dnspod"]));
    assert_eq!(v["dnsConfig"]["nodeResolverSingle"], json!("dnspod"));
    assert_eq!(v["dnsConfig"]["nodeResolverMigrated"], json!(true));
}

#[test]
fn custom_rules_need_migration_detects_legacy_only() {
    // 旧 DomainRule（无 type + domains 数组）→ 需迁移。
    let legacy = json!({"customRules":[{"id":"a","domains":["x.com"],"action":"proxy"}]});
    assert!(custom_rules_need_migration(&legacy));
    // 新 Rule（有 type）→ 不需迁移。
    let modern = json!({"customRules":[{"id":"a","type":"domainSuffix","values":["x.com"],"action":"proxy","enabled":true}]});
    assert!(!custom_rules_need_migration(&modern));
    // 空 / 缺失 → 不需迁移。
    assert!(!custom_rules_need_migration(&json!({"customRules":[]})));
    assert!(!custom_rules_need_migration(&json!({})));
}

#[test]
fn migrate_privacy_password_clears_plaintext() {
    // F29：明文 privacyPassword → 内存清空（防外泄）；哈希落盘属运行时层 FS。
    let mut v = base_config();
    v["privacyPassword"] = json!("secret123");
    let changed = migrate_privacy_password_clear(&mut v);
    assert!(changed);
    assert_eq!(v["privacyPassword"], json!(""));
    // 幂等：已空不再变
    let changed2 = migrate_privacy_password_clear(&mut v);
    assert!(!changed2);
}
