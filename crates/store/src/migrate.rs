//! 一次性迁移链（维度7 #54）。
//!
//! Polaris 锚点：`ConfigManager.ts` 的 migrate* 方法（loadConfig 内顺序调用）+
//! validateConfig 中的旧数据迁移（customRules DomainRule→Rule / bypassProcesses→Rule / mixedPort 收敛）。
//!
//! 迁移纪律（维度7 #54）：幂等（标记守卫）+ 绝不抛（吞异常）+ 落盘失败不阻断。
//! 纯逻辑：本模块仅做就地改写 Value，不触碰 FS；落盘由 store 层 best-effort 驱动。
//!
//! 迁移链顺序（与 TS loadConfig 一致）：
//!   1. validateConfig 内：mixedPort 收敛（删 httpPort/socksPort）/ customRules DomainRule→Rule /
//!      bypassProcesses→Rule / customRules action+bypassFakeIP→effects（均在 sanitize 后的 Value 上幂等执行）
//!   2. migrateFakeIpToggle（缺 dnsConfig 补齐 / enableFakeIp 按模式冻结 + 标记）
//!   3. migrateFakeIpTunPending（systemProxy+false+migrated → fakeIpTunAutoEnable=true）
//!   4. migrateNodeResolver（nodeDomainResolver → nodeResolverPool/Single + 标记）
//!   5. migrateSubscriptionProxyPolicy（旧布尔 subscriptionUpdateViaProxy → 三态）
//!   6. migrateTunStack（存量 stack → 'auto' + 标记）
//!   7. migrateTunMtu（抹掉存量 tunConfig.mtu → 缺席即自动 + 标记）
//!   8. migrateTrayMenuWarmDefault（中间构建写入的旧默认 false → 最终默认 true + 标记）
//!   9. migrateDiagnosticCapture（撤掉的诊断采集机制：还原 logLevel + 清孤儿键）
//!  10. DNS 连接解析所有权（routeDefaults/逐流量规则解析 → dnsDefaults 全局策略）
//!  11. appRulesSeeded（默认注入内置预设 + 剔除下线预设）

#![forbid(unsafe_code)]

use serde_json::{Map, Value};

use polaris_config_engine::user_config::{
    is_valid_bootstrap_dns_resource, rule::RuleType, DnsServerResource,
};

/// 迁移结果：标记本次是否有变更（true → 调用方应 best-effort 落盘）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MigrationDelta {
    pub changed: bool,
}

/// 执行全量迁移链（在 sanitize + validate 之后的 Value 上）。
///
/// 幂等：所有迁移均有标记守卫，已迁移跳过。绝不抛：内部不返回 Err。
/// 返回 [`MigrationDelta`] 供调用方决定是否落盘。
pub fn migrate_all(value: &mut Value) -> MigrationDelta {
    let mut delta = MigrationDelta::default();
    // validateConfig 内联迁移（无独立标记，但本身幂等）
    delta.changed |= migrate_mixed_port(value);
    delta.changed |= migrate_custom_rules_domain_rule(value);
    delta.changed |= migrate_bypass_processes(value);
    delta.changed |= migrate_custom_rule_effects(value);
    // loadConfig 顺序迁移（带标记）
    migrate_fake_ip_toggle(value, &mut delta);
    migrate_fake_ip_tun_pending(value, &mut delta);
    migrate_node_resolver(value, &mut delta);
    // v2 必须在 FakeIP 冻结迁移之后取值，否则缺少 enableFakeIp 的旧配置会被错误物化。
    delta.changed |= migrate_dns_policy_v2(value);
    // v3 将两个执行平面拆成独立集合；Bootstrap 同时提升为可配置的受保护资源。
    delta.changed |= migrate_split_policy_rules(value);
    delta.changed |= migrate_builtin_dns_resources(value);
    // v4：流量规则只决定出口；连接域名解析由 DNS 默认策略单点拥有。
    delta.changed |= migrate_dns_connection_ownership(value);
    migrate_subscription_proxy_policy(value, &mut delta);
    migrate_tun_stack(value, &mut delta);
    migrate_tun_mtu(value, &mut delta);
    migrate_tray_menu_warm_default(value, &mut delta);
    migrate_diagnostic_capture(value, &mut delta);
    delta.changed |= seed_app_rules(value);
    // F29 隐私密码：纯逻辑侧仅清内存明文（防 CONFIG_GET_VALUE 外泄）；
    // 哈希落盘（writePrivacyHash）属运行时层 FS 职责，经 ConfigFs 扩展方法注入。
    delta.changed |= migrate_privacy_password_clear(value);
    delta
}

/// 第一阶段 `customRules.effects.dns` → v2 一等 DNS Policy/Server/双排序。
///
/// `policyRules` 是新真值，`customRules` 保留作旧版只写兼容投影；本迁移只在 schema<2 或
/// policyRules 缺席时执行，因而幂等。所有可原生表达的第一阶段语义都物化，只有节点 resolver
/// 继续留在 dnsConfig（由 sidecar 消费）。
pub fn migrate_dns_policy_v2(value: &mut Value) -> bool {
    let Some(root) = value.as_object_mut() else {
        return false;
    };
    if root
        .get("configSchemaVersion")
        .and_then(Value::as_u64)
        .is_some_and(|version| version >= 2)
        && root.get("policyRules").is_some_and(Value::is_array)
    {
        return false;
    }

    let mut policies = root
        .get("customRules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut route_order = Vec::new();
    let mut dns_order = Vec::new();

    for policy in &mut policies {
        let Some(map) = policy.as_object_mut() else {
            continue;
        };
        let enabled = map.get("enabled").and_then(Value::as_bool).unwrap_or(true);
        let id = map
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let Some(effects) = map.get_mut("effects").and_then(Value::as_object_mut) else {
            continue;
        };
        let has_route = effects.get("route").is_some_and(Value::is_object);
        let has_dns = effects.get("dns").is_some_and(Value::is_object);
        if has_route && !id.is_empty() {
            route_order.push(Value::String(id.clone()));
        }
        if has_dns && !id.is_empty() {
            dns_order.push(Value::String(id.clone()));
        }

        if let Some(route) = effects.get_mut("route").and_then(Value::as_object_mut) {
            route
                .entry("enabled")
                .or_insert_with(|| Value::Bool(enabled));
            // 第一阶段只要带 DNS effect 就自动发 resolve；升级必须把这个隐式行为显式化。
            if has_dns {
                route
                    .entry("destinationResolution")
                    .or_insert_with(|| serde_json::json!({"mode":"dnsRules"}));
            }
        }

        if let Some(dns) = effects.get_mut("dns").and_then(Value::as_object_mut) {
            dns.entry("enabled").or_insert_with(|| Value::Bool(enabled));
            let answer = dns
                .get("answerMode")
                .and_then(Value::as_str)
                .unwrap_or("real");
            let resolver = dns
                .get("resolver")
                .and_then(Value::as_str)
                .unwrap_or("inherit");
            let action = if answer == "fakeIp" {
                serde_json::json!({"type":"fakeIp"})
            } else {
                match resolver {
                    "direct" => serde_json::json!({"type":"server","serverId":"builtin-domestic"}),
                    "proxy" => serde_json::json!({"type":"server","serverId":"builtin-remote"}),
                    _ if has_route => serde_json::json!({"type":"followRouteDefault"}),
                    _ => serde_json::json!({"type":"server","serverId":"builtin-domestic"}),
                }
            };
            dns.entry("action").or_insert(action);
            if !has_route {
                dns.entry("migratedImplicitResolve")
                    .or_insert_with(|| Value::Bool(true));
                if !id.is_empty()
                    && !route_order
                        .iter()
                        .any(|candidate| candidate.as_str() == Some(id.as_str()))
                {
                    route_order.push(Value::String(id.clone()));
                }
            }
        }
    }

    let dns_cfg = root.get("dnsConfig").and_then(Value::as_object);
    let domestic_spec = dns_cfg
        .and_then(|dns| dns.get("domesticDns"))
        .and_then(Value::as_str)
        .unwrap_or("https://doh.pub/dns-query")
        .to_owned();
    let foreign_spec = dns_cfg
        .and_then(|dns| dns.get("foreignDns"))
        .and_then(Value::as_str)
        .unwrap_or("https://dns.google/dns-query")
        .to_owned();
    let fake_ip = dns_cfg
        .and_then(|dns| dns.get("enableFakeIp"))
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let resolve_before_dial = root
        .get("resolveBeforeDial")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let proxy_mode = root
        .get("proxyMode")
        .and_then(Value::as_str)
        .unwrap_or("smart");
    let reverse_region = root
        .get("regionRouting")
        .and_then(Value::as_object)
        .and_then(|region| region.get("reverse"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let legacy_real_default =
        if proxy_mode == "global" || (proxy_mode == "smart" && !reverse_region) {
            "builtin-remote"
        } else {
            "builtin-domestic"
        };

    root.insert("configSchemaVersion".into(), Value::from(2));
    root.insert("policyRules".into(), Value::Array(policies));
    root.insert("routeRuleOrder".into(), Value::Array(route_order));
    root.insert("dnsRuleOrder".into(), Value::Array(dns_order));
    root.insert(
        "dnsServers".into(),
        Value::Array(vec![
            with_bootstrap(dns_resource_from_spec(
                "builtin-domestic",
                "Domestic DNS",
                &domestic_spec,
                "direct",
            )),
            with_bootstrap(dns_resource_from_spec(
                "builtin-remote",
                "Remote DNS",
                &foreign_spec,
                "currentExit",
            )),
            bootstrap_dns_resource(),
        ]),
    );
    root.entry("dnsServerGroups")
        .or_insert_with(|| Value::Array(Vec::new()));
    root.insert(
        "dnsDefaults".into(),
        serde_json::json!({
            "directServerId":"builtin-domestic",
            "proxyServerId":"builtin-remote",
            "unmatchedAction": if fake_ip {
                serde_json::json!({"type":"fakeIp"})
            } else {
                serde_json::json!({"type":"server","serverId":legacy_real_default})
            }
        }),
    );
    root.insert(
        "routeDefaults".into(),
        serde_json::json!({
            "destinationResolution": if resolve_before_dial { "dnsRules" } else { "preserveDomain" }
        }),
    );
    true
}

fn with_bootstrap(mut resource: Value) -> Value {
    if resource
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|kind| matches!(kind, "https" | "tls"))
    {
        if let Some(map) = resource.as_object_mut() {
            map.insert(
                "bootstrapServerId".into(),
                Value::String("builtin-bootstrap".into()),
            );
        }
    }
    resource
}

fn bootstrap_dns_resource() -> Value {
    serde_json::json!({
        "id":"builtin-bootstrap",
        "name":"Bootstrap DNS",
        "enabled":true,
        "type":"https",
        "endpoint":{"host":"223.5.5.5","port":443,"path":"/dns-query"},
        "outbound":{"type":"direct"}
    })
}

/// v2 的共享 policyRules → v3 独立 trafficRules/dnsRules。
///
/// 两个集合的 ID 命名空间独立，因此双效果规则沿用同一个稳定 ID；每份只保留本平面 effect。
/// 旧 DNS-only 的 `migratedImplicitResolve` 另物化为 `resolutionOnly` 流量规则，保证升级前后的
/// mixed/SOCKS/TUN 目的域名预解析行为不变。
pub fn migrate_split_policy_rules(value: &mut Value) -> bool {
    let Some(root) = value.as_object_mut() else {
        return false;
    };
    if root.get("trafficRules").is_some_and(Value::is_array)
        && root.get("dnsRules").is_some_and(Value::is_array)
    {
        return false;
    }

    let shared = root
        .get("policyRules")
        .or_else(|| root.get("customRules"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut traffic_rules = Vec::new();
    let mut dns_rules = Vec::new();

    for rule in shared {
        let Some(rule_map) = rule.as_object() else {
            continue;
        };
        let effects = rule_map.get("effects").and_then(Value::as_object);
        let route = effects.and_then(|all| all.get("route")).cloned();
        let dns = effects.and_then(|all| all.get("dns")).cloned();

        if let Some(route_effect) = route.clone() {
            let mut traffic = rule.clone();
            if let Some(map) = traffic.as_object_mut() {
                map.insert("effects".into(), serde_json::json!({"route":route_effect}));
            }
            traffic_rules.push(traffic);
        } else if effects.is_none() {
            // 迁移链之外直接构造的旧配置仍按传统流量规则处理。
            traffic_rules.push(rule.clone());
        } else if dns
            .as_ref()
            .and_then(Value::as_object)
            .and_then(|effect| effect.get("migratedImplicitResolve"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            let enabled = dns
                .as_ref()
                .and_then(Value::as_object)
                .and_then(|effect| effect.get("enabled"))
                .and_then(Value::as_bool)
                .unwrap_or_else(|| {
                    rule_map
                        .get("enabled")
                        .and_then(Value::as_bool)
                        .unwrap_or(true)
                });
            let action = rule_map
                .get("action")
                .and_then(Value::as_str)
                .filter(|action| matches!(*action, "proxy" | "direct" | "block"))
                .unwrap_or("direct");
            let mut traffic = rule.clone();
            if let Some(map) = traffic.as_object_mut() {
                map.insert(
                    "effects".into(),
                    serde_json::json!({"route":{
                        "enabled":enabled,
                        "action":action,
                        "destinationResolution":{"mode":"dnsRules"},
                        "resolutionOnly":true
                    }}),
                );
            }
            traffic_rules.push(traffic);
        }

        if let Some(mut dns_effect) = dns {
            // 共享模型里的 followRouteDefault 依赖另一平面；拆分时冻结为等价的稳定服务器引用。
            if dns_effect
                .get("action")
                .and_then(|action| action.get("type"))
                .and_then(Value::as_str)
                == Some("followRouteDefault")
            {
                let route_action = route
                    .as_ref()
                    .and_then(|effect| effect.get("action"))
                    .and_then(Value::as_str)
                    .or_else(|| rule_map.get("action").and_then(Value::as_str));
                let server_id = if route_action == Some("proxy") {
                    "builtin-remote"
                } else {
                    "builtin-domestic"
                };
                if let Some(effect) = dns_effect.as_object_mut() {
                    effect.insert(
                        "action".into(),
                        serde_json::json!({"type":"server","serverId":server_id}),
                    );
                }
            }
            if let Some(effect) = dns_effect.as_object_mut() {
                effect.remove("migratedImplicitResolve");
            }
            let mut dns_rule = rule.clone();
            if let Some(map) = dns_rule.as_object_mut() {
                map.insert("effects".into(), serde_json::json!({"dns":dns_effect}));
            }
            dns_rules.push(dns_rule);
        }
    }

    let ids = |rules: &[Value]| -> std::collections::HashSet<String> {
        rules
            .iter()
            .filter_map(|rule| rule.get("id").and_then(Value::as_str).map(str::to_string))
            .collect()
    };
    let filtered_order =
        |key: &str, rules: &[Value], members: &std::collections::HashSet<String>| -> Vec<Value> {
            let mut out: Vec<Value> = Vec::new();
            for id in root
                .get(key)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                if members.contains(id) && !out.iter().any(|entry| entry.as_str() == Some(id)) {
                    out.push(Value::String(id.to_string()));
                }
            }
            for rule in rules {
                let Some(id) = rule.get("id").and_then(Value::as_str) else {
                    continue;
                };
                if !out.iter().any(|entry| entry.as_str() == Some(id)) {
                    out.push(Value::String(id.to_string()));
                }
            }
            out
        };
    let traffic_ids = ids(&traffic_rules);
    let dns_ids = ids(&dns_rules);
    let route_order = filtered_order("routeRuleOrder", &traffic_rules, &traffic_ids);
    let dns_order = filtered_order("dnsRuleOrder", &dns_rules, &dns_ids);

    root.insert("trafficRules".into(), Value::Array(traffic_rules.clone()));
    root.insert("dnsRules".into(), Value::Array(dns_rules));
    // 旧字段只投影流量规则，避免旧版本把 DNS 规则误当终结流量动作。
    root.insert("policyRules".into(), Value::Array(traffic_rules.clone()));
    root.insert("customRules".into(), Value::Array(traffic_rules));
    root.insert("routeRuleOrder".into(), Value::Array(route_order));
    root.insert("dnsRuleOrder".into(), Value::Array(dns_order));
    root.insert("configSchemaVersion".into(), Value::from(3));
    true
}

/// v4：把连接域名解析从流量规则平面收回 DNS 默认策略。
///
/// v1-v3 曾同时存在三份真值：`resolveBeforeDial`、`routeDefaults.destinationResolution`、
/// `trafficRules[].effects.route.destinationResolution`。逐规则覆盖不仅让 UI 把 DNS 塞进流量规则，
/// 其 `preserveDomain` 在全局 resolve 已先执行时也无法真正撤销。v4 只保留
/// `dnsDefaults.connectionResolution`：流量规则不再携带 `bypassFakeIP` / 连接解析字段，旧 DNS-only
/// 迁移产生的 `resolutionOnly` 影子流量规则一并删除，避免去掉标记后意外变成终结 direct 规则。
pub fn migrate_dns_connection_ownership(value: &mut Value) -> bool {
    let Some(root) = value.as_object_mut() else {
        return false;
    };
    let legacy_schema = root
        .get("configSchemaVersion")
        .and_then(Value::as_u64)
        .is_none_or(|version| version < 4);
    let mut changed = false;

    if legacy_schema {
        let connection_resolution = root
            .get("dnsDefaults")
            .and_then(Value::as_object)
            .and_then(|defaults| defaults.get("connectionResolution"))
            .and_then(Value::as_str)
            .filter(|mode| matches!(*mode, "preserveDomain" | "dnsRules"))
            .map(str::to_owned)
            .or_else(|| {
                root.get("routeDefaults")
                    .and_then(Value::as_object)
                    .and_then(|defaults| defaults.get("destinationResolution"))
                    .and_then(Value::as_str)
                    .filter(|mode| matches!(*mode, "preserveDomain" | "dnsRules"))
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| {
                if root
                    .get("resolveBeforeDial")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    "dnsRules".to_string()
                } else {
                    "preserveDomain".to_string()
                }
            });

        let defaults = root
            .entry("dnsDefaults")
            .or_insert_with(|| Value::Object(Map::new()));
        if !defaults.is_object() {
            *defaults = Value::Object(Map::new());
        }
        if let Some(defaults) = defaults.as_object_mut() {
            defaults.insert(
                "connectionResolution".into(),
                Value::String(connection_resolution),
            );
        }
        changed = true;
    }

    let mut canonical_traffic: Option<Vec<Value>> = None;
    for key in ["trafficRules", "policyRules", "customRules"] {
        let Some(rules) = root.get_mut(key).and_then(Value::as_array_mut) else {
            continue;
        };
        let before_len = rules.len();
        rules.retain(|rule| {
            let Some(effects) = rule.get("effects").and_then(Value::as_object) else {
                // 无 effects 的 v1 传统规则仍是合法流量规则，route 动作回退到顶层镜像。
                return true;
            };
            let Some(route) = effects.get("route").and_then(Value::as_object) else {
                // v4 两个执行平面是独立集合：DNS-only / 空 effects 条目不能留在 trafficRules，
                // 否则移除 DNS 字段后会意外回退为顶层 action，凭空变成一条终结流量规则。
                return false;
            };
            !route
                .get("resolutionOnly")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        });
        changed |= rules.len() != before_len;
        for rule in rules.iter_mut() {
            let Some(rule) = rule.as_object_mut() else {
                continue;
            };
            changed |= rule.remove("bypassFakeIP").is_some();
            if let Some(effects) = rule.get_mut("effects").and_then(Value::as_object_mut) {
                // 即使 v3 之前已有畸形双平面副本，也只让 dnsRules 保有 DNS effect。
                changed |= effects.remove("dns").is_some();
                if let Some(route) = effects.get_mut("route").and_then(Value::as_object_mut) {
                    changed |= route.remove("destinationResolution").is_some();
                    changed |= route.remove("resolutionOnly").is_some();
                }
            }
        }
        if key == "trafficRules" {
            canonical_traffic = Some(rules.clone());
        }
    }

    if let Some(traffic) = canonical_traffic {
        let ids: std::collections::HashSet<String> = traffic
            .iter()
            .filter_map(|rule| rule.get("id").and_then(Value::as_str).map(str::to_owned))
            .collect();
        if let Some(order) = root.get_mut("routeRuleOrder").and_then(Value::as_array_mut) {
            let before = order.len();
            order.retain(|id| id.as_str().is_some_and(|id| ids.contains(id)));
            changed |= order.len() != before;
        }
        // v4 回滚兼容镜像仍只投影流量规则，但不再携带 DNS 解析字段。
        let mirror = Value::Array(traffic);
        for key in ["policyRules", "customRules"] {
            if root.get(key) != Some(&mirror) {
                root.insert(key.into(), mirror.clone());
                changed = true;
            }
        }
    }

    changed |= root.remove("routeDefaults").is_some();
    changed |= root.remove("resolveBeforeDial").is_some();
    if legacy_schema {
        root.insert("configSchemaVersion".into(), Value::from(4));
    }
    changed
}

/// 确保三个受保护内置 DNS 服务器始终是显式配置资源；只补缺项，不覆盖用户编辑。
pub fn migrate_builtin_dns_resources(value: &mut Value) -> bool {
    let Some(root) = value.as_object_mut() else {
        return false;
    };
    let servers = root
        .entry("dnsServers")
        .or_insert_with(|| Value::Array(Vec::new()));
    let Some(servers) = servers.as_array_mut() else {
        return false;
    };
    let mut changed = false;
    for (id, fallback) in [
        (
            "builtin-domestic",
            with_bootstrap(dns_resource_from_spec(
                "builtin-domestic",
                "Domestic DNS",
                "https://doh.pub/dns-query",
                "direct",
            )),
        ),
        (
            "builtin-remote",
            with_bootstrap(dns_resource_from_spec(
                "builtin-remote",
                "Remote DNS",
                "https://dns.google/dns-query",
                "currentExit",
            )),
        ),
        ("builtin-bootstrap", bootstrap_dns_resource()),
    ] {
        if let Some(existing) = servers
            .iter_mut()
            .find(|server| server.get("id").and_then(Value::as_str) == Some(id))
        {
            if id == "builtin-bootstrap"
                && serde_json::from_value::<DnsServerResource>(existing.clone())
                    .ok()
                    .is_none_or(|resource| !is_valid_bootstrap_dns_resource(&resource))
            {
                *existing = fallback;
                changed = true;
                continue;
            }
            if existing.get("enabled") != Some(&Value::Bool(true)) {
                if let Some(map) = existing.as_object_mut() {
                    map.insert("enabled".into(), Value::Bool(true));
                    changed = true;
                }
            }
            if id != "builtin-bootstrap"
                && existing
                    .get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|kind| matches!(kind, "https" | "tls"))
                && existing.get("bootstrapServerId").is_none()
            {
                if let Some(map) = existing.as_object_mut() {
                    map.insert(
                        "bootstrapServerId".into(),
                        Value::String("builtin-bootstrap".into()),
                    );
                    changed = true;
                }
            }
        } else {
            servers.push(fallback);
            changed = true;
        }
    }
    changed
}

fn dns_resource_from_spec(id: &str, name: &str, spec: &str, outbound: &str) -> Value {
    use polaris_config_engine::user_config::dns_spec::{parse_dns_server_spec, DnsServerType};

    let parsed = parse_dns_server_spec(Some(spec)).or_else(|| {
        let fallback = if id == "builtin-remote" {
            "https://dns.google/dns-query"
        } else {
            "https://doh.pub/dns-query"
        };
        parse_dns_server_spec(Some(fallback))
    });
    let Some(parsed) = parsed else {
        return serde_json::json!({
            "id":id,"name":name,"enabled":false,"type":"udp",
            "endpoint":{"host":"","port":53},"outbound":{"type":outbound}
        });
    };
    let kind = match parsed.server_type {
        DnsServerType::Https => "https",
        DnsServerType::Tls => "tls",
        DnsServerType::Udp => "udp",
    };
    serde_json::json!({
        "id": id,
        "name": name,
        "enabled": true,
        "type": kind,
        "endpoint": {
            "host": parsed.server,
            "port": parsed.port,
            "path": parsed.path
        },
        "outbound": {"type": outbound}
    })
}

/// 隐私密码明文清除（F29 纯逻辑侧）：config.privacyPassword 非空 → 内存清空（置 ""）。
///
/// Polaris 锚点 loadConfig F29 段：即便后续哈希落盘 fs 失败，明文也不会再经 CONFIG_GET_VALUE /
/// configChanged 外泄。哈希计算 + 落盘（writePrivacyHash）属运行时层职责（需 FS + crypto），
/// 此处仅做「先清内存明文」的纯逻辑改写，幂等（已 "" 不再变）。
pub fn migrate_privacy_password_clear(value: &mut Value) -> bool {
    let Some(obj) = value.as_object_mut() else {
        return false;
    };
    let nonempty = obj
        .get("privacyPassword")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.is_empty());
    if nonempty {
        obj.insert("privacyPassword".into(), Value::String(String::new()));
        true
    } else {
        false
    }
}

/// mixed-only 收敛：mixedPort 未设→旧 httpPort（忽略 65533 哨兵）→ 默认 7890；删 httpPort/socksPort。
/// Polaris validateConfig mixedPort 段。幂等：mixedPort>0 不改写。
pub fn migrate_mixed_port(value: &mut Value) -> bool {
    let Some(obj) = value.as_object_mut() else {
        return false;
    };
    let mixed = obj.get("mixedPort").and_then(|v| v.as_u64());
    let need = mixed.is_none_or(|p| p == 0);
    let mut changed = false;
    if need {
        let legacy_http = obj
            .get("httpPort")
            .and_then(|v| v.as_u64())
            .filter(|&p| p > 0 && p != 65533);
        let port = legacy_http.unwrap_or(7890);
        obj.insert("mixedPort".into(), Value::from(port));
        changed = true;
    }
    if obj.remove("httpPort").is_some() {
        changed = true;
    }
    if obj.remove("socksPort").is_some() {
        changed = true;
    }
    changed
}

/// 旧 DomainRule（无 type、有 domains 数组）→ 新 Rule[]（domainSuffix / geosite / ipCidr）。
/// 上游 `migrateCustomRules` + `migrateLegacyDomainRule`。幂等：已是新 shape 原样保留。
pub fn migrate_custom_rules_domain_rule(value: &mut Value) -> bool {
    let Some(obj) = value.as_object_mut() else {
        return false;
    };
    let Some(Value::Array(rules)) = obj.get_mut("customRules") else {
        return false;
    };
    let original = rules.clone();
    let mut out: Vec<Value> = Vec::new();
    for r in rules.drain(..) {
        if is_legacy_domain_rule(&r) {
            out.extend(migrate_legacy_domain_rule(&r));
        } else if r.as_object().is_some_and(|o| o.contains_key("type")) {
            out.push(r);
        }
        // 其余脏数据丢弃
    }
    let changed = out != original;
    *rules = out;
    changed
}

/// 旧 Rule 的 `action/targetServerId/bypassFakeIP` → 统一 `effects`。
///
/// 旧字段不删除：它们是旧版本回滚读取的兼容镜像。迁移只在 `effects` 缺席时执行，因此幂等，
/// 且不会覆盖用户已保存的新模型。旧 bypass 只有在全部条件都可被 DNS matcher 原生表达时才迁入；
/// 其余规则仍会得到 route effect，不会因畸形 bypass 扩大匹配面。
pub fn migrate_custom_rule_effects(value: &mut Value) -> bool {
    let Some(rules) = value.get_mut("customRules").and_then(Value::as_array_mut) else {
        return false;
    };
    let mut changed = false;
    for rule in rules {
        let Some(map) = rule.as_object_mut() else {
            continue;
        };
        if map.contains_key("effects") {
            continue;
        }
        let Some(action) = map
            .get("action")
            .and_then(Value::as_str)
            .filter(|action| matches!(*action, "proxy" | "direct" | "block"))
            .map(String::from)
        else {
            continue;
        };

        let mut route = Map::new();
        route.insert("action".into(), Value::String(action));
        if let Some(target) = map.get("targetServerId").and_then(Value::as_str) {
            route.insert("targetServerId".into(), Value::String(target.into()));
        }
        let mut effects = Map::new();
        effects.insert("route".into(), Value::Object(route));

        if map.get("bypassFakeIP").and_then(Value::as_bool) == Some(true)
            && rule_dns_conditions_supported(map)
        {
            effects.insert(
                "dns".into(),
                serde_json::json!({"resolver":"inherit","answerMode":"real"}),
            );
        }
        map.insert("effects".into(), Value::Object(effects));
        changed = true;
    }
    changed
}

fn rule_dns_conditions_supported(rule: &Map<String, Value>) -> bool {
    // 复用 config-engine 的权威 RuleType 反序列化与 DNS 能力判据，迁移层不维护第二张字符串表。
    let supported = |type_name: &str| {
        serde_json::from_value::<RuleType>(Value::String(type_name.to_string()))
            .is_ok_and(RuleType::supports_dns_effect)
    };
    if let Some(conditions) = rule.get("conditions").and_then(Value::as_array) {
        if !conditions.is_empty() {
            return conditions.iter().all(|condition| {
                condition
                    .get("type")
                    .and_then(Value::as_str)
                    .is_some_and(supported)
            });
        }
    }
    rule.get("type")
        .and_then(Value::as_str)
        .is_some_and(supported)
}

/// customRules 是否含任何旧版 DomainRule（决定「是否需迁移 + 迁移前备份」）。
/// 上游 `customRulesNeedMigration`（shared/rules.ts:355）。供 store::load 判「起迁移前落 .pre-rule-migration.bak」。
#[must_use]
pub fn custom_rules_need_migration(value: &Value) -> bool {
    value
        .get("customRules")
        .and_then(|v| v.as_array())
        .is_some_and(|rules| rules.iter().any(is_legacy_domain_rule))
}

/// 是否旧版 DomainRule（无 type 字段且 domains 为数组）。上游 `isLegacyDomainRule`。
///
/// `pub(crate)`：sanitize 侧需在丢弃无 `type` 条目**之前**放行旧 shape（待本模块 `migrate_custom_rules_domain_rule`
/// 转 Rule），复用此单一判据，避免与 sanitize 侧另写一份旧规则识别逻辑而漂移。
pub(crate) fn is_legacy_domain_rule(r: &Value) -> bool {
    let Some(o) = r.as_object() else {
        return false;
    };
    !o.contains_key("type") && o.get("domains").is_some_and(|d| d.is_array())
}

/// 旧 DomainRule → 新 Rule[]（无损、幂等）。上游 `migrateLegacyDomainRule`。
fn migrate_legacy_domain_rule(old: &Value) -> Vec<Value> {
    let Some(o) = old.as_object() else {
        return vec![];
    };
    let id = o
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let action = o
        .get("action")
        .and_then(|v| v.as_str())
        .filter(|a| matches!(*a, "proxy" | "direct" | "block"))
        .unwrap_or("proxy");
    let enabled = o.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
    let bypass_fakeip = o.get("bypassFakeIP").cloned();
    let target = o.get("targetServerId").cloned();
    let remarks = o.get("remarks").cloned();

    let mut domains: Vec<String> = Vec::new();
    let mut geosite_tags: Vec<String> = Vec::new();
    if let Some(Value::Array(arr)) = o.get("domains") {
        for d in arr {
            if let Some(s) = d.as_str() {
                let v = s.trim();
                if v.is_empty() {
                    continue;
                }
                if v.to_ascii_lowercase().starts_with("geosite:") {
                    let tag = v[8..].trim();
                    if !tag.is_empty() {
                        geosite_tags.push(tag.to_string());
                    }
                } else {
                    domains.push(v.strip_prefix("*.").unwrap_or(v).to_string());
                }
            }
        }
    }

    let mut out: Vec<Value> = Vec::new();
    if !domains.is_empty() {
        let mut m = Map::new();
        m.insert("id".into(), Value::String(id.clone()));
        m.insert("type".into(), Value::String("domainSuffix".into()));
        m.insert(
            "values".into(),
            Value::Array(domains.into_iter().map(Value::String).collect()),
        );
        m.insert("action".into(), Value::String(action.into()));
        m.insert("enabled".into(), Value::Bool(enabled));
        if let Some(b) = bypass_fakeip.clone() {
            m.insert("bypassFakeIP".into(), b);
        }
        if let Some(t) = target.clone() {
            m.insert("targetServerId".into(), t);
        }
        if let Some(r) = remarks.clone() {
            m.insert("remarks".into(), r);
        }
        out.push(Value::Object(m));
    }
    if !geosite_tags.is_empty() {
        let mut m = Map::new();
        m.insert("id".into(), Value::String(format!("{id}_geosite")));
        m.insert("type".into(), Value::String("geosite".into()));
        m.insert(
            "values".into(),
            Value::Array(geosite_tags.into_iter().map(Value::String).collect()),
        );
        m.insert("action".into(), Value::String(action.into()));
        m.insert("enabled".into(), Value::Bool(enabled));
        if let Some(t) = target.clone() {
            m.insert("targetServerId".into(), t);
        }
        if let Some(r) = remarks.clone() {
            m.insert("remarks".into(), r);
        }
        out.push(Value::Object(m));
    }
    let mut ip_cidrs: Vec<String> = Vec::new();
    if let Some(Value::Array(arr)) = o.get("ipCidr") {
        for c in arr {
            if let Some(s) = c.as_str() {
                if !s.trim().is_empty() {
                    ip_cidrs.push(s.trim().to_string());
                }
            }
        }
    }
    if !ip_cidrs.is_empty() {
        let mut m = Map::new();
        m.insert("id".into(), Value::String(format!("{id}_ip")));
        m.insert("type".into(), Value::String("ipCidr".into()));
        m.insert(
            "values".into(),
            Value::Array(ip_cidrs.into_iter().map(Value::String).collect()),
        );
        m.insert("action".into(), Value::String(action.into()));
        m.insert("enabled".into(), Value::Bool(enabled));
        if let Some(t) = target.clone() {
            m.insert("targetServerId".into(), t);
        }
        if let Some(r) = remarks.clone() {
            let base = r.as_str().unwrap_or("");
            m.insert("remarks".into(), Value::String(format!("{base} (IP)")));
        } else {
            m.insert("remarks".into(), Value::String(" (IP)".into()));
        }
        out.push(Value::Object(m));
    }
    // 极端兜底：既无域名也无 ipCidr → 空 domainSuffix 占位（避免规则凭空消失）
    if out.is_empty() {
        let mut m = Map::new();
        m.insert("id".into(), Value::String(id));
        m.insert("type".into(), Value::String("domainSuffix".into()));
        m.insert("values".into(), Value::Array(vec![]));
        m.insert("action".into(), Value::String(action.into()));
        m.insert("enabled".into(), Value::Bool(enabled));
        if let Some(b) = bypass_fakeip {
            m.insert("bypassFakeIP".into(), b);
        }
        if let Some(t) = target {
            m.insert("targetServerId".into(), t);
        }
        if let Some(r) = remarks {
            m.insert("remarks".into(), r);
        }
        out.push(Value::Object(m));
    }
    out
}

/// 旧「排除进程」bypassProcesses → customRules processName+direct 规则。Polaris validateConfig bypassProcesses 段。
/// 固定 id 'migrated_bypass_processes' 天然幂等；迁移后清空 bypassProcesses。
pub fn migrate_bypass_processes(value: &mut Value) -> bool {
    let Some(obj) = value.as_object_mut() else {
        return false;
    };
    let bypass = obj
        .get("bypassProcesses")
        .and_then(|v| v.as_array())
        .cloned();
    let nonempty = bypass.as_ref().is_some_and(|a| !a.is_empty());
    if !nonempty {
        // 确保字段存在为 []（TS validateConfig 兜底）
        if !obj.contains_key("bypassProcesses") {
            obj.insert("bypassProcesses".into(), Value::Array(vec![]));
            return true;
        }
        return false;
    }
    let mut values: Vec<String> = Vec::new();
    for p in bypass.unwrap() {
        if let Some(s) = p.as_str() {
            let t = s.trim();
            if !t.is_empty() {
                values.push(t.to_string());
            }
        }
    }
    values = crate::dedupe_str(&values);
    let already = obj
        .get("customRules")
        .and_then(|v| v.as_array())
        .is_some_and(|rules| {
            rules
                .iter()
                .any(|r| r.get("id").and_then(|v| v.as_str()) == Some("migrated_bypass_processes"))
        });
    if !values.is_empty() && !already {
        let mut m = Map::new();
        m.insert(
            "id".into(),
            Value::String("migrated_bypass_processes".into()),
        );
        m.insert("type".into(), Value::String("processName".into()));
        m.insert(
            "values".into(),
            Value::Array(values.into_iter().map(Value::String).collect()),
        );
        m.insert("action".into(), Value::String("direct".into()));
        m.insert("enabled".into(), Value::Bool(true));
        m.insert(
            "remarks".into(),
            Value::String("排除进程（自动迁移）".into()),
        );
        let rules = obj
            .entry("customRules")
            .or_insert_with(|| Value::Array(vec![]));
        if let Value::Array(arr) = rules {
            arr.push(Value::Object(m));
        }
    }
    obj.insert("bypassProcesses".into(), Value::Array(vec![]));
    true
}

/// FakeIP 开关统一一次性迁移。上游 `migrateFakeIpToggle`。
/// 缺 dnsConfig → 补默认；否则 fakeIpToggleMigrated!==true 时按模式冻结 enableFakeIp + 置标记。
pub fn migrate_fake_ip_toggle(value: &mut Value, delta: &mut MigrationDelta) {
    let Some(obj) = value.as_object_mut() else {
        return;
    };
    let mode_lower = obj
        .get("proxyModeType")
        .and_then(|v| v.as_str())
        .unwrap_or("systemProxy")
        .to_ascii_lowercase();
    if obj.get("dnsConfig").is_none_or(|v| !v.is_object()) {
        let enable = mode_lower != "systemproxy";
        let mut dns = Map::new();
        dns.insert(
            "domesticDns".into(),
            Value::String("https://doh.pub/dns-query".into()),
        );
        dns.insert(
            "foreignDns".into(),
            Value::String("https://dns.google/dns-query".into()),
        );
        dns.insert("enableFakeIp".into(), Value::Bool(enable));
        dns.insert("fakeIpToggleMigrated".into(), Value::Bool(true));
        obj.insert("dnsConfig".into(), Value::Object(dns));
        delta.changed = true;
        return;
    }
    let dns = obj
        .get_mut("dnsConfig")
        .and_then(|v| v.as_object_mut())
        .unwrap();
    if dns.get("fakeIpToggleMigrated") != Some(&Value::Bool(true)) {
        let enable = if mode_lower != "systemproxy" {
            true
        } else {
            dns.get("enableFakeIp")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        };
        dns.insert("enableFakeIp".into(), Value::Bool(enable));
        dns.insert("fakeIpToggleMigrated".into(), Value::Bool(true));
        delta.changed = true;
    }
}

/// FakeIP-TUN 待纠正快照评估。上游 `migrateFakeIpTunPending`。
/// fakeIpTunAutoEnable===undefined 时评估：systemProxy + enableFakeIp===false + migrated → true，否则 false。
pub fn migrate_fake_ip_tun_pending(value: &mut Value, delta: &mut MigrationDelta) {
    let Some(obj) = value.as_object_mut() else {
        return;
    };
    let mode_lower = obj
        .get("proxyModeType")
        .and_then(|v| v.as_str())
        .unwrap_or("systemProxy")
        .to_ascii_lowercase();
    let Some(dns) = obj.get_mut("dnsConfig").and_then(|v| v.as_object_mut()) else {
        return;
    };
    if dns.contains_key("fakeIpTunAutoEnable") {
        return;
    }
    let pending = mode_lower == "systemproxy"
        && dns.get("enableFakeIp").and_then(|v| v.as_bool()) == Some(false)
        && dns.get("fakeIpToggleMigrated") == Some(&Value::Bool(true));
    dns.insert("fakeIpTunAutoEnable".into(), Value::Bool(pending));
    delta.changed = true;
}

/// 节点域名解析器迁移（issue #147）。上游 `migrateNodeResolver`。
/// nodeResolverMigrated!==true 时：nodeDomainResolver → nodeResolverPool/Single + 标记。
pub fn migrate_node_resolver(value: &mut Value, delta: &mut MigrationDelta) {
    let Some(obj) = value.as_object_mut() else {
        return;
    };
    let Some(dns) = obj.get_mut("dnsConfig").and_then(|v| v.as_object_mut()) else {
        return;
    };
    if dns.get("nodeResolverMigrated") == Some(&Value::Bool(true)) {
        return;
    }
    // 克隆 old 为 owned String 以结束不可变借用，随后才可 mutable insert。
    let old = dns
        .get("nodeDomainResolver")
        .and_then(|v| v.as_str())
        .unwrap_or("auto")
        .to_string();
    if !dns.contains_key("nodeResolverPool") {
        let pool: Vec<&str> = match old.as_str() {
            "dnspod" => vec!["dnspod"],
            "system" => vec!["system"],
            _ => vec!["ali", "dnspod"],
        };
        dns.insert(
            "nodeResolverPool".into(),
            Value::Array(pool.into_iter().map(|s| Value::String(s.into())).collect()),
        );
    }
    if !dns.contains_key("nodeResolverSingle") {
        let single = match old.as_str() {
            "dnspod" => "dnspod",
            "system" => "system",
            _ => "ali",
        };
        dns.insert("nodeResolverSingle".into(), Value::String(single.into()));
    }
    dns.insert("nodeResolverMigrated".into(), Value::Bool(true));
    delta.changed = true;
}

/// 订阅代理策略迁移：旧布尔 subscriptionUpdateViaProxy → 三态 subscriptionProxyPolicy。
/// 上游 `migrateSubscriptionProxyPolicy`。仅旧字段存在时执行，消化后删旧字段。
pub fn migrate_subscription_proxy_policy(value: &mut Value, delta: &mut MigrationDelta) {
    let Some(obj) = value.as_object_mut() else {
        return;
    };
    if !obj.contains_key("subscriptionUpdateViaProxy") {
        return;
    }
    let legacy_true = obj
        .get("subscriptionUpdateViaProxy")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !obj.contains_key("subscriptionProxyPolicy") && legacy_true {
        obj.insert(
            "subscriptionProxyPolicy".into(),
            Value::String("proxy".into()),
        );
    }
    obj.remove("subscriptionUpdateViaProxy");
    delta.changed = true;
}

/// TUN stack 一次性迁移：存量 stack → 'auto' + tunStackMigrated 标记。上游 `migrateTunStackConfig`。
/// tunStackMigrated===true 即不动。
pub fn migrate_tun_stack(value: &mut Value, delta: &mut MigrationDelta) {
    let Some(obj) = value.as_object_mut() else {
        return;
    };
    if obj.get("tunStackMigrated") == Some(&Value::Bool(true)) {
        return;
    }
    if let Some(Value::Object(tun)) = obj.get_mut("tunConfig") {
        tun.insert("stack".into(), Value::String("auto".into()));
    }
    obj.insert("tunStackMigrated".into(), Value::Bool(true));
    delta.changed = true;
}

/// TUN MTU 一次性迁移：抹掉存量 `tunConfig.mtu` → 缺席（= 自动）+ `tunMtuMigrated` 标记。
///
/// # 为什么可以整个抹掉，而不是「只抹掉等于旧默认的值」
///
/// **本项在此之前从未有过 UI 入口**（`SettingsTun` 只暴露 stack / autoRoute / strictRoute），故磁盘上
/// 的任何 `mtu` 都是程序写的默认值（新装 `default_config` 的 1350/1400，或旧 builder 的哨兵 9000），
/// 没有一个承载用户意图。逐值判断反而更糟：既要枚举历史默认（1350 / 1400 / 9000 / 未来还会有），
/// 又会把「碰巧手改成 1350」误当默认——而那种手改本来就无从与默认区分。一刀切既准确又不会漂。
///
/// 本迁移**只跑一次**：跑完置 `tunMtuMigrated`，此后用户在新 UI 里设的值不再被碰。
pub fn migrate_tun_mtu(value: &mut Value, delta: &mut MigrationDelta) {
    let Some(obj) = value.as_object_mut() else {
        return;
    };
    if obj.get("tunMtuMigrated") == Some(&Value::Bool(true)) {
        return;
    }
    if let Some(Value::Object(tun)) = obj.get_mut("tunConfig") {
        tun.remove("mtu");
    }
    obj.insert("tunMtuMigrated".into(), Value::Bool(true));
    delta.changed = true;
}

/// 托盘菜单预热最终默认值的一次性迁移。
///
/// 该开关曾在中间验收构建里以 `false` 为默认并被持久化，最终产品决策改为默认 `true` 后，普通的
/// `or_insert(true)` 无法纠正已经存在的 `false`。配置里没有可用的版本来源来区分「中间默认值」与
/// 「用户在中间构建里手动关闭」，因此这里按最终产品默认统一纠正一次，并写入独立标记。标记落定后，
/// 用户再显式关闭预热会被完整保留，不会在后续启动时反复改回。
pub fn migrate_tray_menu_warm_default(value: &mut Value, delta: &mut MigrationDelta) {
    let Some(obj) = value.as_object_mut() else {
        return;
    };
    if obj.get("keepTrayMenuWarmDefaultMigrated") == Some(&Value::Bool(true)) {
        return;
    }
    obj.insert("keepTrayMenuWarm".into(), Value::Bool(true));
    obj.insert("keepTrayMenuWarmDefaultMigrated".into(), Value::Bool(true));
    delta.changed = true;
}

/// **撤掉的「诊断采集」机制留下的孤儿键清理**（本项无历史锚点，是本仓自己的机制被删后的收尾）。
///
/// # 为什么必须有这条腿
///
/// 旧机制「开始采集」做的是：把当前 `logLevel` 快照进 `diagnosticCapture.prevLogLevel`，再把
/// `logLevel` 拉到 `debug`；「结束采集 / 下次启动自愈」再还原回去。机制整体删除后，**在采集中升级的
/// 用户**磁盘上留下的正是这个中间态：`logLevel:"debug"` + 一个再也没有代码会读的 `diagnosticCapture`。
/// 不清理的话，这两件事都会永久留着 —— 用户被静默钉在 debug 级别（日志刷屏、写盘量翻倍），
/// 而那个键成为谁也解释不了的孤儿。
///
/// # 判据是「键在即迁移」，不设独立标记
///
/// 迁移完键就没了，天然幂等，再加一个 `diagnosticCaptureMigrated` 只会是第二个孤儿键。
///
/// # 还原级别的取值
///
/// 只接受本仓 `LogLevel` 的五个合法值；缺失 / 损坏 / 不认识 → 兜 `info`，**绝不留 `debug`**
/// （留 debug 等于迁移没做）。这与旧 `diagnostic_capture_end` 的兜底口径逐字一致。
pub fn migrate_diagnostic_capture(value: &mut Value, delta: &mut MigrationDelta) {
    const LEVELS: [&str; 5] = ["debug", "info", "warn", "error", "fatal"];
    let Some(obj) = value.as_object_mut() else {
        return;
    };
    let Some(cap) = obj.remove("diagnosticCapture") else {
        return; // 无残留 → no-op（绝大多数配置走这条）
    };
    delta.changed = true;
    // `null` 在旧机制里就等于「未在采集」（`diagnostic_capture_active` 判的是「存在且非 null」）⇒
    // 此时 `logLevel` 是用户自己的选择，**不得**被还原逻辑顶掉；只把这个空壳键删掉。
    if cap.is_null() {
        return;
    }
    let restored = cap
        .get("prevLogLevel")
        .and_then(|v| v.as_str())
        .filter(|s| LEVELS.contains(s))
        .unwrap_or("info")
        .to_string();
    obj.insert("logLevel".into(), Value::String(restored));
}

/// 应用分流默认预设注入。Polaris appRulesSeeded 段 + `seedDefaultAppRules`。
/// !appRulesSeeded 时：补内置预设默认规则 + 剔除下线预设（apple/bilibili）残留 + 置标记。
pub fn seed_app_rules(value: &mut Value) -> bool {
    let Some(obj) = value.as_object_mut() else {
        return false;
    };
    let seeded = obj
        .get("appRulesSeeded")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if seeded {
        return false;
    }
    let existing = obj
        .get("appRules")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let seeded_rules = seed_default_app_rules(&existing);
    obj.insert(
        "appRules".into(),
        Value::Array(seeded_rules.into_iter().map(Value::Object).collect()),
    );
    obj.insert("appRulesSeeded".into(), Value::Bool(true));
    true
}

/// seedDefaultAppRules 纯逻辑：剔除下线预设 + 保留 custom-* + 补内置预设默认规则。
/// 复用 config-engine 的内置预设清单（default_app_rules 单一真值）。
fn seed_default_app_rules(existing: &[Value]) -> Vec<Map<String, Value>> {
    use std::collections::HashSet;
    // 内置预设 id 清单（复用 config-engine 单一真值，避免与本crate 静态列表漂移）。
    let valid_ids: HashSet<String> =
        polaris_config_engine::user_config::app_rules_preset::default_app_rules()
            .into_iter()
            .map(|r| r.app_id)
            .collect();
    let mut kept: Vec<Map<String, Value>> = Vec::new();
    let mut have: HashSet<String> = HashSet::new();
    for r in existing {
        let Some(o) = r.as_object() else {
            continue;
        };
        let Some(app_id) = o.get("appId").and_then(|v| v.as_str()) else {
            continue;
        };
        // 保留内置预设 + 自定义（custom-*）；下线预设（apple/bilibili 等）残留 → 丢弃。
        if valid_ids.contains(app_id) || app_id.starts_with("custom-") {
            kept.push(o.clone());
            have.insert(app_id.to_string());
        }
    }
    // 补缺失内置预设的默认「代理·跟全局」规则。
    for id in &valid_ids {
        if !have.contains(id) {
            let mut m = Map::new();
            m.insert("appId".into(), Value::String(id.clone()));
            m.insert("action".into(), Value::String("proxy".into()));
            m.insert("enabled".into(), Value::Bool(true));
            kept.push(m);
        }
    }
    kept
}

#[cfg(test)]
mod tests;
