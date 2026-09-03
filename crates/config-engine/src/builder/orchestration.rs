//! 编排收尾函数（上游 `ProxyManager.ts` 的纯逻辑子集）。
//!
//! 含：stableStringify（键序无关序列化）、serverFingerprint（节点指纹）、
//! configGenerationNorm（影响生成的配置投影）、fixRouteDeadReferences（route 死引用兜底）。
//! planHotSwitch/canSkipRestartForAddedUnreferenced 见 `hotswitch.rs`（H6-⑤）。
//! generateSingBoxConfig 编排见 `generate.rs`（H6-④）。
//!
//! 所有函数纯逻辑无 I/O，实例态由参数注入。

#![forbid(unsafe_code)]

use crate::user_config::app_config::UserConfig;
use crate::user_config::rule::RuleType;
use crate::user_config::rules::rule_conditions;
use std::collections::BTreeSet;

/// 递归按 key 排序后序列化——使深比较对对象属性插入顺序不敏感。
///
/// 数组顺序保留（customRules/appRules 顺序具语义）。undefined 键丢弃（与 JSON.stringify 一致）。
/// 上游 `ProxyManager.stableStringify`。
pub fn stable_stringify(v: &serde_json::Value) -> String {
    let canonical = canonicalize(v);
    serde_json::to_string(&canonical).unwrap_or_else(|_| "null".to_string())
}

/// 递归把 serde_json::Value 转为键排序的规范形式（Object → BTreeMap-backed）。
fn canonicalize(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            // 收集 (key, canonical_value) 并按 key 排序，丢弃 null 值（对齐 Polaris 丢 undefined）。
            // 注意：Polaris stableStringify 丢 undefined，但 JSON 里 null 是合法值。
            // Polaris 的 `v[k] !== undefined` 在 JS 对象里 undefined = 不存在的键，null = 存在。
            // serde_json Value::Object 不含 undefined（JSON 无），故只需排序，null 保留。
            let mut pairs: Vec<(String, serde_json::Value)> = map
                .iter()
                .map(|(k, v)| (k.clone(), canonicalize(v)))
                .collect();
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            let mut sorted = serde_json::Map::new();
            for (k, v) in pairs {
                sorted.insert(k, v);
            }
            serde_json::Value::Object(sorted)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(canonicalize).collect())
        }
        other => other.clone(),
    }
}

/// 节点生成指纹（剔时间戳、键序无关）。
///
/// canSkip③、runningServersFingerprint 快照、待应用差集、dirty 判定共用单一真值。
/// 剔除 updatedAt/createdAt/providerName（归属元数据不改连接内容）。
/// 上游 `ProxyManager.serverFingerprint`。
pub fn server_fingerprint(server: &crate::user_config::server_config::ServerConfig) -> String {
    // 序列化为 Value，剔除时间戳/归属元数据，再 stableStringify。
    let mut value = serde_json::to_value(server).unwrap_or(serde_json::Value::Null);
    if let Some(obj) = value.as_object_mut() {
        obj.remove("updatedAt");
        obj.remove("createdAt");
        obj.remove("providerName");
    }
    stable_stringify(&value)
}

/// 影响生成的配置投影 → 键序无关序列化字符串。
///
/// 热切换判定基础：norm(old) === norm(new) ⟹ 结构等价（仅 selectedServerId/targetServerId 值变）。
/// 排除所有不影响 sing-box 生成的字段（UI 偏好/调度偏好/元数据）。
/// 上游 `ProxyManager.configGenerationNorm`。
///
/// `server_ids`：P2-A 传 Some 时仅保留被引用节点（canSkipRestart 用），None = 全量。
pub fn config_generation_norm(
    config: &UserConfig,
    server_ids: Option<&BTreeSet<String>>,
) -> String {
    let proxy_mode = config.proxy_mode.as_str();
    let user_routing_active = proxy_mode.eq_ignore_ascii_case("smart");

    // 被启用 ruleSet 规则引用的本地资源 id 集。流量效果受 smart 门控，DNS 效果三种模式均生效。
    let mut ids: BTreeSet<String> = BTreeSet::new();
    for r in config
        .effective_traffic_rules()
        .iter()
        .chain(config.effective_dns_rules().iter())
    {
        if !r.enabled
            || (r.dns_effect().is_none() && !(user_routing_active && r.route_action().is_some()))
        {
            continue;
        }
        for cond in rule_conditions(r) {
            if cond.type_field == RuleType::RuleSet {
                for v in &cond.values {
                    if let Some(rest) = v.strip_prefix("res:") {
                        ids.insert(rest.to_string());
                    }
                }
            }
        }
    }

    // 构建投影对象（对齐 Polaris 的字段排除/投影规则）。
    let mut proj = serde_json::Map::new();

    // 全量 config 序列化后投影（而非 spread + null 覆盖——Rust 无 spread）。
    let full = serde_json::to_value(config).unwrap_or(serde_json::Value::Null);
    if let Some(obj) = full.as_object() {
        for (k, v) in obj {
            // 排除不影响生成的字段（Polaris 置 null 的键 = 此处跳过不进投影）。
            //
            // **只剩 `selectedServerId` 一项，这是全集不是节选**：真实判据是「该键是不是 `UserConfig`
            // 的序列化字段」——`UserConfig` 零 `#[serde(flatten)]`，故 `full` 的键集 ⊆
            // `UserConfig::FIELD_NAMES`（由 `field_names_equals_serde_projection` 钉死）。排除一个
            // 不在该结构里的键是**空操作**，`continue` 永不触发。
            //
            // 2026-07-29 清理：此处原有 15 项，其中 14 项（`ghProxyPrefix` / `language` /
            // `hardwareAcceleration` / `windowEffects` / `subscriptions` / `restartOnNodeChange` /
            // `mainSessionViaProxy` / `meshLoginFallbackDirect` / `builtinGeoMeta` /
            // `ruleResourceAutoUpdate` / `ruleResourceUpdateIntervalHours` / `helper*PromptDismissed` ×3）
            // 都不是 `UserConfig` 字段 ⇒ 全是死分支。它们唯一的存在理由是**与 上游的同名排除表逐行
            // 对拍**（那边 config 形状更宽），而该判据已于 2026-07-29 退役（改为「原型 ↔ 后端双向对拍」，
            // 见 `polaris-oracle-retirement-2026-07-29`）⇒ 理由消失，一并删除。
            //
            // 删除**同时消掉了它们曾带来的风险**：死键留在表里时，谁把 `language` 之类升成真字段，
            // 排除就会从空操作静默变成「让该字段不参与生成判等」（改它不再触发重启内核）。键不在表里，
            // 这条路径不复存在。剩下这一项的生效面仍由 `exclusion_table_live_entries_are_pinned` 钉住。
            if k.as_str() == "selectedServerId" {
                continue;
            }
            // dnsConfig 子投影：剔除迁移元数据标记。
            if k == "dnsConfig" {
                if let Some(dns_obj) = v.as_object() {
                    let mut dns_proj = serde_json::Map::new();
                    for (dk, dv) in dns_obj {
                        if matches!(
                            dk.as_str(),
                            "fakeIpToggleMigrated" | "fakeIpTunAutoEnable" | "nodeResolverMigrated"
                        ) {
                            continue;
                        }
                        dns_proj.insert(dk.clone(), dv.clone());
                    }
                    proj.insert(k.clone(), serde_json::Value::Object(dns_proj));
                }
                continue;
            }
            // 规则平面 / appRules / ruleResources / servers 在下方按生效真值单独投影。
            // 三代规则集合必须全部剔除原始值，再由 effective_* 规范化回填；否则 trafficRules 已是 SoT 时，
            // 陈旧 customRules 会继续影响判等，或 targetServerId 泄漏导致本可证明的 selector 热切误重启。
            if matches!(
                k.as_str(),
                "customRules"
                    | "policyRules"
                    | "trafficRules"
                    | "dnsRules"
                    | "appRules"
                    | "ruleResources"
                    | "servers"
            ) {
                continue;
            }
            proj.insert(k.clone(), v.clone());
        }
    }

    // 一等流量规则投影（缺省兼容 policyRules/customRules）。targetServerId 由 selector 热切，不进 norm。
    let traffic_rules_proj = {
        let dns_rule_active = |rule: &crate::user_config::rule::Rule| match &rule.effects {
            Some(effects) => effects.dns.is_some(),
            None => user_routing_active && rule.bypass_fakeip == Some(true),
        };
        let arr: Vec<serde_json::Value> = config
            .effective_traffic_rules()
            .iter()
            .filter(|r| {
                r.enabled
                    && (dns_rule_active(r) || (user_routing_active && r.route_action().is_some()))
            })
            .map(|r| {
                use crate::builder::custom_rule_files::plan_custom_rule;
                if dns_rule_active(r) {
                    // DNS 规则目前内联进 dns.rules：条件值变化会改变生成配置，必须参与判等。
                    // targetServerId 仍由 selector 热切换，兼容镜像与 effects.route 两处都剔除。
                    let mut v = serde_json::to_value(r).unwrap_or(serde_json::Value::Null);
                    if let Some(o) = v.as_object_mut() {
                        o.remove("remarks");
                        o.remove("targetServerId");
                        if let Some(route) = o
                            .get_mut("effects")
                            .and_then(serde_json::Value::as_object_mut)
                            .and_then(|effects| effects.get_mut("route"))
                            .and_then(serde_json::Value::as_object_mut)
                        {
                            route.remove("targetServerId");
                        }
                    }
                    v
                } else if matches!(
                    plan_custom_rule(r),
                    crate::builder::custom_rule_files::RulePlan::Inline
                ) {
                    // smart inline：保留全量结构，剔 remarks + 两代 targetServerId（值热切换）。
                    let mut v = serde_json::to_value(r).unwrap_or(serde_json::Value::Null);
                    if let Some(o) = v.as_object_mut() {
                        o.remove("remarks");
                        o.remove("targetServerId");
                        if let Some(route) = o
                            .get_mut("effects")
                            .and_then(serde_json::Value::as_object_mut)
                            .and_then(|effects| effects.get_mut("route"))
                            .and_then(serde_json::Value::as_object_mut)
                        {
                            route.remove("targetServerId");
                        }
                    }
                    v
                } else {
                    // smart ext：结构位保留，值移出 norm。
                    let conds: Vec<serde_json::Value> = rule_conditions(r)
                        .into_iter()
                        .map(|cd| {
                            let ok = crate::builder::custom_rule_files::cond_matcher_fields(&cd)
                                .is_some();
                            serde_json::json!({
                                "t": cd.type_field,
                                "ok": ok,
                            })
                        })
                        .collect();
                    serde_json::json!({
                        "__ext": 1,
                        "id": r.id,
                        "action": r.route_action(),
                        "targetServerId": null,
                        "combineMode": r.combine_mode,
                        "bypassFakeIP": r.bypass_fakeip.unwrap_or(false),
                        "conds": conds,
                    })
                }
            })
            .collect();
        serde_json::Value::Array(arr)
    };
    proj.insert("trafficRules".into(), traffic_rules_proj);

    // DNS 规则独立投影。DNS 条件/动作变化必须重生成；纯 route target 不影响 DNS，继续剔除。
    let dns_rules_proj: Vec<serde_json::Value> = config
        .effective_dns_rules()
        .iter()
        .filter(|rule| {
            rule.enabled
                && match &rule.effects {
                    Some(effects) => effects.dns.is_some(),
                    None => user_routing_active && rule.bypass_fakeip == Some(true),
                }
        })
        .map(|rule| {
            let mut value = serde_json::to_value(rule).unwrap_or(serde_json::Value::Null);
            if let Some(object) = value.as_object_mut() {
                object.remove("remarks");
                object.remove("targetServerId");
                if let Some(route) = object
                    .get_mut("effects")
                    .and_then(serde_json::Value::as_object_mut)
                    .and_then(|effects| effects.get_mut("route"))
                    .and_then(serde_json::Value::as_object_mut)
                {
                    route.remove("targetServerId");
                }
            }
            value
        })
        .collect();
    proj.insert("dnsRules".into(), serde_json::Value::Array(dns_rules_proj));

    // appRules 投影：仅 smart 生效。targetServerId 移出 norm。
    let app_rules_proj = if user_routing_active {
        let arr: Vec<serde_json::Value> = config
            .app_rules
            .iter()
            .map(|a| {
                serde_json::json!({
                    "appId": a.app_id,
                    "action": a.action,
                    "enabled": a.enabled,
                    "targetServerId": null,
                })
            })
            .collect();
        serde_json::Value::Array(arr)
    } else {
        serde_json::Value::Array(vec![])
    };
    proj.insert("appRules".into(), app_rules_proj);

    // ruleResources 投影：仅被启用 ruleSet 引用的资源 id，排序。
    let rule_resources_proj: Vec<serde_json::Value> = config
        .rule_resources
        .iter()
        .filter(|rr| ids.contains(&rr.id))
        .map(|rr| serde_json::Value::String(rr.id.clone()))
        .collect();
    let mut sorted_rr = rule_resources_proj;
    sorted_rr.sort_by(|a, b| a.as_str().unwrap_or("").cmp(b.as_str().unwrap_or("")));
    proj.insert("ruleResources".into(), serde_json::Value::Array(sorted_rr));

    // servers 投影：server_ids 过滤 + id 排序 + server_fingerprint。
    let mut servers_proj: Vec<serde_json::Value> = config
        .servers
        .iter()
        .filter(|s| server_ids.map(|ids| ids.contains(&s.id)).unwrap_or(true))
        .map(|s| serde_json::Value::String(server_fingerprint(s)))
        .collect();
    servers_proj.sort_by(|a, b| {
        // server_fingerprint 已含 id，但 Polaris 按 server.id 排序后再 fingerprint。
        // 此处直接对 fingerprint 串排序（等价：fingerprint 内含 id，排序结果一致）。
        a.as_str().unwrap_or("").cmp(b.as_str().unwrap_or(""))
    });
    // 注意：Polaris 先按 server.id.localeCompare 排序再 map fingerprint。
    // 为字节精确对齐，需先按 id 排序。修正：
    let mut servers_with_id: Vec<(&str, String)> = config
        .servers
        .iter()
        .filter(|s| server_ids.map(|ids| ids.contains(&s.id)).unwrap_or(true))
        .map(|s| (s.id.as_str(), server_fingerprint(s)))
        .collect();
    servers_with_id.sort_by(|a, b| a.0.cmp(b.0));
    let servers_final: Vec<serde_json::Value> = servers_with_id
        .into_iter()
        .map(|(_, fp)| serde_json::Value::String(fp))
        .collect();
    proj.insert("servers".into(), serde_json::Value::Array(servers_final));
    // 消除未使用警告（servers_proj 被 servers_final 替代）。
    let _ = servers_proj;

    stable_stringify(&serde_json::Value::Object(proj))
}

/// route 死引用兜底：route 规则的 outbound 指向不存在的 tag → 改写为 proxy-selector。
///
/// 任何 action='route' 的规则，其 outbound 不在 outbounds[].tag ∪ endpoints[].tag 集合中 → 改写。
/// 上游 `ProxyManager.fixRouteDeadReferences`。
pub fn fix_route_dead_references(
    outbounds: &[crate::singbox::Outbound],
    endpoints: &[crate::singbox::Endpoint],
    rules: &mut [crate::singbox::RouteRule],
) {
    let valid_tags: BTreeSet<String> = outbounds
        .iter()
        .map(|o| o.tag.clone())
        .chain(endpoints.iter().map(|e| e.tag.clone()))
        .filter(|t| !t.is_empty())
        .collect();
    for rule in rules.iter_mut() {
        // action='route' 且 outbound 不在有效 tag 集合 → 改写 proxy-selector。
        // RouteRule 的 action/outbound 字段需确认。
        let is_route = rule
            .action
            .as_deref()
            .map(|a| a == "route")
            .unwrap_or(false);
        if is_route {
            if let Some(outbound) = &rule.outbound {
                if !valid_tags.contains(outbound) {
                    rule.outbound = Some("proxy-selector".to_string());
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests;
