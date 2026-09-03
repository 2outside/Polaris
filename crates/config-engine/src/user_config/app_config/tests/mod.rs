use super::*;
use crate::user_config::region_routing::RegionRoutingConfig;
use std::collections::BTreeSet;

/// 全字段就位的实例。
///
/// 两条约束，缺一这道门就没牙：
///  1. **穷尽结构字面量**（禁 `..Default::default()`）—— 新增字段 → E0063 编译失败 → 作者必到此一游。
///  2. 所有 `Option` 一律 `Some` —— 带 `skip_serializing_if = "Option::is_none"` 的 10 个字段若为 `None`
///     就**不出现在投影里**，相等断言会静默退化成「只测了 17 项」。
fn fully_populated() -> UserConfig {
    UserConfig {
        config_schema_version: Some(2),
        servers: Vec::new(),
        subscriptions: vec![SubscriptionInterfacePolicy {
            id: "sub".into(),
            proxy_bind_interface: Some("en0".into()),
        }],
        selected_server_id: Some(String::new()),
        proxy_mode: default_proxy_mode(),
        proxy_mode_type: default_proxy_mode_type(),
        tun_config: Some(TunModeConfig::default()),
        network_interfaces: Some(NetworkInterfaceDefaults {
            direct: Some("en0".into()),
            proxy: Some("en1".into()),
        }),
        custom_rules: Vec::new(),
        policy_rules: Some(Vec::new()),
        traffic_rules: Some(Vec::new()),
        dns_rules: Some(Vec::new()),
        route_rule_order: Vec::new(),
        dns_rule_order: Vec::new(),
        dns_servers: Vec::new(),
        dns_server_groups: Vec::new(),
        dns_defaults: Some(DnsPolicyDefaults::default()),
        route_defaults: Some(RoutePolicyDefaults::default()),
        app_rules: Vec::new(),
        app_routing_enabled: Some(false),
        custom_app_presets: Vec::new(),
        allow_lan: Some(false),
        bypass_lan: Some(false),
        bypass_lan_list: Some(Vec::new()),
        enable_ipv6: Some(false),
        mixed_port: Some(0),
        http_port: Some(0),
        dns_config: Some(DnsConfig::default()),
        rule_resources: Vec::new(),
        tls_fragment: Some(false),
        interrupt_connections_on_switch: Some(false),
        resolve_before_dial: Some(false),
        region_routing: Some(RegionRoutingConfig::default()),
        fake_ip_filter: Some(false),
        fake_ip_filter_list: Some(Vec::new()),
        block_browser_doh: Some(false),
        browser_doh_list: Some(Vec::new()),
        block_quic: Some(false),
        webrtc_leak_protection: Some(String::new()),
        bypass_processes: Some(Vec::new()),
        clash_api_secret: Some(String::new()),
        singbox_dashboard: Some(false),
        log_level: Some(serde_json::json!("info")),
        disable_log_file: Some(serde_json::json!(false)),
    }
}

/// `FIELD_NAMES` ≡ serde 投影的键集。
///
/// 牙：改一个 `#[serde(rename = ...)]` 而不改表（或反之）→ 两侧集合不等 → 转红。
#[test]
fn field_names_equals_serde_projection() {
    let value = serde_json::to_value(fully_populated()).expect("UserConfig 必须可序列化");
    let projected: BTreeSet<&str> = value
        .as_object()
        .expect("UserConfig 序列化必须是 object")
        .keys()
        .map(String::as_str)
        .collect();
    let declared: BTreeSet<&str> = UserConfig::FIELD_NAMES.iter().copied().collect();
    assert_eq!(
        declared, projected,
        "UserConfig::FIELD_NAMES 与实际序列化键集不符（加/删/改名字段后忘了同步常量表）"
    );
}

/// 表内不得有重复项 —— 重复会让上面那条集合断言在「漏了一项 + 抄重了一项」时假绿。
#[test]
fn field_names_has_no_duplicates() {
    let unique: BTreeSet<&str> = UserConfig::FIELD_NAMES.iter().copied().collect();
    assert_eq!(unique.len(), UserConfig::FIELD_NAMES.len());
}
