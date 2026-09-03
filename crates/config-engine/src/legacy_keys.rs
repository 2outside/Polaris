//! sing-box 1.14 升级面：Hysteria v1 透传袋迁移 + 1.16 移除面契约。
//!
//! # 为什么是「改名替换」而不是「新旧并写」
//!
//! 内核对这批旧键的兼容语义是**「新字段为零才取旧值」**（`option/hysteria.go` 的
//! `Deprecated` 迁移分支）。所以并写不是「双保险」而是**新增一条静默歧义**：
//! 新键取值恰为 0（合法输入，含义是「用内核默认」）时，旧键的值会悄悄生效，
//! 用户在表单里把窗口调到默认反而拿到导入时的老值。故本表只做**替换**：旧键 remove、新键 insert。
//!
//! # 取证边界
//!
//! 这五个 Hysteria 键**不在** near-line 上游源码
//! `experimental/deprecated.Report` 的 `Note` 常量表内；1.16 移除日程来自上游
//! docs/changelog，不能伪装成该常量表的五条记录。源码取证是 near-line source，
//! **不是**随包 1.14 的精确 revision；当前接收性则由随包 1.14 二进制
//! `resources/linux/sing-box check -c` 实测。
//!
//! # 随包 1.14 实测
//!
//! 五个旧键在 **hysteria v1 出站**上并非同一处境 —— 两个已经是死配置：
//!
//! | 旧键 | 1.14.0 出站 `check` | 说明 |
//! |------|--------------------|------|
//! | `recv_window_conn`     | rc=0 | 旧名；docs/changelog 定于 1.16 移除 |
//! | `recv_window`          | rc=0 | 旧名；docs/changelog 定于 1.16 移除 |
//! | `recv_window_client`   | **rc=1 `unknown field`** | 只存在于 **入站**，出站从来不收 |
//! | `max_conn_client`      | **rc=1 `unknown field`** | 同上 |
//! | `disable_mtu_discovery`| rc=0 | 旧名；docs/changelog 定于 1.16 移除 |
//!
//! 后两个进本表不是「提前量」而是**修当下的坏配置**：透传袋是从用户本地文件原样收的，
//! 用户把一份 hysteria **服务端** 配置里的键抄进出站，整个核 decode 阶段就起不来
//! （不是坏掉那一个节点）。迁移到出站的对应新键后配置能起。
//!
//! # 新键的类型
//!
//! `stream_receive_window` / `connection_receive_window` 在 1.14 是 `MemoryBytes`
//! （schema：`anyOf: [integer(min 0), string]`）⇒ **裸整数合法**，无需转字符串。
//! 实测：`{"stream_receive_window": 8388608, "connection_receive_window": 16777216,
//! "max_concurrent_streams": 1024, "disable_path_mtu_discovery": true}` → `check` rc=0。

use serde_json::{Map, Value};

/// hysteria **v1** 透传袋里的旧键 → 1.14 新键。
///
/// **表序即优先级**：`recv_window` 与 `recv_window_client` 映射到同一个
/// `stream_receive_window`，靠前者胜（`recv_window` 是出站的正牌旧键，
/// `recv_window_client` 是抄错位置的入站键）⇒ 同一份输入恒得同一份产出。
pub const HYSTERIA_V1_LEGACY_KEYS: &[(&str, &str)] = &[
    ("recv_window_conn", "connection_receive_window"),
    ("recv_window", "stream_receive_window"),
    ("recv_window_client", "stream_receive_window"),
    ("max_conn_client", "max_concurrent_streams"),
    ("disable_mtu_discovery", "disable_path_mtu_discovery"),
];

/// 无需知道 JSON 上下文即可判死的 1.16 移除键。
///
/// 上游 near-line `experimental/deprecated/constants.go` 的 1.16 `Note` 是**特性清单**，
/// 不是可以全局扫的 JSON key 清单。这里只收入键名本身就无歧义的五条：
/// inline ACME、legacy rule-set download detour、legacy DNS rule-set empty 开关、
/// independent DNS cache 与 cache-file RDRC 开关。
///
/// `download_detour` 的上游常量实名是 `OptionLegacyRuleSetDownloadDetour`。
/// Hysteria 五键另由 [`HYSTERIA_V1_LEGACY_KEYS`] 的迁移契约守；DNS rule-action
/// `strategy` 和 legacy address-filter 键必须按 `dns.rules[]` 上下文判；隐式
/// Default HTTP Client 是「必需字段缺席」，由 `explicit_http_client_gate` 守。
pub const UNAMBIGUOUS_JSON_KEYS_REMOVED_IN_1_16: &[&str] = &[
    "acme",
    "download_detour",
    "rule_set_ip_cidr_accept_empty",
    "independent_cache",
    "store_rdrc",
];

/// 只在 `dns.rules[]` 规则对象内才是 1.16 移除面的 rule-action 键。
pub const LEGACY_DNS_RULE_ACTION_KEYS: &[&str] = &["strategy"];

/// `match_response` 未启用时，这两键是 legacy DNS address-filter；启用后它们是
/// 1.14 的合法 response matcher，不能按键名全局扫。
pub const LEGACY_DNS_ADDRESS_FILTER_KEYS: &[&str] = &["ip_cidr", "ip_is_private"];

/// 就地把 hysteria v1 透传袋里的旧键**改名替换**成 1.14 新键。
///
/// 新键已存在时不覆盖：新键是权威（用户表单/上游原文直接给的新名，或表序在前的旧键已迁入），
/// 旧键无论如何都被移除 —— 「产出面旧名零出现」是本函数的后置条件。
pub fn migrate_hysteria_v1_legacy_keys(bag: &mut Map<String, Value>) {
    for (old, new) in HYSTERIA_V1_LEGACY_KEYS {
        let Some(v) = bag.remove(*old) else { continue };
        bag.entry((*new).to_string()).or_insert(v);
    }
}

/// 跨 integration / `src-tauri` 测试共用的 1.16 test-contract analyzer。
///
/// 判据有意拆成两层：无歧义 tombstone 递归全文扫；`strategy` 与
/// address-filter 只深入 `dns.rules[]` 及 logical rule 的嵌套 `rules[]`。因此
/// `outbounds[].strategy`、`route.rules[].ip_cidr` 与已启用 `match_response` 的 DNS
/// `ip_cidr` 不会被误报。
///
/// 这不是 runtime config gate：生产配置路径不得据此拒绝用户配置；它保持 public 仅为了让
/// 两个 crate 的测试共享同一份契约判据。
#[doc(hidden)]
#[must_use]
pub fn removed_in_1_16_config_paths(config: &Value) -> Vec<String> {
    fn scan_tombstones(node: &Value, path: &str, hits: &mut Vec<String>) {
        match node {
            Value::Object(map) => {
                for (key, value) in map {
                    let child = format!("{path}.{key}");
                    if UNAMBIGUOUS_JSON_KEYS_REMOVED_IN_1_16.contains(&key.as_str()) {
                        hits.push(child.clone());
                    }
                    scan_tombstones(value, &child, hits);
                }
            }
            Value::Array(items) => {
                for (index, value) in items.iter().enumerate() {
                    scan_tombstones(value, &format!("{path}[{index}]"), hits);
                }
            }
            _ => {}
        }
    }

    fn match_response_enabled(rule: &Map<String, Value>) -> bool {
        match rule.get("match_response") {
            Some(Value::Bool(enabled)) => *enabled,
            Some(Value::String(tag)) => !tag.is_empty(),
            _ => false,
        }
    }

    fn scan_dns_rule(rule: &Value, path: &str, hits: &mut Vec<String>) {
        let Some(map) = rule.as_object() else {
            return;
        };
        for key in LEGACY_DNS_RULE_ACTION_KEYS {
            if map.contains_key(*key) {
                hits.push(format!("{path}.{key}"));
            }
        }
        if !match_response_enabled(map) {
            for key in LEGACY_DNS_ADDRESS_FILTER_KEYS {
                if map.contains_key(*key) {
                    hits.push(format!("{path}.{key}"));
                }
            }
        }
        if let Some(children) = map.get("rules").and_then(Value::as_array) {
            for (index, child) in children.iter().enumerate() {
                scan_dns_rule(child, &format!("{path}.rules[{index}]"), hits);
            }
        }
    }

    let mut hits = Vec::new();
    scan_tombstones(config, "$", &mut hits);
    if let Some(rules) = config
        .get("dns")
        .and_then(|dns| dns.get("rules"))
        .and_then(Value::as_array)
    {
        for (index, rule) in rules.iter().enumerate() {
            scan_dns_rule(rule, &format!("$.dns.rules[{index}]"), &mut hits);
        }
    }
    hits
}
