//! 路由规则值/聚合校验（上游 `shared/rules.ts` 的 `validateRuleValue` / `validateRule` /
//! `isValidIpCidr` 权威 Rust 实现）——**单一真值**。
//!
//! 历史上本逻辑有两份副本：`user_config/rules.rs`（仅端口 token）与 `store/validate.rs`
//! （完整逐类型校验 + 严格 IP/CIDR，且各自私有一份 `valid_port_token`）。D4 收敛为一份：
//! 完整实现落 config-engine（最底层、持有 `Rule`/`RuleType` 类型），`store/validate.rs`
//! 改为 re-export 本模块（config 落盘 sanitize 复用同一真值），端口 token 复用
//! `rules::is_valid_port_value`（消除第二份 `valid_port_token`）。
//!
//! D4 提交门：rule-dialog 提交经 Tauri `rules_add`/`rules_update` 调 [`validate_rule`]，
//! 权威在 Rust；前端只留 `isValidIpCidr` 做输入内联提示。
//!
//! 语义与 sing-box `netip.ParsePrefix` 对齐（严格 IPv4/IPv6：拒前导零、掩码越界、非法结构），
//! 放过这些值会让内核启动 FATAL。

#![forbid(unsafe_code)]

use crate::user_config::rule::Rule;
use crate::user_config::rules::{is_valid_port_value, rule_conditions};
use crate::user_config::{is_valid_mac_address, is_valid_source_hostname};

/// 规则类型全集（上游 `RULE_TYPE_IDS`，camelCase）。与 [`crate::user_config::rule::RuleType::as_id`]
/// 严格同源（见本模块单测 `rule_type_ids_in_sync`），供 sanitize 阶段按字符串判定已知类型。
pub const RULE_TYPE_IDS: &[&str] = &[
    "domain",
    "domainSuffix",
    "domainKeyword",
    "domainRegex",
    "ipCidr",
    "sourceIpCidr",
    "port",
    "sourcePort",
    "sourceMac",
    "sourceHostname",
    "processName",
    "processPath",
    "geosite",
    "geoip",
    "ruleSet",
];

/// 规则类型是否已知（camelCase 比对）。
#[must_use]
pub fn is_known_rule_type(t: &str) -> bool {
    RULE_TYPE_IDS.contains(&t)
}

/// 严格 IPv4（恰 4 段、每段 0-255、禁前导零）。上游 `isStrictIpv4`。
fn is_strict_ipv4(addr: &str) -> bool {
    let octets: Vec<&str> = addr.split('.').collect();
    octets.len() == 4
        && octets.iter().all(|&o| {
            // (0|[1-9]\d{0,2}) 且 ≤255（禁前导零，对齐 sing-box netip）
            o.parse::<u32>().is_ok_and(|n| n <= 255)
                && (o == "0" || !o.starts_with('0'))
                && o.bytes().all(|b| b.is_ascii_digit())
        })
}

/// 结构化 IPv6 校验（`::` 至多一次、每段 1-4 hex、末段可内嵌 IPv4）。
/// 上游 `isStrictIpv6`，匹配 sing-box netip.ParsePrefix。
fn is_strict_ipv6(addr: &str) -> bool {
    let parts: Vec<&str> = addr.split("::").collect();
    if parts.len() > 2 {
        return false;
    }
    let has_compression = parts.len() == 2;
    let left: Vec<&str> = if parts[0].is_empty() {
        vec![]
    } else {
        parts[0].split(':').collect()
    };
    let right: Vec<&str> = if has_compression {
        if parts[1].is_empty() {
            vec![]
        } else {
            parts[1].split(':').collect()
        }
    } else {
        vec![]
    };
    let mut groups: Vec<&str> = left;
    groups.extend(right);
    let mut ipv4_suffix = false;
    for (i, g) in groups.iter().enumerate() {
        if i == groups.len() - 1 && g.contains('.') {
            if !is_strict_ipv4(g) {
                return false;
            }
            ipv4_suffix = true;
        } else if !(!g.is_empty() && g.len() <= 4 && g.bytes().all(|b| b.is_ascii_hexdigit())) {
            return false;
        }
    }
    let count = groups.len() + if ipv4_suffix { 1 } else { 0 };
    // 无 :: 须恰 8 段；有 :: 时代表 ≥1 零段，显式段须 ≤7。
    if has_compression {
        count <= 7
    } else {
        count == 8
    }
}

/// IPv4/IPv6（可选 CIDR 掩码）严格校验。上游 `isValidIpCidr`。
/// 含范围+结构检查：八位组 ≤255、禁前导零、掩码 v4≤32 / v6≤128、IPv6 结构合法。
#[must_use]
pub fn is_valid_ip_cidr(value: &str) -> bool {
    let v = value.trim();
    if v.is_empty() {
        return false;
    }
    let (addr, mask) = match v.split_once('/') {
        Some((a, m)) => (a, Some(m)),
        None => (v, None),
    };
    let is_v6 = addr.contains(':');
    if let Some(m) = mask {
        if !(m.len() <= 3 && m.bytes().all(|b| b.is_ascii_digit())) {
            return false;
        }
        let prefix: u32 = m.parse().unwrap_or(999);
        let max = if is_v6 { 128 } else { 32 };
        if prefix > max {
            return false;
        }
    }
    if is_v6 {
        is_strict_ipv6(addr)
    } else {
        is_strict_ipv4(addr)
    }
}

/// 单条规则值是否合法（按类型）。上游 `validateRuleValue`（空串一律非法）。
/// 仅做形状校验（sanitize 阶段已过滤非字符串）；生成期再校验。
#[must_use]
pub fn validate_rule_value(rule_type: &str, value: &str) -> bool {
    let v = value.trim();
    if v.is_empty() {
        return false;
    }
    match rule_type {
        "domain" | "domainSuffix" => is_domain_shape(v),
        // 关键词是对**域名**做子串匹配，而 DNS 名里不可能出现 `:` ⇒ 含冒号的关键词恒不命中。
        // 用户把 IPv6 字面量（`2001:db8::1`、URL 写法 `[2001:db8::1]`）填进关键词条件时，落成的
        // `domain_keyword` 是一条永不命中的死配置，且内核不报错、用户以为配好了 —— 故在提交门硬拒。
        // 判据取「含冒号」而非「是 IPv6 字面量」：前者可证（DNS 名不含冒号），且顺带盖住 `foo:bar`
        // 这类同样恒不命中的值；`domain`/`domainSuffix` 经 `is_domain_shape` 本就拒冒号，此处补齐同族最后一个缺口。
        // **不推广到 IPv4**：`1.2.3.4` 作关键词能命中 `1.2.3.4.nip.io` / `4.3.2.1.in-addr.arpa` 这类
        // 真实域名，拒掉会砍掉合法能力（详见本模块单测 `domain_keyword_*`）。
        "domainKeyword" => !v.contains(':'),
        "domainRegex" => {
            // RE2 拒 lookahead/lookbehind/反向引用；Rust 无 new RegExp，仅做 RE2 禁项粗检。
            // 反向引用 \1..\9 全拒（TS `\\[1-9]`），非仅 \1。
            if v.contains("(?=") || v.contains("(?!") || v.contains("(?<") {
                return false;
            }
            !v.as_bytes()
                .windows(2)
                .any(|w| w[0] == b'\\' && w[1].is_ascii_digit() && w[1] != b'0')
        }
        "ipCidr" | "sourceIpCidr" => is_valid_ip_cidr(v),
        "port" | "sourcePort" => is_valid_port_value(v),
        "sourceMac" => is_valid_mac_address(Some(v)),
        "sourceHostname" => is_valid_source_hostname(Some(v)),
        "processName" => !v.contains('/') && !v.contains('\\'),
        "processPath" => v.starts_with('/') || windows_path(v),
        "geosite" | "geoip" => {
            // 小写字母数字 + ! - _（大小写不敏感，对齐 TS GEO_TAG_RE 的 /i）
            v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'!' || b == b'-' || b == b'_')
        }
        "ruleSet" => {
            if let Some(rest) = v.strip_prefix("res:") {
                !rest.is_empty()
            } else {
                v.starts_with("http://") || v.starts_with("https://")
            }
        }
        _ => false,
    }
}

/// Windows 路径前缀（`C:\` / `D:/`）。上游 `/^[A-Za-z]:[\\/]/`。
fn windows_path(v: &str) -> bool {
    let b = v.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
}

/// 域名形状（Polaris DOMAIN_RE 等价手写：标签 1-63、字母数字/连字符/下划线、可 *. 前缀）。
fn is_domain_shape(v: &str) -> bool {
    let s = v.strip_prefix("*.").unwrap_or(v);
    if s.is_empty() {
        return false;
    }
    // 点分标签，每标签 1-63、字母数字开头结尾、中间可 -_
    s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_')
            && label
                .bytes()
                .last()
                .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

/// 一条规则的聚合校验结果（提交门 DTO）。`valid == errors.is_empty()`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleValidation {
    pub valid: bool,
    pub errors: Vec<String>,
}

/// 聚合校验一条规则（上游 `validateRule`）：遍历全部条件（`rule_conditions` 归一——
/// 多条件用 `conditions`，否则退化为镜像单条件），每个条件须有 ≥1 个非空值且全部值合法。
///
/// 类型系统已强制 `RuleType`/`CombineMode` 枚举合法（TS 需运行时校验镜像 `type`/`combineMode`，
/// Rust 由类型保证，故此处不再重复），本函数只判各条件的值。
#[must_use]
pub fn validate_rule(rule: &Rule) -> RuleValidation {
    let mut errors = Vec::new();
    let conditions = rule_conditions(rule);
    if let Some(effects) = &rule.effects {
        if effects.route.is_none() && effects.dns.is_none() {
            errors.push("RULE_EFFECTS_EMPTY".to_string());
        }
        if effects.dns.is_some() {
            for condition in &conditions {
                if !condition.type_field.supports_dns_effect() {
                    errors.push(format!(
                        "RULE_DNS_MATCH_UNSUPPORTED:{}",
                        condition.type_field.as_id()
                    ));
                }
            }
        }
    }
    for cond in conditions {
        let type_id = cond.type_field.as_id();
        let non_empty: Vec<&String> = cond
            .values
            .iter()
            .filter(|v| !v.trim().is_empty())
            .collect();
        if non_empty.is_empty() {
            errors.push(format!("{type_id}: 缺少有效值"));
            continue;
        }
        for v in non_empty {
            if !validate_rule_value(type_id, v) {
                errors.push(format!("{type_id}: 非法值 \"{}\"", v.trim()));
            }
        }
    }
    RuleValidation {
        valid: errors.is_empty(),
        errors,
    }
}

#[cfg(test)]
mod tests;
