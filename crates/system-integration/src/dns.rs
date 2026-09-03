//! 系统 DNS 纯逻辑（marker + 平台输出解析 + 防自指原始值计算）。
//!
//! 1:1 移植自 上游 `shared/system-dns.ts`。可单测、无 I/O 副作用；marker IO 在 [`crate::dns_ops`]，
//! 命令构造 / orchestration 也在 [`crate::dns_ops`]。本模块只提供纯数据 + 纯函数。

#![forbid(unsafe_code)]

use polaris_config_engine::user_config::dns_constants::CONTROLLED_TUN_DNS_IP;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// 系统 DNS marker：记录「DNS 由 Polaris 接管」+ 接管前每个网络服务/接口的原始 DNS（`[] = DHCP/自动`）。
/// 上游 `SystemDnsMarker`。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemDnsMarker {
    pub controlled_ip: String,
    pub original: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub at: u64,
}

/// 受控 DNS IP（封装常量，便于护栏断言其不在 bootstrap-direct 列表）。上游 `controlledTunDnsIp`。
pub fn controlled_tun_dns_ip() -> &'static str {
    CONTROLLED_TUN_DNS_IP
}

/// 受控 DNS IP 是否合法（不在 bootstrap-direct 列表——否则 :53 被直连放行逃逸 hijack）。
/// 上游 `isControlledDnsIpValid`。
pub fn is_controlled_dns_ip_valid(ip: &str) -> bool {
    !polaris_config_engine::user_config::dns_constants::is_bootstrap_direct_dns(ip)
}

/// 解析 macOS `networksetup -getdnsservers "<svc>"` 输出 → IP 列表。
/// 未设置时输出 "There aren't any DNS Servers set on `<svc>`." → 返回 `[]`（= DHCP/自动）。
/// 上游 `parseMacGetDnsServers`。
pub fn parse_mac_get_dns_servers(stdout: &str) -> Vec<String> {
    let lines: Vec<&str> = stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if lines.is_empty() {
        return vec![];
    }
    if lines
        .iter()
        .any(|l| l.contains("aren't any DNS Servers") || l.contains("There aren't any"))
    {
        return vec![];
    }
    // 每行一个 IP（v4 或 v6）；过滤非 IP 行。
    lines
        .iter()
        .filter(|l| {
            let s = l.as_bytes();
            !s.is_empty()
                && s.iter()
                    .all(|&b| b.is_ascii_hexdigit() || b == b'.' || b == b':')
                && (l.contains('.') || l.contains(':'))
        })
        .map(|l| l.to_string())
        .collect()
}

/// macOS 设 DNS 的 networksetup argv。`ips` 空 → `['Empty']` 还原为 DHCP。
/// 上游 `macSetDnsArgs`。
pub fn mac_set_dns_args(service: &str, ips: &[String]) -> Vec<String> {
    let mut args = vec!["-setdnsservers".into(), service.into()];
    if ips.is_empty() {
        args.push("Empty".into());
    } else {
        args.extend(ips.iter().cloned());
    }
    args
}

/// Windows netsh 设/还原某接口 IPv4 DNS 的命令串序列。
/// `ips` 空 → `source=dhcp`；非空 → 首个 static primary，其余 add。
/// 上游 `winSetDnsCommands`。
pub fn win_set_dns_commands(netsh_exe: &str, iface: &str, ips: &[String]) -> Vec<String> {
    if ips.is_empty() {
        return vec![format!(
            "\"{netsh_exe}\" interface ipv4 set dnsservers name=\"{iface}\" source=dhcp"
        )];
    }
    let mut cmds = vec![format!(
        "\"{netsh_exe}\" interface ipv4 set dnsservers name=\"{iface}\" static {} primary validate=no",
        ips[0]
    )];
    for (i, ip) in ips.iter().enumerate().skip(1) {
        cmds.push(format!(
            "\"{netsh_exe}\" interface ipv4 add dnsservers name=\"{iface}\" address={ip} index={} validate=no",
            i + 1
        ));
    }
    cmds
}

/// 解析 `netsh ... show dnsservers` 输出 → 静态 DNS IP 列表（仅 Statically Configured 时取）。
/// 「DHCP/自动」→ `[]`。注：netsh 输出本地化，非英文环境解析可能失准。
/// 上游 `parseWinShowDnsServers`。
pub fn parse_win_show_dns_servers(stdout: &str) -> Vec<String> {
    if !stdout.contains("Statically Configured DNS Servers")
        && !stdout.contains("静态配置的 DNS 服务器")
    {
        return vec![];
    }
    let mut ips = Vec::new();
    for m in ipv4_find_iter(stdout) {
        if !ips.contains(&m) {
            ips.push(m);
        }
    }
    ips
}

/// 解析 `netsh interface ipv4 show interfaces` 输出 → 已连接、非 loopback 的接口名列表。
/// 注：netsh 输出本地化。上游 `parseWinInterfaces`。
pub fn parse_win_interfaces(stdout: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        // 形如：idx rtr mtu state name
        //   12  10  1500  connected  Wi-Fi
        let trimmed = line.trim_start();
        let mut it = trimmed.split_whitespace();
        let Some(idx) = it.next() else { continue };
        let Some(rtr) = it.next() else { continue };
        let Some(mtu) = it.next() else { continue };
        let Some(state) = it.next() else { continue };
        let name_rest: Vec<&str> = it.collect();
        if name_rest.is_empty() {
            continue;
        }
        if !idx.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if !rtr.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if !mtu.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if state.to_lowercase() != "connected" {
            continue;
        }
        let name = name_rest.join(" ");
        if name.to_lowercase().contains("loopback") {
            continue;
        }
        out.push(name);
    }
    out
}

/// 私网 IPv4（10/8、172.16/12、192.168/16）—— LAN 解析器候选过滤用。
/// 上游 `isPrivateIpv4`。
pub fn is_private_ipv4(ip: &str) -> bool {
    let parts: Vec<&str> = ip.trim().split('.').collect();
    if parts.len() != 4
        || !parts
            .iter()
            .all(|p| p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()))
    {
        return false;
    }
    let o: Vec<u32> = parts
        .iter()
        .map(|p| p.parse::<u32>().unwrap_or(999))
        .collect();
    if o.iter().any(|&x| x > 255) {
        return false;
    }
    let (a, b) = (o[0], o[1]);
    if a == 10 {
        return true;
    }
    if a == 172 && (16..=31).contains(&b) {
        return true;
    }
    if a == 192 && b == 168 {
        return true;
    }
    false
}

/// 解析 macOS `scutil --dns` 输出里的全部 `nameserver[N] : <ip>`，按出现顺序去重。
/// 上游 `parseScutilNameservers`。
pub fn parse_scutil_nameservers(stdout: &str) -> Vec<String> {
    let mut out = Vec::new();
    for cap in scutil_ns_iter(stdout) {
        let ip = cap.trim().to_string();
        if !ip.is_empty() && !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

/// 从文本里按出现顺序去重提取 IPv4 字面量（netsh show dnsservers 取生效 DNS 用）。
/// 上游 `extractIpv4s`。
pub fn extract_ipv4s(stdout: &str) -> Vec<String> {
    let mut out = Vec::new();
    for m in ipv4_find_iter(stdout) {
        if !out.contains(&m) {
            out.push(m);
        }
    }
    out
}

/// 挑「可用于内网域名解析的 LAN 解析器」：私网 IPv4 + 排除受控 IP。
/// 公网/ISP/IPv6/link-local 不取 → 返回 None。上游 `pickLanResolverIp`。
pub fn pick_lan_resolver_ip(candidates: &[String], controlled_ip: &str) -> Option<String> {
    for raw in candidates {
        let ip = raw.trim();
        if ip == controlled_ip {
            continue;
        }
        if is_private_ipv4(ip) {
            return Some(ip.to_string());
        }
    }
    None
}

/// 防自指：计算「接管前应保存的原始 DNS」。
///
/// - 首次接管（无既有 marker）：当前值即原始。
/// - 再次接管（有既有 marker）：若某服务当前 DNS 恰为「仅受控 IP」=我们设的，
///   回退到既有 marker 里捕获的真实原始值（或 `[]`），杜绝把受控 IP 误存成原始。
///
/// 上游 `computeOriginalToSave`。
pub fn compute_original_to_save(
    current: &BTreeMap<String, Vec<String>>,
    controlled_ip: &str,
    existing_marker_original: Option<&BTreeMap<String, Vec<String>>>,
) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    for (svc, ips) in current {
        let is_ours = match existing_marker_original {
            Some(existing) => {
                !ips.is_empty()
                    && ips.iter().all(|ip| ip == controlled_ip)
                    && existing.contains_key(svc)
            }
            None => false,
        };
        if is_ours {
            out.insert(
                svc.clone(),
                existing_marker_original
                    .unwrap()
                    .get(svc)
                    .cloned()
                    .unwrap_or_default(),
            );
        } else {
            out.insert(svc.clone(), ips.clone());
        }
    }
    out
}

/// 判断某服务的 DNS 是否已是「仅受控 IP」（reconcile 幂等跳过用）。
pub fn is_controlled(ips: &[String], controlled_ip: &str) -> bool {
    ips.len() == 1 && ips[0] == controlled_ip
}

// ── 内部正则替代：手写 IPv4 字面量 / scutil nameserver 提取（避免 regex 依赖）──

fn ipv4_find_iter(s: &str) -> Vec<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        // 找一个数字起头。
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        // 尝试匹配 a.b.c.d。
        if let Some((ip, end)) = try_parse_ipv4_at(bytes, i) {
            out.push(ip);
            i = end;
        } else {
            i += 1;
        }
    }
    out
}

fn try_parse_ipv4_at(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    let mut pos = start;
    let mut octets: Vec<String> = Vec::new();
    for part in 0..4 {
        let num_start = pos;
        while pos < bytes.len() && bytes[pos].is_ascii_digit() {
            pos += 1;
        }
        if pos == num_start {
            return None;
        }
        octets.push(String::from_utf8(bytes[num_start..pos].to_vec()).unwrap());
        if part < 3 {
            if pos >= bytes.len() || bytes[pos] != b'.' {
                return None;
            }
            pos += 1;
        }
    }
    // 边界：后面不能再紧跟数字/点（避免误吃更长串里的子段）。
    if pos < bytes.len() && (bytes[pos].is_ascii_digit() || bytes[pos] == b'.') {
        return None;
    }
    // 八位段范围校验（粗：≤3 位数字即取，与 Polaris \d{1,3} 口径一致）。
    if octets
        .iter()
        .any(|o| o.parse::<u32>().map(|v| v > 255).unwrap_or(true))
    {
        return None;
    }
    Some((octets.join("."), pos))
}

fn scutil_ns_iter(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in s.lines() {
        // 形如 "  nameserver[0] : 192.168.1.1"
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("nameserver") else {
            continue;
        };
        // 跳过 [N]
        let after_bracket = match rest.find(']') {
            Some(idx) => &rest[idx + 1..],
            None => continue,
        };
        let after_colon = after_bracket.trim_start();
        let after_colon = after_colon.strip_prefix(':').unwrap_or(after_colon).trim();
        if !after_colon.is_empty() {
            out.push(after_colon.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests;
