//! DNS server spec 解析（上游 `shared/dns.ts parseDnsServerSpec` 1:1 移植）。
//!
//! 解析用户 DNS 地址（`https://host[:port]/path`、`tls://host`、`udp://host`、裸 IP）→ ParsedDnsServer。
//! 手写解析（避免 url crate 依赖），覆盖受限 spec 格式。

#![forbid(unsafe_code)]

use crate::user_config::ip::{is_ipv4, is_ipv6_literal, strip_brackets};

/// 解析结果。上游 `ParsedDnsServer`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDnsServer {
    pub server_type: DnsServerType,
    /// 主机名或 IP（IPv6 去方括号）。
    pub server: String,
    pub port: u16,
    /// 仅 https，默认 /dns-query。
    pub path: Option<String>,
    /// server 是否域名（决定是否需 domain_resolver 引导）。
    pub is_domain: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsServerType {
    Https,
    Tls,
    Udp,
}

fn is_ip_literal(host: &str) -> bool {
    is_ipv4(host) || is_ipv6_literal(host)
}

/// 解析 URL 形态（`scheme://host[:port][/path]`）。手写，覆盖 DoH/DoT/UDP 三种。
fn parse_url(s: &str, scheme: &str, default_port: u16, with_path: bool) -> Option<ParsedDnsServer> {
    let rest = s.strip_prefix(scheme)?; // 去掉 scheme://
    let rest = rest.strip_prefix("//")?;

    // 分离 path（首个 /）。
    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], Some(&rest[idx..])),
        None => (rest, None),
    };

    // 分离 host:port（IPv6 带 [] 须按 ] 定位）。
    let (host_raw, port) = if let Some(end) = authority.find(']') {
        // [v6addr]:port 或 [v6addr]
        let host_part = &authority[..=end];
        let after = &authority[end + 1..];
        let port = if let Some(p) = after.strip_prefix(':') {
            parse_port(p)?
        } else {
            default_port
        };
        (host_part, port)
    } else if let Some(colon) = authority.rfind(':') {
        // host:port
        let host = &authority[..colon];
        let port = parse_port(&authority[colon + 1..])?;
        (host, port)
    } else {
        (authority, default_port)
    };

    let host = strip_brackets(host_raw);
    if host.is_empty() {
        return None;
    }

    let server_type = match scheme {
        "https:" => DnsServerType::Https,
        "tls:" => DnsServerType::Tls,
        "udp:" => DnsServerType::Udp,
        _ => return None,
    };

    let path = if with_path {
        Some(match path {
            Some(p) if p != "/" => p.to_string(),
            _ => "/dns-query".to_string(),
        })
    } else {
        None
    };

    Some(ParsedDnsServer {
        server_type,
        server: host.to_string(),
        port,
        path,
        is_domain: !is_ip_literal(host),
    })
}

fn parse_port(s: &str) -> Option<u16> {
    let n: u32 = s.parse().ok()?;
    (1..=65535).contains(&n).then_some(n as u16)
}

/// 解析 DNS 地址字符串。上游 `parseDnsServerSpec`。无法识别 → None。
pub fn parse_dns_server_spec(spec: Option<&str>) -> Option<ParsedDnsServer> {
    let s = spec?.trim();
    if s.is_empty() {
        return None;
    }

    if let Some(r) = parse_url(s, "https:", 443, true) {
        return Some(r);
    }
    if let Some(r) = parse_url(s, "tls:", 853, false) {
        return Some(r);
    }
    if let Some(r) = parse_url(s, "udp:", 53, false) {
        return Some(r);
    }

    // 裸 IP 字面量 → UDP:53。
    let bare = strip_brackets(s);
    if is_ipv4(bare) || is_ipv6_literal(bare) {
        return Some(ParsedDnsServer {
            server_type: DnsServerType::Udp,
            server: bare.to_string(),
            port: 53,
            path: None,
            is_domain: false,
        });
    }

    None
}

#[cfg(test)]
mod tests;
