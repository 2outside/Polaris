//! IP 字面量判定（上游 `shared/ip.ts isIpv4` + `shared/dns.ts isIpv6Literal/isIpLiteral` 1:1 移植）。
//!
//! 刻意手写而非 std::net::IpAddr::parse：对拍需与 TS 正则语义逐字节一致（std 解析更严，
//! 边界超严 case 会致 diff≠0）。Polaris isIpv4 正则严格（每段 0-255），此处等价手写。

#![forbid(unsafe_code)]

/// 去除 IPv6 字面量的方括号（`[::1]` → `::1`）。上游 `dns.ts stripBrackets`。
pub fn strip_brackets(host: &str) -> &str {
    let bytes = host.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'[' && bytes[bytes.len() - 1] == b']' {
        &host[1..host.len() - 1]
    } else {
        host
    }
}

/// 严格 IPv4 字面量（每段 0-255，无前导零限制——对齐 Polaris IPV4_RE `1?\d?\d` 允许 01/001）。
/// 上游 `ip.ts isIpv4`（IPV4_RE = `/^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/`）。
pub fn is_ipv4(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| is_ipv4_segment(p))
}

/// 单段：空→false；纯数字且 ≤255→true（对齐 `1?\d?\d`：允许 "0"/"00"/"01" 等前导零）。
/// `25[0-5]` | `2[0-4]\d` | `1?\d?\d` 三选一。
fn is_ipv4_segment(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    // 非数字字符 → false（正则 \d 仅 ASCII 数字）。
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    // 去前导零后的数值 ≤255。正则 `1?\d?\d` 允许 0-3 位（含前导零），数值上 0..=255。
    // 注意：正则不限制总位数到 3，但 `1?\d?\d` 最多匹配 3 字符 → 实际 1-3 位。
    if s.len() > 3 {
        return false;
    }
    s.parse::<u32>().map(|n| n <= 255).unwrap_or(false)
}

/// IPv4 字面量判定（上游 `dns.ts isIpv4Literal` = isIpv4）。
pub fn is_ipv4_literal(host: &str) -> bool {
    is_ipv4(host)
}

/// IPv6 字面量判定（上游 `dns.ts isIpv6Literal`）。
/// (1) canonical 纯 hex+冒号（至少 2 个冒号）；(2) IPv4-mapped：`<hex+冒号前缀>:<点分 IPv4>`。
pub fn is_ipv6_literal(host: &str) -> bool {
    let h = strip_brackets(host);
    let colon_count = h.bytes().filter(|&b| b == b':').count();
    if colon_count < 2 {
        return false;
    }
    // (1) canonical 纯 hex+冒号。
    if h.bytes().all(|b| b.is_ascii_hexdigit() || b == b':') {
        return true;
    }
    // (2) IPv4-mapped/embedded：前缀纯 hex+冒号，末段严格 IPv4。
    let last_colon = h.rfind(':');
    match last_colon {
        Some(idx) => {
            let prefix = &h[..=idx]; // 含末尾冒号
            let last_seg = &h[idx + 1..];
            prefix.bytes().all(|b| b.is_ascii_hexdigit() || b == b':') && is_ipv4(last_seg)
        }
        None => false,
    }
}

/// IP 字面量（v4 或 v6）。上游 `dns.ts isIpLiteral`。
pub fn is_ip_literal(host: &str) -> bool {
    is_ipv4_literal(host) || is_ipv6_literal(host)
}

#[cfg(test)]
mod tests;
