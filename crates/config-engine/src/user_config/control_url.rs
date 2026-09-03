//! Tailscale `control_url` 前置校验 —— 内核 panic 的**唯一判据源**。
//!
//! # 为什么需要这道校验（上游机制，2026-07-31 实测 + 读源码确认）
//!
//! sing-box `protocol/tailscale/endpoint.go::NewEndpoint` 里有一处**无条件类型断言**：
//!
//! ```text
//! // v1.14.0-beta.3 endpoint.go:174-195
//! var remoteIsDomain bool
//! if options.ControlURL != "" {
//!     controlURL, err := url.Parse(options.ControlURL)
//!     if err != nil { return nil, E.Cause(err, "parse control URL") }
//!     remoteIsDomain = M.ParseSocksaddr(controlURL.Hostname()).IsDomain()
//! } else {
//!     remoteIsDomain = true
//! }
//! outboundDialer, err := dialer.NewWithOptions(dialer.Options{
//!     ..., RemoteIsDomain: remoteIsDomain, ResolverOnDetour: true, NewDialer: true,
//! })
//! dialerQueryOptions := outboundDialer.(dialer.ResolveDialer).QueryOptions()   // ← :195 断言
//! ```
//!
//! 而 `common/dialer/dialer.go:65` 决定「拨号器要不要被包成 `ResolveDialer`」的那道门是：
//!
//! ```text
//! if options.RemoteIsDomain && ( !hasDetour || options.ResolverOnDetour || <domain_resolver 非空> ) {
//!     ... dialer = NewResolveDialer(...)   // 只有进了这里，断言才成立
//! }
//! ```
//!
//! `RemoteIsDomain` 是**合取式的第一项**：它为 false 时整个条件短路，右边三项（含
//! `domain_resolver` 是否配了）一个都不会被求值。于是：
//!
//! - `control_url` 的 host 是**域名** → `remoteIsDomain = true` → 包成 `resolveDialer` → 断言成立；
//! - `control_url` 的 host 是 **IP 字面量或为空** → `remoteIsDomain = false` → 拨号器停在
//!   `*dialer.DefaultDialer`（有 detour 时是 `*dialer.DetourDialer`）→ **:195 断言直接 panic**：
//!   `interface conversion: *dialer.DefaultDialer is not dialer.ResolveDialer: missing method QueryOptions`
//!
//! 这条合取顺序也解释了为什么**补 `domain_resolver` 治不好**（已实测证否）：它是被短路掉的那一项。
//!
//! # 判据 = 「host 不是域名」，比「host 是 IP」更宽
//!
//! `M.Socksaddr::IsDomain()` 在 host 为**空串**时同样返回 false。而 Go 的 `url.Parse` 对
//! **不带 scheme** 的输入（`hs.example.com`、`not-a-url`）解析成功但 `Host` 为空 ⇒ 同样 panic。
//! 也就是说少打一个 `https://` 与填 IP 是**同一个 panic**，且前者是远更常见的手滑。
//!
//! 本模块因此把三类都拦下：IP 字面量 / 缺 scheme / host 缺失或畸形。
//!
//! # 与上游判据的两处**刻意**偏严（下面的单测逐条钉住）
//!
//! 1. **前导零点分四段**（`192.168.001.010`）：Go `netip.ParseAddr` 拒前导零 ⇒ 上游当域名、不 panic。
//!    但它也绝不可能解析成功（DNS 查 "192.168.001.010" 必 NXDOMAIN）——用户意图显然是 IP。
//!    判成 [`ControlUrlReject::IpLiteral`] 让他拿到「要填域名」这句可行动的话，好过让核悄悄连不上。
//! 2. **裸 IPv6 / 方括号里塞 IPv4**（`http://fd7a::1`、`http://[192.168.1.10]:8080`）：上游一个当域名放行、
//!    一个 `parse control URL` 报错（FATAL 而非 panic）。两者都不是能用的地址，本模块一律拒。
//!
//! 偏严只会多拦「本来也不工作」的写法，不会拦住任何**能工作**的域名写法（阴性对照见单测
//! `domain_forms_never_rejected`：`localhost` 明确归**合法**侧——上游 `IsDomain()` 判它是域名，
//! 实测 `sing-box check` 通过）。
//!
//! # 射程自曝
//!
//! 判据来自 `sing-box check`（构造期）——`NewEndpoint` 在 check 与 run 里是同一条代码路径，故 panic 与否
//! 两边一致；但**「不 panic」不等于「连得上」**：控制面可达性、证书、headscale 版本兼容一概不在本模块射程内。

#![forbid(unsafe_code)]

use crate::user_config::ip::{is_ip_literal, strip_brackets};

/// `control_url` 被拒的成因。取值经 [`reject_token`] 转成**稳定机器 token** 下发前端换 i18n 文案，
/// 故枚举项的语义不得复用（要新增成因就加新项，别把旧项的含义改掉）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlUrlReject {
    /// host 是 IP 字面量（v4 / v6 / 带 zone / 方括号形式）→ 内核 `endpoint.go:195` panic。
    IpLiteral,
    /// 缺 `scheme://` → Go `url.Parse` 得到空 Host → 同一处 panic。
    MissingScheme,
    /// 有 scheme 但 host 为空（`http://`、`http://:8080`）→ 同一处 panic。
    NoHost,
    /// host 畸形（裸 IPv6、方括号不配平、内嵌空白等）→ 内核 `parse control URL` FATAL 或 panic。
    Malformed,
}

/// [`ControlUrlReject`] → 稳定机器 token。
///
/// 前端按 token 查 i18n 文案（`ui/src/domain/invalid-node-reason.ts`），**不渲染 token 本身**；
/// `ui/src/contracts/invalid-node-reason-coverage.test.ts` 双向对账本函数与前端映射表。
pub fn reject_token(reject: ControlUrlReject) -> &'static str {
    match reject {
        ControlUrlReject::IpLiteral => "control-url-ip",
        ControlUrlReject::MissingScheme => "control-url-scheme",
        ControlUrlReject::NoHost | ControlUrlReject::Malformed => "control-url-invalid",
    }
}

/// host 是否 IP 字面量（内核 `M.ParseSocksaddr(...).IsDomain() == false` 的 IP 那一半）。
///
/// 取**并集**而非只用一种解析：
/// - `is_ip_literal` 是 上游 正则语义（容前导零），比 Go 宽 → 覆盖上面「偏严 #1」；
/// - `IpAddr::from_str` 是严格语义，与 Go `netip.ParseAddr` 同口径 → 兜住正则写不下的 v6 边角。
///
/// **zone id 必须先截断**：`fe80::1%eth0` 在 Go 那边 `netip` 认 zone、判为 IP（实测 panic），
/// Rust `IpAddr` 不认 zone 会解析失败 —— 不截断就会把它漏判成域名，那正是 fail-open。
fn is_ip_host(host: &str) -> bool {
    let h = strip_brackets(host);
    let h = h.split('%').next().unwrap_or(h);
    is_ip_literal(h) || h.parse::<std::net::IpAddr>().is_ok()
}

/// 端口后缀（`:8080`）判定。空端口（`host:`）不算合法后缀。
fn is_port_suffix(s: &str) -> bool {
    match s.strip_prefix(':') {
        Some(p) => !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()),
        None => false,
    }
}

/// host 是否**可能**是域名。
///
/// 刻意只列**否定**字符（`: / ? # @ [ ] \` 与控制字符），不做 LDH 白名单：headscale 用 IDN 域名
/// 完全合法，白名单会把它误伤成非法。走到本函数时 `/ ? # @` 已在上游切走，剩下的主要是裸 IPv6 的冒号
/// 与不配平的方括号。
fn is_hostname_like(host: &str) -> bool {
    !host.is_empty()
        && !host
            .chars()
            .any(|c| matches!(c, ':' | '/' | '?' | '#' | '@' | '[' | ']' | '\\') || c.is_control())
}

/// Tailscale `control_url` 的前置校验：`None` = 可下发，`Some(_)` = **必须拦在下发之前**。
///
/// 空串 / 全空白 → `None`（用户没填 → 内核走 `remoteIsDomain = true` 的 else 分支，安全）。
pub fn tailscale_control_url_reject(raw: &str) -> Option<ControlUrlReject> {
    let s = raw.trim();
    if s.is_empty() {
        // 未填 = 用官方 controlplane，内核 else 分支恒 remoteIsDomain=true → 不可能 panic。
        return None;
    }
    // 内嵌空白 → Go `url.Parse` 直接报错（实测 `parse control URL`），FATAL 掉整个核。
    if s.chars().any(char::is_whitespace) {
        return Some(ControlUrlReject::Malformed);
    }

    // scheme：必须有 `://`，且 scheme 本身合法（ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )）。
    // 不限定 http/https —— 那是额外的产品意见，本模块只复刻内核的 panic 判据。
    let Some(pos) = s.find("://") else {
        return Some(ControlUrlReject::MissingScheme);
    };
    let scheme = &s[..pos];
    if !scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        || !scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    {
        return Some(ControlUrlReject::MissingScheme);
    }

    // authority = scheme 之后、首个 `/ ? #` 之前；再剥 userinfo（内核 `url.Hostname()` 同样只取 host）。
    let rest = &s[pos + 3..];
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = match authority.rfind('@') {
        Some(i) => &authority[i + 1..],
        None => authority,
    };

    // 方括号形式：内核只接受 IPv6 —— 是 IP 就 panic，不是 IP（如 `[192.168.1.10]`，Go 认 v4 不该带括号）
    // 就 `parse control URL` FATAL。两条都得拦，前者给「别填 IP」的话更有用。
    if let Some(stripped) = hostport.strip_prefix('[') {
        let Some(end) = stripped.find(']') else {
            return Some(ControlUrlReject::Malformed);
        };
        let inner = &stripped[..end];
        let after = &stripped[end + 1..];
        if !after.is_empty() && !is_port_suffix(after) {
            return Some(ControlUrlReject::Malformed);
        }
        return Some(if is_ip_host(inner) {
            ControlUrlReject::IpLiteral
        } else {
            ControlUrlReject::Malformed
        });
    }

    // 非方括号：末段全数字才当端口剥掉；否则残留的冒号意味着裸 IPv6 之类的畸形。
    let host = match hostport.rfind(':') {
        Some(i) if is_port_suffix(&hostport[i..]) => &hostport[..i],
        Some(_) => return Some(ControlUrlReject::Malformed),
        None => hostport,
    };

    if host.is_empty() {
        return Some(ControlUrlReject::NoHost);
    }
    if is_ip_host(host) {
        return Some(ControlUrlReject::IpLiteral);
    }
    if !is_hostname_like(host) {
        return Some(ControlUrlReject::Malformed);
    }
    None
}

#[cfg(test)]
mod tests;
