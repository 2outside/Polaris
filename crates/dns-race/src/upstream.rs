//! 节点域名解析上游模型 —— 上游 `shared/node-resolver-upstreams.ts` 1:1 移植。
//!
//! 纯逻辑、无 I/O、可逐项单测：
//! - 内置上游单一真值（`ali` / `dnspod` / `system`），IP 取自 [`DOH_ALIDNS_IP`] / [`DOH_DNSPOD_IP`]，
//!   并由单测护栏钉死二者 ∈ `BOOTSTRAP_DIRECT_DNS_IPS`（否则其 :443 DoH 不被 route 直连放行 → TUN 下回环）。
//! - 自定义上游**强制纯 IP**（`parse_dns_server_spec().is_domain` 拒绝）：零 bootstrap + 直连放行确定。
//! - Tier1（加密 DoH）抢跑、上限 3；Tier2（明文 UDP / system）兜底，不占额度、不与 Tier1 抢跑。
//! - canonical 去重：内置与等价自定义合并（**先去重再数上限**，否则重复项会挤掉真上游）。

#![forbid(unsafe_code)]

use polaris_config_engine::user_config::dns_config::{CustomDnsUpstream, DnsConfig};
use polaris_config_engine::user_config::dns_spec::{parse_dns_server_spec, DnsServerType};
use polaris_config_engine::user_config::proxy_mode::ProxyModeType;

/// AliDNS IP-DoH 上游地址。**不变量**：∈ `BOOTSTRAP_DIRECT_DNS_IPS`（单测护栏）。上游 `DOH_ALIDNS_IP`。
pub const DOH_ALIDNS_IP: &str = "223.5.5.5";
/// DNSPod IP-DoH 上游地址。**不变量**：同上。上游 `DOH_DNSPOD_IP`。
pub const DOH_DNSPOD_IP: &str = "1.12.12.12";

/// Tier1 抢跑上游上限（设计 §9.1：2 见顶、第 3 冗余；只数 Tier1，Tier2 不占额度）。
pub const MAX_TIER1_UPSTREAMS: usize = 3;

/// 竞速 on 的默认上游池。上游 `DEFAULT_POOL_IDS`。
pub const DEFAULT_POOL_IDS: &[&str] = &["ali", "dnspod"];
/// 竞速 off 的默认单上游 id。上游 `DEFAULT_SINGLE_ID`。
pub const DEFAULT_SINGLE_ID: &str = "ali";

/// 上游解析方式。上游 `ResolveUpstream.kind`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamKind {
    /// DoH（https，POST application/dns-message）/ DoT（tls，见 [`ResolveUpstream::dot`]）。
    Doh,
    /// 明文 UDP:53。
    Udp,
    /// 系统解析器（无 IP，走 OS resolver）。
    System,
}

/// 一个解析上游 = 一种解析方式 + 其 Tier。上游 `ResolveUpstream`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveUpstream {
    /// `ali` / `dnspod` / `system` 或自定义 id。
    pub id: String,
    pub kind: UpstreamKind,
    /// 纯 IP（doh/udp 有；system 无）。
    pub ip: Option<String>,
    pub port: Option<u16>,
    /// 仅 DoH(https) 有。
    pub path: Option<String>,
    /// `kind == Doh` 下是否为 DoT(tls)。**当前恒 false**：DoT 二期，[`parse_custom_upstream`] 直接拒
    /// `tls://`（见该函数注释：接受但永远 FAIL 比拒绝更糟）。
    pub dot: bool,
    /// 1 = 抢跑（加密）；2 = 兜底（明文 UDP / system）。
    pub tier: u8,
}

/// 内置上游单一真值（id → 上游）。上游 `BUILTIN_UPSTREAMS`。
#[must_use]
pub fn builtin_upstream(id: &str) -> Option<ResolveUpstream> {
    match id {
        "ali" => Some(ResolveUpstream {
            id: "ali".into(),
            kind: UpstreamKind::Doh,
            ip: Some(DOH_ALIDNS_IP.into()),
            port: Some(443),
            path: Some("/dns-query".into()),
            dot: false,
            tier: 1,
        }),
        "dnspod" => Some(ResolveUpstream {
            id: "dnspod".into(),
            kind: UpstreamKind::Doh,
            ip: Some(DOH_DNSPOD_IP.into()),
            port: Some(443),
            path: Some("/dns-query".into()),
            dot: false,
            tier: 1,
        }),
        "system" => Some(ResolveUpstream {
            id: "system".into(),
            kind: UpstreamKind::System,
            ip: None,
            port: None,
            path: None,
            dot: false,
            tier: 2,
        }),
        _ => None,
    }
}

/// 自定义上游 spec → [`ResolveUpstream`]；**强制纯 IP**，非法 / 域名 / `tls://` → `None`。
/// 上游 `parseCustomUpstream`。
///
/// - `https://` → Tier1 加密抢跑；`udp://` / 裸 IP → Tier2 明文兜底。
/// - `tls://`（DoT）二期未实现：查询侧对 `dot` 直接 Err（永远 FAIL）。**此处拒绝**，避免 UI 接受
///   `tls://` 上游、用户以为生效却静默全 FAIL。待 DoT 落地后改回 `dot: type == Tls`。
#[must_use]
pub fn parse_custom_upstream(c: &CustomDnsUpstream) -> Option<ResolveUpstream> {
    if c.id.is_empty() || c.spec.is_empty() {
        return None;
    }
    let p = parse_dns_server_spec(Some(&c.spec))?;
    if p.is_domain {
        return None; // 纯 IP 强制
    }
    match p.server_type {
        DnsServerType::Udp => Some(ResolveUpstream {
            id: c.id.clone(),
            kind: UpstreamKind::Udp,
            ip: Some(p.server),
            port: Some(p.port),
            path: None,
            dot: false,
            tier: 2,
        }),
        DnsServerType::Tls => None, // DoT 二期，见函数文档
        DnsServerType::Https => Some(ResolveUpstream {
            id: c.id.clone(),
            kind: UpstreamKind::Doh,
            ip: Some(p.server),
            port: Some(p.port),
            path: Some(p.path.unwrap_or_else(|| "/dns-query".into())),
            dot: false,
            tier: 1,
        }),
    }
}

/// UI 校验：自定义 spec 是否合法（纯 IP DoH / UDP）。上游 `isValidCustomUpstreamSpec`。
#[must_use]
pub fn is_valid_custom_upstream_spec(spec: &str) -> bool {
    parse_custom_upstream(&CustomDnsUpstream {
        id: "_probe".into(),
        spec: spec.to_string(),
    })
    .is_some()
}

/// canonical 去重 key：`system` 唯一；其余按 `(kind, IP, port, path)`。
/// udp 与 doh 即便同 IP 也不同（协议/端口不同）。上游 `upstreamCanonicalKey`。
#[must_use]
pub fn upstream_canonical_key(u: &ResolveUpstream) -> String {
    if u.kind == UpstreamKind::System {
        return "system".into();
    }
    let kind = match u.kind {
        UpstreamKind::Doh => "doh",
        UpstreamKind::Udp => "udp",
        UpstreamKind::System => "system",
    };
    format!(
        "{kind}:{}:{}:{}",
        u.ip.as_deref().unwrap_or(""),
        u.port.map(|p| p.to_string()).unwrap_or_default(),
        u.path.as_deref().unwrap_or("")
    )
}

/// 分桶后的上游集。上游 `ResolvedUpstreams`。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedUpstreams {
    /// 抢跑层（去重 + 上限 [`MAX_TIER1_UPSTREAMS`]）。
    pub tier1: Vec<ResolveUpstream>,
    /// 兜底层（不抢跑、不占额度）。
    pub tier2: Vec<ResolveUpstream>,
    /// 全部纯 IP —— 喂 `GenerateConfigDeps::race_upstream_ips`，供 route 直连放行防 TUN 回环。
    pub direct_ips: Vec<String>,
    /// 上面这些上游**实际在用的端口**（去重）—— 喂 `GenerateConfigDeps::race_upstream_ports`。
    ///
    /// issue #147：直连放行规则的端口集若只有恒定的 `[53, 443]`，自定义 DoH 的非标端口
    /// （`https://9.9.9.9:8443/q`）与自定义 UDP 的非 53 口就**只放行了 IP、没放行端口** ⇒ 规则匹配不上
    /// ⇒ TUN 下该上游的流量落到通用路由经代理出站 ⇒ 起核自举窗内恒 FAIL 或回环（sidecar 本就是要给
    /// 内核解析节点域名的，却得先经内核出网）。上游 同缺口，属上游继承 bug。
    ///
    /// **与 [`direct_ips`](Self::direct_ips) 是同一次遍历的两路投影，各自去重**：route 的直连放行是
    /// 一条 `ip_cidr × port` 的叉乘规则，本就不成对匹配，故两个**集合**才是它要的形态。
    ///
    /// **必须从这里下发、不许在 route 侧照着配置复算**：真实上游集是 Tier 分桶 + canonical 去重 +
    /// Tier1 上限 + INV-1 过滤（外加「Tier1 空则回退默认池」）之后的结果 —— 那是一条只在本 crate 里
    /// 完整存在的选择链，复算必然是它的近似（当时的实现取的是超集）。两份真值源迟早会分叉，而分叉的
    /// 代价不对称：多放行一个端口只是无害的宽松，少放行一个正在用的端口 = 该上游恒死。
    pub direct_ports: Vec<u16>,
}

/// 池里一个 id → 上游（内置优先，回退同 id 的自定义项）。`None` = 无效 id / 自定义 spec 非纯 IP。
///
/// 抽成具名函数是为了让 [`plan_upstreams`] 的 INV-1 过滤与 [`resolve_upstreams`] 的分桶**用同一套
/// 解析口径**：过滤若自己按 id 字符串猜 kind（如 `id == "system"`），将来多一个产 `System` 的来源
/// 就会漏筛 —— 而漏筛的后果是 TUN 下的递归放大，不是少一个上游。
fn lookup_upstream(id: &str, custom: &[CustomDnsUpstream]) -> Option<ResolveUpstream> {
    builtin_upstream(id).or_else(|| {
        custom
            .iter()
            .find(|c| c.id == id)
            .and_then(parse_custom_upstream)
    })
}

/// 上游 id 列表 → Tier1/Tier2 分桶 + canonical 去重 + Tier1 上限。上游 `resolveUpstreams`。
///
/// 无效 id / 自定义解析失败 / 重复 → 跳过。
/// **空 Tier1 → 回退默认 `[ali, dnspod]`**（全不勾 / 全无效 / 只勾了 Tier2 时防「无抢跑上游」全断，
/// 设计 §9.3 校验闸）。
#[must_use]
pub fn resolve_upstreams(ids: &[String], custom: &[CustomDnsUpstream]) -> ResolvedUpstreams {
    let mut seen: Vec<String> = Vec::new();
    let mut tier1: Vec<ResolveUpstream> = Vec::new();
    let mut tier2: Vec<ResolveUpstream> = Vec::new();
    for id in ids {
        let Some(up) = lookup_upstream(id, custom) else {
            continue; // 无效 id / 自定义非纯 IP → 跳过
        };
        let key = upstream_canonical_key(&up);
        if seen.contains(&key) {
            continue; // 去重（内置与等价自定义合并）
        }
        seen.push(key);
        if up.tier == 1 {
            if tier1.len() < MAX_TIER1_UPSTREAMS {
                tier1.push(up); // 上限（去重后才数）
            }
        } else {
            tier2.push(up);
        }
    }
    if tier1.is_empty() {
        // 竞速至少要有一个抢跑上游；去重防与已选 Tier2 重复（system 在 Tier2，不会撞）。
        for id in DEFAULT_POOL_IDS {
            if let Some(up) = builtin_upstream(id) {
                let key = upstream_canonical_key(&up);
                if !seen.contains(&key) {
                    seen.push(key);
                    tier1.push(up);
                }
            }
        }
    }
    // 直连放行的两路投影（同一次遍历、各自去重）：IP 进 `ip_cidr`、端口进 `port`。
    // `system` 两者皆 None ⇒ 一路都不进（它没有可放行的目的地，正是 INV-1 摘它的理由）。
    let mut direct_ips: Vec<String> = Vec::new();
    let mut direct_ports: Vec<u16> = Vec::new();
    for u in tier1.iter().chain(tier2.iter()) {
        if let Some(ip) = &u.ip {
            if !direct_ips.contains(ip) {
                direct_ips.push(ip.clone());
            }
        }
        if let Some(port) = u.port {
            if !direct_ports.contains(&port) {
                direct_ports.push(port);
            }
        }
    }
    ResolvedUpstreams {
        tier1,
        tier2,
        direct_ips,
        direct_ports,
    }
}

/// 起 sidecar 前的**唯一决策点**：读 `dnsConfig` → 该起哪些上游，还是根本不起。
///
/// `None` ⟺ 竞速关（`resolveNodeDomainsAhead === false`）⟹ 调用方不起 sidecar ⟹
/// `race_server_port` 恒 0 ⟹ config-engine `with_race_off` 强制单上游路径（`nodeResolverSingle`）。
/// 缺省 / `true` 均视为开（对齐 上游 `!== false` 语义：老配置无此字段 = 开）。
///
/// 抽成具名纯函数（而不是内联进起核流程）是为了让「竞速 off 不走池」这条不变式**本身可单测** ——
/// 内联进 `start_inner` 就只能靠真起核才测得到，而那是真机门。
///
/// # INV-1（TUN 接管期 `system` 不得入池）
///
/// 非竞速路径早就为这条链立了不变量：`config-engine` 的 `helpers.rs::get_node_resolver_tag` ——
/// **「TUN + rule ctx + single=system → 强制走 dns-node（IP-DoH）防递归」**。竞速路径把节点域名统一
/// 指向 `dns-node-race` 之后，这条不变量在**池里勾了 `system`** 时一度没有对应实现，放大链是：
///
/// ```text
/// 内核查节点域名 → dns-node-race → sidecar 的 system 腿 → OS resolver → 明文 :53 发往 LAN DNS
///   → route 的 `hijack-dns`（先于 LAN bypass）抓走 → 内核按域名规则又指回 dns-node-race → …
/// ```
/// Tier1 全 FAIL（离线 / DoH 被封）时每一层都再放一轮齐射，逐级放大。
///
/// **为什么摘 `system` 就够**：TUN 下所有上游的**出网** IP 都由 `direct_ips` →
/// `GenerateConfigDeps::race_upstream_ips` → route 的「DNS 直连放行」规则放行（`:53`/`:443` 及自定义
/// 端口），故 DoH / 自定义 UDP 上游的查询根本走不到 `hijack-dns`。唯独 `system` **没有 IP**
/// （`kind == System ⇒ ip == None`）—— 它把目的地交给 OS resolver 决定，Polaris 无从放行，这才是
/// 唯一能掉进劫持链的上游形态。
///
/// **摘在 `resolve_upstreams` 之前**（对 id 列表过滤，而不是对结果切）：这样「摘完 Tier1 空」会自动
/// 落进既有的默认池回退闸（`[ali, dnspod]`），不会产出「无抢跑上游」的死配置。
#[must_use]
pub fn plan_upstreams(
    dns: Option<&DnsConfig>,
    proxy_mode_type: ProxyModeType,
) -> Option<ResolvedUpstreams> {
    if dns.and_then(|d| d.resolve_node_domains_ahead) == Some(false) {
        return None;
    }
    let owned_default: Vec<String>;
    let mut ids: &[String] = match dns.and_then(|d| d.node_resolver_pool.as_deref()) {
        Some(p) => p,
        None => {
            owned_default = DEFAULT_POOL_IDS.iter().map(|s| (*s).to_string()).collect();
            &owned_default
        }
    };
    let custom: &[CustomDnsUpstream] = dns
        .and_then(|d| d.node_resolver_custom.as_deref())
        .unwrap_or(&[]);
    let tun_filtered: Vec<String>;
    if proxy_mode_type.is_tun() {
        // INV-1：TUN 接管期把 `system` 从池里摘除（见本函数文档）。
        tun_filtered = ids
            .iter()
            .filter(|id| {
                !matches!(
                    lookup_upstream(id, custom).map(|u| u.kind),
                    Some(UpstreamKind::System)
                )
            })
            .cloned()
            .collect();
        ids = &tun_filtered;
    }
    Some(resolve_upstreams(ids, custom))
}

#[cfg(test)]
mod tests;
