//! DnsConfig 投影（上游 `shared/types.ts DnsConfig` 子集）。
//!
//! 仅 builder 当前所需字段。随 buildDnsConfig 移植扩展。

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// DNS 配置（增量子集）。上游 `DnsConfig`。
/// 含 f64（dnsTimeoutMs）→ 不 derive Eq（f64 非 Eq）。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DnsConfig {
    #[serde(rename = "domesticDns")]
    pub domestic_dns: Option<String>,
    #[serde(rename = "foreignDns")]
    pub foreign_dns: Option<String>,
    #[serde(rename = "enableFakeIp")]
    pub enable_fake_ip: Option<bool>,
    /// issue #147 race 总开关（!==false 即 on）。
    #[serde(rename = "resolveNodeDomainsAhead")]
    pub resolve_node_domains_ahead: Option<bool>,
    /// race off 单上游 id。缺省 'ali'。
    #[serde(rename = "nodeResolverSingle")]
    pub node_resolver_single: Option<String>,
    /// race on 的多选上游池 id 列表（内置 `ali`/`dnspod`/`system` + 自定义 id）。缺省 `["ali","dnspod"]`。
    ///
    /// **本字段不参与 sing-box config 生成**（生成侧只看 `race_server_port` 是否 >0），它由
    /// `polaris-dns-race` 的 `plan_upstreams` 消费来决定 sidecar 起哪些上游。放在这里而非另建投影，
    /// 是因为 UserConfig 是 Rust 侧读 `config.json` 的**唯一**投影：同一份 JSON 解两遍 = 双真值。
    #[serde(rename = "nodeResolverPool")]
    pub node_resolver_pool: Option<Vec<String>>,
    /// 自定义上游定义（强制纯 IP，见 [`CustomDnsUpstream`]）。同上，由 sidecar 消费、不进生成侧。
    #[serde(rename = "nodeResolverCustom")]
    pub node_resolver_custom: Option<Vec<CustomDnsUpstream>>,
    /// legacy 单选档位（迁移读取）。
    #[serde(rename = "nodeDomainResolver")]
    pub node_domain_resolver: Option<String>,
    /// sing-box 1.14 顶层 dns.optimistic（仅 true 时下发）。上游 `optimisticCache`。
    #[serde(rename = "optimisticCache")]
    pub optimistic_cache: Option<bool>,
    /// sing-box 1.14 dns.timeout（Go duration 字符串；仅 >0 有限正整数时下发 "`<n>`ms"）。上游 `dnsTimeoutMs`。
    #[serde(rename = "dnsTimeoutMs")]
    pub dns_timeout_ms: Option<f64>,
}

/// 用户自定义节点解析上游。上游 `shared/types.ts CustomDnsUpstream`。
///
/// `spec` 形态 = DoH URL / `tls://ip:853` / 裸 IP，且**强制纯 IP**（域名会被
/// [`parse_dns_server_spec`](crate::user_config::dns_spec::parse_dns_server_spec) 的 `is_domain`
/// 判出并拒绝）—— 纯 IP 上游零 bootstrap 依赖，且 route 侧「直连放行」的目标地址是确定的。
/// `id` 是稳定引用键，被 [`DnsConfig::node_resolver_pool`] / [`DnsConfig::node_resolver_single`] 指向。
///
/// # 两个字段都 `#[serde(default)]`：缺键不得炸掉整份配置
///
/// 没有 default 时，手编 / 半写坏的 `config.json` 里只要有一条 `nodeResolverCustom` 少了 `id` 或
/// `spec`，**整个 `UserConfig` 反序列化就失败**。而 Rust 侧消费 `UserConfig` 的各腿并不都会把错误往上
/// 报：起核腿会报错，但 `unlock.rs` / `speedtest.rs` 等腿走的是 `unwrap_or_default()` —— 那会把
/// **整份用户配置静默替换成默认值**（节点全没了、规则全没了），而用户只在一个 DNS 上游条目里少写了
/// 一个键。store 侧的 sanitize 也没覆盖 `nodeResolver*` 字段，兜不住这一形态。
///
/// 加了 default，缺键退化为空串，由 [`parse_custom_upstream`](
/// crate::user_config::dns_config::CustomDnsUpstream) 的既有消费方拒绝腿兜住
/// （`polaris-dns-race` 的 `parse_custom_upstream` 首行就是 `id.is_empty() || spec.is_empty() → None`）：
/// **坏条目被跳过，其余配置照常生效** —— 失效范围与用户的错误范围一致。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomDnsUpstream {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub spec: String,
}

#[cfg(test)]
mod tests;
