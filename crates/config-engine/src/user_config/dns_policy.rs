//! 一等 DNS 资源与策略动作。
//!
//! `DnsServerResource` 回答“问谁、从哪个出口问”；`DnsPolicyAction` 回答“命中后怎么答”。
//! 节点拨号 resolver 不在本模块：#4444 解锁前仍由 `dns-race` sidecar 承担。

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const BUILTIN_DOMESTIC_DNS_ID: &str = "builtin-domestic";
pub const BUILTIN_REMOTE_DNS_ID: &str = "builtin-remote";
pub const BUILTIN_BOOTSTRAP_DNS_ID: &str = "builtin-bootstrap";
pub const DNS_BOOTSTRAP_TAG: &str = "dns-bootstrap";

fn default_true() -> bool {
    true
}

/// 稳定资源 id → sing-box tag。builtin 保留第一阶段 tag，控制迁移金样差异。
#[must_use]
pub fn dns_server_tag(id: &str) -> String {
    match id {
        BUILTIN_DOMESTIC_DNS_ID => "dns-domestic".to_string(),
        BUILTIN_REMOTE_DNS_ID => "dns-remote".to_string(),
        BUILTIN_BOOTSTRAP_DNS_ID => DNS_BOOTSTRAP_TAG.to_string(),
        _ => {
            let safe: String = id
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || matches!(c, '-' | '_') {
                        c
                    } else {
                        '-'
                    }
                })
                .collect();
            format!("dns-user-{safe}")
        }
    }
}

/// 用户可管理的 DNS Server 类型。只开放本版本已纳入真核门的集合。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DnsServerKind {
    #[default]
    Udp,
    Tcp,
    Tls,
    Https,
    Local,
    Hosts,
}

/// 网络型 DNS Server 端点。`local` / `hosts` 不使用本结构。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsServerEndpoint {
    #[serde(default)]
    pub host: String,
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// DNS 查询的出口。显式 tagged union 防止 nodeId 与 direct/currentExit 产生非法组合。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum DnsServerOutbound {
    #[default]
    Direct,
    CurrentExit,
    Node {
        #[serde(rename = "nodeId", default)]
        node_id: String,
    },
}

/// 一等 DNS Server 资源。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsServerResource {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(rename = "type", default)]
    pub kind: DnsServerKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<DnsServerEndpoint>,
    #[serde(rename = "bootstrapServerId", skip_serializing_if = "Option::is_none")]
    pub bootstrap_server_id: Option<String>,
    #[serde(default)]
    pub outbound: DnsServerOutbound,
    /// Hosts 文件路径；空 = sing-box 平台默认 hosts 文件。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    /// Hosts 内联记录。value 支持单/多地址，统一持久化为数组。
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub predefined: BTreeMap<String, Vec<String>>,
}

/// 新配置与旧直连 config-engine 调用的 Bootstrap 默认资源。生成器本身不再持有端点常量。
#[must_use]
pub fn builtin_bootstrap_dns_resource() -> DnsServerResource {
    DnsServerResource {
        id: BUILTIN_BOOTSTRAP_DNS_ID.into(),
        name: "Bootstrap DNS".into(),
        enabled: true,
        kind: DnsServerKind::Https,
        endpoint: Some(DnsServerEndpoint {
            host: "223.5.5.5".into(),
            port: Some(443),
            path: Some("/dns-query".into()),
        }),
        bootstrap_server_id: None,
        outbound: DnsServerOutbound::Direct,
        paths: Vec::new(),
        predefined: BTreeMap::new(),
    }
}

/// 三个受保护内置资源的结构化默认值。UI 可编辑字段，但删除由写入层禁止。
#[must_use]
pub fn builtin_dns_server_resources() -> Vec<DnsServerResource> {
    vec![
        DnsServerResource {
            id: BUILTIN_DOMESTIC_DNS_ID.into(),
            name: "Domestic DNS".into(),
            enabled: true,
            kind: DnsServerKind::Https,
            endpoint: Some(DnsServerEndpoint {
                host: "doh.pub".into(),
                port: Some(443),
                path: Some("/dns-query".into()),
            }),
            bootstrap_server_id: Some(BUILTIN_BOOTSTRAP_DNS_ID.into()),
            outbound: DnsServerOutbound::Direct,
            paths: Vec::new(),
            predefined: BTreeMap::new(),
        },
        DnsServerResource {
            id: BUILTIN_REMOTE_DNS_ID.into(),
            name: "Remote DNS".into(),
            enabled: true,
            kind: DnsServerKind::Https,
            endpoint: Some(DnsServerEndpoint {
                host: "dns.google".into(),
                port: Some(443),
                path: Some("/dns-query".into()),
            }),
            bootstrap_server_id: Some(BUILTIN_BOOTSTRAP_DNS_ID.into()),
            outbound: DnsServerOutbound::CurrentExit,
            paths: Vec::new(),
            predefined: BTreeMap::new(),
        },
        builtin_bootstrap_dns_resource(),
    ]
}

/// Bootstrap 是解析 DNS 端点域名的根依赖：只能使用系统解析，或经 direct 查询 IP 字面量。
#[must_use]
pub fn is_valid_bootstrap_dns_resource(resource: &DnsServerResource) -> bool {
    if resource.id != BUILTIN_BOOTSTRAP_DNS_ID || !resource.enabled {
        return false;
    }
    match resource.kind {
        DnsServerKind::Local => true,
        DnsServerKind::Hosts => false,
        DnsServerKind::Udp | DnsServerKind::Tcp | DnsServerKind::Tls | DnsServerKind::Https => {
            matches!(resource.outbound, DnsServerOutbound::Direct)
                && resource
                    .endpoint
                    .as_ref()
                    .map(|endpoint| endpoint.host.trim().trim_matches(['[', ']']))
                    .is_some_and(|host| host.parse::<std::net::IpAddr>().is_ok())
        }
    }
}

/// DNS Server Group 执行模式。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DnsServerGroupMode {
    #[default]
    Fallback,
    Race,
}

/// 一等 DNS Server Group。group 只作为 DNS rule action，不伪装成具名 transport。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsServerGroup {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub mode: DnsServerGroupMode,
    #[serde(default)]
    pub members: Vec<String>,
    #[serde(rename = "fallbackServerId", skip_serializing_if = "Option::is_none")]
    pub fallback_server_id: Option<String>,
}

/// DNS 拒绝方法。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DnsRejectMethod {
    #[default]
    Default,
    Drop,
}

/// DNS 策略动作。`followRouteDefault` 是显式组合能力，不是隐藏依赖。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum DnsPolicyAction {
    Server {
        #[serde(rename = "serverId", default)]
        server_id: String,
    },
    Group {
        #[serde(rename = "groupId", default)]
        group_id: String,
    },
    FakeIp,
    HostsFirst {
        #[serde(rename = "hostsServerId", default)]
        hosts_server_id: String,
        fallback: Box<DnsPolicyAction>,
    },
    Reject {
        #[serde(default)]
        method: DnsRejectMethod,
    },
    Predefined {
        #[serde(default = "default_rcode")]
        rcode: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        answer: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        ns: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        extra: Vec<String>,
    },
    FollowRouteDefault,
}

fn default_rcode() -> String {
    "NOERROR".to_string()
}

/// 连接目的域名的默认处理。它属于 DNS 策略所有权；route builder 只负责把选择编译成
/// sing-box 的非终结 `resolve` 动作。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DnsConnectionResolution {
    /// 保留域名，由目标出站按自身协议能力处理。
    #[default]
    PreserveDomain,
    /// 连接前发起内部 DNS Lookup；不指定 server，完整执行 dns.rules。
    DnsRules,
}

/// DNS 默认策略。缺席时由 legacy dnsConfig 派生，保持存量配置结果。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsPolicyDefaults {
    #[serde(rename = "directServerId", default)]
    pub direct_server_id: String,
    #[serde(rename = "proxyServerId", default)]
    pub proxy_server_id: String,
    #[serde(rename = "unmatchedAction", skip_serializing_if = "Option::is_none")]
    pub unmatched_action: Option<DnsPolicyAction>,
    #[serde(rename = "connectionResolution", default)]
    pub connection_resolution: DnsConnectionResolution,
}

/// v1-v3 流量目标域名处理。v4 起仅用于迁移/旧配置兼容；新配置的连接解析所有权在
/// [`DnsPolicyDefaults::connection_resolution`]，流量规则不再写入本字段。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DestinationResolutionMode {
    #[default]
    Inherit,
    PreserveDomain,
    DnsRules,
    Server,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DestinationResolution {
    #[serde(default)]
    pub mode: DestinationResolutionMode,
    #[serde(rename = "serverId", skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutePolicyDefaults {
    #[serde(rename = "destinationResolution", default)]
    pub destination_resolution: DestinationResolutionMode,
}

#[cfg(test)]
mod tests;
