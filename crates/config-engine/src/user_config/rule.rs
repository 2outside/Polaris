//! 路由规则类型（上游 `shared/types/rules.ts` Rule/RuleCondition/RuleAction/RuleType 1:1 移植）。
//!
//! buildCustomRules + buildRouteConfig 的主输入类型。对齐 sing-box route rule 常用全集。

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

use crate::user_config::dns_policy::{DestinationResolution, DnsPolicyAction};

fn default_true() -> bool {
    true
}

/// 规则动作：proxy=走代理 / direct=直连 / block=拒绝。上游 `RuleAction`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    #[default]
    Proxy,
    Direct,
    Block,
}

/// DNS 解析效果使用的解析器。`inherit` 按流量动作选择：代理→代理 DNS，其余→直连 DNS。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RuleDnsResolver {
    #[default]
    Inherit,
    Direct,
    Proxy,
}

/// DNS 应答形态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RuleDnsAnswerMode {
    #[default]
    Real,
    FakeIp,
}

/// 统一规则里的流量效果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleRouteEffect {
    /// route 平面独立启停；缺省 true 兼容第一阶段数据。
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub action: RuleAction,
    #[serde(rename = "targetServerId", skip_serializing_if = "Option::is_none")]
    pub target_server_id: Option<String>,
    /// v1-v3 兼容字段；schema v4 起连接解析由 `dnsDefaults.connectionResolution` 全局拥有。
    #[serde(
        rename = "destinationResolution",
        skip_serializing_if = "Option::is_none"
    )]
    pub destination_resolution: Option<DestinationResolution>,
    /// v1-v3 兼容字段：仅执行目标解析，不生成终结流量动作；schema v4 迁移会删除该影子规则。
    #[serde(
        rename = "resolutionOnly",
        default,
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub resolution_only: bool,
}

/// 统一规则里的 DNS 解析效果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleDnsEffect {
    /// DNS 平面独立启停；缺省 true 兼容第一阶段数据。
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// v2 一等 DNS 动作。缺省时读取 resolver/answerMode 兼容镜像。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<DnsPolicyAction>,
    /// v1-v3 兼容标记：第一阶段 DNS-only 曾隐式生成 route resolve。
    #[serde(rename = "migratedImplicitResolve", default)]
    pub migrated_implicit_resolve: bool,
    #[serde(default)]
    pub resolver: RuleDnsResolver,
    #[serde(rename = "answerMode", default)]
    pub answer_mode: RuleDnsAnswerMode,
}

/// 规则效果容器。v4 写入门要求 trafficRules 只有 route、dnsRules 只有 dns；双字段仅供旧配置迁移。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleEffects {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<RuleRouteEffect>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<RuleDnsEffect>,
}

/// 自定义规则条件类型（sing-box route rule 常用全集，去冗余）。上游 `RuleType`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RuleType {
    #[default]
    Domain,
    DomainSuffix,
    DomainKeyword,
    DomainRegex,
    IpCidr,
    SourceIpCidr,
    Port,
    SourcePort,
    /// sing-box 1.14 源设备识别（按 MAC 分流；仅 Linux/macOS）。
    SourceMac,
    SourceHostname,
    ProcessName,
    ProcessPath,
    Geosite,
    Geoip,
    RuleSet,
}

impl RuleType {
    /// 稳定 camelCase id（上游 `RULE_TYPE_IDS` 的元素；与本枚举 `serde rename_all = "camelCase"` 一致）。
    /// 供值校验（按类型字符串分派）与 `rule_validate::RULE_TYPE_IDS` 复用，杜绝手抄字符串漂移。
    #[must_use]
    pub fn as_id(self) -> &'static str {
        match self {
            RuleType::Domain => "domain",
            RuleType::DomainSuffix => "domainSuffix",
            RuleType::DomainKeyword => "domainKeyword",
            RuleType::DomainRegex => "domainRegex",
            RuleType::IpCidr => "ipCidr",
            RuleType::SourceIpCidr => "sourceIpCidr",
            RuleType::Port => "port",
            RuleType::SourcePort => "sourcePort",
            RuleType::SourceMac => "sourceMac",
            RuleType::SourceHostname => "sourceHostname",
            RuleType::ProcessName => "processName",
            RuleType::ProcessPath => "processPath",
            RuleType::Geosite => "geosite",
            RuleType::Geoip => "geoip",
            RuleType::RuleSet => "ruleSet",
        }
    }

    /// 首版 DNS 解析效果可安全复用的匹配类型。
    ///
    /// DNS 选择发生在应答前，目的 IP/端口/GeoIP 不在同一阶段；来源设备/进程的 route-resolve
    /// 元数据覆盖面尚未完成全平台验收，先 fail-closed。
    #[must_use]
    pub fn supports_dns_effect(self) -> bool {
        matches!(
            self,
            RuleType::Domain
                | RuleType::DomainSuffix
                | RuleType::DomainKeyword
                | RuleType::DomainRegex
                | RuleType::Geosite
                | RuleType::RuleSet
        )
    }
}

/// 单个匹配条件（type + values）。上游 `RuleCondition`。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleCondition {
    #[serde(rename = "type")]
    pub type_field: RuleType,
    pub values: Vec<String>,
}

/// 多条件组合：or(默认，命中任一) / and(全部命中)。上游 `Rule.combineMode`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CombineMode {
    And,
    #[default]
    Or,
}

/// 自定义路由规则。上游 `Rule`。
///
/// `type`/`values` = 首条件镜像（向后兼容）；`conditions` = 多条件（≥2 时存在）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    /// 首条件镜像（恒与 `conditions[0]` 一致）。
    #[serde(rename = "type")]
    pub type_field: RuleType,
    pub values: Vec<String>,
    /// 多条件共存（≥2 条件时存在）。空/缺省 = 单条件规则。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<RuleCondition>>,
    #[serde(rename = "combineMode", skip_serializing_if = "Option::is_none")]
    pub combine_mode: Option<CombineMode>,
    pub action: RuleAction,
    /// 效果模型。缺省 = 存量流量规则，route 回退到 action/targetServerId，
    /// legacy DNS bypass 回退到 bypassFakeIP。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effects: Option<RuleEffects>,
    pub enabled: bool,
    /// 绕过 FakeIP（仅 domain/domainSuffix/domainKeyword 有效）。
    #[serde(rename = "bypassFakeIP", skip_serializing_if = "Option::is_none")]
    pub bypass_fakeip: Option<bool>,
    /// 目标代理服务器 ID（仅 action=proxy 时有效）。
    #[serde(rename = "targetServerId", skip_serializing_if = "Option::is_none")]
    pub target_server_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remarks: Option<String>,
    /// TLS spoof（P3a 抗审查，sing-box 1.14）：伪造 ClientHello SNI。
    #[serde(rename = "tlsSpoof", skip_serializing_if = "Option::is_none")]
    pub tls_spoof: Option<String>,
    #[serde(rename = "tlsSpoofMethod", skip_serializing_if = "Option::is_none")]
    pub tls_spoof_method: Option<String>,
}

impl Rule {
    /// 生效中的流量动作。`effects` 一旦存在即为权威，route 缺省表示本规则不属于流量平面。
    #[must_use]
    pub fn route_action(&self) -> Option<RuleAction> {
        match &self.effects {
            Some(effects) => effects
                .route
                .as_ref()
                .filter(|route| route.enabled && !route.resolution_only)
                .map(|route| route.action),
            None => Some(self.action),
        }
    }

    /// 生效中的流量目标节点。
    #[must_use]
    pub fn route_target_server_id(&self) -> Option<&str> {
        match &self.effects {
            Some(effects) => effects
                .route
                .as_ref()
                .filter(|route| route.enabled && !route.resolution_only)
                .and_then(|route| route.target_server_id.as_deref()),
            None => self.target_server_id.as_deref(),
        }
    }

    /// 生效中的 DNS 解析效果。存量 bypassFakeIP 迁移为 real + inherit。
    #[must_use]
    pub fn dns_effect(&self) -> Option<RuleDnsEffect> {
        match &self.effects {
            Some(effects) => effects.dns.as_ref().filter(|dns| dns.enabled).cloned(),
            None if self.bypass_fakeip == Some(true) => Some(RuleDnsEffect {
                enabled: true,
                action: None,
                migrated_implicit_resolve: false,
                resolver: RuleDnsResolver::Inherit,
                answer_mode: RuleDnsAnswerMode::Real,
            }),
            None => None,
        }
    }
}

/// 已下载规则资源（.srs）。上游 `RuleResource`。
///
/// **逐字段 rename 不可省**（本结构无 `rename_all`）：config.json 侧是 camelCase
/// （`sourceUrl`/`fileName`/`downloadedAt`，见 `ui/src/shared/types/rules.ts:105`）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleResource {
    pub id: String,
    pub name: String,
    pub category: String,
    #[serde(rename = "sourceUrl")]
    pub source_url: String,
    #[serde(rename = "fileName")]
    pub file_name: String,
    pub format: RuleResourceFormat,
    pub size: u64,
    #[serde(rename = "downloadedAt")]
    pub downloaded_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleResourceFormat {
    Binary,
    Source,
}

/// 应用分流规则（映射到内置 geosite/process 规则集）。上游 `AppRule`。
///
/// **`appId` 的 rename 不可省**（本结构无 `rename_all`）：`targetServerId` 有、`app_id` 曾漏 →
/// 整条 appRules 反序列化不出来。见 `app_config.rs` 的 `app_rules` 注释。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRule {
    #[serde(rename = "appId")]
    pub app_id: String,
    pub action: RuleAction,
    pub enabled: bool,
    #[serde(rename = "targetServerId", skip_serializing_if = "Option::is_none")]
    pub target_server_id: Option<String>,
}

/// 自定义应用分流预设。上游 `CustomAppPreset`。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomAppPreset {
    pub id: String,
    pub name: String,
    pub emoji: String,
    #[serde(rename = "iconUrl", skip_serializing_if = "Option::is_none")]
    pub icon_url: Option<String>,
    #[serde(default, rename = "geositeTags")]
    pub geosite_tags: Vec<String>,
    #[serde(default, rename = "geoipTags", skip_serializing_if = "Vec::is_empty")]
    pub geoip_tags: Vec<String>,
    #[serde(rename = "processNames", skip_serializing_if = "Option::is_none")]
    pub process_names: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
}

#[cfg(test)]
mod tests;
