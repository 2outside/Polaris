//! UserConfig 投影（上游 `shared/types.ts UserConfig` 子集）。
//!
//! 增量定义：仅 builder 所需字段。随各 builder 移植扩展。

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

use crate::user_config::dns_config::DnsConfig;
use crate::user_config::dns_policy::{
    builtin_dns_server_resources, DnsPolicyDefaults, DnsServerGroup, DnsServerResource,
    RoutePolicyDefaults,
};
use crate::user_config::proxy_mode::{ProxyMode, ProxyModeType};
use crate::user_config::region_routing::RegionRoutingConfig;
use crate::user_config::rule::{AppRule, CustomAppPreset, Rule, RuleResource};
use crate::user_config::server_config::ServerConfig;
use crate::user_config::tun_config::TunModeConfig;

/// 代理内核的物理出口网卡默认值。空值表示交给操作系统自动选择。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkInterfaceDefaults {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
}

/// config-engine 只消费订阅的本地出口策略；名称、URL、更新状态等字段由 store/runtime 原样持有。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionInterfacePolicy {
    pub id: String,
    #[serde(rename = "proxyBindInterface", skip_serializing_if = "Option::is_none")]
    pub proxy_bind_interface: Option<String>,
}

/// 用户配置（增量子集）。上游 `UserConfig`。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConfig {
    #[serde(
        rename = "configSchemaVersion",
        skip_serializing_if = "Option::is_none"
    )]
    pub config_schema_version: Option<u32>,
    pub servers: Vec<ServerConfig>,
    #[serde(default)]
    pub subscriptions: Vec<SubscriptionInterfacePolicy>,
    #[serde(rename = "selectedServerId")]
    pub selected_server_id: Option<String>,
    #[serde(rename = "proxyMode", default = "default_proxy_mode")]
    pub proxy_mode: ProxyMode,
    #[serde(rename = "proxyModeType", default = "default_proxy_mode_type")]
    pub proxy_mode_type: ProxyModeType,
    #[serde(rename = "tunConfig")]
    pub tun_config: Option<TunModeConfig>,
    #[serde(rename = "networkInterfaces", skip_serializing_if = "Option::is_none")]
    pub network_interfaces: Option<NetworkInterfaceDefaults>,
    #[serde(rename = "customRules", default)]
    pub custom_rules: Vec<Rule>,
    /// v2 唯一策略真值；缺省时 builder 兼容读取 customRules。
    #[serde(rename = "policyRules", skip_serializing_if = "Option::is_none")]
    pub policy_rules: Option<Vec<Rule>>,
    /// 一等流量规则集合。缺省时兼容读取 policyRules/customRules。
    #[serde(rename = "trafficRules", skip_serializing_if = "Option::is_none")]
    pub traffic_rules: Option<Vec<Rule>>,
    /// 一等 DNS 规则集合。缺省时兼容读取旧版共享 policyRules/customRules。
    #[serde(rename = "dnsRules", skip_serializing_if = "Option::is_none")]
    pub dns_rules: Option<Vec<Rule>>,
    #[serde(rename = "routeRuleOrder", default)]
    pub route_rule_order: Vec<String>,
    #[serde(rename = "dnsRuleOrder", default)]
    pub dns_rule_order: Vec<String>,
    #[serde(rename = "dnsServers", default = "default_dns_server_resources")]
    pub dns_servers: Vec<DnsServerResource>,
    #[serde(rename = "dnsServerGroups", default)]
    pub dns_server_groups: Vec<DnsServerGroup>,
    #[serde(rename = "dnsDefaults", skip_serializing_if = "Option::is_none")]
    pub dns_defaults: Option<DnsPolicyDefaults>,
    /// v1-v3 兼容字段；schema v4 迁入 `dnsDefaults.connectionResolution` 后删除。
    #[serde(rename = "routeDefaults", skip_serializing_if = "Option::is_none")]
    pub route_defaults: Option<RoutePolicyDefaults>,
    // rename 不可省：本结构**无** `rename_all`，逐字段 rename。缺了它 serde 找 `app_rules` 键，
    // 而 config.json 里是 `appRules` → `default` 静默给空 Vec → 应用分流整条在运行期不存在。
    #[serde(rename = "appRules", default)]
    pub app_rules: Vec<AppRule>,
    #[serde(rename = "appRoutingEnabled")]
    pub app_routing_enabled: Option<bool>,
    #[serde(rename = "customAppPresets", default)]
    pub custom_app_presets: Vec<CustomAppPreset>,
    #[serde(rename = "allowLan")]
    pub allow_lan: Option<bool>,
    #[serde(rename = "bypassLAN")]
    pub bypass_lan: Option<bool>,
    #[serde(rename = "bypassLANList")]
    pub bypass_lan_list: Option<Vec<String>>,
    #[serde(rename = "enableIPv6")]
    pub enable_ipv6: Option<bool>,
    #[serde(rename = "mixedPort")]
    pub mixed_port: Option<u16>,
    #[serde(rename = "httpPort")]
    pub http_port: Option<u16>,
    #[serde(rename = "dnsConfig")]
    pub dns_config: Option<DnsConfig>,
    // 同 app_rules：config.json 键是 `ruleResources`（store/src/sanitize.rs:62 亦按此名清洗）。
    #[serde(rename = "ruleResources", default)]
    pub rule_resources: Vec<RuleResource>,
    #[serde(rename = "tlsFragment", skip_serializing_if = "Option::is_none")]
    pub tls_fragment: Option<bool>,
    #[serde(
        rename = "interruptConnectionsOnSwitch",
        skip_serializing_if = "Option::is_none"
    )]
    pub interrupt_connections_on_switch: Option<bool>,
    /// v1 兼容字段；schema v4 迁入 `dnsDefaults.connectionResolution` 后删除。
    ///
    /// 旧语义为拨号前把目的域名解析成真实 IP（sing-box route action `resolve`）；v4 的行为说明与
    /// 默认值由 [`DnsPolicyDefaults::connection_resolution`] 单点持有，避免流量模型继续拥有 DNS 文案。
    #[serde(rename = "resolveBeforeDial", skip_serializing_if = "Option::is_none")]
    pub resolve_before_dial: Option<bool>,
    #[serde(rename = "regionRouting", skip_serializing_if = "Option::is_none")]
    pub region_routing: Option<RegionRoutingConfig>,
    /// fakeip-filter 总开关：false = 完全关（不生成 captive/ntp filter 规则）。上游 `fakeIpFilter`。
    #[serde(rename = "fakeIpFilter", skip_serializing_if = "Option::is_none")]
    pub fake_ip_filter: Option<bool>,
    /// 用户编辑过的 fakeip-filter 域名清单（未编辑=undefined → 用默认 captive+ntp）。上游 `fakeIpFilterList`。
    #[serde(rename = "fakeIpFilterList", skip_serializing_if = "Option::is_none")]
    pub fake_ip_filter_list: Option<Vec<String>>,
    /// 拦截浏览器内置 DoH（Chrome/Firefox 的「安全 DNS」）：对清单内域名的 443/853 与 UDP443 发 reject。
    /// **默认关**。开启前请读 [`Self::browser_doh_list`] 的取舍说明。
    ///
    /// # 为什么需要它
    ///
    /// 浏览器自带 DoH 会绕开本应用的 DNS 接管（hijack-dns / FakeIP）⇒ 基于域名的分流与 FakeIP 路由
    /// 对那部分查询**不生效**，且查询内容直接送到第三方 DoH 提供商。
    ///
    /// # 为什么默认关、且不内置成恒开
    ///
    /// 屏蔽浏览器行为不是代理客户端该替用户做的决定；2026-08-13 之前这里是一张**用户关不掉**的
    /// 硬编码黑名单，已整块移除（见 `builder::route` 的删除说明）。现在它是一个默认关的开关。
    #[serde(rename = "blockBrowserDoh", skip_serializing_if = "Option::is_none")]
    pub block_browser_doh: Option<bool>,
    /// 被拦的 DoH 端点域名清单（`domain_suffix` 语义）。未编辑 = `None` → 用
    /// [`crate::builder::route::DEFAULT_BROWSER_DOH_SUFFIXES`] 的内置起点。
    ///
    /// # 为什么是 suffix 而不是 keyword
    ///
    /// 旧实现用 `domain_keyword`，匹配面宽（`dns.google` 会命中 `foo.dns.google.evil.com`）。
    /// 这是一张**用户可编辑**的清单：用户填个短词就会误伤一大片，而误伤的后果他看不见。
    /// suffix 的代价是「填不全」，那一格已由清单本身可编辑 + 批量导入解决。
    #[serde(rename = "browserDohList", skip_serializing_if = "Option::is_none")]
    pub browser_doh_list: Option<Vec<String>>,
    /// 阻止 QUIC（对代理向 UDP 443 执行 reject，逼浏览器回退 TCP）；默认关；节点无关。
    /// 上游 `blockQuic`。
    #[serde(rename = "blockQuic", skip_serializing_if = "Option::is_none")]
    pub block_quic: Option<bool>,
    /// WebRTC 防泄露：off=不注入 / proxy=STUN 经代理 / block=reject STUN。上游 `webrtcLeakProtection`。
    #[serde(
        rename = "webrtcLeakProtection",
        skip_serializing_if = "Option::is_none"
    )]
    pub webrtc_leak_protection: Option<String>,
    /// 兼容旧配置的兜底排除进程（新数据已迁移为 customRules 的 processName+direct 规则）。上游 `bypassProcesses`。
    #[serde(rename = "bypassProcesses", skip_serializing_if = "Option::is_none")]
    pub bypass_processes: Option<Vec<String>>,
    /// clash_api/management api 鉴权 secret。上游 `clashApiSecret`。generateSingBoxConfig 注入 `services[0].secret`。
    #[serde(rename = "clashApiSecret", skip_serializing_if = "Option::is_none")]
    pub clash_api_secret: Option<String>,
    /// sing-box 1.14 官方面板 opt-in 开关。上游 `singboxDashboard`。on 时注入 `services[0].dashboard`。
    #[serde(rename = "singboxDashboard", skip_serializing_if = "Option::is_none")]
    pub singbox_dashboard: Option<bool>,
    // ── 日志两轴：只为 norm 可见性入列，值的解释权不在这里 ──────────────────────────────
    //
    // **为什么必须在册**：两键被 `runtime/proxy::log_axes_from_config` 从裸 JSON 读走喂 sing-box
    // `log.*` —— 改了要重启内核才生效。不在册则 `config_generation_norm` 恒相等 ⇒ 落 NoOp 腿 ⇒
    // 永不进 pending 差集：核在跑时关「关闭日志写盘」，sing-box 照旧写盘且全程无提示
    // （`ui/src/domain/app-restart-keys.ts` 记的「第四类重启」）。上游的同名排除表**不含**这两键，
    // 即那边本就会进重启判定 —— 本仓此前的行为是一处迁移回归，不是取舍。
    //
    // **为什么是 `Value` 而不是 `LogLevel` / `bool`**：`UserConfig` 的解析是全有全无的
    // （`from_value::<UserConfig>` 一旦 `Err`，起核腿整个放弃），而 `logLevel` 的取值域不由本仓独占
    // （sing-box 有 `trace`，手改/旧版配置还可能写进别的东西）。收紧类型 = 把「提示得晚」的缺陷换成
    // 「起不了核」的缺陷。用 `Value`：任何 JSON 值都进得来、都进投影、变了就判不等，而值怎么解释仍归
    // `log_axes_from_config`（非法值退化 `Info`，行为一字未改）。
    //
    // 「宽容强类型」（`Option<LogLevel>` + 解析失败落 `None`）也不行：那会让 `"trace"` 与 `"bogus"`
    // 归一成同一个 `None` ⇒ 两者互改**看不见**，等于在窄一点的取值域上重犯同一个错。`Value` 无此洞。
    /// 核日志级别。上游 `logLevel`。
    #[serde(rename = "logLevel", skip_serializing_if = "Option::is_none")]
    pub log_level: Option<serde_json::Value>,
    /// 禁用日志写盘。上游 `disableLogFile`。
    #[serde(rename = "disableLogFile", skip_serializing_if = "Option::is_none")]
    pub disable_log_file: Option<serde_json::Value>,
}

fn default_dns_server_resources() -> Vec<DnsServerResource> {
    builtin_dns_server_resources()
}

impl Default for UserConfig {
    fn default() -> Self {
        Self {
            config_schema_version: None,
            servers: Vec::new(),
            subscriptions: Vec::new(),
            selected_server_id: None,
            proxy_mode: default_proxy_mode(),
            proxy_mode_type: default_proxy_mode_type(),
            tun_config: None,
            network_interfaces: None,
            custom_rules: Vec::new(),
            policy_rules: None,
            traffic_rules: None,
            dns_rules: None,
            route_rule_order: Vec::new(),
            dns_rule_order: Vec::new(),
            dns_servers: default_dns_server_resources(),
            dns_server_groups: Vec::new(),
            dns_defaults: None,
            route_defaults: None,
            app_rules: Vec::new(),
            app_routing_enabled: None,
            custom_app_presets: Vec::new(),
            allow_lan: None,
            bypass_lan: None,
            bypass_lan_list: None,
            enable_ipv6: None,
            mixed_port: None,
            http_port: None,
            dns_config: None,
            rule_resources: Vec::new(),
            tls_fragment: None,
            interrupt_connections_on_switch: None,
            resolve_before_dial: None,
            region_routing: None,
            fake_ip_filter: None,
            fake_ip_filter_list: None,
            block_browser_doh: None,
            browser_doh_list: None,
            block_quic: None,
            webrtc_leak_protection: None,
            bypass_processes: None,
            clash_api_secret: None,
            singbox_dashboard: None,
            log_level: None,
            disable_log_file: None,
        }
    }
}

impl UserConfig {
    /// 一等流量规则；存量配置未迁移时兼容读取 policyRules/customRules。
    #[must_use]
    pub fn effective_traffic_rules(&self) -> &[Rule] {
        self.traffic_rules
            .as_deref()
            .or(self.policy_rules.as_deref())
            .unwrap_or(&self.custom_rules)
    }

    /// 一等 DNS 规则；存量配置未迁移时兼容读取共享 policyRules/customRules。
    #[must_use]
    pub fn effective_dns_rules(&self) -> &[Rule] {
        self.dns_rules
            .as_deref()
            .or(self.policy_rules.as_deref())
            .unwrap_or(&self.custom_rules)
    }

    fn ordered_rules<'a>(rules: &'a [Rule], order: &[String]) -> Vec<&'a Rule> {
        use std::collections::{BTreeMap, BTreeSet};

        let by_id: BTreeMap<&str, &Rule> = rules.iter().map(|r| (r.id.as_str(), r)).collect();
        let mut seen = BTreeSet::new();
        let mut out = Vec::with_capacity(rules.len());
        for id in order {
            if seen.insert(id.as_str()) {
                if let Some(rule) = by_id.get(id.as_str()) {
                    out.push(*rule);
                }
            }
        }
        for rule in rules {
            if seen.insert(rule.id.as_str()) {
                out.push(rule);
            }
        }
        out
    }

    #[must_use]
    pub fn ordered_traffic_rules(&self) -> Vec<&Rule> {
        Self::ordered_rules(self.effective_traffic_rules(), &self.route_rule_order)
    }

    #[must_use]
    pub fn ordered_dns_rules(&self) -> Vec<&Rule> {
        Self::ordered_rules(self.effective_dns_rules(), &self.dns_rule_order)
    }

    /// `UserConfig` 的**序列化键集**（= `config_generation_norm` 投影面），按声明序。
    ///
    /// # 这是干什么用的
    ///
    /// 渲染端「配置暂存」的豁免谓词是一行：`豁免(key) := key ∉ UserConfigFieldSet`。
    /// 判据**不是**查 `builder/orchestration.rs` 的排除表——`config_generation_norm` 的入参就是
    /// `&UserConfig`，投影里只可能出现本结构声明的键，排除一个本就不存在的键是空操作。该表
    /// 2026-07-29 前有 15 项、其中 14 项正是这种死键（随 上游 逐行对拍判据退役已删，现只剩
    /// `selectedServerId`）。真正决定「改了这个键核会不会重新生成配置」的，就是「它在不在本结构里」。
    ///
    /// 于是本常量是那条谓词的**唯一真值源**，导出给渲染端
    /// （`ui/src/contracts/user-config-fields.ts`，双向锁见同名 `.test.ts`）。
    ///
    /// # 增删字段时必须同步这里
    ///
    /// 下方 `fully_populated()` 用**穷尽结构字面量**构造实例：给 `UserConfig` 加字段而不改它 → E0063
    /// 编译失败；改了它却忘了本表 → `field_names_equals_serde_projection` 转红。两道门合起来，
    /// 「Rust 加了字段而字段表没跟上」在本 crate 内就被拦住，不必等前端那条跨语言锁。
    pub const FIELD_NAMES: &'static [&'static str] = &[
        "configSchemaVersion",
        "servers",
        "subscriptions",
        "selectedServerId",
        "proxyMode",
        "proxyModeType",
        "tunConfig",
        "networkInterfaces",
        "customRules",
        "policyRules",
        "trafficRules",
        "dnsRules",
        "routeRuleOrder",
        "dnsRuleOrder",
        "dnsServers",
        "dnsServerGroups",
        "dnsDefaults",
        "routeDefaults",
        "appRules",
        "appRoutingEnabled",
        "customAppPresets",
        "allowLan",
        "bypassLAN",
        "bypassLANList",
        "enableIPv6",
        "mixedPort",
        "httpPort",
        "dnsConfig",
        "ruleResources",
        "tlsFragment",
        "interruptConnectionsOnSwitch",
        "resolveBeforeDial",
        "regionRouting",
        "fakeIpFilter",
        "fakeIpFilterList",
        "blockBrowserDoh",
        "browserDohList",
        "blockQuic",
        "webrtcLeakProtection",
        "bypassProcesses",
        "clashApiSecret",
        "singboxDashboard",
        "logLevel",
        "disableLogFile",
    ];
}

fn default_proxy_mode() -> ProxyMode {
    ProxyMode::Smart
}

fn default_proxy_mode_type() -> ProxyModeType {
    ProxyModeType::SystemProxy
}

#[cfg(test)]
mod tests;
