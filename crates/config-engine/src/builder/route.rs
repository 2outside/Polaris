//! sing-box 路由配置生成（上游 `singbox-route-builder.ts` 1:1 移植）。
//!
//! route 子系统集成 hub：纯函数，只读 config/id_to_tag_map + 注入实例态依赖（probe 端口 /
//! lan_resolver_for_dns / pending_endpoints 值 + log·on_degraded 回调）。装配 sniff/探针/DNS 直连·劫持/
//! 节点排除/网银 U盾/endpoint 强制路由/私网直连/自定义规则(build_custom_rules)/应用分流/QUIC 阻断/
//! geo rule_set/悬空剪枝。
//!
//! 纯函数 + 依赖注入：所有实例态经 `RouteConfigDeps` 注入，FS 路径经 `RouteConfigDeps.runtime_rules_dir` /
//! `rule_resources_path` 注入（对拍固定假路径），`is_valid_srs_fn` 注入（对拍 fixture 控制）。

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use crate::builder::custom_rule_files::uses_fake_ip;
use crate::builder::custom_rules::{build_custom_rules, CustomRulesDeps};
use crate::builder::endpoint_routes::{
    collect_rule_targeted_server_ids, endpoint_forced_route_cidrs, mesh_force_routed_servers,
    mesh_forced_route_cidrs, mesh_node_carries_full_tunnel, should_force_route_subnets,
};
use crate::builder::helpers::{
    apply_rule_set_prune, effective_app_rules, effective_custom_rules,
    get_custom_domestic_dns_endpoint, get_required_geo_categories, host_to_exclude_cidr,
    is_ipv4_host, is_ipv6_host, probe_pool_inbound_tag, DOMESTIC_BANK_AND_STOCK_DOMAINS,
};
use crate::builder::subscription_guard::subscription_update_route_rules;
use crate::singbox::{OneOrMany, RouteConfig, RouteRule, RuleSet};
use crate::user_config::app_config::UserConfig;
use crate::user_config::app_rules_preset::get_app_preset;
use crate::user_config::builtin_geo_rulesets::{
    builtin_geo_rulesets, find_builtin, PRIVATE_DOMAIN_DIRECT_TAG,
};
use crate::user_config::cidr::{cidr_overlaps_any, partition_cidrs_by_overlap};
use crate::user_config::collections::dedupe;
use crate::user_config::dns_constants::{
    is_block_selection, is_direct_selection, BOOTSTRAP_DIRECT_DNS_IPS, PROXY_SELECTOR_TAG,
};
use crate::user_config::log_level::LogLevel;
use crate::user_config::proxy_mode::{ProxyMode, ProxyModeType};
use crate::user_config::region_routing::{
    effective_region_routing, region_foreign_geo, region_local_geo,
};
use crate::user_config::rule::AppRule;
use crate::user_config::rule::RuleAction;
use crate::user_config::rules::rule_ip_cidrs;
use crate::user_config::server_config::{is_mesh_node, Protocol};
use crate::user_config::system_proxy_bypass::{bypass_lan_cidrs, effective_bypass_lan};
use crate::user_config::tun_config::{FAKEIP_INET4_RANGE, FAKEIP_INET6_RANGE};

/// DoH 上游 IP 单一真值（上游 `shared/dns#DOH_UPSTREAM_IPS`）。
/// 223.5.5.5 AliDNS + 1.12.12.12 DNSPod（#57）。
const DOH_UPSTREAM_IPS: &[&str] = &["223.5.5.5", "1.12.12.12"];

/// 浏览器内置 DoH 端点的**内置起点清单**（`domain_suffix` 语义，非全集）。
///
/// 只在 `blockBrowserDoh` 开关**打开**且用户没编辑过清单时使用；用户一旦编辑，以用户的为准。
///
/// # 收录判据
///
/// 「浏览器自带的安全 DNS 下拉里能选到的提供商」+ 广泛使用的公共 DoH 端点。suffix 语义下
/// `cloudflare-dns.com` 已覆盖 `mozilla.` / `chrome.` / `security.` / `family.` 那几个子域，
/// 故不逐个列。
///
/// # 刻意不收的两类（不是遗漏）
///
/// - **国内公共 DoH**（`doh.pub` / `dns.alidns.com` / `doh.360.cn` 等）：它们不是浏览器内置选项，
///   而且**本应用自己的 DNS 上游就用其中两个**（`DOH_UPSTREAM_IPS` 与 bootstrap 的 `doh.pub`）。
///   预填进来等于自伤 —— 用户要拦可以自己加，但那是他知情下的选择。
/// - **各家的门户/官网**：这里列的是**解析端点**，不是站点。列 apex（如 `quad9.net`）会把官网一起拦掉，
///   收益为零。用户若想连官网一起拦，把 apex 加进清单即可。
///
/// # 它必然不全，这是设计而非缺陷
///
/// DoH 端点可以是任意自建域名甚至纯 IP，黑名单原理上不可能穷尽。故本清单只是**起点**，
/// 真正的兜底是 UI 上那个可编辑 + 可批量导入的清单。
pub const DEFAULT_BROWSER_DOH_SUFFIXES: &[&str] = &[
    // Google
    "dns.google",
    // Cloudflare（含 mozilla./chrome./security./family. 子域）
    "cloudflare-dns.com",
    "one.one.one.one",
    // Quad9
    "dns.quad9.net",
    "dns9.quad9.net",
    "dns10.quad9.net",
    "dns11.quad9.net",
    // Cisco OpenDNS
    "doh.opendns.com",
    "doh.familyshield.opendns.com",
    // NextDNS（含 firefox. 子域）
    "dns.nextdns.io",
    // AdGuard（含 family./unfiltered. 子域）
    "adguard-dns.com",
    "dns.adguard.com",
    // CleanBrowsing
    "doh.cleanbrowsing.org",
    // Control D
    "dns.controld.com",
    "freedns.controld.com",
    // Mullvad（含 adblock./base. 子域）
    "dns.mullvad.net",
    "doh.mullvad.net",
    // DNS.SB
    "doh.sb",
    "doh.dns.sb",
    // Comss.one（Firefox 在俄区的默认档之一）
    "dns.comss.one",
    "router.comss.one",
    // 其它广泛使用的公共端点
    "wikimedia-dns.org",
    "dns.digitale-gesellschaft.ch",
    "doh.libredns.gr",
];

/// Tailscale preferred_by 试点开关（上游 `TS_PREFERRED_BY_TRIAL = false`）。
/// sing-box 源码确证 TS 的 routePrefixes 运行时动态+就绪窗口 nil → 组网段不归位，故 TS 必走 ip_cidr 静态。
const TS_PREFERRED_BY_TRIAL: bool = false;

/// 注入依赖：上游 `RouteConfigDeps`。实例态（值 + 回调）由 generateSingBoxConfig 注入。
///
/// 对拍：FS 路径注入固定假路径（如 "/fake/rules/"），`is_valid_srs_fn` 由测试夹具控制。
pub struct RouteConfigDeps<'a> {
    pub probe_direct_port: Option<u16>,
    pub probe_proxy_port: Option<u16>,
    pub update_in_port: Option<u16>,
    pub subscription_update_in_port: Option<u16>,
    /// §15 主核测速探测池：K 个 probe-in-k → probe-selector-k 钉死路由的端口数。
    /// 空/缺省 = 不注入池。
    pub probe_pool_ports: Vec<u16>,
    pub lan_resolver_for_dns: Option<String>,
    pub pending_endpoints: &'a [crate::singbox::Endpoint],
    pub log: fn(LogLevel, &str),
    pub on_degraded: fn(),
    /// issue #147：本地 race server 的【自定义】上游 IP（内置 ali/dnspod 已在 BOOTSTRAP_DIRECT_DNS_IPS）。
    /// 缺省空 = race off / 无自定义上游（零变化）。
    pub race_upstream_ips: Vec<String>,
    /// issue #147：上面那些上游**实际在用的端口**（由 `polaris-dns-race` 的 `ResolvedUpstreams::direct_ports`
    /// 一路下发到此，见该字段文档）。缺省空 = race off（端口集逐字节回 `[53,443]` 基线，金样不动）。
    ///
    /// **本 builder 只消费、不复算**：真实上游集是 Tier 分桶 + canonical 去重 + Tier1 上限 + TUN 下摘
    /// `system` 之后的结果，那条选择链只在 `polaris-dns-race` 里完整存在。此处曾就地从
    /// `config.dns_config` 重新导出一遍端口（只认 `nodeResolverPool` 点名的纯 IP 条目，刻意不复制分桶/
    /// 去重/上限 ⇒ 真实集的**超集**）—— 方向是安全的，但那是**第二份真值源**：它与 sidecar 的选择
    /// 逻辑靠人肉对齐，任何一侧改口径都不会让另一侧转红。改成随 IP 一起注入后，两轴同源、同一次遍历
    /// 产出，结构上不可能分叉。
    pub race_upstream_ports: Vec<u16>,
    /// 运行时 rules 目录（内置 geo .srs 路径前缀）。对拍固定假路径。
    pub runtime_rules_dir: String,
    /// 用户规则资源目录（res:`<id>` 文件路径前缀）。对拍固定假路径。
    pub rule_resources_path: String,
    /// 自定义规则外化文件目录（L3 ext 文件路径前缀）。对拍固定假路径。
    pub custom_rules_dir: String,
    /// 编译目标 arch（tls_spoof 门控）。
    pub arch: String,
    /// 运行平台（source device match 门控）。
    pub platform: String,
    /// 文件存在性 + SRS 魔数检查（对拍 fixture 注入固定 true/false）。
    pub is_valid_srs_fn: fn(&str) -> bool,
}

/// QUIC(UDP/443) reject 规则工厂：可选叠加域名/进程等匹配器。route 与各处 blockQuic 共用，
/// 保证 network/port/action 字面量始终一致（避免某处漏写 network 导致行为漂移）。
/// 上游 `udp443RejectRule`。
///
/// # ⚠️ 本仓 5 处「裸 reject」仍受 50 次/30s 泛洪降级影响（已知，待另一批处理）
///
/// 这 5 处（本工厂 + 本文件 `:455` DNS 防泄露 domain_keyword 段、`:548` STUN 阻断、
/// `:596` logical udp443、`:887`）都**不带 `no_drop`** ⇒ 落到 sing-box 默认
/// `no_drop=false`：30s 内超 50 次拒绝就把 `method` 临时降级成 `drop`（静默丢包）。
///
/// **本工厂这一条尤其可疑**：它的既定目的是「阻 QUIC 逼浏览器回退 TCP」，而回退依赖拒绝是
/// **立刻**的；一旦降级成 drop，浏览器就等在那里，功能被打掉。
///
/// 阻断类新腿（自定义规则 / 应用分流的 `RuleAction::Block`）已显式置 `no_drop:true`。
/// 这 5 处**没跟着改的唯一原因**是：其中 3 条逐字节写在金样 37 例的期望值里
/// （`fixtures/config-snapshot.json`），改它们会改动金样、与 上游 参考实现分家 ⇒ 属另一批。
/// **此处只留判据，不改行为。**
fn udp443_reject_rule(matcher: RouteRule) -> RouteRule {
    let mut rule = matcher;
    rule.network = Some(vec!["udp".to_string()]);
    rule.port = Some(OneOrMany::Many(vec![443]));
    rule.action = Some("reject".to_string());
    // 清掉与 udp443 reject 冲突的匹配字段（Polaris 仅复制 matcher 字段，本工厂直接覆盖）。
    rule.port_range = None;
    rule
}

/// 提取 RouteRule 的匹配字段（除 action/outbound/network/port/port_range/type/mode/rules 外），
/// 供 udp443 reject 配对用（上游 `UDP443_MATCHER_EXCLUDE`）。返回 None = 无匹配字段。
fn extract_udp443_matcher(cr: &RouteRule) -> Option<RouteRule> {
    // 用 serde_json::Value 中转：序列化 cr → 移除 excluded 键 → 反序列化为 RouteRule。
    let mut val = serde_json::to_value(cr).ok()?;
    let obj = val.as_object_mut()?;
    for k in [
        "action",
        "outbound",
        "network",
        "port",
        "port_range",
        "type",
        "mode",
        "rules",
    ] {
        obj.remove(k);
    }
    // 仅当仍有非空匹配字段才返回（Polaris: Object.keys(matcher).length > 0）。
    if obj.is_empty() {
        return None;
    }
    // 移除值为 null 的字段（上游 `v != null`）。
    obj.retain(|_, v| !v.is_null());
    if obj.is_empty() {
        return None;
    }
    serde_json::from_value(val).ok()
}

/// [`build_route_config_with_report`] 的产物：路由配置 + 本次 fail-closed 剪枝报告。
#[derive(Debug, Clone)]
pub struct RouteConfigOutcome {
    /// 生成的 route 配置（与 [`build_route_config`] 返回值逐字段相同）。
    pub route: RouteConfig,
    /// 因本地 `.srs` 缺失/损坏而被 fail-closed 剪枝的 rule_set tag（**空 = 规则集完整**）。
    ///
    /// 这是「规则被剪枝」的**唯一诚实来源**：只有剪枝点本身知道哪些 tag 悬空。运行时层据此
    /// 决定要不要给用户发可见信号（资源齐全时恒空 → 零噪音）。
    pub pruned_rule_set_tags: Vec<String>,
}

/// buildRouteConfig 入口。上游 `buildRouteConfig`（904 行）。
///
/// 纯函数：只读 config/id_to_tag_map + 注入 deps。返回完整 RouteConfig。
pub fn build_route_config(
    config: &UserConfig,
    id_to_tag_map: &BTreeMap<String, String>,
    deps: &RouteConfigDeps<'_>,
) -> RouteConfig {
    build_route_config_with_report(config, id_to_tag_map, deps).route
}

/// [`build_route_config`] + 剪枝报告。
///
/// **为什么另开入口而非改原签名**：与 [`crate::builder::generate::generate_sing_box_config_with_report`]
/// 同一取舍——原函数有 30+ 处调用方（含 golden 对拍），改返回类型会把「多返回一个副产物」变成全仓
/// 签名 churn。原函数保留为本函数的薄 wrapper（同一条代码路径，绝无第二份生成逻辑）。
#[allow(clippy::too_many_lines)]
pub fn build_route_config_with_report(
    config: &UserConfig,
    id_to_tag_map: &BTreeMap<String, String>,
    deps: &RouteConfigDeps<'_>,
) -> RouteConfigOutcome {
    let mut rules: Vec<RouteRule> = Vec::new();
    let proxy_mode = proxy_mode_str(config);
    let ordered_route_rules: Vec<_> = config
        .ordered_traffic_rules()
        .into_iter()
        .cloned()
        .collect();
    // 地区分流（智能分流的 geo 基线层）：None=默认中国大陆正向(=今日行为)，仅 smart 模式生效。
    let region = effective_region_routing(config.region_routing.as_ref());

    // 组网 force-route 的「engaged」判定集（与块 0c shouldForceRouteSubnets 同口径，单一真值）：仅
    // enabled+action==='proxy' 的自定义规则/应用分流 targetServerId 计入。下方重叠 warn 与块 0c 发射端共用，
    // 杜绝对「仅出网且未 engaged」节点虚报。
    let custom_rules_eff = effective_custom_rules(proxy_mode.as_str(), &ordered_route_rules);
    let app_rules_eff = effective_app_rules(
        config.app_routing_enabled == Some(true),
        proxy_mode.as_str(),
        &config.app_rules,
    );
    let rule_targeted_server_ids = collect_targeted_mixed(&custom_rules_eff, &app_rules_eff);

    // mesh 重叠提醒（layer-2 兜底，非阻断）。基准只取「本轮实际会发射 force-route」的节点（与块 0c 同 gate）。
    let mesh_cidrs_for_warn = mesh_forced_route_cidrs(&mesh_force_routed_servers(
        &config.servers,
        config.selected_server_id.as_deref(),
        &rule_targeted_server_ids,
    ));
    if !mesh_cidrs_for_warn.is_empty() {
        let mut overlapping: BTreeSet<String> = BTreeSet::new();
        for rule in &custom_rules_eff {
            if !rule.enabled {
                continue;
            }
            for c in rule_ip_cidrs(rule) {
                if cidr_overlaps_any(&c, &mesh_cidrs_for_warn) {
                    overlapping.insert(c);
                }
            }
        }
        if !overlapping.is_empty() {
            let sample_vec: Vec<String> = overlapping.iter().take(5).cloned().collect();
            let sample = sample_vec.join(", ");
            (deps.log)(LogLevel::Warn, &format!(
                "{} 个自定义规则网段（{sample}{}）与组网(WG/Tailscale)路由段重叠：按优先级将覆盖组网路由，该段可能不走组网节点。如非有意请调整规则或组网配置。",
                overlapping.len(),
                if overlapping.len() > 5 { "…" } else { "" }
            ));
        }
    }

    // 主代理出站统一走 selector(proxy-selector)：热切换即改 selector 指向、路由无需重生成。
    // 常量取自 dns_constants 单一真值——与 outbounds.rs 的生成方、hotswitch.rs 的 PUT 消费方同源。
    let selected_server_tag = PROXY_SELECTOR_TAG;

    // 出口选中阻断哨兵（proxy-selector 的 default = block）。只用于管理面豁免判据，**不改 user_exit_tag**：
    // 阻断必须经由 selector 表达（改成直写 block 就退化成不可热切、且切出阻断也要重启）。
    let exit_is_block = is_block_selection(config.selected_server_id.as_deref());

    // D4/D7：主节点是「关外网组网节点」时，「→代理」的用户出口整体回退 direct。
    let exit_fallback = mesh_selected_exit_falls_back_to_direct(config);
    let user_exit_tag = if exit_fallback {
        "direct"
    } else {
        selected_server_tag
    };
    if exit_fallback {
        (deps.log)(
            LogLevel::Warn,
            "选中的组网节点已关闭外网访问：外网流量已回退直连（具体网段仍经组网节点），如需经此节点全隧道请开启该节点「允许访问外网」",
        );
    }

    // blockQuic（节点无关）：开启时对"将走代理"的 QUIC(UDP443) 执行 reject，逼浏览器回退 TCP。
    let block_proxy_quic =
        config.block_quic == Some(true) && proxy_mode != "direct" && !config.servers.is_empty();

    // 给定域名匹配器，返回应配对的 udp443 reject 规则（smart 模式放在每条 →代理 规则之前），否则 None。
    let proxy_udp_reject_for = |matcher: RouteRule| -> Option<RouteRule> {
        if block_proxy_quic {
            Some(udp443_reject_rule(matcher))
        } else {
            None
        }
    };

    // WebRTC 防泄露：off=不注入；proxy=STUN 经代理；block=reject STUN。
    let webrtc_leak = config
        .webrtc_leak_protection
        .as_deref()
        .unwrap_or("off")
        .to_string();

    // A. 嗅探规则（必须在前，用于识别域名）。
    rules.push(RouteRule {
        action: Some("sniff".to_string()),
        ..empty_matcher()
    });
    // WebRTC 防泄露开启时为稳健补一条显式 UDP stun sniffer。
    if webrtc_leak != "off" {
        rules.push(RouteRule {
            network: Some(vec!["udp".to_string()]),
            action: Some("sniff".to_string()),
            sniffer: Some(vec!["stun".to_string()]),
            timeout: Some("300ms".to_string()),
            ..empty_matcher()
        });
    }

    // A2. 出口 IP 探针钉死路由（紧随 sniff、先于一切分流/进程规则）。
    // 上游 `inbound: ['probe-direct-in']`（route-builder.ts:203）恒数组，对齐序列化形态。
    if deps.probe_direct_port.is_some() {
        rules.push(RouteRule {
            inbound: Some(OneOrMany::Many(vec!["probe-direct-in".to_string()])),
            action: Some("route".to_string()),
            outbound: Some("direct".to_string()),
            ..empty_matcher()
        });
    }
    if deps.probe_proxy_port.is_some() {
        rules.push(RouteRule {
            inbound: Some(OneOrMany::Many(vec!["probe-proxy-in".to_string()])),
            action: Some("route".to_string()),
            outbound: Some(selected_server_tag.to_string()),
            ..empty_matcher()
        });
    }

    // A2b. 主核测速探测池钉死路由（§15）：probe-in-k → probe-selector-k。
    // 上游 `inbound: ['probe-in-${k}']`（route-builder.ts:212）恒数组。
    for k in 0..deps.probe_pool_ports.len() {
        rules.push(RouteRule {
            inbound: Some(OneOrMany::Many(vec![probe_pool_inbound_tag(k)])),
            action: Some("route".to_string()),
            outbound: Some(format!("probe-selector-{k}")),
            ..empty_matcher()
        });
    }

    // A3. update-in 钉死路由：global/smart → user_exit_tag；direct → direct。
    // 上游 `inbound: ['update-in']`（route-builder.ts:223）恒数组。
    //
    // **阻断出口豁免**：出口选阻断时 user_exit_tag 指向的 proxy-selector 其 default 已是 block ⇒
    // 订阅更新与检查更新会一并被掐死。这条腿必须改走 direct，理由是管理面同类豁免的一致性——
    // LAN/私网、DNS、ICMP、sing-box 自身进程本来就无条件放行直连，订阅/更新属同一类「让用户还能
    // 自救」的管理流量。掐死它之后用户只剩「切回出口」一条路，多一道自锁台阶而毫无收益。
    if deps.update_in_port.is_some() {
        rules.push(RouteRule {
            inbound: Some(OneOrMany::Many(vec!["update-in".to_string()])),
            action: Some("route".to_string()),
            outbound: Some(if proxy_mode == "direct" || exit_is_block {
                "direct".to_string()
            } else {
                user_exit_tag.to_string()
            }),
            ..empty_matcher()
        });
    }

    // Subscription-only SSRF guard. Keep these three rules adjacent and ahead
    // of every generic direct/private/custom route: resolve -> reject -> pin.
    if deps.subscription_update_in_port.is_some() {
        // This is also consumed by the command layer before it chooses the local SOCKS client.
        // Keeping the route decision in one predicate prevents a live port from being mistaken
        // for a proxy path when the generated core route ultimately exits direct.
        let outbound = if subscription_update_route_uses_proxy(config) {
            user_exit_tag
        } else {
            "direct"
        };
        rules.extend(subscription_update_route_rules(outbound));
    }

    // 1. 强制放行 sing-box 核心进程：防止流量回流死循环。
    rules.push(RouteRule {
        process_name: Some(OneOrMany::Many(vec![
            "sing-box".to_string(),
            "sing-box.exe".to_string(),
        ])),
        action: Some("route".to_string()),
        outbound: Some("direct".to_string()),
        ..empty_matcher()
    });

    // C. 强制引导核心 DNS 直连（必须在 hijack-dns 之前！）。
    let custom_domestic_dns = get_custom_domestic_dns_endpoint(
        config
            .dns_config
            .as_ref()
            .and_then(|d| d.domestic_dns.as_deref()),
    );
    let mut dns_direct_cidrs: Vec<String> = BOOTSTRAP_DIRECT_DNS_IPS
        .iter()
        .map(|ip| format!("{ip}/32"))
        .collect();
    if let Some((ip, _port)) = &custom_domestic_dns {
        if let Some(c) = host_to_exclude_cidr(ip) {
            dns_direct_cidrs.push(c);
        }
    }
    if let Some(lan) = &deps.lan_resolver_for_dns {
        if let Some(c) = host_to_exclude_cidr(lan) {
            dns_direct_cidrs.push(c);
        }
    }
    for ip in &deps.race_upstream_ips {
        if let Some(c) = host_to_exclude_cidr(ip) {
            dns_direct_cidrs.push(c);
        }
    }
    // :53=UDP / :443=DoH（恒）。DoT(:853) 二期未实现——无 DoT 上游，不为永不工作的协议开无用端口。
    let mut dns_ports: Vec<u32> = vec![53, 443];
    if let Some((_, port)) = &custom_domestic_dns {
        dns_ports.push(u32::from(*port));
    }
    // issue #147：race 上游的**实际端口**必须与它的 IP 一起放行（两轴缺一，规则就匹配不上 ⇒ TUN 下该
    // 上游经代理出站/回环）。端口由 sidecar 侧的真实上游集下发（`race_upstream_ports`，见该字段文档），
    // **本处不复算**。race off 时两轴同为空 ⇒ 端口集逐字节回 `[53,443]` 基线，金样输出不动。
    dns_ports.extend(deps.race_upstream_ports.iter().copied().map(u32::from));
    let dns_ports_dedup: Vec<u32> = dedupe(dns_ports);
    rules.push(RouteRule {
        ip_cidr: Some(dns_direct_cidrs),
        port: Some(ports_to_one_or_many(dns_ports_dedup)),
        action: Some("route".to_string()),
        outbound: Some("direct".to_string()),
        ..empty_matcher()
    });

    // D. DNS 劫持（必须在引导 DNS IP 直连之后）。劫持所有其余 port 53 流量。
    // Polaris route-builder L273-276 用 `port: [53]`（恒数组），非单值裸数字；对齐序列化形态。
    rules.push(RouteRule {
        port: Some(OneOrMany::Many(vec![53])),
        action: Some("hijack-dns".to_string()),
        ..empty_matcher()
    });

    rules.push(RouteRule {
        process_name: Some(OneOrMany::Many(vec![
            "Surge".to_string(),
            "Surge 4".to_string(),
            "Surge 5".to_string(),
            "Clash".to_string(),
            "Clash for Windows".to_string(),
            "ClashX".to_string(),
            "ClashX Pro".to_string(),
            "clash-meta".to_string(),
            "Quantumult X".to_string(),
            "sing-box".to_string(),
            "sing-box.exe".to_string(),
            "mDNSResponder".to_string(),
            "apsd".to_string(),
            "nsurlsessiond".to_string(),
            "airportd".to_string(),
            "syspolicyd".to_string(),
            "trustd".to_string(),
            "ocspd".to_string(),
            "securityd".to_string(),
            "taskgated".to_string(),
            "findmydeviced".to_string(),
            "cloudd".to_string(),
        ])),
        action: Some("route".to_string()),
        outbound: Some("direct".to_string()),
        ..empty_matcher()
    });

    // 构造 routeConfig 主体（final 在此定）。
    // direct 模式或 smart+地区反向（如「回国」：海外应直连）→ final=direct；否则 → user_exit_tag。
    // 两分支同返 'direct' 是 1:1 镜像 Polaris（条件语义不同：模式 vs 地区反向），故 allow if_same_then_else。
    #[allow(clippy::if_same_then_else)]
    let final_outbound = if proxy_mode == "direct" {
        "direct".to_string()
    } else if proxy_mode == "smart" && region.enabled && region.reverse {
        "direct".to_string()
    } else {
        user_exit_tag.to_string()
    };
    let mut route_config = RouteConfig {
        rule_set: None,
        rules: rules.clone(),
        default_domain_resolver: Some("dns-bootstrap".to_string()),
        // 只在 TUN 使用全局自动探测：此时 sing-box 自己控制 TUN 路由并需要避开回环。
        // System/manual 没有 TUN 路由上下文，全局探测会把所有默认拨号器（含 direct/DNS）锁到
        // 单一默认网卡，破坏 OS 已有的逐目的路由选择。
        auto_detect_interface: matches!(config.proxy_mode_type, ProxyModeType::Tun).then_some(true),
        final_outbound: Some(final_outbound),
    };

    // 【已删除：内置 DoH 泄漏域名 reject 表】
    // 曾在此处无条件 reject `dns.google` / `cloudflare-dns.com` / `doh.opendns.com` /
    // `dns.quad9.net` / `one.one.one.one` 的 443+853，并在下方再配一条 UDP443 拒 DoH-over-QUIC。
    // 两条都**没有任何开关**，属硬编码域名黑名单，2026-08-13 按用户裁定整块移除。
    //
    // ⚠️ 已知代价（如实记，不是遗漏）：浏览器自带的 DoH（Chrome/Firefox 安全 DNS）不再被强制打断
    // ⇒ 那部分查询绕开本应用的 hijack-dns / FakeIP 体系，基于域名的分流与 FakeIP 路由对它们不生效。
    // 判据是「屏蔽浏览器行为不是代理客户端的职责」——要拦由用户在浏览器侧关掉安全 DNS。
    // **禁止以任何形式重建无条件域名黑名单**，由 `no_builtin_domain_reject_table` 钉住。

    // 【浏览器内置 DoH 拦截】—— 用户开关驱动，默认关（`blockBrowserDoh`）。
    //
    // 与上面那张被删的表的区别只有一个，但那是全部区别：**用户能关**。清单也归用户
    // （`browserDohList`，未编辑则用 `DEFAULT_BROWSER_DOH_SUFFIXES` 起点）。
    //
    // 两条规则一起发、且都排在**自定义规则之前**：开关打开的语义是「这些端点一律不通」，
    // 若 QUIC 那条排在自定义规则之后，一条把该域名路由到代理的自定义规则就会让 DoH-over-QUIC
    // 漏过去 —— 用户开了开关却半通半不通，比不做更坏。
    // （旧实现正是这样：443/853 那条在前、UDP443 那条在后。这里是有意的行为收敛。）
    if config.block_browser_doh == Some(true) {
        let suffixes: Vec<String> = match config.browser_doh_list.as_ref() {
            // 用户编辑过 → 以用户的为准（空清单 = 用户清空了，等于不拦，尊重之）。
            Some(list) => list
                .iter()
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
            None => DEFAULT_BROWSER_DOH_SUFFIXES
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        };
        if !suffixes.is_empty() {
            // ① DoH(443) + DoT(853) 的 TCP 面。
            rules.push(RouteRule {
                domain_suffix: Some(suffixes.clone()),
                port: Some(OneOrMany::Many(vec![443, 853])),
                action: Some("reject".to_string()),
                ..empty_matcher()
            });
            // ② DoH-over-QUIC（UDP/443）。复用 udp443 工厂，与 blockQuic 同形。
            rules.push(udp443_reject_rule(RouteRule {
                domain_suffix: Some(suffixes),
                ..empty_matcher()
            }));
        }
    }

    // 排除全部代理节点的域名/IP，确保到任一节点的连接走直连（防回流死循环 + 兼容无缝切换/代理链）。
    {
        let mut ip_set: BTreeSet<String> = BTreeSet::new();
        let mut domain_set: BTreeSet<String> = BTreeSet::new();
        for s in &config.servers {
            let mut hosts: Vec<String> = Vec::new();
            if !s.address.is_empty() {
                hosts.push(s.address.clone());
            }
            if let Some(sn) = s
                .tls_settings
                .as_ref()
                .and_then(|t| t.server_name.as_deref())
            {
                if !sn.is_empty() {
                    hosts.push(sn.to_string());
                }
            }
            for host in &hosts {
                if is_ipv4_host(host) || is_ipv6_host(host) {
                    if let Some(cidr) = host_to_exclude_cidr(host) {
                        ip_set.insert(cidr);
                    }
                } else {
                    domain_set.insert(host.clone());
                }
            }
        }

        if !domain_set.is_empty() {
            let domains: Vec<String> = domain_set.into_iter().collect();
            let suffixes: Vec<String> = domains.iter().map(|d| format!(".{d}")).collect();
            rules.push(RouteRule {
                domain: Some(domains.clone()),
                domain_suffix: Some(suffixes),
                action: Some("route".to_string()),
                outbound: Some("direct".to_string()),
                ..empty_matcher()
            });
        }

        if !ip_set.is_empty() {
            rules.push(RouteRule {
                ip_cidr: Some(ip_set.into_iter().collect()),
                action: Some("route".to_string()),
                outbound: Some("direct".to_string()),
                ..empty_matcher()
            });
        }
    }

    // 0a. U盾/安全插件的本地伪域名 → override_address 强制 127.0.0.1。
    let ukey_local_domains: &[&str] = &[".microdone.cn"];
    let ukey_set: BTreeSet<&str> = ukey_local_domains.iter().copied().collect();
    let other_bank_domains: Vec<String> = DOMESTIC_BANK_AND_STOCK_DOMAINS
        .iter()
        .map(|s| s.to_string())
        .filter(|d| !ukey_set.contains(d.as_str()))
        .collect();

    rules.push(RouteRule {
        domain_suffix: Some(ukey_local_domains.iter().map(|s| s.to_string()).collect()),
        action: Some("route".to_string()),
        outbound: Some("direct".to_string()),
        override_address: Some("127.0.0.1".to_string()),
        ..empty_matcher()
    });

    // 0b. 其余银行/证券域名 → 普通 direct。
    if !other_bank_domains.is_empty() {
        rules.push(RouteRule {
            domain_suffix: Some(other_bank_domains),
            action: Some("route".to_string()),
            outbound: Some("direct".to_string()),
            ..empty_matcher()
        });
    }

    // WebRTC 防泄露：对嗅出的 STUN(UDP) 协议精确处理。
    if webrtc_leak == "proxy" && proxy_mode != "direct" && !config.servers.is_empty() {
        rules.push(RouteRule {
            protocol: Some("stun".to_string()),
            action: Some("route".to_string()),
            outbound: Some(selected_server_tag.to_string()),
            ..empty_matcher()
        });
    } else if webrtc_leak == "block" {
        rules.push(RouteRule {
            protocol: Some("stun".to_string()),
            action: Some("reject".to_string()),
            ..empty_matcher()
        });
    }

    // 2b. DNS 所有权下的连接域名解析（编译为 route action `resolve`）。
    //
    // # 位置为什么在这里
    //
    // 必须排在**探测/更新入站钉死路由（A2/A2b/A3）、节点域名排除、网银强制直连（0a/0b）、
    // bootstrap DNS 直连（C）之后** —— 那几类是终止规则，且它们的目的地绝不能先被解析成 IP
    // （探针要按域名钉出口、网银要按域名判直连）。
    // 又必须排在**自定义流量规则（块 3）之前** —— 自定义规则命中即 `break match`，排其后则 smart
    // 模式下永远走不到本条。两侧都是硬约束，不是 UI 所有权：用户配置位于 dnsDefaults，route
    // builder 只把它编译成 sing-box 所需的非终结动作。
    //
    // 无 matcher = 对本条之前未被终止的全部流量生效。裸 `{"action":"resolve"}` 经随包核
    // 1.14.0-beta.14 `check` rc=0（实测）。
    //
    // v4 起选择来自 dnsDefaults.connectionResolution，并在 smart/global/direct 三种模式一致生效。
    // 不能再因 direct/组网出口回退而静默跳过：用户选择的是“由 DNS 规则控制连接解析”，不是一条
    // 仅代理模式有效的性能提示。内部 Lookup 在固定核中以 allowFakeIP=false 运行，FakeIP 动作会被跳过
    // 并继续寻找真实解析器，因此这里必须保持 `server` 缺席，不能自造 FakeIP 旁路。
    // v1-v3 则继续保留旧的 direct/组网回退抑制，避免迁移前配置在只升级内核生成器时改变行为。
    let dns_owned_resolution = config.config_schema_version.unwrap_or(0) >= 4;
    let legacy_resolution_is_safe = proxy_mode != "direct" && !exit_fallback;
    if uses_dns_connection_resolution(config) && (dns_owned_resolution || legacy_resolution_is_safe)
    {
        rules.push(RouteRule {
            action: Some("resolve".to_string()),
            ..empty_matcher()
        });
    }

    // 3a. v1-v3 规则级 destinationResolution 兼容。v4 已把连接解析所有权收回 DNS 默认策略，
    // trafficRules 不再生成逐规则 resolve；旧 schema 仍保留原行为，供迁移前配置与备份归一化使用。
    let legacy_rule_resolution = config.config_schema_version.unwrap_or(0) < 4;
    let custom_deps = CustomRulesDeps {
        runtime_rules_dir: deps.runtime_rules_dir.clone(),
        rule_resources_path: deps.rule_resources_path.clone(),
        custom_rules_dir: deps.custom_rules_dir.clone(),
        arch: deps.arch.clone(),
        platform: deps.platform.clone(),
        is_valid_srs_fn: deps.is_valid_srs_fn,
        exists_fn: crate::builder::custom_rule_files::ext_rule_file_exists,
        log: deps.log,
    };
    let custom_rules_for_build: Vec<_> = ordered_route_rules
        .iter()
        .filter(|rule| {
            rule.enabled
                && ((legacy_rule_resolution
                    && rule.effects.as_ref().is_some_and(|effects| {
                        effects.route.as_ref().is_some_and(|route| {
                            route.enabled && route.destination_resolution.is_some()
                        })
                    }))
                    || (proxy_mode == "smart" && rule.route_action().is_some()))
        })
        .cloned()
        .collect();
    let custom_result = build_custom_rules(
        &custom_rules_for_build,
        config.selected_server_id.as_deref(),
        id_to_tag_map,
        selected_server_tag,
        &config.rule_resources,
        uses_fake_ip(
            config
                .dns_config
                .as_ref()
                .and_then(|dns| dns.enable_fake_ip),
        ),
        &custom_deps,
    );
    if legacy_rule_resolution {
        rules.extend(custom_result.resolve_rules.iter().cloned());
    }
    if !custom_result.rule_sets.is_empty() {
        let rs = route_config.rule_set.get_or_insert_with(Vec::new);
        rs.extend(custom_result.rule_sets.iter().cloned());
    }

    // 3b. 终结流量动作 + 应用分流仍仅 smart 模式生效。
    if proxy_mode == "smart" {
        let custom_rules = custom_result.rules;

        // 走代理的自定义规则同样要配对 udp443 reject。逐条插入：
        for cr in &custom_rules {
            // 阻断规则迁到 `action:"reject"` 后已无 outbound（`apply_rule_action` 是自定义规则
            // outbound 的唯一产地），故此处**不再**排 `"block"` 字面量 —— 留着只会让人以为
            // 规则还能指向 block 出站。`action != "route"` 这一项已把 reject 规则挡在外面。
            let is_proxy_out = cr.action.as_deref() == Some("route")
                && cr
                    .outbound
                    .as_deref()
                    .map(|o| o != "direct")
                    .unwrap_or(false);
            if is_proxy_out && block_proxy_quic {
                if cr.type_field.as_deref() == Some("logical") {
                    // logical 规则顶层不接受 network/port → 再套一层 AND logical。
                    rules.push(RouteRule {
                        action: Some("reject".to_string()),
                        type_field: Some("logical".to_string()),
                        mode: Some("and".to_string()),
                        rules: Some(vec![
                            RouteRule {
                                type_field: Some("logical".to_string()),
                                mode: cr.mode.clone(),
                                rules: cr.rules.clone(),
                                ..empty_matcher()
                            },
                            RouteRule {
                                network: Some(vec!["udp".to_string()]),
                                port: Some(OneOrMany::Many(vec![443])),
                                ..empty_matcher()
                            },
                        ]),
                        ..empty_matcher()
                    });
                } else if let Some(matcher) = extract_udp443_matcher(cr) {
                    rules.push(udp443_reject_rule(matcher));
                }
            }
            rules.push(cr.clone());
        }

        // 排除进程：兼容旧配置的兜底（新数据已由 ConfigManager 迁移为 customRules 的 processName+direct 规则）。
        if let Some(bypass_processes) = config.bypass_processes.as_deref() {
            if !bypass_processes.is_empty() {
                rules.push(RouteRule {
                    process_name: Some(OneOrMany::Many(bypass_processes.to_vec())),
                    action: Some("route".to_string()),
                    outbound: Some("direct".to_string()),
                    ..empty_matcher()
                });
            }
        }

        // 应用分流规则（真·应用分流，基于进程名）。
        for app_rule in &app_rules_eff {
            if !app_rule.enabled {
                continue;
            }
            let preset = match get_app_preset(&app_rule.app_id, &config.custom_app_presets) {
                Some(p) => p,
                None => continue,
            };

            // 确定动作 + 出站方式。阻断走**规则级** `action:"reject"`（sing-box 1.11+ 官方替代
            // legacy `block` 出站，口径与 `custom_rules::apply_rule_action` 同一份，见那里的函数文档）
            // ⇒ 无 outbound 可指。其余走 `action:"route"` + 出站 tag。
            let (rule_action, outbound) = match app_rule.action {
                RuleAction::Proxy => ("route", Some(format!("rule-sel-app-{}", app_rule.app_id))),
                RuleAction::Block => ("reject", None),
                RuleAction::Direct => ("route", Some("direct".to_string())),
            };
            // `no_drop:true` 只给阻断腿（关掉 50 次/30s 泛洪降级，与 legacy `block` 出站等价；
            // 判据见 `singbox::RouteRule::no_drop`）。route 腿带上它是无意义字段，故按 action 分。
            let app_no_drop = matches!(app_rule.action, RuleAction::Block).then_some(true);
            // 「出站是代理」直接判枚举：此前由 outbound 字面量反推（`!= direct && != block`），
            // 迁移后 Block 已无 outbound，反推会把它误判成代理 ⇒ 给阻断规则白配一条 udp443 reject。
            let app_out_is_proxy = matches!(app_rule.action, RuleAction::Proxy);

            // a. 基于进程名的规则（最精准）。
            if !preset.process_names.is_empty() {
                if app_out_is_proxy {
                    if let Some(r) = proxy_udp_reject_for(RouteRule {
                        process_name: Some(OneOrMany::Many(preset.process_names.clone())),
                        ..empty_matcher()
                    }) {
                        rules.push(r);
                    }
                }
                rules.push(RouteRule {
                    process_name: Some(OneOrMany::Many(preset.process_names.clone())),
                    action: Some(rule_action.to_string()),
                    outbound: outbound.clone(),
                    no_drop: app_no_drop,
                    ..empty_matcher()
                });
            }

            // b. 基于原有 rule_set 的规则（兜底，基于域名/IP 识别）。tag 小写对齐。
            let mut rule_sets: Vec<String> = Vec::new();
            for tag in &preset.geosite_tags {
                rule_sets.push(format!("geosite-{}", tag.to_ascii_lowercase()));
            }
            for tag in &preset.geoip_tags {
                rule_sets.push(format!("geoip-{}", tag.to_ascii_lowercase()));
            }

            if !rule_sets.is_empty() {
                if app_out_is_proxy {
                    if let Some(r) = proxy_udp_reject_for(RouteRule {
                        rule_set: Some(OneOrMany::Many(rule_sets.clone())),
                        ..empty_matcher()
                    }) {
                        rules.push(r);
                    }
                }
                rules.push(RouteRule {
                    rule_set: Some(OneOrMany::Many(rule_sets)),
                    action: Some(rule_action.to_string()),
                    outbound: outbound.clone(),
                    no_drop: app_no_drop,
                    ..empty_matcher()
                });
            }
        }
    }

    // ===== 用户规则之后的功能性强制路由（reorder：原在用户规则之上，现下移）=====
    // 0c. endpoint 节点（WireGuard/Tailscale）的「配置路由段」强制路由到该节点自身 tag。
    {
        let emitted_endpoint_tags: BTreeSet<String> = deps
            .pending_endpoints
            .iter()
            .map(|e| e.tag.clone())
            .collect();
        let mut claimed_cidrs: BTreeSet<String> = BTreeSet::new();
        let mut force_route_conflicts = 0u32;
        for s in &config.servers {
            let tag = match id_to_tag_map.get(&s.id) {
                Some(t) => t.clone(),
                None => continue,
            };
            if !emitted_endpoint_tags.contains(&tag) {
                continue;
            }
            if !should_force_route_subnets(
                s,
                config.selected_server_id.as_deref(),
                &rule_targeted_server_ids,
            ) {
                continue;
            }
            // preferred_by 适用：非全隧道 +（WG 恒 | TS 试点开）。
            let use_preferred_by = !mesh_node_carries_full_tunnel(s)
                && (s.protocol == Protocol::Wireguard
                    || (s.protocol == Protocol::Tailscale && TS_PREFERRED_BY_TRIAL));
            if use_preferred_by {
                rules.push(RouteRule {
                    preferred_by: Some(vec![tag.clone()]),
                    action: Some("route".to_string()),
                    outbound: Some(tag),
                    ..empty_matcher()
                });
                continue;
            }
            // 否则（全隧道节点 / TS 试点未开）：手动 ip_cidr force-route（去 0/0 + 跨节点 first-match 去重）。
            let cidrs: Vec<String> = endpoint_forced_route_cidrs(s)
                .into_iter()
                .filter(|c| {
                    if claimed_cidrs.contains(c) {
                        force_route_conflicts += 1;
                        false
                    } else {
                        claimed_cidrs.insert(c.clone());
                        true
                    }
                })
                .collect();
            if !cidrs.is_empty() {
                rules.push(RouteRule {
                    ip_cidr: Some(cidrs),
                    action: Some("route".to_string()),
                    outbound: Some(tag),
                    ..empty_matcher()
                });
            }
        }
        if force_route_conflicts > 0 {
            (deps.log)(LogLevel::Warn, &format!(
                "{force_route_conflicts} 个 endpoint 路由段被多个节点重复声明，已按节点顺序去重（先声明者生效）"
            ));
        }
    }

    // 1. 私有 IP 段直连。仅当用户未关闭"绕过局域网"时添加。
    if config.bypass_lan != Some(false) {
        // FakeIP 护栏：剔除与 fakeip 假 IP 段相交的旁路条目。
        let mut fakeip_ranges: Vec<String> = Vec::new();
        if uses_fake_ip(config.dns_config.as_ref().and_then(|d| d.enable_fake_ip)) {
            fakeip_ranges.push(FAKEIP_INET4_RANGE.to_string());
            if config.enable_ipv6 == Some(true) {
                fakeip_ranges.push(FAKEIP_INET6_RANGE.to_string());
            }
        }
        let bypass_cfg = UConfigBypass(config);
        let bypass_list = effective_bypass_lan(&bypass_cfg);
        let (overlapping, bypass_cidrs) =
            partition_cidrs_by_overlap(&bypass_lan_cidrs(&bypass_list), &fakeip_ranges);
        if !overlapping.is_empty() {
            (deps.log)(
                LogLevel::Warn,
                &format!(
                    "旁路局域网清单含与 FakeIP 段({})相交的条目，已剔除以免假 IP 被当私网直连：{}",
                    fakeip_ranges.join(", "),
                    overlapping.join(", ")
                ),
            );
        }
        if !bypass_cidrs.is_empty() {
            rules.push(RouteRule {
                ip_cidr: Some(bypass_cidrs),
                action: Some("route".to_string()),
                outbound: Some("direct".to_string()),
                ..empty_matcher()
            });
        }
        // 私有/本地域名直连（geosite-private，补 ip_cidr 的域名盲区）。仅在本地 .srs 有效时加规则。
        // 必须 proxyMode !== 'direct'（与 rule_set 定义注入块同门控）。
        if proxy_mode != "direct" {
            let private_path =
                format!("{}/{PRIVATE_DOMAIN_DIRECT_TAG}.srs", deps.runtime_rules_dir);
            if (deps.is_valid_srs_fn)(&private_path) {
                rules.push(RouteRule {
                    rule_set: Some(OneOrMany::One(PRIVATE_DOMAIN_DIRECT_TAG.to_string())),
                    action: Some("route".to_string()),
                    outbound: Some("direct".to_string()),
                    ..empty_matcher()
                });
            }
        }
    }

    // ICMP 兜底：放在 mesh force-route(块 0c) + bypass-LAN 之后，恒走 direct。
    rules.push(RouteRule {
        network: Some(vec!["icmp".to_string()]),
        action: Some("route".to_string()),
        outbound: Some("direct".to_string()),
        ..empty_matcher()
    });

    // 【DNS 死循环防范】：sing-box 本地 DNS 解析器的请求必须强制直连。
    rules.push(RouteRule {
        protocol: Some("dns".to_string()),
        action: Some("route".to_string()),
        outbound: Some("direct".to_string()),
        ..empty_matcher()
    });

    rules.push(RouteRule {
        ip_cidr: Some(
            DOH_UPSTREAM_IPS
                .iter()
                .map(|ip| format!("{ip}/32"))
                .collect(),
        ),
        port: Some(OneOrMany::Many(vec![53, 443])),
        action: Some("route".to_string()),
        outbound: Some("direct".to_string()),
        ..empty_matcher()
    });

    rules.push(RouteRule {
        domain_suffix: Some(vec!["doh.pub".to_string()]),
        action: Some("route".to_string()),
        outbound: Some("direct".to_string()),
        ..empty_matcher()
    });

    // 【已删除：Chrome/Edge 后台 beacon 域名黑名单】
    // 曾无条件（`proxy_mode != "direct"` 即发射）reject 14 个 Google 域名。整块移除，不留缩表版本。
    //
    // 逐条独立成立的删除依据：
    //  ① **注释与代码从第一天就相反**：注释写「强制直连」，代码写 `action: "reject"` —— 该块未被复核。
    //  ② **代价已实测、收益从未证**：`clients2.google.com` 是扩展商店 CRX 的更新与下载端点，被 reject
    //     后「添加至 Chrome」必失败；`update.googleapis.com`（Chrome 永不自升级）、
    //     `oauthaccountmanager.googleapis.com`（账号登录/令牌刷新）、`mtalk.google.com`（FCM 推送）
    //     三处均为静默功能损失。而「耗尽连接池导致全站超时」这个立表理由无复现、无测试。
    //  ③ 严格按「掉了无用户可见损失」筛完只剩两条纯遥测，收益不可感知而策略却是硬编码不可关。
    //  ④ 屏蔽遥测不是代理客户端的职责（用户侧 uBlock/hosts 才是），代客户决定属越界。
    //
    // 删除后这些域名与其它 Google 域名同等对待：smart 落 geosite 分类，global 走 final。
    // 若「过一会就断网」的原始症状再现，那是节点侧（UDP 中继 / mux / DNS）问题，本表此前恰恰掩盖了它。

    // 智能分流的「地区分流」geo 基线层（仅 smart + region.enabled）。
    if proxy_mode == "smart" && region.enabled {
        let local_geo = region_local_geo(&region.region);
        let foreign_geo = region_foreign_geo(&region.region);
        // 正向：本地直连·海外代理；反向（如回国）：本地代理·海外直连。
        let local_out = if region.reverse {
            user_exit_tag
        } else {
            "direct"
        };
        let foreign_out = if region.reverse {
            "direct"
        } else {
            user_exit_tag
        };
        // 「→代理」的那一侧才在其前配对「代理向 UDP reject」（exitFallback 回退 direct 时不配对）。
        let foreign_to_proxy = !region.reverse;
        let local_to_proxy = region.reverse;

        // 海外/Google 一类。Google 关键词兜底对所有地区一致。
        let google_keywords = vec![
            "google".to_string(),
            "gmail".to_string(),
            "youtube".to_string(),
            "gstatic".to_string(),
            "googleapis".to_string(),
            "googlevideo".to_string(),
        ];
        // 海外侧。
        if foreign_to_proxy && !exit_fallback {
            if let Some(r) = proxy_udp_reject_for(RouteRule {
                domain_keyword: Some(google_keywords.clone()),
                ..empty_matcher()
            }) {
                rules.push(r);
            }
        }
        rules.push(RouteRule {
            domain_keyword: Some(google_keywords),
            action: Some("route".to_string()),
            outbound: Some(foreign_out.to_string()),
            ..empty_matcher()
        });
        for tag in &foreign_geo {
            if foreign_to_proxy && !exit_fallback {
                if let Some(r) = proxy_udp_reject_for(RouteRule {
                    rule_set: Some(OneOrMany::One(tag.clone())),
                    ..empty_matcher()
                }) {
                    rules.push(r);
                }
            }
            rules.push(RouteRule {
                rule_set: Some(OneOrMany::One(tag.clone())),
                action: Some("route".to_string()),
                outbound: Some(foreign_out.to_string()),
                ..empty_matcher()
            });
        }

        // 本地侧（geosite + geoip）。
        if let Some(local) = &local_geo {
            for tag in &local.geosite {
                if local_to_proxy && !exit_fallback {
                    if let Some(r) = proxy_udp_reject_for(RouteRule {
                        rule_set: Some(OneOrMany::One(tag.clone())),
                        ..empty_matcher()
                    }) {
                        rules.push(r);
                    }
                }
                rules.push(RouteRule {
                    rule_set: Some(OneOrMany::One(tag.clone())),
                    action: Some("route".to_string()),
                    outbound: Some(local_out.to_string()),
                    ..empty_matcher()
                });
            }
            for tag in &local.geoip {
                if local_to_proxy && !exit_fallback {
                    if let Some(r) = proxy_udp_reject_for(RouteRule {
                        rule_set: Some(OneOrMany::One(tag.clone())),
                        ..empty_matcher()
                    }) {
                        rules.push(r);
                    }
                }
                rules.push(RouteRule {
                    rule_set: Some(OneOrMany::One(tag.clone())),
                    action: Some("route".to_string()),
                    outbound: Some(local_out.to_string()),
                    ..empty_matcher()
                });
            }
        }
    }

    // 添加 rule_set（除非是直连模式）。直连模式下不需要 rule_set，因为全部走 direct。
    if proxy_mode != "direct" {
        let rs = route_config.rule_set.get_or_insert_with(Vec::new);
        let runtime_dir = &deps.runtime_rules_dir;
        // 地区分流：未激活地区的 geo 不注入 rule_set。
        let mut inactive_region_geo_tags: BTreeSet<String> = BTreeSet::new();
        for rid in ["ir", "ru"] {
            if !region.enabled || region.region != rid {
                if let Some(g) = region_local_geo(rid) {
                    for t in &g.geosite {
                        inactive_region_geo_tags.insert(t.clone());
                    }
                    for t in &g.geoip {
                        inactive_region_geo_tags.insert(t.clone());
                    }
                }
            }
        }
        // 随包播种目录里已定义的 tag（供下面的「规则资源页副本」回落腿去重）。
        let mut builtin_defined: BTreeSet<String> = rs.iter().map(|r| r.tag.clone()).collect();
        for rs_entry in builtin_geo_rulesets() {
            if inactive_region_geo_tags.contains(&rs_entry.tag) {
                continue;
            }
            let file_path = format!("{runtime_dir}/{}", rs_entry.file_name);
            // 缺失/损坏即跳过：不引用不存在的本地文件（否则 sing-box initialize rule-set FATAL）。
            if (deps.is_valid_srs_fn)(&file_path) {
                builtin_defined.insert(rs_entry.tag.clone());
                rs.push(RuleSet {
                    tag: rs_entry.tag,
                    type_field: "local".to_string(),
                    format: "binary".to_string(),
                    path: Some(file_path),
                    url: None,
                    http_client: None,
                    update_interval: None,
                });
                continue;
            }
            // 随包播种缺失/损坏 → **回落「规则资源」页下载的本地副本**（`<userData>/rule-resource/`）。
            //
            // 不做这条，给用户的指引就是死路：剪枝 warn 与 `RULE_RESOURCES_MISSING` 都写「请到「规则资源」
            // 页下载后重连恢复」，而下载腿一律落 `rule-resource/`、内置 geo 基线却只读 `rules/` ⇒ 用户
            // 照着做、下载成功、再连仍被剪。选这条而非「让文案改口叫用户重置内置/重启重新播种」的理由：
            // 播种失败最常见的成因恰是**随包 `.srs` 本身缺失/损坏**（异常打包），那时重播多少次都没用，
            // 只有下载能救；而 catalog id 与 builtin tag **本就同形**（`rule_resource_catalog.rs` 模块头
            // 明记「同 id ⇒ 下载副本与随包项自然去重」），回落走的是既有机制，不新造第二套。
            add_local_geo_rule_set(&rs_entry.tag, rs, &mut builtin_defined, config, deps);
        }
    }

    // 添加自定义规则和应用分流所需的 Geosite/GeoIP rule_set。
    let (custom_geosite_categories, custom_geoip_categories) = get_required_geo_categories(
        &custom_rules_for_build,
        &app_rules_eff,
        &config.custom_app_presets,
    );

    // fail-closed：自定义规则 / 应用分流引用的 geo 统一由「规则资源」管理。
    if !custom_geosite_categories.is_empty() || !custom_geoip_categories.is_empty() {
        let rs = route_config.rule_set.get_or_insert_with(Vec::new);
        // 已有本地定义（随包内置已在上方注入）→ 跳过；否则用规则资源页的本地副本；再否则缺失（不注入，末尾剪枝）。
        let mut defined_tags: BTreeSet<String> = rs.iter().map(|r| r.tag.clone()).collect();
        let rs_vec = route_config.rule_set.as_mut().unwrap();
        let mut all_tags: Vec<String> = custom_geosite_categories
            .iter()
            .map(|c| format!("geosite-{c}"))
            .chain(custom_geoip_categories.iter().map(|c| format!("geoip-{c}")))
            .collect();
        for tag in &all_tags {
            add_local_geo_rule_set(tag, rs_vec, &mut defined_tags, config, deps);
        }
        all_tags.clear();
        let _ = all_tags;
    }

    // 【代理向 QUIC 兜底】：放在所有直连/分流规则之后，拦截"会落到 final(代理)"的剩余 QUIC(udp443)。
    if block_proxy_quic {
        rules.push(udp443_reject_rule(empty_matcher()));
    }

    // rule_set 按 tag 去重（保留首次=本地 .srs 优先于远程）。
    if let Some(rs) = route_config.rule_set.as_mut() {
        if !rs.is_empty() {
            let mut seen_tags: BTreeSet<String> = BTreeSet::new();
            rs.retain(|r| seen_tags.insert(r.tag.clone()));
        }
    }

    // fail-closed 兜底：剪掉引用「未定义 rule_set tag」的路由规则。
    let mut pruned_rule_set_tags: Vec<String> = Vec::new();
    let mut rules = {
        let defined_tags: BTreeSet<String> = route_config
            .rule_set
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|r| r.tag.clone())
            .collect();
        let mut referenced: BTreeSet<String> = BTreeSet::new();
        collect_refs(&rules, &mut referenced);
        let dangling: Vec<String> = referenced
            .iter()
            .filter(|t| !defined_tags.contains(*t))
            .cloned()
            .collect();
        if dangling.is_empty() {
            rules
        } else {
            // applyRuleSetPrune 操作整个 SingBoxConfig.route；这里构造只含 route 的壳（其它必填字段用最小值）。
            let mut singbox = crate::singbox::SingBoxConfig {
                log: crate::singbox::LogConfig {
                    level: "info".to_string(),
                    timestamp: false,
                    output: None,
                    disabled: None,
                },
                dns: None,
                inbounds: vec![],
                outbounds: vec![],
                endpoints: None,
                route: Some(RouteConfig {
                    rule_set: route_config.rule_set.clone(),
                    rules,
                    default_domain_resolver: None,
                    auto_detect_interface: None,
                    final_outbound: None,
                }),
                experimental: None,
                services: None,
            };
            let dangling_set: BTreeSet<String> = dangling.iter().cloned().collect();
            apply_rule_set_prune(&mut singbox, &dangling_set);
            // 回填剪枝后的 rules/rule_set。
            if let Some(r) = singbox.route.take() {
                route_config.rule_set = r.rule_set;
                // **warn 而非 info**：这是「用户以为在分流、实则整段规则被剪掉」的唯一告知。上游侧同为
                // `deps.log('warn', …)`（`route-builder.ts:895`）；Polaris 早先恒 info，被日志级别过滤吞掉后
                // 真机上「全量直连」只剩 `rule_set=0` 一个裸数字可查。
                (deps.log)(LogLevel::Warn, &format!(
                    "规则资源：{} 缺少本地副本，已跳过引用它的规则以避免代理启动失败（在「规则资源」页下载后自动恢复；应用分流仍按进程名生效）",
                    dangling.join(", ")
                ));
                pruned_rule_set_tags = dangling;
                r.rules
            } else {
                Vec::new()
            }
        }
    };

    // 【T2 fail-safe】资源缺失把「→代理」的腿剪光 → `final` 绝不落 direct。
    //
    // 两条降级各自合理、叠加即 fail-open（真机 2026-07-20 全量明文直连的直接成因）：
    //   - 只有资源缺失：final=proxy-selector，最坏「全走代理」——浪费带宽，不泄露；
    //   - 只有 reverse（回国）：CN 规则把国内流量送代理、海外直连——设计语义；
    //   - 两者叠加：把流量送代理的那两条 rule_set 规则被剪光，final=direct 兜底 ⇒ **全部明文直连**。
    //
    // **判据是「剪枝后还有没有规则指向 `user_exit_tag`」，不是「有没有发生过剪枝」**：
    // 后者对**任意**悬空 tag 生效，会在「28 个内置 geo 全好、只有一条自定义规则引用了未下载的 geo
    // 分类」时误触发 —— 回国模式的 final 从 direct 被翻成 proxy-selector ⇒ **全部海外流量改走国内
    // 节点**，把「海外直连」的语义整体反转，而真正的「→代理」腿（`geosite-cn`/`geoip-cn`）根本完好、
    // 压根没有 fail-open。查「代理腿还在不在」才是这条 fail-safe 想守的东西（因，非果）。
    //
    // 射程另外两道边界：
    //   - `proxy_mode == "direct"` 是用户显式选的全直连，是意图不是降级，**必须保持 direct**；
    //   - `user_exit_tag == "direct"`（D4/D7 组网出口回退）时**无处可退** —— 写 direct 到 direct 是
    //     no-op，此时若照打「已回退为代理」就是日志说谎。故单独分流，改打「无法 fail-safe」。
    if !pruned_rule_set_tags.is_empty()
        && proxy_mode != "direct"
        && route_config.final_outbound.as_deref() == Some("direct")
    {
        if user_exit_tag == "direct" {
            // **必须先判**：出口本身就是 direct 时 `routes_to_exit(rules, "direct")` 问的是「有没有
            // 规则走直连」——恒真且与本判定无关。先分流出去，才不会把这条腿静默吞掉。
            (deps.log)(
                LogLevel::Warn,
                "规则资源缺失已导致分流规则被剪枝，但选中的组网节点已关闭外网访问、用户出口本身就是直连：无法回退为代理，本次流量将明文直连。请下载规则资源，或为该节点开启「允许访问外网」/改选其它节点",
            );
        } else if !routes_to_exit(&rules, user_exit_tag) {
            (deps.log)(
                LogLevel::Warn,
                "规则资源缺失已导致分流规则被剪枝，为避免退化成全量明文直连，默认出口已回退为代理（下载规则资源后自动恢复地区分流语义）",
            );
            route_config.final_outbound = Some(user_exit_tag.to_string());
        }
        // else：「→代理」的腿还活着（剪掉的是别的 tag）→ `final=direct` 仍是设计语义，**不动**。
        // 剪枝本身已在上面 warn 过，不重复告警。
    }

    // ── 出口选阻断：整体改写成规则级 reject ──────────────────────────────────────
    //
    // # 为什么不是「末尾加一条 reject」
    //
    // 所有「→代理」的规则都指向 `proxy-selector`，它们在末尾那条之前就把流量路由走了 ——
    // 只加末尾一条，smart 模式下「海外→代理」照样出网，用户选了阻断却半通。故必须**逐条改写**：
    // 凡出站是 `proxy-selector` 的规则一律变成 `action:"reject"` 且不带 outbound，再补一条
    // 无 matcher 的兜底（实测真核收 matcher-less reject，rc=0）。
    //
    // # 为什么不再走 block 出站
    //
    // 旧形态是 `proxy-selector.default = "block"` + 一个 `{type:"block"}` 出站。它买到的是
    // 「切出阻断可热切」（PUT selector default），代价是**阻断期间核对每条被拦连接打一行 ERROR**
    // （`outbound/block[block]: operation not permitted`），而 `log.level=warn` 过滤不掉它。
    // 本仓核日志是单文件 + 满则轮转一次（`.1`），持续刷 ERROR 会把之前的排障线索**挤出去** ——
    // 丢的不是观感是历史。`action:"reject"` 只在 DEBUG 打一行。
    //
    // 代价如实记：切出阻断（阻断→节点/直连）由热切退化为**整核重启**，因为规则集变了。
    // 切入阻断本来就是重启。这个取舍的依据是「持续吃掉排障历史」比「用户主动改变网络姿态时
    // 断一次连接」更坏。
    if exit_is_block {
        for r in rules.iter_mut() {
            if r.outbound.as_deref() == Some(PROXY_SELECTOR_TAG) {
                r.action = Some("reject".to_string());
                r.outbound = None;
            }
        }
        rules.push(RouteRule {
            action: Some("reject".to_string()),
            ..empty_matcher()
        });
        // final 必须是一个合法出站 tag，且此刻已不可达（上面那条无 matcher 的规则全命中）。
        // 指 direct 而不是 proxy-selector：万一将来有人把兜底那条删了，退化方向是「直连」而不是
        // 「静默走代理」—— 后者与用户选阻断的意图正相反。
        route_config.final_outbound = Some("direct".to_string());
    }

    // 回填最终 rules 到 route_config。
    route_config.rules = rules;
    RouteConfigOutcome {
        route: route_config,
        pruned_rule_set_tags,
    }
}

fn uses_dns_connection_resolution(config: &UserConfig) -> bool {
    let schema = config.config_schema_version.unwrap_or(0);
    if schema >= 4 {
        config.dns_defaults.as_ref().is_some_and(|defaults| {
            defaults.connection_resolution == crate::user_config::DnsConnectionResolution::DnsRules
        })
    } else if schema >= 2 {
        config.route_defaults.as_ref().is_some_and(|defaults| {
            defaults.destination_resolution
                == crate::user_config::DestinationResolutionMode::DnsRules
        })
    } else {
        config.resolve_before_dial == Some(true)
    }
}

// ===== 辅助函数 =====

/// 全默认（None）的 RouteRule matcher 骨架，便于 push 时用 `..empty_matcher()`。
fn empty_matcher() -> RouteRule {
    RouteRule {
        protocol: None,
        network: None,
        rule_set: None,
        domain: None,
        domain_suffix: None,
        domain_keyword: None,
        domain_regex: None,
        geosite: None,
        ip_cidr: None,
        source_ip_cidr: None,
        port: None,
        port_range: None,
        source_port: None,
        source_port_range: None,
        source_mac_address: None,
        source_hostname: None,
        process_name: None,
        process_path: None,
        process_name_not: None,
        inbound: None,
        action: None,
        outbound: None,
        server: None,
        no_drop: None,
        preferred_by: None,
        sniffer: None,
        rewrite_target: None,
        timeout: None,
        domain_resolver: None,
        override_address: None,
        tls_spoof: None,
        tls_spoof_method: None,
        type_field: None,
        mode: None,
        rules: None,
    }
}

/// UserConfig.proxy_mode (enum) → 小写字符串（smart/global/direct）。上游 `config.proxyMode.toLowerCase()`。
fn proxy_mode_str(config: &UserConfig) -> String {
    match config.proxy_mode {
        crate::user_config::ProxyMode::Smart => "smart",
        crate::user_config::ProxyMode::Global => "global",
        crate::user_config::ProxyMode::Direct => "direct",
    }
    .to_string()
}

/// addLocalGeo：已定义则跳过；内置播种目录优先、再查规则资源页本地副本，存在则注入 type:'local' 定义。
/// 缺失 → 不注入、不远程兜底 → 交末尾悬空引用剪枝（fail-closed）。上游 `addLocalGeo`。
pub(super) fn add_local_geo_rule_set(
    tag: &str,
    rs: &mut Vec<RuleSet>,
    defined_tags: &mut BTreeSet<String>,
    config: &UserConfig,
    deps: &RouteConfigDeps<'_>,
) {
    if defined_tags.contains(tag) {
        return;
    }
    // 随包内置优先；缺失/损坏时才回落规则资源页的本地副本。
    // 上面的全局播种块已先处理内置路径，此处仍要保留同一解析逻辑，供 DNS 在 direct
    // 模式下独立引用 geo rule_set 时复用，避免产生第二份定义真值。
    let local = find_builtin(tag)
        .map(|builtin| format!("{}/{}", deps.runtime_rules_dir, builtin.file_name))
        .filter(|path| (deps.is_valid_srs_fn)(path))
        .or_else(|| {
            config
                .rule_resources
                .iter()
                .find(|resource| resource.id == tag)
                .map(|resource| format!("{}/{}", deps.rule_resources_path, resource.file_name))
                .filter(|path| (deps.is_valid_srs_fn)(path))
        });
    if let Some(path) = local {
        rs.push(RuleSet {
            tag: tag.to_string(),
            type_field: "local".to_string(),
            format: "binary".to_string(),
            path: Some(path),
            url: None,
            http_client: None,
            update_interval: None,
        });
        defined_tags.insert(tag.to_string());
    }
}

/// D4/D7：选中的组网节点是否「关外网」→ 整体用户出口回退 direct。
/// 上游 `meshSelectedExitFallsBackToDirect`（`ui/src/domain/endpoint-routes.ts:447-453`）。
///
/// 判据 = 选中节点具备组网资格（[`is_mesh_node`]）且不承载全隧道（[`mesh_node_carries_full_tunnel`]）。
/// 2026-09 前这里是 `Wireguard | Tailscale` 协议字面量白名单，效果是「只走内网」这个语义在协议间不一致：
/// WireGuard 关 `allowInternet`、Tailscale 不选 exit node 都会兜底 direct，但 OpenVPN
/// （`meshRoutes` 非空、显式关 `redirectGateway`）被白名单挡住、不兜底——公网流量会进一个不承载
/// 公网的 endpoint 变成黑洞。产品决策：统一为「组网节点关外网就兜底走直连」，故把判据换成
/// `is_mesh_node`（与 TS 镜像同源：`Wireguard`/`Tailscale` 恒真，`Openconnect`/`OpenvpnClient`
/// 则要求 `meshRoutes` 非空——`meshRoutes` 为空时这两个协议不算组网节点，不进入本判据，行为不变）。
///
/// 已知且不打算消除的一处不对称：TS 镜像首行多一道 `proxyMode==='direct'` 早退，本函数没有。
/// Rust 侧由各调用点自行处理 `direct` 模式（如下面的 [`subscription_update_route_uses_proxy`]
/// 在调用本函数前已单独判过 `proxy_mode != ProxyMode::Direct`），两者当前不构成行为分歧。
///
/// pub：hotswitch.rs planHotSwitch 的 route 投影 guard 复用（选中节点 mesh 退回 direct 翻转 → 重启）。
pub fn mesh_selected_exit_falls_back_to_direct(config: &UserConfig) -> bool {
    let selected_id = match config.selected_server_id.as_deref() {
        Some(s) => s,
        None => return false,
    };
    let selected = match config.servers.iter().find(|s| s.id == selected_id) {
        Some(s) => s,
        None => return false,
    };
    is_mesh_node(selected) && !mesh_node_carries_full_tunnel(selected)
}

/// Whether traffic entering `subscription-update-in` can actually leave through a proxy node.
///
/// A running core and an allocated SOCKS port only prove that the local ingress exists. They do
/// not prove the route behind it is proxied: direct mode, either direct/block sentinel, an empty
/// selector, and a mesh exit without full-tunnel capability all end at `direct`. The command layer
/// uses this same predicate to enforce `subscriptionProxyPolicy="proxy"` before sending bytes.
pub fn subscription_update_route_uses_proxy(config: &UserConfig) -> bool {
    config.proxy_mode != ProxyMode::Direct
        && !is_direct_selection(config.selected_server_id.as_deref())
        && !is_block_selection(config.selected_server_id.as_deref())
        && !config.servers.is_empty()
        && !mesh_selected_exit_falls_back_to_direct(config)
}

/// 混合收集 Rule + AppRule 的 targetServerId（enabled && action==proxy && targetServerId）。
/// 上游 `collectRuleTargetedServerIds([...customRules, ...appRules])`。
fn collect_targeted_mixed(
    custom_rules: &[crate::user_config::rule::Rule],
    app_rules: &[AppRule],
) -> BTreeSet<String> {
    let mut ids = collect_rule_targeted_server_ids(custom_rules);
    for r in app_rules {
        if r.enabled && r.action == RuleAction::Proxy {
            if let Some(tid) = &r.target_server_id {
                ids.insert(tid.clone());
            }
        }
    }
    ids
}

/// 剪枝后是否**还有任何规则把流量送去用户出口**（= 代理腿是否幸存）。
///
/// T2 fail-safe 的判据。递归进 logical rules 的子规则（与 [`collect_refs`] 同一套遍历形态：
/// 只查一半就会在逻辑规则里漏判）。
///
/// 只认 `outbound == exit_tag` 这一种「送去代理」：指向**具体节点 tag**（自定义规则 targetServerId）
/// 的规则不算 —— 少算的方向是**多触发一次 fail-safe**（final 改成代理），安全侧；反过来漏触发才是
/// 明文直连。判据宁可保守。
///
/// **钉死内部入站的规则一律不算**（`inbound` 非空 ⇒ `probe-direct-in` / `probe-proxy-in` /
/// `probe-in-<k>` / `update-in`，`:272`–`:311` 四处，全是应用自己的测速与更新流量）。它们恒指向代理、
/// 与用户流量无关；算进来会让「用户流量的代理腿已被剪光」这个事实被自家探针**永久掩盖** ——
/// fail-safe 从此再不触发，正是它要防的那个 fail-open。此处**必须**留在判据里。
fn routes_to_exit(rules: &[RouteRule], exit_tag: &str) -> bool {
    rules.iter().any(|r| {
        if r.inbound.is_some() {
            return false;
        }
        r.outbound.as_deref() == Some(exit_tag)
            || r.rules
                .as_deref()
                .is_some_and(|sub| routes_to_exit(sub, exit_tag))
    })
}

/// 递归收集 rules 中所有 rule_set 引用（string/array/logical 递归）。上游 `collectRefs`。
fn collect_refs(rules: &[RouteRule], referenced: &mut BTreeSet<String>) {
    for rule in rules {
        if let Some(sub) = rule.rules.as_deref() {
            collect_refs(sub, referenced);
        }
        match &rule.rule_set {
            Some(OneOrMany::One(t)) => {
                referenced.insert(t.clone());
            }
            Some(OneOrMany::Many(arr)) => {
                for t in arr {
                    referenced.insert(t.clone());
                }
            }
            None => {}
        }
    }
}

/// u32 端口列表 → OneOrMany（1 个用 One，否则 Many），镜像 sing-box JSON 形态。
fn ports_to_one_or_many(ports: Vec<u32>) -> OneOrMany<u32> {
    if ports.len() == 1 {
        OneOrMany::One(ports.into_iter().next().unwrap())
    } else {
        OneOrMany::Many(ports)
    }
}

/// BypassConfig 适配器（UserConfig → effective_bypass_lan）。
struct UConfigBypass<'a>(&'a UserConfig);
impl<'a> crate::user_config::system_proxy_bypass::BypassConfig for UConfigBypass<'a> {
    fn bypass_lan(&self) -> Option<bool> {
        self.0.bypass_lan
    }
    fn bypass_lan_list(&self) -> Option<&[String]> {
        self.0.bypass_lan_list.as_deref()
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests;
