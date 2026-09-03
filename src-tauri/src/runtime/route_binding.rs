//! TUN 节点物理拨号的逐目的网卡规划。
//!
//! sing-box 的 `route.auto_detect_interface` 能原生跟随默认接口，但无法表达「节点 A 经 Wi-Fi、
//! 节点 B 经企业 VPN」这类偏离默认出口的逐目的路由。这里在 TUN 接管路由之前读取系统路由表：
//! 与默认出口一致的根保留原生自动探测，只有不同的根才以会话级 `bind_interface` 注入真正的物理
//! 拨号根；不写回用户配置，显式节点/订阅/全局策略仍优先。

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

// `RoutePrefix` / `RuntimeBindingPlan` 已下沉到 `polaris-platform-events`（E2②）。
//
// 这里**不再导出**：方案原本想用 `pub use` 让 `crate::runtime::route_binding::{…}` 这条路径上的
// 消费点一字不改，但 clippy 当场指出 `pub use … RoutePrefix` 在普通构建里是 unused ——
// 本模块自己已经不用它，而 Linux 上唯一的消费点是 `proxy.rs` 那条 `#[cfg(test)]` import。
// 也就是说那条再导出没有非测试消费者：留着就是拿一个 `#[allow]` 去盖真信号。
// 消费点改成直接 import 新 crate，依赖关系因此是诚实的。
use polaris_platform_events::RuntimeBindingPlan;

use polaris_config_engine::builder::endpoint_routes::{
    active_physical_root_ids, hot_switch_physical_root_ids,
};
use polaris_config_engine::builder::outbounds::effective_proxy_bind_interface;
use polaris_config_engine::user_config::app_config::UserConfig;
use polaris_config_engine::user_config::server_config::{Protocol, ServerConfig};
#[cfg(not(windows))]
use polaris_system_integration::route_ops::SystemRouteOps;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

const LOOKUP_TIMEOUT: Duration = Duration::from_millis(1_500);
const PLAN_BUDGET: Duration = Duration::from_secs(3);
const MAX_CONCURRENT_TARGETS: usize = 8;
#[derive(Debug, Clone, PartialEq, Eq)]
struct Candidate {
    server_id: String,
    host: String,
}

fn group_candidates_by_host(candidates: Vec<Candidate>) -> BTreeMap<String, Vec<String>> {
    let mut grouped = BTreeMap::<String, Vec<String>>::new();
    for candidate in candidates {
        grouped
            .entry(candidate.host)
            .or_default()
            .push(candidate.server_id);
    }
    grouped
}

/// 当前配置是否含至少一个需要在起核前判定“原生默认出口 / 特殊逐目的绑定”的物理拨号根。
/// 网络变化 watcher 用同一候选口径；是否真要重启再由本次 plan 的特殊绑定/未解析状态决定。
#[must_use]
pub fn needs_runtime_binding_plan(config: &UserConfig) -> bool {
    !hot_switch_runtime_binding_candidates(config).is_empty()
}

/// 当前配置里**正在承流**且需要自动逐目的规划的物理根。
///
/// 配置变更/热切保护门只消费本集合，不能改成 hot-switch 全集：订阅新增一个尚未选中的节点不应让
/// 当前内核重启。全集只由 [`plan_runtime_bindings`] 在起核前消费并记入 `covered_roots`。
/// 显式策略根不进入本集合；非 TUN 模式由 OS 原生路由接管。
#[must_use]
pub fn automatic_runtime_binding_root_ids(config: &UserConfig) -> BTreeSet<String> {
    runtime_binding_candidates_for_roots(config, active_physical_root_ids(config))
        .into_iter()
        .map(|candidate| candidate.server_id)
        .collect()
}

/// 在 TUN 接管系统路由之前生成会话级绑定。任何单目标失败都 fail-open：该节点继续使用 sing-box
/// `auto_detect_interface`；其余成功节点不受影响。整轮有硬预算，不能把坏 DNS/路由工具拖进冷启动关键路径。
pub async fn plan_runtime_bindings(config: &UserConfig) -> RuntimeBindingPlan {
    let candidates = hot_switch_runtime_binding_candidates(config);
    let covered_roots: BTreeSet<String> = candidates
        .iter()
        .map(|candidate| candidate.server_id.clone())
        .collect();
    let candidate_count = covered_roots.len();
    if candidate_count == 0 {
        return RuntimeBindingPlan::default();
    }
    let grouped = group_candidates_by_host(candidates);
    // 先把「每个根的探测目标」落成具名表，再在得出决策时逐个划掉。剩下的就是「不知道的是谁」，
    // 无论它是 DNS 失败、路由查询无果，还是整轮预算超时被 abort、根本没回过包。
    let mut unresolved_roots: BTreeMap<String, String> = grouped
        .iter()
        .flat_map(|(host, server_ids)| server_ids.iter().map(|id| (id.clone(), host.clone())))
        .collect();

    let allow_ipv6 = config.enable_ipv6 == Some(true);
    let limiter = Arc::new(Semaphore::new(MAX_CONCURRENT_TARGETS));
    let default_v4 = Arc::new(tokio::sync::OnceCell::<Option<String>>::new());
    let default_v6 = Arc::new(tokio::sync::OnceCell::<Option<String>>::new());
    let mut tasks = JoinSet::new();
    for (host, server_ids) in grouped {
        let limiter = Arc::clone(&limiter);
        let default_v4 = Arc::clone(&default_v4);
        let default_v6 = Arc::clone(&default_v6);
        tasks.spawn(async move {
            // 失败腿一律带着 server_ids 回来：用 `?` 早退等于把这些根的身份整个丢掉，只在
            // 计数里留下一个数字，下游再也无法判断某条路由前缀与它们是否相关。
            let Ok(_permit) = limiter.acquire_owned().await else {
                return RouteProbeOutcome::Unresolved { server_ids, host };
            };
            let Some(ip) = resolve_route_probe_ip(&host, allow_ipv6).await else {
                return RouteProbeOutcome::Unresolved { server_ids, host };
            };
            let decision = match query_route_interface(ip).await {
                Some(interface) if !interface.trim().is_empty() => {
                    let default_interface = match ip {
                        IpAddr::V4(_) => {
                            default_v4
                                .get_or_init(|| query_route_interface(DEFAULT_ROUTE_PROBE_V4))
                                .await
                        }
                        IpAddr::V6(_) => {
                            default_v6
                                .get_or_init(|| query_route_interface(DEFAULT_ROUTE_PROBE_V6))
                                .await
                        }
                    };
                    Some(classify_runtime_binding(
                        interface.trim(),
                        default_interface.as_deref(),
                    ))
                }
                _ => None,
            };
            RouteProbeOutcome::Resolved {
                server_ids,
                ip,
                decision,
            }
        });
    }

    let mut bindings = BTreeMap::new();
    let mut native_roots = BTreeSet::new();
    let mut probe_ips = BTreeMap::new();
    let collect = async {
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(RouteProbeOutcome::Resolved {
                    server_ids,
                    ip,
                    decision,
                }) => {
                    for server_id in server_ids {
                        probe_ips.insert(server_id.clone(), ip);
                        match decision.as_ref() {
                            Some(RuntimeBindingDecision::Bind(interface)) => {
                                bindings.insert(server_id.clone(), interface.clone());
                                unresolved_roots.remove(&server_id);
                            }
                            Some(RuntimeBindingDecision::Native) => {
                                unresolved_roots.remove(&server_id);
                                native_roots.insert(server_id);
                            }
                            // 目标 IP 有了但路由查询没结果：该根仍然无决策，留在未决集合里。
                            None => {}
                        }
                    }
                }
                Ok(RouteProbeOutcome::Unresolved { server_ids, host }) => {
                    log::warn!(
                        "TUN 逐目的网卡规划：`{host}` 未解析出探针 IP，{} 个根按未决处理（{}）",
                        server_ids.len(),
                        server_ids.join(",")
                    );
                }
                Err(_) => {}
            }
        }
    };
    if tokio::time::timeout(PLAN_BUDGET, collect).await.is_err() {
        // Drop/abort 等待中的异步任务；已进入 spawn_blocking 的系统查询自行在命令硬超时内收口。
        tasks.abort_all();
        log::warn!(
            "TUN 逐目的网卡规划超过 {}ms，已按已完成结果降级",
            PLAN_BUDGET.as_millis()
        );
    }
    log::info!(
        "TUN 逐目的网卡规划：候选 {candidate_count}，特殊路由绑定 {}，原生自动探测 {}，降级 {}",
        bindings.len(),
        native_roots.len(),
        unresolved_roots.len()
    );
    RuntimeBindingPlan {
        bindings,
        native_roots,
        covered_roots,
        probe_ips,
        unresolved_roots,
        candidate_count,
    }
}

/// 单个探测目标的规划结局。**没有「什么都不回」的腿**：任何失败都必须把 `server_ids` 带回来。
enum RouteProbeOutcome {
    Resolved {
        server_ids: Vec<String>,
        ip: IpAddr,
        decision: Option<RuntimeBindingDecision>,
    },
    Unresolved {
        server_ids: Vec<String>,
        host: String,
    },
}

const DEFAULT_ROUTE_PROBE_V4: IpAddr = polaris_system_integration::route_ops::PROBE_IP;
const DEFAULT_ROUTE_PROBE_V6: IpAddr = IpAddr::V6(std::net::Ipv6Addr::new(
    0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111,
));

#[derive(Debug, Clone, PartialEq, Eq)]
enum RuntimeBindingDecision {
    Bind(String),
    Native,
}

fn classify_runtime_binding(
    destination_interface: &str,
    default_interface: Option<&str>,
) -> RuntimeBindingDecision {
    let destination_interface = destination_interface.trim();
    match default_interface.map(str::trim) {
        Some(default_interface) if destination_interface == default_interface => {
            RuntimeBindingDecision::Native
        }
        // 默认出口不可读但节点逐目的路由可读时，保留已知的安全路径；把它误判成 native 可能让
        // sing-box 回退到另一张默认网卡。后续物理路由事件仍会触发一次重规划。
        _ => RuntimeBindingDecision::Bind(destination_interface.to_owned()),
    }
}

fn hot_switch_runtime_binding_candidates(config: &UserConfig) -> Vec<Candidate> {
    runtime_binding_candidates_for_roots(config, hot_switch_physical_root_ids(config))
}

fn runtime_binding_candidates_for_roots(
    config: &UserConfig,
    roots: BTreeSet<String>,
) -> Vec<Candidate> {
    if !config.proxy_mode_type.is_tun() {
        return Vec::new();
    }
    let by_id: BTreeMap<&str, &ServerConfig> = config
        .servers
        .iter()
        .map(|server| (server.id.as_str(), server))
        .collect();
    roots
        .into_iter()
        .filter_map(|id| {
            let server = by_id.get(id.as_str()).copied()?;
            if effective_proxy_bind_interface(server, config).is_some() {
                return None;
            }
            Some(Candidate {
                server_id: id,
                host: server_route_host(server)?,
            })
        })
        .collect()
}

fn server_route_host(server: &ServerConfig) -> Option<String> {
    let raw = match server.protocol {
        Protocol::Tailscale | Protocol::Tor => return None,
        Protocol::Openconnect => server.openconnect_settings.as_ref()?.server.as_deref()?,
        Protocol::OpenvpnClient => server.openvpn_client_settings.as_ref()?.server.as_deref()?,
        Protocol::Custom => server
            .custom_settings
            .as_ref()
            .and_then(|settings| settings.outbound.get("server"))
            .and_then(serde_json::Value::as_str)
            .filter(|server| !server.trim().is_empty())
            .or_else(|| (!server.address.trim().is_empty()).then_some(server.address.as_str()))?,
        _ => server.address.as_str(),
    };
    normalize_host(raw)
}

fn normalize_host(raw: &str) -> Option<String> {
    let mut value = raw.trim();
    if let Some((_, rest)) = value.split_once("://") {
        value = rest;
    }
    value = value.split('/').next().unwrap_or(value);
    value = value.rsplit('@').next().unwrap_or(value);
    if let Some(rest) = value.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        return (!host.is_empty()).then(|| host.to_owned());
    }
    if value.parse::<IpAddr>().is_ok() {
        return Some(value.to_owned());
    }
    if value.matches(':').count() == 1 {
        if let Some((host, port)) = value.rsplit_once(':') {
            if !host.is_empty() && port.parse::<u16>().is_ok_and(|port| port > 0) {
                value = host;
            }
        }
    }
    (!value.is_empty()).then(|| value.to_owned())
}

async fn resolve_route_probe_ip(host: &str, allow_ipv6: bool) -> Option<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        // `enableIPv6` 约束域名的 AAAA 选择，不得把用户明确填写的 IPv6 节点地址当成“不可解析”。
        // 字面量无需 DNS，且三平台路由 API 都支持按 v6 目的查询。
        return Some(ip);
    }
    let resolved = tokio::time::timeout(LOOKUP_TIMEOUT, tokio::net::lookup_host((host, 0)))
        .await
        .ok()?
        .ok()?;
    let mut first_v6 = None;
    for address in resolved {
        match address.ip() {
            ip @ IpAddr::V4(_) => return Some(ip),
            ip @ IpAddr::V6(_) if first_v6.is_none() => first_v6 = Some(ip),
            _ => {}
        }
    }
    allow_ipv6.then_some(first_v6).flatten()
}

async fn query_route_interface(ip: IpAddr) -> Option<String> {
    tokio::task::spawn_blocking(move || {
        #[cfg(windows)]
        {
            polaris_helper::platform::windows::wintun::best_route_interface_alias(ip).ok()
        }
        #[cfg(not(windows))]
        {
            polaris_system_integration::production_route_ops()
                .exit_interface_for(ip)
                .ok()
                .flatten()
        }
    })
    .await
    .ok()
    .flatten()
}

#[cfg(test)]
mod tests;
