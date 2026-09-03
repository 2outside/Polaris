//! TUN 逐目的绑定的跨平台网络变化归一化。
//!
//! Linux/Windows 能直接取得变化路由的目标前缀；macOS `route -n monitor` 把同一事件拆成
//! 事件头、`sockaddrs` 字段和地址值多行，必须在这里聚合。上层只消费统一 impact。
//!
//! 本模块 2026-08-30 从 `src-tauri/src/runtime/proxy/network_change.rs` 原样下沉（E2②）：
//! 它是纯文本解析，零 tokio、零 C 依赖，留在 src-tauri 就永远进不了跨目标检查。
//! 搬迁**不改任何语义** —— 逐行不变是「搬前搬后行为一致」这条证据的全部基础。

use std::collections::BTreeSet;

use polaris_helper_proto::Platform;

use crate::binding_plan::RuntimeBindingPlan;
use crate::route_prefix::RoutePrefix;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkChangeImpact {
    pub interface: bool,
    pub route: bool,
    pub route_prefixes: BTreeSet<RoutePrefix>,
    /// 事件源确认“路由变了”，但没有提供可判定的目标前缀。未知不能被误当作无关。
    pub route_unknown: bool,
}

impl NetworkChangeImpact {
    pub fn merge(&mut self, other: Self) {
        self.interface |= other.interface;
        self.route |= other.route;
        self.route_prefixes.extend(other.route_prefixes);
        self.route_unknown |= other.route_unknown;
    }
}

#[derive(Debug, Default)]
pub struct MacRouteMonitorParser {
    pending_route: Option<MacPendingRoute>,
}

#[derive(Debug)]
struct MacPendingRoute {
    fields: Vec<String>,
    host_route: bool,
}

#[derive(Debug, Default)]
pub struct NetworkMonitorUpdate {
    pub impact: Option<NetworkChangeImpact>,
    pub observed_event: bool,
}

impl MacRouteMonitorParser {
    pub fn push_line(
        &mut self,
        line: &str,
        managed_tun_interface: Option<&str>,
    ) -> NetworkMonitorUpdate {
        use polaris_system_integration::dns_route_events::{
            classify_route_monitor_line, RouteMonitorEvent,
        };

        match classify_route_monitor_line(line) {
            Some(RouteMonitorEvent::Interface) => {
                let mut impact = self.take_incomplete().unwrap_or_default();
                impact.interface = true;
                return NetworkMonitorUpdate {
                    impact: Some(impact),
                    observed_event: true,
                };
            }
            Some(RouteMonitorEvent::Route) => {
                let previous = self.take_incomplete();
                // 事件头行不含目标地址：`classify_route_monitor_line` 只按**首 token** 判型，而
                // `route -n monitor` 里带地址的只有 `sockaddrs:` 之后的地址值行（首 token 是地址，
                // 判型必然为 None）。两个条件互斥 ⇒ 曾经的「行内直接取前缀」分支在真实输出上永不
                // 触发，已删除（D11：未验证分支不留）。目标一律由下面的 pending 聚合路径取。
                self.pending_route = Some(MacPendingRoute {
                    fields: Vec::new(),
                    host_route: route_monitor_flags_contain(line, "HOST"),
                });
                return NetworkMonitorUpdate {
                    impact: previous,
                    observed_event: true,
                };
            }
            None => {}
        }

        let trimmed = line.trim();
        if trimmed.starts_with("got message of size") {
            return NetworkMonitorUpdate {
                impact: self.take_incomplete(),
                observed_event: false,
            };
        }
        let Some(pending) = self.pending_route.as_mut() else {
            return NetworkMonitorUpdate::default();
        };
        if let Some(fields) = mac_route_sockaddr_fields(trimmed) {
            pending.fields = fields;
            return NetworkMonitorUpdate::default();
        }
        if pending.fields.is_empty() || trimmed.is_empty() {
            return NetworkMonitorUpdate::default();
        }

        let pending = self
            .pending_route
            .take()
            .expect("pending route exists while parsing its address row");
        let values: Vec<&str> = trimmed.split_whitespace().collect();
        if mac_route_values_mention_interface(&pending.fields, &values, managed_tun_interface) {
            return NetworkMonitorUpdate::default();
        }
        NetworkMonitorUpdate {
            impact: Some(mac_route_impact(&pending, &values)),
            observed_event: true,
        }
    }

    pub fn take_incomplete(&mut self) -> Option<NetworkChangeImpact> {
        self.pending_route.take().map(|_| NetworkChangeImpact {
            route: true,
            route_unknown: true,
            ..Default::default()
        })
    }
}

fn route_monitor_flags_contain(line: &str, expected: &str) -> bool {
    line.split_once("flags:")
        .map(|(_, flags)| {
            flags
                .split(|character: char| {
                    character == '<'
                        || character == '>'
                        || character == ','
                        || character.is_whitespace()
                })
                .any(|flag| flag == expected)
        })
        .unwrap_or(false)
}

fn mac_route_sockaddr_fields(line: &str) -> Option<Vec<String>> {
    let fields = line.strip_prefix("sockaddrs:")?.trim();
    let fields = fields.strip_prefix('<')?.strip_suffix('>')?;
    Some(
        fields
            .split(',')
            .map(str::trim)
            .filter(|field| !field.is_empty())
            .map(str::to_owned)
            .collect(),
    )
}

fn mac_route_values_mention_interface(
    fields: &[String],
    values: &[&str],
    managed_tun_interface: Option<&str>,
) -> bool {
    let Some(interface) = managed_tun_interface.filter(|name| !name.trim().is_empty()) else {
        return false;
    };
    fields
        .iter()
        .zip(values)
        .filter(|(field, _)| field.as_str() == "IFP" || field.as_str() == "GATEWAY")
        .any(|(_, value)| {
            *value == interface
                || value
                    .strip_prefix(interface)
                    .is_some_and(|suffix| suffix.starts_with(':') || suffix.starts_with('%'))
        })
}

fn mac_route_impact(pending: &MacPendingRoute, values: &[&str]) -> NetworkChangeImpact {
    let value = |field: &str| {
        pending
            .fields
            .iter()
            .position(|candidate| candidate == field)
            .and_then(|index| values.get(index).copied())
    };
    let Some(destination) = value("DST") else {
        return NetworkChangeImpact {
            route: true,
            route_unknown: true,
            ..Default::default()
        };
    };
    if destination == "default" {
        return NetworkChangeImpact {
            route: true,
            ..Default::default()
        };
    }
    let destination = destination
        .split_once('%')
        .map_or(destination, |(address, _)| address);
    let Ok(destination) = destination.parse::<std::net::IpAddr>() else {
        return NetworkChangeImpact {
            route: true,
            route_unknown: true,
            ..Default::default()
        };
    };
    let prefix = match value("NETMASK") {
        Some("default") => RoutePrefix::new(destination, 0),
        Some(mask) => mask
            .split_once('%')
            .map_or(mask, |(address, _)| address)
            .parse::<std::net::IpAddr>()
            .ok()
            .and_then(|mask| RoutePrefix::from_netmask(destination, mask)),
        None if pending.host_route => {
            RoutePrefix::new(destination, if destination.is_ipv4() { 32 } else { 128 })
        }
        None => None,
    };
    match prefix {
        Some(prefix) => NetworkChangeImpact {
            route: true,
            route_prefixes: BTreeSet::from([prefix]),
            ..Default::default()
        },
        None => NetworkChangeImpact {
            route: true,
            route_unknown: true,
            ..Default::default()
        },
    }
}

fn linux_route_monitor_prefix(line: &str) -> (Option<RoutePrefix>, bool) {
    let Some(mut body) = line.trim().strip_prefix("[ROUTE]") else {
        return (None, false);
    };
    body = body.trim();
    if let Some(deleted) = body.strip_prefix("Deleted") {
        body = deleted.trim();
    }
    for token in body.split_whitespace() {
        let token = token.trim_matches(|character: char| character == ',' || character == ':');
        if token == "default" {
            // 默认出口由 sing-box auto_detect_interface 原生跟随；特殊逐目的绑定不会被 /0 覆盖。
            return (None, false);
        }
        if let Some(prefix) = RoutePrefix::parse(token) {
            return (Some(prefix), false);
        }
        if matches!(token, "dev" | "via" | "table" | "metric") {
            break;
        }
    }
    (None, true)
}

pub fn monitor_line_impact(
    platform: Platform,
    line: &str,
    managed_tun_interface: Option<&str>,
) -> Option<NetworkChangeImpact> {
    if managed_tun_interface
        .filter(|name| !name.trim().is_empty())
        .is_some_and(|name| monitor_line_mentions_interface(line, name))
    {
        return None;
    }
    match platform {
        Platform::Linux => {
            let trimmed = line.trim();
            if trimmed.starts_with("[ROUTE]") {
                let (prefix, route_unknown) = linux_route_monitor_prefix(trimmed);
                let mut impact = NetworkChangeImpact {
                    route: true,
                    route_unknown,
                    ..Default::default()
                };
                if let Some(prefix) = prefix {
                    impact.route_prefixes.insert(prefix);
                }
                Some(impact)
            } else if trimmed.starts_with("[LINK]") || trimmed.starts_with("[ADDR]") {
                Some(NetworkChangeImpact {
                    interface: true,
                    ..Default::default()
                })
            } else if trimmed.is_empty() || line.starts_with(char::is_whitespace) {
                // label 模式会续写 `link/none`、`valid_lft ...` 等缩进行；它们属于上一事件。
                None
            } else {
                // 老 iproute2/未知 label 输出不能静默漏掉网络变化；接口快照仍会做第二层去噪。
                Some(NetworkChangeImpact {
                    interface: true,
                    route: true,
                    route_unknown: true,
                    ..Default::default()
                })
            }
        }
        Platform::Mac => {
            match polaris_system_integration::dns_route_events::classify_route_monitor_line(line) {
                Some(
                    polaris_system_integration::dns_route_events::RouteMonitorEvent::Interface,
                ) => Some(NetworkChangeImpact {
                    interface: true,
                    ..Default::default()
                }),
                Some(polaris_system_integration::dns_route_events::RouteMonitorEvent::Route) => {
                    Some(NetworkChangeImpact {
                        route: true,
                        route_unknown: true,
                        ..Default::default()
                    })
                }
                None => None,
            }
        }
        Platform::Win | Platform::Other => None,
    }
}

fn monitor_line_mentions_interface(line: &str, interface: &str) -> bool {
    line.split_whitespace().any(|token| {
        token.trim_matches(|character: char| {
            matches!(character, '[' | ']' | '(' | ')' | ',' | ':' | ';')
        }) == interface
    })
}

/// 计划里**连探针 IP 都没有**的未决根是否存在。
///
/// 未决根有四类，只有两类真的没有 IP —— 这条区分就是 F12 的全部内容：
///
/// | 类 | 来源 | 有 `probe_ips` 吗 |
/// |----|------|------------------|
/// | ① DNS/探针解析失败 | `route_binding.rs` 的 `RouteProbeOutcome::Unresolved` 腿 | **没有** |
/// | ② 有 IP 但 `query_route_interface` 无果（`decision: None`） | `route_binding.rs` 收集腿 | **有** |
/// | ③ 整轮 `PLAN_BUDGET` 超时被 `abort_all` | 任务没回过包 | **没有** |
/// | ④ `retain_available` 因接口消失剔除的绑定 | `RuntimeBindingPlan::retain_available` | **有** |
///
/// ②④ 有 IP ⇒ 「这条前缀覆不覆盖它」是个可判定的事实，交给下面的 `probe_ips` 覆盖判定即可；
/// 只有 ①③ 是「连问都问不出来」，才必须把「不知道」诚实地读成「可能有关」。
///
/// **旧判据 `!unresolved_roots.is_empty()` 为什么是缺陷而不只是保守**：它把 ②④ 也算进「不可证」。
/// 订阅里只要有**一个**长期解析不了的域名，`unresolved_roots` 就永久非空（没有任何腿会对未决根
/// 重新发起解析），于是**任何**比 `/0` 具体的路由事件都判要重算 → `inferred_binding_replan_needed`
/// → `schedule_restart()`。那不是「多算一次」，是把客户端钉死在「路由表一动就整核重启」。
fn unresolved_roots_without_probe_ip(plan: &RuntimeBindingPlan) -> bool {
    plan.unresolved_roots
        .keys()
        .any(|server_id| !plan.probe_ips.contains_key(server_id))
}

pub fn route_replan_needed(impact: &NetworkChangeImpact, plan: &RuntimeBindingPlan) -> bool {
    if !impact.route {
        return false;
    }
    if impact.route_unknown {
        // 事件源确认「路由变了」却给不出前缀 ⇒ 它可以是**任何**前缀。诚实的答案只有一个：
        // 「存在某个具体前缀会让下面的已知腿判要重算吗」—— 即已知腿的**存在性闭包**，而不是
        // 另起一套更窄的判据。已知腿为真的充要条件是「有未决根拿不到 IP」或「某个具体前缀覆盖
        // 到某个 probe IP」，后者可满足**当且仅当** `probe_ips` 非空（取该 IP 的 /32 即可）。
        //
        // 旧判据 `!bindings.is_empty() || !unresolved_roots.is_empty()` 漏掉了全 native 的计划：
        // 同一份计划、同一条物理路由，事件源给出 `198.51.100.0/24` 就重算、给不出前缀就不重算 ——
        // 结论由**事件源的表达能力**决定而不是由事实决定，正是 F6 要治的沉默收窄留在 native 腿上。
        //
        // `bindings` 不必再单列：`route_binding.rs` 的收集腿在 match decision **之前**就
        // `probe_ips.insert`，`retain_available` 只缩 `bindings`、不动 `probe_ips`
        // ⇒ `bindings.keys() ⊆ probe_ips.keys()` 恒成立，写出来只是一段没有输入能证伪的宽度。
        return unresolved_roots_without_probe_ip(plan) || !plan.probe_ips.is_empty();
    }

    // `/0` 是默认出口本身，由 auto_detect_interface 原生跟随；未决根同样没有写 `bind_interface`、
    // 也在 auto_detect 之下，所以这一条对三类根一视同仁。只有比 /0 更具体、可能覆盖某个节点目标
    // 的路由才会让「原生 / 特殊绑定 / 未决」三种状态互相转换。
    let mut specific_prefixes = impact
        .route_prefixes
        .iter()
        .filter(|prefix| prefix.prefix_len() > 0)
        .peekable();
    if specific_prefixes.peek().is_none() {
        return false;
    }

    // ①③ 类未决根没有探针 IP ⇒ 没有任何事实能证明这条更具体的路由与它无关。把「不知道」读成
    // 「无关」是错的，那正是本条要治的沉默收窄；诚实的答案是重规划，代价是一次多余的重算。
    //
    // 这里也是后续收敛的挂载点：对未决根重新发起解析、成功后它离开 `unresolved_roots`，本分支
    // 自然不再触发；而不是靠调用方去猜「这个数字大概能忽略」。
    if unresolved_roots_without_probe_ip(plan) {
        return true;
    }

    specific_prefixes.any(|prefix| plan.probe_ips.values().any(|ip| prefix.contains(*ip)))
}

/// 去抖窗到期时，把本窗累计的事实交给 `ProxyRuntime::handle_network_change`（src-tauri 侧，跨 crate 不可达）的**唯一出口**。
///
/// 空 impact 不是一次网络变化：送进去会落到 `else` 腿做一次真实出口探测，并向前端广播一帧
/// pending 置空状态（用户可见「正在检测」闪一下）。F4 把 Windows 回调的唤醒移到锁外之后，读侧的
/// `take_pending()` 可能正落在某次回调 unlock 与 `try_send` 之间 ⇒ 下一轮去抖必然拿到全空 impact，
/// 这条腿从「不可能」变成「微秒级窗口内确定会发生」。
///
/// **为什么返回 `Option` 而不是让两个调用点各写一次 `if`**：mac/Linux 腿本来就有守卫、Windows 腿
/// 没有 —— 「同一个决定在两处各写一遍」正是它们能漂移的原因。收成一个返回 `Option` 的出口后，
/// 想跳过守卫就得显式 `unwrap_or_default()`，删守卫不再是「少写一行」。接线由
/// `every_watcher_debounce_leg_funnels_through_the_empty_impact_guard` 逐平台钉住。
pub fn debounced_network_change(impact: NetworkChangeImpact) -> Option<NetworkChangeImpact> {
    (impact != NetworkChangeImpact::default()).then_some(impact)
}

#[cfg(test)]
mod tests;
