//! macOS `route -n monitor` 输出行解析（纯函数，无副作用）。
//!
//! 1:1 移植自 上游 `dns-route-events.ts`。
//! 用途：[`crate::dns_watcher::DnsInterfaceWatcher`] 长驻 `route -n monitor`，逐行喂本函数判定
//! 「是否值得触发一次 DNS reconcile 的网络变更」。命中 → 去抖后调 reconcile。

#![forbid(unsafe_code)]

/// route monitor 中「值得触发 reconcile」的消息类型（前缀匹配，覆盖 RTM_IFINFO2 / RTM_NEWADDR2 变体）：
/// - IFINFO：接口 up/down（插拔网卡、Wi-Fi 开关、坞站上下线）。
/// - NEWADDR / DELADDR：接口地址增删（DHCP 续约、IPv6 SLAAC、VPN 虚拟地址）。
/// - ADD / DELETE：路由增删（默认路由切换 = 出口/解析器可能整体易主）。
const INTERFACE_RTM_TYPES: &[&str] = &["RTM_IFINFO", "RTM_NEWADDR", "RTM_DELADDR"];
const ROUTE_RTM_TYPES: &[&str] = &["RTM_ADD", "RTM_DELETE"];

/// 网络事件对运行时路由规划的影响。DNS 重灌只关心“是否命中”，TUN 逐目的绑定还需要区分
/// 接口事实变化与路由表变化：前者可由接口快照去噪，后者必须撤 TUN 后重新询问物理路由。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteMonitorEvent {
    Interface,
    Route,
}

/// 分类单行 `route -n monitor` 输出；不相关/畸形行返回 `None`。
#[must_use]
pub fn classify_route_monitor_line(line: &str) -> Option<RouteMonitorEvent> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with("got message of size") {
        return None;
    }
    let first_token = trimmed
        .split(|c: char| c.is_whitespace() || c == ':')
        .next()
        .unwrap_or("");
    if INTERFACE_RTM_TYPES
        .iter()
        .any(|kind| first_token == *kind || first_token.starts_with(kind))
    {
        return Some(RouteMonitorEvent::Interface);
    }
    if ROUTE_RTM_TYPES
        .iter()
        .any(|kind| first_token == *kind || first_token.starts_with(kind))
    {
        return Some(RouteMonitorEvent::Route);
    }
    None
}

/// 判定单行 `route -n monitor` 输出是否表示「值得触发 DNS reconcile 的网络变更」。
///
/// 命中：行首 token 为上述 RTM_ 触发类型（或其带数字后缀的变体）。
/// 不命中：统计头（`got message of size ...`）、地址/标志明细行、空行、畸形行。
/// 永不抛（Polaris 不变量）。上游 `isDnsReconcileTriggerLine`。
pub fn is_dns_reconcile_trigger_line(line: &str) -> bool {
    classify_route_monitor_line(line).is_some()
}

#[cfg(test)]
mod tests;
