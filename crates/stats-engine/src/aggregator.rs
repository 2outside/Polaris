//! stats 聚合 —— 上游 `StatsService.ts` 聚合算法 + `connections-aggregate.ts` 纯函数 1:1 移植。
//!
//! 两层：
//! 1. **纯函数聚合**（无状态）：[`trim_connection`]（gRPC → ConnectionEntry 裁剪）、
//!    [`aggregate_connections`]（连接导航排名）、[`project_connections_topology`]（首页动态投影）、
//!    [`aggregate_signature`]（change-driven 内容签名）。
//! 2. **有状态聚合器** [`StatsAggregator`]：移植 `StatsService` 的 connMap 维护
//!    （reset 清空 / NEW 加 / UPDATE 累加 delta + LRU / CLOSED 删 / OOM 上限驱逐）+ snapshot 更新。
//!
//! 不含 gRPC 流接收——帧经 [`StatsAggregator::on_status`] / [`StatsAggregator::on_connection_events`]
//! 注入。调用方（B5 stats actor）持有一个 tonic 流，把帧喂进来；订阅注册表/降流/重订阅在
//! [`crate::subscription`] / [`crate::resubscribe`]。
//!
//! 锚点（StatsService.ts）：
//! - [`StatsAggregator::on_status`] = onStatus（:305）：total 直取 server 值，**speed 由本地对 total
//!   差分 ÷ 实测 Δt 求得**（`Status.uplink/downlink` 不是速率，见该方法文档）。
//! - [`StatsAggregator::on_connection_events`] = onConnectionEvents（:339）：reset/NEW/UPDATE/CLOSED + OOM。
//! - [`trim_connection`] = trimConnection（:89）+ splitHostPort（:37）+ createdAtToRfc3339（:64）。
//! - [`aggregate_connections`] = aggregateConnections（connections-aggregate.ts:41）。
//! - [`aggregate_signature`] = aggregateSignature（connections-aggregate.ts:99）。

use polaris_config_engine::builder::is_probe_pool_inbound_tag;

use crate::types::{
    ConnectionAggFlow, ConnectionAggHost, ConnectionAggOutbound, ConnectionCounters,
    ConnectionEntry, ConnectionEventType, ConnectionMetadata, ConnectionsAggregate,
    SingBoxConnection, SingBoxConnectionEvent, SingBoxConnectionEvents, SingBoxStatus,
    TrafficStats, CONNECTION_RANKING_LIMIT, TOPOLOGY_OTHERS_KEY,
};

/// 一帧连接事件应用到活动表后的净变化。reset 不携带全量连接；中继仅在真正 emit
/// reset 基线时调用 [`StatsAggregator::entries`] 克隆一次最终表。
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ConnectionsDetailChange {
    pub reset: bool,
    pub upserts: std::collections::HashMap<String, ConnectionEntry>,
    pub counters: std::collections::HashMap<String, ConnectionCounters>,
    pub removed_ids: std::collections::HashSet<String>,
}

impl ConnectionsDetailChange {
    /// 拓扑只依赖连接集合与静态元数据；单纯 upload/download 计数变化不改变拓扑投影。
    #[must_use]
    pub fn affects_topology(&self) -> bool {
        self.reset || !self.upserts.is_empty() || !self.removed_ids.is_empty()
    }

    fn upsert(&mut self, entry: ConnectionEntry) {
        if self.reset {
            return;
        }
        let id = entry.id.clone();
        self.removed_ids.remove(&id);
        self.counters.remove(&id);
        self.upserts.insert(id, entry);
    }

    fn update_counters(&mut self, counters: ConnectionCounters) {
        if self.reset {
            return;
        }
        if let Some(entry) = self.upserts.get_mut(&counters.id) {
            entry.upload = Some(counters.upload);
            entry.download = Some(counters.download);
            return;
        }
        self.removed_ids.remove(&counters.id);
        self.counters.insert(counters.id.clone(), counters);
    }

    fn remove(&mut self, id: String) {
        if self.reset {
            return;
        }
        self.upserts.remove(&id);
        self.counters.remove(&id);
        self.removed_ids.insert(id);
    }
}

/// OOM 安全网（StatsService.ts:24 `MAX_CONN_MAP_SIZE`）：sing-box 系统性漏发 CLOSED（UDP/QUIC NAT 超时回收高发）
/// 时 connMap 漏删条目单调累积。正常活跃连接数 << 此值；仅异常累积时硬上限驱逐最旧条目兜底防 OOM。
pub const MAX_CONN_MAP_SIZE: usize = 50_000;

// 长驻连接表的字段级字节预算。条目数上限不能约束外部字符串体积，所有非身份字段在入表时裁剪。
const CONNECTION_HOST_MAX_BYTES: usize = 512;
const CONNECTION_ADDRESS_PART_MAX_BYTES: usize = 128;
const CONNECTION_KIND_MAX_BYTES: usize = 256;
const CONNECTION_PROCESS_PATH_MAX_BYTES: usize = 4096;
const CONNECTION_RULE_MAX_BYTES: usize = 1024;
const CONNECTION_CHAIN_MAX_ITEMS: usize = 16;
const CONNECTION_CHAIN_ITEM_MAX_BYTES: usize = 256;
const TRUNCATION_MARK: &str = "…";

/// 拆 "ip:port"（含 IPv6 "\[::1\]:443"）为 { ip, port }（splitHostPort，StatsService.ts:37）。
///
/// IPv6 字面量带方括号按 `]` 拆；裸 IPv6（多冒号无方括号）无法可靠拆，整体当 ip；IPv4/域名按最后一个冒号拆。
/// 缺省返回 `(None, None)`。
pub fn split_host_port(s: &str) -> (Option<String>, Option<String>) {
    let s = s.trim();
    if s.is_empty() {
        return (None, None);
    }
    if let Some(rest) = s.strip_prefix('[') {
        // IPv6 字面量：[2001:db8::1]:443
        if let Some(close) = rest.find(']') {
            let ip = &rest[..close];
            let after = &rest[close + 1..];
            let port = after.strip_prefix(':').map(str::to_string);
            return (
                (!ip.is_empty()).then(|| ip.to_string()),
                port.filter(|p| !p.is_empty()),
            );
        }
        return (Some(s.to_string()), None);
    }
    // IPv4/域名：按最后一个冒号拆；多冒号且无方括号 = 裸 IPv6，整体当 ip。
    let last_colon = match s.rfind(':') {
        Some(i) => i,
        None => return (Some(s.to_string()), None),
    };
    if s.find(':') != Some(last_colon) {
        return (Some(s.to_string()), None);
    }
    let ip = &s[..last_colon];
    let port = &s[last_colon + 1..];
    (
        (!ip.is_empty()).then(|| ip.to_string()),
        (!port.is_empty()).then(|| port.to_string()),
    )
}

/// gRPC Connection.createdAt（int64 unix 时间戳）→ RFC3339 字符串。
///
/// sing-box 以 unix 纳秒序列化 createdAt；启发式按数量级判 ns/us/ms/s 兼容核版本差异
/// （createdAtToRfc3339，StatsService.ts:64）。<=0 / 溢出 → None（连接页时长列留空）。
pub fn created_at_to_rfc3339(v: i64) -> Option<String> {
    if v <= 0 {
        return None;
    }
    let v_u = u64::try_from(v).ok()?;
    // 与 TS Number(v) 比较：v_u 为正 i64，按数量级分档（ns/us/ms/s）。
    let ms = if v_u >= 1e17 as u64 {
        v_u.checked_div(1_000_000)? // 纳秒
    } else if v_u >= 1e14 as u64 {
        v_u.checked_div(1_000)? // 微秒
    } else if v_u >= 1e11 as u64 {
        v_u // 毫秒
    } else {
        v_u.checked_mul(1_000)? // 秒
    };
    let secs = (ms / 1000) as i64;
    let nanos = ((ms % 1000) * 1_000_000) as u32;
    // 溢出保护：secs 超出 civil 算法表示范围 → None（对齐 TS Number.isNaN(d.getTime()) → undefined）。
    if !(-62135596800..=253402300799).contains(&secs) {
        return None;
    }
    Some(format_rfc3339_from_unix(secs, nanos))
}

/// 无外部 time 依赖的 RFC3339 渲染：从 unix secs + nanos 直接产出 `YYYY-MM-DDTHH:MM:SS.mmmZ`。
fn format_rfc3339_from_unix(secs: i64, nanos: u32) -> String {
    let ms = nanos / 1_000_000; // ns → ms（对齐 JS toISOString 毫秒精度）
    let (year, month, day, hour, min, sec) = unix_to_civil(secs);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year, month, day, hour, min, sec, ms
    )
}

/// unix secs → (year, month, day, hour, min, sec) UTC（civil_from_days 算法，Howard Hinnant）。
fn unix_to_civil(secs: i64) -> (i32, u8, u8, u8, u8, u8) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let hour = (rem / 3600) as u8;
    let min = ((rem % 3600) / 60) as u8;
    let sec = (rem % 60) as u8;
    // civil_from_days
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = (y + if m <= 2 { 1 } else { 0 }) as i32;
    (year, m as u8, d as u8, hour, min, sec)
}

/// 裁剪 gRPC SingBoxConnection → ConnectionEntry（trimConnection，StatsService.ts:89）。
///
/// 字段映射：id→id, chainList→chains, rule→rule；metadata{ host←domain,
/// network, destinationIP/Port←拆 destination, sourceIP/Port←拆 source, inboundType←inboundType,
/// processPath←processInfo.processPath }；upload←uplinkTotal, download←downlinkTotal, start←createdAt 转 RFC3339。
pub fn trim_connection(c: &SingBoxConnection) -> ConnectionEntry {
    let (source_ip, source_port) = split_host_port(&c.source);
    let (destination_ip, destination_port) = split_host_port(&c.destination);
    let metadata = ConnectionMetadata {
        host: field_or_none_bounded(&c.domain, CONNECTION_HOST_MAX_BYTES),
        destination_ip: bound_optional(destination_ip, CONNECTION_ADDRESS_PART_MAX_BYTES),
        network: field_or_none_bounded(&c.network, CONNECTION_KIND_MAX_BYTES),
        inbound_type: field_or_none_bounded(&c.inbound_type, CONNECTION_KIND_MAX_BYTES),
        source_ip: bound_optional(source_ip, CONNECTION_ADDRESS_PART_MAX_BYTES),
        source_port: bound_optional(source_port, CONNECTION_ADDRESS_PART_MAX_BYTES),
        destination_port: bound_optional(destination_port, CONNECTION_ADDRESS_PART_MAX_BYTES),
        process_path: field_or_none_bounded(
            &c.process_info.process_path,
            CONNECTION_PROCESS_PATH_MAX_BYTES,
        ),
    };
    let metadata_non_empty = metadata.host.is_some()
        || metadata.destination_ip.is_some()
        || metadata.network.is_some()
        || metadata.inbound_type.is_some()
        || metadata.source_ip.is_some()
        || metadata.source_port.is_some()
        || metadata.destination_port.is_some()
        || metadata.process_path.is_some();
    ConnectionEntry {
        id: c.id.clone(),
        chains: c
            .chain_list
            .iter()
            .take(CONNECTION_CHAIN_MAX_ITEMS)
            .map(|chain| bounded_display_string(chain, CONNECTION_CHAIN_ITEM_MAX_BYTES))
            .collect(),
        rule: bounded_display_string(&c.rule, CONNECTION_RULE_MAX_BYTES),
        metadata: metadata_non_empty.then_some(metadata),
        upload: Some(c.uplink_total as u64),
        download: Some(c.downlink_total as u64),
        start: created_at_to_rfc3339(c.created_at),
    }
}

fn field_or_none_bounded(s: &str, max_bytes: usize) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(bounded_display_string(s, max_bytes))
    }
}

fn bound_optional(value: Option<String>, max_bytes: usize) -> Option<String> {
    value.map(|value| bounded_display_string(&value, max_bytes))
}

/// UTF-8 安全的显示字段裁剪。ID 不调用本函数，避免身份碰撞。
fn bounded_display_string(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let payload_limit = max_bytes.saturating_sub(TRUNCATION_MARK.len());
    let mut cut = payload_limit.min(value.len());
    while !value.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut bounded = String::with_capacity(cut + TRUNCATION_MARK.len());
    bounded.push_str(&value[..cut]);
    bounded.push_str(TRUNCATION_MARK);
    bounded
}

// ── 纯函数聚合（connections-aggregate.ts 1:1）──────────────────────────────────

/// host 显示名优先级：metadata.host(域名) > metadata.destinationIP(目标 IP) > rule
/// （hostNameOf，connections-aggregate.ts:22）。空串 = 无名连接。
pub fn host_name_of(c: &ConnectionEntry) -> String {
    if let Some(m) = &c.metadata {
        if let Some(host) = &m.host {
            if !host.is_empty() {
                return host.clone();
            }
        }
        if let Some(ip) = &m.destination_ip {
            if !ip.is_empty() {
                return ip.clone();
            }
        }
    }
    c.rule.clone()
}

/// outbound = chains\[0\]（首跳出站 tag），无链或空串则 'Direct'（outboundOf，connections-aggregate.ts:33）。
pub fn outbound_of(c: &ConnectionEntry) -> String {
    c.chains
        .first()
        .filter(|s| !s.is_empty())
        .cloned()
        .unwrap_or_else(|| "Direct".to_string())
}

/// 连接导航排名聚合（aggregateConnections，connections-aggregate.ts:41）。
///
/// - host 按 count 降序、截断 Top-N（剩余合并进 [`TOPOLOGY_OTHERS_KEY`]，最小者按 count 归并）。
/// - outbound 计入所有连接（含无名，与原 layout outboundTotals 同口径——右列节点高度按全部连接算）。
/// - 无名连接（host 名 trim 后空）计入 total/outbound 但不建 host 节点。
/// - outbounds 按 count 降序。
pub fn aggregate_connections(conns: &[ConnectionEntry], at: u64) -> ConnectionsAggregate {
    aggregate_connections_with_topn(conns, at, CONNECTION_RANKING_LIMIT)
}

/// 同 [`aggregate_connections`]，可注入 top_n（测试用小 N 复现 Top-N + Others 合并）。
pub fn aggregate_connections_with_topn(
    conns: &[ConnectionEntry],
    at: u64,
    top_n: usize,
) -> ConnectionsAggregate {
    aggregate_connections_iter(conns.iter(), at, top_n)
}

/// 首页连接流向的动态投影：在**完整活动连接集**上先过滤，再按画布槽位选择
/// 「主要目标约 2/3 + 最近目标约 1/3 + 其它（仅溢出时）」并限制出口列。
///
/// `slots` 是中/右列各自最多可画的节点数；调用边界会再钳制，这里仍至少保留 4，保证
/// 主要/最近/其它三种语义有可用空间。过滤必须发生在投影之前，搜索不会受常态绘制预算影响。
pub fn project_connections_topology(
    conns: &[ConnectionEntry],
    query: &str,
    at: u64,
    slots: usize,
) -> ConnectionsAggregate {
    project_connections_topology_iter(conns.iter(), query, at, slots)
}

fn project_connections_topology_iter<'a>(
    conns: impl IntoIterator<Item = &'a ConnectionEntry>,
    query: &str,
    at: u64,
    slots: usize,
) -> ConnectionsAggregate {
    let query = query.trim().to_lowercase();
    let iter = conns.into_iter().filter(|connection| {
        query.is_empty() || {
            host_name_of(connection).to_lowercase().contains(&query)
                || outbound_of(connection).to_lowercase().contains(&query)
        }
    });
    aggregate_connections_flow_iter(iter, at, slots.max(4))
}

/// 从借用迭代器聚合连接，避免拓扑刷新前先克隆整张连接表。
///
/// 公共函数继续接收 slice 以保持 API 稳定；长驻流内部直接把 `IndexMap::values()` 交给这里，
/// 因而拓扑每 250ms 刷新时只分配 Top-N 聚合结果，不再额外复制每条连接的字符串与 metadata。
fn aggregate_connections_iter<'a>(
    conns: impl IntoIterator<Item = &'a ConnectionEntry>,
    at: u64,
    top_n: usize,
) -> ConnectionsAggregate {
    use std::collections::BTreeMap;

    let (total, mut sorted, outbounds) = collect_connection_aggregates(conns);
    sort_hosts_by_count(&mut sorted);

    let hosts: Vec<ConnectionAggHost> = if sorted.len() > top_n {
        let (top, rest) = sorted.split_at(top_n);
        let mut others_flows: BTreeMap<String, u32> = BTreeMap::new();
        let mut others_count = 0u32;
        for (_, d) in rest {
            others_count += d.count;
            for (k, v) in &d.flows {
                *others_flows.entry(k.clone()).or_insert(0) += v;
            }
        }
        let mut out: Vec<ConnectionAggHost> = top
            .iter()
            .map(|(name, d)| ConnectionAggHost {
                name: name.clone(),
                count: d.count,
                flows: flows_to_arr(&d.flows),
                recent: false,
            })
            .collect();
        if others_count > 0 {
            out.push(ConnectionAggHost {
                name: TOPOLOGY_OTHERS_KEY.to_string(),
                count: others_count,
                flows: flows_to_arr(&others_flows),
                recent: false,
            });
        }
        out
    } else {
        sorted
            .into_iter()
            .map(|(name, d)| ConnectionAggHost {
                name,
                count: d.count,
                flows: flows_to_arr(&d.flows),
                recent: false,
            })
            .collect()
    };

    ConnectionsAggregate {
        total,
        hosts,
        outbounds,
        at,
    }
}

/// 首页流向投影的本体。完整 host/outbound 聚合只做一次；随后按绘制预算裁剪，IPC 载荷与总连接数解耦。
fn aggregate_connections_flow_iter<'a>(
    conns: impl IntoIterator<Item = &'a ConnectionEntry>,
    at: u64,
    slots: usize,
) -> ConnectionsAggregate {
    use std::collections::BTreeMap;

    let (total, mut sorted, mut outbounds) = collect_connection_aggregates(conns);
    sort_hosts_by_count(&mut sorted);

    let overflow = sorted.len() > slots;
    let real_slots = if overflow {
        slots.saturating_sub(1)
    } else {
        sorted.len()
    };
    // 默认 slots=16：可见真实目标 15 → 主要 10 + 最近 5；未溢出时「其它」槽由真实目标回收。
    let planned_visible = slots.saturating_sub(1);
    let planned_recent = (planned_visible + 1) / 3;
    let planned_main = planned_visible.saturating_sub(planned_recent);
    let main_count = planned_main.min(real_slots);
    let recent_count = real_slots.saturating_sub(main_count);

    let mut remainder = sorted.split_off(main_count);
    remainder.sort_by(|a, b| {
        b.1.last_opened
            .cmp(&a.1.last_opened)
            .then_with(|| b.1.count.cmp(&a.1.count))
            .then_with(|| a.0.cmp(&b.0))
    });
    let hidden = if remainder.len() > recent_count {
        remainder.split_off(recent_count)
    } else {
        Vec::new()
    };

    let mut hosts: Vec<ConnectionAggHost> = sorted
        .into_iter()
        .map(|(name, data)| host_to_output(name, data, false))
        .collect();
    hosts.extend(
        remainder
            .into_iter()
            .map(|(name, data)| host_to_output(name, data, true)),
    );

    if !hidden.is_empty() {
        let mut flows = BTreeMap::new();
        let mut count = 0u32;
        for (_, data) in hidden {
            count = count.saturating_add(data.count);
            for (outbound, flow_count) in data.flows {
                *flows.entry(outbound).or_insert(0) += flow_count;
            }
        }
        hosts.push(ConnectionAggHost {
            name: TOPOLOGY_OTHERS_KEY.to_string(),
            count,
            flows: flows_to_arr(&flows),
            recent: false,
        });
    }

    cap_outbounds(&mut hosts, &mut outbounds, slots);
    ConnectionsAggregate {
        total,
        hosts,
        outbounds,
        at,
    }
}

fn collect_connection_aggregates<'a>(
    conns: impl IntoIterator<Item = &'a ConnectionEntry>,
) -> (u32, Vec<(String, HostAgg)>, Vec<ConnectionAggOutbound>) {
    use std::collections::BTreeMap;

    let mut host_map: BTreeMap<String, HostAgg> = BTreeMap::new();
    let mut outbound_totals: BTreeMap<String, u32> = BTreeMap::new();
    let mut total = 0u32;
    for connection in conns {
        total = total.saturating_add(1);
        let outbound = outbound_of(connection);
        *outbound_totals.entry(outbound.clone()).or_insert(0) += 1;
        let name = host_name_of(connection);
        if name.trim().is_empty() {
            continue;
        }
        let host = host_map.entry(name).or_default();
        host.count = host.count.saturating_add(1);
        if let Some(start) = connection.start.as_ref().filter(|value| !value.is_empty()) {
            if start > &host.last_opened {
                host.last_opened.clone_from(start);
            }
        }
        *host.flows.entry(outbound).or_insert(0) += 1;
    }
    let mut outbounds: Vec<ConnectionAggOutbound> = outbound_totals
        .into_iter()
        .map(|(name, count)| ConnectionAggOutbound { name, count })
        .collect();
    outbounds.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
    (total, host_map.into_iter().collect(), outbounds)
}

fn sort_hosts_by_count(hosts: &mut [(String, HostAgg)]) {
    hosts.sort_by(|a, b| b.1.count.cmp(&a.1.count).then_with(|| a.0.cmp(&b.0)));
}

fn host_to_output(name: String, data: HostAgg, recent: bool) -> ConnectionAggHost {
    ConnectionAggHost {
        name,
        count: data.count,
        flows: flows_to_arr(&data.flows),
        recent,
    }
}

/// 右列也服从同一垂直预算；隐藏出口同时在每个 host 的 flows 中重映射到「其它」，保证缎带有落点。
fn cap_outbounds(
    hosts: &mut [ConnectionAggHost],
    outbounds: &mut Vec<ConnectionAggOutbound>,
    slots: usize,
) {
    use std::collections::{BTreeMap, BTreeSet};
    if outbounds.len() <= slots {
        return;
    }
    let keep = slots.saturating_sub(1);
    let hidden_names: BTreeSet<String> = outbounds[keep..]
        .iter()
        .map(|item| item.name.clone())
        .collect();
    let hidden_count = outbounds[keep..]
        .iter()
        .fold(0u32, |sum, item| sum.saturating_add(item.count));
    outbounds.truncate(keep);
    outbounds.push(ConnectionAggOutbound {
        name: TOPOLOGY_OTHERS_KEY.to_string(),
        count: hidden_count,
    });

    for host in hosts {
        let mut merged = BTreeMap::new();
        for flow in host.flows.drain(..) {
            let name = if hidden_names.contains(&flow.outbound) {
                TOPOLOGY_OTHERS_KEY.to_string()
            } else {
                flow.outbound
            };
            *merged.entry(name).or_insert(0) += flow.count;
        }
        host.flows = flows_to_arr(&merged);
    }
}

#[derive(Default)]
struct HostAgg {
    count: u32,
    flows: std::collections::BTreeMap<String, u32>,
    last_opened: String,
}

fn flows_to_arr(flows: &std::collections::BTreeMap<String, u32>) -> Vec<ConnectionAggFlow> {
    flows
        .iter()
        .map(|(outbound, count)| ConnectionAggFlow {
            outbound: outbound.clone(),
            count: *count,
        })
        .collect()
}

/// 聚合内容签名（aggregateSignature，connections-aggregate.ts:99）。
///
/// 内容规范化后稳定序列化 `{total, hosts, outbounds}`，剔 `at`。hosts 按 name 升序、每个 host 的 flows 按
/// outbound 升序、outbounds 按 name 升序（三者均为唯一键，全序确定）。同内容（任意兄弟重排）→ 同签名；
/// host/outbound 计数或成员变 → 签名变。worker 用它与上帧签名比对，仅内容真变才 post aggregate。
///
/// 返回 [`String`] 而非哈希：N 通常 ≤ Top-N+1，序列化字符串本身即比对基线，省一次哈希且可调试。
pub fn aggregate_signature(agg: &ConnectionsAggregate) -> String {
    let mut hosts: Vec<&ConnectionAggHost> = agg.hosts.iter().collect();
    hosts.sort_by(|a, b| a.name.cmp(&b.name));
    let mut outbounds: Vec<&ConnectionAggOutbound> = agg.outbounds.iter().collect();
    outbounds.sort_by(|a, b| a.name.cmp(&b.name));

    // 手写确定性序列化（避免 serde_json 对 BTreeMap 的 key 序依赖 + 确保字段顺序固定）。
    let mut s = String::new();
    s.push_str("{\"total\":");
    s.push_str(&agg.total.to_string());
    s.push_str(",\"hosts\":[");
    for (i, h) in hosts.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str("{\"name\":\"");
        push_escaped(&mut s, &h.name);
        s.push_str("\",\"count\":");
        s.push_str(&h.count.to_string());
        s.push_str(",\"recent\":");
        s.push_str(if h.recent { "true" } else { "false" });
        s.push_str(",\"flows\":[");
        let mut flows_sorted: Vec<&ConnectionAggFlow> = h.flows.iter().collect();
        flows_sorted.sort_by(|a, b| a.outbound.cmp(&b.outbound));
        for (j, f) in flows_sorted.iter().enumerate() {
            if j > 0 {
                s.push(',');
            }
            s.push_str("{\"outbound\":\"");
            push_escaped(&mut s, &f.outbound);
            s.push_str("\",\"count\":");
            s.push_str(&f.count.to_string());
            s.push('}');
        }
        s.push_str("]}");
    }
    s.push_str("],\"outbounds\":[");
    for (i, o) in outbounds.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str("{\"name\":\"");
        push_escaped(&mut s, &o.name);
        s.push_str("\",\"count\":");
        s.push_str(&o.count.to_string());
        s.push('}');
    }
    s.push_str("]}");
    s
}

fn push_escaped(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
}

// ── 有状态聚合器（StatsService.ts onStatus / onConnectionEvents）─────────────────

/// 维护 connMap + TrafficStats snapshot 的有状态聚合器。
///
/// 对应 上游 `StatsService` 的内部状态（不含订阅/重订阅——那部分在 [`crate::subscription`] /
/// [`crate::resubscribe`]）。帧经 [`StatsAggregator::on_status`] / [`StatsAggregator::on_connection_events`]
/// 注入；状态经 [`StatsAggregator::snapshot`] / [`StatsAggregator::entries`] 取。
///
/// connMap 用 [`IndexMap`](indexmap::IndexMap)（保持插入序，支持 LRU：UPDATE 时 delete+set 把活跃条目移到末尾，#167）。
/// key = 连接 id。
pub struct StatsAggregator {
    snapshot: TrafficStats,
    /// 连接事件只在入表时裁剪一次；不保留 gRPC 原始对象中 UI/拓扑永远不会读取的字段。
    conn_map: indexmap::IndexMap<String, ConnectionEntry>,
    /// max conn map size（OOM 安全网，默认 [`MAX_CONN_MAP_SIZE`]；测试可注入小值）。
    max_conn_map_size: usize,
    /// 速率差分基线：`(上一帧 at_ms, 该帧 uplink_total, 该帧 downlink_total)`。
    ///
    /// `None` = 还没有可作差的上一帧（新建 / [`StatsAggregator::reset`] 之后）→ 速率按 0 报，
    /// **绝不拿单帧的累计值当速率**（那是「核启动至今的总量」，会在重连/换核后闪出天文数字）。
    last_status: Option<(u64, u64, u64)>,
}

impl Default for StatsAggregator {
    fn default() -> Self {
        Self::new()
    }
}

impl StatsAggregator {
    /// 默认构造（OOM 上限 = [`MAX_CONN_MAP_SIZE`]）。
    pub fn new() -> Self {
        Self::with_max_conn_map_size(MAX_CONN_MAP_SIZE)
    }

    /// 测试用：注入小 max_conn_map_size 复现 OOM 驱逐。
    pub fn with_max_conn_map_size(max_conn_map_size: usize) -> Self {
        Self {
            snapshot: TrafficStats::zeroed(),
            conn_map: indexmap::IndexMap::new(),
            max_conn_map_size,
            last_status: None,
        }
    }

    /// 当前流量快照（克隆；对应 getSnapshot，StatsService.ts:271）。
    pub fn snapshot(&self) -> TrafficStats {
        self.snapshot
    }

    /// 把当前连接表物化成明细条目。
    ///
    /// # 为什么在**取**的时候物化，而不是在收帧时
    ///
    /// 上游 在 `onConnectionEvents` 末尾就把整张表 `map(trimConnection)` 物化好
    /// （`StatsService.ts` 尾部），本移植此前照抄了这一点。轮询时代无所谓：帧频恒等于 emit 频率
    /// （4Hz / 1Hz），物化多少次就 emit 多少次。
    ///
    /// 长驻流下这个等式**不再成立** —— 帧由内核的事件速率决定（连接风暴时远高于 emit 频率，
    /// 见 [`crate::emit_gate`]），而 emit 有下限间隔。收帧即物化 = 为一堆根本不会被推出去的
    /// 中间态各做一次 O(n) 的整表分配。当前 map 已在 NEW/补建时裁剪为明细契约，故这里只在
    /// detail 真正要 emit 时克隆；aggregate 走借用迭代器，完全不克隆整表。
    pub fn entries(&self) -> Vec<ConnectionEntry> {
        self.conn_map.values().cloned().collect()
    }

    /// 按 id 借用活动连接。CLOSED 帧若省略完整 payload，已结束历史可在删表前用它补齐最终展示字段。
    pub fn entry(&self, id: &str) -> Option<&ConnectionEntry> {
        self.conn_map.get(id)
    }

    /// 当前连接表的连接导航排名投影。`at` = 调用时刻 epoch ms。
    ///
    /// 与 detail 增量是**同一张连接表的两种投影**：前者按 host/出口聚合，后者逐条列出。
    /// 轮询时代各拉一次全量表是重复劳动。
    pub fn aggregate(&self, at: u64) -> ConnectionsAggregate {
        aggregate_connections_iter(self.conn_map.values(), at, CONNECTION_RANKING_LIMIT)
    }

    /// 当前完整活动表的首页流向投影：先过滤、再按实际画布槽位选择主要/最近目标。
    pub fn project_topology(&self, query: &str, at: u64, slots: usize) -> ConnectionsAggregate {
        project_connections_topology_iter(self.conn_map.values(), query, at, slots)
    }

    /// 归零 snapshot + 清空 connMap + **丢掉速率差分基线**（stop / resubscribe 重连窗口，
    /// StatsService.ts:204/251）。
    ///
    /// 基线必须一起丢：它跨越的那段空档长度不定（断流待命可能几分钟），留着的话恢复后第一帧算出来的
    /// 是「整段空档的平均吞吐」，却被当成**此刻**的速率显示一拍。丢掉即退回「首帧速率 0」语义。
    pub fn reset(&mut self) {
        self.snapshot = TrafficStats::zeroed();
        self.conn_map.clear();
        self.last_status = None;
    }

    /// Status 帧处理（onStatus，StatsService.ts:305）。`at_ms` = **调用方实测的单调毫秒时刻**。
    ///
    /// # 速率为什么必须自己算
    ///
    /// 早先这里直接把 `status.uplink` 当速率（并在注释里写「speed 已是速率，无需本地 delta/dt」）。
    /// 那是错的，且错法不止一种：`readStatus()` 从不给 `uplink`/`downlink` 赋值，是
    /// `SubscribeStatus` 的循环里每拍算 `UplinkTotal - uploadTotal` 再写回（
    /// `daemon/started_service.go:408-413`）⇒ 它是**字节增量**不是速率；**首帧在任何 tick 之前就
    /// `Send`，两者恒 0**；而把增量折成速率所需的窗口长度（服务端 ticker 的实际间隔，含调度抖动）
    /// **不在 wire 上**——请求里的 `interval` 只是我们的期望值，不是实际发生的间隔。
    ///
    /// 故速率 = `*_total` 的跨帧差分 ÷ **`at_ms` 实测 Δt**。首帧（无基线）恒 0：拿单帧累计值当速率
    /// 会在每次重连/换核后闪一个「核启动至今总量」级别的假峰值。
    ///
    /// `saturating_sub` 兜住累计回退：核在同一端口上重启时 `ReconnectingStream` 会**静默**重连，
    /// 而内核的 `Total()` 从 0 重新开始（那是新的一条核生命线）——差分为负时钳成 0，
    /// 宁可少报一拍也不出负数/天文数字。
    ///
    /// `active_connections` 取 `connectionsIn`（= 内核 `trafficManager.ConnectionsLen()`，
    /// 与 `SubscribeConnections` 首帧里的活连接条数同源同一口径）。⚠️ 与
    /// [`Self::on_connection_events`] 是同一字段的两个写入者，边界见 [`TrafficStats::active_connections`]。
    ///
    /// **本方法不判 `traffic_available`**：判了也只能报 0，与不判无从区分。那是**可观测性**问题，
    /// 归调用方（有日志门面的那一层）——见 `polaris::runtime::stats::traffic_availability_changed`。
    pub fn on_status(&mut self, status: &SingBoxStatus, at_ms: u64) {
        let up_total = status.uplink_total.max(0) as u64;
        let down_total = status.downlink_total.max(0) as u64;

        let (up_speed, down_speed) = match self.last_status {
            Some((t0, u0, d0)) => {
                // Δt 用**实测**毫秒差；下限 1ms 防除零（服务端 ticker 正常在秒级，落到这个下限
                // 只可能是同一毫秒内的重复帧，此时差分也几乎恒为 0）。
                let dt = ((at_ms.saturating_sub(t0)) as f64 / 1000.0).max(0.001);
                (
                    (up_total.saturating_sub(u0) as f64 / dt).round() as u64,
                    (down_total.saturating_sub(d0) as f64 / dt).round() as u64,
                )
            }
            None => (0, 0),
        };
        self.last_status = Some((at_ms, up_total, down_total));

        self.snapshot.upload_speed = up_speed;
        self.snapshot.download_speed = down_speed;
        self.snapshot.total_upload = up_total;
        self.snapshot.total_download = down_total;
        self.snapshot.active_connections = status.connections_in.max(0) as u32;
    }

    /// Connections 事件帧处理（onConnectionEvents，StatsService.ts:339）。
    ///
    /// reset=true → 清空 map 按 events 全量重建；否则增量（NEW 加 / UPDATE 改 / CLOSED 删）。
    /// UPDATE 累加 delta 到既有条目 totals + LRU delete+set；漏收 NEW 时 ev.connection 兜底补建；
    /// NEW 丢弃 closedAt>0（历史环死连接）。末尾 OOM 驱逐超 max_conn_map_size 的最旧条目。
    /// 返回应用本帧后的净变化；reset 的完整基线延迟到中继实际发送时物化。
    pub fn on_connection_events(
        &mut self,
        events: &SingBoxConnectionEvents,
        _at: u64,
    ) -> ConnectionsDetailChange {
        let mut change = ConnectionsDetailChange {
            reset: events.reset,
            ..ConnectionsDetailChange::default()
        };
        if events.reset {
            self.conn_map.clear();
        }
        for ev in &events.events {
            self.apply_event(ev, &mut change);
        }
        // OOM 安全网：超硬上限按插入序（最旧、最可能是漏删死连接）驱逐。
        while self.conn_map.len() > self.max_conn_map_size {
            if let Some(first) = self.conn_map.keys().next().cloned() {
                self.conn_map.swap_remove(&first);
                change.remove(first);
            } else {
                break;
            }
        }
        // 连接事件这条腿的活跃连接数取 connMap.len —— 它是**已滤掉测速探测池**的口径，
        // 与拓扑 / 明细两个投影同源，故三处恒自洽。
        // （Status 那条腿取 `connectionsIn`，是内核未过滤的口径；两者的分工见 `TrafficStats`。）
        self.snapshot.active_connections = self.conn_map.len() as u32;
        // **不在此物化完整明细**：常态只返回本帧净变化；reset 基线到真正 emit 时才按需读取。
        change
    }

    fn apply_event(&mut self, ev: &SingBoxConnectionEvent, change: &mut ConnectionsDetailChange) {
        let id = if !ev.id.is_empty() {
            ev.id.clone()
        } else {
            match &ev.connection {
                Some(c) if !c.id.is_empty() => c.id.clone(),
                _ => return,
            }
        };
        match ev.kind {
            ConnectionEventType::Closed => {
                self.conn_map.swap_remove(&id);
                change.remove(id);
            }
            ConnectionEventType::Update => {
                // UPDATE 帧只带 delta（connection 通常为 null）→ 累加到既有条目 totals。
                // 漏收 NEW（UPDATE 先到）时 ev.connection 兜底补建。
                // LRU 近似（#167）：delete+set 把活跃条目移到插入序末尾，使迭代序首部恒为「最久未更新」。
                if let Some(existing) = self.conn_map.shift_remove(&id) {
                    let mut updated = existing;
                    // `saturating_add` 而非 `+`：本字段现在是**我们自己跨小时累加**出来的
                    // （轮询时代每拍都从内核重新读全量 total，我们从不累加，故溢出不可能）。
                    // 长驻流下 `+` 一旦溢出，debug 构建直接 panic 掉整条 relay 任务 ——
                    // 流断了、连接页空了，而根因是一个算术溢出，日志里什么都没有。
                    // 内核异常/协议漂移送来一个畸形 delta 不该有这种放大倍数。
                    updated.upload = Some(
                        (updated.upload.unwrap_or(0) as i64).saturating_add(ev.uplink_delta) as u64,
                    );
                    updated.download = Some(
                        (updated.download.unwrap_or(0) as i64).saturating_add(ev.downlink_delta)
                            as u64,
                    );
                    let counters = ConnectionCounters {
                        id: id.clone(),
                        upload: updated.upload.unwrap_or(0),
                        download: updated.download.unwrap_or(0),
                    };
                    self.conn_map.insert(id, updated);
                    change.update_counters(counters);
                } else if let Some(c) = &ev.connection {
                    // 补建腿同样挡探测池：NEW 分支刚把这条探测连接挡在表外，它后续的 UPDATE 必然
                    // 落到「表里没有」这一支——若此处不挡，只要内核在 UPDATE 里带上 connection，
                    // NEW 侧的过滤就被 100% 抵消（不是边角情形，是每条探测连接的必经路径）。
                    if !is_probe_pool_inbound_tag(&c.inbound) {
                        let mut entry = trim_connection(c);
                        entry.id.clone_from(&id);
                        self.conn_map.insert(id, entry.clone());
                        change.upsert(entry);
                    }
                }
            }
            ConnectionEventType::New => {
                // sing-box 1.14 初始/重置帧会把「已关闭连接历史环」（closedAt>0）作为 NEW 下发 → 丢弃。
                //
                // 同理丢弃**主核测速探测池**（`probe-in-{k}` 入站）的连接：那是应用自己的测速流量，
                // 不是用户流量，混进连接表会同时污染三个消费点——拓扑图、连接明细表、活跃连接总数
                // （后者 = `conn_map.len()`）。测速期间拓扑上闪一批 `www.gstatic.com` 就是它。
                //
                // **落点必须在这里（不进表），不能挪到某个投影里滤**：明细 / 拓扑 / 总数是三个独立
                // 消费点，滤一个漏两个。判据取 inbound **tag** 而非目标 host / 端口——tag 是配置里
                // 钉死的事实，host/端口是可变的猜测。
                //
                // ⚠️ **本条是对 上游的主动偏离，不是移植漂移**：上游的 `StatsService` 侧零过滤，
                // 探测连接照样进它的连接表（陈先生 2026-07-30 两端实测确认）。对着 上游 比对的人
                // 会以为这里多了一条——是 上游的既有缺陷，移植目标是功能对等而非缺陷对等。
                if let Some(c) = &ev.connection {
                    if c.closed_at <= 0 && !is_probe_pool_inbound_tag(&c.inbound) {
                        let mut entry = trim_connection(c);
                        entry.id.clone_from(&id);
                        self.conn_map.insert(id, entry.clone());
                        change.upsert(entry);
                    }
                }
            }
        }
    }

    /// 当前 connMap 条数（测试/诊断用）。
    pub fn conn_count(&self) -> usize {
        self.conn_map.len()
    }
}

#[cfg(test)]
mod tests;
