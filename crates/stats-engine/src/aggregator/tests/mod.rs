#![allow(clippy::too_many_lines)]

use polaris_config_engine::builder::probe_pool_inbound_tag;

use super::*;
use crate::types::{SingBoxConnection, SingBoxConnectionEvent, SingBoxConnectionEvents};

fn conn(id: &str, host: Option<&str>, chain: Option<&str>) -> ConnectionEntry {
    ConnectionEntry {
        id: id.to_string(),
        chains: chain.map(|s| vec![s.to_string()]).unwrap_or_default(),
        rule: "final".to_string(),
        metadata: host.map(|h| ConnectionMetadata {
            host: Some(h.to_string()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

// ── splitHostPort ──

#[test]
fn split_host_port_ipv4() {
    assert_eq!(
        split_host_port("1.2.3.4:443"),
        (Some("1.2.3.4".into()), Some("443".into()))
    );
}

#[test]
fn split_host_port_ipv6_bracketed() {
    assert_eq!(
        split_host_port("[2001:db8::1]:443"),
        (Some("2001:db8::1".into()), Some("443".into()))
    );
}

#[test]
fn split_host_port_bare_ipv6_treated_as_ip() {
    let (ip, port) = split_host_port("::1");
    assert_eq!(ip.as_deref(), Some("::1"));
    assert!(port.is_none());
}

#[test]
fn split_host_port_empty_returns_none_none() {
    assert_eq!(split_host_port(""), (None, None));
    assert_eq!(split_host_port("   "), (None, None));
}

#[test]
fn split_host_port_no_port() {
    assert_eq!(
        split_host_port("example.com"),
        (Some("example.com".into()), None)
    );
}

// ── aggregate_connections（移植 connections-aggregate.test.ts）──

#[test]
fn aggregate_total_and_same_host_accumulates_flows() {
    let agg = aggregate_connections(
        &[
            conn("c0", Some("a.com"), Some("P")),
            conn("c1", Some("a.com"), Some("P")),
        ],
        0,
    );
    assert_eq!(agg.total, 2);
    let h = agg.hosts.iter().find(|h| h.name == "a.com").unwrap();
    assert_eq!(h.count, 2);
    assert_eq!(
        h.flows,
        vec![ConnectionAggFlow {
            outbound: "P".into(),
            count: 2
        }]
    );
    let o = agg.outbounds.iter().find(|o| o.name == "P").unwrap();
    assert_eq!(o.count, 2);
}

#[test]
fn aggregate_host_name_priority() {
    let h = host_name_of(&conn("c", Some("h.com"), None));
    assert_eq!(h, "h.com");

    let mut c = conn("c", None, None);
    c.metadata = Some(ConnectionMetadata {
        destination_ip: Some("1.2.3.4".into()),
        ..Default::default()
    });
    assert_eq!(host_name_of(&c), "1.2.3.4");

    // 仅 rule
    let c = conn("c", None, None);
    assert_eq!(host_name_of(&c), "final");
}

#[test]
fn aggregate_outbound_chains0_or_direct() {
    let agg = aggregate_connections(&[conn("c", Some("a.com"), None)], 0);
    assert!(agg.outbounds.iter().any(|o| o.name == "Direct"));
    let agg = aggregate_connections(&[conn("c", Some("a.com"), Some("hk"))], 0);
    assert!(agg.outbounds.iter().any(|o| o.name == "hk"));
}

#[test]
fn aggregate_top_n_plus_others_merge_smallest() {
    // host_k 有 k 条连接（k=1..top_n+1）→ 排序后 host1(最小=1 条) 落入 Others。
    let top_n = 3;
    let mut conns = Vec::new();
    for k in 1..=top_n + 1 {
        for _ in 0..k {
            conns.push(conn(
                &format!("c{k}"),
                Some(&format!("host{k}.com")),
                Some("P"),
            ));
        }
    }
    let agg = aggregate_connections_with_topn(&conns, 0, top_n);
    assert_eq!(agg.hosts.len(), top_n + 1); // Top-N + Others
    let others = agg
        .hosts
        .iter()
        .find(|h| h.name == TOPOLOGY_OTHERS_KEY)
        .unwrap();
    assert_eq!(others.count, 1); // 仅 host1(1 条) 被收敛
    assert_eq!(
        others.flows,
        vec![ConnectionAggFlow {
            outbound: "P".into(),
            count: 1
        }]
    );
}

#[test]
fn topology_search_filters_before_top_n_instead_of_searching_lossy_projection() {
    let mut conns = Vec::new();
    for i in 0..CONNECTION_RANKING_LIMIT {
        conns.push(conn(
            &format!("busy-{i}"),
            Some(&format!("host-{i:02}.example")),
            Some("busy-out"),
        ));
    }
    conns.push(conn("youtube", Some("www.youtube.com"), Some("Hk02-L7-H3")));

    let normal = aggregate_connections(&conns, 10);
    assert!(
        !normal
            .hosts
            .iter()
            .any(|host| host.name == "www.youtube.com"),
        "等计数时 youtube 排在常态 Top-N 之外，先聚合再搜索必然丢失"
    );

    let searched = project_connections_topology(&conns, "YOUTUBE", 20, 16);
    assert_eq!(searched.total, 1);
    assert_eq!(searched.hosts.len(), 1);
    assert_eq!(searched.hosts[0].name, "www.youtube.com");
    assert_eq!(searched.outbounds[0].name, "Hk02-L7-H3");
}

#[test]
fn topology_search_matches_outbound_and_empty_query_preserves_normal_projection() {
    let conns = vec![
        conn("a", Some("a.example"), Some("direct")),
        conn("b", Some("b.example"), Some("Hk02-L7-H3")),
    ];
    let searched = project_connections_topology(&conns, "hk02", 20, 16);
    assert_eq!(searched.total, 1);
    assert_eq!(searched.hosts[0].name, "b.example");
    assert_eq!(
        project_connections_topology(&conns, "  ", 30, 16),
        project_connections_topology(&conns, "", 30, 16)
    );
}

#[test]
fn hidden_connection_can_change_while_normal_top_n_signature_stays_equal() {
    let mut stable = Vec::new();
    for i in 0..CONNECTION_RANKING_LIMIT {
        stable.push(conn(
            &format!("top-{i}-a"),
            Some(&format!("top-{i:02}.example")),
            Some("proxy"),
        ));
        stable.push(conn(
            &format!("top-{i}-b"),
            Some(&format!("top-{i:02}.example")),
            Some("proxy"),
        ));
    }
    let mut before = stable.clone();
    before.push(conn("hidden-old", Some("zzz.hidden"), Some("proxy")));
    let mut after = stable;
    after.push(conn("hidden-new", Some("www.youtube.com"), Some("proxy")));

    assert_eq!(
        aggregate_signature(&aggregate_connections(&before, 10)),
        aggregate_signature(&aggregate_connections(&after, 20)),
        "Top-N + 其它 + total 都不变时，常态有损签名观察不到隐藏成员替换"
    );
    assert_eq!(
        project_connections_topology(&before, "youtube", 30, 16).total,
        0
    );
    assert_eq!(
        project_connections_topology(&after, "youtube", 40, 16).total,
        1,
        "搜索刷新不能依赖常态 Top-N 签名变化"
    );
}

#[test]
fn flow_projection_default_overflow_is_10_main_5_recent_1_others() {
    let mut conns = Vec::new();
    for i in 0..20 {
        let mut entry = conn(
            &format!("c-{i}"),
            Some(&format!("host-{i:02}.example")),
            Some("proxy"),
        );
        entry.start = Some(format!("2026-08-16T12:{i:02}:00.000000000Z"));
        conns.push(entry);
    }
    let projection = project_connections_topology(&conns, "", 1, 16);
    assert_eq!(projection.hosts.len(), 16);
    assert_eq!(
        projection.hosts.iter().filter(|host| host.recent).count(),
        5
    );
    assert_eq!(
        projection
            .hosts
            .iter()
            .filter(|host| !host.recent && host.name != TOPOLOGY_OTHERS_KEY)
            .count(),
        10
    );
    assert_eq!(projection.hosts.last().unwrap().name, TOPOLOGY_OTHERS_KEY);
    assert_eq!(projection.hosts.last().unwrap().count, 5);
    assert_eq!(projection.hosts[10].name, "host-19.example");
}

#[test]
fn flow_projection_without_overflow_reclaims_others_slot_for_real_target() {
    let conns: Vec<_> = (0..16)
        .map(|i| {
            conn(
                &format!("c-{i}"),
                Some(&format!("h-{i}.example")),
                Some("proxy"),
            )
        })
        .collect();
    let projection = project_connections_topology(&conns, "", 1, 16);
    assert_eq!(projection.hosts.len(), 16);
    assert!(!projection
        .hosts
        .iter()
        .any(|host| host.name == TOPOLOGY_OTHERS_KEY));
}

#[test]
fn flow_projection_caps_outbounds_and_remaps_hidden_flows() {
    let conns: Vec<_> = (0..8)
        .map(|i| {
            conn(
                &format!("c-{i}"),
                Some("example.com"),
                Some(&format!("out-{i}")),
            )
        })
        .collect();
    let projection = project_connections_topology(&conns, "", 1, 4);
    assert_eq!(projection.outbounds.len(), 4);
    let others = projection
        .outbounds
        .iter()
        .find(|outbound| outbound.name == TOPOLOGY_OTHERS_KEY)
        .unwrap();
    assert_eq!(others.count, 5);
    let flow = projection.hosts[0]
        .flows
        .iter()
        .find(|flow| flow.outbound == TOPOLOGY_OTHERS_KEY)
        .unwrap();
    assert_eq!(flow.count, 5);
}

#[test]
fn aggregate_unnamed_counts_total_and_outbound_not_host() {
    let mut unnamed = conn("c0", None, Some("P"));
    unnamed.rule = String::new();
    let agg = aggregate_connections(&[unnamed, conn("c1", Some("a.com"), Some("P"))], 0);
    assert_eq!(agg.total, 2);
    assert_eq!(agg.hosts.len(), 1); // 仅 a.com
    let a = agg.hosts.iter().find(|h| h.name == "a.com").unwrap();
    assert_eq!(a.count, 1);
    let p = agg.outbounds.iter().find(|o| o.name == "P").unwrap();
    assert_eq!(p.count, 2); // 两条都计入 outbound
}

#[test]
fn aggregate_outbounds_desc_by_count() {
    let agg = aggregate_connections(
        &[
            conn("c0", Some("a.com"), Some("P1")),
            conn("c1", Some("b.com"), Some("P2")),
            conn("c2", Some("c.com"), Some("P2")),
        ],
        0,
    );
    assert_eq!(
        agg.outbounds
            .iter()
            .map(|o| o.name.clone())
            .collect::<Vec<_>>(),
        vec!["P2", "P1"]
    );
}

#[test]
fn aggregate_empty_keeps_at() {
    let agg = aggregate_connections(&[], 123);
    assert_eq!(agg.total, 0);
    assert!(agg.hosts.is_empty());
    assert!(agg.outbounds.is_empty());
    assert_eq!(agg.at, 123);
}

// ── aggregate_signature（移植 connections-aggregate.test.ts）──

#[test]
fn signature_permutation_invariant() {
    let cs = [
        conn("a", Some("a.com"), Some("P")),
        conn("b", Some("a.com"), Some("Q")),
        conn("c", Some("b.com"), Some("P")),
        conn("d", Some("b.com"), Some("Q")),
    ];
    let permuted = [cs[3].clone(), cs[1].clone(), cs[2].clone(), cs[0].clone()];
    let sig_a = aggregate_signature(&aggregate_connections(&cs, 111));
    let sig_b = aggregate_signature(&aggregate_connections(&permuted, 222));
    assert_eq!(sig_a, sig_b);
}

#[test]
fn signature_same_content_different_at_same_sig() {
    let conns = [
        conn("a", Some("a.com"), Some("P")),
        conn("b", Some("b.com"), Some("Q")),
    ];
    let a = aggregate_signature(&aggregate_connections(&conns, 1000));
    let b = aggregate_signature(&aggregate_connections(&conns, 9_999_999));
    assert_eq!(a, b);
}

#[test]
fn signature_host_count_change_detected() {
    let base = aggregate_signature(&aggregate_connections(
        &[conn("a", Some("a.com"), Some("P"))],
        0,
    ));
    let more = aggregate_signature(&aggregate_connections(
        &[
            conn("a", Some("a.com"), Some("P")),
            conn("b", Some("a.com"), Some("P")),
        ],
        0,
    ));
    assert_ne!(base, more);
}

#[test]
fn signature_outbound_distribution_change_detected() {
    let p = aggregate_signature(&aggregate_connections(
        &[conn("a", Some("a.com"), Some("P"))],
        0,
    ));
    let q = aggregate_signature(&aggregate_connections(
        &[conn("a", Some("a.com"), Some("Q"))],
        0,
    ));
    assert_ne!(p, q);
}

#[test]
fn signature_empty_stable_across_at() {
    let a = aggregate_signature(&aggregate_connections(&[], 1));
    let b = aggregate_signature(&aggregate_connections(&[], 2));
    assert_eq!(a, b);
}

#[test]
fn signature_does_not_mutate_input_order() {
    let agg = aggregate_connections(
        &[
            conn("a", Some("x.com"), Some("Z")),
            conn("b", Some("x.com"), Some("Z")),
            conn("c", Some("x.com"), Some("A")),
        ],
        0,
    );
    let flows_before: Vec<(String, u32)> = agg.hosts[0]
        .flows
        .iter()
        .map(|f| (f.outbound.clone(), f.count))
        .collect();
    let obs_before: Vec<(String, u32)> = agg
        .outbounds
        .iter()
        .map(|o| (o.name.clone(), o.count))
        .collect();
    let _ = aggregate_signature(&agg);
    let flows_after: Vec<(String, u32)> = agg.hosts[0]
        .flows
        .iter()
        .map(|f| (f.outbound.clone(), f.count))
        .collect();
    let obs_after: Vec<(String, u32)> = agg
        .outbounds
        .iter()
        .map(|o| (o.name.clone(), o.count))
        .collect();
    assert_eq!(flows_before, flows_after, "flows 顺序不变");
    assert_eq!(obs_before, obs_after, "outbounds 顺序不变");
}

// ── StatsAggregator 状态机 ──

fn raw_conn(id: &str, created_at: i64, up: i64, down: i64, chain: &str) -> SingBoxConnection {
    SingBoxConnection {
        id: id.to_string(),
        created_at,
        uplink_total: up,
        downlink_total: down,
        chain_list: vec![chain.to_string()],
        ..Default::default()
    }
}

/// 🔴 **首帧恒 0 速率**：单帧的 `*_total` 是「核启动至今总量」，当速率用就是一个假峰值。
///
/// **变异探针**：把 `None` 分支改成拿 `up_total/down_total` 本身（或改成
/// `status.uplink/downlink`）⇒ 转红——后者是本批修掉的原缺陷形态：首帧 uplink 恒 0 看似"也是 0"，
/// 但第二段（真差分）会立刻暴露它。
#[test]
fn on_status_first_frame_reports_zero_speed_but_real_totals() {
    let mut agg = StatsAggregator::new();
    agg.on_status(
        &SingBoxStatus {
            // 内核在首帧把 uplink/downlink 留成 0（它们在第一次 tick 之后才被赋值）。
            uplink: 0,
            downlink: 0,
            uplink_total: 1_000_000,
            downlink_total: 2_000_000,
            connections_in: 7,
            traffic_available: true,
            ..Default::default()
        },
        1_000,
    );
    let s = agg.snapshot();
    assert_eq!(s.upload_speed, 0, "首帧无基线 → 速率必须 0");
    assert_eq!(s.download_speed, 0);
    assert_eq!(s.total_upload, 1_000_000, "累计即刻真实");
    assert_eq!(s.total_download, 2_000_000);
    assert_eq!(s.active_connections, 7, "活跃连接数取 connectionsIn");
}

/// 🔴 **速率 = 累计差分 ÷ 实测 Δt，绝不是 `Status.uplink`。**
///
/// 帧里的 `uplink/downlink` 刻意给成与真相**矛盾**的值（1/2 B），真相是 2s 内涨了 4000/8000 B
/// ⇒ 2000/4000 B/s。
///
/// **变异探针**：改回 `upload_speed = status.uplink.max(0) as u64` ⇒ 实得 1/2 ⇒ 转红；
/// 把「÷ Δt」删掉（直接用差分当速率）⇒ 实得 4000/8000 ⇒ 转红；
/// 把 Δt 换成请求里的 `interval` 常量（1s）⇒ 实得 4000/8000 ⇒ 转红。
#[test]
fn on_status_derives_speed_from_total_delta_over_measured_dt() {
    let mut agg = StatsAggregator::new();
    agg.on_status(
        &SingBoxStatus {
            uplink_total: 1_000,
            downlink_total: 2_000,
            ..Default::default()
        },
        10_000,
    );
    agg.on_status(
        &SingBoxStatus {
            uplink: 1, // 与真相矛盾的诱饵：直接当速率用就会实得 1
            downlink: 2,
            uplink_total: 5_000,
            downlink_total: 10_000,
            ..Default::default()
        },
        12_000, // 实测 Δt = 2s（**不是**请求里那个 1s interval）
    );
    let s = agg.snapshot();
    assert_eq!(s.upload_speed, 2_000, "(5000-1000)/2s");
    assert_eq!(s.download_speed, 4_000, "(10000-2000)/2s");
}

/// 累计回退（核在同一端口重启、流静默重连 → `Total()` 从 0 重来）→ 速率钳成 0，不出负数/天文数字。
#[test]
fn on_status_clamps_total_rollback_to_zero_speed() {
    let mut agg = StatsAggregator::new();
    agg.on_status(
        &SingBoxStatus {
            uplink_total: 9_000_000,
            downlink_total: 9_000_000,
            ..Default::default()
        },
        0,
    );
    agg.on_status(
        &SingBoxStatus {
            uplink_total: 10, // 新核生命线，从 0 重来
            downlink_total: 20,
            ..Default::default()
        },
        1_000,
    );
    let s = agg.snapshot();
    assert_eq!(s.upload_speed, 0, "负差分钳成 0");
    assert_eq!(s.download_speed, 0);
    assert_eq!(s.total_upload, 10, "累计如实跟随新的核生命线");
}

/// 负值防御（协议漂移/畸形帧）：负的累计与负的连接数一律钳成 0。
#[test]
fn on_status_clamps_negative_to_zero() {
    let mut agg = StatsAggregator::new();
    agg.on_status(
        &SingBoxStatus {
            uplink: -5,
            downlink: -10,
            uplink_total: -100,
            downlink_total: -200,
            connections_in: -1,
            ..Default::default()
        },
        0,
    );
    let s = agg.snapshot();
    assert_eq!(s.upload_speed, 0);
    assert_eq!(s.download_speed, 0);
    assert_eq!(s.total_upload, 0);
    assert_eq!(s.total_download, 0);
    assert_eq!(s.active_connections, 0);
}

/// 🔴 **`reset()` 必须一并丢掉速率基线**（断流 / 停核 / 换核的重建点）。
///
/// 不丢的话，恢复后第一帧算出来的是「整段空档的平均吞吐」——用户隐藏窗口期间下过大文件，
/// 切回来的瞬间状态栏就闪一个与此刻无关的高速率。
///
/// **变异探针**：`reset()` 里删掉 `self.last_status = None` ⇒ 第二段实得
/// (1_000_000-0)/1s = 1_000_000 ⇒ 转红。
#[test]
fn reset_drops_speed_baseline_so_next_frame_is_zero() {
    let mut agg = StatsAggregator::new();
    agg.on_status(&SingBoxStatus::default(), 0);
    agg.reset();
    agg.on_status(
        &SingBoxStatus {
            uplink_total: 1_000_000,
            downlink_total: 1_000_000,
            ..Default::default()
        },
        1_000,
    );
    let s = agg.snapshot();
    assert_eq!(
        s.upload_speed, 0,
        "reset 后的第一帧必须走「无基线 → 速率 0」，不得把空档期总量当成当前速率"
    );
    assert_eq!(s.download_speed, 0);
}

#[test]
fn new_event_adds_to_conn_map() {
    let mut agg = StatsAggregator::new();
    agg.on_connection_events(
        &SingBoxConnectionEvents {
            reset: false,
            events: vec![SingBoxConnectionEvent {
                kind: ConnectionEventType::New,
                id: "c1".into(),
                connection: Some(raw_conn("c1", 1_000_000_000i64, 10, 20, "P")),
                ..Default::default()
            }],
        },
        0,
    );
    assert_eq!(agg.conn_count(), 1);
    assert_eq!(agg.snapshot().active_connections, 1);
    assert_eq!(agg.entries().len(), 1);
    assert_eq!(agg.entries()[0].id, "c1");
    assert_eq!(agg.entries()[0].upload, Some(10));
}

#[test]
fn new_event_drops_closed_history_ring_entries() {
    let mut agg = StatsAggregator::new();
    let mut dead = raw_conn("c1", 1_000_000_000i64, 0, 0, "P");
    dead.closed_at = 1_000_000_000i64;
    agg.on_connection_events(
        &SingBoxConnectionEvents {
            reset: false,
            events: vec![SingBoxConnectionEvent {
                kind: ConnectionEventType::New,
                id: "c1".into(),
                connection: Some(dead),
                ..Default::default()
            }],
        },
        0,
    );
    assert_eq!(agg.conn_count(), 0); // 死连接被丢弃
}

#[test]
fn closed_event_removes_from_conn_map() {
    let mut agg = StatsAggregator::new();
    agg.on_connection_events(
        &SingBoxConnectionEvents {
            reset: false,
            events: vec![SingBoxConnectionEvent {
                kind: ConnectionEventType::New,
                id: "c1".into(),
                connection: Some(raw_conn("c1", 1_000_000_000i64, 10, 20, "P")),
                ..Default::default()
            }],
        },
        0,
    );
    agg.on_connection_events(
        &SingBoxConnectionEvents {
            reset: false,
            events: vec![SingBoxConnectionEvent {
                kind: ConnectionEventType::Closed,
                id: "c1".into(),
                ..Default::default()
            }],
        },
        0,
    );
    assert_eq!(agg.conn_count(), 0);
    assert_eq!(agg.snapshot().active_connections, 0);
}

#[test]
fn update_event_accumulates_delta_onto_existing_totals() {
    let mut agg = StatsAggregator::new();
    agg.on_connection_events(
        &SingBoxConnectionEvents {
            reset: false,
            events: vec![SingBoxConnectionEvent {
                kind: ConnectionEventType::New,
                id: "c1".into(),
                connection: Some(raw_conn("c1", 1_000_000_000i64, 100, 200, "P")),
                ..Default::default()
            }],
        },
        0,
    );
    // UPDATE 只带 delta（connection=None）→ 累加到既有 totals
    agg.on_connection_events(
        &SingBoxConnectionEvents {
            reset: false,
            events: vec![SingBoxConnectionEvent {
                kind: ConnectionEventType::Update,
                id: "c1".into(),
                uplink_delta: 50,
                downlink_delta: 70,
                ..Default::default()
            }],
        },
        0,
    );
    assert_eq!(agg.conn_count(), 1);
    assert_eq!(agg.entries()[0].upload, Some(150)); // 100 + 50
    assert_eq!(agg.entries()[0].download, Some(270)); // 200 + 70
}

#[test]
fn update_event_falls_back_to_connection_when_missing_new() {
    // 漏收 NEW（UPDATE 先到）：ev.connection 兜底补建
    let mut agg = StatsAggregator::new();
    agg.on_connection_events(
        &SingBoxConnectionEvents {
            reset: false,
            events: vec![SingBoxConnectionEvent {
                kind: ConnectionEventType::Update,
                id: "c1".into(),
                connection: Some(raw_conn("c1", 1_000_000_000i64, 30, 40, "P")),
                ..Default::default()
            }],
        },
        0,
    );
    assert_eq!(agg.conn_count(), 1);
    assert_eq!(agg.entries()[0].upload, Some(30));
}

#[test]
fn reset_clears_then_rebuilds_from_events() {
    let mut agg = StatsAggregator::new();
    // 先建一条
    agg.on_connection_events(
        &SingBoxConnectionEvents {
            reset: false,
            events: vec![SingBoxConnectionEvent {
                kind: ConnectionEventType::New,
                id: "c1".into(),
                connection: Some(raw_conn("c1", 1_000_000_000i64, 0, 0, "P")),
                ..Default::default()
            }],
        },
        0,
    );
    // reset=true 清空 + 全量重建（带 c2/c3）
    agg.on_connection_events(
        &SingBoxConnectionEvents {
            reset: true,
            events: vec![
                SingBoxConnectionEvent {
                    kind: ConnectionEventType::New,
                    id: "c2".into(),
                    connection: Some(raw_conn("c2", 1_000_000_000i64, 0, 0, "P")),
                    ..Default::default()
                },
                SingBoxConnectionEvent {
                    kind: ConnectionEventType::New,
                    id: "c3".into(),
                    connection: Some(raw_conn("c3", 1_000_000_000i64, 0, 0, "Q")),
                    ..Default::default()
                },
            ],
        },
        0,
    );
    assert_eq!(agg.conn_count(), 2); // c1 被 reset 清掉，剩 c2/c3
}

#[test]
fn oom_evicts_oldest_when_over_max() {
    let mut agg = StatsAggregator::with_max_conn_map_size(2);
    for id in ["c1", "c2", "c3"] {
        let change = agg.on_connection_events(
            &SingBoxConnectionEvents {
                reset: false,
                events: vec![SingBoxConnectionEvent {
                    kind: ConnectionEventType::New,
                    id: id.into(),
                    connection: Some(raw_conn(id, 1_000_000_000i64, 0, 0, "P")),
                    ..Default::default()
                }],
            },
            0,
        );
        if id == "c3" {
            assert!(change.upserts.contains_key("c3"));
            assert!(
                change.removed_ids.contains("c1"),
                "OOM 驱逐也必须通知 detail 前端移除旧行"
            );
        }
    }
    assert_eq!(agg.conn_count(), 2); // 超上限驱逐最旧
                                     // c1（最早插入）被驱逐，剩 c2/c3
    let e = agg.entries();
    let ids: Vec<&str> = e.iter().map(|c| c.id.as_str()).collect();
    assert!(ids.contains(&"c2"));
    assert!(ids.contains(&"c3"));
    assert!(!ids.contains(&"c1"));
}

#[test]
fn lru_update_moves_active_entry_to_end_protecting_from_eviction() {
    // #167：活跃长连接仅走 UPDATE 帧，delete+set 把它移到插入序末尾 → 驱逐删的是最久未更新的死连接。
    let mut agg = StatsAggregator::with_max_conn_map_size(2);
    // 建 c1（旧）、c2（新）
    for id in ["c1", "c2"] {
        agg.on_connection_events(
            &SingBoxConnectionEvents {
                reset: false,
                events: vec![SingBoxConnectionEvent {
                    kind: ConnectionEventType::New,
                    id: id.into(),
                    connection: Some(raw_conn(id, 1_000_000_000i64, 0, 0, "P")),
                    ..Default::default()
                }],
            },
            0,
        );
    }
    // UPDATE c1 → 移到末尾（变成 [c2, c1]）
    agg.on_connection_events(
        &SingBoxConnectionEvents {
            reset: false,
            events: vec![SingBoxConnectionEvent {
                kind: ConnectionEventType::Update,
                id: "c1".into(),
                uplink_delta: 5,
                ..Default::default()
            }],
        },
        0,
    );
    // 再加 c3 → 超上限驱逐最旧（现在是 c2，不是 c1）
    agg.on_connection_events(
        &SingBoxConnectionEvents {
            reset: false,
            events: vec![SingBoxConnectionEvent {
                kind: ConnectionEventType::New,
                id: "c3".into(),
                connection: Some(raw_conn("c3", 1_000_000_000i64, 0, 0, "P")),
                ..Default::default()
            }],
        },
        0,
    );
    let e = agg.entries();
    let ids: Vec<&str> = e.iter().map(|c| c.id.as_str()).collect();
    assert!(ids.contains(&"c1"), "活跃的 c1 应被 LRU 保护");
    assert!(ids.contains(&"c3"));
    assert!(!ids.contains(&"c2"), "最久未更新的 c2 应被驱逐");
}

#[test]
fn reset_clears_snapshot_and_conns() {
    let mut agg = StatsAggregator::new();
    agg.on_status(
        &SingBoxStatus {
            uplink_total: 1000,
            downlink_total: 2000,
            connections_in: 3,
            ..Default::default()
        },
        0,
    );
    agg.on_connection_events(
        &SingBoxConnectionEvents {
            reset: false,
            events: vec![SingBoxConnectionEvent {
                kind: ConnectionEventType::New,
                id: "c1".into(),
                connection: Some(raw_conn("c1", 1_000_000_000i64, 0, 0, "P")),
                ..Default::default()
            }],
        },
        0,
    );
    agg.reset();
    assert_eq!(agg.snapshot(), TrafficStats::zeroed());
    assert_eq!(agg.conn_count(), 0);
    assert!(agg.entries().is_empty());
}

#[test]
fn detail_change_sends_static_fields_once_then_counters_and_removal() {
    let mut agg = StatsAggregator::new();
    let created = agg.on_connection_events(
        &SingBoxConnectionEvents {
            reset: false,
            events: vec![SingBoxConnectionEvent {
                kind: ConnectionEventType::New,
                id: "c1".into(),
                connection: Some(raw_conn("c1", 1_000_000_000i64, 0, 0, "P")),
                ..Default::default()
            }],
        },
        0,
    );
    assert_eq!(created.upserts.len(), 1);
    assert!(created.counters.is_empty());
    assert!(created.removed_ids.is_empty());

    let updated = agg.on_connection_events(
        &SingBoxConnectionEvents {
            reset: false,
            events: vec![SingBoxConnectionEvent {
                kind: ConnectionEventType::Update,
                id: "c1".into(),
                uplink_delta: 5,
                downlink_delta: 7,
                ..Default::default()
            }],
        },
        0,
    );
    assert!(
        updated.upserts.is_empty(),
        "既有连接 UPDATE 不应重复静态字段"
    );
    assert_eq!(updated.counters["c1"].upload, 5);
    assert_eq!(updated.counters["c1"].download, 7);

    let closed = agg.on_connection_events(
        &SingBoxConnectionEvents {
            reset: false,
            events: vec![SingBoxConnectionEvent {
                kind: ConnectionEventType::Closed,
                id: "c1".into(),
                ..Default::default()
            }],
        },
        0,
    );
    assert_eq!(
        closed.removed_ids,
        std::collections::HashSet::from(["c1".into()])
    );
    assert_eq!(agg.conn_count(), 0);
}

#[test]
fn reset_change_defers_full_baseline_materialization() {
    let mut agg = StatsAggregator::new();
    let change = agg.on_connection_events(
        &SingBoxConnectionEvents {
            reset: true,
            events: vec![new_ev("c1"), new_ev("c2")],
        },
        0,
    );
    assert!(change.reset);
    assert!(change.upserts.is_empty());
    assert!(change.counters.is_empty());
    assert!(change.removed_ids.is_empty());
    assert_eq!(agg.entries().len(), 2, "完整基线留到实际 emit 时读取");
}

#[test]
fn created_at_to_rfc3339_nanoseconds() {
    // 1_000_000_000_000_000_000 ns = 1e18 → ms = 1e12 → 2001-09-09 01:46:40 UTC
    let s = created_at_to_rfc3339(1_000_000_000_000_000_000i64).unwrap();
    assert!(s.starts_with("2001-09-09T01:46:40"), "got {s}");
    assert!(s.ends_with('Z'));
}

#[test]
fn created_at_to_rfc3339_zero_or_negative_is_none() {
    assert!(created_at_to_rfc3339(0).is_none());
    assert!(created_at_to_rfc3339(-1).is_none());
}

#[test]
fn trim_connection_maps_all_fields() {
    let raw = SingBoxConnection {
        id: "conn-1".into(),
        source: "1.2.3.4:1234".into(),
        destination: "5.6.7.8:443".into(),
        domain: "example.com".into(),
        network: "tcp".into(),
        inbound_type: "Tun".into(),
        rule: "geoip".into(),
        chain_list: vec!["proxy".into()],
        uplink_total: 111,
        downlink_total: 222,
        created_at: 1_000_000_000_000_000_000i64,
        process_info: crate::types::SingBoxProcessInfo {
            process_path: "/usr/bin/curl".into(),
            ..Default::default()
        },
        ..Default::default()
    };
    let e = trim_connection(&raw);
    assert_eq!(e.id, "conn-1");
    assert_eq!(e.chains, vec!["proxy"]);
    assert_eq!(e.rule, "geoip");
    let m = e.metadata.unwrap();
    assert_eq!(m.host.as_deref(), Some("example.com"));
    assert_eq!(m.destination_ip.as_deref(), Some("5.6.7.8"));
    assert_eq!(m.destination_port.as_deref(), Some("443"));
    assert_eq!(m.source_ip.as_deref(), Some("1.2.3.4"));
    assert_eq!(m.source_port.as_deref(), Some("1234"));
    assert_eq!(m.network.as_deref(), Some("tcp"));
    assert_eq!(m.inbound_type.as_deref(), Some("Tun"));
    assert_eq!(m.process_path.as_deref(), Some("/usr/bin/curl"));
    assert_eq!(e.upload, Some(111));
    assert_eq!(e.download, Some(222));
    assert!(e.start.unwrap().starts_with("2001-"));
}

#[test]
fn trim_connection_bounds_all_untrusted_display_payloads() {
    let raw = SingBoxConnection {
        id: "identity-must-not-be-truncated".repeat(100),
        source: format!("{}:{}", "1".repeat(1000), "2".repeat(1000)),
        destination: format!("{}:{}", "3".repeat(1000), "4".repeat(1000)),
        domain: "域".repeat(1000),
        network: "n".repeat(1000),
        inbound_type: "i".repeat(1000),
        rule: "r".repeat(5000),
        chain_list: (0..40).map(|_| "链".repeat(500)).collect(),
        process_info: crate::types::SingBoxProcessInfo {
            process_path: "路".repeat(5000),
            ..Default::default()
        },
        ..Default::default()
    };
    let expected_id = raw.id.clone();
    let entry = trim_connection(&raw);
    assert_eq!(entry.id, expected_id, "身份字段不能裁剪或制造碰撞");
    assert!(entry.rule.len() <= CONNECTION_RULE_MAX_BYTES);
    assert_eq!(entry.chains.len(), CONNECTION_CHAIN_MAX_ITEMS);
    assert!(entry
        .chains
        .iter()
        .all(|chain| chain.len() <= CONNECTION_CHAIN_ITEM_MAX_BYTES));
    let metadata = entry.metadata.expect("oversized fields remain present");
    assert!(metadata.host.unwrap().len() <= CONNECTION_HOST_MAX_BYTES);
    assert!(metadata.network.unwrap().len() <= CONNECTION_KIND_MAX_BYTES);
    assert!(metadata.inbound_type.unwrap().len() <= CONNECTION_KIND_MAX_BYTES);
    assert!(metadata.process_path.unwrap().len() <= CONNECTION_PROCESS_PATH_MAX_BYTES);
    for part in [
        metadata.source_ip,
        metadata.source_port,
        metadata.destination_ip,
        metadata.destination_port,
    ] {
        assert!(part.unwrap().len() <= CONNECTION_ADDRESS_PART_MAX_BYTES);
    }
}

#[test]
fn topology_invalidation_ignores_counter_only_frames() {
    let mut counters_only = ConnectionsDetailChange::default();
    counters_only.counters.insert(
        "conn".into(),
        ConnectionCounters {
            id: "conn".into(),
            upload: 1,
            download: 2,
        },
    );
    assert!(!counters_only.affects_topology());

    let reset = ConnectionsDetailChange {
        reset: true,
        ..ConnectionsDetailChange::default()
    };
    assert!(reset.affects_topology());

    let mut removed = ConnectionsDetailChange::default();
    removed.removed_ids.insert("conn".into());
    assert!(removed.affects_topology());

    let mut upserted = ConnectionsDetailChange::default();
    upserted.upserts.insert(
        "conn".into(),
        ConnectionEntry {
            id: "conn".into(),
            ..ConnectionEntry::default()
        },
    );
    assert!(upserted.affects_topology());
}

// ══════════════════════════════════════════════════════════════════════════
// 长驻流批：reset 重建 / 幽灵过滤 / 溢出 / 双投影
// ══════════════════════════════════════════════════════════════════════════

/// 帮手：造一帧 NEW（活连接）。
fn new_ev(id: &str) -> SingBoxConnectionEvent {
    SingBoxConnectionEvent {
        kind: ConnectionEventType::New,
        id: id.into(),
        connection: Some(raw_conn(id, 1_000_000_000i64, 0, 0, "P")),
        ..Default::default()
    }
}

/// 帮手：造一帧 NEW，但连接已死（closed_at > 0）—— 内核历史环在 reset 帧里就是这个形状。
fn dead_ev(id: &str) -> SingBoxConnectionEvent {
    let mut c = raw_conn(id, 1_000_000_000i64, 0, 0, "P");
    c.closed_at = 1_700_000_000_000i64;
    SingBoxConnectionEvent {
        kind: ConnectionEventType::New,
        id: id.into(),
        connection: Some(c),
        ..Default::default()
    }
}

/// 🔴 **reset 帧必须整表替换，不能当增量叠加** —— 长驻流下最容易错、后果最隐蔽的一条。
///
/// 触发路径：窗口隐藏 → 我们 drop 流；用户切回 → 重订阅 → 内核**必然**先发一帧
/// `reset=true` 全量表（`daemon/started_service.go:728`，在建 ticker 之前无条件 Send）。
/// 隐藏期间断掉的那些连接，其 CLOSED 事件**永远不会补发**（我们当时没在订阅），
/// 它们消失的唯一信号就是「不在这帧 reset 里」。
///
/// 故 reset 若被当成增量处理，那些连接会**永久滞留** —— 连接页列着早已断开的连线、
/// 字节数冻结不动、拓扑图连着不存在的出口，且此后再无任何事件能清掉它们
/// （只有下一次重订阅，而那次同样会被错误处理）。现象与「切换未断连」一模一样。
///
/// **变异探针**：`on_connection_events` 里删掉 `if events.reset { self.conn_map.clear(); }`
/// ⇒ 本测转红（表里会剩下 c-gone）。
///
/// ⚠️ 顺带纠正一个说法：这个 bug 的表现**不是「连接表翻倍」**。conn_map 以连接 id 为键，
/// reset 帧里重复下发的既有连接只会覆盖同键条目、不会重复计数。真正的伤害是上面这条
/// **幽灵滞留**（少删，不是多加）。
#[test]
fn reset帧整表替换而非增量叠加() {
    let mut agg = StatsAggregator::new();
    // 第一条流：两条活连接
    agg.on_connection_events(
        &SingBoxConnectionEvents {
            reset: true,
            events: vec![new_ev("c-keep"), new_ev("c-gone")],
        },
        0,
    );
    assert_eq!(agg.conn_count(), 2);

    // 流断（窗口隐藏）→ 期间 c-gone 断开，CLOSED 事件我们没收到 → 重订阅的 reset 帧里没有它
    agg.on_connection_events(
        &SingBoxConnectionEvents {
            reset: true,
            events: vec![new_ev("c-keep"), new_ev("c-new")],
        },
        0,
    );

    let ids: Vec<String> = agg.entries().into_iter().map(|c| c.id).collect();
    assert_eq!(agg.conn_count(), 2, "reset 必须整表替换（实得 {ids:?}）");
    assert!(
        !ids.contains(&"c-gone".to_string()),
        "流断期间消失的连接必须随 reset 一起蒸发 —— 它的 CLOSED 永不会补发，\
             reset 是唯一能清掉它的信号（实得 {ids:?}）"
    );
    assert!(ids.contains(&"c-keep".to_string()));
    assert!(ids.contains(&"c-new".to_string()));
}

/// 🔴 **reset 帧里的死连接历史环整批被丢弃**（幽灵过滤，重订阅路径的实战形状）。
///
/// `buildInitialConnectionState`（`daemon/started_service.go:794`）把 `manager.Connections()`
/// **和** `manager.ClosedConnections()`（最近 ≤1000 条死连接）**都当 NEW 下发**，
/// 唯一区别是后者 `ClosedAt` 非零。这些死连接不进服务端 snapshots ⇒ **永不补发 CLOSED**。
/// 照收即永久幽灵。
///
/// 每次重订阅都会重放这批 ≤1000 条，故这条过滤是有界性的另一半：
/// 没有它，反复隐藏/恢复几次就能把连接表堆到 OOM 安全网的量级。
///
/// **变异探针**：`apply_event` 的 NEW 分支去掉 `if c.closed_at <= 0` ⇒ 转红（1000 条死连接全进表）。
#[test]
fn reset帧里的死连接历史环整批丢弃() {
    let mut agg = StatsAggregator::new();
    let mut events: Vec<SingBoxConnectionEvent> =
        (0..1000).map(|i| dead_ev(&format!("dead-{i}"))).collect();
    events.push(new_ev("live-1"));
    events.push(new_ev("live-2"));
    agg.on_connection_events(
        &SingBoxConnectionEvents {
            reset: true,
            events,
        },
        0,
    );

    assert_eq!(
        agg.conn_count(),
        2,
        "内核历史环的 ≤1000 条死连接必须一条不留 —— 它们永不补发 CLOSED，进表即永久幽灵"
    );
    assert_eq!(agg.snapshot().active_connections, 2);
}

/// 帮手：造一帧 NEW，连接来自主核测速探测池第 `k` 槽（`probe-in-{k}` 入站）。
///
/// tag **必须**经 config-engine 的 [`probe_pool_inbound_tag`] 生成，不许写字面量 ——
/// 这样「消费端把前缀硬编码成别的字符串」才会转红：生成端一改名，本帧的 tag 跟着变，
/// 硬编码的过滤当场失配。测试里再抄一份字面量，等于把同源性这条判据废掉。
fn probe_ev(id: &str, k: usize, host: &str) -> SingBoxConnectionEvent {
    let mut c = raw_conn(id, 1_000_000_000i64, 0, 0, "probe-selector");
    c.inbound = probe_pool_inbound_tag(k);
    c.domain = host.to_string();
    SingBoxConnectionEvent {
        kind: ConnectionEventType::New,
        id: id.into(),
        connection: Some(c),
        ..Default::default()
    }
}

/// 🔴 **主核测速探测连接不进连接表**（拓扑 / 明细 / 总数三处同时干净）。
///
/// 测速经专属入站 `probe-in-{k}`（config-engine 起 K 个 http 回环入站 + `probe-selector-{k}`），
/// 这些连接是**应用自己的流量**。照收则每次测速拓扑图上闪一批 `www.gstatic.com`、明细表刷出
/// 一批用户从没发起过的连线、活跃连接数跟着跳。
///
/// 断言覆盖三个消费点，因为它们是**三条独立的读路径**：`conn_count`（表本身）、`entries`
/// （明细 topic）、`aggregate`（拓扑 + `total`）。
///
/// **变异探针**：
/// ① NEW 分支去掉 `!is_probe_pool_inbound_tag(...)` ⇒ 转红（三处全脏）。
/// ② 把判据挪到 `aggregate_connections` 之类的**投影**里滤 ⇒ `conn_count` / `entries` /
///    `active_connections` 三条断言转红（只有拓扑一处干净，正是「滤一个漏两个」）。
/// ③ 消费端把前缀抄成别的字面量 ⇒ 转红（tag 由 config-engine 的生成器给，见 [`probe_ev`]）。
#[test]
fn 测速探测池连接不进连接表() {
    let mut agg = StatsAggregator::new();
    agg.on_connection_events(
        &SingBoxConnectionEvents {
            reset: true,
            events: vec![
                new_ev("user-1"),
                probe_ev("probe-a", 0, "www.gstatic.com"),
                probe_ev("probe-b", 1, "www.gstatic.com"),
                probe_ev("probe-c", 7, "www.gstatic.com"),
                new_ev("user-2"),
            ],
        },
        0,
    );

    // ① 表本身
    let ids: Vec<String> = agg.entries().into_iter().map(|c| c.id).collect();
    assert_eq!(
        agg.conn_count(),
        2,
        "探测连接必须挡在表外，不是进表后再从某个视图里滤（实得 {ids:?}）"
    );
    // ② 明细 topic
    assert_eq!(ids, vec!["user-1".to_string(), "user-2".to_string()]);
    // ③ 活跃连接总数
    assert_eq!(agg.snapshot().active_connections, 2);
    // ④ 拓扑：测速目标域名一个都不该出现
    let topo = agg.aggregate(0);
    assert_eq!(topo.total, 2);
    assert!(
        !topo.hosts.iter().any(|h| h.name == "www.gstatic.com"),
        "拓扑图不该出现测速目标域名（实得 {:?}）",
        topo.hosts.iter().map(|h| &h.name).collect::<Vec<_>>()
    );
}

/// 🔴 **UPDATE 的补建腿同样挡探测池** —— 少了它，NEW 侧的过滤会被 100% 抵消。
///
/// NEW 分支刚把探测连接挡在表外，那条连接后续的每一帧 UPDATE 都必然落到「表里查不到」
/// 这一支。只要内核在 UPDATE 里带上 `connection`（补建腿存在就是为了这种帧），
/// 被挡掉的连接立刻从后门回来。这不是边角情形，是每条探测连接的**必经路径**。
///
/// **变异探针**：UPDATE 的 `else if let Some(c)` 腿去掉判据 ⇒ 转红。
#[test]
fn update补建腿不会把探测连接放回表里() {
    let mut agg = StatsAggregator::new();
    // NEW 先被挡掉
    agg.on_connection_events(
        &SingBoxConnectionEvents {
            reset: true,
            events: vec![probe_ev("probe-a", 0, "www.gstatic.com")],
        },
        0,
    );
    assert_eq!(agg.conn_count(), 0);

    // 随后的 UPDATE 带 connection（表里查不到 → 走补建腿）
    let mut c = raw_conn("probe-a", 1_000_000_000i64, 0, 0, "probe-selector");
    c.inbound = probe_pool_inbound_tag(0);
    c.domain = "www.gstatic.com".into();
    agg.on_connection_events(
        &SingBoxConnectionEvents {
            reset: false,
            events: vec![SingBoxConnectionEvent {
                kind: ConnectionEventType::Update,
                id: "probe-a".into(),
                connection: Some(c),
                uplink_delta: 1024,
                downlink_delta: 4096,
                ..Default::default()
            }],
        },
        0,
    );

    assert_eq!(
        agg.conn_count(),
        0,
        "补建腿把 NEW 侧刚挡掉的探测连接又放了回来 —— 过滤等于没做"
    );
    assert_eq!(agg.snapshot().active_connections, 0);
}

/// 🔴 **过滤前缀与 config-engine 同源**（不是消费端自己抄的一份字面量）。
///
/// 判据链：config-engine 用 [`probe_pool_inbound_tag`] **生成**入站 tag（`inbounds.rs` 建入站、
/// `route.rs` 钉死路由、`dns.rs` 钉死解析三处），stats-engine 用同一模块的
/// `is_probe_pool_inbound_tag` **消费**。两边共用一个常量 ⇒ 改名只需改一处、且不可能只改一半。
///
/// **变异探针**：把消费端判据换成任何自写字面量（`"probe-"` / `"probe-in"` / `"probe_in-"`…）
/// ⇒ 一旦它与生成端不再逐字相等，本测转红。
///
/// 反向腿同样钉死：非探测池入站（`mixed-in` / `tun-in` / `update-in` / 空 tag）**不许**被误伤 ——
/// 过滤放宽成 `starts_with("probe")` 之类会连别的入站一起吞掉，那是把用户流量藏起来。
#[test]
fn 探测池前缀取自config_engine并且不误伤其它入站() {
    for k in [0usize, 1, 9, 42] {
        let tag = probe_pool_inbound_tag(k);
        assert!(
            is_probe_pool_inbound_tag(&tag),
            "生成端给的 {tag} 必须被消费端认出 —— 认不出说明两边前缀已经不同源"
        );
    }
    for tag in ["", "mixed-in", "tun-in", "update-in", "probe-direct-in"] {
        assert!(
            !is_probe_pool_inbound_tag(tag),
            "{tag} 不是测速探测池入站，不该被过滤掉（那是在藏用户流量）"
        );
    }
}

/// 🟡 **CLOSED 立即移除，不设保留窗口**（本仓的口径，刻意与「保留刚断开的连接一段时间」相反）。
///
/// 判据：连接入表与拓扑投影都按 `closed_at <= 0` 过滤，
/// 明细页与拓扑图**从来**只显示活连接。若改成保留 N 秒，会同时得到两个坏结果：
/// ① 与既有 UI 语义相反（用户切换节点后期望旧连接立刻消失，见 上游「看着像切换未断连」那条注释）；
/// ② 给连接表引入一个按时间过期的第二套生命周期，而幽灵的有界性本来只靠「不进表」这一条就够了。
///
/// **变异探针**：CLOSED 分支改成「打标记但保留」⇒ 转红。
#[test]
fn closed事件立即移除不保留时间窗() {
    let mut agg = StatsAggregator::new();
    agg.on_connection_events(
        &SingBoxConnectionEvents {
            reset: true,
            events: vec![new_ev("c1"), new_ev("c2")],
        },
        0,
    );
    agg.on_connection_events(
        &SingBoxConnectionEvents {
            reset: false,
            events: vec![SingBoxConnectionEvent {
                kind: ConnectionEventType::Closed,
                id: "c1".into(),
                closed_at: 1_700_000_000_000i64,
                // 内核的 CLOSED 事件**带** connection（`applyConnectionEvent` 会填），
                // 故这里也带上：若实现误按「有 connection 就 insert」处理，本测转红。
                connection: Some({
                    let mut c = raw_conn("c1", 1_000_000_000i64, 0, 0, "P");
                    c.closed_at = 1_700_000_000_000i64;
                    c
                }),
                ..Default::default()
            }],
        },
        0,
    );
    let ids: Vec<String> = agg.entries().into_iter().map(|c| c.id).collect();
    assert_eq!(ids, vec!["c2".to_string()], "CLOSED 的连接必须当帧消失");
    assert_eq!(agg.snapshot().active_connections, 1);
}

/// 🟡 **UPDATE 累加溢出必须饱和，不得 panic。**
///
/// 轮询时代每拍从内核重读全量 total，我们从不累加 ⇒ 溢出不可能。长驻流下这个字段是我们
/// **自己跨小时累加**出来的，一个畸形 delta 就能在 debug 构建里 panic 掉整条 relay 任务
/// （流断、连接页空白，日志里只有一行算术溢出）。
///
/// **变异探针**：`saturating_add` 改回 `+` ⇒ debug 下转红（attempt to add with overflow）。
#[test]
fn update累加溢出饱和不panic() {
    let mut agg = StatsAggregator::new();
    let mut c = raw_conn("c1", 1_000_000_000i64, 0, 0, "P");
    c.uplink_total = i64::MAX - 1;
    c.downlink_total = i64::MAX - 1;
    agg.on_connection_events(
        &SingBoxConnectionEvents {
            reset: true,
            events: vec![SingBoxConnectionEvent {
                kind: ConnectionEventType::New,
                id: "c1".into(),
                connection: Some(c),
                ..Default::default()
            }],
        },
        0,
    );
    agg.on_connection_events(
        &SingBoxConnectionEvents {
            reset: false,
            events: vec![SingBoxConnectionEvent {
                kind: ConnectionEventType::Update,
                id: "c1".into(),
                uplink_delta: i64::MAX,
                downlink_delta: i64::MAX,
                ..Default::default()
            }],
        },
        0,
    );
    assert_eq!(agg.conn_count(), 1, "溢出不得吃掉连接");
    assert_eq!(agg.entries()[0].upload, Some(i64::MAX as u64));
}

/// 🟡 **aggregate 与 detail 是同一张连接表的两种投影**（两条 topic 共用一条上游流的根据）。
///
/// **变异探针**：让 `aggregate()` 从别处取数（例如漏掉 OOM 驱逐后的表）⇒ 两个投影的
/// 连接总数对不上 ⇒ 转红。
#[test]
fn aggregate与detail是同一张表的两种投影() {
    let mut agg = StatsAggregator::new();
    agg.on_connection_events(
        &SingBoxConnectionEvents {
            reset: true,
            events: vec![new_ev("c1"), new_ev("c2"), new_ev("c3"), dead_ev("d1")],
        },
        0,
    );
    let detail = agg.entries();
    let topo = agg.aggregate(42);
    assert_eq!(detail.len(), 3);
    assert_eq!(
        topo.total as usize,
        detail.len(),
        "拓扑总数必须等于明细条数 —— 两者是同一张表的两种看法，对不上就说明取了两份数据"
    );
    assert_eq!(topo.at, 42);
    assert_eq!(agg.snapshot().active_connections as usize, detail.len());
}
