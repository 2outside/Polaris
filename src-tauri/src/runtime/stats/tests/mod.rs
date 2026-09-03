use super::*;
// 只被本测试模块引用的项（`should_warn_visibility_failure` / `ClosedHistoryChange` 等）不进
// façade 的 `use`（`-D warnings` 下 façade 的未用导入是红），按域直取。
use super::gate::*;
use super::projection::*;
use super::relay::*;
use super::subscription::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use polaris_singbox_grpc::daemon;
use polaris_stats_engine::{
    aggregate_signature, ConnectionEventType, ConnectionsAggregate, EmitGate, SingBoxConnection,
    SingBoxConnectionEvent, SingBoxConnectionEvents, SingBoxStatus, StatsAggregator, Topic,
    TrafficStats,
};

// ══════════════════════════════════════════════════════════════════════════════
// 真机验证（BUG-1 aggregate relay 数据面）—— `#[ignore]`，需 POLARIS_SINGBOX_PATH。
//
//   POLARIS_SINGBOX_PATH=<某个可用的 sing-box 二进制路径> \
//     cargo test -p polaris --bin polaris -- --ignored --nocapture real_core_aggregate
//
// 走**真核 + 真 h2c gRPC + 真连接**，验证 relay 的实际路径：
//   proxy.start(config)（BUG-2：真配置起真核）
//   → first_connection_snapshot（复用热切换批的首帧快照）
//   → build_aggregate（daemon::Connection → 聚合，死连接过滤）
//   → signature_changed（change-driven 去重）。
//
// 安全硬约束（对齐 proxy.rs 真机测试）：config 恒 manual + 全局直连 + 仅 127.0.0.1 混合入站
// → 不接管系统网络、无 TUN、无系统代理；流量只打本地回显服务器（不出网）。
// ══════════════════════════════════════════════════════════════════════════════
mod real_core_tests;

/// impl 内方法的源码切片工具（`guard_scan::top_level_fn_body` 只认列 0 的右花括号，
/// 对 impl 里的方法会一路切到整个 impl 结束 → 守卫可被「删这里、加那里」骗过）。
use crate::runtime::core_update_scheduler::method_scan::method_body;
// 取材面 = **模块** `runtime/stats`（`runtime/stats.rs` 根文件 + `runtime/stats/**` 递归，
// 剔除 `tests/`）。`stats.rs` 正在按域拆成 `stats/{gate,projection,subscription,relay}.rs`，
// 写死单文件锚点会在拆分那天把取材面砍成门面一份：下面 10 处里的切片锚点会 panic（体面），
// 而计数型与否定型断言会静默偏/恒真。`module_source` 递归取材 ⇒ 新增的任何
// `stats/**.rs` 自动进面。
use crate::test_support::{crate_code, module_code};

fn conn(id: &str, domain: &str, chain: &str) -> daemon::Connection {
    daemon::Connection {
        id: id.to_string(),
        domain: domain.to_string(),
        chain_list: vec![chain.to_string()],
        rule: "final".to_string(),
        ..Default::default()
    }
}

fn engine_conn(id: &str, closed_at: i64) -> SingBoxConnection {
    SingBoxConnection {
        id: id.to_string(),
        domain: format!("{id}.example"),
        chain_list: vec!["hk".to_string()],
        closed_at,
        ..Default::default()
    }
}

#[test]
fn closed_history_is_newest_first_and_capped_to_history_limit() {
    let events = SingBoxConnectionEvents {
        reset: true,
        events: (1..=1_002)
            .map(|n| SingBoxConnectionEvent {
                kind: ConnectionEventType::New,
                connection: Some(engine_conn(&format!("c{n}"), n)),
                ..Default::default()
            })
            .collect(),
    };
    let mut history = ClosedHistory::default();
    assert!(matches!(
        history.apply_events(&events, &StatsAggregator::new()),
        Some(ClosedHistoryChange::Reset { .. })
    ));
    assert_eq!(history.entries.len(), MAX_CLOSED_HISTORY);
    assert_eq!(history.entries.first().unwrap().closed_at, 1_002);
    assert_eq!(history.entries.last().unwrap().closed_at, 3);
}

#[test]
fn short_reset_replay_preserves_accumulated_session_history() {
    let mut history = ClosedHistory::default();
    let initial = SingBoxConnectionEvents {
        reset: true,
        events: (1..=MAX_CLOSED_HISTORY)
            .map(|n| SingBoxConnectionEvent {
                kind: ConnectionEventType::New,
                connection: Some(engine_conn(&format!("c{n}"), n as i64)),
                ..Default::default()
            })
            .collect(),
    };
    history
        .apply_events(&initial, &StatsAggregator::new())
        .expect("首帧 reset 必须产生完整基线");

    // 流重订时内核只重放自己的短历史环。它是“当前流的基线”，不是
    // “Polaris 本会话诊断历史的完整真值”，不能把此前 1000 条清成 2 条。
    let short_replay = SingBoxConnectionEvents {
        reset: true,
        events: vec![
            SingBoxConnectionEvent {
                kind: ConnectionEventType::New,
                connection: Some(engine_conn("c1000", 1_000)),
                ..Default::default()
            },
            SingBoxConnectionEvent {
                kind: ConnectionEventType::New,
                connection: Some(engine_conn("c1001", 1_001)),
                ..Default::default()
            },
        ],
    };
    assert!(matches!(
        history.apply_events(&short_replay, &StatsAggregator::new()),
        Some(ClosedHistoryChange::Reset { .. })
    ));
    assert_eq!(history.entries.len(), MAX_CLOSED_HISTORY);
    assert_eq!(history.entries.first().unwrap().entry.id, "c1001");
    assert_eq!(history.entries.last().unwrap().entry.id, "c2");
}

#[test]
fn clearing_closed_history_blocks_old_reset_replay_but_keeps_new_closes() {
    let mut history = ClosedHistory::default();
    history.clear(500);
    let events = SingBoxConnectionEvents {
        reset: true,
        events: vec![
            SingBoxConnectionEvent {
                kind: ConnectionEventType::New,
                connection: Some(engine_conn("old", 499)),
                ..Default::default()
            },
            SingBoxConnectionEvent {
                kind: ConnectionEventType::New,
                connection: Some(engine_conn("new", 501)),
                ..Default::default()
            },
        ],
    };
    assert!(matches!(
        history.apply_events(&events, &StatsAggregator::new()),
        Some(ClosedHistoryChange::Reset { .. })
    ));
    assert_eq!(history.entries.len(), 1);
    assert_eq!(history.entries[0].entry.id, "new");
}

#[test]
fn closed_event_without_payload_uses_active_entry_before_removal() {
    let mut active = StatsAggregator::new();
    active.on_connection_events(
        &SingBoxConnectionEvents {
            reset: false,
            events: vec![SingBoxConnectionEvent {
                kind: ConnectionEventType::New,
                connection: Some(engine_conn("live", 0)),
                ..Default::default()
            }],
        },
        0,
    );
    let closed = SingBoxConnectionEvents {
        reset: false,
        events: vec![SingBoxConnectionEvent {
            kind: ConnectionEventType::Closed,
            id: "live".to_string(),
            closed_at: 700,
            ..Default::default()
        }],
    };
    let mut history = ClosedHistory::default();
    assert!(matches!(
        history.apply_events(&closed, &active),
        Some(ClosedHistoryChange::Delta { .. })
    ));
    assert_eq!(history.entries[0].entry.id, "live");
    active.on_connection_events(&closed, 0);
    assert_eq!(
        active.conn_count(),
        0,
        "活动表仍按 CLOSED 删除，不被历史污染"
    );
}

#[test]
fn closed_history_delta_only_carries_touched_and_evicted_entries() {
    let mut history = ClosedHistory::default();
    let reset = SingBoxConnectionEvents {
        reset: true,
        events: (1..=MAX_CLOSED_HISTORY)
            .map(|n| SingBoxConnectionEvent {
                kind: ConnectionEventType::New,
                connection: Some(engine_conn(&format!("c{n}"), n as i64)),
                ..Default::default()
            })
            .collect(),
    };
    history
        .apply_events(&reset, &StatsAggregator::new())
        .expect("reset 必须产生首帧");

    let delta = SingBoxConnectionEvents {
        reset: false,
        events: vec![SingBoxConnectionEvent {
            kind: ConnectionEventType::Closed,
            connection: Some(engine_conn("c1001", 1_001)),
            ..Default::default()
        }],
    };
    let change = history
        .apply_events(&delta, &StatsAggregator::new())
        .expect("新 CLOSED 必须产生增量");
    let ClosedHistoryChange::Delta {
        connections,
        removed_ids,
        ..
    } = change
    else {
        panic!("常态 CLOSED 不应升格为 reset");
    };
    assert_eq!(connections.len(), 1, "不得夹带其余 999 条历史");
    assert_eq!(connections[0].entry.id, "c1001");
    assert_eq!(removed_ids, vec!["c1"]);

    let same = history.apply_events(&delta, &StatsAggregator::new());
    assert!(same.is_none(), "完全相同的重放不应制造空增量");
}

#[test]
fn clear_generation_discards_pending_pre_clear_delta() {
    let mut history = ClosedHistory::default();
    let event = SingBoxConnectionEvents {
        reset: false,
        events: vec![SingBoxConnectionEvent {
            kind: ConnectionEventType::Closed,
            connection: Some(engine_conn("old", 10)),
            ..Default::default()
        }],
    };
    let change = history
        .apply_events(&event, &StatsAggregator::new())
        .expect("前置增量");
    let mut pending = PendingClosedUpdate::default();
    pending.merge(change);
    history.clear(20);
    assert!(
        pending.take_update(&history, 30).is_none(),
        "清空前的在途增量不得在清空后 emit"
    );
}

#[test]
fn maps_daemon_connection_fields() {
    let c = daemon::Connection {
        id: "c1".into(),
        source: "1.2.3.4:1234".into(),
        destination: "5.6.7.8:443".into(),
        domain: "example.com".into(),
        network: "tcp".into(),
        inbound_type: "Tun".into(),
        rule: "geoip".into(),
        chain_list: vec!["hk".into()],
        uplink_total: 111,
        downlink_total: 222,
        process_info: Some(daemon::ProcessInfo {
            process_path: "/usr/bin/curl".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let e = daemon_conn_to_entry(&c);
    assert_eq!(e.id, "c1");
    assert_eq!(e.chains, vec!["hk"]);
    let m = e.metadata.unwrap();
    assert_eq!(m.host.as_deref(), Some("example.com"));
    assert_eq!(m.destination_ip.as_deref(), Some("5.6.7.8"));
    assert_eq!(m.destination_port.as_deref(), Some("443"));
    assert_eq!(m.process_path.as_deref(), Some("/usr/bin/curl"));
    assert_eq!(e.upload, Some(111));
    assert_eq!(e.download, Some(222));
}

#[test]
fn build_aggregate_counts_and_excludes_dead_connections() {
    let mut dead = conn("dead", "dead.com", "hk");
    dead.closed_at = 1_000_000_000; // 历史环死连接 → 必须被过滤
    let conns = vec![
        conn("c0", "a.com", "hk"),
        conn("c1", "a.com", "hk"),
        conn("c2", "b.com", "us"),
        dead,
    ];
    let agg = build_aggregate(&conns, 0);
    assert_eq!(agg.total, 3, "死连接不计入 total");
    let a = agg.hosts.iter().find(|h| h.name == "a.com").unwrap();
    assert_eq!(a.count, 2);
    assert!(
        agg.hosts.iter().all(|h| h.name != "dead.com"),
        "死连接不建 host 节点"
    );
    let hk = agg.outbounds.iter().find(|o| o.name == "hk").unwrap();
    assert_eq!(hk.count, 2);
}

// ── change-driven 去重的变异门（BUG-1 relay 核心）──
// 打断 emit（signature_changed 恒 None）→ `first_frame_emits` 转红；
// 打断去重（signature_changed 恒 Some）→ `same_content_deduped` 转红。

#[test]
fn first_frame_emits() {
    let agg = build_aggregate(&[conn("c0", "a.com", "hk")], 0);
    // 无上帧签名 → 必推（Some）。
    assert!(signature_changed(&agg, &None).is_some());
}

#[test]
fn same_content_deduped() {
    // 同内容、不同采样时刻 at → 签名相同（at 被剔）→ 去重（None）。
    let agg1 = build_aggregate(&[conn("c0", "a.com", "hk")], 1000);
    let sig = aggregate_signature(&agg1);
    let agg2 = build_aggregate(&[conn("c0", "a.com", "hk")], 9_999_999);
    assert!(
        signature_changed(&agg2, &Some(sig)).is_none(),
        "内容不变（仅 at 变）应去重不推"
    );
}

#[test]
fn content_change_emits_new_signature() {
    let agg1 = build_aggregate(&[conn("c0", "a.com", "hk")], 0);
    let sig = aggregate_signature(&agg1);
    // 多一条连接 → host 计数变 → 签名变 → 推。
    let agg2 = build_aggregate(&[conn("c0", "a.com", "hk"), conn("c1", "a.com", "hk")], 0);
    assert!(signature_changed(&agg2, &Some(sig)).is_some());
}

// ── detail topic：generation/sequence + 1s 增量合并 ──

#[test]
fn detail_reset_materializes_one_full_baseline() {
    let mut table = StatsAggregator::new();
    let change = table.on_connection_events(
        &SingBoxConnectionEvents {
            reset: true,
            events: vec![SingBoxConnectionEvent {
                kind: ConnectionEventType::New,
                connection: Some(engine_conn("live", 0)),
                ..Default::default()
            }],
        },
        0,
    );
    let mut pending = PendingDetailUpdate::default();
    pending.begin_generation(1);
    pending.merge(change);
    let update = pending.take_update(&table, 4_242).expect("reset 基线");
    assert!(update.reset);
    assert_eq!(update.generation, 1);
    assert_eq!(update.sequence, 1);
    assert_eq!(update.at, 4_242);
    assert_eq!(update.connections.len(), 1);
    assert_eq!(update.connections[0].id, "live");
    assert_eq!(
        update.connections[0]
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.host.as_deref()),
        Some("live.example")
    );
    assert!(update.counters.is_empty());
    assert!(update.removed_ids.is_empty());
}

#[test]
fn detail_normal_frame_only_sends_counters_and_heartbeat() {
    let mut table = StatsAggregator::new();
    let mut pending = PendingDetailUpdate::default();
    pending.begin_generation(1);
    pending.merge(table.on_connection_events(
        &SingBoxConnectionEvents {
            reset: true,
            events: vec![SingBoxConnectionEvent {
                kind: ConnectionEventType::New,
                connection: Some(engine_conn("live", 0)),
                ..Default::default()
            }],
        },
        0,
    ));
    pending.take_update(&table, 1).expect("首帧");

    pending.merge(table.on_connection_events(
        &SingBoxConnectionEvents {
            reset: false,
            events: vec![SingBoxConnectionEvent {
                kind: ConnectionEventType::Update,
                id: "live".to_string(),
                uplink_delta: 111,
                downlink_delta: 222,
                ..Default::default()
            }],
        },
        0,
    ));
    let delta = pending.take_update(&table, 2).expect("计数增量");
    assert!(!delta.reset);
    assert_eq!(delta.generation, 1);
    assert_eq!(delta.sequence, 2);
    assert!(delta.connections.is_empty(), "既有连接不得重复静态字段");
    assert_eq!(delta.counters.len(), 1);
    assert_eq!(delta.counters[0].upload, 111);
    assert_eq!(delta.counters[0].download, 222);

    pending.merge(table.on_connection_events(&SingBoxConnectionEvents::default(), 0));
    let heartbeat = pending.take_update(&table, 3).expect("空增量心跳");
    assert_eq!(heartbeat.sequence, 3);
    assert!(heartbeat.connections.is_empty());
    assert!(heartbeat.counters.is_empty());
    assert!(heartbeat.removed_ids.is_empty());
}

#[test]
fn detail_new_reset_starts_new_generation_and_sequence() {
    let mut table = StatsAggregator::new();
    let mut pending = PendingDetailUpdate::default();
    for (generation, id) in ["first", "second"].into_iter().enumerate() {
        pending.begin_generation(generation as u64 + 1);
        pending.merge(table.on_connection_events(
            &SingBoxConnectionEvents {
                reset: true,
                events: vec![SingBoxConnectionEvent {
                    kind: ConnectionEventType::New,
                    connection: Some(engine_conn(id, 0)),
                    ..Default::default()
                }],
            },
            0,
        ));
        let update = pending.take_update(&table, 0).expect("每代 reset");
        assert!(update.reset);
        assert_eq!(update.sequence, 1);
    }
    assert_eq!(pending.generation, 2);
}

#[test]
fn detail_window_coalesces_new_update_and_close_by_id() {
    let mut table = StatsAggregator::new();
    let mut pending = PendingDetailUpdate::default();
    pending.begin_generation(1);
    pending.merge(table.on_connection_events(
        &SingBoxConnectionEvents {
            reset: true,
            events: Vec::new(),
        },
        0,
    ));
    pending.take_update(&table, 0).expect("空基线");

    pending.merge(table.on_connection_events(
        &SingBoxConnectionEvents {
            reset: false,
            events: vec![SingBoxConnectionEvent {
                kind: ConnectionEventType::New,
                connection: Some(engine_conn("live", 0)),
                ..Default::default()
            }],
        },
        0,
    ));
    pending.merge(table.on_connection_events(
        &SingBoxConnectionEvents {
            reset: false,
            events: vec![SingBoxConnectionEvent {
                kind: ConnectionEventType::Update,
                id: "live".to_string(),
                uplink_delta: 9,
                downlink_delta: 8,
                ..Default::default()
            }],
        },
        0,
    ));
    let upsert = pending.take_update(&table, 1).expect("合并后的 upsert");
    assert_eq!(upsert.connections.len(), 1);
    assert_eq!(upsert.connections[0].upload, Some(9));
    assert_eq!(upsert.connections[0].download, Some(8));
    assert!(
        upsert.counters.is_empty(),
        "同窗计数应折进 NEW，不重复传两份"
    );

    pending.merge(table.on_connection_events(
        &SingBoxConnectionEvents {
            reset: false,
            events: vec![SingBoxConnectionEvent {
                kind: ConnectionEventType::Closed,
                id: "live".to_string(),
                ..Default::default()
            }],
        },
        0,
    ));
    let removed = pending.take_update(&table, 2).expect("删除增量");
    assert_eq!(removed.removed_ids, vec!["live"]);
    assert!(removed.connections.is_empty());
    assert!(removed.counters.is_empty());
}

// ── BUG-P2-1：停核 offline 帧（首页拓扑 / StatusBar 不得停在旧数据）──

/// 停核 → 必须推一帧空聚合（total=0 / 无 host），且**只推一帧**（签名去重天然边沿触发）。
/// 打断 `offline_aggregate_frame` 里的 `emit(agg)` → 本测第一段转红。
#[test]
fn offline_aggregate_frame_emits_empty_once_then_dedupes() {
    // 停核前的最后一帧：有连接。
    let live = build_aggregate(&[conn("c0", "a.com", "hk")], 0);
    let last_sig = Some(aggregate_signature(&live));

    // 进入停核态 → 推一帧空聚合。
    let mut emitted: Vec<ConnectionsAggregate> = Vec::new();
    let sig = offline_aggregate_frame(&last_sig, 1_000, |a| emitted.push(a));
    assert!(
        sig.is_some(),
        "停核必须推空帧（否则首页拓扑停在旧 host 列表）"
    );
    assert_eq!(emitted.len(), 1, "恰好一帧");
    assert_eq!(emitted[0].total, 0, "空聚合：连接数归零");
    assert!(emitted[0].hosts.is_empty(), "空聚合：旧 host 列表必须清掉");

    // 核仍停着的后续每一轮 → 去重，不重推（否则渲染端每秒白重渲一次）。
    let mut again: Vec<ConnectionsAggregate> = Vec::new();
    assert!(
        offline_aggregate_frame(&sig, 9_999, |a| again.push(a)).is_none(),
        "停核态逐秒重推内容相同的空帧 = 白重渲"
    );
    assert!(again.is_empty());
}

/// 核回来后的首帧内容非空 → 签名与空签名不同 → 必推（停核态不得把核恢复后的首帧吃掉）。
#[test]
fn aggregate_emits_again_after_core_returns() {
    let empty_sig = offline_aggregate_frame(&None, 0, |_| {}).expect("首次 offline 必推");
    let live = build_aggregate(&[conn("c0", "a.com", "hk")], 0);
    assert!(
        signature_changed(&live, &Some(empty_sig)).is_some(),
        "核恢复后的真实首帧必须推（否则首页恒空）"
    );
}

/// 停核清零帧：速率 / 累计 / 连接数全 0（StatusBar 据此归零而非停格），**且键名是 TS 契约那五个**。
///
/// 键名这一半是本批新长出来的判据：帧载荷从手拼的 `json!` 换成了直接 `Serialize` 的
/// `TrafficStats`，少了 `rename_all` 就整帧变下划线名而两侧类型系统都不报错
/// （契约本体的锁在 `polaris_stats_engine` 的 `traffic_stats_json_keys_match_ts_contract`，
/// 本条锁的是**这条 emit 路径**真送出那份契约）。
#[test]
fn offline_stats_frame_is_all_zero() {
    let v = serde_json::to_value(offline_stats_frame()).expect("清零帧应可序列化");
    assert_eq!(v["uploadSpeed"], 0);
    assert_eq!(v["downloadSpeed"], 0);
    assert_eq!(v["totalUpload"], 0);
    assert_eq!(v["totalDownload"], 0);
    assert_eq!(v["activeConnections"], 0);
    assert_eq!(
        v.as_object().map(serde_json::Map::len),
        Some(5),
        "清零帧的键名/键数必须与 TS 契约一致（下划线名前端读不到，且两侧都不会报错）"
    );
}

/// 清零帧**不得污染速率基线**：核回来后的首帧速率必须是 0，而不是拿「停核期的 0」当基准，
/// 把核重启后的全部历史累计字节一次性算成瞬时速率（天文数字尖峰）。
///
/// 这条锁的是 `offline_stats_frame()` 是个**不碰任何差分状态**的常量帧这一签名约束：
/// 若改成从聚合器里取（`meter.on_status(&Default::default(), t); meter.snapshot()`），
/// 那次调用就把「停核期的 0」写进了基线，本测第二段转红。
#[test]
fn offline_stats_frame_does_not_poison_speed_baseline() {
    // 停核前跑过一帧，留下基线。
    let mut meter = StatsAggregator::new();
    meter.on_status(&status_totals(1_000_000, 1_000_000), 0);

    // 停核：推清零帧（不经聚合器）+ 生产代码紧接着 reset。
    let z = offline_stats_frame();
    assert_eq!(z, TrafficStats::zeroed());
    meter.reset();

    // 核回来：首帧带巨大历史累计 → 速率必须是 0（无基线），不得是尖峰。
    meter.on_status(&status_totals(9_000_000, 9_000_000), 1_000);
    let s = meter.snapshot();
    assert_eq!(
        s.upload_speed, 0,
        "核重启后首帧速率必须 0，不得把历史累计算成尖峰"
    );
    assert_eq!(s.download_speed, 0);
}

// ── BUG-P2-3：relay spawn 侧 TOCTOU 闸门 ──

/// spawn 决策：已在跑 → 不起（单例）；零订阅者 → 不起（TOCTOU：并发 unsubscribe 已退光）。
/// 打断计数条件（`!slot_occupied`）→ `零订阅者` 用例转红；打断单例条件 → `已在跑` 用例转红。
#[test]
fn should_spawn_poller_requires_free_slot_and_live_subscriber() {
    assert!(should_spawn_poller(false, 1), "空 slot + 有订阅 → 起");
    assert!(
        !should_spawn_poller(false, 0),
        "零订阅者绝不起 relay（否则上游流永久开着、无人能停）"
    );
    assert!(!should_spawn_poller(true, 1), "已在跑 → 幂等 no-op");
    assert!(!should_spawn_poller(true, 0));
}

/// 同一 renderer 上下文重复挂载/并发 invoke 只能占一个 token；否则一次 unsubscribe 只删第一项，
/// 余下 token 会永久撑开 registry、让上游流再也停不下来。
#[test]
fn duplicate_window_topic_subscription_is_idempotent() {
    let relay = StatsRelay::new();
    assert!(relay
        .register_subscription("main", Topic::Connections)
        .unwrap());
    assert!(!relay
        .register_subscription("main", Topic::Connections)
        .unwrap());
    assert_eq!(relay.subs.lock().unwrap().len(), 1);
    assert_eq!(relay.connections_subscriber_count(), 1);

    relay.unsubscribe("main", "aggregate");
    assert!(relay.subs.lock().unwrap().is_empty());
    assert_eq!(relay.connections_subscriber_count(), 0);
}

// ── BUG-P2-2：clear_window 清账（webview reload 后旧上下文订阅无人退订）──

/// reload：旧上下文的订阅无人退订，label 仍是 "main" → 必须由 clear_window 清账 + 停 relay，
/// 否则计数恒 ≥1、停机闸门恒拦 → 上游流永久开着、`subs` 无界累积。
/// 打断 clear_window 的 registry 退订循环 → 本测转红。
#[test]
fn clear_window_drops_all_subs_and_stops_pollers() {
    let relay = StatsRelay::new();
    let connection_epoch = relay.connection_lifecycle.start_task(|| {});
    // 模拟旧 JS 上下文的全部 topic 订阅（经真实记账路径入账）。
    for (topic, slot) in [
        (Topic::Connections, &relay.connections),
        (Topic::Stats, &relay.stats_poller),
        (Topic::Topology, &relay.connections),
        (Topic::Detail, &relay.connections),
        (Topic::Closed, &relay.connections),
    ] {
        let token = relay.gate.registry.lock().unwrap().subscribe(topic, "main");
        relay
            .subs
            .lock()
            .unwrap()
            .push(("main".to_string(), topic, token));
        let epoch = (topic != Topic::Stats).then_some(connection_epoch);
        *slot.lock().unwrap() = Some(dummy_poller(epoch));
    }
    assert_eq!(
        relay.connections_subscriber_count(),
        4,
        "连接流的计数是四条需求之和（漏算 topology = 只开首页时整条流被误停）"
    );

    relay.clear_window("main");

    assert_eq!(
        relay.connections_subscriber_count(),
        0,
        "reload 后旧订阅必须清账"
    );
    assert_eq!(relay.stats_subscriber_count(), 0);
    assert!(
        relay.subs.lock().unwrap().is_empty(),
        "subs 记账清空（否则无界累积）"
    );
    assert!(
        relay.connections.lock().unwrap().is_none(),
        "无订阅者 → 连接流必停"
    );
    assert!(relay.stats_poller.lock().unwrap().is_none());
}

/// clear_window 只清目标窗口：其它窗口的订阅与 poller 不得被误清。
#[test]
fn clear_window_spares_other_windows() {
    let relay = StatsRelay::new();
    let token = relay
        .gate
        .registry
        .lock()
        .unwrap()
        .subscribe(Topic::Stats, "other");
    relay
        .subs
        .lock()
        .unwrap()
        .push(("other".to_string(), Topic::Stats, token));
    *relay.stats_poller.lock().unwrap() = Some(dummy_poller(None));

    relay.clear_window("main");

    assert_eq!(relay.stats_subscriber_count(), 1, "别的窗口的订阅不得被清");
    assert!(
        relay.stats_poller.lock().unwrap().is_some(),
        "仍有订阅 → relay 不得停"
    );
}

/// 🔴 **令牌从关到开 → 即使聚合内容与上次相同，也必须发一帧。**
///
/// 这条守的是排名页的空窗：切走再切回时它的 `aggregate` state 回到 `null`，而后端的 `last_sig`
/// 还停在上一轮。网络恰好安静（或表变回旧形态）时，签名去重会把基线帧吞掉 ⇒ 排名页空着，
/// 直到下一次拓扑变化 —— 直接违反「及时性」不变量。
///
/// **变异探针**：删 `*last_sig = None` ⇒ 第二段「同内容也必须发」转红；删 `emit.note_change()`
/// ⇒ 「必须记待推」转红；把条件从 `open && (baseline_requested || !was_open)` 放宽成 `open`
/// ⇒ 「保持开不得动状态」转红；删掉 `baseline_requested ||` 那条边沿腿 ⇒ 「电平没变但有新订阅者」
/// 那段转红。
#[test]
fn 排名令牌翻开必须清签名并强制一帧() {
    let mut last_sig = Some("SIG-A".to_string());
    let mut emit = EmitGate::new(AGGREGATE_EMIT_MIN_INTERVAL);
    assert!(apply_aggregate_demand_transition(
        true,
        false,
        false,
        &mut last_sig,
        &mut emit
    ));
    assert!(
        last_sig.is_none(),
        "签名基线必须作废 —— 否则内容与上次相同时基线帧会被去重吞掉"
    );
    assert!(
        emit.is_pending(),
        "必须记一次待推 —— 只清签名的话，基线帧要等下一次拓扑变化才发得出去"
    );

    // 正向对照：同一份聚合，清签名前被去重、清签名后必发。
    let agg = build_aggregate(&[], 1_000);
    let mut stale = Some(aggregate_signature(&agg));
    assert!(
        signature_changed(&agg, &stale).is_none(),
        "对照组：签名未作废 → 同内容被去重（这正是空窗的来源）"
    );
    apply_aggregate_demand_transition(true, false, false, &mut stale, &mut emit);
    assert!(
        signature_changed(&agg, &stale).is_some(),
        "令牌翻开后：内容与上次逐字相同也必须发一帧"
    );

    // 🔴 边沿腿：**电平没变**（一直开着）但有新订阅者进场 —— 退订+重订两次 bump 被 watch 合并
    // 掉时就是这个形态。只靠电平比对会把它整个漏掉，新订阅者一直空到下一次拓扑变化。
    let mut merged = Some("SIG-M".to_string());
    let mut merged_emit = EmitGate::new(AGGREGATE_EMIT_MIN_INTERVAL);
    assert!(apply_aggregate_demand_transition(
        true,
        true,
        true,
        &mut merged,
        &mut merged_emit
    ));
    assert!(
        merged.is_none() && merged_emit.is_pending(),
        "电平合并窗：边沿标志必须独立触发基线，否则新订阅者拿不到首帧"
    );
    // 门关着时边沿不得兑现（没有消费者，强制的帧纯白付）。
    let mut closed_sig = Some("SIG-C".to_string());
    let mut closed_emit = EmitGate::new(AGGREGATE_EMIT_MIN_INTERVAL);
    assert!(!apply_aggregate_demand_transition(
        false,
        false,
        true,
        &mut closed_sig,
        &mut closed_emit
    ));
    assert_eq!(closed_sig.as_deref(), Some("SIG-C"));
    assert!(!closed_emit.is_pending());

    // 保持开 / 开→关 / 保持关（且无边沿）：一律不得动签名基线，也不得凭空造待推（会白发一帧）。
    let mut sig = Some("SIG-B".to_string());
    let mut idle = EmitGate::new(AGGREGATE_EMIT_MIN_INTERVAL);
    assert!(apply_aggregate_demand_transition(
        true, true, false, &mut sig, &mut idle
    ));
    assert!(!apply_aggregate_demand_transition(
        false, true, false, &mut sig, &mut idle
    ));
    assert!(!apply_aggregate_demand_transition(
        false, false, false, &mut sig, &mut idle
    ));
    assert_eq!(sig.as_deref(), Some("SIG-B"), "非翻开转换不得动签名基线");
    assert!(!idle.is_pending(), "非翻开转换不得凭空造待推");
}

/// 🔴 **边沿标志的 owner 与接线**：旧任务不得偷账，当前任务只兑现一次，别的 topic 不得置。
///
/// 上一条只证「函数收到 `baseline_requested=true` 时会做对的事」，置账那一端断了它照绿 ——
/// 而置账断掉的表现正是本条要挡的空窗。
///
/// **变异探针**：在 `consume_aggregate_baseline` 里先 `take` 再判 epoch ⇒ 新任务拿不到账；
/// 删 `subscribe` 里的 request ⇒ 接线守卫转红；把置账条件放宽成任意 topic ⇒ 末段转红。
#[test]
fn 排名订阅必须记一笔基线欠账且只兑现一次() {
    let lifecycle = ConnectionStreamLifecycle::default();
    let old_epoch = lifecycle.start_task(|| {});
    assert_eq!(
        lifecycle.consume_aggregate_baseline(old_epoch),
        Some(false),
        "正常缺省不得欠账"
    );
    lifecycle.request_aggregate_baseline();
    assert!(lifecycle.retire(old_epoch, || {}));
    let new_epoch = lifecycle.start_task(|| {});
    assert_eq!(
        lifecycle.consume_aggregate_baseline(old_epoch),
        None,
        "旧任务必须先被 epoch 拒绝，不能清标志"
    );
    assert_eq!(
        lifecycle.consume_aggregate_baseline(new_epoch),
        Some(true),
        "旧任务被拒后，基线欠账必须完整留给新任务"
    );
    assert_eq!(
        lifecycle.consume_aggregate_baseline(new_epoch),
        Some(false),
        "当前任务取走即清，不能在下一轮兑现陈账"
    );

    // 接线端：只有 aggregate 订阅置账（topology / detail / closed 不消费聚合载荷）。
    // `subscribe` 是 `impl` 内的方法，不能用 `top_level_fn_body`（它按列 0 的 `}` 封顶 ⇒ 会一路
    // 切到整个 impl 块末尾，射程盖住后面十几个方法，`contains` 类断言随即形同虚设）。
    let src = module_code("runtime/stats");
    let body = method_body(&src, "    pub fn subscribe(");
    let wire = body
        .find("self.connection_lifecycle.request_aggregate_baseline();")
        .expect("订阅侧没记基线欠账 —— 电平合并窗下新订阅者会一直空着");
    let bump = body
        .find("self.gate.bump();")
        .expect("bump 锚点消失，本守卫已失去判据");
    assert!(
        wire < bump,
        "必须先置账再 bump：bump 立刻唤醒流任务，倒过来就有一轮读不到这笔账"
    );
    assert!(
        body.contains("if topic == Topic::Connections {"),
        "置账必须限定在 aggregate topic —— 别的 topic 不消费聚合载荷，置了就是每次订阅白发一帧"
    );
}

/// 🟡 **源码型守卫**：开合转换真被接在流循环里、排在 emit 之前；且新流必然作废签名基线。
///
/// 上一条只证「函数本身对」，接线断了它照绿。而这两件事都只能落在源码上：转换排到 emit 之后
/// ⇒ 基线帧晚一轮；新流不清 `last_sig` ⇒ 断流跨越几分钟后首帧仍可能被旧签名去重吞掉。
///
/// **变异探针**：把 `apply_aggregate_demand_transition(` 那一跳删掉 ⇒ 首段 `expect` 转红；
/// 把它挪到 `if agg_emit.should_emit(now) {` 之后 ⇒ 顺序断言转红；删建流处的 `last_sig = None;`
/// ⇒ 末段转红。
#[test]
fn 令牌转换与新流基线都接在连接流循环里() {
    let src = module_code("runtime/stats");
    let body =
        crate::commands::guard_scan::top_level_fn_body(&src, "async fn run_connections_stream(");
    let transition = body
        .find("apply_aggregate_demand_transition(")
        .expect("开合转换没接进流循环 —— 令牌翻开时排名页会空窗到下一次拓扑变化");
    let take = body
        .find("lifecycle.consume_aggregate_baseline(task_epoch)")
        .expect("边沿标志没人消费 —— 电平合并窗下新订阅者拿不到基线，且陈账会一直挂着");
    assert!(
        take < transition,
        "边沿标志必须先取走再喂进转换：取在后面等于本轮用的是上一轮的账"
    );
    let emit = body
        .find("if agg_emit.should_emit(now) {")
        .expect("aggregate emit 闸门锚点消失，本守卫已失去判据");
    assert!(
        transition < emit,
        "开合转换必须排在 emit 之前，否则强制的那一帧要晚一整轮"
    );
    // 锚点取建流复位段自己那两行（`agg_emit.reset()` 与 `let mut detail_was_open`，各只出现一次）：
    // 用 `offline_sent = false;` 之类会先命中循环外的 `let mut` 声明行，判据形同虚设。
    let reset_block = body
        .find("agg_emit.reset();")
        .expect("建流复位段锚点消失，本守卫已失去判据");
    let baseline = body
        .find("last_sig = None;")
        .expect("建流处未作废签名基线 —— 断流跨几分钟后首帧仍可能被旧签名吞掉");
    let after_reset = body
        .find("let mut detail_was_open")
        .expect("建流复位段锚点消失，本守卫已失去判据");
    assert!(
        reset_block < baseline && baseline < after_reset,
        "签名基线的作废必须落在建流复位段里（与连接表 reset / 三条闸门 reset 同处）"
    );
}

/// 🔴 Closed 没有 generation/sequence，reset 与 delta 必须由同一 lifecycle mutex 排成全序。
///
/// 这里一条腿直证 external commit 的闭包执行期间 owner 仍被持有；另一条腿把三个生产调用点
/// 精确切到各自函数体，避免 command/subscribe 重新退化成“先拿 payload、释放锁、再裸广播”。
///
/// **变异探针**：在 `external_commit` 里拿锁后先 drop 再执行 effect ⇒ owner 断言转红；把任一
/// snapshot/clear 的 broadcast 搬到 helper 外 ⇒ 调用点 contract 转红。
#[test]
fn closed_reset_and_delta_share_one_lifecycle_commit_boundary() {
    let lifecycle = ConnectionStreamLifecycle::default();
    let epoch = lifecycle.start_task(|| {});
    let order = Mutex::new(Vec::new());

    lifecycle.external_commit(|| {
        assert!(
            lifecycle.is_locked_for_test(),
            "external effect 执行到 snapshot/clear+emit 时必须仍持 lifecycle owner"
        );
        order.lock().unwrap().push("external-reset");
    });
    lifecycle
        .commit(epoch, || order.lock().unwrap().push("relay-delta"))
        .expect("当前 relay epoch 应可提交");
    assert_eq!(
        *order.lock().unwrap(),
        vec!["external-reset", "relay-delta"],
        "两类 closed effect 必须经同一 owner 串行提交"
    );

    let subscription_src = crate_code("runtime/stats/subscription.rs");
    let subscribe = method_body(&subscription_src, "    pub fn subscribe(");
    assert!(subscribe.contains("self.emit_closed_snapshot(app);"));
    assert!(!subscribe.contains("EVENT_CONNECTIONS_CLOSED"));
    assert!(!subscribe.contains("broadcast("));

    let assert_inside_external_commit = |body: &str, label: &str| {
        let commit = body
            .find("self.connection_lifecycle.external_commit(")
            .unwrap_or_else(|| panic!("{label} 必须进入 external commit"));
        let event = body
            .find("EVENT_CONNECTIONS_CLOSED")
            .unwrap_or_else(|| panic!("{label} closed event 生产调用点消失"));
        let commit_end = body
            .rfind("\n        })")
            .unwrap_or_else(|| panic!("{label} external commit 封顶锚点消失"));
        assert!(
            commit < event && event < commit_end,
            "{label} 的 history effect 与 event 必须同在 external commit 闭包内"
        );
    };
    let snapshot = method_body(&subscription_src, "    fn emit_closed_snapshot(");
    assert!(snapshot.contains("broadcast(app, EVENT_CONNECTIONS_CLOSED, update);"));
    assert_inside_external_commit(&snapshot, "subscribe snapshot");

    let clear = method_body(&subscription_src, "    pub fn clear_closed_history(");
    assert!(clear.contains("history.clear(now_ns());"));
    assert!(clear.contains("snapshot"));
    assert_inside_external_commit(&clear, "command clear");

    let command_src = crate_code("commands/stats.rs");
    let command =
        crate::commands::guard_scan::top_level_fn_body(&command_src, "pub fn stats_closed_clear(");
    assert!(command.contains("clear_closed_history(&app)"));
    for forbidden in [
        "EVENT_CONNECTIONS_CLOSED",
        "ConnectionsClosedUpdate",
        "broadcast(",
    ] {
        assert!(
            !command_src.contains(forbidden),
            "command 层不得持有 closed emit 能力：{forbidden}"
        );
    }

    let relay_src = crate_code("runtime/stats/relay.rs");
    let relay = crate::commands::guard_scan::top_level_fn_body(
        &relay_src,
        "async fn run_connections_stream(",
    );
    let closed_start = relay
        .find("if closed_emit.should_emit(now) {")
        .expect("closed emit 段锚点消失，本守卫已失去判据");
    let closed_rest = &relay[closed_start..];
    let closed_end = closed_rest
        .find("closed_emit.mark_emitted(now);")
        .expect("closed emit 封顶锚点消失，本守卫已失去判据");
    let closed_block = &closed_rest[..closed_end];
    let commit = closed_block
        .find(".commit(task_epoch, || {")
        .expect("relay closed delta 必须走当前 epoch commit");
    let event = closed_block
        .find("EVENT_CONNECTIONS_CLOSED")
        .expect("relay closed delta 生产调用点消失");
    let commit_end = closed_block[commit..]
        .find("\n                        })\n                        .is_none()")
        .map(|offset| commit + offset)
        .expect("relay closed epoch commit 封顶锚点消失");
    assert!(
        commit < event && event < commit_end,
        "closed delta emit 必须位于 epoch commit 闭包内"
    );

    assert_eq!(
        subscription_src.matches("EVENT_CONNECTIONS_CLOSED").count(),
        3,
        "subscription 中只允许 import + snapshot helper + clear helper 三处引用"
    );
    assert_eq!(
        relay_src.matches("EVENT_CONNECTIONS_CLOSED").count(),
        2,
        "relay 中只允许 import + epoch commit delta 两处引用"
    );
}

#[test]
fn parse_topic_maps_aggregate_to_connections() {
    assert_eq!(parse_topic("aggregate"), Some(Topic::Connections));
    assert_eq!(parse_topic("stats"), Some(Topic::Stats));
    assert_eq!(parse_topic("detail"), Some(Topic::Detail));
    assert_eq!(parse_topic("closed"), Some(Topic::Closed));
    assert_eq!(parse_topic("bogus"), None);
    // `topology`（首页流向信号）必须落在**自己**的 topic 上：映回 `Connections` 就等于首页在场
    // 时排名聚合永远在算，本次拆分整个作废。
    assert_eq!(parse_topic("topology"), Some(Topic::Topology));
    assert_ne!(parse_topic("topology"), parse_topic("aggregate"));
}

// ── BUG-D：relay start/stop TOCTOU 闸门 ──
// stop_* 在 slot 锁下复查订阅计数：仍有订阅 → 绝不停（否则留活订阅无 relay，数据面冻结）。
// 直接装占位 relay 进 slot（不经 ensure，避免真起后台流），断言守卫决策，不依赖时序竞态。

/// 造一个不驱动任何真实数据面的占位 relay（stop flag + 立即完成的空任务句柄）。
fn dummy_poller(connection_epoch: Option<u64>) -> AggregatePoller {
    AggregatePoller {
        stop: Arc::new(AtomicBool::new(false)),
        connection_epoch,
        handle: tauri::async_runtime::spawn(async {}),
    }
}

#[test]
fn stop_stats_stream_keeps_running_while_subscriber_remains() {
    let relay = StatsRelay::new();
    *relay.stats_poller.lock().unwrap() = Some(dummy_poller(None));
    // 模拟并发 subscribe 已重新计数（见 slot=Some 依赖现有 poller）。
    let token = relay
        .gate
        .registry
        .lock()
        .unwrap()
        .subscribe(Topic::Stats, "w1");
    assert_eq!(relay.stats_subscriber_count(), 1);

    relay.stop_stats_stream();
    assert!(
        relay.stats_poller.lock().unwrap().is_some(),
        "仍有活订阅 → 闸门必须拦住 stop（否则 liveness gap）"
    );

    // 退订到 0 → stop 正常生效。
    relay
        .gate
        .registry
        .lock()
        .unwrap()
        .unsubscribe(Topic::Stats, token);
    assert_eq!(relay.stats_subscriber_count(), 0);
    relay.stop_stats_stream();
    assert!(
        relay.stats_poller.lock().unwrap().is_none(),
        "无订阅 → 正常停 relay"
    );
}

/// 🔴 **TOCTOU 闸门 + 共用槽位：任一条投影还有订阅者，连接流就不许停。**
///
/// 取代了原来分列的 poller —— 三个 topic
/// 现在共用一条流一个槽位，分开测反而测不到真正的新风险：**只退订其中一条时误停整条流**
/// （现象是关掉首页拓扑后连接明细页跟着冻住，反之亦然）。
///
/// **变异探针**：`connections_subscriber_count` 改成只数一条 topic ⇒ 转红；
/// `stop_connections_stream` 里锁内那次复查删掉 ⇒ 第一段断言转红。
#[test]
fn stop_connections_stream_keeps_running_while_any_projection_remains() {
    let relay = StatsRelay::new();
    let epoch = relay.connection_lifecycle.start_task(|| {});
    *relay.connections.lock().unwrap() = Some(dummy_poller(Some(epoch)));
    let t_agg = relay
        .gate
        .registry
        .lock()
        .unwrap()
        .subscribe(Topic::Connections, "w1");
    let t_detail = relay
        .gate
        .registry
        .lock()
        .unwrap()
        .subscribe(Topic::Detail, "w1");
    let t_closed = relay
        .gate
        .registry
        .lock()
        .unwrap()
        .subscribe(Topic::Closed, "w1");
    assert_eq!(relay.connections_subscriber_count(), 3);

    relay.stop_connections_stream();
    assert!(
        relay.connections.lock().unwrap().is_some(),
        "三个投影都还订着 → 闸门必须拦住 stop"
    );

    // 只退订拓扑：明细还在看 → 流必须留着
    relay
        .gate
        .registry
        .lock()
        .unwrap()
        .unsubscribe(Topic::Connections, t_agg);
    relay.stop_connections_stream();
    assert!(
        relay.connections.lock().unwrap().is_some(),
        "只退订拓扑、明细仍订着 → 绝不能停整条流（否则连接明细页冻住）"
    );

    // 活动明细退订，已结束历史仍在看 → 流仍须保留
    relay
        .gate
        .registry
        .lock()
        .unwrap()
        .unsubscribe(Topic::Detail, t_detail);
    relay.stop_connections_stream();
    assert!(relay.connections.lock().unwrap().is_some());

    // 最后一条也退订 → 正常停
    relay
        .gate
        .registry
        .lock()
        .unwrap()
        .unsubscribe(Topic::Closed, t_closed);
    relay.stop_connections_stream();
    assert!(
        relay.connections.lock().unwrap().is_none(),
        "三个投影都无订阅 → 正常停流"
    );
}

/// 🔴 detail generation 的 owner 必须跨连接任务存活；sequence 则只在各代内编号。
///
/// **变异探针**：把 `next_detail_generation` 改回每个任务从 1 起，第二个任务的首帧 generation
/// 不再严格晚于旧任务末帧，本测转红。
#[test]
fn detail_generation_is_monotonic_across_connection_tasks() {
    let lifecycle = ConnectionStreamLifecycle::default();
    let table = Mutex::new(StatsAggregator::new());

    let first_epoch = lifecycle.start_task(|| table.lock().unwrap().reset());
    let mut first = PendingDetailUpdate::default();
    first.begin_generation(
        lifecycle
            .next_detail_generation(first_epoch)
            .expect("首任务持有 epoch"),
    );
    let first_reset = first
        .take_update(&table.lock().unwrap(), 1)
        .expect("首任务 reset");
    first.merge(
        table
            .lock()
            .unwrap()
            .on_connection_events(&SingBoxConnectionEvents::default(), 0),
    );
    let first_delta = first
        .take_update(&table.lock().unwrap(), 2)
        .expect("首任务增量");
    assert_eq!(first_reset.sequence, 1);
    assert_eq!(first_delta.sequence, 2);

    assert!(lifecycle.retire(first_epoch, || table.lock().unwrap().reset()));
    let second_epoch = lifecycle.start_task(|| table.lock().unwrap().reset());
    let mut second = PendingDetailUpdate::default();
    second.begin_generation(
        lifecycle
            .next_detail_generation(second_epoch)
            .expect("新任务持有新 epoch"),
    );
    let second_reset = second
        .take_update(&table.lock().unwrap(), 3)
        .expect("新任务首帧 reset");

    assert!(second_reset.reset);
    assert_eq!(second_reset.sequence, 1, "新代 sequence 可以从 1 开始");
    assert!(
        second_reset.generation > first_delta.generation,
        "新任务首个 reset generation 必须严格晚于旧任务已发代"
    );
}

/// 🔴 retire 是旧任务所有共享副作用的截止线；无需 sleep 或调度碰撞即可证明。
///
/// **变异探针**：删掉 `ConnectionStreamLifecycle::commit` 的 epoch compare，旧任务 closure 会清掉
/// 第二代新表并发出旧帧，本测同时在两条断言上转红。
#[test]
fn retired_epoch_cannot_clear_new_table_or_emit_old_frame() {
    let lifecycle = ConnectionStreamLifecycle::default();
    let table = Mutex::new(Vec::<&'static str>::new());
    let emitted = Mutex::new(Vec::<&'static str>::new());

    let old_epoch = lifecycle.start_task(|| table.lock().unwrap().clear());
    lifecycle
        .commit(old_epoch, || table.lock().unwrap().push("old"))
        .expect("旧任务起初当权");
    assert!(lifecycle.retire(old_epoch, || table.lock().unwrap().clear()));

    let new_epoch = lifecycle.start_task(|| table.lock().unwrap().clear());
    lifecycle
        .commit(new_epoch, || table.lock().unwrap().push("new"))
        .expect("新任务当权");

    let stale = lifecycle.commit(old_epoch, || {
        table.lock().unwrap().clear();
        emitted.lock().unwrap().push("old-final-reset");
    });
    assert!(stale.is_none(), "retire 后旧 epoch 必须失去提交权");
    assert_eq!(*table.lock().unwrap(), vec!["new"]);
    assert!(emitted.lock().unwrap().is_empty());
}

// ── stats topic：Status 流数据面（EVENT_STATS_UPDATED 供数）──

/// 只带累计的 Status 帧（速率推导的最小夹具）。
fn status_totals(up: i64, down: i64) -> SingBoxStatus {
    SingBoxStatus {
        uplink_total: up,
        downlink_total: down,
        traffic_available: true,
        ..Default::default()
    }
}

/// 🔴 **prost `daemon::Status` → 纯逻辑 `SingBoxStatus` 必须逐字段搬到，一个不漏。**
///
/// 漏字段在这里是**静默**的：`..Default::default()` 把漏掉的那个填成 0，而 0 恰好是
/// 「没流量 / 没连接 / 统计不可用」这些完全合理的取值 —— 编译过、测试绿、UI 上只是永远显示 0。
/// 本批要修的原缺陷（`trafficAvailable` 曾被误 typed 成 `i64`）就是同一族。
///
/// **变异探针**：映射里删任一行（让它落进默认值）⇒ 转红。
#[test]
fn daemon_status_to_engine_carries_every_field() {
    let raw = daemon::Status {
        memory: 111,
        goroutines: 22,
        connections_in: 33,
        connections_out: 44,
        traffic_available: true,
        uplink: 55,
        downlink: 66,
        uplink_total: 777,
        downlink_total: 888,
    };
    assert_eq!(
        daemon_status_to_engine(&raw),
        SingBoxStatus {
            memory: 111,
            goroutines: 22,
            connections_in: 33,
            connections_out: 44,
            traffic_available: true,
            uplink: 55,
            downlink: 66,
            uplink_total: 777,
            downlink_total: 888,
        }
    );
}

/// 🔴 **`trafficAvailable=false` 必须发出可观测信号，且只在变化沿发。**
///
/// 核内没有 `trafficManager` 时 `SubscribeStatus` **不报错**，只是把累计/连接数三个字段留成 0：
/// UI 表现是「0 B/s 且零报错」，与「真的没流量」逐像素一致。不判它 = 这条故障永远查不出来。
///
/// **变异探针**：把判据改成恒 false（= 不判、静默）⇒ 第一段转红；改成恒 true（= 每帧一条日志，
/// 每秒一条噪音把真信号淹掉）⇒ 第二段转红。
#[test]
fn traffic_availability_reports_only_on_change() {
    assert!(
        traffic_availability_changed(None, false),
        "新流的第一帧必须报一次（哪怕值一直是 false，也得让人看见一次）"
    );
    assert!(traffic_availability_changed(None, true), "首帧必报");
    assert!(
        !traffic_availability_changed(Some(true), true),
        "值没变就别每秒喊一遍 —— 噪音会把真信号淹掉"
    );
    assert!(!traffic_availability_changed(Some(false), false));
    assert!(
        traffic_availability_changed(Some(true), false),
        "true → false（统计刚失效）必须立刻喊"
    );
    assert!(
        traffic_availability_changed(Some(false), true),
        "false → true（恢复）也该记一笔，否则日志里只有病、没有好"
    );
}

/// 首帧：速率 0（无基线），累计 + 活跃连接数即刻真实。
///
/// **变异探针**：把首帧速率改成拿 `uplink_total` 本身（或拿 `Status.uplink`）⇒ 第一段转红。
#[test]
fn stats_first_frame_reports_zero_speed_with_real_totals() {
    let mut meter = StatsAggregator::new();
    meter.on_status(
        &SingBoxStatus {
            uplink_total: 100,
            downlink_total: 900,
            connections_in: 3,
            traffic_available: true,
            ..Default::default()
        },
        0,
    );
    let s = meter.snapshot();
    assert_eq!(s.upload_speed, 0, "首帧无基线 → 速率 0");
    assert_eq!(s.download_speed, 0);
    assert_eq!(s.total_upload, 100);
    assert_eq!(s.total_download, 900);
    assert_eq!(s.active_connections, 3, "活跃连接数取 Status.connectionsIn");
}

/// 🔴 **速率的分母是实测 Δt，不是请求里那个 `STATS_STREAM_INTERVAL_NS`。**
///
/// 服务端 ticker 的实际间隔含调度抖动、wire 上也不回传，把常量当分母就是拿期望值冒充实测值。
/// 本例故意让实测 Δt（2s）≠ 请求间隔（1s）：拿常量当分母会实得 4000/8000。
///
/// **变异探针**：分母换成 `STATS_STREAM_INTERVAL_NS / 1_000_000_000` ⇒ 转红；
/// 直接用 `Status.uplink` 当速率 ⇒ 实得 1 ⇒ 转红。
#[test]
fn stats_speed_divides_by_measured_dt_not_the_requested_interval() {
    let mut meter = StatsAggregator::new();
    meter.on_status(&status_totals(1_000, 2_000), 10_000);
    meter.on_status(
        &SingBoxStatus {
            uplink: 1, // 诱饵：内核这个字段不是速率
            downlink: 2,
            ..status_totals(5_000, 10_000)
        },
        12_000, // 实测 Δt = 2s ≠ 请求的 1s
    );
    let s = meter.snapshot();
    assert_eq!(s.upload_speed, 2_000, "(5000-1000)/2s");
    assert_eq!(s.download_speed, 4_000, "(10000-2000)/2s");
}

// ══════════════════════════════════════════════════════════════════════════
// 降流门（维度7）：两条长驻流都过 `should_stream`（订阅集 × 可见性）
//
// 被测对象是两条 relay 真正调用的那个点 —— `StreamGate::wait_until`。全部 topic 只有
// 一种降流机制（drop 流），故门测试只有这一套夹具；`PollGate`（轮询时代的「park 一拍」）
// 随 stats 换流一并删除，继续拿它测就是在测一个生产里已不存在的形状。
//
// 变异锁（下列转红结果均为**实跑**，非推演）：
//  - 拿掉 `wait_until` 里的判定（无条件放行）→ 4 例转红：`park_gated_topic_when_window_hidden` /
//    `park_any_topic_without_subscriber` / `park_after_last_subscriber_leaves` /
//    `可见性翻回true_立刻恢复`。
//  - 拿掉 `watch` 唤醒（只留超时兜底）→ `可见性翻回true_立刻恢复` 转红（恢复要等满兜底周期）。
//  - 把 `StreamGate::stats` 的 `demand` 换成 `should_stream_connections`（两条流共用一条判据）
//    → `三topic各自独立判定` 转红（只订 stats 时 Status 流不开、连接流反被拉起）。
// 用虚拟时钟（`start_paused`）：兜底回读周期不占真实时间，测试恒毫秒级。
// ══════════════════════════════════════════════════════════════════════════

use std::sync::atomic::AtomicBool as GateFlag;

/// 连接长驻流的门夹具（需求 = aggregate ∪ detail ∪ closed）。
///
/// 必须走生产同一个构造器：测试自己拼 `StreamGate { .. }` 就等于给测试造了一条与生产
/// 无关的判据，门测试会全部失去判据。
fn test_stream_gate() -> (Arc<StreamGateState>, StreamGate, Arc<GateFlag>) {
    let state = Arc::new(StreamGateState::new());
    let gate = StreamGate::connections(state.clone());
    (state, gate, Arc::new(GateFlag::new(true)))
}

/// Status 长驻流的门夹具（需求 = stats topic）。
fn test_stats_gate() -> (Arc<StreamGateState>, StreamGate, Arc<GateFlag>) {
    let state = Arc::new(StreamGateState::new());
    let gate = StreamGate::stats(state.clone());
    (state, gate, Arc::new(GateFlag::new(true)))
}

/// 门**开着**时 `wait_until(false, ..)` 必须一直不返回（流继续跑），反之亦然。
/// 用远大于兜底周期的虚拟时限：判定若反了会立刻返回 → 转红。
async fn assert_gate_holds(gate: &mut StreamGate, want: bool, visible: &Arc<GateFlag>, why: &str) {
    let src = flag_visibility_source(visible.clone());
    assert!(
        tokio::time::timeout(Duration::from_secs(30), gate.wait_until(want, &src))
            .await
            .is_err(),
        "{why}"
    );
}

/// 可见性源（替代生产里那个「读缓存 + 投主线程刷新」的 [`visibility_source`]）：
/// 读一个可随时翻转的 flag，注入点与生产完全同一处（`StreamGate::wait_until` 的入参）。
fn flag_visibility_source(flag: Arc<GateFlag>) -> impl Fn() -> bool {
    move || flag.load(Ordering::Relaxed)
}

/// 可见性 false + 有订阅 → **全部 topic**断流（不收、不 emit）。
///
/// 覆盖面含 Stats：门控口径一致后，隐藏态下一条 gRPC 都不该剩。
#[tokio::test(start_paused = true)]
async fn park_gated_topic_when_window_hidden() {
    // stats（Status 流）：门关 = 流不该开着。
    let (state, mut gate, visible) = test_stats_gate();
    state
        .registry
        .lock()
        .unwrap()
        .subscribe(Topic::Stats, "main");
    visible.store(false, Ordering::Relaxed);
    assert_gate_holds(
        &mut gate,
        true,
        &visible,
        "窗口隐藏 + 有 stats 订阅 → Status 流必须保持断开，绝不再收帧 + emit",
    )
    .await;

    // aggregate / detail / closed（连接流）：门关 = 流不该开着。
    for topic in [
        Topic::Connections,
        Topic::Topology,
        Topic::Detail,
        Topic::Closed,
    ] {
        let (state, mut gate, visible) = test_stream_gate();
        state.registry.lock().unwrap().subscribe(topic, "main");
        visible.store(false, Ordering::Relaxed);
        assert_gate_holds(
            &mut gate,
            true,
            &visible,
            "窗口隐藏 + 有连接订阅 → 连接流必须保持断开，绝不再收事件 + emit",
        )
        .await;
    }
}

/// 无订阅者 → 两条流都不开。
#[tokio::test(start_paused = true)]
async fn park_any_topic_without_subscriber() {
    let (_state, mut gate, visible) = test_stats_gate();
    assert_gate_holds(
        &mut gate,
        true,
        &visible,
        "无 stats 订阅者 → 无人消费，Status 流必须保持断开",
    )
    .await;

    let (_state, mut sgate, visible) = test_stream_gate();
    assert_gate_holds(
        &mut sgate,
        true,
        &visible,
        "四条连接需求都没订阅者 → 连接流必须保持断开",
    )
    .await;
}

/// 退订到零 → 原本放行的门必须翻成 park（订阅集是门的另一条腿）。
/// 🔴 **四条需求都退订才断流；任一仍在看时流必须留着。**
///
/// **变异探针**：`should_stream_connections` 改成 `&&`（或 `stop_connections_stream` 的
/// 计数改成只看一条 topic）⇒ 「关掉首页但连接页还开着」时流被停掉 ⇒ 转红。
#[tokio::test(start_paused = true)]
async fn park_after_last_subscriber_leaves() {
    let (state, mut gate, visible) = test_stream_gate();
    let t_agg = state
        .registry
        .lock()
        .unwrap()
        .subscribe(Topic::Connections, "main");
    let t_detail = state
        .registry
        .lock()
        .unwrap()
        .subscribe(Topic::Detail, "main");
    let t_closed = state
        .registry
        .lock()
        .unwrap()
        .subscribe(Topic::Closed, "main");
    let t_topo = state
        .registry
        .lock()
        .unwrap()
        .subscribe(Topic::Topology, "main");
    let src = flag_visibility_source(visible.clone());
    tokio::time::timeout(Duration::from_secs(5), gate.wait_until(true, &src))
        .await
        .expect("有订阅 + 可见 → 流必须开");

    // 只退订排名聚合：其余三条还在看 → 流必须留着
    state
        .registry
        .lock()
        .unwrap()
        .unsubscribe(Topic::Connections, t_agg);
    assert_gate_holds(
        &mut gate,
        false,
        &visible,
        "只退订排名聚合、首页信号/活动/已结束仍订着 → 连接流绝不能断",
    )
    .await;

    // 活动明细也退订，首页信号与已结束历史仍在看 → 继续保持
    state
        .registry
        .lock()
        .unwrap()
        .unsubscribe(Topic::Detail, t_detail);
    assert_gate_holds(
        &mut gate,
        false,
        &visible,
        "首页信号与已结束历史仍订着 → 连接流绝不能断",
    )
    .await;

    // 🔴 只剩首页信号这一条：它同样是连接流的需求方，漏算它 = 只开着首页时拓扑冻结。
    state
        .registry
        .lock()
        .unwrap()
        .unsubscribe(Topic::Closed, t_closed);
    assert_gate_holds(
        &mut gate,
        false,
        &visible,
        "只剩首页流向信号 → 连接流绝不能断（它是需求方，不是搭便车的）",
    )
    .await;

    // 最后一条也退订 → 断流
    state
        .registry
        .lock()
        .unwrap()
        .unsubscribe(Topic::Topology, t_topo);
    let src = flag_visibility_source(visible.clone());
    tokio::time::timeout(Duration::from_secs(5), gate.wait_until(false, &src))
        .await
        .expect("最后一个订阅者退订 → 必须断流");
}

/// 可见性翻回 true → **立刻**恢复（不等下一拍整周期），用户切回窗口无可感知空窗。
#[tokio::test(start_paused = true)]
async fn 可见性翻回true_立刻恢复() {
    let (state, mut gate, visible) = test_stream_gate();
    state
        .registry
        .lock()
        .unwrap()
        .subscribe(Topic::Connections, "main");
    visible.store(false, Ordering::Relaxed);
    assert_gate_holds(&mut gate, true, &visible, "先确认确实断着流").await;

    // 另一条腿（main.rs 的 Focused 触发器）把可见性写回 true 并 bump 门代次。
    let waker = state.clone();
    let flag = visible.clone();
    tokio::spawn(async move {
        flag.store(true, Ordering::Relaxed);
        waker.set_window_visible(true);
    });

    let src = flag_visibility_source(visible.clone());
    let started = tokio::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(5), gate.wait_until(true, &src))
        .await
        .expect("可见性翻回 true 必须立刻重订阅");
    assert!(
        started.elapsed() < PARK_RECHECK_INTERVAL / 2,
        "恢复必须由门变更立刻唤醒（实测 {:?}），而不是等满一个 PARK_RECHECK_INTERVAL 的兜底回读",
        started.elapsed()
    );
}

/// 三 topic 各自独立判定：只订了 stats → Status 流开，连接流仍断着。
///
/// **变异探针**：把 `StreamGate::stats` 的 `demand` 换成 `should_stream_connections`
/// （两条流共用一条判据）⇒ 第一段转红（只订 stats 时 Status 流打不开）。
#[tokio::test(start_paused = true)]
async fn 三topic各自独立判定() {
    let state = Arc::new(StreamGateState::new());
    state
        .registry
        .lock()
        .unwrap()
        .subscribe(Topic::Stats, "main");
    let visible = Arc::new(GateFlag::new(true));
    let src = flag_visibility_source(visible.clone());

    let mut stats_gate = StreamGate::stats(state.clone());
    tokio::time::timeout(Duration::from_secs(5), stats_gate.wait_until(true, &src))
        .await
        .expect("有 stats 订阅 → Status 流必须开");

    let mut conn_gate = StreamGate::connections(state.clone());
    assert_gate_holds(
        &mut conn_gate,
        true,
        &visible,
        "只订了 stats 不该把连接长驻流拉起来 —— 它不消费连接表",
    )
    .await;
}

/// ★ 契约测试（口径一致 · 消费侧）：全部 topic 在同一可见性下**同进同退**。
///
/// 前身是 `stats_topic_不受可见性门控`，断言「Stats 隐藏也放行」。该差异化语义已作废
/// （理由见 `polaris_stats_engine::Topic::gated_by_visibility`：上游的 status 不门控是
/// worker demand 握手载体，Polaris 没有 worker、没有该握手；而 上游 广播侧
/// `StatsService.ts:312` / `StatsWorkerHost.ts:217` 本来就按可见性门控 stats）。
///
/// 本条不是「再测一遍 `park_*`」：它把全部 topic 放在**同一次可见性翻转**下逐条比对，
/// 任何一条被单独开成「隐藏也流」或「可见也不流」都转红。
///
/// 所有 topic 共用同一种机制（drop 流 + 恢复时重订阅）；
/// 契约本身（隐藏即停、恢复即刻）逐条不变。
#[tokio::test(start_paused = true)]
async fn 全部topic门控口径一致() {
    type Fixture = fn() -> (Arc<StreamGateState>, StreamGate, Arc<GateFlag>);
    for (topic, mk) in [
        (Topic::Stats, test_stats_gate as Fixture),
        (Topic::Connections, test_stream_gate as Fixture),
        (Topic::Detail, test_stream_gate as Fixture),
        (Topic::Closed, test_stream_gate as Fixture),
    ] {
        let (state, mut gate, visible) = mk();
        state.registry.lock().unwrap().subscribe(topic, "main");

        let src = flag_visibility_source(visible.clone());
        tokio::time::timeout(Duration::from_secs(5), gate.wait_until(true, &src))
            .await
            .unwrap_or_else(|_| panic!("{topic:?}：可见 + 有订阅 → 流必须开"));

        visible.store(false, Ordering::Relaxed);
        let src = flag_visibility_source(visible.clone());
        tokio::time::timeout(Duration::from_secs(5), gate.wait_until(false, &src))
            .await
            .unwrap_or_else(|_| panic!("{topic:?}：隐藏 → 流必须断（不是留着白收）"));

        visible.store(true, Ordering::Relaxed);
        let src = flag_visibility_source(visible.clone());
        tokio::time::timeout(Duration::from_secs(5), gate.wait_until(true, &src))
            .await
            .unwrap_or_else(|_| panic!("{topic:?}：窗口回来 → 必须重订阅"));
    }
}

/// 🔴 **断流恢复必须丢掉速率基线**（本批换流后，这条不变式换了落点，不是被删了）。
///
/// 轮询时代它靠 `PollGate::next_tick` 返回「本拍前 park 过」、由 poller 手动复位 `last`。
/// 长驻流下降流的动作是 drop 流，恢复的动作是**重新订阅** —— 于是判据落在建流处那一句
/// `meter.reset()` 上：只要它在，跨越断流期的旧基线就不可能被沿用。
///
/// 锁的是「隐藏期均速被当成当前速率」这个具体缺陷：用户隐藏窗口期间下过大文件，
/// 切回来的瞬间状态栏闪一个与此刻无关的高速率。
///
/// **变异探针**（实跑）：删掉 `run_stats_stream` 里建流后那句 `meter.reset()` ⇒ 转红。
/// 纯逻辑那一半（`reset()` 真的丢基线）由 `polaris_stats_engine` 的
/// `reset_drops_speed_baseline_so_next_frame_is_zero` 锁。
#[test]
fn 断流重订阅必须丢掉速率基线() {
    let src = module_code("runtime/stats");
    let body = crate::commands::guard_scan::top_level_fn_body(&src, "async fn run_stats_stream(");
    let subscribe_at = body
        .find("client.subscribe_status(")
        .expect("锚点消失：stats relay 已不走 SubscribeStatus，守卫失去判据");
    let reset_at = body[subscribe_at..]
        .find("meter.reset();")
        .map(|i| i + subscribe_at)
        .expect(
            "建流后必须 `meter.reset()` —— 否则断流期跨越的旧基线会把整段空档的平均吞吐\
                 当成「此刻的速率」显示一帧",
        );
    assert!(subscribe_at < reset_at);
}

/// 🔴 **变异锁：stats relay 不得退回「拉全量连接表再求和」那条口径已坏的路。**
///
/// 那条路的缺陷不是性能而是口径：`first_connection_snapshot` 返回的表**含内核历史环里的
/// 死连接**，对它整表求 `uplink_total` 得到的「累计」会在环满（1000 条）后每淘汰一条就**下跌**
/// 一截 —— 累计倒退，且 `saturating_sub` 把那一拍速率吃成 0。它修不掉，只能换掉。
///
/// 一并锁住 emit 侧的订阅门：门关的一瞬仍可能收到一帧，不看门就会把它推给已经没人看的窗口。
///
/// **变异探针**：把 `subscribe_status` 换回 `first_connection_snapshot` ⇒ 转红；
/// 删掉 `gate.topic_open(Topic::Stats)` 那道 emit 门 ⇒ 转红。
#[test]
fn stats_relay是流驱动且emit过订阅门() {
    let src = module_code("runtime/stats");
    let body = crate::commands::guard_scan::top_level_fn_body(&src, "async fn run_stats_stream(");
    assert!(
        !body.contains("first_connection_snapshot"),
        "stats relay 里出现了 `first_connection_snapshot` —— 那条路的累计口径是坏的（含死连接、\
             会随历史环淘汰而下跌），本批换掉的正是它"
    );
    assert!(
        body.contains("gate.wait_until(true, &visible).await"),
        "必须先等降流门开才建流 —— 否则无人看也照收帧"
    );
    assert!(
        body.contains("() = gate.wait_until(false, &visible) => break"),
        "门关那条腿必须 `break`（跳出即 drop 流）"
    );
    assert!(
        body.contains("if gate.topic_open(Topic::Stats) {"),
        "emit 前须看订阅门 —— 门关的一瞬仍可能收到一帧"
    );
}

/// 「订阅即出首帧」在流下**不需要节拍特判**：门开着就立刻返回、马上建流，而内核在建 ticker
/// 之前就无条件 `Send` 一帧当前状态（`daemon/started_service.go:396`）。
///
/// 本测取代了旧的 `首拍不睡后续按周期`（那条断言 `PollGate` 首拍不 sleep、第二拍睡满
/// `POLL_INTERVAL`）。**不是放宽，是判据换了对象**：轮询节拍随 stats 换流一并删除，
/// 继续断言它等于要求一个已不存在的东西存在。现在该锁的是「门开着时 `wait_until` 不引入
/// 任何等待」——引入了，用户订阅后就得白等一个周期才看到第一个数字。
#[tokio::test(start_paused = true)]
async fn 门开着时不得引入任何等待() {
    let (state, mut gate, visible) = test_stats_gate();
    state
        .registry
        .lock()
        .unwrap()
        .subscribe(Topic::Stats, "main");
    let src = flag_visibility_source(visible.clone());

    for round in 0..3 {
        let t0 = tokio::time::Instant::now();
        gate.wait_until(true, &src).await;
        assert_eq!(
            t0.elapsed(),
            Duration::ZERO,
            "第 {round} 次：门开着就该立刻返回（订阅即建流、即出首帧），不得有节拍式等待"
        );
    }
}

// ══════════════════════════════════════════════════════════════════════════
// 拓扑节拍独立（本批）：aggregate 单独提频，另两条腿不动，降流门不被高频传染
// ══════════════════════════════════════════════════════════════════════════

/// 🔴 **变异锁：aggregate / detail 不再有任何「节拍」—— 它们是流驱动的。**
///
/// 本测取代了旧的 `aggregate节拍快于另两条腿`（那条断言三条 topic 的 `PollGate` 睡了不同时长）。
/// **不是放宽，是判据换了对象**：那条锁的是「拓扑轮询得比另两条快」，而本批把拓扑与明细的
/// 轮询整个删掉了 —— 继续断言它们的轮询节拍等于要求一个已不存在的东西存在。
///
/// 现在该锁的不变式有两条，都在这里：
/// 1. 连接 relay 的主循环里**没有轮询节拍**（不得出现 `PollGate` / `next_tick`）；
/// 2. 它的两条腿是「等门开」与「等门关」，门关那条**必须 `break`**（drop 流），不是 park。
///
/// **变异探针**：把 `() = gate.wait_until(false, &visible) => break` 改成 `=> continue`
/// 或整条腿删掉（= 不可见时不 drop 流，留着白收事件）⇒ 转红；
/// 把外层的 `wait_until(true, ..)` 删掉（= 无人看也照开流）⇒ 转红；
/// 把 `PollGate` / `next_tick` 引回连接 relay（= 复原成轮询）⇒ 转红。
#[test]
fn 连接流是流驱动而非节拍驱动() {
    let src = module_code("runtime/stats");
    let body =
        crate::commands::guard_scan::top_level_fn_body(&src, "async fn run_connections_stream(");

    assert!(
        body.contains("gate.wait_until(true, &visible).await"),
        "连接 relay 必须先等降流门开才建流 —— 否则无人看也照收事件"
    );
    assert!(
        body.contains("() = gate.wait_until(false, &visible) => break"),
        "门关那条腿必须 `break`（跳出即 drop 流）。park 住不读流只会把帧堆在 tonic 缓冲和\
             内核发送窗口里，非但不省，还会把内核的连接事件分发堵住"
    );
    for forbidden in ["PollGate", "next_tick", "first_connection_snapshot"] {
        assert!(
            !body.contains(forbidden),
            "连接 relay 里出现了 `{forbidden}` —— 那是轮询的形状，本批换掉的正是它"
        );
    }
    assert!(
        body.contains("subscribe_connections("),
        "连接 relay 必须走长驻流订阅"
    );
}

/// 🟡 **变异锁：aggregate 的 emit 比 detail 勤，且两者都由 [`EmitGate`] 而非 sleep 决定。**
///
/// 同一张连接表、同一条上游流，但拓扑关注连接出现/消失，明细承担逐连接计数与速率刷新 ——
/// 没有理由共用一个 emit 频率。
///
/// **变异探针**：两个常量调成相等 ⇒ 第一段转红；把 `detail_emit` 也用
/// [`AGGREGATE_EMIT_MIN_INTERVAL`] 构造（常量本身不动、只是接错线）⇒ 第二段转红。
///
/// ⚠️ 第二段是**变异实测补上的**：只断言两个常量不等，抓不到「常量分得好好的，接线接错了」——
/// 实测把 `EmitGate::new(DETAIL_EMIT_MIN_INTERVAL)` 换成 `AGGREGATE_EMIT_MIN_INTERVAL` 后
/// 全测试套仍全绿。常量的判据必须落在**它被用的那一处**，不是它被定义的那一处。
#[test]
fn aggregate的emit比detail勤() {
    assert!(
        AGGREGATE_EMIT_MIN_INTERVAL < DETAIL_EMIT_MIN_INTERVAL,
        "拓扑 emit 必须严格勤于明细：前者追求连接变化观感，后者按人眼可读节奏合并逐连接计数"
    );
    let src = module_code("runtime/stats");
    let body =
        crate::commands::guard_scan::top_level_fn_body(&src, "async fn run_connections_stream(");
    assert!(
        body.contains("EmitGate::new(AGGREGATE_EMIT_MIN_INTERVAL)")
            && body.contains("EmitGate::new(DETAIL_EMIT_MIN_INTERVAL)"),
        "两条投影的闸门必须各用各的常量 —— 接成同一个，上面那条区间锁就形同虚设"
    );
}

/// 🔴 **变异锁：三个连接投影的 emit 都过闸门，且 emit 后必须 `mark_emitted`。**
///
/// `mark_emitted` 漏掉会有一个很隐蔽的后果：闸门的 `pending` 永不清零 → `wait_for` 恒返回
/// `ZERO` → select 的定时器分支退化成 `sleep(0)` → **忙转烧掉一个 tokio worker**，
/// 而 UI 上一切正常（帧照推），没有任何症状指向它。
///
/// **变异探针**：删任一 `mark_emitted` ⇒ 转红；把 `should_emit` 判定去掉改成逐帧 broadcast ⇒ 转红。
#[test]
fn 连接流emit走闸门不走裸sleep() {
    let src = module_code("runtime/stats");
    let body =
        crate::commands::guard_scan::top_level_fn_body(&src, "async fn run_connections_stream(");
    for probe in [
        "agg_emit.should_emit(now)",
        "detail_emit.should_emit(now)",
        "closed_emit.should_emit(now)",
        "agg_emit.mark_emitted(now)",
        "detail_emit.mark_emitted(now)",
        "closed_emit.mark_emitted(now)",
        "agg_emit.note_change()",
        "detail_emit.note_change()",
        "closed_emit.note_change()",
    ] {
        assert!(
            body.contains(probe),
            "连接 relay 缺 `{probe}` —— emit 必须经闸门合并/记账，漏 mark 会让定时器退化成忙转"
        );
    }
    // 闸门必须在**门关的 topic** 上也 mark（否则 pending 永不清 → 忙转）。
    //
    // aggregate 那条的门是 `agg_open`（同一轮里还要用它判开合转换，故先绑成局部量再用），
    // 与 detail/closed 的直呼形态不同 —— 逐字钉住两种形态，别为了「统一」把判据放宽成
    // 「出现过 Topic::Connections」：那样把 emit 挪到门外也照绿。
    assert!(
        body.contains("let agg_open = gate.topic_open(Topic::Connections);")
            && body.contains("if agg_open {")
            && body.contains("if gate.topic_open(Topic::Topology) || agg_open {")
            && body.contains("if gate.topic_open(Topic::Detail) {")
            && body.contains("if gate.topic_open(Topic::Closed) {"),
        "每条需求 emit 前须各自看自己的订阅门（只订了首页信号就别付 Top-N 聚合的功）"
    );
}

#[test]
fn 完整表变化信号不得受top_n签名去重() {
    let src = module_code("runtime/stats");
    let body =
        crate::commands::guard_scan::top_level_fn_body(&src, "async fn run_connections_stream(");
    let signal = body
        .find("broadcast(&app, EVENT_CONNECTIONS_TOPOLOGY_CHANGED, now_ms())")
        .expect("完整活动表变化必须有独立小信号");
    let lossy_signature = body
        .find("signature_changed(&agg, &last_sig)")
        .expect("常态聚合仍须保留签名去重");
    assert!(
        signal < lossy_signature,
        "先发完整表变化信号，再对常态 Top-N 投影去重；否则隐藏成员替换时搜索不会刷新"
    );
}

/// 🟡 **变异锁：断流期的兜底实况回读周期恒为 [`PARK_RECHECK_INTERVAL`]。**
///
/// 窗口隐藏时连接流已断开，[`StreamGate::wait_until`] 停在那里靠定期回读窗口实况兜底
/// （Tauri 2 无 show/hide 事件）。这个周期若被调快（比如顺手改成 [`AGGREGATE_EMIT_MIN_INTERVAL`]
/// 好让恢复更快），隐藏态下就会按 4Hz 空转：每次一把 registry 锁 + 一次投给主线程的可见性回读
/// —— 降流门省下的电又烧回去，而这正是最容易顺手做坏的一处。
///
/// 恢复速度**不靠**调快它：门变更（`epoch` bump）才是立刻唤醒的那条腿，本兜底只管「事件丢了」。
///
/// 判据是**回读次数**（每轮循环调一次可见性源），虚拟时钟下确定。
/// **变异探针**：`timeout(PARK_RECHECK_INTERVAL, ..)` 改成 `timeout(AGGREGATE_EMIT_MIN_INTERVAL, ..)`
/// ⇒ 10 个周期内从 ~11 次涨到 ~41 次 ⇒ 转红。
#[tokio::test(start_paused = true)]
async fn 断流期回读周期不跟随emit间隔() {
    let (state, mut gate, visible) = test_stream_gate();
    state
        .registry
        .lock()
        .unwrap()
        .subscribe(Topic::Connections, "main");
    visible.store(false, Ordering::Relaxed);

    let probes = Arc::new(AtomicU64::new(0));
    let counted = {
        let probes = probes.clone();
        let flag = visible.clone();
        move || {
            probes.fetch_add(1, Ordering::Relaxed);
            flag.load(Ordering::Relaxed)
        }
    };
    // 隐藏 10 个兜底周期：门永不开，`wait_until(true, ..)` 必然超时。
    assert!(
        tokio::time::timeout(PARK_RECHECK_INTERVAL * 10, gate.wait_until(true, &counted))
            .await
            .is_err(),
        "隐藏态必须一直保持断流"
    );
    let n = probes.load(Ordering::Relaxed);
    assert!(
        n <= 12,
        "隐藏 10 个兜底周期内最多 ~11 次实况回读，实得 {n} —— 回读跟随了 emit 间隔即降流失效"
    );
}

/// 🟡 **取值区间锁**：钉区间而非具体数字 —— 调参可以，但不许滑回 1s，也不许滑到过激。
///
/// **本批换了下界的判据，区间数字未动，理由如实登记**：
/// - 旧下界（250ms）撑在「每拍一次含 ≤1000 条死连接的全量表拉取，成本在签名去重上游、
///   随节拍线性上涨」上。长驻流下**这段成本整个消失**（一次订阅一帧全量，此后只有增量），
///   那条理由随之作废。
/// - 新下界撑在**渲染侧**：每次 emit 都要 O(n log n) 聚合 + 过 IPC + 渲染端重排整张拓扑图，
///   而拓扑节点的出现/消失在 250ms 与 100ms 之间没有可分辨差异 —— `.link` / `.node` 的
///   opacity 过渡本身就是 160ms（`ui/src/styles/components.css:224`），比 100ms 还长。
///   再快只是让渲染端多做功，用户一帧都多看不到。
/// - 上界（350ms）判据未变：再慢就退回「反应了一下」的观感。
///
/// **变异探针**：改回 `from_secs(1)` ⇒ 转红；改成 `from_millis(50)` / `from_millis(16)` ⇒ 转红。
#[test]
fn aggregate_emit间隔取值区间() {
    assert!(
        AGGREGATE_EMIT_MIN_INTERVAL >= Duration::from_millis(200),
        "拓扑 emit 间隔过激（{AGGREGATE_EMIT_MIN_INTERVAL:?}）：每次 emit 都是一次全表聚合 + IPC + \
             渲染端重排拓扑图，而 200ms 以下对一张离散变化的图没有可感知增量（连线过渡本身就 160ms）"
    );
    assert!(
        AGGREGATE_EMIT_MIN_INTERVAL <= Duration::from_millis(350),
        "拓扑 emit 间隔过慢（{AGGREGATE_EMIT_MIN_INTERVAL:?}）：滑回秒级即退回「反应了一下」的观感"
    );
}

/// 可见性未变时不得 bump 门代次（否则每拍的实况回读会白唤醒三条 poller）。
#[test]
fn 可见性未变不bump门代次() {
    let state = StreamGateState::new();
    let rx = state.epoch.subscribe();
    state.set_window_visible(true); // 与缺省同值 → no-op
    assert!(!rx.has_changed().unwrap(), "同值写入不得 bump");
    state.set_window_visible(false);
    assert!(
        rx.has_changed().unwrap(),
        "真变化必须 bump（唤醒 park 的 poller）"
    );
}

// ══════════════════════════════════════════════════════════════════════════
// 可见性缓存（M6/L13）：poller 只读缓存，回读跑在主线程
// ══════════════════════════════════════════════════════════════════════════

/// 缓存缺省必须是「可见」——与 getter 报错时的兜底方向一致（宁可多流一拍，绝不饿死 UI）。
/// 首拍发生在第一次主线程刷新落地之前，缺省若是 false，订阅即出首帧那条语义就断了。
#[test]
fn visibility_cache_defaults_to_visible() {
    let state = StreamGateState::new();
    assert!(state.vis.visible.load(Ordering::Relaxed));
    assert!(
        !state.vis.window_alive.load(Ordering::Relaxed),
        "AppRuntime 先于主窗创建：生命周期缺省必须是 absent"
    );
}

/// 主窗生命周期是平台 registry 之外的真值：created 先以隐藏态入账，探针上屏后翻可见；
/// destroying 必须在 getter 之前把门关掉。
#[test]
fn main_window_lifecycle_gates_visibility() {
    let state = StreamGateState::new();
    state.mark_main_window_created();
    assert!(state.vis.window_alive.load(Ordering::Relaxed));
    assert!(
        !state.vis.visible.load(Ordering::Relaxed),
        "builder 成功时窗口仍被 renderer-ready 门扣在隐藏态"
    );

    state.apply_visibility_probe(Ok(true));
    assert!(state.vis.visible.load(Ordering::Relaxed));

    state.mark_main_window_destroying();
    assert!(!state.vis.window_alive.load(Ordering::Relaxed));
    assert!(
        !state.vis.visible.load(Ordering::Relaxed),
        "销毁事务开始必须同步关闭降流门，不得等平台 registry 清旧句柄"
    );
}

/// 回读成功 → 写缓存 + 同步进降流门（变了才 bump，park 中的 poller 由此立刻醒）。
#[test]
fn visibility_probe_ok_updates_cache_and_gate() {
    let state = StreamGateState::new();
    let rx = state.epoch.subscribe();

    state.apply_visibility_probe(Ok(false));
    assert!(!state.vis.visible.load(Ordering::Relaxed));
    assert!(
        rx.has_changed().unwrap(),
        "可见性真变化必须 bump 门代次（否则恢复要等满一拍）"
    );
    assert!(
        !state.registry.lock().unwrap().window_visible(),
        "缓存与降流门必须是同一个真值，不能只写缓存"
    );

    state.apply_visibility_probe(Ok(true));
    assert!(state.vis.visible.load(Ordering::Relaxed));
    assert!(state.registry.lock().unwrap().window_visible());
}

/// 🟡 **回读报错 → 兜底「可见」+ 计数**（失败方向失败安全，但**不能静默**）。
///
/// **变异探针**：把错误分支改成「保持上一个值」/ 兜底成 false ⇒ 第一条断言转红；
/// 把 `error_streak` 计数删掉 ⇒ 第二条转红。
#[test]
fn visibility_probe_error_falls_back_to_visible_and_counts() {
    let state = StreamGateState::new();
    state.apply_visibility_probe(Ok(false)); // 先进入「不可见」
    assert!(!state.vis.visible.load(Ordering::Relaxed));

    state.apply_visibility_probe(Err("is_visible: boom".into()));
    assert!(
        state.vis.visible.load(Ordering::Relaxed),
        "回读失败必须兜底成「可见」——宁可多流一拍，绝不误把还在屏上的 UI 饿死"
    );
    assert_eq!(state.vis.error_streak.load(Ordering::Relaxed), 1);

    state.apply_visibility_probe(Err("is_minimized: boom".into()));
    assert_eq!(state.vis.error_streak.load(Ordering::Relaxed), 2);
    // 一次成功即复位（连续失败才是「平台性失效」的信号）。
    state.apply_visibility_probe(Ok(true));
    assert_eq!(state.vis.error_streak.load(Ordering::Relaxed), 0);
}

/// 限频告警：既不能只发一条（后续被淹 ⇒ 降流整体失效零可观测），也不能每拍都发。
#[test]
fn visibility_failure_warns_at_a_decaying_rate() {
    assert!(should_warn_visibility_failure(1), "首次必须告警");
    assert!(!should_warn_visibility_failure(2));
    assert!(!should_warn_visibility_failure(9));
    assert!(should_warn_visibility_failure(10));
    assert!(should_warn_visibility_failure(100));
    assert!(!should_warn_visibility_failure(101));
    assert!(
        should_warn_visibility_failure(1000),
        "持续失效必须周期性再喊 —— 只喊一次等于没监控"
    );
    assert!(should_warn_visibility_failure(5000));
    assert!(!should_warn_visibility_failure(5001));
    // 三条 poller 每秒合计约六拍 ⇒ 若每次都发，一分钟就是 360 条。
    let noisy = (1..=600u64)
        .filter(|n| should_warn_visibility_failure(*n))
        .count();
    assert!(noisy <= 3, "600 次失败内最多 3 条告警，实得 {noisy}");
}

/// 🟡 **调用点守卫：两条 relay 都不得直接碰窗口 getter。**
///
/// 窗口 getter 是「投消息进主事件循环 + 阻塞等回包」；主循环被原生模态 / 提权框占住时，
/// 两条 relay 会同时把两个 tokio worker 挂死在 `recv` 上。
///
/// **变异探针**：在任一 relay 里把 `visibility_source(...)` 换回 `|| main_window_visible(&app)`
/// 之类的直读 ⇒ 转红；把回读从 `run_on_main_thread` 里挪出来 ⇒ 也转红。
#[test]
fn pollers_never_touch_window_getters_directly() {
    // 剥注释取材：下面的 `count() == 2` 与 `spawn_visibility_refresh` 两条正面 `contains` 的针
    // 都是单行代码文本，注释里出现一次就替生产调用点作证 —— 实测该方法体内注释写着
    // 「主线程调用时 `run_on_main_thread` 内联执行该闭包」，把生产的 `app.run_on_main_thread(…)`
    // 整段删掉，`refresh.contains("run_on_main_thread")` 仍绿。
    let src = module_code("runtime/stats");
    for f in [
        "async fn run_connections_stream(",
        "async fn run_stats_stream(",
    ] {
        let body = crate::commands::guard_scan::top_level_fn_body(&src, f);
        assert!(
            body.contains("visibility_source(gate.state.clone()"),
            "{f} 没走缓存式可见性源"
        );
        for getter in ["is_visible(", "is_minimized(", "get_webview_window("] {
            assert!(
                !body.contains(getter),
                "{f} 里出现了阻塞式窗口 getter `{getter}` —— 主循环被模态占住时会挂死 tokio worker"
            );
        }
    }
    // 唯一允许调窗口 getter 的地方：投给主线程执行的那个闭包。
    //
    // 旧版要先截到 `mod tests` 之前才数（测试模块里也会出现这个字面量）；测试实体外移到
    // `runtime/stats/tests/` 之后取材面恒为生产码，截断既不再需要也不再成立，
    // 去掉后连锚点之后的生产代码也一并计入，判据更强。
    //
    // ⚠️ **计数型判据 + 递归取材面**：`module_source` 把 `runtime/stats/**` 的新文件自动纳入，
    // 所以这个 `2` 是「整个 stats 模块里的调用点总数」，不是「某个文件里的」。
    // 拆分后两处命中（`probe_main_window_visible` 的定义 + `spawn_visibility_refresh` 里的调用）
    // 按设计同归 `gate.rs`，其余新文件对该串命中数为 0 ⇒ 计数不被稀释。
    // 反过来这正是要的：真在 `relay.rs` 里多写一处直读，本条立刻转红（单文件取材面则看不见）。
    assert_eq!(
        src.matches("probe_main_window_visible(").count(),
        2,
        "窗口回读的调用点应恰为「定义 1 + 主线程闭包 1」——多出来的那个多半是又在别处直读了"
    );
    let refresh = method_body(&src, "    pub(super) fn spawn_visibility_refresh(");
    assert!(
        refresh.contains("run_on_main_thread"),
        "可见性回读必须投给主线程执行（否则调用方要阻塞等主循环回包）"
    );
    assert!(
        refresh.contains("probe_main_window_visible("),
        "回读必须在投给主线程的那个闭包**里面**（挪到闭包外就又是跨线程阻塞了）"
    );
}

// ══════════════════════════════════════════════════════════════════════════
// 订阅来源（L14）：只有主窗可订阅
// ══════════════════════════════════════════════════════════════════════════

/// 🟡 **变异锁：非主窗的订阅一律拒绝。**
///
/// 降流门的可见性只看主窗 → 非主窗的订阅会在主窗隐藏时被整体 park 掉（注册了但永远收不到帧，
/// 且完全静默）。**变异探针**：把判据改成恒 true / 改成「非空即可」⇒ 转红。
#[test]
fn only_the_main_window_may_subscribe_to_stats() {
    assert!(accepts_stats_subscription(MAIN_WINDOW_LABEL));
    for other in ["tray", "update-popup", "main2", "", "Main"] {
        assert!(
            !accepts_stats_subscription(other),
            "label={other:?} 的订阅必须被拒绝：它会在主窗隐藏时被饿死，且没有任何信号"
        );
    }
}

/// 🟡 **调用点守卫：label 闸必须在真正登记订阅之前。**
///
/// 登记之后再判等于白判（订阅已进注册表、poller 已被起起来）。
#[test]
fn subscribe_rejects_foreign_labels_before_registering() {
    let src = module_code("runtime/stats");
    let body = method_body(&src, "    pub fn subscribe(");
    let gate_at = body
        .find("accepts_stats_subscription(window_label)")
        .expect("非主窗订阅闸被删了 —— 将来给浮层接订阅会表现为「数据时有时无」而非立刻报错");
    let register_at = body
        .find("register_subscription(window_label, topic)")
        .expect("锚点消失：守卫已失去判据");
    assert!(
        gate_at < register_at,
        "label 闸必须在 `reg.subscribe(...)` **之前**（登记后再判等于没判）"
    );
}
