//! 帧合并与已结束连接历史环：连接数据面的数据结构底座。
//!
//! detail / closed 两条需求各有一个待发合并窗（[`PendingDetailUpdate`] /
//! [`PendingClosedUpdate`]），把流帧按代次累积成一帧再交给闸门 emit；
//! [`ClosedHistory`] 是 CLOSED 事件在活动表删表前另存的有界环。

use std::collections::{HashMap, HashSet};

use polaris_config_engine::builder::is_probe_pool_inbound_tag;
use polaris_stats_engine::{
    trim_connection, ClosedConnectionEntry, ConnectionCounters, ConnectionEntry,
    ConnectionEventType, ConnectionsClosedSnapshot, ConnectionsClosedUpdate,
    ConnectionsDetailChange, ConnectionsDetailUpdate, SingBoxConnectionEvents, StatsAggregator,
};

use super::relay::now_ns;
use super::MAX_CLOSED_HISTORY;

/// 活动连接 detail 的 1s 合并窗口。`generation` 标识一份权威连接表，`sequence`
/// 标识该代内的帧序；reset 基线只在实际 emit 时从聚合器克隆一次最终表。
#[derive(Debug, Default)]
pub(super) struct PendingDetailUpdate {
    pub(super) generation: u64,
    sequence: u64,
    pub(super) reset: bool,
    dirty: bool,
    upserts: HashMap<String, ConnectionEntry>,
    counters: HashMap<String, ConnectionCounters>,
    removed_ids: HashSet<String>,
}

impl PendingDetailUpdate {
    /// 接受跨任务 owner 分配的新真相编号。若上一份 reset 尚未发送，继续合并到同一基线，避免
    /// 重连首帧再带 reset 时无意义地连续翻代；本地只保存编号，绝不自行递增。
    pub(super) fn begin_generation(&mut self, generation: u64) {
        if !self.reset {
            assert_ne!(
                generation, 0,
                "detail generation 由共享 owner 分配且不得为 0"
            );
            self.generation = generation;
            self.sequence = 0;
        }
        self.reset = true;
        self.dirty = true;
        self.upserts.clear();
        self.counters.clear();
        self.removed_ids.clear();
    }

    pub(super) fn merge(&mut self, change: ConnectionsDetailChange) {
        if change.reset {
            assert!(
                self.reset,
                "reset 变更必须先由共享 lifecycle owner 注入 generation"
            );
            self.dirty = true;
            self.upserts.clear();
            self.counters.clear();
            self.removed_ids.clear();
            return;
        }
        self.dirty = true;
        if self.reset {
            // 待发 reset 会读取活动表最终状态，已包含本窗口内后续增量。
            return;
        }
        for (id, entry) in change.upserts {
            self.removed_ids.remove(&id);
            self.counters.remove(&id);
            self.upserts.insert(id, entry);
        }
        for (id, counters) in change.counters {
            self.removed_ids.remove(&id);
            if let Some(entry) = self.upserts.get_mut(&id) {
                entry.upload = Some(counters.upload);
                entry.download = Some(counters.download);
            } else {
                self.counters.insert(id, counters);
            }
        }
        for id in change.removed_ids {
            self.upserts.remove(&id);
            self.counters.remove(&id);
            self.removed_ids.insert(id);
        }
    }

    pub(super) fn take_update(
        &mut self,
        table: &StatsAggregator,
        at: u64,
    ) -> Option<ConnectionsDetailUpdate> {
        if !self.dirty {
            return None;
        }
        self.sequence = self.sequence.wrapping_add(1).max(1);
        let mut connections;
        let mut counters;
        let mut removed_ids;
        if self.reset {
            connections = table.entries();
            counters = Vec::new();
            removed_ids = Vec::new();
        } else {
            connections = self.upserts.drain().map(|(_, entry)| entry).collect();
            counters = self.counters.drain().map(|(_, entry)| entry).collect();
            removed_ids = self.removed_ids.drain().collect();
            connections.sort_by(|a, b| a.id.cmp(&b.id));
            counters.sort_by(|a, b| a.id.cmp(&b.id));
            removed_ids.sort();
        }
        let update = ConnectionsDetailUpdate {
            reset: self.reset,
            generation: self.generation,
            sequence: self.sequence,
            connections,
            counters,
            removed_ids,
            at,
        };
        self.reset = false;
        self.dirty = false;
        Some(update)
    }
}

/// 历史环一批变更。不携带 reset 全量：reset 时由 emit 点在锁内克隆一次最终快照，
/// 正常 CLOSED 只携带本批 upsert / 淘汰 id。
#[derive(Debug, PartialEq, Eq)]
pub(super) enum ClosedHistoryChange {
    Reset {
        generation: u64,
    },
    Delta {
        generation: u64,
        connections: Vec<ClosedConnectionEntry>,
        removed_ids: Vec<String>,
    },
}

impl ClosedHistoryChange {
    fn generation(&self) -> u64 {
        match self {
            Self::Reset { generation } | Self::Delta { generation, .. } => *generation,
        }
    }
}

/// 1s emit 窗口内的 CLOSED 增量合并器。同 id 只保留最后一次 upsert；如果期间
/// 出现 reset，当前窗口直接升格为全量首帧，不再维护注定会被覆盖的细粒度差集。
#[derive(Debug, Default)]
pub(super) struct PendingClosedUpdate {
    generation: Option<u64>,
    reset: bool,
    upserts: HashMap<String, ClosedConnectionEntry>,
    removed_ids: HashSet<String>,
}

impl PendingClosedUpdate {
    pub(super) fn clear(&mut self) {
        self.generation = None;
        self.reset = false;
        self.upserts.clear();
        self.removed_ids.clear();
    }

    pub(super) fn merge(&mut self, change: ClosedHistoryChange) {
        let generation = change.generation();
        if self.generation != Some(generation) {
            self.clear();
            self.generation = Some(generation);
        }
        match change {
            ClosedHistoryChange::Reset { .. } => {
                self.reset = true;
                self.upserts.clear();
                self.removed_ids.clear();
            }
            ClosedHistoryChange::Delta {
                connections,
                removed_ids,
                ..
            } if !self.reset => {
                for entry in connections {
                    let id = entry.entry.id.clone();
                    self.removed_ids.remove(&id);
                    self.upserts.insert(id, entry);
                }
                for id in removed_ids {
                    self.upserts.remove(&id);
                    self.removed_ids.insert(id);
                }
            }
            ClosedHistoryChange::Delta { .. } => {
                // reset 帧在 emit 时读历史环的最终状态，已自带这些后续变更。
            }
        }
    }

    /// 把累积变更物化成一帧并清空当前窗口。用户在窗口中途清空时
    /// `generation` 会改变；这时必须丢掉清空前的在途增量，不能把旧记录再灌回前端。
    pub(super) fn take_update(
        &mut self,
        history: &ClosedHistory,
        at: u64,
    ) -> Option<ConnectionsClosedUpdate> {
        let generation = self.generation?;
        if generation != history.generation {
            self.clear();
            return None;
        }
        let update = if self.reset {
            ConnectionsClosedUpdate {
                reset: true,
                connections: history.entries.clone(),
                removed_ids: Vec::new(),
                at,
            }
        } else {
            let mut connections: Vec<_> = self.upserts.drain().map(|(_, entry)| entry).collect();
            connections.sort_by_key(|entry| std::cmp::Reverse(entry.closed_at));
            let mut removed_ids: Vec<_> = self.removed_ids.drain().collect();
            removed_ids.sort();
            ConnectionsClosedUpdate {
                reset: false,
                connections,
                removed_ids,
                at,
            }
        };
        self.clear();
        Some(update)
    }
}

/// 已结束连接的独立有界历史环。
///
/// 活跃表收到 CLOSED 后会立即删行；历史不能塞回那张表，否则拓扑、活动数和关闭动作都会被幽灵记录
/// 污染。这里最多保留 1000 条，按结束时间新到旧排列。连接流重订时 sing-box 的 reset 只重放它自己的
/// 短历史环，不能拿这份不完整重放覆盖 Polaris 已积累的 1000 条会话历史；reset 因此按 ID 合并并向
/// 前端重发完整基线。`cutoff_ns` 是用户清空时的水位，确保已清过的旧记录不会借重放重新出现。
/// `generation` 只在用户清空时递增，用来作废 relay 中已积累但还未 emit 的旧增量。
#[derive(Debug, Default)]
pub(super) struct ClosedHistory {
    pub(super) entries: Vec<ClosedConnectionEntry>,
    cutoff_ns: i64,
    generation: u64,
}

impl ClosedHistory {
    pub(super) fn snapshot(&self, at: u64) -> ConnectionsClosedSnapshot {
        ConnectionsClosedSnapshot {
            connections: self.entries.clone(),
            at,
        }
    }

    pub(super) fn update_snapshot(&self, at: u64) -> ConnectionsClosedUpdate {
        ConnectionsClosedUpdate {
            reset: true,
            connections: self.entries.clone(),
            removed_ids: Vec::new(),
            at,
        }
    }

    pub(super) fn clear(&mut self, cutoff_ns: i64) {
        self.entries.clear();
        self.cutoff_ns = self.cutoff_ns.max(cutoff_ns);
        self.generation = self.generation.wrapping_add(1);
    }

    /// 在活跃聚合器消费本帧前提取关闭记录，这样 CLOSED 缺少完整 connection 时仍能用活动表兜底。
    /// 正常帧只返回真正变更的 upsert / 淘汰 id；reset 帧返回 reset 标记，不在这里克隆全表。
    pub(super) fn apply_events(
        &mut self,
        events: &SingBoxConnectionEvents,
        active: &StatsAggregator,
    ) -> Option<ClosedHistoryChange> {
        let has_closed_event = events.events.iter().any(|event| {
            event.kind == ConnectionEventType::Closed
                || event.closed_at > 0
                || event
                    .connection
                    .as_ref()
                    .is_some_and(|connection| connection.closed_at > 0)
        });
        if !events.reset && !has_closed_event {
            return None;
        }

        let mut changed_ids = HashSet::new();
        let mut initially_present = HashMap::new();

        for event in &events.events {
            let payload_closed_at = event
                .connection
                .as_ref()
                .map_or(0, |connection| connection.closed_at);
            let reported_closed_at = event.closed_at.max(payload_closed_at);
            let closed_at = if reported_closed_at > 0 {
                reported_closed_at
            } else if event.kind == ConnectionEventType::Closed {
                now_ns()
            } else {
                0
            };
            let is_closed = event.kind == ConnectionEventType::Closed || closed_at > 0;
            if !is_closed || closed_at <= self.cutoff_ns {
                continue;
            }

            let entry = event
                .connection
                .as_ref()
                .filter(|connection| !is_probe_pool_inbound_tag(&connection.inbound))
                .map(trim_connection)
                .or_else(|| active.entry(&event.id).cloned());
            let Some(entry) = entry else {
                continue;
            };
            if entry.id.is_empty() {
                continue;
            }

            let next = ClosedConnectionEntry { entry, closed_at };
            let id = next.entry.id.clone();
            let old_at = self.entries.iter().position(|old| old.entry.id == id);
            if old_at.is_some_and(|at| self.entries[at] == next) {
                continue;
            }
            if !events.reset {
                initially_present
                    .entry(id.clone())
                    .or_insert(old_at.is_some());
                changed_ids.insert(id.clone());
            }
            if let Some(at) = old_at {
                self.entries.remove(at);
            }
            self.entries.push(next);
        }

        self.entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.closed_at));

        if events.reset {
            self.entries.truncate(MAX_CLOSED_HISTORY);
            return Some(ClosedHistoryChange::Reset {
                generation: self.generation,
            });
        }

        let evicted = if self.entries.len() > MAX_CLOSED_HISTORY {
            self.entries.split_off(MAX_CLOSED_HISTORY)
        } else {
            Vec::new()
        };
        let mut removed_ids = Vec::new();
        for entry in evicted {
            let id = entry.entry.id;
            let was_present = initially_present.remove(&id).unwrap_or(true);
            changed_ids.remove(&id);
            if was_present {
                removed_ids.push(id);
            }
        }
        let connections: Vec<_> = self
            .entries
            .iter()
            .filter(|entry| changed_ids.contains(&entry.entry.id))
            .cloned()
            .collect();
        if connections.is_empty() && removed_ids.is_empty() {
            return None;
        }
        removed_ids.sort();
        Some(ClosedHistoryChange::Delta {
            generation: self.generation,
            connections,
            removed_ids,
        })
    }
}
