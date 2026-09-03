//! Taildrop 发件任务的进程级所有者。
//!
//! 原生文件选择框返回后，发送可能持续数分钟；把状态放在弹窗的 `useState` 里会随关窗丢失，
//! 把 future 留在 command 栈上又无法取消或重新附着。本运行时只持有**有界快照 + 取消发送端**：
//! 真 gRPC future 由 command 启动，但只持本运行时的 `Weak`，因此 `AppRuntime` 释放时本表会先
//! broadcast cancel，后台任务不会反向把所有者永久保活。

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tauri::AppHandle;
use tokio::sync::watch;

use crate::events::{broadcast, channel::EVENT_TAILDROP_TASK_UPDATED};

/// 终态快照最多保留 32 个；活跃任务也计入该上限，内存不会随长会话增长。
pub const MAX_TAILDROP_TASKS: usize = 32;
/// 同时持有的文件句柄 / gRPC 双向流上限。
pub const MAX_ACTIVE_TAILDROP_TASKS: usize = 4;
/// 单任务文件清单上限；除任务数外也封住每份快照自身的大小。
pub const MAX_TAILDROP_FILES_PER_TASK: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TaildropTaskPhase {
    Connecting,
    Sending,
    Canceling,
    Completed,
    Failed,
    Canceled,
}

impl TaildropTaskPhase {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Canceled)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaildropTaskFile {
    pub name: String,
    pub size: u64,
    pub sent_bytes: u64,
    pub completed: bool,
}

/// 前端可随时 pull、也会随事件 push 的完整任务快照。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaildropTaskSnapshot {
    pub task_id: String,
    pub server_id: String,
    pub peer_stable_id: String,
    pub phase: TaildropTaskPhase,
    pub files: Vec<TaildropTaskFile>,
    pub sent_bytes: u64,
    pub acknowledged_bytes: u64,
    pub total_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    pub started_at_ms: u64,
    pub updated_at_ms: u64,
    /// 单任务单调代次；窗口重建时「先监听再 pull」发生竞态，也不会让旧 pull 覆盖新事件。
    pub revision: u64,
}

pub trait TaildropTaskEventSink: Send + Sync {
    fn updated(&self, snapshot: &TaildropTaskSnapshot);
}

pub struct BroadcastTaildropTaskSink {
    app: AppHandle,
}

impl BroadcastTaildropTaskSink {
    #[must_use]
    pub fn new(app: AppHandle) -> Self {
        Self { app }
    }
}

impl TaildropTaskEventSink for BroadcastTaildropTaskSink {
    fn updated(&self, snapshot: &TaildropTaskSnapshot) {
        broadcast(&self.app, EVENT_TAILDROP_TASK_UPDATED, snapshot.clone());
    }
}

struct TaskEntry {
    snapshot: TaildropTaskSnapshot,
    cancel: Option<watch::Sender<bool>>,
}

#[derive(Default)]
struct TaskRegistry {
    entries: HashMap<String, TaskEntry>,
    /// 创建顺序；最老在前。只在新任务进入时驱逐最老终态。
    order: VecDeque<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaildropTaskStartError {
    Busy,
    TooManyFiles,
}

pub struct StartedTaildropTask {
    pub snapshot: TaildropTaskSnapshot,
    pub cancel: watch::Receiver<bool>,
}

pub struct TaildropRuntime {
    next_id: AtomicU64,
    tasks: Mutex<TaskRegistry>,
}

impl Default for TaildropRuntime {
    fn default() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            tasks: Mutex::new(TaskRegistry::default()),
        }
    }
}

impl TaildropRuntime {
    #[must_use]
    pub fn can_start(&self) -> bool {
        let tasks = self
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        active_count(&tasks) < MAX_ACTIVE_TAILDROP_TASKS
    }

    pub fn start_task(
        &self,
        server_id: String,
        peer_stable_id: String,
        files: Vec<(String, u64)>,
    ) -> Result<StartedTaildropTask, TaildropTaskStartError> {
        if files.len() > MAX_TAILDROP_FILES_PER_TASK {
            return Err(TaildropTaskStartError::TooManyFiles);
        }

        let mut tasks = self
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if active_count(&tasks) >= MAX_ACTIVE_TAILDROP_TASKS {
            return Err(TaildropTaskStartError::Busy);
        }
        prune_terminal_for_insert(&mut tasks);
        if tasks.entries.len() >= MAX_TAILDROP_TASKS {
            // 这里只有「全是活跃任务」才可能发生；正常会被 active 上限更早挡住。
            return Err(TaildropTaskStartError::Busy);
        }

        let task_id = format!(
            "taildrop-{}-{}",
            std::process::id(),
            self.next_id.fetch_add(1, Ordering::Relaxed)
        );
        let now = now_ms();
        let total_bytes = files
            .iter()
            .fold(0u64, |sum, (_, size)| sum.saturating_add(*size));
        let snapshot = TaildropTaskSnapshot {
            task_id: task_id.clone(),
            server_id,
            peer_stable_id,
            phase: TaildropTaskPhase::Connecting,
            files: files
                .into_iter()
                .map(|(name, size)| TaildropTaskFile {
                    name,
                    size,
                    sent_bytes: 0,
                    completed: false,
                })
                .collect(),
            sent_bytes: 0,
            acknowledged_bytes: 0,
            total_bytes,
            error_code: None,
            started_at_ms: now,
            updated_at_ms: now,
            revision: 1,
        };
        let (cancel_tx, cancel_rx) = watch::channel(false);
        tasks.order.push_back(task_id.clone());
        tasks.entries.insert(
            task_id,
            TaskEntry {
                snapshot: snapshot.clone(),
                cancel: Some(cancel_tx),
            },
        );
        Ok(StartedTaildropTask {
            snapshot,
            cancel: cancel_rx,
        })
    }

    #[must_use]
    pub fn snapshots(&self, server_id: Option<&str>) -> Vec<TaildropTaskSnapshot> {
        let tasks = self
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tasks
            .order
            .iter()
            .rev()
            .filter_map(|id| tasks.entries.get(id))
            .filter(|entry| server_id.is_none_or(|server_id| entry.snapshot.server_id == server_id))
            .map(|entry| entry.snapshot.clone())
            .collect()
    }

    /// 返回 `None` 表示 taskId 不存在；存在时取消是幂等的（终态原样返回）。
    pub fn cancel<S: TaildropTaskEventSink + ?Sized>(
        &self,
        task_id: &str,
        sink: &S,
    ) -> Option<TaildropTaskSnapshot> {
        let (snapshot, signal) = {
            let mut tasks = self
                .tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let entry = tasks.entries.get_mut(task_id)?;
            if entry.snapshot.phase.is_terminal() {
                return Some(entry.snapshot.clone());
            }
            if entry.snapshot.phase != TaildropTaskPhase::Canceling {
                entry.snapshot.phase = TaildropTaskPhase::Canceling;
                bump(&mut entry.snapshot);
            }
            (entry.snapshot.clone(), entry.cancel.clone())
        };
        if let Some(signal) = signal {
            let _ = signal.send(true);
        }
        sink.updated(&snapshot);
        Some(snapshot)
    }

    pub fn mark_sending<S: TaildropTaskEventSink + ?Sized>(&self, task_id: &str, sink: &S) {
        self.mutate_active(task_id, sink, |snapshot| {
            if snapshot.phase == TaildropTaskPhase::Connecting {
                snapshot.phase = TaildropTaskPhase::Sending;
            }
        });
    }

    pub fn record_progress<S: TaildropTaskEventSink + ?Sized>(
        &self,
        task_id: &str,
        file_index: i32,
        sent_bytes: i64,
        file_completed: bool,
        sink: &S,
    ) {
        self.mutate_active(task_id, sink, |snapshot| {
            let Ok(index) = usize::try_from(file_index) else {
                return;
            };
            let Some(file) = snapshot.files.get_mut(index) else {
                return;
            };
            let sent = u64::try_from(sent_bytes).unwrap_or(0).min(file.size);
            file.sent_bytes = file.sent_bytes.max(sent);
            if file_completed {
                file.completed = true;
                file.sent_bytes = file.size;
            }
            snapshot.sent_bytes = snapshot
                .files
                .iter()
                .fold(0u64, |sum, file| sum.saturating_add(file.sent_bytes))
                .min(snapshot.total_bytes);
        });
    }

    /// `receivedBytes` 是核每次吃进请求 chunk 的**增量**（不是累计值）。
    pub fn record_acknowledged<S: TaildropTaskEventSink + ?Sized>(
        &self,
        task_id: &str,
        acknowledged_bytes: i64,
        sink: &S,
    ) {
        self.mutate_active(task_id, sink, |snapshot| {
            let delta = u64::try_from(acknowledged_bytes).unwrap_or(0);
            snapshot.acknowledged_bytes = snapshot
                .acknowledged_bytes
                .saturating_add(delta)
                .min(snapshot.total_bytes);
        });
    }

    pub fn complete<S: TaildropTaskEventSink + ?Sized>(&self, task_id: &str, sink: &S) {
        self.finish(task_id, TaildropTaskPhase::Completed, None, sink);
    }

    pub fn fail<S: TaildropTaskEventSink + ?Sized>(
        &self,
        task_id: &str,
        error_code: &'static str,
        sink: &S,
    ) {
        self.finish(
            task_id,
            TaildropTaskPhase::Failed,
            Some(error_code.to_owned()),
            sink,
        );
    }

    pub fn canceled<S: TaildropTaskEventSink + ?Sized>(&self, task_id: &str, sink: &S) {
        self.finish(task_id, TaildropTaskPhase::Canceled, None, sink);
    }

    fn mutate_active<S: TaildropTaskEventSink + ?Sized>(
        &self,
        task_id: &str,
        sink: &S,
        mutate: impl FnOnce(&mut TaildropTaskSnapshot),
    ) {
        let snapshot = {
            let mut tasks = self
                .tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(entry) = tasks.entries.get_mut(task_id) else {
                return;
            };
            if entry.snapshot.phase.is_terminal()
                || entry.snapshot.phase == TaildropTaskPhase::Canceling
            {
                return;
            }
            let before = entry.snapshot.clone();
            mutate(&mut entry.snapshot);
            if entry.snapshot == before {
                return;
            }
            bump(&mut entry.snapshot);
            entry.snapshot.clone()
        };
        sink.updated(&snapshot);
    }

    fn finish<S: TaildropTaskEventSink + ?Sized>(
        &self,
        task_id: &str,
        phase: TaildropTaskPhase,
        error_code: Option<String>,
        sink: &S,
    ) {
        let snapshot = {
            let mut tasks = self
                .tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(entry) = tasks.entries.get_mut(task_id) else {
                return;
            };
            if entry.snapshot.phase.is_terminal() {
                return;
            }
            entry.snapshot.phase = phase;
            entry.snapshot.error_code = error_code;
            if phase == TaildropTaskPhase::Completed {
                for file in &mut entry.snapshot.files {
                    file.sent_bytes = file.size;
                    file.completed = true;
                }
                entry.snapshot.sent_bytes = entry.snapshot.total_bytes;
                entry.snapshot.acknowledged_bytes = entry
                    .snapshot
                    .acknowledged_bytes
                    .max(entry.snapshot.total_bytes);
            }
            entry.cancel = None;
            bump(&mut entry.snapshot);
            entry.snapshot.clone()
        };
        sink.updated(&snapshot);
    }
}

impl Drop for TaildropRuntime {
    fn drop(&mut self) {
        let tasks = self
            .tasks
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for entry in tasks.entries.values() {
            if let Some(cancel) = &entry.cancel {
                let _ = cancel.send(true);
            }
        }
    }
}

fn active_count(tasks: &TaskRegistry) -> usize {
    tasks
        .entries
        .values()
        .filter(|entry| !entry.snapshot.phase.is_terminal())
        .count()
}

fn prune_terminal_for_insert(tasks: &mut TaskRegistry) {
    while tasks.entries.len() >= MAX_TAILDROP_TASKS {
        let Some(position) = tasks.order.iter().position(|id| {
            tasks
                .entries
                .get(id)
                .is_some_and(|entry| entry.snapshot.phase.is_terminal())
        }) else {
            break;
        };
        if let Some(id) = tasks.order.remove(position) {
            tasks.entries.remove(&id);
        }
    }
}

fn bump(snapshot: &mut TaildropTaskSnapshot) {
    snapshot.revision = snapshot.revision.saturating_add(1);
    snapshot.updated_at_ms = now_ms();
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests;
