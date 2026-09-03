//! Backend-owned subscription-create operation registry.
//!
//! A renderer only starts or re-attaches to an operation.  The registry owns cancellation,
//! bounded snapshots and the commit-point transition, so destroying a webview cannot cancel the
//! network task and an IPC retry cannot create a second writer.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::Value;
use tauri::AppHandle;
use tokio::sync::watch;

use crate::events::{broadcast, channel::EVENT_SUBSCRIPTION_CREATE_PROGRESS};

pub const MAX_SUBSCRIPTION_CREATE_OPERATIONS: usize = 64;
pub const MAX_ACTIVE_SUBSCRIPTION_CREATES: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SubscriptionCreatePhase {
    Queued,
    Fetching,
    Parsing,
    Committing,
    Succeeded,
    Failed,
    Cancelled,
}

impl SubscriptionCreatePhase {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }

    const fn is_cancelable(self) -> bool {
        matches!(self, Self::Queued | Self::Fetching | Self::Parsing)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionProviderProgress {
    pub done: usize,
    pub total: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionCreateSnapshot {
    pub operation_id: String,
    pub phase: SubscriptionCreatePhase,
    pub terminal: bool,
    pub revision: u64,
    pub started_at_ms: u64,
    pub updated_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub providers: Option<SubscriptionProviderProgress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

pub trait SubscriptionCreateEventSink: Send + Sync {
    fn updated(&self, snapshot: &SubscriptionCreateSnapshot);
}

pub struct BroadcastSubscriptionCreateSink {
    app: AppHandle,
}

impl BroadcastSubscriptionCreateSink {
    #[must_use]
    pub fn new(app: AppHandle) -> Self {
        Self { app }
    }
}

impl SubscriptionCreateEventSink for BroadcastSubscriptionCreateSink {
    fn updated(&self, snapshot: &SubscriptionCreateSnapshot) {
        broadcast(
            &self.app,
            EVENT_SUBSCRIPTION_CREATE_PROGRESS,
            snapshot.clone(),
        );
    }
}

struct OperationEntry {
    request: Value,
    snapshot: SubscriptionCreateSnapshot,
    cancel: Option<watch::Sender<bool>>,
    /// Separate from `phase`: cancel makes the public state terminal immediately, while the
    /// canceled future still has to unwind before process exit may release AppRuntime.
    worker_active: bool,
}

struct Registry {
    accepting: bool,
    entries: HashMap<String, OperationEntry>,
    order: VecDeque<String>,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            accepting: true,
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionCreateStartError {
    ShuttingDown,
    Busy,
    IdempotencyConflict,
}

pub enum SubscriptionCreateRegistration {
    Started(StartedSubscriptionCreate),
    Existing(SubscriptionCreateSnapshot),
}

pub struct StartedSubscriptionCreate {
    pub snapshot: SubscriptionCreateSnapshot,
    pub cancel: watch::Receiver<bool>,
}

#[derive(Default)]
pub struct SubscriptionCreateRuntime {
    registry: Mutex<Registry>,
    workers_changed: Condvar,
}

impl SubscriptionCreateRuntime {
    pub fn register(
        &self,
        operation_id: String,
        request: Value,
    ) -> Result<SubscriptionCreateRegistration, SubscriptionCreateStartError> {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(existing) = registry.entries.get(&operation_id) {
            return if existing.request == request {
                Ok(SubscriptionCreateRegistration::Existing(
                    existing.snapshot.clone(),
                ))
            } else {
                Err(SubscriptionCreateStartError::IdempotencyConflict)
            };
        }
        if !registry.accepting {
            return Err(SubscriptionCreateStartError::ShuttingDown);
        }
        if active_workers(&registry) >= MAX_ACTIVE_SUBSCRIPTION_CREATES {
            return Err(SubscriptionCreateStartError::Busy);
        }
        prune_terminal_for_insert(&mut registry);
        if registry.entries.len() >= MAX_SUBSCRIPTION_CREATE_OPERATIONS {
            return Err(SubscriptionCreateStartError::Busy);
        }

        let now = now_ms();
        let snapshot = SubscriptionCreateSnapshot {
            operation_id: operation_id.clone(),
            phase: SubscriptionCreatePhase::Queued,
            terminal: false,
            revision: 1,
            started_at_ms: now,
            updated_at_ms: now,
            providers: None,
            result: None,
            error: None,
        };
        let (cancel_tx, cancel_rx) = watch::channel(false);
        registry.order.push_back(operation_id.clone());
        registry.entries.insert(
            operation_id,
            OperationEntry {
                request,
                snapshot: snapshot.clone(),
                cancel: Some(cancel_tx),
                worker_active: true,
            },
        );
        Ok(SubscriptionCreateRegistration::Started(
            StartedSubscriptionCreate {
                snapshot,
                cancel: cancel_rx,
            },
        ))
    }

    #[must_use]
    pub fn snapshot(&self, operation_id: &str) -> Option<SubscriptionCreateSnapshot> {
        self.registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entries
            .get(operation_id)
            .map(|entry| entry.snapshot.clone())
    }

    #[must_use]
    pub fn snapshots(&self) -> Vec<SubscriptionCreateSnapshot> {
        let registry = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        registry
            .order
            .iter()
            .rev()
            .filter_map(|id| registry.entries.get(id))
            .map(|entry| entry.snapshot.clone())
            .collect()
    }

    pub fn advance<S: SubscriptionCreateEventSink + ?Sized>(
        &self,
        operation_id: &str,
        phase: SubscriptionCreatePhase,
        sink: &S,
    ) -> Option<SubscriptionCreateSnapshot> {
        let snapshot = self.mutate_precommit(operation_id, |snapshot| {
            snapshot.phase = phase;
            snapshot.providers = None;
        })?;
        sink.updated(&snapshot);
        Some(snapshot)
    }

    pub fn provider_progress<S: SubscriptionCreateEventSink + ?Sized>(
        &self,
        operation_id: &str,
        done: usize,
        total: usize,
        sink: &S,
    ) -> Option<SubscriptionCreateSnapshot> {
        let snapshot = self.mutate_precommit(operation_id, |snapshot| {
            snapshot.phase = SubscriptionCreatePhase::Parsing;
            snapshot.providers = Some(SubscriptionProviderProgress { done, total });
        })?;
        sink.updated(&snapshot);
        Some(snapshot)
    }

    /// Final cancellation check and irreversible commit-point transition under one mutex.
    /// After this returns a snapshot, `cancel` can no longer claim cancellation succeeded.
    pub fn begin_commit<S: SubscriptionCreateEventSink + ?Sized>(
        &self,
        operation_id: &str,
        sink: &S,
    ) -> Option<SubscriptionCreateSnapshot> {
        let snapshot = {
            let mut registry = self
                .registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let entry = registry.entries.get_mut(operation_id)?;
            if entry.snapshot.phase.is_terminal()
                || !entry.snapshot.phase.is_cancelable()
                || entry.cancel.as_ref().is_some_and(|cancel| *cancel.borrow())
            {
                return None;
            }
            entry.snapshot.phase = SubscriptionCreatePhase::Committing;
            entry.snapshot.providers = None;
            bump(&mut entry.snapshot);
            entry.snapshot.clone()
        };
        sink.updated(&snapshot);
        Some(snapshot)
    }

    pub fn succeed<S: SubscriptionCreateEventSink + ?Sized>(
        &self,
        operation_id: &str,
        result: Value,
        sink: &S,
    ) -> Option<SubscriptionCreateSnapshot> {
        self.finish(
            operation_id,
            SubscriptionCreatePhase::Succeeded,
            Some(result),
            None,
            sink,
        )
    }

    pub fn fail<S: SubscriptionCreateEventSink + ?Sized>(
        &self,
        operation_id: &str,
        error: Value,
        sink: &S,
    ) -> Option<SubscriptionCreateSnapshot> {
        self.finish(
            operation_id,
            SubscriptionCreatePhase::Failed,
            None,
            Some(error),
            sink,
        )
    }

    /// Queued/fetching/parsing cancellation becomes a truthful terminal state immediately.
    /// Committing and terminal operations are returned unchanged.
    pub fn cancel<S: SubscriptionCreateEventSink + ?Sized>(
        &self,
        operation_id: &str,
        sink: &S,
    ) -> Option<SubscriptionCreateSnapshot> {
        let (snapshot, signal, changed) = {
            let mut registry = self
                .registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let entry = registry.entries.get_mut(operation_id)?;
            if !entry.snapshot.phase.is_cancelable() {
                return Some(entry.snapshot.clone());
            }
            entry.snapshot.phase = SubscriptionCreatePhase::Cancelled;
            entry.snapshot.terminal = true;
            entry.snapshot.providers = None;
            entry.snapshot.result = None;
            entry.snapshot.error = None;
            bump(&mut entry.snapshot);
            (entry.snapshot.clone(), entry.cancel.clone(), true)
        };
        if let Some(signal) = signal {
            let _ = signal.send(true);
        }
        if changed {
            sink.updated(&snapshot);
        }
        Some(snapshot)
    }

    /// Linearization point for real exit: reject new work and cancel every operation that has not
    /// crossed [`Self::begin_commit`]. This intentionally does not wait, so the caller can first
    /// stop dependent parser queues before waiting for create workers to unwind.
    ///
    /// Called only for a real process exit, never renderer teardown.
    pub fn shutdown_begin(&self) {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        registry.accepting = false;
        let mut signals = Vec::new();
        for entry in registry.entries.values_mut() {
            if entry.snapshot.phase.is_cancelable() {
                entry.snapshot.phase = SubscriptionCreatePhase::Cancelled;
                entry.snapshot.terminal = true;
                entry.snapshot.providers = None;
                bump(&mut entry.snapshot);
                if let Some(signal) = &entry.cancel {
                    signals.push(signal.clone());
                }
            }
        }
        for signal in signals {
            let _ = signal.send(true);
        }
    }

    /// Wait for create workers after [`Self::shutdown_begin`] has made the pre-commit state
    /// terminal. Keeping this separate lets true exit clear parser work between cancellation and
    /// the wait without reopening the precommit-to-commit race.
    pub fn shutdown_wait(&self) {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while active_workers(&registry) > 0 {
            registry = self
                .workers_changed
                .wait(registry)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    /// Convenience for tests and non-exit owners that need the complete two-phase protocol.
    #[cfg(test)]
    pub fn shutdown_and_wait(&self) {
        self.shutdown_begin();
        self.shutdown_wait();
    }

    #[must_use]
    pub fn worker_guard(self: &Arc<Self>, operation_id: String) -> SubscriptionCreateWorkerGuard {
        SubscriptionCreateWorkerGuard {
            runtime: Arc::clone(self),
            operation_id,
        }
    }

    fn worker_finished(&self, operation_id: &str) {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entry) = registry.entries.get_mut(operation_id) {
            entry.worker_active = false;
            entry.cancel = None;
        }
        self.workers_changed.notify_all();
    }

    fn mutate_precommit(
        &self,
        operation_id: &str,
        mutate: impl FnOnce(&mut SubscriptionCreateSnapshot),
    ) -> Option<SubscriptionCreateSnapshot> {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = registry.entries.get_mut(operation_id)?;
        if !entry.snapshot.phase.is_cancelable() {
            return None;
        }
        mutate(&mut entry.snapshot);
        bump(&mut entry.snapshot);
        Some(entry.snapshot.clone())
    }

    fn finish<S: SubscriptionCreateEventSink + ?Sized>(
        &self,
        operation_id: &str,
        phase: SubscriptionCreatePhase,
        result: Option<Value>,
        error: Option<Value>,
        sink: &S,
    ) -> Option<SubscriptionCreateSnapshot> {
        let snapshot = {
            let mut registry = self
                .registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let entry = registry.entries.get_mut(operation_id)?;
            if entry.snapshot.phase.is_terminal() {
                return Some(entry.snapshot.clone());
            }
            entry.snapshot.phase = phase;
            entry.snapshot.terminal = true;
            entry.snapshot.providers = None;
            entry.snapshot.result = result;
            entry.snapshot.error = error;
            entry.cancel = None;
            bump(&mut entry.snapshot);
            entry.snapshot.clone()
        };
        sink.updated(&snapshot);
        Some(snapshot)
    }
}

pub struct SubscriptionCreateWorkerGuard {
    runtime: Arc<SubscriptionCreateRuntime>,
    operation_id: String,
}

impl Drop for SubscriptionCreateWorkerGuard {
    fn drop(&mut self) {
        self.runtime.worker_finished(&self.operation_id);
    }
}

impl Drop for SubscriptionCreateRuntime {
    fn drop(&mut self) {
        let registry = self
            .registry
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        registry.accepting = false;
        for entry in registry.entries.values_mut() {
            if let Some(cancel) = &entry.cancel {
                let _ = cancel.send(true);
            }
        }
    }
}

fn active_workers(registry: &Registry) -> usize {
    registry
        .entries
        .values()
        .filter(|entry| entry.worker_active)
        .count()
}

fn prune_terminal_for_insert(registry: &mut Registry) {
    while registry.entries.len() >= MAX_SUBSCRIPTION_CREATE_OPERATIONS {
        let Some(position) = registry.order.iter().position(|id| {
            registry
                .entries
                .get(id)
                .is_some_and(|entry| entry.snapshot.phase.is_terminal() && !entry.worker_active)
        }) else {
            break;
        };
        if let Some(id) = registry.order.remove(position) {
            registry.entries.remove(&id);
        }
    }
}

fn bump(snapshot: &mut SubscriptionCreateSnapshot) {
    snapshot.revision = snapshot.revision.saturating_add(1);
    snapshot.updated_at_ms = now_ms();
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}
