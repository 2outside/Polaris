//! Selector 意图与后台对账单飞的状态 owner。
//!
//! 这里只拥有与业务 I/O 正交的协调状态：用户意图代次、必须重申的脏位、以及
//! worker/pending 的无缝交接。真实 gRPC/config/lifecycle 事务仍由 [`ProxyRuntime`]
//! 持有；它们消费本 owner 给出的所有权事实，不另存一份协调状态。

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use tokio::sync::Notify;

use super::ProxyRuntime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SelectorReconcileOutcome {
    Applied,
    Converged,
    Superseded,
    NotEligible,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SelectorReconcileRequest {
    pub(super) generation: u64,
    pub(super) intent_generation: u64,
}

/// `active` 与最新 `pending` 共用一把锁，关闭「旧 worker 决定退出、新请求观测
/// 到仍 active 而被吞」的交接窗口。
#[derive(Debug, Default)]
struct WorkerState {
    active: bool,
    pending: Option<SelectorReconcileRequest>,
}

#[derive(Debug, Default)]
pub(super) struct SelectorReconcileOwner {
    intent_generation: AtomicU64,
    required: AtomicBool,
    worker: Mutex<WorkerState>,
    wake: Notify,
}

impl SelectorReconcileOwner {
    /// 同一目标被再选一次也是新意图；所有权不能只靠目标 id 推断。
    pub(super) fn register_intent(&self) -> u64 {
        self.intent_generation
            .fetch_add(1, Ordering::SeqCst)
            .wrapping_add(1)
    }

    pub(super) fn intent_generation(&self) -> u64 {
        self.intent_generation.load(Ordering::SeqCst)
    }

    pub(super) fn is_required(&self) -> bool {
        self.required.load(Ordering::SeqCst)
    }

    pub(super) fn mark_required(&self) {
        self.required.store(true, Ordering::SeqCst);
    }

    pub(super) fn clear_required(&self) {
        self.required.store(false, Ordering::SeqCst);
    }

    /// 登记最新请求；返回 `true` 表示调用方取得 worker 启动权。
    pub(super) fn enqueue(&self, request: SelectorReconcileRequest) -> bool {
        let mut state = self
            .worker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.pending = Some(request);
        if state.active {
            drop(state);
            self.wake.notify_one();
            false
        } else {
            state.active = true;
            true
        }
    }

    /// pending 优先于旧请求重试；都没有时在同一临界区释放 worker 所有权。
    pub(super) fn take_latest_or_finish(
        &self,
        retry: Option<SelectorReconcileRequest>,
    ) -> Option<SelectorReconcileRequest> {
        let mut state = self
            .worker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(request) = state.pending.take().or(retry) {
            return Some(request);
        }
        state.active = false;
        None
    }

    /// panic/取消兜底：释放 worker 所有权并取走期间到达的最新请求。
    pub(super) fn abort_active(&self) -> Option<SelectorReconcileRequest> {
        let mut state = self
            .worker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.active = false;
        state.pending.take()
    }

    /// 新请求可以立即打断旧请求的退避；`Notify` 保存单 permit，不会丢等待窗口。
    pub(super) async fn wait_for_retry_or_newer(&self, delay: Duration) -> bool {
        tokio::select! {
            () = tokio::time::sleep(delay) => false,
            () = self.wake.notified() => true,
        }
    }
}

impl ProxyRuntime {
    /// 声明一次新的 selector 配置意图并返回其所有权代次。调用点必须在对应配置
    /// 写事务内（显式 `server:switch`）或紧邻落盘后的广播入口调用，才能让同目标
    /// 的两次选择仍可区分先后。
    pub(crate) fn register_selector_intent(&self) -> u64 {
        self.selector_reconcile.register_intent()
    }
}

#[cfg(test)]
mod tests;
