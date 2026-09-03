//! Bounded CPU executor for subscription parsing.
//!
//! Parsing remote YAML/JSON is synchronous CPU work.  Running it inside a Tokio future prevents
//! that worker from polling cancellation and can make real-exit wait forever.  This executor uses
//! two detached `std::thread` workers and a bounded queue.  Jobs are pure closures: they may own
//! input text and parse parameters, but must never capture `AppRuntime`, `ConfigManager`, an
//! `AppHandle`, or any commit capability.
//!
//! Cancellation is deliberately logical, not physical.  A queued cancelled job is skipped; a job
//! already inside serde continues on one of the two bounded workers and its result is discarded.
//! Dropping the executor never joins workers, so true process exit does not wait for parser CPU.

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use tokio::sync::oneshot;

pub const SUBSCRIPTION_PARSE_WORKERS: usize = 2;
pub const SUBSCRIPTION_PARSE_QUEUE_CAPACITY: usize = 8;
pub const SUBSCRIPTION_PARSE_INPUT_BYTES: usize = 32 * 1024 * 1024;

struct Job {
    run: Box<dyn FnOnce() + Send + 'static>,
    input_bytes: usize,
}

#[derive(Default)]
struct QueueState {
    accepting: bool,
    jobs: VecDeque<Job>,
    reserved_input_bytes: usize,
}

struct ExecutorInner {
    queue: Mutex<QueueState>,
    available: Condvar,
    queue_capacity: usize,
    max_input_bytes: usize,
}

impl ExecutorInner {
    fn new(queue_capacity: usize, max_input_bytes: usize) -> Self {
        Self {
            queue: Mutex::new(QueueState {
                accepting: true,
                jobs: VecDeque::new(),
                reserved_input_bytes: 0,
            }),
            available: Condvar::new(),
            queue_capacity,
            max_input_bytes,
        }
    }
}

/// Submission failure.  Busy is fail-closed: callers must not fall back to inline parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionParseSubmitError {
    Busy,
    InputBudgetExceeded,
    ShuttingDown,
}

impl fmt::Display for SubscriptionParseSubmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy => f.write_str("订阅解析队列已满，请稍后重试"),
            Self::InputBudgetExceeded => {
                f.write_str("订阅解析正文累计超过 32 MiB 上限，请稍后重试")
            }
            Self::ShuttingDown => f.write_str("应用正在退出，不再接受订阅解析任务"),
        }
    }
}

/// Result channel failure.  A dropped sender means the isolated parser thread panicked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubscriptionParseWorkerError;

impl fmt::Display for SubscriptionParseWorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("订阅解析任务异常终止")
    }
}

/// Awaitable parse result.  Dropping it marks the queued job cancelled.
pub struct SubscriptionParseTask<T> {
    cancelled: Arc<AtomicBool>,
    receiver: Option<oneshot::Receiver<T>>,
}

impl<T> SubscriptionParseTask<T> {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub async fn result(mut self) -> Result<T, SubscriptionParseWorkerError> {
        let receiver = self
            .receiver
            .take()
            .expect("subscription parse task receiver consumed exactly once");
        receiver.await.map_err(|_| SubscriptionParseWorkerError)
    }
}

impl<T> Drop for SubscriptionParseTask<T> {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// Runtime-owned fixed-capacity parser executor.
pub struct SubscriptionParseExecutor {
    inner: Arc<ExecutorInner>,
}

impl Default for SubscriptionParseExecutor {
    fn default() -> Self {
        Self::new_with_limits(
            SUBSCRIPTION_PARSE_WORKERS,
            SUBSCRIPTION_PARSE_QUEUE_CAPACITY,
            SUBSCRIPTION_PARSE_INPUT_BYTES,
        )
    }
}

impl SubscriptionParseExecutor {
    #[cfg(test)]
    fn new(workers: usize, queue_capacity: usize) -> Self {
        Self::new_with_limits(workers, queue_capacity, SUBSCRIPTION_PARSE_INPUT_BYTES)
    }

    fn new_with_limits(workers: usize, queue_capacity: usize, max_input_bytes: usize) -> Self {
        assert!(workers > 0, "subscription parse executor needs a worker");
        assert!(
            queue_capacity > 0,
            "subscription parse queue must be bounded above zero"
        );
        assert!(
            max_input_bytes > 0,
            "subscription parse input budget must be bounded"
        );
        let inner = Arc::new(ExecutorInner::new(queue_capacity, max_input_bytes));
        for index in 0..workers {
            let worker = Arc::clone(&inner);
            std::thread::Builder::new()
                .name(format!("subscription-parse-{index}"))
                .spawn(move || worker_loop(worker))
                .expect("failed to start subscription parse worker");
        }
        Self { inner }
    }

    #[cfg(test)]
    fn submit<T, F>(
        &self,
        work: F,
    ) -> Result<SubscriptionParseTask<T>, SubscriptionParseSubmitError>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        self.submit_weighted(0, work)
    }

    /// Submit owned parser input with its retained byte weight. The reservation covers queued and
    /// active jobs and is released only when the actual job is skipped/completes, not when its
    /// caller drops the receiver.
    pub fn submit_weighted<T, F>(
        &self,
        input_bytes: usize,
        work: F,
    ) -> Result<SubscriptionParseTask<T>, SubscriptionParseSubmitError>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        let cancelled = Arc::new(AtomicBool::new(false));
        let job_cancelled = Arc::clone(&cancelled);
        let (sender, receiver) = oneshot::channel();
        let job = Job {
            run: Box::new(move || {
                if job_cancelled.load(Ordering::Acquire) {
                    return;
                }
                let result = work();
                let _ = sender.send(result);
            }),
            input_bytes,
        };

        let mut queue = self
            .inner
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !queue.accepting {
            return Err(SubscriptionParseSubmitError::ShuttingDown);
        }
        if queue.jobs.len() >= self.inner.queue_capacity {
            return Err(SubscriptionParseSubmitError::Busy);
        }
        // A single request above the executor's owned-input bound is a deterministic size limit.
        // A legal request that merely collides with reservations held by other active/queued work
        // is back-pressure and must retain the distinct `Busy` classification.
        if input_bytes > self.inner.max_input_bytes {
            return Err(SubscriptionParseSubmitError::InputBudgetExceeded);
        }
        let Some(reserved) = queue.reserved_input_bytes.checked_add(input_bytes) else {
            return Err(SubscriptionParseSubmitError::Busy);
        };
        if reserved > self.inner.max_input_bytes {
            return Err(SubscriptionParseSubmitError::Busy);
        }
        queue.reserved_input_bytes = reserved;
        queue.jobs.push_back(job);
        drop(queue);
        self.inner.available.notify_one();
        Ok(SubscriptionParseTask {
            cancelled,
            receiver: Some(receiver),
        })
    }

    /// Stop accepting and discard queued work.  Started jobs remain bounded by the fixed workers.
    /// This method never joins and is therefore safe on the real-exit path.
    pub fn shutdown(&self) {
        let mut queue = self
            .inner
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        queue.accepting = false;
        let queued_bytes = queue
            .jobs
            .iter()
            .fold(0usize, |sum, job| sum.saturating_add(job.input_bytes));
        queue.jobs.clear();
        queue.reserved_input_bytes = queue.reserved_input_bytes.saturating_sub(queued_bytes);
        drop(queue);
        self.inner.available.notify_all();
    }
}

impl Drop for SubscriptionParseExecutor {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn worker_loop(inner: Arc<ExecutorInner>) {
    loop {
        let job = {
            let mut queue = inner
                .queue
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            loop {
                if let Some(job) = queue.jobs.pop_front() {
                    break job;
                }
                if !queue.accepting {
                    return;
                }
                queue = inner
                    .available
                    .wait(queue)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        };
        let input_bytes = job.input_bytes;
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job.run));
        let mut queue = inner
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        queue.reserved_input_bytes = queue.reserved_input_bytes.saturating_sub(input_bytes);
    }
}

#[cfg(test)]
mod tests;
