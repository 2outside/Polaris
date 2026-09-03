//! sidecar 一次运行期内的**噪音型事件计数**（会话结束一次性汇报）。
//!
//! ## 为什么要有这个模块
//!
//! 两类事件本身是**正常工作**，却各自按事件打了一条 `WARN`，真机日志里它们是刷屏第 2 名与第 4 名
//! （2026-08-02 实测：POISONED 189 条、回包无 socket 53 条）：
//!
//! - **POISONED 丢弃**：识别出 GFW 投毒应答并弃用 —— 这是竞速腿**成功履职**的标志，不是异常。
//!   按条 WARN 等于把「防御生效了」喊成「出事了」，真正的异常反而被淹掉。
//! - **回包时无监听 socket**：套接字重建 / 已停窗口内的响应丢弃 —— 预期瞬态，且调用方会重查。
//!
//! 但**完全删掉也不对**：前者的发生率是「当前网络环境被污染得多厉害」的唯一读数，后者持续升高
//! 说明 watchdog 在反复重建。故改为「按条 `debug`（默认不落盘）+ 会话结束一条 `INFO` 汇总」——
//! 信号一条不丢，噪音降到一条/会话。
//!
//! ## 为什么计数器是进程级 static 而不是挂在 server 上
//!
//! 计数的消费者是 `src-tauri` 的停 sidecar 腿（`runtime/proxy.rs`），它拿到的是 `NodeDnsRaceServer`
//! 句柄；而产生计数的 [`crate::race::race_forward`] 是**纯竞速函数**，不持有 server 引用 ——
//! 把计数器穿进它的签名要连带污染全部竞速单测。同一时刻本进程只有一个 sidecar 在跑
//! （`RaceServerState` 单例），故进程级与 per-server 在生产上等价。
//!
//! ## 可测性
//!
//! 计数/清零的**行为**定义在 [`Counters`] 上（普通结构体，单测拿独立实例断言，确定性）；
//! 模块级函数只是把那套行为接到 `SESSION` 这一个 static 上。**不要**改成直接对 static 断言：
//! 本 crate 有 11 处竞速用例并发跑，其中走投毒腿的会并发改动同一个 static ⇒ 那样的用例是 flaky 的。
use std::sync::atomic::{AtomicU64, Ordering};

/// 一组会话计数器（行为本体；`SESSION` 只是它的一个进程级实例）。
#[derive(Default)]
pub struct Counters {
    poisoned_dropped: AtomicU64,
    reply_no_socket: AtomicU64,
}

impl Counters {
    const fn new() -> Self {
        Self {
            poisoned_dropped: AtomicU64::new(0),
            reply_no_socket: AtomicU64::new(0),
        }
    }

    /// 记一次「上游返回 decoy 答案，判 POISONED 丢弃」。
    pub fn record_poisoned_dropped(&self) {
        self.poisoned_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// 记一次「回包时无监听 socket → 丢弃响应」。
    pub fn record_reply_no_socket(&self) {
        self.reply_no_socket.fetch_add(1, Ordering::Relaxed);
    }

    /// 取走计数并清零。
    ///
    /// **读后即清**是承重的：不清零则下一个会话的汇总会把上一个会话的量算进去，
    /// 「这次开代理污染有多严重」就再也读不出来了。
    pub fn take(&self) -> SessionStats {
        SessionStats {
            poisoned_dropped: self.poisoned_dropped.swap(0, Ordering::Relaxed),
            reply_no_socket: self.reply_no_socket.swap(0, Ordering::Relaxed),
        }
    }
}

/// 进程级会话计数器（生产实例）。
static SESSION: Counters = Counters::new();

/// 记一次投毒丢弃（生产入口，委托 `SESSION`）。
pub fn record_poisoned_dropped() {
    SESSION.record_poisoned_dropped();
}

/// 记一次回包无 socket（生产入口，委托 `SESSION`）。
pub fn record_reply_no_socket() {
    SESSION.record_reply_no_socket();
}

/// 取走本会话计数并清零（停 sidecar 时调用一次）。
pub fn take_session() -> SessionStats {
    SESSION.take()
}

/// 本会话计数快照。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SessionStats {
    /// 识别并丢弃的 GFW 投毒应答条数（= 竞速防护实际生效次数）。
    pub poisoned_dropped: u64,
    /// 回包时套接字不在（重建中 / 已停）而丢弃的响应条数。
    pub reply_no_socket: u64,
}

impl SessionStats {
    /// 是否一条都没有（调用方据此决定「没事发生就不打这行日志」）。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.poisoned_dropped == 0 && self.reply_no_socket == 0
    }
}

#[cfg(test)]
mod tests;
