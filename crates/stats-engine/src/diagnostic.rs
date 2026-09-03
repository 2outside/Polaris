//! 诊断分轴计数器 —— 上游 `ProxyManager` 的 `lastStartReadyRetries` / `restartCount` 纯逻辑移植
//! （维度7 #11：慢起 vs 核崩分轴）。
//!
//! 锚点（ProxyManager.ts）：
//! - `lastStartReadyRetries`（:536）：最近一次起核经几次就绪重试才成功。>0 = 起核慢，多因 Windows 重启争用下
//!   wintun 适配器未及时释放——**非核崩溃**。本次 start 累计 readyRetries（:851/906），成功后落库（:1012）。
//! - `restartCount`（:548）：核崩溃自动重启次数。冷却（RESTART_COOLDOWN=60s）后复位（:5900）；达 MAX_RESTART_COUNT=3
//!   不再重启（:5905）。
//!
//! 为什么要分轴（diagnostic-redact.ts:431）：诊断报告里 `lastStartReadyRetries > 0` 单独成行「最近一次起核经 N 次就绪
//! 重试才成功（起核慢，多因 Windows 重启争用；非核崩溃）」，与 `restartCount`（核崩自动重启）是**不同轴**——
//! 「争用下起得慢但已自愈」与「核崩溃自动重启」在诊断里必须区分开，否则会误报核崩。
//!
//! 纯逻辑、无 I/O：本计数器只管累计/复位/快照；真正的 start/ready-retry/restart 事件由上层 actor 喂入。

/// 上游 `ProxyManager.MAX_RESTART_COUNT = 3`（:550）。
pub const MAX_RESTART_COUNT: u32 = 3;
/// 上游 `ProxyManager.RESTART_COOLDOWN = 60000ms`（:551，1 分钟内最多重启 3 次）。
pub const RESTART_COOLDOWN_MS: u64 = 60_000;

/// 两轴计数快照（诊断报告用，对齐 diagnostic-redact.ts:431 的两行）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DiagnosticCounters {
    /// 慢起轴：最近一次起核经几次就绪重试才成功（lastStartReadyRetries，:536）。0 = 一次成功。
    pub last_start_ready_retries: u32,
    /// 核崩轴：当前冷却窗口内的自动重启次数（restartCount，:548）。冷却后归零。
    pub restart_count: u32,
    /// 最近一次自动重启时刻（epoch ms，lastRestartTime，:5965）。0 = 从未重启。
    pub last_restart_ms: u64,
}

impl DiagnosticCounters {
    /// 全零。
    pub const fn zeroed() -> Self {
        Self {
            last_start_ready_retries: 0,
            restart_count: 0,
            last_restart_ms: 0,
        }
    }

    /// 新建空计数器。
    pub fn new() -> Self {
        Self::zeroed()
    }

    // ── 慢起轴（lastStartReadyRetries）──

    /// 开始一次 start：本次起核的就绪重试计数器从 0 起（:851/852）。返回一个 [`StartAttempt`] 句柄，
    /// 调用方在每次就绪重试时 [`StartAttempt::record_retry`]，成功时 [`Self::finish_start`] 落库。
    pub fn begin_start(&self) -> StartAttempt {
        StartAttempt { ready_retries: 0 }
    }

    /// 起核成功：把本次累计的就绪重试次数落到 `last_start_ready_retries`（:1012）。
    /// `attempt.ready_retries` 由 [`StartAttempt::record_retry`] 累计。
    pub fn finish_start(&mut self, attempt: &StartAttempt) {
        self.last_start_ready_retries = attempt.ready_retries;
    }

    // ── 核崩轴（restartCount）──

    /// 是否还能自动重启（shouldAutoRestart，:5900/5905）。
    ///
    /// 冷却窗口外（now - last_restart_ms > RESTART_COOLDOWN）→ 计数归零后判定。
    /// 返回 true 时调用方应先 [`Self::reset_if_past_cooldown`] 再 [`Self::record_restart`]。
    pub fn should_auto_restart(&self, now_ms: u64) -> bool {
        let count = self.effective_restart_count(now_ms);
        count < MAX_RESTART_COUNT
    }

    /// 若已过冷却窗口，把 restart_count 归零（:5900）。返回是否确实归零了。
    pub fn reset_if_past_cooldown(&mut self, now_ms: u64) -> bool {
        if self.restart_count > 0
            && now_ms.saturating_sub(self.last_restart_ms) > RESTART_COOLDOWN_MS
        {
            self.restart_count = 0;
            self.last_restart_ms = 0;
            return true;
        }
        false
    }

    /// 记录一次自动重启（attemptAutoRestart :5964/5965）：count +1，记 last_restart_ms。
    pub fn record_restart(&mut self, now_ms: u64) -> u32 {
        self.restart_count += 1;
        self.last_restart_ms = now_ms;
        self.restart_count
    }

    /// 用户手动停止 / 成功起核后归零核崩轴（:6356）。慢起轴不受影响（独立）。
    pub fn reset_restart_axis(&mut self) {
        self.restart_count = 0;
        self.last_restart_ms = 0;
    }

    /// 当前冷却窗口内有效 restart_count（过冷却则视作 0）。
    pub fn effective_restart_count(&self, now_ms: u64) -> u32 {
        if self.restart_count > 0
            && now_ms.saturating_sub(self.last_restart_ms) > RESTART_COOLDOWN_MS
        {
            0
        } else {
            self.restart_count
        }
    }

    /// 两轴是否都为 0（无诊断信号）。
    pub fn is_clean(&self) -> bool {
        self.last_start_ready_retries == 0 && self.restart_count == 0
    }
}

/// 一次 start 的就绪重试累计句柄（begin_start 返回，finish_start 消费）。
#[derive(Debug, Clone, Copy, Default)]
pub struct StartAttempt {
    ready_retries: u32,
}

impl StartAttempt {
    /// 记录一次就绪重试（onRetry，:906）。
    pub fn record_retry(&mut self) {
        self.ready_retries += 1;
    }

    /// 本次累计的就绪重试次数。
    pub fn ready_retries(&self) -> u32 {
        self.ready_retries
    }
}

#[cfg(test)]
mod tests;
