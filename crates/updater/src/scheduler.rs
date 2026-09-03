//! 检查更新调度（定时/手动）——移植自 上游 `CoreUpdateScheduler`。
//!
//! 移植自 `src/main/services/CoreUpdateScheduler.ts`（116 行）。Polaris 调度器职责：
//!   - 启动延迟 30s 后首轮检查（`STARTUP_DELAY_MS`，避开 autoConnect / app-update / 订阅高峰）。
//!   - 6h 巡检 tick（`TICK_MS`）。
//!   - 24h due 闸（`CHECK_INTERVAL_MS`，距上次成功检查满 24h 才真正跑 cycle）。
//!   - 代理停止后延 5s 双查再落位 staged（`STOPPED_APPLY_DELAY_MS`，规避 stop→start 重启窗口）。
//!
//! **纯逻辑纪律**：本 crate 不持有真实 timer（`setTimeout`/`setInterval` 是 Node/Electron runtime）。
//! 本模块把「是否该检查」的**决策逻辑**抽成纯函数（[`UpdateScheduler::should_check`]），让宿主层
//! 用自己的 timer 机制驱动；并提供一个不带 timer 的「手动触发」入口（[`UpdateScheduler::kick`]）。
//! 真实定时器由 Tauri 侧（tokio::time / tauri::async_runtime）注入，超出本纯逻辑 crate 边界。

use std::time::Duration;

/// 调度配置（移植自 `CoreUpdateScheduler` 的四个常量）。
///
/// 全部可注入（非 `const`），便于测试用极小值驱动；生产用 [`ScheduleConfig::default`] 的 Polaris 原值。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScheduleConfig {
    /// 启动后首轮检查延迟（上游 `STARTUP_DELAY_MS = 30_000`）。
    pub startup_delay: Duration,
    /// 巡检 tick 间隔（上游 `TICK_MS = 6h`）。
    pub tick_interval: Duration,
    /// due 闸：距上次成功检查超过此值才真正跑 cycle（上游 `CHECK_INTERVAL_MS = 24h`）。
    pub check_interval: Duration,
    /// 代理停止后落位 staged 的延迟（上游 `STOPPED_APPLY_DELAY_MS = 5_000`，双查规避重启窗口）。
    pub stopped_apply_delay: Duration,
}

impl Default for ScheduleConfig {
    fn default() -> Self {
        // 上游 `CoreUpdateScheduler` 的原始常量值（`CoreUpdateScheduler.ts:26-29`）。
        Self {
            startup_delay: Duration::from_secs(30),
            tick_interval: Duration::from_secs(6 * 60 * 60), // 6h
            check_interval: Duration::from_secs(24 * 60 * 60), // 24h
            stopped_apply_delay: Duration::from_secs(5),
        }
    }
}

/// 时间源 trait：让 [`UpdateScheduler`] 的「现在刻度」可注入（测试用固定刻度，生产用 Unix 毫秒）。
///
/// 这里刻意不是单调时钟：`last_check_ms` 要跨进程持久化，只有墙钟能在重启后比较。时钟回拨由
/// [`UpdateScheduler::should_check`] 显式 fail-open，不能拿 `Instant` 的进程内刻度与磁盘上的 Unix 时间混算。
pub trait Clock {
    /// 返回 Unix epoch 毫秒。
    fn now_ms(&self) -> u64;
}

/// 生产墙钟。用于可持久化的 `lastCheckAt`；短命冷却/退避应在各自模块使用 `Instant`。
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64
    }
}

/// 固定时钟（测试用）：恒返回构造时给定的值。
#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(pub u64);

#[cfg(test)]
impl Clock for FixedClock {
    fn now_ms(&self) -> u64 {
        self.0
    }
}

/// 检查更新调度器（纯决策逻辑，不含真实 timer）。
///
/// 移植自 上游 `CoreUpdateScheduler`，但剥离 `setTimeout`/`setInterval`（runtime 机制），
/// 只保留「是否该检查」的决策。宿主层用自己的 timer 调 [`Self::should_check`]，true 时才跑 cycle。
///
/// 不变量（逐字对齐 Polaris）：
///   - **绝不主动断流**：本调度器只决策「是否触发检查」，真正换核由 `CoreStagedUpdater::try_apply_staged`
///     在代理态 gating 后执行（本 crate 不查代理态；宿主层 gating）。
///   - **due 闸**：距上次成功检查未满 `check_interval` → 不重复跑（= 上游 `cycleIfDue` 的 24h 闸）。
///   - **autoUpdateCore 守门**：开关未开 → 不跑（= 上游 `config.autoUpdateCore !== true` 提前 return）。
pub struct UpdateScheduler<C: Clock> {
    config: ScheduleConfig,
    clock: C,
    last_check_ms: u64,
    started_at_ms: u64,
    started: bool,
    /// cycle 防重入（= 上游 `isRunning`）。
    running: bool,
}

impl<C: Clock> UpdateScheduler<C> {
    /// 构造：注入调度配置 + 时钟源。`started_at_ms` 取 clock 当前时刻（调用 [`Self::start`] 后才生效）。
    #[must_use]
    pub fn new(config: ScheduleConfig, clock: C) -> Self {
        Self {
            config,
            clock,
            last_check_ms: 0,
            started_at_ms: 0,
            started: false,
            running: false,
        }
    }

    /// 启动调度器（= 上游 `start()`）。记录启动时刻，供 startup_delay 闸判断。
    pub fn start(&mut self) {
        if self.started {
            return;
        }
        self.started = true;
        self.started_at_ms = self.clock.now_ms();
    }

    /// 停止调度器（= 上游 `stop()`）。复位 started/running，保留 last_check（持久态不丢）。
    pub fn stop(&mut self) {
        self.started = false;
        self.running = false;
    }

    /// 是否已启动。
    #[must_use]
    pub fn is_started(&self) -> bool {
        self.started
    }

    /// 手动触发（= 上游 `kick()`）：config 变更时即时体感，无需等 tick。
    /// 幂等：未启动/未 due 时 [`Self::should_check`] 自然返回 false。
    ///
    /// 返回「是否应跑 cycle」（due 闸 + startup_delay 闸 + autoUpdate 守门由调用方在跑前自检；
    /// 本方法只看时间 due）。
    #[must_use]
    pub fn kick(&self) -> bool {
        self.should_check()
    }

    /// 决策：现在是否该跑检查 cycle（= 上游 `cycleIfDue` 的时间判断部分）。
    ///
    /// 移植自 `cycleIfDue:97-114` 的三闸：
    ///   1. 未启动 → false。
    ///   2. 正在跑（`running`）→ false（防重入，= 上游 `if (isRunning) return`）。
    ///   3. 启动后未过 `startup_delay` → false（避开启动高峰）。
    ///   4. 距上次成功检查未满 `check_interval` → false（24h due 闸）。
    ///
    /// 返回 true 时，调用方应：autoUpdateCore 守门 → runAutoUpdateCycle → 成功后调
    /// [`Self::mark_checked`] 刷新 last_check（失败不刷新，对齐 Polaris「仅成功检查刷新」）。
    #[must_use]
    pub fn should_check(&self) -> bool {
        if !self.started || self.running {
            return false;
        }
        let now = self.clock.now_ms();
        // startup_delay 闸：启动后未满 startup_delay → 不检查（避开 autoConnect/订阅高峰）。
        if now.saturating_sub(self.started_at_ms) < self.config.startup_delay.as_millis() as u64 {
            return false;
        }
        // due 闸：距上次成功检查未满 check_interval → 不检查（Polaris 24h）。
        // last_check_ms = 0（从未检查）→ 视为「很久以前」，必 due。
        if self.last_check_ms > 0 && now >= self.last_check_ms {
            let elapsed = now - self.last_check_ms;
            if elapsed < self.config.check_interval.as_millis() as u64 {
                return false;
            }
        }
        // now < last_check_ms = 墙钟回拨/从另一台时钟更快的设备恢复。继续 saturating_sub 会恒为 0，
        // 让自动更新最多冻结到墙钟追平；fail-open 立即检查一次，成功后把基准刷新到当前设备时间。
        true
    }

    /// 标记「一次检查已发起」（开始时调，置 running 防重入）。= 上游 `isRunning = true`。
    pub fn mark_running(&mut self) {
        self.running = true;
    }

    /// 标记「一次检查已完成」。
    ///
    /// - `success = true` → 刷新 last_check（仅成功检查刷新，对齐 Polaris「失败轮保留旧值让下轮重试」）。
    /// - 无论 success → 清 running（防重入闩释放）。
    pub fn mark_done(&mut self, success: bool) {
        if success {
            self.last_check_ms = self.clock.now_ms();
        }
        self.running = false;
    }

    /// 标记一次成功检查（便利方法：= `mark_running` + `mark_done(true)`，用于手动触发的同步路径）。
    pub fn mark_checked(&mut self) {
        self.last_check_ms = self.clock.now_ms();
        self.running = false;
    }

    /// 距上次成功检查的时长（None = 从未检查）。供 UI 展示「X 小时前检查过」。
    #[must_use]
    pub fn elapsed_since_last_check(&self) -> Option<Duration> {
        if self.last_check_ms == 0 {
            return None;
        }
        let now = self.clock.now_ms();
        now.checked_sub(self.last_check_ms)
            .map(Duration::from_millis)
    }

    /// 上次成功检查时刻（毫秒，0 = 从未）。供持久化（= 上游 `lastCheckAt`）。
    #[must_use]
    pub fn last_check_ms(&self) -> u64 {
        self.last_check_ms
    }

    /// 从持久化的 `last_check_at` 恢复（启动时调，= 上游 `getAutoStatus().lastCheckAt`）。
    pub fn restore_last_check(&mut self, last_check_ms: u64) {
        self.last_check_ms = last_check_ms;
    }

    /// 配置访问器。
    #[must_use]
    pub fn config(&self) -> &ScheduleConfig {
        &self.config
    }

    /// 决策：代理停止后是否该尝试落位 staged。
    ///
    /// 移植自 上游 `onProxyStopped:77-91` 的「延 5s 双查」语义：本方法只做**双查**（延 5s 由宿主层
    /// 用 timer 实现），检查 `proxy_running` 是否在延迟后仍为 false。true → 调用方应尝试落位。
    ///
    /// 本方法不查时间（延迟由宿主层 timer 处理）；它只把 Polaris 的「双查」谓词（`getProxyRunning()`
    /// 在延迟回调里）固化成纯函数。
    #[must_use]
    pub fn should_apply_on_proxy_stopped(&self, proxy_running: bool) -> bool {
        // 5s 内又起来了（重启窗口）→ 本次不落位（= 上游 `if (getProxyRunning()) return`）。
        !proxy_running
    }
}

#[cfg(test)]
mod tests;
