//! Unix accept 循环的错误处置（**mac / linux 两条循环共用**的纯逻辑）。
//!
//! ## 为什么要有这一层
//!
//! Go 源两条 accept 循环都是 `conn, err := l.Accept(); if err != nil { continue }`。移植保真地照搬了
//! 这个 `continue`，于是三个性质一起丢了：**不分类、不退避、不打日志**。
//!
//! `EMFILE`/`ENFILE`（进程/系统 fd 耗尽）与 `ENOBUFS`/`ENOMEM` 是**持续态**而非瞬时态：立即重试会
//! 立即再失败，root daemon 就地变成 100% CPU 忙转，且因为一条日志都不打而完全不自曝 —— 运维看到的
//! 只有「helper 吃满一个核」。同位点的 Windows 腿（`service/win.rs` 建管道实例失败）本来就带
//! `log::error!` + 200ms sleep ⇒ 这是移植时漏的，不是取舍。
//!
//! ## 判据形态：白名单瞬时态，其余一律退避
//!
//! `std` 没有给 `EMFILE`/`ENFILE`/`ENOBUFS` 稳定的 [`std::io::ErrorKind`]（落在 `Uncategorized`，
//! 无法 match），逐 errno 列举还要在 linux/macOS 之间对两套数值。故判据反过来写：**已知的单连接级
//! 瞬时错误立即重试，其余全部退避**。漏判方向由此固定为「多退避一次」（吵），而不是「忙转」（瞎）。
//!
//! 本模块不做 IO、不碰 OS，纯决策 ⇒ 两条平台循环的行为由同一份单测钉住（macOS accept 循环在
//! `cfg(target_os = "macos")` 门内，Linux 上没有运行期观察面）。

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// accept 出错后的处置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptAction {
    /// 单连接级瞬时错误（对端在 accept 完成前撤了 / 被信号打断）→ 立即重试，不打日志。
    /// 这类退避是纯损失：连接是别人的，下一次 accept 就正常。
    RetryNow,
    /// 资源耗尽或未知错误 → 退避 [`ACCEPT_BACKOFF`] 后重试，并记一条（限频）日志。
    Backoff,
}

/// 退避时长。取自**同位点的 Windows 腿**（`platform/windows/service/win.rs` 建管道实例失败后
/// `sleep(200ms)` 重试）—— 不是新拍的数值，是把已存在的移植契约补齐到 unix 两条腿。
pub const ACCEPT_BACKOFF: Duration = Duration::from_millis(200);

/// 退避期日志的限频窗口。**可调，无契约源**：EMFILE 是持续态，逐次打会按 5 条/秒写爆 journal；
/// 取「每 5s 至多一条」——足够让运维看见「持续态」，又不至于把日志淹掉。
pub const ACCEPT_LOG_INTERVAL: Duration = Duration::from_secs(5);

/// 把 accept 错误分类成处置动作。
#[must_use]
pub fn classify_accept_error(err: &std::io::Error) -> AcceptAction {
    match err.kind() {
        // ECONNABORTED：对端在 accept 完成前撤了连接；EINTR：被信号打断（收割器装了 SIGTERM/SIGINT）。
        // 都是单连接级、下一次 accept 即恢复的瞬时态。
        std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::Interrupted => {
            AcceptAction::RetryNow
        }
        // 其余一律退避（见模块文档「判据形态」）：EMFILE/ENFILE/ENOBUFS/ENOMEM 在 std 里没有可 match
        // 的 ErrorKind，而它们正是会让循环忙转的那一类。
        _ => AcceptAction::Backoff,
    }
}

/// 限频器：首次放行，之后每 `interval` 至多放行一条。
///
/// 存在的理由与退避同源 —— 持续态错误下「每次都打」本身就是第二个 DoS 面（写爆磁盘/journal）。
/// 时间由调用方传入（[`allow_at`](Self::allow_at)），故可被单测钉死，不依赖 sleep。
#[derive(Debug)]
pub struct LogThrottle {
    interval: Duration,
    last: Mutex<Option<Instant>>,
}

impl LogThrottle {
    #[must_use]
    pub const fn new(interval: Duration) -> Self {
        Self {
            interval,
            last: Mutex::new(None),
        }
    }

    /// 以 `now` 为当前时刻判定是否放行（放行即记账）。
    pub fn allow_at(&self, now: Instant) -> bool {
        let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        if last.is_some_and(|t| now.saturating_duration_since(t) < self.interval) {
            return false;
        }
        *last = Some(now);
        true
    }

    /// 生产调用点：以真实时钟判定。
    pub fn allow(&self) -> bool {
        self.allow_at(Instant::now())
    }
}

#[cfg(test)]
mod tests;
