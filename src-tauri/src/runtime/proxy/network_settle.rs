//! Polaris 自身后台网络请求与代理起核/TUN flush 之间的稳定门。

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use tokio::sync::Notify;

/// Polaris 自身发起网络请求前的**起核稳定门**。
///
/// TUN 起核会在 selector 校正后延迟调用一次 `CloseAllConnections`。若后台订阅恰在这段窗口内发请求，
/// 那条新连接也会被无差别 RST；Windows 冷启动日志已出现两次「flush 成功」与订阅传输失败同毫秒的
/// 实证。计数而非布尔是因为显式 start / 去抖重启 / 崩溃自愈可能重叠；只有最后一条起核/flush 腿
/// 退场，等待者才可继续。
#[derive(Default)]
pub(super) struct NetworkSettleGate {
    pending: AtomicU32,
    changed: Notify,
}

impl NetworkSettleGate {
    pub(super) fn begin(self: &Arc<Self>, leg: &'static str) -> NetworkSettleGuard {
        let pending = self.pending.fetch_add(1, Ordering::SeqCst) + 1;
        log::debug!("代理网络稳定门占用：leg={leg} pending={pending}");
        NetworkSettleGuard {
            gate: Arc::clone(self),
            leg,
        }
    }

    pub(super) fn is_settled(&self) -> bool {
        self.pending.load(Ordering::SeqCst) == 0
    }

    pub(super) fn pending(&self) -> u32 {
        self.pending.load(Ordering::SeqCst)
    }

    /// 等到全部在飞起核与 TUN post-start flush 退场。
    ///
    /// 与代理世代等待复用同一套「先注册、后复查」防丢边沿范式：`Notify` 不留 permit，若先读 1
    /// 再注册，最后一个 guard 恰在缝里归还就会永久睡住。
    pub(super) async fn wait(&self) {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_settled() {
                return;
            }
            notified.await;
        }
    }
}

/// [`NetworkSettleGate`] 计数的 RAII 归还；`?` 早退 / panic / task abort 均不会把门卡死。
pub(super) struct NetworkSettleGuard {
    gate: Arc<NetworkSettleGate>,
    leg: &'static str,
}

impl Drop for NetworkSettleGuard {
    fn drop(&mut self) {
        let previous = self.gate.pending.fetch_sub(1, Ordering::SeqCst);
        debug_assert!(previous > 0, "网络稳定门计数不得下溢");
        let pending = previous.saturating_sub(1);
        log::debug!("代理网络稳定门归还：leg={} pending={pending}", self.leg);
        if previous == 1 {
            self.gate.changed.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests;
