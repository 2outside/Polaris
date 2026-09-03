//! unlock 缓存失效 + 出口 IP / 网络恢复重探排程（经 `ProxyErrorEmitter` 收口）。

use super::ProxyRuntime;

impl ProxyRuntime {
    /// **unlock 缓存失效（核 start/stop）**：核起停 = 出口隧道换一次 → 解锁快照必须作废（否则 30min TTL
    /// 内复用停核前的陈旧解锁角标）。经 [`ProxyErrorEmitter::invalidate_unlock`](super::ProxyErrorEmitter::invalidate_unlock) 收口（bump epoch、清缓存、
    /// 广播三合一）。emitter 未接线（单测 / setup 前极早期失败）→ 静默跳过，对齐既有 emit 腿——发不出失效
    /// 事件绝不反过来打断起停本身。对齐 上游 `ProxyManager` start/stop → `unlockService.invalidate()`。
    pub(super) fn invalidate_unlock_cache(&self, running: bool, exit_blocked: bool) {
        if let Some(emitter) = self.error_emitter.get() {
            emitter.invalidate_unlock(running, exit_blocked);
        }
    }

    /// **出口 IP / 延迟自动重探（核 start/stop/热切）**：出口换了一次 ⇒ 状态栏出口 IP 与其下游的伴测
    /// 延迟都须重探。经 [`ProxyErrorEmitter::schedule_exit_ip_refresh`](super::ProxyErrorEmitter::schedule_exit_ip_refresh) 收口（排程 + 检测中占位 + 探测
    /// 广播三合一）。emitter 未接线（单测 / setup 前极早期）→ 静默跳过，绝不打断起停本身（同
    /// [`invalidate_unlock_cache`] 范式）。
    ///
    /// 对齐 上游 `IpInfoService` 的事件驱动触发表；**不引入周期轮询**（上游 也没有）。
    ///
    /// [`invalidate_unlock_cache`]: Self::invalidate_unlock_cache
    pub(super) fn schedule_exit_ip_refresh(&self, running: bool) {
        if let Some(emitter) = self.error_emitter.get() {
            emitter.schedule_exit_ip_refresh(running);
        }
    }

    /// OS 网络变化后的恢复探测。事件源只负责报告「网络拓扑变了」，是否真的恢复由出口探测判定；
    /// 能力检测也只在恢复/出口变化/旧快照低置信时重跑。
    pub(super) fn schedule_network_recovery_refresh(&self) {
        if let Some(emitter) = self.error_emitter.get() {
            emitter.schedule_network_recovery_refresh();
        }
    }

    /// **R2 出口无效终态**：经 [`ProxyErrorEmitter::mark_exit_blocked`](super::ProxyErrorEmitter::mark_exit_blocked) 把出口 IP 快照落成「出口无效」
    /// （无探测、即时）。emitter 未接线 → 静默跳过（同 [`invalidate_unlock_cache`] 范式）。
    ///
    /// [`invalidate_unlock_cache`]: Self::invalidate_unlock_cache
    pub(super) fn mark_exit_blocked(&self, reason: &str) {
        if let Some(emitter) = self.error_emitter.get() {
            emitter.mark_exit_blocked(reason);
        }
    }
}
