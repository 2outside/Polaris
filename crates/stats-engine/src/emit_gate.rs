//! emit 节流闸门 —— 长驻连接流下「轮询节拍」的替代物。
//!
//! # 为什么长驻流反而**更**需要一道闸门
//!
//! 轮询时代，「多久推一帧给渲染端」这件事是免费搭在拉取节拍上的：`first_connection_snapshot`
//! 每 250ms（aggregate）/ 1s（detail）拉一次，emit 自然也就是那个频率 —— 节拍同时充当了
//! **拉取周期**与**推送上限**两个角色。
//!
//! 换成 `SubscribeConnections` 长驻流后，拉取周期这一半消失了（内核对 NEW/CLOSED 是
//! `case event := <-subscription` 事件驱动即时推送，`daemon/started_service.go:752`），
//! 但**推送上限那一半不能跟着消失**：
//!
//! - 内核在同一次 select 里带 `drain:` 标签把队列里已到的事件一次排空再 Send，故单帧可以很大，
//!   但**帧与帧之间没有任何最小间隔**。一个 BT 客户端瞬间开 500 条连接 = 一串背靠背的帧。
//! - 我们这侧每帧的代价不是「解一次 protobuf」而已：aggregate 要 O(n log n) 排序 + Top-N，
//!   detail 要把整张表 trim 成 `ConnectionEntry` 再整体 JSON 序列化过 IPC，渲染端还要重排一次
//!   拓扑图 / 重渲一张表。**把这条链路的频率交给内核的事件速率去定，等于把前端的帧预算
//!   外包给了对端的负载。**
//!
//! 故：**闸门从「拉取节拍」降级成「emit 下限间隔」**——上游帧照单全收（连接表必须实时准确，
//! 否则 CLOSED 漏一条就是永久幽灵），但**下游 emit 有地板**。两者解耦正是长驻流的收益所在：
//! 状态是实时的，渲染是有节制的。
//!
//! # 合并语义（coalescing，不是采样）
//!
//! 冷却期内到达的 N 帧**不产生 N 次 emit，也不被丢弃** —— 它们把 `pending` 置起，冷却一到
//! 就用**当时最新的连接表**推一帧。这是「尾沿保证」：
//!
//! - 不做尾沿 → 一次孤立的连接变化若恰好落在冷却期内，就**永远**不会被推（下一帧要等下一次
//!   变化，而变化可能几分钟后才有）。拓扑图会停在旧状态，看着像「流断了」。
//!   这是节流实现最经典的一个坑，[`EmitGate::wait_for`] 存在的唯一理由就是它。
//! - 做成「每帧都 emit 但丢弃冷却期内的」= 采样，会丢状态；本闸门丢的是**中间帧**，不丢**状态**
//!   （状态在连接表里，emit 时现取最新的）。
//!
//! # 纯逻辑
//!
//! 不持定时器、不 sleep、不碰时钟：时刻经 `now_ms` 参数注入（对齐 [`crate::resubscribe`] 的同一约定），
//! 上层 actor 据 [`EmitGate::wait_for`] 的返回值调度真实 `tokio::time::sleep`。
//! 于是「冷却期内 N 帧只 emit 一次」「尾沿不丢」这些规则可以用构造的事件序列逐条单测，
//! 不需要真流、不需要真内核、不需要碰网络。

use std::time::Duration;

/// 单条投影（aggregate / detail）的 emit 节流闸门。
///
/// 用法（上层 actor 的流循环）：
/// 1. 收到上游帧、更新完连接表 → [`note_change`](Self::note_change)。
/// 2. 循环顶部 → [`wait_for`](Self::wait_for) 拿「距下次可 emit 还要多久」：
///    `None` = 无待推变更（不设定时器，纯等下一帧）；`Some(ZERO)` = 立刻可推；
///    `Some(d)` = 冷却中，`select!` 里挂一个 `sleep(d)`。
/// 3. 真 emit 后 → [`mark_emitted`](Self::mark_emitted)。
/// 4. 流被 drop / 重订阅 → [`reset`](Self::reset)（下一帧不受上一条流的冷却牵连）。
#[derive(Debug, Clone)]
pub struct EmitGate {
    /// 两次 emit 之间的下限间隔。
    min_interval: Duration,
    /// 上次 emit 时刻（ms）。`None` = 本条流尚未 emit 过 → 首帧不等冷却。
    ///
    /// **首帧必须免冷却**：订阅（或重订阅）后的第一帧是 `reset=true` 全量表，它是渲染端
    /// 从「无数据 / 旧数据」切到「当前真相」的唯一一帧。让它等满 250ms 就是把长驻流最大的
    /// 收益（首帧即真相）主动还回去；轮询时代的「首拍不睡」语义也正是这一条。
    last_emit_ms: Option<u64>,
    /// 是否有「已收到、尚未 emit」的变更（尾沿标志）。
    pending: bool,
}

impl EmitGate {
    /// 用指定下限间隔构造。间隔取值由调用方定（策略属运行时，不属纯逻辑层）。
    #[must_use]
    pub const fn new(min_interval: Duration) -> Self {
        Self {
            min_interval,
            last_emit_ms: None,
            pending: false,
        }
    }

    /// 当前下限间隔。
    #[must_use]
    pub const fn min_interval(&self) -> Duration {
        self.min_interval
    }

    /// 记一次上游变更（收到流帧、连接表已更新）。幂等：冷却期内来 100 帧与来 1 帧等效。
    pub const fn note_change(&mut self) {
        self.pending = true;
    }

    /// 是否有待推变更（尚未 emit）。
    #[must_use]
    pub const fn is_pending(&self) -> bool {
        self.pending
    }

    /// 距下次可 emit 还要等多久。
    ///
    /// - `None`：无待推变更 —— 调用方**不该**设定时器，安静等下一帧即可（长驻流空闲时是常态，
    ///   这一条就是「没变化就零开销」的来源）。
    /// - `Some(Duration::ZERO)`：现在就能推。
    /// - `Some(d)`：冷却中，`d` 之后推。
    ///
    /// 时钟回拨（`now_ms` < `last_emit_ms`）走 `saturating_sub` → 视作「刚推过」→ 等满一个间隔，
    /// 不 panic、也不会因为负数溢出成天文数字把 emit 永久饿死。
    #[must_use]
    pub fn wait_for(&self, now_ms: u64) -> Option<Duration> {
        if !self.pending {
            return None;
        }
        let Some(last) = self.last_emit_ms else {
            return Some(Duration::ZERO); // 本条流首帧：免冷却
        };
        let elapsed = Duration::from_millis(now_ms.saturating_sub(last));
        Some(self.min_interval.saturating_sub(elapsed))
    }

    /// 此刻是否应该 emit（= 有待推变更且冷却已过）。[`wait_for`](Self::wait_for) 的布尔投影。
    #[must_use]
    pub fn should_emit(&self, now_ms: u64) -> bool {
        self.wait_for(now_ms) == Some(Duration::ZERO)
    }

    /// 记一次真实 emit（清尾沿标志 + 重置冷却锚）。
    pub const fn mark_emitted(&mut self, now_ms: u64) {
        self.pending = false;
        self.last_emit_ms = Some(now_ms);
    }

    /// 复位（流被 drop / 重订阅 / 核重启）。
    ///
    /// **冷却锚一并清掉**是刻意的：重订阅后的首帧是 `reset=true` 全量表，若还背着上一条流的冷却
    /// 锚，用户切回窗口的那一刻要多等一个间隔才看到真相 —— 而「恢复不等整拍」正是降流门那一侧
    /// 花了力气保证的事，不该在这里被抵消掉。
    pub const fn reset(&mut self) {
        self.pending = false;
        self.last_emit_ms = None;
    }
}

#[cfg(test)]
mod tests;
