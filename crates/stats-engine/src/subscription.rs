//! 订阅注册表 —— 上游 `StatsService` 订阅门控 + `StatsWorkerHost` 需求开关的纯逻辑移植。
//!
//! Polaris 的订阅模型比 Polaris 更显式：Polaris 把「渲染端 watcher 计数」隐式耦合进「代理运行即订阅」，
//! 且 connections 流的开关经 `setConnectionsStreamEnabled`（窗口隐藏/无消费者 → cancel 上游 SubscribeConnections）。
//! 本 crate 把它拆成可单测的注册表：
//!
//! - [`Topic`]：stats / connections / topology / detail / closed 五条需求的订阅分轨。
//! - [`SubscriptionRegistry`]：记录每个 [`Topic`] 的活跃订阅者集合 + 窗口可见性；判定「是否应保持该 topic 的上游流」。
//!
//! 降流语义（维度7 #实测：无订阅者 / 无可见窗口时断流省资源）：
//! - [`SubscriptionRegistry::should_stream`]：某 topic 的活跃订阅者数 > 0 **且**（窗口可见 **或** 该 topic 不受可见性门控）
//!   才返回 true。无订阅者 → false → 上游 cancel 流。
//! - **全部 topic 口径一致**（[`Topic::gated_by_visibility`] 恒 true）：无可见窗口 = 无 UI 消费者 → 全部降流。
//!   Stats 曾经是例外（"恒需、不门控"），该例外已随其前提一并作废——理由见 [`Topic::gated_by_visibility`]
//!   的「为什么与 上游 表面形态不同」，**不是**漂移。
//!
//! 注册/注销返回 [`SubscriptionToken`]（u64 单调递增），调用方持有 token 注销（避免按字符串 id 误删他人订阅）。

use std::collections::HashMap;

/// 订阅分轨。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Topic {
    /// Status 流（流量速率/累计，首页流量条 + StatusBar）。
    Stats,
    /// 连接导航**排名**投影：Top-N 聚合载荷（`EVENT_CONNECTIONS_AGGREGATE`）。
    ///
    /// ⚠️ 与 [`Topic::Topology`] 是**两条需求**，不是一条的两半。二者共用同一条连接流、同一张连接表，
    /// 但代价差一个数量级：本条每次 emit 要在完整活动表上做一次 O(n log n) 聚合 + 载荷序列化 + 跨
    /// 进程搬运；那条只是一个 `u64` 时间戳。把首页也算进本条，等于让排名页关着时白做那次聚合。
    Connections,
    /// 首页连接流向：**只要「完整活动表变了」这一声招呼**（`EVENT_CONNECTIONS_TOPOLOGY_CHANGED`）。
    ///
    /// 首页拿到信号后按自己的画布槽位去拉**有界**投影（`stats_project_topology`），从不消费
    /// [`Topic::Connections`] 的 Top-N 载荷。它同样是连接流的一个需求方 —— 见
    /// [`should_stream_connections`](SubscriptionRegistry::should_stream_connections)，
    /// 少算它会在「只开着首页」时把整条流误停，首页拓扑随即冻结。
    Topology,
    /// 连接明细（连接信息页 detail topic）。
    Detail,
    /// 已结束连接历史（连接信息页 closed topic）。
    Closed,
}

impl Topic {
    /// 该 topic 是否受窗口可见性门控（true = 无可见窗口时应降流）。
    ///
    /// **全部 topic 同一口径，恒 true**：无可见窗口 = 无 UI 消费者，任何一条 topic 的帧都无人消费。
    /// 刻意不按 topic 分叉——分叉过一次（Stats 曾恒需），理由已随下述前提一并失效。
    ///
    /// # 为什么与 上游的表面形态不同（审计请读完再判漂移）
    ///
    /// 上游的 worker 明写「status 不门控：始终流动，驱动 host 惰性下发 setDemand」
    /// （`src/main/workers/stats-worker.ts:51`）。那条「不门控」是 **worker 协议的实现细节 + 成本事实**，
    /// 不是「流量条恒需」的产品语义：
    /// 1. **载体**：上游的 host 靠常流的 status 帧当载体惰性重发 `setDemand`
    ///    （`StatsWorkerHost.ts:187-199`，reconnect/respawn 后的自愈路径）——status 停了，demand 就发不出去。
    /// 2. **成本**：上游的 status 是 sing-box **server-push 的 `SubscribeStatus` 廉价帧**，保持流动近乎零成本。
    ///
    /// 第一条前提在 Polaris 不成立，这一条就够定论：Polaris 没有 worker 进程、没有 `setDemand`
    /// 握手——**没有任何东西需要 status 流当载体**，停掉它不会让别的东西自愈失败。
    ///
    /// ⚠️ 本条曾另有第二条理由「Polaris 的 stats 与 aggregate 共用 `first_connection_snapshot`
    /// 全量快照，保持流动 = 每秒一次全量连接 dump」——**该理由已随实现作废，勿再据以判断**：
    /// stats 现在也吃 `SubscribeStatus`（`polaris::runtime::stats::run_stats_stream`），
    /// 与 上游 同为廉价 server-push 帧。**但结论不变**：省的不再是 gRPC 全量 dump，而是
    /// 「没人看的时候不做无人消费的 IPC + 重渲染」，而这本来就是 上游 广播侧的语义（见下）。
    ///
    /// 而「窗口不可见就不给 UI 发流量帧」**本来就是 上游的语义**，只是它落在广播侧：
    /// `StatsService.ts:312` 的 `if (this.isWindowVisible && !this.isWindowVisible()) return;`
    /// 与 `StatsWorkerHost.ts:217` 的 `if (this.opts.isUiActive()) this.opts.onStats(...)`。
    /// Polaris 的轮询与广播在同一条 poller 上（没有 worker 那层分离），故把这条门落在**判据本体**：
    /// 对 UI 而言语义等价（不可见 → 不发帧），并顺带省掉那次没人消费的 gRPC。
    pub fn gated_by_visibility(self) -> bool {
        true
    }
}

/// 订阅 token（注册时返回，注销时凭 token 删除——避免按字符串 id 误删）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubscriptionToken(pub u64);

/// 订阅注册表：记录每个 topic 的活跃订阅者 + 窗口可见性，判定「该 topic 的上游流是否应保持」。
///
/// 纯逻辑、无 I/O——调用方（B5 stats actor）据 [`SubscriptionRegistry::should_stream`] 的返回值决定 tonic 流的 subscribe/drop。
/// 多线程访问：调用方自行包 Mutex（对齐 core-supervisor LifecycleGate 的 `&self + 内部 Mutex` 模式）；
/// 本类型方法取 `&self`/`&mut self`，同步语义即可单测。
#[derive(Debug, Default)]
pub struct SubscriptionRegistry {
    /// topic -> (token -> subscriber_id)。用有序结构便于调试 + 确定性测试。
    topics: HashMap<Topic, HashMap<SubscriptionToken, String>>,
    /// 窗口是否可见（无可见窗口 = 无 UI 消费者）。
    ///
    /// 默认 **true = fail-open**：全部 topic 都受可见性门控，缺省若取 false 就等于「还没人告诉我
    /// 窗口状态」时先把 UI 饿死一拍。调用方（poller）在第一拍即按窗口实况回写真值，故乐观缺省不会
    /// 让隐藏态漏降流，只是把「不确定」的那一瞬倒向不伤 UI 的一侧。
    window_visible: bool,
    /// 下一 token（u64 单调递增，不回绕——实际场景远不达上限）。
    next_token: u64,
}

impl SubscriptionRegistry {
    /// 新建空注册表（窗口默认可见）。
    pub fn new() -> Self {
        Self {
            topics: HashMap::new(),
            window_visible: true,
            next_token: 0,
        }
    }

    /// 注册一个订阅者到指定 topic。返回 token（注销时用）。`subscriber_id` 仅诊断/日志用，不参与去重
    /// （同一 subscriber 可订阅多次，每次独立 token——对齐渲染端多窗口/多组件各自订阅）。
    pub fn subscribe(
        &mut self,
        topic: Topic,
        subscriber_id: impl Into<String>,
    ) -> SubscriptionToken {
        let token = SubscriptionToken(self.next_token);
        self.next_token += 1;
        self.topics
            .entry(topic)
            .or_default()
            .insert(token, subscriber_id.into());
        token
    }

    /// 注销一个订阅（凭 token）。返回是否确实删除了（false = token 不存在/已注销）。
    pub fn unsubscribe(&mut self, topic: Topic, token: SubscriptionToken) -> bool {
        self.topics
            .get_mut(&topic)
            .map(|m| m.remove(&token).is_some())
            .unwrap_or(false)
    }

    /// 某 topic 的活跃订阅者数。
    pub fn subscriber_count(&self, topic: Topic) -> usize {
        self.topics.get(&topic).map(|m| m.len()).unwrap_or(0)
    }

    /// 是否有任何 topic 有活跃订阅者。
    pub fn has_any_subscriber(&self) -> bool {
        self.topics.values().any(|m| !m.is_empty())
    }

    /// 设置窗口可见性（无可见窗口 = 无 UI 消费者 → 受门控的 topic 降流）。
    pub fn set_window_visible(&mut self, visible: bool) {
        self.window_visible = visible;
    }

    /// 窗口是否可见。
    pub fn window_visible(&self) -> bool {
        self.window_visible
    }

    /// 判定指定 topic 的上游流是否应保持（true = 订阅上游，false = cancel 降流）。
    ///
    /// 降流语义（维度7）：活跃订阅者数 > 0 **且**（窗口可见 **或** 该 topic 不受可见性门控）。
    /// 全部 topic 口径一致（[`Topic::gated_by_visibility`] 恒 true）→ 实际等价于「有订阅者 且 窗口可见」。
    ///
    /// 门控项刻意保留 `topic.gated_by_visibility()` 这一跳而非内联成常量：它是契约的显式落点，
    /// 「哪些 topic 受可见性门控」的答案（连同它为何是全部）写在那个方法的文档里，改口径改那一处。
    pub fn should_stream(&self, topic: Topic) -> bool {
        if self.subscriber_count(topic) == 0 {
            return false;
        }
        if topic.gated_by_visibility() && !self.window_visible {
            return false;
        }
        true
    }

    /// 判定**连接流**（`SubscribeConnections` 长驻流）是否应保持。
    ///
    /// [`Topic::Connections`]（排名聚合）、[`Topic::Topology`]（首页流向信号）、[`Topic::Detail`]
    /// （活动明细）与 [`Topic::Closed`]（已结束历史）来自同一条连接事件流，共用**一条**上游流 ⇒
    /// 任一有需求即保持，全部没需求才降流。
    ///
    /// 为什么不让这几条需求各开一条流：那是轮询时代的形状，在长驻流下会变成
    /// 两份完全相同的事件流 + 两张各自维护的连接表 —— 上游成本翻倍，且两张表还可能因为
    /// 建流时刻不同而给出**互相矛盾**的两帧（拓扑说 12 条、明细列 13 条）。
    ///
    /// ⚠️ 本判定只回答「流开不开」。**开着不等于全部 topic 都该 emit** —— 每条 topic 的 emit
    /// 仍各自按 `should_stream(topic)` 门控（只订了拓扑就别把活动明细增量推过去）。
    pub fn should_stream_connections(&self) -> bool {
        self.should_stream(Topic::Connections)
            || self.should_stream(Topic::Topology)
            || self.should_stream(Topic::Detail)
            || self.should_stream(Topic::Closed)
    }

    /// 清空某 topic 的全部订阅（stream 断开 / 上层销毁时）。
    pub fn clear_topic(&mut self, topic: Topic) {
        if let Some(m) = self.topics.get_mut(&topic) {
            m.clear();
        }
    }

    /// 清空全部订阅。
    pub fn clear_all(&mut self) {
        for m in self.topics.values_mut() {
            m.clear();
        }
    }
}

#[cfg(test)]
mod tests;
