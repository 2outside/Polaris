//! topic 订阅注册与快照：[`StatsRelay`]（`State`-managed 单实例）持每窗口 topic 记账、
//! 两条 relay 的单例槽位，以及两张共享表（活动连接表 / 已结束历史环）。
//!
//! 订阅集的增减即两条流的起停判据：[`should_spawn_poller`] 在 slot 锁下裁决 spawn，
//! `stop_*_stream` 在同一把锁下复查订阅计数。topic 字面量校验（[`parse_topic`]）与
//! 订阅准入（[`accepts_stats_subscription`]）两个纯判定同域。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tauri::AppHandle;

use polaris_stats_engine::{
    ConnectionsAggregate, ConnectionsClosedSnapshot, ConnectionsClosedUpdate, StatsAggregator,
    SubscriptionToken, Topic,
};

use crate::events::{broadcast, channel::EVENT_CONNECTIONS_CLOSED};
use crate::runtime::config::ConfigManager;
use crate::runtime::proxy::ProxyRuntime;

use super::gate::{StreamGate, StreamGateState};
use super::projection::ClosedHistory;
use super::relay::{
    now_ms, now_ns, run_connections_stream, run_stats_stream, ConnectionStreamTaskContext,
};
use super::MAIN_WINDOW_LABEL;

/// 一条运行中的后台 relay 任务（单例槽位的内容物）。
///
/// 名字留作 `AggregatePoller` 是历史沿革（最早只有 aggregate 一条，且是轮询）；现在两个使用者
/// 都是长驻流 —— **连接流**（[`run_connections_stream`]）与 **Status 流**（[`run_stats_stream`]），
/// 结构本身与「轮询」无关 —— 只是「停机标志 + 任务句柄」。
pub(super) struct AggregatePoller {
    /// 协作停机标志（relay 每轮外循环 top 检查；退订/窗口关即置 true）。
    pub(super) stop: Arc<AtomicBool>,
    /// 连接流任务的归属 epoch；Status 流不共享连接表，固定为 `None`。
    pub(super) connection_epoch: Option<u64>,
    /// 后台任务句柄（abort 作硬兜底，令 sleep/在飞 gRPC 立即取消）。
    pub(super) handle: tauri::async_runtime::JoinHandle<()>,
}

#[derive(Debug, Default)]
struct ConnectionStreamLifecycleState {
    current_epoch: u64,
    detail_generation: u64,
    aggregate_baseline_due: bool,
}

/// 连接流任务跨 spawn/abort 存活的唯一归属 owner。
///
/// `current_epoch` 把共享活动表、已结束历史写入与四类事件归到唯一任务；`detail_generation` 则给
/// 每个真正会发出的 reset 数据集分配跨任务单调编号；`aggregate_baseline_due` 是只能由当前任务
/// 消费的订阅边沿。任务局部 [`super::projection::PendingDetailUpdate`] 只保存 owner 注入的当前编号
/// 和该代 sequence，不再自造 generation。
///
/// # 锁序与线性化
///
/// 固定锁序是：连接 slot →（短暂读取 registry 后释放）→ **本锁** → active table → closed history。
/// relay 任务只走本锁 → active → closed；外部 closed snapshot/clear 走本锁 → closed。投影命令只取
/// active，绝不反向再取本锁；subscribe/command 进入 external commit 前也不持 registry 或 slot。
/// 因此 start/retire 能在同一个临界区完成「换 epoch + 清活动表」，旧任务也只能经 [`Self::commit`]
/// 在当前 epoch 下修改共享表或 emit。closed history 按产品契约跨任务保留，start/retire 从不清它。
///
/// emit 闭包也刻意在本锁内同步执行：`broadcast` 只是 Tauri `AppHandle::emit` 的同步序列化/入队，
/// 不跨 `.await`，也不会同步回入 Rust command；持锁到 emit 返回是封住“最后一次 compare 后、真正
/// 发帧前被 retire 插队”的必要线性化边界。
#[derive(Debug, Default)]
pub(super) struct ConnectionStreamLifecycle {
    state: Mutex<ConnectionStreamLifecycleState>,
}

impl ConnectionStreamLifecycle {
    fn next_nonzero(value: &mut u64) -> u64 {
        *value = value.wrapping_add(1).max(1);
        *value
    }

    /// 在 slot 锁内开始新任务；换 epoch 与清活动表是一个线性化动作。
    pub(super) fn start_task(&self, reset_active: impl FnOnce()) -> u64 {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let epoch = Self::next_nonzero(&mut state.current_epoch);
        reset_active();
        epoch
    }

    /// 在 slot 锁内退休当前任务：先使 epoch 失效并清活动表，调用方随后才置 stop + abort。
    pub(super) fn retire(&self, epoch: u64, reset_active: impl FnOnce()) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.current_epoch != epoch {
            return false;
        }
        Self::next_nonzero(&mut state.current_epoch);
        reset_active();
        true
    }

    /// 当前任务共享副作用的唯一提交口：compare 与闭包副作用共处一个临界区。
    pub(super) fn commit<R>(&self, epoch: u64, effect: impl FnOnce() -> R) -> Option<R> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.current_epoch != epoch {
            return None;
        }
        Some(effect())
    }

    /// 非 relay 任务发起的共享副作用（当前只有 closed snapshot/clear）的线性化口。
    /// 调用方不携 task epoch，但仍与 task commit/start/retire 互斥，闭包不得跨 `.await`。
    pub(super) fn external_commit<R>(&self, effect: impl FnOnce() -> R) -> R {
        let _state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        effect()
    }

    /// 记一笔“新 aggregate 订阅者欠基线”的边沿；请求者不是 relay task，故无需 epoch。
    /// 每次 aggregate 订阅都置，不只 0→1：第二个订阅者同样没有基线；重复置只合并成一笔。
    pub(super) fn request_aggregate_baseline(&self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .aggregate_baseline_due = true;
    }

    /// 当前 task 取走 aggregate 基线边沿。必须先判 epoch 再清标志，stale task 不能偷走新任务的账。
    pub(super) fn consume_aggregate_baseline(&self, epoch: u64) -> Option<bool> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.current_epoch != epoch {
            return None;
        }
        Some(std::mem::take(&mut state.aggregate_baseline_due))
    }

    /// 给当前任务分配下一代 detail reset；非当前任务无权推进全局编号。
    pub(super) fn next_detail_generation(&self, epoch: u64) -> Option<u64> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.current_epoch != epoch {
            return None;
        }
        Some(Self::next_nonzero(&mut state.detail_generation))
    }

    #[cfg(test)]
    pub(super) fn is_locked_for_test(&self) -> bool {
        matches!(
            self.state.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        )
    }
}

/// stats 运行时（`State`-managed，单实例）。
pub struct StatsRelay {
    /// 降流门态（订阅注册表 + 门变更信号）；与两条 relay `Arc` 共享。
    pub(super) gate: Arc<StreamGateState>,
    /// 每窗口订阅记账（key = window label + topic，value = Subscription）。
    /// Polaris 按 webContents.sender 记账；Tauri 按 webview label 记账（窗口关闭时清理）。
    pub(super) subs: Mutex<Vec<(String, Topic, SubscriptionToken)>>,
    /// 连接长驻流 relay（`Some` = 在跑）。**aggregate / detail / closed 共用这一条**
    /// （三者来自同一事件流，见 [`run_connections_stream`]）——
    /// 此前是两个各自轮询的独立槽位。
    pub(super) connections: Mutex<Option<AggregatePoller>>,
    /// 连接流维护的完整活动表。连接导航从中导出有界排名；首页按画布槽位请求主要/最近目标投影，
    /// 搜索同样先过滤再投影，三者共用此表而不复制第二份长驻 host 索引。
    active_connections: Arc<Mutex<StatsAggregator>>,
    /// 已结束连接独立历史环；命令清空与连接流写入共享。
    closed_history: Arc<Mutex<ClosedHistory>>,
    /// 连接任务 epoch + detail generation 的跨任务唯一 owner。
    pub(super) connection_lifecycle: Arc<ConnectionStreamLifecycle>,
    /// stats topic（上下行速率 + 累计 + 连接数）的 `SubscribeStatus` 长驻流 relay（`Some` = 在跑）。
    pub(super) stats_poller: Mutex<Option<AggregatePoller>>,
}

impl Default for StatsRelay {
    fn default() -> Self {
        Self::new()
    }
}

impl StatsRelay {
    pub fn new() -> Self {
        Self {
            gate: Arc::new(StreamGateState::new()),
            subs: Mutex::new(Vec::new()),
            connections: Mutex::new(None),
            active_connections: Arc::new(Mutex::new(StatsAggregator::new())),
            closed_history: Arc::new(Mutex::new(ClosedHistory::default())),
            connection_lifecycle: Arc::new(ConnectionStreamLifecycle::default()),
            stats_poller: Mutex::new(None),
        }
    }

    /// 把 `(window, topic)` 作为幂等订阅键登记。renderer 重挂/StrictMode 可重复 invoke，同一窗口同一
    /// topic 不能因此无限追加 token：退订只会发一次，重复项会永久撑开 Vec 与 registry。
    pub(super) fn register_subscription(
        &self,
        window_label: &str,
        topic: Topic,
    ) -> Result<bool, String> {
        // 同时持两把锁完成「查重 + 两侧登记」，否则两个并发 subscribe 都可能先读到不存在再各自插入。
        // 其它路径在取 subs 后都会先释放再取 registry，不构成反向嵌套。
        let mut subs = self
            .subs
            .lock()
            .map_err(|error| format!("stats subs lock: {error}"))?;
        if subs
            .iter()
            .any(|(label, registered, _)| label == window_label && *registered == topic)
        {
            return Ok(false);
        }
        let mut registry = self
            .gate
            .registry
            .lock()
            .map_err(|error| format!("stats registry lock: {error}"))?;
        let token = registry.subscribe(topic, window_label.to_string());
        subs.push((window_label.to_string(), topic, token));
        Ok(true)
    }

    /// 订阅某 topic（上游 `stats:subscribe`）。非法 topic 静默忽略（不抛，避免 promise reject 噪音）。
    ///
    /// **非主窗的订阅一律拒绝 + 告警**（见 [`accepts_stats_subscription`]）。
    ///
    /// 订阅任一 topic → 起对应的后台 relay（单例幂等）。
    pub fn subscribe(
        &self,
        app: &AppHandle,
        proxy: Arc<ProxyRuntime>,
        config: Arc<ConfigManager>,
        window_label: &str,
        topic_str: &str,
    ) {
        let Some(topic) = parse_topic(topic_str) else {
            return;
        };
        if !accepts_stats_subscription(window_label) {
            log::warn!(
                "拒绝来自非主窗（label={window_label}）的 stats 订阅（topic={topic_str}）：\
                 降流门的可见性只看主窗，该窗的订阅会在主窗隐藏时被整体 park 掉 = 永远收不到帧。\
                 要给非主窗供数，须先把可见性判据从「主窗可见」改成「任一订阅窗可见」"
            );
            return;
        }
        match self.register_subscription(window_label, topic) {
            Ok(true) => {}
            Ok(false) => return,
            Err(error) => {
                log::warn!("{error}");
                return;
            }
        }
        // 新的排名聚合订阅者手上没有任何基线 → 记一笔边沿，由连接流任务在下一轮兑现（见该字段文档）。
        // 必须在 bump 之前置：bump 会立刻唤醒流任务，先 bump 后置就有一轮读不到这笔账。
        if topic == Topic::Connections {
            self.connection_lifecycle.request_aggregate_baseline();
        }
        // 订阅集变了 → 唤醒该 topic 已在跑但正断流待命的 relay（无订阅时停在门上的那条腿）。
        self.gate.bump();
        // 数据面 relay（订阅即起，内部按核起停自适应）：
        // - aggregate（排名聚合）、topology（首页流向信号）、detail（活动）、closed（已结束）→
        //   **同一条**连接长驻流，见 [`run_connections_stream`]）；
        // - stats → `SubscribeStatus` 长驻流（EVENT_STATS_UPDATED，见 [`run_stats_stream`]）。
        // 全部 topic 必须覆盖：漏一条即对应视图永不收帧。
        match topic {
            Topic::Connections | Topic::Topology | Topic::Detail | Topic::Closed => {
                self.ensure_connections_stream(app, proxy, config)
            }
            Topic::Stats => self.ensure_stats_stream(app, proxy, config),
        }
        if topic == Topic::Closed {
            self.emit_closed_snapshot(app);
        }
    }

    /// 退订某 topic（上游 `stats:unsubscribe`）。无匹配为 no-op。
    /// 该 topic 的订阅者归零 → 停对应的后台 relay。
    pub fn unsubscribe(&self, window_label: &str, topic_str: &str) {
        let Some(topic) = parse_topic(topic_str) else {
            return;
        };
        let token = {
            let mut subs = match self.subs.lock() {
                Ok(g) => g,
                Err(e) => {
                    log::warn!("stats subs lock: {e}");
                    return;
                }
            };
            let pos = subs
                .iter()
                .position(|(label, t, _)| label == window_label && *t == topic);
            pos.map(|i| subs.remove(i).2)
        };
        if let Some(token) = token {
            if let Ok(mut reg) = self.gate.registry.lock() {
                reg.unsubscribe(topic, token);
            }
            self.gate.bump(); // 订阅集变了 → 门重判（下一拍即降流，不空转）
        }
        // 连接流由四条需求共用：**四条都归零**才停。
        if matches!(
            topic,
            Topic::Connections | Topic::Topology | Topic::Detail | Topic::Closed
        ) && self.connections_subscriber_count() == 0
        {
            self.stop_connections_stream();
        }
        if topic == Topic::Stats && self.stats_subscriber_count() == 0 {
            self.stop_stats_stream();
        }
    }

    /// 窗口关闭：清该窗口全部订阅（Polaris registry 兜底防泄漏）+ aggregate 归零则停 relay。
    pub fn clear_window(&self, window_label: &str) {
        let removed = {
            let mut subs = match self.subs.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            let (keep, drop) = subs
                .iter()
                .cloned()
                .partition(|(label, _, _)| label != window_label);
            *subs = keep;
            drop
        };
        if let Ok(mut reg) = self.gate.registry.lock() {
            for (_, topic, token) in removed {
                reg.unsubscribe(topic, token);
            }
        }
        self.gate.bump();
        if self.connections_subscriber_count() == 0 {
            self.stop_connections_stream();
        }
        if self.stats_subscriber_count() == 0 {
            self.stop_stats_stream();
        }
    }

    /// 建窗成功后的生命周期接线。与 [`Self::mark_main_window_destroying`] 成对，只由主窗所有者调用。
    pub fn mark_main_window_created(&self) {
        self.gate.mark_main_window_created();
    }

    /// 销毁调用前的生命周期接线。它不清订阅；订阅只在 destroy 成功后提交清理，失败时仍可继续使用。
    pub fn mark_main_window_destroying(&self) {
        self.gate.mark_main_window_destroying();
    }

    /// 按窗口实况刷新可见性 → 降流门（Polaris stats-worker 据此门控 connectionsStreamOn）。
    ///
    /// 由 `main.rs` 的三个显隐写入点调（`WindowEvent::Focused` / 收托盘 `hide()` 后 / 单实例唤起
    /// `show()` 后）—— `Focused` 那处**不取 focused 的值**（失焦 ≠ 隐藏），只把它当「显隐可能刚变」
    /// 的即时触发器，真值一律经 [`probe_main_window_visible`](super::probe_main_window_visible) 回读窗口实况；变了即 bump 门代次 →
    /// 等在门上的 relay 立刻醒（恢复不等兜底周期）。
    ///
    /// 回读经 [`StreamGateState::spawn_visibility_refresh`] 投给主线程执行 —— 本方法在主线程被调用时
    /// 该闭包内联跑完，等价于同步回读；从别的线程调也不会阻塞（见 [`VisibilityCache`](super::gate::VisibilityCache)）。
    /// 托盘那条显隐路径（`tray/window.rs` 的 `hide()` / `show()`）没有写入点，靠 relay 的兜底刷新覆盖。
    pub fn refresh_window_visible(&self, app: &AppHandle) {
        self.gate.spawn_visibility_refresh(app);
    }

    /// 主窗可见性缓存的**只读**取值（非阻塞：一次原子 load + 顺带投递一次主线程刷新）。
    ///
    /// 降流门之外的第二个消费方：C16 自动轻量模式的后端闲置巡检（`crate::idle_lightweight`）。
    /// 让它读**这一份**缓存而不是自己回读窗口，一是不必再摊一份「非主线程回读会阻塞」的风险，
    /// 二是两处显隐真值恒一致。代价是最多落后一拍（调用方各自的巡检周期）—— 轻量巡检据此在真正
    /// 销毁前还会在主线程上做一次新鲜复核，见其 `enter_lightweight_if_still_hidden`。
    #[must_use]
    pub fn window_visible(&self, app: &AppHandle) -> bool {
        self.gate.cached_window_visible(app)
    }

    /// 在完整活动连接表上先过滤、再按首页实际画布槽位投影；返回载荷只随槽位增长。
    pub fn project_topology(
        &self,
        query: &str,
        slots: usize,
    ) -> Result<ConnectionsAggregate, String> {
        match self.active_connections.lock() {
            Ok(table) => Ok(table.project_topology(query, now_ms(), slots)),
            Err(error) => {
                log::warn!("活动连接流向投影 lock: {error}");
                Err(format!("活动连接数据暂不可用：{error}"))
            }
        }
    }

    /// 清空历史、构造返回快照并广播 reset；三步与 relay closed delta 共用同一 owner 临界区。
    pub fn clear_closed_history(&self, app: &AppHandle) -> ConnectionsClosedSnapshot {
        self.connection_lifecycle.external_commit(|| {
            let snapshot = match self.closed_history.lock() {
                Ok(mut history) => {
                    history.clear(now_ns());
                    history.snapshot(now_ms())
                }
                Err(error) => {
                    log::warn!("已结束连接历史 lock: {error}");
                    ConnectionsClosedSnapshot {
                        connections: Vec::new(),
                        at: now_ms(),
                    }
                }
            };
            broadcast(
                app,
                EVENT_CONNECTIONS_CLOSED,
                ConnectionsClosedUpdate {
                    reset: true,
                    connections: Vec::new(),
                    removed_ids: Vec::new(),
                    at: snapshot.at,
                },
            );
            snapshot
        })
    }

    /// 新 closed 订阅者的即时 reset；读取 snapshot 与 emit 不允许 relay delta 插入其间。
    fn emit_closed_snapshot(&self, app: &AppHandle) {
        self.connection_lifecycle.external_commit(|| {
            let at = now_ms();
            let update = self
                .closed_history
                .lock()
                .map(|history| history.update_snapshot(at))
                .unwrap_or(ConnectionsClosedUpdate {
                    reset: true,
                    connections: Vec::new(),
                    removed_ids: Vec::new(),
                    at,
                });
            broadcast(app, EVENT_CONNECTIONS_CLOSED, update);
        });
    }

    /// 连接流的活跃订阅者数 = **四条需求之和**（aggregate + topology + detail + closed）。
    ///
    /// 求和而非取 max/任一：`== 0` 恰好表达四条需求都没人消费。漏掉 `topology` 会在「只开着首页」
    /// 时把整条连接流停掉，首页拓扑随即冻结且无任何报错。
    pub(super) fn connections_subscriber_count(&self) -> usize {
        self.gate
            .registry
            .lock()
            .map(|r| {
                r.subscriber_count(Topic::Connections)
                    + r.subscriber_count(Topic::Topology)
                    + r.subscriber_count(Topic::Detail)
                    + r.subscriber_count(Topic::Closed)
            })
            .unwrap_or(0)
    }

    /// 确保连接长驻流 relay 在跑（单例 + TOCTOU 闸门，见 [`should_spawn_poller`]）。
    fn ensure_connections_stream(
        &self,
        app: &AppHandle,
        proxy: Arc<ProxyRuntime>,
        config: Arc<ConfigManager>,
    ) {
        let mut slot = match self.connections.lock() {
            Ok(g) => g,
            Err(e) => {
                log::warn!("连接流 slot lock: {e}");
                return;
            }
        };
        if !should_spawn_poller(slot.is_some(), self.connections_subscriber_count()) {
            return;
        }
        // 仍持 slot 锁；上面的 registry 计数锁已随调用返回释放。此后按文档锁序进入 lifecycle→active。
        let epoch = self.connection_lifecycle.start_task(|| {
            self.active_connections
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .reset();
        });
        let stop = Arc::new(AtomicBool::new(false));
        let handle = tauri::async_runtime::spawn(run_connections_stream(
            app.clone(),
            proxy,
            config,
            stop.clone(),
            StreamGate::connections(self.gate.clone()),
            ConnectionStreamTaskContext {
                epoch,
                lifecycle: self.connection_lifecycle.clone(),
                active_connections: self.active_connections.clone(),
                closed_history: self.closed_history.clone(),
            },
        ));
        *slot = Some(AggregatePoller {
            stop,
            connection_epoch: Some(epoch),
            handle,
        });
        log::debug!("连接流 relay 已启动");
    }

    /// 停连接流 relay（set stop + abort；无则 no-op）。
    ///
    /// TOCTOU 闸门：**slot 锁下**重校订阅计数（与 [`Self::ensure_connections_stream`] 互斥）。订阅计数
    /// （registry mutex）与 relay slot（本 mutex）是两把锁，非原子。若最后一个 unsubscribe 读到 count==0
    /// 后、并发 subscribe 又重新计数并见 slot=Some（依赖现有 relay 不重建），此处若无条件 stop 会把仍有
    /// 活订阅的 relay 停掉 → 留活订阅无 relay（拓扑/明细冻结到下次 sub/unsub，liveness gap）。故取 slot 后、
    /// abort 前，在锁内复查计数：仍有订阅则不停。
    pub(super) fn stop_connections_stream(&self) {
        let mut slot = match self.connections.lock() {
            Ok(g) => g,
            Err(e) => {
                log::warn!("连接流 slot lock: {e}");
                return;
            }
        };
        if self.connections_subscriber_count() != 0 {
            return; // 并发 subscribe 已重新计数并依赖此 relay → 绝不停。
        }
        if let Some(p) = slot.take() {
            let epoch = p
                .connection_epoch
                .expect("连接流 poller 必须携带 lifecycle epoch");
            // 仍持 slot 锁；registry 计数锁已经释放。严格按 lifecycle→active 先退休并清表，随后才
            // 置协作标志与 abort。旧任务即使正处于无 await 同步区，所有共享副作用也会被 epoch 拒绝。
            self.connection_lifecycle.retire(epoch, || {
                self.active_connections
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .reset();
            });
            p.stop.store(true, Ordering::Relaxed);
            p.handle.abort();
            log::debug!("连接流 relay 已停止");
        }
    }

    /// 当前 stats（[`Topic::Stats`]）活跃订阅者数。
    pub(super) fn stats_subscriber_count(&self) -> usize {
        self.gate
            .registry
            .lock()
            .map(|r| r.subscriber_count(Topic::Stats))
            .unwrap_or(0)
    }

    /// 确保 stats（Status 流）relay 在跑（单例 + TOCTOU 闸门，见 [`should_spawn_poller`]）。
    fn ensure_stats_stream(
        &self,
        app: &AppHandle,
        proxy: Arc<ProxyRuntime>,
        config: Arc<ConfigManager>,
    ) {
        let mut slot = match self.stats_poller.lock() {
            Ok(g) => g,
            Err(e) => {
                log::warn!("stats relay slot lock: {e}");
                return;
            }
        };
        if !should_spawn_poller(slot.is_some(), self.stats_subscriber_count()) {
            return;
        }
        let stop = Arc::new(AtomicBool::new(false));
        let handle = tauri::async_runtime::spawn(run_stats_stream(
            app.clone(),
            proxy,
            config,
            stop.clone(),
            StreamGate::stats(self.gate.clone()),
        ));
        *slot = Some(AggregatePoller {
            stop,
            connection_epoch: None,
            handle,
        });
        log::debug!("stats relay 已启动");
    }

    /// 停 stats relay（set stop + abort；无则 no-op）。
    ///
    /// TOCTOU 闸门：**slot 锁下**重校订阅计数（与 [`Self::ensure_stats_stream`] 互斥）——同连接流的
    /// liveness gap（订阅计数与 relay slot 两把锁非原子）。取 slot 后、abort 前锁内复查：仍有订阅则不停。
    pub(super) fn stop_stats_stream(&self) {
        let mut slot = match self.stats_poller.lock() {
            Ok(g) => g,
            Err(e) => {
                log::warn!("stats relay slot lock: {e}");
                return;
            }
        };
        if self.stats_subscriber_count() != 0 {
            return; // 并发 subscribe 已重新计数并依赖此 relay → 绝不停。
        }
        if let Some(p) = slot.take() {
            p.stop.store(true, Ordering::Relaxed);
            p.handle.abort();
            log::debug!("stats relay 已停止");
        }
    }
}

/// relay spawn 决策（两条流的 `ensure_*` 共用；**须在 slot 锁下**求值）。
///
/// 两个否决条件：
/// - `slot_occupied`：已在跑 → 幂等 no-op（单例）。
/// - `subscriber_count == 0`：**TOCTOU 闸门**，与 `stop_*_poller` 的锁内复查对称。registry 插入与
///   ensure 分属两把锁、中间无守卫，故存在：T1 subscribe 插入（count=1）→ T2 unsubscribe 跑完
///   （count=0；此刻 slot 仍 None → stop 是 no-op）→ T1 才 ensure → 起一条**零订阅者的 relay**。
///   此后无人再触发 stop（退订路径已走完）→ 上游流永久开着 + 无人消费的 emit。
///   前端实况触发器：`ConnectionsScreen` 的订阅 effect 依赖 `[paused]`，暂停切换即快速退订+重订；
///   React StrictMode 的双挂载同理。
pub(super) fn should_spawn_poller(slot_occupied: bool, subscriber_count: usize) -> bool {
    !slot_occupied && subscriber_count > 0
}

/// 纯判定：该 window label 的 stats 订阅能否被接受。
///
/// **只有主窗**（[`MAIN_WINDOW_LABEL`]）可订阅。降流门的可见性判据只看主窗
/// （[`probe_main_window_visible`](super::probe_main_window_visible)），故任何非主窗的订阅都会在主窗隐藏时被整体 park 掉 ——
/// 「注册了但永远收不到帧」，而且是**静默**的（订阅计数正常、relay 也在跑，只是门永远关着）。
///
/// 当前托盘浮层（独立 label 的 `tray.html`）不订阅任何 topic，故这条闸今天是空跑。
/// 它存在是为了让**将来**给非主窗接订阅的人立刻撞墙并看到日志，而不是上线后表现为
/// 「浮层数据时有时无」——那种缺陷要从可见性门一路倒推回来才找得到。
///
/// **拒绝而不是「接受 + 告警」**：接受等于把一条结构性饿死的订阅登记进注册表，
/// 表现为间歇性缺数据（主窗可见时又好了），比彻底不出数难查得多。
pub(super) fn accepts_stats_subscription(label: &str) -> bool {
    label == MAIN_WINDOW_LABEL
}

/// topic 字面量校验：只接受 stats | aggregate | topology | detail | closed。
///
/// `"topology"` 与 `"aggregate"` **必须映到两个不同的 [`Topic`]**：前者是首页那声「完整活动表变了」，
/// 后者是排名页的 Top-N 聚合载荷。映成同一个就等于把本拆分整个抵消掉（首页在场 ⇒ 聚合永远在算）。
pub(super) fn parse_topic(s: &str) -> Option<Topic> {
    match s {
        "stats" => Some(Topic::Stats),
        "aggregate" => Some(Topic::Connections),
        "topology" => Some(Topic::Topology),
        "detail" => Some(Topic::Detail),
        "closed" => Some(Topic::Closed),
        _ => None,
    }
}
