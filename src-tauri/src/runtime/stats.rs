//! stats 运行时：`polaris-stats-engine` 订阅注册表 + 流 relay。
//!
//! Polaris 锚点：`StatsSubscriptionRegistry`（`main/services/StatsSubscriptionRegistry.ts`）+
//! `StatsService.ts` / `StatsWorkerHost` 的 connections 长驻流 + change-driven 签名去重（issue #227
//! 把「连接风暴」挡在 main 侧：载荷与连接总数解耦，只在聚合内容真变时才推一帧）。
//!
//! renderer 按 topic（stats | aggregate | topology | detail | closed）声明订阅 → main 据订阅集派生
//! worker demand + 精确 relay 给订阅者。订阅即回初始帧（合并旧 GET 初值路径）。
//!
//! # 连接数据面：一条长驻流 + 四条需求（aggregate 排名 / topology 首页信号 / detail 活动 / closed 已结束）
//!
//! `aggregate` 与 `topology` **是两条需求不是一条**：前者是排名页要的 Top-N 聚合载荷（每次 emit 一次
//! O(n log n) 聚合 + 载荷序列化 + 跨进程搬运），后者只是首页要的一声「完整活动表变了」（一个 u64，
//! 首页据此按自己的画布槽位去拉**有界**投影）。首页从不读聚合载荷，故它只持 `topology` 令牌 ——
//! 合成一条的话，首页在场就等于排名页关着时那次聚合永远白做。
//!
//! 四个连接事件通道由**同一条**
//! `SubscribeConnections` 长驻流供数（[`run_connections_stream`](relay::run_connections_stream)）：流帧维护一张
//! [`StatsAggregator`](polaris_stats_engine::StatsAggregator) 活动连接表；CLOSED 在删表前另存入有界历史环。各视图同源且互不污染，
//! 上游只订一次。
//!
//! **此前是两条各自轮询的 poller**（每 250ms / 1s 各拉一次 `first_connection_snapshot` 全量表）。
//! 换流的判据：内核对 NEW/CLOSED 本就是事件驱动即时推送
//! （`daemon/started_service.go:752` 的 `case event := <-subscription`，只有 UPDATE 走 ticker）——
//! 轮询等于把一个推送接口当轮询接口用，既白等半拍，又每拍重付一次含 ≤1000 条死连接的全量表。
//!
//! 帧到达 → 更新活动表与历史环（O(1)/事件）→ 三条 [`polaris_stats_engine::EmitGate`] 各自合并节流
//! （topology 信号与 aggregate 载荷同源于一次拓扑变更，共用 `agg_emit` 那一条闸门，只是各看各的订阅门）。
//! aggregate 另有**签名去重**（`aggregate_signature`，同内容不推，issue #227）；detail 不去重
//! （渲染端靠相邻两帧差分算每条连接的速率，理由见 [`run_connections_stream`](relay::run_connections_stream)）。
//!
//! 生命周期：订阅时起（单例幂等）、**四条连接需求都**退订/窗口关闭时停；
//! 核未运行时**不碰 gRPC**（推一帧离线态后等核起）。
//!
//! # 流量数据面：`SubscribeStatus` 长驻流（stats topic）
//!
//! `EVENT_STATS_UPDATED`（StatusBar 的上下行速率 + 累计 + 连接数）由 [`run_stats_stream`](relay::run_stats_stream) 供数：
//! 一条 `SubscribeStatus` 长驻流 → [`StatsAggregator::on_status`](polaris_stats_engine::StatsAggregator::on_status) → emit。
//!
//! **此前是一条 1s 轮询**（每拍拉一次 `first_connection_snapshot` 全量表，对整表的
//! `uplink_total` 求和再跨拍差分）。换掉它的判据是**口径**不是性能：那个和**不过滤已关闭连接**，
//! 而内核的死连接历史环有 1000 条上限，环满后每淘汰一条，"累计总量"就**下跌**一截 ——
//! 累计读数会倒退，且 `saturating_sub` 把那一拍的速率吃成 0（连接高频起落时速率系统性偏低）。
//! `SubscribeStatus` 直给 `trafficcontrol.Manager.Total()`：两个只增的 `atomic.Int64`，
//! 关连接时 `leave()` 不减 ⇒ **结构上不可能回退**。
//!
//! ⚠️ 此前登记的两条拦路条**都是错的，勿再据以判断**：
//! - 「`Status.connectionsIn/Out` 内核不填、恒 0，故第五项仍得靠连接表」——`readStatus()`
//!   （`daemon/started_service.go:417`）两个字段都填：`ConnectionsOut = connectionManager.Count()`
//!   （`box.go:233` 无条件注册）、`ConnectionsIn = trafficManager.ConnectionsLen()`
//!   （daemon gRPC 走 `needAPIService`，该 manager 必被构造，`box.go:245`）。
//!   `connectionsIn` 恰是 `SubscribeConnections` 首帧里活连接的条数，是精确 drop-in。
//! - 「消费 tonic 流需 `futures::StreamExt` 而本 crate 只有 dev-dependency」——`recv()` 是
//!   [`polaris_singbox_grpc::ReconnectingStream`] 的固有方法，连接流早就这么用了。
//!
//! ⚠️ **`Status.uplink` / `downlink` 不是速率**，直接拿来用会得到恒 0：内核从不在 `readStatus()`
//! 里给它们赋值，是 `SubscribeStatus` 的循环每拍算一次 `UplinkTotal - uploadTotal` 再写回
//! （:408-413），**首帧在任何 tick 之前就 `Send`，两者恒 0**；而把增量折成速率所需的窗口长度
//! （服务端 ticker 的实际间隔）根本不在 wire 上。故速率一律由 [`StatsAggregator::on_status`](polaris_stats_engine::StatsAggregator::on_status)
//! 对累计做差分、除以**客户端实测 Δt**。
//!
//! # 降流门（维度7：无 UI 消费者时不拉取、不 emit）
//!
//! 契约的另一条腿：数据面需求 **不只**由订阅集派生，还乘上窗口可见性
//! （[`SubscriptionRegistry::should_stream`](polaris_stats_engine::SubscriptionRegistry::should_stream)；全部 topic 口径一致，均受可见性门控——Stats 曾是例外，
//! 该例外为何作废见 `polaris_stats_engine::Topic::gated_by_visibility` 的文档）。
//!
//! 两条腿现在**同一种机制**（[`StreamGate::wait_until`](gate::StreamGate::wait_until)）：判定为假 → **drop 流**，门再开时重订阅。
//! park 住不读流毫无意义 —— 帧会堆在 tonic 缓冲与内核发送窗口里，反而堵住内核的事件分发。
//! （连接流的重订阅必然收到一帧 `reset=true` 全量表，断流期间消失的连接靠它清掉，那些连接的 CLOSED
//! 永不补发——见 `polaris_stats_engine` 的 `reset帧整表替换而非增量叠加`；Status 流的重订阅则
//! 必须丢掉速率差分基线，理由见 [`StatsAggregator::on_status`](polaris_stats_engine::StatsAggregator::on_status)。）
//!
//! 收托盘/最小化后两条腿一起停手：两条上游流断开、逐秒明细增量与状态 IPC 归零，
//! 笔电不再为没人看的画面付电。断流期的兜底实况回读恒按 [`PARK_RECHECK_INTERVAL`]，
//! **不跟随任何 emit 间隔**——隐藏态下高频空转等于把降流的收益吐回去。
//!
//! 可见性真值来源：**窗口实况回读**（`is_visible() && !is_minimized()`，对齐 上游
//! `isUiBroadcastActive`），**不是** `WindowEvent::Focused`——失焦但仍在屏上的窗口依然有 UI 消费者。
//! Tauri 2 的 `WindowEvent` 没有 show/hide 变体，故实况回读按 [`PARK_RECHECK_INTERVAL`] 兜底重跑，
//! `main.rs` 的显隐写入点（`Focused` / 收托盘 / 单实例唤起）只作「显隐可能刚变」的**即时**触发器
//! （[`StatsRelay::refresh_window_visible`]）：门一变即经 `watch` 唤醒等在门上的 relay，
//! 恢复不等兜底周期，用户切回窗口无可感知空窗。
//!
//! ⚠️ **回读本身跑在主线程、relay 只读缓存**（见 [`VisibilityCache`](gate::VisibilityCache)）：窗口 getter 是「投消息进
//! 主事件循环 + 阻塞等回包」，直接在 relay 里调会在主循环被原生模态（提权框/菜单跟踪）占住时
//! 一次把两条后台腿一起挂死在 `recv` 上。

#![forbid(unsafe_code)]

use std::time::Duration;

/// `SubscribeStatus` 请求里的 `interval`（纳秒）—— **服务端推 Status 帧的节奏**。
///
/// 取 1s：一帧 Status 就是 StatusBar 上那五个数字，而它们是「秒级平均」的语义。推得更勤只会放大
/// 内核累计字节的采样抖动（速率读数更跳而不是更准），并让渲染端按同样的频率白重渲。
///
/// ⚠️ **本值不参与速率计算**，别把它当分母：服务端 `interval <= 0` 会兜底成 1s，且实际间隔含
/// ticker 调度抖动，wire 上也不回传实际值。速率的分母恒是 [`StatsAggregator::on_status`](polaris_stats_engine::StatsAggregator::on_status) 的
/// **实测 Δt**（见该方法文档）。本值改成 500ms 或 2s，速率读数都仍然正确。
const STATS_STREAM_INTERVAL_NS: i64 = 1_000_000_000;

/// aggregate（拓扑）emit 的**下限间隔** —— 注意语义：不是拉取周期。
///
/// # 前身与它为何换了语义
///
/// 本常量的前身是 `AGGREGATE_POLL_INTERVAL`（拓扑轮询周期，同为 250ms）。轮询时代它一身兼两职：
/// **多久拉一次内核**（成本）与**多久推一帧给渲染端**（观感）。改成长驻流后前一职消失
/// —— 内核对 NEW/CLOSED 是 `case event := <-subscription` 事件驱动即时推送
/// （`daemon/started_service.go:752`，只有 UPDATE 走 ticker），我们不再「问」，只是「收」。
///
/// 于是当年那半条成本判据（「每拍新建一条订阅流，服务端构造活跃连接 + ≤1000 条死连接历史环的
/// 全量 protobuf ≈ 200–500 KB/拍，且这段在签名去重的上游、随节拍线性上涨」）**整段作废**：
/// 长驻流一次订阅只付一次首帧全量，此后全是增量。**下界不再由 gRPC 成本决定。**
///
/// # 现在的取值判据
///
/// - **下界 250ms（观感 + 渲染成本，不再是 gRPC 成本）**：每一次 emit 都要 O(n log n) 聚合 + Top-N +
///   过 IPC + 渲染端重排整张拓扑图。而拓扑节点的出现/消失在 250ms 与 100ms 之间没有可分辨差异 ——
///   `.link` / `.node` 的 opacity 过渡本身就是 160ms（`ui/src/styles/components.css:224`），
///   比 100ms 还长。**「实时」不等于越快越好**：再快只是让渲染端多做功，用户一帧都多看不到。
/// - **上界 350ms**：拓扑答的是「此刻有哪些连接、走哪个出口」，用户点开一个网页就等着看新节点冒出来。
///   1s 一拍在交互上是「反应了一下」；250ms 落在 Nielsen 的 0.1s/1s 两道门之间偏 0.1s 一侧，已是「跟手」。
///
/// # 真正的延迟改善来自换流，不来自本常量
///
/// 轮询时代一次变化的可见延迟是「≤一拍 + RTT」（平均半拍 ≈ 125ms 的等待纯属白等）。
/// 长驻流下**事件发生即到达**，本常量只在「上一次 emit 之后不足 250ms 又来了变化」时才生效，
/// 且那种情况下推迟的也只是**合并后的一帧**（见 [`polaris_stats_engine::EmitGate`] 的尾沿保证）。
/// 空闲时一次孤立的连接变化 → 延迟 ≈ RTT，与本常量无关。
///
/// 区间由 `aggregate_emit间隔取值区间` 锁死。
const AGGREGATE_EMIT_MIN_INTERVAL: Duration = Duration::from_millis(250);

/// detail（连接明细）emit 的下限间隔。
///
/// 前身是 detail 那条 poller 的轮询周期（1s）。现在常态只合并 upsert / 累计计数 / 删除 id，
/// 但逐连接速率与时长仍没有高于 1Hz 的阅读价值；1s 窗口也能把同一连接的高频 UPDATE 合成一次。
///
/// **比 aggregate 慢一档是刻意的**：拓扑关注连接出现/消失，明细还承担逐行计数与速率刷新；
/// 两者共用一条上游流，但交互节奏不同，没有理由共用一个 emit 频率。
const DETAIL_EMIT_MIN_INTERVAL: Duration = Duration::from_secs(1);

/// 已结束连接只保留最近 1000 条，对齐 sing-box 重置帧能重放的历史上限。
/// 再高只在本进程期间有效，连接流重订后无法补回，反而会制造不一致。
const MAX_CLOSED_HISTORY: usize = 1_000;

/// 已结束历史最多每秒推一次；连接风暴时合并 CLOSED 增量。
/// 只有订阅首帧 / 内核 reset / 用户清空才传全量，常态不再复制千行 JSON。
const CLOSED_EMIT_MIN_INTERVAL: Duration = Duration::from_secs(1);

/// `SubscribeConnections` 请求里的 `interval`（纳秒）—— **只管服务端 UPDATE 帧的节奏**。
///
/// 对齐 上游 `CONNECTIONS_INTERVAL_NS = 1_000_000_000`（`StatsService.ts:20`）。
///
/// 容易误读，钉清楚：这个值**不影响 NEW / CLOSED 的延迟**。服务端 `SubscribeConnections` 的
/// 事件分支（`case event := <-subscription`）与 ticker 分支是并列的两条腿 ——
/// 连接建立/断开当刻即推，ticker 只驱动 `buildTrafficUpdates`（per-connection 字节增量）。
/// 取 1s 是因为 UPDATE 的唯一消费者是明细表的每条连接速率，而那张表本身按
/// [`DETAIL_EMIT_MIN_INTERVAL`] 每秒推一帧 —— 让内核比我们推得更勤没有意义。
///
/// 服务端 `interval <= 0` 会兜底成 1s，故取值不会退化成忙转。
const CONNECTIONS_STREAM_INTERVAL_NS: i64 = 1_000_000_000;

/// 断流待命期的兜底实况回读周期（**恒 1s，不跟随任何 emit 间隔**）。
///
/// Tauri 2 没有 show/hide 事件，已断流、等在门上的 relay 只能定期回读窗口实况兜底
/// （详见 [`StreamGate::wait_until`](gate::StreamGate::wait_until)）。隐藏态下每回读一次就要取一次 registry 锁 +
/// 投一次主线程可见性回读，把这个周期调快等于把降流省下的电烧回去。
///
/// 第二个用途（**同一个数字，两条理由**）：两条 relay 流循环里的兜底唤醒周期 ——
/// `ReconnectingStream` 断了自己重连、永不 yield 错误，故「核停了 / 核换端口重启了」这两件事
/// 必须靠定期复核 `proxy.status()` 才发现得了。
///
/// 恢复延迟不受它影响 —— 门变更（`epoch` bump）才是立刻唤醒的那条腿，本常量只是「事件丢了」的兜底。
const PARK_RECHECK_INTERVAL: Duration = Duration::from_secs(1);

/// 主窗 label。渲染端订阅只来自主窗（`commands::stats` 按 `window.label()` 记账）；托盘浮层是
/// 独立 label 的 `tray.html`，不订阅任何 stats topic，故不该把它算作「有 UI 消费者」。
pub(crate) const MAIN_WINDOW_LABEL: &str = "main";

mod gate;
mod projection;
mod relay;
mod subscription;

pub(crate) use gate::probe_main_window_visible;
pub use subscription::StatsRelay;

#[cfg(test)]
mod tests;
