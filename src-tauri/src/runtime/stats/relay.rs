//! gRPC 流接收与事件转发：两条长驻流（连接流 / Status 流）的循环体，
//! 外加 `daemon::*` → `polaris-stats-engine` 的映射、聚合/签名与离线帧构造。
//!
//! 连接任务归属与 detail generation 的跨任务 owner 在
//! [`super::subscription::ConnectionStreamLifecycle`]；循环内的合并窗仍是单任务局部状态。
//! 断流是 [`StreamGate::wait_until`] 的假值腿、重订阅是下一轮外循环（连同 `reset()` 与基线作废）。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde_json::Value;
use tauri::AppHandle;

use polaris_singbox_grpc::{daemon, Endpoint, ReconnectConfig, SingBoxApiClient};
use polaris_stats_engine::{
    aggregate_connections_with_topn, aggregate_signature, trim_connection, ConnectionEntry,
    ConnectionEventType, ConnectionsAggregate, EmitGate, SingBoxConnection, SingBoxConnectionEvent,
    SingBoxConnectionEvents, SingBoxProcessInfo, SingBoxStatus, StatsAggregator, Topic,
    TrafficStats, CONNECTION_RANKING_LIMIT,
};

use crate::events::{
    broadcast,
    channel::{
        EVENT_CONNECTIONS_AGGREGATE, EVENT_CONNECTIONS_CLOSED, EVENT_CONNECTIONS_DETAIL,
        EVENT_CONNECTIONS_TOPOLOGY_CHANGED, EVENT_STATS_UPDATED,
    },
};
use crate::runtime::config::ConfigManager;
use crate::runtime::proxy::ProxyRuntime;

use super::gate::{visibility_source, StreamGate};
use super::projection::{ClosedHistory, PendingClosedUpdate, PendingDetailUpdate};
use super::subscription::ConnectionStreamLifecycle;
use super::{
    AGGREGATE_EMIT_MIN_INTERVAL, CLOSED_EMIT_MIN_INTERVAL, CONNECTIONS_STREAM_INTERVAL_NS,
    DETAIL_EMIT_MIN_INTERVAL, PARK_RECHECK_INTERVAL, STATS_STREAM_INTERVAL_NS,
};

/// gRPC `daemon::Connection` → stats-engine `ConnectionEntry`（复用 [`trim_connection`] 的裁剪，
/// 不另写一份 host/IP 拆分逻辑）。
pub(super) fn daemon_conn_to_entry(c: &daemon::Connection) -> ConnectionEntry {
    trim_connection(&daemon_conn_to_engine(c))
}

/// prost `daemon::Connection` → 纯逻辑层 [`SingBoxConnection`]。
///
/// 从 [`daemon_conn_to_entry`] 里拆出来的**同一段**映射：长驻流要把整条连接喂进
/// [`StatsAggregator`]（它按 id 维护连接表、按 delta 累加字节），不能像轮询那样拿到就 trim ——
/// trim 是有损的（丢 `closed_at` / 只留展示字段），trim 完就没法再判幽灵、也没法累加。
///
/// **刻意不加字段**：这里映射哪些字段决定了 aggregate / detail 的输出，与轮询时代必须逐字一致，
/// 否则「换了数据来源」会顺手变成「换了显示内容」。
///
/// `inbound`（入站 **tag**，非 `inbound_type`）是该规矩下唯一的例外，且不破它：[`trim_connection`]
/// 不读这个字段 ⇒ aggregate / detail 的输出一字不变。它只喂 [`StatsAggregator`] 的准入判据——
/// 主核测速探测池 `probe-in-{k}` 的连接是应用自己的流量，不进连接表（见 aggregator NEW 分支）。
/// 此前它一直落在 `..Default::default()` 里恒为空串，探测连接因而无从识别。
fn daemon_conn_to_engine(c: &daemon::Connection) -> SingBoxConnection {
    let process_path = c
        .process_info
        .as_ref()
        .map(|p| p.process_path.clone())
        .unwrap_or_default();
    SingBoxConnection {
        id: c.id.clone(),
        inbound: c.inbound.clone(),
        inbound_type: c.inbound_type.clone(),
        network: c.network.clone(),
        source: c.source.clone(),
        destination: c.destination.clone(),
        domain: c.domain.clone(),
        created_at: c.created_at,
        closed_at: c.closed_at,
        uplink_total: c.uplink_total,
        downlink_total: c.downlink_total,
        rule: c.rule.clone(),
        chain_list: c.chain_list.clone(),
        process_info: SingBoxProcessInfo {
            process_path,
            ..Default::default()
        },
        ..Default::default()
    }
}

/// prost `daemon::ConnectionEvents` 帧 → 纯逻辑层 [`SingBoxConnectionEvents`]。
///
/// `type` 是 proto enum（`NEW=0 / UPDATE=1 / CLOSED=2`），prost 生成成 `i32`。
/// **未知值兜底成 `New`**：proto3 的开放枚举语义 —— 新核加了事件类型而旧客户端不认时，
/// 当 NEW 处理最多是多一条连接（还会被 `closed_at` 幽灵过滤兜一道），当 CLOSED 处理则会
/// **误删一条活连接**。兜底方向选不伤表的那侧。
fn daemon_events_to_engine(ev: &daemon::ConnectionEvents) -> SingBoxConnectionEvents {
    SingBoxConnectionEvents {
        reset: ev.reset,
        events: ev
            .events
            .iter()
            .map(|e| SingBoxConnectionEvent {
                kind: match e.r#type {
                    x if x == daemon::ConnectionEventType::Update as i32 => {
                        ConnectionEventType::Update
                    }
                    x if x == daemon::ConnectionEventType::Closed as i32 => {
                        ConnectionEventType::Closed
                    }
                    _ => ConnectionEventType::New,
                },
                id: e.id.clone(),
                connection: e.connection.as_ref().map(daemon_conn_to_engine),
                uplink_delta: e.uplink_delta,
                downlink_delta: e.downlink_delta,
                closed_at: e.closed_at,
            })
            .collect(),
    }
}

/// 连接快照 → 拓扑聚合（首帧全量含历史环死连接，按 `closed_at>0` 过滤）。
///
/// relay 的纯数据面核心（无 gRPC / 无 emit），单测直接喂 fixture。
pub(super) fn build_aggregate(conns: &[daemon::Connection], at: u64) -> ConnectionsAggregate {
    let entries: Vec<ConnectionEntry> = conns
        .iter()
        .filter(|c| c.closed_at <= 0) // 丢弃历史环死连接（快照含之）
        .map(daemon_conn_to_entry)
        .collect();
    aggregate_connections_with_topn(&entries, at, CONNECTION_RANKING_LIMIT)
}

/// change-driven 去重：聚合内容签名相较上帧变了才返回 `Some(new_sig)`（应 emit）；同签名返回 `None`（去重）。
///
/// issue #227 的核心：载荷与连接总数解耦——连接风暴（大量 UPDATE）但拓扑内容不变时**不推**，
/// 只在 host/outbound 计数或成员真变时推一帧。
pub(super) fn signature_changed(
    agg: &ConnectionsAggregate,
    last: &Option<String>,
) -> Option<String> {
    let sig = aggregate_signature(agg);
    if last.as_deref() == Some(sig.as_str()) {
        None
    } else {
        Some(sig)
    }
}

/// 排名聚合令牌的开合转换处理：**翻开或新订阅者进场**即作废签名基线 + 记一次待推（⇒ 强制发一帧
/// 当前真相）。返回新的 `was_open`（调用方存回）。
///
/// 两条触发腿互为补集，缺一条都留窗口：`baseline_requested` 是 `subscribe` 置的**边沿**（挡住
/// 「退订+重订两次 bump 被 watch 合并、电平没变」那个窗，见
/// `ConnectionStreamLifecycleState::aggregate_baseline_due`）；
/// `!was_open` 是**电平**兜底（挡住「边沿在流未起时被别人取走」）。`open` 为假时两条都不生效 ——
/// 那一刻没有消费者，强制的帧只会白付；此时 `was_open` 落回 false，下次开门由电平腿接住。
///
/// # 为什么必须两件事一起做
///
/// 令牌翻开 = 一轮新的订阅生命周期。订阅方（连接导航排名页）手上没有任何基线——它的 `aggregate`
/// state 从 `null` 起、靠推帧填充——而 `last_sig` 还停在上一轮的残值。只清签名不 `note_change`，
/// 基线帧要等下一次拓扑变化才发得出去（网络恰好安静就是空窗）；只 `note_change` 不清签名，那一帧
/// 会被签名去重当成「内容没变」吞掉（空窗期内表变回旧形态就会命中）。两件事缺一条都留空窗。
///
/// # 为什么抽成函数而不是在循环里内联三行
///
/// 循环本体要真 gRPC 流才跑得起来，内联版本只能靠源码型守卫，而源码守卫抓不到「清了签名却忘了
/// `note_change`」这类半截实现。抽出来之后这条不变式可以被**直测**（见
/// `排名令牌翻开必须清签名并强制一帧`），源码守卫只负责证明它真被接在循环里、且排在 emit 之前。
pub(super) fn apply_aggregate_demand_transition(
    open: bool,
    was_open: bool,
    baseline_requested: bool,
    last_sig: &mut Option<String>,
    emit: &mut EmitGate,
) -> bool {
    if open && (baseline_requested || !was_open) {
        *last_sig = None;
        emit.note_change();
    }
    open
}

/// 核未运行时的 aggregate offline 帧：空聚合经**正常签名去重**推一帧（`emit` 由调用方注入）。
///
/// 返回新签名（推了）/ `None`（去重，本轮不推）。
///
/// 此前 offline 分支只复位签名、**不推帧** → 前端 aggregate state 永远停在停核前的旧值（首页拓扑继续
/// 显示「连接: N」+ 旧 host 列表），而明细页的 offline 空帧已如实归零 → 两页互相矛盾。语义与
/// [`run_connections_stream`] 的离线空帧对齐。
///
/// 走既有签名去重而非另加 flag：空聚合的签名**本身**即「核已停」的基准 —— 进入停核态时签名由旧内容
/// 变空 → 推一帧（天然边沿触发，核停着不逐秒重推）；核回来后首帧内容非空 → 签名再变 → 必推。
pub(super) fn offline_aggregate_frame(
    last_sig: &Option<String>,
    at: u64,
    emit: impl FnOnce(ConnectionsAggregate),
) -> Option<String> {
    let agg = build_aggregate(&[], at);
    let sig = signature_changed(&agg, last_sig)?;
    emit(agg);
    Some(sig)
}

/// 核未运行时的 stats 清零帧（速率 / 累计 / 连接数全 0）。
///
/// **刻意是个常量帧、不经任何差分状态求值**：清零帧若从聚合器里取，就得先把「停核期的 0」写进
/// 速率基线，核回来后的首帧便会拿它做差分 → 把核重启后的全部历史累计字节一次性算成瞬时速率
/// （天文数字尖峰）。调用方另行 `reset()` 聚合器丢基线，两件事各归各位。
pub(super) fn offline_stats_frame() -> TrafficStats {
    TrafficStats::zeroed()
}

/// prost `daemon::Status` 帧 → 纯逻辑层 [`SingBoxStatus`]。
///
/// 与 [`daemon_conn_to_engine`] 同型的一段纯映射。字段逐条搬，**不在这里做任何口径加工**
/// （速率推导、可用性判断都在各自该在的层）。
pub(super) fn daemon_status_to_engine(s: &daemon::Status) -> SingBoxStatus {
    SingBoxStatus {
        memory: s.memory,
        goroutines: s.goroutines,
        connections_in: s.connections_in,
        connections_out: s.connections_out,
        traffic_available: s.traffic_available,
        uplink: s.uplink,
        downlink: s.downlink,
        uplink_total: s.uplink_total,
        downlink_total: s.downlink_total,
    }
}

/// 纯判定：`trafficAvailable` 的当前值是否**相对上一次**变了（`None` = 还没见过任何一帧）。
///
/// # 为什么这件事必须有可观测信号
///
/// `SubscribeStatus` 对 `trafficManager == nil` **不做任何前置校验、不返错**：`readStatus()`
/// 只是跳过那三行赋值，于是流照常每秒推帧，`uplinkTotal` / `downlinkTotal` / `connectionsIn`
/// 安静地全是 0。UI 上的表现是「速率恒 0 B/s、累计恒 0、连接数恒 0，且没有任何错误」——
/// 与「用户真的没在传数据」逐像素一致，无从区分，也无从排查。
///
/// 故必须显式判 `trafficAvailable` 并把它喊出来。判据取**变化沿**而非每帧：值一旦稳定下来
/// （生产里它恒为 true——daemon gRPC 走 `needAPIService`，`trafficManager` 必被构造，见 `box.go:245`），
/// 每帧一条日志就是每秒一条噪音，反而把真信号淹掉；而每次建流后基线复位成 `None`，
/// 故每条新流的第一帧必报一次。
pub(super) fn traffic_availability_changed(prev: Option<bool>, now: bool) -> bool {
    prev != Some(now)
}

/// 当前 epoch 毫秒（聚合 `at` 采样时刻；签名比对时被剔除，故不影响去重）。
pub(super) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 当前 epoch 纳秒。只用作「清空已结束历史」的重放水位及缺失 closedAt 的保守回落。
pub(super) fn now_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// currentConfig.clashApiSecret（对齐 proxy.rs `management_api()` 的读法）。
fn read_clash_secret(config: &ConfigManager) -> String {
    config
        .current()
        .ok()
        .and_then(|c| {
            c.get("clashApiSecret")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_default()
}

/// 把一次本地 reset 请求绑定到共享 owner 分配的 generation。已经有待发 reset 时沿用其编号，
/// 避免连续上游 reset 在真正 emit 前空耗代次；否则必须由当前 task epoch 分配新代。
fn begin_detail_generation(
    lifecycle: &ConnectionStreamLifecycle,
    task_epoch: u64,
    pending: &mut PendingDetailUpdate,
) -> bool {
    let generation = if pending.reset {
        pending.generation
    } else {
        let Some(generation) = lifecycle.next_detail_generation(task_epoch) else {
            return false;
        };
        generation
    };
    pending.begin_generation(generation);
    true
}

/// 一条连接任务的共享归属与表引用；捆成一项避免 spawn 边界把同一生命周期拆成散落参数。
pub(super) struct ConnectionStreamTaskContext {
    pub(super) epoch: u64,
    pub(super) lifecycle: Arc<ConnectionStreamLifecycle>,
    pub(super) active_connections: Arc<Mutex<StatsAggregator>>,
    pub(super) closed_history: Arc<Mutex<ClosedHistory>>,
}

/// 连接长驻流 relay：**一条** `SubscribeConnections` 流同时喂 aggregate（拓扑）与 detail（明细）。
///
/// # 为什么是一条流、两条 emit
///
/// 拓扑与明细从来不是两份数据，是同一张连接表的两种投影（聚合拓扑 / 增量明细）。
/// 轮询时代它们各起一条 poller、各拉一次全量表，是纯粹的重复劳动 ——
/// 而且两次拉取时刻不同，还能给出互相矛盾的两帧（拓扑说 12 条、明细列 13 条）。
/// 一条流 + 一张表 + 两条各自节流的 emit，既省一半上游成本，又让两个页面**恒定自洽**。
///
/// # 相对轮询变了什么
///
/// | | 轮询（旧） | 长驻流（本函数） |
/// |---|---|---|
/// | 延迟 | ≤一拍 + RTT（平均白等半拍） | 事件发生即 ≈RTT |
/// | 上游 | 每秒 4 次(agg) + 1 次(detail) 全量表 | 每次订阅一帧全量，此后只有增量 |
/// | 死连接 | 每拍重新下发 ≤1000 条再由我们过滤 | 只在 reset 帧出现一次 |
/// | 降流 | park 一拍（不拉取） | **drop 流**（见 [`StreamGate`]） |
///
/// # 生命周期（每一轮外循环 = 一条流的一生）
///
/// 1. [`StreamGate::wait_until`] 等门开（无订阅者 / 主窗不可见 → 断流待命，不碰 gRPC）。
/// 2. 核未运行 → 推一帧离线态（拓扑空聚合 + 明细空 reset）让两个页面如实归零，等核回来。
/// 3. 建 h2c 客户端 + 订阅流；**连接表与两条 emit 闸门一并复位** —— 新流的首帧是 `reset=true`
///    全量表，旧表在此刻已作废（断流期间断掉的连接不会补发 CLOSED，只有 reset 能清掉它们）。
/// 4. 内循环消费帧，直到门关 / 核停 / 换端口 → 跳出，drop 流，回到 1。
///
/// # 为什么内循环还有一个 1s 的兜底唤醒
///
/// [`ReconnectingStream`](polaris_singbox_grpc::ReconnectingStream) 的语义是**永不向消费方 yield 错误或 None**（断了自己重连），
/// 于是「核停了」「核换端口重启了」这两件事**流本身不会告诉我们** —— 不兜底的话，核换口重启后
/// 这条流会永远重连到旧端口，两个页面静默冻结。故内循环每 [`PARK_RECHECK_INTERVAL`] 至少醒一次
/// 复核 `proxy.status()`。代价是一次进程内 mutex 读，与它替掉的每秒 5 次全量 gRPC 拉取不在一个量级。
pub(super) async fn run_connections_stream(
    app: AppHandle,
    proxy: Arc<ProxyRuntime>,
    config: Arc<ConfigManager>,
    stop: Arc<AtomicBool>,
    mut gate: StreamGate,
    task: ConnectionStreamTaskContext,
) {
    let ConnectionStreamTaskContext {
        epoch: task_epoch,
        lifecycle,
        active_connections,
        closed_history,
    } = task;
    let visible = visibility_source(gate.state.clone(), app.clone());
    // 节流用**单调**时钟，不是 `now_ms()`（墙钟）：NTP 校时会让墙钟跳变，往前跳一小时 =
    // 一次无节制 emit，往后跳 = emit 被饿死一小时。墙钟只用来填帧里的 `at` 字段（那是给渲染端看的时刻）。
    let clock = Instant::now();
    let mut agg_emit = EmitGate::new(AGGREGATE_EMIT_MIN_INTERVAL);
    let mut detail_emit = EmitGate::new(DETAIL_EMIT_MIN_INTERVAL);
    let mut closed_emit = EmitGate::new(CLOSED_EMIT_MIN_INTERVAL);
    let mut detail_pending = PendingDetailUpdate::default();
    let mut closed_pending = PendingClosedUpdate::default();
    let mut last_sig: Option<String> = None;
    let mut offline_sent = false;
    let mut offline_detail_was_open = false;
    // 每个连接任务出生即欠一帧新代 reset；编号来自跨任务 owner，不随此 future 重建而回退。
    if !begin_detail_generation(&lifecycle, task_epoch, &mut detail_pending) {
        return;
    }

    while !stop.load(Ordering::Relaxed) {
        // ① 降流门：关着就在这里断流待命。
        gate.wait_until(true, &visible).await;

        // ② 核未运行 → 不碰 gRPC，推一帧离线态（只在进入该态时推一次；核停着重复推相同空帧
        //    只会让渲染端白重渲）。
        //
        //    **已知缺口（既存，本批未改，改它要另开射程）**：本分支不做排名聚合令牌的开合处理 ——
        //    核停着时打开排名页，流任务已驻此处且 `offline_sent` 已真 ⇒ 新订阅者收不到空基线帧，
        //    前端 `aggregate` 停在 `null`。判为可接受：`null` 与空聚合在排名页的读点上同解
        //    （`aggregate?.hosts ?? []`），且「无连接」正是核停着时的真相；核一起来建流即
        //    `last_sig = None` 自愈。**待真机确认**：`null` 态与空帧态的占位文案/骨架是否真的同形。
        let status = proxy.status();
        if !status.running || status.clash_api_port == 0 {
            if !offline_sent {
                let Some(sig) = lifecycle.commit(task_epoch, || {
                    let sig = offline_aggregate_frame(&last_sig, now_ms(), |agg| {
                        broadcast(&app, EVENT_CONNECTIONS_AGGREGATE, agg);
                    });
                    active_connections
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .reset();
                    sig
                }) else {
                    return;
                };
                if let Some(sig) = sig {
                    last_sig = Some(sig);
                }
                if !begin_detail_generation(&lifecycle, task_epoch, &mut detail_pending) {
                    return;
                }
                offline_sent = true;
            }
            let detail_open = gate.topic_open(Topic::Detail);
            if ((!detail_open && offline_detail_was_open)
                || (detail_open && !offline_detail_was_open && !detail_pending.reset))
                && !begin_detail_generation(&lifecycle, task_epoch, &mut detail_pending)
            {
                return;
            }
            if detail_open {
                let Some(()) = lifecycle.commit(task_epoch, || {
                    let table = active_connections
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if let Some(update) = detail_pending.take_update(&table, now_ms()) {
                        broadcast(&app, EVENT_CONNECTIONS_DETAIL, update);
                    }
                }) else {
                    return;
                };
            }
            offline_detail_was_open = detail_open;
            tokio::time::sleep(PARK_RECHECK_INTERVAL).await;
            continue;
        }

        // ③ 建流。
        let port = status.clash_api_port;
        let secret = read_clash_secret(&config);
        let client = match SingBoxApiClient::connect(Endpoint::new("127.0.0.1", port), secret).await
        {
            Ok(c) => c,
            Err(e) => {
                log::debug!("连接流：管理 API 连接失败 {e}");
                tokio::time::sleep(PARK_RECHECK_INTERVAL).await;
                continue;
            }
        };
        let mut stream = client
            .subscribe_connections(CONNECTIONS_STREAM_INTERVAL_NS, ReconnectConfig::default());
        // 新流 = 新的一份真相：旧连接表在此刻作废，等首帧 reset 重建。
        if lifecycle
            .commit(task_epoch, || {
                active_connections
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .reset();
            })
            .is_none()
        {
            return;
        }
        if !begin_detail_generation(&lifecycle, task_epoch, &mut detail_pending) {
            return;
        }
        agg_emit.reset();
        detail_emit.reset();
        closed_emit.reset();
        closed_pending.clear();
        // 签名基线同属「旧表的属性」，必须跟着旧表一起作废：断流期间表被 `reset()` 清空又由首帧
        // 重建，留着旧签名就等于宣称「渲染端手上那份仍是当前真相」—— 而断流可能横跨几分钟，且
        // 断流期内订阅方可能整个重挂过（排名页 state 回到 `null`）。签名相等时这一帧会被去重吞掉，
        // 表现就是排名页空着。清成 `None` ⇒ 新流的第一帧必发一次基线。
        last_sig = None;
        offline_sent = false;
        offline_detail_was_open = false;
        let mut detail_was_open = gate.topic_open(Topic::Detail);
        let mut agg_was_open = gate.topic_open(Topic::Connections);
        // 需求集变更的唤醒腿（订阅/退订/可见性翻转都会 bump 这个代次）。`gate` 自己那个接收端已被
        // `wait_until` 占着，这里另订一个：`watch::Receiver::changed()` 是 cancel-safe 的，被 select
        // 丢弃只是停止等待。每条流各建一个 ⇒ 建流那一刻的代次即基准，不会把上一条流的旧 bump 补收。
        let mut demand_epoch = gate.state.epoch.subscribe();
        log::debug!("连接流已订阅（port={port}）");

        // ④ 流循环。
        loop {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            // 下次该醒的时刻：两条 emit 的到期时间与核状态复核周期取最小。
            // 两条都无待推变更（空闲）→ 只剩兜底复核，不设无谓定时器。
            let now = mono_ms(clock);
            let due = [
                agg_emit.wait_for(now),
                detail_emit.wait_for(now),
                closed_emit.wait_for(now),
            ]
            .into_iter()
            .flatten()
            .min()
            .map_or(PARK_RECHECK_INTERVAL, |d| d.min(PARK_RECHECK_INTERVAL));

            tokio::select! {
                frame = stream.recv() => match frame {
                    Some(ev) => {
                        let events = daemon_events_to_engine(&ev);
                        let Some((closed_change, detail_change)) = lifecycle.commit(task_epoch, || {
                            let mut table = active_connections
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            let closed_change = closed_history
                                .lock()
                                .map(|mut history| history.apply_events(&events, &table))
                                .unwrap_or(None);
                            let detail_change = table.on_connection_events(&events, 0);
                            (closed_change, detail_change)
                        }) else {
                            return;
                        };
                        let topology_changed = detail_change.affects_topology();
                        if detail_change.reset
                            && !begin_detail_generation(
                                &lifecycle,
                                task_epoch,
                                &mut detail_pending,
                            )
                        {
                            return;
                        }
                        detail_pending.merge(detail_change);
                        if topology_changed {
                            agg_emit.note_change();
                        }
                        detail_emit.note_change();
                        if let Some(change) = closed_change {
                            closed_pending.merge(change);
                            closed_emit.note_change();
                        }
                    }
                    // ReconnectingStream 正常语义下不返 None；真返了说明它内部终止 → 重建。
                    None => break,
                },
                // 门关（退订 / 主窗隐藏）→ 跳出即 drop 流，整条链路成本归零。
                () = gate.wait_until(false, &visible) => break,
                // 需求集变了（某条 topic 刚被订上/退掉）→ **立刻**醒一次，让下面的开合转换在本帧完成。
                // 没有这条腿，令牌翻开后要等到 `due`（最坏一个 [`PARK_RECHECK_INTERVAL`]）才发得出基线
                // 帧 —— 那是一次实打实的推迟推送，正是本轮不许引入的东西。
                res = demand_epoch.changed() => {
                    // sender 随 StatsRelay 存活于进程全程；Err 只可能出现在收尾 → 退避防忙转
                    // （同 `wait_until` 里那条腿的处置）。
                    if res.is_err() {
                        tokio::time::sleep(PARK_RECHECK_INTERVAL).await;
                    }
                }
                () = tokio::time::sleep(due) => {}
            }

            // emit：各条需求按自己的闸门与订阅状态（topology 信号与 aggregate 载荷共用 `agg_emit`
            // 那一条闸门 —— 同一次拓扑变更 —— 但各看各的订阅门）。
            let now = mono_ms(clock);
            let detail_open = gate.topic_open(Topic::Detail);
            if detail_open != detail_was_open {
                // 新的 detail 订阅生命周期没有旧索引，必须从当前活动表 reset，而非半截增量开始。
                if !begin_detail_generation(&lifecycle, task_epoch, &mut detail_pending) {
                    return;
                }
                if detail_open {
                    detail_emit.note_change();
                }
                detail_was_open = detail_open;
            }
            // 排名聚合令牌的开合转换（与上面 detail 那一跳同构；两件事缺一条都留空窗，见函数文档）。
            // 边沿标志**每轮无条件取走**：留着会在下一轮门开时兑现一帧陈账。
            let agg_open = gate.topic_open(Topic::Connections);
            let Some(baseline_due) = lifecycle.consume_aggregate_baseline(task_epoch) else {
                return;
            };
            agg_was_open = apply_aggregate_demand_transition(
                agg_open,
                agg_was_open,
                baseline_due,
                &mut last_sig,
                &mut agg_emit,
            );
            if agg_emit.should_emit(now) {
                // 两条需求各自看自己的门（**不是同一条**：信号是一个 u64，载荷是一次 O(n log n) 聚合 +
                // 跨进程搬运）。该 topic 没订阅者时**照样 mark**：不消费掉这次待推标志的话，`wait_for`
                // 会恒返回 ZERO，select 的定时器分支退化成 0 延迟 → 忙转烧一个 tokio worker。
                if gate.topic_open(Topic::Topology) || agg_open {
                    let Some(()) = lifecycle.commit(task_epoch, || {
                        // 搜索态不能拿有损 Top-N 的签名当完整表变更信号：两条隐藏连接一进一出时，
                        // total 与 Top-N 都可能不变。单独发一个小信号，让前端仅在非空查询时重查完整表；
                        // 正常图仍由下方签名去重，不增加 Sankey 重渲。
                        broadcast(&app, EVENT_CONNECTIONS_TOPOLOGY_CHANGED, now_ms());
                        if agg_open {
                            let agg = active_connections
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .aggregate(now_ms());
                            // 签名去重（issue #227）：拓扑载荷是 host/出口计数，连接风暴下内容常不变。
                            // 闸门挡的是频率，去重挡的是「频率之内但内容没变」的那些帧，两者不重叠。
                            if let Some(sig) = signature_changed(&agg, &last_sig) {
                                broadcast(&app, EVENT_CONNECTIONS_AGGREGATE, agg);
                                last_sig = Some(sig);
                            }
                        }
                    }) else {
                        return;
                    };
                }
                agg_emit.mark_emitted(now);
            }
            if detail_emit.should_emit(now) {
                if gate.topic_open(Topic::Detail) {
                    if lifecycle
                        .commit(task_epoch, || {
                            let table = active_connections
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            if let Some(update) = detail_pending.take_update(&table, now_ms()) {
                                broadcast(&app, EVENT_CONNECTIONS_DETAIL, update);
                            }
                        })
                        .is_none()
                    {
                        return;
                    }
                } else {
                    // 下一位 detail 订阅者必须先拿完整基线，不能从无人消费期的半截增量开始。
                    if !begin_detail_generation(&lifecycle, task_epoch, &mut detail_pending) {
                        return;
                    }
                }
                detail_emit.mark_emitted(now);
            }
            if closed_emit.should_emit(now) {
                if gate.topic_open(Topic::Closed) {
                    if lifecycle
                        .commit(task_epoch, || {
                            if let Ok(history) = closed_history.lock() {
                                if let Some(update) = closed_pending.take_update(&history, now_ms())
                                {
                                    broadcast(&app, EVENT_CONNECTIONS_CLOSED, update);
                                }
                            }
                        })
                        .is_none()
                    {
                        return;
                    }
                } else {
                    // 无消费者时丢掉在途增量；未来订阅会立即收到一帧 reset 全量。
                    closed_pending.clear();
                }
                closed_emit.mark_emitted(now);
            }

            // 核停 / 换端口（换核、重启动态口）→ 断流重来。ReconnectingStream 自己发现不了这两件事。
            let st = proxy.status();
            if !st.running || st.clash_api_port != port {
                break;
            }
        }
        // 断流 / 隐藏 / 换核后的旧表不再是真值。立即清空，避免搜索命令在下一条 reset 到达前读到
        // 上一代连接；正常聚合签名仍由下一条流的 reset 重建。
        if lifecycle
            .commit(task_epoch, || {
                active_connections
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .reset();
            })
            .is_none()
        {
            return;
        }
        log::debug!("连接流已断开（待重订阅）");
    }
    log::debug!("连接流 relay 已退出");
}

/// 单调毫秒（emit 闸门的时基）。见 [`run_connections_stream`] 里 `clock` 的说明。
fn mono_ms(origin: Instant) -> u64 {
    origin.elapsed().as_millis() as u64
}

/// stats relay：一条 `SubscribeStatus` 长驻流 → [`StatsAggregator::on_status`] → emit
/// `EVENT_STATS_UPDATED`（StatusBar 的上下行速率 + 累计 + 连接数）。
///
/// # 相对 1s 轮询变了什么
///
/// | | 轮询（旧） | 长驻流（本函数） |
/// |---|---|---|
/// | 上游 | 每秒一次 `first_connection_snapshot`（活连接 + ≤1000 条死连接的全量 protobuf） | 一帧 9 个标量 |
/// | 累计口径 | 对**含死连接**的整表 `uplink_total` 求和 → 死连接被历史环淘汰时**下跌** | `Manager.Total()`，两个只增的 `atomic.Int64`，**结构上不回退** |
/// | 速率 | 上述会下跌的和做跨拍差分 → 连接高频起落时被 `saturating_sub` 系统性钳低 | 单调累计做差分 ÷ 实测 Δt |
/// | 活跃连接数 | 快照里 `closed_at <= 0` 的条数 | `Status.connectionsIn`（= `trafficManager.ConnectionsLen()`，同一口径） |
/// | 降流 | park 一拍（不拉取） | **drop 流**（见 [`StreamGate`]） |
///
/// 换流的判据是**口径**不是性能：旧法的累计会倒退（历史环满 1000 条后每淘汰一条就跌一截），
/// 那不是接线问题、修不掉。上游成本下降只是顺带。
///
/// # 生命周期（每一轮外循环 = 一条流的一生）
///
/// 1. [`StreamGate::wait_until`] 等门开（无 stats 订阅者 / 主窗不可见 → 断流待命，不碰 gRPC）。
/// 2. 核未运行 → 推一帧清零态让 StatusBar 如实归零（只在进入该态时推一次），等核回来。
/// 3. 建 h2c 客户端 + 订阅流；**聚合器复位** —— 速率基线在此刻必须作废（断流 / 停核 / 换核跨越的
///    时长不定，沿用旧基线会把整段空档的平均吞吐当成「此刻的速率」显示一帧）。
/// 4. 内循环消费帧，直到门关 / 核停 / 换端口 → 跳出，drop 流，回到 1。
///
/// 内循环那个 [`PARK_RECHECK_INTERVAL`] 兜底唤醒的理由与 [`run_connections_stream`] 逐字相同：
/// `ReconnectingStream` 断了自己重连、永不 yield 错误，故「核停了」「核换端口重启了」这两件事
/// 流本身不会告诉我们。
///
/// # 首帧不必等
///
/// 内核在建 ticker **之前**就无条件 `Send` 一帧当前状态（`daemon/started_service.go:396`），
/// 故订阅即出首帧 —— 轮询时代靠「首拍不睡」换来的那条语义，在流下是白送的。
/// 该帧的速率必然是 0（无基线），累计与连接数即刻真实。
pub(super) async fn run_stats_stream(
    app: AppHandle,
    proxy: Arc<ProxyRuntime>,
    config: Arc<ConfigManager>,
    stop: Arc<AtomicBool>,
    mut gate: StreamGate,
) {
    let visible = visibility_source(gate.state.clone(), app.clone());
    // 速率差分的时基必须是**单调**时钟：墙钟被 NTP 往回校一秒，Δt 就会算成负数（钳到下限后是个
    // 天文数字速率）；往前校则把速率算低。与 `run_connections_stream` 的 `clock` 同一理由。
    let clock = Instant::now();
    let mut meter = StatsAggregator::new();
    // 核未运行的清零帧是否已推过（边沿触发；同 `run_connections_stream` 的 offline_sent）。
    let mut offline_sent = false;

    while !stop.load(Ordering::Relaxed) {
        // ① 降流门：关着就在这里断流待命。
        gate.wait_until(true, &visible).await;

        // ② 核未运行 → 不碰 gRPC，推一帧清零态（只在进入该态时推一次；核停着重复推相同空帧
        //    只会让渲染端白重渲）。
        let status = proxy.status();
        if !status.running || status.clash_api_port == 0 {
            if !offline_sent {
                broadcast(&app, EVENT_STATS_UPDATED, offline_stats_frame());
                offline_sent = true;
            }
            meter.reset(); // 停核 = 旧基线作废（核回来是新的一条生命线，累计从 0 重来）
            tokio::time::sleep(PARK_RECHECK_INTERVAL).await;
            continue;
        }

        // ③ 建流。
        let port = status.clash_api_port;
        let secret = read_clash_secret(&config);
        let client = match SingBoxApiClient::connect(Endpoint::new("127.0.0.1", port), secret).await
        {
            Ok(c) => c,
            Err(e) => {
                log::debug!("Status 流：管理 API 连接失败 {e}");
                tokio::time::sleep(PARK_RECHECK_INTERVAL).await;
                continue;
            }
        };
        let mut stream =
            client.subscribe_status(STATS_STREAM_INTERVAL_NS, ReconnectConfig::default());
        // 新流 = 新的一份真相：速率基线在此刻作废。
        meter.reset();
        offline_sent = false;
        // 上一次见到的 `trafficAvailable`（`None` = 本条流还没见过帧 → 首帧必报一次）。
        // 随流而生、随流而灭：见 [`traffic_availability_changed`]。
        let mut traffic_available: Option<bool> = None;
        log::debug!("Status 流已订阅（port={port}）");

        // ④ 流循环。
        loop {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            tokio::select! {
                frame = stream.recv() => match frame {
                    Some(st) => {
                        // 显式判 `trafficAvailable`：核没有 trafficManager 时本流照推、字段安静全 0，
                        // 不喊出来就是「0 B/s 且零报错」，与真的没流量无从区分。
                        if traffic_availability_changed(traffic_available, st.traffic_available) {
                            traffic_available = Some(st.traffic_available);
                            if st.traffic_available {
                                log::debug!("Status 流：trafficAvailable=true（流量统计可用）");
                            } else {
                                log::warn!(
                                    "sing-box 报 trafficAvailable=false：核内未构造 trafficManager，\
                                     本流的累计/连接数字段将恒为 0 且**不会报任何错** —— \
                                     状态栏的速率、总流量、连接数三个数字全是假 0，别当成「没在传数据」"
                                );
                            }
                        }
                        meter.on_status(&daemon_status_to_engine(&st), mono_ms(clock));
                        // 门关的一瞬可能正好收到一帧（`wait_until(false, ..)` 那条腿还没被调度到）→
                        // emit 前再看一次订阅门，别把帧推给已经没人看的窗口。
                        if gate.topic_open(Topic::Stats) {
                            broadcast(&app, EVENT_STATS_UPDATED, meter.snapshot());
                        }
                    }
                    // ReconnectingStream 正常语义下不返 None；真返了说明它内部终止 → 重建。
                    None => break,
                },
                // 门关（退订 / 主窗隐藏）→ 跳出即 drop 流，整条链路成本归零。
                () = gate.wait_until(false, &visible) => break,
                // 兜底唤醒：复核核状态（流自己发现不了核停 / 换端口）。
                () = tokio::time::sleep(PARK_RECHECK_INTERVAL) => {}
            }

            // 核停 / 换端口（换核、重启动态口）→ 断流重来。ReconnectingStream 自己发现不了这两件事。
            let st = proxy.status();
            if !st.running || st.clash_api_port != port {
                break;
            }
        }
        log::debug!("Status 流已断开（待重订阅）");
    }
    log::debug!("stats relay 已退出");
}
