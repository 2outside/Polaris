//! 测速类 command（上游 `speed-test-handlers.ts`）。
//!
//! 映射 channel：
//! - `server:speedTest` → [`server_speed_test`]
//!
//! # 两条测速路径（按运行核是否已注入主核探测池分流）
//!
//! **① 主核 K 槽探针池分波测速（池就绪 → 「批量比较多节点延迟选优」核心路径）**：起核时
//! [`ProxyRuntime`] 分配 K 个空闲口注入 `probe_pool_ports`，config-engine
//! 据此在主核 config 建 K 个 `probe-in-k`（http 入站）+ `probe-selector-k`（成员=全量 nodeTags）+
//! `probe-in-k→probe-selector-k` 路由 + `dns-probe-exit-k`。测速时把请求的 N 个节点按 K 分波（见纯逻辑
//! [`plan_waves`]），每波经 gRPC `select_outbound`（[`ProxyRuntime::probe_select_slot`]）把各槽 `probe-selector-k`
//! 热切到本波节点，再经 `probe-in-k` 端口量 warm-TTFB（同核单会话，结构性消除 WG/WARP 双会话超时）。
//! 波间串行、波内并发。对齐 上游 `SpeedTestService.testServersViaMainCore`（§15）。
//!
//! **② 回退：仅当前活跃出口（池未注入时）**：探测池端口分配失败（极少见）→ `probe_pool_ports` 空 → 主核无池。
//! 此时只能经本机混合端口（`mixed-in`，CONNECT 隧道见 [`measure_via_local_proxy`]）测【当前选中出站】
//! ——主混合代理只经当前出口出网。
//! 其余请求节点无从测（需池），如实进 `notInPool`，绝不伪造数值（裁定纯逻辑见 [`plan_speed_test`]）。
//!
//! **③ 临时核（代理**关**时；对齐 上游 `testServersViaProxy`，`SpeedTestService.ts:388-620`）**：主核未运行 →
//! 起一个**瞬态** sing-box（每个可测节点一个 HTTP 入站 → 该节点出站），经各自端口量 warm-TTFB，测完即杀。
//! 「先测速比较延迟、再选最快的连上去」是常规使用序 —— 没有这条腿，用户必须先盲选一个节点连上才能测别的。
//! 编排/隔离/让位在 [`crate::runtime::speedtest`]（独立配置文件 + 独立端口 + 不写主核任何生命周期槽；
//! **主核一起来立刻让路**）；本层只做取材、装配与信封折叠，见 [`run_temp_core_speed_test`]。
//! 临时核结构性测不了 Tailscale 节点（建不出第二个 tsnet 实例 + 会与主核抢同一份 `tailscale-state`）→
//! 如实进 `tsNotReady`。真延迟数值走真核真出站 = **真机门**，本机零验证。
//!
//! # 「测不了」必须有出口信号（反伪造 + 反卡死）
//!
//! 前端 `NodesScreen` 设 `testing=true` 后靠 `event:speedTestProgress`（`tested>=total && total>0`）复位；成功信封 +
//! 零事件 ⇒ 测速按钮**永久 disabled 到组件重挂载**。故「零可测」一律走**失败信封**（`success:false` + 结构化 code）让
//! 前端 `ipc-client` throw、`NodesScreen` catch 复位 `testing`：
//! - 池路径请求节点全未入运行核池（新增未重启）→ [`CODE_NONE_IN_POOL`]；
//! - 回退路径无活跃出口 / 活跃出口不在请求集 → [`CODE_NO_ACTIVE_EXIT`] / [`CODE_PROBE_POOL_UNWIRED`]。
//!
//! 可测节点经真实进度事件复位；code 让 UI 把「本层测不了」与「测了但失败」分开呈现。
//!
//! # 诚实缺席（波前预筛：notInPool / tsNotReady）
//!
//! 「起测即知本核测不了」的节点**不 select / 不 measure / 不 report**，如实进缺席列表 —— 而不是硬测出一个
//! `-1` 假失败（或更糟：测出一个**属于别人的**真数值）。对齐 上游 `SpeedTestService.ts:674-700` 的波前
//! 预筛（**主核池路径同样筛**，非仅临时核腿）。裁定纯逻辑见 [`partition_pool`]，两条腿各守一类伪造：
//!
//! - **`notInPool`**（上游 `:680` `!probe.hasTag`）：不在运行核 `id_to_tag` 的节点（订阅新增/改址未重启
//!   入池）→ 其 tag 非 `probe-selector-k` 成员，热切必失败 → 旧行为记假 `-1`。UI 据此显「N 未纳入」。
//! - **`dirty`**（上游 `:688` `probe.isDirty`，判据 `ProxyManager.ts:3446-3450`）：节点**已编辑但未生效**
//!   —— 用户改了地址/端口/凭据/传输，运行核仍跑**起核那一刻**的旧参数。经其槽量到的是**旧参数出口**的
//!   latency，却挂在**新参数**的节点名下 ⇒ 失真数值（比缺席更有害：用户照着一个「已经不存在的配置」的
//!   延迟去选节点）。判据见 [`partition_dirty`]：`起核快照指纹存在 && 与当前指纹不等`。
//! - **`tsNotReady`**（上游 `:692` `!probe.tsNodeReady`）：协议为 `tailscale` 但 TS 尚未登录就绪的节点。
//!   此时运行核对该出口**已让位到直连**（`login_fallback`），经其槽量到的是**直连** RTT —— 记进该节点名下
//!   即失真数值；连不通则记假 `-1`。判据见 [`ts_node_ready`]。
//!
//! **回退腿（`probe_pool_ports` 为空）无 dirty 门 —— 已知残留**：该腿唯一真测的活跃出口若已编辑未生效，
//! 经混合口量到的同样是旧参数出口。补它需要「池未注入时也能读到运行核指纹快照」的公开只读面
//! （`speed_probe_targets()` 在 `pool_ports` 空时返 `None`），属 `runtime/proxy.rs` 的只读面扩张，不在本批
//! 射程。该腿本身是端口分配失败才走的降级路径（极少见），故按已知有界残留登记，不静默。

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// 测速计时用 [`tokio::time::Instant`] 而非 `std::time::Instant`。
///
/// 生产期二者**逐字等价**（`test-util` 关掉时 `tokio::time::Instant::now()` 就是 `std::time::Instant::now()`），
/// 差别只在测试期：`std` 的时钟不受 `#[tokio::test(start_paused = true)]` 的假时钟影响 ⇒ 用 `std` 时
/// 「measured 量的是第一次还是第二次 GET」这条不变式**在假时钟下测出来恒为 0ms、断言恒真**（= 没门）。
/// 换成 tokio 的 Instant 后 `measured_value_is_the_second_get_alone` 才真的有牙。
use tokio::time::Instant;

use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, State};

use polaris_config_engine::builder::level_to_string;
use polaris_config_engine::builder::outbounds::effective_proxy_bind_interface;
use polaris_config_engine::user_config::app_config::UserConfig;
use polaris_config_engine::user_config::proxy_ports::control_api_port;
use polaris_config_engine::user_config::server_config::ServerConfig;
use polaris_config_engine::user_config::LogLevel;
use polaris_core_supervisor::PortExclusions;
use polaris_net_stack::subscription::server_fingerprint;

use crate::events::channel::{EVENT_SPEED_TEST_PROGRESS, EVENT_SPEED_TEST_RESULT};
use crate::response::ApiResponse;
use crate::runtime::proxy::{ProxyRuntime, SpeedProbeTargets};
use crate::runtime::speedtest::{
    emit_speed_test_done, is_temp_core_superseded, plan_temp_core_with_bindings, InterruptReason,
    TempCoreDeps, TempCoreOutcome, TempCoreSession,
};
use crate::runtime::speedtest_tunnel::{open_tunnel, SpeedTestTarget, WarmTunnel};
use crate::runtime::tailscale_status::TailscaleStatusEvent;
use crate::runtime::AppRuntime;

/// Polaris 直连哨兵（`shared/direct-selection.ts DIRECT_SERVER_ID`；对齐 `commands/server.rs` 的本地定义）。
const DIRECT_SERVER_ID: &str = "__direct__";

/// Polaris 阻断哨兵（`domain/direct-selection.ts BLOCK_SERVER_ID`）。
const BLOCK_SERVER_ID: &str = "__block__";

/// 出口 id 是否「无真实出站」——空串（未选）/ 直连 / 阻断三者皆无节点可测。
///
/// 阻断尤其不能漏：它的 proxy-selector default 是 block 出站，伴测流量会被直接丢弃 ⇒ 测出的不是
/// 慢，而是超时，会把「用户主动阻断」记成节点故障、污染延迟表并触发误判换节点。
fn has_no_real_exit(active: &str) -> bool {
    active.is_empty() || active == DIRECT_SERVER_ID || active == BLOCK_SERVER_ID
}

/// 默认测速端点：www.gstatic.com generate_204（204 空响应，连接可立即复用）。
///
/// 不用 cp.cloudflare.com（上游 issue #154）：CF-Workers / 优选IP 节点对此 CF 自家端点测速会失败。
/// 目标域名由每个被测节点的出口远程解析（不经本机），故是否任播/有无国内镜像均与测速无关。
///
/// 原在 `crates/speedtest`（照 Electron 三路径形态 1:1 建的纯逻辑层）。该 crate 的其余抽象与 Tauri 侧
/// 实际形态不匹配（详见本文件 `resolve_speed_test_url` 上方说明），全 crate 仅本常量被消费 → crate 已删，
/// 常量就近落在唯一消费者这里。
const DEFAULT_SPEED_TEST_URL: &str = "http://www.gstatic.com/generate_204";

/// **第一阶段（冷建链）预算**：CONNECT + TLS 握手 + **第一次 GET**。
///
/// # 边界为什么划在 GET1 之**后**，而不是 CONNECT 回 200 之后
///
/// 内核对 CONNECT 是**先回 200、后拨号**：`sing/protocol/http/handshake.go:89` 先写
/// `200 Connection established`，`:104` **才** `NewConnectionEx(...)` 把这条连接交给路由拨号。
/// ⇒ **「收到 200」不蕴含「节点握手已完成」**，节点握手落在**第一次 GET** 的往返里。
/// 按字面把边界划在「CONNECT 200」会让节点握手掉进第二段那 4s 里 —— 反而**更容易误杀**慢握手的
/// 可用节点。故第一段必须一路包到 GET1 返回为止（详见 [`crate::runtime::speedtest_tunnel`] 模块文档）。
///
/// # 这不是回到「两个等长计时器」那个病（**改回单一计时器前先读完本节**）
///
/// 2026-07-31 上午修掉的是 warm 8s + measured 8s ——**两段等长**，故不可达节点的耗时整整翻倍
/// （8s → 16s），而不可达节点恰恰是整轮测速耗时的封顶项。本次分段与它有两条结构性差异：
///
///  1. **第二段远小于第一段**（4s vs 6s），不是等长复制；
///  2. **第一段超时 ⇒ 立即返回 `None`，绝不发第二次**（[`measure_warm_ttfb`] 用 `?` 早退，结构保证）。
///
/// 两条合起来 ⇒ **不可达节点的耗时恒为 6s**（与合并成一个 6s 计时器**逐字相同**），10s 只发生在
/// 「隧道已建起、GET1 已回、但复用请求卡住」这种罕见异常路径上。换言之：分段**没有**放大封顶项，
/// 只是把预算从「冷热共用一份」改成「冷的给足、热的给紧」。
///
/// 陈先生 2026-07-31 裁定：首次冷建链 6s、第二次复用请求 4s、首次超时即判超时不再浪费资源。
///
/// 代价与退路同前：真实冷建链耗时落在 6s 之外的节点判 -1（这类节点即便出值也不可用）；
/// 要放宽只改这两个常量，结构由 [`measure_warm_ttfb`] 的两段 timeout 保证，单测锁死。
///
/// ⚠️ **改这两个值必须同步前端的 `SPEEDTEST_IDLE_TIMEOUT_MS`**（`ui/src/lib/speedtest-progress-toast.ts`）
/// —— 它按 `2 ×（本值 + [`SPEED_TEST_REUSE_TIMEOUT_MS`]）` 推导。该文件的
/// `speedtest-progress-toast.test.ts` 里有一条门**直接读本文件的这两行**做算术校验，失配即转红。
const SPEED_TEST_COLD_TIMEOUT_MS: u64 = 6_000;

/// **第二阶段（复用请求）预算**：GET2 —— 也就是**上报的那个 measured 值**本身。
///
/// 隧道此刻已热（CONNECT + TLS + 节点握手都在第一段花完了），这一次纯粹是在一条已建立的 socket 上
/// 走一个往返 ⇒ 健康节点普遍几十~几百 ms，4s 已是数量级的余量。给得比第一段紧，正是为了让
/// 「隧道建起来了但复用请求卡住」这种异常尽早收口，而不是再赔一份冷建链的钱。
///
/// 边界判据与「为什么不是回到单一计时器」见 [`SPEED_TEST_COLD_TIMEOUT_MS`]。
const SPEED_TEST_REUSE_TIMEOUT_MS: u64 = 4_000;

/// 结构化错误码：无活跃出口（直连 / 未选节点）→ 主混合代理没有真实出站可测。
const CODE_NO_ACTIVE_EXIT: &str = "SPEEDTEST_NO_ACTIVE_EXIT";
/// 结构化错误码（**回退路径**）：探测池未注入（分配失败）且请求集不含活跃出口 → 本层零可测。
const CODE_PROBE_POOL_UNWIRED: &str = "SPEEDTEST_PROBE_POOL_UNWIRED";
/// 结构化错误码（**池路径**）：请求节点全未纳入运行核测速池（订阅新增/改址未重启入池）→ 本波零可测。
const CODE_NONE_IN_POOL: &str = "SPEEDTEST_NONE_IN_POOL";
/// 结构化错误码（**池路径**）：请求节点全部**已编辑未生效**（运行核仍跑旧参数）→ 本波零可测。
///
/// 与 [`CODE_NONE_IN_POOL`] 分开的理由同 [`CODE_TS_NOT_READY`]：用户的下一步不同 —— 未入池要「刷新订阅 /
/// 重启核纳入」，已编辑未生效要「应用更改」（Home 待应用操作条那一下）。合成一个码会把用户指向错误的修法。
/// 渲染端 `speedtest-feedback.ts` 对未知 code 走 `default` 分支直显本层文案，故新码零 UI 改动即可用。
const CODE_ALL_DIRTY: &str = "SPEEDTEST_ALL_DIRTY";
/// 结构化错误码：本波唯一可测的（或全部请求的）节点是 **TS 未登录就绪**的 tailscale 节点 → 零可测。
///
/// 与 [`CODE_NONE_IN_POOL`] 分开：两者对用户的下一步动作不同 —— 未入池要「重启内核」，TS 未就绪要
/// 「去把该节点登录上」。合成一个码会把用户指向错误的修法。
const CODE_TS_NOT_READY: &str = "SPEEDTEST_TS_NOT_READY";
/// 结构化错误码：已有测速在飞（单飞闸拒并发）。前端 catch 后复位自身 testing 灰态，视作 no-op。
const CODE_IN_FLIGHT: &str = "SPEEDTEST_IN_FLIGHT";
/// 结构化错误码：主核**正在启动**（`ProxyStatus::starting`）→ 临时核腿视作被占用，本轮不测。
///
/// 与 [`CODE_IN_FLIGHT`] 分开：那是「别人在测速」（等几秒重试即可），这是「核在起」（等连接完成后
/// 走主核测速池，路径都不同）。渲染端对未知 code 走 `default` 直显本层文案，故新码零 UI 改动即可用。
const CODE_CORE_STARTING: &str = "SPEEDTEST_CORE_STARTING";

/// 测速进程级单飞闸（审查 MED「前后端均无 busy/single-flight」的后端半）。
///
/// 托盘浮层与主窗（首页 / 节点页）是**独立 JS 堆**，各自的「测速中」灰态只锁本窗按钮，拦不住跨窗口
/// 并发（两窗同时点 = 两条 `server_speed_test` 并发跑主混合代理测量，互相污染 warm/measured 计时）。
/// 此处以进程级 flag 收口所有入口：只放行一条，其余立即返 [`CODE_IN_FLIGHT`]（不 emit 任何事件）。
/// 对齐 上游 主进程 `TrayManager.isSpeedTesting` + 单编排 `runSpeedTest` 的去重语义。
static SPEED_TEST_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

/// RAII 单飞守卫：`acquire` 抢占，`drop` 复位——覆盖 early return / `await` 取消 / panic 展开，
/// 绝不把 flag 永久卡死（那会让测速功能整段熄火直到重启）。
struct SpeedTestGuard;
impl SpeedTestGuard {
    /// 抢占单飞闸：闸空 → 占用返 `Some`；已被占 → 返 `None`（并发拒绝）。
    fn acquire() -> Option<Self> {
        SPEED_TEST_IN_FLIGHT
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
            .then_some(Self)
    }
}
impl Drop for SpeedTestGuard {
    fn drop(&mut self) {
        SPEED_TEST_IN_FLIGHT.store(false, Ordering::Release);
    }
}

/// 本波测速裁定（纯逻辑：请求集 × 当前活跃出口 × 本层可测范围 → 测谁 / 谁缺席 / 还是零可测）。
///
/// **抽成纯函数而非内联进 command**：command 要 `AppHandle`/`State`，本机无从构造 → 内联的判定
/// 只能靠肉眼复核。裁定是本次修复的核心（错一个分支就回到「静默返回 + 前端卡死」），故必须可单测。
#[derive(Debug, PartialEq, Eq)]
enum SpeedTestPlan {
    /// 无活跃出口（直连 / 未选节点）→ 本层零可测。
    NoActiveExit,
    /// 有活跃出口，但不在请求集内 → 请求的节点个个都要探针池，本层零可测。
    ActiveNotRequested { requested: usize },
    /// 可测当前活跃出口；`skipped` = 请求集里其余节点（需探针池，本波如实缺席）。
    Measure {
        active: String,
        skipped: Vec<String>,
    },
}

/// 裁定本波测速（[`SpeedTestPlan`]）。
///
/// - `active`：当前选中节点 id（空串 / [`DIRECT_SERVER_ID`] = 无真实出站）。
/// - `requested`：本次请求集；`None` = 全部（上游 `serverIds` 缺省语义）→ 取 `all`。
/// - `all`：当前配置里的全部节点 id（`requested=None` 时的实际请求集，也是 `skipped` 的取材面）。
fn plan_speed_test(active: &str, requested: Option<&[String]>, all: &[String]) -> SpeedTestPlan {
    if has_no_real_exit(active) {
        return SpeedTestPlan::NoActiveExit;
    }
    let requested: &[String] = requested.unwrap_or(all);
    if !requested.iter().any(|id| id == active) {
        return SpeedTestPlan::ActiveNotRequested {
            requested: requested.len(),
        };
    }
    // 活跃节点自身不进 skipped（它是本波唯一真测的那个）；其余请求节点如实缺席。
    let skipped = requested
        .iter()
        .filter(|id| id.as_str() != active)
        .cloned()
        .collect();
    SpeedTestPlan::Measure {
        active: active.to_string(),
        skipped,
    }
}

/// 从用户配置抽全部节点 id（`serverIds` 缺省时的实际请求集）。
fn all_server_ids(config: &Value) -> Vec<String> {
    config
        .get("servers")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s.get("id").and_then(Value::as_str))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

// ══════════════════════════════════════════════════════════════════════════════
//  §15 主核探测池分波编排（纯逻辑，可单测；真测量走真核=真机门，本层不碰宿主网络）。
// ══════════════════════════════════════════════════════════════════════════════

/// 探测池单槽指派：第 `slot` 槽（`probe-selector-{slot}` / `probe-in-{slot}` / `pool_ports[slot]`，三者 1:1）测哪个节点。
#[derive(Debug, Clone, PartialEq, Eq)]
struct SlotAssignment {
    /// 槽序 k（0..K）：既是 `probe-selector-k` 的序，也是 `pool_ports[slot]` 的下标（1:1 绑定）。
    slot: usize,
    /// 被测节点 id（结果回填键 + `event:speedTestResult` 的 serverId + 进度计数）。
    node_id: String,
    /// 被测节点在运行核的出站 tag（`select_outbound` 的 member_tag = `probe-selector-k` 成员）。
    tag: String,
}

/// 波前预筛分区结果（[`partition_pool`] 产出）。四个列表**互斥且各自保序**（前端徽标/进度按请求序流式回填）。
#[derive(Debug, Default, PartialEq, Eq)]
struct PoolPartition {
    /// 本波真测的节点 `(id, 出站 tag)`。
    testable: Vec<(String, String)>,
    /// 不在运行核池（`hasTag` 假）→ 诚实缺席。
    not_in_pool: Vec<String>,
    /// 在池但**已编辑未生效**（指纹 ≠ 起核快照）→ 诚实缺席。
    dirty: Vec<String>,
    /// 在池但 TS 未登录就绪 → 诚实缺席。
    ts_not_ready: Vec<String>,
}

/// 波前预筛的两个**注入集**（[`run_pool_speed_test`] 的入参束，避免 `too_many_arguments`）。
///
/// 两者都在命令层「await 之前」算好（`State` 不跨 await 持有），编排层只消费不重算 —— 重算就有了第二个
/// 真相源，而预筛的失效方式是静默的（筛错了照样出数值，只是数值属于别人）。
struct PoolPrefilter<'a> {
    /// 已编辑未生效的节点 id 集（见 [`partition_dirty`]）。
    dirty: &'a BTreeSet<String>,
    /// TS 未登录就绪的节点 id 集（见 [`partition_ts_not_ready`]）。
    ts_pending: &'a BTreeSet<String>,
    /// 每个不就绪 TS 节点的**具体成因**（键集 == `ts_pending`）。只喂零可测信封的文案，
    /// 不参与分区判定 —— 分区只问「就不就绪」，文案才需要问「为什么」。
    ts_reasons: &'a BTreeMap<String, TsNotReady>,
}

/// 请求集波前预筛分区（纯逻辑，对齐 上游 `SpeedTestService.ts:674-700` 的 `poolTestable` 循环）。
///
/// **三条腿的顺序与 上游 逐字一致**（`:680` hasTag → `:688` isDirty → `:692` tsNodeReady），因为它决定同一个
/// 节点被归到哪个缺席列表，而每个列表对用户是**不同的下一步动作**：
///  - 一个「TS 未就绪 **且** 未入池」的节点算 `notInPool`（下一步是重启内核纳入，而不是先去登录一个核里根本
///    没有的出口）；
///  - 一个「已编辑未生效 **且** TS 未就绪」的节点算 `dirty`（下一步是应用更改 —— 核重起后那份 TS 配置本身
///    就换了，此刻指引「去登录旧配置」是把人引向死路）。
///
/// - `id ∉ id_to_tag` → `not_in_pool`（订阅新增/改址未重启入池：其 tag 非 `probe-selector-k` 成员，
///   热切必失败 → 旧行为记假 `-1`）；
/// - `id ∈ dirty_pending`（指纹 ≠ 起核快照，见 [`partition_dirty`]）→ `dirty`（核仍跑旧参数，测它量到的是
///   **旧参数出口**的 RTT 却挂在新参数名下 = 失真数值）；
/// - `id ∈ ts_pending`（协议 tailscale 且未登录就绪，见 [`partition_ts_not_ready`]）→ `ts_not_ready`
///   （核已让位直连，测它量到的是直连 RTT = 失真数值）；
/// - 其余 → `testable`（带出站 tag）。
fn partition_pool(
    requested: &[String],
    id_to_tag: &BTreeMap<String, String>,
    dirty_pending: &BTreeSet<String>,
    ts_pending: &BTreeSet<String>,
) -> PoolPartition {
    let mut out = PoolPartition::default();
    for id in requested {
        let Some(tag) = id_to_tag.get(id) else {
            out.not_in_pool.push(id.clone());
            continue;
        };
        if dirty_pending.contains(id) {
            out.dirty.push(id.clone());
            continue;
        }
        if ts_pending.contains(id) {
            out.ts_not_ready.push(id.clone());
            continue;
        }
        out.testable.push((id.clone(), tag.clone()));
    }
    out
}

/// 用户配置里逐节点的**当前**指纹（dirty 判据的「新」一侧）。
///
/// 键 = 节点 id，值 = [`server_fingerprint`]（`protocol|address|port|cred|network`，与运行核起核时写进
/// [`SwitchSnapshot::fingerprints`](crate::runtime::proxy::SpeedProbeTargets::fingerprints) 的**同一个公式**
/// —— 两侧必须同源，各算各的公式必然漂移，而漂移的表现是「永远 dirty」或「永远不 dirty」，两种都静默）。
///
/// 解析不出 [`ServerConfig`] 的条目（配置损坏 / 未来字段）→ 直接跳过：**没有指纹 ⇒ 不判 dirty**，
/// 保守方向正确（照旧测，与本腿接线前逐字节一致），绝不因为解析失败就把一个正常节点筛掉。
pub(crate) fn current_server_fingerprints(config: &Value) -> BTreeMap<String, String> {
    config
        .get("servers")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|s| {
                    let id = s.get("id").and_then(Value::as_str)?;
                    let parsed: ServerConfig = serde_json::from_value(s.clone()).ok()?;
                    Some((id.to_string(), server_fingerprint(&parsed)))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// 请求集里「**已编辑未生效**」的节点 id（[`partition_pool`] 的 `dirty_pending` 入参）。
///
/// 判据 1:1 上游 `MainCoreProbe.isDirty`（`ProxyManager.ts:3446-3450`）：
/// `snapshot.get(id) !== undefined && snapshot.get(id) !== serverFingerprint(server)`。
///
/// 两条 `is_some_and` 缺一不可：
/// - **快照无此 id** ⇒ 不判 dirty。那是「新增未入核」，由 `hasTag`/`notInPool` 那条腿管（指引「重启纳入」）；
///   在此处误判成 dirty 会把用户指向「应用更改」——对一个核里根本没有的节点，应用更改确实也能纳入，但
///   与既有的 notInPool 语义打架、且 `partition_pool` 的腿序已保证它先被 notInPool 接走，此处再判即死码。
/// - **当前配置无此 id** ⇒ 不判 dirty（保守：拿不到「新」一侧就没有比对基准，照旧测）。真实可达形态是
///   「请求集点名了一个刚被删除的节点」，此时它多半也已不在 `id_to_tag` 里 → 走 notInPool。
///
/// **为什么当前指纹取自 `ConfigManager` 最新 config 而不是运行核的 `current_config`**：对齐 上游的
/// F-B 修正（`:3444` 注释）—— 「订阅 OFF 自动刷新」这类路径不经 `switch_mode`，运行核侧的 config 镜像会
/// 滞后 ⇒ 拿它当「新」一侧会**漏判 dirty**，于是照旧测出旧参数出口的失真值。
fn partition_dirty(
    requested: &[String],
    snapshot_fingerprints: &BTreeMap<String, String>,
    current_fingerprints: &BTreeMap<String, String>,
) -> BTreeSet<String> {
    requested
        .iter()
        .filter(|id| {
            let Some(snap) = snapshot_fingerprints.get(id.as_str()) else {
                return false;
            };
            current_fingerprints
                .get(id.as_str())
                .is_some_and(|cur| cur != snap)
        })
        .cloned()
        .collect()
}

/// **TS 节点「已登录就绪」判据**（纯逻辑，对齐 上游 `MainCoreProbe.tsNodeReady`，`ProxyManager.ts:3435-3442`）。
///
/// 就绪 ⟺ 有末帧 **且** `backendState == "Running"` **且** key 未过期。无帧（核未起 / 首帧未到 / 已清）
/// → **不就绪**（未知一律按不就绪：宁可缺席，绝不对一个可能已让位到直连的出口写数值）。
///
/// # 为什么不需要 上游的 `tailscaleStatusGen` 世代腿
///
/// 上游的 `tailscaleStatusCache` **跨停核保留**（`ProxyManager.ts:516-518` 注释：「connected 由
/// getStatus().running 实时判，故停代理不清缓存」）⇒ 核 restart 后新核首帧到达前，缓存里还躺着旧核的
/// `Running` 帧，必须靠 `tailscaleStatusGen === lifecycleGeneration`（M-4）挡住。
///
/// Polaris 的同一危险**在数据源侧就已封死**，故此处无同名腿（是结构性不需要，不是漏移植）：
///  - `stop_inner` 停核即 `mesh.clear_ts_status()`（`runtime/proxy.rs:2772`），而 `restart` 复用 `stop_inner`
///    ⇒ 重启后缓存空、`ts_status_event` 返 `None` → 本判据即返 false，与 M-4 的结论逐字相同；
///  - 崩溃腿同样清（`:2956`）；
///  - relay 写帧前后各查一次世代（`:3773`/`:3783`）⇒ 旧核末帧不会落进新核缓存。
///
/// 即：Polaris 里「缓存有帧」已蕴含「本代帧」，世代比对是恒真的空转。
fn ts_node_ready(ev: Option<&TailscaleStatusEvent>) -> bool {
    ev.is_some_and(TailscaleStatusEvent::exit_ready)
}

/// TS 节点「不就绪」的**具体成因**。`None` = 就绪。
///
/// # 为什么必须分开
///
/// 这四种的**用户下一步动作完全不同**，而此前它们共用一句「尚未登录就绪（登录后可测）」：
/// 真机实证（陈先生 2026-07-31）—— Tailscale 管理后台显示 `Connected`、应用里的组网卡也显示
/// 「已登录」，点测速却被告知「未登录」。他照着那句话去登录，登多少次都没用，因为那个节点
/// **本来就登着**。
///
/// 撕裂的来源是两条判据共用一个词：应用里「已登录」的角标是折叠值
/// （`backendState ∈ {Running, Starting}` 且未过期，见 `contracts/tailscale-status.ts`），
/// 而本门要求严格 `Running`。节点停在 `Starting` 时两者同时为真，用户看到的就是自相矛盾。
///
/// 所以这里不再折叠：**把成因如实说出来**，让用户知道该去登录、该等一会儿、还是该重启核。
#[derive(Debug, Clone, PartialEq, Eq)]
enum TsNotReady {
    /// 没有状态帧：核未起 / 起后首帧未到 / 停核已清。**不是「没登录」**。
    NoFrame,
    /// key 已过期 —— 登录过，但必须重新交互授权。
    Expired,
    /// 后端明确要求交互登录。**只有这一种是真的「未登录」**。
    NeedsLogin,
    /// 已登录，隧道还没通（`Starting` / `NoState` / `Stopped` …）。等它起来即可，登录是白做工。
    TunnelNotUp(String),
}

impl TsNotReady {
    /// 面向用户的一句话（含下一步动作）。
    fn user_phrase(&self) -> String {
        match self {
            Self::NoFrame => "尚未收到状态帧（核未就绪，稍后重试）".to_string(),
            Self::Expired => "登录密钥已过期，需重新授权".to_string(),
            Self::NeedsLogin => "尚未登录（登录后可测）".to_string(),
            Self::TunnelNotUp(state) => {
                format!(
                    "已登录但隧道尚未就绪（当前 {state}，等待它变为 Running 即可，无需重新登录）"
                )
            }
        }
    }
}

/// 判成因。顺序即优先级：无帧 > 过期 > 需登录 > 隧道未通。
///
/// `expired` 排在 `backend_state` 之前：key 过期时 `backendState` 完全可能仍报 `Running`
/// （与 `mesh::selected_exit_backend_state` 把 expired 折成 `NeedsLogin` 同一条理由），
/// 那种情形下说「隧道未就绪」会把用户指到错误的方向。
fn ts_not_ready_reason(ev: Option<&TailscaleStatusEvent>) -> Option<TsNotReady> {
    let Some(e) = ev else {
        return Some(TsNotReady::NoFrame);
    };
    if e.expired {
        return Some(TsNotReady::Expired);
    }
    if e.backend_state == "Running" {
        return None;
    }
    if e.backend_state == "NeedsLogin" {
        return Some(TsNotReady::NeedsLogin);
    }
    Some(TsNotReady::TunnelNotUp(e.backend_state.clone()))
}

/// 一组成因 → 报给用户的尾句。**逐类报数**，不折叠成一个总数：折叠回去就退回本次缺陷。
///
/// 空集 → 空串（调用方据此不拼尾巴）。
fn ts_not_ready_phrase(reasons: &[TsNotReady]) -> String {
    if reasons.is_empty() {
        return String::new();
    }
    let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for r in reasons {
        *counts.entry(r.user_phrase()).or_insert(0) += 1;
    }
    counts
        .iter()
        .map(|(phrase, n)| format!("{n} 个{phrase}"))
        .collect::<Vec<_>>()
        .join("；")
}

/// 用户配置里协议为 `tailscale` 的节点 id 集（波前预筛第二腿的取材面）。
///
/// 协议大小写不敏感（对齐 上游 `s.protocol?.toLowerCase() === 'tailscale'` 与本仓
/// `commands/server.rs:669-674` 的既有口径）。
fn tailscale_server_ids(config: &Value) -> BTreeSet<String> {
    config
        .get("servers")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter(|s| {
                    s.get("protocol")
                        .and_then(Value::as_str)
                        .is_some_and(|p| p.eq_ignore_ascii_case("tailscale"))
                })
                .filter_map(|s| s.get("id").and_then(Value::as_str))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// 请求集里「协议 tailscale **且** 未登录就绪」的节点 id（[`partition_pool`] 的 `ts_pending` 入参）。
///
/// `ready` 注入（生产传 `|id| ts_node_ready(mesh.ts_status_event(id).as_ref())`）⇒ 本函数纯、可离线单测，
/// 且**只对 tailscale 协议节点询问就绪**：非 TS 节点没有 TS 状态帧，问了必答「不就绪」，会把整批节点误筛光。
fn partition_ts_not_ready(
    requested: &[String],
    tailscale_ids: &BTreeSet<String>,
    ready: &dyn Fn(&str) -> bool,
) -> BTreeSet<String> {
    requested
        .iter()
        .filter(|id| tailscale_ids.contains(*id))
        .filter(|id| !ready(id.as_str()))
        .cloned()
        .collect()
}

/// 波前预筛后**零可测**时的失败信封裁定（纯逻辑：`(文案, code)`）。
///
/// 零可测必须走**失败信封**而非 `ok(空)`：前端 `NodesScreen` 靠进度事件复位 `testing` 灰态，零事件 +
/// 成功信封 ⇒ 测速按钮永久 disabled（见模块文档「反伪造 + 反卡死」）。
///
/// code 按**用户的下一步动作**分流，不按内部实现分：未入池 → [`CODE_NONE_IN_POOL`]（去重启内核）；
/// 已编辑未生效 → [`CODE_ALL_DIRTY`]（去点「立即应用」）；TS 未就绪 → [`CODE_TS_NOT_READY`]（去登录那些
/// 节点）。多类并存时主码按 `notInPool > dirty > tsNotReady` 取，但文案**每一类非零的数都报** —— 只报一
/// 半会让用户按错误的修法折腾。
///
/// **为什么 dirty 排在 tsNotReady 之前**：前者是一次批量动作（应用更改，一下带回全部），后者是逐节点的
/// 手工登录。且「应用更改」会重起核 —— 那批 TS 节点的配置本身也会换，此刻先指引去登录旧配置是白做工。
fn zero_testable_envelope(
    not_in_pool: usize,
    dirty: usize,
    ts_reasons: &[TsNotReady],
) -> (String, &'static str) {
    let ts_not_ready = ts_reasons.len();
    let ts_detail = ts_not_ready_phrase(ts_reasons);
    let ts_tail = if ts_not_ready > 0 {
        format!("；另有 {ts_not_ready} 个 Tailscale 节点不可测（{ts_detail}）")
    } else {
        String::new()
    };
    let dirty_tail = if dirty > 0 {
        format!("；另有 {dirty} 个节点已编辑未生效")
    } else {
        String::new()
    };
    if not_in_pool > 0 {
        return (
            format!(
                "请求的 {not_in_pool} 个节点均未纳入运行核测速池（刷新订阅或重启核后纳入）{dirty_tail}{ts_tail}"
            ),
            CODE_NONE_IN_POOL,
        );
    }
    if dirty > 0 {
        return (
            format!(
                "请求的 {dirty} 个节点已编辑但尚未生效，运行核仍跑旧参数（应用更改后可测）{ts_tail}"
            ),
            CODE_ALL_DIRTY,
        );
    }
    if ts_not_ready > 0 {
        return (
            format!("请求的 {ts_not_ready} 个 Tailscale 节点不可测：{ts_detail}"),
            CODE_TS_NOT_READY,
        );
    }
    // 退化态（请求集为空）：仍走失败信封（零进度事件 + 成功信封会把前端测速按钮永久卡灰）。
    (
        "请求的 0 个节点均未纳入运行核测速池（刷新订阅或重启核后纳入）".to_string(),
        CODE_NONE_IN_POOL,
    )
}

/// 在池节点按 K 槽分波（纯逻辑，对齐 上游 `testServersViaMainCore` 的 `for base += K`）。
///
/// N 个在池节点 → ⌈N/K⌉ 波，每波至多 K 个 `(slot, node, tag)`；槽 `slot` = **波内位次**（跨波复用同一批槽，
/// 波间串行 → 同槽先测完再重指，`probe-selector-k` 的 `interrupt_exist_connections` 断残留防跨节点串味）。
/// `K==0`（探测池关闭的回滚锚点）→ 空 vec（调用方走回退活跃出口）。
fn plan_waves(pool_testable: &[(String, String)], k: usize) -> Vec<Vec<SlotAssignment>> {
    if k == 0 {
        return Vec::new();
    }
    pool_testable
        .chunks(k)
        .map(|wave| {
            wave.iter()
                .enumerate()
                .map(|(slot, (id, tag))| SlotAssignment {
                    slot,
                    node_id: id.clone(),
                    tag: tag.clone(),
                })
                .collect()
        })
        .collect()
}

/// 结构化错误码（**临时核路径**）：请求节点没有一个能进临时核（全 tailscale / 全构造失败）→ 零可测。
const CODE_TEMP_CORE_NONE_TESTABLE: &str = "SPEEDTEST_TEMP_CORE_NONE_TESTABLE";
/// 结构化错误码（**临时核路径**）：临时核起不来 / 未就绪 / 端口分配失败 → 本轮整批不可测。
///
/// 与 [`CODE_TEMP_CORE_NONE_TESTABLE`] 分开：前者是「这些节点本层测不了」（换节点可测），后者是
/// 「本机此刻起不了测速核」（跟节点无关）。合成一个码会把用户指向错误的排查方向。
const CODE_TEMP_CORE_FAILED: &str = "SPEEDTEST_TEMP_CORE_FAILED";
/// 结构化错误码（**临时核路径**）：本批规模越过单核上限 → **起核前**拒绝
/// （[`TempCoreOutcome::Oversized`]）。
///
/// 与 [`CODE_TEMP_CORE_FAILED`] 分开是本码存在的**全部理由**：前端把后者无条件映射成
/// `nodes.speedTestInterrupted`（zh-CN「测速中断」），与「核起不来 / 未就绪超时」逐字相同 ⇒
/// 用户会朝网络/端口方向排查，而真因是本轮 naive 节点太多、少选一些当场就能测。
/// 用户可见的分流由 `ui/src/components/screens/shared/speedtest-feedback.ts` 的同名 case 承接。
const CODE_TEMP_CORE_OVERSIZED: &str = "SPEEDTEST_TEMP_CORE_OVERSIZED";

/// 临时核零可测的用户文案（纯逻辑，可单测）。
///
/// `has_tailscale` 为假时**不得**附「Tailscale 节点须先连接主核后测」：请求集里一个 TS 节点都没有
/// （零可测的原因是构造失败 / naive 缺 cronet / 节点已删）却这么说，会把用户支去查一个他根本没有的
/// 问题，而真正的原因一个字都没提。
fn temp_core_none_testable_message(
    requested: usize,
    unusable: usize,
    has_tailscale: bool,
) -> String {
    let ts_hint = if has_tailscale {
        "Tailscale 节点须先连接主核后测；"
    } else {
        ""
    };
    format!(
        "本次请求的 {requested} 个节点没有一个能经临时测速核测量（{ts_hint}另有 {unusable} 个节点不可用）"
    )
}

/// 临时核日志级别：**与主核同一求值**（用户档 + 隐私模式地板 `warn`）。
///
/// # 为什么不再把非诊断档一律压成 `warn`
///
/// 旧实现只放行 `debug|trace`，其余压 `warn`，注释理由是「免得每次测速往 app.log 灌一堆核的 info」。
/// 这条理由站不住：主核以 `info` 常驻一整天的行数远超一次测速那点量；而代价是**同一个配置字段两种
/// 解释**——用户设 `info`，主核就是 `info`，临时核却偷偷降到 `warn`。恰恰 `info` 那几类行
/// （`inbound connection from` / `outbound connection to` / `NaiveProxy started`）才是判「核停在哪
/// 一步」的材料，2026-08-02 那次「全是 -1」就因为磁盘上零核侧证据而无从复盘。
///
/// 求值复用 [`LogLevel::effective`]（`config-engine/src/user_config/log_level.rs`），主核经
/// `build_log_config` 走的也是它；字符串形态复用 [`level_to_string`]，两处同一张映射表。
///
/// # 两处与主核不同的地方（都是如实处理，不是分叉）
///
/// - **`trace` 不在 `LogLevel` 枚举里**（那是 sing-box 侧七档词汇才有的档，本仓 `LogLevel` 只有五档），
///   走 `serde` 会解析失败退成默认 `info` ⇒ 用户拨到 trace 反而降档，正是要避免的那件事。故单独放行，
///   并按它比 `debug` 更低这一事实同样受隐私地板约束（隐私模式下压回 `warn`）。
/// - 非法/缺省值经 `LogLevel` 的 `#[default]` 落到 `info`，与主核 `log_axes_from_config` 逐字同义。
///
/// **硬次序**：本函数抬级的前提是临时核的 stdout/stderr 已经有人排空（`runtime::speedtest`
/// 的 `drive_after_spawn`）。未排空时抬级 = 提前把 64 KiB 管道写满、把核堵死 —— 2026-09-02 受控实验
/// 实测 `debug`/`trace` 在未排空时是**确定性断崖**（4/4 轮复现）。两者必须同批，且排空先生效。
fn temp_core_log_level(config: &Value, privacy_mode: bool) -> String {
    let raw = config.get("logLevel").and_then(Value::as_str);
    if raw == Some("trace") {
        return if privacy_mode { "warn" } else { "trace" }.to_string();
    }
    let level: LogLevel = raw
        .and_then(|s| serde_json::from_value(Value::from(s)).ok())
        .unwrap_or_default();
    level_to_string(level.effective(privacy_mode))
}

/// 临时核运行策略的取材：把 config 解析成 [`UserConfig`]，**解析失败也必须保住端口与网卡策略**。
///
/// `from_value::<UserConfig>` 对**任何一个无关字段**的形态错误都整体失败（如 `servers` 不是数组、
/// 某个节点缺必填键）。旧写法 `.unwrap_or_default()` 在那条腿上静默把排除集退化成「默认 control +
/// http/mixed = 0」—— 恰好丢掉这段代码存在的唯一理由：临时核于是可能占住主核随后要 bind 的口，
/// 用户表现为「测完速就连不上」，而日志里一个字都没有。
///
/// 故 Err 腿：① 记 warn（这条 warn 是排查该形态的唯一线索）；② **直接从 `Value` 单独反序列化**
/// 端口、订阅策略和全局网卡策略。`controlPort` 不读：`UserConfig` 的 `PortConfig::control_port()` 恒 `None`
/// （`config-engine/src/builder/inbounds.rs`），排除的永远是默认 9090，与解析成败无关。
fn user_config_for_temp_core(config: &Value) -> UserConfig {
    match serde_json::from_value::<UserConfig>(config.clone()) {
        Ok(c) => c,
        Err(e) => {
            let port = |key: &str| {
                config
                    .get(key)
                    .and_then(Value::as_u64)
                    .and_then(|p| u16::try_from(p).ok())
            };
            let (mixed_port, http_port) = (port("mixedPort"), port("httpPort"));
            let mut fallback = UserConfig {
                mixed_port,
                http_port,
                ..Default::default()
            };
            fallback.subscriptions = config
                .get("subscriptions")
                .cloned()
                .and_then(|value| serde_json::from_value(value).ok())
                .unwrap_or_default();
            fallback.network_interfaces = config
                .get("networkInterfaces")
                .cloned()
                .and_then(|value| serde_json::from_value(value).ok());
            log::warn!(
                "测速临时核用户配置解析失败（已从原始 JSON 单独保留端口和网卡策略，mixed={mixed_port:?} http={http_port:?}）: {e}"
            );
            fallback
        }
    }
}

/// 从用户配置里按**请求序**取出 typed 节点（临时核出站构造的取材面）。
///
/// 保序是硬要求：临时核的「节点 ↔ 入站端口 ↔ 出站 tag」是三重逐位绑定，取材乱序 ⇒ 量到的是别人的延迟。
/// 解析不出 [`ServerConfig`] 的条目直接跳过（由调用方计入缺席，不伪造数值）。
fn requested_server_configs(config: &Value, requested: &[String]) -> Vec<ServerConfig> {
    let by_id: BTreeMap<&str, &Value> = config
        .get("servers")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s.get("id").and_then(Value::as_str).map(|id| (id, s)))
                .collect()
        })
        .unwrap_or_default();
    requested
        .iter()
        .filter_map(|id| by_id.get(id.as_str()))
        .filter_map(|v| serde_json::from_value::<ServerConfig>((*v).clone()).ok())
        .collect()
}

/// **临时核测速腿**（主核未运行；对齐 上游 `SpeedTestService.testServersViaProxy`，`:388-620`）。
///
/// 编排：请求集 → typed 节点（保序）→ [`plan_temp_core_with_bindings`] 裁掉临时核结构性测不了的（tailscale / naive 缺
/// cronet / 构造失败）→ [`TempCoreSession::run`] 起核 + 就绪门 + 分批并发量 warm-TTFB + **无条件收尾** →
/// 折成响应信封。
///
/// # 让位基准必须在 await 之前捕获
///
/// `gen0` 与 `superseded` 闭包都在 `TempCoreSession::run` 的 `.await` **之前**建好。捕获在之后 = 跟自己比，
/// 判据恒假 ⇒ 用户中途点「连接」时临时核不让路，两个核并存跑同一批 WG/WARP peer（双会话事故）。
///
/// # 零可测 / 起核失败一律走**失败信封**
///
/// 与池路径同一条纪律：前端 `NodesScreen` 靠进度事件复位 `testing` 灰态，零事件 + 成功信封 ⇒ 测速按钮
/// 永久 disabled 到组件重挂载。
async fn run_temp_core_speed_test(
    app: &AppHandle,
    state: &State<'_, AppRuntime>,
    config: &Value,
    server_ids: Option<Vec<String>>,
) -> ApiResponse<Value> {
    let url = resolve_speed_test_url(config);
    let all = all_server_ids(config);
    let requested: Vec<String> = server_ids.unwrap_or(all);
    let servers = requested_server_configs(config, &requested);
    // 请求了但配置里查无此节点（前端状态陈旧 / 刚被删）→ 如实缺席，不伪造。
    let missing: Vec<String> = {
        let present: BTreeSet<&str> = servers.iter().map(|s| s.id.as_str()).collect();
        requested
            .iter()
            .filter(|id| !present.contains(id.as_str()))
            .cloned()
            .collect()
    };

    let proxy = state.proxy.clone();
    let user_config = user_config_for_temp_core(config);
    let bind_interfaces: BTreeMap<String, String> = servers
        .iter()
        .filter_map(|server| {
            effective_proxy_bind_interface(server, &user_config)
                .map(|interface| (server.id.clone(), interface))
        })
        .collect();
    let plan = plan_temp_core_with_bindings(&servers, &proxy.core_build_env(), &bind_interfaces);
    if plan.testable.is_empty() {
        return ApiResponse::err_with_code(
            temp_core_none_testable_message(
                requested.len(),
                plan.unusable.len() + missing.len(),
                !plan.tailscale.is_empty(),
            ),
            CODE_TEMP_CORE_NONE_TESTABLE,
        );
    }

    // §15.11 让位（超代）基准：**必须在 await 之前捕获**（判据见函数文档）。
    let gen0 = proxy.core_generation();
    let superseded = || {
        let st = proxy.status();
        is_temp_core_superseded(proxy.core_generation(), gen0, st.running, st.starting)
    };

    // 端口排除集：用户配置的 control/http/mixed 口 —— 临时核占了它们，主核随后就起不来
    // （表现为「测完速就连不上」，归因极难）。
    let exclusions = PortExclusions::for_primary_api(
        Some(control_api_port(&user_config)),
        user_config.http_port,
        None,
        user_config.mixed_port,
    );
    // 隐私模式读**单一真值**（`commands::config` 的进程状态机），不另存镜像 —— 与主核经
    // `ProxyErrorEmitter::privacy_mode` 取的是同一个值（`runtime/proxy.rs:792-801`）。
    let privacy_mode = crate::commands::config::config_get_privacy_mode(State::clone(state))
        .data
        .unwrap_or(false);
    let deps = TempCoreDeps::production(
        state.config().dir().to_path_buf(),
        exclusions,
        temp_core_log_level(config, privacy_mode),
    );

    let outcome = TempCoreSession::run(
        &deps,
        &plan.testable,
        &superseded,
        |port| {
            let url = url.clone();
            async move { measure_via_local_proxy(port, &url).await }
        },
        &mut |event, payload| {
            let _ = app.emit(event, payload);
        },
    )
    .await;

    // 临时核结构性测不了的节点（tailscale）如实进 `tsNotReady` —— 与主核路径同一个键，对用户是同一件事
    // 「本轮没测」，且指引一致（先连主核 / 先登录）。对齐 上游 L-2（`:248-250`）把漂移剔除的 TS-exit
    // 计入 skipped 的处置。
    // `notInPool` 只回 id：成因（[`UnusableReason`]）是排查材料，已按原因汇总进日志，跨语言契约不动。
    let mut not_in_pool: Vec<String> = plan.unusable.into_iter().map(|(id, _)| id).collect();
    not_in_pool.extend(missing);
    match outcome {
        TempCoreOutcome::Ran { results, outcome } => ApiResponse::ok(json!({
            "results": results,
            "outcome": outcome,
            "notInPool": not_in_pool,
            "tsNotReady": plan.tailscale,
            "dirty": Vec::<String>::new(),
        })),
        // 起核前就被主核接管 → 一个节点都没测。**失败信封**：零进度事件 + 成功信封会把前端测速按钮
        // 永久卡灰（同池路径「反伪造 + 反卡死」那一节）。
        TempCoreOutcome::Superseded => ApiResponse::err_with_code(
            "测速已让位给正在启动的代理内核（主核起来后可经主核测速池重测）",
            CODE_TEMP_CORE_FAILED,
        ),
        TempCoreOutcome::Failed(e) => ApiResponse::err_with_code(e, CODE_TEMP_CORE_FAILED),
        // 规模超限**必须**是独立的码：并进 `CODE_TEMP_CORE_FAILED` 就等于告诉用户「测速中断」，
        // 与就绪超时逐字相同，而两者的修法南辕北辙（一个是少选 naive 节点，一个是查网络/端口）。
        TempCoreOutcome::Oversized(e) => ApiResponse::err_with_code(e, CODE_TEMP_CORE_OVERSIZED),
    }
}

/// 上游 `SERVER_SPEED_TEST`：测速（serverIds 缺省=全部；逐节点结果/进度经 event:speedTestResult 推送）。
///
/// 主核在跑 → 池路径 / 回退活跃出口；主核未跑 → **临时核腿**（见 [`run_temp_core_speed_test`]）。
/// 可测范围与三条波前预筛见模块文档。绝不回假延迟。
#[tauri::command]
pub async fn server_speed_test(
    app: AppHandle,
    state: State<'_, AppRuntime>,
    server_ids: Option<Vec<String>>,
) -> Result<ApiResponse<Value>, ()> {
    let status = state.proxy().status();
    // 核在跑却没有混合端口（分配失败的半态）→ 本层确实无从测：临时核腿在此形态下会被让位判据
    // （`running == true`）当场掐掉，硬走只会空转一轮。如实 clean error，绝不回假延迟。
    // **文案不得说「核未运行」**：核正跑着，缺的是混合端口。说反了会把用户支去点「连接」（他已经连着），
    // 排查方向整个偏掉。
    if status.running && status.mixed_port == 0 {
        return Ok(ApiResponse::err(
            "代理核在运行但混合端口缺失（端口分配失败），本层无从测速：重启内核后重试",
        ));
    }
    // 主核**正在启动**（`start` 已置在飞标记、核尚未就绪）→ 临时核腿视作「已被占用」，clean error。
    //
    // 为什么必须在入口挡：`start` 的顺序是 `start_inflight+1` →（可达数秒的）stale 清扫 →
    // `bump_generation` → spawn → 就绪门。这整段里 `running == false` 且世代可能已 bump 完
    // （⇒ 本次测速取的 `gen0` 就是新世代），让位判据的世代腿与 running 腿**同时**盖不住。用户点
    // 「连接」后紧接点测速（或托盘/另一窗口点——UI 灰态拦不住跨窗）就是确定性命中：起临时核 ⇒ 与
    // 启动中的主核同 peer 双会话踢线，且临时核可能抢走主核刚解析、尚未 bind 的 api/probe 池口 ⇒
    // 主核 FATAL address-in-use。入口这道是快路径；真正扛竞态的是让位判据的第三条腿（`st.starting`）。
    if status.starting && !status.running {
        return Ok(ApiResponse::err_with_code(
            "代理内核正在启动，请等待连接完成后再测速",
            CODE_CORE_STARTING,
        ));
    }

    // 单飞闸：并发测速（跨窗口连点）只放行一条，其余立即返 CODE_IN_FLIGHT（不 emit 事件，前端 catch
    // 复位自身灰态）。`_guard` 持有至函数返回（含下面的 await 测量）→ 释放后方可再测。
    // **必须在临时核腿之前抢**：临时核会起真进程 + 占 N 个回环端口，两条并发跑等于同时起两个临时核。
    let Some(_guard) = SpeedTestGuard::acquire() else {
        return Ok(ApiResponse::err_with_code(
            "已有测速进行中，请等待当前测速完成",
            CODE_IN_FLIGHT,
        ));
    };

    // 当前活跃节点 + 测速 URL（同步读；取值后不再借 state，避免跨 await 持有）。
    let config = state.config().current().unwrap_or_default();

    // ── 临时核腿（主核**未运行**）：起一个瞬态 sing-box 逐节点量 warm-TTFB，测完即杀 ──
    // 「先测速比较延迟、再选最快的连上去」是常规使用序；没有这条腿，用户必须先盲选一个节点连上才能测别的。
    // 隔离/让位/收尾语义全在 `runtime::speedtest` 的模块文档（独立配置文件 + 独立端口 + 不写主核生命周期槽；
    // 主核一起来立刻让路）。
    if !status.running {
        return Ok(run_temp_core_speed_test(&app, &state, &config, server_ids).await);
    }
    let active = config
        .get("selectedServerId")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let url = resolve_speed_test_url(&config);
    let mixed = status.mixed_port;
    let all = all_server_ids(&config);
    let tailscale_ids = tailscale_server_ids(&config);
    let current_fingerprints = current_server_fingerprints(&config);
    // owned Arc：跨 await（分波热切/测量）持有，不借 State。
    let proxy = state.proxy.clone();

    // §15 主核探测池分波测速（池就绪 → 「批量比较多节点延迟选优」核心路径）：把请求的 N 个节点按 K 分波，
    // 逐波经 gRPC select_outbound 热切各槽到本波节点、经 probe-in-k 端口量 warm-TTFB。详见模块文档路径①。
    if let Some(targets) = proxy.speed_probe_targets() {
        let requested: Vec<String> = server_ids.clone().unwrap_or_else(|| all.clone());
        // 波前预筛第三腿（dirty）的入参：起核快照指纹 vs **ConfigManager 最新** config 的当前指纹。
        // 当前侧取自 `config`（本函数开头刚读的最新配置），不取运行核的 config 镜像 —— 后者在「订阅 OFF
        // 自动刷新」这类不经 switch_mode 的路径上会滞后 ⇒ 漏判 dirty（对齐 上游 F-B 修正）。
        let dirty_pending =
            partition_dirty(&requested, &targets.fingerprints, &current_fingerprints);
        // 波前预筛第二腿的入参：**取值在 await 之前**（`State` 不跨 await 持有）。TS 状态活态读 mesh 末帧
        // 缓存（`ts_status_event`），判据见 [`ts_node_ready`]。
        let ts_pending = partition_ts_not_ready(&requested, &tailscale_ids, &|id| {
            ts_node_ready(state.mesh().ts_status_event(id).as_ref())
        });
        // 成因与上面的就绪判定**同一次读**同一份缓存：分开读两次会在两次之间收到新帧，
        // 出现「判了不就绪、却取不到成因」或反过来的撕裂。
        let ts_reasons: BTreeMap<String, TsNotReady> = ts_pending
            .iter()
            .filter_map(|id| {
                ts_not_ready_reason(state.mesh().ts_status_event(id).as_ref())
                    .map(|r| (id.clone(), r))
            })
            .collect();
        let prefilter = PoolPrefilter {
            dirty: &dirty_pending,
            ts_pending: &ts_pending,
            ts_reasons: &ts_reasons,
        };
        return Ok(run_pool_speed_test(&app, &proxy, &targets, &requested, &url, &prefilter).await);
    }

    // ── 回退：探测池未注入（端口分配失败/回滚）→ 仅当前活跃出口经 mixed 口可测 ──
    // 零可测的两条腿一律走**失败信封**（非 ok(empty)）：前端据此 throw → catch 复位 testing，
    // 且 code 让 UI 分得清「本层测不了」与「测了但失败」。详见模块文档「反伪造 + 反卡死」。
    let (active, skipped) = match plan_speed_test(&active, server_ids.as_deref(), &all) {
        SpeedTestPlan::NoActiveExit => {
            return Ok(ApiResponse::err_with_code(
                "当前出口为直连 / 未选节点，主混合代理无真实出站可测",
                CODE_NO_ACTIVE_EXIT,
            ));
        }
        SpeedTestPlan::ActiveNotRequested { requested } => {
            return Ok(ApiResponse::err_with_code(
                format!(
                    "测速探测池未就绪（端口分配失败已回退）；本层仅能测当前活跃出口，而它不在本次请求的 {requested} 个节点内"
                ),
                CODE_PROBE_POOL_UNWIRED,
            ));
        }
        SpeedTestPlan::Measure { active, skipped } => (active, skipped),
    };

    // 波前预筛（回退腿版）：本腿唯一真测的就是活跃出口，故只需筛它一个。它若是**未登录就绪的 TS 节点**，
    // 运行核已把默认路由让位到直连（`login_fallback`）⇒ 经混合口量到的是**直连** RTT，记进该节点名下就是
    // 失真数值（比记 -1 更有害：用户会照着一个假的低延迟去选这个连不通的节点）。诚实缺席 → 失败信封。
    // 其余请求节点的缺席原因是「本层无池」而非「TS 未就绪」，故仍如实归 notInPool，不在此处改判。
    if tailscale_ids.contains(&active)
        && !ts_node_ready(state.mesh().ts_status_event(&active).as_ref())
    {
        return Ok(ApiResponse::err_with_code(
            "当前出口是尚未登录就绪的 Tailscale 节点（核已让位直连），测它量到的是直连而非该出口",
            CODE_TS_NOT_READY,
        ));
    }

    // §15.11 让位（超代）基准：**回退腿同样须守**（此前本腿零 `superseded()` 覆盖，见
    // [`drive_fallback_measure`] 文档）。`gen0` 必须在 await **之前**捕获，判据与池路径共用 [`is_superseded`]。
    let gen0 = proxy.core_generation();
    let superseded = || is_superseded(proxy.core_generation(), gen0, proxy.status().running);

    let (results, outcome) = drive_fallback_measure(
        &active,
        &superseded,
        || measure_via_local_proxy(mixed, &url),
        &mut |event, payload| {
            let _ = app.emit(event, payload);
        },
    )
    .await;

    Ok(ApiResponse::ok(json!({
        "results": results,
        // completed：本次入参已全部裁定（测的测了、缺席的进 notInPool）；interrupted：被核跃迁/崩溃打断，
        // 该节点**缺席**（前端据此保留旧值，见 contracts/speed-test.ts SpeedTestOutcome）。
        "outcome": outcome,
        // 请求了但本层测不了的节点（需探针池）→ 如实回报，UI 据此显「N 未纳入」而非假装测过。
        "notInPool": skipped,
        // 本腿走到这里 ⇒ 活跃出口已通过 TS 就绪预筛（未就绪已在上面早退），其余节点的缺席原因一律是
        // 「本层无池」（已进 notInPool）⇒ 本腿的 tsNotReady 恒空是**如实**，不是未接线。
        "tsNotReady": [],
    })))
}

/// **回退腿的测量 + 让位收口**（测量 / 事件发射两个 I/O 面**全部注入** ⇒ 无 `AppHandle`、不碰宿主网络、可单测）。
///
/// # 为什么这条腿也必须守让位
///
/// 池路径的让位三检查点（[`drive_pool_waves`]）此前**没有对应物在回退腿上**：`probe_pool_ports` 为空的
/// 回退腿既无 gen0 捕获、`measure_via_local_proxy` 前后也无检查，`outcome` 硬编码 `"completed"`。后果是
/// 测量中途核重启/崩溃会把一个 `-1`（或经**新**出口测得的值）记在**旧** `selectedServerId` 上 —— 正是
/// 模块文档「绝不伪造数值」承诺要消灭的那类伪造，只是发生在更少见的路径上（端口分配失败才走回退）。
///
/// # 语义与池路径逐字一致
///
/// 被取代 → 该节点**缺席**（不写 `results`、不推 `result`/`progress` 事件）+ `outcome="interrupted"`，
/// 而不是记 `-1`。「超代未测」与「真实超时」不可混淆，这是诚实性根基（同 [`drive_pool_waves`] 的让位③）。
/// 未被取代 → 照常记账：`total` 恒 1（本腿真可测数就是 1，把 `notInPool` 算进 total 等于谎报测过）。
///
/// # 终态事件的唯一出口就在本函数
///
/// 内核 [`drive_fallback_measure_inner`] 有 2 个 `return`（让位 + 正常收尾），本薄壳收成一个出口再发
/// [`EVENT_SPEED_TEST_DONE`](crate::events::channel::EVENT_SPEED_TEST_DONE)。本腿的 `intended` 恒为 `[active]` 一个元素 ⇒ 中断时 `pending == [active]`
/// （它就是唯一没测成的那个）。判据见 [`emit_speed_test_done`]。
async fn drive_fallback_measure<Meas, MeasFut>(
    active: &str,
    superseded: &(dyn Fn() -> bool + Sync),
    measure: Meas,
    emit: &mut (dyn FnMut(&str, Value) + Send),
) -> (serde_json::Map<String, Value>, &'static str)
where
    Meas: FnOnce() -> MeasFut,
    MeasFut: Future<Output = Option<u32>>,
{
    let intended = [active.to_string()];
    let (results, outcome) = drive_fallback_measure_inner(active, superseded, measure, emit).await;
    emit_speed_test_done(
        emit,
        outcome,
        &results,
        &intended,
        interrupt_reason(outcome),
    );
    (results, outcome)
}

async fn drive_fallback_measure_inner<Meas, MeasFut>(
    active: &str,
    superseded: &(dyn Fn() -> bool + Sync),
    measure: Meas,
    emit: &mut (dyn FnMut(&str, Value) + Send),
) -> (serde_json::Map<String, Value>, &'static str)
where
    Meas: FnOnce() -> MeasFut,
    MeasFut: Future<Output = Option<u32>>,
{
    // 经本机混合端口真实测速：warm-TTFB（两次 GET 计第二次，对齐 mihomo unified-delay）。
    let latency = measure().await;

    // ── 让位（测量后）：在飞期间核跃迁/崩溃 ⇒ 在飞值量的是新核/已死核的出站 → 丢弃并略过该节点 ──
    if superseded() {
        return (serde_json::Map::new(), "interrupted");
    }

    let latency_val = latency.map_or(-1_i64, i64::from);

    // 逐节点结果 + 进度（前端 onSpeedTestResult / onSpeedTestProgress 流式回填）。
    emit(
        EVENT_SPEED_TEST_RESULT,
        json!({ "serverId": active, "latency": latency_val }),
    );
    emit(
        EVENT_SPEED_TEST_PROGRESS,
        json!({ "tested": 1, "ok": i32::from(latency.is_some()), "total": 1 }),
    );

    let mut results = serde_json::Map::new();
    results.insert(active.to_string(), json!(latency_val));
    (results, "completed")
}

/// **§15 主核探测池分波测速**（`server_speed_test` 池就绪腿；对齐 上游 `SpeedTestService.testServersViaMainCore`）。
///
/// 编排：请求集经 [`partition_pool`] 波前预筛分「可测 / notInPool / tsNotReady」→ 可测节点经 [`plan_waves`]
/// 按 K 分波 → 逐波：①各槽 [`ProxyRuntime::probe_select_slot`] 热切 `probe-selector-k` → 本波节点；②波内
/// **并发**经 `probe-in-k` 端口量 warm-TTFB（K 槽各测各出口不串味）；③逐节点推 `event:speedTestResult` /
/// `event:speedTestProgress` + 收集。波间串行（同槽跨波复用，selector `interrupt_exist_connections` 断残留防串味）。
///
/// **诚实性**：两条波前缺席列表如实回报（不 select / 不 measure / 不 report、绝不伪造）；热切失败/超时的槽记
/// -1（真实不可测，非缺席）；`total` = 波前预筛**后**的可测数（把缺席节点算进 total 等于谎报测过）。零可测 →
/// 失败信封（[`zero_testable_envelope`] 分流 code，前端 catch 复位、防卡死）。
///
/// **禁本机碰宿主网络**：真延迟走真核真出站 = 真机门；本函数的分波/分区/热切编排纯逻辑已由
/// [`plan_waves`]/[`partition_pool`] 单测，真数值只在真机验。
async fn run_pool_speed_test(
    app: &AppHandle,
    proxy: &ProxyRuntime,
    targets: &SpeedProbeTargets,
    requested: &[String],
    url: &str,
    prefilter: &PoolPrefilter<'_>,
) -> ApiResponse<Value> {
    let k = targets.pool_ports.len();
    let PoolPartition {
        testable: pool_testable,
        not_in_pool,
        dirty,
        ts_not_ready,
    } = partition_pool(
        requested,
        &targets.id_to_tag,
        prefilter.dirty,
        prefilter.ts_pending,
    );

    // 波前预筛后零可测（全未入池 / 全已编辑未生效 / 全 TS 未就绪 / 混合）→ 失败信封防前端卡死 +
    // 缺席原因如实分流。
    if pool_testable.is_empty() {
        // 成因按 `ts_not_ready` 的**实际缺席集**取（不是整张 `ts_reasons`）——分区腿的优先级
        // 可能已经把某个 TS 节点归到 notInPool/dirty 去了，那种情况下再报它的 TS 成因是误导。
        let ts_reasons: Vec<TsNotReady> = ts_not_ready
            .iter()
            .filter_map(|id| prefilter.ts_reasons.get(id).cloned())
            .collect();
        let (msg, code) = zero_testable_envelope(not_in_pool.len(), dirty.len(), &ts_reasons);
        return ApiResponse::err_with_code(msg, code);
    }

    let total = pool_testable.len();
    let waves = plan_waves(&pool_testable, k);

    // §15.11 让位（超代）基准：本轮归属的核世代。三检查点均以它比对（见 [`drive_pool_waves`]）。
    let gen0 = proxy.core_generation();
    let superseded = || is_superseded(proxy.core_generation(), gen0, proxy.status().running);

    let (results, outcome) = drive_pool_waves(
        &waves,
        total,
        &superseded,
        |slot, tag: String| async move { proxy.probe_select_slot(slot, &tag).await },
        |port| {
            let url = url.to_string();
            async move { measure_via_local_proxy(port, &url).await }
        },
        &mut |event, payload| {
            let _ = app.emit(event, payload);
        },
        targets.pool_ports.as_slice(),
    )
    .await;

    ApiResponse::ok(json!({
        "results": results,
        // completed：本次入参已全部裁定（在池的测了、notInPool 如实缺席）；interrupted：被核跃迁/崩溃打断，
        // 未测节点**缺席**（前端据此保留旧值，见 contracts/speed-test.ts SpeedTestOutcome）。
        "outcome": outcome,
        "notInPool": not_in_pool,
        // TS 未登录就绪 → 波前缺席（核已让位直连，测它量到的是直连 RTT）。判据见 [`ts_node_ready`]。
        "tsNotReady": ts_not_ready,
        // 已编辑未生效 → 波前缺席（核仍跑旧参数，测它量到的是旧参数出口的 RTT）。判据见 [`partition_dirty`]。
        //
        // **独立键、不并进 `notInPool`**（1:1 上游 `:688` 的 `continue` 不入 `runCtx.skipped`）：两者
        // 是不同的物理事实与不同的修法（未入池=重启纳入 / 已编辑未生效=应用更改），并进去等于后端谎报
        // 「这些节点不在池里」。**已知残留**：渲染端 `notInPoolMessage` 目前只累加 `notInPool + tsNotReady`
        // ⇒ 混合形态下 toast 少报 dirty 那几个（本批禁碰 `ui/`）。同一事实另有 Home「N 项待应用」操作条
        // 承载，故非静默；接线渲染端计数是后续一行改动。
        "dirty": dirty,
    }))
}

/// 后台自动故障切换复用主核探测池时的结果。它与用户测速共享同一个 [`SpeedTestGuard`]，因此两轮
/// 不会同时改写 `probe-selector-k`；后台拿不到租约就让位，不把一次人为测速误判成节点全故障。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RuntimeProbeBatch {
    Busy,
    Interrupted,
    Completed(BTreeMap<String, Option<u32>>),
}

/// 经当前运行核的 K 槽 probe pool 对一组 `(serverId, outboundTag)` 做真实协议链探测。
///
/// 候选资格（已入核、未脏、TS 已就绪）由 `ProxyRuntime` 在调用前裁定；本函数只复用现有分波、
/// `SelectOutbound`、CONNECT+warm-TTFB 与 generation guard。它不发用户测速事件，避免后台健康治理
/// 污染节点页的进度条和延迟缓存。
pub(crate) async fn probe_runtime_candidates(
    proxy: &ProxyRuntime,
    targets: &SpeedProbeTargets,
    candidates: &[(String, String)],
    url: &str,
) -> RuntimeProbeBatch {
    let Some(_guard) = SpeedTestGuard::acquire() else {
        return RuntimeProbeBatch::Busy;
    };
    let waves = plan_waves(candidates, targets.pool_ports.len());
    if waves.is_empty() {
        return RuntimeProbeBatch::Completed(BTreeMap::new());
    }
    let gen0 = proxy.core_generation();
    let superseded = || is_superseded(proxy.core_generation(), gen0, proxy.status().running);
    let (raw, outcome) = drive_pool_waves(
        &waves,
        candidates.len(),
        &superseded,
        |slot, tag: String| async move { proxy.probe_select_slot(slot, &tag).await },
        |port| {
            let url = url.to_string();
            async move { measure_via_local_proxy(port, &url).await }
        },
        &mut |_, _| {},
        targets.pool_ports.as_slice(),
    )
    .await;
    if outcome == "interrupted" {
        return RuntimeProbeBatch::Interrupted;
    }
    let measured = candidates
        .iter()
        .map(|(id, _)| {
            let latency = raw
                .get(id)
                .and_then(Value::as_i64)
                .and_then(|value| u32::try_from(value).ok());
            (id.clone(), latency)
        })
        .collect();
    RuntimeProbeBatch::Completed(measured)
}

/// **§15.11 让位判据**（纯逻辑，对齐 上游 `SpeedTestService.ts:706` 的 `superseded()`）。
///
/// 两条腿的**析取**，缺一不可：
///  - `gen_now != gen0`：核 start/stop/restart/regen 跃迁 —— 在飞结果量的是**别的核**；
///  - `!running`：核**自发崩溃** —— 崩溃分支不 bump 世代（世代腿漏判），但 `running` 立即转 false。
///
/// 漏掉 `!running` 腿 ⇒ 崩溃窗口的在飞测量失败会被记成「真实超时 -1」，即**伪造数值**（诚实性根基）。
const fn is_superseded(gen_now: u64, gen0: u64, running: bool) -> bool {
    gen_now != gen0 || !running
}

/// **§15.11 分波编排核**（热切 / 测量 / 事件发射三个 I/O 面**全部注入** ⇒ 无 `AppHandle`、不碰宿主网络、可单测）。
///
/// 让位三检查点逐条对齐 上游 `SpeedTestService.ts:711/734/751`，各自守不同的窗口：
///  1. **波首**（`:711`）：核已跃迁 → 停发新波，已测部分照常返回，未测节点缺席；
///  2. **热切后**（`:734`）：热切期间跃迁 ⇒ 本波 `select_outbound` 的失败是**超代所致**而非节点真不可测 ——
///     不加这道，超代的热切失败会被下面记成 `-1`（伪造「真实超时」）；
///  3. **测量后**（`:751`）：测量在飞期间跃迁 ⇒ 在飞值量的是新核/已死核的出站，丢弃而非记账。
///
/// **未测节点一律缺席，绝不写假 -1** —— 这是「超代未测」与「真实超时」不可混淆的诚实性根基。
/// 返回 `(结果 map, outcome)`；任一检查点命中即 `interrupted`。
///
/// # 回填粒度：**逐节点**（对齐 上游，非按波）
///
/// 结果与进度在**每个节点自己测完那一刻**就落账 + 推事件（上游 `SpeedTestService.ts:773` 的 `report()`
/// 就写在 `wave.map` 的每个 worker 体内）。按波统一回填的话，首个延迟数字最晚要等**整波最慢的那个**
/// —— 一波里只要有一个死节点，屏幕就先空 8s，此后每波一跳。总耗时不变，主观耗时天差地别。
///
/// **代价（如实登记）**：让位③随之从「整波级」降为「逐节点级」—— 已经回填的节点不可能再撤回，故跃迁
/// 时丢弃的只是**尚未回来**的那些在飞值，而不是整波。这**正是 上游的语义**（`:751` 的超代检查也在
/// worker 体内、`report()` 之前），且诚实性根基不动：跃迁后回来的值一律丢弃、绝不写假 -1。
///
/// # 终态事件的唯一出口就在本函数
///
/// 内核 [`drive_pool_waves_inner`] 有 4 个 `return`（让位三检查点 + 正常收尾），本薄壳把它们收成一个
/// 出口再发 [`EVENT_SPEED_TEST_DONE`](crate::events::channel::EVENT_SPEED_TEST_DONE) ⇒ 「中断了却没发终态」在结构上写不出来。载荷含未测集合
/// （续测输入），判据见 [`emit_speed_test_done`]。
async fn drive_pool_waves<Sel, SelFut, Meas, MeasFut>(
    waves: &[Vec<SlotAssignment>],
    total: usize,
    superseded: &(dyn Fn() -> bool + Sync),
    select_slot: Sel,
    measure: Meas,
    emit: &mut (dyn FnMut(&str, Value) + Send),
    pool_ports: &[u16],
) -> (serde_json::Map<String, Value>, &'static str)
where
    Sel: Fn(usize, String) -> SelFut,
    SelFut: Future<Output = bool>,
    Meas: Fn(u16) -> MeasFut,
    MeasFut: Future<Output = Option<u32>> + Send + 'static,
{
    // 本腿「已裁定要测」的集合 = 分波后的全部槽位节点（`plan_waves` 就是按可测集分的波，
    // 故这里恒等于波前预筛后的 `pool_testable`，无第二真值源）。
    let intended: Vec<String> = waves.iter().flatten().map(|a| a.node_id.clone()).collect();
    let (results, outcome) = drive_pool_waves_inner(
        waves,
        total,
        superseded,
        select_slot,
        measure,
        emit,
        pool_ports,
    )
    .await;
    emit_speed_test_done(
        emit,
        outcome,
        &results,
        &intended,
        interrupt_reason(outcome),
    );
    (results, outcome)
}

/// 主核两条腿（池 / 回退）的中断成因映射。
///
/// 这两条腿的**全部**中断检查点（池路径三个 + 回退腿一个）判据都是 `is_superseded`（核
/// start/stop/restart/regen 或崩溃）⇒ `interrupted` 在这里恒等于 [`InterruptReason::Superseded`]，
/// 不存在第二种成因。临时核腿则不同：它多出「核退出 / 核无响应」两类，由那条腿自己给出。
fn interrupt_reason(outcome: &str) -> Option<InterruptReason> {
    (outcome == "interrupted").then_some(InterruptReason::Superseded)
}

#[allow(clippy::too_many_arguments)]
async fn drive_pool_waves_inner<Sel, SelFut, Meas, MeasFut>(
    waves: &[Vec<SlotAssignment>],
    total: usize,
    superseded: &(dyn Fn() -> bool + Sync),
    select_slot: Sel,
    measure: Meas,
    emit: &mut (dyn FnMut(&str, Value) + Send),
    pool_ports: &[u16],
) -> (serde_json::Map<String, Value>, &'static str)
where
    Sel: Fn(usize, String) -> SelFut,
    SelFut: Future<Output = bool>,
    Meas: Fn(u16) -> MeasFut,
    MeasFut: Future<Output = Option<u32>> + Send + 'static,
{
    let mut results = serde_json::Map::new();
    let mut tested = 0usize;
    let mut ok = 0usize;

    for wave in waves {
        // ── 让位①（波首）：核跃迁/崩溃 → 停发新波 ──
        if superseded() {
            return (results, "interrupted");
        }

        // 1. 波内各槽热切 probe-selector-k → 本波节点（gRPC select_outbound，live 生效）。逐槽记成败：
        //    热切失败（核未就绪 / stale tag）→ 该槽本波不测，节点记 -1（真实不可测，非伪造缺席）。
        //
        //    **并行**（对齐 上游 `SpeedTestService.ts:718-727` 的 `Promise.all(wave.map(...))`）：
        //    每次热切 = 新建一条 lazy gRPC channel + 一次 select_outbound 往返，串行时这 K 次往返
        //    全摊在每一波的关键路径上。`join_all` **保序** ⇒ `selected[i]` 仍与 `wave[i]` 逐位对应。
        //    各槽热切的是**互不相同**的 `probe-selector-k`，本层无共享可变状态。
        let selected: Vec<bool> =
            futures::future::join_all(wave.iter().map(|a| select_slot(a.slot, a.tag.clone())))
                .await;

        // ── 让位②（热切后）：热切期间跃迁 ⇒ 本波 select 结果作废，不得把超代的热切失败记成真实 -1 ──
        if superseded() {
            return (results, "interrupted");
        }

        // 2. 热切失败的槽本波不测 → 立刻记 -1 回填（**真实**不可测：让位②刚放行，说明核没跃迁，
        //    这次 select 失败是 stale tag / 节点不可用，不是超代所致）。对齐 上游 `:739-744`。
        for (i, a) in wave.iter().enumerate() {
            if !selected[i] {
                record_measured(
                    &mut results,
                    &mut tested,
                    &mut ok,
                    emit,
                    &a.node_id,
                    None,
                    total,
                );
            }
        }

        // 3. 波内并发量 warm-TTFB（各槽经其 probe-in-k 回环端口测各自出口，互不污染）。热切失败的槽不 spawn。
        //    **每回来一个就回填一个**（不等整波）—— 首个数字几百毫秒内上屏，而不是等本波最慢的那个。
        let mut set = tokio::task::JoinSet::new();
        for (i, a) in wave.iter().enumerate() {
            if !selected[i] {
                continue;
            }
            let port = pool_ports[a.slot]; // slot < k = pool_ports.len()（plan_waves 保证）
            let node_id = a.node_id.clone();
            let fut = measure(port);
            set.spawn(async move { (node_id, fut.await) });
        }
        while let Some(res) = set.join_next().await {
            // JoinError（panic）→ 该节点无数值，缺席，绝不补 -1。
            let Ok((id, latency)) = res else { continue };
            // ── 让位③（**每节点**测完即查）：在飞期间跃迁 ⇒ 丢弃这一个及其后的在飞值
            //    （量的是新核/已死核，非本轮出口）。已回填的节点是跃迁前量到的真值，保留。
            if superseded() {
                set.abort_all();
                return (results, "interrupted");
            }
            record_measured(
                &mut results,
                &mut tested,
                &mut ok,
                emit,
                &id,
                latency,
                total,
            );
        }
    }

    (results, "completed")
}

/// 单个节点的落账 + 推事件（`result` 与 `progress` 成对，计数在此处自增 ⇒ 恒单调）。
///
/// `latency == None` ⇒ 记 -1（**真实**不可测：超时 / 传输错 / 热切失败）。「让位未测」的节点根本
/// 不会走到这里 —— 它们缺席，见 [`drive_pool_waves`] 的三检查点。
fn record_measured(
    results: &mut serde_json::Map<String, Value>,
    tested: &mut usize,
    ok: &mut usize,
    emit: &mut (dyn FnMut(&str, Value) + Send),
    node_id: &str,
    latency: Option<u32>,
    total: usize,
) {
    let latency_val = latency.map_or(-1_i64, i64::from);
    if latency.is_none() {
        log::debug!(
            "测速未取得有效延迟：nodeId={node_id}（可能为探针热切失败、冷建链/复用请求超时、传输错误或测速端点非 2xx）"
        );
    }
    results.insert(node_id.to_string(), json!(latency_val));
    emit(
        EVENT_SPEED_TEST_RESULT,
        json!({ "serverId": node_id, "latency": latency_val }),
    );
    *tested += 1;
    if latency.is_some() {
        *ok += 1;
    }
    emit(
        EVENT_SPEED_TEST_PROGRESS,
        json!({ "tested": *tested, "ok": *ok, "total": total }),
    );
}

/// 测速目标 URL 求值（单一真值）：用户配的 `speedTestUrl`（须**解析得出隧道目标**）否则
/// [`DEFAULT_SPEED_TEST_URL`]。
///
/// 池路径 / 回退路径 / 出口伴测三处共用同一口径 —— 测速值可跨路径合法比较（同端点 = 同 warm TTFB 语义）。
///
/// **判据是「能否解析成 [`SpeedTestTarget`]」而不是「是否 `http(s)://` 开头」**：CONNECT 腿要的是
/// host/port/path 三件套，`http://` 这种前缀对但解析不出 host 的值若被放行，会让每个节点都拿一个
/// -1 假失败（原因在配置、锅记在节点头上）。对齐 上游 `resolveSpeedTestTarget` 的回落语义。
pub(crate) fn resolve_speed_test_url(config: &Value) -> String {
    config
        .get("speedTestUrl")
        .and_then(Value::as_str)
        .filter(|&u| SpeedTestTarget::parse(u).is_some())
        .map_or_else(|| DEFAULT_SPEED_TEST_URL.to_string(), str::to_string)
}

/// warm-TTFB 计时的**纯时序核**（隧道的建立与 I/O 全部经 [`WarmTunnel`] 注入 ⇒ 「两段各自独立计时、
/// 首段超时不发第二次」这两个结构事实可用假时钟单测，不必碰宿主网络）。
///
/// `open` 建隧道（CONNECT + https 的 TLS 握手），`WarmTunnel::get()` 在**同一条**隧道上发一次 GET，
/// 返回 `Some(是否 2xx)` / `None`（传输错 / 对端过早关闭 / 畸形响应头）。
///
/// # 两段预算，边界划在 **GET1 之后**
///
/// | 段 | 预算 | 覆盖 |
/// |---|---|---|
/// | 冷建链 | `cold` | `open`（CONNECT + TLS）+ **GET1** |
/// | 复用请求 | `reuse` | **GET2**（= 上报的 measured 值） |
///
/// 边界为什么是 GET1 之后而不是 CONNECT 200 之后（内核先回 200 后拨号，握手落在 GET1 里）、
/// 以及**为什么这不是回到「两个等长计时器」那个病**，见 [`SPEED_TEST_COLD_TIMEOUT_MS`] 的文档。
///
/// ## 🔴 首段超时 ⇒ 立即返回 `None`，**绝不发第二次**
///
/// 结构保证：第一段的 `timeout` 结果经 `?` 早退，第二段的代码在早退之后 ——「首段超时了还继续发
/// GET2」在本函数里**写不出来**，除非把这个 `?` 拆掉。这条直接决定不可达节点的耗时是 6s 而不是 10s
/// （陈先生 2026-07-31 点名：首次超时即判超时，不再浪费资源）。
///
/// **变异锁**：
///  - 两段合用一个预算 → `cold_and_reuse_phases_have_independent_budgets` 转红；
///  - 第二段没有自己的预算（或用了第一段那份）→ `the_reuse_phase_has_its_own_smaller_budget` 转红；
///  - 首段超时后仍发 GET2 → `a_cold_phase_timeout_never_sends_the_second_get` 转红（它数 `get()` 调用次数）；
///  - 把 `open` 挪到计时器之外 → `opening_the_tunnel_spends_the_cold_budget` 转红。
///
/// # 为什么第一次 GET 必须丢弃（不是保险，是必需）
///
/// 内核对 CONNECT 是**先回 200、后拨号**（`sing/protocol/http/handshake.go:89` 写 200 → `:104` 才
/// `NewConnectionEx` 交给路由/出站）⇒ 「收到 200」不蕴含「节点握手已完成」，握手落在**第一次 GET**
/// 的往返里。只发一次 GET 会把握手原样收回 measured，退化成改前 absolute-form 的病。
/// 详见 [`crate::runtime::speedtest_tunnel`] 模块文档。
///
/// 任一段超时 / 传输错 / 非 2xx → `None`（上层记 -1，绝不伪造数值）。
pub(crate) async fn measure_warm_ttfb<T: WarmTunnel>(
    cold: Duration,
    reuse: Duration,
    open: impl Future<Output = Option<T>>,
) -> Option<u32> {
    // ── 第一阶段（冷建链）：CONNECT + TLS + GET1，共用 `cold` 一个计时器 ──
    // 建隧道**也在这一段预算内**（`open` 在 `timeout` 内部才被 poll）——挪出去就意味着一个 CONNECT
    // 挂死的节点能吃掉远超 `cold` 的时间。
    let mut tunnel = tokio::time::timeout(cold, async {
        let mut tunnel = open.await?;
        // warm-up（结果丢弃：这一次承担节点握手 + 对端冷启动）。
        let _ = tunnel.get().await;
        Some(tunnel)
    })
    .await
    .ok() // 冷建链超时
    .flatten()?; // 🔴 这个 `?` 就是「首段超时/建不起来 ⇒ 绝不发第二次」的全部实现

    // ── 第二阶段（复用请求）：GET2 = measured，独立的 `reuse` 预算 ──
    // 隧道已热（握手已在第一段付过），这里只量一个往返。
    let t0 = Instant::now();
    let is_success = tokio::time::timeout(reuse, tunnel.get())
        .await
        .ok()? // 复用请求超时
        ?; // None = 传输错 / 对端过早关闭
    if !is_success {
        return None; // 非 2xx（含 generate_204 的 204，is_success 覆盖）→ 不计
    }
    Some(u32::try_from(t0.elapsed().as_millis()).unwrap_or(u32::MAX))
}

/// 经本机 **http 入站**口对测速 URL 做 warm-TTFB 计时（毫秒）—— **CONNECT 隧道**，不是经代理的
/// absolute-form 请求。
///
/// `proxy_port` 三条生产路径共用（都是本机 http 入站）：主核池 `probe-in-k` / 临时核为该节点建的入站口 /
/// 回退腿的 `mixed-in`。
///
/// 流程：CONNECT 建隧道（非 2xx 即失败）→ https 目标在隧道上 TLS 握手 → **同一条 socket** 上发两次
/// origin-form GET，丢第一次、量第二次到「响应头收齐」。**两段预算**
/// （[`SPEED_TEST_COLD_TIMEOUT_MS`] 包 CONNECT+TLS+GET1，[`SPEED_TEST_REUSE_TIMEOUT_MS`] 包 GET2，
/// 首段超时即返回不发第二次），见 [`measure_warm_ttfb`]；传输面见 [`crate::runtime::speedtest_tunnel`]。
///
/// URL 解析失败 → `None`：`resolve_speed_test_url` 已保证传进来的一定可解析（不可解析的用户值在那里
/// 就回落成默认端点了），故这条腿实际不可达；即便到达也**不伪造数值**（上层记 -1）。
/// 超时 / 传输错 / 非 2xx → None（上层记 -1，绝不伪造数值）。
async fn measure_via_local_proxy(proxy_port: u16, url: &str) -> Option<u32> {
    let target = SpeedTestTarget::parse(url)?;
    measure_warm_ttfb(
        Duration::from_millis(SPEED_TEST_COLD_TIMEOUT_MS),
        Duration::from_millis(SPEED_TEST_REUSE_TIMEOUT_MS),
        open_tunnel(proxy_port, &target),
    )
    .await
}

// ══════════════════════════════════════════════════════════════════════════════
//  出口伴测（FX-warmttfb）：代理出口 IP 探测成功后补测活跃出口 warm RTT + 广播。
//  对齐 上游 `IpInfoService.onProxyProbeSuccess` → `SpeedTestService.measureWarmRttViaHttpProxy`：
//  切节点 / 首连后出口探测成功那刻**隧道已热** → 量 warm TTFB 广播 → UI 延迟徽标自动刷新
//  （否则切节点后徽标不自动更新）。触发时机 = 探测成功那刻（非切节点瞬刻，防冷隧道虚高）。
//  纯门控 `plan_warm_rtt_probe` 可单测；真数值走真核 = 真机门。
// ══════════════════════════════════════════════════════════════════════════════

/// 出口伴测门控裁定（纯逻辑：探测成功后是否补测活跃出口 warm RTT + 测谁）。
///
/// 四条件**全真**才 fire（对齐 oracle：只在隧道已热、有真实出站时伴测，绝不冷隧道 / 无出口虚高）：
/// - `proxy_probed`：代理出口 IP 探测**探到值**（对齐 上游 `proxyProbed`；探测失败 / 直判无效 → 不测）；
/// - `running`：核在跑（无核 = 无出站可测）；
/// - `mixed_port != 0`：主混合端口有效（伴测经此口出网）；
/// - active 非空且非直连（[`DIRECT_SERVER_ID`]）：直连 / 未选节点无真实出站，无从伴测。
///
/// 返回 `Some(active_id)`（写 `EVENT_SPEED_TEST_RESULT.serverId` 的键）/ `None`（本轮不测）。
fn plan_warm_rtt_probe(
    proxy_probed: bool,
    running: bool,
    mixed_port: u16,
    active: &str,
) -> Option<String> {
    if !proxy_probed || !running || mixed_port == 0 {
        return None;
    }
    if has_no_real_exit(active) {
        return None;
    }
    Some(active.to_string())
}

/// 出口伴测入口：代理出口探测成功后 **fire-and-forget** 补测活跃出口 warm RTT + 广播（`ipinfo_get` 成功腿尾部调）。
///
/// 门控（[`plan_warm_rtt_probe`]）通过 → [`tauri::async_runtime::spawn`]（不阻塞 ipinfo 返回，保「IP 先显、延迟后到」）
/// 经主混合端口量 warm-TTFB（复用 [`measure_via_local_proxy`]：CONNECT 隧道 + 2×GET 计第二次、剔冷握手，
/// 口径 == 节点测速值）→
/// 成功广播 `EVENT_SPEED_TEST_RESULT{serverId, latency}`（前端 `onSpeedTestResult` 既有通道，零改）。
///
/// **失败（超时 / 不可达 / 非 2xx → None）不广播**：对齐 oracle `measureWarmRttViaHttpProxy` 返 null 时调用方放弃写入，
/// 保留旧徽标值、绝不伪造 -1（-1 只属用户主动测速的「测了但失败」语义；伴测是被动增益路径，静默保旧值）。
///
/// **不抢 [`SpeedTestGuard`]**：对齐 oracle fire-and-forget 语义 —— 伴测不抢主测速锁，与用户主动全量测速各测各的
/// （每次测量各建**各自的** CONNECT 隧道 = 独立连接，并发不互污 warm 计时）。与主测速偶发并发时容忍，下次探测自愈。
///
/// `epoch` / `seq` = 派生本次伴测的那条出口 IP 探测腿在**开探那一刻**取的世代号与排程线快照；
/// **emit 前复查一次**（见函数体内注释），测量期间换了出口就放弃，绝不把新出口的 RTT 记到 `active_id`
/// 那个旧节点上。两条都要：只查世代时，「更新的腿已排程但还在睡（尚未领号）」这一整个 4s 收敛窗口里
/// 复查恒真 —— 而那正是热切后最容易撞上的窗口（见 `misc::IPINFO_SCHEDULE_SEQ`）。
pub(crate) fn spawn_warm_rtt_probe(
    app: &AppHandle,
    config: &Value,
    proxy_probed: bool,
    running: bool,
    mixed_port: u16,
    epoch: u64,
    seq: u64,
) {
    let active = config
        .get("selectedServerId")
        .and_then(Value::as_str)
        .unwrap_or("");
    let Some(active_id) = plan_warm_rtt_probe(proxy_probed, running, mixed_port, active) else {
        return;
    };
    let url = resolve_speed_test_url(config);
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        // 失败 → None → 不 emit（保留旧徽标、绝不伪造 -1）；成功 → 广播让 UI 延迟徽标自动刷新。
        if let Some(latency) = measure_via_local_proxy(mixed_port, &url).await {
            // 🔵 **emit 前复查出口 IP 探测上下文**：`active_id` 取自**开探时刻**的 config 快照，而本
            // 测量是异步的（秒级）。测量期间起停 / 热切会换掉出口，此刻的 `latency` 量的是**新**出口，
            // 写进 `active_id` 就是把新节点的 RTT 记到旧节点头上 —— 而延迟徽标是用户选节点的依据，
            // 记错比不记更糟（且错值持久：`latencyMap[旧节点]` 保留到下次测它为止）。
            // 判据两条缺一不可：世代管「已开探的腿谁新」，排程线管「我开探后有没有更新的事件宣告」——
            // 只查世代时，热切后那 4s（新腿已排程、还在睡）复查恒真，正是最容易撞上的窗口。
            // 任一条变了 ⇒ 静默放弃（新出口自己那条腿会带着自己的伴测跑一遍，天然自愈）。
            if !crate::commands::misc::ipinfo_probe_is_current(epoch, seq) {
                return;
            }
            let _ = app.emit(
                EVENT_SPEED_TEST_RESULT,
                json!({ "serverId": active_id, "latency": i64::from(latency) }),
            );
        }
    });
}

#[cfg(test)]
mod tests;
