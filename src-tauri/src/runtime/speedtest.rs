//! **临时核测速**的宿主层编排（上游 `SpeedTestService.testServersViaProxy`，`SpeedTestService.ts:388-620`）。
//!
//! # 这条腿补的是什么能力
//!
//! 主核**没在跑**时（用户还没点「连接」），`server_speed_test` 此前只能返 clean error「核未运行，无法测速」。
//! 而「先测速比较延迟、再选一个最快的节点连上去」是常规使用序 —— 少了这条腿，用户必须先盲选一个节点连上、
//! 才能测别的节点。本模块起一个**独立的瞬态 sing-box**（每个可测节点一个 HTTP 入站 → 该节点出站），经各自
//! 端口量 warm-TTFB，测完即杀。
//!
//! # 与常驻主核的隔离（三条硬边界，逐条对应一个真实事故面）
//!
//! 1. **独立配置文件**：`<configDir>/speedtest-core.json`，绝不碰主核的 `singbox-runtime.json`
//!    （[`ProxyRuntime::runtime_config_path`](crate::runtime::proxy::ProxyRuntime::runtime_config_path)）。
//! 2. **独立端口**：经 [`PortAllocator::resolve_distinct_free_ports`] 现分配，且**排除**用户配置的
//!    control/http/mixed 口 —— 否则主核随后起来时会撞在临时核占着的口上，表现为「测完速就连不上」。
//! 3. **不写主核的任何生命周期槽**：child 句柄由本模块的会话独占，绝不进 `ProxyRuntime` 的 `pid`/`child`；
//!    也不置 `core_via_helper` 标记。临时核**永不经 helper 起**（无 TUN、无 root 需求）。
//!
//! # 让位语义（§15.11 gen abort 惯例的镜像腿）
//!
//! 主核和临时核**绝不能同时跑**：同一个 WG/WARP peer 被两个会话同时握手会互相踢线（上游 G1 的
//! 「双会话超时」），Tailscale 更是连第二个 tsnet 实例都建不出来。本腿只在主核未跑时开工，且全程守
//! [`is_temp_core_superseded`]：
//!
//! - `gen != gen0` —— 用户中途点了「连接」（`start` 先 bump 世代再动核）⇒ 主核来了，临时核**立刻让路**；
//! - `running == true` —— **世代腿盖不住的那一半**：起核的 bump 可能发生在本次测速取 `gen0` **之前**
//!   （此刻 `status.running` 仍是 false，因为核还在启动中），随后核就绪 ⇒ `running` 翻真而世代不再变。
//!   只查世代的话，这整段窗口里临时核与主核并存 —— 正是双会话事故的形态。
//! - `starting == true` —— **前两条腿同时为假的那整段启动期**：`start` 先置 `start_inflight`
//!   （`starting` 的源）、再跑可达数秒的 stale 清扫、才 `bump_generation`；`gen0` 落在 bump 之后、
//!   就绪之前时，世代腿与 `running` 腿双盲，而主核正在 spawn + bind 端口。
//!
//! 让路 = **中断编排 + 杀临时核 + 未测节点缺席**（不写假 `-1`），与主核池路径 [`drive_pool_waves`] 的
//! 三检查点逐字同义。收尾（杀核 + 删配置）走**无条件**路径，让位/失败/正常完成三条腿共用。
//!
//! [`drive_pool_waves`]: crate::commands::speedtest
//!
//! # 诚实边界（务必读）
//!
//! 本模块的端到端价值 = **真 sing-box + 真出站 + 真网络往返**。这条真机路径**在本 Linux 开发机上无法
//! 验证**（本仓禁跑触碰宿主网络的测试）。因此：
//! - 全部可单测面（节点分区、配置生成、端口/tag 绑定、并发分批、让位三检查点、收尾回收）都以**注入的**
//!   [`TempCoreDeps`] / 测量闭包 / 事件闭包驱动 —— 无真进程、无网络、无真 sing-box；
//! - **真 spawn + 真延迟数值**一段**在此未验证**，门槛是一次真机会话。不得据本模块宣称「临时核测速端到端可用」。

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use serde_json::{json, Value};

use polaris_config_engine::builder::endpoints::{
    build_vpn_client_endpoint, build_wireguard_endpoint,
};
use polaris_config_engine::builder::outbound::build_proxy_outbound;
use polaris_config_engine::builder::outbounds::build_shadow_tls_outbound;
use polaris_config_engine::singbox::DomainResolver;
use polaris_config_engine::user_config::server_config::{Protocol, ServerConfig};
use polaris_core_supervisor::port_bookkeeping::TokioPortProvider;
use polaris_core_supervisor::{
    core_startup_estimate_ms, wait_for_core_ready, CoreReadyDeps, CoreReadyOutcome, PortAllocator,
    PortExclusions, Signal, SpawnRequest, StdioPolicy, WaitForCoreReadyOptions,
    CORE_READY_SAFETY_FACTOR, CORE_STARTUP_BASELINE_FIXED_MS, CORE_STARTUP_PER_NAIVE_MS,
    CORE_STARTUP_PER_NODE_US,
};

use crate::events::channel::{
    EVENT_SPEED_TEST_DONE, EVENT_SPEED_TEST_PROGRESS, EVENT_SPEED_TEST_RESULT,
};
use crate::logging::SPEEDTEST_CORE_TARGET;
use crate::runtime::proxy::core_log::pipe_to_log;
use crate::runtime::proxy::{pid_alive, send_signal, CoreBuildEnv};
// 瞬态核的进程原语**复用** `tailscale_login_core` 已建好的那一套（spawn → 装箱 child → SIGTERM/宽限/
// SIGKILL/reap）。名字带 "Login" 是历史包袱，语义是「瞬态 sing-box 子进程」，与本腿逐字相同；再写一套
// 进程管理只会多一份要各自维护的收割纪律（而收割写漏的表现是孤儿核，静默且持久）。
use crate::runtime::tailscale_login_core::{
    ConfigChecker, LoginCoreChild, LoginCoreSpawner, SingBoxConfigChecker, TokioLoginCoreSpawner,
};

/// 临时核可测节点的**滑动窗口**上限（对齐 上游 `SpeedTestService.PROXY_TEST_CONCURRENCY = 16`，`:90`）。
///
/// 不设上限时大订阅会把 N 路 TLS/QUIC 握手同时打出去 → 本机 CPU/连接数打满 → 一批**假超时**
/// （节点其实是好的）。≤上限的小订阅等价于全并行，零代价。
///
/// 语义是「**同时在飞**至多这么多」（回来一个补一个），**不是**「切成这么大的批」——
/// 见 [`drive_temp_core_measures`] 的调度形态一节。
pub const TEMP_CORE_CONCURRENCY: usize = 16;

/// 临时核就绪等待的**下限**（= 本门改成规模函数之前的那个固定值，对齐 上游
/// `waitForPortReady(ports[0], 10000)`，`:510`）。
///
/// # 为什么公式之外还要留一个下限
///
/// [`temp_core_startup_estimate_ms`] 的固定项只有 90ms —— 它是**缓存已热的机器上核自报的
/// `started (0.09s)`**，不含进程 spawn、不含杀软扫描、不含应用分流规则集/geo 资源的加载。
/// 让公式在小批上自由取值 ⇒ 一个 20 节点 0 naive 的订阅会拿到 0.2s 的门，把今天跑得好好的
/// 场景当场打穿。而 10s 是**唯一有生产证据**的值（已发布、已在真机上跑）。
///
/// # 这个数不许动 —— 它是「今天能跑通的订阅不受影响」这条承诺的**唯一**锚点
///
/// 门在**时间维度**上的空操作性完全由它承载：只要它还是那个已发布的值，任何今天能在 10s 内就绪的
/// 批在本改动之后拿到的门都 ≥ 10s ⇒ 等待行为逐字不变。把它调小 = 在**没有任何新证据**的前提下把门
/// 收窄到一个从未跑过的取值上，而收窄的失败面正是本改动要消灭的那个（正在正常启动的核被判死 ⇒
/// 整批零结果 ⇒ 报错指向网络）。
///
/// 故它由**两条独立**的门守，缺一条另一条都拦不住对方那种改法：
/// `the_floor_is_actually_applied_to_the_budget`（`.max` 这条接线还在）与
/// `the_floor_stays_at_the_only_value_with_production_evidence`（字面值仍是 10_000）。
///
/// # 空操作性的射程（如实记账，别读成「本改动对今天一律无影响」）
///
/// 逐字空操作**只在门的时间维度上成立**。[`temp_core_ready_timeout_ms`] 的 `Err` 腿是本改动
/// **新增的前置拒绝**，今天不存在：n=0 时 m ≥ 730 即被拒。而一批 730 naive 今天要能在固定 10s 门下
/// 跑通，需 `t_engine ≤ (10_000 − 90) / 730 ≈ 13.6ms`，声明区间却是 30–45ms ⇒
/// **只有当两点回归高估了 ≥2.2 倍，本改动才会打死一个今天能跑通的订阅**。
/// 这条安全性依赖「`t_engine` 真值不低于 13.6ms」，属未实测面（多点实测的测法见
/// [`temp_core_startup_estimate_ms`]）。
const TEMP_CORE_READY_TIMEOUT_FLOOR_MS: u64 = 10_000;

/// 就绪预算的**硬上限**：算出来越过它 ⇒ 本批**根本不起核**，当场带原因失败
/// （[`temp_core_ready_timeout_ms`] 的 `Err` 腿）。
///
/// # 为什么是「拒绝」而不是「截断到上限」
///
/// 截断 = 把「这批要 70s 才起得来」悄悄改写成「等满 60s 还没起来 ⇒ 超时」，用户拿到的报错是
/// `未就绪（Timeout）`，指向网络/端口，而真因是本批规模。那正是固定 10s 门在 ~240 个 naive 上的
/// 表现，逐字相同 —— 本改动存在的理由就是消灭这类误诊，不能在上界处把它原样重建一遍。
/// 故越界必须是**前置的、说得清的失败**，且发生在起核之前（不烧 N 个端口、不留下要收的核）。
///
/// # 60s 的判据
///
/// 它不是启动耗时的物理上限，是「等一个**可能永远不会 bind** 的核」的耐心上限。
/// · 下界：必须远高于本改动要拆掉的那堵墙（240 naive ⇒ 预算 19.9s），否则改了等于没改。
///   60s 对应约 725 个 naive（见 [`temp_core_max_naive`]），是那堵墙的 3 倍；
/// · 上界：一分钟是「这东西是不是死了」的普遍心理阈值，再往上等只是把无解的等待拉长。
///
/// **真会吃满这 60s 的只有一种形态：核活着、但一直不 bind 的僵核。** 另外两条腿都提前返回，
/// 不要把它们算进这个上限的依据里：核**崩掉**由 `CoreReadyDeps::is_alive` 接住
/// （本模块传的是 `pid == 0 || pid_alive(pid)`，进程一没就停等）；用户中途点「连接」由
/// `is_superseded` 接住（命中即停等 + 杀核）。剩下的那种僵核形态确实**没有取消按钮**
/// （登记项 L2-e），且进程级单飞闸（`commands::speedtest::SPEED_TEST_IN_FLIGHT`）在此期间挡住
/// 一切后续测速请求 ⇒ 上限必须有限，且不能定得太大。
///
/// # ⚠️ T1-R1（分批）之后：这条腿**在生产路径上已经不可达**，但它不是死代码
///
/// 分批落地之后，进 [`TempCoreSession::run_batch`] 的每一批都由 [`plan_temp_core_batches`] 裁过，
/// `(n, m)` 被 [`TEMP_CORE_BATCH_MAX_NODES`] / [`temp_core_batch_max_naive`] 封死 ⇒ 单批预算至多
/// ≈11.9s，**永远不会**越过本值（60s）。门 `planned_batches_never_trip_the_oversize_refusal` 把这
/// 件事钉成判据，而不是留成一句注释。
///
/// 那为什么不删掉整条腿：
/// · 它是 [`TempCoreSession::run_batch`] 这个入口的**前置条件检查**。规划器绕过（未来新增第二个
///   调用点）或规划器自身回归（有人把 `TEMP_CORE_BATCH_MAX_NODES` 调大而没跟着调预算）时，它是
///   唯一会喊出来的地方 —— 而不喊的表现是「起核、白等一分多钟、超时、整批零结果、报错指向网络」；
/// · 报错原文给的建议（「减少本轮 naive 节点数分次测」）在那种回归下**仍然可执行**，不是过期建议；
/// · 删它不省任何运行成本（一次整型比较），却把一个已经写好、已有门、已接到用户可见文案的防御拆掉。
///
/// 判据本身**没有变**：60s 仍然是「等一个可能永远不 bind 的核」的耐心上限。变的是它的射程 ——
/// 从「用户选太多 naive 时的拒绝腿」变成「规划器与门失配时的自曝腿」。
/// **真正对用户生效的规模上限现在是 [`TEMP_CORE_BATCH_READY_BUDGET_CAP_MS`]（12s / 批），
/// 而它不再拒绝任何人：越界的批被切开，不被打回。**
const TEMP_CORE_READY_TIMEOUT_CAP_MS: u64 = 60_000;

// ── 起核耗时的规模系数：单一真值在 `polaris_core_supervisor::readiness_gate` ──────────────────
//
// 这里曾有四个本地常量 `TEMP_CORE_STARTUP_FIXED_MS`(90) / `TEMP_CORE_STARTUP_PER_NODE_US`(105) /
// `TEMP_CORE_STARTUP_PER_NAIVE_MS`(41) / `TEMP_CORE_READY_SAFETY_FACTOR`(2)，与 core-supervisor 的
// `CORE_STARTUP_BASELINE_FIXED_MS` / `CORE_STARTUP_PER_NODE_US` / `CORE_STARTUP_PER_NAIVE_MS` /
// `CORE_READY_SAFETY_FACTOR` **逐值相等**。那是主核就绪门那一批落地时的临时状态（本文件当时正在
// 另一支上分批重构，两批不能同时改同一个文件），不是设计。
//
// 重复期间由两道门守着，它们随重复一并退场（2026-09-03 收口）：
// · `temp_core_coefficients_stay_pinned_to_the_supervisor_single_source`
//   （`runtime/proxy/tests/startup.rs`）—— **双向**防漂移：改 core-supervisor 的常量（编译期真值）
//   或改本文件的常量（源码取材）都转红。守的是「两个核必须按同一个模型算就绪门」，而漂移的表现是
//   其中一个门必然偏小 ⇒ 正在正常启动的核被判死；
// · `speedtest_coefficient_digits_are_ambiguous_in_the_raw_source` —— 上面那道门的正向对照，证明它的
//   取材面里裸数字确实歧义（本文件散文里 `90`/`105`/`41` 各出现好几次，按数字取材会取到注释）。
//
// 现在两个核读**同一份**常量：漂移在结构上不可能发生（改一处即两处），两道门无对象可守。判据一条没丢
// —— 系数分级（实测/推导）、30–45ms 的区间、多点实测的测法、「只许偏大」的不对称，全在
// `readiness_gate` 那四个常量的文档里；本文件只留临时核腿**特有**的部分（固定项为什么可以取基线值、
// 估小在本腿上的表现、10s 下限）。收口的行为等价性由
// `runtime/speedtest/tests/mod.rs::the_single_source_collapse_returns_the_same_values` 钉住。

// ══════════════════════════════════════════════════════════════════════════════
//  分批（T1-R1）：让**峰值资源**与订阅节点数无关（O(1)），耗时允许 O(N)
// ══════════════════════════════════════════════════════════════════════════════

/// 前端**静默兜底**的镜像值（ms）：`ui/src/lib/speedtest-progress-toast.ts` 的
/// `SPEEDTEST_IDLE_TIMEOUT_MS` —— 「两条进度事件之间静默这么久 ⇒ 判为中断」。
///
/// # 它为什么是分批的**绑定约束**，而不是一个参考值
///
/// 分批之前，本腿一轮只起一个核，进度事件从第一个节点测完开始就密集地来（间隔 ≤ 单节点最坏耗时
/// 10s），而起核到就绪那一整段窗口里前端**一个定时器都没布防**（`armIdle` 在 `state.live` 为假时
/// 早退）⇒ 后端的就绪门取多大都碰不到这个数（这正是 R0 把门放宽到 60s 的前提）。
///
/// 分批之后**这个前提在第二批起就不成立了**：批 1 的进度事件已经把兜底定时器布防起来，而批 2 的
/// 「收上一批的核 → check → spawn → 就绪门」整段是**没有任何事件**的空窗。空窗一旦越过本值，用户
/// 会在测速**正常进行**时看到一条假的「测速中断」。⇒ 本值经
/// [`TEMP_CORE_BATCH_READY_BUDGET_CAP_MS`] 反解出单批规模的上限。
///
/// 两侧的一致性由跨语言门维持（`speedtest-progress-toast.test.ts` 直接读本文件的这个常量对拍），
/// 不靠两边注释互指。
const TEMP_CORE_UI_IDLE_TIMEOUT_MS: u64 = 20_000;

/// 批间空窗里**就绪门以外**的开销上界（ms）。
///
/// 空窗被两条心跳切成三段（发射点见 [`TempCoreSession::run`] 与 [`TempCoreSession::run_batch`]）：
///
/// | 段 | 从 → 到 | 上界 | 是否随批规模变 |
/// |---|---|---|---|
/// | ① | 上一批最后一条 progress → 本批**批首心跳** | 收核宽限 `LOGIN_STOP_GRACE` = 5s | 否 |
/// | ② | 批首心跳 → 本批**就绪心跳** | 端口分配 + 写配置 + `sing-box check` + spawn + 就绪门 | **是**（就绪门那一项） |
/// | ③ | 就绪心跳 → 本批第一个节点的 progress | 单节点最坏 = 冷建链 6s + 复用 4s = 10s | 否 |
///
/// ①③ 与批规模无关且都远低于 [`TEMP_CORE_UI_IDLE_TIMEOUT_MS`]（③ 的 10s 正是那个 20s 的推导来源）
/// ⇒ **唯一需要用批大小去控的是 ②**。本常量是 ② 里除就绪门之外的全部：
///
/// · `polaris_core_supervisor::CONFIG_CHECK_TIMEOUT`（5s）—— `sing-box check` 的硬超时，
/// 是这一段里第二大的确定上界；
/// · 1s —— 端口分配（n 次 `bind(0)`/`close`）+ 写配置 + spawn + 一个就绪轮询间隔
///   （[`TEMP_CORE_READY_POLL_MS`]）；
/// · 2s —— 余量。它不是凑数：②的三项里只有 check 有硬超时，spawn 与文件 I/O 在杀软扫描/冷盘上
///   都可能比 1s 更久，而越界的代价（假「测速中断」）虽不致命却直接打脸。
///
/// 两条心跳**都必要**，缺任何一条这套不等式都无解（判据写在 [`TempCoreSession::run`]）。
///
/// # 为什么写成字面量而不是 `CONFIG_CHECK_TIMEOUT.as_secs() * 1_000 + 1_000 + 2_000`
///
/// 跨语言那一侧（`speedtest-feedback.test.ts` 的「最多带 N 个」对拍门）要**读出这个数**才能把
/// 用户可见的那个上限现算出来，而它只认 `const NAME: u64 = <字面量>;`。写成表达式 ⇒ 那道门读不到
/// ⇒ 只能退回写死一个数，于是后端系数一改译文就静默过期 —— 正是那道门存在的理由。
/// 与 `polaris_core_supervisor::CONFIG_CHECK_TIMEOUT` 的关系改由门
/// `the_batch_caps_are_derived_from_the_two_budgets` 断言（`5s + 1s + 2s`），一改就红。
const TEMP_CORE_BATCH_WINDOW_OVERHEAD_MS: u64 = 8_000;

/// 单批就绪预算的**上限**（ms）= 前端静默兜底 − 批间空窗的其余开销。
///
/// 越过它 ⇒ 批间空窗可能超过前端的 20s 兜底 ⇒ 用户在测速正常进行时看到假的「测速中断」。
/// 它比 [`TEMP_CORE_READY_TIMEOUT_CAP_MS`]（60s，单核耐心上限）**严得多**，两条约束取严即取本条。
const TEMP_CORE_BATCH_READY_BUDGET_CAP_MS: u64 =
    TEMP_CORE_UI_IDLE_TIMEOUT_MS - TEMP_CORE_BATCH_WINDOW_OVERHEAD_MS;

/// 单批**起核估算**的上限（ms）= 预算上限 ÷ 安全系数（预算 = 估算 × 系数，见
/// [`temp_core_ready_timeout_ms`]）。
///
/// 下限（[`TEMP_CORE_READY_TIMEOUT_FLOOR_MS`] = 10s）恒小于本上限对应的预算上限（12s），故取下限
/// 不会把一个合法批顶过上限 —— 约束只落在公式项上。
const TEMP_CORE_BATCH_ESTIMATE_CAP_MS: u64 =
    TEMP_CORE_BATCH_READY_BUDGET_CAP_MS / CORE_READY_SAFETY_FACTOR;

/// 各平台**临时端口段**里最小的那一个（macOS 49152–65535 = 16384 个）。
///
/// 临时核给每个节点开一个回环 http 入站 ⇒ 一批占用 n 个端口，且从「宿主 `bind(0)` 预留完释放」到
/// 「核真正 bind」之间是 TOCTOU 窗口（被别的进程抢走一个即整核 FATAL）。故 n 必须有界。
const TEMP_CORE_EPHEMERAL_PORT_FLOOR: usize = 16_384;

/// 一批至多占临时端口段的 **1/32**。
///
/// 判据是「一次测速不该把系统的临时端口段吃掉可观的一块」：本机同时还有浏览器、IDE、其它 socket
/// 在申请临时口。1/32 ⇒ 3.1%，是「够大到不必频繁切批」与「小到不影响别人」之间的取值。
const TEMP_CORE_BATCH_PORT_SHARE_DIVISOR: usize = 32;

/// 单批**节点数**上限（= 该批的 http 入站数 = 回环端口数 = 核的 listener fd 数）。
///
/// 由端口预算算出来，不是拍的：[`TEMP_CORE_EPHEMERAL_PORT_FLOOR`] / [`TEMP_CORE_BATCH_PORT_SHARE_DIVISOR`]。
/// 它同时把「核 fd」「配置 JSON 体积」「宿主 `TempNode` 切片」这几项一起封在常数上
/// （fd ≈ n + 6·m + 常数；配置 ≈ 801 B/节点 ⇒ ≤ 410 KB/批）。
const TEMP_CORE_BATCH_MAX_NODES: usize =
    TEMP_CORE_EPHEMERAL_PORT_FLOOR / TEMP_CORE_BATCH_PORT_SHARE_DIVISOR;

/// 单批临时核的 **RSS 预算**（KB）。
///
/// 256 MB：一个**瞬态**测量核的峰值。宿主 app（Tauri + WebView）自身已在 200–400 MB 量级，再叠一个
/// 常驻不了几分钟的子进程，这是「用户不会察觉」与「批不至于切得太碎」之间的取值。
/// 它与 [`TEMP_CORE_BATCH_ESTIMATE_CAP_MS`] 两条**取严**，见 [`temp_core_batch_max_naive`]。
const TEMP_CORE_BATCH_RSS_BUDGET_KB: u64 = 256 * 1024;

/// 临时核的**基线** RSS（KB，实测：`sing-box check` 0 节点 48 MB）。
const TEMP_CORE_BASE_RSS_KB: u64 = 48 * 1024;

/// 每个节点的边际 RSS（KB，实测：`check` 0→2000 节点的斜率 20 KB/节点）。
const TEMP_CORE_PER_NODE_RSS_KB: u64 = 20;

/// 每个 cronet engine 的边际 RSS（KB，推导 ≈1.3 MB/engine：真机 118 节点/58 naive 满负荷 RSS
/// 131–135 MB 减去 `check(118)` 的 57 MB，除以 58）。
const TEMP_CORE_PER_ENGINE_RSS_KB: u64 = 1_331;

/// 单批 **naive 出站数**（= cronet engine 数）上限 —— 两条预算**取严**。
///
/// ```text
/// ① 时间预算（前端 20s 静默兜底反解）：
///    m ≤ (BATCH_ESTIMATE_CAP − T_fix − c_parse·n_max) / t_engine
///      = (6000 − 90 − 0.105×512) / 41 = 142
/// ② 内存预算：
///    m ≤ (RSS_BUDGET − BASE − per_node·n_max) / per_engine
///      = (262144 − 49152 − 20×512) / 1331 = 152
/// ⇒ m_max = min(142, 152) = 142
/// ```
///
/// 两处都按**最坏的 n**（[`TEMP_CORE_BATCH_MAX_NODES`]）折算 ⇒ 任何 (n ≤ n_max, m ≤ m_max) 的批都
/// 同时满足两条预算（估算与 RSS 对 n、m 都单调）。这条「取严」由门
/// `every_planned_batch_fits_the_frontend_idle_window` 与
/// `every_planned_batch_fits_the_core_memory_budget` 各守一条。
///
/// # 为什么不写成一个字面常量
///
/// 写死一个数 ⇒ 五个输入系数（`T_fix` / `c_parse` / `t_engine` / 安全系数 / 前端 20s）里任何一个被
/// 改，这个数都会静默失配，而失配的表现是「批间空窗超过前端兜底 ⇒ 假的测速中断」——一个不会有人
/// 把它联想到批大小的现象。算出来则系数一改它就跟着走，且门会当场指出是哪一条预算在绑。
const fn temp_core_batch_max_naive() -> usize {
    temp_core_batch_naive_cap(
        TEMP_CORE_BATCH_ESTIMATE_CAP_MS,
        TEMP_CORE_BATCH_RSS_BUDGET_KB,
    )
}

/// [`temp_core_batch_max_naive`] 的**可参数化**内核：两条预算给定时的 naive 上限。
///
/// # 为什么把两条预算提成参数（而不是直接读那两个常量）
///
/// 今天 ① 时间预算（142）比 ② 内存预算（152）紧 ⇒ `min` 恒取 ①，**② 那条腿对最终取值毫无影响**。
/// 直接读常量的写法下，把整条 ② 删掉、结果一字不变 —— 于是「内存预算也在把关」这句话在门上
/// **无法证伪**（复审 2026-09-03 实测：删掉 ② 之后本模块与 UI 两侧的门全绿）。
///
/// 提成参数之后，门可以喂一个「① 被放宽到大于 ②」的输入，断言此刻上限被 ② **钉在 152** ——
/// 删掉 ② 那条腿，这条断言当场红。守的就是
/// `every_planned_batch_fits_the_core_memory_budget` 里那条参数化断言。
///
/// # 这不是为测试而造的形状 —— ② 很快就会变成绑定的那一条
///
/// `t_engine = 41ms` 是**两点回归的推导值**（真值区间 30–45ms，多点实测已排进验收 runbook 的 F 组）。
/// 一旦实测把它下修到 30ms，① 放宽到 `(6000 − 90 − 53) / 30 = 195` > 152 ⇒ **② 立刻接管**。
/// 那时若 ② 已经被人当成「反正没用」删掉，单批峰值 RSS 会从 247 MB 涨到 ~308 MB 而没有任何门会喊。
const fn temp_core_batch_naive_cap(estimate_cap_ms: u64, rss_budget_kb: u64) -> usize {
    let n = TEMP_CORE_BATCH_MAX_NODES as u64;
    // ① 时间预算（前端静默兜底反解）
    // `saturating_sub` 而不是 `-`：仓根 `Cargo.toml` 的 `[profile.release]` 没设
    // `overflow-checks`（Cargo 默认 false）⇒ release 下减出负数会**静默回绕**成一个天文数字，
    // 于是「预算被调得太小」这种改动的表现不是报错而是**上限变成无穷大**。本模块自己的纪律是
    // 「越界要响不要哑」——饱和到 0 会让批被切成一节点一批（明显、可观测），回绕则悄无声息。
    let by_time = estimate_cap_ms
        .saturating_sub(CORE_STARTUP_BASELINE_FIXED_MS)
        .saturating_sub(n * CORE_STARTUP_PER_NODE_US / 1_000)
        / CORE_STARTUP_PER_NAIVE_MS;
    // ② 内存预算
    let by_rss = rss_budget_kb
        .saturating_sub(TEMP_CORE_BASE_RSS_KB)
        .saturating_sub(n * TEMP_CORE_PER_NODE_RSS_KB)
        / TEMP_CORE_PER_ENGINE_RSS_KB;
    if by_time < by_rss {
        by_time as usize
    } else {
        by_rss as usize
    }
}

/// 一轮的可测集 → **规模有界**的批（保序、不丢节点、不重复；空集给空 vec）。
///
/// # 这个函数是「资源 O(1)」的本体
///
/// 分批之前，一轮测速的峰值资源（核 RSS / 线程 / fd / 回环端口 / 配置体积）**全部**随订阅节点数
/// 线性增长 —— 因为一份配置里塞了全部 N 个入站与 N 个出站，其中每个 naive 出站还是一个独立的
/// Chromium Cronet Engine（≈1.3 MB + 2 线程 + 6 fd，且由内核**串行**启动）。分批之后每一批的
/// `(n, m)` 都被两个上限封死 ⇒ **峰值与 N 无关，只有批数与总耗时随 N 线性**。
///
/// # 为什么是贪心装箱而不是定长 `chunks(k)`
///
/// 绑定约束是 **m**（naive 数），不是 n。定长切分要想保住 m 的上界，只能按「每个节点都是 naive」
/// 的最坏情况取 k = m_max ⇒ 一个 2000 节点 0 naive 的订阅会被切成 15 批（真实需要 4 批），白白多
/// 起 11 次核。贪心装箱同时看 n 与 m，两个上限谁先满谁切，零 naive 的订阅按 n_max 切、全 naive 的
/// 按 m_max 切，两头都不浪费。代价是 12 行 stdlib 循环，无新抽象。
///
/// **不复用** `commands::speedtest::plan_waves`：那是主核池的「槽位指派」（把节点分配到 k 个固定
/// 槽上按波热切），与本函数的「切成若干批、每批起一个自己的核」语义不同，强行复用会语义错配。
///
/// # 边界
///
/// 单个节点即便自己就超过某条预算也**照样成批**（`start < i` 的守卫保证批非空）——绝不因为装不下
/// 而丢节点。今天不可能发生（m_max ≥ 1），但这条不变量必须由结构保证，不是由取值保证。
#[must_use]
pub fn plan_temp_core_batches(nodes: &[TempNode]) -> Vec<&[TempNode]> {
    let max_naive = temp_core_batch_max_naive();
    let mut batches: Vec<&[TempNode]> = Vec::new();
    let mut start = 0usize;
    let mut naive = 0usize;
    for (i, node) in nodes.iter().enumerate() {
        let is_naive = temp_core_is_naive(node);
        let would_nodes = i - start + 1;
        let would_naive = naive + usize::from(is_naive);
        if start < i && (would_nodes > TEMP_CORE_BATCH_MAX_NODES || would_naive > max_naive) {
            batches.push(&nodes[start..i]);
            start = i;
            naive = 0;
        }
        naive += usize::from(is_naive);
    }
    if start < nodes.len() {
        batches.push(&nodes[start..]);
    }
    batches
}

/// 本批规模 → 临时核**起核耗时估算**（ms）= 单一真值 [`core_startup_estimate_ms`] 在本腿固定项上的
/// 实例化。
///
/// ```text
/// T_ready(n, m) ≈ 90ms + 0.105ms·n + 41ms·m
///     n = 本批节点数（临时核给每个节点配一个 http inbound）
///     m = 其中 naive 出站数（每个 = 一个独立 Chromium Cronet Engine）
/// ```
///
/// # 系数、分级与「m 主导」的机制都在单一真值那边 —— 改公式前先读那里
///
/// 三个系数的出处与分级（`T_fix` 单点实测 / `t_engine` **两点回归的推导值**、真值区间 30–45ms、多点
/// 实测的测法 / `c_parse` 开发机实测）、以及「sing-box 在入站 bind 之前串行 eager 启动全部出站，naive
/// 出站在这一步同步建 Cronet Engine」这条机制，写在 [`CORE_STARTUP_PER_NAIVE_MS`] /
/// [`CORE_STARTUP_PER_NODE_US`] / [`core_startup_estimate_ms`] 上。多点实测拿到真斜率后改的是**那边**的
/// 常量，本函数与本文件的批上限都跟着走，不必动。
///
/// # 固定项为什么可以直接取 [`CORE_STARTUP_BASELINE_FIXED_MS`]（90ms）
///
/// 那个基线只含「核自己从进程起来到 bind 完成」，不含进程 spawn、不含杀软扫描、不含 rule_set / geo
/// 加载、不含建 TUN、不含 helper 提权 —— 而临时核这几项**一项都不做**（判据见该常量的文档）。主核
/// 每项都做，故主核在调用点自带一个大一个数量级的固定项，两个固定项不是同一个数。
///
/// # 公式失效时往哪个方向偏是安全的（不对称的**本腿表现**）
///
/// 通用判据在 [`CORE_STARTUP_PER_NAIVE_MS`] 的「安全方向」一节：只许偏大，不许在没有多点实测的前提下
/// 收紧。落到本腿上，两个方向的代价是：
///
/// · 估**小**（真机比公式慢：更慢的 CPU、冷盘、杀软逐 engine 扫描、首次加载 cronet 动态库）
///   ⇒ 门太紧 ⇒ 把一个**正在正常启动**的核判成失败并掐死 ⇒ **整批零结果**，且报错说「未就绪」，
///   指向网络/端口而不是规模。这正是本模块要消灭的那个失败面，不能由本模块重新引入；
/// · 估**大** ⇒ 一个真起不来的核多等一会儿才被判死。用户多等几秒，无数据损失、无误诊。
///
/// ⇒ 本腿的两道保护因此都只朝偏大开：[`CORE_READY_SAFETY_FACTOR`]（×2，等价于容忍 `t_engine` 真值到
/// 82ms/engine，约为区间上端 45ms 的 1.8 倍），以及 [`TEMP_CORE_READY_TIMEOUT_FLOOR_MS`]（公式在小批上
/// 无论多离谱都不会把门收得比今天窄）。
fn temp_core_startup_estimate_ms(node_count: usize, naive_count: usize) -> u64 {
    core_startup_estimate_ms(CORE_STARTUP_BASELINE_FIXED_MS, node_count, naive_count)
}

/// 本批规模 → 就绪等待预算（ms）。
///
/// `Ok(ms)` = 门取 `max(估算 × 安全系数, 下限)`；
/// `Err(budget)` = 预算越过 [`TEMP_CORE_READY_TIMEOUT_CAP_MS`]，本批必须**当场拒绝、不起核**
/// （载荷是算出来的预算，供报错原文引用 —— 用户得看见那个数，才知道不是「网络有问题」）。
///
/// 上限判在**乘完安全系数之后、取下限之前**：下限（10s）恒小于上限（60s），故取下限不可能把一个
/// 合法预算顶过上限，两道保护互不干涉。
fn temp_core_ready_timeout_ms(node_count: usize, naive_count: usize) -> Result<u64, u64> {
    let budget = CORE_READY_SAFETY_FACTOR
        .saturating_mul(temp_core_startup_estimate_ms(node_count, naive_count));
    if budget > TEMP_CORE_READY_TIMEOUT_CAP_MS {
        return Err(budget);
    }
    Ok(budget.max(TEMP_CORE_READY_TIMEOUT_FLOOR_MS))
}

/// 给定本批节点数，单核**最多**能带多少个 naive 出站 —— 即越界报错里那个**可执行的数**。
///
/// 只服务一件事：「本批规模超限」不带这个数，用户唯一能做的就是二分猜；带上它，他知道要砍到多少。
///
/// # ⚠️ 分母是**批预算**（12s），不是那条 60s 的拒绝上限 —— 这一条 T1-R1 改过，理由在此
///
/// 改前分母取 `TEMP_CORE_READY_TIMEOUT_CAP_MS / SAFETY` = 30s ⇒ 报出去的数是 **≈727**，
/// 即「恰好还不触发拒绝」的那个 m。分批之后那个数是**有害的**：用户照它把 naive 砍到 727，
/// 单批预算约 30s，**远超前端 20s 的静默兜底**（[`TEMP_CORE_UI_IDLE_TIMEOUT_MS`]）⇒ 他会拿到一条
/// 假的「测速中断」，而现场没有任何东西指向「批太大」。**自曝腿把用户引向了第二个坑。**
///
/// 换成 [`TEMP_CORE_BATCH_READY_BUDGET_CAP_MS`] / SAFETY = 6s 之后，报出去的数与
/// [`temp_core_batch_max_naive`] 同源（同一条时间预算），照它砍下去**这一轮真的能跑通**。
///
/// # 那这条建议在分批之后还算不算「可执行」——算，判据如下
///
/// 越界腿本身在生产上已不可达（见 [`TEMP_CORE_READY_TIMEOUT_CAP_MS`] 的射程说明），能看到它
/// 只有一种情形：**规划器被绕过或回归**。那种情形下用户仍然完全控制得了「本轮选哪些节点」
/// （`server_speed_test` 的 `serverIds`），把本轮 naive 砍到本函数报的数 ⇒ 单批预算落回 12s 内
/// ⇒ 这一轮跑得通。⇒ 建议是**真的可执行**，不是安慰话。
///
/// # 已登记的纯理论 nit（不修）
///
/// `n` 大到 `c_parse` 项自己就吃掉整个预算时（阈值随分母变小而下降到 `n ≥ 56_285`），本函数返回
/// **0**，报错会写「最多带 0 个 naive」—— 一条不可执行的建议。不修的判据不变：那是一个 5.6 万节点
/// 的订阅，比本模块任何一个取样点都高两个数量级，且到达该区间之前 `Err` 腿早已把整批拒掉，
/// 用户看到的仍是「规模超限」这个正确结论，只有末尾那句建议退化。加一条 `max(1)` 会让
/// 「最多带 1 个」同样不可执行，纯属把一个触发不到的分支换个说法。
fn temp_core_max_naive(node_count: usize) -> usize {
    let per_core = TEMP_CORE_BATCH_READY_BUDGET_CAP_MS / CORE_READY_SAFETY_FACTOR;
    let non_engine = temp_core_startup_estimate_ms(node_count, 0);
    usize::try_from(per_core.saturating_sub(non_engine) / CORE_STARTUP_PER_NAIVE_MS)
        .unwrap_or(usize::MAX)
}

/// 越过 [`TEMP_CORE_READY_TIMEOUT_CAP_MS`] 那一批的报错原文。
///
/// # 这句话里每一段都不是装饰
///
/// 用户看到的必须是「**规模**超限」而不是「未就绪（Timeout）」—— 后者指向网络/端口，正是固定 10s 门
/// 在 ~240 个 naive 上给出的那个误诊。故原文按「结论 → 推导输入 → 机制 → 可执行的数 → 下一步」排：
/// 缺任何一段，用户要么不知道是自己节点太多，要么知道了也只能二分猜要砍到多少。
///
/// 单独成函数（而不是内联进 `match` 臂）：`format!` 带续行的长字面量在 `match` 臂里会让 rustfmt 在
/// 两种排布之间反复横跳，`cargo fmt --check` 因此永不稳定。
fn temp_core_oversize_message(node_count: usize, naive_count: usize, budget_ms: u64) -> String {
    format!(
        "测速临时核本批规模超限：{node_count} 个节点含 {naive_count} 个 naive，估算起核 {}ms、\
         就绪预算 {budget_ms}ms 超过上限 {TEMP_CORE_READY_TIMEOUT_CAP_MS}ms，不起核。\
         每个 naive 出站都是一个独立 Cronet Engine 且由内核串行启动，\
         本批节点数下单核最多带 {} 个 naive。请减少本轮 naive 节点数分次测。",
        temp_core_startup_estimate_ms(node_count, naive_count),
        temp_core_max_naive(node_count),
    )
}

/// 本批里的 naive 出站数（= cronet engine 数，[`temp_core_startup_estimate_ms`] 的 `m`）。
///
/// # 为什么从出站 JSON 的 `type` 读，而不是在 [`TempNode`] 上另存一个 `is_naive`
///
/// 建 engine 的判据在**核**那边，它看的就是这份 JSON 的 `type` 字段（`protocol/naive/outbound.go`
/// 由 `type: "naive"` 注册）。读同一个字段 ⇒ 预算的输入与核的实际行为**同源**，不可能漂移；
/// 另存一个布尔标记则会在「协议映射改了、标记没跟着改」时静默失配，而失配的表现正是本模块最难
/// 归因的那一种（门算小了 ⇒ 整批零结果 ⇒ 报错指向网络）。
///
/// # 端点不进计数是**已知的模型盲区**，不是「端点不花时间」
///
/// 早先这里写的是「端点类节点（WG/WARP/mesh）永远不是 naive ⇒ 不进计数」，那句话在**会计上是错的**：
/// 端点确实不建 cronet engine，但它们**在同一条串行启动链上做同步阻塞初始化**。上游 v1.14.0：
/// `adapter/outbound/manager.go:58,77-79` 把 `m.endpoint.Endpoints()` **append 进同一个 outbounds 切片**、
/// 喂给**同一次** `startOutbounds`；`adapter/endpoint/manager.go:44-47` 在 `StartStateStart` 直接
/// `return nil`（注释原文 "started with outbound manager"）。而那一步里 wireguard 端点要建 TUN 设备 +
/// `device.NewDevice` + `IpcSet`（`protocol/wireguard/endpoint.go:139/141`），tailscale 在 PostStart 里
/// `t.server.Start()`（`protocol/tailscale/endpoint.go:402`），tor 在 `Start` 里拉起内嵌进程并轮询
/// （`protocol/tor/outbound.go:119-147`）。
///
/// 而 [`temp_core_startup_estimate_ms`] 对它们一律按 `c_parse` = 0.105ms/节点计 ⇒ **偏差方向是危险的
/// 那一侧（门算小）**。量级需真机实测（与 `t_engine` 同一次多点回归里一并测：造 k 个 WG 端点看
/// `started (Xs)` 的增量），拿到数后要么给端点加一项系数，要么在文档里给出「端点数 ≤ K 时可忽略」的界。
///
/// **它不是本改动引入的**：今天那个固定 10s 门有一模一样的盲区（它对端点同样按 0 计），且 10s 的下限
/// 在小批上把这点误差完全吸收 —— 本改动只是把这个既有盲区**写明**，没有让它变大。
///
/// 附属出站（ShadowTLS 外层）同理不进计数，且它们也不建 engine。
fn temp_core_naive_count(nodes: &[TempNode]) -> usize {
    nodes.iter().filter(|n| temp_core_is_naive(n)).count()
}

/// 单个节点是不是 naive 出站（[`temp_core_naive_count`] 与 [`plan_temp_core_batches`] **共用**的判据）。
///
/// 抽成一个函数而不是在两处各写一遍那个 `get("type")`：预算的输入与分批的输入必须是**同一个**判据，
/// 各写一遍就会在「协议映射改了、只改了一处」时静默分叉 —— 而分叉的表现是「批算得太大 ⇒ 就绪门
/// 算得太小 ⇒ 整批零结果 ⇒ 报错指向网络」，本模块最难归因的那一种。判据本身的出处见
/// [`temp_core_naive_count`]。
fn temp_core_is_naive(node: &TempNode) -> bool {
    node.node.get("type").and_then(Value::as_str) == Some("naive")
}

/// 端口列表 → **定长**日志摘要（`128 个 [20001, 20002, 20003 … 20126, 20127, 20128]`）。
///
/// # 为什么不能直接 `{ports:?}`
///
/// 原文把整个数组 `{:?}` 打进日志，长度**与节点数线性**：N=2000 时是一行约 14 KB，而日志代总量
/// 预算只有 5 MiB（`polaris_log_budget::DEFAULT_GENERATION_BYTES`）。这与本批的就绪门是同一类
/// 缺陷 —— 一个在小规模下无害的写法，在大规模下把别的排障线索挤出轮转窗口。
///
/// 摘要与全量对排查**等价**：端口是内核随机给的（`bind(0)` + `getsockname`），中间那 1994 个逐个
/// 列出来对任何人都没有用；真正会被问到的只有「有几个」和「落在哪一段」。
fn format_ports_for_log(ports: &[u16]) -> String {
    const HEAD: usize = 3;
    const TAIL: usize = 3;
    let n = ports.len();
    if n <= HEAD + TAIL {
        return format!("{n} 个 {ports:?}");
    }
    format!("{n} 个 {:?} … {:?}", &ports[..HEAD], &ports[n - TAIL..])
}

/// 就绪轮询间隔。
const TEMP_CORE_READY_POLL_MS: u64 = 200;

/// **在飞**让位轮询间隔（[`drive_temp_core_measures`] 的检查点②）。
///
/// 只在「发新活之前 / 每节点测完」两处查是不够的：窗口里的节点**全部不可达**时（真机上就是订阅里
/// 有 ≥16 个死节点），那两处一个都醒不过来 —— supersede 信号出现后临时核（及其**已建立的 WG/WARP
/// 会话**）还要活满一整个测量超时。Linux/macOS 靠主核 `start()` 入口的 stale sweep 顺带杀掉——那是
/// **副作用缓解、不是设计保证**；Windows 无 sweep（`scan_running_cores` 恒返空）⇒ 全程重叠。
/// 故按本间隔独立轮询（`timeout(poll, join_next())`，**不依赖任何测量返回**），命中即 `abort_all` +
/// 立即返回（调用方紧接着 `terminate()`）。
const TEMP_CORE_SUPERSEDE_POLL_MS: u64 = 200;

/// **连续判 -1 多少个之后复探一次核**（[`InterruptReason::CoreUnresponsive`] 那条腿的触发阈值）。
///
/// # 取值判据：= 一整个在飞窗口
///
/// 取 [`TEMP_CORE_CONCURRENCY`]（16）而不是一个更小的数：本模块的滑动窗口就是 16 路在飞，而「订阅里
/// 连着有十几个死节点」在真机上是常态（模块文档已登记 ≥16 个死节点的形态）。一整窗全军覆没是**能被
/// 「节点确实不通」解释的最大连败**，再往上就该怀疑是自家的核出了事。
///
/// 阈值取小的代价不是误判（复探成功就继续，什么都不会发生），而是**白花一次 300 ms 的阻塞探测**；
/// 取大的代价是卡死后多烧几个节点的 6 s 硬闸。16 让复探频率封顶在「每 16 个失败一次」，可忽略。
const TEMP_CORE_STALL_STREAK: usize = TEMP_CORE_CONCURRENCY;

/// 临时核配置文件名（**独立于**主核 `singbox-runtime.json`）。
///
/// 固定名而非带时间戳（上游 `speedtest_${Date.now()}.json`）：测速已有进程级单飞闸
/// （`commands::speedtest::SpeedTestGuard`）⇒ 同时至多一个临时核，固定名不会自撞，且上次会话崩溃残留的
/// 那份会被本次直接覆盖（带时间戳反而会在 config 目录里越堆越多）。
const TEMP_CORE_CONFIG_NAME: &str = "speedtest-core.json";

/// 诊断档（`debug` / `trace`）下**留档**的临时核配置文件名（见 [`retire_temp_config`]）。
///
/// 与 [`TEMP_CORE_CONFIG_NAME`] 必须不同名：同名就等于「没删」，下次会话会把它当成自己的配置覆盖，
/// 留档也就没留住。
const TEMP_CORE_LAST_CONFIG_NAME: &str = "speedtest-core.last.json";

/// **在飞临时核 pid 表** —— 应用退出清理的唯一真值源。
///
/// # 为什么光有 child 的 `Drop` 守卫不够
///
/// 临时核 child 由本模块的会话 future 独占持有，`TokioLoginCoreChild` 的 Drop 守卫只覆盖「future 被
/// 丢弃 / panic 展开」。**应用退出**走的是 `RunEvent::ExitRequested → run_exit_cleanup → 进程退出`，
/// 在飞的 tokio task **根本不会被 drop** ⇒ 临时核不随父进程死，留下一个持续持有 N 个回环端口 +
/// WG/WARP peer 会话的孤儿 sing-box。而兜底 sweep 只在**下次** `start()` 才跑，且 Windows 的
/// `scan_running_cores` 恒返空（`core-supervisor/src/stale_core.rs`：`tasklist` 不输出命令行，无从
/// 施加「只杀本 app 起的核」判据）⇒ **Windows 孤儿永不被清**。
///
/// 故在此登记 pid，由 `exit_lifecycle::run_exit_cleanup` 经 [`kill_inflight_temp_cores`] 收口。
static INFLIGHT_TEMP_CORES: Mutex<BTreeSet<u32>> = Mutex::new(BTreeSet::new());

/// 取 pid 表锁（临界区极短、绝不跨 await；中毒仍恢复内层，不为一条清理路径 panic 掉退出流程）。
///
/// **模块私有**：`MutexGuard` 经 `DerefMut` 交出的是整张表的**可变**引用（`insert` / `remove` /
/// `mem::take` 全在射程内），那是登记守卫与退出清理才需要的档。跨模块的消费者
/// （[`ProxyRuntime::sweep_exclusions`](crate::runtime::proxy::ProxyRuntime) 的孤儿清扫排除表）
/// 只要一份**只读快照** ⇒ 走 [`inflight_temp_core_pids`]，可变句柄不出模块。
///
/// # ⚠️ 这**不是**「测速是否在跑」的判据
///
/// 表里有没有 pid 只回答一件事：**此刻有没有一个已 spawn、尚未收割的临时核进程**。它的射程是
/// [`TempCorePidGuard`] 的生存期（spawn → terminate 收割），比「一轮测速」窄两头：
/// - 一轮测速里**没有任何可测节点**（全部被 ts/dirty/协议前置过滤掉）时压根不起临时核 ⇒ 表恒空，
///   而测速确实在跑；
/// - 走**主核在跑**那条腿的测速（不起临时核，直接用主核出站）同样全程不入表。
///
/// 故 `!temp_core_pids().is_empty()` 当成「测速在飞」会两头错（漏判在飞、也可能在收核后误判已停）。
/// 要问「测速是否在跑」用 `commands::speedtest` 的单飞闩（`SpeedTestGuard`），那才是那件事的真值源。
fn temp_core_pids() -> MutexGuard<'static, BTreeSet<u32>> {
    INFLIGHT_TEMP_CORES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// **此刻在飞**的测速临时核 pid 快照 —— `ProxyRuntime::cleanup_stale_cores` 排除表的来源之一。
///
/// 与登录核那条腿的 `LoginCoreRegistry::inflight_login_pids` 同形：临界区只做一次拷贝、绝不跨
/// await，调用方拿到的是**快照而不是表**。射程（以及「这不是『测速是否在跑』的判据」）见
/// [`temp_core_pids`]。
pub(crate) fn inflight_temp_core_pids() -> Vec<u32> {
    temp_core_pids().iter().copied().collect()
}

/// pid 表是**进程级**共享状态 ⇒ 触碰它的用例必须串行，否则彼此排空对方的登记。
///
/// 锁放在**表边上**（生产模块内 `cfg(test)`）而不是某一个 tests 模块里：消费者已有两处
/// （本模块的退出清理、`proxy` 的孤儿清扫排除表），两边的用例必须串行到**同一把**锁上。
/// 锁若跟着测试文件走就会分叉成两把，而两把锁等于没有锁。
///
/// # ⚠️ 本项是 `speedtest.rs` 里**第一个** `#[cfg(test)]`，位置比原先靠前 93 行
///
/// 本仓存在一族「按**第一个** `#[cfg(test)]` 截断取材」的扫描判据，共 **4 条**：
/// `crates/unlock-transport/src/tests/mod.rs`、`crates/config-engine/src/builder/orchestration/tests/mod.rs`
/// （两条都是 `.split("#[cfg(test)]").next()`）、
/// `crates/helper-client/src/connector/tests/windows_source_contract_tests.rs`（`.split("\n#[cfg(test)]")`）、
/// `crates/updater/src/popup/tests/mod.rs`（`.find("\n#[cfg(test)]\n")`）。
/// 另有 2 条切的是「**锚点之后**的第一个 `#[cfg(test)]`」（`crates/helper-client/src/manager/tests/mod.rs`、
/// `runtime/proxy/tests/process_supervision.rs`）——它们对首锚位置免疫，不属这一族。
///
/// 本文件的首个 `#[cfg(test)]` 原先在文件中段（:299），本批把它提到了这里（:206）—— **今天无实害**：
/// 上面 6 条一条都没落在 `speedtest.rs` 上；`speedtest.rs` 自己的三个源码型消费者
/// （`speedtest/tests/mod.rs` 的 `production_deps_reuse_the_main_core_binary_resolver` /
/// `temp_core_wires_both_streams_into_its_own_target_at_spawn_time` /
/// `drive_after_spawn_no_longer_touches_the_pipes`）全走 `impl_method_body` 按签名锚点取材、
/// 不做首锚截断（已逐条核过）。
///
/// 但坑往前挪了：将来若有人给 `speedtest.rs` 加一条首锚截断型判据，它的取材面会从「文件前 299 行」
/// 缩成「前 206 行」，而**判据不会喊**（切片非空、断言照跑）。给 `speedtest.rs` 写扫描型门时锚点
/// 请落在具体签名上，别落在 `#[cfg(test)]`。
#[cfg(test)]
static TEMP_CORE_REGISTRY_LOCK: Mutex<()> = Mutex::new(());

/// 取 [`TEMP_CORE_REGISTRY_LOCK`]（测试串行闸，见其文档）。
#[cfg(test)]
pub(crate) fn registry_guard() -> MutexGuard<'static, ()> {
    TEMP_CORE_REGISTRY_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// 排空 pid 表（**不发任何信号**）。退出清理与单测共用同一个真值源 —— 单测只走本函数即可观测
/// 注册/注销，绝不对真实进程发信号（本仓禁在单测里碰宿主进程/网络）。
fn take_inflight_temp_core_pids() -> Vec<u32> {
    std::mem::take(&mut *temp_core_pids()).into_iter().collect()
}

/// **应用退出清理**：SIGKILL 掉全部在飞临时核，返回实际发信号条数（0 = 退出时没有测速在飞）。
///
/// 直接 SIGKILL 不走 SIGTERM 宽限：退出路径不能再等一个 5s 宽限窗；临时核无状态（配置随后即删、
/// 不写主核任何生命周期槽），强杀无副作用。
pub fn kill_inflight_temp_cores() -> usize {
    kill_temp_cores_with(|pid| send_signal(pid, Signal::Sigkill))
}

/// [`kill_inflight_temp_cores`] 的可注入内核（**收割动作是唯一注入点**）：单测传记录闭包驱动整条
/// 「排空 → 逐 pid 收割 → 计数」逻辑，**不对任何真实进程发信号**（本仓禁在单测里碰宿主进程）。
fn kill_temp_cores_with(mut kill: impl FnMut(u32)) -> usize {
    let pids = take_inflight_temp_core_pids();
    for pid in &pids {
        log::warn!("退出清理：强杀在飞测速临时核 pid={pid}");
        kill(*pid);
    }
    pids.len()
}

/// pid 登记 RAII 守卫：`drive_after_spawn` 的每一条 return / panic 展开 / future 被丢弃都会注销，
/// 故表里只会留下**此刻真在飞**的 pid（退出清理据此发信号，pid 复用误杀窗口被压到最小）。
///
/// `pub(crate)`：`proxy` 的孤儿清扫排除表行为门也用它来构造「临时核正在飞」这个状态。**测试必须走
/// 本守卫而不是手写 `insert`/`remove` 一对**——手写的那对在断言之间，任一断言先失败就把 pid 永久
/// 留在这张进程级表里，污染同进程后续用例（今天没人断言「表必须为空」，所以只是隐患，不是当下缺陷）。
pub(crate) struct TempCorePidGuard(u32);

impl TempCorePidGuard {
    /// 登记一个 pid；`pid == 0`（取不到 pid / 测试假核）→ 不登记（返 `None`）。
    pub(crate) fn register(pid: u32) -> Option<Self> {
        (pid != 0).then(|| {
            temp_core_pids().insert(pid);
            Self(pid)
        })
    }
}

impl Drop for TempCorePidGuard {
    fn drop(&mut self) {
        temp_core_pids().remove(&self.0);
    }
}

/// 临时核**入站→出站** 1:1 绑定的一个节点（[`plan_temp_core_with_bindings`] 产出，[`build_temp_core_config`] 消费）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TempNode {
    /// 节点 id（结果回填键 + `event:speedTestResult` 的 serverId）。
    pub id: String,
    /// 临时核内的出站/端点 tag（`out-<id 前 8 位>`，见 [`temp_core_tag`]）。
    pub tag: String,
    /// 预构造的出站（普通协议）或端点（WG / 自定义 endpoint）JSON。
    pub node: Value,
    /// 主出站依赖的附属出站。当前用于 ShadowTLS 外层；它才负责公网拨号和承接网卡绑定。
    pub companion_outbounds: Vec<Value>,
    /// 是否走 `endpoints[]`（L3 端点，须额外配穿隧道 DNS，见 [`build_temp_core_config`]）。
    pub is_endpoint: bool,
    /// WG 本地地址含 IPv6（端点 DNS 族别偏好的分流，对齐 上游 `:868`）。
    ///
    /// 纯 v4 ⇒ 给该入站前置一条 AAAA `predefined` 空答复（等价旧 `ipv4_only`）；
    /// 含 v6 ⇒ 不下发任何东西（等价旧 `prefer_ipv4`，见 [`build_temp_core_config`]）。
    pub has_local_v6: bool,
}

/// 节点**没能进临时核**的具体成因。
///
/// # 为什么不能继续折成一个笼统列表
///
/// 形态与判据照同链路的 [`TsNotReady`](crate::commands::speedtest) 写：那条腿的教训是「四种成因共用
/// 一句话」把用户支去做白工（管理后台显示已登录、应用却让他反复登录）。本腿的旧形态是
/// `unusable: Vec<String>`，把「naive 缺 cronet」与「构造失败」压成同一个 id 列表 —— 用户看到的只有
/// 「N 个节点未纳入」，日志里同样只有 id。于是「某协议在测速链路上被静默剔除」这类缺陷**没有任何
/// 地方会自曝**：两条缺席腿（`plan_temp_core_with_bindings` 的协议预筛、`build_temp_node` 的构造
/// 失败）在盘面上长得一模一样。带上原因后，那类问题在日志汇总里当场现形。
///
/// 响应字段 `notInPool` **仍只回 id**（跨语言契约不动）：对用户「本轮没测」是同一件事，成因是排查
/// 材料、不是渲染材料。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnusableReason {
    /// 协议是 naive，但本机没有 cronet 动态库 —— 放进核会 FATAL 拖垮**整批**，故预筛掉。
    NaiveWithoutCronet,
    /// 出站/端点构造失败。载荷 = **卡在哪一步**（WG 缺 privateKey / 自定义 JSON 形态非法 / …），
    /// 它是「为什么这个节点每次都缺席」的唯一线索。
    BuildFailed(&'static str),
}

/// [`plan_temp_core_with_bindings`] 的产出：可测节点（保序）+ 各原因的缺席列表（保序）。
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TempCorePlan {
    /// 进临时核真测的节点。
    pub testable: Vec<TempNode>,
    /// 因协议是 tailscale 而缺席（回报进响应的 `tsNotReady`，对齐 上游 L-2 `:248-250`）。
    pub tailscale: Vec<String>,
    /// 因 naive 缺 cronet / 构造失败而缺席（回报进响应的 `notInPool`：对用户同样是「本轮没测」），
    /// 各自带上成因（见 [`UnusableReason`]）。
    pub unusable: Vec<(String, UnusableReason)>,
}

/// 临时核里某节点的 **基础** tag（对齐 上游 `out-${s.id.slice(0, 8)}`，`:443`）。
///
/// 取 id 前 8 位而非全 id：sing-box tag 只需在**本临时核内**唯一，而 id 是 uuid ⇒ 前 8 位碰撞概率可忽略，
/// 短 tag 让核日志与 DNS 规则可读。**碰撞真发生时**由 [`unique_temp_core_tag`] 加序号消歧，绝不生成两个
/// 同 tag 的出站（那会让核启动直接 FATAL、整批测不成）。
#[must_use]
pub fn temp_core_tag(id: &str) -> String {
    let head: String = id.chars().take(8).collect();
    format!("out-{head}")
}

/// 在 `taken` 之外取一个唯一 tag：基础 tag 空着就用它，否则加序号（`out-xxxxxxxx-2`、`-3`…）。
///
/// # 为什么不是「后来者出局」
///
/// id **不保证是 uuid**：手输/导入的节点常见 `mynode-a1` / `mynode-a2` 这种前缀相同的命名，前 8 位
/// 逐字相同 ⇒ 碰撞不是「概率可忽略」而是**确定性**发生。旧的去重腿把后来者整个丢进 `unusable`，
/// 用户侧表现是那个节点**每次**都以笼统的 `notInPool` 缺席、且无从修复（他不知道要去改 id 前 8 位）。
/// 消歧后两个节点各有独立入站/出站/DNS 规则，照常各测各的。
///
/// `taken` 有限 ⇒ 循环必然终止。
fn unique_temp_core_tag(id: &str, taken: &BTreeSet<String>) -> String {
    let base = temp_core_tag(id);
    if !taken.contains(&base) {
        return base;
    }
    let mut n = 2usize;
    loop {
        let candidate = format!("{base}-{n}");
        if !taken.contains(&candidate) {
            return candidate;
        }
        n += 1;
    }
}

/// 把请求集裁成「进临时核的节点」+「缺席列表」（纯逻辑，对齐 上游 `:438-450` 的 `usable` 循环）。
///
/// 判定序（每一条都对应一个真实的整批失败面，顺序不可换）：
/// 1. **tailscale → 缺席**：临时核建不出第二个 tsnet 实例；即便建得出，它与主核共用 `tailscale-state`
///    目录，两个核同写必然把登录态写坏。这条**必须在构造之前**判 —— 构造它本身就要落状态目录。
/// 2. **naive 且无 cronet → 缺席**：进核会 FATAL 拖垮**整批**（不是只坏它自己）。
/// 3. **tag 消歧**：同 tag 两个出站 ⇒ 核启动 FATAL。id 前 8 位碰撞时加序号
///    （[`unique_temp_core_tag`]），**不丢节点**。
/// 4. **构造失败 → 缺席**：WG 缺 privateKey / 自定义 JSON 形态非法。绝不放一个半截出站进核。
#[cfg(test)]
#[must_use]
pub fn plan_temp_core(servers: &[ServerConfig], env: &CoreBuildEnv) -> TempCorePlan {
    plan_temp_core_with_bindings(servers, env, &BTreeMap::new())
}

/// `plan_temp_core` + 用户显式配置的节点/订阅/全局代理出口绑定。
///
/// 临时核只在主核停止时运行，不需要 TUN 启动前的按目的路由推导；但显式策略属于用户配置，测速路径
/// 必须与真实连接一致。映射只按节点 id 取值，空值继续交给操作系统逐目的选路。
#[must_use]
pub fn plan_temp_core_with_bindings(
    servers: &[ServerConfig],
    env: &CoreBuildEnv,
    bind_interfaces: &BTreeMap<String, String>,
) -> TempCorePlan {
    let mut out = TempCorePlan::default();
    let mut seen_tags: BTreeSet<String> = BTreeSet::new();
    for s in servers {
        if s.protocol == Protocol::Tailscale {
            out.tailscale.push(s.id.clone());
            continue;
        }
        if s.protocol == Protocol::Naive && !env.has_cronet {
            out.unusable
                .push((s.id.clone(), UnusableReason::NaiveWithoutCronet));
            continue;
        }
        let tag = unique_temp_core_tag(&s.id, &seen_tags);
        seen_tags.insert(tag.clone());
        match build_temp_node(s, &tag, env, bind_interfaces.get(&s.id).map(String::as_str)) {
            Ok(node) => out.testable.push(node),
            Err(step) => {
                // tag 已占坑但节点没建成 → 归还，免得后一个真能建成的同 tag 节点被误判成碰撞。
                seen_tags.remove(&tag);
                out.unusable
                    .push((s.id.clone(), UnusableReason::BuildFailed(step)));
            }
        }
    }
    log_unusable_summary(&out.unusable);
    out
}

/// 缺席节点的**按原因汇总**日志（唯一出口，[`plan_temp_core_with_bindings`] 收尾调一次）。
///
/// 全量列 id 在 116 节点的订阅上是一行几 KB，而排查只需要「是不是集中在某一类」——故只报两类计数
/// 加前 5 个带原因的样本，与 [`log_speed_test_summary`] 的取样口径同源。
///
/// 级别取 `warn`：真机常态 `logLevel=info`（`warn` 及以上才落盘的场景另说），而「某些节点每轮都不
/// 被测」正是用户会来问、且此前磁盘上零线索的那一类。
fn log_unusable_summary(unusable: &[(String, UnusableReason)]) {
    if unusable.is_empty() {
        return;
    }
    let naive = unusable
        .iter()
        .filter(|(_, r)| matches!(r, UnusableReason::NaiveWithoutCronet))
        .count();
    let samples: Vec<String> = unusable
        .iter()
        .take(5)
        .map(|(id, reason)| format!("{id}={reason:?}"))
        .collect();
    log::warn!(
        "临时核测速缺席 {} 个节点：naive 缺 cronet {naive}，构造失败 {}；样本 {}",
        unusable.len(),
        unusable.len() - naive,
        samples.join(", ")
    );
}

/// 单节点的出站/端点构造（复用 config-engine 的 20 协议字段映射，**不在本层重写任何协议细节**）。
///
/// `domain_resolver` 一律指向临时核自己的 `dns-direct`（223.5.5.5）—— 那是**节点 server 地址**的解析器，
/// 与「目标域名怎么解析」是两回事（见 [`build_temp_core_config`] 的两类解析不变量）。
///
/// 失败返 `Err(卡在哪一步)`（进 [`UnusableReason::BuildFailed`]）而不是裸 `None`：这些步骤失败的原因
/// 各不相同（协议设置缺失 / 上游 builder 拒绝 / 序列化 / 网卡绑定注入），而它们在盘面上此前长得
/// 完全一样 —— 用户只看到「这个节点每次都不被测」，日志里连它卡在哪一步都没有。
fn build_temp_node(
    s: &ServerConfig,
    tag: &str,
    env: &CoreBuildEnv,
    bind_interface: Option<&str>,
) -> Result<TempNode, &'static str> {
    let is_custom_endpoint = s.protocol == Protocol::Custom
        && s.custom_settings
            .as_ref()
            .and_then(|c| c.is_endpoint)
            .unwrap_or(false);

    if s.protocol == Protocol::Wireguard {
        // detour 恒传 `None`：临时测速核只装被测节点自己 + `dns-direct`，前置代理那个 outbound
        // 压根不在这份配置里 —— 填了就是指向不存在的 tag ⇒ FATAL。判据同下面自定义 endpoint 腿的
        // `obj.remove("detour")`（那条注释写的就是这件事），两条腿口径一致。
        // 代价：带前置代理的 WG 节点，测得的是**直连**该 peer 的速度，不是经链路的速度。
        // dial 侧解析器传**纯 tag**，不是 #335 的结构化 `{server, strategy}` 形态：那条缺陷的根因是
        // 「顶层 `dns.strategy=ipv4_only` 连带压掉节点域名的 AAAA」，而临时测速核**恒不下发顶层
        // `dns.strategy`**（见下方 `build_temp_core_config` 的不变量注释，变异锁单测
        // `temp_core_dns_never_sets_a_legacy_or_top_level_strategy` 断言 1.16 DNS 旧形态为空，
        // 且 `dns.strategy` 必须缺席）
        // ⇒ 这份配置里没有可覆盖的顶层策略，下发结构化形态属无据的行为变更。
        let ep = build_wireguard_endpoint(
            s,
            tag,
            Some(&DomainResolver::Tag(DIRECT_DNS_TAG.to_string())),
            &env.platform,
            None,
        )
        .map_err(|_| "wireguard 端点构造")?;
        let has_local_v6 = s
            .wireguard_settings
            .as_ref()
            .is_some_and(|w| w.local_address.iter().any(|a| a.contains(':')));
        let mut node = serde_json::to_value(ep).map_err(|_| "wireguard 端点序列化")?;
        set_bind_interface(&mut node, bind_interface).ok_or("wireguard 端点网卡绑定")?;
        return Ok(TempNode {
            id: s.id.clone(),
            tag: tag.to_string(),
            node,
            companion_outbounds: Vec::new(),
            is_endpoint: true,
            has_local_v6,
        });
    }

    if matches!(s.protocol, Protocol::Openconnect | Protocol::OpenvpnClient) {
        let has_settings = match s.protocol {
            Protocol::Openconnect => s.openconnect_settings.is_some(),
            Protocol::OpenvpnClient => s.openvpn_client_settings.is_some(),
            _ => unreachable!("protocol was guarded above"),
        };
        if !has_settings {
            return Err("vpn-client 协议设置缺失");
        }
        let endpoint = build_vpn_client_endpoint(
            s,
            tag,
            Some(&DomainResolver::Tag(DIRECT_DNS_TAG.to_string())),
        )
        .map_err(|_| "vpn-client 端点构造")?;
        let mut node = serde_json::to_value(endpoint).map_err(|_| "vpn-client 端点序列化")?;
        set_bind_interface(&mut node, bind_interface).ok_or("vpn-client 端点网卡绑定")?;
        return Ok(TempNode {
            id: s.id.clone(),
            tag: tag.to_string(),
            node,
            companion_outbounds: Vec::new(),
            is_endpoint: true,
            has_local_v6: false,
        });
    }

    if is_custom_endpoint {
        // 自定义 endpoint：原样透传用户 JSON，仅覆盖 tag、剥内层 detour（对齐 config-engine
        // `build_outbounds` 的自定义 endpoint 腿；detour 在临时核里指向不存在的 tag 会 FATAL）。
        let mut val = s
            .custom_settings
            .as_ref()
            .ok_or("自定义 endpoint 设置缺失")?
            .outbound
            .clone();
        let obj = val.as_object_mut().ok_or("自定义 endpoint JSON 非对象")?;
        obj.remove("detour");
        obj.insert("tag".into(), Value::from(tag));
        set_bind_interface(&mut val, bind_interface).ok_or("自定义 endpoint 网卡绑定")?;
        return Ok(TempNode {
            id: s.id.clone(),
            tag: tag.to_string(),
            node: val,
            companion_outbounds: Vec::new(),
            is_endpoint: true,
            has_local_v6: false,
        });
    }

    // 纯 tag 而非 #335 的结构化形态，理由同上面 WG 那条腿（临时核无顶层 `dns.strategy` 可覆盖）。
    let ob = build_proxy_outbound(
        s,
        tag,
        &DomainResolver::Tag(DIRECT_DNS_TAG.to_string()),
        &env.arch,
        &env.platform,
    );
    // **detour 一律剥掉**：临时核只装被测节点自己，链式前置节点的 tag 在核里根本不存在 ⇒ 留着必 FATAL。
    // 代价是「代理链节点测的是它自己那一跳」——如实、且与旧行为（根本测不了）相比只增不减。
    let mut val = serde_json::to_value(ob).map_err(|_| "出站序列化")?;
    let obj = val.as_object_mut().ok_or("出站 JSON 非对象")?;
    obj.remove("detour");
    let mut companion_outbounds = Vec::new();
    if let Some(outer) = build_shadow_tls_outbound(s, bind_interface) {
        obj.remove("bind_interface");
        obj.insert("detour".into(), Value::from(outer.tag.clone()));
        companion_outbounds.push(serde_json::to_value(outer).map_err(|_| "ShadowTLS 外层序列化")?);
    } else {
        set_bind_interface(&mut val, bind_interface).ok_or("出站网卡绑定")?;
    }
    Ok(TempNode {
        id: s.id.clone(),
        tag: tag.to_string(),
        node: val,
        companion_outbounds,
        is_endpoint: false,
        has_local_v6: false,
    })
}

fn set_bind_interface(node: &mut Value, bind_interface: Option<&str>) -> Option<()> {
    let object = node.as_object_mut()?;
    if let Some(interface) = bind_interface
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        object.insert("bind_interface".into(), Value::from(interface));
    } else {
        object.remove("bind_interface");
    }
    Some(())
}

/// 临时核里解析**节点 server 地址**用的 DNS server tag（223.5.5.5，本机直发）。
const DIRECT_DNS_TAG: &str = "dns-direct";

/// 生成临时核 sing-box 配置（纯逻辑，1:1 上游 `generateProxyTestConfig`，`:808-890`）。
///
/// 形状：每个可测节点一个 `http` 入站（`127.0.0.1:<port>`）→ `route.rules` 按 `inbound` 指到该节点 tag。
/// 端点类节点另进 `endpoints[]`，普通协议进 `outbounds[]`。
///
/// # 两类解析不变量（上游 issue #154 + 2026-07 端点修正，真机 debug 确证 —— 勿动）
///
/// - **代理出站**（vless/vmess/trojan/hy2/tuic/ss/…）：目标域名以 `ATYP=domain` **透传给出口远程解析**，
///   不经本机 `dns-direct`。各节点因此量到自身真实路径。⚠️ 勿引入 `sniff` / `outbound.domain_strategy` /
///   任何针对**目标**的本地解析 —— 会破坏此不变量，把所有节点测成同一条本机解析路径。
/// - **端点**（WG/WARP… L3）：内核**强制本地解析**目标域名。默认 `dns-direct` 从**本机**解析 ⇒ 拿到的是
///   本机地理的 IP，而端点出口可能在别处（境外 WARP / 国内自建 WG）⇒ 够不着 → 超时/失真。故按 `inbound`
///   键控一条 DNS 规则，把该端点的目标解析定向到**穿本隧道**的 223.5.5.5（AliDNS 有大陆 PoP + ECS，
///   按**出口地理**返 IP，境内外单形态覆盖）。`disable_cache` 必开：多端点并测时各自的答案不同，共享缓存
///   会互相污染。
///
/// `ports[i]` 与 `nodes[i]` **逐位 1:1**（调用方保证等长；短了则多出的节点不生成入站 —— 由
/// [`TempCoreSession::run`] 的等长断言挡在生成之前）。
#[must_use]
pub fn build_temp_core_config(nodes: &[TempNode], ports: &[u16], log_level: &str) -> Value {
    let mut inbounds = Vec::new();
    let mut outbounds = Vec::new();
    let mut endpoints = Vec::new();
    let mut route_rules = Vec::new();
    let mut dns_servers = vec![json!({
        "tag": DIRECT_DNS_TAG, "type": "udp", "server": "223.5.5.5", "server_port": 53,
    })];
    let mut dns_rules: Vec<Value> = Vec::new();

    for (node, port) in nodes.iter().zip(ports.iter()) {
        let inbound_tag = format!("in-{}", node.tag);
        inbounds.push(json!({
            "type": "http", "tag": inbound_tag, "listen": "127.0.0.1", "listen_port": port,
        }));
        route_rules.push(json!({
            "inbound": [inbound_tag], "action": "route", "outbound": node.tag,
        }));
        if node.is_endpoint {
            let exit_dns_tag = format!("dns-exit-{}", node.tag);
            dns_servers.push(json!({
                "tag": exit_dns_tag, "type": "udp", "server": "223.5.5.5", "server_port": 53,
                // 查询穿本端点隧道 → AliDNS 按出口地理（ECS）返 IP。
                // ⚠️ 端点级 `domain_resolver` 只管 peer 地址，**禁**指向隧道 DNS（peer 解析死锁 FATAL，实测）。
                "detour": node.tag,
            }));
            // 族别偏好（语义不变，写法迁移；1:1 上游 `0875f66`(#334)，`SpeedTestService.ts:850-881`）。
            //
            // **为什么不能留 legacy rule-action `strategy`**：sing-box 1.14.0 起 ① `run` 输出 deprecation
            // 警告、**1.16.0 移除**（`check` 静默放行 ⇒ 我们起核前那道 `sing-box check` 抓不到）；
            // ② 它与**同一份 dns 配置内**任何带 `query_type`/`ip_version` 的规则**互斥**，共存即
            // `initialize dns router` FATAL、`check` 与 `run` 双双硬拒。下方纯 v4 端点恰好明确下发
            // `query_type: ["AAAA"]`，故任何规则复活 `strategy` 都会让整批测速起核 FATAL。
            //
            //  · 旧 `prefer_ipv4`（localAddress 含 v6）→ **不下发任何东西**：本配置无顶层 `dns.strategy`
            //    （见下方 `dns` 组装），内核默认并发 A/AAAA 且把 v4 排在 v6 前（`sortAddresses` 对
            //    AsIS 与 prefer_ipv4 同一分支）。⚠️ 该等价性**依赖测速配置不带顶层 dns.strategy**，
            //    由 `temp_core_dns_never_sets_a_legacy_or_top_level_strategy` 锁死。
            //  · 旧 `ipv4_only`（纯 v4）→ 给该 inbound 的 AAAA 查询前置一条 `predefined` 空 NOERROR：
            //    AAAA 就地返空、不出网，结果集只剩 A。
            //
            // 顺序有牙：抑制规则必须排在本节点 route 规则**之前** —— DNS 规则先匹配先命中，route 规则是
            // 该 inbound 的 catch-all，排它后面则 AAAA 先被 route 吃掉、抑制静默失效（且配置照样过校验）。
            if !node.has_local_v6 {
                dns_rules.push(json!({
                    "inbound": [inbound_tag], "query_type": ["AAAA"],
                    // 空答复：等价旧 ipv4_only 的「不要 v6」，且不触发拒绝日志噪声。
                    "action": "predefined", "rcode": "NOERROR",
                }));
            }
            dns_rules.push(json!({
                "inbound": [inbound_tag], "action": "route", "server": exit_dns_tag,
                "disable_cache": true,
            }));
            endpoints.push(node.node.clone());
        } else {
            outbounds.push(node.node.clone());
            outbounds.extend(node.companion_outbounds.iter().cloned());
        }
    }

    // sing-box 启动要求至少一个 direct 出站（也是 DNS 直发腿的落点）。
    outbounds.push(json!({ "type": "direct", "tag": "direct" }));

    // ⚠️ **恒不下发顶层 `dns.strategy`**：端点族别偏好靠上面的 `query_type` 规则项表达，而「无顶层
    // strategy」正是「省略 == 旧 prefer_ipv4」这条等价性的前提（顶层若为 prefer_ipv6，端点解析会翻成
    // v6 优先）。要加顶层 strategy 必须同时重新推导端点规则，别只加一半。单测锁死本不变量。
    let mut dns = json!({ "servers": dns_servers });
    if !dns_rules.is_empty() {
        dns["rules"] = Value::Array(dns_rules);
    }
    let mut cfg = json!({
        "log": { "level": log_level, "timestamp": true },
        "dns": dns,
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {
            "rules": route_rules,
            "default_domain_resolver": DIRECT_DNS_TAG,
        },
    });
    if !endpoints.is_empty() {
        cfg["endpoints"] = Value::Array(endpoints);
    }
    cfg
}

/// **临时核让位判据**（纯逻辑；[`crate::commands::speedtest`] 的 `is_superseded` 的镜像腿）。
///
/// 三条腿的**析取**，缺一不可 —— 且后两条与主核路径**方向相反**，这不是笔误：
/// - `gen_now != gen0`：主核 start/stop/restart/regen 跃迁 ⇒ 主核来了，临时核必须让路；
/// - `running`：主核**已经跑起来了**。世代腿盖不住的窗口是「bump 发生在本次取 `gen0` **之前**」——
///   那一刻 `status.running` 还是 false（核在启动中），我们照常起了临时核；随后核就绪，`running` 翻真
///   而世代不再变化。只查世代 ⇒ 两个核并存跑同一批 WG/WARP peer（上游 G1 双会话事故的形态）。
/// - `starting`：**前两条腿都盖不住的那整段启动期**。`ProxyRuntime::start` 的顺序是
///   `start_inflight+1`（`starting` 的源）→ **stale 清扫（可达数秒）** → `bump_generation` → spawn →
///   就绪门。若本次测速的 `gen0` 恰好取在「bump 之后、核就绪之前」，世代腿与 `running` 腿**同时**为假，
///   而主核正在起：用户点「连接」后紧接点测速（或托盘/另一窗口点，UI 灰态拦不住跨窗）就是确定性命中。
///   后果有两层：① 临时核与启动中的主核并存 ⇒ 同 peer 双会话踢线；② 临时核端口只排除
///   control/http/mixed，会抢走主核刚解析、尚未 bind 的 api/update-in/probe 池口 ⇒ 主核起核
///   FATAL address-in-use（用户看到的是「连接失败」，归因极难）。
///
/// 主核池路径的第二条腿是 `!running`（守的是「核崩了」），本腿是 `running`/`starting`（守的是「核来了」）
/// —— 因为两条腿的**前提**相反：那边跑在核活着的前提上，这边跑在核不在的前提上。
#[must_use]
pub const fn is_temp_core_superseded(
    gen_now: u64,
    gen0: u64,
    running: bool,
    starting: bool,
) -> bool {
    gen_now != gen0 || running || starting
}

/// **临时核测量编排核**（测量 / 事件发射 / 让位三个 I/O 面**全部注入** ⇒ 无 `AppHandle`、无进程、
/// 不碰宿主网络、可单测）。
///
/// # 调度形态：**滑动窗口**（≤`concurrency` 在飞，回来一个补一个）
///
/// = 上游 `runWithLimit`（`SpeedTestService.ts:1331-1344`，调用点 `:530`）的固定 worker 池。
/// 此前是**批屏障**（切成 16 个一批、整批 join 完才发下一批），两者的 makespan 差 W = ⌈N/K⌉ 倍：
///
/// - worker 池的下界是 `max(单点最坏, 总功/并发)` —— 一个测不通的死节点只占住 1/K 的算力；
/// - 批屏障是 `Σ 每批最大值` —— 一个死节点把**整批 K 个**的耗时钉死在超时上限。
///
/// 而「每批至少一个死节点」的概率 = `1-(1-f)^K`，f=0.2、K=16 时是 **0.97** —— 即中等失效率的订阅
/// 几乎每一批都被超时值封顶。N=50/K=16/f=0.2 的模型：批屏障 4 批 × 8s = 32s，滑动窗口
/// `max(8, 40×0.5+10×8 /16) = 8s`。
///
/// # 让位（**这段是本函数的事故面，改前先读完**）
///
/// 主核和临时核**绝不能同时跑**：同一个 WG/WARP peer 被两个会话同时握手会互相踢线，且临时核端口
/// 只排除 control/http/mixed，会抢走主核尚未 bind 的口 ⇒ 主核起核 FATAL。所以「主核来了就立刻停」
/// 不是优化，是**正确性**。三个检查点覆盖全程，缺一即静默重叠：
///
/// 1. **发新活之前**（每轮补位一次）：主核已起 → 停发新活 + `abort_all` 已在飞的，未测节点缺席。
///    这条替代了旧的「批首」检查，粒度**更细**：旧的是每 K 个节点一次，现在是每次补位一次。
/// 2. **在飞轮询**（每 [`TEMP_CORE_SUPERSEDE_POLL_MS`] 一次）：命中即 `abort_all` + 立刻返回。
///    **这条是唯一不依赖任何测量返回的腿** —— 窗口里 16 个全挂死（真机上就是 16 个不可达节点）时，
///    上面两条都醒不过来，只有它按间隔醒。批屏障时代它挂在「批内」，现在挂在整轮，覆盖面只增不减：
///    以前批与批之间那一小段没有轮询（靠批首查兜），现在全程都在轮询窗口里。
///    实现仍用 `timeout(poll, join_next())` 而非 `select!`：`join_next()` 已借走 `set`，`select!` 的
///    另一臂里再调 `set.abort_all()` 会撞借用检查；`join_next` 是 cancel-safe（tokio 文档明载），
///    超时丢弃不丢结果。
/// 3. **每节点测完**：该节点的测量在飞期间主核起来 ⇒ 这个值量的是**与主核抢同一条 peer 会话**的
///    临时核出站，丢弃（并中止其余在飞）。
///
/// 收尾（杀核）由调用方 [`TempCoreSession`] 的**无条件**路径负责，不在本函数。
///
/// **未测节点一律缺席，绝不写假 `-1`** —— 「让位未测」与「真实超时」不可混淆，同主核路径的诚实性根基。
/// 返回 `(结果 map, outcome)`；任一检查点命中即 `interrupted`。
///
/// # 回填粒度：**逐节点**（对齐 上游 `SpeedTestService.ts:564`）
///
/// 每个节点测完那一刻就落账 + 推事件。统一回填的话首个延迟数字要等最慢的那个，屏幕先空十几秒。
/// 代价：让位③是「逐节点级」—— 已回填的不可撤回，丢弃的只是尚未回来的在飞值。这正是 上游的语义
/// （`:541-545` 的超代再检也在 worker 体内、`report()` 之前）。
///
/// # 为什么主核池路径**不**跟着改
///
/// 那边的槽 ↔ 端口是 1:1 硬绑定，跨波复用同槽必须先测完再重指，波屏障是**正确性要求**而非性能选择
/// （上游 同样是波屏障，`SpeedTestService.ts:709-776`）。本腿没有这个约束：每个节点有**自己**的
/// 入站端口，全程不复用。
/// # 终态事件的唯一出口在**轮**级，不在本函数（T1-R1 分批之后上移了一层）
///
/// 内核 [`drive_temp_core_measures_inner`] 有 4 个 `return`（让位三检查点 + 正常收尾），本薄壳把它们
/// 收成一个出口、把成因交给 [`RoundProgress::note_interrupt`]；[`EVENT_SPEED_TEST_DONE`] 由
/// [`TempCoreSession::run`] 的**唯一**出口发一次。
///
/// 上移的理由是结构性的：分批之后本函数一轮会跑 k 次，留在这里就是 k 条终态事件 —— 而前端收到第一条
/// 就把 sticky 收口了（`reduceSpeedTestDone`），后面 k−1 批的进度再也没有归宿。「唯一出口」这条
/// 不变量没有被放宽，只是搬到了**它现在唯一成立的那一层**：一轮 = 一条终态。
/// 载荷含未测集合（续测输入），判据见 [`emit_speed_test_done`]。
/// 测量循环的**核观测面**（A3 两条腿的入参束）。
///
/// 两条腿必须都在：受控实验实测到的形态是「核卡死但进程还活着」（`State=S`、`alive_after=true`），
/// 只看退出会全盲；而只看端口响应又抓不到「核干脆退出了」（那时端口连不上只是结果之一，
/// 且 `wait()` 能立刻给出确定答案）。
pub struct TempCoreWatch<'a> {
    /// 核 pid（**仅日志用**）。假核 / 取不到 → 0。
    pub pid: u32,
    /// 腿一：`child.wait()` 的 future。**只建一次、反复 poll**（cancel-safe，见 `LoginCoreChild::wait`
    /// 的 trait 文档）。测试传 `Box::pin(std::future::pending())` = 「这个核不会自己死」。
    pub exited: Pin<Box<dyn Future<Output = ()> + Send + 'a>>,
    /// 腿二：端口复探（生产 = [`TempCoreDeps::probe_port`]，即就绪门用的那条
    /// `TcpStream::connect_timeout(300ms)`；**同一个判据，零新增**）。返回 `true` = 核仍在接受连接。
    pub probe_port: Arc<dyn Fn(u16) -> bool + Send + Sync>,
    /// 复探目标端口（= `ports[0]`，与就绪门同一个口）。
    pub port: u16,
}

/// 一**轮**测速（可能跨多批）的进度账 —— 进度事件的口径持有者。
///
/// # 为什么进度必须是轮级的，不能是批级的
///
/// 前端 `reduceSpeedTestProgress` 在 `tested >= total` 那一帧就**收口**（`live: false` + 弹一条
/// 「测速完成」）。若每批各报各的 `total`，批 1 测完那一刻前端就会看到 `152/152` ⇒ 当场弹「测速完成」，
/// 随后批 2 的事件又把 sticky 重新拉起来 —— 一轮测速里连弹 k 条「完成」。⇒ `total` 恒为**本轮全部
/// 批次的可测节点总数**，`tested`/`ok` 跨批累加。**「批」是实现细节，不进用户可见的口径。**
///
/// 它同时持有本轮的**中断成因**：成因产生在批级（某一批的核退出/无响应/让位），而消费它的终态事件
/// 在轮级唯一出口发（见 [`TempCoreSession::run`]），中间必须有个地方存。
pub struct RoundProgress {
    /// 本轮全部批次的可测节点总数（进度事件与终态事件的 `total`，恒全局）。
    total: usize,
    /// 已出值节点数（含真实 `-1`），跨批累加 ⇒ 恒单调。
    tested: usize,
    /// 其中测出有效延迟的个数，跨批累加。
    ok: usize,
    /// 本轮第一个中断成因（[`Self::note_interrupt`] 的取舍规则见其文档）。
    reason: Option<InterruptReason>,
}

impl RoundProgress {
    /// 开一轮的账。`total` = 本轮**全部批次**的可测节点数。
    #[must_use]
    pub const fn new(total: usize) -> Self {
        Self {
            total,
            tested: 0,
            ok: 0,
            reason: None,
        }
    }

    /// 已出值节点数。
    ///
    /// 它同时是「**前端的静默兜底定时器此刻是否已布防**」的判据：前端只在收到进度事件之后才布防
    /// （`armIdle` 在 `state.live` 为假时早退），而本腿的进度事件只由 [`record_measured`] 发 ⇒
    /// `tested == 0` ⟺ 本轮一条进度事件都没出去 ⟺ 前端没有任何定时器在跑。心跳的发射判据就挂在
    /// 这上面（见 [`TempCoreSession::run`]）。
    #[must_use]
    pub const fn tested(&self) -> usize {
        self.tested
    }

    /// 落一个节点的账（[`record_measured`] 专用；`Some` 计进 `ok`）。
    fn record(&mut self, latency: Option<u32>) {
        self.tested += 1;
        if latency.is_some() {
            self.ok += 1;
        }
    }

    /// 当前进度的事件载荷。
    fn payload(&self) -> Value {
        json!({ "tested": self.tested, "ok": self.ok, "total": self.total })
    }

    /// 发一条 [`EVENT_SPEED_TEST_PROGRESS`]，内容 = 此刻**轮级**的账。
    ///
    /// # 三个调用点，两种语义（名字必须中立）
    ///
    /// 本方法**不叫 `heartbeat`**：它的三个调用点里只有两个是心跳。
    ///
    /// · [`record_measured`]：某个节点刚出值 —— 这是**真进度**，与 `event:speedTestResult` 成对；
    /// · [`TempCoreSession::run`] 的批首、[`TempCoreSession::run_batch`] 的就绪之后：内容与上一帧
    ///   逐字相同、不带新数据 —— 这才是**心跳**，用途是把前端那个「两条进度事件之间静默 20s
    ///   ⇒ 判为中断」的兜底定时器**重新起算**，好让批间那段没有测量结果的空窗
    ///   （收核 → check → spawn → 就绪门）不被误判成中断。
    ///
    /// 把方法名写成 `heartbeat` 会让读到 `record_measured` 的人以为逐节点进度也是心跳（反过来
    /// 也一样），而这两者对「进度到底动没动」的含义完全相反。心跳复用同一个通道
    /// （不新起事件通道）：对前端这就是「还在测，进度没变」，reducer 与 toast 一行都不用改。
    fn emit_progress(&self, emit: &mut (dyn FnMut(&str, Value) + Send)) {
        emit(EVENT_SPEED_TEST_PROGRESS, self.payload());
    }

    /// 登记一个中断成因。
    ///
    /// **[`InterruptReason::Superseded`] 覆盖一切，其余取第一个**：让位是唯一会终止整轮的成因
    /// （主核来了，后面的批一个都不该起），它必须能盖过前面某一批留下的核退出/无响应；反过来，
    /// 已经让位了再被别的成因改写就会把「去主核重测」这条正确指引换成「去看日志」。
    /// 其余两种成因下一轮仍在继续（批死不连坐），第一个才是最接近根因的那个。
    fn note_interrupt(&mut self, reason: InterruptReason) {
        if reason == InterruptReason::Superseded || self.reason.is_none() {
            self.reason = Some(reason);
        }
    }

    /// 本轮登记到的中断成因。
    #[must_use]
    pub const fn reason(&self) -> Option<InterruptReason> {
        self.reason
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn drive_temp_core_measures<Meas, MeasFut>(
    nodes: &[TempNode],
    ports: &[u16],
    concurrency: usize,
    superseded: &(dyn Fn() -> bool + Sync),
    watch: &mut TempCoreWatch<'_>,
    measure: Meas,
    emit: &mut (dyn FnMut(&str, Value) + Send),
    progress: &mut RoundProgress,
) -> (serde_json::Map<String, Value>, &'static str)
where
    Meas: Fn(u16) -> MeasFut,
    MeasFut: Future<Output = Option<u32>> + Send + 'static,
{
    // `results` 由**本薄壳**持有：内核的每一条中断腿（含 `select!` 的核退出臂）都要能把「已落账的那些」
    // 交出来，而返回值持有的话，中断臂那一刻还没有返回值可交。
    let mut results = serde_json::Map::new();
    let reason = drive_temp_core_measures_inner(
        &mut results,
        nodes,
        ports,
        concurrency,
        superseded,
        watch,
        measure,
        emit,
        progress,
    )
    .await;
    // outcome **由 reason 派生**，不是各腿各写一个字面量 ⇒「说自己 interrupted 却给不出成因」
    // 在结构上写不出来。
    let outcome = if let Some(reason) = reason {
        // 成因交给轮级的账保管：终态事件在**轮**的唯一出口发（见 [`TempCoreSession::run`]），
        // 那时本函数早已返回。
        progress.note_interrupt(reason);
        "interrupted"
    } else {
        "completed"
    };
    (results, outcome)
}

#[allow(clippy::too_many_arguments)]
async fn drive_temp_core_measures_inner<Meas, MeasFut>(
    results: &mut serde_json::Map<String, Value>,
    nodes: &[TempNode],
    ports: &[u16],
    concurrency: usize,
    superseded: &(dyn Fn() -> bool + Sync),
    watch: &mut TempCoreWatch<'_>,
    measure: Meas,
    emit: &mut (dyn FnMut(&str, Value) + Send),
    progress: &mut RoundProgress,
) -> Option<InterruptReason>
where
    Meas: Fn(u16) -> MeasFut,
    MeasFut: Future<Output = Option<u32>> + Send + 'static,
{
    // `total` 是**本批**的调度上界（`nodes`/`ports` 逐位 1:1，多出的一侧不测）——它只管这个循环该
    // 派多少活。事件里那个 `total` 是**轮**级的，由 [`RoundProgress`] 持有，两者不是一回事：
    // 把批级的数发出去，前端会在每一批测完时都收口一次（判据见 `RoundProgress` 的文档）。
    let total = nodes.len().min(ports.len());
    // 连续判 -1 的计数（满 `TEMP_CORE_STALL_STREAK` 即复探核；测出值即清零）。
    let mut failure_streak = 0usize;

    // `concurrency == 0` → 视作 1：绝不退化成「一个都不测」（那会零事件 ⇒ 前端测速按钮永久卡灰）。
    // 0 并发是配置错误，不是「不测」的意思。
    let window = concurrency.max(1);
    let mut set = tokio::task::JoinSet::new();
    let mut next = 0usize; // 下一个待发的节点下标（ports/nodes 逐位 1:1，全程不复用）

    while !set.is_empty() || next < total {
        if next < total {
            // ── 让位①（发新活之前）：主核已起/已跃迁 → 停发新活 + 中止在飞，未测节点缺席 ──
            if superseded() {
                set.abort_all();
                return Some(InterruptReason::Superseded);
            }
            // 补位：起手补满窗口，此后回来一个补一个。
            while next < total && set.len() < window {
                let node_id = nodes[next].id.clone();
                let fut = measure(ports[next]);
                set.spawn(async move { (node_id, fut.await) });
                next += 1;
            }
        }

        let poll = Duration::from_millis(TEMP_CORE_SUPERSEDE_POLL_MS);
        // ── A3 腿一（核**已死**）：`select!` on `child.wait()` ──
        //
        // 形态照抄同文件同 trait 的生产先例（`tailscale_login_core::supervise` 的
        // `() = child.wait() => break ExitReason::SelfExit`）。**不用 `pid_alive` 轮询**：未 reap 的
        // 死核是僵尸，`kill(pid, 0)` 对僵尸返回成功 ⇒ 轮询腿在最需要它的时刻恒盲。`wait()` 是
        // cancel-safe（trait 文档明载，生产实现即 tokio `Child::wait`），此处更进一步——future 只建
        // 一次、反复 poll，连重建都不发生。
        //
        // 另一臂 `timeout(poll, join_next())` 的 cancel-safety 与改前同源（`join_next` cancel-safe，
        // tokio 文档明载；超时丢弃不丢结果）。
        //
        // # `biased` 不是风格选择，是正确性要求
        //
        // 核崩溃时**内核先关掉它的全部 socket**（`exit_files`），**随后**父进程才可能 reap 到它。
        // 于是在飞的 `open_tunnel`（`speedtest_tunnel.rs` 的 `.ok()?`）立刻返 `None`，与 `exited`
        // 在**同一 tick** 就绪。`select!` 默认随机取臂 ⇒ 有一半概率先走 join 臂，把这个「核死了」
        // 造成的失败当成节点的真实超时落成 `-1` 并推 `event:speedTestResult`；循环顶再派下一个节点
        // 又立刻 ECONNREFUSED，一直到 `exited` 臂被抽中为止。这些 id 因为**已经进了 `results`**，
        // 不会出现在 DONE 的 `pending` 里 ⇒ 用户点「继续剩余」会**跳过**它们。
        // `biased` 把退出臂钉在前面：同一次 poll 里两者都就绪时，恒定先认「核死了」。
        //
        // ⚠️ **平台射程**：Linux 上 tokio 的 unix reaper 在每次 poll 都 `try_wait()`，僵尸态即命中，
        // 故 `biased` 足以覆盖这条竞态。macOS / Windows 的 reap 时序与此不同，`biased` 在那两个平台
        // 上**是否同样足够属未验证**（需真机）——落账前那次复查是它们的兜底。
        let joined = tokio::select! {
            biased;
            () = &mut watch.exited => {
                set.abort_all();
                log::error!(
                    "测速临时核异常退出：pid={}，已出值 {}/{total}，检测到退出之后未出值的节点本轮缺席；核侧日志见 target={SPEEDTEST_CORE_TARGET}",
                    watch.pid,
                    results.len()
                );
                return Some(InterruptReason::CoreExited);
            }
            joined = tokio::time::timeout(poll, set.join_next()) => joined,
        };
        match joined {
            // 窗口已空且无待发（上面刚补过位）⇒ 全部收尾。
            Ok(None) => break,
            Ok(Some(Ok((id, latency)))) => {
                // ── 让位③（每节点测完即查）──
                if superseded() {
                    set.abort_all();
                    return Some(InterruptReason::Superseded);
                }
                if latency.is_some() {
                    failure_streak = 0;
                } else {
                    // ── 落账前对核再探一次（`biased` 的兜底）──
                    //
                    // `biased` 管的是「同一次 select poll 里两者都就绪」。它管不到的是：join 臂在
                    // 更早一次 poll 就已经把结果取走、核的退出**随后**才可观测（多线程 runtime、
                    // 或 macOS/Windows 上不同的 reap 时序）。此时这个 `None` 同样是核死造成的，
                    // 落成 `-1` 就是替一个好节点背锅、且它还进不了 `pending`。
                    //
                    // 只在**失败**那一支探：成功的值是核活着时量出来的真数据，核随后死了也不影响它。
                    // 探到即返回，故不会出现「对已 Ready 的 future 再次 poll」。
                    let exited_now = std::future::poll_fn(|cx| {
                        std::task::Poll::Ready(Pin::new(&mut watch.exited).poll(cx).is_ready())
                    })
                    .await;
                    if exited_now {
                        set.abort_all();
                        log::error!(
                            "测速临时核已退出（落账前复查命中）：pid={}，已出值 {}/{total}，含本次在内的未出值节点一律缺席；核侧日志见 target={SPEEDTEST_CORE_TARGET}",
                            watch.pid,
                            results.len()
                        );
                        return Some(InterruptReason::CoreExited);
                    }
                    failure_streak += 1;
                }
                record_measured(results, progress, emit, &id, latency);

                // ── A3 腿二（核**不再接受连接**）：连败满一窗 → 对 `ports[0]` 复探一次 ──
                //
                // 腿一抓不到这一类：受控实验实测核被堵死时 `State=S`、`alive_after=true`，进程好端端
                // 活着，`child.wait()` 永不返回。判据换成「核还响不响应」——复用**就绪门那条一模一样的
                // 判据**（`deps.probe_port` = `TcpStream::connect_timeout(127.0.0.1:ports[0], 300ms)`），
                // 零新增。
                if failure_streak >= TEMP_CORE_STALL_STREAK {
                    // 无论复探结果如何都清零：探过一次就重新起算，把复探频率封顶在「每 N 个失败一次」。
                    failure_streak = 0;
                    let probe = Arc::clone(&watch.probe_port);
                    let port = watch.port;
                    // `spawn_blocking` 与就绪门逐字同法：探测是阻塞 syscall，直接在 runtime 线程上
                    // 跑会把 300 ms 摊到所有在飞测量头上。`JoinError` → 判不响应（同就绪门的
                    // `unwrap_or(false)`；它只在 runtime 关停时发生，那时本轮本来也已经死了）。
                    let responding = tokio::task::spawn_blocking(move || probe(port))
                        .await
                        .unwrap_or(false);
                    if !responding {
                        set.abort_all();
                        log::error!(
                            "测速临时核连续 {TEMP_CORE_STALL_STREAK} 个节点判 -1 且复探 127.0.0.1:{port} 无响应：pid={}，已出值 {}/{total}，本轮就地终止（检测到之后未出值的节点一律缺席；此前那一整窗的 -1 同样可能是核致的，见 `InterruptReason::CoreUnresponsive` 的射程说明）；核侧日志见 target={SPEEDTEST_CORE_TARGET}",
                            watch.pid,
                            results.len()
                        );
                        return Some(InterruptReason::CoreUnresponsive);
                    }
                }
            }
            // JoinError（panic / 本函数自己 abort 掉的）→ 该节点无数值，缺席，绝不补 -1。
            Ok(Some(Err(_))) => {}
            // ── 让位②（在飞轮询）：**不依赖任何测量返回**，窗口全挂死时也照样醒 ──
            Err(_elapsed) => {
                if superseded() {
                    set.abort_all();
                    return Some(InterruptReason::Superseded);
                }
            }
        }
    }

    None
}

/// 单个节点的落账 + 推事件（`result` 与 `progress` 成对，计数在此处自增 ⇒ 恒单调）。
///
/// 与主核池路径 [`crate::commands::speedtest`] 的同名函数逐字同义 —— 两条腿的事件形状必须一致，
/// 前端 `use-latency-store` / `NodesScreen` 只有一套消费逻辑。
///
/// `latency == None` ⇒ 记 -1（**真实**不可测：超时 / 传输错）。「让位未测」的节点根本不会走到这里。
fn record_measured(
    results: &mut serde_json::Map<String, Value>,
    progress: &mut RoundProgress,
    emit: &mut (dyn FnMut(&str, Value) + Send),
    node_id: &str,
    latency: Option<u32>,
) {
    let latency_val = latency.map_or(-1_i64, i64::from);
    if latency.is_none() {
        log::debug!(
            "临时核测速未取得有效延迟：nodeId={node_id}（可能为冷建链/复用请求超时、传输错误或测速端点非 2xx）"
        );
    }
    results.insert(node_id.to_string(), json!(latency_val));
    emit(
        EVENT_SPEED_TEST_RESULT,
        json!({ "serverId": node_id, "latency": latency_val }),
    );
    // 计数与口径都由**轮**级的账持有（跨批累加、`total` 恒全局）：批级计数一旦出到事件里，
    // 前端会在每批测完那一帧收口（判据见 [`RoundProgress`]）。
    progress.record(latency);
    progress.emit_progress(emit);
}

/// 一轮测速被**中断**的具体成因（`outcome` 之外的第三分量）。
///
/// # 为什么 `outcome` 保持二值、成因另开一个可选字段
///
/// `interrupted` 的既有语义是「有入参节点缺席，保留旧值不写假 -1」——这对下面三种成因**逐字成立**，
/// 前端的续测/重测动作也原样适用。新增第三个 `outcome` 取值要动跨语言镜像类型
/// `SpeedTestOutcome`（invoke 返回 / DONE 事件 / toast reducer 三处消费），收益只是把一个字段拆成
/// 两个。故 `outcome` 不动，成因走 DONE 载荷的可选 `reason`。
///
/// # 为什么「缺席」必须再分
///
/// 改前 absent 只有「让位」一种解释（[`SpeedTestSummary`] 的三分），于是「核死了/核卡死」这两类只能
/// 伪装成让位，或者更糟——被翻译成一批**真实的 -1**（等于伪造 N 次测量，说这些节点不通）。三者对
/// 用户的下一步动作完全不同：让位 = 主核接管了，去主核重测；核退出/无响应 = 本机测速核出事了，
/// 日志里 `target=speedtest-core` 那段有核自己的最后几行。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptReason {
    /// 主核起来了/已跃迁 → 临时核让路（三个让位检查点，语义与主核池路径逐字相同）。
    Superseded,
    /// 核在测量期间**自己退出**了（`select!` on `child.wait()` 命中，或落账前那次复查命中）。
    ///
    /// **射程如实说**：「未出值节点缺席、绝不写假 -1」只在**检测点之后**成立。核崩溃时内核先关它的
    /// socket、随后才可 reap，两者之间在飞的拨号会真实失败；`biased` + 落账前复查把这个窗口压到
    /// 「同一次 poll 内」，但压不到零 —— 检测点**之前**已经落账的 `-1` 保留不撤回（同让位③
    /// 「已回填的不可撤回」）。⚠️ macOS / Windows 的 reap 时序与 Linux 不同，这两条守卫在那两个平台
    /// 上的覆盖程度**未验证**（真机验收项）。
    CoreExited,
    /// 核**不再接受连接**：连续 [`TEMP_CORE_STALL_STREAK`] 个节点判 -1 之后，对 `ports[0]` 的
    /// 带超时 CONNECT 复探也失败。
    ///
    /// **射程如实说**：触发本判据的那一整窗 `-1` 同样可能是核致的（它们已落账、不撤回）。本枚举
    /// 只保证**检测点之后**的节点缺席而不是被写成 `-1`。
    ///
    /// ⚠️ **这条腿的射程如实登记**：复探失败是「核确实不再接受连接」的强证据，但复探**成功不证明
    /// 核没卡住** —— 内核 backlog 会替一个不再 `accept()` 的进程完成 TCP 三次握手。2026-09-02 受控
    /// 实验里核被管道堵死时，81/95 个失败正是卡在 CONNECT 报文阶段（TCP 已连上）。故本腿只抓得到
    /// 「核不再 listen / 已消失」那一类，抓不到「listen 着但线程全堵住」那一类；后者的证据由 A1 的
    /// 排空腿从根上消掉（那才是那条形态的根治），本腿是兜底而非替代。
    CoreUnresponsive,
}

impl InterruptReason {
    /// DONE 载荷 `reason` 的线上字面量（前端 `SpeedTestDonePayload.reason` 逐字消费）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Superseded => "superseded",
            Self::CoreExited => "core_exited",
            Self::CoreUnresponsive => "core_unresponsive",
        }
    }
}

/// 一轮测速的结果口径三分（供 [`log_speed_test_summary`]；纯函数，可单测）。
///
/// **`-1` 与「缺席」是两件不同的事，混起来就没法排查**：
/// - `ok`：真测出了值（毫秒 ≥ 0）；
/// - `failed`：真测了但没通（`-1` —— 超时 / 传输错 / 非 2xx，见 `measure_via_local_proxy`）；
/// - `absent`：**根本没测**（波前让位 / 中断 / 起测即知不可测）——绝不写假 `-1`，故不在 `results` 里。
///
/// `absent` 再由 `absent_reason` 分开（这就是「四分」的第四类）：让位 / 核退出 / 核无响应对用户的
/// 下一步动作完全不同，见 [`InterruptReason`]。`None` = 本轮没被中断（`absent` 若非零，来源是波前
/// 预筛那几类「起测即知不可测」，不是中断）。
///
/// 非数值 / 越界的值一律计入 `failed`（宁可报多也不静默丢：这一层不该有非数值，出现即是缺陷信号）。
#[derive(Debug, PartialEq, Eq)]
pub struct SpeedTestSummary {
    pub ok: usize,
    pub failed: usize,
    pub absent: usize,
    pub absent_reason: Option<InterruptReason>,
}

#[must_use]
pub fn summarize_speed_test(
    results: &serde_json::Map<String, Value>,
    intended: &[String],
    absent: usize,
    absent_reason: Option<InterruptReason>,
) -> SpeedTestSummary {
    let ok = results
        .values()
        .filter(|v| v.as_i64().is_some_and(|ms| ms >= 0))
        .count();
    SpeedTestSummary {
        ok,
        failed: results.len() - ok,
        absent,
        absent_reason,
    }
    .also_assert_total(intended.len())
}

impl SpeedTestSummary {
    /// 三类之和必须等于请求数 —— 不等即口径漏了一类（debug 构型下当场炸，release 只记警告）。
    fn also_assert_total(self, total: usize) -> Self {
        let sum = self.ok + self.failed + self.absent;
        debug_assert_eq!(sum, total, "测速结果三分之和必须等于请求数");
        if sum != total {
            log::warn!("测速结果口径不自洽：ok+failed+absent={sum} ≠ 请求 {total}（{self:?}）");
        }
        self
    }
}

/// 一轮测速的**结果级**日志（唯一出口，三条腿共用 —— 挂在 [`emit_speed_test_done`] 里）。
///
/// # 这条补的是什么洞
///
/// 本链此前**零结果级日志**：机器上只有「测速临时核已 spawn：126 个节点」和「已回收：
/// outcome=completed」两行，中间什么都没有。陈先生 2026-08-02 报「全部测速全部显示 -1，跟实际不符」
/// 时，磁盘上拿不出任何东西能分辨三种完全不同的成因 ——
/// ① 网络真的全失败；② 本轮被让位/中断（节点根本没测，前端把**缺席**画成了 `-1`）；
/// ③ 少数失败但 UI 全渲染成 `-1`。`latency` 又不落 `config.json`（纯渲染端 map），
/// 事后无从复盘。汇总一行即可把三者分开。
///
/// 失败样本只带前 5 个 id：全量在 126 节点时是一行几 KB 的日志，而排查只需要「是不是集中在某一类」。
fn log_speed_test_summary(
    outcome: &str,
    results: &serde_json::Map<String, Value>,
    intended: &[String],
    pending: &[&String],
    reason: Option<InterruptReason>,
) {
    let s = summarize_speed_test(results, intended, pending.len(), reason);
    let samples: Vec<&str> = results
        .iter()
        .filter(|(_, v)| !v.as_i64().is_some_and(|ms| ms >= 0))
        .map(|(k, _)| k.as_str())
        .take(5)
        .collect();
    let tail = if samples.is_empty() {
        String::new()
    } else {
        format!("；失败样本 {}", samples.join(", "))
    };
    // 缺席成因进汇总行：此前这里只写「未测（让位或中断）N」，而那个「或」正是排查时要分开的那一刀。
    let why = s.absent_reason.map_or("", InterruptReason::as_str);
    log::info!(
        "测速一轮完成：outcome={outcome}，reason={why}，请求 {}，成功 {}，超时/失败 {}，未测 {}{tail}",
        intended.len(),
        s.ok,
        s.failed,
        s.absent
    );
}

/// 一轮测速的**终态事件**（[`EVENT_SPEED_TEST_DONE`]）——三条腿各自在**唯一出口**调一次。
///
/// # 为什么放在这里、并且只有一个调用点/腿
///
/// 三条腿（主核池 [`crate::commands::speedtest`]、回退腿、临时核腿）各有 2~4 个 `return`
/// （让位检查点 + 正常收尾）。逐个 `return` 前手动 emit 必然漏 —— 漏掉的那条正是「中断」路径，
/// 而中断恰恰是本事件唯一不可替代的用途。故三条腿一律改成「内核函数照旧多点 return + 薄壳在
/// 唯一出口调本函数」，漏发在结构上写不出来。
///
/// `intended` = 本腿**已裁定要测**的节点 id（波前预筛之后的可测集）。据此派生三个字段：
///  - `total` = `intended.len()`（与该腿进度事件里的 `total` 同一口径，两者失配会让前端的
///    `tested/total` 与终态对不上）；
///  - `tested` = `results.len()`（已出值的，含真实 `-1`）；
///  - `serverIds` = `intended`（本轮原始可测范围，= 中断后「重新测速」的输入）；
///  - `pending` = `intended − results`（**没拿到值**的，= 中断后「继续剩余」的输入）。
///
/// 判据与「差集为什么必须由后端算 / 波前缺席的三类为什么不算 pending」见
/// [`EVENT_SPEED_TEST_DONE`] 的常量文档。
pub fn emit_speed_test_done(
    emit: &mut (dyn FnMut(&str, Value) + Send),
    outcome: &str,
    results: &serde_json::Map<String, Value>,
    intended: &[String],
    reason: Option<InterruptReason>,
) {
    // 「缺席即未测」——复用既有诚实性根基（让位未测的节点根本不进 `results`，绝不写假 -1）。
    let pending: Vec<&String> = intended
        .iter()
        .filter(|id| !results.contains_key(id.as_str()))
        .collect();
    log_speed_test_summary(outcome, results, intended, &pending, reason);
    let mut payload = json!({
        "outcome": outcome,
        "tested": results.len(),
        "total": intended.len(),
        "serverIds": intended,
        "pending": pending,
    });
    // `reason` 是**可选**字段：`completed` 不带它（前端 `reason?`），故这里按 `Option` 决定发不发，
    // 而不是发一个 `null` —— 后者会让「旧后端没这字段」与「本轮没有成因」在前端长得一样。
    if let Some(reason) = reason {
        payload["reason"] = Value::from(reason.as_str());
    }
    emit(EVENT_SPEED_TEST_DONE, payload);
}

// ══════════════════════════════════════════════════════════════════════════════
//  生产接线：起临时核 → 就绪门 → 编排 → 无条件收尾。全部 I/O 经注入点，测试用 mock 驱动。
// ══════════════════════════════════════════════════════════════════════════════

/// 临时核会话的注入依赖（生产 [`TempCoreDeps::production`]，测试注入 mock spawner / 假核路径）。
pub struct TempCoreDeps {
    /// 瞬态 sing-box spawn（复用 `tailscale_login_core` 的瞬态核进程抽象）。
    pub spawner: Arc<dyn LoginCoreSpawner>,
    /// spawn 前的 `sing-box check`（fail-fast，复用瞬态登录核那条已建好的抽象）。
    ///
    /// **不是洁癖**：临时核配置里唯一不由本仓完全掌控的部分是 `custom` 协议的**用户原样 JSON**。它形态
    /// 非法时核会预初始化 FATAL、立即退出，而没有这道 check 的话，用户看到的是就绪门那句「N ms 内未监听」
    /// —— 把「你那个自定义节点的 JSON 写错了」误报成「网络/端口有问题」，且白等整个就绪预算
    /// （[`temp_core_ready_timeout_ms`]，大批 naive 时可达数十秒）。
    pub checker: Arc<dyn ConfigChecker>,
    /// 核二进制解析（生产 = `resolve_core_binary`，与主核**同一份**解析逻辑，禁重复实现）。
    pub resolve_binary: Arc<dyn Fn() -> Result<PathBuf, String> + Send + Sync>,
    /// 临时配置落盘目录（= 主核 config 目录；文件名另用 [`TEMP_CORE_CONFIG_NAME`]，绝不同名）。
    pub config_dir: PathBuf,
    /// 端口分配（生产 = `PortAllocator` + `TokioPortProvider`；测试注入确定性序列）。
    pub allocate_ports: Arc<dyn Fn(usize) -> Vec<u16> + Send + Sync>,
    /// 就绪探测：能连上 `127.0.0.1:<port>` ⇒ 临时核已开始 listen。
    pub probe_port: Arc<dyn Fn(u16) -> bool + Send + Sync>,
    /// 核日志级别（跟随用户配置；诊断态调高时临时核一并抬级，便于复现）。
    pub log_level: String,
    /// 就绪等待上限的**覆写**：`None` = 生产口径，按本批规模现算
    /// （[`temp_core_ready_timeout_ms`]）；`Some(ms)` 只给测试用，免得 gate 空等一个真实超时。
    ///
    /// 生产恒 `None` 是本改动的**要点本身**：门是规模的函数，不再是一个常数。任何把它写成
    /// `Some(<定值>)` 的改动都会被 `production_ready_gate_is_scale_derived_not_a_constant` 拦下。
    pub ready_timeout_override_ms: Option<u64>,
}

impl TempCoreDeps {
    /// 生产装配：真 spawn + 真核解析 + 真端口分配 + 真 TCP 就绪探测。
    ///
    /// `exclusions` = 用户配置的 control/http/mixed 口 —— **必须排除**，否则临时核占了主核随后要 bind
    /// 的口，用户测完速再点连接就起不来（表现为「测速把代理搞坏了」，归因极难）。
    #[must_use]
    pub fn production(config_dir: PathBuf, exclusions: PortExclusions, log_level: String) -> Self {
        Self {
            spawner: Arc::new(TokioLoginCoreSpawner),
            checker: Arc::new(SingBoxConfigChecker),
            resolve_binary: Arc::new(crate::runtime::proxy::resolve_core_binary),
            config_dir,
            allocate_ports: Arc::new(move |n| {
                PortAllocator::new(TokioPortProvider).resolve_distinct_free_ports(&exclusions, n)
            }),
            probe_port: Arc::new(|port| {
                std::net::TcpStream::connect_timeout(
                    &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
                    Duration::from_millis(300),
                )
                .is_ok()
            }),
            log_level,
            ready_timeout_override_ms: None,
        }
    }
}

/// 一次临时核测速的结局（命令层折成响应信封）。
#[derive(Debug)]
pub enum TempCoreOutcome {
    /// 跑完了（可能部分节点 `-1` = 真实不可测）。`outcome` 同主核路径语义。
    Ran {
        results: serde_json::Map<String, Value>,
        outcome: &'static str,
    },
    /// 起核前/就绪前失败（解析不到核 / 端口分配失败 / 写配置失败 / spawn 失败 / 未就绪）。
    /// **整批一个数值都不产出**（绝不把「核没起来」写成一批 `-1`）。
    Failed(String),
    /// 本批规模越过 [`TEMP_CORE_READY_TIMEOUT_CAP_MS`] ⇒ **起核前**拒绝（一个端口都没烧、
    /// 一个子进程都没留）。载荷是**诊断原文**。
    ///
    /// # 与 [`TempCoreOutcome::Failed`] 分开不是内部整洁，是用户可见的差别
    ///
    /// 合成一个变体 ⇒ 命令层只能发同一个错误码 ⇒ 前端只能映射到同一句「测速中断」，与「核起不来
    /// 超时」**逐字相同**。用户于是去查网络/端口，而真因是本轮 naive 节点太多、少选一些就能测。
    /// 那正是本改动要消灭的那类误诊，不能在响应信封这一层把它原样重建一遍。
    Oversized(String),
    /// 起核前就已被主核接管 → 一个节点都没测，未测节点缺席。
    Superseded,
}

/// **一批**的结局（[`TempCoreSession::run_batch`] 的返回值）。
///
/// # 为什么不直接复用 [`TempCoreOutcome`]
///
/// 那是**轮**级的结局，要折成响应信封给用户；批级的结局只服务一件事：让轮级循环决定「继续下一批
/// 还是停」。两者的取值域也不同 —— 批级没有 `outcome: "completed"/"interrupted"` 这一格（那是轮
/// 的口径，由 [`RoundProgress`] 汇总后在轮的唯一出口算），批级的中断成因也不在返回值里而是记进
/// [`RoundProgress::note_interrupt`]（跨批要合并，不能各批各报）。
///
/// 合成一个类型 ⇒ 「批说自己 completed」这种没有意义的状态就变得可表达，而它一旦被误当成轮的结论
/// 就是「第一批测完即宣告整轮结束」——分批最危险的那个失效面。
#[derive(Debug)]
enum BatchOutcome {
    /// 走到了测量阶段。载荷是**本批**的结果（可能部分节点真实 `-1`，也可能中途被中断 ——
    /// 成因已记进 [`RoundProgress`]，不在这里重复）。
    Ran(serde_json::Map<String, Value>),
    /// 起核前/就绪前失败 ⇒ **本批一个数值都不产出**，节点缺席（绝不写假 `-1`），后续批照跑。
    ///
    /// `oversized` = 本批规模越过 [`TEMP_CORE_READY_TIMEOUT_CAP_MS`]。分批之后它在生产上不可达
    /// （见该常量的射程说明），但仍要与「核起不来」分开：两者在用户侧不是一句话，修法也南辕北辙。
    Failed { detail: String, oversized: bool },
    /// 起核前/就绪期间被主核接管 ⇒ **整轮**到此为止（后面的批一个都不该再起）。
    Superseded,
}

/// 一次临时核测速会话：分批 → 每批（起核 → 就绪门 → 编排 → **无条件**收尾）→ 一条终态事件。
pub struct TempCoreSession;

impl TempCoreSession {
    /// 跑一**轮**临时核测速：把可测集切成规模有界的批，逐批起一个自己的核，最后发**唯一**一条终态事件。
    ///
    /// - `nodes`：[`plan_temp_core_with_bindings`] 裁出的可测节点（保序）；空 → 调用方不该进来（此处防御性返 `Ran` 空）。
    /// - `superseded`：让位判据（生产 = [`is_temp_core_superseded`] 闭包，见模块文档）。
    /// - `measure`：按端口量 warm-TTFB（命令层注入，复用与主核路径**同一个**测量口径 ⇒ 两条腿的数值可比）。
    /// - `emit`：逐节点事件 + 心跳 + 终态（命令层注入 `AppHandle::emit`）。
    ///
    /// # 为什么要分批（T1-R1 的本体）
    ///
    /// 一份配置塞下全部 N 个节点时，峰值资源（核 RSS / 线程 / fd / 回环端口 / 配置体积 / 起核耗时）
    /// **全部**随 N 线性 —— 其中每个 naive 出站是一个独立的 Chromium Cronet Engine，由内核在入站
    /// bind **之前**串行 eager 启动。分批把 `(n, m)` 封在常数上 ⇒ **峰值与 N 无关，只有批数与总耗时
    /// 随 N 线性**。切法与两条预算见 [`plan_temp_core_batches`]。
    ///
    /// # 批间的两条心跳：为什么两条都必要
    ///
    /// 前端 `SPEEDTEST_IDLE_TIMEOUT_MS`（[`TEMP_CORE_UI_IDLE_TIMEOUT_MS`]）= 「两条进度事件之间静默
    /// 20s ⇒ 判为中断」，且它**只在收到过进度事件之后才布防**。分批之后批间那段空窗
    /// （收核 → check → spawn → 就绪门）落在已布防的定时器里，必须被切开。三段与各自的上界见
    /// [`TEMP_CORE_BATCH_WINDOW_OVERHEAD_MS`]，结论：
    ///
    /// · **只留就绪心跳**（去掉批首那条）⇒ 需要 `收核5s + check5s + 就绪预算 < 20s` ⇒ 就绪预算 < 9s，
    ///   而它的**下限**就是 10s（[`TEMP_CORE_READY_TIMEOUT_FLOOR_MS`]）⇒ 无解；
    /// · **只留批首心跳**（去掉就绪那条）⇒ 需要 `check5s + 就绪预算 + 单节点最坏10s < 20s` ⇒ 就绪预算
    ///   < 4s ⇒ 同样无解。
    ///
    /// ⇒ 两条都留，把空窗切成三段，只有中间那段随批规模变，于是批大小可以由它反解出来。
    ///
    /// # 心跳的发射判据：`tested > 0`（批首那条）
    ///
    /// 「本轮已经发过进度事件」⟺「前端的兜底定时器已布防」（判据见 [`RoundProgress::tested`]）。
    /// 只有此刻发心跳才是**重新起算**一个已经在跑的定时器；在**没布防**的时候发，反而是把定时器
    /// 提前布防到一个可以合法长达十几秒的起核窗口前面 —— 那正是 R0 那条门
    /// （`no_progress_event_escapes_before_the_readiness_gate_resolves`）拦的改动。故第一批
    /// （以及此前各批一个值都没测出来时）**不发**批首心跳，行为与分批之前逐字相同。
    ///
    /// # 批死不连坐
    ///
    /// 某一批起不了核（撞端口 / check 判无效 / spawn 失败 / 就绪超时）**不作废整轮**：那批的节点
    /// 缺席（绝不写假 `-1`），原因落日志，后续批照跑。唯一会终止整轮的是**让位** —— 主核来了，
    /// 后面的批一个都不该再起（双会话事故的源头）。
    ///
    /// # 终态事件的唯一出口
    ///
    /// 本函数只有一处发 [`EVENT_SPEED_TEST_DONE`]，且载荷一律是**轮**级口径（`total` / `serverIds`
    /// 取全轮可测集，`pending` = 全轮差集 = 「继续剩余」的输入）。发不发的判据与分批之前逐字相同：
    /// **只要有任何一批走到过测量阶段就发**（起核阶段整轮失败时不发，命令层给失败信封）。
    pub async fn run<Meas, MeasFut>(
        deps: &TempCoreDeps,
        nodes: &[TempNode],
        superseded: &(dyn Fn() -> bool + Sync),
        measure: Meas,
        emit: &mut (dyn FnMut(&str, Value) + Send),
    ) -> TempCoreOutcome
    where
        Meas: Fn(u16) -> MeasFut,
        MeasFut: Future<Output = Option<u32>> + Send + 'static,
    {
        if nodes.is_empty() {
            return TempCoreOutcome::Ran {
                results: serde_json::Map::new(),
                outcome: "completed",
            };
        }

        let intended: Vec<String> = nodes.iter().map(|n| n.id.clone()).collect();
        let mut progress = RoundProgress::new(nodes.len());
        let mut results = serde_json::Map::new();
        // 「有没有任何一批走到过测量阶段」——终态事件发不发的判据（见函数文档）。
        let mut measured_any_batch = false;
        // 起核阶段失败的批：数量 + **第一条**诊断原文与它的成因分档（整轮零测量时，它就是失败
        // 信封里那句话，`oversized` 决定折成哪个错误码）。
        let mut failed_batches = 0usize;
        let mut first_failure: Option<(String, bool)> = None;
        // 起核前就被让位、且**一个数值都没测出来** ⇒ 与分批之前同义：整轮 `Superseded`。
        let mut superseded_with_no_results = false;

        let batches = plan_temp_core_batches(nodes);
        log::info!(
            "测速临时核分批：{} 个可测节点（naive {}）切成 {} 批（单批上限 {} 节点 / {} naive）",
            nodes.len(),
            temp_core_naive_count(nodes),
            batches.len(),
            TEMP_CORE_BATCH_MAX_NODES,
            temp_core_batch_max_naive(),
        );

        for (index, batch) in batches.iter().enumerate() {
            // 批首心跳（判据见函数文档）。
            //
            // 这里**不再单独查一次** `superseded()`：`run_batch` 的第一件事就是同一个检查，且它在
            // 起核之前 —— 两处判据逐字相同、时序上也没有任何指令隔开，多写一次不会更早停下来，
            // 只会多出一条没有任何门能分辨的分支（「门在但没牙」）。让位真正的射程差别在下面那条
            // `Superseded` 臂：它决定整轮**到此为止**，而不是像失败批那样继续下一批。
            if index > 0 && progress.tested() > 0 {
                // 批首**心跳**：内容不变的一条进度事件（判据见 `RoundProgress::emit_progress`）。
                progress.emit_progress(emit);
            }
            match Self::run_batch(deps, batch, superseded, &measure, emit, &mut progress).await {
                BatchOutcome::Ran(batch_results) => {
                    measured_any_batch = true;
                    for (id, latency) in batch_results {
                        results.insert(id, latency);
                    }
                    // 让位是**唯一**终止整轮的成因（其余成因下一批换一个新核继续）。
                    if progress.reason() == Some(InterruptReason::Superseded) {
                        break;
                    }
                }
                BatchOutcome::Superseded => {
                    progress.note_interrupt(InterruptReason::Superseded);
                    // 判据**只看有没有测出值**，不看此前有没有批起核失败 ——
                    // 原来那句 `&& failed_batches == 0` 会让「批 1 spawn 失败 + 批 2 让位」这条
                    // 交叉路落到下面的 `!measured_any_batch` 分支，把结局报成
                    // `Failed("测速临时核 spawn 失败: …")`：用户被指去查二进制/端口，
                    // 而真正的终止原因是他自己点了「连接」。这与 `note_interrupt` 的
                    // 「Superseded 覆盖一切」是同一条判据，两处必须一致。
                    superseded_with_no_results = !measured_any_batch;
                    log::info!(
                        "测速临时核让位：主核已接管，剩余 {} 批不再起核",
                        batches.len() - index
                    );
                    break;
                }
                BatchOutcome::Failed { detail, oversized } => {
                    failed_batches += 1;
                    log::warn!(
                        "测速临时核第 {}/{} 批未能开测（本批 {} 个节点缺席，后续批继续）：{detail}",
                        index + 1,
                        batches.len(),
                        batch.len()
                    );
                    if first_failure.is_none() {
                        first_failure = Some((detail, oversized));
                    }
                }
            }
        }

        // ── 轮级唯一出口 ───────────────────────────────────────────────────────────────
        if superseded_with_no_results {
            return TempCoreOutcome::Superseded;
        }
        if !measured_any_batch {
            // 整轮一个数值都没产出 ⇒ 失败信封（与分批之前逐字同义：核没起来 ≠ 每个节点都超时）。
            // 让位那一支已在上面返回，走到这里必有失败批。
            return match first_failure {
                Some((detail, true)) => TempCoreOutcome::Oversized(detail),
                Some((detail, false)) => TempCoreOutcome::Failed(detail),
                None => TempCoreOutcome::Superseded,
            };
        }
        // 一批都没起成功时不发终态（同分批之前）；只要测过就必须发，且载荷是**轮**级口径。
        let outcome = if progress.reason().is_some() || failed_batches > 0 {
            "interrupted"
        } else {
            "completed"
        };
        emit_speed_test_done(emit, outcome, &results, &intended, progress.reason());
        TempCoreOutcome::Ran { results, outcome }
    }

    /// 跑**一批**：起核 → 就绪门 → 编排 → **无条件**收尾（杀核 + 删配置）。
    ///
    /// 这就是分批之前的整条会话流程，逐字未动 —— 分批只是在它外面套了一层循环
    /// （[`TempCoreSession::run`]），批内的起核/就绪/排空/收尾/pid 登记一格都没改。
    ///
    /// - `nodes`：**本批**的节点（[`plan_temp_core_batches`] 的一片；`ports` 与它逐位 1:1）。
    /// - `progress`：**轮**级的进度账（跨批累加），逐节点事件与就绪心跳都从它取口径。
    ///
    /// # 收尾纪律
    ///
    /// 杀核 + 删配置走**无条件**路径（正常完成 / 让位 / 就绪失败 / 编排 panic 之外的一切分支共用）——
    /// 漏一条腿的表现是**孤儿 sing-box 常驻**，占着 N 个回环端口且用户完全看不见。
    async fn run_batch<Meas, MeasFut>(
        deps: &TempCoreDeps,
        nodes: &[TempNode],
        superseded: &(dyn Fn() -> bool + Sync),
        measure: Meas,
        emit: &mut (dyn FnMut(&str, Value) + Send),
        progress: &mut RoundProgress,
    ) -> BatchOutcome
    where
        Meas: Fn(u16) -> MeasFut,
        MeasFut: Future<Output = Option<u32>> + Send + 'static,
    {
        if nodes.is_empty() {
            return BatchOutcome::Ran(serde_json::Map::new());
        }
        // ── 让位（起核前）：主核已在跑/已跃迁 → 根本不起临时核（双会话从源头掐掉）──
        if superseded() {
            return BatchOutcome::Superseded;
        }

        // ── 规模门（起核**之前**）：就绪预算按本批规模现算，越过硬上限就当场拒绝 ──
        //
        // 判在这里而不是就绪门那里，是因为越界那一批的正确结局是「不起核」：起了再等超时会白烧
        // N 个回环端口（且把它们暴露在 TOCTOU 窗口里）、白留一个要收的子进程，而结论早在这一行
        // 就是确定的。报错原文必须**说清是规模问题**并给出可执行的数 —— 静默截断成超时就是把
        // 本改动要消灭的那个误诊原样搬到上界处（判据见 `TEMP_CORE_READY_TIMEOUT_CAP_MS`）。
        let naive_count = temp_core_naive_count(nodes);
        let ready_timeout_ms = match deps.ready_timeout_override_ms {
            Some(ms) => ms,
            None => match temp_core_ready_timeout_ms(nodes.len(), naive_count) {
                Ok(ms) => ms,
                Err(budget) => {
                    // 越界腿在生产上**唯一**的观测点。这四个数（n / m / 估算 / 预算）此外只活在
                    // 报错字符串里，而那条字符串会被命令层折成结构化码、由前端换成本地化文案 ⇒
                    // 不落这一行，「门为什么把这批拒了」在事后排查里一个数都读不到（spawn 那条
                    // 带规模数字的 info 走的是起核之后，这条腿根本到不了）。
                    log::warn!(
                        "测速临时核规模门拒绝本批：{} 个节点（naive {naive_count}）/ 估算起核 {}ms / 就绪预算 {budget}ms 超过上限 {TEMP_CORE_READY_TIMEOUT_CAP_MS}ms ⇒ 不起核",
                        nodes.len(),
                        temp_core_startup_estimate_ms(nodes.len(), naive_count),
                    );
                    return BatchOutcome::Failed {
                        detail: temp_core_oversize_message(nodes.len(), naive_count, budget),
                        oversized: true,
                    };
                }
            },
        };

        let binary = match (deps.resolve_binary)() {
            Ok(b) => b,
            Err(e) => {
                return BatchOutcome::Failed {
                    detail: e,
                    oversized: false,
                }
            }
        };

        // 端口：整批原子（任一槽拿不到互异空闲口 → 空 vec）。部分池不可用 —— 槽↔端口 1:1 一旦错位，
        // 量到的就是**别的节点**的延迟，比测不了更糟。
        let ports = (deps.allocate_ports)(nodes.len());
        if ports.len() != nodes.len() {
            return BatchOutcome::Failed {
                detail: format!(
                    "测速临时核端口分配失败（需 {} 个互异空闲口，实得 {}）",
                    nodes.len(),
                    ports.len()
                ),
                oversized: false,
            };
        }

        let config_path = deps.config_dir.join(TEMP_CORE_CONFIG_NAME);
        // 诊断档留档判据：用户把日志级别拨到 `debug`/`trace` 就是在说「这次我要证据」。取 `deps.log_level`
        // 而不是另读一次配置 —— 它就是本次真正下发给核的那一档（`temp_core_log_level` 的产出）。
        let keep_config = matches!(deps.log_level.as_str(), "debug" | "trace");
        let cfg = build_temp_core_config(nodes, &ports, &deps.log_level);
        let bytes = match serde_json::to_vec_pretty(&cfg) {
            Ok(b) => b,
            Err(e) => {
                return BatchOutcome::Failed {
                    detail: format!("序列化测速临时核配置失败: {e}"),
                    oversized: false,
                }
            }
        };
        if let Err(e) = std::fs::write(&config_path, bytes) {
            return BatchOutcome::Failed {
                detail: format!("写测速临时核配置失败 {}: {e}", config_path.display()),
                oversized: false,
            };
        }

        // `sing-box check` 先验配置形态（fail-fast，同瞬态登录核的既定手法）。没有这道门时，`custom`
        // 协议里用户写错的原样 JSON 会让核预初始化 FATAL ⇒ 用户白等整个就绪预算再看到「未监听」这个指错方向的
        // 报错。check 的诊断原文冒泡给用户 —— 那句话里直接写着哪个字段错了。
        if let Err(e) = deps.checker.check(&binary, &config_path).await {
            retire_temp_config(&config_path, keep_config);
            return BatchOutcome::Failed {
                detail: e,
                oversized: false,
            };
        }

        // ── 两条流的去向写在请求里（**必填**，见 `StdioPolicy`）────────────────────────────
        //
        // # 这几行补的是全仓唯一一条「管道被 piped 却从不排空」的腿
        //
        // spawner 一律开两条管道，主核与瞬态登录核各自记得去读，只有测速临时核两条流都没人读 ⇒
        // 核往管道里写满 64 KiB（Linux 默认容量）后 `write(2)` **永久阻塞**，整个 sing-box 卡死但
        // **不死**，此后每个节点都吃满 6 s 硬闸判 -1 且永不恢复。2026-09-02 的受控对照实验已实测
        // 坐实这条链：同配置同批节点，唯一翻转「排不排空」，断崖即出现/消失（4/4 轮可重复，
        // nodrain 组 `wchan` 全程命中 `anon_pipe_write`）。
        //
        // 接线放在**请求里**而不是 spawn 之后：spawner 在返回之前就把读端交给这个闭包，起核到
        // 就绪那一整段（上限 = 本批的就绪预算）窗口里也不存在「已经在写、还没人读」的空档；而且少写这一格
        // 编不过 —— 这条腿当年正是「少写了那一格」才漏掉的。
        //
        // target 用本腿自己的 `SPEEDTEST_CORE_TARGET`：核侧的行要和 Rust 侧的编排行落在同一份
        // `polaris.log` 的同一条时间线上，混进主核 target 会污染 `singbox.log` 的分流与日志页的
        // 来源筛选。`fatal` / `handoff` 传 `None` —— 那两个是主核专属语义（起核真因槽、与
        // `SubscribeLog` 流的交接闸），临时核两样都没有。
        //
        // fire-and-forget：排空任务的生命周期由**流的 EOF** 决定（核被 `terminate()` 收掉 → 管道
        // 关闭 → 任务自然结束），不需要句柄；它也**不是任何判据的来源**，纯诊断出口。
        let mut req = SpawnRequest::new(
            &binary,
            &config_path,
            StdioPolicy::drain(|stdout, stderr| {
                pipe_to_log(stdout, SPEEDTEST_CORE_TARGET, None, None);
                pipe_to_log(stderr, SPEEDTEST_CORE_TARGET, None, None);
            }),
        );
        // 核输出进日志 sink（非 TTY）；不加 flag 会混入 ANSI 转义。CWD 设可写 config 目录，
        // 理由同主核 spawner（GUI 从 launchd 拉起时父进程 CWD=`/` 只读）。
        req.extra_args = vec!["--disable-color".to_string()];
        req.working_dir = Some(deps.config_dir.clone());
        let child = match deps.spawner.spawn(req) {
            Ok(c) => c,
            Err(e) => {
                retire_temp_config(&config_path, keep_config);
                return BatchOutcome::Failed {
                    detail: format!("测速临时核 spawn 失败: {e}"),
                    oversized: false,
                };
            }
        };

        // 起核之后的一切分支都必须经收尾（杀核 + 删配置），故从此处起收束到一个 helper。
        let outcome = Self::drive_after_spawn(
            deps,
            nodes,
            &ports,
            ready_timeout_ms,
            naive_count,
            superseded,
            measure,
            emit,
            progress,
            child,
        )
        .await;
        retire_temp_config(&config_path, keep_config);
        outcome
    }

    /// spawn 之后的编排（就绪门 → 测量 → **无条件杀核**）。抽出以保证「起了核就一定会被杀」这条纪律
    /// 只有一个出口：本函数的每一条 `return` 之前都已 `terminate()`。
    #[allow(clippy::too_many_arguments)]
    async fn drive_after_spawn<Meas, MeasFut>(
        deps: &TempCoreDeps,
        nodes: &[TempNode],
        ports: &[u16],
        ready_timeout_ms: u64,
        naive_count: usize,
        superseded: &(dyn Fn() -> bool + Sync),
        measure: Meas,
        emit: &mut (dyn FnMut(&str, Value) + Send),
        progress: &mut RoundProgress,
        mut child: Box<dyn LoginCoreChild>,
    ) -> BatchOutcome
    where
        Meas: Fn(u16) -> MeasFut,
        MeasFut: Future<Output = Option<u32>> + Send + 'static,
    {
        let pid = child.pid().unwrap_or(0);
        // 登记进在飞表：应用退出时 `run_exit_cleanup` 据此强杀（本 future 届时不会被 drop，Drop 守卫
        // 覆盖不到那条路径）。守卫在本函数返回/展开时自动注销。
        let _pid_guard = TempCorePidGuard::register(pid);
        // 端口打**摘要**不打全量：`{ports:?}` 的长度与节点数线性（N=2000 时一行 14 KB），
        // 判据见 `format_ports_for_log`。顺带把本批的规模与算出来的就绪预算落进同一行 ——
        // 「门为什么是这个数」在事后排查里必须能从日志直接读出来，否则规模门就成了一个不可观测的判断。
        log::info!(
            "测速临时核已 spawn：pid={pid}，{} 个节点（naive {naive_count}）/ 端口 {} / 就绪预算 {ready_timeout_ms}ms（估算起核 {}ms）",
            nodes.len(),
            format_ports_for_log(ports),
            temp_core_startup_estimate_ms(nodes.len(), naive_count),
        );

        // 两条流的排空**不在这里**：它在 `run()` 构造 `SpawnRequest` 时就接好了，spawner 返回
        // 之前已经生效 —— 比「就绪门之前」更早，起核到就绪那段窗口里也没有无人读的空档。

        // ── 就绪门（复用 core-supervisor `wait_for_core_ready`；本层只注入真实 I/O）──
        // 就绪信号 = 第一个 HTTP 入站端口可连（对齐 上游 `waitForPortReady(ports[0], …)`；
        // 上游那个 10000 是常数，本腿的等待上限是本批规模的函数，见 `temp_core_ready_timeout_ms`）。
        let probe = Arc::clone(&deps.probe_port);
        let first_port = ports[0];
        let ready_deps = CoreReadyDeps {
            is_alive: Box::new(move || pid == 0 || pid_alive(pid)),
            is_ready: Box::new(move || {
                let probe = Arc::clone(&probe);
                Box::pin(async move {
                    tokio::task::spawn_blocking(move || probe(first_port))
                        .await
                        .unwrap_or(false)
                })
            }),
            sleep: Box::new(|d| Box::pin(tokio::time::sleep(d))),
            // 就绪等待期同样守让位：临时核起到一半用户点了「连接」⇒ 立刻停等 + 杀核，
            // 而不是先傻等满整个就绪预算再发现要让路（那一整段里两个核并存）。
            is_superseded: Some(Box::new(superseded)),
            on_retry: None,
        };
        let ready = wait_for_core_ready(
            WaitForCoreReadyOptions {
                timeout_ms: ready_timeout_ms,
                poll_ms: TEMP_CORE_READY_POLL_MS,
            },
            &ready_deps,
        )
        .await;
        // ── 就绪心跳（批间空窗的第二把剪刀）───────────────────────────────────────────
        //
        // 就绪门**解析之后**立刻发一条心跳，把前端那个 20s 静默兜底重新起算 —— 后面紧接着的是
        // 「本批第一个节点的测量」，最坏 10s（冷建链 6s + 复用 4s），稳稳落在 20s 里。
        //
        // # 判据为什么是 `Ready || tested > 0`，而不是无条件
        //
        // · **就绪成功**：后面没有任何长窗口，发它零风险，且用户此刻就能看到「测速中 · x/N」
        //   （大批 naive 的起核可以合法地花十几秒，这条心跳是那段时间里唯一的活信号）；
        // · **就绪失败/让位**：本批要提前返回，下一批还要再走一遍「收核 → check → 起核」。
        //   此时发心跳只有在**定时器已经布防**（`tested > 0`）时才是「重新起算」；一轮里还没有
        //   任何进度事件时发它，就是把定时器提前布防到下一批的起核窗口前面 —— 那正是 R0 那条门
        //   （`no_progress_event_escapes_before_the_readiness_gate_resolves`）拦的改动，
        //   它守的命题在分批之后逐字不变：**第一批的就绪门解析之前，一条 progress 都不许出去**。
        if matches!(ready, CoreReadyOutcome::Ready) || progress.tested() > 0 {
            // 就绪**心跳**：内容不变的一条进度事件（判据见 `RoundProgress::emit_progress`）。
            progress.emit_progress(emit);
        }
        match ready {
            CoreReadyOutcome::Ready => {}
            CoreReadyOutcome::Superseded => {
                child.terminate().await;
                return BatchOutcome::Superseded;
            }
            other => {
                child.terminate().await;
                // 整批一个数值都不产出：核没起来 ≠ 每个节点都超时。写一批 -1 就是伪造 N 次真实测量。
                // 报错必须带**本批规模与预算的推导输入**：门不再是一个人人都知道的常数了，
                // 少了这三个数，下一个人看到「20784ms 内未监听」根本无从判断门是算宽了还是算窄了。
                return BatchOutcome::Failed {
                    detail: format!(
                        "测速临时核未就绪（{other:?}，{ready_timeout_ms}ms 内 127.0.0.1:{first_port} 未监听；\
                         本批 {} 个节点 / {naive_count} 个 naive，估算起核 {}ms）",
                        nodes.len(),
                        temp_core_startup_estimate_ms(nodes.len(), naive_count),
                    ),
                    oversized: false,
                };
            }
        }

        // `watch` 圈在内层块里：它持有 `child.wait()` 这条**可变借用**，而 `Pin<Box<..>>` 有析构
        // ⇒ 借用活到作用域末尾。不圈起来的话下面的 `child.terminate()` 借不出 `child`。
        let (results, outcome) = {
            let mut watch = TempCoreWatch {
                pid,
                exited: child.wait(),
                probe_port: Arc::clone(&deps.probe_port),
                port: first_port,
            };
            drive_temp_core_measures(
                nodes,
                ports,
                TEMP_CORE_CONCURRENCY,
                superseded,
                &mut watch,
                measure,
                emit,
                progress,
            )
            .await
        };
        // 收核走**无条件**路径（含核已自己退出那条腿：那时 `terminate()` 只是收残句柄，不会再发信号，
        // 见 `TokioLoginCoreChild::terminate` 的 `pid == 0` 早退）。
        child.terminate().await;
        log::info!("测速临时核本批已回收：pid={pid}，outcome={outcome}");
        BatchOutcome::Ran(results)
    }
}

/// 收尾处置临时配置。
///
/// - **常规档**：删掉，并顺手收掉上一次的留档。
/// - **诊断档**（`debug` / `trace`）：改名成固定的 [`TEMP_CORE_LAST_CONFIG_NAME`] 留一份。
///
/// # 为什么诊断档要留、且留固定名
///
/// 排查临时核绕不开「这一轮到底给核喂了什么」——出站条数、有几条 `type:"naive"`、某个节点的形态。
/// 而收尾是**无条件**删除，于是任何事后复盘都只能靠抢在删除前 `cp`（真机上抢不住）。用户已经把级别
/// 拨到诊断档，就是在说「这次我要证据」，留一份配置正是最便宜的那份证据。
///
/// 固定名（覆盖式）而非带时间戳：理由同 [`TEMP_CORE_CONFIG_NAME`] —— 带时间戳会在 config 目录里越堆
/// 越多，而排查只关心**最后一次**。改名而非复制：`rename` 是同目录内的元数据操作，不复制字节、不新增
/// 失败面，且原路径当场消失（与「删掉」对下次运行的语义完全一致）。
fn retire_temp_config(path: &std::path::Path, keep_for_diagnosis: bool) {
    let kept = path.with_file_name(TEMP_CORE_LAST_CONFIG_NAME);
    if keep_for_diagnosis {
        match std::fs::rename(path, &kept) {
            // 留档成功即收尾结束：原路径已经不在了，不需要再删一次。
            Ok(()) => {
                log::debug!("诊断档：测速临时核配置已留档 {}", kept.display());
                return;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            // 改名失败（跨设备 / 权限 / 目标被占）→ 退回删除。留不下证据是可惜，留下一份**没被删掉的
            // 活配置**才是真问题：这份文件里有全部被测节点的凭证（密码 / uuid / WG 私钥）。
            Err(e) => log::warn!("留档测速临时核配置失败 {}: {e}（退回删除）", kept.display()),
        }
    } else {
        // **非诊断档顺手收掉上一次的留档**（`NotFound` 即常态，忽略）。
        //
        // 留档里含**全部被测节点的凭证**（密码 / uuid / WG 私钥）。它与运行期配置的泄露等级相同，
        // 但有一个决定性差别：`singbox-runtime.json` **有主**（核在跑就该在、停核换配置就被覆盖），
        // 而这份**无主** —— 用户为排查把级别拨到 debug 跑一轮、随后拨回 info，这份带凭证的文件就
        // 永远躺在 config 目录里，没有任何路径会再碰它。故把「回到非诊断档」当作它的回收点。
        if let Err(e) = std::fs::remove_file(&kept) {
            if e.kind() != std::io::ErrorKind::NotFound {
                log::warn!("清理测速临时核留档失败 {}: {e}", kept.display());
            }
        }
    }
    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            log::warn!("删测速临时核配置失败 {}: {e}", path.display());
        }
    }
}

#[cfg(test)]
mod tests;
