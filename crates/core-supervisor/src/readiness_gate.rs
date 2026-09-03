//! sing-box 核就绪门控 —— 上游 `core-readiness.ts` 的 1:1 Rust 移植。
//!
//! 移植锚点（行为不变式见 capability-registry-special-logic.md §1 #2 / #10）：
//! - [`CoreReadyOutcome`] = `'ready' | 'dead' | 'timeout' | 'superseded'`（core-readiness.ts:63）。
//! - [`wait_for_core_ready`] = `waitForCoreReady`（core-readiness.ts:81-100）：每轮 supersede → ready → alive 顺序判定。
//! - [`CoreStartRetryError`] / [`CoreStartSupersededError`] = core-readiness.ts:18 / :32 的标记错误类型。
//!
//! 关键不变式（issue #176 / #159）：
//! 1. supersede 先于一切判定（被更新的 start/stop 接管后继续等就绪有害——抢适配器/撞端口）。
//! 2. isReady（异步）先于 isAlive（同步探活）：成功路径（API 早绑）即返回，绝不触发阻塞探活。
//!    顺序安全：API 监听随核进程而生灭，端口可连 ⟹ 核存活。
//! 3. 满轮后末轮再判一次（boundary check），不漏判就绪/退出。
//!
//! 纯逻辑：所有 I/O（is_ready/is_alive/sleep/is_superseded）由调用方注入，便于无进程/端口/计时器单测。

use std::future::Future;

/// 核就绪轮询结局（core-readiness.ts:63 `CoreReadyOutcome`）。
///
/// - `Ready`：管理 API 端口可连（核已就绪）。
/// - `Dead`：进程已退出（起核期死，立即判定，不等满 timeout）。
/// - `Timeout`：进程在但管理 API 未在预期内绑定。
/// - `Superseded`：就绪等待期内被更新的 start/stop 接管（issue #176），应静默让位（不重试、不清理）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreReadyOutcome {
    Ready,
    Dead,
    Timeout,
    Superseded,
}

/// 「核已起但起核期未就绪/退出，应交 retry 静默重起」的标记错误（core-readiness.ts:18）。
///
/// 文案不含不可重试关键词（找不到/权限/permission/enoent/...）→ 调用方 should_retry 判可重试。
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct CoreStartRetryError {
    pub message: String,
}

impl CoreStartRetryError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// issue #176：本次起核在就绪等待期内被「更新的 start/stop」接管（lifecycle_generation 变化）的让位标记错误
/// （core-readiness.ts:32）。
///
/// 关键区别于 [`CoreStartRetryError`]：**不重试、不清理**——接管方拥有进程/系统代理/适配器状态，本腿必须静默退场，
/// 绝不调 stop/cleanup（会清掉接管方的 refs）。start() 包装层捕获本类型后直接 return（不 rethrow）。
#[derive(Debug, thiserror::Error)]
#[error("sing-box 起核已被更新的启动/停止操作接管，本腿让位")]
pub struct CoreStartSupersededError;

/// wait_for_core_ready 注入依赖（core-readiness.ts:66 `CoreReadyDeps`，单测可替换为桩）。
///
/// 所有闭包以 `&self` 借用调用，故用 trait object 风格的结构体持有闭包。生产路径注入真实 TCP 探测 + 进程探活；
/// 测试路径注入桩函数 + 计数器。
pub struct CoreReadyDeps<'a> {
    /// 核进程是否存活（isAlive）。
    pub is_alive: Box<dyn Fn() -> bool + Send + Sync + 'a>,
    /// 管理 API 是否可连（就绪信号，isReady）——异步 TCP 探测。
    pub is_ready: Box<dyn Fn() -> PinReadyFuture<'a> + Send + Sync + 'a>,
    /// sleep（轮询间隔）。
    pub sleep: Box<dyn Fn(Duration) -> PinSleepFuture<'a> + Send + Sync + 'a>,
    /// 本次起核是否已被更新的 start/stop 接管（issue #176，可选；缺省视作未接管）。
    pub is_superseded: Option<Box<dyn Fn() -> bool + Send + Sync + 'a>>,
    /// 每次「未就绪 + 进程仍活 → 即将 sleep 重试」时回调一次（上游 `onRetry`，core-readiness.ts:906）。
    /// 供上层累计「本次 start 的就绪重试次数」（DiagnosticCounters 慢起轴 `lastStartReadyRetries`）。
    /// 可选；缺省不计。**纯观测回调**：绝不参与轮询判定/顺序——本状态机逻辑与既有测试完全不变。
    pub on_retry: Option<Box<dyn Fn() + Send + Sync + 'a>>,
}

type PinReadyFuture<'a> = Pin<Box<dyn Future<Output = bool> + Send + 'a>>;
type PinSleepFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

use std::pin::Pin;
use std::time::Duration;

impl<'a> CoreReadyDeps<'a> {
    /// 构造一个最小的依赖集（is_superseded = None）。
    pub fn new(
        is_alive: impl Fn() -> bool + Send + Sync + 'a,
        is_ready: impl Fn() -> PinReadyFuture<'a> + Send + Sync + 'a,
        sleep: impl Fn(Duration) -> PinSleepFuture<'a> + Send + Sync + 'a,
    ) -> Self {
        Self {
            is_alive: Box::new(is_alive),
            is_ready: Box::new(is_ready),
            sleep: Box::new(sleep),
            is_superseded: None,
            on_retry: None,
        }
    }
}

// ── 起核耗时的规模模型（**单一真值**）──────────────────────────────────────────
//
// sing-box 在**入站 bind 之前**串行 eager 启动全部出站（`box.go:544` 早于 `:576`），而 naive 出站在
// 这一步同步 `NewEngine()` + `StartWithParams` 建一个独立的 Chromium Cronet Engine。⇒ 一个核的就绪
// 时间基本等于「engine 数 × 单 engine 启动耗时」，与其余协议、与节点总数几乎无关。
//
// 本仓有**两个**核要按这个模型算就绪门（主核 = 用户点连接那一个；测速临时核），故系数与安全方向
// 收在此处一份。**各调用点自己提供**：固定项（主核要加载 rule_set/geo、可能建 TUN、可能经 helper
// 提权起核，测速临时核什么都不加载 ⇒ 两者差一个数量级）、下限、以及越界策略（临时核越界当场拒绝
// 不起核；主核**不许有拒绝腿** —— 连接被拒 = 不让用户上网，只能延长等待）。
//
// 「一份」这件事一度**不成立**：测速临时核那一侧曾在 `src-tauri/src/runtime/speedtest.rs` 里有一组
// 逐值相同的 `TEMP_CORE_*` 副本（主核就绪门落地时该文件正在另一支上重构，两批不能同时改它），
// 靠一道双向防漂移门 `temp_core_coefficients_stay_pinned_to_the_supervisor_single_source` 顶着。
// 2026-09-03 副本被收口进本模块，那道门连同它的正向对照一并退场（判词留在 `speedtest.rs` 收口处的
// 注释里）。**再往那边加一份本地副本 = 把那道门连同它守的失败面一起请回来。**

/// 起核耗时估算的**每 naive 出站项**（ms/engine）—— 公式里唯一的大头，占 M=500 时启动总时长的 99.5%。
///
/// # 系数是**推导值，不是多点实测** —— 改它之前必须先读完本段
///
/// | 系数 | 值 | 怎么来的 | 分级 |
/// |---|---|---|---|
/// | `t_engine` | 41ms | **两点回归**：macOS 真机 50 出站 / 0 naive 核自报 `started (0.09s)`，加上 Windows 真机 130 出站 / 56 naive 核自报 `started 2.38s`；`(2.38 − 0.09) / 56 = 40.9ms` | **推导** |
///
/// 两个数据点**分属两台机器、两个操作系统**，斜率里因此裹着跨机差异；跨平台推导给出的合理区间是
/// **30–45ms**。真值待多点实测确认：测法是在同一台机器上取 m ∈ {0, 50, 100, 200} 四点、读核自报的
/// `started (Xs)` 做线性回归，拿到真斜率后回来改本常量（公式形态不必动）。
///
/// # 安全方向：只许偏大，不许在无多点实测的前提下收紧
///
/// 两个方向的代价**严重不对称**：
///
/// · 估**小**（真机比公式慢：更慢的 CPU、冷盘、杀软逐 engine 扫描、首次加载 cronet 动态库）
///   ⇒ 门太紧 ⇒ 把一个**正在正常启动**的核判成失败并掐死。主核这条腿上的表现是「用户点连接直接
///   连不上」，且报错指向网络/端口而不是规模；
/// · 估**大** ⇒ 一个真起不来的核多等一会儿才被判死。用户多等几秒，无数据损失、无误诊。
///
/// ⇒ 安全方向是**偏大**。[`CORE_READY_SAFETY_FACTOR`] 与各调用点的下限都只朝这一个方向开。
/// **任何后续修改都必须保住这条不对称**：可以放宽，不可以在没有多点实测的前提下收紧。
pub const CORE_STARTUP_PER_NAIVE_MS: u64 = 41;

/// 起核耗时估算的**每节点项**（µs/节点）：配置解析 + inbound/outbound 对象构造。
///
/// 开发机实测 `sing-box check`：0 节点 0.03s → 2000 节点 0.24s ⇒ 0.105ms/节点。取 µs 而不是 ms：
/// 它 < 1ms，写成 ms 的整型常量就只能是 0（公式里 n 项直接消失）。
pub const CORE_STARTUP_PER_NODE_US: u64 = 105;

/// 核**自报**起核耗时的固定项基线（ms）：macOS 真机 50 出站 / 0 naive、缓存已热时
/// `sing-box started (0.09s)`。**单点实测。**
///
/// # 它不是任何调用点的固定项，只是固定项的**下界**
///
/// 这个数只含「核自己从进程起来到 bind 完成」的那一段，**不含**进程 spawn、不含杀软扫描、不含
/// rule_set / geo 资源加载、不含建 TUN、不含 helper 提权 IPC。测速临时核确实什么都不加载 ⇒ 可以直接
/// 拿它当固定项；主核这几项一个都不少 ⇒ 必须自己取一个更大的值（见 `MAIN_CORE_STARTUP_FIXED_MS`）。
///
/// 把它照抄成主核的固定项 = 在没有任何证据的前提下把门收窄到一个**从未验证过**的取值上，
/// 正是上面那条不对称明令禁止的方向。
pub const CORE_STARTUP_BASELINE_FIXED_MS: u64 = 90;

/// 就绪预算 = 估算 × 本系数。
///
/// 取 2 的判据：等价于容忍 [`CORE_STARTUP_PER_NAIVE_MS`] 的真值到 82ms/engine，约为声明区间上端
/// 45ms 的 1.8 倍 —— 即公式整体低估近一倍仍不会误杀一个正在正常启动的核。它是上面那条不对称的
/// 第一道保护（第二道是各调用点的下限）。
pub const CORE_READY_SAFETY_FACTOR: u64 = 2;

/// 本批规模 → 起核耗时估算（ms）。
///
/// ```text
/// T_ready(fixed, n, m) ≈ fixed + 0.105ms·n + 41ms·m
///     fixed = 调用点自己的固定项（与规模无关的那一段，见 CORE_STARTUP_BASELINE_FIXED_MS）
///     n     = 本次下发配置里的解析单元数（出站 + 端点）
///     m     = 其中 naive 出站数（每个 = 一个独立 Cronet Engine）
/// ```
///
/// # `m` 数的是**出站**，不是节点，也不是组成员
///
/// 建 engine 的判据在**核**那边，它看的是下发配置里 `outbounds[]` 每一项的 `type` 字段
/// （`protocol/naive/outbound.go` 由 `type: "naive"` 注册）。故：
/// · `selector` / `urltest` 的**成员**只是 tag 字符串，不是出站对象，一个 engine 都不建，不计入；
/// · WireGuard / Tailscale 走 `endpoints[]`，不建 engine，不计入 `m`（但计入 `n`）。
///
/// # 端点只按 `n` 计是**已知的模型盲区**，不是「端点不花时间」
///
/// 端点确实不建 cronet engine，但它们**在同一条串行启动链上做同步阻塞初始化**：上游 v1.14.0
/// `adapter/outbound/manager.go:58,77-79` 把 `m.endpoint.Endpoints()` append 进同一个 outbounds 切片、
/// 喂给**同一次** `startOutbounds`，而 wireguard 端点要建 TUN 设备 + `device.NewDevice` + `IpcSet`。
/// ⇒ 偏差方向是危险的那一侧（门算小）。量级需真机实测；在拿到数之前，各调用点的固定项要按
/// 「宁可偏大」取，把这点误差吸收掉。
///
/// 全程 `saturating_*`：规模是外部输入（订阅大小不受本仓控制），溢出回绕会把一个巨大的预算算成一个
/// 极小的门 —— 那正是本模型要消灭的失败面，不能由算术本身重新引入。
pub fn core_startup_estimate_ms(fixed_ms: u64, node_count: usize, naive_count: usize) -> u64 {
    let n = node_count as u64;
    let m = naive_count as u64;
    fixed_ms
        .saturating_add(n.saturating_mul(CORE_STARTUP_PER_NODE_US) / 1000)
        .saturating_add(m.saturating_mul(CORE_STARTUP_PER_NAIVE_MS))
}

/// 本批规模 → 就绪等待预算（ms）= `max(估算 × 安全系数, floor_ms)`。
///
/// # 为什么一定要有 `floor_ms`，而且由调用点给
///
/// 公式的固定项是**推导 + 单点**，在小批（m 很小）上它无论多离谱都不该把门收得比今天窄 —— 今天那个
/// 已发布、已在真机上跑过的固定门才是「小批能跑通」这条承诺的唯一锚点。故下限**不是**保险丝，
/// 它是承诺本身：只要它还是那个已发布的值，任何今天能在该窗口内就绪的批在本模型下拿到的门都
/// ≥ 原值 ⇒ 等待行为逐字不变。
///
/// # 本函数**没有上界**，上界是调用点的事
///
/// 「预算大到离谱时怎么办」在两个调用点上是**两个不同的正确答案**：测速临时核可以当场拒绝（测速被拒
/// 可以重试，且拒绝发生在起核之前，一个端口都不烧）；主核**绝不可以**（连接被拒 = 不让用户上网）。
/// 把上界写进本函数就等于把其中一个答案强加给另一个调用点。
pub fn core_ready_budget_ms(
    fixed_ms: u64,
    floor_ms: u64,
    node_count: usize,
    naive_count: usize,
) -> u64 {
    CORE_READY_SAFETY_FACTOR
        .saturating_mul(core_startup_estimate_ms(fixed_ms, node_count, naive_count))
        .max(floor_ms)
}

/// wait_for_core_ready 配置（core-readiness.ts:82 `{ timeoutMs, pollMs }`）。
#[derive(Debug, Clone, Copy)]
pub struct WaitForCoreReadyOptions {
    /// 总超时（ms）。
    pub timeout_ms: u64,
    /// 轮询间隔（ms）。
    pub poll_ms: u64,
}

/// 本次起核是否已被更新的 start/stop 接管（`is_superseded` 缺省视作未接管）。
fn is_superseded(deps: &CoreReadyDeps<'_>) -> bool {
    deps.is_superseded.as_ref().map(|f| f()).unwrap_or(false)
}

/// 失败结局收口：报 `fallback`（Dead/Timeout）**之前**再判一次 supersede。
///
/// # 为什么不能直接返回 fallback（与 TS 的**刻意分歧**，非移植疏漏）
///
/// 不变式 #1 说「supersede 先于一切判定」，但轮首那一次检查只在**轮首**成立：`is_ready` 是 async，
/// 一次 await 就是一段可被抢占的窗口。真实竞态（用户在起核途中点「停止」）：
/// 轮首判 supersede=false → await is_ready 期间 stop 跑完（bump 世代 + 取走 child）→ 本轮 is_ready
/// 失败、is_alive 见 child=None → 返 `Dead` → 调用方 `set_error(STARTUP_FAILED)` → 用户主动停核却
/// 收到「启动失败」错误弹窗。
///
/// 即：进程「死」的**死因恰恰是接管本身**，此时结局是让位（Superseded：不重试、不清理），不是失败。
/// 故把两条失败腿的返回收口到此处统一复判——判定顺序不变（supersede 仍先于 ready/alive），只是补上
/// 「判定期间世界变了」这一路。TS 原版（core-readiness.ts:93/:99）无此复判，是同一个误报面。
fn settle_failure(deps: &CoreReadyDeps<'_>, fallback: CoreReadyOutcome) -> CoreReadyOutcome {
    if is_superseded(deps) {
        CoreReadyOutcome::Superseded
    } else {
        fallback
    }
}

/// 轮询等核就绪（core-readiness.ts:81 `waitForCoreReady`）。
///
/// 每轮：被接管 → `Superseded`（立即让位，#176）；API 可连 → `Ready`；进程死 → `Dead`（立即，不等满 timeout）；
/// 否则 sleep。满 max_polls 仍未就绪 → 末轮再判一次 → `Timeout`。
///
/// 两条失败腿（Dead/Timeout）返回前经 `settle_failure` 复判 supersede —— 见该函数文档。
///
/// `max_polls = max(1, ceil(timeout_ms / poll_ms))`，与 TS 实现逐字一致（`Math.max(1, Math.ceil(...))`）。
pub async fn wait_for_core_ready(
    opts: WaitForCoreReadyOptions,
    deps: &CoreReadyDeps<'_>,
) -> CoreReadyOutcome {
    let poll_ms = opts.poll_ms.max(1);
    let max_polls = (opts.timeout_ms.div_ceil(poll_ms)).max(1);

    for _ in 0..max_polls {
        // supersede 先于一切判定（#176）。
        if is_superseded(deps) {
            return CoreReadyOutcome::Superseded;
        }
        // isReady（异步）先于 isAlive（同步探活）：成功路径即返回。
        if (deps.is_ready)().await {
            return CoreReadyOutcome::Ready;
        }
        if !(deps.is_alive)() {
            return settle_failure(deps, CoreReadyOutcome::Dead);
        }
        // 未就绪 + 进程仍活 → 即将 sleep 后重试：计一次就绪重试（上游 onRetry，:906）。
        // 纯观测，位于判定之后、sleep 之前，绝不改变任何 return 分支。
        if let Some(cb) = deps.on_retry.as_ref() {
            cb();
        }
        (deps.sleep)(Duration::from_millis(poll_ms)).await;
    }

    // 末轮 boundary check（core-readiness.ts:96-99）。
    if is_superseded(deps) {
        return CoreReadyOutcome::Superseded;
    }
    if (deps.is_ready)().await {
        return CoreReadyOutcome::Ready;
    }
    if !(deps.is_alive)() {
        return settle_failure(deps, CoreReadyOutcome::Dead);
    }
    settle_failure(deps, CoreReadyOutcome::Timeout)
}

#[cfg(test)]
mod tests;
