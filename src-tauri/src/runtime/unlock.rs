//! 解锁检测运行时：命令编排层（把纯逻辑 `polaris-unlock` crate 接成 run/get/快照/事件的生产路径）。
//!
//! # 这条接线守的是 §K7.1「两扇门之间的缝」
//!
//! `crates/unlock/` 有完整的检测器（`detect_all`/`run_checker`/`probe_egress`，全 mock-testable，
//! 有单测门）；`runtime/http.rs` 的 `UnlockHttp` 生产实现有真 socket 门。**但没有任何生产代码把
//! 「命令 → 编排 → 事件」这条路接起来** —— `commands/unlock.rs` 曾是 stub，`unlock:run` 返回空对象、
//! `unlock:get` 返回 null。检测器再全，前端也恒是灰徽章（与 §O1「数据面 aggregate 无人 emit」同族：
//! 事件常量在、无人 emit → UI 恒收 null）。本模块就是那条缺失的接线，且**必须由组合面门覆盖**：
//! 真 `UnlockHttp` 注入 → `run` 真调 → 快照真存 → 事件真 emit（见 `#[cfg(test)]`）。
//!
//! # 编排职责（上游 `UnlockDetectionService` 剥离 electron 壳后的应用层）
//!
//! 纯逻辑 crate 刻意不移植的编排策略（见 `crates/unlock/src/detector.rs` 模块文档「不移植」清单），
//! 在此重建。四个淬火不变式（`上游-unlock-4bug-fix.md`，registry 维度 7）逐条落：
//!
//! 1. **TTL + warm 补测**（#65/#6）：快照带 TTL（含 timeout 且非受限 → 2min 自然重检兜底；否则 30min）；
//!    partial-timeout 提交后 5s 定向重打 timeout 项（[`UnlockRuntime::run_recheck`]，epoch 守卫，invalidate 取消）。
//! 2. **出口归属 bracket**（#7）：轮首/轮尾各探一次 egress，不符=契约外翻转→丢弃+invalidate；
//!    并行地，commit 前校验 `epoch == epoch0`（有并发 invalidate 则 epoch 已变）→ 丢弃。
//!    **决不把 A 出口的结果标给 B 出口**。丢弃腿排的自跑由 [`MAX_CONSECUTIVE_DRIFT`] 熔断封顶
//!    （连续漂移 N 轮 → 落低置信终态、停止再排程），否则出口持续漂移 = 无界自持循环 + UI 永钉「检测中」。
//! 3. **invalidate 契约**（#7）：[`UnlockRuntime::invalidate`] 递增 epoch + 清缓存 + 广播 `{running,exitBlocked}`。
//!    停代理时 [`UnlockRuntime::peek`] 也自证失效（`unlock_get` 见 command 层）。
//! 4. **受限地区收敛**（#8）：出口 region ∈ `RESTRICTED_EGRESS_REGIONS`（CN）时，全超是结构性预期，
//!    按高置信终态收敛——不置 `low_confidence`、不 warm 补测、用正常 30min TTL（不 2min churn）。
//!
//! # 出口 pin
//!
//! 检测须走**用户当前分流出口**（否则测的是本机直连，无意义）。command 层用
//! [`HttpRuntime::via_local_proxy`](crate::runtime::http::HttpRuntime::via_local_proxy) 建经本机 mixed
//! 端口的客户端注入 [`UnlockRuntime::run`] —— 即 上游 `ensureFetch` 的 socks5 session pin 的等价物。
//! 本模块的 `run` 对 http 是注入无关的（`H: UnlockHttp`），故单测用 mock、生产用 pin 客户端，同一条编排。
//!
//! # headers 透传（CF 挑战判据不丢）
//!
//! HTTP 批给 `UnlockResponse` 加了 `headers`（`cf-mitigated` 是 CF 挑战主判据）。本编排层**不读也不动**
//! headers —— 它只调 `run_checker`/`probe_egress`，headers 由 checker（现在的判定 + #29 的 challenge.rs）
//! 消费。透传是自动的：`HttpRuntime::request` 填 headers → checker 读。本层不在中间截断，故不丢。
//!
//! # Restricted 变体前向兼容
//!
//! #29 可能给 `UnlockStatus` 加 `Restricted` 变体。本模块**不穷举 match** `UnlockStatus`：只用
//! `r.status == UnlockStatus::Timeout` 等值比较判「是否 timeout」，新变体自然落「非 timeout」，
//! 不炸编译、不误计数。加变体无需改本文件。

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use tauri::AppHandle;

use polaris_unlock::detector::{is_restricted_egress_region, probe_egress};
use polaris_unlock::endpoints::CHECKER_BUDGET_MS;
use polaris_unlock::{
    run_checker, ServiceId, UnlockBlockedReason, UnlockEgress, UnlockHttp, UnlockProgress,
    UnlockResult, UnlockSnapshot, UnlockStatus,
};

use crate::events::broadcast;
use crate::events::channel::{
    EVENT_UNLOCK_INVALIDATED, EVENT_UNLOCK_PROGRESS, EVENT_UNLOCK_UPDATED,
};

/// 新鲜快照缓存 TTL（30min）。对齐 上游 `EGRESS_CACHE_TTL_MS`。
const FRESH_TTL_MS: u64 = 30 * 60 * 1000;

/// 含 timeout 的快照 TTL（2min）。对齐 上游 `TIMEOUT_TTL_MS`——2min 后自然重检兜底，
/// 不让一次冷隧道 timeout 锁死 30min。**受限地区不走这条**（收敛，用 FRESH_TTL）。
const TIMEOUT_TTL_MS: u64 = 2 * 60 * 1000;

/// warm 补测延时（5s）。对齐 上游 `RECHECK_DELAY_MS`——等隧道热起来再定向重打 timeout 项。
/// **真机需调**（可能 3s 够）；由 command 层调度。
pub const WARM_RECHECK_DELAY_MS: u64 = 5_000;

/// **force 硬下限**（item 5，上游 `FORCE_MIN_MS`）：force 绕 TTL，但仍防手点连发触发对端限频。
/// **FX-ui 已加前端 15s 冷却灰态；本常量是后端硬下限**，双保险对齐（脚本/自动化绕过前端仍受此限）。
const FORCE_MIN_MS: u64 = 15_000;

/// **就绪门退避 schedule**（item 2，上游 `READINESS_BACKOFF_SCHEDULE_MS`）：核刚 running 时 mixed inbound
/// 尚未真正路由 → egress trace 探针会失败。首次即时探（核已就绪则零延迟），失败按此退避重试。前 3 攻 1.2s
/// （冷启动常态 <4s 就绪），后 3 攻拉长（+4/+4/+8s）吸收慢起窗。attempt n 的退避 = `schedule[n-1]`。
const READINESS_BACKOFF_SCHEDULE_MS: &[u64] = &[1200, 1200, 1200, 4000, 4000, 8000];

/// 就绪门最大攻数（item 2，上游 `READINESS_MAX_ATTEMPTS`）= schedule 长度 + 1（首攻即时探 + 6 次退避 = 7）。
const READINESS_MAX_ATTEMPTS: usize = READINESS_BACKOFF_SCHEDULE_MS.len() + 1;

/// **B1 自适应就绪确认**（item 2，上游 `READINESS_CONFIRM_MS`）：疑似 flap（曾失败过）时，成功探测后追加
/// 1 次确认探（此间隔后连续 2 成才判就绪）；首攻即成（健康路径）零代价直接就绪，不伤「连上即点亮」体感。
const READINESS_CONFIRM_MS: u64 = 1200;

/// **轮内 settle-retry 最大轮数**（item 4，上游 `SETTLE_RETRY_MAX_ROUNDS`）。
const SETTLE_RETRY_MAX_ROUNDS: u64 = 2;

/// **轮内 settle-retry 退避基数**（item 4，上游 `SETTLE_RETRY_BACKOFF_MS`）：第 n 轮退避 = n × 此值
/// （2s→4s，隧道进一步热）。首轮个别 checker 撞冷隧道 8s 超时 = 低置信瞬态，不与命中 marker 的高置信结果同权落定。
const SETTLE_RETRY_BACKOFF_MS: u64 = 2_000;

/// **整轮检测 wall-clock 硬上限**（上游 `TOTAL_DETECTION_BUDGET_MS`，`UnlockDetectionService.ts:78`）：
/// **就绪门 + checker 主轮 + settle-retry 共享一条 deadline**，非各段独立预算加法累加。加法累加的旧行为
/// 最坏 ≈ 就绪门 19.6s + checker 15s + settle-retry 6s ≈ 40s+（上游 同形态旧行为 ≈127s），用户实测
/// 「总超时不生效」。deadline 本身即上限：
/// - 就绪门每次退避/探测前判 deadline，单次探测按剩余收紧，耗尽 → notReady（不空等）；
/// - checker 主轮 + settle-retry 的单 checker 截止点 = `min(CHECKER_BUDGET_MS, 剩余)`；
/// - settle-retry 退避若跨 deadline 直接停（保留已有终态）。
///
/// **值经真机反馈定为 10s**（陈先生 2026-07-13：慢节点检测 ≤10s 比较合理）——本仓迁移时漏移植该值，
/// 分段常量按 上游 **修复前**版本抄了回来，等于把用户已反馈过的回归搬了过来。此处照搬 10s，不另定值。
/// 慢隧道超预算落 notReady/timeout，靠后续 invalidate 自跑（[`UnlockEventSink::schedule_self_run`]）恢复。
pub const TOTAL_DETECTION_BUDGET_MS: u64 = 10_000;

/// 单次网络操作在 deadline 逼近时的最小配额（上游 `MIN_OP_BUDGET_MS`）：防「按剩余收紧」算出 0/负值的
/// 退化请求。代价是整轮最多超出 deadline 此值——换来「每个 checker 都拿得到一个真实终态」。
const MIN_OP_BUDGET_MS: u64 = 500;

/// **invalidate 后主进程侧自跑去抖窗**（上游 `UNLOCK_SELF_RUN_DEBOUNCE_MS`，`index.ts:1772`）。
///
/// 起代理会连发多条 invalidate（起核就绪 + 切节点 + 热切换…），去抖把这一串合并成**一轮**检测。
/// 语义与 上游 逐字对齐：**每次 invalidate 重置计时**，只有静默满 1500ms 的那一次真正开跑。
pub const SELF_RUN_DEBOUNCE_MS: u64 = 1_500;

/// **出口漂移连击熔断阈值**：连续 N 轮「轮首/轮尾 egress 不符」丢弃 → 停止再排自跑，改落低置信终态。
///
/// # 没有这道熔断会怎样（本常量存在的唯一理由）
///
/// 漂移丢弃腿调 [`UnlockRuntime::invalidate`]，而 invalidate 会排一轮 [`SELF_RUN_DEBOUNCE_MS`] 后的自跑；
/// 那一轮重新探测、再次漂移、再次丢弃 —— **永不收敛**。每次迭代都是一整个 [`TOTAL_DETECTION_BUDGET_MS`]
/// 预算的真实网络流量（6 个解锁端点 + 2 次 CF trace），且每次 invalidate 广播 `{running:true}` →
/// 前端 `App.tsx` 调 `beginUnlockCheck()` ⇒ **UI 永久钉在「检测中」**。
///
/// 触发条件不是边角：任何负载均衡 / urltest / WARP / 多 IP 出口，只要出口 IP 轮换快过一轮检测即可。
/// 迁移时曾按「与 上游 同构、不加熔断」放行，本轮据上述具体机制推翻——上游 同构不等于 上游 没这个洞。
///
/// # 为什么是「熔断」而不是「放宽漂移判据」
///
/// 放宽判据（按 /24 比对、只比 region…）会削弱 §K7.1 的核心不变式「**决不把 A 出口的结果标给 B 出口**」。
/// 熔断不碰判据：前 N-1 轮照旧丢弃 + 重跑（快速漂移多半是瞬态，一两轮就稳），只有**持续**漂移才承认
/// 「这个出口在本轮时间尺度上没有稳定 IP」并落终态。归属不变式全程不破 —— 终态的 `egress` 置 `None`
/// （不标给任何出口），只如实告诉 UI「测到了这些值，但出口在抖，低置信」。
///
/// # 不是永久闩锁
///
/// 熔断落的终态是 `low_confidence` ⇒ 按既有规则**不入 TTL 缓存**，且落定即把连击计数清零。
/// 下一次真触发（起停 / 切节点 / 用户 force）照常重检，只是不再有「自己排给自己」的自持循环。
const MAX_CONSECUTIVE_DRIFT: u64 = 3;

/// 缓存的快照 + 其 TTL 记账。
struct Cached {
    snapshot: UnlockSnapshot,
    stored_at_ms: u64,
    ttl_ms: u64,
}

/// 解锁 gating 短路判定（**SoT**，命令层唯一入口）。1:1 上游 `UnlockDetectionService.run` 的 gating 段：
/// - 核未运行 / 无 mixed 入站 → `ProxyNotRunning`（不发起检测、不缓存）；
/// - 选中 TS 出口直判无效（`exit_blocked`，见 [`crate::runtime::tailscale_status::selected_ts_exit_blocked`]）
///   → `ExitInvalid`（经死出口检测只会空转就绪门数十秒 → 短路，零网络零就绪门）。
///
/// 优先级 `ProxyNotRunning > ExitInvalid`（无代理谈不上出口有效性），对齐 Polaris gate 顺序
/// （`isRunning` 先于 `getExitBlock`）。返回 `None` = 放行，进真检测。
#[must_use]
pub fn unlock_gate_reason(
    running: bool,
    mixed_port: u16,
    exit_blocked: bool,
) -> Option<UnlockBlockedReason> {
    if !running || mixed_port == 0 {
        return Some(UnlockBlockedReason::ProxyNotRunning);
    }
    if exit_blocked {
        return Some(UnlockBlockedReason::ExitInvalid);
    }
    None
}

/// `EVENT_UNLOCK_INVALIDATED` 载荷（对齐前端 `UnlockInvalidatedPayload`：`{running,exitBlocked}`）。
///
/// 由**主进程**带上核真态，供渲染端决定「显检测中 vs 复位 idle」（invalidate 常先于 STARTED 抵达，
/// 渲染端视图可能陈旧）。`rename_all` 对齐前端 camelCase 契约。
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct InvalidatedPayload {
    running: bool,
    exit_blocked: bool,
}

/// 解锁事件出口（注入抽象）。
///
/// 生产实现 [`BroadcastSink`] 经 `AppHandle` 广播 Tauri 事件；测试实现记录到 `Vec` 供断言——
/// 这样组合面门能证「事件真 emit」而无需 Tauri 运行时。对齐本仓「纯逻辑 + 注入 I/O」架构
/// （`events.rs` 是被注入的那一侧）。
pub trait UnlockEventSink {
    /// 单服务 settle 逐个点亮（`EVENT_UNLOCK_PROGRESS`）。
    fn progress(&self, service_id: &str, result: &UnlockResult);
    /// 一轮完成的完整终态快照（`EVENT_UNLOCK_UPDATED`）。
    fn updated(&self, snapshot: &UnlockSnapshot);
    /// 缓存失效（`EVENT_UNLOCK_INVALIDATED`）。
    fn invalidated(&self, running: bool, exit_blocked: bool);

    /// **invalidate 后的主进程侧去抖自跑**（上游 `scheduleUnlockSelfRun`，`index.ts:1774-1789`）。
    ///
    /// # 为何驱动层必须在这一侧
    ///
    /// 上游 源码 `index.ts:1808` 原文警告过这个坑：「GAP-1：invalidate 后主进程侧防抖自跑（**不依赖
    /// home 页挂载着的 renderer hook 发 IPC**）」。本仓迁移时只搬了 invalidate 的「作废 + 广播」半边，
    /// 把重跑责任交给了渲染端 hook，而该 hook 只有手动腿 ⇒ invalidate 把六个徽章置成「检测中」后**无人调
    /// run**，永久转圈。故驱动层落在此处（Rust 侧 = Electron 主进程的等价物），**不是**前端补 `useEffect`。
    ///
    /// # token 与去抖合并
    ///
    /// `token` 由 [`UnlockRuntime::invalidate`] 递增取得。实现方等 [`SELF_RUN_DEBOUNCE_MS`] 后须用
    /// [`UnlockRuntime::self_run_token_current`] 复核：token 已被后续 invalidate 顶掉 → 让位（不跑），
    /// 只有最后一次 invalidate 排的那一轮真正开跑。这就是「短时间内多次 invalidate 只跑一轮」。
    ///
    /// 默认实现 no-op：单测用的记录型 sink 无需真跑网络（也拿不到 `AppHandle`）。
    fn schedule_self_run(&self, token: u64) {
        let _ = token;
    }
}

/// 生产事件出口：经 `AppHandle` 广播给所有 webview。
pub struct BroadcastSink<'a> {
    handle: &'a AppHandle,
}

impl<'a> BroadcastSink<'a> {
    #[must_use]
    pub fn new(handle: &'a AppHandle) -> Self {
        Self { handle }
    }
}

impl UnlockEventSink for BroadcastSink<'_> {
    fn progress(&self, service_id: &str, result: &UnlockResult) {
        broadcast(
            self.handle,
            EVENT_UNLOCK_PROGRESS,
            UnlockProgress {
                service_id: service_id.to_string(),
                result: result.clone(),
            },
        );
    }

    fn updated(&self, snapshot: &UnlockSnapshot) {
        broadcast(self.handle, EVENT_UNLOCK_UPDATED, snapshot.clone());
    }

    fn invalidated(&self, running: bool, exit_blocked: bool) {
        broadcast(
            self.handle,
            EVENT_UNLOCK_INVALIDATED,
            InvalidatedPayload {
                running,
                exit_blocked,
            },
        );
    }

    /// 生产实现：取得受管 runtime 的去抖 task 槽，先取消上一只 timer，再等
    /// [`SELF_RUN_DEBOUNCE_MS`] 且复核 token，只让最后一轮真跑。
    ///
    /// gating（核未跑 / 出口直判无效）与出口 pin 全在
    /// [`run_unlock_cycle`](crate::commands::unlock::run_unlock_cycle) 内，与手动 `unlock:run` **同一条
    /// 编排** —— 自跑不是第二套逻辑，只是第二个触发源。`run(force=false)` 幂等：撞 gating 短路 = 零网络
    /// no-op，撞在飞轮 = `run_lock` 单飞串行后走 TTL 快路。
    /// ⚠️ **必须用 `tauri::async_runtime::spawn`，不能用 `tokio::spawn`**（2026-07-21 真机崩溃血证）。
    ///
    /// `tokio::spawn` 要求调用处**已在 Tokio runtime 上下文内**，否则 panic ⇒ Rust panic 在 Tauri IPC
    /// 回调里无处可catch ⇒ `abort()` ⇒ 整个应用崩溃。而 `invalidate` 的调用方**全是同步 command**
    /// （`server_switch` / `server_delete` / `server_delete_batch` / `subscription_delete` /
    /// `config_save` / `config_set_value`），Tauri 对 `pub fn`（非 `async fn`）command 是在**主线程**
    /// 直接调用的，**没有 runtime 上下文** ⇒ 切一次节点必崩，射程覆盖切/删节点、删订阅、存配置、改设置项。
    ///
    /// `tauri::async_runtime::spawn` 持有 Tauri 的全局 runtime handle，任意线程可调，仓内另有 21 处先例。
    ///
    /// **单测抓不到这个**：`#[tokio::test]` 自带 runtime 上下文，两种 spawn 在测试里行为一致、都能过。
    /// 唯一能在本层锁住的判据是源码扫描 —— 见本文件 `mod spawn_guard`。
    fn schedule_self_run(&self, token: u64) {
        use tauri::Manager;

        let app = self.handle.clone();
        // BroadcastSink 只会在 AppRuntime 已 manage 后的 command 路径使用。关停窗口若 State
        // 已不可取，直接放弃，不再留一只无主 timer。
        let unlock = {
            let Some(runtime) = app.try_state::<crate::runtime::AppRuntime>() else {
                return;
            };
            Arc::clone(&runtime.unlock)
        };
        let task = tauri::async_runtime::spawn(async move {
            tokio::time::sleep(Duration::from_millis(SELF_RUN_DEBOUNCE_MS)).await;
            {
                // setup 前极早期 / 关停中取不到 State → 静默放弃（绝不 panic，同 proxy.rs 的 try_state 范式）。
                let Some(rt) = app.try_state::<crate::runtime::AppRuntime>() else {
                    return;
                };
                if !rt.unlock.self_run_token_current(token) {
                    // 去抖合并：窗内又来了 invalidate → 由更晚那一轮负责跑，本轮让位。
                    log::debug!(
                        "解锁自跑：token {token} 已被后续 invalidate 顶掉 → 让位（合并为一轮）"
                    );
                    return;
                }
            } // State 守卫不跨 await（Tauri State 非 Send）。
            log::debug!(
                "解锁自跑：去抖窗静默满 {SELF_RUN_DEBOUNCE_MS}ms → 发起一轮检测（token {token}）"
            );
            if let Err(e) = crate::commands::unlock::run_unlock_cycle(app, false).await {
                // 真机 logLevel=warn ⇒ 此条必须 warn：自跑失败 = 前端「检测中」无人收口，正是卡住的形态。
                log::warn!("解锁自跑失败（前端可能停在检测中，需手动刷新）：{e}");
            }
        });
        unlock.install_self_run_task(token, task.inner().abort_handle());
    }
}

/// 选中出口 identity 是否变化（A7 解锁缓存失效判准，**四写腿共用的唯一权威**）。
///
/// 判准 = `selectedServerId` 变；两侧皆 `Option<&str>`（`None` = 无选中 / 清除选中，如删光节点或订阅刷没了）：
/// - 旧 == 新（含两侧皆 `None`）→ 未变（`false`）：出口不动，旧解锁结果仍有效，不失效（防白刷探测）。
/// - 旧 != 新 → 变（`true`）：出口切走，旧结果作废。含三类变：
///   - 旧 `None` → 新 `Some`（首次选中）；
///   - 旧 `Some` → 新 `Some'`（换节点）；
///   - **旧 `Some` → 新 `None`（→null：删当前选中 / 订阅刷新令选中消失）** —— 也是出口变，必须失效
///     （否则解锁角标最长陈旧 30min，即缓存 `FRESH_TTL_MS`）。
///
/// 曾在 `commands/server.rs`（`exit_node_changed`，新值 `&str`）与 `commands/config.rs`（`selected_exit_changed`，
/// 两侧 `Option`）各有一份；本函数收敛为单一真值源，两处引用它（server 侧调用点包 `Some(new)`）。
#[must_use]
pub fn selected_exit_changed(old_selected: Option<&str>, new_selected: Option<&str>) -> bool {
    old_selected != new_selected
}

/// 解锁检测运行时（`State`-managed 单实例）。
///
/// 持有 epoch（归属 bracket）+ 快照缓存；每轮使用的出口 pin HTTP 由调用方显式注入 `run`。
pub struct UnlockRuntime {
    /// 归属世代：invalidate 递增，作废在飞轮的 commit（别把旧出口结果标给新出口）。
    epoch: AtomicU64,
    /// 最近一轮的终态快照（TTL 内 `unlock_get` 零网络水合）。
    cache: Mutex<Option<Cached>>,
    /// **单飞串行**（item 7，上游 `inflight`）：并发 `run`/`run_recheck` 经此互斥串行化——第二者等第一者
    /// commit 后走 TTL 快路（零网络往返），而非各跑一遍 6 checker。Rust 无法像 JS 那样存借用 `http` 的在飞
    /// future（其生命周期借栈），故以「持锁跑整轮」等价实现单飞：第二者阻塞至第一者释放，再命中新鲜缓存。
    run_lock: tokio::sync::Mutex<()>,
    /// 最近一次**提交**的终态快照（含 notReady / lowConfidence；与 TTL `cache` 分离——后者受 TTL 约束且
    /// lowConfidence 不入）。供 S-gate（item 2：notReady 终态非 force 不重扫）+ force 硬下限（item 5）读。
    /// 上游 `lastSnapshot`。invalidate 清空。
    last_snapshot: Mutex<Option<UnlockSnapshot>>,
    /// 最近一次真跑网络（就绪门 / checker 轮）的时刻（Unix ms）。force 硬下限据此判 <15s 连点（item 5）。
    /// 上游 `lastRunAt`。invalidate 归零。
    last_run_at: AtomicU64,
    /// **自跑去抖世代**（上游 `unlockSelfRunTimer` 的等价物）：每次 invalidate 递增，作为该次排程的 token。
    /// 定时器到点时 token 与当前值不符 = 窗内又来过 invalidate → 该次让位。这就是「多次 invalidate 合并成
    /// 一轮」的第二道守卫；[`Self::self_run_task`] 则用 abort handle 复刻 JS `clearTimeout`，
    /// 不让失效的 sleep task 在高频 IPC 下堆积。
    self_run_seq: AtomicU64,
    /// 当前 trailing 自跑 timer（至多一只）。新 invalidate 安装新任务时 abort 旧任务；
    /// Drop 也 abort，避免 runtime 释放后还有脱离所有者的延迟回调。
    self_run_task: Mutex<Option<(u64, tokio::task::AbortHandle)>>,
    /// **出口漂移连击计数**（熔断器状态，见 [`MAX_CONSECUTIVE_DRIFT`]）：轮尾 egress 与轮首不符**且 epoch 未变**
    /// 时递增；任何落定终态（正常 commit / notReady commit / 熔断 commit）或「epoch 真变了」都清零。
    ///
    /// 刻意**不在 [`UnlockRuntime::invalidate`] 里清零** —— 漂移丢弃腿自己就调 invalidate，在那里清零会让
    /// 计数恒为 1、熔断永不触发，即「加了熔断却没有牙」。清零点只放在上面列的那几处。
    drift_streak: AtomicU64,
}

impl Default for UnlockRuntime {
    fn default() -> Self {
        Self {
            epoch: AtomicU64::new(0),
            cache: Mutex::new(None),
            run_lock: tokio::sync::Mutex::new(()),
            last_snapshot: Mutex::new(None),
            last_run_at: AtomicU64::new(0),
            self_run_seq: AtomicU64::new(0),
            self_run_task: Mutex::new(None),
            drift_streak: AtomicU64::new(0),
        }
    }
}

impl Drop for UnlockRuntime {
    fn drop(&mut self) {
        let slot = self
            .self_run_task
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((_, task)) = slot.take() {
            task.abort();
        }
    }
}

impl UnlockRuntime {
    /// 安装最新自跑 timer，并 abort 被取代的任务。并发 schedule 可能乱序进入本方法，
    /// 因此同时核对原子真值源和槽内 token，旧代永远不能反向取消新代。
    fn install_self_run_task(&self, token: u64, task: tokio::task::AbortHandle) {
        let mut slot = self
            .self_run_task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !self.self_run_token_current(token)
            || slot
                .as_ref()
                .is_some_and(|(installed, _)| *installed > token)
        {
            task.abort();
            return;
        }
        if let Some((_, previous)) = slot.replace((token, task)) {
            previous.abort();
        }
    }

    /// 当前自跑去抖世代（排程 token 的真值源）。
    #[must_use]
    pub fn self_run_seq(&self) -> u64 {
        self.self_run_seq.load(Ordering::SeqCst)
    }

    /// 该排程 token 是否仍是最新（否 = 去抖窗内又发生过 invalidate，本次排程应让位）。
    ///
    /// **去抖合并的判据单点**：[`UnlockEventSink::schedule_self_run`] 的实现方只调本函数，
    /// 不自己比大小——语义（含「相等才算最新」）由此处收口，单测直接锁这条。
    #[must_use]
    pub fn self_run_token_current(&self, token: u64) -> bool {
        self.self_run_seq() == token
    }

    /// 读最近提交的终态快照（S-gate / force-min 用；与 TTL `cache` 分离，无 TTL 约束）。
    fn last_snapshot(&self) -> Option<UnlockSnapshot> {
        self.last_snapshot.lock().ok().and_then(|g| g.clone())
    }

    /// OS 网络恢复后是否值得补跑一轮能力检测。
    ///
    /// 只把上一轮明确的瞬态/低置信形态纳入：inbound 未就绪、整轮低置信、或任一服务 timeout。
    /// 高置信快照不因普通路由抖动被无条件作废，避免网络接口 burst 反复重打外部服务。
    #[must_use]
    pub fn should_recheck_after_connectivity_recovery(&self) -> bool {
        self.last_snapshot().is_some_and(|snapshot| {
            snapshot.not_ready == Some(true)
                || snapshot.low_confidence == Some(true)
                || snapshot
                    .results
                    .values()
                    .any(|result| result.status == UnlockStatus::Timeout)
        })
    }

    /// 写最近提交的终态快照。
    fn set_last_snapshot(&self, snap: Option<UnlockSnapshot>) {
        if let Ok(mut g) = self.last_snapshot.lock() {
            *g = snap;
        }
    }

    /// 当前归属世代。
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }

    /// 递增世代，返回新值。
    fn bump_epoch(&self) -> u64 {
        self.epoch.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// `unlock:get` —— 纯读 TTL 内的缓存快照，**零网络**。过期/无缓存 → None（前端水合复位）。
    ///
    /// 无需 epoch 校验：invalidate 已在切节点/起停时清缓存，故非空缓存恒是当前出口的合法结果。
    #[must_use]
    pub fn peek(&self, now_ms: u64) -> Option<UnlockSnapshot> {
        let guard = self.cache.lock().ok()?;
        let cached = guard.as_ref()?;
        if now_ms < cached.stored_at_ms.saturating_add(cached.ttl_ms) {
            Some(cached.snapshot.clone())
        } else {
            None
        }
    }

    /// **invalidate 契约**：切节点/起停 → 递增 epoch（作废在飞轮）+ 清缓存 + 广播 `{running,exitBlocked}`
    /// + **排一轮去抖自跑**。
    ///
    /// 由生命周期事件（proxy start/stop/热切换、server switch、订阅刷新、config 换出口）触发。
    ///
    /// # 这里是自跑的唯一汇聚点
    ///
    /// 自跑排程**不在各调用点逐个接线**，而是收口在本函数（对齐 上游：所有 `invalidate()` → `onInvalidated`
    /// 回调 → `scheduleUnlockSelfRun()`，`index.ts:1806-1809`）。好处是「新增一个 invalidate 触发点」自动获得
    /// 自跑，不会像本批修的缺陷那样出现「广播了失效、没人重跑」的半边移植。含 `run()` 内的出口漂移丢弃腿
    /// （经 [`Self::invalidate_keep_run_at`]）——那一轮结果被丢弃后必须有人重跑，否则前端停在检测中。
    ///
    /// # 自跑不会无界自持
    ///
    /// 「丢弃 → 排自跑 → 再丢弃」这条边是有界的：漂移丢弃腿由 [`MAX_CONSECUTIVE_DRIFT`] 熔断，连续 N 轮后
    /// 改落低置信终态且**不再经过本函数**（不排新的自跑）。本函数自身不设限流，边界由调用侧的丢弃腿承担。
    pub fn invalidate<S: UnlockEventSink>(&self, sink: &S, running: bool, exit_blocked: bool) {
        self.bump_epoch();
        if let Ok(mut guard) = self.cache.lock() {
            *guard = None;
        }
        // S-gate / force-min 内存态一并复位（切节点/起停 = 一切真状态变化的解除通道，对齐 上游 invalidate：
        // 清 lastSnapshot + lastRunAt）——否则 notReady 终态会锁死 S-gate、旧 lastRunAt 会误挡新出口的首次 force。
        self.set_last_snapshot(None);
        self.last_run_at.store(0, Ordering::SeqCst);
        sink.invalidated(running, exit_blocked);
        // 去抖自跑：先递增世代取 token，再交给 sink 排程。递增必须在 `schedule_self_run` **之前**——否则
        // 并发 invalidate 可能拿到相同 token，两轮都判「最新」而双跑。
        let token = self.self_run_seq.fetch_add(1, Ordering::SeqCst) + 1;
        sink.schedule_self_run(token);
    }

    /// 丢弃腿专用的失效：语义同 [`Self::invalidate`]，但**保留 `last_run_at`**。
    ///
    /// # 为什么丢弃腿不能沿用裸 `invalidate`
    ///
    /// `invalidate` 把 `last_run_at` 置 0，那是为「起停 / 切节点」设计的：真状态变了，旧的限流记账不该
    /// 再挡新出口的首次 force。但**丢弃腿不是状态变化，而是本轮真跑过一整轮网络**（就绪门 + 6 个 checker
    /// + 2 次 trace）。在这条腿上置 0 会同时击穿两道防连点闸门：
    ///  - 后端 [`FORCE_MIN_MS`] 硬下限的 `force && last_at != 0` 守卫失效 ⇒ 连点 force 全部放行；
    ///  - 丢弃腿不 emit UPDATED ⇒ 前端 `unlock.lastRunAt` 停在陈旧/null ⇒ `unlockCooldown`
    ///    （`HomeScreen.tsx` 由 `lastRunAt` 派生的 15s 灰态）永不武装。
    ///
    /// 于是在漂移出口上刷新按钮**两侧都不受限流**，而这**恰好是后端已在自跑的时候** —— 对端限频风险最高
    /// 的那一刻反而门户大开。保留 `last_run_at` 即恢复后端那道闸门；前端那道由熔断落终态时的 UPDATED
    /// （带 `checkedAt` ⇒ store 的 `lastRunAt` 得到更新）收口，见 [`MAX_CONSECUTIVE_DRIFT`]。
    fn invalidate_keep_run_at<S: UnlockEventSink>(
        &self,
        sink: &S,
        running: bool,
        exit_blocked: bool,
    ) {
        let ran_at = self.last_run_at.load(Ordering::SeqCst);
        self.invalidate(sink, running, exit_blocked);
        self.last_run_at.store(ran_at, Ordering::SeqCst);
    }

    /// 写缓存（commit 后）。
    fn store(&self, snapshot: UnlockSnapshot, stored_at_ms: u64, ttl_ms: u64) {
        if let Ok(mut guard) = self.cache.lock() {
            *guard = Some(Cached {
                snapshot,
                stored_at_ms,
                ttl_ms,
            });
        }
    }

    /// **编排核心**（注入 http/sink/clock，天然可单测；生产由 command 注入 `via_local_proxy` 出口 pin 客户端）。
    ///
    /// 流程：单飞持锁（item 7）→ TTL 快路（非 force）→ S-gate（item 2 notReady 终态非 force 不重扫）→
    /// force 硬下限（item 5）→ 就绪门退避（item 2：核起→路由前探针重试 7 次 + B1 flap）→ checker 主轮
    /// （item 3 每 checker `CHECKER_BUDGET_MS` 封顶，逐 settle emit progress）→ 轮内 settle-retry
    /// （item 4：timeout 项退避补测 ≤2 轮）→ 轮尾 egress 确认 → 归属 bracket（epoch + egress）→
    /// commit（受限收敛 + TTL 挂置信度 + 维护 lastSnapshot）→ emit UPDATED。
    ///
    /// **整轮共享 deadline** = [`TOTAL_DETECTION_BUDGET_MS`]（10s），见
    /// [`Self::run_with_budget`]。
    pub async fn run<H, S>(
        &self,
        http: &H,
        sink: &S,
        force: bool,
        now: impl Fn() -> u64,
    ) -> UnlockSnapshot
    where
        H: UnlockHttp + ?Sized,
        S: UnlockEventSink,
    {
        self.run_with_budget(http, sink, force, now, TOTAL_DETECTION_BUDGET_MS)
            .await
    }

    /// [`Self::run`] 的预算参数化版本。
    ///
    /// `budget_ms` = 整轮 wall-clock 硬上限，**就绪门 + checker 主轮 + settle-retry 共享**（非各段加法累加）。
    /// 生产恒用 [`TOTAL_DETECTION_BUDGET_MS`]；单测用它把预算调大/调小，分别验「预算足时全 7 攻退避可达」
    /// 与「预算耗尽时写终态而非挂着」——对应 上游「单测以冻结注入时钟绕过 deadline」的等价手法。
    ///
    /// # deadline 用 `tokio::time::Instant` 而非注入的 `now`
    ///
    /// 注入的 `now`（生产 `unix_millis`）是**打戳用的墙钟**，单测里常冻结成常量（`|| 1_000`）。而所有真正
    /// 耗时的动作（退避 sleep、checker 超时）走的是 `tokio::time`，`start_paused` 下是虚拟时钟。deadline 必须
    /// 跟这些动作同一条时间轴，否则单测里 deadline 永不到点（虚拟时钟推进了，墙钟没动）= 假绿。
    ///
    /// # 「到点必须写终态」
    ///
    /// deadline 不是「到点就撒手」：每个 checker 的截止点取 `min(CHECKER_BUDGET_MS, 剩余)` 但**不低于**
    /// [`MIN_OP_BUDGET_MS`]，超时落 [`UnlockStatus::Timeout`] —— 即 deadline 到点时每个服务都拿得到一个真实
    /// 终态、快照照常 commit + emit。就绪门耗尽则提交 `notReady` 终态。**绝不留「检测中」挂着**，那正是本批修的缺陷形态。
    pub async fn run_with_budget<H, S>(
        &self,
        http: &H,
        sink: &S,
        force: bool,
        now: impl Fn() -> u64,
        budget_ms: u64,
    ) -> UnlockSnapshot
    where
        H: UnlockHttp + ?Sized,
        S: UnlockEventSink,
    {
        // ── item 7 单飞：串行化并发 run（第二者等第一者 commit 后走下方 TTL 快路，避免双网络往返）──
        let _run_guard = self.run_lock.lock().await;

        // ── TTL 快路：非 force 且缓存未过期 → 直接返回（零网络），并广播 UPDATED 让新监听者点亮 ──
        if !force {
            if let Some(cached) = self.peek(now()) {
                sink.updated(&cached);
                return cached;
            }
        }

        // ── item 2 S-gate：已提交 notReady 失败终态 → 非 force 直接返终态（防 mount/切 tab 反复重扫死出口
        //    就绪门数十秒）。解除通道 = invalidate（起停/切节点，清 last_snapshot）+ force。──
        if !force {
            if let Some(last) = self.last_snapshot() {
                if last.not_ready == Some(true) {
                    sink.updated(&last);
                    return last;
                }
            }
        }

        // ── item 5 force 硬下限：force 也不得 <15s 重打（连点触发对端限频）→ 返上次快照 ──
        //
        // **「限流」与「返什么」是两件事**：`last_snapshot` 只决定返回值，不该决定是否限流。此前二者绑在
        // 一起（无快照 ⇒ 落空、照常重跑），而「有 lastRunAt 但无快照」恰恰是**漂移丢弃轮**的形态
        // （丢弃腿经 invalidate 清了 last_snapshot）—— 后端正在自跑、对端限频风险最高的那一刻，闸门反而
        // 门户大开。故限流只看 `last_at`；无快照时返空快照：前端 `applyUnlockSnapshot` 的 no-op 守卫
        // （空 results + 无终态标记）识得它、不动现有显示，收口交给自跑那一轮的 UPDATED（其排程由漂移
        // 熔断封顶，见 [`MAX_CONSECUTIVE_DRIFT`]，故不会等一个永不到来的终态）。
        let last_at = self.last_run_at.load(Ordering::SeqCst);
        if force && last_at != 0 && now().saturating_sub(last_at) < FORCE_MIN_MS {
            let last = self.last_snapshot();
            if let Some(snap) = &last {
                sink.updated(snap);
            }
            return last.unwrap_or_default();
        }

        let epoch0 = self.epoch();
        // 整轮 deadline 从此刻起算（gating/TTL/S-gate/force-min 四条早退路径是零网络的，不吃预算）。
        let deadline = tokio::time::Instant::now() + Duration::from_millis(budget_ms);

        // ── item 2 就绪门退避：egress trace 兼作「inbound 已就绪」探针（首次即时探 + 失败退避重试 7 次 +
        //    B1 flap 确认）。拿到有效 egress = 就绪，兼作轮首出口锚（bracket）。──
        let egress0 = match self.probe_ready(http, epoch0, deadline).await {
            Some(e) => e,
            None => {
                // 退避期/探测期被 invalidate（epoch 变）→ 丢弃本轮（陈旧，不提交 notReady 污染新出口）。
                if self.epoch() != epoch0 {
                    log::debug!("解锁检测：就绪门期间被 invalidate → 丢弃本轮（由自跑重跑）");
                    return UnlockSnapshot::default();
                }
                // 真机 logLevel=warn ⇒ warn：这是「一个 checker 都没跑成」的降级终态，正是用户报「没有最终
                // 结果」时最需要在日志里看见的一条。
                log::warn!(
                    "解锁检测：就绪门未过（{READINESS_MAX_ATTEMPTS} 攻退避或 {budget_ms}ms 整轮预算耗尽）→ 提交 notReady 终态"
                );
                // 就绪门耗尽 → 提交 notReady 终态（checkedAt=null，不伪造；S-gate 兜住不重扫）。lastRunAt 置位
                // （本轮真跑了整轮就绪门网络 → force 15s 硬下限据此生效）。egress=null → 天然不入 TTL 缓存。
                self.last_run_at.store(now(), Ordering::SeqCst);
                let snap = UnlockSnapshot {
                    not_ready: Some(true),
                    ..Default::default()
                };
                // 落定终态 → 漂移连击清零（本轮连 checker 都没跑，谈不上漂移；且已有终态收口，无自持循环）。
                self.drift_streak.store(0, Ordering::SeqCst);
                self.set_last_snapshot(Some(snap.clone()));
                sink.updated(&snap);
                return snap;
            }
        };

        self.last_run_at.store(now(), Ordering::SeqCst);
        // 受限出口（CN）：海外服务 timeout 是结构性预期、非低置信瞬态 → 跳过 settle-retry + 用正常 30min TTL
        // + 不标 low_confidence（就绪门已过 → egress 必非空，此值贯穿本轮）。
        let restricted = is_restricted_egress_region(egress0.region.as_deref());

        // ── item 3 checker 主轮（单 checker 截止点 = min(CHECKER_BUDGET_MS, 整轮剩余)）：逐 settle emit progress ──
        let mut results =
            run_checkers_budgeted(http, ServiceId::ALL, deadline, |id, r| sink.progress(id, r))
                .await;

        // ── item 4 轮内 settle-retry：就绪门只证「单点连通」非「各端点已热」→ 首轮个别 checker 撞冷隧道 8s
        //    超时。commit 前仅对 timeout 项退避补测 ≤2 轮（保留高置信结果、只重打灰的，对端友好）。受限出口
        //    跳过（timeout 是结构性终态、补测无意义）。──
        if !restricted {
            for round in 1..=SETTLE_RETRY_MAX_ROUNDS {
                let timeout_ids: Vec<ServiceId> = ServiceId::ALL
                    .iter()
                    .copied()
                    .filter(|id| {
                        results
                            .get(id.as_str())
                            .is_some_and(|r| r.status == UnlockStatus::Timeout)
                    })
                    .collect();
                if timeout_ids.is_empty() {
                    break; // 全部高置信 → 快路径零额外开销
                }
                if self.epoch() != epoch0 {
                    break; // 本轮已作废 → 下方 bracket 守卫会丢弃
                }
                // deadline 判在**发 checking 之前**：跨界就直接停、保留已有 timeout 终态。若先发了 checking
                // 再停，那几个服务会永远停在「补测中」——正是本批修的「徽章转圈不落地」形态。
                let backoff = Duration::from_millis(SETTLE_RETRY_BACKOFF_MS * round);
                if tokio::time::Instant::now() + backoff >= deadline {
                    log::debug!("解锁检测：settle-retry 第 {round} 轮退避跨整轮 deadline → 停止补测，保留已有终态");
                    break;
                }
                // 灰点翻回 checking（视觉诚实：补测中，非终态）。
                for id in &timeout_ids {
                    sink.progress(id.as_str(), &UnlockResult::new(UnlockStatus::Checking));
                }
                tokio::time::sleep(backoff).await;
                if self.epoch() != epoch0 {
                    break; // 退避期间被 invalidate → 放弃本轮补测
                }
                let fresh = run_checkers_budgeted(http, &timeout_ids, deadline, |id, r| {
                    sink.progress(id, r)
                })
                .await;
                for (id, r) in fresh {
                    results.insert(id, r);
                }
            }
        }

        // ── 出口归属 bracket 确认：轮尾 egress ──
        // 同样受整轮 deadline 约束（floor MIN_OP_BUDGET_MS）：轮尾探测若无界，一次挂死的确认探就能把整轮拖成
        // 「永远不 commit」——即用户报的「一直在检测中」。超时按 None 处理，语义同「confirm 失败 ≠ 出口不符」。
        let egress1 =
            tokio::time::timeout_at(op_deadline(deadline, CHECKER_BUDGET_MS), probe_egress(http))
                .await
                .unwrap_or(None);
        // confirm 失败(None) ≠ 不符：网络瞬态不误触发丢弃（Polaris F-B）。两端都拿到但 IP 不同 = 契约外翻转。
        let egress_moved = match &egress1 {
            Some(b) => b.ip != egress0.ip,
            None => false,
        };

        // ── 归属校验：epoch 变了（并发 invalidate）或出口漂移 → 丢弃，不 commit，广播失效自动重跑 ──
        // **这是「决不把 A 出口的结果标给 B 出口」的门**。
        let epoch_changed = self.epoch() != epoch0;
        if epoch_changed || egress_moved {
            // epoch 变 = 外部真状态变化（起停/切节点），不是漂移 → 连击清零，别让「用户切了三次节点」
            // 被误算成「出口在抖」而错误熔断。
            if epoch_changed {
                self.drift_streak.store(0, Ordering::SeqCst);
            }
            // ── 漂移熔断（见 [`MAX_CONSECUTIVE_DRIFT`]）：连续 N 轮纯漂移 → 停止自持循环，落低置信终态 ──
            // 只有「纯漂移」（epoch 未变）才计数：epoch 变那条腿本就有外部触发源，不会自持。
            if egress_moved && !epoch_changed {
                let streak = self.drift_streak.fetch_add(1, Ordering::SeqCst) + 1;
                if streak >= MAX_CONSECUTIVE_DRIFT {
                    // 真机 logLevel=warn ⇒ warn：这是「为什么徽章突然不转了、且标着低置信」的唯一线索。
                    log::warn!(
                        "解锁检测：出口连续漂移 {streak} 轮（≥{MAX_CONSECUTIVE_DRIFT}）→ 熔断，落低置信终态并停止自跑排程（出口 IP 轮换快过一轮检测：负载均衡/urltest/WARP/多 IP 出口）"
                    );
                    // 归属不变式仍守住：`egress=None` —— 结果不标给**任何**出口，只如实说「测到了，但出口在抖」。
                    let snapshot = UnlockSnapshot {
                        results,
                        checked_at: Some(now()),
                        egress: None,
                        blocked_reason: None,
                        not_ready: None,
                        low_confidence: Some(true),
                    };
                    // 落定即清零：熔断掐断的是自持循环，不是把检测永久闩死。
                    self.drift_streak.store(0, Ordering::SeqCst);
                    self.set_last_snapshot(Some(snapshot.clone()));
                    // low_confidence 不入 TTL 缓存（沿用既有规则）→ 下一次真触发即重检。
                    // **必须 emit UPDATED**：这是 UI 脱离「检测中」的唯一出口（丢弃腿本身从不 emit 终态）。
                    sink.updated(&snapshot);
                    return snapshot;
                }
            }
            // warn：本轮**不产出终态**（不 commit、不 emit UPDATED），前端停在「检测中」直到 invalidate 排的
            // 自跑落地。真机 logLevel=warn 下这条是判「为什么这一轮没结果」的唯一线索。
            log::warn!(
                "解锁检测：归属校验失败（epoch 变={epoch_changed}，出口漂移={egress_moved}）→ 丢弃本轮结果，排自跑重测"
            );
            // 保留 `last_run_at`：本轮真跑过整轮网络，force 15s 硬下限必须继续生效（见 `invalidate_keep_run_at`）。
            self.invalidate_keep_run_at(sink, true, false);
            return UnlockSnapshot::default();
        }
        // 归属校验通过 → 本轮出口稳定，漂移连击中断。
        self.drift_streak.store(0, Ordering::SeqCst);

        // ── commit ──
        let egress = egress1.or(Some(egress0));
        let has_timeout = results.values().any(|r| r.status == UnlockStatus::Timeout);
        let all_timeout =
            !results.is_empty() && results.values().all(|r| r.status == UnlockStatus::Timeout);
        // **受限地区收敛**：CN 出口全超是结构性预期，不置 low_confidence（高置信终态）。
        let low_confidence = all_timeout && !restricted;

        let checked_at = now();
        let snapshot = UnlockSnapshot {
            results,
            checked_at: Some(checked_at),
            egress,
            blocked_reason: None,
            not_ready: None,
            low_confidence: low_confidence.then_some(true),
        };

        // lastSnapshot 恒记（含 lowConfidence，供 S-gate/force-min 读）；TTL `cache` 仅高置信入。
        self.set_last_snapshot(Some(snapshot.clone()));
        // TTL 挂置信度：含 timeout 且非受限 → 2min；否则（含受限全超）→ 30min（受限不 churn）。
        let ttl = if has_timeout && !restricted {
            TIMEOUT_TTL_MS
        } else {
            FRESH_TTL_MS
        };
        // low_confidence（全超瞬态、非受限）不写缓存：避免垃圾快照锁 30min（Polaris：未写 egressIp 缓存）。
        // 下一真触发即重检。仍返回 + emit UPDATED（UI 如实显、但不入缓存）。
        if !low_confidence {
            self.store(snapshot.clone(), checked_at, ttl);
        }
        // info 级：正常收口。真机 logLevel=warn 看不到本条 —— 刻意如此，「成功落终态」不是排查线索；
        // 排查靠上面那几条 warn（没落终态的路径）+ 「没有 warn」这个事实本身。
        log::info!(
            "解锁检测：一轮完成（{} 项，含 timeout={has_timeout}，低置信={low_confidence}，出口={}）",
            snapshot.results.len(),
            snapshot.egress.as_ref().map_or("-", |e| e.ip.as_str())
        );
        sink.updated(&snapshot);
        snapshot
    }

    /// **就绪门退避探测**（item 2，上游 `probeReady`）：egress trace 兼作「inbound 已就绪」探针。attempt 0
    /// 立即探（核已就绪则零延迟，如手动刷新），失败退避 `READINESS_BACKOFF_SCHEDULE_MS[attempt-1]` 重试，
    /// 至多 `READINESS_MAX_ATTEMPTS`(7) 次。**B1 自适应确认**：健康路径（一路成功）首成即就绪、零确认；疑似
    /// flap（曾失败过）成功后追加 1 次确认探（`READINESS_CONFIRM_MS` + 一探，连续 2 成才判就绪）。epoch 守卫：
    /// 退避 sleep 后 / 每次探测后比对 `epoch0`（invalidate 递增 → 立即放弃本轮返 None）。耗尽 → None。
    /// `deadline`：整轮共享死线。**每次退避/探测前判**，且单次探测按剩余收紧（`op_deadline`）——耗尽即返
    /// `None`（→ 调用方提交 notReady 终态），不空等。这是 上游「deadline 本身即上限」语义的就绪门那一段：
    /// 默认 10s 预算下累进退避在第 5 攻（累计 11.6s）越界收口，故 schedule 末段 +4/+8s 尾在默认预算下不可达，
    /// 仅作 headroom 供预算调大时启用。
    async fn probe_ready<H: UnlockHttp + ?Sized>(
        &self,
        http: &H,
        epoch0: u64,
        deadline: tokio::time::Instant,
    ) -> Option<UnlockEgress> {
        let mut ever_failed = false; // 是否曾有一攻失败（触发 B1 确认，疑似 flap）
        for attempt in 0..READINESS_MAX_ATTEMPTS {
            if attempt > 0 {
                let backoff = Duration::from_millis(
                    READINESS_BACKOFF_SCHEDULE_MS
                        .get(attempt - 1)
                        .copied()
                        .unwrap_or(8_000),
                );
                // 退避跨越 deadline → 不睡了（睡完也没预算探，纯空等）。
                if tokio::time::Instant::now() + backoff >= deadline {
                    return None;
                }
                tokio::time::sleep(backoff).await;
                if self.epoch() != epoch0 {
                    return None; // 退避期间被 invalidate → 放弃本轮
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return None; // 预算耗尽
            }
            let egress = probe_with_deadline(http, deadline).await;
            if self.epoch() != epoch0 {
                return None; // 探测期间被 invalidate → 放弃本轮
            }
            match egress {
                Some(e) => {
                    if !ever_failed {
                        return Some(e); // 健康路径：首攻/一路成 → 直接就绪，零代价
                    }
                    // B1：疑似 flap（曾失败）→ 追加 1 次确认（连续 2 成才判就绪；确认失败则续 schedule）。
                    let confirm_gap = Duration::from_millis(READINESS_CONFIRM_MS);
                    if tokio::time::Instant::now() + confirm_gap >= deadline {
                        // 没预算做确认探 → 直接采信这次成功（有 egress 好过 notReady 空转）。
                        return Some(e);
                    }
                    tokio::time::sleep(confirm_gap).await;
                    if self.epoch() != epoch0 {
                        return None;
                    }
                    let confirm = probe_with_deadline(http, deadline).await;
                    if self.epoch() != epoch0 {
                        return None;
                    }
                    if confirm.is_some() {
                        return Some(e); // 2 连成 → 就绪
                    }
                    ever_failed = true; // 确认失败 → 本轮不判就绪，续下一攻 schedule
                }
                None => ever_failed = true,
            }
        }
        None // 重试耗尽，未就绪
    }

    /// **warm 补测**（#6 partial-timeout 自愈）：重打上轮 timeout 的服务，结果 merge 进缓存并广播。
    ///
    /// epoch 守卫（`epoch0` = 调度时的世代）：补测期间有 invalidate（epoch 变）→ 丢弃，
    /// **别把旧出口的补测结果标给新出口**。无缓存/无 timeout 项 → no-op 返 false。
    /// 生产由 command 层 `tokio::spawn(sleep(WARM_RECHECK_DELAY_MS) + run_recheck)` 调度。
    pub async fn run_recheck<H, S>(
        &self,
        http: &H,
        sink: &S,
        epoch0: u64,
        now: impl Fn() -> u64,
    ) -> bool
    where
        H: UnlockHttp + ?Sized,
        S: UnlockEventSink,
    {
        // item 7 单飞：与 run 共用锁——补测不与并发 run 抢网络（command 层在 run 完成后 5s spawn 本腿，
        // 正常已无竞争；持锁兜并发触发面）。
        let _run_guard = self.run_lock.lock().await;
        // 取当前缓存快照 + 其 timeout 服务集（快照可能已被 invalidate 清空 → no-op）。
        let (mut snapshot, timeout_ids) = {
            let guard = match self.cache.lock() {
                Ok(g) => g,
                Err(_) => return false,
            };
            let Some(cached) = guard.as_ref() else {
                return false;
            };
            let ids: Vec<ServiceId> = ServiceId::ALL
                .iter()
                .copied()
                .filter(|id| {
                    cached
                        .snapshot
                        .results
                        .get(id.as_str())
                        .is_some_and(|r| r.status == UnlockStatus::Timeout)
                })
                .collect();
            (cached.snapshot.clone(), ids)
        };
        if timeout_ids.is_empty() {
            return false;
        }

        // 重打 timeout 项（并发；每 checker CHECKER_BUDGET_MS 封顶 item 3；**先收集不即时 emit**——补测期间
        // 可能 invalidate，须先过 epoch 门再 emit，否则会漏发一两个旧出口的 progress）。
        // 补测轮自成一条 deadline（它是 commit 之后 5s 才起的独立一轮，不共享主轮预算）。
        let deadline =
            tokio::time::Instant::now() + Duration::from_millis(TOTAL_DETECTION_BUDGET_MS);
        let fresh = run_checkers_budgeted(http, &timeout_ids, deadline, |_, _| {}).await;

        // epoch 守卫：补测期间有 invalidate → 丢弃（归属 bracket 的补测腿），一个 emit 都不发。
        if self.epoch() != epoch0 {
            return false;
        }

        for (id, result) in &fresh {
            sink.progress(id, result);
            snapshot.results.insert(id.clone(), result.clone());
        }
        let t = now();
        snapshot.checked_at = Some(t);
        let has_timeout = snapshot
            .results
            .values()
            .any(|r| r.status == UnlockStatus::Timeout);
        let restricted =
            is_restricted_egress_region(snapshot.egress.as_ref().and_then(|e| e.region.as_deref()));
        let ttl = if has_timeout && !restricted {
            TIMEOUT_TTL_MS
        } else {
            FRESH_TTL_MS
        };
        // lastSnapshot 同步（补测复过的 timeout 已是可信终态，供 S-gate/force-min）；TTL cache 恒写（含 timeout
        // 由 R3 短 TTL 兜底，2min 后可再自然重检）。
        self.set_last_snapshot(Some(snapshot.clone()));
        self.store(snapshot.clone(), t, ttl);
        sink.updated(&snapshot);
        true
    }
}

/// 单次网络操作的截止点：不晚于整轮 `deadline`、不晚于 `now + budget_ms`，但**至少** [`MIN_OP_BUDGET_MS`]。
///
/// 那条 floor 是有意的（上游 `MIN_OP_BUDGET_MS` 同款）：deadline 逼近时按剩余收紧会算出 0/负值，发出去的
/// 是必然失败的退化请求。宁可整轮超出 deadline 至多 500ms，也要让每个操作有一次真实机会 —— 换来的是
/// **每个 checker 都拿得到终态**，而不是一堆没跑就判超时的假结果。
fn op_deadline(deadline: tokio::time::Instant, budget_ms: u64) -> tokio::time::Instant {
    let now = tokio::time::Instant::now();
    let capped = deadline.min(now + Duration::from_millis(budget_ms));
    capped.max(now + Duration::from_millis(MIN_OP_BUDGET_MS))
}

/// 受整轮 deadline 约束的 egress 探测：超时按「探不到」处理（与网络失败同路，交退避重试腿）。
async fn probe_with_deadline<H: UnlockHttp + ?Sized>(
    http: &H,
    deadline: tokio::time::Instant,
) -> Option<UnlockEgress> {
    tokio::time::timeout_at(op_deadline(deadline, CHECKER_BUDGET_MS), probe_egress(http))
        .await
        .unwrap_or(None)
}

/// 并发跑指定服务子集的 checker，**每 checker 用 `min(CHECKER_BUDGET_MS, 整轮剩余)` 封顶**（item 3），逐 settle 回调
/// `on_settle(serviceId, &result)`，返回 serviceId → UnlockResult。
///
/// 为何自建而非调 crate `run_checkers_with_progress`：① crate 版内部无预算，Disney 主链+备法可 4 连请求
/// 串联、最坏尾延迟累加远超单请求 8s → 此处 `tokio::time::timeout` 对**整个 checker** 封顶，超预算落
/// `Timeout`（有界即可，非精确；底层请求各自 8s 传输超时惰性释放，不铺 AbortSignal 全栈，对齐 上游 E2）；
/// ② 预算需 timer（`tokio::time`），而 unlock crate 无生产 tokio 依赖（纯逻辑层），故预算只能在此运行时层。
///
/// **并发实现**：手写 `poll_fn` 并发轮询（等价 `FuturesUnordered`，语义=并发齐射 + 逐 settle 回调 + 错误隔离）
/// ——**src-tauri 的 `futures` 仅 dev-dependency**（见 `stats.rs` 注：本仓生产禁 `futures` 依赖），故不用
/// `FuturesUnordered`。集合有界（≤6 服务），每次唤醒 O(N) 重轮询代价可忽略。
async fn run_checkers_budgeted<H, F>(
    http: &H,
    ids: &[ServiceId],
    deadline: tokio::time::Instant,
    mut on_settle: F,
) -> BTreeMap<String, UnlockResult>
where
    H: UnlockHttp + ?Sized,
    F: FnMut(&str, &UnlockResult),
{
    use std::future::Future;
    use std::pin::Pin;
    use std::task::Poll;

    // 单 checker 截止点 = min(CHECKER_BUDGET_MS, 整轮剩余)，floor 于 MIN_OP_BUDGET_MS。
    // **每个 checker 必落终态**：超时 → Timeout，不留 Checking 挂着。
    let cap = op_deadline(deadline, CHECKER_BUDGET_MS);
    type Fut<'a> = Pin<Box<dyn Future<Output = UnlockResult> + Send + 'a>>;
    let mut pending: Vec<(ServiceId, Fut<'_>)> = ids
        .iter()
        .map(|&id| {
            let fut: Fut<'_> = Box::pin(async move {
                match tokio::time::timeout_at(cap, run_checker(id, http)).await {
                    Ok(r) => r,
                    Err(_) => UnlockResult::timeout(), // 超预算 → timeout（Disney 4 连请求尾延迟兜底）
                }
            });
            (id, fut)
        })
        .collect();

    let mut out = BTreeMap::new();
    // 并发轮询：每次外层被唤醒即遍历未决 future，settle 的立即回调 + 移出（共享外层 waker，任一就绪即重轮询）。
    std::future::poll_fn(|cx| {
        let mut i = 0;
        while i < pending.len() {
            match pending[i].1.as_mut().poll(cx) {
                Poll::Ready(result) => {
                    let (id, _) = pending.remove(i); // 移出已 settle（不自增 i，remove 已左移）
                    on_settle(id.as_str(), &result);
                    out.insert(id.as_str().to_string(), result);
                }
                Poll::Pending => i += 1,
            }
        }
        if pending.is_empty() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
    out
}

#[cfg(test)]
mod tests;
