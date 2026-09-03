//! 检测调度 + 结果聚合 —— 纯逻辑层。
//!
//! 移植自 上游 `UnlockDetectionService.doRun` 的**检测核心**，剥离 Electron/状态机壳：
//! - **保留**：egress trace（probe_egress）+ 全 checker 并发齐射（detect_all）+ 结果聚合为快照（detect）。
//! - **不移植**（属 B7 应用层）：session pin/proxy（electron Session）、缓存 TTL/egressIp key、epoch 失效、
//!   就绪门退避、settle-retry、partial-timeout warm 补测、F-B 出口归属 bracket、force 硬下限、IPC 事件广播。
//!   这些都是与宿主网络/进程状态强耦合的编排策略，留给 B7 Tauri 应用层基于本纯逻辑层重建。
//!
//! 这样本 crate 的 gate = 纯函数测试（mock HTTP -> 判定），不触碰宿主网络。

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::checkers::run_checker;
use crate::endpoints::{EGRESS_TRACE_URL, UA};
use crate::http::{UnlockHttp, UnlockRequest};
use crate::trace::parse_trace;
use crate::types::{ServiceId, UnlockEgress, UnlockResult, UnlockSnapshot};

/// 受限地区集合（出口位于其中时，海外服务 timeout 是结构性预期）。上游 `RESTRICTED_EGRESS_REGIONS`。
pub const RESTRICTED_EGRESS_REGIONS: &[&str] = &["CN"];

/// 出口 region 是否属受限地区。上游 `isRestrictedEgressRegion`。
pub fn is_restricted_egress_region(region: Option<&str>) -> bool {
    region
        .map(|r| RESTRICTED_EGRESS_REGIONS.contains(&r.to_uppercase().as_str()))
        .unwrap_or(false)
}

/// 当前 Unix 毫秒时间戳。Polaris 用 `Date.now()`。
///
/// 生产路径上由 B7 应用层注入时钟（测时钟）；此处提供默认实现便于 detect() 单发使用。
/// 测试经 [`UnlockDetector::detect_with_clock`] 注入冻结时钟。
pub fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 打出口 trace 探针，返回 egress（ip + region）。失败返 None（不 panic）。上游 `probeEgress`。
///
/// 单次探测，无退避重试（重试/就绪门属 B7 应用层编排）。trace 解析失败（portal/截断假响应）-> None。
pub async fn probe_egress<H: UnlockHttp + ?Sized>(http: &H) -> Option<UnlockEgress> {
    let res = http
        .request(&UnlockRequest::get(EGRESS_TRACE_URL).header("User-Agent", UA))
        .await;
    if res.status != 200 || res.body.is_empty() {
        return None;
    }
    let info = parse_trace(&res.body)?;
    Some(UnlockEgress {
        ip: info.ip,
        region: info.country_code,
    })
}

/// 并发检测 [`ServiceId::ALL`] 全部服务，返回 serviceId -> UnlockResult 的 map。
/// 上游 `Promise.allSettled(SERVICE_IDS.map(runOne))`。
///
/// 每服务独立兜底：checker 内部异常（不应发生）落 Timeout，不影响其他服务结果。
/// 顺序与 [`ServiceId::ALL`] 一致（BTreeMap 按 key 字面量排序，序列化稳定）。
pub async fn detect_all<H: UnlockHttp + ?Sized>(http: &H) -> BTreeMap<String, UnlockResult> {
    // 并发齐射全部 checker。每个 future 自兜底 timeout，单服务失败不波及他者。
    let results = futures::future::join_all(ServiceId::ALL.iter().map(|&id| async move {
        let result = run_checker(id, http).await;
        (id, result)
    }))
    .await;
    results
        .into_iter()
        .map(|(id, r)| (id.as_str().to_string(), r))
        .collect()
}

/// 并发跑**指定服务子集**的 checker，**逐 settle 回调** `on_settle`，返回 serviceId -> UnlockResult。
///
/// 与 [`detect_all`] 的差别：① 可只跑子集（warm 补测只重打 timeout 项）；② 提供逐完成回调
/// （B7 应用层据此 emit `EVENT_UNLOCK_PROGRESS` 逐个点亮 badge，而非全 settle 后一次性）。
/// 并发语义同 `detect_all`（`FuturesUnordered` 并发齐射 + 错误隔离，单服务失败不波及他者）。
///
/// `ids` 为空 → 空 map（无 checker，`on_settle` 不触发）。顺序 = settle 顺序（非 `ids` 顺序）。
pub async fn run_checkers_with_progress<H, F>(
    http: &H,
    ids: &[ServiceId],
    mut on_settle: F,
) -> BTreeMap<String, UnlockResult>
where
    H: UnlockHttp + ?Sized,
    F: FnMut(ServiceId, &UnlockResult),
{
    use futures::stream::{FuturesUnordered, StreamExt};
    // 装箱以获得可命名类型：`ids` 为空时 `FuturesUnordered::new()` 无从推断 Item（E0282）。
    type Settled<'a> =
        std::pin::Pin<Box<dyn std::future::Future<Output = (ServiceId, UnlockResult)> + Send + 'a>>;
    let mut inflight: FuturesUnordered<Settled<'_>> = FuturesUnordered::new();
    for &id in ids {
        inflight.push(Box::pin(async move { (id, run_checker(id, http).await) }));
    }
    let mut out = BTreeMap::new();
    while let Some((id, result)) = inflight.next().await {
        on_settle(id, &result);
        out.insert(id.as_str().to_string(), result);
    }
    out
}

/// 检测调度器：egress 探测 + 全服务并发检测 + 聚合为完整快照。上游 `doRun` 核心。
///
/// 这是纯逻辑「跑一轮」：不涉缓存/失效/退避/gating（那些属 B7 应用层编排）。
/// - egress 探测失败（出口 trace 不可达）-> 仍跑 checker（Polaris 中 egress=null 但 checker 照跑），
///   只是不带 egress 字段。调用方（B7）可据 egress=None 走就绪门重试。
/// - `checked_at` 由注入时钟决定（默认系统时间）。
pub struct UnlockDetector;

impl UnlockDetector {
    /// 跑一轮完整检测：egress + 全部 checker（[`ServiceId::ALL`]）并发，返回终态快照。
    pub async fn detect<H: UnlockHttp + ?Sized>(http: &H) -> UnlockSnapshot {
        Self::detect_with_clock(http, unix_millis).await
    }

    /// 同 [`Self::detect`]，但注入时钟（测试冻结时间用）。
    pub async fn detect_with_clock<H: UnlockHttp + ?Sized>(
        http: &H,
        now: impl Fn() -> u64,
    ) -> UnlockSnapshot {
        // egress 探测与 checker 主轮可并发（Polaris 也是先 probe 再 run，但 egress 不 gate checker）。
        // 此处并发以省 wall-clock（trace 与 checker 共享同 http，但请求间无依赖）。
        let (egress, results) = futures::future::join(probe_egress(http), detect_all(http)).await;
        UnlockSnapshot {
            results,
            checked_at: Some(now()),
            egress,
            blocked_reason: None,
            not_ready: None,
            low_confidence: None,
        }
    }
}

#[cfg(test)]
mod tests;
