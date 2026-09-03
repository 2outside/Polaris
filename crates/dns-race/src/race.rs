//! 节点域名解析竞速转发核心 —— 上游 `shared/node-dns-race.ts` 1:1 移植。
//!
//! 上游查询经 [`UpstreamQuery`] 注入 ⟹ **本模块单测零网络**（mock 上游即可穷举四态）。
//!
//! ## 四态竞速
//! - **HIT 抢跑**：任一上游返回 NOERROR + 含 qtype 记录 → 立即取该上游【完整响应 wire】透传
//!   （回填内核 query id），其余 in-flight 取消；
//! - **POISONED（first-clean-wins）**：HIT 但答案 IP ∈ GFW decoy 段 → 弃之、**不抢跑**、按 FAIL 递减
//!   （等干净上游胜出）；全 settle 只剩 POISONED → 当 FAIL 走 SERVFAIL（fail-safe：宁可失败重试，
//!   也不把用户连到投毒 IP）；
//! - **EMPTY 不抢跑**：空解析（NODATA/NXDOMAIN）不立即用 —— 等本层全部 settle 才下「空」结论
//!   （否则一个快的 NXDOMAIN 会盖掉慢的真答案）；
//! - **FAIL ≠ EMPTY**：上游故障（SERVFAIL/超时/畸形/TC）不算答案；全 FAIL → SERVFAIL。
//!
//! ## Tier 分层
//! 先 Tier1（加密 DoH）抢跑；Tier1 全无 HIT 才查 Tier2（明文/system 兜底，**不**与 Tier1 抢跑）。
//! 整体受 `total_budget` 硬约束。
//!
//! ## 取消语义（TS AbortController → Rust）
//! TS 侧靠 `AbortController` 显式取消其余上游；Rust 侧 future 天然「drop 即取消」——
//! 抢跑时直接 `return`，[`FuturesUnordered`] 随栈销毁把未完成的上游查询一并析构。
//! 预算到点同理。故不需要、也**不应该**再造一层 abort 标志（那会是第二个真值）。

#![forbid(unsafe_code)]

use std::time::Duration;

use async_trait::async_trait;
use futures::stream::{FuturesUnordered, StreamExt};
use tokio::time::Instant;

use crate::decoy::DecoySet;
use crate::upstream::{ResolveUpstream, ResolvedUpstreams};
use crate::wire::{
    build_servfail, classify_dns_response, decode_dns_question, extract_answer_ip_bytes,
    set_dns_message_id, DnsResponseClass,
};

/// 竞速总预算（上游 `DEFAULT_RACE_BUDGET_MS`）。超时即用已有 EMPTY 收口，无 EMPTY 则 SERVFAIL。
pub const DEFAULT_RACE_BUDGET: Duration = Duration::from_millis(2000);

/// 单上游查询注入面：发 query wire → 响应 wire。
///
/// `Err` ⟺ FAIL（超时 / 网络错 / 拒绝 / 不支持的上游形态）。实现方**必须**自带单上游超时，
/// 否则一个永不返回的上游会把本层拖到总预算耗尽（见 [`crate::query::DefaultUpstreamQuery`]）。
#[async_trait]
pub trait UpstreamQuery: Send + Sync {
    async fn query(&self, upstream: &ResolveUpstream, query: &[u8]) -> Result<Vec<u8>, String>;
}

/// HIT 响应的答案 IP 是否含 GFW decoy 段（→ 判 POISONED，弃之）。上游 `isPoisonedResponse`。
///
/// `decoys` 由调用方注入而非直读内置常量：段表要能跟 geo 资源同节奏更新（见 [`DecoySet`] 模块文档），
/// 而读文件/挑路径不属于本 crate —— 注入是唯一能同时保住「可更新」与「纯函数、零 I/O」的形态。
fn is_poisoned_response(resp: &[u8], decoys: &DecoySet) -> bool {
    extract_answer_ip_bytes(resp)
        .iter()
        .any(|ip| decoys.contains(ip))
}

/// 单层竞速结果。`hit` 有值 ⟺ 本层抢跑成功。
#[derive(Debug, Default)]
struct TierResult {
    hit: Option<Vec<u8>>,
    /// 本层见到的**第一个** EMPTY 整包（保留原始 NXDOMAIN/NODATA 语义透传给内核）。
    empty: Option<Vec<u8>>,
}

/// 单层竞速：并发查一组上游。HIT 抢跑（first-clean-wins）；无 HIT 则等全部 settle。
/// 预算到点 → 用已收集到的 EMPTY 收口（未完成的上游随 `FuturesUnordered` drop 取消）。
async fn race_tier(
    query: &[u8],
    qtype: u16,
    upstreams: &[ResolveUpstream],
    fetch: &dyn UpstreamQuery,
    deadline: Instant,
    decoys: &DecoySet,
) -> TierResult {
    if upstreams.is_empty() {
        return TierResult::default();
    }
    let mut inflight: FuturesUnordered<_> = upstreams
        .iter()
        .map(|up| async move { fetch.query(up, query).await })
        .collect();
    let mut empty: Option<Vec<u8>> = None;
    let timer = tokio::time::sleep_until(deadline);
    tokio::pin!(timer);
    loop {
        tokio::select! {
            settled = inflight.next() => match settled {
                None => return TierResult { hit: None, empty }, // 本层全部 settle，无 HIT
                Some(Err(_)) => {}                              // FAIL：不抢跑，继续等其余
                Some(Ok(resp)) => match classify_dns_response(&resp, qtype) {
                    DnsResponseClass::Hit => {
                        // first-clean-wins：HIT 但答案含 GFW decoy → POISONED，弃之、按 FAIL 递减。
                        // 删掉这一段 = 投毒应答会抢跑（它总是最快的那个）→ 用户被连到伪造 IP。
                        if is_poisoned_response(&resp, decoys) {
                            // 按条 `debug` + 计数，会话结束由停 sidecar 腿汇总一条 INFO：
                            // 这是**防护生效**的标志而非异常，按条 WARN 会把真异常淹掉（见 `stats` 模块）。
                            crate::stats::record_poisoned_dropped();
                            log::debug!(
                                "dns-race: 上游 {} 返回 decoy 答案，判 POISONED 丢弃（first-clean-wins）",
                                upstream_label(upstreams, &resp)
                            );
                            continue;
                        }
                        return TierResult { hit: Some(resp), empty };
                    }
                    DnsResponseClass::Empty => {
                        if empty.is_none() {
                            empty = Some(resp); // 记下但**不**抢跑
                        }
                    }
                    DnsResponseClass::Fail => {}
                },
            },
            () = &mut timer => return TierResult { hit: None, empty },
        }
    }
}

/// POISONED 日志里的上游标识。`FuturesUnordered` 不保序、拿不回是哪个上游返回的，故只报本层规模
/// （漂移信号看的是**计数**不是归属）。单独抽出来是为了让 `race_tier` 主流程不被字符串拼装淹没。
fn upstream_label(upstreams: &[ResolveUpstream], resp: &[u8]) -> String {
    format!("(本层 {} 个之一，应答 {}B)", upstreams.len(), resp.len())
}

/// 竞速转发主入口：内核 query wire → 四态竞速（Tier1 抢跑 → Tier2 兜底）→ 响应 wire（回填内核 id）。
///
/// **绝不返回 Err**（fail-open 第一层）：畸形 query / 全上游 FAIL / 预算耗尽一律回 SERVFAIL ——
/// 挂着不回会让内核那条 Lookup 一直等到它自己的超时，比明确失败更糟。
/// HIT / EMPTY 透传命中上游的【完整响应】（多 A / TTL / CNAME 全保留，供内核 DialSerial 逐 IP 重试）。
pub async fn race_forward(
    query: &[u8],
    upstreams: &ResolvedUpstreams,
    fetch: &dyn UpstreamQuery,
    total_budget: Duration,
    decoys: &DecoySet,
) -> Vec<u8> {
    let Some(q) = decode_dns_question(query) else {
        return build_servfail(query);
    };
    let deadline = Instant::now() + total_budget;

    // 阶段 1：Tier1 抢跑。
    let r1 = race_tier(query, q.qtype, &upstreams.tier1, fetch, deadline, decoys).await;
    if let Some(hit) = r1.hit {
        return set_dns_message_id(&hit, q.id);
    }
    let mut empty = r1.empty;

    // 阶段 2：Tier1 无 HIT 且预算未尽 → Tier2 兜底（不与 Tier1 抢跑）。
    if Instant::now() < deadline && !upstreams.tier2.is_empty() {
        let r2 = race_tier(query, q.qtype, &upstreams.tier2, fetch, deadline, decoys).await;
        if let Some(hit) = r2.hit {
            return set_dns_message_id(&hit, q.id);
        }
        if empty.is_none() {
            empty = r2.empty;
        }
    }

    // 阶段 3：有 EMPTY → 如实空（NODATA/NXDOMAIN 透传，回填 id）；全 FAIL → SERVFAIL。
    match empty {
        Some(e) => set_dns_message_id(&e, q.id),
        None => build_servfail(query),
    }
}

#[cfg(test)]
mod tests;
