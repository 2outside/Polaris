use super::*;
use crate::upstream::{resolve_upstreams, UpstreamKind};
use crate::wire::{
    build_answer_response, encode_dns_query, AnswerRecord, DnsResponseClass, TYPE_A,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// 单个上游的脚本化行为。**零网络**：只是延时后吐一段预置 wire（或报错）。
#[derive(Clone)]
enum Script {
    /// 延时后返回给定响应。
    Reply(Duration, Vec<u8>),
    /// 延时后 FAIL。
    Fail(Duration),
    /// 永不返回（模拟挂死上游；由预算兜）。
    Hang,
}

/// mock 上游查询：按上游 id 派发脚本，并记录被真正查过的上游（验「Tier2 不与 Tier1 抢跑」）。
struct MockQuery {
    scripts: HashMap<String, Script>,
    calls: Arc<std::sync::Mutex<Vec<String>>>,
    concurrent_peak: Arc<AtomicUsize>,
    live: Arc<AtomicUsize>,
}

impl MockQuery {
    fn new(scripts: &[(&str, Script)]) -> Self {
        Self {
            scripts: scripts
                .iter()
                .map(|(k, v)| ((*k).to_string(), v.clone()))
                .collect(),
            calls: Arc::new(std::sync::Mutex::new(Vec::new())),
            concurrent_peak: Arc::new(AtomicUsize::new(0)),
            live: Arc::new(AtomicUsize::new(0)),
        }
    }
    fn queried(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl UpstreamQuery for MockQuery {
    async fn query(&self, up: &ResolveUpstream, _q: &[u8]) -> Result<Vec<u8>, String> {
        self.calls.lock().unwrap().push(up.id.clone());
        let live = self.live.fetch_add(1, Ordering::SeqCst) + 1;
        self.concurrent_peak.fetch_max(live, Ordering::SeqCst);
        let script = self
            .scripts
            .get(&up.id)
            .cloned()
            .unwrap_or(Script::Fail(Duration::from_millis(1)));
        let out = match script {
            Script::Reply(d, wire) => {
                tokio::time::sleep(d).await;
                Ok(wire)
            }
            Script::Fail(d) => {
                tokio::time::sleep(d).await;
                Err("mock fail".into())
            }
            Script::Hang => {
                std::future::pending::<()>().await;
                unreachable!()
            }
        };
        self.live.fetch_sub(1, Ordering::SeqCst);
        out
    }
}

fn q_wire() -> Vec<u8> {
    encode_dns_query("node.example.com", TYPE_A, 0x4242)
}

fn a_reply(q: &[u8], ips: &[[u8; 4]]) -> Vec<u8> {
    let answers: Vec<AnswerRecord> = ips
        .iter()
        .map(|ip| AnswerRecord {
            rtype: TYPE_A,
            rdata: ip.to_vec(),
        })
        .collect();
    // 用不同的 message id 造响应，验「透传前必须回填内核 id」。
    let mut r = build_answer_response(q, &answers);
    r[0] = 0xff;
    r[1] = 0xff;
    r
}

fn ups(pool: &[&str]) -> ResolvedUpstreams {
    resolve_upstreams(
        &pool.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(),
        &[],
    )
}

#[tokio::test]
async fn hit_wins_and_message_id_is_rewritten() {
    let q = q_wire();
    let mock = MockQuery::new(&[
        (
            "ali",
            Script::Reply(Duration::from_millis(5), a_reply(&q, &[[1, 2, 3, 4]])),
        ),
        ("dnspod", Script::Fail(Duration::from_millis(1))),
    ]);
    let out = race_forward(
        &q,
        &ups(&["ali", "dnspod"]),
        &mock,
        DEFAULT_RACE_BUDGET,
        &DecoySet::builtin(),
    )
    .await;
    assert_eq!(classify_dns_response(&out, TYPE_A), DnsResponseClass::Hit);
    assert_eq!(&out[..2], &q[..2], "响应 id 必须回填成内核 query 的 id");
    assert_eq!(
        &out[12..],
        &a_reply(&q, &[[1, 2, 3, 4]])[12..],
        "整包透传，不重编码"
    );
}

/// 【不变式：first-clean-wins 剔 decoy】
/// 变异验证：删掉 `race_tier` 里的 `is_poisoned_response` 分支（让 POISONED 走正常 HIT 抢跑）
/// → 本测试拿到 31.13.95.169 而非 93.184.216.34 → 转红。
#[tokio::test]
async fn poisoned_hit_is_discarded_and_clean_slow_upstream_wins() {
    let q = q_wire();
    let mock = MockQuery::new(&[
        // 投毒应答**更快**（GFW 抢答的真实形态）。
        (
            "ali",
            Script::Reply(Duration::from_millis(1), a_reply(&q, &[[31, 13, 95, 169]])),
        ),
        // 干净答案慢 30ms。
        (
            "dnspod",
            Script::Reply(
                Duration::from_millis(30),
                a_reply(&q, &[[93, 184, 216, 34]]),
            ),
        ),
    ]);
    let out = race_forward(
        &q,
        &ups(&["ali", "dnspod"]),
        &mock,
        DEFAULT_RACE_BUDGET,
        &DecoySet::builtin(),
    )
    .await;
    assert_eq!(
        extract_answer_ip_bytes(&out),
        vec![vec![93, 184, 216, 34]],
        "decoy 抢答必须被弃，干净上游胜出"
    );
}

/// 全上游都投毒 → 当 FAIL 处理 → SERVFAIL（fail-safe：宁可失败重试，也不连 decoy）。
#[tokio::test]
async fn all_poisoned_degrades_to_servfail_not_decoy() {
    let q = q_wire();
    let mock = MockQuery::new(&[
        (
            "ali",
            Script::Reply(Duration::from_millis(1), a_reply(&q, &[[31, 13, 95, 169]])),
        ),
        (
            "dnspod",
            Script::Reply(Duration::from_millis(2), a_reply(&q, &[[157, 240, 17, 35]])),
        ),
    ]);
    let out = race_forward(
        &q,
        &ups(&["ali", "dnspod"]),
        &mock,
        DEFAULT_RACE_BUDGET,
        &DecoySet::builtin(),
    )
    .await;
    assert_eq!(classify_dns_response(&out, TYPE_A), DnsResponseClass::Fail);
    assert_eq!(out[3] & 0x0f, 2, "RCODE=SERVFAIL");
}

/// 【不变式：fail-open】全上游 FAIL / 上游挂死 / 畸形 query —— 一律有回包，绝不挂着不回。
/// 变异验证：把阶段 3 的 `None => build_servfail(query)` 改成返回空 `Vec` 或让函数 hang
/// → 本测试转红（收不到合法 SERVFAIL / 超时）。
#[tokio::test]
async fn all_fail_returns_servfail_with_echoed_id() {
    let q = q_wire();
    let mock = MockQuery::new(&[
        ("ali", Script::Fail(Duration::from_millis(1))),
        ("dnspod", Script::Fail(Duration::from_millis(2))),
    ]);
    let out = race_forward(
        &q,
        &ups(&["ali", "dnspod"]),
        &mock,
        DEFAULT_RACE_BUDGET,
        &DecoySet::builtin(),
    )
    .await;
    assert!(out.len() >= 12);
    assert_eq!(&out[..2], &q[..2], "SERVFAIL 也要回声 id，否则内核直接丢弃");
    assert_eq!(out[3] & 0x0f, 2, "RCODE=SERVFAIL");
    assert_eq!(out[2] & 0x80, 0x80, "QR=1");
}

#[tokio::test]
async fn hung_upstreams_are_cut_by_total_budget() {
    let q = q_wire();
    let mock = MockQuery::new(&[("ali", Script::Hang), ("dnspod", Script::Hang)]);
    let t0 = std::time::Instant::now();
    let out = race_forward(
        &q,
        &ups(&["ali", "dnspod"]),
        &mock,
        Duration::from_millis(60),
        &DecoySet::builtin(),
    )
    .await;
    assert!(
        t0.elapsed() < Duration::from_secs(2),
        "必须被预算切断，不等到天荒地老"
    );
    assert_eq!(out[3] & 0x0f, 2, "预算耗尽且无 EMPTY → SERVFAIL");
}

#[tokio::test]
async fn malformed_query_returns_servfail_without_touching_upstreams() {
    let mock = MockQuery::new(&[]);
    let out = race_forward(
        &[0u8; 5],
        &ups(&["ali"]),
        &mock,
        DEFAULT_RACE_BUDGET,
        &DecoySet::builtin(),
    )
    .await;
    assert!(out.len() >= 12);
    assert!(mock.queried().is_empty(), "畸形 query 不该打上游");
}

#[tokio::test]
async fn empty_does_not_preempt_and_is_only_used_after_all_settle() {
    let q = q_wire();
    // ali 秒回 NODATA，dnspod 30ms 后回真答案 —— EMPTY 不得抢跑。
    let mock = MockQuery::new(&[
        (
            "ali",
            Script::Reply(Duration::from_millis(1), a_reply(&q, &[])),
        ),
        (
            "dnspod",
            Script::Reply(Duration::from_millis(30), a_reply(&q, &[[5, 6, 7, 8]])),
        ),
    ]);
    let out = race_forward(
        &q,
        &ups(&["ali", "dnspod"]),
        &mock,
        DEFAULT_RACE_BUDGET,
        &DecoySet::builtin(),
    )
    .await;
    assert_eq!(extract_answer_ip_bytes(&out), vec![vec![5, 6, 7, 8]]);
}

#[tokio::test]
async fn empty_is_passed_through_when_every_upstream_says_empty() {
    let q = q_wire();
    let mock = MockQuery::new(&[
        (
            "ali",
            Script::Reply(Duration::from_millis(1), a_reply(&q, &[])),
        ),
        (
            "dnspod",
            Script::Reply(Duration::from_millis(2), a_reply(&q, &[])),
        ),
    ]);
    let out = race_forward(
        &q,
        &ups(&["ali", "dnspod"]),
        &mock,
        DEFAULT_RACE_BUDGET,
        &DecoySet::builtin(),
    )
    .await;
    assert_eq!(classify_dns_response(&out, TYPE_A), DnsResponseClass::Empty);
    assert_eq!(&out[..2], &q[..2]);
    assert_ne!(out[3] & 0x0f, 2, "空解析不得伪装成 SERVFAIL");
}

#[tokio::test]
async fn tier2_is_not_queried_when_tier1_hits() {
    let q = q_wire();
    let mock = MockQuery::new(&[
        (
            "ali",
            Script::Reply(Duration::from_millis(2), a_reply(&q, &[[1, 1, 1, 1]])),
        ),
        (
            "system",
            Script::Reply(Duration::from_millis(1), a_reply(&q, &[[2, 2, 2, 2]])),
        ),
    ]);
    let u = ups(&["ali", "system"]);
    assert_eq!(u.tier2[0].kind, UpstreamKind::System);
    let out = race_forward(&q, &u, &mock, DEFAULT_RACE_BUDGET, &DecoySet::builtin()).await;
    assert_eq!(extract_answer_ip_bytes(&out), vec![vec![1, 1, 1, 1]]);
    assert_eq!(mock.queried(), vec!["ali"], "Tier1 命中 → Tier2 一次都不打");
}

#[tokio::test]
async fn tier2_backs_up_when_tier1_all_fail() {
    let q = q_wire();
    let mock = MockQuery::new(&[
        ("ali", Script::Fail(Duration::from_millis(1))),
        ("dnspod", Script::Fail(Duration::from_millis(1))),
        (
            "system",
            Script::Reply(Duration::from_millis(2), a_reply(&q, &[[3, 3, 3, 3]])),
        ),
    ]);
    let out = race_forward(
        &q,
        &ups(&["ali", "dnspod", "system"]),
        &mock,
        DEFAULT_RACE_BUDGET,
        &DecoySet::builtin(),
    )
    .await;
    assert_eq!(extract_answer_ip_bytes(&out), vec![vec![3, 3, 3, 3]]);
}

#[tokio::test]
async fn tier1_upstreams_run_concurrently_not_serially() {
    let q = q_wire();
    let mock = MockQuery::new(&[
        ("ali", Script::Fail(Duration::from_millis(40))),
        (
            "dnspod",
            Script::Reply(Duration::from_millis(5), a_reply(&q, &[[4, 4, 4, 4]])),
        ),
    ]);
    let t0 = std::time::Instant::now();
    let out = race_forward(
        &q,
        &ups(&["ali", "dnspod"]),
        &mock,
        DEFAULT_RACE_BUDGET,
        &DecoySet::builtin(),
    )
    .await;
    assert_eq!(extract_answer_ip_bytes(&out), vec![vec![4, 4, 4, 4]]);
    assert!(t0.elapsed() < Duration::from_millis(40), "串行就会 ≥40ms");
    assert_eq!(mock.concurrent_peak.load(Ordering::SeqCst), 2, "同层齐射");
}
