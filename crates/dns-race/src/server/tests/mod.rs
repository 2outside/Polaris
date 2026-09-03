use super::*;
use crate::race::DEFAULT_RACE_BUDGET;
use crate::upstream::{resolve_upstreams, ResolveUpstream};
use crate::wire::{
    build_answer_response, classify_dns_response, encode_dns_query, extract_answer_ip_bytes,
    AnswerRecord, DnsResponseClass, TYPE_A,
};
use async_trait::async_trait;

/// 固定应答的 mock 上游（零网络）。
struct FixedQuery(Result<Vec<u8>, String>);

#[async_trait]
impl UpstreamQuery for FixedQuery {
    async fn query(&self, _u: &ResolveUpstream, q: &[u8]) -> Result<Vec<u8>, String> {
        match &self.0 {
            Ok(ips) => Ok(build_answer_response(
                q,
                &[AnswerRecord {
                    rtype: TYPE_A,
                    rdata: ips.clone(),
                }],
            )),
            Err(e) => Err(e.clone()),
        }
    }
}

fn default_pool() -> ResolvedUpstreams {
    resolve_upstreams(&["ali".to_string(), "dnspod".to_string()], &[])
}

/// 扮演 sing-box：往 sidecar 发 query、收响应（**全程 127.0.0.1**）。
async fn ask(port: u16, query: &[u8]) -> io::Result<Vec<u8>> {
    let sock = UdpSocket::bind("127.0.0.1:0").await?;
    sock.send_to(query, ("127.0.0.1", port)).await?;
    let mut buf = vec![0u8; MAX_DNS_UDP_BYTES];
    let (n, _) = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "sidecar 未回包"))??;
    Ok(buf[..n].to_vec())
}

#[tokio::test]
async fn sidecar_answers_kernel_query_on_loopback() {
    let srv = NodeDnsRaceServer::start(
        default_pool(),
        Arc::new(FixedQuery(Ok(vec![1, 2, 3, 4]))),
        DEFAULT_RACE_BUDGET,
        None,
        Arc::new(DecoySet::builtin()),
    )
    .await
    .expect("绑回环");
    assert!(srv.port() > 0 && srv.is_listening());
    let q = encode_dns_query("node.example.com", TYPE_A, 0x0abc);
    let resp = ask(srv.port(), &q).await.expect("有回包");
    assert_eq!(classify_dns_response(&resp, TYPE_A), DnsResponseClass::Hit);
    assert_eq!(&resp[..2], &q[..2], "id 回填");
    assert_eq!(extract_answer_ip_bytes(&resp), vec![vec![1, 2, 3, 4]]);
}

/// 【不变式：fail-open】上游全挂 → sidecar 仍**必须**回 SERVFAIL，不能沉默。
/// 变异验证：把 `handle_one` 里的 `send_to` 删掉（或让 `race_forward` 失败时不回包）→
/// 本测试 3s 超时转红。
#[tokio::test]
async fn sidecar_replies_servfail_when_all_upstreams_fail() {
    let srv = NodeDnsRaceServer::start(
        default_pool(),
        Arc::new(FixedQuery(Err("boom".into()))),
        Duration::from_millis(100),
        None,
        Arc::new(DecoySet::builtin()),
    )
    .await
    .expect("绑回环");
    let q = encode_dns_query("node.example.com", TYPE_A, 0x0def);
    let resp = ask(srv.port(), &q).await.expect("全 FAIL 也必须有回包");
    assert_eq!(resp[3] & 0x0f, 2, "RCODE=SERVFAIL");
    assert_eq!(&resp[..2], &q[..2]);
}

#[tokio::test]
async fn malformed_datagram_still_gets_a_reply() {
    let srv = NodeDnsRaceServer::start(
        default_pool(),
        Arc::new(FixedQuery(Ok(vec![1, 1, 1, 1]))),
        Duration::from_millis(100),
        None,
        Arc::new(DecoySet::builtin()),
    )
    .await
    .expect("绑回环");
    let resp = ask(srv.port(), &[0xde, 0xad, 0xbe, 0xef])
        .await
        .expect("畸形包也回");
    assert!(resp.len() >= 12);
}

#[tokio::test]
async fn stop_releases_the_port() {
    let srv = NodeDnsRaceServer::start(
        default_pool(),
        Arc::new(FixedQuery(Ok(vec![1, 1, 1, 1]))),
        DEFAULT_RACE_BUDGET,
        None,
        Arc::new(DecoySet::builtin()),
    )
    .await
    .expect("绑回环");
    let port = srv.port();
    srv.stop();
    assert!(!srv.is_listening());
    drop(srv);
    // 端口释放是异步的（任务 abort → 析构），给它几轮调度再断言可复绑。
    let mut rebound = false;
    for _ in 0..50 {
        if UdpSocket::bind(("127.0.0.1", port)).await.is_ok() {
            rebound = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(rebound, "stop 后端口必须被释放，否则重连会占着旧口");
}

#[tokio::test]
async fn concurrent_queries_are_not_serialized_behind_a_slow_one() {
    /// 慢上游：固定 80ms 后成功。两个并发 query 若被串行化则总耗时 ≥160ms。
    struct SlowQuery;
    #[async_trait]
    impl UpstreamQuery for SlowQuery {
        async fn query(&self, _u: &ResolveUpstream, q: &[u8]) -> Result<Vec<u8>, String> {
            tokio::time::sleep(Duration::from_millis(80)).await;
            Ok(build_answer_response(
                q,
                &[AnswerRecord {
                    rtype: TYPE_A,
                    rdata: vec![8, 8, 8, 8],
                }],
            ))
        }
    }
    let srv = NodeDnsRaceServer::start(
        default_pool(),
        Arc::new(SlowQuery),
        DEFAULT_RACE_BUDGET,
        None,
        Arc::new(DecoySet::builtin()),
    )
    .await
    .expect("绑回环");
    let port = srv.port();
    let q1 = encode_dns_query("a.example.com", TYPE_A, 1);
    let q2 = encode_dns_query("b.example.com", TYPE_A, 2);
    let t0 = std::time::Instant::now();
    let (r1, r2) = tokio::join!(ask(port, &q1), ask(port, &q2));
    assert!(r1.is_ok() && r2.is_ok());
    assert!(
        t0.elapsed() < Duration::from_millis(160),
        "并发 query 不得被串行化"
    );
}

/// 【不变式：watchdog 按原端口重建**真的能成功**】
///
/// 直接驱动生产的重建腿 [`Watchdog::recover`]（收发循环遇非瞬态错时调的就是它），断言：
/// 旧 socket 被释放后同口重绑成功、新 socket 能真正收包、`live_port` 复位、不误触死亡回调。
///
/// 变异验证（两半各锁一条）：
/// - 删掉 `recover` 里的 `set_socket(slot, None)` → 槽仍持旧 socket → 5 次 bind 全 EADDRINUSE → `None` → 红；
/// - 删掉 `drop(local)`（让 `local` 活到函数末尾）→ 同样 5 次全失败 → 红。
#[tokio::test]
async fn watchdog_rebinds_same_port_after_releasing_old_socket() {
    let old = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("绑回环"));
    let port = old.local_addr().unwrap().port();
    let slot: SockSlot = Arc::new(Mutex::new(Some(Arc::clone(&old))));
    // 模拟一个在飞的 handle_one：**只持槽**（修复后的形状），不持 socket。
    let inflight_view = Arc::clone(&slot);

    // 前提锁定（本机回环实测 errno 98）：旧 fd 还有引用时同口重绑必失败 ——
    // 这正是「重建腿在旧结构下结构性不可能成功」的根因。
    assert!(
        UdpSocket::bind(("127.0.0.1", port)).await.is_err(),
        "旧 socket 未释放时同口重绑必须失败（否则本测试锁不住任何东西）"
    );

    let live_port = Arc::new(AtomicU16::new(port));
    let dead_calls = Arc::new(AtomicU64::new(0));
    let seen = Arc::clone(&dead_calls);
    let wd = Watchdog {
        port,
        live_port: Arc::clone(&live_port),
        closing: Arc::new(AtomicBool::new(false)),
        on_dead: Some(Arc::new(move |_p| {
            seen.fetch_add(1, Ordering::SeqCst);
        })),
    };

    let local = current_socket(&slot).expect("槽里有 socket");
    drop(old); // 只留「收发循环那一份 + 槽那一份」，与生产形状一致
    let rebuilt = wd
        .recover(&slot, local)
        .await
        .expect("释放旧 socket 后必须能按原端口重建");

    assert_eq!(
        rebuilt.local_addr().unwrap().port(),
        port,
        "必须重绑**原**端口：内核 config 里烧的就是它，换口 = 查死口"
    );
    assert_eq!(live_port.load(Ordering::SeqCst), port, "live_port 须复位");
    assert_eq!(
        dead_calls.load(Ordering::SeqCst),
        0,
        "重建成功不得触发死亡回调"
    );

    // 新 socket 真的在收包（不是「bind 上了但没接管」）。
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(b"ping", ("127.0.0.1", port)).await.unwrap();
    let mut buf = [0u8; 16];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), rebuilt.recv_from(&mut buf))
        .await
        .expect("重建后的 socket 须能收包")
        .expect("recv 成功");
    assert_eq!(&buf[..n], b"ping");

    // 在飞腿的视角：槽里已换成新 socket → 它那份迟到的回包仍从**同一端口**发出，内核照收。
    let seen_by_inflight = current_socket(&inflight_view).expect("在飞腿仍能取到当前 socket");
    assert_eq!(seen_by_inflight.local_addr().unwrap().port(), port);
}

/// 【不变式：彻底失败必自曝】端口被别人占死 → 重试耗尽 → `live_port=0` **且**触发死亡回调。
///
/// 没有回调时，src-tauri 的注入态仍是 >0 的旧端口，之后每次 config 重生成都继续把内核指向死口。
/// 变异验证：删掉 `recover` 末尾的 `cb(self.port)` → 回调计数断言转红；删掉 `live_port.store(0,..)`
/// → 端口归零断言转红。
#[tokio::test]
async fn watchdog_gives_up_zeroes_live_port_and_fires_on_dead() {
    // 占死目标端口：重建腿无论重试多少次都绑不上。
    let squatter = UdpSocket::bind("127.0.0.1:0").await.expect("绑回环");
    let dead_port = squatter.local_addr().unwrap().port();
    // 「旧 socket」另绑一口（同口不可能有两只），它只是被 recover 释放掉的那一份。
    let old = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("绑回环"));
    let slot: SockSlot = Arc::new(Mutex::new(Some(Arc::clone(&old))));

    let live_port = Arc::new(AtomicU16::new(dead_port));
    let reported = Arc::new(AtomicU16::new(0));
    let sink = Arc::clone(&reported);
    let wd = Watchdog {
        port: dead_port,
        live_port: Arc::clone(&live_port),
        closing: Arc::new(AtomicBool::new(false)),
        on_dead: Some(Arc::new(move |p| sink.store(p, Ordering::SeqCst))),
    };

    let local = current_socket(&slot).unwrap();
    drop(old);
    assert!(
        wd.recover(&slot, local).await.is_none(),
        "端口被占死 → 重试耗尽 → None"
    );
    assert_eq!(
        live_port.load(Ordering::SeqCst),
        0,
        "彻底失败 → live_port 归 0"
    );
    assert_eq!(
        reported.load(Ordering::SeqCst),
        dead_port,
        "必须把**死掉的端口**报给上层，否则注入态无从知道该清哪一个"
    );
    assert!(
        current_socket(&slot).is_none(),
        "失败后槽必须是空的（不留一个已死的 socket 让回包腿误用）"
    );
    drop(squatter);
}

/// 【判定表】哪些 recv 错误算「对端瞬态」（继续收）、哪些算 socket 故障（走重建）。
/// 变异验证：把任一 kind 从 `is_transient_recv_error` 挪走/挪进 → 对应断言转红。
#[test]
fn transient_recv_errors_are_classified_apart_from_socket_faults() {
    use io::ErrorKind::*;
    for k in [ConnectionRefused, ConnectionReset, Interrupted, WouldBlock] {
        assert!(
            is_transient_recv_error(&io::Error::new(k, "x")),
            "{k:?} 是对端瞬态（ICMP port-unreachable 等），重建 socket 是过度反应"
        );
    }
    // ENOBUFS / 权限 / 已关闭 fd 等 → 视作 socket 故障，必须走重建腿。
    for k in [OutOfMemory, PermissionDenied, BrokenPipe, Other] {
        assert!(
            !is_transient_recv_error(&io::Error::new(k, "x")),
            "{k:?} 必须触发按原端口重建"
        );
    }
}

/// 【不变式：在飞封顶 + 超限不放大】限 1 + 慢上游：第 2 个 query 在第 1 个未完成时到达 →
/// 被丢弃（无回包），且**上游一次都没被多问**（这才是放大面被堵住的证据，不是「少了个回包」）。
///
/// 变异验证：删掉 serve 里的 `try_acquire_owned` 早退（恢复无条件 spawn）→ 上游调用计数变 2 → 转红。
#[tokio::test]
async fn inflight_cap_drops_excess_without_upstream_fanout() {
    struct CountingSlowQuery(Arc<AtomicU64>);
    #[async_trait]
    impl UpstreamQuery for CountingSlowQuery {
        async fn query(&self, _u: &ResolveUpstream, q: &[u8]) -> Result<Vec<u8>, String> {
            self.0.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(300)).await;
            Ok(build_answer_response(
                q,
                &[AnswerRecord {
                    rtype: TYPE_A,
                    rdata: vec![4, 4, 4, 4],
                }],
            ))
        }
    }
    let hits = Arc::new(AtomicU64::new(0));
    // 单上游池 → 一个 query 恰好一次上游调用，计数即「有没有被放行」。
    let pool = resolve_upstreams(&["ali".to_string()], &[]);
    let srv = NodeDnsRaceServer::start_with_limit(
        pool,
        Arc::new(CountingSlowQuery(Arc::clone(&hits))),
        DEFAULT_RACE_BUDGET,
        None,
        Arc::new(DecoySet::builtin()),
        1, // 在飞上限 1
    )
    .await
    .expect("绑回环");
    let port = srv.port();

    let c1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    c1.send_to(
        &encode_dns_query("a.example.com", TYPE_A, 1),
        ("127.0.0.1", port),
    )
    .await
    .unwrap();
    // 让第一个 query 被收下并占住唯一的令牌。
    tokio::time::sleep(Duration::from_millis(80)).await;

    let c2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    c2.send_to(
        &encode_dns_query("b.example.com", TYPE_A, 2),
        ("127.0.0.1", port),
    )
    .await
    .unwrap();

    let mut buf = vec![0u8; MAX_DNS_UDP_BYTES];
    assert!(
        tokio::time::timeout(Duration::from_millis(250), c2.recv_from(&mut buf))
            .await
            .is_err(),
        "超出在飞上限的 query 必须被丢弃（内核自会重试），不得排队占内存"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "被丢弃的 query 绝不能触发上游齐射 —— 放大面就是靠这一条堵住的"
    );

    // 第一个 query 不受影响，正常拿到答案。
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), c1.recv_from(&mut buf))
        .await
        .expect("首个 query 必须正常回包")
        .expect("recv 成功");
    assert_eq!(
        classify_dns_response(&buf[..n], TYPE_A),
        DnsResponseClass::Hit
    );
}
