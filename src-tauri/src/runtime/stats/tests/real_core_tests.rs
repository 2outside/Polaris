use super::super::relay::{build_aggregate, now_ms, signature_changed};
use super::super::*;
use crate::runtime::config::ConfigManager;
use crate::runtime::helper::HelperRuntime;
use crate::runtime::mesh::MeshRuntime;
use crate::runtime::proxy::ProxyRuntime;
use polaris_singbox_grpc::{Endpoint, SingBoxApiClient};
use serde_json::Value;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn free_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// 真机验证用最小 config：manual + 全局直连 + 仅本地混合入站。
fn local_only_config(mixed: u16) -> Value {
    serde_json::json!({
        "servers": [],
        "selectedServerId": "__direct__",
        "proxyMode": "direct",
        "proxyModeType": "manual",
        "mixedPort": mixed,
    })
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "真机验证：需 POLARIS_SINGBOX_PATH 指向真实 sing-box；非 CI 门"]
async fn real_core_aggregate_relay_emits_real_frames() {
    let _real_core_guard = crate::runtime::REAL_CORE_TEST_LOCK.lock().await;
    let core =
        std::path::PathBuf::from(std::env::var("POLARIS_SINGBOX_PATH").expect(
            "真机验证需 POLARIS_SINGBOX_PATH 指向真实 sing-box（前置缺失即失败，不静默跳过）",
        ));
    assert!(
        core.is_file(),
        "POLARIS_SINGBOX_PATH 必须指向真实文件，实得 {}",
        core.display()
    );

    let dir = std::env::temp_dir().join(format!(
        "polaris-agg-test-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&dir).unwrap();
    crate::logging::init(&dir);
    let config = Arc::new(ConfigManager::new(dir.clone()));
    let helper = Arc::new(HelperRuntime::never_installed_for_tests(dir.clone()));
    let mesh = Arc::new(MeshRuntime::new(dir.clone()));
    // 系统代理清理收口器：真实控制器 + 临时目录 marker 路径（无 marker → 门控 1 即返、零系统调用）。
    let proxy_clearer: Box<dyn crate::runtime::proxy::system_takeover::SystemProxyClearer> =
        Box::new(polaris_system_integration::production_proxy_controller(
            dir.join(polaris_system_integration::PROXY_MARKER_FILENAME)
                .to_string_lossy()
                .into_owned(),
        ));
    let proxy = Arc::new(ProxyRuntime::new(
        config,
        helper,
        mesh,
        proxy_clearer,
        // C11：真机验证用不到 DoH 竞速（本地 direct config，无节点域名）→ 桩即可。
        Arc::new(crate::runtime::proxy::NoNetworkDoh),
    ));
    proxy.inject_real_core_for_test(core);

    let mixed = free_port();

    // ── BUG-2：真配置起真核（proxy.start(config: Value) → running）──────────────
    let st = proxy
        .start(local_only_config(mixed))
        .await
        .expect("[BUG-2] proxy.start(config) 起核应成功");
    println!(
        "[BUG-2] proxy.start(config) → running={} pid={} mixedPort={} apiPort={}",
        st.running, st.pid, st.mixed_port, st.clash_api_port
    );
    assert!(st.running, "[BUG-2] 起核后必须 running");
    assert_ne!(st.pid, 0, "[BUG-2] 必须拿到真实 pid");
    assert_ne!(st.clash_api_port, 0, "[BUG-2] 管理 API 端口必须已解析");

    // ── 造真实连接：本地服务器（仅 127.0.0.1，不出网），**延迟 10s 才响应** →
    //    请求已发、响应未回，连接在整个窗口内确定活跃（对齐「首页有活连接」的稳态场景）。──
    let srv = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let srv_port = srv.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = srv.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf).await;
                tokio::time::sleep(Duration::from_secs(10)).await; // 延迟响应 → 连接持续活跃
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                    .await;
            });
        }
    });
    let mut holds = Vec::new();
    for _ in 0..3 {
        let mut c = tokio::net::TcpStream::connect(("127.0.0.1", mixed))
            .await
            .expect("混合入站应可连");
        let req = format!(
            "GET http://127.0.0.1:{srv_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{srv_port}\r\n\r\n"
        );
        c.write_all(req.as_bytes()).await.unwrap();
        holds.push(c); // 持有 + 不等响应 → 连接保持活跃
    }
    // 给 sing-box 一点时间把连接登记进管理面。
    tokio::time::sleep(Duration::from_millis(500)).await;

    // ── BUG-1：走 relay 的真实路径（snapshot → build_aggregate → signature_changed）──
    let client = SingBoxApiClient::connect(Endpoint::new("127.0.0.1", st.clash_api_port), "")
        .await
        .expect("[BUG-1] 管理 API gRPC 连接应成功");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(6);
    let mut agg = None;
    while tokio::time::Instant::now() < deadline {
        let conns = client
            .first_connection_snapshot()
            .await
            .expect("[BUG-1] 连接快照应成功");
        let alive = conns.iter().filter(|c| c.closed_at <= 0).count();
        eprintln!(
            "[poll] first_connection_snapshot → {} conns（活跃 {alive}）",
            conns.len()
        );
        let a = build_aggregate(&conns, now_ms());
        if a.total > 0 {
            agg = Some(a);
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let agg = agg.expect("[BUG-1] relay 必须从真核聚合出 total>0 的真实帧（否则数据面仍无供数）");
    println!(
        "[BUG-1] build_aggregate(真核快照) → {}",
        serde_json::to_string(&agg).unwrap()
    );
    assert!(agg.total > 0, "[BUG-1] 真实连接总数必须 > 0");
    assert!(!agg.hosts.is_empty(), "[BUG-1] 至少一个真实 host 节点");

    // change-driven：首帧必推，同内容去重不推。
    let sig1 = signature_changed(&agg, &None).expect("[BUG-1] 首帧必推（emit）");
    assert!(
        signature_changed(&agg, &Some(sig1)).is_none(),
        "[BUG-1] 同内容必须去重不推（change-driven）"
    );
    println!("[BUG-1] change-driven：首帧 emit + 同内容去重 ✓");

    // ── 停核干净 ──────────────────────────────────────────────────────────
    drop(holds);
    let pid = st.pid;
    proxy.stop().await.expect("停核应成功");
    assert!(!proxy.status().running, "停核后 running 必须为 false");
    println!("[done] proxy.stop() → running=false（pid={pid} 已收割）");
    let _ = std::fs::remove_dir_all(&dir);
}
