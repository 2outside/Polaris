use super::super::*;
use polaris_helper_proto::{Platform, Request};
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::thread;

/// 起一个单次 accept 的 UnixListener（tempdir 内的本地 IPC socket，**非宿主网络** —— 不碰
/// netns/veth/iptables/TUN，等同临时文件，安全隔离），读请求帧、回预置响应。
fn spawn_echo_server(
    path: PathBuf,
    response: &'static [u8],
    delay: Duration,
) -> thread::JoinHandle<Vec<u8>> {
    let listener = UnixListener::bind(&path).unwrap();
    thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        // 读到 EOF（client shutdown(Write) 触发）或读满一小段。
        let mut got = Vec::new();
        let mut chunk = [0u8; 256];
        loop {
            match conn.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    got.extend_from_slice(&chunk[..n]);
                    // 请求帧以 `\n` 结尾；client 半关闭后我们读到 EOF，但也可提前在收到整帧后停。
                    if got.contains(&b'\n') {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        // 慢响应用例里 client 可能已因超时先关连接（EPIPE）——这是被测的预期结局，
        // 不是夹具故障，故不 unwrap（否则 join 会把预期结局报成测试崩溃）。
        thread::sleep(delay);
        let _ = conn.write_all(response);
        // 回完即 drop → client 读到响应 + EOF。
        got
    })
}

#[test]
fn unix_connector_roundtrip_ping() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("helper.sock");
    let server = spawn_echo_server(sock.clone(), b"OK pong uid=0 v9\n", Duration::ZERO);
    // 用 UnixConnector 建 HelperClient，发 ping，验证真连接 + 编帧 + 读响应往返。
    let connector = UnixConnector::new(sock);
    let client = crate::client::HelperClient::new(Box::new(connector), Platform::Mac, "TOK");
    let resp = client.send(&Request::Ping).unwrap();
    assert!(matches!(
        resp,
        polaris_helper_proto::Response::Ok(polaris_helper_proto::response::ResponseKind::Pong(_))
    ));
    // 服务端收到的请求帧 = mac wire "TOK\nping\n"（验证 shutdown 半关闭让服务端读到完整帧 + EOF）。
    let got = server.join().unwrap();
    assert_eq!(got, b"TOK\nping\n");
}

#[test]
fn unix_connector_connect_refused_when_no_socket() {
    // socket 路径不存在 → connect 失败（helper 未装/未跑，对齐 Polaris sock.on('error')）。
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nonexistent.sock");
    let connector = UnixConnector::new(missing);
    // Box<dyn ConnectionStream> 无 Debug，不能 unwrap_err；用 match 取错误。
    match connector.connect() {
        Err(ClientError::Connect(_)) => {}
        Ok(_) => panic!("expected connect refused"),
        Err(other) => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn unix_connector_exposes_socket_path() {
    let connector = UnixConnector::new("/run/polaris/helper.sock");
    assert_eq!(
        connector.socket_path(),
        Path::new("/run/polaris/helper.sock")
    );
}

#[test]
fn caller_budget_overrides_connector_default_read_timeout() {
    // 复审 High（connector.rs:83）：调用方单请求超时此前在 Unix 生产腿被连接器默认读超时硬顶，
    // install-core(30s) / linux-resolved(45s) / start(15s) 三个预算全部不可达 —— helper 把动作
    // 做完了，app 却已按失败分叉。这里把连接器默认压到 80ms、服务端 400ms 才回，
    // 以 3s 的调用方预算复现同一形态：修复前在 80ms 判失败，修复后应成功。
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("slow.sock");
    let server = spawn_echo_server(
        sock.clone(),
        b"OK pong uid=0 v9\n",
        Duration::from_millis(400),
    );
    let connector = UnixConnector::with_timeout(sock, Duration::from_millis(80));
    let client = crate::client::HelperClient::new(Box::new(connector), Platform::Mac, "TOK");
    let resp = client
        .send_with_timeout(&Request::Ping, Duration::from_secs(3))
        .expect("调用方 3s 预算应盖过连接器 80ms 默认读超时");
    assert!(matches!(
        resp,
        polaris_helper_proto::Response::Ok(polaris_helper_proto::response::ResponseKind::Pong(_))
    ));
    server.join().unwrap();
}

#[test]
fn caller_budget_is_the_real_bound_when_helper_is_slow() {
    // 反向：预算**小于**服务端耗时时，必须在预算处判 Timeout —— 既不是等到连接器默认值（30s），
    // 也不是被吞成普通 IO 错误。与上一条合起来钉住「调用方预算是唯一的界」。
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("stalled.sock");
    let server = spawn_echo_server(
        sock.clone(),
        b"OK pong uid=0 v9\n",
        Duration::from_millis(800),
    );
    let connector = UnixConnector::with_timeout(sock, Duration::from_secs(30));
    let client = crate::client::HelperClient::new(Box::new(connector), Platform::Mac, "TOK");
    let started = Instant::now();
    let err = client
        .send_with_timeout(&Request::Ping, Duration::from_millis(120))
        .unwrap_err();
    let elapsed = started.elapsed();
    assert!(
        matches!(err, ClientError::Timeout),
        "期望 Timeout，实际 {err:?}"
    );
    assert!(
        elapsed < Duration::from_millis(600),
        "调用方 120ms 预算未生效，实耗 {elapsed:?}"
    );
    server.join().unwrap();
}
