use super::*;
use crate::transport::MockStream;
use polaris_helper_proto::response::{ResponseKind, Status};
use std::sync::{Arc, Mutex};

/// 测试用 connector：每次 connect 返回一个预置的 MockStream。
struct MockConnector {
    streams: Arc<Mutex<Vec<MockStream>>>,
}

impl MockConnector {
    fn new(streams: Vec<MockStream>) -> Self {
        Self {
            streams: Arc::new(Mutex::new(streams)),
        }
    }
}

impl Connector for MockConnector {
    fn connect(&self) -> Result<Box<dyn ConnectionStream>, ClientError> {
        let mut guard = self.streams.lock().unwrap();
        if guard.is_empty() {
            return Err(ClientError::Connect("no mock stream".into()));
        }
        Ok(Box::new(guard.remove(0)))
    }
}

fn client_with(streams: Vec<MockStream>) -> (HelperClient, Arc<Mutex<Vec<MockStream>>>) {
    let c = MockConnector::new(streams);
    let streams_ref = c.streams.clone();
    let client = HelperClient::new(Box::new(c), Platform::Mac, "TOK");
    (client, streams_ref)
}

/// 连接级失败 connector：connect() 直接返回 Connect 错误（模拟 helper 未装/未跑）。
struct FailingConnector {
    message: &'static str,
}
impl Connector for FailingConnector {
    fn connect(&self) -> Result<Box<dyn ConnectionStream>, ClientError> {
        Err(ClientError::Connect(self.message.into()))
    }
}

/// 序列 connector：按预设顺序返回「连接成功（MockStream）」或「连接失败（Connect 错误）」。
/// 用于重连测试：首次失败、二次成功等。
enum ConnAttempt {
    Ok(MockStream),
    Fail(String),
}
struct SequenceConnector {
    attempts: Arc<Mutex<Vec<ConnAttempt>>>,
}
impl Connector for SequenceConnector {
    fn connect(&self) -> Result<Box<dyn ConnectionStream>, ClientError> {
        let mut g = self.attempts.lock().unwrap();
        if g.is_empty() {
            return Err(ClientError::Connect("no attempts".into()));
        }
        match g.remove(0) {
            ConnAttempt::Ok(s) => Ok(Box::new(s)),
            ConnAttempt::Fail(m) => Err(ClientError::Connect(m)),
        }
    }
}

#[test]
fn ping_roundtrip_parses_pong() {
    // Polaris helper.go:423: OK pong uid=0 v9
    let mock = MockStream::with_response(b"OK pong uid=0 v9\n".to_vec());
    let (client, _) = client_with(vec![mock]);
    let resp = client.send(&Request::Ping).unwrap();
    match resp {
        Response::Ok(ResponseKind::Pong(p)) => {
            assert_eq!(p.uid, 0);
            assert_eq!(p.proto_version, 9);
        }
        other => panic!("expected Pong, got {other:?}"),
    }
}

#[test]
fn status_roundtrip_parses_running() {
    // Polaris helper.go:427: OK running <pid>
    let mock = MockStream::with_response(b"OK running 4242\n".to_vec());
    let (client, _) = client_with(vec![mock]);
    let resp = client.send(&Request::Status).unwrap();
    match resp {
        Response::Ok(ResponseKind::Status(Status::Running { pid })) => {
            assert_eq!(pid, 4242);
        }
        other => panic!("expected Status Running, got {other:?}"),
    }
}

#[test]
fn err_response_routes_to_err_variant() {
    // Polaris helper.go:406: ERR auth（token 不匹配）
    let mock = MockStream::with_response(b"ERR auth\n".to_vec());
    let (client, _) = client_with(vec![mock]);
    let resp = client.send(&Request::Ping).unwrap();
    assert!(matches!(resp, Response::Err(_)));
}

#[test]
fn written_frame_matches_wire_protocol() {
    // 验证 client 编帧正确：mac 帧 = "TOK\nping\n"（对照 helper-proto codec test）
    // 用一个共享结构捕获写入字节（MockStream 写入后会被 client 消费，无法直接读回）
    struct CapturingConnector {
        captured: Arc<Mutex<Vec<u8>>>,
    }
    impl Connector for CapturingConnector {
        fn connect(&self) -> Result<Box<dyn ConnectionStream>, ClientError> {
            let cap = self.captured.clone();
            Ok(Box::new(CapturingMock { captured: cap }))
        }
    }
    struct CapturingMock {
        captured: Arc<Mutex<Vec<u8>>>,
    }
    impl ConnectionStream for CapturingMock {
        fn read_until_timeout(&mut self, _buf: &mut Vec<u8>) -> io::Result<usize> {
            Ok(0) // EOF
        }
        fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
            self.captured.lock().unwrap().extend_from_slice(data);
            Ok(())
        }
        fn shutdown(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let captured = Arc::new(Mutex::new(Vec::new()));
    let client = HelperClient::new(
        Box::new(CapturingConnector {
            captured: captured.clone(),
        }),
        Platform::Mac,
        "TOK",
    );
    // 即使读 EOF 报 EmptyResponse，写入侧已捕获帧
    let _ = client.send(&Request::Ping);
    let written = captured.lock().unwrap().clone();
    assert_eq!(written, b"TOK\nping\n");
}

#[test]
fn linux_frame_omits_token_line() {
    // linux 经 SO_PEERCRED 无 token 行（helper-linux/helper.go:343）
    struct CaptureConnector {
        captured: Arc<Mutex<Vec<u8>>>,
    }
    impl Connector for CaptureConnector {
        fn connect(&self) -> Result<Box<dyn ConnectionStream>, ClientError> {
            let cap = self.captured.clone();
            Ok(Box::new(CaptureMock { captured: cap }))
        }
    }
    struct CaptureMock {
        captured: Arc<Mutex<Vec<u8>>>,
    }
    impl ConnectionStream for CaptureMock {
        fn read_until_timeout(&mut self, _buf: &mut Vec<u8>) -> io::Result<usize> {
            Ok(0)
        }
        fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
            self.captured.lock().unwrap().extend_from_slice(data);
            Ok(())
        }
        fn shutdown(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let captured = Arc::new(Mutex::new(Vec::new()));
    let client = HelperClient::new(
        Box::new(CaptureConnector {
            captured: captured.clone(),
        }),
        Platform::Linux,
        "ignored-token",
    );
    let _ = client.send(&Request::Ping);
    // linux 帧无 token 行：直接 "ping\n"
    assert_eq!(*captured.lock().unwrap(), b"ping\n");
}

#[test]
fn start_roundtrip_full_frame() {
    // 验证 start 完整帧（mac: TOK/start/cfg/log/fwd/ppid）
    struct CaptureConnector {
        captured: Arc<Mutex<Vec<u8>>>,
    }
    impl Connector for CaptureConnector {
        fn connect(&self) -> Result<Box<dyn ConnectionStream>, ClientError> {
            let cap = self.captured.clone();
            Ok(Box::new(CaptureMock { captured: cap }))
        }
    }
    struct CaptureMock {
        captured: Arc<Mutex<Vec<u8>>>,
    }
    impl ConnectionStream for CaptureMock {
        fn read_until_timeout(&mut self, _buf: &mut Vec<u8>) -> io::Result<usize> {
            Ok(0)
        }
        fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
            self.captured.lock().unwrap().extend_from_slice(data);
            Ok(())
        }
        fn shutdown(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    use polaris_helper_proto::StartParams;
    let captured = Arc::new(Mutex::new(Vec::new()));
    let client = HelperClient::new(
        Box::new(CaptureConnector {
            captured: captured.clone(),
        }),
        Platform::Mac,
        "TOK",
    );
    let req = Request::Start(StartParams {
        cfg: "/tmp/c.json".into(),
        log: "/tmp/l.log".into(),
        fwd: true,
        parent_pid: Some(1000),
    });
    let _ = client.send(&req);
    // 对照 helper-proto::tests::mac_start_frame_full
    assert_eq!(
        *captured.lock().unwrap(),
        b"TOK\nstart\n/tmp/c.json\n/tmp/l.log\n1\n1000\n"
    );
}

#[test]
fn connect_failure_returns_connect_error() {
    // helper 未装 / 未跑 → 连接拒绝（connect() 阶段失败）
    let client = HelperClient::new(
        Box::new(FailingConnector {
            message: "connection refused",
        }),
        Platform::Mac,
        "TOK",
    );
    let err = client.send(&Request::Ping).unwrap_err();
    assert!(matches!(err, ClientError::Connect(_)));
}

#[test]
fn empty_response_returns_error() {
    // helper 连上但无响应（上游 `helper 无响应`，HelperManager.ts:321）
    let mock = MockStream::with_response(b"".to_vec());
    let (client, _) = client_with(vec![mock]);
    let err = client.send(&Request::Ping).unwrap_err();
    assert!(matches!(err, ClientError::EmptyResponse));
}

#[test]
fn retry_succeeds_on_second_attempt() {
    // install 后等 daemon 起来：首次连接失败，二次就绪
    let conn = SequenceConnector {
        attempts: Arc::new(Mutex::new(vec![
            ConnAttempt::Fail("connection refused".into()),
            ConnAttempt::Ok(MockStream::with_response(b"OK pong uid=0 v9\n".to_vec())),
        ])),
    };
    let client = HelperClient::new(Box::new(conn), Platform::Mac, "TOK");
    let resp = client
        .send_with_retry(
            &Request::Ping,
            Duration::from_millis(500),
            3,
            Duration::from_millis(1),
        )
        .unwrap();
    assert!(matches!(resp, Response::Ok(ResponseKind::Pong(_))));
}

#[test]
fn retry_exhausted_returns_last_error() {
    let conn = SequenceConnector {
        attempts: Arc::new(Mutex::new(vec![
            ConnAttempt::Fail("connection refused".into()),
            ConnAttempt::Fail("connection refused".into()),
        ])),
    };
    let client = HelperClient::new(Box::new(conn), Platform::Mac, "TOK");
    let err = client
        .send_with_retry(
            &Request::Ping,
            Duration::from_millis(500),
            1,
            Duration::from_millis(1),
        )
        .unwrap_err();
    assert!(matches!(err, ClientError::Connect(_)));
}

#[test]
fn install_core_uses_long_timeout() {
    // install-core 默认超时 30s（HelperManager.ts:421）
    let mock = MockStream::with_response(b"OK installed\n".to_vec());
    let (client, _) = client_with(vec![mock]);
    use polaris_helper_proto::InstallCoreParams;
    let req = Request::InstallCore(InstallCoreParams {
        src_dir: "/tmp/staging".into(),
        want_hash: "a".repeat(64),
    });
    let resp = client
        .send_with_timeout(&req, Duration::from_millis(INSTALL_CORE_TIMEOUT_MS))
        .unwrap();
    assert!(matches!(resp, Response::Ok(ResponseKind::Installed)));
}

#[test]
fn set_token_updates_auth_token() {
    let mock = MockStream::with_response(b"OK pong uid=0 v9\n".to_vec());
    let (mut client, _) = client_with(vec![mock]);
    client.set_token("new-token");
    assert_eq!(client.token(), "new-token");
}

#[test]
fn platform_accessor() {
    let mock = MockStream::with_response(b"OK\n".to_vec());
    let (client, _) = client_with(vec![mock]);
    assert_eq!(client.platform(), Platform::Mac);
}

#[test]
fn partial_response_assembled_across_reads() {
    // 模拟 helper 响应分多个 TCP 段到达（Polaris sock.on('data') 累积，HelperManager.ts:444-446）
    struct ChunkedMock {
        chunks: Vec<Vec<u8>>,
        pos: usize,
    }
    impl ConnectionStream for ChunkedMock {
        fn read_until_timeout(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
            if self.pos >= self.chunks.len() {
                return Ok(0);
            }
            let chunk = &self.chunks[self.pos];
            self.pos += 1;
            buf.extend_from_slice(chunk);
            Ok(chunk.len())
        }
        fn write_all(&mut self, _data: &[u8]) -> io::Result<()> {
            Ok(())
        }
        fn shutdown(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    struct ChunkedConnector;
    impl Connector for ChunkedConnector {
        fn connect(&self) -> Result<Box<dyn ConnectionStream>, ClientError> {
            Ok(Box::new(ChunkedMock {
                chunks: vec![b"OK pong".to_vec(), b" uid=0 v9\n".to_vec()],
                pos: 0,
            }))
        }
    }
    let client = HelperClient::new(Box::new(ChunkedConnector), Platform::Mac, "T");
    let resp = client.send(&Request::Ping).unwrap();
    match resp {
        Response::Ok(ResponseKind::Pong(p)) => {
            assert_eq!(p.proto_version, 9);
        }
        other => panic!("expected Pong, got {other:?}"),
    }
}

#[test]
fn caller_timeout_is_pushed_down_to_the_stream() {
    // 复审 High（connector.rs:83）的机制面：调用方预算必须逐轮下发给流。
    // 不下发 ⇒ 生产流只用建连时的默认读超时（transport::READ_TIMEOUT = 5s），
    // install-core(30s) 在 5s 被误判失败而 helper 仍把动作做完。
    use crate::transport::READ_TIMEOUT;
    struct RecordingMock {
        budgets: Arc<Mutex<Vec<Duration>>>,
        resp: Vec<u8>,
        pos: usize,
    }
    impl ConnectionStream for RecordingMock {
        fn read_until_timeout(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
            if self.pos >= self.resp.len() {
                return Ok(0);
            }
            buf.push(self.resp[self.pos]);
            self.pos += 1;
            Ok(1)
        }
        fn write_all(&mut self, _data: &[u8]) -> io::Result<()> {
            Ok(())
        }
        fn shutdown(&mut self) -> io::Result<()> {
            Ok(())
        }
        fn set_read_timeout(&mut self, timeout: Duration) -> io::Result<()> {
            self.budgets.lock().unwrap().push(timeout);
            Ok(())
        }
    }
    struct RecordingConnector {
        budgets: Arc<Mutex<Vec<Duration>>>,
    }
    impl Connector for RecordingConnector {
        fn connect(&self) -> Result<Box<dyn ConnectionStream>, ClientError> {
            Ok(Box::new(RecordingMock {
                budgets: self.budgets.clone(),
                resp: b"OK pong uid=0 v9\n".to_vec(),
                pos: 0,
            }))
        }
    }
    let budgets = Arc::new(Mutex::new(Vec::new()));
    let client = HelperClient::new(
        Box::new(RecordingConnector {
            budgets: budgets.clone(),
        }),
        Platform::Mac,
        "TOK",
    );
    let resp = client
        .send_with_timeout(
            &Request::Ping,
            Duration::from_millis(INSTALL_CORE_TIMEOUT_MS),
        )
        .unwrap();
    assert!(matches!(resp, Response::Ok(ResponseKind::Pong(_))));
    let got = budgets.lock().unwrap().clone();
    assert!(!got.is_empty(), "调用方预算一次都没下发到流");
    assert!(
        got[0] > READ_TIMEOUT,
        "首次下发 {:?} 未超过 5s 默认读超时 ⇒ 预算被硬顶",
        got[0]
    );
    assert!(got[0] <= Duration::from_millis(INSTALL_CORE_TIMEOUT_MS));
    // 下发的是**剩余**预算：随读进度单调不增。
    assert!(
        got.windows(2).all(|w| w[0] >= w[1]),
        "下发的不是递减的剩余预算: {got:?}"
    );
}

#[test]
fn read_timeout_maps_to_timeout_error_but_other_io_errors_do_not() {
    // send_with_timeout 文档承诺「超时返回 ClientError::Timeout」。归一必须只吃超时那两种
    // kind（Unix SO_RCVTIMEO 在 Linux 回 WouldBlock），否则「归一」就变成把所有读失败都说成超时。
    struct ErrKindMock(io::ErrorKind);
    impl ConnectionStream for ErrKindMock {
        fn read_until_timeout(&mut self, _buf: &mut Vec<u8>) -> io::Result<usize> {
            Err(io::Error::from(self.0))
        }
        fn write_all(&mut self, _data: &[u8]) -> io::Result<()> {
            Ok(())
        }
        fn shutdown(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    struct ErrKindConnector(io::ErrorKind);
    impl Connector for ErrKindConnector {
        fn connect(&self) -> Result<Box<dyn ConnectionStream>, ClientError> {
            Ok(Box::new(ErrKindMock(self.0)))
        }
    }
    let send_with = |kind| {
        HelperClient::new(Box::new(ErrKindConnector(kind)), Platform::Mac, "T")
            .send(&Request::Ping)
            .unwrap_err()
    };
    for kind in [io::ErrorKind::TimedOut, io::ErrorKind::WouldBlock] {
        let err = send_with(kind);
        assert!(matches!(err, ClientError::Timeout), "{kind:?} → {err:?}");
    }
    // 反向对照：非超时 IO 错误仍走 Io 分支。
    let err = send_with(io::ErrorKind::ConnectionReset);
    assert!(
        matches!(err, ClientError::Io(_)),
        "ConnectionReset → {err:?}"
    );
}
