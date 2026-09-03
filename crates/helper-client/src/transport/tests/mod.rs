use super::*;

#[test]
fn mock_streams_request_and_captures_response() {
    // 预置 helper 回 "OK pong uid=0 v9\n"，client 应读到完整一行
    let mut mock = MockStream::with_response(b"OK pong uid=0 v9\n".to_vec());
    // client 写请求帧
    mock.write_all(b"TOK\nping\n").unwrap();
    mock.shutdown().unwrap();
    // 读响应
    let mut buf = Vec::new();
    let n = mock.read_until_timeout(&mut buf).unwrap();
    assert_eq!(n, 1);
    // 写入被捕获
    assert_eq!(mock.take_written(), b"TOK\nping\n");
    assert!(mock.shutdown_was_called());
}

#[test]
fn mock_eof_after_response() {
    let mut mock = MockStream::with_response(b"OK\n".to_vec());
    let mut buf = Vec::new();
    // 读两字节后 EOF
    assert_eq!(mock.read_until_timeout(&mut buf).unwrap(), 1); // 'O'
    assert_eq!(mock.read_until_timeout(&mut buf).unwrap(), 1); // 'K'
    assert_eq!(mock.read_until_timeout(&mut buf).unwrap(), 1); // '\n'
    assert_eq!(mock.read_until_timeout(&mut buf).unwrap(), 0); // EOF
    assert_eq!(buf, b"OK\n");
}

#[test]
fn mock_broken_returns_error() {
    let mut mock = MockStream::broken(io::ErrorKind::ConnectionRefused);
    let mut buf = Vec::new();
    let err = mock.read_until_timeout(&mut buf).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
    let err = mock.write_all(b"x").unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
}

#[test]
fn read_timeout_constant_matches_helper_proto() {
    // 与 helper-proto::codec::READ_TIMEOUT_SECS 对齐（5s，Go SetReadDeadline）
    assert_eq!(READ_TIMEOUT, Duration::from_secs(5));
}

#[test]
fn default_timeouts_match_polaris() {
    // HelperManager.ts:443 ping 1500ms；:421 install-core 30000ms
    assert_eq!(DEFAULT_REQUEST_TIMEOUT_MS, 1500);
    assert_eq!(INSTALL_CORE_TIMEOUT_MS, 30_000);
}

#[test]
fn io_adapter_uses_single_byte_reads_and_stops_at_newline() {
    struct PipeLike {
        inner: std::io::Cursor<Vec<u8>>,
        requested: Vec<usize>,
    }
    impl Read for PipeLike {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.requested.push(buf.len());
            self.inner.read(buf)
        }
    }
    impl Write for PipeLike {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut adapter = IoAdapter::new(PipeLike {
        inner: std::io::Cursor::new(b"OK stopped\nignored".to_vec()),
        requested: Vec::new(),
    });
    let mut buf = Vec::new();
    let total = adapter.read_until_timeout(&mut buf).unwrap();
    assert_eq!(buf, b"OK stopped\n");
    assert_eq!(total, b"OK stopped\n".len());
    assert_eq!(adapter.inner().requested, vec![1; b"OK stopped\n".len()]);
}
