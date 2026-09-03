use super::*;

#[test]
fn err_roundtrip_no_detail() {
    // 对应 Go: fmt.Fprintln(conn, "ERR auth") —— helper.go:406
    let e = Error::new(ErrorCode::Auth);
    assert_eq!(e.to_wire_line(), "ERR auth");
    let parsed = Error::parse("ERR auth").unwrap();
    assert_eq!(parsed, e);
}

#[test]
fn err_roundtrip_with_detail() {
    // 对应 Go: fmt.Fprintf(conn, "ERR start %v\n", err) —— helper.go:552
    let e = Error::with_detail(ErrorCode::Start, "exit status 1");
    assert_eq!(e.to_wire_line(), "ERR start exit status 1");
    let parsed = Error::parse("ERR start exit status 1").unwrap();
    assert_eq!(parsed.code, ErrorCode::Start);
    assert_eq!(parsed.detail, "exit status 1");
}

#[test]
fn err_detail_trimmed_on_serialize() {
    // 对齐 Go strings.TrimSpace(string(out))：尾部空白不应进 wire
    let e = Error::with_detail(ErrorCode::Dscacheutil, "  flusing failed  \n");
    assert_eq!(e.to_wire_line(), "ERR dscacheutil flusing failed");
}

#[test]
fn err_parse_unknown_token_falls_back_to_other() {
    // install-core 的 OS 错误前缀（read-singbox/readdir 等）未锁死进枚举 → Other + detail 保留完整原文
    let parsed = Error::parse("ERR read-singbox open /tmp/x: no such file").unwrap();
    assert_eq!(parsed.code, ErrorCode::Other);
    // Other 的 detail 保留完整原文（含未知 token），保 round-trip 无损
    assert_eq!(parsed.detail, "read-singbox open /tmp/x: no such file");
    // round-trip：to_wire_line 应重建原行
    assert_eq!(
        parsed.to_wire_line(),
        "ERR read-singbox open /tmp/x: no such file"
    );
}

#[test]
fn err_parse_non_err_returns_none() {
    assert!(Error::parse("OK pong uid=0 v9").is_none());
    assert!(Error::parse("").is_none());
}

#[test]
fn all_known_codes_roundtrip_through_wire_token() {
    // 锁住 wire token 不漂移 —— 改名 = 与已部署 helper 断协议
    let known = [
        ErrorCode::Auth,
        ErrorCode::Peercred,
        ErrorCode::Unauthorized,
        ErrorCode::Unknown,
        ErrorCode::NoConfig,
        ErrorCode::BadArgs,
        ErrorCode::ConfigPathDenied,
        ErrorCode::LogPathDenied,
        ErrorCode::CorePathDenied,
        ErrorCode::ConfigNotOwned,
        ErrorCode::CoreMissing,
        ErrorCode::IfaceDenied,
        ErrorCode::BadGateway,
        ErrorCode::BadPort,
        ErrorCode::BadMetric,
        ErrorCode::CoredirUnset,
        ErrorCode::HashMismatch,
        ErrorCode::Enum,
        ErrorCode::Start,
        ErrorCode::Dscacheutil,
        ErrorCode::SetMetric,
    ];
    for c in known {
        let tok = c.as_wire_token();
        assert_eq!(ErrorCode::from_wire_token(tok), c, "token {tok} mismatch");
        // 其它 -> 序列化为 "unknown"（兜底，调用方构造时通常已知具体 code）
        assert_eq!(ErrorCode::from_wire_token("read-singbox"), ErrorCode::Other);
        let _ = tok; // suppress unused in case of empty
    }
}
