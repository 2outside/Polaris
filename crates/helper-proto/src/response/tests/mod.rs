use super::*;
use crate::error::ErrorCode;

#[test]
fn parse_pong_mac_linux() {
    // helper.go:423: fmt.Fprintf(conn, "OK pong uid=%d v%s\n", os.Getuid(), protoVersion)
    let r = Response::parse("OK pong uid=0 v9");
    let Response::Ok(ResponseKind::Pong(p)) = r else {
        panic!("{r:?}");
    };
    assert_eq!(
        p,
        Pong {
            uid: 0,
            proto_version: 9,
            build_identity: None,
        }
    );
}

#[test]
fn parse_pong_win_uid_zero() {
    // helper-win/helper.go:180: 固定发 uid=0（os.Getuid() 在 Windows 返回 -1 会破坏客户端正则）
    let r = Response::parse("OK pong uid=0 v5");
    let Response::Ok(ResponseKind::Pong(p)) = r else {
        panic!("{r:?}");
    };
    assert_eq!(p.uid, 0);
    assert_eq!(p.proto_version, 5);
    assert_eq!(p.build_identity, None);
}

#[test]
fn parse_pong_with_build_identity() {
    let r = Response::parse("OK pong uid=0 v1 build=0123456789abcdef");
    let Response::Ok(ResponseKind::Pong(p)) = r else {
        panic!("{r:?}");
    };
    assert_eq!(p.build_identity.as_deref(), Some("0123456789abcdef"));
    assert_eq!(
        Response::Ok(ResponseKind::Pong(p)).to_wire_line(),
        "OK pong uid=0 v1 build=0123456789abcdef"
    );
}

#[test]
fn parse_version_response() {
    // helper.go:425: fmt.Fprintf(conn, "OK %s\n", protoVersion) —— 注意首 token 是版本号本身
    for (line, want) in [("OK 9", 9u32), ("OK 5", 5), ("OK 1", 1)] {
        let r = Response::parse(line);
        let Response::Ok(ResponseKind::Version { proto_version }) = r else {
            panic!("{r:?}");
        };
        assert_eq!(proto_version, want);
    }
}

#[test]
fn mac_proxy_transaction_response_roundtrips() {
    let response = Response::parse("OK system-proxy");
    assert_eq!(response, Response::Ok(ResponseKind::MacProxyTransaction));
    assert_eq!(response.to_wire_line(), "OK system-proxy");
}

#[test]
fn parse_status_running_stopped() {
    // helper.go:427-430
    let r = Response::parse("OK running 12345");
    let Response::Ok(ResponseKind::Status(Status::Running { pid })) = r else {
        panic!("{r:?}");
    };
    assert_eq!(pid, 12345);

    let r = Response::parse("OK stopped");
    let Response::Ok(ResponseKind::Status(Status::Stopped)) = r else {
        panic!("{r:?}");
    };
}

#[test]
fn parse_stop_stopped_notrunning() {
    // helper.go:440-442
    let r = Response::parse("OK stopped 12345"); // stop 的 stopped 带 pid
    let Response::Ok(ResponseKind::Stop(Stop::Stopped { pid })) = r else {
        panic!("{r:?}");
    };
    assert_eq!(pid, 12345);

    let r = Response::parse("OK notrunning");
    let Response::Ok(ResponseKind::Stop(Stop::NotRunning)) = r else {
        panic!("{r:?}");
    };
}

/// `stop-mismatch` 的解析 + 序列化 round-trip（诚实 no-op 的 wire 形态）。
///
/// 两个 pid 都必须原样带回来：客户端的日志/记账靠它们才说得清「谁被拒了、daemon 手里的是谁」。
#[test]
fn stop_mismatch_round_trips_with_both_pids() {
    let r = Response::parse("OK stop-mismatch 4242 9001");
    let Response::Ok(ResponseKind::Stop(Stop::Mismatch { want, current })) = r else {
        panic!("{r:?}");
    };
    assert_eq!((want, current), (4242, 9001));
    assert_eq!(
        Response::Ok(ResponseKind::Stop(Stop::Mismatch {
            want: 4242,
            current: 9001
        }))
        .to_wire_line(),
        "OK stop-mismatch 4242 9001"
    );
}

#[test]
fn parse_start_started_already() {
    // helper.go:522,579
    let r = Response::parse("OK started 12345");
    let Response::Ok(ResponseKind::Start(Start::Started { pid })) = r else {
        panic!("{r:?}");
    };
    assert_eq!(pid, 12345);

    let r = Response::parse("OK already 12345");
    let Response::Ok(ResponseKind::Start(Start::Already { pid })) = r else {
        panic!("{r:?}");
    };
    assert_eq!(pid, 12345);
}

#[test]
fn timed_start_is_additive_and_incomplete_metrics_fall_back() {
    let line =
        "OK started 42 forwarding_ms=3 process_ms=1200 job_ms=2 log_handoff_ms=1 total_ms=1206";
    let r = Response::parse(line);
    let Response::Ok(ResponseKind::Start(Start::StartedTimed { pid, timing })) = r else {
        panic!("{r:?}");
    };
    assert_eq!(pid, 42);
    assert_eq!(timing.process_ms, 1200);
    assert_eq!(r.to_wire_line(), line);

    // 旧客户端只取 `started` 后首个 pid，尾 token 不改变既有 wire 前缀；新客户端遇到残缺字段
    // 则诚实降级为无 timing 的旧响应，绝不补 0 冒充实测。
    let fallback = Response::parse("OK started 42 process_ms=1200");
    assert_eq!(
        fallback,
        Response::Ok(ResponseKind::Start(Start::Started { pid: 42 }))
    );
}

#[test]
fn parse_freeport_variants() {
    // helper.go:370,391,393
    let Response::Ok(ResponseKind::FreePort(FreePort::Free)) = Response::parse("OK free") else {
        panic!();
    };

    let r = Response::parse("OK killed 123,456");
    let Response::Ok(ResponseKind::FreePort(FreePort::Killed { pids })) = r else {
        panic!("{r:?}");
    };
    assert_eq!(pids, vec![123, 456]);

    let r = Response::parse("OK foreign nginx | pid:789");
    let Response::Ok(ResponseKind::FreePort(FreePort::Foreign { names })) = r else {
        panic!("{r:?}");
    };
    assert_eq!(names, vec!["nginx".to_owned(), "pid:789".to_owned()]);
}

#[test]
fn parse_flush_dns_mac() {
    // helper/helper.go:503,506
    let Response::Ok(ResponseKind::FlushDns(FlushDns::Flushed)) = Response::parse("OK flushed")
    else {
        panic!();
    };

    let r = Response::parse("OK flushed-partial killall-hup exit status 1 ");
    let Response::Ok(ResponseKind::FlushDns(FlushDns::FlushedPartial { tail })) = r else {
        panic!("{r:?}");
    };
    assert!(tail.contains("killall-hup"));
}

#[test]
fn linux_resolved_dns_responses_round_trip() {
    for response in [
        Response::Ok(ResponseKind::LinuxDns(LinuxDns::Set)),
        Response::Ok(ResponseKind::LinuxDns(LinuxDns::Reverted)),
    ] {
        assert_eq!(Response::parse(&response.to_wire_line()), response);
    }
}

#[test]
fn parse_simple_ok_tokens() {
    assert_eq!(
        Response::parse("OK cleaned"),
        Response::Ok(ResponseKind::Cleaned)
    );
    assert_eq!(
        Response::parse("OK route"),
        Response::Ok(ResponseKind::Route)
    );
    assert_eq!(
        Response::parse("OK installed"),
        Response::Ok(ResponseKind::Installed)
    );
    assert_eq!(
        Response::parse("OK default-restore"),
        Response::Ok(ResponseKind::DefaultRestored)
    );
    assert_eq!(
        Response::parse("OK iface-metric"),
        Response::Ok(ResponseKind::IfaceMetric)
    );
    assert_eq!(
        Response::parse("OK uninstalling"),
        Response::Ok(ResponseKind::Uninstalling)
    );
}

#[test]
fn parse_err_routes_to_err_variant() {
    let r = Response::parse("ERR auth");
    let Response::Err(e) = r else {
        panic!("{r:?}");
    };
    assert_eq!(e.code, ErrorCode::Auth);
}

#[test]
fn parse_unknown_ok_token_kept_as_raw() {
    // 协议演进兜底：未来加 "OK new-capability X" 不应丢消息
    let r = Response::parse("OK new-capability payload here");
    let Response::Ok(ResponseKind::OkRaw { token, rest }) = r else {
        panic!("{r:?}");
    };
    assert_eq!(token, "new-capability");
    assert_eq!(rest, "payload here");
}

#[test]
fn parse_empty_line_no_panic() {
    // 畸形输入兜底：绝不 panic（freeport 任何持 token 用户可触发）
    let _ = Response::parse("");
    let _ = Response::parse("OK");
    let _ = Response::parse("garbage no prefix");
}

// ===== to_wire_line（写方向，G3.1 上提自 mac handler.rs / win service/win.rs）=====

/// 逐字锁定 wire 输出 —— 对照 Go 源各 `fmt.Fprintln(conn, "OK ...")` 调用点。
/// 这些字符串是三平台 helper 与 app 的协议契约，改动即破网。
#[test]
fn to_wire_line_matches_go_source_literals() {
    let cases: &[(Response, &str)] = &[
        (
            Response::Ok(ResponseKind::Pong(Pong {
                uid: 501,
                proto_version: 9,
                build_identity: None,
            })),
            "OK pong uid=501 v9",
        ),
        (
            Response::Ok(ResponseKind::Version { proto_version: 9 }),
            "OK 9",
        ),
        (
            Response::Ok(ResponseKind::Status(Status::Running { pid: 123 })),
            "OK running 123",
        ),
        (
            Response::Ok(ResponseKind::Status(Status::Stopped)),
            "OK stopped",
        ),
        (
            Response::Ok(ResponseKind::Stop(Stop::Stopped { pid: 456 })),
            "OK stopped 456",
        ),
        (
            Response::Ok(ResponseKind::Stop(Stop::NotRunning)),
            "OK notrunning",
        ),
        (
            Response::Ok(ResponseKind::Start(Start::Started { pid: 7 })),
            "OK started 7",
        ),
        (
            Response::Ok(ResponseKind::Start(Start::StartedTimed {
                pid: 9,
                timing: StartTiming {
                    forwarding_ms: 1,
                    process_ms: 2,
                    job_ms: 3,
                    log_handoff_ms: 4,
                    total_ms: 10,
                },
            })),
            "OK started 9 forwarding_ms=1 process_ms=2 job_ms=3 log_handoff_ms=4 total_ms=10",
        ),
        (
            Response::Ok(ResponseKind::Start(Start::Already { pid: 8 })),
            "OK already 8",
        ),
        (Response::Ok(ResponseKind::Cleaned), "OK cleaned"),
        (Response::Ok(ResponseKind::Route), "OK route"),
        (
            Response::Ok(ResponseKind::FreePort(FreePort::Free)),
            "OK free",
        ),
        (
            Response::Ok(ResponseKind::FreePort(FreePort::Killed {
                pids: vec![1, 22, 333],
            })),
            "OK killed 1,22,333",
        ),
        (
            Response::Ok(ResponseKind::FreePort(FreePort::Foreign {
                names: vec!["nginx".into(), "pid:42".into()],
            })),
            "OK foreign nginx | pid:42",
        ),
        (Response::Ok(ResponseKind::Installed), "OK installed"),
        (
            Response::Ok(ResponseKind::DefaultRestored),
            "OK default-restore",
        ),
        (
            Response::Ok(ResponseKind::FlushDns(FlushDns::Flushed)),
            "OK flushed",
        ),
        (
            Response::Ok(ResponseKind::FlushDns(FlushDns::FlushedPartial {
                tail: "killall-hup err out".into(),
            })),
            "OK flushed-partial killall-hup err out",
        ),
        (Response::Ok(ResponseKind::IfaceMetric), "OK iface-metric"),
        (Response::Ok(ResponseKind::Uninstalling), "OK uninstalling"),
        (
            Response::Err(Error::new(ErrorCode::BadPort)),
            "ERR bad-port",
        ),
    ];
    for (resp, want) in cases {
        assert_eq!(&resp.to_wire_line(), want, "wire mismatch for {resp:?}");
    }
}

/// 写→读 round-trip：`parse(to_wire_line(r)) == r`，含 OkRaw 空 rest（不产尾空格）。
#[test]
fn to_wire_line_round_trips_through_parse() {
    let cases = vec![
        Response::Ok(ResponseKind::Pong(Pong {
            uid: 0,
            proto_version: 3,
            build_identity: None,
        })),
        Response::Ok(ResponseKind::Status(Status::Running { pid: 999 })),
        Response::Ok(ResponseKind::Status(Status::Stopped)),
        Response::Ok(ResponseKind::Stop(Stop::Stopped { pid: 1 })),
        Response::Ok(ResponseKind::Stop(Stop::NotRunning)),
        Response::Ok(ResponseKind::Stop(Stop::Mismatch {
            want: 4242,
            current: 9001,
        })),
        Response::Ok(ResponseKind::Start(Start::Started { pid: 2 })),
        Response::Ok(ResponseKind::Start(Start::StartedTimed {
            pid: 4,
            timing: StartTiming {
                forwarding_ms: 1,
                process_ms: 2,
                job_ms: 3,
                log_handoff_ms: 4,
                total_ms: 10,
            },
        })),
        Response::Ok(ResponseKind::Start(Start::Already { pid: 3 })),
        Response::Ok(ResponseKind::Cleaned),
        Response::Ok(ResponseKind::Route),
        Response::Ok(ResponseKind::FreePort(FreePort::Free)),
        Response::Ok(ResponseKind::FreePort(FreePort::Killed {
            pids: vec![5, 6],
        })),
        Response::Ok(ResponseKind::FreePort(FreePort::Foreign {
            names: vec!["a".into(), "b".into()],
        })),
        Response::Ok(ResponseKind::Installed),
        Response::Ok(ResponseKind::DefaultRestored),
        Response::Ok(ResponseKind::FlushDns(FlushDns::Flushed)),
        Response::Ok(ResponseKind::IfaceMetric),
        Response::Ok(ResponseKind::Uninstalling),
        // OkRaw 空 rest：`OK foo`（无尾空格）→ parse 回 rest=""
        Response::Ok(ResponseKind::OkRaw {
            token: "foo".into(),
            rest: String::new(),
        }),
        Response::Ok(ResponseKind::OkRaw {
            token: "new-capability".into(),
            rest: "payload here".into(),
        }),
    ];
    for r in cases {
        assert_eq!(Response::parse(&r.to_wire_line()), r, "round-trip failed");
    }
}
