use super::*;
use std::sync::Mutex;
use std::time::Duration;

/// 可配置返回序列的 MockRunner：按程序名区分 dscacheutil vs killall 调用。
struct SeqRunner {
    dscache_out: Result<Vec<u8>, TestErr>,
    killall_out: Result<Vec<u8>, TestErr>,
    seen: Mutex<Vec<String>>,
}

/// 测试用错误（避开 ExitStatus::from_raw 的平台依赖）。
#[derive(Clone)]
enum TestErr {
    Exit { code: i32, stderr: Vec<u8> },
    Timeout,
}

impl SeqRunner {
    fn calls(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}

impl CommandRunner for SeqRunner {
    fn run(&self, _t: Duration, p: &str, _a: &[&str]) -> Result<(), RunError> {
        self.seen.lock().unwrap().push(p.to_owned());
        Ok(())
    }
    fn output(&self, _t: Duration, _p: &str, _a: &[&str]) -> Result<Vec<u8>, RunError> {
        Ok(Vec::new())
    }
    fn combined(&self, _t: Duration, p: &str, _a: &[&str]) -> Result<Vec<u8>, RunError> {
        self.seen.lock().unwrap().push(p.to_owned());
        let is_dscache = p == DSCACHEUTIL_BIN;
        let res = if is_dscache {
            &self.dscache_out
        } else {
            &self.killall_out
        };
        res.clone().map_err(|e| match e {
            TestErr::Exit { code, stderr } => RunError::NonZero {
                code,
                output: std::process::Output {
                    status: exit_status_for_test(code),
                    stdout: Vec::new(),
                    stderr,
                },
            },
            TestErr::Timeout => RunError::Timeout,
        })
    }
}

/// 构造测试用 ExitStatus（跨平台）—— 用 from_raw 在 Linux 上对小正数 code 稳定。
fn exit_status_for_test(code: i32) -> std::process::ExitStatus {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(code)
    }
    #[cfg(not(unix))]
    {
        // 非 unix 测试环境无法构造任意 ExitStatus —— 但 helper-mac 本就只跑 unix
        let _ = code;
        std::process::ExitStatus::default()
    }
}

#[test]
fn flush_dns_both_succeed() {
    // helper.go:506: 两层全清 → OK flushed
    let runner = SeqRunner {
        dscache_out: Ok(Vec::new()),
        killall_out: Ok(Vec::new()),
        seen: Mutex::new(Vec::new()),
    };
    let r = flush_dns(&runner);
    assert_eq!(r, FlushResult::Flushed);
    // 两步都被调用
    assert_eq!(runner.calls().len(), 2);
}

#[test]
fn flush_dns_dscacheutil_fails() {
    // helper.go:498-501: dscacheutil 失败 → ERR dscacheutil（不调 killall）
    let runner = SeqRunner {
        dscache_out: Err(TestErr::Exit {
            code: 1,
            stderr: b"flush failed".to_vec(),
        }),
        killall_out: Ok(Vec::new()),
        seen: Mutex::new(Vec::new()),
    };
    let r = flush_dns(&runner);
    match r {
        FlushResult::DscacheutilFailed { detail } => {
            assert!(detail.contains("dscacheutil"), "{detail}");
        }
        other => panic!("expected DscacheutilFailed, got {other:?}"),
    }
    // 失败后不再调 killall
    assert_eq!(runner.calls().len(), 1);
}

#[test]
fn flush_dns_killall_fails_partial() {
    // helper.go:502-505: HUP 失败 → OK flushed-partial killall-hup
    let runner = SeqRunner {
        dscache_out: Ok(Vec::new()),
        killall_out: Err(TestErr::Exit {
            code: 1,
            stderr: b"no mDNSResponder".to_vec(),
        }),
        seen: Mutex::new(Vec::new()),
    };
    let r = flush_dns(&runner);
    match r {
        FlushResult::Partial { tail } => {
            assert!(tail.contains("killall-hup"), "{tail}");
            assert!(tail.contains("exit status 1"), "{tail}");
        }
        other => panic!("expected Partial, got {other:?}"),
    }
}

#[test]
fn flush_result_to_response_flushed() {
    let resp: Response = FlushResult::Flushed.into();
    assert!(matches!(
        resp,
        Response::Ok(ResponseKind::FlushDns(FlushDns::Flushed))
    ));
}

#[test]
fn flush_result_to_response_partial() {
    let resp: Response = FlushResult::Partial {
        tail: "killall-hup exit status 1".into(),
    }
    .into();
    match resp {
        Response::Ok(ResponseKind::FlushDns(FlushDns::FlushedPartial { tail })) => {
            assert!(tail.contains("killall-hup"));
        }
        other => panic!("expected FlushedPartial, got {other:?}"),
    }
}

#[test]
fn flush_result_to_response_dscacheutil_err() {
    let resp: Response = FlushResult::DscacheutilFailed {
        detail: "exit status 1".into(),
    }
    .into();
    match resp {
        Response::Err(e) => {
            assert_eq!(e.code, polaris_helper_proto::ErrorCode::Dscacheutil);
        }
        other => panic!("expected Err, got {other:?}"),
    }
}

#[test]
fn flush_dns_killall_timeout_partial() {
    // helper.go:502-505: killall 超时 → OK flushed-partial killall-hup timeout
    let runner = SeqRunner {
        dscache_out: Ok(Vec::new()),
        killall_out: Err(TestErr::Timeout),
        seen: Mutex::new(Vec::new()),
    };
    let r = flush_dns(&runner);
    match r {
        FlushResult::Partial { tail } => {
            assert!(tail.contains("killall-hup"), "{tail}");
            assert!(tail.contains("timeout"), "{tail}");
        }
        other => panic!("expected Partial, got {other:?}"),
    }
}

#[test]
fn command_paths_match_go_source() {
    // helper.go:498,502
    assert_eq!(DSCACHEUTIL_BIN, "/usr/bin/dscacheutil");
    assert_eq!(KILLALL_BIN, "/usr/bin/killall");
    assert_eq!(DSCACHEUTIL_ARGS, &["-flushcache"]);
    assert_eq!(KILLALL_HUP_ARGS, &["-HUP", "mDNSResponder"]);
}
