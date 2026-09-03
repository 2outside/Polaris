use super::*;
use std::sync::Mutex;

/// MockRunner：记录所有调用 + 按预设规则返回结果。测试完全不触碰宿主命令。
#[derive(Default)]
struct MockRunner {
    calls: Mutex<Vec<Call>>,
    output_bytes: Vec<u8>,
    fail_combined: bool,
}

#[derive(Debug, Clone, PartialEq)]
struct Call {
    program: String,
    args: Vec<String>,
}

impl MockRunner {
    fn calls_snapshot(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }
}

impl CommandRunner for MockRunner {
    fn run(&self, _t: Duration, program: &str, args: &[&str]) -> Result<(), RunError> {
        self.calls.lock().unwrap().push(Call {
            program: program.into(),
            args: args.iter().map(|s| (*s).into()).collect(),
        });
        Ok(())
    }

    fn output(&self, _t: Duration, program: &str, args: &[&str]) -> Result<Vec<u8>, RunError> {
        self.calls.lock().unwrap().push(Call {
            program: program.into(),
            args: args.iter().map(|s| (*s).into()).collect(),
        });
        Ok(self.output_bytes.clone())
    }

    fn combined(&self, _t: Duration, program: &str, args: &[&str]) -> Result<Vec<u8>, RunError> {
        self.calls.lock().unwrap().push(Call {
            program: program.into(),
            args: args.iter().map(|s| (*s).into()).collect(),
        });
        if self.fail_combined {
            Err(RunError::NonZero {
                code: 1,
                output: std::process::Output {
                    status: make_exit_status(1),
                    stdout: Vec::new(),
                    stderr: b"err".to_vec(),
                },
            })
        } else {
            Ok(self.output_bytes.clone())
        }
    }
}

fn make_exit_status(code: i32) -> std::process::ExitStatus {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(code)
    }
    #[cfg(not(unix))]
    {
        let _ = code;
        std::process::ExitStatus::default()
    }
}

#[test]
fn mock_runner_records_calls() {
    let m = MockRunner::default();
    m.run(
        EXEC_TIMEOUT,
        "/sbin/route",
        &["-n", "add", "default", "1.2.3.4"],
    )
    .unwrap();
    let calls = m.calls_snapshot();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].program, "/sbin/route");
    assert_eq!(calls[0].args, vec!["-n", "add", "default", "1.2.3.4"]);
}

#[test]
fn mock_runner_output_returns_preset_bytes() {
    let m = MockRunner {
        output_bytes: b"192.168.1.1".to_vec(),
        ..Default::default()
    };
    let out = m.output(EXEC_TIMEOUT, "/bin/ps", &[]).unwrap();
    assert_eq!(out, b"192.168.1.1");
}

#[test]
fn mock_runner_combined_failure_returns_nonzero() {
    let m = MockRunner {
        fail_combined: true,
        ..Default::default()
    };
    let err = m.combined(EXEC_TIMEOUT, "/usr/bin/dscacheutil", &["-flushcache"]);
    assert!(matches!(err, Err(RunError::NonZero { code: 1, .. })));
}

#[test]
fn timeouts_match_go_source() {
    // helper.go:102-103
    assert_eq!(EXEC_TIMEOUT, Duration::from_secs(8));
    assert_eq!(CODESIGN_TIMEOUT, Duration::from_secs(30));
}

#[test]
fn run_error_display_matches_go_exit_status_format() {
    // Go *exec.ExitError 的 Error() 返回 "exit status N" —— 我们 Display 对齐
    let e = RunError::NonZero {
        code: 1,
        output: std::process::Output {
            status: make_exit_status(1),
            stdout: Vec::new(),
            stderr: Vec::new(),
        },
    };
    assert_eq!(e.to_string(), "exit status 1");
    assert_eq!(RunError::Timeout.to_string(), "timeout");
    assert_eq!(
        RunError::Spawn("no such file".into()).to_string(),
        "spawn failed: no such file"
    );
}

// ===== SystemRunner 真跑命令（按平台选程序；spawn 失败即红，不容忍）=====

#[test]
fn system_runner_run_echo() {
    // 跨平台验证 SystemRunner 真能 spawn + wait。
    #[cfg(unix)]
    let (program, args): (&str, &[&str]) = ("/bin/echo", &["hello"]);
    #[cfg(windows)]
    let (program, args): (&str, &[&str]) = ("cmd", &["/c", "echo hello"]);
    let runner = SystemRunner::new();
    runner
        .run(EXEC_TIMEOUT, program, args)
        .expect("echo 须 spawn 成功且零退出");
}

#[test]
fn system_runner_output_echo() {
    #[cfg(unix)]
    let (program, args): (&str, &[&str]) = ("/bin/echo", &["world"]);
    #[cfg(windows)]
    let (program, args): (&str, &[&str]) = ("cmd", &["/c", "echo world"]);
    let runner = SystemRunner::new();
    let out = runner
        .output(EXEC_TIMEOUT, program, args)
        .expect("echo 须 spawn 成功且零退出");
    assert!(String::from_utf8_lossy(&out).contains("world"));
}

#[test]
fn system_runner_nonzero_exit() {
    // unix：/usr/bin/false 退出码 1；windows：cmd /c exit 1。
    #[cfg(unix)]
    let (program, args): (&str, &[&str]) = ("/usr/bin/false", &[]);
    #[cfg(windows)]
    let (program, args): (&str, &[&str]) = ("cmd", &["/c", "exit 1"]);
    let runner = SystemRunner::new();
    let result = runner.run(EXEC_TIMEOUT, program, args);
    match result {
        Err(RunError::NonZero { .. }) => {}
        other => panic!("expected NonZero, got {other:?}"),
    }
}
