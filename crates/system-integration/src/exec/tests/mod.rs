use super::*;
use crate::exec::exec_tests_helpers::MockRunner;
use std::cell::RefCell;

#[test]
fn command_new_builds_argv() {
    let c = Command::new(
        "gsettings",
        ["set", "org.gnome.system.proxy", "mode", "none"],
    );
    assert_eq!(c.program, "gsettings");
    assert_eq!(c.args.len(), 4);
    assert_eq!(c.args[3], "none");
}

#[test]
fn command_poll_interval_backs_off_but_keeps_the_original_ceiling() {
    let mut interval = INITIAL_POLL_INTERVAL;
    let mut observed = vec![interval];
    for _ in 0..5 {
        interval = next_poll_interval(interval, MAX_POLL_INTERVAL);
        observed.push(interval);
    }
    assert_eq!(
        observed,
        [1, 2, 4, 8, 10, 10].map(Duration::from_millis).to_vec()
    );
}

#[test]
fn mock_runner_records_and_returns_queued_stdout() {
    let r = MockRunner {
        stdouts: RefCell::new(vec!["hello".into()]),
        ..Default::default()
    };
    let out = r.run(&Command::new("x", [] as [&str; 0]), Duration::from_secs(1));
    assert_eq!(out.unwrap().stdout, "hello");
    assert_eq!(r.calls.borrow().len(), 1);
}

#[test]
fn mock_runner_fails_listed_program() {
    let r = MockRunner {
        fail_programs: vec!["boom".into()],
        ..Default::default()
    };
    assert!(r
        .run(
            &Command::new("boom", [] as [&str; 0]),
            Duration::from_secs(1)
        )
        .is_err());
}

// ── StdCommandRunner：只验「执行器」本身（不碰网络/代理/DNS，仅无害的 true/false/sleep）──
//
// 真进程 smoke 按宿主用 `#[cfg]` 选择可执行文件；紧邻的 system32 纯函数仍保持全平台可测。

// Windows hosted runner 在整仓并行 test 的峰值期，PowerShell 冷启动实测可越过 5s；这里验证的是
// stdout/stderr/exit-code 契约，不是启动时延。把平台差异收在一个测试常量，避免两条烟测各漂一份。
#[cfg(unix)]
const COMMAND_SMOKE_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(windows)]
const COMMAND_SMOKE_TIMEOUT: Duration = Duration::from_secs(15);

// ── system32（纯函数，Linux 上得 Windows 路径 —— 零 cfg 可测性的样板）──

#[test]
fn system_root_prefers_systemroot_then_windir_then_default() {
    assert_eq!(system_root(Some("D:\\Win"), Some("E:\\w")), "D:\\Win");
    assert_eq!(system_root(None, Some("E:\\w")), "E:\\w");
    assert_eq!(system_root(None, None), "C:\\Windows");
    // 空串视同缺失（上游 `env.SystemRoot || env.windir || ...` 的 falsy 语义）。
    assert_eq!(system_root(Some(""), Some("E:\\w")), "E:\\w");
    assert_eq!(system_root(Some(""), Some("")), "C:\\Windows");
}

#[test]
fn system32_builds_backslash_absolute_path() {
    assert_eq!(
        system32("reg.exe", None, None),
        "C:\\Windows\\System32\\reg.exe"
    );
    assert_eq!(
        system32("netsh.exe", Some("D:\\Win"), None),
        "D:\\Win\\System32\\netsh.exe"
    );
    // 尾斜杠不产生双分隔符。
    assert_eq!(
        system32("ipconfig.exe", Some("D:\\Win\\"), None),
        "D:\\Win\\System32\\ipconfig.exe"
    );
}

#[test]
fn std_runner_ok_on_zero_exit() {
    // Windows 用 PowerShell 而非 cmd：`[Console]::Out.Write` 输出字节可精确控制
    // （cmd 的 echo 会带 CRLF 和多余空格，无法与下面的精确相等断言对齐）。
    #[cfg(unix)]
    let cmd = Command::new("/bin/sh", ["-c", "printf out; printf err >&2"]);
    #[cfg(windows)]
    let cmd = Command::new(
        "powershell",
        [
            "-NoProfile",
            "-Command",
            "[Console]::Out.Write('out'); [Console]::Error.Write('err')",
        ],
    );
    let out = StdCommandRunner.run(&cmd, COMMAND_SMOKE_TIMEOUT);
    let out = out.expect("zero exit → Ok");
    assert_eq!(out.stdout, "out");
    assert_eq!(out.stderr, "err");
}

#[test]
fn std_runner_err_on_nonzero_exit_carries_stderr() {
    #[cfg(unix)]
    let cmd = Command::new("/bin/sh", ["-c", "echo boom >&2; exit 3"]);
    #[cfg(windows)]
    let cmd = Command::new(
        "powershell",
        [
            "-NoProfile",
            "-Command",
            "[Console]::Error.Write('boom'); exit 3",
        ],
    );
    let e = StdCommandRunner
        .run(&cmd, COMMAND_SMOKE_TIMEOUT)
        .expect_err("非零退出 → Err（对齐 execFileAsync reject）");
    assert!(e.contains('3'), "错误须带退出码: {e}");
    assert!(e.contains("boom"), "错误须带 stderr: {e}");
}

#[test]
fn std_runner_err_on_missing_program() {
    let e = StdCommandRunner
        .run(
            &Command::new("polaris-no-such-binary-xyz", [] as [&str; 0]),
            Duration::from_secs(5),
        )
        .expect_err("二进制缺失 → Err");
    assert!(e.contains("启动失败"), "{e}");
}

/// 硬超时是 [`FlushExec`](crate::dns_flush::FlushExec) 契约的一部分（上游 EXEC_TIMEOUT_MS=3s，
/// 防挂起命令拖住 fire-and-forget 链）。若 runner 忽略 timeout 参数，本测试转红。
#[test]
fn std_runner_kills_on_timeout() {
    #[cfg(unix)]
    let cmd = Command::new("/bin/sh", ["-c", "sleep 30"]);
    #[cfg(windows)]
    let cmd = Command::new(
        "powershell",
        ["-NoProfile", "-Command", "Start-Sleep -Seconds 30"],
    );
    // unix 150ms 够 /bin/sh 进 sleep；Windows 上 PowerShell 冷启动约 200–400ms，
    // 沿用 150ms 会「还没开始 sleep 就超时」→ 测的变成「杀启动中的进程」而非
    // 「杀已在运行的挂起命令」。放宽到 2s（仍 ≪ 被杀命令的 30s，故断言语义不变）。
    #[cfg(unix)]
    let timeout = Duration::from_millis(150);
    #[cfg(windows)]
    let timeout = Duration::from_secs(2);
    let started = Instant::now();
    let e = StdCommandRunner.run(&cmd, timeout).expect_err("超时 → Err");
    assert!(e.contains("超时"), "{e}");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "须在超时后即刻返回，实际 {:?}",
        started.elapsed()
    );
}

#[test]
fn std_runner_drains_large_output_without_deadlock() {
    #[cfg(unix)]
    let cmd = Command::new("/bin/sh", ["-c", "yes polaris | head -c 300000"]);
    #[cfg(windows)]
    let cmd = Command::new(
        "powershell",
        [
            "-NoProfile",
            "-Command",
            "[Console]::Out.Write('x' * 300000)",
        ],
    );
    // 远超管道缓冲（64KB）：若不起排空线程，此处会与 try_wait 轮询互等 → 超时失败。
    // 复用平台烟测预算：Windows hosted runner 在整仓并行测试峰值期启动 PowerShell + 写出
    // 300KB 曾超过固定 10s；此测试验证「能排空并退出」，不把共享 runner 负载误判成死锁。
    let out = StdCommandRunner
        .run(&cmd, COMMAND_SMOKE_TIMEOUT)
        .expect("大输出须正常收完");
    assert_eq!(out.stdout.len(), 300_000);
}
