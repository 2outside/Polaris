use super::*;
use std::sync::Mutex;
use std::time::Duration;

// ===== format_start_time（移植自 proc_starttime_darwin.go:39-43）=====

#[test]
fn format_start_time_valid() {
    // proc_starttime_darwin.go:43: fmt.Sprintf("%d.%06d", sec, usec)
    assert_eq!(
        format_start_time(1_700_000_000, 1234),
        Some("1700000000.001234".into())
    );
    assert_eq!(
        format_start_time(1_700_000_000, 0),
        Some("1700000000.000000".into())
    );
    assert_eq!(
        format_start_time(1_700_000_000, 999_999),
        Some("1700000000.999999".into())
    );
}

#[test]
fn format_start_time_rejects_invalid() {
    // proc_starttime_darwin.go:39-42: sec<=0 / usec<0 / usec>999999 → 返回空（这里 None）
    assert_eq!(format_start_time(0, 0), None);
    assert_eq!(format_start_time(-1, 0), None);
    assert_eq!(format_start_time(100, -1), None);
    assert_eq!(format_start_time(100, 1_000_000), None);
}

// ===== parse_kinfo_starttime（移植 proc_starttime_darwin.go:33-37，纯解析跨平台可测）=====

fn kinfo_buf(sec: i64, usec: i32) -> Vec<u8> {
    // tv_sec @0 (int64 LE), tv_usec @8 (int32 LE)，其余填充到 648 字节（模拟内核回写）
    let mut b = vec![0u8; 648];
    b[0..8].copy_from_slice(&sec.to_le_bytes());
    b[8..12].copy_from_slice(&usec.to_le_bytes());
    b
}

#[test]
fn parse_kinfo_starttime_reads_le_fields() {
    // proc_starttime_darwin.go:36-37: sec @0, usec @8 小端
    let buf = kinfo_buf(1_700_000_000, 123_456);
    assert_eq!(
        parse_kinfo_starttime(&buf, 648),
        Some((1_700_000_000, 123_456))
    );
    // 结合 format：得微秒身份串
    let (s, u) = parse_kinfo_starttime(&buf, 648).unwrap();
    assert_eq!(
        format_start_time(s, u).as_deref(),
        Some("1700000000.123456")
    );
}

#[test]
fn parse_kinfo_starttime_rejects_short_n() {
    // proc_starttime_darwin.go:33: n < 16 → None
    let buf = kinfo_buf(1, 1);
    assert_eq!(parse_kinfo_starttime(&buf, 15), None);
    assert_eq!(parse_kinfo_starttime(&buf, 0), None);
    // n>=16 边界可解析
    assert!(parse_kinfo_starttime(&buf, 16).is_some());
}

#[test]
fn parse_kinfo_starttime_rejects_short_buf() {
    // 缓冲不足 12 字节 → None（防越界；生产缓冲恒 1024）
    let short = vec![0u8; 8];
    assert_eq!(parse_kinfo_starttime(&short, 648), None);
}

// ===== classify_alive（移植自 helper.go:336-343）=====

#[test]
fn classify_alive_dead_when_not_exists() {
    // helper.go:337: kill(pid,0)==ESRCH → dead
    assert_eq!(classify_alive(false, None, None), AliveProbe::Dead);
    assert_eq!(
        classify_alive(false, Some("x"), Some("x")),
        AliveProbe::Dead
    );
}

#[test]
fn classify_alive_when_start_matches() {
    // helper.go:339-340: kill==nil && cur==ppidStart → 存活
    assert_eq!(
        classify_alive(true, Some("100.000001"), Some("100.000001")),
        AliveProbe::Alive
    );
}

#[test]
fn classify_pid_reused_when_start_differs() {
    // helper.go:340-342: kill==nil 但 cur != ppidStart → PID 复用 → dead
    assert_eq!(
        classify_alive(true, Some("100.000001"), Some("200.000002")),
        AliveProbe::PidReused
    );
}

#[test]
fn classify_unknown_when_snapshot_missing() {
    // helper.go:335: ppidStart=="" → 不据此判死（保守存活）
    assert_eq!(
        classify_alive(true, None, Some("100.000001")),
        AliveProbe::Unknown
    );
}

#[test]
fn classify_unknown_when_current_missing() {
    // helper.go:335: cur==""（ps 失败/超时）→ 不据此判死
    assert_eq!(
        classify_alive(true, Some("100.000001"), None),
        AliveProbe::Unknown
    );
}

// ===== proc_start_time_via_ps_with_runner =====

struct PsMock {
    retval: Mutex<Option<Vec<u8>>>,
}

impl crate::platform::macos::exec::CommandRunner for PsMock {
    fn run(
        &self,
        _t: Duration,
        _p: &str,
        _a: &[&str],
    ) -> Result<(), crate::platform::macos::exec::RunError> {
        Ok(())
    }
    fn output(
        &self,
        _t: Duration,
        _p: &str,
        _a: &[&str],
    ) -> Result<Vec<u8>, crate::platform::macos::exec::RunError> {
        self.retval
            .lock()
            .unwrap()
            .clone()
            .ok_or(crate::platform::macos::exec::RunError::NonZero {
                code: 1,
                output: std::process::Output {
                    status: std::process::ExitStatus::default(),
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                },
            })
    }
    fn combined(
        &self,
        _t: Duration,
        _p: &str,
        _a: &[&str],
    ) -> Result<Vec<u8>, crate::platform::macos::exec::RunError> {
        Ok(Vec::new())
    }
}

#[test]
fn proc_start_time_via_ps_parses_output() {
    // helper.go:305-309: ps -o lstart= -p <pid> 取启动时间字符串
    let m = PsMock {
        retval: Mutex::new(Some(b"Mon Jan  1 10:00:00 2024\n".to_vec())),
    };
    let t = proc_start_time_via_ps_with_runner(&m, 1234);
    assert_eq!(t.as_deref(), Some("Mon Jan  1 10:00:00 2024"));
}

#[test]
fn proc_start_time_via_ps_empty_returns_none() {
    // helper.go:308: strings.TrimSpace(out) 为空 → 返回 ""
    let m = PsMock {
        retval: Mutex::new(Some(b"   \n".to_vec())),
    };
    assert!(proc_start_time_via_ps_with_runner(&m, 1234).is_none());
}

#[test]
fn proc_start_time_via_ps_error_returns_none() {
    // helper.go:305: err != nil → 返回 ""（保守不判死）
    let m = PsMock {
        retval: Mutex::new(None),
    };
    assert!(proc_start_time_via_ps_with_runner(&m, 1234).is_none());
}

// ===== 常量锁定 =====

#[test]
fn watch_tick_and_grace_match_go_source() {
    // helper.go:284: time.After(5 * time.Second)
    // helper.go:317: time.NewTicker(time.Second)
    assert_eq!(WATCH_TICK_INTERVAL, Duration::from_secs(1));
    assert_eq!(TERMINATE_GRACE, Duration::from_secs(5));
}

#[cfg(target_os = "macos")]
#[test]
fn kill_zero_exists_for_self() {
    // 自身进程必然存在
    let pid = std::process::id();
    assert!(kill_zero_exists(pid));
    // PID 0 不存在（init 在 mac 上是 1，0 是 kernel_task 但 kill(0,0) 语义特殊）
    // 用一个大不存在的 PID 测：不保证 ESRCH（可能被复用），跳过断言方向
    let _ = kill_zero_exists(999_999);
}

#[cfg(target_os = "macos")]
#[test]
fn mac_sysctl_consts_match_darwin_abi() {
    // proc_starttime_darwin.go:20: mib := [4]int32{1, 14, 1, pid}
    assert_eq!(sysctl_const::CTL_KERN, 1);
    assert_eq!(sysctl_const::KERN_PROC, 14);
    assert_eq!(sysctl_const::KERN_PROC_PID, 1);
    // proc_starttime_darwin.go:36-37: tv_sec @0, tv_usec @8
    assert_eq!(KINFO_STARTTIME_SEC_OFFSET, 0);
    assert_eq!(KINFO_STARTTIME_USEC_OFFSET, 8);
    // proc_starttime_darwin.go:22: kinfo_proc 648 bytes
    assert_eq!(KINFO_PROC_SIZE_64, 648);
}
