use super::*;
use std::cell::RefCell;

#[derive(Default)]
struct MockExec {
    calls: RefCell<Vec<FlushCommand>>,
    fail: bool,
}
impl FlushExec for MockExec {
    fn exec(&self, cmd: &FlushCommand, _timeout: Duration) -> Result<(), String> {
        self.calls.borrow_mut().push(cmd.clone());
        if self.fail {
            Err("exec failed".into())
        } else {
            Ok(())
        }
    }
}

#[test]
fn mac_user_flush_command_shape() {
    let c = mac_user_flush_command();
    assert_eq!(c.program, "/usr/bin/dscacheutil");
    assert_eq!(c.args, vec!["-flushcache".to_string()]);
}

#[test]
fn windows_flush_command_shape() {
    let c = windows_flush_command();
    // System32 绝对路径而非裸 `ipconfig`：部分设备 PATH 缺 System32 → 裸命令报「不是内部或外部
    // 命令」（上游 `ipconfigExe = system32('ipconfig.exe')` 同因）。本机非 Windows 时 env 无
    // SystemRoot → 回落 C:\Windows，故断言以 System32 路径结尾。
    assert!(
        c.program.ends_with("\\System32\\ipconfig.exe"),
        "须用 System32 绝对路径，实际 {}",
        c.program
    );
    assert_eq!(c.args, vec!["/flushdns".to_string()]);
}

#[test]
fn linux_flush_command_shape() {
    let c = linux_flush_command();
    assert_eq!(c.program, "resolvectl");
    assert_eq!(c.args, vec!["flush-caches".to_string()]);
}

#[test]
fn mac_uses_helper_when_ok() {
    let exec = MockExec::default();
    let mut warned = String::new();
    flush_os_dns_cache(
        Platform::Mac,
        &exec,
        Some(&|| HelperFlushResult {
            ok: true,
            partial: None,
            error: None,
        }),
        &mut |m| warned = m.into(),
    );
    // helper ok → 不走 exec。
    assert!(exec.calls.borrow().is_empty());
    assert!(warned.is_empty());
}

#[test]
fn mac_partial_warns_no_degrade() {
    let exec = MockExec::default();
    let mut warned = String::new();
    flush_os_dns_cache(
        Platform::Mac,
        &exec,
        Some(&|| HelperFlushResult {
            ok: true,
            partial: Some("HUP mDNSResponder failed".into()),
            error: None,
        }),
        &mut |m| warned = m.into(),
    );
    // partial → 不降级（不 exec），仅 warn。
    assert!(exec.calls.borrow().is_empty());
    assert!(warned.contains("partial"));
}

#[test]
fn mac_helper_unavailable_degrades_to_user_level() {
    let exec = MockExec::default();
    let mut warned = String::new();
    flush_os_dns_cache(
        Platform::Mac,
        &exec,
        Some(&|| HelperFlushResult {
            ok: false,
            partial: None,
            error: Some("ERR unknown".into()),
        }),
        &mut |m| warned = m.into(),
    );
    // helper 不可用 → 降级 dscacheutil。
    let calls = exec.calls.borrow();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].program, "/usr/bin/dscacheutil");
    assert!(warned.contains("降级"));
}

#[test]
fn mac_no_helper_degrades_directly() {
    let exec = MockExec::default();
    let warned = String::new();
    flush_os_dns_cache(Platform::Mac, &exec, None, &mut |_m| {});
    let calls = exec.calls.borrow();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].program, "/usr/bin/dscacheutil");
    assert!(warned.is_empty());
}

#[test]
fn mac_exec_failure_warns_not_throws() {
    let exec = MockExec {
        fail: true,
        ..Default::default()
    };
    let mut warned = String::new();
    assert!(!flush_os_dns_cache(Platform::Mac, &exec, None, &mut |m| {
        warned = m.into()
    }));
    assert!(warned.contains("失败（忽略）"));
}

#[test]
fn windows_runs_ipconfig_flushdns() {
    let exec = MockExec::default();
    flush_os_dns_cache(Platform::Win, &exec, None, &mut |_| {});
    let calls = exec.calls.borrow();
    assert_eq!(calls.len(), 1);
    assert!(calls[0].program.ends_with("ipconfig.exe"), "{:?}", calls[0]);
    assert_eq!(calls[0].args, vec!["/flushdns".to_string()]);
}

#[test]
fn linux_runs_resolvectl() {
    let exec = MockExec::default();
    flush_os_dns_cache(Platform::Linux, &exec, None, &mut |_| {});
    let calls = exec.calls.borrow();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].program, "resolvectl");
}

#[test]
fn linux_flush_failure_is_observable_without_throwing() {
    let exec = MockExec {
        fail: true,
        ..Default::default()
    };
    let mut warned = String::new();
    let ok = flush_os_dns_cache(Platform::Linux, &exec, None, &mut |message| {
        warned = message.to_owned();
    });
    assert!(!ok);
    assert!(warned.contains("失败（忽略）"));
}

#[test]
fn other_platform_noop() {
    let exec = MockExec::default();
    flush_os_dns_cache(Platform::Other, &exec, None, &mut |_| {});
    assert!(exec.calls.borrow().is_empty());
}

#[test]
fn current_platform_matches_target() {
    // current() 由编译 target 决定，按 target 断言（对齐 helper-proto
    // platform_current_matches_compile_target），三平台 CI 均成立。
    let cur = Platform::current();
    if cfg!(target_os = "macos") {
        assert_eq!(cur, Platform::Mac);
    } else if cfg!(target_os = "windows") {
        assert_eq!(cur, Platform::Win);
    } else if cfg!(target_os = "linux") {
        assert_eq!(cur, Platform::Linux);
    } else {
        assert_eq!(cur, Platform::Other);
    }
}
