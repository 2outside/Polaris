use super::*;
use crate::platform::macos::exec::RunError;
use std::sync::Mutex;
use std::time::Duration;

// ===== 纯逻辑测试 =====

#[test]
fn is_valid_port_str_digits_only() {
    // helper.go:363
    assert!(is_valid_port_str("9090"));
    assert!(is_valid_port_str("80"));
    assert!(is_valid_port_str("0"));
    assert!(!is_valid_port_str(""));
    assert!(!is_valid_port_str("9090abc"));
    assert!(!is_valid_port_str("90 90"));
    assert!(!is_valid_port_str("-1"));
    assert!(!is_valid_port_str("9090.0"));
}

#[test]
fn parse_lsof_pids_multiline() {
    // helper.go:367-368: Fields(TrimSpace(out))
    let out = b"123\n456\n789\n";
    assert_eq!(parse_lsof_pids(out), vec![123, 456, 789]);
    // 单行多个（空格分隔）
    assert_eq!(parse_lsof_pids(b"123 456"), vec![123, 456]);
    // 含空白/非数字项过滤
    assert_eq!(parse_lsof_pids(b"  123  \n abc \n456  "), vec![123, 456]);
    // 空
    assert!(parse_lsof_pids(b"").is_empty());
    assert!(parse_lsof_pids(b"   \n").is_empty());
}

#[test]
fn is_singbox_comm_substring_match() {
    // helper.go:378: strings.Contains(comm, "sing-box")
    assert!(is_singbox_comm("sing-box"));
    assert!(is_singbox_comm("/usr/local/bin/sing-box"));
    assert!(is_singbox_comm("/opt/homebrew/bin/sing-box"));
    assert!(!is_singbox_comm("nginx"));
    assert!(!is_singbox_comm("singbox")); // 无连字符
    assert!(!is_singbox_comm(""));
}

#[test]
fn classify_holder_singbox() {
    assert_eq!(
        classify_holder("/usr/local/bin/sing-box", 123),
        HolderKind::SingBox
    );
}

#[test]
fn classify_holder_foreign_uses_comm_name() {
    // helper.go:382-383: name = comm
    assert_eq!(
        classify_holder("nginx", 456),
        HolderKind::Foreign {
            name: "nginx".into()
        }
    );
}

#[test]
fn classify_holder_foreign_empty_comm_uses_pid() {
    // helper.go:384-385: name == "" → "pid:<pid>"
    assert_eq!(
        classify_holder("", 789),
        HolderKind::Foreign {
            name: "pid:789".into()
        }
    );
}

#[test]
fn classify_holder_trims_whitespace() {
    // ps 输出通常带尾随换行
    assert_eq!(classify_holder("sing-box\n", 100), HolderKind::SingBox);
    assert_eq!(
        classify_holder("nginx\n", 200),
        HolderKind::Foreign {
            name: "nginx".into()
        }
    );
}

// ===== killed/foreign → FreePort 终态收敛（原 outcome → response）=====

#[test]
fn outcome_free_to_response() {
    let r = free_port_response(Vec::new(), Vec::new());
    assert!(matches!(
        r,
        Response::Ok(ResponseKind::FreePort(FreePort::Free))
    ));
}

#[test]
fn outcome_killed_only_to_response() {
    let r = free_port_response(vec![123, 456], Vec::new());
    match r {
        Response::Ok(ResponseKind::FreePort(FreePort::Killed { pids })) => {
            assert_eq!(pids, vec![123, 456]);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn outcome_foreign_present_prefers_foreign() {
    // helper.go:389-391: 有 foreign → OK foreign（即使也有 killed）
    let r = free_port_response(vec![123], vec!["nginx".into()]);
    match r {
        Response::Ok(ResponseKind::FreePort(FreePort::Foreign { names })) => {
            assert_eq!(names, vec!["nginx".to_owned()]);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn bad_port_response_is_err_badport() {
    let r = bad_port_response();
    match r {
        Response::Err(e) => assert_eq!(e.code, ErrorCode::BadPort),
        other => panic!("{other:?}"),
    }
}

#[test]
fn command_paths_match_go_source() {
    // helper.go:367,376,379
    assert_eq!(LSOF_BIN, "/usr/sbin/lsof");
    assert_eq!(PS_BIN, "/bin/ps");
    assert_eq!(KILL_BIN, "/bin/kill");
}

// ===== run_freeport 端到端（mock runner）=====

/// 可编程 mock：按 (program, key) 返回预设 output。
struct ProgMock {
    lsof_out: Mutex<Vec<u8>>,
    comm_map: Mutex<std::collections::HashMap<u32, String>>,
    killed: Mutex<Vec<u32>>,
}

impl CommandRunner for ProgMock {
    fn run(&self, _t: Duration, p: &str, a: &[&str]) -> Result<(), RunError> {
        // /bin/kill -9 <pid>
        if p == KILL_BIN && a.len() >= 2 && a[0] == "-9" {
            if let Ok(pid) = a[1].parse::<u32>() {
                self.killed.lock().unwrap().push(pid);
            }
        }
        Ok(())
    }
    fn output(&self, _t: Duration, p: &str, a: &[&str]) -> Result<Vec<u8>, RunError> {
        if p == LSOF_BIN {
            return Ok(self.lsof_out.lock().unwrap().clone());
        }
        if p == PS_BIN {
            // ps -o comm= -p <pid>
            for arg in a {
                if let Ok(pid) = arg.parse::<u32>() {
                    if let Some(comm) = self.comm_map.lock().unwrap().get(&pid) {
                        return Ok(comm.as_bytes().to_vec());
                    }
                }
            }
        }
        Ok(Vec::new())
    }
    fn combined(&self, _: Duration, _: &str, _: &[&str]) -> Result<Vec<u8>, RunError> {
        Ok(Vec::new())
    }
}

#[test]
fn run_freeport_bad_port() {
    let m = ProgMock {
        lsof_out: Mutex::new(Vec::new()),
        comm_map: Mutex::new(std::collections::HashMap::new()),
        killed: Mutex::new(Vec::new()),
    };
    let r = run_freeport(&m, "abc");
    assert!(matches!(
        r,
        Response::Err(ProtoError {
            code: ErrorCode::BadPort,
            ..
        })
    ));
}

#[test]
fn run_freeport_empty_port() {
    let m = ProgMock {
        lsof_out: Mutex::new(Vec::new()),
        comm_map: Mutex::new(std::collections::HashMap::new()),
        killed: Mutex::new(Vec::new()),
    };
    let r = run_freeport(&m, "");
    assert!(matches!(
        r,
        Response::Err(ProtoError {
            code: ErrorCode::BadPort,
            ..
        })
    ));
}

#[test]
fn run_freeport_no_holder_returns_free() {
    // lsof 输出空 → OK free
    let m = ProgMock {
        lsof_out: Mutex::new(Vec::new()),
        comm_map: Mutex::new(std::collections::HashMap::new()),
        killed: Mutex::new(Vec::new()),
    };
    let r = run_freeport(&m, "9090");
    assert!(matches!(
        r,
        Response::Ok(ResponseKind::FreePort(FreePort::Free))
    ));
}

#[test]
fn run_freeport_kills_singbox_holders() {
    let mut comm = std::collections::HashMap::new();
    comm.insert(123, "/usr/local/bin/sing-box".into());
    comm.insert(456, "/opt/homebrew/bin/sing-box".into());
    let m = ProgMock {
        lsof_out: Mutex::new(b"123\n456\n".to_vec()),
        comm_map: Mutex::new(comm),
        killed: Mutex::new(Vec::new()),
    };
    let r = run_freeport(&m, "9090");
    match r {
        Response::Ok(ResponseKind::FreePort(FreePort::Killed { pids })) => {
            assert_eq!(pids, vec![123, 456]);
        }
        other => panic!("{other:?}"),
    }
    // kill -9 被调用两次
    assert_eq!(*m.killed.lock().unwrap(), vec![123, 456]);
}

#[test]
fn run_freeport_reports_foreign_not_kills() {
    let mut comm = std::collections::HashMap::new();
    comm.insert(123, "nginx".into());
    let m = ProgMock {
        lsof_out: Mutex::new(b"123\n".to_vec()),
        comm_map: Mutex::new(comm),
        killed: Mutex::new(Vec::new()),
    };
    let r = run_freeport(&m, "9090");
    match r {
        Response::Ok(ResponseKind::FreePort(FreePort::Foreign { names })) => {
            assert_eq!(names, vec!["nginx".to_owned()]);
        }
        other => panic!("{other:?}"),
    }
    // foreign 不应被 kill
    assert!(m.killed.lock().unwrap().is_empty());
}

#[test]
fn run_freeport_mixed_prefers_foreign() {
    // 混合：sing-box + nginx。Go helper.go:389 → OK foreign（混合也归 foreign，诚实终态）
    let mut comm = std::collections::HashMap::new();
    comm.insert(123, "sing-box".into());
    comm.insert(456, "nginx".into());
    let m = ProgMock {
        lsof_out: Mutex::new(b"123 456\n".to_vec()),
        comm_map: Mutex::new(comm),
        killed: Mutex::new(Vec::new()),
    };
    let r = run_freeport(&m, "9090");
    assert!(matches!(
        r,
        Response::Ok(ResponseKind::FreePort(FreePort::Foreign { .. }))
    ));
    // sing-box 那个仍被 kill（Go 源对每个 sing-box 都 kill -9，即便最终报 foreign）
    assert_eq!(*m.killed.lock().unwrap(), vec![123]);
}
