#![allow(clippy::too_many_lines)]

use super::*;
use polaris_helper_proto::{Response, ResponseKind};
use std::sync::Mutex;

/// 把 [`FreePort`] 走协议层序列化为 wire 行 —— 断言 linux 的 freeport 终态产出的 wire
/// 与 Go 源逐字一致（序列化本体是 `Response::to_wire_line`，见 G3.1）。
fn wire(fp: &FreePort) -> String {
    Response::Ok(ResponseKind::FreePort(fp.clone())).to_wire_line()
}

// ===== parse_ss_pids（逐字对照 Go TestSsPidRe）=====

#[test]
fn parse_ss_pids_extracts_pid_from_listen_line() {
    // Go TestSsPidRe: LISTEN ... users:(("sing-box",pid=1234,fd=7))
    let line = "LISTEN 0 4096 0.0.0.0:9090 0.0.0.0:* users:((\"sing-box\",pid=1234,fd=7))";
    let pids = parse_ss_pids(line);
    assert_eq!(pids, vec![1234]);
}

#[test]
fn parse_ss_pids_returns_empty_when_no_match() {
    assert!(parse_ss_pids("no match here").is_empty());
}

#[test]
fn parse_ss_pids_dedupes_repeated_pids() {
    // Go 用 map[string]bool 去重 —— 同一 pid 多次出现只算一次。
    let out = "pid=111 pid=222 pid=111";
    let pids = parse_ss_pids(out);
    assert_eq!(pids, vec![111, 222]);
}

#[test]
fn parse_ss_pids_multiple_distinct() {
    let out = "pid=1000\npid=1001\npid=1002";
    assert_eq!(parse_ss_pids(out), vec![1000, 1001, 1002]);
}

#[test]
fn parse_ss_pids_ignores_non_digit_after_pid_eq() {
    // pid= 后无数字 → 不匹配（digits 为空 parse 失败）。
    assert!(parse_ss_pids("pid=abc").is_empty());
}

// ===== FreePortDeps mock + free_port 逻辑 =====

/// 完全可控的 deps mock：proc_uid / proc_comm / kill 全部按预置表返回。
struct MockDeps {
    /// pid → uid 映射（缺省 → None）。
    uids: std::collections::HashMap<u32, u32>,
    /// pid → comm 映射（缺省 → None）。
    comms: std::collections::HashMap<u32, String>,
    /// 记录被 kill 的 pid 序。
    killed: Mutex<Vec<u32>>,
}

impl MockDeps {
    fn new() -> Self {
        Self {
            uids: std::collections::HashMap::new(),
            comms: std::collections::HashMap::new(),
            killed: Mutex::new(Vec::new()),
        }
    }
    fn with(pid: u32, uid: u32, comm: &str) -> Self {
        let mut m = Self::new();
        m.uids.insert(pid, uid);
        m.comms.insert(pid, comm.to_string());
        m
    }
}

impl FreePortDeps for MockDeps {
    fn proc_uid(&self, pid: u32) -> Option<u32> {
        self.uids.get(&pid).copied()
    }
    fn proc_comm(&self, pid: u32) -> Option<String> {
        self.comms.get(&pid).cloned()
    }
    fn kill(&self, pid: u32) -> bool {
        self.killed.lock().unwrap().push(pid);
        true
    }
}

#[test]
fn free_port_empty_pids_returns_free() {
    let deps = MockDeps::new();
    let r = free_port(&[], 1000, &deps);
    assert_eq!(r, FreePort::Free);
    assert_eq!(wire(&r), "OK free");
}

#[test]
fn free_port_kills_own_singbox() {
    // 对端 uid 自己的 sing-box → kill。
    let deps = MockDeps::with(1234, 1000, "sing-box");
    let r = free_port(&[1234], 1000, &deps);
    assert_eq!(r, FreePort::Killed { pids: vec![1234] });
    assert_eq!(wire(&r), "OK killed 1234");
    assert_eq!(*deps.killed.lock().unwrap(), vec![1234]);
}

#[test]
fn free_port_foreign_when_other_uid() {
    // 非 caller_uid 的进程 → foreign，不杀。
    let deps = MockDeps::with(1234, 999, "sing-box"); // uid 999 != caller 1000
    let r = free_port(&[1234], 1000, &deps);
    let wire_line = wire(&r);
    match r {
        FreePort::Foreign { names } => {
            assert_eq!(names, vec!["pid:1234".to_string()]);
        }
        other => panic!("expected Foreign, got {other:?}"),
    }
    assert_eq!(wire_line, "OK foreign pid:1234");
    assert!(deps.killed.lock().unwrap().is_empty(), "不应跨用户杀");
}

#[test]
fn free_port_foreign_when_not_singbox() {
    // caller 自己的进程但非 sing-box → 记名，不杀。
    let deps = MockDeps::with(1234, 1000, "nginx");
    let r = free_port(&[1234], 1000, &deps);
    match r {
        FreePort::Foreign { names } => {
            assert_eq!(names, vec!["nginx".to_string()]);
        }
        other => panic!("expected Foreign, got {other:?}"),
    }
    assert!(deps.killed.lock().unwrap().is_empty(), "非 sing-box 不应杀");
}

#[test]
fn free_port_foreign_uses_pid_when_comm_empty() {
    // comm 为空 → 用 "pid:<n>"（Go :321-322）。
    let mut deps = MockDeps::new();
    deps.uids.insert(1234, 1000);
    // comm 缺省 → None → unwrap_or_default → ""
    let r = free_port(&[1234], 1000, &deps);
    match r {
        FreePort::Foreign { names } => {
            assert_eq!(names, vec!["pid:1234".to_string()]);
        }
        other => panic!("expected Foreign, got {other:?}"),
    }
}

#[test]
fn free_port_foreign_when_proc_uid_missing() {
    // proc_uid 返回 None（进程已退出）→ 视作非本 uid → foreign。
    let deps = MockDeps::new();
    let r = free_port(&[1234], 1000, &deps);
    match r {
        FreePort::Foreign { names } => {
            assert_eq!(names, vec!["pid:1234".to_string()]);
        }
        other => panic!("expected Foreign, got {other:?}"),
    }
}

#[test]
fn free_port_mixed_killed_and_foreign_returns_foreign() {
    // 混合占用：有 sing-box（杀）+ 有 foreign（不杀）→ Go :327 归 foreign。
    let mut deps = MockDeps::new();
    deps.uids.insert(100, 1000);
    deps.uids.insert(200, 1000);
    deps.comms.insert(100, "sing-box".to_string());
    deps.comms.insert(200, "nginx".to_string());
    let r = free_port(&[100, 200], 1000, &deps);
    // 混合 → Foreign（Go: if len(foreign) > 0 → foreign）。
    assert!(matches!(r, FreePort::Foreign { .. }));
    // sing-box 仍被杀（foreign 分支不影响 kill 调用已发生）。
    assert_eq!(*deps.killed.lock().unwrap(), vec![100]);
}

#[test]
fn free_port_multiple_singbox_all_killed() {
    let mut deps = MockDeps::new();
    for pid in [100, 200, 300] {
        deps.uids.insert(pid, 1000);
        deps.comms.insert(pid, "sing-box".to_string());
    }
    let r = free_port(&[100, 200, 300], 1000, &deps);
    assert_eq!(
        r,
        FreePort::Killed {
            pids: vec![100, 200, 300]
        }
    );
    assert_eq!(wire(&r), "OK killed 100,200,300");
}
