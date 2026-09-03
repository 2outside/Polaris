#![allow(clippy::too_many_lines)]

use super::*;
use std::sync::Mutex;

// ===== SystemdOps mock + 测试 =====

/// 记录所有 systemctl 调用的 mock（线程安全，可断言副作用序）。
#[derive(Debug, Default)]
struct MockSystemd {
    calls: Mutex<Vec<(String, SystemdAction)>>,
    /// 固定返回值（每次 run 都返回此）。
    result: SystemdResult,
}

impl MockSystemd {
    fn succeeding() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            result: SystemdResult::ok(),
        }
    }

    fn failing(detail: &str) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            result: SystemdResult::err(detail),
        }
    }

    fn snapshot(&self) -> Vec<(String, SystemdAction)> {
        self.calls.lock().unwrap().clone()
    }
}

impl SystemdOps for MockSystemd {
    fn run(&self, unit: &str, action: SystemdAction) -> SystemdResult {
        self.calls.lock().unwrap().push((unit.to_string(), action));
        self.result.clone()
    }
}

#[test]
fn systemd_action_verb_mapping() {
    // systemctl 子命令名是 wire 兼容/运维契约（改名 = 断 systemctl 调用）。
    assert_eq!(SystemdAction::Install.systemctl_verb(), "enable");
    assert_eq!(SystemdAction::Start.systemctl_verb(), "start");
    assert_eq!(SystemdAction::Stop.systemctl_verb(), "stop");
    assert_eq!(SystemdAction::Restart.systemctl_verb(), "restart");
    assert_eq!(SystemdAction::Uninstall.systemctl_verb(), "disable");
}

#[test]
fn mock_systemd_records_calls_and_returns_ok() {
    let m = MockSystemd::succeeding();
    let r = m.run("polaris-helper.service", SystemdAction::Start);
    assert!(r.ok);
    assert_eq!(
        m.snapshot(),
        vec![("polaris-helper.service".to_string(), SystemdAction::Start)]
    );
}

#[test]
fn mock_systemd_returns_failure_detail() {
    let m = MockSystemd::failing("unit not loaded");
    let r = m.run("polaris-helper.service", SystemdAction::Stop);
    assert!(!r.ok);
    assert_eq!(r.detail, "unit not loaded");
}

#[test]
fn mock_systemd_records_sequence_of_actions() {
    // 验证 install → start → stop 的副作用序（对应 helper 生命周期）。
    let m = MockSystemd::succeeding();
    m.run("u", SystemdAction::Install);
    m.run("u", SystemdAction::Start);
    m.run("u", SystemdAction::Stop);
    let snap = m.snapshot();
    assert_eq!(snap.len(), 3);
    assert_eq!(snap[0].1, SystemdAction::Install);
    assert_eq!(snap[1].1, SystemdAction::Start);
    assert_eq!(snap[2].1, SystemdAction::Stop);
}

// ===== TunOps mock + 测试 =====

#[derive(Debug, Default)]
struct MockTun {
    calls: Mutex<Vec<TunAction>>,
    fail: bool,
}

// bool 的默认值 false 即 MockTun 的成功路径。

impl TunOps for MockTun {
    fn run(&self, action: &TunAction) -> Result<(), String> {
        self.calls.lock().unwrap().push(action.clone());
        if self.fail {
            Err("tuntap busy".to_string())
        } else {
            Ok(())
        }
    }
}

#[test]
fn tun_action_create_destroy_roundtrip() {
    let m = MockTun::default();
    m.run(&TunAction::Create {
        name: "polaris-ts".into(),
    })
    .unwrap();
    m.run(&TunAction::Destroy {
        name: "polaris-ts".into(),
    })
    .unwrap();
    let snap = m.calls.lock().unwrap().clone();
    assert_eq!(snap.len(), 2);
    assert!(matches!(&snap[0], TunAction::Create { name } if name == "polaris-ts"));
    assert!(matches!(&snap[1], TunAction::Destroy { name } if name == "polaris-ts"));
}

#[test]
fn tun_action_failure_propagates() {
    let m = MockTun {
        calls: Mutex::new(Vec::new()),
        fail: true,
    };
    let r = m.run(&TunAction::Create { name: "x".into() });
    assert!(r.is_err());
    assert_eq!(r.unwrap_err(), "tuntap busy");
}

// ===== RouteOps mock + 测试 =====

#[derive(Debug, Default)]
struct MockRoute {
    calls: Mutex<Vec<RouteAction>>,
}

impl RouteOps for MockRoute {
    fn run(&self, action: &RouteAction) -> Result<(), String> {
        self.calls.lock().unwrap().push(action.clone());
        Ok(())
    }
}

#[test]
fn route_verb_as_str() {
    assert_eq!(RouteVerb::Add.as_str(), "add");
    assert_eq!(RouteVerb::Del.as_str(), "del");
}

#[test]
fn route_action_recorded() {
    let m = MockRoute::default();
    m.run(&RouteAction {
        verb: RouteVerb::Add,
        cidr: "10.0.0.0/8".into(),
        via: "dev polaris-ts".into(),
    })
    .unwrap();
    let snap = m.calls.lock().unwrap();
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].cidr, "10.0.0.0/8");
    assert_eq!(snap[0].via, "dev polaris-ts");
}

// ===== trim_lossy =====

#[test]
fn trim_lossy_combines_stdout_stderr() {
    let o = std::process::Output {
        status: std::process::ExitStatus::default(),
        stdout: b"out line".to_vec(),
        stderr: b"err line".to_vec(),
    };
    let s = trim_lossy(&o);
    assert_eq!(s, "out line err line");
}

#[test]
fn trim_lossy_empty_when_no_output() {
    let o = std::process::Output {
        status: std::process::ExitStatus::default(),
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    assert_eq!(trim_lossy(&o), "");
}

// ===== set_forward_prod（best-effort，非 root 不 panic）=====

#[test]
fn set_forward_prod_does_not_panic_when_not_root() {
    // 写 /proc/sys 需要 root；非 root 环境应静默忽略（best-effort，对齐 Go `_ =`）。
    set_forward_prod(true);
    set_forward_prod(false);
    // 不 panic 即通过。
}

// ===== SystemdResult helpers =====

#[test]
fn systemd_result_ok_no_detail() {
    let r = SystemdResult::ok();
    assert!(r.ok);
    assert!(r.detail.is_empty());
}

#[test]
fn systemd_result_err_carries_detail() {
    let r = SystemdResult::err("boom");
    assert!(!r.ok);
    assert_eq!(r.detail, "boom");
}

/// 静态断言：trait 是对象安全的（可 `Box<dyn Trait>`，生产环境注入用）。
#[allow(dead_code)]
fn _assert_object_safety(_s: Box<dyn SystemdOps>, _t: Box<dyn TunOps>, _r: Box<dyn RouteOps>) {}

/// 静态断言：Send + Sync 约束满足（tokio spawn 跨 await 需要）。
#[allow(dead_code)]
fn _assert_send_sync(
    _s: &(dyn SystemdOps + Send + Sync),
    _t: &(dyn TunOps + Send + Sync),
    _r: &(dyn RouteOps + Send + Sync),
) {
}

/// Path 引用避免未用 import 警告（owned_by 等用 Path，此模块仅类型引用）。
#[test]
fn path_type_referenced() {
    let _ = Path::new("/tmp");
}
