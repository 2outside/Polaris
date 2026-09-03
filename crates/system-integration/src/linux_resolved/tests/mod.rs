use super::*;
use crate::proxy::proxy_tests_helpers::MemFs;
use std::sync::Mutex;

#[derive(Default)]
struct MockOps {
    calls: Mutex<Vec<&'static str>>,
    takeover_error: Option<String>,
    revert_error: Option<String>,
}

impl LinuxResolvedOps for MockOps {
    fn takeover(&self) -> Result<(), String> {
        self.calls.lock().unwrap().push("takeover");
        self.takeover_error.clone().map_or(Ok(()), Err)
    }

    fn revert(&self) -> Result<(), String> {
        self.calls.lock().unwrap().push("revert");
        self.revert_error.clone().map_or(Ok(()), Err)
    }
}

fn controller(ops: MockOps) -> LinuxResolvedController<MockOps, MemFs> {
    LinuxResolvedController::new(ops, MemFs::new(), "/linux-resolved.marker.json")
}

#[test]
fn takeover_writes_intent_before_apply() {
    let mut controller = controller(MockOps::default());
    controller.takeover().unwrap();
    assert!(controller.has_marker());
    assert_eq!(*controller.ops.calls.lock().unwrap(), ["takeover"]);
}

#[test]
fn failed_takeover_clears_marker_after_helper_rollback() {
    let mut controller = controller(MockOps {
        takeover_error: Some("unsupported old helper".to_owned()),
        ..Default::default()
    });
    assert!(controller.takeover().is_err());
    assert!(!controller.has_marker());
}

#[test]
fn restore_clears_only_after_success() {
    let mut controller = controller(MockOps::default());
    controller.takeover().unwrap();
    controller.restore().unwrap();
    assert!(!controller.has_marker());
    assert_eq!(
        *controller.ops.calls.lock().unwrap(),
        ["takeover", "revert"]
    );
}

#[test]
fn failed_restore_keeps_marker_for_crash_recovery() {
    let mut controller = controller(MockOps::default());
    controller.takeover().unwrap();
    controller.ops.revert_error = Some("temporary failure".to_owned());
    assert!(controller.restore().is_err());
    assert!(controller.has_marker());
}

#[test]
fn reconcile_is_gated_by_marker() {
    let mut controller = controller(MockOps::default());
    controller.reconcile().unwrap();
    assert!(controller.ops.calls.lock().unwrap().is_empty());
    controller.takeover().unwrap();
    controller.reconcile().unwrap();
    assert_eq!(
        *controller.ops.calls.lock().unwrap(),
        ["takeover", "takeover"]
    );
}
