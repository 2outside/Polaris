use super::*;

#[test]
fn handler_state_new_has_no_child() {
    let s = HandlerState::new();
    assert!(s.child.is_none());
}

#[test]
fn handler_state_default_equals_new() {
    let a = HandlerState::new();
    let b = HandlerState::default();
    assert!(a.child.is_none());
    assert!(b.child.is_none());
}

#[test]
fn spawn_request_carries_all_fields() {
    let r = SpawnCoreRequest {
        binary: PathBuf::from("/core/sing-box"),
        config: PathBuf::from("/tmp/c.json"),
        log: Some(PathBuf::from("/tmp/l.log")),
        fwd: true,
        parent_pid: Some(999),
        uid: 1000,
        gid: 1000,
        groups: vec![1000, 27, 44],
    };
    assert_eq!(r.binary, PathBuf::from("/core/sing-box"));
    assert_eq!(r.config, PathBuf::from("/tmp/c.json"));
    assert!(r.fwd);
    assert_eq!(r.parent_pid, Some(999));
    assert_eq!(r.uid, 1000);
    assert_eq!(r.gid, 1000);
    assert_eq!(r.groups, vec![1000, 27, 44]);
}

#[test]
fn spawn_error_display_matches_wire() {
    // wire 形态 "ERR start <detail>" 的 detail 部分应与 Display 输出一致。
    let e = SpawnError::Spawn {
        detail: "exit status 1".into(),
    };
    assert_eq!(e.to_string(), "start exit status 1");
}

/// 静态断言：CoreSpawner 是对象安全 + Send + Sync（生产注入用 `Box<dyn>`）。
#[allow(dead_code)]
fn _assert_core_spawner_object_safe(_s: Box<dyn CoreSpawner>) {}
