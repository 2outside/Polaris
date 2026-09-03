use super::*;
use std::collections::HashMap;

/// 内存 FS mock：dir → 条目名列表。未注册的 dir → None。
struct MockFs {
    dirs: HashMap<PathBuf, Vec<String>>,
}

impl TailscaleStateFs for MockFs {
    fn read_dir_names(&self, dir: &Path) -> Option<Vec<String>> {
        self.dirs.get(dir).cloned()
    }
}

#[test]
fn state_dir_joins_user_data_tailscale_serverid() {
    let p = tailscale_state_dir(Path::new("/app/userdata"), "srv-1").unwrap();
    assert_eq!(p, PathBuf::from("/app/userdata/tailscale/srv-1"));
}

#[test]
fn state_exists_true_when_nonempty() {
    let dir = tailscale_state_dir(Path::new("/ud"), "s1").unwrap();
    let fs = MockFs {
        dirs: [(dir, vec!["tailscaled.state".to_string()])]
            .into_iter()
            .collect(),
    };
    assert!(state_exists(&fs, Path::new("/ud"), "s1"));
}

#[test]
fn state_exists_false_when_empty() {
    let dir = tailscale_state_dir(Path::new("/ud"), "s1").unwrap();
    let fs = MockFs {
        dirs: [(dir, vec![])].into_iter().collect(),
    };
    assert!(!state_exists(&fs, Path::new("/ud"), "s1"));
}

#[test]
fn state_exists_false_when_missing_or_read_fails() {
    let fs = MockFs {
        dirs: HashMap::new(),
    };
    // 目录缺失 → read_dir_names 返 None → false（失败安全）。
    assert!(!state_exists(&fs, Path::new("/ud"), "absent"));
}

#[test]
fn state_dir_rejects_non_portable_or_escaping_ids() {
    for id in [
        "",
        ".",
        "..",
        "../victim",
        "/tmp/victim",
        r"..\victim",
        r"C:\victim",
        r"\\server\share",
        "bad\0id",
    ] {
        assert!(
            tailscale_state_dir(Path::new("/ud"), id).is_err(),
            "must reject {id:?}"
        );
    }
    assert!(tailscale_state_dir(Path::new("/ud"), &"x".repeat(256)).is_err());
}

#[test]
fn invalid_id_never_reaches_the_filesystem_boundary() {
    let fs = MockFs {
        dirs: HashMap::new(),
    };
    assert!(!state_exists(&fs, Path::new("/ud"), "../victim"));
}
