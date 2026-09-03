#![allow(clippy::too_many_lines)]

use super::*;

#[test]
fn spawn_request_argv_is_run_c_config_plus_extras() {
    // 对齐 Polaris 直接 spawn：`['run', '-c', configPath]`（:4790）。
    let req = SpawnRequest::new(
        "/usr/local/bin/sing-box",
        "/tmp/cfg.json",
        StdioPolicy::Discard,
    );
    assert_eq!(
        req.argv(),
        vec![
            "run".to_string(),
            "-c".to_string(),
            "/tmp/cfg.json".to_string()
        ]
    );
}

#[test]
fn spawn_request_argv_appends_extra_args() {
    let mut req = SpawnRequest::new("/bin/sing-box", "/tmp/c.json", StdioPolicy::Discard);
    req.extra_args = vec!["--debug".to_string(), "--legacy".to_string()];
    assert_eq!(
        req.argv(),
        vec![
            "run".to_string(),
            "-c".to_string(),
            "/tmp/c.json".to_string(),
            "--debug".to_string(),
            "--legacy".to_string()
        ]
    );
}

#[tokio::test]
async fn tokio_spawner_returns_spawn_error_for_missing_binary() {
    // ENOENT → SpawnError::Spawn（上层据此判 retry）。
    let spawner = TokioSpawner::new();
    let req = SpawnRequest::new(
        "/nonexistent/sing-box-xyz",
        "/tmp/c.json",
        StdioPolicy::Discard,
    );
    let r = spawner.spawn(req);
    assert!(r.is_err());
    match r {
        Err(SpawnError::Spawn { bin, source }) => {
            assert_eq!(bin, PathBuf::from("/nonexistent/sing-box-xyz"));
            // io::Error kind 应为 NotFound。
            assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
        }
        other => panic!("expected SpawnError::Spawn, got {other:?}"),
    }
}

#[test]
fn spawned_child_pid_api_is_callable() {
    // SpawnedChild::pid 转发 child.id()。仅静态验证 API 存在；
    // 真实 pid 读取由 tokio_spawner_real_child_spawns_and_pid_present 覆盖。
    fn takes_spawned(s: &SpawnedChild) -> Option<u32> {
        s.pid()
    }
    // 引用以避免未用警告；不构造真实 Child（pid 语义由集成测试覆盖）。
    let _ = takes_spawned as fn(&SpawnedChild) -> Option<u32>;
}
