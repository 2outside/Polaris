//! A3 缓存面门：末帧缓存读写 + 快照合成（relay ⇄ tailscale_get_status 的中转）。
use super::super::*;
use crate::test_support::TestDir;

fn temp_dir(tag: &str) -> TestDir {
    TestDir::new(&format!("polaris-tsstatus-{tag}-"))
}

fn event(id: &str, logged_in: bool) -> TailscaleStatusEvent {
    TailscaleStatusEvent {
        server_id: id.to_string(),
        backend_state: if logged_in { "Running" } else { "NeedsLogin" }.to_string(),
        logged_in,
        auth_url: None,
        tailscale_ips: vec!["100.64.0.1".to_string()],
        expired: false,
        peers: Vec::new(),
        details: Default::default(),
        // Taildrop 四位在本用例无关，取「无能力、无文件」的中性值；不给 Default 是刻意的：
        // 日后再加字段时，这些构造点必须重新被人看一眼，而不是被 `..Default::default()` 静默补齐。
        can_share_files: false,
        waiting_file_count: 0,
        receiving_file_count: 0,
        unread_file_count: 0,
    }
}

#[test]
fn logout_rejects_path_escape_without_touching_sibling_directory() {
    let root = temp_dir("logout-escape");
    let config = root.join("config");
    let victim = root.join("victim");
    std::fs::create_dir_all(&config).unwrap();
    std::fs::create_dir_all(&victim).unwrap();
    std::fs::write(victim.join("sentinel"), b"keep").unwrap();

    let mesh = MeshRuntime::new(config);
    let error = mesh.tailscale_logout("../victim").unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(victim.join("sentinel").exists());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn logout_removes_only_the_valid_managed_state_directory() {
    let root = temp_dir("logout-valid");
    let config = root.join("config");
    let mesh = MeshRuntime::new(config.clone());
    let state = mesh.tailscale_state_dir("srv-1").unwrap();
    std::fs::create_dir_all(&state).unwrap();
    std::fs::write(state.join("tailscaled.state"), b"state").unwrap();

    mesh.tailscale_logout("srv-1").unwrap();
    assert!(!state.exists());
    assert!(config.exists());
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn logout_rejects_a_state_root_symlink_escape() {
    let root = temp_dir("logout-symlink");
    let config = root.join("config");
    let victim_state = root.join("victim/srv-1");
    std::fs::create_dir_all(&config).unwrap();
    std::fs::create_dir_all(&victim_state).unwrap();
    std::fs::write(victim_state.join("sentinel"), b"keep").unwrap();
    std::os::unix::fs::symlink(root.join("victim"), config.join("tailscale")).unwrap();

    let mesh = MeshRuntime::new(config);
    let error = mesh.tailscale_logout("srv-1").unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(victim_state.join("sentinel").exists());
    let _ = std::fs::remove_dir_all(root);
}

/// 空缓存（无帧）→ 快照 statuses 空；connected 透传调用方入参（核 running 态）。
#[test]
fn empty_cache_snapshot_is_empty_but_connected_passes_through() {
    let dir = temp_dir("empty");
    let mesh = MeshRuntime::new(dir.clone());
    let snap = mesh.tailscale_status_snapshot(true);
    assert!(snap.connected, "connected 由入参透传（核在跑）");
    assert!(snap.statuses.is_empty(), "无帧 → statuses 空");
}

/// update → 快照读回真数据（非恒空）。打断 `update_ts_status` 落库 / `tailscale_status_snapshot` 读缓存 → 转红。
#[test]
fn update_then_snapshot_returns_cached_frame() {
    let dir = temp_dir("update");
    let mesh = MeshRuntime::new(dir.clone());
    mesh.update_ts_status(vec![event("srv-a", true), event("srv-b", false)]);
    let snap = mesh.tailscale_status_snapshot(true);
    assert_eq!(snap.statuses.len(), 2, "快照读回缓存末帧（非恒空）");
    assert_eq!(snap.statuses[0].server_id, "srv-a");
    assert!(snap.statuses[0].logged_in);
    assert!(!snap.statuses[1].logged_in);
}

/// 每帧整体替换（非累加）：第二帧覆盖第一帧。打断「替换」为「追加」→ len 转红。
#[test]
fn frame_replaces_wholesale() {
    let dir = temp_dir("replace");
    let mesh = MeshRuntime::new(dir.clone());
    mesh.update_ts_status(vec![event("srv-a", true), event("srv-b", true)]);
    mesh.update_ts_status(vec![event("srv-c", false)]); // 新的全量帧
    let snap = mesh.tailscale_status_snapshot(true);
    assert_eq!(snap.statuses.len(), 1, "全量帧整体替换，非累加");
    assert_eq!(snap.statuses[0].server_id, "srv-c");
}

/// 停核 clear → 缓存清空。打断 `clear_ts_status` → 快照仍带陈旧帧 → 转红。
#[test]
fn clear_drops_cached_frame() {
    let dir = temp_dir("clear");
    let mesh = MeshRuntime::new(dir.clone());
    mesh.update_ts_status(vec![event("srv-a", true)]);
    mesh.clear_ts_status();
    let snap = mesh.tailscale_status_snapshot(false);
    assert!(!snap.connected);
    assert!(snap.statuses.is_empty(), "清缓存后无陈旧帧");
}

/// A4：`selected_exit_backend_state` 读选中出口末帧 backendState。
#[test]
fn selected_exit_backend_state_reads_frame() {
    let dir = temp_dir("bstate");
    let mesh = MeshRuntime::new(dir.clone());
    // 无帧 → None。
    assert_eq!(mesh.selected_exit_backend_state("srv-a"), None);
    // 有帧 → 读回 backendState。
    mesh.update_ts_status(vec![event("srv-a", false), event("srv-b", true)]);
    assert_eq!(
        mesh.selected_exit_backend_state("srv-a").as_deref(),
        Some("NeedsLogin")
    );
    assert_eq!(
        mesh.selected_exit_backend_state("srv-b").as_deref(),
        Some("Running")
    );
    // 未在册端点 → None。
    assert_eq!(mesh.selected_exit_backend_state("srv-x"), None);
}

/// A4：`expired` 帧即便 backendState=Running 也投影为 `"NeedsLogin"`（key 过期须重登，防死出口黑洞）。
/// 打断 `selected_exit_backend_state` 的 expired 分支 → 返回 "Running" → 转红。
#[test]
fn selected_exit_backend_state_expired_maps_to_needs_login() {
    let dir = temp_dir("expired");
    let mesh = MeshRuntime::new(dir.clone());
    let mut ev = event("srv-a", true); // backend_state=Running, logged_in=true
    ev.expired = true;
    mesh.update_ts_status(vec![ev]);
    assert_eq!(
        mesh.selected_exit_backend_state("srv-a").as_deref(),
        Some("NeedsLogin"),
        "过期 key 须投影为 NeedsLogin，即便帧仍报 Running"
    );
}
