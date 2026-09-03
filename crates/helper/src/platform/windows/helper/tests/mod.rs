#![allow(clippy::too_many_lines)]

use super::*;
use crate::platform::windows::ops::{MockNetTableOps, MockProcOps};
use crate::token::StaticTokenStore;
use polaris_helper_proto::StartParams;

fn make_helper(
    proc_ops: MockProcOps,
    net_ops: MockNetTableOps,
) -> WinHelper<StaticTokenStore, MockProcOps, MockNetTableOps> {
    WinHelper::new(
        StaticTokenStore::new("real-token"),
        proc_ops,
        net_ops,
        r"C:\Program Files\Polaris\sing-box.exe",
        r"C:\Users\polaris\config",
        "PolarisHelper",
        r"C:\ProgramData\Polaris",
    )
}

fn make_helper_defaults() -> WinHelper<StaticTokenStore, MockProcOps, MockNetTableOps> {
    make_helper(MockProcOps::new(), MockNetTableOps::new())
}

// ===== 鉴权 =====

#[test]
fn auth_failed_on_wrong_token() {
    let h = make_helper_defaults();
    let out = h.handle("wrong-token", Request::Ping);
    assert_eq!(out, HandleOutcome::AuthFailed);
}

#[test]
fn auth_failed_on_empty_token() {
    let h = make_helper_defaults();
    let out = h.handle("", Request::Ping);
    assert_eq!(out, HandleOutcome::AuthFailed);
}

#[test]
fn auth_passes_on_correct_token() {
    let h = make_helper_defaults();
    let out = h.handle("real-token", Request::Ping);
    let HandleOutcome::Respond(Response::Ok(ResponseKind::Pong(pong))) = out else {
        panic!("{out:?}");
    };
    // Windows uid 固定 0（helper.go:179）
    assert_eq!(pong.uid, 0);
    assert_eq!(pong.proto_version, crate::platform::windows::PROTO_VERSION);
}

// ===== ping/version/status =====

#[test]
fn version_returns_proto_version() {
    let h = make_helper_defaults();
    let out = h.handle("real-token", Request::Version);
    let HandleOutcome::Respond(Response::Ok(ResponseKind::Version { proto_version })) = out else {
        panic!("{out:?}");
    };
    assert_eq!(proto_version, crate::platform::windows::PROTO_VERSION);
}

#[test]
fn status_stopped_when_no_child() {
    let h = make_helper_defaults();
    let out = h.handle("real-token", Request::Status);
    assert_eq!(
        out,
        HandleOutcome::Respond(Response::Ok(ResponseKind::Status(
            polaris_helper_proto::Status::Stopped
        )))
    );
}

// ===== start =====

#[test]
fn start_with_empty_cfg_is_no_config() {
    let h = make_helper_defaults();
    let out = h.handle(
        "real-token",
        Request::Start(StartParams {
            cfg: String::new(),
            log: String::new(),
            fwd: false,
            parent_pid: None,
        }),
    );
    let HandleOutcome::Respond(Response::Err(e)) = out else {
        panic!("{out:?}");
    };
    assert_eq!(e.code, polaris_helper_proto::ErrorCode::NoConfig);
}

#[test]
fn start_with_cfg_outside_confdir_is_denied() {
    let h = make_helper_defaults();
    let out = h.handle(
        "real-token",
        Request::Start(StartParams {
            cfg: r"C:\Windows\evil.json".to_owned(),
            log: String::new(),
            fwd: false,
            parent_pid: None,
        }),
    );
    let HandleOutcome::Respond(Response::Err(e)) = out else {
        panic!("{out:?}");
    };
    assert_eq!(e.code, polaris_helper_proto::ErrorCode::ConfigPathDenied);
}

/// log 与 cfg 走同一条白名单 —— 不校验就是「SYSTEM 在任意位置建文件并持续追加写」。
#[test]
fn start_with_log_outside_confdir_is_denied() {
    let h = make_helper_defaults();
    let out = h.handle(
        "real-token",
        Request::Start(StartParams {
            // cfg 合法，只有 log 越界 —— 单独钉住 log 这一格。
            cfg: r"C:\Users\polaris\config\singbox-runtime.json".to_owned(),
            log: r"C:\Windows\System32\drivers\etc\hosts".to_owned(),
            fwd: false,
            parent_pid: None,
        }),
    );
    let HandleOutcome::Respond(Response::Err(e)) = out else {
        panic!("{out:?}");
    };
    assert_eq!(e.code, polaris_helper_proto::ErrorCode::LogPathDenied);
}

/// 生产形态（cfg 与 log 同在 confDir）必须放行 —— 否则上面那条可能被「恒拒」满足。
#[test]
fn start_with_log_inside_confdir_is_allowed() {
    let h = make_helper_defaults();
    let out = h.handle(
        "real-token",
        Request::Start(StartParams {
            cfg: r"C:\Users\polaris\config\singbox-runtime.json".to_owned(),
            log: r"C:\Users\polaris\config\singbox-startup.log".to_owned(),
            fwd: false,
            parent_pid: None,
        }),
    );
    assert!(
        !matches!(
            &out,
            HandleOutcome::Respond(Response::Err(e))
                if e.code == polaris_helper_proto::ErrorCode::LogPathDenied
        ),
        "生产形态被误拒：{out:?}"
    );
}

/// 空 log = 不重定向（`win.rs` 的 `if !log_path.is_empty()`），必须放行。
#[test]
fn start_with_empty_log_is_allowed() {
    let h = make_helper_defaults();
    let out = h.handle(
        "real-token",
        Request::Start(StartParams {
            cfg: r"C:\Users\polaris\config\singbox-runtime.json".to_owned(),
            log: String::new(),
            fwd: false,
            parent_pid: None,
        }),
    );
    assert!(
        !matches!(
            &out,
            HandleOutcome::Respond(Response::Err(e))
                if e.code == polaris_helper_proto::ErrorCode::LogPathDenied
        ),
        "空 log 被误拒：{out:?}"
    );
}

#[test]
fn start_with_valid_cfg_starts_and_records_pid() {
    let proc_ops = MockProcOps::new();
    let h = make_helper(proc_ops, MockNetTableOps::new());
    let out = h.handle(
        "real-token",
        Request::Start(StartParams {
            cfg: r"C:\Users\polaris\config\c.json".to_owned(),
            log: String::new(),
            fwd: false,
            parent_pid: None,
        }),
    );
    let HandleOutcome::Respond(Response::Ok(ResponseKind::Start(
        polaris_helper_proto::Start::StartedTimed { pid, timing },
    ))) = out
    else {
        panic!("{out:?}");
    };
    // mock next_pid + mock 阶段耗时。
    assert_eq!(pid, 1000);
    assert_eq!(timing.total_ms, 0);
    // status 应反映 running
    let out2 = h.handle("real-token", Request::Status);
    assert!(matches!(
        out2,
        HandleOutcome::Respond(Response::Ok(ResponseKind::Status(
            polaris_helper_proto::Status::Running { pid: 1000 }
        )))
    ));
}

#[test]
fn status_clears_a_managed_pid_after_the_child_exits() {
    let proc_ops = MockProcOps::new();
    let h = make_helper(proc_ops.clone(), MockNetTableOps::new());
    let request = Request::Start(StartParams {
        cfg: r"C:\Users\polaris\config\c.json".to_owned(),
        log: String::new(),
        fwd: false,
        parent_pid: None,
    });
    let _ = h.handle("real-token", request.clone());

    proc_ops.set_alive(false);
    assert!(matches!(
        h.handle("real-token", Request::Status),
        HandleOutcome::Respond(Response::Ok(ResponseKind::Status(
            polaris_helper_proto::Status::Stopped
        )))
    ));

    proc_ops.set_alive(true);
    let restarted = h.handle("real-token", request);
    assert!(matches!(
        restarted,
        HandleOutcome::Respond(Response::Ok(ResponseKind::Start(
            polaris_helper_proto::Start::StartedTimed { pid: 1001, .. }
        )))
    ));
}

#[test]
fn start_when_already_running_returns_already() {
    let proc_ops = MockProcOps::new();
    let h = make_helper(proc_ops, MockNetTableOps::new());
    let cfg = r"C:\Users\polaris\config\c.json".to_owned();
    let req = Request::Start(StartParams {
        cfg,
        log: String::new(),
        fwd: false,
        parent_pid: None,
    });
    let _ = h.handle("real-token", req.clone());
    let out = h.handle("real-token", req);
    assert!(matches!(
        out,
        HandleOutcome::Respond(Response::Ok(ResponseKind::Start(
            polaris_helper_proto::Start::Already { pid: 1000 }
        )))
    ));
}

#[test]
fn start_failure_returns_err_start() {
    let proc_ops = MockProcOps::new();
    proc_ops.set_start_error(std::io::Error::other("ENOENT"));
    let h = make_helper(proc_ops, MockNetTableOps::new());
    let out = h.handle(
        "real-token",
        Request::Start(StartParams {
            cfg: r"C:\Users\polaris\config\c.json".to_owned(),
            log: String::new(),
            fwd: false,
            parent_pid: None,
        }),
    );
    let HandleOutcome::Respond(Response::Err(e)) = out else {
        panic!("{out:?}");
    };
    assert_eq!(e.code, polaris_helper_proto::ErrorCode::Start);
}

#[test]
fn start_with_fwd_calls_enable_ip_forwarding() {
    let proc_ops = MockProcOps::new();
    let snap_before = proc_ops.snapshot();
    let h = make_helper(proc_ops.clone(), MockNetTableOps::new());
    let _ = h.handle(
        "real-token",
        Request::Start(StartParams {
            cfg: r"C:\Users\polaris\config\c.json".to_owned(),
            log: String::new(),
            fwd: true, // 应触发 enable_ip_forwarding
            parent_pid: None,
        }),
    );
    let snap_after = proc_ops.snapshot();
    assert!(snap_after.ip_forward_calls > snap_before.ip_forward_calls);
}

// ===== stop =====

#[test]
fn stop_when_not_running_is_idempotent() {
    let h = make_helper_defaults();
    let out = h.handle("real-token", Request::Stop { pid: None });
    assert!(matches!(
        out,
        HandleOutcome::Respond(Response::Ok(ResponseKind::Stop(
            polaris_helper_proto::Stop::NotRunning
        )))
    ));
}

#[test]
fn stop_reaps_running_child_and_clears_state() {
    let proc_ops = MockProcOps::new();
    let h = make_helper(proc_ops.clone(), MockNetTableOps::new());
    // 先 start
    let _ = h.handle(
        "real-token",
        Request::Start(StartParams {
            cfg: r"C:\Users\polaris\config\c.json".to_owned(),
            log: String::new(),
            fwd: false,
            parent_pid: None,
        }),
    );
    let snap_before = proc_ops.snapshot();
    // stop
    let out = h.handle("real-token", Request::Stop { pid: None });
    assert!(matches!(
        out,
        HandleOutcome::Respond(Response::Ok(ResponseKind::Stop(
            polaris_helper_proto::Stop::Stopped { pid: 1000 }
        )))
    ));
    let snap_after = proc_ops.snapshot();
    assert_eq!(snap_after.reap_calls, snap_before.reap_calls + 1);
    // status 现在应是 stopped
    let out2 = h.handle("real-token", Request::Status);
    assert!(matches!(
        out2,
        HandleOutcome::Respond(Response::Ok(ResponseKind::Status(
            polaris_helper_proto::Status::Stopped
        )))
    ));
}

/// **变异门（核心）**：身份不匹配 → 不摘不收割，child 状态原样留给新会话。
///
/// 变异（逃逸面穷举）：
/// - 删掉 `Request::Stop` 分支里的 `stop_pid_matches` 判据 → 响应变 `Stopped{1000}` +
///   `reap_calls` 涨 → 转红（那正是「杀掉用户刚连上的新核」）。
/// - 只改响应不改行为（回 Mismatch 但仍 `take()` + `reap_child`）→ 后两条断言转红。
/// - `parse_request` 里把身份行丢掉、恒 `pid: None` → 判据永不触发 → 转红（另有
///   `service/win::parse_request_stop_reads_optional_pid` 直接钉住解码侧）。
#[test]
fn stop_refuses_to_reap_when_managed_pid_is_another_session() {
    let proc_ops = MockProcOps::new();
    let h = make_helper(proc_ops.clone(), MockNetTableOps::new());
    // daemon 手里的是新会话的核（MockProcOps 的 start 固定报 1000）。
    let _ = h.handle(
        "real-token",
        Request::Start(StartParams {
            cfg: r"C:\Users\polaris\config\c.json".to_owned(),
            log: String::new(),
            fwd: false,
            parent_pid: None,
        }),
    );
    let snap_before = proc_ops.snapshot();
    // 老 stop 腿声明它要停 4242。
    let out = h.handle("real-token", Request::Stop { pid: Some(4242) });
    assert_eq!(
        out,
        HandleOutcome::Respond(Response::Ok(ResponseKind::Stop(
            polaris_helper_proto::Stop::Mismatch {
                want: 4242,
                current: 1000
            }
        ))),
        "身份不匹配 → 诚实 no-op，回报两个 pid"
    );
    assert_eq!(
        proc_ops.snapshot().reap_calls,
        snap_before.reap_calls,
        "绝不能收割：1000 是用户刚连上的新核"
    );
    assert!(
        matches!(
            h.handle("real-token", Request::Status),
            HandleOutcome::Respond(Response::Ok(ResponseKind::Status(
                polaris_helper_proto::Status::Running { pid: 1000 }
            )))
        ),
        "child 记账必须原样留给新会话（摘掉 = 新核失联，daemon 再也停不掉它）"
    );
}

/// 反向失效门：身份匹配照常停（判据不能收得太紧，否则停核彻底失效）。
#[test]
fn stop_proceeds_when_managed_pid_matches() {
    let proc_ops = MockProcOps::new();
    let h = make_helper(proc_ops.clone(), MockNetTableOps::new());
    let _ = h.handle(
        "real-token",
        Request::Start(StartParams {
            cfg: r"C:\Users\polaris\config\c.json".to_owned(),
            log: String::new(),
            fwd: false,
            parent_pid: None,
        }),
    );
    let snap_before = proc_ops.snapshot();
    let out = h.handle("real-token", Request::Stop { pid: Some(1000) });
    assert_eq!(
        out,
        HandleOutcome::Respond(Response::Ok(ResponseKind::Stop(
            polaris_helper_proto::Stop::Stopped { pid: 1000 }
        )))
    );
    assert_eq!(proc_ops.snapshot().reap_calls, snap_before.reap_calls + 1);
}

// ===== cleanup =====

#[test]
fn cleanup_reaps_child_and_kills_all_singbox() {
    let proc_ops = MockProcOps::new();
    proc_ops.set_kill_all_return(2);
    let h = make_helper(proc_ops.clone(), MockNetTableOps::new());
    // 先 start
    let _ = h.handle(
        "real-token",
        Request::Start(StartParams {
            cfg: r"C:\Users\polaris\config\c.json".to_owned(),
            log: String::new(),
            fwd: false,
            parent_pid: None,
        }),
    );
    let snap_before = proc_ops.snapshot();
    let out = h.handle("real-token", Request::Cleanup);
    assert_eq!(
        out,
        HandleOutcome::Respond(Response::Ok(ResponseKind::Cleaned))
    );
    let snap_after = proc_ops.snapshot();
    assert_eq!(snap_after.reap_calls, snap_before.reap_calls + 1);
    // kill_all_singbox 由 mock 的 kill_all_return 返回 2（调用计数不经此路径，但行为对齐 Go）
}

// ===== uninstall =====

#[test]
fn uninstall_spawns_self_uninstall_and_signals_exit() {
    let proc_ops = MockProcOps::new();
    let h = make_helper(proc_ops.clone(), MockNetTableOps::new());
    let snap_before = proc_ops.snapshot();
    let out = h.handle("real-token", Request::Uninstall);
    match out {
        HandleOutcome::UninstallAndExit(Response::Ok(ResponseKind::Uninstalling)) => {}
        other => panic!("expected UninstallAndExit, got {other:?}"),
    }
    let snap_after = proc_ops.snapshot();
    assert_eq!(
        snap_after.spawn_uninstall_calls,
        snap_before.spawn_uninstall_calls + 1
    );
    // spawn 参数传了 service_name + support_dir
    let args = proc_ops.last_spawn_args();
    assert_eq!(
        args,
        Some((
            "PolarisHelper".to_owned(),
            r"C:\ProgramData\Polaris".to_owned()
        ))
    );
}

// ===== freeport =====

#[test]
fn freeport_free_when_no_listener() {
    let h = make_helper_defaults();
    let out = h.handle("real-token", Request::FreePort { port: 9090 });
    assert_eq!(
        out,
        HandleOutcome::Respond(Response::Ok(ResponseKind::FreePort(
            polaris_helper_proto::FreePort::Free
        )))
    );
}

#[test]
fn freeport_kills_locked_singbox_listener() {
    let proc_ops = MockProcOps::new();
    proc_ops.set_image(1000, r"C:\Program Files\Polaris\sing-box.exe");
    let net_ops = MockNetTableOps::new();
    net_ops.set_entries(vec![crate::platform::windows::logic::ListenEntry {
        pid: 1000,
        port: 9090,
    }]);
    let h = make_helper(proc_ops.clone(), net_ops);
    let out = h.handle("real-token", Request::FreePort { port: 9090 });
    let HandleOutcome::Respond(Response::Ok(ResponseKind::FreePort(
        polaris_helper_proto::FreePort::Killed { pids },
    ))) = out
    else {
        panic!("{out:?}");
    };
    assert_eq!(pids, vec![1000]);
    // terminate_pid 被调用
    assert_eq!(proc_ops.snapshot().terminate_calls, 1);
}

#[test]
fn freeport_reports_foreign_listener_without_killing() {
    let proc_ops = MockProcOps::new();
    proc_ops.set_image(2000, r"C:\Windows\System32\nginx.exe");
    let net_ops = MockNetTableOps::new();
    net_ops.set_entries(vec![crate::platform::windows::logic::ListenEntry {
        pid: 2000,
        port: 80,
    }]);
    let h = make_helper(proc_ops.clone(), net_ops);
    let out = h.handle("real-token", Request::FreePort { port: 80 });
    let HandleOutcome::Respond(Response::Ok(ResponseKind::FreePort(
        polaris_helper_proto::FreePort::Foreign { names },
    ))) = out
    else {
        panic!("{out:?}");
    };
    assert_eq!(names, vec!["nginx.exe".to_owned()]);
    // 不应调 terminate_pid（foreign 不杀）
    assert_eq!(proc_ops.snapshot().terminate_calls, 0);
}

// ===== route-add / route-del =====

#[test]
fn route_add_denies_non_polaris_iface() {
    let h = make_helper_defaults();
    let out = h.handle(
        "real-token",
        Request::RouteAdd(polaris_helper_proto::RouteParams {
            iface: "Ethernet0".to_owned(),
            cidrs: vec!["10.0.0.0/8".to_owned()],
        }),
    );
    let HandleOutcome::Respond(Response::Err(e)) = out else {
        panic!("{out:?}");
    };
    assert_eq!(e.code, polaris_helper_proto::ErrorCode::IfaceDenied);
}

#[test]
fn route_add_allows_polaris_iface() {
    let h = make_helper_defaults();
    let out = h.handle(
        "real-token",
        Request::RouteAdd(polaris_helper_proto::RouteParams {
            iface: "polaris-tun0".to_owned(),
            cidrs: vec!["10.0.0.0/8".to_owned()],
        }),
    );
    assert_eq!(
        out,
        HandleOutcome::Respond(Response::Ok(ResponseKind::Route))
    );
}

// ===== route netsh 真派发（W9 修）=====

#[test]
fn route_add_dispatches_apply_route_for_each_valid_cidr() {
    let proc_ops = MockProcOps::new();
    let h = make_helper(proc_ops.clone(), MockNetTableOps::new());
    let out = h.handle(
        "real-token",
        Request::RouteAdd(polaris_helper_proto::RouteParams {
            iface: "polaris-tun0".to_owned(),
            // 中间一项非法 CIDR + 一项空 → 应被跳过（Go: ParseCIDR err / "" → continue）。
            cidrs: vec![
                "10.0.0.0/8".to_owned(),
                "not-a-cidr".to_owned(),
                String::new(),
                "::/0".to_owned(),
            ],
        }),
    );
    assert_eq!(
        out,
        HandleOutcome::Respond(Response::Ok(ResponseKind::Route))
    );
    // 仅 2 个合法 CIDR 触发 apply_route（非法/空跳过）。
    assert_eq!(proc_ops.snapshot().route_calls, 2);
    // 最后一次 = ::/0, del=false（add）。
    assert_eq!(
        proc_ops.last_route(),
        Some(("polaris-tun0".to_owned(), "::/0".to_owned(), false))
    );
}

#[test]
fn route_del_dispatches_apply_route_with_del_true() {
    let proc_ops = MockProcOps::new();
    let h = make_helper(proc_ops.clone(), MockNetTableOps::new());
    let _ = h.handle(
        "real-token",
        Request::RouteDel(polaris_helper_proto::RouteParams {
            iface: "polaris-tun0".to_owned(),
            cidrs: vec!["10.0.0.0/8".to_owned()],
        }),
    );
    assert_eq!(proc_ops.snapshot().route_calls, 1);
    assert_eq!(
        proc_ops.last_route(),
        Some(("polaris-tun0".to_owned(), "10.0.0.0/8".to_owned(), true))
    );
}

#[test]
fn route_denied_iface_runs_no_netsh() {
    let proc_ops = MockProcOps::new();
    let h = make_helper(proc_ops.clone(), MockNetTableOps::new());
    let out = h.handle(
        "real-token",
        Request::RouteAdd(polaris_helper_proto::RouteParams {
            iface: "Ethernet0".to_owned(),
            cidrs: vec!["10.0.0.0/8".to_owned()],
        }),
    );
    let HandleOutcome::Respond(Response::Err(e)) = out else {
        panic!("{out:?}");
    };
    assert_eq!(e.code, polaris_helper_proto::ErrorCode::IfaceDenied);
    // iface 被拒 → 不应跑任何 netsh。
    assert_eq!(proc_ops.snapshot().route_calls, 0);
}

// ===== 父死看护接线（W15 修）=====

fn start_req_with_ppid(ppid: Option<u32>) -> Request {
    Request::Start(StartParams {
        cfg: r"C:\Users\polaris\config\c.json".to_owned(),
        log: String::new(),
        fwd: false,
        parent_pid: ppid,
    })
}

#[test]
fn start_with_ppid_wires_watch_parent() {
    let proc_ops = MockProcOps::new();
    let h = make_helper(proc_ops.clone(), MockNetTableOps::new());
    let _ = h.handle("real-token", start_req_with_ppid(Some(4242)));
    let snap = proc_ops.snapshot();
    assert_eq!(snap.watch_parent_calls, 1);
    // 传入 (ppid, child_pid)：child_pid = mock start 返回的 1000。
    assert_eq!(proc_ops.last_watch_args(), Some((4242, 1000)));
}

#[test]
fn start_without_ppid_does_not_wire_watch_parent() {
    let proc_ops = MockProcOps::new();
    let h = make_helper(proc_ops.clone(), MockNetTableOps::new());
    let _ = h.handle("real-token", start_req_with_ppid(None));
    assert_eq!(proc_ops.snapshot().watch_parent_calls, 0);
}

#[test]
fn start_with_zero_ppid_does_not_wire_watch_parent() {
    // Go: ppid <= 0 → 不启看护。parent_pid=Some(0) 等价（filter ppid>0 排除）。
    let proc_ops = MockProcOps::new();
    let h = make_helper(proc_ops.clone(), MockNetTableOps::new());
    let _ = h.handle("real-token", start_req_with_ppid(Some(0)));
    assert_eq!(proc_ops.snapshot().watch_parent_calls, 0);
}

#[test]
fn watch_parent_reaps_child_when_parent_dead() {
    // mock spawn_watch_parent 单次评估：父死（alive=false）+ child 仍当前 → on_parent_dead 收割 + 摘 child。
    let proc_ops = MockProcOps::new();
    proc_ops.set_alive(false);
    let h = make_helper(proc_ops.clone(), MockNetTableOps::new());
    let snap_before = proc_ops.snapshot();
    let _ = h.handle("real-token", start_req_with_ppid(Some(4242)));
    let snap_after = proc_ops.snapshot();
    // on_parent_dead → proc.reap_child(pid) → reap_calls +1。
    assert_eq!(snap_after.reap_calls, snap_before.reap_calls + 1);
    // child 已被摘 → status 现在 stopped。
    let out = h.handle("real-token", Request::Status);
    assert!(matches!(
        out,
        HandleOutcome::Respond(Response::Ok(ResponseKind::Status(
            polaris_helper_proto::Status::Stopped
        )))
    ));
}

#[test]
fn watch_parent_keeps_child_when_parent_alive() {
    // 父存活（alive=true 默认）→ on_parent_dead 不触发 → child 仍在（running）。
    let proc_ops = MockProcOps::new();
    let h = make_helper(proc_ops.clone(), MockNetTableOps::new());
    let _ = h.handle("real-token", start_req_with_ppid(Some(4242)));
    let out = h.handle("real-token", Request::Status);
    assert!(matches!(
        out,
        HandleOutcome::Respond(Response::Ok(ResponseKind::Status(
            polaris_helper_proto::Status::Running { pid: 1000 }
        )))
    ));
}

// ===== iface-metric =====

#[test]
fn iface_metric_denies_non_polaris_iface() {
    let h = make_helper_defaults();
    let out = h.handle(
        "real-token",
        Request::IfaceMetric {
            iface: "en0".to_owned(),
            metric: 999,
        },
    );
    let HandleOutcome::Respond(Response::Err(e)) = out else {
        panic!("{out:?}");
    };
    assert_eq!(e.code, polaris_helper_proto::ErrorCode::IfaceDenied);
}

// ===== reap_child_on_exit =====

#[test]
fn reap_child_on_exit_reaps_when_child_present() {
    let proc_ops = MockProcOps::new();
    let h = make_helper(proc_ops.clone(), MockNetTableOps::new());
    let _ = h.handle(
        "real-token",
        Request::Start(StartParams {
            cfg: r"C:\Users\polaris\config\c.json".to_owned(),
            log: String::new(),
            fwd: false,
            parent_pid: None,
        }),
    );
    let snap_before = proc_ops.snapshot();
    h.reap_child_on_exit();
    let snap_after = proc_ops.snapshot();
    assert_eq!(snap_after.reap_calls, snap_before.reap_calls + 1);
}

#[test]
fn reap_child_on_exit_killall_when_no_child() {
    let proc_ops = MockProcOps::new();
    let h = make_helper(proc_ops.clone(), MockNetTableOps::new());
    h.reap_child_on_exit(); // 无 child → 走 killAllSingbox 兜底
                            // kill_all_singbox 调用无独立计数器，但行为对齐 Go（Go 注释 helper.go:407-409）
}

// ===== unsupported commands =====

#[test]
fn mac_linux_commands_return_unknown() {
    // Windows helper 无 install-core / flush-dns / default-restore / linux-start
    let h = make_helper_defaults();
    let out = h.handle(
        "real-token",
        Request::FlushDns, // mac 专属
    );
    let HandleOutcome::Respond(Response::Err(e)) = out else {
        panic!("{out:?}");
    };
    assert_eq!(e.code, polaris_helper_proto::ErrorCode::Unknown);
}
