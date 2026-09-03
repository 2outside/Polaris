use super::*;
use crate::platform::macos::exec::RunError;
use crate::token::FileTokenStore;
use std::sync::Mutex;

// 测试用 services bundle：注入 FileTokenStore（tempfile）+ 记录型 runner + 可控 child。
struct TestServices {
    token_value: Mutex<String>,
    runner_calls: Mutex<Vec<(String, Vec<String>)>>,
    child: Mutex<Option<ChildHandle>>,
    uid: i64,
    spawn_result: Mutex<Option<Result<u32, SpawnError>>>,
    terminate_calls: Mutex<u32>,
}

impl TestServices {
    fn new(token: &str) -> Self {
        Self {
            token_value: Mutex::new(token.into()),
            runner_calls: Mutex::new(Vec::new()),
            child: Mutex::new(None),
            uid: 0,
            spawn_result: Mutex::new(Some(Ok(5555))),
            terminate_calls: Mutex::new(0),
        }
    }

    fn calls(&self) -> Vec<(String, Vec<String>)> {
        self.runner_calls.lock().unwrap().clone()
    }
}

impl TokenStore for TestServices {
    fn token_value(&self) -> String {
        self.token_value.lock().unwrap().clone()
    }
}

// 复用 exec::MockRunner 的记录逻辑，但需接入 TestServices。
impl CommandRunner for TestServices {
    fn run(&self, _t: std::time::Duration, p: &str, a: &[&str]) -> Result<(), RunError> {
        self.runner_calls
            .lock()
            .unwrap()
            .push((p.into(), a.iter().map(|s| (*s).into()).collect()));
        Ok(())
    }
    fn output(&self, _t: std::time::Duration, p: &str, a: &[&str]) -> Result<Vec<u8>, RunError> {
        self.runner_calls
            .lock()
            .unwrap()
            .push((p.into(), a.iter().map(|s| (*s).into()).collect()));
        Ok(Vec::new())
    }
    fn combined(&self, _t: std::time::Duration, p: &str, a: &[&str]) -> Result<Vec<u8>, RunError> {
        self.runner_calls
            .lock()
            .unwrap()
            .push((p.into(), a.iter().map(|s| (*s).into()).collect()));
        Ok(Vec::new())
    }
}

impl MacServices for TestServices {
    fn token_store(&self) -> &dyn TokenStore {
        self
    }
    fn runner(&self) -> &dyn CommandRunner {
        self
    }
    fn child(&self) -> &Mutex<Option<ChildHandle>> {
        &self.child
    }
    fn uid(&self) -> i64 {
        self.uid
    }
    fn spawn_child(
        &self,
        _cfg: &str,
        _log: &str,
        _fwd: bool,
        _parent_pid: Option<u32>,
    ) -> Result<SpawnedCore, SpawnError> {
        let r = self.spawn_result.lock().unwrap().clone();
        match r {
            Some(Ok(pid)) => {
                *self.child.lock().unwrap() = Some(ChildHandle { pid });
                Ok(SpawnedCore {
                    pid,
                    process_ms: 0,
                    log_handoff_ms: 0,
                })
            }
            Some(Err(e)) => Err(e),
            None => Err(SpawnError::NotImplemented),
        }
    }
    fn terminate_child(&self, want_pid: Option<u32>) -> TerminateOutcome {
        *self.terminate_calls.lock().unwrap() += 1;
        // 复用生产判定点（替身只记调用，不自抄一份判据 —— 否则删掉判据本测照样绿）。
        terminate_managed_child(&self.child, want_pid)
    }
}

fn test_config() -> MacConfig {
    MacConfig::new(
        "/usr/local/lib/polaris/sing-box",
        "/Users/test/Polaris",
        "/Library/Application Support/Polaris",
        "/Library/Application Support/Polaris/core",
    )
}

fn assert_started_timed(resp: Response, want_pid: u32) {
    match resp {
        Response::Ok(ResponseKind::Start(StartResp::StartedTimed { pid, timing })) => {
            assert_eq!(pid, want_pid);
            assert_eq!(timing.job_ms, 0, "macOS 没有 Windows Job Object");
        }
        other => panic!("预期带计时的 started，实得 {other:?}"),
    }
}

#[test]
fn mac_proxy_compare_capability_is_authenticated_and_performs_zero_commands() {
    let svc = TestServices::new("t");
    let response = dispatch(
        &svc,
        &test_config(),
        "t",
        &Request::MacProxyCompareCapability,
    );

    assert_eq!(response, Response::Ok(ResponseKind::MacProxyTransaction));
    assert!(svc.calls().is_empty());
}

#[test]
fn mac_proxy_compare_dispatch_rejects_invalid_payload_without_runner_commands() {
    let svc = TestServices::new("t");
    let response = dispatch(
        &svc,
        &test_config(),
        "t",
        &Request::MacProxyCompareTransaction {
            payload_hex: "not-hex".into(),
        },
    );

    #[cfg(target_os = "macos")]
    assert!(matches!(
        response,
        Response::Err(ProtoError {
            code: ErrorCode::SystemProxy,
            ..
        })
    ));
    #[cfg(not(target_os = "macos"))]
    assert!(matches!(
        response,
        Response::Err(ProtoError {
            code: ErrorCode::Unknown,
            ..
        })
    ));
    assert!(svc.calls().is_empty());
}

// ===== 鉴权 =====

#[test]
fn auth_denied_wrong_token() {
    // helper.go:405-407: tok != tokenValue → ERR auth
    let svc = TestServices::new("real-token");
    let cfg = test_config();
    let resp = dispatch(&svc, &cfg, "wrong-token", &Request::Ping);
    assert!(matches!(
        resp,
        Response::Err(ProtoError {
            code: ErrorCode::Auth,
            ..
        })
    ));
}

#[test]
fn auth_denied_empty_token() {
    let svc = TestServices::new("real-token");
    let cfg = test_config();
    let resp = dispatch(&svc, &cfg, "", &Request::Ping);
    assert!(matches!(
        resp,
        Response::Err(ProtoError {
            code: ErrorCode::Auth,
            ..
        })
    ));
}

#[test]
fn auth_ok_correct_token_reaches_command() {
    let svc = TestServices::new("real-token");
    let cfg = test_config();
    let resp = dispatch(&svc, &cfg, "real-token", &Request::Ping);
    match resp {
        Response::Ok(ResponseKind::Pong(p)) => {
            assert_eq!(p.proto_version, crate::platform::macos::PROTO_VERSION);
            assert_eq!(p.uid, 0);
        }
        other => panic!("{other:?}"),
    }
}

// ===== ping / version =====

#[test]
fn ping_response_format() {
    // wire 形态追加 shared build identity；旧 app 忽略，新 app 用它识别同 proto 旧 helper。
    let svc = TestServices::new("t");
    let cfg = test_config();
    let resp = dispatch(&svc, &cfg, "t", &Request::Ping);
    let line = resp.to_wire_line();
    assert_eq!(
        line,
        format!(
            "OK pong uid=0 v{} build={}",
            crate::platform::macos::PROTO_VERSION,
            polaris_helper_proto::build_identity::current()
        )
    );
}

#[test]
fn version_response_format() {
    // wire 形态 `OK <ver>`；版本走统一的 PROTO_VERSION（不再是 上游 mac=9）。
    let svc = TestServices::new("t");
    let cfg = test_config();
    let resp = dispatch(&svc, &cfg, "t", &Request::Version);
    let line = resp.to_wire_line();
    assert_eq!(
        line,
        format!("OK {}", crate::platform::macos::PROTO_VERSION)
    );
}

// ===== status =====

#[test]
fn status_stopped_when_no_child() {
    // helper.go:429-430
    let svc = TestServices::new("t");
    let cfg = test_config();
    let resp = dispatch(&svc, &cfg, "t", &Request::Status);
    assert!(matches!(
        resp,
        Response::Ok(ResponseKind::Status(Status::Stopped))
    ));
    assert_eq!(resp.to_wire_line(), "OK stopped");
}

#[test]
fn status_running_after_start() {
    // helper.go:427-428
    let svc = TestServices::new("t");
    let cfg = test_config();
    let _ = dispatch(&svc, &cfg, "t", &Request::Start(proto_start_params()));
    let resp = dispatch(&svc, &cfg, "t", &Request::Status);
    match resp {
        Response::Ok(ResponseKind::Status(Status::Running { pid })) => assert_eq!(pid, 5555),
        other => panic!("{other:?}"),
    }
}

// ===== stop =====

#[test]
fn stop_notrunning_when_no_child() {
    // helper.go:442
    let svc = TestServices::new("t");
    let cfg = test_config();
    let resp = dispatch(&svc, &cfg, "t", &Request::Stop { pid: None });
    assert!(matches!(
        resp,
        Response::Ok(ResponseKind::Stop(Stop::NotRunning))
    ));
}

#[test]
fn stop_stopped_when_child_present() {
    // helper.go:440-441
    let svc = TestServices::new("t");
    let cfg = test_config();
    let _ = dispatch(&svc, &cfg, "t", &Request::Start(proto_start_params()));
    let resp = dispatch(&svc, &cfg, "t", &Request::Stop { pid: None });
    match resp {
        Response::Ok(ResponseKind::Stop(Stop::Stopped { pid })) => assert_eq!(pid, 5555),
        other => panic!("{other:?}"),
    }
}

/// **变异门（核心）**：身份不匹配 → 不摘不杀，child 原样留给新会话。
///
/// 时序同 linux 版：老 stop 腿拿着旧 pid 落到已换了核的 daemon 上。
///
/// 变异（逃逸面穷举）：
/// - 删掉 [`terminate_managed_child`] 里的 `stop_pid_matches` 判据 → 响应变 `Stopped{5555}`
///   且 child 被摘 → 转红。
/// - 只改响应不改行为（回 Mismatch 但仍 `take()`）→ 末条 child 断言转红。
/// - dispatch 里把 `*pid` 丢掉、恒传 `None` → 判据永不触发 → 转红。
#[test]
fn stop_refuses_to_kill_when_managed_pid_is_another_session() {
    let svc = TestServices::new("t");
    let cfg = test_config();
    // daemon 手里的是新会话的核（TestServices 的 spawn 固定报 5555）。
    let _ = dispatch(&svc, &cfg, "t", &Request::Start(proto_start_params()));
    let resp = dispatch(&svc, &cfg, "t", &Request::Stop { pid: Some(4242) });
    assert_eq!(
        resp,
        Response::Ok(ResponseKind::Stop(Stop::Mismatch {
            want: 4242,
            current: 5555
        })),
        "身份不匹配 → 诚实 no-op，回报两个 pid"
    );
    assert_eq!(
        svc.child.lock().unwrap().as_ref().map(|c| c.pid),
        Some(5555),
        "child 必须原样留给新会话 —— 摘掉它 = 新核失联，daemon 此后再也停不掉"
    );
}

/// 反向失效门：身份匹配照常停（判据不能收得太紧）。
#[test]
fn stop_proceeds_when_managed_pid_matches() {
    let svc = TestServices::new("t");
    let cfg = test_config();
    let _ = dispatch(&svc, &cfg, "t", &Request::Start(proto_start_params()));
    let resp = dispatch(&svc, &cfg, "t", &Request::Stop { pid: Some(5555) });
    assert_eq!(
        resp,
        Response::Ok(ResponseKind::Stop(Stop::Stopped { pid: 5555 }))
    );
    assert!(svc.child.lock().unwrap().is_none(), "匹配时须真摘 child");
}

// ===== start =====

#[test]
fn start_already_when_child_exists() {
    // helper.go:521-523: OK already <pid>
    let svc = TestServices::new("t");
    let cfg = test_config();
    let _ = dispatch(&svc, &cfg, "t", &Request::Start(proto_start_params()));
    let resp = dispatch(&svc, &cfg, "t", &Request::Start(proto_start_params()));
    match resp {
        Response::Ok(ResponseKind::Start(StartResp::Already { pid })) => {
            assert_eq!(pid, 5555)
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn start_no_config_when_empty_cfg() {
    // helper.go:525-527: ERR no-config
    let svc = TestServices::new("t");
    let cfg = test_config();
    let mut p = proto_start_params();
    p.cfg = String::new();
    let resp = dispatch(&svc, &cfg, "t", &Request::Start(p));
    assert!(matches!(
        resp,
        Response::Err(ProtoError {
            code: ErrorCode::NoConfig,
            ..
        })
    ));
}

#[test]
fn start_config_path_denied_when_outside_confdir() {
    // helper.go:528-531: ERR config-path-denied
    let svc = TestServices::new("t");
    let cfg = test_config(); // conf_dir = /Users/test/Polaris
    let mut p = proto_start_params();
    p.cfg = "/etc/passwd".into(); // 越权
    let resp = dispatch(&svc, &cfg, "t", &Request::Start(p));
    assert!(matches!(
        resp,
        Response::Err(ProtoError {
            code: ErrorCode::ConfigPathDenied,
            ..
        })
    ));
}

#[test]
fn start_ok_when_cfg_inside_confdir() {
    let svc = TestServices::new("t");
    let cfg = test_config();
    let mut p = proto_start_params();
    p.cfg = "/Users/test/Polaris/config.json".into();
    let resp = dispatch(&svc, &cfg, "t", &Request::Start(p));
    assert_started_timed(resp, 5555);
}

/// log 与 cfg 走同一条白名单 —— 不校验就是「root 在任意位置建文件并持续追加写」。
#[test]
fn start_log_path_denied_when_outside_confdir() {
    let svc = TestServices::new("t");
    let cfg = test_config(); // conf_dir = /Users/test/Polaris
    let mut p = proto_start_params();
    // cfg 合法，只有 log 越界 —— 单独钉住 log 这一格。
    p.cfg = "/Users/test/Polaris/singbox-runtime.json".into();
    p.log = "/etc/newsyslog.d/pwn.conf".into();
    let resp = dispatch(&svc, &cfg, "t", &Request::Start(p));
    assert!(
        matches!(
            resp,
            Response::Err(ProtoError {
                code: ErrorCode::LogPathDenied,
                ..
            })
        ),
        "{resp:?}"
    );
}

/// 生产形态（cfg 与 log 同在 confDir）必须放行 —— 否则上面那条可能被「恒拒」满足。
#[test]
fn start_ok_when_log_inside_confdir() {
    let svc = TestServices::new("t");
    let cfg = test_config();
    let mut p = proto_start_params();
    p.cfg = "/Users/test/Polaris/singbox-runtime.json".into();
    p.log = "/Users/test/Polaris/singbox-startup.log".into();
    let resp = dispatch(&svc, &cfg, "t", &Request::Start(p));
    assert_started_timed(resp, 5555);
}

/// 空 log = 不重定向（`server.rs` 的 `if !log.is_empty()`），必须放行。
#[test]
fn start_ok_when_log_empty() {
    let svc = TestServices::new("t");
    let cfg = test_config();
    let mut p = proto_start_params();
    p.cfg = "/Users/test/Polaris/singbox-runtime.json".into();
    p.log = String::new();
    let resp = dispatch(&svc, &cfg, "t", &Request::Start(p));
    assert_started_timed(resp, 5555);
}

#[test]
fn start_fwd_enables_ip_forwarding() {
    // helper.go:534-537: allowLan → sysctl net.inet.ip.forwarding=1 + ip6.forwarding=1
    let svc = TestServices::new("t");
    let cfg = test_config();
    let mut p = proto_start_params();
    p.cfg = "/Users/test/Polaris/c.json".into();
    p.fwd = true;
    let _ = dispatch(&svc, &cfg, "t", &Request::Start(p));
    let calls = svc.calls();
    let sysctls: Vec<_> = calls
        .iter()
        .filter(|(p, _)| p == "/usr/sbin/sysctl")
        .collect();
    assert_eq!(sysctls.len(), 2, "应有 ipv4 + ipv6 两次 sysctl");
    assert!(sysctls
        .iter()
        .any(|(_, a)| a.contains(&"net.inet.ip.forwarding=1".to_string())));
    assert!(sysctls
        .iter()
        .any(|(_, a)| a.contains(&"net.inet6.ip6.forwarding=1".to_string())));
}

fn proto_start_params() -> polaris_helper_proto::request::StartParams {
    polaris_helper_proto::request::StartParams {
        cfg: "/Users/test/Polaris/c.json".into(),
        log: String::new(),
        fwd: false,
        parent_pid: None,
    }
}

// ===== route-add / route-del =====

#[test]
fn route_add_denied_bad_iface() {
    // helper.go:457-459: ERR iface-denied
    let svc = TestServices::new("t");
    let cfg = test_config();
    let resp = dispatch(
        &svc,
        &cfg,
        "t",
        &Request::RouteAdd(RouteParams {
            iface: "en0".into(), // 非白名单
            cidrs: vec!["10.0.0.0/8".into()],
        }),
    );
    assert!(matches!(
        resp,
        Response::Err(ProtoError {
            code: ErrorCode::IfaceDenied,
            ..
        })
    ));
}

#[test]
fn route_add_ok_runs_route_cmd() {
    // helper.go:465-480
    let svc = TestServices::new("t");
    let cfg = test_config();
    let resp = dispatch(
        &svc,
        &cfg,
        "t",
        &Request::RouteAdd(RouteParams {
            iface: "polaris-ts".into(),
            cidrs: vec!["10.0.0.0/8".into(), "172.16.0.0/12".into()],
        }),
    );
    assert!(matches!(resp, Response::Ok(ResponseKind::Route)));
    let calls = svc.calls();
    let route_calls: Vec<_> = calls
        .iter()
        .filter(|(p, _)| p == route::ROUTE_BIN)
        .collect();
    assert_eq!(route_calls.len(), 2, "每个 CIDR 一次 route 命令");
}

#[test]
fn route_add_skips_invalid_cidr() {
    // helper.go:470-471: 非法 CIDR continue
    let svc = TestServices::new("t");
    let cfg = test_config();
    let _ = dispatch(
        &svc,
        &cfg,
        "t",
        &Request::RouteAdd(RouteParams {
            iface: "polaris-wg".into(),
            cidrs: vec![
                "10.0.0.0/8".into(),
                "not-a-cidr".into(),
                "192.168.0.0/16".into(),
            ],
        }),
    );
    let calls = svc.calls();
    let route_calls: Vec<_> = calls
        .iter()
        .filter(|(p, _)| p == route::ROUTE_BIN)
        .collect();
    assert_eq!(route_calls.len(), 2, "非法项跳过，仅 2 条 route");
}

#[test]
fn route_del_uses_delete_subcmd() {
    let svc = TestServices::new("t");
    let cfg = test_config();
    let _ = dispatch(
        &svc,
        &cfg,
        "t",
        &Request::RouteDel(RouteParams {
            iface: "utun3".into(),
            cidrs: vec!["10.0.0.0/8".into()],
        }),
    );
    let calls = svc.calls();
    let route_call = calls.iter().find(|(p, _)| p == route::ROUTE_BIN).unwrap();
    assert!(route_call.1.contains(&"delete".to_string()));
}

// ===== default-restore =====

#[test]
fn default_restore_ok_valid_ipv4() {
    // helper.go:485-491
    let svc = TestServices::new("t");
    let cfg = test_config();
    let resp = dispatch(
        &svc,
        &cfg,
        "t",
        &Request::DefaultRestore {
            gateway_ipv4: "192.168.1.1".into(),
        },
    );
    assert!(matches!(resp, Response::Ok(ResponseKind::DefaultRestored)));
}

#[test]
fn default_restore_bad_gateway() {
    // helper.go:486-489: ERR bad-gateway
    let svc = TestServices::new("t");
    let cfg = test_config();
    let resp = dispatch(
        &svc,
        &cfg,
        "t",
        &Request::DefaultRestore {
            gateway_ipv4: "not-an-ip".into(),
        },
    );
    assert!(matches!(
        resp,
        Response::Err(ProtoError {
            code: ErrorCode::BadGateway,
            ..
        })
    ));
}

// ===== flush-dns =====

#[test]
fn flush_dns_response_wire() {
    // helper.go:506: OK flushed
    let svc = TestServices::new("t");
    let cfg = test_config();
    let resp = dispatch(&svc, &cfg, "t", &Request::FlushDns);
    let line = resp.to_wire_line();
    assert_eq!(line, "OK flushed");
}

// ===== cleanup =====

#[test]
fn cleanup_pkill_and_clears_child() {
    // helper.go:444-449: pkill -9 -f "<singboxBin> run" + 摘 child
    let svc = TestServices::new("t");
    let cfg = test_config();
    let _ = dispatch(&svc, &cfg, "t", &Request::Start(proto_start_params()));
    let resp = dispatch(&svc, &cfg, "t", &Request::Cleanup);
    assert!(matches!(resp, Response::Ok(ResponseKind::Cleaned)));
    let calls = svc.calls();
    let pkill = calls
        .iter()
        .find(|(p, _)| p == "/usr/bin/pkill")
        .expect("应有 pkill 调用");
    assert!(pkill.1.contains(&"-9".to_string()));
    assert!(pkill.1.contains(&"-f".to_string()));
    assert!(pkill
        .1
        .contains(&"/usr/local/lib/polaris/sing-box run".to_string()));
    // child 被摘除
    assert!(svc.child.lock().unwrap().is_none());
}

// ===== install-core（文件操作 + mac 签名）=====

#[test]
fn install_core_bad_args() {
    // helper.go:583-584 → installCore → :137 bad-args
    let svc = TestServices::new("t");
    let cfg = test_config();
    let resp = dispatch(
        &svc,
        &cfg,
        "t",
        &Request::InstallCore(InstallCoreParams {
            src_dir: "".into(),
            want_hash: "a".repeat(64),
        }),
    );
    assert!(matches!(
        resp,
        Response::Err(ProtoError {
            code: ErrorCode::BadArgs,
            ..
        })
    ));
}

#[test]
fn install_core_coredir_unset() {
    let svc = TestServices::new("t");
    let mut cfg = test_config();
    cfg.core_dir = String::new();
    let resp = dispatch(
        &svc,
        &cfg,
        "t",
        &Request::InstallCore(InstallCoreParams {
            src_dir: "/tmp/x".into(),
            want_hash: "a".repeat(64),
        }),
    );
    assert!(matches!(
        resp,
        Response::Err(ProtoError {
            code: ErrorCode::CoredirUnset,
            ..
        })
    ));
}

#[test]
fn install_core_success_runs_xattr_and_codesign() {
    // helper.go:195-196: 文件就位后 xattr -cr + codesign --force --deep -s -
    use sha2::{Digest, Sha256};
    let src = tempfile::tempdir().unwrap();
    let sb = b"fake sing-box";
    std::fs::write(src.path().join("sing-box"), sb).unwrap();
    let mut h = Sha256::new();
    h.update(sb);
    let hash = hex::encode(h.finalize());

    let svc = TestServices::new("t");
    let cfg = test_config();
    // 用临时 core_dir
    let core_tmp = tempfile::tempdir().unwrap();
    let mut cfg2 = cfg.clone();
    cfg2.core_dir = core_tmp.path().to_string_lossy().into_owned();

    let resp = dispatch(
        &svc,
        &cfg2,
        "t",
        &Request::InstallCore(InstallCoreParams {
            src_dir: src.path().to_string_lossy().into_owned(),
            want_hash: hash,
        }),
    );
    assert!(matches!(resp, Response::Ok(ResponseKind::Installed)));
    // 验证 xattr + codesign 被调
    let calls = svc.calls();
    assert!(calls.iter().any(|(p, _)| p == "/usr/bin/xattr"));
    assert!(calls.iter().any(|(p, _)| p == "/usr/bin/codesign"));
}

// ===== 未知/不属于 mac 谱系的命令 =====

#[test]
fn linux_start_unknown_on_mac() {
    let svc = TestServices::new("t");
    let cfg = test_config();
    let resp = dispatch(
        &svc,
        &cfg,
        "t",
        &Request::LinuxStart(polaris_helper_proto::request::LinuxStartParams {
            singbox_path: "/x".into(),
            common: proto_start_params(),
        }),
    );
    assert!(matches!(
        resp,
        Response::Err(ProtoError {
            code: ErrorCode::Unknown,
            ..
        })
    ));
}

#[test]
fn iface_metric_unknown_on_mac() {
    let svc = TestServices::new("t");
    let cfg = test_config();
    let resp = dispatch(
        &svc,
        &cfg,
        "t",
        &Request::IfaceMetric {
            iface: "polaris-ts".into(),
            metric: 100,
        },
    );
    assert!(matches!(
        resp,
        Response::Err(ProtoError {
            code: ErrorCode::Unknown,
            ..
        })
    ));
}

// ===== wire 序列化（对照 Go 各 fmt.Fprintln/Fprintf 调用点）=====

#[test]
fn wire_started_format() {
    // helper.go:579: OK started <pid>
    let r = Response::Ok(ResponseKind::Start(StartResp::Started { pid: 1234 }));
    assert_eq!(r.to_wire_line(), "OK started 1234");
}

#[test]
fn wire_already_format() {
    // helper.go:522: OK already <pid>
    let r = Response::Ok(ResponseKind::Start(StartResp::Already { pid: 5678 }));
    assert_eq!(r.to_wire_line(), "OK already 5678");
}

#[test]
fn wire_freeport_killed_format() {
    // helper.go:393: OK killed <pid>,<pid>
    let r = Response::Ok(ResponseKind::FreePort(
        polaris_helper_proto::response::FreePort::Killed {
            pids: vec![111, 222],
        },
    ));
    assert_eq!(r.to_wire_line(), "OK killed 111,222");
}

#[test]
fn wire_freeport_foreign_format() {
    // helper.go:391: OK foreign <name> | <name>
    let r = Response::Ok(ResponseKind::FreePort(
        polaris_helper_proto::response::FreePort::Foreign {
            names: vec!["nginx".into(), "pid:789".into()],
        },
    ));
    assert_eq!(r.to_wire_line(), "OK foreign nginx | pid:789");
}

#[test]
fn wire_flushed_partial_format() {
    // helper.go:503: OK flushed-partial killall-hup <err> <out>
    let r = Response::Ok(ResponseKind::FlushDns(
        polaris_helper_proto::response::FlushDns::FlushedPartial {
            tail: "killall-hup exit status 1 ".into(),
        },
    ));
    let line = r.to_wire_line();
    assert!(line.starts_with("OK flushed-partial"));
    assert!(line.contains("killall-hup"));
}

#[test]
fn wire_err_format() {
    let r = Response::Err(ProtoError::with_detail(ErrorCode::Start, "exit status 1"));
    assert_eq!(r.to_wire_line(), "ERR start exit status 1");
}

// ===== freeport 经 dispatch 端到端（mock 已在 freeport.rs 测，这里测 dispatch 路由）=====

#[test]
fn dispatch_routes_freeport() {
    // freeport 在鉴权后、锁前处理（helper.go:413）
    let svc = TestServices::new("t");
    let cfg = test_config();
    let resp = dispatch(&svc, &cfg, "t", &Request::FreePort { port: 9090 });
    // mock lsof 返回空 → OK free
    assert!(matches!(
        resp,
        Response::Ok(ResponseKind::FreePort(
            polaris_helper_proto::response::FreePort::Free
        ))
    ));
}

#[test]
fn dispatch_freeport_still_requires_auth() {
    // 即使是 freeport，token 错也先 ERR auth
    let svc = TestServices::new("t");
    let cfg = test_config();
    let resp = dispatch(&svc, &cfg, "wrong", &Request::FreePort { port: 9090 });
    assert!(matches!(
        resp,
        Response::Err(ProtoError {
            code: ErrorCode::Auth,
            ..
        })
    ));
}

/// 确认 FileTokenStore 可作 token_store 注入（编译期验证 trait 兼容）。
#[test]
fn file_token_store_trait_compat() {
    let _store = FileTokenStore::new("/tmp/nonexistent");
}
