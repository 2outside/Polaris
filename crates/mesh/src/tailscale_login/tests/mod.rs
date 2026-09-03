use super::*;
use polaris_config_engine::user_config::server_config::TailscaleSettings;

fn ts_server(over: TailscaleSettings) -> ServerConfig {
    ServerConfig {
        id: "ts1".to_string(),
        name: "myts".to_string(),
        protocol: Protocol::Tailscale,
        tailscale_settings: Some(Box::new(over)),
        ..Default::default()
    }
}

fn api() -> TailscaleLoginApiService {
    TailscaleLoginApiService {
        port: 51234,
        secret: "rand-secret".to_string(),
    }
}

#[test]
fn login_config_minimal_endpoint_state_dir_and_direct() {
    let server = ts_server(TailscaleSettings::default());
    let cfg = build_tailscale_login_config(&server, Path::new("/ud"), &api()).unwrap();
    assert_eq!(cfg.log["level"], "info");
    assert_eq!(cfg.log["timestamp"], true);
    assert_eq!(cfg.endpoints.len(), 1);
    let ep = cfg.endpoints[0].as_object().unwrap();
    assert_eq!(ep["type"], "tailscale");
    assert_eq!(ep["tag"], "myts");
    // 生产侧把 `Path::join` 结果 `to_string_lossy` 进 JSON → Windows 上是 `/ud\tailscale\ts1`
    // （sing-box 在 Windows 上本就该收反斜杠）。用同样的 join 语义构造期望值，仍钉住
    // 「user_data / "tailscale" / server.id 三段及其顺序」。
    let want = Path::new("/ud").join("tailscale").join("ts1");
    assert_eq!(
        ep["state_directory"].as_str().unwrap(),
        want.to_string_lossy().as_ref()
    );
    // auth_key 永不写入。
    assert!(ep.get("auth_key").is_none());
    // 无 control_url/hostname/ephemeral 时不写入。
    assert!(ep.get("control_url").is_none());
    assert!(ep.get("hostname").is_none());
    assert!(ep.get("ephemeral").is_none());
    assert_eq!(cfg.outbounds.len(), 1);
    let ob = cfg.outbounds[0].as_object().unwrap();
    assert_eq!(ob["type"], "direct");
    assert_eq!(ob["tag"], "direct");
    // 管理 api service 恒注入（登录 URL / 登录成功的唯一真值源，见模块头）。
    assert_eq!(cfg.services.len(), 1);
}

#[test]
fn login_config_rejects_an_escaping_state_id() {
    let mut server = ts_server(TailscaleSettings::default());
    server.id = "../victim".to_string();
    assert_eq!(
        build_tailscale_login_config(&server, Path::new("/ud"), &api()),
        Err(crate::tailscale_state::InvalidTailscaleStateId)
    );
}

#[test]
fn login_config_passes_login_related_fields_only() {
    let ts = TailscaleSettings {
        control_url: Some("  https://headscale.example  ".to_string()),
        hostname: Some("node-1".to_string()),
        ephemeral: Some(true),
        // 这些运行期字段不应被 login config 透传（即使设了）。
        exit_node: Some("100.x".to_string()),
        ..Default::default()
    };
    let server = ts_server(ts);
    let cfg = build_tailscale_login_config(&server, Path::new("/ud"), &api()).unwrap();
    let ep = cfg.endpoints[0].as_object().unwrap();
    assert_eq!(ep["control_url"], "https://headscale.example"); // trim
    assert_eq!(ep["hostname"], "node-1");
    assert_eq!(ep["ephemeral"], true);
    // exit_node 不在 login config。
    assert!(ep.get("exit_node").is_none());
}

#[test]
fn login_config_injects_management_service_with_listen_and_secret() {
    let server = ts_server(TailscaleSettings::default());
    let cfg = build_tailscale_login_config(&server, Path::new("/ud"), &api()).unwrap();
    assert_eq!(cfg.services.len(), 1);
    let svc = cfg.services[0].as_object().unwrap();
    assert_eq!(svc["type"], "api");
    assert_eq!(svc["listen"], "127.0.0.1"); // 只回环，不对外
    assert_eq!(svc["listen_port"], 51234);
    assert_eq!(svc["secret"], "rand-secret");
}

#[test]
fn login_config_api_empty_secret_omits_secret_field() {
    let server = ts_server(TailscaleSettings::default());
    let api = TailscaleLoginApiService {
        port: 51234,
        secret: "   ".to_string(),
    };
    let cfg = build_tailscale_login_config(&server, Path::new("/ud"), &api).unwrap();
    let svc = cfg.services[0].as_object().unwrap();
    assert!(svc.get("secret").is_none());
}

/// 顶层键齐全，且 `services` **必写**——瞬态核没有这条 api service 就没有 STATUS 流，
/// 而 STATUS 流是登录 URL 与登录成功的唯一来源。变异：把 `services` 的写入改回
/// `if !cfg.services.is_empty()` 之外的任何「可省略」形态 → 末条断言转红。
#[test]
fn login_config_to_json_always_carries_management_service() {
    let server = ts_server(TailscaleSettings::default());
    let cfg = build_tailscale_login_config(&server, Path::new("/ud"), &api()).unwrap();
    let json = login_config_to_json(&cfg);
    assert!(json.get("log").is_some());
    assert!(json.get("endpoints").is_some());
    assert!(json.get("outbounds").is_some());
    assert_eq!(json["services"].as_array().map(Vec::len), Some(1));
    assert_eq!(json["services"][0]["listen_port"], 51234);
}

fn user_config_with(server: ServerConfig) -> UserConfig {
    UserConfig {
        servers: vec![server],
        ..Default::default()
    }
}

#[test]
fn endpoint_in_running_core_false_when_not_running() {
    let server = ts_server(TailscaleSettings::default());
    let cfg = user_config_with(server);
    assert!(!tailscale_endpoint_in_running_core(
        "ts1",
        false,
        Some(&cfg)
    ));
}

#[test]
fn endpoint_in_running_core_false_when_no_running_config() {
    assert!(!tailscale_endpoint_in_running_core("ts1", true, None));
}

#[test]
fn endpoint_in_running_core_true_when_ts_node_present_and_running() {
    let server = ts_server(TailscaleSettings::default());
    let cfg = user_config_with(server);
    assert!(tailscale_endpoint_in_running_core("ts1", true, Some(&cfg)));
}

#[test]
fn endpoint_in_running_core_ignores_non_ts_protocol() {
    let s = ServerConfig {
        id: "v1".to_string(),
        name: "v".to_string(),
        protocol: Protocol::Vless,
        ..Default::default()
    };
    let cfg = user_config_with(s);
    assert!(!tailscale_endpoint_in_running_core("v1", true, Some(&cfg)));
}

#[test]
fn endpoint_in_running_core_unknown_id_false() {
    let server = ts_server(TailscaleSettings::default());
    let cfg = user_config_with(server);
    assert!(!tailscale_endpoint_in_running_core(
        "other",
        true,
        Some(&cfg)
    ));
}

// ── 登录状态机 ──────────────────────────────────────────────

#[test]
fn state_machine_idle_to_awaiting_on_auth_url() {
    let next = advance_login_state(&LoginState::Idle, &LoginEvent::AuthUrlSeen("u".into()));
    assert_eq!(next, LoginState::AwaitingAuth("u".into()));
}

#[test]
fn state_machine_status_running_to_logged_in() {
    let next = advance_login_state(
        &LoginState::AwaitingAuth("u".into()),
        &LoginEvent::StatusRunning,
    );
    assert_eq!(next, LoginState::LoggedIn);
}

#[test]
fn state_machine_logged_in_not_regressed_by_late_auth_url() {
    // 后到的 AUTH_URL 行不应回退已登录态。
    let next = advance_login_state(&LoginState::LoggedIn, &LoginEvent::AuthUrlSeen("u".into()));
    assert_eq!(next, LoginState::LoggedIn);
}

/// 同 URL 反复到达 → 状态不变（调用方据此免去自备去重表；STATUS 每帧都带 authURL）。
/// 换了 URL → 状态变（重登录会换 URL，必须重新发给用户）。
/// 变异：把 `AuthUrlSeen` 分支改成恒返回 `AwaitingAuth(url)` 之外的东西 / 让它带上帧序号之类
/// 的可变量 → 首条断言转红。
#[test]
fn state_machine_same_auth_url_is_idempotent_new_url_is_not() {
    let s1 = advance_login_state(&LoginState::Idle, &LoginEvent::AuthUrlSeen("u1".into()));
    let s2 = advance_login_state(&s1, &LoginEvent::AuthUrlSeen("u1".into()));
    assert_eq!(s1, s2, "同 URL 重复到达 → 同一状态（=不重复通知用户）");
    let s3 = advance_login_state(&s2, &LoginEvent::AuthUrlSeen("u2".into()));
    assert_ne!(s2, s3, "URL 变了 → 状态必须变（新授权页要送到用户手上）");
    assert_eq!(s3, LoginState::AwaitingAuth("u2".into()));
}

#[test]
fn state_machine_reset_returns_idle() {
    let next = advance_login_state(&LoginState::LoggedIn, &LoginEvent::Reset);
    assert_eq!(next, LoginState::Idle);
}
