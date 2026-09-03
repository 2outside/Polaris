//! §H.2 出口无效谓词矩阵（协议 × proxyMode × loggedIn × exitNode × running × peer 三态）。
use super::super::*;
use polaris_config_engine::user_config::server_config::TailscaleSettings;

fn ts_server(exit_node: Option<&str>) -> ServerConfig {
    ServerConfig {
        id: "ts1".into(),
        name: "ts".into(),
        protocol: Protocol::Tailscale,
        tailscale_settings: Some(Box::new(TailscaleSettings {
            exit_node: exit_node.map(str::to_string),
            ..Default::default()
        })),
        ..Default::default()
    }
}

fn peer(host: &str, ip: &str, online: bool, advertises: bool) -> TailscaleStatusPeer {
    TailscaleStatusPeer {
        host_name: host.into(),
        ip: ip.into(),
        online,
        exit_node: false,
        exit_node_option: advertises,
        active: false,
        stable_id: None,
        details: Default::default(),
    }
}

fn base<'a>(
    selected: Option<&'a ServerConfig>,
    peers: &'a [TailscaleStatusPeer],
) -> TsExitWarningInput<'a> {
    TsExitWarningInput {
        selected,
        logged_in: true,
        proxy_mode_direct: false,
        proxy_running: true,
        peers,
        definitive_logged_out: false,
    }
}

/// `NeedsAuth` 优先于其余各条，且**只认终局否定 + 核在跑**。
///
/// 变异表（逐条真跑过）：
/// - 把 `proxy_running && definitive_logged_out` 的 `proxy_running` 删 → 停核 case 转红；
/// - 把该判据整段挪到 `!logged_in` 守卫**之后** → 第一个断言拿到 `None`（被守卫吞掉）转红；
/// - 把它挪到 `no_exit_node` 之后 → 第二个断言拿到 `NoExitDevice` 转红；
/// - 把 `definitive_logged_out` 换成 `!logged_in` → 「启动过渡帧」case 从 `None` 变 `NeedsAuth` 转红。
#[test]
fn needs_auth_is_definitive_only_and_outranks_exit_device_faults() {
    let s = ts_server(Some("exit-host"));
    let peers = [peer("exit-host", "100.64.0.5", true, true)];

    // 终局否定 + 核在跑 → NeedsAuth（即便出口设备本身完全健康）。
    let mut i = base(Some(&s), &peers);
    i.logged_in = false;
    i.definitive_logged_out = true;
    assert_eq!(derive_ts_exit_warning(&i), TsExitWarning::NeedsAuth);
    assert!(selected_ts_exit_blocked(&i));

    // 同为终局否定，但**未配 exit_node** → 仍报 NeedsAuth（根因先行，不指错方向）。
    let no_exit = ts_server(None);
    let mut i2 = base(Some(&no_exit), &[]);
    i2.logged_in = false;
    i2.definitive_logged_out = true;
    assert_eq!(derive_ts_exit_warning(&i2), TsExitWarning::NeedsAuth);

    // 核没跑 → 帧陈旧，不据其报未认证（浏览器里补完的登录我们收不到）。
    let mut stale = base(Some(&s), &peers);
    stale.logged_in = false;
    stale.definitive_logged_out = true;
    stale.proxy_running = false;
    assert_eq!(derive_ts_exit_warning(&stale), TsExitWarning::None);

    // 启动过渡帧（NoState/Stopped 折叠出的 logged_in=false，非终局）→ 静默。
    let mut transitional = base(Some(&s), &peers);
    transitional.logged_in = false;
    transitional.definitive_logged_out = false;
    assert_eq!(derive_ts_exit_warning(&transitional), TsExitWarning::None);

    // 直连模式在认证态之前短路（用户显式全直连，TS 出口不适用）。
    let mut direct = base(Some(&s), &peers);
    direct.logged_in = false;
    direct.definitive_logged_out = true;
    direct.proxy_mode_direct = true;
    assert_eq!(derive_ts_exit_warning(&direct), TsExitWarning::None);
}

/// [`is_definitive_logged_out`] 的取值面：只有 NeedsLogin / NeedsMachineAuth / expired 算数，
/// 且 `logged_in=true` 一律不算（后端已确认在跑）。变异：去掉 `!ev.logged_in` 前置 → 首条转红；
/// 把 `NeedsMachineAuth` 删 → 第三条转红；把 `expired` 删 → 第四条转红。
#[test]
fn definitive_logged_out_matrix() {
    let ev = |backend: &str, logged_in: bool, expired: bool| TailscaleStatusEvent {
        server_id: "ts1".into(),
        backend_state: backend.into(),
        logged_in,
        auth_url: None,
        tailscale_ips: vec![],
        expired,
        peers: vec![],
        details: Default::default(),
        // Taildrop 四位在本用例无关，取「无能力、无文件」的中性值；不给 Default 是刻意的：
        // 日后再加字段时，这些构造点必须重新被人看一眼，而不是被 `..Default::default()` 静默补齐。
        can_share_files: false,
        waiting_file_count: 0,
        receiving_file_count: 0,
        unread_file_count: 0,
    };
    assert!(!is_definitive_logged_out(&ev("Running", true, false)));
    // `logged_in=true` 一票否决，**即便**同帧带着否定信号。这两格 [`decode_tailscale_status`]
    // 造不出来（那里 `logged_in = backendState ∈ {Running,Starting} && !expired`），但谓词是
    // pub、判据独立于解码器：没有这两条，删掉 `!ev.logged_in` 前置的变异会**存活**（实测如此）。
    assert!(!is_definitive_logged_out(&ev("NeedsLogin", true, false)));
    assert!(!is_definitive_logged_out(&ev("Running", true, true)));
    assert!(is_definitive_logged_out(&ev("NeedsLogin", false, false)));
    assert!(is_definitive_logged_out(&ev(
        "NeedsMachineAuth",
        false,
        false
    )));
    // 过期与 backendState 正交：Running 但 key 过期，后端已折叠成 logged_in=false。
    assert!(is_definitive_logged_out(&ev("Running", false, true)));
    // 启动过渡态：不知道 ≠ 否定。
    assert!(!is_definitive_logged_out(&ev("NoState", false, false)));
    assert!(!is_definitive_logged_out(&ev("Starting", false, false)));
    assert!(!is_definitive_logged_out(&ev("Stopped", false, false)));
}

/// 有 TS 出口但无 exit_node → NoExitDevice（断开态也报）。
#[test]
fn no_exit_node_is_no_exit_device() {
    let s = ts_server(None);
    assert_eq!(
        derive_ts_exit_warning(&base(Some(&s), &[])),
        TsExitWarning::NoExitDevice
    );
    // 断开态（proxy_running=false）仍报（配置态，与 running 无关）。
    let mut i = base(Some(&s), &[]);
    i.proxy_running = false;
    assert_eq!(derive_ts_exit_warning(&i), TsExitWarning::NoExitDevice);
    assert!(selected_ts_exit_blocked(&base(Some(&s), &[])));
}

/// 未选中 / 非 TS / 直连 / 未登录 → 永不告警（四条抑制路径，逐条变异删任一 → 该 case 转红）。
#[test]
fn suppressed_paths_never_warn() {
    let s = ts_server(None);
    // 未选中
    assert_eq!(
        derive_ts_exit_warning(&base(None, &[])),
        TsExitWarning::None
    );
    // 非 TS
    let vless = ServerConfig {
        protocol: Protocol::Vless,
        ..ts_server(None)
    };
    assert_eq!(
        derive_ts_exit_warning(&base(Some(&vless), &[])),
        TsExitWarning::None
    );
    // 直连
    let mut d = base(Some(&s), &[]);
    d.proxy_mode_direct = true;
    assert_eq!(derive_ts_exit_warning(&d), TsExitWarning::None);
    // 未登录
    let mut nl = base(Some(&s), &[]);
    nl.logged_in = false;
    assert_eq!(derive_ts_exit_warning(&nl), TsExitWarning::None);
}

/// exit_node 匹配到离线 peer → ExitDeviceOffline；在线但未广告 → ExitDeviceNotAdvertised；
/// 在线且广告 → None。新鲜度守卫：proxy_running=false → None（防陈旧）。
/// 变异：把 offline 分支删 → 离线 case 落到 not-advertised 或 None → 转红。
#[test]
fn peer_state_drives_offline_and_not_advertised() {
    let s = ts_server(Some("exit-host"));
    // 离线
    let offline = [peer("exit-host", "100.64.0.5", false, true)];
    assert_eq!(
        derive_ts_exit_warning(&base(Some(&s), &offline)),
        TsExitWarning::ExitDeviceOffline
    );
    // 在线未广告
    let not_adv = [peer("exit-host", "100.64.0.5", true, false)];
    assert_eq!(
        derive_ts_exit_warning(&base(Some(&s), &not_adv)),
        TsExitWarning::ExitDeviceNotAdvertised
    );
    // 在线且广告 → 有效
    let ok = [peer("exit-host", "100.64.0.5", true, true)];
    assert_eq!(
        derive_ts_exit_warning(&base(Some(&s), &ok)),
        TsExitWarning::None
    );
    assert!(!selected_ts_exit_blocked(&base(Some(&s), &ok)));
    // 新鲜度守卫：流断 → 保守 None（不据陈旧 peers 报离线）。
    let mut stale = base(Some(&s), &offline);
    stale.proxy_running = false;
    assert_eq!(derive_ts_exit_warning(&stale), TsExitWarning::None);
}

/// exit_node 自定义值不匹配任何 peer → 不误报（None）。
#[test]
fn unmatched_exit_node_does_not_false_warn() {
    let s = ts_server(Some("custom-value"));
    let peers = [peer("other-host", "100.64.0.9", true, true)];
    assert_eq!(
        derive_ts_exit_warning(&base(Some(&s), &peers)),
        TsExitWarning::None
    );
}
