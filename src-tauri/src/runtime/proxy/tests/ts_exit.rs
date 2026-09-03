use super::*;

/// A3 relay 组合面门：一帧全量端点快照 → 缓存整体更新（幽灵过滤）+ 逐在册端点 `emit_tailscale_status`。
/// 打断 emit 循环 → 记录空转红；打断解码幽灵过滤 → len 转红；打断 `update_ts_status` → 缓存空转红。
#[tokio::test]
async fn ts_status_frame_updates_cache_and_emits_per_registered_endpoint() {
    use polaris_singbox_grpc::daemon;
    let (rt, _dir) = test_runtime();
    let ts_events: TsStatusEvents = Arc::new(Mutex::new(Vec::new()));
    rt.set_error_emitter(Box::new(RecordingErrorEmitter {
        ts_status: Arc::clone(&ts_events),
        ..Default::default()
    }));
    let tag_to_id = BTreeMap::from([("东京 03".to_string(), "srv-tokyo".to_string())]);
    let update = daemon::TailscaleStatusUpdate {
        endpoints: vec![
            daemon::TailscaleEndpointStatus {
                endpoint_tag: "东京 03".into(),
                backend_state: "Running".into(),
                self_: Some(daemon::TailscalePeer {
                    host_name: "self".into(),
                    tailscale_i_ps: vec!["100.64.0.9".into()],
                    ..Default::default()
                }),
                ..Default::default()
            },
            // 幽灵端点（tag 不在册）→ 既不进缓存也不 emit。
            daemon::TailscaleEndpointStatus {
                endpoint_tag: "幽灵".into(),
                backend_state: "Running".into(),
                ..Default::default()
            },
        ],
    };
    rt.apply_ts_status_frame(&update, &tag_to_id, rt.gate.generation());

    // 缓存：只留在册端点，可经 tailscale_status_snapshot 读回（非恒空）。
    let snap = rt.mesh.tailscale_status_snapshot(true);
    assert_eq!(snap.statuses.len(), 1, "幽灵端点不进缓存");
    assert_eq!(snap.statuses[0].server_id, "srv-tokyo");
    assert!(snap.statuses[0].logged_in);

    // emit：逐在册端点各一条（幽灵不发）。
    let emitted = ts_events.lock().unwrap();
    assert_eq!(emitted.len(), 1, "逐在册端点发一条（幽灵端点不发）");
    assert_eq!(emitted[0].server_id, "srv-tokyo");
    drop(emitted);
}

/// rc.2 企业 VPN 组合面门：两条原生全量帧必须同时完成幽灵过滤、缓存替换、逐端点事件发射，
/// 且挑战新鲜度门随缓存清理失效。只测解码器或只测 gRPC 客户端都证明不了这段运行时接线。
#[test]
fn native_vpn_status_frames_update_cache_emit_and_guard_current_challenge() {
    use polaris_singbox_grpc::daemon;

    let (rt, _dir) = test_runtime();
    let openconnect_events: OpenConnectStatusEvents = Arc::new(Mutex::new(Vec::new()));
    let openvpn_events: OpenVpnStatusEvents = Arc::new(Mutex::new(Vec::new()));
    rt.set_error_emitter(Box::new(RecordingErrorEmitter {
        openconnect_status: Arc::clone(&openconnect_events),
        openvpn_status: Arc::clone(&openvpn_events),
        ..Default::default()
    }));
    let tags = BTreeMap::from([
        ("oc-tag".to_string(), "oc-id".to_string()),
        ("ovpn-tag".to_string(), "ovpn-id".to_string()),
    ]);

    rt.apply_openconnect_status_frame(
        &daemon::OpenConnectStatusUpdate {
            endpoints: vec![
                daemon::OpenConnectEndpointStatus {
                    endpoint_tag: "oc-tag".into(),
                    state: "auth-pending".into(),
                    auth_challenge: Some(daemon::OpenConnectAuthChallenge {
                        id: "oc-challenge".into(),
                        challenge: Some(daemon::open_connect_auth_challenge::Challenge::Browser(
                            daemon::OpenConnectBrowserRequest {
                                url: "https://vpn.example/sso?token=secret".into(),
                                cookie_names: vec!["webvpn".into()],
                                ..Default::default()
                            },
                        )),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                daemon::OpenConnectEndpointStatus {
                    endpoint_tag: "ghost".into(),
                    ..Default::default()
                },
            ],
        },
        &tags,
    );
    rt.apply_openvpn_status_frame(
        &daemon::OpenVpnStatusUpdate {
            endpoints: vec![daemon::OpenVpnEndpointStatus {
                endpoint_tag: "ovpn-tag".into(),
                state: "auth-pending".into(),
                challenge: Some(daemon::OpenVpnChallenge {
                    id: "ovpn-challenge".into(),
                    kind: "credentials".into(),
                    ..Default::default()
                }),
                ..Default::default()
            }],
        },
        &tags,
    );

    let snapshot = rt.mesh.vpn_status_snapshot(true);
    assert!(snapshot.connected);
    assert_eq!(snapshot.open_connect.len(), 1, "OpenConnect 幽灵端点须过滤");
    assert_eq!(snapshot.open_vpn.len(), 1);
    assert_eq!(openconnect_events.lock().unwrap().len(), 1);
    assert_eq!(openvpn_events.lock().unwrap().len(), 1);
    assert!(rt.mesh.has_openconnect_challenge("oc-id", "oc-challenge"));
    assert!(!rt.mesh.has_openconnect_challenge("ovpn-id", "oc-challenge"));
    assert!(rt.mesh.has_openvpn_challenge("ovpn-id", "ovpn-challenge"));

    rt.mesh.clear_vpn_status();
    let cleared = rt.mesh.vpn_status_snapshot(false);
    assert!(!cleared.connected);
    assert!(cleared.open_connect.is_empty());
    assert!(cleared.open_vpn.is_empty());
    assert!(!rt.mesh.has_openvpn_challenge("ovpn-id", "ovpn-challenge"));
}

/// 🔵 **上游 触发点④「TS 隧道就绪」纯谓词**：只认**上升沿**（非 Running → Running）。
///
/// **变异锁**（逐条覆盖逃逸面，不是碰巧杀一条）：
/// - 去掉 `before != Some("Running")`（改成只看 after）→ 稳态 Running 帧也触发 → 第 2 条转红，
///   而那正是「纯事件驱动」退化成每秒一次轮询的形态；
/// - 去掉 `after == Some("Running")`（改成只看 before 变了）→ 第 3/4 条转红；
/// - 把 `Running` 写成别的状态串 → 第 1 条转红。
#[test]
fn ts_exit_ready_fires_only_on_the_rising_edge() {
    // ① 登录完成 / 首帧即就绪 → 触发（出口此刻才真正换成 TS 出口）。
    assert!(ts_exit_became_ready(Some("NeedsLogin"), Some("Running")));
    assert!(ts_exit_became_ready(Some("Starting"), Some("Running")));
    assert!(
        ts_exit_became_ready(None, Some("Running")),
        "首帧即 Running 同样是「此刻起经 TS 出口走」——起核腿那次重探跑在隧道未通时，正需本点纠正"
    );
    // ② 稳态 Running：relay 每秒量级推帧，若也触发 = 每秒重探一次出口 IP（轮询退化）。
    assert!(
        !ts_exit_became_ready(Some("Running"), Some("Running")),
        "稳态帧绝不能触发，否则纯事件驱动退化成轮询"
    );
    // ③ 隧道未就绪 / 掉线：不触发（掉线由停核腿与解锁 gating 各自负责，非本触发点射程）。
    assert!(!ts_exit_became_ready(Some("Running"), Some("NeedsLogin")));
    assert!(!ts_exit_became_ready(
        Some("NeedsLogin"),
        Some("NeedsLogin")
    ));
    assert!(
        !ts_exit_became_ready(None, None),
        "选中的不是 TS 节点 / 首帧未到"
    );
    assert!(!ts_exit_became_ready(None, Some("Starting")));
}

/// 🔴 **停流自愈的两个判据**（2026-08-02 真机：首帧 `NoState` 之后再无第二帧，TS 早已就绪却
/// 一直被当成「尚未登录」，测速被挡、出口卡显示 `—`）。
///
/// **变异锁**：
/// - 去掉 `!states.is_empty()`（只留 `all`）→ 第 1 条转红。空集上 `all` 恒真 ⇒ 一帧都没收到时
///   被判成「全就绪」⇒ 自愈在最该触发的那一刻恰好不触发，这正是本条存在的全部理由；
/// - 把 `all` 写成 `any` → 第 4 条转红（一个端点就绪就不再自愈另一个卡住的）。
#[test]
fn ts_resubscribe_only_when_not_all_endpoints_ready() {
    let m = |pairs: &[(&str, &str)]| -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    };
    assert!(
        !ts_all_running(&m(&[])),
        "一帧都没收到 = 最该重订阅，绝不能因空集被判成全就绪"
    );
    assert!(!ts_all_running(&m(&[("a", "NoState")])));
    assert!(ts_all_running(&m(&[("a", "Running")])), "稳态不该 churn");
    assert!(
        !ts_all_running(&m(&[("a", "Running"), ("b", "NeedsLogin")])),
        "有端点没就绪就还要自愈"
    );
    assert!(ts_all_running(&m(&[("a", "Running"), ("b", "Running")])));
}

/// 🔴 **跃迁日志只在真变了时落**（稳态每秒一帧全打 = 刷屏，与本批治理的 switchMode/dns-race 同病），
/// 且**幽灵端点不入日志**（tag 不在册 ⇒ UI 上根本没这个节点，打出来比不打更误导）。
///
/// 断言的是**末态表**而非日志文本（`log` 宏在单测里无 sink 可断言）：末态表既是跃迁判据的载体，
/// 也是停流自愈 `ts_all_running` 的输入 —— 它错了两个功能一起错。
///
/// **变异锁**：删掉「相同即 continue」那一句 → 末态表仍对，但第 3 段的 `<无帧>` 语义丢失
/// （`insert` 返回值会变成上一次的同值）；删掉幽灵过滤 → 第 2 条断言转红。
#[test]
fn ts_transition_log_records_only_registered_endpoints_and_real_changes() {
    let tag_to_id = BTreeMap::from([("mesh-01".to_string(), "srv-ts".to_string())]);
    use polaris_singbox_grpc::daemon as dm;
    let frame = |state: &str, ips: Vec<String>| dm::TailscaleStatusUpdate {
        endpoints: vec![
            dm::TailscaleEndpointStatus {
                endpoint_tag: "mesh-01".into(),
                backend_state: state.into(),
                self_: Some(dm::TailscalePeer {
                    tailscale_i_ps: ips,
                    ..Default::default()
                }),
                ..Default::default()
            },
            dm::TailscaleEndpointStatus {
                endpoint_tag: "幽灵".into(),
                backend_state: "Running".into(),
                ..Default::default()
            },
        ],
    };
    let mut last = BTreeMap::new();

    log_ts_state_transitions(&frame("NoState", vec![]), &tag_to_id, &mut last);
    assert_eq!(last.get("srv-ts").map(String::as_str), Some("NoState"));
    assert!(
        !last.contains_key("幽灵") && last.len() == 1,
        "幽灵端点（tag 不在册）不得进末态表——否则 ts_all_running 会被一个 UI 上不存在的节点左右"
    );

    // 稳态重复帧：末态不变（也不该打日志）。
    log_ts_state_transitions(&frame("NoState", vec![]), &tag_to_id, &mut last);
    assert_eq!(last.get("srv-ts").map(String::as_str), Some("NoState"));

    // 真跃迁：末态跟上，且此刻 tailnet IP 已有 ⇒ 自愈判据翻成「全就绪」。
    log_ts_state_transitions(
        &frame("Running", vec!["100.64.0.9".into()]),
        &tag_to_id,
        &mut last,
    );
    assert_eq!(last.get("srv-ts").map(String::as_str), Some("Running"));
    assert!(ts_all_running(&last));
}

/// 🔵 **触发点④的组合面门**：一帧把选中 TS 出口带到 `Running` ⇒ `apply_ts_status_frame` 必须同时
/// 失效解锁缓存并排程出口 IP 重探；紧接着的稳态 Running 帧**一次都不许**再触发。
///
/// # 这条补的是什么洞
///
/// §10.1 的 上游 触发表含「TS 隧道就绪」，而 Polaris 侧原先只接了广播半边
/// （`emit_tailscale_status`）—— mesh 出口就绪同样换掉出口 IP，漏掉它就是那句「只移植了广播半边」
/// 的同款形态。且 `exit_ip_wiring_guard` 的配对扫描对它**天然失明**（它压根不在命中的三个点里）。
///
/// 帧④⑤（选中端点从帧里消失 → 再带 Running 回来）是第三轮复审登记的**覆盖缺口**补测：
/// 它钉住「`after=None` 不算就绪」与「消失后回来算新的上升沿」这一对语义。
///
/// **变异锁**：删掉 `apply_ts_status_frame` 里那对调用 → 两处记录皆空 → 转红；
/// 只删其中一条 → 对应那条转红；把上升沿判据改成「看当前值」→ 第二帧后计数变 2 → 转红；
/// 把 `after == Some("Running")` 放宽成「after 非空」→ 帧④（endpoints 为空）语义不变，
/// 但帧①（NeedsLogin）即触发 → 转红。
#[tokio::test]
async fn ts_tunnel_ready_invalidates_unlock_and_refreshes_exit_ip_once() {
    use polaris_singbox_grpc::daemon;
    let (rt, _dir) = test_runtime();
    let inval: UnlockInvalidations = Arc::new(Mutex::new(Vec::new()));
    let refreshes: ExitIpRefreshes = Arc::new(Mutex::new(Vec::new()));
    rt.set_error_emitter(Box::new(RecordingErrorEmitter {
        unlock_invalidations: Arc::clone(&inval),
        exit_ip_refreshes: Arc::clone(&refreshes),
        ..Default::default()
    }));
    // 选中出口 = 那个 TS 节点（触发点只关心**选中**出口：别的端点就绪不换我的出口 IP）。
    *rt.current_config.write().unwrap() = Some(serde_json::json!({ "selectedServerId": "srv-ts" }));
    let tag_to_id = BTreeMap::from([("mesh-01".to_string(), "srv-ts".to_string())]);
    let frame = |state: &str| daemon::TailscaleStatusUpdate {
        endpoints: vec![daemon::TailscaleEndpointStatus {
            endpoint_tag: "mesh-01".into(),
            backend_state: state.into(),
            ..Default::default()
        }],
    };

    // 帧①登录中 → 未就绪，不触发。
    rt.apply_ts_status_frame(&frame("NeedsLogin"), &tag_to_id, rt.gate.generation());
    assert!(
        refreshes.lock().unwrap().is_empty(),
        "隧道未就绪就重探 = 探到让位期的直连出口，把它当成 TS 出口显示"
    );

    // 帧②跃迁 Running → 隧道就绪，出口 IP 换掉 ⇒ 两条腿都必须动。
    rt.apply_ts_status_frame(&frame("Running"), &tag_to_id, rt.gate.generation());
    assert_eq!(
        *refreshes.lock().unwrap(),
        vec![true],
        "TS 隧道就绪须排程出口 IP 重探（running=true ⇒ 等 4s 选路收敛）"
    );
    assert_eq!(
        *inval.lock().unwrap(),
        vec![(true, false)],
        "新出口上线 ⇒ 解锁快照作废，与起核/热切/停核三点同语义"
    );

    // 帧③稳态 Running → 一次都不许再触发（relay 每秒量级推帧）。
    rt.apply_ts_status_frame(&frame("Running"), &tag_to_id, rt.gate.generation());
    rt.apply_ts_status_frame(&frame("Running"), &tag_to_id, rt.gate.generation());
    assert_eq!(
        refreshes.lock().unwrap().len(),
        1,
        "稳态帧重复触发 ⇒ 出口 IP 重探退化成每秒一次的轮询（本子系统的设计前提是无轮询）"
    );
    assert_eq!(
        inval.lock().unwrap().len(),
        1,
        "同上：解锁检测也会被每秒作废一次"
    );

    // 帧④选中端点**从帧里消失**（relay 重连后的首帧可能不含它 / 该端点被摘）：
    // `after = None` ⇒ 不触发，但边沿状态也就此复位。这一形态原先组合测未覆盖（第三轮复审登记的
    // 覆盖缺口），补在这里是因为它决定了帧⑤的语义 —— 而帧⑤才是真正需要钉死的那一条。
    rt.apply_ts_status_frame(
        &daemon::TailscaleStatusUpdate { endpoints: vec![] },
        &tag_to_id,
        rt.gate.generation(),
    );
    assert_eq!(
        refreshes.lock().unwrap().len(),
        1,
        "端点消失（after=None）不是「就绪」，不得触发重探"
    );

    // 帧⑤端点带着 Running 回来 ⇒ **重新触发**（`ts_exit_became_ready(None, Some(\"Running\"))`）。
    // 这是**有意**的：中间那一帧意味着 relay 眼里这条隧道确实不在了，回来即「此刻起经 TS 出口走」，
    // 与首帧即 Running 同性质。它不构成轮询——复位需要一次真正的「端点消失」帧，稳态 Running 帧
    // （帧③）一次都不会复位。
    rt.apply_ts_status_frame(&frame("Running"), &tag_to_id, rt.gate.generation());
    assert_eq!(
        *refreshes.lock().unwrap(),
        vec![true, true],
        "端点消失后再回到 Running = 新的上升沿，须重探（出口在这期间确实换过）"
    );
    assert_eq!(inval.lock().unwrap().len(), 2, "同上：解锁快照同样须作废");
}

/// `endpoint_tag_to_id` = `build_id_to_tag_map` 的逆（tag→id）。打断（tuple 反了 → id→tag）→ 查 tag 取不到 → 转红。
#[test]
fn endpoint_tag_to_id_inverts_id_to_tag_map() {
    use polaris_config_engine::user_config::server_config::{Protocol, ServerConfig};
    let mut cfg = UserConfig::default();
    cfg.servers.push(ServerConfig {
        id: "id-a".into(),
        name: "东京 03".into(),
        protocol: Protocol::Tailscale,
        ..Default::default()
    });
    let map = ProxyRuntime::endpoint_tag_to_id(&cfg);
    assert_eq!(
        map.get("东京 03").map(String::as_str),
        Some("id-a"),
        "endpointTag → serverId 逆映射"
    );
}

/// 选中 TS 出口的**可落盘**配置（`exit_node` 为 None ⇒ NoExitDevice；给值则按 peers 判 offline/未广告）。
///
/// 基于 `polaris_store::default_config()` 增量覆盖（同 `two_node_config_ports` 的既定手法）——
/// `save_full` 会跑校验（`tunConfig` 等必填），裸 json 字面量过不了。
/// 安全硬约束：`proxyModeType` 恒 `manual`（本组测试全程不起核，但绝不在配置里留 tun/systemProxy）。
fn ts_exit_config(exit_node: Option<&str>) -> Value {
    let mut ts = serde_json::json!({});
    if let Some(e) = exit_node {
        ts["exitNode"] = Value::String(e.to_string());
    }
    let mut cfg = polaris_store::default_config();
    let obj = cfg.as_object_mut().unwrap();
    obj.insert(
        "servers".into(),
        serde_json::json!([{
            "id": "ts1", "name": "组网出口", "protocol": "tailscale",
            "address": "100.64.0.5", "port": 0,
            "tailscaleSettings": ts
        }]),
    );
    obj.insert("selectedServerId".into(), serde_json::json!("ts1"));
    obj.insert("proxyMode".into(), serde_json::json!("smart"));
    obj.insert("proxyModeType".into(), serde_json::json!("manual"));
    cfg
}

/// 让 `mesh.ts_status_event("ts1")` 有一帧（`logged_in` 是 `derive_ts_exit_warning` 的必要前置）。
fn seed_ts_frame(
    rt: &Arc<ProxyRuntime>,
    peers: Vec<crate::runtime::tailscale_status::TailscaleStatusPeer>,
) {
    rt.mesh.update_ts_status(vec![TailscaleStatusEvent {
        server_id: "ts1".into(),
        backend_state: "Running".into(),
        logged_in: true,
        auth_url: None,
        tailscale_ips: vec!["100.64.0.9".into()],
        expired: false,
        peers,
        details: Default::default(),
        // Taildrop 四位在本用例无关，取「无能力、无文件」的中性值；不给 Default 是刻意的：
        // 日后再加字段时，这些构造点必须重新被人看一眼，而不是被 `..Default::default()` 静默补齐。
        can_share_files: false,
        waiting_file_count: 0,
        receiving_file_count: 0,
        unread_file_count: 0,
    }]);
}

fn ts_peer(
    host: &str,
    ip: &str,
    online: bool,
    advertises: bool,
) -> crate::runtime::tailscale_status::TailscaleStatusPeer {
    crate::runtime::tailscale_status::TailscaleStatusPeer {
        host_name: host.into(),
        ip: ip.into(),
        online,
        exit_node: false,
        exit_node_option: advertises,
        active: false,
        stable_id: Some("sid-x".into()),
        details: Default::default(),
    }
}

/// `TsExitWarning` → 前端 `ProxyExitBlock` 值域的**逐条**投影（四个字符串是跨层契约，拼错 = 前端读不到）。
///
/// **变异锁**：任一分支改串 / 合并两个分支 / 把 `None` 也映成某个原因 → 对应断言转红。
/// 这四个值必须与 `ui/src/contracts/types/runtime.ts` 的 `ProxyExitBlock` 联合类型逐字一致。
#[test]
fn ts_exit_block_reason_projects_the_frontend_contract_values() {
    assert_eq!(
        ProxyRuntime::ts_exit_block_reason(TsExitWarning::None),
        None
    );
    assert_eq!(
        ProxyRuntime::ts_exit_block_reason(TsExitWarning::NeedsAuth),
        Some("ts-needs-auth")
    );
    assert_eq!(
        ProxyRuntime::ts_exit_block_reason(TsExitWarning::NoExitDevice),
        Some("ts-no-exit-device")
    );
    assert_eq!(
        ProxyRuntime::ts_exit_block_reason(TsExitWarning::ExitDeviceOffline),
        Some("ts-exit-device-offline")
    );
    assert_eq!(
        ProxyRuntime::ts_exit_block_reason(TsExitWarning::ExitDeviceNotAdvertised),
        Some("ts-exit-not-advertised")
    );
}

/// **廉价前置的等价性**：STATUS 缓存空 ⇒ 判定恒 `None`，**与配置内容无关**。
///
/// 前置存在的理由是省掉每帧一次整份配置深拷贝；它的正确性靠的是
/// 「无帧 ⇒ `logged_in=false` ⇒ [`derive_ts_exit_warning`] 第一道守卫返 None」这条链。本测用一份
/// **必然会判无效**的配置（选中 TS 出口 + 无 `exitNode` ⇒ NoExitDevice）压住它：只要前置被写成
/// 「跳过时返回别的东西」或链条断了（如把 `logged_in` 默认成 true），本测立刻转红。
///
/// **变异锁**：把 `has_ts_status` 的空判反向（空 → true 继续走）→ 判定变成 `Some(...)` → 转红；
/// 把前置整个删掉 → 本测仍绿（前置只是省功），但 `ts_exit_none_to_blocked_*` 那条仍守着行为——
/// 这正是设计意图：前置是优化，不是语义。
#[tokio::test]
async fn exit_block_is_none_when_status_cache_empty() {
    let (rt, _dir) = test_runtime();
    rt.config
        .save_full(&ts_exit_config(None))
        .expect("save cfg");
    assert!(
        rt.selected_ts_exit_block().is_none(),
        "无任何 TS STATUS 帧 ⇒ 判定恒 None（廉价前置与全量判定必须同结论）"
    );
    // 补一帧后，同一份配置立刻判无效 —— 证明上面的 None 来自「无帧」而非「判定坏了」。
    seed_ts_frame(&rt, vec![]);
    assert_eq!(
        rt.selected_ts_exit_block(),
        Some("ts-no-exit-device"),
        "有帧后同一配置必须判无效，否则上面那条 None 是假绿"
    );
}

/// **逐字段投影 ≡ 整份 `UserConfig` 反序列化**（NIT：每帧一次 200 节点级 typed 反序列化）。
///
/// `selected_ts_exit_block` 不再 `from_value::<UserConfig>(整份)`，改为只取
/// `selectedServerId` / 被选中的那**一个** server / `proxyMode` 三项。等价性不能靠肉眼读 ——
/// 本测把同一份配置**双路**跑：投影路（真方法）vs typed 路（原样重建 `TsExitWarningInput`），
/// 逐格对拍谓词结论。
///
/// 覆盖矩阵（每格都能单独打死一种投影写法）：
/// - `proxyMode=direct` ⇒ 恒 None（投影若把 `proxyMode` 取错键/大小写敏感反了 → 两路分叉）；
/// - 选中项 = 撞在**后面**的那个 server（投影若按下标 0 取 / 忘了按 id 匹配 → 拿到错的节点）；
/// - 选中 TS 无 `exitNode` ⇒ `ts-no-exit-device`（投影若把整个 server 丢了 → 变 None）。
///
/// **变异锁**：把投影的 `find(id == sel_id)` 换成 `first()` → 第二格转红；把 `proxyMode` 比对写成
/// `== Some("Direct")` → 第一格转红；把 `selected` 恒置 None → 第三格转红。
#[tokio::test]
async fn selected_ts_exit_block_projection_matches_typed_parse() {
    let (rt, _dir) = test_runtime();
    seed_ts_frame(&rt, vec![]); // logged_in=true、peers 空 → 走到 exitNode 那道判据

    // 选中项刻意排在**第二位**，前面放一个合法的非 TS 干扰项。不能放第二个 TS：配置契约只
    // 保留首个 Tailscale 节点，规范化保存会合法剔除后者；用非法夹具会让本门依赖清洗前缓存。
    let mut cfg = ts_exit_config(None);
    let obj = cfg.as_object_mut().unwrap();
    obj.insert(
        "servers".into(),
        serde_json::json!([
            { "id": "decoy", "name": "干扰", "protocol": "vless", "address": "decoy.example.com",
              "port": 443, "uuid": "00000000-0000-0000-0000-000000000001" },
            { "id": "ts1", "name": "组网出口", "protocol": "tailscale", "address": "100.64.0.5",
              "port": 0, "tailscaleSettings": {} },
        ]),
    );

    for mode in ["smart", "direct"] {
        cfg["proxyMode"] = serde_json::json!(mode);
        rt.config.save_full(&cfg).expect("save cfg");
        // typed 路：原样重建（这正是被替换掉的那段实现）。
        let canonical = rt.config.current().expect("读取规范化当前配置");
        let typed: UserConfig = serde_json::from_value(canonical).expect("typed 解析");
        let sel_id = typed.selected_server_id.as_deref().expect("有选中项");
        let event = rt.mesh.ts_status_event(sel_id);
        let (logged_in, peers, definitive_logged_out) =
            event.as_ref().map_or((false, &[][..], false), |e| {
                (e.logged_in, e.peers.as_slice(), is_definitive_logged_out(e))
            });
        let expected =
            ProxyRuntime::ts_exit_block_reason(derive_ts_exit_warning(&TsExitWarningInput {
                selected: typed.servers.iter().find(|s| s.id == sel_id),
                logged_in,
                proxy_mode_direct: typed.proxy_mode == ProxyMode::Direct,
                proxy_running: rt.status().running,
                peers,
                definitive_logged_out,
            }));
        assert_eq!(
            rt.selected_ts_exit_block(),
            expected,
            "proxyMode={mode}：逐字段投影与整份反序列化必须同结论"
        );
        // 反证：矩阵里至少有一格是**非 None**，否则整条对拍可能只是「两边都恒 None」。
        if mode == "smart" {
            assert_eq!(
                expected,
                Some("ts-no-exit-device"),
                "前置：选中的 ts1 未配 exitNode ⇒ 必判无效（若这里是 None，本测退化成空对拍）"
            );
        } else {
            assert_eq!(expected, None, "direct ⇒ 方向反转不适用");
        }
    }
}

/// **R2 `none → blocked`**：出口 IP **不探测**直落终态 + 解锁快照失效并带 `exit_blocked=true`。
///
/// 这条钉住的是三件事，缺一不可：
/// 1. 走的是 `mark_exit_blocked` 而**不是** `schedule_exit_ip_refresh` —— 排探测在已知无效的出口上
///    必然打空转（20s 重试预算耗尽后仍是 null），用户看到「一直在检测」；
/// 2. `exit_blocked=true` 真的传下去了 —— 这是该参数**唯一**的生产真值来源（其余三个触发点恒 false），
///    渲染端据此复位 idle 而非留着陈旧绿点；
/// 3. 原因串是契约值域里的那一个（NoExitDevice → `ts-no-exit-device`）。
///
/// **变异锁**：删 `mark_exit_blocked` 调用 → marks 空转红；把它换成 `schedule_exit_ip_refresh` →
/// refreshes 非空 + marks 空、两处同时转红；`exit_blocked` 写死 false → 第 2 条转红；
/// 把跨态判据改成 level（每帧都动作）→ 下面的「同态零动作」测转红。
#[tokio::test]
async fn ts_exit_none_to_blocked_marks_terminal_state_and_invalidates_with_flag() {
    let (rt, _dir, inval, refreshes, marks) = test_runtime_r2();
    rt.config
        .save_full(&ts_exit_config(None))
        .expect("save cfg");
    seed_ts_frame(&rt, vec![]);

    rt.reconcile_ts_exit_block(rt.gate.generation());

    assert_eq!(
        *marks.lock().unwrap(),
        vec!["ts-no-exit-device".to_string()],
        "出口已知无效 ⇒ 无探测直落终态（探了必然空转 20s 预算再吐 null）"
    );
    assert_eq!(
        *inval.lock().unwrap(),
        vec![(false, true)],
        "跨态即令解锁快照失效，且 exit_blocked=true 必须真传下去（该参数唯一的生产真值来源）"
    );
    assert!(
        refreshes.lock().unwrap().is_empty(),
        "blocked 态绝不能排真探测：那正是「一直在检测」的成因"
    );
}

/// **R2 同态零动作**：`blocked → blocked`（同原因）一次都不许再动作。
///
/// STATUS relay 每秒量级推帧，level 触发 = 每秒一次解锁失效 + 每秒一次终态广播
/// （与 [`ts_exit_became_ready`] 挡住的是同一种轮询退化）。
///
/// **变异锁**：删掉 `if *g == cur { return; }` 早退 → 第二次调用后计数变 2 → 转红。
#[tokio::test]
async fn ts_exit_same_state_frames_never_re_fire() {
    let (rt, _dir, inval, _refreshes, marks) = test_runtime_r2();
    rt.config
        .save_full(&ts_exit_config(None))
        .expect("save cfg");
    seed_ts_frame(&rt, vec![]);

    rt.reconcile_ts_exit_block(rt.gate.generation());
    rt.reconcile_ts_exit_block(rt.gate.generation());
    rt.reconcile_ts_exit_block(rt.gate.generation());

    assert_eq!(marks.lock().unwrap().len(), 1, "同态帧不得重复落终态");
    assert_eq!(inval.lock().unwrap().len(), 1, "同态帧不得重复失效解锁");
}

/// **R2 原因变更 `blocked → blocked'`** 仍算跨态：终态原因要更新（离线 → 未广告是两种不同的用户指引）。
///
/// **变异锁**：把跨态判据从「值不等」改成「有无 block 的布尔不等」→ 第二次不触发 → 转红。
#[tokio::test]
async fn ts_exit_reason_change_is_a_transition_too() {
    let (rt, _dir, _inval, _refreshes, marks) = test_runtime_r2();
    rt.config
        .save_full(&ts_exit_config(Some("exit-host")))
        .expect("save cfg");
    *rt.status.write().unwrap() = ProxyStatus {
        running: true,
        ..Default::default()
    };
    // ① exit peer 离线
    seed_ts_frame(&rt, vec![ts_peer("exit-host", "100.64.0.5", false, true)]);
    rt.reconcile_ts_exit_block(rt.gate.generation());
    // ② 同一 peer 上线但未广告出口 → 原因变了
    seed_ts_frame(&rt, vec![ts_peer("exit-host", "100.64.0.5", true, false)]);
    rt.reconcile_ts_exit_block(rt.gate.generation());

    assert_eq!(
        *marks.lock().unwrap(),
        vec![
            "ts-exit-device-offline".to_string(),
            "ts-exit-not-advertised".to_string()
        ],
        "原因变更也是跨态：终态原因必须更新，否则用户拿到的是上一个原因的排障指引"
    );
}

/// **R2 `blocked → none`**：走**恢复腿**（而非直接重探）+ 解锁快照失效且 `exit_blocked=false`。
///
/// 用「预置单飞在飞」把 spawn 挡在门外，使断言完全确定（否则后台任务与断言竞速）——
/// 同时这本身就证明了对账腿**真的调到了** `begin_ts_exit_recovery`：pending 只可能由它置位。
///
/// **变异锁**：删 `spawn_ts_exit_recovery` 调用 → pending 保持 false → 转红；
/// 把恢复腿换成裸 `schedule_exit_ip_refresh` → pending false + refreshes 非空 → 两处转红
/// （而那正是「re-advertise 后核不重解析 exit_node、只重探等于探了个寂寞」的形态）；
/// `exit_blocked` 在恢复腿传 true → 断言转红。
#[tokio::test]
async fn ts_exit_blocked_to_none_runs_recovery_leg_not_a_bare_reprobe() {
    let (rt, _dir, inval, refreshes, marks) = test_runtime_r2();
    rt.config
        .save_full(&ts_exit_config(Some("exit-host")))
        .expect("save cfg");
    *rt.status.write().unwrap() = ProxyStatus {
        running: true,
        ..Default::default()
    };
    // ① 无效（peer 离线）
    seed_ts_frame(&rt, vec![ts_peer("exit-host", "100.64.0.5", false, true)]);
    rt.reconcile_ts_exit_block(rt.gate.generation());
    assert_eq!(marks.lock().unwrap().len(), 1);
    inval.lock().unwrap().clear();

    // ② 恢复有效（peer 上线且广告出口）。预置「恢复腿在飞」→ 本次只记 pending，不 spawn。
    rt.ts_exit_recovering.store(true, Ordering::SeqCst);
    seed_ts_frame(&rt, vec![ts_peer("exit-host", "100.64.0.5", true, true)]);
    rt.reconcile_ts_exit_block(rt.gate.generation());

    assert!(
        rt.ts_exit_recover_pending.load(Ordering::SeqCst),
        "blocked→none 必须触达恢复腿（在飞时记 pending）——只重探不热重设 exit_node = 探了个寂寞"
    );
    assert_eq!(
        *inval.lock().unwrap(),
        vec![(true, false)],
        "出口恢复有效 ⇒ 解锁自动重检，且 exit_blocked 必须翻回 false"
    );
    assert_eq!(marks.lock().unwrap().len(), 1, "恢复态不得再落无效终态");
    assert!(
        refreshes.lock().unwrap().is_empty(),
        "重探由恢复腿在 reapply+reassert 之后收尾，不在对账腿里抢跑"
    );
}

/// **R2 恢复腿单飞 + 补跑门**（纯状态机，同步可直测）。
///
/// - 首次抢占成功；
/// - 在飞期间的后来者一律 `false` 且**记 pending**（边沿触发的腿丢了边沿不会自愈，见字段文档）；
/// - 令牌归还后可再次抢占。
///
/// 归还口是 [`TsExitRecoverGuard`] 的 Drop（**唯一**归还点，见
/// [`ProxyRuntime::reset_ts_exit_block_state`] 文档解释为何停核腿不再代为归还）。
///
/// **变异锁**：`swap(true)` 写成 `load()` → 第二次也返 true → 转红；
/// 删掉 pending 置位 → 第二条断言转红（那正是 flap 期边沿被静默吞掉的形态）；
/// Drop 里删掉 `recovering` 复位 → 末条转红（此后本会话所有真恢复被单飞永久吞掉）。
#[tokio::test]
async fn ts_exit_recovery_single_flight_records_pending_for_late_comers() {
    let (rt, _dir) = test_runtime();
    assert!(rt.begin_ts_exit_recovery(), "首次必须抢到");
    assert!(
        !rt.ts_exit_recover_pending.load(Ordering::SeqCst),
        "首次抢到不该置 pending（否则每轮都白补跑一次）"
    );
    assert!(!rt.begin_ts_exit_recovery(), "在飞期间后来者必须被单飞挡下");
    assert!(
        rt.ts_exit_recover_pending.load(Ordering::SeqCst),
        "被挡下的边沿必须记 pending：恢复腿是边沿触发，丢了不会靠下一帧自愈"
    );
    // 持有者退场（核未运行 ⇒ Drop 的补跑门第一条就不成立，不会 spawn 出新腿来干扰断言）。
    drop(TsExitRecoverGuard(Arc::clone(&rt)));
    assert!(rt.begin_ts_exit_recovery(), "令牌归还后可再次抢占");
}

/// 🔴 **丢边沿补救门（#8）**：`pending` 由 Drop 用 `swap` 取走并按当下核状态裁定要不要补跑。
///
/// # 这条窗口 上游 没有、Rust 有
///
/// 上游 `recoverTsExit` 的 `while (this.tsExitRecoverPending && …)` 判定与 `finally` 之间没有插入点
/// （单线程）。Rust 这里有：循环判 `pending == false` 之后、Drop 执行之前，STATUS relay **另一条线程**
/// 完全可以跑一次 `begin_ts_exit_recovery` 把 pending 置回 `true`。Drop 若无条件 `store(false)`，
/// 这条 `blocked→none` 边沿就被**永久**抹掉 —— 恢复腿是边沿触发，同态帧下一轮直接早退，不会自愈。
///
/// **变异锁**：
/// - `swap(false)` 改回 `load()` → ② 转红（边沿留在位上，下一次 Drop 会重复消费）；
/// - 删掉 `status().running` 判据 → ③ 转红（核已停时 `selected_ts_exit_block()` 恒 None，会被误读成
///   「出口有效」⇒ 对着已停的核重申路由 + 以 `running=true` 语义重探）；
/// - 删掉 `selected_ts_exit_block().is_none()` 判据 → ④ 转红（flap 回 blocked 还去空跑恢复）。
#[tokio::test]
async fn drop_reclaims_the_edge_lost_between_the_loop_check_and_the_guard() {
    let (rt, _dir, _inval, _refreshes, _marks) = test_runtime_r2();
    rt.config
        .save_full(&ts_exit_config(Some("exit-host")))
        .expect("save cfg");
    *rt.status.write().unwrap() = ProxyStatus {
        running: true,
        ..Default::default()
    };
    // 出口有效（peer 上线且广告出口）⇒ selected_ts_exit_block() == None。
    seed_ts_frame(&rt, vec![ts_peer("exit-host", "100.64.0.5", true, true)]);
    assert!(rt.selected_ts_exit_block().is_none(), "前置：出口判有效");

    // ① 无边沿 → 不补跑（否则每轮恢复腿都白跑第二遍）。
    assert!(!rt.take_ts_exit_recover_rerun());

    // ② 有边沿 + 核在跑 + 出口仍有效 → 补跑，且边沿被**取走**（不留给下一次 Drop 重复消费）。
    rt.ts_exit_recover_pending.store(true, Ordering::SeqCst);
    assert!(
        rt.take_ts_exit_recover_rerun(),
        "循环判定与 Drop 之间被 relay 记下的边沿必须由 Drop 捡回来补跑"
    );
    assert!(
        !rt.ts_exit_recover_pending.load(Ordering::SeqCst),
        "边沿必须被 swap 取走"
    );

    // ③ 核已停：`selected_ts_exit_block()` 因 STATUS 缓存被清而恒 None —— 只看它就会把「没有核」
    //    误读成「出口有效」，于是拿旧会话的 current_config 去重申出口路由并以 running=true 重探。
    rt.ts_exit_recover_pending.store(true, Ordering::SeqCst);
    *rt.status.write().unwrap() = ProxyStatus::default();
    rt.mesh.clear_ts_status();
    assert!(
        !rt.take_ts_exit_recover_rerun(),
        "核已停 ⇒ 绝不补跑（那会对着已停的核重申路由 + 重探）"
    );

    // ④ 核在跑但出口 flap 回 blocked（peer 离线）→ 不对已知无效的出口空跑。
    *rt.status.write().unwrap() = ProxyStatus {
        running: true,
        ..Default::default()
    };
    seed_ts_frame(&rt, vec![ts_peer("exit-host", "100.64.0.5", false, true)]);
    assert!(rt.selected_ts_exit_block().is_some(), "前置：出口判无效");
    rt.ts_exit_recover_pending.store(true, Ordering::SeqCst);
    assert!(
        !rt.take_ts_exit_recover_rerun(),
        "flap 回 blocked ⇒ 不得对着已知无效的出口空跑恢复"
    );

    // ⑤ Drop 真的接了这道门（行为侧的 spawn 不可确定性观测 ⇒ 判据落在 Drop 体的源码上）。
    // `impl Drop for …` 是**顶层项**（列 0），封顶要用列 0 的 `}` —— 取材器因此是
    // `top_level_fn_body` 而不是 `method_body`（后者按四空格 `}` 封顶，是为 impl 内的方法设计的）。
    // 两者只差一个封顶串，用错的代价见 `impl_method_body` 的文档（98 倍超宽 + 可证明的假绿）。
    let drop_body = crate::commands::guard_scan::top_level_fn_body(
        &module_code("runtime/proxy"),
        "impl Drop for TsExitRecoverGuard {",
    );
    assert!(
        drop_body.contains("take_ts_exit_recover_rerun()")
            && drop_body.contains("spawn_ts_exit_recovery(&self.0)"),
        "Drop 必须「先放单飞位 → 取边沿判定 → 命中则补跑」；少了补跑那一步，被 Drop 窗口丢掉的\
             边沿就永远没人消费"
    );
    assert!(
        drop_body.find("ts_exit_recovering").expect("放单飞位")
            < drop_body
                .find("take_ts_exit_recover_rerun()")
                .expect("取边沿"),
        "单飞位必须先放：反过来补跑腿的 begin 会撞上还没放的位 → 边沿又被记回 pending，\
             而此刻已经没有在飞腿会去消费它"
    );
}

/// 🔴 **恢复腿的世代守卫（#2）**：被停核 / 换核 / 新 start 接管的旧腿，三步一步都不许做。
///
/// 这条 `'static` 任务能活过停核（`spawn` 出去、无人 abort），而三步全是「对着**当前**核」的动作。
/// 可观测末端取 `schedule_exit_ip_refresh`（`running=true` 语义的重探）：旧腿放它出去，会去重探一个
/// 已死的核，并**后发覆盖** `stop_inner` 那次 `schedule_exit_ip_refresh(false)`。
///
/// 另两条后果本机观测不到（macOS `find_tailnet_iface` 的 18s 轮询 + 真 route 手术是真机门），
/// 由源码守卫 `ts_exit_recover_once_order_is_reapply_reassert_refresh` 的「三处世代比对」断言锁住。
///
/// **变异锁**：删掉 `ts_exit_recover_once` 的任一处世代比对 → 那条源码断言转红；删掉**收尾**那处
/// → 本测试也转红。
#[tokio::test]
async fn superseded_recovery_leg_must_not_reprobe_a_dead_core() {
    let (rt, _dir, _inval, refreshes, _marks) = test_runtime_r2();
    rt.config
        .save_full(&ts_exit_config(Some("exit-host")))
        .expect("save cfg");
    *rt.current_config.write().unwrap() = Some(ts_exit_config(Some("exit-host")));
    let stale = rt.gate.generation();
    rt.bump_generation(); // 停核 / 新 start 接管

    rt.ts_exit_recover_once(stale).await;

    assert!(
        refreshes.lock().unwrap().is_empty(),
        "被接管的旧腿不得以「代理在跑」语义重探：它会对着已死的核探，并后发覆盖停核腿的 refresh(false)"
    );
    // 正向对照：当权者仍必须跑完三步（守卫不得退化成「谁都不跑」）。
    rt.ts_exit_recover_once(rt.gate.generation()).await;
    assert_eq!(
        *refreshes.lock().unwrap(),
        vec![true],
        "当权的恢复腿必须照常以重探收尾"
    );
}

/// 🔴 **对账腿的锁内世代守卫（#7）**：旧会话的在飞帧不得把 `Some(reason)` 写进新会话的缓存。
///
/// relay 在收帧后复查过一次世代，但那之后还要跑完整个 `apply_ts_status_frame`。停核腿是
/// 「`bump_generation()` → … → `reset_ts_exit_block_state()`」，若对账尾部的缓存写入晚于那次复位，
/// `last_ts_exit_block` 就带着旧原因漏进新会话 ⇒ 重连后**同因** blocked 的首帧被同态早退吞掉，
/// 终态永远落不下去（对账是边沿触发，没有轮询会来纠正）。
///
/// **变异锁**：删掉 `reconcile_ts_exit_block` 里那句 `if self.gate.generation() != my_gen`
/// → ①② 同时转红；把它挪到 `last_ts_exit_block.lock()` 之外（函数入口）→ 语义仍是 check-then-act，
/// 由 `reconcile_generation_guard_is_inside_the_cache_lock` 的源码判据转红。
#[tokio::test]
async fn a_superseded_frame_must_not_poison_the_next_session_reconcile_cache() {
    let (rt, _dir, _inval, _refreshes, marks) = test_runtime_r2();
    rt.config
        .save_full(&ts_exit_config(None))
        .expect("save cfg");
    seed_ts_frame(&rt, vec![]);
    let stale = rt.gate.generation();
    // 停核：bump 世代 + 复位会话起点缓存。
    rt.bump_generation();
    rt.reset_ts_exit_block_state();

    // 旧世代的在飞帧此刻才跑到对账尾部。
    rt.reconcile_ts_exit_block(stale);

    assert!(
        marks.lock().unwrap().is_empty(),
        "① 旧会话的帧不得再落终态（核都停了）"
    );
    assert!(
        rt.last_ts_exit_block.lock().unwrap().is_none(),
        "② 残留的 Some(reason) 会让新会话同因 blocked 的首帧被同态早退吞掉 ⇒ 终态永不落"
    );
    // 正向对照：新会话的帧照常落终态。
    rt.reconcile_ts_exit_block(rt.gate.generation());
    assert_eq!(marks.lock().unwrap().len(), 1, "新会话必须能正常落终态");
}

/// **#7 的位置判据**：世代比对必须在 `last_ts_exit_block` 的**锁内**。
///
/// 放函数入口是 check-then-act：判完到写缓存之间隔着 `selected_ts_exit_block()`（深拷贝整份配置 +
/// 反序列化，微秒级但非零），停核腿完全可以在这条缝里跑完 bump + 复位。`reset_ts_exit_block_state`
/// 持的是**同一把**锁，故把判据放进锁里就等于把「判权 + 写缓存」做成原子的。
#[test]
fn reconcile_generation_guard_is_inside_the_cache_lock() {
    let seg = method_body(
        &module_code("runtime/proxy"),
        "    pub(super) fn reconcile_ts_exit_block(self: &Arc<Self>, my_gen: u64) {",
    );
    let lock_at = seg
        .find("self.last_ts_exit_block.lock()")
        .expect("对账缓存锚点消失，守卫已失去判据");
    let guard_at = seg
        .find("if self.gate.generation() != my_gen {")
        .expect("对账腿缺世代守卫：旧会话的在飞帧会把 Some(reason) 写进新会话的缓存");
    let swap_at = seg
        .find("std::mem::replace(&mut *g, cur)")
        .expect("缓存写入锚点消失，守卫已失去判据");
    assert!(
        lock_at < guard_at && guard_at < swap_at,
        "世代比对必须夹在「取锁」与「写缓存」之间（= 锁内）；放函数入口就还是 check-then-act"
    );
}

/// **R2 恢复腿单轮**跑完三步后必须以「重探」收尾（顺序的可观测末端）。
///
/// 核未运行 ⇒ `reapply_ts_exit_node` 守卫链在第一道就返 false（零 gRPC、零网络）、
/// `exit_route_reassert` 在测试构造的 `enabled=false` op 下诚实 no-op（零 `ip`/`route` 进程）——
/// 本测因此**绝不碰宿主网络**，却仍能证明整轮跑到了尾。
///
/// **变异锁**：删掉末尾的 `schedule_exit_ip_refresh` → 空转红；把它挪到 reapply 之前 → 顺序守卫
/// （`ts_exit_recover_once_order_is_reapply_reassert_refresh`）转红。
#[tokio::test]
async fn ts_exit_recover_once_ends_with_a_reprobe() {
    let (rt, _dir, _inval, refreshes, _marks) = test_runtime_r2();
    rt.config
        .save_full(&ts_exit_config(Some("exit-host")))
        .expect("save cfg");
    *rt.current_config.write().unwrap() = Some(ts_exit_config(Some("exit-host")));

    rt.ts_exit_recover_once(rt.gate.generation()).await;

    assert_eq!(
        *refreshes.lock().unwrap(),
        vec![true],
        "恢复腿必须以重探收尾（running=true ⇒ 等 4s 选路收敛）"
    );
}

/// **R2 恢复腿三步顺序守卫**：`reapply → reassert → refresh`，一步都不许换位。
///
/// 为什么必须守：三步的**顺序本身**就是修复内容 —— re-advertise 后运行中的 sing-box 不随 netmap
/// 重解析 exit_node（上游 watchState 缺陷），不先热重设就 reassert/重探，探到的还是恢复前的出口。
/// 而顺序错了行为测试**看不出来**（本机三步都是 no-op / 记录，末端记录一样有）。
///
/// **取材限定在 `ts_exit_recover_once` 的函数体内**（[`method_body`]）：早先的版本把 `seg` 从方法头
/// 一路切到 EOF，`self.schedule_exit_ip_refresh(true);` 会命中后文其它方法里的同名调用 ⇒ 从恢复腿
/// 里删掉收尾重探，本断言**仍绿**。
/// **常驻轮询腿禁整份深拷贝**：这三个方法都由无条件周期循环驱动，必须走
/// [`ConfigManager::with_current`](crate::runtime::ConfigManager::with_current) 持锁投影，
/// 不得回退到 `config.current()`（后者恒 clone 整份配置，含 200 节点级 `servers`）。
///
/// # 为什么只能是源码型判据
///
/// 这是**纯性能**改动：`current()` 与 `with_current()` 读的是同一份缓存、结论逐字节相同，故把
/// 任何一处改回 `current()`，全部行为断言（`selected_ts_exit_block_projection_matches_typed_parse`
/// / `exit_block_is_none_when_status_cache_empty` / 心跳那几条）**照样全绿** —— 省下的那次深拷贝
/// 在单测里根本不可观测。没有这条守卫，「热路径不深拷贝」就只是注释里的一句话。
///
/// 三条腿的节奏：`selected_ts_exit_block` = TS STATUS relay **每帧（~1Hz）**；
/// 另两条 = 自动换节点心跳**每 tick**（`HEARTBEAT_INTERVAL_MS`，核在跑就一直跑）。
///
/// **双向断言**（缺一都能被绕过）：禁 `.current()` 挡住回退；要求 `.with_current(` 挡住
/// 「把配置读整个删掉」这种让负面断言恒真的改法。
///
/// **变异锁**：任一方法体里把 `.with_current(` 换回 `.current()` ⇒ 逐条转红。
#[test]
fn periodic_legs_read_config_by_projection_not_full_clone() {
    let src = module_code("runtime/proxy");
    for head in [
        "    pub(super) fn selected_ts_exit_block(&self) -> Option<&'static str> {",
        "    fn auto_switch_enabled(&self) -> bool {",
        "    fn selected_server_is_real(&self) -> bool {",
    ] {
        let body = method_body(&src, head);
        assert!(
            !body.contains(".current()"),
            "`{head}` 是常驻周期腿，出现了 `config.current()` —— 那是每帧/每 tick 一次整份配置\
                 深拷贝（含 200 节点级 servers）。改用 `with_current(|v| …)` 只投影要用的字段。"
        );
        assert!(
            body.contains(".with_current("),
            "`{head}` 里连 `with_current` 都没有了 —— 负面断言会因此恒真（门被抽空）。\
                 若确实不再读配置，请连同本守卫的这一项一起删掉，而不是留个空壳。"
        );
    }
}

#[test]
fn ts_exit_recover_once_order_is_reapply_reassert_refresh() {
    let seg = method_body(
        &module_code("runtime/proxy"),
        "    pub(super) async fn ts_exit_recover_once(&self, my_gen: u64) {",
    );
    let reapply = seg
        .find("self.reapply_ts_exit_node().await")
        .expect("① 热重设");
    let reassert = seg
        .find("self.mesh.exit_route_reassert(&cfg, ipv6).await")
        .expect("② 重申出口路由");
    let refresh = seg
        .find("self.schedule_exit_ip_refresh(true);")
        .expect("③ 重探");
    assert!(
        reapply < reassert && reassert < refresh,
        "恢复腿必须按 reapply → reassert → refresh 排列：先修核内 exit_node 与 System 路由，最后才探——\
             顺序换了就是「对着恢复前的出口重探」，与不修一样"
    );
    // 世代守卫（#2）也归本段守：三步之间隔着 gRPC 往返与最长 18s 的路由手术，只在入口判一次等于没判。
    assert_eq!(
        seg.matches("if self.gate.generation() != my_gen {").count(),
        3,
        "恢复腿必须在**每步之前**比对世代（3 处）：少一处就漏掉「停核卡 18s / 旧配置重装路由 / \
             对死核重探」三条后果里的一条"
    );
}

/// **R1 热重设的守卫链**：核未运行 → 一律跳过（返 false），**零 gRPC 连接**（本机零网络的前提）。
///
/// **变异锁**：删掉 `!status.running` 守卫 → 本测会尝试连 127.0.0.1:0 → 仍返 false 但耗时/日志变化；
/// 故同时断言 `clash_api_port == 0` 这条：把端口守卫删掉 → `Endpoint::new("127.0.0.1", 0)` 建连
/// 路径被真的走到（连接必失败，返回值不变但语义已错）。两条守卫都由本测覆盖其**存在性**。
#[tokio::test]
async fn reapply_ts_exit_node_short_circuits_when_core_not_running() {
    let (rt, _dir) = test_runtime();
    *rt.current_config.write().unwrap() = Some(ts_exit_config(Some("exit-host")));
    seed_ts_frame(&rt, vec![ts_peer("exit-host", "100.64.0.5", true, true)]);
    assert!(
        !rt.reapply_ts_exit_node().await,
        "核未运行 → 无管理 API 可打，必须直接跳过（绝不盲连）"
    );
    // 有 running 但无端口 → 同样跳过（端口是 gRPC 目标的必要条件）。
    *rt.status.write().unwrap() = ProxyStatus {
        running: true,
        clash_api_port: 0,
        ..Default::default()
    };
    assert!(
        !rt.reapply_ts_exit_node().await,
        "clash_api_port=0 → 无从建连，必须跳过"
    );
}

/// **R1 守卫链的其余分支**：未配 `exitNode` / peers 解不到 `stableID` → 跳过（不猜、不盲发）。
///
/// **变异锁**：删掉「exitNode 非空」守卫 → 第一条会走到 peers 匹配（找不到 → 仍 false，但下一条
/// 断言的语义已丢）；删掉 `stable_id` 守卫 → 第二条会走到真 gRPC 建连 → 本机零网络前提被打破。
#[tokio::test]
async fn reapply_ts_exit_node_requires_exit_node_and_stable_id() {
    let (rt, _dir) = test_runtime();
    *rt.status.write().unwrap() = ProxyStatus {
        running: true,
        clash_api_port: 65_535,
        ..Default::default()
    };
    // ① 未配 exitNode（切走出口 / 仅内网）→ 无可重设
    *rt.current_config.write().unwrap() = Some(ts_exit_config(None));
    seed_ts_frame(&rt, vec![ts_peer("exit-host", "100.64.0.5", true, true)]);
    assert!(!rt.reapply_ts_exit_node().await, "未配 exitNode → 跳过");
    // ② 配了但 peers 里那条没有 stableID（旧核不发）→ 跳过
    *rt.current_config.write().unwrap() = Some(ts_exit_config(Some("exit-host")));
    let mut p = ts_peer("exit-host", "100.64.0.5", true, true);
    p.stable_id = None;
    seed_ts_frame(&rt, vec![p]);
    assert!(
        !rt.reapply_ts_exit_node().await,
        "无 stableID → 跳过，绝不盲发 EditPrefs"
    );
}

/// **R2 会话起点复位**：停核/崩溃后翻转对账缓存归零，而在飞恢复腿的**单飞令牌一根手指都不许碰**。
///
/// 后半条是本轮修的偏离（上游 `ProxyManager.ts:695` 只清 `lastTsExitBlock`）：清了令牌，
/// 新会话就能在旧腿还在飞时再抢一次 ⇒ 两条恢复腿并发；更糟的是旧腿退出时
/// [`TsExitRecoverGuard`] 的 Drop 会把**新会话**刚置的 recovering/pending 清掉 ⇒ 单飞被打穿。
///
/// **变异锁**：删掉 `last_ts_exit_block` 复位 → ① 转红（复位后第一次 blocked 被当成同态吞掉）；
/// 把 `ts_exit_recovering` / `ts_exit_recover_pending` 的 `store(false)` **加回** `reset_ts_exit_block_state`
/// → ②③ 转红。
#[tokio::test]
async fn reset_clears_the_reconcile_cache_but_never_the_single_flight_token() {
    let (rt, _dir, _inval, _refreshes, marks) = test_runtime_r2();
    rt.config
        .save_full(&ts_exit_config(None))
        .expect("save cfg");
    seed_ts_frame(&rt, vec![]);
    rt.reconcile_ts_exit_block(rt.gate.generation());
    assert_eq!(marks.lock().unwrap().len(), 1);
    // 造出「旧会话的恢复腿仍在飞、且期间又记下一条边沿」的现场。
    assert!(rt.begin_ts_exit_recovery(), "首次抢占");
    assert!(!rt.begin_ts_exit_recovery(), "在飞 → 记 pending");

    rt.reset_ts_exit_block_state();

    // ① 复位后同一无效态必须能**重新**触发（会话起点语义）。
    rt.reconcile_ts_exit_block(rt.gate.generation());
    assert_eq!(
        marks.lock().unwrap().len(),
        2,
        "复位后首帧须能重新落终态；不复位则重连后终态永远落不下去"
    );
    // ②③ 令牌与边沿都归在飞任务所有，停核腿无权归还 —— 归还权错位正是「旧腿 Drop 清掉新会话
    // 的单飞位」那条打穿路径的入口。
    assert!(
        rt.ts_exit_recovering.load(Ordering::SeqCst),
        "停核不得替在飞任务归还单飞令牌（否则新会话可再抢一次 → 两条恢复腿并发跑同一套 route 手术）"
    );
    assert!(
        rt.ts_exit_recover_pending.load(Ordering::SeqCst),
        "停核不得抹掉在飞期间记下的边沿（消费权归在飞任务的 Drop，它会按当下核状态裁定要不要补跑）"
    );
}

/// **组合面门**：R2 对账真的挂在 `apply_ts_status_frame` 尾部（而不是只写了个没人调的方法）。
///
/// 喂一帧真 proto 更新（选中 TS 出口无 exit_node ⇒ NoExitDevice）→ 终态必须被落下。
///
/// **变异锁**：删掉 `apply_ts_status_frame` 尾部的 `self.reconcile_ts_exit_block(my_gen);` → marks 空 → 转红。
/// 这正是「逻辑在、接线不在」那类缺陷的守卫（本仓已栽过一次：`exit_route_reassert` 挂着
/// `#[allow(dead_code)]` 全仓零调用点）。
#[tokio::test]
async fn ts_status_frame_drives_the_exit_block_reconcile() {
    use polaris_singbox_grpc::daemon;
    let (rt, _dir, _inval, _refreshes, marks) = test_runtime_r2();
    rt.config
        .save_full(&ts_exit_config(None))
        .expect("save cfg");
    let tag_to_id = BTreeMap::from([("组网出口".to_string(), "ts1".to_string())]);
    let update = daemon::TailscaleStatusUpdate {
        endpoints: vec![daemon::TailscaleEndpointStatus {
            endpoint_tag: "组网出口".into(),
            backend_state: "Running".into(),
            self_: Some(daemon::TailscalePeer {
                host_name: "self".into(),
                tailscale_i_ps: vec!["100.64.0.9".into()],
                ..Default::default()
            }),
            ..Default::default()
        }],
    };

    rt.apply_ts_status_frame(&update, &tag_to_id, rt.gate.generation());

    assert_eq!(
        *marks.lock().unwrap(),
        vec!["ts-no-exit-device".to_string()],
        "STATUS 帧尾必须跑翻转对账，否则推侧整条腿是死代码（拉侧只在用户点检测那刻求值）"
    );
}
