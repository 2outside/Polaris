use super::*;
use serde_json::json;

// ── on_heartbeat：触发阈值真值表（别过度触发 / 别欠触发）──

#[test]
fn heartbeat_alive_when_no_prior_failures_is_stable() {
    let mut m = AutoSwitchMachine::new();
    m.enable();
    assert_eq!(m.on_heartbeat(true), HeartbeatOutcome::Stable);
}

#[test]
fn heartbeat_two_failures_do_not_trigger() {
    // 单次/两次瞬断不该切——别过度触发。
    let mut m = AutoSwitchMachine::new();
    m.enable();
    assert_eq!(
        m.on_heartbeat(false),
        HeartbeatOutcome::Failing { failures: 1 }
    );
    assert_eq!(
        m.on_heartbeat(false),
        HeartbeatOutcome::Failing { failures: 2 }
    );
}

#[test]
fn heartbeat_third_consecutive_failure_triggers() {
    // 恰好第 3 次连续失败触发——变异：阈值 >= 改 > 会漏这次触发。
    let mut m = AutoSwitchMachine::new();
    m.enable();
    m.on_heartbeat(false);
    m.on_heartbeat(false);
    assert_eq!(m.on_heartbeat(false), HeartbeatOutcome::Trigger);
}

#[test]
fn heartbeat_trigger_resets_failure_count() {
    // 触发后失败计数复位（上游 :142）——下一次失败重新从 1 计。
    let mut m = AutoSwitchMachine::new();
    m.enable();
    m.on_heartbeat(false);
    m.on_heartbeat(false);
    assert_eq!(m.on_heartbeat(false), HeartbeatOutcome::Trigger);
    assert_eq!(
        m.on_heartbeat(false),
        HeartbeatOutcome::Failing { failures: 1 }
    );
}

#[test]
fn heartbeat_alive_resets_failure_streak() {
    // 中途恢复联通 → 失败连击清零（别欠触发的对偶：也别把不连续的失败攒成触发）。
    let mut m = AutoSwitchMachine::new();
    m.enable();
    m.on_heartbeat(false);
    m.on_heartbeat(false);
    assert_eq!(
        m.on_heartbeat(true),
        HeartbeatOutcome::Recovered { prior: 2 }
    );
    // 复位后重新从 1 计，不会因之前 2 次就触发。
    assert_eq!(
        m.on_heartbeat(false),
        HeartbeatOutcome::Failing { failures: 1 }
    );
}

// ── evaluate_switch：冷却 / 熔断 / 在飞 真值表 ──

#[test]
fn gate_in_flight_blocks() {
    let mut m = AutoSwitchMachine::new();
    m.enable();
    m.begin_switch(1_000_000);
    assert_eq!(m.evaluate_switch(2_000_000), SwitchGate::InFlight);
}

#[test]
fn gate_proceeds_when_clear() {
    let mut m = AutoSwitchMachine::new();
    m.enable();
    // 尚无 last_switch_time → 首次切换直接放行。
    assert_eq!(m.evaluate_switch(10_000_000), SwitchGate::Proceed);
}

#[test]
fn first_gate_proceeds_even_when_monotonic_clock_starts_at_zero() {
    let mut m = AutoSwitchMachine::new();
    m.enable();
    assert_eq!(m.evaluate_switch(0), SwitchGate::Proceed);
}

#[test]
fn gate_cooldown_blocks_within_window() {
    // 距上次换节点 30s < 60s 冷却 → 拦。变异：删冷却检查会误放行。
    let mut m = AutoSwitchMachine::new();
    m.enable();
    m.begin_switch(1_000_000);
    m.end_switch();
    match m.evaluate_switch(1_000_000 + 30_000) {
        SwitchGate::Cooldown { remaining_ms } => assert_eq!(remaining_ms, 30_000),
        other => panic!("期望 Cooldown，实际 {other:?}"),
    }
}

#[test]
fn gate_proceeds_after_cooldown_window() {
    let mut m = AutoSwitchMachine::new();
    m.enable();
    m.begin_switch(1_000_000);
    m.end_switch();
    // 距上次 60s+ → 冷却结束，放行。
    assert_eq!(m.evaluate_switch(1_000_000 + 60_001), SwitchGate::Proceed);
}

#[test]
fn gate_breaker_trips_after_max_switches() {
    // 连续切换达上限 + 未过熔断冷却 → 熔断拦。变异：删熔断检查会在整体网络故障时空转。
    let mut m = AutoSwitchMachine::new();
    m.enable();
    // 模拟 3 次成功切换记账。
    m.record_switch_success(1_000_000);
    m.record_switch_success(1_000_000);
    m.record_switch_success(1_000_000); // 第 3 次 → breaker_tripped_at=1_000_000
                                        // 冷却窗内（+5min < 10min）且非在飞、且冷却已过（last_switch_time=0）→ 仍应被熔断拦。
    match m.evaluate_switch(1_000_000 + 5 * 60_000) {
        SwitchGate::Breaker { remaining_ms } => assert_eq!(remaining_ms, 5 * 60_000),
        other => panic!("期望 Breaker，实际 {other:?}"),
    }
}

#[test]
fn gate_breaker_resets_and_proceeds_after_cooldown() {
    let mut m = AutoSwitchMachine::new();
    m.enable();
    m.record_switch_success(1_000_000);
    m.record_switch_success(1_000_000);
    m.record_switch_success(1_000_000);
    // 熔断冷却过后（+10min+1）→ 复位熔断 + 放行。
    let now = 1_000_000 + BREAKER_COOLDOWN_MS + 1;
    assert_eq!(m.evaluate_switch(now), SwitchGate::Proceed);
}

#[test]
fn recovered_heartbeat_clears_breaker_count() {
    // 恢复联通 → 熔断计数清零（上游 :132）：随后连续失败触发时不再被残留计数熔断。
    let mut m = AutoSwitchMachine::new();
    m.enable();
    m.record_switch_success(1_000_000);
    m.record_switch_success(1_000_000);
    m.record_switch_success(1_000_000);
    m.on_heartbeat(true); // 恢复 → consecutive_switches 清零
                          // 冷却也已过（用远后的 now），闸门应放行（熔断计数已清）。
    assert_eq!(m.evaluate_switch(20_000_000), SwitchGate::Proceed);
}

#[test]
fn record_success_only_trips_breaker_at_threshold() {
    // 变异：把 record 的 >= 改成别的会让熔断时刻记错 → 第 3 次才置 breaker_tripped_at。
    let mut m = AutoSwitchMachine::new();
    m.enable();
    m.record_switch_success(500);
    m.record_switch_success(600);
    // 前两次：consecutive_switches<3 → 未熔断，冷却过后放行。
    assert_eq!(m.evaluate_switch(10_000_000), SwitchGate::Proceed);
}

// ── enable/disable 复位 ──

#[test]
fn enable_resets_counters() {
    let mut m = AutoSwitchMachine::new();
    m.enable();
    m.on_heartbeat(false);
    m.record_switch_success(1_000_000);
    m.disable();
    m.enable(); // 重新启用 → 复位
    assert_eq!(
        m.on_heartbeat(false),
        HeartbeatOutcome::Failing { failures: 1 }
    );
}

#[test]
fn enable_is_idempotent_no_reset_on_second_call() {
    // 幂等：已启用再 enable 不复位（否则轮询驱动的重复 enable 会抹掉进行中的失败连击 → 永不触发）。
    let mut m = AutoSwitchMachine::new();
    m.enable();
    m.on_heartbeat(false);
    m.on_heartbeat(false);
    m.enable(); // 已启用 → no-op，不复位
    assert_eq!(m.on_heartbeat(false), HeartbeatOutcome::Trigger);
}

#[test]
fn reset_failures_only_keeps_breaker_count() {
    // 核未运行分支：只清失败、不清熔断（上游 :107-110）。
    let mut m = AutoSwitchMachine::new();
    m.enable();
    m.record_switch_success(1_000_000);
    m.record_switch_success(1_000_000);
    m.record_switch_success(1_000_000);
    m.on_heartbeat(false);
    m.reset_failures_only();
    // 失败清零：下一失败从 1 计。
    assert_eq!(
        m.on_heartbeat(false),
        HeartbeatOutcome::Failing { failures: 1 }
    );
    // 熔断计数未清：仍被熔断拦。
    assert!(matches!(
        m.evaluate_switch(1_000_000 + 60_001),
        SwitchGate::Breaker { .. }
    ));
}

// ── plan_runtime_candidates：运行态候选规划 ──

#[test]
fn plan_runtime_candidates_excludes_current() {
    let cfg = json!({
        "selectedServerId": "a",
        "servers": [
            { "id": "a", "name": "A", "address": "1.1.1.1", "port": 443 },
            { "id": "b", "name": "B", "address": "2.2.2.2", "port": 8443 },
        ]
    });
    let plan = plan_runtime_candidates(
        &cfg,
        Some("a"),
        &BTreeMap::from([(String::from("b"), String::from("b-tag"))]),
        &BTreeMap::from([(String::from("b"), String::from("fp-b"))]),
        &BTreeMap::from([(String::from("b"), String::from("fp-b"))]),
        &BTreeSet::new(),
        &BTreeSet::new(),
    );
    assert_eq!(plan.candidates.len(), 1);
    assert_eq!(plan.candidates[0].id, "b");
    assert_eq!(plan.candidates[0].name, "B");
    assert_eq!(plan.candidates[0].tag, "b-tag");
}

#[test]
fn plan_runtime_candidates_missing_servers_is_empty() {
    assert_eq!(
        plan_runtime_candidates(
            &json!({}),
            Some("a"),
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
        ),
        RuntimeCandidatePlan::default()
    );
}

#[test]
fn plan_runtime_candidates_name_falls_back_to_id() {
    let cfg = json!({ "servers": [ { "id": "x", "address": "h", "port": 1 } ] });
    let plan = plan_runtime_candidates(
        &cfg,
        None,
        &BTreeMap::from([(String::from("x"), String::from("x-tag"))]),
        &BTreeMap::from([(String::from("x"), String::from("fp-x"))]),
        &BTreeMap::from([(String::from("x"), String::from("fp-x"))]),
        &BTreeSet::new(),
        &BTreeSet::new(),
    );
    assert_eq!(plan.candidates[0].name, "x");
}

#[test]
fn plan_runtime_candidates_staged_is_excluded() {
    let plan = plan_runtime_candidates(
        &json!({ "servers": [{ "id": "staged", "name": "Staged" }] }),
        None,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeSet::from([String::from("staged")]),
        &BTreeSet::new(),
    );
    assert!(plan.candidates.is_empty());
    assert_eq!(plan.staged, 1);
}

#[test]
fn plan_runtime_candidates_not_loaded_is_excluded() {
    let plan = plan_runtime_candidates(
        &json!({ "servers": [{ "id": "disk-only" }] }),
        None,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
    );
    assert!(plan.candidates.is_empty());
    assert_eq!(plan.not_loaded, 1);
}

#[test]
fn plan_runtime_candidates_dirty_is_excluded() {
    let plan = plan_runtime_candidates(
        &json!({ "servers": [{ "id": "dirty" }] }),
        None,
        &BTreeMap::from([(String::from("dirty"), String::from("dirty-tag"))]),
        &BTreeMap::from([(String::from("dirty"), String::from("running-fp"))]),
        &BTreeMap::from([(String::from("dirty"), String::from("current-fp"))]),
        &BTreeSet::new(),
        &BTreeSet::new(),
    );
    assert!(plan.candidates.is_empty());
    assert_eq!(plan.dirty, 1);
}

#[test]
fn plan_runtime_candidates_not_ready_is_excluded() {
    let plan = plan_runtime_candidates(
        &json!({ "servers": [{ "id": "not-ready" }] }),
        None,
        &BTreeMap::from([(String::from("not-ready"), String::from("not-ready-tag"))]),
        &BTreeMap::from([(String::from("not-ready"), String::from("same-fp"))]),
        &BTreeMap::from([(String::from("not-ready"), String::from("same-fp"))]),
        &BTreeSet::new(),
        &BTreeSet::from([String::from("not-ready")]),
    );
    assert!(plan.candidates.is_empty());
    assert_eq!(plan.not_ready, 1);
}

#[test]
fn plan_runtime_candidates_clean_is_included() {
    let plan = plan_runtime_candidates(
        &json!({ "servers": [{ "id": "clean", "name": "Clean" }] }),
        None,
        &BTreeMap::from([(String::from("clean"), String::from("clean-tag"))]),
        &BTreeMap::from([(String::from("clean"), String::from("same-fp"))]),
        &BTreeMap::from([(String::from("clean"), String::from("same-fp"))]),
        &BTreeSet::new(),
        &BTreeSet::new(),
    );
    assert_eq!(
        plan.candidates,
        vec![RuntimeCandidate {
            id: String::from("clean"),
            name: String::from("Clean"),
            tag: String::from("clean-tag"),
        }]
    );
    assert_eq!(plan.staged, 0);
    assert_eq!(plan.not_loaded, 0);
    assert_eq!(plan.dirty, 0);
    assert_eq!(plan.not_ready, 0);
}

// ── select_best_candidate：下一节点选择决策 ──

fn cand(id: &str, lat: Option<u32>) -> CandidateLatency {
    CandidateLatency {
        id: id.to_string(),
        name: format!("name-{id}"),
        latency_ms: lat,
    }
}

#[test]
fn select_picks_lowest_latency() {
    let list = vec![
        cand("a", Some(120)),
        cand("b", Some(40)),
        cand("c", Some(80)),
    ];
    assert_eq!(select_best_candidate(&list).unwrap().id, "b");
}

#[test]
fn select_skips_unreachable() {
    // 变异：不过滤 None 会把不可达当最优 → 切到死节点。
    let list = vec![cand("a", None), cand("b", Some(200))];
    assert_eq!(select_best_candidate(&list).unwrap().id, "b");
}

#[test]
fn select_none_when_all_unreachable() {
    let list = vec![cand("a", None), cand("b", None)];
    assert!(select_best_candidate(&list).is_none());
}

#[test]
fn select_empty_is_none() {
    assert!(select_best_candidate(&[]).is_none());
}

#[test]
fn select_ties_take_first() {
    let list = vec![cand("a", Some(50)), cand("b", Some(50))];
    assert_eq!(select_best_candidate(&list).unwrap().id, "a");
}

// ── switch_payload：emit payload ──

#[test]
fn switch_payload_uses_selected_candidate_fields() {
    let best = cand("new-id", Some(42));
    let payload = switch_payload(&best, "连通性检测").unwrap();
    assert_eq!(payload.reason, "连通性检测");
    assert_eq!(payload.new_server_name, "name-new-id");
    assert_eq!(payload.latency, 42);
}

#[test]
fn switch_payload_none_when_candidate_unreachable() {
    assert!(switch_payload(&cand("x", None), "r").is_none());
}

#[test]
fn payload_serializes_camel_case() {
    let p = AutoNodeSwitchedPayload {
        reason: "连通性检测".to_string(),
        new_server_name: "东京-01".to_string(),
        latency: 88,
    };
    let v = serde_json::to_value(&p).unwrap();
    assert_eq!(
        v.get("newServerName").and_then(Value::as_str),
        Some("东京-01")
    );
    assert_eq!(v.get("reason").and_then(Value::as_str), Some("连通性检测"));
    assert_eq!(v.get("latency").and_then(Value::as_u64), Some(88));
}

// ══════════════════════════════════════════════════════════════════════════════
// 本世代停摆判据（`auto_switch_blocked_for_generation`）真值表
//
// 判据本身不重写、直接复用 route 侧的谓词，故本表锁的是**接线**：哪些节点形态会让本世代整体
// 停摆、哪些不会（含「承载公网的组网节点」这条回归锁）。
// ══════════════════════════════════════════════════════════════════════════════

use polaris_config_engine::user_config::app_config::UserConfig;
use polaris_config_engine::user_config::dns_constants::DIRECT_SERVER_ID;
use polaris_config_engine::user_config::protocol_settings::OpenvpnClientSettings;
use polaris_config_engine::user_config::server_config::{
    Protocol, ServerConfig, TailscaleSettings, WireGuardSettings,
};

/// 单节点 config，选中即该节点。
fn cfg_with_selected(server: ServerConfig) -> UserConfig {
    UserConfig {
        selected_server_id: Some(server.id.clone()),
        servers: vec![server],
        ..Default::default()
    }
}

fn wg_node(
    allow_internet: Option<bool>,
    always_route_subnets: Option<bool>,
    allowed_ips: &[&str],
) -> ServerConfig {
    ServerConfig {
        id: "n-wg".into(),
        name: "WG".into(),
        protocol: Protocol::Wireguard,
        address: "1.2.3.4".into(),
        port: 51820,
        wireguard_settings: Some(Box::new(WireGuardSettings {
            allow_internet,
            always_route_subnets,
            allowed_ips: allowed_ips.iter().map(|s| (*s).to_string()).collect(),
            ..Default::default()
        })),
        ..Default::default()
    }
}

fn ts_node(exit_node: Option<&str>, always_route_subnets: Option<bool>) -> ServerConfig {
    ServerConfig {
        id: "n-ts".into(),
        name: "TS".into(),
        protocol: Protocol::Tailscale,
        tailscale_settings: Some(Box::new(TailscaleSettings {
            exit_node: exit_node.map(str::to_string),
            always_route_subnets,
            ..Default::default()
        })),
        ..Default::default()
    }
}

/// WARP：`is_warp_server` 的域名兜底腿（老/导入节点无 `warpDevice` 标记）。
fn warp_node(allow_internet: Option<bool>) -> ServerConfig {
    ServerConfig {
        address: "engage.cloudflareclient.com".into(),
        ..wg_node(allow_internet, Some(false), &[])
    }
}

fn ovpn_node(redirect_gateway: Option<bool>, mesh_routes: &[&str]) -> ServerConfig {
    ServerConfig {
        id: "n-ovpn".into(),
        name: "OVPN".into(),
        protocol: Protocol::OpenvpnClient,
        mesh_routes: mesh_routes.iter().map(|s| (*s).to_string()).collect(),
        openvpn_client_settings: Some(Box::new(OpenvpnClientSettings {
            redirect_gateway,
            ..Default::default()
        })),
        ..Default::default()
    }
}

fn ss_node() -> ServerConfig {
    ServerConfig {
        id: "n-ss".into(),
        name: "SS".into(),
        protocol: Protocol::Shadowsocks,
        address: "1.2.3.4".into(),
        port: 8388,
        ..Default::default()
    }
}

/// **停摆判据的真值表**（判据只此一条：选中的组网节点关外网 → 用户流量整体兜底 direct）。
///
/// 覆盖面按「什么算关外网」在各协议上的表达逐个走一遍：WG 的 `allowInternet` 三态、TS 的
/// `exitNode` 空/全空格/非空、WARP 的恒真短路、OpenVPN 的 `redirectGateway` × `meshRoutes` 四格。
/// 后两族是 2026-09 换判据（协议白名单 → `is_mesh_node`）后才进入这条腿的，必须钉住。
///
/// 变异锁：把 `auto_switch_blocked_for_generation` 的函数体改成恒 `false`（= 删掉守卫）→ 全部
/// 断言为真的格转红；改成恒 `true` → 全部为假的格转红。
#[test]
fn blocked_for_generation_truth_table_mesh_exit_falls_back() {
    // WireGuard `allowInternet` 三态（缺省 = true = 承载全隧道）。
    assert!(
        !auto_switch_blocked_for_generation(&cfg_with_selected(wg_node(
            None,
            None,
            &["10.9.0.0/24"]
        ))),
        "WG allowInternet 缺省落 true，承载全隧道 → 不停摆"
    );
    assert!(!auto_switch_blocked_for_generation(&cfg_with_selected(
        wg_node(Some(true), None, &["10.9.0.0/24"])
    )));
    assert!(
        auto_switch_blocked_for_generation(&cfg_with_selected(wg_node(
            Some(false),
            None,
            &["10.9.0.0/24"]
        ))),
        "WG 关外网 = 只走内网 → 本世代不判不切"
    );

    // Tailscale：`allowInternet` 由 `exitNode` 派生 —— 空 / 全空格 / 非空。
    assert!(
        auto_switch_blocked_for_generation(&cfg_with_selected(ts_node(None, None))),
        "TS 未选 exit node → 无公网出口"
    );
    assert!(auto_switch_blocked_for_generation(&cfg_with_selected(
        ts_node(Some(""), None)
    )));
    assert!(
        auto_switch_blocked_for_generation(&cfg_with_selected(ts_node(Some("   "), None))),
        "全空格必须与空串同判（`trim().is_empty()`；漏 trim 会让停摆守卫被一个空格绕过）"
    );
    assert!(
        !auto_switch_blocked_for_generation(&cfg_with_selected(ts_node(Some("exit-1"), None))),
        "TS 选了 exit node → 有公网出口，自动切换照常工作"
    );

    // WARP：`mesh_allows_internet` 对它恒真短路（anycast 云出口），即便显式写了 allowInternet=false。
    assert!(
        !auto_switch_blocked_for_generation(&cfg_with_selected(warp_node(Some(false)))),
        "WARP 恒是云出口，不得因 allowInternet=false 被判成只走内网"
    );

    // OpenVPN：`redirectGateway` × `meshRoutes` 四格（组网资格由 meshRoutes 决定）。
    assert!(
        auto_switch_blocked_for_generation(&cfg_with_selected(ovpn_node(
            Some(false),
            &["10.1.0.0/24"]
        ))),
        "OpenVPN 组网节点显式关 redirectGateway = 只走公司内网 → 停摆（Fix 0 扩面新进的一格）"
    );
    assert!(
        !auto_switch_blocked_for_generation(&cfg_with_selected(ovpn_node(Some(false), &[]))),
        "没填 meshRoutes 就不是组网节点，只是个普通出口 → 不停摆"
    );
    assert!(!auto_switch_blocked_for_generation(&cfg_with_selected(
        ovpn_node(Some(true), &["10.1.0.0/24"])
    )));
    assert!(!auto_switch_blocked_for_generation(&cfg_with_selected(
        ovpn_node(Some(true), &[])
    )));
    assert!(
        !auto_switch_blocked_for_generation(&cfg_with_selected(ovpn_node(None, &["10.1.0.0/24"]))),
        "redirectGateway 缺省落 true（承载全隧道）→ 不停摆"
    );

    // 普通协议：连组网资格都没有，压根不进本判据（回归保护）。
    assert!(!auto_switch_blocked_for_generation(&cfg_with_selected(
        ss_node()
    )));
}

/// **本批回归的锁：承载公网的组网节点不得被判停摆**。
///
/// 2026-09 一度把 `config-engine` 的 `sel_only_forces_subnets`（组网资格 ×
/// `alwaysRouteSubnets=false` × 段非空）当作第二条停摆原因。那三项里**没有** `allow_internet`，
/// 于是下面第一格（`allowInternet=true` + `alwaysRouteSubnets=false` + 有段）会命中它 —— 而它是
/// 承载公网的全隧道节点，隧道死了用户就断网，心跳探针探的正是用户在走的那条路。把它整条心跳
/// 静音 = 亲手造出本批要消灭的盲区（不探 ⇒ 不上报 ⇒ 前端总门也判无异常，三面静默）。
///
/// 第二格是**反向对照**：同形态只翻 `allowInternet`，那才是真该停摆的一格。没有它，本条门可以被
/// 一个恒 `false` 的判据满足（那就是「门在但没牙」）。
#[test]
fn public_carrying_mesh_node_is_never_blocked() {
    assert!(
        !auto_switch_blocked_for_generation(&cfg_with_selected(wg_node(
            Some(true),
            Some(false),
            &["10.9.0.0/24"]
        ))),
        "承载公网的组网节点必须照常心跳：段规则切不过去是**热切可行性**问题，不是「探针无意义」"
    );
    assert!(
        auto_switch_blocked_for_generation(&cfg_with_selected(wg_node(
            Some(false),
            Some(false),
            &["10.9.0.0/24"]
        ))),
        "同形态只翻 allowInternet → 真停摆（正向对照，防判据恒 false 也能过）"
    );
}

/// **选中不是一个真实节点时不得停摆**：`__direct__` 哨兵 / 选中 id 不在 `servers` / 无选中。
///
/// 这三种形态由心跳自己的 `selected_server_is_real` 那条腿处理（[`SkipReason::SelectionNotReal`]），
/// 不该被停摆守卫抢答 —— 抢答会把两条语义不同的跳过（复位 / 不复位失败计数）混成一条。
#[test]
fn not_blocked_when_selection_is_not_a_real_node() {
    // `__direct__` 哨兵：不在 servers，谓词解不到节点。
    let direct = UserConfig {
        selected_server_id: Some(DIRECT_SERVER_ID.into()),
        servers: vec![wg_node(Some(false), Some(false), &["10.9.0.0/24"])],
        ..Default::default()
    };
    assert!(!auto_switch_blocked_for_generation(&direct));

    // 选中 id 不存在（节点已被删）。
    let ghost = UserConfig {
        selected_server_id: Some("ghost".into()),
        servers: vec![wg_node(Some(false), Some(false), &["10.9.0.0/24"])],
        ..Default::default()
    };
    assert!(!auto_switch_blocked_for_generation(&ghost));

    // 无选中。
    let none_sel = UserConfig {
        selected_server_id: None,
        servers: vec![wg_node(Some(false), Some(false), &["10.9.0.0/24"])],
        ..Default::default()
    };
    assert!(!auto_switch_blocked_for_generation(&none_sel));
}

// ══════════════════════════════════════════════════════════════════════════════
// 每 tick 决策（`decide_tick`）真值表
//
// 心跳体是 `tokio::spawn` + 30s sleep，任何测试都驱动不了它 —— 分支裁决抽成纯函数正是为了让
// 「删掉某条守卫必须有测试转红」这件事在本模块重新可达。
// ══════════════════════════════════════════════════════════════════════════════

/// 一切通畅（会去探测）的基线输入；各用例只翻一个字段。
fn clear_tick() -> TickInput {
    TickInput {
        enabled: true,
        switching: false,
        core_running: true,
        selected_server_is_real: true,
        generation_blocked: false,
        probe_proxy_port: Some(7891),
    }
}

/// 基线必须真的会去探测 —— 否则下面每条负例都因为「本来就不探」而恒绿（正向对照）。
#[test]
fn decide_tick_probes_when_everything_is_clear() {
    assert_eq!(
        decide_tick(clear_tick()),
        TickAction::Probe {
            probe_proxy_port: 7891
        }
    );
}

/// **每条腿逐一翻转的真值表**，且把「复位 / 不复位失败计数」当成结论的一部分断言。
///
/// 这两类跳过的分界正是本模块出过的那类缺陷：不复位会让停摆/中断期间的陈旧计数活到恢复之后，
/// 一次失败即达阈值触发换节点。只断言「跳过了」而不断言「复不复位」，等于门在但没牙。
#[test]
fn decide_tick_truth_table_per_leg() {
    let cases: &[(&str, TickInput, TickAction)] = &[
        (
            "关闭 → 跳过，不复位",
            TickInput {
                enabled: false,
                ..clear_tick()
            },
            TickAction::Skip(SkipReason::Disabled),
        ),
        (
            "换节点在飞 → 跳过，不复位",
            TickInput {
                switching: true,
                ..clear_tick()
            },
            TickAction::Skip(SkipReason::Switching),
        ),
        (
            "核未运行 → 跳过，**复位**",
            TickInput {
                core_running: false,
                ..clear_tick()
            },
            TickAction::SkipAfterResettingFailures(SkipReason::CoreNotRunning),
        ),
        (
            "选中不是真实节点 → 跳过，不复位（姊妹腿，见 decide_tick 文档）",
            TickInput {
                selected_server_is_real: false,
                ..clear_tick()
            },
            TickAction::Skip(SkipReason::SelectionNotReal),
        ),
        (
            "本世代停摆 → 跳过，**复位**（对齐 NoProbePort / CoreNotRunning）",
            TickInput {
                generation_blocked: true,
                ..clear_tick()
            },
            TickAction::SkipAfterResettingFailures(SkipReason::GenerationBlocked),
        ),
        (
            "探针端口未分配 → 跳过，**复位**",
            TickInput {
                probe_proxy_port: None,
                ..clear_tick()
            },
            TickAction::SkipAfterResettingFailures(SkipReason::NoProbePort),
        ),
    ];
    for (label, input, expected) in cases {
        assert_eq!(decide_tick(*input), *expected, "{label}");
    }
}

/// **停摆守卫的位置**：它必须落在 `selected_server_is_real` **之后**、端口解构**之前**。
///
/// 两侧各钉一条：
///  - 与 `SelectionNotReal` 同时成立 → 报 `SelectionNotReal`（守卫没被提前到前面去，
///    否则 `__direct__` 期间的跳过会从「不复位」变成「复位」，悄悄改掉那条姊妹腿的语义）；
///  - 与 `NoProbePort` 同时成立 → 报 `GenerationBlocked`（守卫确实在端口解构之前，
///    否则端口没分配的世代里停摆原因永远显不出来）。
#[test]
fn decide_tick_generation_block_sits_between_selection_and_port() {
    assert_eq!(
        decide_tick(TickInput {
            selected_server_is_real: false,
            generation_blocked: true,
            ..clear_tick()
        }),
        TickAction::Skip(SkipReason::SelectionNotReal)
    );
    assert_eq!(
        decide_tick(TickInput {
            generation_blocked: true,
            probe_proxy_port: None,
            ..clear_tick()
        }),
        TickAction::SkipAfterResettingFailures(SkipReason::GenerationBlocked)
    );
}

/// 前四道守卫的相对优先级（逐字保持抽纯函数前那串 `if … continue` 的书写顺序）。
/// 变异锁：调换 `decide_tick` 里任意两道守卫的先后 → 对应一条转红。
#[test]
fn decide_tick_guard_precedence_is_unchanged() {
    // 全部条件同时不利 → 报最靠前的那条。
    let all_bad = TickInput {
        enabled: false,
        switching: true,
        core_running: false,
        selected_server_is_real: false,
        generation_blocked: true,
        probe_proxy_port: None,
    };
    assert_eq!(
        decide_tick(all_bad),
        TickAction::Skip(SkipReason::Disabled),
        "关闭优先于一切"
    );
    assert_eq!(
        decide_tick(TickInput {
            enabled: true,
            ..all_bad
        }),
        TickAction::Skip(SkipReason::Switching),
        "在飞优先于核状态"
    );
    assert_eq!(
        decide_tick(TickInput {
            enabled: true,
            switching: false,
            ..all_bad
        }),
        TickAction::SkipAfterResettingFailures(SkipReason::CoreNotRunning),
        "核未运行优先于选中真实性"
    );
}

// ── 「候选全被『切过去要整核重启』剔光」的上报判据与每世代锁存 ──

/// `do_switch_io` 的签名锚点（下面两条接线门共用）。改名 ⇒ 两门齐红，而不是静默放行。
const DO_SWITCH_IO: &str = "    async fn do_switch_io(self: &Arc<Self>, \
                            machine: &mut AutoSwitchMachine, reason: &str) -> bool {";

/// 造一份候选规划：`candidates` 条候选 + `needs_restart` + 其余五个排除计数各 `others`。
fn restart_plan(candidates: usize, needs_restart: usize, others: usize) -> RuntimeCandidatePlan {
    RuntimeCandidatePlan {
        candidates: (0..candidates)
            .map(|i| RuntimeCandidate {
                id: format!("n{i}"),
                name: format!("节点{i}"),
                tag: format!("tag{i}"),
            })
            .collect(),
        staged: others,
        not_loaded: others,
        dirty: others,
        not_ready: others,
        not_exit: others,
        needs_restart,
    }
}

/// **判据真值表**：`candidates` 空/非空 × `needs_restart` >0/==0 × 其余五因 >0/==0 的全部组合。
///
/// 唯一为真的一格是「候选空 **且** needs_restart>0」——自动切换真的触发了、候选也规划出来了，
/// 却每一个都因为「切过去要整核重启」被剔光 ⇒ 故障切换实际什么也没做，而用户完全无感。
/// 其余各格为假的理由见 [`switch_blocked_by_restart`] 文档。
///
/// **变异锁**：
/// - 删掉判据里的 `&& plan.needs_restart > 0` ⇒ ③④ 转红（那正是「用户刚编辑过节点草稿」
///   被误报成故障的形态）；
/// - 删掉 `plan.candidates.is_empty()` ⇒ ⑤⑦ 转红（还有候选就报，等于把正常轮报成故障）。
#[test]
fn switch_blocked_by_restart_truth_table() {
    for (candidates, needs_restart, others, want, why) in [
        (0, 1, 0, true, "① 唯一该报的一格"),
        (
            0,
            2,
            3,
            true,
            "② 需重启与其它因同时为正：只要有节点是被重启挡住的，那条可行动的路就真实存在",
        ),
        (
            0,
            0,
            3,
            false,
            "③ 候选空但成因全是草稿/未入核/参数脏/未就绪/不可作出口 —— 都不是「系统帮不上忙」，不报",
        ),
        (
            0,
            0,
            0,
            false,
            "④ 压根没有别的节点（单节点配置）—— 无事可报",
        ),
        (
            1,
            1,
            0,
            false,
            "⑤ 还剩候选 ⇒ 本轮真去探了，成败由后面的腿说话，与本判据无关",
        ),
        (1, 0, 0, false, "⑥ 正常轮"),
        (
            2,
            3,
            1,
            false,
            "⑦ 剔掉了几个但还剩候选 ⇒ 不是「什么也没做」",
        ),
        (1, 0, 5, false, "⑧ 其余因很多但仍有候选"),
    ] {
        assert_eq!(
            switch_blocked_by_restart(&restart_plan(candidates, needs_restart, others)),
            want,
            "{why}（候选={candidates} 需重启={needs_restart} 其余各={others}）"
        );
    }
}

/// **锁存真值表**：同一世代最多认领一次上报权；新世代（新实例）恢复可报。
///
/// 触发面每约 90 秒（3 次心跳失败 → 触发 → 候选被剔光）就原样复现一次，而 `set_nonfatal_error`
/// 每次落值都 `log::error` + emit `event:proxyError` ⇒ 不锁存 = 用户每 90 秒吃一次 toast +
/// 桌面通知，而事实一条都没变。
///
/// **变异锁**：把 [`AutoSwitchMachine::claim_restart_blocked_report`] 的早退删掉（恒返 `true`）
/// ⇒ 第二、三条断言转红。
#[test]
fn restart_blocked_report_claims_once_per_generation() {
    let mut m = AutoSwitchMachine::new();
    m.enable();
    assert!(m.claim_restart_blocked_report(), "本世代第一次必须报");
    assert!(!m.claim_restart_blocked_report(), "同世代第二次不许再报");
    assert!(!m.claim_restart_blocked_report(), "第三次同理");

    // 新世代 = 新实例：`spawn_auto_switch_heartbeat` 每次起核都 `AutoSwitchMachine::new()`，
    // 故复位不需要任何显式代码。
    let mut next_generation = AutoSwitchMachine::new();
    next_generation.enable();
    assert!(
        next_generation.claim_restart_blocked_report(),
        "核重启换世代后必须恢复可报 —— 那时运行核换了一份配置，结论可能已经不一样"
    );
}

/// 运行期开关切换（用户在设置里把自动换节点关了又开）**不是**新世代，故不复位锁存。
///
/// [`AutoSwitchMachine::enable`] 会复位失败计数与熔断计数，本位刻意不在其中：跟着复位等于给
/// 「关一下再开」留了一条重复报警的路，而运行核那一份配置根本没变。
///
/// **变异锁**：在 `enable()` 里补一句 `self.restart_blocked_reported = false;` ⇒ 本条转红。
#[test]
fn restart_blocked_report_latch_is_not_reset_by_disable_enable() {
    let mut m = AutoSwitchMachine::new();
    m.enable();
    assert!(m.claim_restart_blocked_report());
    m.disable();
    m.enable();
    assert!(
        !m.claim_restart_blocked_report(),
        "关了再开不是新世代，不许重复报"
    );
}

/// **接线门**（源码型）：判据 + 锁存 + 上报三者必须真的接在 `do_switch_io` 的「候选为空」早退上。
///
/// # 为什么必须是源码型
///
/// 上面两条真值表锁的是纯逻辑。纯逻辑全绿而**没人调**，用户侧一条都收不到，且那两条照样全绿
/// ——「门在但没牙」。能证明接线的行为门要真起核 + 真碰宿主网络（`do_switch_io` 全程 I/O），
/// 那是真机门的射程，本机跑不了；故此处锁调用点。
///
/// 三条断言各挡一种改法：
///  1. **判据没了** —— 被就地展开成 `candidates.is_empty()`，于是草稿/未入核也报；
///  2. **锁存没了** —— 每约 90 秒重发一次；
///  3. **顺序反了** —— 先认领上报权、再判该不该报，任意一次候选为空的早退都会吃掉本世代唯一那次
///     上报权，真该报的那轮反而静默。这一条纯逻辑侧看不见，只有调用点看得见。
///
/// 取材经 `module_code` **剥注释**（本注释与被守代码的注释里都逐字写着这些锚点，不剥就是让注释
/// 替生产调用点作证），并用 `impl_method_body` 封顶在 `do_switch_io` 自己的方法体内
/// （切到 EOF 会命中后文同名调用）。
///
/// # 射程自曝
///
/// 只证明「这三样按此顺序出现在这个方法体里」，不证明它们在同一个 `if` 条件上、也不证明运行期
/// 真发得出事件。前者靠 review，后者靠真机门。
#[test]
fn auto_switch_needs_restart_report_is_wired_into_do_switch_io() {
    let body = crate::commands::guard_scan::impl_method_body(
        &crate::test_support::module_code("runtime/proxy"),
        DO_SWITCH_IO,
    );
    let criterion = body
        .find("switch_blocked_by_restart(&candidate_plan)")
        .expect(
            "① 判据没接上：候选为空的早退必须问一句 `switch_blocked_by_restart(&candidate_plan)`。\
             就地展开成 `candidates.is_empty()` 会把「用户刚编辑过节点草稿」也报成故障。",
        );
    let latch = body.find("machine.claim_restart_blocked_report()").expect(
        "② 锁存没接上：`status.error` 是单槽覆盖且每次落值都 emit，不锁存就是每约 90 秒\
         一次 toast + 桌面通知。",
    );
    assert!(
        body.contains("code::AUTO_SWITCH_NEEDS_RESTART"),
        "③ 上报没接上：判据与锁存都在，却没把码落进 `set_nonfatal_error` —— 用户侧仍是静默。"
    );
    assert!(
        criterion < latch,
        "判据必须写在认领上报权**之前**（`&&` 左短路）：反过来会让任意一次候选为空的早退吃掉\
         本世代唯一那次上报权，真该报的那轮反而静默 —— 那是把锁存装反。"
    );
}

/// **接线门②**（源码型）：候选**还剩几个、但探测全败**的早退也必须上报，且与「候选被剃光」那条
/// 共用同一个码、同一份文案、同一个每世代锁存。
///
/// # 为什么这条腿必须报
///
/// 用户的可行动性与「候选被剃光」**完全相同**：有 `needs_restart` 个节点本来能救场，只是被切换门
/// 挡在探测之外，而他无从得知。原本这里只 `warn!` 一行 —— 日志不在用户面前，等于那些节点对他
/// 不存在。判据仍只有 `needs_restart > 0` 一项，故「探测全败」本身不会多报一条（那件事用户下不了
/// 手，只该进日志）。
///
/// # 为什么必须是源码型
///
/// 同 [`auto_switch_needs_restart_report_is_wired_into_do_switch_io`]：`do_switch_io` 全程 I/O
/// （真起核 + 真管理面 + 真探测池），本机跑不了。故此处锁四个可静态判定的属性：两个上报点、
/// 同一个码、同一个锁存、第二个确实落在探测早退**之后**。
///
/// # 射程自曝
///
/// 不证明运行期真发得出事件（真机门），也不证明两处的 `if` 条件在语义上等价 —— 后者由
/// [`switch_blocked_by_restart`] 的真值表与本门断言的 `needs_restart > 0` 各自守住。
#[test]
fn probe_all_failed_early_exit_reports_with_the_same_code_and_latch() {
    let body = crate::commands::guard_scan::impl_method_body(
        &crate::test_support::module_code("runtime/proxy"),
        DO_SWITCH_IO,
    );
    assert_eq!(
        body.matches("code::AUTO_SWITCH_NEEDS_RESTART").count(),
        2,
        "两个上报点缺一不可：候选被剃光 + 候选还剩但探测全败",
    );
    assert_eq!(
        body.matches("machine.claim_restart_blocked_report()")
            .count(),
        2,
        "两处必须共用同一个每世代锁存 —— 各开一个位 = 同一个世代能报两次",
    );
    assert_eq!(
        body.matches("RESTART_BLOCKED_MESSAGE").count(),
        2,
        "两处共用同一份文案常量，防措辞漂移（一处说得对、另一处还留着「或重启代理」这种空操作建议）",
    );
    let probe_exit = body
        .find("select_best_candidate(&measured)")
        .expect("探测早退锚点：本门若因改名找不到它，必须转红而不是静默放行");
    let tail = &body[probe_exit..];
    assert!(
        tail.contains("candidate_plan.needs_restart > 0")
            && tail.contains("machine.claim_restart_blocked_report()")
            && tail.contains("code::AUTO_SWITCH_NEEDS_RESTART"),
        "探测全败的早退必须带上报：判据 `needs_restart > 0` + 同一个锁存 + 同一个码",
    );
}
