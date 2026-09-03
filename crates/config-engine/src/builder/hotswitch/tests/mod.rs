use super::*;
use crate::user_config::app_config::{SubscriptionInterfacePolicy, UserConfig};
use crate::user_config::proxy_mode::{ProxyMode, ProxyModeType};
use crate::user_config::rule::{Rule, RuleAction, RuleEffects, RuleRouteEffect, RuleType};
use crate::user_config::server_config::{Protocol, ServerConfig, WireGuardSettings};
use crate::user_config::tun_config::TunModeConfig;
use crate::user_config::tun_stack::TunStack;

const NODE_A: &str = "node-a";
const NODE_B: &str = "node-b";

fn ss(id: &str, addr: &str) -> ServerConfig {
    ServerConfig {
        id: id.into(),
        name: id.into(),
        protocol: Protocol::Shadowsocks,
        address: addr.into(),
        port: 8388,
        ..Default::default()
    }
}

fn ss_extra(id: &str, addr: &str, port: u16) -> ServerConfig {
    ServerConfig {
        port,
        ..ss(id, addr)
    }
}

fn wg(id: &str, allow_internet: Option<bool>, always_route: Option<bool>) -> ServerConfig {
    ServerConfig {
        id: id.into(),
        name: id.into(),
        protocol: Protocol::Wireguard,
        wireguard_settings: Some(Box::new(WireGuardSettings {
            allow_internet,
            always_route_subnets: always_route,
            allowed_ips: vec!["10.9.0.0/24".into()],
            ..Default::default()
        })),
        ..Default::default()
    }
}

fn ext_rule(id: &str, target: Option<&str>) -> Rule {
    Rule {
        id: id.into(),
        type_field: RuleType::DomainSuffix,
        values: vec!["example.com".into()],
        conditions: None,
        combine_mode: None,
        effects: None,
        action: RuleAction::Proxy,
        enabled: true,
        bypass_fakeip: None,
        target_server_id: target.map(String::from),
        remarks: None,
        tls_spoof: None,
        tls_spoof_method: None,
    }
}

fn first_class_ext_rule(id: &str, target: &str) -> Rule {
    Rule {
        effects: Some(RuleEffects {
            route: Some(RuleRouteEffect {
                enabled: true,
                action: RuleAction::Proxy,
                target_server_id: Some(target.into()),
                destination_resolution: None,
                resolution_only: false,
            }),
            dns: None,
        }),
        ..ext_rule(id, None)
    }
}

/// 基础 smart config：两节点(A/B) + selectedServerId=A + systemProxy。
fn base_config() -> UserConfig {
    UserConfig {
        servers: vec![ss(NODE_A, "1.1.1.1"), ss(NODE_B, "2.2.2.2")],
        selected_server_id: Some(NODE_A.into()),
        proxy_mode: ProxyMode::Smart,
        proxy_mode_type: ProxyModeType::SystemProxy,
        custom_rules: vec![],
        app_rules: vec![],
        ..Default::default()
    }
}

fn deps_with_tags() -> HotSwitchDeps {
    let mut map = BTreeMap::new();
    map.insert(NODE_A.into(), "tagA".into());
    map.insert(NODE_B.into(), "tagB".into());
    HotSwitchDeps {
        current_id_to_tag_map: Some(map),
        ..Default::default()
    }
}

// === resolveGlobalExitTag ===

#[test]
fn resolve_global_exit_tag_direct_sentinel() {
    assert_eq!(
        resolve_global_exit_tag(Some("__direct__"), None),
        Some("direct".into())
    );
}

/// 阻断哨兵 → block tag（不依赖 idToTagMap，同 direct）。
///
/// 变异锁：删掉 `is_block_selection` 那条早返回 → 落到 map 查询 → None → 转红。
#[test]
fn resolve_global_exit_tag_block_sentinel() {
    // 阻断不再是一个出站 ⇒ 没有成员 tag 可解析。返回 None 是**正确的退化**：
    // 目标侧 None ⇒ 整核重启；旧出口侧 None ⇒ 跳过精准断连（而进出阻断本就走重启）。
    assert_eq!(
        resolve_global_exit_tag(Some("__block__"), None),
        None,
        "阻断已改由规则级 reject 表达；若这里又能解析出 tag，说明 block 出站被复活了"
    );
}

/// 【切入阻断退回重启】block 尚未进运行核的 selector ⇒ planHotSwitch 必须给空计划（= 整核重启），
/// 绝不能 PUT 到一个不存在的成员（核返 NotFound → executor 判 Failed → 静默退回重启，
/// 用户看到「切换成功」而热切永久失效）。
///
/// 变异锁：给 hotswitch 的成员校验加一条 block 豁免（仿 `to_direct`）→ 本用例转红。
#[test]
fn switch_into_block_falls_back_to_restart() {
    let old = base_config();
    let mut new = old.clone();
    new.selected_server_id = Some("__block__".into());
    let plan = plan_hot_switch(&old, &new, &deps_with_tags());
    assert!(
        plan.puts.is_empty(),
        "切入阻断必须退回重启，不得 PUT 到非成员：{:?}",
        plan.puts
    );
}

/// 【切出阻断可热切】运行核的 selector 是带 block 成员生成的、目标节点也在其中 ⇒ 可热切，
/// 且 old_member_tag 须解析成 block（供精准断连那一对）。
#[test]
fn switch_out_of_block_falls_back_to_restart() {
    // 【行为变更 2026-08-13，如实钉住】此前切出阻断是**热切**（block 是 selector 成员）。
    // 阻断改由规则级 reject 表达之后，进出阻断都动 route 规则集，而热切换只能 PUT 一个
    // selector 的 default ⇒ 表达不了 ⇒ 两个方向都必须整核重启。
    //
    // 这是那次迁移唯一的行为代价：会断掉阻断期间仍活着的直连连接。换到的是「阻断态不再
    // 每拦一条连接打一行 ERROR 把核日志历史挤掉」。
    let mut old = base_config();
    old.selected_server_id = Some("__block__".into());
    let mut new = old.clone();
    new.selected_server_id = Some(NODE_A.into());
    let plan = plan_hot_switch(&old, &new, &deps_with_tags());
    assert!(
        plan.puts.is_empty(),
        "切出阻断必须退回整核重启（规则集变了，PUT selector default 表达不了）：{:?}",
        plan.puts
    );
}

#[test]
fn resolve_global_exit_tag_node_via_map() {
    let mut map = BTreeMap::new();
    map.insert("n1".into(), "tagN1".into());
    assert_eq!(
        resolve_global_exit_tag(Some("n1"), Some(&map)),
        Some("tagN1".into())
    );
}

#[test]
fn resolve_global_exit_tag_unknown_node_none() {
    let map = BTreeMap::new();
    assert_eq!(resolve_global_exit_tag(Some("ghost"), Some(&map)), None);
}

#[test]
fn resolve_global_exit_tag_none_when_no_id() {
    assert_eq!(resolve_global_exit_tag(None, None), None);
}

// === planHotSwitch 全局节点切换 ===

#[test]
fn plan_global_switch_a_to_b() {
    let old = base_config();
    let mut new_cfg = base_config();
    new_cfg.selected_server_id = Some(NODE_B.into());
    let plan = plan_hot_switch(&old, &new_cfg, &deps_with_tags());
    assert_eq!(plan.kind, HotSwitchKind::Global);
    assert_eq!(
        plan.puts,
        vec![HotSwitchPut {
            selector_tag: "proxy-selector".into(),
            member_tag: "tagB".into(),
            old_member_tag: Some("tagA".into()),
        }]
    );
    assert!(!plan.must_restart);
}

#[test]
fn subscription_interface_difference_does_not_turn_selection_into_restart() {
    let mut old = base_config();
    old.servers[0].subscription_id = Some("sub-a".into());
    old.servers[1].subscription_id = Some("sub-b".into());
    old.subscriptions = vec![
        SubscriptionInterfacePolicy {
            id: "sub-a".into(),
            proxy_bind_interface: Some("en0".into()),
        },
        SubscriptionInterfacePolicy {
            id: "sub-b".into(),
            proxy_bind_interface: Some("en7".into()),
        },
    ];
    let mut new = old.clone();
    new.selected_server_id = Some(NODE_B.into());

    let plan = plan_hot_switch(&old, &new, &deps_with_tags());
    assert_eq!(plan.kind, HotSwitchKind::Global);
    assert_eq!(plan.puts.len(), 1);
    assert_eq!(plan.puts[0].member_tag, "tagB");
    assert!(
        !plan.must_restart,
        "两个出站的 bind_interface 已在起核时固化；切 selector 不应重启"
    );
}

#[test]
fn plan_global_switch_to_direct() {
    let old = base_config();
    let mut new_cfg = base_config();
    new_cfg.selected_server_id = Some("__direct__".into());
    let plan = plan_hot_switch(&old, &new_cfg, &deps_with_tags());
    assert_eq!(plan.kind, HotSwitchKind::Global);
    assert_eq!(plan.puts[0].member_tag, "direct");
    assert!(!plan.must_restart);
}

#[test]
fn plan_global_switch_no_norm_change_is_none() {
    // norm 不等（结构变）→ none。
    let old = base_config();
    let mut new_cfg = base_config();
    new_cfg.proxy_mode = ProxyMode::Global; // norm 翻转
    new_cfg.selected_server_id = Some(NODE_B.into());
    let plan = plan_hot_switch(&old, &new_cfg, &deps_with_tags());
    assert_eq!(plan.kind, HotSwitchKind::None);
    assert!(plan.puts.is_empty());
    assert!(!plan.must_restart);
}

#[test]
fn plan_global_switch_target_added_node_flips_norm_none() {
    // 目标节点不在 old.servers（新增未入核）→ 但加节点本身翻转 norm（servers 集合变）→
    //   norm 前提失败先于「目标不在 selector」闸门 → none（非 mustRestart）。
    // 注：纯 config 视角下「目标不在运行 selector」无法与「norm 翻转」分离——新增节点必改 servers 集合。
    //   该闸门在 Polaris 运行态才有独立意义（currentIdToTagMap 与 servers 集合解耦）。unknown_tag 用例覆盖 idToTagMap 缺失路径。
    let old = base_config();
    let mut new_cfg = base_config();
    new_cfg.servers.push(ss("ghost", "9.9.9.9"));
    new_cfg.selected_server_id = Some("ghost".into());
    let mut deps = deps_with_tags();
    deps.current_id_to_tag_map
        .as_mut()
        .unwrap()
        .insert("ghost".into(), "tagGhost".into());
    let plan = plan_hot_switch(&old, &new_cfg, &deps);
    assert_eq!(plan.kind, HotSwitchKind::None);
    assert!(plan.puts.is_empty());
    assert!(!plan.must_restart);
}

#[test]
fn plan_global_switch_unknown_target_tag_none() {
    // 目标 tag 解析不到（idToTagMap 无此 id）→ none。
    let old = base_config();
    let mut new_cfg = base_config();
    new_cfg.selected_server_id = Some(NODE_B.into());
    // idToTagMap 无 B → resolve 返 None → none。
    let mut map = BTreeMap::new();
    map.insert(NODE_A.into(), "tagA".into());
    let deps = HotSwitchDeps {
        current_id_to_tag_map: Some(map),
        ..Default::default()
    };
    let plan = plan_hot_switch(&old, &new_cfg, &deps);
    assert_eq!(plan.kind, HotSwitchKind::None);
    assert!(plan.puts.is_empty());
}

#[test]
fn plan_global_switch_bootstrap_fallback_old_tag_is_direct() {
    let old = base_config();
    let mut new_cfg = base_config();
    new_cfg.selected_server_id = Some(NODE_B.into());
    let mut deps = deps_with_tags();
    deps.bootstrap_fallback_engaged = true; // 旧全局 tag = direct
    let plan = plan_hot_switch(&old, &new_cfg, &deps);
    assert_eq!(plan.kind, HotSwitchKind::Global);
    assert_eq!(plan.puts[0].old_member_tag.as_deref(), Some("direct"));
}

#[test]
fn plan_no_change_is_none() {
    // old===new（selectedServerId 同）+ 无规则变化 → none。
    let old = base_config();
    let new_cfg = base_config();
    let plan = plan_hot_switch(&old, &new_cfg, &deps_with_tags());
    assert_eq!(plan.kind, HotSwitchKind::None);
    assert!(plan.puts.is_empty());
    assert!(!plan.must_restart);
}

// === planHotSwitch TUN 端到端 ===

/// Windows 192.168.10.207 真机（2026-08-21）：本体 TUN + auto（实际 gVisor）下直接执行
/// `SelectOutbound`，Hk01-L7 → Hk01 → Hk01-L7 两次读回正确，sing-box PID 恒为 10684。
/// selector 切换属于管理面操作，不依赖 TUN stack；四种配置值都不得再触发平台式重启。
#[test]
fn plan_tun_stack_does_not_block_selector_hot_switch() {
    for (stack, label) in [
        (TunStack::Auto, "auto"),
        (TunStack::Gvisor, "gvisor"),
        (TunStack::Mixed, "mixed"),
        (TunStack::System, "system"),
    ] {
        let mut old = base_config();
        old.proxy_mode_type = ProxyModeType::Tun;
        old.tun_config = Some(TunModeConfig {
            stack,
            ..Default::default()
        });
        let mut new_cfg = old.clone();
        new_cfg.selected_server_id = Some(NODE_B.into());
        let plan = plan_hot_switch(&old, &new_cfg, &deps_with_tags());
        assert_eq!(plan.kind, HotSwitchKind::Global, "stack={label}");
        assert_eq!(plan.puts.len(), 1, "stack={label}");
        assert_eq!(plan.puts[0].member_tag, "tagB", "stack={label}");
    }
}

// === planHotSwitch route 投影 guard（mesh 退回 direct 翻转 / force-route engaged）===

#[test]
fn plan_full_tunnel_to_off_mesh_endpoint_none() {
    // 全隧道 endpoint → off-mesh endpoint：fallsBackToDirect 翻转 → none。
    let list = vec![
        wg("wg-full", Some(true), None),
        wg("wg-offmesh", Some(false), None),
    ];
    let mut old = base_config();
    old.servers = list.clone();
    old.selected_server_id = Some("wg-full".into());
    let mut new_cfg = old.clone();
    new_cfg.selected_server_id = Some("wg-offmesh".into());
    let mut deps = HotSwitchDeps::default();
    let mut map = BTreeMap::new();
    map.insert("wg-full".into(), "tag-wg-full".into());
    map.insert("wg-offmesh".into(), "tag-wg-offmesh".into());
    deps.current_id_to_tag_map = Some(map);
    let plan = plan_hot_switch(&old, &new_cfg, &deps);
    assert_eq!(plan.kind, HotSwitchKind::None);
}

#[test]
fn plan_full_tunnel_to_another_full_tunnel_global() {
    let list = vec![
        wg("wg-full", Some(true), None),
        wg("wg-full-2", Some(true), None),
    ];
    let mut old = base_config();
    old.servers = list.clone();
    old.selected_server_id = Some("wg-full".into());
    let mut new_cfg = old.clone();
    new_cfg.selected_server_id = Some("wg-full-2".into());
    let mut deps = HotSwitchDeps::default();
    let mut map = BTreeMap::new();
    map.insert("wg-full".into(), "tag-wg-full".into());
    map.insert("wg-full-2".into(), "tag-wg-full-2".into());
    deps.current_id_to_tag_map = Some(map);
    let plan = plan_hot_switch(&old, &new_cfg, &deps);
    assert_eq!(plan.kind, HotSwitchKind::Global);
    assert!(plan.puts.iter().any(|p| p.member_tag == "tag-wg-full-2"));
}

#[test]
fn plan_switch_to_force_route_only_endpoint_none() {
    // 切到 alwaysRouteSubnets=false 的 endpoint（force-route 段随选中翻转）→ none。
    let list = vec![
        wg("wg-full", Some(true), None),
        wg("wg-onlysub", Some(true), Some(false)),
    ];
    let mut old = base_config();
    old.servers = list.clone();
    old.selected_server_id = Some("wg-full".into());
    let mut new_cfg = old.clone();
    new_cfg.selected_server_id = Some("wg-onlysub".into());
    let mut deps = HotSwitchDeps::default();
    let mut map = BTreeMap::new();
    map.insert("wg-full".into(), "t1".into());
    map.insert("wg-onlysub".into(), "t2".into());
    deps.current_id_to_tag_map = Some(map);
    let plan = plan_hot_switch(&old, &new_cfg, &deps);
    assert_eq!(plan.kind, HotSwitchKind::None);
}

// === planHotSwitch dirty 闸门 ===

#[test]
fn plan_switch_to_dirty_node_none() {
    // 场景（对齐 Polaris p2a "§2 dirty 闸门"）：编辑步骤已提交 → currentConfig(old) 的 Z 已是 5.5.5.5；
    //   运行核快照(snap)仍是 9.9.9.9（编辑未生效）→ Z dirty。本步把选中 A→Z。
    // old/new servers 同（均 Z=5.5.5.5）→ norm 等价（selectedServerId 已出 norm）→ 进全局切换分支 →
    //   dirty 闸门：目标 Z dirty → none（退回重启，防热切到运行核旧参数成员）。
    let mut old = base_config();
    old.servers = vec![ss("A", "1.1.1.1"), ss("Z", "5.5.5.5")];
    old.selected_server_id = Some("A".into());
    let mut new_cfg = old.clone();
    new_cfg.selected_server_id = Some("Z".into()); // 仅切选中，servers 不变
    let mut deps = HotSwitchDeps::default();
    let mut map = BTreeMap::new();
    map.insert("A".into(), "tagA".into());
    map.insert("Z".into(), "tagZ".into());
    deps.current_id_to_tag_map = Some(map);
    // 快照起于旧参数 Z(9.9.9.9) → config Z(5.5.5.5) dirty。
    let mut snap = BTreeMap::new();
    snap.insert("A".into(), server_fingerprint(&ss("A", "1.1.1.1")));
    snap.insert("Z".into(), server_fingerprint(&ss("Z", "9.9.9.9")));
    deps.running_servers_fingerprint = Some(snap);
    let plan = plan_hot_switch(&old, &new_cfg, &deps);
    assert_eq!(plan.kind, HotSwitchKind::None);
    assert!(!plan.must_restart); // 全局 dirty 闸门走正常 none（非 mustRestart）
}

#[test]
fn plan_rule_target_to_dirty_node_must_restart() {
    // §2 F1：规则目标改到 dirty 节点 → mustRestart（防被 no-op/canSkip 吞）。
    // 场景（对齐 Polaris p2a F1）：编辑步骤已提交 → currentConfig(old) 的 Z 已是 5.5.5.5；
    //   运行核快照(snap)仍是 9.9.9.9（编辑未生效）→ Z dirty。本步把 r1 目标 A→Z。
    // old 与 new 的 servers 同（均 Z=5.5.5.5），仅 customRules.targetServerId 变（出 norm）→ norm 等价 →
    //   进 planRuleHotSwitch → 新目标 Z dirty → null → mustRestart（防 no-op/canSkip 腿吞静默不生效）。
    let r1_a = ext_rule("r1", Some("A"));
    let mut old = base_config();
    old.servers = vec![ss("A", "1.1.1.1"), ss("Z", "5.5.5.5")];
    old.selected_server_id = Some("A".into());
    old.custom_rules = vec![r1_a];
    let r1_z = ext_rule("r1", Some("Z"));
    let mut new_cfg = old.clone();
    new_cfg.custom_rules = vec![r1_z]; // 仅规则目标 A→Z，servers 不变
    let mut deps = HotSwitchDeps::default();
    let mut map = BTreeMap::new();
    map.insert("A".into(), "tagA".into());
    map.insert("Z".into(), "tagZ".into());
    deps.current_id_to_tag_map = Some(map);
    // 快照仍是旧参数 Z(9.9.9.9) → config Z(5.5.5.5) dirty。
    let mut snap = BTreeMap::new();
    snap.insert("A".into(), server_fingerprint(&ss("A", "1.1.1.1")));
    snap.insert("Z".into(), server_fingerprint(&ss("Z", "9.9.9.9")));
    deps.running_servers_fingerprint = Some(snap);
    let mut rtm = BTreeMap::new();
    rtm.insert(
        "custom:r1".into(),
        RuleTargetEntry {
            selector_tag: "rule-sel-r1".into(),
            member_tag: "tagA".into(),
        },
    );
    deps.current_rule_target_map = Some(rtm);
    let plan = plan_hot_switch(&old, &new_cfg, &deps);
    assert_eq!(plan.kind, HotSwitchKind::None);
    assert!(plan.must_restart);
}

// === planRuleHotSwitch（经 plan_hot_switch 端到端 + 直接断言行为）===

fn setup_rule_deps() -> (HotSwitchDeps, ()) {
    let mut map = BTreeMap::new();
    map.insert(NODE_A.into(), "tagA".into());
    map.insert(NODE_B.into(), "tagB".into());
    let mut rtm = BTreeMap::new();
    rtm.insert(
        "custom:r1".into(),
        RuleTargetEntry {
            selector_tag: "rule-sel-r1".into(),
            member_tag: "stub".into(),
        },
    );
    (
        HotSwitchDeps {
            current_id_to_tag_map: Some(map),
            current_rule_target_map: Some(rtm),
            ..Default::default()
        },
        (),
    )
}

#[test]
fn plan_rule_switch_a_to_b() {
    let (deps, _) = setup_rule_deps();
    let mut old = base_config();
    old.custom_rules = vec![ext_rule("r1", Some(NODE_A))];
    let mut new_cfg = old.clone();
    new_cfg.custom_rules = vec![ext_rule("r1", Some(NODE_B))];
    let plan = plan_hot_switch(&old, &new_cfg, &deps);
    assert_eq!(plan.kind, HotSwitchKind::Rules);
    assert_eq!(
        plan.puts,
        vec![HotSwitchPut {
            selector_tag: "rule-sel-r1".into(),
            member_tag: "tagB".into(),
            old_member_tag: Some("tagA".into()),
        }]
    );
}

#[test]
fn plan_rule_switch_uses_traffic_rules_as_authoritative_plane() {
    let (deps, _) = setup_rule_deps();
    let mut old = base_config();
    // legacy 镜像保持不变；真正变化只发生在一等 trafficRules。
    old.custom_rules = vec![ext_rule("legacy", Some(NODE_A))];
    old.traffic_rules = Some(vec![first_class_ext_rule("r1", NODE_A)]);
    let mut new_cfg = old.clone();
    new_cfg.traffic_rules = Some(vec![first_class_ext_rule("r1", NODE_B)]);

    let plan = plan_hot_switch(&old, &new_cfg, &deps);
    assert_eq!(plan.kind, HotSwitchKind::Rules);
    assert_eq!(plan.puts[0].selector_tag, "rule-sel-r1");
    assert_eq!(plan.puts[0].member_tag, "tagB");
}

#[test]
fn plan_rule_switch_node_to_default() {
    let (deps, _) = setup_rule_deps();
    let mut old = base_config();
    old.custom_rules = vec![ext_rule("r1", Some(NODE_A))];
    let mut new_cfg = old.clone();
    new_cfg.custom_rules = vec![ext_rule("r1", None)];
    let plan = plan_hot_switch(&old, &new_cfg, &deps);
    assert_eq!(plan.kind, HotSwitchKind::Rules);
    assert_eq!(plan.puts[0].member_tag, "proxy-selector");
    assert_eq!(plan.puts[0].old_member_tag.as_deref(), Some("tagA"));
}

#[test]
fn plan_rule_switch_default_to_node() {
    let (deps, _) = setup_rule_deps();
    let mut old = base_config();
    old.custom_rules = vec![ext_rule("r1", None)];
    let mut new_cfg = old.clone();
    new_cfg.custom_rules = vec![ext_rule("r1", Some(NODE_B))];
    let plan = plan_hot_switch(&old, &new_cfg, &deps);
    assert_eq!(plan.kind, HotSwitchKind::Rules);
    assert_eq!(plan.puts[0].member_tag, "tagB");
    assert_eq!(
        plan.puts[0].old_member_tag.as_deref(),
        Some("proxy-selector")
    );
}

#[test]
fn plan_rule_target_unknown_node_must_restart() {
    let (deps, _) = setup_rule_deps();
    let mut old = base_config();
    old.servers.push(ss("ghost-src", "4.4.4.4")); // 保持 servers 集合一致让 norm 等价
    old.custom_rules = vec![ext_rule("r1", Some(NODE_A))];
    let mut new_cfg = old.clone();
    new_cfg.custom_rules = vec![ext_rule("r1", Some("ghost"))]; // ghost 不在 idToTagMap
    let plan = plan_hot_switch(&old, &new_cfg, &deps);
    assert_eq!(plan.kind, HotSwitchKind::None);
    assert!(plan.must_restart);
}

#[test]
fn plan_rule_no_map_entry_skipped() {
    // currentRuleTargetMap 无 custom:r1 → 跳过（非 null/mustRestart）→ 无规则 puts。
    let (deps, _) = setup_rule_deps();
    let mut deps = deps;
    // 换成只有 r2 的 map
    deps.current_rule_target_map = Some(
        [(
            ("custom:r2".to_string()),
            RuleTargetEntry {
                selector_tag: "rule-sel-r2".into(),
                member_tag: "m".into(),
            },
        )]
        .into_iter()
        .collect(),
    );
    let mut old = base_config();
    old.custom_rules = vec![ext_rule("r1", Some(NODE_A))];
    let mut new_cfg = old.clone();
    new_cfg.custom_rules = vec![ext_rule("r1", Some(NODE_B))];
    let plan = plan_hot_switch(&old, &new_cfg, &deps);
    assert_eq!(plan.kind, HotSwitchKind::None); // 无 puts
    assert!(!plan.must_restart);
}

#[test]
fn plan_rule_no_id_to_tag_map_must_restart() {
    // currentIdToTagMap 未注入但 currentRuleTargetMap 有条目 → null → mustRestart。
    let mut rtm = BTreeMap::new();
    rtm.insert(
        "custom:r1".into(),
        RuleTargetEntry {
            selector_tag: "rule-sel-r1".into(),
            member_tag: "m".into(),
        },
    );
    let deps = HotSwitchDeps {
        current_id_to_tag_map: None,
        current_rule_target_map: Some(rtm),
        ..Default::default()
    };
    let mut old = base_config();
    old.custom_rules = vec![ext_rule("r1", Some(NODE_A))];
    let mut new_cfg = old.clone();
    new_cfg.custom_rules = vec![ext_rule("r1", Some(NODE_B))];
    let plan = plan_hot_switch(&old, &new_cfg, &deps);
    assert_eq!(plan.kind, HotSwitchKind::None);
    assert!(plan.must_restart);
}

#[test]
fn plan_rule_no_target_map_empty_puts() {
    // currentRuleTargetMap=None（启动无 rule-sel）→ 返空 Vec（非 null）→ 无规则 puts、非 mustRestart。
    let mut deps = deps_with_tags();
    deps.current_rule_target_map = None;
    let mut old = base_config();
    old.custom_rules = vec![ext_rule("r1", Some(NODE_A))];
    let mut new_cfg = old.clone();
    new_cfg.custom_rules = vec![ext_rule("r1", Some(NODE_B))];
    let plan = plan_hot_switch(&old, &new_cfg, &deps);
    assert_eq!(plan.kind, HotSwitchKind::None);
    assert!(!plan.must_restart);
}

#[test]
fn plan_rule_disabled_rule_skipped() {
    let (deps, _) = setup_rule_deps();
    let mut old = base_config();
    let mut r2 = ext_rule("r2", Some(NODE_A));
    r2.enabled = false;
    old.custom_rules = vec![ext_rule("r1", Some(NODE_A)), r2.clone()];
    let mut new_cfg = old.clone();
    new_cfg.custom_rules[0].target_server_id = Some(NODE_B.into()); // r1 变
    new_cfg.custom_rules[1].target_server_id = Some(NODE_B.into()); // r2 禁用，不参与
    let plan = plan_hot_switch(&old, &new_cfg, &deps);
    assert_eq!(plan.kind, HotSwitchKind::Rules);
    assert_eq!(plan.puts.len(), 1);
    assert_eq!(plan.puts[0].selector_tag, "rule-sel-r1");
}

#[test]
fn plan_both_global_and_rule_change() {
    // 全局 + 规则同时变 → kind=Both。
    let (deps, _) = setup_rule_deps();
    let mut old = base_config();
    old.custom_rules = vec![ext_rule("r1", Some(NODE_A))];
    let mut new_cfg = old.clone();
    new_cfg.selected_server_id = Some(NODE_B.into());
    new_cfg.custom_rules = vec![ext_rule("r1", Some(NODE_B))];
    let plan = plan_hot_switch(&old, &new_cfg, &deps);
    assert_eq!(plan.kind, HotSwitchKind::Both);
    assert_eq!(plan.puts.len(), 2);
}

#[test]
fn plan_rule_app_rule_switch() {
    // appRules 换节点 → PUT rule-sel-<appId>。
    use crate::user_config::rule::AppRule;
    let mut map = BTreeMap::new();
    map.insert(NODE_A.into(), "tagA".into());
    map.insert(NODE_B.into(), "tagB".into());
    let mut rtm = BTreeMap::new();
    rtm.insert(
        "app:app1".into(),
        RuleTargetEntry {
            selector_tag: "rule-sel-app1".into(),
            member_tag: "stub".into(),
        },
    );
    let deps = HotSwitchDeps {
        current_id_to_tag_map: Some(map),
        current_rule_target_map: Some(rtm),
        ..Default::default()
    };
    let mut old = base_config();
    old.app_rules = vec![AppRule {
        app_id: "app1".into(),
        action: RuleAction::Proxy,
        enabled: true,
        target_server_id: Some(NODE_A.into()),
    }];
    let mut new_cfg = old.clone();
    new_cfg.app_rules = vec![AppRule {
        app_id: "app1".into(),
        action: RuleAction::Proxy,
        enabled: true,
        target_server_id: Some(NODE_B.into()),
    }];
    let plan = plan_hot_switch(&old, &new_cfg, &deps);
    assert_eq!(plan.kind, HotSwitchKind::Rules);
    assert_eq!(
        plan.puts,
        vec![HotSwitchPut {
            selector_tag: "rule-sel-app1".into(),
            member_tag: "tagB".into(),
            old_member_tag: Some("tagA".into()),
        }]
    );
}

// === isServerDirty ===

#[test]
fn is_server_dirty_no_snapshot_false() {
    let cfg = base_config();
    let deps = HotSwitchDeps::default(); // 无快照
    assert!(!is_server_dirty(NODE_A, &cfg, &deps));
}

#[test]
fn is_server_dirty_not_in_snapshot_false() {
    let cfg = base_config();
    let mut deps = HotSwitchDeps::default();
    deps.running_servers_fingerprint = Some(BTreeMap::new()); // 空 → A 不在
    assert!(!is_server_dirty(NODE_A, &cfg, &deps));
}

#[test]
fn is_server_dirty_params_changed_true() {
    let cfg = base_config(); // A=1.1.1.1
    let mut deps = HotSwitchDeps::default();
    let mut snap = BTreeMap::new();
    snap.insert(NODE_A.into(), server_fingerprint(&ss(NODE_A, "8.8.8.8"))); // 快照是旧地址
    deps.running_servers_fingerprint = Some(snap);
    assert!(is_server_dirty(NODE_A, &cfg, &deps)); // 1.1.1.1 ≠ 8.8.8.8
}

#[test]
fn is_server_dirty_same_params_false() {
    let cfg = base_config();
    let mut deps = HotSwitchDeps::default();
    let mut snap = BTreeMap::new();
    snap.insert(NODE_A.into(), server_fingerprint(&ss(NODE_A, "1.1.1.1")));
    deps.running_servers_fingerprint = Some(snap);
    assert!(!is_server_dirty(NODE_A, &cfg, &deps));
}

// === canSkipRestartForAddedUnreferenced（四步守卫）===

fn snap_of(servers: &[ServerConfig]) -> BTreeMap<String, String> {
    servers
        .iter()
        .map(|s| (s.id.clone(), server_fingerprint(s)))
        .collect()
}

#[test]
fn can_skip_add_unreferenced_node_true() {
    let a = base_config(); // A 选中, B
    let mut b = base_config();
    b.servers.push(ss("Z", "9.9.9.9")); // 新增未引用 Z
    let snap = snap_of(&a.servers);
    assert!(can_skip_restart_for_added_unreferenced(&a, &b, &snap));
}

/// 新增一个 **openconnect / openvpn-client** 节点 ⇒ **不得** defer，必须重启。
///
/// 它们落 `endpoints[]`，无论有没有被选中/被规则指向都自成一条出网路径（内核起来就在跑），
/// 不是「只挂在 selector 上的惰性成员」。承流播种此前只认 WG/TS，这两个协议漏在外面 ——
/// 后果不是「少一次重启」而是**静默失效**：走 defer 腿不重启，核继续用旧配置，用户以为加上了。
///
/// 变异对照：把 `endpoint_routes.rs` 的播种判据改回 `is_mesh_protocol` ⇒ 本条转红。
#[test]
fn adding_an_endpoint_leg_vpn_client_forces_restart() {
    use crate::user_config::protocol_settings::OpenconnectSettings;
    use crate::user_config::server_config::Protocol;
    for proto in [Protocol::Openconnect, Protocol::OpenvpnClient] {
        let a = base_config();
        let mut b = base_config();
        b.servers.push(ServerConfig {
            id: "vpn".into(),
            name: "VPN".into(),
            protocol: proto,
            openconnect_settings: Some(Box::new(OpenconnectSettings {
                server: Some("vpn.example.com:443".into()),
                ..Default::default()
            })),
            ..Default::default()
        });
        let snap = snap_of(&a.servers);
        assert!(
            !can_skip_restart_for_added_unreferenced(&a, &b, &snap),
            "{proto:?} 新增被判成「未引用可 defer」—— 它是 endpoint 腿，核起来就在承流"
        );
    }
}

#[test]
fn can_skip_delete_unreferenced_node_true() {
    // P2-B：删未引用节点 → defer。
    let mut a = base_config();
    a.servers.push(ss("Z", "9.9.9.9"));
    let b = base_config(); // 删 Z
    let snap = snap_of(&a.servers);
    assert!(can_skip_restart_for_added_unreferenced(&a, &b, &snap));
}

#[test]
fn can_skip_edit_unreferenced_node_true() {
    // P2-B：改未引用节点 address → defer（dirty 闸门防热切到旧参数）。
    let mut a = base_config();
    a.servers.push(ss("Z", "9.9.9.9"));
    let mut b = base_config();
    b.servers.push(ss("Z", "5.5.5.5")); // Z 地址变
    let snap = snap_of(&a.servers);
    assert!(can_skip_restart_for_added_unreferenced(&a, &b, &snap));
}

#[test]
fn can_skip_edit_rule_targeted_node_false() {
    // 删/改被规则指向的节点 → 重启（被引用，改/删影响活流量）。
    let mut a = base_config();
    a.servers.push(ss("Z", "9.9.9.9"));
    a.custom_rules = vec![ext_rule("r1", Some("Z"))];
    let mut b = a.clone();
    b.servers = vec![
        ss(NODE_A, "1.1.1.1"),
        ss(NODE_B, "2.2.2.2"),
        ss("Z", "5.5.5.5"),
    ]; // Z 地址变
    let snap = snap_of(&a.servers);
    assert!(!can_skip_restart_for_added_unreferenced(&a, &b, &snap));
}

#[test]
fn can_skip_edit_selected_node_false() {
    // 改选中节点参数 → 重启（选中∈旧节点、须不变）。
    let a = base_config(); // A=1.1.1.1 选中
    let mut b = base_config();
    b.servers = vec![ss(NODE_A, "8.8.8.8"), ss(NODE_B, "2.2.2.2")];
    let snap = snap_of(&a.servers);
    assert!(!can_skip_restart_for_added_unreferenced(&a, &b, &snap));
}

#[test]
fn can_skip_add_endpoint_node_false() {
    // 新增 endpoint 节点 → 重启（endpoint 被引用：可 force-route 子网）。
    let a = base_config();
    let mut b = base_config();
    b.servers.push(wg("wg1", None, None));
    let snap = snap_of(&a.servers);
    assert!(!can_skip_restart_for_added_unreferenced(&a, &b, &snap));
}

#[test]
fn can_skip_change_selected_server_id_false() {
    // ① selectedServerId 变 → 重启。
    let a = base_config();
    let mut b = base_config();
    b.selected_server_id = Some(NODE_B.into());
    let snap = snap_of(&a.servers);
    assert!(!can_skip_restart_for_added_unreferenced(&a, &b, &snap));
}

#[test]
fn can_skip_add_rule_false() {
    // ② 非 servers 字段变（加规则）→ 重启（正交守卫）。
    let a = base_config();
    let mut b = base_config();
    b.custom_rules = vec![ext_rule("r1", None)];
    let snap = snap_of(&a.servers);
    assert!(!can_skip_restart_for_added_unreferenced(&a, &b, &snap));
}

#[test]
fn can_skip_add_node_with_detour_to_old_unreferenced_true() {
    // 新增节点的 detour 指向某旧节点（链未触达选中）→ 仍可免重启（新节点整体未被引用）。
    let a = base_config();
    let mut b = base_config();
    let mut z = ss("Z", "9.9.9.9");
    z.detour = Some(NODE_B.into());
    b.servers.push(z);
    let snap = snap_of(&a.servers);
    assert!(can_skip_restart_for_added_unreferenced(&a, &b, &snap));
}

#[test]
fn can_skip_port_only_change_on_unreferenced_true() {
    // 改未引用节点任一参数（同址端口）→ defer（P2-B）。
    let mut a = base_config();
    a.servers.push(ss_extra("Z", "9.9.9.9", 8388));
    let mut b = base_config();
    b.servers.push(ss_extra("Z", "9.9.9.9", 9999)); // 端口变
    let snap = snap_of(&a.servers);
    assert!(can_skip_restart_for_added_unreferenced(&a, &b, &snap));
}

#[test]
fn can_skip_added_node_also_rule_targeted_false() {
    // 新增节点同时被规则指向（被引用）→ 重启（②规则变 与 ④Z被引用 双重拦截）。
    let a = base_config();
    let mut b = base_config();
    b.servers.push(ss("Z", "9.9.9.9"));
    b.custom_rules = vec![ext_rule("r1", Some("Z"))];
    let snap = snap_of(&a.servers);
    assert!(!can_skip_restart_for_added_unreferenced(&a, &b, &snap));
}

// === selector default 兜底态：defer 腿不得放行任何节点编辑 ===

/// 未选节点态的两节点基线（刚导入订阅、还没选出口）。
fn no_selection_config() -> UserConfig {
    UserConfig {
        selected_server_id: None,
        ..base_config()
    }
}

/// 【缺陷复现 · 首节点】`selectedServerId=None` ⇒ `build_outbounds`（outbounds.rs:262-271）把
/// proxy-selector 的 default 落到 `node_tags.first()`，该节点承载**全部**代理流量。
/// 它若不在 `referenced_server_ids` 里，改它的 address 会被本函数第③步判「未引用 → 放行」
/// → 走 defer 腿不重启 → 核继续用**旧地址**出网，且无任何提示（热切腿有 `is_server_dirty`
/// 闸门，defer 腿没有）。本用例红 = 这条静默失效回来了。
#[test]
fn can_skip_edit_first_node_without_selection_false() {
    let a = no_selection_config();
    let mut b = a.clone();
    b.servers[0] = ss(NODE_A, "8.8.8.8");
    let snap = snap_of(&a.servers);
    assert!(!can_skip_restart_for_added_unreferenced(&a, &b, &snap));
}

/// 【缺陷复现 · 非首节点】兜底命中的是「生成期**第一个成功发射**的节点」，而生成期跳过了谁
/// 取决于运行期能力（naive 缺 cronet / WG 不可路由 / custom-endpoint 解析失败）——UserConfig
/// 静态算不出 ⇒ 未选节点态下**任何**节点都可能是 live default，改任何一个都必须重启。
/// 本用例红 = 判据退化成「只保护 servers[0]」，前面的节点一被跳过就又漏。
#[test]
fn can_skip_edit_non_first_node_without_selection_false() {
    let a = no_selection_config();
    let mut b = a.clone();
    b.servers[1] = ss(NODE_B, "8.8.8.8");
    let snap = snap_of(&a.servers);
    assert!(!can_skip_restart_for_added_unreferenced(&a, &b, &snap));
}

/// 【同型第二处 · prune 后重算 default】`prune_detour_dead_references` 剔掉 detour 死引用的
/// outbound 后，经 `pruned_selector_default`（outbound_helpers.rs:147）把 proxy-selector 的
/// default 重算成 `remaining.first()`（outbounds.rs:568-578）——又一个「不在任何播种里」的节点。
///
/// 此处 NODE_A 的 detour 指向 naive 节点：缺 libcronet 时 naive 不发射 → NODE_A 成死引用被剔
/// → default 由 NODE_B 接棒。该重算只可能发生在「default ≠ 选中节点 tag」时（default == 选中
/// tag 会走 outbounds.rs:558 的 Err 腿而非静默重算）⇒ 与兜底态同一状态，故同一道闸覆盖。
/// 本用例红 = 接棒者漏出引用集，改它照样静默不重启。
#[test]
fn can_skip_edit_reelected_default_after_prune_false() {
    let mut a = no_selection_config();
    a.servers[0].detour = Some("naive-1".into());
    a.servers.push(ServerConfig {
        protocol: Protocol::Naive,
        ..ss("naive-1", "9.9.9.9")
    });
    let mut b = a.clone();
    b.servers[1] = ss(NODE_B, "8.8.8.8"); // 改接棒者
    let snap = snap_of(&a.servers);
    assert!(!can_skip_restart_for_added_unreferenced(&a, &b, &snap));
}

/// 【新增节点在兜底态也不得放行】未选节点时新增一个节点：它可能排在现有节点之前、
/// 或前面的节点被跳过而由它接棒成 live default ⇒ 不能按「新增即未引用」放行。
#[test]
fn can_skip_add_node_without_selection_false() {
    let a = no_selection_config();
    let mut b = a.clone();
    b.servers.push(ss("Z", "9.9.9.9"));
    let snap = snap_of(&a.servers);
    assert!(!can_skip_restart_for_added_unreferenced(&a, &b, &snap));
}

// === sel_only_forces_subnets：闭包 → 模块级函数提取后的语义不变回归 ===

/// **提取前后结论必须逐格一致**。
///
/// 2026-09 把 [`plan_hot_switch`] 里的局部闭包 `sel_only_forces_subnets` 原样提成模块级函数
/// （当时是为让自动故障切换的停摆判据复用同一份判据而提为 `pub`；那条复用已撤回、函数收回私有，
/// 但提取本身保留 —— 它仍是 [`plan_hot_switch`] 里那道 route 投影 guard 的判据）。提取是纯搬运，
/// 但「纯搬运」这件事得有人证：本测把提取前那三项合取**按当时的源码原样重写**成参照实现，喂同一批
/// 输入逐格对差 —— 提取时若手滑改了任一项（漏 `!`、换成 `mesh_allows_internet`、把
/// `endpoint_forced_route_cidrs` 换成 `mesh_routes`），对差立刻转红。
///
/// 输入面按三项合取的**每一项各自可翻转**来铺：组网资格（WG/TS/OVPN±meshRoutes/普通协议）×
/// `alwaysRouteSubnets`（true/false/缺省）× 段（空/非空）。
///
/// 变异锁：改 `sel_only_forces_subnets` 的任一项 → 本测转红；
/// 而把参照实现和被测实现**一起**改则由 `plan_switch_to_force_route_only_endpoint_none`
/// 这条行为门兜住（那条断言热切规划仍退回重启）。
#[test]
fn sel_only_forces_subnets_matches_pre_extraction_formula() {
    use crate::user_config::protocol_settings::OpenvpnClientSettings;
    use crate::user_config::server_config::TailscaleSettings;

    /// 提取**前**的判据，按 hotswitch.rs 里那个闭包的源码原样重写。
    fn reference(s: Option<&ServerConfig>) -> bool {
        match s {
            Some(srv) => {
                is_mesh_node(srv)
                    && !mesh_always_routes_subnets(srv)
                    && !endpoint_forced_route_cidrs(srv).is_empty()
            }
            None => false,
        }
    }

    fn ts(exit: Option<&str>, always: Option<bool>) -> ServerConfig {
        ServerConfig {
            id: "ts".into(),
            name: "ts".into(),
            protocol: Protocol::Tailscale,
            tailscale_settings: Some(Box::new(TailscaleSettings {
                exit_node: exit.map(str::to_string),
                always_route_subnets: always,
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    fn ovpn(mesh: &[&str]) -> ServerConfig {
        ServerConfig {
            id: "ovpn".into(),
            name: "ovpn".into(),
            protocol: Protocol::OpenvpnClient,
            mesh_routes: mesh.iter().map(|s| (*s).to_string()).collect(),
            openvpn_client_settings: Some(Box::new(OpenvpnClientSettings::default())),
            ..Default::default()
        }
    }

    /// WARP：`endpoint_forced_route_cidrs` 恒空（无子网广播能力）→ 第三项必假。
    fn warp() -> ServerConfig {
        ServerConfig {
            address: "engage.cloudflareclient.com".into(),
            ..wg("warp", Some(true), Some(false))
        }
    }

    let mut wg_no_cidrs = wg("wg-empty", Some(true), Some(false));
    wg_no_cidrs
        .wireguard_settings
        .as_mut()
        .expect("fixture 带 wireguardSettings")
        .allowed_ips
        .clear();

    let matrix = vec![
        // WireGuard：alwaysRouteSubnets 三态 × 段空/非空（`wg` fixture 恒带 10.9.0.0/24）。
        ("wg 恒发段", wg("wg1", Some(true), Some(true))),
        ("wg 仅选中发段", wg("wg2", Some(true), Some(false))),
        ("wg 缺省(恒发)", wg("wg3", Some(true), None)),
        ("wg 关外网+仅选中发段", wg("wg4", Some(false), Some(false))),
        ("wg 仅选中发段但无段", wg_no_cidrs),
        ("warp(无段)", warp()),
        // Tailscale：tailnet 两族段恒非空 ⇒ 第三项恒真，翻的是前两项。
        ("ts 恒发段", ts(Some("e1"), Some(true))),
        ("ts 仅选中发段", ts(Some("e1"), Some(false))),
        ("ts 无 exit + 仅选中发段", ts(None, Some(false))),
        ("ts 缺省", ts(Some("e1"), None)),
        // OpenVPN：组网资格由 meshRoutes 决定；alwaysRouteSubnets 对它落 `_ => true`（恒发段）。
        ("ovpn 有 meshRoutes", ovpn(&["10.1.0.0/24"])),
        ("ovpn 无 meshRoutes", ovpn(&[])),
        // 普通协议：第一项即假。
        ("shadowsocks", ss("ss1", "1.1.1.1")),
    ];

    for (label, server) in &matrix {
        assert_eq!(
            sel_only_forces_subnets(Some(server)),
            reference(Some(server)),
            "提取前后结论不一致：{label}"
        );
    }
    // `None`（无选中 / 选中不在 servers）两侧同判 false。
    assert_eq!(sel_only_forces_subnets(None), reference(None));
    assert!(!sel_only_forces_subnets(None));

    // 正向对照：这批输入里**确实有**判 true 的（否则上面的逐格对差可能只是「两侧一起恒 false」）。
    assert!(
        matrix.iter().any(|(_, s)| sel_only_forces_subnets(Some(s))),
        "输入面必须至少覆盖一个 true 格，否则对差无信息量"
    );
    assert!(
        matrix
            .iter()
            .any(|(_, s)| !sel_only_forces_subnets(Some(s))),
        "输入面必须至少覆盖一个 false 格"
    );
}
