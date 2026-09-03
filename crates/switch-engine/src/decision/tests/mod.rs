#![allow(clippy::too_many_lines)]

use super::*;
use polaris_config_engine::builder::hotswitch::{HotSwitchKind, HotSwitchPut};

fn empty_plan() -> HotSwitchPlan {
    HotSwitchPlan::default()
}

fn plan_with_global_put() -> HotSwitchPlan {
    HotSwitchPlan {
        kind: HotSwitchKind::Global,
        puts: vec![HotSwitchPut {
            selector_tag: "proxy-selector".into(),
            member_tag: "tagB".into(),
            old_member_tag: Some("tagA".into()),
        }],
        must_restart: false,
    }
}

fn plan_none_must_restart() -> HotSwitchPlan {
    HotSwitchPlan {
        kind: HotSwitchKind::None,
        puts: Vec::new(),
        must_restart: true,
    }
}

#[test]
fn hotswitch_leg_when_plan_has_puts() {
    // 腿 1：kind=Global → HotSwitch（即使 norm 不等也走此腿：planHotSwitch 已保证 kind!=None 时 norm 相等）。
    let plan = plan_with_global_put();
    let input = DecisionInput {
        norm_equal: true,
        selected_server_id_equal: false,
        ..DecisionInput::default()
    };
    assert!(matches!(
        decide(&plan, &input),
        SwitchDecision::HotSwitch(_)
    ));
}

#[test]
fn hotswitch_leg_rules_kind() {
    let plan = HotSwitchPlan {
        kind: HotSwitchKind::Rules,
        puts: vec![HotSwitchPut {
            selector_tag: "rule-sel-r1".into(),
            member_tag: "tagX".into(),
            old_member_tag: Some("tagY".into()),
        }],
        must_restart: false,
    };
    let input = DecisionInput::default();
    assert!(matches!(
        decide(&plan, &input),
        SwitchDecision::HotSwitch(_)
    ));
}

#[test]
fn hotswitch_leg_both_kind() {
    let plan = HotSwitchPlan {
        kind: HotSwitchKind::Both,
        puts: vec![
            HotSwitchPut {
                selector_tag: "proxy-selector".into(),
                member_tag: "tagB".into(),
                old_member_tag: Some("tagA".into()),
            },
            HotSwitchPut {
                selector_tag: "rule-sel-r1".into(),
                member_tag: "tagX".into(),
                old_member_tag: Some("tagY".into()),
            },
        ],
        must_restart: false,
    };
    assert!(matches!(
        decide(&plan, &DecisionInput::default()),
        SwitchDecision::HotSwitch(_)
    ));
}

#[test]
fn must_restart_overrides_noop_and_defer() {
    // §2 F1：kind=None + must_restart=true → Restart，绝不落 no-op/defer（即使 norm 等价 / 仅新增）。
    let plan = plan_none_must_restart();

    let input_noop = DecisionInput {
        norm_equal: true,
        selected_server_id_equal: true,
        ..DecisionInput::default()
    };
    assert!(matches!(
        decide(&plan, &input_noop),
        SwitchDecision::Restart
    ));

    let input_defer = DecisionInput {
        only_added_unreferenced: true,
        restart_on_node_change: false,
        ..DecisionInput::default()
    };
    assert!(matches!(
        decide(&plan, &input_defer),
        SwitchDecision::Restart
    ));
}

#[test]
fn noop_leg_when_norm_equal_and_selected_unchanged() {
    // 腿 2：norm 等价 + selectedServerId 未变 + 无 must_restart → NoOp。
    let plan = empty_plan();
    let input = DecisionInput {
        norm_equal: true,
        selected_server_id_equal: true,
        ..DecisionInput::default()
    };
    assert!(matches!(decide(&plan, &input), SwitchDecision::NoOp));
}

#[test]
fn noop_not_taken_when_selected_server_id_changed() {
    // selectedServerId 变了但 norm 等价（selectedServerId 出 norm）+ kind=None：
    // 说明切到一个不在运行 selector 的节点（planHotSwitch 退回 None）→ 必须重启。
    let plan = empty_plan();
    let input = DecisionInput {
        norm_equal: true,
        selected_server_id_equal: false,
        ..DecisionInput::default()
    };
    assert!(matches!(decide(&plan, &input), SwitchDecision::Restart));
}

#[test]
fn defer_leg_when_only_added_unreferenced_and_switch_off() {
    // 腿 3：仅新增未引用节点 + restart_on_node_change 关闭 → Defer。
    let plan = empty_plan();
    let input = DecisionInput {
        norm_equal: false,
        selected_server_id_equal: true,
        only_added_unreferenced: true,
        restart_on_node_change: false,
        defer_restart: false,
    };
    assert!(matches!(decide(&plan, &input), SwitchDecision::Defer));
}

#[test]
fn defer_not_taken_when_restart_on_node_change_on() {
    // restart_on_node_change=true → 节点变更即刻重启，不落 defer（auto-apply 语义）。
    let plan = empty_plan();
    let input = DecisionInput {
        only_added_unreferenced: true,
        restart_on_node_change: true,
        ..DecisionInput::default()
    };
    assert!(matches!(decide(&plan, &input), SwitchDecision::Restart));
}

#[test]
fn restart_leg_for_structural_changes() {
    // 腿 4：norm 不等（结构性变更）+ 非仅新增未引用 → Restart。
    let plan = empty_plan();
    let input = DecisionInput {
        norm_equal: false,
        selected_server_id_equal: true,
        only_added_unreferenced: false,
        restart_on_node_change: false,
        defer_restart: false,
    };
    assert!(matches!(decide(&plan, &input), SwitchDecision::Restart));
}

#[test]
fn restart_leg_default_for_empty_input() {
    // 默认输入（全 false / norm 不等）→ Restart。
    let plan = empty_plan();
    assert!(matches!(
        decide(&plan, &DecisionInput::default()),
        SwitchDecision::Restart
    ));
}

#[test]
fn hotswitch_leg_precedence_over_must_restart() {
    // kind!=None 时走热切腿（planHotSwitch 保证 must_restart 仅在 kind=None 时置 true）。
    // 即便 must_restart 误置，只要 kind!=None 仍走热切（plan.puts 是真值）。
    let plan = HotSwitchPlan {
        kind: HotSwitchKind::Global,
        puts: vec![HotSwitchPut {
            selector_tag: "proxy-selector".into(),
            member_tag: "tagB".into(),
            old_member_tag: None,
        }],
        must_restart: true, // 异常组合，但 kind!=None 优先
    };
    assert!(matches!(
        decide(&plan, &DecisionInput::default()),
        SwitchDecision::HotSwitch(_)
    ));
}

// ── defer_restart（暂存层「保存」腿，spec §2.5 Q4）─────────────────────────────────
//
// 这五条一起钉死「保存只持久化」：NoOp 不造债，其余会动运行核的腿全部 Defer。

#[test]
fn defer_restart_downgrades_structural_restart_leg() {
    // 唯一被降级的腿：结构性变更（norm 不等、非仅新增未引用、无 must_restart）。
    let plan = empty_plan();
    let input = DecisionInput {
        norm_equal: false,
        selected_server_id_equal: true,
        only_added_unreferenced: false,
        restart_on_node_change: false,
        defer_restart: true,
    };
    assert!(
        matches!(decide(&plan, &input), SwitchDecision::Defer),
        "「保存」腿的结构性变更必须落 Defer（落盘 + 进差集、不排程重启）"
    );
}

#[test]
fn defer_restart_defers_must_restart_until_explicit_apply() {
    // must_restart 描述的是“入核所需手段”，不是“保存动作有权立刻断流”。待应用条 + Apply
    // 让延后可见且有确定出口，不构成静默吞。
    let plan = plan_none_must_restart();
    let input = DecisionInput {
        defer_restart: true,
        ..DecisionInput::default()
    };
    assert!(
        matches!(decide(&plan, &input), SwitchDecision::Defer),
        "must_restart 在保存腿必须等待显式 Apply"
    );
}

#[test]
fn defer_restart_defers_hotswitch_until_explicit_apply() {
    // 热切虽不断流，仍会改变活流量；保存不能越过 Apply 边界。
    let plan = plan_with_global_put();
    let input = DecisionInput {
        defer_restart: true,
        ..DecisionInput::default()
    };
    assert!(matches!(decide(&plan, &input), SwitchDecision::Defer));
}

#[test]
fn defer_restart_leaves_noop_leg_intact() {
    // NoOp 腿本就不重启；若被本标志改写成 Defer，生成无关变更会凭空进「待应用」差集 → 噪音条。
    let plan = empty_plan();
    let input = DecisionInput {
        norm_equal: true,
        selected_server_id_equal: true,
        defer_restart: true,
        ..DecisionInput::default()
    };
    assert!(matches!(decide(&plan, &input), SwitchDecision::NoOp));
}

#[test]
fn defer_restart_outranks_restart_on_node_change() {
    // 显式动作（点「保存」）压默认策略（restartOnNodeChange=true 的 auto-apply）。
    // 降级后变更仍进待应用差集、条上可见，不是静默吞。
    let plan = empty_plan();
    let input = DecisionInput {
        norm_equal: false,
        selected_server_id_equal: false,
        only_added_unreferenced: true,
        restart_on_node_change: true,
        defer_restart: true,
    };
    assert!(matches!(decide(&plan, &input), SwitchDecision::Defer));
}
