#![allow(clippy::too_many_lines)]

use super::*;
use polaris_config_engine::builder::hotswitch::HotSwitchPut;

fn pair(selector: &str, old: &str) -> SwitchedMemberPair {
    SwitchedMemberPair {
        selector_tag: selector.into(),
        old_member_tag: old.into(),
    }
}

fn put(selector: &str, member: &str, old: Option<&str>) -> HotSwitchPut {
    HotSwitchPut {
        selector_tag: selector.into(),
        member_tag: member.into(),
        old_member_tag: old.map(Into::into),
    }
}

// =========================================================================
// switched_pairs_from_puts
// =========================================================================

#[test]
fn pairs_extracted_from_global_and_rule_puts() {
    let puts = vec![
        put("proxy-selector", "tagB", Some("tagA")),
        put("rule-sel-r1", "tagX", Some("tagY")),
    ];
    let pairs = switched_pairs_from_puts(&puts);
    assert_eq!(pairs.len(), 2);
    assert!(pairs.contains(&pair("proxy-selector", "tagA")));
    assert!(pairs.contains(&pair("rule-sel-r1", "tagY")));
}

#[test]
fn pair_skipped_when_old_member_tag_missing() {
    // 缺 oldMemberTag → 跳过（宁可漏关不误杀）。
    let puts = vec![put("proxy-selector", "tagB", None)];
    assert!(switched_pairs_from_puts(&puts).is_empty());
}

#[test]
fn pair_skipped_when_old_equals_new() {
    // 旧==新 → 指向未变、无需断。
    let puts = vec![put("proxy-selector", "tagA", Some("tagA"))];
    assert!(switched_pairs_from_puts(&puts).is_empty());
}

#[test]
fn pairs_empty_when_no_puts() {
    assert!(switched_pairs_from_puts(&[]).is_empty());
}

#[test]
fn pairs_dedup_not_applied_repeats_preserved() {
    // Polaris 原文不做去重（每个 put 一个 pair）；重复 selector+old 保留（极罕见但忠实移植）。
    let puts = vec![
        put("rule-sel-r1", "tagX", Some("tagY")),
        put("rule-sel-r2", "tagX", Some("tagY")),
    ];
    let pairs = switched_pairs_from_puts(&puts);
    assert_eq!(pairs.len(), 2);
}

// =========================================================================
// connection_matches_switched_pairs —— 维度7 #19 chains 语义
// =========================================================================

#[test]
fn global_switch_matches_following_rule_connection() {
    // #19 核心：跟全局的规则连接 chains=['节点A','proxy-selector','rule-sel-x']
    // 同时含 proxy-selector 与节点A tag → 全局切换 pair ('proxy-selector','节点A') 命中。
    let chains = vec![
        "节点A".to_string(),
        "proxy-selector".into(),
        "rule-sel-x".into(),
    ];
    let pairs = vec![pair("proxy-selector", "节点A")];
    assert!(connection_matches_switched_pairs(Some(&chains), &pairs));
}

#[test]
fn global_switch_does_not_kill_rule_fixed_connection() {
    // #19 核心：规则固定节点 chains=['节点A','rule-sel-x'] 不含 proxy-selector
    // → 全局切换不误杀（chains 嵌套不折叠）。
    let chains = vec!["节点A".to_string(), "rule-sel-x".into()];
    let pairs = vec![pair("proxy-selector", "节点A")];
    assert!(!connection_matches_switched_pairs(Some(&chains), &pairs));
}

#[test]
fn rule_switch_matches_its_own_old_connection() {
    // 规则切换：对称断连该规则自己的旧连接。
    let chains = vec!["节点Y".to_string(), "rule-sel-r1".into()];
    let pairs = vec![pair("rule-sel-r1", "节点Y")];
    assert!(connection_matches_switched_pairs(Some(&chains), &pairs));
}

#[test]
fn rule_switch_does_not_match_other_rule_connection() {
    // 规则 r1 切换不误杀 r2 的连接（selector tag 不同）。
    let chains = vec!["节点Z".to_string(), "rule-sel-r2".into()];
    let pairs = vec![pair("rule-sel-r1", "节点Y")];
    assert!(!connection_matches_switched_pairs(Some(&chains), &pairs));
}

#[test]
fn direct_connection_not_matched() {
    // direct 连接（无 selector tag）不受影响。
    let chains = vec!["direct".to_string()];
    let pairs = vec![pair("proxy-selector", "节点A")];
    assert!(!connection_matches_switched_pairs(Some(&chains), &pairs));
}

#[test]
fn new_member_connection_not_matched() {
    // 切到新成员后新建的连接走新成员 tag，不含旧成员 tag → 不被断（保留）。
    let chains = vec!["节点B".to_string(), "proxy-selector".into()];
    let pairs = vec![pair("proxy-selector", "节点A")]; // 旧是节点A
    assert!(!connection_matches_switched_pairs(Some(&chains), &pairs));
}

#[test]
fn empty_chains_not_matched() {
    let pairs = vec![pair("proxy-selector", "节点A")];
    assert!(!connection_matches_switched_pairs(Some(&[]), &pairs));
}

#[test]
fn none_chains_not_matched() {
    let pairs = vec![pair("proxy-selector", "节点A")];
    assert!(!connection_matches_switched_pairs(None, &pairs));
}

#[test]
fn empty_pairs_never_matches() {
    let chains = vec!["节点A".to_string(), "proxy-selector".into()];
    assert!(!connection_matches_switched_pairs(Some(&chains), &[]));
}

#[test]
fn any_pair_match_wins() {
    // 多 pair（global + rules 同时切）：任一命中即关。
    let chains = vec!["节点A".to_string(), "rule-sel-r1".into()];
    let pairs = vec![
        pair("proxy-selector", "节点A"), // 不命中（chains 无 proxy-selector）
        pair("rule-sel-r1", "节点A"),    // 命中
    ];
    assert!(connection_matches_switched_pairs(Some(&chains), &pairs));
}

#[test]
fn both_global_and_rule_pairs_match_following_connection() {
    // kind=Both：跟全局的规则连接同时被 global pair 与 rule pair 命中（去重由上层关连接时处理）。
    let chains = vec![
        "节点A".to_string(),
        "proxy-selector".into(),
        "rule-sel-r1".into(),
    ];
    let pairs = vec![
        pair("proxy-selector", "节点A"),
        pair("rule-sel-r1", "节点A"),
    ];
    assert!(connection_matches_switched_pairs(Some(&chains), &pairs));
}

// =========================================================================
// select_connections_to_close —— 死连接过滤 + 命中筛选
// =========================================================================

#[test]
fn dead_connections_skipped() {
    // closed_at > 0 的死连接（重置帧幽灵历史环）不处理。
    let conns = vec![
        ConnectionSnapshot {
            id: "alive".into(),
            chains: vec!["节点A".into(), "proxy-selector".into()],
            closed_at: 0,
        },
        ConnectionSnapshot {
            id: "dead".into(),
            chains: vec!["节点A".into(), "proxy-selector".into()],
            closed_at: 1234567890,
        },
    ];
    let pairs = vec![pair("proxy-selector", "节点A")];
    let outcome = select_connections_to_close(&conns, &pairs);
    assert_eq!(outcome.closed_ids, vec!["alive".to_string()]);
    assert_eq!(outcome.closed_count(), 1);
}

#[test]
fn only_matching_alive_connections_closed() {
    let conns = vec![
        ConnectionSnapshot {
            id: "old-global".into(),
            chains: vec![
                "节点A".into(),
                "proxy-selector".into(),
                "rule-sel-r1".into(),
            ],
            closed_at: 0,
        },
        ConnectionSnapshot {
            id: "rule-fixed".into(),
            chains: vec!["节点A".into(), "rule-sel-r2".into()], // 不含 proxy-selector
            closed_at: 0,
        },
        ConnectionSnapshot {
            id: "new-member".into(),
            chains: vec!["节点B".into(), "proxy-selector".into()],
            closed_at: 0,
        },
        ConnectionSnapshot {
            id: "direct".into(),
            chains: vec!["direct".into()],
            closed_at: 0,
        },
    ];
    let pairs = vec![pair("proxy-selector", "节点A")];
    let outcome = select_connections_to_close(&conns, &pairs);
    // 只关 old-global（跟全局走旧节点A的连接）。
    assert_eq!(outcome.closed_ids, vec!["old-global".to_string()]);
}

#[test]
fn empty_connections_yields_empty_outcome() {
    let pairs = vec![pair("proxy-selector", "节点A")];
    let outcome = select_connections_to_close(&[], &pairs);
    assert_eq!(outcome.closed_count(), 0);
}

#[test]
fn empty_pairs_yields_empty_outcome() {
    let conns = vec![ConnectionSnapshot {
        id: "x".into(),
        chains: vec!["proxy-selector".into()],
        closed_at: 0,
    }];
    let outcome = select_connections_to_close(&conns, &[]);
    assert_eq!(outcome.closed_count(), 0);
}

#[test]
fn closed_at_zero_or_negative_treated_as_alive() {
    // 上游 `Number(c.closedAt) > 0`：仅 >0 为死连接；0 / 负 / 缺失视为活连接。
    let conns = vec![
        ConnectionSnapshot {
            id: "zero".into(),
            chains: vec!["节点A".into(), "proxy-selector".into()],
            closed_at: 0,
        },
        ConnectionSnapshot {
            id: "negative".into(),
            chains: vec!["节点A".into(), "proxy-selector".into()],
            closed_at: -1,
        },
    ];
    let pairs = vec![pair("proxy-selector", "节点A")];
    let outcome = select_connections_to_close(&conns, &pairs);
    assert_eq!(
        outcome.closed_ids,
        vec!["zero".to_string(), "negative".into()]
    );
}
