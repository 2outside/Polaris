#![allow(clippy::too_many_lines)]

use super::*;
use polaris_config_engine::builder::hotswitch::{HotSwitchKind, HotSwitchPut};

fn global_plan() -> HotSwitchPlan {
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

fn conn(id: &str, chains: &[&str], closed_at: i64) -> ConnectionSnapshot {
    ConnectionSnapshot {
        id: id.into(),
        chains: chains.iter().map(|s| s.to_string()).collect(),
        closed_at,
    }
}

#[tokio::test]
async fn execute_applies_all_puts_when_success() {
    let api = MockManagementApi::new();
    let exec = SwitchExecutor;
    let outcome = exec.execute(&api, &global_plan(), false).await;
    match outcome {
        HotSwitchOutcome::Applied { disconnect } => {
            assert!(disconnect.is_none()); // 开关关
        }
        _ => panic!("expected Applied"),
    }
    // PUT 被调用。
    let calls = api.put_calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0], ("proxy-selector".into(), "tagB".into()));
}

#[tokio::test]
async fn execute_triggers_precision_disconnect_when_switch_on() {
    // 开关开 + 有命中旧成员的连接 → 断连。
    let api = MockManagementApi::new().with_connections(vec![
        conn("old-global", &["tagA", "proxy-selector", "rule-sel-r1"], 0),
        conn("rule-fixed", &["tagA", "rule-sel-r2"], 0), // 不含 proxy-selector
        conn("new", &["tagB", "proxy-selector"], 0),     // 新成员连接
    ]);
    let exec = SwitchExecutor;
    let outcome = exec.execute(&api, &global_plan(), true).await;
    match outcome {
        HotSwitchOutcome::Applied {
            disconnect: Some(d),
        } => {
            assert_eq!(d.closed_ids, vec!["old-global".to_string()]);
        }
        _ => panic!("expected Applied with disconnect"),
    }
    // close_connection 被调用一次（关 old-global）。
    let close_calls = api.close_calls.lock().unwrap();
    assert_eq!(*close_calls, vec!["old-global".to_string()]);
}

#[tokio::test]
async fn execute_skips_disconnect_when_switch_off() {
    let api =
        MockManagementApi::new().with_connections(vec![conn("x", &["tagA", "proxy-selector"], 0)]);
    let exec = SwitchExecutor;
    let outcome = exec.execute(&api, &global_plan(), false).await;
    match outcome {
        HotSwitchOutcome::Applied { disconnect } => assert!(disconnect.is_none()),
        _ => panic!("expected Applied"),
    }
    // 开关关 → 不查连接、不关连接。
    assert!(api.close_calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn execute_returns_failed_on_put_error() {
    // 第二个 PUT 失败 → Failed（退回重启兜底）。第一个 PUT 仍执行（break 在失败处）。
    let api = MockManagementApi::new().with_put(
        "proxy-selector",
        "tagB",
        Err(ManagementError::Call("boom".into())),
    );
    let exec = SwitchExecutor;
    let outcome = exec.execute(&api, &global_plan(), true).await;
    match outcome {
        HotSwitchOutcome::Failed {
            failed_selector,
            failed_member,
            error,
        } => {
            assert_eq!(failed_selector, "proxy-selector");
            assert_eq!(failed_member, "tagB");
            assert!(error.contains("boom"));
        }
        _ => panic!("expected Failed"),
    }
    // 失败后不执行断连。
    assert!(api.close_calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn execute_returns_client_not_ready() {
    let api = MockManagementApi::new().not_ready();
    let exec = SwitchExecutor;
    let outcome = exec.execute(&api, &global_plan(), true).await;
    assert_eq!(outcome, HotSwitchOutcome::ClientNotReady);
}

#[tokio::test]
async fn execute_first_put_failure_stops_loop() {
    // 两条 PUT，第一条失败 → 不尝试第二条（Polaris break）。
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
    let api = MockManagementApi::new().with_put(
        "proxy-selector",
        "tagB",
        Err(ManagementError::Call("fail".into())),
    );
    let exec = SwitchExecutor;
    let outcome = exec.execute(&api, &plan, true).await;
    assert!(matches!(outcome, HotSwitchOutcome::Failed { .. }));
    // 只调了第一条 PUT（break）。
    let calls = api.put_calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "proxy-selector");
}

#[tokio::test]
async fn execute_both_kind_closes_global_and_rule_following_connections() {
    // kind=Both：global pair + rule pair 都断各自的旧成员连接。
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
                old_member_tag: Some("tagA".into()),
            },
        ],
        must_restart: false,
    };
    let api = MockManagementApi::new().with_connections(vec![
        // 跟全局走旧节点A的规则连接 → 命中 global pair。
        conn("c1", &["tagA", "proxy-selector", "rule-sel-r1"], 0),
        // r1 规则固定走旧节点A → 命中 rule pair。
        conn("c2", &["tagA", "rule-sel-r1"], 0),
        // r2 规则连接 → 不命中（selector 不同）。
        conn("c3", &["tagA", "rule-sel-r2"], 0),
        // 死连接 → 跳过。
        conn("c4", &["tagA", "proxy-selector"], 999),
    ]);
    let exec = SwitchExecutor;
    let outcome = exec.execute(&api, &plan, true).await;
    match outcome {
        HotSwitchOutcome::Applied {
            disconnect: Some(d),
        } => {
            // c1 + c2 命中（c3 不命中、c4 死连接跳过）。
            assert_eq!(d.closed_ids.len(), 2);
            assert!(d.closed_ids.contains(&"c1".to_string()));
            assert!(d.closed_ids.contains(&"c2".to_string()));
        }
        _ => panic!("expected Applied"),
    }
}

#[tokio::test]
async fn execute_no_disconnect_when_pairs_empty() {
    // puts 有 PUT 但 oldMemberTag 全缺 / old==new → pairs 空 → 不查连接、不关。
    let plan = HotSwitchPlan {
        kind: HotSwitchKind::Global,
        puts: vec![HotSwitchPut {
            selector_tag: "proxy-selector".into(),
            member_tag: "tagB".into(),
            old_member_tag: None, // 无旧成员 → 无 pair
        }],
        must_restart: false,
    };
    let api =
        MockManagementApi::new().with_connections(vec![conn("x", &["tagA", "proxy-selector"], 0)]);
    let exec = SwitchExecutor;
    let outcome = exec.execute(&api, &plan, true).await;
    match outcome {
        HotSwitchOutcome::Applied {
            disconnect: Some(d),
        } => {
            assert_eq!(d.closed_count(), 0); // 无 pair → 无断连
        }
        _ => panic!("expected Applied"),
    }
    // pairs 空 → 不关连接。
    assert!(api.close_calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn execute_empty_puts_applies_without_disconnect() {
    // 空 plan（无 puts）→ Applied，无 PUT、无断连。
    let plan = HotSwitchPlan::default();
    let api = MockManagementApi::new();
    let exec = SwitchExecutor;
    let outcome = exec.execute(&api, &plan, true).await;
    match outcome {
        HotSwitchOutcome::Applied { disconnect } => {
            // 空 puts → pairs 空 → disconnect 是 Some(空 outcome)（开关开但无 pair）。
            assert!(disconnect.is_some());
            assert_eq!(disconnect.unwrap().closed_count(), 0);
        }
        _ => panic!("expected Applied"),
    }
    assert!(api.put_calls.lock().unwrap().is_empty());
}
