use super::*;
use crate::test_support::{crate_code, module_code};

fn request(generation: u64, intent_generation: u64) -> SelectorReconcileRequest {
    SelectorReconcileRequest {
        generation,
        intent_generation,
    }
}

#[test]
fn intent_generation_and_required_flag_have_one_owner() {
    let owner = SelectorReconcileOwner::default();
    assert_eq!(owner.intent_generation(), 0);
    assert_eq!(owner.register_intent(), 1);
    assert_eq!(owner.register_intent(), 2);
    assert!(!owner.is_required());
    owner.mark_required();
    assert!(owner.is_required());
    owner.clear_required();
    assert!(!owner.is_required());
}

#[test]
fn single_flight_hands_off_latest_request_without_gap() {
    let owner = SelectorReconcileOwner::default();
    let old = request(7, 11);
    let latest = request(8, 12);

    assert!(owner.enqueue(old));
    assert!(!owner.enqueue(latest));
    assert_eq!(owner.take_latest_or_finish(None), Some(latest));
    assert_eq!(owner.take_latest_or_finish(None), None);
    assert!(owner.enqueue(request(9, 13)));
}

#[test]
fn latest_pending_wins_over_retry_and_abort_returns_the_handoff() {
    let owner = SelectorReconcileOwner::default();
    let failed = request(7, 11);
    let latest = request(8, 12);

    assert!(owner.enqueue(failed));
    assert_eq!(owner.take_latest_or_finish(None), Some(failed));
    assert!(!owner.enqueue(latest));
    assert_eq!(owner.take_latest_or_finish(Some(failed)), Some(latest));

    assert!(!owner.enqueue(request(9, 13)));
    assert_eq!(owner.abort_active(), Some(request(9, 13)));
    assert!(owner.enqueue(request(10, 14)));
}

#[tokio::test(start_paused = true)]
async fn newer_request_interrupts_retry_delay() {
    let owner = std::sync::Arc::new(SelectorReconcileOwner::default());
    assert!(owner.enqueue(request(1, 1)));
    let waiter = {
        let owner = std::sync::Arc::clone(&owner);
        tokio::spawn(async move { owner.wait_for_retry_or_newer(Duration::from_secs(5)).await })
    };
    tokio::task::yield_now().await;
    assert!(!owner.enqueue(request(2, 2)));
    assert!(waiter.await.unwrap(), "新请求必须立即唤醒退避 worker");
}

// B0 换锚：façade 字段断言（含负向）钉死 `crate_source` —— 判据的一半就是「这个字段/这些旧字段
// 不得再出现」必须专指门面，不能因为取材面变宽而被 `proxy/**` 别处的同名文本顶替（例外，见
// `feedback_rewritten_criterion_can_be_weaker`）。调用点断言另立一条，见下方
// `owner_is_called_where_selector_reconcile_is_reconciled`。
#[test]
fn facade_uses_the_owner_instead_of_recreating_coordination_fields() {
    let facade = crate_code("runtime/proxy.rs");
    assert!(facade.contains("selector_reconcile: Arc<SelectorReconcileOwner>"));
    assert!(!facade.contains("selector_reconcile_required: AtomicBool"));
    assert!(!facade.contains("selector_reconcile_wake: Notify"));
}

/// 调用点半边：`enqueue`/`take_latest_or_finish` 今天仍在门面里，B1+ 搬进 `hot_switch.rs` 后
/// 需要跟随 —— 用 `module_source` 使取材面随生产码搬迁自动跟随（递归覆盖 `proxy/**`，排除
/// `tests/`），不必等换批时再回来改锚点。
#[test]
fn owner_is_called_where_selector_reconcile_is_reconciled() {
    let module = module_code("runtime/proxy");
    assert!(module.contains("self.selector_reconcile.enqueue(request)"));
    assert!(module.contains("selector_reconcile.take_latest_or_finish(retry.take())"));
}
