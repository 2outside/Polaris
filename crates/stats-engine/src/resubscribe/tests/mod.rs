use super::*;

#[test]
fn cyclic_not_triggered_before_interval() {
    let mut s = ResubscribeStrategy::new(Duration::from_secs(30));
    s.begin_generation(0); // 锚=0
    assert!(s.decide_cyclic(10_000).is_none());
    assert!(s.decide_cyclic(29_999).is_none());
}

#[test]
fn cyclic_triggered_at_or_after_interval() {
    let mut s = ResubscribeStrategy::new(Duration::from_secs(30));
    s.begin_generation(0);
    // 30s 到期
    let d = s.decide_cyclic(30_000).expect("到期应触发");
    assert_eq!(d.kind, ResubscribeKind::Cyclic);
    assert!(!d.reset_snapshot, "周期重建不归零 snapshot");
}

#[test]
fn cyclic_decision_carries_current_generation() {
    let mut s = ResubscribeStrategy::new(Duration::from_secs(10));
    let g = s.begin_generation(0);
    let d = s.decide_cyclic(10_000).unwrap();
    assert_eq!(d.generation, g);
}

#[test]
fn mark_cyclic_done_resets_anchor_no_repeat_in_same_period() {
    let mut s = ResubscribeStrategy::new(Duration::from_secs(30));
    s.begin_generation(0);
    assert!(s.decide_cyclic(30_000).is_some());
    s.mark_cyclic_done(30_000);
    // 同一时刻再判 → 不应再触发（锚已更新到 30_000）
    assert!(s.decide_cyclic(30_000).is_none());
    assert!(s.decide_cyclic(59_999).is_none());
    // 下一周期到期
    assert!(s.decide_cyclic(60_000).is_some());
}

#[test]
fn begin_generation_increments_and_resets_anchor() {
    let mut s = ResubscribeStrategy::new(Duration::from_secs(30));
    let g0 = s.begin_generation(0);
    let g1 = s.begin_generation(100);
    assert_eq!(g1, g0 + 1);
    // 新世代从 100 起算 → 100 + 30s = 30100ms 才到期
    assert!(s.decide_cyclic(30_099).is_none());
    assert!(s.decide_cyclic(30_100).is_some());
}

#[test]
fn begin_generation_generation_is_monotonic() {
    let mut s = ResubscribeStrategy::new(Duration::from_secs(1));
    let a = s.begin_generation(0);
    let b = s.begin_generation(1);
    let c = s.begin_generation(2);
    assert!(c > b && b > a, "世代应单调递增");
}

#[test]
fn forced_decision_resets_snapshot() {
    let s = ResubscribeStrategy::new(Duration::from_secs(30));
    let d = s.force();
    assert_eq!(d.kind, ResubscribeKind::Forced);
    assert!(d.reset_snapshot, "强制重建归零 snapshot");
}

#[test]
fn forced_does_not_consume_cyclic_quota() {
    // force 不调 mark_cyclic_done → 周期锚不变。调用方应在 force 后 begin_generation 重置锚。
    let mut s = ResubscribeStrategy::new(Duration::from_secs(30));
    s.begin_generation(0);
    let _ = s.force();
    // 仍按原锚判定周期
    assert!(s.decide_cyclic(30_000).is_some(), "force 不影响周期锚");
}

#[test]
fn cyclic_let_go_if_generation_advanced_between_decide_and_execute() {
    // 维度7 #6 generation 守卫：decide 拿到 g=1，但执行前 begin_generation 把世代推到 g=2
    // → 调用方比对 decision.generation != 当前基线 → 让位不重建。本测试锁 decide 返回的 generation
    // 是「快照世代」，供调用方比对（decide 与执行之间的抢占由调用方处理）。
    let mut s = ResubscribeStrategy::new(Duration::from_secs(10));
    let g1 = s.begin_generation(0);
    let decision = s.decide_cyclic(10_000).unwrap();
    assert_eq!(decision.generation, g1);
    // 执行前被 supersede
    let g2 = s.begin_generation(10_000);
    assert_ne!(decision.generation, g2, "决策世代已陈旧，调用方应让位");
}

#[test]
fn default_interval_is_30min() {
    let s = ResubscribeStrategy::default();
    assert_eq!(s.interval(), STREAM_RESUBSCRIBE_INTERVAL);
    assert_eq!(s.interval(), Duration::from_secs(30 * 60));
}

#[test]
fn decide_cyclic_with_saturating_sub_on_underflow() {
    // now_ms < last_cyclic_ms（时钟回拨）不应 panic；saturating_sub → 0 → 不触发。
    let mut s = ResubscribeStrategy::new(Duration::from_secs(30));
    s.begin_generation(1_000_000);
    assert!(s.decide_cyclic(0).is_none(), "时钟回拨不应触发周期重建");
}
