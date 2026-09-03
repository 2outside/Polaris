use super::*;

#[test]
fn visible_window_resets_countdown() {
    assert_eq!(next_hidden_secs(570, TICK_SECS, true), 0);
}

#[test]
fn hidden_window_accumulates_and_saturates() {
    assert_eq!(next_hidden_secs(0, TICK_SECS, false), 30);
    assert_eq!(next_hidden_secs(570, TICK_SECS, false), 600);
    assert_eq!(next_hidden_secs(u64::MAX, TICK_SECS, false), u64::MAX);
}

#[test]
fn reclaim_boundary_is_exactly_twenty_ticks() {
    assert_eq!(HIDDEN_RECLAIM_SECS, 10 * 60);
    let mut elapsed = 0;
    for tick in 1..=20 {
        elapsed = next_hidden_secs(elapsed, TICK_SECS, false);
        assert_eq!(elapsed >= HIDDEN_RECLAIM_SECS, tick == 20);
    }
}

#[test]
fn one_visible_tick_restarts_full_countdown() {
    let elapsed = next_hidden_secs(590, TICK_SECS, true);
    assert!(next_hidden_secs(elapsed, TICK_SECS, false) < HIDDEN_RECLAIM_SECS);
}
