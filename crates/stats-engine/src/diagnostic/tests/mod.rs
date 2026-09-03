use super::*;

// ── 慢起轴 ──

#[test]
fn start_with_no_retries_records_zero() {
    let mut d = DiagnosticCounters::new();
    let a = d.begin_start();
    d.finish_start(&a);
    assert_eq!(d.last_start_ready_retries, 0);
}

#[test]
fn start_with_retries_records_count() {
    let mut d = DiagnosticCounters::new();
    let mut a = d.begin_start();
    a.record_retry();
    a.record_retry();
    a.record_retry();
    d.finish_start(&a);
    assert_eq!(d.last_start_ready_retries, 3, "三次就绪重试 = 慢起");
}

#[test]
fn last_start_ready_retries_overwritten_on_each_start() {
    // 每次 start 重新累计，落库覆盖上次值
    let mut d = DiagnosticCounters::new();
    let mut a = d.begin_start();
    a.record_retry();
    a.record_retry();
    d.finish_start(&a);
    assert_eq!(d.last_start_ready_retries, 2);

    let a2 = d.begin_start(); // 本次无重试
    d.finish_start(&a2);
    assert_eq!(d.last_start_ready_retries, 0, "新 start 覆盖旧值");
}

// ── 核崩轴 ──

#[test]
fn should_auto_restart_within_max_and_cooldown() {
    let mut d = DiagnosticCounters::new();
    assert!(d.should_auto_restart(1_000));
    d.record_restart(1_000); // count=1
    assert!(d.should_auto_restart(2_000)); // 1 < 3
    d.record_restart(2_000); // count=2
    assert!(d.should_auto_restart(3_000)); // 2 < 3
    d.record_restart(3_000); // count=3
    assert!(!d.should_auto_restart(4_000)); // 3 = MAX，不再重启
}

#[test]
fn restart_count_resets_after_cooldown() {
    let mut d = DiagnosticCounters::new();
    d.record_restart(1_000);
    d.record_restart(2_000);
    d.record_restart(3_000);
    assert_eq!(d.restart_count, 3);
    assert!(!d.should_auto_restart(4_000));

    // 过冷却窗口（> 60s）→ 归零，可再重启
    assert!(d.reset_if_past_cooldown(70_000));
    assert_eq!(d.restart_count, 0);
    assert!(d.should_auto_restart(70_000));
}

#[test]
fn reset_if_past_cooldown_noop_within_window() {
    let mut d = DiagnosticCounters::new();
    d.record_restart(1_000);
    assert!(!d.reset_if_past_cooldown(30_000)); // 未过 60s
    assert_eq!(d.restart_count, 1);
}

#[test]
fn reset_if_past_cooldown_noop_when_already_zero() {
    let mut d = DiagnosticCounters::new();
    assert!(!d.reset_if_past_cooldown(100_000)); // 本来就 0
}

#[test]
fn effective_restart_count_accounts_for_cooldown() {
    let mut d = DiagnosticCounters::new();
    d.record_restart(1_000);
    d.record_restart(2_000);
    assert_eq!(d.effective_restart_count(3_000), 2);
    assert_eq!(d.effective_restart_count(70_000), 0, "过冷却视作 0");
}

#[test]
fn reset_restart_axis_clears_only_restart_axis() {
    // 用户手动停止归零核崩轴，但慢起轴（lastStartReadyRetries）独立保留
    let mut d = DiagnosticCounters::new();
    let mut a = d.begin_start();
    a.record_retry();
    d.finish_start(&a);
    d.record_restart(1_000);
    d.record_restart(2_000);
    assert!(!d.is_clean());

    d.reset_restart_axis();
    assert_eq!(d.restart_count, 0, "核崩轴清零");
    assert_eq!(d.last_start_ready_retries, 1, "慢起轴保留（独立分轴）");
    assert!(!d.is_clean(), "慢起仍有信号");
}

// ── 维度7 #11 分轴不变式 ──

#[test]
fn 两轴独立_慢起非核崩() {
    // 锁：lastStartReadyRetries > 0 但 restartCount == 0 = 「争用下起得慢但已自愈」，不是核崩。
    let mut d = DiagnosticCounters::new();
    let mut a = d.begin_start();
    a.record_retry();
    a.record_retry();
    d.finish_start(&a);
    assert_eq!(d.last_start_ready_retries, 2);
    assert_eq!(d.restart_count, 0, "慢起不增加核崩计数");
    assert!(!d.is_clean());
}

#[test]
fn 两轴独立_核崩非慢起() {
    // 锁：restartCount > 0 但 lastStartReadyRetries == 0 = 核崩自动重启，起核本身一次成功。
    let mut d = DiagnosticCounters::new();
    let a = d.begin_start(); // 一次成功
    d.finish_start(&a);
    d.record_restart(1_000);
    assert_eq!(d.last_start_ready_retries, 0, "核崩不增加慢起计数");
    assert_eq!(d.restart_count, 1);
    assert!(!d.is_clean());
}

#[test]
fn 两轴可同时非零() {
    // 一次慢起后核崩：两轴都 > 0（诊断报告里两行各自呈现）
    let mut d = DiagnosticCounters::new();
    let mut a = d.begin_start();
    a.record_retry();
    d.finish_start(&a);
    d.record_restart(1_000);
    assert_eq!(d.last_start_ready_retries, 1);
    assert_eq!(d.restart_count, 1);
    assert!(!d.is_clean());
}

#[test]
fn clean_when_both_zero() {
    let d = DiagnosticCounters::new();
    assert!(d.is_clean());
}

#[test]
fn clock_rollback_does_not_panic() {
    // now_ms < last_restart_ms（时钟回拨）不应 panic；saturating_sub → 0（未过冷却）→ 视作仍在窗口内。
    // 即回拨时钟下保守地把重启视作「刚发生过」：仍受 MAX_RESTART_COUNT 约束（不放宽成可无限重启）。
    let mut d = DiagnosticCounters::new();
    d.record_restart(1_000_000);
    assert_eq!(d.effective_restart_count(0), 1, "回拨视作仍在窗口内");
    assert!(d.should_auto_restart(0)); // 1 < MAX(3) → 允许
                                       // 关键不变式：达 MAX 后回拨也不应错误地「过冷却归零」放宽重启上限
    d.record_restart(1_000_001);
    d.record_restart(1_000_002);
    assert_eq!(
        d.effective_restart_count(0),
        3,
        "回拨仍视作 3 次（未过冷却）"
    );
    assert!(!d.should_auto_restart(0), "回拨不应绕过 MAX_RESTART_COUNT");
}

#[test]
fn max_restart_count_is_3_and_cooldown_60s() {
    assert_eq!(MAX_RESTART_COUNT, 3);
    assert_eq!(RESTART_COOLDOWN_MS, 60_000);
}
