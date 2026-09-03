use super::*;

#[test]
fn config_default_matches_polaris() {
    // 移植自 CoreUpdateScheduler.ts:26-29 的常量值。
    let c = ScheduleConfig::default();
    assert_eq!(c.startup_delay, Duration::from_secs(30));
    assert_eq!(c.tick_interval, Duration::from_secs(6 * 60 * 60));
    assert_eq!(c.check_interval, Duration::from_secs(24 * 60 * 60));
    assert_eq!(c.stopped_apply_delay, Duration::from_secs(5));
}

#[test]
fn should_check_false_before_start() {
    let mut s = UpdateScheduler::new(ScheduleConfig::default(), FixedClock(1_000_000));
    // 未 start → false。
    assert!(!s.should_check());
    s.start();
    assert!(s.is_started());
}

#[test]
fn should_check_respects_startup_delay() {
    let cfg = ScheduleConfig {
        startup_delay: Duration::from_secs(30),
        ..ScheduleConfig::default()
    };
    // 启动时刻 = 1000ms。
    let mut s = UpdateScheduler::new(cfg, FixedClock(1000));
    s.start();
    // 10s 后（< 30s startup_delay）→ false。
    s.clock = FixedClock(1000 + 10_000);
    assert!(!s.should_check());
    // 31s 后（≥ 30s）→ true（首次检查，last_check=0 视为 due）。
    s.clock = FixedClock(1000 + 31_000);
    assert!(s.should_check());
}

#[test]
fn should_check_respects_due_interval() {
    let cfg = ScheduleConfig {
        startup_delay: Duration::from_secs(0), // 跳过 startup 闸便于测 due
        check_interval: Duration::from_secs(60),
        ..ScheduleConfig::default()
    };
    let mut s = UpdateScheduler::new(cfg, FixedClock(0));
    s.start();
    // 首次：last_check=0 → due。
    assert!(s.should_check());
    // 标记成功检查（推进时钟到 now=1000 再 mark_done，刷新 last_check=1000）。
    s.clock = FixedClock(1000);
    s.mark_running();
    s.mark_done(true);
    assert_eq!(s.last_check_ms(), 1000);
    // 30s 后（< 60s due）→ false。
    s.clock = FixedClock(1000 + 30_000);
    assert!(!s.should_check());
    // 61s 后（≥ 60s due）→ true。
    s.clock = FixedClock(1000 + 61_000);
    assert!(s.should_check());
}

#[test]
fn mark_done_failure_does_not_refresh_last_check() {
    // 移植自 Polaris「失败轮保留旧值让下轮重试」：失败检查不刷新 last_check。
    let cfg = ScheduleConfig {
        startup_delay: Duration::from_secs(0),
        check_interval: Duration::from_secs(60),
        ..ScheduleConfig::default()
    };
    let mut s = UpdateScheduler::new(cfg, FixedClock(1000));
    s.start();
    s.mark_checked(); // 成功，last_check=1000
                      // 一次失败检查（now=2000）。
    s.clock = FixedClock(2000);
    s.mark_running();
    s.mark_done(false); // 失败
                        // last_check 仍为 1000（失败不刷新）。
    assert_eq!(s.last_check_ms(), 1000);
}

#[test]
fn should_check_false_while_running() {
    // 防重入：running 时 false（= Polaris isRunning）。
    let cfg = ScheduleConfig {
        startup_delay: Duration::from_secs(0),
        ..ScheduleConfig::default()
    };
    let mut s = UpdateScheduler::new(cfg, FixedClock(0));
    s.start();
    s.mark_running();
    assert!(!s.should_check());
    s.mark_done(true);
    assert!(s.should_check());
}

#[test]
fn kick_returns_should_check() {
    // kick = should_check 的别名（手动触发，幂等）。
    let cfg = ScheduleConfig {
        startup_delay: Duration::from_secs(0),
        ..ScheduleConfig::default()
    };
    let mut s = UpdateScheduler::new(cfg, FixedClock(0));
    s.start();
    assert!(s.kick());
}

#[test]
fn restore_last_check_persists_across_restart() {
    // 持久化场景：启动时从持久态恢复 last_check。
    let cfg = ScheduleConfig {
        startup_delay: Duration::from_secs(0),
        check_interval: Duration::from_secs(60),
        ..ScheduleConfig::default()
    };
    let mut s = UpdateScheduler::new(cfg, FixedClock(5000));
    s.start();
    s.restore_last_check(1000); // 恢复「上次检查在 1000」
                                // now=5000，距上次 4000 < 60000 → 未 due。
    assert!(!s.should_check());
    // now=62000，距上次 61000 ≥ 60000 → due。
    s.clock = FixedClock(62_000);
    assert!(s.should_check());
}

#[test]
fn clock_rollback_does_not_freeze_persisted_schedule() {
    let cfg = ScheduleConfig {
        startup_delay: Duration::ZERO,
        check_interval: Duration::from_secs(60),
        ..ScheduleConfig::default()
    };
    let mut s = UpdateScheduler::new(cfg, FixedClock(50_000));
    s.start();
    s.restore_last_check(90_000); // 备份来自快 40s 的设备，或本机墙钟刚被拨回。
    assert!(
        s.should_check(),
        "墙钟落后于持久化基准时应 fail-open 检查一次并刷新基准，不能冻结到追平"
    );
}

#[test]
fn elapsed_since_last_check() {
    let cfg = ScheduleConfig {
        startup_delay: Duration::from_secs(0),
        ..ScheduleConfig::default()
    };
    let mut s = UpdateScheduler::new(cfg, FixedClock(1000));
    s.start();
    assert!(s.elapsed_since_last_check().is_none());
    s.mark_checked(); // last_check=1000
    s.clock = FixedClock(4000);
    assert_eq!(
        s.elapsed_since_last_check(),
        Some(Duration::from_millis(3000))
    );
}

#[test]
fn should_apply_on_proxy_stopped_double_check() {
    // 移植自 Polaris onProxyStopped 的双查：proxy 仍运行 → false；已停 → true。
    let s = UpdateScheduler::new(ScheduleConfig::default(), FixedClock(0));
    assert!(!s.should_apply_on_proxy_stopped(true)); // 重启窗口内 → 不落位
    assert!(s.should_apply_on_proxy_stopped(false)); // 确实停了 → 落位
}

#[test]
fn stop_resets_running_and_started() {
    let mut s = UpdateScheduler::new(ScheduleConfig::default(), FixedClock(0));
    s.start();
    s.mark_running();
    s.stop();
    assert!(!s.is_started());
    assert!(!s.should_check()); // 未启动 → false
}

#[test]
fn fixed_and_system_clock() {
    assert_eq!(FixedClock(12345).now_ms(), 12345);
    // 可持久化时钟必须是 Unix epoch 量级；进程内单调刻度重启后无法与磁盘值比较。
    let first = SystemClock.now_ms();
    let second = SystemClock.now_ms();
    assert!(first > 1_000_000_000_000);
    assert!(second >= first);
}
