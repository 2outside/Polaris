use super::*;
use std::cell::RefCell;

/// fake scheduler：记录排程数 + clear 次数（fake timers）。
struct FakeScheduler {
    scheduled: RefCell<u32>,
    cleared: RefCell<u32>,
}
impl FakeScheduler {
    fn new() -> Self {
        Self {
            scheduled: RefCell::new(0),
            cleared: RefCell::new(0),
        }
    }
    fn scheduled_count(&self) -> u32 {
        *self.scheduled.borrow()
    }
    fn cleared_count(&self) -> u32 {
        *self.cleared.borrow()
    }
}
impl DebounceScheduler for FakeScheduler {
    fn schedule(&mut self, _cb: Box<dyn FnMut()>, _delay: Duration) {
        *self.scheduled.borrow_mut() += 1;
    }
    fn clear(&mut self) {
        *self.cleared.borrow_mut() += 1;
    }
}

fn make_watcher<'a>(
    debounce_ms: u64,
    on_trigger: &'a mut dyn FnMut(),
    on_warn: &'a mut dyn FnMut(LogLevel, &str),
) -> DnsInterfaceWatcher<'a> {
    DnsInterfaceWatcher::new(debounce_ms, on_trigger, on_warn)
}

// ── should_reconcile_dns 门控 ──

#[test]
fn gate_true_only_tun_takeover_on_with_marker() {
    assert!(should_reconcile_dns(Some("tun"), None, true));
    assert!(should_reconcile_dns(Some("tun"), Some(true), true));
}

#[test]
fn gate_false_when_not_tun() {
    assert!(!should_reconcile_dns(Some("system"), None, true));
    assert!(!should_reconcile_dns(None, None, true));
}

#[test]
fn gate_false_when_takeover_disabled() {
    assert!(!should_reconcile_dns(Some("tun"), Some(false), true));
}

#[test]
fn gate_false_when_no_marker() {
    assert!(!should_reconcile_dns(Some("tun"), Some(true), false));
}

// ── watcher on_data 去抖 ──
// 注：on_trigger / on_warn 是 &mut dyn FnMut，需绑定到 let 变量再传 &mut（避免临时值）。

#[test]
fn on_data_schedules_debounce_on_trigger_line() {
    let triggered = std::cell::Cell::new(0u32);
    let mut warned: Vec<String> = vec![];
    let mut on_trigger = || triggered.set(triggered.get() + 1);
    let mut on_warn = |_lvl: LogLevel, msg: &str| warned.push(msg.to_string());
    let mut watcher = make_watcher(1500, &mut on_trigger, &mut on_warn);

    let mut sched = FakeScheduler::new();
    let fired = watcher.on_data("RTM_IFINFO: ifflags\n", &mut sched);
    assert!(fired);
    assert_eq!(sched.scheduled_count(), 1);
    assert_eq!(sched.cleared_count(), 0);
    assert!(watcher.debounce_pending());
}

#[test]
fn on_data_ignores_noise_lines() {
    let mut on_trigger = || {};
    let mut warned: Vec<String> = vec![];
    let mut on_warn = |_lvl: LogLevel, msg: &str| warned.push(msg.to_string());
    let mut watcher = make_watcher(1500, &mut on_trigger, &mut on_warn);

    let mut sched = FakeScheduler::new();
    let fired = watcher.on_data("got message of size 92 on Wed\nlock: 0 flags\n", &mut sched);
    assert!(!fired);
    assert_eq!(sched.scheduled_count(), 0);
    assert!(!watcher.debounce_pending());
}

#[test]
fn on_data_assembles_split_lines_across_chunks() {
    // 一条触发行被分片到达：先 "RTM_"，再 "ADD: default\n"
    let triggered = std::cell::Cell::new(0u32);
    let mut on_trigger = || triggered.set(triggered.get() + 1);
    let mut warned: Vec<String> = vec![];
    let mut on_warn = |_lvl: LogLevel, msg: &str| warned.push(msg.to_string());
    let mut watcher = make_watcher(1500, &mut on_trigger, &mut on_warn);

    let mut sched = FakeScheduler::new();
    // 第一个 chunk 末尾是半行（无 \n），不应触发。
    assert!(!watcher.on_data("prefix\nRTM_", &mut sched));
    assert_eq!(sched.scheduled_count(), 0);
    assert!(!watcher.debounce_pending());
    // 第二个 chunk 补全 → 完整 RTM_ADD 行 → 触发。
    assert!(watcher.on_data("ADD: default route\n", &mut sched));
    assert_eq!(sched.scheduled_count(), 1);
    assert!(watcher.debounce_pending());
}

#[test]
fn on_data_burst_clears_then_reschedules_debounce() {
    // 一个 burst 内多条触发行 → 第 2+ 条触发前 clear（合并 burst）。
    let triggered = std::cell::Cell::new(0u32);
    let mut on_trigger = || triggered.set(triggered.get() + 1);
    let mut warned: Vec<String> = vec![];
    let mut on_warn = |_lvl: LogLevel, msg: &str| warned.push(msg.to_string());
    let mut watcher = make_watcher(1500, &mut on_trigger, &mut on_warn);

    let mut sched = FakeScheduler::new();
    // 3 条触发行在一个 chunk。
    watcher.on_data("RTM_IFINFO: a\nRTM_NEWADDR: b\nRTM_ADD: c\n", &mut sched);
    // 每条都 schedule（3 次），其中后 2 次因 pending 先 clear（2 次 clear）。
    assert_eq!(sched.scheduled_count(), 3);
    assert_eq!(sched.cleared_count(), 2);
    assert!(watcher.debounce_pending());
}

#[test]
fn on_resume_schedules_debounce() {
    let triggered = std::cell::Cell::new(0u32);
    let mut on_trigger = || triggered.set(triggered.get() + 1);
    let mut warned: Vec<String> = vec![];
    let mut on_warn = |_lvl: LogLevel, msg: &str| warned.push(msg.to_string());
    let mut watcher = make_watcher(1500, &mut on_trigger, &mut on_warn);

    let mut sched = FakeScheduler::new();
    watcher.on_resume(&mut sched);
    assert_eq!(sched.scheduled_count(), 1);
    assert!(watcher.debounce_pending());
}

#[test]
fn fire_invokes_on_trigger_and_clears_pending() {
    let triggered = std::cell::Cell::new(0u32);
    let mut on_trigger = || triggered.set(triggered.get() + 1);
    let mut warned: Vec<String> = vec![];
    let mut on_warn = |_lvl: LogLevel, msg: &str| warned.push(msg.to_string());
    let mut watcher = make_watcher(1500, &mut on_trigger, &mut on_warn);

    let mut sched = FakeScheduler::new();
    watcher.on_data("RTM_ADD: default\n", &mut sched);
    assert!(watcher.debounce_pending());

    // timer 到期 → fire。
    watcher.fire("test");
    assert!(!watcher.debounce_pending());
    assert_eq!(triggered.get(), 1);
}

#[test]
fn cancel_pending_resets_state() {
    let triggered = std::cell::Cell::new(0u32);
    let mut on_trigger = || triggered.set(triggered.get() + 1);
    let mut warned: Vec<String> = vec![];
    let mut on_warn = |_lvl: LogLevel, msg: &str| warned.push(msg.to_string());
    let mut watcher = make_watcher(1500, &mut on_trigger, &mut on_warn);

    let mut sched = FakeScheduler::new();
    watcher.on_data("RTM_ADD: default\n", &mut sched);
    // 半行残留 + pending
    watcher.on_data("RTM_NEWADDR", &mut sched);

    watcher.cancel_pending();
    assert!(!watcher.debounce_pending());
    // buffer 也清。
    let mut sched2 = FakeScheduler::new();
    // 下一个完整行才触发（buffer 已清，旧半行丢失）。
    assert!(watcher.on_data("RTM_DELADDR: x\n", &mut sched2));
}
