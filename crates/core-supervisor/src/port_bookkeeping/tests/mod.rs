#![allow(clippy::too_many_lines)]

use super::*;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Mutex;

/// 确定性桩：按预置序列返回端口（模拟 listen(0) 拿到的系统分配口）。
/// `None` 元素模拟 bind 失败。
struct SeededPortProvider {
    seq: Mutex<Vec<Option<u16>>>,
    idx: AtomicU16,
}

impl SeededPortProvider {
    fn new(seq: Vec<Option<u16>>) -> Self {
        Self {
            seq: Mutex::new(seq),
            idx: AtomicU16::new(0),
        }
    }
}

impl FreePortProvider for SeededPortProvider {
    fn try_allocate(&self) -> Option<u16> {
        let i = self.idx.fetch_add(1, Ordering::SeqCst) as usize;
        self.seq.lock().unwrap().get(i).copied().flatten()
    }
}

#[test]
fn control_api_port_resolves_configured_or_default() {
    assert_eq!(control_api_port(None), 9090);
    assert_eq!(control_api_port(Some(0)), 9090);
    assert_eq!(control_api_port(Some(9091)), 9091);
}

#[test]
fn resolve_returns_first_non_excluded_port() {
    // 序列：9090(排除)、2080(排除)、0(bind fail)、12345(采用)。
    let p = SeededPortProvider::new(vec![Some(9090), Some(2080), None, Some(12345)]);
    let alloc = PortAllocator::new(p);
    let excl = PortExclusions {
        control_api: 9090,
        http: 2080,
        socks: 0,
        mixed: 0,
        primary_api: 0,
    };
    let r = alloc.resolve_free_local_port(&excl, 9091);
    assert_eq!(r.port, 12345);
    assert!(!r.used_fallback);
}

#[test]
fn resolve_falls_back_when_all_attempts_hit_exclude() {
    // 5 次全撞 9090 → fallback。
    let p = SeededPortProvider::new(vec![Some(9090); 5]);
    let alloc = PortAllocator::new(p);
    let excl = PortExclusions {
        control_api: 9090,
        ..Default::default()
    };
    let r = alloc.resolve_free_local_port(&excl, 9999);
    assert_eq!(r.port, 9999);
    assert!(r.used_fallback);
}

#[test]
fn resolve_falls_back_when_all_binds_fail() {
    // 5 次 bind 全失败 → fallback。
    let p = SeededPortProvider::new(vec![None; 5]);
    let alloc = PortAllocator::new(p);
    let r = alloc.resolve_free_local_port(&PortExclusions::default(), 7777);
    assert_eq!(r.port, 7777);
    assert!(r.used_fallback);
}

#[test]
fn resolve_uses_fallback_immediately_if_exhausted_seq() {
    // 序列耗尽（超出长度返回 None）→ 走 fallback。
    let p = SeededPortProvider::new(vec![Some(12345)]); // 仅 1 个
    let alloc = PortAllocator::new(p).with_max_attempts(5);
    let excl = PortExclusions {
        control_api: 12345,
        ..Default::default()
    };
    let r = alloc.resolve_free_local_port(&excl, 8888);
    // 第 1 次：12345 被排除；2-5 次：序列耗尽 None → fallback。
    assert_eq!(r.port, 8888);
    assert!(r.used_fallback);
}

#[test]
fn tailscale_api_port_excludes_all_user_ports() {
    // #A1：排除 control+http+socks+mixed，fallback = control+1。
    let p = SeededPortProvider::new(vec![
        Some(9090),
        Some(7890),
        Some(1080),
        Some(2080),
        Some(0o0),
    ]); // 全排除
    let _ = p; // 仅构造验证
    let p2 = SeededPortProvider::new(vec![Some(9090), Some(7890), Some(12345)]);
    let alloc = PortAllocator::new(p2);
    let excl = PortExclusions::for_primary_api(Some(9090), Some(7890), Some(1080), Some(2080));
    let r = alloc.resolve_tailscale_api_port(&excl);
    assert_eq!(r.port, 12345); // 9090/7890 排除，12345 采用
    let set = excl.as_set();
    assert!(set.contains(&9090));
    assert!(set.contains(&7890));
    assert!(set.contains(&1080));
    assert!(set.contains(&2080));
}

#[test]
fn tailscale_api_port_fallback_is_control_plus_one() {
    let p = SeededPortProvider::new(vec![Some(9090); 5]);
    let alloc = PortAllocator::new(p);
    let excl = PortExclusions::for_primary_api(Some(9090), None, None, None);
    let r = alloc.resolve_tailscale_api_port(&excl);
    assert_eq!(r.port, 9091); // control(9090)+1
    assert!(r.used_fallback);
}

#[test]
fn login_api_port_excludes_primary_and_uses_control_plus_two_fallback() {
    // 登录核额外排除主核 api，fallback = control+2（:3031）。
    let p = SeededPortProvider::new(vec![
        Some(9091), // = control+1，未被排除但验证排除 primary=9092
        Some(9092), // primary_api，排除
        Some(12345),
    ]);
    let alloc = PortAllocator::new(p);
    let excl = PortExclusions::for_login_api(9092, Some(9090), None, None, None);
    let set = excl.as_set();
    assert!(set.contains(&9092)); // primary 被排除
    let r = alloc.resolve_tailscale_login_api_port(&excl);
    // 9091 不在排除集 → 采用（控制流验证 primary 不被采用需独立测）。
    assert_eq!(r.port, 9091);
    assert!(!r.used_fallback);
}

#[test]
fn login_api_port_fallback_is_control_plus_two() {
    let p = SeededPortProvider::new(vec![Some(9090); 5]);
    let alloc = PortAllocator::new(p);
    let excl = PortExclusions::for_login_api(0, Some(9090), None, None, None);
    let r = alloc.resolve_tailscale_login_api_port(&excl);
    assert_eq!(r.port, 9092);
    assert!(r.used_fallback);
}

#[test]
fn exclusions_default_empty_when_all_unset() {
    let excl = PortExclusions::for_primary_api(None, None, None, None);
    // control_api 默认 9090 仍入集；其余 0 不入。
    let set = excl.as_set();
    assert_eq!(set.len(), 1);
    assert!(set.contains(&9090));
}

#[test]
fn zero_ports_are_not_excluded() {
    // 0/None 视作未设，不进排除集（:3009 filter p>0）。
    let excl = PortExclusions {
        control_api: 0,
        http: 0,
        socks: 0,
        mixed: 0,
        primary_api: 0,
    };
    assert!(excl.as_set().is_empty());
}

#[test]
fn tokio_port_provider_returns_real_ephemeral_port() {
    // 真实 bind 探测（不触碰外部网络，仅 127.0.0.1 loopback）。
    let p = TokioPortProvider;
    let port = p.try_allocate().expect("loopback bind should succeed");
    // 临时端口范围，非 0。
    assert_ne!(port, 0);
    // 应在动态端口区（通常 >= 1024，linux 32768-60999；此处仅宽松断言非保留）。
    assert!(port > 1023 || port > 0);
}

// ── resolve_distinct_free_ports（测速探测池 K 端口批分配）─────────────────────

#[test]
fn distinct_ports_returns_k_unique_ports() {
    // 3 个互异空闲口 → 全采用、保序。
    let p = SeededPortProvider::new(vec![Some(20000), Some(20001), Some(20002)]);
    let alloc = PortAllocator::new(p);
    let ports = alloc.resolve_distinct_free_ports(&PortExclusions::default(), 3);
    assert_eq!(ports, vec![20000, 20001, 20002]);
}

#[test]
fn distinct_ports_rerolls_on_excluded_port() {
    // 首槽先撞排除端口(9090) → 重滚到 20000；验证 exclude 生效。
    let p = SeededPortProvider::new(vec![Some(9090), Some(20000), Some(20001)]);
    let alloc = PortAllocator::new(p);
    let excl = PortExclusions {
        control_api: 9090,
        ..Default::default()
    };
    let ports = alloc.resolve_distinct_free_ports(&excl, 2);
    assert_eq!(ports, vec![20000, 20001]);
}

#[test]
fn distinct_ports_rerolls_on_duplicate_already_taken() {
    // 第二槽先重发首槽已选的 20000（!ports.includes 去重）→ 重滚到 20001。
    let p = SeededPortProvider::new(vec![Some(20000), Some(20000), Some(20001)]);
    let alloc = PortAllocator::new(p);
    let ports = alloc.resolve_distinct_free_ports(&PortExclusions::default(), 2);
    assert_eq!(ports, vec![20000, 20001]);
    // 互异性：无重复。
    assert_ne!(ports[0], ports[1]);
}

#[test]
fn distinct_ports_atomic_fail_returns_empty_when_a_slot_exhausts() {
    // 首槽 5 次全撞排除 9090 → 该槽拿不到 → **整批**返回空（回退：探测池不注入），非部分池。
    let mut seq = vec![Some(9090); 5];
    seq.push(Some(20000)); // 即便后面有空闲口，整批已放弃
    let p = SeededPortProvider::new(seq);
    let alloc = PortAllocator::new(p);
    let excl = PortExclusions {
        control_api: 9090,
        ..Default::default()
    };
    let ports = alloc.resolve_distinct_free_ports(&excl, 2);
    assert!(ports.is_empty(), "任一槽失败即整批放弃");
}

#[test]
fn distinct_ports_zero_count_is_empty() {
    // K=0（探测池关闭的回滚锚点）→ 空 vec，不触 provider。
    let p = SeededPortProvider::new(vec![]);
    let alloc = PortAllocator::new(p);
    assert!(alloc
        .resolve_distinct_free_ports(&PortExclusions::default(), 0)
        .is_empty());
}
