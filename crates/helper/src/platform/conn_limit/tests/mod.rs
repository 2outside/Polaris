use super::*;

#[test]
fn conn_limiter_caps_in_flight_connections() {
    let limiter = ConnLimiter::new(2);
    let a = limiter.try_acquire().expect("第 1 个许可");
    let b = limiter.try_acquire().expect("第 2 个许可");
    assert_eq!(limiter.live(), 2);
    // 达上限 → 快速失败（不排队、不阻塞）。
    assert!(
        limiter.try_acquire().is_none(),
        "超上限仍发许可 ⇒ 闸门形同虚设"
    );
    // 归还一个 → 立即又能收（正向对照：不是「一关就永久关死」）。
    drop(a);
    assert_eq!(limiter.live(), 1);
    let c = limiter.try_acquire().expect("归还后应能再取");
    assert_eq!(limiter.live(), 2);
    drop((b, c));
    assert_eq!(limiter.live(), 0, "全部归还后应归零");
}

/// 许可必须随执行体结束归还 —— 包括 panic 展开那条腿（手工加减会漏，漏几次闸门永久关死）。
#[test]
fn conn_permit_is_returned_when_the_connection_thread_panics() {
    let limiter = ConnLimiter::new(1);
    let permit = limiter.try_acquire().expect("许可");
    let handle = std::thread::spawn(move || {
        let _permit = permit;
        panic!("模拟连接线程 panic");
    });
    assert!(handle.join().is_err(), "该线程应确实 panic 了");
    assert_eq!(limiter.live(), 0, "panic 展开必须归还许可");
    assert!(limiter.try_acquire().is_some(), "闸门不应被 panic 关死");
}

/// 上限是保守值而非「等于没有」：既要挡住耗尽，又不能误伤单 app 的正常并发。
#[test]
fn max_concurrent_connections_is_a_conservative_bound() {
    assert_eq!(MAX_CONCURRENT_CONNECTIONS, 32);
    // 区间断言在编译期即可判定（clippy::assertions_on_constants）→ 放进 const block。
    const {
        assert!(
            MAX_CONCURRENT_CONNECTIONS >= 8,
            "低于正常并发会误伤合法客户端"
        )
    };
    const {
        assert!(
            MAX_CONCURRENT_CONNECTIONS <= 128,
            "上限太高 = 线程/fd 仍可被耗尽，闸门无意义"
        )
    };
}
