use super::*;

/// 瞬时态白名单：这两类退避是纯损失（连接是别人的，下一次 accept 就好）。
#[test]
fn transient_accept_errors_retry_immediately() {
    for kind in [
        std::io::ErrorKind::ConnectionAborted,
        std::io::ErrorKind::Interrupted,
    ] {
        assert_eq!(
            classify_accept_error(&std::io::Error::new(kind, "x")),
            AcceptAction::RetryNow,
            "{kind:?} 是单连接级瞬时态，不该退避"
        );
    }
}

/// fd 耗尽是**持续态**：立即重试 = 立即再失败 = 100% CPU 忙转。
///
/// 这里刻意用 `from_raw_os_error` 造真 errno（EMFILE=24 / ENFILE=23，linux 与 macOS 同值），
/// 而不是造一个 `ErrorKind::Other` —— 门要挡的就是「std 没给它们 ErrorKind，于是被当成普通错误」。
#[test]
fn resource_exhaustion_backs_off() {
    for errno in [
        24, /* EMFILE */
        23, /* ENFILE */
        12, /* ENOMEM */
    ] {
        let err = std::io::Error::from_raw_os_error(errno);
        assert_eq!(
            classify_accept_error(&err),
            AcceptAction::Backoff,
            "errno {errno} ({:?}) 必须退避",
            err.kind()
        );
    }
}

/// 未知错误也退避（漏判方向必须是「多退避一次」，不是「忙转」）。
#[test]
fn unknown_accept_errors_back_off() {
    assert_eq!(
        classify_accept_error(&std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "x"
        )),
        AcceptAction::Backoff
    );
    assert_eq!(
        classify_accept_error(&std::io::Error::other("x")),
        AcceptAction::Backoff
    );
}

/// 退避值与 Windows 腿同源（改这条常量前先去改 `service/win.rs` 那条 sleep）。
#[test]
fn backoff_matches_the_windows_sibling_leg() {
    assert_eq!(ACCEPT_BACKOFF, Duration::from_millis(200));
    // 退避必须真的能压住忙转：≥100ms 才把「每秒上万次 accept」压到个位数量级。
    assert!(ACCEPT_BACKOFF >= Duration::from_millis(100));
}

#[test]
fn log_throttle_passes_first_then_rate_limits() {
    let throttle = LogThrottle::new(Duration::from_secs(5));
    let t0 = Instant::now();
    // 首条必须放行 —— 否则持续态可能整整 5s 不自曝。
    assert!(throttle.allow_at(t0), "首条应放行");
    // 窗口内的后续一律压掉（EMFILE 下每 200ms 来一条）。
    assert!(!throttle.allow_at(t0 + Duration::from_millis(200)));
    assert!(!throttle.allow_at(t0 + Duration::from_secs(4)));
    // 窗口过后再放行一条（正向对照：不是「永远只打一条」）。
    assert!(throttle.allow_at(t0 + Duration::from_secs(5)));
    // 新窗口重新起算。
    assert!(!throttle.allow_at(t0 + Duration::from_secs(6)));
    assert!(throttle.allow_at(t0 + Duration::from_secs(11)));
}

/// 记账只在放行时发生 —— 若被压掉的那条也刷新了 `last`，持续态下窗口会被无限推后（永不再打）。
#[test]
fn suppressed_logs_do_not_extend_the_window() {
    let throttle = LogThrottle::new(Duration::from_secs(5));
    let t0 = Instant::now();
    assert!(throttle.allow_at(t0));
    for ms in [200, 400, 600, 4900] {
        assert!(!throttle.allow_at(t0 + Duration::from_millis(ms)));
    }
    assert!(
        throttle.allow_at(t0 + Duration::from_secs(5)),
        "被压掉的调用刷新了窗口 ⇒ 持续态下再也打不出第二条"
    );
}
