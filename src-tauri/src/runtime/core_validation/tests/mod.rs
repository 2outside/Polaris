use super::*;

#[test]
fn dwell_matches_upstream_constant() {
    // 上游 CoreUpdateService.ts:104 `STABILITY_DWELL_MS = 30000`。
    assert_eq!(STABILITY_DWELL.as_millis(), 30_000);
}

#[test]
fn core_failures_warrant_rollback() {
    for code in ["STARTUP_FAILED", "PROCESS_EXITED", "AUTO_RESTART_FAILED"] {
        assert!(
            failure_warrants_rollback(false, Some(code)),
            "{code} 表示核自己没跑起来 / 跑挂了 —— 换核窗口内必须回滚"
        );
    }
}

#[test]
fn environment_failures_do_not_warrant_rollback() {
    // 这些是「环境/权限」轴：回滚换不掉它们，只会把健康的新核白白换走
    // （上游 issue #324 的同类失败面）。
    for code in [
        "HELPER_NOT_INSTALLED",
        "HELPER_GATE_ABORTED",
        "ROOT_ORPHAN_BLOCKED",
        "TUN_ROUTE_NOT_CAPTURED",
    ] {
        assert!(
            !failure_warrants_rollback(false, Some(code)),
            "{code} 是环境问题，与核版本无关，回滚解决不了"
        );
    }
}

#[test]
fn unknown_future_codes_default_to_no_rollback() {
    // 白名单的**全部价值**在这一条：将来新增任何码，默认不回滚。
    assert!(!failure_warrants_rollback(false, Some("SOME_FUTURE_CODE")));
    assert!(!failure_warrants_rollback(false, None));
}

#[test]
fn running_core_never_rolls_back_even_with_error_code() {
    // 非致命错误（set_nonfatal_error）保留 running=true。只看码不看 running 会在
    // 「核好好跑着、只是系统代理没设上」时把核回滚掉。
    assert!(!failure_warrants_rollback(
        true,
        Some("SYSTEM_PROXY_FAILED")
    ));
    assert!(!failure_warrants_rollback(true, Some("EXIT_MISMATCH")));
    // 连白名单里的码也一样：running 为真就不是「核挂了」。
    assert!(!failure_warrants_rollback(true, Some("PROCESS_EXITED")));
}
