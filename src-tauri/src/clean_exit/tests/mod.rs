use super::*;
use crate::test_support::TestDir;

/// 没写过标记 ⇒ 上次不是正常退出（强杀 / 崩溃 / 首次启动）。
/// 牙：把 `take` 改成恒 `true` → 本条转红。
#[test]
fn absent_marker_means_not_a_clean_exit() {
    let d = TestDir::new("polaris-clean-exit-absent-");
    assert!(!take(d.path()));
}

/// 写了 ⇒ 读到真。牙：删掉 `mark` 里的 `fs::write` → 本条转红。
#[test]
fn marked_exit_is_seen_as_clean() {
    let d = TestDir::new("polaris-clean-exit-marked-");
    mark(d.path());
    assert!(d.join(CLEAN_EXIT_MARKER_FILENAME).exists());
    assert!(take(d.path()));
}

/// **读后即清**：连续两次启动不会重复判成「上次正常退出」。
/// 这条是 ④ 的正确性核心 —— 不清的话，正常退出一次之后**每次**启动都会清掉 staged，
/// 强杀那条恢复腿就永远走不到了。
/// 牙：把 `take` 改成 `marker_path(dir).exists()`（只读不清）→ 第二次断言转红。
#[test]
fn take_consumes_the_marker_so_the_next_start_sees_nothing() {
    let d = TestDir::new("polaris-clean-exit-consume-");
    mark(d.path());
    assert!(take(d.path()), "第一次启动：上次正常退出");
    assert!(
        !take(d.path()),
        "第二次启动：标记已被消费，按非正常退出处理"
    );
    assert!(!d.join(CLEAN_EXIT_MARKER_FILENAME).exists());
}

/// 重复 `mark` 幂等（退出腿理论上只跑一次，但 `app:restart` + 末窗关闭这类叠加路径不该炸）。
#[test]
fn mark_is_idempotent() {
    let d = TestDir::new("polaris-clean-exit-idempotent-");
    mark(d.path());
    mark(d.path());
    assert!(take(d.path()));
    assert!(!take(d.path()));
}

/// **`app:restart` 不落标记** ⇒ 重启回来暂存还在。用户几秒内就回来、心智连续，
/// 在这条路径上清掉 staged = App 自己吃掉用户的工作（NFR-1）。
///
/// 牙：删掉 `mark_unless_restarting` 里的 `if restarting { return; }` → 本条转红。
///
/// ⚠️ 本条钉的是**判定腿**（bit 为真就不落）。「那个 bit 真的由 `app_restart` 置上、
/// 且真的传到了这里」是**接线**，本条证不了 —— 那一半由
/// `exit_lifecycle::restart_leg_is_wired_to_skip_the_clean_exit_marker` 的源码守卫盯着。
#[test]
fn restart_leg_does_not_leave_a_marker() {
    let d = TestDir::new("polaris-clean-exit-restart-");
    mark_unless_restarting(d.path(), true);
    assert!(!d.join(CLEAN_EXIT_MARKER_FILENAME).exists());
    assert!(
        !take(d.path()),
        "app:restart 后再启动必须按「没正常退出」处理 ⇒ 恢复暂存"
    );
}

/// 反向对照：同一个函数、bit 为假 ⇒ 照落。没有这条，上一条把 `mark_unless_restarting`
/// 改成空函数也全绿（「跳过」变成「永远跳过」）。
#[test]
fn real_exit_leg_still_leaves_a_marker() {
    let d = TestDir::new("polaris-clean-exit-realexit-");
    mark_unless_restarting(d.path(), false);
    assert!(take(d.path()));
}

/// 目录不存在 ⇒ 写失败但不 panic、不留标记（下次启动保守恢复）。
/// 牙：把 `mark` 里的 `if let Err` 改成 `.expect(...)` → 本条 panic 转红。
#[test]
fn mark_on_missing_dir_degrades_to_no_marker() {
    let d = TestDir::new("polaris-clean-exit-missing-");
    let gone = d.join("nope");
    mark(&gone);
    assert!(!take(&gone));
}
