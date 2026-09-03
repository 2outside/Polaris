use super::super::*;
use std::sync::Mutex;

/// 记录器落点：单测无 `AppHandle`，靠它把「发了哪几帧」变成可断言的数据。
#[derive(Default)]
struct RecordingSink(Mutex<Vec<Value>>);

impl UpdateProgressSink for RecordingSink {
    fn emit(&self, frame: Value) {
        self.0.lock().expect("测试锁未中毒").push(frame);
    }
}

impl RecordingSink {
    fn frames(&self) -> Vec<Value> {
        self.0.lock().expect("测试锁未中毒").clone()
    }
}

#[test]
fn failure_frame_carries_the_real_backend_message() {
    let frame = terminal_progress_frame(&update_failure("订阅缺少 URL"));
    assert_eq!(frame["phase"], "failed");
    // 变异锁：换成「订阅更新失败」这类笼统兜底 → 订阅栏上那个 tooltip 就再也说不出是哪一步坏了。
    assert_eq!(frame["error"], "订阅缺少 URL");
}

#[test]
fn classified_fetch_failure_keeps_kind_and_http_status_through_terminal_frame() {
    let result = update_classified_failure(&json!({
        "ok": false,
        "errorKind": "http",
        "httpStatus": 403,
        "message": "sanitized transport diagnostic",
    }));
    assert_eq!(result["error"], "sanitized transport diagnostic");
    assert_eq!(result["errorKind"], "http");
    assert_eq!(result["httpStatus"], 403);

    let frame = terminal_progress_frame(&result);
    assert_eq!(frame["phase"], "failed");
    assert_eq!(frame["errorKind"], "http");
    assert_eq!(frame["httpStatus"], 403);
    // 变异锁：只复制分类却丢掉原始脱敏诊断，会让 unknown 类失去最后一段准确兜底。
    assert_eq!(frame["error"], "sanitized transport diagnostic");
}

#[test]
fn missing_success_key_is_treated_as_failure_not_success() {
    // 防御性：契约破了也不能把「更新中」永远挂在栏上，更不能报一个假的「已完成」。
    let frame = terminal_progress_frame(&json!({}));
    assert_eq!(frame["phase"], "failed");
}

#[test]
fn unchanged_is_not_collapsed_into_done_with_zero_counts() {
    let unchanged = terminal_progress_frame(&update_ok(0, 0, 0, true, None));
    let done_zero = terminal_progress_frame(&update_ok(0, 0, 0, false, None));
    // 变异锁：删掉 `unchanged` 分支 → 304 与「真跑了但零变化」在栏上长得一模一样，
    // 而这两件事对用户的下一步动作不同（前者订阅本来就没更新，后者才是「更新过了」）。
    assert_eq!(unchanged["phase"], "unchanged");
    assert_eq!(done_zero["phase"], "done");
}

#[test]
fn done_frame_carries_real_reconcile_counts() {
    let frame = terminal_progress_frame(&update_ok(3, 1, 2, false, None));
    assert_eq!(frame["phase"], "done");
    // 变异锁：三个计数写串位（added/updated/deleted）在只看 phase 的断言下抓不到。
    assert_eq!(frame["added"], 3);
    assert_eq!(frame["updated"], 1);
    assert_eq!(frame["deleted"], 2);
}

#[test]
fn provider_progress_reports_completed_count_starting_at_zero() {
    let sink = Arc::new(RecordingSink::default());
    let erased: Arc<dyn UpdateProgressSink> = sink.clone();
    let p = ProviderProgress::new(erased, 3);
    p.on_fetch_start();
    p.on_fetch_start();
    p.on_fetch_start();
    p.on_fetch_finish();
    p.on_fetch_finish();
    p.on_fetch_finish();

    let frames = sink.frames();
    assert_eq!(frames.len(), 4, "并发发起只报一次 0，三次完成各报一帧");
    for (i, f) in frames.iter().enumerate() {
        assert_eq!(f["phase"], "providers");
        assert_eq!(f["done"], i as u64, "done = 已完成数");
        assert_eq!(f["total"], 3);
    }
}
