use super::*;

/// 🔴 计数累加 + **读后即清**。
///
/// 对**独立实例**断言而非 [`SESSION`]：本 crate 的竞速用例并发跑、其中走投毒腿的会改动那个
/// static，对它断言的用例必然 flaky（本条曾这么写过，随即改掉）。
///
/// 变异锁：把 [`Counters::take`] 里的 `swap` 写成 `load` → 末两条断言转红，
/// 而那正是「上一次开代理的污染量被算进这一次」的形态。
#[test]
fn counts_accumulate_and_reset_on_take() {
    let c = Counters::default();
    assert!(c.take().is_empty(), "新计数器必须为空");

    c.record_poisoned_dropped();
    c.record_poisoned_dropped();
    c.record_reply_no_socket();

    let s = c.take();
    assert_eq!(s.poisoned_dropped, 2);
    assert_eq!(s.reply_no_socket, 1);
    assert!(!s.is_empty());

    let after = c.take();
    assert_eq!(after, SessionStats::default(), "读后即清，不得跨会话累加");
    assert!(after.is_empty());
}

/// 生产入口确实接在同一个 static 上（委托断线 → 计数永远是 0，汇总行恒不打印）。
///
/// 只断言「记了之后取得到」，不断言具体数值 —— 并发用例可能同时在往里加。
#[test]
fn module_level_entrypoints_delegate_to_the_process_counters() {
    record_poisoned_dropped();
    record_reply_no_socket();
    let s = take_session();
    assert!(
        s.poisoned_dropped >= 1 && s.reply_no_socket >= 1,
        "模块级入口必须落到 SESSION 上，否则汇总永远是 0"
    );
}
