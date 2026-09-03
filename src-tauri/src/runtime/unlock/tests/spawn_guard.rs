use crate::commands::guard_scan::top_level_fn_body;
use crate::test_support::crate_code;

/// 锚定**生产** impl（`BroadcastSink`）而非 trait 上的默认 no-op 实现。
///
/// 两处签名逐字相同（`fn schedule_self_run(&self, token: u64)`），直接按签名 `find` 会命中靠前的
/// trait 默认实现 —— 那个 body 是 `let _ = token;`，**既不含 `tokio::spawn` 也不含正确 API**。
/// 首版守卫就踩了这个：只写否定断言的话会在那段空实现上**恒真通过 = 假绿**；是肯定断言把它顶红的。
///
/// 取材面 = `unlock.rs` 的**剥注释面**（[`crate_code`]：行首/行尾行注释 + 块注释都剥，字符串
/// 字面量原样保留）。此前这里内联着本仓的一份剥注释实现（朴素 `l.split("//").next()`），字符串
/// 字面量里出现 `//` 会把后半行截掉 —— 对本模块的否定断言（`!contains("tokio::spawn")`）方向刚好
/// 是**假绿**：真出现的 `tokio::spawn` 若恰好落在被误截的半行里就漏判。现改用共享的词法级
/// `mask_comments`（经 [`crate_code`]），该缺陷不再存在。
fn production_impl_body() -> String {
    let src = crate_code("runtime/unlock.rs");
    top_level_fn_body(&src, "impl UnlockEventSink for BroadcastSink<'_> {")
}

#[test]
fn schedule_self_run_uses_tauri_async_runtime_not_bare_tokio_spawn() {
    let body = production_impl_body();
    assert!(
        body.contains("tauri::async_runtime::spawn"),
        "schedule_self_run 必须用 tauri::async_runtime::spawn（持全局 runtime handle，任意线程可调）"
    );
    assert!(
        !body.contains("tokio::spawn"),
        "schedule_self_run 出现裸 tokio::spawn —— 同步 command 路径无 runtime 上下文，真机必 panic→abort"
    );
}

/// 守卫的守卫：证明扫到的确实是**生产 impl 的函数体**而非空串或 trait 的默认 no-op。
/// 空串会让 `!contains(...)` 恒真 —— 正是「return 型门 = 没门」的形态。
#[test]
fn guard_scan_actually_captured_the_production_impl() {
    let body = production_impl_body();
    assert!(
        body.len() > 200,
        "扫到的 impl 体太短（{} 字节），守卫可能已退化",
        body.len()
    );
    assert!(
        body.contains("SELF_RUN_DEBOUNCE_MS"),
        "扫到的片段里没有 schedule_self_run 的标志性内容 ⇒ 锚点漂了，守卫失去判据"
    );
    // 反向自证：确认扫到的**不是** trait 的默认 no-op（那段的全部内容就是 `let _ = token;`）。
    assert!(
        body.contains("run_unlock_cycle"),
        "扫到的像是 trait 默认 no-op 而非生产 impl ⇒ 锚点撞了（两处签名逐字相同）"
    );
}
