use crate::commands::guard_scan::top_level_fn_body;
use crate::test_support::crate_code;

/// 取材面 = `ipinfo.rs` 的**剥注释面**（[`crate_code`]：行首/行尾行注释 + 块注释都剥，
/// 字符串字面量原样保留）。
fn src() -> String {
    crate_code("commands/misc/ipinfo.rs")
}

/// 锚定函数体（签名之后起算 ⇒ 上方那段解释「为什么不能用 `tokio::spawn`」的文档注释天然不在射程内）。
///
/// 此前这里内联着本仓的**第 3 份**剥注释实现（`lines().map(trim_start().starts_with("//"))`），
/// 与 `guard_scan::strip_line_comments` 逐字同形、只认整行注释。三处差别都由共享面接管：
/// 行尾注释也剥、块注释也剥、字符串里的 `//` 不再被误当注释。
fn scheduler_body() -> String {
    top_level_fn_body(&src(), "fn schedule_ipinfo_refresh_inner(")
}

#[test]
fn schedule_ipinfo_refresh_inner_uses_tauri_async_runtime_not_bare_tokio_spawn() {
    let body = scheduler_body();
    assert!(
        body.contains("tauri::async_runtime::spawn"),
        "必须用 tauri::async_runtime::spawn（持全局 runtime handle，任意线程可调）"
    );
    assert!(
        !body.contains("tokio::spawn"),
        "出现裸 tokio::spawn —— 同步 command 路径无 runtime 上下文，真机必 panic→abort"
    );
}

/// 守卫的守卫：证明扫到的是真函数体而非空串（空串会让上面的否定断言恒真 = 没门）。
#[test]
fn guard_scan_actually_captured_the_scheduler_body() {
    let body = scheduler_body();
    assert!(
        body.contains("next_ipinfo_epoch") && body.contains("probe_publish_ipinfo"),
        "扫到的片段缺少排程腿的标志性内容 ⇒ 锚点漂了，守卫失去判据：{body}"
    );
}
