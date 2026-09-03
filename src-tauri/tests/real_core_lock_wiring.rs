//! **真核测试必须先取跨模块锁**——源码级门。
//!
//! `real_core_*` 测试会拉起真的 sing-box 进程、占端口、写 `POLARIS_*` 环境变量。两条同时跑
//! 就会互相踩，表现为随机失败而不是稳定失败。约束是「每条 `real_core_*` 的函数体开头先取
//! `REAL_CORE_TEST_LOCK`」，而这条约束没有任何运行期表现可以断言（不取锁的那条在单跑时照样绿），
//! 所以只能在源码层面钉。
//!
//! # 为什么取材面是整个 `src/` 而不是几个文件
//!
//! 本门原先住在 `src/runtime.rs` 里，取材面是**手写的三个 `include_str!`**
//! （`runtime/proxy.rs` / `runtime/speedtest.rs` / `runtime/stats.rs`）。那份清单与「哪些文件
//! 里有 `real_core_*` 测试」是两份事实：
//!
//! - 在别的模块新写一条 `real_core_*`，它永远不进扫描面 —— 门不报错，只是看不见它；
//! - 测试实体从 `foo.rs` 外移到 `foo/tests/mod.rs` 之后（本仓正在做的结构治理），那三个
//!   `include_str!` 会指向**只剩生产代码的文件**，扫描面里一条 `real_core_*` 都不剩，
//!   而 `found > 0` 那个自检也会跟着一起消失。**门从有牙变成恒真，全程不报错。**
//!
//! 现在取材面由目录推导（`module_files_with_tests!("")` = `src-tauri/src/` 下全部 `.rs`，
//! 含 `tests/` 子目录），新文件自动进面，外移不改变覆盖。
//!
//! # 为什么不住在 `src/` 里
//!
//! 门自身的源码含 `"async fn real_core_"` 这个针字面量。住在 `src/` 里就会扫到自己，
//! 落进「针在注释/字符串里」的假阳性。放到 `src-tauri/tests/`（不在取材面内）后，
//! 针只可能来自真实代码。
//!
//! 残余风险：`src/` 里若有注释或字符串恰好含 `async fn real_core_`，本门会误报。
//! 那是**假红**（吵但可查），不是假绿，故不为它引入剥注释/剥字符串的取材面。

/// 函数体开头多少字节内必须出现取锁语句。
///
/// 取锁必须是**第一件事**：先建 runtime、先起进程再取锁，冲突已经发生了。256 字节容得下
/// 一两行 setup 与注释，容不下一段真正的初始化。
const PROLOGUE_BYTES: usize = 256;

/// 针：`real_core_*` 测试的定义形态。
const NEEDLE: &str = "async fn real_core_";

/// 取锁语句的形态（`proxy.rs` 走 `lock_real_core_tests()`，其余直接 `REAL_CORE_TEST_LOCK`，
/// 两者都绑到这个名字上）。
const GUARD_BINDING: &str = "let _real_core_guard =";

/// **覆盖下限**：这些模块必须各自保留至少一条 `real_core_*`。
///
/// 与取材面是两件事，不要合并理解：取材面由目录推导（新增自动进面），这里是防**删空**——
/// 把某个模块的真核测试全删了，上面的「每条都取锁」在空集上恒真。原门用「三个
/// `include_str!` + 每个 `found > 0`」同时表达这两件事，于是扫描边界与覆盖下限绑死，
/// 加文件就漏覆盖。拆开后：面自动长，底线显式写。
///
/// 写的是**模块路径**不是文件路径 —— 测试实体外移到 `<模块>/tests/*.rs` 之后，
/// 文件路径会变，模块归属不变。
const MINIMUM_COVERAGE: [&str; 3] = ["runtime/proxy", "runtime/speedtest", "runtime/stats"];

/// 文件相对路径 → 它所属的模块路径。
///
/// - `runtime/proxy.rs`            → `runtime/proxy`
/// - `runtime/proxy/dns_race.rs`   → `runtime/proxy/dns_race`
/// - `runtime/proxy/tests/mod.rs`  → `runtime/proxy`
/// - `runtime/stats/tests/live.rs` → `runtime/stats`
fn owning_module(rel: &str) -> String {
    let stem = rel.strip_suffix(".rs").unwrap_or(rel);
    let mut parts: Vec<&str> = stem.split('/').collect();
    if let Some(index) = parts.iter().position(|part| *part == "tests") {
        parts.truncate(index);
    } else if parts.last() == Some(&"mod") {
        parts.pop();
    }
    parts.join("/")
}

/// 🔴 每条 `real_core_*` 测试的函数体开头必须先取跨模块锁。
///
/// **变异探针**：把任意一条 `real_core_*` 的 `let _real_core_guard = …` 删掉 ⇒ 本条转红并
/// 点名文件与测试名；把某个模块的 `real_core_*` 全删 ⇒ 覆盖下限那条转红。
#[test]
fn every_real_core_test_acquires_the_cross_module_lock() {
    let files = polaris_source_probe::module_files_with_tests!("");

    let mut found: Vec<(String, String)> = Vec::new();
    let mut unlocked: Vec<String> = Vec::new();

    for (rel, source) in &files {
        let mut remaining = source.as_str();
        while let Some(start) = remaining.find(NEEDLE) {
            let function = &remaining[start..];
            let name: String = function["async fn ".len()..]
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            let body = function
                .find('{')
                .map(|open| &function[open + 1..])
                .unwrap_or_else(|| panic!("{rel} 的 `{name}` 没有函数体"));
            // 按字节切会切裂中文注释里的多字节字符；`get` 在非边界上返回 `None`，
            // 退回全体只会让门更宽松地找到取锁语句 —— 不会把假绿变成假红。
            let prologue = body.get(..body.len().min(PROLOGUE_BYTES)).unwrap_or(body);
            if !prologue.contains(GUARD_BINDING) {
                unlocked.push(format!("{rel}::{name}"));
            }
            found.push((rel.clone(), name));
            remaining = body;
        }
    }

    assert!(
        unlocked.is_empty(),
        "这些真核测试没有在函数体前 {PROLOGUE_BYTES} 字节内取得 `REAL_CORE_TEST_LOCK`，\
         并发跑时会互相踩端口与进程（症状是随机失败，不是稳定失败）：\n  {}",
        unlocked.join("\n  ")
    );

    assert!(
        !found.is_empty(),
        "整个 `src-tauri/src/` 里一条 `{NEEDLE}` 都没扫到 —— 要么真核测试全没了，\
         要么命名约定改了而本门的针没跟着改。两种都必须当场红：空集上「每条都取锁」恒真。"
    );

    let covered: std::collections::BTreeSet<String> =
        found.iter().map(|(rel, _)| owning_module(rel)).collect();
    for module in MINIMUM_COVERAGE {
        assert!(
            covered.contains(module),
            "模块 `{module}` 已经没有任何 `real_core_*` 测试了。实际有覆盖的模块：{covered:?}\n\
             若这是有意为之，改本门的 MINIMUM_COVERAGE 并在提交信息里说明为什么这条真核\
             覆盖可以不要；不要靠删测试让门变绿。"
        );
    }
}

/// 🔴 取材面自检：`module_files_with_tests!` 必须真的把 `tests/` 子目录里的文件收进来。
///
/// 没有这条时，上面那条门在「取材面误用了排除 `tests/` 的那一版」下依然会绿——因为结构治理
/// 完成前真核测试还内联在生产文件里。等治理完成、测试搬进 `tests/` 之后它才会突然变成恒真，
/// 而那时候没有任何东西会报错。这条把「取材面选对了没有」提前钉死。
#[test]
fn the_scan_surface_includes_test_directories() {
    let files = polaris_source_probe::module_files_with_tests!("");
    assert!(
        files.iter().any(|(rel, _)| rel.contains("/tests/")),
        "取材面里一个 `tests/` 下的文件都没有 —— 取材面选成了「只要生产代码」的那一版，\
         测试实体一外移，上面那条门就会在空集上恒真。实际文件数：{}",
        files.len()
    );
}
