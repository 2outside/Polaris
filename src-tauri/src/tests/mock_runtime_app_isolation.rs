//! **建 `MockRuntime` App 的集成测试，每个文件只许有一个测试函数。**
//!
//! # 守的不变量
//!
//! `tauri::test::mock_builder()` 建 App 会摸 **GTK / tray 的进程级初始化**。同一个测试二进制里
//! 两个测试函数各建一个 App，在 cargo 默认并行下会撞同一份进程级状态。
//! `tests/remote_webview_cannot_reach_app_commands.rs` 的头注记着实测形态：三 test 版在默认并行
//! 下失败、`--test-threads=1` 才绿。2026-08-17 那次 `remote_webview_cannot_reach_app_commands`
//! 的 SIGSEGV（apport 记录在案，调试构建、`--nocapture`）就是收拢成单 test 之前的形态。
//!
//! # 为什么必须是源码级门
//!
//! 「同一文件里有几个 `#[test]`」**没有任何运行期表征**：拆成两个照样编得过、clippy 全绿，
//! 本机 `--test-threads=1` 也照样绿。它只在**默认并行**下概率性地崩，而崩的形态是 SIGSEGV ——
//! 不是断言失败，读日志的人第一反应会是「环境问题，重跑一次」。把「绿」建立在调用方每次都传对
//! flag 上是脆的：那正是收拢成单 test 的原始理由，而那条理由此前只写在被守文件的注释里，
//! **注释对执行没有强制力**。
//!
//! # 判据被自己污染（这道门最容易写歪的地方）
//!
//! 被守文件的注释里逐字写着「刻意是单个 `#[test]`」——**裸 grep 数出来是 2 个**。
//! 于是朴素判据只有两条路：写成 `== 2`（等于把注释算进判据，删掉那句注释就假红，
//! 真加一个测试要到 3 才红），或者先剥注释。本门取后者：取材一律过
//! [`mask_comments_and_strings`]，注释与字符串字面量同时抹掉——`test_only_symbols_gated.rs`
//! 这类元门的判据本身就是写在字符串里的 `"#[test]"`，不抹字符串会把它们算成测试。
//! 剥离在真实语料上确实生效由 [`comment_masking_is_live_on_the_guarded_file`] 证明
//! （它断言的是**裸计数严格大于净化计数**，不是某个写死的数字）。
//!
//! # 覆盖面由判据定，不由夹具定
//!
//! 取材面是 `src-tauri/tests/**.rs` 全体，选择器是「净化面上出现 `MockRuntime`」——
//! 将来**新增**一个建 App 的集成测试会自动进射程。写死文件名的门在「有人新加了一个文件」时
//! 静默失去覆盖，这是本仓已经吃过的亏。选择器一个文件都没选中时本门硬失败，
//! 而不是让循环体零次执行、断言恒真。
//!
//! # 不在射程内（显式声明，不是遗漏）
//!
//! - **一个属性生成多个测试**的宏（`test_case` / `rstest`）：它们会让「属性数 = 测试数」这个
//!   前提失效。本仓无此依赖，[`no_multi_case_test_macros_in_range`] 断言它们在射程内不出现——
//!   哪天真引入了，那条会红，提示先修本门的计数假设，而不是让本门悄悄变弱。
//! - **`src/**` 里的单元测试**：那些不建 App，不在本不变量的射程内。

use crate::test_support::repo_dir_files;
use polaris_source_probe::mask_comments_and_strings;

/// 建 App 的集成测试的取材根（仓库内路径）。
const INTEGRATION_TESTS_DIR: &str = "src-tauri/tests";

/// 选择器：净化面上出现这个类型名 = 这个文件会建 `MockRuntime` App。
const APP_BUILDING_NEEDLE: &str = "MockRuntime";

/// 净化面上的**测试属性**计数。
///
/// 命中形状：`#[` + 一段 `A-Za-z0-9_:` 的路径 + `]`，且路径以 `test` 结尾。
/// 故 `#[test]` 与 `#[tokio::test]` 都算，`#[cfg(test)]`（路径后跟 `(`）与 `#[should_panic]`
/// （路径不以 `test` 结尾）都不算。宁可多算不可少算：路径以 `test` 结尾的自定义属性会被算进来，
/// 那个方向只会让门更严。
fn test_attribute_count(code: &str) -> usize {
    let bytes = code.as_bytes();
    let mut count = 0usize;
    let mut index = 0usize;
    while index + 1 < bytes.len() {
        if !(bytes[index] == b'#' && bytes[index + 1] == b'[') {
            index += 1;
            continue;
        }
        let mut cursor = index + 2;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let path_start = cursor;
        while cursor < bytes.len()
            && (bytes[cursor].is_ascii_alphanumeric()
                || bytes[cursor] == b'_'
                || bytes[cursor] == b':')
        {
            cursor += 1;
        }
        let path = &code[path_start..cursor];
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor < bytes.len() && bytes[cursor] == b']' && path.ends_with("test") {
            count += 1;
        }
        index += 2;
    }
    count
}

/// `(仓库内路径, 净化面)`，只留会建 App 的那些文件。
fn app_building_files() -> Vec<(String, String)> {
    repo_dir_files(INTEGRATION_TESTS_DIR, "rs")
        .into_iter()
        .map(|(path, source)| (path, mask_comments_and_strings(&source)))
        .filter(|(_, code)| code.contains(APP_BUILDING_NEEDLE))
        .collect()
}

#[test]
fn app_building_integration_tests_hold_exactly_one_test_fn() {
    let files = app_building_files();
    assert!(
        !files.is_empty(),
        "`{INTEGRATION_TESTS_DIR}` 下没有一个文件在净化面上提到 `{APP_BUILDING_NEEDLE}` —— \
         要么建 App 的集成测试被挪走/改名了，要么选择器过时了。本门此刻覆盖不到任何东西，\
         不许静默通过。"
    );
    for (path, code) in &files {
        let count = test_attribute_count(code);
        assert_eq!(
            count, 1,
            "{path} 里有 {count} 个测试函数。建 `MockRuntime` App 会摸 GTK/tray 的进程级初始化，\
             同一个二进制里两个 App 在默认并行下会撞（2026-08-17 实测 SIGSEGV）。\
             要加断言就加进那个已有的测试函数里，按节分段；不要拆成第二个 `#[test]`，\
             也不要靠调用方传 `--test-threads=1` 来救。"
        );
    }
}

/// 计数器自检：不喂真实语料，只喂合成夹具，逐个形态对差。
///
/// 没有这一格，上面那条的绿有两种读法：判据真的成立，或者计数器压根数不出东西（恒 0）。
#[test]
fn test_attribute_counter_self_check() {
    for (source, expected, why) in [
        ("#[test]\nfn a() {}", 1usize, "裸 test 属性"),
        (
            "#[test]\nfn a() {}\n#[test]\nfn b() {}",
            2,
            "两个才是本门要抓的形态",
        ),
        ("#[tokio::test]\nfn a() {}", 1, "带路径的 test 属性同样算"),
        ("#[ test ]\nfn a() {}", 1, "属性内空白不改变语义"),
        ("#[cfg(test)]\nmod tests;", 0, "cfg(test) 不是测试函数"),
        ("#[should_panic]\nfn a() {}", 0, "非 test 结尾的属性不算"),
        (
            "#[cfg(test)]\n#[test]\nfn a() {}",
            1,
            "两个属性叠加只有一个是测试",
        ),
    ] {
        assert_eq!(
            test_attribute_count(source),
            expected,
            "计数器在「{why}」这一格数错了"
        );
    }

    // 注释与字符串面：净化之后必须归零，否则被守文件的头注会自己把门顶红。
    for source in [
        "// 刻意是单个 #[test]\nfn a() {}",
        "//! 刻意是单个 `#[test]`\nfn a() {}",
        "/* #[test] */\nfn a() {}",
        "const NEEDLE: &str = \"#[test]\";",
    ] {
        assert_eq!(
            test_attribute_count(&mask_comments_and_strings(source)),
            0,
            "净化面上不该把注释/字符串里的 `#[test]` 算成测试函数：{source}"
        );
    }
}

/// 剥注释在**真实语料**上确实在做功：被守文件的裸计数严格大于净化计数。
///
/// 断言的是两者的**关系**而不是某个写死的数字 —— 注释里多写一句 `#[test]` 不该让门红。
/// 这一格红了说明净化那步被摘掉了，此时上面那条会因为注释而假红，读的人会去改被守文件而不是修门。
#[test]
fn comment_masking_is_live_on_the_guarded_file() {
    let raw = repo_dir_files(INTEGRATION_TESTS_DIR, "rs")
        .into_iter()
        .find(|(path, _)| path.ends_with("remote_webview_cannot_reach_app_commands.rs"))
        .map(|(_, source)| source)
        .expect("建 App 的那个集成测试必须在取材面里");
    let bare = test_attribute_count(&raw);
    let masked = test_attribute_count(&mask_comments_and_strings(&raw));
    assert_eq!(masked, 1, "净化面上应恰有 1 个测试函数，实为 {masked}");
    assert!(
        bare > masked,
        "裸计数 {bare} 没有大于净化计数 {masked} —— 该文件注释里那句「刻意是单个 `#[test]`」\
         是本门剥注释的原始理由，两者相等说明取材没过净化，或那句注释被删了。"
    );
}

/// 计数假设的边界：一个属性生成多个测试的宏不许出现在射程内。
///
/// 它们一旦引入，「属性数 = 测试数」就不再成立，本门会在真有两个测试时报 1。
#[test]
fn no_multi_case_test_macros_in_range() {
    for (path, code) in app_building_files() {
        for macro_name in ["test_case", "rstest", "parameterized"] {
            assert!(
                !code.contains(macro_name),
                "{path} 引入了 `{macro_name}` —— 它一个属性能生成多个测试，\
                 本门「属性数 = 测试数」的计数假设当场失效。先修本门的计数器再用它。"
            );
        }
    }
}
