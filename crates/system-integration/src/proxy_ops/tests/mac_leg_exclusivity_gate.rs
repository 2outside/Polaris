//! G-互斥：macOS 两条系统代理实现腿的**实现面互斥门**。
//!
//! 今天两条腿都是活路径：legacy `set_proxy_from_snapshot` 先试原生事务
//! （`macos_proxy.rs`，SystemConfiguration FFI），`MacProxyWriterError::Unavailable` 时回落
//! `proxy_ops` 的 networksetup CLI 腿；exact 路径一旦选中则 fail closed。**两条都活着是设计，
//! 两条各长出对方那套实现才是缺陷** —— 那时
//! 「改哪边」失去唯一答案，同一个行为有两处可改、修一处另一处仍旧，且没有任何编译期信号。
//!
//! 散文约束（Phase 3「先核对已有 `macos_proxy.rs`，禁止新建第二套同义实现」）对执行没有
//! 强制力：同一句话在不同天会被执行成不同结果。本门把它落成判据。
//!
//! ## 取材面
//!
//! - CLI 腿 = `module_source("proxy_ops")`（`proxy_ops.rs` + `proxy_ops/**`，排 `tests/`）。
//!   拆分后新增的 `proxy_ops/*.rs` **自动进面**；写死单文件的形态会在拆分当天塌掉一半。
//! - 原生腿 = `module_source("macos_proxy")`（`macos_proxy.rs` + `macos_proxy/**`，排
//!   `tests/`）。取材面形状与 CLI 腿一致：模块 = 根文件 + 目录递归，拆分后新增的
//!   `macos_proxy/*.rs` **自动进面**。今天 `macos_proxy/` 下只有 `tests/`（已排除在外），
//!   故此刻的取材面与单文件锚逐字节相同；明天原生腿一旦真拆出子文件，这道门会严格更宽，
//!   不会像单文件锚那样在拆分当天塌掉一半。
//!
//! 两侧都先剥注释（散文里两个词都必然出现：`macos_proxy.rs:4` 写着 `networksetup`、
//! `proxy_ops.rs:5` 写着 `SystemConfiguration` —— 不剥则本门到货即红）。符号面判据再剥
//! 字符串（[`code_face`]）；字面量面判据保留字符串（[`literal_face`]），理由见该函数文档：
//! 判据的对象就是字符串字面量，一起剥掉判据不是变弱而是消失。

use crate::test_support::{code_face, expect_marker, literal_face, module_source};

/// 原生 SystemConfiguration 腿的**符号面**（标识符 / 类型名 / extern 静态）。
/// 剥注释与字符串后仍在，正因为它们是代码而不是散文。
const SC_SYMBOL_FACE: &[&str] = &[
    "SCPreferences",
    "SCNetworkSet",
    "SCNetworkService",
    "SCNetworkProtocol",
    "SCDynamicStore",
    "CFDictionary",
    "kSCPropNet",
];

/// 原生腿的**框架名字面量**（`#[link(name = "…", kind = "framework")]`）。
/// 它只以字符串形态存在 ⇒ 在符号面上看不见 ⇒ 必须单列一组、判在字面量面上。
const SC_FRAMEWORK_LITERALS: &[&str] = &["SystemConfiguration", "CoreFoundation"];

/// networksetup CLI 腿的**字面量面**：程序名 + 写路径子命令族。
/// 这条腿的全部对外形态就是 argv 字符串，没有别的符号可锚。
const CLI_LITERAL_FACE: &[&str] = &[
    "networksetup",
    "-setwebproxy",
    "-setsecurewebproxy",
    "-setsocksfirewallproxy",
    "-setproxybypassdomains",
];

#[test]
fn proxy_ops_must_not_grow_a_native_systemconfiguration_leg() {
    let src = expect_marker(
        module_source("proxy_ops"),
        "proxy_ops",
        "pub trait SystemProxyOps",
    );
    let code = code_face(&src);
    let literals = literal_face(&src);

    // ── 取材面自检（fail-closed：面塌了要当场喊，不能让否定型断言在空面上恒真）──
    assert!(
        code.contains("pub trait SystemProxyOps"),
        "代码面塌了：`proxy_ops` 的符号都不在了，下面每条否定断言都会恒真"
    );
    assert!(
        !code.contains("macOS 生产写路径经独立"),
        "代码面没剥注释：注释里的散文会绊倒否定型断言（假红），也会喂饱肯定型断言（假绿）"
    );
    assert!(
        !code.contains("-setwebproxystate"),
        "代码面没剥字符串：符号面判据必须只看代码"
    );
    assert!(
        literals.contains("-setwebproxystate"),
        "字面量面把字符串一起剥了：那样 `SC_FRAMEWORK_LITERALS` 这组针恒真，判据消失"
    );
    assert!(
        !literals.contains("SystemConfiguration 原生事务模块"),
        "字面量面没剥注释：`proxy_ops.rs:5` 的模块注释就写着 SystemConfiguration"
    );

    for needle in SC_SYMBOL_FACE {
        assert!(
            !code.contains(needle),
            "`proxy_ops` 里出现了原生 SystemConfiguration 符号 `{needle}` —— \
             原生腿的唯一 owner 是 `macos_proxy.rs`；两侧的交汇点只能是 \
             `MacProxyTransactionWriter` / `execute_macos_transaction` 那道缝"
        );
    }
    for needle in SC_FRAMEWORK_LITERALS {
        assert!(
            !literals.contains(needle),
            "`proxy_ops` 里出现了原生框架名字面量 `{needle}`（`#[link(name = …)]` 形态）—— \
             它不该链接任何 macOS 原生框架"
        );
    }
}

#[test]
fn macos_proxy_must_not_grow_a_second_networksetup_cli_leg() {
    let src = expect_marker(
        module_source("macos_proxy"),
        "macos_proxy.rs",
        "SCPreferencesCreate",
    );
    let literals = literal_face(&src);

    // ── 取材面自检（三面各钉一条：代码在、字符串在、注释没了）──
    assert!(
        literals.contains("SCPreferencesCreate"),
        "取材面塌了：读到的不是那条原生腿，下面每条否定断言都会恒真"
    );
    assert!(
        literals.contains("\"SystemConfiguration\""),
        "字面量面把字符串一起剥了：`networksetup` 只以字符串形态存在，剥掉后本门恒真"
    );
    assert!(
        !literals.contains("避免逐服务启动"),
        "字面量面没剥注释：`macos_proxy.rs:4` 的模块注释就写着 networksetup，本门会到货即红"
    );

    for needle in CLI_LITERAL_FACE {
        assert!(
            !literals.contains(needle),
            "`macos_proxy.rs` 里出现了 networksetup CLI 腿的字面量 `{needle}` —— \
             CLI 腿的唯一 owner 是 `proxy_ops`；原生腿再长一套等于同一个行为有两处可改"
        );
    }
}

/// 钉死 [`literal_face`] 的形状本身：本门的判据全压在它身上，而它的实现在**另一个 crate**
/// （`polaris-source-probe::mask_comments`）—— 跨 crate 的口径变更不会在本文件的 diff 里露面，
/// 故在消费侧留一份可执行的前提。
///
/// 后半段同时是**输入对差表**：同一份输入，`code_face`（连字符串一起剥）会把两条 CLI 字面量
/// 一并抹掉 ⇒ 上面那道门在它上面**恒真**（放行）；`literal_face` 拦截。这就是本门不用统一
/// 代码面的全部理由，写成可执行的，免得下一个人「顺手统一一下」。
#[test]
fn literal_face_strips_comments_and_keeps_string_literals() {
    let sample = concat!(
        "//! 避免逐服务启动 `networksetup`。\n",
        "/* 块注释 /* 嵌套 */ networksetup */\n",
        "fn f() { let _ = Command::new(\"networksetup\", [\"-setwebproxystate\"]); }\n",
        "const U: &str = \"http://a // b\";\n",
    );

    let literals = literal_face(sample);
    assert!(!literals.contains("避免逐服务启动"), "行注释未剥");
    assert!(!literals.contains("块注释"), "块注释未剥");
    assert!(!literals.contains("嵌套"), "嵌套块注释未剥");
    assert!(literals.contains("\"networksetup\""), "字符串字面量被误剥");
    assert!(literals.contains("-setwebproxystate"), "字符串字面量被误剥");
    assert!(
        literals.contains("http://a // b"),
        "字符串里的 `//` 被当成注释开头，从此把该行后半段吃掉"
    );
    assert!(literals.contains("Command::new"), "代码被误剥");

    // 对差：全剥面上，同样两条针一个都命中不到 —— 判据不是变弱，是消失。
    let code = code_face(sample);
    assert!(
        !code.contains("networksetup") && !code.contains("-setwebproxystate"),
        "前提变了：`code_face` 不再剥字符串，本门的取材面选择需要重新论证"
    );
    assert!(code.contains("Command::new"), "代码面把代码也剥了");
}
