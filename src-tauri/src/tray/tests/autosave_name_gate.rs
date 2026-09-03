//! #313b 的接线门。三条断言全部**源码级**，故在 Linux 上也跑得动 ——
//! 而这恰恰是必须的：这条腿的实现是 `#[cfg(target_os = "macos")]`，本机连编都编不了，
//! 若判据也只能在 mac 上跑，那本地就是全盲。
//!
//! 取材锚在 **crate 根**（`CARGO_MANIFEST_DIR`），不锚在本文件：本模块搬进
//! `tray/tests/` 后，下面三行一个字都不用改。旧写法 `include_str!("tray.rs")` 锚在
//! 含它的那个文件，搬家即静默平移到 `tray/tests/tray.rs`（若那里恰好有同名文件，
//! 就是编译过、门全绿、扫的却是别的东西）。
//!
//! 仍然不走「运行期读盘 + 读不到就跳过」：读不到 / 取材面为空一律 panic（`crate_code` 与
//! `module_code` 的共同契约），空取材面不会退化成一条恒真的断言；`expect_marker` 再钉一道
//! 「读到的确实是那份源码」。

use std::sync::LazyLock;

use crate::test_support::{crate_code, crate_file, expect_marker, module_code};

/// 取材面 = **模块** `tray`（`tray.rs` + `tray/**` 递归，剔除 `tests/`）的**剥注释面**，
/// 不是单文件 `tray.rs`、也不是全文。
///
/// # 为什么哨兵串不能是 `pub const TRAY_AUTOSAVE_NAME`
///
/// 那正是本门**被测的对象**：`autosave_name_in_source()` 就是去源码里读它的字面量。
/// 哨兵与判据指向同一个符号时，符号一搬家两者同时失效，而修法看起来只是「顺手把哨兵改成
/// 新位置的串」——改完门恢复绿、判据却已经是「我读到的那个文件里有我要读的那个东西」，
/// 一句同义反复。哨兵必须是**独立于被测对象**的稳定标识：这里取 façade 里的
/// `pub const TRAY_LABEL`（托盘窗 label，定义在 `tray.rs` 门面、无搬移计划，且本文件三条
/// 断言一条都不碰它）。它证的是「这份 blob 确实是 tray 模块」，与「autosaveName 是什么」无关。
static TRAY_RS: LazyLock<String> = LazyLock::new(|| {
    expect_marker(
        module_code("tray"),
        "src-tauri/src/tray（模块：tray.rs + tray/**，剔除 tests/）",
        "pub const TRAY_LABEL",
    )
});
/// 🔴 取材必须过 [`crate_code`]（剥注释），不是 `crate_source` 全文。
///
/// 下面 [`wired_once_at_boot`] 的三条针（`pin_tray_autosave_name(` 的**计数**、它与
/// `reconcile_tray(handle);` 的**先后**）全是单行代码文本，写进任何一行注释就够替生产接线作证。
/// 实测（批 D 复验）：把 `main.rs:964` 那行接线整行注释掉，全套件仍然全绿 —— 计数照旧是 1，
/// 顺序照旧成立，而 autosaveName 已经没人钉了。这是「注释喂饱正面断言」的教科书形态。
static MAIN_RS: LazyLock<String> = LazyLock::new(|| {
    expect_marker(
        crate_code("main.rs"),
        "src-tauri/src/main.rs",
        "\nfn main() {",
    )
});
static CARGO_TOML: LazyLock<String> = LazyLock::new(|| {
    expect_marker(
        crate_file("Cargo.toml"),
        "src-tauri/Cargo.toml",
        "\nname = \"polaris\"",
    )
});

/// 从源码里取 `TRAY_AUTOSAVE_NAME` 的字面量。
fn autosave_name_in_source() -> &'static str {
    let needle = "pub const TRAY_AUTOSAVE_NAME: &str = \"";
    let i = TRAY_RS
        .find(needle)
        .expect("找不到 TRAY_AUTOSAVE_NAME 的定义 —— 改名或挪窝了，先确认再动本门");
    let rest = &TRAY_RS[i + needle.len()..];
    &rest[..rest.find('"').expect("字面量没收口")]
}

/// 🔴 autosaveName 是**用户数据的钥匙**，改了等于把所有人已拖好的位置全丢，且无任何报错。
///
/// 期望值是**拼出来**的，不写成同一个字面量 —— 否则一次全局改名会把常量和判据一起改掉，
/// 门恒绿。这类「判据被自己污染」是源码级门最典型的失效方式，本门落地时就踩过一次：
/// 第一版把期望值直接写成 `"com.polaris.app.tray"`，验红时 sed 全局替换同时改了两处，
/// 变异**没红**。
#[test]
fn tray_autosave_name_is_frozen() {
    let frozen = ["com", "polaris", "app", "tray"].join(".");
    assert_eq!(
        autosave_name_in_source(),
        frozen,
        "TRAY_AUTOSAVE_NAME 的字面量变了。系统按 `NSStatusItem Preferred Position <名字>` 存位置，\
             换名字 = 换钥匙 = 所有用户已拖好的菜单栏位置当场全丢，而且丢完不会报错。\
             真要改，先想清楚这个代价再来动本门。"
    );
}

/// 🔴 必须在启动时调一次，且**只调一次**。
///
/// 反向也锁：放进 `reconcile_tray` 那两个汇流点里会被 30s 自愈轮询反复重设 —— 不会出错，
/// 但那是每 30 秒一次的无用功，且会掩盖「首次到底设没设上」这个信息。
#[test]
fn wired_once_at_boot() {
    let calls = MAIN_RS.matches("pin_tray_autosave_name(").count();
    assert_eq!(
        calls, 1,
        "main.rs 里 pin_tray_autosave_name 的调用点有 {calls} 处，应恰好 1 处（启动时一次）"
    );
    let i = MAIN_RS
        .find("pin_tray_autosave_name(")
        .expect("main.rs 没有调用 pin_tray_autosave_name —— 实现写了但没接线");
    let j = MAIN_RS
        .find("reconcile_tray(handle);")
        .expect("找不到托盘启动汇流点 —— 启动流程改过了，先确认再动本门");
    assert!(
        i < j,
        "pin_tray_autosave_name 排在托盘启动汇流点之后 —— 位置属性应在首次呈现前就位"
    );
}

/// 🔴 `objc2-app-kit` 必须开 `NSStatusItem` 与 `NSWindow` feature。
///
/// 这条门的存在理由很具体：漏了它 **mac 腿编不过，而本机（Linux）完全看不到** ——
/// 要等 CI 的 macOS 矩阵跑完才暴露，而那条腿是 10x 计费里最慢的一档。
#[test]
fn objc2_app_kit_has_nsstatusitem_feature() {
    let line = CARGO_TOML
        .lines()
        .find(|l| l.trim_start().starts_with("objc2-app-kit"))
        .expect("Cargo.toml 里找不到 objc2-app-kit");
    assert!(
        line.contains("\"NSStatusItem\"") && line.contains("\"NSWindow\""),
        "objc2-app-kit 没开 NSStatusItem/NSWindow feature —— 托盘位置或 non-activating 宿主在 mac 上编不过，\
             而本机看不到。当前行：{line}"
    );
}
