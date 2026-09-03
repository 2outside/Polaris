//! `test_support` 的自证。
//!
//! # 本文件的位置本身就是判据
//!
//! 它在 `src-tauri/src/test_support/tests/mod.rs` —— 也就是**全仓测试外移之后**每个测试实体
//! 会落到的那个深度。下面所有取材调用写的都是「`src-tauri/src/` 里的哪个文件」，与本文件
//! 在第几层**无关**：`crate_source("tray.rs")` 在这里读到的仍然是 `src-tauri/src/tray.rs`。
//!
//! 换成旧写法就不成立：在这个位置 `include_str!("tray.rs")` 指的是
//! `src-tauri/src/test_support/tests/tray.rs`。今天它不存在（编译期红），但 143 处站点里
//! 有 129 处是同目录裸文件名，搬家后**大量会撞上另一个真实存在的同名文件** —— 那才是
//! 真正的失败模式：编译过、门全绿、扫的却是别的文件。
//!
//! # 跨 crate 那一半
//!
//! `polaris-source-probe` 内部**不读** `env!("CARGO_MANIFEST_DIR")`（读了会解析成
//! `crates/source-probe`）。锚点由本 crate 的 wrapper 传入，而「传进去的确实是 src-tauri」
//! 只能在 src-tauri 这一侧证 —— 就是下面第一条。

use super::*;

/// 与 [`crate::commands::misc`] 各文件一一对应的独有标识。
///
/// 按 `(文件, 标识)` 成对断言而不是「blob 里有就行」：后者在「拼接顺序错乱 / 只读到一个文件」
/// 时照样绿，前者能指出是哪个文件掉了。
///
/// **第一条是模块根 `misc.rs`**：一个 Rust 模块的源码分布在 `foo.rs` 与目录 `foo/` 两处，
/// 取材面漏掉根文件就是只有一半判据（2026-08-30 修复前 `module_source` 正是只走目录）。
const MISC_MARKERS: [(&str, &str); 7] = [
    (
        "misc.rs",
        "pub use autostart::{auto_start_get_status, auto_start_set}",
    ),
    ("autostart.rs", "pub fn auto_start_set"),
    ("backup.rs", "pub async fn backup_export"),
    ("dashboard.rs", "pub fn open_singbox_dashboard"),
    ("ipinfo.rs", "pub(crate) fn ipinfo_probe_is_current"),
    ("logs.rs", "pub(crate) fn clear_log_stream_window"),
    ("support.rs", "pub(super) fn node_platform"),
];

#[test]
fn removes_directory_during_panic_unwind() {
    let mut path = None;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let dir = TestDir::new("polaris-test-support-");
        path = Some(dir.path().to_path_buf());
        std::fs::write(dir.join("sentinel"), b"owned").unwrap();
        panic!("exercise unwind");
    }));
    assert!(result.is_err());
    assert!(!path.unwrap().exists());
}

// ── 锚点：与调用方文件位置无关 ────────────────────────────────────────────

/// 🔴 **本次改造的核心断言**：取材锚点钉在 crate 根，不随测试实体的深度移动。
///
/// # 为什么本条是全仓唯一**保留** `crate_source("tray.rs")` 的地方
///
/// 其余三处 tray 守卫（`tray/tests/mod.rs`、`overlay_lifecycle_gate.rs`、`autosave_name_gate.rs`）
/// 已改用 `module_source("tray")`，因为它们守的是**托盘的行为**，而托盘的实现正在按域拆进
/// `tray/**`，取材面必须跟着模块走。本条守的不是托盘，是 [`crate_source`] **自己**：
/// 「单文件锚点解析到的到底是不是 `<crate>/src/<rel>`」。把它一起换成 `module_source`
/// 等于删掉这条测试——`module_source` 是另一个函数，证不了 `crate_source` 的锚点算得对，
/// 而 `crate_source` 仍是全仓 100+ 处单文件取材的实现单点。
///
/// 代价已兑现（Phase 4A 批 B7）：本条原先引用 `TRAY_AUTOSAVE_NAME` / `pin_tray_autosave_name`，
/// 两者随 `tray/platform.rs` 搬走后本条如期**响红**（`expect_marker` 在变薄的门面上找不到哨兵）。
/// 按上面写好的修法，哨兵换成 façade 里**无搬移计划**的稳定符号（`pub const TRAY_LABEL`，
/// 证「读到的是 tray.rs 不是别的文件」），锚点仍是 `crate_source`——换成 `module_source`
/// 就把这条元测试的判据抽走了。「读到全文」不靠第二个 contains 串：B7 复验实测两个 contains
/// 串全落在门面前 26%（读到 121/461 行即可全绿），判据③曾实质退化——改用 `ends_with`
/// 钉住物理末行 `mod tests;`（façade 恒以 `#[cfg(test)] mod tests;` 收尾，B8 搬走
/// commands/transition 后仍在），读不到末尾必红，且未来尾部变化会如期响红提示换锚。
///
/// 三件事一次证完：
///  ① 跨 crate 的 `env!("CARGO_MANIFEST_DIR")` 拿到的是 **src-tauri**（不是 source-probe）；
///  ② 从 `src/test_support/tests/` 这个深度仍然读得到 `src/tray.rs`；
///  ③ 同位置的旧写法**指向别处** —— 用「那个路径不存在」把差异摆出来，而不是嘴上说。
#[test]
fn crate_source_anchors_on_the_crate_root_not_on_this_files_location() {
    let tray = expect_marker(
        crate_source("tray.rs"),
        "src-tauri/src/tray.rs",
        "pub const TRAY_LABEL",
    );
    assert!(
        tray.ends_with("mod tests;\n"),
        "读到的不是 tray.rs 的全文（物理末行应为 `mod tests;`）"
    );

    // ③ 旧写法在本文件位置会指向 `src/test_support/tests/tray.rs`。
    let drifted =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/test_support/tests/tray.rs");
    assert!(
        !drifted.exists(),
        "`{}` 竟然存在 —— 那么在本文件里写 `include_str!(\"tray.rs\")` 会**静默**读到它，\
         这正是本次换锚点要消灭的失败模式；此时本条对照失效，需要换一个演示路径。",
        drifted.display()
    );
}

/// crate 根下的非源码（`Cargo.toml`）与仓库根下的跨语言判据源（`ui/index.html`）
/// 各有自己的锚点，且同样与调用方位置无关。
#[test]
fn crate_file_and_repo_file_have_their_own_fixed_anchors() {
    assert!(
        crate_file("Cargo.toml").contains("name = \"polaris\""),
        "crate_file 没读到 src-tauri 自己的 Cargo.toml"
    );
    let index = expect_marker(
        repo_file("ui/index.html"),
        "ui/index.html",
        "<title>Polaris</title>",
    );
    assert!(
        index.contains("Content-Security-Policy"),
        "repo_file 没读到仓库根的 ui/index.html 全文"
    );
}

// ── module_source：真实模块上的覆盖面 ─────────────────────────────────────

/// 🔴 逐文件核对：目录里**每个**生产 `.rs` 都在取材面内，且映射到对的那个文件。
///
/// 文件数直接与磁盘实况对差 —— 「少读了一个」和「多读了一个」都当场红，不靠人去数。
#[test]
fn module_source_covers_every_production_file_of_a_real_module() {
    let files = module_files("commands/misc");
    // 磁盘实况 = **模块根文件 + 目录下的生产 `.rs`**。只数目录是上一版的错误模型：
    // 那样 `misc.rs` 掉出取材面而本条照样绿 —— 判据自己认可了缺一半的取材面。
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let on_disk = std::fs::read_dir(src.join("commands/misc"))
        .expect("读 commands/misc")
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|x| x == "rs"))
        .count()
        + usize::from(src.join("commands/misc.rs").is_file());
    assert_eq!(files.len(), on_disk, "取材文件数与磁盘实况对不上");
    assert!(
        files.iter().any(|(rel, _)| rel == "misc.rs"),
        "取材面里没有模块根 `misc.rs` —— 模块的源码有一半在根文件里"
    );
    assert_eq!(files.len(), MISC_MARKERS.len(), "夹具清单该更新了");

    for (name, marker) in MISC_MARKERS {
        let (_, text) = files
            .iter()
            .find(|(rel, _)| rel == name)
            .unwrap_or_else(|| panic!("取材面缺 `{name}`"));
        assert!(
            text.contains(marker),
            "`{name}` 读到的内容里没有它的独有标识 `{marker}`"
        );
    }

    // 拼接形态必须含全部标识（证明真拼接，不是只读了第一个）。
    let blob = module_source("commands/misc");
    for (name, marker) in MISC_MARKERS {
        assert!(blob.contains(marker), "拼接结果里缺 `{name}` 的内容");
    }
}

/// 🔴 **副本**上验「新增子模块自动进取材面」：把真实模块整个拷进临时 crate 布局，
/// 先取基线，再落一个新 `.rs`，取材面必须自动 +1。
///
/// 只碰副本：工作树全程有别的改动在跑，验证不得依赖也不得触碰它。
#[test]
fn a_newly_added_file_enters_the_scan_surface_on_a_copy_of_a_real_module() {
    const ADDED: &str = "pub fn newly_added_submodule_marker() {}";

    let scratch = TestDir::new("polaris-module-source-copy-");
    let dst = scratch.join("src").join("misc");
    std::fs::create_dir_all(&dst).expect("建副本目录");
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/commands/misc");
    for entry in std::fs::read_dir(&src).expect("读源模块") {
        let path = entry.expect("目录项").path();
        if path.extension().is_some_and(|x| x == "rs") {
            std::fs::copy(&path, dst.join(path.file_name().expect("文件名"))).expect("拷贝");
        }
    }
    // **模块根也要拷**：一个 Rust 模块是「`foo.rs` + 目录 `foo/`」两处。只拷目录的副本不是
    // 这个模块的副本，而是它的一半 —— 建在这种副本上的「取材面 +1」对照会算错基数。
    std::fs::copy(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/commands/misc.rs"),
        scratch.join("src").join("misc.rs"),
    )
    .expect("拷模块根");

    let before = polaris_source_probe::module_files_in(scratch.path(), "misc");
    assert_eq!(before.len(), MISC_MARKERS.len(), "副本没拷全");
    assert!(
        !polaris_source_probe::module_source_in(scratch.path(), "misc").contains(ADDED),
        "正向对照失效：新增前副本里就已经有这段内容"
    );

    std::fs::write(dst.join("newly_added.rs"), ADDED).expect("落新模块");

    let after = polaris_source_probe::module_source_in(scratch.path(), "misc");
    assert!(after.contains(ADDED), "新增的子模块没有自动进取材面");
    assert_eq!(
        polaris_source_probe::module_files_in(scratch.path(), "misc").len(),
        before.len() + 1,
        "取材文件数没有 +1"
    );
}

/// 🔴 `tests/` 不得进生产扫描面：测试代码充数会让否定型断言失真。
///
/// 用副本造一个 `misc/tests/mod.rs`（本仓测试外移后的真实形态），断言它的内容不在取材面内。
#[test]
fn a_tests_directory_stays_out_of_the_scan_surface_on_a_copy() {
    const IN_TESTS: &str = "FIXTURE_CONTENT_THAT_MUST_NOT_REACH_THE_SCAN_SURFACE";

    let scratch = TestDir::new("polaris-module-source-tests-");
    let module = scratch.join("src").join("misc");
    std::fs::create_dir_all(module.join("tests")).expect("建副本目录");
    std::fs::write(module.join("real.rs"), "pub fn production_marker() {}").expect("写生产文件");
    std::fs::write(module.join("tests").join("mod.rs"), IN_TESTS).expect("写测试文件");

    let blob = polaris_source_probe::module_source_in(scratch.path(), "misc");
    assert!(blob.contains("production_marker"), "生产文件反而没进取材面");
    assert!(
        !blob.contains(IN_TESTS),
        "`tests/` 的内容混进了生产扫描面 —— 基于它的否定型断言会被测试夹具顶红/顶绿"
    );
}
