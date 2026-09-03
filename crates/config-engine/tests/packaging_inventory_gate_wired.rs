//! 打包腿必须真的在跑**包内容白名单**（`scripts/verify-packaging.mjs inventory`）。
//!
//! 为什么要有这条：那道门是 2026-08-29 才补上的，补它的直接起因是一批**已经出货**的夹带 ——
//! `resources/data/README*.md`（8 KB 开发文档）、0 字节 `.gitkeep`、面板的 gh-pages/PWA 残留
//! （`.nojekyll` / `sw.js` / `registerSW.js` / `workbox-*.js` / `manifest.webmanifest`）
//! 全都随四个平台的安装包分发过，而当时全链**零转红**。
//!
//! 门本身在 Node 脚本里，接线在 workflow 里。**没有本文件的话，把那几个 step 删掉不会有任何东西红**：
//! 单测全绿、`cargo check` rc=0、打包照样出包，缺陷类原样复活。故这里按 `package.yml` 的结构断言
//! 「哪条命令在什么条件下跑」。
//!
//! 判据形状同 `core_build_matrix::ci_step_still_wired`，但**多守两件事**（那条只 `contains` 裸串）：
//!
//!  1. **按 step 块解析，且剔掉注释行**。本仓两天内被「把 step 删掉、注释里留下同名字样」这个
//!     形状骗过两次；这里只认非注释行。
//!  2. **断言 (if 条件, 命令) 的集合恰好相等，不是「出现过」**。原因是 Windows 那条的 `--root
//!     target/release` 是 Linux 那条 `--root target/release/bundle` 的**前缀** —— 用 `contains`
//!     判 Windows 那条，只要 Linux 那条在就恒真，删掉 Windows 腿的门照样绿。
//!     计数同理不够：三条腿各一次与「同一条腿写三次」在数上无法区分，故连 `if` 一起对。

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("CARGO_MANIFEST_DIR 应形如 <repo>/crates/config-engine")
        .to_path_buf()
}

/// 一个 step 里跑到的、含 `needle` 的命令行（已剔注释），连同该 step 的 `if:` 条件。
///
/// 只按缩进认「`- name:` 开一个新块」，不做通用 YAML 解析 —— 本仓 workflow 的 step 形态固定，
/// 为一次断言引一个 YAML crate 不值得。结构变形（认不出块）的方向是**认到的命令变少 ⇒ 集合对不上 ⇒ 红**，
/// 不会假绿。
fn inventory_steps(workflow: &str, needle: &str) -> Vec<(Option<String>, String)> {
    let mut out = Vec::new();
    let mut cond: Option<String> = None;
    let mut cmds: Vec<String> = Vec::new();
    let flush = |cond: &mut Option<String>, cmds: &mut Vec<String>, out: &mut Vec<_>| {
        for c in cmds.drain(..) {
            out.push((cond.clone(), c));
        }
        *cond = None;
    };
    for raw in workflow.lines() {
        let line = raw.trim();
        if line.starts_with("- name:") {
            flush(&mut cond, &mut cmds, &mut out);
            continue;
        }
        if line.starts_with('#') {
            continue; // 注释里出现同款字样不算接线（本仓踩过两次的形状）
        }
        if let Some(rest) = line.strip_prefix("if:") {
            cond = Some(rest.trim().to_owned());
            continue;
        }
        if line.contains(needle) {
            // `run: <cmd>` 与块标量里的裸命令行都收（本仓这几步是前者）
            let cmd = line.strip_prefix("run:").unwrap_or(line).trim().to_owned();
            cmds.push(cmd);
        }
    }
    flush(&mut cond, &mut cmds, &mut out);
    out
}

#[test]
fn packaging_inventory_gate_wired() {
    let wf = repo_root().join(".github/workflows/package.yml");
    let raw =
        std::fs::read_to_string(&wf).unwrap_or_else(|e| panic!("读不到 {}: {e}", wf.display()));

    let mut got = inventory_steps(&raw, "verify-packaging.mjs inventory");
    got.sort();

    // 四条接线：构建前一遍静态推导口径（每条腿都跑，故**不带 if**），构建后三条腿各一遍产物/staging 口径。
    let mut want: Vec<(Option<String>, String)> = vec![
        (
            None,
            "node scripts/verify-packaging.mjs inventory --label ${{ matrix.label }} --static".to_owned(),
        ),
        (
            Some("runner.os == 'macOS'".to_owned()),
            "node scripts/verify-packaging.mjs inventory --label ${{ matrix.label }} --root target/${{ matrix.rust_target }}/release/bundle".to_owned(),
        ),
        (
            Some("runner.os == 'Linux'".to_owned()),
            "node scripts/verify-packaging.mjs inventory --label ${{ matrix.label }} --root target/release/bundle".to_owned(),
        ),
        (
            Some("runner.os == 'Windows'".to_owned()),
            "node scripts/verify-packaging.mjs inventory --label ${{ matrix.label }} --root target/release".to_owned(),
        ),
    ];
    want.sort();

    assert_eq!(
        got,
        want,
        "\n.github/workflows/package.yml 的**包内容白名单接线**与预期不符。\n\
         预期（4 条）：构建前 1 条静态推导口径（无 if，每条腿都跑）+ 构建后 mac/linux/windows 各 1 条产物口径。\n\
         实际解析到：{got:#?}\n\
         这道门守的是「不该进包的东西进没进包」：删掉/改条件/写错 --root，包里多夹带什么都不会再有东西红，\n\
         而 2026-08-29 之前正是这个状态 —— 开发文档、0 字节占位、面板 PWA 残留全都随四个平台出货过。\n\
         真要挪动这些 step，请连同本断言一起改，别只改一边。"
    );
}

#[test]
fn inventory_mode_still_exists_in_the_script() {
    // 接线还在、脚本里那个模式却没了 ⇒ CI 会以 exit 2「用法错误」红（不是假绿），
    // 但报错会指向「用法」而不是「门被摘了」。这里给出一条能直接读懂的失败信息。
    let script = repo_root().join("scripts/verify-packaging.mjs");
    let raw = std::fs::read_to_string(&script)
        .unwrap_or_else(|e| panic!("读不到 {}: {e}", script.display()));
    assert!(
        raw.contains("case 'inventory':"),
        "scripts/verify-packaging.mjs 里没有 `case 'inventory':` —— 包内容白名单模式被摘掉了，\
         而 package.yml 还在调它"
    );
    assert!(
        raw.contains("function payloadAllowRules("),
        "scripts/verify-packaging.mjs 里没有 payloadAllowRules() —— 登记表（白名单本体）被摘掉了"
    );
}
