//! **测试代码不许用 `include_str!` 取材**——源码级门。
//!
//! `include_str!` 的相对路径锚在**含它的那个文件**。本仓正在把测试实体从 `foo.rs` 外移到
//! `foo/tests/mod.rs`，测试文件的深度因此会变；每一处 `include_str!("../x.rs")` 的 `..` 个数
//! 都是一个随之失效的锚点。失效形态分两种：
//!
//! - 平移后路径不存在 ⇒ 编译错误（吵，但能查）；
//! - 平移后**恰好命中另一个真实文件** ⇒ 编译通过、门继续绿、扫的却是别的东西。**这是假绿。**
//!
//! 替代品是 `polaris-source-probe`：锚点固定在 crate 根 / 仓库根（`CARGO_MANIFEST_DIR`），
//! 与调用方文件的位置无关，所以外移不改变取材。
//!
//! 本门的作用是让这次一次性替换**不再退回去**：新写的测试若又用 `include_str!`，当场红。
//! 没有这条门，前面那一百多处替换只是一次快照，几个月后会重新长回来。
//!
//! # 取材面
//!
//! workspace 全部成员的 `src/` 与 `tests/` 下的 `.rs`（`Cargo.toml` 的 `members` 推导，
//! 不手写清单）。命中前先用 [`polaris_source_probe::mask_comments_and_strings`] 剥掉注释与
//! 字面量 —— 本门自己的说明里就写满了 `include_str!`，不剥就全是假阳性。

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// 被禁的取材宏。
///
/// `include_bytes!` 与 `include_str!` 的锚点语义**完全一样**（都锚在含它的那个文件），
/// 失效方式也一样。只因为它取的是二进制而不是文本就漏掉不管，等于按类型分类而不是按缺陷分类
/// —— 本门第一版正是这么写的，随后 Batch A 把 8 处 `include_bytes!("../../../icons/*.png")`
/// 从 `app_tray.rs` 搬进 `app_tray/tests/mod.rs`，那串 `..` 整体平移，门一声不吭。
const FORBIDDEN: &[&str] = &["include_str!", "include_bytes!"];

/// 永久白名单：每条必须**恰好命中一次**，多了少了都红。
///
/// 「恰好一次」不是洁癖：白名单条目命中 0 次说明它守的东西已经没了，条目本身成了将来某个
/// 真违规的免死金牌；命中多次说明一条豁免悄悄覆盖了它没打算覆盖的地方。
/// **当前为空**：唯一一条（门 C 的棘轮基线清单 `data/gate_c_baseline.txt`）已随 Batch A 收尾
/// 删除，本门当场按设计报「命中 0 次」把清理逼了出来 —— 那正是「恰好一次」这条规则的用途。
///
/// 机制保留而不是连同 [`Exempt`] 一起删掉：下一个要开豁免的人必须落进这套防腐规则里，
/// 而不是自己新起一个没有过期检查的例外表。
const WHITELIST: [Exempt; 0] = [];

struct Exempt {
    /// 仓库相对路径（`/` 分隔）。
    file: &'static str,
    /// 为什么这条可以豁免。写清楚是为了让下一个人判断得了它还该不该在。
    reason: &'static str,
}

/// 一处命中。
#[derive(Debug)]
struct Hit {
    file: String,
    line: usize,
    /// 判定为测试代码的依据。
    why: &'static str,
}

fn workspace_root() -> PathBuf {
    polaris_source_probe::workspace_root_from(env!("CARGO_MANIFEST_DIR"))
}

/// 从 workspace 根 `Cargo.toml` 的 `members` 推导成员目录。
///
/// 不手写清单：新加一个 crate 就该自动进取材面，否则「新 crate 里的测试」是本门的永久盲区。
fn workspace_members(root: &Path) -> Vec<PathBuf> {
    let manifest =
        std::fs::read_to_string(root.join("Cargo.toml")).expect("读不到 workspace 根 Cargo.toml");
    let masked = mask_toml_comments(&manifest);
    let start = masked
        .find("members")
        .expect("workspace 根 Cargo.toml 没有 members");
    let open = masked[start..].find('[').expect("members 后面没有 `[`") + start;
    let close = masked[open..].find(']').expect("members 列表没有闭合 `]`") + open;

    let mut members = Vec::new();
    for raw in manifest[open + 1..close].split(',') {
        let entry = raw.trim().trim_matches('"').trim();
        if entry.is_empty() {
            continue;
        }
        if let Some(prefix) = entry.strip_suffix("/*") {
            let dir = root.join(prefix);
            let entries = std::fs::read_dir(&dir).unwrap_or_else(|err| {
                panic!("读不到 members 通配目录 `{}`（{err}）", dir.display())
            });
            for child in entries.flatten() {
                let path = child.path();
                if path.join("Cargo.toml").is_file() {
                    members.push(path);
                }
            }
        } else {
            members.push(root.join(entry));
        }
    }
    members.sort();
    assert!(
        !members.is_empty(),
        "members 解析出来是空的 —— 取材面为空，本门会恒真"
    );
    members
}

/// TOML 行注释抹成空格（保留长度与换行），避免注释里的 `members` 把定位带偏。
fn mask_toml_comments(source: &str) -> String {
    source
        .lines()
        .map(|line| match line.find('#') {
            Some(at) => format!("{}{}", &line[..at], " ".repeat(line.len() - at)),
            None => line.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// 递归收集目录下的 `.rs`（相对仓库根的 `/` 分隔路径）。
fn collect_rs(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs(root, &path, out);
            continue;
        }
        if path.extension().is_some_and(|ext| ext == "rs") {
            let rel = path
                .strip_prefix(root)
                .expect("文件不在仓库根内")
                .to_string_lossy()
                .replace('\\', "/");
            out.push((rel, path));
        }
    }
}

/// 取材面：全部成员的 `src/` 与 `tests/` 下的 `.rs`。
fn scan_surface() -> Vec<(String, PathBuf)> {
    let root = workspace_root();
    let mut files = Vec::new();
    for member in workspace_members(&root) {
        for sub in ["src", "tests"] {
            let dir = member.join(sub);
            if dir.is_dir() {
                collect_rs(&root, &dir, &mut files);
            }
        }
    }
    files.sort();
    assert!(!files.is_empty(), "取材面是空的 —— 本门会恒真");
    files
}

/// `masked` 中所有「被 `#[cfg(…test…)]` 罩住的花括号块」的字节区间。
///
/// **不是过渡期规则**（2026-08-30 订正）。Batch A 之后内联 `#[cfg(test)] mod … { }` 确实归零，
/// 但门 C 禁的只有内联 **mod**：生产文件里的 `#[cfg(test)] fn` / `#[cfg(test)] impl`
/// 一直合法且大量存在（`runtime/helper.rs`、`runtime/proxy.rs` 各有十余处）。那些同样是
/// 测试代码，路径腿看不见它们 —— 删掉本腿就等于把这一整类放行。
///
/// 谓词用「属性文本里含 `test`」而不是完整的 cfg 求值：过宽的方向命中的是
/// `cfg(feature = "test-utils")` 这类 —— 那**也是**只在测试里编译的代码，红得不冤。
fn cfg_test_regions(masked: &str) -> Vec<(usize, usize)> {
    let bytes = masked.as_bytes();
    let mut regions = Vec::new();
    let mut from = 0usize;
    while let Some(offset) = masked[from..].find("#[cfg(") {
        let start = from + offset;
        let mut depth = 0usize;
        let mut i = start + 1;
        while i < bytes.len() {
            match bytes[i] {
                b'[' => depth += 1,
                b']' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        from = i + 1;
        if !masked[start..i.min(masked.len())].contains("test") {
            continue;
        }
        // 声明形态（`#[cfg(test)] mod tests;`）没有块体：它指向的文件由路径规则覆盖。
        let brace = masked[i..].find('{').map(|off| i + off);
        let semi = masked[i..].find(';').map(|off| i + off);
        let Some(open) = brace else { continue };
        if semi.is_some_and(|s| s < open) {
            continue;
        }
        let mut depth = 0usize;
        let mut j = open;
        while j < bytes.len() {
            match bytes[j] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            j += 1;
        }
        regions.push((start, j));
        from = from.max(open + 1);
    }
    regions
}

fn scan() -> Vec<Hit> {
    let mut hits = Vec::new();
    for (rel, path) in scan_surface() {
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("读不到 `{}`（{err}）", path.display()));
        let masked = polaris_source_probe::mask_comments_and_strings(&source);
        if !FORBIDDEN.iter().any(|needle| masked.contains(needle)) {
            continue;
        }
        let in_tests_dir = rel.contains("/tests/");
        let regions = if in_tests_dir {
            Vec::new()
        } else {
            cfg_test_regions(&masked)
        };
        for needle in FORBIDDEN {
            let mut from = 0usize;
            while let Some(offset) = masked[from..].find(needle) {
                let at = from + offset;
                from = at + needle.len();
                let why = if in_tests_dir {
                    "文件在 `tests/` 目录下（本仓约定：`<dir>/tests/` 恒为测试）"
                } else if regions.iter().any(|(a, b)| *a <= at && at <= *b) {
                    "位于 `#[cfg(…test…)]` 罩住的块内"
                } else {
                    continue;
                };
                hits.push(Hit {
                    file: rel.clone(),
                    line: masked[..at].matches('\n').count() + 1,
                    why,
                });
            }
        }
    }
    hits
}

/// 🔴 测试代码里不许出现 `include_str!`。
///
/// **变异探针**：在任意 `#[cfg(test)] mod` 里加一行 `let _ = include_str!("Cargo.toml");`
/// ⇒ 本条转红并点名 `文件:行号`；把它挪到该块外（真生产代码）⇒ 恢复绿。
#[test]
fn test_code_uses_source_probe_anchors_not_include_str() {
    let hits = scan();
    let exempt_files: BTreeSet<&str> = WHITELIST.iter().map(|e| e.file).collect();
    let violations: Vec<&Hit> = hits
        .iter()
        .filter(|hit| !exempt_files.contains(hit.file.as_str()))
        .collect();

    assert!(
        violations.is_empty(),
        "测试代码里仍有 {} 处 `include_str!` / `include_bytes!`。它们的相对路径锚在含它的那个文件，测试实体一外移就整体平移，\
         而平移后**撞上另一个真实文件**时编译通过、门继续绿、扫的却是别的东西。\n\
         改用 `crate_source` / `crate_file` / `repo_file` / `module_source`（`src-tauri` 走 \
         `crate::test_support::*`，其他 crate 走 `polaris_source_probe::*!` 宏）。\n{}",
        violations.len(),
        violations
            .iter()
            .map(|hit| format!("  {}:{}（{}）", hit.file, hit.line, hit.why))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// 🔴 每条白名单必须恰好命中一次。
///
/// 命中 0 次 = 它守的东西没了，条目成了将来某个真违规的免死金牌；命中多次 = 一条豁免
/// 覆盖了它没打算覆盖的地方。两种都必须红。
#[test]
fn whitelist_entries_must_all_match_exactly_once() {
    let hits = scan();
    for exempt in WHITELIST {
        let count = hits.iter().filter(|hit| hit.file == exempt.file).count();
        assert_eq!(
            count, 1,
            "白名单 `{}` 命中 {count} 次（应为 1）。豁免理由：{}",
            exempt.file, exempt.reason
        );
    }
}

/// 🔴 取材面自检：`src/` 与 `tests/` 两侧都必须真的进面，且成员是从 `members` 推导的。
///
/// 没有这条时，「members 解析写错导致只扫到一个 crate」会让上面两条门静默变宽。
#[test]
fn scan_surface_covers_both_src_and_tests_across_members() {
    let files = scan_surface();
    assert!(
        files
            .iter()
            .any(|(rel, _)| rel.starts_with("src-tauri/src/")),
        "取材面里没有 `src-tauri/src/`"
    );
    assert!(
        files
            .iter()
            .any(|(rel, _)| rel.starts_with("src-tauri/tests/")),
        "取材面里没有 `src-tauri/tests/`"
    );
    assert!(
        files.iter().any(|(rel, _)| rel.starts_with("crates/")),
        "取材面里没有任何 `crates/` 成员 —— members 通配没展开"
    );
    let crates: BTreeSet<&str> = files
        .iter()
        .filter_map(|(rel, _)| rel.strip_prefix("crates/"))
        .filter_map(|rest| rest.split('/').next())
        .collect();
    assert!(
        crates.len() > 5,
        "只扫到 {} 个 crate，members 解析多半只取到了第一条。实际：{crates:?}",
        crates.len()
    );
}

// ============================================================================
// 测试模块的接线：外移之后「没接上」是静默的
// ============================================================================

/// 测试实体从 `foo.rs` 外移到 `foo/tests/mod.rs` 时，漏写 `foo.rs` 里那句 `mod tests;`
/// 的后果是**静默的**：Rust 对未被任何 `mod` 声明引用的 `.rs` 文件不给任何警告，
/// 于是编译通过、门 C（内联块清零）转绿、而那个文件的全部测试**从此不再运行**。
///
/// 同一形态有三个方向，本节逐个钉死：
///
/// | 方向 | 失效形态 | 会不会自曝 |
/// |---|---|---|
/// | `foo/tests/mod.rs` 存在但 `foo.rs` 没声明 | 整个文件的测试消失 | **否**，编译照过 |
/// | `foo/tests/x.rs` 存在但 `tests/mod.rs` 没声明 | 该子域的测试消失 | **否** |
/// | `foo.rs` 声明了但文件不存在 | — | 是（编译错误），故不用建门 |
///
/// 前两个方向的共同点：**少运行一批测试，看起来和「测试都过了」一模一样。**
/// 这正是 Batch A（239 文件 / 279 块外移）最主要的翻车方式，故门先于批次建。
/// `mod` 声明用剥过注释与字面量的文本判定 —— 注释掉的 `// mod tests;` 不算数。
fn declares_module(parent_source: &str, name: &str) -> bool {
    let masked = polaris_source_probe::mask_comments_and_strings(parent_source);
    let needle = format!("mod {name};");
    masked.contains(&needle)
}

/// `<member>/src` 下所有 `tests` 目录（相对仓库根）。
fn test_dirs() -> Vec<PathBuf> {
    let root = workspace_root();
    let mut dirs = Vec::new();
    for member in workspace_members(&root) {
        let src = member.join("src");
        if src.is_dir() {
            collect_test_dirs(&src, &mut dirs);
        }
    }
    dirs.sort();
    dirs
}

fn collect_test_dirs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if path.file_name().is_some_and(|n| n == "tests") {
            out.push(path.clone());
        }
        collect_test_dirs(&path, out);
    }
}

/// 🔴 每个 `<dir>/tests/` 都必须被它的父模块用 `mod tests;` 真正接上。
///
/// **变异探针**：把任意一处 `#[cfg(test)]\nmod tests;` 注释掉 ⇒ 本条转红并点名那个目录。
/// 注意这个变异**不会**让 `cargo test` 变红 —— 它只会让计数悄悄变小，这就是本门存在的理由。
#[test]
fn every_test_directory_is_wired_into_its_parent_module() {
    let root = workspace_root();
    let dirs = test_dirs();
    assert!(
        !dirs.is_empty(),
        "一个 `tests/` 目录都没扫到 —— 取材面塌了，本门会恒真"
    );

    let mut orphans = Vec::new();
    for dir in &dirs {
        let rel = dir
            .strip_prefix(&root)
            .expect("目录不在仓库根内")
            .to_string_lossy()
            .replace('\\', "/");
        let parent = dir.parent().expect("tests 目录必有父目录");
        // 父模块的两种落点：`<parent>.rs`（同级兄弟文件）或 `<parent>/mod.rs`。
        // `<member>/src/tests/` 的父是 crate 根，即 `lib.rs` / `main.rs`。
        let candidates: Vec<PathBuf> = if parent.file_name().is_some_and(|n| n == "src") {
            vec![parent.join("lib.rs"), parent.join("main.rs")]
        } else {
            let mut v = vec![parent.join("mod.rs")];
            if let Some(name) = parent.file_name() {
                v.push(
                    parent
                        .parent()
                        .expect("模块目录必有父目录")
                        .join(format!("{}.rs", name.to_string_lossy())),
                );
            }
            v
        };
        let wired = candidates.iter().any(|candidate| {
            std::fs::read_to_string(candidate).is_ok_and(|src| declares_module(&src, "tests"))
        });
        if !wired {
            orphans.push(format!(
                "  {rel}  ← 找不到 `mod tests;` 声明（找过：{}）",
                candidates
                    .iter()
                    .map(|c| c
                        .strip_prefix(&root)
                        .unwrap_or(c)
                        .to_string_lossy()
                        .replace('\\', "/"))
                    .collect::<Vec<_>>()
                    .join("、")
            ));
        }
    }

    assert!(
        orphans.is_empty(),
        "有 {} 个 `tests/` 目录没被父模块接上。**这不会让编译或 `cargo test` 转红** —— \
         它只会让那些测试从此不再运行，计数悄悄变小，看起来和「全过了」一模一样：\n{}",
        orphans.len(),
        orphans.join("\n")
    );
}

/// 🔴 `tests/` 目录里的每个 `*.rs` 都必须在同目录 `mod.rs` 里被声明。
///
/// 与上一条同源：子文件没被 `mod x;` 引用同样是静默失效。
///
/// **变异探针**：在任意 `tests/mod.rs` 里注释掉一条 `mod x;` ⇒ 本条转红并点名 `x.rs`。
#[test]
fn every_file_in_a_test_directory_is_declared_in_its_mod_rs() {
    let root = workspace_root();
    let mut orphans = Vec::new();
    let mut checked = 0usize;

    for dir in test_dirs() {
        let mod_rs = dir.join("mod.rs");
        let Ok(mod_source) = std::fs::read_to_string(&mod_rs) else {
            orphans.push(format!(
                "  {}  ← 缺 `mod.rs`（本仓约定测试模块是 `<dir>/tests/mod.rs` 形态）",
                dir.strip_prefix(&root).unwrap_or(&dir).to_string_lossy()
            ));
            continue;
        };
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // 子目录形态（`tests/foo/mod.rs`）同样要被声明。
                if let Some(name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) {
                    checked += 1;
                    if !declares_module(&mod_source, &name) {
                        orphans.push(format!(
                            "  {}/  ← `{}` 里没有 `mod {name};`",
                            path.strip_prefix(&root).unwrap_or(&path).to_string_lossy(),
                            mod_rs
                                .strip_prefix(&root)
                                .unwrap_or(&mod_rs)
                                .to_string_lossy()
                        ));
                    }
                }
                continue;
            }
            if !path.extension().is_some_and(|ext| ext == "rs") {
                continue;
            }
            let stem = path
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            if stem == "mod" {
                continue;
            }
            checked += 1;
            if !declares_module(&mod_source, &stem) {
                orphans.push(format!(
                    "  {}  ← `{}` 里没有 `mod {stem};`",
                    path.strip_prefix(&root).unwrap_or(&path).to_string_lossy(),
                    mod_rs
                        .strip_prefix(&root)
                        .unwrap_or(&mod_rs)
                        .to_string_lossy()
                ));
            }
        }
    }

    assert!(
        orphans.is_empty(),
        "有 {} 个测试文件/子目录没被同目录 `mod.rs` 声明（同样是静默失效：少跑一批测试与全过一模一样）：\n{}",
        orphans.len(),
        orphans.join("\n")
    );
    // 自检：`checked` 为 0 说明所有 `tests/` 目录都只有 `mod.rs`，
    // 上面那个循环从未真正判定过任何东西 —— Batch A 之后这个数会变大，
    // 现在只要求它不 panic，不设下限（今天确实可能为 0）。
    let _ = checked;
}

/// 🔴 文件形态的 `tests.rs` 全仓禁绝。
///
/// 本仓约定 `<dir>/*.rs` 恒为生产、`<dir>/tests/` 恒为测试；`<dir>/tests.rs` 的归属不可判，
/// 会让按目录取材的门要么把测试算进生产扫描面（否定型断言被测试代码喂饱 ⇒ 假绿），
/// 要么跳过它而漏掉真生产文件。`polaris_source_probe::module_files_in` 撞见它直接 panic，
/// 但那只在有人**恰好**对那个目录取材时才触发 —— 本条把它提前到全仓层面。
///
/// **变异探针**：`touch crates/store/src/tests.rs` ⇒ 本条转红。
#[test]
fn no_file_shaped_test_modules_anywhere() {
    let root = workspace_root();
    let offenders: Vec<String> = scan_surface()
        .into_iter()
        .filter(|(rel, _)| rel.ends_with("/tests.rs"))
        .map(|(rel, _)| rel)
        .collect();
    let _ = &root;
    assert!(
        offenders.is_empty(),
        "存在文件形态的测试模块（本仓约定是 `<dir>/tests/mod.rs`）：\n  {}\n\
         归属不可判会让按目录取材的门在「算进生产面」与「漏掉真生产文件」之间二选一，\
         两条都通向假绿。",
        offenders.join("\n  ")
    );
}

// ============================================================================
// 目录与文件命名：两套命名空间，各自内部统一
// ============================================================================

/// 仓库里 `-` 与 `_` 并存不是漏改，是**两套命名空间**，边界由语言划：
///
/// | 命名空间 | 约定 | 为什么 |
/// |---|---|---|
/// | Rust 模块（`<member>/src/**`、`<member>/tests/**` 下的目录与 `.rs`） | `snake_case` | **语言强制**：`-` 不是合法标识符字符，`mod dns-race;` 编不过。想用 kebab 目录只能靠 `#[path]`，而本仓禁用 `#[path]` |
/// | 其它一切（crate 根、前端、脚本、资源、仓库根） | `kebab-case` | 仓库约定；Cargo 包名本身也是 kebab（`polaris-dns-race`） |
///
/// 所以 `crates/dns-race/`（crate 根，kebab）里装着 `src/dns_race/`（模块，snake）是**对的**。
///
/// 本门把「碰巧一致」变成「守得住」：两侧各自不许出现对方的分隔符。
///
/// **变异探针**：`mkdir crates/store/src/foo-bar` ⇒ Rust 侧转红；
/// `mkdir crates/foo_bar` ⇒ 非 Rust 侧转红。
#[test]
fn directory_and_file_naming_is_uniform_within_each_namespace() {
    let root = workspace_root();
    let mut rust_side = Vec::new();
    let mut kebab_side = Vec::new();

    // ── Rust 模块命名空间：`-` 一律违规 ──────────────────────────────────
    for member in workspace_members(&root) {
        for sub in ["src", "tests"] {
            let dir = member.join(sub);
            if !dir.is_dir() {
                continue;
            }
            let mut found = Vec::new();
            // 取材面的根是 `src` / `tests` **本身**，不是仓库根：`crates/dns-race/` 这一层是
            // crate 根（kebab，归另一套命名空间），把它算进来会误报。
            collect_rs(&dir, &dir, &mut found);
            for (rel, _) in found {
                // 文件名与它上面每一层（到 `src`/`tests` 为止）都参与判定。
                if let Some(part) = rel.split('/').find(|part| part.contains('-')) {
                    let full = format!(
                        "{}/{sub}/{rel}",
                        member
                            .strip_prefix(&root)
                            .unwrap_or(&member)
                            .to_string_lossy()
                            .replace('\\', "/")
                    );
                    rust_side.push(format!("  {full}（成分 `{part}` 含 `-`）"));
                }
            }
        }
    }

    // ── 非 Rust 命名空间：`_` 一律违规 ──────────────────────────────────
    // 取材面点名而非全仓遍历：`target/` `node_modules/` `src-tauri/gen/` 是生成物，
    // 命名不由本仓决定，扫它们只会产出改不了的红。
    for area in ["crates", "ui/src", "scripts", "resources", "packaging"] {
        let dir = root.join(area);
        if !dir.is_dir() {
            continue;
        }
        let mut stack = vec![(dir, area.to_string())];
        while let Some((cur, rel)) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&cur) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let Some(name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else {
                    continue;
                };
                if name.starts_with('.') {
                    continue;
                }
                let child_rel = format!("{rel}/{name}");
                // 取材面只覆盖**本仓决定命名的东西**。`resources/dashboard/` 是 fetch 下来的
                // 上游产物（sing-box 面板的 gh-pages 构建），文件名是打包器的内容哈希
                // （`terminalThemes-D55_FX1d.js`），本仓改不了也不该改 —— 与排除 `target/`、
                // `node_modules/`、`src-tauri/gen/` 同理。这不是「为了变绿开的白名单」，
                // 是取材面本来就不该包含它。
                if child_rel == "resources/dashboard" {
                    continue;
                }
                if path.is_dir() {
                    // `crates/<pkg>/` 之下就进入 Rust 的地盘了，交给上一段判。
                    if rel == "crates" {
                        if name.contains('_') {
                            kebab_side.push(format!("  {child_rel}/（crate 根目录含 `_`）"));
                        }
                        continue;
                    }
                    if name.contains('_') {
                        kebab_side.push(format!("  {child_rel}/（目录名含 `_`）"));
                    }
                    stack.push((path, child_rel));
                    continue;
                }
                if name.contains('_') {
                    kebab_side.push(format!("  {child_rel}（文件名含 `_`）"));
                }
            }
        }
    }

    assert!(
        rust_side.is_empty(),
        "Rust 模块命名空间里出现了 `-`（模块名必须是合法标识符，`-` 编不过；\
         用 kebab 目录只能靠本仓禁用的 `#[path]`）：\n{}",
        rust_side.join("\n")
    );
    assert!(
        kebab_side.is_empty(),
        "非 Rust 命名空间里出现了 `_`（本仓这一侧统一 kebab-case，Cargo 包名亦然）：\n{}",
        kebab_side.join("\n")
    );
}

/// 🔴 cfg 腿必须有活样本：生产文件里确实存在 `#[cfg(test)]` 罩住的块。
///
/// [`cfg_test_regions`] 恒返回空时本门不报错、也不少扫文件 —— 它只是**不再看**生产文件里的
/// 测试代码，`include_str!` 从此可以躲在 `#[cfg(test)] fn` 里进来。这条把「那腿还活着」
/// 从假设变成断言。
///
/// **变异探针**：把 [`cfg_test_regions`] 改成 `Vec::new()` ⇒ 本条转红。
#[test]
fn the_cfg_test_leg_has_live_population() {
    let mut with_regions = 0usize;
    let mut total_regions = 0usize;
    for (rel, path) in scan_surface() {
        if rel.contains("/tests/") {
            continue;
        }
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("读不到 `{}`（{err}）", path.display()));
        let regions = cfg_test_regions(&polaris_source_probe::mask_comments_and_strings(&source));
        if !regions.is_empty() {
            with_regions += 1;
            total_regions += regions.len();
        }
    }
    assert!(
        with_regions > 0,
        "生产文件里一个 `#[cfg(…test…)]` 块都没算出来 —— cfg 腿在真语料上是死的，\
         躲在 `#[cfg(test)] fn` 里的 `include_str!` 会整类放行"
    );
    eprintln!("[门 D] cfg 腿活样本：{with_regions} 个生产文件 / {total_regions} 个块");
}
