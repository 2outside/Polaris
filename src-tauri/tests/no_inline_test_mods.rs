//! 门 C：反内联测试模块门 —— 给「测试外移」这条规则装上执行力。
//!
//! # 守的是什么
//!
//! 全仓统一的测试布局：`foo.rs` 末尾只留 `#[cfg(test)] mod tests;`（声明式），
//! 实体落 `foo/tests/mod.rs`（需分域时同目录追加 `foo/tests/<域>.rs`）。
//! 由此得到一条**目录级不变量**：`<dir>/*.rs` 恒为生产，`<dir>/tests/` 恒为测试。
//!
//! 这条不变量一旦成立，「这个文件是不是生产代码」就能靠路径判定，
//! 不再靠人去数花括号——本仓已经为「测试与生产在同一文件里交错」付过账：
//! `commands.rs` 的 `guard_scan` 在文件**头部**（93% 内容在它之后）、
//! `commands/proxy.rs` 的 `probe_tests` 在**中部**（其后还有 472 行生产代码）、
//! `runtime/proxy.rs` 顶层 `#[cfg(test)]` 实测 5 处且最后一处还在测试之后。
//! 任何「按第一个 `#[cfg(test)]` 截断取材」的扫描型判据在这些文件上都会哑绿
//! （见 `src-tauri/src/commands/updater/tests/mod.rs` 里那段复审 F2 教训的注释，
//! 以及 `crates/helper-client/src/manager.rs:2732` 的同类注解）。
//!
//! # 为什么必须是源码级门
//!
//! 「测试写在哪」**没有任何运行期表征**：内联与外移编出来的二进制完全一样，
//! 单测全绿、clippy 全绿、`cargo test` 全绿。唯一的观察面就是源码本身。
//! 没有这道门，规则只是一句约定——只要有人忘了，缺陷类立刻复发。
//!
//! # 判据形状
//!
//! 命中 =「cfg 在 test 打开时可能为真」的属性 + `mod <名> {`（**带 body**）。
//!
//! - `mod <名>;`（声明式）**不命中**——那正是目标形态。反向对照见
//!   [`declaration_form_is_not_a_hit`]。
//! - cfg 表达式做真实解析（不是字面量匹配）：`test` 标识符只要不落在任何 `not(...)` 之内
//!   就算正向。仓内实测存在的形态：`#[cfg(test)]`、`#[cfg(all(test, unix))]`、
//!   `#[cfg(any(target_os = "macos", test))]`、`#[cfg(any(target_os = "…", all(unix, test)))]`；
//!   必须放过的反向形态：`#[cfg(not(test))]`、`#[cfg(not(any(windows, test)))]`。
//!   对差表见 [`cfg_predicate_truth_table`]。
//! - `#[cfg(test)]` 与 `mod` 之间允许夹**别的属性**——仓内 6 处
//!   `crates/config-engine/src/builder/*.rs` 就是 `#[cfg(test)]` + `#[allow(…)]` + `mod tests {`，
//!   朴素的 `grep -A1` 判据会整批漏掉（见文末「对账」）。
//! - 取材前**先剥注释与字符串**：`//`、`//!`、`///`、**嵌套** `/* */`、`"…"`、`r#"…"#`、
//!   `b"…"`、`br#"…"#`、字符字面量，并区分生命周期 `'a` 与字符 `'a'`。
//!   本仓真实存在 24 处在注释/字符串里写着 `#[cfg(test)]` 的文本
//!   （如 `crates/config-engine/src/builder/orchestration/tests/mod.rs:41`、
//!   `crates/helper-client/src/manager/tests/mod.rs:1331`）。实际计数由
//!   [`mask_is_live_on_real_corpus`] 每次运行时打印，不靠这里的数字。
//!   剥离的**必要性**由合成夹具 [`masking_slice_self_check`] 的正向对照证明；
//!   剥离在**真实语料**上确实生效由 [`mask_is_live_on_real_corpus`] 证明。
//!
//! # 当前形态：零命中
//!
//! Batch A（全仓 279 块 / 239 文件测试外移）已完成，本门断言的就是**零命中**：
//! `foo.rs` 末尾只留 `#[cfg(test)] mod tests;`，实体落 `foo/tests/mod.rs`
//! （需分域时同目录追加 `foo/tests/<域>.rs`）。
//!
//! 棘轮基线（`tests/data/gate_c_baseline.txt` + `BASELINE_*` 常量 + `POLARIS_GATE_C_STRICT`
//! 环境开关）随 Batch A 收尾一并删除 —— 基线的唯一用途是「允许存量、只禁新增」，
//! 存量归零之后它就只剩两种可能：要么恒真的死代码，要么下一个人误以为还有存量可以往里加。
//!
//! [`WHITELIST`] 保留 —— 那 6 条是**机制性**永久例外（跨模块/跨 crate 可见的测试基础设施，
//! 外移后可见性穿不过私有 `tests` mod），不随 Batch A 消失。
//!
//! # 不在射程内（显式声明，不是遗漏）
//!
//! - `src-tauri/tests/` 与 `crates/*/tests/`：Cargo 集成测试，本来就在 `tests/` 下，
//!   目录级不变量对它们天然成立。
//! - 挂在**生产 item** 上的 `#[cfg(test)]`（struct 字段 / 构造器初始化 / 函数体内语句 /
//!   `cfg(test)` + `cfg(not(test))` 成对方法）：判据只认 `mod … {`，天然不命中。
//!
//! # 对账（基线是怎么来的）
//!
//! | 口径 | 块数 | 文件数 |
//! |---|---|---|
//! | 朴素 `grep -A1 '^\s*#\[cfg(test)\]$'`（同一快照） | 278 | 235 |
//! | 本判据全量（含白名单） | 285 | 241 |
//! | 本判据扣白名单 = **棘轮基线** | **279** | **239** |
//!
//! 立基线时工作树里 `src-tauri/src/test_support.rs` 已被外移成 `mod tests;`，
//! 故朴素口径是 278/235 而非交接时说的 279/236（差的正是这一条）。
//!
//! 差异 +7 块，逐条已核实，全部是旧统计的**漏报**、不是本判据的多报：
//! - `crates/config-engine/src/builder/{endpoint_routes,generate,hotswitch,orchestration,outbounds,route}.rs`
//!   共 6 处：`#[cfg(test)]` 与 `mod tests {` 之间夹了 `#[allow(clippy::field_reassign_with_default)]`，
//!   `grep -A1` 只看下一行 ⇒ 整批漏。
//! - `crates/helper-client/src/connector.rs:223`：属性是 `#[cfg(all(test, unix))]`，
//!   不是裸 `#[cfg(test)]` ⇒ 旧正则漏。
//!
//! 文件数 235 → 239 = +6（上述 6 个 builder 文件此前整个不在集合里）
//! −2（`commands.rs`、`commands/rules/icons.rs` 的唯一命中是白名单，扣除后整个文件退出）。
//!
//! 该 +7 已用**第二套引擎**（perl 多行正则，与本扫描器实现完全无关）独立复核：
//! 两者结果一致，唯一差异是 perl 手写的嵌套括号模式认不出 `#[cfg(all(test, unix))]`
//! ——即 `connector.rs` 那一条，正是本判据比朴素口径多抓到的其中之一。

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

// ============================================================================
// 基线与白名单
// ============================================================================

/// 一条永久白名单。
struct Exempt {
    /// 仓库相对路径（`/` 分隔）。
    file: &'static str,
    /// mod 名。
    name: &'static str,
    /// **为什么这一条不能外移**。
    reason: &'static str,
}

/// 跨模块共享的 `#[cfg(test)]` 辅助 mod —— 它们是**被别的模块 `use` 的测试基础设施**，
/// 不是某个文件的私有自测。
///
/// 共同的不可外移理由（机制层面，不是「历史如此」）：
/// 外移后路径变成 `foo::tests::<name>`，而承载它的那条声明 `#[cfg(test)] mod tests;`
/// **本身是私有的**。Rust 的可见性是逐段收窄的：`pub(crate)` / `pub` 的 item 一旦被一个私有
/// 父 mod 包住，crate 内/crate 外的消费方就再也 `use` 不到。要修就得把每个文件的
/// `mod tests;` 都提成 `pub(crate) mod tests;`——那等于把**全仓每个文件的私有自测**
/// 一起提升成 crate 公开面，代价远大于这 6 条例外。
///
/// - **删掉任何一条 ⇒ 该 mod 变成命中 ⇒ 不在基线集里 ⇒ 门红**（回放已验证）。
/// - **任何一条对不上真实源码（文件改名 / mod 改名 / 已外移）⇒ 门红**，
///   见 [`whitelist_entries_must_all_match`]——白名单不允许静默失效。
const WHITELIST: &[Exempt] = &[
    Exempt {
        file: "src-tauri/src/commands.rs",
        name: "guard_scan",
        reason: "`pub(crate)` 扫描型守卫的公共取材器，被 commands/ 下多个子模块的测试复用。\
                 外移则跨模块不可达（见上方机制说明）；且它位于文件头部、其后 93% 是生产代码，\
                 正是「测试不在文件尾」的活样本。",
    },
    Exempt {
        file: "src-tauri/src/runtime/core_update_scheduler.rs",
        name: "method_scan",
        reason: "`pub(crate)` 方法级扫描器，供 runtime 下其它模块的测试断言内核更新调度的方法集。\
                 消费方在别的文件里 ⇒ 外移后 `use` 不到。",
    },
    Exempt {
        file: "src-tauri/src/runtime/speedtest_tunnel.rs",
        name: "mock_proxy",
        reason: "`pub(crate)` 的**运行期夹具**（会真起本地监听的 mock 代理服务端），\
                 被多处测试共享。外移后跨模块不可达，只能各自复制一份 ⇒ 多份实现必然漂移。",
    },
    Exempt {
        file: "src-tauri/src/commands/rules/icons.rs",
        name: "icon_gallery_tests",
        reason: "`pub(crate)` 的图标 gallery 共享快照取材器，规则侧多个测试依赖同一份快照。\
                 外移后不可达；复制成多份会让快照之间漂移，等于把判据变哑。",
    },
    Exempt {
        file: "crates/system-integration/src/proxy.rs",
        name: "proxy_tests_helpers",
        reason: "`pub` —— **跨 crate** 可见，供 src-tauri 侧测试构造系统代理夹具。\
                 crate 外只能看到 `pub` 路径；外移进私有 `tests` mod 后整条路径从公开面消失，\
                 下游 crate 直接编不过。",
    },
    Exempt {
        file: "crates/system-integration/src/exec.rs",
        name: "exec_tests_helpers",
        reason: "`pub` —— **跨 crate** 可见，供下游 crate 的测试替换命令执行器（避免真起进程）。\
                 与上一条同因：跨 crate 可见性无法穿过私有 `tests` mod。",
    },
];

/// 已外移形态的先例（`#[cfg(test)] mod <名>;`，声明式）。
///
/// 作用是**反向对照**：判据若退化成「见 `cfg(test)` + `mod` 就红」，这三条立刻变假阳性。
/// 它们必须被扫到（作为声明式记录），且必须**不**出现在命中集里。
const DECL_CONTROLS: &[(&str, &str)] = &[
    ("src-tauri/src/main.rs", "test_support"),
    ("src-tauri/src/commands/updater.rs", "tests"),
    ("crates/net-stack/src/share_link.rs", "tests"),
];

// ============================================================================
// 词法：剥注释与字符串（保长度、保换行 ⇒ 行号不偏）
// ============================================================================

fn is_ident_start(c: u8) -> bool {
    c == b'_' || c.is_ascii_alphabetic() || c >= 0x80
}

fn is_ident_continue(c: u8) -> bool {
    c == b'_' || c.is_ascii_alphanumeric() || c >= 0x80
}

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && b[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// 把注释与字符串/字符字面量整体替换成空格（保留字节长度与 `\n`）。
///
/// 实现在 [`polaris_source_probe::mask_comments_and_strings`] —— 本门、门 3
/// （`release_escape_hatches.rs`）、门 D（`test_source_anchors.rs`）共用**同一份**。
///
/// 为什么不各留一份：同一事实多份实现，差异只会在某一天以「某个门漏判」的形式暴露。
/// 收敛前两份实现在全仓 604 个文件上差分实测有 13 处不一致（转义单引号 `'\''` 的收尾引号
/// 没被抹掉，扫描随后从它重新起算 ⇒ 净化面整段错位），收敛后差分为 0。
fn mask_rust(src: &str) -> Vec<u8> {
    polaris_source_probe::mask_comments_and_strings(src).into_bytes()
}

// ============================================================================
// 判据：cfg 表达式在 test 打开时是否可能为真
// ============================================================================

/// `attr` 是 `#[ … ]` 的内层文本（**已剥字符串**，故 `feature = "testing"` 里的 `testing` 不会误触）。
///
/// 判定：表达式里存在一个 `test` 标识符，且它不在任何 `not(...)` 之内
/// —— 即「打开 `test` 会让这个 cfg 在某种配置下为真」。
fn cfg_is_test_positive(attr: &[u8]) -> bool {
    let s = attr;
    let mut i = skip_ws(s, 0);
    let start = i;
    while i < s.len() && is_ident_continue(s[i]) {
        i += 1;
    }
    if &s[start..i] != b"cfg" {
        return false; // 排除 cfg_attr / allow / derive / …
    }
    i = skip_ws(s, i);
    if i >= s.len() || s[i] != b'(' {
        return false;
    }
    i += 1;
    let mut frames: Vec<bool> = vec![false]; // 每层括号：是不是 not(...)
    let mut positive = false;
    while i < s.len() && !frames.is_empty() {
        let c = s[i];
        if c == b'(' {
            frames.push(false);
            i += 1;
            continue;
        }
        if c == b')' {
            frames.pop();
            i += 1;
            continue;
        }
        if is_ident_start(c) {
            let st = i;
            while i < s.len() && is_ident_continue(s[i]) {
                i += 1;
            }
            let ident = &s[st..i];
            let k = skip_ws(s, i);
            if k < s.len() && s[k] == b'(' {
                frames.push(ident == b"not");
                i = k + 1;
                continue;
            }
            if ident == b"test" && !frames.iter().any(|&f| f) {
                positive = true;
            }
            continue;
        }
        i += 1;
    }
    positive
}

// ============================================================================
// 扫描
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ModRecord {
    file: String,
    /// `mod` 关键字所在行（1-based，**原始源码**行号）。
    line: usize,
    /// `#[cfg(...)]` 属性所在行（1-based）。
    attr_line: usize,
    name: String,
    /// `true` = `mod x { … }`（内联，违规形态）；`false` = `mod x;`（声明式，目标形态）。
    body: bool,
}

/// 匹配 `b[open]` 处的 `[`，返回配对 `]` 的下标。
fn match_bracket(b: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = open;
    while i < b.len() {
        match b[i] {
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// 跳过可见性修饰：`pub`、`pub(crate)`、`pub(super)`、`pub(in path)`。认不出就原样返回。
fn skip_vis(b: &[u8], i: usize) -> usize {
    let j = skip_ws(b, i);
    if !b[j..].starts_with(b"pub") {
        return i;
    }
    let k = j + 3;
    if k < b.len() && is_ident_continue(b[k]) {
        return i; // `public_thing` 之类
    }
    let m = skip_ws(b, k);
    if m < b.len() && b[m] == b'(' {
        let mut depth = 0usize;
        let mut p = m;
        while p < b.len() {
            match b[p] {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return p + 1;
                    }
                }
                _ => {}
            }
            p += 1;
        }
        return i;
    }
    m
}

/// 在**已剥注释与字符串**的字节流上找「正向 cfg(test) 属性 + mod 项」。
/// 返回 `(属性偏移, mod 关键字偏移, mod 名, 是否带 body)`。
fn scan_masked(m: &[u8]) -> Vec<(usize, usize, String, bool)> {
    let n = m.len();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < n {
        if m[i] != b'#' {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        if j < n && m[j] == b'!' {
            j += 1;
        }
        if j >= n || m[j] != b'[' {
            i += 1;
            continue;
        }
        let Some(close) = match_bracket(m, j) else {
            i += 1;
            continue;
        };
        if !cfg_is_test_positive(&m[j + 1..close]) {
            i = j + 1;
            continue;
        }
        // 跨过属性与 item 之间夹的其它属性（doc 注释此刻已是空白）
        let mut k = close + 1;
        loop {
            k = skip_ws(m, k);
            if k < n && m[k] == b'#' {
                let mut jj = k + 1;
                if jj < n && m[jj] == b'!' {
                    jj += 1;
                }
                if jj < n && m[jj] == b'[' {
                    if let Some(c2) = match_bracket(m, jj) {
                        k = c2 + 1;
                        continue;
                    }
                }
            }
            break;
        }
        k = skip_ws(m, skip_vis(m, k));
        if m[k..].starts_with(b"mod") && (k + 3 >= n || !is_ident_continue(m[k + 3])) {
            let mod_off = k;
            let mut p = skip_ws(m, k + 3);
            if m[p..].starts_with(b"r#") {
                p += 2; // raw identifier
            }
            let name_start = p;
            while p < n && is_ident_continue(m[p]) {
                p += 1;
            }
            if p > name_start {
                let name = String::from_utf8_lossy(&m[name_start..p]).to_string();
                let q = skip_ws(m, p);
                if q < n && (m[q] == b'{' || m[q] == b';') {
                    out.push((i, mod_off, name, m[q] == b'{'));
                }
            }
        }
        i = j + 1;
    }
    out
}

fn line_of(src: &str, off: usize) -> usize {
    src.as_bytes()[..off.min(src.len())]
        .iter()
        .filter(|&&c| c == b'\n')
        .count()
        + 1
}

fn scan_file(rel: &str, src: &str, strip: bool) -> Vec<ModRecord> {
    let bytes = if strip {
        mask_rust(src)
    } else {
        src.as_bytes().to_vec()
    };
    scan_masked(&bytes)
        .into_iter()
        .map(|(attr_off, mod_off, name, body)| ModRecord {
            file: rel.to_string(),
            line: line_of(src, mod_off),
            attr_line: line_of(src, attr_off),
            name,
            body,
        })
        .collect()
}

// ============================================================================
// 语料
// ============================================================================

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("src-tauri 必有上级目录")
        .to_path_buf()
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let rd = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("读不到目录 {}: {e}（射程被静默削掉）", dir.display()));
    for e in rd {
        let p = e.expect("目录项不可读").path();
        if p.is_dir() {
            collect_rs(&p, out);
        } else if p.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(p);
        }
    }
}

/// 射程：`src-tauri/src` + `crates/*/src` 全部 `.rs`。
/// 前置缺失（根不存在 / 语料过小）**必须红**，不许静默跳过。
fn corpus() -> Vec<(String, String)> {
    let root = repo_root();
    let mut roots = vec![root.join("src-tauri/src")];
    let crates = root.join("crates");
    let mut crate_dirs: Vec<PathBuf> = std::fs::read_dir(&crates)
        .unwrap_or_else(|e| panic!("读不到 {}: {e}", crates.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    crate_dirs.sort();
    assert!(
        crate_dirs.len() >= 10,
        "crates/ 下只有 {} 个 crate —— 远低于本仓规模，语料收集坏了",
        crate_dirs.len()
    );
    for c in crate_dirs {
        let s = c.join("src");
        if s.is_dir() {
            roots.push(s);
        }
    }
    let mut files = Vec::new();
    for r in &roots {
        assert!(
            r.is_dir(),
            "扫描根不存在: {}（射程被静默削掉）",
            r.display()
        );
        collect_rs(r, &mut files);
    }
    files.sort();
    assert!(
        files.len() > 300,
        "只扫到 {} 个 .rs —— 远低于本仓规模，语料收集坏了",
        files.len()
    );
    files
        .into_iter()
        .map(|p| {
            let rel = p
                .strip_prefix(&root)
                .expect("语料必在仓库根之下")
                .to_string_lossy()
                .replace('\\', "/");
            let src = std::fs::read_to_string(&p)
                .unwrap_or_else(|e| panic!("读不到 {}: {e}", p.display()));
            (rel, src)
        })
        .collect()
}

fn all_records(strip: bool) -> Vec<ModRecord> {
    corpus()
        .iter()
        .flat_map(|(rel, src)| scan_file(rel, src, strip))
        .collect()
}

fn is_whitelisted(r: &ModRecord) -> bool {
    WHITELIST
        .iter()
        .any(|e| e.file == r.file && e.name == r.name)
}

/// 违规命中：带 body 且不在白名单。
fn violations() -> Vec<ModRecord> {
    let mut v: Vec<ModRecord> = all_records(true)
        .into_iter()
        .filter(|r| r.body && !is_whitelisted(r))
        .collect();
    v.sort();
    v
}

/// 人读报告（带行号，用于定位）。
fn render(v: &[ModRecord]) -> String {
    let files: BTreeSet<&str> = v.iter().map(|r| r.file.as_str()).collect();
    let mut s = format!(
        "# 门 C 命中清单：内联 `#[cfg(test)] mod … {{`（带 body，已扣白名单）\n\
         # 命中块数 = {}\n# 涉及文件数 = {}\n\
         # 格式: <文件>:<mod 行>  mod <名>   (cfg 属性行 <n>)\n\n",
        v.len(),
        files.len()
    );
    for r in v {
        s.push_str(&format!(
            "{}:{}  mod {}   (cfg @ {})\n",
            r.file, r.line, r.name, r.attr_line
        ));
    }
    s
}

// ============================================================================
// 门
// ============================================================================

/// 主门：全仓不得有内联 `#[cfg(test)] mod … { }`（白名单 6 条除外）。
#[test]
fn no_new_inline_test_mods() {
    let v = violations();
    let files: BTreeSet<&str> = v.iter().map(|r| r.file.as_str()).collect();

    if let Ok(p) = std::env::var("POLARIS_GATE_C_DUMP") {
        std::fs::write(&p, render(&v)).unwrap_or_else(|e| panic!("写不了 {p}: {e}"));
        eprintln!("[门 C] 人读命中清单 -> {p}");
    }

    // 阳性对照：取材面恒空时下面那条否定型断言恒真。语料数、被扫到的 `mod` 记录数都必须非零。
    let corpus_files = corpus().len();
    assert!(
        corpus_files > 400,
        "取材面只有 {corpus_files} 个文件 —— 语料收集坏了，本门在裸奔"
    );
    let records = all_records(true);
    assert!(
        records.iter().any(|r| r.body) || records.iter().any(|r| !r.body),
        "一条 `mod` 记录都没扫到 —— 扫描器坏了"
    );

    assert!(
        v.is_empty(),
        "有 {} 处内联 `#[cfg(test)] mod`（{} 个文件）：\n{}\n\
         规则：`foo.rs` 末尾只留 `#[cfg(test)] mod tests;`，实体落 `foo/tests/mod.rs`\n\
         （需分域时同目录追加 `foo/tests/<域>.rs`）。\n\
         若这是**跨模块共享**的测试基础设施（`pub(crate)` / `pub` 且被别的文件 use），\
         请加进本文件的 WHITELIST 并写明「为什么不能外移」。",
        v.len(),
        files.len(),
        render(&v)
    );
}

/// 白名单不允许静默失效：每条都必须**恰好**对上一个真实的、带 body 的内联 mod，且必须带理由。
#[test]
fn whitelist_entries_must_all_match() {
    let all = all_records(true);
    for e in WHITELIST {
        let hits: Vec<&ModRecord> = all
            .iter()
            .filter(|r| r.file == e.file && r.name == e.name && r.body)
            .collect();
        assert_eq!(
            hits.len(),
            1,
            "白名单条目 {}::{} 匹配到 {} 处（应为 1）。\n\
             文件改名 / mod 改名 / 已外移 / 打错字都会走到这里 —— \
             请同步删除或修正该条，别让白名单变成哑绿的免死金牌。",
            e.file,
            e.name,
            hits.len()
        );
        assert!(
            e.reason.trim().chars().count() >= 20,
            "白名单条目 {}::{} 的理由太短，必须回答「为什么这一条不能外移」",
            e.file,
            e.name
        );
    }
    // 白名单条目不得出现在命中集里（否则白名单没生效）
    let v = violations();
    for e in WHITELIST {
        assert!(
            !v.iter().any(|r| r.file == e.file && r.name == e.name),
            "白名单条目 {}::{} 仍被判成命中 —— 白名单匹配逻辑坏了",
            e.file,
            e.name
        );
    }
}

/// 反向对照：声明式 `#[cfg(test)] mod x;` 必须被扫到、且**不得**被判成命中。
///
/// 判据若退化成「见 `cfg(test)` + `mod` 就红」，这里立刻假阳性。
#[test]
fn declaration_form_is_not_a_hit() {
    let all = all_records(true);
    let v = violations();
    for (file, name) in DECL_CONTROLS {
        assert!(
            all.iter()
                .any(|r| r.file == *file && r.name == *name && !r.body),
            "先例 {file}::{name}（`#[cfg(test)] mod {name};`）没被扫到 —— \
             要么源码被改了，要么扫描器认不出声明式形态（那样 Batch A 完成后全仓都会假阳性）"
        );
        assert!(
            !v.iter().any(|r| r.file == *file && r.name == *name),
            "声明式 {file}::{name} 被误判成命中 —— 判据把目标形态也杀了"
        );
    }
    assert!(
        all.iter().filter(|r| !r.body).count() >= DECL_CONTROLS.len(),
        "扫不到任何声明式 mod —— 反向对照落在空集上，无信息量"
    );
}

/// 切片自检（合成夹具）：注释 / 普通串 / 原始串 / 字节串 / 字符字面量 / 生命周期 里的
/// `#[cfg(test)] mod … {` 字样必须**全部**被剥掉；同一份夹具里的真实代码必须命中。
///
/// 末尾的**正向对照**证明剥离不是恒真的空操作：不剥时这些噪声确实会变成命中。
#[test]
fn masking_slice_self_check() {
    let fixture = r####"
// #[cfg(test)] mod in_line_comment { }
//! #[cfg(test)] mod in_inner_doc { }
/// #[cfg(test)] mod in_outer_doc { }
/* #[cfg(test)] mod in_block { } /* 嵌套 #[cfg(test)] mod in_nested { } */ 仍在注释 */
const A: &str = "#[cfg(test)] mod in_string { }";
const B: &str = r#"#[cfg(test)] mod in_raw_string { }"#;
const C: &str = r##"含 "# 的原始串：#[cfg(test)] mod in_raw2 { }"##;
const D: &[u8] = b"#[cfg(test)] mod in_byte_string { }";
const E: char = '"';                  // 孤立双引号：剥串器不能被它带偏
const F: char = '\'';                 // 转义单引号
const G: char = '中';                 // 多字节码点
struct L<'a>(&'a str);                // 生命周期不是字符字面量
#[cfg(test)]
mod real_hit { }
#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod hit_behind_another_attr { }
#[cfg(all(test, unix))]
mod hit_non_bare_cfg { }
#[cfg(not(test))]
mod prod_only_not_a_hit { }
#[cfg(test)]
mod decl_form_not_a_hit;
"####;
    let recs = scan_file("fixture.rs", fixture, true);
    let got: Vec<&str> = recs
        .iter()
        .filter(|r| r.body)
        .map(|r| r.name.as_str())
        .collect();
    assert_eq!(
        got,
        vec!["real_hit", "hit_behind_another_attr", "hit_non_bare_cfg"],
        "剥离后的命中集不对。\n---- 剥离结果切片自检 ----\n{}\n---- 全部记录 ----\n{:#?}",
        String::from_utf8_lossy(&mask_rust(fixture)),
        recs
    );
    assert!(
        recs.iter()
            .any(|r| r.name == "decl_form_not_a_hit" && !r.body),
        "声明式没被记成 Decl。切片：\n{}",
        String::from_utf8_lossy(&mask_rust(fixture))
    );

    // 正向对照：不剥的话，噪声确实变命中 ⇒ 上面的断言不是恒真。
    let raw_hits: Vec<String> = scan_file("fixture.rs", fixture, false)
        .into_iter()
        .filter(|r| r.body)
        .map(|r| r.name)
        .collect();
    assert!(
        raw_hits.len() > got.len(),
        "不剥注释/字符串时命中 {raw_hits:?}，并不比剥离后多 —— 夹具没造出污染，剥离断言无信息量"
    );
    eprintln!(
        "[门 C] 夹具正向对照：不剥 {} 命中 / 剥后 {} 命中，被剥掉的假阳性 = {:?}",
        raw_hits.len(),
        got.len(),
        raw_hits
            .iter()
            .filter(|n| !got.contains(&n.as_str()))
            .collect::<Vec<_>>()
    );
}

/// 真实语料上的剥离生效证明（不是「没观测到」，是正向计数）。
///
/// 本仓有 20+ 处在注释/字符串里写着 `#[cfg(test)]` 的文本
/// （`runtime/stats.rs`、`helper-client/manager.rs`、`config-engine/.../orchestration.rs` …）。
/// 这里逐个字节位置比对：属性字样在剥离后应变成空白。至少要有一处被剥掉，否则说明剥离器没跑。
///
/// 另一半是**方向性**断言：剥离只能减少命中，绝不能凭空增加——增加就意味着掩码破坏了字节偏移。
#[test]
fn mask_is_live_on_real_corpus() {
    const NEEDLE: &[u8] = b"#[cfg(test)]";
    let mut killed: Vec<String> = Vec::new();
    let mut survived = 0usize;
    for (rel, src) in corpus() {
        let raw = src.as_bytes();
        let masked = mask_rust(&src);
        assert_eq!(
            masked.len(),
            raw.len(),
            "{rel}: 掩码改变了字节长度 —— 行号会整体错位"
        );
        for i in 0..raw.len().saturating_sub(NEEDLE.len()) {
            if &raw[i..i + NEEDLE.len()] == NEEDLE {
                if masked[i] == b'#' {
                    survived += 1;
                } else {
                    killed.push(format!("{rel}:{}", line_of(&src, i)));
                }
            }
        }
    }
    eprintln!(
        "[门 C] 真实语料剥离对照：`#[cfg(test)]` 字样共 {} 处，其中 {} 处是代码（保留）、\
         {} 处在注释/字符串里（已剥）。前 5 处被剥的：{:?}",
        survived + killed.len(),
        survived,
        killed.len(),
        killed.iter().take(5).collect::<Vec<_>>()
    );
    assert!(
        survived > 200,
        "只有 {survived} 处 `#[cfg(test)]` 被当成代码保留 —— 掩码把真代码也吃了"
    );
    assert!(
        !killed.is_empty(),
        "真实语料里一处注释/字符串中的 `#[cfg(test)]` 都没被剥掉 —— \
         要么剥离器没生效，要么本仓污染已清零。前者是 bug，后者请改用合成夹具兜底。"
    );

    // 方向性：剥离绝不能新增命中
    let stripped: BTreeSet<(String, usize, String)> = violations()
        .into_iter()
        .map(|r| (r.file, r.line, r.name))
        .collect();
    let raw_keys: BTreeSet<(String, usize, String)> = all_records(false)
        .into_iter()
        .filter(|r| r.body && !is_whitelisted(r))
        .map(|r| (r.file, r.line, r.name))
        .collect();
    let added: Vec<_> = stripped.difference(&raw_keys).collect();
    assert!(
        added.is_empty(),
        "剥离后**新增**了命中 —— 掩码破坏了字节偏移或拼出了假代码：{added:#?}"
    );
}

/// cfg 表达式判据的输入对差表：仓内实测形态 + 必须放过的反向形态。
#[test]
fn cfg_predicate_truth_table() {
    // 注：串已被剥离器换成空格，故这里的 `target_os = "macos"` 写成 `target_os =       `。
    let cases: &[(&str, bool)] = &[
        ("cfg(test)", true),
        ("cfg( test )", true),
        ("cfg(all(test, unix))", true),
        ("cfg(all(test, windows))", true),
        ("cfg(any(target_os =        , test))", true),
        ("cfg(any(test, target_os =        ))", true),
        ("cfg(any(target_os =        , all(unix, test)))", true),
        ("cfg(any(windows, test))", true),
        (
            "cfg(any(target_os =        , target_os =        , test))",
            true,
        ),
        ("cfg(not(test))", false),
        ("cfg(not(any(windows, test)))", false),
        ("cfg(all(not(test), unix))", false),
        ("cfg(windows)", false),
        ("cfg(unix)", false),
        ("cfg(feature =        )", false), // feature = "testing"：串已剥 ⇒ 不误触
        ("cfg(test_util)", false),
        ("cfg(target_os =        )", false),
        ("cfg_attr(test, allow(dead_code))", false),
        ("allow(dead_code)", false),
        ("derive(Debug)", false),
        ("must_use", false),
        // 同时含正反出现：存在一个不在 not 内的 test ⇒ 正向（编译期确实会在 test 下为真）
        ("cfg(any(not(test), test))", true),
    ];
    for (attr, want) in cases {
        assert_eq!(
            cfg_is_test_positive(attr.as_bytes()),
            *want,
            "cfg 判据在 `{attr}` 上判错（期望 {want}）"
        );
    }
}
