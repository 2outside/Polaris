//! 测试专用符号必须带 cfg 门。
//!
//! # 守的是什么
//!
//! 一个「只服务测试」的符号（mock / fake / stub / 桩 / 固定时钟 / 内存簿记…）如果**不带 cfg 门**，
//! 它就是**生产符号**：进 release 产物、进 crate 的公开 API 面、被 `pub use` 一路导出到宿主。
//! 后果不是「多几 KB」，而是三条真实路径：
//!
//! 1. **生产代码可以装上它，编译过、类型对**。`traits.rs` 的 `UnavailableDownloader` 文档里
//!    已经把这个形状写成教训：一个「读起来像能用」的类型被宿主装上，全部单测注入 mock ⇒ mock 全绿，
//!    **生产路径第一次真跑必失败**。测试替身是同一个形状的更强版本 —— 它连"失败"都不会，只是悄悄地假。
//! 2. **公开 API 契约被污染**。`pub use ... MockStream` 之后，删掉这个 mock 就是一次 breaking change。
//! 3. **门自己被绕过**。测试替身留在生产模块里，`<dir>/*.rs 恒为生产` 这条不变量当场失效。
//!
//! # 判据（两支，取材面不同 —— 见 [`mask`] 的文档）
//!
//! 对 `src-tauri/src/**` + `crates/*/src/**` 里的每个 item：
//!
//! - **NAME 支**：item 名字含 `Mock` / `Fake` / `Stub` / `Dummy`。取材面 = **纯代码**
//!   （注释与字符串字面量全剥）—— 注释里写 `MockFoo` 不算声明，字符串里写 `struct FakeBar` 更不算。
//! - **DOC 支**：item 是**类型定义**（`struct`/`enum`/`union`/`type`），且其 doc 注释**摘要行**
//!   含「测试用 / 测试 mock / 仅供测试 / 桩 / 测试专用 / 仅测试」。取材面 = **代码 + doc 注释**
//!   （只剥非 doc 注释与字符串）—— doc 注释在这一支里**是判据本身**，剥掉它这一支就恒绿。
//!
//! 命中后必须被 cfg 门盖住，否则红。「盖住」= 自身属性、任一祖先块、或**跨文件的 `mod` 声明**
//! 带一个在生产构建（`test` 关、`feature = "test-utils"` 关）下求值为 false 的 `cfg(..)`。
//!
//! # 为什么 DOC 支只取摘要行、且只认类型定义
//!
//! 「便于测试 mock」「单测可替换为桩」这类话描述的是**生产类型的可测性**，不是「我是替身」。
//! 它们出现在 trait 声明与 DI 结构的正文里。摘要行（rustdoc summary）回答的是「这是什么」，
//! 替身在那一行会自报家门（"内存下载器（测试 mock）"、"固定时钟（测试用）"、"静态凭据桩（测试用…）"）。
//! 仍有残余误报 —— 逐条登记在 [`WHITELIST`]，带理由，且**过期条目会让门变红**（防白名单腐烂）。
//!
//! # 与 Batch A（测试外移）的关系
//!
//! 本门**不按路径名跳过** `tests.rs` / `tests/`。文件级门是从**父模块的 `mod` 声明**读出来的：
//! `#[cfg(test)] mod tests;` ⇒ `foo/tests.rs` 与 `foo/tests/mod.rs` 整文件视为已门控。
//! 于是外移前（`foo/tests.rs`）与外移后（`foo/tests/mod.rs`）判据不变，且**没有** "叫 tests 就放行"
//! 这条命名约定漏洞 —— 一个叫 `helpers` 的模块只要 `mod helpers;` 没带 cfg，里面的替身照样红。

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

// ===================== 白名单 =====================

/// 命中判据但**确属生产用途**的 item：(仓库相对路径, item 名, 理由)。
///
/// 每条都必须给出「谁在生产路径上用它」。过期条目（不再命中）会让门变红 —— 白名单不是垃圾桶。
const WHITELIST: &[(&str, &str, &str)] = &[
    (
        "crates/config-engine/src/singbox/dns.rs",
        "FakeIpConfig",
        "名字撞 NAME 支正则，但 FakeIP 是 sing-box `dns.fakeip` 的协议概念，不是测试替身；\
         由 crates/config-engine/src/singbox/dns.rs 的生产配置生成路径构造并序列化进真实 config.json。",
    ),
    (
        "crates/core-supervisor/src/readiness_gate.rs",
        "CoreReadyDeps",
        "生产依赖注入结构：wait_for_core_ready 的入参本体，生产由 src-tauri 装真实现；\
         摘要行里的「单测可替换为桩」描述的是它的可测性，不是它自己是桩。",
    ),
    (
        "crates/helper/src/platform/linux/handler.rs",
        "HandlerDeps",
        "生产依赖注入结构：linux helper 的 handle() 入参，生产由 server.rs accept 循环装真实现；\
         摘要行的「便于测试 mock」同上，描述可测性。",
    ),
    (
        "src-tauri/src/runtime/tailscale_login_core.rs",
        "LoginCoreRegistry",
        "生产注册表：瞬态登录核的生命周期持有者，由 runtime 生产路径构造；\
         摘要行「生产真实现，测试 mock」明示生产用途在先。",
    ),
];

// ===================== 取材：剥注释与字符串 =====================

/// 把源码剥成两个**行号对齐**的取材面。
///
/// 返回 `(code, docs, attrs)`，三者与输入**行数完全相同**（换行原样保留，其余被剥字符换成空格）：
///
/// - `code`：**所有**注释（含 doc）+ 所有字符串/字符字面量 → 空格。用于 item 声明识别、
///   属性识别、花括号深度。判据必须落在可执行形态上：注释里的 `struct MockFoo` 不是声明。
/// - `docs`：**只剥**非 doc 注释与字面量，`///` `//!` `/** */` `/*! */` **原样保留**。
///   DOC 支的判据就是 doc 注释本身，用 `code` 去匹配它会恒绿。
/// - `attrs`：**只剥注释**，字符串字面量**原样保留**。cfg 谓词求值面 ——
///   `#[cfg(any(test, feature = "test-utils"))]` 里那个 `"test-utils"` 是**字面量**，
///   在 `code` 面上已被抹成空格，拿 `code` 去求值会把这个门读成「不带门」而静默放行
///   （本门首版就是这个 bug，被 fixture 的 `MockGatedByFeature` 正向对照抓到）。
///   注释仍必须剥：被注释掉的 `#[cfg(test)]` 不是门。
///
/// 处理：行注释、块注释（含嵌套）、doc 与非 doc 的区分、普通/字节字符串、转义、
/// 原始字符串 `r"…"` / `r#"…"#` / `br##"…"##`（任意 `#` 数）、字符字面量与生命周期的区分。
fn mask(src: &str) -> (String, String, String) {
    let c: Vec<char> = src.chars().collect();
    let n = c.len();
    let mut code = String::with_capacity(src.len());
    let mut docs = String::with_capacity(src.len());
    let mut attrs = String::with_capacity(src.len());
    let mut i = 0usize;

    // 把 [from,to) 在 code 面整段抹掉（换行保留）；docs/attrs 面按各自的保留策略。
    macro_rules! blank {
        ($from:expr, $to:expr, $keep_doc:expr, $keep_attr:expr) => {{
            for k in $from..$to {
                let ch = c[k];
                if ch == '\n' {
                    code.push('\n');
                    docs.push('\n');
                    attrs.push('\n');
                } else {
                    code.push(' ');
                    docs.push(if $keep_doc { ch } else { ' ' });
                    attrs.push(if $keep_attr { ch } else { ' ' });
                }
            }
        }};
    }

    while i < n {
        let ch = c[i];

        // ---- 原始字符串 r"…" / r#"…"# / br##"…"## ----
        if (ch == 'r' || ch == 'b') && !is_ident_char(if i == 0 { ' ' } else { c[i - 1] }) {
            let mut j = i;
            if c[j] == 'b' {
                j += 1;
            }
            if j < n && c[j] == 'r' {
                j += 1;
                let hs = j;
                while j < n && c[j] == '#' {
                    j += 1;
                }
                if j < n && c[j] == '"' {
                    let hashes = j - hs;
                    let start = i;
                    let mut k = j + 1;
                    let end = loop {
                        if k >= n {
                            break n;
                        }
                        if c[k] == '"' {
                            let mut h = 0;
                            while h < hashes && k + 1 + h < n && c[k + 1 + h] == '#' {
                                h += 1;
                            }
                            if h == hashes {
                                break k + 1 + hashes;
                            }
                        }
                        k += 1;
                    };
                    blank!(start, end, false, true);
                    i = end;
                    continue;
                }
            }
        }

        // ---- 普通字符串 "…"（含 b"…"，b 已作为普通代码字符输出）----
        if ch == '"' {
            let mut j = i + 1;
            while j < n {
                if c[j] == '\\' {
                    j += 2;
                    continue;
                }
                if c[j] == '"' {
                    j += 1;
                    break;
                }
                j += 1;
            }
            blank!(i, j.min(n), false, true);
            i = j.min(n);
            continue;
        }

        // ---- 字符字面量 vs 生命周期 ----
        if ch == '\'' {
            if let Some(end) = char_lit_end(&c, i) {
                blank!(i, end, false, true);
                i = end;
                continue;
            }
            // 生命周期：原样
            code.push(ch);
            docs.push(ch);
            attrs.push(ch);
            i += 1;
            continue;
        }

        // ---- 行注释 ----
        if ch == '/' && i + 1 < n && c[i + 1] == '/' {
            // doc 行注释：`///`（但 `////` 不是）或 `//!`
            let is_doc = (i + 2 < n && c[i + 2] == '/' && !(i + 3 < n && c[i + 3] == '/'))
                || (i + 2 < n && c[i + 2] == '!');
            let mut j = i;
            while j < n && c[j] != '\n' {
                j += 1;
            }
            blank!(i, j, is_doc, false);
            i = j;
            continue;
        }

        // ---- 块注释（含嵌套）----
        if ch == '/' && i + 1 < n && c[i + 1] == '*' {
            let is_doc = (i + 2 < n && c[i + 2] == '*' && !(i + 3 < n && c[i + 3] == '*'))
                || (i + 2 < n && c[i + 2] == '!');
            let mut depth = 0usize;
            let mut j = i;
            while j < n {
                if c[j] == '/' && j + 1 < n && c[j + 1] == '*' {
                    depth += 1;
                    j += 2;
                    continue;
                }
                if c[j] == '*' && j + 1 < n && c[j + 1] == '/' {
                    depth -= 1;
                    j += 2;
                    if depth == 0 {
                        break;
                    }
                    continue;
                }
                j += 1;
            }
            let end = j.min(n);
            blank!(i, end, is_doc, false);
            i = end;
            continue;
        }

        code.push(ch);
        docs.push(ch);
        attrs.push(ch);
        i += 1;
    }
    (code, docs, attrs)
}

fn is_ident_char(ch: char) -> bool {
    ch.is_alphanumeric() || ch == '_'
}

/// `c[i] == '\''` 时判断是否为字符字面量，是则返回结束下标（右单引号之后）。
fn char_lit_end(c: &[char], i: usize) -> Option<usize> {
    let n = c.len();
    if i + 1 >= n {
        return None;
    }
    if c[i + 1] == '\\' {
        // 转义：'\n' '\\' '\'' '\u{1F600}'
        let mut j = i + 2;
        while j < n && c[j] != '\'' && c[j] != '\n' {
            j += 1;
        }
        return if j < n && c[j] == '\'' {
            Some(j + 1)
        } else {
            None
        };
    }
    if i + 2 < n && c[i + 2] == '\'' {
        return Some(i + 3);
    }
    None
}

// ===================== cfg 谓词求值 =====================

/// 在**生产构建**下求值一个 `cfg(..)` 内部谓词：`test` = false、`feature = "test-utils"` = false，
/// 其余原子（`unix` / `windows` / `target_os = "…"` / 其它 feature…）一律 **true**（最宽松）。
///
/// 返回 true = 该 item 在生产构建里**仍然存在** ⇒ 不算被门控。
///
/// 这样 `cfg(all(test, unix))`、`cfg(any(test, feature = "test-utils"))` 都算门控，
/// 而 `cfg(any(target_os = "windows", test))`（helper 的平台模块谓词）**不算** —— 它在 Windows
/// 生产构建里真的存在。判据是语义而不是字面量匹配：写死 `#[cfg(test)]` 字符串的门，
/// 遇到 `#[cfg(all(test, unix))]` 会静默放行（本仓 helper-client/connector.rs 就是这个形状）。
fn eval_cfg(expr: &str) -> bool {
    let e = expr.trim();
    for (kw, _) in [("all", 0), ("any", 1), ("not", 2)] {
        if let Some(rest) = e.strip_prefix(kw) {
            let rest = rest.trim_start();
            if rest.starts_with('(') && rest.ends_with(')') {
                let inner = &rest[1..rest.len() - 1];
                let parts = split_top_level(inner);
                let vals: Vec<bool> = parts.iter().map(|p| eval_cfg(p)).collect();
                return match kw {
                    "all" => vals.iter().all(|v| *v),
                    "any" => vals.iter().any(|v| *v),
                    _ => !vals.first().copied().unwrap_or(false),
                };
            }
        }
    }
    let flat: String = e.chars().filter(|ch| !ch.is_whitespace()).collect();
    if flat == "test" || flat == "feature=\"test-utils\"" {
        return false;
    }
    true
}

fn split_top_level(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for ch in s.chars() {
        match ch {
            '(' => {
                depth += 1;
                cur.push(ch);
            }
            ')' => {
                depth -= 1;
                cur.push(ch);
            }
            ',' if depth == 0 => {
                out.push(cur.clone());
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

/// 一串属性文本里是否存在「在生产构建下求值为 false」的 `#[cfg(..)]`。
fn is_gated(attrs: &str) -> bool {
    let c: Vec<char> = attrs.chars().collect();
    let mut i = 0usize;
    while i < c.len() {
        // 找 `#[` … `cfg` … `(`
        if c[i] == '#' && i + 1 < c.len() && c[i + 1] == '[' {
            // 属性名（允许 cfg 前有空白）
            let mut j = i + 2;
            while j < c.len() && c[j].is_whitespace() {
                j += 1;
            }
            if c[j..].starts_with(&['c', 'f', 'g']) {
                let mut k = j + 3;
                while k < c.len() && c[k].is_whitespace() {
                    k += 1;
                }
                if k < c.len() && c[k] == '(' {
                    let mut depth = 0i32;
                    let mut m = k;
                    while m < c.len() {
                        if c[m] == '(' {
                            depth += 1;
                        } else if c[m] == ')' {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        m += 1;
                    }
                    let inner: String = c[k + 1..m.min(c.len())].iter().collect();
                    if !eval_cfg(&inner) {
                        return true;
                    }
                    i = m;
                }
            }
        }
        i += 1;
    }
    false
}

// ===================== item 识别 =====================

const ITEM_KEYWORDS: &[&str] = &[
    "struct",
    "enum",
    "union",
    "trait",
    "fn",
    "type",
    "mod",
    "static",
    "const",
    "macro_rules!",
];
const TYPE_KEYWORDS: &[&str] = &["struct", "enum", "union", "type"];

/// 从一行**已剥净**的代码里认出 item 声明，返回 (关键字, 名字)。
///
/// `impl` 块返回 `("impl", 自身类型名)` —— `impl Trait for MockX` 的判据落在 `MockX` 上。
fn parse_item(line: &str) -> Option<(String, String)> {
    let s = line.trim_start();
    if s.starts_with("#[") || s.starts_with("#!") {
        return None;
    }
    let mut rest = s;

    if let Some(r) = strip_word(rest, "impl") {
        let r = skip_balanced(r.trim_start(), '<', '>');
        let r = r.trim_start();
        let target = match find_top_level_for(r) {
            Some(pos) => &r[pos + 5..],
            None => r,
        };
        let name = leading_path_last(target.trim_start())?;
        return Some(("impl".to_string(), name));
    }

    // 前缀修饰词
    loop {
        let t = rest.trim_start();
        if let Some(r) = t.strip_prefix("pub") {
            let r2 = r.trim_start();
            if r2.starts_with('(') {
                rest = skip_balanced(r2, '(', ')');
                continue;
            }
            if r.starts_with(char::is_whitespace) {
                rest = r;
                continue;
            }
        }
        let mut advanced = false;
        for w in ["default", "async", "unsafe"] {
            if let Some(r) = strip_word(t, w) {
                rest = r;
                advanced = true;
                break;
            }
        }
        if advanced {
            continue;
        }
        // `const fn` 里的 const 是修饰词；裸 const 是 item
        if let Some(r) = strip_word(t, "const") {
            if strip_word(r.trim_start(), "fn").is_some() {
                rest = r;
                continue;
            }
        }
        if let Some(r) = strip_word(t, "extern") {
            let r2 = r.trim_start();
            if r2.starts_with('"') {
                // 已被 mask 抹成空格，直接跳到下一个词
                rest = r2.trim_start();
                continue;
            }
            rest = r;
            continue;
        }
        break;
    }

    let t = rest.trim_start();
    for kw in ITEM_KEYWORDS {
        let hit = if *kw == "macro_rules!" {
            t.strip_prefix("macro_rules!")
        } else {
            strip_word(t, kw)
        };
        if let Some(r) = hit {
            let name: String = r
                .trim_start()
                .chars()
                .take_while(|ch| is_ident_char(*ch))
                .collect();
            if name.is_empty() {
                return None;
            }
            return Some(((*kw).to_string(), name));
        }
    }
    None
}

/// `s` 以词 `w` 开头（后面是非标识符字符）时返回其后的切片。
fn strip_word<'a>(s: &'a str, w: &str) -> Option<&'a str> {
    let s = s.trim_start();
    let r = s.strip_prefix(w)?;
    match r.chars().next() {
        None => Some(r),
        Some(ch) if !is_ident_char(ch) => Some(r),
        _ => None,
    }
}

fn skip_balanced(s: &str, open: char, close: char) -> &str {
    let b: Vec<char> = s.chars().collect();
    if b.is_empty() || b[0] != open {
        return s;
    }
    let mut depth = 0i32;
    for (idx, ch) in s.char_indices() {
        if ch == open {
            depth += 1;
        } else if ch == close {
            depth -= 1;
            if depth == 0 {
                return &s[idx + ch.len_utf8()..];
            }
        }
    }
    s
}

/// 找 `impl` 头里顶层的 ` for `（跳过 `<…>` 内的）。
fn find_top_level_for(s: &str) -> Option<usize> {
    let mut depth = 0i32;
    let bytes: Vec<char> = s.chars().collect();
    let mut byte_idx = 0usize;
    for (k, ch) in bytes.iter().enumerate() {
        match ch {
            '<' | '(' | '[' => depth += 1,
            '>' | ')' | ']' => depth -= 1,
            _ => {}
        }
        if depth == 0 && *ch == ' ' {
            let tail: String = bytes[k + 1..].iter().collect();
            if tail.starts_with("for ") || tail.starts_with("for\t") {
                return Some(byte_idx);
            }
            let _ = k;
        }
        byte_idx += ch.len_utf8();
    }
    None
}

/// 取开头的路径（`std::io::Error` / `MockFs<'a>`）的**最后一段**。
fn leading_path_last(s: &str) -> Option<String> {
    let mut path = String::new();
    for ch in s.chars() {
        if is_ident_char(ch) || ch == ':' {
            path.push(ch);
        } else {
            break;
        }
    }
    let last = path.rsplit("::").next()?.to_string();
    if last.is_empty() {
        None
    } else {
        Some(last)
    }
}

// ===================== 文件枚举 + 跨文件 mod 门控 =====================

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("src-tauri 必有上级目录")
        .to_path_buf()
}

/// 被扫描的生产源码面：`src-tauri/src/**` + `crates/*/src/**`。
///
/// **不含** `crates/*/tests/`（Cargo 集成测试，整目录天然是测试面）。
fn scan_roots() -> Vec<PathBuf> {
    let root = repo_root();
    let mut roots = vec![root.join("src-tauri/src")];
    let mut crate_dirs: Vec<PathBuf> = std::fs::read_dir(root.join("crates"))
        .expect("crates/ 必存在")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    crate_dirs.sort();
    for d in crate_dirs {
        let s = d.join("src");
        if s.is_dir() {
            roots.push(s);
        }
    }
    roots
}

fn walk_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("读不到 {}: {e}", dir.display()))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            walk_rs(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

fn all_files() -> Vec<PathBuf> {
    let mut out = Vec::new();
    for r in scan_roots() {
        walk_rs(&r, &mut out);
    }
    out.sort();
    out
}

fn rel(root: &Path, p: &Path) -> String {
    p.strip_prefix(root)
        .unwrap_or(p)
        .to_string_lossy()
        .replace('\\', "/")
}

/// `mod NAME;`（无 body）在文件系统上的两个候选落点。
fn child_paths(parent: &Path, name: &str) -> [PathBuf; 2] {
    let dir = parent.parent().unwrap_or(Path::new("."));
    let stem = parent.file_stem().map(|s| s.to_string_lossy().to_string());
    let base = match stem.as_deref() {
        Some("mod") | Some("lib") | Some("main") => dir.to_path_buf(),
        Some(s) => dir.join(s),
        None => dir.to_path_buf(),
    };
    [
        base.join(format!("{name}.rs")),
        base.join(name).join("mod.rs"),
    ]
}

/// 把一份 code 面切成「属性块 / 普通行」序列。属性可跨行（按 `[`/`]` 配平合并）。
enum Chunk {
    /// `text` = code 面（结构用）；`cfg_text` = attrs 面（字面量保留，cfg 求值用）。
    Attr {
        line: usize,
        cfg_text: String,
    },
    Line {
        line: usize,
        text: String,
    },
}

/// 按 code 面切块；属性块的文本从 **attrs 面**取（同一行区间），因为 cfg 谓词里的
/// `feature = "test-utils"` 是字面量，在 code 面上已被抹掉。
fn chunks(code: &str, attr_surface: &str) -> Vec<Chunk> {
    let lines: Vec<&str> = code.split('\n').collect();
    let alines: Vec<&str> = attr_surface.split('\n').collect();
    let bal = |t: &str| t.matches('[').count() as i32 - t.matches(']').count() as i32;
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < lines.len() {
        let s = lines[i].trim_start();
        if s.starts_with("#[") || s.starts_with("#![") {
            let mut buf = lines[i].to_string();
            let mut abuf = alines.get(i).copied().unwrap_or("").to_string();
            let start = i;
            while bal(&buf) > 0 && i + 1 < lines.len() {
                i += 1;
                buf.push('\n');
                buf.push_str(lines[i]);
                abuf.push('\n');
                abuf.push_str(alines.get(i).copied().unwrap_or(""));
            }
            out.push(Chunk::Attr {
                line: start,
                cfg_text: abuf,
            });
            i += 1;
        } else {
            out.push(Chunk::Line {
                line: i,
                text: lines[i].to_string(),
            });
            i += 1;
        }
    }
    out
}

/// 从所有文件的 `mod NAME;` 声明推出「整文件已被 cfg 门盖住」的集合（含向下传播）。
fn file_level_gates(
    files: &[PathBuf],
    masked: &BTreeMap<PathBuf, (String, String, String)>,
) -> BTreeSet<PathBuf> {
    let known: BTreeSet<&PathBuf> = files.iter().collect();
    // child -> (parent, 该 mod 声明是否带门)
    let mut edges: Vec<(PathBuf, PathBuf, bool)> = Vec::new();
    for p in files {
        let (code, _, attr_surface) = &masked[p];
        let mut pend = String::new();
        for ch in chunks(code, attr_surface) {
            match ch {
                Chunk::Attr { cfg_text, .. } => {
                    pend.push('\n');
                    pend.push_str(&cfg_text);
                }
                Chunk::Line { text, .. } => {
                    let t = text.trim();
                    if let Some((kw, name)) = parse_item(&text) {
                        if kw == "mod" && t.ends_with(';') {
                            let g = is_gated(&pend);
                            for cp in child_paths(p, &name) {
                                if known.contains(&cp) {
                                    edges.push((cp, p.clone(), g));
                                }
                            }
                        }
                    }
                    if !t.is_empty() {
                        pend.clear();
                    }
                }
            }
        }
    }
    let mut gated: BTreeSet<PathBuf> = BTreeSet::new();
    for _ in 0..16 {
        let before = gated.len();
        for (child, parent, g) in &edges {
            if *g || gated.contains(parent) {
                gated.insert(child.clone());
            }
        }
        if gated.len() == before {
            break;
        }
    }
    gated
}

// ===================== 扫描 =====================

const NAME_NEEDLES: &[&str] = &["Mock", "Fake", "Stub", "Dummy"];
const DOC_NEEDLES: &[&str] = &[
    "测试用",
    "测试 mock",
    "测试mock",
    "仅供测试",
    "桩",
    "测试专用",
    "仅测试",
];

#[derive(Debug)]
struct Hit {
    file: String,
    line: usize,
    kw: String,
    name: String,
    by_name: bool,
    by_doc: bool,
    summary: String,
}

struct Scan {
    hits: Vec<Hit>,
    ungated_tests: Vec<(String, usize)>,
    total_test_attrs: usize,
    /// 实际扫描的 `.rs` 文件数。此前这里是写死的 305，会随仓库漂移而失真。
    files_scanned: usize,
    /// 名字含 tests 的模块声明（第 4 条对照用）：(file, line, name, gated)
    test_named_mods: Vec<(String, usize, String, bool)>,
    /// **真正装着 `#[test]` 的模块**（语义判据，非命名约定）：`file::mod_path` -> `#[test]` 条数。
    /// 键里的 mod_path 为空串表示这些 `#[test]` 直接挂在文件顶层（无 inline mod）。
    modules_with_tests: BTreeMap<String, usize>,
}

fn scan_file(
    relname: &str,
    code: &str,
    docs: &str,
    attr_surface: &str,
    file_gated: bool,
    out: &mut Scan,
) {
    let dl: Vec<&str> = docs.split('\n').collect();
    // (该层是否被 cfg 门盖住, 该层若是 mod 则记其名)
    let mut stack: Vec<(bool, Option<String>)> = Vec::new();
    let mut pend_attrs = String::new();
    let mut pend_docs: Vec<String> = Vec::new();

    for ch in chunks(code, attr_surface) {
        match ch {
            Chunk::Attr { line, cfg_text } => {
                let flat: String = cfg_text.chars().filter(|c| !c.is_whitespace()).collect();
                if flat.starts_with("#[test]")
                    || flat.starts_with("#[test(")
                    || flat.starts_with("#[tokio::test")
                {
                    out.total_test_attrs += 1;
                    let covered =
                        file_gated || stack.iter().any(|(g, _)| *g) || is_gated(&pend_attrs);
                    if !covered {
                        out.ungated_tests.push((relname.to_string(), line + 1));
                    }
                    let mod_path: Vec<&str> =
                        stack.iter().filter_map(|(_, m)| m.as_deref()).collect();
                    *out.modules_with_tests
                        .entry(format!("{relname}::{}", mod_path.join("::")))
                        .or_insert(0) += 1;
                }
                pend_attrs.push('\n');
                pend_attrs.push_str(&cfg_text);
            }
            Chunk::Line { line, text } => {
                let item = parse_item(&text);
                let gated_self = item.is_some() && is_gated(&pend_attrs);
                let gated_anc = file_gated || stack.iter().any(|(g, _)| *g);

                if let Some((kw, name)) = &item {
                    let summary = pend_docs.first().cloned().unwrap_or_default();
                    let by_name = NAME_NEEDLES.iter().any(|nd| name.contains(nd));
                    let by_doc = TYPE_KEYWORDS.contains(&kw.as_str())
                        && DOC_NEEDLES.iter().any(|nd| summary.contains(nd));
                    if (by_name || by_doc) && !(gated_self || gated_anc) {
                        out.hits.push(Hit {
                            file: relname.to_string(),
                            line: line + 1,
                            kw: kw.clone(),
                            name: name.clone(),
                            by_name,
                            by_doc,
                            summary: summary.trim().chars().take(90).collect(),
                        });
                    }
                    if kw == "mod" && name.to_lowercase().contains("test") {
                        out.test_named_mods.push((
                            relname.to_string(),
                            line + 1,
                            name.clone(),
                            gated_self || gated_anc,
                        ));
                    }
                }

                // pending doc / attr 状态机
                let ds = dl.get(line).map(|s| s.trim()).unwrap_or("");
                let t = text.trim();
                if ds.starts_with("///")
                    || ds.starts_with("/**")
                    || (ds.starts_with('*') && !pend_docs.is_empty())
                {
                    pend_docs.push(ds.to_string());
                } else if ds.starts_with("//!") || ds.starts_with("/*!") {
                    // 模块级 doc：永远不属于某个 item
                } else if t.is_empty() {
                    // 空行：不打断
                } else {
                    pend_attrs.clear();
                    pend_docs.clear();
                }

                let o = text.matches('{').count() as i32;
                let c = text.matches('}').count() as i32;
                let cur = gated_self || stack.iter().any(|(g, _)| *g);
                let mod_name = match &item {
                    Some((kw, name)) if kw == "mod" => Some(name.clone()),
                    _ => None,
                };
                for k in 0..(o - c).max(0) {
                    stack.push((cur, if k == 0 { mod_name.clone() } else { None }));
                }
                for _ in 0..(c - o).max(0) {
                    stack.pop();
                }

                if item.is_some() {
                    pend_attrs.clear();
                    pend_docs.clear();
                }
            }
        }
    }
}

fn scan_repo() -> Scan {
    let root = repo_root();
    let files = all_files();
    let mut masked: BTreeMap<PathBuf, (String, String, String)> = BTreeMap::new();
    for p in &files {
        let src =
            std::fs::read_to_string(p).unwrap_or_else(|e| panic!("读不到 {}: {e}", p.display()));
        masked.insert(p.clone(), mask(&src));
    }
    let gates = file_level_gates(&files, &masked);
    let mut out = Scan {
        hits: Vec::new(),
        ungated_tests: Vec::new(),
        total_test_attrs: 0,
        files_scanned: files.len(),
        test_named_mods: Vec::new(),
        modules_with_tests: BTreeMap::new(),
    };
    for p in &files {
        let (code, docs, attr_surface) = &masked[p];
        scan_file(
            &rel(&root, p),
            code,
            docs,
            attr_surface,
            gates.contains(p),
            &mut out,
        );
    }
    out
}

// ===================== 门 =====================

#[test]
fn test_only_symbols_must_be_cfg_gated() {
    let scan = scan_repo();
    let mut wl_used: BTreeSet<(String, String)> = BTreeSet::new();
    let mut bad: Vec<String> = Vec::new();

    for h in &scan.hits {
        let entry = WHITELIST
            .iter()
            .find(|(f, n, _)| *f == h.file && *n == h.name);
        if let Some((f, n, _)) = entry {
            wl_used.insert(((*f).to_string(), (*n).to_string()));
            continue;
        }
        let branch = match (h.by_name, h.by_doc) {
            (true, true) => "NAME+DOC",
            (true, false) => "NAME",
            _ => "DOC",
        };
        bad.push(format!(
            "  {}:{}  [{} {}]  命中 {} 支\n      摘要行: {}\n      修法: 同 crate 消费 → 加 `#[cfg(test)]`；\
             跨 crate 消费 → 该 crate 加 `test-utils` feature 并用 `#[cfg(any(test, feature = \"test-utils\"))]`，\
             消费方 [dev-dependencies] 开该 feature。确属生产 → 登记进 WHITELIST 并写明生产消费者。",
            h.file, h.line, h.kw, h.name, branch, if h.summary.is_empty() { "（无 doc）" } else { &h.summary }
        ));
    }

    let stale: Vec<String> = WHITELIST
        .iter()
        .filter(|(f, n, _)| !wl_used.contains(&((*f).to_string(), (*n).to_string())))
        .map(|(f, n, _)| format!("  {f} :: {n}"))
        .collect();

    assert!(
        bad.is_empty(),
        "\n{} 个测试专用符号没有 cfg 门（它们现在是**生产符号**）：\n{}\n",
        bad.len(),
        bad.join("\n")
    );
    assert!(
        stale.is_empty(),
        "\nWHITELIST 有 {} 条过期条目（已不再命中，说明符号被改名/删除/已加门）—— 删掉它们，\
         否则白名单会退化成垃圾桶，下一个同名符号会被静默放行：\n{}\n",
        stale.len(),
        stale.join("\n")
    );
}

/// 第 4 条：**语义**验证「测试模块都带 cfg(test)」——判据是「函数带 `#[test]`」，
/// 不是「模块名里有 tests」。名字不含 test 的测试模块整类逃逸，正是命名约定型判据的盲区。
#[test]
fn every_test_attribute_is_under_a_cfg_gate() {
    let scan = scan_repo();
    // 正向对照：扫描器必须真的看得见 #[test]，否则「0 个未门控」只是扫描器死了。
    assert!(
        scan.total_test_attrs >= 3000,
        "正向对照失败：全仓只扫到 {} 个 #[test]/#[tokio::test] 属性（实测量级 4000+）——\
         扫描器或取材面坏了，本门的「0 个未门控」无信息量",
        scan.total_test_attrs
    );
    // ---- 第 4 条：命名约定判据 vs 语义判据的对差 ----
    let named_total = scan.test_named_mods.len();
    let named_ungated: Vec<&(String, usize, String, bool)> = scan
        .test_named_mods
        .iter()
        .filter(|(_, _, _, g)| !*g)
        .collect();
    let holders = scan.modules_with_tests.len();
    // 「装着 #[test] 却不叫 *test*」的模块 —— 命名约定型判据整类看不见它们。
    let escapees: Vec<(&String, &usize)> = scan
        .modules_with_tests
        .iter()
        .filter(|(k, _)| {
            let m = k.rsplit("::").next().unwrap_or("");
            !m.to_lowercase().contains("test")
        })
        .collect();
    println!("\n=== 第 4 条：测试模块门控的两种判据对差 ===");
    println!(
        "  取材面：src-tauri/src/** + crates/*/src/**（{} 个 .rs），已剥注释与字符串字面量；",
        scan.files_scanned
    );
    println!(
        "          文件级门从父模块的 `mod x;` 声明读，cfg 谓词按生产构建求值（非字面量匹配）。"
    );
    println!(
        "  命名约定判据（名字含 test）：命中 {named_total} 个 mod，其中无 cfg 门 {} 个 —— \
逐条看都是**生产模块**（假阳性方向）：",
        named_ungated.len()
    );
    for (f, l, n, _) in &named_ungated {
        println!("      {f}:{l}  mod {n}");
    }
    println!("  语义判据    ：真正装着 #[test] 的作用域共 {holders} 个（#[test] 总数 {}），其中未门控 {} 个",
             scan.total_test_attrs, scan.ungated_tests.len());
    println!(
        "  命名约定的盲区（装着 #[test] 但名字不含 test 的作用域）共 {} 个：",
        escapees.len()
    );
    for (k, n) in escapees.iter().take(30) {
        println!("      {k}  ({n} 个 #[test])");
    }

    assert!(
        scan.ungated_tests.is_empty(),
        "\n{} 个 #[test] 不在任何 cfg 门下（自身属性 / 祖先块 / 父模块 `mod x;` 声明都没有）：\n{}\n",
        scan.ungated_tests.len(),
        scan.ungated_tests
            .iter()
            .map(|(f, l)| format!("  {f}:{l}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ===================== 取材面自检（两支各一条切片）=====================

const FIXTURE: &str = r####"
// 行注释里写 struct MockGhost 不是声明
/* 块注释里写 测试用 也不是 doc：NotADocKeywordHere */
const S: &str = "字符串里写 pub struct DummyInString { 还带花括号 }";
const R: &str = r#"原始串里写 // 与 " 与 struct FakeInRaw"#;

/// 测试用：本类型必须被 DOC 支抓到。
pub struct DocOnlyDouble {
    ch: char,
}

pub struct MockGood;

#[cfg(test)]
pub struct MockGatedBySelf;

#[cfg(all(test, unix))]
pub struct MockGatedByAllTestUnix;

#[cfg(any(test, feature = "test-utils"))]
pub struct MockGatedByFeature;

#[cfg(any(target_os = "windows", test))]
pub struct MockNotGatedPlatformPredicate;

#[cfg(test)]
mod inner {
    pub struct MockGatedByAncestor;
}

impl DocOnlyDouble {
    fn lifetime_vs_char<'a>(x: &'a str) -> char {
        let _q = '\'';
        let _b = b'\n';
        let _brace_in_char = '{';
        x.chars().next().unwrap_or('}')
    }
}
"####;

#[test]
fn extraction_self_check_two_surfaces() {
    let (code, docs, attr_surface) = mask(FIXTURE);

    // 行号必须对齐 —— 门的失败信息全靠它定位。
    assert_eq!(
        FIXTURE.split('\n').count(),
        code.split('\n').count(),
        "code 面行数漂移"
    );
    assert_eq!(
        FIXTURE.split('\n').count(),
        docs.split('\n').count(),
        "docs 面行数漂移"
    );

    let cl: Vec<&str> = code.split('\n').collect();
    let dl: Vec<&str> = docs.split('\n').collect();

    // ---- 切片自检 ①：NAME 支的取材面（code，全剥）----
    println!("\n=== 切片自检 ① NAME 支取材面（code：注释与字面量全剥）===");
    for (i, masked_line) in cl.iter().enumerate().take(8).skip(1) {
        println!(
            "  L{:<2} 原文 | {}",
            i + 1,
            FIXTURE.split('\n').nth(i).unwrap()
        );
        println!("       剥后 | {masked_line}");
    }
    assert!(!code.contains("MockGhost"), "行注释里的声明未剥净");
    assert!(!code.contains("DummyInString"), "字符串里的声明未剥净");
    assert!(!code.contains("FakeInRaw"), "原始字符串未剥净");
    assert!(!code.contains("测试用"), "doc 注释未从 code 面剥净");
    assert!(!code.contains("NotADocKeywordHere"), "块注释未剥净");
    assert!(code.contains("pub struct MockGood"), "真声明被误剥");

    // ---- 切片自检 ②：DOC 支的取材面（docs，只剥非 doc 注释与字面量）----
    println!("\n=== 切片自检 ② DOC 支取材面（docs：doc 注释保留，其余剥）===");
    for i in [2, 3, 4, 6, 7] {
        println!(
            "  L{:<2} 原文 | {}",
            i + 1,
            FIXTURE.split('\n').nth(i).unwrap()
        );
        println!("       剥后 | {}", dl[i]);
    }
    assert!(
        docs.contains("/// 测试用：本类型必须被 DOC 支抓到。"),
        "doc 注释被误剥 —— DOC 支会恒绿"
    );
    assert!(
        !docs.contains("NotADocKeywordHere"),
        "非 doc 块注释未从 docs 面剥净"
    );
    assert!(!docs.contains("DummyInString"), "字符串未从 docs 面剥净");
    assert!(!docs.contains("FakeInRaw"), "原始字符串未从 docs 面剥净");

    // ---- 切片自检 ③：cfg 求值面（attrs：只剥注释，字面量保留）----
    // 首版本门就是把 cfg 求值放在 code 面上，`feature = "test-utils"` 的字面量被抹成空格，
    // 于是 `#[cfg(any(test, feature = "test-utils"))]` 被读成「无门」而静默放行。
    let al: Vec<&str> = attr_surface.split('\n').collect();
    println!("\n=== 切片自检 ③ cfg 求值面（attrs：注释剥、字面量留）===");
    for i in [1, 2, 3, 4, 19] {
        println!(
            "  L{:<2} 原文 | {}",
            i + 1,
            FIXTURE.split('\n').nth(i).unwrap()
        );
        println!("       剥后 | {}", al[i]);
    }
    assert!(
        attr_surface.contains("#[cfg(any(test, feature = \"test-utils\"))]"),
        "cfg 求值面把 feature 字面量剥掉了 —— test-utils 门会被读成无门"
    );
    assert!(!attr_surface.contains("MockGhost"), "cfg 面的行注释未剥净");
    assert!(
        !attr_surface.contains("NotADocKeywordHere"),
        "cfg 面的块注释未剥净 —— 被注释掉的 #[cfg(test)] 不是门"
    );

    // ---- 正向对照：扫描器在 fixture 上的判定 ----
    let mut out = Scan {
        hits: Vec::new(),
        ungated_tests: Vec::new(),
        total_test_attrs: 0,
        files_scanned: 1,
        test_named_mods: Vec::new(),
        modules_with_tests: BTreeMap::new(),
    };
    scan_file("FIXTURE", &code, &docs, &attr_surface, false, &mut out);
    let names: Vec<&str> = out.hits.iter().map(|h| h.name.as_str()).collect();
    println!("\n=== fixture 上的命中 ===\n  {names:?}");
    assert!(
        names.contains(&"DocOnlyDouble"),
        "DOC 支未命中（正向对照失败）"
    );
    assert!(names.contains(&"MockGood"), "NAME 支未命中（正向对照失败）");
    assert!(
        names.contains(&"MockNotGatedPlatformPredicate"),
        "cfg(any(target_os=…, test)) 不应算门控 —— 它在 Windows 生产构建里真的存在"
    );
    for gated in [
        "MockGatedBySelf",
        "MockGatedByAllTestUnix",
        "MockGatedByFeature",
        "MockGatedByAncestor",
        "MockGhost",
        "DummyInString",
        "FakeInRaw",
    ] {
        assert!(!names.contains(&gated), "{gated} 不该命中");
    }
}

#[test]
fn cfg_evaluator_self_check() {
    for (expr, survives_prod) in [
        ("test", false),
        ("all(test, unix)", false),
        ("any(test, feature = \"test-utils\")", false),
        ("any(target_os = \"windows\", test)", true),
        ("not(test)", true),
        ("windows", true),
        ("all(unix, not(test))", true),
        ("feature = \"test-utils\"", false),
        ("any(feature = \"test-utils\", feature = \"other\")", true),
    ] {
        assert_eq!(
            eval_cfg(expr),
            survives_prod,
            "cfg({expr}) 在生产构建下的存活判定错了"
        );
    }
}

// ===================== test-utils feature 的隔离门 =====================

/// `test-utils` 只能从 `[dev-dependencies]` 打开。
///
/// # 为什么需要这道门
///
/// 上一道门把跨 crate 的测试替身收进 `#[cfg(any(test, feature = "test-utils"))]`。
/// 那个 cfg 本身**不保证**替身不进生产 —— 保证来自「谁打开这个 feature」：
/// resolver = "2" 下 dev-dependency 的 feature 不会被统一进 `cargo build` / `cargo tauri build`
/// 的普通依赖图（实证：`cargo tree -e features --edges normal` 只有 `default`；
/// 临时插 `#[cfg(all(feature = "test-utils", not(test)))] compile_error!` 后
/// `cargo build --workspace` 仍 rc=0，而 `cargo check -p polaris --all-targets` 立刻炸）。
///
/// 但只要有人把 `features = ["test-utils"]` 写进 `[dependencies]`（复制粘贴一行即可），
/// 上面那条实证当场失效、替身直接进 release 产物，**没有任何编译错误**。
/// 「答案是『能，只要有人忘了』就是没治到根」—— 所以判据落成这道门，而不是留在文档里。
#[test]
fn test_utils_feature_is_enabled_only_from_dev_dependencies() {
    let root = repo_root();
    let mut manifests = vec![root.join("Cargo.toml"), root.join("src-tauri/Cargo.toml")];
    let mut crate_dirs: Vec<PathBuf> = std::fs::read_dir(root.join("crates"))
        .expect("crates/ 必存在")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    crate_dirs.sort();
    for d in crate_dirs {
        let m = d.join("Cargo.toml");
        if m.is_file() {
            manifests.push(m);
        }
    }

    let mut declarations = 0usize;
    let mut dev_enables: Vec<String> = Vec::new();
    let mut violations: Vec<String> = Vec::new();

    for m in &manifests {
        let text = std::fs::read_to_string(m).unwrap_or_default();
        let mut section = String::new();
        for (idx, raw) in text.lines().enumerate() {
            // 剥 TOML 行注释（引号内的 `#` 不算）
            let mut line = String::new();
            let mut in_str = false;
            for ch in raw.chars() {
                match ch {
                    '"' => {
                        in_str = !in_str;
                        line.push(ch);
                    }
                    '#' if !in_str => break,
                    _ => line.push(ch),
                }
            }
            let t = line.trim();
            if t.starts_with('[') && t.ends_with(']') {
                section = t.trim_matches(|c| c == '[' || c == ']').to_string();
                continue;
            }
            if !t.contains("test-utils") {
                continue;
            }
            let where_ = format!("{}:{}  [{}]  {}", rel(&root, m), idx + 1, section, t);
            if section == "features" {
                declarations += 1;
            } else if section.contains("dev-dependencies") {
                dev_enables.push(where_);
            } else {
                violations.push(where_);
            }
        }
    }

    // 正向对照：门必须真的看见了声明面与开启面，否则「0 违规」只是解析器死了。
    assert!(
        declarations >= 2,
        "正向对照失败：只解析到 {declarations} 条 `test-utils` feature 声明（实况 ≥2：polaris-updater / polaris-helper-client）"
    );
    assert!(
        dev_enables.len() >= 2,
        "正向对照失败：只解析到 {} 条 [dev-dependencies] 开启点（实况 ≥2，都在 src-tauri/Cargo.toml）",
        dev_enables.len()
    );
    assert!(
        violations.is_empty(),
        "\n`test-utils` 被从**非 dev-dependencies** 的位置打开 —— 测试替身会随普通依赖进 release 产物：\n{}\n\
         正确写法：普通依赖不带该 feature，只在 [dev-dependencies] 里重复声明一次并加 features = [\"test-utils\"]。\n",
        violations.join("\n")
    );
}
