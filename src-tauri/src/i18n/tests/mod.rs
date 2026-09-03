use super::*;
use crate::test_support::crate_code;

// ════════════════════════════════════════════════════════════════════════
// 语言解析（口径必须与 ui/src/domain/language.ts 一致）
// ════════════════════════════════════════════════════════════════════════

#[test]
fn explicit_choice_wins_over_system() {
    let sys = vec!["zh-CN".to_owned()];
    assert_eq!(resolve_effective("ru", &sys), Lang::Ru);
    assert_eq!(resolve_effective("fa", &sys), Lang::Fa);
    assert_eq!(resolve_effective("en-US", &sys), Lang::EnUS);
    assert_eq!(
        resolve_effective(" zh-TW ", &sys),
        Lang::ZhTW,
        "两侧空白应 trim"
    );
}

/// 存量 `fa-IR` 必须与前端 `migrateLanguageCode` 同口径迁移；不迁移的症状是波斯语老用户
/// 的原生对话框恒回落系统语言，而应用内一切正常 —— 查不出来。
#[test]
fn legacy_fa_ir_migrates_to_fa() {
    assert_eq!(resolve_effective("fa-IR", &[]), Lang::Fa);
}

#[test]
fn auto_and_unknown_fall_back_to_system_preference() {
    for choice in ["auto", "", "   ", "de-DE", "ZH-CN"] {
        assert_eq!(
            resolve_effective(choice, &["ru-RU".to_owned()]),
            Lang::Ru,
            "{choice} 应回落系统偏好"
        );
    }
    // 系统偏好也认不出 → DEFAULT（en-US），**不是**中文。
    assert_eq!(resolve_effective("auto", &["de-DE".to_owned()]), Lang::EnUS);
    assert_eq!(resolve_effective("auto", &[]), Lang::EnUS);
}

/// 中文的简繁消歧：`Hant` 脚本或 tw/hk/mo 地区 → 繁体，其余（含裸 `zh` / `Hans` / `sg`）→ 简体。
/// 弄反的症状是全体繁体用户看到简体（或反之），而门若只测 `zh-CN`/`zh-TW` 两个规范码测不出来。
#[test]
fn chinese_script_and_region_disambiguation_matches_frontend() {
    for (sys, want) in [
        ("zh-Hant", Lang::ZhTW),
        ("zh-TW", Lang::ZhTW),
        ("zh-Hant-HK", Lang::ZhTW),
        ("zh_MO", Lang::ZhTW),
        ("zh-Hans-CN", Lang::ZhCN),
        ("zh", Lang::ZhCN),
        ("zh-SG", Lang::ZhCN),
    ] {
        assert_eq!(
            resolve_effective("auto", &[sys.to_owned()]),
            want,
            "系统 locale {sys} 解析错了"
        );
    }
}

/// 系统偏好是**有序**列表，命中即止（前端 `resolveAutoLanguage` 同款）。
#[test]
fn system_preference_list_is_ordered_first_match_wins() {
    assert_eq!(
        resolve_effective(
            "auto",
            &["de-DE".to_owned(), "ru".to_owned(), "fa".to_owned()]
        ),
        Lang::Ru
    );
}

// ════════════════════════════════════════════════════════════════════════
// 文案表 + 回落链
// ════════════════════════════════════════════════════════════════════════

#[test]
fn five_catalogs_are_embedded_and_non_trivial() {
    assert_eq!(
        CATALOGS.len(),
        5,
        "语种数不对 —— SUPPORTED 与 include_str! 分叉了"
    );
    for l in SUPPORTED {
        let c = catalog(l);
        assert!(
            c.len() >= 50,
            "{} 只解析出 {} 条文案 —— aux JSON 结构变了？",
            l.code(),
            c.len()
        );
    }
}

/// 回落链 `lang → en-US → 键名`。第三档必须是**键名本身**，不得是中文
/// （回落中文 = 波斯语用户在缺译时看到中文，正是本模块要消灭的形态）。
#[test]
fn fallback_chain_is_lang_then_en_then_key_name() {
    assert_eq!(t(Lang::Ru, key::NATIVE_CANCEL), "Отмена");
    // 不存在的键：五个语种都必须原样回键名。
    for l in SUPPORTED {
        assert_eq!(t(l, "native.__no_such_key__"), "native.__no_such_key__");
    }
}

/// 每一条声明过的键都必须在**五个**语种里各有真译文（不靠回落）。
///
/// 这是「加了 Rust 文案却只补了中文」的直接判据。反向（locale 里有、Rust 没消费）见下一条。
#[test]
fn every_declared_key_resolves_in_all_five_locales() {
    let keys = declared_keys();
    assert!(
        keys.len() >= 30,
        "只解析出 {} 个键常量 —— `mod key` 的写法变了？门已失去判据",
        keys.len()
    );
    let mut missing = Vec::new();
    for k in &keys {
        for l in SUPPORTED {
            match catalog(l).get(k.as_str()) {
                Some(v) if !v.trim().is_empty() => {}
                Some(_) => missing.push(format!("  {} 的 {k} 是空串", l.code())),
                None => missing.push(format!("  {} 缺 {k}", l.code())),
            }
        }
    }
    assert!(
        missing.is_empty(),
        "Rust 侧消费的键没有五语种齐备（补进 ui/src/i18n/locales/auxiliary/*.json）：\n{}",
        missing.join("\n")
    );
}

/// 反向对差：`native.*` 命名空间里的每一条都必须被 `mod key` 声明。
///
/// `native.*` 的**唯一**消费方是 Rust（前端不加载它，`i18n-coverage.test.ts` 的 G4 还禁止
/// TS 侧消费）⇒ 没有 Rust 常量指向它 = 死翻译，会一直被翻译者维护却没人显示。
/// `tray.*` 不在本条射程内：它归浮层所有，Rust 只是共用其中一部分。
#[test]
fn every_native_key_in_locale_is_declared_here() {
    let declared = declared_keys();
    let dead: Vec<_> = catalog(Lang::EnUS)
        .keys()
        .filter(|k| k.starts_with("native.") && !declared.contains(*k))
        .cloned()
        .collect();
    assert!(
        dead.is_empty(),
        "aux 的 native.* 里有没人消费的死键（删掉，或在 `mod key` 里登记消费点）：{dead:?}"
    );
}

/// 从本文件源码抽出 `mod key` 里声明的全部键值。
///
/// 用源码扫描而不是另维护一张 `ALL: &[&str]` 表：两张表必然漂移，而漂移的方向恰好是
/// 「新键忘了登记 ⇒ 门看不见它 ⇒ 门恒绿」。
fn declared_keys() -> Vec<String> {
    let src = crate_code("i18n.rs");
    let start = src
        .find("pub mod key {")
        .expect("锚点消失：`pub mod key {` —— 门已失去判据");
    let body = &src[start..];
    let end = body
        .find("\n}\n")
        .expect("锚点消失：`mod key` 的收尾 —— 门已失去判据");
    let mut out = Vec::new();
    for line in body[..end].lines() {
        let l = line.trim();
        if !l.starts_with("pub const ") {
            continue;
        }
        let Some(rest) = l.split_once(" = \"") else {
            continue;
        };
        let Some((v, _)) = rest.1.split_once('"') else {
            continue;
        };
        out.push(v.to_owned());
    }
    out
}

// ════════════════════════════════════════════════════════════════════════
// 门：Rust 侧用户可见文案不得裸写中文
// ════════════════════════════════════════════════════════════════════════
//
// # 为什么是「按 sink 收口」而不是「全仓禁裸中文字符串」
//
// `src-tauri/src` 里有 **3538** 条含中文的字符串字面量（实测）：日志、单测断言消息、
// 诊断报告正文、panic 文案。它们**不是**缺陷 —— 本仓的写作约定就是中文注释 + 中文日志。
// 一刀切禁掉等于要求把全仓日志改英文，那是另一件事。真正的缺陷面是「**送到用户眼前的
// 原生表面**」：文件对话框、消息框、菜单项、tooltip、系统通知、窗口标题。这些出口是
// **可枚举的**（下方 `SINKS`），且新增一个出口必然要写出这些 API 名之一。
//
// # 注释里的中文怎么排除（本门最大的假阳性源）
//
// 不靠正则「跳过以 `//` 开头的行」——那对块注释、行尾注释、`///` 文档注释里带引号的例子
// 全部失效。改成**词法切分**（[`tokenize`]）：单行/块注释（Rust 块注释可嵌套）、普通串、
// 原始串（`r#"…"#`）、字节/C 串、字符字面量（并与生命周期 `'a` 区分）各按语法走一遍，
// 产出两样东西：
//   ① **代码骨架**：与原文**等长**，注释字节与字符串**内容**字节一律换成空格（保留换行与引号）。
//      sink 模式只在骨架上匹配 ⇒ 注释里写 `.set_title("导出…")` 当例子不会触发；
//      括号配对也在骨架上做 ⇒ 串里的括号不会把配对带跑偏。
//   ② **字面量表**：每条串在原文里的字节区间 + 是否含 CJK。
// 一条 CJK 字面量落在某个 sink 调用的实参括号内 ⇒ 转红。
//
// # 读不到就抛
//
// 扫不到文件、某个 sink 模式在全仓一次都没匹配上（= 被改名 / 被删干净）⇒ **panic**，
// 不是静默跳过。「扫到 0 处于是 0 条断言全绿」是假门。

/// 用户可见的原生表面 —— 每条模式的实参里都不得出现裸中文字面量。
///
/// 收录判据 = 「这个调用的字符串实参会**原样显示给用户**」。刻意**不收** `.body(`：
/// 全仓 5 处里 3 处是 HTTP 请求体（`icon_cache.rs` / `runtime/http.rs`），语义完全不同；
/// 通知那一处由唯一漏斗 `notify_user(` 覆盖。
const SINKS: &[&str] = &[
    ".set_title(",                           // 文件对话框标题 / 窗口标题
    ".add_filter(",                          // 文件对话框过滤器显示名
    ".set_file_name(",                       // 文件对话框默认文件名
    ".message(",                             // 消息框正文
    ".title(",                               // 消息框标题 / 通知标题 / 建窗标题
    ".set_tooltip(",                         // 托盘 tooltip
    "MessageDialogButtons::OkCancelCustom(", // 消息框自定义按钮
    "MenuItem::with_id(",                    // 菜单项（同时命中 CheckMenuItem::with_id）
    "Submenu::with_items(",                  // 子菜单标题
    "notify_user(",                          // 系统通知（本仓唯一漏斗）
];

/// 一条字符串字面量在原文里的位置与成分。
#[derive(Debug)]
struct Lit {
    /// 内容起始字节偏移（不含起始引号）。
    start: usize,
    /// 内容结束字节偏移（不含结束引号）。
    end: usize,
    has_cjk: bool,
}

/// CJK 统一表意文字 + 扩展 A + 兼容 + CJK 标点 + 全角。与
/// `ui/src/i18n/i18n-coverage.test.ts` 的 `CJK` 同口径（假名/谚文不算，本仓不出这两个语种）。
fn is_cjk(c: char) -> bool {
    matches!(c,
            '\u{3400}'..='\u{4DBF}'
            | '\u{4E00}'..='\u{9FFF}'
            | '\u{F900}'..='\u{FAFF}'
            | '\u{3000}'..='\u{303F}'
            | '\u{FF00}'..='\u{FFEF}')
}

/// 词法切分：返回（与原文等长的代码骨架, 字符串字面量表）。详见上方段落。
fn tokenize(src: &str) -> (String, Vec<Lit>) {
    let b = src.as_bytes();
    let n = b.len();
    let mut sk = b.to_vec();
    let mut lits = Vec::new();
    // 抹掉 [s, e)：换行保留（骨架的行号要与原文对得上），其余换空格（保持等长）。
    let blank = |sk: &mut Vec<u8>, s: usize, e: usize| {
        for byte in &mut sk[s..e] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
    };
    let is_ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut i = 0usize;
    while i < n {
        // 行注释（含 /// 与 //!）
        if b[i] == b'/' && i + 1 < n && b[i + 1] == b'/' {
            let e = src[i..].find('\n').map_or(n, |p| i + p);
            blank(&mut sk, i, e);
            i = e;
            continue;
        }
        // 块注释（Rust 可嵌套）
        if b[i] == b'/' && i + 1 < n && b[i + 1] == b'*' {
            let s = i;
            let mut depth = 1usize;
            i += 2;
            while i < n && depth > 0 {
                if b[i] == b'/' && i + 1 < n && b[i + 1] == b'*' {
                    depth += 1;
                    i += 2;
                } else if b[i] == b'*' && i + 1 < n && b[i + 1] == b'/' {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            assert_eq!(
                depth, 0,
                "块注释未闭合（偏移 {s}）—— 词法器读不下去，不静默跳过"
            );
            blank(&mut sk, s, i);
            continue;
        }
        // 原始串 r"…" / r#"…"# / br#"…"# / cr#"…"#
        let prefix_ok = i == 0 || !is_ident(b[i - 1]);
        if prefix_ok {
            let mut j = i;
            if b[j] == b'b' || b[j] == b'c' {
                j += 1;
            }
            if j < n && b[j] == b'r' {
                let mut h = j + 1;
                while h < n && b[h] == b'#' {
                    h += 1;
                }
                if h < n && b[h] == b'"' {
                    let hashes = h - (j + 1);
                    let term = format!("\"{}", "#".repeat(hashes));
                    let cs = h + 1;
                    let ce = src[cs..]
                        .find(&term)
                        .map(|p| cs + p)
                        .unwrap_or_else(|| panic!("原始串未闭合（偏移 {i}）"));
                    lits.push(Lit {
                        start: cs,
                        end: ce,
                        has_cjk: src[cs..ce].chars().any(is_cjk),
                    });
                    blank(&mut sk, cs, ce);
                    i = ce + term.len();
                    continue;
                }
            }
        }
        // 普通串 "…" / b"…" / c"…"
        let str_start = if b[i] == b'"' {
            Some(i + 1)
        } else if prefix_ok && (b[i] == b'b' || b[i] == b'c') && i + 1 < n && b[i + 1] == b'"' {
            Some(i + 2)
        } else {
            None
        };
        if let Some(cs) = str_start {
            let mut j = cs;
            loop {
                assert!(j < n, "字符串未闭合（偏移 {i}）");
                match b[j] {
                    b'\\' => j += 2,
                    b'"' => break,
                    _ => j += 1,
                }
            }
            lits.push(Lit {
                start: cs,
                end: j,
                has_cjk: src[cs..j].chars().any(is_cjk),
            });
            blank(&mut sk, cs, j);
            i = j + 1;
            continue;
        }
        // 字符字面量 vs 生命周期：`'a` / `'static` 不是字面量，`'x'` / `'\n'` / `'中'` 是。
        if b[i] == b'\'' {
            let rest = &src[i + 1..];
            let lit_len = if let Some(after_backslash) = rest.strip_prefix('\\') {
                // 转义形：`'\n'` / `'\''` / `'\u{4e2d}'` —— 长度 = 反斜杠 + 转义体 + 收尾引号。
                after_backslash.find('\'').map(|p| p + 2)
            } else {
                rest.chars()
                    .next()
                    .map(char::len_utf8)
                    .filter(|&l| rest.as_bytes().get(l) == Some(&b'\''))
            };
            if let Some(l) = lit_len {
                blank(&mut sk, i + 1, i + 1 + l);
                i += l + 2;
                continue;
            }
            i += 1;
            continue;
        }
        i += 1;
    }
    (
        String::from_utf8(sk).expect("骨架只把注释/串内容换成 ASCII 空格，必然仍是合法 UTF-8"),
        lits,
    )
}

/// 一条命中：sink 名 + 行号 + 文案。
#[derive(Debug, PartialEq, Eq)]
struct Finding {
    line: usize,
    sink: &'static str,
    text: String,
}

/// 扫一份源码：落在 sink 实参括号内的裸 CJK 字面量。
///
/// 返回值第二项是「本文件里每个 sink 各命中几处调用」，供全仓自检（模式失效即全 0）。
fn scan(src: &str) -> (Vec<Finding>, HashMap<&'static str, usize>) {
    let (skeleton, lits) = tokenize(src);
    let sk = skeleton.as_bytes();
    let mut hits = Vec::new();
    let mut counts: HashMap<&'static str, usize> = SINKS.iter().map(|s| (*s, 0)).collect();
    for sink in SINKS {
        let mut from = 0usize;
        while let Some(p) = skeleton[from..].find(sink) {
            let at = from + p;
            from = at + sink.len();
            *counts.get_mut(sink).expect("counts 由 SINKS 构造") += 1;
            // 实参区间 = 模式末尾那个 '(' 到与之配对的 ')'。骨架里串内容已抹空 ⇒ 不会被串里的括号带跑。
            let open = at + sink.len() - 1;
            let mut depth = 0i32;
            let mut close = None;
            for (k, byte) in sk.iter().enumerate().skip(open) {
                match byte {
                    b'(' => depth += 1,
                    b')' => {
                        depth -= 1;
                        if depth == 0 {
                            close = Some(k);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let close = close.unwrap_or(sk.len());
            for l in lits
                .iter()
                .filter(|l| l.has_cjk && l.start > open && l.end <= close)
            {
                hits.push(Finding {
                    line: src[..l.start].matches('\n').count() + 1,
                    sink,
                    text: src[l.start..l.end].chars().take(40).collect(),
                });
            }
        }
    }
    (hits, counts)
}

/// 递归收 `src-tauri/src` 下的 `.rs`。
fn rust_sources() -> Vec<std::path::PathBuf> {
    fn walk(dir: &std::path::Path, acc: &mut Vec<std::path::PathBuf>) {
        let rd =
            std::fs::read_dir(dir).unwrap_or_else(|e| panic!("读不到目录 {}：{e}", dir.display()));
        for ent in rd {
            let p = ent.expect("目录项读取失败").path();
            if p.is_dir() {
                walk(&p, acc);
            } else if p.extension().is_some_and(|e| e == "rs") {
                acc.push(p);
            }
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut acc = Vec::new();
    walk(&root, &mut acc);
    acc.sort();
    acc
}

/// **本门的自证**：词法器把注释里的中文排除掉、把代码里的中文抓出来。
///
/// 这两条是磁盘变异测试（往真文件塞一条裸中文 ⇒ 红；塞进注释 ⇒ 不红）的自动化对应物 ——
/// 磁盘变异是一次性的人工判据，这两条永久钉在 CI 上，防的是「哪天有人把注释剥离改坏了，
/// 门从此对注释假阳性/对代码假阴性」。
#[test]
fn gate_flags_code_literals_and_ignores_comments() {
    // ① 代码里的裸中文 ⇒ 抓到
    let (bad, _) = scan("fn f() { d().set_title(\"导出备份\"); }");
    assert_eq!(bad.len(), 1, "代码里的裸中文没被抓到：{bad:?}");
    assert_eq!(bad[0].text, "导出备份");

    // ② 各种形态的注释里的中文 ⇒ 一条都不抓
    let commented = r##"
            // 行注释：`.set_title("导出备份")` 这样写就错了
            /// 文档注释：.add_filter("所有文件", &["*"])
            //! 内层文档注释：.message("需要修复提权助手")
            /* 块注释
               .set_title("导入配置备份")
               /* 嵌套块注释 .title("未知错误") */
            */
            fn f() { let s = "日志里的中文不算用户可见"; log::info!("托盘：{s}"); }
        "##;
    let (clean, _) = scan(commented);
    assert!(
        clean.is_empty(),
        "注释/日志里的中文被误判成用户文案：{clean:?}"
    );

    // ③ 原始串 / 字节串 / 转义引号 / 生命周期 都不能把词法器带跑
    let tricky = r####"
            fn f<'a>(x: &'a str) { let _ = '中'; let _ = '\''; let _ = "带\"引号\"的中文";
                let _ = r#"原始串里的 "引号" 与中文"#;
                d().set_title(r"原始串标题"); }
        "####;
    let (t3, _) = scan(tricky);
    assert_eq!(t3.len(), 1, "原始串/转义/生命周期把词法器带跑了：{t3:?}");
    assert_eq!(t3[0].text, "原始串标题");
}

/// 全仓门：任何 sink 的实参里都不得出现裸中文。
#[test]
fn no_hardcoded_cjk_in_user_facing_native_sinks() {
    let files = rust_sources();
    assert!(
        files.len() >= 30,
        "只扫到 {} 个 .rs —— 目录布局变了？门已失去判据",
        files.len()
    );
    let mut findings = Vec::new();
    let mut totals: HashMap<&'static str, usize> = SINKS.iter().map(|s| (*s, 0)).collect();
    for f in &files {
        let src =
            std::fs::read_to_string(f).unwrap_or_else(|e| panic!("读不到 {}：{e}", f.display()));
        let (hits, counts) = scan(&src);
        for (k, v) in counts {
            *totals.get_mut(k).expect("totals 由 SINKS 构造") += v;
        }
        let rel = f.strip_prefix(env!("CARGO_MANIFEST_DIR")).unwrap_or(f);
        for h in hits {
            findings.push(format!(
                "  {}:{} 经 `{}` 显示裸中文「{}」",
                rel.display(),
                h.line,
                h.sink,
                h.text
            ));
        }
    }
    // 自检：任何一条模式在全仓一次都没匹配上 = API 被改名/该出口被删 ⇒ 这条断言从此恒真。
    let dead: Vec<_> = totals
        .iter()
        .filter(|(_, n)| **n == 0)
        .map(|(s, _)| *s)
        .collect();
    assert!(
        dead.is_empty(),
        "这些 sink 模式在全仓一处都没匹配上（被改名了？删了？）——留着等于门的这几档恒绿：{dead:?}"
    );
    assert!(
            findings.is_empty(),
            "Rust 侧的用户可见文案硬编码了中文（非中文用户会看到中文）。\
             修法：把文案加进 `ui/src/i18n/locales/auxiliary/*.json` 的 `native` 命名空间（五语种齐补），\
             在 `i18n::key` 登记常量，调用点改 `i18n::t(lang, key::X)`：\n{}",
            findings.join("\n")
        );
}
