//! 本地 renderer → 应用命令这条高权限边界的 **CSP 纵深防线**。
//!
//! 打包态真正生效的策略来自 Tauri 响应层（Linux 注入 meta，macOS/Windows 发 header），配置在
//! `src-tauri/tauri.conf.json` 的 `app.security.{csp,devCsp}`；`ui/` 下的 renderer 入口 HTML 各自
//! 还有一条**同口径**的 meta 兜底，覆盖 Vite dev server 与「浏览器直开 dist」这两种响应层够不着
//! 的场景（meta 形态的 `frame-ancestors` 本就不生效，故那一条只在响应层要求）。
//!
//! # 这道门此前的四个假绿（本批修的就是它们）
//!
//! 1. **判据打在 HTML 原文上，注释一个字都没剥。** `ui/index.html` 的一段注释里逐字写着
//!    `script-src 'self'`（解释「为什么用 `<style>` 而不是内联 `<script>`」）⇒ 把那条真 meta
//!    整条删掉、只留一句 `<!-- script-src 'self' -->`，两条正面 `contains` 照绿 —— 策略没了，
//!    门不响。→ 全部判据改打在 [`mask_html_comments`] 的净化面上。
//! 2. **内联脚本扫描用 `"<script "`（`script` 后面带一个空格）分段。** 最典型的两种内联写法
//!    ——无属性的 `<script>alert(1)</script>`、属性换行的 `<script\n  type="module">`——
//!    压根不进循环，而这条断言想守的正是「不许引入内联脚本」。→ 改成按「`<script` 之后是
//!    空白 / `>` / `/`」判标签边界。
//! 3. **覆盖面由夹具定，不由判据定。** 三个入口路径写死在测试里 ⇒ `ui/` 下将来新增的 renderer
//!    入口不受任何约束，而且不报错。→ 改成遍历 `ui/**.html`，只放行一份**必须真实存在**的
//!    开发夹具豁免名单，且随包分发的入口一条都不许落进该名单。
//! 4. **CSP 用子串 `contains` 判，而 source list 是无序集合 + 自由空白。** 旧的三条判据是
//!    「正面 `contains("script-src 'self'")` + 否定 `!contains("'unsafe-eval'")` + 否定
//!    `!contains("script-src 'self' 'unsafe-inline'")`」，实测（本文件末尾三条守卫是它的收据）：
//!    - `script-src 'self' https://evil.example` —— 追加任意外部源，三条全过；
//!    - `script-src 'self'  'unsafe-inline'` —— **只多打一个空格**，正面判据照命中，而否定
//!      判据那串写死单空格的字面量不再匹配 ⇒ `'unsafe-inline'` 就这么进来了。
//!
//!    （顺带记一条**没有**被绕过的：`script-src 'unsafe-inline' 'self'` 这种顺序对调会让正面
//!    判据落空，旧门是红的。子串判据的洞在「追加」与「空白」，不在「重排」。）
//!
//!    → 改成解析出每条 directive 的 source list 逐条**集合相等**（token 化后与空白无关），
//!    并把 directive 的**名字集合**本身也钉死：一条新加的 `script-src-elem 'unsafe-inline'`
//!    会在元素层整个覆盖 `script-src`，而任何只盯着 `script-src` 的检查都看不见它。

use std::collections::BTreeMap;

use crate::test_support::{
    crate_file, expect_marker, mask_html_comments, repo_dir_files, repo_file,
};

/// renderer 入口 HTML 的取材目录（相对仓库根）。
const ENTRY_DIR: &str = "ui";

/// **不进产品**的开发夹具入口：只由 Vite dev server 直开做保真对拍，从不进
/// `rollupOptions.input`，因而不随包分发、也不承载 IPC 权限，故豁免 meta 兜底那一条。
///
/// 豁免只针对「必须有 CSP meta」这一条 —— 禁内联脚本对它们同样生效（见下方扫描顺序）。
/// 名单里的每一条都必须**真实存在**：陈旧条目 = 名单在替一个已经不存在的文件挡门。
const DEV_ONLY_ENTRIES: [&str; 2] = ["ui/harness.html", "ui/tray-harness.html"];

/// 三份策略（prod / dev / meta 兜底）**共有**的 directive 与其 source list。
///
/// 共有部分单点声明，是因为「meta 兜底与响应层策略是同口径」这句话本身就是判据：各写一份就
/// 等于允许两边悄悄漂移，而漂移的那一侧恰恰是响应层够不着、只剩 meta 顶着的那些场景。
const SHARED_DIRECTIVES: [(&str, &[&str]); 6] = [
    ("default-src", &["'self'"]),
    (
        "img-src",
        &[
            "'self'",
            "data:",
            "https:",
            "polaris-icon:",
            "http://polaris-icon.localhost",
        ],
    ),
    ("style-src", &["'self'", "'unsafe-inline'"]),
    ("script-src", &["'self'"]),
    ("object-src", &["'none'"]),
    ("base-uri", &["'none'"]),
];

/// IPC 通道：`connect-src` 的**完整**允许集（dev 腿另加 `ws:` 给 Vite HMR）。
const IPC_CONNECT: [&str; 3] = ["'self'", "ipc:", "http://ipc.localhost"];

/// 一份完整策略的期望形 = 共有部分 + 本腿的 `connect-src`（+ 只有响应层才生效的
/// `frame-ancestors`）。
fn expected_policy<'a>(
    connect: &'a [&'a str],
    frame_ancestors: bool,
) -> Vec<(&'a str, &'a [&'a str])> {
    let mut expected: Vec<(&'a str, &'a [&'a str])> = SHARED_DIRECTIVES.to_vec();
    expected.push(("connect-src", connect));
    if frame_ancestors {
        expected.push(("frame-ancestors", &["'none'"]));
    }
    expected
}

// ── 判据实现 ──────────────────────────────────────────────────────────────

/// CSP 文本 → `directive 名 → source list`。
///
/// 重复的 directive 直接 panic：CSP 只认第一条、后面那条被**静默**忽略，于是同一份策略在
/// 人眼和浏览器里读出两个不同的结果 —— 那正是给审阅者下套的形状。
fn csp_directives(policy: &str, origin: &str) -> BTreeMap<String, Vec<String>> {
    let mut parsed: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for chunk in policy.split(';') {
        let mut tokens = chunk.split_whitespace();
        let Some(name) = tokens.next() else {
            continue;
        };
        let name = name.to_ascii_lowercase();
        let sources: Vec<String> = tokens.map(str::to_owned).collect();
        assert!(
            parsed.insert(name.clone(), sources).is_none(),
            "{origin}：directive `{name}` 出现了两次。CSP 只认第一条、后面那条被静默忽略 —— \
             同一份策略在人眼和浏览器里会读出两个不同的结果。"
        );
    }
    assert!(
        !parsed.is_empty(),
        "{origin}：解析不出任何 directive —— 判据已经失去对象，后面每一条断言都会恒真。"
    );
    parsed
}

/// 整条策略必须**恰好**是 `expected`：名字集合相等，且每条的 source list 集合相等。
///
/// # 为什么是集合相等，而不是 `contains`
///
/// source list 是**无序集合 + 自由空白**，而子串判据只能枚举写死的字面量。两条实测过的绕法：
/// `script-src 'self' https://evil.example` 满足 `contains("script-src 'self'")`；
/// `script-src 'self'  'unsafe-inline'`（多打一个空格）同时满足那条正面判据与
/// `!contains("script-src 'self' 'unsafe-inline'")` 这条否定判据。token 化之后两者都无处可藏。
///
/// # 为什么连**名字集合**也要钉死
///
/// 只逐条检查已知 directive，等于默许新加 directive。而 CSP 里新加一条就能推翻旧的：
/// `script-src-elem` 存在时，`<script>` 元素**只**看它、完全不看 `script-src`。名字集合钉死
/// 之后，任何新增/删除都必须先过这道门的复审。
fn expect_policy(policy: &str, expected: &[(&str, &[&str])], origin: &str) {
    let parsed = csp_directives(policy, origin);

    let mut actual_names: Vec<&str> = parsed.keys().map(String::as_str).collect();
    let mut expected_names: Vec<&str> = expected.iter().map(|(name, _)| *name).collect();
    actual_names.sort_unstable();
    expected_names.sort_unstable();
    assert_eq!(
        actual_names, expected_names,
        "{origin}：directive 的名字集合变了。多出来的 directive 可能整个覆盖既有的那条\
         （`script-src-elem` 之于 `script-src`），少掉的那条则是防线直接消失 —— \
         两个方向都必须在这里被看见一次。"
    );

    for (name, want) in expected {
        let mut have: Vec<&str> = parsed[*name].iter().map(String::as_str).collect();
        let mut want: Vec<&str> = want.to_vec();
        have.sort_unstable();
        want.sort_unstable();
        assert_eq!(
            have, want,
            "{origin}：`{name}` 的 source list 不是期望的那一套（此处按**集合**比对，\
             与书写顺序无关）。放宽这条 source list 就是放宽这条边界本身，改它必须过复审。"
        );
    }
}

/// 取 `<name …>` 全部开标签的 `(行号, 属性段)`；属性段是 `<name` 之后、到最近一个 `>` 之前。
///
/// # 判据是「`<name` 之后是不是标签名的结束」，不是「`<name ` 带个空格」
///
/// 旧判据写成 `html.split("<script ")`（`script` 后面一个空格），漏掉的恰好是最典型的两种
/// 内联写法：无属性的 `<script>alert(1)</script>`（名字后直接是 `>`）、以及属性换行的
/// `<script\n  type="module">`（名字后是换行）。故这里判「空白 / `>` / `/` / 文档结束」四种
/// 收尾，`<scriptlet` 这类同前缀的别的标签则不会被误当成 `<script`。
///
/// 行号带出来是因为无属性的 `<script>` 属性段是**空串**：只报属性段的话，失败信息里就是一个
/// 空引号，说不出「在哪儿」。喂进来的净化面由 `mask_html_comments` 保证行号与原文一致。
///
/// 闭合 `>` 找不到就 panic：此时 HTML 已经不是可判的，继续扫等于对着半截标签作证。
fn element_open_tags<'a>(html: &'a str, name: &str) -> Vec<(usize, &'a str)> {
    let opener = format!("<{name}");
    let mut tags = Vec::new();
    let mut scanned = 0usize;
    while let Some(offset) = html[scanned..].find(&opener) {
        let at = scanned + offset;
        let after = &html[at + opener.len()..];
        let ends_name = after
            .chars()
            .next()
            .is_none_or(|ch| ch.is_ascii_whitespace() || ch == '>' || ch == '/');
        scanned = at + opener.len();
        if !ends_name {
            continue;
        }
        let close = after
            .find('>')
            .unwrap_or_else(|| panic!("`<{name}` 起手的标签没有闭合 `>` —— HTML 已经不可判"));
        tags.push((html[..at].matches('\n').count() + 1, &after[..close]));
        scanned = at + opener.len() + close;
    }
    tags
}

/// 开标签属性段里 `name="…"` 的值。`name` 必须是**独立的属性**（前面是空白），
/// 否则 `data-content="…"` 会冒充 `content="…"`。
fn attr_value<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("{name}=\"");
    let mut from = 0usize;
    while let Some(offset) = tag[from..].find(&needle) {
        let at = from + offset;
        let start = at + needle.len();
        let end = start + tag[start..].find('"')?;
        if at == 0 || tag.as_bytes()[at - 1].is_ascii_whitespace() {
            return Some(&tag[start..end]);
        }
        from = end;
    }
    None
}

/// 入口 HTML 里那条 CSP meta 的 `content`。必须**恰好一条**。
///
/// 零条 = 兜底策略没了（浏览器直开 / dev 时整页无策略）；两条 = 浏览器取**交集**，于是
/// 「读得懂的那一条」和「实际生效的那一套」不是一回事，判据从此说不清在守什么。
fn meta_csp(html: &str, origin: &str) -> String {
    let metas: Vec<&str> = element_open_tags(html, "meta")
        .into_iter()
        .map(|(_, tag)| tag)
        .filter(|tag| {
            attr_value(tag, "http-equiv")
                .is_some_and(|value| value.eq_ignore_ascii_case("Content-Security-Policy"))
        })
        .collect();
    assert_eq!(
        metas.len(),
        1,
        "{origin}：`http-equiv=\"Content-Security-Policy\"` 的 meta 有 {} 条（应为 1）。\
         为 0 = dev / 浏览器直开时整页没有兜底策略（注释里写着同样的字样**不算**，判据打在\
         剥完注释的净化面上）；>1 = 浏览器按交集生效，判据说不清自己在守哪一套。",
        metas.len()
    );
    attr_value(metas[0], "content")
        .unwrap_or_else(|| panic!("{origin}：CSP meta 没有 `content` 属性，等于没有策略"))
        .to_owned()
}

/// 没有 `src` 属性的 `<script>` 开标签 —— 即内联脚本；返回 `第 N 行 <script …>` 便于直接定位。
///
/// `src` 按**空白分隔的属性**判，`data-src="…"` 不会冒充它。
fn inline_script_tags(html: &str) -> Vec<String> {
    element_open_tags(html, "script")
        .into_iter()
        .filter(|(_, tag)| {
            !tag.split_whitespace()
                .any(|token| token == "src" || token.starts_with("src="))
        })
        .map(|(line, tag)| format!("第 {line} 行 <script{tag}>"))
        .collect()
}

/// `ui/vite.config.ts` 的 `rollupOptions.input` 里列的 `*.html` —— 即**真正随包分发**的入口，
/// 返回相对仓库根的路径。
///
/// 它在本门里有两个用途，都不是「覆盖面」：
///
/// - **扫描面的地板**：遍历一旦扫空 / 扫错目录，循环体一次都不执行而门照绿。拿构建清单对拍，
///   这种「哑掉」当场红。
/// - **豁免名单的护栏**：随包分发的入口一条都不许出现在 [`DEV_ONLY_ENTRIES`] 里 —— 否则
///   「把入口加进豁免名单」就是一条现成的绕门路径，而那正是白名单这种结构天生的弱点。
///
/// # 射程（只认单引号字面量），以及为什么这个边界是安全的
///
/// 只收 `input: { … }` 块里以**单引号**写的 `*.html` 字面量（本仓与 Prettier 默认都是单引号）。
/// 改成双引号 / 模板串会让本函数少认几条 —— 但那**只**削弱地板与护栏，覆盖面来自
/// [`repo_dir_files`] 的目录遍历，不受影响：新入口照样被扫、照样必须有 CSP meta。
/// 失效方向因此是「少一层冗余检查」，不是「漏掉一个入口」。
fn vite_html_inputs(config: &str) -> Vec<String> {
    const ANCHOR: &str = "input: {";
    let at = config
        .find(ANCHOR)
        .expect("ui/vite.config.ts 里找不到 `input: {` —— 构建清单的锚点没了，对拍已失去依据");
    // 从锚点里的 `{` 起手做花括号配对：按缩进/行形状封顶会被 formatter 改写悄悄改掉射程。
    let block = &config[at + ANCHOR.len() - 1..];
    let mut depth = 0usize;
    let mut end = None;
    for (offset, ch) in block.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(offset);
                    break;
                }
            }
            _ => {}
        }
    }
    let block = &block[..end.expect("`rollupOptions.input` 的花括号没有闭合")];

    // 单引号成对出现，奇数段就是字面量内容。
    let inputs: Vec<String> = block
        .split('\'')
        .skip(1)
        .step_by(2)
        .filter(|literal| literal.ends_with(".html"))
        .map(|literal| format!("{ENTRY_DIR}/{literal}"))
        .collect();
    assert!(
        !inputs.is_empty(),
        "`rollupOptions.input` 里一个 `.html` 都没有 —— 对拍的地板是空的，等于没对拍"
    );
    inputs
}

// ── 门 ────────────────────────────────────────────────────────────────────

/// `ui/` 下每个 renderer 入口的 CSP 兜底 + `tauri.conf.json` 的响应层权威策略，
/// 逐条 directive 对拍；并且任何入口都不许出现内联脚本。
#[test]
fn local_renderer_entries_keep_strict_csp_contract() {
    // ── ① 响应层权威策略（打包态真正生效的那一份）──
    let config: serde_json::Value =
        serde_json::from_str(&crate_file("tauri.conf.json")).expect("tauri config JSON");
    let security = &config["app"]["security"];
    // dev 腿与 meta 兜底覆盖的是同一批场景（Vite dev server / 浏览器直开），故 `connect-src`
    // 同为「IPC 三项 + HMR 的 `ws:`」，共用同一份清单。
    let dev_connect: Vec<&str> = IPC_CONNECT.iter().copied().chain(["ws:"]).collect();
    for (key, connect) in [("csp", &IPC_CONNECT[..]), ("devCsp", &dev_connect[..])] {
        let origin = format!("tauri.conf.json app.security.{key}");
        let policy = security[key]
            .as_str()
            .unwrap_or_else(|| panic!("{origin} 必须是字符串 —— 没有策略就没有这条边界"));
        expect_policy(policy, &expected_policy(connect, true), &origin);
    }

    // ── ② renderer 入口 HTML（覆盖面 = 目录实况，不是写死的清单）──
    let entries = repo_dir_files(ENTRY_DIR, "html");
    let scanned: Vec<&str> = entries.iter().map(|(path, _)| path.as_str()).collect();

    for exempt in DEV_ONLY_ENTRIES {
        assert!(
            scanned.contains(&exempt),
            "豁免名单里的 `{exempt}` 在 `{ENTRY_DIR}/` 下不存在了 —— 名单陈旧，\
             它正在替一个已经不存在的文件挡门。扫描面实况：{scanned:?}"
        );
    }

    let shipped = vite_html_inputs(&expect_marker(
        repo_file("ui/vite.config.ts"),
        "ui/vite.config.ts",
        "rollupOptions",
    ));
    for entry in &shipped {
        assert!(
            scanned.contains(&entry.as_str()),
            "构建清单里的入口 `{entry}` 不在扫描面上 —— 遍历扫空 / 扫错目录了，\
             此时下面的循环体一次都不执行而门照绿。扫描面实况：{scanned:?}"
        );
        assert!(
            !DEV_ONLY_ENTRIES.contains(&entry.as_str()),
            "`{entry}` 随包分发（在 `rollupOptions.input` 里），却被放进了开发夹具豁免名单 —— \
             那是一条现成的绕门路径。"
        );
    }

    for (path, raw) in &entries {
        // 判据一律打在**剥完注释**的净化面上：正面方向防「注释喂饱 `contains`」，
        // 否定方向防「注释里的 `<script` 顶红」。
        let html = mask_html_comments(raw);

        // 禁内联脚本对**全部**入口生效，含开发夹具 —— 豁免只针对 meta 兜底那一条。
        let inline = inline_script_tags(&html);
        assert!(
            inline.is_empty(),
            "`{path}` 引入了内联脚本（开标签没有 `src`）：{inline:?}。\
             CSP 是 `script-src 'self'`，内联脚本会被直接拦掉；为它放宽成 'unsafe-inline'\
             等于拿整页的脚本注入防线换一个次要效果。"
        );

        if DEV_ONLY_ENTRIES.contains(&path.as_str()) {
            continue;
        }
        expect_policy(
            &meta_csp(&html, path),
            &expected_policy(&dev_connect, false),
            path,
        );
    }
}

// ── 门的守卫：判据本身必须先立得住 ────────────────────────────────────────

/// 🔴 净化面是这道门的地基：注释里写着同样的字样**不算**策略。
///
/// 变异锁：把入口 HTML 的真 meta 整条删掉、只留一句 `<!-- script-src 'self' -->`（本仓
/// `ui/index.html` 的注释里今天就有这句），本用例必红。
#[test]
#[should_panic(expected = "的 meta 有 0 条")]
fn a_policy_that_only_exists_in_a_comment_is_not_a_policy() {
    let html = mask_html_comments(
        "<head>\n<!-- 上面那条 CSP 是 script-src 'self' -->\n<title>x</title>\n</head>",
    );
    assert!(
        !html.contains("script-src"),
        "正向对照失效：注释根本没被剥，后面那条断言证明不了任何东西"
    );
    let _ = meta_csp(&html, "合成夹具");
}

/// 🔴 内联脚本的两种典型写法都必须被认出来 —— 它们正是旧判据 `"<script "` 的盲区。
#[test]
fn inline_scripts_are_detected_in_both_bare_and_wrapped_forms() {
    assert_eq!(
        inline_script_tags("<script>alert(1)</script>").len(),
        1,
        "无属性的内联脚本没被认出来 —— 这是旧判据 `\"<script \"` 的第一个盲区"
    );
    assert_eq!(
        inline_script_tags("<script\n  type=\"module\"\n>alert(1)</script>").len(),
        1,
        "属性换行的内联脚本没被认出来 —— 这是旧判据的第二个盲区"
    );
    assert!(
        inline_script_tags("<script type=\"module\" src=\"/src/main.tsx\"></script>").is_empty(),
        "带 `src` 的外链脚本被误判成内联 —— 这条门会从此恒红"
    );
    assert_eq!(
        inline_script_tags("<script data-src=\"x\">alert(1)</script>").len(),
        1,
        "`data-src` 冒充了 `src`"
    );
    assert!(
        inline_script_tags("<scriptlet foo=\"1\">").is_empty(),
        "同前缀的别的标签被误当成 `<script>`"
    );
}

/// 合成一份**除 `script-src` 外都合规**的响应层策略，用来单独考这条 directive。
fn policy_with_script_src(script_src: &str) -> String {
    format!(
        "default-src 'self'; connect-src 'self' ipc: http://ipc.localhost; \
         img-src 'self' data: https: polaris-icon: http://polaris-icon.localhost; \
         style-src 'self' 'unsafe-inline'; {script_src}; \
         object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    )
}

/// 🔴 **旧判据在这两份策略上是绿的** —— 先把这件事钉成事实，再证明新判据把它们挡下来。
///
/// 没有这条正向对照，下面两条 `should_panic` 只能证明「新门会红」，证明不了「它补上了一个
/// 真实存在的缺口」。
#[test]
fn the_substring_era_assertions_really_do_let_these_two_through() {
    for smuggled in [
        // 追加任意外部源：正面判据只要求 `script-src 'self'` 相邻出现，后面接什么都行。
        "script-src 'self' https://example.invalid",
        // 只多打一个空格：正面判据照命中，而否定判据那串写死单空格的字面量不再匹配。
        "script-src 'self'  'unsafe-inline'",
    ] {
        let policy = policy_with_script_src(smuggled);
        assert!(
            policy.contains("script-src 'self'")
                && !policy.contains("'unsafe-eval'")
                && !policy.contains("script-src 'self' 'unsafe-inline'"),
            "正向对照失效：`{smuggled}` 本来就过不了旧判据，那么用它证明新判据的增量是无效的"
        );
    }
}

/// 🔴 追加任意外部脚本源必须红。
#[test]
#[should_panic(expected = "`script-src` 的 source list")]
fn an_extra_script_source_is_rejected() {
    expect_policy(
        &policy_with_script_src("script-src 'self' https://example.invalid"),
        &expected_policy(&IPC_CONNECT, true),
        "合成夹具",
    );
}

/// 🔴 靠多打一个空格夹带 `'unsafe-inline'` 必须红 —— token 化之后空白不再是藏身处。
#[test]
#[should_panic(expected = "`script-src` 的 source list")]
fn extra_whitespace_does_not_smuggle_unsafe_inline_past_the_gate() {
    expect_policy(
        &policy_with_script_src("script-src 'self'  'unsafe-inline'"),
        &expected_policy(&IPC_CONNECT, true),
        "合成夹具",
    );
}

/// 🔴 新加一条 directive 同样必须红：`script-src-elem` 在元素层**整个覆盖** `script-src`，
/// 而只盯着 `script-src` 的检查看不见它。
#[test]
#[should_panic(expected = "directive 的名字集合变了")]
fn a_newly_added_directive_that_overrides_script_src_is_rejected() {
    let policy =
        policy_with_script_src("script-src 'self'; script-src-elem 'self' 'unsafe-inline'");
    // 旧判据在这份策略上同样全绿：`script-src 'self'` 逐字在、两条否定字面量都不匹配。
    assert!(
        policy.contains("script-src 'self'")
            && !policy.contains("script-src 'self' 'unsafe-inline'"),
        "正向对照失效：这份策略本来就过不了旧判据"
    );
    expect_policy(&policy, &expected_policy(&IPC_CONNECT, true), "合成夹具");
}
