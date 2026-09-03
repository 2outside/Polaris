//! 本 crate 的**自证**：取材 helper 自己必须先可信，否则所有基于它的源码级门都是空转。
//!
//! 全部用合成临时目录（`Scratch`），不碰工作树：验证必须独立于被验证对象，
//! 且「新增子模块自动进取材面」这条只能在**可写的副本**上造。
//!
//! 真实仓库布局上的对照（`crate_source` 真读到 `src-tauri/src/tray.rs`、
//! 跨 crate 的 `env!("CARGO_MANIFEST_DIR")` 确实是**调用方**的目录）在 src-tauri 侧的
//! `test_support` 里——那里才是跨 crate 的调用点，本 crate 内证不了。

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

// ── 夹具 ──────────────────────────────────────────────────────────────────

const MARKER_LIB: &str = "SOURCE_PROBE_FIXTURE_LIB";
const MARKER_ALPHA: &str = "SOURCE_PROBE_FIXTURE_ALPHA";
const MARKER_BETA: &str = "SOURCE_PROBE_FIXTURE_BETA_IN_SUBDIR";
const MARKER_GAMMA: &str = "SOURCE_PROBE_FIXTURE_GAMMA_ADDED_LATER";
const MARKER_TESTS_ROOT: &str = "SOURCE_PROBE_FIXTURE_TESTS_AT_SRC_ROOT";
const MARKER_TESTS_DEEP: &str = "SOURCE_PROBE_FIXTURE_TESTS_IN_SUBDIR";
const MARKER_ROOT_ASSET: &str = "SOURCE_PROBE_FIXTURE_WORKSPACE_ROOT_ASSET";

static NEXT: AtomicU64 = AtomicU64::new(0);

/// 自清理的临时目录（`Drop` 绑定到栈展开 ⇒ `#[should_panic]` 的用例也会清）。
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let seq = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "polaris-source-probe-{tag}-{}-{nonce}-{seq}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("临时目录必须唯一且可创建");
        Self(path)
    }

    fn write(&self, rel: &str, body: &str) {
        let path = self.0.join(rel);
        std::fs::create_dir_all(path.parent().expect("夹具路径必有父目录")).expect("建父目录");
        std::fs::write(&path, body).expect("写夹具文件");
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 合成一个「workspace 根 + 一个成员 crate」的最小仓库：
///
/// ```text
/// <tmp>/Cargo.toml                     [workspace]
/// <tmp>/root_asset.txt                 ← repo_file 的靶
/// <tmp>/member/Cargo.toml              ← crate_file 的靶
/// <tmp>/member/src/lib.rs              MARKER_LIB
/// <tmp>/member/src/alpha.rs            MARKER_ALPHA
/// <tmp>/member/src/deep/beta.rs        MARKER_BETA        ← 递归证据
/// <tmp>/member/src/tests/mod.rs        MARKER_TESTS_ROOT  ← 必须被排除
/// <tmp>/member/src/deep/tests/mod.rs   MARKER_TESTS_DEEP  ← 必须被排除（任意深度）
/// ```
fn fixture(tag: &str) -> (Scratch, PathBuf) {
    let scratch = Scratch::new(tag);
    scratch.write("Cargo.toml", "[workspace]\nmembers = [\"member\"]\n");
    scratch.write("root_asset.txt", MARKER_ROOT_ASSET);
    scratch.write("member/Cargo.toml", "[package]\nname = \"member\"\n");
    scratch.write("member/src/lib.rs", MARKER_LIB);
    scratch.write("member/src/alpha.rs", MARKER_ALPHA);
    scratch.write("member/src/deep/beta.rs", MARKER_BETA);
    scratch.write("member/src/tests/mod.rs", MARKER_TESTS_ROOT);
    scratch.write("member/src/deep/tests/mod.rs", MARKER_TESTS_DEEP);
    let manifest = scratch.0.join("member");
    (scratch, manifest)
}

// ── ① 读不到必须 panic，且信息可定位 ──────────────────────────────────────

/// 🔴 读不到不得静默返回空串：空串会让否定型断言恒真，是「绿而零信息量」的标准入口。
#[test]
#[should_panic(expected = "crate_source：读不到")]
fn crate_source_panics_when_the_file_is_missing() {
    let (_scratch, manifest) = fixture("missing");
    let _ = crate_source_in(&manifest, "no_such_file.rs");
}

/// 🔴 panic 信息必须**带上被解析出的绝对路径**，否则「读不到」等于没说。
#[test]
fn missing_file_panic_message_locates_the_resolved_path() {
    let (_scratch, manifest) = fixture("missing-msg");
    let expected = manifest.join("src").join("no_such_file.rs");
    let err = std::panic::catch_unwind(|| crate_source_in(&manifest, "no_such_file.rs"))
        .expect_err("读不到必须 panic");
    let message = err
        .downcast_ref::<String>()
        .cloned()
        .expect("panic 载荷应是格式化后的 String");
    assert!(
        message.contains(&expected.display().to_string()),
        "panic 信息里没有解析出的绝对路径，定位不了。实际：{message}"
    );
}

/// 🔴 `..` 必须被拒：放行它就等于把锚点交回调用方位置，本 crate 的存在意义当场归零。
#[test]
#[should_panic(expected = "含 `.` / `..` / 根成分")]
fn escaping_the_anchor_is_rejected() {
    let (_scratch, manifest) = fixture("escape");
    let _ = crate_source_in(&manifest, "../Cargo.toml");
}

// ── ② module_source：真拼接、真递归、真排除 tests ─────────────────────────

/// 🔴 一次覆盖三件事：多文件**同时**在场（证明真拼接，不是只读了第一个）、
/// 子目录文件在场（证明递归）、两处 `tests/` 都不在场（证明排除在任意深度生效）。
#[test]
fn module_source_concatenates_recursively_and_excludes_tests_dirs() {
    let (_scratch, manifest) = fixture("module");
    let blob = module_source_in(&manifest, "");

    for marker in [MARKER_LIB, MARKER_ALPHA, MARKER_BETA] {
        assert!(
            blob.contains(marker),
            "取材面缺 `{marker}` —— 没有真正拼接目录内全部生产 .rs"
        );
    }
    for marker in [MARKER_TESTS_ROOT, MARKER_TESTS_DEEP] {
        assert!(
            !blob.contains(marker),
            "`tests/` 的内容混进了取材面（`{marker}`）—— 测试代码会给生产扫描面充数，\
             基于它的否定/计数型断言全部失真"
        );
    }
}

/// 🔴 顺序必须稳定且与路径升序一致：不稳定的顺序会让「按偏移比先后」的断言随机翻面。
#[test]
fn module_files_order_is_stable_and_sorted() {
    let (_scratch, manifest) = fixture("order");
    let first: Vec<String> = module_files_in(&manifest, "")
        .into_iter()
        .map(|(rel, _)| rel)
        .collect();
    let second: Vec<String> = module_files_in(&manifest, "")
        .into_iter()
        .map(|(rel, _)| rel)
        .collect();
    assert_eq!(first, second, "两次遍历顺序不一致");
    assert_eq!(
        first,
        vec![
            "alpha.rs".to_string(),
            "deep/beta.rs".to_string(),
            "lib.rs".to_string()
        ],
        "遍历结果不是按相对路径升序，或收/漏了文件"
    );
}

/// 🔴 **本 crate 存在的第二个理由**：新增子模块自动进取材面。
///
/// 在副本上先取一次基线（不含 gamma），再落一个新 `.rs`，第二次取材必须自动包含它 ——
/// 「手写文件清单 ⇒ 新模块逃出扫描」这个缺陷类到此消失。Phase 2 把 `proxy.rs` 拆成约 10 个
/// 新模块时，靠的就是这条。
#[test]
fn a_newly_added_submodule_enters_the_scan_surface_automatically() {
    let (scratch, manifest) = fixture("grow");

    let before = module_source_in(&manifest, "");
    assert!(
        !before.contains(MARKER_GAMMA),
        "正向对照失效：新增前就已经含 gamma，后面那条断言证明不了任何东西"
    );
    let before_count = module_files_in(&manifest, "").len();

    // 新增一个子模块（深一层，顺带覆盖「新增的是子目录里的文件」）。
    scratch.write("member/src/deep/gamma.rs", MARKER_GAMMA);

    let after = module_source_in(&manifest, "");
    assert!(
        after.contains(MARKER_GAMMA),
        "新增子模块没有自动进取材面 —— 目录遍历退化成了固定清单"
    );
    assert_eq!(
        module_files_in(&manifest, "").len(),
        before_count + 1,
        "取材文件数没有 +1"
    );
}

/// 🔴 空取材面必须当场红：`assert!(!blob.contains(X))` 在空串上恒真。
#[test]
#[should_panic(expected = "一个生产 `.rs` 都没有")]
fn an_empty_scan_surface_is_an_error_not_a_pass() {
    let (scratch, manifest) = fixture("empty");
    scratch.write("member/src/hollow/tests/mod.rs", MARKER_TESTS_DEEP);
    let _ = module_source_in(&manifest, "hollow");
}

/// 🔴 归属不可判时不猜、不静默跳过：文件形态的 `tests.rs` 直接 panic 并给出迁移动作。
#[test]
#[should_panic(expected = "**文件形态**的测试模块")]
fn a_legacy_file_shaped_test_module_refuses_to_be_guessed() {
    let (scratch, manifest) = fixture("legacy");
    scratch.write("member/src/tests.rs", MARKER_TESTS_ROOT);
    let _ = module_source_in(&manifest, "");
}

// ── ②b module_source_with_tests：取材面本身就是测试代码的那一类门 ──────────

/// 🔴 与 [`module_source_in`] 的对照必须是**双向**的：这条要 `tests/` 在场，
/// 上面那条要 `tests/` 不在场。只留一条时，`include_tests` 被忽略（恒真或恒假）
/// 都能让剩下那条继续绿。
#[test]
fn module_source_with_tests_includes_test_dirs_at_any_depth() {
    let (_scratch, manifest) = fixture("with-tests");
    let blob = module_source_with_tests_in(&manifest, "");

    for marker in [MARKER_LIB, MARKER_ALPHA, MARKER_BETA] {
        assert!(blob.contains(marker), "生产文件掉出了取材面：`{marker}`");
    }
    for marker in [MARKER_TESTS_ROOT, MARKER_TESTS_DEEP] {
        assert!(
            blob.contains(marker),
            "`tests/` 的内容不在取材面里（`{marker}`）—— 断言测试代码的门会从此扫了个空，\
             而空取材面上的否定型断言恒真：门不报错，只是不再有牙"
        );
    }
}

/// 🔴 两条取材面的差集必须**恰好**是 `tests/` 下的内容，不多不少。
/// 「都包含生产文件」是弱断言（两个恒等实现也满足）；差集才钉得住那个布尔真的在分流。
#[test]
fn the_two_scan_surfaces_differ_exactly_by_the_tests_dirs() {
    let (_scratch, manifest) = fixture("diff");
    let production: Vec<String> = module_files_in(&manifest, "")
        .into_iter()
        .map(|(rel, _)| rel)
        .collect();
    let everything: Vec<String> = module_files_with_tests_in(&manifest, "")
        .into_iter()
        .map(|(rel, _)| rel)
        .collect();

    let extra: Vec<&String> = everything
        .iter()
        .filter(|rel| !production.contains(rel))
        .collect();
    assert_eq!(
        extra,
        vec!["deep/tests/mod.rs", "tests/mod.rs"],
        "两条取材面的差集不是恰好 `tests/` 下那两个文件"
    );
    assert!(
        production.iter().all(|rel| everything.contains(rel)),
        "生产取材面不是全取材面的子集 —— 两条实现已经漂移"
    );
}

/// 🔴 空取材面在这条腿上同样必须当场红（只有 `tests/` 也算有内容，所以要造一个真空目录）。
#[test]
fn an_empty_surface_is_an_error_on_the_with_tests_leg_too() {
    let (scratch, manifest) = fixture("empty-with-tests");
    scratch.write("member/src/void/notes.txt", "not rust");
    let err = std::panic::catch_unwind(|| module_source_with_tests_in(&manifest, "void"))
        .expect_err("空取材面必须 panic");
    let message = err
        .downcast_ref::<String>()
        .cloned()
        .expect("panic 载荷应是格式化后的 String");
    assert!(
        message.contains("都没有 —— 取材面是空的"),
        "不是空取材面那条 panic。实际：{message}"
    );
    assert!(
        message.contains("module_source_with_tests"),
        "panic 文案没点名是哪条取材面 —— 两条腿的失败信息必须可分辨。实际：{message}"
    );
}

/// 🔴 被禁的文件形态 `tests.rs` 两条腿都拒收：它是写法层面被禁，不是取材面的选择问题。
#[test]
#[should_panic(expected = "**文件形态**的测试模块")]
fn the_with_tests_leg_also_refuses_a_legacy_tests_file() {
    let (scratch, manifest) = fixture("legacy-with-tests");
    scratch.write("member/src/tests.rs", MARKER_TESTS_ROOT);
    let _ = module_source_with_tests_in(&manifest, "");
}

// ── ③ crate_file / repo_file / workspace 根 ───────────────────────────────

#[test]
fn crate_file_reads_from_the_crate_root_not_from_src() {
    let (_scratch, manifest) = fixture("crate-file");
    assert!(crate_file_in(&manifest, "Cargo.toml").contains("name = \"member\""));
}

#[test]
fn repo_file_reads_from_the_workspace_root_however_deep_the_member_is() {
    let (scratch, manifest) = fixture("repo-file");
    assert!(repo_file_in(&manifest, "root_asset.txt").contains(MARKER_ROOT_ASSET));
    assert_eq!(
        workspace_root_from(&manifest),
        scratch.0,
        "workspace 根解析错位"
    );
}

/// 🔴 `[workspace]` 的识别必须是行级精确匹配：注释掉的那一行不能算数，
/// 否则任意成员 crate 的 Cargo.toml 里提一句 `# [workspace]` 就会把仓库根算成它自己。
#[test]
fn a_commented_workspace_marker_does_not_count_as_the_root() {
    let (scratch, manifest) = fixture("commented");
    std::fs::write(
        manifest.join("Cargo.toml"),
        "# [workspace] —— 这里只是提了一句\n[package]\nname = \"member\"\n",
    )
    .expect("改写成员 Cargo.toml");
    assert_eq!(workspace_root_from(&manifest), scratch.0);
}

// ── ④ 哨兵 ───────────────────────────────────────────────────────────────

#[test]
fn expect_marker_passes_through_a_matching_blob() {
    let (_scratch, manifest) = fixture("sentinel-ok");
    let blob = expect_marker(
        crate_source_in(&manifest, "alpha.rs"),
        "alpha.rs",
        MARKER_ALPHA,
    );
    assert!(blob.contains(MARKER_ALPHA));
}

/// 🔴 哨兵防的是「读到的是另一个真实存在的文件」：blob 非空、断言照跑，只是跑错了对象。
#[test]
#[should_panic(expected = "取材哨兵失败")]
fn expect_marker_catches_a_blob_from_the_wrong_file() {
    let (_scratch, manifest) = fixture("sentinel-bad");
    // 读到的是 alpha.rs，却按 beta.rs 的独有标识校验 —— 正是锚点解析错位的形态。
    let _ = expect_marker(
        crate_source_in(&manifest, "alpha.rs"),
        "beta.rs",
        MARKER_BETA,
    );
}

// ── ④ 取材面净化：注释与字面量必须被抹掉，且偏移不变 ──────────────────────

/// 🔴 三类噪声都必须消失：行注释、块注释（嵌套）、字符串字面量。
/// 这三类正是源码级门的**假绿**来源——门自己的说明里几乎必然写着它要找的那个针。
#[test]
fn masking_removes_comments_and_string_literals() {
    let source = r####"
// needle_in_line_comment
/// needle_in_doc_comment
/* needle_in_block /* needle_nested */ still_comment */
let s = "needle_in_string";
let r = r#"needle_in_raw"#;
let c = 'n';
fn needle_in_code() {}
"####;
    let masked = mask_comments_and_strings(source);
    for noise in [
        "needle_in_line_comment",
        "needle_in_doc_comment",
        "needle_in_block",
        "needle_nested",
        "still_comment",
        "needle_in_string",
        "needle_in_raw",
    ] {
        assert!(
            !masked.contains(noise),
            "`{noise}` 没被抹掉 —— 门会把注释/字面量里的针当成代码里的命中"
        );
    }
    assert!(
        masked.contains("fn needle_in_code"),
        "真代码被误抹了 —— 少抹是假红（吵但可查），错抹是假绿（门从此看不见真命中）"
    );
}

/// 🔴 字节偏移与行号必须不变：抹成等长空格是「先在净化文本里定位、再回原文取上下文」
/// 这套用法的前提；删除会让两份文本错位，而错位的取材比不取材更难发现。
#[test]
fn masking_preserves_byte_offsets_and_line_numbers() {
    let source = "let a = \"多字节字符串\"; // 中文注释\nfn keep() {}\n";
    let masked = mask_comments_and_strings(source);
    assert_eq!(
        masked.len(),
        source.len(),
        "净化后字节长度变了 —— 偏移不再可用"
    );
    assert_eq!(
        masked.matches('\n').count(),
        source.matches('\n').count(),
        "换行被抹掉了 —— 行号不再可用"
    );
    let at = masked.find("fn keep").expect("真代码应留在净化文本里");
    assert_eq!(
        &source[at..at + "fn keep".len()],
        "fn keep",
        "同一偏移回原文取到的不是同一段 —— 偏移已经错位"
    );
}

/// 🔴 生命周期标注不是字符字面量：把 `'a` 当字面量开头会从这里一路抹到下一个 `'`，
/// 中间的真代码整段消失 —— 这是**假绿**方向的错抹。
#[test]
fn masking_does_not_mistake_a_lifetime_for_a_char_literal() {
    let source = "fn f<'a>(x: &'a str) -> &'a str { needle_here(x) }";
    let masked = mask_comments_and_strings(source);
    assert!(
        masked.contains("needle_here"),
        "生命周期被当成字符字面量，真代码被抹掉了。实际：{masked}"
    );
}

/// 🔴 字符字面量本身仍要被抹（否则 `'"'` 之类会把后续解析带偏）。
#[test]
fn masking_still_removes_real_char_literals() {
    let source = "let q = '\"'; let t = \"needle_in_string\"; fn keep() {}";
    let masked = mask_comments_and_strings(source);
    assert!(
        !masked.contains("needle_in_string"),
        "字符字面量 `'\\\"'` 没被抹 ⇒ 它里面的引号把后面的字符串解析带偏了。实际：{masked}"
    );
    assert!(masked.contains("fn keep"), "真代码被误抹。实际：{masked}");
}

// ── ④b HTML 面净化：只剥 `<!-- -->`，属性值必须原样活着 ────────────────────

/// 🔴 切片自检（不是「剥完变短了」这种计数）：注释里的内容必须**逐条**消失，
/// 而同一份文档里 meta 的 `content=` 属性必须**逐字**完整保留。
///
/// 计数不等于位置：只断言长度变短的话，「把 meta 抹了、注释留着」同样满足。故这里两个方向
/// 都钉死 —— 该消失的按 needle 逐条查，该活着的按整条属性值 `assert_eq!` 对拍。
#[test]
fn html_masking_strips_comments_and_keeps_attribute_values() {
    const POLICY: &str =
        "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'";
    let source = format!(
        "<!doctype html>\n\
         <head>\n\
         <!-- 兜底说明：上面那条 CSP 是 script-src 'self' -->\n\
         <meta http-equiv=\"Content-Security-Policy\" content=\"{POLICY}\" />\n\
         <!--\n\
           多行注释，里面提到 <script> 与 needle_in_multiline\n\
           还提到 needle_second_line\n\
         -->\n\
         <script type=\"module\" src=\"/src/main.tsx\"></script>\n\
         <!-- 第三段注释 needle_third -->\n\
         </head>\n"
    );
    let masked = mask_html_comments(&source);

    for noise in [
        "兜底说明",
        "needle_in_multiline",
        "needle_second_line",
        "needle_third",
    ] {
        assert!(
            !masked.contains(noise),
            "`{noise}` 还在净化面上 —— 注释没被剥干净（同一文件多段 / 多行注释各是一条腿）"
        );
    }
    assert!(
        !masked.contains("<script>"),
        "注释体里的 `<script>` 必须一起消失，否则「禁内联脚本」的扫描会被注释误红"
    );

    // 该活着的那一半：整条 CSP 逐字保留（属性值 = HTML 里的「字符串」，抹了判据就没有对象）。
    let content = masked
        .split_once("content=\"")
        .and_then(|(_, tail)| tail.split_once('"'))
        .map(|(value, _)| value.to_owned())
        .expect("meta 的 content 属性必须还在净化面上");
    assert_eq!(
        content, POLICY,
        "CSP 属性值被改动了 —— 判据的对象已经不完整"
    );
    assert!(
        masked.contains("<script type=\"module\" src=\"/src/main.tsx\">"),
        "真元素被误剥了。实际：{masked}"
    );
}

/// 🔴 偏移与行号守恒：同 [`mask_comments`]，「净化面上定位 → 回原文取上下文」是这套用法的前提。
#[test]
fn html_masking_preserves_byte_offsets_and_line_numbers() {
    let source = "<!-- 多字节注释内容 -->\n<meta content=\"keep\" />\n";
    let masked = mask_html_comments(source);
    assert_eq!(
        masked.len(),
        source.len(),
        "净化后字节长度变了 —— 偏移不可用"
    );
    assert_eq!(
        masked.matches('\n').count(),
        source.matches('\n').count(),
        "换行被抹掉了 —— 行号不可用"
    );
    let at = masked.find("<meta").expect("真元素应留在净化面上");
    assert_eq!(
        &source[at..at + "<meta".len()],
        "<meta",
        "同一偏移回原文取到的不是同一段 —— 偏移已经错位"
    );
}

/// 🔴 HTML 注释**不嵌套**：注释体里出现的 `<!--` 只是普通文本，第一个 `-->` 就闭合。
///
/// 这条与 Rust 的块注释（嵌套）正好相反，抄错的后果是把 `-->` 之后的真文档一路吞掉 ——
/// 那是「多剥」方向，会让 meta 消失、门恒红，吵但至少不哑；这里把它钉成与浏览器一致。
#[test]
fn html_masking_treats_the_first_close_as_the_end() {
    let masked =
        mask_html_comments("<!-- needle_outer <!-- needle_inner --><meta content=\"kept\" />\n");
    assert!(
        !masked.contains("needle_outer") && !masked.contains("needle_inner"),
        "注释体没剥干净。实际：{masked}"
    );
    assert!(
        masked.contains("<meta content=\"kept\" />"),
        "第一个 `-->` 之后的真文档被吞了 —— 判据把 HTML 注释当成可嵌套的了。实际：{masked}"
    );
}

/// 🔴 未闭合注释抹到文件尾（与 HTML 规范一致），方向是「多剥 ⇒ 门红」，不是静默放行。
#[test]
fn html_masking_swallows_an_unterminated_comment_to_eof() {
    let masked =
        mask_html_comments("<meta content=\"kept\" />\n<!-- 没有闭合 <meta content=\"lost\" />\n");
    assert!(masked.contains("kept"), "注释之前的文档不该受影响");
    assert!(
        !masked.contains("lost"),
        "未闭合注释之后的内容必须一并抹掉 —— 浏览器也是这么吞的"
    );
}

// ── ④c repo_dir_files：仓库根下按扩展名的目录取材 ─────────────────────────

/// 🔴 覆盖面由目录实况定，不由清单定：新落一个 `.html` 必须自动进取材面。
///
/// 与 [`a_newly_added_submodule_enters_the_scan_surface_automatically`] 同一条理由，
/// 只是换到「仓库根 + 任意扩展名」这个面上 —— 跨语言门此前正是靠手写文件名清单，
/// 于是新增入口逃出扫描而且不报错。
#[test]
fn a_newly_added_repo_file_enters_the_scan_surface_automatically() {
    let (scratch, manifest) = fixture("repo-dir");
    scratch.write("ui/index.html", "<html><!-- one --></html>");
    scratch.write("ui/nested/tray.html", "<html>two</html>");
    scratch.write("ui/notes.md", "不是 html，不该进面");

    let before = repo_dir_files_in(&manifest, "ui", "html");
    assert_eq!(
        before.iter().map(|(p, _)| p.as_str()).collect::<Vec<_>>(),
        ["ui/index.html", "ui/nested/tray.html"],
        "键必须是**相对 workspace 根**的路径且升序；扩展名不匹配的必须落选"
    );

    scratch.write("ui/probe-entry.html", "<html>three</html>");
    let after = repo_dir_files_in(&manifest, "ui", "html");
    assert_eq!(
        after.iter().map(|(p, _)| p.as_str()).collect::<Vec<_>>(),
        [
            "ui/index.html",
            "ui/nested/tray.html",
            "ui/probe-entry.html"
        ],
        "新增入口没有自动进取材面 —— 目录遍历退化成了固定清单"
    );
}

/// 🔴 依赖缓存与构建产物不进取材面：进去了，扫描结果就取决于「这台机器跑没跑过安装/构建」。
#[test]
fn non_source_directories_stay_out_of_the_scan_surface() {
    let (scratch, manifest) = fixture("repo-dir-skip");
    scratch.write("ui/index.html", "<html>real</html>");
    scratch.write("ui/node_modules/pkg/demo.html", "第三方包里的 html");
    scratch.write("ui/dist/index.html", "构建产物");
    scratch.write("ui/.webkit-verify/probe.html", "隐藏目录里的临时产物");

    assert_eq!(
        repo_dir_files_in(&manifest, "ui", "html")
            .iter()
            .map(|(p, _)| p.as_str())
            .collect::<Vec<_>>(),
        ["ui/index.html"],
        "非源码目录漏进了取材面 —— 同一份代码在两台机器上会扫出不同结果"
    );
}

/// 🔴 空取材面必须当场红：循环体一次都不执行时，里面的断言全部恒真。
#[test]
#[should_panic(expected = "一个 `.html` 都没有")]
fn an_empty_repo_dir_surface_is_an_error_not_a_pass() {
    let (scratch, manifest) = fixture("repo-dir-empty");
    scratch.write("ui/only.md", "没有 html");
    let _ = repo_dir_files_in(&manifest, "ui", "html");
}

// ── ⑤ 宏形态：`env!` 求值在调用点所在 crate ───────────────────────────────

/// 宏在本 crate 内展开 ⇒ `env!("CARGO_MANIFEST_DIR")` = `crates/source-probe`。
/// （跨 crate 的那一半由 src-tauri 侧的 `test_support` 对照，见本文件头。）
#[test]
fn the_macro_anchors_on_the_calling_crate() {
    let blob = crate::crate_source!("lib.rs");
    assert!(
        blob.contains("pub fn crate_source_in"),
        "宏没有解析到本 crate 的 src/lib.rs"
    );
    assert!(
        crate::module_source!("").contains("pub fn module_files_in"),
        "module_source! 没有解析到本 crate 的 src/"
    );
    assert!(crate::crate_file!("Cargo.toml").contains("polaris-source-probe"));
    assert!(crate::repo_file!("Cargo.toml").contains("[workspace]"));
    assert!(
        crate::module_source_with_tests!("").contains("fn the_macro_anchors_on_the_calling_crate"),
        "module_source_with_tests! 没有把本 crate 的 src/tests/ 收进取材面"
    );
    assert!(
        crate::module_files_with_tests!("")
            .iter()
            .any(|(rel, _)| rel == "tests/mod.rs"),
        "module_files_with_tests! 没有列出 src/tests/mod.rs"
    );
}

/// 🔴 逐格对差：字面量前缀与转义引号两类，历史上各让净化面漏过一批字节。
///
/// 两条缺陷都不是「抹少了几个空格」那么轻：漏掉的收尾引号会让扫描**从它重新起算**，
/// 把后面的正常代码当成新字面量抹掉 —— 净化面自此整段错位，而所有基于它的门都照跑不误。
/// 2026-08-30 全仓差分实测：转义引号那条在 13 个文件上真实命中。
///
/// 每格写成 `(前缀, 该被整段抹掉的那段, 后缀)`，期望值由三段拼出来 —— 手数空格个数本身就是
/// 一处会写错的判据（第一版正是这么错的）。
///
/// **变异探针**：
/// - 把 [`char_literal_end`] 转义支的 `i = open + 3` 改回 `i += 1` ⇒ `escaped_quote` 那格转红；
/// - 删掉 `mask_comments_and_strings` 里的标识符整体消费分支 ⇒ `ident_prefix_*` 三格转红。
#[test]
fn masking_truth_table_for_literal_prefixes_and_escapes() {
    for (name, prefix, literal, suffix) in [
        // 转义单引号：收尾引号必须一起抹掉，否则它会被当成下一个字面量的开引号。
        ("escaped_quote", "let c = ", r"'\''", "; let keep = 1;"),
        ("escaped_backslash", "let c = ", r"'\\'", "; let keep = 1;"),
        // 标识符里的 `r` / `b` / `br` 不是字面量前缀。`ar"y"` 不是合法 Rust，但净化器是**词法级
        // 工具**，各门的合成夹具就是手写片段；逐字节试探会把 `ar` 的那个 `r` 读成原始字符串起点，
        // 从此偏移整段错位。这一格钉的正是「整体消费标识符」那个分支。
        (
            "ident_is_not_a_prefix",
            "let s = ar",
            "\"y\"",
            "; let k = 1;",
        ),
        // 独立前缀仍然要认。
        ("real_raw", "let s = ", "r#\"a\"b\"#", "; let k = 1;"),
        ("real_byte_str", "let s = ", "b\"ab\"", "; let k = 1;"),
        ("real_byte_char", "let s = ", "b'a'", "; let k = 1;"),
    ] {
        let input = format!("{prefix}{literal}{suffix}");
        let want = format!("{prefix}{}{suffix}", " ".repeat(literal.len()));
        assert_eq!(
            mask_comments_and_strings(&input),
            want,
            "净化面在 `{name}` 这格与预期不符\n  输入: {input}"
        );
    }

    // 生命周期不是字符字面量：一个字节都不许动（反向对照，防「宁可多抹」滑成整段吞掉）。
    let lifetime = "fn f<'a>(x: &'a str) {}";
    assert_eq!(
        mask_comments_and_strings(lifetime),
        lifetime,
        "生命周期标注被当成字符字面量抹掉了"
    );
}

/// 🔴 [`mask_comments`]（字面量面）：注释全剥、字符串一个字节不动。
///
/// 三种注释形态都必须剥，**行尾注释是重点**：本仓此前的剥注释器只认「整行起手 `//`」，
/// 于是「把符号改名 + 在同一行行尾留一句 `// 原名 X`」就足以喂饱正面断言 —— 代码里已经
/// 一个 `X` 都没有，门照绿。这是实测过的假绿形态，不是假想。
///
/// **变异探针**：把 [`mask`] 里的行注释分支改成「仅当 `//` 处于行首才剥」⇒ `trailing` 那条转红。
#[test]
fn literal_face_strips_every_comment_form_and_keeps_literals() {
    let source = concat!(
        "//! 模块文档提到 needle_in_doc\n",
        "/* 块注释 /* 嵌套 */ needle_in_block */\n",
        "fn f() {\n",
        "    let a = 1; // 行尾注释提到 needle_in_trailing\n",
        "    let b = \"needle_in_string\";\n",
        "    let c = \"http://a // b\";\n",
        "    let d = r#\"raw // \"# ;\n",
        "    let e = '/';\n",
        "}\n",
    );
    let face = mask_comments(source);

    for gone in [
        "needle_in_doc",
        "needle_in_block",
        "嵌套",
        "needle_in_trailing",
    ] {
        assert!(!face.contains(gone), "注释未剥：{gone}");
    }
    for kept in [
        "\"needle_in_string\"",
        "http://a // b",
        "raw // ",
        "'/'",
        "let a = 1;",
        "fn f() {",
    ] {
        assert!(face.contains(kept), "被误剥：{kept}");
    }
}

/// 🔴 两个面的**输入对差表**：同一份输入，符号面把字面量也抹掉、字面量面保留。
///
/// 写成可执行的，是因为「顺手统一成一个面」看起来永远像化简：真统一到符号面之后，
/// 「某文件不得出现 `networksetup` 字面量」这类判据在净化面上**永远命中不到** ——
/// 判据不是变弱，是消失。
#[test]
fn the_two_faces_differ_exactly_on_literals() {
    let source = "fn f() { let _ = Command::new(\"networksetup\"); } // networksetup\n";
    let code = mask_comments_and_strings(source);
    let literals = mask_comments(source);

    assert!(
        !code.contains("networksetup"),
        "符号面必须把字符串里的 `networksetup` 也抹掉"
    );
    assert!(
        literals.contains("\"networksetup\""),
        "字面量面必须保留字符串"
    );
    for face in [&code, &literals] {
        assert!(face.contains("Command::new"), "两个面都必须保留代码");
        assert_eq!(face.len(), source.len(), "两个面都必须保长度");
    }
    assert!(
        !literals.contains("// networksetup"),
        "字面量面仍须剥掉行尾注释"
    );
}

/// 净化必须保长度保换行 —— 偏移与行号是所有消费方的共同前提。
#[test]
fn masking_preserves_byte_length_and_newlines_on_the_real_corpus() {
    let files = module_files_with_tests_in(env!("CARGO_MANIFEST_DIR"), "");
    assert!(!files.is_empty(), "取材面是空的");
    for (rel, source) in &files {
        // 两个面共用同一份扫描，故长度/行号守恒对**两个**面都是前提；只测一个面，
        // 另一个面的守恒就没有判据（而它已经被 src-tauri 与 system-integration 的门消费）。
        for (face, masked) in [
            ("符号面", mask_comments_and_strings(source)),
            ("字面量面", mask_comments(source)),
        ] {
            assert_eq!(
                masked.len(),
                source.len(),
                "{rel}（{face}）: 净化后字节数变了"
            );
            assert_eq!(
                masked.matches('\n').count(),
                source.matches('\n').count(),
                "{rel}（{face}）: 净化后换行数变了 —— 行号会全错"
            );
        }
    }
}

/// 🔴 取材面必须含**模块根文件**，不只是目录。
///
/// 一个 Rust 模块 `foo` 的源码分布在 `foo.rs`（或 `foo/mod.rs`）与目录 `foo/` 两处。
/// 早前这里只走目录：`module_source("commands/updater")` 漏掉 `commands/updater.rs`、
/// `module_source("runtime/proxy")` 会漏掉 11995 行的 `runtime/proxy.rs` —— 缺一半判据，
/// 而否定型断言在缺失的那一半上恒真。
///
/// **变异探针**：把 `collect_module` 里收集 `roots` 的那段删掉 ⇒ 本条两个方向同时转红。
#[test]
fn the_scan_surface_includes_the_module_root_file() {
    let scratch = Scratch::new("module_root");
    // foo.rs（模块根）+ foo/ 目录（子模块）+ foo/tests/（测试面）
    scratch.write(
        "src/foo.rs",
        "pub const ROOT_MARKER: u8 = 1;\nmod bar;\nmod tests;\n",
    );
    scratch.write("src/foo/bar.rs", "pub const CHILD_MARKER: u8 = 2;\n");
    scratch.write("src/foo/tests/mod.rs", "const TEST_MARKER: u8 = 3;\n");

    let production = module_source_in(&scratch.0, "foo");
    assert!(
        production.contains("ROOT_MARKER"),
        "生产取材面漏了模块根文件 `foo.rs` —— 取材面缺一半，否定型断言在那一半上恒真"
    );
    assert!(production.contains("CHILD_MARKER"), "生产取材面漏了子模块");
    assert!(
        !production.contains("TEST_MARKER"),
        "生产取材面把 `tests/` 收进来了 —— 测试夹具会给生产扫描面充数"
    );

    let with_tests = module_source_with_tests_in(&scratch.0, "foo");
    for marker in ["ROOT_MARKER", "CHILD_MARKER", "TEST_MARKER"] {
        assert!(with_tests.contains(marker), "全量取材面漏了 {marker}");
    }

    // 模块根写成 `foo/mod.rs` 时同样要收（另一种合法形态）。
    let alt = Scratch::new("module_root_mod_rs");
    alt.write("src/baz/mod.rs", "pub const MOD_RS_MARKER: u8 = 4;\n");
    alt.write("src/baz/inner.rs", "pub const INNER_MARKER: u8 = 5;\n");
    let blob = module_source_in(&alt.0, "baz");
    assert!(
        blob.contains("MOD_RS_MARKER"),
        "`<模块>/mod.rs` 形态的模块根没被收进来"
    );
    assert!(blob.contains("INNER_MARKER"));

    // 根文件只出现一次（`foo/mod.rs` 既是根、又在目录遍历面里，去重必须生效）。
    assert_eq!(
        blob.matches("MOD_RS_MARKER").count(),
        1,
        "`mod.rs` 被收了两遍 —— 计数型断言会因此翻倍"
    );
}
