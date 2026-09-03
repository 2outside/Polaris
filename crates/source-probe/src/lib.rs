//! 源码级门的**取材锚点**：一律以 crate 根（`CARGO_MANIFEST_DIR`）或 workspace 根为基准，
//! 在运行期读源码，**不用 `include_str!`**。
//!
//! # 为什么要有这个 crate（根因）
//!
//! `include_str!` 的相对路径锚在**含它的那个文件**。本仓源码级门有 150+ 处这样的取材，其中
//! 129 处写成同目录裸文件名（`include_str!("tray.rs")`）。测试实体从 `foo.rs` 搬进
//! `foo/tests/mod.rs` 时，这些锚点**全部平移一层**，而失败模式是最坏的那种：
//! `foo/tests/` 下常常真的存在同名文件（或上跳一层后解析到另一个真实文件），于是
//! **编译通过、门继续绿、取材面却整个换了对象**——否定型断言从此恒真，计数型断言恒偏。
//!
//! 锚点选错了对象：它锚在**会动的东西**（调用方文件的位置）上。本模块把锚点换成
//! **不动的东西**（crate 根 / workspace 根）：路径从此表达「这个 crate 里的哪个文件」，
//! 与调用方文件在哪一层无关 ⇒ 测试搬到任何深度都不需要改一个字符。
//!
//! # 三个锚点，覆盖全部取材形态
//!
//! | 函数 | 基准 | 覆盖的旧写法 |
//! |---|---|---|
//! | [`crate_source_in`] | `<crate>/src/` | `include_str!("tray.rs")` / `include_str!("runtime/stats.rs")` |
//! | [`crate_file_in`]   | `<crate>/`     | `include_str!("../Cargo.toml")` / `"../capabilities/default.json"` |
//! | [`repo_file_in`]    | workspace 根   | `include_str!("../../ui/index.html")` / `"../../../../scripts/verify-packaging.mjs"` |
//!
//! 三个都拒收 `..` 与绝对路径：放行 `..` 等于把锚点又交还给调用方的位置。
//!
//! # [`module_source_in`]：让「新模块逃出扫描」这个缺陷类消失
//!
//! 手写文件清单的扫描门有一个天生的洞：新增一个模块，清单不动，门照绿。本仓已经吃过这个亏
//! （`commands/updater/tests/mod.rs` 那道调用点守卫的文档里记着「上一版照着三个函数名硬编码 ⇒
//! 明天加第四条腿，三条断言全绿」）。[`module_source_in`] 用**目录遍历**代替清单：
//! 新增子模块自动进取材面，且**递归**——不只直接子文件，任意深度的新子树也进来。
//!
//! 递归而不是只扫一层，是因为「逃出扫描」正是要治的那个缺陷类：只扫一层的话，
//! `runtime/proxy/d/e.rs` 又逃出去了。取材面偏宽的失败方向是**多红**（吵），偏窄的失败方向是
//! **静默绿**（瞎）——必须选前者。
//!
//! ## 遍历排除 `tests/`
//!
//! 本仓约定 `<dir>/*.rs` 恒为生产、`<dir>/tests/` 恒为测试。遍历若把 `tests/` 也拼进来，
//! 测试代码会给扫描面**充数**：`assert!(!blob.contains("坏写法"))` 这类否定型断言会被
//! 「测试里写了一份坏写法当反例」直接顶红，而更糟的是反过来——门要找的正例出现在测试夹具里，
//! 于是「生产代码里其实没有」也判成有。故 `tests` 目录一律不入取材面。
//!
//! 遇到**文件形态**的 `tests.rs`（旧写法）时不猜、不静默跳过，直接 panic 并指出迁移动作：
//! 归属不可判时静默选一边，正是这一整类缺陷的来源。
//!
//! # 两个净化面：[`mask_comments_and_strings`] 与 [`mask_comments`]
//!
//! 取材拿到的是**源码全文**，而门要断言的是「代码里有没有 X」。注释里几乎必然也写着 X
//! （门自己的说明、变异探针的写法），不剥就是给正面断言喂一份与生产调用点无关的证据。
//!
//! | 面 | 抹掉 | 保留 | 判据的针是 |
//! |---|---|---|---|
//! | [`mask_comments_and_strings`]（符号面） | 注释 + 字符串/字符/字节字面量 | 其余代码 | 标识符 / 路径 / 类型名 |
//! | [`mask_comments`]（字面量面） | 注释 | 字面量 + 其余代码 | 字符串字面量本身 |
//!
//! 两个面**共用同一份词法扫描**（`mask`），只差一个布尔。这不是可以合并成一个的重复：合到符号面，
//! 「某文件不得出现 `networksetup` 字面量」这类判据在净化面上永远命中不到 —— 判据不是变弱，是消失。
//!
//! 两个面都**保长度、保换行**（注释按字节抹成空格），故偏移与行号守恒，失败信息说得出「第几行」。
//!
//! # 哨兵：[`expect_marker`]
//!
//! 换锚点治的是「锚点跟着调用方走」，剩余风险是「锚点本身解析错了对象」（crate 根算错、
//! 文件被改名后相对路径撞上另一个真实文件）。[`expect_marker`] 要求每份 blob 含该文件的
//! 独有标识，把这类剩余风险从「静默绿」变成「当场红」。它是纵深防御，不是主防线。
//!
//! # 用法
//!
//! 调用方 crate 在 `[dev-dependencies]` 里引 `polaris-source-probe`，然后二选一：
//!
//! ```text
//! // ① 宏（零样板）：`env!` 在**调用方 crate** 编译时求值 ⇒ 拿到调用方的 CARGO_MANIFEST_DIR
//! let src = polaris_source_probe::crate_source!("tray.rs");
//!
//! // ② 本 crate 里包一层薄 wrapper（src-tauri 走这条，见 `test_support.rs`）
//! pub(crate) fn crate_source(rel: &str) -> String {
//!     polaris_source_probe::crate_source_in(env!("CARGO_MANIFEST_DIR"), rel)
//! }
//! ```
//!
//! 两条都把 `env!("CARGO_MANIFEST_DIR")` 留在**调用方 crate** 里——这是必须的：若本 crate
//! 内部去读 `env!("CARGO_MANIFEST_DIR")`，拿到的是 `crates/source-probe`，全部取材当场跑偏。
//! 本 crate 的公开函数因此一律要求把 manifest 目录**当参数传进来**，没有隐式读取的那一版。

use std::path::{Component, Path, PathBuf};

/// 测试目录名。约定：`<dir>/tests/` 恒为测试，`<dir>/*.rs` 恒为生产。
const TESTS_DIR: &str = "tests";

/// 旧写法的文件形态测试模块——归属不可判，遇到即 panic（见模块文档）。
const LEGACY_TESTS_FILE: &str = "tests.rs";

// ── 锚点解析 ──────────────────────────────────────────────────────────────

/// `base` + `rel`，且 `rel` 必须是**纯**相对路径（只含 `Normal` 成分）。
///
/// 拒收 `..` / `.` / 绝对路径不是洁癖：放行 `..` 就等于允许「从锚点再往回走到调用方附近」，
/// 而那正是 `include_str!` 的失效方式。拒收后，路径的含义只剩「这个 crate/仓库里的哪个文件」。
fn resolve(base: &Path, rel: &str, what: &str) -> PathBuf {
    assert!(!rel.is_empty(), "{what}：相对路径不能为空");
    let relative = Path::new(rel);
    for component in relative.components() {
        assert!(
            matches!(component, Component::Normal(_)),
            "{what}：`{rel}` 含 `.` / `..` / 根成分。取材路径必须是从锚点出发的纯相对路径 —— \
             放行 `..` 等于把锚点又交回给调用方文件的位置，测试一搬家就静默解析到别的文件。"
        );
    }
    base.join(relative)
}

/// 读全文；读不到就 panic，且信息足以直接定位（绝对路径 + 系统错误 + 该怎么办）。
///
/// **不返回空串 / `Option`**：源码级门拿到空串会静默变成「什么都没扫到」，
/// 而否定型断言在空串上恒真——那正是这套门要防的失效形态。
fn read(path: &Path, what: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|err| {
        panic!(
            "{what}：读不到 `{}`（{err}）。\n\
             该路径以 crate 根 / workspace 根为锚，与调用方文件位置无关 —— 所以这不是\
             「测试搬家了」，而是那个文件真的改名 / 挪窝 / 没生成。改这里的相对路径，\
             别改回 `include_str!`（那会把锚点重新钉回会动的东西上）。",
            path.display()
        )
    })
}

/// 从 `manifest_dir` 逐层上溯，找持有 `[workspace]` 的 `Cargo.toml` 所在目录。
///
/// 不写死 `../..`：`src-tauri` 与 `crates/*` 到仓库根的层数不同，写死就等于给每个调用方
/// 一次数错的机会（又一个会动的锚点）。
pub fn workspace_root_from(manifest_dir: impl AsRef<Path>) -> PathBuf {
    let start = manifest_dir.as_ref();
    for dir in start.ancestors() {
        let manifest = dir.join("Cargo.toml");
        let Ok(text) = std::fs::read_to_string(&manifest) else {
            continue;
        };
        // 行级精确匹配：注释形态 `# [workspace]` trim 后不等于 `[workspace]`，不会误命中。
        if text.lines().any(|line| line.trim() == "[workspace]") {
            return dir.to_path_buf();
        }
    }
    panic!(
        "workspace_root：从 `{}` 上溯到根都没找到含 `[workspace]` 的 Cargo.toml —— \
         workspace 布局变了，或本测试不是由 cargo 驱动的。",
        start.display()
    )
}

// ── 三个取材入口 ──────────────────────────────────────────────────────────

/// `<manifest_dir>/src/<rel>` 的全文。取代同目录 / 同 crate 内的 `include_str!`。
pub fn crate_source_in(manifest_dir: impl AsRef<Path>, rel: &str) -> String {
    let path = resolve(&manifest_dir.as_ref().join("src"), rel, "crate_source");
    read(&path, "crate_source")
}

/// `<manifest_dir>/<rel>` 的全文（crate 根下的非源码：`Cargo.toml` / `tauri.conf.json` /
/// `capabilities/*.json`）。取代 `include_str!("../Cargo.toml")` 这一形。
pub fn crate_file_in(manifest_dir: impl AsRef<Path>, rel: &str) -> String {
    let path = resolve(manifest_dir.as_ref(), rel, "crate_file");
    read(&path, "crate_file")
}

/// workspace 根下 `<rel>` 的全文（`ui/**`、`scripts/**`、根 README 等跨语言判据源）。
/// 取代 `include_str!("../../../../scripts/verify-packaging.mjs")` 这一形——那串 `../` 的
/// 个数本身就是随调用方深度变化的锚点。
pub fn repo_file_in(manifest_dir: impl AsRef<Path>, rel: &str) -> String {
    let root = workspace_root_from(manifest_dir);
    let path = resolve(&root, rel, "repo_file");
    read(&path, "repo_file")
}

/// `<manifest_dir>/<rel>` 的**原始字节**。取代 `include_bytes!("../icons/x.png")` 这一形。
///
/// `include_bytes!` 与 `include_str!` 的锚点语义**完全一样**（都锚在含它的那个文件），
/// 失效方式也一样：测试搬家后那串 `..` 整体平移，撞上另一个真实文件就编译通过、断言照跑、
/// 跑在别的字节上。只因为它取的是二进制而不是文本，就漏掉不管，是按类型分类而不是按缺陷分类。
pub fn crate_bytes_in(manifest_dir: impl AsRef<Path>, rel: &str) -> Vec<u8> {
    let path = resolve(manifest_dir.as_ref(), rel, "crate_bytes");
    read_bytes(&path, "crate_bytes")
}

/// workspace 根下 `<rel>` 的原始字节。
pub fn repo_bytes_in(manifest_dir: impl AsRef<Path>, rel: &str) -> Vec<u8> {
    let root = workspace_root_from(manifest_dir);
    let path = resolve(&root, rel, "repo_bytes");
    read_bytes(&path, "repo_bytes")
}

/// 读原始字节；读不到就 panic。**不返回空 `Vec`** —— 理由同 [`read`]：
/// 空取材面上的否定型断言恒真。
fn read_bytes(path: &Path, what: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|err| {
        panic!(
            "{what}：读不到 `{}`（{err}）。取材锚点已失效：确认文件路径，或改用另一个锚点函数。",
            path.display()
        )
    })
}

// ── 目录取材 ──────────────────────────────────────────────────────────────

/// 模块 `<dir_rel>` 的**全部生产 `.rs`**（递归，排除 `tests/`），按相对路径升序返回
/// `(相对 dir 的路径, 全文)`。
///
/// **取材面 = 模块根文件 + 目录**：一个 Rust 模块 `foo` 的源码天然分布在 `foo.rs`
/// （或 `foo/mod.rs`）与目录 `foo/` 两处，只取其一就是只有一半判据。
///
/// `dir_rel` 传空串 = 整个 `src/`（此时 `lib.rs` / `main.rs` 本就在遍历面里）。
///
/// 返回逐文件的形态而不是一整块，是为了让调用方的失败信息能直接说出「哪个文件哪一行」；
/// 只需要一整块时用 [`module_source_in`]。
///
/// # Panics
///
/// - 目录不存在 / 不是目录；
/// - 目录里一个生产 `.rs` 都没有（取材面为空 ⇒ 调用方的断言从此恒真，必须当场红）；
/// - 撞见文件形态的 `tests.rs`（归属不可判，见模块文档）。
pub fn module_files_in(manifest_dir: impl AsRef<Path>, dir_rel: &str) -> Vec<(String, String)> {
    collect_module(manifest_dir.as_ref(), dir_rel, false)
}

/// [`module_files_in`] / [`module_files_with_tests_in`] 的共同实现。
///
/// 两者只差 `include_tests` 一个布尔：目录解析、空取材面自检、排序、panic 文案必须**同一份**，
/// 各写一份就是给两条取材面留出各自漂移的余地（本仓已经为「同一事实两份实现」付过账）。
fn collect_module(
    manifest_dir: &Path,
    dir_rel: &str,
    include_tests: bool,
) -> Vec<(String, String)> {
    let (what, kind) = if include_tests {
        ("module_source_with_tests", "`.rs`")
    } else {
        ("module_source", "生产 `.rs`")
    };
    let src_root = manifest_dir.join("src");
    let dir = if dir_rel.is_empty() {
        src_root.clone()
    } else {
        resolve(&src_root, dir_rel, what)
    };

    // ── 模块根文件 ──
    //
    // 一个 Rust 模块 `foo` 的源码天然分布在**两处**：`foo.rs`（或 `foo/mod.rs`）与目录 `foo/`。
    // 早前这里只走目录，于是 `module_source("commands/updater")` 漏掉 `commands/updater.rs`、
    // `module_source("runtime/proxy")` 会漏掉 11995 行的 `runtime/proxy.rs` —— 取材面**缺一半**，
    // 而建在它上面的否定型断言在缺失的那一半上恒真。
    //
    // `dir_rel` 为空串时目录就是 `src/` 本身，其模块根（`lib.rs` / `main.rs`）本来就在遍历面里，
    // 由下面的去重兜住，不会重复计入。
    let mut roots: Vec<PathBuf> = Vec::new();
    if !dir_rel.is_empty() {
        for candidate in [src_root.join(format!("{dir_rel}.rs")), dir.join("mod.rs")] {
            if candidate.is_file() {
                roots.push(candidate);
                break;
            }
        }
    }

    assert!(
        dir.is_dir() || !roots.is_empty(),
        "{what}：`{}` 既不是目录、也没有同名的 `{dir_rel}.rs` —— \
         模块被拆分/合并/改名了，取材面已经不是原来那个。",
        dir.display()
    );

    let mut files = Vec::new();
    for root in &roots {
        let rel = root
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        files.push((rel, read(root, what)));
    }
    if dir.is_dir() {
        collect_rs(&dir, &dir, include_tests, &mut files);
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files.dedup_by(|a, b| a.0 == b.0);
    assert!(
        !files.is_empty(),
        "{what}：`{}` 下一个{kind} 都没有 —— 取材面是空的，\
         基于它的任何否定型断言都会恒真。先确认目录对不对。",
        dir.display()
    );
    files
}

/// 逐文件全文按稳定顺序拼成一块，以 `\n` 分隔（避免首尾行被粘连成一行）。
fn join_files(files: Vec<(String, String)>) -> String {
    let mut blob = String::new();
    for (_, text) in files {
        blob.push_str(&text);
        blob.push('\n');
    }
    blob
}

/// [`module_files_in`] 的全文拼接（按同一稳定顺序，以 `\n` 分隔，避免首尾行被粘连成一行）。
pub fn module_source_in(manifest_dir: impl AsRef<Path>, dir_rel: &str) -> String {
    join_files(module_files_in(manifest_dir, dir_rel))
}

/// 递归收集 `dir` 下的 `.rs`（`include_tests` 决定 `tests/` 进不进）。`root` 只用来算相对路径。
fn collect_rs(root: &Path, dir: &Path, include_tests: bool, out: &mut Vec<(String, String)>) {
    let entries = std::fs::read_dir(dir)
        .unwrap_or_else(|err| panic!("module_source：读不到目录 `{}`（{err}）", dir.display()));
    for entry in entries {
        let path = entry
            .unwrap_or_else(|err| {
                panic!(
                    "module_source：`{}` 的目录项读取失败（{err}）",
                    dir.display()
                )
            })
            .path();

        if path.is_dir() {
            // `tests/` 恒为测试：进生产取材面会让测试夹具给生产扫描面充数。
            // `include_tests` 为真时反过来——那是取材面**本身就是测试代码**的门（见
            // [`module_files_with_tests_in`]），漏掉 `tests/` 才是它的失效形态。
            if !include_tests && path.file_name().is_some_and(|name| name == TESTS_DIR) {
                continue;
            }
            collect_rs(root, &path, include_tests, out);
            continue;
        }

        if !path.extension().is_some_and(|ext| ext == "rs") {
            continue;
        }
        assert!(
            !path.file_name().is_some_and(|n| n == LEGACY_TESTS_FILE),
            "module_source：`{}` 是**文件形态**的测试模块（旧写法）。本仓约定 `<dir>/*.rs` 恒为生产、\
             `<dir>/tests/` 恒为测试，故 `tests.rs` 的归属不可判 —— 拼进来会让测试代码给生产扫描面\
             充数，跳过又可能漏掉真生产文件。把它迁成 `<dir>/tests/mod.rs` 后再用 module_source 取材。",
            path.display()
        );

        out.push((
            relative_key(root, &path, "module_source"),
            read(&path, "module_source"),
        ));
    }
}

/// `path` 相对 `root` 的路径，成分以 `/` 连接 —— 平台无关的稳定键。
///
/// 单点实现：这个键同时是**排序依据**与**失败信息里的定位**，两份实现各自漂移的代价是
/// 「同一个文件在两条取材面上叫两个名字」，而排序与名单对拍都靠它逐字相等。
fn relative_key(root: &Path, path: &Path, what: &str) -> String {
    path.strip_prefix(root)
        .unwrap_or_else(|_| panic!("{what}：`{}` 不在取材根内", path.display()))
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// `<manifest_dir>/src/<dir_rel>` 下**全部 `.rs`：生产 + `tests/` 里的测试**（递归），
/// 按相对路径升序返回 `(相对 dir 的路径, 全文)`。
///
/// 与 [`module_files_in`] 的分工按**取材面的性质**划，不按方便程度划：
///
/// - 门断言的是「生产代码长什么样」（调用点守卫、禁用 API 扫描）→ 用 [`module_files_in`]，
///   `tests/` 必须排除，否则测试夹具给生产扫描面充数。
/// - 门断言的是「测试代码长什么样」（每条 `real_core_*` 必须先取跨模块锁、测试里不许出现
///   `include_str!`）→ 用本函数，`tests/` 必须包含，否则测试一从 `foo.rs` 搬进
///   `foo/tests/mod.rs`，取材面就把被断言的对象整个丢了 —— 门不报错，只是从此扫了个空。
///   这是**沉默失效**：`found > 0` 之类的自检要么一起消失，要么把别的模块的命中当成还活着。
///
/// `dir_rel` 传空串 = 整个 `src/`。
///
/// # Panics
///
/// 与 [`module_files_in`] 同：目录不存在 / 不是目录；一个 `.rs` 都没有；撞见文件形态的
/// `tests.rs`（归属不可判 —— 这一条两种取材面都拒收，因为该形态本身是被禁的写法）。
pub fn module_files_with_tests_in(
    manifest_dir: impl AsRef<Path>,
    dir_rel: &str,
) -> Vec<(String, String)> {
    collect_module(manifest_dir.as_ref(), dir_rel, true)
}

/// [`module_files_with_tests_in`] 的全文拼接（同一稳定顺序，以 `\n` 分隔）。
pub fn module_source_with_tests_in(manifest_dir: impl AsRef<Path>, dir_rel: &str) -> String {
    join_files(module_files_with_tests_in(manifest_dir, dir_rel))
}

/// workspace 根下 `<dir_rel>` 里**全部 `.<extension>` 文件**（递归），按**相对 workspace 根**的
/// 路径升序返回 `(路径, 全文)`。
///
/// # 为什么要有它：覆盖面必须由判据定，不由夹具定
///
/// 跨语言门此前一律把被扫的文件名写死在测试里（CSP 契约那条门列了 `ui/index.html` /
/// `ui/tray.html` / `ui/update-popup.html` 三行）。那等于把「哪些文件受这条不变式约束」交给
/// **当天的夹具清单**保管：明天在 `ui/` 下新增一个 renderer 入口，门看不见它，而且不报错。
/// [`module_files_in`] 在 `.rs` 面上治的正是同一个缺陷类，本函数是它在**仓库根 + 任意扩展名**
/// 上的对应形态。
///
/// # 相对路径的基准是 workspace 根，不是 `dir_rel`
///
/// 与 [`module_files_in`]（相对 `dir_rel`）刻意不同：本函数的消费方要把返回的键直接当**仓库内
/// 路径**用（写进豁免名单、写进失败信息、与别处的配置对拍），相对 `dir_rel` 的裸
/// `index.html` 既定位不到文件，也没法和那些以 `ui/` 起手的清单逐字相等。
///
/// # 跳过的目录（非源码）
///
/// `node_modules` / `dist`（见私有常量 `NON_SOURCE_DIRS`）与全部以 `.` 起手的目录。前两个是
/// 仓库根 `.gitignore` 里就登记的依赖缓存与构建产物：递归进去会让取材面**取决于有没有人跑过
/// 依赖安装 / 构建** —— 同一份代码在两台机器上得出不同的扫描结果，那比漏扫更难查。除此之外
/// 一律进面：取材面偏宽只会多红（吵），偏窄是静默绿（瞎）。
///
/// # Panics
///
/// 目录不存在 / 不是目录；面上一个匹配文件都没有 —— 空取材面会让调用方的循环体一次都不执行、
/// 断言恒真，必须当场红。
pub fn repo_dir_files_in(
    manifest_dir: impl AsRef<Path>,
    dir_rel: &str,
    extension: &str,
) -> Vec<(String, String)> {
    let root = workspace_root_from(manifest_dir);
    let dir = resolve(&root, dir_rel, "repo_dir_files");
    assert!(
        dir.is_dir(),
        "repo_dir_files：`{}` 不是目录 —— 取材面的根改名 / 挪窝了。",
        dir.display()
    );

    let mut files = Vec::new();
    collect_by_extension(&root, &dir, extension, &mut files);
    files.sort_by(|left, right| left.0.cmp(&right.0));
    assert!(
        !files.is_empty(),
        "repo_dir_files：`{}` 下一个 `.{extension}` 都没有 —— 取材面是空的，\
         基于它的循环体一次都不会执行、断言恒真。",
        dir.display()
    );
    files
}

/// 非源码目录：依赖缓存与构建产物（仓库根 `.gitignore` 已登记的那两个名字）。
const NON_SOURCE_DIRS: [&str; 2] = ["node_modules", "dist"];

/// 递归收集 `dir` 下扩展名为 `extension` 的文件。`root` 只用来算相对路径。
fn collect_by_extension(root: &Path, dir: &Path, extension: &str, out: &mut Vec<(String, String)>) {
    let entries = std::fs::read_dir(dir)
        .unwrap_or_else(|err| panic!("repo_dir_files：读不到目录 `{}`（{err}）", dir.display()));
    for entry in entries {
        let path = entry
            .unwrap_or_else(|err| {
                panic!(
                    "repo_dir_files：`{}` 的目录项读取失败（{err}）",
                    dir.display()
                )
            })
            .path();

        if path.is_dir() {
            let skip = path.file_name().is_some_and(|name| {
                let name = name.to_string_lossy();
                name.starts_with('.') || NON_SOURCE_DIRS.contains(&name.as_ref())
            });
            if !skip {
                collect_by_extension(root, &path, extension, out);
            }
            continue;
        }

        if !path.extension().is_some_and(|ext| ext == extension) {
            continue;
        }
        out.push((
            relative_key(root, &path, "repo_dir_files"),
            read(&path, "repo_dir_files"),
        ));
    }
}

// ── 取材面净化 ────────────────────────────────────────────────────────────

/// 把 Rust 源码里的**注释与字面量**整段抹成空格，保留其余字节与全部换行。
///
/// 源码级门扫的是「代码里有没有 X」，而注释和字符串里几乎必然也会出现 X —— 门自己的说明、
/// 变异探针的写法、错误消息的模板。不剥就会把这些当成命中：
///
/// - 肯定型断言（「必须存在 X」）被注释里的 X 喂饱 ⇒ **假绿**，代码里删光了也不红；
/// - 否定型断言（「不许出现 X」）被注释里的 X 绊倒 ⇒ 假红，吵但能查。
///
/// 前者是这函数存在的理由。
///
/// # 为什么按字节抹成空格，而不是删除
///
/// 抹成等长空格后**字节偏移不变**，于是「在净化后的文本里找到位置，再回原文取上下文」
/// 是安全的；删除会让两份文本的偏移错位，而错位的取材比不取材更难发现。
/// 换行原样保留，行号也就不变，失败信息才能直接说「第几行」。
///
/// # 覆盖
///
/// 行注释（`//`，含文档注释 `///` / `//!`）、块注释（`/* */`，**支持嵌套**，Rust 的块注释
/// 是嵌套的）、字符串字面量（含转义）、原始字符串（`r"…"` / `r#"…"#`，任意个 `#`）、
/// 字符与字节字面量（`'x'` / `b'x'`）、字节串（`b"…"` / `br#"…"#`）。
///
/// # 已知边界
///
/// 生命周期标注 `'a` 与字符字面量 `'a'` 在词法上只差一个收尾引号；本函数按「引号后第 2~3 个
/// 字节内是否有收尾 `'`」判定，判不出就当生命周期放过（宁可少抹，不可错抹整段）。
pub fn mask_comments_and_strings(source: &str) -> String {
    mask(source, true)
}

/// 把 Rust 源码里的**注释**整段抹成空格，**字符串 / 字符 / 字节字面量原样保留**；
/// 其余字节与全部换行不变（偏移与行号守恒，同 [`mask_comments_and_strings`]）。
///
/// # 为什么必须与 [`mask_comments_and_strings`] 并存
///
/// 两者的差别不是「剥得多一点少一点」，而是**判据的对象**：
///
/// - 判据的针是**符号**（标识符 / 路径 / 类型名）→ 用 [`mask_comments_and_strings`]：
///   字符串里出现同名文本同样是伪证据，一并抹掉才干净。
/// - 判据的针**本身就是字符串字面量**（「某文件不得出现 `networksetup`」「帧里必须带
///   `"subscriptionId"`」）→ 必须用本函数：连字符串一起抹，针在净化面上**永远命中不到**，
///   判据不是变弱是消失（把被禁的那行整段复制进去也照样绿）。
///
/// 所以这两个面**都**是共享实现的一部分，不是可以「顺手统一成一个」的重复。
///
/// # 覆盖（射程如实登记）
///
/// **剥**：行注释 `//`（含 `///` / `//!`，**行首与行尾同等对待** —— 判据只认「是不是注释」，
/// 不认它在行里的位置）、块注释 `/* */`（**支持嵌套**，Rust 语义），块注释在行中间起笔
/// 也剥（`foo(/* x */ 1)`）。
///
/// **不剥**：字符串字面量（含转义）、原始字符串（`r"…"` / `r#"…"#`，任意个 `#`）、
/// 字符与字节字面量（`'x'` / `b'x'`）、字节串（`b"…"` / `br#"…"#`）—— 这些整段跳过，
/// 于是字面量**内部**的 `//` 与 `/*`（`"http://a // b"`）不会被当成注释起笔。
///
/// 也**不剥**：`#[cfg(…)]` 属性、宏体、被 `#[cfg(test)]` 关掉的代码 —— 净化只做词法层的
/// 注释剥离，不做条件编译求值；取材面要排除测试代码靠 [`module_files_in`] 那一层，不靠这里。
///
/// # 已知边界
///
/// 同 [`mask_comments_and_strings`]：生命周期标注 `'a` 与字符字面量 `'a'` 词法上只差一个收尾
/// 引号，判不出就当生命周期放过。此处放过的后果是**该处的字面量当普通代码留在面上**（不是被
/// 误剥），方向仍是「宁可少剥」。
pub fn mask_comments(source: &str) -> String {
    mask(source, false)
}

/// 把 **HTML** 里的注释 `<!-- … -->` 整段抹成空格；属性值、元素内容与全部换行原样保留
/// （偏移与行号守恒，同 [`mask_comments`]）。
///
/// # 为什么 HTML 面既不能用 [`mask_comments`]、也不能用 [`mask_comments_and_strings`]
///
/// 两条理由都来自「HTML 的词法与 Rust 不同源」，不是风格偏好：
///
/// 1. **定界符不同**（`<!-- -->` vs `//` / `/* */`）—— [`mask_comments`] 打在 HTML 上等于没剥；
/// 2. **HTML 里的「字符串」就是属性值本身**。CSP 策略整条住在
///    `content="default-src 'self'; …"` 里，连属性值一起抹（[`mask_comments_and_strings`] 那一路）
///    会把判据的**对象**抹没，门从此对着一份空属性作证 —— 不是判据变弱，是判据消失。
///
/// 故本函数只做一件事：**剥注释、留属性值**。
///
/// # 这条剥离是刚需（本仓实测过的假绿）
///
/// `ui/index.html` 有一段注释逐字写着 `script-src 'self'`（解释「为什么用 `<style>` 而不是内联
/// `<script>`」）。判据打在**原文**上时，把那条真 meta 整条删掉、只留一句
/// `<!-- script-src 'self' -->`，`contains("script-src 'self'")` 照样绿 —— 策略没了，门不响。
///
/// 反方向同样是刚需：注释里出现的 `<script` 会让「禁内联脚本」的扫描**误红**，逼后人把判据
/// 改宽 = 门被磨钝。
///
/// # 射程（如实登记）
///
/// **剥**：`<!--` 起、到**最近一个** `-->` 止。HTML 注释不嵌套 —— 注释体内出现的 `<!--` 只是
/// 普通文本，第一个 `-->` 就闭合，与浏览器一致。跨行、同一文件多段、注释体内含 `<script`
/// 或 `-->` 字样都按这条规则处理。
///
/// **不剥**：属性值、文本节点、`<script>` / `<style>` 元素的内容。
///
/// # 已知边界（两条，方向都是「多剥」⇒ 门更容易红，不会静默绿）
///
/// - 属性值里若出现 `<!--` 会被当成注释起笔（合法 HTML，本仓无此写法）；
/// - `<!--` 找不到闭合时抹到文件尾 —— 与 HTML 规范一致（未闭合注释吞掉文档剩余部分）。
///   此时被吞掉的 meta 会让门当场红，而不是让一份浏览器根本读不出策略的文档静默过门。
pub fn mask_html_comments(source: &str) -> String {
    const OPEN: &[u8] = b"<!--";
    const CLOSE: &[u8] = b"-->";

    let bytes = source.as_bytes();
    let total = bytes.len();
    let mut out = bytes.to_vec();

    let mut i = 0usize;
    while i < total {
        if !bytes[i..].starts_with(OPEN) {
            i += 1;
            continue;
        }
        let body = i + OPEN.len();
        let end = bytes[body..]
            .windows(CLOSE.len())
            .position(|window| window == CLOSE)
            .map_or(total, |at| body + at + CLOSE.len());
        for byte in out[i..end].iter_mut() {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
        i = end;
    }

    String::from_utf8(out).expect("只把整段多字节序列换成 ASCII 空格，不会破坏 UTF-8")
}

/// [`mask_comments_and_strings`] 与 [`mask_comments`] 的共同实现。
///
/// 两者只差 `mask_literals` 一个布尔：注释的识别、字面量的**边界扫描**（原始字符串的 `#`
/// 计数、转义、字符字面量与生命周期的区分）必须是**同一份**。各写一份的代价本仓已经付过：
/// 第二份实现是「先跑全剥面、再按下标反推哪些区是字面量」的近似器，带着一条只往假红走的
/// 保守边界；两份实现的边界从此各自漂移。
fn mask(source: &str, mask_literals: bool) -> String {
    let bytes = source.as_bytes();
    let total = bytes.len();
    let mut out = bytes.to_vec();
    let blank = |out: &mut Vec<u8>, from: usize, to: usize| {
        for byte in out[from..to.min(total)].iter_mut() {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
    };

    let mut i = 0usize;
    while i < total {
        // 行注释
        if bytes[i] == b'/' && i + 1 < total && bytes[i + 1] == b'/' {
            let end = source[i..].find('\n').map_or(total, |off| i + off);
            blank(&mut out, i, end);
            i = end;
            continue;
        }
        // 块注释（嵌套）
        if bytes[i] == b'/' && i + 1 < total && bytes[i + 1] == b'*' {
            let mut depth = 1usize;
            let mut j = i + 2;
            while j < total && depth > 0 {
                if bytes[j] == b'/' && j + 1 < total && bytes[j + 1] == b'*' {
                    depth += 1;
                    j += 2;
                } else if bytes[j] == b'*' && j + 1 < total && bytes[j + 1] == b'/' {
                    depth -= 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
            blank(&mut out, i, j);
            i = j;
            continue;
        }
        // 标识符整体消费：`r` / `b` / `br` 只有作为**独立**标识符时才是字面量前缀。
        // 逐字节扫会把 `foo_r"…"` 里的 `r"` 读成原始字符串起点，从此整段偏移错位。
        if is_ident_start(bytes[i]) {
            let mut j = i;
            while j < total && is_ident_continue(bytes[j]) {
                j += 1;
            }
            let ident = &bytes[i..j];
            if matches!(ident, b"r" | b"b" | b"br") {
                if let Some(end) = raw_string_end(bytes, i) {
                    if mask_literals {
                        blank(&mut out, i, end);
                    }
                    i = end;
                    continue;
                }
                if matches!(ident, b"b" | b"br") && bytes.get(j) == Some(&b'"') {
                    let end = normal_string_end(bytes, j + 1);
                    if mask_literals {
                        blank(&mut out, i, end);
                    }
                    i = end;
                    continue;
                }
                if ident == b"b" && bytes.get(j) == Some(&b'\'') {
                    if let Some(end) = char_literal_end(bytes, j) {
                        if mask_literals {
                            blank(&mut out, i, end);
                        }
                        i = end;
                        continue;
                    }
                }
            }
            i = j;
            continue;
        }
        // 普通字符串
        if bytes[i] == b'"' {
            let j = normal_string_end(bytes, i + 1);
            if mask_literals {
                blank(&mut out, i, j);
            }
            i = j;
            continue;
        }
        // 字符字面量（与生命周期标注区分）。`b'x'` 已在标识符分支里处理。
        if bytes[i] == b'\'' {
            if let Some(j) = char_literal_end(bytes, i) {
                if mask_literals {
                    blank(&mut out, i, j);
                }
                i = j;
                continue;
            }
        }
        i += 1;
    }

    String::from_utf8(out).expect("只把整段多字节序列换成 ASCII 空格，不会破坏 UTF-8")
}

fn is_ident_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic() || byte >= 0x80
}

fn is_ident_continue(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric() || byte >= 0x80
}

/// 从开引号之后的 `from` 起，返回普通字符串结束偏移（开区间右端；未闭合则到文件尾）。
fn normal_string_end(bytes: &[u8], from: usize) -> usize {
    let mut i = from;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == b'"' {
            return i + 1;
        }
        i += 1;
    }
    bytes.len()
}

/// `bytes[start..]` 若是原始字符串（可带 `b` 前缀），返回其结束偏移（开区间右端）。
fn raw_string_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    if bytes.get(i) == Some(&b'b') {
        i += 1;
    }
    if bytes.get(i) != Some(&b'r') {
        return None;
    }
    i += 1;
    let hash_start = i;
    while bytes.get(i) == Some(&b'#') {
        i += 1;
    }
    let hashes = i - hash_start;
    if bytes.get(i) != Some(&b'"') {
        return None;
    }
    i += 1;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            let mut closing = 0usize;
            while closing < hashes && bytes.get(i + 1 + closing) == Some(&b'#') {
                closing += 1;
            }
            if closing == hashes {
                return Some(i + 1 + hashes);
            }
        }
        i += 1;
    }
    Some(bytes.len())
}

/// `bytes[open]` 是 `'`；若它开启的是**字符字面量**（而非生命周期标注），返回结束偏移。
fn char_literal_end(bytes: &[u8], open: usize) -> Option<usize> {
    let mut i = open + 1;
    if bytes.get(i) == Some(&b'\\') {
        // **先越过被转义的那个字节**：否则 `'\''`（转义单引号）会把 `\` 后面那个 `'` 当成收尾引号，
        // 只抹掉 3 个字节，真正的收尾引号原样留在净化面上 —— 而扫描随后又从它开始，
        // 把后面的代码当成新的字面量。2026-08-30 全仓差分实测：13 个文件命中这个形态。
        i = open + 3;
        // 转义序列长度不定（`\n` / `\x41` / `\u{1F600}`），扫到收尾引号为止，给个上限。
        while i < bytes.len() && i < open + 12 {
            if bytes[i] == b'\'' {
                return Some(i + 1);
            }
            if bytes[i] == b'\n' {
                return None;
            }
            i += 1;
        }
        return None;
    }
    // 非转义：一个字符（可能多字节）后必须紧跟收尾引号，否则是生命周期。
    let rest = &bytes[i..];
    let width = utf8_width(*rest.first()?);
    if bytes.get(i + width) == Some(&b'\'') {
        return Some(i + width + 1);
    }
    None
}

/// UTF-8 首字节 → 该字符的字节宽度。
fn utf8_width(first: u8) -> usize {
    match first {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}

// ── 哨兵 ──────────────────────────────────────────────────────────────────

/// blob 必须含该来源的**独有标识**，否则 panic。返回入参本身，便于内联串接。
///
/// 防的是「锚点解析错了对象」这类剩余风险（crate 根算错 / 相对路径撞上另一个真实文件）：
/// 那种情况下 blob 非空、断言照跑，只是跑在**别的文件**上——否定型断言恒真，计数型恒偏。
///
/// marker 要挑**只可能出现在该文件**的串（`pub struct ProxyRuntime`、
/// `pub const TRAY_AUTOSAVE_NAME`），不要挑 `use std::` 这种到处都有的。
pub fn expect_marker<S: AsRef<str>>(blob: S, origin: &str, marker: &str) -> S {
    let text = blob.as_ref();
    assert!(
        text.contains(marker),
        "取材哨兵失败：`{origin}` 读到 {} 字节，但里面找不到独有标识 `{marker}`。\n\
         说明拿到的不是那个文件（锚点解析错 / 文件被替换 / 标识改名）。在修好之前不要\
         继续用这份 blob 做断言 —— 否定型断言在错的 blob 上会恒真。",
        text.len()
    );
    blob
}

// ── 宏形态（零样板；`env!` 在调用方 crate 求值）────────────────────────────

/// [`crate_source_in`] 的零样板形态。
#[macro_export]
macro_rules! crate_source {
    ($rel:expr $(,)?) => {
        $crate::crate_source_in(env!("CARGO_MANIFEST_DIR"), $rel)
    };
}

/// [`crate_file_in`] 的零样板形态。
#[macro_export]
macro_rules! crate_file {
    ($rel:expr $(,)?) => {
        $crate::crate_file_in(env!("CARGO_MANIFEST_DIR"), $rel)
    };
}

/// [`repo_file_in`] 的零样板形态。
#[macro_export]
macro_rules! repo_file {
    ($rel:expr $(,)?) => {
        $crate::repo_file_in(env!("CARGO_MANIFEST_DIR"), $rel)
    };
}

/// [`crate_bytes_in`] 的零样板形态。
#[macro_export]
macro_rules! crate_bytes {
    ($rel:expr $(,)?) => {
        $crate::crate_bytes_in(env!("CARGO_MANIFEST_DIR"), $rel)
    };
}

/// [`repo_bytes_in`] 的零样板形态。
#[macro_export]
macro_rules! repo_bytes {
    ($rel:expr $(,)?) => {
        $crate::repo_bytes_in(env!("CARGO_MANIFEST_DIR"), $rel)
    };
}

/// [`module_source_in`] 的零样板形态。
#[macro_export]
macro_rules! module_source {
    ($dir_rel:expr $(,)?) => {
        $crate::module_source_in(env!("CARGO_MANIFEST_DIR"), $dir_rel)
    };
}

/// [`module_files_in`] 的零样板形态。
#[macro_export]
macro_rules! module_files {
    ($dir_rel:expr $(,)?) => {
        $crate::module_files_in(env!("CARGO_MANIFEST_DIR"), $dir_rel)
    };
}

/// [`module_source_with_tests_in`] 的零样板形态。
#[macro_export]
macro_rules! module_source_with_tests {
    ($dir_rel:expr $(,)?) => {
        $crate::module_source_with_tests_in(env!("CARGO_MANIFEST_DIR"), $dir_rel)
    };
}

/// [`module_files_with_tests_in`] 的零样板形态。
#[macro_export]
macro_rules! module_files_with_tests {
    ($dir_rel:expr $(,)?) => {
        $crate::module_files_with_tests_in(env!("CARGO_MANIFEST_DIR"), $dir_rel)
    };
}

#[cfg(test)]
mod tests;
