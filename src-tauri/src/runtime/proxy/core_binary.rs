//! 核二进制解析 owner：随包资源候选布局、开发树 manifest 目录、现役核三级优先级解析、
//! sing-box 官方面板 serve 目录。
//!
//! 纯自由函数，零 [`super::ProxyRuntime`] 状态依赖（L0，`proxy` 依赖拓扑的叶）。7 个符号被
//! `proxy` 外部消费（`speedtest.rs` / `tailscale_login_core.rs` / `updater.rs` / `core_paths.rs` /
//! `geo_seed.rs` / `env_trust.rs` / `commands/misc/dashboard.rs`），façade 必须 `pub(crate) use` 再导出。

use std::path::{Path, PathBuf};

use super::platform_contracts::core_platform_dirs;

/// Linux deb/AppImage 的 FHS 资源目录名 —— 就是 `tauri.conf.json` 的 `productName`，
/// 由 `src-tauri/build.rs::export_product_name` 用 `cargo:rustc-env` 在编译期注入。
///
/// **这里刻意不再存第二份字面量**：两份存在过（本常量 + conf），于是需要
/// `verify-packaging.mjs confs` 拿正则去本文件里抓常量再跟 JSON 对拍 —— 代价是整棵
/// `src-tauri/src/runtime/` 变成打包判据面，且正则硬锚在本文件上（拆分即失锚）。
/// 塌成一份后那道门已删除，仅存的保险是 `injected_product_name_matches_tauri_conf`
/// （对着 conf 逐字核注入值，改 conf 不改注入链即转红）。
pub(super) const LINUX_BUNDLE_PRODUCT_DIR: &str = env!("POLARIS_PRODUCT_NAME");

/// bundled 资源二进制候选路径（sing-box 核 / polaris-helper 共用）。抽纯函数便于**钉 `_up_` 布局回归**。
///
/// 布局兜底顺序：① **`exe/_up_/resources/`（Windows NSIS 装机权威布局）**：tauri-utils 的
/// `resource_relpath` 把 `../` 段改名 `_up_`，NSIS 装机后资源在 `<exe目录>\_up_\resources\`——W10 根因，
/// 漏掉则装机态核/helper 解析双双落空（2026-08-19 真机 toast 首曝）。②
/// **`exe/../Resources/_up_/resources/`（macOS .app 权威布局）**：同一 `_up_` 改名机制在 .app 里
/// 实际落 `Contents/Resources/_up_/resources/`，漏掉则打包态 mac 上核/helper 恒找不到。③
/// **`usr/bin/../lib/Polaris/_up_/resources/`（Linux deb/AppImage 权威布局）**：Tauri 的 Debian/AppImage
/// 数据树把应用资源落在 `/usr/lib/<productName>/`，可执行文件则在 `/usr/bin/`；只从 exe 同级找会得到
/// 「包里明明有核/规则，运行期却全部报未找到」的假坏包。④ exe 同级 `resources/`（portable 权威布局 /
/// NSIS legacy 兜底）。⑤ `exe/../Resources/resources/`（mac legacy 兜底）。④⑤必须排在三条权威布局
/// **之后**：安装升级不会删除旧版遗留目录，反过来会让新 app 静默首选旧 core/helper
/// （2026-08-23 `.207` 真机实证）。⑥ `CARGO_MANIFEST_DIR/../resources/`（开发态）。
///
/// `exe_dir` = `current_exe().parent()`（None=取不到）；`manifest_dir` = `CARGO_MANIFEST_DIR`。
pub(crate) fn bundle_resource_candidates(
    exe_dir: Option<&std::path::Path>,
    dev_manifest_dir: Option<&std::path::Path>,
    platform_dirs: &[&str],
    filename: &str,
) -> Vec<PathBuf> {
    let prefixes = bundle_resource_roots(exe_dir, dev_manifest_dir);

    let mut candidates: Vec<PathBuf> = Vec::new();
    for prefix in &prefixes {
        for pdir in platform_dirs {
            candidates.push(prefix.join(pdir).join(filename));
        }
    }
    candidates
}

/// [`bundle_resource_candidates`] 的**前缀腿**：随包资源目录本身（不含平台子目录与文件名）。
///
/// 抽出来是因为它有第二个消费者：`runtime/env_trust` 的可信来源判据要拿这些目录当 containment
/// 的根。两处各写一份布局的代价是确定的 —— 一边认 `_up_/resources`、另一边漏掉它之后，
/// 「随包核解析得到」与「随包核被判可信」会在同一台机器上给出相反的答案。
pub(crate) fn bundle_resource_roots(
    exe_dir: Option<&std::path::Path>,
    dev_manifest_dir: Option<&std::path::Path>,
) -> Vec<PathBuf> {
    let mut prefixes: Vec<PathBuf> = Vec::new();
    if let Some(dir) = exe_dir {
        // Windows NSIS 装机布局（W10 根因，2026-08-19 真机 toast 首曝）：tauri-utils 的
        // `resource_relpath` 把 `../` 段改名 `_up_`（与 bundler 无关，NSIS 同样生效），装机后资源
        // 在 `<exe目录>\_up_\resources\`——此前候选表只有 mac 的一种 `_up_` 形态（`../Resources/
        // _up_/resources`），Windows 装机态的核 / helper 解析双双落空（helper 安装 toast「未找到
        // polaris-helper 二进制」，核解析同函数同病）。它必须排在裸 `resources/` 前：后者是 portable
        // 权威布局，但在 NSIS 装机态也可能是升级前残件；裸目录先行会把新包静默降级成旧 payload。
        prefixes.push(dir.join("_up_").join("resources"));
        prefixes.push(
            dir.join("..")
                .join("Resources")
                .join("_up_")
                .join("resources"),
        );
        // Linux deb / AppImage 的 Tauri 权威布局：exe 在 `<root>/usr/bin`，资源在
        // `<root>/usr/lib/Polaris/_up_/resources`。只对组件后缀恰为 `usr/bin` 的路径加这条，避免
        // Windows/macOS 的失败文案里混入不属于它们的 FHS 猜测路径。
        if dir.ends_with(Path::new("usr").join("bin")) {
            prefixes.push(
                dir.join("..")
                    .join("lib")
                    .join(LINUX_BUNDLE_PRODUCT_DIR)
                    .join("_up_")
                    .join("resources"),
            );
        }
        prefixes.push(dir.join("resources"));
        prefixes.push(dir.join("..").join("Resources").join("resources"));
    }
    // 开发树候选：**release 里恒不存在**（`dev_manifest_dir()` 返 `None`），见其文档。
    if let Some(manifest_dir) = dev_manifest_dir {
        prefixes.push(manifest_dir.join("..").join("resources"));
    }
    prefixes
}

/// 开发树的 crate 根（`CARGO_MANIFEST_DIR`）。**release 构建里恒为 `None`**。
///
/// # 为什么是 `#[cfg]` 而不是 `cfg!()`
///
/// `cfg!(debug_assertions)` 是**运行期**布尔，两条腿都会被编译 ⇒ `env!("CARGO_MANIFEST_DIR")`
/// 那个字面量照样进 `.rodata`。2026-08-30 对发行产物实测：`strip = "symbols"` 之后仍有
/// **143 处** `/home/sway/Code/polaris` 字样，其中开发者仓库路径正是这么泄出去的
/// （余下来自 `btls-sys` 编译 BoringSSL 时 C 编译器写进去的 `__FILE__`）。
/// `#[cfg]` 是**编译期**分叉，release 那条腿里根本没有这个 `env!`。
///
/// # 它在开发态还有用
///
/// `cargo run` / `cargo test` 时二进制在 `target/debug/`，随包资源并不在 exe 旁边，
/// 只能靠 `<crate 根>/../resources` 找到。测试构建 `debug_assertions` 恒开，故取材面不变。
#[cfg(debug_assertions)]
pub(crate) fn dev_manifest_dir() -> Option<&'static std::path::Path> {
    Some(std::path::Path::new(env!("CARGO_MANIFEST_DIR")))
}

/// [`dev_manifest_dir`] 的 release 腿：没有开发树，也**不留下那个字面量**。
#[cfg(not(debug_assertions))]
pub(crate) fn dev_manifest_dir() -> Option<&'static std::path::Path> {
    None
}

/// 从按权威度排序的 bundled 候选中取第一个真实文件（core / helper 共用同一选择语义）。
pub(crate) fn first_existing_bundle_candidate(candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates.iter().find(|path| path.is_file()).cloned()
}

/// 内核路径的**环境逃生门腿**：[`resolve_core_binary`] 第 1 级与
/// [`UpdaterRuntime::new`](crate::runtime::updater::UpdaterRuntime::new) 的**唯一**共用实现。
///
/// # 为什么必须是一份而不是两份（根因）
///
/// 这条腿此前有两份：本函数所在的解析链一份、`updater.rs` 里 `UpdaterRuntime::new` 一份 ——
/// 后者旁边还写着「完整解析仍归 proxy.rs 单一真值」，而那句话当时并不成立（它自己又读了一次
/// 同一个环境变量）。两份实现意味着给逃生门加信任级时只改一处就会留下另一条仍能把任意二进制
/// 喂给 `Command::new(..).arg("version")` 的腿，且那句注释还会让 review 以为已经覆盖全。
/// 塌成一份之后，「信任级判据」与「稳定错误码」对两个调用方按构造同一。
///
/// 两个调用方的差别只剩**怎么处理 `Err`**（开发态逃生门指向不存在的文件）：起核腿把它冒泡成
/// 失败（不静默回落 PATH），版本探测腿把它当「无探测目标」。这是真实的契约差异，不是重复实现。
///
/// 语义（构型分流 / containment 判据 / 稳定错误码）全在
/// [`crate::runtime::env_trust`]，本函数只负责把名字与信任级绑到一起。
pub(crate) fn core_binary_env_override() -> Result<Option<PathBuf>, String> {
    crate::runtime::env_trust::adopt_trusted_env_path(
        "POLARIS_SINGBOX_PATH",
        // 名字必须以**字面量**留在 `env::var(` 调用处：`release_escape_hatches` 的探测器①靠这个
        // 形态清点发行包里的逃生门，提成常量它就读不出名字了。
        std::env::var("POLARIS_SINGBOX_PATH").ok(),
        crate::runtime::env_trust::TrustScope::AppDataOrBundle,
    )
}

/// 现役核解析（三级优先级）：
///  1. `POLARIS_SINGBOX_PATH` 环境逃生门（[`core_binary_env_override`]）——**开发态**是原样的
///     第一优先级（指向不存在的文件即 Err，不静默回落）；**release** 侧路径须过可信来源判据，
///     不过即记 `ENV_PATH_UNTRUSTED` 并回落第 2/3 级；
///  2. **可写现役核** `<config_dir>/core_update/sing-box[.exe]`（换核/回滚的落位目标，见
///     [`crate::runtime::core_paths`]）——存在即用；
///  3. 随包出厂核（bundle 种子，[`resolve_bundled_core_binary`]）。
///
/// 第 2 级是「可写现役核 + 随包种子」模型的读侧（移植 上游 `ResourceManager.getSingBoxPath`）：
/// 缺失即回落种子 ⇒ **首启/迁移永不 brick**。核基目录未注入时（单测/子进程）第 2 级恒 miss，
/// 行为与接线前逐字一致。
///
/// 找不到 → Err（**不静默回落 PATH**：误起系统里别的 sing-box 比起不来更糟）。
pub(crate) fn resolve_core_binary() -> Result<PathBuf, String> {
    if let Some(core) = core_binary_env_override()? {
        return Ok(core);
    }

    // 可写现役核优先（换核/回滚/reset-factory 全部落位于此）。
    if let Some(p) = crate::runtime::core_paths::writable_core_path() {
        if p.is_file() {
            return Ok(p);
        }
    }

    resolve_bundled_core_binary()
}

/// **随包出厂核**（bundle 种子）：绕过环境逃生门与可写核层，只解析打进安装包的资源。
///
/// 这是 reset-factory / reseed 的**源**——它们要的恰是「出厂那一份」，而非现役核。
pub(crate) fn resolve_bundled_core_binary() -> Result<PathBuf, String> {
    let filename = if cfg!(windows) {
        "sing-box.exe"
    } else {
        "sing-box"
    };
    let platform_dirs = core_platform_dirs(std::env::consts::OS, std::env::consts::ARCH);

    let exe = std::env::current_exe().ok();
    let candidates = bundle_resource_candidates(
        exe.as_deref().and_then(std::path::Path::parent),
        dev_manifest_dir(),
        &platform_dirs,
        filename,
    );
    if let Some(core) = first_existing_bundle_candidate(&candidates) {
        return Ok(core);
    }
    Err(format!(
        "未找到 sing-box 二进制（尝试过：{}）。开发态可设 POLARIS_SINGBOX_PATH，或跑 `node scripts/fetch-core.mjs`。",
        candidates
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(" | ")
    ))
}

/// sing-box 官方面板运行时下载覆盖目录名（`<config_dir>/singbox-dashboard`）。
/// 与 `commands/misc.rs` 的 `SINGBOX_DASHBOARD_DIR` 同名同义：「刷新面板资源」清此目录 → 核下次启动回落随包内置。
const SINGBOX_DASHBOARD_DIR_NAME: &str = "singbox-dashboard";

/// 解析 sing-box 官方面板 `services[].dashboard.path`（对齐 上游 `resolveDashboardServeDir`）。
///
/// 优先级：**运行时下载覆盖**（`<config_dir>/singbox-dashboard` 含 `index.html`）→ **随包内置**
/// （`resources/dashboard/index.html`，`scripts/fetch-dashboard.mjs` 落地、tauri.conf `resources` 打包）→
/// 两者皆无返 `None`。
///
/// `None` 时 config-engine 省略 `path` → 核回落**联网下载**兜底（保「异常打包不 brick」）；该下载会在进程 CWD 下
/// 相对 mkdir `dashboard`，故必须配合起核 `.current_dir(<可写目录>)`（见 spawner `working_dir` / helper spawn）
/// 避免 CWD=`/` 下的只读 mkdir 噪音。命中（有 `path`）时核直接 serve 本地文件、**零联网下载、打开即时离线可用**
/// ——根治噪音的首选路径。
pub(crate) fn resolve_dashboard_serve_dir(config_dir: &std::path::Path) -> Option<String> {
    // 1) 运行时下载覆盖优先。
    let override_dir = config_dir.join(SINGBOX_DASHBOARD_DIR_NAME);
    if override_dir.join("index.html").is_file() {
        return Some(override_dir.to_string_lossy().into_owned());
    }
    // 2) 随包内置 resources/dashboard（非平台特定 → 借 bundle_resource_candidates 以 "dashboard" 作子目录、
    //    "index.html" 作探针；命中即取其父目录 = serve 根）。
    let exe = std::env::current_exe().ok();
    bundle_resource_candidates(
        exe.as_deref().and_then(std::path::Path::parent),
        dev_manifest_dir(),
        &["dashboard"],
        "index.html",
    )
    .iter()
    .find(|c| c.is_file())
    .and_then(|c| c.parent())
    .map(|p| p.to_string_lossy().into_owned())
}
