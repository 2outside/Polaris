//! GitHub release JSON → 更新检查结果的**纯逻辑**转换 + 平台/架构资产选择 + 更新源常量。
//!
//! ## 移植来源（上游 TS → Rust 纯逻辑，逐字保留行为）
//!
//! - `UpdateService.fetchReleases`（`UpdateService.ts:843`）+ `UpdateService.checkForUpdate`
//!   （`:146-240`）：拉 `api.github.com/repos/{owner}/{repo}/releases` → 过滤 prerelease → 按
//!   `published_at` 降序取最新 → 去 `v` 前缀 → `compareSemver` 判新 → `findSuitableAsset` 挑平台包
//!   → 组装 `UpdateInfo`。本模块把**除网络获取以外**的全部逻辑抽成纯函数 [`check_app_update`]
//!   （吃已拉回的 JSON 字节，宿主注入 HTTP），可 mock 单测。
//! - `update-asset.findSuitableUpdateAsset`（`update-asset.ts`，52 行）：App 安装包资产选择
//!   （每平台 loose/installed 双形态消歧，#72）→ [`find_suitable_update_asset`]。
//! - `singbox-asset.findSuitableSingboxAsset`（`singbox-asset.ts`，62 行）：内核资产选择
//!   （平台/架构关键词 + with-naive/full 优先）→ [`find_suitable_singbox_asset`]。
//! - 更新源仓库常量（上游 `UpdateService.ts:43-44` `GITHUB_OWNER/GITHUB_REPO`；
//!   `core-downloader.ts:69` `SagerNet/sing-box`）→ [`APP_UPDATE_REPO`] / [`CORE_UPDATE_REPO`]。
//!
//! ## 为什么平台/架构是**参数**而非读 `process`
//!
//! 与 上游的 `findSuitable*` 同纪律：平台/架构由调用方注入（上游 传 `process.platform/arch`，
//! 本仓宿主传 `std::env::consts::OS/ARCH` 经 [`AssetPlatform::from_os`] / [`AssetArch::from_arch`]
//! 映射）。如此本函数**不读全局态**，可用平台真值表全覆盖单测。这也是 `manifest.rs` 早先
//! `AssetSelector` trait 的意图落地版——具体规则移进本模块（纯函数，参数注入），不再需要宿主注入 trait。

use serde::{Deserialize, Serialize};

use crate::manifest::ManifestError;
use crate::version::compare_semver;

// ── 更新源仓库常量（单点定义，宿主不得自造第二份）────────────────────────────────

/// App 自更新源仓库 `(owner, repo)`（= 上游 `GITHUB_OWNER/GITHUB_REPO` 的 Polaris 对应）。
pub const APP_UPDATE_REPO: (&str, &str) = ("2outside", "Polaris");

/// 内核（sing-box）更新源仓库 `(owner, repo)`（= 上游 `core-downloader.ts` 的 `SagerNet/sing-box`）。
pub const CORE_UPDATE_REPO: (&str, &str) = ("SagerNet", "sing-box");

/// Windows 便携版 release 资产的文件名前缀（完整形态 `polaris-portable-<label>.zip`）。
///
/// **跨文件命名契约的单点定义**，三处必须一致，改一处就要改全部：
///  1. 产出侧 `.github/workflows/package.yml` 的 `Build Windows portable zip` 步；
///  2. 选包侧 [`find_suitable_update_asset`] 的 Windows loose 分支（本模块）；
///  3. 断言侧 `scripts/verify-packaging.mjs` 的 `updaterPortableCandidates`。
///
/// 大小写敏感：`package.yml` 产的是字面小写名，三侧同口径才守得住真正会被选中的那个资产。
pub const PORTABLE_ZIP_PREFIX: &str = "polaris-portable-";

/// 构造 GitHub releases API URL（= 上游 `https://api.github.com/repos/${owner}/${repo}/releases`）。
#[must_use]
pub fn github_releases_api_url(owner: &str, repo: &str) -> String {
    format!("https://api.github.com/repos/{owner}/{repo}/releases")
}

// ── 目标平台 / 架构（对齐 NodeJS.Platform / process.arch 的分支面）──────────────────

/// 目标平台（对齐 上游 `process.platform` 的三分支 `win32`/`darwin`/`linux`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetPlatform {
    Windows,
    Macos,
    Linux,
}

/// 目标架构（对齐 上游 `process.arch` 关心的 `x64`/`arm64`；其余归 [`Other`](AssetArch::Other)）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetArch {
    X64,
    Arm64,
    Other,
}

impl AssetPlatform {
    /// 从 `std::env::consts::OS` 映射（宿主注入真实平台）。`None` = 非三大目标平台（无适配包）。
    #[must_use]
    pub fn from_os(os: &str) -> Option<Self> {
        match os {
            "windows" => Some(Self::Windows),
            "macos" => Some(Self::Macos),
            "linux" => Some(Self::Linux),
            _ => None,
        }
    }
}

impl AssetArch {
    /// 从 `std::env::consts::ARCH` 映射（`x86_64` → X64、`aarch64` → Arm64，其余 → Other）。
    #[must_use]
    pub fn from_arch(arch: &str) -> Self {
        match arch {
            "x86_64" => Self::X64,
            "aarch64" => Self::Arm64,
            _ => Self::Other,
        }
    }
}

// ── GitHub release JSON 形状（只取本模块需要的字段）───────────────────────────────

/// GitHub release 资产（`assets[]` 元素）。
#[derive(Debug, Clone, Deserialize)]
pub struct GithubAsset {
    /// 资产文件名（平台/架构/形态的判据来源）。
    pub name: String,
    /// 直下 URL（= 上游 `asset.browser_download_url`）。
    #[serde(rename = "browser_download_url", default)]
    pub browser_download_url: String,
    /// 字节大小（= 上游 `asset.size`；缺失按 0）。
    #[serde(default)]
    pub size: u64,
    /// GitHub 给出的内容摘要，形如 `sha256:ab12…`（较新的 REST API 字段；旧 release 可能缺失）。
    ///
    /// **供应链增强（上游 没有这一层）**：下载件按它做 sha256 强校验，补上「HTTPS 只保传输、
    /// 镜像回退把信任面扩到 gh-proxy 运营方」的洞。信任根仍是 GitHub（摘要与资产同源），
    /// 故**不需要自建密钥**——防的是截断/镜像投毒，不是防 GitHub 本身。
    /// 缺失时回落 Content-Length 完整性校验（= 上游 基线），**不因缺摘要就拒绝更新**。
    #[serde(default)]
    pub digest: Option<String>,
}

/// GitHub release（`/releases` 数组元素）。
#[derive(Debug, Clone, Deserialize)]
pub struct GithubRelease {
    /// 版本 tag（如 `v0.2.0`；= 上游 `tag_name`）。
    pub tag_name: String,
    /// release 标题（= 上游 `name`；缺省回落 tag）。
    #[serde(default)]
    pub name: Option<String>,
    /// 发布说明正文（= 上游 `body`）。
    #[serde(default)]
    pub body: Option<String>,
    /// 是否预览版（= 上游 `prerelease`）。
    #[serde(default)]
    pub prerelease: bool,
    /// 发布时间（RFC3339 UTC，如 `2024-05-01T12:00:00Z`；= 上游 `published_at`）。
    #[serde(default)]
    pub published_at: Option<String>,
    /// release 资产列表（= 上游 `assets`）。
    #[serde(default)]
    pub assets: Vec<GithubAsset>,
}

// ── App 自更新检查结果（移植 UpdateService 的 UpdateInfo / UpdateCheckResult）──────────

/// App 更新信息（= 上游 `UpdateInfo`；字段名 camelCase，与 `ui` 的 `UpdateInfo` 契约逐字对齐）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppUpdateInfo {
    /// 原始 tag（**含 `v`**，= 上游 `UpdateInfo.version = latestRelease.tag_name`）。
    pub version: String,
    /// 标题（= 上游 `name || tag_name`）。
    pub title: String,
    /// 发布说明（= 上游 `body || ''`）。
    pub release_notes: String,
    /// 下载 URL（选中资产的 `browser_download_url`）。
    pub download_url: String,
    /// 文件大小（选中资产的 `size`）。
    pub file_size: u64,
    /// 发布时间。
    pub published_at: String,
    /// 是否预览版。
    pub is_prerelease: bool,
    /// 资产文件名。
    pub file_name: String,
    /// 选中资产的期望 sha256（由 GitHub `digest` 字段解析；旧 release 无该字段 → `None`）。
    ///
    /// 下载侧据此做强校验（**上游 没有这一层**）。`None` 时回落 Content-Length 完整性校验，
    /// **不因缺摘要就拒绝更新**——否则所有旧 release 都会更新不了。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// App 更新检查结论。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppUpdateCheck {
    /// 无可用更新（已最新 / 无正式版 / 已跳过此版本 / 无适配平台资产）。
    NoUpdate,
    /// 有可用更新。
    Available(AppUpdateInfo),
}

/// GitHub release asset 的 `digest` 字段 → 裸 sha256 hex（**纯函数**）。
///
/// GitHub 返回形如 `sha256:ab12…`。非 sha256 算法（未来若加 blake3 之类）一律返 `None`
/// —— **绝不把不认识的摘要当 sha256 喂进 [`verify_bytes`](crate::verify::verify_bytes)**：
/// 那会必然 mismatch，把「本地不支持该摘要算法」伪装成「下载件被篡改」，成因错位。
#[must_use]
pub fn parse_asset_digest(digest: &str) -> Option<String> {
    let hex = digest.trim().strip_prefix("sha256:")?;
    if hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(hex.to_ascii_lowercase())
    } else {
        None
    }
}

/// 去 tag 的前导 `v`（= 上游 `tag_name.replace(/^v/, '')`——仅小写 `v`，仅前导一处）。
///
/// `pub` 不是给外部自由用：[`check_app_update`] 拿它算比较侧（`strip_v(tag)`），而「跳过此版本」
/// 的**存储侧**必须用同一个函数归一化（W8）——两侧各自实现一份就是「v0.2.0 存进去、0.2.0 比
/// 出来，永不相等」的原发病理。导出它是为了让写点复用同一真值。
pub fn strip_v(tag: &str) -> &str {
    tag.strip_prefix('v').unwrap_or(tag)
}

/// 挑更新目标 release：过滤 prerelease 后按 `published_at` **降序取最新**
/// （= 上游 `validReleases.sort((a,b) => dateB - dateA)[0]`）。
///
/// `published_at` 为 RFC3339 UTC（固定宽度、恒带 `Z`），字典序 == 时间序，故直接比字符串等价于
/// 上游的 `new Date(...).getTime()` 比较，且零依赖、无需日期解析。缺失 `published_at`（草稿等）
/// 按空串处理（排到最旧，仅当它是唯一候选才被选中——对齐 上游 `new Date(null)=epoch0` 沉底）。
fn select_update_release(
    releases: &[GithubRelease],
    include_prerelease: bool,
) -> Option<&GithubRelease> {
    releases
        .iter()
        .filter(|r| include_prerelease || !r.prerelease)
        .max_by(|a, b| {
            a.published_at
                .as_deref()
                .unwrap_or("")
                .cmp(b.published_at.as_deref().unwrap_or(""))
        })
}

/// 检查 App 更新（移植 `UpdateService.checkForUpdate` 的纯逻辑部分）。
///
/// 步骤（逐字对齐 `UpdateService.ts:151-212`）：
///  1. 解析 releases JSON（网络获取由宿主注入，本函数只吃已拉回的字节 → 纯逻辑可单测）。
///  2. 过滤 prerelease + 按 `published_at` 降序取最新（`select_update_release`）。
///  3. 去 `v` 前缀 → `compare_semver > 0` 判新（空/不可解析按**无更新**处理，失败安全）。
///  4. 命中用户「跳过此版本」→ 无更新。
///  5. [`find_suitable_update_asset`] 挑平台/架构/形态资产；无适配 → 无更新。
///  6. 组装 [`AppUpdateInfo`]（`version` 保留原始 tag，对齐 上游）。
///
/// # Errors
///
/// - [`ManifestError::ParseJson`]：releases JSON 解析失败（= 上游 `解析 GitHub API 响应失败`）。
pub fn check_app_update(
    releases_json: &str,
    current_version: &str,
    include_prerelease: bool,
    skipped_version: Option<&str>,
    platform: AssetPlatform,
    arch: AssetArch,
    loose_form: bool,
) -> Result<AppUpdateCheck, ManifestError> {
    let releases: Vec<GithubRelease> =
        serde_json::from_str(releases_json).map_err(|e| ManifestError::ParseJson(e.to_string()))?;

    let Some(release) = select_update_release(&releases, include_prerelease) else {
        // 无（正式）发布版本（= 上游 `未找到发布版本`）。
        return Ok(AppUpdateCheck::NoUpdate);
    };

    let latest_version = strip_v(&release.tag_name);

    // 必须比 current 新（compare_semver 对空串/不可解析报错 → 失败安全按无更新，绝不误报有更新）。
    let is_newer = compare_semver(latest_version, current_version)
        .map(|ord| ord > 0)
        .unwrap_or(false);
    if !is_newer {
        return Ok(AppUpdateCheck::NoUpdate);
    }

    // 用户已跳过此版本（= 上游 `if (this.skippedVersion === latestVersion)`）。
    if skipped_version == Some(latest_version) {
        return Ok(AppUpdateCheck::NoUpdate);
    }

    Ok(app_update_info_for_release(
        release, platform, arch, loose_form,
    ))
}

/// 解析所选通道的最新 release，并且仅在它与当前安装版本**完全相同**时返回安装清单。
///
/// 这是设置页“重新下载当前版本”的解析腿：下载、摘要校验与安装仍复用既有命令；这里仅放宽
/// “必须更高版本”这一道发现策略。比当前版本旧或新都返回 [`AppUpdateCheck::NoUpdate`]，因此不会
/// 借“重新安装”之名静默降级，也不会把真正的新版本伪装成同版本重装。
pub fn resolve_current_app_release(
    releases_json: &str,
    current_version: &str,
    include_prerelease: bool,
    platform: AssetPlatform,
    arch: AssetArch,
    loose_form: bool,
) -> Result<AppUpdateCheck, ManifestError> {
    let releases: Vec<GithubRelease> =
        serde_json::from_str(releases_json).map_err(|e| ManifestError::ParseJson(e.to_string()))?;

    let Some(release) = select_update_release(&releases, include_prerelease) else {
        return Ok(AppUpdateCheck::NoUpdate);
    };
    let is_current = compare_semver(strip_v(&release.tag_name), current_version)
        .map(|ord| ord == 0)
        .unwrap_or(false);
    if !is_current {
        return Ok(AppUpdateCheck::NoUpdate);
    }

    Ok(app_update_info_for_release(
        release, platform, arch, loose_form,
    ))
}

fn app_update_info_for_release(
    release: &GithubRelease,
    platform: AssetPlatform,
    arch: AssetArch,
    loose_form: bool,
) -> AppUpdateCheck {
    let Some(asset) = find_suitable_update_asset(&release.assets, platform, arch, loose_form)
    else {
        // 无适配当前平台的安装包（= 上游 `未找到适合当前平台的安装包`）。
        return AppUpdateCheck::NoUpdate;
    };

    AppUpdateCheck::Available(AppUpdateInfo {
        version: release.tag_name.clone(),
        title: release
            .name
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| release.tag_name.clone()),
        release_notes: release.body.clone().unwrap_or_default(),
        download_url: asset.browser_download_url.clone(),
        file_size: asset.size,
        published_at: release.published_at.clone().unwrap_or_default(),
        is_prerelease: release.prerelease,
        file_name: asset.name.clone(),
        sha256: asset.digest.as_deref().and_then(parse_asset_digest),
    })
}

// ── App 安装包资产选择（移植 update-asset.findSuitableUpdateAsset，逐字保留）──────────

/// 从 release 资产里挑适配 `(platform, arch, loose_form)` 的 **App 安装包**。
///
/// 移植自 `update-asset.findSuitableUpdateAsset`（#72：每平台 loose/installed 双形态须按**当前运行
/// 形态**选对应包，否则错配——便携被发 NSIS setup 会装出多余副本）：
///  - Windows：**两条互不相交的规则**（见下）——loose→`polaris-portable-*.zip`（无则 `None`）/
///    installed→`.exe` 且名含 `win`（setup → 非 portable → 首个）。
///  - macOS：按架构 `mac-arm64`/`mac-x64` 的 `.dmg`；**无则 `None`，不回落任意 `.dmg`**
///    （分架构单出后回落 = 发错架构包，见 macOS 分支注释；`.app` 恒 loose，不分形态）。
///  - Linux：loose→`.AppImage`（无则 `.deb`）/ installed→`.deb`（无则 `.AppImage`）。
///
/// ## Windows 为什么按形态分成两条**独立**规则（2026-07-22 修 #72 形态错配本体）
///
/// 本仓 Windows 的两件交付物分属**两个不相交的命名空间**（核对于 `package.yml` 的实际产物名）：
///
/// | 形态 | 产物 | 谁选它 |
/// |---|---|---|
/// | installed | `*-win-setup.exe`（NSIS downloadBootstrapper） | `.exe` 且名含 `win` |
/// | loose | `polaris-portable-*.zip`（`Compress-Archive` 打的免安装 zip） | `polaris-portable-` 前缀 + `.zip` |
///
/// 便携产物是 **zip**，结构性进不了「`.exe` 且名含 `win`」这道过滤。此前 loose 分支与 installed
/// 分支**共用**那个候选集，于是 `find(is_portable)` 空 → `find(!is_setup)` 空 → `first()`
/// **无条件命中 NSIS setup**：便携用户被发安装器，装出与便携副本并存的第二份程序
/// （配置目录 / 自启项 / 内核资源各一套）—— 正是本函数头部自称要防的 #72 形态错配本体。
///
/// 现改为 loose 走自己的规则，且**无回落**：选不到即 `None`（= 无更新）。理由与 macOS 那条同源
/// ——**宁可不更新，也不发错形态包**。回落到安装器不是「降级但可用」，而是制造第二份安装。
///
/// 两条规则的判据不相交（`.zip` vs `.exe`），故各自无歧义，`.exe && contains("win")`
/// 这条命名契约**一字未动**。
///
/// ## 为什么 Windows / Linux 的 installed 侧仍保留回落（别按对称性「顺手修」）
///
/// macOS 取消回落跨的是**架构**：release 缺一份 dmg 时把 arm64 包发给 Intel 用户 = 装了也跑不起来。
/// Windows / Linux 在本仓 CI matrix 里各只有**一个** target（`x86_64-pc-windows-msvc` /
/// `x86_64-unknown-linux-gnu`），资产名里根本没有架构判别位 ⇒ 回落绝不会发错架构。
/// 将来 Windows/Linux 真出 arm64 包时，本结论失效，须回来按 macOS 同法处理。
///
/// Linux 的 loose↔installed 回落**保留**：`.deb` 与 `.AppImage` 同 release 都在（`package.yml` 的
/// assets 断言机守着两者皆存），两者都是**单文件安装件**、下游 `decide_install_plan` 认得，
/// 回落跨形态是降级但可用，正是 #72 要保的 上游 行为。Windows 的 zip↔exe 不同：zip 不是安装件，
/// 反向回落（安装态拿 zip）无意义，正向回落（便携拿 exe）就是缺陷本身，故两侧都不回落。
///
/// ## 便携更新的下游：**交系统，不自动替换**（如实登记，别读成全自动）
///
/// 选中的 `.zip` 走到 `runtime::update_install::classify_installer` 时**不被识别**
/// （它只认 `.exe/.dmg/.appimage/.deb`）⇒ `InstallReject::UnknownAsset` ⇒ command 层回退
/// `shell.open` 打开该 zip，由用户自行解压覆盖。这是**有意的诚实降级**：便携用户拿到的是
/// 正确形态的产物，且绝不会有 NSIS 在背后装出第二份。自动解压替换需引 zip 解压依赖，未做。
#[must_use]
pub fn find_suitable_update_asset(
    assets: &[GithubAsset],
    platform: AssetPlatform,
    arch: AssetArch,
    loose_form: bool,
) -> Option<&GithubAsset> {
    match platform {
        AssetPlatform::Windows => {
            if loose_form {
                // 便携(loose)：**独立规则、无回落**。判据与 `verify-packaging.mjs` 的
                // `updaterPortableCandidates` 逐字同口径（大小写敏感，同 `package.yml` 里
                // `polaris-portable-${BUILD_LABEL}.zip` 的字面产物名）——两侧判据一旦不一致，
                // 那道断言守的就不是选包器真正会选的东西。
                return assets
                    .iter()
                    .find(|a| a.name.starts_with(PORTABLE_ZIP_PREFIX) && a.name.ends_with(".zip"));
            }
            // 安装态口径：`.exe` 且名含 'win'（大小写敏感，与 上游 一致）。
            let win_exe: Vec<&GithubAsset> = assets
                .iter()
                .filter(|a| a.name.ends_with(".exe") && a.name.contains("win"))
                .collect();
            if win_exe.is_empty() {
                return None;
            }
            let is_portable = |a: &GithubAsset| a.name.to_lowercase().contains("portable");
            let is_setup = |a: &GithubAsset| a.name.to_lowercase().contains("setup");
            // 安装(NSIS)：setup → 非 portable → 首个。
            win_exe
                .iter()
                .copied()
                .find(|a| is_setup(a))
                .or_else(|| win_exe.iter().copied().find(|a| !is_portable(a)))
                .or_else(|| win_exe.first().copied())
        }
        AssetPlatform::Macos => {
            let arch_pattern = if arch == AssetArch::Arm64 {
                "mac-arm64"
            } else {
                "mac-x64"
            };
            // **无回落**（2026-07-21 用户裁定）：分架构单出后，「任意 .dmg」回落会在 release 缺
            // 一份（某个 mac job 挂掉）时把另一架构的包发给用户 —— arm64 包在 Intel 上根本执行
            // 不了，x64 包在 Apple Silicon 上走 Rosetta 且内核错配。宁可不更新，也不发错架构。
            // 返回 None ⇒ check_app_update 走 AppUpdateCheck::NoUpdate（= 上游「未找到适合当前
            // 平台的安装包」），不是报错。
            assets
                .iter()
                .find(|a| a.name.contains(arch_pattern) && a.name.ends_with(".dmg"))
        }
        AssetPlatform::Linux => {
            let app_image: Vec<&GithubAsset> = assets
                .iter()
                .filter(|a| a.name.ends_with(".AppImage"))
                .collect();
            let deb: Vec<&GithubAsset> =
                assets.iter().filter(|a| a.name.ends_with(".deb")).collect();
            if loose_form {
                // AppImage(loose)：AppImage → .deb。
                app_image.first().copied().or_else(|| deb.first().copied())
            } else {
                // deb 安装：.deb → AppImage。
                deb.first().copied().or_else(|| app_image.first().copied())
            }
        }
    }
}

// ── 内核资产选择（移植 singbox-asset.findSuitableSingboxAsset，逐字保留）──────────────

/// 从 release 资产里挑适配 `(platform, arch)` 的 **sing-box 内核**构建。
///
/// 移植自 `singbox-asset.findSuitableSingboxAsset`：
///  1. 平台关键词（windows/darwin/linux）+ 架构关键词（amd64/arm64）+ 后缀（平台默认 ext 或 `.zip`）过滤；
///  2. 命中集合内按优先级取：① 含 `with-naive`/`full`（带 naive 出站）② 非 `legacy` ③ 首个命中。
///
/// 架构为 [`Other`](AssetArch::Other) 时架构关键词为空串（`contains("")` 恒真，= 上游 `archKeyword=''`
/// 时 `.includes('')` 恒真），即不按架构过滤。无任何命中返回 `None`。
#[must_use]
pub fn find_suitable_singbox_asset(
    assets: &[GithubAsset],
    platform: AssetPlatform,
    arch: AssetArch,
) -> Option<&GithubAsset> {
    let (keyword, ext) = match platform {
        AssetPlatform::Windows => ("windows", ".zip"),
        AssetPlatform::Macos => ("darwin", ".tar.gz"),
        AssetPlatform::Linux => ("linux", ".tar.gz"),
    };
    let arch_keyword = match arch {
        AssetArch::X64 => "amd64",
        AssetArch::Arm64 => "arm64",
        AssetArch::Other => "",
    };

    let filtered: Vec<&GithubAsset> = assets
        .iter()
        .filter(|a| {
            let lower = a.name.to_lowercase();
            lower.contains(keyword)
                && lower.contains(arch_keyword)
                && (a.name.ends_with(ext) || a.name.ends_with(".zip"))
        })
        .collect();
    if filtered.is_empty() {
        return None;
    }

    // 1. with-naive / full 优先。
    if let Some(a) = filtered.iter().copied().find(|a| {
        let lower = a.name.to_lowercase();
        lower.contains("with-naive") || lower.contains("full")
    }) {
        return Some(a);
    }
    // 2. 非 legacy。
    if let Some(a) = filtered
        .iter()
        .copied()
        .find(|a| !a.name.to_lowercase().contains("legacy"))
    {
        return Some(a);
    }
    // 3. 首个命中。
    filtered.first().copied()
}

#[cfg(test)]
mod tests;
