//! 完全卸载编排（上游 `APP_UNINSTALL_ALL`）：提权 helper / 受保护目录内核 / 用户配置 / 应用本体。
//!
//! # 本模块存在的理由：把「顺序、失败传播、部分成功」从不可测的薄壳里拆出来
//!
//! 卸载这条链上真正会出错的不是某一次 `remove_dir_all`，而是**编排**：谁先谁后、某一步炸了之后
//! 还敢不敢继续删、删了一半怎么如实交代。这些恰恰是最难在真机上验的（真跑一次就把被测的安装
//! 删了），所以全部收在本模块的**纯函数**里：
//!
//! - [`run_uninstall`]：固定因果序 + fail-fast，`UninstallOps` 注入 ⇒ 单测断言顺序与失败传播；
//! - [`stop_core_outcome`] / [`verdict_of`] / [`plan_app_removal`] / [`validate_config_dir`]：纯判定，真值表可穷举；
//! - [`SystemUninstallOps`]：唯一碰真实文件系统与提权通道的**最外层薄壳**，且它自己的两条删除腿
//!   也走「先判定后删除」，判定部分仍是纯函数。
//!
//! # 为什么是这个顺序（每一步都有因果，不是随手排的）
//!
//! | # | 步骤 | 为什么必须在这个位置 |
//! |---|------|---------------------|
//! | 0 | [停核](UninstallStep::StopCore) | 受管核跑着 TUN 时删 helper，核就成了用户态杀不动的 root 孤儿 + 全网断（判据复用 [`decide_uninstall_preflight`](super::helper::decide_uninstall_preflight)） |
//! | 1 | [取消开机自启](UninstallStep::Autostart) | 全链**最便宜、最可逆、零提权**的一步，排最前 ⇒ 失败时一个字节都还没删。放最后则意味着「什么都删完了才发现登录项摘不掉」，而系统此后每次登录都会去拉一个已不存在的可执行文件 |
//! | 2 | [卸 helper](UninstallStep::Helper) | 必须**早于**删用户配置：[`HelperRuntime::uninstall`](crate::runtime::helper::HelperRuntime::uninstall) 把提权脚本写进**配置目录**（`manager.uninstall(&self.dir, …)`）、并从那里读 app 侧 token。先删配置 ⇒ 提权脚本没地方落、token 没得读 ⇒ helper 永远卸不掉 |
//! | 3 | [删用户配置](UninstallStep::UserConfig) | 含**可写内核** `core_update/`、日志 `logs/`、图标缓存 `icons/`、`update-state.json`（受保护目录里那份 root 核由第 2 步的提权脚本删）。放在 helper 之后见上一行 |
//! | 4 | [删更新缓存](UninstallStep::CacheDir) | `app_cache_dir()/updates`（下载的安装包）**在配置目录之外**，删配置带不走 —— 漏掉就是卸载完还剩几百 MB |
//! | 5 | [清 Preferences 域](UninstallStep::Preferences) | macOS `~/Library/Preferences/<identifier>.plist`（[`crate::app_language`] 写的 `AppleLanguages`）**在配置目录之外**。排在这里而不是更早：本进程仍在跑，AppKit 退出前还可能往同一个域写窗口状态等键，越晚清窗口越小（**不能保证零回写**，如实记）。仍在删应用本体之前 —— 那一步之后就没有代码可执行了 |
//! | 6 | [删应用本体](UninstallStep::AppBundle) | 必须**最后**：它是当前正在跑的这个进程的载体。先删它，后面几步就没有代码可执行了 |
//!
//! 「属于 Polaris 的落盘位置」是逐处对过的：`logs/`、`icons/`、`rule-resource/`、`rules/`、
//! `singbox-dashboard/`、`core_update/`、`core-staged/`、`config.json`、`update-state.json`、
//! `helper-client.token` **全在配置目录内**（第 3 步一并带走）；配置目录**之外**只有三处 ——
//! 开机自启登录项（第 1 步）、更新包缓存（第 4 步）、macOS 的应用 Preferences 域（第 5 步），
//! 故它们各占一个独立步骤。
//!
//! # Preferences 域为什么**不能**用 `remove_file`（这一步与其它删除腿形制不同的唯一理由）
//!
//! macOS 的 `~/Library/Preferences/*.plist` 不归进程直接管：`cfprefsd`（Defaults Server）把域
//! 缓存在内存里，绕过它删文件的结果是「删了，然后被守护进程按它的缓存写回来」——
//! 苹果自己的指引与社区实测都是这一条（用 `defaults` / `CFPreferences` / `NSUserDefaults`，
//! 别碰文件）。故本步骤走 [`NSUserDefaults::removePersistentDomainForName`][rm]
//! （= `defaults delete <domain>` 的代码等价形式，与 `crate::app_language::write_apple_languages`
//! 写入时同一条通道），**一次 `remove_file` 都不做** —— 也因此它不走 [`validate_removable`]
//! 那套路径白名单，改用 [`validate_pref_domain`] 守域名。
//!
//! [rm]: https://developer.apple.com/documentation/foundation/nsuserdefaults/removepersistentdomain(forname:)
//!
//! 受保护目录里的 root 内核**没有独立步骤**，因为它没有独立的删除通道：`crates/helper-proto`
//! 里根本不存在「删内核 / 删受保护目录」这个 IPC 动词（只有 `InstallCore`），三平台的清除一律
//! 由 `helper-client` 那把 root 卸载脚本顺手做掉（mac `rm -rf /Library/Application Support/Polaris`、
//! linux `rm -rf /usr/local/lib/polaris` 等、win `Remove-Item -Recurse C:\ProgramData\Polaris`）。
//! 故它作为第 1 步的**子结果**如实呈现（带真实路径），而不是伪造成一个「已删除」的独立条目。

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::runtime::helper::UninstallPreflight;
use crate::runtime::update_install::mac_app_bundle_from_exe;

/// 用户配置目录的**固定叶名**——白名单判定的锚（`<app_config_dir>/polaris`，见 `main.rs::init_base_dir`）。
///
/// 删除腿只认这个叶名：路径不是本进程算出来的那一个（比如被改成了 `$HOME`）就直接拒绝，
/// 而不是「先删了再说」。
pub const CONFIG_DIR_LEAF: &str = "polaris";

/// 更新包缓存子目录的固定叶名（`app_cache_dir()/updates`，见 `commands::update_download`）。
pub const CACHE_UPDATES_LEAF: &str = "updates";

// ────────────────────────────────────────────────────────────────────────────
// 步骤 / 结果 / 报告（前端逐项呈现的契约面）
// ────────────────────────────────────────────────────────────────────────────

/// 完全卸载的四类目标。**声明序 = 因果序**（理由见模块文档的表）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum UninstallStep {
    /// 零提权停掉「经 helper 起的」受管核。
    StopCore,
    /// 取消开机自启注册（OS 级登录项，**在配置目录之外**）。
    Autostart,
    /// 卸载提权 helper —— 其 root 脚本同时清掉受保护目录中的内核。
    Helper,
    /// 删用户配置目录（含订阅 / 规则 / 可写内核 / 日志 / 图标缓存）。
    UserConfig,
    /// 删缓存目录中的更新包（`app_cache_dir()/updates`，**在配置目录之外**）。
    CacheDir,
    /// 清应用的 UserDefaults 域（macOS `~/Library/Preferences/<identifier>.plist`，**在配置目录之外**）。
    Preferences,
    /// 删应用本体（最后一步）。
    AppBundle,
}

impl UninstallStep {
    /// **删除腿**的固定执行序。停核不在内：它是前置条件，不是删除动作。
    ///
    /// # 为什么取消自启排在最前
    ///
    /// 它是全链**最便宜、最可逆、且零提权**的一步：失败时一个字节都还没删，用户重试的代价为零。
    /// 反过来，把它放在最后就意味着「helper 已卸、配置已删、应用已删」之后才发现登录项摘不掉 ——
    /// 而那正是后果最重的一项：系统此后每次登录都会去拉一个**已经不存在的可执行文件**。
    /// 它也必须在删应用本体**之前**：注销登录项要读当前 exe 路径，应用没了就无从注销。
    pub const DELETE_ORDER: [Self; 6] = [
        Self::Autostart,
        Self::Helper,
        Self::UserConfig,
        Self::CacheDir,
        Self::Preferences,
        Self::AppBundle,
    ];

    /// 人话步骤名（写进「因上一步失败而未执行」的理由里，日志/UI 都能对上账）。
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::StopCore => "停止内核",
            Self::Autostart => "取消开机自启",
            Self::Helper => "卸载提权助手",
            Self::UserConfig => "删除用户配置",
            Self::CacheDir => "删除更新缓存",
            Self::Preferences => "清除应用偏好域",
            Self::AppBundle => "删除应用本体",
        }
    }
}

/// 单步结果。**五态而非布尔**——「没做」有三种完全不同的成因，糊成一个 `false` 就等于说谎。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum StepOutcome {
    /// 真做了且成功。`detail` 必须说清**动了哪个路径**。
    Done { detail: String },
    /// 本来就没有可做的（helper 没装 / 配置目录不存在）——不算失败，也不算成功。
    Skipped { detail: String },
    /// 本平台/本安装形态**做不到**。如实标注，绝不冒充 `Done`。
    Unsupported { detail: String },
    /// 试了，失败了。`detail` = 失败原因。
    Failed { detail: String },
    /// **因前一步失败而根本没试**（fail-fast 的证据）。
    NotAttempted { detail: String },
}

impl StepOutcome {
    /// 成功。
    pub fn done(detail: impl Into<String>) -> Self {
        Self::Done {
            detail: detail.into(),
        }
    }
    /// 无事可做。
    pub fn skipped(detail: impl Into<String>) -> Self {
        Self::Skipped {
            detail: detail.into(),
        }
    }
    /// 本平台做不到。
    pub fn unsupported(detail: impl Into<String>) -> Self {
        Self::Unsupported {
            detail: detail.into(),
        }
    }
    /// 失败。
    pub fn failed(detail: impl Into<String>) -> Self {
        Self::Failed {
            detail: detail.into(),
        }
    }

    /// 是否为失败态（**唯一**会触发 fail-fast 的形态）。
    #[must_use]
    pub const fn is_failure(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }
}

/// 一步的完整记录。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StepReport {
    pub step: UninstallStep,
    pub outcome: StepOutcome,
}

/// 整体判定。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum UninstallVerdict {
    /// 每一步要么做成了、要么本就无事可做 —— **只有这一态才算卸载成功**。
    Complete,
    /// 没有失败，但有本平台做不到的步骤（典型：Windows 应用本体）⇒ 需要用户手动补完。
    Incomplete,
    /// 有步骤失败（以及因此未执行的后续步骤）。
    Failed,
}

/// 逐项卸载报告（前端据此逐条渲染，**不是**一句「已卸载」）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UninstallReport {
    pub steps: Vec<StepReport>,
    pub verdict: UninstallVerdict,
    /// 用户配置或应用本体已被真删 ⇒ 当前进程所依赖的东西已经没了，应引导退出。
    pub requires_exit: bool,
}

/// 纯判定：逐项结果 → 整体判定。
///
/// 顺序不可换：`Failed`/`NotAttempted` 压过 `Unsupported`，`Unsupported` 压过全绿。
/// **`Skipped` 不降级** —— helper 本就没装，不该把一次干净的卸载判成「不完整」。
#[must_use]
pub fn verdict_of(steps: &[StepReport]) -> UninstallVerdict {
    if steps.iter().any(|s| {
        matches!(
            s.outcome,
            StepOutcome::Failed { .. } | StepOutcome::NotAttempted { .. }
        )
    }) {
        return UninstallVerdict::Failed;
    }
    if steps
        .iter()
        .any(|s| matches!(s.outcome, StepOutcome::Unsupported { .. }))
    {
        return UninstallVerdict::Incomplete;
    }
    UninstallVerdict::Complete
}

/// 纯判定：删过用户配置或应用本体 ⇒ 该退出了。
#[must_use]
pub fn requires_exit_of(steps: &[StepReport]) -> bool {
    steps.iter().any(|s| {
        matches!(s.step, UninstallStep::UserConfig | UninstallStep::AppBundle)
            && matches!(s.outcome, StepOutcome::Done { .. })
    })
}

// ────────────────────────────────────────────────────────────────────────────
// 停核腿 → 步骤结果
// ────────────────────────────────────────────────────────────────────────────

/// 纯映射：停核前置判定 + 停核结果 → [`StepOutcome`]。
///
/// # 停核失败在「完全卸载」里必须是 `Failed`（与 helper 单卸载**刻意相反**）
///
/// `commands::helper_uninstall` 那条腿停不掉核也**继续卸载**，理由成文在
/// [`uninstall_preflight_stop`](crate::runtime::helper::uninstall_preflight_stop)：卸载是用户要的终态，
/// 中止的话「既没卸成、也没停成」更糟，而且**应用还在**，用户还能再点一次、还能 forceKill。
///
/// 完全卸载没有这个兜底：后面三步会依次删掉 helper、删掉配置、删掉**应用本体**。若此时还有一个
/// root 受管核占着 TUN，终局是「一个用户态杀不动的 root 核 + 没有应用 + 没有配置」——用户的网断了，
/// 而能停它的那个程序刚被自己删掉。故这里停不掉就**一步都不删**，如实报错让用户重试。
#[must_use]
pub fn stop_core_outcome(preflight: UninstallPreflight, stop_error: Option<&str>) -> StepOutcome {
    match preflight {
        UninstallPreflight::ProceedDirectly => StepOutcome::skipped(
            "无需停核：代理未运行，或内核不是经提权助手启动的（不归 helper 管，卸载不会让它变孤儿）",
        ),
        UninstallPreflight::StopCoreFirst => match stop_error {
            None => StepOutcome::done("已零提权停止经提权助手启动的受管内核"),
            Some(e) => StepOutcome::failed(format!(
                "停止受管内核失败（{e}）：完全卸载已中止，一项都未删除 —— \
                 继续删下去会留下一个用户态杀不动的 root 内核占着 TUN，而能停它的应用刚好被删掉"
            )),
        },
    }
}

// ────────────────────────────────────────────────────────────────────────────
// 删除前的路径判定（白名单式，**先判定后删除**）
// ────────────────────────────────────────────────────────────────────────────

/// 目标形态：删目录树还是删单文件。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    Dir,
    File,
}

/// 路径被拒的原因（每一条都对应一个具体的误删场景）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathReject {
    /// 相对路径 —— 会相对当前工作目录解析，删到哪儿全看进程 cwd。
    NotAbsolute,
    /// 叶名不在白名单里 —— 路径已经不是本进程算出来的那一个了。
    LeafMismatch,
    /// 太浅（没有具名父目录）：`/polaris`、`C:\polaris` 这种一删就是半个系统。
    TooShallow,
    /// 目标不存在。
    Missing,
    /// 目标是软链 —— 跟着删会删到链外的任意位置。
    Symlink,
    /// 目标形态不符（要目录给了文件，或反之）。
    KindMismatch,
}

impl PathReject {
    /// 人话原因（进报告，用户看得懂为什么没删）。
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::NotAbsolute => "路径不是绝对路径（会相对进程工作目录解析）",
            Self::LeafMismatch => "路径末段不是 Polaris 自有目录名（白名单不匹配）",
            Self::TooShallow => "路径过浅（没有具名父目录），拒绝删除",
            Self::Missing => "目标不存在",
            Self::Symlink => "目标是软链接（跟随删除会删到链接之外的位置）",
            Self::KindMismatch => "目标形态不符（期望目录/文件不一致）",
        }
    }
}

/// 删除前的白名单式判定。**任一条不满足即拒绝，绝不「先删了再说」**。
///
/// 判据全部来自本进程自己算出来的路径（`app_config_dir` / `current_exe` / `$APPIMAGE`），
/// **没有任何一段来自前端入参**——`app_uninstall_all` 是零参数命令，这是结构性保证而非约定。
///
/// # 变异探针
///
/// 删掉 `is_absolute` 判定 ⇒ `tests::reject_relative_path` 转红；删掉叶名判定 ⇒
/// `tests::reject_leaf_mismatch` 转红；删掉 `parent` 判定 ⇒ `tests::reject_too_shallow` 转红；
/// 把 `symlink_metadata` 换成 `metadata` ⇒ `tests::reject_symlinked_dir` 转红。
fn validate_removable(
    path: &Path,
    leaf_ok: &dyn Fn(&str) -> bool,
    want: TargetKind,
) -> Result<(), PathReject> {
    if !path.is_absolute() {
        return Err(PathReject::NotAbsolute);
    }
    let Some(leaf) = path.file_name().and_then(|s| s.to_str()) else {
        return Err(PathReject::LeafMismatch);
    };
    if !leaf_ok(leaf) {
        return Err(PathReject::LeafMismatch);
    }
    // 必须有**具名**父目录：挡掉 `/polaris`、`C:\polaris` 这类一层路径。
    if path.parent().and_then(Path::file_name).is_none() {
        return Err(PathReject::TooShallow);
    }
    // `symlink_metadata` 而非 `metadata`：后者会跟随软链，于是「是不是目录」问的是**链尾**，
    // 而 `remove_dir_all` 删的是链本身/链尾，两者对不上就是任意位置删除。
    let md = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(PathReject::Missing),
        Err(_) => return Err(PathReject::Missing),
    };
    if md.file_type().is_symlink() {
        return Err(PathReject::Symlink);
    }
    match want {
        TargetKind::Dir if !md.is_dir() => Err(PathReject::KindMismatch),
        TargetKind::File if !md.is_file() => Err(PathReject::KindMismatch),
        _ => Ok(()),
    }
}

/// 用户配置目录判定：叶名必须**恰好**是 [`CONFIG_DIR_LEAF`]。
pub fn validate_config_dir(path: &Path) -> Result<(), PathReject> {
    validate_removable(path, &|leaf| leaf == CONFIG_DIR_LEAF, TargetKind::Dir)
}

/// 更新缓存目录判定：叶名必须**恰好**是 [`CACHE_UPDATES_LEAF`]。
///
/// 只删这一个子目录、**不删整个 `app_cache_dir()`**：那是 OS 给的应用缓存根，Polaris 在其中
/// 唯一的写入点就是 `updates/`（`commands/updater.rs` 的下载腿）。整根删掉等于替 OS 和将来
/// 可能出现的其它写入者做主，收益为零、风险不为零。
pub fn validate_cache_updates_dir(path: &Path) -> Result<(), PathReject> {
    validate_removable(path, &|leaf| leaf == CACHE_UPDATES_LEAF, TargetKind::Dir)
}

// ────────────────────────────────────────────────────────────────────────────
// Preferences 域：域名判定（纯函数；这一步没有路径可判，判的是**域名**）
// ────────────────────────────────────────────────────────────────────────────

/// UserDefaults 域名被拒的原因。每一条都对应一个具体的误清场景。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefDomainReject {
    /// 空 / 全空白 —— 取不到 identifier。传给 `removePersistentDomainForName:` 是未定义行为面。
    Empty,
    /// 命中系统**全局**域。清它等于把用户全系统的偏好（语言、区域、键盘、滚动方向…）一把抹掉，
    /// 而那与 Polaris 毫无关系 —— 这是本判定存在的首要理由。
    Global,
    /// 不是反向 DNS 形态（无 `.`，或含路径分隔符/空白）—— identifier 已经不是本应用那一个了。
    Malformed,
}

impl PrefDomainReject {
    /// 人话原因（进报告，用户看得懂为什么没清）。
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Empty => "应用 identifier 为空，算不出 UserDefaults 域名",
            Self::Global => "该域是系统全局偏好域（清除它会抹掉与 Polaris 无关的全系统设置）",
            Self::Malformed => {
                "域名不是应用 identifier 的反向 DNS 形态（含路径分隔符/空白，或没有点号）"
            }
        }
    }
}

/// 系统全局偏好域的各种写法。`removePersistentDomainForName:` 收到它们会清掉
/// `~/Library/Preferences/.GlobalPreferences.plist` —— 用户全系统的语言/区域/键盘设置。
const GLOBAL_PREF_DOMAINS: [&str; 3] = [
    "NSGlobalDomain",
    ".GlobalPreferences",
    "kCFPreferencesAnyApplication",
];

/// 清 UserDefaults 域之前的白名单式判定。**任一条不满足即拒绝，绝不「先清了再说」**。
///
/// 判据来自 `tauri.conf.json` 的 `identifier`（编译期常量，不是前端入参），与其它删除腿同一条纪律：
/// 判定不看「值从哪来」，只看「值长什么样」——来源哪天变了，这道判定仍在。
///
/// # 变异探针
///
/// 删掉 `GLOBAL_PREF_DOMAINS` 判据 ⇒ `tests::reject_global_pref_domains` 转红；
/// 删掉 `contains('.')` 判据 ⇒ `tests::reject_malformed_pref_domain` 转红。
pub fn validate_pref_domain(identifier: &str) -> Result<(), PrefDomainReject> {
    let id = identifier.trim();
    if id.is_empty() {
        return Err(PrefDomainReject::Empty);
    }
    if GLOBAL_PREF_DOMAINS
        .iter()
        .any(|g| g.eq_ignore_ascii_case(id))
    {
        return Err(PrefDomainReject::Global);
    }
    // 反向 DNS 形态：必须有点号（`polaris` 这种裸名在 defaults 里同样能建域，但它不是本应用的域），
    // 且不得含路径分隔符或空白（那说明拿到的根本不是 identifier）。
    if !id.contains('.')
        || id.starts_with('.')
        || id.contains('/')
        || id.contains('\\')
        || id.chars().any(char::is_whitespace)
    {
        return Err(PrefDomainReject::Malformed);
    }
    Ok(())
}

/// 应用 Preferences 域的落盘路径（macOS 非沙盒形态：`$HOME/Library/Preferences/<identifier>.plist`）。
///
/// **只用于报告文案**：真正的清除走 `removePersistentDomainForName:`（理由见模块文档），
/// 本函数算出来的路径一个字节都不会被删。写成纯函数是为了让它可测 —— 拼错的形态是
/// 「报告里指了个不存在的文件」，用户照着去看会以为没清干净。
#[cfg(any(target_os = "macos", test))]
#[must_use]
pub fn preferences_plist_path(home: &Path, identifier: &str) -> PathBuf {
    home.join("Library")
        .join("Preferences")
        .join(format!("{identifier}.plist"))
}

/// macOS `.app` 包判定：叶名必须以 `.app` 结尾且是真目录。
pub fn validate_app_bundle(path: &Path) -> Result<(), PathReject> {
    validate_removable(path, &|leaf| leaf.ends_with(".app"), TargetKind::Dir)
}

/// Linux AppImage 判定：叶名必须以 `.AppImage` 结尾（忽略大小写）且是真文件。
pub fn validate_appimage(path: &Path) -> Result<(), PathReject> {
    validate_removable(
        path,
        &|leaf| leaf.to_ascii_lowercase().ends_with(".appimage"),
        TargetKind::File,
    )
}

// ────────────────────────────────────────────────────────────────────────────
// 应用本体：三平台可行性判定（纯函数）
// ────────────────────────────────────────────────────────────────────────────

/// 删除应用本体的计划。**`Unsupported` 是一等公民**——做不到就如实说，不假装做了。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppRemoval {
    /// 删整个目录树（macOS `.app` 包）。
    RemoveDir(PathBuf),
    /// 删单个文件（Linux AppImage）。
    RemoveFile(PathBuf),
    /// 拉起系统卸载程序（Windows NSIS `uninstall.exe`）。**这不等于「已删除」**，报告里必须区分。
    LaunchUninstaller(PathBuf),
    /// 本平台/本安装形态做不到，附**用户能照做的**手动路径。
    Unsupported(String),
}

/// 纯判定：当前平台 + 安装形态 ⇒ 应用本体怎么删（或为什么删不了）。
///
/// `exists` 注入（而非直接 `Path::exists`）是为了让 **Windows 腿在 Linux 开发机上可测** ——
/// 否则那条分支只能靠读代码推理，等于没门。
///
/// # 三平台的实情（每条都对应一个真实的系统约束，不是偷懒）
///
/// - **macOS**：`.app` 是自包含目录树，且 Unix 允许删掉正在运行的可执行文件所在的目录
///   （进程持 inode，删的是目录项）⇒ 可行。定位不到 `.app`（开发构建 / 裸二进制）就**不猜路径**，
///   与 `update_install` 里「定位不到 `.app` → 回退手动拖拽」同一条纪律。
/// - **Linux**：只有 AppImage 形态能自删（`$APPIMAGE` 由 AppImage 运行时自己设，删文件不影响
///   已挂载的运行实例）。`/usr` 下的包管理器安装**故意不碰**：绕过 dpkg/rpm 删文件会留下
///   「包数据库说装着、磁盘上没有」的坏态，比不删更糟。
/// - **Windows**：运行中的 `.exe` 被文件系统锁住，**进程不能删自己**。唯一正路是拉起 NSIS
///   `uninstall.exe`（它会等本进程退出再删）。便携版没有 uninstaller ⇒ 只能手动删。
#[must_use]
pub fn plan_app_removal(
    os: &str,
    exe: &Path,
    appimage: Option<&Path>,
    exists: &dyn Fn(&Path) -> bool,
) -> AppRemoval {
    match os {
        "macos" => mac_app_bundle_from_exe(exe).map_or_else(
            || {
                AppRemoval::Unsupported(format!(
                    "当前可执行文件不在 .app 包内（{}）—— 多为开发构建或裸二进制，无法定位应用本体。\
                     不猜路径，请手动删除该文件",
                    exe.display()
                ))
            },
            AppRemoval::RemoveDir,
        ),
        "linux" => {
            if let Some(img) = appimage {
                return AppRemoval::RemoveFile(img.to_path_buf());
            }
            if exe.starts_with("/usr") {
                return AppRemoval::Unsupported(format!(
                    "检测到系统包管理器安装（{}）。绕过 dpkg/rpm 直接删文件会让包数据库与磁盘不一致，\
                     故本步骤不执行 —— 请用 apt/dnf 等包管理器卸载 polaris",
                    exe.display()
                ));
            }
            AppRemoval::Unsupported(format!(
                "无法判定 Linux 安装形态（既非 AppImage，也不在 /usr 下）：{}。\
                 不猜路径，请手动删除该目录",
                exe.display()
            ))
        }
        "windows" => {
            let Some(dir) = exe.parent() else {
                return AppRemoval::Unsupported(format!(
                    "定位不到安装目录（{}），请从「设置 › 应用」卸载 Polaris",
                    exe.display()
                ));
            };
            let uninstaller = dir.join("uninstall.exe");
            if exists(&uninstaller) {
                return AppRemoval::LaunchUninstaller(uninstaller);
            }
            AppRemoval::Unsupported(format!(
                "未找到 NSIS 卸载程序（{}）—— 多为便携版。Windows 上运行中的 .exe 被系统锁住，\
                 进程无法删除自己，请退出 Polaris 后手动删除 {}",
                uninstaller.display(),
                dir.display()
            ))
        }
        other => AppRemoval::Unsupported(format!("平台 {other} 无应用本体删除实现，请手动删除")),
    }
}

/// 执行应用本体删除计划。`spawn` 注入 ⇒ Windows 腿在单测里**不真起进程**也能断言。
///
/// 每条腿都先跑对应的白名单判定再动手（`RemoveDir`/`RemoveFile` 各自的 validate）。
#[must_use]
pub fn execute_app_removal(
    plan: AppRemoval,
    spawn: &dyn Fn(&Path) -> Result<(), String>,
) -> StepOutcome {
    match plan {
        AppRemoval::Unsupported(why) => StepOutcome::unsupported(why),
        AppRemoval::RemoveDir(dir) => match validate_app_bundle(&dir) {
            Err(PathReject::Missing) => {
                StepOutcome::skipped(format!("应用本体已不在原处（{}）", dir.display()))
            }
            Err(r) => StepOutcome::failed(format!("拒绝删除 {}：{}", dir.display(), r.reason())),
            Ok(()) => match std::fs::remove_dir_all(&dir) {
                Ok(()) => StepOutcome::done(format!("已删除应用本体 {}", dir.display())),
                Err(e) => StepOutcome::failed(format!("删除 {} 失败：{e}", dir.display())),
            },
        },
        AppRemoval::RemoveFile(file) => match validate_appimage(&file) {
            Err(PathReject::Missing) => {
                StepOutcome::skipped(format!("应用本体已不在原处（{}）", file.display()))
            }
            Err(r) => StepOutcome::failed(format!("拒绝删除 {}：{}", file.display(), r.reason())),
            Ok(()) => match std::fs::remove_file(&file) {
                Ok(()) => StepOutcome::done(format!("已删除 AppImage {}", file.display())),
                Err(e) => StepOutcome::failed(format!("删除 {} 失败：{e}", file.display())),
            },
        },
        // 措辞刻意是「已启动」而不是「已删除」：这一步交出去的是控制权，不是结果。
        AppRemoval::LaunchUninstaller(p) => match spawn(&p) {
            Ok(()) => StepOutcome::done(format!(
                "已启动 Windows 卸载程序 {} —— 应用本体需在它的窗口中完成卸载（本步骤不代表已删除）",
                p.display()
            )),
            Err(e) => StepOutcome::failed(format!("启动卸载程序 {} 失败：{e}", p.display())),
        },
    }
}

// ────────────────────────────────────────────────────────────────────────────
// 纯编排：固定序 + fail-fast
// ────────────────────────────────────────────────────────────────────────────

/// 三条删除腿的注入面。真实实现见 [`SystemUninstallOps`]；单测注入替身，**一个真实路径都不碰**。
pub trait UninstallOps {
    /// 取消开机自启注册（OS 级登录项）。
    fn disable_autostart(&self) -> StepOutcome;
    /// 卸载提权 helper（其 root 脚本同时清受保护目录中的内核）。
    fn uninstall_helper(&self) -> StepOutcome;
    /// 删用户配置目录。
    fn remove_user_config(&self) -> StepOutcome;
    /// 删更新包缓存目录。
    fn remove_cache_dir(&self) -> StepOutcome;
    /// 清应用的 UserDefaults 域（macOS 才有内容）。
    fn remove_preferences(&self) -> StepOutcome;
    /// 删应用本体。
    fn remove_app(&self) -> StepOutcome;
}

/// **纯编排**：按 [`UninstallStep::DELETE_ORDER`] 依次执行，任一步 `Failed` 即停，
/// 其后各步一律记 `NotAttempted`（带上是谁把它拦下的）。
///
/// # 为什么必须 fail-fast，而不是「尽力删完」
///
/// 每一步失败都会让后一步变得**更危险**，而不只是「少删一样」：
/// - 停核失败还继续 ⇒ root 孤儿核 + 应用被删 = 用户断网且无处补救；
/// - 卸 helper 失败还继续删配置 ⇒ 配置里的 app 侧 token 没了，helper 从此**永远卸不掉**
///   （`HelperManager::uninstall` 要从配置目录读 token、往那里写提权脚本）；
/// - 删配置失败还继续删应用本体 ⇒ 应用没了，残留配置再没有任何 UI 能清。
///
/// 所以「上一步失败就别删下一项」不是保守，是唯一正确的传播方式。
#[must_use]
pub fn run_uninstall(ops: &dyn UninstallOps, stop_core: StepOutcome) -> UninstallReport {
    // 停核腿虽然不是删除动作，但它失败同样要拦下后面所有删除（理由见 `stop_core_outcome` 文档）。
    let mut halted = stop_core.is_failure().then_some(UninstallStep::StopCore);
    let mut steps = vec![StepReport {
        step: UninstallStep::StopCore,
        outcome: stop_core,
    }];

    // 执行序**读 [`UninstallStep::DELETE_ORDER`]**，而不是在这里另排一份。
    //
    // 早先这里是一个自带顺序的 `legs` 数组，`DELETE_ORDER` 只被单测引用 —— 于是那个常量成了
    // 一句没人执行的注释：把它改坏（比如对调 Helper / UserConfig），生产行为纹丝不动，
    // 顺序守卫照样绿（实测如此）。顺序是本模块最要紧的不变式，它必须只有**一个**声明处。
    let dispatch = |step: UninstallStep| -> StepOutcome {
        match step {
            UninstallStep::Autostart => ops.disable_autostart(),
            UninstallStep::Helper => ops.uninstall_helper(),
            UninstallStep::UserConfig => ops.remove_user_config(),
            UninstallStep::CacheDir => ops.remove_cache_dir(),
            UninstallStep::Preferences => ops.remove_preferences(),
            UninstallStep::AppBundle => ops.remove_app(),
            // 停核腿是前置条件，不该出现在删除序列里。真出现说明 `DELETE_ORDER` 被改坏了 ——
            // 记失败并触发 fail-fast，比 panic 掉整条命令好（用户至少拿得到一份如实报告）。
            UninstallStep::StopCore => {
                StepOutcome::failed("内部错误：停核腿不应出现在删除序列中，卸载已中止")
            }
        }
    };

    for step in UninstallStep::DELETE_ORDER {
        let outcome = match halted {
            Some(blocker) => StepOutcome::NotAttempted {
                detail: format!("未执行：「{}」失败后已中止卸载", blocker.label()),
            },
            None => dispatch(step),
        };
        if outcome.is_failure() {
            halted = Some(step);
        }
        steps.push(StepReport { step, outcome });
    }

    UninstallReport {
        verdict: verdict_of(&steps),
        requires_exit: requires_exit_of(&steps),
        steps,
    }
}

// ────────────────────────────────────────────────────────────────────────────
// 最外层薄壳：真实文件系统 + 提权通道
// ────────────────────────────────────────────────────────────────────────────

/// 「卸载提权 helper」这一个能力的窄 trait —— 与 [`HelperStopOps`](crate::runtime::helper::HelperStopOps)
/// 同一套路：单测既起不了真 daemon、也不许弹提权框，没有替身这条腿就完全无法断言。
pub trait HelperUninstallOps {
    /// 本平台是否有提权 helper 实现。
    fn supported(&self) -> bool;
    /// 是否已安装（未装则整步跳过，不该为此白弹一次提权框）。
    fn installed(&self) -> bool;
    /// 真卸载（弹一次提权框）。
    fn uninstall(&self) -> Result<(), String>;
    /// 本平台受保护目录中被一并清掉的内核路径（进报告，让用户知道到底删了哪儿）。
    fn protected_core_dir(&self) -> String;
}

/// 「取消开机自启」这一个能力的窄 trait。
///
/// 生产实现包一层 `tauri_plugin_autostart::AutoLaunchManager`（它要 `AppHandle`，单测构造不出）；
/// 抽出来后这条腿的三态（本就没开 / 摘掉了 / 摘不掉）才能被断言。
pub trait AutostartOps {
    /// 当前是否已注册开机自启。
    fn is_enabled(&self) -> bool;
    /// 注销登录项。
    fn disable(&self) -> Result<(), String>;
}

/// 生产实现：唯一碰真实 FS 与提权通道的地方。判定部分仍全部委给上面的纯函数。
pub struct SystemUninstallOps<'a, H: HelperUninstallOps, A: AutostartOps> {
    /// 提权 helper 面（生产是 `HelperRuntime`）。
    pub helper: &'a H,
    /// 开机自启面（生产是 `AutoLaunchManager` 的薄包装）。
    pub autostart: &'a A,
    /// 目标平台（`std::env::consts::OS`）。
    pub os: &'a str,
    /// 用户配置目录 = `<app_config_dir>/polaris`（由 `AppRuntime` 给，非前端入参）。
    pub config_dir: PathBuf,
    /// 更新包缓存目录 = `<app_cache_dir>/updates`（解析不到为 `None`）。
    pub cache_updates_dir: Option<PathBuf>,
    /// 应用 identifier = UserDefaults 域名（`tauri.conf.json` 的 `identifier`，非前端入参）。
    pub bundle_identifier: String,
    /// 当前可执行文件路径（`current_exe()`；取不到为 `None`）。
    pub exe: Option<PathBuf>,
    /// `$APPIMAGE`（仅 Linux AppImage 形态有值）。
    pub appimage: Option<PathBuf>,
}

/// 清掉应用的 UserDefaults 域（macOS）。
///
/// **走 API 不走文件**：`cfprefsd` 把域缓存在内存里，直接 `remove_file` 会被它按缓存写回来
/// （理由与出处见模块文档）。`removePersistentDomainForName:` 是 `defaults delete <domain>` 的代码
/// 等价形式，由 cfprefsd 自己落盘，故本函数**不返回失败**：它没有可失败的步骤，
/// 而编造一条永不触发的失败分支比没有分支更糟（同 [`crate::app_language::write_apple_languages`]）。
///
/// 清的是**整个域**而不只是 `AppleLanguages` 一个键：域里还会有 AppKit/WebKit 顺手写的窗口状态等键，
/// 它们同样是 Polaris 留下的痕迹；且只删一个键的话 plist 文件本身会留下来。
#[cfg(target_os = "macos")]
fn clear_preferences_domain(identifier: &str) -> StepOutcome {
    use objc2_foundation::{NSString, NSUserDefaults};

    let plist = std::env::var_os("HOME").map(|h| preferences_plist_path(Path::new(&h), identifier));
    // 存在性只用于**如实措辞**，不作为「要不要清」的判据：cfprefsd 的内存态可能尚未落盘，
    // 「文件不在」不等于「域是空的」，据此早退就会把内存里那份留到退出后被写出来。
    let existed = plist.as_deref().is_some_and(Path::exists);
    let at = plist.map_or_else(
        || "$HOME 未设，算不出 plist 路径".to_owned(),
        |p| p.display().to_string(),
    );

    NSUserDefaults::standardUserDefaults()
        .removePersistentDomainForName(&NSString::from_str(identifier));

    StepOutcome::done(if existed {
        format!(
            "已清除应用偏好域 {identifier}（{at}）—— 经 NSUserDefaults 交给 cfprefsd，未直接删 plist"
        )
    } else {
        format!(
            "已清除应用偏好域 {identifier}；清除前 {at} 并不存在（没改过应用内语言即如此）—— \
             仍发一次清除，防 cfprefsd 内存态在退出后被写出来"
        )
    })
}

/// 非 macOS 无此域：`AppleLanguages` 只在 macOS 写（[`crate::app_language`] 的两个入口在别的平台是空函数）。
///
/// 用 `Skipped` 而**不是** `Unsupported`：这里不是「本平台做不到」，是「本平台压根没有这东西」。
/// 判成 `Unsupported` 会让 Linux/Windows 上每一次干净卸载都被 [`verdict_of`] 降级成 `Incomplete`。
#[cfg(not(target_os = "macos"))]
fn clear_preferences_domain(identifier: &str) -> StepOutcome {
    StepOutcome::skipped(format!(
        "本平台没有 UserDefaults 域（{identifier}）：应用内语言只在 macOS 写进 AppleLanguages"
    ))
}

/// 分离式拉起 Windows 卸载程序：**不等它退出**（它要等本进程先退出才能删文件，等它就是死锁）。
fn spawn_uninstaller(path: &Path) -> Result<(), String> {
    std::process::Command::new(path)
        .spawn()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

impl<H: HelperUninstallOps, A: AutostartOps> UninstallOps for SystemUninstallOps<'_, H, A> {
    fn disable_autostart(&self) -> StepOutcome {
        if !self.autostart.is_enabled() {
            return StepOutcome::skipped("未开启开机自启，无需注销");
        }
        match self.autostart.disable() {
            Ok(()) => StepOutcome::done("已注销开机自启登录项"),
            // 这条**必须**是硬失败：留着登录项 = 系统每次登录都去拉一个马上要被删掉的可执行文件。
            Err(e) => StepOutcome::failed(format!(
                "注销开机自启失败（{e}）：卸载已中止 —— 若继续删下去，系统每次登录都会尝试启动\
                 一个已不存在的 Polaris"
            )),
        }
    }

    fn remove_cache_dir(&self) -> StepOutcome {
        let Some(dir) = self.cache_updates_dir.as_deref() else {
            return StepOutcome::skipped("解析不到应用缓存目录，无更新包可清");
        };
        match validate_cache_updates_dir(dir) {
            Err(PathReject::Missing) => {
                StepOutcome::skipped(format!("更新包缓存目录不存在（{}）", dir.display()))
            }
            Err(r) => StepOutcome::failed(format!("拒绝删除 {}：{}", dir.display(), r.reason())),
            Ok(()) => match std::fs::remove_dir_all(dir) {
                Ok(()) => StepOutcome::done(format!("已删除更新包缓存 {}", dir.display())),
                Err(e) => StepOutcome::failed(format!("删除 {} 失败：{e}", dir.display())),
            },
        }
    }

    fn remove_preferences(&self) -> StepOutcome {
        let id = self.bundle_identifier.trim();
        // 先判定后清除（同其它删除腿）：域名一旦不是本应用那一个，最坏结果是抹掉用户全系统的偏好。
        if let Err(r) = validate_pref_domain(id) {
            return StepOutcome::failed(format!(
                "拒绝清除 UserDefaults 域「{id}」：{}",
                r.reason()
            ));
        }
        clear_preferences_domain(id)
    }

    fn uninstall_helper(&self) -> StepOutcome {
        if !self.helper.supported() {
            return StepOutcome::unsupported("当前平台没有提权助手实现");
        }
        if !self.helper.installed() {
            return StepOutcome::skipped(
                "提权助手未安装，无需卸载（受保护目录中也不会有受管内核）",
            );
        }
        match self.helper.uninstall() {
            Ok(()) => StepOutcome::done(format!(
                "已卸载提权助手，并一并清除受保护目录中的内核（{}）",
                self.helper.protected_core_dir()
            )),
            Err(e) => StepOutcome::failed(e),
        }
    }

    fn remove_user_config(&self) -> StepOutcome {
        let dir = &self.config_dir;
        match validate_config_dir(dir) {
            Err(PathReject::Missing) => {
                StepOutcome::skipped(format!("用户配置目录不存在（{}）", dir.display()))
            }
            Err(r) => StepOutcome::failed(format!("拒绝删除 {}：{}", dir.display(), r.reason())),
            Ok(()) => match std::fs::remove_dir_all(dir) {
                Ok(()) => StepOutcome::done(format!(
                    "已删除用户配置目录 {}（config.json / 订阅 / 规则 / 可写内核 core_update）",
                    dir.display()
                )),
                Err(e) => StepOutcome::failed(format!("删除 {} 失败：{e}", dir.display())),
            },
        }
    }

    fn remove_app(&self) -> StepOutcome {
        let Some(exe) = self.exe.as_deref() else {
            return StepOutcome::unsupported(
                "取不到当前可执行文件路径（current_exe 失败）—— 无法定位应用本体，请手动删除",
            );
        };
        let plan = plan_app_removal(self.os, exe, self.appimage.as_deref(), &|p| p.exists());
        execute_app_removal(plan, &spawn_uninstaller)
    }
}

#[cfg(test)]
mod tests;
