//! Rust 侧**用户可见文案**的 i18n —— 原生文件对话框、Linux 托盘原生菜单 / 托盘 tooltip、
//! 提权引导消息框、应用菜单（⌘Q）、系统通知。
//!
//! ══ 补的是什么缺口 ══
//!
//! 产品出 5 语种（`ui/src/domain/language.ts` 的 `SUPPORTED_LANGUAGES`），前端有 i18next +
//! 5 份 locale JSON，**Rust 侧一个字都没有**：文件对话框标题 / 过滤器名、提权引导消息框
//! （标题 / 正文 / 按钮）、应用菜单的「退出 Polaris」一律硬编码中文；托盘原生菜单与 tooltip
//! 稍好一档，但只有 zh/en **二态**（旧 `TrayLang`）。于是俄语用户看到的是俄语按钮 + 中文标题
//! （macOS `AppleLanguages` 对账让 `NSOpenPanel` 的按钮/边栏跟随了语言，标题却是我们自己传的）。
//! Linux 上更要紧：AppIndicator 不递送可靠点击事件时，**原生菜单是主交互面**。
//!
//! ══ 为什么必须有 Rust 侧体系（而不是「前端把译好的文案当参数传下来」）══
//!
//! 「前端传参」对**由前端 invoke 发起**的那几个对话框确实成立（导出备份 / 导入订阅 / 选内核
//! 都是 `#[tauri::command]`，全仓无 Rust 内部调用方）。但它对下面两类**结构性覆盖不到**：
//!
//!  1. **托盘原生菜单 / tooltip**：菜单在 Rust 侧由 `build_tray_menu` 构建，由
//!     `reconcile_tray_menu` 的 30s 自愈轮询驱动，**没有任何前端调用方**；
//!  2. **提权引导消息框**（`runtime/proxy.rs::prompt_helper_gate`）：它挂在
//!     `run_helper_gate` ← `start_inner` ← `ProxyRuntime::start`，而起核的发起方包含
//!     `runtime/startup_tasks.rs::spawn_auto_connect`（启动 2s 后**Rust 自己**调
//!     `commands::proxy_start`）与托盘原生菜单的 `tray_toggle` —— 两条都没有前端在场，
//!     前端手上那份 i18next 递不进来。
//!
//! 两类都要弹给用户看，故 Rust 侧的文案表**无法回避**。既然它无论如何要存在，剩下的
//! 5 个前端发起的对话框也走它 —— 反过来给 5 个 command 加 title/filter 参数 + 改 5 处前端调用点
//! 的改动面更大，且会长出**两套**文案真值源（同一个「所有文件」在两处各写一遍，迟早分叉）。
//!
//! ══ 文案住哪：复用 `ui/src/i18n/locales/auxiliary/`，新增 `native.*` 命名空间 ══
//!
//! `locales/auxiliary/` 这个分区的定义就是「**主窗 i18next 不加载**、由别的消费方按命名空间具名导入」
//! （见 `ui/src/i18n/auxiliary.ts`）。此前的消费方是托盘浮层与更新弹窗两个辅助 webview，Rust 进程是
//! **第三个**这样的消费方，形状完全吻合：
//!
//!  · **不用主分区** `locales/*.json`：那是 i18next 的全量包，en-US 单份 159 kB、五份合计
//!    ~870 kB。`include_str!` 主分区 = 把 870 kB 常量烧进二进制，只为取二十来条串。
//!    aux 分区五份合计 ~14 kB。
//!  · **不另起 `locales/native/`**：那要把 `locale-parity.test.ts` 的键集/形态/棘轮门、
//!    `text-fit.test.ts` 的语料装配各复制一份。aux 分区已被这两道门覆盖（parity 把 aux
//!    合进主分区一起判，缺译会转红），新命名空间**零门禁成本**地继承。
//!  · **托盘那批键直接复用 `tray.*`，不另起一份**：`tray.rs` 的旧注释写着「文案与浮层
//!    `TrayMenu.tsx` 的 `TAKEOVERS` 表逐字一致（同一概念在两个入口不得措辞分叉）」——
//!    那是一条**靠人守**的散文约束。改成读同一个键之后，它变成结构性的：两个入口取的是
//!    同一个字符串，想分叉都分叉不了。
//!  · 辅助窗的 bundle **不会**因此变大：`labels.ts` / `update-popup/main.ts` 走的是
//!    `import { tray } from '.../aux/en-US.json'` 具名导入，Rollup 只保留那一棵子树，
//!    `native` 被 tree-shake 掉（这正是 `aux.ts` 选具名导入的理由，实测 3.2 kB）。
//!
//! ══ `include_str!` 而不是运行期读文件 ══
//!
//! 五份 JSON 在**编译期**嵌进二进制（下方 [`Lang::catalog_json`]）。
//!
//!  · **不能放 `resources/`**：该目录被 `.gitignore` 整体排除（`/resources/*`）、由
//!    `scripts/` 在构建期 fetch 填充。翻译是源码不是下载物，放进去等于「翻译不入库」。
//!  · **不做运行期读盘**：那要多一条「文件没跟着装进包」的失效腿，而它的症状是**静默**的
//!    （读不到 → 回落键名 → 用户看到 `native.allFiles`），且三平台各有一套资源目录布局。
//!  · **改 JSON 会不会不重编**（最容易埋的雷：静默用旧文案）：不会。`include_str!` 读到的文件
//!    由 rustc 写进 dep-info，cargo 据此判定重编 —— 与 `build.rs` 的 `cargo:rerun-if-changed`
//!    是两套机制，后者管的是 build script 自己的输入，`include_str!` 用不上它，**故本模块
//!    不需要也不应该往 `build.rs` 加 rerun-if-changed**。
//!
//!    这是实测的，不是推断（2026-07-31，本工作树）：
//!      · `target/debug/polaris.d` 里逐行列出了五份 `ui/src/i18n/locales/auxiliary/*.json`；
//!      · 无改动连跑两次 `cargo build -p polaris` ⇒ `Compiling polaris` 出现 **0** 次；
//!      · `touch ui/src/i18n/locales/auxiliary/ru.json` 后再跑 ⇒ 出现 **1** 次；其后再跑又回 **0** 次。
//!    复现命令记在 handoff 里。哪天换构建方式（自定义 build script 生成 locale、或改成运行期读盘），
//!    重跑这三步即可判定这条论断是否仍成立。
//!  · **路径跨出 crate**（`../../ui/...`）：这是本模块唯一的跨界依赖，且是**单向、只读、
//!    编译期**的。`crates/` 下的子 crate 不受影响 —— 它们没有 tauri 依赖，也就没有任何
//!    用户可见的原生表面（对话框 / 菜单 / 通知全在 `src-tauri/` 内，已实测），
//!    没有复用本模块的需求。
//!
//! ══ 语言从哪来 ══
//!
//! [`app_lang`] 读 `config.language`（`ConfigManager` 缓存投影），`auto` / 空 / 不认识的码
//! 回落系统 locale（`tauri_plugin_os::locale()`）。这与前端 `i18n/index.ts`（「语言选择真值源
//! = config.language」）和 `app_language.rs`（macOS `AppleLanguages` 对账）**同一个真值源**。
//! 解析规则是 `ui/src/domain/language.ts` 的 `resolveEffectiveLanguage` + `migrateLanguageCode`
//! 的逐条移植（见 [`resolve_effective`]），三处口径不得分叉。
//!
//! ══ 回落链：`当前语种 → en-US → 键名`，**刻意不回落 zh** ══
//!
//! 1. `en-US` 是前端 `DEFAULT_LANGUAGE`、i18next 的 `fallbackLng`、也是
//!    `locale-parity.test.ts` 的 `REFERENCE`（zh-CN/zh-TW 对它严格全等，ru/fa 走精确棘轮）
//!    ⇒ 它是**结构上唯一被保证完整**的一份。
//! 2. 回落 zh 会让「某个键漏译」的症状变成**波斯语用户看到中文**——那正是本模块要消灭的形态，
//!    而且它比英文更难被用户/我们辨认成 bug。
//! 3. `en-US` 也缺 → 返回**键名本身**（`native.allFiles` 这样的裸串），显式坏相、不静默显示
//!    别的语言。这一档不该发生：本文件的键覆盖门（`every_declared_key_resolves_in_all_five_locales`）
//!    与 `locale-parity.test.ts` 会先转红。口径与 `ui/src/i18n/auxiliary.ts` 逐条相同。
//!
//! ══ IPC 诊断与用户文案边界 ══
//!
//! Rust 载荷可保留 OS/core/HTTP 原文用于日志与诊断，但 renderer 不得把这些字段直接显示。
//! 当前六类历史出口均已按这一边界收口：
//!
//! | # | 通道 | 当前用户可见真值 |
//! |---|---|---|
//! | 1 | `update:progress` | `UpdateErr.errorCode` → 五语 `settings.update.err.*` / `updatePopup.err*`；`detail` 仅诊断 |
//! | 2 | `ApiResponse::msg` / `IpcError.message` | wire/log 兼容诊断；动作出口由稳定 code 的 domain mapper 或本地化通用失败句显示 |
//! | 3 | 手动订阅刷新终态 | `errorKind` / `httpStatus` → `subscriptionErrorDetail`；原始 `error` 不参与渲染 |
//! | 4 | 自动订阅刷新终态 | 与手动刷新共用 `subscriptionErrorDetail`，原始诊断只写日志 |
//! | 5 | 成功信封内嵌 `error` | 节点探测只记录诊断，表单按稳定 `errorPath` 显示；诊断导出正文不属于 UI 文案 |
//! | 6 | `proxyError` / `proxyLifecycle` | `errorCode` → `proxy-error-text.ts` 五语键；未知/缺码回落本地化通用失败句 |
//!
//! 前端契约门 `raw-ipc-error-visibility.test.ts` 与 `action-failure-visibility.test.ts` 锁定
//! “诊断可记录、不可直显”；`proxy-error-key-coverage.test.ts` 对账 Rust 错误码与五语映射。
//! 原生 Rust sink 则继续由本模块的 `SINKS` 与五语键覆盖测试约束。新增跨进程错误时，必须先
//! 定义稳定 code/分类，再接本地化显示；不得以某一种语言的 `message` 作为控制流或 UI 真值。
//!
use std::collections::HashMap;
use std::sync::LazyLock;

use serde_json::Value;
use tauri::{AppHandle, Manager};

// ────────────────────────────────────────────────────────────────────────────
// 语言
// ────────────────────────────────────────────────────────────────────────────

/// 界面语言 —— 逐项等于 `ui/src/domain/language.ts` 的 `SUPPORTED_LANGUAGES`。
///
/// 顺序即 [`SUPPORTED`] 的顺序，无语义。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Lang {
    ZhCN,
    ZhTW,
    EnUS,
    Ru,
    Fa,
}

/// 全部受支持语言。`ui/src/domain/language.ts::SUPPORTED_LANGUAGES` 的 Rust 侧对应物
/// （**两侧由 `ui/src/contracts/rust-i18n-coverage.test.ts` 对账**）。
pub const SUPPORTED: [Lang; 5] = [Lang::ZhCN, Lang::ZhTW, Lang::EnUS, Lang::Ru, Lang::Fa];

/// 回落语言。= 前端 `DEFAULT_LANGUAGE`（理由见模块文档「回落链」一节）。
pub const DEFAULT: Lang = Lang::EnUS;

impl Lang {
    /// i18n 资源键（= locale 文件名，= `config.language` 的取值）。
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Lang::ZhCN => "zh-CN",
            Lang::ZhTW => "zh-TW",
            Lang::EnUS => "en-US",
            Lang::Ru => "ru",
            Lang::Fa => "fa",
        }
    }

    /// 该语种的 aux 分区 JSON 原文（编译期嵌入，理由见模块文档）。
    ///
    /// 路径写死而不是 `concat!` 拼 —— `include_str!` 的实参必须是字面量才能让 rustc 把它
    /// 记进 dep-info（改 JSON 才会重编）。
    const fn catalog_json(self) -> &'static str {
        match self {
            Lang::ZhCN => include_str!("../../ui/src/i18n/locales/auxiliary/zh-CN.json"),
            Lang::ZhTW => include_str!("../../ui/src/i18n/locales/auxiliary/zh-TW.json"),
            Lang::EnUS => include_str!("../../ui/src/i18n/locales/auxiliary/en-US.json"),
            Lang::Ru => include_str!("../../ui/src/i18n/locales/auxiliary/ru.json"),
            Lang::Fa => include_str!("../../ui/src/i18n/locales/auxiliary/fa.json"),
        }
    }
}

/// 旧语言码迁移：`fa-IR` → `fa`（其余原样）。与 `domain/language.ts::migrateLanguageCode`
/// 同口径 —— 不迁移的话波斯语存量用户在这条腿上恒回落系统语言。
fn migrate_code(code: &str) -> &str {
    if code == "fa-IR" {
        "fa"
    } else {
        code
    }
}

/// 单个 BCP47 码 → 受支持语言；无匹配 `None`。
///
/// 移植 `domain/language.ts::matchSupported`：按主语言子标签 + 脚本/地区消歧。
/// 繁体判据 = `Hant` 脚本**或** tw/hk/mo 地区段（原文正则 `/(^|[-_])(tw|hk|mo)([-_]|$)/`
/// 在此实现为「按 `-`/`_` 切段后整段相等」——同一语义，且不为一个正则给 src-tauri 加 `regex` 依赖）。
fn match_supported(raw: &str) -> Option<Lang> {
    let l = raw.trim().to_ascii_lowercase();
    if l.is_empty() {
        return None;
    }
    let mut segs = l.split(['-', '_']);
    let primary = segs.next().unwrap_or_default();
    match primary {
        "zh" => {
            let hant =
                l.contains("hant") || l.split(['-', '_']).any(|s| matches!(s, "tw" | "hk" | "mo"));
            Some(if hant { Lang::ZhTW } else { Lang::ZhCN })
        }
        "fa" => Some(Lang::Fa),
        "ru" => Some(Lang::Ru),
        "en" => Some(Lang::EnUS),
        _ => None,
    }
}

/// OS 偏好语言有序列表 → 受支持语言；命中即止，全不匹配 → [`DEFAULT`]。
/// 移植 `domain/language.ts::resolveAutoLanguage`。
fn resolve_auto(preferred: &[String]) -> Lang {
    preferred
        .iter()
        .find_map(|p| match_supported(p))
        .unwrap_or(DEFAULT)
}

/// 解析有效界面语言。移植 `domain/language.ts::resolveEffectiveLanguage`。
///
/// - `choice` 为 `auto` / 空 / **不在受支持集合里**（含 `de-DE`、大小写不符的 `ZH-CN`）→ 按系统偏好解析；
/// - `choice` 是受支持的具体码（`fa-IR` 先迁移成 `fa`）→ 用它。
///
/// ⚠️ 与旧 `resolve_tray_lang` 的**行为差异**（刻意）：旧实现把「显式的非中文码」一律判英文
/// （`de-DE` → En），新实现按前端口径回落系统偏好（德语系统 + `de-DE` 选择 → 系统里若有俄语
/// 就取俄语）。分叉的那一版没有理由，只是二态解析的副产物。
#[must_use]
pub fn resolve_effective(choice: &str, system: &[String]) -> Lang {
    let c = migrate_code(choice.trim());
    if c.is_empty() || c == "auto" {
        return resolve_auto(system);
    }
    SUPPORTED
        .into_iter()
        .find(|l| l.code() == c)
        .unwrap_or_else(|| resolve_auto(system))
}

/// 本进程当前应显示的语言：`config.language` → `auto`/空/未知码回落系统 locale。
///
/// 走 [`ConfigManager::with_current`](crate::runtime::config::ConfigManager::with_current) **投影**而非
/// `current()`：本函数在托盘两个汇流点（tooltip 语言 + 菜单语言）里各调一次，而那两个汇流点挂着
/// **30s 自愈轮询**（`TRAY_ICON_POLL`）—— 用 `current()` 则核不动、用户不动，进程也会每 30s
/// 因为一个语言标签把整份配置（含 200 节点级 `servers`）深拷贝两遍。闭包内只取字段，不回调任何子系统。
///
/// ⚠️ 调用方**不得**把本函数塞进另一个 `with_current` 闭包里：闭包内持着 `ConfigManager` 的读锁，
/// 而本函数自己还要再读一次，递归读在有写者排队时永久阻塞。`main.rs` 的
/// `tray_reconcile_reads_config_by_projection_not_full_clone` 在源码层面钉着这两条。
#[must_use]
pub fn app_lang(app: &AppHandle) -> Lang {
    let choice = app
        .try_state::<crate::runtime::AppRuntime>()
        .and_then(|rt| {
            rt.config()
                .with_current(|c| {
                    c.get("language")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .ok()
                .flatten()
        })
        .unwrap_or_default();
    let sys = tauri_plugin_os::locale()
        .map(|l| vec![l])
        .unwrap_or_default();
    resolve_effective(&choice, &sys)
}

// ────────────────────────────────────────────────────────────────────────────
// 文案表
// ────────────────────────────────────────────────────────────────────────────

/// 一个语种的扁平文案表（`"tray.connect"` → 译文）。
type Catalog = HashMap<String, String>;

/// 把 aux JSON（两层：命名空间 → 键 → 串）压成扁平表。
///
/// **解析失败即 panic，不回落空表**：入参是 `include_str!` 嵌进来的**编译期常量**，不是用户
/// 可写的运行期文件 —— 它坏掉是我们自己提交了破 JSON，不是用户输入异常。回落空表的后果是
/// 每一条文案都退化成裸键名（`native.allFiles` 显在对话框标题上），比早失败更糟且更难归因。
/// 这与 `app_language.rs` 「读 config.json 绝不 panic」并不矛盾：那边读的是**用户可写的磁盘文件**。
/// 本函数被下方键覆盖门对五个语种各跑一遍，破 JSON 进不了 CI。
fn flatten(json: &str, lang: Lang) -> Catalog {
    let root: Value = serde_json::from_str(json)
        .unwrap_or_else(|e| panic!("locale {} 不是合法 JSON：{e}", lang.code()));
    let obj = root
        .as_object()
        .unwrap_or_else(|| panic!("locale {} 顶层不是对象", lang.code()));
    let mut out = Catalog::new();
    for (ns, sub) in obj {
        let leaves = sub
            .as_object()
            .unwrap_or_else(|| panic!("locale {}：命名空间 {ns} 不是对象", lang.code()));
        for (k, v) in leaves {
            let s = v
                .as_str()
                .unwrap_or_else(|| panic!("locale {}：{ns}.{k} 不是字符串", lang.code()));
            out.insert(format!("{ns}.{k}"), s.to_owned());
        }
    }
    out
}

/// 五份文案表（首次取用时解析一次）。
static CATALOGS: LazyLock<HashMap<&'static str, Catalog>> = LazyLock::new(|| {
    SUPPORTED
        .into_iter()
        .map(|l| (l.code(), flatten(l.catalog_json(), l)))
        .collect()
});

/// 取某语种的文案表。语种恒在表内（由 [`SUPPORTED`] 构造），故 `expect` 不可达。
fn catalog(lang: Lang) -> &'static Catalog {
    CATALOGS
        .get(lang.code())
        .expect("CATALOGS 由 SUPPORTED 构造，不可能缺项")
}

/// 取文案。回落链 `lang → en-US → 键名`（理由见模块文档「回落链」一节）。
///
/// `key` 用 [`key`] 模块里的常量，别写裸串 —— 键覆盖门只认那个模块里声明的常量。
#[must_use]
pub fn t(lang: Lang, key: &str) -> String {
    catalog(lang)
        .get(key)
        .or_else(|| catalog(DEFAULT).get(key))
        .cloned()
        .unwrap_or_else(|| key.to_owned())
}

// ────────────────────────────────────────────────────────────────────────────
// 键
// ────────────────────────────────────────────────────────────────────────────

/// Rust 侧消费的全部 i18n 键。
///
/// 两类：
///  · `tray.*` —— 与托盘浮层 `TrayMenu.tsx` **共用**的键（同一概念在原生菜单与浮层不得措辞分叉，
///    见模块文档）。这些键归浮层所有，`text-fit.test.ts` 的槽位穷尽性断言也盯着它们，
///    **不要往 `tray` 命名空间加只有 Rust 用的键**（浮层没有消费点 ⇒ 那道门会红，且它红得对）。
///  · `native.*` —— webview 里**没有对应表面**的文案（文件对话框、提权引导、应用菜单、
///    托盘检查更新的系统通知）。新增 Rust 侧文案往这里加。
///
/// 本模块内每一条 `pub const` 都被 `every_declared_key_resolves_in_all_five_locales` 逐个查表
/// 验证（五语种齐备），反向由 `every_native_key_in_locale_is_declared_here` 查死键。
pub mod key {
    // ── 托盘原生菜单（与浮层共用）──
    /// 「连接代理」。
    pub const TRAY_CONNECT: &str = "tray.connect";
    /// 「断开代理」。
    pub const TRAY_DISCONNECT: &str = "tray.disconnect";
    /// 「取消启动」。
    pub const TRAY_CANCEL_STARTUP: &str = "tray.cancelStartup";
    /// 节点/出口子菜单标题。
    pub const TRAY_NODES: &str = "tray.nodes";
    /// 自建节点分组。
    pub const TRAY_GROUP_MANUAL: &str = "tray.groupManual";
    /// 组网节点分组。
    pub const TRAY_GROUP_MESH: &str = "tray.groupMesh";
    /// 阻断出口。
    pub const TRAY_BLOCKED: &str = "tray.blocked";
    /// 直连模式下无效。
    pub const TRAY_NO_EFFECT_IN_DIRECT: &str = "tray.noEffectInDirect";
    /// 接管方式子菜单标题。
    pub const TRAY_GROUP_TAKEOVER: &str = "tray.groupTakeover";
    /// 分流策略子菜单标题。
    pub const TRAY_GROUP_MODE: &str = "tray.groupMode";
    /// 「打开设置」。
    pub const TRAY_OPEN_SETTINGS: &str = "tray.openSettings";
    /// 「检查更新」。
    pub const TRAY_CHECK_UPDATE: &str = "tray.checkUpdate";
    /// 「测速」。
    pub const TRAY_SPEEDTEST: &str = "tray.speedtest";
    /// 「立即锁定」。
    pub const TRAY_LOCK_NOW: &str = "tray.lockNow";
    /// 「进入轻量模式」。
    pub const TRAY_LIGHTWEIGHT: &str = "tray.lightweight";
    /// 托盘动作失败模板。
    pub const TRAY_ACTION_FAILED: &str = "tray.actionFailed";
    /// 「打开主窗口」。
    pub const TRAY_OPEN_MAIN: &str = "tray.openMain";
    /// 「退出 Polaris」（托盘菜单 + 应用菜单 ⌘Q 共用）。
    pub const TRAY_QUIT: &str = "tray.quit";

    // ── 接管方式三档（`config.proxyModeType` 值域）──
    /// 系统代理。
    pub const TRAY_TAKEOVER_SYSTEM_PROXY: &str = "tray.takeoverSystemProxy";
    /// TUN 模式。
    pub const TRAY_TAKEOVER_TUN: &str = "tray.takeoverTun";
    /// 仅本机。
    pub const TRAY_TAKEOVER_MANUAL: &str = "tray.takeoverManual";

    // ── 分流策略三档（`config.proxyMode` 值域）──
    /// 智能分流。
    pub const TRAY_MODE_SMART: &str = "tray.modeSmart";
    /// 全局。
    pub const TRAY_MODE_GLOBAL: &str = "tray.modeGlobal";
    /// 直连。
    pub const TRAY_MODE_DIRECT: &str = "tray.modeDirect";

    // ── tooltip 四态 ──
    /// 已连接。
    pub const TRAY_STATUS_CONNECTED: &str = "tray.statusConnected";
    /// 连接中。
    pub const TRAY_STATUS_CONNECTING: &str = "tray.statusConnecting";
    /// 连接异常。
    pub const TRAY_STATUS_ERROR: &str = "tray.statusError";
    /// 未连接。
    pub const TRAY_STATUS_DISCONNECTED: &str = "tray.statusDisconnected";

    // ── 检查更新结果（浮层 notice 行与原生通知共用）──
    /// 已是最新版本。
    pub const TRAY_UP_TO_DATE: &str = "tray.upToDate";
    /// 检查更新失败。
    pub const TRAY_UPDATE_CHECK_FAILED: &str = "tray.updateCheckFailed";

    // ── 原生文件对话框 ──
    /// 导出配置备份：保存框标题。
    pub const NATIVE_BACKUP_EXPORT_TITLE: &str = "native.backupExportTitle";
    /// 导入配置备份：打开框标题。
    pub const NATIVE_BACKUP_IMPORT_TITLE: &str = "native.backupImportTitle";
    /// `.polaris-backup` 过滤器显示名。
    pub const NATIVE_BACKUP_FILE_TYPE: &str = "native.backupFileType";
    /// `.json` 过滤器显示名。
    pub const NATIVE_JSON_FILE_TYPE: &str = "native.jsonFileType";
    /// 导出诊断报告：保存框标题。
    pub const NATIVE_DIAGNOSTIC_EXPORT_TITLE: &str = "native.diagnosticExportTitle";
    /// 导出日志：保存框标题。
    pub const NATIVE_LOGS_EXPORT_TITLE: &str = "native.logsExportTitle";
    /// 归档旧版无界核日志：保存框标题。
    pub const NATIVE_LEGACY_LOG_ARCHIVE_TITLE: &str = "native.legacyLogArchiveTitle";
    /// `.log` 过滤器显示名。
    pub const NATIVE_LOG_FILE_TYPE: &str = "native.logFileType";
    /// 本地导入配置：打开框标题。
    pub const NATIVE_CONFIG_PICK_TITLE: &str = "native.configPickTitle";
    /// 配置文件过滤器显示名。
    pub const NATIVE_CONFIG_FILE_TYPE: &str = "native.configFileType";
    /// 手动替换内核：打开框标题。
    pub const NATIVE_CORE_PICK_TITLE: &str = "native.corePickTitle";
    /// 「所有文件」过滤器显示名。
    pub const NATIVE_ALL_FILES: &str = "native.allFiles";
    /// Taildrop 取件：保存框标题。
    pub const NATIVE_TAILDROP_SAVE_TITLE: &str = "native.taildropSaveTitle";
    /// Taildrop 发件：多文件选择框标题。
    pub const NATIVE_TAILDROP_SEND_TITLE: &str = "native.taildropSendTitle";

    // ── 提权引导消息框 ──
    /// 未装 helper：标题。
    pub const NATIVE_HELPER_INSTALL_TITLE: &str = "native.helperInstallTitle";
    /// 未装 helper：正文。
    pub const NATIVE_HELPER_INSTALL_BODY: &str = "native.helperInstallBody";
    /// 未装 helper：确认按钮。
    pub const NATIVE_HELPER_INSTALL_CONFIRM: &str = "native.helperInstallConfirm";
    /// 已装但不可用：标题。
    pub const NATIVE_HELPER_REPAIR_TITLE: &str = "native.helperRepairTitle";
    /// 已装但不可用：正文。
    pub const NATIVE_HELPER_REPAIR_BODY: &str = "native.helperRepairBody";
    /// 已装但不可用：确认按钮。
    pub const NATIVE_HELPER_REPAIR_CONFIRM: &str = "native.helperRepairConfirm";
    /// 取消按钮。
    pub const NATIVE_CANCEL: &str = "native.cancel";

    // ── 托盘「检查更新」的系统通知 ──
    /// 通知标题。
    pub const NATIVE_UPDATE_NOTIFY_TITLE: &str = "native.updateNotifyTitle";
    /// `hasUpdate` 为真却缺 version（后端契约破损）。
    pub const NATIVE_UPDATE_INFO_INCOMPLETE: &str = "native.updateInfoIncomplete";
    /// 提醒窗弹不出来。
    pub const NATIVE_UPDATE_POPUP_FAILED: &str = "native.updatePopupFailed";
    /// 兜底错误串。
    pub const NATIVE_UNKNOWN_ERROR: &str = "native.unknownError";
    /// 无渲染端参与的起核入口发现主窗仍有未保存草稿。
    pub const NATIVE_UNSAVED_CONFIG_CHANGES: &str = "native.unsavedConfigChanges";
    /// Linux 原生托盘测速完成后的系统通知正文。
    pub const NATIVE_SPEED_TEST_COMPLETE: &str = "native.speedTestComplete";
    /// 主窗口 renderer 连续初始化失败后的终局页标题。
    pub const NATIVE_FATAL_PAGE_TITLE: &str = "native.fatalPageTitle";
    /// 主窗口 renderer 连续初始化失败后的终局页正文。
    pub const NATIVE_FATAL_PAGE_BODY: &str = "native.fatalPageBody";
    /// 主窗口 renderer 连续初始化失败后的重载按钮。
    pub const NATIVE_FATAL_PAGE_RELOAD: &str = "native.fatalPageReload";
}

#[cfg(test)]
mod tests;
