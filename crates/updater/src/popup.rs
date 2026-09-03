//! mini 更新弹窗的状态载荷 + 会话编排（移植自 上游 `UpdateService` 的 popup 族）。
//!
//! 移植来源（`src/main/services/UpdateService.ts` + `update-popup-layout.ts`）：
//!  - `createUpdatePopup:541-631`：建窗 + 复用分支 + 初始态下发。
//!  - `sendPopupState:636-647`：写 `lastPopupState` + 推 renderer + 按 phase 改窗高。
//!  - `showUpdateDialog:486-503`：互斥闸 + remind 态 + 动作等待。
//!  - `popupHeightFor:18-28`（`update-popup-layout.ts`）：上游四态窗高（本移植另加 `noupdate` 一档）。
//!
//! # 本模块存在的理由：#300/#301 的不变式需要一个「结构上无法违反」的落点
//!
//! 上游 issue #300（v4.2.3 全平台 remind 态 100% 必现白屏挂死窗）的根因链
//! （取证见 vault 里「更新弹窗『稍后提醒』留白」那份修复记录）：
//!
//! ```text
//! createUpdatePopup(新建路径) —— 全程无 sendPopupState
//!   did-finish-load 只重放 lastPopupState，而 lastPopupState 仅在 sendPopupState 内写入
//!   → 新建路径从不调 sendPopupState → lastPopupState 恒 null → 重放条件 false
//!   → renderer onState 永不触发 → 页面永空 → 用户看到 frameless 实色底、无按钮、Esc 失效、无法关闭
//! ```
//!
//! PR #301 的修法是在建窗末尾补一行 `this.sendPopupState(state)`。**那一行是可以再次被删掉的** ——
//! #300 本身就是 PR #292 把「首次加载后下发」替换成「崩溃后重放」时丢掉初始下发引入的回归，
//! 讽刺的是那次改动的注释目的正是「避免空白挂死窗」。**同一个类别的 bug 在同一个文件上复发过一次，
//! 说明「记得调用某个方法」不是一条能长期成立的不变式。**
//!
//! 本移植不复制那条「记得调用」的约定，改为把它**编码进类型**：
//!
//!  1. 页面的初始态经 [`PopupSession::open`] 产出的 [`PopupBootstrap`] **注入文档本身**
//!     （Tauri `initialization_script`，页面 boot 时同步可读）——而非建窗后再 push IPC。
//!     于是「窗口存在但从未拿到状态」**不再是一个可达状态**：没有 bootstrap 就没有页面。
//!     这比 #301 的单行 seed 严格更强：#301 仍依赖一次 IPC push 及时送达（早发即丢，靠重放兜底），
//!     而 bootstrap 根本不经 IPC，**无竞态可言**。
//!  2. [`PopupSession::open`] 是产出 bootstrap 的**唯一**入口，且它必然写 `last_state`
//!     → `did-finish-load` 重放（[`PopupSession::replay`]）恒有料可放，覆盖 reload / renderer 崩溃重建。
//!  3. 于是宿主层「建窗时忘了下发初始态」在编译期就写不出来：建窗需要 script，script 只能来自 `open`。
//!
//! Polaris 的 push 通道仍保留（[`PopupSession::send_state`]）用于**后续**状态流转（progress 百分比等），
//! 语义与上游一致：先写 `last_state`、再推 renderer（对齐 `UpdateService.ts:637` 的「写在 destroyed 检查之前」）。

use crate::state::PopupPhase;

/// 弹窗宽度（= 上游 `UPDATE_POPUP_WIDTH`，`update-popup-layout.ts:11`）。
pub const POPUP_WIDTH: u32 = 380;

/// 按阶段取弹窗高度（移植自 上游 `popupHeightFor`，`update-popup-layout.ts:18-28`）。
///
/// 上游四态高度逐字对齐：`remind`=184 / `error`=152 / `progress`|`done`=116。
/// 本移植新增的 `noupdate` 上游没有对应值，与 `progress`/`done` 同档：三者都是「标题 + 一两行
/// 辅助信息、无按钮行」的卡 ——**不新造魔数**。
///
/// 代价如实登记（真机可见）：`noupdate` 的内容只有标题 + 一行副文案，按本窗排版实算约 75px
/// （padding 28 + 标题 21 + gap 8 + 副文案 18），于是卡片**底部留约 41px 空白**。取舍是「宁可
/// 多一格空白，也不为一屏新造一个只此一处用的高度常量」；真要收，得连同 `progress`/`done`
/// 一起按内容算高，那是另一件事。
#[must_use]
pub fn popup_height_for(phase: PopupPhase) -> u32 {
    match phase {
        PopupPhase::Remind => 184,
        PopupPhase::Error => 152,
        PopupPhase::Progress | PopupPhase::Done | PopupPhase::NoUpdate => 116,
    }
}

/// `done` 态自动关窗延迟（ms）（= 上游 `UpdateService.ts:772` 的 800ms）。
pub const DONE_AUTO_CLOSE_MS: u64 = 800;

/// `noupdate` 态自动关窗延迟（ms）。
///
/// **刻意不沿用 [`DONE_AUTO_CLOSE_MS`]**：那 800ms 是上游「打勾即走」的确认动画时长 —— `done` 那一屏
/// 用户不必读任何字就知道发生了什么。`noupdate` 则是五档里**唯一要求用户把一句话读完才有
/// 信息量**的终态（「本次检查未找到 vX 的更新包」），800ms 内一闪而过等于没说 —— 那与本批要修的「只有状态、
/// 没有事实」是同一个病。
///
/// 取值属**判断**，不是实测：本仓没有可援引的一次性提示停留时长先例（应用内 toast 由 sonner 托管、
/// 未设显式时长），故取 3s 这个保守整数。
pub const NO_UPDATE_AUTO_CLOSE_MS: u64 = 3_000;

/// App 更新失败的**机器码**（U1）。
///
/// `update:progress` 的 error 帧、弹窗 error 态、以及 `update_download` 失败早退的信封
/// 三条出口共用同一张码表；正文本地化全部在前端按码取键完成，后端只产 `detail`
/// （语言中性的诊断串）。此前这三条出口直接携带硬编码中文正文（i18n 模块文档登记的
/// 出口 #1/#2），俄语/波斯语用户在更新失败时看到的是俄语按钮 + 整段中文正文。
///
/// ⚠️ `wire()` 的返回串是**跨语言契约**（前端 locale 键 `update.err.<code>` /
/// `updatePopup.err.<code>` 与覆盖门都咬它）——改串等于改协议，必须五语种同步。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateErrCode {
    /// 调用契约破坏：`updateInfo.downloadUrl` 缺失/为空（前端与 Rust 的握手 bug，非用户可修）。
    MissingDownloadUrl,
    /// 摘要字段存在但类型不对（发布方写坏了清单，重试无用）。
    DigestFieldInvalid,
    /// 解析/创建更新缓存目录失败（本地文件系统问题）。
    CacheDirFailed,
    /// 下载本身失败（网络层）。
    DownloadFailed,
    /// 下载后端不可用（与「网络失败」必须可区分：重试后者有意义、修前者没意义）。
    BackendUnavailable,
    /// 下载任务异常终止（join 层面的 panic/取消，非网络错误）。
    DownloadTaskFailed,
    /// 已收字节数与清单声明不符（可能被截断或掉包）。
    SizeMismatch,
    /// 清单里的 sha256 不是合法 64 位十六进制（发布方写坏，重试无用）。
    DigestHexInvalid,
    /// sha256 逐字节校验不中（可能被截断或篡改）。
    DigestMismatch,
    /// 落位失败（fsync / rename 阶段）。
    LandingFailed,
    /// 弹窗「更新」动作的复查阶段失败（检查腿报错 / 复查契约破损）。
    RecheckFailed,
}

impl UpdateErrCode {
    /// 线上形态（camelCase，前端键的后缀）。
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::MissingDownloadUrl => "missingDownloadUrl",
            Self::DigestFieldInvalid => "digestFieldInvalid",
            Self::CacheDirFailed => "cacheDirFailed",
            Self::DownloadFailed => "downloadFailed",
            Self::BackendUnavailable => "backendUnavailable",
            Self::DownloadTaskFailed => "downloadTaskFailed",
            Self::SizeMismatch => "sizeMismatch",
            Self::DigestHexInvalid => "digestHexInvalid",
            Self::DigestMismatch => "digestMismatch",
            Self::LandingFailed => "landingFailed",
            Self::RecheckFailed => "recheckFailed",
        }
    }

    /// 信封通道的英文回落文案（`err_with_code` 的 msg；诊断串由调用点拼进 detail）。
    /// 只在信封里出现——事件/弹窗两条出口的正文由前端按码本地化，不走这个。
    #[must_use]
    pub const fn en(self) -> &'static str {
        match self {
            Self::MissingDownloadUrl => "update contract broken: missing downloadUrl",
            Self::DigestFieldInvalid => "release digest field is malformed (retry won't help)",
            Self::CacheDirFailed => "failed to resolve or create the update cache dir",
            Self::DownloadFailed => "failed to download the update package",
            Self::BackendUnavailable => "download backend unavailable",
            Self::DownloadTaskFailed => "download task terminated abnormally",
            Self::SizeMismatch => "package size does not match the release manifest",
            Self::DigestHexInvalid => "release sha256 is not valid hex (retry won't help)",
            Self::DigestMismatch => "package digest verification failed",
            Self::LandingFailed => "failed to land the downloaded package",
            Self::RecheckFailed => "update re-check failed",
        }
    }
}

/// 一次失败的全部事实：码 + 诊断串（`None` = 无可给的技术细节）。
#[derive(Debug, Clone, Copy)]
pub struct UpdateErr<'a> {
    pub code: UpdateErrCode,
    pub detail: Option<&'a str>,
}

impl<'a> UpdateErr<'a> {
    #[must_use]
    pub const fn new(code: UpdateErrCode) -> Self {
        Self { code, detail: None }
    }

    /// 诊断串要求**语言中性**（路径 / 哈希 / OS 错误原文）：它是数据不是文案。
    #[must_use]
    pub const fn with_detail(code: UpdateErrCode, detail: &'a str) -> Self {
        Self {
            code,
            detail: Some(detail),
        }
    }
}

/// 弹窗状态载荷（主 → 弹窗）。
///
/// 移植自 上游 `UpdatePopupState`（`shared/types/update.ts`）。字段经 serde 转 camelCase
/// 与前端契约对齐（前端 `ui/src/shared/types/update.ts` 按本结构重建）。
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePopupState {
    /// 当前阶段（决定布局与窗高）。
    pub phase: PopupPhase,
    /// 目标新版本号（remind 态展示）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// 当前版本号（remind 态展示，Polaris 形如 `v4.2.3`）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_version: Option<String>,
    /// 本次提醒采用的 App 更新候选通道。跨 phase 继承，供宿主在用户点击“更新/重试”时按同一
    /// 候选集复查；`None` 仅兼容旧载荷，并按稳定通道处理。
    // 仅供宿主在同一进程内复查；不属于主→renderer 载荷，避免把内部决策元数据暴露成 UI 契约。
    #[serde(skip)]
    pub include_prerelease: Option<bool>,
    /// 下载进度百分比（progress/done 态，0-100）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub percentage: Option<u8>,
    /// 本次下载**已收字节**（progress 态；下载回调给的原值，不是从百分比反推的估算）。
    ///
    /// # 为什么发数字而不是发拼好的文案
    ///
    /// 本字段的前身是 `bytes_text: Option<String>`（形如 `3.2 MB / 48 MB`）——**全仓零生产写点**，
    /// 有字段、有 serde 单测，渲染端恒回落 `${pct}%`。改发数字不是「顺手换个形状」：后端拼文案
    /// 就意味着**后端又多产出一份用户可见文案**，而本仓已有一条登记在案的欠账正是那条路
    /// （`emit_progress` 的 `message` 携带硬编码中文、经 `update:progress` 原样广播、绕过 i18n）。
    /// 数字过线、渲染端拼串，是不把那个口子再开宽一格的唯一方向。
    ///
    /// ⚠️ **不要把它说成「换到前端就本地化了」**：渲染端用的 `fmtBytes` 同样语种无关（拉丁数字、
    /// `.` 小数点、写死 `B/KB/MB/GB/TB`）。真按语种给数字形要走 `Intl.NumberFormat`，未做。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received_bytes: Option<u64>,
    /// 本次下载的**总字节**（= 清单 `fileSize`）。
    ///
    /// 分母未知（清单没给 / 给了 0）时为 `None` —— 渲染端据此只显示已收量或回落百分比，
    /// **绝不拿已收字节凑一个假分母**（同 `progress_percent` 的第一条规则）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<u64>,
    /// 是否走镜像下载（progress 态角标；= 上游 `mirror` 标记）。
    ///
    /// ⚠️ **今天仍无生产写点**（如实登记，见 `tests::every_declared_field_has_a_production_write_point`
    /// 的待修表）：App 更新下载腿不回报本次走的是源站还是 gh 镜像。补的是下载腿的回报路径，
    /// 不是本结构 —— 单列。
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub mirror: bool,
    /// 包的落位路径（done 态）。
    ///
    /// **这是 `done` 的必填随行事实**：[`UpdatePopupState::done`] 把它做成必填参数之后，
    /// 零参的 `done()` 这个写法不复存在（此前 `update_popup_action` 的「复查发现没有可下的东西」
    /// 那一档正是这么写的，弹窗于是显示「下载完成」+ 满格进度条）。
    ///
    /// ⚠️ **类型只挡住零参调用，挡不住空串/伪造路径**：`done(version, "")` 照样编译得过。真正
    /// 挡住那一档的是源码门 `commands::updater::tests::the_no_download_path_never_claims_a_download`
    /// —— 类型挡「拿不出路径」，那道门挡「随手编一个路径喂给它」。两道都得在，删任一条缺陷都能
    /// 静默复活（实测：把源码门 `#[ignore]` 掉 ⇒ 全仓仍绿）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    /// App 更新失败的**机器码**（U1：error 态）。前端按 `updatePopup.err.<code>` 取五语种文案，
    /// 后端不再经任何通道产出本地化的（今天是硬编码中文的）失败正文。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// 失败的**技术诊断串**（error 态；语言中性的数据：路径 / 哈希 / OS 错误原文）。
    /// 不参与本地化——它给「想看细节的人」，正文那行给所有人。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_detail: Option<String>,
}

impl UpdatePopupState {
    /// remind 态（唯一入口态——#300 恰好杀死的就是它）。
    #[must_use]
    pub fn remind(version: impl Into<String>, current_version: impl Into<String>) -> Self {
        Self::remind_with_channel(version, current_version, false)
    }

    /// remind 态，并记录产出这次提醒时使用的预发布候选口径。
    #[must_use]
    pub fn remind_with_channel(
        version: impl Into<String>,
        current_version: impl Into<String>,
        include_prerelease: bool,
    ) -> Self {
        Self {
            phase: PopupPhase::Remind,
            version: Some(version.into()),
            current_version: Some(current_version.into()),
            include_prerelease: Some(include_prerelease),
            ..Self::default()
        }
    }

    /// progress 态（百分比 + 已收/总字节）。
    ///
    /// 两个字节参数都是 `Option` 且**必须显式传**（不给默认值）：调用点得为「这一帧到底知不知道
    /// 字节数」表态。今天两个调用点各占一种形态 —— 用户点「更新」后复查前那一发只有 `progress(0,
    /// None, None)`（此刻确实什么都不知道），下载回调那一发两者都有。
    #[must_use]
    pub fn progress(percentage: u8, received: Option<u64>, total: Option<u64>) -> Self {
        Self {
            phase: PopupPhase::Progress,
            percentage: Some(percentage.min(100)),
            received_bytes: received,
            total_bytes: total.filter(|n| *n > 0),
            ..Self::default()
        }
    }

    /// done 态（包**已经落在盘上**；宿主应在 [`DONE_AUTO_CLOSE_MS`] 后自动关窗）。
    ///
    /// # `file_path` 是必填参数，这就是本态的判据
    ///
    /// 本函数此前是零参的 `done()`，于是「复查回来发现没有可下的东西」那一档能拿它收场 ——
    /// 弹窗渲染「下载完成」+ 100% 进度条，而**一个字节都没下**。把落位路径提成必填参数之后，
    /// 调用点至少得为「包在哪儿」这件事**显式表态**一次，而不是什么都不填就拿到一个终态。
    /// 「没有可下的东西」现在有自己的一档（[`PopupPhase::NoUpdate`] /
    /// [`UpdatePopupState::no_update`]）。
    ///
    /// ⚠️ **别把这条读成「谎话在类型上写不出来」**（本注释初版就是那么写的，过头了）：
    /// `done(version, "")` 编译得过，`done(version, "/dev/null")` 也编译得过。类型消掉的只是
    /// 「零参即得终态」这一种形态；「编一个路径喂给它」由源码门
    /// `commands::updater::tests::the_no_download_path_never_claims_a_download` 挡
    /// （该门那边的注释是对的：类型挡拿不出路径，门挡随手编一个）。实测把那道门 `#[ignore]`
    /// 掉再把分支改回推 `done` ⇒ 全仓 4185 passed / 0 failed，缺陷复活且零告警 ——
    /// **看着这句话去删门的人会把缺陷放回来**，故此处必须写准。
    ///
    /// `version` 可缺（清单理论上可能没有 `version` 字段）；缺时由
    /// [`PopupSession::send_state`] 的会话级继承补上这次弹窗邀请的那一版 —— 两处都没有才留空。
    ///
    /// `percentage` 恒 100：done 与 progress 共用同一条进度条 DOM，留 `None` 会让条子在最后一帧
    /// 掉回 0（上游 `done` 载荷同样带满值）。
    #[must_use]
    pub fn done(version: Option<String>, file_path: impl Into<String>) -> Self {
        Self {
            phase: PopupPhase::Done,
            version,
            percentage: Some(100),
            file_path: Some(file_path.into()),
            ..Self::default()
        }
    }

    /// noupdate 态（用户点了「更新」，复查回来没有任何可下载的包）。
    ///
    /// 只带**主语**（这次弹窗邀请的版本号），不带成因 —— 后端分辨不出五条 `NoUpdate` 成因里的哪
    /// 一条（见 [`PopupPhase::NoUpdate`] 的文档），编一个出来就是拿状态冒充事实。
    #[must_use]
    pub fn no_update(version: Option<String>) -> Self {
        Self {
            phase: PopupPhase::NoUpdate,
            version,
            ..Self::default()
        }
    }

    /// error 态（U1 起携带机器码 + 诊断串，本地化在渲染端完成）。
    #[must_use]
    pub fn error(code: UpdateErrCode, detail: impl Into<String>) -> Self {
        Self {
            phase: PopupPhase::Error,
            error_code: Some(code.wire().to_string()),
            error_detail: Some(detail.into()),
            ..Self::default()
        }
    }

    /// 本状态对应的窗高。
    #[must_use]
    pub fn height(&self) -> u32 {
        popup_height_for(self.phase)
    }
}

/// 弹窗动作（弹窗 → 主）。
///
/// 移植自 上游 `UpdatePopupAction`（`shared/types/update.ts:46-54`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PopupAction {
    /// 立即更新（remind → progress）。
    Update,
    /// 稍后（关窗，本次不再提醒）。
    Later,
    /// 跳过此版本（写 skipped 版本号）。
    Skip,
    /// 查看发布说明（开浏览器；**不 resolve 等待**，弹窗停在 remind）。
    ViewLog,
    /// 取消下载（progress 态）。
    Cancel,
    /// 重试（error → progress）。
    Retry,
    /// 手动下载（开浏览器；仅 https URL 放行）。
    ManualDownload,
    /// 关闭弹窗。
    Close,
}

impl PopupAction {
    /// 该动作是否**不**结束等待（= 上游 `viewLog` 分支：开页面但不 resolve，弹窗停在 remind）。
    ///
    /// 移植自 `UpdateService.ts:683-686`。
    #[must_use]
    pub fn is_non_resolving(self) -> bool {
        matches!(self, Self::ViewLog)
    }

    /// 给定阶段下该动作是否合法（= 上游 `awaitPopupAction(valid)` 白名单，`UpdateService.ts:712-717`）。
    ///
    /// 非法动作**静默忽略**（不报错、不改状态），对齐上游语义。
    #[must_use]
    pub fn is_valid_for(self, phase: PopupPhase) -> bool {
        match phase {
            // remind：update / later / skip（+ viewLog 非 resolving）
            PopupPhase::Remind => matches!(
                self,
                Self::Update | Self::Later | Self::Skip | Self::ViewLog
            ),
            // progress：仅 cancel
            PopupPhase::Progress => matches!(self, Self::Cancel),
            // error：retry / manualDownload / close
            PopupPhase::Error => matches!(self, Self::Retry | Self::ManualDownload | Self::Close),
            // done：800ms 后自动关窗，用户无按钮可点（仅容 close 兜底）
            PopupPhase::Done => matches!(self, Self::Close),
            // noupdate：同为终态（[`NO_UPDATE_AUTO_CLOSE_MS`] 后自动关窗），同样只容 close 兜底。
            // close 必须在表内：角标 `×` 与 Esc 在本态都发它（`exitActionFor` 的兜底分支），
            // 拒收就等于死键 —— 而本窗 always_on_top，用户读作卡死。
            //
            // **一态一臂，不与 `Done` 合并成 or-pattern**：`is_valid_for` 是跨语言对拍门
            // （`ui/src/lib/update-popup-action-parity.test.ts`）的判据面，那边逐臂解析
            // `PopupPhase::X => matches!(…)`。合并写法会让被合并的前一个 phase 从白名单里消失
            // —— 该门会红（不是静默），但红在「两侧阶段集合不等」，诊断指错方向。
            PopupPhase::NoUpdate => matches!(self, Self::Close),
        }
    }
}

/// 建窗引导载荷：注入页面文档的初始状态（**替代** Polaris 建窗后 push IPC 的做法）。
///
/// 由 [`PopupSession::open`] 唯一产出。宿主层把 [`PopupBootstrap::init_script`] 交给
/// Tauri `WebviewWindowBuilder::initialization_script`，页面 boot 时同步读
/// `window.__POLARIS_UPDATE_POPUP_INITIAL__` 即可渲染首帧 —— 无 IPC、无竞态、无「早发即丢」。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PopupBootstrap {
    /// 注入文档的初始化脚本（定义 `window.__POLARIS_UPDATE_POPUP_INITIAL__`）。
    pub init_script: String,
    /// 建窗时应使用的窗口宽度。
    pub width: u32,
    /// 建窗时应使用的窗口高度（按初始 phase）。
    pub height: u32,
}

/// 状态推送通道（宿主注入真实 Tauri `emit_to`；测试注入记录器）。
///
/// 移植自 上游 `webContents.send(IPC_CHANNELS.UPDATE_POPUP_STATE, state)`。
pub trait PopupTransport {
    /// 推一条状态到弹窗 renderer。
    ///
    /// # Errors
    ///
    /// 窗口已销毁 / IPC 失败。上游对此**静默吞掉**（`sendPopupState` 先写 `lastPopupState` 再检查
    /// destroyed），本 trait 返回 [`Result`] 让宿主决定记日志与否——但
    /// [`PopupSession::send_state`] 保证**先写 `last_state` 再推**，故推送失败不影响重放兜底。
    fn send_state(&self, state: &UpdatePopupState) -> Result<(), String>;

    /// 按 phase 调整窗口内容高度（= 上游 `sendPopupState` 内的 `setContentSize`，`:641-645`）。
    ///
    /// # Errors
    ///
    /// 窗口已销毁 / 平台调用失败。
    fn set_content_height(&self, height: u32) -> Result<(), String>;
}

/// 弹窗代次的**进程级**计数源（🟡#4，复审 F1 修正）。
///
/// 必须跨会话单调：宿主的 `close_update_popup` 会把整个 `PopupSession` 连槽丢弃、新建分支每次
/// `PopupSession::new`——若代次是**每会话对象**自增，新会话从 1 重开，「关旧窗 → 3s 内开新窗」
/// 恰好撞回同一编号（1==1），陈旧定时器照样关掉新窗（守卫在标称主场景失效）。进程级原子
/// 计数让「另一扇窗」永远拿不到旧窗用过的号。
static POPUP_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// 弹窗会话：持有 `last_state` + 推送通道，编排「建窗初始态 / 状态流转 / 重放」。
///
/// **`last_state` 的写入点唯一**（[`Self::open`] 与 [`Self::send_state`]），且二者都在推送**之前**写——
/// 这正是 #300 的根因所在（上游 `lastPopupState` 只在 `sendPopupState` 内写，而建窗路径不调它）。
#[derive(Debug)]
pub struct PopupSession<T: PopupTransport> {
    transport: T,
    last_state: Option<UpdatePopupState>,
    /// 本窗的代次（[`POPUP_GENERATION`] 进程级发号，`open` 时领取；`reuse`/`send_state` 不换号，
    /// `new` 后、`open` 前为 0=未建窗）。自动关窗定时器捕获调度时的代次、fire 时核对——
    /// 不等说明这扇窗已经不在了（用户关掉后另一条腿开了新窗），陈旧定时器不得关新窗。
    /// 本批把 noupdate 窗口从 800ms 拉到 3000ms（3.75 倍），「3s 内关旧开新」从理论竞态变成
    /// 现实可达，这条守卫是它的解。
    generation: u64,
}

impl<T: PopupTransport> PopupSession<T> {
    /// 构造会话（尚未建窗，`last_state` 为空，代次 0=未领号——首次 `open` 从进程计数领新号）。
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            last_state: None,
            generation: 0,
        }
    }

    /// 本窗代次（自动关窗定时器的核对值；0=尚未建窗，语义见 `POPUP_GENERATION`）。
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// **新建窗口路径的唯一入口**：产出注入页面的 bootstrap，并落 `last_state`。
    ///
    /// #300/#301 不变式在此结构性成立 —— 宿主要建窗就必须拿 [`PopupBootstrap::init_script`]，
    /// 而拿它就必然经过本方法，本方法必然写 `last_state`。**「建窗但没下发初始态」写不出来。**
    ///
    /// 注意：本方法**不**经 [`PopupTransport::send_state`] 推 IPC —— 初始态走文档注入，不走 IPC。
    /// 这与上游 #301 的 `sendPopupState(state)` 单行 seed 语义等价（都让首帧有料 + 让重放有料），
    /// 但消灭了「push 早于 listener 注册」的整类竞态（= #301 文档里列为「可选 C，后续加固」的那条，
    /// 本移植直接做进建窗路径）。
    pub fn open(&mut self, state: UpdatePopupState) -> PopupBootstrap {
        let height = state.height();
        let init_script = Self::build_init_script(&state);
        // 先落 last_state：did-finish-load / renderer 崩溃重建时靠它重放（#300 的 lastPopupState 恒 null 即死在这）。
        self.last_state = Some(state);
        // 新窗口 = 从进程计数领新号（🟡#4/F1）：跨会话不复用，上一窗遗留的定时器永远对不上新窗的号。
        self.generation = POPUP_GENERATION.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        PopupBootstrap {
            init_script,
            width: POPUP_WIDTH,
            height,
        }
    }

    /// 复用已存在弹窗时的状态下发（= 上游 `createUpdatePopup:542-545` 复用分支）。
    ///
    /// # Errors
    ///
    /// 透传 [`PopupTransport::send_state`] 失败（`last_state` 已先写，重放仍可兜底）。
    pub fn reuse(&mut self, state: UpdatePopupState) -> Result<(), String> {
        self.send_state(state)
    }

    /// 推一条新状态：**先写 `last_state`，再推 renderer**（对齐 `UpdateService.ts:637` 的写入时序）。
    ///
    /// 窗高随 phase 变化时同步调整（= 上游 `:641-645` 的 `setContentSize` 差量更新）。
    ///
    /// # Errors
    ///
    /// 透传推送失败。**失败也已写 `last_state`** —— 这是上游把 `lastPopupState = state` 放在
    /// destroyed 检查之前的原因：推送失败不能让重放失去依据。
    ///
    /// # 邀请过的版本号是**会话级**事实，不是 phase 级事实
    ///
    /// [`UpdatePopupState::progress`] / [`UpdatePopupState::done`] / [`UpdatePopupState::error`]
    /// 三个构造点都只填自己那一档要用的字段（`..Self::default()` ⇒ `version: None`）。不继承的话，
    /// **一离开 remind，「这次弹窗邀请的是哪一版」就在会话里蒸发了** —— 而下游有两个消费者要它：
    ///
    ///  1. `commands/updater.rs` 的 `Update` / `Retry` 分支：复查回来要与邀请版本逐字对账。
    ///     `Retry` 按 [`PopupAction::is_valid_for`] **只在 `Error` 态合法**，那里 `version` 恒 `None`
    ///     ⇒ 对账恒判「变了」⇒ 退回 remind 而**一个字节都不下**，「重试」实际变成「返回」。
    ///  2. 同文件 `ManualDownload` 分支（同样只在 `Error` 态合法）：拿它去拼该版本的 release tag 页。
    ///     `None` 时回落泛列表页 —— #311 修的正是「找不到对应版本说明」，而 error 态恰好是最需要
    ///     它的一屏。
    ///
    /// 只继承 `version`，**不继承 `current_version`**：前者有决策依赖它（上面两条），后者今天在
    /// remind 之外无任何消费者，而 remind 恒自带两者。为对称而继承是给未来的猜测付税。
    ///
    /// 继承只在 `version.is_none()` 时发生 ⇒ [`UpdatePopupState::remind`] 恒显式带版本，覆盖关系
    /// 明确（新邀请永远压过旧记忆）。[`Self::open`] 不需要这一层：它只被 `update_popup_show` 以
    /// remind 态调用，且那时会话刚 `new` 出来、`last_state` 为空。
    pub fn send_state(&mut self, mut state: UpdatePopupState) -> Result<(), String> {
        if state.version.is_none() {
            state.version = self.last_state.as_ref().and_then(|s| s.version.clone());
        }
        if state.include_prerelease.is_none() {
            state.include_prerelease = self.last_state.as_ref().and_then(|s| s.include_prerelease);
        }
        let height_changed = self.last_state.as_ref().map(|s| s.height()) != Some(state.height());
        let height = state.height();
        // 先写：任何推送失败都不得让 last_state 失同步（#300 的核心教训）。
        self.last_state = Some(state);
        if height_changed {
            self.transport.set_content_height(height)?;
        }
        // unwrap 安全：上一行刚写入 Some。
        let s = self.last_state.as_ref().expect("last_state just written");
        self.transport.send_state(s)
    }

    /// 重放最后一次状态（= 上游 `did-finish-load` 的 `lastPopupState` 重放，`:596-599`）。
    ///
    /// 用 `.on` 而非 `.once` 语义：renderer 每次 reload / 崩溃重建都重放，覆盖崩溃自愈。
    /// 返回 `Ok(false)` = 无可重放状态（本移植下**不可达**：`open` 必然已 seed；保留返回值
    /// 供宿主断言，作为不变式被破坏时的哨兵）。
    ///
    /// # Errors
    ///
    /// 透传推送失败。
    pub fn replay(&self) -> Result<bool, String> {
        match &self.last_state {
            Some(s) => {
                self.transport.send_state(s)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// 最后一次状态（宿主/测试断言用）。
    #[must_use]
    pub fn last_state(&self) -> Option<&UpdatePopupState> {
        self.last_state.as_ref()
    }

    /// 会话是否已 seed（#300 不变式的直接断言点）。
    #[must_use]
    pub fn is_seeded(&self) -> bool {
        self.last_state.is_some()
    }

    /// 清状态（关窗；= 上游 `closed` 事件后重置）。
    pub fn reset(&mut self) {
        self.last_state = None;
    }

    /// 取推送通道（宿主取回以关窗等）。
    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// 构造注入脚本：把初始状态序列化进 `window.__POLARIS_UPDATE_POPUP_INITIAL__`。
    ///
    /// 序列化用 `serde_json`，故 JSON 内的 `<`/`</script>`/引号等已被转义为合法 JSON 字面量；
    /// 且本脚本经 Tauri `initialization_script` 注入（**不是**拼进 HTML 文本），不存在
    /// `</script>` 提前闭合的注入面。状态内容全部来自本地 manifest / 版本号 / 本地化文案，
    /// 但仍按不可信输入处理（`version` 取自远端 GitHub tag）。
    fn build_init_script(state: &UpdatePopupState) -> String {
        // serde_json 对本结构不可能失败（全 Plain Old Data，无 Map<非字符串键>/非有限浮点）；
        // 万一失败也必须给页面一个可渲染的初始态 —— 绝不产出「无 bootstrap 的窗」（那正是 #300）。
        let json = serde_json::to_string(state).unwrap_or_else(|_| {
            r#"{"phase":"error","errorCode":"downloadFailed","errorDetail":"popup bootstrap serialization failed"}"#.to_string()
        });
        format!("window.__POLARIS_UPDATE_POPUP_INITIAL__ = {json};")
    }
}

#[cfg(test)]
mod tests;
