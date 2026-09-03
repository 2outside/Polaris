//! 应用自更新：检查、摘要校验下载、安装、跳过与 mini-popup。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};

use serde_json::{json, Value};
use tauri::{AppHandle, Manager, State};
use tauri_plugin_shell::ShellExt;

use super::{fetch_releases_json, updater_downloader};
use crate::response::{ok_void, ApiResponse};
use crate::runtime::update_popup::{close_update_popup, show_update_popup};
use crate::runtime::{update_install, AppRuntime};
use crate::startup::QuitState;
use polaris_updater::github::{
    check_app_update, resolve_current_app_release, strip_v, AppUpdateCheck, AssetArch,
    AssetPlatform, APP_UPDATE_REPO,
};
use polaris_updater::popup::{
    PopupAction, UpdateErr, UpdateErrCode, UpdatePopupState, DONE_AUTO_CLOSE_MS,
    NO_UPDATE_AUTO_CLOSE_MS,
};
use polaris_updater::state::PopupPhase;
use polaris_updater::traits::UnavailableDownloader;

// ── 宿主指针宽度绊线（非 64 位直接编不过）────────────────────────────────────────
//
// 本文件的写入闸全程以 `u64` 表达（`fileSize` / [`APP_UPDATE_MAX_BYTES`]），而
// [`CoreDownloader::with_max_bytes`](crate::runtime::http::CoreDownloader::with_max_bytes) 吃
// `usize` ⇒ 中间必有一次 `u64 → usize` 换算。在 <64 位宿主上装不下的闸值只能退到 `usize::MAX`，
// 也就是**把闸悄悄变成「不设闸」**：一个报 100 GiB 的 `fileSize` 会一路写到 ENOSPC，
// 而这恰恰是 [`APP_UPDATE_MAX_BYTES`] 自陈要防的那件事。
//
// 这条降级腿从未被测过（Polaris 三平台均为 64 位构建，CI 的交叉编译矩阵也只有 64 位目标），
// 与其留一条**静默**失效的闸，不如让非 64 位目标当场编不过 —— 失效面从「用户的盘被写满」
// 降到「构建期一条明确的错误」。
//
// 将来真要支持 32 位：不是放宽本绊线，而是把这些闸改成**全程 u64 比较、不经 usize**
// （即 `with_max_bytes` 也收 `u64`，读侧比较在 u64 上做）。
#[cfg(not(target_pointer_width = "64"))]
compile_error!(
    "polaris 的 App 更新写入闸以 u64 表达，非 64 位宿主上 `u64 → usize` 会退化成 usize::MAX（闸形同不设）。\
     支持 32 位前须先把 http.rs 的体积闸改成全程 u64 比较。"
);

/// 单次 GitHub releases 响应体上限（16 MiB；= 上游 `MAX_GITHUB_JSON_BYTES`：被劫持/WAF 回灌 GB 级
/// 响应会撞堆，流式超限即中断）。
pub(crate) const MAX_GITHUB_JSON_BYTES: usize = 16 * 1024 * 1024;

/// GitHub API 拉取**逐跳**超时（连接 + 读取，每跳各算一次）；= 上游 `fetchReleases` 的 15s 兜底
/// （防连接被静默吞永不 settle）。**注意它不是请求级上限** —— 见 [`CORE_CHECK_TOTAL_TIMEOUT_MS`]。
pub(crate) const GITHUB_FETCH_TIMEOUT_MS: u64 = 15_000;

/// 内核更新检查的**请求级总超时**（契约要求的 20s 整体兜底）。
///
/// 逐跳的 [`GITHUB_FETCH_TIMEOUT_MS`] 管不住多跳叠加（`safe_redirect_fetch` 最多 5 跳 ⇒ 最坏 90s），
/// 故在 [`core_update_check`](super::core_update::core_update_check) 外面再包一层整体 `timeout`。
pub(crate) const CORE_CHECK_TOTAL_TIMEOUT_MS: u64 = 20_000;

/// 结构化错误码：下载后端不可用（仅在 [`UnavailableDownloader`] 真被注入时才可能出现；
/// 生产注入的是 [`CoreDownloader`](crate::runtime::http::CoreDownloader)，故此码现只作为 trait 契约的映射目标保留）。
pub(crate) const CODE_HTTP_UNAVAILABLE: &str = UnavailableDownloader::CODE;
// `CODE_CORE_SWAP_UNWIRED`（"CORE_SWAP_NOT_WIRED"）随 `app_uninstall_all` 接线一并删除：
// 它是本文件最后一个「未接线」错误码，留着就是个没有生产调用方的死常量。
/// 结构化错误码：无可回滚的备份。
pub(crate) const CODE_NO_BACKUP: &str = "NO_CORE_BACKUP";
/// 结构化错误码：活核为第三方 fork，在线更新被硬闸拦下。
pub(crate) const CODE_FORK_BLOCKED: &str = "CORE_FORK_BLOCKED";
/// 结构化错误码：核基目录未注入（`init_base_dir` 未跑；理论上只在异常启动路径出现）。
pub(crate) const CODE_CORE_DIR_UNAVAILABLE: &str = "CORE_DIR_UNAVAILABLE";
/// 结构化错误码：检查更新**整体超时**（≠ 网络失败：重试大概率还是超时，UI 应引导配置加速）。
pub(crate) const CODE_CHECK_TIMEOUT: &str = "UPDATE_CHECK_TIMEOUT";

/// 一帧 App 更新进度**及其随行事实**。
///
/// # 为什么是枚举，而不是 `(status, percentage, path, bytes, …)` 一串平行形参
///
/// `update:progress` 走 [`crate::events::broadcast`] fan-out 给**所有**窗口，于是「别的窗口发起的
/// 下载」（启动腿 `startup_tasks::spawn_auto_download`、弹窗腿 `update_popup_action`）同样会把
/// **设置页**推进 downloading/downloaded/error。而在本类型出现之前，事件只搬「状态」、不搬状态
/// 所依赖的数据，设置页只能拿本页上一次检查的结果去描述别人刚下的那个包 —— 后果是三条已核实的
/// 缺陷：「重启并安装」按钮首行 `if (!downloadedPath) return` 恒早退（哑键）、「重试」按钮首行
/// `if (!updateInfo) return` 恒早退（哑键）、卡片上的版本号与体积写的是另一个版本。
///
/// 修法是让**态与其随行事实同行**，并且由**类型**保证同行：`Downloaded` 不给落位路径就构造不
/// 出来，`Downloading` 不给已收字节就构造不出来。平行形参表达不了这条 —— `("downloaded", 100,
/// None, None)` 照样编译通过，只能另加一道源码级门去数，而那种门是后加的、可被新写法绕开。
///
/// # ⚠️ 类型挡不住的三样（如实登记，2026-08-17 复审补）
///
/// 「必填」只保证**字段在**，不保证**值可用**。以下三条今天在生产上都不可达，方向也安全，
/// 但别把本类型读成「构造得出来就一定对」：
///
///  1. `Downloaded { path: Path::new("") }` —— 空串照样是合法的 `&Path`，而前端
///     `if (!downloadedPath) return` 对空串同样早退 ⇒ 哑键原样复发。生产的两个构造点传的都是
///     `&dest`（`dir.join(&file_name)`，`file_name` 经 `unwrap_or_else` 兜底非空），够不着。
///     要挡得住得上 newtype（`NonEmptyPath`），代价与收益不成比例。
///  2. `Downloading { percentage: 200 }` —— [`stage_facts`] 原样透传。生产只有两个来源：字面量
///     `0`，与 [`progress_percent`] 的 `clamp(1, 99)`。同上，挡它要 newtype。
///  3. **给已有变体加字段**曾经会被 `..` 静默吃掉（三处解构都写 `{ .., }` ⇒ 加字段三处全不红、
///     载荷里不出现、跨语言对拍也不红）。**这一条已修**：三处解构一律写成逐字段绑定
///     （不需要的写 `_`），加字段现在是编译错误。「加变体被挡住了、加字段没有」这个不对称
///     由此消掉 —— 留这段是为了让下一个想图省事改回 `..` 的人看见代价。
#[derive(Clone, Copy)]
pub(super) enum ProgressStage<'a> {
    /// 下载中：本帧的百分比 + **已收字节**（下载刚开始那一发是 `0 / 0`）。
    Downloading { percentage: u8, received: u64 },
    /// 已落位：包在盘上的路径 + 摘要是否逐字节校验过（与 `update_download` 回包的 `verified`
    /// 同一真值）。**路径是必填的**：设置页的「重启并安装」拿的就是它。
    Downloaded { path: &'a Path, verified: bool },
    /// 失败：机器码 + 诊断串（U1。此前是硬编码中文正文，i18n 模块文档登记的出口 #1/#2；
    /// 现在本地化在前端按 [`UpdateErrCode::wire`] 取键完成，`detail` 是语言中性的诊断数据）。
    Failed(UpdateErr<'a>),
}

/// 纯派生：一帧的 `(status, percentage)`。事件载荷与弹窗镜像共用同一份派生 ——
/// 两处各写一遍必然漂出「设置页说 100%、弹窗说 99%」这种同源不同话。
///
/// `percentage` 在两个终态上是**由类型定死的**：`Downloaded` 恒 100、`Failed` 恒 0，
/// 调用点没有把它写错的余地（此前是每个调用点自己传一个数）。
///
/// 第三格（`message`）在 U1 拆掉了：失败的正文本地化移到渲染端，这里只派生与文案无关的
/// 两个字段；错误码/诊断串由 [`progress_payload`] / [`popup_state_for`] 直接从
/// `Failed(UpdateErr)` 逐字段取——`UpdateErr` 的字段即契约。
///
/// **不用 `..` 通配**（本函数与 [`progress_payload`] 及其行为门的解构一律逐字段写）：`..` 会把
/// 「给已有变体新加一个字段」静默吃掉 —— 三处都不红、载荷里不出现、跨语言对拍也不红。写成
/// `received: _` 之后，加字段是编译错误。
pub(super) const fn stage_facts(stage: ProgressStage<'_>) -> (&'static str, u8) {
    match stage {
        ProgressStage::Downloading {
            percentage,
            received: _,
        } => ("downloading", percentage),
        ProgressStage::Downloaded {
            path: _,
            verified: _,
        } => ("downloaded", 100),
        ProgressStage::Failed(UpdateErr { code: _, detail: _ }) => ("error", 0),
    }
}

/// 进度帧**不带**的清单字段（其余一律原样带过）。
///
/// # 为什么是「剥两个」而不是「留几个」
///
/// 剥除表的失效方向是**多带**（上游将来加一个大字段没被剥 ⇒ 帧胖了，性能退化，正确性零损失）；
/// 白名单的失效方向是**漏带**（消费方要的字段没在表里 ⇒ 「重试」重新变哑键、卡片又开始显示别的
/// 版本）—— 后者正是本批立项要修的那三条缺陷。判据面同样是枚举，但两者的**失效代价不对称**，
/// 故取失效安全的那一侧。
///
/// 逐条依据（均已核实，非估算）：
///  - `releaseNotes` = GitHub release body 原文，**无截断**（GitHub 单 body 上限 125 KB）。它只在
///    「已发现新版本」那一屏渲染（`SettingsUpdate.tsx` 的 `available` 态，且本就写着
///    `{updateInfo.releaseNotes && …}`），而 `available` **不可能**由进度帧进入 ——
///    `PROGRESS_CARD_RULE` 的取值里没有它，两侧状态集合由跨语言门对拍。
///  - `title` 全仓**零消费点**（前端 grep 已核：`title:` 的命中全是 i18n 对话框标题）。
///
/// 不剥的后果是具体的：一次下载最多 ~100 帧 × 所有窗口，20 KB 的 release notes ⇒ 约 2 MB 在
/// webview 主线程反序列化。**这是及时性问题，不是省内存**：进度条本身就是要「现在」到。
pub(super) const PROGRESS_MANIFEST_OMITTED: [&str; 2] = ["releaseNotes", "title"];

/// 取清单在进度帧里的投影：删掉 [`PROGRESS_MANIFEST_OMITTED`]，**其余一个字段都不动**。
///
/// 非对象（理论上不可达：三条调用腿传的都是 `update_check` 的 `updateInfo`）原样返回 ——
/// 宁可把说不清的东西原样递过去，也不伪造一个空对象。
pub(super) fn progress_manifest(info: &Value) -> Value {
    let Some(obj) = info.as_object() else {
        return info.clone();
    };
    let mut out = obj.clone();
    for key in PROGRESS_MANIFEST_OMITTED {
        out.remove(key);
    }
    Value::Object(out)
}

/// 纯函数：把一帧 + 它描述的那份发布清单拼成 `update:progress` 的载荷。
///
/// 形状：`{status, percentage, message, updateInfo, error?, receivedBytes?, filePath?, verified?}`
/// （与前端 `UpdateProgress` 契约逐字对齐；两侧的字段集由
/// `ui/src/contracts/update-progress-payload.test.ts` 做**双向**对拍）。
///
/// `updateInfo` 恒在：它是形参而不是可选项，故不存在「发了个态却没说是哪份包」的帧。带的是
/// [`progress_manifest`] 的投影（剥掉两个只在 `available` 那一屏渲染、且体积无上限的字段），
/// 其余字段一律原样 —— 「不丢字段」在剩下的字段上仍逐字成立。
///
/// 抽成纯函数是为了**可测**：[`emit_progress`] 持 `AppHandle`，单测构造不出 Tauri 运行时，
/// 判据留在里面就只剩源码级守卫，而那守得住「写没写那一行」，守不住「写出来的是什么」。
pub(super) fn progress_payload(info: &Value, stage: ProgressStage<'_>) -> Value {
    let (status, percentage) = stage_facts(stage);
    let mut payload = json!({
        "status": status,
        "percentage": percentage,
        // 随行事实之一：这一帧描述的是**哪一份包**。设置页据此渲染版本号 / 体积 / 预发布档次，
        // 并在 error 态拿它重试 —— 没有它，那些数字说的是本页上一次检查的另一个版本。
        "updateInfo": progress_manifest(info),
    });
    // 失败帧带机器码 + 诊断串（U1）：正文在前端按 `update.err.<code>` 本地化，
    // `errorDetail` 是语言中性的技术数据。旧的 `message`/`error` 中文通道已拆。
    if let ProgressStage::Failed(UpdateErr { code, detail }) = stage {
        payload["errorCode"] = Value::String(code.wire().to_string());
        if let Some(d) = detail {
            payload["errorDetail"] = Value::String((*d).to_string());
        }
    }
    // 逐字段解构（不用 `..`）：给变体加字段时这里必须显式表态，否则编译红。成因见
    // [`ProgressStage`] 文档「类型挡不住的三样」第 3 条。
    match stage {
        ProgressStage::Downloading {
            received,
            percentage: _,
        } => {
            payload["receivedBytes"] = Value::from(received);
        }
        ProgressStage::Downloaded { path, verified } => {
            payload["filePath"] = Value::String(path.to_string_lossy().into_owned());
            payload["verified"] = Value::Bool(verified);
        }
        ProgressStage::Failed(UpdateErr { code: _, detail: _ }) => {}
    }
    payload
}

/// 广播 App 更新进度（`update:progress`）。
///
/// # 同一份进度也镜像进 mini 弹窗
///
/// 弹窗与设置页看的是**同一次下载**，各自维护一份进度必然漂移。故此处是唯一产地：广播事件之后，
/// 若弹窗会话存在就把同一真值转成对应的弹窗档位推过去（见 [`popup_state_for`]）。这也是
/// `progress`/`done`/`error` 三态**唯一**的产地 —— 在此之前全仓只有 `remind`
/// （`update_popup_show`）能产出，于是弹窗里点「更新」后窗内零反馈、`PopupAction::Cancel`
/// （仅 Progress 合法）结构性不可达。
pub(super) fn emit_progress(app: &AppHandle, info: &Value, stage: ProgressStage<'_>) {
    crate::events::broadcast(
        app,
        crate::events::channel::EVENT_UPDATE_PROGRESS,
        progress_payload(info, stage),
    );
    push_popup_state(app, popup_state_for(info, stage));
}

/// 纯映射：一帧下载进度 → 弹窗状态。**与 [`progress_payload`] 同参同源**。
///
/// # 为什么吃 `stage` 而不是吃压平后的 `(status, percentage, message)`
///
/// 本函数此前的形参是那三个标量 —— 于是**落位路径与版本号在那层压平里丢了**，`done` 只剩一个
/// 「完成」的状态字：既说不出下的是哪一版、落在哪儿，也让「复查回来没有可下的东西」能借用同一个
/// `UpdatePopupState::done()` 收场（弹窗照画「下载完成」+ 满格进度条，而一个字节都没下）。
/// 改吃 [`ProgressStage`] 之后，弹窗镜像与 `update:progress` 载荷读的是**同一个**类型化的帧 +
/// 同一份清单，两屏不可能各说各话；「未知 status」也不再是一种可达输入 —— 故本函数不再返
/// `Option`，弹窗态是**总**有的。
///
/// `remind` / `noupdate` 不在此映射内：前者由 `update_popup_show` 产出，后者由
/// [`update_popup_action`] 产出，都不是进度事件的产物。
///
/// **逐字段解构、不用 `..`**：给变体加字段时这里必须显式表态（同 [`progress_payload`] 的理由）。
#[must_use]
pub(super) fn popup_state_for(info: &Value, stage: ProgressStage<'_>) -> UpdatePopupState {
    match stage {
        ProgressStage::Downloading {
            percentage,
            received,
        } => UpdatePopupState::progress(
            percentage,
            Some(received),
            // 分母取本帧随行清单的 `fileSize`（与设置页下载卡右半边同源）。缺失/为 0 时
            // `UpdatePopupState::progress` 会把它当「分母未知」，渲染端只显示已收量。
            info.get("fileSize").and_then(Value::as_u64),
        ),
        ProgressStage::Downloaded {
            path,
            // `verified` 不进弹窗：它已在 `update:progress` 载荷里给设置页用了，而弹窗要为它多一句
            // 五语文案才说得清「校验过 / 没校验」——那是另一件事，本批不夹带。
            verified: _,
        } => UpdatePopupState::done(
            info.get("version")
                .and_then(Value::as_str)
                .map(str::to_string),
            path.to_string_lossy(),
        ),
        ProgressStage::Failed(UpdateErr { code, detail }) => {
            // U1：弹窗 error 态与事件载荷同源（同一个 `UpdateErr`），本地化在渲染端按
            // `updatePopup.err.<code>` 取键；`detail` 原样透传（语言中性的诊断数据）。
            UpdatePopupState::error(code, detail.unwrap_or(""))
        }
    }
}

/// 纯判定：当前处于 `phase` 的弹窗，该不该跟随一次进度事件。
///
/// **只有 `Progress` 跟随。** 这条闸的存在理由是「后台下载不得吃掉用户面前的提示」：
///
/// | 弹窗当前态 | 场景 | 跟随会怎样 |
/// |---|---|---|
/// | `Remind` | 启动检查到新版弹了提醒；此时 `autoDownloadUpdate` 的后台下载正在跑 | 提示被进度条顶掉，用户**再也看不到**「要不要更新」那一屏 |
/// | `Done` / `Error` | 终态，等自动关窗 / 等用户点重试 | 被一次无关下载改写成别的态 |
/// | `Progress` | 用户**刚在弹窗里点了「更新」**（该分支先手动推 `progress(0)`） | 正是要跟随的那一次 |
///
/// 于是「弹窗跟不跟随」由**用户是否亲手把它推进 progress** 决定，而不是由「碰巧有没有下载在跑」
/// 决定。`Retry`（error → 重试）同样先推 `progress(0)`，故重试链照常跟随。
#[must_use]
pub(super) const fn should_mirror_to_popup(phase: PopupPhase) -> bool {
    matches!(phase, PopupPhase::Progress)
}

/// 把状态推给弹窗（弹窗未开 / 不在 progress 态 → no-op，**绝不为了推状态而建窗**）。
pub(super) fn push_popup_state(app: &AppHandle, state: UpdatePopupState) {
    push_popup_state_inner(app, state, true);
}

/// 强制推送（绕过 [`should_mirror_to_popup`] 闸）：仅用于用户动作的**入口**那一发
/// —— 那一发正是把弹窗从 remind/error 推进 progress 的动作本身，闸对它恒 false。
pub(super) fn force_popup_state(app: &AppHandle, state: UpdatePopupState) {
    push_popup_state_inner(app, state, false);
}

pub(super) fn push_popup_state_inner(app: &AppHandle, state: UpdatePopupState, gated: bool) {
    let Some(rt) = app.try_state::<AppRuntime>() else {
        return;
    };
    let Ok(mut slot) = rt.updater().popup().lock() else {
        return;
    };
    let Some(session) = slot.as_mut() else {
        return; // 弹窗未开（用户只在设置页操作）→ 无处可推
    };
    if gated {
        let current = session.last_state().map(|s| s.phase);
        // `None` 不可达（`open` 必然 seed），保守按「不跟随」处理。
        if !current.is_some_and(should_mirror_to_popup) {
            return;
        }
    }
    if let Err(e) = session.reuse(state) {
        // 窗可能刚被关掉；`reuse` 已先写 last_state，重放兜底不受影响 → 只记 debug。
        log::debug!("弹窗状态推送失败（窗可能已关）: {e}");
    }
}

/// 纯函数：`(已收字节, Content-Length)` → **该发的百分比**（`None` = 本 chunk 不发事件）。
///
/// 三条规则，各有其因：
///  - 无 `Content-Length` / 为 0 → `None`：算不出分母就不发（**绝不**拿已收字节凑一个假分母，
///    那会让进度条一路 100% 再跳回去）。
///  - 结果被夹在 `1..=99`：`0` 由下载**开始前**那一发独占、`100` 由 `downloaded` 独占 ——
///    否则会出现「downloaded(100%) 之后又来一发 downloading(100%)」的倒退帧。
///  - 与 `last_pct` 相同 → `None`：**逐 chunk 发就是 IPC 洪水**（几 MB 的包上千个 chunk）。
///    按整数百分比去重后，一次下载最多 99 个事件。
#[must_use]
pub(super) fn progress_percent(received: u64, expected: Option<u64>, last_pct: u8) -> Option<u8> {
    let total = expected.filter(|t| *t > 0)?;
    let pct = (received.min(total) * 100 / total) as u8;
    let pct = pct.clamp(1, 99);
    (pct != last_pct).then_some(pct)
}

/// 构造下载进度回调：把 [`progress_percent`] 的判定接到 [`emit_progress`] 上。
///
/// 回调在下载 task 线程跑，故用 `Arc` + 原子游标（不是 `&mut`）。
///
/// `info` 按值收下（下载 task 的生命周期与本次调用解耦，借不了栈上的那份）——**一次下载克隆一次**，
/// 不是一帧一次。中间帧带的是回调给的 `received` 原值，**不是从百分比反推**的估算：百分比被
/// [`progress_percent`] 夹在 `1..=99` 且按整数去重，反推出来的字节数在每一帧上都是错的。
pub(super) fn download_progress_emitter(
    app: &AppHandle,
    info: Value,
) -> std::sync::Arc<crate::runtime::http::DownloadProgressFn> {
    use std::sync::atomic::{AtomicU8, Ordering};
    let app = app.clone();
    let last = std::sync::Arc::new(AtomicU8::new(0));
    std::sync::Arc::new(move |received, expected| {
        let prev = last.load(Ordering::Relaxed);
        if let Some(pct) = progress_percent(received, expected, prev) {
            last.store(pct, Ordering::Relaxed);
            emit_progress(
                &app,
                &info,
                ProgressStage::Downloading {
                    percentage: pct,
                    received,
                },
            );
        }
    })
}

/// 上游 `VERSION_GET_INFO`：版本信息（app + core 版本）。
///
/// ✅ **已接线**：app 版本取自 Tauri `package_info`；core 版本经 `UpdaterRuntime` 双读法的**展示读法**
/// （探测失败回落随包基线，= 上游 `getCoreVersion` 语义）；基线取自编译期嵌入的 `core-manifest.json`。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn version_get_info(app: AppHandle, state: State<'_, AppRuntime>) -> ApiResponse<Value> {
    let u = state.updater();
    ApiResponse::ok(json!({
        "appVersion": app.package_info().version.to_string(),
        "coreVersion": u.read_core_version(),
        "coreBaseline": u.bundled_core_version(),
    }))
}

// ── App 更新 ──

/// Windows 便携版的**形态标记文件名**（与 `polaris.exe` 同级，由 `.github/workflows/package.yml`
/// 的 `Build Windows portable zip` 步写进 zip 根，并在同一步开包核验确实打进去了）。
pub(super) const PORTABLE_MARKER: &str = "portable.marker";

/// 当前是否跑在 Windows 便携（loose）形态：**exe 同目录存在 [`PORTABLE_MARKER`]**。
///
/// # 为什么不能用 env（`PORTABLE_EXECUTABLE_DIR` / `PORTABLE_EXECUTABLE_FILE`）
///
/// 这两个变量是 **electron-builder 便携目标特有**的注入：它的便携版是一个自解压 NSIS stub，
/// 由该 stub 在拉起真 exe 之前设好它们。上游 由 electron-builder 打包，故白拿这份真值。
///
/// **Polaris 的便携版是 `Compress-Archive` 打的纯 zip，没有任何 stub**（`package.yml`
/// `Build Windows portable zip`：拷 exe + resources 后直接压缩）⇒ 这两个 env 在真机上
/// **恒不存在** ⇒ 便携用户恒被判成 installed 形态。这与选包器那半边是**同一个缺陷的两层**：
/// 判定层恒 false，选包层的便携分支即便修好也永不被走到；修任一层都不足以让便携用户拿到便携包。
///
/// 标记文件是本仓能给出的**确定性**判据：产出侧写、运行侧读，零依赖、不探注册表、不猜安装路径。
///
/// ⚠️ **已知边界（如实登记，不假装守住了）**：用户手动删掉标记文件后本函数判为 installed，
/// 该用户会重新被推安装器。方向是失败安全的那一侧（安装器能装、不会砸掉便携副本），
/// 但**没有任何自动手段能守住它** —— 兜底只有标记文件内写明的「勿删」。
///
/// **纯函数**（exe 路径注入，不读全局态）⇒ 可单测。
///
/// `pub(crate)`：`runtime/startup_tasks.rs` 的「自动下载更新」腿要在下载前预判资产形态，
/// 用的必须是**同一个**便携判据（各写一份 ⇒ 预判与实际安装形态漂移）。
pub(crate) fn is_portable_layout(exe_path: &std::path::Path) -> bool {
    exe_path
        .parent()
        .is_some_and(|dir| dir.join(PORTABLE_MARKER).is_file())
}

/// 已成功 detached 的安装脚本之后，才允许把退出交给调用方。
///
/// 错误原样交回且不触碰任何副作用；成功路径固定为先标记显式退出、再退出进程。把顺序收进
/// 这一个可注入控制流点，避免 command 侧的早退分支日后意外越过 spawn 预先置位。
pub(super) fn complete_detached_install<T, E>(
    detached_spawn: Result<T, E>,
    mark_quit: impl FnOnce(),
    exit: impl FnOnce(),
) -> Result<T, E> {
    let detached = detached_spawn?;
    mark_quit();
    exit();
    Ok(detached)
}

fn mark_explicit_update_quit(app: &AppHandle) {
    app.state::<QuitState>()
        .0
        .store(true, std::sync::atomic::Ordering::SeqCst);
}

fn exit_after_detached_update(app: &AppHandle) {
    app.exit(0);
}

/// App 更新通道不再是进程级常量：启动、托盘与前端入口均从 `appUpdateChannel` 解析。
/// mini 弹窗把产出提醒时的 `includePrerelease` 随会话保存，复查不得重新读取可能已变化的配置；
/// 版本内容仍由下方的逐字对账处理，两个约束共同保证“提示哪个版本，就下载哪个版本”。
/// 上游 `UPDATE_CHECK`：检查应用更新。
///
/// ✅ **检查侧已接线**：经 `runtime/http.rs` 的真实 client（`state.http()`）走**同一条**
/// SSRF 安全路径 [`safe_redirect_fetch`](polaris_net_stack::safe_redirect::safe_redirect_fetch)（首 URL + 每跳 Location 都过 `assert_host_allowed`）拉
/// `2outside/Polaris` 的 releases → `polaris_updater::check_app_update` 纯逻辑转换（过滤 prerelease /
/// 按 `published_at` 挑最新 / `compare_semver` 判新 / 平台架构资产选择 / skip 判定）→ 返
/// `{ hasUpdate, updateInfo? }`（`updateInfo` 字段与前端 `UpdateInfo` 契约逐字对齐）。
///
/// **代理策略**：本批走 `state.http()`（`no_proxy` 直连 client）。proxy 未运行时直连是合法回退
/// （C19 `resolve_update_proxy_target`：`update-in` 端口为 0 → 强制直连，自举友好）；「经 update-in 口
/// 拉取」需 `proxy.rs` 端口访问器（禁区，另批），而 GitHub API 公网可达，直连对「检查」已足够。
///
/// **失败语义**（B5 反伪造）：网络/SSRF/超时/非 2xx → `success:false`（前端 error 态显因），**绝不**
/// 把失败伪装成「已是最新」；无更新 / 无适配资产 / 已跳过 → `{ hasUpdate:false }`（诚实无更新）。
#[tauri::command]
pub async fn update_check(
    app: AppHandle,
    state: State<'_, AppRuntime>,
    include_prerelease: Option<bool>,
    include_current: Option<bool>,
) -> Result<ApiResponse<Value>, ()> {
    let include_pre = include_prerelease.unwrap_or(false);
    let include_current = include_current.unwrap_or(false);

    // 平台/架构：宿主真值注入纯逻辑（非三大目标平台 → 无适配包，如实报无更新）。
    let Some(platform) = AssetPlatform::from_os(std::env::consts::OS) else {
        return Ok(ApiResponse::ok(json!({ "hasUpdate": false })));
    };
    let arch = AssetArch::from_arch(std::env::consts::ARCH);
    // 运行形态（loose vs installed）：
    //  - Linux：`APPIMAGE` 由 AppImage 运行时注入（Electron/Tauri 通用，**真值**）。
    //  - Windows：exe 同级的便携标记文件（[`is_portable_layout`]）—— **不是** electron-builder
    //    的 `PORTABLE_EXECUTABLE_DIR`，那个在本仓恒不存在（成因见 [`is_portable_layout`] 文档）。
    //  - macOS：`.app` 恒 loose，但 mac 选包不看形态（只看架构），故传什么都不影响结果。
    let loose_form = match platform {
        AssetPlatform::Windows => std::env::current_exe().is_ok_and(|exe| is_portable_layout(&exe)),
        AssetPlatform::Linux => std::env::var_os("APPIMAGE").is_some(),
        AssetPlatform::Macos => false,
    };

    // await 前取出 owned 值（当前版本 / 跳过版本），fetch 不持 State 借用（同 icon.rs 纪律）。
    let current = app.package_info().version.to_string();
    let skipped = state.updater().state().skipped_version;

    let (owner, repo) = APP_UPDATE_REPO;
    let body = match fetch_releases_json(&state, owner, repo).await {
        Ok(b) => b,
        // U1/F1：msg 是信封正文（英文回落）兼 RecheckFailed 的 detail（语言中性诊断串）——
        // 不再用中文（曾渗进弹窗括注：ru/fa 用户看到本地化正文 + 整句中文括注）。
        Err(e) => return Ok(ApiResponse::err(format!("update check failed: {e}"))),
    };
    let checked = check_app_update(
        &body,
        &current,
        include_pre,
        skipped.as_deref(),
        platform,
        arch,
        loose_form,
    );
    match checked {
        Ok(AppUpdateCheck::Available(info)) => {
            let info_v = serde_json::to_value(&info).unwrap_or(Value::Null);
            Ok(ApiResponse::ok(json!({
                "hasUpdate": true,
                "updateInfo": info_v,
            })))
        }
        Ok(AppUpdateCheck::NoUpdate) if include_current => match resolve_current_app_release(
            &body,
            &current,
            include_pre,
            platform,
            arch,
            loose_form,
        ) {
            Ok(AppUpdateCheck::Available(info)) => {
                let info_v = serde_json::to_value(&info).unwrap_or(Value::Null);
                Ok(ApiResponse::ok(json!({
                    "hasUpdate": false,
                    "isCurrentVersion": true,
                    "updateInfo": info_v,
                })))
            }
            Ok(AppUpdateCheck::NoUpdate) => Ok(ApiResponse::ok(json!({ "hasUpdate": false }))),
            Err(e) => Ok(ApiResponse::err(format!(
                "failed to parse GitHub response: {e}"
            ))),
        },
        Ok(AppUpdateCheck::NoUpdate) => Ok(ApiResponse::ok(json!({ "hasUpdate": false }))),
        Err(e) => Ok(ApiResponse::err(format!(
            "failed to parse GitHub response: {e}"
        ))),
    }
}

/// 按**目标文件路径**的下载单飞闸（同一个 dest 同时只允许一条下载腿在飞）。
///
/// # 并发是默认流程，不是异常路径
///
/// `autoDownloadUpdate` 开启时，启动腿（`runtime/startup_tasks.rs` 的 `spawn_auto_download`）在后台
/// 下载的**同时**弹 remind 窗邀请用户点「更新」（[`update_popup_action`] 的 Update/Retry 分支）。
/// 两条腿写的是同一个 `<cache>/updates/<fileName>`。没有单飞时：
///  - 两次下载各自把字节写盘再 rename（tmp 唯一化后不会撕裂 dest，但仍是一份白下的流量）；
///  - **进度事件两个产地**互相镜像：后台腿完成时发的 `downloaded(100)` 会把用户正在看的弹窗提前推到
///    Done，百分比在两个游标之间来回跳。
///
/// 故后到者在此等待；等到之后若前一位已把**同一份**包落好（sha256 相符）就直接复用，不重下。
///
/// 表只持弱引用：并发下载共同持有强引用时，同一 dest 仍命中同一把锁；最后一个下载释放后，下一次
/// 取锁会驱逐失效项。这样容量只与**当前在途目标**相关，不与长会话里见过多少更新文件名相关。
pub(super) type DownloadGate = tokio::sync::Mutex<()>;
pub(super) type DownloadGateMap = HashMap<PathBuf, Weak<DownloadGate>>;

pub(super) fn keyed_download_gate(map: &mut DownloadGateMap, dest: &Path) -> Arc<DownloadGate> {
    map.retain(|_, gate| gate.strong_count() > 0);
    if let Some(gate) = map.get(dest).and_then(Weak::upgrade) {
        return gate;
    }
    let gate = Arc::new(DownloadGate::new(()));
    map.insert(dest.to_path_buf(), Arc::downgrade(&gate));
    gate
}

pub(super) fn download_gate(dest: &Path) -> Arc<DownloadGate> {
    static GATES: OnceLock<Mutex<DownloadGateMap>> = OnceLock::new();
    let map = GATES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = map.lock().unwrap_or_else(PoisonError::into_inner);
    keyed_download_gate(&mut guard, dest)
}

// ── App 更新包：期望摘要的来源（D1）────────────────────────────────────────────

/// 期望 sha256 的**来源**。当前**只有一级**（GitHub asset `digest`）。
///
/// # 为什么是枚举而不是「读一个字段」
///
/// 让「摘要是谁给的」成为**结果契约的一部分**（`digestSource` 回给前端 / 进日志）：出事时能追责
/// 到具体信任根，而不是只知道「校验过了」。这一条与「将来好不好扩展」无关，今天就有价值。
///
/// # ⚠️ 它**不是**「加一级只改一处」的形状（2026-08-16 订正）
///
/// 本段原写「加一级只需在 [`EXPECTED_DIGEST_SOURCES`] 里插一行」。**那句话不成立**，因为
/// [`DigestSource::field`] + `info.get(field)` 已经把来源的取法**锁死**成「`update_info` 顶层的一个
/// 字符串字段」，而 U3 要加的随包 `SHA256SUMS` 是**另一次网络下载 + 按资产名查表**：既不在
/// `update_info` 里，也不是一个纯函数拿得到的东西。U3 落地时必然要动本枚举、[`Self::field`]、
/// [`resolve_expected_digest`] 的签名，以及钉住当前表的那条单测。
///
/// **刻意不预先抽象**（YAGNI）：把 `field()` 换成 `extract(self, info, ctx)` 这类「每个来源自带
/// 取法」的形状，等于今天就为一个尚未落地、形态还会变的需求付设计税。留一条诚实的注释比留一个
/// 猜出来的抽象更有用 —— 本条注释本身就是 U3 的交接单。
///
/// **U3 已落地，但只落发布侧**（2026-08-17）：`SHA256SUMS` 现在**随每个 release 产出并有门守着**
/// （`.github/workflows/package.yml` 的 `Generate SHA256SUMS` + `scripts/verify-packaging.mjs` 的摘要门），
/// 而**消费侧刻意未接** —— 本枚举因此仍是单变体。判断与依据登记在
/// [`resolve_expected_digest`] 文档的「第 1 级已产出、消费侧未接」段，不在此重复。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DigestSource {
    /// GitHub release asset 的 `digest` 字段（经 `parse_asset_digest` 解析后放在 `updateInfo.sha256`）。
    GithubAssetDigest,
}

impl DigestSource {
    /// `updateInfo` 里承载该来源摘要的字段名。
    pub(super) const fn field(self) -> &'static str {
        match self {
            Self::GithubAssetDigest => "sha256",
        }
    }

    /// 回给前端 / 日志的来源标识（**如实标注摘要是谁给的**，便于事后追责到具体信任根）。
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::GithubAssetDigest => "githubAssetDigest",
        }
    }
}

/// 期望摘要来源的**优先级序**（靠前者优先）。当前只有一项：U3 的 `SHA256SUMS` 虽已在发布侧产出，
/// 消费侧**经判断不接**（依据见 [`resolve_expected_digest`] 文档末节），且它也不是「在这里插一行」
/// 就能接上的（成因见 [`DigestSource`] 文档的订正段）。
pub(super) const EXPECTED_DIGEST_SOURCES: [DigestSource; 1] = [DigestSource::GithubAssetDigest];

/// 一条选定的期望摘要。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExpectedDigest {
    pub(super) hex: String,
    pub(super) source: DigestSource,
}

/// 按 [`EXPECTED_DIGEST_SOURCES`] 的优先级挑第一条可用的期望摘要。
///
/// `Ok(None)` = 一条都没有：**不拒装**，降级为「Content-Length + `fileSize` 完整性校验 + 结果里
/// 如实标记未校验」（否则所有旧 release 都更新不了）。字段**整个缺失**是旧 release 的正常形态
/// （`AppUpdateInfo.sha256` 带 `skip_serializing_if = "Option::is_none"`），空串/纯空白同理。
///
/// # 两类「拿不到摘要」必须分开（本函数的全部难点）
///
///  - **本来就没有**（字段缺失 / 空串）→ `Ok(None)`，降级放行；
///  - **有，但不是个字符串**（`123` / `null` / `["…"]`）→ `Err`，**显式早退**。
///
/// 原实现两类都走 `Value::as_str` ⇒ 后者被**静默丢弃**成前者 ⇒ `verified:false` 放行 ——
/// 而本函数自己的文档写的正是「静默丢弃会把『摘要写坏了』伪装成『本来就没摘要』而放行」。
/// 一个把 `sha256` 序列化成数字的发布流程，本该当场炸掉、而不是让全体用户静默地少一道校验。
///
/// hex **格式**仍不在此校验（非法 hex 走到校验步报 `VerifyError::InvalidExpectedHash`，
/// 那里才分得出「发布方写坏了」与「包被篡改」两种文案）。
///
/// **纯函数**（吃 `Value`，无 IO）⇒ 可单测。
///
/// # 第 1 级（随包 `SHA256SUMS`）已产出，消费侧**经判断不接**（2026-08-17 登记）
///
/// 发布侧已落地：每个 release 都产出 `SHA256SUMS`，缺失/覆盖面不符/摘要不符任一即红
/// （`.github/workflows/package.yml` + `scripts/verify-packaging.mjs`）。本函数**仍然只看 asset
/// digest**，是判断结果，不是没做完。三条依据：
///
///  1. **增量价值的射程接近空集**。它只在「GitHub 没给 asset `digest`」∩「该 release 有
///     `SHA256SUMS`」这一个交集里有用。而 `SHA256SUMS` 从本轮才开始产出 ⇒ 有它的 release 都是
///     此后新发的 ⇒ 那些 release 的 asset `digest` 由 GitHub 在资产上传时算好、随
///     `update_check` 的同一次响应返回。老 release 两样都没有，接了也救不了。
///  2. **把它排在 asset digest 之前是拿弱的换强的**。两者防的都只是传输损坏与截断（都不防账号或
///     TLS 被攻破 —— 那需要签名，公钥内置于应用，属独立决策，本轮不做，也不假装 SHA 等价于它），
///     差别在**取它的那条腿会不会跟安装包一起被同一个中间人经手**：
///
///     - asset `digest` 随 `update_check` 从 `api.github.com` 的 JSON 到手，**不与安装包走同一个
///       host**，且由 GitHub 侧对已存字节算出；
///     - `SHA256SUMS` 是同一个 release 里的另一个**资产**，URL 与安装包同 host。
///
///     这不是权衡，是**结构性**的：镜像回落的判定面 `GITHUB_ASSET_HOSTS`
///     （`runtime/http.rs`）与前端的 `GH_HOSTS`（`ui/src/domain/gh-proxy.ts`）两侧独立实现、
///     **都显式排除 `api.github.com`** ⇒ API 腿结构性走不到 gh-proxy；而 `SHA256SUMS` 命中
///     `is_github_asset` ⇒ 真启用镜像时它会**跟安装包一起经同一个代理**。即恰恰在「启用代理、
///     信任面最大」的那个场景里，asset `digest` 的价值最高而 `SHA256SUMS` 的价值归零。
///
///     （措辞注：`github.rs` 的 `digest` 字段文档说「摘要与资产**同源**故不必自建密钥」，那句里的
///     「同源」指**信任根**都是 GitHub；本条说的「同 host」指**取回路径**。两个词各指一件事，
///     不要混读。）
///  3. **成本不是「插一行」**：要多一次网络往返（多一条会超时/被截断/被限流的失败腿）、要把本函数
///     从纯函数变成带 IO 的异步函数（现有这套纯函数单测随之作废）、要把清单 URL 从
///     `check_app_update` 一路穿到这里、还要动前端 `digestSource` 的字面量联合。付这些去覆盖第 1 条
///     那个近乎空的交集，是负收益。
///
/// **若将来要接**：正确形状不是「第 1 级」，而是 asset `digest` **缺失时的惰性回落** ——
/// 只在真正没摘要那条腿上多花一次往返，好路径一行不动。
///
/// **重开这个决定的触发条件**（有探测器，不靠人肉撞见）：GitHub 不再给 asset `digest`
/// —— 那一刻第 1 条的前提不成立，且客户端会静默降级成无摘要弱校验。发布流程里
/// `Verify published asset digests against SHA256SUMS` 那一步会在**发布当场**把它判红
/// （`.assets[].digest` 为空即红，release 停在草稿态），故这条触发条件是被机器盯着的，
/// 不必等用户在 UI 上看到 `verified:false`。
///
/// # Errors
///
/// 某一级来源的字段存在、但不是字符串。
pub(super) fn resolve_expected_digest(info: &Value) -> Result<Option<ExpectedDigest>, String> {
    for src in EXPECTED_DIGEST_SOURCES {
        let Some(raw) = info.get(src.field()) else {
            continue; // 字段缺失 = 旧 release 的正常形态。
        };
        let Some(hex) = raw.as_str() else {
            // U1：这是 errorDetail（诊断数据），语言中性；「绝不当成没摘要放行」的语义
            // 由 DigestFieldInvalid 的 locale 文案承担，这里只报事实。
            return Err(format!("{} field is not a string (got {raw})", src.field()));
        };
        let hex = hex.trim();
        if hex.is_empty() {
            continue; // 空串 / 纯空白 = 等同没有。
        }
        return Ok(Some(ExpectedDigest {
            hex: hex.to_string(),
            source: src,
        }));
    }
    Ok(None)
}

// ── App 更新包：写入体积闸（D4）────────────────────────────────────────────────

// `APP_UPDATE_SIZE_MARGIN`（声明值之上的 8 MiB 裕度）已删（2026-08-17）。
//
// 它自陈的唯一作用是「给清单 `fileSize` 与真实资产差一点点留条活路（改包名/重传后忘了同步清单
// 之类），免得一次人为疏忽把全体用户的更新卡死」。而**同批**新增的 [`check_declared_size`] 对
// `received != declared` 是**零容差**的等值判据 ⇒ 落在 `(declared, declared + 8 MiB]` 里的任何
// 差异都只有一条归宿：预检放行 → 白下满整包 → 等值判据拒绝。裕度已不存在任何「成功放行」的输入，
// 留着只会让人误以为清单写偏一点还能更新得动。
//
// 删掉裕度不会把「大小恰好等于声明值」的正常包卡掉，理由见 [`app_update_size_limit`] 头注
// （三处体积闸都是**严格大于**才拒）。

/// App 安装包写入闸的**绝对上限**（512 MiB）—— 不只是「清单没声明时的回落值」。
///
/// Polaris 三平台安装包在几十 MiB 量级，512 MiB 留了一个数量级以上的余量；
/// 它的职责只是「别让一个撒谎的服务端把盘写满」，不是精确判定。
///
/// # 为什么它必须同时压住**有**声明值的那条分支（原名 `APP_UPDATE_FALLBACK_MAX_BYTES`）
///
/// 原实现只在 `None`/`0` 分支用它，`Some(n)` 分支是 `n + 裕度` 且**不与任何上限取 min**：
/// `fileSize` 若是 100 GiB（发布流程写错 / GitHub 异常 / 前端构造的 `updateInfo`），闸值就是
/// 100 GiB ⇒ Content-Length 预检放行 ⇒ 一路写到 ENOSPC，用户系统盘被写满 —— 而这恰恰是本常量
/// 文档自陈要防的那件事。「回落值」这个名字本身就是那个洞的成因：它读起来只管一条分支。
pub(super) const APP_UPDATE_MAX_BYTES: u64 = 512 * 1024 * 1024;

/// App 安装包的写入闸取值。
///
/// # 陷阱：`fileSize` 为 0 不等于「包是空的」
///
/// [`AppUpdateInfo::file_size`](polaris_updater::github::AppUpdateInfo::file_size) 在 GitHub asset
/// 缺 `size` 字段时按 **0** 填（`github.rs` 的 `#[serde(default)]`）。直接拿它当闸 ⇒ 闸值 0，
/// **任何**包都过不去 —— 而且失败长得像「下载超限」，没人会想到成因是清单少了个字段。
/// 故声明值有效（`> 0`）才拿它当闸，为 0 / 缺失一律回落 [`APP_UPDATE_MAX_BYTES`]。
///
/// # 闸值就等于声明值，**不再加裕度**（2026-08-17 核实后删）
///
/// 「闸 == 声明值」不会把一个大小恰好等于声明值的正常包卡掉 —— 三处体积闸全是**严格大于**才拒
/// （实测源码，非推断）：
///  - Content-Length 预检：`runtime/http.rs` `open_download_response` 的 `if n > self.max_bytes`；
///  - 内存腿读侧：`read_body_capped_with_progress` 的 `if buf.len() + chunk.len() > limit`；
///  - 流式腿读侧：`read_body_to_sink_with_progress` 的 `if received + chunk.len() > limit`。
///
/// 这条边界本身有门钉着（`runtime::http` 的 `size_limit_boundary_admits_a_body_of_exactly_the_limit`
/// 逐处拿「恰好等于闸值」的响应体撞过），故三处任一被改成 `>=` 会先在那条门上转红，而不是等到
/// 真机上「更新永远差一个字节」。
///
/// 裕度被删的成因见上方注释块：同批的 [`check_declared_size`] 是零容差等值判据，
/// `(declared, declared + 裕度]` 区间里的输入无论如何都会被拒，裕度只是让它**多下满一个整包**。
///
/// # 两条分支都封在 [`APP_UPDATE_MAX_BYTES`] 之下
///
/// 声明值是**服务端给的数**，闸不能由它单方面顶到任意高（成因见该常量文档）。
///
/// **纯函数** ⇒ 三条路径各有单测。
pub(super) fn app_update_size_limit(declared: Option<u64>) -> usize {
    let limit = match declared.filter(|n| *n > 0) {
        Some(n) => n.min(APP_UPDATE_MAX_BYTES),
        None => APP_UPDATE_MAX_BYTES,
    };
    // 本回落（装不下 → usize::MAX）在受支持的宿主上**不可达**：本文件顶部的
    // `compile_error!` 已把非 64 位目标挡在编译期之外。保留 `try_from` 而不写 `as usize`，
    // 是因为 `as` 会**静默截断**成一个小值（闸比声明值还紧 ⇒ 正常包被拒）。
    usize::try_from(limit).unwrap_or(usize::MAX)
}

/// 发布清单声明的 `fileSize` 当**等值判据**（无摘要腿的硬化）。
///
/// # 为什么不能只靠 Content-Length
///
/// [`update_download`] 在无摘要时「回落 Content-Length 完整性校验」—— 但 Content-Length 是
/// **撒谎方自己给的数**，对撒谎方零约束：服务端/镜像返 `Content-Length: 1000` 且真发 1000 字节，
/// 完整性校验就过了，然后「无摘要 ⇒ 不校验」⇒ 一个 1000 字节的假包被 promote，返
/// `{success:true, verified:false}`，UI 给出安装入口。极端版 `Content-Length: 0` ⇒
/// 0 字节文件「下载成功」。
///
/// `fileSize` 来自 GitHub release 清单（与 `downloadUrl` 同一次 API 响应），镜像**改不动**它。
/// 故 `declared > 0` 时它是这条腿唯一有牙的等值判据 —— 零成本，且不影响旧 release
/// （缺 `size` 字段 ⇒ 0 ⇒ 不判，与本判据引入之前逐字一致）。
///
/// 判定委托 [`check_content_length`](crate::runtime::http::check_content_length)（同一条「实收 vs
/// 声明」判据，不另写一份）；本函数只负责 App 腿特有的 `> 0` 过滤。
///
/// # Errors
///
/// [`DownloadError::Incomplete`](polaris_updater::traits::DownloadError::Incomplete)：实收字节数
/// 与清单声明不符。
pub(super) fn check_declared_size(
    received: u64,
    declared: Option<u64>,
) -> Result<(), polaris_updater::traits::DownloadError> {
    crate::runtime::http::check_content_length(received, declared.filter(|n| *n > 0))
}

/// 流式下载的**部分写入残件**（tmp）的所有权凭证：**drop 即删**，落位成功才 [`Self::disarm`]。
///
/// 形态照 [`ExtractWorkDir`](super::core_update::ExtractWorkDir)（本文件既有的 RAII 清理守卫）：构造即持有、`Drop` 里尽力清、
/// 清理失败只记日志。差别只有一个 —— 本守卫多一个「解除」出口，因为落位成功后那个文件
/// **已经变成 dest 了**，再删就是把刚下好的包删掉。
///
/// # 为什么是类型，不是「数一数清理调用」的守卫
///
/// 改造之前下载失败**不产生任何磁盘残留**（字节只在内存里）。流式之后「网络失败 / 停滞 / 超限 /
/// 摘要不符 / 落位失败」每一条早退都会留下一个写了一半的 tmp，故 U1 曾配了一条源码级守卫
/// （`every_failure_path_after_staging_discards_the_partial_tmp`），数
/// 「`ApiResponse::err(` 出现次数 == `discard_partial_download(&tmp)` 出现次数」。
///
/// **那条守卫是假的**，三条独立反例，每条都能让「漏清理」照样全绿：
///  1. 把落位失败的早退降级成「只 log 不早退」⇒ 两侧计数**同减**，仍相等；
///  2. 给一条早退配**两次**清理即可把另一条漏掉的配平；
///  3. 它**不匹配** `ApiResponse::err_with_code(`（`err` 后面是 `_` 不是 `(`）—— tmp 之后新增
///     一条带 code 且漏清理的早退，守卫全盲。
///
/// 计数守卫守的是「代码里有没有写那一行」，而不变量是「控制流离开这个作用域时残件在不在」。
/// 后者是**作用域**的性质，只有类型（`Drop`）表达得了：`?`、panic、以及任何将来新增的早退
/// 都自动被覆盖，不需要任何人记得配一行清理，也就没有「配平」可言。
pub(super) struct PartialDownload {
    /// `None` = 已解除（落位成功，那个 inode 现在叫 dest 了）⇒ `Drop` 不再删。
    tmp: Option<PathBuf>,
}

impl PartialDownload {
    pub(super) fn new(tmp: PathBuf) -> Self {
        Self { tmp: Some(tmp) }
    }

    /// 残件路径。
    ///
    /// [`Self::disarm`] **消费 self** ⇒ 能调到本方法的实例必然还持着路径，`expect` 不可达。
    pub(super) fn path(&self) -> &Path {
        self.tmp
            .as_deref()
            .expect("PartialDownload 在 disarm 之后被使用（不可达：disarm 消费 self）")
    }

    /// 解除清理（**仅落位成功后**调）：tmp 已被 rename 成 dest，再删就是删掉成品。
    pub(super) fn disarm(mut self) {
        self.tmp = None;
    }
}

impl Drop for PartialDownload {
    fn drop(&mut self) {
        use polaris_updater::traits::UpdateFs;
        let Some(tmp) = self.tmp.take() else {
            return; // 已解除：落位成功，什么都不该删。
        };
        // `StdFs::remove_file` 把「文件不存在」视作成功，故「还没来得及建文件就失败」是 no-op。
        // 清理失败只记日志不改变结论：本守卫恒在一条**已经失败**的路径上析构，
        // 让清理错误盖掉真正的失败成因是本末倒置。
        if let Err(e) = polaris_updater::traits::StdFs.remove_file(&tmp) {
            log::warn!("清理更新包临时文件失败 {}: {e}", tmp.display());
        }
    }
}

/// 落位结论（[`land_payload`] 的产物）。**不含任何事件语义** —— 发不发 `downloaded` 由调用方按
/// 本枚举分支决定，这正是把它抽出来的全部目的。
#[derive(Debug, PartialEq, Eq)]
pub(super) enum LandingOutcome {
    /// rename 成功，dest 现在是一个完整文件。
    Landed,
    /// 落位失败（dest 未动）。载荷是给用户看的成因。
    Failed(String),
}

/// tmp → dest 的落位**纯编排**（吃 `&dyn UpdateFs` ⇒ 可注入失败，可单测）。
///
/// # 为什么这一步必须是可注入的运行时判据，而不是一条文本守卫
///
/// 「`downloaded` 只在 rename 成功之后发」此前由一条**文本下标比较**守着
/// （`promote_staged(` 的位置 < 发 `ProgressStage::Downloaded` 的位置）。那条守卫表达不了
/// 「rename **成功**才执行」：把落位失败的早退降级成「只 log 不早退」，文本序**照样成立**，
/// 而运行时会在 rename 失败时广播 `downloaded(100)` 外加一个**根本不存在**的 `filePath` ——
/// 设置页据此给出一个点不开的安装入口。
///
/// 分成「判定」与「发事件」两半之后，判定这一半吃 trait、可注入 `MockFailOp::Rename`，
/// 于是「rename 失败时 dest 必须不存在、结论必须是 Failed」变成一条**运行得起来**的断言。
///
/// # rename **之前**先 `fsync` 文件（2026-08-17 新增）
///
/// 此前这一步是纯「写完 → rename」，中间没有任何 `sync`。rename 只保证**目录项**的原子替换，
/// 不保证被替换的那个 inode 的**数据**已经离开 page cache ⇒ 断电 / 内核崩溃后完全可能出现
/// 「dest 这个名字在、内容是零或半截」。而 dest 一旦存在，[`cached_download_is_reusable`]
/// （摘要对不上 → 重下，还算好）与 [`update_install()`]（**直接拿去装**）都会把它当成完整包。
/// sync 失败按落位失败处理：残件由 [`PartialDownload`] 守卫在调用方的早退上清掉。
///
/// # 已知限制：**不做目录级 fsync**（如实登记，本批刻意不做）
///
/// 严格的崩溃一致性还需要在 rename **之后** `fsync` 父目录，否则崩溃后可能丢失那条目录项。
/// 本批不做，因为两种失效的后果不对称：
///  - 少了**文件级** fsync ⇒ 可能产生「名字在、内容是半截」的 dest ⇒ 装一个坏包（**这是本次修的**）；
///  - 少了**目录级** fsync ⇒ 最坏只是那次 rename 没落盘，dest 干脆不存在 ⇒ 退化成「更新包不见了」，
///    下次进 [`update_download`] 会重下一遍。**不会**产生半截包。
///
/// 即目录级 fsync 换来的是「少重下一次」，而文件级 fsync 换来的是「不装坏包」。要补目录级
/// fsync 还得在 `UpdateFs` 上再开一个 `sync_dir`（Windows 上没有可移植的目录句柄 fsync 等价物，
/// 得走 `FlushFileBuffers` on volume handle 这类平台分支）—— 半径与收益不成比例。
pub(super) fn land_payload(
    fs: &dyn polaris_updater::traits::UpdateFs,
    tmp: &Path,
    dest: &Path,
) -> LandingOutcome {
    // 先刷盘再改名：顺序不可换（换了就等于没做 —— 崩溃窗口正好在 rename 之后）。
    if let Err(e) = fs.sync_file(tmp) {
        // U1：LandingOutcome 的串只作 errorDetail（诊断数据），语言中性。
        return LandingOutcome::Failed(format!("fsync {}: {e}", tmp.display()));
    }
    match polaris_updater::verify::promote_staged(fs, tmp, dest) {
        Ok(()) => LandingOutcome::Landed,
        Err(e) => LandingOutcome::Failed(format!("rename to {}: {e}", dest.display())),
    }
}

/// 孤儿 tmp 的存活阈值（24h）：**跨进程**残件早于此才删。
///
/// 为什么是 mtime 而不是 pid 存活探测：跨平台判「这个 pid 还活着吗」不可靠（Windows 无
/// `kill(0)` 等价物、pid 复用），而判错的代价是删掉另一个实例正在写的文件。mtime 阈值判错的
/// 代价只是「多留一天」。
pub(super) const ORPHAN_TMP_MAX_AGE: std::time::Duration =
    std::time::Duration::from_secs(24 * 60 * 60);

/// tmp 命名族的中缀 —— 与 [`verify::tmp_name`](polaris_updater::verify::tmp_name) 生成的
/// `{dest}.polaris-new-{pid}-{seq}` 逐字对齐。
pub(super) const ORPHAN_TMP_INFIX: &str = ".polaris-new-";

/// 纯判定：这个文件名是不是 [`verify::tmp_name`](polaris_updater::verify::tmp_name) 的产物。
///
/// 判据 = 含 [`ORPHAN_TMP_INFIX`]，且其后是 `{pid}-{seq}` 形态（两段都非空、都是纯十进制数字）。
/// **不**只看中缀：一个用户自己放的 `notes.polaris-new-draft` 不该被当成在飞下载的残件删掉。
/// 取**最后**一次中缀出现（`rsplit_once`）：`tmp_name` 是往 dest 名末尾追加，故末段才是它写的那一截。
pub(super) fn is_orphan_tmp_name(name: &str) -> bool {
    let Some((_, tail)) = name.rsplit_once(ORPHAN_TMP_INFIX) else {
        return false;
    };
    let Some((pid, seq)) = tail.split_once('-') else {
        return false;
    };
    !pid.is_empty()
        && !seq.is_empty()
        && pid.bytes().all(|b| b.is_ascii_digit())
        && seq.bytes().all(|b| b.is_ascii_digit())
}

/// 清扫 `dir` 下的**孤儿** tmp 残件（best-effort，失败只记日志）。
///
/// # 主触发器不是崩溃，是「下载途中退出 App」
///
/// [`update_download`] 是 **async command**：tmp 建立之后唯一的 await 点是
/// `spawn_blocking(...).await`。用户在下载完成前退出 App ⇒ tauri runtime **drop 掉那个 future**
/// ⇒ 从 [`PartialDownload`] 的 `Drop` 到各条早退，**全部被绕过**（future 被 drop 时局部变量确实
/// 会析构，但 `spawn_blocking` 的 blocking 线程**不可取消**，它会继续把 tmp 写完 —— 于是残件在
/// 守卫析构之后才出现）。开着 `autoDownloadUpdate` 时，每个「启动 → 后台下载 → 用户在完成前
/// 关 App」周期必留一个几十 MiB 的孤儿，而全仓唯一会碰这个目录的回收点是**完全卸载**
/// （`app_uninstall_all`）—— 长期累积到 GB 级。
///
/// 注意 `verify::tmp_name` 文档里那条「换核暂存目录每次 stage 整目录重建会一并清掉」的兜底
/// **只对换核腿成立**：App 更新落在 `<cache>/updates/`，没有任何整目录重建（该注释已一并订正）。
///
/// # 匹配面是**命名族**，不是「本次资产名」（2026-08-17 订正）
///
/// 原实现的前缀是 `{file_name}.polaris-new-` —— 只收**本次资产名**的残件。而 App 更新的资产名
/// 里带版本号（`Polaris_0.3.0_x64.dmg`），版本一换前缀就变，于是上面那个主触发器留下的残件
/// （必然是**旧版本名**的：这次要下的是新版本）**永远收不回来**，直到用户完全卸载 ——
/// 本函数自陈要防的那件事，恰好落在它的射程之外。
///
/// 故匹配面改成整个 `.polaris-new-` 命名族（判据见 [`is_orphan_tmp_name`]），不限资产名。
///
/// # 判据分两档（都不探测别的进程死活）
///
///  - **本次资产名 + 本 pid**：调用点在**单飞闸之内**，而闸按 dest 加锁 ⇒ 此刻本进程绝无第二条腿
///    在写同一个 `file_name` 的 tmp ⇒ 直接删（不看 mtime）。
///  - **其余全部**（别的资产名 / 别的 pid / 上次运行留下的）：只按 [`ORPHAN_TMP_MAX_AGE`]（≥24h）
///    删。读不到 mtime 一律当「新鲜」保留（失败安全的那一侧）。
///
/// 两档的边界就是单飞闸的射程：**闸只按 dest 串行**，管不到别的资产名 —— 本进程完全可能有另一条腿
/// 正在下另一个资产（版本回退、或用户手动触发了别的包），把「别的资产名」也放进即时档就会删掉
/// 一个在飞的下载。反过来，超过 24h 的残件不可能还是在飞下载（下载腿自带 30s 停滞看门狗 +
/// 15s 逐跳超时），故陈旧档对**任何** pid、**任何**资产名都安全。
///
/// 目录遍历走 [`UpdateFs::list_files`](polaris_updater::traits::UpdateFs::list_files)（它只列文件、
/// 跳过子目录）而不是手搓 `read_dir`：本函数因此可注入 `MockFs` 测试，也不会在 FS 抽象层上开
/// 第二个口子。mtime 不在 trait 面上（那是 trait 刻意不管的东西），故只对**需要**它的那一档
/// 读一次 `std::fs::metadata`。
///
/// 零新增依赖；失败一律吞掉（清扫是附带收益，**绝不**改变本次下载的结论）。
pub(super) fn sweep_orphan_downloads(
    fs: &dyn polaris_updater::traits::UpdateFs,
    dir: &Path,
    file_name: &str,
) {
    // 即时档的前缀：本次资产名 + 本进程 pid（两者都对上才走即时删）。
    let self_prefix = format!("{file_name}{ORPHAN_TMP_INFIX}{}-", std::process::id());
    let Ok(names) = fs.list_files(dir) else {
        return; // 目录不存在 / 读不动：不是本次下载的问题，静默跳过。
    };
    let now = std::time::SystemTime::now();
    for name in names {
        if !is_orphan_tmp_name(&name) {
            continue; // 不是 tmp 命名族（含落位好的成品）。
        }
        let path = dir.join(&name);
        if !name.starts_with(&self_prefix) {
            // 别的资产名 / 别的 pid：只按 mtime 阈值收。读不到时间 → 当新鲜 → 保留。
            let stale = std::fs::metadata(&path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| now.duration_since(t).ok())
                .is_some_and(|age| age >= ORPHAN_TMP_MAX_AGE);
            if !stale {
                continue;
            }
        }
        match fs.remove_file(&path) {
            Ok(()) => log::info!("已清理更新包孤儿残件: {}", path.display()),
            Err(e) => log::debug!("清理更新包孤儿残件失败 {}: {e}", path.display()),
        }
    }
}

/// 纯判定（吃真实 FS）：已落盘的更新包能否被单飞的**后到者**直接复用。
///
/// 判据只有一条：文件在 **且** sha256 与本次期望相符。
///
/// **缺 sha256 时一律不复用**（返 false）：没有判据就不能声称「磁盘上这份就是你要的包」——
/// 旧 release 的 asset 没有 `digest` 字段，那种情况老老实实重下一遍，不拿文件名当身份。
///
/// # 摘要走流式（与下载腿同一个根因）
///
/// 原实现是 `std::fs::read(dest)` —— 为了一个 64 字节的判定，把整个安装包搬进内存。
/// 这与「下载时整包入内存」是**同一条缺陷的另一条腿**：下载腿改流式后若不一并修，
/// 单飞的后到者仍会在复用探测这一步把内存顶到包体积。判定结论逐字不变
/// （格式非法 / 摘要不符 / 文件不在 → 一律 false）。
///
/// # 比对委托 [`verify_hex_digest`](polaris_updater::verify::verify_hex_digest)（全 crate 单点）
///
/// 末行原本是手搓的 `actual.eq_ignore_ascii_case(sha)` —— 那是绕开该单点的第 4 处判定，
/// 而它的文档明写着不许手搓（两个变体处置相反，手搓必然把分野压成一个 bool）。本函数只需要
/// bool，但「只需要 bool」不是各写一份比较逻辑的理由：分叉只会在「大小写敏不敏感」
/// 这类地方发生，且只在真机大包上暴露。
///
/// 前置的 [`is_valid_sha256_hex`](polaris_updater::verify::is_valid_sha256_hex) 早退**保留**，
/// 理由与 `verify_bytes` 里那句「先验格式再算摘要」相同：期望值本身非法时，不该为一个必然
/// 返 false 的判定，白读一遍几十 MiB 的文件算流式摘要。
pub(super) fn cached_download_is_reusable(dest: &Path, expected_sha: Option<&str>) -> bool {
    let Some(sha) = expected_sha.map(str::trim).filter(|s| !s.is_empty()) else {
        return false;
    };
    if !polaris_updater::verify::is_valid_sha256_hex(sha) {
        return false;
    }
    let Ok(file) = std::fs::File::open(dest) else {
        return false;
    };
    let Ok(actual) = polaris_updater::verify::sha256_reader_hex(std::io::BufReader::new(file))
    else {
        return false;
    };
    polaris_updater::verify::verify_hex_digest(&actual, sha).is_ok()
}

/// 上游 `UPDATE_DOWNLOAD`：下载更新包到本地缓存目录。
///
/// ✅ **已接线**：复用 [`CoreDownloader`](crate::runtime::http::CoreDownloader)（**唯一**下载适配器：重定向跟随 / UA / Content-Length 完整性 /
/// 停滞看门狗 / 镜像回退 / 16MiB 闸 / 15s 超时 / 403 限流分类），**不在此复制第二份编排**
/// —— 上游的 `core-downloader.ts` 与 `UpdateService.ts` 各写 ~170 行同构编排正是前车之鉴。
///
/// # 流式落盘（**不再把整包读进内存**）
///
/// 字节从网络下来即写进 `dest` 旁的同目录临时文件（`verify::tmp_name`），sha256 由
/// `verify::Sha256Stream` **边写边算**，全部收完且摘要相符后经 `verify::promote_staged`
/// 一次原子 rename 提升为 dest。内存占用与包体积**解耦**（原实现的 `Vec<u8>` 峰值 = 包体积，
/// 几十 MiB 到上百 MiB 的安装包直接顶在堆上）。
///
/// 三条不变式：
///  - **全程只碰 tmp**：dest 从「不存在」瞬间变为「完整文件」，故并发单飞的后到者经
///    [`cached_download_is_reusable`] 绝不会读到半截包；
///  - **失败即清理**：由 [`PartialDownload`] 这个 RAII 守卫承担 —— 不变量是「控制流离开这个作用域时
///    残件不在」，那是**作用域**的性质，只有类型表达得了（原先那条「数一数清理调用」的守卫为什么是
///    假的，见 [`PartialDownload`] 文档的三条反例）；
///  - **`downloaded` 只在 rename 成功之后发**：下载完成 ≠ 校验完成 ≠ 落位完成，早发一步就是
///    广播一个 dest 尚不存在的假成功态。落位判定与发事件被拆成 [`land_payload`] + 分支
///    （文本序守不住「成功才发」，成因见该函数文档）。
///
/// 落盘：`app_cache_dir()/updates/<fileName>`。同目录下**整个 `.polaris-new-` 命名族的孤儿 tmp**
/// （不限资产名 —— 残件多半带着**旧版本**的资产名）在拿到单飞闸之后顺手清一遍
/// （[`sweep_orphan_downloads`]）——「下载途中退出 App」会绕过上面那个 RAII 守卫。
///
/// **体积闸**：按 `updateInfo.fileSize` 声明值注入（**无裕度**，成因见 [`app_update_size_limit`]），
/// 并封在 [`APP_UPDATE_MAX_BYTES`] 之下；声明缺失/为 0 时直接取该上限。
/// **不**再与两条内核腿共用 16 MiB 内存闸 —— 那个闸的语义是「别把堆撑爆」，对流式落盘腿既无必要
/// 也卡不住正常安装包。
///
/// **完整性**（三级，由强到弱，**逐级都在**）：
///  1. 有期望摘要（[`resolve_expected_digest`]，当前只有 GitHub asset `digest`；随包 `SHA256SUMS`
///     虽已在发布侧产出，消费侧经判断不接，依据见该函数文档末节）→ sha256 **强校验**，
///     不符即丢弃 tmp、绝不落位（防截断/镜像投毒）；
///  2. 清单声明了 `fileSize` → **等值判据**（[`check_declared_size`]）。这一级是无摘要腿的主防线：
///     `fileSize` 来自 GitHub release 清单，镜像改不动；
///  3. 兜底 `Content-Length` 完整性（`CoreDownloader` 内）。**它对撒谎方零约束**——那个数就是撒谎方
///     自己给的，故绝不可把它当作「无摘要也安全」的理由（原文档正是这么写的，已订正）。
///
/// 三级全无（旧 release + 清单无 `fileSize`）时**不拒装**，但结果里 `verified:false`
/// **如实标记未校验**——否则所有旧 release 都更新不了。
///
/// **进度事件**：走 [`CoreDownloader::download_to_sink_with_progress`](crate::runtime::http::CoreDownloader::download_to_sink_with_progress) 的逐 chunk 回调，发
/// `downloading(0%)` → `downloading(n%)`（**按整数百分比去重**，见下）→ `downloaded(100%)`。
/// 服务端不给 `Content-Length` 时算不出分母 → 中间那段没有百分比可发，进度条停在 0% 走
/// indeterminate（**不拿已收字节瞎凑一个分母**）。同一份进度由 [`emit_progress`] 一并镜像进 mini 弹窗。
///
/// **单飞**：按 `dest` 加闸（见 [`download_gate`]）。后台自动下载腿与用户在弹窗点「更新」的腿写同一个
/// dest，是默认流程而非异常；后到者等待 + 按 sha256 复用，绝不出现两个进度游标互相顶。
///
/// **失败即发 `error`**：本命令的**每一条**失败早退都先发一发 [`ProgressStage::Failed`] 再返错误信封 ——
/// 弹窗被推进 progress 后只有 `error`/`downloaded` 能把它推出去，静默 return 会让它永远转圈。
/// 该不变式由单测 `every_failure_path_emits_an_error_progress_event` 按计数锁住
/// （计数用**前缀** `ApiResponse::err`，故带 code 的早退同样在射程内）。
#[tauri::command]
pub async fn update_download(
    app: AppHandle,
    state: State<'_, AppRuntime>,
    update_info: Value,
) -> Result<ApiResponse<Value>, ()> {
    // 本次下载**唯一**的发事件入口：随行事实（这次要下的那份发布清单）由它一处附着，
    // 下面十余个调用点因此没有「漏带」或「带成另一个版本的清单」的余地 —— 而设置页正是靠
    // 这份清单渲染版本号/体积、并在失败时重试。射程与成因见 [`ProgressStage`]。
    let emit = |stage: ProgressStage<'_>| emit_progress(&app, &update_info, stage);
    // U1：失败早退的统一出口——error 进度帧与失败信封两条出口共用同一个 `UpdateErr`
    // （此前一处中文串喂两条通道，i18n 模块文档登记的出口 #1/#2）。信封 msg = 英文回落 +
    // 诊断串；前端 toast 端拿到结构化 code 可优先本地化。
    let fail = |e: UpdateErr<'_>| -> ApiResponse<Value> {
        emit(ProgressStage::Failed(e));
        let msg = match e.detail {
            Some(d) => format!("{}: {d}", e.code.en()),
            None => e.code.en().to_string(),
        };
        ApiResponse::err_with_code(msg, e.code.wire())
    };

    let Some(url) = update_info
        .get("downloadUrl")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
    else {
        // 前置校验的早退**也必须发 error 进度**：弹窗被 `force progress(0)` 推进 Progress 后，
        // 只有 `error` / `downloaded` 能把它推出去 —— 静默 return 会让窗永远转圈（只剩 Cancel）。
        return Ok(fail(UpdateErr::new(UpdateErrCode::MissingDownloadUrl)));
    };
    let file_name = update_info
        .get("fileName")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| "polaris-update".to_string());
    // 路径穿越防线：文件名来自 GitHub 资产名，但它经过前端往返 —— 只取末段，绝不让 `../` 逃出目录。
    let file_name = std::path::Path::new(&file_name)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "polaris-update".to_string());
    // 期望摘要：按来源优先级挑（D1）。字段在但不是字符串 ⇒ **显式早退**，绝不静默降级成
    // 「本来就没摘要」（那等于把发布方的失误偷偷换成少一道校验）。
    let expected_digest = match resolve_expected_digest(&update_info) {
        Ok(d) => d,
        Err(detail) => {
            return Ok(fail(UpdateErr::with_detail(
                UpdateErrCode::DigestFieldInvalid,
                &detail,
            )));
        }
    };
    let expected_sha = expected_digest.as_ref().map(|d| d.hex.clone());
    // 声明大小 → 写入闸（**新增读取点**：改造之前本 command 根本没读过 fileSize）。
    let declared_size = update_info.get("fileSize").and_then(Value::as_u64);

    let dir = match app.path().app_cache_dir() {
        Ok(d) => d.join("updates"),
        Err(e) => {
            let detail = e.to_string();
            return Ok(fail(UpdateErr::with_detail(
                UpdateErrCode::CacheDirFailed,
                &detail,
            )));
        }
    };
    if let Err(e) = std::fs::create_dir_all(&dir) {
        let detail = format!("{}: {e}", dir.display());
        return Ok(fail(UpdateErr::with_detail(
            UpdateErrCode::CacheDirFailed,
            &detail,
        )));
    }
    let dest = dir.join(&file_name);

    // ── 单飞（见 [`download_gate`]）：后到者在此等待，等待期间**不发任何进度事件**
    //    （否则两个游标互相顶）。首发者跑完再决定复用还是重下。
    let gate = download_gate(&dest);
    let _in_flight = gate.lock().await;

    // ── 孤儿 tmp 清扫（best-effort）：位置必须在**闸之内、`tmp_name` 之前** ——
    //    闸保证本进程此刻无人在写同名 tmp；`tmp_name` 之前保证不会误删自己这一次的残件。
    //    主触发器是「下载途中退出 App」（见 `sweep_orphan_downloads` 文档），RAII 守卫覆盖不到。
    sweep_orphan_downloads(&polaris_updater::traits::StdFs, &dir, &file_name);

    // 复用先完成者的成果（有 sha256 判据时才敢认，见 [`cached_download_is_reusable`]）。
    let reuse_probe = {
        let dest = dest.clone();
        let sha = expected_sha.clone();
        tokio::task::spawn_blocking(move || cached_download_is_reusable(&dest, sha.as_deref()))
            .await
            .unwrap_or(false)
    };
    if reuse_probe {
        log::info!(
            "更新包已在本地且 sha256 复核通过，复用不重复下载: {}",
            dest.display()
        );
        // 复用腿的 `verified` 恒 `true`：它之所以敢认盘上这份，判据**就是** sha256 比中
        // （见 `cached_download_is_reusable`）—— 与下面回包里那个 `true` 同一条理由、同一个值。
        emit(ProgressStage::Downloaded {
            path: &dest,
            verified: true,
        });
        return Ok(ApiResponse::ok(json!({
            "success": true,
            "filePath": dest.to_string_lossy(),
            "verified": true,
            // 复用分支**最有资格**标注来源：它之所以敢认盘上这份，正是靠这条 asset digest 比中的
            // （`cached_download_is_reusable` 的唯一判据）。此前这里漏了 `digestSource`，于是
            // 「复用」与「刚下的」两条成功路径的响应形状不一致，前端分不出摘要是谁给的。
            "digestSource": expected_digest.as_ref().map(|d| d.source.as_str()),
        })));
    }

    emit(ProgressStage::Downloading {
        percentage: 0,
        received: 0,
    });

    // ── 落盘目标：**全程只碰 tmp**，dest 直到最后一次 rename 之前一个字节都不动。
    //    tmp 由 `verify::tmp_name` 生成 ⇒ 与 dest 同目录同卷（原子 rename 的前提），
    //    且每次调用唯一 ⇒ 并发的另一条腿写的是另一个 tmp，不会互相截断。
    //
    //    RAII：从这一行起，**任何**离开本作用域的方式（早退 / `?` / panic / future 被 drop）
    //    都会删掉残件；只有落位成功那一条路才 `disarm`。不需要任何人记得配一行清理。
    let partial = PartialDownload::new(polaris_updater::verify::tmp_name(&dest));
    let dl = updater_downloader(&state, app_update_size_limit(declared_size));
    // 写句柄经 `UpdateFs` trait 取（生产 StdFs / 测试 MockFs 的注入纪律）。
    // 传**工厂**而非句柄：镜像回退换候选重下时要一个截断过的干净句柄。
    let sink_path = partial.path().to_path_buf();
    let new_sink: Arc<crate::runtime::http::DownloadSinkFactory> = Arc::new(move || {
        use polaris_updater::traits::UpdateFs;
        polaris_updater::traits::StdFs.open_write(&sink_path)
    });
    // `CoreDownloader::download*` 是**同步**桥（其 doc 明令须在 blocking 线程调用：
    // 在 async 上下文直调会阻塞 executor，Tauri 同步 command 更是跑在主线程上会冻 UI）。
    let url_for_task = url.clone();
    // 中间帧的发事件入口在下载 task 线程上，接不到上面那个借栈的 `emit` ⇒ 清单按值克隆一份
    // （一次下载克隆一次，不是一帧一次）。带的仍是**同一个** `update_info`。
    let on_progress = download_progress_emitter(&app, update_info.clone());
    let streamed = match tokio::task::spawn_blocking(move || {
        dl.download_to_sink_with_progress(&url_for_task, new_sink, on_progress)
    })
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            // 「后端未接线」与「下载失败」**必须**可区分（trait 契约；生产注入的是 CoreDownloader，
            // 故这条实际不可达，但映射保留——折叠进泛化失败会让上层无限重试一个永不成功的调用）。
            // 信封 code 保留既有的 CODE_HTTP_UNAVAILABLE（上游契约），事件/弹窗走 U1 码表。
            let detail = e.to_string();
            return Ok(match e {
                polaris_updater::traits::DownloadError::BackendUnavailable(_) => {
                    emit(ProgressStage::Failed(UpdateErr::with_detail(
                        UpdateErrCode::BackendUnavailable,
                        &detail,
                    )));
                    ApiResponse::err_with_code(
                        format!("{}: {detail}", UpdateErrCode::BackendUnavailable.en()),
                        CODE_HTTP_UNAVAILABLE,
                    )
                }
                _ => fail(UpdateErr::with_detail(
                    UpdateErrCode::DownloadFailed,
                    &detail,
                )),
            });
        }
        Err(e) => {
            let detail = e.to_string();
            return Ok(fail(UpdateErr::with_detail(
                UpdateErrCode::DownloadTaskFailed,
                &detail,
            )));
        }
    };

    // ── 完整性第 2 级：清单声明的 `fileSize` 等值判据（见 [`check_declared_size`]）。
    //    这一级专治无摘要腿：Content-Length 是撒谎方自己给的数，对撒谎方零约束。
    if let Err(e) = check_declared_size(streamed.bytes, declared_size) {
        let detail = e.to_string();
        return Ok(fail(UpdateErr::with_detail(
            UpdateErrCode::SizeMismatch,
            &detail,
        )));
    }

    // ── 完整性第 1 级：sha256 强校验（有摘要才做）——摘要是**边下边算**的，零额外 IO、零额外内存。
    //    判定委托 `verify::verify_hex_digest`（全 crate 单点），**按变体分流文案**：
    //    「发布方 digest 写坏了」重下一万次也不会好，把它显示成「可能被截断或篡改」只会引导用户
    //    反复重下。原实现手搓 `!is_valid_sha256_hex(..) || !eq_ignore_ascii_case(..)`，
    //    正是把这条分野压成了一个 bool。
    if let Some(d) = expected_digest.as_ref() {
        if let Err(e) = polaris_updater::verify::verify_hex_digest(&streamed.sha256_hex, &d.hex) {
            // 「发布方 digest 写坏了」重下一万次也不会好，把它显示成「可能被截断或篡改」只会
            // 引导用户反复重下——两个变体两个码，正文里的这句分野由 locale 文案承担。
            let mismatch_detail = format!("expected {}, actual {}", d.hex, streamed.sha256_hex);
            return Ok(fail(match e {
                polaris_updater::verify::VerifyError::InvalidExpectedHash(_) => {
                    UpdateErr::with_detail(UpdateErrCode::DigestHexInvalid, &d.hex)
                }
                polaris_updater::verify::VerifyError::HashMismatch { .. } => {
                    UpdateErr::with_detail(UpdateErrCode::DigestMismatch, &mismatch_detail)
                }
            }));
        }
    }

    // ── 落位：tmp 已在盘 ⇒ **只做 rename**，绝不把刚写完的文件读回内存（那会抵消整个改造）。
    //    dest 从「不存在」瞬间变成「完整文件」，故并发单飞的后到者经
    //    `cached_download_is_reusable` 绝不会读到半截包。
    //
    //    判定与发事件**必须分开**：文本序表达不了「rename 成功才发 downloaded」，
    //    成因见 [`land_payload`]。先求值再 match，让 `partial` 的借用在 match 之前就结束。
    let landing = land_payload(&polaris_updater::traits::StdFs, partial.path(), &dest);
    match landing {
        LandingOutcome::Failed(detail) => {
            // `promote_staged` 自己已尽力删过 tmp；`partial` 在此 return 时析构再兜一次。
            return Ok(fail(UpdateErr::with_detail(
                UpdateErrCode::LandingFailed,
                &detail,
            )));
        }
        LandingOutcome::Landed => {
            // tmp 这个 inode 现在叫 dest 了 —— 先解除守卫，再广播成功。
            partial.disarm();
            // 「下载完成 / 校验完成 / 落位完成」三点分离后，`downloaded` **只在这一支**发：
            // 早一步发就是广播一个 dest 尚不存在的假成功态，设置页会给出一个点不开的安装入口。
            // 随行的 `path` 就是刚落位的那个 dest，`verified` 与下面回包里那个字段同源同值。
            emit(ProgressStage::Downloaded {
                path: &dest,
                verified: expected_digest.is_some(),
            });
        }
    }
    log::info!(
        "更新包已落位: {}（{} 字节，校验来源 {}）",
        dest.display(),
        streamed.bytes,
        expected_digest
            .as_ref()
            .map_or("none", |d| d.source.as_str())
    );
    Ok(ApiResponse::ok(json!({
        "success": true,
        "filePath": dest.to_string_lossy(),
        // `verified` 特指**摘要**这一级。无摘要时如实标记未校验（不拒装）——此时仍过了
        // `fileSize` 等值判据与 Content-Length，但那两级都弱于摘要，不配叫 verified。
        "verified": expected_digest.is_some(),
        "digestSource": expected_digest.as_ref().map(|d| d.source.as_str()),
    })))
}

/// 上游 `UPDATE_INSTALL`：安装已下载的更新包（生成平台脚本 → 停代理 → detached 起脚本 → 退出应用）。
///
/// ✅ **已接线**。决策全在纯函数 [`update_install::decide_install_plan`] /
/// [`update_install::build_install_script`]（真值表 + 快照单测），本 command 只做薄编排。
///
/// # 两段式：先告知，后执行
///
/// **用户已拍板走 ad-hoc 签名**（不买 Developer ID / Authenticode），故 macOS/Windows 都会被 OS 拦一道；
/// Linux deb 还要弹 polkit 提权框。[`update_install::install_advisory`] 判定后，**未确认前一律早退**，
/// 返 `{ok:false, needConfirm:true, advisory}`，由 UI 弹说明框讲清用户可执行的下一步。
///
/// **顺序不可换**（= 上游 `UpdateService.ts:306-315` 的明确注释）：确认框必须在**停代理之前**，
/// 用户取消即真 no-op —— 否则会留下「代理被停了但没更新」的坏态。
///
/// # 形态错配 → 交系统，**绝不强制 root**
///
/// 资产形态与运行形态错配（如 AppImage 运行拿到 `.deb`）时不自动提权安装，回退 `shell.open`
/// 让系统处理（= 上游 `:427-436`）。
#[tauri::command]
pub async fn update_install(
    app: AppHandle,
    state: State<'_, AppRuntime>,
    file_path: String,
    confirmed: Option<bool>,
) -> Result<ApiResponse<Value>, ()> {
    let installer = std::path::PathBuf::from(&file_path);
    if !installer.is_file() {
        return Ok(ApiResponse::err(format!(
            "更新包不存在（请先下载）: {}",
            installer.display()
        )));
    }
    let Ok(exe_path) = std::env::current_exe() else {
        return Ok(ApiResponse::err("无法解析当前可执行文件路径"));
    };

    let os = std::env::consts::OS;
    let appimage = std::env::var_os("APPIMAGE").map(std::path::PathBuf::from);
    // 便携形态判据与 [`update_check`] 同源（标记文件），**不是** electron-builder 的
    // `PORTABLE_EXECUTABLE_FILE`（本仓恒不存在，见 [`is_portable_layout`]）。
    // `portable_exe` 的语义是「原便携 exe 路径」⇒ 便携形态下即当前 exe 自身。
    let portable = is_portable_layout(&exe_path).then(|| exe_path.clone());
    let run_form = update_install::detect_run_form(os, appimage.as_deref(), portable.as_deref());

    let plan = match update_install::decide_install_plan(
        os,
        run_form,
        &installer,
        &exe_path,
        appimage.as_deref(),
        portable.as_deref(),
    ) {
        Ok(p) => p,
        Err(reject) => {
            // 形态错配 / 不认识的资产 → **交系统处理**（不强制 root、不瞎猜脚本）。
            log::warn!("安装计划被拒（{reject:?}）：回退交系统打开");
            #[allow(deprecated)]
            let opened = app.shell().open(installer.to_string_lossy(), None).is_ok();
            return Ok(ApiResponse::ok(json!({
                "ok": false,
                "handedToSystem": opened,
                "reason": "form-mismatch",
                "detail": format!("{reject:?}"),
            })));
        }
    };

    // ── 安装前告知（ad-hoc 签名 / 提权）——未确认一律早退，**此刻还没碰代理**。
    if let Some(advisory) = update_install::install_advisory(&plan) {
        if confirmed != Some(true) {
            return Ok(ApiResponse::ok(json!({
                "ok": false,
                "needConfirm": true,
                "advisory": advisory.key(),
            })));
        }
    }

    let texts = update_install::InstallTexts::default();
    let spec = update_install::build_install_script(&plan, &texts);

    // ── 停代理（必须在写脚本/退出**之前**：Windows 上核进程占着文件会让替换失败）。
    let proxy = state.proxy.clone();
    if proxy.status().running {
        if let Err(e) = proxy.stop().await {
            // 停不掉就**不装**（带着跑着的核去替换应用本体 = 半死不活的坏态），如实报错。
            return Ok(ApiResponse::err(format!("安装前停止代理失败: {e}")));
        }
    }

    let dir = app
        .path()
        .app_cache_dir()
        .map(|d| d.join("updates"))
        .unwrap_or_else(|_| std::env::temp_dir());
    let detached_spawn = update_install::spawn_detached_script(&dir, &spec);
    if detached_spawn.is_ok() {
        log::info!("安装脚本已起（{:?}），应用即将退出", plan.platform);
    }
    if let Err(e) = complete_detached_install(
        detached_spawn,
        || mark_explicit_update_quit(&app),
        || exit_after_detached_update(&app),
    ) {
        return Ok(ApiResponse::err(format!("启动安装脚本失败: {e}")));
    }
    Ok(ApiResponse::ok(json!({ "ok": true, "success": true })))
}

/// 「跳过此版本」存储口径的**唯一归一化点**（W8）。
///
/// [`check_app_update`] 的比较侧是 `strip_v(tag)`（如 `0.2.0`），而两个写点拿到的都是原始 tag
/// （`AppUpdateInfo.version` 保留 `v` 前缀）——不归一化就是「v0.2.0 存进去、0.2.0 比出来，
/// 永不相等」，跳过功能全仓失效（弹窗与设置页同病）。存这条状态只有经过本函数才算入口径；
/// 顺带 trim，空串/纯空白仍由调用侧判掉。
///
/// ⚠️ 存量 `update-state.json` 里的原始 tag 条目（`v0.2.0`）**有意不救援**（2026-08-18 拍板）：
/// 那些用户会重新开始收到提醒，正是功能恢复本意。
pub(super) fn stored_skip_version(input: &str) -> String {
    strip_v(input.trim()).to_string()
}

/// 上游 `UPDATE_SKIP`：跳过本次版本。
///
/// ✅ **已接线**：纯本地状态（`update-state.json` 的 `skippedVersion`，原子写 tmp+rename）。不依赖网络。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn update_skip(state: State<'_, AppRuntime>, version: Option<String>) -> ApiResponse<()> {
    let Some(v) = version.filter(|s| !s.trim().is_empty()) else {
        return ApiResponse::err("update_skip 需要非空 version");
    };
    let stored = stored_skip_version(&v);
    match state
        .updater()
        .mutate_state(|s| s.skipped_version = Some(stored))
    {
        Ok(()) => ok_void(),
        Err(e) => ApiResponse::err(e),
    }
}

/// 泛 releases 列表页（无版本号可用时的回落目标）。
pub(super) const RELEASES_LIST_URL: &str = "https://github.com/2outside/Polaris/releases";

/// 拼「查看更新日志」目标 URL（纯函数，可测）：有版本号 → 直达该版本 release 页；否则回落泛列表页。
///
/// # tag 前缀已核实：本仓 release tag 恒带 `v`（不能凭 上游的写法直接抄）
///
/// 证据（均在本仓，非臆测）：
///  - `.github/workflows/package.yml`「产物标识：tag 用 tag 名（ref_name，如 `v0.1.0`）」；
///  - 同文件发布 job：`tag="${GITHUB_REF_NAME}"` → `gh release create "$tag" ...`——release 的 tag
///    **就是**推送的 git tag 本身，未做任何改写；
///  - 触发条件注释「push tags v*」；
///  - `GithubRelease.tag_name` 字段文档「如 `v0.2.0`」（`crates/updater/src/github.rs`）。
///
/// 传入的 `version` 取自 [`AppUpdateInfo::version`](polaris_updater::github::AppUpdateInfo) /
/// 弹窗 `UpdatePopupState.version`，两者都保留**原始 tag（已含 `v`）**。此处仍先
/// `trim_start_matches('v')` 再补一次前缀（= [`core_update_check_inner`](super::core_update::core_update_check_inner) 同一行代码的写法）——
/// 防止调用方将来改传裸 semver 时把 URL 拼成 `vv0.1.0`，函数对两种输入形态都幂等。
///
/// `version` 为空/仅空白 → 回落 [`RELEASES_LIST_URL`]：拼一个大概率 404 的直达链接不如给用户一个
/// 打得开的页面。
#[must_use]
pub(super) fn releases_url_for(version: Option<&str>) -> String {
    match version.map(str::trim).filter(|v| !v.is_empty()) {
        Some(v) => format!("{RELEASES_LIST_URL}/tag/v{}", v.trim_start_matches('v')),
        None => RELEASES_LIST_URL.to_string(),
    }
}

/// 上游 `UPDATE_OPEN_RELEASES`：用系统浏览器打开 releases 页（shell 插件）。
///
/// #311：此前恒打开泛列表页——用户点「查看更新日志」找不到对应版本说明，形同摆设。现按
/// `version` 直达该版本 release 页（`/releases/tag/v<version>`，前缀依据见 [`releases_url_for`]）；
/// `version` 缺失/空时回落泛列表页。
///
/// 注：`shell.open` 在 tauri-plugin-shell 2.x 标记 deprecated，推荐 tauri-plugin-opener；
/// 切换属独立依赖决策（opener 需新增 crate 依赖），此处暂用 shell 并抑制 deprecation。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
#[allow(deprecated)]
pub fn update_open_releases(app: AppHandle, version: Option<String>) -> ApiResponse<()> {
    if let Err(e) = app.shell().open(releases_url_for(version.as_deref()), None) {
        return ApiResponse::err(format!("{e}"));
    }
    ok_void()
}

// 弹窗「更新 / 重试」复查阶段失败的文案常量已随 U1 退役：两处早退共用
// `UpdateErrCode::RecheckFailed`（同一件事同一码），正文本地化在渲染端。

/// 复查回来之后的三档处置（[`reconcile_recheck`] 的结论）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RecheckVerdict {
    /// 复查得到的版本与弹窗上写着的**逐字相同** ⇒ 照下。
    Proceed,
    /// 变了 ⇒ 退回 `remind(新版本)`，请用户对当前这串字重新决定。
    Renegotiate,
    /// 复查回包根本没有版本号（契约破损）⇒ 既无法对账，也不能弹个空版本号 ⇒ 按检查失败收场。
    Unusable,
}

/// **纯判定**：拿弹窗上写着的版本（`advertised`）与复查回来的版本（`rechecked`）对账。
///
/// 抽成纯函数是为了它**可被真值表钉死**：[`update_popup_action`] 持 `AppHandle` / `State`，
/// 单测构造不出 Tauri 运行时，判定留在里面就只剩源码级守卫能守 —— 那守得住「有没有调用」，
/// 守不住「判对没判对」。
///
/// # `advertised == None` 的含义：**会话把邀请版本弄丢了 = 不变式被破坏**
///
/// 判 [`RecheckVerdict::Renegotiate`] 作**兜底**：不知道当初承诺过什么，就不能声称「对上了」——
/// 失败安全的方向是让用户再确认一次，不是闷头下。
///
/// ⚠️ **不要把它读成「理论不可达」**。本注释 2026-08-17 前正是那么写的，而它每次「重试」都发生：
/// `Retry` 按 `PopupAction::is_valid_for` **只在 `Error` 态合法**，而 `UpdatePopupState::error()`
/// 只填 `error_text`（`..Self::default()` ⇒ `version: None`）⇒ 对账恒判「变了」⇒ 退回 remind、
/// 一个字节都不下，「重试」退化成「返回」。根因不在本函数，在**会话没记住自己邀请过谁**；已由
/// `polaris_updater::popup::PopupSession::send_state` 的版本继承修掉（那里有它自己的门）。
/// 所以今天走到这一档 = 那条继承坏了，属**哨兵**，不是常规路径。
pub(super) fn reconcile_recheck(advertised: Option<&str>, rechecked: &str) -> RecheckVerdict {
    if rechecked.is_empty() {
        return RecheckVerdict::Unusable;
    }
    if advertised == Some(rechecked) {
        RecheckVerdict::Proceed
    } else {
        RecheckVerdict::Renegotiate
    }
}

/// 上游 `UPDATE_POPUP_ACTION`：弹窗 → 主进程按钮/关闭动作。
///
/// ✅ **已接线**（动作路由）：按 phase 白名单校验 → 合法动作执行副作用。
///
/// 语义对齐 `UpdateService.onPopupAction:680-702`：
///  - **非法动作静默忽略**（不报错、不改状态）—— 上游 `awaitPopupAction` 的 `valid` 白名单语义。
///  - `viewLog` **不结束等待**：开该版本 release 页（无版本号回落泛列表页），弹窗停在 remind。
///  - `manualDownload` 开外链（上游 `:696-700` 只放行 https；此处走该版本 release 页/回落泛列表页，天然满足）。
///  - `update` / `retry` **真下载**：弹窗自身只持有版本号、不持有下载地址，故先复查一次拿
///    `updateInfo`，再走 [`update_download`]；进度经 `update:progress` 广播，并由
///    [`emit_progress`] 镜像成弹窗 `progress` / `done` / `error` 三态。
///    「弹窗写的版本 == 真正下载的版本」这句不变量在这条分支上由**两道**东西合起来守：
///    ① 候选集**规则**——复查读取弹窗会话保存的 `include_prerelease`；
///    ② 候选集**内容**——复查回来的 `version` 与 `popup.version` 逐字对账，不一致就退回
///    `remind(新版本)` 请用户重新确认，绝不换个目标接着下。缺一道都只守住一半。
///
/// # 窗内反馈的两个边角（`emit_progress` 覆盖不到的）
///
///  1. **复查期**：`update_check` 可跑满 15s，其间 `emit_progress` 一次都不发 → 用户点完按钮
///     看着 remind 态发呆。故本分支在复查**之前**先手动推一发 `progress(0)`。
///  2. **done 后关窗**：`done` 是终态，上游 800ms（[`DONE_AUTO_CLOSE_MS`]）后自动关窗；
///     进度事件本身不含「关窗」语义，故收在这里。
///
/// # 已知边界（如实登记）
///
/// `PopupAction::Cancel` 现在可达了（progress 态真会出现），但它只关窗、**不中断在飞的下载**——
/// `CoreDownloader` 无取消令牌。关窗后下载继续跑完并落盘，不会留半截文件（原子写），
/// 用户的下一次「更新」会直接复用。真正的下载取消需给下载器加 cancel token，单列。
#[tauri::command]
pub async fn update_popup_action(
    app: AppHandle,
    state: State<'_, AppRuntime>,
    action: String,
) -> Result<ApiResponse<Value>, ()> {
    let Ok(act) = serde_json::from_value::<PopupAction>(Value::String(action.clone())) else {
        return Ok(ApiResponse::err(format!("未知弹窗动作: {action}")));
    };

    // 白名单：动作必须对当前 phase 合法，否则静默忽略（对齐上游）。
    let Some(popup) = state.updater().popup_state() else {
        // 弹窗不存在 → 无 phase 可校验（= 上游 awaitPopupAction 的 '__closed__' 短路）。
        return Ok(ApiResponse::ok(
            json!({ "handled": false, "reason": "popup-closed" }),
        ));
    };
    if !act.is_valid_for(popup.phase) {
        return Ok(ApiResponse::ok(
            json!({ "handled": false, "reason": "invalid-for-phase" }),
        ));
    }

    match act {
        // viewLog 不结束等待（弹窗停在 remind）。
        PopupAction::ViewLog => {
            let _ = update_open_releases(app, popup.version.clone());
            Ok(ApiResponse::ok(
                json!({ "handled": true, "resolving": false }),
            ))
        }
        PopupAction::Skip => {
            let u = state.updater();
            // W8：popup.version 是原始 tag（AppUpdateInfo.version 含 `v`），与比较侧
            // strip_v 后的口径不同 ⇒ 存前必须过同一个归一化点（stored_skip_version）。
            let stored = u
                .popup_state()
                .and_then(|s| s.version)
                .map(|v| stored_skip_version(&v));
            let r = u.mutate_state(|s| s.skipped_version = stored);
            let _ = close_update_popup(&app, u.popup());
            Ok(match r {
                Ok(()) => ApiResponse::ok(json!({ "handled": true })),
                Err(e) => ApiResponse::err(e),
            })
        }
        PopupAction::Later | PopupAction::Close | PopupAction::Cancel => {
            let u = state.updater();
            Ok(match close_update_popup(&app, u.popup()) {
                Ok(()) => ApiResponse::ok(json!({ "handled": true })),
                Err(e) => ApiResponse::err(e),
            })
        }
        // 真下载（**不再假装未接线，也不假装已开始**：下面这条路径确实会把包下下来）。
        PopupAction::Update | PopupAction::Retry => {
            // 复查期没有进度事件（可达 15s）→ 先把弹窗推进 progress，否则窗内零反馈。
            // 用 force：这一发正是「用户点了更新」的动作本身，闸（只放行 Progress）对它恒 false。
            force_popup_state(&app, UpdatePopupState::progress(0, None, None));
            // 候选口径取自本次邀请的弹窗会话，而不是重新读取可能已被用户改动的配置。
            let checked =
                update_check(app.clone(), state.clone(), popup.include_prerelease, None).await?;
            let Some(data) = checked.data.filter(|_| checked.success) else {
                // 复查请求本身失败（网络 / 超时 / 非 2xx）。**只推弹窗，不广播** —— 与下面
                // 「已是最新」那档同一条理由：这条路径一个字节都没下，而 `emit_progress` 会把
                // `update:progress` 广播出去，让**设置页**弹一条它从未发起过的下载错误。
                // 弹窗是本次动作的唯一相关方（`emit_progress` 的弹窗镜像正是 `error(msg)` 这一发，
                // 故行为对弹窗逐字不变，少掉的只有那次全局广播）。
                // U1：复查失败也走码表（detail = 检查腿带回的错误原文，F1 后为语言中性英文）。
                let detail = checked.error.unwrap_or_default();
                push_popup_state(
                    &app,
                    UpdatePopupState::error(UpdateErrCode::RecheckFailed, detail.clone()),
                );
                return Ok(ApiResponse::err_with_code(
                    format!("{}: {detail}", UpdateErrCode::RecheckFailed.en()),
                    UpdateErrCode::RecheckFailed.wire(),
                ));
            };
            let Some(info) = data.get("updateInfo").cloned().filter(|v| !v.is_null()) else {
                // 复查回来没有任何可下载的包：弹窗停在 progress 会永远转圈 → 推进 `noupdate` 终态
                // （随后自动关窗）。
                //
                // **只推弹窗，不广播 `update:progress`**：这条路径一个字节都没下、没有 filePath，
                // 而全局广播会让设置页的 `onProgress` 显示「已下载」并给出一个不存在的安装入口
                // （`SettingsUpdate` 据 status==='downloaded' 判定包已就位）。弹窗是本次动作的
                // 唯一相关方，故状态只推给它。
                //
                // # 这里 2026-08-17 前推的是 `done()`，那是一句谎话
                //
                // 弹窗 `done` 渲染的是「下载完成」+ 满格进度条，而这条路径一个字节都没下。它至少
                // 有两条已核实的到达方式：① 用户已经是最新版；② 用户此前对**同一个版本**按过
                // 「跳过此版本」，再回弹窗点「更新」，复查被 `skipped_version` 过滤成 NoUpdate。
                // 与下面那道版本对账**同源**（复查结果与弹窗承诺不符），但处置不同：那边有新版本
                // 号可以退回 `remind` 重新征求，这边没有任何可下载的目标可展示。
                //
                // **不区分成因**：`check_app_update` 判 NoUpdate 有五条路（无正式发布 / 不比当前新 /
                // 已跳过 / 无适配本平台的资产 / 平台不受支持），回包只有一个 `hasUpdate:false`，
                // 后端**分辨不出**是哪一条。挑一条说出来就是拿状态冒充事实 —— 那正是本批要修的病。
                // 故只陈述确实知道的那件事：这次检查没找到 `popup.version` 的更新包。
                //
                // 版本号取 `popup.version`（弹窗上写着的那串字），不是复查结果 —— 复查什么都没返回。
                push_popup_state(&app, UpdatePopupState::no_update(popup.version.clone()));
                schedule_popup_auto_close(&app, NO_UPDATE_AUTO_CLOSE_MS);
                return Ok(ApiResponse::ok(
                    json!({ "handled": true, "hasUpdate": false }),
                ));
            };
            // ── 对账：复查回来的版本必须就是弹窗上写着的那串字 ────────────────────────
            //
            // 会话里记录的通道只让两次 check 的**候选集规则**相同，管不了
            // **候选集内容** —— 邀请与兑现之间隔着用户的思考时间，上游随时可能再发一版。那时
            // 两端都是正式版（无预发布风险），但「按 A 邀请、下到 B」原样成立：弹窗上仍写着
            // v1.2.0，下回来的是 v1.3.0。而弹窗真写着的那串字就在同一作用域里 —— `popup.version`，
            // Skip 与 ManualDownload 两条分支一直在读它，唯独这条从不比对。
            //
            // **不一致时退回 remind(新版本)，不是「改个标签接着下」**：`progress` 态根本不渲染
            // 版本号（`ui/src/update-popup/main.ts` 的 `case 'progress'` 只有标题 + 进度条 + 字节数），
            // 把新版本号写进去用户一个字都看不见 —— 那是名义上的告知。退回 remind 让用户对
            // **当前这串字**再按一次「更新」，守的与本批同一句不变量：用户点的是哪个版本，就下哪个。
            // 代价只是罕见竞态下多一次点击；不会打转（下一次复查即命中同一版本）。
            //
            // `popup.version` 为 `None` 同样判不一致（不知道承诺过什么就不能声称对上了）。注意
            // 它**不是**「理论不可达」：`Retry` 只在 error 态合法，而 error 态的版本号靠
            // `PopupSession::send_state` 的**会话级继承**才有——那条继承一坏，重试就永不下载。
            // 判据与门都在 `polaris_updater::popup`，此处只作兜底。
            let rechecked = info
                .get("version")
                .and_then(Value::as_str)
                .unwrap_or_default();
            match reconcile_recheck(popup.version.as_deref(), rechecked) {
                RecheckVerdict::Unusable => {
                    // hasUpdate 为真却没有版本号 = 后端契约破损。既无法对账，也**不弹空版本号**
                    // （与 `startup_tasks` / `tray` 两条产出腿同一处置）⇒ 按检查失败收场，
                    // 弹窗停在 error 仍可重试。码与上面那条早退共用 `RecheckFailed`（U1）。
                    // 同样**只推弹窗、不广播**（理由见上面那条早退）。
                    log::warn!("弹窗复查：hasUpdate 为真但 updateInfo 缺 version，放弃本次下载");
                    push_popup_state(
                        &app,
                        UpdatePopupState::error(UpdateErrCode::RecheckFailed, ""),
                    );
                    return Ok(ApiResponse::err_with_code(
                        UpdateErrCode::RecheckFailed.en(),
                        UpdateErrCode::RecheckFailed.wire(),
                    ));
                }
                RecheckVerdict::Renegotiate => {
                    log::info!(
                        "弹窗复查：邀请的是 {:?}，复查得到 {rechecked} —— 退回提醒态让用户重新确认",
                        popup.version
                    );
                    let current = app.package_info().version.to_string();
                    // 走带闸的 push（当前 phase 恒为上面 force 进去的 Progress，闸放行）：
                    // 弹窗若已被用户关掉，这里就该是 no-op，而不是替他重新弹一个窗。
                    push_popup_state(
                        &app,
                        UpdatePopupState::remind_with_channel(
                            rechecked,
                            current,
                            popup.include_prerelease.unwrap_or(false),
                        ),
                    );
                    // 只回 `handled`：弹窗端 `sendAction` 是 `void invoke(...).catch(() => {})`，
                    // 返回值整体丢弃，用户看到的变化全部由上面那发状态推送承载。曾多回过
                    // `reason` / `version` 两个字段 —— 零消费者、零测试、零对拍门，删。
                    return Ok(ApiResponse::ok(json!({ "handled": true })));
                }
                RecheckVerdict::Proceed => {}
            }

            // 下载腿内部经 emit_progress 推 downloading(n%) / downloaded(100%) / error。
            let resp = update_download(app.clone(), state, info).await?;
            if resp.success {
                schedule_popup_auto_close(&app, DONE_AUTO_CLOSE_MS);
            }
            Ok(resp)
        }
        PopupAction::ManualDownload => {
            let _ = update_open_releases(app, popup.version.clone());
            Ok(ApiResponse::ok(json!({ "handled": true })))
        }
    }
}

/// 终态后延时自动关窗。
///
/// 延时**由调用点传**，不是写死的 [`DONE_AUTO_CLOSE_MS`]：两个终态对用户的要求不同 ——
/// `done` 那一屏（= 上游 `UpdateService.ts:772` 的 800ms）用户不必读字就知道发生了什么；
/// `noupdate` 是唯一要求把一句话读完才有信息量的一屏，故取 [`NO_UPDATE_AUTO_CLOSE_MS`]。
/// 写死一个值就等于让后者一闪而过 —— 说了等于没说。
///
/// 单独 spawn 而非在命令里 sleep：命令得立刻返回给渲染端，否则弹窗按钮多转这么久才复位。
/// 读当前弹窗会话代次（无会话 / 锁不可得按 0；语义见 `PopupSession::generation`）。
pub(super) fn popup_generation(app: &AppHandle) -> u64 {
    let Some(rt) = app.try_state::<AppRuntime>() else {
        return 0;
    };
    let Ok(slot) = rt.updater().popup().lock() else {
        return 0;
    };
    slot.as_ref().map_or(0, |s| s.generation())
}

pub(super) fn schedule_popup_auto_close(app: &AppHandle, delay_ms: u64) {
    // 🟡#4 代次守卫：捕获**调度时刻**的会话代次，fire 时核对。代次已前进 = 用户手动关掉本窗
    // 后另一条腿开了新弹窗——陈旧定时器不得把新窗关掉（noupdate 窗口 3000ms 内这条竞态
    // 现实可达）。核对放在 `close_update_popup` 之前，且本函数只读代次不持锁进入关闭路径。
    // ⚠️ 已知微窗（复审 F1 附带，登记不修）：核对通过后、close 取锁前恰逢开新窗仍会被误关
    // ——两条 lock 之间的几条指令 vs 原本 3s 的窗口，缩小约六个数量级；全修需「持锁核对 +
    // 清槽」合并成 checked-close，不值当。
    let scheduled_gen = popup_generation(app);
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        let Some(rt) = app.try_state::<AppRuntime>() else {
            return;
        };
        if popup_generation(&app) != scheduled_gen {
            log::debug!(
                "自动关窗跳过：会话代次已从 {scheduled_gen} 前进（旧窗的定时器不关新窗，见 🟡#4）"
            );
            return;
        }
        // 延时期间用户若手动关了窗，`close_update_popup` 是幂等的（窗没了只清会话槽）。
        if let Err(e) = close_update_popup(&app, rt.updater().popup()) {
            // 本函数同时服务 done 与 noupdate 两个终态（🟢#8），日志不写死「done 态」。
            log::debug!("终态自动关窗失败: {e}");
        }
    });
}

/// 开 mini 更新弹窗（主动唤起入口；供检查到新版本后调用）。
///
/// ✅ **已接线**：建窗路径的初始态随文档注入 —— #300/#301 的「建窗但从未下发初始态」在此**结构性不可达**
/// （见 `updater::popup` 模块文档）。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn update_popup_show(
    app: AppHandle,
    state: State<'_, AppRuntime>,
    version: String,
    current_version: String,
    include_prerelease: Option<bool>,
) -> ApiResponse<()> {
    let u = state.updater();
    let st = UpdatePopupState::remind_with_channel(
        version,
        current_version,
        include_prerelease.unwrap_or(false),
    );
    match show_update_popup(&app, u.popup(), st) {
        Ok(()) => ok_void(),
        Err(e) => ApiResponse::err(e),
    }
}
