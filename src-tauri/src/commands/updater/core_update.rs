//! Core 更新：检查、暂存、停核换核、验证、回滚与手动替换。

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use tauri::{AppHandle, Manager, State};

use super::{
    core_base_dir, fetch_releases_json, updater_downloader, CODE_CHECK_TIMEOUT, CODE_FORK_BLOCKED,
    CODE_NO_BACKUP, CORE_CHECK_TOTAL_TIMEOUT_MS,
};
use crate::response::{ok_void, ApiResponse};
use crate::runtime::http::MAX_DOWNLOAD_BYTES;
use crate::runtime::{core_paths, core_swap, AppRuntime};
use polaris_updater::core_build::{ComparableVersion, CoreBuildKind};
use polaris_updater::github::{find_suitable_singbox_asset, CORE_UPDATE_REPO};
use polaris_updater::github::{AssetArch, AssetPlatform, GithubRelease};
use polaris_updater::traits::UpdateDownloader;
use polaris_updater::verify::verify_bytes;
use polaris_updater::version::{compare_semver, same_major_minor};
use polaris_updater::{extract_version_token, parse_asset_digest};

/// 上游 `core-update:check`：检查内核更新。
///
/// ✅ **已接线**：fork 硬闸 → 拉 `SagerNet/sing-box` releases → [`find_suitable_singbox_asset`]
/// 选平台/架构资产 → 版本比较 + 跨带标注。
///
/// # fork 硬闸（顺序要紧）
///
/// 活核是第三方 fork 时**直接拒绝、根本不发这次 HTTP 请求**（= 上游 `CoreUpdateService.ts:167,274`）。
/// 理由：官方 release 覆盖 fork 会静默吃掉用户明确选择的特性分支。该闸**必须前置于网络调用** ——
/// 「先请求再判」在功能上等价，但会向 GitHub 泄露一次本可避免的请求，且让闸看起来可有可无。
///
/// # 请求级总超时（[`CORE_CHECK_TOTAL_TIMEOUT_MS`]）
///
/// [`GITHUB_FETCH_TIMEOUT_MS`](super::app_update::GITHUB_FETCH_TIMEOUT_MS) 是**逐跳**超时（连接 + 读取，每一跳各算一次），而
/// `safe_redirect_fetch` 最多跟 5 跳 ⇒ 最坏可叠到 90s，远超契约要求的 20s 兜底。
/// 故此处再包一层**整体** `timeout`：无论内部跑到哪一步，20s 到点即返。
///
/// 超时用**独立错误码** [`CODE_CHECK_TIMEOUT`]（不折叠进泛化网络失败）：二者处置不同 ——
/// 网络失败可立刻重试，超时说明这条链路当前就是慢/被墙，重试大概率还是超时，UI 该提示配置加速。
///
/// **`invoke` 无取消语义**：前端做的 UI 等待上限只是不再等结果，后端请求照跑；这一层是唯一
/// 真能让请求停下来的地方（`timeout` drop 掉 future ⇒ 连接随之关闭）。
#[tauri::command]
pub async fn core_update_check(state: State<'_, AppRuntime>) -> Result<ApiResponse<Value>, ()> {
    match tokio::time::timeout(
        std::time::Duration::from_millis(CORE_CHECK_TOTAL_TIMEOUT_MS),
        core_update_check_inner(state),
    )
    .await
    {
        Ok(r) => r,
        Err(_) => Ok(ApiResponse::err_with_code(
            format!(
                "检查内核更新超时（超过 {}s）：网络不可达或需要配置 GitHub 加速",
                CORE_CHECK_TOTAL_TIMEOUT_MS / 1000
            ),
            CODE_CHECK_TIMEOUT,
        )),
    }
}

/// 读 `config.coreUpdateChannel`：`"prerelease"` → true，其余（含缺省 / 非法值）→ false。
///
/// 缺省即 `stable`，与本开关引入前的写死行为逐字一致 —— 存量用户不会因为升级被动切进测试通道。
/// 非法值不在此处纠错：`store::sanitize` 已把它删掉，这里读到的要么是两个合法值之一，要么不存在。
pub(super) fn core_update_channel_is_prerelease(state: &AppRuntime) -> bool {
    state
        .config()
        .get_value("coreUpdateChannel")
        .ok()
        .and_then(|v| v.as_str().map(|s| s == "prerelease"))
        .unwrap_or(false)
}

/// [`core_update_check`] 的本体（被 20s 总超时包着；见其文档）。
pub(super) async fn core_update_check_inner(
    state: State<'_, AppRuntime>,
) -> Result<ApiResponse<Value>, ()> {
    let u = state.updater();
    let current_line = u.read_core_version_line();
    let current = u.read_core_version();

    // ── fork 硬闸：前置，零网络。
    if u.core_build_kind() == CoreBuildKind::Fork {
        return Ok(ApiResponse::err_with_code(
            "当前为第三方（非官方）内核，已禁用在线更新；请先回滚或重置到出厂内核",
            CODE_FORK_BLOCKED,
        ));
    }

    let Some(platform) = AssetPlatform::from_os(std::env::consts::OS) else {
        return Ok(ApiResponse::ok(json!({
            "hasUpdate": false,
            "currentVersion": current,
        })));
    };
    let arch = AssetArch::from_arch(std::env::consts::ARCH);

    let (owner, repo) = CORE_UPDATE_REPO;
    let body = match fetch_releases_json(&state, owner, repo).await {
        Ok(b) => b,
        Err(e) => return Ok(ApiResponse::err(format!("检查内核更新失败: {e}"))),
    };
    let releases: Vec<GithubRelease> = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return Ok(ApiResponse::err(format!("解析 sing-box release 失败: {e}"))),
    };

    // 候选集按**更新通道**取（`config.coreUpdateChannel`）：
    //   - `stable`（缺省，与改动前行为逐字一致）：只看正式版；
    //   - `prerelease`：alpha / beta / rc 一并纳入。
    //
    // 为什么必须有这个开关：sing-box 的 alpha/beta 在 GitHub 上就是 `prerelease=true`，写死过滤等于
    // 把**整条预发布线**从候选里删掉 —— 跑 `1.14.0-alpha.31` 的用户不但看不到 `1.14.0-beta.1`，
    // 连「有没有更新」都恒为否：剩下的正式版是 1.13.x，`compare_semver` 判它更旧
    // （陈先生 2026-07-30 报「同样 1.14.0，alpha 无法更新到 beta」）。**比对逻辑本身没问题**，
    // `compare_semver` 完整实现了 semver 预发布优先级（alpha.31 < alpha.32 < beta.1 < rc.1 < 1.14.0）。
    //
    // **不按 alpha/beta/rc 再细分档次**：GitHub 只给一个 `prerelease` 布尔，档次仅存在于 tag 文本里，
    // 靠字符串猜会在上游改命名的那天静默失效。
    //
    // 跨带闸（`same_major_minor`）与本通道**正交**：通道决定「看不看预发布」，跨带决定「跨不跨 minor」，
    // 两道各管各的，开预发布不会顺带放开跨带。
    let include_prerelease = core_update_channel_is_prerelease(&state);
    let Some(release) = releases
        .iter()
        .filter(|r| include_prerelease || !r.prerelease)
        .max_by(|a, b| {
            a.published_at
                .as_deref()
                .unwrap_or("")
                .cmp(b.published_at.as_deref().unwrap_or(""))
        })
    else {
        return Ok(ApiResponse::ok(json!({
            "hasUpdate": false,
            "currentVersion": current,
        })));
    };

    let latest = release.tag_name.trim_start_matches('v').to_string();
    // 版本闸：必须**严格新于**当前（不可解析 → 失败安全按无更新，绝不误报有更新）。
    let is_newer = compare_semver(&latest, &current)
        .map(|o| o > 0)
        .unwrap_or(false);
    let Some(asset) = find_suitable_singbox_asset(&release.assets, platform, arch) else {
        // 无适配资产 → 如实报无更新（而非报错：这不是失败，是这台机器没有对应构建）。
        return Ok(ApiResponse::ok(json!({
            "hasUpdate": false,
            "currentVersion": current,
        })));
    };
    // 跨带标注（UI 据此提示兼容性风险；**自动路径**的硬闸在 `core_update_run` 里，此处只标注）。
    let cross_band = !same_major_minor(&latest, &current).unwrap_or(true);

    Ok(ApiResponse::ok(json!({
        "hasUpdate": is_newer,
        "currentVersion": current,
        "currentVersionLine": current_line,
        "latestVersion": latest,
        "downloadUrl": asset.browser_download_url,
        "assetName": asset.name,
        "sha256": asset.digest.as_deref().and_then(parse_asset_digest),
        "releaseNotes": release.body.clone().unwrap_or_default(),
        "crossBand": cross_band,
    })))
}

/// 上游 `core-update:update`：下载并更新内核（下载 → sha256 → 解压 → 停核 → 换 → 起核）。
///
/// ✅ **已接线**，零提权（落位于 `<config_dir>/core_update/`）。落位顺序见 [`swap_core_with_restart`]。
///
/// # 闸门顺序（前置判定全在网络之前）
///
/// 1. fork 硬闸（零网络）→ 2. 版本闸（不比当前新即 no-op）→ 3. 跨带闸（自动路径拒绝，手动路径由
///    `core_replace_manual` 承担）→ 4. 才下载。
///
/// # 完整性
///
/// GitHub asset `digest` 存在 → sha256 **强校验**，不符即拒绝（**字节绝不落盘**）；缺失回落
/// `CoreDownloader` 的 Content-Length 校验。
#[tauri::command]
pub async fn core_update_run(
    app: AppHandle,
    state: State<'_, AppRuntime>,
    value: Option<String>,
) -> Result<ApiResponse<Value>, ()> {
    let base = match core_base_dir::<Value>() {
        Ok(b) => b,
        Err(resp) => return Ok(resp),
    };
    let u = state.updater();
    if u.core_build_kind() == CoreBuildKind::Fork {
        return Ok(ApiResponse::err_with_code(
            "当前为第三方（非官方）内核，已禁用在线更新；请先回滚或重置到出厂内核",
            CODE_FORK_BLOCKED,
        ));
    }
    let current = u.read_core_version();

    // 前端传 downloadUrl（invokeScalar → `{ value }`）；缺省则自己先查一次。
    let (url, expected_sha, latest) = match value.filter(|s| !s.trim().is_empty()) {
        Some(u) => (u, None, String::new()),
        None => {
            let checked = core_update_check(state.clone()).await?;
            let Some(data) = checked.data.filter(|_| checked.success) else {
                return Ok(ApiResponse::err(
                    checked.error.unwrap_or_else(|| "检查内核更新失败".into()),
                ));
            };
            if !data
                .get("hasUpdate")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                return Ok(ApiResponse::ok(json!({ "result": "noop", "ok": true })));
            }
            let Some(u) = data.get("downloadUrl").and_then(Value::as_str) else {
                return Ok(ApiResponse::err("内核更新缺下载地址"));
            };
            (
                u.to_string(),
                data.get("sha256")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                data.get("latestVersion")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            )
        }
    };

    // 跨带硬闸（**自动路径**）：跨 major.minor 不自动换（= 上游 `sameMajorMinor` 闸）。
    // 手动换核路径（`core_replace_manual`）可绕过——那是用户明确的一次性选择。
    if !latest.is_empty()
        && !same_major_minor(&latest, &current).unwrap_or(true)
        && state
            .config()
            .get_value("restrictCoreUpdateToCompatibleMinor")
            .ok()
            .and_then(|v| v.as_bool())
            != Some(false)
    {
        return Ok(ApiResponse::ok(json!({
            "result": "deferred",
            "ok": false,
            "crossBand": true,
            "latestVersion": latest,
        })));
    }

    let asset_name = url.rsplit('/').next().unwrap_or("core-asset").to_string();
    // 内核腿整包入内存（解归档要用）⇒ 闸就是内存闸，逐字沿用形参化之前的 16 MiB。
    let dl = updater_downloader(&state, MAX_DOWNLOAD_BYTES);
    let url_for_task = url.clone();
    let bytes = match tokio::task::spawn_blocking(move || dl.download(&url_for_task)).await {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => return Ok(ApiResponse::err(format!("下载内核失败: {e}"))),
        Err(e) => return Ok(ApiResponse::err(format!("下载任务异常终止: {e}"))),
    };
    if let Some(sha) = expected_sha.as_deref().filter(|s| !s.is_empty()) {
        if let Err(e) = verify_bytes(&bytes, sha) {
            return Ok(ApiResponse::err(format!(
                "内核校验失败（可能被截断或篡改），已拒绝落位: {e}"
            )));
        }
    }

    // 归档 → 裸二进制。官方资产是 .tar.gz/.zip，解压走 OS 自带 tar（不引新依赖，见 core_swap 模块文档）。
    let core_bytes = match extract_core_bytes(base, &asset_name, &bytes) {
        Ok(b) => b,
        Err(e) => return Ok(ApiResponse::err(e)),
    };

    let version_line = if latest.is_empty() {
        String::new()
    } else {
        latest.clone()
    };
    Ok(swap_core_with_restart(
        &app,
        &state,
        base,
        &core_bytes,
        &version_line,
        core_swap::SwapSource::Update,
        false,
        &current,
        // 用户明确点了「更新」→ 允许为换核停/起核。
        SwapInterrupt::Allowed,
    )
    .await)
}

/// 把下载到的资产解成裸核字节（归档 → 解压 → 定位；已是裸二进制则原样返回）。
///
/// 解压落在 `<base>/core-staged/extract-<pid>-<seq>`（**每次调用唯一** + RAII 清理，见 [`ExtractWorkDir`]），
/// 不污染现役核目录、也不与并发的另一条解归档腿互踩。
///
/// `pub(crate)`：内核自动更新调度器（`runtime/core_update_scheduler.rs`）在暂存前走**同一条**
/// 解归档路径 —— 各写一份会在「哪些资产算裸二进制 / 解压到哪 / 何时清工作目录」上漂移。
pub(crate) fn extract_core_bytes(
    base: &std::path::Path,
    asset_name: &str,
    bytes: &[u8],
) -> Result<Vec<u8>, String> {
    if core_swap::is_raw_binary_asset(asset_name) {
        return Ok(bytes.to_vec());
    }
    let work = ExtractWorkDir::create(base)?;
    // 归档名来自资产名（可能含 `../`）→ 只取末段，绝不让它逃出工作目录。
    let archive_name = std::path::Path::new(asset_name).file_name().map_or_else(
        || "core-asset".to_string(),
        |s| s.to_string_lossy().into_owned(),
    );
    let archive = work.path().join(&archive_name);
    std::fs::write(&archive, bytes).map_err(|e| format!("写归档失败: {e}"))?;
    let out = work.path().join("x");
    core_swap::extract_archive(&archive, &out)?;
    let core = core_swap::pick_core_from_dir(&out, core_paths::core_filename())?;
    std::fs::read(&core).map_err(|e| format!("读解压产物失败: {e}"))
    // `work` 在此 drop → 无论成败（含上面任一 `?` 早退）都清掉工作目录。
}

/// 解归档工作目录：`<base>/core-staged/extract-<pid>-<seq>`（**每次调用唯一** + RAII 清理）。
///
/// # 为什么必须唯一
///
/// 原实现固定用 `core-staged/extract`，且入口就是 `rm -rf` 再重建。两条解归档腿并发时
/// （调度器的自动下载腿 vs 用户点的 `core_update_run` —— 调度器的 `busy` 闸**不覆盖手动命令**）
/// 它们互相 rm/写同一个目录：一方可能读到**对方**的核字节，并以自己的版本号 stage / 换入 ——
/// 簿记记的是 A 的版本，落盘的是 B 的二进制，且两边都「成功」。
///
/// RAII 清理同时修掉原实现的另一半：原来的 `let _ = remove_dir_all(&work)` 在 `?` 早退
/// （建目录后、写归档失败）和 panic 路径上都不执行，会留下 GB 级残件。
pub(super) struct ExtractWorkDir {
    path: std::path::PathBuf,
}

impl ExtractWorkDir {
    pub(super) fn create(base: &std::path::Path) -> Result<Self, String> {
        use std::sync::atomic::{AtomicU64, Ordering};
        /// 进程内单调序号（同一毫秒的两次调用也不会撞名）。
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let path =
            core_paths::staged_dir_in(base).join(format!("extract-{}-{seq}", std::process::id()));
        // 同名残件（上次进程硬崩留下的）先清；正常情况下这个路径不存在。
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).map_err(|e| format!("建解压工作目录失败: {e}"))?;
        Ok(Self { path })
    }

    pub(super) fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for ExtractWorkDir {
    fn drop(&mut self) {
        // 无论成败都清（本机 /tmp 与 config 目录都不该留 GB 级残件）。
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// 本次换核**允不允许**为换核停/起核。
///
/// 「绝不主动断流」是内核自动更新的硬不变量，而唯一持有 `proxy.stop()` 的地方是
/// [`swap_core_with_restart`] —— 判据必须收在那里，见 [`swap_blocked_by_no_interrupt`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SwapInterrupt {
    /// 用户明确发起（在线更新 / 回滚 / 手动替换 / 重置出厂 / 点「立即应用」）→ 可停可起。
    Allowed,
    /// 自动路径 → **绝不断流**：换核那一刻代理若在跑，一律放弃本次落位并保留 staged。
    Forbidden,
}

/// 纯判定：本次换核是否被「绝不主动断流」硬不变量拦下。
///
/// # 为什么这条判定必须在 [`swap_core_with_restart`] 里、而不能只留在调度器
///
/// 调度器的 `apply_staged_auto` 先判 `proxy.status().running == false` 才调落位命令，但从那次判定
/// 到 `swap_core_with_restart` 真正 `proxy.stop()` 之间，还隔着「读 `update-state.json` → 版本闸 →
/// **读几十 MB 的 staged 核文件** → sha 复核」几十~几百 ms（post-download 腿更是在下载完成的任意
/// 时刻触发）。用户在这个窗口里点「连接」，落位就会照常走 stop→swap→restart，**在用户从未同意的
/// 情况下断流一次**；新核起不来还会再走一遍回滚舞。
///
/// 判定放到读 `was_running` 的那一层后，判定与 `stop()` 之间不再有任何 `await`，窗口收敛到不可见。
#[must_use]
pub(super) const fn swap_blocked_by_no_interrupt(
    interrupt: SwapInterrupt,
    was_running: bool,
) -> bool {
    matches!(interrupt, SwapInterrupt::Forbidden) && was_running
}

/// 取换核返回里的 `result` 字段。
///
/// `deferred` 的信封是 `success:true`（它不是错误，是一次合法的「本轮不落位」），故**必须**能与
/// 「真的换成功了」区分 —— 否则 [`apply_staged_inner`] 会把一个字节都没换的轮次当成功、清掉 staged。
pub(super) fn swap_result_code(resp: &ApiResponse<Value>) -> Option<&str> {
    resp.data.as_ref()?.get("result")?.as_str()
}

/// 换核落位 + 停/起核编排（**唯一**的停起腿；四条换核路径共用）。
///
/// 顺序严格对齐规格 §7.3：
/// ```text
/// 1. 记录当前是否在跑 + 快照配置
/// 2. proxy.stop()                       ← 经 ProxyRuntime 公有 API，其内部走 LifecycleGate
/// 3. 备份现役核 → <core>.bak（skip_backup 时跳过）
/// 4. atomic_replace（tmp+rename）+ chmod +x +（macOS）xattr -cr / codesign
/// 5. proxy.start(config)
/// 6. 验证闩：起核失败 → 回滚 .bak → 再起 → 如实返 failed
/// 7. 成功 → 写 pendingChangeNotice{previous,current}
/// ```
///
/// **不绕过 `LifecycleGate` 自行发信号**：`ProxyRuntime::stop/start` 内部已持有 gate
/// （起停竞态单飞 + 世代守卫），此处调它们即是经 gate。
#[allow(clippy::too_many_arguments)]
pub(super) async fn swap_core_with_restart(
    app: &AppHandle,
    state: &AppRuntime,
    base: &std::path::Path,
    core_bytes: &[u8],
    version_line: &str,
    source: core_swap::SwapSource,
    skip_backup: bool,
    previous_version: &str,
    interrupt: SwapInterrupt,
) -> ApiResponse<Value> {
    // ── wire 契约前置检查：**非随包核唯一有牙的地方** ──────────────────────────
    //
    // `crates/singbox-grpc/build.rs` 那道 release 硬门的取材面只有 `resources/*/sing-box` 四条路径，
    // 而在线换核 / 用户自带 fork 走的正是本函数 —— 该路径此前无任何 wire 对拍，
    // 是 2026-08-05 那类「上游插一个字段把后面全顶掉一位 ⇒ 整条流静默死掉」在本仓仍敞着的一格。
    //
    // 判据只拦「字段号对不上」这一档（prost 整帧解码失败 → 当断线无限重连 → 功能**静默**消失，
    // 用户看不出）；符号缺失 / 抠不出 descriptor 一律放行 + 告警 —— 没观测到 ≠ 观测到没问题，
    // 据一次读失败剥夺用户自选的核是更坏的错（判据分档见 `verdict_for_core_bytes` 文档）。
    //
    // 位置在**停核之前**（也在 `swap_blocked_by_no_interrupt` 之前）：拒绝时用户的代理毫发无损，
    // 且不必先把一份注定要拒的核落到盘上。本检查是纯 CPU 的字节扫描，不含 await。
    // **回滚豁免**：那份 `.bak` 正是用户此前一直在跑的核，而回滚的触发场景恰恰是「新核不可用」——
    // 在这里拒绝回滚 = 把用户困在坏核上，且没有任何一条更安全的路可走。故只对「换上一份新核」
    // 这个方向拦；`Rollback` 直接放行（它换回去的东西本来就是现状的上一态）。
    if !matches!(source, core_swap::SwapSource::Rollback) {
        match polaris_singbox_grpc::verdict_for_core_bytes(core_bytes) {
            polaris_singbox_grpc::WireVerdict::Match => {}
            polaris_singbox_grpc::WireVerdict::Unobservable(why) => {
                log::warn!(
                    "换核 wire 契约对拍取不到判据（{why}）→ 放行（没观测到 ≠ 观测到没问题）"
                );
            }
            polaris_singbox_grpc::WireVerdict::Mismatch(report) => {
                log::error!("换核被拒：目标内核的管理 API 字段布局与本应用不一致\n{report}");
                return ApiResponse::err(format!(
                    "目标内核的管理 API 字段布局与本应用不一致，已放弃换核 —— \
                     换上去会让日志、连接、组网状态等整块**静默**失效（不报错、只是没有下一帧）：\n{report}"
                ));
            }
        }
    }

    let proxy = state.proxy.clone();
    let was_running = proxy.status().running;
    // ── 「绝不主动断流」硬不变量：判在**拥有 stop 的这一层**（成因见 `swap_blocked_by_no_interrupt`）。
    //    此后到 `proxy.stop()` 之间不得再插入任何 await —— 那会把 TOCTOU 窗口重新撑开。
    if swap_blocked_by_no_interrupt(interrupt, was_running) {
        log::info!("换核前一刻代理已在运行 → 自动路径放弃本次落位，保留 staged 待下次安全窗口");
        return ApiResponse::ok(json!({
            "result": "deferred",
            "ok": false,
            "reason": "proxy-running",
        }));
    }
    // 起核用的配置在停核**之前**快照：停完再读若失败就没法把用户的代理恢复回去。
    let config = if was_running {
        match state.config().load_full() {
            Ok(c) => Some(c),
            Err(e) => return ApiResponse::err(format!("读取配置失败，已放弃换核: {e}")),
        }
    } else {
        None
    };

    if was_running {
        if let Err(e) = proxy.stop().await {
            // 停不掉就**不换**（在核跑着时替换二进制：Linux ETXTBSY / Windows 文件占用）。
            return ApiResponse::err(format!("换核前停止内核失败，已放弃换核: {e}"));
        }
    }

    let swap = match core_swap::install_core_bytes(
        base,
        std::env::consts::OS,
        core_bytes,
        version_line,
        source,
        skip_backup,
    ) {
        Ok(s) => s,
        Err(e) => {
            // 落位失败 → 现役核未动（atomic_replace 保证），把代理恢复回去再报错。
            if let Some(c) = config {
                let _ = proxy.start(c).await;
            }
            return ApiResponse::err(format!("换核失败: {e}"));
        }
    };

    // ── 验证闩：新核起不来就自动回退（= 上游 `:1401` 的 arm 验证闩；skipBackup 时不 arm）。
    if let Some(c) = config {
        if let Err(start_err) = proxy.start(c.clone()).await {
            log::error!("新内核起核失败（{start_err}），触发自动回退");
            if swap.backed_up {
                match core_swap::rollback_core(base, std::env::consts::OS, previous_version) {
                    Ok(_) => {
                        let restarted = proxy.start(c).await.is_ok();
                        return ApiResponse::err(format!(
                            "新内核启动失败（{start_err}），已自动回滚到原内核{}",
                            if restarted {
                                "并重新启动"
                            } else {
                                "，但重启失败，请手动启动"
                            }
                        ));
                    }
                    Err(e) => {
                        return ApiResponse::err(format!(
                            "新内核启动失败（{start_err}），且回滚也失败（{e}）——请到设置页「重置为出厂内核」"
                        ));
                    }
                }
            }
            return ApiResponse::err(format!(
                "新内核启动失败（{start_err}），且本次未留备份（重置出厂路径）——请重试或重装应用"
            ));
        }
    }

    // ── 簿记回写：以**盘上那个二进制**为版本真值 ──
    // `install_core_bytes` 写进簿记的是调用方声明的 `version_line`，而两条主路径给的是空串
    // （`core_update_run` 前端恒传 downloadUrl ⇒ latest 为空；`core_rollback` 直接传 ""）。
    // 空簿记 ⇒ 下次启动判 unknown ⇒ `decide_reseed` 恒 Keep ⇒ 这个核被**永久钉住**，之后
    // `bundledCoreVersion` 提到多高都不再播种，盘面与 UI 都看不出来。判据与取舍见
    // `core_swap::marker_rewrite_line`。
    //
    // 位置**必须在验证闩之后**：闩内失败会走 `rollback_core`（它自己按 `previous_version`
    // 重写簿记），此刻盘上已经是**旧核**，在闩前回写只会把旧核的版本盖到新核的簿记上。
    // 用 `read_core_version_line()`（探测失败返空串），**不用** `read_core_version()`
    // ——后者失败回落随包基线，会把「读不到」伪装成「就是基线」写进簿记。
    let probed_line = state.updater().read_core_version_line();
    // 回写失败**不致命**：核已换好且已起来，此刻中止只会丢掉一次成功的换核。但要如实告警。
    if let Err(e) = core_swap::rewrite_marker_from_probe(base, version_line, &probed_line, source) {
        log::warn!("换核簿记回写失败（{e}）：簿记仍为空，该核将不被后续随包基线重播种");
    }

    // 版本变更通知（push 型持久位；banner show→ack 弹一次，非每启动重弹）。
    let current_version = state.updater().read_core_version();
    let _ = state.updater().mutate_state(|s| {
        s.pending_change_notice = Some(crate::runtime::updater::PendingChangeNotice {
            previous_version: previous_version.to_string(),
            current_version: current_version.clone(),
        });
    });
    crate::events::broadcast(
        app,
        crate::events::channel::EVENT_CORE_VERSION_CHANGED,
        json!({
            "previousVersion": previous_version,
            "currentVersion": current_version,
            "hasBackup": core_swap::has_backup(base, std::env::consts::OS),
        }),
    );

    // ── 稳定观察窗：起核成功**不等于**换核成功（= 上游 `armPendingValidation` + `startStabilityWatch`）──
    // 上面那道验证闩是同步的：`proxy.start()` 返 Err 才回滚。新核「起得来、几十秒后崩」这一类
    // 它一概看不见。守护腿补的正是这一段，条件与 上游 一致：
    //   · `was_running` —— 没重启过就没有「首次运行」可观察（arm 的前提是刚起了一次新核）；
    //   · `swap.backed_up` —— 没备份就无处可回滚，arm 了也只能干看着；
    //   · 非 Rollback 源 —— 否则回滚本身又 arm 一次，形成来回换核的循环。
    //     （Rollback 走 `skip_backup=true` ⇒ `backed_up` 恒 false，本条是**第二道**闸，写明意图。）
    if was_running && swap.backed_up && source != core_swap::SwapSource::Rollback {
        arm_core_validation(app.clone(), current_version.clone());
    }

    ApiResponse::ok(json!({
        "ok": true,
        "result": "applied",
        "corePath": swap.core_path.to_string_lossy(),
        "hasBackup": swap.backed_up,
        "previousVersion": previous_version,
        "currentVersion": current_version,
        "restarted": was_running,
    }))
}

/// 换核后的**稳定观察窗守护腿**（上游 `startStabilityWatch` + `autoRollbackIfPendingUpdate` 的编排侧）。
///
/// 判据与常量在 [`core_validation`](crate::runtime::core_validation)（纯逻辑、可穷举单测）；
/// 本函数只做那三件带副作用的事：**置抑制位 → 轮询观察 → 回滚**。
///
/// # 时序
///
/// 1. 置 `auto_restart_suppressed(true)`：窗口内核意外退出**不自动重启**。没有这一步，Polaris 的
///    崩溃自愈会先退避重启 3 次再放弃 —— 把「新核有问题」这个信号淹掉，而那是本窗口唯一要采集的信息。
/// 2. 每 `POLL_INTERVAL` 看一次 `proxy.status()`，直到 `STABILITY_DWELL` 走完。
/// 3. 观察到 [`failure_warrants_rollback`](crate::runtime::core_validation::failure_warrants_rollback)
///    成立 → **先撤抑制位再回滚**（顺序不可反：回滚回去的老核必须立刻恢复崩溃自愈保护），
///    然后走 [`core_rollback`] 的整条编排（读备份 → 停/起核 → prune → 清陈旧「已更新」通知）。
///
/// # 已知边界（如实登记，与 上游 同）
///
/// - 用户在窗口内**主动停核** ⇒ `running=false` 但无错误码 ⇒ 判据不成立 ⇒ 窗口走完按「稳定」收尾。
///   即这次换核实际上没被真正验证过。上游的 `startStabilityWatch` 定时器同样照常到期，
///   本移植不额外收紧 —— 收紧要引入「用户意图」输入，那是新语义不是移植。
/// - 观察窗只覆盖**本次进程存活期**。窗口内应用退出 ⇒ 状态随进程消失，下次启动不续验（上游 亦然：
///   `pendingUpdateVersion` 是内存态）。
pub(super) fn arm_core_validation(app: AppHandle, new_version: String) {
    use crate::runtime::core_validation::{
        failure_warrants_rollback, POLL_INTERVAL, STABILITY_DWELL,
    };

    tauri::async_runtime::spawn(async move {
        let proxy = app.state::<AppRuntime>().proxy.clone();
        proxy.set_auto_restart_suppressed(true);
        log::info!(
            "换核验证窗口开启（{}s）：新内核 {new_version}，窗口内核异常退出将自动回滚",
            STABILITY_DWELL.as_secs()
        );

        let mut waited = std::time::Duration::ZERO;
        let mut failed = false;
        while waited < STABILITY_DWELL {
            tokio::time::sleep(POLL_INTERVAL).await;
            waited += POLL_INTERVAL;
            let st = proxy.status();
            if failure_warrants_rollback(st.running, st.error_code.as_deref()) {
                log::error!(
                    "换核验证窗口内新内核 {new_version} 异常退出（code={:?}，距换核 {:?}）→ 自动回滚",
                    st.error_code,
                    waited
                );
                failed = true;
                break;
            }
        }

        // 撤抑制位**必须在回滚之前**：回滚会把老核起回来，那一刻起它就该受崩溃自愈保护；
        // 也覆盖「稳定收尾」这条路径，故放在分支之外无条件执行。
        proxy.set_auto_restart_suppressed(false);

        if !failed {
            log::info!("新内核 {new_version} 稳定运行 {STABILITY_DWELL:?}，换核验证通过");
            return;
        }

        // 复用 `core_rollback` 的整条编排（读备份 → 同一条停/起核 → prune → 清陈旧通知），
        // 不在此另写一份：那会变成第二个「怎么回滚」的真值源。
        match core_rollback(app.clone(), app.state::<AppRuntime>()).await {
            Ok(resp) if resp.success => {
                log::warn!("已自动回滚到原内核（新内核 {new_version} 未通过换核验证）");
            }
            Ok(resp) => {
                log::error!(
                    "自动回滚失败：{} —— 请到设置页手动回滚或「重置为出厂内核」",
                    resp.error.as_deref().unwrap_or("未知原因")
                );
            }
            Err(()) => log::error!("自动回滚调用失败 —— 请到设置页手动回滚"),
        }
    });
}

/// 上游 `core:getVersionInfo`：内核版本信息。
///
/// ✅ **已接线**（§C6 的主消费点）：`currentVersion` / `bundledVersion` / `build`
/// （official|fork|unknown）/ `pendingChangeNotice`。
///
/// `build` 经 `classify_core_build(原始版本行)` —— 喂的是**失败置空**的读法产物，
/// 故探测失败时如实报 `unknown`（**不回落基线伪装成 official**）。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn core_get_version_info(state: State<'_, AppRuntime>) -> ApiResponse<Value> {
    let u = state.updater();
    let st = u.state();
    let build = match u.core_build_kind() {
        CoreBuildKind::Official => "official",
        CoreBuildKind::Fork => "fork",
        CoreBuildKind::Unknown => "unknown",
    };
    // 备份状态现读**真实** `.bak`（换核链路已接线，备份由任何一次换核产生）。
    let os = std::env::consts::OS;
    let backup = core_paths::base_dir().filter(|b| core_swap::has_backup(b, os));
    // ⚠️ `backupVersion` 需跑 `<bak> version` 才知道 —— 那是**执行内核二进制**，属真机腿
    // （本机禁起核）。故这里如实返 `null` 而非编造：UI 只需 `hasBackup` 就能给出「回滚」按钮，
    // 版本号缺失不影响功能。**绝不**拿现役核版本冒充备份版本（那会让用户以为回滚到别的版本）。
    ApiResponse::ok(json!({
        "currentVersion": u.read_core_version(),
        "bundledVersion": u.bundled_core_version(),
        "build": build,
        "hasBackup": backup.is_some(),
        "backupVersion": Value::Null,
        "pendingChangeNotice": serde_json::to_value(st.pending_change_notice).unwrap_or(Value::Null),
    }))
}

/// 上游 `core:rollback`：回滚到备份内核。
///
/// ✅ **已接线**：`<core>.bak` → `<core>`（原子替换）+ 停/起核 + 清 `pendingChangeNotice`。
///
/// 无备份时**保留** [`CODE_NO_BACKUP`]——那是**正确语义**（真的没有可回滚的东西），不是 stub。
#[tauri::command]
pub async fn core_rollback(
    app: AppHandle,
    state: State<'_, AppRuntime>,
) -> Result<ApiResponse<Value>, ()> {
    let base = match core_base_dir::<Value>() {
        Ok(b) => b,
        Err(resp) => return Ok(resp),
    };
    let os = std::env::consts::OS;
    if !core_swap::has_backup(base, os) {
        return Ok(ApiResponse::err_with_code(
            "没有可回滚的内核备份",
            CODE_NO_BACKUP,
        ));
    }
    let previous = state.updater().read_core_version();
    let backup_path = match core_paths::core_backup_path() {
        Some(p) => p,
        None => return Ok(ApiResponse::err("无法解析备份路径")),
    };
    // 空文件必须拒绝：落位一个 0 字节的核 = 直接 brick（起核必失败，且备份已被消费掉）。
    // `.bak` 由 `install_core_bytes` 从非空字节产出，故空只会来自外部截断/磁盘故障 ——
    // 概率低，但后果与另两条腿完全相同，判据不该只有两条腿有。
    let bytes = match std::fs::read(&backup_path) {
        Ok(b) if !b.is_empty() => b,
        Ok(_) => return Ok(ApiResponse::err("内核备份文件为空（已损坏），放弃回滚")),
        Err(e) => return Ok(ApiResponse::err(format!("读取内核备份失败: {e}"))),
    };

    // 走同一条停/起核编排（`skip_backup=true`：备份正被消费，不该再拿它备份一次自己）。
    let resp = swap_core_with_restart(
        &app,
        &state,
        base,
        &bytes,
        "",
        core_swap::SwapSource::Rollback,
        true,
        &previous,
        // 用户明确点了「回滚」→ 允许为换核停/起核。
        SwapInterrupt::Allowed,
    )
    .await;
    if resp.success {
        // 备份已被消费 → 删掉，避免 UI 出现「回滚到自己」的假选项。
        core_swap::prune_backup(base, os);
        // 陈旧的版本变更通知一并清（防回滚后还弹「已更新到 X」）。
        let _ = state
            .updater()
            .mutate_state(|s| s.pending_change_notice = None);
    }
    Ok(resp)
}

/// 上游 `core:replaceManual`：手动上传替换内核（**无网络**）。
///
/// ✅ **已接线**，零提权。两段式（对齐前端契约 `{ok:true}` / `{ok:false, needConfirm}`）：
///  1. 无 `filePath` → 弹文件选择器；
///  2. 经 [`decide_core_override`](polaris_updater::decide_core_override) 的同款判据预判
///     fork / 跨基线风险 → 需确认则返 `{ok:false, needConfirm:true, …}`，**不落位**；
///  3. `force=true` 或无风险 → 备份现役核 → 停核 → 原子替换 → 起核。
///
/// **跨带在此路径放行**（与自动更新相反）：手动换核是用户明确的一次性选择，上游 同语义。
#[tauri::command]
pub async fn core_replace_manual(
    app: AppHandle,
    state: State<'_, AppRuntime>,
    file_path: Option<String>,
    force: Option<bool>,
) -> Result<ApiResponse<Value>, ()> {
    let base = match core_base_dir::<Value>() {
        Ok(b) => b,
        Err(resp) => return Ok(resp),
    };

    // 1. 取文件：前端没给就弹系统文件选择器。
    let path = match file_path.filter(|s| !s.trim().is_empty()) {
        Some(p) => std::path::PathBuf::from(p),
        None => {
            use tauri_plugin_dialog::DialogExt;
            let picked = app
                .dialog()
                .file()
                .set_title(crate::i18n::t(
                    crate::i18n::app_lang(&app),
                    crate::i18n::key::NATIVE_CORE_PICK_TITLE,
                ))
                .blocking_pick_file();
            let Some(f) = picked else {
                // 用户取消 = 正常流程，不是错误（**不返 error 信封**，否则 UI 会弹红）。
                return Ok(ApiResponse::ok(json!({ "ok": false, "cancelled": true })));
            };
            match f.into_path() {
                Ok(p) => p,
                Err(e) => return Ok(ApiResponse::err(format!("解析所选文件路径失败: {e}"))),
            }
        }
    };
    if !path.is_file() {
        return Ok(ApiResponse::err(format!(
            "所选内核文件不存在: {}",
            path.display()
        )));
    }

    let u = state.updater();
    let bundled = u.bundled_core_version().to_string();
    let previous = u.read_core_version();

    // 2. 预判（**不执行上传的二进制**：本机禁起核，且执行来路不明的二进制本身就是风险面）。
    //    判据来自文件名里的版本 token —— 探测不到就当 unknown，走「需确认」而非静默放行。
    let name_token = extract_version_token(&path.file_name().unwrap_or_default().to_string_lossy());
    let forced = force == Some(true);
    if !forced {
        let comparable = ComparableVersion::normalize(&name_token);
        let baseline_override = compare_semver(comparable.as_str(), &bundled)
            .map(|o| o < 0)
            .unwrap_or(true); // 解析不出 = 未知 → 保守要求确认
        if baseline_override {
            return Ok(ApiResponse::ok(json!({
                "ok": false,
                "needConfirm": true,
                "baselineOverride": true,
                "uploadVersion": name_token,
                "bundledVersion": bundled,
                "filePath": path.to_string_lossy(),
            })));
        }
    }

    // 3. 落位。version_line 用文件名解析出的 token；解析不出即空串，随后由
    //    `swap_core_with_restart` 按 `core_swap::marker_rewrite_line` 用**盘上实读**补齐
    //    （连实读也失败才落 unknown）。
    //
    //    ⚠️ 「保护用户手放的核」**不靠这里的空串**，靠 `SwapSource::Manual` 那条显式豁免
    //    （`core_paths::decide_reseed`）。旧写法把两件事塞进一个空串，真实形状是：文件名解析
    //    得出版本 ⇒ 写进簿记 ⇒ official 且旧 ⇒ **照样被覆盖**；解析不出 ⇒ 永不覆盖。
    //    同一个用户动作、结果取决于文件名长什么样，那是不一致而非失败安全。现在拆开：
    //    **簿记如实记版本**（诚实，诊断/UI 看到真话）+ **决策尊重来源**（尊重意图）。
    let bytes = match std::fs::read(&path) {
        Ok(b) if !b.is_empty() => b,
        Ok(_) => return Ok(ApiResponse::err("所选内核文件为空")),
        Err(e) => return Ok(ApiResponse::err(format!("读取内核文件失败: {e}"))),
    };
    Ok(swap_core_with_restart(
        &app,
        &state,
        base,
        &bytes,
        &name_token,
        core_swap::SwapSource::Manual,
        false,
        &previous,
        // 用户明确选了文件替换内核 → 允许为换核停/起核。
        SwapInterrupt::Allowed,
    )
    .await)
}

/// 上游 `core:getAutoStatus`：内核自动更新状态。
///
/// ✅ **已接线**：纯本地状态读取（`autoUpdateCore` / `lastCheckAt` / `staged` /
/// `crossBandNotifiedVersion`），零网络零探测。
///
/// `autoUpdateCore` 现返**真值**（此前硬返 `null`）：判据是
/// [`auto_update_core_enabled`](crate::runtime::core_update_scheduler::auto_update_core_enabled)
/// —— 与调度器守门用的**同一个**纯函数，UI 显示的开关态与后台实际是否会跑不可能对不上。
/// 读配置失败 → `false`（失败安全：宁可显示「关」，也不显示一个不会生效的「开」）。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn core_update_get_auto_status(state: State<'_, AppRuntime>) -> ApiResponse<Value> {
    let st = state.updater().state();
    let enabled = state
        .config()
        .load_full()
        .map(|c| crate::runtime::core_update_scheduler::auto_update_core_enabled(&c))
        .unwrap_or(false);
    ApiResponse::ok(json!({
        "autoUpdateCore": enabled,
        "lastCheckAt": st.last_check_at,
        "staged": serde_json::to_value(st.staged).unwrap_or(Value::Null),
        "crossBandNotifiedVersion": st.cross_band_notified_version,
    }))
}

/// 上游 `core:applyStaged`：用户点「立即应用」已暂存的内核。
///
/// ✅ **已接线**：无 staged → `"noop"`；有 staged → 版本闸 → 落位（走同一条停/起核编排）。
///
/// 落位结果沿用 `ApplyOutcome` 的五态词汇（`applied` / `discarded` / `deferred` / `failed` / `noop`），
/// 与前端 `coreUpdateApi.applyStaged()` 的联合类型逐字对齐 —— **不用 void/boolean 折叠**
/// （上游 修 M1 的原因：布尔返回把 discarded/deferred/failed 一律误报成「已应用」）。
///
/// 另有 `discarded` 的新成因 `reason:"integrity"`：暂存核的 sha256 复核不过（位腐 / 篡改）。
#[tauri::command]
pub async fn core_update_apply_staged(
    app: AppHandle,
    state: State<'_, AppRuntime>,
) -> Result<ApiResponse<Value>, ()> {
    // 用户亲手点的「立即应用」→ 允许为换核停/起核。
    Ok(apply_staged_inner(&app, &state, SwapInterrupt::Allowed).await)
}

/// 自动路径的落位入口（**仅**供 `runtime/core_update_scheduler.rs` 调用）。
///
/// 与 [`core_update_apply_staged`] 唯一的差别是 [`SwapInterrupt::Forbidden`]：换核那一刻代理若在跑，
/// **不停核**、返 `deferred`、保留 staged 等下一个安全窗口。调度器自己那道 `running == false` 的
/// gating 只是省一次白跑，**不是**不变量的守卫 —— 守卫在 [`swap_core_with_restart`]
/// （见 [`swap_blocked_by_no_interrupt`]）。
pub(crate) async fn core_update_apply_staged_auto(
    app: &AppHandle,
    state: &AppRuntime,
) -> ApiResponse<Value> {
    apply_staged_inner(app, state, SwapInterrupt::Forbidden).await
}

/// [`core_update_apply_staged`] / [`core_update_apply_staged_auto`] 的共同本体。
pub(super) async fn apply_staged_inner(
    app: &AppHandle,
    state: &AppRuntime,
    interrupt: SwapInterrupt,
) -> ApiResponse<Value> {
    let Some(staged) = state.updater().state().staged else {
        return ApiResponse::ok(json!({ "result": "noop" }));
    };
    let base = match core_base_dir::<Value>() {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    let current = state.updater().read_core_version();

    // 版本闸：staged 不再领先当前 → 作废（= 上游 `compareVersions <= 0 → clearStaged → discarded`）。
    if compare_semver(&staged.version, &current)
        .map(|o| o <= 0)
        .unwrap_or(true)
    {
        discard_staged_dir(state, &staged.dir);
        return ApiResponse::ok(json!({ "result": "discarded" }));
    }

    let staged_dir = std::path::Path::new(&staged.dir);
    let staged_core = staged_dir.join(core_paths::core_filename());
    let bytes = match std::fs::read(&staged_core) {
        Ok(b) if !b.is_empty() => b,
        // 暂存核缺失/为空 → 作废清理（= 上游「staged 暂存核心缺失，清理」）。
        _ => {
            discard_staged_dir(state, &staged.dir);
            return ApiResponse::ok(json!({ "result": "discarded" }));
        }
    };

    // ── 完整性复核（stage → apply 之间可隔多日）：暂存时自算的**裸核** sha256 在这里对账。
    //    起核验证闩只能拦「起不来」，拦不住「起得来但行为坏」的位腐/篡改核。
    let recorded = std::fs::read_to_string(staged_core_sha_path(staged_dir)).ok();
    match check_staged_integrity(&bytes, recorded.as_deref()) {
        StagedIntegrity::Mismatch => {
            log::error!(
                "暂存内核完整性复核失败（位腐或被篡改），已作废不落位：{}",
                staged.dir
            );
            discard_staged_dir(state, &staged.dir);
            return ApiResponse::ok(json!({ "result": "discarded", "reason": "integrity" }));
        }
        StagedIntegrity::Unrecorded => {
            log::debug!("暂存内核无 sha256 记录（旧版本 App 暂存的）→ 跳过完整性复核");
        }
        StagedIntegrity::Ok => {}
    }

    let resp = swap_core_with_restart(
        app,
        state,
        base,
        &bytes,
        &staged.version,
        core_swap::SwapSource::Update,
        false,
        &current,
        interrupt,
    )
    .await;
    // `deferred`（不断流硬不变量拦下）信封是 success:true 但**一个字节都没换** → 绝不能清 staged。
    if swap_result_code(&resp) == Some("deferred") {
        return resp;
    }
    if resp.success {
        discard_staged_dir(state, &staged.dir);
        return resp;
    }
    // 落位失败：**保留 staged 待重试**（= 上游 failed 语义），并如实返 failed。
    ApiResponse::ok(json!({
        "result": "failed",
        "error": resp.error,
    }))
}

/// 作废 staged：清簿记 + 删暂存目录（三条作废路径共用，避免各写一份漏删）。
pub(super) fn discard_staged_dir(state: &AppRuntime, dir: &str) {
    let _ = state.updater().mutate_state(|s| s.staged = None);
    let _ = std::fs::remove_dir_all(dir);
}

/// 暂存核的 sha256 旁挂文件：`<staged_dir>/<core_filename>.sha256`（内容 = 64 字符 hex）。
///
/// # 为什么是旁挂文件而不是 `StagedRecord` 字段
///
/// 旁挂文件与被它校验的字节**同目录、同生命周期**：`CoreStagedUpdater::stage` 每次都
/// `remove_dir_all(staged_dir)` 重建，故不可能出现「摘要还是旧的、核已被换成别的」这种错配；
/// 而写进 `update-state.json` 的字段与暂存目录是两份独立状态，一致性得自己维护。
///
/// 文件名收在此一处：生产端（`runtime/core_update_scheduler.rs` 暂存后写）与消费端
/// （[`apply_staged_inner`] 落位前读）共用，各拼一份必然漂移。
pub(crate) fn staged_core_sha_path(staged_dir: &Path) -> PathBuf {
    staged_dir.join(format!("{}.sha256", core_paths::core_filename()))
}

/// 暂存核完整性复核的三态结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StagedIntegrity {
    /// 没有摘要记录（旧版本 App 暂存的核）→ **放行**：拿不到基准不等于字节坏了，
    /// 「没记录就拒绝落位」会让跨版本升级的用户白丢一次已下好的核。
    Unrecorded,
    /// 复核通过。
    Ok,
    /// 与暂存时记录的摘要不符 → 位腐 / 被篡改 → 必须作废，绝不换入。
    Mismatch,
}

/// 纯判定：暂存核字节 vs 暂存时记录的 sha256。
///
/// 空串 / 全空白的记录按「没有记录」处理（旁挂文件写了一半不该把一个好核毙掉）。
/// 非法 hex（长度不对 / 非 hex 字符）走 [`verify_bytes`] 判成错误 → [`StagedIntegrity::Mismatch`]：
/// 那说明旁挂文件本身已损坏，与它同目录的核不值得信任。
#[must_use]
pub(crate) fn check_staged_integrity(bytes: &[u8], recorded_sha: Option<&str>) -> StagedIntegrity {
    let Some(sha) = recorded_sha.map(str::trim).filter(|s| !s.is_empty()) else {
        return StagedIntegrity::Unrecorded;
    };
    if verify_bytes(bytes, sha).is_ok() {
        StagedIntegrity::Ok
    } else {
        StagedIntegrity::Mismatch
    }
}

/// 上游 `core:ackVersionChange`：banner 展示版本变更通知后 ack 清除。
///
/// ✅ **已接线**：清 `pendingChangeNotice`（show→ack，弹一次非每启）。
///
/// 语义要点（= 上游 `ackPendingChangeNotice:1171-1175`）：这是「推送式一次性通知」的消费端，
/// 取代了旧的「last-known-version !== current」推断式判定（后者每次启动都重弹）。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn core_update_ack_version_change(state: State<'_, AppRuntime>) -> ApiResponse<()> {
    match state
        .updater()
        .mutate_state(|s| s.pending_change_notice = None)
    {
        Ok(()) => ok_void(),
        Err(e) => ApiResponse::err(e),
    }
}

/// 上游 `core-update:reset-factory`：把内核恢复为随 App 出厂的版本。
///
/// ✅ **已接线**：≡ `replaceManual({filePath: 随包核, force: true, skipBackup: true})` + `pruneBackup`。
///
/// # `skip_backup=true` 的语义（严格照 上游 `CoreUpdateService.ts:1272-1278, 1475-1484`）
///
/// 不备份、不 arm 验证闩、不自动回退，末尾清残留 `.bak`。理由：现役核正是用户**主动要丢弃**的那个，
/// 出厂核已知稳定。若照常备份，用户「重置到出厂」后 UI 会冒出一个「回滚到刚被丢弃的核」的选项，
/// 语义正好倒错。
#[tauri::command]
pub async fn core_reset_factory(
    app: AppHandle,
    state: State<'_, AppRuntime>,
) -> Result<ApiResponse<Value>, ()> {
    let base = match core_base_dir::<Value>() {
        Ok(b) => b,
        Err(resp) => return Ok(resp),
    };
    // **随包出厂核**（绕过可写核优先级与 env 逃生门——要的正是「出厂那一份」）。
    let bundled_path = match core_paths::bundled_core_path() {
        Ok(p) => p,
        Err(e) => return Ok(ApiResponse::err(format!("未找到随包出厂内核: {e}"))),
    };
    let bytes = match std::fs::read(&bundled_path) {
        Ok(b) if !b.is_empty() => b,
        Ok(_) => return Ok(ApiResponse::err("随包出厂内核文件为空（打包异常）")),
        Err(e) => return Ok(ApiResponse::err(format!("读取随包出厂内核失败: {e}"))),
    };
    let u = state.updater();
    let previous = u.read_core_version();
    let bundled_version = u.bundled_core_version().to_string();

    let resp = swap_core_with_restart(
        &app,
        &state,
        base,
        &bytes,
        &bundled_version,
        core_swap::SwapSource::ResetFactory,
        true, // skip_backup
        &previous,
        // 用户明确点了「重置为出厂内核」→ 允许为换核停/起核。
        SwapInterrupt::Allowed,
    )
    .await;
    // 末尾清残留（install_core_bytes 在 skip_backup 分支已 prune 一次；此处覆盖失败路径）。
    core_swap::prune_backup(base, std::env::consts::OS);
    Ok(resp)
}
