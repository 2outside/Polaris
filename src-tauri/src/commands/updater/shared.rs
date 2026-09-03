//! App/Core 更新命令共用的窄原语。

use super::{CODE_CORE_DIR_UNAVAILABLE, GITHUB_FETCH_TIMEOUT_MS, MAX_GITHUB_JSON_BYTES};
use crate::response::ApiResponse;
use crate::runtime::http::{app_user_agent, CoreDownloader, SystemDnsLookup};
use crate::runtime::{core_paths, AppRuntime};
use polaris_net_stack::safe_redirect::{safe_redirect_fetch, SafeRedirectFetchOptions};
use polaris_updater::github::github_releases_api_url;

pub(crate) fn core_base_dir<T>() -> Result<&'static std::path::Path, ApiResponse<T>> {
    core_paths::base_dir().ok_or_else(|| {
        ApiResponse::err_with_code(
            "内核可写目录未初始化（应用启动期 core_paths::init_base_dir 未执行）",
            CODE_CORE_DIR_UNAVAILABLE,
        )
    })
}

/// 构造生产下载器（真实 HTTP + 用户配置的 gh 加速前缀）。
///
/// gh 前缀取自通用 config（`ghProxyPrefix`）；读不到就空串 = 不用镜像（**只回退，不改写原址优先**）。
///
/// `pub(crate)`：内核自动更新调度器（`runtime/core_update_scheduler.rs`）复用**同一个**构造入口 ——
/// 各建一份必然在 gh 前缀读法上漂移。
///
/// # `max_bytes` 为什么是形参
///
/// 三条生产腿的体积闸**语义不同**：两条内核腿把整包收进 `Vec<u8>` 再解归档 ⇒ 闸是**内存闸**，
/// 恒传 [`MAX_DOWNLOAD_BYTES`](crate::runtime::http::MAX_DOWNLOAD_BYTES)（16 MiB，与形参化之前逐字一致）；App 安装包腿改成流式落盘后
/// 内存不随包体积长 ⇒ 16 MiB 只会把所有正常安装包拒掉，闸改由「清单声明大小 + 裕度」注入
/// （见 [`app_update_size_limit`](super::app_update::app_update_size_limit)）。
///
/// 选形参而非「再开一个构造入口」：gh 前缀读法只该有一份。两个入口意味着有一天 App 腿
/// 读不到用户配的镜像前缀，而没有任何测试会发现。
pub(crate) fn updater_downloader(state: &AppRuntime, max_bytes: usize) -> CoreDownloader {
    let prefix = state
        .config()
        .get_value("ghProxyPrefix")
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    CoreDownloader::new(state.http().clone(), tokio::runtime::Handle::current())
        .with_gh_proxy(prefix)
        .with_max_bytes(max_bytes)
}

/// GitHub releases API 的**状态码 → 成因文案**（纯函数）。`None` = 2xx，调用方继续读 body。
///
/// 抽成自由函数只为**可测**：判定夹在真 HTTP 调用之后，留在 [`fetch_releases_json`] 里就只能起真
/// 网络才断言得了，而本仓禁跑触网测试 —— 那等于这段「哪个状态码是什么成因」一条断言都没有。
pub(crate) fn github_status_error(status: u16, owner: &str, repo: &str) -> Option<String> {
    match status {
        200..=299 => None,
        // 403 限流单独成因（= 上游 `fetchReleases`）：它与「403 无权限」表象相同但处置相反。
        403 => Some("GitHub API 访问频率限制 (403)，请稍后再试或配置 GitHub 加速".to_string()),
        // 404 单独成因。**它不是「该仓库还没有 release」**：本端点是 releases **列表**
        // （`/repos/{owner}/{repo}/releases`，不是 `/releases/latest`），零 release 的**可见**仓库
        // 返回的是 `200 []` —— 由 `check_app_update` 判 `NoUpdate`（见 updater crate 的
        // `check_app_update_empty_releases_is_no_update`）。所以这里的 404 只有一个含义：
        // **更新源仓库对本次（未鉴权）请求不可见** —— 不存在 / 已改名 / 或是私有仓。GitHub 对私有仓
        // 一律以 404 掩盖存在性而**不是** 403，故上面的 403 分支永远兜不到这类。
        //
        // 仍返 `Err` 而不伪装成「已是最新」：把「更新通道整条不通」显示成已最新会让它永久静默，
        // 违反本函数下方 [`fetch_releases_json`] 的反伪造契约。原文案只有裸状态码，分辨不出
        // 「URL 写错」还是「仓库不可见」，带上 owner/repo 才是可行动的诊断（两条检查腿共用本函数，
        // 不带仓名连是 app 腿还是 core 腿都看不出）。
        404 => Some(format!(
            "更新源仓库不可访问 (404)：{owner}/{repo} 不存在、已改名或为私有仓库"
        )),
        s => Some(format!("GitHub API 返回错误: {s}")),
    }
}

/// 拉 GitHub releases JSON（**单点**：app 与 core 两条检查腿共用同一条 SSRF 安全路径）。
///
/// 失败语义（反伪造）：网络/SSRF/超时/非 2xx 一律 `Err(消息)`，**绝不**把失败伪装成「已是最新」。
pub(crate) async fn fetch_releases_json(
    state: &AppRuntime,
    owner: &str,
    repo: &str,
) -> Result<String, String> {
    let http = state.http().clone();
    let url = github_releases_api_url(owner, repo);
    let resp = safe_redirect_fetch(SafeRedirectFetchOptions {
        fetch_impl: http.as_ref(),
        url: &url,
        user_agent: app_user_agent(),
        headers: Some(vec![(
            "Accept".to_string(),
            "application/vnd.github.v3+json".to_string(),
        )]),
        exempt_fake_ip: false,
        max_redirects: Some(5),
        timeout_ms: Some(GITHUB_FETCH_TIMEOUT_MS),
        max_body_bytes: Some(MAX_GITHUB_JSON_BYTES),
        lookup: &SystemDnsLookup,
    })
    .await
    .map_err(|e| format!("请求 GitHub 失败: {}", e.message))?;

    if let Some(msg) = github_status_error(resp.status, owner, repo) {
        return Err(msg);
    }
    Ok(String::from_utf8_lossy(&resp.body).into_owned())
}
