use serde_json::{json, Value};
use std::path::Path;
use tauri::{AppHandle, Manager, State, WebviewUrl, WebviewWindowBuilder};

use crate::response::ApiResponse;
use crate::runtime::AppRuntime;

/// sing-box 官方面板内窗口 label（单例：已存在则聚焦复用，对齐 上游 `dashboardWindow`）。
const DASHBOARD_WINDOW_LABEL: &str = "singbox-dashboard";

/// 上游 `OPEN_SINGBOX_DASHBOARD`：打开 sing-box 官方面板（应用内 webview 窗，dashboard #55）。
///
/// 对齐 上游 helper-handlers `OPEN_SINGBOX_DASHBOARD`：开一个内窗口加载核 serve 的运行期
/// `http://127.0.0.1:<clash_api_port>/dashboard/`，并经 `initialization_script`（= Electron preload 等价：
/// document-start 于面板同源执行）在面板 JS 读 localStorage 前预写后端连接——**面板只读 localStorage、不读 URL
/// 参数**（上游 真机 + 面板源码实证），故必须此路径注入而非 URL query。写两个键覆盖各版本面板：
///  - `sing-box-dashboard.servers`：权威 `{servers:[{id,name,url,secret}],activeId}`；
///  - `sing-box-dashboard.server` ：旧版扁平 `{url,secret}` 迁移键。
///
/// 安全（H1）：本窗加载第三方面板代码且 localStorage 内含 clash_api secret → `on_navigation` 锁死导航边界，
/// 仅允许停留在本地 api service 源，跨源 http(s) 一律拦（防 secret 外泄）。代理未运行（端口=0）→ 不开窗。
///
/// 系统右键菜单：本窗与本仓三个前端入口同口径禁掉（第二条 `initialization_script`，见
/// [`DISABLE_CONTEXT_MENU_SCRIPT`]）。`initialization_script` 是 **push 语义**（tauri 2.11.5
/// `webview/mod.rs`：`initialization_scripts.push(..)`），两次调用都会注入，不互相覆盖。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn open_singbox_dashboard(
    app: AppHandle,
    state: State<'_, AppRuntime>,
    locale: Option<String>,
) -> ApiResponse<Value> {
    let info = state.proxy().dashboard_connection();
    if !info.get("ok").and_then(Value::as_bool).unwrap_or(false) {
        return ApiResponse::ok(json!({ "ok": false }));
    }
    // 已有面板窗 → 聚焦复用（对齐 上游「已存在则 focus」，不重复开窗）。
    if let Some(win) = app.get_webview_window(DASHBOARD_WINDOW_LABEL) {
        let _ = win.set_focus();
        return ApiResponse::ok(json!({ "ok": true }));
    }
    let url = info
        .get("url")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let api_url = info
        .get("apiUrl")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let secret = info
        .get("secret")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if url.is_empty() || api_url.is_empty() {
        return ApiResponse::ok(json!({ "ok": false }));
    }
    // 面板后端 url 用 host:port（无协议前缀），与面板归一化（去 http:// 前缀 + 去尾斜杠）后的存量格式一致。
    let bare = api_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .to_string();
    let script = build_dashboard_preload_script(
        &bare,
        &secret,
        map_locale_to_dashboard_lang(locale.as_deref()),
    );

    let parsed = match url.parse::<tauri::Url>() {
        Ok(u) => u,
        Err(e) => return ApiResponse::err(format!("面板 URL 非法：{e}")),
    };
    // 仅允许停留在本地 api service 源（`http://127.0.0.1:<port>/…`）；跨源 http(s) 拦下。内部 scheme 放行。
    let allowed_prefix = format!("{api_url}/");
    let win = WebviewWindowBuilder::new(&app, DASHBOARD_WINDOW_LABEL, WebviewUrl::External(parsed))
        .title("sing-box Dashboard")
        .inner_size(1100.0, 760.0)
        .min_inner_size(800.0, 600.0)
        // preload 等价：document-start 于面板同源预写 localStorage（读前已写）。
        .initialization_script(&script)
        // 同一条 preload 通道再挂一次系统右键菜单禁用（面板是第三方产物，改不了它的 JS）。
        .initialization_script(DISABLE_CONTEXT_MENU_SCRIPT)
        .on_navigation(move |u| {
            let scheme = u.scheme();
            if scheme == "http" || scheme == "https" {
                u.as_str().starts_with(&allowed_prefix)
            } else {
                true // tauri:/about:/data: 等内部 scheme 放行
            }
        })
        .build();
    match win {
        Ok(_) => ApiResponse::ok(json!({ "ok": true })),
        Err(e) => ApiResponse::err(format!("建面板窗失败：{e}")),
    }
}

/// Electron/系统 locale → 面板合法语言码（源码实证 `en/zh-Hans/zh-Hant/fa/ru`；前缀匹配处理 zh-CN/zh-TW/fa-IR 等）。
fn map_locale_to_dashboard_lang(locale: Option<&str>) -> &'static str {
    let l = locale.unwrap_or("").to_ascii_lowercase();
    if l.starts_with("zh-hant")
        || l.starts_with("zh-tw")
        || l.starts_with("zh-hk")
        || l.starts_with("zh-mo")
    {
        "zh-Hant"
    } else if l.starts_with("zh") {
        "zh-Hans"
    } else if l.starts_with("fa") {
        "fa"
    } else if l.starts_with("ru") {
        "ru"
    } else {
        "en"
    }
}

/// 构造面板 preload 脚本（注入 localStorage 后端连接）。payload 经 serde_json **双重序列化**嵌为 JS 字符串字面量
/// （secret 含引号/反斜杠也不破——serde 产的字符串本身即合法 JS 字面量），杜绝脚本注入。对齐 上游 `dashboard-preload.ts`。
fn build_dashboard_preload_script(bare_url: &str, secret: &str, lang: &str) -> String {
    // 单一 server（id 固定即可，面板按 activeId 选中）。
    const SERVER_ID: &str = "polaris";
    let servers_val = json!({
        "servers": [{ "id": SERVER_ID, "name": "", "url": bare_url, "secret": secret }],
        "activeId": SERVER_ID,
    });
    let legacy_val = json!({ "url": bare_url, "secret": secret });
    // localStorage 值须为 string → 先 stringify 成 JSON 字符串，再序列化成 JS 字符串字面量嵌入脚本。
    let servers_lit =
        serde_json::to_string(&servers_val.to_string()).unwrap_or_else(|_| "\"\"".into());
    let legacy_lit =
        serde_json::to_string(&legacy_val.to_string()).unwrap_or_else(|_| "\"\"".into());
    let lang_lit = serde_json::to_string(lang).unwrap_or_else(|_| "\"en\"".into());
    format!(
        "(function(){{try{{var ls=window.localStorage;if(!ls)return;\
ls.setItem('sing-box-dashboard.servers',{servers_lit});\
ls.setItem('sing-box-dashboard.server',{legacy_lit});\
if(!ls.getItem('sing-box-dashboard.language')){{ls.setItem('sing-box-dashboard.language',{lang_lit});}}\
}}catch(e){{}}}})();"
    )
}

/// 面板窗的系统右键菜单禁用脚本（document-start 注入）—— 本仓第四个 webview 入口。
///
/// 前三个（主窗 / 托盘浮层 / 更新弹窗）在前端各调一次 `disableNativeContextMenu()`
/// （`ui/src/lib/native-context-menu.ts`）。面板窗**够不到那条腿**：页面是
/// `scripts/fetch-dashboard.mjs` 拉下来的第三方产物、由核 serve，我们改不了它的 JS，
/// 只能经 `initialization_script`（= preload 等价，document-start 同源执行）从外面挂同一条监听。
///
/// 判据与 TS 侧**逐条对齐**（可编辑文本控件放行系统菜单以便粘贴 / 复制，其余一律禁）：
/// input 类型白名单、label→control 解析、disabled 不放行 / readonly 放行、contenteditable 继承。
/// 完整论证在 TS 那份头注，此处不复述。
///
/// ⚠️ 这是**跨语言的第二份实现**（TS 那份跑不到本窗里）。防漂移靠
/// `ui/src/lib/native-context-menu.test.ts` 的 parity 断言：它把两边的类型白名单抠出来比对，
/// 只改一边即转红。
const DISABLE_CONTEXT_MENU_SCRIPT: &str = "(function(){\
var T=['text','search','url','tel','email','password','number'];\
document.addEventListener('contextmenu',function(e){\
var el=e.target;\
if(el&&el.closest){\
var h=el.closest('input, textarea')||(el.closest('label')||{}).control||el;\
var g=(h.tagName||'').toUpperCase();\
if(g==='TEXTAREA'?!h.disabled:g==='INPUT'\
?(!h.disabled&&T.indexOf((h.type||'text').toLowerCase())>=0)\
:h.isContentEditable===true)return;\
}\
e.preventDefault();\
});})();";

/// sing-box 官方面板资源缓存目录名（`<config_dir>/singbox-dashboard`）。核首启时若该目录为空，从
/// `download_url` 拉 zip 解此 + 写 `.etag`；「刷新面板资源」清此目录使核下次启动重拉。对齐 上游
/// `getSingboxDashboardDir()`（`<userData>/singbox-dashboard`，utils/paths.ts）。
const SINGBOX_DASHBOARD_DIR: &str = "singbox-dashboard";

/// 清 sing-box 面板资源缓存目录（best-effort，幂等）。抽出为纯函数便于单测喂临时目录。
///
/// 对齐 上游 `clearSingboxDashboardCache`（helper-handlers.ts）：`fs.rmSync(dir, {recursive, force})`——
/// 删失败 / 目录不存在（ENOENT）均**不致命**（核启动若目录仍非空只是沿用旧资源，下次仍可重试清理），
/// 故忽略错误。
fn clear_singbox_dashboard_cache(dashboard_dir: &Path) {
    let _ = std::fs::remove_dir_all(dashboard_dir);
}

/// 上游 `REFRESH_SINGBOX_DASHBOARD`：清面板资源缓存目录（核下次启动重拉）。
///
/// 对齐 上游 helper-handlers `REFRESH_SINGBOX_DASHBOARD`：清 `<config_dir>/singbox-dashboard` → 核下次
/// 启动（或下次配置变更触发的 `switch_mode` 重启）重拉新 zip。**不在此触发重启**（保「不打断连接」语义）
/// ——UI 提示用户重连 / 下次启动生效。删目录幂等，不存在不报错。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn refresh_singbox_dashboard(state: State<'_, AppRuntime>) -> ApiResponse<Value> {
    clear_singbox_dashboard_cache(&state.config().dir().join(SINGBOX_DASHBOARD_DIR));
    ApiResponse::ok(json!({ "ok": true }))
}

/// 上游 `GET_SINGBOX_DASHBOARD_CONNECTION`：取面板连接信息（URL + secret）。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn get_singbox_dashboard_connection(state: State<'_, AppRuntime>) -> ApiResponse<Value> {
    ApiResponse::ok(state.proxy().dashboard_connection())
}

#[cfg(test)]
mod tests;
