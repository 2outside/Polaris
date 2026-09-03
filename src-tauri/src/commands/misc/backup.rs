use std::collections::BTreeSet;
use std::path::PathBuf;

use serde_json::{json, Value};
use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;

use super::support::{node_platform, now_iso8601, today_yyyy_mm_dd};
use crate::i18n::{key, t};
use crate::response::ApiResponse;
use crate::runtime::AppRuntime;
use polaris_store::backup::{
    build_backup_info, count_category, detect_categories, merge_categories, parse_backup_content,
    pick_categories, sanitize_cross_platform_rules, sanitize_unavailable_interface_bindings,
    BackupCategory, BACKUP_CATEGORIES, BACKUP_FILE_VERSION,
};

/// 把前端传来的类别串解析成枚举；空 / None → 全选。
/// 未知类别忽略，以兼容版本差异。
fn parse_categories(raw: Option<Vec<String>>) -> Vec<BackupCategory> {
    let picked: Vec<BackupCategory> = raw
        .unwrap_or_default()
        .iter()
        .filter_map(|s| BackupCategory::from_wire(s))
        .collect();
    if picked.is_empty() {
        BACKUP_CATEGORIES.to_vec()
    } else {
        picked
    }
}

// ── 数据备份 / 恢复 ── 上游 `backup-handlers.ts` ──

/// 弹「保存文件」框，返回用户选定路径（取消 → None）。
///
/// 用**回调式** API + oneshot，而非 `blocking_save_file` —— 后者禁止在主线程调用（会死锁）；
/// 本 command 是 `async fn`，回调式是官方推荐路径。
async fn ask_save_path(app: &AppHandle, default_name: &str) -> Option<PathBuf> {
    let lang = crate::i18n::app_lang(app);
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_title(t(lang, key::NATIVE_BACKUP_EXPORT_TITLE))
        .set_file_name(default_name)
        .add_filter(t(lang, key::NATIVE_BACKUP_FILE_TYPE), &["polaris-backup"])
        .add_filter(t(lang, key::NATIVE_ALL_FILES), &["*"])
        .save_file(move |p| {
            let _ = tx.send(p);
        });
    rx.await.ok().flatten().and_then(|p| p.into_path().ok())
}

/// 弹「打开文件」框，返回用户选定路径（取消 → None）。
async fn ask_open_path(app: &AppHandle) -> Option<PathBuf> {
    let lang = crate::i18n::app_lang(app);
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_title(t(lang, key::NATIVE_BACKUP_IMPORT_TITLE))
        .add_filter(t(lang, key::NATIVE_BACKUP_FILE_TYPE), &["polaris-backup"])
        .add_filter(t(lang, key::NATIVE_JSON_FILE_TYPE), &["json"])
        .add_filter(t(lang, key::NATIVE_ALL_FILES), &["*"])
        .pick_file(move |p| {
            let _ = tx.send(p);
        });
    rx.await.ok().flatten().and_then(|p| p.into_path().ok())
}

/// 上游 `BACKUP_EXPORT`：选择性导出（按 categories）。
///
/// `categories` 缺省 / 空 → 全 7 类。1.1 新增 DNS 资源类别，仍兼容导入 1.0 / 裸配置。
/// **clashApiSecret / privacyPassword 恒不入备份**（由 `pick_categories` 的排除表保证，见 store::backup）。
#[tauri::command]
pub async fn backup_export(
    app: AppHandle,
    state: State<'_, AppRuntime>,
    categories: Option<Vec<String>>,
) -> Result<ApiResponse<Value>, ()> {
    let config = match state.config().load_full() {
        Ok(c) => c,
        Err(e) => {
            log::warn!("[backup] export failed to load config: {e}");
            return Ok(ApiResponse::ok(backup_failure("configLoadFailed")));
        }
    };
    let selected = parse_categories(categories);
    let picked = pick_categories(&config, &selected);

    let backup = json!({
        "version": BACKUP_FILE_VERSION,
        "appVersion": app.package_info().version.to_string(),
        "platform": node_platform(),
        "exportedAt": now_iso8601(),
        "config": picked,
    });

    let default_name = format!("polaris-backup-{}.polaris-backup", today_yyyy_mm_dd());
    let Some(path) = ask_save_path(&app, &default_name).await else {
        return Ok(ApiResponse::ok(backup_failure("cancelled")));
    };

    let body = match serde_json::to_string_pretty(&backup) {
        Ok(s) => s,
        Err(e) => {
            log::warn!("[backup] export serialization failed: {e}");
            return Ok(ApiResponse::ok(backup_failure("serializeFailed")));
        }
    };
    if let Err(e) = std::fs::write(&path, body) {
        log::warn!("[backup] export write failed: {e}");
        return Ok(ApiResponse::ok(backup_failure("writeFailed")));
    }
    Ok(ApiResponse::ok(json!({
        "success": true,
        "filePath": path.to_string_lossy(),
    })))
}

/// 上游 `BACKUP_IMPORT_PICK`：弹文件框 + 解析 → 返回含哪些类 + 各类数量（**不 apply**）。
#[tauri::command]
pub async fn backup_import_pick(app: AppHandle) -> Result<ApiResponse<Value>, ()> {
    let Some(path) = ask_open_path(&app).await else {
        return Ok(ApiResponse::ok(json!({ "canceled": true })));
    };
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return Ok(ApiResponse::ok(
            json!({ "canceled": false, "errorCode": "readFailed" }),
        ));
    };
    let parsed = match parse_backup_content(&raw) {
        Ok(p) => p,
        Err(code) => {
            log::warn!("[backup] import preview parse rejected: {code}");
            return Ok(ApiResponse::ok(
                json!({ "canceled": false, "errorCode": "invalidFormat" }),
            ));
        }
    };
    let available = detect_categories(&parsed.config);
    let interface_names: BTreeSet<String> =
        crate::commands::system::list_network_interfaces_blocking()
            .into_iter()
            .map(|interface| interface.name)
            .collect();
    let mut counts = serde_json::Map::new();
    let mut unavailable_interface_bindings = serde_json::Map::new();
    for cat in &available {
        counts.insert(
            cat.as_str().to_string(),
            json!(count_category(&parsed.config, *cat)),
        );
        let mut preview = parsed.config.clone();
        let missing = sanitize_unavailable_interface_bindings(
            &mut preview,
            &interface_names,
            std::slice::from_ref(cat),
        );
        if missing > 0 {
            unavailable_interface_bindings.insert(cat.as_str().to_string(), json!(missing));
        }
    }
    Ok(ApiResponse::ok(json!({
        "canceled": false,
        "filePath": path.to_string_lossy(),
        "available": available,
        "counts": counts,
        "unavailableInterfaceBindings": unavailable_interface_bindings,
    })))
}

/// 上游 `BACKUP_IMPORT_APPLY`：按所选类**整类替换 + 空跳过** + 跨平台 sanitize + 保存。
///
/// 失效 `selectedServerId` 已在 `merge_categories` 末尾归零（`validate_config` 对失效引用是 Err、非归零，
/// 不兜底会令整份导入失败）。保存走 `save_full`（内部再跑 sanitize + validate）。
///
/// 存盘成功后必须走 `broadcast_config_changed`：那是本仓配置变更的唯一汇流点（前端 store 对账 +
/// `switch_mode` 热切换/重启判定 + `set_level` 跟随 logLevel）。本命令的落盘腿
/// （[`crate::commands::config::backup_import_save_core`]）不含广播 → 少了这一步，导入的备份只落磁盘、
/// 运行核与前端一无所知（一份含 logLevel/节点变更的备份导入后静默不生效）。
#[tauri::command]
pub async fn backup_import_apply(
    app: AppHandle,
    state: State<'_, AppRuntime>,
    file_path: String,
    categories: Vec<String>,
) -> Result<ApiResponse<Value>, ()> {
    let selected: Vec<BackupCategory> = categories
        .iter()
        .filter_map(|s| BackupCategory::from_wire(s))
        .collect();
    if file_path.is_empty() || selected.is_empty() {
        return Ok(ApiResponse::ok(backup_failure("invalidArgs")));
    }
    let Ok(raw) = std::fs::read_to_string(&file_path) else {
        return Ok(ApiResponse::ok(backup_failure("readFailed")));
    };
    let parsed = match parse_backup_content(&raw) {
        Ok(p) => p,
        Err(code) => {
            log::warn!("[backup] import apply parse rejected: {code}");
            return Ok(ApiResponse::ok(backup_failure("invalidFormat")));
        }
    };

    let current = match state.config().load_full() {
        Ok(c) => c,
        Err(e) => {
            log::warn!("[backup] import failed to load config: {e}");
            return Ok(ApiResponse::ok(backup_failure("configLoadFailed")));
        }
    };
    let mut outcome = merge_categories(&current, &parsed.config, &selected);

    // 仅当导入了自定义规则才需 sanitize（其余类无进程规则）。
    let mut cross_disabled = 0usize;
    if selected.contains(&BackupCategory::CustomRules) {
        cross_disabled = sanitize_cross_platform_rules(
            &mut outcome.config,
            parsed.platform.as_deref(),
            node_platform(),
        );
        if cross_disabled > 0 {
            log::info!(
                "[backup] 跨平台导入（{:?}→{}）：禁用 {cross_disabled} 条进程规则（保留供重映射）",
                parsed.platform,
                node_platform()
            );
        }
    }

    // 网卡名属于设备本地资源。跨设备恢复时若目标机不存在同名接口，保留该名字会让代理核启动失败；
    // 静默改走其它网卡又可能造成出口泄漏。因此导入预览先明确告知，应用时只把本次真正导入的失效绑定
    // 回退为自动 / 继承，并把数量回传给 UI 做完成提醒。接口枚举失败（空集）时不改配置，避免误清。
    let effective_selected: Vec<BackupCategory> = selected
        .iter()
        .copied()
        .filter(|category| !outcome.skipped.contains(category))
        .collect();
    let interface_names: BTreeSet<String> =
        crate::commands::system::list_network_interfaces_blocking()
            .into_iter()
            .map(|interface| interface.name)
            .collect();
    let unavailable_interface_bindings = sanitize_unavailable_interface_bindings(
        &mut outcome.config,
        &interface_names,
        &effective_selected,
    );
    if unavailable_interface_bindings > 0 {
        log::warn!(
            "[backup] 导入配置引用了本机不存在的网卡：已将 {unavailable_interface_bindings} 处绑定回退为自动/继承"
        );
    }

    // 落盘前的三条策略 + 保存全部收口在 [`config::backup_import_save_core`]（见该函数文档）：
    // 回填隐私 hash（备份导出侧脱敏，不回填 = 导入即拆锁）、以本机磁盘回正后端权威字段（外机 MRU /
    // geo 元数据不得灌进本机）、全局 UA 变更时作废受影响订阅的条件 GET 验证器（不清 = 换 UA 后恒 304）。
    let mut restored = outcome.config.clone();
    let old_selected = match crate::commands::config::backup_import_save_core(
        state.config(),
        &current,
        &mut restored,
    ) {
        Ok(old_selected) => old_selected,
        Err(e) => {
            log::warn!("[backup] import save failed: {e}");
            return Ok(ApiResponse::ok(backup_failure("saveFailed")));
        }
    };
    // 恢复后二次 load_full 重走完整迁移链（migrate_all）再广播：备份可能来自旧版本（上游/旧 Polaris），含旧 shape
    // 字段（legacy DomainRule / subscriptionUpdateViaProxy / 未迁移 tunStack 等）。`save_full` 只 sanitize+validate、
    // **不跑迁移链**，直接广播 restored 会让旧 shape 未迁移即入核/下发前端。二次 load_full 触发 migrate_all，
    // 广播迁移后配置。load 异常（刚存的合法配置几乎不可能）→ 回落广播 restored（仍带回填后的私密字段，不裸奔）。
    // 广播**回填后**（restored / 其迁移形）而非 outcome.config：后者 server 私密字段已被导出侧脱敏抹平，入核 = 缺密钥热切换。
    let broadcast_cfg = state.config().load_full().unwrap_or(restored);
    crate::commands::config::broadcast_config_changed(&app, &broadcast_cfg);
    crate::commands::config::invalidate_unlock_on_exit_change(
        state.unlock(),
        &crate::runtime::unlock::BroadcastSink::new(&app),
        state.proxy().status().running,
        old_selected.as_deref(),
        broadcast_cfg
            .get("selectedServerId")
            .and_then(Value::as_str),
    );

    let info = build_backup_info(&outcome.config, cross_disabled);
    let skipped: Vec<&str> = outcome.skipped.iter().map(|c| c.as_str()).collect();
    let mut out = json!({ "success": true, "info": info });
    if unavailable_interface_bindings > 0 {
        out["unavailableInterfaceBindings"] = json!(unavailable_interface_bindings);
    }
    if !skipped.is_empty() {
        out["skipped"] = json!(skipped);
    }
    Ok(ApiResponse::ok(out))
}

/// 备份失败的用户面只带稳定码。原始 OS/路径错误只记日志，不能越过 IPC 变成跨语种 UI 文案。
fn backup_failure(code: &str) -> Value {
    json!({ "success": false, "errorCode": code })
}

/// 上游 `BACKUP_GET_INFO`：当前配置摘要。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn backup_get_info(state: State<'_, AppRuntime>) -> ApiResponse<Value> {
    match state.config().current() {
        Ok(c) => ApiResponse::ok(json!(build_backup_info(&c, 0))),
        Err(e) => ApiResponse::err(format!("{e}")),
    }
}

#[cfg(test)]
mod tests;
