//! 内置应用分流预设 —— **Rust 是单一真值（SoT）**，前端经 `app_presets_list` command 拉取。
//!
//! 表本体见 `app_rules_preset_data.rs`（16 条，行是维护单元）。本模块提供两个投影 + 消费函数：
//! - [`AppPreset`]（`all_presets()`）：路由生成消费的子集，**不含 UI 列**（builder 零污染）。
//! - [`AppPresetDto`]（`all_presets_dto()`）：全列（含 labelKey/emoji/iconUrl），下发前端渲染。
//!
//! 历史：本模块曾是 `src/shared/app-rules-preset.ts` 的手抄投影（TS 为真源）。现已反转，TS 表已删。

#![forbid(unsafe_code)]

use crate::user_config::rule::{AppRule, CustomAppPreset, RuleAction};
use serde::Serialize;
use std::collections::HashSet;

/// 应用分流预设（路由生成消费的子集）。上游 `AppPreset` 后端投影。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPreset {
    pub id: String,
    pub geosite_tags: Vec<String>,
    pub geoip_tags: Vec<String>,
    pub process_names: Vec<String>,
    pub category: String,
}

/// 内置预设全列 DTO —— `app_presets_list` command 的载荷，对齐前端 `AppPreset` interface
/// （`ui/src/shared/app-rules-preset.ts`）逐字段。
///
/// **键名契约**：`rename_all = "camelCase"` 产出 `labelKey`/`iconUrl`/`geositeTags`/`geoipTags`/
/// `processNames` —— 与 TS interface 一致。改键名 = 破坏前端渲染，且 **tsc 抓不到**（invoke 返回值
/// 是 as-cast）→ 由 `tests/frontend_sot_guard.rs` 锁死。
///
/// `iconUrl` 用 `Option` + `skip_serializing_if`：对齐 TS `iconUrl?: string`（自定义预设可无图标）。
/// `geoipTags`/`processNames` 恒序列化为数组（TS 侧标 `?` 但消费点全是 `|| []` / `.some()`，
/// 空数组与缺省等价，恒发更简单）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppPresetDto {
    pub id: String,
    pub label_key: String,
    pub emoji: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_url: Option<String>,
    pub geosite_tags: Vec<String>,
    pub geoip_tags: Vec<String>,
    pub process_names: Vec<String>,
    pub category: String,
}

include!("app_rules_preset_data.rs");

/// 根据 appId 查找预设（先内置，后自定义）。上游 `getAppPreset`。
///
/// 内置预设查 `all_presets()`；自定义预设查 `custom_presets`，将 `CustomAppPreset` 转为兼容格式。
/// 找不到返回 `None`。
pub fn get_app_preset(app_id: &str, custom_presets: &[CustomAppPreset]) -> Option<AppPreset> {
    let builtin = all_presets();
    if let Some(p) = builtin.iter().find(|p| p.id == app_id) {
        return Some(p.clone());
    }
    custom_presets
        .iter()
        .find(|p| p.id == app_id)
        .map(|c| AppPreset {
            id: c.id.clone(),
            geosite_tags: c.geosite_tags.clone(),
            geoip_tags: c.geoip_tags.clone(),
            process_names: c.process_names.clone().unwrap_or_default(),
            // 后端不消费 category；分组呈现由渲染层直接读 custom.category。
            category: "tools".to_string(),
        })
}

/// 按 appId 查全列预设（先内置，后自定义）——[`get_app_preset`] 的 UI 列版本。
///
/// 与 [`get_app_preset`] 的唯一差别是**多带 UI 列**（labelKey/emoji/iconUrl）。消费方：
/// `rule_resource_refs::enumerate_resource_refs` 要 `labelKey` 当引用徽标文案。
///
/// 自定义预设的 `labelKey` 取 `name`（自定义应用直接存名称，非 i18n key —— 渲染端据
/// `RuleResourceRef.appBuiltin` 决定要不要过 i18n）；`category` 取**真实值**而非
/// [`get_app_preset`] 那个 `"tools"` 占位 —— 后者的占位注释「后端不消费 category」在后端成立，
/// 但本 DTO 是给渲染端的，分组呈现要真值。
pub fn get_app_preset_dto(
    app_id: &str,
    custom_presets: &[CustomAppPreset],
) -> Option<AppPresetDto> {
    if let Some(p) = all_presets_dto().into_iter().find(|p| p.id == app_id) {
        return Some(p);
    }
    custom_presets
        .iter()
        .find(|p| p.id == app_id)
        .map(|c| AppPresetDto {
            id: c.id.clone(),
            label_key: c.name.clone(),
            emoji: c.emoji.clone(),
            icon_url: c.icon_url.clone(),
            geosite_tags: c.geosite_tags.clone(),
            geoip_tags: c.geoip_tags.clone(),
            process_names: c.process_names.clone().unwrap_or_default(),
            category: c.category.clone().unwrap_or_else(|| "tools".to_string()),
        })
}

/// 默认应用分流规则：为每个内置预设生成「代理·跟全局」规则。上游 `defaultAppRules`。
pub fn default_app_rules() -> Vec<AppRule> {
    all_presets()
        .iter()
        .map(|p| AppRule {
            app_id: p.id.clone(),
            action: RuleAction::Proxy,
            enabled: true,
            target_server_id: None,
        })
        .collect()
}

/// 一次性默认注入合并（幂等）。上游 `seedDefaultAppRules`。
///
/// 为未配置的预设补默认规则；剔除已下线预设的残留规则；保留用户已配置的预设规则与自定义 app（custom-*）。
pub fn seed_default_app_rules(existing: &[AppRule]) -> Vec<AppRule> {
    let presets = all_presets();
    let valid_ids: HashSet<String> = presets.iter().map(|p| p.id.clone()).collect();
    let kept: Vec<AppRule> = existing
        .iter()
        .filter(|r| valid_ids.contains(&r.app_id) || r.app_id.starts_with("custom-"))
        .cloned()
        .collect();
    let have: HashSet<String> = kept.iter().map(|r| r.app_id.clone()).collect();
    let mut result = kept;
    for r in default_app_rules() {
        if !have.contains(&r.app_id) {
            result.push(r);
        }
    }
    result
}

#[cfg(test)]
mod tests;
