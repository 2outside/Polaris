//! 规则资源引用枚举（**反向**：资源 → 引用它的规则）—— `rule_resources_list` 的 `referencedBy`
//! 与 `rule_resources_delete` 的 `referencingRules` 的单一真值。
//!
//! # 为什么在 Rust 而不是前端
//!
//! 前端 `ui/src/shared/rule-resource-refs.ts` 有同一份逻辑。审计 §B 判它「前端展示派生，合理」——
//! 那是在**消费方未定**时的判断。现在消费方定了：`referencedBy` / `referencingRules` 是
//! **command 返回的 DTO 字段**（`RuleResourceListItem` / `RuleResourceDeleteResult`），由后端算完下发。
//! 依 ~/docs/polaris/design/polaris-dialog-layer-and-governance.md §3.1 Q2：
//! 「**Rust 预计算派生字段随 DTO 下发（零漂移）> 前端谓词（有漂移敞口）**」→ 反向枚举归 Rust。
//!
//! 前端保留的是**正向**判定（`availableResourceTagSet` / `ruleHasMissingResource` /
//! `missingResourceRuleIds` / `missingResourceAppIds`）—— 那些是渲染期就地角标（③类即时门控谓词），
//! 输入已在 store、错了只是角标瑕疵，且不进 config。两者互补，不是重复。
//!
//! # 已登记缺口：`kind: "system"` 未实现
//!
//! `RuleResourceRef.kind` 的 TS 定义含 `'system'`，注释称「智能分流 geo 基线层对内置默认
//! (geosite-cn/geoip-cn/geolocation-!cn) 的隐式引用（**纳入 referencedBy 计数**）」。
//! **但 TS 侧 `enumerateResourceRefs` 从未 emit 过 system** —— 类型宣称的能力实现里没有。
//! 本移植保持 1:1（route + app 两类），**不擅自新增行为**：`smart_baseline_geo_tags()` 就在手边
//! （`region_routing.rs:94`），但要不要把基线算作引用、算了之后 geosite-cn 是否就删不掉，
//! 是产品判断，且当前无消费方（资源库弹窗未实现）。留待弹窗批与 UI 一起定。

#![forbid(unsafe_code)]

use serde::Serialize;

use crate::user_config::app_rules_preset::get_app_preset_dto;
use crate::user_config::builtin_geo_rulesets::BUILTIN_ID_PREFIX;
use crate::user_config::rule::{AppRule, CustomAppPreset, Rule, RuleType};
use crate::user_config::rules::rule_conditions;

/// 引用记录。上游 `RuleResourceRef`（`ui/src/shared/types/rules.ts:137`）。
///
/// `label`：route = 备注，无备注则首条件摘要；app = 内置 `labelKey`(i18n key) 或自定义 `name`
/// —— **渲染端据 `appBuiltin` 决定要不要过 i18n**，故这两者必须同时下发。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleResourceRef {
    /// `route` = 自定义路由规则；`app` = 应用分流卡片。（`system` 见模块文档，未实现。）
    pub kind: String,
    pub id: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_builtin: Option<bool>,
}

/// 扫描输入。上游 `RefScanInput`。
#[derive(Debug, Default, Clone, Copy)]
pub struct RefScanInput<'a> {
    pub custom_rules: &'a [Rule],
    pub app_rules: &'a [AppRule],
    pub custom_app_presets: &'a [CustomAppPreset],
}

/// 归一 resId 为 geo tag：`builtin:geosite-x` → `geosite-x`；其余原样（`geosite-amazon` / `res_xxx`）。
/// 上游 `geoTagOf`。
pub fn geo_tag_of(res_id: &str) -> &str {
    res_id.strip_prefix(BUILTIN_ID_PREFIX).unwrap_or(res_id)
}

/// 把 `RuleType` 转成 TS 侧同名字符串（`ruleSet` / `domainSuffix` …）。
///
/// **走 serde 而非手写 match**：`RuleType` 的 `rename_all = "camelCase"` 是键名真值，手写第二张
/// 映射表就是又一处必然漂移的副本。
fn rule_type_str(t: RuleType) -> String {
    serde_json::to_value(t)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// 拆 geo tag 为 (kind, name)：`geosite-youtube` → `(Geosite, "youtube")`。非 geo 形态 → None。
fn split_geo_tag(tag: &str) -> Option<(RuleType, String)> {
    // 注意 name 可含 '-'（`geolocation-!cn`）→ 只切首个分隔符，对齐 TS 的 `^(geosite|geoip)-(.+)$`。
    for (prefix, kind) in [("geosite-", RuleType::Geosite), ("geoip-", RuleType::Geoip)] {
        if let Some(rest) = tag.strip_prefix(prefix) {
            if rest.is_empty() {
                return None; // `(.+)` 要求至少 1 字符
            }
            return Some((kind, rest.trim().to_ascii_lowercase()));
        }
    }
    None
}

/// 枚举 resId 被哪些**已启用**规则引用。上游 `enumerateResourceRefs`。
///
/// resId 口径：`geosite-<tag>` / `geoip-<tag>` / `builtin:<tag>` / `res_<id>`。三类引用：
/// - customRules 的 `ruleSet` 条件 `res:<resId>`（精确串比）；
/// - customRules 的 geosite/geoip **类型条件**（值是裸 tag，如 `youtube`）；
/// - appRules 经 preset 的 geositeTags/geoipTags **间接引用**。
///
/// 后两类是历史缺口的补丁：原 RuleResourceManager 只扫第一类 → 删这些 geo 资源时不提示、
/// 补回后不触发 reload。
pub fn enumerate_resource_refs(res_id: &str, input: &RefScanInput<'_>) -> Vec<RuleResourceRef> {
    let mut refs: Vec<RuleResourceRef> = Vec::new();
    let res_ref = format!("res:{res_id}");
    let geo = split_geo_tag(geo_tag_of(res_id));

    // ① / ② 自定义路由规则
    for rule in input.custom_rules {
        if !rule.enabled {
            continue;
        }
        let conds = rule_conditions(rule);
        let matched = conds.iter().any(|c| {
            if c.type_field == RuleType::RuleSet && c.values.iter().any(|v| v == &res_ref) {
                return true;
            }
            match &geo {
                Some((kind, name)) if c.type_field == *kind => c
                    .values
                    .iter()
                    .any(|v| v.trim().to_ascii_lowercase() == *name),
                _ => false,
            }
        });
        if !matched {
            continue;
        }
        // label：备注优先；无备注取首条件摘要 `type: value`（值截 24 字符）。
        let label = rule
            .remarks
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| match conds.first() {
                Some(c0) => {
                    let v0 = c0.values.first().map(String::as_str).unwrap_or("");
                    // TS 用 `.slice(0,24)`（UTF-16 码元）；此处按 char 截。规则值实际是域名/IP/端口
                    // 等 ASCII，两者等价；真出现非 BMP 字符时长度可能差一两个字符，纯展示摘要，
                    // 不影响任何判定。
                    let v0: String = v0.chars().take(24).collect();
                    format!("{}: {}", rule_type_str(c0.type_field), v0)
                }
                None => rule_type_str(rule.type_field),
            });
        refs.push(RuleResourceRef {
            kind: "route".to_string(),
            id: rule.id.clone(),
            label,
            app_builtin: None,
        });
    }

    // ③ 应用分流：仅 geo tag 类资源可被 preset 引用
    if let Some((kind, name)) = geo {
        for ar in input.app_rules {
            if !ar.enabled {
                continue;
            }
            let preset = match get_app_preset_dto(&ar.app_id, input.custom_app_presets) {
                Some(p) => p,
                None => continue,
            };
            let tags = if kind == RuleType::Geosite {
                &preset.geosite_tags
            } else {
                &preset.geoip_tags
            };
            if tags.iter().any(|t| t.trim().to_ascii_lowercase() == name) {
                refs.push(RuleResourceRef {
                    kind: "app".to_string(),
                    id: ar.app_id.clone(),
                    label: preset.label_key.clone(),
                    // 内置 = 非 custom- 前缀 → 渲染端据此决定 label 是否过 i18n。
                    app_builtin: Some(!ar.app_id.starts_with("custom-")),
                });
            }
        }
    }

    refs
}

/// 是否被任意启用规则引用。上游 `isResourceReferenced`。
pub fn is_resource_referenced(res_id: &str, input: &RefScanInput<'_>) -> bool {
    !enumerate_resource_refs(res_id, input).is_empty()
}

#[cfg(test)]
mod tests;
