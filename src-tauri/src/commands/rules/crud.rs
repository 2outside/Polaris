use serde_json::{json, Value};
use tauri::{AppHandle, State};

use crate::commands::config::broadcast_config_changed;
use crate::commands::rules::new_uuid;
use crate::response::ok_void;
use crate::response::ApiResponse;
use crate::runtime::config::Decision;
use crate::runtime::AppRuntime;
use polaris_config_engine::user_config::rule::Rule;
use polaris_config_engine::user_config::AppPresetDto;
use polaris_config_engine::user_config::{all_presets_dto, validate_rule};

/// 规则兜底校验失败错误码（上游 `assertValidRule`）。前端据此把「规则非法」与「保存失败」分流：
/// 前者提示用户改表单、不重试；后者是 IO/写盘失败、可重试。D4 提交门权威即 add/update 的本校验。
const ERR_RULE_INVALID: &str = "RULE_INVALID";

/// 服务端权威规则校验（上游 `validateRule`）：结构须能反序列化为 `Rule`，且每个条件有 ≥1 个
/// 非空值、全部值按类型合法。成功 `Ok(())`；失败返错误串（分号连接各条件错误），调用方包 `RULE_INVALID` 信封。
///
/// 单一真值在 config-engine `user_config::rule_validate::validate_rule`；前端 rule-dialog 只保留
/// `isValidIpCidr` 做输入内联提示，提交门以此为准。
fn validate_rule_payload(rule: &Value) -> Result<(), String> {
    let parsed: Rule =
        serde_json::from_value(rule.clone()).map_err(|e| format!("规则结构非法: {e}"))?;
    let result = validate_rule(&parsed);
    if result.valid {
        Ok(())
    } else {
        Err(result.errors.join("; "))
    }
}

fn plane_keys(plane: &str) -> Result<(&'static str, &'static str), &'static str> {
    match plane {
        "route" => Ok(("trafficRules", "routeRuleOrder")),
        "dns" => Ok(("dnsRules", "dnsRuleOrder")),
        _ => Err("plane must be route or dns"),
    }
}

fn plane_rules(cfg: &Value, collection_key: &str) -> Vec<Value> {
    cfg.get(collection_key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// 独立集合写入；流量规则同步旧版投影，DNS 规则绝不混入旧版 customRules。
fn write_plane_rules(cfg: &mut Value, collection_key: &str, rules: Vec<Value>) {
    if let Some(obj) = cfg.as_object_mut() {
        obj.insert(collection_key.to_string(), Value::Array(rules.clone()));
        if collection_key == "trafficRules" {
            obj.insert("policyRules".to_string(), Value::Array(rules.clone()));
            obj.insert("customRules".to_string(), Value::Array(rules));
        }
        obj.insert("configSchemaVersion".to_string(), Value::from(4));
    }
}

fn validate_rule_plane(rule: &Value, plane: &str) -> Result<(), &'static str> {
    let effects = rule.get("effects").and_then(Value::as_object);
    let has_route = effects
        .and_then(|value| value.get("route"))
        .is_some_and(Value::is_object);
    let has_dns = effects
        .and_then(|value| value.get("dns"))
        .is_some_and(Value::is_object);
    let route_has_dns_fields = effects
        .and_then(|value| value.get("route"))
        .and_then(Value::as_object)
        .is_some_and(|route| {
            route.contains_key("destinationResolution") || route.contains_key("resolutionOnly")
        });
    let has_legacy_dns_field = rule.get("bypassFakeIP").is_some();

    if plane == "route" && (has_dns || route_has_dns_fields || has_legacy_dns_field) {
        return Err("traffic rule must not contain DNS fields");
    }
    match (plane, has_route, has_dns) {
        ("route", true, false) | ("route", false, false) | ("dns", false, true) => Ok(()),
        ("route", _, _) => Err("traffic rule must contain only effects.route"),
        ("dns", _, _) => Err("DNS rule must contain only effects.dns"),
        _ => Err("plane must be route or dns"),
    }
}

fn sync_plane_order(cfg: &mut Value, order_key: &str, rules: &[Value]) {
    let Some(obj) = cfg.as_object_mut() else {
        return;
    };
    let members: Vec<String> = rules
        .iter()
        .filter_map(|rule| rule.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    let member_set: std::collections::HashSet<&str> = members.iter().map(String::as_str).collect();
    let mut order: Vec<String> = obj
        .get(order_key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|id| member_set.contains(*id))
        .map(str::to_string)
        .collect();
    for id in members {
        if !order.contains(&id) {
            order.push(id);
        }
    }
    obj.insert(order_key.to_string(), json!(order));
}

/// 上游 `RULES_ADD`：新增规则（服务端兜底校验 + 生成 id）。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn rules_add(
    app: AppHandle,
    state: State<'_, AppRuntime>,
    rule: Value,
    plane: String,
) -> ApiResponse<Value> {
    let (collection_key, order_key) = match plane_keys(&plane) {
        Ok(keys) => keys,
        Err(message) => return ApiResponse::err(message),
    };
    let mut new_rule = rule;
    let id = new_rule
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("rule_{}", new_uuid()));
    if let Some(obj) = new_rule.as_object_mut() {
        obj.insert("id".to_string(), json!(id));
    }
    // 提交门权威校验（Polaris assertValidRule）：非法规则不入盘。
    if let Err(msg) = validate_rule_payload(&new_rule) {
        return ApiResponse::err_with_code(msg, ERR_RULE_INVALID);
    }
    if let Err(msg) = validate_rule_plane(&new_rule, &plane) {
        return ApiResponse::err_with_code(msg, ERR_RULE_INVALID);
    }
    let created = new_rule.clone();
    match state.config().update(|cfg| {
        let mut rules = plane_rules(cfg, collection_key);
        rules.push(new_rule);
        sync_plane_order(cfg, order_key, &rules);
        write_plane_rules(cfg, collection_key, rules);
        Decision::Write(())
    }) {
        Ok(((), Some(cfg))) => {
            broadcast_config_changed(&app, &cfg);
            ApiResponse::ok(created)
        }
        Ok(_) => unreachable!("rules_add decision and persistence must agree"),
        Err(e) => ApiResponse::err(format!("{e}")),
    }
}

/// 上游 `RULES_UPDATE`：更新规则（按 id）。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn rules_update(
    app: AppHandle,
    state: State<'_, AppRuntime>,
    rule: Value,
    plane: String,
) -> ApiResponse<()> {
    let (collection_key, order_key) = match plane_keys(&plane) {
        Ok(keys) => keys,
        Err(message) => return ApiResponse::err(message),
    };
    let id = rule.get("id").and_then(Value::as_str).map(str::to_string);
    let id = match id {
        Some(i) => i,
        None => return ApiResponse::err("rule.id required"),
    };
    // 提交门权威校验（Polaris assertValidRule）：非法规则不入盘。
    if let Err(msg) = validate_rule_payload(&rule) {
        return ApiResponse::err_with_code(msg, ERR_RULE_INVALID);
    }
    if let Err(msg) = validate_rule_plane(&rule, &plane) {
        return ApiResponse::err_with_code(msg, ERR_RULE_INVALID);
    }
    match state.config().update(|cfg| {
        let mut rules = plane_rules(cfg, collection_key);
        let Some(idx) = rules
            .iter()
            .position(|candidate| candidate.get("id").and_then(Value::as_str) == Some(&id))
        else {
            return Decision::Skip(Err(format!("Rule not found: {id}")));
        };
        rules[idx] = rule;
        sync_plane_order(cfg, order_key, &rules);
        write_plane_rules(cfg, collection_key, rules);
        Decision::Write(Ok(()))
    }) {
        Ok((Ok(()), Some(cfg))) => {
            broadcast_config_changed(&app, &cfg);
            ok_void()
        }
        Ok((Err(error), None)) => ApiResponse::err(error),
        Ok(_) => unreachable!("rules_update decision and persistence must agree"),
        Err(e) => ApiResponse::err(format!("{e}")),
    }
}

/// 上游 `RULES_DELETE`：删除规则（按 id）。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn rules_delete(
    app: AppHandle,
    state: State<'_, AppRuntime>,
    rule_id: String,
    plane: String,
) -> ApiResponse<()> {
    let (collection_key, order_key) = match plane_keys(&plane) {
        Ok(keys) => keys,
        Err(message) => return ApiResponse::err(message),
    };
    match state.config().update(|cfg| {
        let mut rules = plane_rules(cfg, collection_key);
        let Some(idx) = rules
            .iter()
            .position(|candidate| candidate.get("id").and_then(Value::as_str) == Some(&rule_id))
        else {
            return Decision::Skip(Err(format!("Rule not found: {rule_id}")));
        };
        rules.remove(idx);
        sync_plane_order(cfg, order_key, &rules);
        write_plane_rules(cfg, collection_key, rules);
        Decision::Write(Ok(()))
    }) {
        Ok((Ok(()), Some(cfg))) => {
            broadcast_config_changed(&app, &cfg);
            ok_void()
        }
        Ok((Err(error), None)) => ApiResponse::err(error),
        Ok(_) => unreachable!("rules_delete decision and persistence must agree"),
        Err(e) => ApiResponse::err(format!("{e}")),
    }
}

/// 重排纯决策：校验 `ordered_ids` 是现有 id 的严格排列，并算出新序列。
///
/// 三态返回（**净零序单独成一态**，契约 §Rules「规则重排」明写「净零序跳过 save」）：
/// - `Err(msg)`   → 入参非法（长度不符 / 有重复 / 含未知 id），调用方原样报错；
/// - `Ok(None)`   → **净零序**：请求的顺序与当前顺序逐位相同，无需落盘；
/// - `Ok(Some(v))`→ 真变化，`v` 是重排后的规则数组。
///
/// # 为什么净零序必须短路，而不是「反正 save 一次也没坏处」
///
/// `save_full` 之后跟着 `broadcast_config_changed` → 渲染端刷 store，且后端在 `config:changed`
/// 上挂着**整核评估**（待应用差集 / 是否需重启的判定）。规则顺序决定命中优先级，是参与配置生成的
/// 输入，所以这条评估链是真跑的。而 UI 侧「拖起来又放回原位」「上移列表首行 / 下移末行」这类
/// 空操作会照发一次 `rules:reorder` —— 净零序不短路的话，每个空手势都要付一轮全量评估 +
/// 一次全量 config 广播（前端整棵列表重渲染）。
///
/// 判据是**逐位序列相等**（不是集合相等）：集合恒相等（上面刚校验过是排列），只有位置才携带信息。
fn plan_reorder(rules: &[Value], ordered_ids: &[String]) -> Result<Option<Vec<Value>>, String> {
    // orderedIds 必须是现有 id 的严格排列（长度 + 无重复）。
    if ordered_ids.len() != rules.len() || {
        let mut s = ordered_ids.to_vec();
        s.sort_unstable();
        s.dedup();
        s.len() != ordered_ids.len()
    } {
        return Err("orderedIds must be a permutation of existing rule ids".to_string());
    }
    let by_id: std::collections::HashMap<&str, &Value> = rules
        .iter()
        .filter_map(|r| r.get("id").and_then(Value::as_str).map(|id| (id, r)))
        .collect();
    if !ordered_ids.iter().all(|id| by_id.contains_key(id.as_str())) {
        return Err("orderedIds contains unknown rule id".to_string());
    }
    // 净零序：逐位比对现序与请求序（现序里缺 id 的畸形条目 → 视作不等，走正常重排路径修复）。
    let unchanged = rules
        .iter()
        .zip(ordered_ids.iter())
        .all(|(cur, want)| cur.get("id").and_then(Value::as_str) == Some(want.as_str()));
    if unchanged {
        return Ok(None);
    }
    Ok(Some(
        ordered_ids
            .iter()
            .map(|id| (*by_id.get(id.as_str()).unwrap_or(&&Value::Null)).clone())
            .collect(),
    ))
}

/// 上游 `RULES_REORDER`：重排规则（orderedIds 必须是现有 id 的严格排列）。
///
/// **净零序不落盘不广播**（见 [`plan_reorder`]），仍返 `ok` —— 对调用方而言「顺序已是你要的样子」
/// 就是成功，报错会让前端把空手势当失败回滚。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn rules_reorder(
    app: AppHandle,
    state: State<'_, AppRuntime>,
    ordered_ids: Vec<String>,
    plane: String,
) -> ApiResponse<()> {
    let (collection_key, order_key) = match plane_keys(&plane) {
        Ok(keys) => keys,
        Err(message) => return ApiResponse::err(message),
    };
    match state.config().update(|cfg| {
        let rules = plane_rules(cfg, collection_key);
        let by_id: std::collections::HashMap<&str, &Value> = rules
            .iter()
            .filter_map(|rule| rule.get("id").and_then(Value::as_str).map(|id| (id, rule)))
            .collect();
        let configured_order: Vec<&str> = cfg
            .get(order_key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter(|id| by_id.contains_key(*id))
            .collect();
        let configured_set: std::collections::HashSet<&str> =
            configured_order.iter().copied().collect();
        let mut current: Vec<Value> = configured_order
            .into_iter()
            .filter_map(|id| by_id.get(id).map(|rule| (*rule).clone()))
            .collect();
        current.extend(
            rules
                .iter()
                .filter(|rule| {
                    rule.get("id")
                        .and_then(Value::as_str)
                        .is_some_and(|id| !configured_set.contains(id))
                })
                .cloned(),
        );
        let reordered = match plan_reorder(&current, &ordered_ids) {
            Err(message) => return Decision::Skip(Err(message)),
            Ok(None) => return Decision::Skip(Ok(())),
            Ok(Some(reordered)) => reordered,
        };
        if let Some(obj) = cfg.as_object_mut() {
            obj.insert(
                order_key.to_string(),
                json!(reordered
                    .iter()
                    .filter_map(|rule| rule.get("id").and_then(Value::as_str))
                    .collect::<Vec<_>>()),
            );
        }
        Decision::Write(Ok(()))
    }) {
        Ok((Ok(()), None)) => ok_void(),
        Ok((Ok(()), Some(cfg))) => {
            broadcast_config_changed(&app, &cfg);
            ok_void()
        }
        Ok((Err(error), None)) => ApiResponse::err(error),
        Ok(_) => unreachable!("rules_reorder decision and persistence must agree"),
        Err(e) => ApiResponse::err(format!("{e}")),
    }
}

/// 上游 `APP_PRESETS_LIST`：内置应用分流预设表（16 条，含 UI 列）。
///
/// **Rust 是本表的单一真值**（`config-engine/user_config/app_rules_preset_data.rs`）。前端曾持有
/// 一份同构的 `APP_PRESETS`（TS 才是真源、Rust 是手抄投影），现已删除 → 前端启动时经本 command
/// 一次拉取入 store（常量表 KB 级，一次往返摊销为零）。
///
/// 无参、无 state：静态表，不读 config。自定义预设（`config.customAppPresets`）**不在此下发** ——
/// 它们是用户配置、随 `config:changed` 实时变，前端 store 里本就有；合并（内置 ∪ 自定义）是渲染层
/// 的列表组合（`mergeAppPresets`），若在此合并则本表一缓存就会与新增的自定义应用脱节。
#[tauri::command]
pub fn app_presets_list() -> ApiResponse<Vec<AppPresetDto>> {
    ApiResponse::ok(all_presets_dto())
}

#[cfg(test)]
mod tests;
