//! 配置类 command（上游 `config-handlers.ts` + `privacy-handlers.ts`）。
//!
//! 映射 channel：
//! - `config:get` → [`config_get`]
//! - `config:save` → [`config_save`]（落盘 + 广播 event:configChanged）
//! - `config:patch` / `config:mutateEntities` → 原子顶层补丁 / 原子集合实体事务
//! - `config:updateMode` → [`config_update_mode`]
//! - `config:setValue` → [`config_set_value`]
//! - `config:getPrivacyMode` / `config:setPrivacyMode` → [`config_get_privacy_mode`] / [`config_set_privacy_mode`]
//! - `privacy:setPassword` / `privacy:unlock` / `privacy:hasPassword` → [`privacy_set_password`] /
//!   [`privacy_unlock`] / [`privacy_has_password`]（scrypt 独立文件 privacy-lock.json + 存量 SHA-256 平滑迁移）
//!
//! F29：config_get 绝不下发隐私密码（privacyPassword 字段剥除）——对齐 Polaris。

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use polaris_store::fs::StdFs;
use serde::Deserialize;
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager, State};

use crate::commands::subscription::invalidate_validators_on_global_ua_change;
use crate::events::channel::{
    EVENT_CONFIG_CHANGED, EVENT_ENTER_PRIVACY_MODE, EVENT_EXIT_PRIVACY_MODE,
};
use crate::response::{ok_void, ApiResponse};
use crate::runtime::config::{ConfigManager, Decision};
use crate::runtime::proxy::StagedClassification;
use crate::runtime::unlock::{
    selected_exit_changed, BroadcastSink, UnlockEventSink, UnlockRuntime,
};
use crate::runtime::AppRuntime;
use polaris_config_engine::builder::orchestration::stable_stringify;
use serde::Serialize;

/// 上游 `CONFIG_GET`：加载完整 UserConfig（剥除 privacyPassword）。
///
/// F1：`bypassLANList` 缺省时在此边界补成生效默认（27 条 `DEFAULT_BYPASS_LAN`），使 UI
/// 的旁路 / route_exclude 编辑器永远编辑真实清单 —— 否则首个按键会把前端 3 条兜底当用户清单
/// 持久化，静默丢弃 24 条真实默认。语义镜像 `effective_bypass_lan`，对 builder 透明。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn config_get(state: State<'_, AppRuntime>) -> ApiResponse<Value> {
    // 启动期一次性配置维护（对齐 上游 `loadConfig` 内联步骤，Polaris 运行时 `load_full` 未接线 →
    // 收口在前端首个配置入口）：清孤儿 tmp + 回填 clashApiSecret + F29 旧明文密码无损迁移为哈希。best-effort。
    run_startup_maintenance_once(state.config());
    match state.config().load_full() {
        Ok(mut cfg) => {
            apply_frontend_view(&mut cfg);
            ApiResponse::ok(cfg)
        }
        Err(e) => ApiResponse::err(format!("{e}")),
    }
}

/// 磁盘配置 → **渲染端看到的那一份**的投影。`config_get` 的下发形，也是 [`config_version`] 的定义域。
///
/// # 为什么必须抽出来（而不是让 `config_get` 内联这两步）
///
/// 乐观并发的版本号两侧各算（spec §3.7）：前端对 `config:get` 拿到的 config 算 FNV 短 hash，
/// 后端对磁盘现值算。两边算的若不是**同一份文档**，版本恒不等 ⇒ 每一次带 `base_version` 的保存
/// 都返 conflict，功能整体失效。而 `config_get` 恰好不是原样下发：
///
///  - `strip_privacy_secrets`：设过隐私密码的机器上，磁盘有 `privacyPasswordHash`、前端没有；
///  - `ensure_bypass_lan_list`：磁盘缺 `bypassLANList` 时前端拿到的是补齐后的 27 条默认。
///
/// 两条都足以让「hash 磁盘」与「hash 前端那份」系统性分叉。故版本的定义域**只能**是本投影。
fn apply_frontend_view(cfg: &mut Value) {
    // F29：绝不下发隐私密码（历史残留明文 `privacyPassword` + salted hash `privacyPasswordHash`）。
    strip_privacy_secrets(cfg);
    // F1：补齐 bypassLANList，防编辑器首个按键坍塌默认。
    polaris_config_engine::user_config::system_proxy_bypass::ensure_bypass_lan_list(cfg);
}

/// 配置的**内容版本**（spec §2.3.3）：渲染端投影经 `stable_stringify` 后取 FNV-1a 32 位短 hash。
///
/// 不用 mtime（同秒两次写可能相等），不用自增计数（进程重启即失忆）。
///
/// # 与前端 `configBaseVersion` 的逐字节等价（`ui/src/lib/staged-config.ts`）
///
/// 两侧各算、不走 IPC 往返，故实现必须逐位对齐，三处易错点：
///
///  1. **哈希单元是 UTF-16 code unit**，不是 UTF-8 字节 —— JS 侧是 `text.charCodeAt(i)`。
///     故此处走 `encode_utf16()`；写成 `bytes()` 会在任何非 ASCII 字符串（节点名、备注）上分叉。
///  2. **乘法回绕**：JS 侧 `Math.imul` 是 32 位有符号回绕乘 ⇒ 此处 `wrapping_mul`。
///  3. **序列化必须同源**：`stable_stringify` 键序无关、数组保序，与前端 `stableStringify` 同规。
///
/// 由 `ui/src/contracts/config-version.fixture.json` 的双侧固定 fixture 锁住（值一致性，非表一致性）。
///
/// # 已知边界（不在本轮射程）
///
/// serde_json 把「JSON 字面量带小数点的整数」（`5000.0`）序列化回 `5000.0`，而 JS `JSON.stringify`
/// 输出 `5000` ⇒ 该形态下两侧分叉。config 里唯一的浮点字段是 `dnsConfig.dnsTimeoutMs`，其写入路径
/// （前端提交 / `sanitize_dns_config` 取整成 i64）都产出整数字面量，故只有**手改 config.json 写成
/// `5000.0`** 才够得着。后果是保存恒返 conflict（不丢数据、不误写），不是静默错值。
fn config_version(cfg: &Value) -> String {
    let mut view = cfg.clone();
    apply_frontend_view(&mut view);
    config_content_hash(&view)
}

/// 版本函数的**纯哈希那一半**（与前端 `configBaseVersion` 逐位对齐的就是这个函数）。
///
/// 与 [`config_version`] 拆开是为了让跨语言 fixture 锁只锁哈希、不受渲染端投影的干扰：
/// 投影是「哪一份文档」的问题，哈希是「怎么算」的问题，两者各有各的门，混在一起会让
/// fixture 被迫写成「已投影形」，而那个前提读者无从校验。
fn config_content_hash(cfg: &Value) -> String {
    let text = stable_stringify(cfg);
    let mut hash: u32 = 0x811c_9dc5;
    for unit in text.encode_utf16() {
        hash ^= u32::from(unit);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    format!("{hash:08x}")
}

/// `config:save` 的结果（spec §2.3.3）。
///
/// **conflict 不是错误**：它不走 `ApiResponse::err`，因为「磁盘在你编辑期间被别人改了」是一个
/// 正常结局 —— 前端据此走合并腿（Q8-b），而不是弹一个报错。走 err 会让它和「落盘 IO 失败」
/// 挤在同一条通道里，前端只能靠 message 文本区分，那是最脆的一种分派。
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum SaveOutcome {
    /// 已落盘。`config` 是实际写盘规范形的渲染端投影；前端必须拿它而不是提交前 `merged` 刷新
    /// baseline，否则后端归一/派生字段会让下一批编辑基于一份磁盘上从未存在过的对象。
    Saved { version: String, config: Value },
    /// 磁盘现值 ≠ `base_version` ⇒ **一个字节都没写**。`diskVersion` 供前端定位它该基于哪一版重放。
    #[serde(rename_all = "camelCase")]
    Conflict { disk_version: String },
}

const CONFIG_BASE_VERSION_REQUIRED: &str = "CONFIG_BASE_VERSION_REQUIRED";

/// 上游 `CONFIG_SAVE`：保存 UserConfig + 广播 event:configChanged。
///
/// `deferRestart=true` = 暂存层「保存」腿的**不改变运行态**标志（spec §2.5 Q4）：NoOp 仍保持
/// NoOp；热切换、强制重启和普通重启全部只落盘，运行态统一由「应用」提交。
///
/// `baseVersion` 是整份保存的必填并发基准。即时控件改走 [`config_patch`]；因此不存在一个合理的
/// “无版本整份覆盖”调用者。缺失时 fail-closed，避免未来入口把旧快照重新接回。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn config_save(
    app: AppHandle,
    state: State<'_, AppRuntime>,
    config: Value,
    defer_restart: Option<bool>,
    base_version: Option<String>,
) -> ApiResponse<SaveOutcome> {
    if base_version.is_none() {
        log::warn!("config:save 缺少 baseVersion，拒绝无版本整份覆盖");
        return ApiResponse::err_with_code(
            crate::i18n::t(
                crate::i18n::app_lang(&app),
                crate::i18n::key::NATIVE_UNKNOWN_ERROR,
            ),
            CONFIG_BASE_VERSION_REQUIRED,
        );
    }
    // 本地转 mut 而非参数上写 `mut config`：check-ipc-args.mjs 的 Rust 形参解析不 strip `mut`，会把
    // 参数名误读成 `mut config` 从而要求前端多传该键（运行期 Tauri 其实 strip 了、无害，但 CI 门会红）。
    let mut config = config;
    // `deferRestart=true` 是暂存保存；即使调用方未传该标志，只要旧核仍在也不能立即清资源/state。
    // 后者覆盖将来新增的直写入口，避免把安全性押在“前端一定经过暂存层”这一条接线上。
    let defer_cleanup = defer_restart.unwrap_or(false) || state.proxy().status().running;
    match config_save_core(
        state.config(),
        &mut config,
        base_version.as_deref(),
        defer_cleanup,
    ) {
        // 冲突腿**不广播、不入核**：磁盘没变，广播出去只会让所有窗口把一份从未落盘的配置当现值。
        Ok((outcome @ SaveOutcome::Conflict { .. }, _)) => ApiResponse::ok(outcome),
        Ok((outcome, old_selected)) => {
            // 不在此处清 staged marker：后端只看到本次提交，不知道 IPC 在途期间前端是否又产生了
            // 下一批草稿。盲清会打开托盘/自动连接按旧配置起核的窗口。前端在回包后按剩余条目
            // 写 false/true；回包丢失时保守保留 true，下次 hydrate 剪掉磁盘已满足的意图后再清。
            broadcast_config_changed_with(&app, &config, defer_restart.unwrap_or(false));
            invalidate_unlock_on_exit_change(
                state.unlock(),
                &BroadcastSink::new(&app),
                state.proxy().status().running,
                old_selected.as_deref(),
                config.get("selectedServerId").and_then(Value::as_str),
            );
            ApiResponse::ok(outcome)
        }
        Err(e) => ApiResponse::err(format!("{e}")),
    }
}

/// `CONFIG_CLASSIFY_STAGED`（spec §2.3.4）：候选配置**若现在落盘**会走哪条腿。
///
/// **只读、零副作用**：不落盘、不碰核、不 emit。用于暂存层在保存**之前**逐条标注
/// 「已生效 / 保存后待应用」（FR-9），从而解释「5 项待保存 → 保存 → 2 项待应用」这个转移。
///
/// 判定本体在 [`ProxyRuntime::classify_staged`](crate::runtime::proxy::ProxyRuntime::classify_staged)，与真正的 `switch_mode` 共用同一个
/// [`classify_switch`](crate::runtime::proxy::ProxyRuntime) —— 预告与实际在构造上不可能分歧。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn config_classify_staged(
    state: State<'_, AppRuntime>,
    config: Value,
) -> ApiResponse<StagedClassification> {
    ApiResponse::ok(state.proxy().classify_staged(&config))
}

/// 主窗暂存区的跨入口镜像。正文不跨 IPC；后端只记 pending + 节点 id 遮罩，供托盘、自动连接和
/// 自动故障切换在无渲染端参与时 fail-closed。`node_ids=Some([])` 明确表达“草稿存在但未改节点”；
/// `None` 只用于旧调用方，按节点范围未知处理。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn config_set_staged_pending(
    state: State<'_, AppRuntime>,
    pending: bool,
    node_ids: Option<Vec<String>>,
) -> ApiResponse<()> {
    state
        .config()
        .set_staged_pending_snapshot(pending, node_ids);
    ok_void()
}

/// 即时配置编辑的原子补丁：只替换本次明确提交的顶层字段，未触及字段始终保留锁内最新磁盘值。
///
/// 这与 [`config_save`] 的整份快照语义刻意分开：主窗口、托盘、订阅 scheduler 是并发写入者，拿一份
/// 打开页面时的旧快照整份覆盖，即使写锁正确也会“串行地丢更新”。即时控件只需要提交变动字段；需要
/// 整份事务的暂存保存则继续使用 `config_save + baseVersion` 做冲突裁决。
fn config_patch_core(
    config: &ConfigManager,
    patch: serde_json::Map<String, Value>,
) -> Result<(Option<String>, Value, bool), polaris_store::StoreError> {
    let ((old_selected, changed, transaction_view), saved) =
        config.update_deferred_cleanup(|current| {
            let old_selected = current
                .get("selectedServerId")
                .and_then(Value::as_str)
                .map(str::to_string);
            if patch.is_empty() {
                return Decision::Skip((old_selected, false, current.clone()));
            }

            let mut next = current.clone();
            let root = next
                .as_object_mut()
                .expect("validated UserConfig root must be an object");
            for (key, value) in patch {
                root.insert(key, value);
            }

            // 补丁入口同样经过全量保存的字段所有权与派生投影规则；否则换一个写入口就能绕过隐私保护、
            // 后端权威字段和 UA 验证器失效语义。
            preserve_server_owned_secrets_from(current, &mut next);
            enforce_backend_authoritative_fields_from(current, &mut next);
            crate::commands::server::prune_recent_server_ids_to_existing(&mut next);
            sync_traffic_rules_projection(&mut next);
            log_invalidated_validators(invalidate_validators_on_global_ua_change(
                current, &mut next,
            ));
            if next == *current {
                Decision::Skip((old_selected, false, current.clone()))
            } else {
                *current = next;
                Decision::Write((old_selected, true, current.clone()))
            }
        })?;

    match (changed, saved) {
        (true, Some(saved)) => Ok((old_selected, saved, true)),
        // Skip 的返回快照与 old_selected 来自同一锁内事务；不要在解锁后再读一次，否则另一 writer
        // 可插入其间，让后续“出口是否变化”拿两份不属于同一时刻的值做比较。
        (false, None) => Ok((old_selected, transaction_view, false)),
        _ => unreachable!("config patch decision and persistence must agree"),
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn config_patch(
    app: AppHandle,
    state: State<'_, AppRuntime>,
    patch: Value,
) -> ApiResponse<Value> {
    let Some(patch) = patch.as_object().cloned() else {
        return ApiResponse::err(crate::i18n::t(
            crate::i18n::app_lang(&app),
            crate::i18n::key::NATIVE_UNKNOWN_ERROR,
        ));
    };
    match config_patch_core(state.config(), patch) {
        Ok((old_selected, cfg, changed)) => {
            if changed {
                broadcast_config_changed(&app, &cfg);
            }
            invalidate_unlock_on_exit_change(
                state.unlock(),
                &BroadcastSink::new(&app),
                state.proxy().status().running,
                old_selected.as_deref(),
                cfg.get("selectedServerId").and_then(Value::as_str),
            );
            let mut frontend = cfg;
            apply_frontend_view(&mut frontend);
            ApiResponse::ok(frontend)
        }
        Err(e) => ApiResponse::err(format!("{e}")),
    }
}

/// 集合实体级变更。`config_patch` 的粒度是“整个顶层字段”，适合设置项；对 `appRules` 这类数组，
/// 前端拿旧数组做增删再整字段替换仍会串行地丢掉并发实体。实体事务在锁内最新数组上按主键 upsert/delete，
/// 且一次请求可携多条操作（删除自定义应用 + 清关联规则必须全成或全不成）。
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigEntityMutation {
    collection: String,
    entity_id: String,
    /// `null` = 删除；对象 = 按主键整体 upsert。
    value: Value,
}

fn entity_collection_primary_key(collection: &str) -> Option<&'static str> {
    match collection {
        "customAppPresets" => Some("id"),
        "appRules" => Some("appId"),
        _ => None,
    }
}

fn config_mutate_entities_core(
    config: &ConfigManager,
    mutations: &[ConfigEntityMutation],
) -> Result<(Value, bool), polaris_store::StoreError> {
    let (outcome, saved) = config.update_deferred_cleanup(|current| {
        let mut next = current.clone();
        let mut changed = false;
        for mutation in mutations {
            let Some(primary_key) = entity_collection_primary_key(&mutation.collection) else {
                return Decision::Skip(Err(polaris_store::StoreError::validation(
                    "unsupported config entity collection",
                )));
            };
            if mutation.entity_id.is_empty() {
                return Decision::Skip(Err(polaris_store::StoreError::validation(
                    "config entity id must not be empty",
                )));
            }

            let root = next
                .as_object_mut()
                .expect("validated UserConfig root must be an object");
            let collection = root
                .entry(mutation.collection.clone())
                .or_insert_with(|| Value::Array(Vec::new()));
            let Some(items) = collection.as_array_mut() else {
                return Decision::Skip(Err(polaris_store::StoreError::validation(
                    "config entity collection must be an array",
                )));
            };
            let position = items.iter().position(|item| {
                item.get(primary_key).and_then(Value::as_str) == Some(mutation.entity_id.as_str())
            });

            if mutation.value.is_null() {
                if let Some(position) = position {
                    items.remove(position);
                    changed = true;
                }
                continue;
            }
            if mutation.value.get(primary_key).and_then(Value::as_str)
                != Some(mutation.entity_id.as_str())
            {
                return Decision::Skip(Err(polaris_store::StoreError::validation(
                    "config entity value does not match its identity",
                )));
            }
            match position {
                Some(position) if items[position] == mutation.value => {}
                Some(position) => {
                    items[position] = mutation.value.clone();
                    changed = true;
                }
                None => {
                    items.push(mutation.value.clone());
                    changed = true;
                }
            }
        }

        if changed {
            *current = next;
            Decision::Write(Ok((true, current.clone())))
        } else {
            Decision::Skip(Ok((false, current.clone())))
        }
    })?;

    let (changed, transaction_view) = outcome?;
    match (changed, saved) {
        (true, Some(saved)) => Ok((saved, true)),
        (false, None) => Ok((transaction_view, false)),
        _ => unreachable!("entity mutation decision and persistence must agree"),
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn config_mutate_entities(
    app: AppHandle,
    state: State<'_, AppRuntime>,
    mutations: Vec<ConfigEntityMutation>,
) -> ApiResponse<Value> {
    match config_mutate_entities_core(state.config(), &mutations) {
        Ok((mut cfg, changed)) => {
            if changed {
                broadcast_config_changed(&app, &cfg);
            }
            apply_frontend_view(&mut cfg);
            ApiResponse::ok(cfg)
        }
        Err(error) => {
            log::warn!("config:mutateEntities rejected: {error}");
            ApiResponse::err(crate::i18n::t(
                crate::i18n::app_lang(&app),
                crate::i18n::key::NATIVE_UNKNOWN_ERROR,
            ))
        }
    }
}

/// `config_save` 的可测核心（剥掉 `AppHandle`/`State`，单测能直接调）。
///
/// **抽出来是为了让测试走生产路径**：若测试自己调 `preserve_server_owned_secrets` 再 `save_full`，
/// 那么删掉生产代码里的回填调用测试照样绿 = 假绿（本仓刚因同类假绿漏掉一个隐私锁失效的洞）。
/// 让二者共用本函数后，回填与落盘的**顺序与配对**才真被测试锁住。
/// # 乐观并发校验为什么钉在**最顶端**（R6）
///
/// 下面三条策略都以「磁盘现值」为输入、并就地改写 `incoming`。校验若排在它们之后：
///  - `incoming` 已被回填/覆盖过 —— 冲突腿本该「一个字节都没动」，实际却交还了一份被改过的入参；
///  - 校验基准与「用户提交的到底是什么」之间多出一层后端自己刚加的东西，判据不再是纯粹的
///    「磁盘变没变」。
///
/// 由 `optimistic_conflict_touches_nothing` 钉住（把这段挪到三条策略之后即转红）。
fn config_save_core(
    config: &ConfigManager,
    incoming: &mut Value,
    base_version: Option<&str>,
    defer_cleanup: bool,
) -> Result<(SaveOutcome, Option<String>), polaris_store::StoreError> {
    enum Attempt {
        Conflict { disk_version: String },
        Save { old_selected: Option<String> },
    }

    let submitted = incoming.clone();
    let (attempt, saved) = config.update_with_cleanup(defer_cleanup, |current| {
        if let Some(base) = base_version {
            let disk_version = config_version(current);
            if base != disk_version {
                return crate::runtime::config::Decision::Skip(Attempt::Conflict { disk_version });
            }
        }

        // 与版本校验、字段合并取自同一份锁内旧态。命令层若在事务外先 `current()`，
        // 后台 writer 可插在两者之间，让出口缓存失效拿两个不同时刻的值比较。
        let old_selected = current
            .get("selectedServerId")
            .and_then(Value::as_str)
            .map(str::to_string);
        let mut next = submitted;
        // 三条基于磁盘真值的策略与版本校验、最终写入处在同一个 ConfigManager 写临界区：
        // 后台订阅/MRU 写不再能插进“校验通过 → 覆盖落盘”的窗口。
        preserve_server_owned_secrets_from(current, &mut next);
        enforce_backend_authoritative_fields_from(current, &mut next);
        crate::commands::server::prune_recent_server_ids_to_existing(&mut next);
        sync_traffic_rules_projection(&mut next);
        log_invalidated_validators(invalidate_validators_on_global_ua_change(
            current, &mut next,
        ));
        *current = next;
        crate::runtime::config::Decision::Write(Attempt::Save { old_selected })
    })?;

    match attempt {
        Attempt::Conflict { disk_version } => Ok((SaveOutcome::Conflict { disk_version }, None)),
        Attempt::Save { old_selected } => {
            let saved = saved.expect("Decision::Write 必须返回已落盘配置");
            *incoming = saved.clone();
            let mut frontend = saved.clone();
            apply_frontend_view(&mut frontend);
            Ok((
                SaveOutcome::Saved {
                    version: config_version(&saved),
                    config: frontend,
                },
                old_selected,
            ))
        }
    }
}

fn sync_traffic_rules_projection(config: &mut Value) {
    let traffic = config
        .get("trafficRules")
        .or_else(|| config.get("policyRules"))
        .or_else(|| config.get("customRules"))
        .and_then(Value::as_array)
        .cloned();
    let Some(traffic) = traffic else {
        return;
    };
    if let Some(root) = config.as_object_mut() {
        root.insert("trafficRules".to_string(), Value::Array(traffic.clone()));
        root.insert("policyRules".to_string(), Value::Array(traffic.clone()));
        root.insert("customRules".to_string(), Value::Array(traffic));
        root.insert("configSchemaVersion".to_string(), Value::from(4));
    }
}

// ── 全局订阅 UA 变更 → 条件 GET 验证器作废（config 写入侧的那一半）────────────────────
//
// per-sub UA 那一级由 `commands/subscription.rs` 的 `subscription_update` 收口；全局
// `subscriptionUserAgent` 的交互写入口都汇入本文件的全量保存或 patch 核心；兼容命令
// `config:setValue` 也复用 patch，不再自造第三套逻辑。判据本体（含「带 per-sub 覆盖的订阅不该被牵连」）收在
// `commands/subscription::invalidate_validators_on_global_ua_change` —— UA 的归一与优先级语义只有一份。

/// 全量保存腿：拿盘上旧配置与入参比全局 UA，变了就清受影响订阅的 `etag`/`lastModified`。
///
/// 读不到当前配置（首启无文件等）→ 无旧值可比，跳过（保守：判不准不误清，与同文件
/// `preserve_server_owned_secrets` / `enforce_backend_authoritative_fields` 同款取向）。
/// 备份导入腿的**落盘前收口**（三条策略 + 延迟清理保存），与 [`config_save_core`] 是同一条流水线的第三个入口。
///
/// # 为什么抽出来（理由与 [`config_save_core`] 逐字相同）
///
/// `backup_import_apply` 持 `State<'_, AppRuntime>` + `AppHandle`，单测构造不出 Tauri 运行时 ⇒ 若测试
/// 自己按顺序调那三个函数再 `save_full`，「命令里少挂一条」对测试是**恒绿**的（本仓已因同类假绿漏过
/// 隐私锁与后端权威字段两次）。收口成一个函数后，三条策略的**存在、顺序与落盘配对**才真被测试锁住。
///
/// # 三条策略各自守什么
///
/// 1. `preserve_server_owned_secrets`：备份文件不含隐私 hash（导出侧脱敏）→ 不回填 = 导入即拆锁；
/// 2. `enforce_backend_authoritative_fields`：外机的托盘 MRU / geo 元数据不得覆盖本机真值；
/// 3. [`invalidate_validators_on_global_ua_change`]：**这条腿此前缺失**。`subscriptionUserAgent` 按排除法
///    属 generalSettings 类（既不在 `DATA_FIELDS` 也不在 `EXCLUDED_FROM_BACKUP`，见 `store::backup`）⇒
///    勾了「通用设置」的导入就能改全局 UA，而本机订阅的 `etag`/`lastModified` 原样留着 ⇒ 机场按 UA 下发
///    变体时**恒 304**、新格式永远拿不到（与 `config:save` / `config:setValue` 两腿是同一个洞的第三条腿）。
///
/// 备份导入本身就是一次整类 Apply，但广播触发的旧核退出发生在保存之后。因此资源文件、应用图标、
/// Tailscale state 与 WARP 注销不能在这里立即执行；先写持久 journal，由 restart/start 在旧核消失后消费。
///
/// `current` = 打开备份导入时的本机基准，只用来算“本次选中类别真改了哪些顶层字段”。
/// 等待文件/网卡枚举期间可能已有后台写入；真正的字段所有权、UA 验证器失效与旧选中出口都必须以
/// `update_deferred_cleanup` 闭包里的 `latest` 为准。
pub(crate) fn backup_import_save_core(
    config: &ConfigManager,
    current: &Value,
    restored: &mut Value,
) -> Result<Option<String>, polaris_store::StoreError> {
    let submitted = restored.clone();
    let (old_selected, saved) = config.update_deferred_cleanup(|latest| {
        // `restored` 是基于命令开始时的 `current` 合并出的整类结果。等待文件选择/接口枚举期间若后台
        // 写了别的类别，直接整份覆盖会丢更新；这里只把 base→restored 真正变化的顶层类别重放到
        // 最新盘值上。同一被导入类别并发变化仍由显式导入覆盖，未选类别则完整保留最新值。
        let old_selected = latest
            .get("selectedServerId")
            .and_then(Value::as_str)
            .map(str::to_string);
        let mut next = latest.clone();
        replay_top_level_delta(current, &submitted, &mut next);
        preserve_server_owned_secrets_from(latest, &mut next);
        enforce_backend_authoritative_fields_from(latest, &mut next);
        log_invalidated_validators(invalidate_validators_on_global_ua_change(latest, &mut next));
        *latest = next;
        crate::runtime::config::Decision::Write(old_selected)
    })?;
    *restored = saved.expect("Decision::Write 必须返回已落盘配置");
    Ok(old_selected)
}

/// 把 `base → changed` 的顶层替换差集重放到 `target`。UserConfig 的备份类别本来就是顶层字段集合；
/// 这里不做递归 merge，避免把“清空数组/删除键”误解释成“保留旧成员”。
fn replay_top_level_delta(base: &Value, changed: &Value, target: &mut Value) {
    let (Some(base), Some(changed), Some(target)) = (
        base.as_object(),
        changed.as_object(),
        target.as_object_mut(),
    ) else {
        *target = changed.clone();
        return;
    };
    let keys: std::collections::HashSet<&String> = base.keys().chain(changed.keys()).collect();
    for key in keys {
        if base.get(key) == changed.get(key) {
            continue;
        }
        match changed.get(key) {
            Some(value) => {
                target.insert(key.clone(), value.clone());
            }
            None => {
                target.remove(key);
            }
        }
    }
}

/// 作废条数的统一日志（三条写腿共用；0 条不出声，避免每次保存都刷一行）。
fn log_invalidated_validators(n: usize) {
    if n > 0 {
        log::info!(
            "全局订阅 UA 变更 → 已作废 {n} 条订阅的条件 GET 验证器（下次更新走全量 GET，\
             不再因机场按 UA 下发变体而恒 304）"
        );
    }
}

/// 旧 `config:setValue` IPC 的**订阅 UA 感知**兼容腿。
///
/// # 为什么包在命令层而不是改 `ConfigManager::set_value`
///
/// `ConfigManager::set_value` 是与业务语义无关的通用顶层键写入器。把「订阅验证器」
/// 这种领域知识塞进去，等于让配置运行时依赖订阅模块的语义。命令层是既持 `ConfigManager`、
/// 又允许知道订阅语义的那一层，故收口在此。
///
/// 所有键共用 `current → 插键 → save`，使运行核存在时也能生成删除 journal；仅
/// [`SUBSCRIPTION_USER_AGENT_KEY`](super::subscription::SUBSCRIPTION_USER_AGENT_KEY) 在落盘前额外作废验证器（顺序同 [`config_save_core`]）。
fn set_value_with_ua_invalidation(
    config: &ConfigManager,
    key: &str,
    value: Value,
) -> Result<(Option<String>, Value, bool), polaris_store::StoreError> {
    // 兼容旧 IPC 名，但不保留第二套单键写实现：字段所有权、UA validator 失效、MRU 修剪、规则投影、
    // 删除 journal 与规范化终态全部复用 config_patch_core。否则未来把 setValue 用于集合字段时会重新
    // 打开“配置已删、不可逆资产未记账”的旁路。
    let mut patch = serde_json::Map::new();
    patch.insert(key.to_string(), value);
    config_patch_core(config, patch)
}

/// 上游 `CONFIG_UPDATE_MODE`：更新 proxyMode 字段。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn config_update_mode(
    app: AppHandle,
    state: State<'_, AppRuntime>,
    mode: Value,
) -> ApiResponse<()> {
    match set_value_with_ua_invalidation(state.config(), "proxyMode", mode) {
        Ok((_old_selected, cfg, changed)) => {
            if changed {
                broadcast_config_changed(&app, &cfg);
            }
            ok_void()
        }
        Err(e) => ApiResponse::err(format!("{e}")),
    }
}

/// 上游 `CONFIG_SET_VALUE`：置单键 + 广播 event:configChanged。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn config_set_value(
    app: AppHandle,
    state: State<'_, AppRuntime>,
    key: String,
    value: Value,
) -> ApiResponse<()> {
    // 单键写腿同样能改全局订阅 UA → 经 [`set_value_with_ua_invalidation`] 落盘（其余键零行为变化）。
    match set_value_with_ua_invalidation(state.config(), &key, value) {
        Ok((old_selected, cfg, changed)) => {
            if changed {
                broadcast_config_changed(&app, &cfg);
            }
            invalidate_unlock_on_exit_change(
                state.unlock(),
                &BroadcastSink::new(&app),
                state.proxy().status().running,
                old_selected.as_deref(),
                cfg.get("selectedServerId").and_then(Value::as_str),
            );
            ok_void()
        }
        Err(e) => ApiResponse::err(format!("{e}")),
    }
}

// ── A7（R21）：换出口后作废旧解锁探测缓存 ────────────────────────────────────────
//
// server_switch（β 已接，`commands/server.rs`）之外，config 写路径也能改选中出口（`selectedServerId`）
// 而不走 server_switch：`config_save`（前端全量保存 / 备份恢复整份覆盖）与 `config_set_value`（直接置
// `selectedServerId` 键）。换出口后旧出口的解锁角标最长陈旧 30min（缓存 `FRESH_TTL_MS`）。此处按与
// server_switch **同款判准**（出口 identity 变 = 失效）在这两条命令层腿补接线——命令层持 `State<AppRuntime>`
// （可达 `unlock()`/`proxy()`）+ `AppHandle`（建 `BroadcastSink`），是能触达失效契约的正确层
// （`ProxyRuntime` 内部不持 unlock/AppHandle，故失效不在 `runtime/proxy.rs` 内接）。
//
// **守卫「同 id 不失效」**：出口未变（含改无关 config 键）→ 不失效，避免每次设置写都白刷解锁探测。
//
// 判准谓词 `selected_exit_changed` 收敛到 `runtime::unlock`（四写腿共用单一真值源），此处 use 引入。

/// 读当前选中出口 id（落盘前快照，用于出口变判定）。读不到（首启无文件等）→ None（保守：判不准不误失效）。
#[cfg(test)]
fn current_selected_server_id(config: &ConfigManager) -> Option<String> {
    config.current().ok().and_then(|c| {
        c.get("selectedServerId")
            .and_then(Value::as_str)
            .map(str::to_string)
    })
}

/// A7（R21）失效决策**可测核心**（剥掉 `AppHandle`/`State`）：仅当出口 identity 真变时经注入的
/// `UnlockEventSink` 调 `UnlockRuntime::invalidate`。单测注 `UnlockRuntime` + 记录型 sink 摆 old/new
/// 即可断言「变→失效一次 / 不变→零失效」，无需 Tauri 运行时。
///
/// `exit_blocked=false`：切换瞬间尚未探新出口，交前端按 `running` 复位「检测中」并重跑（对齐 invalidate
/// 契约，同 server_switch）。
pub(crate) fn invalidate_unlock_on_exit_change<S: UnlockEventSink>(
    unlock: &UnlockRuntime,
    sink: &S,
    running: bool,
    old_selected: Option<&str>,
    new_selected: Option<&str>,
) {
    if selected_exit_changed(old_selected, new_selected) {
        unlock.invalidate(sink, running, false);
    }
}

// ── 隐私锁状态机（F29；FX-privacy-kdf 升级 scrypt + 独立文件）────────────────────────
//
// 此前三占位是**安全洞**：set_password 空转、unlock 恒 true、has_password 恒 false ——
// 任何人无需密码即可退出隐私模式。现落真状态机（对齐 上游 `main/utils/privacy-lock.ts`）：
//   - **存储（新真值源）**：scrypt 哈希（memory-hard 慢哈希）存**独立文件** `<userData>/privacy-lock.json`
//     （0600，仅属主读写），落盘结构 `{algo,salt,hash,params}`（见 `store::privacy_lock`）。独立文件**永不进
//     config 对象** → 天然免疫「前端全量保存把 config 里的密钥静默抹除」这类洞，也无需在 10+ 个 configChanged
//     广播点脱敏（上游 选独立文件的原始理由）。scrypt 参数逐字对齐 上游 交互档（N=2^14/r=8/p=1/keyLen=32，
//     salt 16B CSPRNG）。
//   - **为何从 salted SHA-256 升级**：早期把 salted SHA-256（**快**哈希，GPU 每秒几十亿次暴力）存进 config.json
//     `privacyPasswordHash`。SHA-256 无 KDF 慢化 → 离线撞库成本极低。scrypt memory-hard 单次 ~50-100ms，
//     抬高暴力成本数个量级。
//   - **存量迁移（不锁死老用户）**：读侧优先 scrypt 文件；文件不存在时回退 config.json 里的 legacy salted-SHA256
//     `privacyPasswordHash`（旧版本存量），**验过即透明升级**到 scrypt 文件并抹掉旧键（见 [`unlock_core`]）；
//     `set` 新密码亦直接落 scrypt 文件 + 抹旧键。旧密码**验败绝不删旧键**（防锁死）。写文件在前、抹旧键在后，
//     任一步失败都不会出现「两者皆无」的锁死窗口。SHA-256 是单向 → 无法在启动期无明文批量转 scrypt，故迁移只能
//     在「拿得到明文」的 unlock/set 时刻惰性做。
//   - **legacy 键防护（过渡期）**：legacy `privacyPasswordHash`（未迁移态）+ 历史明文 `privacyPassword` 仍由
//     [`strip_privacy_secrets`] 在 `config_get`（全量快照的唯一出口）剥除（绝不下发前端；`configChanged`
//     已无载荷，`strip_privacy_secrets` 在那条广播路径上服务的是入核的那份 `cfg`，不是发给前端的）。
//     单键出口 `config_get_value`（曾经以 `is_privacy_key` 短路挡下同一份键）已随 D14 退役——
//     现在整份配置只经这一个出口下发前端。backup / 诊断脱敏亦排除（见 store::backup / stats_engine::redact）。
//     scrypt 独立文件本就不在 config 里，无从经这些出口泄漏。
//   - **校验**：scrypt 与 legacy SHA-256 均**常量时间比较**，仅匹配返 true。
//   - 隐私模式开关：进程内状态（随重启复位，对齐前端 app-store）；enter/exit 状态变更时
//     emit `EVENT_ENTER/EXIT_PRIVACY_MODE`。

/// 隐私模式当前状态（进程内；重启复位——对齐前端 app-store 的 `privacyMode: false` 初值）。
static PRIVACY_MODE: AtomicBool = AtomicBool::new(false);

/// 历史遗留明文密码键（旧版本残留）。由 `store::migrate` 每次 load 清空 + 本层在 `config_get`
/// （全量快照的唯一出口；`configChanged` 已无载荷，不构成全量快照出口）剥除。单键出口
/// `config_get_value` 已随 D14 退役，不再是第二处剥除点。
const PRIVACY_PASSWORD_KEY: &str = "privacyPassword";

/// **legacy** 隐私密码 salted-SHA256 存储键（FX-privacy-kdf 之前的旧真值源）。新真值源已迁至独立
/// `privacy-lock.json`（scrypt）；此键仅为**存量未迁移用户**保留读取/校验 + 迁移完成后清除。
/// `config_get`（全量快照的唯一出口）剥除此键 → 绝不下发前端；`broadcast_config_changed` 里的
/// 剥除服务的是入核那份 `cfg`，`configChanged` 广播本身已无载荷，不构成前端出口。
const PRIVACY_PASSWORD_HASH_KEY: &str = "privacyPasswordHash";

/// 隐私锁独立文件路径（`<userData>/privacy-lock.json`，与 config.json 同目录）。scrypt 新真值源。
fn privacy_lock_path(config: &ConfigManager) -> PathBuf {
    polaris_store::privacy_lock::lock_path(config.dir())
}

/// legacy 隐私键的**单一真值源**：[`strip_privacy_secrets`] 全量出口剥除依赖的唯一列表——
/// 往这里加第三个键即同步生效，不必在别处另抄一份常量用法。
const PRIVACY_KEYS: [&str; 2] = [PRIVACY_PASSWORD_KEY, PRIVACY_PASSWORD_HASH_KEY];

/// 剥除绝不下发前端的隐私密钥键：legacy 明文 `privacyPassword` + legacy salted-SHA256 `privacyPasswordHash`。
/// `config_get`（读出口）与 `broadcast_config_changed`（写广播出口）共用同一份 —— 防任一处漏剥。
/// （scrypt 新真值源在独立文件，本就不在 config 里，无需在此剥除。）
pub(crate) fn strip_privacy_secrets(cfg: &mut Value) {
    if let Some(obj) = cfg.as_object_mut() {
        for key in PRIVACY_KEYS {
            obj.remove(key);
        }
    }
}

/// 回填「服务端独占」的隐私密钥，供**前端来的全量保存**用。
///
/// # 为什么必须有
///
/// `config_get`（全量快照的唯一出口）经 [`strip_privacy_secrets`]（hash 绝不下发；`configChanged`
/// 已无载荷，不构成出口），故前端 store
/// 里的 config **恒无** `privacyPasswordHash`。即时设置如今走锁内 patch，不会碰未提交字段；但暂存保存
/// 与备份恢复仍合法提交整份前端投影，若不在这两个边界回填，任一整份提交都会把 hash 静默抹除，
/// `has_password` 随即把它判成“未设密码”。
///
/// # 为什么不做在 `save_full`（唯一汇流点）里
///
/// `set_password_core` **清除密码用的就是「键缺失」**（`obj.remove(HASH_KEY)`）。若在汇流点无条件回填，
/// 清除密码会永久失效（每次都把旧 hash 填回来）。故只作用于「前端全量提交」的两个入口
/// （`config_save` / `backup_import_apply`）；后端自己读 `current()` 改键的路径（server/rules/
/// subscription/set_value…）本就带着 hash，不受影响。
///
/// 语义：**入参显式带该键 → 尊重入参**（专线写入 / 清除）；入参缺该键 → 从当前配置回填。
#[cfg(test)]
pub(crate) fn preserve_server_owned_secrets(config: &ConfigManager, incoming: &mut Value) {
    // 读不到当前配置（首启无文件等）→ 无可回填，原样保存（不猜、不阻断保存）。
    let Ok(current) = config.current() else {
        return;
    };
    preserve_server_owned_secrets_from(&current, incoming);
}

fn preserve_server_owned_secrets_from(current: &Value, incoming: &mut Value) {
    let Some(obj) = incoming.as_object_mut() else {
        return;
    };
    for key in [PRIVACY_PASSWORD_KEY, PRIVACY_PASSWORD_HASH_KEY] {
        if obj.contains_key(key) {
            continue;
        }
        if let Some(v) = current.get(key) {
            obj.insert(key.to_string(), v.clone());
        }
    }
}

// ── 后端权威字段（前端零写入权）在全量保存边界的强制回正 ────────────────────────────
//
// # 与 `preserve_server_owned_secrets` 是两条不同策略，不能合并
//
// 隐私密钥在 `config_get`（全量快照的唯一出口）被 `strip_privacy_secrets` 剥除 ⇒ 前端快照里
// **根本没有该键**，故「键缺失即回填、键在即尊重入参」够用（且必须尊重入参——清密码用的就是键缺失）。
//
// 本组字段**照常下发前端**（`TrayMenu` 要读 `recentServerIds` 渲染「节点·最近」）⇒ 前端快照里
// **键在、值陈旧**，回填策略永不触发，必须无条件以磁盘为准。
//
// # 历史缺陷与当前边界（用户 2026-07-21 真机报「托盘最近节点只剩 1 条」）
//
// 后端 `server_switch` 写 `recentServerIds`（`commands/server.rs` 的 `push_recent_server_id`：
// unshift + 去重 + `truncate(3)`）后经 `broadcast_config_changed` 广播；前端保鲜总线
// （`ui/src/App.tsx` 的 `api.config.onChanged(() => void loadConfig(true))`）本应把新值拉回，但
// `ui/src/store/app-store.ts` 的乐观写腿（`switchServer` / `saveConfig`）在 mutation 后调
// `invalidateLoadConfig()`，而其代际守卫（`if (myGeneration !== loadConfigGeneration) return`）
// **无法区分**「mutation 之前发起的陈旧 load（该丢）」与「mutation 自己的新鲜回声（该留）」，一律丢弃
// ⇒ store 留陈旧值 ⇒ 旧实现的多个全量保存入口能把后端刚写的历史整份抹回。
//
// # 为什么边界保护仍保留
//
// 当前即时编辑已改为顶层 patch / 集合实体事务，整份保存只剩版本化暂存与备份导入；两者在
// `ConfigManager::update*` 的同一锁内拿磁盘现值、执行本策略并落盘。MRU/订阅后台写无法再插进
// “回填权威字段 → 保存”的窗口。本策略因此是字段所有权的最后一道约束，不再承担并发补丁职责。
//
// # 为什么不做深合并（本仓刻意不引入 merge）
//
// 深合并会同时废掉「清空数组」（传 `[]`）与「删键」两种删除表达，且射程覆盖**全部**字段——用户删掉
// 最后一条规则会发现删不掉。上游 全仓 save 路径零 merge 正是这个原因；它对唯一需要保护的字段
// （隐私密码）的解法是**把字段搬出 config 对象**（独立 `privacy-lock.json`），而非在 save 路径加保护。
// 字段级所有权划分把「以磁盘为准」的射程压到前端根本不写的键上，删除困境自然不存在。

/// 「后端权威」配置字段：**前端零写入权**（UI 只读或全仓零引用），真值只由后端写路径产生。
///
/// # 判准是「前端零写入权」，不是「后端写过」
///
/// `clashApiSecret` 后端也写（[`backfill_secret_and_privacy`] 回填），但前端**有**写入权——
/// 设置·网络页有「重新生成」按钮（`ui/src/components/screens/settings/SettingsNetwork.tsx` 的
/// `update({ clashApiSecret: generateSecret() })`）⇒ **不得**收录，否则该按钮会被静默废掉
/// （点了没反应，比现在的 bug 更隐蔽）。收录前必须逐字段实证「ui/ 全仓零写入」，宁缺勿滥。
///
/// `appRulesSeeded` 同样**不收**：它在 `polaris_store::backup` 的 `DATA_FIELDS` 里，随 appRules 类
/// 被备份导入合法写入 ⇒ 所有权有争议，不满足「零写入权」。
const BACKEND_AUTHORITATIVE_KEYS: [&str; 2] = [
    // 托盘「节点·最近」MRU。只由 `server_switch` 写；ui 全仓仅 TrayMenu 读。
    "recentServerIds",
    // 内置 geo 元数据（随包）。只由 geo seed 写；ui 全仓零读零写。
    "builtinGeoMeta",
    // 曾有第三项 `diagnosticCapture`（诊断采集态）。整条机制已删除（核日志改由 `SubscribeLog` 全级别
    // 送达、级别筛在客户端，不再需要「临时把核提级到 debug」的会话），故该键不再是任何人的权威字段。
    // 旧配置里的残留由 `polaris_store::migrate::migrate_diagnostic_capture` 还原级别后清除。
];

/// 以磁盘当前值**强制回正**入参里的后端权威字段（[`BACKEND_AUTHORITATIVE_KEYS`]）。
///
/// 语义是**镜像磁盘**，两条腿缺一不可：
/// - 磁盘**有**该键 → 覆盖入参（挡掉前端陈旧值）
/// - 磁盘**无**该键 → 从入参**删除**（否则前端携带的陈旧值会把后端刚删掉的键复活）
///
/// 第二条腿不是可选的：只做「有则覆盖」就只实现了「镜像磁盘」的一半 —— 后端一旦**删掉**某个权威键，
/// 任一全量保存都会用前端携带的陈旧值把它复活，而字段所有者对此毫无察觉。
/// （这条腿此前的血证是 `diagnosticCapture` 的「结束采集 = 删该键」；那套机制已随本批删除，
/// 语义本身不变 —— 删除权归字段所有者，缺了这条腿就等于所有者删不掉自己的键。）
///
/// 这也是本组字段的**删除表达**：删除权归字段所有者（后端），前端既无写入权也无需表达删除。
/// 白名单外的键一律不受影响，删除仍靠整份覆盖天然表达（传 `[]` 清空数组 / 缺键删除），与 上游 同构。
#[cfg(test)]
pub(crate) fn enforce_backend_authoritative_fields(config: &ConfigManager, incoming: &mut Value) {
    // 读不到当前配置（首启无文件等）→ 无权威值可依，原样保存（不猜、不阻断保存；
    // 与 `preserve_server_owned_secrets` 同款保守取向）。
    let Ok(current) = config.current() else {
        return;
    };
    enforce_backend_authoritative_fields_from(&current, incoming);
}

fn enforce_backend_authoritative_fields_from(current: &Value, incoming: &mut Value) {
    let Some(obj) = incoming.as_object_mut() else {
        return;
    };
    for key in BACKEND_AUTHORITATIVE_KEYS {
        match current.get(key) {
            Some(v) => {
                obj.insert(key.to_string(), v.clone());
            }
            None => {
                obj.remove(key);
            }
        }
    }
}

// ── 启动期配置维护（上游 loadConfig 内联步骤的 Polaris 收口点）────────────────────
//
// 上游 在 `loadConfig` 里做了三件启动维护：sweepStaleTmpFiles / 回填 clashApiSecret / F29 旧明文密码
// 迁移为哈希。Polaris 的 `store::ConfigStore::load` 是纯逻辑（load 成功路径绝不写盘，仅返回 migration_delta
// 供调用方决策），故这三件需 FS 写 + crypto 的维护收口在**前端首个配置入口** `config_get`，一次性执行。

/// 进程内一次性守卫：启动维护只跑一次（对齐 上游 `tmpSwept` / 首次 loadConfig 语义）。
static STARTUP_MAINTENANCE_DONE: AtomicBool = AtomicBool::new(false);

/// 启动期一次性维护：清孤儿 tmp + 回填 clashApiSecret + F29 明文密码无损迁移。全 best-effort，绝不阻断。
fn run_startup_maintenance_once(config: &ConfigManager) {
    if STARTUP_MAINTENANCE_DONE.swap(true, Ordering::SeqCst) {
        return;
    }
    // ① 清扫原子写遗留的孤儿 tmp（进程 write(tmp) 成功后 rename 前被硬杀/断电留下；随机名不会被下次写覆盖自愈）。
    sweep_stale_tmp_files(config.path());
    // ② 回填 clashApiSecret（本地管理 API/dashboard 出厂鉴权）+ F29 旧明文密码无损迁移为 salted hash。
    if let Err(e) = backfill_secret_and_privacy(config) {
        log::warn!("启动配置维护（clashApiSecret / 隐私哈希回填）失败（不阻断）: {e}");
    }
}

/// 清扫孤儿 tmp（`<config>.<12hex>.tmp` 且 mtime>60s）。上游 `sweepStaleTmpFiles`。
///
/// 决策纯逻辑收在 `store::fs::should_sweep_stale_tmp`（名匹配 + 龄期>60s，变异可验）；本函数只做 FS 遍历/删除。
/// mtime 守卫防误删并发 saveConfig 的在途 tmp。best-effort：任何 FS 失败忽略。
fn sweep_stale_tmp_files(config_path: &Path) {
    let (Some(dir), Some(base_name)) = (
        config_path.parent(),
        config_path.file_name().and_then(|n| n.to_str()),
    ) else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let age_secs = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.elapsed().ok())
            .map_or(0, |d| d.as_secs());
        if polaris_store::fs::should_sweep_stale_tmp(base_name, name, age_secs) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// 生成本地管理 API 的 secret（CSPRNG 16 字节 → 32 位小写 hex）。上游 `randomBytes(16).toString('hex')`。
/// 复用 `gen_salt` 同源的 ring CSPRNG（rustls 既有依赖），OS 熵源失败 → Err（绝不产弱/空密钥）。
///
/// 两个消费者、同一形状：持久化的 `clashApiSecret`（本文件 [`backfill_secret_and_privacy`]）与
/// Tailscale 瞬态登录核那条一次性管理 API 的 secret（`runtime::tailscale_login_core`）。
pub(crate) fn generate_local_api_secret() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut bytes)
        .map_err(|_| "系统随机源不可用，无法生成本地管理 API secret".to_string())?;
    Ok(hex_encode(&bytes))
}

/// 回填 clashApiSecret（缺失/空 → 随机生成）+ F29 旧明文密码无损迁移（明文 → salted hash）。
///
/// # clashApiSecret（HIGH 安全）
/// 本地管理 API（含默认开的 sing-box dashboard）出厂无鉴权（`proxy.rs` 读侧：空 secret = 免认证）。
/// 新装/存量随机回填 + **持久化**（供 external_ui/外部客户端跨会话复用，故必须落盘稳定，不能每次 load 重生成）。
///
/// # F29 无损迁移（隐私锁 → scrypt 独立文件）
/// `store::migrate::migrate_privacy_password_clear` 每次 load 把旧明文 `privacyPassword` 抹成 ""（防外泄），
/// 但**丢了密码** → 隐私锁静默失效。此处在明文被抹前直读**盘上**明文（in-memory load 已清空，盘上 load 不落盘
/// 仍留），算 **scrypt** 哈希存进独立 `privacy-lock.json`（0600），并触发 config save_full 抹掉盘上残留明文。
/// 仅当盘上有明文 **且** 既无 scrypt 文件 **又** 无 legacy SHA-256 键时执行（不覆盖用户已设的新密码）。
///
/// clashApiSecret 与「明文迁移触发的明文抹除」合并为**一次** save_full 落盘。幂等：secret 已在 /
/// 无旧明文 / 已有 scrypt 文件或 legacy 键 → 不写。
fn backfill_secret_and_privacy(config: &ConfigManager) -> Result<(), String> {
    let path = config.path();
    // 盘上旧明文密码：in-memory load 经 migrate 抹成 ""，故直读盘取明文（load 成功不落盘 → 盘上此刻仍留明文）。
    let disk_plain: Option<String> = std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .and_then(|v| {
            v.get(PRIVACY_PASSWORD_KEY)
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .filter(|s| !s.is_empty());

    // 直接取 LoadResult 判「是否真从盘加载成功」：损坏回落（error 且非新装）**绝不 save_full**——
    // 否则会用默认配置覆盖损坏原文件 = 破坏 `store::ConfigStore::load` 的「不覆盖损坏磁盘」保护（数据丢失）。
    let loaded = polaris_store::ConfigStore::load(&polaris_store::StdFs, path);
    if loaded.error.is_some() && !loaded.was_missing {
        return Ok(()); // 损坏配置：只备份（load 已做），绝不回填覆盖
    }
    let mut cfg = loaded.config;
    // 已有隐私密码 = scrypt 文件存在 **或** legacy SHA-256 键存在（任一都不得被旧明文覆盖）。
    let has_scrypt_file = polaris_store::privacy_lock::has(&StdFs, &privacy_lock_path(config));
    let has_legacy = config_has_password(&cfg);
    let Some(obj) = cfg.as_object_mut() else {
        return Ok(());
    };
    let mut changed = false;

    // clashApiSecret 回填（缺失/空 → 随机生成）。
    let has_secret = obj
        .get("clashApiSecret")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty());
    if !has_secret {
        obj.insert(
            "clashApiSecret".to_string(),
            json!(generate_local_api_secret()?),
        );
        changed = true;
    }

    // F29 无损迁移：盘上有旧明文 && 既无 scrypt 文件又无 legacy 键 → 用明文算 **scrypt** 存独立文件。
    // changed=true 触发下方 save_full → 用 migrate 已抹空明文的 cfg 覆盖盘上 config.json（scrub 残留明文）。
    let needs_plain_scrub = disk_plain.is_some();
    if let Some(plain) = disk_plain {
        if !has_scrypt_file && !has_legacy {
            let salt = gen_salt()?;
            let hash = polaris_store::privacy_lock::hash_password(&plain, &salt)
                .map_err(|e| format!("{e}"))?;
            polaris_store::privacy_lock::write(&StdFs, &privacy_lock_path(config), &hash)
                .map_err(|e| format!("{e}"))?;
            changed = true;
        }
    }
    // 独立 scrypt 文件可能已在上一次迁移中写成、但 config 原子写随后失败。只要盘上仍有旧明文，
    // 本轮就必须再次落配置完成 scrub；不能因 scrypt 已存在而永久留下明文。
    changed |= needs_plain_scrub;

    if changed {
        let generated_secret = cfg.get("clashApiSecret").cloned();
        // 基于锁内最新配置补字段并触发 migrate/sanitize 落盘，避免启动期其它写入恰好插入时被整份覆盖。
        config
            .update(|latest| {
                let Some(obj) = latest.as_object_mut() else {
                    return Decision::Skip(());
                };
                let has_secret = obj
                    .get("clashApiSecret")
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.is_empty());
                if !has_secret {
                    if let Some(secret) = generated_secret {
                        obj.insert("clashApiSecret".to_string(), secret);
                    }
                }
                Decision::Write(())
            })
            .map_err(|e| format!("{e}"))?;
    }
    Ok(())
}

/// 生成 16 字节盐（ring CSPRNG，经 rustls 既有依赖的 `crypto::ring` provider 暴露——与
/// `runtime::mesh::generate_warp_seed` 同源，无新依赖）。OS 熵源失败 → Err（绝不产弱/零盐）。
fn gen_salt() -> Result<[u8; 16], String> {
    let mut salt = [0u8; 16];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut salt)
        .map_err(|_| "系统随机源不可用，无法生成密码盐".to_string())?;
    Ok(salt)
}

/// 字节 → 小写 hex。
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        s.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    s
}

/// hex → 字节。非偶长度/非法字符 → None。
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// **legacy** salted SHA-256：`sha256(salt || password)` → hex。复用 `polaris_helper::core_install::sha256_hex`。
/// 新密码已改用 scrypt 独立文件（见 `store::privacy_lock`）；本函数仅供**存量 SHA-256 用户的解锁校验**
/// （经 [`verify_password`] → [`unlock_core`] legacy 分支）复算比对，production 不再用它**创建**新哈希。
fn hash_password(salt: &[u8], password: &str) -> String {
    let mut data = salt.to_vec();
    data.extend_from_slice(password.as_bytes());
    polaris_helper::core_install::sha256_hex(&data)
}

/// 常量时间比较（等长逐字节 XOR 累加，无早退时序泄漏）。长度不等直接 false（hash 恒等长，不泄信息）。
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// **legacy** 校验：明文是否匹配存储的 `salt_hex$hash_hex`（salted SHA-256）。格式非法 → 不匹配（fail-closed）。
/// 仅存量未迁移用户走此路径；验过后 [`unlock_core`] 会把其升级为 scrypt 文件。
fn verify_password(stored: &str, password: &str) -> bool {
    let Some((salt_hex, hash_hex)) = stored.split_once('$') else {
        return false;
    };
    let Some(salt) = hex_decode(salt_hex) else {
        return false;
    };
    let expected = hash_password(&salt, password);
    constant_time_eq(expected.as_bytes(), hash_hex.as_bytes())
}

/// 清除 config.json 里的 legacy salted-SHA256 `privacyPasswordHash` 键（scrypt 文件已成新真值源）。
///
/// 快路径：当前配置无该键（绝大多数新用户 / 已迁移用户）→ 空操作，不触盘。有该键 → load_full 拿全量 →
/// 移除 → save_full 落盘。留着旧键 = 双真值源 + 多一处泄漏面，故迁移完成即抹。
fn clear_legacy_hash_key(config: &ConfigManager) -> Result<(), polaris_store::StoreError> {
    config
        .update(|cfg| {
            let Some(obj) = cfg.as_object_mut() else {
                return Decision::Skip(());
            };
            if obj.remove(PRIVACY_PASSWORD_HASH_KEY).is_some() {
                Decision::Write(())
            } else {
                Decision::Skip(())
            }
        })
        .map(|_| ())
}

/// config 是否已设隐私密码（`privacyPasswordHash` 存有非空 salted hash）。纯函数，便于单测。
fn config_has_password(cfg: &Value) -> bool {
    cfg.get(PRIVACY_PASSWORD_HASH_KEY)
        .and_then(Value::as_str)
        .map(|s| !s.is_empty())
        .unwrap_or(false)
}

/// `set_password_core` 失败原因：区分「锁屏门控拒绝」（`privacy_set_password` 需转 `err_with_code`
/// 供前端按 code 识别）与其它失败（config 读写 / CSPRNG 出错等，原始 message 透传）。
#[derive(Debug)]
enum SetPasswordError {
    /// 隐私模式（锁屏）中：契约 L141「锁屏禁改/清密码」，无条件拒绝——不读写存储、不生成新盐。
    Locked,
    /// 非锁屏态下的其它失败。
    Other(String),
}

/// `privacy:setPassword` 核心（注入 `ConfigManager` + 显式 `locked` 态，便于真实 ConfigStore 驱动测试）。
///
/// 非空 → 新盐算 **scrypt** 存独立 `privacy-lock.json`（0600）+ 抹掉 config.json 里的 legacy SHA-256 键；
/// 空串 → 删 scrypt 文件 + 抹 legacy 键（任何人可解锁）。**绝不存明文**。每次 set 都新生成盐（salt 唯一）。
///
/// # 为什么 `locked` 是显式参数而非直接读 `PRIVACY_MODE`
///
/// 同文件其余 `_core` 函数一律不碰进程内 static（纯函数、状态由调用方传入），本函数照此惯例；
/// 且 `cargo test` 默认多线程并行跑，若在此直接读写共享的 `PRIVACY_MODE` static，跑锁屏门控用例时
/// 会与同时跑的其它 `set_password_core` 正常流程用例互相脏读、产生 flaky（该 static 是进程唯一实例，
/// 无法每测试隔离一份）。真实调用方（`privacy_set_password`）在其**唯一**调用处显式读一次 `PRIVACY_MODE`
/// 传入，语义等价，且单测可完全绕开全局态直接摆 `locked: true/false`。
///
/// # 门控做什么
///
/// `locked=true` → 无条件拒绝改 / 清密码（契约 L141），且在**碰存储之前**就返回——这正是此前的洞：
/// 锁屏状态下传空串会走到清密码路径 = 未验证密码即解锁。对「改」与「清」一视同仁
/// （`password` 是否为空不影响门控判定）。
fn set_password_core(
    config: &ConfigManager,
    password: &str,
    locked: bool,
) -> Result<(), SetPasswordError> {
    if locked {
        return Err(SetPasswordError::Locked);
    }
    let path = privacy_lock_path(config);
    if password.is_empty() {
        // 清除：删 scrypt 文件（不存在视为成功）。
        polaris_store::privacy_lock::remove(&StdFs, &path)
            .map_err(|e| SetPasswordError::Other(format!("{e}")))?;
    } else {
        // 新盐 → scrypt 哈希 → 写独立文件（0600）。文件写成功后才抹 legacy 键，避免中途失败致锁死。
        let salt = gen_salt().map_err(SetPasswordError::Other)?;
        let hash = polaris_store::privacy_lock::hash_password(password, &salt)
            .map_err(|e| SetPasswordError::Other(format!("{e}")))?;
        polaris_store::privacy_lock::write(&StdFs, &path, &hash)
            .map_err(|e| SetPasswordError::Other(format!("{e}")))?;
    }
    // 抹掉 config.json 里的 legacy SHA-256 键（若存量用户此前设过）——scrypt 文件已成唯一真值源。
    clear_legacy_hash_key(config).map_err(|e| SetPasswordError::Other(format!("{e}")))
}

/// `privacy:unlock` 核心：已设密码 → 仅匹配返 true；未设 → 自由解锁（true）。
///
/// 读侧优先级：**scrypt 独立文件**（新真值源）> config.json legacy SHA-256（存量未迁移）> 未设密码。
/// legacy 分支验过后**透明升级**到 scrypt 文件（拿得到明文的唯一时机）；升级 best-effort，失败不阻断解锁
/// （下次再升）。旧密码**验败绝不删旧键 / 不建文件**（防把老用户锁在外）。
fn unlock_core(config: &ConfigManager, password: &str) -> Result<bool, String> {
    let path = privacy_lock_path(config);
    // ① scrypt 文件存在 → 唯一判据（忽略残留 legacy 键）。
    if let Some(h) = polaris_store::privacy_lock::read(&StdFs, &path) {
        return Ok(polaris_store::privacy_lock::verify(password, &h));
    }
    // ② 无 scrypt 文件 → 回退 legacy SHA-256。
    let cfg = config.current().map_err(|e| format!("{e}"))?;
    let stored = cfg
        .get(PRIVACY_PASSWORD_HASH_KEY)
        .and_then(Value::as_str)
        .unwrap_or("");
    if stored.is_empty() {
        return Ok(true); // 未设密码 → 自由解锁。
    }
    if !verify_password(stored, password) {
        return Ok(false); // 旧格式密码错——不升级、不删旧键（防锁死）。
    }
    // 旧格式验过：升级到 scrypt 文件（写文件在前、抹旧键在后）。best-effort，失败仅记日志、仍放行解锁。
    if let Err(e) = upgrade_legacy_to_scrypt(config, &path, password) {
        log::warn!("隐私锁 legacy SHA-256 → scrypt 升级失败（不阻断解锁，下次再升）: {e}");
    }
    Ok(true)
}

/// 把验过的 legacy SHA-256 密码升级为 scrypt 独立文件：写文件 → 抹 legacy 键。
/// **顺序关键**：先写 scrypt 文件、后抹旧键，任一步失败都不会出现「两者皆无」的锁死窗口。
fn upgrade_legacy_to_scrypt(
    config: &ConfigManager,
    path: &Path,
    password: &str,
) -> Result<(), String> {
    let salt = gen_salt()?;
    let hash =
        polaris_store::privacy_lock::hash_password(password, &salt).map_err(|e| format!("{e}"))?;
    polaris_store::privacy_lock::write(&StdFs, path, &hash).map_err(|e| format!("{e}"))?;
    clear_legacy_hash_key(config).map_err(|e| format!("{e}"))
}

/// `privacy:hasPassword` 核心：scrypt 文件存在 **或** config.json 里有非空 legacy SHA-256 键。
fn has_password_core(config: &ConfigManager) -> Result<bool, String> {
    if polaris_store::privacy_lock::has(&StdFs, &privacy_lock_path(config)) {
        return Ok(true);
    }
    let cfg = config.current().map_err(|e| format!("{e}"))?;
    Ok(config_has_password(&cfg))
}

/// 上游 `CONFIG_GET_PRIVACY_MODE`：隐私模式开关状态（进程内状态机实值）。
#[tauri::command]
pub fn config_get_privacy_mode(_state: State<'_, AppRuntime>) -> ApiResponse<bool> {
    ApiResponse::ok(PRIVACY_MODE.load(Ordering::Relaxed))
}

/// 上游 `CONFIG_SET_PRIVACY_MODE`：切换隐私模式（进/出）+ 状态变更时 emit enter/exit 事件。
///
/// 密码闸在 unlock 侧（前端退出前先 `privacy_unlock` 验证）；本 command 落状态转移 + 广播事件，
/// 供 UI（Logs/Connections 脱敏）与 log builder（隐私模式抬日志级别）联动。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn config_set_privacy_mode(
    app: AppHandle,
    _state: State<'_, AppRuntime>,
    value: bool,
) -> ApiResponse<()> {
    let prev = PRIVACY_MODE.swap(value, Ordering::Relaxed);
    if prev != value {
        let evt = if value {
            EVENT_ENTER_PRIVACY_MODE
        } else {
            EVENT_EXIT_PRIVACY_MODE
        };
        let _ = app.emit(evt, ());
    }
    ok_void()
}

/// 上游 `PRIVACY_HAS_PASSWORD`：是否设置了隐私密码（scrypt 文件存在或存量 legacy 键非空）。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn privacy_has_password(state: State<'_, AppRuntime>) -> ApiResponse<bool> {
    match has_password_core(state.config()) {
        Ok(has) => ApiResponse::ok(has),
        Err(e) => ApiResponse::err(e),
    }
}

/// 上游 `PRIVACY_SET_PASSWORD`：设置 / 改 / 清隐私密码。
///
/// 非空 → 新盐算 **scrypt** 存独立 `privacy-lock.json`（0600）+ 抹 legacy 键；空串 → 删文件 + 抹 legacy 键。
/// **绝不存明文**。不广播 `config:changed`：密码变更不影响代理配置生成 → 无需热切换（且 scrypt 哈希本就
/// 不入 config → 不经 configChanged 出口）。返回 `{success:true}`（前端契约）。
///
/// 锁屏门控（契约 L141）：`PRIVACY_MODE` 为 true（隐私模式/锁屏中）时无条件拒绝——改密码、清密码皆算，
/// 返 `err_with_code(_, "PRIVACY_LOCKED")` 供前端区分。当前隐私遮罩 UI 尚未接线，此路径暂无 UI 触发
/// （latent），但契约明确点名「不得简化」，故后端闸先落好，UI 落地时直接受益。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn privacy_set_password(state: State<'_, AppRuntime>, password: String) -> ApiResponse<Value> {
    let locked = PRIVACY_MODE.load(Ordering::Relaxed);
    match set_password_core(state.config(), &password, locked) {
        Ok(()) => ApiResponse::ok(json!({ "success": true })),
        Err(SetPasswordError::Locked) => ApiResponse::err_with_code(
            "锁屏状态下禁止修改或清除隐私密码，请先解锁",
            "PRIVACY_LOCKED",
        ),
        Err(SetPasswordError::Other(e)) => ApiResponse::err(e),
    }
}

/// 解锁失败弱限速时长（契约 L141「解锁失败 sleep(300) 弱限速」）：抑制单进程高速暴力猜密码
/// （无限速时单进程每秒可猜上万次）。契约给定值，不额外加码。
const UNLOCK_FAIL_DELAY_MS: u64 = 300;

/// 解锁限速：`ok=false`（密码错）才延时 [`UNLOCK_FAIL_DELAY_MS`]；`ok=true`（密码对 / 未设密码自由解锁）
/// 不延时，不拖累正常解锁手感。
///
/// 抽成独立 async helper（不接触 `ConfigManager`/`State`）只为让 300ms 限速本身可单测（`State<'_, AppRuntime>`
/// 无法在 `#[tokio::test]` 里构造，同文件其余 `_core` 拆分也是同一动机）。
async fn apply_unlock_rate_limit(ok: bool) {
    if !ok {
        tokio::time::sleep(std::time::Duration::from_millis(UNLOCK_FAIL_DELAY_MS)).await;
    }
}

/// 上游 `PRIVACY_UNLOCK`：解锁（验证密码，常量时间比较）。返回 `{ok:bool}`（前端契约）。
///
/// 已设密码 → 仅哈希匹配返 `true`（scrypt 文件优先，legacy SHA-256 回退+透明升级）；未设密码 → 自由解锁
/// （`true`，对齐「留空则任何人可解锁」）。
///
/// 契约 L141：解锁失败经 [`apply_unlock_rate_limit`] 弱限速 300ms。`async fn` + `tokio::time::sleep`——
/// **绝不 `std::thread::sleep`**：本 command 跑在 tauri 的 tokio executor 上，`std::thread::sleep`
/// 会硬阻塞该 worker 线程、冻结同线程上其余并发 IPC；`tokio::time::sleep` 只让出当前 task，executor
/// 照常调度其余任务（对齐仓内既有用法，如 `runtime/stats.rs`）。`unlock_core` 本身是纯同步计算（无 IO），
/// 限速前先同步跑完拿到 `ok`，`state` 借用不跨随后的 `.await`（本仓 async command 惯例，
/// 见 `commands/proxy::system_proxy_disable`）。
#[tauri::command]
pub async fn privacy_unlock(
    state: State<'_, AppRuntime>,
    password: String,
) -> Result<ApiResponse<Value>, ()> {
    // tauri 硬性要求：async command 若带引用型入参（`State<'_, _>`），返回值必须是 `Result`
    // （否则宏展开报 `AsyncCommandMustReturnResult` / `'static` 借用期不够）——同 `system_proxy_disable`。
    let result = unlock_core(state.config(), &password);
    Ok(match result {
        Ok(ok) => {
            apply_unlock_rate_limit(ok).await;
            ApiResponse::ok(json!({ "ok": ok }))
        }
        Err(e) => ApiResponse::err(e),
    })
}

/// 广播 event:configChanged（上游 `ipcEventEmitter.sendToAll('event:configChanged', { newValue })`）
/// **并把变更送进运行核**（上游 `config-change-handler.ts:77` 的 `proxyManager.switchMode(latest)`）。
///
/// # 为什么接线在这里
///
/// 这是本仓所有配置写命令（`config:save` / `config:setValue` / `server:switch` / `rules:*` /
/// `subscription:*` 共 10+ 处）的**唯一汇流点** —— 与 Polaris 把 switchMode 挂在 CONFIG_CHANGED
/// 单一监听器上同构。接在此处 = 每条配置变更路径自动获得热切换判定，无需逐个命令改造，
/// 也不会漏掉将来新增的写命令（§K7.1：门要开在唯一的生产路径上）。
///
/// 此前本函数只 emit 给 UI，**运行核对配置变更一无所知** —— 切节点只改磁盘、核继续跑旧节点，
/// 唯一入核手段是用户手点「应用」触发的全量重启。
///
/// `switch_mode` 是 async 且含 gRPC I/O（最长 ~2s deadline），而本函数被同步 command 调用 →
/// `spawn` 到 tokio 后台，不阻塞 IPC 返回（对齐 Polaris 的 `void switchMode(...)` 即发即忘）。
pub(crate) fn broadcast_config_changed(app: &AppHandle, new_value: &Value) {
    broadcast_config_changed_with(app, new_value, false);
}

/// 只广播“磁盘配置已变”信号，不把整份 D 送入运行核。自动故障切换已经自行完成了受限的
/// `selectedServerId` 热切事务，必须用本腿刷新各 WebView/托盘；若复用 [`broadcast_config_changed`]
/// 会再次调用普通 `switch_mode`，把 D 中其它已保存未 Apply 的字段夹带重启入核。
pub(crate) fn emit_config_changed_signal(app: &AppHandle) {
    let _ = app.emit(EVENT_CONFIG_CHANGED, json!({}));
}

/// 配置落盘后立即生效的 App/窗口投影。由运行时的“候选仍是最新磁盘版本”闸门回调，
/// 与入核共享乱序作废语义；不得在闸门之前单独执行。
fn apply_process_config_projections(app: &AppHandle, cfg: &Value) {
    if let Some(level) = cfg.get("logLevel").and_then(Value::as_str) {
        crate::logging::set_level(level);
    }
    let native_theme =
        crate::tray::native_theme_override(cfg.get("uiTheme").and_then(Value::as_str));
    for label in ["main", crate::tray::TRAY_LABEL] {
        if let Some(win) = app.get_webview_window(label) {
            let _ = win.set_theme(native_theme);
        }
    }
}

/// [`broadcast_config_changed`] 带「保存不重启」标志的形态（暂存层「保存」腿，spec §2.5 Q4）。
///
/// 只有 `config:save` 会传 `true`（且仅当前端显式传了 `deferRestart`）。其余十余个配置写命令
/// （`server:switch` / `rules:*` / `subscription:*` / `config:setValue` …）一律走无参形态 =
/// 今天行为逐字节不变 —— 那些是「用户点了某个具体动作」，不是「用户点了保存」，不该被降级。
pub(crate) fn broadcast_config_changed_with(
    app: &AppHandle,
    new_value: &Value,
    defer_restart: bool,
) {
    // F29 defense-in-depth：隐私密码（legacy 明文 + salted hash）绝不经**任何**前端可见路径下发。
    // 本事件已不带载荷（见下），故这份剥离服务的是**入核**那一份 —— `cfg` 一路 move 进
    // `switch_mode_with`；剥在源头，将来谁把它接回某条前端可见路径也带不出 hash。
    // （隐私密码不参与代理配置生成，剥除对热切换无影响。）
    let mut cfg = new_value.clone();
    strip_privacy_secrets(&mut cfg);
    // **无载荷信号**。四个消费方一个都不读 payload，收到即各自重拉：`App.tsx` → `loadConfig(true)`、
    // `TrayMenu.tsx` → `hydrate()`、`settings/use-config.ts` → `load(true)`（该处还专门注明「payload 的
    // newValue 不能直接用」——它经脱敏、且没走 `config_get` 那侧的 bypassLANList 补齐，与其契约不同源）、
    // `main.rs` 的 `listen_any` → `reconcile_tray`（回调签名 `|_|` 直接丢弃）。
    //
    // 而 `cfg` 在这行之后仍要用（logLevel / uiTheme / move 进 `switch_mode_with`）⇒ 载荷里写 `cfg`
    // 只能借用 ⇒ `json!` 展开成 `to_value(&cfg)`，在上面那次 clone 之外**再深拷贝一整棵配置树**，
    // 外加整份 JSON 序列化、按 webview 拼注入脚本、`NSString` 构造与 Rust 侧监听各自一份 —— 全白做。
    emit_config_changed_signal(app);
    // try_state：测试/早期启动期可能尚未 manage(AppRuntime) → 取不到就只广播不入核，不 panic。
    if let Some(state) = app.try_state::<AppRuntime>() {
        let proxy = state.proxy.clone();
        // 配置内容相同也不代表意图相同：用户可再次选择同一目标。独立代次在 spawn 前取得，
        // 后到广播会让排队中的旧 selector 事务在拿锁后自行作废。
        let intent_generation = proxy.register_selector_intent();
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            let _ = proxy
                .switch_persisted_config_if_current(
                    cfg,
                    defer_restart,
                    intent_generation,
                    move |current| {
                        apply_process_config_projections(&app, current);
                    },
                )
                .await;
        });
    } else {
        // 早期启动/单测没有 AppRuntime，无法做磁盘版本复核；保留历史的 best-effort 投影行为。
        apply_process_config_projections(app, &cfg);
    }
}

#[cfg(test)]
mod tests;
