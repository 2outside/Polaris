//! 订阅类 command（上游 `subscription-handlers.ts`）。
//!
//! 映射 channel：
//! - 新增只允许 backend-owned 原子 `subscription_create_start`；旧 `subscription:add` 不注册 invoke。
//! - `subscription:update` → [`subscription_update`]
//! - `subscription:delete` → [`subscription_delete`]
//! - `subscription:updateServers` → [`subscription_update_servers`]（net-stack 拉取 + 对账 + force-restart）
//! - `subscription:preview` → [`subscription_preview`]（net-stack 预检，不写 config）
//! - `localImport:parse` → [`local_import_parse`]（net-stack 离线解析）
//! - `localImport:pickFile` → [`local_import_pick_file`]（Tauri dialog 插件）

use std::{sync::Arc, time::Duration};

use serde_json::{json, Value};
use tauri::{AppHandle, Manager, State, WebviewWindow};
use tauri_plugin_dialog::DialogExt;
use tokio::io::AsyncReadExt;

use polaris_config_engine::builder::endpoint_routes::{
    is_mesh_node_unroutable, mesh_node_carries_full_tunnel,
};
use polaris_config_engine::builder::route::subscription_update_route_uses_proxy;
use polaris_config_engine::user_config::dns_constants::{is_direct_selection, DIRECT_SERVER_ID};
use polaris_config_engine::user_config::server_config::{Protocol, ServerConfig};
use polaris_config_engine::user_config::UserConfig;
use polaris_net_stack::singbox_import::ImportOrigin;
use polaris_net_stack::ssrf::DnsLookup;
#[cfg(test)]
use polaris_net_stack::subscription::default_subscription_user_agent;
use polaris_net_stack::subscription::{Conditional, ProviderFetchError, SubscriptionParseLimits};
use polaris_net_stack::subscription_error::SubscriptionErrorKind;

use crate::commands::config::broadcast_config_changed;
use crate::events::{broadcast, channel::EVENT_SUBSCRIPTION_UPDATE_PROGRESS};
use crate::i18n::{key, t};
use crate::response::{ok_void, ApiResponse};
use crate::runtime::config::Decision;
use crate::runtime::http::{HttpRuntime, SystemDnsLookup};
use crate::runtime::subscription_parse::SubscriptionParseExecutor;
use crate::runtime::unlock::{selected_exit_changed, BroadcastSink};
use crate::runtime::AppRuntime;

/// 主订阅首跳的唯一瞬时重试：TUN 冷启动的路由/连接池已经过 settle gate，但 Windows 数据面仍可能
/// 在首个真实请求上报一次连接类错误。300ms 只落失败腿，健康路径零等待；次数由
/// [`primary_fetch_retry_delay`] 钉死为一次，避免把 30s 超时或确定性业务错误放大成漫长假成功。
const PRIMARY_FETCH_RETRY_DELAY: Duration = Duration::from_millis(300);
/// create / update / preview 的整次拉取+provider+解析墙钟上限。commit 在成功 await 之后单独线性化，
/// 不会被 timeout future 半途打断。
const SUBSCRIPTION_OPERATION_TIMEOUT: Duration = Duration::from_secs(60);
/// Native file picks are local I/O but can still block indefinitely on a disconnected mount. Keep
/// this shorter than the parser operation deadline and return the established read failure shape.
const LOCAL_IMPORT_FILE_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// 首跳错误是否值得再试一次。这里只认**尚未收到 HTTP 响应**的瞬时传输类：
/// - DNS / Refused：确定是网络瞬态；
/// - Unknown：reqwest 的 TLS/connect 源错误跨平台形态不同，分类器宁可不误判，但仍属首跳传输失败。
///
/// Timeout 已经消费 30s，不再翻倍；HTTP/SSRF/Scheme/TooLarge/Parse/Empty 都是确定性错误，重试无益。
fn primary_fetch_retry_delay(kind: SubscriptionErrorKind, retries_done: u8) -> Option<Duration> {
    (retries_done == 0
        && matches!(
            kind,
            SubscriptionErrorKind::Dns
                | SubscriptionErrorKind::Refused
                | SubscriptionErrorKind::Unknown
        ))
    .then_some(PRIMARY_FETCH_RETRY_DELAY)
}

/// 条件 GET 验证器是否随本次编辑作废：**per-sub UA 变了就作废**。
///
/// # 为什么（`DESIGN-REVIEW(ua-invalidates-validators)` 的落地）
///
/// `etag`/`lastModified` 是**上一次响应**的验证器，而机场普遍**按 UA 下发不同变体**
/// （clash / sing-box / base64 三套正文，同一个 URL）。若 ETag 是按「订阅版本」而非「响应变体」
/// 生成的（相当常见），那么换了 UA 之后带旧验证器再请求，服务端照样回 **304** ——
/// 我们短路 parse/reconcile，**新格式永远拿不到**，用户只看到「无变化」且无从排查。
///
/// 判据只看 UA 是否**真的变了**（`None`/`""`/纯空白按同一口径归一，与
/// [`resolve_subscription_ua`] 的 falsy 语义一致）：URL/名字等其它字段的编辑不该白扔验证器。
/// URL 变了不需要在此处理 —— 那是另一个资源，服务端本来就不会拿旧 ETag 判 304。
///
/// **本函数只管 per-sub 那一级**。全局 `config.subscriptionUserAgent` 改动走 config 写命令、
/// 不经本函数 → 那条腿由 [`invalidate_validators_on_global_ua_change`] 在 config 写入侧收口
/// （`commands/config.rs` 的两个写命令各挂一处）。二者判据同源（都走 [`pick_ua`] 归一 +
/// [`resolve_subscription_ua`] 的优先级），合起来覆盖两级 UA 的全部变更面。
fn ua_changed(old_sub: &Value, new_sub: &Value) -> bool {
    pick_ua(old_sub.get("userAgent")) != pick_ua(new_sub.get("userAgent"))
}

/// 全局订阅 UA 的 config 键名（**单一真值**：解析、变更判定、config 写侧路由三处共用一个字面量）。
pub(crate) const SUBSCRIPTION_USER_AGENT_KEY: &str = "subscriptionUserAgent";

/// UA 取值归一（**falsy** 语义）：缺省 / 非字符串 / `""` / 纯空白 一律折成 `None`。
///
/// 全仓凡是「这个 UA 算不算设了」的判断都必须经本函数 —— 三处（解析优先级、per-sub 变更判定、
/// 全局变更判定）各写一遍 `trim().is_empty()` 迟早漂移，而漂移的表现是**恒 304**这种无声故障。
fn pick_ua(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// 全局 `subscriptionUserAgent` 变更 → 作废**受影响订阅**的条件 GET 验证器。就地改 `new_cfg`，
/// 返回真被清掉验证器的订阅条数（供调用方记日志 / 测试断言）。
///
/// # 为什么必须有（与 [`ua_changed`] 是同一个洞的另一半）
///
/// `etag`/`lastModified` 是**上一次响应**的验证器，而机场普遍按 UA 下发不同正文变体
/// （clash / sing-box / base64 三套，同一个 URL）。ETag 若按「订阅版本」而非「响应变体」生成
/// （相当常见），换 UA 后带旧验证器再请求照样回 **304** ⇒ 我们短路 parse/reconcile，
/// **新格式永远拿不到**，用户只看到「无变化」且无从排查。per-sub UA 那一级已由 [`ua_changed`]
/// 在 `subscription_update` 里收口；全局这一级此前**无任何消费/清理点**（全仓实证），
/// 于是「改了全局 UA 仍恒 304」是一条完全没人管的腿。
///
/// # 射程为什么不是「全部订阅一把清」
///
/// 判据是**生效 UA 是否变**，不是「全局键是否变」：带 per-sub `userAgent` 覆盖的订阅，其生效 UA
/// 由第一级决定（见 [`resolve_subscription_ua`]），全局怎么改都不影响它 ⇒ 它的验证器仍然有效，
/// 清掉只会白扔一次条件 GET、把下次更新变成全量下载。所以逐订阅按 `per-sub ?? 全局` 折算前后两值再比。
///
/// 归一口径与 [`pick_ua`] 一致：`None` / `""` / 纯空白三者互相之间**不算变更**（用户把设置框清空
/// 再存回，不该把全部订阅的验证器扔掉）。
pub(crate) fn invalidate_validators_on_global_ua_change(
    old_cfg: &Value,
    new_cfg: &mut Value,
) -> usize {
    let old_global = pick_ua(old_cfg.get(SUBSCRIPTION_USER_AGENT_KEY));
    let new_global = pick_ua(new_cfg.get(SUBSCRIPTION_USER_AGENT_KEY));
    // 全局键没动 → 任何订阅的生效 UA 都不可能因此变。早退，零遍历、零改动。
    if old_global == new_global {
        return 0;
    }
    let Some(arr) = new_cfg
        .get_mut("subscriptions")
        .and_then(Value::as_array_mut)
    else {
        return 0;
    };
    let mut cleared = 0usize;
    for sub in arr.iter_mut() {
        // 生效 UA 折算：per-sub 优先（`resolve_subscription_ua` 第一级），缺省才回落全局。
        let per_sub = pick_ua(sub.get("userAgent"));
        if per_sub.is_some() {
            continue; // per-sub 覆盖 → 生效 UA 与全局无关，验证器仍有效
        }
        // 计数只算「真有验证器被扔掉」的那些，日志才不会谎报条数。
        let had = sub.get("etag").is_some() || sub.get("lastModified").is_some();
        set_or_remove(sub, "etag", None);
        set_or_remove(sub, "lastModified", None);
        if had {
            cleared += 1;
        }
    }
    cleared
}

/// 上游 `SUBSCRIPTION_UPDATE`：更新订阅元数据（按 id）。
///
/// **前端整体替换该记录**（`SubDialog` 用 `{...base, …}` 回传），故 etag/lastModified 等后端字段
/// 靠 spread 幸存 —— 唯独 UA 变更必须主动作废验证器，见 [`ua_changed`]。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn subscription_update(
    app: AppHandle,
    state: State<'_, AppRuntime>,
    subscription: Value,
) -> ApiResponse<()> {
    let id = subscription
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_string);
    let id = match id {
        Some(i) => i,
        None => return ApiResponse::err("subscription.id required"),
    };
    let mut subscription = subscription;
    match state.config().update(|cfg| {
        let Some(idx) = cfg
            .get("subscriptions")
            .and_then(Value::as_array)
            .and_then(|arr| {
                arr.iter()
                    .position(|s| s.get("id").and_then(Value::as_str) == Some(&id))
            })
        else {
            return Decision::Skip(Err(format!("订阅不存在: {id}")));
        };
        let arr = cfg
            .get_mut("subscriptions")
            .and_then(Value::as_array_mut)
            .expect("subscription index came from the same array");
        if ua_changed(&arr[idx], &subscription) {
            // UA 换了 = 响应变体可能整个换掉 → 旧验证器作废，下次走全量 GET。
            set_or_remove(&mut subscription, "etag", None);
            set_or_remove(&mut subscription, "lastModified", None);
        }
        arr[idx] = subscription;
        Decision::Write(Ok(()))
    }) {
        Ok((Ok(()), Some(cfg))) => {
            broadcast_config_changed(&app, &cfg);
            ok_void()
        }
        Ok((Err(error), None)) => ApiResponse::err(error),
        Ok(_) => unreachable!("subscription_update decision and persistence must agree"),
        Err(e) => ApiResponse::err(format!("{e}")),
    }
}

/// 删订阅的纯 `Value` 变换（订阅本身 + 其下全部节点 + 悬挂选中置 null）。
///
/// 返回 `Err(())` = 订阅不存在（`subscriptions` 数组在但无此 id；命令层报 err）。`subscriptions` 字段整体缺失
/// → 视为无副作用的 `Ok`（对齐原命令：`if let Some(arr)` 直接跳过、不报错）。
///
/// A7：选中节点落在被删订阅下 → 该 id 从 servers 消失 → `selectedServerId` 置 `DIRECT_SERVER_ID` 哨兵
/// （**绝不裸 null**）。上游 删订阅置 null 后由 generate 视 null=direct；上游 `generate.rs:219` 对
/// **非哨兵 null** 报 `Selected server not found`（→ 删订阅后下次热切换必失败），故置显式 direct 哨兵达成
/// 等价的「直连」终态且不触发该回归。命令层落盘后用 `selected_exit_changed(old, new)` 判失效。
fn apply_subscription_delete(cfg: &mut Value, subscription_id: &str) -> Result<(), ()> {
    // 删订阅本身。
    if let Some(arr) = cfg.get_mut("subscriptions").and_then(Value::as_array_mut) {
        if let Some(idx) = arr
            .iter()
            .position(|s| s.get("id").and_then(Value::as_str) == Some(subscription_id))
        {
            arr.remove(idx);
        } else {
            return Err(());
        }
    }
    // 删该订阅下全部节点。
    if let Some(arr) = cfg.get_mut("servers").and_then(Value::as_array_mut) {
        arr.retain(|s| s.get("subscriptionId").and_then(Value::as_str) != Some(subscription_id));
    }
    // 选中被删 → 置 direct 哨兵（订阅删除路径：直连终态，对齐 上游 删订阅 null→direct 语义，
    // 但用哨兵避开 generate 对裸 null 的 `Selected server not found` 回归）。
    let selected_gone = cfg
        .get("selectedServerId")
        .and_then(Value::as_str)
        .map(|sid| {
            cfg.get("servers")
                .and_then(Value::as_array)
                .map(|arr| {
                    !arr.iter()
                        .any(|s| s.get("id").and_then(Value::as_str) == Some(sid))
                })
                .unwrap_or(true)
        })
        .unwrap_or(false);
    if selected_gone {
        if let Some(obj) = cfg.as_object_mut() {
            // 绝不裸 null（避免 generate.rs `Selected server not found` 回归）：置 direct 哨兵 = 显式直连。
            obj.insert("selectedServerId".to_string(), json!(DIRECT_SERVER_ID));
        }
    }
    Ok(())
}

/// 上游 `SUBSCRIPTION_DELETE`：删除订阅 + 其下全部节点 + 修选中（删选中 → null）。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn subscription_delete(
    app: AppHandle,
    state: State<'_, AppRuntime>,
    subscription_id: String,
) -> ApiResponse<()> {
    match state.config().update_deferred_cleanup(|cfg| {
        let old_selected = cfg
            .get("selectedServerId")
            .and_then(Value::as_str)
            .map(str::to_string);
        if apply_subscription_delete(cfg, &subscription_id).is_err() {
            return Decision::Skip(Err(format!("订阅不存在: {subscription_id}")));
        }
        Decision::Write(Ok(old_selected))
    }) {
        Ok((Ok(old_selected), Some(cfg))) => {
            broadcast_config_changed(&app, &cfg);
            // A7：删订阅令选中节点从列表消失 → selectedServerId 变 null = 出口变 → 作废旧出口解锁探测缓存
            // （否则解锁角标最长陈旧 30min）。选中不属该订阅（仍存活）→ 出口不动、不失效。
            if selected_exit_changed(
                old_selected.as_deref(),
                cfg.get("selectedServerId").and_then(Value::as_str),
            ) {
                let sink = BroadcastSink::new(&app);
                let running = state.proxy().status().running;
                state.unlock().invalidate(&sink, running, false);
            }
            ok_void()
        }
        Ok((Err(error), None)) => ApiResponse::err(error),
        Ok(_) => unreachable!("subscription_delete decision and persistence must agree"),
        Err(e) => ApiResponse::err(format!("{e}")),
    }
}

/// 订阅更新成功结果（前端 `updateServers` 契约）。`unchanged`（304 / 内容等价）时 `true`；
/// `user_info`（本次流量/到期）有则透传供前端流量条即时刷新。
fn update_ok(
    added: usize,
    updated: usize,
    deleted: usize,
    unchanged: bool,
    user_info: Option<&Value>,
) -> Value {
    let mut v = json!({
        "success": true,
        "addedServers": added,
        "updatedServers": updated,
        "deletedServers": deleted,
        "unchanged": unchanged,
    });
    if let Some(ui) = user_info {
        v["userInfo"] = ui.clone();
    }
    v
}

/// 订阅更新的业务失败态（`success:false` + error，信封仍 ok —— 对齐旧 stub 与前端「读 data.success」）。
fn update_failure(error: impl Into<String>) -> Value {
    json!({
        "success": false,
        "addedServers": 0,
        "updatedServers": 0,
        "deletedServers": 0,
        "error": error.into(),
    })
}

/// 把订阅拉取层已经判定好的结构化错误字段复制到更新结果/事件帧。
///
/// `message` 只承担脱敏诊断；渲染端应优先按 `errorKind` 取 i18n 文案，`httpStatus` 只给 HTTP 类
/// 插值。字段复制收在一处，避免手动更新终态与后台调度事件再次出现「一条有分类、一条只剩字符串」的漂移。
pub(crate) fn copy_subscription_error_metadata(source: &Value, target: &mut Value) {
    if let Some(kind) = source.get("errorKind").and_then(Value::as_str) {
        target["errorKind"] = json!(kind);
    }
    if let Some(status) = source.get("httpStatus").and_then(Value::as_u64) {
        target["httpStatus"] = json!(status);
    }
}

/// [`fetch_parse_resolve`] 的分类失败 → `updateServers` 业务失败信封。
///
/// 旧实现只抄 `message`，在这里丢掉 `errorKind/httpStatus`，导致后续进度徽标、订阅 tab tooltip 与
/// 自动更新 toast 都只能展示 reqwest 的笼统字符串。分类必须在抛出点一路保留，不能让 UI 回头猜文案。
fn update_classified_failure(classified: &Value) -> Value {
    let mut result = update_failure(
        classified
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("订阅更新失败"),
    );
    copy_subscription_error_metadata(classified, &mut result);
    result
}

/// 订阅「经代理更新」生效求值（上游 `resolveSubscriptionViaProxy`，`shared/subscription-proxy.ts`）。
///
/// 全局三态 `subscriptionProxyPolicy`（默认 `follow`）：
/// - `proxy`：所有订阅强制经代理，**忽略** per-sub；
/// - `direct`：所有订阅强制直连，**忽略** per-sub；
/// - `follow`（默认/未知值）：按 per-sub `updateViaProxy` 决定（默认 false=直连）。
pub(crate) fn resolve_subscription_via_proxy(
    policy: Option<&str>,
    sub_enabled: Option<bool>,
) -> bool {
    match policy {
        Some("proxy") => true,
        Some("direct") => false,
        _ => sub_enabled == Some(true), // follow（默认）
    }
}

/// 从整 config + 单订阅 Value 求值本次拉取是否经代理（C14 接线点）。
///
/// 读全局 `subscriptionProxyPolicy` 与该订阅 `updateViaProxy`，委托 [`resolve_subscription_via_proxy`]。
/// 独立成函数以便纯单测覆盖「配置键提取 + 三态决策」，无需真拉订阅（真经代理出口属真机门）。
fn want_proxy_for_sub(cfg: &Value, sub: &Value) -> bool {
    let policy = cfg.get("subscriptionProxyPolicy").and_then(Value::as_str);
    let sub_enabled = sub.get("updateViaProxy").and_then(Value::as_bool);
    resolve_subscription_via_proxy(policy, sub_enabled)
}

/// 全局策略是否**显式强制**经代理（`subscriptionProxyPolicy == "proxy"`）。
///
/// 与 [`want_proxy_for_sub`] 的区别是「意图强度」：`follow` 下的 `updateViaProxy=true` 是**偏好**
/// （上游 与本仓一致：端口不可用就退直连，自举友好）；`proxy` 是用户在设置页显式勾的
/// **全局强制**——它的语义是「订阅地址不许明文出网」。这两者不能共用一个静默回退。
fn proxy_policy_is_forced(cfg: &Value) -> bool {
    cfg.get("subscriptionProxyPolicy").and_then(Value::as_str) == Some("proxy")
}

/// 本次拉取的订阅 UA（三级优先级，**契约单一真值**）：
/// `subscription.userAgent` → 全局 `config.subscriptionUserAgent` → `None`（交
/// [`fetch_parse_resolve`] 落 `default_subscription_user_agent`）。
///
/// 契约声明见 `ui/src/contracts/types.ts`（per-sub 字段注释 + `subscriptionUserAgent` 字段）；
/// 上游 两条路径同式（`subscription-handlers.ts` 手动更新 + `SubscriptionScheduler` 自动更新，
/// 均为 `sub.userAgent ?? config.subscriptionUserAgent`）。
///
/// 此前后端**只读 per-sub**、全局键零消费 → 全局 UA 是死键：机场按 UA 下发不同格式（clash/sing-box/
/// base64），用户设了全局 UA 却不生效 → 拿到错格式或 0 节点。
///
/// # 与 TS `??` 的**已知差异**（登记，不是「对齐」）
///
/// 契约注释与 上游 写的都是 `sub.userAgent ?? config.subscriptionUserAgent`——**nullish** 合并：
/// 显式 `""` 是非 nullish 值，会**胜出**并把空 UA 发出去。本实现用的是 `trim().is_empty()` 过滤
/// = **falsy** 语义：空串/纯空白一律视同未设，继续向下一级回落。
///
/// 差异只在「per-sub 显式存了空串」这一格，且本实现的行为更可取：把 `User-Agent: ` 空值真发出去，
/// 机场侧多半按未知客户端处理 → 拿到错格式或 0 节点，而用户在对话框里清空输入框的意图显然是
/// 「不要 per-sub 覆盖」而非「发一个空 UA」。前端 `SubDialog` 也确实把空输入折成 `undefined`
/// （`ua.trim() || undefined`），故这一格在真实链路上几乎不可达 —— 但**导入的配置/手改的 json
/// 可以造出它**，所以行为差异必须写在这里，而不是自称「对齐 TS falsy 语义」（TS 那边是 `??`，
/// 不是 `||`，原注释名不副实）。差异已同步登记在 `ui/src/contracts/types.ts` 的 `userAgent` 字段注释。
fn resolve_subscription_ua(cfg: &Value, sub: &Value) -> Option<String> {
    pick_ua(sub.get("userAgent")).or_else(|| pick_ua(cfg.get(SUBSCRIPTION_USER_AGENT_KEY)))
}

/// 上游 `SUBSCRIPTION_UPDATE_SERVERS`：拉取订阅 + 对账节点集（net-stack）+ 持久化。
///
/// **已接线**（此前为「HTTP 栈依赖未拍板」占位；该结论已过时——`runtime/http.rs` 的 `HttpRuntime`
/// = reqwest+rustls，已实现 net-stack [`HttpClient`](polaris_net_stack::safe_redirect::HttpClient)，`subscription_preview` 两函数之外即在用）：
///
/// 1. 取该订阅的 `url`/`userAgent`，并按**全局三态策略** `subscriptionProxyPolicy` × per-sub
///    `updateViaProxy` 求值本次经代理与否（C14；[`want_proxy_for_sub`]）；
/// 2. 经 [`HttpRuntime`] + [`fetch_parse_resolve`]
///    （SSRF 逐跳 guard + 体积闸 + 超时 + 手动重定向，与 preview **同一** 拉取层）拉取；
/// 3. [`SubscriptionParseExecutor`] 解析（节点带本订阅 id）；
/// 4. **reconcile**（[`reconcile_subscription_servers`]）：五元组指纹（protocol/address/port/cred/network，
///    **剔除 name**，见 [`node_fingerprint`]）稳定对账——
///    命中保留原 id+createdAt（选中节点/用户身份不丢）、新增补入、消失删除；他订阅/自建节点不动；
/// 5. `save_full` 持久化 + 广播 `config:changed`（汇流点自动热切换判定）。
///
/// **空集/拉取失败走 merge-only**（不 permanent 删存量节点）：拉取半通或解析 0 节点时**不对账删除**，
/// 如实报业务失败（对齐旧占位注释的破坏性告警——差集不可信时绝不删节点）。
#[tauri::command]
pub async fn subscription_update_servers(
    app: AppHandle,
    state: State<'_, AppRuntime>,
    subscription_id: String,
) -> Result<ApiResponse<Value>, ()> {
    // 命令与 scheduler 共用同一份拉取+对账+落盘核心（唯一生产路径，§K7.1）。
    Ok(ApiResponse::ok(
        perform_subscription_update(&app, state.inner(), &subscription_id).await,
    ))
}

/// 选择本次拉取的 HTTP client + 是否**实际**经代理。返回 `(client, via_effective)`。
///
/// `want_proxy` 且核在跑且订阅专用 socks 口有效 → 经 **subscription-update-in** 借道；
/// 该入口先远端解析、拒绝私网目标，再把已审查 IP 钉到既有更新出口。否则直连（不假装）。
///
/// **scheme 已对齐**（原 review-queue 条目 `sub-update-in-scheme`，已闭合）：改用
/// [`HttpRuntime::via_local_socks_proxy`]（`socks5://`），对齐 上游 `UpdateNetwork` 的
/// `proxyRules: socks5://127.0.0.1:<subscription-update-in>`。此前用的是 `via_local_proxy`（`http://`），而
/// 专用入口是 sing-box `type:"socks"` 入站 → 明文 HTTP 打 socks 服务器首字节就对不上、必断连
/// → 本条链**恒失败**。`icon_cache` 同一口同一错，一并改。
///
/// **注意别改回共用一个构造器**：`speedtest` 的探测池 `probe-in-k` 是纯 `http` 入站，socks5 打不通；
/// 两个 scheme 各有其入站，见 [`HttpRuntime::via_local_socks_proxy`] 文档的入站对照表。
/// 协议握手由 `runtime::http` 的 `via_local_socks_proxy_really_speaks_socks5_to_a_socks_inbound`
/// 单测钉住；专用入口的真核 resolve/reject/pin 顺序由 config-engine integration fixture 钉住。
fn backend_subscription_route_uses_proxy(cfg: &Value) -> bool {
    serde_json::from_value::<UserConfig>(cfg.clone())
        .is_ok_and(|typed| subscription_update_route_uses_proxy(&typed))
}

fn select_fetch_client(
    state: &AppRuntime,
    cfg: &Value,
    want_proxy: bool,
) -> (Arc<HttpRuntime>, bool) {
    // The listener existing is not enough: the generated route may deliberately terminate at
    // direct (direct mode/sentinel, block management exemption, empty selector, mesh fallback).
    // Only report `via_effective=true` when both ingress and its backend-owned route are proxied.
    if want_proxy && backend_subscription_route_uses_proxy(cfg) {
        let st = state.proxy().status();
        if st.running && st.subscription_update_in_port != 0 {
            if let Ok(c) = HttpRuntime::via_local_socks_proxy(st.subscription_update_in_port) {
                return (Arc::new(c), true);
            }
        }
    }
    (state.http().clone(), false)
}

/// SubscriptionFetchError → 前端分类错误 Value（`{ok:false, errorKind, message, httpStatus?}`）。
fn classify_fetch_error(e: &polaris_net_stack::subscription::SubscriptionFetchError) -> Value {
    // SubscriptionErrorKind serde 小写字面量 = TS errorKind，逐字对齐。
    let kind = serde_json::to_value(e.kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string());
    let mut out = json!({ "ok": false, "errorKind": kind, "message": e.message });
    if let Some(status) = e.http_status {
        out["httpStatus"] = json!(status);
    }
    out
}

/// provider 子拉取失败的**永久性分类**（`SubscriptionFetchError` → [`ProviderFetchError`]）。
///
/// 判据 = 「重试还会不会变好」，不是「错得严不严重」：
/// - **permanent**：4xx（404 删了 / 403 撤权 / 410 gone）、SSRF guard 拒绝、URL 非法/协议不支持
///   —— 这些下一轮、下一天都还是一样。
/// - **transient**：超时、连不上、5xx、429（限流，等等就好）、正文解析失败（可能是 WAF 错误页）。
///
/// 为什么分类必须在这一层：`SubscriptionErrorKind` 与 `http_status` 只有拉取层有；net-stack 的编排
/// 函数只拿到一个 `String`，在那里靠子串猜状态码是必然漂移的假判据。分类结果决定
/// **该 provider 名下的存量节点本轮删不删**（见 [`ProviderFetchError`] 文档）。
fn classify_provider_fetch_error(
    e: &polaris_net_stack::subscription::SubscriptionFetchError,
) -> ProviderFetchError {
    // 429 = 限流：状态码在 4xx 段但语义是「稍后再来」→ 归 transient（否则一次限流就删光节点）。
    let permanent_status = matches!(e.http_status, Some(s) if (400..500).contains(&s) && s != 429);
    // SSRF guard 拒绝（内网/回环/重定向超限）与非 http(s) 协议：URL 本身的问题，重试不转好。
    let permanent_kind = matches!(
        e.kind,
        SubscriptionErrorKind::Ssrf | SubscriptionErrorKind::Scheme
    );
    if permanent_status || permanent_kind {
        ProviderFetchError::permanent(e.message.clone())
    } else {
        ProviderFetchError::transient(e.message.clone())
    }
}

// ── 订阅更新进度（`EVENT_SUBSCRIPTION_UPDATE_PROGRESS`）──────────────────────────
//
// 形态判据（为什么是**阶段名 + provider 计数**，不是百分比）：
//
// 百分比要求「已收字节 / 总字节」。总字节这一半是有的（`content-length` 响应头在
// `MinimalResponse::headers` 里，体积闸 `subscription.rs:421` 正在读它）——**分子这一半结构上不存在**：
// `HttpClient::fetch` 返回的是**已缓冲完的 `MinimalResponse.body: Vec<u8>`**（SSRF/重定向/体积三道
// guard 都建立在「整体收完再判」上），调用方拿到它时下载已经结束，中途没有任何可数的字节流。
// 这与同仓 `commands/rules::download_with_progress` 判 `percent: null` 是**同一条**结论
// （那里逐字写着「宁可没有进度条，也不编一个匀速爬升的假条」），本处照同一口径。
//
// 且即便把传输层改成流式，百分比对本场景仍是错的呈现：订阅正文典型几十 KB，耗时几乎全在 TTFB
// （DNS + TLS + 机场服务端现场生成配置），进度条会在 0% 上冻十几秒再瞬间到 100%——比没有更误导。
//
// 真正有量的地方只有一处：Clash `proxy-providers` 的**并发子拉取**（可数、每个最长 15s），
// 那里按真实完成数给 `done/total`。其余阶段给阶段名。

/// 进度落点（注入式：生产广播给渲染端，单测用记录器 → 帧序可逐条对账）。
///
/// 抽 trait 而不是直接在发射点写 `broadcast(app, …)`：本仓未引 `tauri::test`，没有 `AppHandle`
/// 就无法在单测里证伪任何一帧。同 `commands/rules::ProgressSink` 的先例。
pub(crate) trait UpdateProgressSink: Send + Sync {
    fn emit(&self, frame: Value);

    /// 主正文已拉完、同步解析即将开始。旧更新进度无需展示这一细阶段；原子创建任务覆盖它，
    /// 让 renderer 能区分仍可中断的网络与解析腿。
    fn primary_fetched(&self) {}
}

/// 生产落点：补上 `subscriptionId` 后广播给全部窗口。
struct BroadcastUpdateProgress {
    app: AppHandle,
    subscription_id: String,
}

impl UpdateProgressSink for BroadcastUpdateProgress {
    fn emit(&self, mut frame: Value) {
        if let Some(obj) = frame.as_object_mut() {
            obj.insert("subscriptionId".to_string(), json!(self.subscription_id));
        }
        broadcast(&self.app, EVENT_SUBSCRIPTION_UPDATE_PROGRESS, frame);
    }
}

/// 由 [`perform_subscription_update_inner`] 的返回值派生**终态帧**（纯函数）。
///
/// 输入就是前端 `updateServers` 拿到的那个业务结果 —— 终态帧与它同源，故不可能出现
/// 「toast 说成功、订阅栏挂着失败」这种两个真值源打架的形态。
fn terminal_progress_frame(result: &Value) -> Value {
    if result.get("success").and_then(Value::as_bool) != Some(true) {
        let mut frame = json!({
            "phase": "failed",
            "error": result.get("error").and_then(Value::as_str).unwrap_or_default(),
        });
        copy_subscription_error_metadata(result, &mut frame);
        return frame;
    }
    if result.get("unchanged").and_then(Value::as_bool) == Some(true) {
        return json!({ "phase": "unchanged" });
    }
    let count = |k: &str| result.get(k).and_then(Value::as_u64).unwrap_or(0);
    json!({
        "phase": "done",
        "added": count("addedServers"),
        "updated": count("updatedServers"),
        "deleted": count("deletedServers"),
    })
}

/// 单订阅拉取 + 对账 + 落盘 + 元数据回写（items 2/3/6/7）。**命令与 scheduler 共用**。
///
/// 返回业务结果 Value（`{success, addedServers, updatedServers, deletedServers, unchanged?, userInfo?}`
/// 或 `{success:false, error}`）；信封由调用方包 ok（前端读 `data.success`）。
///
/// 本函数是**薄壳**：只负责「起手一帧 + 终态一帧」，真实现全在
/// [`perform_subscription_update_inner`]。这样拆的唯一理由是**终态必达**——内层有七八条
/// `return update_failure(...)` 早退，逐条在前面补一句 emit 是能写对，但下一个人新加一条早退时
/// 不会想起来补，订阅栏就会永远挂在「更新中」。派生自返回值 ⇒ 结构上漏不掉。
pub(crate) async fn perform_subscription_update(
    app: &AppHandle,
    state: &AppRuntime,
    subscription_id: &str,
) -> Value {
    let sink: Arc<dyn UpdateProgressSink> = Arc::new(BroadcastUpdateProgress {
        app: app.clone(),
        subscription_id: subscription_id.to_string(),
    });
    // 起手即报「拉取中」：这一帧之前的活（load_full / UA 求值）是微秒级，不值一个独立阶段。
    sink.emit(json!({ "phase": "fetching" }));
    let result = perform_subscription_update_inner(app, state, subscription_id, &sink).await;
    sink.emit(terminal_progress_frame(&result));
    result
}

/// 真实现。**任何早退都不必自己发终态帧**——外壳按返回值派生（见
/// [`perform_subscription_update`] 文档）。
async fn perform_subscription_update_inner(
    app: &AppHandle,
    state: &AppRuntime,
    subscription_id: &str,
    sink: &Arc<dyn UpdateProgressSink>,
) -> Value {
    let update_started = std::time::Instant::now();
    let operation_deadline = update_started + SUBSCRIPTION_OPERATION_TIMEOUT;
    // 1) 取订阅元数据（URL + per-sub UA/viaProxy + 条件 GET 验证器）。
    let initial_config_started = std::time::Instant::now();
    let cfg = match state.config().load_full() {
        Ok(c) => c,
        Err(e) => return update_failure(format!("{e}")),
    };
    let initial_config_ms = initial_config_started.elapsed().as_millis();
    let Some(sub) = find_subscription(&cfg, subscription_id) else {
        return update_failure(format!("订阅不存在: {subscription_id}"));
    };
    let url = match sub
        .get("url")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        Some(u) => u.to_string(),
        None => return update_failure("订阅缺少 URL"),
    };
    let user_agent = resolve_subscription_ua(&cfg, &sub);
    let want_proxy = want_proxy_for_sub(&cfg, &sub);
    // 条件 GET：provider 型订阅豁免（主正文 304 掩盖 provider 独立变化）；否则带上次验证器。
    let conditional = if sub.get("hasProviders").and_then(Value::as_bool) == Some(true) {
        None
    } else {
        Some(Conditional {
            etag: sub.get("etag").and_then(Value::as_str).map(str::to_string),
            last_modified: sub
                .get("lastModified")
                .and_then(Value::as_str)
                .map(str::to_string),
        })
    };

    // 2) 拉取 + 解析 + provider 编排。
    let (client, via_effective) = select_fetch_client(state, &cfg, want_proxy);

    // 2a) **显式强制经代理却经不了 → fail-closed，绝不静默直连**。
    //
    // `subscriptionProxyPolicy="proxy"` 是用户在设置页显式勾的全局强制，语义 = 「订阅地址不许
    // 明文出网」。核未跑 / `subscription-update-in` 口为 0 时静默回退直连，会把订阅 URL 的 DNS 查询与 TLS SNI
    // 直接暴露给本地网络 —— 而且 `result` 里没有任何一个字段能让用户看出这次是明文拉的
    // （`{success:true, addedServers:…}` 与经代理成功**逐字无别**）。这不是「降级 UX」，是把用户
    // 明确要求避开的那件事悄悄做了。
    //
    // 为什么这里与 上游 分叉（**刻意**）：上游的回退发生在它只有 per-sub `viaProxy` 偏好的路径上
    // （`SubscriptionService:690-698`），那是「偏好落空 → 退直连」，合理；本仓的三态策略多出一个
    // **显式强制**档，对它照抄回退就是把「强制」实现成了「建议」。`follow` 档（含 per-sub
    // `updateViaProxy=true`）**保持**静默回退不变，自举友好不受影响。
    if !via_effective && proxy_policy_is_forced(&cfg) {
        let st = state.proxy().status();
        log::warn!(
            "订阅 {subscription_id} 更新中止：全局策略强制经代理，但代理不可用\
             （running={}, subscription_update_in_port={}）——不静默直连，以免订阅地址明文外泄",
            st.running,
            st.subscription_update_in_port
        );
        return update_failure(
            "全局策略要求「所有订阅经代理更新」，但当前代理不可用，或订阅专用入口的后端路由实际落到直连。\
             已中止本次更新以避免订阅地址明文外泄；请先启动代理，或把订阅代理策略改为「跟随」/「直连」。",
        );
    }

    let lookup = SystemDnsLookup;
    let pipeline = fetch_parse_resolve(
        client,
        &lookup,
        &url,
        subscription_id,
        via_effective,
        user_agent.as_deref(),
        conditional.as_ref(),
        Some(sink),
        None,
        Arc::clone(state.subscription_parse()),
        operation_deadline,
    );
    let outcome = match tokio::time::timeout_at(operation_deadline.into(), pipeline).await {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(err_value)) => return update_classified_failure(&err_value),
        Err(_) => return update_classified_failure(&operation_timeout_error()),
    };
    let network_ms = update_started.elapsed().as_millis();

    // 3) 304 无变化 → 仅刷元数据（lastUpdated + 验证器），不 reconcile、不广播（零节点扰动、不断流）。
    if outcome.not_modified {
        let apply_started = std::time::Instant::now();
        let transaction_started = std::time::Instant::now();
        let result = state.config().update(|cfg| {
            let Some(s) = find_subscription_mut(cfg, subscription_id) else {
                return Decision::Skip(Err(format!("订阅不存在: {subscription_id}")));
            };
            s["lastUpdated"] = json!(current_iso());
            if let Some(e) = &outcome.etag {
                s["etag"] = json!(e);
            }
            if let Some(lm) = &outcome.last_modified {
                s["lastModified"] = json!(lm);
            }
            Decision::Write(Ok(()))
        });
        let transaction_ms = transaction_started.elapsed().as_millis();
        match result {
            Ok((Ok(()), Some(_))) => {}
            Ok((Err(error), None)) => return update_failure(error),
            Ok(_) => unreachable!("not-modified subscription transaction must be consistent"),
            Err(e) => return update_failure(format!("{e}")),
        }
        log::info!(
            "subscription reconcile timing: outcome=not_modified initial_config_ms={initial_config_ms} network_ms={network_ms} config_transaction_ms={transaction_ms} reconcile_total_ms={} total_ms={}",
            apply_started.elapsed().as_millis(),
            update_started.elapsed().as_millis()
        );
        return update_ok(0, 0, 0, true, None);
    }

    // 4) 空集（非 partial）→ merge-only 失败：0 节点极可能拉取半通/解析失败，permanent 删不可逆。
    if outcome.servers.is_empty() && !outcome.partial {
        let detail = outcome
            .warnings
            .first()
            .cloned()
            .unwrap_or_else(|| "解析得到 0 个可用节点".to_string());
        return update_failure(detail);
    }

    // 5) reconcile（最新 config；partial → merge_only 防穿仓）。
    //
    // 网络腿到此为止，余下是对账 + 落盘 + 广播（广播可能触发内核热切换/重启）。单独报一个阶段是因为
    // 它与「拉取中」的失败含义完全不同：卡在这里是本地磁盘/配置问题，不是机场不通。
    sink.emit(json!({ "phase": "reconciling" }));
    let apply_started = std::time::Instant::now();
    let transaction_started = std::time::Instant::now();
    // 拉取期间可能已有别的写入落盘；对账、删除 journal 与保存必须在同一写临界区，以最新配置为基准。
    // 这里统一走 deferred-cleanup 形态：无删除时不会生成 journal，有删除时则保证旧核退出前不清理资产。
    let transaction = state.config().update_deferred_cleanup(|cfg| {
        if find_subscription(cfg, subscription_id).is_none() {
            return Decision::Skip(Err(format!("订阅不存在: {subscription_id}")));
        }
        let old_selected = cfg
            .get("selectedServerId")
            .and_then(Value::as_str)
            .map(str::to_string);
        let user_info = outcome.user_info.clone();
        let recon = reconcile_subscription_servers(
            cfg,
            subscription_id,
            outcome.servers,
            outcome.partial,
            &outcome.failed_providers,
        );
        let content_changed = recon.added > 0 || recon.updated > 0 || recon.deleted > 0;

        // 6) 元数据回写到 sub 记录（lastUpdated + userInfo + 验证器 + hasProviders）。
        write_sub_metadata(
            cfg,
            subscription_id,
            user_info.as_ref(),
            outcome.etag.as_deref(),
            outcome.last_modified.as_deref(),
            outcome.has_providers,
        );
        Decision::Write(Ok((
            recon,
            old_selected,
            user_info,
            content_changed,
            outcome.partial,
        )))
    });
    let transaction_ms = transaction_started.elapsed().as_millis();
    let (recon, old_selected, user_info, content_changed, partial, cfg) = match transaction {
        Ok((Ok((recon, old_selected, user_info, content_changed, partial)), Some(cfg))) => (
            recon,
            old_selected,
            user_info,
            content_changed,
            partial,
            cfg,
        ),
        Ok((Err(error), None)) => return update_failure(error),
        Ok(_) => unreachable!("subscription reconcile decision and persistence must agree"),
        Err(e) => return update_failure(format!("{e}")),
    };

    // 7) L-5：200 但节点集内容等价（!content_changed && !partial）→ 仅刷元数据 return unchanged，
    //    **不广播**（避免字节级无变化也 switch_mode 断流）。
    if !content_changed && !partial {
        log::info!(
            "subscription reconcile timing: outcome=unchanged initial_config_ms={initial_config_ms} network_ms={network_ms} config_transaction_ms={transaction_ms} reconcile_total_ms={} total_ms={}",
            apply_started.elapsed().as_millis(),
            update_started.elapsed().as_millis()
        );
        return update_ok(0, 0, 0, true, user_info.as_ref());
    }

    // 8) 内容变 / partial → 广播（汇流点自动热切换）+ 出口变则作废解锁缓存。
    broadcast_config_changed(app, &cfg);
    if selected_exit_changed(
        old_selected.as_deref(),
        cfg.get("selectedServerId").and_then(Value::as_str),
    ) {
        let sink = BroadcastSink::new(app);
        let running = state.proxy().status().running;
        state.unlock().invalidate(&sink, running, false);
    }
    log::info!(
        "subscription reconcile timing: outcome=changed initial_config_ms={initial_config_ms} network_ms={network_ms} config_transaction_ms={transaction_ms} reconcile_total_ms={} total_ms={}",
        apply_started.elapsed().as_millis(),
        update_started.elapsed().as_millis()
    );
    update_ok(
        recon.added,
        recon.updated,
        recon.deleted,
        false,
        user_info.as_ref(),
    )
}

/// 按 id 取订阅记录（只读克隆）。
fn find_subscription(cfg: &Value, id: &str) -> Option<Value> {
    cfg.get("subscriptions")
        .and_then(Value::as_array)
        .and_then(|arr| {
            arr.iter()
                .find(|s| s.get("id").and_then(Value::as_str) == Some(id))
        })
        .cloned()
}

/// 按 id 取订阅记录可变引用（元数据回写）。
fn find_subscription_mut<'a>(cfg: &'a mut Value, id: &str) -> Option<&'a mut Value> {
    cfg.get_mut("subscriptions")
        .and_then(Value::as_array_mut)?
        .iter_mut()
        .find(|s| s.get("id").and_then(Value::as_str) == Some(id))
}

/// 200 路径回写 sub 元数据：lastUpdated + userInfo（有则写）+ etag/lastModified（**无条件**，L-3：
/// 服务端撤 validator 后不残留旧值致伪 304）+ hasProviders。
fn write_sub_metadata(
    cfg: &mut Value,
    id: &str,
    user_info: Option<&Value>,
    etag: Option<&str>,
    last_modified: Option<&str>,
    has_providers: bool,
) {
    let Some(s) = find_subscription_mut(cfg, id) else {
        return;
    };
    s["lastUpdated"] = json!(current_iso());
    if let Some(ui) = user_info {
        s["userInfo"] = ui.clone();
    }
    set_or_remove(s, "etag", etag);
    set_or_remove(s, "lastModified", last_modified);
    s["hasProviders"] = json!(has_providers);
}

/// 置键（`Some`）或删键（`None`）——L-3 无条件写验证器（含清除）。
fn set_or_remove(obj: &mut Value, key: &str, val: Option<&str>) {
    if let Some(o) = obj.as_object_mut() {
        match val {
            Some(v) => {
                o.insert(key.to_string(), json!(v));
            }
            None => {
                o.remove(key);
            }
        }
    }
}

/// 订阅节点对账结果计数。
struct ReconcileOutcome {
    added: usize,
    updated: usize,
    deleted: usize,
}

/// 节点稳定指纹（对账键）：`protocol|address|port|cred|network`（**排除 name**）。
/// 上游 `SubscriptionService.serverFingerprint`。同一物理节点跨拉取指纹一致 → reconcile 命中。
///
/// 排除 name：订阅方常改名/调顺序，用 name 做键会把同一物理节点误判「删旧增新」→ id 抖动、
/// selectedServerId 丢失、本地编辑被清。cred（uuid / password / 嵌套 ss·ssh password / username /
/// wg peerPublicKey）区分同 host:port 并列节点；network 维度区分同 host:port:cred 但传输不同的节点。
///
/// **与 net-stack `server_fingerprint(&ServerConfig)` 是同一公式的 json 侧**——作用于 `Value`（对账两侧
/// 均为 camelCase JSON），由 `reconcile_tests::fingerprint_matches_net_stack_typed` 跨类型等价单测锁定。
fn node_fingerprint(v: &Value) -> String {
    let protocol = v
        .get("protocol")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    let address = v.get("address").and_then(Value::as_str).unwrap_or("");
    let port = v.get("port").and_then(Value::as_u64).unwrap_or(0);
    let network = v
        .get("network")
        .and_then(Value::as_str)
        .unwrap_or("tcp")
        .to_ascii_lowercase();
    let cred = node_cred(v);
    format!("{protocol}|{address}|{port}|{cred}|{network}")
}

/// 凭据落点（上游 `cred` 链）：uuid → password → shadowsocksSettings.password → username →
/// sshSettings.password → wireguardSettings.peerPublicKey，首个非空即取（空串视缺）。
fn node_cred(v: &Value) -> String {
    let pick = |val: Option<&Value>| {
        val.and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    pick(v.get("uuid"))
        .or_else(|| pick(v.get("password")))
        .or_else(|| pick(v.get("shadowsocksSettings").and_then(|s| s.get("password"))))
        .or_else(|| pick(v.get("username")))
        .or_else(|| pick(v.get("sshSettings").and_then(|s| s.get("password"))))
        .or_else(|| {
            pick(
                v.get("wireguardSettings")
                    .and_then(|s| s.get("peerPublicKey")),
            )
        })
        .unwrap_or_default()
}

/// 兜底出口候选选择（上游 `pickViableFallbackExit`，main 侧无 latency → 取首个可用候选）。
///
/// 候选须过可用性谓词——排 subnet-only 组网节点（WG allowInternet:false 带网段 / TS 无 exitNode），
/// 否则重启后公网流量静默走 direct = VPN 语义泄漏（#291）。返回首个「可反序列化 + 承载全隧道 + 可路由」
/// 节点 id；全不可用 → `None`（调用方置 `DIRECT_SERVER_ID` 哨兵 = 显式可见直连，非裸 null）。
///
/// **注**：完整 `isServerComplete` 字段校验属 nodes-servers 域（另有专项）；此处用 config-engine 既有
/// `mesh_node_carries_full_tunnel` + `!is_mesh_node_unroutable` 覆盖 #291 泄漏面（组网节点承载性），
/// 结构完整性以「可反序列化为 ServerConfig」近似。
fn pick_viable_fallback_exit(servers: &[Value]) -> Option<String> {
    for s in servers {
        let Some(id) = s
            .get("id")
            .and_then(Value::as_str)
            .filter(|i| !i.is_empty())
        else {
            continue;
        };
        // 结构完整（可反序列化）+ 非 unroutable + 承载全隧道 → 可作兜底出口。
        if let Ok(sc) = serde_json::from_value::<ServerConfig>(s.clone()) {
            if !is_mesh_node_unroutable(&sc) && mesh_node_carries_full_tunnel(&sc) {
                return Some(id.to_string());
            }
        }
    }
    None
}

/// partial（provider 瞬时失败）时，这个「已下架」的存量节点是否**保留**（provider 级精确 merge-back）。
/// 上游 `SubscriptionService.leftoverToKeep` 1:1。
///
/// 三条规则，顺序即优先级：
/// 1. `failed_providers` 为空 —— 失败 provider 名未知（整订阅级失败兜底）→ **全保留**，退回旧的整订阅
///    merge-only（宁滞留不误删）；
/// 2. 节点无 `providerName`（迁移前存量 / 主正文内联 `proxies` / 非 Clash 订阅）—— 没有归属信息可判，
///    **保守保留**；
/// 3. 否则仅保留**失败** provider 名下的 —— 成功 provider 名下的下架是真下架，正常删除。
///
/// 规则 3 是本函数存在的理由：此前 partial 一律整订阅 merge-only，某个 provider 503 会连带让**成功**
/// provider 名下的真下架节点无限滞留在列表里（且 `deletedServers` 恒 0，前端看不出）。
fn leftover_survives_partial(node: &Value, failed_providers: &[String]) -> bool {
    if failed_providers.is_empty() {
        return true;
    }
    match node
        .get("providerName")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        None => true,
        Some(name) => failed_providers.iter().any(|f| f == name),
    }
}

/// 忽略顶层易变元数据后比较节点内容。旧实现为每个命中节点各深拷贝新旧 JSON 再删 3 个键；大订阅
/// 对账时会复制大量嵌套 TLS/transport 数据。这里直接借用比较，语义仍是“只忽略顶层三键”。
fn node_content_eq(left: &Value, right: &Value) -> bool {
    const VOLATILE: [&str; 3] = ["id", "createdAt", "updatedAt"];
    match (left.as_object(), right.as_object()) {
        (Some(left), Some(right)) => {
            let stable_len = |obj: &serde_json::Map<String, Value>| {
                obj.keys()
                    .filter(|key| !VOLATILE.contains(&key.as_str()))
                    .count()
            };
            stable_len(left) == stable_len(right)
                && left.iter().all(|(key, value)| {
                    VOLATILE.contains(&key.as_str()) || right.get(key) == Some(value)
                })
        }
        _ => left == right,
    }
}

/// 破坏性对账：以拉取的新节点集为准，对本订阅节点做差集（add/update/remove），
/// **他订阅节点与自建节点（subscriptionId 不匹配）一律不动**。
///
/// 命中（指纹一致）：保留原 `id` + `createdAt`（选中节点 id 不失效、用户可见身份不变），
/// 其余字段以新拉取为准。选中节点被删 → `selectedServerId` 置 `pick_viable_fallback_exit ?? DIRECT`
/// 哨兵（**绝不裸 null**，避 generate 回归 + 不静默泄漏，对齐 上游 手动/自动路径 F14 reselect）。
///
/// `merge_only=true`（provider transient 失败）→ **provider 级精确** merge-back（上游
/// `SubscriptionService.leftoverToKeep`，见 [`leftover_survives_partial`]）：只保留「失败 provider 名下 +
/// 无归属」的下架节点，**成功 provider 名下的真下架节点照常删除**。`failed_providers` 为空（失败名未知）
/// → 退回旧的整订阅级 merge-only（全保留、`deleted=0`）。被保留的节点不计入 `deleted`。
fn reconcile_subscription_servers(
    cfg: &mut Value,
    sub_id: &str,
    new_servers: Vec<ServerConfig>,
    merge_only: bool,
    failed_providers: &[String],
) -> ReconcileOutcome {
    use std::collections::{HashMap, VecDeque};

    let new_vals: Vec<Value> = new_servers
        .into_iter()
        .filter_map(|s| serde_json::to_value(s).ok())
        .collect();

    let existing: Vec<Value> = cfg
        .get("servers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    // 分区：本订阅节点 vs 其他（其他原样保留）。
    let (this_sub, mut others): (Vec<Value>, Vec<Value>) = existing
        .into_iter()
        .partition(|s| s.get("subscriptionId").and_then(Value::as_str) == Some(sub_id));

    // 指纹 → 该指纹下**所有**现有节点的 FIFO 队列。指纹（protocol/address/port/cred/network，**不含 name**）
    // 会碰撞：同 uuid 同 host:port 同传输、仅 name/SNI/path 异的 CDN/中转节点常见。此前用 `insert` 只留最后一个
    // → 丢其余 id；且两个同指纹新节点会 `get` 到同一个旧节点 → 复制**同一个** id（重复 id）。
    // 改为保留全部 + 逐个 1:1 消费（`pop_front`），彻底杜绝 id 丢失与重复。
    let mut existing_by_key: HashMap<String, VecDeque<Value>> = HashMap::new();
    for s in this_sub {
        existing_by_key
            .entry(node_fingerprint(&s))
            .or_default()
            .push_back(s);
    }

    let mut reconciled: Vec<Value> = Vec::with_capacity(new_vals.len());
    let (mut added, mut updated) = (0usize, 0usize);
    for mut nv in new_vals {
        let key = node_fingerprint(&nv);
        // 1:1 消费：pop 掉一个已匹配的旧节点，防第二个同指纹新节点复用同一 id。
        let matched = existing_by_key.get_mut(&key).and_then(VecDeque::pop_front);
        if let Some(old) = matched {
            // 命中 → 保留稳定 id + 原 createdAt。
            if let Some(nobj) = nv.as_object_mut() {
                if let Some(oid) = old.get("id").cloned() {
                    nobj.insert("id".to_string(), oid);
                }
                if let Some(created) = old.get("createdAt").cloned() {
                    nobj.insert("createdAt".to_string(), created);
                }
            }
            if !node_content_eq(&nv, &old) {
                updated += 1;
            }
        } else {
            added += 1;
        }
        reconciled.push(nv);
    }

    // 未被任何新节点 1:1 消费掉的现有本订阅节点（队列剩余）。指纹整体消失 + 碰撞未配对都算。
    let leftover: Vec<Value> = existing_by_key.into_values().flatten().collect();
    let leftover_total = leftover.len();
    // merge_only（provider 部分失败）→ 按 provider 精确挑保留项；否则 leftover 整体即删除集。
    let kept: Vec<Value> = if merge_only {
        leftover
            .into_iter()
            .filter(|s| leftover_survives_partial(s, failed_providers))
            .collect()
    } else {
        Vec::new()
    };
    // 报给前端的 deleted = **实际**删掉的（= leftover 总数 − 被 merge-back 保留的）。
    // 此前 merge_only 恒 0，把「成功 provider 下架了 3 个节点」谎报成「无变化」。
    let deleted = leftover_total.saturating_sub(kept.len());

    others.extend(reconciled);
    others.extend(kept); // provider 级 merge-back：失败 provider / 无归属的存量保留
    if let Some(o) = cfg.as_object_mut() {
        o.insert("servers".to_string(), Value::Array(others));
    }

    // 悬挂 selectedServerId：按**实际结果 id 集**校验，仅当选中 id 真不在最终 servers 才兜底。
    // 此前按「指纹缺失」判：碰撞丢 id 时选中项指纹仍在却指向已消失 id → 漏判、留悬空引用。直连哨兵
    // `__direct__` 与空值不是节点 id，不参与存在性校验（否则会被误兜底）。
    let selected = cfg
        .get("selectedServerId")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if let Some(sid) = selected {
        if !sid.is_empty() && !is_direct_selection(Some(&sid)) {
            let fallback = cfg
                .get("servers")
                .and_then(Value::as_array)
                .and_then(|servers| {
                    let still_exists = servers
                        .iter()
                        .any(|s| s.get("id").and_then(Value::as_str) == Some(sid.as_str()));
                    (!still_exists).then(|| {
                        // F14 逃死节点：选可用兜底出口逃离已下架的选中节点；全不可用 → direct 哨兵。
                        // **绝不裸 null**（避 generate `Selected server not found` 回归 + 不静默泄漏）。
                        pick_viable_fallback_exit(servers)
                            .unwrap_or_else(|| DIRECT_SERVER_ID.to_string())
                    })
                });
            if let Some(fallback) = fallback {
                if let Some(o) = cfg.as_object_mut() {
                    o.insert("selectedServerId".to_string(), json!(fallback));
                }
            }
        }
    }

    ReconcileOutcome {
        added,
        updated,
        deleted,
    }
}

/// 订阅预检核心（**生产与门共用同一份**）：拉取 → 解析 → 节点计数，产出前端 `SubscriptionPreviewResult`。
///
/// 泛型注入 `client`/`lookup`：
/// - **生产**：`client = state.http()`（真 reqwest）、`lookup = SystemDnsLookup`（真系统解析）；
/// - **组合面门**：`client = 真 HttpRuntime`（resolve 钉到回环）、`lookup = 真 SystemDnsLookup`（解析真公网 hostname）。
///
/// §K7.1 纪律：门必须驱动**这个函数**（生产唯一路径），不得只测 mock HttpClient。
/// 复用 [`fetch_parse_resolve`]（含 provider 编排，与 updateServers 同一份）→ 节点计数（含 provider 节点）。
pub(crate) async fn preview_core<L: DnsLookup>(
    client: Arc<HttpRuntime>,
    lookup: &L,
    url: &str,
    via_proxy: bool,
    user_agent: Option<&str>,
    parse_executor: Arc<SubscriptionParseExecutor>,
    operation_deadline: std::time::Instant,
) -> Value {
    // subscription_id 传空串（预检不建订阅记录）；conditional=None（无 sub 无验证器）；
    // progress=None（还没有订阅记录可归属，见 `fetch_parse_resolve` 的 `progress` 文档）。
    let pipeline = fetch_parse_resolve(
        client,
        lookup,
        url,
        "",
        via_proxy,
        user_agent,
        None,
        None,
        None,
        parse_executor,
        operation_deadline,
    );
    match tokio::time::timeout_at(operation_deadline.into(), pipeline).await {
        Ok(Ok(outcome)) => {
            // 解析：0 节点 → errorKind:'empty'（对齐 local_import_parse 的 0 节点不变式，防空集删存量）。
            let node_count = outcome.servers.len();
            if node_count == 0 {
                let detail = outcome
                    .warnings
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "解析得到 0 个可用节点".to_string());
                return json!({ "ok": false, "errorKind": "empty", "message": detail });
            }
            json!({ "ok": true, "nodeCount": node_count })
        }
        Ok(Err(err_value)) => err_value,
        Err(_) => operation_timeout_error(),
    }
}

/// 上游 `SUBSCRIPTION_PREVIEW`：新增订阅前预检（拉取+解析 URL，不写 config）。
///
/// **已接线**（2026-07-16）：注入 `runtime/http.rs` 传输层单点 → `preview_core` → 拉取+解析。
/// 返回形态对齐前端 `SubscriptionPreviewResult`（`ui/src/shared/subscription-preview.ts`）。
///
/// renderer 的 `via_proxy` 只表示新订阅在 `follow` 档的偏好；全局 `proxy/direct` 覆盖与专用
/// **subscription-update-in** 后端路由是否真的经节点，都由后端配置判定。强制代理档不可用时
/// fail-closed；follow 偏好不可用时才允许回落直连。
#[tauri::command]
pub async fn subscription_preview(
    state: State<'_, AppRuntime>,
    url: String,
    via_proxy: Option<bool>,
    user_agent: Option<String>,
) -> Result<ApiResponse<Value>, ()> {
    let operation_deadline = std::time::Instant::now() + SUBSCRIPTION_OPERATION_TIMEOUT;
    let cfg = match state.config().load_full() {
        Ok(cfg) => cfg,
        Err(error) => {
            return Ok(ApiResponse::ok(json!({
                "ok": false,
                "errorKind": "unknown",
                "message": format!("无法读取后端订阅策略: {error}"),
            })));
        }
    };
    // `viaProxy` is only the draft subscription's follow-mode preference. The backend still owns
    // the global direct/proxy override and the effective core-route decision; a renderer cannot
    // claim that the request is proxied merely by setting this boolean.
    let draft = json!({
        "updateViaProxy": via_proxy.unwrap_or(false),
        "userAgent": user_agent,
    });
    let want_proxy = want_proxy_for_sub(&cfg, &draft);
    let forced_proxy = proxy_policy_is_forced(&cfg);
    let effective_user_agent = resolve_subscription_ua(&cfg, &draft);
    let lookup = SystemDnsLookup;
    let (client, via_effective) = select_fetch_client(state.inner(), &cfg, want_proxy);
    if forced_proxy && !via_effective {
        return Ok(ApiResponse::ok(json!({
            "ok": false,
            "errorKind": "unknown",
            "message": "全局策略要求订阅经代理预检，但当前后端路由不是可用代理；已中止且未直连",
        })));
    }
    let result = preview_core(
        client,
        &lookup,
        &url,
        via_effective,
        effective_user_agent.as_deref(),
        Arc::clone(state.subscription_parse()),
        operation_deadline,
    )
    .await;
    Ok(ApiResponse::ok(result))
}

/// 上游 `LOCAL_IMPORT_PARSE`：本地导入解析（文件/文本 → 节点预览，不联网）。
///
/// 接 net-stack [`polaris_net_stack::subscription::parse_subscription_bundle_limited`]
/// （纯逻辑，无 I/O）：Clash YAML / base64 / url-list 三路分发。产出对齐前端
/// `ImportParseResult`（`ui/src/shared/types.ts:254`）。
///
/// **本地导入的节点是「自建」节点** → 不带 `subscriptionId`（前端契约注释明示）：故 subscription_id
/// 传空串后剥离该字段。`subscriptions[]` 仅来自 Clash proxy-providers（不联网拉取），当前 net-stack
/// 的 provider 编排属拉取层 → 恒空，见下方注释。
///
/// 体积闸（10 MB，与 上游 `MAX_BODY_BYTES` 同口径）：防超大文件 / YAML 锚点炸弹经 IPC 进主进程 OOM。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub async fn local_import_parse(
    state: State<'_, AppRuntime>,
    text: String,
) -> Result<ApiResponse<Value>, ()> {
    let executor = Arc::clone(state.subscription_parse());
    let input_bytes = text.len();
    let task = match executor.submit_weighted(input_bytes, move || parse_local_import_owned(text)) {
        Ok(task) => task,
        Err(error) => return Ok(ApiResponse::err(error.to_string())),
    };
    Ok(
        match tokio::time::timeout(SUBSCRIPTION_OPERATION_TIMEOUT, task.result()).await {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => ApiResponse::err(error.to_string()),
            Err(_) => ApiResponse::err("本地导入解析超过 60 秒总时限，已取消结果"),
        },
    )
}

/// 纯本地导入解析。只持有 owned 正文，不接触 Tauri/runtime/config/commit；生产 command 必须经
/// [`SubscriptionParseExecutor`] 调用，unit tests 可直接覆盖此函数。
fn parse_local_import_owned(text: String) -> ApiResponse<Value> {
    const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;
    let trimmed = text.trim();
    if trimmed.len() > MAX_BODY_BYTES {
        return ApiResponse::err("导入内容过大");
    }

    let now = current_iso();
    let mut id_gen = new_uuid;
    // subscription_id 传空串：本地导入产出自建节点，下方剥离该字段（不归属任何订阅）。
    // `LocalFile`：内容是用户自己的文件/粘贴 ⇒ 未建模 type 透传为 custom 逃生舱
    // （上游 `parseLocalContent` 的 `makeCustomNode` 腿，见 [`ImportOrigin`]）。
    let bundle = match polaris_net_stack::subscription::parse_subscription_bundle_limited(
        trimmed,
        "",
        &now,
        &mut id_gen,
        ImportOrigin::LocalFile,
        SubscriptionParseLimits::default(),
    ) {
        Ok(bundle) => bundle,
        Err(error) => return ApiResponse::err(error),
    };
    let format = bundle.format;
    let parsed = bundle.parsed;
    // 「不支持协议 → 透传为 custom」的条数。**由产物派生而非解析器另报一个计数**：契约
    // （`ui/src/contracts/types.ts` `ImportParseResult.stats.unsupported`）的定义就是
    // 「imported 里已透传为 custom 的数量」，派生使二者恒等而非靠两处各自加对；且解析管线里
    // 只有 sing-box 这条腿会产出 `Protocol::Custom`（clash / xray / share-link 三个解析器
    // grep 零命中）。
    let unsupported = parsed
        .servers
        .iter()
        .filter(|s| s.protocol == Protocol::Custom)
        .count();

    let nodes: Vec<Value> = parsed
        .servers
        .iter()
        .filter_map(|s| serde_json::to_value(s).ok())
        .map(|mut v| {
            if let Some(o) = v.as_object_mut() {
                o.remove("subscriptionId"); // 自建节点无归属
            }
            v
        })
        .collect();

    // 0 节点即报错（与 Polaris 对齐）：空集会让渲染端「导入成功但什么也没有」，
    // 且不可识别格式本就该由前端门控报错（ipc-channels.ts:31「不可识别格式 throw」）。
    if nodes.is_empty() {
        let detail = parsed
            .warnings
            .first()
            .cloned()
            .unwrap_or_else(|| "未识别到任何可用节点".to_string());
        return ApiResponse::err(format!("解析得到 0 个可用节点：{detail}"));
    }

    ApiResponse::ok(json!({
        "nodes": nodes,
        // 仅来自 Clash proxy-providers；provider 需联网拉取 → 本地导入路径恒空（对齐「不联网拉取」契约）。
        "subscriptions": [],
        "stats": {
            "imported": nodes.len(),
            // custom 透传：不建模的 sing-box type（`hysteria` v1 / `tor` / 独立 `shadowtls` /
            // `openconnect` / `openvpn-*` …）原文入库、可编辑，使用时由 `kernel:probeOutbound`
            // 按内核实况置灰（内核即权威，不在此复刻协议白名单）。
            "unsupported": unsupported,
            "skipped": parsed.skipped,
            "failed": parsed.failed,
        },
        "warnings": parsed.warnings,
        "format": import_format_label(format),
    }))
}

/// net-stack 格式探测 → 前端 `ImportFormat`（`ui/src/shared/types.ts:248`）。
///
/// 前端联合类型是 `'singbox'|'xray'|'clash'|'links'|'unknown'`：base64 与 url-list 在前端
/// 同属 `links`（两者只是编码差异，节点级语义一致）；`xray` 走 xray JSON 导入（C17 已移植）。
fn import_format_label(f: polaris_net_stack::subscription::SubscriptionFormat) -> &'static str {
    use polaris_net_stack::subscription::SubscriptionFormat as F;
    match f {
        F::Clash => "clash",
        F::SingboxJson => "singbox",
        F::XrayJson => "xray",
        F::Base64 | F::UrlList => "links",
        F::Unknown => "unknown",
    }
}

/// 上游 `LOCAL_IMPORT_PICK_FILE`：弹系统原生文件框 + 读内容回传（Tauri dialog 插件）。
///
/// 替代 Electron `dialog.showOpenDialog`（上游 `subscription-handlers.ts` `LOCAL_IMPORT_PICK_FILE`）：
/// 文件类型过滤对齐 上游（配置文件 json/yaml/yml/txt/conf + 所有文件）；10MB 上限对齐 Polaris
/// （与 [`local_import_parse`] 同口径）。回调式 `pick_file` + oneshot（对齐 `misc::ask_open_path`）——
/// `blocking_pick_file` 在主线程调用会死锁，故本 command 为 `async fn`。
/// 取消 → `{canceled:true}`；文件过大/读失败 → `{canceled:false,error}`（`too_large`|`read_failed`，
/// 对齐 上游 错误码）；成功 → `{canceled:false,content,fileName}`（`fileName` 为 basename，非全路径，
/// 避免向渲染端泄漏本机目录结构）。
#[tauri::command]
pub async fn local_import_pick_file(window: WebviewWindow) -> ApiResponse<Value> {
    const MAX_BODY_BYTES: u64 = 10 * 1024 * 1024;
    enum ReadError {
        TooLarge,
        Failed,
    }

    let lang = crate::i18n::app_lang(window.app_handle());
    let (tx, rx) = tokio::sync::oneshot::channel();
    window
        .dialog()
        .file()
        .set_title(t(lang, key::NATIVE_CONFIG_PICK_TITLE))
        .add_filter(
            t(lang, key::NATIVE_CONFIG_FILE_TYPE),
            &["json", "yaml", "yml", "txt", "conf"],
        )
        .add_filter(t(lang, key::NATIVE_ALL_FILES), &["*"])
        .pick_file(move |p| {
            let _ = tx.send(p);
        });
    let Some(path) = rx.await.ok().flatten().and_then(|p| p.into_path().ok()) else {
        return ApiResponse::ok(json!({ "canceled": true }));
    };

    let read = async {
        let file = tokio::fs::File::open(&path)
            .await
            .map_err(|_| ReadError::Failed)?;
        let metadata = file.metadata().await.map_err(|_| ReadError::Failed)?;
        if metadata.len() > MAX_BODY_BYTES {
            return Err(ReadError::TooLarge);
        }
        // Metadata can race with a writer (and special files need not have a meaningful length),
        // so stream at most one byte beyond the cap rather than trusting the preflight alone.
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_BODY_BYTES + 1)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| ReadError::Failed)?;
        if bytes.len() as u64 > MAX_BODY_BYTES {
            return Err(ReadError::TooLarge);
        }
        String::from_utf8(bytes).map_err(|_| ReadError::Failed)
    };
    match tokio::time::timeout(LOCAL_IMPORT_FILE_READ_TIMEOUT, read).await {
        Ok(Ok(content)) => {
            let file_name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            ApiResponse::ok(json!({
                "canceled": false,
                "content": content,
                "fileName": file_name,
            }))
        }
        Ok(Err(ReadError::TooLarge)) => {
            ApiResponse::ok(json!({ "canceled": false, "error": "too_large" }))
        }
        Ok(Err(ReadError::Failed)) | Err(_) => {
            ApiResponse::ok(json!({ "canceled": false, "error": "read_failed" }))
        }
    }
}

fn current_iso() -> String {
    // 复用 stats-engine 的 created_at_to_rfc3339（无 chrono/time 依赖）；旧实现把整个 epoch 秒塞进秒字段
    // 产出非法 ISO（前端 Invalid Date），改为真 epoch-millis→RFC3339。时钟异常 → 空串，不 panic。
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .and_then(polaris_stats_engine::created_at_to_rfc3339)
        .unwrap_or_default()
}

fn new_uuid() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("pol-{nanos:032x}")
}

#[cfg(test)]
mod tests;

mod pipeline;
#[cfg(test)]
use pipeline::ProviderProgress;
use pipeline::{fetch_parse_resolve, operation_timeout_error, FetchOutcome};

mod create;
pub use create::*;
