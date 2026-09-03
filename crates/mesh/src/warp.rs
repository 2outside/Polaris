//! Cloudflare WARP 设备注册协议（纯逻辑，无网络）。
//!
//! 1:1 移植自 上游 `src/shared/warp.ts`。WARP 即 WireGuard：匿名注册一台设备 → 拿到一份 WG 配置
//! （对端公钥/端点/分配 IP/client_id），Polaris 直接作为普通 WireGuard endpoint 节点使用。
//! 网络发送/TLS 指纹在 [`crate::warp_http::WarpHttp`] trait 实现方（维度7 R5：rustls TLS 指纹回归点）。
//!
//! 版本串说明：Cloudflare 按客户端发版滚动 API 版本，path 段(version)与 `CF-Client-Version` 必须配对，
//! 旧串会被服务端拒（如 wgcf 钉死的 v0a1922 自 2025-08 起注册返 500）。故做成常量、可被调用方覆盖重试。

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

// ── 注册端点与请求头默认值 ────────────────────────────────────────────

/// WARP 注册 API base。上游 `WARP_API_BASE`。
pub const WARP_API_BASE: &str = "https://api.cloudflareclient.com";

/// WARP API 版本段（path）。上游 `WARP_API_VERSION`。CF 滚动版本，旧串会被拒。
pub const WARP_API_VERSION: &str = "v0a2158";

/// CF-Client-Version header 值。上游 `WARP_CLIENT_VERSION`。须与 API 版本段配对。
pub const WARP_CLIENT_VERSION: &str = "a-7.21-0721";

/// User-Agent（okhttp，配合 TLS1.2 指纹避开 Cloudflare 1020）。上游 `WARP_USER_AGENT`。
pub const WARP_USER_AGENT: &str = "okhttp/3.12.1";

/// WARP 标准 endpoint 兜底 host。上游 `WARP_DEFAULT_ENDPOINT_HOST`。
pub const WARP_DEFAULT_ENDPOINT_HOST: &str = "engage.cloudflareclient.com";

/// WARP 标准 endpoint 兜底端口。上游 `WARP_DEFAULT_ENDPOINT_PORT`。
pub const WARP_DEFAULT_ENDPOINT_PORT: u16 = 2408;

/// WARP 端点域名锚点：注册响应给出的 endpoint 均属此域。上游 `WARP_ENDPOINT_DOMAIN`。
///
/// **定义在 `polaris-config-engine`**（`crate::warp`），这里只再导出：该域名同时是 config-engine
/// 侧 `is_warp_server` 的判据 —— `system:true` 否决要用它，而 config-engine 不能反向依赖本 crate
/// （会成环）。写第二份字面量 = 把「两侧各自判定」的漂移面复制进 Rust 内部。
pub use polaris_config_engine::warp::WARP_ENDPOINT_DOMAIN;

// ── 注销队列护栏 ──────────────────────────────────────────────────────

/// 注销重试年龄阈值：7 天未成功 → 放弃（孤儿零计费）。上游 `WARP_DEREGISTER_MAX_AGE_MS`。
pub const WARP_DEREGISTER_MAX_AGE_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// 队列条数上限，超则丢最旧 + 日志（防 register-loop 撑爆）。上游 `WARP_DEREGISTER_MAX_QUEUE`。
pub const WARP_DEREGISTER_MAX_QUEUE: usize = 100;

/// 单次 drain 至多处理条数（避免启动 hammer CF / 触 1020）。上游 `WARP_DEREGISTER_MAX_PER_DRAIN`。
pub const WARP_DEREGISTER_MAX_PER_DRAIN: usize = 10;

// ── 类型 ──────────────────────────────────────────────────────────────

/// WARP 注册产出的 WireGuard 草稿（无 id，供渲染端填表）。上游 `WarpWireGuardDraft`。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarpWireGuardDraft {
    pub address: String,
    pub port: u16,
    pub private_key: String,
    pub peer_public_key: String,
    #[serde(rename = "localAddress")]
    pub local_address: Vec<String>,
    #[serde(rename = "reserved", default, skip_serializing_if = "Option::is_none")]
    pub reserved: Option<Vec<u8>>,
    pub meta: WarpDraftMeta,
    /// 远端设备自删凭据（deviceId+token）。删除此节点时据它发 DELETE 注销匿名设备。
    #[serde(rename = "warpDevice")]
    pub warp_device: WarpDeviceCreds,
}

/// WG 草稿的展示元数据。上游 `WarpWireGuardDraft.meta`。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarpDraftMeta {
    #[serde(rename = "deviceId")]
    pub device_id: String,
    #[serde(rename = "accountId")]
    pub account_id: String,
    pub license: String,
    #[serde(rename = "warpPlus")]
    pub warp_plus: bool,
}

/// 远端设备自删凭据（deviceId+token），随节点落 `wireguardSettings.warpDevice`。
/// 上游 `wireguardSettings.warpDevice`。与 privateKey 同脱敏。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarpDeviceCreds {
    #[serde(rename = "deviceId")]
    pub device_id: String,
    pub token: String,
}

/// WARP 注册响应里 Polaris 关心的子集。上游 `WarpRegisterResult`。不含 privateKey（本地生成）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarpRegisterResult {
    /// 对端（WARP relay）地址：endpoint host。
    pub address: String,
    /// 对端端口。
    pub port: u16,
    /// 对端 WG 公钥。
    pub peer_public_key: String,
    /// 分配给本机的隧道地址（v4 /32、v6 /128）。
    pub local_address: Vec<String>,
    /// reserved 3 字节（来自 client_id）。
    pub reserved: Option<Vec<u8>>,
    /// 设备 id。
    pub device_id: String,
    /// 账户 id。
    pub account_id: String,
    pub license: String,
    /// 是否 WARP+（account.warp_plus）。
    pub warp_plus: bool,
}

/// 注销结果分类。上游 `DeregisterResult`。
/// - `Done`：出队（已注销/别处已销）；
/// - `Drop`：出队（凭据死，重试纯浪费）；
/// - `Retry`：留队消耗重试预算。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeregisterResult {
    Done,
    Drop,
    Retry,
}

/// 待注销队列条目（落 `<userData>/warp/pending-deregister.json`）。上游 `PendingDeregisterEntry`。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingDeregisterEntry {
    #[serde(rename = "deviceId")]
    pub device_id: String,
    pub token: String,
    /// 入队时刻（unix 毫秒），按年龄判超时。
    #[serde(rename = "enqueuedAt")]
    pub enqueued_at: u64,
}

/// 单条 drain 计划：超龄 expire（不调网络直接 drop）/ 在龄 eligible（调 unregister）。
/// 上游 `DrainPlanItem`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrainPlanItem {
    pub entry: PendingDeregisterEntry,
    pub action: DrainAction,
}

/// drain 单条动作。上游 `DrainPlanItem.action`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainAction {
    /// 超龄放弃（不调网络，出队）。
    Expire,
    /// 在龄，本次调 unregister。
    Eligible,
}

// ── 注册请求/响应纯逻辑 ──────────────────────────────────────────────

/// 注册请求体（POST /reg）。上游 `buildRegisterBody`。
/// `tos` = RFC3339Nano UTC 时间戳（ToS 接受时间）；install_id/fcm_token 传空可注册。
pub fn build_register_body(public_key_b64: &str, tos_timestamp: &str) -> Value {
    json!({
        "key": public_key_b64,
        "install_id": "",
        "fcm_token": "",
        "tos": tos_timestamp,
        "model": "PC",
        "type": "Android",
        "locale": "en_US",
    })
}

/// base64(client_id) → 前 3 字节（sing-box/xray 的 reserved）。非法/不足 3 字节返回 None。
/// 上游 `reservedFromClientId`。
pub fn reserved_from_client_id(client_id: Option<&str>) -> Option<Vec<u8>> {
    let id = client_id?;
    if id.is_empty() {
        return None;
    }
    // 标准 base64 解码（Polaris 用 Node Buffer.from(id,'base64')，对非标准字符容忍失败）。
    let decoded = base64_decode(id)?;
    if decoded.len() < 3 {
        return None;
    }
    Some(vec![decoded[0], decoded[1], decoded[2]])
}

/// 拆 "host:port" / "\[v6\]:port"；缺端口回落 WARP 默认 2408。上游 `splitEndpoint`。
pub fn split_endpoint(endpoint: Option<&str>) -> (String, u16) {
    let e = endpoint.unwrap_or("").trim();
    if e.is_empty() {
        return (
            WARP_DEFAULT_ENDPOINT_HOST.to_string(),
            WARP_DEFAULT_ENDPOINT_PORT,
        );
    }
    // [2606:4700:...]:2408
    if let Some(rest) = e.strip_prefix('[') {
        if let Some(close) = rest.find(']') {
            let host = &rest[..close];
            let after = &rest[close + 1..];
            if let Some(port_str) = after.strip_prefix(':') {
                if let Ok(port) = port_str.parse::<u16>() {
                    return (host.to_string(), port);
                }
            }
        }
    }
    // host:port（host 不含更多冒号）；否则整个当 host。
    if let Some(idx) = e.rfind(':') {
        let after = &e[idx + 1..];
        if !after.is_empty() && !after.contains(':') {
            if let Ok(port) = after.parse::<u16>() {
                return (e[..idx].to_string(), port);
            }
        }
    }
    (e.to_string(), WARP_DEFAULT_ENDPOINT_PORT)
}

/// 解析 POST /reg 的 JSON 响应 → [`WarpRegisterResult`]。上游 `parseRegisterResponse`。
/// 缺关键字段（peer 公钥/端点/分配 IP）则返 Err。
pub fn parse_register_response(json: &Value) -> Result<WarpRegisterResult, String> {
    let config = json.get("config");
    let peers = config
        .and_then(|c| c.get("peers"))
        .and_then(|p| p.as_array());
    let peer = peers.and_then(|arr| arr.first());
    let peer_public_key = peer
        .and_then(|p| p.get("public_key"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let endpoint_host = peer
        .and_then(|p| p.get("endpoint"))
        .and_then(|e| e.get("host"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());

    let addresses = config
        .and_then(|c| c.get("interface"))
        .and_then(|i| i.get("addresses"));
    let v4 = addresses
        .and_then(|a| a.get("v4"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let v6 = addresses
        .and_then(|a| a.get("v6"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());

    let public_key = peer_public_key
        .ok_or_else(|| "WARP 注册响应缺少 peer 公钥 / 端点 / 分配地址".to_string())?;
    let host =
        endpoint_host.ok_or_else(|| "WARP 注册响应缺少 peer 公钥 / 端点 / 分配地址".to_string())?;
    if v4.is_none() && v6.is_none() {
        return Err("WARP 注册响应缺少 peer 公钥 / 端点 / 分配地址".to_string());
    }

    let (address, port) = split_endpoint(Some(host));
    let mut local_address = Vec::new();
    if let Some(v4) = v4 {
        local_address.push(format!("{}/32", v4));
    }
    if let Some(v6) = v6 {
        local_address.push(format!("{}/128", v6));
    }
    let client_id = config
        .and_then(|c| c.get("client_id"))
        .and_then(|v| v.as_str());
    let reserved = reserved_from_client_id(client_id);

    Ok(WarpRegisterResult {
        address,
        port,
        peer_public_key: public_key.to_string(),
        local_address,
        reserved,
        device_id: json
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        account_id: json
            .get("account")
            .and_then(|a| a.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        license: json
            .get("account")
            .and_then(|a| a.get("license"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        warp_plus: json
            .get("account")
            .and_then(|a| a.get("warp_plus"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    })
}

// ── 设备注销 / 待注销队列（纯逻辑） ──────────────────────────────────

/// 构造注销请求（纯函数，无网络）。上游 `buildUnregisterRequest`。
/// 裸 `DELETE /{version}/reg/{deviceId}` + Bearer token + 同 register 的 UA/CF-Client-Version。
/// 实测：自删走裸 /reg/{id}（非 .../account/reg/{id}——那是登录账户删绑定设备、自删返 401）→ 204；再删 404。
pub fn build_unregister_request(
    version: &str,
    device_id: &str,
    token: &str,
) -> (String, BTreeMap<String, String>) {
    let url = format!("{}/{}/reg/{}", WARP_API_BASE, version, device_id);
    let mut headers = BTreeMap::new();
    headers.insert("User-Agent".to_string(), WARP_USER_AGENT.to_string());
    headers.insert(
        "CF-Client-Version".to_string(),
        WARP_CLIENT_VERSION.to_string(),
    );
    headers.insert("Authorization".to_string(), format!("Bearer {}", token));
    headers.insert("Accept".to_string(), "application/json".to_string());
    (url, headers)
}

/// 注销失败分类（纯函数）。上游 `classifyDeregisterResult`。
/// - `status == None` 表网络失败/超时（无 HTTP 状态）。
/// - 204 / 404 → Done（404=别处已销，视作成功），优先于一切；
/// - err 文本含 `1020` → Retry（WAF/版本失效，须优先于 401/403 的 Drop）；
/// - 401 / 403 → Drop（token 失效/被拒）；
/// - 网络失败(None) / 5xx / 400 → Retry；
/// - 其它未知 4xx → Drop（非暂时性，不无限占预算）。
pub fn classify_deregister_result(status: Option<u16>, err: Option<&str>) -> DeregisterResult {
    // 网络失败 / 超时：无 HTTP 状态 → 暂时不可达，重试。
    let status = match status {
        Some(s) => s,
        None => return DeregisterResult::Retry,
    };
    if status == 204 || status == 404 {
        return DeregisterResult::Done; // definitive success，优先于一切
    }
    // Cloudflare WAF 1020（版本串失效）常以 403 携带 body code 1020 返回——须**优先于** 401/403 的 Drop
    // 判定（否则被误当 token 死而放弃）。err 文本含 1020 一律 Retry（升级后恢复）。
    if let Some(text) = err {
        if text.contains("1020") {
            return DeregisterResult::Retry;
        }
    }
    if status == 401 || status == 403 {
        return DeregisterResult::Drop; // token 失效/被拒
    }
    if status >= 500 {
        return DeregisterResult::Retry;
    }
    if status == 400 {
        return DeregisterResult::Retry;
    }
    // 其它未知 4xx：非暂时性，Drop。
    DeregisterResult::Drop
}

/// 入队（纯函数）：追加新条目，受 `WARP_DEREGISTER_MAX_QUEUE` 护栏——超上限丢最旧（FIFO）。
/// 上游 `enqueuePendingDeregister`。返回 `(next_queue, dropped)`：dropped=被挤掉的最旧条目。
pub fn enqueue_pending_deregister(
    queue: &[PendingDeregisterEntry],
    entry: PendingDeregisterEntry,
) -> (Vec<PendingDeregisterEntry>, Vec<PendingDeregisterEntry>) {
    let mut next: Vec<PendingDeregisterEntry> = queue.to_vec();
    next.push(entry);
    let mut dropped = Vec::new();
    while next.len() > WARP_DEREGISTER_MAX_QUEUE {
        // 丢最旧（队首）。
        if let Some(old) = next.first().cloned() {
            dropped.push(old);
        }
        next.remove(0);
    }
    (next, dropped)
}

/// drain 计划（纯函数，无 IO）：按年龄分流 + 截断到 `WARP_DEREGISTER_MAX_PER_DRAIN`。
/// 上游 `planDeregisterDrain`。
/// - 年龄 > MAX_AGE_MS → Expire（放弃，warn 后出队，不调网络）；
/// - 否则 → Eligible（本次调 unregister）；Eligible 至多取前 MAX_PER_DRAIN 条，余下顺延。
/// Expired 不占 MAX_PER_DRAIN 预算（不调网络）。返回 (plan, deferred)：deferred 留队。
pub fn plan_deregister_drain(
    queue: &[PendingDeregisterEntry],
    now: u64,
) -> (Vec<DrainPlanItem>, Vec<PendingDeregisterEntry>) {
    let mut plan = Vec::new();
    let mut deferred = Vec::new();
    let mut eligible_count = 0usize;
    for entry in queue {
        // 注意：Polaris 用 `now - enqueuedAt > MAX_AGE` 判超龄（>，非 >=）。
        if now.saturating_sub(entry.enqueued_at) > WARP_DEREGISTER_MAX_AGE_MS {
            plan.push(DrainPlanItem {
                entry: entry.clone(),
                action: DrainAction::Expire,
            });
        } else if eligible_count < WARP_DEREGISTER_MAX_PER_DRAIN {
            plan.push(DrainPlanItem {
                entry: entry.clone(),
                action: DrainAction::Eligible,
            });
            eligible_count += 1;
        } else {
            deferred.push(entry.clone());
        }
    }
    (plan, deferred)
}

// ── base64 解码（纯 std，避免引入新依赖） ─────────────────────────────

/// 宽容的标准 base64 解码：接受 +/ 与 URL-safe -_；忽略非字母表字符不报错（与 Polaris 的容忍度对齐：
/// Polaris 用 Node `Buffer.from(id,'base64')`，对合法字母表解码、忽略填充异常）。失败返回 None。
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    // 收集字母表字符（兼容 URL-safe 变体）。
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    for ch in input.bytes() {
        let val = match ch {
            b'A'..=b'Z' => (ch - b'A') as u32,
            b'a'..=b'z' => (ch - b'a' + 26) as u32,
            b'0'..=b'9' => (ch - b'0' + 52) as u32,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' | b'\n' | b'\r' | b' ' => continue,
            _ => continue,
        };
        bits = (bits << 6) | val;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests;
