//! Tailscale STATUS 帧解码：sing-box 管理 API `TailscaleStatusUpdate`（proto）→ 前端契约事件。
//!
//! # 为什么解码在 src-tauri 而不在 mesh crate
//!
//! `polaris-mesh` 是纯逻辑 crate，**不依赖** `polaris-singbox-grpc`（tonic/prost）——让它依赖会把
//! gRPC 传输层拖进 mesh 决策层。而本解码的输入就是 proto 生成类型（`daemon::TailscaleStatusUpdate`），
//! 故落在 src-tauri（既定的「proto → domain 投影」注入点，同 `runtime/management_api.rs` 把
//! `daemon::Connection → ConnectionSnapshot` 的手法）。
//!
//! # 数据链
//!
//! `SubscribeTailscaleStatus` 流每帧 = **全量端点快照**（所有 tailscale endpoint）。本模块把它逐端点投影成
//! [`TailscaleStatusEvent`]（前端 `contracts/tailscale-status.ts` 的 1:1 镜像，serde 字段名对齐 camelCase）：
//! - `endpointTag → serverId`：经 `tag_to_id`（`build_id_to_tag_map` 的逆，仅当前运行配置在册的 tailscale 节点）。
//!   **不在册的端点（幽灵/历史）直接丢弃**（前端契约「幽灵条目已过滤」）。
//! - `loggedIn = (backendState ∈ {Running, Starting}) 且 self 未过期`（1.14 登录成功信号，对齐前端契约）。
//! - `peers`：摊平 `userGroups[].peers[]` + 按 hostName 去重，投影成 UI lean 形态。
//!
//! 契约唯一真值 = `ui/src/contracts/tailscale-status.ts`（跨层三方共享）。改字段先改那份。

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use polaris_singbox_grpc::daemon;

/// 对端节点 lean 形态（`contracts/tailscale-status.ts` `TailscaleStatusPeer` 镜像）。
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TailscalePeerDetails {
    pub dns_name: String,
    pub os: String,
    #[serde(rename = "tailscaleIPs")]
    pub tailscale_ips: Vec<String>,
    pub rx_bytes: i64,
    pub tx_bytes: i64,
    pub key_expiry: i64,
    pub expired: bool,
    pub ssh_host_keys: Vec<String>,
    pub sharee_node: bool,
    pub last_seen: i64,
    pub can_receive_files: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TailscaleStatusPeer {
    /// 主机名。
    pub host_name: String,
    /// 内网 IP：首个 IPv4（tailnet 100.x），无则首个 IP。
    pub ip: String,
    /// 该 peer 在 tailnet 上是否 up。
    pub online: bool,
    /// 是否当前被本节点选中作出口。
    pub exit_node: bool,
    /// 是否广告了可当出口（出口下拉候选判据）。
    pub exit_node_option: bool,
    /// 近期是否有活跃直连/流量。
    pub active: bool,
    /// tailnet stableID（主进程热重设 exit_node 用；UI 不消费，旧核/无 ID → None）。
    #[serde(rename = "stableID", skip_serializing_if = "Option::is_none")]
    pub stable_id: Option<String>,
    /// rc.2 的其余原生节点字段；旧的 lean 字段保留在顶层以稳定既有消费方。
    pub details: TailscalePeerDetails,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TailscaleUserGroupStatus {
    #[serde(rename = "userID")]
    pub user_id: i64,
    pub login_name: String,
    pub display_name: String,
    #[serde(rename = "profilePicURL")]
    pub profile_pic_url: String,
    pub peers: Vec<TailscaleStatusPeer>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TailscaleStatusDetails {
    pub state_text: String,
    pub network_name: String,
    #[serde(rename = "magicDNSSuffix")]
    pub magic_dns_suffix: String,
    pub key_auth: bool,
    #[serde(rename = "self")]
    pub self_peer: Option<TailscaleStatusPeer>,
    pub user_groups: Vec<TailscaleUserGroupStatus>,
    pub exit_node: Option<TailscaleStatusPeer>,
}

/// 单个 Tailscale endpoint 的状态事件（`contracts/tailscale-status.ts` `TailscaleStatusEvent` 镜像）。
///
/// 既是 `EVENT_TAILSCALE_STATUS` 的推送载荷（逐 endpoint 发一条），也是 [`TailscaleStatusSnapshot`]
/// 的成员（`TAILSCALE_GET_STATUS` 拉末帧）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TailscaleStatusEvent {
    /// 节点 id（由 `endpointTag` 经 tag→id 逆映射得到）。
    pub server_id: String,
    /// NoState | NeedsLogin | Starting | Running | …
    pub backend_state: String,
    /// loggedIn =（Running||Starting）且 key 未过期。
    pub logged_in: bool,
    /// NeedsLogin 时的交互登录 URL（主核路径带；空 → None）。
    #[serde(rename = "authURL", skip_serializing_if = "Option::is_none")]
    pub auth_url: Option<String>,
    /// 本节点自身内网 IP（self.tailscaleIPs）。
    #[serde(rename = "tailscaleIPs")]
    pub tailscale_ips: Vec<String>,
    /// key 是否过期。
    pub expired: bool,
    /// 对端列表（摊平 userGroups 各组 + 去重）。
    pub peers: Vec<TailscaleStatusPeer>,
    /// rc.2 完整原生状态。顶层继续保留既有 lean 投影，避免 UI/备份契约被一次性打碎。
    pub details: TailscaleStatusDetails,
    /// Taildrop **能力位**：tailnet 是否授了 `https://tailscale.com/cap/file-sharing`。
    ///
    /// 这是 UI 的门，不是用户开关 —— 未授时内核照常跑，只是收发不成立。不拿它当门就会做出
    /// 「点了没反应」的界面（本仓为 `allowInternet` / `resolveByName` 两次记过同一条教训）。
    ///
    /// 旧核（< 1.14.0-beta.15）没有这个字段 ⇒ prost 给 proto3 标量的缺省 `false`，UI 落到
    /// 「此 tailnet 未启用文件共享」那一档。**这个降级是对的**：换了没有 Taildrop 的核，
    /// 收发本来也不成立。
    pub can_share_files: bool,
    /// 已落盘待处理的文件数。
    pub waiting_file_count: i32,
    /// 正在接收中的文件数。
    pub receiving_file_count: i32,
    /// 未读数（`MarkTaildropInboxRead` 清零）。角标取它而不是 waiting：读过但没删的文件
    /// 仍在 waiting 里，拿 waiting 当角标会让角标永远消不掉。
    pub unread_file_count: i32,
}

impl TailscaleStatusEvent {
    /// 当前 endpoint 是否可作为真实代理出口。`Starting` 只说明已登录，数据面尚未就绪；过期 key 即使
    /// 内核暂时报 `Running` 也必须拒绝，避免 probe pool 量到登录期让位后的直连出口。
    #[must_use]
    pub fn exit_ready(&self) -> bool {
        self.backend_state == "Running" && !self.expired
    }
}

/// `TAILSCALE_GET_STATUS` 返回：缓存末帧 + 新鲜度（`contracts/tailscale-status.ts` `TailscaleStatusSnapshot`）。
///
/// `connected` = 主核是否在运行（=状态流是否 live）。false → `statuses` 为上次已知/空（renderer 灰显动态位）。
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TailscaleStatusSnapshot {
    pub connected: bool,
    pub statuses: Vec<TailscaleStatusEvent>,
}

/// 取对端/自身的展示 IP：首个 IPv4（不含 `:`，tailnet 100.x），无则首个，全无则空串。
/// 对齐前端契约「首个 IPv4(100.x)，无则首个 IP」。
fn pick_ip(ips: &[String]) -> String {
    ips.iter()
        .find(|ip| !ip.contains(':'))
        .or_else(|| ips.first())
        .cloned()
        .unwrap_or_default()
}

/// proto peer → UI lean peer。`stable_id` 空串 → None（旧核/无 ID）。
fn lean_peer(p: &daemon::TailscalePeer) -> TailscaleStatusPeer {
    TailscaleStatusPeer {
        host_name: p.host_name.clone(),
        ip: pick_ip(&p.tailscale_i_ps),
        online: p.online,
        exit_node: p.exit_node,
        exit_node_option: p.exit_node_option,
        active: p.active,
        stable_id: if p.stable_id.is_empty() {
            None
        } else {
            Some(p.stable_id.clone())
        },
        details: TailscalePeerDetails {
            dns_name: p.dns_name.clone(),
            os: p.os.clone(),
            tailscale_ips: p.tailscale_i_ps.clone(),
            rx_bytes: p.rx_bytes,
            tx_bytes: p.tx_bytes,
            key_expiry: p.key_expiry,
            expired: p.expired,
            ssh_host_keys: p.ssh_host_keys.clone(),
            sharee_node: p.sharee_node,
            last_seen: p.last_seen,
            can_receive_files: p.can_receive_files,
        },
    }
}

/// 摊平 `userGroups[].peers[]`。优先按 stableID 去重；旧核/无 ID 才回落 hostName。
fn flatten_peers(groups: &[daemon::TailscaleUserGroup]) -> Vec<TailscaleStatusPeer> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for g in groups {
        for p in &g.peers {
            let identity = if p.stable_id.is_empty() {
                format!("host:{}", p.host_name)
            } else {
                format!("id:{}", p.stable_id)
            };
            if seen.insert(identity) {
                out.push(lean_peer(p));
            }
        }
    }
    out
}

/// 解码一帧全量端点快照 → 前端事件集。
///
/// `tag_to_id` = 当前运行配置的 `tag → serverId`（`build_id_to_tag_map` 的逆）。**端点 tag 不在其中 → 丢弃**
/// （幽灵/历史端点过滤，前端契约要求）。`loggedIn` 判定 = backendState ∈ {Running, Starting} 且 self 未过期。
#[must_use]
pub fn decode_tailscale_status(
    update: &daemon::TailscaleStatusUpdate,
    tag_to_id: &BTreeMap<String, String>,
) -> Vec<TailscaleStatusEvent> {
    update
        .endpoints
        .iter()
        .filter_map(|ep| {
            // 幽灵过滤：端点 tag 不对应任何在册节点 → 丢弃（不 emit、不进缓存）。
            let server_id = tag_to_id.get(&ep.endpoint_tag)?.clone();
            let expired = ep.self_.as_ref().is_some_and(|s| s.expired);
            let logged_in = matches!(ep.backend_state.as_str(), "Running" | "Starting") && !expired;
            let auth_url = if ep.auth_url.is_empty() {
                None
            } else {
                Some(ep.auth_url.clone())
            };
            let tailscale_ips = ep
                .self_
                .as_ref()
                .map(|s| s.tailscale_i_ps.clone())
                .unwrap_or_default();
            Some(TailscaleStatusEvent {
                server_id,
                backend_state: ep.backend_state.clone(),
                logged_in,
                auth_url,
                tailscale_ips,
                expired,
                peers: flatten_peers(&ep.user_groups),
                details: TailscaleStatusDetails {
                    state_text: ep.state_text.clone(),
                    network_name: ep.network_name.clone(),
                    magic_dns_suffix: ep.magic_dns_suffix.clone(),
                    key_auth: ep.key_auth,
                    self_peer: ep.self_.as_ref().map(lean_peer),
                    user_groups: ep
                        .user_groups
                        .iter()
                        .map(|group| TailscaleUserGroupStatus {
                            user_id: group.user_id,
                            login_name: group.login_name.clone(),
                            display_name: group.display_name.clone(),
                            profile_pic_url: group.profile_pic_url.clone(),
                            peers: group.peers.iter().map(lean_peer).collect(),
                        })
                        .collect(),
                    exit_node: ep.exit_node.as_ref().map(lean_peer),
                },
                can_share_files: ep.can_share_files,
                waiting_file_count: ep.waiting_file_count,
                receiving_file_count: ep.receiving_file_count,
                unread_file_count: ep.unread_file_count,
            })
        })
        .collect()
}

// ── item6 / row31：选中 TS 出口无效直判（`ProxyExitBlock` 信号源的纯谓词核）─────────────────────
//
// 1:1 移植自 上游 `shared/tailscale-exit-warning.ts`。解锁 gating（`unlock_gate_reason`）与状态栏
// 出口角标共用此谓词判「选中 TS 出口是否失效」，避免死出口检测空转就绪门数十秒。

use polaris_config_engine::user_config::server_config::{Protocol, ServerConfig};

/// TS 出口告警（前三态 1:1 上游 `TsExitWarning`；`NeedsAuth` 为本仓新增）。`None` = 无告警。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsExitWarning {
    /// 出口有效或不适用（未选 TS / 直连 / 非终局的未登录）。
    None,
    /// 选中 TS 作出口，但控制面明说这份凭据不能用（NeedsLogin / NeedsMachineAuth / 已过期）
    /// ⇒ 该 endpoint 从未认证成功，**永不承载流量**。**上游 无此态**（其渲染层拿不到
    /// `backendState`，只有一次性登录 toast），2026-07-31 真机上正是这一格静默：
    /// 日志 `Waiting for authentication` ×6、`Running` ×0、tailscale outbound 仅 2 条计数，
    /// 而 UI 全绿。判据是控制面终局否定，不是超时猜测。
    NeedsAuth,
    /// 选中 TS 但无 exit_node（公网不经 TS）。
    NoExitDevice,
    /// exit_node 对应 peer 离线。
    ExitDeviceOffline,
    /// exit_node 对应 peer 在线但未广告可当出口 → 流量出不去。
    ExitDeviceNotAdvertised,
}

/// 这一帧 STATUS 是否**终局否定**（definitive-out：控制面明说凭据不能用）。
///
/// 与前端 `domain/tailscale-conn-state.ts::isDefinitiveTsLoginFrame` 的 definitive-out 分支同口径
/// （那边多一条 `loggedIn → true` 的 definitive-in，是登录态判决门用的；此处只问「否定得算数吗」）。
/// **启动过渡帧不算**：`NoState` / `Stopped` 折叠出的 `logged_in=false` 说的是「核还没启完」。
#[must_use]
pub fn is_definitive_logged_out(ev: &TailscaleStatusEvent) -> bool {
    !ev.logged_in
        && (ev.expired || matches!(ev.backend_state.as_str(), "NeedsLogin" | "NeedsMachineAuth"))
}

/// [`derive_ts_exit_warning`] 输入（1:1 上游 `TsExitWarningInput`）。
pub struct TsExitWarningInput<'a> {
    /// 当前选中的出口节点（`selectedServerId` 对应；None = 未选中）。
    pub selected: Option<&'a ServerConfig>,
    /// 选中 TS 节点是否已登录（STATUS backendState ∈ {Running,Starting} 且 self 未过期）。
    pub logged_in: bool,
    /// 是否显式全直连模式（direct）。
    pub proxy_mode_direct: bool,
    /// 主核是否运行（= STATUS 流 live；离线/未认证判定均须新鲜帧，防据陈旧帧误判）。
    pub proxy_running: bool,
    /// 选中 TS 节点末帧 peers（STATUS 缓存）。
    pub peers: &'a [TailscaleStatusPeer],
    /// 该帧是否**终局否定**（[`is_definitive_logged_out`]；无帧 → false）。与 `peers`/`logged_in`
    /// 必须取自**同一帧**，调用方一次 `map_or` 一并投影。
    pub definitive_logged_out: bool,
}

/// 选中 TS 出口无效判定（纯谓词，1:1 上游 `deriveTsExitWarning`）。判定顺序即 §G 方向反转口径：
/// 未选 TS / 直连 / 未登录 → 永不告警；有 TS 但无 exit_node → NoExitDevice（配置态，断开也提示）；
/// 有 exit_node 但需新鲜 STATUS 才判 peer 离线/未广告（`proxy_running=false` 时保守返 None 防陈旧误报）。
#[must_use]
pub fn derive_ts_exit_warning(i: &TsExitWarningInput) -> TsExitWarning {
    let Some(s) = i.selected else {
        return TsExitWarning::None; // 未选中 → 永不告警
    };
    if s.protocol != Protocol::Tailscale {
        return TsExitWarning::None; // 非 TS 出口 → 方向反转不适用
    }
    if i.proxy_mode_direct {
        return TsExitWarning::None; // 显式全直连
    }
    // 认证态优先：endpoint 没认证成功就根本不承载流量，此时报「没选出口设备」是指错方向。
    // 三重门：核在跑（帧新鲜）+ 该帧终局否定（无帧 → definitive_logged_out=false，不猜）。
    if i.proxy_running && i.definitive_logged_out {
        return TsExitWarning::NeedsAuth;
    }
    if !i.logged_in {
        return TsExitWarning::None; // 其余未登录（启动过渡/无帧）：登录角标/toast 已 own，不叠加
    }
    let exit_node = s
        .tailscale_settings
        .as_ref()
        .and_then(|t| t.exit_node.as_deref())
        .map(str::trim)
        .filter(|e| !e.is_empty());
    let Some(exit_node) = exit_node else {
        return TsExitWarning::NoExitDevice; // 无 exit_node → 公网不经 TS（不信 allowInternet）
    };
    if !i.proxy_running {
        return TsExitWarning::None; // offline/未广告判定须新鲜 STATUS，陈旧 snapshot 会误报
    }
    // exit_node 值与 peer 匹配（ip / hostName 口径）；匹配到才判，自定义值不匹配 → 不误报。
    let peer = i
        .peers
        .iter()
        .find(|p| p.ip == exit_node || p.host_name == exit_node);
    if let Some(p) = peer {
        if !p.online {
            return TsExitWarning::ExitDeviceOffline; // 离线优先（离线态 exit_node_option 可能陈旧）
        }
        if !p.exit_node_option {
            return TsExitWarning::ExitDeviceNotAdvertised; // 在线但未广告出口 → 流量出不去
        }
    }
    TsExitWarning::None
}

/// 「选中 TS 出口是否失效」布尔（上游 `selectedTsExitBlock` 的 bool 投影；供 [`crate::runtime::unlock::
/// unlock_gate_reason`] 的 `exit_blocked` 输入）。新鲜度守卫已内建于 [`derive_ts_exit_warning`]
/// （offline/not-advertised 在 `proxy_running=false` 时已提前返 None），故此处 `warning != None` 即为失效。
#[must_use]
pub fn selected_ts_exit_blocked(i: &TsExitWarningInput) -> bool {
    !matches!(derive_ts_exit_warning(i), TsExitWarning::None)
}

#[cfg(test)]
mod tests;
