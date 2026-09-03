//! WireGuard/Tailscale endpoint 构造（上游 `buildWireGuardEndpoint` + `buildTailscaleEndpoint`）。

#![forbid(unsafe_code)]

use crate::builder::endpoint_routes::{
    mesh_node_carries_full_tunnel, mesh_uses_system_interface, wireguard_peer_allowed_ips,
    TS_SYSTEM_INTERFACE_NAME, WG_SYSTEM_INTERFACE_NAME,
};
use crate::singbox::{DomainResolver, Endpoint, WireGuardPeer};
use crate::user_config::ip::is_ip_literal;
use crate::user_config::server_config::{Protocol, ServerConfig};

/// Taildrop 收件目录相对 `state_dir` 的子目录名。取与内核默认值相同的字面量（`"Taildrop"`），
/// 差别只在**我们把它锚成绝对路径**、不让它跟着 CWD 漂 —— 见
/// [`crate::singbox::Endpoint::taildrop_directory`]。
const TAILDROP_SUBDIR: &str = "Taildrop";

/// OpenConnect / OpenVPN 客户端 endpoint 的共享构造器。
/// 两者的设置结构 serde 名就是 sing-box wire 键，因此整体 flatten 到 `extra`；主核与临时测速核
/// 必须走同一入口，防止后者只生成 `type/tag` 空壳却仍被误判为“可测”。
pub fn build_vpn_client_endpoint(
    server: &ServerConfig,
    tag: &str,
    domain_resolver: Option<&DomainResolver>,
) -> Result<Endpoint, String> {
    let payload = match server.protocol {
        Protocol::Openconnect => server
            .openconnect_settings
            .as_ref()
            .and_then(|settings| serde_json::to_value(settings).ok()),
        Protocol::OpenvpnClient => server
            .openvpn_client_settings
            .as_ref()
            .and_then(|settings| serde_json::to_value(settings).ok()),
        _ => return Err("节点不是 OpenConnect/OpenVPN 客户端 endpoint".to_owned()),
    };
    let extra = match payload {
        Some(serde_json::Value::Object(extra)) => extra,
        _ => serde_json::Map::new(),
    };
    Ok(Endpoint {
        type_field: crate::builder::outbound::protocol_str(server.protocol),
        tag: tag.to_owned(),
        domain_resolver: domain_resolver.cloned(),
        extra,
        ..Default::default()
    })
}

/// WireGuard endpoint 构造。上游 `buildWireGuardEndpoint`。
/// domain_resolver + platform + tailscale_state_dir（路径）注入。
///
/// `domain_resolver` **纯透传**（#335）：本函数不构造也不给默认值，调用方用
/// [`get_node_dial_domain_resolver`](crate::builder::helpers::get_node_dial_domain_resolver) 备好。
/// 类型是 [`DomainResolver`] 而非 `&str`，新增 call site 塞裸 tag 会编译失败而非静默回落未修形态。
/// `None` 仍表示「不下发」（IP 直拨节点、以及 `endpoint_routes` 的可构造性预检）。
///
/// `detour_tag` = 前置代理的 **outbound tag**（已由调用方经 id→tag 映射解析 + 排除 endpoint 目标，
/// 见 `builder/outbounds.rs#resolve_detour_tag`；本函数不做解析，也不接受 server id）。
/// 这是对 上游的**有意偏离**（上游的 WG 表单与 `SingBoxEndpoint` 都没有 detour），
/// 语义实测与「前置代理必须支持 UDP 转发」这条硬约束见 `singbox/endpoint.rs` 的 `Endpoint::detour`。
pub fn build_wireguard_endpoint(
    server: &ServerConfig,
    tag: &str,
    domain_resolver: Option<&DomainResolver>,
    platform: &str,
    detour_tag: Option<&str>,
) -> Result<Endpoint, String> {
    let s = server
        .wireguard_settings
        .as_ref()
        .ok_or("WireGuard 配置缺失 wireguardSettings")?;
    let private_key = s.private_key.clone().ok_or("WireGuard 缺少 privateKey")?;
    let peer_public_key = s
        .peer_public_key
        .clone()
        .ok_or("WireGuard 缺少 peerPublicKey")?;
    if s.local_address.is_empty() {
        return Err("WireGuard 缺少 localAddress".into());
    }

    let allowed_ips = wireguard_peer_allowed_ips(server).ok_or_else(|| {
        "WireGuard 节点无可路由网段（关外网或 system 内核接口且无具体段）：空 allowed_ips 致 FATAL".to_string()
    })?;

    // 域名 server 才需 domain_resolver（IP 直拨无需）。
    let needs_resolver = domain_resolver.is_some() && !is_ip_literal(&server.address);
    let uses_system = mesh_uses_system_interface(server);

    let mut ep = Endpoint {
        type_field: "wireguard".into(),
        tag: tag.to_string(),
        domain_resolver: None,
        detour: detour_tag.map(String::from),
        extra: serde_json::Map::new(),
        system: None,
        mtu: None,
        address: None,
        private_key: None,
        listen_port: None,
        peers: None,
        udp_timeout: None,
        workers: None,
        auth_key: None,
        state_directory: None,
        control_url: None,
        hostname: None,
        exit_node: None,
        exit_node_allow_lan_access: None,
        accept_routes: None,
        ephemeral: None,
        advertise_routes: None,
        system_interface: None,
        system_interface_name: None,
        name: None,
        advertise_tags: None,
        ssh_server: None,
        relay_server_port: None,
        taildrop_directory: None,
    };

    if needs_resolver {
        ep.domain_resolver = domain_resolver.cloned();
    }
    ep.system = Some(uses_system);
    if uses_system && platform != "darwin" {
        ep.name = Some(WG_SYSTEM_INTERFACE_NAME.to_string());
    }
    let default_mtu = if crate::warp::is_warp_server(server) {
        crate::warp::WARP_MTU
    } else {
        1408
    };
    ep.mtu = Some(s.mtu.filter(|mtu| *mtu > 0).unwrap_or(default_mtu));
    ep.address = Some(s.local_address.clone());
    ep.private_key = Some(private_key);
    let mut peer = WireGuardPeer {
        address: server.address.clone(),
        port: server.port,
        public_key: peer_public_key,
        pre_shared_key: s.pre_shared_key.clone(),
        allowed_ips,
        // 缺省按 Polaris 既有策略回落 25 秒；显式 0 遵循 WireGuard 语义关闭保活。
        persistent_keepalive_interval: Some(s.persistent_keepalive.unwrap_or(25)),
        reserved: None,
    };
    if s.reserved.len() == 3 {
        peer.reserved = Some(s.reserved.clone());
    }
    ep.peers = Some(vec![peer]);

    Ok(ep)
}

/// Tailscale endpoint 构造。上游 `buildTailscaleEndpoint`。
/// state_dir 注入（生产 = UserData/tailscale/`<id>`，对拍 = 固定假路径）。
///
/// `detour_tag` 同 [`build_wireguard_endpoint`]：已解析好的 outbound tag，本函数不做解析。
/// 对 上游的有意偏离；TS 侧经前置代理的是**控制面 / DERP 的 TCP 拨号**（异于 WG 的 UDP），
/// 实测见 `singbox/endpoint.rs` 的 `Endpoint::detour`。
pub fn build_tailscale_endpoint(
    server: &ServerConfig,
    tag: &str,
    state_dir: &str,
    platform: &str,
    detour_tag: Option<&str>,
) -> Endpoint {
    // 只读，故借而不拷（与 `builder/outbound.rs` 的 snell 那处同型、同修法）。
    // 此前写的是 `.clone().unwrap_or_default()` —— 装箱后 Some/None **两支各多一次堆分配**
    // （`Box::clone` 先 alloc 再深拷；`Box::<T>::default()` 也 alloc），而 `ts` 在本函数里
    // 全程只读（10 个字段访问点，零写入）。调用点 `builder/outbounds.rs` 在每节点循环里。
    let fallback;
    let ts = match server.tailscale_settings.as_deref() {
        Some(ts) => ts,
        None => {
            fallback = crate::user_config::server_config::TailscaleSettings::default();
            &fallback
        }
    };
    let mut ep = Endpoint {
        type_field: "tailscale".into(),
        tag: tag.to_string(),
        domain_resolver: None,
        detour: detour_tag.map(String::from),
        extra: serde_json::Map::new(),
        system: None,
        mtu: None,
        address: None,
        private_key: None,
        listen_port: None,
        peers: None,
        udp_timeout: None,
        workers: None,
        auth_key: ts
            .auth_key
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        state_directory: Some(state_dir.to_string()),
        control_url: ts
            .control_url
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        hostname: ts
            .hostname
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        exit_node: None,
        exit_node_allow_lan_access: None,
        accept_routes: None,
        ephemeral: None,
        advertise_routes: None,
        system_interface: None,
        system_interface_name: None,
        name: None,
        advertise_tags: None,
        ssh_server: None,
        relay_server_port: None,
        // 恒填绝对路径，绝不留给内核默认值 —— 默认是相对的 `Taildrop`，按核进程 CWD 解析后
        // 无条件 mkdir。为什么这是硬约束（含 Windows helper 那条 CWD 腿）见
        // [`crate::singbox::Endpoint::taildrop_directory`]。
        // 落在 state_dir 之下而不是与之并列：state_dir 已按节点 id 分好、随节点删除一起清理，
        // 收件目录跟着走即天然隔离；同时它是 state_dir 的**子目录**，peer 送来的文件名不可能
        // 撞上 `tailscaled.state` 这类密钥文件。
        taildrop_directory: Some(format!("{state_dir}/{TAILDROP_SUBDIR}")),
    };

    // exit_node 仅承载全隧道时下发。
    if mesh_node_carries_full_tunnel(server) {
        if let Some(en) = &ts.exit_node {
            let en = en.trim();
            if !en.is_empty() {
                ep.exit_node = Some(en.to_string());
                ep.exit_node_allow_lan_access = if ts.exit_node_allow_lan_access == Some(true) {
                    Some(true)
                } else {
                    None
                };
            }
        }
    }
    ep.accept_routes = if ts.accept_routes == Some(true) {
        Some(true)
    } else {
        None
    };
    ep.ephemeral = if ts.ephemeral == Some(true) {
        Some(true)
    } else {
        None
    };
    let adv: Vec<String> = ts
        .advertise_routes
        .iter()
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty())
        .collect();
    if !adv.is_empty() {
        ep.advertise_routes = Some(adv);
    }
    let adv_tags: Vec<String> = ts
        .advertise_tags
        .iter()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();
    if !adv_tags.is_empty() {
        ep.advertise_tags = Some(adv_tags);
    }
    ep.ssh_server = if ts.ssh_server == Some(true) {
        Some(true)
    } else {
        None
    };
    if let Some(p) = ts.relay_server_port {
        if p > 0 {
            ep.relay_server_port = Some(p);
        }
    }
    // `0` = 内核语义里的「自动选端口」（= 不设）。与 relay_server_port 同一口径：不把等价于默认值的
    // 显式 0 写进配置，免得日后上游改默认时磁盘上躺着一份冻结的旧默认。
    if let Some(p) = ts.listen_port {
        if p > 0 {
            ep.listen_port = Some(p);
        }
    }
    // Phase 2 reverseMesh → system_interface。
    if mesh_uses_system_interface(server) {
        ep.system_interface = Some(true);
        if platform != "darwin" {
            ep.system_interface_name = Some(TS_SYSTEM_INTERFACE_NAME.to_string());
        }
    }

    ep
}

#[cfg(test)]
mod tests;
