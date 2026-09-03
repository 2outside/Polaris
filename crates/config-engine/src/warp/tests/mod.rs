use super::*;
use crate::user_config::protocol_settings::WarpDevice;
use crate::user_config::server_config::WireGuardSettings;

fn wg(address: &str, warp_device: Option<WarpDevice>) -> ServerConfig {
    ServerConfig {
        id: "w".into(),
        name: "w".into(),
        protocol: Protocol::Wireguard,
        address: address.into(),
        port: 2408,
        wireguard_settings: Some(Box::new(WireGuardSettings {
            warp_device,
            ..Default::default()
        })),
        ..Default::default()
    }
}

fn creds() -> WarpDevice {
    WarpDevice {
        device_id: "d".into(),
        token: "t".into(),
    }
}

#[test]
fn warp_by_device_creds() {
    // 有自删凭据 → 即使 address 是裸 IP（注册响应给的 162.159.x）也判 WARP。
    assert!(is_warp_server(&wg("162.159.192.1", Some(creds()))));
}

#[test]
fn warp_by_endpoint_domain_without_creds() {
    // 旧 / 导入 / 上游 迁移来的 WARP：无 warpDevice，只能靠域名兜底 —— 这条漏了就是 FATAL。
    assert!(is_warp_server(&wg("engage.cloudflareclient.com", None)));
    // 大小写不敏感（前端 `.toLowerCase()` 的对应物）。
    assert!(is_warp_server(&wg("ENGAGE.CloudflareClient.COM", None)));
}

#[test]
fn plain_wireguard_is_not_warp() {
    assert!(!is_warp_server(&wg("vpn.example.com", None)));
    assert!(!is_warp_server(&wg("10.0.0.1", None)));
    // wireguardSettings 整体缺失也不能误判。
    assert!(!is_warp_server(&ServerConfig {
        protocol: Protocol::Wireguard,
        address: "vpn.example.com".into(),
        ..Default::default()
    }));
}

#[test]
fn non_wireguard_never_warp() {
    // 协议闸在最前：非 WG 节点即使 address 撞上该域名也不是 WARP。
    assert!(!is_warp_server(&ServerConfig {
        protocol: Protocol::Vless,
        address: "engage.cloudflareclient.com".into(),
        ..Default::default()
    }));
}
