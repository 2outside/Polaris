use super::*;
use crate::user_config::server_config::{Protocol, ServerConfig, WireGuardSettings};

#[test]
fn wg_endpoint_basic() {
    let mut s = ServerConfig {
        id: "w1".into(),
        name: "WG".into(),
        protocol: Protocol::Wireguard,
        address: "1.2.3.4".into(),
        port: 51820,
        ..Default::default()
    };
    s.wireguard_settings = Some(Box::new(WireGuardSettings {
        private_key: Some("priv".into()),
        peer_public_key: Some("pub".into()),
        local_address: vec!["10.0.0.2/32".into()],
        allow_internet: Some(true),
        ..Default::default()
    }));
    let dial = crate::builder::helpers::get_node_dial_domain_resolver("dns-bootstrap", false);
    let ep = build_wireguard_endpoint(&s, "tag-w1", Some(&dial), "linux", None).unwrap();
    assert_eq!(ep.type_field, "wireguard");
    assert_eq!(ep.mtu, Some(1408));
    assert_eq!(ep.peers.as_ref().unwrap()[0].address, "1.2.3.4");
    // allowInternet=on → allowed_ips 含 0/0。
    assert!(ep.peers.as_ref().unwrap()[0]
        .allowed_ips
        .contains(&"0.0.0.0/0".to_string()));
}

#[test]
fn wg_unroutable_errors() {
    let mut s = ServerConfig {
        id: "w1".into(),
        name: "WG".into(),
        protocol: Protocol::Wireguard,
        address: "1.2.3.4".into(),
        port: 51820,
        ..Default::default()
    };
    s.wireguard_settings = Some(Box::new(WireGuardSettings {
        private_key: Some("priv".into()),
        peer_public_key: Some("pub".into()),
        local_address: vec!["10.0.0.2/32".into()],
        allow_internet: Some(false), // 关外网
        allowed_ips: vec![],         // 无具体段
        ..Default::default()
    }));
    assert!(build_wireguard_endpoint(&s, "tag", None, "linux", None).is_err());
}

#[test]
fn ts_endpoint_exit_node_when_full_tunnel() {
    let mut s = ServerConfig {
        id: "t1".into(),
        name: "TS".into(),
        protocol: Protocol::Tailscale,
        ..Default::default()
    };
    s.tailscale_settings = Some(Box::new(
        crate::user_config::server_config::TailscaleSettings {
            exit_node: Some("exit-peer".into()),
            ..Default::default()
        },
    ));
    let ep = build_tailscale_endpoint(&s, "tag-t1", "/fake/ts/t1", "linux", None);
    // exit_node 设 → mesh_allows_internet=true → exit_node 下发。
    assert_eq!(ep.exit_node.as_deref(), Some("exit-peer"));
}

/// `taildrop_directory` **恒下发且恒绝对**（1.14.0-beta.15）。
///
/// 这条不是「多测一个字段」：金样快照里**一个 tailscale endpoint 都没有**，
/// 整套 golden/`sing-box check` 对拍对本字段的检出力恒为 0 —— 缺了这条断言，
/// 把它改回 `None`（= 回落到内核那个跟着 CWD 漂的相对默认值）不会红任何门。
#[test]
fn ts_endpoint_always_pins_taildrop_directory_under_state_dir() {
    let mut s = ServerConfig {
        id: "t1".into(),
        name: "TS".into(),
        protocol: Protocol::Tailscale,
        ..Default::default()
    };
    // 用户一个 tailscale 设置都没填的最小形态：本字段仍须下发。
    s.tailscale_settings = Some(Default::default());
    let ep = build_tailscale_endpoint(&s, "tag-t1", "/fake/ts/t1", "linux", None);
    let dir = ep
        .taildrop_directory
        .as_deref()
        .expect("taildrop_directory 必须下发，不得留给内核相对默认值");
    assert_eq!(dir, "/fake/ts/t1/Taildrop");
    // 绝对性是本字段存在的**唯一理由**：相对路径会被内核按核进程 CWD 解析。
    assert!(
        dir.starts_with('/') || dir.as_bytes().get(1) == Some(&b':'),
        "必须是绝对路径（unix `/…` 或 Windows `X:\\…`），实得 {dir}"
    );
    assert!(
        dir.starts_with("/fake/ts/t1"),
        "须落在该节点自己的 state_dir 之下，随节点一起清理，实得 {dir}"
    );
}

/// `listen_port`：填了才下发，`0` 与未填一律不下发。
///
/// 同 `taildrop_directory` 那条的理由 —— 金样里零个 tailscale endpoint，对拍抓不到这条接线；
/// 而 `Endpoint.listen_port` 是 WG 腿也在用的**共用字段**，接错了不会编译失败，只会静默不发。
#[test]
fn ts_endpoint_emits_listen_port_only_when_set_nonzero() {
    fn ep_with(port: Option<u16>) -> Endpoint {
        let mut s = ServerConfig {
            id: "t1".into(),
            name: "TS".into(),
            protocol: Protocol::Tailscale,
            ..Default::default()
        };
        s.tailscale_settings = Some(Box::new(
            crate::user_config::server_config::TailscaleSettings {
                listen_port: port,
                ..Default::default()
            },
        ));
        build_tailscale_endpoint(&s, "tag-t1", "/fake/ts/t1", "linux", None)
    }
    assert_eq!(ep_with(Some(41641)).listen_port, Some(41641));
    // 0 = 内核的「自动选端口」，等价未设 ⇒ 不写进配置。
    assert_eq!(ep_with(Some(0)).listen_port, None);
    assert_eq!(ep_with(None).listen_port, None);
}

/// WireGuard 腿**不得**下发 `taildrop_directory`（该键只属 tailscale endpoint）。
#[test]
fn wg_endpoint_never_sets_taildrop_directory() {
    let s = ServerConfig {
        id: "w1".into(),
        name: "WG".into(),
        protocol: Protocol::Wireguard,
        address: "1.2.3.4".into(),
        port: 51820,
        wireguard_settings: Some(Box::new(WireGuardSettings {
            private_key: Some("priv".into()),
            peer_public_key: Some("pub".into()),
            local_address: vec!["10.0.0.2/32".into()],
            ..Default::default()
        })),
        ..Default::default()
    };
    let ep = build_wireguard_endpoint(&s, "tag-w1", None, "linux", None).unwrap();
    assert_eq!(ep.taildrop_directory, None);
}

/// 落盘态直达生成器：`reverseMesh:true` 的 WARP 节点**不得**发出 `system:true` / 接口名。
///
/// 谓词单测（`endpoint_routes.rs`）只钉判据；这条钉的是**发射面** —— 判据与 `ep.system`
/// 之间的接线断了（比如有人把 `ep.system = Some(uses_system)` 改成 `Some(reverse_mesh)`），
/// 谓词测试照绿，而磁盘上的 WARP 节点照样 FATAL。
#[test]
fn warp_endpoint_policy_differs_from_plain_wireguard() {
    fn wg(address: &str) -> ServerConfig {
        ServerConfig {
            id: "w1".into(),
            name: "WARP".into(),
            protocol: Protocol::Wireguard,
            address: address.into(),
            port: 2408,
            wireguard_settings: Some(Box::new(WireGuardSettings {
                private_key: Some("priv".into()),
                peer_public_key: Some("pub".into()),
                local_address: vec!["172.16.0.2/32".into()],
                reverse_mesh: Some(true),
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    // 非 darwin 才会下发接口名 → 用 linux 让「接口名也没漏出去」这条断言有意义。
    let warp = build_wireguard_endpoint(
        &wg("engage.cloudflareclient.com"),
        "tag",
        None,
        "linux",
        None,
    )
    .expect("WARP endpoint 应能构建");
    assert_eq!(warp.system, Some(false), "WARP 不得发 system:true");
    assert_eq!(warp.name, None, "WARP 不得占用内核接口名");
    assert_eq!(warp.mtu, Some(crate::warp::WARP_MTU));

    // 反向对照：同样的 reverseMesh:true，普通 WG 仍应发 system:true + 接口名。
    let plain = build_wireguard_endpoint(&wg("vpn.example.com"), "tag", None, "linux", None)
        .expect("普通 WG endpoint 应能构建");
    assert_eq!(plain.system, Some(true));
    assert_eq!(plain.name.as_deref(), Some(WG_SYSTEM_INTERFACE_NAME));
    assert_eq!(plain.mtu, Some(1408));

    // 用户显式设置始终优先于协议缺省值。
    let mut custom = wg("engage.cloudflareclient.com");
    let settings = custom.wireguard_settings.as_mut().unwrap();
    settings.mtu = Some(1360);
    settings.persistent_keepalive = Some(0);
    let custom = build_wireguard_endpoint(&custom, "tag", None, "linux", None)
        .expect("显式 MTU 的 WARP endpoint 应能构建");
    assert_eq!(custom.mtu, Some(1360));
    assert_eq!(
        custom.peers.unwrap()[0].persistent_keepalive_interval,
        Some(0),
        "显式 0 应关闭保活，不能被改写回 25 秒"
    );
}
