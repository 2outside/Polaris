use super::*;

mod exit_warning_tests;

fn tag_map() -> BTreeMap<String, String> {
    // tag "东京 03" → serverId "srv-tokyo"（build_id_to_tag_map 逆映射的一条）。
    BTreeMap::from([("东京 03".to_string(), "srv-tokyo".to_string())])
}

fn peer(host: &str, ips: &[&str]) -> daemon::TailscalePeer {
    daemon::TailscalePeer {
        host_name: host.to_string(),
        tailscale_i_ps: ips.iter().map(|s| s.to_string()).collect(),
        online: true,
        exit_node_option: true,
        stable_id: "sid".to_string(),
        ..Default::default()
    }
}

fn running_endpoint(tag: &str) -> daemon::TailscaleEndpointStatus {
    daemon::TailscaleEndpointStatus {
        endpoint_tag: tag.to_string(),
        backend_state: "Running".to_string(),
        auth_url: String::new(),
        self_: Some(daemon::TailscalePeer {
            host_name: "self".to_string(),
            tailscale_i_ps: vec!["100.64.0.9".to_string()],
            expired: false,
            ..Default::default()
        }),
        user_groups: vec![daemon::TailscaleUserGroup {
            peers: vec![peer("box-a", &["100.64.0.1"])],
            user_id: 7,
            login_name: "owner@example.com".to_string(),
            display_name: "Owner".to_string(),
            profile_pic_url: "https://profiles.example.com/owner".to_string(),
        }],
        exit_node: None,
        state_text: "connected".to_string(),
        network_name: "example-tailnet".to_string(),
        magic_dns_suffix: "example.ts.net".to_string(),
        key_auth: true,
        ..Default::default()
    }
}

/// 幽灵过滤：tag 不在 tag_to_id → 丢弃。打断（不过滤 / 用空串兜底 id）→ 转红。
#[test]
fn ghost_endpoint_filtered_out() {
    let update = daemon::TailscaleStatusUpdate {
        endpoints: vec![running_endpoint("不在册的节点")],
    };
    let out = decode_tailscale_status(&update, &tag_map());
    assert!(out.is_empty(), "tag 不在册 → 端点必须被丢弃（幽灵过滤）");
}

/// 在册端点 → 映射 serverId + backendState Running → loggedIn=true + self IP + peers 摊平。
#[test]
fn running_endpoint_maps_to_logged_in_event() {
    let update = daemon::TailscaleStatusUpdate {
        endpoints: vec![running_endpoint("东京 03")],
    };
    let out = decode_tailscale_status(&update, &tag_map());
    assert_eq!(out.len(), 1);
    let ev = &out[0];
    assert_eq!(ev.server_id, "srv-tokyo");
    assert_eq!(ev.backend_state, "Running");
    assert!(ev.logged_in, "Running 且未过期 → loggedIn");
    assert_eq!(ev.tailscale_ips, vec!["100.64.0.9".to_string()]);
    assert_eq!(ev.peers.len(), 1);
    assert_eq!(ev.peers[0].host_name, "box-a");
    assert_eq!(ev.peers[0].ip, "100.64.0.1");
    assert_eq!(ev.peers[0].stable_id.as_deref(), Some("sid"));
    assert_eq!(ev.details.network_name, "example-tailnet");
    assert_eq!(ev.details.magic_dns_suffix, "example.ts.net");
    assert!(ev.details.key_auth);
    assert_eq!(ev.details.user_groups[0].user_id, 7);
    assert_eq!(ev.details.user_groups[0].login_name, "owner@example.com");
}

/// loggedIn 判定：key 过期 → 即使 Running 也 loggedIn=false。打断「且未过期」→ 转红。
#[test]
fn expired_key_forces_logged_out_even_when_running() {
    let mut ep = running_endpoint("东京 03");
    ep.self_.as_mut().unwrap().expired = true;
    let update = daemon::TailscaleStatusUpdate {
        endpoints: vec![ep],
    };
    let ev = &decode_tailscale_status(&update, &tag_map())[0];
    assert!(ev.expired);
    assert!(!ev.logged_in, "key 过期 → 不算登录（防陈旧绿标）");
}

/// NeedsLogin + authURL → loggedIn=false + authUrl 携带。打断「Running/Starting 才 loggedIn」（如恒 true）→ 转红。
#[test]
fn needs_login_carries_auth_url_and_not_logged_in() {
    let mut ep = running_endpoint("东京 03");
    ep.backend_state = "NeedsLogin".to_string();
    ep.auth_url = "https://login.tailscale.com/a/abc".to_string();
    let update = daemon::TailscaleStatusUpdate {
        endpoints: vec![ep],
    };
    let ev = &decode_tailscale_status(&update, &tag_map())[0];
    assert!(!ev.logged_in);
    assert_eq!(
        ev.auth_url.as_deref(),
        Some("https://login.tailscale.com/a/abc")
    );
}

/// peers 去重（同 hostName 只留一条）+ IPv4 优先取 IP。打断去重 → len 转红；打断 pick_ip → ip 转红。
#[test]
fn peers_dedup_by_hostname_and_prefer_ipv4() {
    let mut ep = running_endpoint("东京 03");
    ep.user_groups = vec![
        daemon::TailscaleUserGroup {
            peers: vec![peer("dup", &["fd7a::1", "100.64.0.5"])],
            ..Default::default()
        },
        daemon::TailscaleUserGroup {
            peers: vec![peer("dup", &["100.64.0.6"])], // 同名 → 去重丢弃
            ..Default::default()
        },
    ];
    let ev = &decode_tailscale_status(&update_of(ep), &tag_map())[0];
    assert_eq!(ev.peers.len(), 1, "同 hostName 去重");
    assert_eq!(ev.peers[0].ip, "100.64.0.5", "IPv4 优先于 v6");
}

fn update_of(ep: daemon::TailscaleEndpointStatus) -> daemon::TailscaleStatusUpdate {
    daemon::TailscaleStatusUpdate {
        endpoints: vec![ep],
    }
}

/// serde 字段名对齐前端契约（authURL / tailscaleIPs / stableID / serverId / backendState / loggedIn）。
/// 打断任一 rename → JSON key 变 → 前端 duck-typing 读不到 → 此断言转红。
#[test]
fn serialized_field_names_match_frontend_contract() {
    let update = daemon::TailscaleStatusUpdate {
        endpoints: vec![running_endpoint("东京 03")],
    };
    let ev = &decode_tailscale_status(&update, &tag_map())[0];
    let v = serde_json::to_value(ev).unwrap();
    assert!(v.get("serverId").is_some());
    assert!(v.get("backendState").is_some());
    assert!(v.get("loggedIn").is_some());
    assert!(v.get("tailscaleIPs").is_some());
    let peer = &v["peers"][0];
    assert!(peer.get("hostName").is_some());
    assert!(peer.get("exitNodeOption").is_some());
    assert_eq!(peer.get("stableID").and_then(|x| x.as_str()), Some("sid"));
}
