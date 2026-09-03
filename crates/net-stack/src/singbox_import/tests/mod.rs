use super::*;
use serde_json::json;

fn id_gen() -> impl FnMut() -> String {
    let mut n = 0;
    move || {
        n += 1;
        format!("id-{n}")
    }
}

/// 订阅腿（不透传 custom）—— 既有建模映射用例全部走这条，语义与改动前逐字相同。
fn parse(v: Value) -> ClashParseResult {
    parse_with(v, ImportOrigin::RemoteSubscription)
}

/// 本机导入腿（未建模 type 透传 custom）。
fn parse_local(v: Value) -> ClashParseResult {
    parse_with(v, ImportOrigin::LocalFile)
}

fn parse_with(v: Value, origin: ImportOrigin) -> ClashParseResult {
    let mut g = id_gen();
    parse_singbox_outbounds(
        v.get("outbounds").unwrap(),
        "sub1",
        "2026-07-18T00:00:00Z",
        &mut g,
        origin,
    )
}

fn parse_eps(v: Value, origin: ImportOrigin) -> ClashParseResult {
    let mut g = id_gen();
    parse_singbox_endpoints(
        v.get("endpoints").unwrap(),
        "sub1",
        "2026-07-18T00:00:00Z",
        &mut g,
        origin,
    )
}

#[test]
fn vless_ws_tls_full_mapping() {
    let out = parse(json!({ "outbounds": [{
            "type": "vless",
            "tag": "HK-01",
            "server": "a.example.com",
            "server_port": 443,
            "uuid": "uuid-1",
            "flow": "XTLS-RPRX-Vision",
            "packet_encoding": "packetaddr",
            "tls": { "enabled": true, "server_name": "sni.example.com", "insecure": true,
                     "alpn": ["h2", "http/1.1"], "utls": { "fingerprint": "Chrome" } },
            "transport": { "type": "ws", "path": "/ray", "host": "cdn.example.com" }
        }] }));
    assert_eq!(out.servers.len(), 1);
    let s = &out.servers[0];
    assert_eq!(s.name, "HK-01");
    assert_eq!(s.protocol, Protocol::Vless);
    assert_eq!(s.address, "a.example.com");
    assert_eq!(s.port, 443);
    assert_eq!(s.uuid.as_deref(), Some("uuid-1"));
    assert_eq!(s.flow.as_deref(), Some("xtls-rprx-vision"), "flow R4 归一");
    assert_eq!(s.packet_encoding.as_deref(), Some("packetaddr"));
    assert_eq!(s.network.as_deref(), Some("ws"));
    let ws = s.ws_settings.as_ref().unwrap();
    assert_eq!(ws.path.as_deref(), Some("/ray"));
    assert_eq!(
        ws.headers
            .as_ref()
            .and_then(|h| h.get("Host"))
            .map(String::as_str),
        Some("cdn.example.com")
    );
    assert_eq!(s.security, Some(SecurityMode::Tls));
    let tls = s.tls_settings.as_ref().unwrap();
    assert_eq!(tls.server_name.as_deref(), Some("sni.example.com"));
    assert_eq!(tls.allow_insecure, Some(true));
    assert_eq!(
        tls.fingerprint.as_deref(),
        Some("chrome"),
        "fingerprint R4 归一"
    );
    assert_eq!(
        tls.alpn.as_deref(),
        Some(&["h2".to_string(), "http/1.1".to_string()][..])
    );
    assert_eq!(s.subscription_id.as_deref(), Some("sub1"));
}

#[test]
fn vless_reality_mapping() {
    let out = parse(json!({ "outbounds": [{
            "type": "vless", "server": "r.com", "server_port": 443, "uuid": "u",
            "tls": { "enabled": true, "server_name": "sni",
                     "reality": { "enabled": true, "public_key": "PBK", "short_id": "sid" },
                     "utls": { "fingerprint": "chrome" } }
        }] }));
    let s = &out.servers[0];
    assert_eq!(s.security, Some(SecurityMode::Reality));
    let r = s.reality_settings.as_ref().unwrap();
    assert_eq!(r.public_key, "PBK");
    assert_eq!(r.short_id.as_deref(), Some("sid"));
}

#[test]
fn reality_without_public_key_falls_to_tls() {
    // reality.enabled 但缺 public_key → 非 reality（回落 tls）。
    let out = parse(json!({ "outbounds": [{
            "type": "vless", "server": "r.com", "server_port": 443, "uuid": "u",
            "tls": { "enabled": true, "reality": { "enabled": true } }
        }] }));
    assert_eq!(out.servers[0].security, Some(SecurityMode::Tls));
    assert!(out.servers[0].reality_settings.is_none());
}

#[test]
fn tls_disabled_leaves_security_unset() {
    let out = parse(json!({ "outbounds": [{
            "type": "trojan", "server": "t.com", "server_port": 443, "password": "pw",
            "tls": { "enabled": false }
        }] }));
    assert_eq!(out.servers[0].security, None, "tls.enabled:false → 不启用");
    assert!(out.servers[0].tls_settings.is_none());
}

#[test]
fn vmess_grpc_mapping() {
    let out = parse(json!({ "outbounds": [{
            "type": "vmess", "server": "b.com", "server_port": "8443", "uuid": "u2",
            "alter_id": 4, "security": "AES-128-GCM",
            "transport": { "type": "grpc", "service_name": "gsvc" }
        }] }));
    let s = &out.servers[0];
    assert_eq!(s.protocol, Protocol::Vmess);
    assert_eq!(s.port, 8443);
    assert_eq!(s.alter_id, Some(4));
    assert_eq!(
        s.vmess_security.as_deref(),
        Some("aes-128-gcm"),
        "vmessSecurity R4 归一"
    );
    assert_eq!(s.network.as_deref(), Some("grpc"));
    assert_eq!(
        s.grpc_settings
            .as_ref()
            .and_then(|g| g.service_name.as_deref()),
        Some("gsvc")
    );
}

#[test]
fn hysteria2_obfs_and_port_hopping() {
    let out = parse(json!({ "outbounds": [{
            "type": "hysteria2", "server": "hy.com", "server_ports": ["20000:30000"],
            "password": "pw", "hop_interval": "30s",
            "obfs": { "type": "salamander", "password": "obfspw" }
        }] }));
    let s = &out.servers[0];
    assert_eq!(s.protocol, Protocol::Hysteria2);
    assert_eq!(s.port, 20000, "无 server_port → server_ports 首范围低位");
    assert_eq!(s.security, Some(SecurityMode::Tls));
    let hy2 = s.hysteria2_settings.as_ref().unwrap();
    assert_eq!(hy2.server_ports.as_deref(), Some("20000:30000"));
    assert_eq!(hy2.hop_interval.as_deref(), Some("30s"));
    let obfs = hy2.obfs.as_ref().unwrap();
    assert_eq!(obfs.type_field.as_deref(), Some("salamander"));
    assert_eq!(obfs.password.as_deref(), Some("obfspw"));
}

#[test]
fn hysteria2_gecko_obfs_and_bbr_profile() {
    // 订阅下发 gecko 混淆 + min/max_packet_size + bbr_profile（导出侧生成的抗审查/性能字段）。
    let out = parse(json!({ "outbounds": [{
            "type": "hysteria2", "server": "hy.com", "server_port": 443, "password": "pw",
            "obfs": { "type": "gecko", "password": "obfspw",
                      "min_packet_size": 100, "max_packet_size": 1200 },
            "bbr_profile": "aggressive"
        }] }));
    let s = &out.servers[0];
    let hy2 = s.hysteria2_settings.as_ref().unwrap();
    let obfs = hy2.obfs.as_ref().unwrap();
    assert_eq!(obfs.type_field.as_deref(), Some("gecko"));
    assert_eq!(obfs.password.as_deref(), Some("obfspw"));
    assert_eq!(obfs.min_packet_size, Some(100), "gecko 才读 packet_size");
    assert_eq!(obfs.max_packet_size, Some(1200));
    assert_eq!(hy2.bbr_profile.as_deref(), Some("aggressive"));
}

#[test]
fn hysteria2_bbr_profile_unknown_and_salamander_no_packet_size() {
    // 未知 bbr_profile 值不设（graceful）；salamander 不带 packet_size。
    let out = parse(json!({ "outbounds": [{
            "type": "hysteria2", "server": "hy.com", "server_port": 443, "password": "pw",
            "obfs": { "type": "salamander", "password": "s",
                      "min_packet_size": 100, "max_packet_size": 1200 },
            "bbr_profile": "turbo"
        }] }));
    let hy2 = out.servers[0].hysteria2_settings.as_ref().unwrap();
    assert_eq!(hy2.bbr_profile, None, "非枚举域值不设");
    let obfs = hy2.obfs.as_ref().unwrap();
    assert_eq!(obfs.type_field.as_deref(), Some("salamander"));
    assert_eq!(obfs.min_packet_size, None, "salamander 不读 packet_size");
    assert_eq!(obfs.max_packet_size, None);
}

#[test]
fn tls_ech_config_imported() {
    // tls.ech.config（ECHConfigList）为字符串数组（sing-box 1.14）→ 归一多行字符串。
    let out = parse(json!({ "outbounds": [{
            "type": "vless", "server": "e.com", "server_port": 443, "uuid": "u",
            "tls": { "enabled": true, "server_name": "sni",
                     "ech": { "enabled": true, "config": ["ECHLINE1", "ECHLINE2"] } }
        }] }));
    let tls = out.servers[0].tls_settings.as_ref().unwrap();
    assert_eq!(tls.ech, Some(true));
    assert_eq!(
        tls.ech_config.as_deref(),
        Some("ECHLINE1\nECHLINE2"),
        "数组 → \\n 拼接"
    );
}

#[test]
fn tls_ech_config_multiline_string_and_enabled_gates_config() {
    // config 亦容忍单个多行字符串（trim + 去空行）；ech 未开启时不读 config。
    let out = parse(json!({ "outbounds": [
            { "type": "vless", "server": "e.com", "server_port": 443, "uuid": "u",
              "tls": { "enabled": true,
                       "ech": { "enabled": true, "config": "  L1 \n\n L2 " } } },
            { "type": "vless", "server": "e2.com", "server_port": 443, "uuid": "u",
              "tls": { "enabled": true,
                       "ech": { "enabled": false, "config": ["L1"] } } }
        ] }));
    assert_eq!(
        out.servers[0]
            .tls_settings
            .as_ref()
            .unwrap()
            .ech_config
            .as_deref(),
        Some("L1\nL2"),
        "多行字符串 trim + 去空行"
    );
    let t2 = out.servers[1].tls_settings.as_ref().unwrap();
    assert_eq!(t2.ech, None, "enabled:false 不启用");
    assert_eq!(t2.ech_config, None, "ech 未开启不读 config");
}

#[test]
fn round_trip_hysteria2_anti_censorship_fields() {
    // 最强验证：typed 节点 → config-engine 导出 outbound → singbox_import 解析回 → 字段等价。
    use polaris_config_engine::builder::outbound::build_proxy_outbound;
    use polaris_config_engine::singbox::DomainResolver;
    use polaris_config_engine::user_config::protocol_settings::{
        Hysteria2ObfsSettings, Hysteria2Settings, TlsSettings,
    };

    let src = ServerConfig {
        id: "src".into(),
        name: "hy2-anti".into(),
        protocol: Protocol::Hysteria2,
        address: "hy.example.com".into(),
        port: 443,
        password: Some("pw".into()),
        security: Some(SecurityMode::Tls),
        tls_settings: Some(TlsSettings {
            server_name: Some("sni.example.com".into()),
            ech: Some(true),
            ech_config: Some("ECHLINE1\nECHLINE2".into()),
            ..Default::default()
        }),
        hysteria2_settings: Some(Box::new(Hysteria2Settings {
            obfs: Some(Hysteria2ObfsSettings {
                type_field: Some("gecko".into()),
                password: Some("obfspw".into()),
                min_packet_size: Some(100),
                max_packet_size: Some(1200),
            }),
            bbr_profile: Some("aggressive".into()),
            server_ports: Some("20000:30000".into()),
            hop_interval: Some("30s".into()),
            ..Default::default()
        })),
        ..Default::default()
    };

    // 导出（config-engine）→ sing-box outbound JSON → 导入回。
    // 纯 tag：本用例验的是 outbound 的**导出→导入往返闭合**，dial 侧解析器形态与它无关；
    // 用结构化形态只会给 round-trip 断言引入无关噪声。
    let ob = build_proxy_outbound(
        &src,
        "proxy-1",
        &DomainResolver::Tag("dns-bootstrap".to_string()),
        "x64",
        "linux",
    );
    let wrapped = json!({ "outbounds": [serde_json::to_value(&ob).unwrap()] });
    let out = parse(wrapped);

    assert_eq!(out.servers.len(), 1, "round-trip 节点应闭合");
    let s = &out.servers[0];
    assert_eq!(s.protocol, Protocol::Hysteria2);
    assert_eq!(s.security, Some(SecurityMode::Tls));

    let tls = s.tls_settings.as_ref().unwrap();
    assert_eq!(tls.ech, Some(true), "ech 开关闭合");
    assert_eq!(
        tls.ech_config.as_deref(),
        Some("ECHLINE1\nECHLINE2"),
        "ech.config 多行字符串 ←→ 数组 round-trip 闭合"
    );

    let hy2 = s.hysteria2_settings.as_ref().unwrap();
    let obfs = hy2.obfs.as_ref().unwrap();
    assert_eq!(obfs.type_field.as_deref(), Some("gecko"));
    assert_eq!(obfs.password.as_deref(), Some("obfspw"));
    assert_eq!(obfs.min_packet_size, Some(100), "gecko packet_size 闭合");
    assert_eq!(obfs.max_packet_size, Some(1200));
    assert_eq!(
        hy2.bbr_profile.as_deref(),
        Some("aggressive"),
        "bbr_profile 闭合"
    );
    assert_eq!(hy2.server_ports.as_deref(), Some("20000:30000"));
    assert_eq!(hy2.hop_interval.as_deref(), Some("30s"));
}

#[test]
fn tuic_heartbeat_and_congestion() {
    let out = parse(json!({ "outbounds": [{
            "type": "tuic", "server": "tu.com", "server_port": 443, "uuid": "u", "password": "pw",
            "congestion_control": "bbr", "udp_relay_mode": "native",
            "zero_rtt_handshake": true, "heartbeat": 10000
        }] }));
    let s = &out.servers[0];
    let ts = s.tuic_settings.as_ref().unwrap();
    assert_eq!(ts.congestion_control.as_deref(), Some("bbr"));
    assert_eq!(ts.udp_relay_mode.as_deref(), Some("native"));
    assert_eq!(ts.zero_rtt_handshake, Some(true));
    assert_eq!(ts.heartbeat.as_deref(), Some("10000ms"), "纯数字补 ms 单位");
}

#[test]
fn snell_v4_obfs_and_reject_bad_version() {
    let out = parse(json!({ "outbounds": [
            { "type": "snell", "server": "s.com", "server_port": 443, "psk": "k", "version": 4,
              "obfs_mode": "http", "obfs_host": "h.com" },
            { "type": "snell", "server": "s2.com", "server_port": 443, "psk": "k", "version": 3 }, // 坏版本
            { "type": "snell", "server": "s3.com", "server_port": 443, "version": 4 }              // 缺 psk
        ] }));
    assert_eq!(out.servers.len(), 1, "仅合法 v4 入库");
    let s = &out.servers[0];
    assert_eq!(s.protocol, Protocol::Snell);
    assert_eq!(s.password.as_deref(), Some("k"), "psk → password");
    let snell = s.snell_settings.as_ref().unwrap();
    assert_eq!(snell.version, 4);
    assert_eq!(snell.obfs_mode.as_deref(), Some("http"));
    assert_eq!(snell.obfs_host.as_deref(), Some("h.com"));
    assert_eq!(out.failed, 2, "坏版本 + 缺 psk 计 failed");
}

#[test]
fn shadowsocks_and_ssh_mapping() {
    let out = parse(json!({ "outbounds": [
            { "type": "shadowsocks", "server": "ss.com", "server_port": 8388, "method": "aes-256-gcm", "password": "p" },
            { "type": "ssh", "server": "ssh.com", "server_port": 22, "user": "root", "password": "pw",
              "host_key_algorithms": ["ssh-ed25519"] }
        ] }));
    assert_eq!(out.servers.len(), 2);
    let ss = out.servers[0].shadowsocks_settings.as_ref().unwrap();
    assert_eq!(ss.method, "aes-256-gcm");
    assert_eq!(ss.password, "p");
    let ssh_srv = &out.servers[1];
    assert_eq!(ssh_srv.network.as_deref(), Some("tcp"));
    assert_eq!(ssh_srv.security, Some(SecurityMode::None));
    let ssh = ssh_srv.ssh_settings.as_ref().unwrap();
    assert_eq!(ssh.user.as_deref(), Some("root"));
    assert_eq!(
        ssh.host_key_algorithms.as_deref(),
        Some(&["ssh-ed25519".to_string()][..])
    );
}

#[test]
fn skip_internal_unsupported_type_and_transport() {
    let out = parse(json!({ "outbounds": [
            { "type": "direct" },                                        // internal → 不计
            { "type": "selector", "outbounds": [] },                     // internal → 不计
            { "type": "wireguard", "server": "w.com", "server_port": 1 },// 不支持 type → skipped
            { "type": "vless", "server": "q.com", "server_port": 443, "uuid": "u",
              "transport": { "type": "quic" } },                         // 不支持传输 → skipped
            { "type": "trojan", "server": "t.com", "server_port": 443, "password": "p" }
        ] }));
    assert_eq!(out.servers.len(), 1, "仅 trojan 入库");
    assert_eq!(out.skipped, 2, "wireguard(type) + quic(transport)");
    assert!(out.warnings.iter().any(|w| w.contains("wireguard(1)")));
    assert!(out.warnings.iter().any(|w| w.contains("quic(1)")));
}

#[test]
fn missing_server_or_port_counts_failed() {
    let out = parse(json!({ "outbounds": [
            { "type": "vless", "server_port": 443, "uuid": "u" },   // 缺 server
            { "type": "vless", "server": "a.com", "uuid": "u" },    // 缺 port
            { "type": "vless", "server": "", "server_port": 443, "uuid": "u" } // 空 server
        ] }));
    assert_eq!(out.servers.len(), 0);
    assert_eq!(out.failed, 3);
}

#[test]
fn port_zero_and_overflow_rejected() {
    let out = parse(json!({ "outbounds": [
            { "type": "vless", "server": "a.com", "server_port": 0, "uuid": "u" },
            { "type": "vless", "server": "a.com", "server_port": 70000, "uuid": "u" }
        ] }));
    assert_eq!(out.servers.len(), 0, "port 0 / 越界拒");
    assert_eq!(out.failed, 2);
}

#[test]
fn multiplex_and_naive_http3() {
    let out = parse(json!({ "outbounds": [
            { "type": "vless", "server": "a.com", "server_port": 443, "uuid": "u",
              "multiplex": { "enabled": true, "protocol": "smux", "max_connections": 4 } },
            { "type": "naive", "server": "n.com", "server_port": 443, "username": "x", "password": "y", "quic": true }
        ] }));
    let mux = out.servers[0].multiplex_settings.as_ref().unwrap();
    assert_eq!(mux.enabled, Some(true));
    assert_eq!(mux.protocol.as_deref(), Some("smux"));
    assert_eq!(mux.max_connections, Some(4));
    let naive = &out.servers[1];
    assert_eq!(naive.protocol, Protocol::Naive);
    assert_eq!(
        naive.naive_settings.as_ref().and_then(|n| n.use_http3),
        Some(true)
    );
}

#[test]
fn non_array_outbounds_is_empty() {
    let mut g = id_gen();
    let r = parse_singbox_outbounds(
        &json!({}),
        "s",
        "now",
        &mut g,
        ImportOrigin::RemoteSubscription,
    );
    assert_eq!(r.servers.len(), 0);
    assert_eq!((r.skipped, r.failed), (0, 0));
    let mut g2 = id_gen();
    let e = parse_singbox_endpoints(&json!({}), "s", "now", &mut g2, ImportOrigin::LocalFile);
    assert_eq!(e.servers.len(), 0);
    assert_eq!((e.skipped, e.failed), (0, 0));
}

// ── P1：未建模 type → custom 逃生舱 ───────────────────────────────────────────

#[test]
fn local_import_wraps_unmodeled_types_as_custom() {
    // 语料 = 真实存在于内核、Polaris **未建模**的 outbound type。
    // ⚠️ 2026-08-11：hysteria(v1) / tor 已进建模协议，故从本语料移出（它们现在走各自的建模腿，
    // 见 `hysteria_and_tor_map_to_modeled_protocols`）。留下的 shadowtls 是**故意**的：
    // 它在本仓以 shadowsocks 插件形态建模，作为**独立 outbound type** 仍无落点 ⇒ 仍该包 custom。
    let out = parse_local(json!({ "outbounds": [
            { "type": "shadowtls", "server": "st.example.com", "server_port": 443, "version": 3,
              "password": "pw", "tls": { "enabled": true, "server_name": "cdn.example.com" } },
            { "type": "direct", "tag": "direct" },
            { "type": "trojan", "tag": "T", "server": "t.com", "server_port": 443, "password": "p" }
        ] }));
    assert_eq!(out.servers.len(), 2, "1 custom + 1 建模 trojan");
    assert_eq!(out.skipped, 0, "透传后不再计 skipped");
    assert_eq!(out.failed, 0);
    assert!(out.warnings.is_empty(), "透传腿不产「跳过不支持类型」告警");

    // 唯一的 custom：shadowtls（独立 outbound type 无落点）。原文逐字透传。
    let st = &out.servers[0];
    assert_eq!(st.protocol, Protocol::Custom);
    assert_eq!(st.address, "st.example.com");
    assert_eq!(st.port, 443);
    let cs = st.custom_settings.as_ref().unwrap();
    assert_eq!(cs.is_endpoint, None, "outbounds[] 腿不置 isEndpoint");
    assert_eq!(cs.outbound.get("type").unwrap(), "shadowtls");
    assert_eq!(cs.outbound.get("version").unwrap(), 3);
    assert_eq!(cs.outbound.get("password").unwrap(), "pw");

    assert_eq!(out.servers[1].protocol, Protocol::Trojan, "建模腿不受影响");
}

#[test]
fn remote_subscription_never_wraps_custom() {
    // 反向对照（信任级分流）：**同一份**输入走订阅腿 → 一个 custom 都不产，仍旧 skipped + 告警。
    // 这条是安全不变量：custom 逃传把原文逐字下发内核，而 `tor` outbound 收
    // `executable_path`/`extra_args`（随包核 1.14.0-beta.7 `sing-box check` rc=0）
    // ⇒ 远端订阅一旦能造 custom 即等于任意本机命令执行。
    let doc = json!({ "outbounds": [
            { "type": "hysteria", "tag": "HY1-JP", "server": "hy1.example.com", "server_port": 8443 },
            { "type": "tor", "tag": "Tor", "executable_path": "/usr/bin/tor" },
            { "type": "trojan", "tag": "T", "server": "t.com", "server_port": 443, "password": "p" }
        ] });
    let out = parse(doc);
    // 2026-08-11：hysteria(v1) 已建模 ⇒ 订阅腿正常收它（它没有命令执行向量，与 tor 不同）。
    // tor 仍被跳过：`executable_path`/`extra_args` = 起任意本机程序，只许本地文件。
    assert_eq!(
        out.servers.len(),
        2,
        "建模 trojan + 建模 hysteria；tor 被信任级分流挡下"
    );
    assert!(out.servers.iter().all(|s| s.protocol != Protocol::Custom));
    assert!(
        out.servers.iter().all(|s| s.protocol != Protocol::Tor),
        "tor 从订阅入库了 —— executable_path 等于任意本机命令执行"
    );
    // 🔴 订阅腿**不填透传袋**：袋里任意键会随配置下发，而未知字段是 decode 阶段拒收
    // ⇒ 远端塞个乱键就能让整个核起不来。
    let hy = out
        .servers
        .iter()
        .find(|s| s.protocol == Protocol::Hysteria)
        .expect("hysteria 没入库");
    assert!(
        hy.hysteria_settings.as_ref().unwrap().extra.is_empty(),
        "订阅腿填了透传袋 —— 远端可借未知字段让整个核 decode 失败"
    );
    assert_eq!(out.skipped, 1);
    assert!(out.warnings.iter().any(|w| w.contains("tor(1)")));
}

/// **逃生舱的价值验在这里**：导入产出的 custom 节点经 config-engine 生成回 sing-box outbound，
/// 未建模字段一个不少 —— 否则 P1 只是「从直接丢弃变成留下来但被吃掉」，不值得做。
///
/// 锁的是与 `098b41e`（`Outbound::extra` 真透传）的接线：那条修复回退成窄 struct
/// `from_value` 的话，`up_mbps`/`auth_str`/`executable_path` 会静默消失而本例转红。
#[test]
fn round_trip_custom_wrapped_node_survives_generation() {
    use polaris_config_engine::builder::outbound::build_proxy_outbound;
    use polaris_config_engine::singbox::DomainResolver;

    let out = parse_local(json!({ "outbounds": [
            { "type": "hysteria", "tag": "HY1", "server": "hy1.example.com", "server_port": 8443,
              "up_mbps": 100, "down_mbps": 500, "auth_str": "pw",
              "tls": { "enabled": true, "server_name": "hy1.example.com" } },
            { "type": "tor", "tag": "Tor", "executable_path": "/usr/bin/tor",
              "extra_args": ["--x"], "data_directory": "/var/lib/tor" }
        ] }));
    assert_eq!(out.servers.len(), 2);

    let hy = serde_json::to_value(build_proxy_outbound(
        &out.servers[0],
        "proxy-1",
        &DomainResolver::Tag("dns-bootstrap".to_string()),
        "x64",
        "linux",
    ))
    .unwrap();
    assert_eq!(
        hy.get("type").unwrap(),
        "hysteria",
        "type 原样，非 \"custom\""
    );
    assert_eq!(
        hy.get("tag").unwrap(),
        "proxy-1",
        "tag 被生成侧覆盖（既有语义）"
    );
    assert_eq!(hy.get("up_mbps").unwrap(), 100, "未建模字段必须活着下发");
    assert_eq!(hy.get("down_mbps").unwrap(), 500);
    assert_eq!(hy.get("auth_str").unwrap(), "pw");
    assert_eq!(hy.get("server").unwrap(), "hy1.example.com");
    assert_eq!(hy.get("server_port").unwrap(), 8443);

    let tor = serde_json::to_value(build_proxy_outbound(
        &out.servers[1],
        "proxy-2",
        &DomainResolver::Tag("dns-bootstrap".to_string()),
        "x64",
        "linux",
    ))
    .unwrap();
    assert_eq!(tor.get("type").unwrap(), "tor");
    assert_eq!(tor.get("executable_path").unwrap(), "/usr/bin/tor");
    assert_eq!(tor.get("extra_args").unwrap(), &json!(["--x"]));
    assert_eq!(tor.get("data_directory").unwrap(), "/var/lib/tor");
}

/// 透传袋的旧键在**入口**就改名：导入是用户文件进入本仓数据结构的第一道。
///
/// 判据与「为什么是替换不是并写」见 [`polaris_config_engine::legacy_keys`]：内核的兼容语义是
/// 「新字段为零才取旧值」⇒ 并写会在用户把窗口调回 0（= 用内核默认）时让旧值悄悄生效。
///
/// 早改一步的收益是：此后「导入 → 编辑 → 保存」全程看到的都是新名，表单与落盘内容一致。
/// 生成侧另有同一个函数兜住**本次改动之前就已落盘**的旧配置（那批不会再走一次导入），
/// 两处不是重复：这里管新进来的，那里管已经在里面的。
#[test]
fn hysteria_v1_legacy_keys_are_renamed_at_import() {
    use polaris_config_engine::legacy_keys::HYSTERIA_V1_LEGACY_KEYS;

    const EXACT_HYSTERIA_V1_MIGRATION_ORACLE: [(&str, &str); 5] = [
        ("recv_window_conn", "connection_receive_window"),
        ("recv_window", "stream_receive_window"),
        ("recv_window_client", "stream_receive_window"),
        ("max_conn_client", "max_concurrent_streams"),
        ("disable_mtu_discovery", "disable_path_mtu_discovery"),
    ];
    assert_eq!(
        HYSTERIA_V1_LEGACY_KEYS,
        EXACT_HYSTERIA_V1_MIGRATION_ORACLE.as_slice(),
        "Hysteria v1 迁移契约不再是精确五键"
    );

    let legacy_fixture = [
        ("recv_window_conn", json!(16_777_216u32)),
        ("recv_window", json!(8_388_608u32)),
        ("recv_window_client", json!(4_194_304u32)),
        ("max_conn_client", json!(1024u32)),
        ("disable_mtu_discovery", json!(true)),
    ];
    let mut outbound = json!({
        "type": "hysteria", "tag": "HY1", "server": "hy1.example.com", "server_port": 8443,
        "up_mbps": 100, "down_mbps": 500, "auth_str": "pw",
        // 不在迁移表里的未建模键：袋子本身的判据。
        "initial_packet_size": 1200
    });
    for (old, value) in &legacy_fixture {
        outbound
            .as_object_mut()
            .expect("fixture outbound 必须是对象")
            .insert((*old).to_string(), value.clone());
    }
    let out = parse_local(json!({ "outbounds": [outbound] }));
    let bag = &out.servers[0].hysteria_settings.as_ref().unwrap().extra;

    let migrated_expected = [
        ("connection_receive_window", json!(16_777_216u32)),
        ("stream_receive_window", json!(8_388_608u32)),
        ("max_concurrent_streams", json!(1024u32)),
        ("disable_path_mtu_discovery", json!(true)),
    ];
    for (new, expected) in &migrated_expected {
        assert_eq!(&bag[*new], expected, "{new} 迁移值不对");
    }
    assert_eq!(bag["initial_packet_size"], json!(1200u32));

    for (old, new) in EXACT_HYSTERIA_V1_MIGRATION_ORACLE {
        assert!(
            bag.get(old).is_none(),
            "袋子里还留着 1.16 会移除的旧键 {old:?}（应已替换为 {new:?}）"
        );
    }
}

#[test]
fn malformed_type_never_wrapped_even_locally() {
    // 形状判据与生成侧 `custom_outbound_type` 同源 + 上游的「type 非空白」：
    //  - 缺 type / 空串 / 纯空白 → 落盘门 `protocol_requirement_ok("custom")` 会剔，别造；
    //  - **非字符串 type**（数字）→ 生成侧 `custom_outbound_type` 返 None ⇒ 导得进也会被剔
    //    （这正是「导入侧另写一份判据」会产生的第三种分叉）。
    let doc = json!({ "outbounds": [
            { "tag": "x", "server": "a.com" },
            { "type": "", "server": "b.com" },
            { "type": "   ", "server": "c.com" },
            { "type": 42, "server": "d.com" }
        ] });
    for out in [parse_local(doc.clone()), parse(doc)] {
        assert_eq!(out.servers.len(), 0);
        assert!(out.servers.iter().all(|s| s.protocol != Protocol::Custom));
        assert_eq!(out.skipped, 4);
    }
}

#[test]
fn internal_types_never_wrapped() {
    // direct/block/dns/selector/urltest 是内核内部 outbound，不是节点 —— 两条腿都静默忽略。
    let doc = json!({ "outbounds": [
            { "type": "direct", "tag": "d" }, { "type": "block", "tag": "b" },
            { "type": "dns", "tag": "dns" }, { "type": "selector", "tag": "s", "outbounds": [] },
            { "type": "urltest", "tag": "u", "outbounds": [] }
        ] });
    let out = parse_local(doc);
    assert_eq!(out.servers.len(), 0, "内部 type 不得被包成 custom 节点");
    assert_eq!((out.skipped, out.failed), (0, 0));
    assert!(out.warnings.is_empty());
}

// ── P2：endpoints[] ─────────────────────────────────────────────────────────

/// 与 `sing-box check` 验过的那份 endpoints 语料同形（见本批交付说明）。
fn wg_endpoint_doc() -> Value {
    json!({ "endpoints": [{
            "type": "wireguard",
            "tag": "WG-HK",
            "system": true,
            "mtu": 1408,
            "address": ["172.16.0.2/32", "fd00::2/128"],
            "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEk=",
            "listen_port": 51820,
            "udp_timeout": "5m",
            "workers": 2,
            "peers": [{
                "address": "wg.example.com",
                "port": 2408,
                "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                "pre_shared_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEk=",
                "allowed_ips": ["0.0.0.0/0", "::/0", "10.8.0.0/24"],
                "persistent_keepalive_interval": 25,
                "reserved": [1, 2, 3]
            }]
        }] })
}

#[test]
fn wireguard_endpoint_full_mapping() {
    let out = parse_eps(wg_endpoint_doc(), ImportOrigin::RemoteSubscription);
    assert_eq!(out.servers.len(), 1, "endpoints-only 订阅不再恒 0 节点");
    assert_eq!((out.skipped, out.failed), (0, 0));
    let s = &out.servers[0];
    assert_eq!(s.protocol, Protocol::Wireguard);
    assert_eq!(s.name, "WG-HK", "tag → name");
    assert_eq!(s.address, "wg.example.com", "peers[0].address → address");
    assert_eq!(s.port, 2408, "peers[0].port → port");
    assert_eq!(s.subscription_id.as_deref(), Some("sub1"));
    let wg = s.wireguard_settings.as_ref().unwrap();
    assert_eq!(
        wg.private_key.as_deref(),
        Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEk=")
    );
    assert_eq!(wg.local_address, vec!["172.16.0.2/32", "fd00::2/128"]);
    assert_eq!(
        wg.peer_public_key.as_deref(),
        Some("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=")
    );
    assert_eq!(
        wg.pre_shared_key.as_deref(),
        Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEk=")
    );
    assert_eq!(
        wg.allowed_ips,
        vec!["10.8.0.0/24"],
        "catch-all 抽进 allowInternet，allowedIPs 只留具体段（与 wg-quick 导入腿同源）"
    );
    assert_eq!(wg.allow_internet, Some(true));
    assert_eq!(wg.persistent_keepalive, Some(25));
    assert_eq!(wg.mtu, Some(1408));
    assert_eq!(wg.reserved, vec![1, 2, 3]);
    assert_eq!(
        wg.reverse_mesh, None,
        "`system:true` 刻意不映射 reverseMesh —— 外部文件不该能翻抢内核 utun 的开关"
    );
}

#[test]
fn wireguard_endpoint_without_catch_all_is_mesh_only() {
    let out = parse_eps(
        json!({ "endpoints": [{
                "type": "wireguard", "address": ["10.0.0.2/32"], "private_key": "pk",
                "peers": [{ "address": "1.2.3.4", "port": 51820, "public_key": "pub",
                            "allowed_ips": ["10.0.0.0/24"] }]
            }] }),
        ImportOrigin::RemoteSubscription,
    );
    let s = &out.servers[0];
    assert_eq!(s.name, "1.2.3.4:51820", "无 tag → addr:port 兜底");
    let wg = s.wireguard_settings.as_ref().unwrap();
    assert_eq!(wg.allow_internet, Some(false), "无 catch-all → 仅组网");
    assert_eq!(wg.allowed_ips, vec!["10.0.0.0/24"]);
    assert_eq!(wg.persistent_keepalive, None, "缺省不写");
    assert_eq!(wg.mtu, None);
    assert!(wg.reserved.is_empty());
    assert_eq!(wg.pre_shared_key, None);
}

#[test]
fn wireguard_endpoint_missing_required_counts_failed() {
    // 逐条对应落盘门：`protocol_requirement_ok("wireguard")`（privateKey / peerPublicKey /
    // 非空 localAddress）+ `sanitize_servers` 的 address / port∈1..=65535。
    let out = parse_eps(
        json!({ "endpoints": [
                { "type": "wireguard", "address": ["10.0.0.2/32"],
                  "peers": [{ "address": "1.2.3.4", "port": 1, "public_key": "pub" }] },   // 缺 private_key
                { "type": "wireguard", "private_key": "pk", "address": ["10.0.0.2/32"],
                  "peers": [{ "address": "1.2.3.4", "port": 1 }] },                        // 缺 public_key
                { "type": "wireguard", "private_key": "pk",
                  "peers": [{ "address": "1.2.3.4", "port": 1, "public_key": "pub" }] },   // 缺 address[]
                { "type": "wireguard", "private_key": "pk", "address": ["10.0.0.2/32"] },  // 缺 peers
                { "type": "wireguard", "private_key": "pk", "address": ["10.0.0.2/32"],
                  "peers": [{ "port": 1, "public_key": "pub" }] },                         // peer 缺 address
                { "type": "wireguard", "private_key": "pk", "address": ["10.0.0.2/32"],
                  "peers": [{ "address": "1.2.3.4", "port": 0, "public_key": "pub" }] }    // port 0
            ] }),
        ImportOrigin::RemoteSubscription,
    );
    assert_eq!(out.servers.len(), 0);
    assert_eq!(out.failed, 6);
    assert_eq!(out.skipped, 0);
    assert!(out
        .warnings
        .iter()
        .any(|w| w.contains("6 个缺 private_key")));
}

#[test]
fn wireguard_endpoint_reserved_must_be_exactly_three() {
    // 与生成侧 `if s.reserved.len() == 3` 对称：残值等价缺席，不留半截数组。
    let out = parse_eps(
        json!({ "endpoints": [{
                "type": "wireguard", "address": ["10.0.0.2/32"], "private_key": "pk",
                "peers": [{ "address": "1.2.3.4", "port": 1, "public_key": "pub",
                            "reserved": [1, 2] }]
            }] }),
        ImportOrigin::RemoteSubscription,
    );
    assert!(out.servers[0]
        .wireguard_settings
        .as_ref()
        .unwrap()
        .reserved
        .is_empty());
}

#[test]
fn tailscale_endpoint_always_skipped_never_custom() {
    for origin in [ImportOrigin::RemoteSubscription, ImportOrigin::LocalFile] {
        let out = parse_eps(
            json!({ "endpoints": [{
                    "type": "tailscale", "tag": "TS", "auth_key": "tskey-auth-SECRET",
                    "hostname": "victim", "control_url": "https://ctl.example.com"
                }] }),
            origin,
        );
        assert_eq!(out.servers.len(), 0, "{origin:?}：账号制凭据不导入");
        assert!(
            out.servers.iter().all(|s| s.protocol != Protocol::Custom),
            "{origin:?}：也不得包成 custom（会绕过前端 tailscale 单例闸门）"
        );
        assert_eq!(out.skipped, 1);
        assert!(out
            .warnings
            .iter()
            .any(|w| w.contains("tailscale endpoint")));
    }
}

#[test]
fn unmodeled_endpoint_types_wrap_as_custom_endpoint() {
    // openconnect / openvpn-client（+ openvpn-server，同一条 `_` 臂）：内核 `$defs/Endpoint`
    // 认这些 type，Polaris 无落点 → custom + isEndpoint。本语料 `sing-box check` rc=0
    // （openvpn-client 的 `tls.peer_fingerprint` 是自签证书的 sha256，凑够内核的必填 TLS 材料；
    // openvpn-server 需本机证书文件路径，不适合进单测语料，故不入本例）。
    let doc = json!({ "endpoints": [
            { "type": "openconnect", "tag": "OC", "server": "vpn.example.com:443",
              "username": "u", "password": "p" },
            { "type": "openvpn-client", "server": "ovpn.example.com", "server_port": 1194,
              "username": "u", "password": "p",
              "tls": { "peer_fingerprint":
                       "e0593c478275d2bd1722039e5b7ba37fd39cd75cacff0a81bc66b46b5628f9bf" } }
        ] });
    let out = parse_eps(doc.clone(), ImportOrigin::LocalFile);
    assert_eq!(out.servers.len(), 2);
    assert_eq!((out.skipped, out.failed), (0, 0));
    // 2026-08-11：二者已进建模协议 ⇒ 不再包 custom，而是各归各的设置结构。
    assert_eq!(out.servers[0].protocol, Protocol::Openconnect);
    assert_eq!(out.servers[1].protocol, Protocol::OpenvpnClient);
    assert_eq!(out.servers[0].name, "OC");
    // openconnect 的 server 是 host:port 单串 ⇒ address/port 由它拆出（落盘门要这两项）。
    assert_eq!(out.servers[0].address, "vpn.example.com");
    assert_eq!(out.servers[0].port, 443);
    let oc = out.servers[0].openconnect_settings.as_ref().unwrap();
    assert_eq!(
        oc.server.as_deref(),
        Some("vpn.example.com:443"),
        "原串保留"
    );
    assert_eq!(oc.username.as_deref(), Some("u"));
    // 命名口径随之改变：custom 腿用 type 作名，建模腿走 new_server ⇒ 无 tag 时用 addr:port。
    // 这是形态变化不是回归 —— 与其余 15 个建模协议一致了。
    assert_eq!(
        out.servers[1].name, "ovpn.example.com:1194",
        "无 tag → addr:port"
    );
    assert_eq!(out.servers[1].port, 1194);
    // 未建模的 tls.peer_fingerprint 走透传袋（本地文件才填）—— 逐字保全，
    // 否则「导入 → 编辑 → 保存」会把内核唯一的 TLS 材料丢掉，节点从能连变成起不来。
    let ov = out.servers[1].openvpn_client_settings.as_ref().unwrap();
    assert_eq!(
        ov.tls
            .as_ref()
            .and_then(|t| t.extra.get("peer_fingerprint"))
            .and_then(|v| v.as_str()),
        Some("e0593c478275d2bd1722039e5b7ba37fd39cd75cacff0a81bc66b46b5628f9bf"),
        "未建模的 TLS 材料被丢掉了"
    );

    // 订阅腿：同一份输入一个不导，计 skipped。
    let remote = parse_eps(doc, ImportOrigin::RemoteSubscription);
    assert_eq!(remote.servers.len(), 0);
    assert_eq!(remote.skipped, 2);
    assert!(remote
        .warnings
        .iter()
        .any(|w| w.contains("openconnect(1)") && w.contains("openvpn-client(1)")));
}
