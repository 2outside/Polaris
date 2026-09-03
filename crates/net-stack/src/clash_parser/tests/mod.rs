use super::*;

fn new_uuid() -> impl FnMut() -> String {
    let mut counter = 0u32;
    move || {
        counter += 1;
        format!("uuid-{}", counter)
    }
}

// ── 文档加载 ──────────────────────────────────────────────────────────────
#[test]
fn load_valid_clash_doc() {
    let yaml = "proxies:\n  - name: a\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n    cipher: aes-256-gcm\n    password: pw\n";
    let doc = try_load_clash_doc(yaml).unwrap();
    assert!(doc.get("proxies").is_some());
}

#[test]
fn load_merge_key_expanded() {
    let yaml = r#"
proxies:
  - &tpl
    type: ss
    cipher: aes-256-gcm
    password: shared
  - <<: *tpl
    name: node1
    server: 1.1.1.1
    port: 8388
"#;
    let doc = try_load_clash_doc(yaml).unwrap();
    let proxies = doc.get("proxies").unwrap().as_sequence().unwrap();
    let node = &proxies[1];
    // merge 后应有 type/cipher/password + 显式 name/server/port
    assert_eq!(node.get("name").unwrap().as_str(), Some("node1"));
    assert_eq!(node.get("type").unwrap().as_str(), Some("ss"));
    assert_eq!(node.get("cipher").unwrap().as_str(), Some("aes-256-gcm"));
    assert_eq!(node.get("password").unwrap().as_str(), Some("shared"));
}

#[test]
fn load_invalid_yaml_wraps_error() {
    let r = try_load_clash_doc("proxies: [unclosed");
    assert!(r.is_err());
    assert!(r.unwrap_err().contains("Clash YAML 解析失败"));
}

#[test]
fn clash_probe_detects_proxies() {
    assert!(is_clash_probe("proxies:\n  - name: x"));
    assert!(is_clash_probe("proxy-providers:\n  p1:"));
    assert!(!is_clash_probe("rules:\n  - DOMAIN-SUFFIX,x"));
}

// ── 各协议解析 ────────────────────────────────────────────────────────────
fn parse_one(yaml: &str) -> ClashParseResult {
    let mut id = new_uuid();
    let v: Value = serde_yaml::from_str(yaml).unwrap();
    parse_clash_proxies(&v, "sub-1", "2024-01-01T00:00:00Z", &mut id)
}

#[test]
fn parse_vless() {
    let r = parse_one(
        r#"
- name: vless1
  type: vless
  server: example.com
  port: 443
  uuid: abc-uuid
  flow: xtls-rprx-vision
  tls: true
  servername: example.com
  network: ws
  ws-opts:
    path: /ray
    headers:
      Host: cdn.example.com
"#,
    );
    assert_eq!(r.servers.len(), 1);
    let s = &r.servers[0];
    assert_eq!(s.protocol, Protocol::Vless);
    assert_eq!(s.uuid.as_deref(), Some("abc-uuid"));
    assert_eq!(s.encryption.as_deref(), Some("none"));
    assert_eq!(s.flow.as_deref(), Some("xtls-rprx-vision"));
    assert_eq!(s.security, Some(SecurityMode::Tls));
    assert_eq!(s.network.as_deref(), Some("ws"));
    assert_eq!(
        s.tls_settings.as_ref().unwrap().server_name.as_deref(),
        Some("example.com")
    );
    assert_eq!(
        s.ws_settings.as_ref().unwrap().path.as_deref(),
        Some("/ray")
    );
}

#[test]
fn parse_vmess() {
    let r = parse_one(
        r#"
- name: vmess1
  type: vmess
  server: example.com
  port: 443
  uuid: vm-uuid
  alterId: 64
  cipher: aes-128-gcm
  tls: true
  network: grpc
  grpc-opts:
    grpc-service-name: gun
"#,
    );
    let s = &r.servers[0];
    assert_eq!(s.protocol, Protocol::Vmess);
    assert_eq!(s.uuid.as_deref(), Some("vm-uuid"));
    assert_eq!(s.alter_id, Some(64));
    assert_eq!(s.vmess_security.as_deref(), Some("aes-128-gcm"));
    assert_eq!(s.network.as_deref(), Some("grpc"));
    assert_eq!(
        s.grpc_settings.as_ref().unwrap().service_name.as_deref(),
        Some("gun")
    );
}

#[test]
fn parse_trojan() {
    let r = parse_one(
        r#"
- name: trojan1
  type: trojan
  server: example.com
  port: 443
  password: trojan-pw
  sni: example.com
  skip-cert-verify: true
"#,
    );
    let s = &r.servers[0];
    assert_eq!(s.protocol, Protocol::Trojan);
    assert_eq!(s.password.as_deref(), Some("trojan-pw"));
    assert_eq!(s.security, Some(SecurityMode::Tls)); // force_tls
    assert!(s.tls_settings.as_ref().unwrap().allow_insecure.unwrap());
}

#[test]
fn parse_shadowsocks_basic() {
    let r = parse_one(
        r#"
- name: ss1
  type: ss
  server: 1.2.3.4
  port: 8388
  cipher: aes-256-gcm
  password: ss-pw
"#,
    );
    let s = &r.servers[0];
    assert_eq!(s.protocol, Protocol::Shadowsocks);
    let ss = s.shadowsocks_settings.as_ref().unwrap();
    assert_eq!(ss.method, "aes-256-gcm");
    assert_eq!(ss.password, "ss-pw");
    assert!(ss.plugin.is_none());
}

#[test]
fn parse_shadowsocks_obfs_plugin() {
    let r = parse_one(
        r#"
- name: ss-obfs
  type: ss
  server: 1.2.3.4
  port: 8388
  cipher: aes-256-gcm
  password: pw
  plugin: obfs
  plugin-opts:
    mode: tls
    host: bing.com
"#,
    );
    let ss = &r.servers[0].shadowsocks_settings.as_ref().unwrap();
    assert_eq!(ss.plugin.as_deref(), Some("obfs-local"));
    assert!(ss.plugin_opts.as_deref().unwrap().contains("obfs=tls"));
    assert!(ss
        .plugin_opts
        .as_deref()
        .unwrap()
        .contains("obfs-host=bing.com"));
}

#[test]
fn parse_shadowsocks_v2ray_plugin() {
    let r = parse_one(
        r#"
- name: ss-v2ray
  type: ss
  server: 1.2.3.4
  port: 8388
  cipher: aes-256-gcm
  password: pw
  plugin: v2ray-plugin
  plugin-opts:
    mode: websocket
    tls: true
    host: cdn.example.com
    path: /ws
"#,
    );
    let ss = &r.servers[0].shadowsocks_settings.as_ref().unwrap();
    assert_eq!(ss.plugin.as_deref(), Some("v2ray-plugin"));
    let opts = ss.plugin_opts.as_deref().unwrap();
    assert!(opts.contains("mode=websocket"));
    assert!(opts.contains("tls"));
    assert!(opts.contains("host=cdn.example.com"));
    assert!(opts.contains("path=/ws"));
}

#[test]
fn parse_shadowsocks_shadowtls_plugin() {
    let r = parse_one(
        r#"
- name: ss-stls
  type: ss
  server: 1.2.3.4
  port: 8388
  cipher: 2022-blake3-aes-128-gcm
  password: pw
  plugin: shadow-tls
  plugin-opts:
    password: stls-pw
    host: shadow.example.com
    port: 443
"#,
    );
    let s = &r.servers[0];
    let stls = s.shadow_tls_settings.as_ref().unwrap();
    assert_eq!(stls.password, "stls-pw");
    assert_eq!(stls.sni, "shadow.example.com");
    assert_eq!(stls.port, Some(443));
    assert_eq!(stls.fingerprint.as_deref(), Some("chrome"));
}

#[test]
fn parse_shadowsocks_unknown_plugin_skipped() {
    let r = parse_one(
        r#"
- name: ss-restls
  type: ss
  server: 1.2.3.4
  port: 8388
  cipher: aes-256-gcm
  password: pw
  plugin: restls
"#,
    );
    assert_eq!(r.servers.len(), 0);
    assert_eq!(r.skipped, 1);
    assert!(r.warnings.iter().any(|w| w.contains("ss-plugin:restls")));
}

#[test]
fn parse_hysteria2() {
    let r = parse_one(
        r#"
- name: hy2-1
  type: hysteria2
  server: example.com
  port: 443
  password: hy2-pw
  sni: example.com
  obfs: salamander
  obfs-password: obfs-pw
  up: 100
  down: 200
  ports: 20000-30000
  hop-interval: 30
"#,
    );
    let s = &r.servers[0];
    assert_eq!(s.protocol, Protocol::Hysteria2);
    assert_eq!(s.password.as_deref(), Some("hy2-pw"));
    assert_eq!(s.security, Some(SecurityMode::Tls));
    let hy2 = s.hysteria2_settings.as_ref().unwrap();
    assert_eq!(hy2.up_mbps, Some(100));
    assert_eq!(hy2.down_mbps, Some(200));
    assert_eq!(hy2.server_ports.as_deref(), Some("20000:30000"));
    assert_eq!(hy2.hop_interval.as_deref(), Some("30s"));
    assert_eq!(
        hy2.obfs.as_ref().unwrap().type_field.as_deref(),
        Some("salamander")
    );
    assert_eq!(
        hy2.obfs.as_ref().unwrap().password.as_deref(),
        Some("obfs-pw")
    );
}

#[test]
fn parse_hysteria2_salamander_missing_obfs_password_rejected() {
    // 上游 #263 迁移：obfs=salamander 缺 obfs-password → 拒节点（与其他协议缺密码口径一致），
    // 而非静默跳过导致 obfs 丢失、节点连不上。
    let r = parse_one(
        r#"
- name: hy2-no-obfs-pw
  type: hysteria2
  server: example.com
  port: 443
  password: hy2-pw
  obfs: salamander
"#,
    );
    assert_eq!(r.servers.len(), 0);
    assert_eq!(r.failed, 1);
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("obfs=salamander 缺 obfs-password")),
        "warnings 应含拒节点原因，实际: {:?}",
        r.warnings
    );
}

#[test]
fn parse_tuic() {
    let r = parse_one(
        r#"
- name: tuic1
  type: tuic
  server: example.com
  port: 443
  uuid: tuic-uuid
  password: tuic-pw
  congestion-controller: bbr
  udp-relay-mode: native
  reduce-rtt: true
  heartbeat: 10000
  sni: example.com
"#,
    );
    let s = &r.servers[0];
    assert_eq!(s.protocol, Protocol::Tuic);
    assert_eq!(s.uuid.as_deref(), Some("tuic-uuid"));
    assert_eq!(s.password.as_deref(), Some("tuic-pw"));
    let ts = s.tuic_settings.as_ref().unwrap();
    assert_eq!(ts.congestion_control.as_deref(), Some("bbr"));
    assert_eq!(ts.udp_relay_mode.as_deref(), Some("native"));
    assert!(ts.zero_rtt_handshake.unwrap());
    assert_eq!(ts.heartbeat.as_deref(), Some("10000ms")); // 毫秒补单位
}

#[test]
fn parse_anytls() {
    let r = parse_one(
        r#"
- name: anytls1
  type: anytls
  server: example.com
  port: 443
  password: anytls-pw
  idle-session-timeout: 30s
  sni: example.com
"#,
    );
    let s = &r.servers[0];
    assert_eq!(s.protocol, Protocol::Anytls);
    assert_eq!(s.password.as_deref(), Some("anytls-pw"));
    assert_eq!(s.security, Some(SecurityMode::Tls)); // force_tls
    assert_eq!(
        s.any_tls_settings
            .as_ref()
            .unwrap()
            .idle_session_timeout
            .as_deref(),
        Some("30s")
    );
}

#[test]
fn parse_snell_v4_http_obfs() {
    let r = parse_one(
        r#"
- name: snell1
  type: snell
  server: example.com
  port: 443
  psk: psk-value
  version: 4
  obfs-opts:
    mode: http
    host: bing.com
"#,
    );
    let s = &r.servers[0];
    assert_eq!(s.protocol, Protocol::Snell);
    assert_eq!(s.password.as_deref(), Some("psk-value"));
    let snell = s.snell_settings.as_ref().unwrap();
    assert_eq!(snell.version, 4);
    assert_eq!(snell.obfs_mode.as_deref(), Some("http"));
    assert_eq!(snell.obfs_host.as_deref(), Some("bing.com"));
}

#[test]
fn parse_snell_unsupported_version_skipped() {
    let r = parse_one(
        r#"
- name: snell-old
  type: snell
  server: example.com
  port: 443
  psk: psk-value
  version: 3
"#,
    );
    assert_eq!(r.servers.len(), 0);
    assert_eq!(r.skipped, 1);
}

#[test]
fn parse_socks() {
    let r = parse_one(
        r#"
- name: socks1
  type: socks5
  server: 1.2.3.4
  port: 1080
  username: user
  password: pass
"#,
    );
    let s = &r.servers[0];
    assert_eq!(s.protocol, Protocol::Socks);
    assert_eq!(s.username.as_deref(), Some("user"));
    assert_eq!(s.password.as_deref(), Some("pass"));
    assert_eq!(s.network.as_deref(), Some("tcp"));
    assert_eq!(s.security, Some(SecurityMode::None));
}

#[test]
fn parse_http_tls() {
    let r = parse_one(
        r#"
- name: http1
  type: http
  server: example.com
  port: 443
  username: user
  password: pass
  tls: true
  sni: example.com
"#,
    );
    let s = &r.servers[0];
    assert_eq!(s.protocol, Protocol::Http);
    assert_eq!(s.security, Some(SecurityMode::Tls));
    assert_eq!(
        s.tls_settings.as_ref().unwrap().server_name.as_deref(),
        Some("example.com")
    );
}

#[test]
fn parse_ssh() {
    let r = parse_one(
        r#"
- name: ssh1
  type: ssh
  server: 1.2.3.4
  port: 22
  username: root
  password: toor
  client-version: SSH-2.0-OpenSSH_8.0
"#,
    );
    let s = &r.servers[0];
    assert_eq!(s.protocol, Protocol::Ssh);
    let ssh = s.ssh_settings.as_ref().unwrap();
    assert_eq!(ssh.user.as_deref(), Some("root"));
    assert_eq!(ssh.password.as_deref(), Some("toor"));
    assert_eq!(ssh.client_version.as_deref(), Some("SSH-2.0-OpenSSH_8.0"));
}

// ── 缺字段/不支持类型 ─────────────────────────────────────────────────────
#[test]
fn missing_required_field_fails() {
    let r = parse_one(
        r#"
- name: bad-vless
  type: vless
  server: example.com
  port: 443
"#,
    );
    assert_eq!(r.servers.len(), 0);
    assert_eq!(r.failed, 1);
    assert!(r.warnings.iter().any(|w| w.contains("缺 uuid")));
}

#[test]
fn unsupported_type_skipped() {
    let r = parse_one(
        r#"
- name: ssr1
  type: ssr
  server: 1.2.3.4
  port: 8388
"#,
    );
    assert_eq!(r.servers.len(), 0);
    assert_eq!(r.skipped, 1);
    assert!(r.warnings.iter().any(|w| w.contains("ssr")));
}

#[test]
fn unsupported_transport_fails() {
    let r = parse_one(
        r#"
- name: bad-transport
  type: vmess
  server: example.com
  port: 443
  uuid: u
  network: kcp
"#,
    );
    assert_eq!(r.servers.len(), 0);
    assert!(r
        .warnings
        .iter()
        .any(|w| w.contains("不支持的传输层类型: kcp")));
}

#[test]
fn empty_proxies_returns_empty() {
    let r = parse_one("[]");
    assert_eq!(r.servers.len(), 0);
    assert_eq!(r.skipped, 0);
    assert_eq!(r.failed, 0);
}

#[test]
fn non_array_proxies_returns_empty() {
    let r = parse_one("null");
    assert_eq!(r.servers.len(), 0);
}

#[test]
fn alpn_dedup_and_split() {
    let r = parse_one(
        r#"
- name: alpn-test
  type: vless
  server: example.com
  port: 443
  uuid: u
  tls: true
  alpn:
    - h2
    - " http/1.1"
    - h2,http/3
"#,
    );
    let tls = r.servers[0].tls_settings.as_ref().unwrap();
    let alpn = tls.alpn.as_ref().unwrap();
    // h2 出现两次去重；" http/1.1" trim；h2,http/3 拆分
    assert!(alpn.contains(&"h2".to_string()));
    assert!(alpn.contains(&"http/1.1".to_string()));
    assert!(alpn.contains(&"http/3".to_string()));
}

// ── filter / override ─────────────────────────────────────────────────────
#[test]
fn apply_override_skip_cert_on_tls_nodes() {
    let mut id = new_uuid();
    let v: Value = serde_yaml::from_str(
        r#"
- name: t1
  type: trojan
  server: example.com
  port: 443
  password: pw
"#,
    )
    .unwrap();
    let mut result = parse_clash_proxies(&v, "s1", "now", &mut id);
    let ov: Value = serde_yaml::from_str("skip-cert-verify: true").unwrap();
    apply_override(&mut result.servers, &ov);
    assert!(result.servers[0]
        .tls_settings
        .as_ref()
        .unwrap()
        .allow_insecure
        .unwrap());
}

#[test]
fn apply_override_skip_cert_ignored_on_non_tls() {
    let mut id = new_uuid();
    let v: Value = serde_yaml::from_str(
        r#"
- name: s1
  type: socks5
  server: 1.2.3.4
  port: 1080
"#,
    )
    .unwrap();
    let mut result = parse_clash_proxies(&v, "s1", "now", &mut id);
    let ov: Value = serde_yaml::from_str("skip-cert-verify: true").unwrap();
    apply_override(&mut result.servers, &ov);
    // 非 TLS 节点不注入 tlsSettings（防代理指纹噪音）
    assert!(result.servers[0].tls_settings.is_none());
}

#[test]
fn apply_override_up_down_on_hysteria2() {
    let mut id = new_uuid();
    let v: Value = serde_yaml::from_str(
        r#"
- name: h
  type: hysteria2
  server: example.com
  port: 443
  password: pw
"#,
    )
    .unwrap();
    let mut result = parse_clash_proxies(&v, "s1", "now", &mut id);
    let ov: Value = serde_yaml::from_str("up: 50\ndown: 100").unwrap();
    apply_override(&mut result.servers, &ov);
    let hy2 = result.servers[0].hysteria2_settings.as_ref().unwrap();
    assert_eq!(hy2.up_mbps, Some(50));
    assert_eq!(hy2.down_mbps, Some(100));
}

#[test]
fn provider_filter_keeps_matching() {
    let mut id = new_uuid();
    let v: Value = serde_yaml::from_str(
        r#"
- name: HK-01
  type: ss
  server: 1.1.1.1
  port: 8388
  cipher: a
  password: p
- name: US-01
  type: ss
  server: 2.2.2.2
  port: 8388
  cipher: a
  password: p
"#,
    )
    .unwrap();
    let result = parse_clash_proxies(&v, "s1", "now", &mut id);
    let mut warns = Vec::new();
    let filtered = apply_provider_filters(
        result.servers,
        Some("HK"),
        None,
        &mut |m| warns.push(m),
        "p1",
    );
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].name, "HK-01");
}

#[test]
fn provider_exclude_filter_removes() {
    let mut id = new_uuid();
    let v: Value = serde_yaml::from_str(
        r#"
- name: HK-01
  type: ss
  server: 1.1.1.1
  port: 8388
  cipher: a
  password: p
- name: US-01
  type: ss
  server: 2.2.2.2
  port: 8388
  cipher: a
  password: p
"#,
    )
    .unwrap();
    let result = parse_clash_proxies(&v, "s1", "now", &mut id);
    let mut warns = Vec::new();
    let filtered = apply_provider_filters(
        result.servers,
        None,
        Some("HK"),
        &mut |m| warns.push(m),
        "p1",
    );
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].name, "US-01");
}

#[test]
fn provider_invalid_filter_warns() {
    let mut id = new_uuid();
    let v: Value = serde_yaml::from_str(
        r#"
- name: HK-01
  type: ss
  server: 1.1.1.1
  port: 8388
  cipher: a
  password: p
"#,
    )
    .unwrap();
    let result = parse_clash_proxies(&v, "s1", "now", &mut id);
    let mut warns = Vec::new();
    let filtered = apply_provider_filters(
        result.servers,
        Some("(unclosed"),
        None,
        &mut |m| warns.push(m),
        "p1",
    );
    // 非法正则 → 忽略 filter，保留全部
    assert_eq!(filtered.len(), 1);
    assert!(warns.iter().any(|w| w.contains("filter 非法")));
}

#[test]
fn compile_filter_too_long_returns_none() {
    let long = "a".repeat(MAX_FILTER_PATTERN_LEN + 1);
    assert!(compile_provider_filter(Some(&long)).is_none());
    assert!(compile_provider_filter(Some("HK.*")).is_some());
    assert!(compile_provider_filter(None).is_none());
}

#[test]
fn normalize_duration_rules() {
    assert_eq!(
        normalize_duration(&Value::Number(serde_yaml::Number::from(10000))),
        Some("10000ms".to_string())
    );
    assert_eq!(
        normalize_duration(&Value::String("30s".into())),
        Some("30s".to_string())
    );
    assert_eq!(
        normalize_duration(&Value::String("500".into())),
        Some("500ms".to_string())
    );
    assert_eq!(normalize_duration(&Value::String("".into())), None);
}
