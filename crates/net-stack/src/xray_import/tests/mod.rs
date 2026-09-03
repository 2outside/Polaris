use super::*;
use serde_json::json;

/// 递增 id 生成器（可复现，便于断言）。
fn id_gen() -> impl FnMut() -> String {
    let mut n = 0;
    move || {
        n += 1;
        format!("id-{n}")
    }
}

fn parse(v: Value) -> ClashParseResult {
    let mut g = id_gen();
    parse_xray_outbounds(
        v.get("outbounds").unwrap(),
        "sub1",
        "2026-07-18T00:00:00Z",
        &mut g,
    )
}

// ── looks_like_xray（区分 xray/sing-box）─────────────────────────────────────
#[test]
fn looks_like_xray_distinguishes_schemas() {
    // xray：protocol 存在、无 type。
    let xray = json!([{ "protocol": "vless", "settings": {} }]);
    assert!(looks_like_xray(xray.as_array().unwrap()));
    // sing-box：有 type。
    let singbox = json!([{ "type": "vless", "server": "a.com" }]);
    assert!(!looks_like_xray(singbox.as_array().unwrap()));
    // protocol 存在但同时有 type（歧义）→ 非 xray（对齐 `type === undefined`）。
    let both = json!([{ "protocol": "vless", "type": "vless" }]);
    assert!(!looks_like_xray(both.as_array().unwrap()));
    // 空 / 非对象。
    assert!(!looks_like_xray(&[]));
    assert!(!looks_like_xray(json!(["x", 1]).as_array().unwrap()));
}

// ── vless + ws + tls：全字段映射（打断任一映射 → 断言转红）──────────────────────
#[test]
fn vless_ws_tls_full_mapping() {
    let out = parse(json!({ "outbounds": [{
            "protocol": "vless",
            "tag": "HK-01",
            "settings": { "vnext": [{
                "address": "a.example.com",
                "port": 443,
                "users": [{ "id": "uuid-1", "flow": "XTLS-RPRX-Vision" }]
            }] },
            "streamSettings": {
                "network": "ws",
                "wsSettings": { "path": "/ray", "headers": { "Host": "cdn.example.com" } },
                "security": "tls",
                "tlsSettings": { "serverName": "sni.example.com", "allowInsecure": true, "fingerprint": "Chrome", "alpn": ["h2", "http/1.1"] }
            }
        }] }));
    assert_eq!(out.servers.len(), 1, "一个合法 vless 节点");
    let s = &out.servers[0];
    assert_eq!(s.name, "HK-01", "tag → name");
    assert_eq!(s.protocol, Protocol::Vless);
    assert_eq!(s.address, "a.example.com");
    assert_eq!(s.port, 443);
    assert_eq!(s.uuid.as_deref(), Some("uuid-1"));
    assert_eq!(
        s.flow.as_deref(),
        Some("xtls-rprx-vision"),
        "flow R4 归一小写"
    );
    assert_eq!(s.network.as_deref(), Some("ws"));
    let ws = s.ws_settings.as_ref().expect("ws_settings");
    assert_eq!(ws.path.as_deref(), Some("/ray"));
    assert_eq!(
        ws.headers
            .as_ref()
            .and_then(|h| h.get("Host"))
            .map(String::as_str),
        Some("cdn.example.com")
    );
    assert_eq!(s.security, Some(SecurityMode::Tls));
    let tls = s.tls_settings.as_ref().expect("tls_settings");
    assert_eq!(tls.server_name.as_deref(), Some("sni.example.com"));
    assert_eq!(tls.allow_insecure, Some(true));
    assert_eq!(
        tls.fingerprint.as_deref(),
        Some("chrome"),
        "fingerprint R4 归一小写"
    );
    assert_eq!(
        tls.alpn.as_deref(),
        Some(&["h2".to_string(), "http/1.1".to_string()][..])
    );
    assert_eq!(s.subscription_id.as_deref(), Some("sub1"), "挂订阅 id");
}

// ── vmess + grpc：alterId/security/serviceName ───────────────────────────────
#[test]
fn vmess_grpc_mapping() {
    let out = parse(json!({ "outbounds": [{
            "protocol": "vmess",
            "settings": { "vnext": [{
                "address": "b.example.com",
                "port": "8443",
                "users": [{ "id": "uuid-2", "alterId": 4, "security": "AES-128-GCM" }]
            }] },
            "streamSettings": { "network": "grpc", "grpcSettings": { "serviceName": "gsvc" } }
        }] }));
    let s = &out.servers[0];
    assert_eq!(s.protocol, Protocol::Vmess);
    assert_eq!(s.port, 8443, "字符串端口规整");
    assert_eq!(s.alter_id, Some(4));
    assert_eq!(
        s.vmess_security.as_deref(),
        Some("aes-128-gcm"),
        "vmessSecurity R4 归一"
    );
    assert_eq!(s.name, "b.example.com:8443", "无 tag → address:port");
    assert_eq!(s.network.as_deref(), Some("grpc"));
    assert_eq!(
        s.grpc_settings
            .as_ref()
            .and_then(|g| g.service_name.as_deref()),
        Some("gsvc")
    );
}

// ── trojan + reality ─────────────────────────────────────────────────────────
#[test]
fn trojan_reality_mapping() {
    let out = parse(json!({ "outbounds": [{
            "protocol": "trojan",
            "settings": { "servers": [{ "address": "c.example.com", "port": 443, "password": "pw" }] },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": { "serverName": "r.example.com", "publicKey": "PBK", "shortId": "sid" }
            }
        }] }));
    let s = &out.servers[0];
    assert_eq!(s.protocol, Protocol::Trojan);
    assert_eq!(s.password.as_deref(), Some("pw"));
    assert_eq!(s.security, Some(SecurityMode::Reality));
    let r = s.reality_settings.as_ref().expect("reality_settings");
    assert_eq!(r.public_key, "PBK");
    assert_eq!(r.short_id.as_deref(), Some("sid"));
    assert_eq!(
        s.tls_settings
            .as_ref()
            .and_then(|t| t.server_name.as_deref()),
        Some("r.example.com")
    );
}

// ── shadowsocks ──────────────────────────────────────────────────────────────
#[test]
fn shadowsocks_mapping() {
    let out = parse(json!({ "outbounds": [{
            "protocol": "shadowsocks",
            "settings": { "servers": [{ "address": "d.example.com", "port": 8388, "method": "aes-256-gcm", "password": "sspw" }] }
        }] }));
    let s = &out.servers[0];
    assert_eq!(s.protocol, Protocol::Shadowsocks);
    let ss = s
        .shadowsocks_settings
        .as_ref()
        .expect("shadowsocks_settings");
    assert_eq!(ss.method, "aes-256-gcm");
    assert_eq!(ss.password, "sspw");
}

// ── skipped / internal / failed 统计（打断分类 → 计数断言转红）──────────────────
#[test]
fn skip_internal_and_count_unsupported() {
    let out = parse(json!({ "outbounds": [
            { "protocol": "freedom" },                                   // internal → 不计
            { "protocol": "blackhole" },                                 // internal → 不计
            // http / socks 都已在册（issue #1），换两个**真未登记**的协议继续钉住 skipped 分类
            // 本身——这条门守的是「未登记协议计 skipped 并列入告警」，不是某个具体协议。
            { "protocol": "dokodemo-door", "settings": {} },             // unsupported → skipped
            { "protocol": "wireguard", "settings": {} },                 // unsupported → skipped
            { "protocol": "vless", "settings": { "vnext": [{ "address": "a.com", "port": 443, "users": [{ "id": "u" }] }] } }
        ] }));
    assert_eq!(out.servers.len(), 1, "仅 vless 入库");
    assert_eq!(
        out.skipped, 2,
        "dokodemo-door + wireguard 计 skipped（freedom/blackhole 不计）"
    );
    assert_eq!(out.failed, 0);
    assert_eq!(out.warnings.len(), 1);
    assert!(
        out.warnings[0].contains("dokodemo-door(1)") && out.warnings[0].contains("wireguard(1)"),
        "warning 列明协议计数: {}",
        out.warnings[0]
    );
}

#[test]
fn incomplete_nodes_count_failed() {
    let out = parse(json!({ "outbounds": [
            { "protocol": "vless", "settings": { "vnext": [{ "address": "a.com", "port": 443, "users": [{}] }] } }, // 缺 uuid
            { "protocol": "vmess", "settings": { "vnext": [{ "address": "", "port": 443, "users": [{ "id": "u" }] }] } }, // 空 address
            { "protocol": "trojan", "settings": { "servers": [{ "address": "c.com", "port": 443 }] } }, // 缺 password
            { "protocol": "vless", "settings": {} } // 缺 vnext
        ] }));
    assert_eq!(out.servers.len(), 0);
    assert_eq!(out.failed, 4, "四个受支持但字段缺失 → failed");
    assert_eq!(out.skipped, 0);
}

#[test]
fn port_zero_and_overflow_rejected() {
    let out = parse(json!({ "outbounds": [
            { "protocol": "vless", "settings": { "vnext": [{ "address": "a.com", "port": 0, "users": [{ "id": "u" }] }] } },      // port 0 → 拒
            { "protocol": "vless", "settings": { "vnext": [{ "address": "a.com", "port": 70000, "users": [{ "id": "u" }] }] } }   // >65535 → 拒
        ] }));
    assert_eq!(
        out.servers.len(),
        0,
        "port 0 / 越界必须拒（不 as u16 静默截断）"
    );
    assert_eq!(out.failed, 2);
}

// ── DESIGN-REVIEW(xray-transport-fallback)：未知传输 → tcp（锁 上游 现行行为）──────
#[test]
fn unknown_transport_falls_back_to_tcp() {
    let out = parse(json!({ "outbounds": [{
            "protocol": "vless",
            "settings": { "vnext": [{ "address": "a.com", "port": 443, "users": [{ "id": "u" }] }] },
            "streamSettings": { "network": "kcp" }
        }] }));
    assert_eq!(
        out.servers[0].network.as_deref(),
        Some("tcp"),
        "忠实 上游：未知传输降级 tcp"
    );
}

// ── h2 host 数组 / 单串两形态 ─────────────────────────────────────────────────
#[test]
fn http_host_array_and_scalar() {
    let out = parse(json!({ "outbounds": [
            { "protocol": "vless", "settings": { "vnext": [{ "address": "a.com", "port": 443, "users": [{ "id": "u" }] }] },
              "streamSettings": { "network": "h2", "httpSettings": { "host": ["h1.com", "h2.com"], "path": "/p" } } },
            { "protocol": "vless", "settings": { "vnext": [{ "address": "b.com", "port": 443, "users": [{ "id": "u" }] }] },
              "streamSettings": { "network": "http", "httpSettings": { "host": "single.com" } } }
        ] }));
    let a = &out.servers[0];
    assert_eq!(a.network.as_deref(), Some("http"), "h2 → http");
    let ha = a.http_settings.as_ref().expect("http_settings");
    assert_eq!(
        ha.host.as_deref(),
        Some(&["h1.com".to_string(), "h2.com".to_string()][..])
    );
    assert_eq!(ha.path.as_deref(), Some("/p"));
    let b = &out.servers[1];
    let hb = b.http_settings.as_ref().expect("http_settings");
    assert_eq!(
        hb.host.as_deref(),
        Some(&["single.com".to_string()][..]),
        "标量 host → 单元素数组"
    );
    assert_eq!(hb.path.as_deref(), Some("/"), "缺 path 缺省 /");
}

#[test]
fn non_array_outbounds_is_empty() {
    let mut g = id_gen();
    let r = parse_xray_outbounds(&json!({}), "s", "now", &mut g);
    assert_eq!(r.servers.len(), 0);
    assert_eq!((r.skipped, r.failed), (0, 0));
}

// ── issue #1 缺口⑤：xray `protocol: "http"`（唯一的登记表级缺席）─────────────────
//
// 端到端确认报告（`~/docs/polaris/fixes/polaris-http-proxy-import-audit-2026-09-02.md` §④）
// 里唯一一处「白名单缺席」：同一批节点换成 sing-box JSON 全收、换成 xray JSON 则 HTTP 节点
// 整体跳过。这条差集与报告人「换成 sing-box 1.14 格式就全识别了」的描述方向完全吻合。
#[test]
fn http_outbound_maps_address_credentials_and_tls() {
    let out = parse(json!({ "outbounds": [
            // 带认证 + streamSettings TLS ⇒ HTTPS 代理。
            { "protocol": "http", "tag": "HTTP-A", "settings": { "servers": [{
                  "address": "a.example.com", "port": 8080,
                  "users": [{ "user": "alice", "pass": "secret" }] }] },
              "streamSettings": { "security": "tls", "tlsSettings": { "serverName": "sni.example.com" } } },
            // 无认证、无 streamSettings ⇒ 明文 HTTP 代理，缺省 tcp + 无 TLS。
            { "protocol": "http", "settings": { "servers": [{ "address": "b.example.com", "port": 3128 }] } }
        ] }));
    assert_eq!(
        (out.skipped, out.failed),
        (0, 0),
        "http 已在册，不得计 skipped/failed；warnings={:?}",
        out.warnings
    );
    assert_eq!(out.servers.len(), 2, "两个 http outbound 都应入库");

    let a = &out.servers[0];
    assert_eq!(a.name, "HTTP-A", "tag → name");
    assert_eq!(a.protocol, Protocol::Http);
    assert_eq!((a.address.as_str(), a.port), ("a.example.com", 8080));
    assert_eq!(
        a.username.as_deref(),
        Some("alice"),
        "users[0].user → username"
    );
    assert_eq!(
        a.password.as_deref(),
        Some("secret"),
        "users[0].pass → password"
    );
    assert_eq!(a.security, Some(SecurityMode::Tls));
    assert_eq!(
        a.tls_settings
            .as_ref()
            .and_then(|t| t.server_name.as_deref()),
        Some("sni.example.com")
    );

    let b = &out.servers[1];
    assert_eq!(b.protocol, Protocol::Http);
    assert_eq!((b.address.as_str(), b.port), ("b.example.com", 3128));
    assert_eq!((b.username.as_deref(), b.password.as_deref()), (None, None));
    assert_eq!(
        b.network.as_deref(),
        Some("tcp"),
        "无 streamSettings 缺省 tcp"
    );
    assert_eq!(
        b.security,
        Some(SecurityMode::None),
        "无 streamSettings 缺省无 TLS（与 Clash / 分享链接两腿同口径）"
    );
    assert_eq!(b.name, "b.example.com:3128", "无 tag → address:port");
}

/// 受支持不等于放宽字段校验：缺 address / port 越界仍计 failed（与其余四腿同分层）。
#[test]
fn http_and_socks_outbound_with_missing_fields_count_failed() {
    let out = parse(json!({ "outbounds": [
            { "protocol": "http", "settings": { "servers": [{ "port": 8080 }] } },       // 缺 address
            { "protocol": "http", "settings": { "servers": [{ "address": "c.example.com" }] } }, // 缺 port
            { "protocol": "http", "settings": {} },                                       // 缺 servers
            { "protocol": "socks", "settings": { "servers": [{ "port": 1080 }] } },      // 缺 address
            { "protocol": "socks", "settings": {} }                                       // 缺 servers
        ] }));
    assert_eq!(out.servers.len(), 0);
    assert_eq!(out.failed, 5, "受支持但字段缺失 → failed");
    assert_eq!(out.skipped, 0, "不得再计入「不支持的 Xray 协议」");
}

// ── issue #1 姊妹腿：xray `protocol: "socks"`（与 http 完全同类的登记表级缺席）──────────
//
// Clash（`socks5|socks`）、sing-box（`SINGBOX_SUPPORTED_TYPES` 含 `"socks"`）、分享链接
// （`socks://` / `socks5://` / `s5://`）三条腿都收 socks，唯独 xray 导入把它当不支持整体跳过。
#[test]
fn socks_outbound_maps_address_and_optional_credentials() {
    let out = parse(json!({ "outbounds": [
            // 带认证（xray socks outbound 与 http 共用 servers[].users[].{user,pass}）。
            { "protocol": "socks", "tag": "SOCKS-A", "settings": { "servers": [{
                  "address": "s.example.com", "port": 1080,
                  "users": [{ "user": "alice", "pass": "secret" }] }] } },
            // 匿名（无 users）⇒ 不得因缺凭据被拒，与 Clash / 分享链接同口径。
            { "protocol": "socks", "settings": { "servers": [{ "address": "t.example.com", "port": 1081 }] } }
        ] }));
    assert_eq!(
        (out.skipped, out.failed),
        (0, 0),
        "socks 已在册，不得计 skipped/failed；warnings={:?}",
        out.warnings
    );
    assert_eq!(out.servers.len(), 2, "两个 socks outbound 都应入库");

    let a = &out.servers[0];
    assert_eq!(a.name, "SOCKS-A", "tag → name");
    assert_eq!(a.protocol, Protocol::Socks);
    assert_eq!((a.address.as_str(), a.port), ("s.example.com", 1080));
    assert_eq!(
        (a.username.as_deref(), a.password.as_deref()),
        (Some("alice"), Some("secret")),
        "users[0].{{user,pass}} → username/password"
    );
    assert_eq!(a.network.as_deref(), Some("tcp"));
    assert_eq!(a.security, Some(SecurityMode::None), "socks 无 TLS");

    let b = &out.servers[1];
    assert_eq!(b.protocol, Protocol::Socks);
    assert_eq!((b.address.as_str(), b.port), ("t.example.com", 1081));
    assert_eq!(
        (b.username.as_deref(), b.password.as_deref()),
        (None, None),
        "匿名 socks：凭据留空而不是空串"
    );
    assert_eq!(b.name, "t.example.com:1081", "无 tag → address:port");
}
