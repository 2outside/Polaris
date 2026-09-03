//! 分享链接解析单测。
//!
//! 覆盖：各 scheme 特征 + transport 别名全表 + 裸 IPv6 歧义边界 + 脏输入容错分层 +
//! 前后端 scheme 白名单同源。断言全部锁**事故形态**（issue #263 / #191 / K3-1），
//! 不做「跑通即可」的形式覆盖。

use super::*;

/// 测试用 id 生成（确定性，便于断言）。
fn ids() -> impl FnMut() -> String {
    let mut n = 0u32;
    move || {
        n += 1;
        format!("id-{n}")
    }
}

/// 解析成功即返回 config，失败 panic 带原因。
fn parse_ok(url: &str) -> ServerConfig {
    let mut w = |_: String| {};
    parse_share_url(url, &mut ids(), &mut w).unwrap_or_else(|e| panic!("{url} 应解析成功: {e}"))
}

/// 解析必须失败，返回错误消息。
fn parse_err(url: &str) -> String {
    let mut w = |_: String| {};
    match parse_share_url(url, &mut ids(), &mut w) {
        Ok(c) => panic!("{url} 应拒绝，却产出节点 {:?}", c.name),
        Err(e) => e,
    }
}

const U: &str = "11111111-1111-1111-1111-111111111111";

// ── 前后端 scheme 白名单同源（issue #191）──────────────────────────────────────

#[test]
fn scheme_whitelist_matches_frontend() {
    // 前后端各持一份白名单 → naive:// 曾仅后端支持、前端漏列（issue #191）。
    // Rust 无法 import TS 常量，故以此测试跨语言对差：任一侧增删 scheme 而另一侧未跟 → 红。
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../ui/src/domain/protocol-url-schemes.ts"
    );
    let src = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("读不到前端白名单单一真值 {path}: {e}（文件移动请同步本测试）"));

    // 剥行注释后截取 SUPPORTED_URL_SCHEMES = [ ... ] 段，抽单引号 token。
    let no_comments: String = src
        .lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    let start = no_comments
        .find("SUPPORTED_URL_SCHEMES")
        .and_then(|i| no_comments[i..].find('[').map(|j| i + j + 1))
        .expect("前端白名单数组起始未找到");
    let end = start
        + no_comments[start..]
            .find(']')
            .expect("前端白名单数组结束未找到");
    let front: Vec<&str> = no_comments[start..end]
        .split('\'')
        .skip(1)
        .step_by(2)
        .collect();

    assert!(!front.is_empty(), "前端白名单解析出 0 条，测试自身失效");
    assert_eq!(
        front, SUPPORTED_URL_SCHEMES,
        "前后端 scheme 白名单漂移（issue #191 复发面）：前端={front:?} Rust={SUPPORTED_URL_SCHEMES:?}"
    );
}

#[test]
fn is_supported_matches_prefix_exactly() {
    assert!(is_supported_share_url("vless://x"));
    assert!(is_supported_share_url("naive+https://x"));
    // 'http' 不得误命中 'https://'（前缀精确匹配，列表顺序无关）。
    assert!(is_supported_share_url("https://x"));
    assert!(is_supported_share_url("http://x"));
    assert!(!is_supported_share_url("ftp://x"));
    assert!(!is_supported_share_url("wireguard://x"));
    assert!(!is_supported_share_url("tailscale://x"));
    // scheme 大小写不敏感（RFC 3986 §3.1，与前端 isSupportedShareUrl 同口径）。
    // 专项门见 `uppercase_scheme_is_case_insensitive_per_rfc3986`。
    assert!(is_supported_share_url("VLESS://x"));
    // 缺 :// 或空体。
    assert!(!is_supported_share_url("vless"));
    assert!(!is_supported_share_url("vless://"));
    assert!(!is_supported_share_url(""));
}

#[test]
fn unsupported_scheme_rejected_with_scheme_name() {
    assert_eq!(parse_err("ftp://x.example.com"), "不支持的协议: ftp");
}

// ── transport 别名全表（issue #263 事故面）────────────────────────────────────

#[test]
fn transport_alias_full_table_via_uri() {
    // 别名表逐条过 URI 路径（归一函数的单测在 config-engine；此处锁「解析器确实接了它」）。
    for (ty, want_net) in [
        ("ws", "ws"),
        ("WS", "ws"),
        ("httpupgrade", "httpupgrade"),
        ("HttpUpgrade", "httpupgrade"),
        ("grpc", "grpc"),
        ("h2", "http"),
        ("http", "http"),
        ("tcp", "tcp"),
        ("raw", "tcp"),
        ("none", "tcp"),
        ("RAW", "tcp"),
    ] {
        let c = parse_ok(&format!(
            "vless://{U}@a.com:443?encryption=none&type={ty}#n"
        ));
        assert_eq!(
            c.network.as_deref(),
            Some(want_net),
            "type={ty} 应归一为 {want_net}"
        );
    }
}

#[test]
fn transport_unknown_rejects_whole_node_with_searchable_message() {
    // issue #263 根因：机场把 vless 迁到 xhttp → default 分支整船丢。
    // 修法是**拒节点 + 可检索告警**，不是假装支持（sing-box 内核本就连不上）。
    for ty in ["xhttp", "splithttp", "kcp", "quic"] {
        let e = parse_err(&format!(
            "vless://{U}@a.com:443?encryption=none&type={ty}#n"
        ));
        assert!(
            e.contains("不支持的传输层类型"),
            "{ty}: 消息须含可检索关键词（用户定案靠日志搜它），实为 {e}"
        );
        assert!(e.contains(ty), "{ty}: 消息须点名靶点，实为 {e}");
    }
}

#[test]
fn transport_alias_shared_between_uri_and_vmess_paths() {
    // 收敛证明：同一别名在两条入参形态（URI type= / vmess JSON net）产出同一 network。
    // 上游 此处是两份表 → 曾各自漏 case。
    for (ty, want) in [
        ("ws", "ws"),
        ("httpupgrade", "httpupgrade"),
        ("h2", "http"),
        ("raw", "tcp"),
        ("none", "tcp"),
        ("grpc", "grpc"),
    ] {
        let via_uri = parse_ok(&format!(
            "vless://{U}@a.com:443?encryption=none&type={ty}#n"
        ));
        let via_vmess = parse_ok(&vmess_url(&format!(
            r#"{{"add":"a.com","port":"443","id":"{U}","ps":"n","net":"{ty}"}}"#
        )));
        assert_eq!(via_uri.network.as_deref(), Some(want), "uri type={ty}");
        assert_eq!(
            via_vmess.network, via_uri.network,
            "两条形态对同一别名 {ty} 必须产出同一 network"
        );
    }
}

#[test]
fn ws_and_httpupgrade_share_path_host_carrier() {
    let c = parse_ok(&format!(
        "vless://{U}@a.com:443?encryption=none&type=httpupgrade&path=%2Fhu&host=h.com#n"
    ));
    assert_eq!(c.network.as_deref(), Some("httpupgrade"));
    let ws = c.ws_settings.expect("httpupgrade 复用 ws 承载 path/host");
    assert_eq!(ws.path.as_deref(), Some("/hu"));
    assert_eq!(
        ws.headers.unwrap().get("Host").map(String::as_str),
        Some("h.com")
    );
}

// ── 裸 IPv6 歧义（fixes 文档的启发式，url-list 路径专有）────────────────────────

#[test]
fn bare_ipv6_with_port_splits() {
    let c = parse_ok(&format!("vless://{U}@2001:db8::1:443?encryption=none#v6"));
    assert_eq!(c.address, "2001:db8::1");
    assert_eq!(c.port, 443);
}

#[test]
fn bare_ipv6_single_digit_tail_is_address_not_port() {
    // `2001:db8::1:1` 末段单数字 → 按地址整段（真实代理端口不用 1-9，而地址末段 '1' 极常见）。
    let c = parse_ok(&format!("vless://{U}@2001:db8::1:1?encryption=none#v6"));
    assert_eq!(c.address, "2001:db8::1:1", "单数字末段不得被当端口切走");
    assert_eq!(c.port, 443, "端口缺省交 parse_base");
}

#[test]
fn bare_ipv6_without_port_defaults() {
    let c = parse_ok(&format!("vless://{U}@2001:db8::1?encryption=none#v6"));
    assert_eq!(c.address, "2001:db8::1");
    assert_eq!(c.port, 443);
}

#[test]
fn bare_ipv6_port_boundary() {
    let c = parse_ok(&format!("vless://{U}@2001:db8::1:65535?encryption=none#v6"));
    assert_eq!((c.address.as_str(), c.port), ("2001:db8::1", 65535));
    // 65536 越界 → 既非端口、整段也非合法 IPv6 → 原样交 URL 解析报错（丢弃可见，不静默截断）。
    let e = parse_err(&format!("vless://{U}@2001:db8::1:65536?encryption=none#v6"));
    assert!(e.contains("Invalid URL"), "越界端口须丢弃可见，实为 {e}");
}

#[test]
fn bracketed_ipv6_unchanged_and_stripped() {
    let c = parse_ok(&format!("vless://{U}@[2001:db8::1]:443?encryption=none#v6"));
    assert_eq!(c.address, "2001:db8::1", "方括号须剥离");
    let c = parse_ok(&format!("vless://{U}@[2001:db8::1]?encryption=none#v6"));
    assert_eq!((c.address.as_str(), c.port), ("2001:db8::1", 443));
}

#[test]
fn bare_ipv6_generalized_beyond_ss() {
    // issue #263：原仅 ss:// 处理，vless/trojan/hy2 裸 IPv6 全在 URL 解析处 throw 整节点丢。
    let t = parse_ok("trojan://pw@2001:db8::2:8443#t6");
    assert_eq!((t.address.as_str(), t.port), ("2001:db8::2", 8443));
    let h = parse_ok("hysteria2://pw@2001:db8::3:443#h6");
    assert_eq!((h.address.as_str(), h.port), ("2001:db8::3", 443));
}

#[test]
fn bare_ipv6_non_ipv6_garbage_is_rejected_not_truncated() {
    // 两种读法皆非 → 原样返回交 URL 解析抛错。绝不静默入库「截断地址」的假节点。
    let e = parse_err(&format!(
        "vless://{U}@notipv6:garbage:443?encryption=none#x"
    ));
    assert!(e.contains("Invalid URL"), "实为 {e}");
}

#[test]
fn sip002_bare_ipv6_with_plugin_truncates_at_slash() {
    // `…:port/?plugin=…` 的 `/` 在 `?` 前是 SIP002 标准写法；不截断则 hostPort 携 `/` 双判定皆失败。
    let c = parse_ok(&format!(
        "ss://{}@2001:db8::1:8388/?plugin=obfs-local%3Bobfs%3Dhttp#ss-v6",
        b64("aes-128-gcm:pw")
    ));
    assert_eq!((c.address.as_str(), c.port), ("2001:db8::1", 8388));
    assert_eq!(
        c.shadowsocks_settings.unwrap().plugin.as_deref(),
        Some("obfs-local")
    );
}

// ── security 类型化协同（§L1 / K3-1）──────────────────────────────────────────

#[test]
fn security_case_variants_enable_tls_not_silent_plaintext() {
    // K3-1 事故形态：裸串 + `== "tls"` 严格比较 → `security=TLS` 静默不启用 TLS（明文出站）。
    for raw in ["tls", "TLS", "Tls"] {
        let c = parse_ok(&format!(
            "vless://{U}@a.com:443?encryption=none&security={raw}&sni=s.com#n"
        ));
        assert_eq!(c.security, Some(SecurityMode::Tls), "security={raw}");
        assert!(
            c.tls_settings.is_some(),
            "security={raw} 必须带 tlsSettings（否则静默明文）"
        );
    }
    for raw in ["reality", "REALITY", "Reality"] {
        let c = parse_ok(&format!(
            "vless://{U}@a.com:443?encryption=none&security={raw}&pbk=PK&sni=s.com#n"
        ));
        assert_eq!(c.security, Some(SecurityMode::Reality), "security={raw}");
        assert!(c.reality_settings.is_some(), "security={raw}");
    }
}

#[test]
fn security_dirty_value_keeps_node_alive() {
    // §L1：单个脏枚举不得让整个节点消失；保留原文、按非 TLS 处理、不报错。
    let c = parse_ok(&format!(
        "vless://{U}@a.com:443?encryption=none&security=bogus-mode#n"
    ));
    assert_eq!(c.security, Some(SecurityMode::Unknown("bogus-mode".into())));
    assert!(c.tls_settings.is_none(), "未知模式不得被当作 TLS");
    assert_eq!(c.name, "n", "其余字段完好");
}

#[test]
fn vmess_tls_case_variant_enables_tls() {
    // 上游 此处是 `vmessData.tls === 'tls'` 裸串比较 → `"tls":"TLS"` 静默明文（K3-1 同类）。
    let c = parse_ok(&vmess_url(&format!(
        r#"{{"add":"a.com","port":"443","id":"{U}","ps":"n","net":"tcp","tls":"TLS"}}"#
    )));
    assert_eq!(c.security, Some(SecurityMode::Tls));
    assert!(c.tls_settings.is_some(), "大小写变体必须照常启用 TLS");
}

#[test]
fn vmess_absent_tls_is_none_security() {
    let c = parse_ok(&vmess_url(&format!(
        r#"{{"add":"a.com","port":"443","id":"{U}","ps":"n","net":"tcp"}}"#
    )));
    assert_eq!(c.security, Some(SecurityMode::None));
    assert!(c.tls_settings.is_none());
}

// ── R4 token 边界归一 ────────────────────────────────────────────────────────

#[test]
fn r4_tokens_normalized_at_parse() {
    // 未归一 → sing-box FATAL（fingerprint/flow/vmessSecurity）或静默丢传输层（network）。
    let c = parse_ok(&format!(
        "vless://{U}@a.com:443?encryption=none&security=tls&fp=Chrome&flow=XTLS-RPRX-Vision&type=WS&sni=s.com#n"
    ));
    assert_eq!(c.flow.as_deref(), Some("xtls-rprx-vision"));
    assert_eq!(c.network.as_deref(), Some("ws"));
    assert_eq!(
        c.tls_settings.unwrap().fingerprint.as_deref(),
        Some("chrome")
    );

    let v = parse_ok(&vmess_url(&format!(
        r#"{{"add":"a.com","port":"443","id":"{U}","ps":"n","net":"tcp","scy":"AES-128-GCM","tls":"tls","fp":"Firefox"}}"#
    )));
    assert_eq!(v.vmess_security.as_deref(), Some("aes-128-gcm"));
    assert_eq!(
        v.tls_settings.unwrap().fingerprint.as_deref(),
        Some("firefox")
    );
}

#[test]
fn fingerprint_alias_fp_or_fingerprint() {
    let c = parse_ok(&format!(
        "vless://{U}@a.com:443?encryption=none&security=tls&fingerprint=FIREFOX&sni=s.com#n"
    ));
    assert_eq!(
        c.tls_settings.unwrap().fingerprint.as_deref(),
        Some("firefox")
    );
}

// ── 凭据残缺 / 能力缺席 → 整节点拒绝 ──────────────────────────────────────────

#[test]
fn reality_without_pbk_rejected() {
    // 缺 pbk 的 reality 无法握手（builder 不生成 reality tls 块 → 退化裸 TCP 假节点）。
    for url in [
        format!("vless://{U}@a.com:443?encryption=none&security=reality&sni=s.com#n"),
        "trojan://pw@a.com:443?security=reality#n".to_string(),
        "anytls://pw@a.com:443?security=reality#n".to_string(),
    ] {
        let e = parse_err(&url);
        assert!(e.contains("pbk"), "{url}: 实为 {e}");
    }
}

#[test]
fn hysteria2_salamander_without_password_rejected() {
    // 声明 salamander 即服务端强制混淆，缺密码剥离后裸连必死（假节点）。
    let e = parse_err("hysteria2://pw@a.com:443?obfs=salamander#n");
    assert!(e.contains("obfs-password"), "实为 {e}");
}

#[test]
fn hysteria2_unknown_obfs_stripped_with_warning_not_rejected() {
    // 非 salamander → 剥离 + warn 留痕（不拒节点：sing-box 无对应混淆，裸连仍可用）。
    let mut warns = Vec::new();
    let mut w = |m: String| warns.push(m);
    let c = parse_share_url(
        "hysteria2://pw@a.com:443?obfs=faketype&obfs-password=x#n",
        &mut ids(),
        &mut w,
    )
    .expect("未知 obfs 应剥离而非拒节点");
    assert!(c
        .hysteria2_settings
        .map(|h| h.obfs.is_none())
        .unwrap_or(true));
    assert_eq!(warns.len(), 1, "剥离必须留痕可见");
    assert!(warns[0].contains("faketype"), "{:?}", warns);
}

#[test]
fn missing_credentials_rejected() {
    assert!(parse_err("vless://@a.com:443?encryption=none#n").contains("UUID"));
    assert!(parse_err("hysteria2://@a.com:443#n").contains("密码"));
    assert!(parse_err("anytls://@a.com:443#n").contains("密码"));
    assert!(parse_err("snell://@a.com:443?version=4#n").contains("psk"));
    assert!(parse_err("tuic://onlyuuid@a.com:443#n").contains("uuid 或 password"));
    assert!(parse_err("ss://@a.com:8388#n").contains("加密信息"));
    assert!(parse_err("naive://u@a.com:443#n").contains("用户名或密码"));
}

#[test]
fn snell_whitespace_only_psk_rejected() {
    // trim 语义与 completeness 闸门对齐：'%20' → ' ' → 视同缺失。
    assert!(parse_err("snell://%20@a.com:443?version=4#n").contains("psk"));
}

// ── snell（三路之一：snell:// 事实形态）───────────────────────────────────────

#[test]
fn snell_v4_http_obfs() {
    let c =
        parse_ok("snell://psk-secret@s.com:443?version=4&obfs=http&obfs-host=bing.com&reuse=1#s4");
    assert_eq!(c.protocol, Protocol::Snell);
    assert_eq!(c.password.as_deref(), Some("psk-secret"));
    let s = c.snell_settings.unwrap();
    assert_eq!(s.version, 4);
    assert_eq!(s.obfs_mode.as_deref(), Some("http"));
    assert_eq!(s.obfs_host.as_deref(), Some("bing.com"));
    assert_eq!(s.reuse, Some(true));
}

#[test]
fn snell_v6_mode_and_userkey() {
    let c = parse_ok("snell://pw@s.com:443?version=6&mode=unsafe-raw&network=tcp&userkey=uk#s6");
    let s = c.snell_settings.unwrap();
    assert_eq!(s.version, 6);
    assert_eq!(s.mode.as_deref(), Some("unsafe-raw"));
    assert_eq!(s.network.as_deref(), Some("tcp"));
    assert_eq!(s.userkey.as_deref(), Some("uk"));
}

#[test]
fn snell_version_defaults_to_4_and_v_alias() {
    assert_eq!(
        parse_ok("snell://pw@s.com:443#n")
            .snell_settings
            .unwrap()
            .version,
        4
    );
    assert_eq!(
        parse_ok("snell://pw@s.com:443?v=6#n")
            .snell_settings
            .unwrap()
            .version,
        6
    );
}

#[test]
fn snell_capability_gate_rejects_out_of_range() {
    // sing-box 官方 snell 仅 4/6；v1-3 是 Surge/mihomo 旧协议版本 → 入库也连不上。
    for v in ["1", "2", "3", "5", "7", "abc", ""] {
        let e = parse_err(&format!("snell://pw@s.com:443?version={v}#n"));
        assert!(e.contains("Snell 版本不受支持"), "version={v}: 实为 {e}");
    }
}

#[test]
fn snell_obfs_capability_gate() {
    // v4 tls 混淆（Surge 旧形态）/ v6 带 obfs：sing-box snell 无对应能力 → 拒。
    assert!(parse_err("snell://pw@s.com:443?version=4&obfs=tls#n").contains("obfs 不受支持"));
    assert!(parse_err("snell://pw@s.com:443?version=6&obfs=http#n").contains("obfs 不受支持"));
    // obfs=none / 缺省 → 不设混淆，不拒。
    assert!(parse_ok("snell://pw@s.com:443?version=4&obfs=none#n")
        .snell_settings
        .unwrap()
        .obfs_mode
        .is_none());
}

#[test]
fn snell_psk_with_colon_is_rejoined() {
    // psk 含未编码 ':' 时 URL 引擎拆成 username:password —— 两段拼回，避免静默截断成假节点。
    let c = parse_ok("snell://part1:part2@s.com:443?version=4#n");
    assert_eq!(c.password.as_deref(), Some("part1:part2"));
}

// ── shadowsocks ──────────────────────────────────────────────────────────────

#[test]
fn ss_base64_userinfo() {
    let c = parse_ok(&format!("ss://{}@e.com:8388#ss", b64("aes-256-gcm:pw")));
    let s = c.shadowsocks_settings.unwrap();
    assert_eq!(
        (s.method.as_str(), s.password.as_str()),
        ("aes-256-gcm", "pw")
    );
}

#[test]
fn ss_sip002_plaintext_userinfo() {
    let c = parse_ok("ss://aes-256-gcm:sspass@e.com:8388#ss");
    let s = c.shadowsocks_settings.unwrap();
    assert_eq!(
        (s.method.as_str(), s.password.as_str()),
        ("aes-256-gcm", "sspass")
    );
}

#[test]
fn ss_name_defaults() {
    assert_eq!(
        parse_ok(&format!("ss://{}@e.com:8388", b64("aes-256-gcm:pw"))).name,
        "Shadowsocks"
    );
}

#[test]
fn ss_shadow_tls_via_query_params() {
    let c = parse_ok(&format!(
        "ss://{}@e.com:8388?shadow-tls-password=stpw&shadow-tls-sni=st.com&shadow-tls-fp=Firefox&shadow-tls-port=443#n",
        b64("aes-256-gcm:pw")
    ));
    let st = c.shadow_tls_settings.expect("shadow-tls-* 直传形态");
    assert_eq!(st.password, "stpw");
    assert_eq!(st.sni, "st.com");
    assert_eq!(st.fingerprint.as_deref(), Some("firefox"), "指纹须边界归一");
    assert_eq!(st.port, Some(443));
}

#[test]
fn ss_plugin_options_split() {
    let c = parse_ok(&format!(
        "ss://{}@e.com:8388?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Db.com#n",
        b64("aes-256-gcm:pw")
    ));
    let s = c.shadowsocks_settings.unwrap();
    assert_eq!(s.plugin.as_deref(), Some("obfs-local"));
    assert_eq!(s.plugin_opts.as_deref(), Some("obfs=http;obfs-host=b.com"));
}

// ── vmess ────────────────────────────────────────────────────────────────────

#[test]
fn vmess_ws_full() {
    let c = parse_ok(&vmess_url(
        r#"{"add":"v.com","port":"443","id":"vm-1","ps":"vmess-ws","aid":"0","net":"ws","path":"/wp","host":"cdn.com","tls":"tls","sni":"sni.com","scy":"auto","alpn":"h2,http/1.1"}"#,
    ));
    assert_eq!(c.protocol, Protocol::Vmess);
    assert_eq!(c.name, "vmess-ws");
    assert_eq!((c.address.as_str(), c.port), ("v.com", 443));
    assert_eq!(c.uuid.as_deref(), Some("vm-1"));
    assert_eq!(c.alter_id, Some(0));
    assert_eq!(c.network.as_deref(), Some("ws"));
    let tls = c.tls_settings.unwrap();
    assert_eq!(tls.server_name.as_deref(), Some("sni.com"));
    assert_eq!(tls.alpn.unwrap(), vec!["h2", "http/1.1"]);
}

#[test]
fn vmess_incomplete_rejected() {
    for body in [
        r#"{"add":"","port":"443","id":"x","ps":"n","net":"tcp"}"#,
        r#"{"add":"a.com","port":"443","ps":"n","net":"tcp"}"#,
        r#"{"add":"a.com","id":"x","ps":"n","net":"tcp"}"#,
    ] {
        assert!(
            parse_err(&vmess_url(body)).contains("配置信息不完整"),
            "{body}"
        );
    }
}

#[test]
fn vmess_malformed_base64_or_json_rejected() {
    assert!(!parse_err("vmess://!!!notbase64!!!").is_empty());
    assert!(parse_err(&vmess_url_raw(&b64("not a json"))).contains("JSON"));
}

#[test]
fn vmess_alpn_array_form_deduped() {
    let c = parse_ok(&vmess_url(
        r#"{"add":"a.com","port":"443","id":"x","ps":"n","net":"ws","tls":"tls","alpn":["h2"," h2 ","http/1.1"]}"#,
    ));
    // 带前导空格的 ALPN 原样进 sing-box 会按字面匹配失败 → dedupe_trim 保序去重。
    assert_eq!(
        c.tls_settings.unwrap().alpn.unwrap(),
        vec!["h2", "http/1.1"]
    );
}

// ── tuic / anytls duration 归一 ──────────────────────────────────────────────

#[test]
fn tuic_heartbeat_bare_ms_gets_unit() {
    // 订阅写裸毫秒整数 → 必须补 ms 单位，否则 sing-box "missing unit"。
    let c = parse_ok("tuic://uu:pp@g.com:443?heartbeat=10000&congestion_control=bbr#n");
    let t = c.tuic_settings.unwrap();
    assert_eq!(t.heartbeat.as_deref(), Some("10000ms"));
    assert_eq!(t.congestion_control.as_deref(), Some("bbr"));
    // 已带单位透传。
    let c = parse_ok("tuic://uu:pp@g.com:443?heartbeat=10s#n");
    assert_eq!(c.tuic_settings.unwrap().heartbeat.as_deref(), Some("10s"));
}

#[test]
fn tuic_enum_gates_drop_invalid_values() {
    let c = parse_ok("tuic://uu:pp@g.com:443?congestion_control=bogus&udp_relay_mode=bogus#n");
    let t = c.tuic_settings.unwrap();
    assert_eq!(t.congestion_control, None, "非白名单拥塞控制须丢弃");
    assert_eq!(t.udp_relay_mode, None);
}

#[test]
fn tuic_name_default() {
    assert_eq!(parse_ok("tuic://uu:pp@g.com:443").name, "TUIC Node");
}

#[test]
fn anytls_min_idle_session_zero_kept_nan_dropped() {
    // min=0 是合法值（须保留）；非数字串必须丢弃（不得写成 NaN）。
    let c = parse_ok("anytls://pw@f.com:443?security=tls&min_idle_session=0#n");
    assert_eq!(c.any_tls_settings.unwrap().min_idle_session, Some(0));
    let c = parse_ok("anytls://pw@f.com:443?security=tls&min_idle_session=abc#n");
    assert_eq!(c.any_tls_settings.and_then(|a| a.min_idle_session), None);
}

#[test]
fn anytls_defaults_to_tls() {
    let c = parse_ok("anytls://pw@f.com:443#n");
    assert_eq!(c.security, Some(SecurityMode::Tls));
    assert!(c.tls_settings.is_some());
}

#[test]
fn anytls_duration_normalized() {
    let c = parse_ok(
        "anytls://pw@f.com:443?security=tls&idle_session_check_interval=30000&idle_session_timeout=5s#n",
    );
    let a = c.any_tls_settings.unwrap();
    assert_eq!(a.idle_session_check_interval.as_deref(), Some("30000ms"));
    assert_eq!(a.idle_session_timeout.as_deref(), Some("5s"));
}

// ── 协议默认值 / 别名族 ──────────────────────────────────────────────────────

#[test]
fn trojan_defaults_to_tls() {
    let c = parse_ok("trojan://pw@c.com:443#n");
    assert_eq!(c.security, Some(SecurityMode::Tls));
}

#[test]
fn hysteria2_forces_tls_and_sni_fallback() {
    let c = parse_ok("hysteria2://pw@d.com:8443#n");
    assert_eq!(c.security, Some(SecurityMode::Tls));
    assert_eq!(
        c.tls_settings.unwrap().server_name.as_deref(),
        Some("d.com"),
        "缺 SNI 时回落 address"
    );
}

#[test]
fn hy2_is_alias_of_hysteria2() {
    assert_eq!(
        parse_ok("hy2://pw@d.com:443#n").protocol,
        Protocol::Hysteria2
    );
}

#[test]
fn naive_alias_family() {
    for url in [
        "naive://u:p@h.com:443#n",
        "naive+https://u:p@h.com:443#n",
        "http2://u:p@h.com:443#n",
        // 部分客户端用 https://..#naive 形态。
        "https://u:p@h.com:443#naive",
        "https://u:p@h.com:443#NAIVE",
    ] {
        assert_eq!(parse_ok(url).protocol, Protocol::Naive, "{url}");
    }
    // 无 naive 片段的 https → 普通 http 协议节点。
    assert_eq!(
        parse_ok("https://u:p@h.com:443#plain").protocol,
        Protocol::Http
    );
}

#[test]
fn socks_alias_family_and_default_port() {
    for url in [
        "socks5://u:p@j.com:1080#n",
        "socks://u:p@j.com:1080#n",
        "s5://u:p@j.com:1080#n",
    ] {
        assert_eq!(parse_ok(url).protocol, Protocol::Socks, "{url}");
    }
    assert_eq!(
        parse_ok("socks5://u:p@j.com#n").port,
        1080,
        "socks 默认端口"
    );
}

#[test]
fn http_default_ports_and_security() {
    let c = parse_ok("http://u:p@h.com#n");
    assert_eq!((c.port, c.security.clone()), (80, Some(SecurityMode::None)));
    let c = parse_ok("https://u:p@h.com#n");
    assert_eq!((c.port, c.security.clone()), (443, Some(SecurityMode::Tls)));
    assert!(c.tls_settings.is_some());
}

#[test]
fn name_defaults_to_address_port() {
    assert_eq!(
        parse_ok(&format!("vless://{U}@n.com:443?encryption=none")).name,
        "n.com:443"
    );
}

#[test]
fn name_percent_decoded() {
    assert_eq!(parse_ok("socks5://g.com:1080#My%20Node").name, "My Node");
    assert_eq!(
        parse_ok(&format!(
            "vless://{U}@a.com:443?encryption=none#%E9%A6%99%E6%B8%AF"
        ))
        .name,
        "香港"
    );
}

#[test]
fn no_port_protocols_without_default_are_rejected() {
    // TS 侧 `parseInt(url.port,10)` 无缺省 → NaN port 坏节点（JSON 里 null）。
    // 上游 `port: u16` 不可表示 NaN → 显式拒绝（可见丢弃 > 静默坏节点）。
    assert!(parse_err("tuic://uu:pp@n.com#n").contains("缺少端口"));
    assert!(parse_err(&format!("ss://{}@n.com#n", b64("aes-256-gcm:pw"))).contains("缺少端口"));
}

// ── url-list 分发 ────────────────────────────────────────────────────────────

#[test]
fn url_list_parses_lines_and_isolates_failures() {
    let text = format!(
        "# 注释行\n\
         \n\
         vless://{U}@a.com:443?encryption=none#ok1\n\
         vless://{U}@b.com:443?encryption=none&type=xhttp#bad\n\
         trojan://pw@c.com:443#ok2\n\
         这是一行说明文字\n"
    );
    let r = parse_url_list(&text, "sub-1", "2026-01-01", &mut ids());
    assert_eq!(r.servers.len(), 2, "坏链不得连累其余节点");
    assert_eq!(r.failed, 1);
    assert!(r.warnings.iter().any(|w| w.contains("不支持的传输层类型")));
    // 注释/空行/说明文字不计入 failed（本行不含节点，非解析失败）。
    assert_eq!(r.servers[0].name, "ok1");
    assert_eq!(r.servers[1].name, "ok2");
    // 订阅归属与时间戳落盘。
    assert_eq!(r.servers[0].subscription_id.as_deref(), Some("sub-1"));
    assert_eq!(r.servers[0].created_at.as_deref(), Some("2026-01-01"));
    assert_eq!(r.servers[0].updated_at.as_deref(), Some("2026-01-01"));
}

#[test]
fn url_list_trims_lines() {
    // 行 trim（issue #263 A 线修项）：带前后空白的行仍须解析。
    let text = format!("  vless://{U}@a.com:443?encryption=none#ok  \n");
    let r = parse_url_list(&text, "s", "t", &mut ids());
    assert_eq!(r.servers.len(), 1);
}

// ── 工具 ─────────────────────────────────────────────────────────────────────

/// 测试用 base64 编码（标准字母表）。
fn b64(input: &str) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn vmess_url(json: &str) -> String {
    vmess_url_raw(&b64(json))
}

fn vmess_url_raw(b64_body: &str) -> String {
    format!("vmess://{b64_body}")
}

// ── 内部纯函数直测 ───────────────────────────────────────────────────────────

#[test]
fn js_parse_int_matches_js_semantics() {
    assert_eq!(js_parse_int("100"), Some(100));
    assert_eq!(
        js_parse_int("100abc"),
        Some(100),
        "JS parseInt 截断前导数字段"
    );
    assert_eq!(js_parse_int("  42  "), Some(42));
    assert_eq!(js_parse_int("-7"), Some(-7));
    assert_eq!(js_parse_int("abc"), None);
    assert_eq!(js_parse_int(""), None);
}

#[test]
fn decode_uri_component_rejects_malformed() {
    assert_eq!(decode_uri_component("a%20b").unwrap(), "a b");
    assert_eq!(decode_uri_component("%E9%A6%99").unwrap(), "香");
    assert!(
        decode_uri_component("%zz").is_err(),
        "畸形序列须报错（对齐 URIError）"
    );
    assert!(decode_uri_component("%E9%A6").is_err(), "非法 UTF-8 须报错");
    assert!(decode_uri_component("%").is_err());
}

#[test]
fn strip_ipv6_brackets_only_when_paired() {
    assert_eq!(strip_ipv6_brackets("[::1]"), "::1");
    assert_eq!(strip_ipv6_brackets("a.com"), "a.com");
    assert_eq!(strip_ipv6_brackets("[unclosed"), "[unclosed");
}

#[test]
fn preprocess_bare_ipv6_is_noop_without_at() {
    // vmess://base64 无 '@' → 原样返回（base64 体不得被改写）。
    assert_eq!(preprocess_bare_ipv6("vmess://abc123"), "vmess://abc123");
}

// ── 编码 round-trip（`parse_share_url(encode_share_url(cfg))` ≈ cfg）─────────────
//
// 逐协议锁死：编码器产出的 URI 必须能被解析器还原出**语义等价**节点（id 重生、name 缺省
// 回落等除外）。断言比对连接必需字段（协议/地址/端口/凭据/传输/TLS），证明是真实编码而非
// `polaris://<uuid>` 假链。

/// 编码 → 重解析（失败带 URL + 原因 panic）。
fn roundtrip(c: &ServerConfig) -> ServerConfig {
    let url = encode_share_url(c).unwrap_or_else(|e| panic!("encode 应成功: {e}"));
    let mut w = |_: String| {};
    parse_share_url(&url, &mut ids(), &mut w).unwrap_or_else(|e| panic!("重解析 {url} 应成功: {e}"))
}

#[test]
fn roundtrip_vless_ws_tls() {
    let mut c = ServerConfig {
        name: "HK-01".into(),
        protocol: Protocol::Vless,
        address: "a.example.com".into(),
        port: 443,
        uuid: Some(U.into()),
        encryption: Some("none".into()),
        network: Some("ws".into()),
        security: Some(SecurityMode::Tls),
        ..Default::default()
    };
    c.ws_settings = Some(Box::new(WebSocketSettings {
        path: Some("/vpath".into()),
        headers: Some(
            std::iter::once(("Host".to_string(), "cdn.example.com".to_string())).collect(),
        ),
        ..Default::default()
    }));
    c.tls_settings = Some(TlsSettings {
        server_name: Some("sni.example.com".into()),
        ..Default::default()
    });
    let r = roundtrip(&c);
    assert_eq!(r.protocol, Protocol::Vless);
    assert_eq!(r.address, "a.example.com");
    assert_eq!(r.port, 443);
    assert_eq!(r.uuid.as_deref(), Some(U));
    assert_eq!(r.network.as_deref(), Some("ws"));
    assert_eq!(r.security, Some(SecurityMode::Tls));
    assert_eq!(
        r.ws_settings.as_ref().unwrap().path.as_deref(),
        Some("/vpath")
    );
    assert_eq!(
        r.tls_settings.as_ref().unwrap().server_name.as_deref(),
        Some("sni.example.com")
    );
    assert_eq!(r.name, "HK-01");
}

#[test]
fn roundtrip_vless_reality() {
    let c = ServerConfig {
        name: "R".into(),
        protocol: Protocol::Vless,
        address: "1.2.3.4".into(),
        port: 8443,
        uuid: Some(U.into()),
        flow: Some("xtls-rprx-vision".into()),
        network: Some("tcp".into()),
        security: Some(SecurityMode::Reality),
        tls_settings: Some(TlsSettings {
            server_name: Some("www.microsoft.com".into()),
            ..Default::default()
        }),
        reality_settings: Some(RealitySettings {
            public_key: "PBKPBKPBK".into(),
            short_id: Some("ab12".into()),
        }),
        ..Default::default()
    };
    let r = roundtrip(&c);
    assert_eq!(r.security, Some(SecurityMode::Reality));
    assert_eq!(r.flow.as_deref(), Some("xtls-rprx-vision"));
    let reality = r.reality_settings.as_ref().expect("reality 应还原");
    assert_eq!(reality.public_key, "PBKPBKPBK");
    assert_eq!(reality.short_id.as_deref(), Some("ab12"));
}

#[test]
fn roundtrip_vmess_ws() {
    let c = ServerConfig {
        name: "vm".into(),
        protocol: Protocol::Vmess,
        address: "vm.example.com".into(),
        port: 80,
        uuid: Some(U.into()),
        alter_id: Some(0),
        vmess_security: Some("auto".into()),
        network: Some("ws".into()),
        ws_settings: Some(Box::new(WebSocketSettings {
            path: Some("/ray".into()),
            headers: Some(
                std::iter::once(("Host".to_string(), "h.example.com".to_string())).collect(),
            ),
            ..Default::default()
        })),
        ..Default::default()
    };
    let r = roundtrip(&c);
    assert_eq!(r.protocol, Protocol::Vmess);
    assert_eq!(r.address, "vm.example.com");
    assert_eq!(r.port, 80);
    assert_eq!(r.uuid.as_deref(), Some(U));
    assert_eq!(r.network.as_deref(), Some("ws"));
    assert_eq!(
        r.ws_settings.as_ref().unwrap().path.as_deref(),
        Some("/ray")
    );
}

#[test]
fn roundtrip_vmess_tls() {
    let c = ServerConfig {
        name: "vmtls".into(),
        protocol: Protocol::Vmess,
        address: "vm.example.com".into(),
        port: 443,
        uuid: Some(U.into()),
        network: Some("tcp".into()),
        security: Some(SecurityMode::Tls),
        tls_settings: Some(TlsSettings {
            server_name: Some("sni.example.com".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let r = roundtrip(&c);
    assert_eq!(r.security, Some(SecurityMode::Tls));
    assert_eq!(
        r.tls_settings.as_ref().unwrap().server_name.as_deref(),
        Some("sni.example.com")
    );
}

#[test]
fn roundtrip_trojan() {
    let c = ServerConfig {
        name: "tj".into(),
        protocol: Protocol::Trojan,
        address: "t.example.com".into(),
        port: 443,
        password: Some("p@ss w0rd/+=".into()),
        security: Some(SecurityMode::Tls),
        tls_settings: Some(TlsSettings {
            server_name: Some("t.sni.com".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let r = roundtrip(&c);
    assert_eq!(r.protocol, Protocol::Trojan);
    assert_eq!(
        r.password.as_deref(),
        Some("p@ss w0rd/+="),
        "特殊字符密码须转义还原"
    );
    assert_eq!(r.security, Some(SecurityMode::Tls));
    assert_eq!(
        r.tls_settings.as_ref().unwrap().server_name.as_deref(),
        Some("t.sni.com")
    );
}

#[test]
fn roundtrip_shadowsocks() {
    let c = ServerConfig {
        name: "ss".into(),
        protocol: Protocol::Shadowsocks,
        address: "ss.example.com".into(),
        port: 8388,
        shadowsocks_settings: Some(Box::new(ShadowsocksSettings {
            method: "aes-256-gcm".into(),
            password: "sspass:with:colons".into(),
            ..Default::default()
        })),
        ..Default::default()
    };
    let r = roundtrip(&c);
    assert_eq!(r.protocol, Protocol::Shadowsocks);
    let ss = r.shadowsocks_settings.as_ref().expect("ss 设置还原");
    assert_eq!(ss.method, "aes-256-gcm");
    assert_eq!(ss.password, "sspass:with:colons");
    assert_eq!(r.port, 8388);
}

#[test]
fn roundtrip_hysteria2() {
    let c = ServerConfig {
        name: "hy2".into(),
        protocol: Protocol::Hysteria2,
        address: "hy.example.com".into(),
        port: 443,
        password: Some("hypw".into()),
        security: Some(SecurityMode::Tls),
        tls_settings: Some(TlsSettings {
            server_name: Some("hy.sni.com".into()),
            ..Default::default()
        }),
        hysteria2_settings: Some(Box::new(Hysteria2Settings {
            obfs: Some(Hysteria2ObfsSettings {
                type_field: Some("salamander".into()),
                password: Some("obfspw".into()),
                ..Default::default()
            }),
            ..Default::default()
        })),
        ..Default::default()
    };
    let r = roundtrip(&c);
    assert_eq!(r.protocol, Protocol::Hysteria2);
    assert_eq!(r.password.as_deref(), Some("hypw"));
    assert_eq!(
        r.tls_settings.as_ref().unwrap().server_name.as_deref(),
        Some("hy.sni.com")
    );
    let obfs = r
        .hysteria2_settings
        .as_ref()
        .and_then(|h| h.obfs.as_ref())
        .expect("salamander obfs 还原");
    assert_eq!(obfs.password.as_deref(), Some("obfspw"));
}

#[test]
fn roundtrip_tuic() {
    let c = ServerConfig {
        name: "tuic".into(),
        protocol: Protocol::Tuic,
        address: "tuic.example.com".into(),
        port: 443,
        uuid: Some(U.into()),
        password: Some("tpw".into()),
        tuic_settings: Some(TuicSettings {
            congestion_control: Some("bbr".into()),
            ..Default::default()
        }),
        tls_settings: Some(TlsSettings {
            server_name: Some("tuic.sni.com".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let r = roundtrip(&c);
    assert_eq!(r.protocol, Protocol::Tuic);
    assert_eq!(r.uuid.as_deref(), Some(U));
    assert_eq!(r.password.as_deref(), Some("tpw"));
    assert_eq!(
        r.tuic_settings
            .as_ref()
            .and_then(|t| t.congestion_control.as_deref()),
        Some("bbr")
    );
    assert_eq!(
        r.tls_settings.as_ref().unwrap().server_name.as_deref(),
        Some("tuic.sni.com")
    );
}

#[test]
fn roundtrip_anytls() {
    let c = ServerConfig {
        name: "at".into(),
        protocol: Protocol::Anytls,
        address: "at.example.com".into(),
        port: 8443,
        password: Some("atpw".into()),
        security: Some(SecurityMode::Tls),
        tls_settings: Some(TlsSettings {
            server_name: Some("at.sni.com".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let r = roundtrip(&c);
    assert_eq!(r.protocol, Protocol::Anytls);
    assert_eq!(r.password.as_deref(), Some("atpw"));
    assert_eq!(r.port, 8443);
}

#[test]
fn roundtrip_snell() {
    let c = ServerConfig {
        name: "sn".into(),
        protocol: Protocol::Snell,
        address: "sn.example.com".into(),
        port: 6160,
        password: Some("psk123".into()),
        snell_settings: Some(Box::new(SnellSettings {
            version: 4,
            obfs_mode: Some("http".into()),
            obfs_host: Some("bing.com".into()),
            ..Default::default()
        })),
        ..Default::default()
    };
    let r = roundtrip(&c);
    assert_eq!(r.protocol, Protocol::Snell);
    assert_eq!(r.password.as_deref(), Some("psk123"));
    let sn = r.snell_settings.as_ref().expect("snell 还原");
    assert_eq!(sn.version, 4);
    assert_eq!(sn.obfs_mode.as_deref(), Some("http"));
    assert_eq!(sn.obfs_host.as_deref(), Some("bing.com"));
}

#[test]
fn roundtrip_socks() {
    let c = ServerConfig {
        name: "s5".into(),
        protocol: Protocol::Socks,
        address: "s.example.com".into(),
        port: 1080,
        username: Some("user".into()),
        password: Some("p@ss".into()),
        ..Default::default()
    };
    let r = roundtrip(&c);
    assert_eq!(r.protocol, Protocol::Socks);
    assert_eq!(r.username.as_deref(), Some("user"));
    assert_eq!(r.password.as_deref(), Some("p@ss"));
    assert_eq!(r.port, 1080);
}

#[test]
fn roundtrip_http_and_https() {
    let http = ServerConfig {
        name: "h".into(),
        protocol: Protocol::Http,
        address: "h.example.com".into(),
        port: 8080,
        username: Some("u".into()),
        password: Some("pw".into()),
        security: Some(SecurityMode::None),
        ..Default::default()
    };
    let r = roundtrip(&http);
    assert_eq!(r.protocol, Protocol::Http);
    assert_eq!(r.address, "h.example.com");
    assert_eq!(r.port, 8080);
    assert_eq!(r.username.as_deref(), Some("u"));
    assert_eq!(r.password.as_deref(), Some("pw"));
    assert_eq!(r.security, Some(SecurityMode::None));

    let https = ServerConfig {
        protocol: Protocol::Http,
        security: Some(SecurityMode::Tls),
        port: 8443,
        ..http
    };
    let r2 = roundtrip(&https);
    assert_eq!(r2.security, Some(SecurityMode::Tls), "https 走 TLS");
    assert_eq!(r2.port, 8443);
}

#[test]
fn roundtrip_naive() {
    let c = ServerConfig {
        name: "nv".into(),
        protocol: Protocol::Naive,
        address: "nv.example.com".into(),
        port: 443,
        username: Some("nuser".into()),
        password: Some("npass".into()),
        ..Default::default()
    };
    let r = roundtrip(&c);
    assert_eq!(r.protocol, Protocol::Naive);
    assert_eq!(r.username.as_deref(), Some("nuser"));
    assert_eq!(r.password.as_deref(), Some("npass"));
    assert_eq!(r.address, "nv.example.com");
}

#[test]
fn roundtrip_ipv6_host_gets_brackets() {
    let c = ServerConfig {
        name: "v6".into(),
        protocol: Protocol::Vless,
        address: "2001:db8::1".into(),
        port: 443,
        uuid: Some(U.into()),
        encryption: Some("none".into()),
        ..Default::default()
    };
    let url = encode_share_url(&c).expect("encode");
    assert!(url.contains("[2001:db8::1]"), "裸 IPv6 须加方括号: {url}");
    let r = roundtrip(&c);
    assert_eq!(r.address, "2001:db8::1", "IPv6 地址须去括号还原");
}

#[test]
fn encode_rejects_unrepresentable_protocols() {
    for p in [
        Protocol::Wireguard,
        Protocol::Tailscale,
        Protocol::Ssh,
        Protocol::Custom,
    ] {
        let c = ServerConfig {
            name: "x".into(),
            protocol: p,
            address: "a".into(),
            port: 1,
            ..Default::default()
        };
        assert!(
            encode_share_url(&c).is_err(),
            "{p:?} 无标准分享链接形态，须诚实 Err（不编造假链）"
        );
    }
}

// ── issue #1「不支持HTTP协议么?」：HTTP 代理导入缺口的回归门 ─────────────────────
//
// 端到端确认报告：`~/docs/polaris/fixes/polaris-http-proxy-import-audit-2026-09-02.md`。
// 报告列出的六处实测缺口里，四处落在本模块（另两处分别在 `xray_import` 与 `subscription`）。
// 这四条断言全部锁「用户可见的事故形态」：静默丢节点 / 静默改协议 / 能导入但必 407。

/// 缺口①：scheme 大小写敏感 ⇒ `HTTP://` / `Http://` 被**零告警静默跳过**。
///
/// RFC 3986 §3.1 明写 scheme 大小写不敏感。事故形态是双重的：`is_supported_share_url` 判假 →
/// `parse_url_list` 直接 `continue`（既不 `failed += 1` 也不 push warning），用户只看到
/// 「导入 N 个」，看不到丢了几行、丢的是什么。
///
/// **两处判据都要过门**：白名单前缀匹配（`is_supported_share_url`）与 scheme 分派
/// （`parse_share_url_inner` 的 `match scheme`）。只改一处 = 只修一半——只改白名单会让链接通过
/// 闸门后落到 `不支持的协议` 分支（从静默丢变成计 failed，仍导不进来）。
#[test]
fn uppercase_scheme_is_case_insensitive_per_rfc3986() {
    // 第一处：白名单前缀匹配。
    for url in [
        "HTTP://a.example.com:8080",
        "Http://a.example.com:8080",
        "HTTPS://a.example.com",
        "VLESS://x.example.com",
        "Socks5://a.example.com:1080",
    ] {
        assert!(
            is_supported_share_url(url),
            "{url} 的 scheme 应大小写不敏感"
        );
    }
    // 第二处：scheme 分派。只改白名单则此处转红。
    let c = parse_ok("HTTP://alice:secret@1.2.3.4:8080#%E5%A4%A7%E5%86%99");
    assert_eq!((c.protocol, c.port), (Protocol::Http, 8080));
    assert_eq!(c.username.as_deref(), Some("alice"));
    assert_eq!(c.password.as_deref(), Some("secret"));
    let c = parse_ok("HttpS://bob:pw@h.example.com#n");
    assert_eq!(
        (c.protocol, c.port, c.security.clone()),
        (Protocol::Http, 443, Some(SecurityMode::Tls))
    );
    // 大小写不敏感 ≠ 放宽白名单：不在册的 scheme 仍须拒。
    assert!(parse_err("FTP://x.example.com").contains("不支持的协议"));
    assert!(!is_supported_share_url("FTP://x.example.com"));
}

/// 缺口②：`https://…#<名称含 naive>` 被改写成 Naive 协议。
///
/// 该分支**是有意设计不是 bug**：naive 与 HTTPS 代理共用同一条 URL 文法
/// （`https://user:pass@host:port`），`#naive` 是部分客户端唯一的类型判别标记（上游 oracle
/// `src/main/services/ProtocolParser.ts:124-131` 同款）。故**收窄而非删除**：判据由
/// 「fragment **含** `naive` 子串」收紧为「fragment **整体恰为** `naive` 标记」（trim + ASCII
/// 大小写不敏感）。理由是标记与名字的语义区别——客户端发的是类型标记（fragment 的**全部**），
/// 机场发的是节点名（`naive` 只是其中一个词）。
///
/// 误判代价不对称，也支持收窄：被误判成 naive 的 HTTP 节点在无 cronet 的平台上会被生成期
/// `is_node_usable` 连同测速一起剔除，节点凭空消失且不留 http 的痕迹。
#[test]
fn https_naive_marker_requires_whole_fragment() {
    // 兼容面保住：标记形态（含大小写变体）仍走 naive。
    for url in [
        "https://u:p@h.example.com:443#naive",
        "https://u:p@h.example.com:443#NAIVE",
        "https://u:p@h.example.com:443#Naive",
    ] {
        assert_eq!(
            parse_ok(url).protocol,
            Protocol::Naive,
            "{url} 是 naive 类型标记形态，须保留兼容"
        );
    }
    // 误判面消除：naive 只是节点名的一部分 → 仍是 HTTPS 代理。
    for url in [
        "https://u:p@h.example.com:443#naive%E8%8A%82%E7%82%B9", // #naive节点
        "https://u:p@h.example.com:443#NAIVE-HK",
        "https://u:p@h.example.com:443#my-naive-proxy",
        "https://u:p@h.example.com:443#%E9%A6%99%E6%B8%AFnaive01", // #香港naive01
    ] {
        let c = parse_ok(url);
        assert_eq!(
            c.protocol,
            Protocol::Http,
            "{url} 的 naive 只是名字的一部分，不是类型标记"
        );
        assert_eq!(c.security, Some(SecurityMode::Tls), "{url} 仍是 HTTPS 代理");
    }
}

/// 缺口③：`http2://` 被判成 naive —— 判定为**正确，保留**。依据两条，都是源码级可复核的：
///
/// ① **本仓自证**：本模块的编码器 `encode_naive` 就以 `http2` 作 naive 的 scheme
///    （`share_link.rs` 内 `assemble("http2", …)`）。改判 `http2://` 会让 Polaris 自己产出的
///    分享链接解不回来——本测试的往返断言即是那条自证。
/// ② **上游 oracle**：`src/main/services/ProtocolParser.ts:124`「naive 是 http2 或者
///    naive+https 的内部别名」，`:695`「格式: http2://username:password@address:port#name」，
///    `:1260`「NaiveUrl scheme is http2://」。
///
/// 生态侧无竞争约定：`http2` 不是注册 URI scheme，也不存在「HTTP/2 代理」的分享链接形态需要
/// 这个前缀，故保留不会挡住任何真实的 HTTP 代理节点。
#[test]
fn http2_scheme_stays_naive_and_survives_roundtrip() {
    assert_eq!(
        parse_ok("http2://u:p@h.example.com:443#n").protocol,
        Protocol::Naive
    );
    let c = ServerConfig {
        name: "nv".into(),
        protocol: Protocol::Naive,
        address: "nv.example.com".into(),
        port: 443,
        username: Some("nuser".into()),
        password: Some("npass".into()),
        ..Default::default()
    };
    let url = encode_share_url(&c).expect("naive 节点应可编码");
    assert!(
        url.starts_with("http2://"),
        "编码器以 http2 为 naive 的 scheme，实得 {url}"
    );
    assert_eq!(
        parse_ok(&url).protocol,
        Protocol::Naive,
        "改判 http2 即自断编解码往返"
    );
}

/// 缺口④：userinfo 里被百分号编码的冒号（`%3A`）导致用户名/密码切错。
///
/// 事故形态最阴：节点能导入、列表里看得见，但凭据是错的 ⇒ 代理必回 407，用户只看到「连不上 /
/// 测速失败」，不会怀疑解析。根因是**顺序**——先把 `user:pass` 拼回整串 percent-decode、再按
/// `:` 切分：解码把 `%3A` 还原成真冒号后，切分点被挪进了用户名内部。
///
/// 正确顺序是**先按 URL 文法切分、再逐段解码**：WHATWG 在 userinfo 的第一个**未编码** `:`
/// 处切分，`url` crate 的 `username()` / `password()` 已经给出那个切点，逐段过既有的
/// `decode_uri_component` 即可。
#[test]
fn userinfo_encoded_colon_splits_before_decoding() {
    // 用户名里含编码冒号：切点必须仍在那个未编码的 `:` 上。
    let c = parse_ok("http://u%40s%3Ae%2Fr:p%25ss@1.2.3.4:8080#n");
    assert_eq!(c.username.as_deref(), Some("u@s:e/r"));
    assert_eq!(c.password.as_deref(), Some("p%ss"));
    // 密码里含编码冒号。
    let c = parse_ok("http://user:pa%3Ass@1.2.3.4:8080#n");
    assert_eq!(
        (c.username.as_deref(), c.password.as_deref()),
        (Some("user"), Some("pa:ss"))
    );
    // 既有语义不得回退：未编码的第二个及以后的 `:` 仍整段归 password。
    let c = parse_ok("http://user:p:a:ss@1.2.3.4:8080#n");
    assert_eq!(
        (c.username.as_deref(), c.password.as_deref()),
        (Some("user"), Some("p:a:ss"))
    );
    // 末个 `@` 才是分隔符（既有行为，回归保护）。
    assert_eq!(
        parse_ok("http://user:p@ss@1.2.3.4:8080#n")
            .password
            .as_deref(),
        Some("p@ss")
    );
    // socks 与 http 共用同一处拆分，同门覆盖。
    let c = parse_ok("socks5://u%3Ax:pw@1.2.3.4:1080#n");
    assert_eq!(
        (c.username.as_deref(), c.password.as_deref()),
        (Some("u:x"), Some("pw"))
    );
    // 无凭据 / 仅用户名两形态不受影响。
    let c = parse_ok("http://1.2.3.4:8080#n");
    assert_eq!((c.username.as_deref(), c.password.as_deref()), (None, None));
    let c = parse_ok("http://tokenonly@1.2.3.4:8080#n");
    assert_eq!(
        (c.username.as_deref(), c.password.as_deref()),
        (Some("tokenonly"), None)
    );
}

/// 缺口①的收紧面（review 指出、本次改动**自己引入**的退化）：url-list 嗅探改成全文扫描后，
/// 非订阅正文里只要夹一行独立 URL 就判 `UrlList`，那行会被当成 HTTPS 代理节点静默导入 ——
/// 用户拿到一个连不通的假节点，且 servers=1 / failed=0 / warnings=[]，比原来的
/// 「暂不支持的订阅格式」还难排查。
///
/// **判据**：`http` / `https` 链接若**有路径**（`/` 之外）、**无名称**（无非空 fragment）、
/// **无凭据**（无 userinfo），判为订阅/网页 URL 而非节点，整条拒绝（计 failed + 告警）。
///
/// 三条腿各自的理由：
/// - **有路径**：HTTP CONNECT 代理的地址就是 `host:port`，路径对它无意义 —— 本模块的
///   `parse_http` 从头到尾**没读过** `u.path()`，带路径的链接与不带路径的产出完全相同。
///   而订阅链接的路径正是它的全部信息（`/link/abc`）。
/// - **无名称**：机场下发的节点必带 `#名称`（列表要显示），订阅链接不带。
/// - **无凭据**：代理节点要么带 `user:pass@`，要么是匿名代理（此时也没有路径）。
///
/// 判据只作用于 `http` / `https` —— 它们是白名单里**仅有的两个**会与普通网页 URL 撞形的 scheme。
/// 其余 scheme 不套用：`vmess://` / `ss://` 的 base64 体含 `/` 时会被 URL 引擎解成「路径」
/// （实测 `ss://YWVzOnB3/QDEuMi4z…` → `path="/QDEuMi4z…"`），套上去会误杀一船节点。
#[test]
fn http_link_with_path_but_no_name_and_no_credentials_is_rejected() {
    // 订阅链接 / 网页 URL 形态：拒绝，且错误里点明原因。
    for url in [
        "https://sub.example.com/renew",
        "https://vip.example.com/link/abc?sub=1",
        "http://portal.example.com:8080/notice",
    ] {
        let e = parse_err(url);
        assert!(
            e.contains("疑似订阅链接"),
            "{url} 应被判为订阅链接而非节点，实得: {e}"
        );
    }
}

/// 收紧不得误伤 issue #1 本身的形态 —— 这是本次修复的目的，堵洞不能把它堵回去。
#[test]
fn narrowing_does_not_reject_any_real_http_node_shape() {
    // ① 带凭据带名称。
    assert_eq!(
        parse_ok("http://user:pass@1.2.3.4:8080#name").protocol,
        Protocol::Http
    );
    // ② 无凭据带名称。
    assert_eq!(
        parse_ok("https://1.2.3.4:8443#name").protocol,
        Protocol::Http
    );
    // ③ 无凭据无名称（判据里「无路径」这条腿唯一的支撑面）。
    let c = parse_ok("http://1.2.3.4:8080");
    assert_eq!((c.protocol, c.port), (Protocol::Http, 8080));
    assert_eq!(
        c.name, "1.2.3.4:8080",
        "无 fragment → 名称回落 address:port"
    );
    // ③' 无端口 / 尾斜杠 / IPv6 / 查询参数四个变体同样不得误杀。
    assert_eq!(parse_ok("http://1.2.3.4").port, 80);
    assert_eq!(parse_ok("http://1.2.3.4:8080/").port, 8080);
    assert_eq!(parse_ok("http://[2001:db8::1]:8080").address, "2001:db8::1");
    assert_eq!(
        parse_ok("https://h.example.com?sni=a.example.com").port,
        443
    );
    // ④ 有路径但**带名称** → 仍是节点（名称即用户意图，路径只是被忽略的冗余）。
    assert_eq!(
        parse_ok("http://1.2.3.4:8080/x#named").protocol,
        Protocol::Http
    );
    // ⑤ 有路径但**带凭据** → 仍是节点。
    assert_eq!(
        parse_ok("http://u:p@1.2.3.4:8080/x").protocol,
        Protocol::Http
    );
    // ⑥ 判据只管 http/https：其余 scheme 的「路径」可能是 base64 体的一部分，不得套用。
    assert_eq!(parse_ok("socks5://1.2.3.4:1080").protocol, Protocol::Socks);
}

/// `#naive` 标记判据的**真实**空白行为（死码清理的配套钉子）。
///
/// 原判据写成 `u.fragment().unwrap_or("").trim()`，读起来像覆盖了空格变体，实则 `.trim()`
/// **对任何输入都是死码**：WHATWG 在 URL 解析期就把 fragment 里的空白处理干净了 —— 实测
/// `#naive ` → `Some("naive")`（尾部空白在解析前整串剥掉）、`# naive ` → `Some("%20naive")`、
/// `#naive%20` → `Some("naive%20")`、U+00A0 / U+3000 → `%C2%A0` / `%E3%80%80`（>U+007E 一律
/// 百分号编码）。**没有任何输入能让 `u.fragment()` 带上首尾空白**，故 `.trim()` 已删除。
/// 本用例把上面这些形态的真实归属钉死，免得后来人再按注释的字面意思去理解。
#[test]
fn naive_marker_whitespace_behaviour_is_pinned() {
    // 尾部裸空格：URL 解析期整串剥掉 ⇒ 仍是标记形态。
    assert_eq!(
        parse_ok("https://u:p@h.example.com:443#naive ").protocol,
        Protocol::Naive
    );
    // 编码空白进了 fragment ⇒ 不再是「整体恰为 naive」⇒ 普通 HTTPS 代理。
    for url in [
        "https://u:p@h.example.com:443#naive%20",
        "https://u:p@h.example.com:443# naive",
        "https://u:p@h.example.com:443#\u{00a0}naive",
        "https://u:p@h.example.com:443#naive\u{3000}",
    ] {
        assert_eq!(
            parse_ok(url).protocol,
            Protocol::Http,
            "{url} 的 fragment 带编码空白，不是纯标记"
        );
    }
}
