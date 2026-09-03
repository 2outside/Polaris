use super::*;
use crate::user_config::protocol_settings as ps;

fn server(protocol: Protocol, addr: &str) -> ServerConfig {
    ServerConfig {
        id: "s1".into(),
        name: "test".into(),
        protocol,
        address: addr.into(),
        port: 443,
        ..Default::default()
    }
}

// ── custom 逃生舱：真透传（P0 回归锁）────────────────────────────────────────────
//
// 修复前这里是 `serde_json::from_value::<Outbound>(val)` —— 一个约 70 个具名字段的强类型
// struct，无 flatten 兜底。注释写「原样下发」，实现是「只下发建模过的字段」。下面四组是
// **真跑测出来的**四档形态（随包 sing-box 1.14.0-beta.7 逐条 `check` 过），不是推演。

/// 造一个 custom 节点（raw JSON 逐字进 `customSettings.outbound`）。
fn custom_server(raw: serde_json::Value) -> ServerConfig {
    let mut s = server(Protocol::Custom, "unused.example");
    s.custom_settings = Some(ps::CustomSettings {
        outbound: raw,
        is_endpoint: None,
        secret_keys: None,
    });
    s
}

fn custom_outbound_json(raw: serde_json::Value) -> serde_json::Value {
    let ob = build_proxy_outbound(
        &custom_server(raw),
        "proxy-c1",
        &test_dial_resolver(),
        "x64",
        "linux",
    );
    serde_json::to_value(&ob).unwrap()
}

/// 🔴 **变异锁：custom = 逐键真透传**。四组场景 = 修复前四种不同的坏法。
///
/// 断言方式是「输出 == 输入 + tag 覆盖」的**整对象相等**，不是逐键点名：后者对「多吃掉一个
/// 没被点名的键」不转红，而静默丢字段正是本缺陷的形态。把实现改回 `from_value::<Outbound>`
/// ⇒ 第 2 组（整份解析失败 → `{"type":"custom"}`）、第 3/4 组（静默丢字段）立刻转红。
#[test]
fn custom_outbound_is_verbatim_passthrough() {
    for (name, raw) in [
        // ① 字段恰好都在 `Outbound` 里 —— 修复前也过，是本组的**阴性对照**：
        //    没有它，「四组全绿」可能只是因为透传把什么都不做当成了成功。
        (
            "shadowtls（全字段已建模）",
            serde_json::json!({"type":"shadowtls","server":"s.example.com","server_port":443,
                "version":3,"password":"pw","tls":{"enabled":true,"server_name":"sni.example"}}),
        ),
        // ② 建模过但**类型不同**：hysteria v1 的 `obfs` 按真实 schema 是**字符串**，本 struct 是
        //    `Option<Hysteria2Obfs>` 对象 ⇒ 修复前**整个反序列化失败**，回落成
        //    `{"type":"custom","tag":…}`，而 `sing-box check` 对它判 `unknown outbound type:
        //    custom`（rc=1）——一个坏节点炸掉整份配置。
        (
            "hysteria v1（obfs 是字符串）",
            serde_json::json!({"type":"hysteria","server":"h1.example.com","server_port":443,
                "up_mbps":100,"down_mbps":500,"obfs":"salamander-secret","auth_str":"mypass",
                "tls":{"enabled":true,"server_name":"h1.example.com"}}),
        ),
        // ③ 没建模：hysteria v1 的 `auth_str` ⇒ 修复前解析成功但该键**静默丢失**（= 无凭证，
        //    连不上，可配置「看起来是好的」）。
        (
            "hysteria v1（auth_str）",
            serde_json::json!({"type":"hysteria","server":"h1.example.com","server_port":443,
                "auth_str":"mypass"}),
        ),
        // ④ 没建模：tor 的四个键 ⇒ 修复前全丢，只剩 `{"type":"tor","tag":…}`。
        (
            "tor（executable_path 等四键）",
            serde_json::json!({"type":"tor","executable_path":"/usr/bin/tor",
                "data_directory":"/tmp/tordata","extra_args":["--HTTPTunnelPort","0"],
                "torrc":{"UseBridges":"1"}}),
        ),
    ] {
        let mut expected = raw.clone();
        expected["tag"] = serde_json::json!("proxy-c1");
        assert_eq!(
            custom_outbound_json(raw),
            expected,
            "{name}：custom 必须逐键原样下发（多一键少一键都是把逃生舱改回白名单）"
        );
    }
}

/// 唯二的两处改写：`tag` 强制覆盖、内层 `detour` 剥离 —— 两条都是既有的、有理由的
/// （tag 是 Polaris 的拓扑真值；内层 detour 会绕过本仓的 detour 死引用/成环检测）。
#[test]
fn custom_outbound_overrides_tag_and_strips_inner_detour() {
    let v = custom_outbound_json(serde_json::json!({
        "type":"socks","tag":"用户自己写的tag","detour":"某个内层出站","server":"s.example.com"
    }));
    assert_eq!(v["tag"], serde_json::json!("proxy-c1"));
    assert!(v.get("detour").is_none(), "内层 detour 必须剥掉：{v}");
    assert_eq!(v["server"], serde_json::json!("s.example.com"));
}

/// 形状非法（非对象 / 无 string `type`）⇒ 保留 `{"type":"custom"}` **毒丸**。
///
/// 这不是「兜底成一个能用的 outbound」：随包 sing-box 对 `custom` 判 `unknown outbound type`
/// 立刻拒。主生成路径根本到不了这里（`builder/outbounds.rs` 用同一条判据先把节点剔除并上报），
/// 到得了的是 `runtime/speedtest.rs` 的临时测速核 —— 那里「测速失败」正是如实的结论。
#[test]
fn custom_malformed_shape_stays_a_poison_pill() {
    for raw in [
        serde_json::json!([1, 2, 3]),
        serde_json::json!("hysteria"),
        serde_json::json!({"server": "no-type.example"}),
        serde_json::json!({"type": 4}),
    ] {
        let v = custom_outbound_json(raw.clone());
        assert_eq!(
            v,
            serde_json::json!({"type":"custom","tag":"proxy-c1"}),
            "形状非法的 custom 不得被编成一个像样的 outbound：{raw}"
        );
    }
}

/// 本模块各测试断言的是**协议字段映射**，与 dial 解析器形态无关；取生产默认分支
/// （enableIPv6 关 → 结构化）即可，形态本身的门在 `builder/outbounds.rs` 的 #335 三连测里。
fn test_dial_resolver() -> DomainResolver {
    crate::builder::helpers::get_node_dial_domain_resolver("dns-bootstrap", false)
}

#[test]
fn vless_basic() {
    let mut s = server(Protocol::Vless, "a.com");
    s.uuid = Some("uuid-1".into());
    s.security = Some(SecurityMode::Tls); // vless 需显式 security=tls 才生成 TLS 块
    let ob = build_proxy_outbound(&s, "proxy-s1", &test_dial_resolver(), "x64", "linux");
    assert_eq!(ob.type_field, "vless");
    assert_eq!(ob.uuid.as_deref(), Some("uuid-1"));
    assert_eq!(ob.packet_encoding.as_deref(), Some("xudp")); // 默认 xudp
    assert_eq!(ob.server.as_deref(), Some("a.com"));
    // vless security=tls 默认 chrome utls。
    assert!(ob.tls.is_some());
    assert_eq!(
        ob.tls.as_ref().unwrap().utls.as_ref().unwrap().fingerprint,
        "chrome"
    );
}

#[test]
fn trojan_default_alpn() {
    let mut s = server(Protocol::Trojan, "t.com");
    s.password = Some("pw".into());
    let ob = build_proxy_outbound(&s, "proxy-s1", &test_dial_resolver(), "x64", "linux");
    assert_eq!(
        ob.tls.as_ref().unwrap().alpn.as_ref().unwrap(),
        &vec!["http/1.1".to_string()]
    );
}

#[test]
fn shadowsocks_method_password() {
    let mut s = server(Protocol::Shadowsocks, "ss.com");
    s.shadowsocks_settings = Some(Box::new(ps::ShadowsocksSettings {
        method: "aes-256-gcm".into(),
        password: "secret".into(),
        ..Default::default()
    }));
    let ob = build_proxy_outbound(&s, "proxy-s1", &test_dial_resolver(), "x64", "linux");
    assert_eq!(ob.method.as_deref(), Some("aes-256-gcm"));
    assert_eq!(ob.password.as_deref(), Some("secret"));
}

#[test]
fn hysteria2_obfs_gecko() {
    let mut s = server(Protocol::Hysteria2, "h.com");
    s.password = Some("pw".into());
    s.hysteria2_settings = Some(Box::new(ps::Hysteria2Settings {
        obfs: Some(ps::Hysteria2ObfsSettings {
            type_field: Some("gecko".into()),
            password: Some("obfspw".into()),
            min_packet_size: Some(100),
            max_packet_size: Some(200),
        }),
        ..Default::default()
    }));
    let ob = build_proxy_outbound(&s, "proxy-s1", &test_dial_resolver(), "x64", "linux");
    let obfs = ob.obfs.as_ref().unwrap();
    let crate::singbox::outbound::ObfsField::Object(obfs) = obfs else {
        panic!("hysteria2 的 obfs 必须是对象形态（v1 才是裸字符串）");
    };
    assert_eq!(obfs.type_field, "gecko");
    assert_eq!(obfs.min_packet_size, Some(100));
}

/// 默认（用户没碰这个开关）⇒ 生成的 hysteria2 outbound **不含** `disable_chrome_parrot` 键。
/// 核心默认值就是 `false`，下发它等于给每份存量配置凭空加一个键（金样字节漂移），语义却没变。
#[test]
fn hysteria2_no_chrome_parrot_key_by_default() {
    let mut s = server(Protocol::Hysteria2, "h.com");
    s.password = Some("pw".into());
    s.hysteria2_settings = Some(Box::new(ps::Hysteria2Settings::default()));
    let ob = build_proxy_outbound(&s, "proxy-s1", &test_dial_resolver(), "x64", "linux");
    assert_eq!(ob.disable_chrome_parrot, None);
    let json = serde_json::to_value(&ob).unwrap();
    assert!(json.get("disable_chrome_parrot").is_none());
    // 显式关（Some(false)）与没填一样不下发——`false` 与省略在核心侧等价。
    s.hysteria2_settings = Some(Box::new(ps::Hysteria2Settings {
        disable_chrome_parrot: Some(false),
        ..Default::default()
    }));
    let ob = build_proxy_outbound(&s, "proxy-s1", &test_dial_resolver(), "x64", "linux");
    assert!(serde_json::to_value(&ob)
        .unwrap()
        .get("disable_chrome_parrot")
        .is_none());
}

/// 🟡 **变异锁：`up_mbps`/`down_mbps` 的 `0` 不下发，非零值原样下发。**
///
/// 两条断言方向相反，缺一不可：
/// - 只断言「0 不下发」→ 把整个赋值删掉也绿（那会静默丢掉用户真填的带宽）；
/// - 只断言「非零下发」→ 退回 `= h.up_mbps` 也绿（那正是本次要改掉的形态）。
///
/// 断言落在**序列化后的 JSON 键集**而非 `Option` 字段：`skip_serializing_if` 若被删，
/// 结构体断言照绿而 JSON 里会多出 `"up_mbps": null`。
#[test]
fn hysteria2_zero_bandwidth_is_omitted_but_nonzero_is_kept() {
    let mut s = server(Protocol::Hysteria2, "h.com");
    s.password = Some("pw".into());

    // 0 ≡ 不设（内核 `actualTx > 0` 才走 Brutal，否则 BBR）⇒ 整键不出现。
    s.hysteria2_settings = Some(Box::new(ps::Hysteria2Settings {
        up_mbps: Some(0),
        down_mbps: Some(0),
        ..Default::default()
    }));
    let ob = build_proxy_outbound(&s, "proxy-s1", &test_dial_resolver(), "x64", "linux");
    let json = serde_json::to_value(&ob).unwrap();
    assert!(json.get("up_mbps").is_none(), "0 不该下发：{json}");
    assert!(json.get("down_mbps").is_none(), "0 不该下发：{json}");

    // 非零是用户/订阅的真实意图（遵循订阅下发，2026-08-06 定），必须原样带上。
    s.hysteria2_settings = Some(Box::new(ps::Hysteria2Settings {
        up_mbps: Some(100),
        down_mbps: Some(500),
        ..Default::default()
    }));
    let ob = build_proxy_outbound(&s, "proxy-s1", &test_dial_resolver(), "x64", "linux");
    let json = serde_json::to_value(&ob).unwrap();
    assert_eq!(json["up_mbps"], 100);
    assert_eq!(json["down_mbps"], 500);
}

/// 显式开启 ⇒ 下发 `"disable_chrome_parrot": true`（服务端 Ed25519 证书握手失败时的逃生舱）。
#[test]
fn hysteria2_chrome_parrot_disabled_when_opted_in() {
    let mut s = server(Protocol::Hysteria2, "h.com");
    s.password = Some("pw".into());
    s.hysteria2_settings = Some(Box::new(ps::Hysteria2Settings {
        disable_chrome_parrot: Some(true),
        ..Default::default()
    }));
    let ob = build_proxy_outbound(&s, "proxy-s1", &test_dial_resolver(), "x64", "linux");
    assert_eq!(ob.disable_chrome_parrot, Some(true));
    assert_eq!(
        serde_json::to_value(&ob).unwrap()["disable_chrome_parrot"],
        serde_json::json!(true)
    );
}

#[test]
fn naive_only_server_name_tls() {
    let mut s = server(Protocol::Naive, "n.com");
    s.username = Some("u".into());
    s.password = Some("p".into());
    let ob = build_proxy_outbound(&s, "proxy-s1", &test_dial_resolver(), "x64", "linux");
    // naive TLS 仅 server_name，无 alpn/insecure。
    let tls = ob.tls.as_ref().unwrap();
    assert!(tls.alpn.is_none());
    assert!(tls.insecure.is_none());
}

#[test]
fn ssh_no_tls() {
    let mut s = server(Protocol::Ssh, "ssh.com");
    s.ssh_settings = Some(Box::new(ps::SshSettings {
        user: Some("root".into()),
        ..Default::default()
    }));
    let ob = build_proxy_outbound(&s, "proxy-s1", &test_dial_resolver(), "x64", "linux");
    assert!(ob.tls.is_none());
    assert_eq!(ob.user.as_deref(), Some("root"));
}

// ── 静默 TLS/Reality 降级回归（安全）────────────────────────────────────
//
// 锁死的事故形态：`security` 大小写变体 → 分支不命中 → TLS 不启用且无报错
// → 用户以为加密，实际明文出站。断言落在**生成的 sing-box JSON** 上，
// 而非归一函数本身：光测归一函数不能证明 config 真的启用了 TLS。

/// 从 JSON 反序列化建节点 → 走完整生成链 → 返回 sing-box outbound JSON。
/// 必须经 serde 入口，才覆盖「存量/订阅脏数据进来」的真实路径。
fn outbound_json_from(server_json: &str) -> serde_json::Value {
    let s: ServerConfig = serde_json::from_str(server_json).expect("节点必须能反序列化");
    let ob = build_proxy_outbound(&s, "proxy-s1", &test_dial_resolver(), "x64", "linux");
    serde_json::to_value(&ob).unwrap()
}

#[test]
fn uppercase_tls_still_enables_tls_in_generated_json() {
    // 端到端核心断言：大写 "TLS" → 生成的 JSON 里 TLS 必须真启用。
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"vless","address":"a.com","port":443,
                "uuid":"u-1","security":"TLS"}"#,
    );
    assert_eq!(
        v["tls"]["enabled"],
        serde_json::json!(true),
        "大写 TLS 必须启用 TLS —— 否则即为明文出站事故"
    );
    assert_eq!(v["tls"]["server_name"], serde_json::json!("a.com"));
}

#[test]
fn tls_case_variants_produce_identical_outbound_json() {
    // 全大小写变体 → 生成结果逐字节一致（含 utls 指纹等一切下游影响）。
    let baseline = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"vless","address":"a.com","port":443,
                "uuid":"u-1","security":"tls"}"#,
    );
    for raw in ["TLS", "Tls", "tLs", " tls "] {
        let v = outbound_json_from(&format!(
            r#"{{"id":"s1","name":"n","protocol":"vless","address":"a.com","port":443,
                    "uuid":"u-1","security":"{raw}"}}"#
        ));
        assert_eq!(v, baseline, "security={raw:?} 必须与小写 tls 生成完全一致");
    }
}

#[test]
fn uppercase_reality_still_enables_reality_in_generated_json() {
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"vless","address":"a.com","port":443,
                "uuid":"u-1","security":"REALITY",
                "realitySettings":{"publicKey":"pk-abc","shortId":"01ab"}}"#,
    );
    assert_eq!(v["tls"]["enabled"], serde_json::json!(true));
    assert_eq!(
        v["tls"]["reality"]["enabled"],
        serde_json::json!(true),
        "大写 REALITY 必须启用 Reality —— 否则 Reality 静默失效"
    );
    assert_eq!(
        v["tls"]["reality"]["public_key"],
        serde_json::json!("pk-abc")
    );
    assert_eq!(v["tls"]["reality"]["short_id"], serde_json::json!("01ab"));
}

#[test]
fn reality_case_variants_produce_identical_outbound_json() {
    let baseline = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"vless","address":"a.com","port":443,
                "uuid":"u-1","security":"reality",
                "realitySettings":{"publicKey":"pk","shortId":"01"}}"#,
    );
    for raw in ["REALITY", "Reality", "ReAlItY", "  reality "] {
        let v = outbound_json_from(&format!(
            r#"{{"id":"s1","name":"n","protocol":"vless","address":"a.com","port":443,
                    "uuid":"u-1","security":"{raw}",
                    "realitySettings":{{"publicKey":"pk","shortId":"01"}}}}"#
        ));
        assert_eq!(v, baseline, "security={raw:?} 必须与小写 reality 生成一致");
    }
}

#[test]
fn unknown_security_does_not_fabricate_tls() {
    // 未知 security（且无 tlsSettings）→ 不凭空造 TLS 块（语义即"未请求 TLS"）。
    // vless 不在 TLS_PROTOCOLS 里，故此处 tls 必须缺席。
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"vless","address":"a.com","port":443,
                "uuid":"u-1","security":"bogus"}"#,
    );
    assert!(v.get("tls").is_none(), "未知 security 不得生成 TLS 块");
}

#[test]
fn security_none_does_not_enable_tls_for_vless() {
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"vless","address":"a.com","port":443,
                "uuid":"u-1","security":"NONE"}"#,
    );
    assert!(v.get("tls").is_none(), "security=none 不得启用 TLS");
}

// ── hy2/tuic 的 tls.server_name / tls.insecure 端到端（UI 补 sni/insecure 控件的后端侧门）──────
//
// 这两个协议在 `TLS_PROTOCOLS` 里 ⇒ 恒有 TLS 块，`allow_insecure` 走的是和 trojan/anytls
// 同一段装配（本文件 `insecure: Some(...allow_insecure.unwrap_or(false))`）。
// 断言落在**序列化后的 JSON** 而不是结构体字段：`OutboundTls::insecure` 带
// `skip_serializing_if = "Option::is_none"`，只断言 `ob.tls.insecure == Some(true)` 的话，
// 哪天这个键被漏出配置也照样绿。

#[test]
fn hysteria2_allow_insecure_true_emits_tls_insecure_true() {
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"hysteria2","address":"h.com","port":443,
                "password":"pw","tlsSettings":{"serverName":"hy2.sni","allowInsecure":true}}"#,
    );
    assert_eq!(v["tls"]["enabled"], serde_json::json!(true));
    assert_eq!(v["tls"]["insecure"], serde_json::json!(true));
    assert_eq!(v["tls"]["server_name"], serde_json::json!("hy2.sni"));
}

#[test]
fn hysteria2_without_tls_settings_emits_insecure_false_and_address_sni() {
    // 未填（UI 开关默认关、SNI 留空）：`insecure` 仍**显式**下发 `false`，`server_name` 回落节点地址。
    // 这不是「不下发」——金样 `fixtures/config-snapshot.json` 的 hy2/tuic 条目逐字节就是这个形状
    // （与 上游 对齐），改成省略键会让金样对拍转红。
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"hysteria2","address":"h.com","port":443,
                "password":"pw"}"#,
    );
    assert_eq!(v["tls"]["insecure"], serde_json::json!(false));
    assert_eq!(v["tls"]["server_name"], serde_json::json!("h.com"));
}

#[test]
fn tuic_allow_insecure_true_emits_tls_insecure_true() {
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"tuic","address":"t.com","port":443,
                "uuid":"u-1","password":"pw",
                "tlsSettings":{"serverName":"tuic.sni","allowInsecure":true}}"#,
    );
    assert_eq!(v["tls"]["enabled"], serde_json::json!(true));
    assert_eq!(v["tls"]["insecure"], serde_json::json!(true));
    assert_eq!(v["tls"]["server_name"], serde_json::json!("tuic.sni"));
}

#[test]
fn tuic_without_tls_settings_emits_insecure_false_and_address_sni() {
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"tuic","address":"t.com","port":443,
                "uuid":"u-1","password":"pw"}"#,
    );
    assert_eq!(v["tls"]["insecure"], serde_json::json!(false));
    assert_eq!(v["tls"]["server_name"], serde_json::json!("t.com"));
}

// ── http 的 tls.server_name / tls.insecure 端到端（UI 补 sni/insecure 控件的后端侧门）─────────
//
// http **不在** `TLS_PROTOCOLS` 里，TLS 由 `security` 决定；一旦 `security='tls'`，走的就是
// 与 trojan/vless 同一段装配。断言同样落在序列化后的 JSON（理由见上一组注释）。

#[test]
fn http_tls_allow_insecure_true_emits_tls_insecure_true() {
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"http","address":"p.com","port":8080,
                "username":"u","password":"pw","security":"tls",
                "tlsSettings":{"serverName":"http.sni","allowInsecure":true}}"#,
    );
    assert_eq!(v["tls"]["enabled"], serde_json::json!(true));
    assert_eq!(v["tls"]["insecure"], serde_json::json!(true));
    assert_eq!(v["tls"]["server_name"], serde_json::json!("http.sni"));
}

#[test]
fn http_tls_without_tls_settings_emits_insecure_false_and_address_sni() {
    // 开了 HTTPS 但两颗控件都没填：`insecure` 仍**显式**下发 `false`（不是省略键），
    // `server_name` 回落节点地址 —— 与 hy2/tuic/trojan 同一段代码，同一形状。
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"http","address":"p.com","port":8080,
                "security":"tls"}"#,
    );
    assert_eq!(v["tls"]["insecure"], serde_json::json!(false));
    assert_eq!(v["tls"]["server_name"], serde_json::json!("p.com"));
}

#[test]
fn http_security_none_does_not_enable_tls() {
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"http","address":"p.com","port":8080,
                "security":"none"}"#,
    );
    assert!(v.get("tls").is_none(), "明文 http 不得生成 TLS 块");
}

/// 前端 HIGH-1 清除门（关 TLS 时整块删 `tlsSettings`）的**后端侧理由**：
/// 装配条件是 `security.is_tls() || tls_settings.is_some()` —— 残留的 phantom `tlsSettings`
/// 会绕过 `security='none'` 把 TLS 打开，用户以为是明文代理，实际握手失败、静默失联。
#[test]
fn http_phantom_tls_settings_enable_tls_despite_security_none() {
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"http","address":"p.com","port":8080,
                "security":"none","tlsSettings":{"serverName":"stale.sni"}}"#,
    );
    assert_eq!(
        v["tls"]["enabled"],
        serde_json::json!(true),
        "残留 tlsSettings 会对明文口误开 TLS —— 故前端关 TLS 时必须整块清除"
    );
    assert_eq!(v["tls"]["server_name"], serde_json::json!("stale.sni"));
}

#[test]
fn tls_protocols_keep_tls_regardless_of_security_case() {
    // trojan 恒需 TLS 块（TLS_PROTOCOLS）——不因 security 变体而丢。
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"trojan","address":"t.com","port":443,
                "password":"pw","security":"TLS"}"#,
    );
    assert_eq!(v["tls"]["enabled"], serde_json::json!(true));
}

// ── R4：指纹 / flow 归一（上游 #298）────────────────────────────────────

#[test]
fn uppercase_fingerprint_normalized_in_generated_json() {
    // 实测：sing-box 对 "Chrome" 报 `unknown uTLS fingerprint` FATAL → 核起不来。
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"vless","address":"a.com","port":443,
                "uuid":"u-1","security":"tls","tlsSettings":{"fingerprint":"Firefox"}}"#,
    );
    assert_eq!(
        v["tls"]["utls"]["fingerprint"],
        serde_json::json!("firefox")
    );
    assert_eq!(v["tls"]["utls"]["enabled"], serde_json::json!(true));
}

#[test]
fn uppercase_fingerprint_none_disables_utls() {
    // "None" 本意是禁用 utls；不归一则反而下发非法指纹 "None" → sing-box FATAL。
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"vless","address":"a.com","port":443,
                "uuid":"u-1","security":"tls","tlsSettings":{"fingerprint":"NONE"}}"#,
    );
    assert!(
        v["tls"].get("utls").is_none(),
        "fingerprint=none（任意大小写）必须禁用 utls，而非下发非法指纹"
    );
}

#[test]
fn reality_fingerprint_normalized_in_generated_json() {
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"vless","address":"a.com","port":443,
                "uuid":"u-1","security":"reality","tlsSettings":{"fingerprint":"SAFARI"},
                "realitySettings":{"publicKey":"pk","shortId":"01"}}"#,
    );
    assert_eq!(v["tls"]["utls"]["fingerprint"], serde_json::json!("safari"));
}

#[test]
fn uppercase_flow_normalized_in_generated_json() {
    // 实测：sing-box 对 "XTLS-RPRX-Vision" 报 `unsupported flow` FATAL。
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"vless","address":"a.com","port":443,
                "uuid":"u-1","security":"tls","flow":"XTLS-RPRX-Vision"}"#,
    );
    assert_eq!(v["flow"], serde_json::json!("xtls-rprx-vision"));
}

#[test]
fn uppercase_flow_still_suppresses_multiplex() {
    // vision flow 必须跳过 mux —— 大小写变体不得让该判定失效。
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"vless","address":"a.com","port":443,
                "uuid":"u-1","security":"tls","flow":"XTLS-RPRX-VISION",
                "multiplexSettings":{"enabled":true}}"#,
    );
    assert!(
        v.get("multiplex").is_none(),
        "vision flow 必须跳过 multiplex"
    );
}

#[test]
fn uppercase_vmess_security_normalized_in_generated_json() {
    // 实测：sing-box 对 "AES-128-GCM" 报 `unsupported security type` FATAL。
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"vmess","address":"v.com","port":443,
                "uuid":"u-1","vmessSecurity":"AES-128-GCM"}"#,
    );
    assert_eq!(v["security"], serde_json::json!("aes-128-gcm"));
}

#[test]
fn uppercase_network_still_generates_transport() {
    // "WS" 不归一 → generate_transport_config 落 `_ => None` → 静默丢传输层。
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"vless","address":"w.com","port":443,
                "uuid":"u-1","security":"tls","network":"WS",
                "wsSettings":{"path":"/ws"}}"#,
    );
    assert_eq!(v["transport"]["type"], serde_json::json!("ws"));
    assert_eq!(v["transport"]["path"], serde_json::json!("/ws"));
}

// ── 传输层 / Reality / 指纹 / ALPN 的**后端侧门**（UI 补 ws·grpc·anytls-reality·fp·alpn 控件那批）──
//
// 这批断言全部落在**序列化后的 JSON**：`Transport` 的每个字段都带
// `skip_serializing_if = "Option::is_none"`，只断言结构体字段的话，哪天某个键被漏出配置也照样绿。

/// 🔴 **「选了就废」的证据**：选了 ws 传输但 `wsSettings` 缺席 ⇒ path 落默认 `/`。
/// 机场节点的 ws path 绝大多数不是 `/` ⇒ 该节点必然连不上。前端补 path/Host 控件的全部理由。
#[test]
fn ws_without_settings_falls_back_to_root_path() {
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"vless","address":"w.com","port":443,
                "uuid":"u-1","security":"tls","network":"ws"}"#,
    );
    assert_eq!(v["transport"]["type"], serde_json::json!("ws"));
    assert_eq!(v["transport"]["path"], serde_json::json!("/"));
    assert!(
        v["transport"].get("headers").is_none(),
        "没填 Host 时不得凭空造 headers"
    );
}

/// ws：`path` 原样下发，`headers` 整份透传（Host 是其中一个键，值为单值形态）。
#[test]
fn ws_path_and_host_header_reach_transport_json() {
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"vless","address":"w.com","port":443,
                "uuid":"u-1","security":"tls","network":"ws",
                "wsSettings":{"path":"/ray","headers":{"Host":"cdn.example.com"}}}"#,
    );
    assert_eq!(v["transport"]["type"], serde_json::json!("ws"));
    assert_eq!(v["transport"]["path"], serde_json::json!("/ray"));
    assert_eq!(
        v["transport"]["headers"]["Host"],
        serde_json::json!("cdn.example.com")
    );
}

/// httpupgrade **与 ws 同读 `wsSettings`**，但形态不同构：Host 落在顶层 `host` 而不是 `headers`，
/// 且缺席时回落 `tlsSettings.serverName`。前端因此可以共用 path/Host 两个控件（同一份 wsSettings），
/// 但 ws 独有的 `?ed=` 早数据解析在这条腿上**不发生** —— 那部分不属于本批。
#[test]
fn httpupgrade_reads_ws_settings_host_into_top_level_host() {
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"trojan","address":"t.com","port":443,
                "password":"pw","network":"httpupgrade",
                "wsSettings":{"path":"/hu","headers":{"Host":"hu.example.com"}}}"#,
    );
    assert_eq!(v["transport"]["type"], serde_json::json!("httpupgrade"));
    assert_eq!(v["transport"]["path"], serde_json::json!("/hu"));
    assert_eq!(v["transport"]["host"], serde_json::json!("hu.example.com"));
    assert!(v["transport"].get("headers").is_none());
}

#[test]
fn httpupgrade_without_host_header_falls_back_to_tls_server_name() {
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"trojan","address":"t.com","port":443,
                "password":"pw","network":"httpupgrade",
                "tlsSettings":{"serverName":"sni.example.com"}}"#,
    );
    assert_eq!(v["transport"]["path"], serde_json::json!("/"));
    assert_eq!(v["transport"]["host"], serde_json::json!("sni.example.com"));
}

/// grpc：`service_name` **恒下发**（`unwrap_or_default()`）⇒ 前端留空与不建 `grpcSettings` 逐字节同结果。
#[test]
fn grpc_service_name_emitted_and_defaults_to_empty_string() {
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"vmess","address":"g.com","port":443,
                "uuid":"u-1","security":"tls","network":"grpc",
                "grpcSettings":{"serviceName":"GunService"}}"#,
    );
    assert_eq!(v["transport"]["type"], serde_json::json!("grpc"));
    assert_eq!(
        v["transport"]["service_name"],
        serde_json::json!("GunService")
    );

    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"vmess","address":"g.com","port":443,
                "uuid":"u-1","security":"tls","network":"grpc"}"#,
    );
    assert_eq!(v["transport"]["service_name"], serde_json::json!(""));
}

/// trojan 的 `httpupgrade` / `http` 传输一直可用（分派只看 `network`，不按协议门控）——
/// 缺的只是前端下拉档位。
#[test]
fn trojan_supports_httpupgrade_and_http_transports() {
    for (net, want) in [("httpupgrade", "httpupgrade"), ("http", "http")] {
        let v = outbound_json_from(&format!(
            r#"{{"id":"s1","name":"n","protocol":"trojan","address":"t.com","port":443,
                    "password":"pw","network":"{net}"}}"#
        ));
        assert_eq!(
            v["transport"]["type"],
            serde_json::json!(want),
            "trojan network={net} 必须生成传输层"
        );
    }
}

/// 🔴 **Reality 不按协议门控**：判据是 `security.is_reality()`，anytls 与 vless 走同一段装配
/// ⇒ anytls 一直支持 reality，缺的只是前端的 sec 选择器与 pbk/sid 控件。
#[test]
fn anytls_reality_is_assembled_like_vless() {
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"anytls","address":"a.com","port":443,
                "password":"pw","security":"reality",
                "tlsSettings":{"serverName":"at.sni","fingerprint":"firefox","allowInsecure":true},
                "realitySettings":{"publicKey":"at-pub","shortId":"cd34"}}"#,
    );
    assert_eq!(v["tls"]["enabled"], serde_json::json!(true));
    assert_eq!(v["tls"]["reality"]["enabled"], serde_json::json!(true));
    assert_eq!(
        v["tls"]["reality"]["public_key"],
        serde_json::json!("at-pub")
    );
    assert_eq!(v["tls"]["reality"]["short_id"], serde_json::json!("cd34"));
    // reality 版 TLS 块仍从 tlsSettings 取 sni/insecure/utls ⇒ 那三颗控件在 reality 下照样有效。
    assert_eq!(v["tls"]["server_name"], serde_json::json!("at.sni"));
    assert_eq!(v["tls"]["insecure"], serde_json::json!(true));
    assert_eq!(
        v["tls"]["utls"]["fingerprint"],
        serde_json::json!("firefox")
    );
}

/// anytls 选了 reality 却没填公钥（`realitySettings` 缺席）⇒ 不造 reality 块，但 TLS 块仍在
/// （anytls ∈ `TLS_PROTOCOLS`）—— 前端「pbk 为空即整块不下发」不会造出半成品节点。
#[test]
fn anytls_reality_without_settings_keeps_plain_tls_block() {
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"anytls","address":"a.com","port":443,
                "password":"pw","security":"reality"}"#,
    );
    assert_eq!(v["tls"]["enabled"], serde_json::json!(true));
    assert!(v["tls"].get("reality").is_none());
    assert_eq!(v["tls"]["server_name"], serde_json::json!("a.com"));
}

/// vmess / trojan 的 uTLS 指纹：**缺省是 `none`**（与 vless/anytls 的 `chrome` 不同）
/// ⇒ 没填时整个 `utls` 块不下发；填了才有。前端的 fp 首档因此必须是空串而非 chrome。
#[test]
fn vmess_trojan_fingerprint_defaults_to_none_and_is_emitted_when_set() {
    for (proto, extra) in [
        ("vmess", r#""uuid":"u-1","security":"tls""#),
        ("trojan", r#""password":"pw""#),
    ] {
        let v = outbound_json_from(&format!(
            r#"{{"id":"s1","name":"n","protocol":"{proto}","address":"x.com","port":443,{extra}}}"#
        ));
        assert!(
            v["tls"].get("utls").is_none(),
            "{proto} 没填指纹时不得下发 utls（缺省 none）"
        );

        let v = outbound_json_from(&format!(
            r#"{{"id":"s1","name":"n","protocol":"{proto}","address":"x.com","port":443,{extra},
                    "tlsSettings":{{"fingerprint":"safari"}}}}"#
        ));
        assert_eq!(
            v["tls"]["utls"]["fingerprint"],
            serde_json::json!("safari"),
            "{proto} 填了指纹必须下发"
        );
    }
}

/// trojan 的 ALPN：**留空 ≠ 空数组** —— 缺省专属回落 `["http/1.1"]`，填了才覆盖。
/// 故前端空值必须是「不下发 alpn 键」；写 `alpn: []` 会把这条缺省顶掉。
#[test]
fn trojan_alpn_default_is_overridden_only_when_set() {
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"trojan","address":"t.com","port":443,
                "password":"pw"}"#,
    );
    assert_eq!(v["tls"]["alpn"], serde_json::json!(["http/1.1"]));

    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"trojan","address":"t.com","port":443,
                "password":"pw","tlsSettings":{"alpn":["h3","h2"]}}"#,
    );
    assert_eq!(v["tls"]["alpn"], serde_json::json!(["h3", "h2"]));

    // 空数组是**用户真的清空了 ALPN**，不等于「没填」——不得被缺省顶回 http/1.1。
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"trojan","address":"t.com","port":443,
                "password":"pw","tlsSettings":{"alpn":[]}}"#,
    );
    assert_eq!(v["tls"]["alpn"], serde_json::json!([]));
}

/// vmess `security` 是开放 String，`zero` 原样透传（内核合法档，上游 下拉里也有）。
#[test]
fn vmess_zero_security_passes_through() {
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"vmess","address":"v.com","port":443,
                "uuid":"u-1","vmessSecurity":"zero"}"#,
    );
    assert_eq!(v["security"], serde_json::json!("zero"));
}

#[test]
fn ws_transport_ed_parse() {
    let mut s = server(Protocol::Vless, "w.com");
    s.uuid = Some("u".into());
    s.network = Some("ws".into());
    s.ws_settings = Some(Box::new(ps::WebSocketSettings {
        path: Some("/ws?ed=2560".into()),
        ..Default::default()
    }));
    let ob = build_proxy_outbound(&s, "proxy-s1", &test_dial_resolver(), "x64", "linux");
    let t = ob.transport.as_ref().unwrap();
    assert_eq!(t.type_field, "ws");
    assert_eq!(t.path.as_deref(), Some("/ws")); // ed 剥离
    assert_eq!(t.max_early_data, Some(2560));
}

// ══════════════════════════════════════════════════════════════════════════
// 批 B（TLS 高级三件套 · multiplex · tuic 0-RTT/心跳 · ssh 算法协商 · ss 插件 ·
// ws 早数据）的**后端侧门**。生产代码一行未改，这些断言只是把「Rust 本来就会下发」
// 这个前提钉死 —— 它一旦不成立，前端那批控件就退化成假控件。
//
// 与上一批同一纪律：断言全部落在**序列化后的 JSON**（`OutboundTls`/`Transport`/`Multiplex`
// 的字段几乎都带 `skip_serializing_if`，只断言结构体字段的话，键被漏出配置也照样绿）。
// ══════════════════════════════════════════════════════════════════════════

/// `outbound_json_from` 把 arch/platform 钉死成 `("x64","linux")`；TLS engine 与 spoof 的门
/// **恰恰读这两个参数**，故本批需要一个能改这两维的版本。
fn outbound_json_on(server_json: &str, arch: &str, platform: &str) -> serde_json::Value {
    let s: ServerConfig = serde_json::from_str(server_json).expect("节点必须能反序列化");
    let ob = build_proxy_outbound(&s, "proxy-s1", &test_dial_resolver(), arch, platform);
    serde_json::to_value(&ob).unwrap()
}

/// TLS engine 是**平台门控**（`should_emit_tls_engine`）：只有 windows/win32、apple/darwin
/// 两种组合才下发；`go` 与缺席都不下发 ⇒ 前端 engine 下拉的首档必须是空串，且跨平台选错档
/// 不会造出会 FATAL 的配置（这正是 Polaris 不像 上游 那样按平台隐藏选项的安全依据）。
#[test]
fn tls_engine_is_platform_gated() {
    let node = |engine: &str| {
        format!(
            r#"{{"id":"s1","name":"n","protocol":"vless","address":"a.com","port":443,
                    "uuid":"u-1","security":"tls","tlsSettings":{{"engine":"{engine}"}}}}"#
        )
    };
    assert_eq!(
        outbound_json_on(&node("windows"), "x64", "win32")["tls"]["engine"],
        serde_json::json!("windows")
    );
    assert_eq!(
        outbound_json_on(&node("apple"), "arm64", "darwin")["tls"]["engine"],
        serde_json::json!("apple")
    );
    // 平台不匹配 / go / 缺席：一律不下发该键。
    for (engine, platform) in [
        ("windows", "darwin"),
        ("apple", "win32"),
        ("windows", "linux"),
        ("go", "win32"),
    ] {
        let v = outbound_json_on(&node(engine), "x64", platform);
        assert!(
            v["tls"].get("engine").is_none(),
            "engine={engine} platform={platform} 不得下发 tls.engine"
        );
    }
}

/// 🔴 **Reality 下不发 `tls.engine`，且这不是缺口——是内核的硬约束。**
///
/// 机制：TLS 段先按 `should_emit_tls_engine` 把 engine 装进 `ob.tls`，reality 段随后用一个
/// 新造的 `OutboundTls`（`engine: None`）**整体替换**掉它。spoof/ech 由
/// `apply_anti_censorship_options` 在替换**之后**补，故照常生效 —— 它们是本测试的阴性对照，
/// 用来证明「reality 段替换掉了整个块」这个机制描述本身是对的，而不是随便丢了几个键。
///
/// 判据不是 schema：`$defs/OutboundTLSOptions` 里 `engine` 与 `reality` 确实是平级、无互斥约束，
/// 但那只表达键的形状。真正的拒绝发生在 `initialize outbound` 阶段，四个随包二进制的字符串
/// 在场矩阵是判决书（生产注释里有完整表）：`"reality is unsupported in "` 与
/// `"utls is unsupported in "` 只编进 win / mac 那三个构建，linux 一条都没有。
/// ⇒ Linux 上做的任何 `reality × engine` 对照都只能碰到桩，检出力为 0。
///
/// ⇒ 前端 `whenTlsEngine` 上那条 `!whenReality` **有依据、必须留着**：reality 下这一档在任何
/// 平台都不可用，显示它就是一个「拨了必然让整核起不来」的控件。
///
/// 2026-08-07 曾按「schema 平级 ⇒ 是本仓缺口」把 engine 搬进 reality 块，本测试同批被改成
/// 断言 `engine == "windows"`。那次改动把「静默丢一个键、核照常起」换成了「核起不来」，
/// 已回退。别再来一次。
#[test]
fn reality_branch_drops_tls_engine_but_keeps_spoof_and_ech() {
    let node = |security: &str| {
        format!(
            r#"{{"id":"s1","name":"n","protocol":"vless","address":"a.com","port":443,
                    "uuid":"u-1","security":"{security}",
                    "realitySettings":{{"publicKey":"pk","shortId":"ab"}},
                    "tlsSettings":{{"serverName":"s.com","engine":"windows",
                        "spoofMethod":"wrong-ack","spoofSni":"decoy.com","ech":true}}}}"#
        )
    };
    // 正向对照：同一份 tlsSettings 在 security=tls 下 engine **是**下发的 ——
    // 没有这一条，下面那句 `is_none()` 可能只是因为平台门没放行，与 reality 无关。
    let plain = outbound_json_on(&node("tls"), "x64", "win32");
    assert_eq!(plain["tls"]["engine"], serde_json::json!("windows"));

    let reality = outbound_json_on(&node("reality"), "x64", "win32");
    assert_eq!(
        reality["tls"]["reality"]["public_key"],
        serde_json::json!("pk")
    );
    assert!(
        reality["tls"].get("engine").is_none(),
        "reality 下发了 tls.engine ⇒ 真机 win32/darwin 上内核会 \
             `FATAL initialize outbound: reality is unsupported in <engine>`，整份配置起不来"
    );
    // 阴性对照：spoof / ech 在 reality 下**照常生效**（它们在替换之后才补），
    // 故「reality 不发 engine」不是「reality 把 TLS 相关的都丢了」。
    assert_eq!(reality["tls"]["spoof"], serde_json::json!("decoy.com"));
    assert_eq!(
        reality["tls"]["spoof_method"],
        serde_json::json!("wrong-ack")
    );
    assert_eq!(reality["tls"]["ech"]["enabled"], serde_json::json!(true));
}

/// 同一条约束在 darwin 上也成立 —— 上面那条只跑了 win32。
///
/// 为什么值得单列：`should_emit_tls_engine` 是 `(engine, platform)` 二元门，win32 绿不蕴含
/// darwin 绿；而 `"reality is unsupported in "` 在 mac-x64 / mac-arm64 两个二进制里都在场，
/// 即 darwin 上的判决与 win32 同型。
#[test]
fn reality_drops_tls_engine_on_darwin_too() {
    let node = |security: &str| {
        format!(
            r#"{{"id":"s1","name":"n","protocol":"vless","address":"a.com","port":443,
                    "uuid":"u-1","security":"{security}",
                    "realitySettings":{{"publicKey":"pk","shortId":"ab"}},
                    "tlsSettings":{{"serverName":"s.com","engine":"apple"}}}}"#
        )
    };
    // 正向对照先行：apple × darwin 这一组在 security=tls 下确实过得了平台门。
    assert_eq!(
        outbound_json_on(&node("tls"), "arm64", "darwin")["tls"]["engine"],
        serde_json::json!("apple")
    );
    let v = outbound_json_on(&node("reality"), "arm64", "darwin");
    assert_eq!(v["tls"]["reality"]["public_key"], serde_json::json!("pk"));
    assert!(v["tls"].get("engine").is_none());
}

/// QUIC 自管 TLS 的两个协议**永远拿不到 engine**（`is_quic_managed_tls` 前置门）——
/// 覆盖矩阵把「hy2/tuic 不出 engine」列为有意排除，依据就是这一句。
#[test]
fn tls_engine_never_emitted_for_quic_protocols() {
    for (proto, extra) in [
        ("hysteria2", r#""password":"pw""#),
        ("tuic", r#""uuid":"u-1","password":"pw""#),
    ] {
        let v = outbound_json_on(
            &format!(
                r#"{{"id":"s1","name":"n","protocol":"{proto}","address":"q.com","port":443,{extra},
                        "tlsSettings":{{"engine":"windows"}}}}"#
            ),
            "x64",
            "win32",
        );
        assert!(
            v["tls"].get("engine").is_none(),
            "{proto} 的 TLS 在 QUIC 内自管，不得下发 engine"
        );
    }
}

/// TLS spoof 的下发要**同时**满足：方法合法 + 非 ARM + 诱饵 SNI 非空非 IP + 协议非 QUIC/naive
/// + 诱饵 ≠ 真 server_name 且真 server_name 非 IP。任一不满足即整对不下发（不 FATAL）。
#[test]
fn tls_spoof_emitted_only_when_every_gate_passes() {
    let node = |method: &str, spoof: &str, sni: &str| {
        format!(
            r#"{{"id":"s1","name":"n","protocol":"vless","address":"a.com","port":443,
                    "uuid":"u-1","security":"tls",
                    "tlsSettings":{{"serverName":"{sni}","spoofMethod":"{method}","spoofSni":"{spoof}"}}}}"#
        )
    };
    let v = outbound_json_on(&node("wrong-ack", "decoy.com", "real.com"), "x64", "linux");
    assert_eq!(v["tls"]["spoof"], serde_json::json!("decoy.com"));
    assert_eq!(v["tls"]["spoof_method"], serde_json::json!("wrong-ack"));

    // ARM64：内核只在 amd64 实现 ⇒ 整对不下发（前端因此把 ARM64 限制写进控件说明）。
    let v = outbound_json_on(
        &node("wrong-ack", "decoy.com", "real.com"),
        "arm64",
        "linux",
    );
    assert!(v["tls"].get("spoof").is_none());
    assert!(v["tls"].get("spoof_method").is_none());

    // 诱饵 == 真 server_name / 诱饵是 IP 字面量 / 诱饵为空 / 方法不在三档白名单：都不下发。
    for (method, spoof, sni, why) in [
        ("wrong-ack", "same.com", "same.com", "诱饵不得等于真 SNI"),
        ("wrong-ack", "1.2.3.4", "real.com", "诱饵不得是 IP 字面量"),
        ("wrong-ack", "", "real.com", "诱饵为空"),
        (
            "wrong-sequence",
            "decoy.com",
            "real.com",
            "内核 schema 有这档但本仓门控只放行三档",
        ),
    ] {
        let v = outbound_json_on(&node(method, spoof, sni), "x64", "linux");
        assert!(v["tls"].get("spoof").is_none(), "{why}");
        assert!(v["tls"].get("spoof_method").is_none(), "{why}");
    }
}

/// 真 server_name 是 IP 字面量（节点地址是 IP 且没填 SNI 的回落形态）同样堵死 spoof ——
/// 这条是「填了却没生效」的最常见成因，前端说明里点了名。
#[test]
fn tls_spoof_blocked_when_real_server_name_is_ip() {
    let v = outbound_json_on(
        r#"{"id":"s1","name":"n","protocol":"vless","address":"1.2.3.4","port":443,
                "uuid":"u-1","security":"tls",
                "tlsSettings":{"spoofMethod":"wrong-md5","spoofSni":"decoy.com"}}"#,
        "x64",
        "linux",
    );
    assert_eq!(v["tls"]["server_name"], serde_json::json!("1.2.3.4"));
    assert!(v["tls"].get("spoof").is_none());
}

/// ECH 对**任何有 TLS 块的协议**一视同仁（`apply_anti_censorship_options` 无协议门）——
/// hy2/tuic 早已做过控件，vless/vmess/trojan/anytls 缺的只是控件。
/// `echConfig` 留空 = 只发 `{enabled:true}`（内核从 DNS HTTPS RR 自取），填了才带 config 数组。
#[test]
fn ech_is_assembled_for_every_tcp_tls_protocol() {
    for (proto, extra) in [
        ("vless", r#""uuid":"u-1","security":"tls""#),
        ("vmess", r#""uuid":"u-1","security":"tls""#),
        ("trojan", r#""password":"pw""#),
        ("anytls", r#""password":"pw""#),
        ("http", r#""username":"u","password":"pw","security":"tls""#),
    ] {
        let v = outbound_json_from(&format!(
            r#"{{"id":"s1","name":"n","protocol":"{proto}","address":"e.com","port":443,{extra},
                    "tlsSettings":{{"ech":true}}}}"#
        ));
        assert_eq!(
            v["tls"]["ech"]["enabled"],
            serde_json::json!(true),
            "{proto} 的 ECH 没装配"
        );
        assert!(
            v["tls"]["ech"].get("config").is_none(),
            "{proto}: echConfig 留空时不得下发 config 键"
        );

        let v = outbound_json_from(&format!(
            r#"{{"id":"s1","name":"n","protocol":"{proto}","address":"e.com","port":443,{extra},
                    "tlsSettings":{{"ech":true,"echConfig":"line-a\nline-b"}}}}"#
        ));
        assert_eq!(
            v["tls"]["ech"]["config"],
            serde_json::json!(["line-a", "line-b"]),
            "{proto}: echConfig 按行拆成数组"
        );
    }
}

/// 🔴 Multiplex 的协议面就是那句 `matches!` —— 四个协议下发、其余**静默丢弃**。
/// 前端 `F_MUX` 只挂这四个，依据即此；给别的协议加控件就是假控件。
#[test]
fn multiplex_only_for_the_four_protocols_in_matches() {
    let node = |proto: &str, extra: &str| {
        format!(
            r#"{{"id":"s1","name":"n","protocol":"{proto}","address":"m.com","port":443,{extra},
                    "multiplexSettings":{{"enabled":true,"protocol":"yamux","maxConnections":4,
                    "minStreams":2,"padding":true}}}}"#
        )
    };
    for (proto, extra) in [
        ("vless", r#""uuid":"u-1""#),
        ("vmess", r#""uuid":"u-1""#),
        ("trojan", r#""password":"pw""#),
        (
            "shadowsocks",
            r#""shadowsocksSettings":{"method":"aes-256-gcm","password":"p"}"#,
        ),
    ] {
        let v = outbound_json_from(&node(proto, extra));
        assert_eq!(
            v["multiplex"]["enabled"],
            serde_json::json!(true),
            "{proto}"
        );
        assert_eq!(v["multiplex"]["protocol"], serde_json::json!("yamux"));
        assert_eq!(v["multiplex"]["max_connections"], serde_json::json!(4));
        assert_eq!(v["multiplex"]["min_streams"], serde_json::json!(2));
        assert_eq!(v["multiplex"]["padding"], serde_json::json!(true));
    }
    // 阴性对照：不在 `matches!` 里的协议，同一份 multiplexSettings 一个字节都到不了配置。
    for (proto, extra) in [
        ("anytls", r#""password":"pw""#),
        ("hysteria2", r#""password":"pw""#),
        ("socks", r#""username":"u""#),
    ] {
        let v = outbound_json_from(&node(proto, extra));
        assert!(
            v.get("multiplex").is_none(),
            "{proto} 不在 matches! 里，multiplex 必须被丢弃"
        );
    }
}

/// multiplex 的可选三键留空 → 不下发；`protocol` 缺席 → 后端补 `h2mux`
/// （故前端下拉的 h2mux 档与「不写」逐字节同结果）。
#[test]
fn multiplex_optional_keys_omitted_and_protocol_defaults_to_h2mux() {
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"vless","address":"m.com","port":443,
                "uuid":"u-1","multiplexSettings":{"enabled":true}}"#,
    );
    assert_eq!(v["multiplex"]["protocol"], serde_json::json!("h2mux"));
    for k in ["max_connections", "min_streams", "padding"] {
        assert!(v["multiplex"].get(k).is_none(), "留空的 {k} 不得下发");
    }
    // `enabled:false` 与整块缺席同结果 —— 前端「关开关即整块不下发」不会改变生成产物。
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"vless","address":"m.com","port":443,
                "uuid":"u-1","multiplexSettings":{"enabled":false,"protocol":"smux"}}"#,
    );
    assert!(v.get("multiplex").is_none());
}

/// vision flow 跳过 multiplex —— 判据是 `flow.to_ascii_lowercase().contains("vision")`
/// （**子串**匹配，不是相等），前端 `whenMuxAvail` 逐字镜像了这一点。
#[test]
fn multiplex_skipped_for_any_vision_flow_variant() {
    for flow in [
        "xtls-rprx-vision",
        "XTLS-RPRX-VISION",
        "xtls-rprx-vision-udp443",
    ] {
        let v = outbound_json_from(&format!(
            r#"{{"id":"s1","name":"n","protocol":"vless","address":"m.com","port":443,
                    "uuid":"u-1","flow":"{flow}","multiplexSettings":{{"enabled":true}}}}"#
        ));
        assert!(
            v.get("multiplex").is_none(),
            "flow={flow} 必须跳过 multiplex"
        );
    }
}

/// tuic 的 0-RTT 与心跳都是真下发；`heartbeat` 走 `normalize_duration`（裸数字补 `ms`）。
#[test]
fn tuic_zero_rtt_and_heartbeat_reach_json() {
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"tuic","address":"t.com","port":443,
                "uuid":"u-1","password":"pw",
                "tuicSettings":{"zeroRttHandshake":true,"heartbeat":"10s"}}"#,
    );
    assert_eq!(v["zero_rtt_handshake"], serde_json::json!(true));
    assert_eq!(v["heartbeat"], serde_json::json!("10s"));

    // 裸数字 → 补 ms（前端因此原样存用户输入，不在 UI 侧补单位）。
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"tuic","address":"t.com","port":443,
                "uuid":"u-1","password":"pw","tuicSettings":{"heartbeat":"3000"}}"#,
    );
    assert_eq!(v["heartbeat"], serde_json::json!("3000ms"));

    // 两键缺席 → 都不下发（前端「关=删键、空=删键」与之逐字节一致）。
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"tuic","address":"t.com","port":443,
                "uuid":"u-1","password":"pw","tuicSettings":{"congestionControl":"bbr"}}"#,
    );
    assert!(v.get("zero_rtt_handshake").is_none());
    assert!(v.get("heartbeat").is_none());
}

/// ssh 的四个算法协商列表都是真下发，键名以内核 schema 为准（单数 `cipher`/`mac`/`kex_algorithm`）。
#[test]
fn ssh_algorithm_lists_reach_json() {
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"ssh","address":"s.com","port":22,
                "sshSettings":{"user":"root","hostKey":["ssh-ed25519 AAAA"],
                "hostKeyAlgorithms":["ssh-ed25519","rsa-sha2-256"],
                "cipher":["aes128-ctr"],"mac":["hmac-sha2-256"],
                "kexAlgorithm":["curve25519-sha256"]}}"#,
    );
    assert_eq!(
        v["host_key_algorithms"],
        serde_json::json!(["ssh-ed25519", "rsa-sha2-256"])
    );
    assert_eq!(v["cipher"], serde_json::json!(["aes128-ctr"]));
    assert_eq!(v["mac"], serde_json::json!(["hmac-sha2-256"]));
    assert_eq!(v["kex_algorithm"], serde_json::json!(["curve25519-sha256"]));

    // 缺席 → 不下发（前端留空必须删键：空数组等于「一个算法都不接受」，不是「用默认集」）。
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"ssh","address":"s.com","port":22,
                "sshSettings":{"user":"root"}}"#,
    );
    for k in ["host_key_algorithms", "cipher", "mac", "kex_algorithm"] {
        assert!(v.get(k).is_none(), "{k} 缺席时不得下发");
    }
}

/// shadowsocks 的 SIP003 插件两键原样透传。
#[test]
fn shadowsocks_plugin_and_opts_reach_json() {
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"shadowsocks","address":"ss.com","port":8388,
                "shadowsocksSettings":{"method":"aes-256-gcm","password":"p",
                "plugin":"obfs-local","pluginOptions":"obfs=http;obfs-host=bing.com"}}"#,
    );
    assert_eq!(v["plugin"], serde_json::json!("obfs-local"));
    assert_eq!(
        v["plugin_opts"],
        serde_json::json!("obfs=http;obfs-host=bing.com")
    );

    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"shadowsocks","address":"ss.com","port":8388,
                "shadowsocksSettings":{"method":"aes-192-gcm","password":"p"}}"#,
    );
    assert_eq!(v["method"], serde_json::json!("aes-192-gcm")); // T5：表外档位是内核合法值
    assert!(v.get("plugin").is_none());
    assert!(v.get("plugin_opts").is_none());
}

/// 🔴 ws 早数据两键的**归属与优先级**（前端控件语义的全部依据）：
///  ① 两键只在 `ws` 腿下发，`httpupgrade` 腿根本不读 ⇒ 前端用 `whenWs` 而非 `whenWsLike`；
///  ② `path` 里的 `?ed=` **赢过** `wsSettings.maxEarlyData`（`ed.or_else(|| ws.max_early_data)`），
///     且 `ed`/`eh` 会从 path 上被摘掉。
#[test]
fn ws_early_data_belongs_to_ws_leg_and_path_ed_wins() {
    // ① 只填 settings、path 无 ed：两键按填的走。
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"vless","address":"w.com","port":443,
                "uuid":"u-1","network":"ws",
                "wsSettings":{"path":"/ray","maxEarlyData":1024,"earlyDataHeaderName":"X-Ed"}}"#,
    );
    assert_eq!(v["transport"]["path"], serde_json::json!("/ray"));
    assert_eq!(v["transport"]["max_early_data"], serde_json::json!(1024));
    assert_eq!(
        v["transport"]["early_data_header_name"],
        serde_json::json!("X-Ed")
    );

    // ② path 的 ?ed=/?eh= 覆盖 settings（前端因此在控件说明里写明「路径赢」）。
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"vless","address":"w.com","port":443,
                "uuid":"u-1","network":"ws",
                "wsSettings":{"path":"/ray?ed=2560&eh=X-Path","maxEarlyData":1024,
                "earlyDataHeaderName":"X-Settings"}}"#,
    );
    assert_eq!(v["transport"]["path"], serde_json::json!("/ray"));
    assert_eq!(v["transport"]["max_early_data"], serde_json::json!(2560));
    assert_eq!(
        v["transport"]["early_data_header_name"],
        serde_json::json!("X-Path")
    );

    // ③ httpupgrade 腿：同一份 wsSettings 里的这两键**一个都不下发**。
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"vless","address":"w.com","port":443,
                "uuid":"u-1","security":"tls","network":"httpupgrade",
                "wsSettings":{"path":"/hu","maxEarlyData":1024,"earlyDataHeaderName":"X-Ed"}}"#,
    );
    assert_eq!(v["transport"]["type"], serde_json::json!("httpupgrade"));
    assert!(v["transport"].get("max_early_data").is_none());
    assert!(v["transport"].get("early_data_header_name").is_none());
}

/// 🔴 **`GrpcSettings.multiMode` 永远到不了内核** —— 这是「不该补控件」那条裁定的证据。
/// `generate_transport_config` 的 grpc 腿只造 `type` + `service_name`，`Transport` 结构体里
/// 压根没有这个字段；随包核 beta.7 的 grpc 传输 schema 同样没有（`additionalProperties:false`，
/// 真下发反而是 FATAL）。它只活在 share-link 往返里（`net-stack/share_link.rs` 的 `mode=multi`）。
#[test]
fn grpc_multi_mode_never_reaches_the_kernel() {
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"vless","address":"g.com","port":443,
                "uuid":"u-1","security":"tls","network":"grpc",
                "grpcSettings":{"serviceName":"GunService","multiMode":true}}"#,
    );
    assert_eq!(
        v["transport"]["service_name"],
        serde_json::json!("GunService")
    );
    let keys: Vec<&str> = v["transport"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    // `serde_json::Map` 无 preserve_order feature ⇒ 键有序，断言按字典序写。
    assert_eq!(
        keys,
        vec!["service_name", "type"],
        "grpc 传输只有这两个键 —— multi_mode 建了模却无处可去，给它加控件即假控件"
    );
}

// ── 批 D 的后端侧门（UI 补 h2 四件套 · alpn×5 · http 指纹 · hy2 network · naive ECH · fragment×5）──
//
// 同上一批：断言全部落在**序列化后的 JSON**，只断言结构体字段的话，某个键被 `skip_serializing_if`
// 漏出配置也照样绿。

/// h2 传输的四个键**全都被读**（`generate_transport_config` 的 `"http" | "h2"` 腿）。
/// `host` 是 `Vec<String>`：长度 1 序列化成裸串、>1 成数组（`OneOrMany`），两种形态内核都认。
#[test]
fn h2_transport_reads_all_four_http_settings_keys() {
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"vless","address":"h.com","port":443,
                "uuid":"u-1","security":"tls","network":"http",
                "httpSettings":{"path":"/h2","host":["a.com","b.com"],"method":"PUT",
                                "headers":{"X-Real-IP":["1.2.3.4"]}}}"#,
    );
    assert_eq!(v["transport"]["type"], serde_json::json!("http"));
    assert_eq!(v["transport"]["path"], serde_json::json!("/h2"));
    assert_eq!(
        v["transport"]["host"],
        serde_json::json!(["a.com", "b.com"])
    );
    assert_eq!(v["transport"]["method"], serde_json::json!("PUT"));
    assert_eq!(
        v["transport"]["headers"]["X-Real-IP"],
        serde_json::json!(["1.2.3.4"])
    );

    // 单元素 host → 裸串（`OneOrMany::One`）。
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"vmess","address":"h.com","port":443,
                "uuid":"u-1","security":"tls","network":"http",
                "httpSettings":{"host":["only.com"]}}"#,
    );
    assert_eq!(v["transport"]["host"], serde_json::json!("only.com"));
}

/// 「选了就废」的第二个实例：选了 h2 却没有 `httpSettings` ⇒ 只落 `path:"/"`，其余三键不下发。
/// 前端补这四颗控件的全部理由（同 ws 那条 `ws_without_settings_falls_back_to_root_path`）。
#[test]
fn h2_without_settings_falls_back_to_root_path_only() {
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"trojan","address":"h.com","port":443,
                "password":"pw","network":"http"}"#,
    );
    assert_eq!(v["transport"]["type"], serde_json::json!("http"));
    assert_eq!(v["transport"]["path"], serde_json::json!("/"));
    for k in ["host", "method", "headers"] {
        assert!(
            v["transport"].get(k).is_none(),
            "没填 {k} 时不得凭空造该键（前端留空必须是删键）"
        );
    }
}

/// `final_alpn` 对**所有**走标准 TLS 栈的协议都读 `tls_settings.alpn` —— 此前只有 trojan/tuic
/// 的表单给了输入框，其余四个协议的 alpn 是 per-protocol 判据新暴露出来的欠账。
#[test]
fn alpn_reaches_tls_json_for_every_standard_tls_protocol() {
    for (proto, cred) in [
        ("vless", r#""uuid":"u-1""#),
        ("vmess", r#""uuid":"u-1""#),
        ("anytls", r#""password":"pw""#),
        ("hysteria2", r#""password":"pw""#),
        ("http", r#""username":"u""#),
    ] {
        let v = outbound_json_from(&format!(
            r#"{{"id":"s1","name":"n","protocol":"{proto}","address":"a.com","port":443,
                    {cred},"security":"tls","tlsSettings":{{"alpn":["h2","http/1.1"]}}}}"#
        ));
        assert_eq!(
            v["tls"]["alpn"],
            serde_json::json!(["h2", "http/1.1"]),
            "{proto} 的 alpn 必须原样下发"
        );
    }
}

/// 不填 alpn ⇒ **除 trojan 外都不下发该键**（trojan 有专属缺省 `["http/1.1"]`）。
/// 这条钉的是前端「留空 = 删键」的正确性：写空数组会把 trojan 那条缺省顶掉。
#[test]
fn alpn_absent_means_no_key_except_trojan_default() {
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"vless","address":"a.com","port":443,
                "uuid":"u-1","security":"tls"}"#,
    );
    assert!(v["tls"].get("alpn").is_none());
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"trojan","address":"a.com","port":443,
                "password":"pw","security":"tls"}"#,
    );
    assert_eq!(v["tls"]["alpn"], serde_json::json!(["http/1.1"]));
}

/// http 协议的 uTLS 指纹：http **不在** `is_quic_managed_tls` 里 ⇒ `final_fp != "none"` 时
/// utls 块照常下发；不填则回落 `none`（非 vless/anytls 的缺省）⇒ 整块不下发。
/// 后者正是前端必须用 `O_FP_OPT`（带空首项）而不是 `O_FP` 的理由。
#[test]
fn http_fingerprint_emits_utls_and_defaults_to_none() {
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"http","address":"a.com","port":8080,
                "username":"u","security":"tls","tlsSettings":{"fingerprint":"firefox"}}"#,
    );
    assert_eq!(v["tls"]["utls"]["enabled"], serde_json::json!(true));
    assert_eq!(
        v["tls"]["utls"]["fingerprint"],
        serde_json::json!("firefox")
    );

    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"http","address":"a.com","port":8080,
                "username":"u","security":"tls"}"#,
    );
    assert!(
        v["tls"].get("utls").is_none(),
        "http 缺省 final_fp = none ⇒ 整个 utls 块不下发；前端首档必须是空串"
    );
}

/// 🔴 **http 协议的 headers/path 必须落在出站顶层，`transport` 键一出现整个核就起不来。**
///
/// 随包核 1.14.0-beta.7 的 http 出站 schema 无 `transport` 且 `additionalProperties:false`：
/// 实测 `sing-box check` → `FATAL decode config: outbounds[0].transport: json: unknown field
/// "transport"`（rc=1）；同一份 headers/path 写顶层 → rc=0。
///
/// 这条断言是那次移植错误（上游 `singbox-outbound-builder.ts:391-398` 的 1:1 搬运）的回归锁：
/// 只要有人把这两键挪回 `transport`，`transport` 键就会重新出现 ⇒ 转红。
///
/// 🔴 **输入必须带 `network`。** 全仓 `http_settings` 的 4 个非测试写入点
/// （`singbox_import.rs:269` / `xray_import.rs:120` / `clash_parser.rs:365` /
/// `share_link.rs:280`）**每一处都在写 `http_settings` 的同时写 `network`**，
/// 没有任何生产路径能造出「有 httpSettings、无 network」。若这里省掉 `network`，
/// 传输层那段压根不跑，`transport` 恒缺席 ⇒ 断言恒真、对本缺陷零信息量
/// （本测试第一版正是那个形状：产物在真实链路上照样 FATAL，而门全绿）。
#[test]
fn http_protocol_masquerade_goes_to_top_level_never_transport() {
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"http","address":"a.com","port":8080,
                "username":"u","password":"p","network":"http",
                "httpSettings":{"path":"/tunnel","headers":{"Host":["a.example.com"]}}}"#,
    );
    assert_eq!(v["path"], serde_json::json!("/tunnel"));
    assert_eq!(
        v["headers"],
        serde_json::json!({"Host": ["a.example.com"]}),
        "headers 对齐 schema 的 $defs/HTTPHeader = map<string, string|string[]>"
    );
    assert!(
        v.get("transport").is_none(),
        "http 出站一旦带 transport，内核 decode 阶段就 FATAL（整份配置起不来）"
    );
}

/// 🔴 **缺 `snellSettings` 的 snell 节点仍须发出内核认的 `version` + `psk`。**
///
/// 此前整段包在 `if let Some(s) = &server.snell_settings` 里 ⇒ 缺席时一个键都不发，
/// 内核在 **decode 阶段**判 `snell: missing version`，**整份配置起不来**（不止这个节点）。
/// 由 `tests/kernel_accepts_outbounds.rs` 的协议 × 传输交叉门发现。
///
/// 归一到 4/6 的第二个理由：`SnellVersion = u32` 且 `Default` 派生 ⇒ 缺省值是 **0**，
/// 而 0 同样不是内核认的版本 —— 半份 JSON 反序列化就能得到它。
///
/// 本条**不依赖真核**，故在 `ci.yml`（不拉核）上也守得住；交叉门那边是它的真环境复核。
#[test]
fn snell_without_settings_still_emits_a_kernel_valid_version_and_psk() {
    // 缺 `snellSettings`：此前整段跳过 ⇒ 出站既无 version 也无 psk ⇒ 内核 **decode 阶段**
    // 判 `snell: missing version`，整份配置起不来。
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"snell","address":"a.com","port":443,
                "password":"pw"}"#,
    );
    assert_eq!(
        v["version"],
        serde_json::json!(4),
        "缺 snellSettings 时必须落到 v4（同 UI proto-codec 的 `version === 6 ? 6 : 4`）"
    );
    assert_eq!(v["psk"], serde_json::json!("pw"), "psk 一并不能漏");

    // `version` 为 0（`SnellVersion = u32` + `Default` 派生的缺省值，半份 JSON 反序列化即得）
    // 同样要归一 —— 0 不是内核认的版本。
    let zero = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"snell","address":"a.com","port":443,
                "password":"pw","snellSettings":{"version":0}}"#,
    );
    assert_eq!(zero["version"], serde_json::json!(4));

    // 正向对照：显式 v6 不受归一影响，且走的是 v6 那条腿（mode 生效、obfs 不生效）。
    let v6 = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"snell","address":"a.com","port":443,
                "password":"pw","snellSettings":{"version":6,"mode":"aes-128-gcm",
                    "obfsMode":"http","obfsHost":"decoy.com"}}"#,
    );
    assert_eq!(v6["version"], serde_json::json!(6));
    assert_eq!(v6["mode"], serde_json::json!("aes-128-gcm"));
    assert!(
        v6.get("obfs_mode").is_none(),
        "v6 不走 obfs 腿 —— 若这条红了说明归一把版本分支也一起改坏了"
    );
    // 反向：显式 v4 时 obfs 生效、mode 不生效。
    let v4 = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"snell","address":"a.com","port":443,
                "password":"pw","snellSettings":{"version":4,"obfsMode":"http",
                    "mode":"aes-128-gcm"}}"#,
    );
    assert_eq!(v4["obfs_mode"], serde_json::json!("http"));
    assert!(v4.get("mode").is_none());
}

/// **非白名单协议拿到 `network != tcp` 时不得长出 `transport`** —— 传输层白名单的正面锁。
///
/// 判据是内核 schema：20 支出站 oneOf 里只有 trojan/vless/vmess 有 `transport`。
/// 这些形状**导入侧造得出来**（xray 的 `streamSettings` 可挂任意出站、clash 的 `network:` 同理），
/// 而修前的黑名单 `!matches!(Hysteria2|Anytls|Naive)` 会照单放行 ⇒ 整份配置 FATAL。
#[test]
fn only_trojan_vless_vmess_may_carry_a_transport() {
    // 正向对照先行：白名单里的协议确实**要**长出 transport，否则下面全是 `is_none()` 的空对照。
    for proto in ["vless", "vmess", "trojan"] {
        let v = outbound_json_from(&format!(
            r#"{{"id":"s1","name":"n","protocol":"{proto}","address":"a.com","port":443,
                    "uuid":"u-1","password":"p","network":"ws","wsSettings":{{"path":"/w"}}}}"#
        ));
        assert_eq!(
            v["transport"]["type"],
            serde_json::json!("ws"),
            "{proto} 是内核认的 transport 协议，丢了它等于把用户的传输层配置吞掉"
        );
    }
    // 内核 schema 里没有 transport 的那些：给了 network 也不许长出来。
    for (proto, extra) in [
        ("shadowsocks", r#""method":"aes-256-gcm","password":"p""#),
        ("socks", r#""username":"u","password":"p""#),
        ("http", r#""username":"u","password":"p""#),
        ("tuic", r#""uuid":"u-1","password":"p""#),
        ("snell", r#""password":"p""#),
        ("ssh", r#""username":"u","password":"p""#),
    ] {
        let v = outbound_json_from(&format!(
            r#"{{"id":"s1","name":"n","protocol":"{proto}","address":"a.com","port":443,
                    {extra},"network":"ws","wsSettings":{{"path":"/w"}}}}"#
        ));
        assert!(
            v.get("transport").is_none(),
            "{proto} 出站长出了 transport ⇒ `FATAL decode config: outbounds[0].transport: \
                 json: unknown field \"transport\"`，整份配置起不来"
        );
    }
}

/// `HttpSettings` 的另两键 **`host` / `method` 在 http 协议下刻意不消费**。
///
/// 判据不是「懒得做」：内核 http 出站 schema 里压根没有这两个键，写到顶层同样是
/// `unknown field`（实测 rc=1）⇒ 建模/下发它们只会造出起不来的节点。
/// 它们只在 h2 **传输**那条腿有意义（容器是 `transport`，schema 允许），由
/// `h2_transport_reads_all_four_http_settings_keys` 那侧守着。
///
/// 只断言 `method`，**不断言 `host`**：`singbox::Outbound` 上根本没有 `host` 字段
/// （它只在 `Transport` 上，见 `singbox/outbound.rs`）⇒ `v.get("host").is_none()` 是**恒真**断言，
/// 任何 builder 实现都无法让它红，写进来只会让这道门看起来比实际严。
/// `method` 则相反：它在 `Outbound` 上真实存在（Shadowsocks 的加密方式），
/// http 腿一旦借它来装 HTTP 方法就会被这条抓住。
#[test]
fn http_protocol_never_emits_method() {
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"http","address":"a.com","port":8080,
                "username":"u","password":"p","network":"http",
                "httpSettings":{"path":"/x","host":["decoy.com"],"method":"PUT",
                    "headers":{"X-A":["1"]}}}"#,
    );
    // 正向对照：同一份 httpSettings 里能下发的那两键确实下发了，证明分支真的跑到了。
    assert_eq!(v["path"], serde_json::json!("/x"));
    assert_eq!(v["headers"], serde_json::json!({"X-A": ["1"]}));
    assert!(
        v.get("method").is_none(),
        "内核 http 出站没有 method 键，下发即 FATAL；\
             `Outbound::method` 是 Shadowsocks 的加密方式，http 腿不得借用"
    );
    assert!(v.get("transport").is_none());
}

/// 没有 `httpSettings` 的 http 节点：两键都不出现（**不写空对象、不写 `path:"/"`**）。
///
/// 这一条同时是金样零影响的依据 —— 金样里那个 http 用例的输入就没有 `httpSettings`
/// （`fixtures/config-snapshot.json` 全文 `httpSettings` 出现 0 次），故本次修复不动它一个字节。
#[test]
fn http_without_settings_emits_neither_path_nor_headers() {
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"http","address":"a.com","port":8080,
                "username":"u","password":"p"}"#,
    );
    assert!(v.get("path").is_none(), "留空必须删键，不是 path:\"/\"");
    assert!(v.get("headers").is_none());
    assert!(v.get("transport").is_none());
}

/// **顶层 path/headers 是 http 协议独占**：h2 **传输**那条腿仍把四键装进 `transport`
/// （容器不同，schema 各自合法），顶层必须干净。
///
/// 少了这条，「把两键搬到顶层」很容易被误做成全协议通用 ⇒ vless+h2 会同时出现顶层与
/// transport 两份，而 vless 出站的 schema 没有顶层 `path` ⇒ FATAL。
#[test]
fn h2_transport_leg_keeps_using_transport_and_leaves_top_level_clean() {
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"vless","address":"a.com","port":443,
                "uuid":"u-1","network":"http",
                "httpSettings":{"path":"/h2","host":["a.com"],"method":"PUT",
                    "headers":{"X-B":["2"]}}}"#,
    );
    assert_eq!(v["transport"]["type"], serde_json::json!("http"));
    assert_eq!(v["transport"]["path"], serde_json::json!("/h2"));
    assert_eq!(v["transport"]["method"], serde_json::json!("PUT"));
    assert_eq!(v["transport"]["host"], serde_json::json!("a.com"));
    assert!(
        v.get("path").is_none() && v.get("headers").is_none(),
        "非 http 协议的出站没有顶层 path/headers（vless schema 里不存在这两键）"
    );
}

/// `Hysteria2Settings.network` 真被消费（`ob.network = h.network.clone()`）—— 它此前被覆盖门
/// 跨协议同名判据（snell 的 `{k:'network'}`）遮成「已覆盖」，债务表记的是零。
#[test]
fn hysteria2_network_reaches_outbound_json() {
    for want in ["tcp", "udp"] {
        let v = outbound_json_from(&format!(
            r#"{{"id":"s1","name":"n","protocol":"hysteria2","address":"a.com","port":443,
                    "password":"pw","hysteria2Settings":{{"network":"{want}"}}}}"#
        ));
        assert_eq!(v["network"], serde_json::json!(want));
    }
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"hysteria2","address":"a.com","port":443,
                "password":"pw"}"#,
    );
    assert!(
        v.get("network").is_none(),
        "留空必须删键 = 内核缺省 tcp+udp 都走"
    );
}

/// 🔴 **naive 的 ECH 到得了内核** —— 批 C 把它记成债务时只推理到「`apply_anti_censorship_options`
/// 在 `ech: None` 之后运行」，本条把那一步钉成断言：分支里写死的 `None` 确实被覆盖掉了。
///
/// 内核侧同样实测过（随包核 beta.7）：naive 出站对 TLS 选项有一张**显式拒绝名单**
/// （`… is not supported on naive outbound`：insecure / alpn / uTLS / fragment / reality /
/// min_version / max_version / disable_sni / cipher_suites / curve_preferences /
/// client_certificate / client_key / kernel TLS），**`ech` 不在名单里**；且喂一份坏 PEM 时
/// naive 与 trojan 报同一句 `invalid ECH configs pem` ⇒ 走的是同一条 ECH 装配路径，不是被忽略。
#[test]
fn naive_ech_survives_the_branch_writing_none() {
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"naive","address":"a.com","port":443,
                "username":"u","password":"pw",
                "tlsSettings":{"serverName":"s.com","ech":true,"echConfig":"-----BEGIN ECH CONFIGS-----\nAAAA\n-----END ECH CONFIGS-----"}}"#,
    );
    assert_eq!(v["tls"]["ech"]["enabled"], serde_json::json!(true));
    assert_eq!(
        v["tls"]["ech"]["config"],
        serde_json::json!([
            "-----BEGIN ECH CONFIGS-----",
            "AAAA",
            "-----END ECH CONFIGS-----"
        ])
    );
    // 同一份 tlsSettings 里的其余键仍被 naive 分支挡掉（这才是「只补 ECH」的边界）。
    for k in ["alpn", "insecure", "utls", "engine", "spoof", "fragment"] {
        assert!(
            v["tls"].get(k).is_none(),
            "naive 分支必须继续挡掉 tls.{k}（随包核会点名 FATAL）"
        );
    }
}

/// naive 的拒绝名单在**本仓侧**的落点：分支把这几项写死 `None`，故它们进 `NODE_EXEMPT` 而非债务表。
/// 名单哪天松动（Rust 改成透传），本断言先红 —— 豁免表的依据行就是指着这里。
#[test]
fn naive_tls_branch_pins_the_kernel_reject_list() {
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"naive","address":"a.com","port":443,
                "username":"u","password":"pw",
                "tlsSettings":{"serverName":"s.com","alpn":["h2"],"allowInsecure":true,
                               "fingerprint":"chrome","engine":"windows","fragment":true,
                               "spoofSni":"www.bing.com","spoofMethod":"wrong-ack"}}"#,
    );
    let keys: Vec<&str> = v["tls"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        vec!["enabled", "server_name"],
        "naive 的 TLS 块只许有这两个键 —— 其余项随包核 beta.7 会 `… is not supported on naive outbound` FATAL"
    );
}

/// `fragment` 的下发条件是**严格 `Some(true)`**（`tls_s.fragment == Some(true)`）⇒
/// `None` 与 `Some(false)` 逐字节同结果，前端「关 = 删键、不写 false」由此而来。
/// 键名是内核 `tls.fragment`（boolean），**不是 `record_fragment`**（本仓未建模的另一个键）。
#[test]
fn fragment_emits_only_on_explicit_true_for_the_five_tcp_tls_protocols() {
    for (proto, cred) in [
        ("vless", r#""uuid":"u-1""#),
        ("vmess", r#""uuid":"u-1""#),
        ("trojan", r#""password":"pw""#),
        ("anytls", r#""password":"pw""#),
        ("http", r#""username":"u""#),
    ] {
        let on = outbound_json_from(&format!(
            r#"{{"id":"s1","name":"n","protocol":"{proto}","address":"a.com","port":443,
                    {cred},"security":"tls","tlsSettings":{{"fragment":true}}}}"#
        ));
        assert_eq!(
            on["tls"]["fragment"],
            serde_json::json!(true),
            "{proto} 的 fragment 必须下发"
        );
        assert!(
            on["tls"].get("record_fragment").is_none(),
            "{proto}：本仓建模的是 tls.fragment，不得串到 record_fragment 上"
        );

        for off in ["false", "null"] {
            let v = outbound_json_from(&format!(
                r#"{{"id":"s1","name":"n","protocol":"{proto}","address":"a.com","port":443,
                        {cred},"security":"tls","tlsSettings":{{"fragment":{off}}}}}"#
            ));
            assert!(
                v["tls"].get("fragment").is_none(),
                "{proto} fragment={off} 必须不下发该键（写 false 只是多一个语义等价的键）"
            );
        }
    }
}

/// fragment 在 **reality 下照常生效** ⇒ 前端 `fragment` 的门只叠一级、不叠 `!whenReality`。
///
/// 原版这里还捎带断言「engine 被 reality 吞掉」，那句是**错误归因**：`outbound_json_from` 把
/// platform 钉死成 `"linux"`，`engine:"windows"` 在这条路径上本来就被 `should_emit_tls_engine`
/// 的平台门拦掉 —— 无论 reality 段吞不吞，此处都是 `None`，那条断言**永远分辨不出两者**。
/// engine × reality 的真实关系由 `reality_branch_drops_tls_engine_but_keeps_spoof_and_ech`
/// 与 `reality_drops_tls_engine_on_darwin_too` 两条在 win32/darwin 上分别守着（各带正向对照）。
#[test]
fn fragment_survives_the_reality_branch() {
    let v = outbound_json_from(
        r#"{"id":"s1","name":"n","protocol":"vless","address":"a.com","port":443,
                "uuid":"u-1","security":"reality",
                "realitySettings":{"publicKey":"pk"},
                "tlsSettings":{"fragment":true,"engine":"windows"}}"#,
    );
    assert_eq!(v["tls"]["reality"]["enabled"], serde_json::json!(true));
    assert_eq!(v["tls"]["fragment"], serde_json::json!(true));
}

/// QUIC 两协议：`fragment_unsupported` 挡在前面 ⇒ 填了也不下发（`NODE_EXEMPT` 的依据）。
#[test]
fn fragment_is_dropped_for_quic_managed_protocols() {
    for (proto, cred) in [
        ("hysteria2", r#""password":"pw""#),
        ("tuic", r#""uuid":"u-1","password":"pw""#),
    ] {
        let v = outbound_json_from(&format!(
            r#"{{"id":"s1","name":"n","protocol":"{proto}","address":"a.com","port":443,
                    {cred},"tlsSettings":{{"fragment":true}}}}"#
        ));
        assert!(
            v["tls"].get("fragment").is_none(),
            "{proto} 的 TLS 在 QUIC 内自管，fragment 永不下发 ⇒ 给控件即假控件"
        );
    }
}
