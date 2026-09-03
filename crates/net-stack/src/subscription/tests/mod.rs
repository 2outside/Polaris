use super::*;
use polaris_config_engine::user_config::server_config::{Protocol, SecurityMode};

mod fetch_tests;
mod provider_tests;

#[test]
fn limited_parse_rejects_declared_nodes_before_mapping_them() {
    let text = "proxies:\n  - {name: A, type: ss, server: a.example, port: 1, cipher: aes-256-gcm, password: p}\n  - {name: B, type: ss, server: b.example, port: 2, cipher: aes-256-gcm, password: p}\n";
    let mut gen = || "id".to_string();
    let error = parse_subscription_bundle_limited(
        text,
        "sub",
        "now",
        &mut gen,
        ImportOrigin::RemoteSubscription,
        SubscriptionParseLimits {
            max_nodes: 1,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(error.contains("节点数超过上限 1"));
}

#[test]
fn limited_parse_rejects_structure_and_merge_expansion() {
    let deep = "proxies:\n  - name: A\n    type: ss\n    server: a.example\n    port: 1\n    cipher: aes-256-gcm\n    password: p\n    nested: {a: {b: {c: 1}}}\n";
    let mut gen = || "id".to_string();
    let depth_error = parse_subscription_bundle_limited(
        deep,
        "sub",
        "now",
        &mut gen,
        ImportOrigin::RemoteSubscription,
        SubscriptionParseLimits {
            max_structure_depth: 3,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(depth_error.contains("结构深度超过上限"));

    let merged = "defaults: &defaults\n  cipher: aes-256-gcm\n  password: p\nproxies:\n  - <<: *defaults\n    name: A\n    type: ss\n    server: a.example\n    port: 1\n";
    let merge_error = parse_subscription_bundle_limited(
        merged,
        "sub",
        "now",
        &mut gen,
        ImportOrigin::RemoteSubscription,
        SubscriptionParseLimits {
            max_merge_expansions: 1,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(merge_error.contains("merge 展开项数超过上限"));
}

#[test]
fn every_json_import_format_hits_structure_container_and_scalar_budgets_before_mapping() {
    let formats = [
        ("Clash", r#"{"proxies":[]}"#),
        ("sing-box", r#"{"outbounds":[]}"#),
        ("Xray", r#"{"outbounds":[{"protocol":"vless"}]}"#),
    ];
    let budgets = [
        (
            SubscriptionParseLimits {
                max_structure_depth: 0,
                ..Default::default()
            },
            "结构深度超过上限",
        ),
        (
            SubscriptionParseLimits {
                max_container_items: 0,
                ..Default::default()
            },
            "容器项数超过上限",
        ),
        (
            SubscriptionParseLimits {
                max_scalar_bytes: 0,
                ..Default::default()
            },
            "标量总量超过上限",
        ),
    ];
    for (format, text) in formats {
        for (limits, expected) in budgets {
            let mut id_gen = || "id".to_string();
            let error = parse_subscription_bundle_limited(
                text,
                "sub",
                "now",
                &mut id_gen,
                ImportOrigin::RemoteSubscription,
                limits,
            )
            .unwrap_err();
            assert!(
                error.contains(expected),
                "{format} JSON must reject {expected} before mapping; got {error}"
            );
        }
    }
}

#[test]
fn malformed_json_exhausting_depth_is_rejected_by_the_pre_ast_budget_scanner() {
    let mut id_gen = || "id".to_string();
    let error = parse_subscription_bundle_limited(
        r#"{"outbounds":[[["#,
        "sub",
        "now",
        &mut id_gen,
        ImportOrigin::RemoteSubscription,
        SubscriptionParseLimits {
            max_structure_depth: 1,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(
        error.contains("结构深度超过上限"),
        "the budget scanner must fail before serde reports malformed JSON: {error}"
    );
}

/// 供 fetch_tests 复用的 base64 编码。
pub(super) fn b64(s: &str) -> String {
    base64_encode(s)
}

#[test]
fn detect_clash_format() {
    let yaml = "proxies:\n  - name: x\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n";
    assert_eq!(detect_format(yaml), SubscriptionFormat::Clash);
    assert_eq!(
        detect_format("proxy-providers:\n  p:\n    url: x"),
        SubscriptionFormat::Clash
    );
}

// ── JSON 编码的 Clash 订阅（此前整类不可用：落 Unknown → 「暂不支持的订阅格式」）──────
//
// 变异验证：把 `detect_format` 的 `is_json_clash` 分支删掉 → 三条 detect 断言 + 解析断言全红；
// 把 `try_load_clash_doc` 的 JSON 分支删掉 → 解析断言红（serde_yaml 也能吃多数 JSON，但
// `json_clash_with_json_only_escape_parses` 这条专挑 YAML 1.1 不认的转义，必红）。

/// 一份最小 JSON 编码 Clash 订阅（两个 ss 节点）。
const JSON_CLASH: &str = r#"{"proxies":[
        {"name":"J-1","type":"ss","server":"1.2.3.4","port":8388,"cipher":"aes-256-gcm","password":"pw1"},
        {"name":"J-2","type":"ss","server":"5.6.7.8","port":8389,"cipher":"aes-256-gcm","password":"pw2"}
    ]}"#;

#[test]
fn detect_json_encoded_clash() {
    assert_eq!(detect_format(JSON_CLASH), SubscriptionFormat::Clash);
    // 只有 proxy-providers 的 JSON 形态同样算 Clash。
    assert_eq!(
        detect_format(r#"{"proxy-providers":{"p":{"type":"http","url":"https://e.com/p"}}}"#),
        SubscriptionFormat::Clash
    );
    // 结构不符不得误判（`proxies` 不是数组 / `proxy-providers` 不是对象）。
    assert_eq!(
        detect_format(r#"{"proxies":"not-an-array"}"#),
        SubscriptionFormat::Unknown
    );
    // sing-box JSON 仍走 sing-box 分支（分支顺序：outbounds 优先，对齐 上游）。
    assert_eq!(
        detect_format(r#"{"outbounds":[{"type":"vless","server":"a.com"}]}"#),
        SubscriptionFormat::SingboxJson
    );
}

#[test]
fn json_encoded_clash_parses_into_nodes() {
    let mut gen = {
        let mut n = 0u32;
        move || {
            n += 1;
            format!("id-{n}")
        }
    };
    let r = parse_subscription(
        JSON_CLASH,
        "sub-json",
        "2026-01-01T00:00:00Z",
        &mut gen,
        ImportOrigin::RemoteSubscription,
    );
    assert_eq!(
        r.servers.len(),
        2,
        "JSON 编码的 Clash 应解析出 2 个节点，实得 {} + warnings {:?}",
        r.servers.len(),
        r.warnings
    );
    assert_eq!(r.servers[0].name, "J-1");
    assert_eq!(r.servers[1].address, "5.6.7.8");
    assert_eq!(r.servers[0].subscription_id.as_deref(), Some("sub-json"));
}

#[test]
fn json_clash_with_json_only_escape_parses() {
    // `\/` 是合法 JSON 转义、**YAML 1.1（libyaml）不认** —— 这条钉死「必须走真 JSON 解析器」，
    // 而不是靠「YAML 是 JSON 超集」把正文直接喂给 serde_yaml。
    let text = r#"{"proxies":[{"name":"a\/b","type":"ss","server":"1.2.3.4","port":8388,"cipher":"aes-256-gcm","password":"pw"}]}"#;
    assert_eq!(detect_format(text), SubscriptionFormat::Clash);
    let mut gen = || "id-1".to_string();
    let r = parse_subscription(
        text,
        "s",
        "2026-01-01T00:00:00Z",
        &mut gen,
        ImportOrigin::RemoteSubscription,
    );
    assert_eq!(r.servers.len(), 1, "warnings: {:?}", r.warnings);
    assert_eq!(r.servers[0].name, "a/b");
}

#[test]
fn extract_proxy_providers_covers_json_encoding() {
    // 此前 `extract_proxy_providers` 单独判 `is_clash_probe`（YAML 行首探测）→ JSON 编码的
    // provider 一个都拉不到、节点全丢。改走 detect_format（单一真值）后两种编码同覆盖。
    let json = r#"{"proxy-providers":{"P1":{"type":"http","url":"https://e.com/p1"}}}"#;
    let got = extract_proxy_providers(json).expect("JSON 编码的 proxy-providers 必须被提取到");
    let map = got.as_mapping().expect("providers 应是 mapping");
    assert_eq!(map.len(), 1);
    assert_eq!(
        got.get("P1")
            .and_then(|p| p.get("url"))
            .and_then(serde_yaml::Value::as_str),
        Some("https://e.com/p1")
    );
    // YAML 编码不回归。
    assert!(extract_proxy_providers(
        "proxy-providers:\n  P1:\n    type: http\n    url: https://e.com/p1\n"
    )
    .is_some());
    // 非 Clash 正文仍返 None（不得把任意 JSON 当 Clash 拆）。
    assert!(extract_proxy_providers(r#"{"outbounds":[]}"#).is_none());
    assert!(extract_proxy_providers("vless://x@a.com:443#n").is_none());
}

#[test]
fn parsed_bundle_returns_inline_nodes_and_providers_from_one_document() {
    let text = r#"{
        "proxies":[{"name":"inline","type":"ss","server":"1.2.3.4","port":8388,"cipher":"aes-256-gcm","password":"pw"}],
        "proxy-providers":{"remote":{"type":"http","url":"https://provider.example/sub"}}
    }"#;
    let mut gen = || "id-1".to_string();
    let bundle = parse_subscription_bundle(
        text,
        "sub",
        "now",
        &mut gen,
        ImportOrigin::RemoteSubscription,
    );
    assert_eq!(bundle.parsed.servers.len(), 1);
    assert_eq!(bundle.parsed.servers[0].name, "inline");
    assert_eq!(
        bundle
            .proxy_providers
            .as_ref()
            .and_then(|v| v.get("remote"))
            .and_then(|v| v.get("url"))
            .and_then(serde_yaml::Value::as_str),
        Some("https://provider.example/sub")
    );
}

#[test]
fn detect_singbox_json_format() {
    let json = r#"{"outbounds":[{"type":"direct"}]}"#;
    assert_eq!(detect_format(json), SubscriptionFormat::SingboxJson);
    let json2 = r#"{"endpoints":[]}"#;
    assert_eq!(detect_format(json2), SubscriptionFormat::SingboxJson);
}

#[test]
fn detect_xray_json_format() {
    // outbound 有 protocol、无 type → xray（与 sing-box 区分）。
    let json = r#"{"outbounds":[{"protocol":"vless","settings":{}}]}"#;
    assert_eq!(detect_format(json), SubscriptionFormat::XrayJson);
    // 有 type 的同键 JSON 仍判 sing-box（不误判 xray）。
    let singbox = r#"{"outbounds":[{"type":"vless","server":"a.com"}]}"#;
    assert_eq!(detect_format(singbox), SubscriptionFormat::SingboxJson);
}

#[test]
fn parse_subscription_xray_yields_nodes() {
    let json = r#"{"outbounds":[
            {"protocol":"freedom"},
            {"protocol":"vless","tag":"n1","settings":{"vnext":[{"address":"a.com","port":443,"users":[{"id":"u1"}]}]},
             "streamSettings":{"network":"ws","security":"tls","wsSettings":{"path":"/p"}}}
        ]}"#;
    let mut n = 0;
    let mut id_gen = || {
        n += 1;
        format!("id-{n}")
    };
    let parsed = parse_subscription(
        json,
        "sub-x",
        "2026-07-18T00:00:00Z",
        &mut id_gen,
        ImportOrigin::RemoteSubscription,
    );
    assert_eq!(parsed.servers.len(), 1, "vless 入库、freedom 忽略");
    assert_eq!(parsed.servers[0].address, "a.com");
    assert_eq!(parsed.servers[0].network.as_deref(), Some("ws"));
    assert_eq!(
        parsed.servers[0].subscription_id.as_deref(),
        Some("sub-x"),
        "订阅路径挂 sub id"
    );
}

/// endpoints-only 的 sing-box 原生订阅（机场下发 WireGuard 组网）—— 此前恒 0 节点 + warning，
/// 现按 endpoint 建模映射入库。语料 `sing-box check` rc=0（随包核 1.14.0-beta.7）。
#[test]
fn parse_subscription_singbox_endpoints_only_yields_wireguard() {
    let json = r#"{"endpoints":[{
            "type":"wireguard","tag":"WG-HK","mtu":1408,
            "address":["172.16.0.2/32"],
            "private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEk=",
            "peers":[{"address":"wg.example.com","port":2408,
                      "public_key":"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                      "allowed_ips":["0.0.0.0/0","::/0"],
                      "persistent_keepalive_interval":25}]
        }]}"#;
    assert_eq!(detect_format(json), SubscriptionFormat::SingboxJson);
    let mut n = 0;
    let mut id_gen = || {
        n += 1;
        format!("id-{n}")
    };
    let r = parse_subscription(
        json,
        "sub-wg",
        "2026-07-18T00:00:00Z",
        &mut id_gen,
        ImportOrigin::RemoteSubscription,
    );
    assert_eq!(r.servers.len(), 1, "endpoints[] 不再被整份丢弃");
    assert_eq!((r.skipped, r.failed), (0, 0));
    let s = &r.servers[0];
    assert_eq!(s.protocol, Protocol::Wireguard);
    assert_eq!(s.name, "WG-HK");
    assert_eq!((s.address.as_str(), s.port), ("wg.example.com", 2408));
    assert_eq!(s.subscription_id.as_deref(), Some("sub-wg"));
    let wg = s.wireguard_settings.as_ref().unwrap();
    assert_eq!(wg.allow_internet, Some(true));
    assert!(wg.allowed_ips.is_empty(), "catch-all 全抽进 allowInternet");
}

/// `outbounds[]` + `endpoints[]` 同时在场：两条腿的结果合并，不互相吞。
#[test]
fn parse_subscription_singbox_merges_outbounds_and_endpoints() {
    let json = r#"{
          "outbounds":[
            {"type":"direct","tag":"direct"},
            {"type":"trojan","tag":"T","server":"t.example.com","server_port":443,"password":"p"}
          ],
          "endpoints":[
            {"type":"wireguard","tag":"WG","address":["10.0.0.2/32"],"private_key":"pk",
             "peers":[{"address":"1.2.3.4","port":51820,"public_key":"pub","allowed_ips":["10.0.0.0/24"]}]},
            {"type":"tailscale","tag":"TS","auth_key":"tskey-auth-SECRET"}
          ]
        }"#;
    let mut n = 0;
    let mut id_gen = || {
        n += 1;
        format!("id-{n}")
    };
    let r = parse_subscription(
        json,
        "sub-mix",
        "2026-07-18T00:00:00Z",
        &mut id_gen,
        ImportOrigin::RemoteSubscription,
    );
    let protos: Vec<Protocol> = r.servers.iter().map(|s| s.protocol).collect();
    assert_eq!(
        protos,
        vec![Protocol::Trojan, Protocol::Wireguard],
        "outbounds 的节点在前、endpoints 的在后；direct 忽略、tailscale 跳过"
    );
    assert_eq!(r.skipped, 1, "tailscale endpoint");
    assert_eq!(r.failed, 0);
    assert!(r.warnings.iter().any(|w| w.contains("tailscale endpoint")));
}

#[test]
fn detect_url_list_format() {
    assert_eq!(
        detect_format("vless://uuid@host:443\nss://..."),
        SubscriptionFormat::UrlList
    );
}

#[test]
fn detect_base64_format() {
    // "vless://..." 的 base64
    let b64 = base64_encode("vless://abc@host:443#name");
    assert_eq!(detect_format(&b64), SubscriptionFormat::Base64);
}

#[test]
fn detect_unknown_format() {
    assert_eq!(
        detect_format("just some random text"),
        SubscriptionFormat::Unknown
    );
    assert_eq!(detect_format(""), SubscriptionFormat::Unknown);
}

#[test]
fn parse_clash_subscription_full() {
    let yaml = "proxies:\n  - name: x\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n    cipher: aes-256-gcm\n    password: pw\n";
    let mut counter = 0u32;
    let mut id_gen = || {
        counter += 1;
        format!("id-{counter}")
    };
    let r = parse_subscription(
        yaml,
        "sub-1",
        "2024-01-01",
        &mut id_gen,
        ImportOrigin::RemoteSubscription,
    );
    assert_eq!(r.servers.len(), 1);
    assert_eq!(r.servers[0].name, "x");
}

#[test]
fn parse_unknown_format_warns() {
    let mut id_gen = || "id".to_string();
    let r = parse_subscription(
        "random",
        "sub-1",
        "now",
        &mut id_gen,
        ImportOrigin::RemoteSubscription,
    );
    assert!(r.servers.is_empty());
    assert!(r.warnings.iter().any(|w| w.contains("暂不支持")));
}

#[test]
fn parse_invalid_clash_yaml_warns() {
    let mut id_gen = || "id".to_string();
    let r = parse_subscription(
        "proxies: [bad",
        "sub-1",
        "now",
        &mut id_gen,
        ImportOrigin::RemoteSubscription,
    );
    assert!(r.servers.is_empty());
    assert!(r.warnings[0].contains("Clash YAML 解析失败"));
}

#[test]
fn base64_roundtrip() {
    let orig = "vless://abc@example.com:443#节点";
    let encoded = base64_encode(orig);
    assert_eq!(base64_decode(&encoded).unwrap(), orig);
}

#[test]
fn base64_url_safe() {
    // 含 +/ → 转成 -_ 的 URL-safe 形式也应可解码
    let orig = "ss://aes-256-gcm:pass@host:8388";
    let std = base64_encode(orig);
    let urlsafe: String = std
        .chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            _ => c,
        })
        .collect();
    assert_eq!(base64_decode(&urlsafe).unwrap(), orig);
}

/// 测试用 base64 编码（标准字母表）。
fn base64_encode(input: &str) -> String {
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
        if chunk.len() > 1 {
            out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(n & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

// ── issue #1「不支持HTTP协议么?」：正文预处理与格式嗅探的回归门 ───────────────────
//
// 端到端确认报告：`~/docs/polaris/fixes/polaris-http-proxy-import-audit-2026-09-02.md`。
// 报告 §⑤ 指出旧测试面对「base64 / url-list 正文里含 http 节点」的端到端覆盖是**零**——
// 钉住的只是「http 这个 match 分支存在且默认端口对」，钉不住「用户那份正文里的 http 节点会不会
// 到达 UI」。以下用例补的正是那条端到端腿，且逐条锁「整份订阅 0 节点 / 首节点静默丢」的事故形态。

/// 三个 HTTP 系节点（带认证 / TLS / 无认证），覆盖 issue 里报告人的形态。
const HTTP_URL_LIST: &str = "http://alice:secret@1.2.3.4:8080#HTTP-A\n\
https://bob:pw@b.example.com:443#HTTPS-B\n\
http://3.3.3.3:3128#HTTP-NOAUTH";

/// 走生产入口解析一份订阅正文（不带 limits，与 `parse_subscription` 的默认路径同）。
fn parse_body(text: &str) -> ClashParseResult {
    let mut n = 0u32;
    let mut gen = move || {
        n += 1;
        format!("id-{n}")
    };
    parse_subscription(
        text,
        "sub-http",
        "2026-09-02T00:00:00Z",
        &mut gen,
        ImportOrigin::RemoteSubscription,
    )
}

/// 三个节点全在、且协议都是 http（https 系也归 `Protocol::Http`，靠 security 区分）。
fn assert_three_http_nodes(r: &ClashParseResult, ctx: &str) {
    assert_eq!(
        r.servers.len(),
        3,
        "{ctx}：三个 HTTP 节点应全部到达，实得 {} 个 / failed={} / warnings={:?}",
        r.servers.len(),
        r.failed,
        r.warnings
    );
    assert!(
        r.servers.iter().all(|s| s.protocol == Protocol::Http),
        "{ctx}：协议须全为 Http"
    );
    assert_eq!(r.servers[0].name, "HTTP-A", "{ctx}：首节点不得丢");
    assert_eq!(r.servers[0].username.as_deref(), Some("alice"));
    assert_eq!(
        r.servers[1].security,
        Some(SecurityMode::Tls),
        "{ctx}：HTTPS 节点走 TLS"
    );
    assert_eq!(r.servers[2].port, 3128, "{ctx}：无认证节点");
}

/// 基线：无 BOM 的明文 url-list 与 base64 正文，HTTP 节点端到端到达（此前测试面为零）。
#[test]
fn http_nodes_reach_the_end_of_url_list_and_base64_legs() {
    assert_eq!(detect_format(HTTP_URL_LIST), SubscriptionFormat::UrlList);
    assert_three_http_nodes(&parse_body(HTTP_URL_LIST), "明文 url-list");

    let b64 = base64_encode(HTTP_URL_LIST);
    assert_eq!(detect_format(&b64), SubscriptionFormat::Base64);
    assert_three_http_nodes(&parse_body(&b64), "base64 正文");
}

/// 缺口⑥-a：BOM + base64 ⇒ **整份订阅 0 节点**。
///
/// U+FEFF 不属于 `White_Space`，既有的 `trim` / `trim_start` 吃不掉它；它落在 base64 字母表外
/// 使解码失败 → `detect_format` 一路落到 `Unknown` → 「暂不支持的订阅格式」+ 0 节点。
/// 剥 BOM 必须发生在**格式嗅探之前**。
#[test]
fn bom_before_base64_body_still_detects_and_parses() {
    let body = format!("\u{feff}{}", base64_encode(HTTP_URL_LIST));
    assert_eq!(
        detect_format(&body),
        SubscriptionFormat::Base64,
        "BOM 不得让 base64 正文判成 Unknown"
    );
    assert_three_http_nodes(&parse_body(&body), "BOM + base64");
}

/// 缺口⑥-a'（同根因第二条路径）：BOM 被**包在 base64 里面**——外层正文干净、解码产物首行带 BOM，
/// 于是首节点照旧在 `parse_url_list` 里静默丢。剥 BOM 必须在**每一处把文本交给逐行解析器之前**。
#[test]
fn bom_inside_the_base64_payload_keeps_the_first_node() {
    let body = base64_encode(&format!("\u{feff}{HTTP_URL_LIST}"));
    assert_eq!(detect_format(&body), SubscriptionFormat::Base64);
    assert_three_http_nodes(&parse_body(&body), "base64 内层 BOM");
}

/// 缺口⑥-b：BOM + 明文列表 ⇒ **首节点静默丢**（`line.trim()` 同样不去 U+FEFF ⇒ 首行的
/// scheme 前缀匹配失败 ⇒ `parse_url_list` 直接 `continue`，failed 不加、warning 不 push）。
#[test]
fn bom_before_plain_url_list_keeps_the_first_node() {
    let body = format!("\u{feff}{HTTP_URL_LIST}");
    assert_eq!(detect_format(&body), SubscriptionFormat::UrlList);
    assert_three_http_nodes(&parse_body(&body), "BOM + 明文列表");
}

/// 缺口⑥-c：首行不是链接 ⇒ **整份订阅 0 节点**。
///
/// 根因是嗅探判据只看首行（`t.lines().next()` 是否含 `://`）：机场把「剩余流量 / 到期时间」
/// 之类公告文本放在正文第一行时，整份落 `Unknown`。判据改为全文扫描 + 前缀锚定匹配。
#[test]
fn announcement_first_line_does_not_kill_the_whole_body() {
    let body = format!("剩余流量：100 GB\n到期时间：2026-12-31\n\n{HTTP_URL_LIST}");
    assert_eq!(
        detect_format(&body),
        SubscriptionFormat::UrlList,
        "正文里有分享链接行就不该判 Unknown"
    );
    assert_three_http_nodes(&parse_body(&body), "首行公告文本");
}

/// 前缀锚定不得放宽：正文里只是内嵌了带 `://` 的**值**（YAML/JSON 的 url 字段、纯说明文字），
/// 不构成 url-list —— 否则会把一份解析不了的正文伪装成「格式已识别、0 节点」而吞掉告警。
#[test]
fn embedded_url_values_do_not_masquerade_as_url_list() {
    for body in [
        "公告：详情见 https://example.com/notice 页面",
        "name: x\n  url: https://example.com/sub\n",
    ] {
        assert_eq!(
            detect_format(body),
            SubscriptionFormat::Unknown,
            "{body:?} 里的 URL 是值不是节点行"
        );
    }
}

/// 缺口①的端到端腿：大写 scheme 行此前在订阅里**零告警静默跳过**（servers=0 / failed=0 /
/// warnings=[]），用户只看到「导入 0 个」而无任何线索。
#[test]
fn uppercase_scheme_line_is_no_longer_silently_dropped() {
    let r = parse_body("HTTP://alice:secret@1.2.3.4:8080#UP\nHttps://bob:pw@b.example.com#UP2");
    assert_eq!(
        r.servers.len(),
        2,
        "大写 scheme 行应正常导入，实得 {} / failed={} / warnings={:?}",
        r.servers.len(),
        r.failed,
        r.warnings
    );
    assert!(r.servers.iter().all(|s| s.protocol == Protocol::Http));
    assert_eq!(r.servers[1].security, Some(SecurityMode::Tls));
}

/// 缺口⑤的端到端腿：Xray JSON 的 `protocol: "http"` 此前整体跳过（0 节点 + 「跳过 1 个不支持
/// 的 Xray 协议: http(1)」），而同一批节点换成 sing-box JSON 全收——这正是报告人「换成
/// sing-box 1.14 格式就全识别了」那句话对应的差集。
#[test]
fn xray_json_http_outbound_reaches_the_end() {
    let body = r#"{"outbounds":[
        {"protocol":"http","tag":"X-HTTP","settings":{"servers":[
            {"address":"x.example.com","port":8080,"users":[{"user":"alice","pass":"secret"}]}]}},
        {"protocol":"freedom","tag":"direct"}
    ]}"#;
    assert_eq!(detect_format(body), SubscriptionFormat::XrayJson);
    let r = parse_body(body);
    assert_eq!(
        r.servers.len(),
        1,
        "xray http outbound 应入库，warnings={:?}",
        r.warnings
    );
    assert_eq!(r.servers[0].protocol, Protocol::Http);
    assert_eq!(r.servers[0].username.as_deref(), Some("alice"));
    assert_eq!(r.skipped, 0, "不得再报「跳过不支持的 Xray 协议: http」");
}

/// 缺口⑤的姊妹腿：Xray JSON 的 `protocol: "socks"` 与 `http` 完全同类——Clash / sing-box /
/// 分享链接三条腿都收 socks，只有 xray 腿把它当不支持整体跳过。凭据与匿名两种形态都走端到端。
#[test]
fn xray_json_socks_outbound_reaches_the_end() {
    let body = r#"{"outbounds":[
        {"protocol":"socks","tag":"X-SOCKS","settings":{"servers":[
            {"address":"s.example.com","port":1080,"users":[{"user":"alice","pass":"secret"}]}]}},
        {"protocol":"socks","tag":"X-SOCKS-ANON","settings":{"servers":[
            {"address":"t.example.com","port":1081}]}},
        {"protocol":"freedom","tag":"direct"}
    ]}"#;
    assert_eq!(detect_format(body), SubscriptionFormat::XrayJson);
    let r = parse_body(body);
    assert_eq!(
        r.servers.len(),
        2,
        "两个 xray socks outbound 都应入库，warnings={:?}",
        r.warnings
    );
    assert!(r.servers.iter().all(|s| s.protocol == Protocol::Socks));
    assert_eq!(r.servers[0].name, "X-SOCKS");
    assert_eq!(
        (
            r.servers[0].username.as_deref(),
            r.servers[0].password.as_deref()
        ),
        (Some("alice"), Some("secret"))
    );
    assert_eq!(
        (
            r.servers[1].username.as_deref(),
            r.servers[1].password.as_deref()
        ),
        (None, None),
        "匿名 socks 不得被拒"
    );
    assert_eq!(r.skipped, 0, "不得再报「跳过不支持的 Xray 协议: socks」");
    assert_eq!(r.failed, 0);
}

// ── 剥 BOM 的另外两条腿：Clash 文档与 sing-box JSON ──────────────────────────────
//
// `parse_subscription_bundle_inner` 的剥 BOM 注释声称「base64 / url-list / JSON / YAML 四条腿
// 一起受益」，但此前只有 base64（⑥-a / ⑥-a'）与 url-list（⑥-b）两条有门，另外两条只有注释。
// 以下三条把那句话兑现成门：BOM 落在正文最前面时，Clash 的两种编码与 sing-box JSON 都须端到端
// 出节点。**两处剥离点各守哪几条腿，是逐条变异量出来的**：摘掉
// `parse_subscription_bundle_inner` 那次，只有 base64 / url-list / sing-box JSON 三条转红；
// Clash 的两种编码都不动——libyaml 在编码探测阶段自己吞掉 BOM。Clash 腿真正的保护点是
// `detect_format` 那次剥离（摘掉它，本节全部转红：`is_clash_probe` 的行首匹配吃不掉 U+FEFF）。

/// BOM + Clash YAML：BOM 打掉的是嗅探（`is_clash_probe` 看行首）——没剥就整份落 `Unknown` + 0 节点。
#[test]
fn bom_before_clash_yaml_body_still_imports_nodes() {
    let body = "\u{feff}proxies:\n  - {name: CLASH-A, type: http, server: 1.2.3.4, port: 8080, username: alice, password: secret}\n";
    assert_eq!(
        detect_format(body),
        SubscriptionFormat::Clash,
        "BOM 不得让 Clash YAML 正文判成 Unknown"
    );
    let r = parse_body(body);
    assert_eq!(
        r.servers.len(),
        1,
        "BOM + Clash YAML：节点应到达，failed={} / warnings={:?}",
        r.failed,
        r.warnings
    );
    assert_eq!(r.servers[0].name, "CLASH-A");
    assert_eq!(r.servers[0].protocol, Protocol::Http);
    assert_eq!(r.servers[0].username.as_deref(), Some("alice"));
}

/// BOM + **JSON 编码**的 Clash：与 YAML 编码同格式、不同解析器，两种编码都得端到端出节点。
///
/// 保护点与 YAML 编码同样是 [`detect_format`] 的剥 BOM。`parse_subscription_bundle_inner` 那次
/// 对本腿是**冗余**的（实测：摘掉它本用例不红）——BOM 让 `t.starts_with('{')` 与
/// `try_load_clash_doc` 的同款首字符探针双双落空（`trim_start` 不去 U+FEFF），正文改喂 libyaml，
/// 而 libyaml 连 BOM 带 `\/` 都吃得下、产出与 JSON 分支一致。故本用例守的是「节点到达」，
/// 不声称「走了哪条分支」。
#[test]
fn bom_before_json_encoded_clash_body_still_imports_nodes() {
    let body = "\u{feff}{\"proxies\":[{\"name\":\"a\\/b\",\"type\":\"http\",\"server\":\"1.2.3.4\",\"port\":8080,\"username\":\"alice\",\"password\":\"secret\"}]}";
    assert_eq!(
        detect_format(body),
        SubscriptionFormat::Clash,
        "BOM 不得让 JSON 编码的 Clash 正文判错格式"
    );
    let r = parse_body(body);
    assert_eq!(
        r.servers.len(),
        1,
        "BOM + JSON 编码 Clash：节点应到达，failed={} / warnings={:?}",
        r.failed,
        r.warnings
    );
    assert_eq!(r.servers[0].name, "a/b", "`\\/` 须被解成 `/`");
    assert_eq!(r.servers[0].protocol, Protocol::Http);
    assert_eq!(r.servers[0].username.as_deref(), Some("alice"));
}

/// BOM + sing-box JSON：`serde_json` 不接受前置 BOM（不像 libyaml 会在编码探测阶段吞掉它），
/// 未剥就是「sing-box JSON 解析失败」+ 0 节点。
#[test]
fn bom_before_singbox_json_body_still_imports_nodes() {
    let body = "\u{feff}{\"outbounds\":[{\"type\":\"http\",\"tag\":\"SB-A\",\"server\":\"1.2.3.4\",\"server_port\":8080,\"username\":\"alice\",\"password\":\"secret\"}]}";
    assert_eq!(
        detect_format(body),
        SubscriptionFormat::SingboxJson,
        "BOM 不得让 sing-box JSON 正文判错格式"
    );
    let r = parse_body(body);
    assert_eq!(
        r.servers.len(),
        1,
        "BOM + sing-box JSON：节点应到达，failed={} / warnings={:?}",
        r.failed,
        r.warnings
    );
    assert_eq!(r.servers[0].name, "SB-A");
    assert_eq!(r.servers[0].protocol, Protocol::Http);
    assert_eq!(r.servers[0].username.as_deref(), Some("alice"));
}

// ── 全文扫描的收紧面：夹带的裸 URL 不得变成静默假节点 ───────────────────────────
//
// 缺口⑥-b 把 url-list 嗅探从「只看首行」改成「全文扫描」后引入的退化（review 指出，本次一并收口）：
// 非订阅正文里只要有一行独立 URL 就判 `UrlList`，那行会被当成 HTTPS 代理节点**静默**导入。
// 收紧发生在 `share_link::parse_http`（判据与理由见其单测），这里锁端到端的可见性。

/// 机场对失效订阅返回的纯文本：旧行为是 `Unknown` + 「暂不支持的订阅格式」（可见失败），
/// 全文扫描一度让它变成 servers=1 / failed=0 / warnings=[]（**静默失败 + 一个连不通的假节点**）。
/// 现在回到可见失败：那行计 failed 并带出点明原因的告警，节点数仍是 0。
#[test]
fn expired_subscription_notice_yields_a_visible_failure_not_a_fake_node() {
    let body = "订阅已过期\nhttps://sub.example.com/renew\n请续费";
    let r = parse_body(body);
    assert_eq!(
        r.servers.len(),
        0,
        "夹带的订阅链接不得变成节点，实得 {:?}",
        r.servers.iter().map(|s| &s.name).collect::<Vec<_>>()
    );
    assert_eq!(r.failed, 1, "那行须计 failed，不得静默跳过");
    assert!(
        r.warnings.iter().any(|w| w.contains("疑似订阅链接")),
        "须带出点明原因的告警，实得 {:?}",
        r.warnings
    );
    // 告警不得回显整条 URL：订阅链接的 path/query 常含 token。
    assert!(
        !r.warnings.iter().any(|w| w.contains("/renew")),
        "告警不得回显 path（可能含 token），实得 {:?}",
        r.warnings
    );
}

/// 混合正文（真节点 + 夹带一行裸订阅 URL）——**期望行为：真节点全进，夹带那行计 failed + 告警**。
///
/// 为什么不是「整份判 Unknown」：真节点是用户要的东西，不能被一行垃圾连坐（逐行 try/catch 的
/// 容错分层本就是为此存在）。
/// 为什么不是「静默跳过那行」：可见失败优于静默失败——这是本次修复的主旨，静默跳过正是缺口①的病根。
/// 为什么不是「照旧导入成节点」：它连不通，且 `failed=0` 会让用户以为一切正常，比报错更难排查。
#[test]
fn mixed_body_keeps_real_nodes_and_reports_the_stray_url() {
    let body = "http://alice:secret@1.2.3.4:8080#HTTP-A\n\
https://sub.example.com/renew\n\
https://bob:pw@b.example.com:443#HTTPS-B";
    let r = parse_body(body);
    assert_eq!(detect_format(body), SubscriptionFormat::UrlList);
    assert_eq!(
        r.servers.len(),
        2,
        "两个真节点必须全进，实得 {:?}",
        r.servers.iter().map(|s| &s.name).collect::<Vec<_>>()
    );
    assert_eq!(r.servers[0].name, "HTTP-A");
    assert_eq!(r.servers[1].name, "HTTPS-B");
    assert_eq!(r.failed, 1, "夹带的订阅链接计 failed");
    assert!(
        r.warnings.iter().any(|w| w.contains("疑似订阅链接")),
        "实得 {:?}",
        r.warnings
    );
}
