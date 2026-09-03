use super::*;
use crate::redact::{collect_custom_secret_keys, collect_node_identifiers, redact_deep};
use serde_json::json;

fn input() -> DiagnosticReportInput {
    DiagnosticReportInput {
        generated_at: "2026-07-16T10:00:00.000Z".into(),
        app: AppSection {
            polaris_version: "0.1.0".into(),
            core_version: "1.14.0".into(),
            os: "linux x86_64 6.8.0".into(),
        },
        runtime: RuntimeSection {
            proxy_mode: "rule".into(),
            proxy_mode_type: "tun".into(),
            proxy_running: true,
            log_level: "info".into(),
            ..Default::default()
        },
        redacted_user_config: json!({ "proxyMode": "rule" }),
        redacted_singbox_config: json!({ "log": { "level": "info" } }),
        app_log_tail: "app started".into(),
        singbox_log_tail: "core started".into(),
        ..Default::default()
    }
}

#[test]
fn 报告含全部固定段() {
    let md = build_diagnostic_report(&input());
    for h in [
        "# Polaris 诊断报告",
        "## 环境",
        "## 运行态",
        "## 生成的 sing-box 配置（脱敏）",
        "## 用户配置（脱敏）",
        "## app.log（近期）",
        "## singbox.log（近期）",
    ] {
        assert!(md.contains(h), "缺段 {h}");
    }
}

#[test]
fn 报告头声明脱敏() {
    let md = build_diagnostic_report(&input());
    assert!(md.contains("**密钥与节点身份已脱敏**"));
    assert!(
        md.contains("可自行删减后再上传"),
        "访问活动未打码 → 必须在报告头如实声明"
    );
}

#[test]
fn 可选行取不到就不渲染() {
    let md = build_diagnostic_report(&input());
    assert!(!md.contains("Helper 状态"));
    assert!(!md.contains("系统代理实际值"));
    assert!(!md.contains("节点域名解析档位"));
}

#[test]
fn 可选行有值则渲染() {
    let mut i = input();
    i.runtime.helper_status = Some("installed".into());
    i.runtime.system_proxy = Some("127.0.0.1:7890".into());
    i.runtime.effective_dns = Some("223.5.5.5".into());
    i.runtime.node_domain_resolver = Some("auto".into());
    i.runtime.started_via_helper = Some(true);
    let md = build_diagnostic_report(&i);
    assert!(md.contains("- Helper 状态：installed"));
    assert!(md.contains("- 系统代理实际值：127.0.0.1:7890"));
    assert!(md.contains("- 生效系统 DNS：223.5.5.5"));
    assert!(md.contains("- 节点域名解析档位：auto"));
    assert!(md.contains("- 经提权 helper 启动：是"));
}

#[test]
fn hint_有值才渲染() {
    assert!(!build_diagnostic_report(&input()).contains("> 提示："));
    let mut i = input();
    i.hint = Some("建议把日志级别切到 DEBUG".into());
    assert!(build_diagnostic_report(&i).contains("> 提示：建议把日志级别切到 DEBUG"));
}

// ── DiagnosticCounters 接线（维度7 #11 两轴分离）──

#[test]
fn 两轴皆零时两行都不渲染() {
    let md = build_diagnostic_report(&input());
    assert!(!md.contains("就绪重试"));
    assert!(!md.contains("核崩溃自动重启"));
}

#[test]
fn 慢起轴单独成行且明说非核崩() {
    let mut i = input();
    let mut c = DiagnosticCounters::new();
    let mut a = c.begin_start();
    a.record_retry();
    a.record_retry();
    c.finish_start(&a);
    i.runtime.counters = c;
    let md = build_diagnostic_report(&i);
    assert!(md.contains("最近一次起核经 2 次就绪重试才成功"));
    assert!(
        md.contains("非核崩溃"),
        "慢起必须明说非核崩，否则诊断者会误判"
    );
    assert!(!md.contains("核崩溃自动重启"), "慢起不该渲染核崩行");
}

#[test]
fn 核崩轴单独成行() {
    let mut i = input();
    let mut c = DiagnosticCounters::new();
    c.record_restart(1_000);
    c.record_restart(2_000);
    i.runtime.counters = c;
    let md = build_diagnostic_report(&i);
    assert!(md.contains("核崩溃自动重启：2 次"));
    assert!(!md.contains("就绪重试"), "核崩不该渲染慢起行");
}

#[test]
fn 两轴同时非零各自成行() {
    let mut i = input();
    let mut c = DiagnosticCounters::new();
    let mut a = c.begin_start();
    a.record_retry();
    c.finish_start(&a);
    c.record_restart(1_000);
    i.runtime.counters = c;
    let md = build_diagnostic_report(&i);
    assert!(md.contains("最近一次起核经 1 次就绪重试才成功"));
    assert!(md.contains("核崩溃自动重启：1 次"));
}

// ── 动态围栏 ──

#[test]
fn 围栏_普通内容用三反引号() {
    assert_eq!(fence("text", "hello"), "```text\nhello\n```");
}

#[test]
fn 围栏_空内容占位() {
    assert_eq!(fence("text", ""), "```text\n(空)\n```");
}

#[test]
fn 围栏_内容含三反引号则用四个() {
    assert_eq!(fence("text", "a ``` b"), "````text\na ``` b\n````");
}

#[test]
fn 围栏_内容含更长反引号串则更长() {
    assert_eq!(fence("text", "`````"), "``````text\n`````\n``````");
}

#[test]
fn 围栏_机场可控内容不得截断报告结构() {
    // 节点名/日志是外部可控输入：塞 ``` 不得提前闭合代码块把后续段甩出去
    let mut i = input();
    i.app_log_tail = "evil ``` \n## 伪造标题\n".into();
    let md = build_diagnostic_report(&i);
    assert!(md.contains("````text"), "含 ``` 的日志必须用更长围栏");
    // singbox.log 段仍在围栏外的正常位置（结构没被撑坏）
    assert!(md.contains("## singbox.log（近期）"));
}

// ── 节点标识符统一替换（末尾 pass）──

#[test]
fn 末尾统一打码_配置段与日志段占位一致() {
    let mut i = input();
    i.redacted_user_config = json!({ "servers": [{ "address": "n.example.com" }] });
    i.app_log_tail = "lookup n.example.com SERVFAIL".into();
    i.node_identifiers = vec![NodeIdentifier {
        value: "n.example.com".into(),
        placeholder: "<domain-1>".into(),
    }];
    let md = build_diagnostic_report(&i);
    assert!(
        !md.contains("n.example.com"),
        "节点域名不得在报告任何位置留明文"
    );
    assert_eq!(
        md.matches("<domain-1>").count(),
        2,
        "配置段 + 日志段各一处，跨段可关联"
    );
}

// ── 端到端红线 ──

#[test]
fn 红线_端到端_报告不含任何明文密钥() {
    let user_config = json!({
        "proxyMode": "rule",
        "clashApiSecret": "CLASH_SECRET_X",
        "privacyPassword": "PRIVACY_X",
        "selectedServerId": "s1",
        "servers": [
            { "id": "s1", "name": "东京节点甲", "address": "tokyo.example.com", "protocol": "vless",
              "uuid": "UUID_SECRET_X", "tlsSettings": { "serverName": "cdn.example.com" } },
            { "id": "s2", "name": "WG 节点乙", "protocol": "wireguard", "address": "1.2.3.4",
              "wireguardSettings": { "privateKey": "WG_PRIV_X", "preSharedKey": "WG_PSK_X",
                                      "warpDevice": { "deviceId": "d1", "token": "WARP_TOK_X" } } },
            { "id": "s3", "name": "TS 节点丙", "protocol": "tailscale",
              "tailscaleSettings": { "authKey": "TS_AUTH_X", "hostname": "ts-host-name" } },
            { "id": "s4", "name": "自定义节点丁", "protocol": "custom",
              "customSettings": { "secretKeys": ["myToken"],
                                  "outbound": { "type": "snell", "server": "custom.example.com", "myToken": "CUSTOM_X", "psk": "PSK_X" } } },
        ],
        "subscriptions": [{ "id": "sub1", "url": "https://air.example.com/link/SUBTOK_X?flag=clash" }],
    });
    let singbox_config = json!({
        "outbounds": [
            { "tag": "s1", "type": "vless", "server": "tokyo.example.com", "uuid": "UUID_SECRET_X" },
            { "tag": "s4", "type": "snell", "server": "custom.example.com", "myToken": "CUSTOM_X", "psk": "PSK_X" },
        ],
        "experimental": { "clash_api": { "secret": "CLASH_SECRET_X" } },
    });

    let extra = collect_custom_secret_keys(&user_config);
    let i = DiagnosticReportInput {
        generated_at: "2026-07-16T10:00:00.000Z".into(),
        app: AppSection {
            polaris_version: "0.1.0".into(),
            core_version: "1.14.0".into(),
            os: "linux".into(),
        },
        runtime: RuntimeSection {
            proxy_mode: "rule".into(),
            proxy_mode_type: "tun".into(),
            proxy_running: true,
            log_level: "info".into(),
            ..Default::default()
        },
        redacted_user_config: redact_deep(&user_config, &extra),
        redacted_singbox_config: redact_deep(&singbox_config, &extra),
        app_log_tail:
            "dial tokyo.example.com ok\nTLS to cdn.example.com\n东京节点甲 up\nts-host-name joined"
                .into(),
        singbox_log_tail: "lookup custom.example.com SERVFAIL\npeer 1.2.3.4 handshake".into(),
        node_identifiers: collect_node_identifiers(&user_config, &[]),
        hint: None,
    };
    let md = build_diagnostic_report(&i);

    // 密钥类：一条都不许出现
    for secret in [
        "UUID_SECRET_X",
        "WG_PRIV_X",
        "WG_PSK_X",
        "WARP_TOK_X",
        "TS_AUTH_X",
        "CUSTOM_X",
        "PSK_X",
        "CLASH_SECRET_X",
        "PRIVACY_X",
        "SUBTOK_X",
    ] {
        assert!(
            !md.contains(secret),
            "红线破：报告含明文密钥 {secret:?}\n{md}"
        );
    }
    // 节点身份类：一条都不许出现
    for ident in [
        "tokyo.example.com",
        "cdn.example.com",
        "custom.example.com",
        "东京节点甲",
        "WG 节点乙",
        "TS 节点丙",
        "自定义节点丁",
        "ts-host-name",
    ] {
        assert!(
            !md.contains(ident),
            "红线破：报告含明文节点身份 {ident:?}\n{md}"
        );
    }
    // 反面：诊断信号必须还在（打码不能把报告打成废纸）
    assert!(md.contains("<domain-1>"), "域名占位符应在");
    assert!(md.contains("<node-1>"), "节点名占位符应在");
    assert!(md.contains("\"type\": \"vless\""), "协议形态应保留");
    assert!(md.contains("SERVFAIL"), "日志错误信号应保留");
}

// ════════════════════════════════════════════════════════════════════
// 组合面的门（§K7.1）：测「原始 UserConfig → 报告」这条**唯一生产路径**。
//
// 「redact 有门 + build 有门」≠「两者的组合有门」。命令层实际调用的是
// assemble_diagnostic_report，故门必须开在它上面，喂**原始未脱敏** config。
// ════════════════════════════════════════════════════════════════════

/// 一份「什么都有」的真实形态 UserConfig：8 节点覆盖全部协议族与全部密钥承载位。
fn 全协议族_原始配置() -> Value {
    json!({
        "proxyMode": "rule",
        "proxyModeType": "tun",
        "logLevel": "info",
        "selectedServerId": "n1",
        "clashApiSecret": "LEAK_CLASH_SECRET",
        "privacyPassword": "LEAK_PRIVACY_PW",
        "servers": [
            { "id": "n1", "name": "东京 VLESS 甲", "address": "tokyo.air.example.com", "port": 443,
              "protocol": "vless", "uuid": "LEAK_VLESS_UUID",
              "tlsSettings": { "serverName": "sni-a.example.com", "fingerprint": "chrome",
                               "realitySettings": { "publicKey": "KEEP_REALITY_PUB", "shortId": "ab12" } },
              "wsSettings": { "path": "/ws", "headers": { "Host": "ws-a.example.com" } } },
            { "id": "n2", "name": "大阪 Trojan 乙", "address": "osaka.air.example.com",
              "protocol": "trojan", "password": "LEAK_TROJAN_PW" },
            { "id": "n3", "name": "首尔 SS 丙", "address": "seoul.air.example.com",
              "protocol": "shadowsocks", "password": "LEAK_SS_PW", "method": "aes-256-gcm",
              "plugin_opts": "obfs=http;password=LEAK_PLUGIN_PW" },
            { "id": "n4", "name": "新加坡 Hy2 丁", "address": "sg.air.example.com",
              "protocol": "hysteria2", "password": "LEAK_HY2_PW" },
            { "id": "n5", "name": "WARP 组网戊", "address": "162.159.192.1",
              "protocol": "wireguard",
              "wireguardSettings": { "privateKey": "LEAK_WG_PRIV", "preSharedKey": "LEAK_WG_PSK",
                                     "peerPublicKey": "KEEP_PEER_PUB",
                                     "warpDevice": { "deviceId": "KEEP_DEV_ID", "token": "LEAK_WARP_TOKEN" } } },
            { "id": "n6", "name": "Tailscale 组网己", "protocol": "tailscale",
              "tailscaleSettings": { "authKey": "LEAK_TS_AUTHKEY", "hostname": "ts-host-alpha",
                                      "exitNode": "exit-beta.ts.net",
                                      "controlUrl": "https://controlplane.tailscale.com" } },
            { "id": "n7", "name": "SSH 隧道庚", "address": "ssh.example.com", "protocol": "ssh",
              "sshSettings": { "username": "KEEP_USER", "password": "LEAK_SSH_PW",
                               "privateKey": "LEAK_SSH_PRIV", "privateKeyPassphrase": "LEAK_SSH_PASS",
                               "privateKeyPath": "/home/u/.ssh/id_rsa" } },
            { "id": "n8", "name": "Snell 自定义辛", "protocol": "custom",
              "customSettings": { "secretKeys": ["myVendorToken"],
                                  "outbound": { "type": "snell", "server": "snell.example.com",
                                                "psk": "LEAK_SNELL_PSK", "myVendorToken": "LEAK_VENDOR_TOK",
                                                "tls": { "server_name": "nested-sni.example.com" } } } },
            { "id": "n9", "name": "订阅节点壬", "address": "sub-node.air.example.com",
              "protocol": "vmess", "uuid": "LEAK_VMESS_UUID", "subscriptionId": "sub1" },
        ],
        "subscriptions": [
            { "id": "sub1", "name": "机场订阅", "url": "https://air.example.com/sub?token=LEAK_SUB_TOKEN" },
            { "id": "sub2", "name": "路径 token 订阅", "url": "https://air2.example.com/LEAK_PATH_TOKEN/clash" },
        ],
        "ruleResources": [{ "id": "res1", "url": "https://res.example.com/u:LEAK_RES_PW@x.srs" }],
    })
}

/// 上面那份 config 生成出的 sing-box 配置形态（custom 已展平、customSettings 包装已剥离）。
fn 全协议族_生成配置() -> Value {
    json!({
        "log": { "level": "info" },
        "outbounds": [
            { "tag": "n1", "type": "vless", "server": "tokyo.air.example.com", "uuid": "LEAK_VLESS_UUID",
              "tls": { "server_name": "sni-a.example.com" } },
            { "tag": "n2", "type": "trojan", "server": "osaka.air.example.com", "password": "LEAK_TROJAN_PW" },
            // custom 展平：secretKeys 包装已不在，只能靠 collect_custom_secret_keys 汇总兜底
            { "tag": "n8", "type": "snell", "server": "snell.example.com",
              "psk": "LEAK_SNELL_PSK", "myVendorToken": "LEAK_VENDOR_TOK" },
        ],
        "endpoints": [
            { "tag": "n5", "type": "wireguard", "private_key": "LEAK_WG_PRIV",
              "peers": [{ "public_key": "KEEP_PEER_PUB", "pre_shared_key": "LEAK_WG_PSK" }] },
            { "tag": "n6", "type": "tailscale", "auth_key": "LEAK_TS_AUTHKEY", "hostname": "ts-host-alpha" },
        ],
        "experimental": { "clash_api": { "secret": "LEAK_CLASH_SECRET" } },
    })
}

fn 全协议族_source() -> DiagnosticReportSource {
    DiagnosticReportSource {
            generated_at: "2026-07-16T10:00:00.000Z".into(),
            app: AppSection { polaris_version: "0.1.0".into(), core_version: "1.14.0".into(), os: "linux x86_64".into() },
            runtime: RuntimeSection { proxy_mode: "rule".into(), proxy_mode_type: "tun".into(),
                                      proxy_running: true, log_level: "info".into(), ..Default::default() },
            user_config: 全协议族_原始配置(),
            singbox_config: 全协议族_生成配置(),
            // #57：节点域名预解析出的真实 IP（不在 servers 里）
            extra_addresses: vec!["203.0.113.77".into()],
            app_log_tail: "dial tokyo.air.example.com:443 ok\nlookup sni-a.example.com\n东京 VLESS 甲 latency 42ms\n\
ts-host-alpha joined tailnet\nresolved to 203.0.113.77".into(),
            singbox_log_tail: "lookup snell.example.com SERVFAIL\nhandshake nested-sni.example.com failed\n\
peer 162.159.192.1 up\nws-a.example.com 200".into(),
            hint: None,
        }
}

/// **红线主门**：原始 config 走唯一生产入口 → 报告里逐个密钥不得出现。
///
/// 覆盖清单：节点密码（trojan/ss/hy2/ssh/shadowtls）· UUID（vless/vmess）· WireGuard private_key ·
/// preshared key · WARP 设备 token · Tailscale authkey · SSH 私钥/passphrase · snell psk ·
/// custom 厂商自定义密钥 · ss plugin_opts · clash_api secret · 隐私密码 ·
/// 订阅 URL（query token + path token）· 规则资源 URL 里的 userinfo 凭据。
#[test]
fn 红线_组合面_原始配置走生产入口不泄漏任何密钥() {
    let md = assemble_diagnostic_report(&全协议族_source());

    // 穷举：任何以 LEAK_ 开头的值都不许出现在报告里。
    // 用前缀扫描而非逐个列举 —— 夹具里新增密钥忘了加断言时，这条仍然抓得住。
    assert!(
        !md.contains("LEAK_"),
        "红线破：报告含明文密钥。命中片段：\n{}",
        md.lines()
            .filter(|l| l.contains("LEAK_"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn 红线_组合面_节点身份不泄漏() {
    let md = assemble_diagnostic_report(&全协议族_source());
    for ident in [
        "tokyo.air.example.com",
        "osaka.air.example.com",
        "seoul.air.example.com",
        "sg.air.example.com",
        "sub-node.air.example.com",
        "ssh.example.com",
        "sni-a.example.com",
        "ws-a.example.com",
        "snell.example.com",
        "nested-sni.example.com",
        "ts-host-alpha",
        "exit-beta.ts.net",
        "162.159.192.1",
        "东京 VLESS 甲",
        "大阪 Trojan 乙",
        "首尔 SS 丙",
        "新加坡 Hy2 丁",
        "WARP 组网戊",
        "Tailscale 组网己",
        "SSH 隧道庚",
        "Snell 自定义辛",
        "订阅节点壬",
        // #57：预解析 IP 在 config.servers 之外，靠 extra_addresses 传入才打得到
        "203.0.113.77",
    ] {
        assert!(
            !md.contains(ident),
            "红线破：报告含明文节点身份 {ident:?}\n{md}"
        );
    }
}

#[test]
fn 组合面_诊断价值未被打码毁掉() {
    // 反面不变式：脱敏不得把报告打成废纸。打码过度 = 另一种失败。
    let md = assemble_diagnostic_report(&全协议族_source());
    assert!(
        md.contains("KEEP_REALITY_PUB"),
        "reality 公钥本就公开，须保留"
    );
    assert!(md.contains("KEEP_PEER_PUB"), "WG 对端公钥须保留");
    assert!(
        md.contains("KEEP_DEV_ID"),
        "WARP deviceId 非密钥，须保留供定位"
    );
    assert!(md.contains("KEEP_USER"), "username 须保留");
    assert!(md.contains("aes-256-gcm"), "SS 算法名须保留判形态");
    assert!(md.contains("chrome"), "fingerprint 须保留判形态");
    assert!(
        md.contains("/home/u/.ssh/id_rsa"),
        "私钥路径非密钥本体，须保留"
    );
    assert!(md.contains("SERVFAIL"), "日志错误信号须保留");
    assert!(
        md.contains("controlplane.tailscale.com"),
        "官方控制面地址非节点身份，须保留"
    );
    assert!(md.contains("<domain-"), "域名占位符须在");
    assert!(md.contains("<ip-"), "IP 占位符须在");
    assert!(md.contains("<node-"), "节点名占位符须在");
}

#[test]
fn 组合面_跨段占位一致可关联() {
    // 报告的核心价值：日志里的 <domain-N> 能对上配置块里的同一个 <domain-N>
    let md = assemble_diagnostic_report(&全协议族_source());
    // tokyo.air.example.com 在 用户配置段 + 生成配置段 + app.log 三处出现 → 同一占位符 ≥3 次
    let ids = crate::redact::collect_node_identifiers(&全协议族_原始配置(), &[]);
    let tokyo = ids
        .iter()
        .find(|i| i.value == "tokyo.air.example.com")
        .expect("应收集到东京节点地址");
    assert!(
        md.matches(&tokyo.placeholder).count() >= 3,
        "同一节点在配置/生成配置/日志三段应共用占位符 {}，实际 {} 次",
        tokyo.placeholder,
        md.matches(&tokyo.placeholder).count()
    );
}

#[test]
fn 红线_组合面_secret_keys_跨节点取并集() {
    // assemble 把汇总出的 secretKeys **同时**喂给 UserConfig 与生成配置两份脱敏。
    //
    // 对 UserConfig 而言这一步**看似冗余**：custom 节点的 secretKeys 与 outbound 同处一个
    // customSettings 对象，redact_deep 的就地 childExtra 机制本就能覆盖同节点。上游的
    // DiagnosticService 正是据此只给生成配置传 extra（`redactDeep(config)` 不传）。
    //
    // 但**跨节点**时二者不等价：节点甲声明了 vendorTok 是密钥，节点乙（同厂商、用户忘了声明）
    // 的 outbound 里也有 vendorTok —— 就地机制只保得住甲，并集才保得住乙。
    // 本实现取并集 = 刻意比 上游 更严（红线：宁过勿漏），此测锁住这条偏离。
    let cfg = json!({ "servers": [
        { "id": "a", "name": "甲节点厂商A", "protocol": "custom",
          "customSettings": { "secretKeys": ["vendorTok"], "outbound": { "type": "x", "vendorTok": "LEAK_A" } } },
        // 乙：同厂商，用户**没声明** secretKeys
        { "id": "b", "name": "乙节点厂商A", "protocol": "custom",
          "customSettings": { "outbound": { "type": "x", "vendorTok": "LEAK_B" } } },
    ]});
    let src = DiagnosticReportSource {
        generated_at: "t".into(),
        user_config: cfg,
        singbox_config: Value::Null,
        ..Default::default()
    };
    let md = assemble_diagnostic_report(&src);
    assert!(!md.contains("LEAK_A"), "声明方自身的密钥必须打码");
    assert!(
        !md.contains("LEAK_B"),
        "未声明节点的同名密钥须靠跨节点并集兜住（红线：宁过勿漏）：\n{md}"
    );
}

#[test]
fn 组合面_singbox_配置取不到也能出报告() {
    // best-effort：生成失败不该让整份报告导不出（诊断最需要它的时候往往正是它生成失败的时候）
    let mut src = 全协议族_source();
    src.singbox_config = json!({ "error": "生成失败: 缺 libcronet" });
    let md = assemble_diagnostic_report(&src);
    assert!(md.contains("生成失败: 缺 libcronet"));
    assert!(!md.contains("LEAK_"), "降级路径同样不得泄漏");
}

#[test]
fn 组合面_空配置不panic() {
    let src = DiagnosticReportSource {
        generated_at: "t".into(),
        user_config: json!({}),
        singbox_config: Value::Null,
        ..Default::default()
    };
    let md = assemble_diagnostic_report(&src);
    assert!(md.contains("# Polaris 诊断报告"));
}
