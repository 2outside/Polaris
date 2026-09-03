//! 代理 Outbound 构造（上游 `buildProxyOutbound` + `generateTransportConfig` +
//! `applyAntiCensorshipOptions` 1:1 移植）。20 协议字段映射 + TLS/Reality/传输层 + 抗封后处理。

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use crate::builder::outbound_helpers::{
    is_quic_managed_tls, normalize_duration, parse_ws_early_data, should_emit_tls_engine,
};
use crate::singbox::{
    DomainResolver, Ech, Hysteria2Obfs, Multiplex, OneOrMany, Outbound, OutboundTls, Reality,
    Transport, Utls,
};
use crate::user_config::normalize::normalize_token;
use crate::user_config::protocol_settings::custom_outbound_type;
use crate::user_config::server_config::{Protocol, SecurityMode, ServerConfig};
use crate::user_config::tls_spoof::validate_tls_spoof_default;

/// TLS 协议集（恒需 TLS 块即使无 tlsSettings）。
///
/// `hysteria`（**v1**）2026-08-11 补入：随包核对缺 TLS 的 hysteria v1 出站判
/// `initialize outbound[0]: TLS required` —— 是 **initialize 阶段**硬失败，不是「少个可选块」。
/// 这条不是从文档推的，是新加协议时被 `bundled_core_accepts_hysteria_v1_and_tor` 当场判红逼出来的。
const TLS_PROTOCOLS: &[&str] = &["trojan", "anytls", "hysteria2", "tuic", "hysteria"];

/// 内核允许挂 `transport` 的出站类型 —— **白名单，判据取自内核 schema**。
///
/// 随包核 beta.7 `sing-box schema` → `$defs/Outbound` 的 20 支 oneOf 里，只有这三支有
/// `transport` 属性；其余 17 支一律 `additionalProperties:false` 且无该键。
const TRANSPORT_CAPABLE: &[Protocol] = &[Protocol::Trojan, Protocol::Vless, Protocol::Vmess];

/// 该协议的出站能不能带 `transport`（ws/grpc/http/httpupgrade 那一层）。
///
/// **导出给 `net-stack` 复用** —— 导入侧要据此告诉用户「你这个节点上的传输层参数不会生效」。
/// 那边不许复制一份自己的名单：复制出来的第二份判据迟早与内核漂移，而漂移的表现是
/// 「要么产出起不来的配置、要么把好配置误报成无效」。
pub fn protocol_can_carry_transport(protocol: Protocol) -> bool {
    TRANSPORT_CAPABLE.contains(&protocol)
}

/// 生成代理 Outbound。上游 `buildProxyOutbound`。
/// arch/platform 注入。
///
/// `node_resolver` = 节点域名 dial 解析器，**纯透传**：本函数不构造、不给默认值，由调用方经
/// [`get_node_dial_domain_resolver`](crate::builder::helpers::get_node_dial_domain_resolver)
/// 备好后传入。这是 #335 修复的一部分——参数类型是 [`DomainResolver`] 而非 `&str`，未来新增
/// call site 若图省事直接塞一个 tag 字符串会是**编译错误**，而不是静默回落到「纯 tag 覆盖顶层
/// strategy」的未修形态（那个形态在 loopback 上表现为节点域名 `lookup failed: empty result`）。
pub fn build_proxy_outbound(
    server: &ServerConfig,
    tag: &str,
    node_resolver: &DomainResolver,
    arch: &str,
    platform: &str,
) -> Outbound {
    let protocol = protocol_str(server.protocol);

    // 自定义协议（逃生舱）：**真透传** —— 用户给什么就下发什么，只做两处既有且有理由的改写
    // （覆盖 `tag`、剥内层 `detour`，见 [`custom_passthrough_parts`]）。
    //
    // 此前这里是 `serde_json::from_value::<Outbound>(val)`：注释写「原样下发」，实现却是「只下发
    // 本 struct 建模过的字段」，且类型对不上时整份反序列化失败、回落成 `{"type":"custom"}` 空壳。
    // 完整的三档坏法与实测判决见 [`Outbound::extra`] 的头注。
    if server.protocol == Protocol::Custom {
        if let Some((type_field, extra)) = server
            .custom_settings
            .as_ref()
            .and_then(|cs| custom_passthrough_parts(&cs.outbound))
        {
            let mut ob = Outbound::shell(&type_field, tag);
            ob.extra = extra;
            return ob;
        }
        // 形状非法（非对象 / 无 string `type`）。装配层 `builder/outbounds.rs` 用**同一条判据**
        // （`custom_outbound_type`）把这种节点剔除并记进 `invalid_nodes`，故主生成路径到不了这里；
        // 直调本函数的第二个 call site（`runtime/speedtest.rs` 的临时测速核）会走到。
        //
        // 此时保留 `{"type":"custom","tag":…}` 这颗**毒丸**是刻意的：随包 sing-box 对它的判决是
        // `unknown outbound type: custom`（实测 rc=1），临时核起不来 = 该节点测速失败，如实。
        // 换成「编一个像样的 outbound」反而会把「用户 JSON 写坏了」伪装成「这节点就是慢」。
        return Outbound::shell(&protocol, tag);
    }

    let mut ob = Outbound {
        type_field: protocol.clone(),
        tag: tag.to_string(),
        detour: None,
        server: Some(server.address.clone()),
        server_port: Some(server.port),
        override_address: None,
        method: None,
        password: None,
        username: None,
        plugin: None,
        plugin_opts: None,
        uuid: None,
        security: None,
        alter_id: None,
        flow: None,
        packet_encoding: None,
        up_mbps: None,
        down_mbps: None,
        obfs: None,
        auth_str: None,
        executable_path: None,
        data_directory: None,
        extra_args: None,
        torrc: None,
        bbr_profile: None,
        disable_chrome_parrot: None,
        network: None,
        quic: None,
        congestion_control: None,
        udp_relay_mode: None,
        zero_rtt_handshake: None,
        heartbeat: None,
        version: None,
        psk: None,
        userkey: None,
        reuse: None,
        obfs_mode: None,
        obfs_host: None,
        mode: None,
        idle_session_check_interval: None,
        idle_session_timeout: None,
        min_idle_session: None,
        path: None,
        headers: None,
        tls: None,
        transport: None,
        multiplex: None,
        server_ports: None,
        hop_interval: None,
        domain_resolver: Some(node_resolver.clone()),
        udp_over_tcp: None,
        udp_fragment: None,
        user: None,
        private_key: None,
        private_key_path: None,
        private_key_passphrase: None,
        host_key: None,
        host_key_algorithms: None,
        client_version: None,
        cipher: None,
        mac: None,
        kex_algorithm: None,
        outbounds: None,
        default: None,
        interrupt_exist_connections: None,
        extra: serde_json::Map::new(),
    };

    let packet_encoding = server
        .packet_encoding
        .clone()
        .unwrap_or_else(|| "xudp".to_string());

    match server.protocol {
        Protocol::Vless => {
            ob.uuid = server.uuid.clone();
            // 消费点归一：serde 边界已归一，但 net-stack 的 clash_parser 直接字段赋值
            // （`config.flow = Some(raw_yaml)`）绕过 serde → 此处兜底。
            // 未归一的 `"XTLS-RPRX-Vision"` 会让 sing-box `unsupported flow` FATAL。
            ob.flow = server.flow.as_deref().and_then(normalize_token);
            if !packet_encoding.is_empty() {
                ob.packet_encoding = Some(packet_encoding);
            }
        }
        Protocol::Vmess => {
            ob.uuid = server.uuid.clone();
            ob.security = Some(
                server
                    .vmess_security
                    .clone()
                    .unwrap_or_else(|| "auto".into()),
            );
            ob.alter_id = Some(server.alter_id.unwrap_or(0));
            if !packet_encoding.is_empty() {
                ob.packet_encoding = Some(packet_encoding);
            }
        }
        Protocol::Trojan => {
            ob.password = server.password.clone();
        }
        Protocol::Hysteria2 => {
            ob.password = server.password.clone();
            if let Some(h) = &server.hysteria2_settings {
                // `0` 与「不下发」在内核侧**语义等价**，故过滤掉而不是原样写出去。
                //
                // 判据是内核源码不是猜：`sing-quic v0.6.4 hysteria2/client.go:573-590`（= 随包
                // beta.7 `go.mod` 的精确 pin）里是
                // `if !authResponse.RxAuto && actualTx > 0 { NewBrutalSender(actualTx) } else { NewBbrSender... }`
                // —— `> 0` 这一支把 `0` 明确划进 BBR 腿。官方文档同口径：「If empty, the BBR
                // congestion control algorithm will be used instead of Hysteria CC.」
                // loopback A/B 复核（随包 beta.7，200MB×3）：不设 = 3287/3282/3124 Mbps，
                // `up:0 down:0` = 2868/2879/2842 Mbps —— 同为 BBR 量级，`0` 不会 stall。
                //
                // 那为什么还要过滤：写出去会让每份存量配置凭空多一个 `"up_mbps": 0` 键，
                // 与 上游（`if (server.hysteria2Settings?.upMbps)` 的 truthy 判断）产生纯字节分歧，
                // 而本仓的金样对拍是逐字节的。行为等价、字节不等价 = 无谓的漂移。
                //
                // **刻意不做的事**：不过滤非零值、不加「忽略订阅带宽」开关。
                // 用户 2026-08-06 定：**遵循订阅下发**。代价是知情的——非零 `up_mbps`/`down_mbps`
                // 会让内核改用 Brutal 固定速率而非 BBR 自适应（VM185 真机实测：声明 30 → 实测
                // 29.5 Mbps = 1GbE 线速的 3.1%），机场在订阅里填保守值时吞吐会被钉死。
                // 详见 vault `design/networking/` 下的 hy2 自建验证记录。
                ob.up_mbps = h.up_mbps.filter(|v| *v > 0);
                ob.down_mbps = h.down_mbps.filter(|v| *v > 0);
                if let Some(obfs) = &h.obfs {
                    if let (Some(t), Some(pw)) = (&obfs.type_field, &obfs.password) {
                        let mut o = Hysteria2Obfs {
                            type_field: t.clone(),
                            password: pw.clone(),
                            min_packet_size: None,
                            max_packet_size: None,
                        };
                        if t == "gecko" {
                            o.min_packet_size = obfs.min_packet_size;
                            o.max_packet_size = obfs.max_packet_size;
                        }
                        ob.obfs = Some(crate::singbox::outbound::ObfsField::Object(o));
                    }
                }
                ob.bbr_profile = h.bbr_profile.clone();
                // 只有用户显式打开才下发 `true`（核心默认 false=拟态开）。`Some(false)` 与 `None` 一样
                // 不下发 —— 下发 `false` 与省略语义等价，却会让每份存量配置多出一个键（金样字节漂移）。
                if h.disable_chrome_parrot == Some(true) {
                    ob.disable_chrome_parrot = Some(true);
                }
                ob.network = h.network.clone();
            }
        }
        Protocol::Snell => {
            // 🔴 `snellSettings` 缺席时**不能整段跳过** —— 跳过就一个 `version`/`psk` 都不发，
            // 而内核在 **decode 阶段**判 `snell: missing version` ⇒ 整份配置起不来，不止这个节点
            // （随包核 beta.7 实测；由 `tests/kernel_accepts_outbounds.rs` 的协议×传输交叉门发现）。
            //
            // 缺席按全默认处理，且 `version` 归一到 4/6：`SnellVersion = u32` 且 `Default` 派生 ⇒
            // 缺省值是 **0**，而 0 同样不是内核认的版本。归一判据取自 UI 侧既有的那一条
            // （`proto-codec.ts:778` 的 `version === 6 ? '6' : '4'`）—— 两侧同判据，不另立第二份。
            //
            // 生产可达性：UI 的 `toConfig` 与三个 importer 都恒写 `snellSettings`，故这是**防御**
            // 而非已复现的线上缺陷。但落点是「整核起不来」，与 `Protocol::Http` 那次同级，
            // 且修法是纯收窄（4/6 之外的值本就会被内核拒），故不留着。
            {
                // 只读，故借而不拷。此前写的是 `.clone().unwrap_or_default()` —— 那在装箱之前
                // 就已经是白拷一份带 5 个 `Option<String>` + 1 个 `Option<bool>` 的结构体
                // （`SnellSettings`，另有一个 `u32` 版本号），装箱后更是 Some/None 两支
                // **各多一次堆分配**（`Box::clone` 先 alloc；`Box::<T>::default()` 也 alloc）。
                // 本函数有两个生产调用点（`builder/outbounds.rs` 的每节点循环、
                // `runtime/speedtest.rs` 的每轮测速 × 每节点），故按节点数放大，不是一次性的。
                // 改成借用后两支都零分配，比装箱前还省一次拷贝。
                let fallback;
                let s = match server.snell_settings.as_deref() {
                    Some(s) => s,
                    None => {
                        fallback = crate::user_config::protocol_settings::SnellSettings::default();
                        &fallback
                    }
                };
                let version: u32 = if s.version == 6 { 6 } else { 4 };
                ob.version = Some(crate::singbox::OutboundVersion::Num(version));
                ob.psk = server.password.clone();
                ob.userkey = s.userkey.clone();
                if s.reuse == Some(true) {
                    ob.reuse = Some(true);
                }
                ob.network = s.network.clone();
                if version == 4 {
                    if let Some(mode) = &s.obfs_mode {
                        if mode != "none" {
                            ob.obfs_mode = Some(mode.clone());
                            ob.obfs_host =
                                Some(s.obfs_host.clone().unwrap_or_else(|| "bing.com".into()));
                        }
                    }
                } else {
                    if let Some(m) = &s.mode {
                        if m != "default" {
                            ob.mode = Some(m.clone());
                        }
                    }
                }
            }
        }
        Protocol::Anytls => {
            ob.password = server.password.clone();
            if let Some(a) = &server.any_tls_settings {
                ob.idle_session_check_interval =
                    normalize_duration(a.idle_session_check_interval.as_deref());
                ob.idle_session_timeout = normalize_duration(a.idle_session_timeout.as_deref());
                ob.min_idle_session = a.min_idle_session;
            }
        }
        Protocol::Shadowsocks => {
            if let Some(ss) = &server.shadowsocks_settings {
                ob.method = Some(ss.method.clone());
                ob.password = Some(ss.password.clone());
                ob.plugin = ss.plugin.clone();
                ob.plugin_opts = ss.plugin_opts.clone();
            }
        }
        Protocol::Tuic => {
            ob.uuid = server.uuid.clone();
            ob.password = server.password.clone();
            if let Some(t) = &server.tuic_settings {
                ob.congestion_control = t.congestion_control.clone();
                ob.udp_relay_mode = t.udp_relay_mode.clone();
                ob.zero_rtt_handshake = t.zero_rtt_handshake;
                ob.heartbeat = normalize_duration(t.heartbeat.as_deref());
            }
        }
        Protocol::Naive => {
            ob.username = server.username.clone();
            ob.password = server.password.clone();
            // naive TLS 由 Cronet 自管：仅 server_name（alpn/insecure 会 FATAL）。
            ob.tls = Some(OutboundTls {
                enabled: true,
                server_name: Some(
                    server
                        .tls_settings
                        .as_ref()
                        .and_then(|t| t.server_name.clone())
                        .unwrap_or_else(|| server.address.clone()),
                ),
                insecure: None,
                alpn: None,
                engine: None,
                spoof: None,
                spoof_method: None,
                utls: None,
                reality: None,
                ech: None,
                fragment: None,
            });
            if let Some(n) = &server.naive_settings {
                if n.use_http3 == Some(true) {
                    ob.quic = Some(true);
                }
            }
        }
        Protocol::Socks => {
            ob.username = server.username.clone();
            ob.password = server.password.clone();
            // SOCKS 默认版本：上游 `version = '5'`（字符串，outbound-builder.ts:381），非裸数字。
            ob.version = Some(crate::singbox::OutboundVersion::Str("5".to_string()));
        }
        Protocol::Http => {
            ob.username = server.username.clone();
            ob.password = server.password.clone();
            // HTTP 伪装的 headers/path 走**出站顶层**，不是 `transport`。
            //
            // 此前这里 1:1 移植了 上游 `singbox-outbound-builder.ts:391-398` 的「塞进 ob.transport」，
            // 而随包 sing-box 1.14.0-beta.7 的 http 出站 schema **没有 `transport` 键**且
            // `additionalProperties:false` ⇒ 只要用户在 http 节点上填过 headers/path，产出的就是一份
            // `FATAL decode config: outbounds[0].transport: json: unknown field "transport"` 的死配置
            // （整个核起不来，不止这一个节点）。正反对照与 schema 原文见 [`Outbound::path`] 的头注。
            //
            // `h.host` / `h.method` **无处可去**：内核 http 出站没有这两键（写顶层同样 FATAL），故此处
            // 刻意不读——它们只在 h2 **传输**那条腿（`generate_transport_config` 的 "http"|"h2" 分支）
            // 有意义，那里的容器是 `transport`，schema 允许。
            if let Some(h) = &server.http_settings {
                if let Some(headers) = &h.headers {
                    let mut m = BTreeMap::new();
                    for (k, v) in headers {
                        m.insert(k.clone(), OneOrMany::Many(v.clone()));
                    }
                    ob.headers = Some(m);
                }
                if let Some(path) = &h.path {
                    ob.path = Some(path.clone());
                }
            }
        }
        // ── Hysteria v1（2026-08-11）──
        // 与 Hysteria2 是两个协议：v1 的 obfs 是**裸字符串**、认证走 auth_str/auth、
        // 带宽 up_mbps/down_mbps 是必填语义（缺了内核不报错但拥塞控制无从工作）。
        Protocol::Hysteria => {
            if let Some(h) = &server.hysteria_settings {
                // 透传袋：先铺，再把本臂会写的具名键从袋里剔掉。
                // 顺序不够 —— `extra` 是 `#[serde(flatten)]`，序列化时**袋里的键胜出**，
                // 所以「先铺后写」并不能让具名字段赢。必须显式移除冲突键。
                // 判据：具名字段是**表单的真值**，否则用户改过的项会被导入时留下的原值盖回去。
                //
                // 铺之前先做 Hysteria v1 旧键的**改名替换**：随包 1.14 出站收其中三键，
                // 另两键是放错上下文的入站键；五键均有上游 docs/changelog 的 1.16 移除日程。
                // 放在生成侧而不是只放在
                // 导入侧：袋子里的旧名可能来自**本次改动之前就已落盘**的用户配置，那批配置不会
                // 再走一次导入。产出面是所有来路的唯一汇合点，把判据钉在这里才是「零出现」。
                let mut bag = h.extra.clone();
                crate::legacy_keys::migrate_hysteria_v1_legacy_keys(&mut bag);
                ob.extra.extend(bag);
                for k in [
                    "auth_str",
                    "auth",
                    "up_mbps",
                    "down_mbps",
                    "obfs",
                    "server_ports",
                    "hop_interval",
                ] {
                    ob.extra.remove(k);
                }
                ob.auth_str = h.auth_str.clone();
                ob.up_mbps = h.up_mbps;
                ob.down_mbps = h.down_mbps;
                if let Some(o) = &h.obfs {
                    ob.obfs = Some(crate::singbox::outbound::ObfsField::Text(o.clone()));
                }
                // 端口跳跃：内核这两个键与 hy2 同名同义，直接复用 Outbound 上已有的字段。
                if let Some(ports) = &h.server_ports {
                    if !ports.trim().is_empty() {
                        ob.server_ports = Some(vec![ports.clone()]);
                    }
                }
                ob.hop_interval = h.hop_interval.clone();
            }
        }
        // ── 内嵌 Tor（2026-08-11）──
        // **没有 server/server_port**：实测传 server 得 `unknown field "server"`。
        // 上面的通用构造已经无条件填了这两个键，故此处必须显式清掉，否则整份配置 decode 失败
        // ——这不是「多发一个没用的键」，是**整个内核起不来**。
        Protocol::Tor => {
            ob.server = None;
            ob.server_port = None;
            if let Some(t) = &server.tor_settings {
                ob.extra.extend(t.extra.clone());
                for k in ["executable_path", "data_directory", "extra_args", "torrc"] {
                    ob.extra.remove(k);
                }
                ob.executable_path = t.executable_path.clone();
                ob.data_directory = t.data_directory.clone();
                if !t.extra_args.is_empty() {
                    ob.extra_args = Some(t.extra_args.clone());
                }
                if !t.torrc.is_empty() {
                    ob.torrc = Some(t.torrc.clone());
                }
            }
            // Tor 自带传输层，不叠 TLS/transport。
            return ob;
        }
        Protocol::Ssh => {
            if let Some(s) = &server.ssh_settings {
                ob.user = s.user.clone();
                ob.password = s.password.clone();
                ob.private_key = s.private_key.clone();
                ob.private_key_path = s.private_key_path.clone();
                ob.private_key_passphrase = s.private_key_passphrase.clone();
                ob.host_key = s.host_key.clone();
                ob.host_key_algorithms = s.host_key_algorithms.clone();
                ob.client_version = s.client_version.clone();
                ob.cipher = s.cipher.clone();
                ob.mac = s.mac.clone();
                ob.kex_algorithm = s.kex_algorithm.clone();
            }
            // SSH 不需 TLS/transport，直接返回。
            return ob;
        }
        _ => {}
    }

    // TLS（非 naive）。
    // security 是 SecurityMode 枚举 → 大小写变体在反序列化边界已归一，此处不可能漏判。
    if server.protocol != Protocol::Naive
        && (server.security.as_ref().is_some_and(SecurityMode::is_tls)
            || server.tls_settings.is_some()
            || TLS_PROTOCOLS.contains(&protocol.as_str()))
    {
        let mut final_alpn = server.tls_settings.as_ref().and_then(|t| t.alpn.clone());
        if final_alpn.is_none() && server.protocol == Protocol::Trojan {
            final_alpn = Some(vec!["http/1.1".into()]);
        }

        ob.tls = Some(OutboundTls {
            enabled: true,
            server_name: Some(
                server
                    .tls_settings
                    .as_ref()
                    .and_then(|t| t.server_name.clone())
                    .unwrap_or_else(|| server.address.clone()),
            ),
            insecure: Some(
                server
                    .tls_settings
                    .as_ref()
                    .and_then(|t| t.allow_insecure)
                    .unwrap_or(false),
            ),
            alpn: final_alpn,
            engine: None,
            spoof: None,
            spoof_method: None,
            utls: None,
            reality: None,
            ech: None,
            fragment: None,
        });

        let tls_engine = server
            .tls_settings
            .as_ref()
            .and_then(|t| t.engine.as_deref());
        if !is_quic_managed_tls(&protocol) && should_emit_tls_engine(tls_engine, platform) {
            ob.tls.as_mut().unwrap().engine = tls_engine.map(String::from);
        }

        // uTLS fingerprint（非 QUIC）。消费点归一（理由同 flow：绕过 serde 的字段赋值兜底）。
        // 未归一的 `"Chrome"` / `"NONE"` 会让 sing-box `unknown uTLS fingerprint` FATAL；
        // 尤其 `"None"` 本意是禁用 utls，不归一则反而下发非法指纹 → 核起不来。
        let fingerprint = server
            .tls_settings
            .as_ref()
            .and_then(|t| t.fingerprint.as_deref())
            .and_then(normalize_token);
        let final_fp = fingerprint.unwrap_or_else(|| {
            if server.protocol == Protocol::Vless || server.protocol == Protocol::Anytls {
                "chrome".to_string()
            } else {
                "none".to_string()
            }
        });
        if !is_quic_managed_tls(&protocol) && final_fp != "none" {
            ob.tls.as_mut().unwrap().utls = Some(Utls {
                enabled: true,
                fingerprint: final_fp,
            });
        }
    }

    // Reality。
    if server
        .security
        .as_ref()
        .is_some_and(SecurityMode::is_reality)
    {
        if let Some(r) = &server.reality_settings {
            // 🔴 `engine` 在本段**必须写死 `None`**，别改成「把上面 TLS 段装好的那个搬过来」。
            //
            // 曾按「schema 里 engine 与 reality 是平级属性、无互斥约束」判定这是本仓 builder 的缺口
            // 并动手搬运，**那是错的**：schema 只表达键的形状，reality 与平台 engine 的互斥发生在
            // `initialize outbound` 阶段，schema 与 `sing-box check` 在 Linux 上都看不到。
            //
            // 判据（随包核 beta.7 四个平台二进制的字符串在场矩阵，`strings -n 6 | grep -c`）：
            // ```
            // "reality is unsupported in "   linux=0  win=1  mac-x64=1  mac-arm64=1
            // "utls is unsupported in "      linux=0  win=1  mac-x64=1  mac-arm64=1
            // "ech is unsupported in "       linux=0  win=1  mac-x64=1  mac-arm64=1
            // ```
            // 这三条只编进「有真实平台 engine 客户端」的那几个构建；Linux 里 Windows/Apple 引擎是
            // **提前返回的桩**（报 `... TLS engine is not available on non-Windows platforms`），
            // 于是 Linux 上任何 `reality × engine` 对照都测不到真判决 —— 那种实验的检出力是 **0**，
            // 「四组报错逐字相同 ⇒ 与 reality 无关」是桩的必然输出，不是证据。
            //
            // 而 `should_emit_tls_engine` 只在 `(windows,win32)`/`(apple,darwin)` 放行 ⇒ 一旦搬运，
            // 落到真机上的恰好就是「平台 engine 客户端 + reality」这一组，判决是
            // `FATAL initialize outbound[N]: reality is unsupported in <engine>`，
            // **整份配置起不来**（不止这个节点）。且本替换体无条件发 `utls{enabled:true}`，
            // 即使 reality 那条不先触发，`utls is unsupported in ` 也会触发 —— 双重致命。
            //
            // ⇒ 前端 `whenTlsEngine` 上那条 `!whenReality` 不是止血门，是**正确的**：reality 下
            // 这一档在任何平台都不可用，显示它就是一个拨了必然炸核的控件。
            ob.tls = Some(OutboundTls {
                enabled: true,
                server_name: server
                    .tls_settings
                    .as_ref()
                    .and_then(|t| t.server_name.clone()),
                insecure: Some(
                    server
                        .tls_settings
                        .as_ref()
                        .and_then(|t| t.allow_insecure)
                        .unwrap_or(false),
                ),
                alpn: None,
                engine: None,
                spoof: None,
                spoof_method: None,
                utls: Some(Utls {
                    enabled: true,
                    fingerprint: server
                        .tls_settings
                        .as_ref()
                        .and_then(|t| t.fingerprint.as_deref())
                        .and_then(normalize_token)
                        .unwrap_or_else(|| "chrome".into()),
                }),
                reality: Some(Reality {
                    enabled: true,
                    public_key: r.public_key.clone(),
                    short_id: r.short_id.clone().unwrap_or_default(),
                }),
                ech: None,
                fragment: None,
            });
        }
    }

    // 传输层 —— **白名单**，判据取自内核 schema 而非「排掉几个已知不行的」。
    //
    // 随包核 beta.7 `sing-box schema` → `$defs/Outbound` 的 20 支 oneOf 里，**只有 trojan / vless /
    // vmess 三支有 `transport` 属性**，其余 17 支（http/socks/shadowsocks/tuic/shadowtls/anytls/…）
    // 一律 `additionalProperties:false` 且无该键 ⇒ 给它们挂 transport 的产物是
    // `FATAL decode config: outbounds[N].transport: json: unknown field "transport"`，
    // **整份配置起不来**，不止这个节点。
    //
    // 此处此前是黑名单（`!matches!(Hysteria2|Anytls|Naive)`），与内核判据方向相反：内核说「只有这三个
    // 可以」，本仓说「只有这三个不可以」。中间那 14 个协议只要拿到 `network != "tcp"` 就产出死配置。
    // 而它们**拿得到**：UI 侧只有 vless/vmess/trojan 暴露传输选择器（`ND_SPEC` 里只有这三支带
    // `F_TRANSPORT`，与内核白名单精确一致），但**导入侧不受这个限制** —— xray 的 `streamSettings`
    // 挂在任意出站上、clash 的 `network:` 同理，`net-stack` 那几个 parser 会照单写进 `server.network`。
    //
    // 改成白名单后，非白名单协议带进来的传输参数被**丢弃**（而不是让整份配置炸）。这是有意的取舍：
    // 二者都丢信息，但前者只影响该节点、后者影响全部节点。丢弃这件事今天没有上报通道
    // （builder 无 diagnostics 出口），登记为债务：真正该报的位置在导入侧，那里有 `unsupported` 计数。
    if protocol_can_carry_transport(server.protocol) {
        if let Some(net) = &server.network {
            if net != "tcp" {
                ob.transport = generate_transport_config(server);
            }
        }
    }

    // 抗封后处理。
    apply_anti_censorship_options(&mut ob, server, arch);

    ob
}

/// custom 逃生舱 raw JSON → `(type, 其余键)`，供 outbound / endpoint 两条腿共用。
///
/// 形状不合法（非对象 / 无 string `type`）→ `None`，判据与 C10 probe 共用
/// [`custom_outbound_type`]（那条注释解释了为什么必须是同一个谓词）。
///
/// 只做三处键改写，**每处都有既有理由，不是新策略**：
///  - `type` 取出来进 `type_field` 具名字段 —— 留在 map 里会与具名字段撞成重复键；
///  - `tag` 丢弃 —— 节点 tag 是 Polaris 的拓扑真值（selector 成员、detour 目标、路由规则全指它），
///    由调用方覆盖，用户在 JSON 里自填的那个不作数；
///  - `detour` 丢弃 —— 内层 detour 会绕过 Polaris 自己的 detour 死引用/成环检测
///    （`builder/outbounds.rs::prune_detour_dead_references`），是本仓一直在剥的东西。
///
/// 其余键**一律原样保留**：这正是「逃生舱」三个字的全部内容。
pub(crate) fn custom_passthrough_parts(
    raw: &serde_json::Value,
) -> Option<(String, serde_json::Map<String, serde_json::Value>)> {
    let type_field = custom_outbound_type(raw)?.to_string();
    let mut extra = raw.as_object()?.clone();
    extra.remove("type");
    extra.remove("tag");
    extra.remove("detour");
    Some((type_field, extra))
}

/// 生成传输层配置。上游 `generateTransportConfig`。
fn generate_transport_config(server: &ServerConfig) -> Option<Transport> {
    let net = server.network.as_deref()?;
    match net {
        "ws" => {
            let ws = server.ws_settings.as_ref();
            let raw_path = ws.and_then(|w| w.path.as_deref()).unwrap_or("/");
            let ed = parse_ws_early_data(raw_path);
            Some(Transport {
                type_field: "ws".into(),
                path: Some(ed.path),
                host: None,
                method: None,
                headers: ws.and_then(|w| w.headers.as_ref()).map(|h| {
                    let mut m = BTreeMap::new();
                    for (k, v) in h {
                        m.insert(k.clone(), OneOrMany::One(v.clone()));
                    }
                    m
                }),
                service_name: None,
                max_early_data: ed
                    .max_early_data
                    .or_else(|| ws.and_then(|w| w.max_early_data)),
                early_data_header_name: ed
                    .early_data_header_name
                    .or_else(|| ws.and_then(|w| w.early_data_header_name.clone())),
            })
        }
        "grpc" => {
            let g = server.grpc_settings.as_ref();
            Some(Transport {
                type_field: "grpc".into(),
                service_name: Some(g.and_then(|g| g.service_name.clone()).unwrap_or_default()),
                path: None,
                host: None,
                method: None,
                headers: None,
                max_early_data: None,
                early_data_header_name: None,
            })
        }
        "http" | "h2" => {
            let h = server.http_settings.as_ref();
            Some(Transport {
                type_field: "http".into(),
                host: h.and_then(|h| h.host.clone()).map(|hosts| {
                    if hosts.len() == 1 {
                        OneOrMany::One(hosts[0].clone())
                    } else {
                        OneOrMany::Many(hosts)
                    }
                }),
                path: Some(h.and_then(|h| h.path.clone()).unwrap_or_else(|| "/".into())),
                method: h.and_then(|h| h.method.clone()),
                headers: h.and_then(|h| h.headers.as_ref()).map(|hdrs| {
                    let mut m = BTreeMap::new();
                    for (k, v) in hdrs {
                        m.insert(k.clone(), OneOrMany::Many(v.clone()));
                    }
                    m
                }),
                service_name: None,
                max_early_data: None,
                early_data_header_name: None,
            })
        }
        "httpupgrade" => Some(Transport {
            type_field: "httpupgrade".into(),
            path: Some(
                server
                    .ws_settings
                    .as_ref()
                    .and_then(|w| w.path.clone())
                    .unwrap_or_else(|| "/".into()),
            ),
            host: server
                .ws_settings
                .as_ref()
                .and_then(|w| w.headers.as_ref().and_then(|h| h.get("Host").cloned()))
                .or_else(|| {
                    server
                        .tls_settings
                        .as_ref()
                        .and_then(|t| t.server_name.clone())
                })
                .map(OneOrMany::One),
            method: None,
            headers: None,
            service_name: None,
            max_early_data: None,
            early_data_header_name: None,
        }),
        _ => None,
    }
}

/// 抗封后处理（ECH/fragment/spoof/multiplex/hy2 端口跳跃）。上游 `applyAntiCensorshipOptions`。
fn apply_anti_censorship_options(ob: &mut Outbound, server: &ServerConfig, arch: &str) {
    let protocol_lower = protocol_str(server.protocol);
    let fragment_unsupported =
        is_quic_managed_tls(&protocol_lower) || server.protocol == Protocol::Naive;

    // ECH + fragment + spoof（需 tls 块）。
    if let Some(tls) = ob.tls.as_mut() {
        if let Some(tls_s) = &server.tls_settings {
            if tls_s.ech == Some(true) {
                let ech_cfg = tls_s.ech_config.as_deref().map(|s| s.trim()).unwrap_or("");
                let lines: Vec<String> = if ech_cfg.is_empty() {
                    vec![]
                } else {
                    ech_cfg
                        .lines()
                        .map(|l| l.trim().to_string())
                        .filter(|l| !l.is_empty())
                        .collect()
                };
                tls.ech = Some(if lines.is_empty() {
                    Ech {
                        enabled: true,
                        config: None,
                    }
                } else {
                    Ech {
                        enabled: true,
                        config: Some(lines),
                    }
                });
            }
            if tls_s.fragment == Some(true) && !fragment_unsupported {
                tls.fragment = Some(true);
            }
            // TLS spoof。
            let spoof_sni = tls_s.spoof_sni.as_deref().map(|s| s.trim()).unwrap_or("");
            let real_sni = tls.server_name.as_deref();
            if validate_tls_spoof_default(
                Some(spoof_sni),
                tls_s.spoof_method.as_deref(),
                Some(arch),
                Some(protocol_lower.as_str()),
                real_sni,
            ) {
                tls.spoof = Some(spoof_sni.to_string());
                tls.spoof_method = tls_s.spoof_method.clone();
            }
        }
    }

    // Multiplex（vless/trojan/vmess/ss；vision flow 跳过）。
    if let Some(mux) = &server.multiplex_settings {
        if mux.enabled == Some(true)
            && matches!(
                server.protocol,
                Protocol::Vless | Protocol::Trojan | Protocol::Vmess | Protocol::Shadowsocks
            )
        {
            let has_vision = server
                .flow
                .as_deref()
                .map(|f| f.to_ascii_lowercase().contains("vision"))
                .unwrap_or(false);
            if !has_vision {
                ob.multiplex = Some(Multiplex {
                    enabled: true,
                    protocol: Some(mux.protocol.clone().unwrap_or_else(|| "h2mux".into())),
                    max_connections: mux.max_connections,
                    min_streams: mux.min_streams,
                    padding: mux.padding,
                });
            }
        }
    }

    // Hysteria2 端口跳跃。
    if server.protocol == Protocol::Hysteria2 {
        if let Some(h) = &server.hysteria2_settings {
            if let Some(ports_str) = &h.server_ports {
                let ports: Vec<String> = ports_str
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if !ports.is_empty() {
                    ob.server_ports = Some(ports);
                    ob.hop_interval = h.hop_interval.clone();
                }
            }
        }
    }
}

/// 协议的内核 type 字符串。**导出给 outbounds.rs 的端点族腿复用** —— 那里要拿它当
/// `Endpoint::type_field`，复制一份必然与本表漂移。
pub(crate) fn protocol_str(p: Protocol) -> String {
    match p {
        Protocol::Vless => "vless",
        Protocol::Trojan => "trojan",
        Protocol::Hysteria2 => "hysteria2",
        Protocol::Shadowsocks => "shadowsocks",
        Protocol::Anytls => "anytls",
        Protocol::Tuic => "tuic",
        Protocol::Vmess => "vmess",
        Protocol::Naive => "naive",
        Protocol::Snell => "snell",
        Protocol::Socks => "socks",
        Protocol::Http => "http",
        Protocol::Ssh => "ssh",
        Protocol::Wireguard => "wireguard",
        Protocol::Tailscale => "tailscale",
        Protocol::Hysteria => "hysteria",
        Protocol::Tor => "tor",
        Protocol::Openconnect => "openconnect",
        Protocol::OpenvpnClient => "openvpn-client",
        Protocol::Custom => "custom",
    }
    .to_string()
}

#[cfg(test)]
mod tests;
