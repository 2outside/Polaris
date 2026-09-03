use super::*;
use crate::test_support::{crate_code, flooding_stderr, module_code};
// 生产侧的 `TEMP_CORE_BATCH_WINDOW_OVERHEAD_MS` 是字面量（跨语言那道门要读得出来），它与
// `sing-box check` 硬超时的关系由本模块的门断言 —— 故这个常量只在测试侧引。
use async_trait::async_trait;
use polaris_core_supervisor::CONFIG_CHECK_TIMEOUT;
use std::sync::atomic::{AtomicUsize, Ordering};

fn env() -> CoreBuildEnv {
    CoreBuildEnv {
        platform: "linux".to_string(),
        arch: "x86_64".to_string(),
        has_cronet: true,
    }
}

/// 🔴 **`-1`（真测了没通）与「未测」必须分开计**（陈先生 2026-08-02：「全部测速全部显示 -1，
/// 跟实际不符」）。两者在日志里混成一类，就再也分不出「网络真挂了」和「本轮压根没测、
/// 前端把缺席画成了 -1」——而这两件事的修法完全相反。
///
/// **变异锁**：
/// - 把 `ms >= 0` 写成 `ms > 0` → 第 2 组转红（0ms 是合法的本地极速值，不是失败）；
/// - 把 `failed` 算成 `results.len()`（不减 ok）→ 第 1 组转红；
/// - 把 `absent` 并进 `failed` → 第 1 组转红且三分之和溢出（`also_assert_total` 在 debug 下当场炸）。
#[test]
fn speed_test_summary_splits_timeout_from_never_measured() {
    let m = |pairs: &[(&str, i64)]| -> serde_json::Map<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), json!(v)))
            .collect()
    };
    let intended: Vec<String> = ["a", "b", "c", "d"].iter().map(|s| (*s).into()).collect();

    // 2 个出值（1 成功 1 超时）+ 2 个根本没测。
    let s = summarize_speed_test(
        &m(&[("a", 120), ("b", -1)]),
        &intended,
        2,
        Some(InterruptReason::Superseded),
    );
    assert_eq!(
        s,
        SpeedTestSummary {
            ok: 1,
            failed: 1,
            absent: 2,
            absent_reason: Some(InterruptReason::Superseded),
        }
    );

    // 0ms 是合法测量值（本地/极近节点），不是失败。
    let s = summarize_speed_test(&m(&[("a", 0)]), &["a".to_string()], 0, None);
    assert_eq!(
        s,
        SpeedTestSummary {
            ok: 1,
            failed: 0,
            absent: 0,
            absent_reason: None,
        }
    );

    // 全员未测（让位/中断）：一个 `-1` 都不该被伪造出来。
    let s = summarize_speed_test(
        &serde_json::Map::new(),
        &intended,
        4,
        Some(InterruptReason::CoreExited),
    );
    assert_eq!(
        s,
        SpeedTestSummary {
            ok: 0,
            failed: 0,
            absent: 4,
            // 「四分」的第四类：全员缺席**不是**让位，而是核死了 —— 用户的下一步动作完全不同。
            absent_reason: Some(InterruptReason::CoreExited),
        }
    );
}

fn srv(id: &str, protocol: Protocol) -> ServerConfig {
    ServerConfig {
        id: id.to_string(),
        name: format!("node-{id}"),
        protocol,
        address: "example.com".to_string(),
        port: 443,
        uuid: Some("u-1".to_string()),
        ..Default::default()
    }
}

// ══════════════════════════════════════════════════════════════════════════
// temp_core_tag / plan_temp_core：进核前的裁定。每条盯一个「整批测不成」的面。
// ══════════════════════════════════════════════════════════════════════════

/// tag = `out-<id 前 8 位>`（1:1 上游 `:443`）。变异（取全 id / 换前缀）→ 转红：
/// tag 是入站路由规则与出站的**唯一绑定键**，两侧算法不一致 ⇒ 核里没有匹配出站 → 整批 FATAL。
#[test]
fn temp_core_tag_takes_first_eight_chars() {
    assert_eq!(temp_core_tag("0123456789abcdef"), "out-01234567");
    assert_eq!(temp_core_tag("abc"), "out-abc", "短 id 不得 panic / 补位");
}

/// **tailscale 一律缺席**：临时核建不出第二个 tsnet 实例，且会与主核抢同一份 tailscale-state。
///
/// **变异锁**：删掉这条腿 → `testable` 多出 ts 节点、`tailscale` 列表空 → 两条断言全红。
/// 那不是「多测一个」——它会去写主核的登录态目录，把用户已登录的 TS 节点写坏。
#[test]
fn plan_excludes_tailscale_nodes() {
    let plan = plan_temp_core(
        &[
            srv("a1111111", Protocol::Vless),
            srv("t1111111", Protocol::Tailscale),
        ],
        &env(),
    );
    assert_eq!(plan.testable.len(), 1);
    assert_eq!(plan.testable[0].id, "a1111111");
    assert_eq!(plan.tailscale, vec!["t1111111".to_string()]);
}

/// **naive 缺 cronet → 缺席，且成因如实登记**（进核会预初始化 FATAL 拖垮**整批**，不是只坏它自己）。
///
/// **变异锁**：① 删掉 `!env.has_cronet` 判据 → naive 节点进 testable → 转红；② 把这条腿的成因写成
/// `BuildFailed` → 转红（两类缺席互换就等于把「本机缺个动态库」说成「这个节点配错了」，用户的下一步
/// 动作完全相反）。
#[test]
fn plan_excludes_naive_when_cronet_missing() {
    let mut e = env();
    e.has_cronet = false;
    let plan = plan_temp_core(
        &[
            srv("n1111111", Protocol::Naive),
            srv("v1111111", Protocol::Vless),
        ],
        &e,
    );
    assert_eq!(
        plan.unusable,
        vec![("n1111111".to_string(), UnusableReason::NaiveWithoutCronet)]
    );
    assert_eq!(plan.testable.len(), 1);
}

/// cronet 可用时 naive 照常进核（预筛不得误伤正常路径）。
#[test]
fn plan_keeps_naive_when_cronet_available() {
    let plan = plan_temp_core(&[srv("n1111111", Protocol::Naive)], &env());
    assert_eq!(plan.testable.len(), 1);
    assert!(plan.unusable.is_empty());
}

/// **tag 碰撞消歧**：两个 id 前 8 位相同的节点 → 各拿一个唯一 tag，**都照常进核测**。
///
/// 旧行为是「后来者出局记 `unusable`」。而 id **不保证是 uuid**：手输/导入常见 `mynode-a1` /
/// `mynode-a2`，前 8 位逐字相同 ⇒ 碰撞是**确定性**的，那个节点于是每次都以笼统的 `notInPool`
/// 缺席、用户无从修复（他不知道要去改 id 的前 8 位）。
///
/// **变异锁**：① 退回「后来者出局」→ `testable.len()` / `unusable` 两条断言转红；② 干脆不消歧
/// （两个同 tag 出站）→ tag 互异断言转红，真机则是核启动 FATAL ⇒ **整批**一个都测不成。
#[test]
fn plan_disambiguates_colliding_tags_instead_of_dropping_the_node() {
    let plan = plan_temp_core(
        &[
            srv("dup00000-a", Protocol::Vless),
            srv("dup00000-b", Protocol::Vless),
            srv("dup00000-c", Protocol::Vless),
        ],
        &env(),
    );
    assert_eq!(plan.testable.len(), 3, "碰撞不得让任何节点出局");
    assert!(plan.unusable.is_empty(), "碰撞不再是「不可用」");
    let tags: Vec<&str> = plan.testable.iter().map(|n| n.tag.as_str()).collect();
    assert_eq!(
        tags,
        vec!["out-dup00000", "out-dup00000-2", "out-dup00000-3"],
        "碰撞按序号消歧（同 tag 两个出站 ⇒ 核启动 FATAL）"
    );
    // 入站路由键 `in-<tag>` 随之互异 —— 否则两个入站同 tag，同样 FATAL。
    assert_eq!(
        tags.iter().collect::<BTreeSet<_>>().len(),
        3,
        "tag 必须两两互异"
    );
}

/// **构造失败 → 缺席，且带上卡在哪一步**（WG 缺 privateKey）。绝不放半截出站进核。
///
/// **变异锁**：① 把构造失败腿改成「塞个空 outbound 进去」→ `testable` 非空 → 转红；② 把成因写成
/// `NaiveWithoutCronet` 或把步骤串抹成空 → 转红（那条串是「这个节点为什么每轮都缺席」的唯一线索）。
#[test]
fn plan_reports_build_failure_as_unusable() {
    let plan = plan_temp_core(&[srv("w1111111", Protocol::Wireguard)], &env());
    assert!(plan.testable.is_empty(), "缺 wireguardSettings 应构造失败");
    assert_eq!(
        plan.unusable,
        vec![(
            "w1111111".to_string(),
            UnusableReason::BuildFailed("wireguard 端点构造")
        )]
    );
}

/// 构造失败后 tag 必须**归还**：否则同 tag 的下一个（能建成的）节点会被误判成碰撞而白白出局。
/// **变异锁**：删掉 `seen_tags.remove(&tag)` → 第二个节点落进 unusable → 转红。
#[test]
fn plan_returns_tag_slot_when_build_failed() {
    let plan = plan_temp_core(
        &[
            srv("dup00000-w", Protocol::Wireguard), // 构造必失败
            srv("dup00000-v", Protocol::Vless),     // 同 tag，但能建成
        ],
        &env(),
    );
    assert_eq!(plan.testable.len(), 1);
    assert_eq!(plan.testable[0].id, "dup00000-v");
}

/// 出站里的 `detour` 必须剥掉：链式前置节点的 tag 在临时核里不存在 ⇒ 留着必 FATAL。
/// **变异锁**：删掉 `obj.remove("detour")` → 断言转红。
#[test]
fn plan_strips_detour_from_outbound() {
    let mut s = srv("d1111111", Protocol::Vless);
    s.detour = Some("some-other-node".to_string());
    let plan = plan_temp_core(&[s], &env());
    assert_eq!(plan.testable.len(), 1);
    assert!(
        plan.testable[0].node.get("detour").is_none(),
        "detour 指向临时核里不存在的 tag ⇒ 核启动 FATAL ⇒ 整批测不成"
    );
}

/// 停核测速必须继承真实连接使用的显式网卡；ShadowTLS 的绑定要落在真正拨号的外层，不能留在
/// Shadowsocks 内层。否则测速与连接会走不同出口，所得数值没有决策价值。
#[test]
fn plan_applies_explicit_bindings_to_the_physical_dialer() {
    use polaris_config_engine::user_config::protocol_settings::{
        OpenconnectSettings, ShadowTlsSettings, ShadowsocksSettings,
    };

    let plain = srv("plain111", Protocol::Vless);
    let vpn = ServerConfig {
        id: "vpn11111".into(),
        name: "VPN".into(),
        protocol: Protocol::Openconnect,
        openconnect_settings: Some(Box::new(OpenconnectSettings {
            server: Some("vpn.example.com:443".into()),
            ..Default::default()
        })),
        ..Default::default()
    };
    let mut shadow = srv("shadow11", Protocol::Shadowsocks);
    shadow.shadowsocks_settings = Some(Box::new(ShadowsocksSettings {
        method: "aes-128-gcm".into(),
        password: "inner-secret".into(),
        ..Default::default()
    }));
    shadow.shadow_tls_settings = Some(ShadowTlsSettings {
        password: "secret".into(),
        sni: "tls.example.com".into(),
        fingerprint: Some("Chrome".into()),
        port: Some(8443),
    });
    let bindings = BTreeMap::from([
        (plain.id.clone(), "eth-plain".to_string()),
        (vpn.id.clone(), "eth-vpn".to_string()),
        (shadow.id.clone(), "eth-shadow".to_string()),
    ]);
    let plan = plan_temp_core_with_bindings(&[plain, vpn, shadow], &env(), &bindings);
    assert_eq!(plan.testable.len(), 3);

    assert_eq!(plan.testable[0].node["bind_interface"], json!("eth-plain"));
    assert_eq!(plan.testable[1].node["bind_interface"], json!("eth-vpn"));
    assert!(plan.testable[1].is_endpoint);

    let shadow = &plan.testable[2];
    assert!(shadow.node.get("bind_interface").is_none());
    assert_eq!(shadow.node["detour"], json!("stls-out-shadow11"));
    assert_eq!(shadow.companion_outbounds.len(), 1);
    let outer = &shadow.companion_outbounds[0];
    assert_eq!(outer["type"], json!("shadowtls"));
    assert_eq!(outer["server_port"], json!(8443));
    assert_eq!(outer["tls"]["utls"]["fingerprint"], json!("chrome"));
    assert_eq!(outer["bind_interface"], json!("eth-shadow"));

    let config = build_temp_core_config(&plan.testable, &[20001, 20002, 20003], "warn");
    assert!(config["outbounds"]
        .as_array()
        .is_some_and(|items| items.iter().any(|item| item["tag"] == outer["tag"])));
}

/// 真内核静态验收：ShadowTLS 复合出站 + 显式网卡必须被随包 sing-box 接受。
///
/// 运行示例：
/// `POLARIS_SINGBOX_PATH="$PWD/resources/linux/sing-box" POLARIS_TEST_INTERFACE=eno1 cargo test -p polaris --bin polaris real_core_accepts_bound_shadow_tls_temp_config -- --ignored --nocapture`
#[tokio::test]
#[ignore = "真机验证：需 POLARIS_SINGBOX_PATH 与 POLARIS_TEST_INTERFACE；非 CI 门"]
async fn real_core_accepts_bound_shadow_tls_temp_config() {
    let _real_core_guard = crate::runtime::REAL_CORE_TEST_LOCK.lock().await;
    use polaris_config_engine::user_config::protocol_settings::{
        ShadowTlsSettings, ShadowsocksSettings,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    let core = PathBuf::from(
        std::env::var("POLARIS_SINGBOX_PATH")
            .expect("POLARIS_SINGBOX_PATH 必须指向待验收的真实 sing-box"),
    );
    assert!(core.is_file(), "sing-box 不存在：{}", core.display());
    let interface = std::env::var("POLARIS_TEST_INTERFACE")
        .expect("POLARIS_TEST_INTERFACE 必须是本机真实 InterfaceAlias/接口名");
    let mut server = srv("shadow-real", Protocol::Shadowsocks);
    server.shadowsocks_settings = Some(Box::new(ShadowsocksSettings {
        method: "aes-128-gcm".into(),
        password: "inner-secret".into(),
        ..Default::default()
    }));
    server.shadow_tls_settings = Some(ShadowTlsSettings {
        password: "shape-only-secret".into(),
        sni: "tls.example.com".into(),
        fingerprint: Some("Chrome".into()),
        port: Some(8443),
    });
    let plan = plan_temp_core_with_bindings(
        &[server],
        &env(),
        &BTreeMap::from([("shadow-real".into(), interface)]),
    );
    let config = build_temp_core_config(&plan.testable, &[39191], "warn");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "polaris-shadowtls-check-{}-{nonce}.json",
        std::process::id()
    ));
    tokio::fs::write(&path, serde_json::to_vec_pretty(&config).unwrap())
        .await
        .expect("write temporary config");
    let result = SingBoxConfigChecker.check(&core, &path).await;
    let _ = tokio::fs::remove_file(&path).await;
    result.expect("真实 sing-box 必须接受临时测速配置");
}

// ══════════════════════════════════════════════════════════════════════════
// build_temp_core_config：临时核配置形状。每条盯一个「核起不来 / 数值属于别人」的面。
// ══════════════════════════════════════════════════════════════════════════

fn plain_nodes() -> Vec<TempNode> {
    plan_temp_core(
        &[
            srv("a1111111", Protocol::Vless),
            srv("b1111111", Protocol::Trojan),
        ],
        &env(),
    )
    .testable
}

/// **入站↔端口↔出站三者逐位 1:1**。这是本模块最致命的不变式：错位一格 ⇒ 量到的是**别的节点**的
/// 延迟并挂在这个节点名下（失真数值，比测不了更糟）。
///
/// **变异锁**：把 `zip` 换成对 ports 的独立索引 / 把 route 规则的 outbound 写成固定 tag → 转红。
#[test]
fn config_binds_inbound_port_and_outbound_one_to_one() {
    let nodes = plain_nodes();
    let cfg = build_temp_core_config(&nodes, &[20001, 20002], "warn");
    let inbounds = cfg["inbounds"].as_array().unwrap();
    assert_eq!(inbounds.len(), 2);
    assert_eq!(inbounds[0]["listen_port"], json!(20001));
    assert_eq!(inbounds[1]["listen_port"], json!(20002));
    assert_eq!(inbounds[0]["listen"], json!("127.0.0.1"), "只许监听回环");
    let rules = cfg["route"]["rules"].as_array().unwrap();
    for (i, node) in nodes.iter().enumerate() {
        assert_eq!(rules[i]["outbound"], json!(node.tag));
        assert_eq!(rules[i]["inbound"][0], json!(format!("in-{}", node.tag)));
    }
}

/// 必有 `direct` 出站（sing-box 启动要求）+ `default_domain_resolver` 指向 dns-direct。
/// **变异锁**：删掉任一 → 核启动 FATAL / 节点域名解析不了 → 整批 -1。
#[test]
fn config_has_direct_outbound_and_default_resolver() {
    let cfg = build_temp_core_config(&plain_nodes(), &[20001, 20002], "warn");
    let outbounds = cfg["outbounds"].as_array().unwrap();
    assert!(outbounds.iter().any(|o| o["type"] == json!("direct")));
    assert_eq!(cfg["route"]["default_domain_resolver"], json!("dns-direct"));
    assert_eq!(cfg["dns"]["servers"][0]["tag"], json!("dns-direct"));
}

/// **endpoint 腿的 VPN 客户端必须进 `endpoints[]`** —— 塞进 `outbounds[]` 内核 decode 阶段判
/// `unknown outbound type`，**整个临时核起不来**，同批被测的其它节点一并测不成。
///
/// 判据故意走 `plan_temp_core` 全链路而不是直接构造 `TempNode`：主核与临时核必须共同调用
/// `build_vpn_client_endpoint`，否则临时核很容易只留下 `type/tag` 空壳。手搓
/// `TempNode { is_endpoint: true }` 会绕开构造路径，无法锁住 server/port/TLS 载荷。
///
/// **变异锁**：删掉 VPN 客户端专用构造腿，或丢掉 endpoint 载荷 ⇒ 本条转红。
#[test]
fn endpoint_leg_vpn_clients_go_into_endpoints_not_outbounds() {
    use polaris_config_engine::user_config::protocol_settings::{
        OpenconnectSettings, OpenvpnClientSettings, OpenvpnTlsSettings,
    };
    let servers = vec![
        ServerConfig {
            id: "oc111111".into(),
            name: "OC".into(),
            protocol: Protocol::Openconnect,
            openconnect_settings: Some(Box::new(OpenconnectSettings {
                server: Some("vpn.example.com:443".into()),
                ..Default::default()
            })),
            ..Default::default()
        },
        ServerConfig {
            id: "ov111111".into(),
            name: "OV".into(),
            protocol: Protocol::OpenvpnClient,
            openvpn_client_settings: Some(Box::new(OpenvpnClientSettings {
                server: Some("vpn.example.com".into()),
                server_port: Some(1194),
                tls: Some(OpenvpnTlsSettings::default()),
                ..Default::default()
            })),
            ..Default::default()
        },
    ];
    let plan = plan_temp_core(&servers, &env());
    assert_eq!(plan.testable.len(), 2, "两个节点都该可测");
    for n in &plan.testable {
        assert!(
            n.is_endpoint,
            "{} 没被判成 endpoint 腿 —— 它会被塞进临时核的 outbounds[]",
            n.tag
        );
    }
    let cfg = build_temp_core_config(&plan.testable, &[20001, 20002], "warn");
    assert_eq!(
        cfg["endpoints"].as_array().map(Vec::len),
        Some(2),
        "两个 VPN 客户端都必须落 endpoints[]"
    );
    let ob_types: Vec<&str> = cfg["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|o| o["type"].as_str())
        .collect();
    assert!(
        !ob_types.contains(&"openconnect") && !ob_types.contains(&"openvpn-client"),
        "它们出现在 outbounds[] 里 ⇒ 内核 unknown outbound type，整核起不来。实得 {ob_types:?}"
    );
    let endpoints = cfg["endpoints"].as_array().unwrap();
    assert_eq!(endpoints[0]["server"], json!("vpn.example.com:443"));
    assert_eq!(endpoints[1]["server"], json!("vpn.example.com"));
    assert_eq!(endpoints[1]["server_port"], json!(1194));
    assert!(
        endpoints[1].get("tls").is_some(),
        "OpenVPN TLS 载荷不得丢失"
    );
    assert!(
        cfg["route"].get("auto_detect_interface").is_none(),
        "无 TUN 的临时核必须保留 OS 逐目的路由"
    );
}

#[test]
fn vpn_client_without_settings_is_excluded_before_temp_core_start() {
    for protocol in [Protocol::Openconnect, Protocol::OpenvpnClient] {
        let node = ServerConfig {
            id: format!("missing-{protocol:?}"),
            name: "missing settings".into(),
            protocol,
            ..Default::default()
        };
        let plan = plan_temp_core(std::slice::from_ref(&node), &env());
        assert!(plan.testable.is_empty());
        assert_eq!(
            plan.unusable,
            vec![(
                node.id.clone(),
                UnusableReason::BuildFailed("vpn-client 协议设置缺失")
            )]
        );
    }
}

/// **纯代理配置零端点噪声**：没有端点节点时不得下发 `endpoints[]` / `dns.rules`
/// （空数组会让核对 schema 更挑剔，且掩盖「到底有没有端点」这件事）。
/// **变异锁**：无条件写 `endpoints`/`dns.rules` → 转红。
#[test]
fn config_omits_endpoint_sections_for_plain_proxies() {
    let cfg = build_temp_core_config(&plain_nodes(), &[20001, 20002], "warn");
    assert!(cfg.get("endpoints").is_none());
    assert!(cfg["dns"].get("rules").is_none());
}

/// **不得引入 sniff / 目标域名的本地解析**（issue #154 的两类解析不变量之一）：
/// 代理出站的目标域名必须 `ATYP=domain` 透传给出口远程解析，否则所有节点测的是同一条本机解析路径。
///
/// **变异锁**：加 `"sniff": true` 或给 route 规则加 `domain_strategy` → 转红。
#[test]
fn config_never_enables_sniff_or_local_target_resolution() {
    let cfg = build_temp_core_config(&plain_nodes(), &[20001, 20002], "warn");
    let raw = serde_json::to_string(&cfg).unwrap();
    assert!(
        !raw.contains("sniff"),
        "sniff 会破坏「目标域名由出口远程解析」不变量"
    );
    assert!(
        !raw.contains("domain_strategy"),
        "针对目标的本地解析会把各节点测成同一条本机路径"
    );
}

/// 日志级别透传（诊断态抬级用）。变异（硬编码 warn）→ 转红。
#[test]
fn config_passes_through_log_level() {
    let cfg = build_temp_core_config(&plain_nodes(), &[1, 2], "debug");
    assert_eq!(cfg["log"]["level"], json!("debug"));
}

/// 端点节点：进 `endpoints[]` + 配一条**按 inbound 键控**的穿隧道 DNS 规则（`disable_cache` 必开）。
///
/// **变异锁**：① 把端点塞进 `outbounds` → `endpoints` 缺失转红；② 删掉 dns.rules → 转红
/// （端点目标解析回落本机 geo IP，境外出口够不着 → 全批超时）；③ 关掉 `disable_cache` → 转红
/// （多端点并测时共享缓存互相污染，量到的是别人出口解析出来的 IP）。
#[test]
fn config_wires_endpoint_nodes_with_tunneled_dns() {
    let node = TempNode {
        id: "e1111111".to_string(),
        tag: "out-e1111111".to_string(),
        node: json!({ "type": "wireguard", "tag": "out-e1111111" }),
        companion_outbounds: Vec::new(),
        is_endpoint: true,
        has_local_v6: false,
    };
    let cfg = build_temp_core_config(&[node], &[20001], "warn");
    assert_eq!(cfg["endpoints"].as_array().unwrap().len(), 1);
    // 纯 v4 端点：rules[0] 是 AAAA 抑制（见下一条），route 规则排在它**后面**。
    let rule = &cfg["dns"]["rules"][1];
    assert_eq!(rule["inbound"][0], json!("in-out-e1111111"));
    assert_eq!(rule["server"], json!("dns-exit-out-e1111111"));
    assert_eq!(rule["disable_cache"], json!(true));
    // 穿隧道 DNS server 必须 detour 到本端点 tag（否则查询从本机发，等于没穿隧道）。
    let exit = cfg["dns"]["servers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["tag"] == json!("dns-exit-out-e1111111"))
        .expect("端点必须配自己的穿隧道 DNS server");
    assert_eq!(exit["detour"], json!("out-e1111111"));
}

/// 🔴 **纯 v4 端点：AAAA 前置一条 `predefined` 空 NOERROR，且必须排在 route 规则之前**
/// （旧 legacy `strategy: ipv4_only` 的等价写法，1:1 上游 `0875f66`(#334)）。
///
/// 顺序有牙：DNS 规则先匹配先命中，route 规则是该 inbound 的 catch-all —— 抑制规则排它后面则
/// AAAA 先被 route 吃掉、抑制**静默失效**，而配置照样通过 `sing-box check`。
///
/// **变异锁**：① 删掉抑制规则 → 长度断言红；② 两条规则顺序颠倒 → 顺序断言红；
/// ③ 键名写错（`query_types` / `rcode` 拼错）→ 形状断言红。
#[test]
fn config_suppresses_aaaa_before_routing_for_v4_only_endpoints() {
    let node = TempNode {
        id: "e1111111".to_string(),
        tag: "out-e1111111".to_string(),
        node: json!({ "type": "wireguard", "tag": "out-e1111111" }),
        companion_outbounds: Vec::new(),
        is_endpoint: true,
        has_local_v6: false,
    };
    let cfg = build_temp_core_config(&[node], &[20001], "warn");
    let rules = cfg["dns"]["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 2, "纯 v4 端点 = 抑制规则 + route 规则");
    assert_eq!(
        rules[0],
        json!({
            "inbound": ["in-out-e1111111"],
            "query_type": ["AAAA"],
            "action": "predefined",
            "rcode": "NOERROR",
        }),
        "抑制规则形状必须逐字对齐（键名写错 = 静默失效）"
    );
    assert_eq!(
        rules[1]["action"],
        json!("route"),
        "抑制规则必须排在同 inbound 的 route（catch-all）之前，否则 AAAA 先被 route 吃掉"
    );
}

/// WG 本地地址含 v6 → **不下发任何族别偏好**（等价旧 `prefer_ipv4`：无顶层 strategy 时内核默认
/// 并发 A/AAAA 且 v4 排前）。对齐 上游 `:868-877`。
///
/// **变异锁**：把抑制规则无条件下发（丢掉 `!node.has_local_v6` 判据）→ 规则数变 2 → 转红；
/// 那在真机上的后果是双栈 WG 端点的 v6 解析被砍掉。
#[test]
fn config_emits_no_family_preference_for_dual_stack_endpoints() {
    let node = TempNode {
        id: "e2222222".to_string(),
        tag: "out-e2222222".to_string(),
        node: json!({ "type": "wireguard" }),
        companion_outbounds: Vec::new(),
        is_endpoint: true,
        has_local_v6: true,
    };
    let cfg = build_temp_core_config(&[node], &[20001], "warn");
    let rules = cfg["dns"]["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 1, "含 v6 的端点只有 route 规则，无抑制规则");
    assert_eq!(rules[0]["action"], json!("route"));
}

/// 🔴 **全配置禁 1.16 DNS 旧形态**：legacy rule-action `strategy` 与未启用
/// `match_response` 的 address-filter。前者与同一份 DNS 配置内任何
/// 带 `query_type`/`ip_version` 的规则**互斥**，共存即 `initialize dns router` FATAL —— 而
/// `check` 静默放行，我们起核前那道 check 抓不到）。
///
/// **前置断言防平凡通过**：先证明本配置**确实**含 `query_type`（否则「无 strategy」这条在一个空
/// 规则集上恒真、门是假的），再用 config-engine 的同一个上下文谓词断言零命中。
///
/// **变异锁**：把 `"strategy": ...` 写回任一规则 → 转红；偷加顶层 `dns.strategy` → 转红。
#[test]
fn temp_core_dns_never_sets_a_legacy_or_top_level_strategy() {
    use polaris_config_engine::legacy_keys::removed_in_1_16_config_paths;

    let node = TempNode {
        id: "e1111111".to_string(),
        tag: "out-e1111111".to_string(),
        node: json!({ "type": "wireguard", "tag": "out-e1111111" }),
        companion_outbounds: Vec::new(),
        is_endpoint: true,
        has_local_v6: false,
    };
    let cfg = build_temp_core_config(&[node], &[20001], "warn");
    let raw = serde_json::to_string(&cfg["dns"]).unwrap();
    assert!(
        raw.contains("query_type"),
        "前置断言：本配置必须确实带 query_type，否则下面的「禁 strategy」是空集平凡通过"
    );
    let hits = removed_in_1_16_config_paths(&cfg);
    assert!(
        hits.is_empty(),
        "临时核配置命中 1.16 DNS 旧形态：{hits:?}\n{raw}"
    );
    assert!(
        cfg["dns"].get("strategy").is_none(),
        "顶层 dns.strategy 是「省略 == prefer_ipv4」这条等价性的前提，不得下发"
    );
}

// ══════════════════════════════════════════════════════════════════════════
// 让位判据 + 分批。
// ══════════════════════════════════════════════════════════════════════════

/// 主核没起、没在起、世代未变 → 未让位（正常临时核测速全程走这条，误判即一个节点都测不成）。
///
/// **反向变异锁**：把判据写成恒真（或多加一条恒真的腿）→ 本测转红。没有这条，下面三条「必要性」
/// 断言可以被一个 `true` 全部满足。
#[test]
fn temp_core_not_superseded_when_main_core_absent() {
    assert!(!is_temp_core_superseded(7, 7, false, false));
}

/// 🔴 **第一腿（世代）的必要性**：只有世代跃迁（用户点了连接 / 停止），另两腿都为假。
///
/// 交错窗口：`start` 已 bump 完世代且核已**停**（stop→start 序列 / 起核失败回落）——此刻
/// `running` 与 `starting` 都可能是 false，唯一可见的证据就是世代变了。
/// **变异锁**：删掉 `gen_now != gen0` 这条腿 → 本测转红。
#[test]
fn temp_core_superseded_on_generation_change_alone() {
    assert!(is_temp_core_superseded(8, 7, false, false));
}

/// 🔴 **第二腿（running）的必要性**：主核**已经跑起来了**，而世代与本次基准相同、也不在启动中。
///
/// 交错窗口：bump 发生在本次取 `gen0` **之前**（那一刻 running 还是 false，核在启动中），随后核就绪
/// ⇒ running 翻真、starting 归假、世代不再动。三腿里只剩这一条能看见主核。
/// **变异锁**：删掉 `running` 腿 → 本测转红；真机表现是**两个核并存**跑同一批 WG/WARP peer
/// （上游 G1 的双会话超时事故）。
#[test]
fn temp_core_superseded_once_main_core_is_running_alone() {
    assert!(is_temp_core_superseded(7, 7, true, false));
}

/// 🔴 **第三腿（starting）的必要性**：主核**正在启动**——世代已 bump 完（⇒ 与本次 `gen0` 相同）、
/// 核尚未就绪（⇒ `running == false`）。前两腿在这一整段里**同时**为假。
///
/// 窗口有多宽：`ProxyRuntime::start` 的顺序是 `start_inflight+1`（`starting` 的源）→ **stale 清扫
/// （真机可达数秒）** → `bump_generation` → spawn → 就绪门（最长 10s 级）。用户点「连接」后紧接点
/// 测速（或托盘/另一窗口点——UI 灰态拦不住跨窗）就确定性落在这段里。
///
/// **变异锁**：删掉 `starting` 腿 → 本测转红；真机表现有两层：① 临时核与启动中的主核同 peer 双会话
/// 踢线；② 临时核端口只排除 control/http/mixed，会抢走主核刚解析、尚未 bind 的 api/update-in/probe
/// 池口 ⇒ 主核起核 FATAL address-in-use（用户看到的是「连接失败」）。
#[test]
fn temp_core_superseded_while_main_core_is_starting_alone() {
    assert!(is_temp_core_superseded(7, 7, false, true));
}

// ══════════════════════════════════════════════════════════════════════════
// drive_temp_core_measures：滑动窗口调度 + 让位三检查点（全注入，无进程无网络）。
//
// 每条用例都要给一个「核观测面」（[`TempCoreWatch`]，A3 两条腿的入参束）。默认用 [`healthy_watch`]
// ——核不会自己死、复探恒答「还在」——即**只**驱动让位与调度语义，与改造前逐字等价。A3 两条腿
// 各有专门的用例在下面单独驱动。

/// 「这个核一切正常」的观测面：`exited` 永挂（核不会自己退出），复探恒 `true`（核仍在接受连接）。
///
/// `pending()` 而不是「立即完成」：夹具若让 `wait()` 立刻返回，接上 `select!` 之后**每一条**会话用例
/// 都会被误判成「核死了」——这正是夹具语义门要挡的那件事（见 `fake_child_wait_must_not_resolve_by_default`）。
fn healthy_watch() -> TempCoreWatch<'static> {
    TempCoreWatch {
        pid: 0,
        exited: Box::pin(std::future::pending()),
        probe_port: Arc::new(|_| true),
        port: 1,
    }
}

/// **测试壳**：以「一轮只有一批」的账驱动 [`drive_temp_core_measures`]，跑完在同一处发终态事件。
///
/// # 它替代了什么、又没替代什么
///
/// 分批（T1-R1）之前，终态事件由 `drive_temp_core_measures` 自己发，本节这批「调度 + 让位三检查点 +
/// 核观测两条腿」的用例因此可以直接在它的事件流里断言 DONE。分批之后终态上移到了**轮**级
/// （[`TempCoreSession::run`] 的唯一出口）——因为一轮 k 批就会是 k 条终态，而前端收到第一条就把
/// sticky 收口了。本壳把那一步在测试侧原样补上，好让本节用例**逐字不变**：它们测的是批内编排，
/// 与分批无关，改判据只会引入无谓的漂移。
///
/// ⚠️ **它不能替代生产接线的门**：「`run` 真的会发那一条终态」「载荷是轮级口径而不是批级」
/// 「k 批只发一条」这三件事本壳一件都证明不了（它自己就在发）。那三条由本文件末尾「分批」一节的
/// `a_round_emits_exactly_one_terminal_event_with_round_wide_scope` 直接驱动生产路径守住。
#[allow(clippy::too_many_arguments)]
async fn drive_round_of_one_batch<Meas, MeasFut>(
    nodes: &[TempNode],
    ports: &[u16],
    concurrency: usize,
    superseded: &(dyn Fn() -> bool + Sync),
    watch: &mut TempCoreWatch<'_>,
    measure: Meas,
    emit: &mut (dyn FnMut(&str, Value) + Send),
) -> (serde_json::Map<String, Value>, &'static str)
where
    Meas: Fn(u16) -> MeasFut,
    MeasFut: std::future::Future<Output = Option<u32>> + Send + 'static,
{
    let intended: Vec<String> = nodes
        .iter()
        .take(nodes.len().min(ports.len()))
        .map(|n| n.id.clone())
        .collect();
    let mut progress = RoundProgress::new(intended.len());
    let (results, outcome) = drive_temp_core_measures(
        nodes,
        ports,
        concurrency,
        superseded,
        watch,
        measure,
        emit,
        &mut progress,
    )
    .await;
    emit_speed_test_done(emit, outcome, &results, &intended, progress.reason());
    (results, outcome)
}

//
// 此前这里还有 `plan_temp_batches`（纯逻辑切批）的两条单测。批屏障换成滑动窗口后**没有批这个
// 概念了**，那个函数与它的两条测试一并删除 —— 不是放宽，是把断言下移到真正的调度器上：
//  · 「N/limit 切批」→ 由 `never_exceeds_the_concurrency_limit`（真实在飞峰值 ≤ 上限）替代，
//    这条比切批断言强：它测的是实际并发，而切批只测了一个不再被消费的纯函数；
//  · 「limit==0 退化成 1、绝不吞掉节点」→ 由 `zero_concurrency_degrades_to_serial_not_to_nothing`
//    保留同名同义，只是从「测 plan 的返回值」改成「测 drive 真的把每个节点都测了」。
// ══════════════════════════════════════════════════════════════════════════

/// 按「第几次询问」脚本化让位信号（0 = 从不让位）。
fn superseded_at(trip: usize) -> impl Fn() -> bool {
    let calls = AtomicUsize::new(0);
    move || {
        let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
        trip != 0 && n >= trip
    }
}

fn three_nodes() -> Vec<TempNode> {
    ["a1111111", "b1111111", "c1111111"]
        .iter()
        .map(|id| TempNode {
            id: (*id).to_string(),
            tag: temp_core_tag(id),
            node: json!({}),
            companion_outbounds: Vec::new(),
            is_endpoint: false,
            has_local_v6: false,
        })
        .collect()
}

/// 全程未让位 → 全部节点有结果 + `completed` + 每节点恰一条 result/progress。
/// 这是「让位检查不得误伤正常路径」的基准。
#[tokio::test]
async fn measures_all_nodes_when_never_superseded() {
    let mut events: Vec<String> = Vec::new();
    let (results, outcome) = drive_round_of_one_batch(
        &three_nodes(),
        &[1, 2, 3],
        2,
        &superseded_at(0),
        &mut healthy_watch(),
        |_| async { Some(120_u32) },
        &mut |ev, _| events.push(ev.to_string()),
    )
    .await;
    assert_eq!(outcome, "completed");
    assert_eq!(results.len(), 3);
    assert_eq!(results["a1111111"], json!(120));
    assert_eq!(
        events
            .iter()
            .filter(|e| *e == EVENT_SPEED_TEST_RESULT)
            .count(),
        3
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| *e == EVENT_SPEED_TEST_PROGRESS)
            .count(),
        3
    );
}

/// **真实超时仍记 -1**（测不通是真的）→ 让位检查不得把它吞成缺席。
/// 与下一条成对：把「真实 -1」与「让位缺席」钉成两种结局，正是本腿诚实性的全部意义。
#[tokio::test]
async fn genuine_timeout_is_recorded_as_minus_one() {
    let (results, outcome) = drive_round_of_one_batch(
        &three_nodes(),
        &[1, 2, 3],
        8,
        &superseded_at(0),
        &mut healthy_watch(),
        |_| async { None },
        &mut |_, _| {},
    )
    .await;
    assert_eq!(outcome, "completed");
    assert_eq!(results["a1111111"], json!(-1));
}

/// 让位①（发新活之前）：第 1 次询问即让位 → 一个节点都不测、零**逐节点**事件、`interrupted`。
///
/// # 断言从「零事件」改成「零逐节点事件 + 恰一条终态事件」的理由
///
/// 本条原文是 `events.is_empty()`。终态事件（2026-07-31 B 批）落地后，**中断路径恰恰必须发一条**
/// —— 原断言留着等于禁止本批的核心行为。守的那条诚实性根基不变：逐节点 result/progress 一条不许有。
/// 顺带钉住载荷：一个都没测 ⇒ `pending` 必须是**全集**（这也是续测的输入）。
#[tokio::test]
async fn interrupts_before_dispatching_without_measuring() {
    let mut events: Vec<(String, Value)> = Vec::new();
    let (results, outcome) = drive_round_of_one_batch(
        &three_nodes(),
        &[1, 2, 3],
        8,
        &superseded_at(1),
        &mut healthy_watch(),
        |_| async { Some(120_u32) },
        &mut |ev, payload| events.push((ev.to_string(), payload)),
    )
    .await;
    assert_eq!(outcome, "interrupted");
    assert!(results.is_empty(), "让位下未测节点必须缺席，绝不写假 -1");
    assert!(
        events
            .iter()
            .all(|(ev, _)| ev != EVENT_SPEED_TEST_RESULT && ev != EVENT_SPEED_TEST_PROGRESS),
        "让位轮不得推逐节点事件：{events:?}"
    );
    let done: Vec<&Value> = events
        .iter()
        .filter(|(ev, _)| ev == EVENT_SPEED_TEST_DONE)
        .map(|(_, p)| p)
        .collect();
    assert_eq!(done.len(), 1, "中断也必须**恰好**发一条终态事件");
    assert_eq!(done[0]["outcome"], json!("interrupted"));
    assert_eq!(done[0]["tested"], json!(0));
    assert_eq!(
        done[0]["serverIds"],
        json!(["a1111111", "b1111111", "c1111111"]),
        "重新测速必须拿到本轮原始范围"
    );
    assert_eq!(
        done[0]["pending"],
        json!(["a1111111", "b1111111", "c1111111"]),
        "一个都没测 ⇒ pending 必须是全集"
    );
}

/// 让位②（测量后）：在飞期间主核起来 → 丢弃在飞值（它与主核抢同一条 peer 会话，数值不可信）。
///
/// **变异锁**：删掉这道检查 → 那批值被写进 results、outcome 变 completed → 两条断言全红。
/// 最危险的假绿形态：双会话下测量多半失败，`None → -1` 恰好「看起来很合理」。
#[tokio::test]
async fn discards_in_flight_values_when_main_core_arrives() {
    let (results, outcome) = drive_round_of_one_batch(
        &three_nodes(),
        &[1, 2, 3],
        8,
        &superseded_at(2), // 批首过、测量后命中
        &mut healthy_watch(),
        |_| async { Some(999_u32) },
        &mut |_, _| {},
    )
    .await;
    assert_eq!(outcome, "interrupted");
    assert!(results.is_empty(), "跨核在飞值必须丢弃，不得写入结果集");
}

/// 前两个节点正常、第三个之前让位 → 已测部分**保留**，未测缺席。中断 ≠ 丢弃已拿到的真值。
///
/// **trip 编号随调度形态变化（不是放宽门槛）**：3 节点 / 窗口 2 的询问序列是
/// `发活①(补 a,b) → 节点a → 发活②(补 c) → 节点b → 节点c`，第 5 次落在**节点 c 测完那一刻**
/// ⇒ c 的值被丢弃、a/b 保留。命中语义与改前逐字相同：先测完的两个留下，第三个缺席。
#[tokio::test]
async fn keeps_measured_prefix_on_later_interruption() {
    let (results, outcome) = drive_round_of_one_batch(
        &three_nodes(),
        &[1, 2, 3],
        2,
        &superseded_at(5),
        &mut healthy_watch(),
        |_| async { Some(120_u32) },
        &mut |_, _| {},
    )
    .await;
    assert_eq!(outcome, "interrupted");
    assert_eq!(results.len(), 2, "先测完的两个节点应保留");
    assert!(!results.contains_key("c1111111"), "最后一个未落账 → 缺席");
}

/// 🔴 **worker 池（滑动窗口）而非批屏障**：一个慢节点只占住 1/K 的算力，绝不把整批钉死。
///
/// 这是 S2 的**收益本体**。批屏障下 `Σ 每批最大值` —— 一个 8s 的死节点让同批 15 个健康节点也等
/// 8s；worker 池下界是 `max(单点最坏, 总功/K)`，死节点只堵一个槽。f=0.2/K=16 时「每批至少一个
/// 死节点」的概率是 0.97 ⇒ 几乎每批都被封顶，两者相差 W=⌈N/K⌉ 倍。
///
/// 构造：窗口 2，节点① 慢（400ms），节点②③④ 秒回。滑动窗口下 ②③④ 全部在 ① 之前回来；
/// 批屏障下 ③④ 属第二批，必须等 ① 收尾 ⇒ 落在 ① 之后。
/// **变异锁**：改回 `plan_temp_batches` 批屏障 → `slow-done` 跑到 ③④ 前面 → 转红。
#[tokio::test]
async fn a_slow_node_does_not_block_the_rest_of_the_queue() {
    let nodes: Vec<TempNode> = ["s1111111", "f2222222", "f3333333", "f4444444"]
        .iter()
        .map(|id| TempNode {
            id: (*id).to_string(),
            tag: temp_core_tag(id),
            node: json!({}),
            companion_outbounds: Vec::new(),
            is_endpoint: false,
            has_local_v6: false,
        })
        .collect();
    let log = Arc::new(Mutex::new(Vec::<String>::new()));
    let mlog = Arc::clone(&log);
    let elog = Arc::clone(&log);
    let (results, outcome) = drive_round_of_one_batch(
        &nodes,
        &[1, 2, 3, 4],
        2, // 窗口 2：慢节点占住一个槽，另一个槽必须继续轮转
        &superseded_at(0),
        &mut healthy_watch(),
        move |port| {
            let mlog = Arc::clone(&mlog);
            async move {
                if port == 1 {
                    tokio::time::sleep(Duration::from_millis(400)).await;
                    mlog.lock().unwrap().push("slow-done".to_string());
                }
                Some(120_u32)
            }
        },
        &mut |ev, payload| {
            if ev == EVENT_SPEED_TEST_RESULT {
                let id = payload["serverId"].as_str().unwrap().to_string();
                elog.lock().unwrap().push(format!("emit:{id}"));
            }
        },
    )
    .await;

    assert_eq!(outcome, "completed");
    assert_eq!(results.len(), 4, "四个节点全部要有结果");
    let log = log.lock().unwrap();
    let slow = log
        .iter()
        .position(|l| l == "slow-done")
        .expect("慢节点必须测完");
    for id in ["f3333333", "f4444444"] {
        let fast = log
            .iter()
            .position(|l| *l == format!("emit:{id}"))
            .unwrap_or_else(|| panic!("{id} 必须回填"));
        assert!(
            fast < slow,
            "队尾的健康节点必须在慢节点之前测完（批屏障会让它等满一整批）：{log:?}"
        );
    }
}

/// 🔴 **在飞并发不得超过窗口上限**：不设上限时大订阅会把 N 路 TLS/QUIC 握手同时打出去
/// → 本机 CPU/连接数打满 → 一批**假超时**（节点其实是好的）。
///
/// **变异锁**：把补位条件里的 `set.len() < window` 去掉（一次性全 spawn）→ 峰值 6 > 2 → 转红。
#[tokio::test]
async fn never_exceeds_the_concurrency_limit() {
    let nodes: Vec<TempNode> = ["n1111111", "n2222222", "n3333333", "n4444444", "n5555555"]
        .iter()
        .map(|id| TempNode {
            id: (*id).to_string(),
            tag: temp_core_tag(id),
            node: json!({}),
            companion_outbounds: Vec::new(),
            is_endpoint: false,
            has_local_v6: false,
        })
        .collect();
    let live = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let peak = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (m_live, m_peak) = (Arc::clone(&live), Arc::clone(&peak));
    let (results, outcome) = drive_round_of_one_batch(
        &nodes,
        &[1, 2, 3, 4, 5],
        2,
        &superseded_at(0),
        &mut healthy_watch(),
        move |_| {
            let (live, peak) = (Arc::clone(&m_live), Arc::clone(&m_peak));
            async move {
                let now = live.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                live.fetch_sub(1, Ordering::SeqCst);
                Some(120_u32)
            }
        },
        &mut |_, _| {},
    )
    .await;

    assert_eq!(outcome, "completed");
    assert_eq!(results.len(), 5, "全部节点都要测到");
    assert!(
        peak.load(Ordering::SeqCst) <= 2,
        "在飞峰值 {} 超过窗口上限 2",
        peak.load(Ordering::SeqCst)
    );
}

/// `concurrency == 0` 必须退化成 1，**绝不一个都不测**（零事件 ⇒ 前端测速按钮永久卡灰）。
/// **变异锁**：去掉 `.max(1)` → 窗口恒 0、一个都不 spawn、`results` 空 → 转红。
#[tokio::test]
async fn zero_concurrency_degrades_to_serial_not_to_nothing() {
    let (results, outcome) = drive_round_of_one_batch(
        &three_nodes(),
        &[1, 2, 3],
        0,
        &superseded_at(0),
        &mut healthy_watch(),
        |port| async move { Some(u32::from(port)) },
        &mut |_, _| {},
    )
    .await;
    assert_eq!(outcome, "completed");
    assert_eq!(results.len(), 3, "0 并发是配置错误，不是「不测」的意思");
    assert_eq!(results["a1111111"], json!(1), "串行也不得让结果与端口错位");
}

/// 🔴 **让位②（在飞轮询）：supersede 命中即 `abort_all` + 立刻返回，不等在飞测量收尾。**
///
/// **本腿守的是真事故面**：窗口里的节点全部不可达时，「发新活之前」与「每节点测完」两个检查点
/// 一个都醒不过来 —— 信号出现后临时核（**及其已建立的 WG/WARP 会话**）还要活满一整个测量超时，
/// 与启动中的主核同 peer 双会话踢线、并抢主核尚未 bind 的端口。Linux/macOS 靠主核 `start()` 入口
/// 的 stale sweep 顺带杀掉——那是副作用缓解、不是设计保证；Windows 无 sweep
/// （`scan_running_cores` 恒返空）⇒ 全程重叠。
///
/// 牙：删掉 `Err(_elapsed)` 那条轮询臂（或把 `timeout(poll, join_next())` 换回裸 `join_next()`）
/// → 本测的**时限**断言转红：注入的测量要 30s 才结束，而本测只给 5s。
#[tokio::test]
async fn aborts_in_flight_measurements_instead_of_waiting_for_them() {
    let started = std::time::Instant::now();
    let out = tokio::time::timeout(
        Duration::from_secs(5),
        drive_round_of_one_batch(
            &three_nodes(),
            &[1, 2, 3],
            8,
            // 发活（第 1 次询问）放行 → 全部进入在飞；在飞轮询（第 2 次）命中。
            &superseded_at(2),
            &mut healthy_watch(),
            // 测量 30s 不返回：只有真 abort 才能让本函数在 5s 内收场。
            |_| async {
                tokio::time::sleep(Duration::from_secs(30)).await;
                Some(120_u32)
            },
            &mut |_, _| {},
        ),
    )
    .await
    .expect("在飞让位必须中断在飞测量：等它收尾 = 临时核与主核重叠一整个测量超时");
    let (results, outcome) = out;
    assert_eq!(outcome, "interrupted");
    assert!(
        results.is_empty(),
        "被中断的在飞测量必须缺席，绝不补 -1（让位未测 ≠ 真实超时）"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "必须在轮询间隔量级内返回，而不是等满 30s 的在飞测量"
    );
}

/// 在飞轮询**不得误伤正常路径**：从不让位时，全部节点照常测完（轮询只是旁路）。
#[tokio::test]
async fn in_flight_polling_does_not_disturb_slow_but_uninterrupted_measurements() {
    let (results, outcome) = drive_round_of_one_batch(
        &three_nodes(),
        &[1, 2, 3],
        8,
        &superseded_at(0),
        &mut healthy_watch(),
        // 比轮询间隔长 → 至少触发一次轮询，且必须不影响结果。
        |port| async move {
            tokio::time::sleep(Duration::from_millis(TEMP_CORE_SUPERSEDE_POLL_MS + 120)).await;
            Some(u32::from(port))
        },
        &mut |_, _| {},
    )
    .await;
    assert_eq!(outcome, "completed");
    assert_eq!(results.len(), 3);
    assert_eq!(results["a1111111"], json!(1), "轮询不得让结果与端口错位");
}

/// 🔴 **逐节点回填**：先测完的节点必须在**其它节点还在飞**的时候就上屏。
///
/// 按批统一回填时，首个延迟数字要等整批最慢的那个（一批里有一个死节点就是一个完整超时），
/// 屏幕先空十几秒。总耗时一点没变，主观耗时天差地别（差异分析 R3）。
///
/// **变异锁**：改回「先 drain 完整批 → 收集循环统一 emit」→ `emit:a1111111` 落到 `c-measured`
/// 之后 → 转红。
#[tokio::test]
async fn reports_each_node_as_soon_as_it_finishes() {
    let log = Arc::new(Mutex::new(Vec::<String>::new()));
    let mlog = Arc::clone(&log);
    let elog = Arc::clone(&log);
    let (_results, outcome) = drive_round_of_one_batch(
        &three_nodes(),
        &[1, 2, 3],
        8,
        &superseded_at(0),
        &mut healthy_watch(),
        move |port| {
            let mlog = Arc::clone(&mlog);
            async move {
                // 第三个节点慢：它还没回来时，第一个节点的结果就必须已经推出去了。
                if port == 3 {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    mlog.lock().unwrap().push("c-measured".to_string());
                }
                Some(120_u32)
            }
        },
        &mut |ev, payload| {
            if ev == EVENT_SPEED_TEST_RESULT {
                let id = payload["serverId"].as_str().unwrap().to_string();
                elog.lock().unwrap().push(format!("emit:{id}"));
            }
        },
    )
    .await;

    assert_eq!(outcome, "completed");
    let log = log.lock().unwrap();
    let emit_a = log
        .iter()
        .position(|l| l == "emit:a1111111")
        .expect("首个节点必须回填");
    let c_done = log
        .iter()
        .position(|l| l == "c-measured")
        .expect("慢节点必须测完");
    assert!(
        emit_a < c_done,
        "首个节点的结果必须在慢节点回来之前就上屏（实际顺序：{log:?}）"
    );
}

/// 🔴 **进度计数恒单调**：`tested` 严格 1,2,…,N，`ok` 非降。
///
/// 前端 `NodesScreen` 靠 `tested >= total` 复位测速灰态 —— 计数一旦回退或跳号，要么按钮永久卡灰，
/// 要么进度条倒着走。**变异锁**：把 `tested` 改成按批内下标计算（或在 emit 之后才自增）→ 转红。
#[tokio::test]
async fn progress_counter_is_strictly_monotonic() {
    let mut tested_seq: Vec<i64> = Vec::new();
    let mut ok_seq: Vec<i64> = Vec::new();
    let (_results, outcome) = drive_round_of_one_batch(
        &three_nodes(),
        &[1, 2, 3],
        2, // 跨批也必须连续计数
        &superseded_at(0),
        &mut healthy_watch(),
        |port| async move {
            if port == 1 {
                None // 真实超时 → -1，不计入 ok
            } else {
                Some(120_u32)
            }
        },
        &mut |ev, payload| {
            if ev == EVENT_SPEED_TEST_PROGRESS {
                tested_seq.push(payload["tested"].as_i64().unwrap());
                ok_seq.push(payload["ok"].as_i64().unwrap());
            }
        },
    )
    .await;

    assert_eq!(outcome, "completed");
    assert_eq!(tested_seq, vec![1, 2, 3], "tested 必须严格递增且不跳号");
    assert!(
        ok_seq.windows(2).all(|w| w[1] >= w[0]),
        "ok 必须非降：{ok_seq:?}"
    );
}

/// **端口按节点索引取**：并发乱序回收不得让结果与端口错位。
/// 注入「端口 → 延迟」的一一映射，断言每个节点拿到的正是**自己**那个端口的值。
///
/// **变异锁**：把 `measure(ports[*i])` 换成 `ports[0]` / 用批内序号取端口 → 转红。
/// 这条盯的是本模块最贵的失真面：数值属于别的节点。
#[tokio::test]
async fn each_node_measures_through_its_own_port() {
    let (results, _) = drive_round_of_one_batch(
        &three_nodes(),
        &[10, 20, 30],
        8,
        &superseded_at(0),
        &mut healthy_watch(),
        |port| async move { Some(u32::from(port)) },
        &mut |_, _| {},
    )
    .await;
    assert_eq!(results["a1111111"], json!(10));
    assert_eq!(results["b1111111"], json!(20));
    assert_eq!(results["c1111111"], json!(30));
}

// ══════════════════════════════════════════════════════════════════════════
// TempCoreSession：起核 → 就绪门 → 编排 → **无条件收尾**（mock spawner，无真进程）。
// ══════════════════════════════════════════════════════════════════════════

// 假管道容量与灌注量在 `crate::test_support`：三条核腿的灌满门共用同一对常量与同一份写手
// （`flooding_stderr`）。各写一份的代价不是重复几行，而是两份会漂——容量取值一旦分叉，其中一份的
// 「绿」就悄悄变成「压根没越过容量」。
use crate::test_support::{FAKE_PIPE_CAPACITY, STDERR_FLOOD_BYTES};

/// 假瞬态核：记录 terminate 次数，永不真起进程。
struct FakeChild {
    terminated: Arc<AtomicUsize>,
    /// 假 pid（`None` = 取不到 → 就绪门 is_alive 恒真）。仅退出清理登记表那条测试用。
    pid: Option<u32>,
    /// `Some(d)` = 核在 `d` 之后**自己退出**（A3 腿一的场景）；`None` = 永不自己退出。
    die_after: Option<Duration>,
}

#[async_trait]
impl LoginCoreChild for FakeChild {
    fn pid(&self) -> Option<u32> {
        // 默认 None → pid=0 → 就绪门的 is_alive 恒真（假核不死），把判定压到 is_ready 那条腿上
        self.pid
    }
    /// **默认永不完成**（`pending`）。
    ///
    /// 🔴 这是本批必须同步改的夹具语义：改前它**立即返回**，而生产侧接上 `select!` on `child.wait()`
    /// 之后，立即返回 = 「核刚起来就死了」⇒ 每一条会话用例都会被误判成中断。夹具比生产宽容或严苛
    /// 都会让门失去信息量，这里属于后者（全红），但同样是夹具在说谎。
    async fn wait(&mut self) {
        match self.die_after {
            Some(d) => tokio::time::sleep(d).await,
            None => std::future::pending::<()>().await,
        }
    }
    async fn terminate(&mut self) {
        self.terminated.fetch_add(1, Ordering::SeqCst);
    }
}

struct FakeSpawner {
    terminated: Arc<AtomicUsize>,
    spawns: Arc<AtomicUsize>,
    fail: bool,
    /// 只让**第 k 次**（1 起数）spawn 失败 —— 分批之后「某一批起不了核」这个形态需要它。
    /// `fail`（全失败）与它是两个开关：整轮失败与单批失败在轮级的结局不同（失败信封 vs 部分结果）。
    fail_at: Option<usize>,
    child_pid: Option<u32>,
    /// 见 [`FakeChild::die_after`]。
    die_after: Option<Duration>,
    /// 非 0 = 给假核接一条内存 stderr，并起一个写手往里灌这么多字节；已写字节数经 watch 播报。
    stderr_flood: usize,
    stderr_written: tokio::sync::watch::Sender<usize>,
}

impl LoginCoreSpawner for FakeSpawner {
    fn spawn(
        &self,
        req: SpawnRequest,
    ) -> Result<Box<dyn LoginCoreChild>, polaris_core_supervisor::SpawnError> {
        let nth = self.spawns.fetch_add(1, Ordering::SeqCst) + 1;
        if self.fail || self.fail_at == Some(nth) {
            return Err(polaris_core_supervisor::SpawnError::Spawn {
                bin: PathBuf::from("/nonexistent"),
                source: std::io::Error::from(std::io::ErrorKind::NotFound),
            });
        }
        let stderr = (self.stderr_flood > 0)
            .then(|| flooding_stderr(self.stderr_flood, self.stderr_written.clone()));
        // 假 spawner 走的是**生产那条排空接线**：把假 stderr 的读端喂进请求里的回调
        // （生产是 `TempCoreSession::run` 构造的 `pipe_to_log(.., SPEEDTEST_CORE_TARGET, ..)`），
        // 而不是让假 child 另开一条只有测试才走的取管道路径。灌满门因此测的是生产接线本身。
        if let StdioPolicy::Drain(sink) = req.stdio {
            sink(
                Box::new(tokio::io::empty()),
                stderr.unwrap_or_else(|| Box::new(tokio::io::empty())),
            );
        }
        Ok(Box::new(FakeChild {
            terminated: Arc::clone(&self.terminated),
            // **每次 spawn 一个不同的 pid**：分批之后一轮会起 k 个核，pid 表的登记/注销必须跟着换
            // k 次。全批同一个假 pid 会让「上一批没注销 / 这一批没登记」这两种缺陷长得和正确行为
            // 一模一样（表里始终恰好那一个数）。
            pid: self.child_pid.map(|p| p + u32::try_from(nth).unwrap() - 1),
            die_after: self.die_after,
        }))
    }
}

/// 假 `sing-box check`：`ok=false` 模拟核判定配置无效（**绝不**真起 sing-box）。
struct FakeChecker {
    ok: bool,
}

#[async_trait]
impl ConfigChecker for FakeChecker {
    async fn check(
        &self,
        _binary: &std::path::Path,
        _config: &std::path::Path,
    ) -> Result<(), String> {
        if self.ok {
            Ok(())
        } else {
            Err("sing-box check 判定测速配置无效: bad custom outbound".to_string())
        }
    }
}

struct Harness {
    deps: TempCoreDeps,
    terminated: Arc<AtomicUsize>,
    spawns: Arc<AtomicUsize>,
    dir: PathBuf,
    /// 假核已写进 stderr 的字节数（[`HarnessOpts::stderr_flood`] 非 0 时才有意义）。
    stderr_written: tokio::sync::watch::Receiver<usize>,
}

/// 会话夹具的可选开关。**默认全关**（`Default`）= 与本批改造之前逐字等价的假核。
#[derive(Default)]
struct HarnessOpts {
    /// 给假核一个 pid（退出清理登记表那条测试用；其余一律 `None`）。
    child_pid: Option<u32>,
    /// 假核在这么久之后**自己退出**（A3 腿一）。
    die_after: Option<Duration>,
    /// 假核往 stderr 灌这么多字节（A1 排空门）。
    stderr_flood: usize,
    /// 只让第 k 次 spawn 失败（见 [`FakeSpawner::fail_at`]）。
    spawn_fail_at: Option<usize>,
    /// 只让**第 k 批**的就绪门失败（1 起数）：该批 spawn 成功、走进 `drive_after_spawn`、
    /// 在就绪门上耗满预算后失败。
    ///
    /// 与 [`Self::spawn_fail_at`] 不是一回事，**两者都要有**：spawn 失败根本走不到
    /// `drive_after_spawn`（就绪心跳那一段代码一行都不执行），而「中间批就绪失败」正是
    /// 就绪心跳里 `|| progress.tested() > 0` 那半个判据**唯一**的触发路径。
    /// 缺了它，删掉那半个判据全仓无一门转红（复审 2026-09-03 实测）。
    ready_fail_at: Option<usize>,
}

/// 造一个全 mock 的会话依赖：假 spawner + 假 check + 假核路径 + 确定性端口 + 可控就绪。
/// **零真进程、零网络**（`probe_port` 是纯闭包，绝不 connect；`checker` 不 exec 任何东西）。
fn harness(ready: bool, spawn_fail: bool, ports: Vec<u16>) -> Harness {
    harness_opts(ready, spawn_fail, ports, HarnessOpts::default())
}

/// 同 [`harness`]，但给假核一个 pid（退出清理登记表那条测试用；其余一律 `None`）。
fn harness_with_pid(
    ready: bool,
    spawn_fail: bool,
    ports: Vec<u16>,
    child_pid: Option<u32>,
) -> Harness {
    harness_opts(
        ready,
        spawn_fail,
        ports,
        HarnessOpts {
            child_pid,
            ..Default::default()
        },
    )
}

fn harness_opts(ready: bool, spawn_fail: bool, ports: Vec<u16>, opts: HarnessOpts) -> Harness {
    let dir = std::env::temp_dir().join(format!(
        "polaris-tempcore-test-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let terminated = Arc::new(AtomicUsize::new(0));
    let spawns = Arc::new(AtomicUsize::new(0));
    let fake_bin = dir.join("fake-sing-box");
    std::fs::write(&fake_bin, b"#!/bin/sh\n").unwrap();
    let (stderr_tx, stderr_rx) = tokio::sync::watch::channel(0usize);
    Harness {
        deps: TempCoreDeps {
            spawner: Arc::new(FakeSpawner {
                terminated: Arc::clone(&terminated),
                spawns: Arc::clone(&spawns),
                fail: spawn_fail,
                fail_at: opts.spawn_fail_at,
                child_pid: opts.child_pid,
                die_after: opts.die_after,
                stderr_flood: opts.stderr_flood,
                stderr_written: stderr_tx,
            }),
            checker: Arc::new(FakeChecker { ok: true }),
            resolve_binary: Arc::new(move || Ok(fake_bin.clone())),
            config_dir: dir.clone(),
            allocate_ports: Arc::new(move |n| ports.iter().copied().take(n).collect()),
            probe_port: {
                // 「第几批」= 此刻的 spawn 计数（spawner 进门即自增，就绪探测发生在它之后）。
                // 就绪探测本身不改计数，故同一批里反复探到的是同一个序号。
                let spawns = Arc::clone(&spawns);
                let fail_at = opts.ready_fail_at;
                Arc::new(move |_| ready && Some(spawns.load(Ordering::SeqCst)) != fail_at)
            },
            log_level: "warn".to_string(),
            ready_timeout_override_ms: Some(400),
        },
        terminated,
        spawns,
        dir,
        stderr_written: stderr_rx,
    }
}

static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

fn cleanup(dir: &PathBuf) {
    let _ = std::fs::remove_dir_all(dir);
}

/// 正常路径：起核 → 就绪 → 测完 → **杀核 + 删配置**。
///
/// **变异锁**：删掉 `child.terminate()` → `terminated == 0` 转红（真机表现 = 孤儿 sing-box 常驻，
/// 占着 N 个回环端口且用户完全看不见）；删掉 `remove_temp_config` → 配置文件残留断言转红。
#[tokio::test]
async fn session_kills_core_and_removes_config_on_success() {
    let h = harness(true, false, vec![20001, 20002, 20003]);
    let nodes = three_nodes();
    let out = TempCoreSession::run(
        &h.deps,
        &nodes,
        &|| false,
        |_| async { Some(50_u32) },
        &mut |_, _| {},
    )
    .await;
    match out {
        TempCoreOutcome::Ran { results, outcome } => {
            assert_eq!(outcome, "completed");
            assert_eq!(results.len(), 3);
        }
        other => panic!("应跑完，得到 {other:?}"),
    }
    assert_eq!(h.terminated.load(Ordering::SeqCst), 1, "临时核必须被杀");
    assert!(
        !h.dir.join(TEMP_CORE_CONFIG_NAME).exists(),
        "临时配置必须删掉（它含全部被测节点的凭证，核一退就是一份没人再用、却仍躺在盘上的凭据）"
    );
    // A6 的**反向对照**：非诊断档（本 harness 是 `warn`）一个字节都不许留。留档只在用户主动把级别
    // 拨到 debug/trace 时发生 —— 否则每次测速都在 config 目录里落一份配置，属于凭空的常驻残留。
    assert!(
        !h.dir.join(TEMP_CORE_LAST_CONFIG_NAME).exists(),
        "非诊断档不得留档"
    );
    cleanup(&h.dir);
}

/// 配置**落的是独立文件**，绝不是主核的 `singbox-runtime.json`。
///
/// **变异锁**：把文件名改成 `singbox-runtime.json` → 转红。那会在主核起来前**覆盖掉主核的运行配置**，
/// 表现为「测完速再点连接，代理行为莫名其妙」——归因极难。
#[test]
fn temp_config_name_is_isolated_from_the_main_core() {
    assert_eq!(TEMP_CORE_CONFIG_NAME, "speedtest-core.json");
    assert_ne!(TEMP_CORE_CONFIG_NAME, "singbox-runtime.json");
}

/// 就绪门失败 → 杀核 + **整批一个数值都不产出**（核没起来 ≠ 每个节点都超时）。
///
/// **变异锁**：把未就绪腿改成「给每个节点记 -1」→ 本测转红：那是伪造 N 次真实测量。
#[tokio::test]
async fn session_reports_failure_without_faking_results_when_not_ready() {
    let h = harness(false, false, vec![20001, 20002, 20003]);
    let out = TempCoreSession::run(
        &h.deps,
        &three_nodes(),
        &|| false,
        |_| async { Some(50_u32) },
        &mut |_, _| {},
    )
    .await;
    assert!(matches!(out, TempCoreOutcome::Failed(_)), "得到 {out:?}");
    assert_eq!(h.terminated.load(Ordering::SeqCst), 1, "未就绪也必须杀核");
    assert!(!h.dir.join(TEMP_CORE_CONFIG_NAME).exists());
    cleanup(&h.dir);
}

/// **起核前就让位 → 根本不 spawn**（双会话从源头掐掉，而不是起了再杀）。
/// **变异锁**：删掉起核前那道检查 → `spawns == 1` 转红。
#[tokio::test]
async fn session_never_spawns_when_already_superseded() {
    let h = harness(true, false, vec![20001, 20002, 20003]);
    let out = TempCoreSession::run(
        &h.deps,
        &three_nodes(),
        &|| true,
        |_| async { Some(50_u32) },
        &mut |_, _| {},
    )
    .await;
    assert!(matches!(out, TempCoreOutcome::Superseded), "得到 {out:?}");
    assert_eq!(h.spawns.load(Ordering::SeqCst), 0, "让位态绝不许起临时核");
    cleanup(&h.dir);
}

/// **端口不够 → 整批失败，绝不部分起核**：槽↔端口 1:1 一旦错位，量到的就是别的节点的延迟。
/// **变异锁**：把等长断言放宽成 `ports.len() >= 1` → 转红。
#[tokio::test]
async fn session_fails_atomically_when_ports_are_short() {
    let h = harness(true, false, vec![20001]); // 只给 1 个，需 3 个
    let out = TempCoreSession::run(
        &h.deps,
        &three_nodes(),
        &|| false,
        |_| async { Some(50_u32) },
        &mut |_, _| {},
    )
    .await;
    assert!(matches!(out, TempCoreOutcome::Failed(_)), "得到 {out:?}");
    assert_eq!(h.spawns.load(Ordering::SeqCst), 0, "端口不齐就不该起核");
    cleanup(&h.dir);
}

/// **配置形态非法 → 根本不 spawn**，且 check 的诊断**原文冒泡**（那句话里写着哪个字段错了）。
///
/// 唯一不由本仓完全掌控的配置片段是 `custom` 协议的用户原样 JSON。没有这道 fail-fast 门时，用户看到
/// 的是就绪门那句「10s 内未监听」—— 把「你的自定义节点 JSON 写错了」误报成「网络/端口有问题」，
/// 还白等 10 秒。
///
/// **变异锁**：删掉 `deps.checker.check(...)` 那段 → `spawns == 1` + outcome 变成就绪失败 → 转红。
#[tokio::test]
async fn session_rejects_invalid_config_before_spawning() {
    let mut h = harness(true, false, vec![20001, 20002, 20003]);
    h.deps.checker = Arc::new(FakeChecker { ok: false });
    let out = TempCoreSession::run(
        &h.deps,
        &three_nodes(),
        &|| false,
        |_| async { Some(50_u32) },
        &mut |_, _| {},
    )
    .await;
    match out {
        TempCoreOutcome::Failed(e) => assert!(
            e.contains("bad custom outbound"),
            "check 的诊断必须原文冒泡（吞成通用文案 = 用户无从知道哪个字段错了），得到：{e}"
        ),
        other => panic!("非法配置应 fail-fast，得到 {other:?}"),
    }
    assert_eq!(h.spawns.load(Ordering::SeqCst), 0, "配置无效就不该起核");
    assert!(!h.dir.join(TEMP_CORE_CONFIG_NAME).exists());
    cleanup(&h.dir);
}

/// spawn 失败 → 失败信封 + **临时配置照样删掉**（它含被测节点凭证，核都没起来更没有留着的理由）。
#[tokio::test]
async fn session_cleans_up_config_when_spawn_fails() {
    let h = harness(true, true, vec![20001, 20002, 20003]);
    let out = TempCoreSession::run(
        &h.deps,
        &three_nodes(),
        &|| false,
        |_| async { Some(50_u32) },
        &mut |_, _| {},
    )
    .await;
    assert!(matches!(out, TempCoreOutcome::Failed(_)), "得到 {out:?}");
    assert!(!h.dir.join(TEMP_CORE_CONFIG_NAME).exists());
    cleanup(&h.dir);
}

/// 空节点集 → 不起核、不失败（调用方本不该进来；防御性返 completed 空）。
#[tokio::test]
async fn session_is_noop_for_empty_node_set() {
    let h = harness(true, false, vec![]);
    let out = TempCoreSession::run(
        &h.deps,
        &[],
        &|| false,
        |_| async { Some(1_u32) },
        &mut |_, _| {},
    )
    .await;
    assert!(matches!(out, TempCoreOutcome::Ran { .. }));
    assert_eq!(h.spawns.load(Ordering::SeqCst), 0);
    cleanup(&h.dir);
}

/// 🔵 **结构守卫**：生产装配必须复用主核的 `resolve_core_binary`，绝不另写一份核路径解析。
///
/// 另写一份的失效方式是静默的：换核（core-swap）后主核用新核、临时核仍指旧核路径 ⇒ 测速结果来自
/// 一个**版本不同**的内核，而两边都「能跑」。
///
/// 🔴 **二次封顶**：`top_level_fn_body` 按**列 0** 的 `\n}\n` 收尾，对 `production` 这种 4 空格缩进
/// 的方法实际扫到的是 `impl TempCoreDeps` 的结尾。将来在该 impl 里追加任何含 `resolve_core_binary`
/// 字样的方法，本守卫就会**照绿**（哪怕 `production` 自己已经不再复用它）。故在此把切片再收到
/// 「下一个同级方法之前」，把判据钉回 `production` **自己的**函数体。
#[test]
fn production_deps_reuse_the_main_core_binary_resolver() {
    let src = crate_code("runtime/speedtest.rs");
    // 取材器换成 `impl_method_body`（按 `"\n    }\n"` 封顶，正是为 impl 方法设计的）。
    // 此前这里用的是 `top_level_fn_body` + 手搓的二次封顶：那个组合能工作，但它是在**错误的
    // 工具**上打补丁 —— 同一形态在 `proxy/tests/mod.rs` 上没打补丁，于是切出了 98 倍超宽片
    // 与一个可证明的假绿。补丁不该各写各的，封顶要由取材器自己负责。
    let body = crate::commands::guard_scan::impl_method_body(
        &src,
        "    pub fn production(config_dir: PathBuf",
    );
    // 自检：封顶真的生效（切片里不得混进同 impl 的下一个方法）。
    assert!(
        !body.contains("\n    pub fn "),
        "封顶失效：切片里混进了同 impl 的其它方法 ⇒ 下面的断言可被「删这里、加那里」骗过"
    );
    assert!(
        body.contains("crate::runtime::proxy::resolve_core_binary"),
        "临时核必须与主核共用同一份核二进制解析（另写一份 ⇒ 换核后两边指向不同内核，静默）"
    );
    assert!(
        body.contains("resolve_distinct_free_ports"),
        "端口必须走 core-supervisor 的批分配（自己 bind 一圈会丢掉排除集，撞主核端口）"
    );
}

// ══════════════════════════════════════════════════════════════════════════
// 在飞临时核 pid 表（应用退出清理的收口）。**任何一条都不对真实进程发信号**。
// ══════════════════════════════════════════════════════════════════════════

// 串行闸 [`registry_guard`] 已挪到 `speedtest.rs`（表边上）—— 孤儿清扫的排除表用例也要串行到
// **同一把**锁上，锁跟着测试文件走就会分叉成两把。经 `use super::*` 原名可见。

/// 🔴 会话必须把在飞 pid 登记进表（**退出清理唯一能杀到它的途径**），并在收尾时注销。
///
/// 为什么不能只靠 child 的 `Drop` 守卫：应用退出走 `ExitRequested → run_exit_cleanup → 进程退出`，
/// 在飞的 tokio task **根本不会被 drop** ⇒ Drop 守卫够不着 ⇒ 留下持有 N 个回环端口 + WG peer 会话
/// 的孤儿 sing-box（Windows 无 stale sweep 兜底，永不被清）。
///
/// 牙：① 删掉 `TempCorePidGuard::register(pid)` → 在飞断言转红；② 把守卫换成裸 insert（不注销）
/// → 收尾断言转红（表里留着死 pid，退出时可能误杀一个 pid 复用的无关进程）。
///
/// 用**本进程自己的 pid** 当假核 pid：就绪门的 `is_alive` 需要一个真存活的 pid，而本测**只读**表、
/// 绝不调用发信号的那条路径（`kill_inflight_temp_cores`）。
// `await_holding_lock`：`REGISTRY_LOCK` 是**测试串行闸**，语义上就必须罩住整个 async 测试体
// （否则并发的排空用例会把本测登记的 pid 抽走）。不会死锁：`#[tokio::test]` 默认单线程运行时，
// 而另一个持锁者是普通同步 `#[test]`（跑在别的线程上），两边各自推进；换 async Mutex 反而要求
// 同步那条用例也变 async，为一个纯串行闸把射程搞大。
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn session_registers_inflight_pid_so_app_exit_cleanup_can_reach_it() {
    let _lock = registry_guard();
    let self_pid = std::process::id();
    let h = harness_with_pid(true, false, vec![20001, 20002, 20003], Some(self_pid));
    let seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let probe = Arc::clone(&seen);
    let out = TempCoreSession::run(
        &h.deps,
        &three_nodes(),
        &|| false,
        move |_| {
            let probe = Arc::clone(&probe);
            async move {
                if temp_core_pids().contains(&self_pid) {
                    probe.store(true, Ordering::SeqCst);
                }
                Some(50_u32)
            }
        },
        &mut |_, _| {},
    )
    .await;
    assert!(matches!(out, TempCoreOutcome::Ran { .. }), "得到 {out:?}");
    assert!(
        seen.load(Ordering::SeqCst),
        "测量在飞期间 pid 必须在表里 —— 否则应用退出时清理路径根本看不见这个核"
    );
    assert!(
        !temp_core_pids().contains(&self_pid),
        "会话收尾必须注销 pid（留着 = 退出时对一个已死 pid 发信号，pid 复用即误杀无关进程）"
    );
    cleanup(&h.dir);
}

/// 排空语义：逐 pid 收割一次 + 计数 + **幂等**（第二次调用返 0，绝不重复发信号）。
///
/// 收割动作经注入闭包 ⇒ 零真实信号。假 pid 取 `> i32::MAX`：即便有人把它接到真 `send_signal` 上，
/// `checked_pid` 也会挡掉（负数 pid 是 kill 的**广播**语义 —— 那是全场 SIGKILL）。
#[test]
fn kill_inflight_temp_cores_drains_table_once_and_counts_each_pid() {
    let _lock = registry_guard();
    let fake: u32 = 0xDEAD_BEEF;
    temp_core_pids().insert(fake);
    let mut killed: Vec<u32> = Vec::new();
    let n = kill_temp_cores_with(|pid| killed.push(pid));
    assert_eq!(n, killed.len(), "返回值必须等于实际收割条数");
    assert!(killed.contains(&fake), "在飞 pid 必须被收割");
    // 幂等：表已排空 → 再调零收割（重复发信号 = 对复用了该 pid 的无关进程动手）。
    let mut again: Vec<u32> = Vec::new();
    assert_eq!(kill_temp_cores_with(|pid| again.push(pid)), 0);
    assert!(again.is_empty());
}

/// 🔵 **调用点守卫**：退出生命周期 owner 必须真的调 [`kill_inflight_temp_cores`]。
///
/// 没有这条，「登记了 pid」与「退出时会被杀」之间是断的，而断了的表现**恰好是静默的**：
/// 用户看不到孤儿核，只在下次起核时莫名 address-in-use（Windows 连那次兜底都没有）。
/// 牙：把 `exit_lifecycle::run_exit_cleanup` 里那行删掉 / 挪出该函数 → 转红。
#[test]
fn app_exit_cleanup_kills_inflight_temp_cores() {
    let body = crate::commands::guard_scan::top_level_fn_body(
        &crate_code("exit_lifecycle.rs"),
        "fn run_exit_cleanup(",
    );
    assert!(
            body.contains("kill_inflight_temp_cores()"),
            "退出清理必须收掉在飞测速临时核：它不在 ProxyRuntime 的任何生命周期槽里，proxy.stop() 碰不到它"
        );
}

// ══════════════════════════════════════════════════════════════════════════
// 批 A：可观测性（A1 排空 / A3 核异常感知 / A4 归因 / A6 留档）
// ══════════════════════════════════════════════════════════════════════════

/// 造 n 个假节点（A3 腿二要跨过 [`TEMP_CORE_STALL_STREAK`]，三个不够用）。
fn n_nodes(n: usize) -> Vec<TempNode> {
    (0..n)
        .map(|i| {
            let id = format!("node{i:04}");
            TempNode {
                tag: temp_core_tag(&id),
                id,
                node: json!({}),
                companion_outbounds: Vec::new(),
                is_endpoint: false,
                has_local_v6: false,
            }
        })
        .collect()
}

/// 🔴 **A1 排空门（行为级，不是源码级 grep）**：核往 stderr 猛灌 1 MiB，会话必须一路排空它。
///
/// # 这条门守的是什么
///
/// 全仓三条核腿的 stdio 都被 `Stdio::piped()`，主核与瞬态登录核都排空，只有测速临时核不排 ——
/// 核写满 64 KiB 后 `write(2)` 永久阻塞，整个 sing-box 卡死但**不死**，此后每个节点吃满 6 s 硬闸
/// 判 -1 且永不恢复（2026-09-02 受控实验实测坐实，macOS 真机 `logLevel=debug` 即命中）。
///
/// 夹具用 [`FAKE_PIPE_CAPACITY`]（= Linux 匿名管道默认容量）的内存 duplex，把这个回压**同构**搬进
/// 内存：零进程、零网络。
///
/// **牙**：把 `run()` 里请求上的 `StdioPolicy::drain(...)` 换成 `StdioPolicy::Discard`，或者删掉
/// 那两条 `pipe_to_log(` 里排 stderr 的那条 ⇒ 没人读 ⇒ 写手停在 64 KiB，会话收尾丢掉读端后它
/// 拿到 BrokenPipe 就此打住 ⇒ 下面的 `wait_for` 超时 ⇒ 转红。
///
/// 假 spawner 把内存 duplex 的读端喂给**请求里那个回调**（不是喂给假 child 的某个取管道方法），
/// 所以本门压的是生产接线本身。
#[tokio::test]
async fn temp_core_drains_stderr_so_a_flooding_core_never_wedges() {
    let mut h = harness_opts(
        true,
        false,
        vec![20001, 20002, 20003],
        HarnessOpts {
            stderr_flood: STDERR_FLOOD_BYTES,
            ..Default::default()
        },
    );
    let out = TempCoreSession::run(
        &h.deps,
        &three_nodes(),
        &|| false,
        |_| async { Some(50_u32) },
        &mut |_, _| {},
    )
    .await;
    assert!(matches!(out, TempCoreOutcome::Ran { .. }), "得到 {out:?}");

    let drained = matches!(
        tokio::time::timeout(
            Duration::from_secs(5),
            h.stderr_written.wait_for(|n| *n >= STDERR_FLOOD_BYTES),
        )
        .await,
        Ok(Ok(_))
    );
    let written = *h.stderr_written.borrow();
    assert!(
        drained,
        "核的 stderr 必须被排空：写手只推进到 {written} / {STDERR_FLOOD_BYTES} 字节，\
         说明管道在无人读时把核堵死了 —— 这正是 M1 的形态"
    );
    cleanup(&h.dir);
}

/// 🔴 **夹具语义门**：[`FakeChild::wait`] 默认**必须永不完成**。
///
/// 改前它立即返回。生产侧接上 `select!` on `child.wait()` 之后，「立即返回」= 「核刚起来就死了」
/// ⇒ 每一条会话用例都会被判成中断（全体假红），而更糟的是有人为了让它们变绿去改**生产**的判据。
#[tokio::test]
async fn fake_child_wait_never_resolves_by_default() {
    let mut child = FakeChild {
        terminated: Arc::new(AtomicUsize::new(0)),
        pid: None,
        die_after: None,
    };
    assert!(
        tokio::time::timeout(Duration::from_millis(120), child.wait())
            .await
            .is_err(),
        "默认假核不得「自己死」——否则 A3 腿一会把每一轮正常测速都判成核退出"
    );
}

/// 🔴 **A3 腿一（核已死）**：核在测量中途自己退出 ⇒ `interrupted` + `reason=core_exited`，
/// **检测到退出之后**未出值的节点一律缺席（不写 `-1`），且收尾照走。
///
/// 口径注意：这不是「核死后一个 -1 都不会有」的全称承诺 —— 核崩溃与检测之间在飞的拨号会真实失败，
/// `biased` + 落账前复查把那个窗口压到「同一次 poll 内」（下面两条时序门各钉一半），压不到零。
/// 本门里测量恒挂 30 s，故检测点之前没有任何结果落账，`results` 必须为空。
///
/// **牙**：① 把退出臂改成「给每个未出值节点记 -1」→ `results.is_empty()` 转红（那是伪造 N 次真实
/// 测量，等于告诉用户这些节点不通）；② 删掉整条 `select!` 退出臂 → 本测卡在 30 s 的假测量上超时；
/// ③ 把 `reason` 写成 `superseded` → 归因断言转红（让位与核死的下一步动作完全不同）。
#[tokio::test]
async fn session_reports_core_exit_as_interrupted_without_faking_results() {
    let h = harness_opts(
        true,
        false,
        vec![20001, 20002, 20003],
        HarnessOpts {
            die_after: Some(Duration::from_millis(80)),
            ..Default::default()
        },
    );
    let mut done: Vec<Value> = Vec::new();
    let out = TempCoreSession::run(
        &h.deps,
        &three_nodes(),
        &|| false,
        |_| async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Some(50_u32)
        },
        &mut |ev, payload| {
            if ev == EVENT_SPEED_TEST_DONE {
                done.push(payload);
            }
        },
    )
    .await;
    match out {
        TempCoreOutcome::Ran { results, outcome } => {
            assert_eq!(outcome, "interrupted");
            assert!(
                results.is_empty(),
                "核死了 ≠ 每个节点都超时：检测点之前没有任何结果落账，故此处必须为空，得到 {results:?}"
            );
        }
        other => panic!("核退出应走 Ran/interrupted，得到 {other:?}"),
    }
    assert_eq!(
        h.terminated.load(Ordering::SeqCst),
        1,
        "核退出臂也必须经无条件收尾（否则句柄不收割 = 僵尸）"
    );
    assert_eq!(done.len(), 1, "终态事件恰发一次（三条腿各自唯一出口）");
    assert_eq!(
        done[0]["reason"],
        json!("core_exited"),
        "中断成因必须如实给到前端（让位 / 核死的下一步动作完全不同）"
    );
    assert_eq!(
        done[0]["pending"].as_array().unwrap().len(),
        3,
        "三个都没出值 ⇒ 三个都进续测输入"
    );
    cleanup(&h.dir);
}

/// 🔴 **A3 腿二（核不再接受连接）**：连败满一整窗后复探 `ports[0]` 无响应 ⇒ `interrupted` +
/// `reason=core_unresponsive`，剩余节点缺席（不再各烧一个 6 s 硬闸去凑假 -1）。
///
/// **牙**：① 把复探腿删掉 → `outcome` 变 `completed` 转红；② 把阈值判据写成 `> 0`（每失败一次就
/// 探）→ `results.len()` 断言转红；③ 复探失败后只记日志不终止 → 同样 `completed` 转红。
#[tokio::test]
async fn a_core_that_stops_answering_ends_the_round_as_unresponsive() {
    let nodes = n_nodes(TEMP_CORE_STALL_STREAK + 4);
    let ports: Vec<u16> = (1..=u16::try_from(nodes.len()).unwrap()).collect();
    let mut done: Vec<Value> = Vec::new();
    let mut watch = TempCoreWatch {
        pid: 4242,
        exited: Box::pin(std::future::pending()),
        // 核还在（进程没死），但已经不接受连接了。
        probe_port: Arc::new(|_| false),
        port: 1,
    };
    let (results, outcome) = drive_round_of_one_batch(
        &nodes,
        &ports,
        4,
        &superseded_at(0),
        &mut watch,
        |_| async { None }, // 每个节点都判 -1
        &mut |ev, payload| {
            if ev == EVENT_SPEED_TEST_DONE {
                done.push(payload);
            }
        },
    )
    .await;
    assert_eq!(outcome, "interrupted");
    assert_eq!(
        results.len(),
        TEMP_CORE_STALL_STREAK,
        "复探那一刻已落账的恰是连败的那一整窗；其余节点缺席，绝不补假 -1"
    );
    assert_eq!(done[0]["reason"], json!("core_unresponsive"));
    assert_eq!(
        done[0]["pending"].as_array().unwrap().len(),
        nodes.len() - TEMP_CORE_STALL_STREAK
    );
}

/// 🔵 **上一条门的正向对照**：同样连败满一整窗，但复探答「核还在」⇒ 本轮必须**跑完**。
///
/// 没有这条对照，上面那扇门抓的可能只是「失败次数够多」而不是「核不响应」——那会把「订阅里有一串
/// 死节点」误判成自家核出事，用户每次都少测一批好节点。
#[tokio::test]
async fn a_responding_core_finishes_the_round_despite_a_full_streak_of_failures() {
    let nodes = n_nodes(TEMP_CORE_STALL_STREAK + 4);
    let ports: Vec<u16> = (1..=u16::try_from(nodes.len()).unwrap()).collect();
    let probed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = Arc::clone(&probed);
    let mut watch = TempCoreWatch {
        pid: 4242,
        exited: Box::pin(std::future::pending()),
        probe_port: Arc::new(move |_| {
            seen.fetch_add(1, Ordering::SeqCst);
            true
        }),
        port: 1,
    };
    let (results, outcome) = drive_round_of_one_batch(
        &nodes,
        &ports,
        4,
        &superseded_at(0),
        &mut watch,
        |_| async { None },
        &mut |_, _| {},
    )
    .await;
    assert_eq!(
        outcome, "completed",
        "核还在 ⇒ 连败只是节点不通，本轮照跑完"
    );
    assert_eq!(
        results.len(),
        nodes.len(),
        "每个节点都要有自己的 -1（真实测量）"
    );
    assert!(
        probed.load(Ordering::SeqCst) >= 1,
        "满一窗连败必须真的探过核"
    );
}

/// 🔵 **阈值对照**：连败**未满**一整窗时不得复探（也就不可能因此中断）。
///
/// 阈值这条线的含义是「一整个在飞窗口全灭」——低于它的连败在真机上就是订阅里有一串死节点，
/// 不是自家核出事。
#[tokio::test]
async fn failures_below_the_streak_never_probe_the_core() {
    let nodes = n_nodes(TEMP_CORE_STALL_STREAK - 1);
    let ports: Vec<u16> = (1..=u16::try_from(nodes.len()).unwrap()).collect();
    let probed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen = Arc::clone(&probed);
    let mut watch = TempCoreWatch {
        pid: 0,
        exited: Box::pin(std::future::pending()),
        probe_port: Arc::new(move |_| {
            seen.store(true, Ordering::SeqCst);
            false // 探了就一定会中断 ⇒ 「没中断」即证明没探
        }),
        port: 1,
    };
    let (results, outcome) = drive_round_of_one_batch(
        &nodes,
        &ports,
        4,
        &superseded_at(0),
        &mut watch,
        |_| async { None },
        &mut |_, _| {},
    )
    .await;
    assert_eq!(outcome, "completed");
    assert_eq!(results.len(), nodes.len());
    assert!(
        !probed.load(Ordering::SeqCst),
        "连败未满 {TEMP_CORE_STALL_STREAK} 不得复探核"
    );
}

/// 🔴 **A4**：让位中断的成因同样如实上报（`reason=superseded`），且 `outcome` 保持二值。
///
/// **牙**：把让位腿的成因写成 `core_exited`（或干脆不发 `reason`）→ 转红。前端要靠它换文案：
/// 「主核接管了，去主核重测」与「本机测速核出事了，去看 `speedtest-core` 日志」是两件事。
#[tokio::test]
async fn superseded_round_reports_the_superseded_reason() {
    let mut done: Vec<Value> = Vec::new();
    let (_results, outcome) = drive_round_of_one_batch(
        &three_nodes(),
        &[1, 2, 3],
        8,
        &superseded_at(1), // 发活前即让位
        &mut healthy_watch(),
        |_| async { Some(120_u32) },
        &mut |ev, payload| {
            if ev == EVENT_SPEED_TEST_DONE {
                done.push(payload);
            }
        },
    )
    .await;
    assert_eq!(outcome, "interrupted");
    assert_eq!(done[0]["outcome"], json!("interrupted"), "outcome 保持二值");
    assert_eq!(done[0]["reason"], json!("superseded"));
}

/// 🔵 **`completed` 不带 `reason`**：可选字段的缺席语义（发 `null` 会让「旧后端没这字段」与
/// 「本轮没有成因」在前端长得一样）。
#[tokio::test]
async fn completed_round_carries_no_reason_field() {
    let mut done: Vec<Value> = Vec::new();
    let (_results, outcome) = drive_round_of_one_batch(
        &three_nodes(),
        &[1, 2, 3],
        8,
        &superseded_at(0),
        &mut healthy_watch(),
        |_| async { Some(120_u32) },
        &mut |ev, payload| {
            if ev == EVENT_SPEED_TEST_DONE {
                done.push(payload);
            }
        },
    )
    .await;
    assert_eq!(outcome, "completed");
    assert!(
        done[0].get("reason").is_none(),
        "completed 不得带 reason，得到 {:?}",
        done[0]
    );
}

/// 🔴 **A6**：诊断档（`debug`/`trace`）收尾把配置**改名留档**，固定名、覆盖式。
///
/// **牙**：① 退回无条件删除 → 留档断言转红（排查临时核绕不开「这一轮到底给核喂了什么」，而抢在
/// 收尾前 `cp` 在真机上抢不住）；② 留档写成「复制」而不是「改名」→ 原文件仍在，第一条断言转红
/// （留档是给人看的证据，不该同时还留着一份原名的活配置）。
#[tokio::test]
async fn diagnostic_level_keeps_the_last_temp_config_under_a_fixed_name() {
    let mut h = harness(true, false, vec![20001, 20002, 20003]);
    h.deps.log_level = "debug".to_string();
    let out = TempCoreSession::run(
        &h.deps,
        &three_nodes(),
        &|| false,
        |_| async { Some(50_u32) },
        &mut |_, _| {},
    )
    .await;
    assert!(matches!(out, TempCoreOutcome::Ran { .. }), "得到 {out:?}");
    assert!(
        !h.dir.join(TEMP_CORE_CONFIG_NAME).exists(),
        "留档是**改名**：原路径必须消失，否则下次会话会把它当自己的配置覆盖，等于没留"
    );
    let kept = h.dir.join(TEMP_CORE_LAST_CONFIG_NAME);
    assert!(kept.exists(), "诊断档必须留下最后一份临时核配置");
    let cfg: Value = serde_json::from_slice(&std::fs::read(&kept).unwrap()).unwrap();
    assert_eq!(
        cfg["log"]["level"],
        json!("debug"),
        "留下来的必须是**本轮真下发的那一份**"
    );
    cleanup(&h.dir);
}

/// 🔵 **A1 接线守卫（源码级）**：临时核的两条流必须在**构造 spawn 请求时**就接进本腿自己的
/// target，两条都接。
///
/// 行为级的排空门（[`temp_core_drains_stderr_so_a_flooding_core_never_wedges`]）证明「有人在读」，
/// 但证不了 ① 读的是不是**两条**流 ② 打的是不是本腿的 target ③ 接线是不是在起核**之前**就绑好。
///
/// 第 ③ 条现在由类型层扛了一半：`SpawnRequest` 的 `stdio` 必填，spawner 在返回之前就调用回调，
/// child 到手时已经不带管道（没有 `take_stdout`/`take_stderr` 可用），所以「接在就绪门之后」这条
/// 路已经写不出来。类型层扛不动的是**另外三格**，正是本门守的：
///
/// - 把策略写成 `StdioPolicy::Discard`（编得过，核的输出被内核丢弃、日志页从此空白）；
/// - 只把其中一条流喂给 `pipe_to_log`、另一条直接丢掉（编得过，那条管道的读端一关，核对它的下
///   一次写拿到 EPIPE 而不是阻塞 —— 不卡死，但诊断没了）；
/// - target 写成主核的 `SING_BOX_TARGET`（编得过，临时核的行混进 `singbox.log` 并污染日志页的
///   来源筛选）。
///
/// 取材器按 `"\n    }\n"` 封顶并剥掉行注释 ⇒ 本文件与注释都进不了判据面（不自污染）。
#[test]
fn temp_core_wires_both_streams_into_its_own_target_at_spawn_time() {
    let src = crate_code("runtime/speedtest.rs");
    // 锚点是**批级**那个入口（T1-R1 分批之后 `run` 变成轮级薄壳，spawn 请求的构造留在 `run_batch`）。
    let body = crate::commands::guard_scan::impl_method_body(
        &src,
        "    async fn run_batch<Meas, MeasFut>(",
    );
    // 自检：封顶真的生效（切片里不得混进同 impl 的其它方法）。
    assert!(
        !body.contains("\n    async fn drive_after_spawn<"),
        "封顶失效：切片里混进了同 impl 的其它方法 ⇒ 下面的顺序断言可被「删这里、加那里」骗过"
    );
    assert!(
        body.contains("StdioPolicy::drain("),
        "临时核必须选 `Drain` 策略：换成 `Discard` 一样编得过，代价是核的输出被内核丢弃、\
         排查临时核时日志页一片空白"
    );
    assert_eq!(
        body.matches("pipe_to_log(").count(),
        2,
        "两条流各接一次排空（全 app 唯一那份实现，禁止另写）：少接一条，那条管道的读端一关，\
         核对它的写就拿到 EPIPE，诊断静默消失"
    );
    // 🔴 **计数不是位置**。上一条只数得出「排空调用发生了 2 次」，数不出「**哪条流**喂给了
    // **哪次**调用」：把回调改成 `|stdout, _stderr|` 再补一行
    // `pipe_to_log(tokio::io::empty(), SPEEDTEST_CORE_TARGET, None, None);` —— 编得过、计数照旧是 2、
    // 上面那条与 α 的 G2 旧判据**全绿**，而临时核的 stderr 从此无人读（这正是本轮根因那条腿）。
    // 故逐条流钉精确接线。判据打在**去掉全部空白**的形上：接线写在闭包里，缩进随闭包层级变，
    // 钉死缩进的断言一次 `cargo fmt` 就失去判据 —— 而失去判据的门是绿的。形态与主核那两条门
    // （`proxy/tests/startup.rs` / `proxy/tests/core_log.rs`）逐字同源，不另发明一套。
    let compact: String = body.split_whitespace().collect();
    for wired in [
        "StdioPolicy::drain(|stdout,stderr|{",
        "pipe_to_log(stdout,SPEEDTEST_CORE_TARGET,None,None);",
        "pipe_to_log(stderr,SPEEDTEST_CORE_TARGET,None,None);",
    ] {
        assert!(
            compact.contains(wired),
            "临时核的排空接线里找不到 `{wired}` —— 这条流没有被喂给排空调用（或绑定名/target 变了）。\
             计数型判据在这一格是哑的：补一次别的调用就能把次数凑回来，而那条管道仍旧无人读"
        );
    }
    assert!(
        body.contains("SPEEDTEST_CORE_TARGET"),
        "target 必须是本腿自己的：混进主核 target 会污染主核日志文件分流与日志页来源筛选"
    );
    assert!(
        !body.contains("SING_BOX_TARGET"),
        "不得把临时核的行打进主核 target"
    );
    // 取**最后**一个 pipe_to_log：两条都必须写在请求里（= spawn 之前），不是 spawn 之后再补一条。
    let wired_at = body.rfind("pipe_to_log(").expect("上面已断言存在");
    let spawn_at = body
        .find("deps.spawner.spawn(")
        .expect("起核调用必须还在这条腿上");
    assert!(
        wired_at < spawn_at,
        "排空接线必须写在 `SpawnRequest` 里（spawn 之前生效）：接在 spawn 之后就又出现了\
         「核已经在写、还没人读」的窗口"
    );
}

/// 🔵 **接线搬家之后 `drive_after_spawn` 必须干净**：排空不许再回到 spawn 之后。
///
/// 这条与上一条成对：上一条钉「接线在请求里」，本条钉「没有第二份接线偷偷长回原处」。
/// 两条都在的时候，「排空发生在起核之前」这件事在源码上是闭合的。
#[test]
fn drive_after_spawn_no_longer_touches_the_pipes() {
    let src = crate_code("runtime/speedtest.rs");
    let body = crate::commands::guard_scan::impl_method_body(
        &src,
        "    async fn drive_after_spawn<Meas, MeasFut>(",
    );
    assert!(
        !body.contains("pipe_to_log(") && !body.contains("StdioPolicy"),
        "spawn 之后不该再有排空接线：`SpawnedChild` 到手时两条管道已经交出去了，\
         这里再接一份只可能是接到别的东西上"
    );
    assert!(
        body.contains("wait_for_core_ready("),
        "就绪门必须还在这条腿上（否则上面那条否定断言只是在一个空壳上恒真）"
    );
}

// ══════════════════════════════════════════════════════════════════════════
// 复审必修：核退出窗口内的失败**不许**落成 -1；drain 不许被一个坏字节掐断
// ══════════════════════════════════════════════════════════════════════════

/// 「核已退出」这一事实的**可观测开关**：只在被 poll 时看一眼原子标志，不注册 waker。
///
/// 用它而不是 `sleep`/`watch`，是因为本组门要的是**精确时序**：测试要能说清「核是在 select 之前、
/// 同一 tick、还是 select 之后才变得可观测」。计时器做不到这件事（`FakeChild::die_after` 那条门
/// 就因为测量恒挂 30 s、根本碰不到这一格）。
fn exit_flag_future(
    flag: &Arc<std::sync::atomic::AtomicBool>,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    let flag = Arc::clone(flag);
    Box::pin(std::future::poll_fn(move |_cx| {
        if flag.load(Ordering::SeqCst) {
            std::task::Poll::Ready(())
        } else {
            std::task::Poll::Pending
        }
    }))
}

/// 跑一轮「核退出与测量失败**同一 tick** 就绪」的时序：测量任务自己置退出标志再返回 `None`
/// —— 对应真机上「内核先关掉核的全部 socket（`exit_files`），在飞的 `open_tunnel` 立刻返 `None`，
/// 而 `child.wait()` 也在同一轮就绪」。
async fn run_core_exit_in_the_same_tick() -> (serde_json::Map<String, Value>, &'static str) {
    let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut watch = TempCoreWatch {
        pid: 7,
        exited: exit_flag_future(&flag),
        probe_port: Arc::new(|_| true),
        port: 1,
    };
    let trip = Arc::clone(&flag);
    drive_round_of_one_batch(
        &three_nodes(),
        &[1, 2, 3],
        3,
        &superseded_at(0),
        &mut watch,
        move |_| {
            let trip = Arc::clone(&trip);
            async move {
                trip.store(true, Ordering::SeqCst); // 核在这一刻已经没了
                None // …于是这次拨号立刻失败
            }
        },
        &mut |_, _| {},
    )
    .await
}

/// 🔴 **核退出与测量失败同 tick 就绪时，该节点缺席而不是落 `-1`**（`select!` 的 `biased`）。
///
/// # 为什么要跑 24 轮
///
/// 不带 `biased` 的 `tokio::select!` **每次随机取臂**，所以单次试验只有一半概率走到 join 臂、
/// 落下那个假 `-1`。一轮的门无法区分「修好了」和「这次运气好」。24 轮全干净在无守卫时的概率
/// 约 `0.5^24 ≈ 6e-8`，等于确定性转红；有 `biased` 时则是恒真。
///
/// **牙**：删掉 `biased` ⇒ 实测在第 1–3 轮内就会落下 `-1` 转红（见批 A 文档的变异记录）。
///
/// 这个假 `-1` 的危害不止「数字不对」：它已经进了 `results` ⇒ **不会**出现在 DONE 的 `pending` 里
/// ⇒ 用户点「继续剩余」会跳过这些节点，而它们其实一次都没被公平地测过。
#[tokio::test]
async fn a_failure_in_the_same_tick_as_core_exit_is_absent_not_minus_one() {
    for round in 0..24 {
        let (results, outcome) = run_core_exit_in_the_same_tick().await;
        assert_eq!(outcome, "interrupted", "第 {round} 轮");
        assert!(
            results.is_empty(),
            "第 {round} 轮落了假 -1：{results:?} —— 核退出那一刻的拨号失败不是节点的错，\
             且它进了 results 就再也不会进 pending（「继续剩余」会跳过它）"
        );
    }
}

/// 🔴 **核退出在 select 收场之后、落账之前才可观测** ⇒ 仍须缺席（落账前那次 `poll_fn` 复查）。
///
/// `biased` 只管「同一次 select poll 里两者都就绪」。它管不到的是：join 臂在更早一次 poll 就把结果
/// 取走了，核的退出**随后**才变得可观测——多线程 runtime，或 macOS / Windows 上不同的 reap 时序。
///
/// # 时间锚：让位闭包的**第 2 次**调用
///
/// 测量循环里 `superseded()` 有两个调用点：① 派活之前（每轮至多一次，`next < total` 时）；
/// ③ 每个 join 结果回来、**落账之前**。3 节点 / 窗口 3 的时序里，第 1 次调用是 ①（此时还没有任何
/// 结果），第 2 次起都是 ③。故在**第 2 次**调用里翻开退出标志，就精确落在「select 已用 join 臂
/// 收场、尚未落账」那一格 —— 这正是 `biased` 够不着、只有落账前那次 `poll_fn` 复查能接住的窗口。
///
/// ⚠️ 早一格（第 1 次调用就翻）会让 `select!` 直接命中退出臂，本门就变成在测 `biased` 而不是测复查
/// ——**实测踩过一次**：那版在「复查被删掉」的变异下照样全绿。
///
/// **牙**：删掉落账前的 `poll_fn` 复查 ⇒ 第一个节点落成 `-1`（`results.len() == 1`）转红。
#[tokio::test]
async fn a_core_exit_seen_between_select_and_record_makes_the_node_absent() {
    let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut watch = TempCoreWatch {
        pid: 9,
        exited: exit_flag_future(&flag),
        probe_port: Arc::new(|_| true),
        port: 1,
    };
    let trip = Arc::clone(&flag);
    let calls = AtomicUsize::new(0);
    let mut done: Vec<Value> = Vec::new();
    let (results, outcome) = drive_round_of_one_batch(
        &three_nodes(),
        &[1, 2, 3],
        3,
        // 让位判据恒假；**副作用**是在第 2 次询问（= 首个 join 结果的落账前那一刻）翻开退出标志。
        &move || {
            if calls.fetch_add(1, Ordering::SeqCst) + 1 == 2 {
                trip.store(true, Ordering::SeqCst);
            }
            false
        },
        &mut watch,
        |_| async { None },
        &mut |ev, payload| {
            if ev == EVENT_SPEED_TEST_DONE {
                done.push(payload);
            }
        },
    )
    .await;
    assert_eq!(outcome, "interrupted");
    assert!(
        results.is_empty(),
        "核已退出才被观察到，这个失败不是节点的错 —— 不许落账，得到 {results:?}"
    );
    assert_eq!(done[0]["reason"], json!("core_exited"));
    assert_eq!(
        done[0]["pending"].as_array().unwrap().len(),
        3,
        "三个都没公平测过 ⇒ 三个都要能被「继续剩余」捡回来"
    );
}

/// 🔴 **一个非 UTF-8 字节不得掐断 drain**（否则核还活着、管道从此无人读 = M1 原形态复现）。
///
/// `AsyncBufReadExt::lines()` 遇非 UTF-8 返回 `Err(InvalidData)`，而 `while let Ok(Some(_))` 会把它
/// 当成流结束。sing-box 与 Cronet 的输出完全可能含非 UTF-8（截断的多字节字符、二进制片段、乱码）。
///
/// **牙**：把 `read_until` + `from_utf8_lossy` 换回 `lines()` ⇒ drain 在坏行处退出，写手停在
/// 64 KiB 的管道容量上 ⇒ 下面的字节数断言转红。
#[tokio::test]
async fn drain_keeps_reading_past_a_non_utf8_line() {
    let (mut writer, reader) = tokio::io::duplex(FAKE_PIPE_CAPACITY);
    let (tx, rx) = tokio::sync::watch::channel(0usize);
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let _ = writer.write_all(b"normal line before\n").await;
        // 孤立的 0xFF / 0xFE 在 UTF-8 里非法（不是任何序列的合法前导字节）。
        let _ = writer.write_all(b"broken \xff\xfe line\n").await;
        let mut line = vec![b'y'; 1023];
        line.push(b'\n');
        let mut sent = 0usize;
        while sent < STDERR_FLOOD_BYTES {
            if writer.write_all(&line).await.is_err() {
                return;
            }
            sent += line.len();
            let _ = tx.send(sent);
        }
    });
    // 排空实现自己 `tokio::spawn`，不返回句柄 —— 判据落在**写手推进到哪**：排空一中断，
    // 写手就停在管道容量（64 KiB）上，下面的 `wait_for` 必然超时。
    pipe_to_log(
        Box::new(reader) as polaris_core_supervisor::ChildStream,
        SPEEDTEST_CORE_TARGET,
        None,
        None,
    );
    let mut rx = rx;
    let drained = matches!(
        tokio::time::timeout(
            Duration::from_secs(5),
            rx.wait_for(|n| *n >= STDERR_FLOOD_BYTES),
        )
        .await,
        Ok(Ok(_))
    );
    let written = *rx.borrow();
    assert!(
        drained,
        "坏字节之后必须继续排空：写手只推进到 {written} / {STDERR_FLOOD_BYTES} 字节 —— \
         drain 在坏行处退出了，核会被自己的输出堵死"
    );
}

/// 🔵 **唯一那份 drain 的形态守卫**：不许退回 `lines()`，也不许再长出第二份实现。
///
/// 曾经有两份：主核的 `proxy::core_log::pipe_to_log` 与瞬态核的
/// `tailscale_login_core::drain_to_log`，那时这条门要求**两份**都按字节读 —— 只修一处就等于
/// 承认「另一条腿的坏字节可以掐断排空」是刻意取舍，而它不是。现在两份折叠成一份，判据跟着变成
/// 两半：① 剩下这一份必须按字节读；② 曾经长过第二份的那个文件不许再长回来（两份实现各自漂的
/// 失效方式是静默的 —— 新那份漏掉级别映射、漏掉 EOF 收尾，日志少几行没人会当场发现）。
#[test]
fn the_only_child_stream_drain_reads_bytes_not_lines() {
    let src = crate_code("runtime/proxy/core_log.rs");
    assert!(
        !src.contains("next_line().await"),
        "core_log.rs 又用回了 `lines()`：遇一个非 UTF-8 字节即静默退出 drain，核随后被自己的输出堵死"
    );
    assert!(
        src.contains("read_until(b'\\n'"),
        "core_log.rs 必须按字节读（`read_until`），坏字节经 from_utf8_lossy 渲染而不是中断排空"
    );
    let login = crate_code("runtime/tailscale_login_core.rs");
    assert!(
        !login.contains("read_until(b'\\n'") && !login.contains("next_line().await"),
        "瞬态核不该再自带一份排空实现：折叠掉的那一份正是因为「两份各自漂」才被折叠的"
    );
}

/// 🔴 **回到非诊断档时，上一次的留档必须被收掉**（它含全部被测节点的凭证）。
///
/// 留档与 `singbox-runtime.json` 泄露等级相同，但那份**有主**（核在跑就该在、换配置即被覆盖），
/// 这份**无主**：用户为排查把级别拨到 debug 跑一轮、随后拨回 info，这份带凭证的文件就永远躺在
/// config 目录里，没有任何路径会再碰它。
///
/// **牙**：删掉非诊断路径里那句 `remove_file(TEMP_CORE_LAST_CONFIG_NAME)` ⇒ 转红。
#[tokio::test]
async fn leaving_the_diagnostic_level_reclaims_the_credential_bearing_leftover() {
    let mut h = harness(true, false, vec![20001, 20002, 20003]);
    h.deps.log_level = "trace".to_string();
    let _ = TempCoreSession::run(
        &h.deps,
        &three_nodes(),
        &|| false,
        |_| async { Some(50_u32) },
        &mut |_, _| {},
    )
    .await;
    let kept = h.dir.join(TEMP_CORE_LAST_CONFIG_NAME);
    assert!(kept.exists(), "前提：诊断档这一轮确实留了档");

    // 用户把级别拨回常规档，再测一轮。
    h.deps.log_level = "info".to_string();
    let _ = TempCoreSession::run(
        &h.deps,
        &three_nodes(),
        &|| false,
        |_| async { Some(50_u32) },
        &mut |_, _| {},
    )
    .await;
    assert!(
        !kept.exists(),
        "回到非诊断档必须收掉上一次的留档 —— 那是一份无主的、含节点密码/uuid/WG 私钥的文件"
    );
    cleanup(&h.dir);
}

// ══════════════════════════════════════════════════════════════════════════
// 就绪门 = 本批规模的函数（R0-1）+ spawn 日志定长（R0-2）
//
// 这一组守的是同一件事的两面：**一个在小规模下无害的常数，在大规模下变成缺陷**。
// 就绪门 10s 在 ~240 个 naive 处让整核起不来（零结果 + 指错方向的报错）；端口全量 `{:?}`
// 在 2000 节点处是一行 14 KB。两条都不是「参数调小了」，是「判据没有拿规模当输入」。
// ══════════════════════════════════════════════════════════════════════════

/// `count` 个 naive 形态的 [`TempNode`]（`node.type == "naive"` 是预算公式与核建 engine 的**同一个**判据）。
fn naive_nodes(count: usize) -> Vec<TempNode> {
    (0..count)
        .map(|i| {
            let id = format!("n{i:07}");
            TempNode {
                tag: temp_core_tag(&id),
                id,
                node: json!({ "type": "naive", "server": "example.com" }),
                companion_outbounds: Vec::new(),
                is_endpoint: false,
                has_local_v6: false,
            }
        })
        .collect()
}

/// 🔴 **预算就是文档里那个公式**（表驱动，逐点钉死）。
///
/// 四行覆盖三个档：下限主导（今天跑得通的形态）、公式接管（今天必然失败的形态）、上限拒绝。
/// 系数是**两点回归的推导值**（见 `temp_core_startup_estimate_ms` 的系数出处表）——本条不证明它对，
/// 只证明**代码算的就是文档写的那个数**；系数真值待多点实测，改系数时本表要跟着重算。
///
/// **变异锁**：动三个系数、动安全系数、动下限/上限中的任何一个 → 本条转红并指出是哪一行。
#[test]
fn ready_budget_is_the_documented_function_of_batch_scale() {
    // (n, m, 估算 ms, 预算 ms)
    for (n, m, est, budget) in [
        (0_usize, 0_usize, 90_u64, 10_000_u64), // 空批：只剩固定项，下限主导
        (118, 58, 2_480, 10_000), // 真机形态：估算 2.48s，仍在下限之内 ⇒ 本改动对它是空操作
        (240, 120, 5_035, 10_070), // 交叉点：公式在此处刚刚超过下限并接管
        (500, 250, 10_392, 20_784), // 固定 10s 门下「必然偶发失败」的那一档
        (1_000, 500, 20_695, 41_390), // 固定 10s 门下「必然超时」的那一档
    ] {
        assert_eq!(
            temp_core_startup_estimate_ms(n, m),
            est,
            "估算失配：n={n} m={m}"
        );
        assert_eq!(
            temp_core_ready_timeout_ms(n, m),
            Ok(budget),
            "预算失配：n={n} m={m}"
        );
    }
}

/// 🔴 **收口到单一真值那一刻，三个函数对任意输入的返回值一个都没变**（等价性收据）。
///
/// # 本条是什么、不是什么
///
/// 2026-09-03 本文件生产侧那四个与 core-supervisor 逐值相同的 `TEMP_CORE_*` 系数副本被删掉，改调
/// `core_startup_estimate_ms` 与单一真值常量（判词见 `runtime/speedtest.rs` 常量原位的注释）。收口
/// **声称**是纯重构、行为逐字不变；本条是那句声称的收据：下面每一格的期望值都是**收口前的实现算出来
/// 的数**，逐字冻在这里。收口后代码若在任何一格上给出别的数，那句声称就是假的。
///
/// 它**不**证明这些系数是对的（那是多点实测的事，见 `CORE_STARTUP_PER_NAIVE_MS` 的分级表），也**不**
/// 替代 [`ready_budget_is_the_documented_function_of_batch_scale`]（那条钉的是「代码算的就是文档写的
/// 那个公式」）。本条只钉「收口前 == 收口后」，取样刻意压在边界上：n=0 / m=0、下限与公式的交叉点两侧、
/// 两条批上限**同时**贴顶的那一批、越界腿触发点的两侧，以及 `usize::MAX` 那个饱和面 —— 收口时若把
/// `saturating_*` 换成裸算术，回绕会把一个天文数字的预算算成一个极小的门，正是这个模型要消灭的失败面，
/// 不能由收口重新引入。
///
/// # 后来的人：多点实测把系数改了之后本条会红 —— 那是**正确**的
///
/// 那时它红的含义不是「收口坏了」，而是「你正在改的这个数确实会改变这三个函数的输出」。照新系数重算
/// 本表即可（与 [`ready_budget_is_the_documented_function_of_batch_scale`] 同一套动作）。
///
/// **变异锁**：`CORE_STARTUP_BASELINE_FIXED_MS` / `CORE_STARTUP_PER_NODE_US` /
/// `CORE_STARTUP_PER_NAIVE_MS` / `CORE_READY_SAFETY_FACTOR` 任改一个 → 转红并指出是哪一格。
#[test]
fn the_single_source_collapse_returns_the_same_values() {
    // ① 估算与就绪预算：(n, m) → (估算 ms, 预算)
    for (n, m, est, budget, why) in [
        (
            0_usize,
            0_usize,
            90_u64,
            Ok(10_000_u64),
            "空批：只剩固定项，下限主导",
        ),
        (0, 1, 131, Ok(10_000), "n=0 的邻边"),
        (512, 0, 143, Ok(10_000), "n 贴批上限、m=0"),
        (0, 119, 4_969, Ok(10_000), "下限仍主导的最后一格"),
        (0, 120, 5_010, Ok(10_020), "公式接管的第一格"),
        (512, 142, 5_965, Ok(11_930), "两条批上限同时贴顶"),
        (
            0,
            729,
            29_979,
            Ok(59_958),
            "越界腿触发点左侧（最后一个 Ok）",
        ),
        (0, 730, 30_020, Err(60_040), "越界腿触发点（第一个 Err）"),
    ] {
        assert_eq!(
            temp_core_startup_estimate_ms(n, m),
            est,
            "估算变了：n={n} m={m}（{why}）"
        );
        assert_eq!(
            temp_core_ready_timeout_ms(n, m),
            budget,
            "预算变了：n={n} m={m}（{why}）"
        );
    }
    // 饱和面：`saturating_*` 一个都不许丢。
    assert_eq!(
        temp_core_startup_estimate_ms(usize::MAX, 0),
        18_446_744_073_709_641,
        "n 项饱和面变了"
    );
    assert_eq!(
        temp_core_ready_timeout_ms(usize::MAX, usize::MAX),
        Err(u64::MAX),
        "预算饱和面变了"
    );

    // ② 越界报错里那个「本批节点数下单核最多带 N 个 naive」
    for (n, want) in [
        (0_usize, 144_usize),
        (512, 142),
        (900, 141),
        (4_000, 133),
        (55_904, 1),
        (55_905, 0), // 已登记的纯理论 nit：n 大到 c_parse 项吃掉整个预算 ⇒ 报 0
        (usize::MAX, 0),
    ] {
        assert_eq!(temp_core_max_naive(n), want, "上限变了：n={n}");
    }

    // ③ 批 naive 上限的可参数化内核（两条预算各绑一次 + 饱和面）。输入写字面量而不是那两个常量：
    // 本条要钉的是「同一个输入给同一个输出」，输入本身跟着常量走就不再是同一个输入了。
    for (cap, rss, want, why) in [
        (6_000_u64, 262_144_u64, 142_usize, "生产取值：时间腿在绑"),
        (12_000, 262_144, 152, "时间腿放宽 ⇒ 内存腿接管"),
        (12_000, 1_048_576, 289, "两条都放宽 ⇒ 时间公式本身"),
        (0, 0, 0, "两条预算都为 0 ⇒ 饱和到 0，不回绕成天文数字"),
    ] {
        assert_eq!(
            temp_core_batch_naive_cap(cap, rss),
            want,
            "批上限变了：cap={cap} rss={rss}（{why}）"
        );
    }
}

/// 🔴 **下限这条接线还在** —— 公式的固定项只有 90ms，没有 `.max(FLOOR)` 时一个小订阅会拿到 0.2s 的门。
///
/// # 本条守什么、不守什么（名字与文档必须如实，否则会被当成第二道锁）
///
/// 判据是 `budget >= FLOOR`，而实现就是 `.max(FLOOR)` ⇒ 本条与实现**同义反复**，它唯一能抓的变异是
/// **`.max(FLOOR)` 被删掉**。它**抓不到**「把 FLOOR 本身改小」：把 10_000 改成 5_000，`budget >= 5_000`
/// 照样成立，本条保持绿。所以「门不会比今天窄」这个承诺**不由本条承载** —— 它由
/// [`the_floor_stays_at_the_only_value_with_production_evidence`] 钉住那个字面值。两条各守一半，
/// 少任何一条，另一条都拦不住对方那种改法。
///
/// 全称断言（扫过下限接管区两侧）而不是取一个点：接线被删时小 n 才露馅，取样点选在交叉点右侧就看不见。
///
/// **变异锁**：删掉 `.max(FLOOR)` → n 小时预算落到几百 ms → 转红。
#[test]
fn the_floor_is_actually_applied_to_the_budget() {
    for m in 0..=300_usize {
        let budget = temp_core_ready_timeout_ms(m * 2, m).expect("这一段不该越上限");
        assert!(
            budget >= TEMP_CORE_READY_TIMEOUT_FLOOR_MS,
            "n={} m={m} 的门比历史固定值还窄：{budget}ms",
            m * 2
        );
    }
}

/// 🔴 **下限的字面值必须仍是 10_000** —— 「今天能跑通的订阅不受影响」这条承诺的唯一锚点。
///
/// # 为什么这条不能靠上面那条代劳
///
/// [`the_floor_is_actually_applied_to_the_budget`] 判的是 `budget >= FLOOR`，而 `FLOOR` 就是被改的那个
/// 数 ⇒ 把它改成 5_000，那条门全程保持绿。**复审实测过这个洞**：跨语言那侧的门当时用裸
/// `readFileSync` + 正则读源码且不剥注释，于是「在文档注释里写一行假的常量定义 + 把真常量改成
/// 5_000」⇒ UI 门 40/40 全绿。本条是 Rust 侧的对应锁：它读的是**编译进来的那个值**，注释怎么写都
/// 与它无关。TS 侧的对应锁在 `ui/src/lib/speedtest-progress-toast.test.ts`（已改走 `moduleSource`
/// 入口 + 剥注释 + 命中数自检）。
///
/// # 这个数不许动的判据
///
/// 10s 是**唯一有生产证据**的取值（已发布、已在真机上跑）。调小 = 在没有任何新证据的前提下把门收窄
/// 到一个从未跑过的取值上，而收窄的失败面（正在正常启动的核被判死 ⇒ 整批零结果 ⇒ 报错指向网络）
/// 正是本改动存在的理由。要动它，先拿多点实测把 `t_engine` 的真值钉下来。
///
/// **变异锁**：`TEMP_CORE_READY_TIMEOUT_FLOOR_MS` 改成任何别的值（哪怕同时在注释里补一行假定义）→ 转红。
#[test]
fn the_floor_stays_at_the_only_value_with_production_evidence() {
    assert_eq!(
        TEMP_CORE_READY_TIMEOUT_FLOOR_MS, 10_000,
        "下限被改动了。它是「今天能跑通的订阅一律不受影响」这条承诺的唯一锚点：\
         改小 = 把门收窄到一个没有任何生产证据的取值上，而收窄的失败面正是本改动要消灭的那个。\
         真要改，先补多点实测把 t_engine 的真值钉下来，再连同本断言与文档一起改。"
    );
}

/// 🔴 **门是规模的函数，不许有人把它改回一个不看规模的常数**。
///
/// 三条腿分别堵三种「退回常数」的写法：
/// 1. 生产装配不带覆写（写成 `Some(10_000)` 就是原地复活那个常数）；
/// 2. naive 数一多，预算必须**严格**变大（任何常数形态在这里都会相等 ⇒ 转红）；
/// 3. 节点数也进账（`c_parse` 项被抹成 0 → 转红）。
#[test]
fn production_ready_gate_is_scale_derived_not_a_constant() {
    let deps = TempCoreDeps::production(
        PathBuf::from("/nonexistent-config-dir"),
        PortExclusions::for_primary_api(None, None, None, None),
        "info".to_string(),
    );
    assert!(
        deps.ready_timeout_override_ms.is_none(),
        "生产装配一旦带上定值覆写，就等于把规模门整个短路掉"
    );

    let small = temp_core_ready_timeout_ms(400, 200).unwrap();
    let large = temp_core_ready_timeout_ms(800, 400).unwrap();
    assert!(
        large > small && small > TEMP_CORE_READY_TIMEOUT_FLOOR_MS,
        "naive 翻倍而门没变宽（{small}ms → {large}ms）⇒ 门没在看规模"
    );

    assert!(
        temp_core_startup_estimate_ms(20_000, 0) > temp_core_startup_estimate_ms(0, 0),
        "节点数完全不进账 ⇒ 公式里少了一项"
    );
}

/// 🔴 **naive 数从核自己派发用的那个字段读**（判据同源，不可能与配置生成漂移）。
///
/// 走的是**生产路径** `plan_temp_core` 的真实产出，不是手搓的 JSON —— 手搓只能证明函数会数
/// `type` 字段，证明不了生产真的会把 `"naive"` 写进那个位置。含反向对照（无 naive 的一批必须数出 0），
/// 否则「数出 1」没有信息量。
///
/// **变异锁**：把判据换成 `TempNode` 上另存的布尔标记 / 换成别的键名 → 转红。
#[test]
fn naive_count_reads_the_field_the_core_itself_dispatches_on() {
    let plan = plan_temp_core(
        &[
            srv("n1111111", Protocol::Naive),
            srv("v1111111", Protocol::Vless),
        ],
        &env(),
    );
    assert_eq!(
        plan.testable.len(),
        2,
        "前提：两个节点都得建成，否则本条没测到东西"
    );
    assert_eq!(
        temp_core_naive_count(&plan.testable),
        1,
        "生产产出的 naive 出站没被数到 ⇒ 预算恒按 0 个 engine 算 ⇒ 规模门整个失效"
    );
    assert_eq!(
        temp_core_naive_count(&plan.testable[1..]),
        0,
        "反向对照：不含 naive 的一批必须数出 0"
    );
}

/// 🔴 **越过上限的一批：当场拒绝、绝不起核，且报错说清是规模问题**。
///
/// 「静默截断到上限再当成超时」是本改动明确不选的形态：那样用户拿到的是 `未就绪（Timeout）`，
/// 指向网络/端口，与固定 10s 门在 240 naive 上的误诊逐字相同。
///
/// **四重牙**：
/// 1. `spawns == 0` —— 把规模判挪到 spawn 之后 → 转红（真机代价 = 白烧 N 个回环端口 + 一个要收的核）；
/// 2. harness 的端口池是**空的** ⇒ 一旦判据挪到端口分配之后，报错会变成「端口分配失败」→ 文案断言转红；
/// 3. 报错必须带 naive 数、上限、以及**可执行的上限 naive 数** —— 少任何一个，用户只能二分猜；
/// 4. 结局必须是 [`TempCoreOutcome::Oversized`] 而**不是** `Failed` —— 折回 `Failed` ⇒ 命令层发出
///    `SPEEDTEST_TEMP_CORE_FAILED` ⇒ 前端显示的和「核起不来超时」逐字相同（`nodes.speedTestInterrupted`），
///    用户被支去查网络/端口。那正是本改动要消灭的误诊，只是换了一层重建。
#[tokio::test]
async fn oversized_batch_is_refused_before_spawning_and_says_why() {
    let mut h = harness(true, false, Vec::new());
    h.deps.ready_timeout_override_ms = None; // 走生产口径（覆写只为让别的用例免等真实超时）
    let nodes = naive_nodes(900);
    // 直接驱动**批级**入口：分批（T1-R1）之后 `run` 会把这 900 个先切开，规模门再也拦不到它
    // ——那是本轮的目的，不是本门的失效。本门守的是「万一有一批真的越界，它必须被前置拒绝且
    // 说清是规模问题」这条前置条件检查本身；「生产路径永远送不出越界的批」由
    // `planned_batches_never_trip_the_oversize_refusal` 单独证明。
    let mut progress = RoundProgress::new(nodes.len());
    let out = TempCoreSession::run_batch(
        &h.deps,
        &nodes,
        &|| false,
        |_| async { Some(50_u32) },
        &mut |_, _| {},
        &mut progress,
    )
    .await;
    let msg = match out {
        BatchOutcome::Failed {
            detail,
            oversized: true,
        } => detail,
        other => panic!(
            "越界批必须打上 `oversized` 标（独立错误码的唯一来源），得到 {other:?} —— \
             折成普通 `Failed` 会让前端把它显示成「测速中断」，与就绪超时逐字相同"
        ),
    };
    assert!(msg.contains("规模超限"), "报错没说是规模问题：{msg}");
    assert!(msg.contains("900"), "报错没带本批节点数：{msg}");
    assert!(
        msg.contains(&TEMP_CORE_READY_TIMEOUT_CAP_MS.to_string()),
        "报错没带上限：{msg}"
    );
    assert!(
        msg.contains(&temp_core_max_naive(900).to_string()),
        "报错没给出可执行的 naive 上限：{msg}"
    );
    assert_eq!(
        h.spawns.load(Ordering::SeqCst),
        0,
        "越界批绝不许起核：起了就要白烧 N 个回环端口、还要收一个注定被判超时的子进程"
    );
    assert!(!h.dir.join(TEMP_CORE_CONFIG_NAME).exists(), "也不该写配置");
    cleanup(&h.dir);
}

/// 🔴 **越界腿必须落一行日志** —— 否则「规模门可观测」这条承诺在生产上是假的。
///
/// # 为什么这条必须是源码守卫
///
/// 越界腿的四个数（n / m / 估算 / 预算）此外只活在报错字符串里，而那条字符串一路是：
/// `Oversized(msg)` → 命令层 `err_with_code`（`response.rs` 的失败信封**不写日志**）→ 前端按码换成
/// 本地化文案。⇒ 不落这一行，事后排查一个数都读不到。而 `spawn` 那条带规模数字的 `log::info!` 走的是
/// 起核**之后**，越界腿根本到不了它 —— 「那边已经打过了」是错觉。
///
/// 行为级验证在本仓做不到：`log::warn!` 的落点是全局 logger，注入不进来，捕获它要引一个测试用
/// logger 依赖（新增依赖，且只服务这一条断言）。故用取材器把判据钉在**接线**上。
///
/// **三重牙**：① 越界臂里确实有 `log::warn!`；② 它排在 `Err(budget)` 与 `Oversized(` 之间（挪到别的臂
/// 里、或降级成只在别处打，位置断言转红）；③ 四个数与上限都在那条格式串里（少一个 ⇒ 日志读不出
/// 「门为什么是这个数」）。
///
/// **变异锁**：删掉那条 `log::warn!` → ①② 转红；把 `{budget_ms}` 从格式串里去掉 → ③ 转红。
#[test]
fn the_oversize_refusal_logs_the_numbers_it_refused_on() {
    let body = crate::commands::guard_scan::impl_method_body(
        &module_code("runtime/speedtest"),
        "    async fn run_batch<Meas, MeasFut>(",
    );
    let at_err = body
        .find("Err(budget)")
        .expect("越界臂的锚点 `Err(budget)` 没了 —— 规模门被改写了，本门已失去判据，不得静默放行");
    let at_warn = body[at_err..]
        .find("log::warn!")
        .map(|i| i + at_err)
        .expect(
            "越界腿一条日志都不打：n / m / 估算 / 预算 这四个数此外只活在报错字符串里，\
             而那条字符串会被折成结构化码 + 前端本地化文案 ⇒ 生产上「门为什么拒了这批」不可观测",
        );
    let at_ret = body[at_err..]
        .find("oversized: true")
        .map(|i| i + at_err)
        .expect("越界臂不再打 `oversized` 标 —— 独立错误码的来源没了");
    assert!(
        at_warn < at_ret,
        "日志必须落在越界臂内、返回之前（现在它在返回之后 ⇒ 多半是被挪进了别的分支）"
    );
    // 格式串里必须出现这五样东西。`module_code` 只抹注释、保留字符串字面量，故这是在读真格式串。
    let line = &body[at_warn..at_ret];
    for needle in [
        "naive {naive_count}",
        "估算起核",
        "{budget}ms",
        "TEMP_CORE_READY_TIMEOUT_CAP_MS",
        "nodes.len()",
    ] {
        assert!(
            line.contains(needle),
            "越界日志里缺 `{needle}` —— 少一个数，事后就推不出「门为什么是这个数」：{line}"
        );
    }
}

/// 🔴 **越界报错里那个「最多带 N 个」必须是「照它砍下去这一轮真的跑得通」的数**。
///
/// # 判据在 T1-R1 改过（旧判据更弱，输入对差如下）
///
/// 旧判据是「`m` 恰好不触发 60s 拒绝腿，`m + 1` 触发」。分批之后它**放行了一个有害的数**：
/// 60s 对应 m ≈ 727，而单批真正的窗口是 12s（前端 20s 静默兜底减去批间固定开销）。用户照 727
/// 砍完 ⇒ 单批预算 ≈30s ⇒ 拿到一条假的「测速中断」，而现场没有任何东西指向批太大。
///
/// | 输入 | 旧判据 | 新判据 |
/// |---|---|---|
/// | 分母 = `CAP(60s)/SAFETY`（改前的实现） | 绿 | **红**（m=727 的预算 ≈30s > 12s 批窗） |
/// | 分母 = `BATCH_READY_BUDGET_CAP(12s)/SAFETY`（本批的实现） | **红**（m+1 仍不触发 60s ⇒ 第二条断言失败） | 绿 |
/// | 分母被改成任意更大的值 | 视值而定 | 红 |
///
/// ⇒ 新判据**严格更强**：它同时钉住「不越 60s 拒绝腿」（第一条）与「不越 12s 批窗」（第二、三条），
/// 旧判据只钉前者。
///
/// ⚠️ **射程登记**：本条与 `oversized_batch_is_refused_before_spawning_and_says_why`、
/// `the_oversize_refusal_logs_the_numbers_it_refused_on`、命令层那条码分流门、前端那条文案分流门
/// 一共 **5 条**，守的都是同一条**生产不可达**的链路（分批之后单批预算至多 ≈11.9s，碰不到 60s）。
/// 它们不是假绿门（代码改坏照样红），但**不能被读成「这条路是活的」** —— 用户在正常运行的
/// 应用里永远看不到这条腿。它们存在的理由只有一个：规划器被绕过或回归时，这是唯一会喊出来的地方。
///
/// **变异锁**：把 `temp_core_max_naive` 的分母改回 `TEMP_CORE_READY_TIMEOUT_CAP_MS` → 转红。
#[test]
fn advertised_naive_ceiling_is_the_largest_batch_that_actually_runs() {
    for n in [0_usize, 500, 1_500, 4_000] {
        let m = temp_core_max_naive(n);
        // ① 报出去的数自己不许触发那条拒绝腿（否则用户砍到它仍被拒）。
        assert!(
            temp_core_ready_timeout_ms(n, m).is_ok(),
            "n={n}：报出去的上限 {m} 自己就越了 60s 拒绝腿"
        );
        // ② 它必须装得进**批窗**——这才是「照它砍下去真的跑得通」的判据。
        let budget = |m: usize| CORE_READY_SAFETY_FACTOR * temp_core_startup_estimate_ms(n, m);
        assert!(
            budget(m) <= TEMP_CORE_BATCH_READY_BUDGET_CAP_MS,
            "n={n}：报出去的上限 {m} 对应预算 {}ms 越过批窗 {TEMP_CORE_BATCH_READY_BUDGET_CAP_MS}ms \
             ⇒ 用户照它砍完会拿到一条假的「测速中断」",
            budget(m)
        );
        // ③ 而且是**恰好**那个（报小了等于让用户白砍）。
        assert!(
            budget(m + 1) > TEMP_CORE_BATCH_READY_BUDGET_CAP_MS,
            "n={n}：上限 {m} 报小了，{} 其实也装得进批窗",
            m + 1
        );
    }
}

/// 🔴 **就绪门解析之前一条 `progress` 都不许发** —— 这是后端门可以远超前端 20s 兜底的**全部理由**。
///
/// # 两侧的耦合长什么样
///
/// 前端 `speedtest-progress-toast.ts` 的 `SPEEDTEST_IDLE_TIMEOUT_MS = 20_000` 是「两次进度事件之间
/// 静默这么久 ⇒ 判为中断」。它**只在收到第一条 progress 之后才布防**（`armIdle` 在 `state.live`
/// 为假时早退）⇒ 起核到就绪那一整段窗口里前端没有任何定时器，后端的门取多大都碰不到它。
///
/// 反过来说：**一旦有人在 spawn 处补一条 progress 事件**（"让用户看见在起核" 是个很自然的想法），
/// 20s 的兜底就会在那一刻布防，而本批的就绪预算可以合法地到 60s ⇒ 用户会在核还在正常启动时
/// 看到一条假的「测速中断」+ 一个点了会白跑的「继续」。本条就是拦这个改动的。
///
/// 前端那一半由 `speedtest-progress-toast.test.ts` 的
/// 「首个进度事件之前一个定时器都不许布防」对称守住。
#[tokio::test]
async fn no_progress_event_escapes_before_the_readiness_gate_resolves() {
    let h = harness(false, false, vec![20001, 20002, 20003]); // 永不就绪 ⇒ 走满整个就绪门
    let mut events: Vec<String> = Vec::new();
    let out = TempCoreSession::run(
        &h.deps,
        &three_nodes(),
        &|| false,
        |_| async { Some(50_u32) },
        &mut |ev, _| events.push(ev.to_string()),
    )
    .await;
    assert!(
        matches!(out, TempCoreOutcome::Failed(_)),
        "前提：这一轮确实卡在就绪门上"
    );
    assert!(
        !events.iter().any(|e| e == EVENT_SPEED_TEST_PROGRESS),
        "就绪门之前发 progress ⇒ 前端 20s 兜底当场布防，而后端门可以合法地到 60s：{events:?}"
    );
    assert!(
        !events.iter().any(|e| e == EVENT_SPEED_TEST_RESULT),
        "核都没就绪就推逐节点结果 = 伪造测量：{events:?}"
    );
    cleanup(&h.dir);
}

/// 🔴 **spawn 日志里的端口摘要定长**（R0-2）。
///
/// 判据是「跨四个数量级长度不涨」，不是「比原来短」——后者用一个 `truncate(200)` 就能骗过去，
/// 而那仍然是线性的（只是斜率被截断），且会把尾端端口整段吞掉。
///
/// **变异锁**：退回 `format!("{ports:?}")` → 2000 端口那一行长度断言当场转红。
#[test]
fn spawn_log_port_summary_stays_constant_length_across_batch_sizes() {
    for n in [7_usize, 200, 2_000, 60_000] {
        let ports: Vec<u16> = (0..n)
            .map(|i| 1024 + u16::try_from(i % 60_000).unwrap())
            .collect();
        let line = format_ports_for_log(&ports);
        assert!(
            line.len() <= 96,
            "{n} 个端口的日志行 {} 字节，摘要没起作用：{line}",
            line.len()
        );
        assert!(
            line.starts_with(&format!("{n} 个 ")),
            "摘要必须先报数量（排查唯一真正要问的那个数）：{line}"
        );
    }

    // 小批仍然全量列出 —— 摘要不该在信息量本来就够小的地方制造缺口。
    assert_eq!(
        format_ports_for_log(&[20001, 20002, 20003]),
        "3 个 [20001, 20002, 20003]"
    );

    // **反向对照**：证明本门守的是一个真实存在的膨胀，而不是一句空断言。
    let big: Vec<u16> = (0..2_000)
        .map(|i| 20_000 + u16::try_from(i).unwrap())
        .collect();
    assert!(
        format!("{big:?}").len() > 13_000,
        "前提校验：全量打印在这一批上确实是**一行 14 KB**（实得 {} 字节）",
        format!("{big:?}").len()
    );
}

// ══════════════════════════════════════════════════════════════════════════
// T1-R1：分批起临时核 —— 峰值资源与订阅节点数无关（O(1)），耗时允许 O(N)
//
// 分批之前，一轮把全部 N 个节点塞进**一份**配置：N 个 http 入站 + N 个出站，其中每个 naive 出站
// 是一个独立的 Chromium Cronet Engine（≈1.3 MB + 2 线程 + 6 fd，由内核在入站 bind 之前**串行**
// eager 启动）⇒ RSS / 线程 / fd / 回环端口 / 起核耗时**全部**随 N 线性。本节的门守的是
// 「切完之后每一批的规模被封在常数上」这件事本身，而不是「到 N 为止还能撑住」。
// ══════════════════════════════════════════════════════════════════════════

/// 造 `n` 个节点，其中每 `naive_every` 个里有一个是 naive（`0` = 一个都没有）。
///
/// naive 的位置**均匀分布**而不是集中在头部：贪心装箱要在两条上限之间切换（naive 多的地方按 m 切、
/// 少的地方按 n 切），取样点如果只给「全 naive」和「零 naive」两个极端，混合形态那条路就没人走。
fn mixed_nodes(n: usize, naive_every: usize) -> Vec<TempNode> {
    (0..n)
        .map(|i| {
            let id = format!("mix{i:07}");
            let is_naive = naive_every > 0 && i % naive_every == 0;
            TempNode {
                tag: temp_core_tag(&id),
                id,
                node: if is_naive {
                    json!({ "type": "naive", "server": "example.com" })
                } else {
                    json!({ "type": "trojan", "server": "example.com" })
                },
                companion_outbounds: Vec::new(),
                is_endpoint: false,
                has_local_v6: false,
            }
        })
        .collect()
}

/// 造**两条上限都贴顶**的一批：n = [`TEMP_CORE_BATCH_MAX_NODES`]、m = [`temp_core_batch_max_naive`]，
/// 且第 m+1 个 naive 不存在 ⇒ 规划器恰好把它当成一整批。
///
/// # 为什么上限要取**现值**而不是写死 512 / 142
///
/// 本夹具服务的是「上限调大一点点就该转红」这条承诺。写死数字 ⇒ 把上限从 142 调到 143 时夹具还是
/// 造 142 个 naive，最坏形态根本没被取到，门要到 +2 才红（复审 2026-09-03 实测正是这个洞）。
/// 取现值 ⇒ 上限一涨，夹具跟着造出更坏的那一批，**+1 即红**。
fn topped_out_batch() -> Vec<TempNode> {
    let m = temp_core_batch_max_naive();
    (0..TEMP_CORE_BATCH_MAX_NODES)
        .map(|i| {
            let id = format!("top{i:07}");
            TempNode {
                tag: temp_core_tag(&id),
                id,
                node: if i < m {
                    json!({ "type": "naive", "server": "example.com" })
                } else {
                    json!({ "type": "trojan", "server": "example.com" })
                },
                companion_outbounds: Vec::new(),
                is_endpoint: false,
                has_local_v6: false,
            }
        })
        .collect()
}

/// 🔴 **O(1) 的验收判据本体：峰值批规模不随订阅规模增长**。
///
/// # 为什么判据是「峰值不变」而不是「能撑到 N」
///
/// 仓主定的目标函数是**资源占用与节点数无关**，不是「上限抬到多少」。抬上限的方案在任何一个取样点
/// 之外都会重新失效，而且没人知道下一个用户的订阅有多大。故本条的判据形态是：**同一个 naive 比例
/// 下，N 从 100 涨到 10000（两个数量级），每批的节点数上界与 naive 数上界一个都不许动**；随 N 增长
/// 的只许是**批数**（线性）。
///
/// 批规模一旦封住，配置里的入站数 / 出站数 / 回环端口数 / engine 数 / 核 RSS / 核线程数
/// / 起核耗时**全部**跟着封住 —— 它们都是 `(n_batch, m_batch)` 的函数，与 N 无关。
///
/// **变异锁**：
/// - 把 [`plan_temp_core_batches`] 换成「一批装完」（返回 `vec![nodes]`）→ 峰值随 N 涨 → 转红；
/// - 只按 n 切、不看 m（定长 `chunks(TEMP_CORE_BATCH_MAX_NODES)`）→ 全 naive 那一列的 m 峰值涨到
///   512 → 转红；
/// - 切批时丢节点 / 乱序 / 重复 → 最后那条重组断言转红。
#[test]
fn batch_plan_keeps_peak_scale_flat_as_the_subscription_grows() {
    // (naive 每隔几个一个, 说明)
    for (naive_every, shape) in [(0_usize, "零 naive"), (2, "半数 naive"), (1, "全 naive")] {
        // **空操作对照**：真机形态那一档（≈118 节点）必须仍然是**一批** —— 分批对今天跑得通的
        // 订阅逐字无影响（一次起核、一份配置、同一条事件流），这是本改动的射程边界。
        assert_eq!(
            plan_temp_core_batches(&mixed_nodes(118, naive_every)).len(),
            1,
            "{shape}：118 节点的真机形态被切开了 ⇒ 本改动对今天能跑通的订阅不再是空操作"
        );

        let mut peak_nodes: Option<usize> = None;
        let mut peak_naive: Option<usize> = None;
        let mut prev: Option<(usize, usize)> = None; // (N, 批数)
                                                     // 两个取样点都远高于任何一条上限 ⇒ 峰值已经饱和，跨一个数量级必须逐字不变。
        for n in [1_000_usize, 10_000] {
            let nodes = mixed_nodes(n, naive_every);
            let batches = plan_temp_core_batches(&nodes);
            let max_nodes = batches.iter().map(|b| b.len()).max().unwrap_or(0);
            let max_naive = batches
                .iter()
                .map(|b| temp_core_naive_count(b))
                .max()
                .unwrap_or(0);

            assert!(
                max_nodes <= TEMP_CORE_BATCH_MAX_NODES,
                "{shape} N={n}：单批 {max_nodes} 个节点越过上限 {TEMP_CORE_BATCH_MAX_NODES}"
            );
            assert!(
                max_naive <= temp_core_batch_max_naive(),
                "{shape} N={n}：单批 {max_naive} 个 naive 越过上限 {}",
                temp_core_batch_max_naive()
            );

            // ── 本门的核心：峰值跨一个数量级**逐字不变** ──
            if n > 1_000 {
                assert_eq!(
                    Some(max_nodes),
                    peak_nodes,
                    "{shape}：N 从上一档涨到 {n} 时单批节点数峰值变了 ⇒ 峰值资源仍然在跟着订阅规模走"
                );
                assert_eq!(
                    Some(max_naive),
                    peak_naive,
                    "{shape}：N 从上一档涨到 {n} 时单批 naive 峰值变了 ⇒ engine 数仍然在跟着订阅规模走"
                );
            }
            peak_nodes = Some(max_nodes);
            peak_naive = Some(max_naive);

            // 批数 = ⌈N / 峰值批规模⌉ —— 比「约等于线性」强：它同时说明每一批都**装满了**
            // （贪心没有提前切），故批数只随 N 线性增长，这正是允许 O(N) 的那一维。
            assert_eq!(
                batches.len(),
                n.div_ceil(max_nodes),
                "{shape} N={n}：批数不是 ⌈N/{max_nodes}⌉ ⇒ 要么切早了（白起核），要么峰值算错了"
            );
            if let Some((prev_n, prev_batches)) = prev {
                assert!(
                    batches.len() > prev_batches && n > prev_n,
                    "{shape}：N 涨了批数却没涨 ⇒ 某一批把多出来的节点吃进去了"
                );
            }
            prev = Some((n, batches.len()));

            // 保序、不丢、不重：切批只许换个装法，不许动集合本身。
            let flat: Vec<&str> = batches
                .iter()
                .flat_map(|b| b.iter().map(|x| x.id.as_str()))
                .collect();
            let want: Vec<&str> = nodes.iter().map(|x| x.id.as_str()).collect();
            assert_eq!(flat, want, "{shape} N={n}：切批改变了节点集合或顺序");
        }
    }
}

/// 🔴 **每一批的就绪预算都装得进前端那个 20s 静默兜底** —— 这是 D1 里更紧的那条约束。
///
/// # 它守的是什么
///
/// 分批之后批间会出现一段没有测量结果的空窗（收上一批的核 → check → spawn → 就绪门）。前端
/// `SPEEDTEST_IDLE_TIMEOUT_MS` 是「两条进度事件之间静默 20s ⇒ 判为中断」，且它在批 1 的进度事件
/// 之后就已经布防 ⇒ 空窗越界，用户会在测速**正常进行**时看到一条假的「测速中断」。
///
/// 空窗被两条心跳切成三段（见 [`TEMP_CORE_BATCH_WINDOW_OVERHEAD_MS`]），只有中间那段随批规模变，
/// 于是约束落在**单批的就绪预算**上。
///
/// # 为什么不用 `temp_core_ready_timeout_ms` 算预算（这是刻意的）
///
/// 那个函数会先撞 60s 的**单核拒绝腿**并返 `Err`。用它 ⇒ 「批上限被调大」与「60s 常量被调小」
/// 两种完全不同的改动在本门上长得一样，而后者是
/// [`planned_batches_never_trip_the_oversize_refusal`] 的对象。两条门的红因纠缠在一起，就没法
/// 从红报里读出该改哪个数。故本门直接用「预算 = 安全系数 × 估算，再取下限」这条原式 ——
/// 它与生产实现的一致性由 R0 的 `ready_budget_is_the_documented_function_of_batch_scale` 钉住。
///
/// # 取样必须含**贴顶**形态
///
/// [`topped_out_batch`] 是唯一能让「上限 +1 即红」成立的取样点：`mixed_nodes` 那几档要么 n 先满
/// （m 远没到上限）、要么 m 先满（n 只有一两百），两条上限**同时**贴顶的那一批取不到，于是把
/// naive 上限从 142 调到 143 时全部取样点都还绿，要到 +2 才红（复审 2026-09-03 实测）。
///
/// **变异锁**：把 [`TEMP_CORE_BATCH_MAX_NODES`] 或 [`temp_core_batch_max_naive`] 调大 **1**
/// → 贴顶那一批的预算越过上限 → 转红并报出是哪一批。
#[test]
fn every_planned_batch_fits_the_frontend_idle_window() {
    let raw_budget = |n: usize, m: usize| {
        (CORE_READY_SAFETY_FACTOR * temp_core_startup_estimate_ms(n, m))
            .max(TEMP_CORE_READY_TIMEOUT_FLOOR_MS)
    };
    let mut samples: Vec<(String, Vec<TempNode>)> = Vec::new();
    for naive_every in [0_usize, 1, 2, 3, 7] {
        for n in [1_usize, 143, 513, 2_000] {
            samples.push((
                format!("naive_every={naive_every} N={n}"),
                mixed_nodes(n, naive_every),
            ));
        }
    }
    samples.push((
        "贴顶形态（n 与 m 同时顶到上限）".to_string(),
        topped_out_batch(),
    ));

    let mut saw_topped_out = false;
    for (shape, nodes) in &samples {
        for (i, batch) in plan_temp_core_batches(nodes).iter().enumerate() {
            let m = temp_core_naive_count(batch);
            if batch.len() == TEMP_CORE_BATCH_MAX_NODES && m == temp_core_batch_max_naive() {
                saw_topped_out = true;
            }
            let budget = raw_budget(batch.len(), m);
            assert!(
                budget <= TEMP_CORE_BATCH_READY_BUDGET_CAP_MS,
                "{shape} 第 {i} 批（{} 节点 / {m} naive）的就绪预算 {budget}ms 越过批上限 \
                 {TEMP_CORE_BATCH_READY_BUDGET_CAP_MS}ms ⇒ 批间空窗可能超过前端 \
                 {TEMP_CORE_UI_IDLE_TIMEOUT_MS}ms 的静默兜底，用户会看到假的「测速中断」",
                batch.len()
            );
        }
    }
    assert!(
        saw_topped_out,
        "取样里没有任何一批同时顶到两条上限 ⇒ 「上限 +1 即红」这条承诺落空（本门会到 +2 才红）"
    );
}

/// 🔴 **内存预算这条腿确实在把关**（不只是「每批算下来恰好也没超」）。
///
/// # 本门第一版是假的，如实记账
///
/// 原文档写「把 `min` 改成只取时间那条 → 红」。**实测不成立**：今天时间预算（142）比内存预算（152）
/// 紧，`min` 恒取时间那条 ⇒ 把内存那条腿**整个删掉**，最终取值一字不变，本门与
/// [`the_batch_caps_are_derived_from_the_two_budgets`] 双双全绿（复审 2026-09-03 实测）
/// ⇒ 内存预算当时**完全没有门**。
///
/// 修法不是换个说法，是把判据换到**它自己能观测到差别**的量上：`temp_core_batch_naive_cap` 被提成
/// 了可参数化的内核，本门喂它一个「时间预算被放宽到大于内存预算」的输入，断言此刻上限**被内存那条
/// 钉在 152** —— 删掉内存腿，这里立刻变成时间公式的值（484），当场红。
///
/// # 这不是为门造的形状：内存腿很快就会变成绑定的那一条
///
/// `t_engine = 41ms` 是两点回归的推导值（区间 30–45ms），多点实测已排进验收 runbook 的 F 组。
/// 实测一旦把它下修到 30ms，时间预算放宽到 `(6000 − 90 − 53) / 30 = 195` > 152 ⇒ **内存腿接管**。
/// 那时若它已被人当成「反正没用」删掉，单批峰值 RSS 会从 247 MB 涨到 ~308 MB 而没有任何门会喊。
///
/// **变异锁**：删掉 `temp_core_batch_naive_cap` 里的 `by_rss` 那条腿（或把 `min` 改成只取时间）
/// → 第一条断言转红。
#[test]
fn every_planned_batch_fits_the_core_memory_budget() {
    // ── ① 内存腿确实参与 `min`（本门今天**唯一**的独有覆盖）──
    let roomy_time = TEMP_CORE_BATCH_ESTIMATE_CAP_MS * 2;
    let by_time_only = (roomy_time
        - CORE_STARTUP_BASELINE_FIXED_MS
        - TEMP_CORE_BATCH_MAX_NODES as u64 * CORE_STARTUP_PER_NODE_US / 1_000)
        / CORE_STARTUP_PER_NAIVE_MS;
    assert!(
        by_time_only > 152,
        "前提校验：放宽后的时间预算得真的松过内存预算（实得 {by_time_only}），否则本条无对象可守"
    );
    assert_eq!(
        temp_core_batch_naive_cap(roomy_time, TEMP_CORE_BATCH_RSS_BUDGET_KB),
        152,
        "时间预算放宽到 {by_time_only} 之后，naive 上限必须被**内存预算**钉在 152 —— \
         得到别的值说明 `min` 里那条内存腿已经不在了（今天它对最终取值没有影响，\
         正因如此它是最容易被顺手删掉的一条）"
    );

    // ── ② 规划器产出的每一批都装得进内存预算（端到端一致性）──
    for naive_every in [0_usize, 1, 2] {
        let nodes = mixed_nodes(3_000, naive_every);
        let mut batches: Vec<&[TempNode]> = plan_temp_core_batches(&nodes);
        let topped = topped_out_batch();
        batches.extend(plan_temp_core_batches(&topped));
        for (i, batch) in batches.iter().enumerate() {
            let m = temp_core_naive_count(batch) as u64;
            let rss_kb = TEMP_CORE_BASE_RSS_KB
                + batch.len() as u64 * TEMP_CORE_PER_NODE_RSS_KB
                + m * TEMP_CORE_PER_ENGINE_RSS_KB;
            assert!(
                rss_kb <= TEMP_CORE_BATCH_RSS_BUDGET_KB,
                "naive_every={naive_every} 第 {i} 批（{} 节点 / {m} naive）估算核 RSS {} MB \
                 越过预算 {} MB",
                batch.len(),
                rss_kb / 1024,
                TEMP_CORE_BATCH_RSS_BUDGET_KB / 1024
            );
        }
    }
}

/// 🔴 **批大小是那两条预算算出来的，不是写下来的**（表驱动，逐点钉死）。
///
/// 与 R0 的 `ready_budget_is_the_documented_function_of_batch_scale` 同形：本条不证明那些系数对，
/// 只证明**代码算的就是文档写的那个数**。五个输入（前端 20s / check 5s / 安全系数 / 三个起核系数）
/// 与两个资源预算（端口段 1/32、RSS 256 MB）里任何一个被改，本条都会转红并指出是哪一格。
///
/// # 射程分工（别把它当成内存腿的门）
///
/// 本条钉的是**算式**：四个常量的取值 + `temp_core_batch_naive_cap` 在几个点上的取值。
/// 「内存那条腿有没有参与 `min`」由 [`every_planned_batch_fits_the_core_memory_budget`] 的第一条
/// 断言守 —— 本条的取样点里内存腿恒不绑定，删掉它本条照样绿。两条各守一半，不要合并。
#[test]
fn the_batch_caps_are_derived_from_the_two_budgets() {
    assert_eq!(
        TEMP_CORE_BATCH_WINDOW_OVERHEAD_MS,
        CONFIG_CHECK_TIMEOUT.as_secs() * 1_000 + 1_000 + 2_000,
        "批间空窗的固定开销 = `sing-box check` 硬超时 + 端口/写盘/spawn/轮询 1s + 余量 2s。\
         它写成字面量只是为了让跨语言那道门读得出来（判据见常量文档），成分必须仍然对得上"
    );
    assert_eq!(TEMP_CORE_BATCH_WINDOW_OVERHEAD_MS, 8_000);
    assert_eq!(
        TEMP_CORE_BATCH_READY_BUDGET_CAP_MS, 12_000,
        "单批就绪预算上限 = 前端静默兜底 20s − 固定开销 8s"
    );
    assert_eq!(
        TEMP_CORE_BATCH_ESTIMATE_CAP_MS, 6_000,
        "单批起核估算上限 = 预算上限 ÷ 安全系数"
    );
    assert_eq!(
        TEMP_CORE_BATCH_MAX_NODES, 512,
        "单批节点数上限 = 最小临时端口段 16384 ÷ 32"
    );

    // 参数化内核在四个点上的取值（生产点 + 三个把两条腿分别钉住的点）。
    for (est_cap, rss_budget, want, why) in [
        (
            TEMP_CORE_BATCH_ESTIMATE_CAP_MS,
            TEMP_CORE_BATCH_RSS_BUDGET_KB,
            142_usize,
            "生产取值：时间腿在绑",
        ),
        (
            TEMP_CORE_BATCH_ESTIMATE_CAP_MS,
            1_048_576,
            142,
            "内存放宽到 1 GB 也不动 ⇒ 确认此刻是时间腿在绑",
        ),
        (
            TEMP_CORE_BATCH_ESTIMATE_CAP_MS * 2,
            1_048_576,
            289,
            "两条都放宽 ⇒ 取值就是时间公式本身（钉住 T_fix / c_parse / t_engine 三个系数）",
        ),
    ] {
        assert_eq!(
            temp_core_batch_naive_cap(est_cap, rss_budget),
            want,
            "naive 上限失配（{why}）"
        );
    }
    assert_eq!(
        temp_core_batch_max_naive(),
        142,
        "生产上限必须就是参数化内核在生产预算上的取值"
    );

    // **反向对照**：最坏批的估算确实贴着上限，而不是离得远到「随便填个数都能过」。
    let worst =
        temp_core_startup_estimate_ms(TEMP_CORE_BATCH_MAX_NODES, temp_core_batch_max_naive());
    assert!(
        worst <= TEMP_CORE_BATCH_ESTIMATE_CAP_MS
            && worst + CORE_STARTUP_PER_NAIVE_MS > TEMP_CORE_BATCH_ESTIMATE_CAP_MS,
        "最坏批估算 {worst}ms 应当是「再多一个 naive 就越界」的那个点（上限 \
         {TEMP_CORE_BATCH_ESTIMATE_CAP_MS}ms）——离得太远说明上限根本没在绑"
    );
}

/// 🔴 **那条 60s 拒绝腿在生产上碰不到**（deliverable 8 的判据）—— 弱门，射程如实登记。
///
/// R0 的 [`TEMP_CORE_READY_TIMEOUT_CAP_MS`]（60s）在分批之后于生产路径上**不可达**。不可达这件事
/// 必须是一条门，不能是一句注释 —— 注释拦不住有人把 [`TEMP_CORE_BATCH_MAX_NODES`] 调大。它同时
/// 说明那条腿为什么可以留着：它是 [`TempCoreSession::run_batch`] 这个入口的前置条件检查，
/// 规划器回归时是唯一会喊出来的地方。
///
/// # 弱在哪里（复审 2026-09-03 的判词，照录）
///
/// 规划器那一半**被 [`every_planned_batch_fits_the_frontend_idle_window`] 支配**：凡是能让本门红的
/// 批（预算 > 60s）必然也 > 12s，那边先红且取样更宽。`m ∈ (142, 728]` 这一整段本门是**绿**的 ——
/// 那一段确实越了批窗、却确实没越 60s。⇒ 本门不承担「批不许过大」这件事。
///
/// # 它今天唯一的独有覆盖
///
/// 1. **60s 那个常量本身被调小到规划器产出之下**（例如有人为了「保守一点」把它改成 10s）——
///    那时姊妹门用的是原式、与该常量无关，只有本门红；
/// 2. **生产入口是否真的经规划器**：下半段直接驱动 `TempCoreSession::run`（生产口径，
///    不带就绪覆写），断言 900 个全 naive 的一轮不会得到 `Oversized`。规划器只测函数的门看不到这条接线。
#[tokio::test]
async fn planned_batches_never_trip_the_oversize_refusal() {
    // ── 规划器一半（弱：被姊妹门支配，留作红报里的定位线索）──
    for naive_every in [0_usize, 1, 2] {
        for n in [1_usize, 512, 5_000] {
            for batch in plan_temp_core_batches(&mixed_nodes(n, naive_every)) {
                let m = temp_core_naive_count(batch);
                assert!(
                    temp_core_ready_timeout_ms(batch.len(), m).is_ok(),
                    "规划器切出了一个会被 60s 规模门拒绝的批（{} 节点 / {m} naive）",
                    batch.len()
                );
            }
        }
    }

    // ── 端到端一半（本门的独有覆盖）：生产入口不会把越界的批交给 `run_batch` ──
    let nodes = naive_nodes(900);
    let mut h = multi_batch_harness(nodes.len(), None);
    h.deps.ready_timeout_override_ms = None; // 走生产口径：规模门真的会跑
    let (out, _events) = run_round(&h, &nodes).await;
    assert!(
        !matches!(out, TempCoreOutcome::Oversized(_)),
        "生产入口把一个越界的批交给了 `run_batch` —— 多半是 `run` 绕过了 `plan_temp_core_batches`。\
         用户会看到「本轮 naive 太多请自己分批测」，而分批的全部意义就是他不用再自己分：{out:?}"
    );
    assert!(matches!(out, TempCoreOutcome::Ran { .. }), "得到 {out:?}");
    assert_eq!(
        h.spawns.load(Ordering::SeqCst),
        plan_temp_core_batches(&nodes).len(),
        "起核次数必须等于规划出来的批数"
    );
    cleanup(&h.dir);
}

/// 多批的会话夹具：端口够 `ports` 个、就绪即真、可选让第 k 次 spawn 失败。
fn multi_batch_harness(nodes: usize, spawn_fail_at: Option<usize>) -> Harness {
    harness_opts(
        true,
        false,
        (0..nodes.min(TEMP_CORE_BATCH_MAX_NODES))
            .map(|i| 20_001 + u16::try_from(i).unwrap())
            .collect(),
        HarnessOpts {
            spawn_fail_at,
            ..Default::default()
        },
    )
}

/// 收集一轮里的事件（保序）。
async fn run_round(h: &Harness, nodes: &[TempNode]) -> (TempCoreOutcome, Vec<(String, Value)>) {
    let mut events: Vec<(String, Value)> = Vec::new();
    let out = TempCoreSession::run(
        &h.deps,
        nodes,
        &|| false,
        |_| async { Some(50_u32) },
        &mut |ev, payload| events.push((ev.to_string(), payload)),
    )
    .await;
    (out, events)
}

/// 🔴 **一轮 k 批只发一条终态事件，且载荷是轮级口径**（复用既有 `EVENT_SPEED_TEST_DONE`，不新起通道）。
///
/// # 这条守的是分批最危险的那个失效面
///
/// 终态事件原本由 `drive_temp_core_measures` 发。分批之后它一轮会跑 k 次 —— 留在原处就是 k 条终态，
/// 而前端 `reduceSpeedTestDone` 收到第一条就把 sticky 收口（`live: false`），后面 k−1 批的进度事件
/// 再也没有归宿，用户看到的是「第一批测完就说测完了」。故终态上移到轮级唯一出口。
///
/// 载荷也必须是轮级的：`total` / `serverIds` 取**全轮**可测集，`pending` = 全轮差集
/// —— 它就是「继续剩余」按钮的输入，取成批级 ⇒ 用户点了只会重测最后一批。
///
/// **变异锁**：
/// - 把 `emit_speed_test_done` 挪回 `drive_temp_core_measures` → 条数断言转红（k 条）；
/// - 删掉轮级那一条 → 条数断言转红（0 条）；
/// - `intended` 取成 `batch` 而不是 `nodes` → `total` / `serverIds` 断言转红。
#[tokio::test]
async fn a_round_emits_exactly_one_terminal_event_with_round_wide_scope() {
    let nodes = naive_nodes(300); // > 142 ⇒ 必然多批
    let h = multi_batch_harness(nodes.len(), None);
    let (out, events) = run_round(&h, &nodes).await;
    assert!(matches!(out, TempCoreOutcome::Ran { .. }), "得到 {out:?}");

    let done: Vec<&Value> = events
        .iter()
        .filter(|(ev, _)| ev == EVENT_SPEED_TEST_DONE)
        .map(|(_, p)| p)
        .collect();
    assert_eq!(
        done.len(),
        1,
        "一轮测速恰好一条终态事件（本轮切了 {} 批）",
        plan_temp_core_batches(&nodes).len()
    );
    assert_eq!(done[0]["outcome"], json!("completed"));
    assert_eq!(
        done[0]["total"],
        json!(nodes.len()),
        "终态的 total 必须是全轮可测集，不是最后一批"
    );
    assert_eq!(
        done[0]["tested"],
        json!(nodes.len()),
        "全部批都测完 ⇒ tested 必须等于全轮总数"
    );
    assert_eq!(
        done[0]["serverIds"].as_array().map(Vec::len),
        Some(nodes.len()),
        "「重新测速」的输入必须是全轮原始范围"
    );
    assert_eq!(
        done[0]["pending"],
        json!(Vec::<String>::new()),
        "一个都没漏 ⇒ pending 空"
    );
    cleanup(&h.dir);
}

/// 🔴 **进度事件的口径是轮级的，不是批级的**（前端在 `tested >= total` 那一帧就收口）。
///
/// 批级口径下，批 1 测完那一刻前端会收到 `142/142` ⇒ 当场弹一条「测速完成」并把 sticky 收掉，
/// 随后批 2 的事件又把它拉起来 —— 一轮里连弹 k 条「完成」。故 `total` 恒为全轮总数、`tested` 跨批
/// 累加且严格单调。
///
/// **变异锁**：把 `RoundProgress` 换成每批新建一份（或 `total` 取 `nodes.len().min(ports.len())`）
/// → `total` 断言与单调断言同时转红。
#[tokio::test]
async fn progress_is_reported_on_the_round_scale_across_batches() {
    let nodes = naive_nodes(300);
    let h = multi_batch_harness(nodes.len(), None);
    let (_out, events) = run_round(&h, &nodes).await;

    let mut last_tested = 0usize;
    let mut saw_cross_batch = false;
    for (ev, payload) in events
        .iter()
        .filter(|(ev, _)| ev == EVENT_SPEED_TEST_PROGRESS)
    {
        assert_eq!(
            payload["total"],
            json!(nodes.len()),
            "进度事件的 total 必须是全轮总数（{ev} 载荷 {payload}）"
        );
        let tested = payload["tested"].as_u64().unwrap() as usize;
        assert!(
            tested >= last_tested,
            "跨批的 tested 必须单调不减：{last_tested} → {tested}"
        );
        // 心跳与逐节点事件都进这个流；只要出现过「已超过**第一批**的规模」就说明账是跨批累加的。
        //
        // 阈值取本轮**第一批的实际大小**，不取两条上限的 min：后者恰好等于本夹具（全 naive）第一批
        // 的 142，纯属巧合 —— 换成零 naive 的夹具（第一批 512）阈值仍是 142，于是「第一批内部」就
        // 满足了断言，本条当场变成假绿（复审 2026-09-03 指出）。判据必须跟着夹具走。
        if tested > plan_temp_core_batches(&nodes)[0].len() {
            saw_cross_batch = true;
        }
        last_tested = tested;
    }
    assert_eq!(last_tested, nodes.len(), "最后一条进度必须走到全轮总数");
    assert!(
        saw_cross_batch,
        "从未见到超过单批上限的 tested ⇒ 进度是按批各报各的（前端会在每批测完时收口）"
    );
    cleanup(&h.dir);
}

/// 🔴 **批间空窗被两条心跳切开**（D1 那套不等式的可观测形态）。
///
/// 只留一条都无解：
/// · 只留就绪心跳 ⇒ 需要 `收核5s + check5s + 就绪预算 < 20s` ⇒ 预算 < 9s，而预算的**下限**就是 10s；
/// · 只留批首心跳 ⇒ 需要 `check5s + 就绪预算 + 单节点最坏10s < 20s` ⇒ 预算 < 4s。
///
/// 故判据是「两批之间**恰好**多出两条不带新数据的 progress」：批首那条（起核之前）与就绪那条
/// （就绪门解析之后、开测之前）。判的是**位置**而不是条数总和 —— 条数总和用「多发几条心跳」就能
/// 骗过去，而位置骗不过去：心跳必须夹在「上一批最后一个结果」与「本批第一个结果」之间。
///
/// **变异锁**：删掉任一条心跳 → 该批边界的心跳数从 2 变 1 → 转红。
#[tokio::test]
async fn every_batch_boundary_is_bridged_by_two_heartbeats() {
    let nodes = naive_nodes(300);
    let batches = plan_temp_core_batches(&nodes).len();
    assert!(batches >= 2, "前提：这一轮确实切了多批（实得 {batches}）");
    let h = multi_batch_harness(nodes.len(), None);
    let (_out, events) = run_round(&h, &nodes).await;

    // 把事件流折成「结果 / 进度」的序列：连续两条 result 之间夹了几条 progress。
    // 逐节点那条 progress 与 result 成对（`record_measured` 先 result 后 progress）⇒ 正常间隔恒为 1，
    // 批边界处多出来的就是心跳。
    let mut gaps: Vec<usize> = Vec::new();
    let mut progress_since_result = 0usize;
    let mut seen_first_result = false;
    for (ev, _) in &events {
        if ev == EVENT_SPEED_TEST_RESULT {
            if seen_first_result {
                gaps.push(progress_since_result);
            }
            seen_first_result = true;
            progress_since_result = 0;
        } else if ev == EVENT_SPEED_TEST_PROGRESS {
            progress_since_result += 1;
        }
    }
    let bridged = gaps.iter().filter(|g| **g == 3).count();
    assert_eq!(
        bridged,
        batches - 1,
        "每个批边界都必须恰好多出**两条**心跳（逐节点那条 progress 之外）；\
         实得各间隔 {gaps:?}（3 = 1 条逐节点 + 2 条心跳）"
    );
    assert!(
        gaps.iter().all(|g| *g == 1 || *g == 3),
        "除批边界外不该有额外的进度事件：{gaps:?}"
    );
    cleanup(&h.dir);
}

/// 🔴 **中间某一批就绪失败时，空窗仍然被切开** —— 就绪心跳里 `|| progress.tested() > 0` 那半个判据
/// 的**唯一**触发路径。
///
/// # 这条补的是一个「承重但无门」的洞（复审 2026-09-03 实测）
///
/// 就绪心跳的判据是 `matches!(ready, Ready) || progress.tested() > 0`。前半截由
/// [`every_batch_boundary_is_bridged_by_two_heartbeats`] 守（正常批），**后半截此前一条门都没有**：
/// 已有的多批用例要么造「spawn 失败」（根本走不进 `drive_after_spawn`，就绪心跳那段代码一行不执行），
/// 要么造「全批就绪失败」（`tested == 0`，判据两半都为假 ⇒ 本来就不该发）。
///
/// 删掉那半个判据的真实后果：批 2 就绪失败时不发心跳 ⇒ 空窗从
/// 「批 2 批首心跳」一路拉到「批 3 就绪心跳」＝ `check 5s + spawn/端口 1s + 就绪预算 12s + 收核 5s`
/// ≈ **23s > 前端 20s 兜底** ⇒ 用户在测速仍在正常推进时看到假的「测速中断」。
///
/// # 判据：批 1 末 RESULT → 批 3 首 RESULT 之间**恰好 5 条** progress
///
/// | # | 是什么 | 它封住哪一段空窗 |
/// |---|---|---|
/// | 1 | 批 1 最后一个节点的逐节点 progress | —（与 RESULT 成对） |
/// | 2 | 批 2 **批首**心跳 | 收批 1 的核（≤5s） |
/// | 3 | 批 2 **就绪失败**心跳 ← 本门的守护对象 | 批 2 的 check + spawn + 就绪门（≤12s） |
/// | 4 | 批 3 批首心跳 | 收批 2 的核（≤5s） |
/// | 5 | 批 3 就绪心跳 | 批 3 的 check + spawn + 就绪门（≤12s） |
///
/// 少了第 3 条，②③④ 三段会连成一段 ⇒ 计数 4 ≠ 5，当场红。
///
/// **变异锁**：删掉 `|| progress.tested() > 0` → 本门转红（且只有本门）。
#[tokio::test]
async fn a_failed_middle_batch_still_bridges_the_silent_window() {
    let nodes = naive_nodes(300);
    let batches = plan_temp_core_batches(&nodes);
    assert_eq!(
        batches.len(),
        3,
        "前提：本轮切成 3 批（实得 {}）",
        batches.len()
    );
    let doomed: Vec<String> = batches[1].iter().map(|n| n.id.clone()).collect();

    // 第 2 批：spawn 成功、走进就绪门、耗满预算后失败（**不是** spawn 失败）。
    let h = harness_opts(
        true,
        false,
        (0..TEMP_CORE_BATCH_MAX_NODES)
            .map(|i| 20_001 + u16::try_from(i).unwrap())
            .collect(),
        HarnessOpts {
            ready_fail_at: Some(2),
            ..Default::default()
        },
    );
    let (out, events) = run_round(&h, &nodes).await;

    let TempCoreOutcome::Ran { results, outcome } = out else {
        panic!("一批就绪失败不该作废整轮，得到 {out:?}");
    };
    assert_eq!(outcome, "interrupted");
    assert_eq!(
        h.spawns.load(Ordering::SeqCst),
        3,
        "前提：三批都起过核（第 2 批是**就绪**失败，不是 spawn 失败）"
    );
    assert_eq!(
        results.len(),
        nodes.len() - doomed.len(),
        "前提：就绪失败的那一批缺席，其余两批照常出值"
    );

    // 批 1 末 RESULT 与 批 3 首 RESULT 之间的 progress 条数。
    let idx: Vec<usize> = events
        .iter()
        .enumerate()
        .filter(|(_, (ev, _))| ev == EVENT_SPEED_TEST_RESULT)
        .map(|(i, _)| i)
        .collect();
    let last_of_first = idx[results.len() - batches[2].len() - 1];
    let first_of_third = idx[results.len() - batches[2].len()];
    let bridge = events[last_of_first..first_of_third]
        .iter()
        .filter(|(ev, _)| ev == EVENT_SPEED_TEST_PROGRESS)
        .count();
    assert_eq!(
        bridge, 5,
        "跨过「就绪失败的那一批」的空窗只被切成 {bridge} 段（应为 5 条 progress：\
         批1逐节点 + 批2批首 + 批2就绪失败 + 批3批首 + 批3就绪）—— 少的那条多半是\
         就绪心跳的 `|| progress.tested() > 0`，删了它这里会出现一段 ≈23s 的静默，\
         而前端 20s 就判中断"
    );
    cleanup(&h.dir);
}

/// 🔴 **第一批的就绪门解析之前，一条 progress 都不许出去**（R0 那条不变量在分批之后的版本）。
///
/// R0 的 `no_progress_event_escapes_before_the_readiness_gate_resolves` 驱动的是单批。分批之后多出
/// 一条路：批 1 起不来（就绪超时）⇒ 轮级循环继续起批 2 —— 如果心跳在这里无条件发，前端的 20s 兜底
/// 就会在**一个还没有任何测量结果**的时刻布防，而后面每一批都还要再走一遍可以合法长达十几秒的
/// 起核窗口。故心跳的判据是 `tested > 0`（= 前端此刻已布防），而不是「到批边界就发」。
///
/// **变异锁**：把批首心跳或就绪失败腿那条心跳的 `progress.tested() > 0` 去掉 → 本条转红。
#[tokio::test]
async fn no_progress_escapes_while_no_batch_has_measured_anything() {
    let nodes = naive_nodes(300);
    // 全程不就绪 ⇒ 每一批都走满就绪门后失败，一个节点都测不出来。
    let h = harness_opts(
        false,
        false,
        (0..TEMP_CORE_BATCH_MAX_NODES)
            .map(|i| 20_001 + u16::try_from(i).unwrap())
            .collect(),
        HarnessOpts::default(),
    );
    let (out, events) = run_round(&h, &nodes).await;
    assert!(
        matches!(out, TempCoreOutcome::Failed(_)),
        "前提：整轮确实卡在就绪门上，得到 {out:?}"
    );
    assert!(
        !events.iter().any(|(ev, _)| ev == EVENT_SPEED_TEST_PROGRESS),
        "一个节点都没测出来的一轮不许发进度事件（含心跳）——发了就等于让前端的 20s 兜底\
         在起核窗口前布防：{events:?}"
    );
    assert!(
        !events.iter().any(|(ev, _)| ev == EVENT_SPEED_TEST_DONE),
        "整轮零测量走的是失败信封，不发终态（与分批之前逐字相同）：{events:?}"
    );
    cleanup(&h.dir);
}

/// 🔴 **批死不连坐**：某一批起不了核，那批的节点缺席，**后续批照跑**。
///
/// 分批把「一次起核」变成 k 次，每一次都是一个新的失败机会（撞端口 / check 判无效 / spawn 失败）。
/// 若一批失败就作废整轮，分批反而把可靠性除以了 k —— 那就不是修复，是把一个 O(N) 的资源问题换成
/// 一个 O(k) 的可靠性问题。
///
/// 缺席**不是** `-1`：那批的节点根本没测过，写 `-1` 就是伪造 N 次「这些节点不通」的测量。它们进
/// 终态的 `pending`，也就是「继续剩余」的输入。
///
/// **变异锁**：把 `BatchOutcome::Failed` 那一臂改成 `break`（或直接返回 `Failed`）→ 结果数与
/// `pending` 断言同时转红。
#[tokio::test]
async fn a_batch_that_cannot_start_does_not_sink_the_round() {
    let nodes = naive_nodes(300);
    let batches = plan_temp_core_batches(&nodes);
    assert_eq!(
        batches.len(),
        3,
        "前提：本轮切成 3 批（实得 {}）",
        batches.len()
    );
    let doomed: Vec<String> = batches[1].iter().map(|n| n.id.clone()).collect();

    let h = multi_batch_harness(nodes.len(), Some(2)); // 第 2 次 spawn 失败
    let (out, events) = run_round(&h, &nodes).await;

    let TempCoreOutcome::Ran { results, outcome } = out else {
        panic!("一批起不了核不该作废整轮，得到 {out:?}");
    };
    assert_eq!(
        outcome, "interrupted",
        "有节点缺席的一轮必须报 interrupted（前端据此给出「继续剩余」）"
    );
    assert_eq!(
        results.len(),
        nodes.len() - doomed.len(),
        "失败的那一批之外，其余批必须照常出值"
    );
    for id in &doomed {
        assert!(
            !results.contains_key(id.as_str()),
            "起不了核的那一批必须**缺席**，绝不写假 -1：{id}"
        );
    }
    let done: Vec<&Value> = events
        .iter()
        .filter(|(ev, _)| ev == EVENT_SPEED_TEST_DONE)
        .map(|(_, p)| p)
        .collect();
    assert_eq!(done.len(), 1);
    assert_eq!(
        done[0]["pending"],
        json!(doomed),
        "缺席的那一批必须进 pending —— 它就是「继续剩余」的输入"
    );
    // 三批都起过核（第 2 次失败之后没有停下来）。
    assert_eq!(
        h.spawns.load(Ordering::SeqCst),
        3,
        "失败的那一批之后必须继续起下一批的核"
    );
    cleanup(&h.dir);
}

/// 🔴 **批间让位：主核一来就不再起下一个核**（双会话事故的源头在这里被掐掉）。
///
/// 分批把「一轮 = 一个核」变成「一轮 = k 个核」，让位的射程必须跟着覆盖到**每一个批边界**：
/// 只在轮首查一次，用户在批 2 之前点「连接」，批 3、批 4… 会照旧起核，与主核并存跑同一批
/// WG/WARP peer。
///
/// # 构造：让位信号**恰好落在批边界上**
///
/// 让位在**测量途中**触发是另一条路（`drive_temp_core_measures` 的让位三检查点接住，已有既有门），
/// 走不到本条要守的那一臂。故本条按「本轮已推出的逐节点结果数」触发：第一批最后一个节点落账之后
/// 才翻真 ⇒ 批 1 完整跑完（`completed`），信号落在**批 2 起核之前**。
///
/// # 两处让位检查是**互为冗余**的，如实记账
///
/// 轮级那条（`Ran` 臂里 `reason == Superseded` 即 `break`）与 `run_batch` 起核前那条判据逐字相同，
/// 删掉任何**一条**都还有另一条兜着（表现只差一条心跳）。本条守的是「两条都没了」这个真实后果：
/// 剩余批照起核 ⇒ `spawns` 从 1 变 3。单独删一条的可观测差别由「让位之后至多一条心跳」那条断言接住。
///
/// **变异锁**：删掉 `BatchOutcome::Superseded` 臂里的 `note_interrupt` → 终态里没有 `reason` →
/// 前端把「主核接管了」说成一句笼统的「测速中断」→ 转红。
#[tokio::test]
async fn superseded_between_batches_stops_the_round_before_starting_another_core() {
    let nodes = naive_nodes(300);
    let batches = plan_temp_core_batches(&nodes);
    assert!(
        batches.len() >= 3,
        "前提：本轮至少 3 批（实得 {}）",
        batches.len()
    );
    let first_batch = batches[0].len();
    let pending_ids: Vec<String> = nodes[first_batch..].iter().map(|n| n.id.clone()).collect();
    let h = multi_batch_harness(nodes.len(), None);

    let tripped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let trip_read = Arc::clone(&tripped);
    let results_seen = AtomicUsize::new(0);
    let mut events: Vec<(String, Value)> = Vec::new();
    let out = TempCoreSession::run(
        &h.deps,
        &nodes,
        &move || trip_read.load(Ordering::SeqCst),
        |_| async { Some(50_u32) },
        &mut |ev, payload| {
            if ev == EVENT_SPEED_TEST_RESULT
                && results_seen.fetch_add(1, Ordering::SeqCst) + 1 >= first_batch
            {
                // 第一批最后一个结果已经落账 ⇒ 主核来了。信号落在批 2 起核之前。
                tripped.store(true, Ordering::SeqCst);
            }
            events.push((ev.to_string(), payload));
        },
    )
    .await;

    let TempCoreOutcome::Ran { results, outcome } = out else {
        panic!("已经测出值的一轮不该整轮失败，得到 {out:?}");
    };
    assert_eq!(outcome, "interrupted");
    assert_eq!(
        h.spawns.load(Ordering::SeqCst),
        1,
        "让位之后一个新核都不许再起（每多起一个就是一段与主核并存的双会话窗口）"
    );
    assert_eq!(
        results.len(),
        first_batch,
        "让位之前测出的值必须原样保留（第一批全部）"
    );
    let done: Vec<&Value> = events
        .iter()
        .filter(|(ev, _)| ev == EVENT_SPEED_TEST_DONE)
        .map(|(_, p)| p)
        .collect();
    assert_eq!(done.len(), 1, "让位也必须**恰好**发一条终态");
    assert_eq!(
        done[0]["reason"],
        json!("superseded"),
        "成因必须一路带到终态（前端据此说「主核接管了」而不是「去看日志」）"
    );
    assert_eq!(
        done[0]["pending"],
        json!(pending_ids),
        "让位之后没测的节点必须缺席并进 pending —— 绝不写假 -1"
    );
    // 最后一个结果之后的进度事件**恰好两条**：与它成对的那条逐节点 progress + 批 2 的批首心跳。
    // `break` 换成 `continue` ⇒ 剩下每一批都再发一条心跳，而那些批一个核都起不了 ——
    // 心跳在说「还在测」，实际上这一轮已经停了。
    let tail_progress = events
        .iter()
        .rev()
        .take_while(|(ev, _)| ev != EVENT_SPEED_TEST_RESULT)
        .filter(|(ev, _)| ev == EVENT_SPEED_TEST_PROGRESS)
        .count();
    assert_eq!(
        tail_progress, 2,
        "让位之后的进度事件数不对（应为 1 条逐节点 + 1 条批首心跳）⇒ 轮级循环没有就地停下"
    );
    cleanup(&h.dir);
}

/// 🔴 **让位覆盖一切：此前有批起核失败，也不许把让位报成 spawn 失败**。
///
/// # 这条补的是一个无门的交叉路（复审 2026-09-03 行为审）
///
/// 已有两条门各走一条单路：[`a_batch_that_cannot_start_does_not_sink_the_round`] 走「批失败」，
/// [`superseded_between_batches_stops_the_round_before_starting_another_core`] 走「让位」。
/// **两条路交叉的那格没有门**，而实现原本在那里写着
/// `superseded_with_no_results = !measured_any_batch && failed_batches == 0`：
///
/// 批 1 spawn 失败（杀软锁住二进制 / 撞端口）⇒ 用户见没反应，点了「连接」⇒ 批 2 让位 ⇒
/// `failed_batches != 0` 让结局落到「整轮零测量」那支，返回
/// `Failed("测速临时核 spawn 失败: …")`。**用户被指去查二进制和端口，而真正的终止原因是他自己点了
/// 连接** —— 正确指引是命令层那句「测速已让位给正在启动的代理内核」。这正是本模块反复要消灭的
/// 那类误诊。
///
/// 判据与 [`RoundProgress::note_interrupt`] 的「Superseded 覆盖一切」同源：两处必须一致，
/// 否则「成因」与「结局」会各说各话。
///
/// **变异锁**：把 `&& failed_batches == 0` 加回去 → 结局变 `Failed(spawn …)` → 转红。
#[tokio::test]
async fn superseding_a_round_that_already_lost_a_batch_still_reports_superseded() {
    let nodes = naive_nodes(300);
    assert!(
        plan_temp_core_batches(&nodes).len() >= 2,
        "前提：本轮至少 2 批"
    );
    // 批 1 spawn 失败；此后 `superseded` 恒真 ⇒ 批 2 在起核前让位。
    let h = multi_batch_harness(nodes.len(), Some(1));
    let failed_once = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let trip = Arc::clone(&failed_once);
    let spawns = Arc::clone(&h.spawns);
    let out = TempCoreSession::run(
        &h.deps,
        &nodes,
        &move || {
            // 批 1 那次 spawn 已经发生（且失败）之后才让位 —— 否则批 1 根本不会去 spawn。
            if spawns.load(Ordering::SeqCst) >= 1 {
                trip.store(true, Ordering::SeqCst);
            }
            failed_once.load(Ordering::SeqCst)
        },
        |_| async { Some(50_u32) },
        &mut |_, _| {},
    )
    .await;

    assert!(
        matches!(out, TempCoreOutcome::Superseded),
        "整轮零测量 + 让位 ⇒ 结局必须是 `Superseded`（命令层据此说「测速已让位给正在启动的代理内核」）。\
         得到 {out:?} —— 报成起核失败会把用户支去查二进制/端口，而真因是他点了「连接」"
    );
    assert_eq!(
        h.spawns.load(Ordering::SeqCst),
        1,
        "让位之后不许再起核（批 2 在 `run_batch` 起核前就该停）"
    );
    cleanup(&h.dir);
}

/// 🔴 **每一批各自登记/注销自己的在飞 pid** —— 分批之后 pid 会换 k 次。
///
/// 孤儿清扫的排除表（`ProxyRuntime::sweep_exclusions`）读的就是这张表。少登记一批 ⇒ 那一批的核在
/// 清扫窗口里没有豁免（被自家的 stale sweep 杀掉，表现是「测到一半整批变 -1」）；漏注销一批 ⇒
/// 退出清理对一个已死 pid 发信号，pid 复用即误杀无关进程。
///
/// **变异锁**：把 `TempCorePidGuard::register` 从 `drive_after_spawn`（批级）挪到轮级 → 第二批起
/// 表里就是上一批的 pid → 「测量期间表里恰好是当前这一批的 pid」断言转红。
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn each_batch_registers_and_releases_its_own_inflight_pid() {
    let _lock = registry_guard();
    let self_pid = std::process::id();
    let nodes = naive_nodes(300);
    let h = harness_opts(
        true,
        false,
        (0..TEMP_CORE_BATCH_MAX_NODES)
            .map(|i| 20_001 + u16::try_from(i).unwrap())
            .collect(),
        HarnessOpts {
            child_pid: Some(self_pid),
            ..Default::default()
        },
    );
    // 每次测量都记下此刻表里的**全部** pid。判据两条：
    //  ① 任一时刻表里**恰好一个** —— 多了 = 上一批的 pid 没注销，少了 = 这一批没登记；
    //  ② 整轮见过的不同 pid 数 == 批数 —— 登记若被挪到轮级，整轮就只会有一个 pid。
    // 假 spawner 每次给一个不同的 pid（见 `FakeSpawner::spawn`），这两条才有分辨力。
    let snapshots: Arc<std::sync::Mutex<Vec<Vec<u32>>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let writer = Arc::clone(&snapshots);
    let out = TempCoreSession::run(
        &h.deps,
        &nodes,
        &|| false,
        move |_| {
            let writer = Arc::clone(&writer);
            async move {
                writer.lock().unwrap().push(inflight_temp_core_pids());
                Some(50_u32)
            }
        },
        &mut |_, _| {},
    )
    .await;
    assert!(matches!(out, TempCoreOutcome::Ran { .. }), "得到 {out:?}");
    let seen = snapshots.lock().unwrap().clone();
    assert_eq!(seen.len(), nodes.len(), "前提：每个节点都测了");
    assert!(
        seen.iter().all(|pids| pids.len() == 1),
        "测量在飞期间，在飞 pid 表里必须恰好是**当前这一批**的那一个核（实得 {:?}）",
        seen.iter().find(|p| p.len() != 1)
    );
    let distinct: BTreeSet<u32> = seen.iter().flatten().copied().collect();
    assert_eq!(
        distinct.len(),
        plan_temp_core_batches(&nodes).len(),
        "整轮见过的在飞 pid 数必须等于批数 —— 少了说明登记被挪到了轮级，\
         那样第二批起，孤儿清扫的排除表里就是上一批那个已经死掉的 pid"
    );
    assert!(
        inflight_temp_core_pids().is_empty(),
        "全部批收尾之后表必须排空（留着 = 退出时对已死 pid 发信号）"
    );
    cleanup(&h.dir);
}
