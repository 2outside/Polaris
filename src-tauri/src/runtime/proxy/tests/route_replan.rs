use super::*;
use crate::runtime::proxy::connection_flush::FlushOutcome;

/// 被测对象是 `managed_tun_interface_for_network_watcher` / `managed_tun_interface_for_session` /
/// `ExitInterfaceId` —— 三者都留在 src-tauri，故这半段不随 E2② 搬走。
///
/// 它原本是 `dns_monitor_lines_follow_platform_event_shapes` 的后半段；前半段（平台 monitor 行的
/// 解析）已随被测符号迁进 `polaris-platform-events`。**测试跟着被测符号走，不跟着断言里出现的类型走。**
#[test]
fn managed_tun_interface_resolution_follows_platform_and_mode() {
    let mut config = UserConfig {
        proxy_mode_type: polaris_config_engine::user_config::proxy_mode::ProxyModeType::Tun,
        tun_config: Some(Default::default()),
        ..Default::default()
    };
    assert_eq!(
        managed_tun_interface_for_network_watcher(&config, Platform::Win).as_deref(),
        Some("polaris-tun0")
    );
    assert_eq!(
        managed_tun_interface_for_network_watcher(&config, Platform::Linux).as_deref(),
        Some(polaris_helper_proto::linux_dns::TUN_INTERFACE_NAME)
    );
    assert_eq!(
        managed_tun_interface_for_network_watcher(&config, Platform::Mac),
        None
    );
    assert_eq!(
        managed_tun_interface_for_session(
            &config,
            Platform::Mac,
            ExitInterfaceId::from_alias("utun8")
        ),
        ExitInterfaceId::from_alias("utun8"),
        "macOS 动态 utun 必须由 post-flight 捕获值补齐"
    );
    let win_session = managed_tun_interface_for_session(
        &config,
        Platform::Win,
        Some(ExitInterfaceId {
            alias: None,
            ifindex: Some(42),
        }),
    )
    .expect("Windows TUN 会话身份必须可得");
    assert_eq!(
        win_session.alias(),
        Some("polaris-tun0"),
        "Windows 路由闸返回 ifindex，接口快照/订阅必须继续用稳定别名"
    );
    assert_eq!(
        win_session.ifindex,
        Some(42),
        "同一张网卡的 ifindex 必须并进同一份身份，否则退场等待没有可比表示"
    );
    assert_eq!(
        managed_tun_interface_for_session(&config, Platform::Linux, None)
            .as_ref()
            .and_then(ExitInterfaceId::alias),
        Some(polaris_helper_proto::linux_dns::TUN_INTERFACE_NAME),
        "Linux 会话必须沿用 helper 与 sing-box 共同约定的稳定接口名"
    );
    config.proxy_mode_type =
        polaris_config_engine::user_config::proxy_mode::ProxyModeType::SystemProxy;
    assert_eq!(
        managed_tun_interface_for_network_watcher(&config, Platform::Win),
        None
    );
    assert_eq!(
        managed_tun_interface_for_session(
            &config,
            Platform::Mac,
            ExitInterfaceId::from_alias("utun8")
        ),
        None,
        "非 TUN 模式不得消费捕获接口"
    );
}

/// F5 回归：Windows 口径下「配置别名 + 路由闸 ifindex」与探测出的 ifindex 是同一张网卡。
/// 旧实现拿别名字符串 `!=` `"ifindex:42"`，必然判成两张网卡。
#[test]
fn exit_interface_identity_compares_windows_alias_and_ifindex_as_one_interface() {
    let managed = ExitInterfaceId::from_alias("polaris-tun0")
        .expect("非空别名是合法身份")
        .merged_with(Some(ExitInterfaceId {
            alias: None,
            ifindex: Some(42),
        }));
    let same = ExitInterfaceId {
        alias: None,
        ifindex: Some(42),
    };
    let other = ExitInterfaceId {
        alias: None,
        ifindex: Some(43),
    };
    assert_eq!(managed.same_interface(&same), Some(true));
    assert_eq!(managed.same_interface(&other), Some(false));
    assert_eq!(
        managed.alias(),
        Some("polaris-tun0"),
        "合并只补缺失表示，配置别名不得被覆盖"
    );

    // 只有别名的两侧按别名比。
    let mac = ExitInterfaceId::from_alias("utun8").unwrap();
    assert_eq!(
        mac.same_interface(&ExitInterfaceId::from_alias(" utun8 ").unwrap()),
        Some(true)
    );
    assert_eq!(
        mac.same_interface(&ExitInterfaceId::from_alias("utun9").unwrap()),
        Some(false)
    );

    // 没有共同表示 = 不可比，**不是**「不同」。
    assert_eq!(mac.same_interface(&same), None);
    assert_eq!(ExitInterfaceId::from_alias("   "), None);
}

/// F5 回归：退场等待的三态结局必须各自可达且可辨。
#[tokio::test]
async fn retiring_tun_route_wait_reports_each_outcome() {
    let managed = ExitInterfaceId::from_alias("polaris-tun0")
        .unwrap()
        .merged_with(Some(ExitInterfaceId {
            alias: None,
            ifindex: Some(42),
        }));
    let old_tun = ExitInterfaceId {
        alias: None,
        ifindex: Some(42),
    };
    let physical = ExitInterfaceId {
        alias: None,
        ifindex: Some(7),
    };

    // skipped：没有可等的对象。
    assert_eq!(
        wait_for_retiring_tun_route_outcome(None, 4, Duration::ZERO, || async {
            unreachable!("没有退场对象时不得发起任何探测")
        })
        .await,
        RetiringTunRouteOutcome::Skipped("no_managed_tun_interface")
    );

    // skipped：身份不可比（macOS 别名身份撞 Windows ifindex 探测）——旧实现在这里静默返回。
    let alias_only = ExitInterfaceId::from_alias("polaris-tun0").unwrap();
    assert_eq!(
        wait_for_retiring_tun_route_outcome(Some(&alias_only), 4, Duration::ZERO, || {
            let observed = old_tun.clone();
            async move { Some(observed) }
        })
        .await,
        RetiringTunRouteOutcome::Skipped("incomparable_interface_identity")
    );

    // matched：第 3 次探测出口终于切走。
    let observations = std::sync::Mutex::new(vec![
        Some(old_tun.clone()),
        Some(old_tun.clone()),
        Some(physical.clone()),
    ]);
    assert_eq!(
        wait_for_retiring_tun_route_outcome(Some(&managed), 8, Duration::ZERO, || {
            let next = observations.lock().unwrap().remove(0);
            async move { next }
        })
        .await,
        RetiringTunRouteOutcome::Retired { polls: 3 }
    );

    // timeout：界内每一次都仍是旧 TUN。
    assert_eq!(
        wait_for_retiring_tun_route_outcome(Some(&managed), 4, Duration::ZERO, || {
            let observed = old_tun.clone();
            async move { Some(observed) }
        })
        .await,
        RetiringTunRouteOutcome::TimedOut { polls: 4 }
    );

    // 探测不可读沿用旧行为：不空等满界。
    assert_eq!(
        wait_for_retiring_tun_route_outcome(Some(&managed), 4, Duration::ZERO, || async { None })
            .await,
        RetiringTunRouteOutcome::Retired { polls: 1 }
    );
}

#[test]
fn runtime_binding_replan_matrix_filters_noise_and_keeps_failover_safe() {
    let plan = RuntimeBindingPlan {
        bindings: BTreeMap::from([("node-a".into(), "en0".into())]),
        native_roots: BTreeSet::new(),
        covered_roots: BTreeSet::from(["node-a".into()]),
        probe_ips: BTreeMap::from([("node-a".into(), "198.51.100.77".parse().unwrap())]),
        candidate_count: 1,
        unresolved_roots: BTreeMap::new(),
    };
    let baseline = BTreeMap::from([
        ("en0".into(), (true, vec!["192.0.2.2".into()])),
        ("en9".into(), (true, vec!["198.51.100.2".into()])),
    ]);
    let unrelated_change = BTreeMap::from([
        ("en0".into(), (true, vec!["192.0.2.2".into()])),
        ("en9".into(), (false, vec!["198.51.100.2".into()])),
    ]);
    assert!(inferred_binding_replan_needed(
        &NetworkChangeImpact {
            route: true,
            route_unknown: true,
            ..Default::default()
        },
        &plan,
        Some(&baseline),
        Some(&baseline),
        None,
    ));
    assert!(inferred_binding_replan_needed(
        &NetworkChangeImpact {
            route: true,
            route_prefixes: BTreeSet::from([RoutePrefix::parse("198.51.100.0/24").unwrap(),]),
            ..Default::default()
        },
        &plan,
        Some(&baseline),
        Some(&baseline),
        None,
    ));
    assert!(!inferred_binding_replan_needed(
        &NetworkChangeImpact {
            route: true,
            route_prefixes: BTreeSet::from([RoutePrefix::parse("192.0.2.0/24").unwrap(),]),
            ..Default::default()
        },
        &plan,
        Some(&baseline),
        Some(&baseline),
        None,
    ));
    assert!(!inferred_binding_replan_needed(
        &NetworkChangeImpact {
            route: true,
            ..Default::default()
        },
        &plan,
        Some(&baseline),
        Some(&baseline),
        None,
    ));
    assert!(!inferred_binding_replan_needed(
        &NetworkChangeImpact {
            route: true,
            route_prefixes: BTreeSet::from([RoutePrefix::parse("0.0.0.0/0").unwrap()]),
            ..Default::default()
        },
        &plan,
        Some(&baseline),
        Some(&baseline),
        None,
    ));
    assert!(!inferred_binding_replan_needed(
        &NetworkChangeImpact {
            interface: true,
            ..Default::default()
        },
        &plan,
        Some(&baseline),
        Some(&unrelated_change),
        None,
    ));
    let bound_down = BTreeMap::from([("en0".into(), (false, Vec::new()))]);
    assert!(inferred_binding_replan_needed(
        &NetworkChangeImpact {
            interface: true,
            ..Default::default()
        },
        &plan,
        Some(&baseline),
        Some(&bound_down),
        None,
    ));

    let unresolved = RuntimeBindingPlan {
        candidate_count: 1,
        unresolved_roots: BTreeMap::from([("node-a".into(), "node-a.example.com".into())]),
        ..Default::default()
    };
    assert!(inferred_binding_replan_needed(
        &NetworkChangeImpact {
            interface: true,
            ..Default::default()
        },
        &unresolved,
        Some(&baseline),
        Some(&unrelated_change),
        None,
    ));

    let tun_added = BTreeMap::from([
        ("en0".into(), (true, vec!["192.0.2.2".into()])),
        ("en9".into(), (true, vec!["198.51.100.2".into()])),
        ("utun8".into(), (true, vec!["172.19.0.1".into()])),
    ]);
    assert!(!inferred_binding_replan_needed(
        &NetworkChangeImpact {
            interface: true,
            ..Default::default()
        },
        &unresolved,
        Some(&baseline),
        Some(&tun_added),
        Some("utun8"),
    ));
    assert!(inferred_binding_replan_needed(
        &NetworkChangeImpact {
            interface: true,
            ..Default::default()
        },
        &unresolved,
        Some(&baseline),
        Some(&tun_added),
        None,
    ));

    let tun_added_and_physical_changed = BTreeMap::from([
        ("en0".into(), (false, vec!["192.0.2.2".into()])),
        ("en9".into(), (true, vec!["198.51.100.2".into()])),
        ("utun8".into(), (true, vec!["172.19.0.1".into()])),
    ]);
    assert!(
        inferred_binding_replan_needed(
            &NetworkChangeImpact {
                interface: true,
                ..Default::default()
            },
            &unresolved,
            Some(&baseline),
            Some(&tun_added_and_physical_changed),
            Some("utun8"),
        ),
        "忽略受管 TUN 只能消除自身噪音，不得吞掉同窗发生的物理接口变化"
    );

    let native = RuntimeBindingPlan {
        native_roots: BTreeSet::from(["node-a".into()]),
        covered_roots: BTreeSet::from(["node-a".into()]),
        probe_ips: BTreeMap::from([("node-a".into(), "198.51.100.77".parse().unwrap())]),
        candidate_count: 1,
        ..Default::default()
    };
    // F13：native 计划下的未知路由事件也要重算 —— 它可能就是下面那条 `198.51.100.77/32`
    // （只是事件源没能把前缀交出来）。此处此前断言 false，与下一格自相矛盾。
    assert!(inferred_binding_replan_needed(
        &NetworkChangeImpact {
            route: true,
            interface: true,
            route_unknown: true,
            ..Default::default()
        },
        &native,
        Some(&baseline),
        Some(&unrelated_change),
        None,
    ));
    assert!(inferred_binding_replan_needed(
        &NetworkChangeImpact {
            route: true,
            route_prefixes: BTreeSet::from([RoutePrefix::parse("198.51.100.77/32").unwrap(),]),
            ..Default::default()
        },
        &native,
        Some(&baseline),
        Some(&baseline),
        None,
    ));
    assert!(!inferred_binding_replan_needed(
        &NetworkChangeImpact {
            route: true,
            route_prefixes: BTreeSet::from([RoutePrefix::parse("203.0.113.0/24").unwrap(),]),
            ..Default::default()
        },
        &native,
        Some(&baseline),
        Some(&baseline),
        None,
    ));
}

#[test]
fn existing_selector_roots_are_hot_switchable_but_runtime_additions_require_restart() {
    use polaris_config_engine::user_config::proxy_mode::ProxyModeType;
    use polaris_config_engine::user_config::server_config::Protocol;

    let server = |id: &str, address: &str| ServerConfig {
        id: id.into(),
        name: id.into(),
        protocol: Protocol::Vless,
        address: address.into(),
        port: 443,
        ..Default::default()
    };
    let plan = RuntimeBindingPlan {
        native_roots: BTreeSet::new(),
        covered_roots: BTreeSet::from(["node-a".to_string(), "node-b".to_string()]),
        candidate_count: 2,
        unresolved_roots: BTreeMap::from([
            ("node-a".into(), "1.1.1.1".into()),
            ("node-b".into(), "2.2.2.2".into()),
        ]),
        ..Default::default()
    };
    let mut config = UserConfig {
        proxy_mode_type: ProxyModeType::Tun,
        servers: vec![server("node-a", "1.1.1.1"), server("node-b", "2.2.2.2")],
        selected_server_id: Some("node-a".into()),
        ..Default::default()
    };
    assert!(runtime_binding_roots_covered(&config, &plan));

    config.selected_server_id = Some("node-b".into());
    assert!(
        runtime_binding_roots_covered(&config, &plan),
        "同一运行核已生成的 B 必须可从 A 真热切，不能因启动时闲置而重启"
    );

    config.servers.push(server("node-c", "3.3.3.3"));
    assert!(
        runtime_binding_roots_covered(&config, &plan),
        "订阅只新增闲置 C 时仍由当前 B 承流，不得提前重启"
    );
    config.selected_server_id = Some("node-c".into());
    assert!(
        !runtime_binding_roots_covered(&config, &plan),
        "运行期新增 C 未进入当前核的路由规划，必须重启后再承流"
    );

    use polaris_config_engine::user_config::proxy_mode::ProxyMode;
    use polaris_config_engine::user_config::rule::{
        Rule, RuleAction, RuleEffects, RuleRouteEffect, RuleType,
    };
    config.selected_server_id = Some("node-a".into());
    config.proxy_mode = ProxyMode::Smart;
    config.traffic_rules = Some(vec![Rule {
        id: "to-c".into(),
        type_field: RuleType::Domain,
        values: vec!["example.com".into()],
        action: RuleAction::Proxy,
        enabled: true,
        effects: Some(RuleEffects {
            route: Some(RuleRouteEffect {
                enabled: true,
                action: RuleAction::Proxy,
                target_server_id: Some("node-c".into()),
                destination_resolution: None,
                resolution_only: false,
            }),
            dns: None,
        }),
        ..Default::default()
    }]);
    assert!(!runtime_binding_roots_covered(&config, &plan));
}

#[test]
fn explicit_interface_unavailability_distinguishes_missing_down_and_recovery() {
    let required = BTreeSet::from(["en0".to_owned(), "utun7".to_owned()]);
    let observed = BTreeMap::from([("en0".into(), (false, Vec::new()))]);
    let unavailable = required_interfaces_unavailable(&required, &observed);
    assert_eq!(unavailable.down, BTreeSet::from(["en0".to_owned()]));
    assert_eq!(unavailable.missing, BTreeSet::from(["utun7".to_owned()]));

    let recovered = BTreeMap::from([
        ("en0".into(), (true, Vec::new())),
        ("utun7".into(), (true, Vec::new())),
    ]);
    assert!(required_interfaces_unavailable(&required, &recovered).is_empty());
}

// ══════════════════════════════════════════════════════════════════════════════
// A1 系统代理启用侧（最大缺口：systemProxy 模式 start 成功却从不设 OS 代理 → 流量不经核）
//
// 注：**start_inner 内的调用点**（wait_ready 成功后）无法在本机验证——它须真核就绪、而本机硬禁
// 起核（同 residual 发射的约束，见其上方注释）。故此处覆盖 `maybe_enable_system_proxy` 的**全部
// 决策 + 装配逻辑**（模式门控 / enable 真被调 / req 参数），start_inner 的单行调用点靠代码审查背书
// （诚实披露，见报告）。enable 内部状态机（marker/防自指/fail-closed 回滚）另在
// `system-integration::proxy_ops` 单测覆盖。
// ══════════════════════════════════════════════════════════════════════════════

/// C-tun-conflict 模式守卫：TUN 出口夺取硬闸**仅**适用 TUN 模式。
/// systemProxy/manual 不接管 tun、出口恒在物理网卡 → baseline 差分永不成立，设闸必误判 → 不闸（caveat）。
/// 变异锁：改成恒 true → systemProxy/manual 起核会被本不该有的闸拦（且 baseline/verify 空跑）。
#[test]
fn tun_route_gate_only_applies_to_tun_mode() {
    assert!(tun_route_gate_applies(ProxyModeType::Tun));
    assert!(!tun_route_gate_applies(ProxyModeType::SystemProxy));
    assert!(!tun_route_gate_applies(ProxyModeType::Manual));
}

/// 🔴 **守卫①**：非 TUN 模式一律不 flush。
///
/// systemProxy / manual 的旧连接多在 sing-box 连接表之外，无差别 RST 够不着它们、只会误伤
/// 已经过代理的连接。**其余前置全部满足**（核在跑、世代未变）—— 唯一变量就是模式，
/// 否则测的是「别的守卫恰好也拦了」。
///
/// **变异锁**：删掉 `if !mode.is_tun()` 早退 → 两个模式都走到建连腿 → 本测转红。
#[tokio::test]
async fn flush_skips_every_non_tun_mode() {
    let (rt, _dir, my_gen) = flush_ready_runtime();
    for mode in [ProxyModeType::SystemProxy, ProxyModeType::Manual] {
        assert_eq!(
            rt.flush_connections_once(mode, my_gen, 1).await,
            FlushOutcome::SkippedNotTun,
            "{mode:?} 模式绝不允许 flush：够不着表外的旧连接，只会误伤已代理的连接"
        );
    }
}

/// 🔴 **守卫②·世代**：延迟窗口内被 stop / 重启接管 → 放弃，不得打到已换的核。
///
/// **变异锁**：删掉世代比对 → 落到建连腿（非 Skipped*）→ 本测转红。
#[tokio::test]
async fn flush_skips_when_generation_superseded() {
    let (rt, _dir, my_gen) = flush_ready_runtime();
    rt.bump_generation(); // 等价于窗口内来了一次 stop / restart
    assert_eq!(
        rt.flush_connections_once(ProxyModeType::Tun, my_gen, 1)
            .await,
        FlushOutcome::SkippedSuperseded,
        "世代已被接管仍开枪 = 把新核刚建立的连接全 RST 掉"
    );
}

/// 🔴 **守卫②·核在跑**：核已停 → 无连接表可 flush。
///
/// **变异锁**：删掉 `status().running` 判定 → 落到建连腿（非 Skipped*）→ 本测转红。
#[tokio::test]
async fn flush_skips_when_core_stopped() {
    let (rt, _dir, my_gen) = flush_ready_runtime();
    *rt.status.write().unwrap() = ProxyStatus::default(); // running:false
    assert_eq!(
        rt.flush_connections_once(ProxyModeType::Tun, my_gen, 1)
            .await,
        FlushOutcome::SkippedCoreStopped,
        "核已停不该再去连管理 API"
    );
}

/// 🔴 **守卫全过 ⇒ 真的走到管理 API**（不是「三条跳过腿都绿」的假闭环）。
///
/// 没有活核，所以断言只到「**不是**任何一条跳过腿」：说明两条守卫都放行、代码真的去开枪了。
/// 端口取一个刚释放的空闲口（纯回环、无监听，不碰宿主网络），故必然落 `ConnectFailed`
/// 或 `CallFailed` —— 具体哪个取决于 tonic 建连是否惰性，不该由本测钉死。
/// 真的把连接 RST 掉需要活核 + 抓包，属真机门。
#[tokio::test]
async fn flush_reaches_management_api_when_both_guards_pass() {
    let (rt, _dir, my_gen) = flush_ready_runtime();
    let dead_port = free_port(); // 监听已 drop ⇒ 无人接
    let outcome = tokio::time::timeout(
        Duration::from_secs(10),
        rt.flush_connections_once(ProxyModeType::Tun, my_gen, dead_port),
    )
    .await
    .expect("flush 腿必须自行了结，不得挂死在建连上");
    assert!(
        matches!(
            outcome,
            FlushOutcome::ConnectFailed(_) | FlushOutcome::CallFailed(_)
        ),
        "两条守卫都放行时必须真的走到管理 API，实得 {outcome:?}"
    );
}

/// 🔴 **接线守卫**：flush 必须在 `running:true` 落定之后才可能开枪。
///
/// 顺序不是洁癖：守卫②查的就是 `status().running`，排在状态提交之前会让每次起核都落
/// `SkippedCoreStopped` —— 腿在、恒不开枪，而上面四条单测照样全绿（它们直调决策点，不经起核腿）。
///
/// **判据现在是间接的**：flush 已挪进 selector 校正的续延（上游「时序修 E」，理由见
/// [`after_selector_reasserted`](ProxyRuntime::after_selector_reasserted)），起核腿里只剩
/// **spawn** 那一行。于是这条不变式改由「spawn 点晚于状态提交」承担 —— 续延只会更晚，
/// 传递性给出同样的保证，且比原来更强（原来 flush 与提交之间还隔着一整段可被重排的主链）。
///
/// 「恰调一次 flush」那条计数不在这里：它已经被
/// [`selector_reassert_continuation_holds_all_three_deferred_actions`] 与
/// [`start_inner_spawns_reassert_and_defers_unlock_invalidation`] 两侧夹住
/// （续延里恰一次 + 主链上零次）。此处再抄一遍只会在下次搬家时留下第三处要改的地方。
///
/// **变异锁**：把 `spawn_reassert_selector_selection(...)` 挪到 `*g = new_status.clone();` 之前 → 转红。
#[test]
fn connection_flush_is_reachable_only_after_status_commit() {
    let body = method_body(
        &module_code("runtime/proxy"),
        "    pub(super) async fn start_inner(",
    );
    let commit = body
        .find("*g = new_status.clone();")
        .expect("锚点 `*g = new_status.clone();` 消失，顺序守卫已失去判据");
    let spawn = body
        .find("self.spawn_reassert_selector_selection(")
        .expect("校正腿的 spawn 点消失 —— flush 已随它挪进续延，没有 spawn 就没有 flush");
    assert!(
        commit < spawn,
        "校正腿（flush 挂在它的续延上）必须 spawn 在 running:true 提交之后，\
             否则守卫②恒判『核已停』→ 腿在但永不开枪"
    );
}

/// 🔴 **建连之后必须再查一次世代**（上面四条行为测试够不着的那半条守卫）。
///
/// 为什么只能用源码守卫：这条腿只在「建连**成功**、随后被接管」时才走到，而单测里没有活的
/// 管理 API —— 建连必失败、必在此之前返回。造一个假 gRPC 服务端来喂它，代价远超这条断言的价值；
/// 真实覆盖在真机门（TUN 起核 + 窗口内点停止）。
///
/// **变异锁**：删掉建连后的那次世代比对 → 计数从 2 掉到 1 → 本测转红。
#[test]
fn flush_rechecks_generation_after_connect() {
    let body = method_body(
        &module_code("runtime/proxy"),
        "    pub(super) async fn flush_connections_once(",
    );
    assert_eq!(
        body.matches("self.gate.generation() != my_gen").count(),
        2,
        "世代必须查两次：建连前一次、建连（await 点）后一次 —— 少一次就可能把新核的连接 RST 掉"
    );
    let connect = body
        .find("SingBoxApiClient::connect(")
        .expect("锚点 `SingBoxApiClient::connect(` 消失，顺序守卫已失去判据");
    let last_check = body
        .rfind("self.gate.generation() != my_gen")
        .expect("上一条断言已保证存在");
    assert!(
        connect < last_check,
        "第二次世代比对必须排在建连之后，排在前面等于两次查同一个时刻"
    );
}
