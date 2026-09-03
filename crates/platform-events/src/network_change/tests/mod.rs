use super::*;
// src-tauri 侧这个函数是以别名 `network_monitor_line_impact` 导入的（`proxy.rs` 的
// `monitor_line_impact as network_monitor_line_impact`）。搬进本 crate 后用真名，测试里保留别名
// 只是为了让搬迁 diff 只剩位置变化 —— 断言正文一个字节都没动。
use super::monitor_line_impact as network_monitor_line_impact;
use polaris_helper_proto::Platform;
use std::collections::{BTreeMap, BTreeSet};

use crate::RoutePrefix;

#[test]
fn platform_monitor_lines_follow_event_shapes() {
    assert!(network_monitor_line_impact(
        Platform::Linux,
        "[ROUTE]Deleted 192.0.2.10 dev eth0",
        None,
    )
    .is_some());
    assert!(network_monitor_line_impact(Platform::Linux, "  \n", None).is_none());
    assert!(network_monitor_line_impact(
        Platform::Linux,
        "       valid_lft forever preferred_lft forever",
        Some("polaris-tun0"),
    )
    .is_none());
    assert!(
        network_monitor_line_impact(Platform::Linux, "    link/none", Some("polaris-tun0"),)
            .is_none()
    );
    assert!(network_monitor_line_impact(Platform::Mac, "RTM_IFINFO: iface up", None).is_some());
    assert!(network_monitor_line_impact(Platform::Mac, "noise", None).is_none());
    assert!(network_monitor_line_impact(Platform::Win, "anything", None).is_none());
    assert_eq!(
        network_monitor_line_impact(Platform::Linux, "[LINK]2: eth0: <UP>", None),
        Some(NetworkChangeImpact {
            interface: true,
            ..Default::default()
        })
    );
    assert_eq!(
        network_monitor_line_impact(Platform::Linux, "[ROUTE]default via 192.0.2.1", None,),
        Some(NetworkChangeImpact {
            route: true,
            ..Default::default()
        })
    );
    assert!(network_monitor_line_impact(
        Platform::Linux,
        "[ROUTE]0.0.0.0/1 dev polaris-tun0",
        Some("polaris-tun0"),
    )
    .is_none());
    assert!(network_monitor_line_impact(
        Platform::Linux,
        "[ROUTE]default via 192.0.2.1 dev eth0",
        Some("polaris-tun0"),
    )
    .is_some());
    // 精确前缀必须断言到**值**：`(Some(prefix), false)` 与 `(None, true)` 都是 `is_some()`，
    // 只查 is_some 时「取到了 198.51.100.0/24」与「没看懂、按未知保守处理」不可区分。
    assert_eq!(
        network_monitor_line_impact(Platform::Linux, "[ROUTE]198.51.100.0/24 dev eth0", None),
        Some(NetworkChangeImpact {
            route: true,
            route_prefixes: BTreeSet::from([RoutePrefix::parse("198.51.100.0/24").unwrap()]),
            ..Default::default()
        })
    );
    assert_eq!(
        network_monitor_line_impact(
            Platform::Linux,
            "[ROUTE]Deleted 2001:db8:1234::/48 via fe80::1 dev eth0",
            None,
        ),
        Some(NetworkChangeImpact {
            route: true,
            route_prefixes: BTreeSet::from([RoutePrefix::parse("2001:db8:1234::/48").unwrap()]),
            ..Default::default()
        })
    );
    // `dev` 之前没出现任何可解析目标 → 只能按未知路由保守处理，绝不能静默当成无关。
    assert_eq!(
        network_monitor_line_impact(Platform::Linux, "[ROUTE]dev eth0 table main", None),
        Some(NetworkChangeImpact {
            route: true,
            route_unknown: true,
            ..Default::default()
        })
    );
    // 老 iproute2 / 未知 label：非缩进且不带任何已知前缀的行走兜底分支，接口与路由都当变了。
    assert_eq!(
        network_monitor_line_impact(Platform::Linux, "Deleted 192.0.2.0/24 dev eth0", None),
        Some(NetworkChangeImpact {
            interface: true,
            route: true,
            route_unknown: true,
            ..Default::default()
        }),
        "无 label 的老 iproute2 输出不得被静默丢弃"
    );
    assert_eq!(
        network_monitor_line_impact(Platform::Linux, "[NEIGH]192.0.2.1 dev eth0", None),
        Some(NetworkChangeImpact {
            interface: true,
            route: true,
            route_unknown: true,
            ..Default::default()
        }),
        "未知 label 同样走兜底，由接口快照做第二层去噪"
    );

    let mut mac_parser = MacRouteMonitorParser::default();
    let header = mac_parser.push_line(
        "RTM_ADD: Add Route: len 160, pid: 7, flags:<UP,GATEWAY,STATIC>",
        Some("utun8"),
    );
    assert!(header.observed_event);
    assert!(header.impact.is_none());
    assert!(mac_parser
        .push_line("sockaddrs: <DST,GATEWAY,NETMASK,IFP>", Some("utun8"))
        .impact
        .is_none());
    let parsed = mac_parser
        .push_line(
            " 198.51.100.0 192.0.2.1 255.255.255.0 en0:aa.bb.cc",
            Some("utun8"),
        )
        .impact
        .expect("complete route block yields a precise impact");
    assert_eq!(
        parsed.route_prefixes,
        BTreeSet::from([RoutePrefix::parse("198.51.100.0/24").unwrap()])
    );
    assert!(!parsed.route_unknown);

    let mut mac_parser = MacRouteMonitorParser::default();
    mac_parser.push_line(
        "RTM_DELETE: Delete Route: len 160, flags:<UP,GATEWAY,HOST>",
        Some("utun8"),
    );
    mac_parser.push_line("sockaddrs: <DST,GATEWAY,IFP>", Some("utun8"));
    assert!(
        mac_parser
            .push_line(" 203.0.113.7 link#22 utun8:01.02", Some("utun8"))
            .impact
            .is_none(),
        "受管 utun 自身路由事件必须整块忽略"
    );

    let mut mac_parser = MacRouteMonitorParser::default();
    mac_parser.push_line(
        "RTM_ADD: Add Route: len 160, flags:<UP,GATEWAY,STATIC>",
        None,
    );
    assert!(mac_parser.take_incomplete().is_some_and(|impact| {
        impact.route && impact.route_unknown && impact.route_prefixes.is_empty()
    }));

    let mut mac_parser = MacRouteMonitorParser::default();
    mac_parser.push_line(
        "RTM_ADD: Add Route: len 160, flags:<UP,GATEWAY,STATIC>",
        None,
    );
    mac_parser.push_line("sockaddrs: <DST,GATEWAY,NETMASK,IFP>", None);
    let default_route = mac_parser
        .push_line(" default 192.0.2.1 default en0:aa.bb.cc", None)
        .impact
        .unwrap();
    assert!(default_route.route);
    assert!(!default_route.route_unknown);
    assert!(default_route.route_prefixes.is_empty());

    let mut mac_parser = MacRouteMonitorParser::default();
    mac_parser.push_line(
        "RTM_ADD: Add Route: len 200, flags:<UP,GATEWAY,HOST,STATIC>",
        None,
    );
    mac_parser.push_line("sockaddrs: <DST,GATEWAY,IFP>", None);
    let host_route = mac_parser
        .push_line(" 2001:db8::42 fe80::1%en0 en0:aa.bb.cc", None)
        .impact
        .unwrap();
    assert_eq!(
        host_route.route_prefixes,
        BTreeSet::from([RoutePrefix::parse("2001:db8::42/128").unwrap()])
    );
    assert!(!host_route.route_unknown);
}
/// F6 回归：事件源给出了精确前缀，但计划里还有**没解析出探针 IP 的根**时，必须重规划。
///
/// 未决根不在 `probe_ips` 里 ⇒ 没有任何事实能证明这条前缀与它无关。旧判据只查 `probe_ips`，
/// 于是「精确前缀 + 存在未决根」被判成无关，而 `route_unknown` 那条腿对同一份计划却判要重算 ——
/// 同一个事实按事件源是否给出前缀得到相反结论，是一次沉默的行为收窄。
#[test]
fn route_replan_treats_unresolved_roots_as_unprovable_not_unrelated() {
    let unrelated_prefix = NetworkChangeImpact {
        route: true,
        route_prefixes: BTreeSet::from([RoutePrefix::parse("192.0.2.0/24").unwrap()]),
        ..Default::default()
    };
    let covering_prefix = NetworkChangeImpact {
        route: true,
        route_prefixes: BTreeSet::from([RoutePrefix::parse("198.51.100.0/24").unwrap()]),
        ..Default::default()
    };
    let default_route = NetworkChangeImpact {
        route: true,
        route_prefixes: BTreeSet::from([RoutePrefix::parse("0.0.0.0/0").unwrap()]),
        ..Default::default()
    };
    let unknown_route = NetworkChangeImpact {
        route: true,
        route_unknown: true,
        ..Default::default()
    };

    let special = RuntimeBindingPlan {
        bindings: BTreeMap::from([("node-a".into(), "en0".into())]),
        covered_roots: BTreeSet::from(["node-a".into()]),
        probe_ips: BTreeMap::from([("node-a".into(), "198.51.100.77".parse().unwrap())]),
        candidate_count: 1,
        ..Default::default()
    };
    let native = RuntimeBindingPlan {
        native_roots: BTreeSet::from(["node-a".into()]),
        covered_roots: BTreeSet::from(["node-a".into()]),
        probe_ips: BTreeMap::from([("node-a".into(), "198.51.100.77".parse().unwrap())]),
        candidate_count: 1,
        ..Default::default()
    };
    let unresolved = RuntimeBindingPlan {
        covered_roots: BTreeSet::from(["node-b".into()]),
        unresolved_roots: BTreeMap::from([("node-b".into(), "node-b.example.com".into())]),
        candidate_count: 1,
        ..Default::default()
    };

    // 特殊绑定：精确前缀仍按覆盖关系过滤（新旧一致）。
    assert!(route_replan_needed(&covering_prefix, &special));
    assert!(!route_replan_needed(&unrelated_prefix, &special));
    // 全 native：默认出口由 auto_detect_interface 跟随，无关前缀不重算（新旧一致）。
    assert!(!route_replan_needed(&unrelated_prefix, &native));
    // F13：同一份 native 计划，`198.51.100.0/24` 判要重算（下一行），事件源给不出前缀就判不用 ——
    // 结论由事件源的表达能力决定而不是由事实决定。这一格此前断言的正是那个收窄，现已翻正。
    assert!(route_replan_needed(&covering_prefix, &native));
    assert!(route_replan_needed(&unknown_route, &native));
    // /0 不代表任何节点目标（新旧一致）；未决根同样没写 bind_interface，默认出口由
    // auto_detect_interface 跟随，不能因为「有未决根」就把 /0 也升级成重规划。
    assert!(!route_replan_needed(&default_route, &special));
    assert!(!route_replan_needed(&default_route, &native));
    assert!(!route_replan_needed(&default_route, &unresolved));
    // 本条即被治的格：旧判据在这里返回 false。
    assert!(
        route_replan_needed(&unrelated_prefix, &unresolved),
        "未决根没有 IP ⇒ 无法证明该前缀与它无关 ⇒ 必须重规划"
    );
    // 与 route_unknown 腿对同一份计划给出一致结论。
    assert!(route_replan_needed(&unknown_route, &unresolved));
    // 非路由事件仍然与本判据无关。
    assert!(!route_replan_needed(
        &NetworkChangeImpact {
            interface: true,
            ..Default::default()
        },
        &unresolved
    ));
}

/// F12：**带**探针 IP 的未决根按「前缀覆不覆盖它」判定，不再因为「它是未决的」就无条件重算。
///
/// 四类未决根里 ②（有 IP、路由查询无果）与 ④（`retain_available` 剔除的绑定）都保留着
/// `probe_ips`，对它们「这条前缀有没有关系」是**可判定的事实**。旧判据
/// `!unresolved_roots.is_empty()` 把这两类一并算作「不可证」⇒ 订阅里只要有一个长期解析不了的
/// 域名（`unresolved_roots` 永久非空，没有任何腿会重新解析未决根），**任何**比 `/0` 具体的
/// 路由事件都会走到 `schedule_restart()`：路由表一动就整核重启。
///
/// 两格缺一不可：只断言「覆盖 ⇒ true」时旧宽判据同样绿，配上「不覆盖 ⇒ false」才可区分。
#[test]
fn unresolved_root_with_probe_ip_is_judged_by_coverage_not_by_being_unresolved() {
    let unrelated = NetworkChangeImpact {
        route: true,
        route_prefixes: BTreeSet::from([RoutePrefix::parse("192.0.2.0/24").unwrap()]),
        ..Default::default()
    };
    let covering = NetworkChangeImpact {
        route: true,
        route_prefixes: BTreeSet::from([RoutePrefix::parse("198.51.100.0/24").unwrap()]),
        ..Default::default()
    };

    // class ②：`plan_runtime_bindings` 的收集腿先 `probe_ips.insert` 再 match decision，
    // 于是 `decision: None` 的根**带着 IP** 留在 `unresolved_roots` 里。
    let class_two = RuntimeBindingPlan {
        covered_roots: BTreeSet::from(["node-a".into()]),
        probe_ips: BTreeMap::from([("node-a".into(), "198.51.100.77".parse().unwrap())]),
        unresolved_roots: BTreeMap::from([("node-a".into(), "node-a.example.com".into())]),
        candidate_count: 1,
        ..Default::default()
    };
    assert!(
        !route_replan_needed(&unrelated, &class_two),
        "未决根有 IP ⇒「192.0.2.0/24 与它无关」是可证的事实，不该重算"
    );
    assert!(route_replan_needed(&covering, &class_two));

    // class ④：不手搓形状，走**真正的产生腿** —— 绑定接口消失时 `retain_available` 把该根降级
    // 进未决集合，同时原样保留 `probe_ips`。手搓的话，证明的只是我对产生腿的记忆。
    let mut class_four = RuntimeBindingPlan {
        bindings: BTreeMap::from([("node-a".into(), "en5".into())]),
        covered_roots: BTreeSet::from(["node-a".into()]),
        probe_ips: BTreeMap::from([("node-a".into(), "198.51.100.77".parse().unwrap())]),
        candidate_count: 1,
        ..Default::default()
    };
    assert_eq!(
        class_four.retain_available(&BTreeMap::from([("en5".to_string(), false)])),
        1
    );
    assert!(
        class_four.unresolved_roots.contains_key("node-a")
            && class_four.probe_ips.contains_key("node-a"),
        "class ④ 的前提事实：降级进未决集合，但 probe_ips 原样保留"
    );
    assert!(!route_replan_needed(&unrelated, &class_four));
    assert!(route_replan_needed(&covering, &class_four));

    // 反向对照：①③ 类（连 IP 都没有）仍必须保守重算 —— 本条修的是分类，不是把保守面砍掉。
    let class_one_or_three = RuntimeBindingPlan {
        covered_roots: BTreeSet::from(["node-b".into()]),
        unresolved_roots: BTreeMap::from([("node-b".into(), "node-b.example.com".into())]),
        candidate_count: 1,
        ..Default::default()
    };
    assert!(route_replan_needed(&unrelated, &class_one_or_three));

    // 混合：一个有 IP 的未决根 + 一个没 IP 的 ⇒ 后者仍然让无关前缀重算（判据按根逐个问，
    // 不是「有未决根吗」这个整体谓词）。
    let mixed = RuntimeBindingPlan {
        covered_roots: BTreeSet::from(["node-a".into(), "node-b".into()]),
        probe_ips: BTreeMap::from([("node-a".into(), "198.51.100.77".parse().unwrap())]),
        unresolved_roots: BTreeMap::from([
            ("node-a".into(), "node-a.example.com".into()),
            ("node-b".into(), "node-b.example.com".into()),
        ]),
        candidate_count: 2,
        ..Default::default()
    };
    assert!(route_replan_needed(&unrelated, &mixed));
}

/// F13：`route_unknown` 腿必须**恰好**是已知前缀腿的存在性闭包。
///
/// 「路由变了但事件源给不出前缀」＝ 它可能是**任何**前缀。于是唯一自洽的判据是「存在某个具体
/// 前缀会让已知腿判要重算吗」。旧判据 `!bindings.is_empty() || !unresolved_roots.is_empty()`
/// 对全 native 计划答 false，而同一份计划遇到 `198.51.100.0/24` 答 true —— 结论由**事件源的
/// 表达能力**决定而不是由事实决定，正是 F6 要治的沉默收窄留在 native 腿上的残留。
///
/// 本门不抽查几格，而是对整张计划矩阵断言等价关系，两个方向各拦一种改坏法：
/// - `⇐`（闭包为真而未知腿为假）＝ 沉默收窄，F13 的缺陷本身；
/// - `⇒`（未知腿恒真）＝ 以重启风暴换一致性，复审建议的照抄版在空计划上就会撞红。
#[test]
fn route_unknown_leg_is_exactly_the_existential_closure_of_the_known_prefix_leg() {
    let plans: Vec<(&str, RuntimeBindingPlan)> = vec![
        ("空计划（无候选根）", RuntimeBindingPlan::default()),
        (
            "全 native",
            RuntimeBindingPlan {
                native_roots: BTreeSet::from(["node-a".into()]),
                covered_roots: BTreeSet::from(["node-a".into()]),
                probe_ips: BTreeMap::from([("node-a".into(), "198.51.100.77".parse().unwrap())]),
                candidate_count: 1,
                ..Default::default()
            },
        ),
        (
            "特殊绑定",
            RuntimeBindingPlan {
                bindings: BTreeMap::from([("node-a".into(), "en0".into())]),
                covered_roots: BTreeSet::from(["node-a".into()]),
                probe_ips: BTreeMap::from([("node-a".into(), "198.51.100.77".parse().unwrap())]),
                candidate_count: 1,
                ..Default::default()
            },
        ),
        (
            "未决且无 IP（①③）",
            RuntimeBindingPlan {
                covered_roots: BTreeSet::from(["node-b".into()]),
                unresolved_roots: BTreeMap::from([("node-b".into(), "node-b.example.com".into())]),
                candidate_count: 1,
                ..Default::default()
            },
        ),
        (
            "未决但有 IP（②④）",
            RuntimeBindingPlan {
                covered_roots: BTreeSet::from(["node-a".into()]),
                probe_ips: BTreeMap::from([("node-a".into(), "198.51.100.77".parse().unwrap())]),
                unresolved_roots: BTreeMap::from([("node-a".into(), "node-a.example.com".into())]),
                candidate_count: 1,
                ..Default::default()
            },
        ),
        (
            "native + 未决无 IP",
            RuntimeBindingPlan {
                native_roots: BTreeSet::from(["node-a".into()]),
                covered_roots: BTreeSet::from(["node-a".into(), "node-b".into()]),
                probe_ips: BTreeMap::from([("node-a".into(), "198.51.100.77".parse().unwrap())]),
                unresolved_roots: BTreeMap::from([("node-b".into(), "node-b.example.com".into())]),
                candidate_count: 2,
                ..Default::default()
            },
        ),
        (
            "IPv6 native",
            RuntimeBindingPlan {
                native_roots: BTreeSet::from(["node-v6".into()]),
                covered_roots: BTreeSet::from(["node-v6".into()]),
                probe_ips: BTreeMap::from([("node-v6".into(), "2001:db8::77".parse().unwrap())]),
                candidate_count: 1,
                ..Default::default()
            },
        ),
    ];

    for (label, plan) in plans {
        assert!(
            plan.bindings
                .keys()
                .all(|server_id| plan.probe_ips.contains_key(server_id)),
            "{label}：矩阵里的计划必须是生产形状（bindings ⊆ probe_ips，见收集腿的 insert 次序），\
                 否则等价关系测的不是真实输入"
        );

        // 具体前缀全域：每个 probe IP 的 host 前缀、一个确定无关的前缀，外加两族 `/0`
        // （已知腿对 `/0` 恒 false —— 用它证明闭包不是被默认路由撑起来的）。
        let mut universe = vec![
            RoutePrefix::parse("203.0.113.0/24").unwrap(),
            RoutePrefix::parse("0.0.0.0/0").unwrap(),
            RoutePrefix::parse("::/0").unwrap(),
        ];
        for probe in plan.probe_ips.values() {
            universe.push(
                RoutePrefix::new(*probe, if probe.is_ipv4() { 32 } else { 128 })
                    .expect("host 前缀长度合法"),
            );
        }
        let closure = universe.iter().any(|prefix| {
            route_replan_needed(
                &NetworkChangeImpact {
                    route: true,
                    route_prefixes: BTreeSet::from([*prefix]),
                    ..Default::default()
                },
                &plan,
            )
        });
        let unknown = route_replan_needed(
            &NetworkChangeImpact {
                route: true,
                route_unknown: true,
                ..Default::default()
            },
            &plan,
        );
        assert_eq!(
            unknown, closure,
            "{label}：未知路由腿必须等于「存在某个具体前缀会让已知腿重算」"
        );
    }
}

/// F15：去抖窗到期时的**全空** impact 必须被拦在 `handle_network_change` 之外。
///
/// 空 impact 放行会落到 `else` 腿：一次真实出口探测 + 向前端广播一帧 pending 置空状态
/// （用户可见「正在检测」闪一下）。F4 把 Windows 回调的唤醒移出锁后，读侧的 `take_pending()`
/// 可能正落在某次回调 unlock 与 `try_send` 之间 ⇒ 下一轮去抖必然拿到全空 impact。
#[test]
fn debounced_network_change_drops_the_empty_window_and_keeps_every_fact() {
    assert_eq!(
        debounced_network_change(NetworkChangeImpact::default()),
        None,
        "全空窗口不是一次网络变化"
    );
    for fact in [
        NetworkChangeImpact {
            interface: true,
            ..Default::default()
        },
        NetworkChangeImpact {
            route: true,
            ..Default::default()
        },
        NetworkChangeImpact {
            route: true,
            route_unknown: true,
            ..Default::default()
        },
        NetworkChangeImpact {
            route: true,
            route_prefixes: BTreeSet::from([RoutePrefix::parse("198.51.100.0/24").unwrap()]),
            ..Default::default()
        },
    ] {
        assert_eq!(
            debounced_network_change(fact.clone()),
            Some(fact),
            "守卫只拦全空窗口；任何一位事实都必须原样送达，否则它就成了新的静默丢事件点"
        );
    }
}
