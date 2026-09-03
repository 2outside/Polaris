use super::*;
use crate::exec::exec_tests_helpers::MockRunner;
use std::cell::Cell;

// ══════════ 纯解析（真实样例 fixture）══════════

#[test]
fn parse_mac_route_get_extracts_utun() {
    // `route -n get 1.1.1.1` 在 sing-box auto_route 已装 /1 半程路由时的真实态：出口 = utunN。
    let sample = "\
   route to: 1.1.1.1
destination: 0.0.0.0
       mask: 128.0.0.0
    gateway: 10.255.0.1
  interface: utun4
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
";
    assert_eq!(
        parse_mac_route_get_interface(sample),
        Some("utun4".to_string())
    );
}

#[test]
fn parse_mac_route_get_physical_iface() {
    // 无 VPN 时出口 = 物理网卡（en0）——差分 baseline 就是这种值。
    let sample = "   route to: 1.1.1.1\n  interface: en0\n      flags: <UP,GATEWAY>\n";
    assert_eq!(
        parse_mac_route_get_interface(sample),
        Some("en0".to_string())
    );
}

#[test]
fn parse_mac_route_get_none_when_no_interface_line() {
    assert_eq!(
        parse_mac_route_get_interface("   route to: 1.1.1.1\n"),
        None
    );
    assert_eq!(parse_mac_route_get_interface(""), None);
}

#[test]
fn parse_linux_ip_route_get_dev_via_gateway() {
    // 物理出口（经网关）：`... via <gw> dev eth0 src ...`。
    let sample = "1.1.1.1 via 192.168.1.1 dev eth0 src 192.168.1.100 uid 1000 \n    cache \n";
    assert_eq!(parse_linux_ip_route_dev(sample), Some("eth0".to_string()));
}

#[test]
fn parse_linux_ip_route_get_dev_tun() {
    // tun 出口（无网关直连 dev）：`1.1.1.1 dev tun0 src ...`。
    let sample = "1.1.1.1 dev tun0 table 2022 src 172.19.0.2 uid 1000 \n    cache \n";
    assert_eq!(parse_linux_ip_route_dev(sample), Some("tun0".to_string()));
}

#[test]
fn parse_linux_ip_route_none_when_no_dev() {
    assert_eq!(
        parse_linux_ip_route_dev("RTNETLINK answers: Network is unreachable\n"),
        None
    );
    assert_eq!(parse_linux_ip_route_dev(""), None);
}

#[test]
fn parse_win_find_netroute_extracts_first_alias() {
    // Find-NetRoute | Format-List InterfaceAlias：源地址对象 + 路由对象各一行，取首个。
    let sample = "\n\nInterfaceAlias : polaris-tun0\n\nInterfaceAlias : polaris-tun0\n\n";
    assert_eq!(
        parse_win_find_netroute_alias(sample),
        Some("polaris-tun0".to_string())
    );
}

#[test]
fn parse_win_find_netroute_physical_alias() {
    let sample = "InterfaceAlias : Ethernet\nInterfaceAlias : Ethernet\n";
    assert_eq!(
        parse_win_find_netroute_alias(sample),
        Some("Ethernet".to_string())
    );
}

#[test]
fn parse_win_find_netroute_none_when_absent() {
    assert_eq!(parse_win_find_netroute_alias("InterfaceIndex : 12\n"), None);
    assert_eq!(parse_win_find_netroute_alias(""), None);
}

// ══════════ 生产实现分派（MockRunner 断言 argv）══════════

fn route_ops_for(platform: Platform, runner: MockRunner) -> SystemRouteOpsImpl<MockRunner> {
    SystemRouteOpsImpl::with_platform(runner, platform)
}

#[test]
fn impl_mac_uses_route_n_get_specific_ip_not_default() {
    let runner = MockRunner::default().with_arg_stdout("get", "  interface: utun7\n");
    let ops = route_ops_for(Platform::Mac, runner);
    assert_eq!(
        ops.exit_interface_for(PROBE_IP).unwrap(),
        Some("utun7".to_string())
    );
    let cmd = &ops.runner.snapshot()[0];
    assert_eq!(cmd.program, "route");
    // **绝不查 default**：必须是具体公网 IP（§4.5 半程路由陷阱）。
    assert_eq!(cmd.args, vec!["-n", "get", "1.1.1.1"]);
    assert!(!ops.runner.ran_arg("default"), "禁止 route -n get default");
}

#[test]
fn impl_mac_uses_inet6_for_ipv6_destination() {
    let runner = MockRunner::default().with_arg_stdout("-inet6", "  interface: en0\n");
    let ops = route_ops_for(Platform::Mac, runner);
    let ip = "2606:4700:4700::1111".parse().unwrap();
    assert_eq!(ops.exit_interface_for(ip).unwrap(), Some("en0".to_string()));
    assert_eq!(
        ops.runner.snapshot()[0].args,
        vec!["-n", "get", "-inet6", "2606:4700:4700::1111"]
    );
}

#[test]
fn impl_linux_uses_ip_route_get() {
    let runner = MockRunner::default().with_arg_stdout("route", "1.1.1.1 dev tun0 src 10.0.0.2\n");
    let ops = route_ops_for(Platform::Linux, runner);
    assert_eq!(
        ops.exit_interface_for(PROBE_IP).unwrap(),
        Some("tun0".to_string())
    );
    let cmd = &ops.runner.snapshot()[0];
    assert_eq!(cmd.program, "ip");
    assert_eq!(cmd.args, vec!["route", "get", "1.1.1.1"]);
}

#[test]
fn impl_linux_uses_ipv6_family_flag() {
    let runner = MockRunner::default()
        .with_arg_stdout("-6", "2606:4700:4700::1111 dev eth0 src 2001:db8::2\n");
    let ops = route_ops_for(Platform::Linux, runner);
    let ip = "2606:4700:4700::1111".parse().unwrap();
    assert_eq!(
        ops.exit_interface_for(ip).unwrap(),
        Some("eth0".to_string())
    );
    assert_eq!(
        ops.runner.snapshot()[0].args,
        vec!["-6", "route", "get", "2606:4700:4700::1111"]
    );
}

#[test]
fn impl_win_uses_find_netroute() {
    let runner =
        MockRunner::default().with_arg_stdout("Find-NetRoute", "InterfaceAlias : polaris-tun0\n");
    let ops = route_ops_for(Platform::Win, runner);
    assert_eq!(
        ops.exit_interface_for(PROBE_IP).unwrap(),
        Some("polaris-tun0".to_string())
    );
    let cmd = &ops.runner.snapshot()[0];
    assert!(cmd.program.ends_with("powershell.exe"));
    assert!(cmd
        .args
        .iter()
        .any(|a| a.contains("Find-NetRoute -RemoteIPAddress 1.1.1.1")));
}

#[test]
fn impl_win_accepts_typed_ipv6_destination() {
    let runner = MockRunner::default().with_arg_stdout("Find-NetRoute", "InterfaceAlias : Wi-Fi\n");
    let ops = route_ops_for(Platform::Win, runner);
    let ip = "2606:4700:4700::1111".parse().unwrap();
    assert_eq!(
        ops.exit_interface_for(ip).unwrap(),
        Some("Wi-Fi".to_string())
    );
    assert!(ops.runner.snapshot()[0]
        .args
        .iter()
        .any(|a| a.contains("Find-NetRoute -RemoteIPAddress 2606:4700:4700::1111")));
}

#[test]
fn impl_other_platform_returns_none_no_command() {
    let ops = route_ops_for(Platform::Other, MockRunner::default());
    assert_eq!(ops.exit_interface_for(PROBE_IP).unwrap(), None);
    assert!(ops.runner.snapshot().is_empty(), "未知平台不得跑任何命令");
}

#[test]
fn impl_command_failure_propagates_err() {
    let runner = MockRunner {
        fail_programs: vec!["route".into()],
        ..Default::default()
    };
    assert!(route_ops_for(Platform::Mac, runner)
        .exit_interface_for(PROBE_IP)
        .is_err());
}

// ══════════ baseline 差分判定（verify_exit_captured）══════════

/// 队列式 mock 探针：按序返回预置结果；耗尽后返回末个（模拟稳定态）。
fn queued_probe(
    seq: Vec<Option<String>>,
) -> impl FnMut() -> Result<Option<String>, SystemIntegrationError> {
    let mut it = seq.into_iter();
    let mut last: Option<String> = None;
    move || {
        if let Some(next) = it.next() {
            last = next.clone();
            Ok(next)
        } else {
            Ok(last.clone())
        }
    }
}

fn s(x: &str) -> Option<String> {
    Some(x.to_string())
}

#[test]
fn verify_captured_when_iface_changes_from_baseline() {
    // baseline=utun3（他方 VPN），起核后切到 utun7（我方）→ 夺到路由 → Captured（且早退）。
    let sleeps = Cell::new(0);
    let outcome = verify_exit_captured(
        s("utun3"),
        8,
        queued_probe(vec![s("utun3"), s("utun7"), s("utun7")]),
        || sleeps.set(sleeps.get() + 1),
    );
    assert_eq!(
        outcome,
        ExitCaptureOutcome::Captured {
            interface: s("utun7")
        }
    );
    // 第 2 次探测即切走 → 只 sleep 了 1 次（第 1 次探测后），随即早退。
    assert_eq!(sleeps.get(), 1, "夺到即早退，不空等剩余 grace");
}

#[test]
fn verify_not_captured_when_iface_stays_baseline_through_grace() {
    // baseline=utun3，grace 全程仍是 utun3（我方 utun 抢不到路由）→ NotCaptured（硬闸）。
    let sleeps = Cell::new(0);
    let outcome = verify_exit_captured(
        s("utun3"),
        4,
        queued_probe(vec![s("utun3")]), // 耗尽后恒返 utun3
        || sleeps.set(sleeps.get() + 1),
    );
    assert_eq!(
        outcome,
        ExitCaptureOutcome::NotCaptured {
            baseline: "utun3".into(),
            last: "utun3".into()
        }
    );
    // grace 超时：4 次探测之间 sleep 3 次（末次探测后不 sleep）。
    assert_eq!(sleeps.get(), 3);
}

#[test]
fn verify_not_captured_for_own_route_install_failure() {
    // 无他方 VPN（baseline=en0 物理网卡），TUN 模式起核后出口仍 en0（我方路由装失败）→ 同样 NotCaptured。
    // 后验断言的是「出口切没切」而非「因谁没切」→ 我方装失败也一网打尽（设计 §4.2）。
    let outcome = verify_exit_captured(s("en0"), 3, queued_probe(vec![s("en0")]), || {});
    assert_eq!(
        outcome,
        ExitCaptureOutcome::NotCaptured {
            baseline: "en0".into(),
            last: "en0".into()
        }
    );
}

#[test]
fn verify_indeterminate_when_baseline_unreadable() {
    // 起核前 baseline 读不到 → 无法差分 → 不闸（避免假阳性拦掉正常起核，§4.7）。
    let outcome = verify_exit_captured(None, 3, queued_probe(vec![s("utun7")]), || {});
    // baseline=None 时任何可读新出口都算切走（偏向不闸的安全方向）。
    assert_eq!(
        outcome,
        ExitCaptureOutcome::Captured {
            interface: s("utun7")
        }
    );
}

#[test]
fn verify_indeterminate_when_probe_unreadable_through_grace() {
    // baseline 可读但 grace 内探测恒不可读（命令一直失败/无接口）→ 不可断言 → 不闸。
    let outcome = verify_exit_captured(
        s("utun3"),
        3,
        || Err(SystemIntegrationError::route("boom")),
        || {},
    );
    assert_eq!(outcome, ExitCaptureOutcome::Indeterminate);
}

#[test]
fn verify_single_poll_grace_still_evaluates() {
    // max_polls=0 被夹到 1：至少探一次，不 sleep。
    let sleeps = Cell::new(0);
    let outcome = verify_exit_captured(s("utun3"), 0, queued_probe(vec![s("utun3")]), || {
        sleeps.set(sleeps.get() + 1)
    });
    assert_eq!(
        outcome,
        ExitCaptureOutcome::NotCaptured {
            baseline: "utun3".into(),
            last: "utun3".into()
        }
    );
    assert_eq!(sleeps.get(), 0, "单次探测无相邻间隔可等");
}
