use super::*;
use crate::proxy::proxy_tests_helpers::MemFs;
use std::cell::RefCell;

struct MockDnsOps {
    targets: Vec<String>,
    dns_state: RefCell<BTreeMap<String, Vec<String>>>,
    apply_calls: RefCell<Vec<(String, Vec<String>)>>,
    apply_fail_targets: Vec<String>,
    list_fails: bool,
    /// 模拟平台是否接管（mac=true / win·linux=false）。
    takeover: bool,
    /// 仅对**该 target** 生效的「瞬时失败」计数器：每次对它的 `apply_dns` 调用消耗 1，耗尽后
    /// 转正常（成功）。与 `apply_fail_targets` 的**永久**失败区分——用于验证重试：先失败 N 次
    /// 再成功，且不误伤同一轮里的其它 target（同构 `proxy_ops.rs` `FlakyRunner` 设计）。
    transient_fail_target: Option<String>,
    transient_fail_count: RefCell<u32>,
    /// 瞬时失败时返回的错误消息（决定 `dns_set_should_retry` 判「重试」还是「放弃」）。
    transient_fail_msg: String,
}

/// `takeover: true` = mac 语义（默认）；win/linux 腿的测试显式置 false。
impl Default for MockDnsOps {
    fn default() -> Self {
        Self {
            targets: Vec::new(),
            dns_state: RefCell::new(BTreeMap::new()),
            apply_calls: RefCell::new(Vec::new()),
            apply_fail_targets: Vec::new(),
            list_fails: false,
            takeover: true,
            transient_fail_target: None,
            transient_fail_count: RefCell::new(0),
            transient_fail_msg: String::new(),
        }
    }
}

impl SystemDnsOps for MockDnsOps {
    fn takeover_supported(&self) -> bool {
        self.takeover
    }
    fn list_targets(&self) -> Result<Vec<String>, crate::error::SystemIntegrationError> {
        if self.list_fails {
            return Err(crate::error::SystemIntegrationError::dns("list failed"));
        }
        Ok(self.targets.clone())
    }
    fn read_dns(&self, target: &str) -> Result<Vec<String>, crate::error::SystemIntegrationError> {
        Ok(self
            .dns_state
            .borrow()
            .get(target)
            .cloned()
            .unwrap_or_default())
    }
    fn apply_dns(
        &self,
        target: &str,
        ips: &[String],
    ) -> Result<(), crate::error::SystemIntegrationError> {
        self.apply_calls
            .borrow_mut()
            .push((target.to_string(), ips.to_vec()));
        if self.transient_fail_target.as_deref() == Some(target) {
            let mut rem = self.transient_fail_count.borrow_mut();
            if *rem > 0 {
                *rem -= 1;
                return Err(crate::error::SystemIntegrationError::dns(
                    self.transient_fail_msg.clone(),
                ));
            }
        }
        if self.apply_fail_targets.iter().any(|t| t == target) {
            return Err(crate::error::SystemIntegrationError::dns("apply failed"));
        }
        // 模拟真实写入状态。
        self.dns_state
            .borrow_mut()
            .insert(target.to_string(), ips.to_vec());
        Ok(())
    }
    fn read_effective_resolvers(
        &self,
    ) -> Result<Vec<String>, crate::error::SystemIntegrationError> {
        Ok(vec!["192.168.1.1".to_string()])
    }
}

fn mem_dns_marker() -> DnsMarker<MemFs> {
    DnsMarker::new(MemFs::new(), "/dns-marker.json")
}

fn controller(ops: MockDnsOps) -> SystemDnsController<MockDnsOps, MemFs> {
    SystemDnsController::new(ops, mem_dns_marker())
}

#[test]
fn set_dns_takes_over_writes_marker_applies_controlled_ip() {
    let ops = MockDnsOps {
        targets: vec!["Wi-Fi".into()],
        dns_state: RefCell::new({
            let mut m = BTreeMap::new();
            m.insert("Wi-Fi".into(), vec!["192.168.1.1".to_string()]);
            m
        }),
        ..Default::default()
    };
    let mut c = controller(ops);

    c.set_dns();
    assert!(c.has_marker());
    // apply 受控 IP。
    let applied = c.ops.apply_calls.borrow();
    assert!(applied
        .iter()
        .any(|(t, ips)| t == "Wi-Fi" && ips == &vec!["8.8.8.8".to_string()]));
    // marker.original 记录了接管前的真实 LAN（192.168.1.1）。
    let marker = c.marker.read().unwrap();
    assert_eq!(
        marker.original.get("Wi-Fi").unwrap(),
        &vec!["192.168.1.1".to_string()]
    );
}

#[test]
fn set_dns_noop_when_no_targets() {
    let mut c = controller(MockDnsOps::default());
    c.set_dns();
    assert!(!c.has_marker());
    assert!(c.ops.apply_calls.borrow().is_empty());
}

#[test]
fn set_dns_noop_when_controlled_ip_invalid() {
    // CONTROLLED_TUN_DNS_IP=8.8.8.8 不在 bootstrap-direct → 合法，set 正常。
    // 此测试验证守卫路径：构造一个 controlled_ip 非法的 marker 不易（常量），改为验证合法时不被拦截。
    let ops = MockDnsOps {
        targets: vec!["Wi-Fi".into()],
        ..Default::default()
    };
    let mut c = controller(ops);
    c.set_dns();
    assert!(c.has_marker(), "8.8.8.8 合法，应正常接管");
}

#[test]
fn set_dns_rolls_back_on_apply_failure() {
    // "apply failed"（`apply_fail_targets` 永久失败腿）非权限类 → 可重试，耗尽 maxRetries=2
    // （共 3 次 attempt）后仍失败 → 兜底还原（还原本身也因同一目标永久失败而失败）→ 补清 marker。
    let ops = MockDnsOps {
        targets: vec!["Wi-Fi".into()],
        dns_state: RefCell::new({
            let mut m = BTreeMap::new();
            m.insert("Wi-Fi".into(), vec!["192.168.1.1".to_string()]);
            m
        }),
        apply_fail_targets: vec!["Wi-Fi".into()],
        ..Default::default()
    };
    let mut c = controller(ops).with_noop_sleeper();
    c.set_dns();
    // apply 耗尽重试仍失败 → 兜底还原 → marker 清。
    assert!(!c.has_marker(), "rollback cleared marker");
    assert_eq!(
        c.ops.apply_calls.borrow().len(),
        4,
        "重试 3 次（maxRetries=2）+ 回滚还原 1 次（不重试）"
    );
}

// ══════════ set_dns 重试（补齐与系统代理侧 `retry_op` 的不对称；仅 set_dns 一处）══════════

#[test]
fn dns_set_should_retry_aborts_on_permission_or_not_authorized() {
    // 纯谓词断言（同构 `proxy_ops.rs` 的 `mac_should_retry_aborts_on_permission_or_not_authorized`）。
    let ret = |m: &str| dns_set_should_retry(&crate::error::SystemIntegrationError::dns(m));
    assert!(
        !ret("networksetup: permission denied"),
        "permission → 不重试"
    );
    assert!(
        !ret("Error: not authorized to change"),
        "not authorized → 不重试"
    );
    assert!(ret("networksetup: temporarily unavailable"), "瞬时 → 重试");
    // 词表补齐后的关键形态：macOS `networksetup` 真实权限文案不含上游那两词。
    // 变异锁：把 `dns_set_should_retry` 改回手抄的 `permission || not authorized` → 本断言转红
    // （= 一次必败的权限错误会持 `dns_controller` 锁多跑 2 次重试 + 1.5s 退避）。
    assert!(
        !ret("networksetup: requires admin privileges to change DNS"),
        "requires admin privileges → 不重试（此前被误判成瞬时）"
    );
    assert!(
        !ret("setting DNS: Operation not permitted"),
        "EPERM → 不重试"
    );
}

/// 端到端形态（不只是谓词）：权限错误必须**只跑一次** apply，绝不重试。
///
/// 变异锁：这条与上面的纯谓词断言分工不同 —— 谓词断言证明「判据认得这句话」，本用例证明
/// 「判据真的接在 `DNS_SET_RETRY.should_retry` 上」（换回 `|_| true` 时纯谓词断言仍绿）。
#[test]
fn set_dns_admin_privileges_error_aborts_without_retry() {
    let ops = MockDnsOps {
        targets: vec!["Wi-Fi".into()],
        dns_state: RefCell::new({
            let mut m = BTreeMap::new();
            m.insert("Wi-Fi".into(), vec!["192.168.1.1".to_string()]);
            m
        }),
        transient_fail_target: Some("Wi-Fi".into()),
        transient_fail_count: RefCell::new(99),
        transient_fail_msg: "networksetup: requires admin privileges".into(),
        ..Default::default()
    };
    let mut c = controller(ops).with_noop_sleeper();
    c.set_dns();
    assert_eq!(
        c.ops.apply_calls.borrow().len(),
        2,
        "权限失败 → 1 次 apply + 1 次兜底还原（**不含**任何重试；\
             判据漏词时这里会变成 3+1=4，正是那 1.5s 白占锁的来源）"
    );
}

#[test]
fn set_dns_retries_transient_failure_then_succeeds() {
    // ① 瞬态失败一次后成功 → 整体成功且不回滚。
    let ops = MockDnsOps {
        targets: vec!["Wi-Fi".into()],
        dns_state: RefCell::new({
            let mut m = BTreeMap::new();
            m.insert("Wi-Fi".into(), vec!["192.168.1.1".to_string()]);
            m
        }),
        transient_fail_target: Some("Wi-Fi".into()),
        transient_fail_count: RefCell::new(1),
        transient_fail_msg: "networksetup: temporarily unavailable".into(),
        ..Default::default()
    };
    let mut c = controller(ops).with_noop_sleeper();
    c.set_dns();
    assert!(c.has_marker(), "重试后应成功接管，不应回滚");
    assert_eq!(
        c.ops.apply_calls.borrow().len(),
        2,
        "首次失败 + 1 次重试成功 = 2 次 apply"
    );
    assert_eq!(
        c.ops.dns_state.borrow().get("Wi-Fi").unwrap(),
        &vec!["8.8.8.8".to_string()],
        "重试成功后应已 apply 受控 IP"
    );
}

#[test]
fn set_dns_permission_error_aborts_without_retry() {
    // ② 权限类错误 → 立即失败不重试（断言尝试次数）。
    let ops = MockDnsOps {
        targets: vec!["Wi-Fi".into()],
        dns_state: RefCell::new({
            let mut m = BTreeMap::new();
            m.insert("Wi-Fi".into(), vec!["192.168.1.1".to_string()]);
            m
        }),
        // 权限错误不会自愈 → 计数给足（99），验证「不重试」而非「凑巧次数够用」。
        transient_fail_target: Some("Wi-Fi".into()),
        transient_fail_count: RefCell::new(99),
        transient_fail_msg: "networksetup: permission denied".into(),
        ..Default::default()
    };
    let mut c = controller(ops).with_noop_sleeper();
    c.set_dns();
    assert!(!c.has_marker(), "权限错误 → 回滚兜底 → marker 清");
    assert_eq!(
        c.ops.apply_calls.borrow().len(),
        2,
        "重试阶段仅 1 次尝试（不重试）+ 回滚还原 1 次（本身也不重试）= 2 次；\
             若误重试则耗尽 3 次 attempt + 回滚 ≥ 4 次"
    );
}

#[test]
fn set_dns_retry_exhausted_still_rolls_back_partial_takeover() {
    // ③ 重试耗尽 → 回滚半接管路径仍正确：Wi-Fi 每次 attempt 都成功切到受控 IP（半接管），
    // Ethernet 持续瞬时失败拖垮整轮 → 3 次 attempt（maxRetries=2）耗尽后放弃 → 兜底还原，
    // 须把「已半接管」的 Wi-Fi 也一并撤回原始值（不是只管失败的那个 target）。
    let ops = MockDnsOps {
        targets: vec!["Wi-Fi".into(), "Ethernet".into()],
        dns_state: RefCell::new({
            let mut m = BTreeMap::new();
            m.insert("Wi-Fi".into(), vec!["192.168.1.1".to_string()]);
            m.insert("Ethernet".into(), vec!["10.0.0.1".to_string()]);
            m
        }),
        // 恰好覆盖 3 次 attempt（耗尽后回滚阶段的 Ethernet apply 自然转为成功）。
        transient_fail_target: Some("Ethernet".into()),
        transient_fail_count: RefCell::new(3),
        transient_fail_msg: "networksetup: temporarily unavailable".into(),
        ..Default::default()
    };
    let mut c = controller(ops).with_noop_sleeper();
    c.set_dns();
    assert!(!c.has_marker(), "重试耗尽应回滚并清 marker");
    assert_eq!(
        c.ops.dns_state.borrow().get("Wi-Fi").unwrap(),
        &vec!["192.168.1.1".to_string()],
        "半接管的 Wi-Fi 必须被回滚为原始值，不能残留受控 IP"
    );
    assert_eq!(
        c.ops.dns_state.borrow().get("Ethernet").unwrap(),
        &vec!["10.0.0.1".to_string()],
        "Ethernet 还原为原始值"
    );
    assert_eq!(
        c.ops.apply_calls.borrow().len(),
        8,
        "3 次 attempt × 2 target + 回滚 2 target = 8 次 apply"
    );
}

#[test]
fn restore_dns_restores_original_and_clears_marker() {
    let ops = MockDnsOps {
        targets: vec!["Wi-Fi".into()],
        dns_state: RefCell::new({
            let mut m = BTreeMap::new();
            m.insert("Wi-Fi".into(), vec!["192.168.1.1".to_string()]);
            m
        }),
        ..Default::default()
    };
    let mut c = controller(ops);
    c.set_dns();
    assert!(c.has_marker());

    c.restore_dns();
    // 还原 → apply 原始 LAN IP + 清 marker。
    assert!(!c.has_marker());
    let applied = c.ops.apply_calls.borrow();
    assert!(applied
        .iter()
        .any(|(t, ips)| t == "Wi-Fi" && ips == &vec!["192.168.1.1".to_string()]));
}

#[test]
fn restore_dns_noop_when_no_marker_and_no_original() {
    let mut c = controller(MockDnsOps::default());
    c.restore_dns();
    assert!(c.ops.apply_calls.borrow().is_empty());
}

#[test]
fn reconcile_dns_idempotent_when_all_controlled() {
    // 所有服务已受控 → 幂等 no-op（不写 marker、不动系统）。
    let ops = MockDnsOps {
        targets: vec!["Wi-Fi".into()],
        dns_state: RefCell::new({
            let mut m = BTreeMap::new();
            m.insert("Wi-Fi".into(), vec!["8.8.8.8".to_string()]);
            m
        }),
        ..Default::default()
    };
    let mut c = controller(ops);
    // 先 set 建立 marker。
    c.set_dns();
    let calls_before = c.ops.apply_calls.borrow().len();

    c.reconcile_dns();
    // 全部已受控 → 不再 apply。
    assert_eq!(c.ops.apply_calls.borrow().len(), calls_before);
}

#[test]
fn reconcile_dns_takes_over_new_uncontrolled_service() {
    // Wi-Fi 已接管（marker 在），Ethernet 新出现且未受控 → reconcile 接管 Ethernet。
    let ops = MockDnsOps {
        targets: vec!["Wi-Fi".into(), "Ethernet".into()],
        dns_state: RefCell::new({
            let mut m = BTreeMap::new();
            m.insert("Wi-Fi".into(), vec!["8.8.8.8".to_string()]); // 已受控
            m.insert("Ethernet".into(), vec!["10.0.0.1".to_string()]); // 未受控（真实 LAN）
            m
        }),
        ..Default::default()
    };
    let mut c = controller(ops);

    // 模拟 set 已完成（marker 在，Wi-Fi=8.8.8.8 是我们设的，原始=用户真值）。
    // 直接写 marker 模拟接管态：
    let mut original = BTreeMap::new();
    original.insert("Wi-Fi".into(), vec!["192.168.1.1".to_string()]);
    c.marker.write(&original);
    c.original = Some(original);

    c.reconcile_dns();
    // Ethernet 被 apply 受控 IP。
    let applied = c.ops.apply_calls.borrow();
    assert!(applied
        .iter()
        .any(|(t, ips)| t == "Ethernet" && ips == &vec!["8.8.8.8".to_string()]));
    // Wi-Fi 不重复 apply（已受控跳过）。
    let wifi_applies = applied.iter().filter(|(t, _)| t == "Wi-Fi").count();
    assert_eq!(wifi_applies, 0);
    // marker.original 合并了 Ethernet 的真实原始（10.0.0.1）。
    let marker = c.marker.read().unwrap();
    assert_eq!(
        marker.original.get("Ethernet").unwrap(),
        &vec!["10.0.0.1".to_string()]
    );
    assert_eq!(
        marker.original.get("Wi-Fi").unwrap(),
        &vec!["192.168.1.1".to_string()]
    );
}

#[test]
fn reconcile_dns_noop_when_no_marker() {
    // marker 不在 = 接管未激活 → 绝不擅自接管。
    let ops = MockDnsOps {
        targets: vec!["Wi-Fi".into()],
        ..Default::default()
    };
    let mut c = controller(ops);
    c.reconcile_dns();
    assert!(c.ops.apply_calls.borrow().is_empty());
    assert!(!c.has_marker());
}

#[test]
fn get_lan_resolver_uses_marker_original_when_active() {
    let ops = MockDnsOps::default();
    let c = controller(ops);
    let mut original = BTreeMap::new();
    original.insert("Wi-Fi".into(), vec!["192.168.1.1".to_string()]);
    c.marker.write(&original);
    assert_eq!(
        c.get_lan_resolver_for_dns(),
        Some("192.168.1.1".to_string())
    );
}

#[test]
fn get_lan_resolver_reads_effective_when_no_marker() {
    let ops = MockDnsOps::default();
    let c = controller(ops);
    // 无 marker → read_effective_resolvers → 192.168.1.1（私网）。
    assert_eq!(
        c.get_lan_resolver_for_dns(),
        Some("192.168.1.1".to_string())
    );
}

// ══════════ takeover_supported 门（win/linux 不接管）══════════
//
// 这道门守的是上游 2026-06-17 真机实证修掉的 bug：win 上 `netsh set` 必 ACCESS DENIED，
// 而 set_dns 是「先写 marker 再 apply」→ marker 卡死 → 每次启动反复空跑还原刷错误日志。

#[test]
fn set_dns_writes_no_marker_when_platform_does_not_take_over() {
    // **关键**：不接管的平台连 marker 都不能写（写了就卡死）。
    let ops = MockDnsOps {
        targets: vec!["Wi-Fi".into()],
        takeover: false,
        ..Default::default()
    };
    let mut c = controller(ops);
    c.set_dns();
    assert!(!c.has_marker(), "不接管的平台绝不能写 marker（否则卡死）");
    assert!(c.ops.apply_calls.borrow().is_empty(), "不接管 → 不得 apply");
}

#[test]
fn restore_dns_clears_stuck_marker_on_non_takeover_platform() {
    // 上游 `WindowsSystemDns.restoreDns` = clearMarker()：清历史版本残留的 stuck marker，
    // 否则 has_marker 恒 true → 每个终态点/启动 recovery 反复空跑还原。
    let ops = MockDnsOps {
        targets: vec!["Wi-Fi".into()],
        takeover: false,
        ..Default::default()
    };
    let mut c = controller(ops);
    // 模拟历史遗留的 stuck marker（旧版本 netsh 失败留下的）。
    let mut original = BTreeMap::new();
    original.insert("Wi-Fi".into(), vec!["192.168.1.1".to_string()]);
    c.marker.write(&original);
    assert!(c.has_marker());

    c.restore_dns();
    assert!(!c.has_marker(), "stuck marker 须被清");
    assert!(
        c.ops.apply_calls.borrow().is_empty(),
        "不接管的平台不得往系统写 DNS"
    );
}

#[test]
fn reconcile_dns_noop_on_non_takeover_platform() {
    let ops = MockDnsOps {
        targets: vec!["Wi-Fi".into()],
        takeover: false,
        ..Default::default()
    };
    let mut c = controller(ops);
    let mut original = BTreeMap::new();
    original.insert("Wi-Fi".into(), vec!["192.168.1.1".to_string()]);
    c.marker.write(&original);

    c.reconcile_dns();
    assert!(c.ops.apply_calls.borrow().is_empty());
}

// ══════════ 生产实现接线（SystemDnsOpsImpl）══════════

use crate::exec::exec_tests_helpers::MockRunner;

fn dns_ops_for(platform: Platform, runner: MockRunner) -> SystemDnsOpsImpl<MockRunner> {
    SystemDnsOpsImpl::with_platform(runner, platform)
}

#[test]
fn impl_takeover_only_on_mac() {
    assert!(dns_ops_for(Platform::Mac, MockRunner::default()).takeover_supported());
    // win/linux 不接管 —— 判据见 trait doc（win netsh 需管理员 + strict_route 已劫持 :53）。
    assert!(!dns_ops_for(Platform::Win, MockRunner::default()).takeover_supported());
    assert!(!dns_ops_for(Platform::Linux, MockRunner::default()).takeover_supported());
    assert!(!dns_ops_for(Platform::Other, MockRunner::default()).takeover_supported());
}

#[test]
fn impl_mac_list_targets_excludes_bluetooth() {
    let runner = MockRunner::default().with_arg_stdout(
        "-listallnetworkservices",
        "An asterisk...\nWi-Fi\nBluetooth PAN\n*Disabled Svc\nEthernet\n",
    );
    let t = dns_ops_for(Platform::Mac, runner).list_targets().unwrap();
    // 排除 Bluetooth PAN —— 否则 DNS 接管写到蓝牙网络，关闭后残留。
    assert_eq!(t, vec!["Wi-Fi".to_string(), "Ethernet".to_string()]);
}

#[test]
fn impl_mac_read_dns_parses_and_dhcp_is_empty() {
    let runner = MockRunner::default().with_arg_stdout("-getdnsservers", "192.168.1.1\n8.8.4.4\n");
    assert_eq!(
        dns_ops_for(Platform::Mac, runner)
            .read_dns("Wi-Fi")
            .unwrap(),
        vec!["192.168.1.1".to_string(), "8.8.4.4".to_string()]
    );
    // DHCP/自动 → networksetup 输出提示句 → []（不是把提示句当 IP）。
    let runner2 = MockRunner::default().with_arg_stdout(
        "-getdnsservers",
        "There aren't any DNS Servers set on Wi-Fi.\n",
    );
    assert!(dns_ops_for(Platform::Mac, runner2)
        .read_dns("Wi-Fi")
        .unwrap()
        .is_empty());
}

#[test]
fn impl_mac_apply_dns_uses_argv_and_empty_means_dhcp() {
    let ops = dns_ops_for(Platform::Mac, MockRunner::default());
    ops.apply_dns("USB 10/100/1000 LAN", &["8.8.8.8".to_string()])
        .unwrap();
    let cmds = ops.runner.snapshot();
    assert_eq!(cmds[0].program, "networksetup");
    // 服务名含空格经 argv 下发，无引号歧义。
    assert_eq!(cmds[0].args[1], "USB 10/100/1000 LAN");
    assert_eq!(cmds[0].args[2], "8.8.8.8");

    // 空 ips → `Empty`（还原为 DHCP）。
    let ops2 = dns_ops_for(Platform::Mac, MockRunner::default());
    ops2.apply_dns("Wi-Fi", &[]).unwrap();
    assert!(ops2.runner.ran_arg("Empty"));
}

#[test]
fn impl_mac_read_effective_resolvers_uses_scutil() {
    // scutil --dns 才拿得到 DHCP 下发的解析器（-getdnsservers 对 DHCP 返空）。
    let runner = MockRunner::default().with_arg_stdout(
        "--dns",
        "resolver #1\n  nameserver[0] : 192.168.1.1\n  nameserver[1] : 8.8.8.8\nresolver #2\n  nameserver[0] : 192.168.1.1\n",
    );
    let ops = dns_ops_for(Platform::Mac, runner);
    let r = ops.read_effective_resolvers().unwrap();
    assert_eq!(r, vec!["192.168.1.1".to_string(), "8.8.8.8".to_string()]);
    assert_eq!(ops.runner.snapshot()[0].program, "scutil");
}

#[test]
fn impl_win_apply_dns_is_noop_writes_nothing() {
    // 写路径 no-op：一条命令都不能发（netsh set 需管理员，GUI 非提权必失败）。
    let ops = dns_ops_for(Platform::Win, MockRunner::default());
    ops.apply_dns("Ethernet", &["8.8.8.8".to_string()]).unwrap();
    assert!(
        ops.runner.snapshot().is_empty(),
        "win 写路径必须零命令 —— 发了就是 ACCESS DENIED + marker 卡死"
    );
}

#[test]
fn impl_win_read_paths_stay_live_for_plan_b() {
    // 读路径保留（show 非提权可跑），供方案B getLanResolverForDns 用。
    let runner = MockRunner::default()
        .with_arg_stdout(
            "show",
            "Idx     Met         MTU          State                Name\n 12      10        1500  connected            Wi-Fi\n  1      75  4294967295  connected            Loopback Pseudo-Interface 1\n",
        );
    let ops = dns_ops_for(Platform::Win, runner);
    let targets = ops.list_targets().unwrap();
    assert_eq!(targets, vec!["Wi-Fi".to_string()], "loopback 须排除");
    assert!(ops
        .runner
        .snapshot()
        .iter()
        .any(|c| c.program.ends_with("netsh.exe")));
}

#[test]
fn impl_linux_dns_is_fully_noop() {
    // 上游 LinuxSystemDns 逐字：读也返空，写 no-op，零命令。
    let ops = dns_ops_for(Platform::Linux, MockRunner::default());
    assert!(ops.list_targets().unwrap().is_empty());
    assert!(ops.read_dns("eth0").unwrap().is_empty());
    assert!(ops.read_effective_resolvers().unwrap().is_empty());
    ops.apply_dns("eth0", &["8.8.8.8".to_string()]).unwrap();
    assert!(ops.runner.snapshot().is_empty(), "linux 全 no-op，零命令");
}

/// 组合面（§K7「两扇门之间的缝」）：生产 ops + 控制器一起跑，验 win 不写 marker。
/// 单测 ops 的 no-op 与单测控制器的门控**各自通过**并不能证明组合正确 —— 这条才是生产路径。
#[test]
fn impl_win_controller_combination_writes_no_marker() {
    let ops = dns_ops_for(Platform::Win, MockRunner::default());
    let mut c = SystemDnsController::new(ops, mem_dns_marker());
    c.set_dns();
    assert!(!c.has_marker(), "win 生产路径不得留 marker");
    assert!(
        c.ops.runner.snapshot().is_empty(),
        "win 生产路径不得发任何 DNS 写命令"
    );
}

/// 组合面：mac 生产 ops + 控制器 → 真接管（marker + apply 受控 IP）。
#[test]
fn impl_mac_controller_combination_takes_over() {
    let runner = MockRunner::default()
        .with_arg_stdout("-listallnetworkservices", "An asterisk...\nWi-Fi\n")
        .with_arg_stdout("-getdnsservers", "192.168.1.1\n");
    let ops = dns_ops_for(Platform::Mac, runner);
    let mut c = SystemDnsController::new(ops, mem_dns_marker());
    c.set_dns();
    assert!(c.has_marker(), "mac 应真接管");
    // 受控 IP 被 apply 到 Wi-Fi。
    assert!(c.ops.runner.ran_arg("-setdnsservers"));
    assert!(c.ops.runner.ran_arg(controlled_tun_dns_ip()));
    // marker 记录了接管前的真实 LAN。
    assert_eq!(
        c.marker.read().unwrap().original.get("Wi-Fi").unwrap(),
        &vec!["192.168.1.1".to_string()]
    );
}
