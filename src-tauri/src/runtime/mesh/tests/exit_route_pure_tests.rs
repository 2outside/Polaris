//! C5 出口路由 op 纯逻辑门（argv 构造 / ifconfig 解析 / tailnet 反查）——真 OS 手术是 mac/Linux 真机门，
//! 但 argv 与解析是纯字符串→数据，可离线单测 + 变异（防真机门代码悄悄写错却无人守）。
use super::super::*;

/// Linux add：先 `rule add`，再逐 cidr `route replace`（独立表 7732）。
/// 变异：把 add 写成先 route 后 rule、或表号写错、或 replace 写成 add → 断言序列不符 → 转红。
#[test]
fn linux_route_argv_add_sequence() {
    let cmds = linux_route_argv(
        "add",
        "polaris-ts",
        &["0.0.0.0/0".to_string(), "::/0".to_string()],
    );
    assert_eq!(cmds.len(), 3, "rule add + 2 条 route replace");
    assert_eq!(
        cmds[0],
        vec![
            "rule",
            "add",
            "oif",
            "polaris-ts",
            "table",
            "7732",
            "priority",
            "7732"
        ]
    );
    assert_eq!(
        cmds[1],
        vec![
            "route",
            "replace",
            "0.0.0.0/0",
            "dev",
            "polaris-ts",
            "table",
            "7732"
        ]
    );
    assert_eq!(
        cmds[2],
        vec![
            "route",
            "replace",
            "::/0",
            "dev",
            "polaris-ts",
            "table",
            "7732"
        ]
    );
}

/// Linux del：先逐 cidr `route del`，最后 `rule del`（与 add 逆序，避免规则先删致路由删不掉）。
/// 变异：把 del 顺序写反（先 rule del）→ 断言 cmds.last() != rule del → 转红。
#[test]
fn linux_route_argv_del_sequence() {
    let cmds = linux_route_argv("del", "polaris-ts", &["0.0.0.0/0".to_string()]);
    assert_eq!(cmds.len(), 2, "1 条 route del + rule del");
    assert_eq!(
        cmds[0],
        vec![
            "route",
            "del",
            "0.0.0.0/0",
            "dev",
            "polaris-ts",
            "table",
            "7732"
        ]
    );
    assert_eq!(
        cmds[1],
        vec![
            "rule",
            "del",
            "oif",
            "polaris-ts",
            "table",
            "7732",
            "priority",
            "7732"
        ]
    );
}

// ── Linux 出口路由腿的**返回值诚实性**（此前无条件 true = 假成功）────────────────────────
//
// 缺陷形态：`run_ip_command` 吞掉全部错误（`ip` 缺失 / 无 CAP_NET_ADMIN / 内核无策略路由），
// 而 Linux 分支无条件返 true ⇒ 状态机把「一条都没装上」标成 `installed` ⇒ ① 用户以为 System
// 出口生效、实则公网 unreachable；② clear 时对不存在的路由发 del。下面四条穷举返回值逃逸面。

/// 假 runner 记录的「真正被执行」的命令序列（失败后是否短路的唯一观测量）。
type RanCommands = Arc<Mutex<Vec<Vec<String>>>>;

/// 假 runner：按脚本返回成功/失败，并记录**真正被执行**的命令序列（验证失败后是否短路）。
fn scripted_runner(
    script: Vec<bool>,
) -> (
    impl Fn(Vec<String>) -> std::future::Ready<bool>,
    RanCommands,
) {
    let calls: Arc<Mutex<Vec<Vec<String>>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&calls);
    let script = Arc::new(Mutex::new(script.into_iter().collect::<Vec<_>>()));
    let run = move |argv: Vec<String>| {
        let idx = {
            let mut g = sink.lock().unwrap();
            g.push(argv);
            g.len() - 1
        };
        let ok = script.lock().unwrap().get(idx).copied().unwrap_or(true);
        std::future::ready(ok)
    };
    (run, calls)
}

/// add 腿的**门**在首条 `ip rule add`：它失败 ⇒ 返 false（不标 installed）且**不再跑**后续 route。
/// 变异：删掉 `return false` → 返 true 转红；删掉短路（continue 而非 return）→ 执行数 3 转红；
/// 把门索引从 0 改成别的 → 首条失败被放行 → 返回值转红。
#[tokio::test]
async fn linux_add_returns_false_and_short_circuits_when_rule_add_fails() {
    let cmds = linux_route_argv("add", "polaris-ts", &["0.0.0.0/0".into(), "::/0".into()]);
    let (run, calls) = scripted_runner(vec![false]); // 首条 rule add 失败
    let ok = run_linux_route_seq("add", cmds, run).await;
    assert!(
        !ok,
        "rule add 失败仍返 true = 把「一条都没装上」记成 installed"
    );
    assert_eq!(
        calls.lock().unwrap().len(),
        1,
        "规则没装上 ⇒ 表 7732 永不被查中 ⇒ 后续 route replace 是白跑，必须短路"
    );
}

/// `rule add` 成功但**单条 cidr** 失败 ⇒ 仍返 true：已装的那部分必须被标 installed，
/// 否则 clear 收不回去 = 泄漏（典型：关掉 IPv6 的机器上 `::/0` replace 失败）。
/// 变异：把门改成「全部命令都成功才 true」→ 本测转红。
#[tokio::test]
async fn linux_add_tolerates_single_cidr_failure_after_rule_installed() {
    let cmds = linux_route_argv("add", "polaris-ts", &["0.0.0.0/0".into(), "::/0".into()]);
    let (run, calls) = scripted_runner(vec![true, true, false]); // v6 那条失败
    let ok = run_linux_route_seq("add", cmds, run).await;
    assert!(
        ok,
        "规则已装 + v4 路由已装 ⇒ 必须标 installed，否则 clear 收不回已装部分"
    );
    assert_eq!(
        calls.lock().unwrap().len(),
        3,
        "rule 成功后逐条跑完，不短路"
    );
}

/// 全成功 → true（正向自证：门不是恒 false）。
#[tokio::test]
async fn linux_add_returns_true_when_all_succeed() {
    let cmds = linux_route_argv("add", "polaris-ts", &["0.0.0.0/0".into()]);
    let (run, _) = scripted_runner(vec![true, true]);
    assert!(run_linux_route_seq("add", cmds, run).await);
}

/// del 腿全程 best-effort：即便**每条**都失败也返 true（clear 是幂等收尾，installed 已被 take）。
/// 变异：把 del 也纳入门（首条失败即 false）→ 本测转红。
#[tokio::test]
async fn linux_del_stays_best_effort_true_even_when_every_command_fails() {
    let cmds = linux_route_argv("del", "polaris-ts", &["0.0.0.0/0".into()]);
    let (run, calls) = scripted_runner(vec![false, false]);
    assert!(run_linux_route_seq("del", cmds, run).await);
    assert_eq!(calls.lock().unwrap().len(), 2, "del 腿逐条跑完，不短路");
}

/// 门的**前置不变式**：add 腿首条必须是 `rule add`（索引 0 的门才有意义）。
/// 变异：把 [`linux_route_argv`] 的 add 顺序改成先 route 后 rule → 本测转红
/// （而不是让门静默守错命令）。
#[test]
fn linux_add_argv_starts_with_rule_add() {
    let cmds = linux_route_argv("add", "polaris-ts", &["0.0.0.0/0".into()]);
    assert_eq!(&cmds[0][..2], &["rule".to_string(), "add".to_string()]);
}

/// `ifconfig -l` → 仅 utun\d+ 名（滤掉 lo0/en0/非数字后缀 utunX）。
#[test]
fn parse_utun_list_filters_utun_only() {
    let s = "lo0 gif0 stf0 en0 utun0 utun4 utunfoo utun12 bridge0";
    let got = parse_utun_list(s);
    let mut v: Vec<_> = got.into_iter().collect();
    v.sort();
    assert_eq!(v, vec!["utun0", "utun12", "utun4"]);
}

/// 全量 ifconfig → 每 utun 的 v4 地址（忽略 inet6、缩进明细归属当前接口头）。
#[test]
fn parse_ifconfig_ifaces_groups_v4_by_utun() {
    let s = "\
en0: flags=8863<UP> mtu 1500
\tinet 192.168.1.10 netmask 0xffffff00
utun4: flags=8051<UP> mtu 1400
\tinet6 fe80::1 prefixlen 64
\tinet 100.64.0.7 --> 100.64.0.7 netmask 0xffffffff
utun5: flags=8051<UP> mtu 1280
\tinet 10.0.0.2 --> 10.0.0.2 netmask 0xffffffff
";
    let got = parse_ifconfig_ifaces(s);
    // en0 非 utun → 不入。
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].0, "utun4");
    assert_eq!(got[0].1, vec!["100.64.0.7"]); // inet6 被忽略
    assert_eq!(got[1].0, "utun5");
    assert_eq!(got[1].1, vec!["10.0.0.2"]);
}

/// tailnet 100.64.0.0/10 边界（100.64–100.127 命中；100.63/100.128/非 100 不命中）。
/// 变异：把范围写成 (64..=126) 或 0..=127 → 边界 case 转红。
#[test]
fn is_tailnet_addr_boundaries() {
    assert!(is_tailnet_addr("100.64.0.1"));
    assert!(is_tailnet_addr("100.127.255.255"));
    assert!(!is_tailnet_addr("100.63.0.1"));
    assert!(!is_tailnet_addr("100.128.0.1"));
    assert!(!is_tailnet_addr("192.168.1.1"));
    assert!(!is_tailnet_addr("10.64.0.1"));
}

/// 反查优先「起核后新增（不在 baseline）且带 tailnet 地址」的 utun。
/// 变异：删掉 baseline 过滤（filter）→ 会错命中 baseline 里的 Tailscale.app utun（utun3）→ 转红。
#[test]
fn pick_tailnet_iface_prefers_new_utun_over_baseline() {
    // utun3 = 起核前已存在的 Tailscale.app 接口（在 baseline，也带 tailnet 地址）；
    // utun7 = 起核后 sing-box 新建的 TS 接口（不在 baseline）。应挑 utun7。
    let ifaces = vec![
        ("utun3".to_string(), vec!["100.100.0.1".to_string()]),
        ("utun7".to_string(), vec!["100.64.0.9".to_string()]),
    ];
    let mut baseline = HashSet::new();
    baseline.insert("utun3".to_string());
    assert_eq!(
        pick_tailnet_iface(&ifaces, Some(&baseline)).as_deref(),
        Some("utun7"),
        "须优先起核后新增的 utun（时序 diff），不误命中 baseline 里的 Tailscale.app utun"
    );
}

/// 无 baseline → 退化为纯地址反推（Polaris 兜底）：取第一张带 tailnet 地址的 utun。
#[test]
fn pick_tailnet_iface_falls_back_to_address_when_no_baseline() {
    let ifaces = vec![
        ("utun5".to_string(), vec!["10.0.0.2".to_string()]),
        ("utun6".to_string(), vec!["100.96.1.2".to_string()]),
    ];
    assert_eq!(pick_tailnet_iface(&ifaces, None).as_deref(), Some("utun6"));
    // 无任何 tailnet 地址 → None。
    let none = vec![("utun5".to_string(), vec!["10.0.0.2".to_string()])];
    assert_eq!(pick_tailnet_iface(&none, None), None);
}
