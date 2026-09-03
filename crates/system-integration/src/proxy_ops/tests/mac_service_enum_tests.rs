//! mac「该接管哪些网络服务」的口径门。
//!
//! 缺陷来历（2026-08-08，p101 只读取证）：旧口径按**名字**过滤（跳 `*` 停用 + 跳含 Bluetooth 的），
//! 于是 7 个网络服务全被接管改写成 `8.8.8.8` —— 其中 `Tailscale` 与 `Shadowrocket` 是**别家 VPN**
//! 由 NetworkExtension 提供的服务。我们不但覆盖了它们的解析器，还把还原责任揽到自己的 marker 上。
//! 系统代理侧同型（两处此前共用同一个按名字过滤的解析器）。
//!
//! 夹具是那台机器 `-listnetworkserviceorder` 的**真实输出**，不是手搓的理想形状。

use super::super::*;
use crate::error::SystemIntegrationError;
use crate::exec::exec_tests_helpers::MockRunner;
use crate::exec::CommandRunner;
use crate::proxy::SystemProxyStatus;
use crate::test_support::{crate_source, expect_marker, literal_face, module_source};
use std::time::Duration;

/// p101 实测输出（2026-08-08）。五个物理服务带 `en*`/`bridge0`，两个 VPN 服务 **Device 为空**。
const ORDER_REAL: &str = "An asterisk (*) denotes that a network service is disabled.\n\
(1) USB 10/100/1G/2.5G LAN\n\
(Hardware Port: USB 10/100/1G/2.5G LAN, Device: en7)\n\
\n\
(2) F50 Pro\n\
(Hardware Port: F50 Pro, Device: en9)\n\
\n\
(3) USB 10/100/1000 LAN\n\
(Hardware Port: USB 10/100/1000 LAN, Device: en11)\n\
\n\
(4) Thunderbolt Bridge\n\
(Hardware Port: Thunderbolt Bridge, Device: bridge0)\n\
\n\
(5) Wi-Fi\n\
(Hardware Port: Wi-Fi, Device: en0)\n\
\n\
(6) Shadowrocket\n\
(Hardware Port: com.liguangming.Shadowrocket, Device: )\n\
\n\
(7) Tailscale\n\
(Hardware Port: io.tailscale.ipn.macsys, Device: )\n";

fn enumerate(runner: &MockRunner) -> Vec<String> {
    mac_list_manageable_services(|c| {
        runner
            .run(c, Duration::from_secs(5))
            .map_err(SystemIntegrationError::proxy)
    })
    .expect("枚举不应失败")
}

#[test]
fn real_output_drops_vpn_services_and_keeps_every_physical_one() {
    let runner = MockRunner::default().with_arg_stdout("-listnetworkserviceorder", ORDER_REAL);
    let got = enumerate(&runner);

    // 正向：五个物理服务一个不少。漏掉任何一个 = 该网卡 DNS 不被接管 = 泄漏，比误接管严重。
    assert_eq!(
        got,
        vec![
            "USB 10/100/1G/2.5G LAN",
            "F50 Pro",
            "USB 10/100/1000 LAN",
            "Thunderbolt Bridge",
            "Wi-Fi",
        ],
        "物理服务必须全部保留且保持顺序"
    );
    // 反向：两个 VPN 服务一个不进。
    assert!(!got.iter().any(|s| s == "Tailscale"), "不得接管 Tailscale");
    assert!(
        !got.iter().any(|s| s == "Shadowrocket"),
        "不得接管 Shadowrocket"
    );
}

#[test]
fn never_falls_back_when_service_order_parses() {
    // 负向对照：否则「结果看着对」也可能是因为一直在跑旧口径。
    let runner = MockRunner::default().with_arg_stdout("-listnetworkserviceorder", ORDER_REAL);
    let _ = enumerate(&runner);
    assert!(
        !runner.ran_arg("-listallnetworkservices"),
        "顺序命令解析成功时不得再跑 -listallnetworkservices"
    );
}

#[test]
fn disabled_and_bluetooth_services_excluded() {
    let order = "An asterisk (*) denotes that a network service is disabled.\n\
(1) Wi-Fi\n\
(Hardware Port: Wi-Fi, Device: en0)\n\
\n\
(2) *Ethernet\n\
(Hardware Port: Ethernet, Device: en4)\n\
\n\
(3) Bluetooth PAN\n\
(Hardware Port: Bluetooth PAN, Device: en5)\n";
    let runner = MockRunner::default().with_arg_stdout("-listnetworkserviceorder", order);
    assert_eq!(enumerate(&runner), vec!["Wi-Fi"]);
}

#[test]
fn falls_back_to_legacy_enumeration_when_nothing_has_a_device() {
    // 防「未来 macOS 改输出形态 ⇒ 过滤后全空 ⇒ 一个服务都不接管 ⇒ 全量泄漏」。
    let runner = MockRunner::default()
        .with_arg_stdout("-listnetworkserviceorder", "totally unexpected output\n")
        .with_arg_stdout(
            "-listallnetworkservices",
            "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Ethernet\n",
        );
    let got = enumerate(&runner);
    assert_eq!(got, vec!["Wi-Fi"], "回落后应拿到旧口径结果");
    assert!(
        runner.ran_arg("-listallnetworkservices"),
        "回落必须真的去跑旧命令"
    );
}

#[test]
fn dns_takeover_and_system_proxy_share_one_enumeration() {
    // 这两处此前共用的是**按名字过滤**的解析器，于是同一个缺陷有两个面。
    // 判据落在「调用了哪个函数」，而不是「文件里出现过某个词」—— 后者会被注释骗过去（本仓踩过）。
    //
    // 🔴 取材必须排除测试区：本断言的字面量自己就住在被扫的模块里，
    // 不排的话把生产调用点整个删掉、断言字符串留下，这条照样绿 —— 实测如此（M2 变异第一次没红）。
    //
    // 取材锚在**模块**上（`module_source` = 模块根 `<模块>.rs` + `<模块>/**` 递归，
    // 且天然排除 `tests/`），取代此前手写的
    // `read_to_string(CARGO_MANIFEST_DIR/src/<文件>.rs)` + 「截到首个 `\n#[cfg(test)]`」：
    // ① 手写形态只认**一个根文件**。生产码一旦拆进 `proxy_ops/*.rs`，取材面就塌掉一半，
    //    下面那条否定断言在缺失的那一半上**恒真** —— 绿得不出声。实测：把
    //    `crate::macos_proxy::list_service_names()` 写进 `proxy_ops/macos_cli.rs`，旧形态放行、本形态转红。
    // ② 「截到首个 `\n#[cfg(test)]`」是手搓语义，只认列 0 的字面量：撞上模块中段的
    //    `#[cfg(test)] use ...` 会把其后的生产码整段误切，判据射程随之无声缩短。
    //
    // `expect_marker` 守的是 `module_source` 自己看不出的那种塌陷：目录非空、但读到的**不是这个模块**
    // （锚点解析错 / 模块被改名搬走）。那时 blob 非空、断言照跑，否定型断言同样恒真。
    //
    // 取材再过 `literal_face`（**只剥注释**，字符串字面量原样保留）：下面那条**正面**
    // `contains` 的针是单行代码文本，写进任何一行 `//` 注释就够替生产调用点作证 —— 与
    // `mac_leg_exclusivity_gate.rs` 同口径。不用 `code_face`：本门另有针落在字符串面上时
    // 会被一并抹掉（那边已为此付过一次账）。
    let module_src = |module: &str, marker: &str| -> String {
        literal_face(&expect_marker(module_source(module), module, marker))
    };
    let dns_src = module_src("dns_ops", "pub trait SystemDnsOps");
    let proxy_src = module_src("proxy_ops", "pub trait SystemProxyOps");

    for (module, what, src) in [
        ("dns_ops", "DNS 接管", &dns_src),
        ("proxy_ops", "系统代理", &proxy_src),
    ] {
        assert!(
            src.contains("mac_list_manageable_services(|c| self.run(c))"),
            "{what}（模块 {module}）没有走统一口径函数"
        );
    }

    // 正向对照：否定断言的针里嵌着**对面那条腿的模块名**（`macos_proxy`）。那个文件被改名/删除
    // 的那天，针从此指不到任何东西 —— 断言恒真，而 `proxy_ops` 侧的取材面看不出对面出了事
    // （它扫的是另一半）。故对针的这一半单独取材：文件不在了 `crate_source` 当场 panic；
    // 还在，就必须仍是那条原生 SC 腿（不是被换成了第二套 networksetup 实现）。
    expect_marker(
        crate_source("macos_proxy.rs"),
        "macos_proxy.rs",
        "SCPreferencesCreate",
    );

    assert!(
        !proxy_src.contains("macos_proxy::list_service_names"),
        "生产 macOS System 路径不得绕过 networksetup 可管理服务口径"
    );
}

// ── bypass 清单的捕获与还原（2026-08-09）──────────────────────────────────

/// `-getproxybypassdomains` 的两种输出形态必须可分辨：真条目 vs 「一条都没有」的英文提示句。
#[test]
fn mac_bypass_parse_separates_entries_from_the_empty_notice() {
    // 有条目：每行一个，含域名 / 通配 / CIDR 三种形态。
    let listed = "intranet.corp.com\n*.local\n192.168.0.0/16\n";
    assert_eq!(
        parse_mac_bypass_domains(listed),
        vec!["intranet.corp.com", "*.local", "192.168.0.0/16"]
    );

    // 空清单：networksetup 回一句英文提示 —— **绝不能**被当成一个条目写回去。
    let empty = "There aren't any bypass domains set on Wi-Fi.\n";
    assert!(
        parse_mac_bypass_domains(empty).is_empty(),
        "提示句被当成 bypass 条目了"
    );
    // 提示文案随系统版本变，判据不能锚在英文原文上 —— 换一句同样得判空。
    assert!(parse_mac_bypass_domains("No bypass domains configured\n").is_empty());

    assert!(parse_mac_bypass_domains("").is_empty());
}

/// restore 必须把 bypass 写回原值；**没捕获过**（None）时一个字都不能碰。
#[test]
fn mac_restore_writes_bypass_back_only_when_captured() {
    let base = SystemProxyStatus {
        enabled: true,
        http_proxy: Some("h:80".into()),
        https_proxy: None,
        socks_proxy: None,
        bypass_domains: None,
    };

    // ① 没捕获过 → 不得出现任何 bypass 写命令（读失败折成「清空」比不还原更糟）。
    let cmds = mac_service_restore_commands("Wi-Fi", &base);
    assert!(
        !cmds
            .iter()
            .any(|c| c.args.iter().any(|a| a == "-setproxybypassdomains")),
        "没捕获到原值却去写 bypass —— 会把用户的清单清掉"
    );

    // ② 捕获到条目 → 原样写回（顺序保持）。
    let with = SystemProxyStatus {
        bypass_domains: Some(vec!["intranet.corp.com".into(), "*.local".into()]),
        ..base.clone()
    };
    let cmds = mac_service_restore_commands("Wi-Fi", &with);
    let bypass = cmds
        .iter()
        .find(|c| c.args.first().map(String::as_str) == Some("-setproxybypassdomains"))
        .expect("捕获到了却没写回");
    assert_eq!(
        bypass.args,
        vec![
            "-setproxybypassdomains",
            "Wi-Fi",
            "intranet.corp.com",
            "*.local"
        ]
    );

    // ③ 捕获到空 → 必须写 Empty 哨兵（什么都不传会被 networksetup 判参数不足）。
    let empty = SystemProxyStatus {
        bypass_domains: Some(vec![]),
        ..base
    };
    let cmds = mac_service_restore_commands("Wi-Fi", &empty);
    let bypass = cmds
        .iter()
        .find(|c| c.args.first().map(String::as_str) == Some("-setproxybypassdomains"))
        .expect("捕获到空清单也要写回（清空）");
    assert_eq!(
        bypass.args,
        vec!["-setproxybypassdomains", "Wi-Fi", "Empty"]
    );
}

#[test]
fn mac_enable_writes_empty_bypass_sentinel_after_formatting() {
    let request = |bypass_list: Vec<String>| ProxyEnableRequest {
        address: "127.0.0.1".into(),
        http_port: 7890,
        socks_port: 7890,
        bypass_list,
    };
    let enable_bypass_args = |request: &ProxyEnableRequest| {
        mac_service_enable_commands("Wi-Fi", request)
            .into_iter()
            .find(|command| {
                command.args.first().map(String::as_str) == Some("-setproxybypassdomains")
            })
            .expect("enable 必须下发 bypass 命令")
            .args
    };
    let restore_bypass_args = |domains: Vec<String>| {
        let status = SystemProxyStatus {
            bypass_domains: Some(domains),
            ..Default::default()
        };
        mac_service_restore_commands("Wi-Fi", &status)
            .into_iter()
            .find(|command| {
                command.args.first().map(String::as_str) == Some("-setproxybypassdomains")
            })
            .expect("restore 必须下发 bypass 命令")
            .args
    };

    assert_eq!(
        enable_bypass_args(&request(vec![])),
        vec!["-setproxybypassdomains", "Wi-Fi", "Empty"]
    );
    assert_eq!(
        enable_bypass_args(&request(vec!["  ".into(), "\t".into()])),
        vec!["-setproxybypassdomains", "Wi-Fi", "Empty"]
    );
    assert_eq!(
        enable_bypass_args(&request(vec![])),
        restore_bypass_args(vec![]),
        "enable 与 restore 必须共享同一 bypass 命令结果"
    );
    assert_eq!(
        enable_bypass_args(&request(vec![" intranet.corp ".into(), "*.local".into()])),
        vec![
            "-setproxybypassdomains",
            "Wi-Fi",
            "intranet.corp",
            "*.local"
        ]
    );
}

/// enable 写了 bypass、restore 就必须能写回 —— 两侧的子命令必须成对存在。
///
/// 这条守的是「只写不撤」这个**形状**本身，比逐条断言参数更难被绕过：
/// 谁把 restore 那条删掉，或者给 enable 加一条新的「只写不撤」的 set 子命令，都会红。
#[test]
fn every_mac_set_subcommand_has_a_restore_counterpart() {
    let req = ProxyEnableRequest {
        address: "127.0.0.1".into(),
        http_port: 7890,
        socks_port: 7890,
        bypass_list: vec!["10.0.0.0/8".into()],
    };
    let enable = mac_service_enable_commands("Wi-Fi", &req);
    let captured = SystemProxyStatus {
        enabled: true,
        http_proxy: Some("h:80".into()),
        https_proxy: Some("h:80".into()),
        socks_proxy: Some("h:80".into()),
        bypass_domains: Some(vec!["x.corp".into()]),
    };
    let restore = mac_service_restore_commands("Wi-Fi", &captured);

    let subs = |cmds: &[Command]| -> std::collections::BTreeSet<String> {
        cmds.iter()
            .filter_map(|c| c.args.first().cloned())
            .filter(|a| a.starts_with("-set"))
            .map(|a| a.trim_end_matches("state").to_owned())
            .collect()
    };
    let enabled_subs = subs(&enable);
    let restore_subs = subs(&restore);
    assert!(!enabled_subs.is_empty(), "enable 一条 set 都没有？判据失效");
    for sub in &enabled_subs {
        assert!(
            restore_subs.contains(sub),
            "enable 下发了 `{sub}` 却没有对应的还原 —— 这正是 bypass 当初漏掉的形状\n\
             enable={enabled_subs:?}\nrestore={restore_subs:?}"
        );
    }
}
