//! 活态查询（「OS 代理是否仍指向本进程 mixed 入站」）三平台解析 + 判定。
//!
//! 全部经 [`ArgvMockRunner`] 注入命令输出 —— **不触碰宿主系统代理**（本机绝不真跑
//! `networksetup`/`gsettings`/`reg`，更不改任何系统设置）。`with_platform` 让 Linux CI
//! 同时跑通 mac/win 两套解析（本 crate 零 `#[cfg(target_os)]` 的既有纪律）。

use super::super::*;
use crate::error::SystemIntegrationError;
use crate::exec::{CommandOutput, CommandRunner};
use crate::proxy::SystemProxyStatus;
use polaris_helper_proto::Platform;
use std::cell::RefCell;

/// 按「argv 必须**同时**含全部指定项（**逐字相等**，非子串）」匹配 stdout 的 mock。
///
/// 为什么不复用共享的 `exec_tests_helpers::MockRunner`（它按单个**子串**匹配）：
/// 1. Linux gsettings 的读取键是 (schema, key) 二元组，单个子串区分不了「读 mode」与「读 http.host」；
/// 2. **子串匹配在此处会串台成假绿**（实测踩到）——`org.gnome.system.proxy` 是
///    `org.gnome.system.proxy.http` 的前缀，后者又是 `...proxy.https` 的前缀，https 的读取会拿到
///    http 的桩输出。逐字相等把这两层前缀陷阱一并堵死。
#[derive(Default)]
struct ArgvMockRunner {
    rules: Vec<(Vec<&'static str>, String)>,
    fails: Vec<Vec<&'static str>>,
    calls: RefCell<Vec<Command>>,
}

impl ArgvMockRunner {
    fn on(mut self, needles: &[&'static str], stdout: impl Into<String>) -> Self {
        self.rules.push((needles.to_vec(), stdout.into()));
        self
    }
    /// argv 同时含这些项的调用直接失败（模拟 schema 不存在 / 命令缺失 / 无权限）。
    fn failing(mut self, needles: &[&'static str]) -> Self {
        self.fails.push(needles.to_vec());
        self
    }
    /// 是否跑过 argv 含该**逐字**参数的命令（同上：子串会让 `.http` 命中 `.https` 的调用）。
    fn ran_arg(&self, needle: &str) -> bool {
        self.calls
            .borrow()
            .iter()
            .any(|c| c.args.iter().any(|a| a == needle))
    }
}

impl CommandRunner for ArgvMockRunner {
    fn run(&self, cmd: &Command, _t: Duration) -> Result<CommandOutput, String> {
        self.calls.borrow_mut().push(cmd.clone());
        let hit = |ns: &[&str]| ns.iter().all(|n| cmd.args.iter().any(|a| a == n));
        if self.fails.iter().any(|ns| hit(ns)) {
            return Err("mock failure".into());
        }
        for (ns, out) in &self.rules {
            if hit(ns) {
                return Ok(CommandOutput {
                    stdout: out.clone(),
                    stderr: String::new(),
                });
            }
        }
        Ok(CommandOutput::default())
    }
}

/// 本进程 mixed 入站（全部用例的比对基准）。
const OUR_ADDR: &str = "127.0.0.1";
const OUR_PORT: u16 = 7890;

fn live(
    runner: ArgvMockRunner,
    platform: Platform,
) -> (
    Result<SystemProxyLiveStatus, SystemIntegrationError>,
    SystemProxyOpsImpl<ArgvMockRunner>,
) {
    let ops = SystemProxyOpsImpl::with_platform(runner, platform);
    let r = ops.live_status(OUR_ADDR, OUR_PORT);
    (r, ops)
}

// ── 纯判定 `points_to_mixed_inbound`（三平台共用的唯一判据）─────────────────────────

#[test]
fn points_to_mixed_inbound_requires_enabled_exact_hostport_and_no_foreign_leg() {
    let ours = |legs: [Option<&str>; 3], enabled: bool| SystemProxyStatus {
        enabled,
        http_proxy: legs[0].map(str::to_string),
        https_proxy: legs[1].map(str::to_string),
        socks_proxy: legs[2].map(str::to_string),
        bypass_domains: None,
    };
    let ok = "127.0.0.1:7890";

    // 三腿全指向我们 → 生效。
    assert!(points_to_mixed_inbound(
        &ours([Some(ok), Some(ok), Some(ok)], true),
        OUR_ADDR,
        OUR_PORT
    ));
    // Windows 从不设 socks= → socks 为 None 不算「指向别处」。
    assert!(points_to_mixed_inbound(
        &ours([Some(ok), Some(ok), None], true),
        OUR_ADDR,
        OUR_PORT
    ));
    // enabled=false（注册表 ProxyEnable=0 仍留 ProxyServer 值的形态）→ 未生效。
    assert!(!points_to_mixed_inbound(
        &ours([Some(ok), Some(ok), Some(ok)], false),
        OUR_ADDR,
        OUR_PORT
    ));
    // 端口不匹配 → 未生效（**别只比 host**，见函数文档第 2 条）。
    assert!(!points_to_mixed_inbound(
        &ours([Some("127.0.0.1:9999"), None, None], true),
        OUR_ADDR,
        OUR_PORT
    ));
    // 指向别的代理 → 未生效。
    assert!(!points_to_mixed_inbound(
        &ours([Some("proxy.corp:3128"), None, None], true),
        OUR_ADDR,
        OUR_PORT
    ));
    // 一腿指向我们、另一腿被改到别处 → 该协议绕开本地核 → 整体未生效。
    assert!(!points_to_mixed_inbound(
        &ours([Some(ok), Some("proxy.corp:3128"), None], true),
        OUR_ADDR,
        OUR_PORT
    ));
    // 三腿全空（enabled 但没有实际服务器）→ 无「指向我们」的证据 → 未生效。
    assert!(!points_to_mixed_inbound(
        &ours([None, None, None], true),
        OUR_ADDR,
        OUR_PORT
    ));
}

// ── macOS：networksetup -getwebproxy / -getsecurewebproxy / -getsocksfirewallproxy ──

const MAC_SERVICES: &str =
    "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\nEthernet\n";

fn mac_on(server: &str, port: u16) -> String {
    format!("Enabled: Yes\nServer: {server}\nPort: {port}\nAuthenticated Proxy Enabled: 0\n")
}
const MAC_OFF: &str = "Enabled: No\nServer: \nPort: 0\nAuthenticated Proxy Enabled: 0\n";

fn mac_runner(http: String, https: String, socks: String) -> ArgvMockRunner {
    ArgvMockRunner::default()
        .on(&["-listallnetworkservices"], MAC_SERVICES)
        .on(&["-getwebproxy"], http)
        .on(&["-getsecurewebproxy"], https)
        .on(&["-getsocksfirewallproxy"], socks)
}

#[test]
fn mac_live_status_effective_when_all_legs_point_at_mixed_inbound() {
    let (r, _) = live(
        mac_runner(
            mac_on("127.0.0.1", 7890),
            mac_on("127.0.0.1", 7890),
            mac_on("127.0.0.1", 7890),
        ),
        Platform::Mac,
    );
    let s = r.expect("读取成功");
    assert!(s.points_to_us);
    assert_eq!(s.expected, "127.0.0.1:7890");
    assert_eq!(s.status.http_proxy.as_deref(), Some("127.0.0.1:7890"));
}

#[test]
fn mac_live_status_not_effective_when_user_turned_proxy_off() {
    // 形态①「未开启」：运行期用户在「系统设置 › 网络 › 代理」里把开关关掉 —— 起核那一刻是成功的、
    // `SYSTEM_PROXY_FAILED` 干净，只有活态查询能看见。
    let (r, _) = live(
        mac_runner(MAC_OFF.into(), MAC_OFF.into(), MAC_OFF.into()),
        Platform::Mac,
    );
    let s = r.expect("读取成功");
    assert!(!s.points_to_us, "代理已关 → 未生效");
    assert!(!s.status.enabled);
}

#[test]
fn mac_live_status_not_effective_when_pointing_at_another_proxy() {
    // 形态②「指向别的代理」：开着，但指向第三方 → 我们的流量同样没走本地核。
    let (r, _) = live(
        mac_runner(
            mac_on("proxy.corp", 3128),
            mac_on("proxy.corp", 3128),
            MAC_OFF.into(),
        ),
        Platform::Mac,
    );
    let s = r.expect("读取成功");
    assert!(!s.points_to_us, "指向第三方代理 → 未生效");
    assert!(s.status.enabled, "OS 层确实开着（只是不指向我们）");
}

/// **变异锁（比对端口）**：把 [`points_to_mixed_inbound`] 里的 `*p == ours` 改成只比 host
/// （如 `p.split(':').next() == Some(address)`），本用例立刻转红 —— `127.0.0.1:9999` 会被
/// 判成「仍指向我们」，而那是另一个本地代理软件 / 用户手改端口，流量根本不到我们的 mixed 口。
#[test]
fn mac_live_status_rejects_port_mismatch() {
    let (r, _) = live(
        mac_runner(
            mac_on("127.0.0.1", 9999),
            mac_on("127.0.0.1", 9999),
            mac_on("127.0.0.1", 9999),
        ),
        Platform::Mac,
    );
    let s = r.expect("读取成功");
    assert!(
        !s.points_to_us,
        "host 对但端口不是我们的 mixed 口 → 必须判未生效"
    );
}

#[test]
fn mac_live_status_reads_only_one_service() {
    // 活态口径 = **单个**在用服务（不是全部）。扫全部服务会在「主服务代理被关、闲置服务
    // 留着指向我们的残值」时谎报「仍生效」。本例无 route 桩 → 回落 services[0] = Wi-Fi。
    let (_, ops) = live(
        mac_runner(
            mac_on("127.0.0.1", 7890),
            mac_on("127.0.0.1", 7890),
            mac_on("127.0.0.1", 7890),
        ),
        Platform::Mac,
    );
    assert!(ops.runner.ran_arg("Wi-Fi"), "须读在用服务");
    assert!(
        !ops.runner.ran_arg("Ethernet"),
        "活态查询不得扫非在用服务（那是 get_proxy_status 的残留检测口径）"
    );
}

// ── macOS primary service（默认路由 → 服务名）────────────────────────────────────

/// `-listallnetworkservices`：**雷电桥排在 Wi-Fi 前**、且都不带 `*`（未插线 ≠ 停用）。
const MAC_SERVICES_BRIDGE_FIRST: &str =
    "An asterisk (*) denotes that a network service is disabled.\nThunderbolt Bridge\nWi-Fi\n";

/// `-listnetworkserviceorder`：服务名 ↔ BSD 设备名的成对输出（真机格式）。
const MAC_SERVICE_ORDER: &str = "An asterisk (*) denotes that a network service is disabled.\n\
    \n(1) Thunderbolt Bridge\n(Hardware Port: Thunderbolt Bridge, Device: bridge0)\n\
    \n(2) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n\
    \n(3) *Old Ethernet\n(Hardware Port: Ethernet, Device: en5)\n";

fn mac_route(device: &str) -> String {
    format!(
        "   route to: default\ndestination: default\n       mask: default\n\
         gateway: 192.168.1.1\n  interface: {device}\n      flags: <UP,GATEWAY,DONE>\n"
    )
}

#[test]
fn parse_mac_service_order_pairs_names_with_devices_and_drops_disabled() {
    let got = parse_mac_service_order(MAC_SERVICE_ORDER);
    assert_eq!(
        got,
        vec![
            ("Thunderbolt Bridge".to_string(), "bridge0".to_string()),
            ("Wi-Fi".to_string(), "en0".to_string()),
        ],
        "停用服务（`(3) *Old Ethernet`）不得进映射：它不承载流量"
    );
    // 无设备名的条目（部分 VPN 服务）不得进映射，也不得让解析崩掉。
    assert!(parse_mac_service_order("(1) VPN\n(Hardware Port: VPN)\n").is_empty());
    assert!(parse_mac_service_order("").is_empty());
}

/// 默认路由行的解析复用 `route_ops` 那一份；此处只钉「`route -n get default` 的真机输出形态
/// 确实能被它吃下」（两模块共用同一解析器 → 不再有第二份会漂移的实现）。
#[test]
fn default_route_output_is_parsed_by_the_shared_route_parser() {
    assert_eq!(
        crate::route_ops::parse_mac_route_get_interface(&mac_route("en0")).as_deref(),
        Some("en0")
    );
    // 无默认路由（`route: writing to routing socket: not in table`）→ None，不是 panic。
    assert_eq!(
        crate::route_ops::parse_mac_route_get_interface(
            "   route: writing to routing socket: not in table\n"
        ),
        None
    );
}

/// **变异锁（本条 review 的核心）**：把 `read_active_proxy` 的 Mac 分支改回
/// `list_network_services()?.first()` → 本用例立刻转红。
///
/// 场景 = reviewer 给的恶性样例：雷电桥（未插线、不带 `*`）排在 `-listallnetworkservices` 首位，
/// 流量实际走 Wi-Fi；用户在 **Wi-Fi** 上手关了代理，而雷电桥上还留着我们 enable 时写的值
/// （`set_proxy` 写全部服务）。读首项 → `points_to_us=true` → **漏报**（绿灯 + 明文直连）。
#[test]
fn mac_live_status_follows_default_route_not_service_list_order() {
    let runner = ArgvMockRunner::default()
        .on(&["-listallnetworkservices"], MAC_SERVICES_BRIDGE_FIRST)
        .on(&["-listnetworkserviceorder"], MAC_SERVICE_ORDER)
        .on(&["default"], mac_route("en0"))
        // 雷电桥（首项）上留着指向我们的残值；Wi-Fi（主服务）上用户已手关。
        .on(
            &["-getwebproxy", "Thunderbolt Bridge"],
            mac_on("127.0.0.1", 7890),
        )
        .on(
            &["-getsecurewebproxy", "Thunderbolt Bridge"],
            mac_on("127.0.0.1", 7890),
        )
        .on(
            &["-getsocksfirewallproxy", "Thunderbolt Bridge"],
            mac_on("127.0.0.1", 7890),
        )
        .on(&["-getwebproxy", "Wi-Fi"], MAC_OFF)
        .on(&["-getsecurewebproxy", "Wi-Fi"], MAC_OFF)
        .on(&["-getsocksfirewallproxy", "Wi-Fi"], MAC_OFF);
    let (r, ops) = live(runner, Platform::Mac);
    let s = r.expect("读取成功");
    assert!(
        !s.points_to_us,
        "主服务（Wi-Fi，默认路由 en0）上代理已关 → 必须判未生效；读首项会漏报成「仍生效」"
    );
    assert!(ops.runner.ran_arg("Wi-Fi"), "须读默认路由所属服务");
    assert!(
        !ops.runner.ran_arg("Thunderbolt Bridge"),
        "不得去读非承载流量的服务"
    );
}

/// 反向：主服务上确实指向我们，而排在前面的闲置服务没设 —— 读首项会**误亮黄灯**。
#[test]
fn mac_live_status_effective_when_only_the_primary_service_points_at_us() {
    let runner = ArgvMockRunner::default()
        .on(&["-listallnetworkservices"], MAC_SERVICES_BRIDGE_FIRST)
        .on(&["-listnetworkserviceorder"], MAC_SERVICE_ORDER)
        .on(&["default"], mac_route("en0"))
        .on(&["-getwebproxy", "Wi-Fi"], mac_on("127.0.0.1", 7890))
        .on(&["-getsecurewebproxy", "Wi-Fi"], mac_on("127.0.0.1", 7890))
        .on(
            &["-getsocksfirewallproxy", "Wi-Fi"],
            mac_on("127.0.0.1", 7890),
        );
    let s = live(runner, Platform::Mac).0.expect("读取成功");
    assert!(
        s.points_to_us,
        "主服务指向我们 → 生效（读首项会误报未生效）"
    );
}

/// 查不到主服务（无默认路由 / `route` 不可用）→ **回落 `services[0]`**，不升级成 Err。
/// 回落是改动前的行为，不比它差；把「查不到主服务」升成查询失败会平白多一路黄灯。
#[test]
fn mac_live_status_falls_back_to_first_service_when_primary_unresolvable() {
    let runner = ArgvMockRunner::default()
        .on(&["-listallnetworkservices"], MAC_SERVICES_BRIDGE_FIRST)
        .on(&["-listnetworkserviceorder"], MAC_SERVICE_ORDER)
        .failing(&["default"]) // route 不可用
        .on(
            &["-getwebproxy", "Thunderbolt Bridge"],
            mac_on("127.0.0.1", 7890),
        )
        .on(
            &["-getsecurewebproxy", "Thunderbolt Bridge"],
            mac_on("127.0.0.1", 7890),
        )
        .on(
            &["-getsocksfirewallproxy", "Thunderbolt Bridge"],
            mac_on("127.0.0.1", 7890),
        );
    let (r, ops) = live(runner, Platform::Mac);
    assert!(r.expect("读取成功").points_to_us, "回落首项后照常判定");
    assert!(ops.runner.ran_arg("Thunderbolt Bridge"), "回落读首项");

    // 设备名映射不上（默认路由走 utun3，服务顺序表里没有）→ 同样回落，不 Err。
    let runner = ArgvMockRunner::default()
        .on(&["-listallnetworkservices"], MAC_SERVICES_BRIDGE_FIRST)
        .on(&["-listnetworkserviceorder"], MAC_SERVICE_ORDER)
        .on(&["default"], mac_route("utun3"))
        .on(
            &["-getwebproxy", "Thunderbolt Bridge"],
            mac_on("127.0.0.1", 7890),
        )
        .on(
            &["-getsecurewebproxy", "Thunderbolt Bridge"],
            mac_on("127.0.0.1", 7890),
        )
        .on(
            &["-getsocksfirewallproxy", "Thunderbolt Bridge"],
            mac_on("127.0.0.1", 7890),
        );
    let (r, ops) = live(runner, Platform::Mac);
    assert!(r.expect("读取成功").points_to_us);
    assert!(
        ops.runner.ran_arg("Thunderbolt Bridge"),
        "映射不上也回落首项"
    );
}

#[test]
fn mac_live_status_read_failure_is_err_not_false() {
    // **读不到 ≠ 没生效**：折成「未生效」会在读取受阻的环境里稳定误亮降级黄灯。
    let runner = ArgvMockRunner::default()
        .on(&["-listallnetworkservices"], MAC_SERVICES)
        .failing(&["-getwebproxy"]);
    let (r, _) = live(runner, Platform::Mac);
    assert!(r.is_err(), "读失败必须出栈为 Err（由上层折成「未知」）");
}

// ── Windows：reg query Internet Settings ────────────────────────────────────────

const WIN_ON: &str =
    "\r\nHKEY_CURRENT_USER\\...\\Internet Settings\r\n    ProxyEnable    REG_DWORD    0x1\r\n";
const WIN_OFF: &str = "\r\n    ProxyEnable    REG_DWORD    0x0\r\n";

fn win_server(value: &str) -> String {
    format!("\r\n    ProxyServer    REG_SZ    {value}\r\n")
}

#[test]
fn win_live_status_effective_when_registry_points_at_mixed_inbound() {
    let runner = ArgvMockRunner::default().on(&["ProxyEnable"], WIN_ON).on(
        &["ProxyServer"],
        win_server("http=127.0.0.1:7890;https=127.0.0.1:7890"),
    );
    let s = live(runner, Platform::Win).0.expect("读取成功");
    assert!(s.points_to_us);
    // 我们从不设 socks=（Chromium 经 SOCKS5 本地解析 DNS 会被污染）→ 该腿 None，不影响判定。
    assert_eq!(s.status.socks_proxy, None);
}

#[test]
fn win_live_status_not_effective_when_proxy_enable_is_zero() {
    // 形态①「未开启」：ProxyEnable=0 —— 注意 ProxyServer 值仍留在注册表里，只看串会误判。
    let runner = ArgvMockRunner::default().on(&["ProxyEnable"], WIN_OFF).on(
        &["ProxyServer"],
        win_server("http=127.0.0.1:7890;https=127.0.0.1:7890"),
    );
    let s = live(runner, Platform::Win).0.expect("读取成功");
    assert!(
        !s.points_to_us,
        "ProxyEnable=0 → 未生效（残留 server 值不算数）"
    );
}

#[test]
fn win_live_status_not_effective_when_pointing_at_another_proxy() {
    let runner = ArgvMockRunner::default().on(&["ProxyEnable"], WIN_ON).on(
        &["ProxyServer"],
        win_server("http=proxy.corp:3128;https=proxy.corp:3128"),
    );
    let s = live(runner, Platform::Win).0.expect("读取成功");
    assert!(!s.points_to_us);
    assert!(s.status.enabled);
}

/// 变异锁（比对端口）的 Windows 腿。
#[test]
fn win_live_status_rejects_port_mismatch() {
    let runner = ArgvMockRunner::default().on(&["ProxyEnable"], WIN_ON).on(
        &["ProxyServer"],
        win_server("http=127.0.0.1:9999;https=127.0.0.1:9999"),
    );
    let s = live(runner, Platform::Win).0.expect("读取成功");
    assert!(!s.points_to_us, "端口不匹配 → 必须判未生效");
}

#[test]
fn win_live_status_read_failure_is_err_not_false() {
    let runner = ArgvMockRunner::default().failing(&["ProxyEnable"]);
    assert!(live(runner, Platform::Win).0.is_err());
}

// ── Linux：gsettings org.gnome.system.proxy ─────────────────────────────────────

fn linux_runner(
    mode: &str,
    http: (&str, u16),
    https: (&str, u16),
    socks: (&str, u16),
) -> ArgvMockRunner {
    let mut r =
        ArgvMockRunner::default().on(&["org.gnome.system.proxy", "mode"], format!("'{mode}'\n"));
    for (schema, (host, port)) in [("http", http), ("https", https), ("socks", socks)] {
        let base: &'static str = match schema {
            "http" => "org.gnome.system.proxy.http",
            "https" => "org.gnome.system.proxy.https",
            _ => "org.gnome.system.proxy.socks",
        };
        r = r
            .on(&[base, "host"], format!("'{host}'\n"))
            // GVariant 前缀必须能被剥掉（`uint32 7890`），否则端口恒解析失败。
            .on(&[base, "port"], format!("uint32 {port}\n"));
    }
    r
}

#[test]
fn linux_live_status_effective_when_gsettings_points_at_mixed_inbound() {
    let s = live(
        linux_runner(
            "manual",
            ("127.0.0.1", 7890),
            ("127.0.0.1", 7890),
            ("127.0.0.1", 7890),
        ),
        Platform::Linux,
    )
    .0
    .expect("读取成功");
    assert!(s.points_to_us);
    assert_eq!(s.status.http_proxy.as_deref(), Some("127.0.0.1:7890"));
}

/// 形态①「未开启」的 Linux 形态 —— 并且是**只读 host/port 抓不到**的那一种：
/// 用户把 mode 改回 `none`，三个 schema 的 host/port **残值仍在**。
/// 变异锁：删掉 `read_active_proxy` 里的 mode 闸门 → 残值会被判成「仍指向我们」→ 本用例转红。
#[test]
fn linux_live_status_not_effective_when_mode_is_none_despite_residual_host() {
    let (r, ops) = live(
        linux_runner(
            "none",
            ("127.0.0.1", 7890),
            ("127.0.0.1", 7890),
            ("127.0.0.1", 7890),
        ),
        Platform::Linux,
    );
    let s = r.expect("读取成功");
    assert!(!s.points_to_us, "mode=none → GNOME 不下发代理 → 未生效");
    assert!(!s.status.enabled);
    assert!(
        !ops.runner.ran_arg("org.gnome.system.proxy.http"),
        "mode 非 manual 即早退，不必再读三 schema"
    );
}

#[test]
fn linux_live_status_not_effective_when_pointing_at_another_proxy() {
    // http 指向我们、https 被改到第三方 → 该协议绕开本地核 → 整体未生效。
    let s = live(
        linux_runner(
            "manual",
            ("127.0.0.1", 7890),
            ("proxy.corp", 3128),
            ("127.0.0.1", 7890),
        ),
        Platform::Linux,
    )
    .0
    .expect("读取成功");
    assert!(!s.points_to_us);
    assert_eq!(s.status.https_proxy.as_deref(), Some("proxy.corp:3128"));
}

/// 变异锁（比对端口）的 Linux 腿。
#[test]
fn linux_live_status_rejects_port_mismatch() {
    let s = live(
        linux_runner(
            "manual",
            ("127.0.0.1", 9999),
            ("127.0.0.1", 9999),
            ("127.0.0.1", 9999),
        ),
        Platform::Linux,
    )
    .0
    .expect("读取成功");
    assert!(!s.points_to_us, "端口不匹配 → 必须判未生效");
}

#[test]
fn linux_live_status_read_failure_is_err_not_false() {
    // 非 GNOME 桌面：`gsettings get org.gnome.system.proxy mode` 报「无此 schema」。
    let runner = ArgvMockRunner::default().failing(&["org.gnome.system.proxy", "mode"]);
    assert!(
        live(runner, Platform::Linux).0.is_err(),
        "读不到 ≠ 没生效：必须 Err，否则非 GNOME 环境恒亮降级黄灯"
    );
}

#[test]
fn other_platform_is_err() {
    assert!(live(ArgvMockRunner::default(), Platform::Other).0.is_err());
}

#[test]
fn parse_gsettings_mode_strips_quotes() {
    assert_eq!(parse_gsettings_mode("'manual'\n"), "manual");
    assert_eq!(parse_gsettings_mode("  'none' \n"), "none");
    assert_eq!(parse_gsettings_mode(""), "");
}
