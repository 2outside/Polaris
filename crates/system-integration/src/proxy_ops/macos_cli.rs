//! macOS 系统代理 networksetup CLI 腿：命令构造 + 输出解析。
//!
//! 这条腿是**回落路径**：生产写路径先试原生事务（`macos_proxy.rs`），
//! legacy 路径的 `MacProxyWriterError::Unavailable` 时才落到这里；exact 路径不回落。两条腿的实现面互斥由
//! `proxy_ops/tests/mac_leg_exclusivity_gate.rs` 钉死 —— 本文件只持有 argv 构造与输出解析，
//! 不持有执行与重试（那是 `ops.rs` 的 retry 边界，见设计文档 T2）。

use super::model::ProxyEnableRequest;
use crate::error::SystemIntegrationError;
use crate::exec::Command;
use crate::proxy::SystemProxyStatus;
use polaris_config_engine::user_config::system_proxy_bypass::format_bypass_for_mac;

/// macOS 恢复单服务原始代理 argv 序列：设了的 → set+state on；没设的 → state off（对称撤销）。
/// 上游 `MacOSSystemProxy.restoreProxySettings` 的 `settings.enabled` 分支。
///
/// `host:port` 拆分复用 [`crate::proxy::split_host_port`]（与 Linux restorePlan 同一真值），
/// 拆不出（畸形原始值）→ 该协议按「未设」关掉，不把畸形值喂给 networksetup。
pub fn mac_service_restore_commands(service: &str, original: &SystemProxyStatus) -> Vec<Command> {
    // (读取子命令前缀, set 子命令, state 子命令)
    const SPEC: [(&str, &str); 3] = [
        ("-setwebproxy", "-setwebproxystate"),
        ("-setsecurewebproxy", "-setsecurewebproxystate"),
        ("-setsocksfirewallproxy", "-setsocksfirewallproxystate"),
    ];
    let values = [
        original.http_proxy.as_deref(),
        original.https_proxy.as_deref(),
        original.socks_proxy.as_deref(),
    ];

    let mut cmds = Vec::new();
    for ((set_sub, state_sub), value) in SPEC.iter().zip(values) {
        match crate::proxy::split_host_port(value) {
            Some(hp) => {
                cmds.push(Command::new(
                    "networksetup",
                    [set_sub, service, &hp.host, &hp.port.to_string()],
                ));
                cmds.push(Command::new("networksetup", [state_sub, service, "on"]));
            }
            None => {
                cmds.push(Command::new("networksetup", [state_sub, service, "off"]));
            }
        }
    }
    // bypass 还原：enable 时整表覆盖过，这里必须写回原值。
    //
    // `None` = 捕获阶段没读到（旧 marker / 读失败）⇒ **什么都不做**。把它折成「写 Empty」会在
    // 读失败时反过来清掉用户的清单 —— 那比不还原更糟。
    // `Some(vec![])` = 用户本来就没有条目 ⇒ 写 `Empty` 哨兵清空（不能什么都不传，参数不足会被拒）。
    if let Some(domains) = original.bypass_domains.as_ref() {
        cmds.push(mac_service_bypass_command(service, domains));
    }
    cmds
}

// ── macOS 命令构造（Polaris MacOSSystemProxy）──

/// macOS 列网络服务命令。
pub fn mac_list_services_command() -> Command {
    Command::new("networksetup", ["-listallnetworkservices"])
}

/// macOS 列「服务顺序 + 硬件端口 + BSD 设备名」命令（`-listallnetworkservices` **没有**设备名）。
///
/// 输出形如：
/// ```text
/// An asterisk (*) denotes that a network service is disabled.
/// (1) Wi-Fi
/// (Hardware Port: Wi-Fi, Device: en0)
///
/// (2) Thunderbolt Bridge
/// (Hardware Port: Thunderbolt Bridge, Device: bridge0)
/// ```
/// 供 [`parse_mac_service_order`] 建「设备名 → 服务名」映射，把默认路由的接口翻译回服务名。
pub fn mac_list_service_order_command() -> Command {
    Command::new("networksetup", ["-listnetworkserviceorder"])
}

/// macOS 查默认路由出接口命令（`route -n get default`）。
///
/// 为什么不用 reviewer 建议的 `scutil` 查 `State:/Network/Global/IPv4` 的 `PrimaryService`：
/// `scutil` 的 `show` 子命令**只接受 stdin 交互输入**，而本 crate 的执行缝
/// （[`crate::exec::CommandRunner`]）刻意只走 argv、`stdin(Stdio::null())`（杜绝 shell 插值）。
/// 要走 scutil 就得给执行缝加 stdin 通道或退回 `sh -c` 管道 —— 前者动的是全 crate 的唯一 OS 交互点，
/// 后者把好不容易关掉的 shell 插值面重新打开。`route + -listnetworkserviceorder` 是纯 argv 的等价问法，
/// 答的是同一件事：**此刻流量从哪个接口出去、那个接口属于哪个网络服务**。
///
/// 输出解析复用 [`crate::route_ops::parse_mac_route_get_interface`]（同一条 `interface:` 行，
/// 本 crate 已有唯一实现，不另写第二份）。
pub fn mac_default_route_command() -> Command {
    Command::new("route", ["-n", "get", "default"])
}

/// 解析 `networksetup -listnetworkserviceorder` 输出 → `(服务名, 设备名)` 有序对。
///
/// 只收「`(N) 服务名` 紧跟 `(Hardware Port: …, Device: dev)`」的成对行；`(*)`/`(N) *名` 标记的
/// **停用**服务直接丢弃（停用服务不承载流量）。缺设备名（如某些 VPN 服务）的条目一并丢弃 ——
/// 本函数唯一的用途就是按设备名反查，没设备名的条目对它无意义。
pub fn parse_mac_service_order(stdout: &str) -> Vec<(String, String)> {
    let lines: Vec<&str> = stdout.lines().map(str::trim).collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        // `(1) Wi-Fi` / `(2) *Ethernet`（停用）。注意 `(Hardware Port: …)` 行也以 `(` 开头，
        // 靠「首段必须是纯数字序号」区分。
        let Some(rest) = line.strip_prefix('(') else {
            continue;
        };
        let Some((idx, name)) = rest.split_once(')') else {
            continue;
        };
        if idx.is_empty() || !idx.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let name = name.trim();
        if name.starts_with('*') {
            continue; // 停用服务不承载流量
        }
        // 设备名在**下一行**：`(Hardware Port: Wi-Fi, Device: en0)`。
        let Some(dev_line) = lines.get(i + 1) else {
            continue;
        };
        let Some(dev) = dev_line
            .rsplit_once("Device:")
            .map(|(_, d)| d.trim_end_matches(')').trim())
            .filter(|d| !d.is_empty())
        else {
            continue;
        };
        if !name.is_empty() {
            out.push((name.to_string(), dev.to_string()));
        }
    }
    out
}

/// mac「哪些网络服务该被我们接管」的**唯一口径** —— DNS 接管与系统代理共用这一条。
///
/// # 为什么不能用 `-listallnetworkservices`
///
/// 那条命令只给名字，于是判据只能落在名字上（旧口径就是「跳 `*` 停用 + 跳含 Bluetooth 的」）。
/// 后果实测于 p101（2026-08-08，只读取证）：**7 个服务全被改写成 8.8.8.8，其中两个是别家 VPN 的**
/// —— `Tailscale`（`io.tailscale.ipn.macsys`）与 `Shadowrocket`（`com.liguangming.Shadowrocket`）。
/// 我们不但覆盖了它们的解析器，还把还原责任揽到自己的 marker 上：Polaris 崩溃即别家 VPN 的 DNS
/// 停在 8.8.8.8。系统代理侧同理（两处此前共用同一个名字口径）。
///
/// # 判据：有没有底层 BSD 设备名
///
/// `-listnetworkserviceorder` 多给一行 `(Hardware Port: …, Device: …)`。实测同一台机器：
/// 五个物理服务分别是 `en7` / `en9` / `en11` / `bridge0` / `en0`，而两个 VPN 服务的 **Device 为空**
/// （NetworkExtension 提供的服务没有 BSD 设备）。这是「这个服务**是什么**」的属性，
/// 不是它叫什么 —— 换个名字、换个语言、装个没见过的 VPN，判据都还成立；名字黑名单做不到。
///
/// 复用既有的 [`parse_mac_service_order`]（它本来就丢弃空 Device 的条目，doc 里点名「如某些 VPN 服务」），
/// 不新写第二份解析。
///
/// # 失败方向与回落
///
/// 漏掉一个**物理**服务 = 该网卡的 DNS 没被接管 = 泄漏（重）；多接管一个虚拟服务 = 本次要修的问题（轻）。
/// 物理服务恒有 Device，故新判据不会误跳过物理口。但为防「某机型/未来 macOS 输出形态变了导致全空」，
/// **过滤后为空时回落到旧口径并告警** —— 「一个都不接管」比「多接管两个」错得更离谱。
pub fn mac_list_manageable_services<F>(mut run: F) -> Result<Vec<String>, SystemIntegrationError>
where
    F: FnMut(&Command) -> Result<crate::exec::CommandOutput, SystemIntegrationError>,
{
    let order = run(&mac_list_service_order_command())?;
    let picked: Vec<String> = parse_mac_service_order(&order.stdout)
        .into_iter()
        // 蓝牙沿用旧口径排除：写进蓝牙网络的设置在关闭后可能残留（该理由与设备名无关，故按名字排）。
        .filter(|(name, _dev)| !name.contains("Bluetooth"))
        .map(|(name, _dev)| name)
        .collect();
    if !picked.is_empty() {
        return Ok(picked);
    }
    log::warn!(
        "networksetup -listnetworkserviceorder 未解析出任何带设备名的服务 —— \
         回落到 -listallnetworkservices 旧口径（会把无底层设备的虚拟服务一并纳入）"
    );
    let all = run(&mac_list_services_command())?;
    Ok(parse_mac_network_services(&all.stdout))
}

/// macOS 读单服务某协议代理命令（`sub` ∈ `-getwebproxy` / `-getsecurewebproxy` / `-getsocksfirewallproxy`）。
/// 上游 `MacOSSystemProxy.readServiceProxy`。
pub fn mac_read_proxy_command(sub: &str, service: &str) -> Command {
    Command::new("networksetup", [sub, service])
}

/// macOS 三协议读取子命令（顺序 = http / https / socks，与 [`SystemProxyStatus`] 字段对应）。
pub const MAC_PROXY_READ_SUBS: [&str; 3] = [
    "-getwebproxy",
    "-getsecurewebproxy",
    "-getsocksfirewallproxy",
];

/// macOS bypass 清单读取子命令（`-setproxybypassdomains` 的对偶）。
pub const MAC_BYPASS_READ_SUB: &str = "-getproxybypassdomains";

/// `networksetup` 用来表示「清空 bypass 清单」的哨兵实参。
///
/// 写空清单不能什么都不传（`-setproxybypassdomains <svc>` 参数不足会被拒），必须显式给 `Empty`。
pub const MAC_BYPASS_EMPTY_SENTINEL: &str = "Empty";

fn mac_service_bypass_command(service: &str, domains: &[String]) -> Command {
    let mut args = vec!["-setproxybypassdomains".to_owned(), service.to_owned()];
    if domains.is_empty() {
        args.push(MAC_BYPASS_EMPTY_SENTINEL.to_owned());
    } else {
        args.extend(domains.iter().cloned());
    }
    Command {
        program: "networksetup".into(),
        args,
    }
}

/// 解析 `networksetup -getproxybypassdomains <svc>` 输出 → 清单。
///
/// 输出形态：每行一个条目；一条都没有时是一句英文提示
/// （`There aren't any bypass domains set on <svc>.`）。
///
/// **提示句必须与真条目区分开**：它没有前导空白、含空格、且不是合法域名/CIDR。判据取
/// 「整行不含空白字符」—— bypass 条目（域名 / `*.suffix` / CIDR）本身不可能含空格，
/// 而任何英文提示句必然含空格。比匹配英文原文稳（`networksetup` 的提示文案随系统版本变）。
#[must_use]
pub fn parse_mac_bypass_domains(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.chars().any(char::is_whitespace))
        .map(str::to_owned)
        .collect()
}

/// 解析 `networksetup -getwebproxy <svc>` 输出 → `host:port`（未启用 → None）。
/// 上游 `MacOSSystemProxy.readServiceProxy` 的 `read` 闭包。
pub fn parse_mac_service_proxy(stdout: &str) -> Option<String> {
    if !stdout.contains("Enabled: Yes") {
        return None;
    }
    let field = |key: &str| -> Option<String> {
        stdout.lines().find_map(|l| {
            let v = l.trim().strip_prefix(key)?.trim();
            (!v.is_empty()).then(|| v.to_string())
        })
    };
    let server = field("Server:")?;
    let port = field("Port:")?;
    // 端口须为纯数字（上游正则 `/Port: (\d+)/`）。
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(format!("{server}:{port}"))
}

/// macOS 单网络服务设代理 argv 序列：web/secureweb/socks 各 set，外加 bypass。
///
/// `networksetup -set{web,secureweb,socksfirewall}proxy` 写入 host/port 时会同时把对应协议置为
/// Enabled；随后再跑一次 `-set*proxystate ... on` 只是重复提交。2026-08-27 在 macOS 26.6.2
/// 对三种协议逐一做了 `get → set → get → state off` 真机闭环，三条 `set` 后均从 `Enabled: No`
/// 变为 `Enabled: Yes`。这里据此省掉每个服务 3 个串行子进程；显式的 state-off 仍保留在
/// disable/restore 路径，断开时的 fail-safe 语义不变。
/// 上游 `MacOSSystemProxy.enableProxy` per-service 块（execFile argv 参数化）。
pub fn mac_service_enable_commands(service: &str, req: &ProxyEnableRequest) -> Vec<Command> {
    let mut cmds = Vec::new();
    let http_port = req.http_port.to_string();
    let socks_port = req.socks_port.to_string();

    // HTTP 代理
    cmds.push(Command {
        program: "networksetup".into(),
        args: vec![
            "-setwebproxy".into(),
            service.into(),
            req.address.clone(),
            http_port.clone(),
        ],
    });
    // HTTPS 代理
    cmds.push(Command {
        program: "networksetup".into(),
        args: vec![
            "-setsecurewebproxy".into(),
            service.into(),
            req.address.clone(),
            http_port.clone(),
        ],
    });
    // SOCKS 代理
    cmds.push(Command {
        program: "networksetup".into(),
        args: vec![
            "-setsocksfirewallproxy".into(),
            service.into(),
            req.address.clone(),
            socks_port,
        ],
    });
    // bypass（argv，原样接受 CIDR + 域名 + 通配）；空清单必须显式传 Empty，
    // 否则 networksetup 会收到参数不足的命令并拒绝执行。
    let bypass = format_bypass_for_mac(&req.bypass_list);
    cmds.push(mac_service_bypass_command(service, &bypass));
    cmds
}

/// macOS 禁用单服务代理（三协议 state off）。
/// 上游 `MacOSSystemProxy.disableProxy` else 分支 per-service。
pub fn mac_service_disable_commands(service: &str) -> Vec<Command> {
    vec![
        Command {
            program: "networksetup".into(),
            args: vec!["-setwebproxystate".into(), service.into(), "off".into()],
        },
        Command {
            program: "networksetup".into(),
            args: vec![
                "-setsecurewebproxystate".into(),
                service.into(),
                "off".into(),
            ],
        },
        Command {
            program: "networksetup".into(),
            args: vec![
                "-setsocksfirewallproxystate".into(),
                service.into(),
                "off".into(),
            ],
        },
    ]
}

/// 解析 macOS `networksetup -listallnetworkservices` 输出 → 网络服务名列表。
/// 跳过首行提示 + 空行 + 以 `*` 开头的禁用服务 + Bluetooth PAN。
/// 上游 `MacOSSystemProxy.getNetworkServices`。
pub fn parse_mac_network_services(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .skip(1) // 首行提示 "An asterisk (*) denotes..."
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('*') && !l.contains("Bluetooth"))
        .map(str::to_string)
        .collect()
}
