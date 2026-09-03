//! 系统路由出口接口探测 + TUN 出口夺取（post-flight）判定。
//!
//! 解决的问题（真机复现 `~/docs/polaris/design/polaris-tun-conflict-detect-design-2026-07-22.md`）：
//! 其他 VPN（如另一个 TUN 客户端）已占用系统默认路由时，Polaris 起核后 sing-box 的 utun 抢不到流量，
//! 但既有就绪门（进程活 + 管理 API 环回口可连）**照样全真** → 假报「已连接」、连接数恒 0、↓0↑0。
//!
//! ## 关键不变式（设计 §4.1 / §4.5）
//!
//! **成功接管 ⟺ 对「本应走代理的公网目的」的出口接口从 baseline 切走。** 直接观测这条比数流量更可靠：
//! 路由表在 utun 起来时即被写（与有无流量无关），故不受「用户恰好空闲、连接数 0」的假阳性影响。
//! macOS 内核给 tun 分配 `utunN` 名字、进程**无法预知自己的 utun 叫什么**（config-engine 不设
//! `interface_name`），故不靠名字识别「我方 utun」，而靠 **baseline 差分**：起核前记出口，起核 +grace
//! 后仍等于 baseline 那个「起核前就存在的接口」→ 判未夺到路由。
//!
//! ## 手段（设计 §4.5 / §4.6，D4/D5）
//!
//! probe 目的固定为公网 IP `1.1.1.1`（[`PROBE_IP`]）——`route get` / `ip route get` 是**路由表读**，
//! **不发包**、非 root、非破坏。命令经 [`CommandRunner`] 下发（mock 可单测），与 `dns_ops` 同缝。
//!
//! - **macOS**：`route -n get 1.1.1.1` → 解析 `interface: utunN`。**绝不用 `route -n get default`**：
//!   sing-box `auto_route` 装的是 `0.0.0.0/1`+`128.0.0.0/1` 两条半程路由、**不动** `0.0.0.0/0`，查 default
//!   会返物理网卡（假阴性）。查具体公网 IP 让 /1 半程按最长前缀命中（设计 §4.5 陷阱行）。
//! - **Linux**：`ip route get 1.1.1.1` → 解析 `dev tunX`。
//! - **Windows**：`Find-NetRoute -RemoteIPAddress 1.1.1.1` → 解析 `InterfaceAlias`（内核代算最优路由，
//!   等价 `route get`；设计 §4.6 「route print 最低 metric」的可解析替身）。首版命令式，PF_ROUTE 编程读延后。
//!
//! ## 零 cfg（与 `dns_ops` / `proxy_ops` 同纪律）
//!
//! 平台差异只是「跑什么命令 / 怎么解析输出」的纯函数，用运行时 [`Platform`] 分派而非 `#[cfg(target_os)]`
//! → Linux CI 100% 编译 + 跑测三平台逻辑。命令构造与输出解析全是纯函数、mock 一注入即可断言。

#![forbid(unsafe_code)]

use crate::error::SystemIntegrationError;
use crate::exec::{Command, CommandRunner};
use polaris_helper_proto::Platform;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

/// post-flight 探测的固定公网目的 IP（设计 D4）。route 查询是路由表读、不发包 → 选公网 IP 让
/// sing-box auto_route 的 /1 半程路由按最长前缀命中，避开 `default`(0/0) 的物理网卡假阴性。
pub const PROBE_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

/// 单条路由查询命令硬超时（对齐 `dns_ops::DNS_CMD_TIMEOUT`）。
pub const ROUTE_CMD_TIMEOUT: Duration = Duration::from_secs(5);

/// 平台路由出口探测抽象。mac/linux/win 真实现（命令 + 解析），Other 收敛为「查不到」（`Ok(None)`）。
pub trait SystemRouteOps {
    /// 查目的 IP 的出口接口名。
    ///
    /// - `Ok(Some(iface))`：路由表命中，出口接口 = `iface`（macOS `utunN` / linux `tunX`/`eth0` /
    ///   win `InterfaceAlias`）。
    /// - `Ok(None)`：命令成功但输出里没有可识别的接口（无匹配路由 / 解析不出）——**非错误**，判定层按
    ///   「不可断言」处理，绝不据此硬闸（避免 §4.7 假阳性）。
    /// - `Err`：命令执行失败（spawn/超时/非零退出）。
    fn exit_interface_for(&self, ip: IpAddr) -> Result<Option<String>, SystemIntegrationError>;
}

/// [`SystemRouteOps`] 的生产实现（运行时 [`Platform`] 分派 + [`CommandRunner`] 下发；零 cfg）。
pub struct SystemRouteOpsImpl<R: CommandRunner> {
    runner: R,
    platform: Platform,
    /// Windows `powershell.exe` 绝对路径（规避 PATH 缺 System32；见 `exec::system32`）。
    powershell_exe: String,
}

impl<R: CommandRunner> SystemRouteOpsImpl<R> {
    /// 生产构造：平台取本机。
    pub fn new(runner: R) -> Self {
        Self::with_platform(runner, Platform::current())
    }

    /// 指定平台构造（测试用：Linux 上断言 mac/win 的 argv 与解析）。
    pub fn with_platform(runner: R, platform: Platform) -> Self {
        Self {
            runner,
            platform,
            powershell_exe: crate::exec::system32_from_env(
                "WindowsPowerShell\\v1.0\\powershell.exe",
            ),
        }
    }

    fn run(&self, cmd: &Command) -> Result<crate::exec::CommandOutput, SystemIntegrationError> {
        self.runner
            .run(cmd, ROUTE_CMD_TIMEOUT)
            .map_err(SystemIntegrationError::route)
    }
}

impl<R: CommandRunner> SystemRouteOps for SystemRouteOpsImpl<R> {
    fn exit_interface_for(&self, ip: IpAddr) -> Result<Option<String>, SystemIntegrationError> {
        let ip = ip.to_string();
        match self.platform {
            Platform::Mac => {
                // `-n` 抑制反向 DNS（不发包、更快）；查具体公网 IP 而非 default（§4.5 半程路由陷阱）。
                let args = if ip.contains(':') {
                    vec!["-n".to_owned(), "get".to_owned(), "-inet6".to_owned(), ip]
                } else {
                    vec!["-n".to_owned(), "get".to_owned(), ip]
                };
                let out = self.run(&Command::new("route", args))?;
                Ok(parse_mac_route_get_interface(&out.stdout))
            }
            Platform::Linux => {
                let args = if ip.contains(':') {
                    vec!["-6".to_owned(), "route".to_owned(), "get".to_owned(), ip]
                } else {
                    vec!["route".to_owned(), "get".to_owned(), ip]
                };
                let out = self.run(&Command::new("ip", args))?;
                Ok(parse_linux_ip_route_dev(&out.stdout))
            }
            Platform::Win => {
                // Find-NetRoute 让内核代算「到该目的会用哪个接口」（等价 route get），Format-List 收窄输出。
                let cmd = Command::new(
                    &self.powershell_exe,
                    [
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        &format!(
                            "Find-NetRoute -RemoteIPAddress {ip} | Format-List InterfaceAlias"
                        ),
                    ],
                );
                Ok(parse_win_find_netroute_alias(&self.run(&cmd)?.stdout))
            }
            // 未知平台：无对应路由工具 → 查不到（判定层按「不可断言」不闸）。
            Platform::Other => Ok(None),
        }
    }
}

// ── 纯解析函数（跨平台可单测；Linux CI 上断言三平台输出解析）──

/// 解析 macOS `route -n get <ip>` 的 `interface: utunN` 行。无该行 → None。
pub fn parse_mac_route_get_interface(stdout: &str) -> Option<String> {
    stdout.lines().find_map(|line| {
        let line = line.trim();
        let rest = line.strip_prefix("interface:")?;
        let iface = rest.trim();
        (!iface.is_empty()).then(|| iface.to_string())
    })
}

/// 解析 Linux `ip route get <ip>` 的 `dev <iface>` token。无该 token → None。
///
/// 兼容两形态：`1.1.1.1 via <gw> dev eth0 src ...` 与 `1.1.1.1 dev tun0 src ...`。
pub fn parse_linux_ip_route_dev(stdout: &str) -> Option<String> {
    let mut tokens = stdout.split_whitespace();
    while let Some(tok) = tokens.next() {
        if tok == "dev" {
            if let Some(dev) = tokens.next() {
                if !dev.is_empty() {
                    return Some(dev.to_string());
                }
            }
        }
    }
    None
}

/// 解析 Windows `Find-NetRoute ... | Format-List InterfaceAlias` 的首个 `InterfaceAlias : <name>` 值。
///
/// Find-NetRoute 返回源地址 + 路由两个对象、二者的 InterfaceAlias 均指向出口接口，取首个即可。
pub fn parse_win_find_netroute_alias(stdout: &str) -> Option<String> {
    stdout.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim() != "InterfaceAlias" {
            return None;
        }
        let alias = value.trim();
        (!alias.is_empty()).then(|| alias.to_string())
    })
}

// ── baseline 差分判定（方向①后验的核心；纯逻辑，与探测手段解耦）──

/// 出口接口是否已从 baseline 切走（成功接管的判据）。
///
/// - `current = Some(c)` 且 `c != baseline` → `true`（含 baseline 不可读的情形：任何可读的新出口都算切走，
///   偏向「不闸」这一安全方向——见 [`ExitCaptureOutcome`]）。
/// - `current = Some(c)` 且 `c == baseline` → `false`（出口未动）。
/// - `current = None`（探测不可读） → `false`（无法断言切走）。
fn exit_changed<T: PartialEq>(baseline: &Option<T>, current: &Option<T>) -> bool {
    match current {
        Some(c) => baseline.as_ref() != Some(c),
        None => false,
    }
}

/// post-flight 出口归属判定结果。
///
/// `T` = 调用方使用的**接口身份类型**。本判定只做「同一探测通道的前后两次观测是否相等」，
/// 不解释身份的内部表示；调用方据此可以传别名字符串，也可以传别名/索引合一的结构化身份，
/// 而不必先把索引编码成字符串再假装它是个名字。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitCaptureOutcome<T> {
    /// 出口已从 baseline 切走 → 成功接管（macOS 不可命名 → 差分即判据）。
    Captured { interface: Option<T> },
    /// grace 耗尽、出口仍等于（可读的）baseline → **未夺到路由**，判定层据此硬闸。
    NotCaptured { baseline: T, last: T },
    /// baseline 或末次探测不可读 → 无法断言 → **不闸**（caveat，设计 §4.7 避免假阳性）。
    Indeterminate,
}

/// 在 grace 窗口内轮询出口接口，按 baseline 差分判定是否夺到路由（方向①后验）。
///
/// - `baseline`：起核**前**（我方 utun 上线前）的出口接口快照。
/// - `max_polls`：grace 窗口内的探测次数（≥1）。任一次探到出口切走即**立即** `Captured`（早退，接管越快
///   越早点亮）；仅全部轮次都未切走才落终判。
/// - `probe`：读当前出口接口（生产 = [`SystemRouteOps::exit_interface_for`]；测试 = 队列）。探测 `Err`
///   按 `None`（best-effort，绝不据探测失败误判为夺到）。
/// - `sleep_between_polls`：相邻两次探测之间的等待（生产 = `thread::sleep`；测试 = 计数）。**末次探测后
///   不再 sleep**（省一个 grace 间隔的白等）。
///
/// 终判：全程未切走时，若 baseline 与末次探测**都可读且相等** → [`ExitCaptureOutcome::NotCaptured`]；
/// 否则 [`ExitCaptureOutcome::Indeterminate`]（不可读 → 不闸）。
pub fn verify_exit_captured<T, P, S>(
    baseline: Option<T>,
    max_polls: usize,
    mut probe: P,
    mut sleep_between_polls: S,
) -> ExitCaptureOutcome<T>
where
    T: PartialEq,
    P: FnMut() -> Result<Option<T>, SystemIntegrationError>,
    S: FnMut(),
{
    let polls = max_polls.max(1);
    let mut last: Option<T> = None;
    for i in 0..polls {
        let current = probe().unwrap_or(None);
        if exit_changed(&baseline, &current) {
            return ExitCaptureOutcome::Captured { interface: current };
        }
        last = current;
        if i + 1 < polls {
            sleep_between_polls();
        }
    }
    match (baseline, last) {
        // 都可读且相等（出口自始至终没动）→ 未夺到路由，硬闸。
        (Some(b), Some(l)) if b == l => ExitCaptureOutcome::NotCaptured {
            baseline: b,
            last: l,
        },
        // baseline 不可读 / 末次探测不可读 / 二者不等但又没触发早退 → 不可断言，不闸。
        _ => ExitCaptureOutcome::Indeterminate,
    }
}

#[cfg(test)]
mod tests;
