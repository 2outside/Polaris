//! 系统 DNS 平台操作抽象 + 接管/还原/重灌编排。
//!
//! 1:1 移植自 上游 `SystemDnsManager.ts` 基类 `SystemDnsBase`：
//! - [`SystemDnsOps`] trait：物理网卡 list/read/apply/读生效解析器（mac 真实实现 + Win/Linux no-op）。
//!   Linux 生产接管不走本抽象，而走 [`crate::linux_resolved`] 的 TUN per-link 生命周期。
//! - [`DnsMarker`]：marker 读写（FS trait 注入，纯逻辑）。
//! - [`SystemDnsController`]：setDns / restoreDns / reconcileDns / restoreDnsSync 编排。
//!
//! 关键不变量（对齐 Polaris）：
//! - setDns **best-effort**：失败仅告警 + 回滚还原，绝不抛（DNS 治理降级不阻断 TUN 启动）。
//! - marker 前置写入（intent）：set 期间崩溃也留 marker，下次启动据此还原。
//! - 防自指：再次接管时若当前已是受控 IP，回退既有 marker 的真实原始。
//! - reconcile：仅 marker 在才动手（接管未激活绝不写系统）；只 apply 未受控服务（幂等）。

#![forbid(unsafe_code)]

use crate::dns::{
    compute_original_to_save, controlled_tun_dns_ip, extract_ipv4s, is_controlled,
    is_controlled_dns_ip_valid, mac_set_dns_args, parse_mac_get_dns_servers,
    parse_scutil_nameservers, parse_win_interfaces, parse_win_show_dns_servers,
    pick_lan_resolver_ip, SystemDnsMarker,
};
use crate::error::SystemIntegrationError;
use crate::exec::{Command, CommandRunner};
use crate::proxy::MarkerFs;
use crate::proxy_ops::{retry_op, RetryConfig};
use polaris_helper_proto::Platform;
use std::collections::BTreeMap;
use std::time::Duration;

/// 系统 DNS marker 读写（FS trait 注入）。
/// 上游 `SystemDnsBase` 的 marker IO 部分。
pub struct DnsMarker<Fs: MarkerFs> {
    fs: Fs,
    path: String,
    controlled_ip: String,
}

impl<Fs: MarkerFs> DnsMarker<Fs> {
    pub fn new(fs: Fs, path: impl Into<String>) -> Self {
        Self {
            fs,
            path: path.into(),
            controlled_ip: controlled_tun_dns_ip().to_string(),
        }
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    /// 写 marker（setDns 前置 intent）。失败仅告警绝不抛（Polaris writeMarker try/catch）。
    pub fn write(&self, original: &BTreeMap<String, Vec<String>>) {
        let marker = SystemDnsMarker {
            controlled_ip: self.controlled_ip.clone(),
            original: original.clone(),
            at: now_ms(),
        };
        let Ok(json) = serde_json::to_string(&marker) else {
            return;
        };
        let _ = self.fs.write_marker(&self.path, &json);
    }

    pub fn clear(&self) {
        let _ = self.fs.remove_marker(&self.path);
    }

    /// 读 marker；不存在 / 损坏 / 结构非法 → None。
    pub fn read(&self) -> Option<SystemDnsMarker> {
        let raw = self.fs.read_marker(&self.path)?;
        let m: SystemDnsMarker = serde_json::from_str(&raw).ok()?;
        if !is_controlled_dns_ip_valid(&m.controlled_ip) {
            return None;
        }
        Some(m)
    }

    pub fn exists(&self) -> bool {
        self.read().is_some()
    }
}

/// 物理网卡 DNS 操作抽象。mac 真实实现（networksetup），Win/Linux 收敛为 no-op；Linux 的
/// `systemd-resolved` TUN per-link 接管由 [`crate::linux_resolved`] 独立负责。
/// 语义对齐 上游 `SystemDnsBase` 的 abstract 方法。
pub trait SystemDnsOps {
    /// **本平台是否接管系统 DNS（写路径）**。mac=true；win/linux=false。
    ///
    /// ## 为什么是 trait 方法而不是「让 apply_dns 静默 no-op」
    ///
    /// 上游把 no-op 做在**平台子类覆写 `setDns` 整个方法**上（`WindowsSystemDns.setDns` /
    /// `LinuxSystemDns.setDns`），**不是**让 `applyDns` 空转 —— 这个区别是**血证**：
    ///
    /// - **Windows**（上游 2026-06-17 真机实证收口）：① sing-box TUN `strict_route`(WFP) 已在路由层
    ///   把所有 `:53` 强制逼进 TUN → 不需要也不应再改系统 DNS 设置项；② `netsh set dnsservers` **需管理员**，
    ///   GUI 非提权 → 真机**每次 ACCESS DENIED**。而 `set_dns` 是**先写 marker 再 apply** →
    ///   apply 必失败 → **marker 卡死** → 每次启动反复「还原 netsh 失败、保留 marker」刷错误日志。
    /// - **Linux**：发行版差异大（systemd-resolved / resolv.conf / NetworkManager），写入风险高，
    ///   且 TUN 由 sing-box `auto_route` 自身处理 DNS。
    ///
    /// 故若仅让 `apply_dns` 空转、`set_dns` 照常写 marker，**会精确复现上游修掉的 marker 卡死 bug**。
    /// [`SystemDnsController::set_dns`] 据本方法**在写 marker 之前**早退。
    ///
    /// **读路径不受影响**：`list_targets` / `read_dns` / `read_effective_resolvers` 在 win 上仍是真实现
    /// （`netsh show` 非提权可跑），供方案B [`SystemDnsController::get_lan_resolver_for_dns`] 用。
    fn takeover_supported(&self) -> bool;

    /// 列出应接管的网络服务/接口名。
    fn list_targets(&self) -> Result<Vec<String>, crate::error::SystemIntegrationError>;
    /// 读某服务/接口的当前 DNS（`[] = DHCP/自动`）。
    fn read_dns(&self, target: &str) -> Result<Vec<String>, crate::error::SystemIntegrationError>;
    /// 设某服务/接口 DNS（`[] → DHCP/Empty 还原`）。
    fn apply_dns(
        &self,
        target: &str,
        ips: &[String],
    ) -> Result<(), crate::error::SystemIntegrationError>;
    /// 读生效解析器候选 IP（含 DHCP 下发的；方案B 用）。无法读 → `[]`。
    fn read_effective_resolvers(&self)
        -> Result<Vec<String>, crate::error::SystemIntegrationError>;
}

/// 接管请求/结果辅助。
pub struct DnsTakeover {
    pub targets: Vec<String>,
    pub current: BTreeMap<String, Vec<String>>,
}

/// 单条系统 DNS 命令硬超时（上游 `DNS_CMD_TIMEOUT_MS`）。
pub const DNS_CMD_TIMEOUT: Duration = Duration::from_secs(5);

/// [`SystemDnsOps`] 的生产实现（运行时 [`Platform`] 分派 + [`CommandRunner`] 下发；零 cfg）。
///
/// 平台分界（真差异，保留隔离）：
/// - **mac**：真接管。`networksetup -listallnetworkservices` / `-getdnsservers` / `-setdnsservers`；
///   生效解析器读 `scutil --dns`（含 DHCP 下发的，`-getdnsservers` 对 DHCP 返空拿不到）。
/// - **win**：**写路径 no-op**（`takeover_supported=false`，判据见该方法）；读路径真实现
///   （`netsh interface ipv4 show ...`，非提权可跑）供方案B 用。
/// - **linux**：本物理网卡抽象全 no-op（读也返空）；生产接管另走 [`crate::linux_resolved`]。
pub struct SystemDnsOpsImpl<R: CommandRunner> {
    runner: R,
    platform: Platform,
    /// Windows `netsh.exe` 绝对路径（规避 PATH 缺 System32）。
    netsh_exe: String,
}

impl<R: CommandRunner> SystemDnsOpsImpl<R> {
    /// 生产构造：平台取本机。
    pub fn new(runner: R) -> Self {
        Self::with_platform(runner, Platform::current())
    }

    /// 指定平台构造（测试用：Linux 上断言 mac/win 的 argv 与解析）。
    pub fn with_platform(runner: R, platform: Platform) -> Self {
        Self {
            runner,
            platform,
            netsh_exe: crate::exec::system32_from_env("netsh.exe"),
        }
    }

    fn run(&self, cmd: &Command) -> Result<crate::exec::CommandOutput, SystemIntegrationError> {
        self.runner
            .run(cmd, DNS_CMD_TIMEOUT)
            .map_err(SystemIntegrationError::dns)
    }

    /// Windows：读单接口 DNS 输出（读路径，show 非提权可跑）。
    fn win_show_dnsservers(&self, iface: &str) -> Result<String, SystemIntegrationError> {
        let cmd = Command::new(
            &self.netsh_exe,
            [
                "interface",
                "ipv4",
                "show",
                "dnsservers",
                &format!("name={iface}"),
            ],
        );
        Ok(self.run(&cmd)?.stdout)
    }
}

impl<R: CommandRunner> SystemDnsOps for SystemDnsOpsImpl<R> {
    fn takeover_supported(&self) -> bool {
        // 仅 mac 接管系统 DNS。win/linux 的判据见 trait 方法 doc（上游真机实证收口）。
        matches!(self.platform, Platform::Mac)
    }

    fn list_targets(&self) -> Result<Vec<String>, SystemIntegrationError> {
        match self.platform {
            // 与系统代理共用**同一个**口径函数（此前是共用同一个「按名字过滤」的解析器，
            // 于是两处一起把 DNS/代理写到了别家 VPN 的网络服务上）。判据与回落见该函数 doc。
            Platform::Mac => crate::proxy_ops::mac_list_manageable_services(|c| self.run(c)),
            Platform::Win => {
                let out = self.run(&Command::new(
                    &self.netsh_exe,
                    ["interface", "ipv4", "show", "interfaces"],
                ))?;
                Ok(parse_win_interfaces(&out.stdout))
            }
            Platform::Linux | Platform::Other => Ok(vec![]),
        }
    }

    fn read_dns(&self, target: &str) -> Result<Vec<String>, SystemIntegrationError> {
        match self.platform {
            Platform::Mac => {
                let out = self.run(&Command::new("networksetup", ["-getdnsservers", target]))?;
                Ok(parse_mac_get_dns_servers(&out.stdout))
            }
            Platform::Win => Ok(parse_win_show_dns_servers(
                &self.win_show_dnsservers(target)?,
            )),
            Platform::Linux | Platform::Other => Ok(vec![]),
        }
    }

    fn apply_dns(&self, target: &str, ips: &[String]) -> Result<(), SystemIntegrationError> {
        match self.platform {
            Platform::Mac => {
                // execFile argv：服务名含空格（如 "USB 10/100/1000 LAN"）也安全，无引号歧义。
                self.run(&Command::new("networksetup", mac_set_dns_args(target, ips)))?;
                Ok(())
            }
            // 写路径 no-op —— 但**正常不可达**：`takeover_supported=false` 已让 set_dns/reconcile_dns
            // 在写 marker 前早退。此处是纵深防御（万一有人绕过控制器直调 ops）。
            // 上游 `winSetDnsCommands` 纯函数保留在 `dns::win_set_dns_commands`（移植真值 + 待
            // Windows 接管解禁时复用），故意不接线。
            Platform::Win | Platform::Linux | Platform::Other => Ok(()),
        }
    }

    fn read_effective_resolvers(&self) -> Result<Vec<String>, SystemIntegrationError> {
        match self.platform {
            Platform::Mac => {
                // scutil --dns 反映生效解析器（含 DHCP 下发的）。
                let out = self.run(&Command::new("scutil", ["--dns"]))?;
                Ok(parse_scutil_nameservers(&out.stdout))
            }
            Platform::Win => {
                // 逐**已连接**接口读（与 list_targets 同口径，避免 VMware/Hyper-V/VPN 虚拟网卡的
                // 私网 DNS 抢先被选）。单接口 show 同时含 static 与 dhcp 行 → extract_ipv4s 两者都取。
                let mut all: Vec<String> = Vec::new();
                for iface in self.list_targets()? {
                    // 单接口读失败跳过（上游 per-iface try/catch）。
                    let Ok(stdout) = self.win_show_dnsservers(&iface) else {
                        continue;
                    };
                    for ip in extract_ipv4s(&stdout) {
                        if !all.contains(&ip) {
                            all.push(ip);
                        }
                    }
                }
                Ok(all)
            }
            Platform::Linux | Platform::Other => Ok(vec![]),
        }
    }
}

// ── set_dns 重试配置（1:1 移植 上游 `SystemDnsManager.ts:214-229` 的 `retry(...)` 块）──
//
// 复用 [`crate::proxy_ops`] 的通用重试原语（`RetryConfig`/`retry_op` 已 `pub(crate)`），不另写一套。
// **仅套 `set_dns` 一处**：上游 `restoreDns`/`reconcileDns` 均无 retry 包裹（`reconcileDns` 逐服务
// best-effort `.catch()` 吞错即放弃，`restoreDns` 单次 apply），故 [`SystemDnsController::restore_dns_inner`]
// 保持原样不套 retry —— 对齐上游这一不对称。

/// `set_dns` 的重试配置：`maxRetries:2, delay:500`（指数退避缺省 true → 退避 500/1000ms），
/// `shouldRetry`= 权限拒绝 / 未授权 → 不重试，其余瞬时抖动 → 重试（`SystemDnsManager.ts:221-226`）。
///
/// 仅 mac 会用到——**唯一真接管平台**（见 [`SystemDnsOps::takeover_supported`]）；win/linux 在
/// [`SystemDnsController::set_dns`] 写 marker 前已早退，走不到这条重试。
const DNS_SET_RETRY: RetryConfig = RetryConfig {
    max_retries: 2,
    delay: Duration::from_millis(500),
    exponential_backoff: true,
    should_retry: dns_set_should_retry,
};

/// `set_dns` 的 `shouldRetry`（上游 `SystemDnsManager.ts:223-225`）：权限拒绝 / 未授权 → 不重试，
/// 其余（`networksetup` 瞬时抖动）→ 重试。**配置**（次数/退避）与 `proxy_ops` 的 mac enable 独立
/// ——对齐「三平台参数不同，勿合并成单一配置」；但**判据词表**共用
/// [`crate::proxy_ops::PERMISSION_DENIED_NEEDLES`]（两份手抄的词表必然漂移，且漏词的后果
/// 在这条路径上更贵：本重试是**持 `dns_controller` 锁**跑的，误判瞬时 → 多 2 次必败重试 + 1.5s 退避
/// 全程占锁）。
///
/// 上游只判 `permission` / `not authorized` 两词 —— 那是 Node 侧文案；Rust 侧把子进程 stderr 原文
/// 归入消息串，macOS `networksetup` 的 `requires admin privileges` 形态一个都不含，故必须补表。
fn dns_set_should_retry(e: &SystemIntegrationError) -> bool {
    !crate::proxy_ops::is_permission_denied(&e.to_string().to_lowercase())
}

/// 系统 DNS 控制器：setDns / restoreDns / reconcileDns / sync 编排。
pub struct SystemDnsController<Ops: SystemDnsOps, Fs: MarkerFs> {
    ops: Ops,
    marker: DnsMarker<Fs>,
    /// 内存中的原始 DNS 快照（restoreDns 用；restoreDnsSync 走 marker 跨会话）。
    original: Option<BTreeMap<String, Vec<String>>>,
    /// `set_dns` 重试退避 sleep（注入便于测试：生产 [`std::thread::sleep`]，测试传 no-op 杜绝真睡；
    /// 对齐 `proxy_ops::SystemProxyOpsImpl` 既有的可注入执行缝风格）。
    sleeper: fn(Duration),
}

impl<Ops: SystemDnsOps, Fs: MarkerFs> SystemDnsController<Ops, Fs> {
    pub fn new(ops: Ops, marker: DnsMarker<Fs>) -> Self {
        Self {
            ops,
            marker,
            original: None,
            sleeper: std::thread::sleep,
        }
    }

    /// 测试：换成 no-op sleeper（重试路径不真睡）。
    #[cfg(test)]
    fn with_noop_sleeper(mut self) -> Self {
        self.sleeper = |_| {};
        self
    }

    /// 受控 DNS IP。
    pub fn controlled_ip(&self) -> &str {
        &self.marker.controlled_ip
    }

    /// 方案B：挑接管前的内网 LAN 解析器（私网 IPv4，排除受控 IP）。
    /// marker 在 → 用 marker.original；否则读生效解析器。上游 `getLanResolverForDns`。
    pub fn get_lan_resolver_for_dns(&self) -> Option<String> {
        let marker = self.marker.read();
        let candidates: Vec<String> = match &marker {
            Some(m) => m.original.values().flatten().cloned().collect(),
            None => self.ops.read_effective_resolvers().unwrap_or_default(),
        };
        pick_lan_resolver_ip(&candidates, &self.marker.controlled_ip)
    }

    /// 读各服务当前 DNS（best-effort：单服务读失败按 `[]`）。
    fn snapshot_current(&self, targets: &[String]) -> BTreeMap<String, Vec<String>> {
        let mut current = BTreeMap::new();
        for t in targets {
            let ips = self.ops.read_dns(t).unwrap_or_default();
            current.insert(t.clone(), ips);
        }
        current
    }

    /// TUN 启动接管系统 DNS。**best-effort**：失败仅告警 + 回滚，绝不抛（不阻断 TUN 启动）。
    /// 上游 `setDns`。
    pub fn set_dns(&mut self) {
        // 守卫：本平台不接管 DNS（win/linux）→ 早退。**必须在写 marker 之前** ——
        // 否则 marker 写下、apply 必失败（win netsh 需管理员）→ marker 卡死 → 每次启动反复空跑还原。
        // 判据见 `SystemDnsOps::takeover_supported`。
        if !self.ops.takeover_supported() {
            return;
        }
        // 守卫：受控 IP 在 bootstrap-direct → fail-closed 不接管。
        if !is_controlled_dns_ip_valid(&self.marker.controlled_ip) {
            return;
        }

        let Ok(targets) = self.ops.list_targets() else {
            return;
        };
        if targets.is_empty() {
            return;
        }

        // 读当前 DNS + 防自指计算原始值。
        let current = self.snapshot_current(&targets);
        let existing = self.marker.read();
        let original = compute_original_to_save(
            &current,
            &self.marker.controlled_ip,
            existing.as_ref().map(|m| &m.original),
        );

        // marker 前置写（intent）。
        self.original = Some(original.clone());
        self.marker.write(&original);

        // apply（整循环重试，非逐 target 单独重试——上游 `setDns` 的 `retry()` 包裹的是整个
        // for-loop：单条 target 抖动失败即整轮重跑，幂等安全，重复 apply 受控 IP 无害）。
        // 任一 attempt 耗尽重试后仍失败 → best-effort 回滚还原（不抛）。
        let controlled_ip = self.marker.controlled_ip.clone();
        let ops = &self.ops;
        let result = retry_op(
            &DNS_SET_RETRY,
            || -> Result<(), SystemIntegrationError> {
                for t in &targets {
                    ops.apply_dns(t, std::slice::from_ref(&controlled_ip))?;
                }
                Ok(())
            },
            self.sleeper,
        );
        if result.is_err() {
            // 失败兜底：还原以免半接管残留；还原失败补清 marker。
            if !self.restore_dns_inner() {
                self.marker.clear();
            }
        }
    }

    /// 还原系统 DNS。无 marker/原始 → 仅清 marker。上游 `restoreDns`。
    pub fn restore_dns(&mut self) {
        // 不接管的平台（win/linux）：**仍要清 marker** —— 清掉历史版本（旧版 netsh 失败）残留的
        // stuck marker，否则 has_marker 恒 true 致每个终态点/启动 recovery 反复空跑还原。
        // 对齐上游 `WindowsSystemDns.restoreDns` = `this.clearMarker()`。
        if !self.ops.takeover_supported() {
            self.original = None;
            self.marker.clear();
            return;
        }
        self.restore_dns_inner();
    }

    fn restore_dns_inner(&mut self) -> bool {
        let marker = self.marker.read();
        let original = self
            .original
            .clone()
            .or_else(|| marker.as_ref().map(|m| m.original.clone()));
        let Some(original) = original else {
            self.marker.clear();
            return true;
        };

        let targets = self
            .ops
            .list_targets()
            .unwrap_or_else(|_| original.keys().cloned().collect());
        let restore_targets = if targets.is_empty() {
            original.keys().cloned().collect::<Vec<_>>()
        } else {
            targets
        };

        // 逐服务 best-effort：单服务失败不阻断其余。
        let mut all_ok = true;
        for t in &restore_targets {
            if let Some(ips) = original.get(t) {
                if self.ops.apply_dns(t, ips).is_err() {
                    all_ok = false;
                }
            }
        }
        if all_ok {
            self.original = None;
            self.marker.clear();
            true
        } else {
            // 部分失败 → 保留 marker 交下次启动重试。
            false
        }
    }

    /// 热插重灌：接管激活中（marker 在）时，把「新出现 / 仍未受控」的服务也接管为受控 IP。
    /// 不变量：① 仅 marker 在才动手；② 先写 marker 再 apply；③ 只 apply 未受控服务（幂等）；
    /// ④ best-effort 逐服务；⑤ 防自指（mergedOriginal 以既有 marker.original 为底）。
    /// 上游 `reconcileDns`。
    pub fn reconcile_dns(&mut self) {
        // 守卫：本平台不接管 DNS → 无物可重灌（marker 也不会有）。
        if !self.ops.takeover_supported() {
            return;
        }
        // 守卫：受控 IP 在 bootstrap-direct → fail-closed。
        if !is_controlled_dns_ip_valid(&self.marker.controlled_ip) {
            return;
        }
        let Some(marker) = self.marker.read() else {
            // marker 不在 = 接管未激活 → 绝不擅自接管。
            return;
        };

        let Ok(targets) = self.ops.list_targets() else {
            return;
        };
        if targets.is_empty() {
            return;
        }

        let current = self.snapshot_current(&targets);

        // 以既有 marker.original 为底，并入当前各服务的应保存原始（防自指）。
        let mut merged = marker.original.clone();
        let computed =
            compute_original_to_save(&current, &self.marker.controlled_ip, Some(&merged));
        for (k, v) in computed {
            merged.insert(k, v);
        }

        // 只 apply 未受控服务。
        let to_apply: Vec<&String> = targets
            .iter()
            .filter(|t| {
                let ips = current.get(*t);
                !matches!(ips, Some(ips) if is_controlled(ips, &self.marker.controlled_ip))
            })
            .collect();
        if to_apply.is_empty() {
            return; // 全部已受控 → 幂等 no-op。
        }

        // 先写 marker 再 apply（崩溃留 intent）。
        self.original = Some(merged.clone());
        self.marker.write(&merged);

        for t in to_apply {
            let _ = self
                .ops
                .apply_dns(t, std::slice::from_ref(&self.marker.controlled_ip));
        }
    }

    /// 是否存在接管 marker（终态清理门控用）。
    pub fn has_marker(&self) -> bool {
        self.marker.exists()
    }
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests;
