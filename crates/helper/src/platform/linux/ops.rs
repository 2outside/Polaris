//! 系统操作 trait 抽象 —— systemctl / ip route / TUN tuntap 的可测试边界。
//!
//! ## 设计动机（§D 特权矩阵 + 移植纪律 #4）
//!
//! Polaris Go 源 `helper-linux/helper.go` 用 AmbientCaps 把 CAP_NET_ADMIN 挂在 sing-box 进程上，
//! **TUN/路由由核 sing-tun 自己装**（非 helper 装路由）。但本任务要求把所有系统操作用 trait 抽象、测试 mock、
//! 不碰宿主网络。故把 helper 侧的系统副作用归类为三组 trait：
//!
//! - [`SystemdOps`]：systemd unit 安装/启停（任务职责 1，对照 §D.3 systemd 行）。
//! - [`TunOps`]：TUN 接口创建/销毁（任务职责 3，对照 上游 `ip tuntap` / ioctl）。
//! - [`RouteOps`]：路由表操作（任务职责 4，对照 上游 `ip route`）。
//!
//! **DNS 刷新不在此列**（2026-07-16 调和）：上游 Linux helper 无 DNS 命令，且刷缓存非提权操作 →
//! 单一真值在 `system-integration::dns_flush`（app 进程侧）。判据见下方「系统 DNS 刷新」段。
//!
//! 每组 trait 有生产实现（经 `tokio::process::Command` 调 `systemctl`/`ip`）与
//! mock 实现（记录调用、可断言），让命令处理逻辑在不碰宿主的前提下全路径测试。
//!
//! 不变式：所有命令处理函数只依赖 trait（不直接 Command::new），测试注入 mock 即可断言副作用。
//!
//! ## DESIGN-REVIEW(linux-ops-dormant)：TunOps / RouteOps / SystemdOps **忠实休眠**（C6-2 决策）
//!
//! Go 源 `helper-linux/helper.go` 的命令集 = ping|version|status|start|stop|cleanup|freeport|install-core
//! —— **无 route / tun / systemd 命令**：核 sing-tun 自建 TUN + 自装路由（CAP_NET_ADMIN 在 ambient set，
//! 见 [`server::apply_privilege_drop`](crate::platform::linux::server)），helper 侧不碰路由。故本三组 trait
//! 是 Polaris 自有增强（range-expansion，[[polaris-code-audit]] §3.3）：**保留但不接 `handler` dispatch**
//! （铁律：非缺陷不删自有）。价值待未来（手动 tuntap 模式 / helper 自管 systemd unit）兑现时接线。
//! `SystemdOps` 仍在 [`HandlerDeps`](crate::platform::linux::handler::HandlerDeps) 里占位（同休眠），
//! 无命令消费。

// std::path::Path 在本模块的测试中被引用（path_type_referenced 测试）。
#[cfg(test)]
use std::path::Path;

// ===== systemd 服务管理（任务职责 1）=====

/// systemd unit 操作请求（安装/启动/停止 helper 服务）。
///
/// 对照 §D.3 systemd 行：helper 作为 root system service，装一次（pkexec 一次授权）后
/// 普通用户 app 经 socket 零提权启停 sing-box。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemdAction {
    /// 安装 unit 文件 + daemon-reload + enable（首次部署）。
    Install,
    /// systemctl start `<unit>`。
    Start,
    /// systemctl stop `<unit>`。
    Stop,
    /// systemctl restart `<unit>`。
    Restart,
    /// 自卸载：stop + disable + remove unit + daemon-reload。
    Uninstall,
}

impl SystemdAction {
    /// 对应的 systemctl 子命令名（便于生产实现拼 argv）。
    #[must_use]
    pub const fn systemctl_verb(self) -> &'static str {
        match self {
            Self::Install => "enable",
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
            Self::Uninstall => "disable",
        }
    }
}

/// systemd 操作结果（成功无 payload；失败带 stderr 尾部文本供诊断）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdResult {
    /// 是否成功（systemctl exit code == 0）。
    pub ok: bool,
    /// 失败时的 stderr/stdout 合并文本（trim 后）。
    pub detail: String,
}

impl Default for SystemdResult {
    /// 默认 = 成功无 payload（mock 构造用，对齐 [`SystemdResult::ok`]）。
    fn default() -> Self {
        Self {
            ok: true,
            detail: String::new(),
        }
    }
}

impl SystemdResult {
    /// 成功（无 payload）。
    #[must_use]
    pub const fn ok() -> Self {
        Self {
            ok: true,
            detail: String::new(),
        }
    }

    /// 失败，带诊断文本。
    #[must_use]
    pub fn err(detail: impl Into<String>) -> Self {
        Self {
            ok: false,
            detail: detail.into(),
        }
    }
}

/// systemd 操作抽象（trait 便于测试 mock；生产用 [`TokioSystemd`]）。
pub trait SystemdOps: Send + Sync {
    /// 对指定 unit 执行 `action`。
    fn run(&self, unit: &str, action: SystemdAction) -> SystemdResult;
}

/// tokio::process 调 systemctl 的生产实现。
#[derive(Debug, Default, Clone)]
pub struct TokioSystemd;

impl TokioSystemd {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl SystemdOps for TokioSystemd {
    fn run(&self, unit: &str, action: SystemdAction) -> SystemdResult {
        // systemctl <verb> <unit>。Install/Uninstall 额外需要 daemon-reload，但本 helper 侧
        // 假定 unit 文件由安装器（pkexec 一次性）部署，helper 只做运行期 start/stop/restart。
        // verb 选用 systemctl_verb（enable/disable/start/stop/restart）。
        let output = std::process::Command::new("systemctl")
            .arg(action.systemctl_verb())
            .arg(unit)
            .output();
        match output {
            Ok(o) if o.status.success() => SystemdResult::ok(),
            Ok(o) => SystemdResult::err(trim_lossy(&o)),
            Err(e) => SystemdResult::err(e.to_string()),
        }
    }
}

// ===== TUN 接口（任务职责 3）=====

/// TUN 接口操作（对照 上游 `ip tuntap add` / sing-tun 自动建 tun）。
///
/// 注：Polaris Linux 用 AmbientCaps 让 sing-box 自建 TUN（CAP_NET_ADMIN 在核进程）。
/// 本 trait 抽象 helper 侧若需手动建/毁 TUN 的边界（如未来手动 tuntap 模式），
/// 当前主路径仍是核自建 —— trait 保留以覆盖 §D 特权矩阵的可测试性。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunAction {
    /// `ip tuntap add dev <name> mode tun`。
    Create { name: String },
    /// `ip tuntap del dev <name> mode tun`。
    Destroy { name: String },
}

/// TUN 操作抽象。
pub trait TunOps: Send + Sync {
    /// 执行 TUN 创建/销毁。成功返回空；失败返回诊断文本。
    fn run(&self, action: &TunAction) -> Result<(), String>;
}

/// 生产实现：`ip tuntap add/del`。
#[derive(Debug, Default, Clone)]
pub struct TokioTun;

impl TunOps for TokioTun {
    fn run(&self, action: &TunAction) -> Result<(), String> {
        let (verb, name) = match action {
            TunAction::Create { name } => ("add", name.as_str()),
            TunAction::Destroy { name } => ("del", name.as_str()),
        };
        let out = std::process::Command::new("ip")
            .args(["tuntap", verb, "dev", name, "mode", "tun"])
            .output()
            .map_err(|e| e.to_string())?;
        if out.status.success() {
            Ok(())
        } else {
            Err(trim_lossy(&out))
        }
    }
}

// ===== 路由表操作（任务职责 4）=====

/// 路由操作请求（对照 上游 `ip route add/del`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteAction {
    /// add 或 del。
    pub verb: RouteVerb,
    /// 目标 CIDR（如 `10.0.0.0/8`）。
    pub cidr: String,
    /// 下一跳 / 出口接口（如 `dev polaris-ts` 或 `via 10.0.0.1`）。
    pub via: String,
}

/// 路由增删动词。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteVerb {
    Add,
    Del,
}

impl RouteVerb {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Del => "del",
        }
    }
}

/// 路由操作抽象（trait 便于测试 mock；生产用 [`TokioRoute`]）。
pub trait RouteOps: Send + Sync {
    /// 执行 `ip route add/del <cidr> <via>`。成功返回空；失败返回诊断文本。
    fn run(&self, action: &RouteAction) -> Result<(), String>;
}

/// 生产实现：`ip route add/del`。
#[derive(Debug, Default, Clone)]
pub struct TokioRoute;

impl RouteOps for TokioRoute {
    fn run(&self, action: &RouteAction) -> Result<(), String> {
        let out = std::process::Command::new("ip")
            .args(["route", action.verb.as_str(), &action.cidr])
            .arg(&action.via)
            .output()
            .map_err(|e| e.to_string())?;
        if out.status.success() {
            Ok(())
        } else {
            Err(trim_lossy(&out))
        }
    }
}

// ===== 系统 DNS 刷新：不在 Linux helper 的职责内（2026-07-16 调和，勿重新加回）=====
//
// 此处曾有 `DnsOps` / `TokioDns` / `DnsFlushOutcome`（resolvectl + resolvconf -u 回退），已删。
// 判据（逐条对上游实证，非偏好）：
//
// 1. **无上游**：Polaris Go 源 `helper-linux/helper.go` 的命令集是
//    ping|version|status|stop|cleanup|freeport|install-core|start —— **没有任何 DNS 命令**。
//    `flush-dns` 只存在于 **macOS** helper（`helper/helper.go:492`），因为那里真需要 root
//    （`killall -HUP mDNSResponder`）。被删代码的 `OK flushed` / `OK flushed-partial` 结果枚举
//    正是从 mac helper 抄来的 —— 那是 `dscacheutil` + `HUP mDNSResponder` 两层缓存的语义，Linux 无对应物。
// 2. **权限层级错位**：Linux 的 `resolvectl flush-caches` 由 **app 进程非提权直接调**
//    （上游 `os-dns-flush.ts:82`）。放进 root helper 等于为一个不需要 root 的缓存刷新
//    加一次 IPC 往返 + 提权面。
// 3. **`resolvconf -u` 上游零出现**（全仓 .go/.ts grep 无命中），且它**不是缓存刷新** ——
//    它是从 resolvconf 数据库重新生成 /etc/resolv.conf。无 systemd-resolved 的机器通常
//    根本没有 OS 级 DNS 缓存（glibc 不缓存）→ 无物可刷。
// 4. **该回退在其立论场景里不可达**：`Command::output()` 只在**二进制缺失/无法 spawn** 时返 `Err`。
//    resolvectl 存在但 resolved 未运行 → 返 `Ok(非零退出)` → 走 `FlushedPartial`，**永不落到 resolvconf**。
//    即「systemd-resolved 装了但没跑」这个唯一值得回退的场景，回退根本不触发。
// 5. **零调用点**：`handler.rs` 从不 dispatch 到它，仅 `mod.rs` 重导出。
//
// 单一真值 → `crates/system-integration/src/dns_flush.rs`（1:1 移植 `os-dns-flush.ts`，app 进程侧，
// 三平台 + mac helper 通道）。**已知缺口**（上游同样没有，如实登记而非静默补）：非 systemd 的 Linux
// 若跑 nscd/dnsmasq 本地缓存，`resolvectl` 缺失 → 不刷。上游行为一致（仅 log warn）。

// ===== 辅助：stderr/stdout trim 为 String（utf8 lossy，对齐 Go string(out)）=====

fn trim_lossy(o: &std::process::Output) -> String {
    let mut s = String::new();
    if !o.stdout.is_empty() {
        s.push_str(&String::from_utf8_lossy(&o.stdout));
    }
    if !o.stderr.is_empty() {
        if !s.is_empty() {
            s.push(' ');
        }
        s.push_str(&String::from_utf8_lossy(&o.stderr));
    }
    s.trim().to_string()
}

/// IP 转发开关（移植自 Go `setForward`，:172-179）。
///
/// allowLan 时开 IPv4+IPv6 转发（直写 /proc/sys）；stop 复位为 0，使转发态严格跟随运行中的核。
/// best-effort（写失败静默忽略，Go: `_ = os.WriteFile(...)`）。
///
/// 抽象为闭包注入便于测试；生产用 [`set_forward_prod`]。
pub fn set_forward_prod(on: bool) {
    let v = if on { b"1" } else { b"0" };
    // best-effort：忽略失败（非 root / proc 未挂载等）。
    let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", v);
    let _ = std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", v);
}

#[cfg(test)]
mod tests;
