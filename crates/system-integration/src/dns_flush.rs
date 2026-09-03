//! OS 级 DNS 缓存刷新命令构造（三平台，best-effort）。
//!
//! 1:1 移植自 上游 `os-dns-flush.ts`。模块只构造命令 + 编排降级；真实 exec 经 trait 注入（不触碰宿主）。
//!
//! 不变量（对齐 Polaris）：永不抛——刷缓存是增益项，绝不阻塞代理生命周期；每个命令 3s 硬超时。

#![forbid(unsafe_code)]

use crate::exec::{Command, CommandRunner};
use polaris_helper_proto::Platform;
use std::time::Duration;

/// 单个外部命令硬超时（上游 `EXEC_TIMEOUT_MS`）。
pub const EXEC_TIMEOUT: Duration = Duration::from_secs(3);

/// 一条刷缓存命令。
///
/// 单一真值在 [`crate::exec::Command`]（此前本模块的 `FlushCommand` 与 `proxy_ops::Command` 是两份
/// 逐字相同的 `{program, args}` —— 假差异，已合并）。别名保留移植血缘可读性。
pub type FlushCommand = Command;

/// 命令执行器（注入便于 mock；真实实现带超时）。
/// 失败返回 Err（调用方降级为告警，不抛）。
pub trait FlushExec {
    fn exec(&self, cmd: &FlushCommand, timeout: Duration) -> Result<(), String>;
}

/// [`FlushExec`] 的生产实现：委托 [`CommandRunner`]（硬超时在其中落实）。
///
/// **不是多余的一层**：`FlushExec` 是 flush 的**语义**缝（契约=「失败返 Err，调用方降级为告警」），
/// `CommandRunner` 是**执行**缝。此 impl 让任意 runner（含生产 `StdCommandRunner`）直接当 flush 执行器用，
/// 同时保留 `FlushExec` 的独立 mock 面。
impl<R: CommandRunner> FlushExec for R {
    fn exec(&self, cmd: &FlushCommand, timeout: Duration) -> Result<(), String> {
        self.run(cmd, timeout).map(|_| ())
    }
}

/// macOS 用户级降级命令：`dscacheutil -flushcache`。
/// 上游 `flushOsDnsCache` darwin 降级腿。
pub fn mac_user_flush_command() -> FlushCommand {
    Command::new("/usr/bin/dscacheutil", ["-flushcache"])
}

/// Windows 命令：`ipconfig /flushdns`。
///
/// 用 System32 绝对路径（上游 `WindowsSystemProxy` 的 `ipconfigExe = system32('ipconfig.exe')` 同因）：
/// 部分设备 PATH 缺 `C:\Windows\System32` → 裸 `ipconfig` 报「不是内部或外部命令」。见 [`crate::exec::system32`]。
pub fn windows_flush_command() -> FlushCommand {
    Command::new(
        crate::exec::system32_from_env("ipconfig.exe"),
        ["/flushdns"],
    )
}

/// Linux 命令：`resolvectl flush-caches`。
///
/// **无回退，与上游一致**（`os-dns-flush.ts:82`）。曾有一份 `helper/platform/linux/ops.rs::TokioDns`
/// 带 `resolvconf -u` 回退与本函数分叉；2026-07-16 调和时判定其**无上游、不可达、语义非刷缓存**并删除
/// （判据见该文件「系统 DNS 刷新」段）。**已知缺口**：非 systemd 且跑 nscd/dnsmasq 的机器不刷 —— 上游同样如此。
pub fn linux_flush_command() -> FlushCommand {
    Command::new("resolvectl", ["flush-caches"])
}

/// helper flush 结果（macOS root helper 通道）。上游 `helperFlushDns` 返回。
#[derive(Debug, Clone, Default)]
pub struct HelperFlushResult {
    pub ok: bool,
    pub partial: Option<String>,
    pub error: Option<String>,
}

/// helper flush 通道（mac root helper；缺省 None = 不可用走用户级降级）。
pub type HelperFlushFn<'a> = Option<&'a dyn Fn() -> HelperFlushResult>;

/// 刷 OS DNS 缓存。best-effort、永不抛（失败仅 on_warn）。
///
/// - mac：helper 可用且 ok → 用 helper；否则降级 `dscacheutil -flushcache`。
/// - win：`ipconfig /flushdns`。
/// - linux：`resolvectl flush-caches`。
/// - 其它：no-op。
///
/// 上游 `flushOsDnsCache`。
pub fn flush_os_dns_cache<E: FlushExec>(
    platform: Platform,
    exec: &E,
    helper_flush: HelperFlushFn,
    on_warn: &mut dyn FnMut(&str),
) -> bool {
    match platform {
        Platform::Mac => {
            if let Some(helper) = helper_flush {
                let r = helper();
                if r.ok {
                    if r.partial.is_some() {
                        on_warn(&format!(
                            "已刷新系统 DNS 缓存（helper root，partial：{}）",
                            r.partial.unwrap_or_default()
                        ));
                    }
                    // ok（无论 partial）→ 不降级。
                    return true;
                }
                on_warn(&format!(
                    "helper flush-dns 不可用（{}），降级用户级 dscacheutil",
                    r.error.unwrap_or_else(|| "未知".into())
                ));
            }
            // 用户级降级。
            exec.exec(&mac_user_flush_command(), EXEC_TIMEOUT)
                .map(|()| true)
                .unwrap_or_else(|e| {
                    on_warn(&format!("刷新系统 DNS 缓存失败（忽略）: {e}"));
                    false
                })
        }
        Platform::Win => exec
            .exec(&windows_flush_command(), EXEC_TIMEOUT)
            .map(|()| true)
            .unwrap_or_else(|e| {
                on_warn(&format!("刷新系统 DNS 缓存失败（忽略）: {e}"));
                false
            }),
        Platform::Linux => exec
            .exec(&linux_flush_command(), EXEC_TIMEOUT)
            .map(|()| true)
            .unwrap_or_else(|e| {
                on_warn(&format!("刷新系统 DNS 缓存失败（忽略）: {e}"));
                false
            }),
        Platform::Other => true,
    }
}

#[cfg(test)]
mod tests;
