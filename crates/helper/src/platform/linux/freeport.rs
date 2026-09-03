//! freeport —— 按端口找 LISTEN 持有者，仅作用于对端 uid 自己的 sing-box 进程（移植自 上游 `helper-linux/helper.go:287-331`）。
//!
//! ## 安全模型（对照 Go 源注释 :290-291）
//!
//! - 按 `ss -H -ltnp 'sport = :<port>'` 找 LISTEN 持有者。
//! - **仅作用于对端 uid 自己的进程**（`/proc/<pid>` 属主 == callerUID）—— 跨用户防误杀。
//! - 是 sing-box 才 kill（SIGKILL），否则回报占用者名（不杀无辜）。
//! - ss 缺失 / 无占用 → `OK free`。
//!
//! ## 移植纪律
//!
//! Go 源 `freePort(port, callerUID)` 返回 wire 行字符串。本实现拆为：
//! - [`parse_ss_pids`]：纯正则提取 pid（移植自 Go `ssPidRe`）。
//! - [`free_port`]：组合逻辑，进程操作经 [`FreePortDeps`] trait 抽象（测试 mock /proc 读 + kill）。
//!   结果直接产出协议类型 [`FreePort`]（原有个逐变体同构的 `FreePortOutcome` 影子枚举 +
//!   `to_wire_line`/`to_response_kind` 双向映射，已删 —— wire 序列化归 `Response::to_wire_line`，
//!   见 G3.1/G3.3）。
//!
//! **持有者定位机制（`ss` + `/proc` 属主 + comm）是 linux 真差异，保留本 crate**；
//! 与 mac（lsof + ps）共享的只有「结果形状」，那部分归协议层。

use polaris_helper_proto::response::FreePort;

/// freeport 的进程操作依赖（trait 便于测试 mock；生产用 [`ProdFreePortDeps`]）。
///
/// 抽象 `/proc/<pid>/comm` 读 + `/proc/<pid>` 属主 + kill(2)，让逻辑在不碰宿主前提下测试。
pub trait FreePortDeps: Send + Sync {
    /// `/proc/<pid>` 属主 uid（Go `procUID`，:158-167）。None = 进程已退出 / 读失败。
    fn proc_uid(&self, pid: u32) -> Option<u32>;
    /// `/proc/<pid>/comm` 进程名（Go :311，trim 后）。None = 读失败（当不存在）。
    fn proc_comm(&self, pid: u32) -> Option<String>;
    /// kill(pid, SIGKILL)（Go :316）。返回是否成功发送（对死进程也视作发送）。
    fn kill(&self, pid: u32) -> bool;
}

/// 生产实现：直接读 /proc + kill(2)。
#[derive(Debug, Default, Clone)]
pub struct ProdFreePortDeps;

impl FreePortDeps for ProdFreePortDeps {
    fn proc_uid(&self, pid: u32) -> Option<u32> {
        // Go: os.Stat("/proc/<pid>") → Stat_t.Uid
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(format!("/proc/{pid}"))
            .ok()
            .map(|m| m.uid())
    }

    fn proc_comm(&self, pid: u32) -> Option<String> {
        // Go: os.ReadFile("/proc/<pid>/comm") → TrimSpace
        let s = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
        Some(s.trim().to_string())
    }

    fn kill(&self, pid: u32) -> bool {
        // nix::sys::signal::kill 是 kill(2) 的 safe wrapper（forbid(unsafe_code) 下替代 libc::kill 的 unsafe FFI）。
        // 对死进程返回 ESRCH（视作 false，Go syscall.Kill 同语义）。
        let nix_pid = nix::unistd::Pid::from_raw(pid as i32);
        nix::sys::signal::kill(nix_pid, nix::sys::signal::Signal::SIGKILL).is_ok()
    }
}

/// ss -ltnp 输出里提取 pid（移植自 Go `ssPidRe = regexp.MustCompile("pid=(\\d+)")`，:287）。
///
/// 返回去重后的 pid 列表（Go 用 map\[string\]bool 去重，:296-299）。
#[must_use]
pub fn parse_ss_pids(ss_output: &str) -> Vec<u32> {
    let mut pids: Vec<u32> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    // 手写提取 "pid=<digits>"（避免引 regex 依赖；Go 用 regexp，语义等价）。
    for hit in ss_output.match_indices("pid=") {
        let rest = &ss_output[hit.0 + 4..];
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(n) = digits.parse::<u32>() {
            if seen.insert(n) {
                pids.push(n);
            }
        }
    }
    pids
}

/// freeport 主逻辑（移植自 Go `freePort`，:291-331）。
///
/// 参数：
/// - `pids`：从 ss 输出提取的 LISTEN 持有者 pid 列表（空 → `OK free`）。
/// - `caller_uid`：对端进程 uid（跨用户防误杀边界）。
/// - `deps`：进程操作依赖（mock / prod）。
pub fn free_port(pids: &[u32], caller_uid: u32, deps: &dyn FreePortDeps) -> FreePort {
    if pids.is_empty() {
        return FreePort::Free;
    }
    let mut killed: Vec<u32> = Vec::new();
    let mut foreign: Vec<String> = Vec::new();
    for &pid in pids {
        // :305-308: 跨用户防误杀 —— 非 caller_uid 的进程一律不动，记 foreign。
        match deps.proc_uid(pid) {
            Some(uid) if uid == caller_uid => {}
            _ => {
                foreign.push(format!("pid:{pid}"));
                continue;
            }
        }
        // :310-313: 读 comm 判定是否 sing-box。
        let comm = deps.proc_comm(pid).unwrap_or_default();
        if comm.contains("sing-box") {
            // :316: kill SIGKILL。
            deps.kill(pid);
            killed.push(pid);
        } else {
            // :319-323: 非 sing-box → 记名（不杀）。
            let name = if comm.is_empty() {
                format!("pid:{pid}")
            } else {
                comm
            };
            foreign.push(name);
        }
    }
    // :327-330: 有 foreign → foreign（混合占用亦归此）；否则 killed。
    if !foreign.is_empty() {
        FreePort::Foreign { names: foreign }
    } else {
        FreePort::Killed { pids: killed }
    }
}

#[cfg(test)]
mod tests;
