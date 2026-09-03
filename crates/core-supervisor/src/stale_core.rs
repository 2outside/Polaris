//! 启动期 stale-core 清扫 —— 父进程（Polaris）异常退出时，其 spawn 的 sing-box 子进程会存活
//! （§K2 边界声明：`Child` 无 `kill_on_drop`，panic 时 `rt.stop()` 不执行 → 孤儿核）。下次启动前
//! 须清掉这些孤儿核，否则它们占着端口/TUN 设备致新核起不来（Linux "resource busy"）。
//!
//! # 安全第一性：只杀「本 app 二进制起的」核
//!
//! 判定 = 进程 cmdline **同时**含 (1) 本 app 解析出的 sing-box 二进制**绝对路径**
//! （app 资源目录下，用户系统装的 sing-box 路径不同）且 (2) `run` 子命令 token —— 与 上游
//! `killOrphanedProcessesLinux`（`pgrep -f "<path> run"`）同判据。**绝不按进程名 `pkill sing-box`**：
//! 用户机器上可能装有无关的 sing-box，误杀是安全事故。
//!
//! 两者缺一不可：
//! - 只判 `run` → 会误杀任意 `xxx run`；
//! - 只判路径 → 会误杀 `less <path>` / `tar <path>` 等只是打开了核文件的进程（上游 P2-2 教训）。
//!
//! 纯判定（[`is_our_core`] / [`stale_pids`]）与 I/O 扫描（[`scan_running_cores`]）分离：
//! 前者可零进程单测，含「**非本 app 的 sing-box 不被选中**」变异门（`tests` 模块）。

use std::path::Path;

/// 扫描到的一个候选进程。
///
/// **两种载荷按平台二选一**（另一个留空），因为两个平台能拿到的保真度不同：
/// - `cmdline`：精确 argv（Linux `/proc/<pid>/cmdline`，NUL 分隔 → 无歧义）。
/// - `raw`：空格拼接的原始命令行（macOS `ps -axo args=`）。**ps 的输出是有损的**——argv 已被
///   空格拼死，无法还原。而 macOS 真实核路径恰恰含空格
///   （`/Library/Application Support/Polaris/core/sing-box`），按空白切分会把它劈成两段 →
///   路径全等比对必然失配 → 孤儿一个都扫不出来。故 macOS 只能按原始串匹配（同 上游 `pgrep -f`）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CoreProcess {
    pub pid: u32,
    /// 完整命令行 argv（Linux 取自 `/proc/<pid>/cmdline`，NUL 分隔）。非 Linux 为空。
    pub cmdline: Vec<String>,
    /// 原始命令行整串（macOS 取自 `ps -axo args=`）。Linux 为空。
    pub raw: String,
}

/// 该进程是否是「本 app 二进制起的」sing-box 核。
///
/// 判据（与 上游 同）：cmdline 中**存在一个参数等于本 app 的 sing-box 二进制绝对路径** `our_binary`，
/// **且**存在 `run` 子命令 token。路径按绝对路径相等判：本 app 的核在资源目录下，系统
/// `/usr/bin/sing-box` 路径不同 → 不匹配 → 不会误杀。
#[must_use]
pub fn is_our_core(cmdline: &[String], our_binary: &Path) -> bool {
    let has_binary = cmdline.iter().any(|a| Path::new(a) == our_binary);
    let has_run = cmdline.iter().any(|a| a == "run");
    has_binary && has_run
}

/// 原始命令行整串版判据（macOS `ps` 路径用）——判「串中是否出现 `<our_binary> run`」。
///
/// 与 [`is_our_core`] **同一安全契约**（路径 + run 两个条件缺一不可），只是因为 `ps` 丢了 argv
/// 边界而改用连续子串匹配 —— 与 上游 `pgrep -f "<singboxPath> run"` 逐字同源判据。
/// `less <path>` 不含 `<path> run` → 不匹配；系统 `/usr/bin/sing-box run` 路径不同 → 不匹配。
#[must_use]
pub fn is_our_core_raw(raw: &str, our_binary: &Path) -> bool {
    if raw.is_empty() {
        return false;
    }
    raw.contains(&format!("{} run", our_binary.display()))
}

/// 从候选进程中挑出「本 app 起的、需清理的」pid，排除 `exclude`（自身 / 当前受管 pid）。
///
/// 两种载荷任一命中即算本 app 的核（各平台只填其一，另一个恒空 → 空的那侧恒不命中）。
#[must_use]
pub fn stale_pids(candidates: &[CoreProcess], our_binary: &Path, exclude: &[u32]) -> Vec<u32> {
    candidates
        .iter()
        .filter(|c| is_our_core(&c.cmdline, our_binary) || is_our_core_raw(&c.raw, our_binary))
        .map(|c| c.pid)
        .filter(|p| !exclude.contains(p))
        .collect()
}

/// 扫描系统内在跑的候选进程。
///
/// Linux：直接读 `/proc/<pid>/cmdline`（无外部命令、无新依赖）。非 Linux：返回空
/// （本批边界，见模块文档；真机验证限 Linux）。
#[cfg(target_os = "linux")]
#[must_use]
pub fn scan_running_cores() -> Vec<CoreProcess> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        // 只看纯数字 pid 目录（跳过 /proc/self、/proc/cpuinfo 等）。
        let Some(pid) = name.to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(bytes) = std::fs::read(entry.path().join("cmdline")) else {
            continue; // 进程已退 / 无权限读 → 跳过。
        };
        if bytes.is_empty() {
            continue; // 内核线程 cmdline 为空。
        }
        // /proc/<pid>/cmdline 是 NUL 分隔的 argv；末尾可能有多余 NUL。
        let cmdline: Vec<String> = bytes
            .split(|b| *b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();
        if cmdline.is_empty() {
            continue;
        }
        out.push(CoreProcess {
            pid,
            cmdline,
            raw: String::new(),
        });
    }
    out
}

/// `ps -axo pid=,args=` 输出 → 候选进程（纯解析，可零进程单测）。
///
/// 每行 = 前导空格 + pid + 空白 + 命令行余部。**余部整串留作 `raw` 不再切分**——见
/// [`CoreProcess`] 的说明：macOS 核路径含空格，切分即失配。
#[cfg(any(target_os = "macos", test))]
#[must_use]
pub fn parse_ps_output(stdout: &str) -> Vec<CoreProcess> {
    stdout
        .lines()
        .filter_map(|line| {
            let (pid_s, rest) = line.trim_start().split_once(char::is_whitespace)?;
            let pid = pid_s.parse::<u32>().ok()?;
            let raw = rest.trim();
            (!raw.is_empty()).then(|| CoreProcess {
                pid,
                cmdline: Vec::new(),
                raw: raw.to_owned(),
            })
        })
        .collect()
}

/// macOS 孤儿扫描：`ps -axo pid=,args=` 全量列进程（`-a` 含他人进程 → **root 起的核也在列**，
/// 这正是 helper 提权路径遗留的孤儿；`-x` 含无控制终端的后台进程）。
///
/// **为什么必须有**：此前本函数在非 Linux 恒返空 ⇒ macOS 的启动期清扫是彻底的 no-op ⇒
/// helper 以 root 遗留的孤儿核永不被发现、永不被清理，一直占着 `cache.db` ⇒ 之后每次起核
/// 都 `initialize cache-file: timeout`，连切回 systemProxy 也起不来（真机实证的卡死链）。
#[cfg(target_os = "macos")]
#[must_use]
pub fn scan_running_cores() -> Vec<CoreProcess> {
    let Ok(out) = std::process::Command::new("/bin/ps")
        .args(["-axo", "pid=,args="])
        .output()
    else {
        return Vec::new();
    };
    parse_ps_output(&String::from_utf8_lossy(&out.stdout))
}

/// Windows 孤儿扫描（CIM/WMI 取 CommandLine）本批未实现 —— 边界声明，非静默省略。
/// `tasklist` 不输出命令行，无从施加「只杀本 app 二进制起的核」这条安全判据，故不用它凑数。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[must_use]
pub fn scan_running_cores() -> Vec<CoreProcess> {
    Vec::new()
}

#[cfg(test)]
mod tests;
