//! 系统能力类 command（上游 `system-handlers.ts` + 系统代理/DNS 设置）。
//!
//! 映射 channel：
//! - `system:listProcesses` → [`system_list_processes`]（路由规则的进程快速选择器）
//!
//! 进程枚举按平台取**可执行真实路径**（picker 选出的 name/path 会成为 processName/processPath
//! 路由规则值，必须与 sing-box 的进程匹配口径一致，否则据其建的规则永不命中 → 静默路由失效）：
//! - Linux：读 `/proc/<pid>/exe`（readlink 得完整可执行路径——无 comm 的 15 字符截断、含空格无碍），
//!   basename → name；exe 不可读（内核线程/权限）时回退 `/proc/<pid>/comm` 或 cmdline argv\[0\]；
//! - macOS/BSD：`ps -axo comm=`（**单列**：每行即完整 comm/路径，无第二列可误切；`=` 抑制 `COMM` 表头），
//!   basename → name；
//! - Windows：`tasklist /fo csv /nh`（CSV 首字段带引号 = 映像名；tasklist 不给路径 → `None`）。
//!
//! 解析层是**纯函数**（captured 样本驱动，跨平台可单测）；平台差异只在「读哪个源 / 怎么解析」的运行时
//! [`Platform`] 分派里。**绝不对合并了多列的整行做空白切分**——否则 `Google Chrome Helper` /
//! `Web Content` / `tmux: server` 之类含空格的名字会被切碎（`name="Google"` / `path="Chrome.app/…"`）。

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use tauri::State;

use polaris_helper_proto::Platform;
use polaris_system_integration::{Command, CommandRunner, StdCommandRunner};

use crate::response::ApiResponse;
use crate::runtime::AppRuntime;

/// 进程枚举命令的硬超时（本机 `ps`/`tasklist` 均在毫秒级返回；5s 仅作挂起兜底）。
const PROCESS_LIST_TIMEOUT: Duration = Duration::from_secs(5);

/// 进程信息（上游 `SystemProcessInfo`，`ui/src/contracts/types/rules.ts:81`）。
///
/// 按进程名聚合：`count` = 同名进程数，`path` = 首个带可执行路径的实例（`tasklist` 不给路径 → `None`）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemProcessInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub count: u32,
}

/// 可供 sing-box `bind_interface` 使用的系统网卡。`name` 是内核实际接受的 OS 接口名，
/// `display_name` 只用于展示。Windows 必须用 InterfaceAlias，Adapter GUID 不被 sing-box 接受。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkInterfaceInfo {
    pub name: String,
    pub display_name: String,
    pub is_up: bool,
    pub addresses: Vec<String>,
}

#[cfg(unix)]
fn enumerate_unix_interfaces(
    display_names: &BTreeMap<String, String>,
) -> Vec<NetworkInterfaceInfo> {
    use nix::ifaddrs::getifaddrs;
    use nix::net::if_::InterfaceFlags;

    let Ok(addrs) = getifaddrs() else {
        return Vec::new();
    };
    let mut by_name: BTreeMap<String, NetworkInterfaceInfo> = BTreeMap::new();
    for ifa in addrs {
        if ifa.flags.contains(InterfaceFlags::IFF_LOOPBACK) {
            continue;
        }
        let name = ifa.interface_name;
        let row = by_name
            .entry(name.clone())
            .or_insert_with(|| NetworkInterfaceInfo {
                display_name: display_names
                    .get(&name)
                    .cloned()
                    .unwrap_or_else(|| name.clone()),
                name,
                is_up: false,
                addresses: Vec::new(),
            });
        row.is_up |= ifa.flags.contains(InterfaceFlags::IFF_UP);
        if let Some(address) = ifa.address {
            if let Some(v4) = address.as_sockaddr_in() {
                row.addresses.push(v4.ip().to_string());
            } else if let Some(v6) = address.as_sockaddr_in6() {
                row.addresses.push(v6.ip().to_string());
            }
        }
    }
    let mut out: Vec<_> = by_name.into_values().collect();
    for row in &mut out {
        row.addresses.sort();
        row.addresses.dedup();
    }
    out.sort_by(|a, b| {
        b.is_up
            .cmp(&a.is_up)
            .then_with(|| a.display_name.cmp(&b.display_name))
    });
    out
}

#[cfg(not(unix))]
fn enumerate_unix_interfaces(_: &BTreeMap<String, String>) -> Vec<NetworkInterfaceInfo> {
    Vec::new()
}

fn macos_interface_display_names() -> BTreeMap<String, String> {
    let command = Command::new("networksetup", ["-listnetworkserviceorder"]);
    StdCommandRunner
        .run(&command, PROCESS_LIST_TIMEOUT)
        .map(|out| {
            polaris_system_integration::proxy_ops::parse_mac_service_order(&out.stdout)
                .into_iter()
                .map(|(service, device)| (device, service))
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn list_network_interfaces_blocking() -> Vec<NetworkInterfaceInfo> {
    match Platform::current() {
        Platform::Mac => enumerate_unix_interfaces(&macos_interface_display_names()),
        Platform::Linux | Platform::Other => enumerate_unix_interfaces(&BTreeMap::new()),
        Platform::Win => {
            #[cfg(windows)]
            {
                polaris_helper::platform::windows::netinfo::enumerate_network_adapters()
                    .into_iter()
                    .filter(|row| !row.is_loopback)
                    .map(|row| NetworkInterfaceInfo {
                        name: row.name,
                        display_name: row.display_name,
                        is_up: row.is_up,
                        addresses: row.addresses,
                    })
                    .collect()
            }
            #[cfg(not(windows))]
            Vec::new()
        }
    }
}

/// macOS 进程枚举命令：只给 `ps` 子进程注入 UTF-8 locale，避免非 UTF-8 会话下应用名被替换或截断。
/// 不修改 Polaris 进程环境，也不把 locale 能力扩散到通用 [`Command`] 抽象。
fn macos_ps_command() -> Command {
    Command::new(
        "/usr/bin/env",
        [
            "LC_ALL=en_US.UTF-8",
            "LANG=en_US.UTF-8",
            "/bin/ps",
            "-axo",
            "comm=",
        ],
    )
}

/// Windows 进程枚举命令：`tasklist /fo csv /nh`（CSV 无表头，首字段 = 映像名；不提供路径）。
fn windows_tasklist_command() -> Command {
    Command::new("tasklist", ["/fo", "csv", "/nh"])
}

/// 取路径 basename（去目录段）。用作聚合键的进程名（`comm`/exe 在 macOS/Linux 常是可执行全路径）。
fn basename(s: &str) -> String {
    s.rsplit(['/', '\\']).next().unwrap_or(s).to_string()
}

/// 解析 `ps -axo comm=` 单列输出：每行 = 一个进程的 comm（macOS 常为完整可执行路径，可含空格）。
fn parse_comm_column_output(stdout: &str) -> Vec<SystemProcessInfo> {
    aggregate(stdout.lines().filter_map(parse_comm_line))
}

/// 单行 comm → (name, path?)。**整行**即名字/路径——绝不空白切分；name = basename，含分隔符则整行即 path。
fn parse_comm_line(line: &str) -> Option<(String, Option<String>)> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let name = basename(line);
    if name.is_empty() {
        return None;
    }
    let path = (line.contains('/') || line.contains('\\')).then(|| line.to_string());
    Some((name, path))
}

/// 从 `/proc/<pid>` 三来源解析单个 Linux 进程的 (name, path?)。
///
/// 优先级：`exe`（readlink 真实完整路径——无 15 字符 comm 截断、含空格无碍）→ `comm`（exe 不可读时的
/// 名字回退，无路径）→ cmdline argv\[0\]（comm 也缺时）。全空 → `None`（跳过）。
fn resolve_linux_process(
    exe: Option<&str>,
    comm: Option<&str>,
    cmdline_argv0: Option<&str>,
) -> Option<(String, Option<String>)> {
    if let Some(exe) = exe.map(str::trim).filter(|s| !s.is_empty()) {
        // exe readlink 可能带 " (deleted)" 后缀（二进制已被删/替换）——剥离再取 basename。
        let clean = exe.strip_suffix(" (deleted)").unwrap_or(exe);
        let name = basename(clean);
        if !name.is_empty() {
            return Some((name, Some(clean.to_string())));
        }
    }
    if let Some(comm) = comm.map(str::trim).filter(|s| !s.is_empty()) {
        return Some((comm.to_string(), None));
    }
    if let Some(argv0) = cmdline_argv0.map(str::trim).filter(|s| !s.is_empty()) {
        let name = basename(argv0);
        if !name.is_empty() {
            let path = argv0.contains('/').then(|| argv0.to_string());
            return Some((name, path));
        }
    }
    None
}

/// `/proc/<pid>/cmdline` 的 argv\[0\]（NUL 分隔；空 → `None`，如内核线程）。
fn read_cmdline_argv0(path: &std::path::Path) -> Option<String> {
    let raw = std::fs::read(path).ok()?;
    let argv0 = raw.split(|&b| b == 0).next()?;
    if argv0.is_empty() {
        return None;
    }
    String::from_utf8(argv0.to_vec()).ok()
}

/// 枚举 Linux 进程：遍历 `/proc/<pid>`，每 pid 读 exe/comm/cmdline → [`resolve_linux_process`] → 聚合。
fn enumerate_linux_processes() -> Result<Vec<SystemProcessInfo>, String> {
    let entries = std::fs::read_dir("/proc").map_err(|e| format!("读取 /proc 失败: {e}"))?;
    let rows = entries.flatten().filter_map(|entry| {
        let file_name = entry.file_name();
        let pid = file_name.to_str()?;
        // 只认纯数字 pid 目录（跳过 /proc/self、/proc/meminfo 等非进程项）。
        if pid.is_empty() || !pid.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let dir = entry.path();
        let exe = std::fs::read_link(dir.join("exe"))
            .ok()
            .and_then(|p| p.to_str().map(str::to_string));
        let comm = std::fs::read_to_string(dir.join("comm")).ok();
        let argv0 = read_cmdline_argv0(&dir.join("cmdline"));
        resolve_linux_process(exe.as_deref(), comm.as_deref(), argv0.as_deref())
    });
    Ok(aggregate(rows))
}

/// 取 CSV 一行的首字段（tasklist `/fo csv` 各字段带双引号；映像名内无引号）。
fn csv_first_field(line: &str) -> String {
    let line = line.trim();
    if let Some(rest) = line.strip_prefix('"') {
        return rest.split('"').next().unwrap_or(rest).to_string();
    }
    line.split(',').next().unwrap_or("").trim().to_string()
}

fn parse_tasklist_output(stdout: &str) -> Vec<SystemProcessInfo> {
    aggregate(stdout.lines().filter_map(|line| {
        let name = csv_first_field(line);
        // tasklist 不提供路径 → path 恒 None。
        (!name.is_empty()).then_some((name, None))
    }))
}

/// 按 name 聚合行 → `count` + 首个可用 `path`。输出按 count 降序、同数按 name 升序（确定性，利 UI/测试）。
fn aggregate(rows: impl IntoIterator<Item = (String, Option<String>)>) -> Vec<SystemProcessInfo> {
    let mut order: Vec<String> = Vec::new();
    let mut map: HashMap<String, (u32, Option<String>)> = HashMap::new();
    for (name, path) in rows {
        if name.is_empty() {
            continue;
        }
        let entry = map.entry(name.clone()).or_insert_with(|| {
            order.push(name.clone());
            (0, None)
        });
        entry.0 = entry.0.saturating_add(1);
        if entry.1.is_none() {
            entry.1 = path;
        }
    }
    let mut out: Vec<SystemProcessInfo> = order
        .into_iter()
        .map(|name| {
            let (count, path) = map.remove(&name).unwrap_or((0, None));
            SystemProcessInfo { name, path, count }
        })
        .collect();
    out.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
    out
}

/// 按平台阻塞枚举进程（读 `/proc` 或跑 `ps`/`tasklist`）。在 [`system_list_processes`] 的
/// `spawn_blocking` 里调——含同步 IO / 子进程等待，不得在 async executor 线程直跑。
fn list_processes_blocking() -> Result<Vec<SystemProcessInfo>, String> {
    match Platform::current() {
        Platform::Linux => enumerate_linux_processes(),
        Platform::Win => {
            let out = StdCommandRunner.run(&windows_tasklist_command(), PROCESS_LIST_TIMEOUT)?;
            Ok(parse_tasklist_output(&out.stdout))
        }
        // macOS / BSD / Other 均有 POSIX `ps`，`-axo comm=` 单列输出。
        Platform::Mac | Platform::Other => {
            let out = StdCommandRunner.run(&macos_ps_command(), PROCESS_LIST_TIMEOUT)?;
            Ok(parse_comm_column_output(&out.stdout))
        }
    }
}

/// 上游 `SYSTEM_LIST_PROCESSES`：枚举系统进程（路由规则的进程快速选择器用）。
///
/// **`async fn` + `spawn_blocking`**：枚举要读 `/proc` 或跑 `ps`/`tasklist`（0.5–2s，5s 超时），
/// Tauri 同步 command 跑在**主线程**上会冻 UI（与 `http.rs` CoreDownloader 同纪律）→ 卸到 blocking
/// 线程池。失败（`/proc` 不可读 / 命令缺失 / 超时 / 非零退出）→ 显式 `err`，而非静默返空数组：picker
/// 「拉不到进程」与「一个都没有」语义不同，前端据此可提示重试。
#[tauri::command]
pub async fn system_list_processes(
    _state: State<'_, AppRuntime>,
) -> Result<ApiResponse<Vec<SystemProcessInfo>>, ()> {
    match tokio::task::spawn_blocking(list_processes_blocking).await {
        Ok(Ok(procs)) => Ok(ApiResponse::ok(procs)),
        Ok(Err(e)) => {
            log::warn!("枚举系统进程失败: {e}");
            Ok(ApiResponse::err(format!("枚举系统进程失败: {e}")))
        }
        Err(e) => {
            log::warn!("进程枚举任务失败: {e}");
            Ok(ApiResponse::err("进程枚举任务失败"))
        }
    }
}

/// 枚举代理内核可绑定的系统网卡。纯只读，不修改路由、DNS 或接口状态。
#[tauri::command]
pub async fn system_list_network_interfaces(
    _state: State<'_, AppRuntime>,
) -> Result<ApiResponse<Vec<NetworkInterfaceInfo>>, ()> {
    match tokio::task::spawn_blocking(list_network_interfaces_blocking).await {
        Ok(items) => Ok(ApiResponse::ok(items)),
        Err(error) => {
            log::warn!("网卡枚举任务失败: {error}");
            Ok(ApiResponse::err("network_interface_list_failed"))
        }
    }
}

#[cfg(test)]
mod tests;
