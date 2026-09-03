//! Windows 系统代理：注册表命令构造 + 输出解析 + QUIC 旧规则清理预热。

use super::model::{ProxyEnableRequest, WindowsProxyRegistryValues};
use crate::bypass::format_bypass_for_windows;
use crate::exec::{Command, CommandRunner};
use crate::proxy::{
    SystemProxyStatus, WindowsProxyRegistrySnapshot, WindowsRegistryDwordValue,
    WindowsRegistryStringValue,
};
use polaris_helper_proto::Platform;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Windows 旧版 QUIC 防火墙规则清理的独立预算。
///
/// 这条命令只是在代理启停时清扫旧版本可能遗留的 `Polaris_Block_QUIC`，不是系统代理成立条件；
/// 规则不存在或普通用户无权删除时都应 best-effort 让位。若与必要的注册表事务共用 10s 预算，
/// `netsh advfirewall` 在防火墙服务繁忙时会把已经成功的连接动作额外钉住十余秒
/// （Windows 真机 2026-08-20：15_254ms），用户看到的是“代理启动卡死”。750ms 足够健康本机命令
/// 完成，同时把可选清理的最坏墙钟锁在首次点击可接受的范围内；停止/恢复腿也复用同一预算。
pub(super) const WINDOWS_QUIC_CLEANUP_TIMEOUT: Duration = Duration::from_millis(750);

/// App 启动期是否已经把 Windows 旧 QUIC 规则清理移入后台预热。
///
/// 只有桌面应用生产 setup 会显式调用 [`start_windows_quic_cleanup_prewarm`]；库测试与其它调用方
/// 默认仍在 enable 内同步清理，不会因为构造一个生产 controller 就触碰宿主防火墙。
static WINDOWS_QUIC_PREWARM_STARTED: AtomicBool = AtomicBool::new(false);

/// 把旧版 `Polaris_Block_QUIC` 清理提前到 Windows App 启动期。
///
/// 该规则是历史迁移残件，不是系统代理成立条件。真机分段显示每次连接重复执行 `netsh` 的 p50 约
/// 129ms、长尾 837ms，且规则 10/10 不存在。预热仍完整执行同一条命令与 750ms 硬预算，只把它从
/// 用户点击连接的热路径移出；正常 stop/restore 腿继续保留清理兜底。
#[must_use]
pub fn start_windows_quic_cleanup_prewarm() -> bool {
    if Platform::current() != Platform::Win {
        return false;
    }
    if WINDOWS_QUIC_PREWARM_STARTED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return true;
    }

    let netsh_exe = crate::exec::system32_from_env("netsh.exe");
    let spawn = std::thread::Builder::new()
        .name("polaris-quic-cleanup".into())
        .spawn(move || {
            let started = Instant::now();
            let command = windows_clear_quic_command(&netsh_exe);
            match crate::exec::StdCommandRunner.run(&command, WINDOWS_QUIC_CLEANUP_TIMEOUT) {
                Ok(_) => log::info!(
                    "Windows QUIC 旧规则启动预热完成：结果=cleared，耗时={}ms",
                    started.elapsed().as_millis()
                ),
                Err(error) => log::info!(
                    "Windows QUIC 旧规则启动预热完成：结果=absent-or-unavailable，耗时={}ms，详情={error}",
                    started.elapsed().as_millis()
                ),
            }
        });
    if let Err(error) = spawn {
        WINDOWS_QUIC_PREWARM_STARTED.store(false, Ordering::Release);
        log::warn!("Windows QUIC 旧规则启动预热线程创建失败：{error}");
        return false;
    }
    true
}

/// 当前进程是否已把 Windows QUIC 旧规则清理交给启动预热。
#[must_use]
pub fn windows_quic_cleanup_prewarmed() -> bool {
    WINDOWS_QUIC_PREWARM_STARTED.load(Ordering::Acquire)
}

// ── Windows 命令构造（Polaris WindowsSystemProxy）──

/// Windows Internet Settings 注册表路径。
pub const WIN_REG_PATH: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

/// Windows 设代理命令序列（reg add ProxyServer / ProxyOverride / ProxyEnable）。
/// 关键：只设 http/https，不设 socks=（Chromium 内核会把 WebSocket 经 SOCKS5 本地解析 DNS 被污染）。
///
/// QUIC 旧规则清理由 [`windows_clear_quic_command`] 单独构造并 best-effort 执行：规则本来就不存在时
/// `netsh delete rule` 也会以 exit=1 退出，不能把这个幂等成功态混进代理注册表事务。
pub fn windows_enable_commands(reg_exe: &str, req: &ProxyEnableRequest) -> Vec<Command> {
    let values = windows_enable_values(req);
    vec![
        Command {
            program: reg_exe.to_string(),
            args: vec![
                "add".into(),
                WIN_REG_PATH.into(),
                "/v".into(),
                "ProxyServer".into(),
                "/t".into(),
                "REG_SZ".into(),
                "/d".into(),
                values.proxy_server,
                "/f".into(),
            ],
        },
        Command {
            program: reg_exe.to_string(),
            args: vec![
                "add".into(),
                WIN_REG_PATH.into(),
                "/v".into(),
                "ProxyOverride".into(),
                "/t".into(),
                "REG_SZ".into(),
                "/d".into(),
                values.proxy_override,
                "/f".into(),
            ],
        },
        Command {
            program: reg_exe.to_string(),
            args: vec![
                "add".into(),
                WIN_REG_PATH.into(),
                "/v".into(),
                "ProxyEnable".into(),
                "/t".into(),
                "REG_DWORD".into(),
                "/d".into(),
                values.proxy_enable.to_string(),
                "/f".into(),
            ],
        },
    ]
}

/// Windows 注册表值生成的单一真值；`reg.exe` 回退与原生 writer 共用。
#[must_use]
pub fn windows_enable_values(req: &ProxyEnableRequest) -> WindowsProxyRegistryValues {
    WindowsProxyRegistryValues {
        proxy_server: format!(
            "http={addr}:{http};https={addr}:{http}",
            addr = req.address,
            http = req.http_port
        ),
        proxy_enable: 1,
        proxy_override: format_bypass_for_windows(&req.bypass_list, None),
    }
}

/// Windows 简单禁用（无原始可恢复时）：ProxyEnable=0。
/// 上游 `WindowsSystemProxy.disableProxy` else 分支。
pub fn windows_disable_commands(reg_exe: &str) -> Command {
    Command {
        program: reg_exe.to_string(),
        args: vec![
            "add".into(),
            WIN_REG_PATH.into(),
            "/v".into(),
            "ProxyEnable".into(),
            "/t".into(),
            "REG_DWORD".into(),
            "/d".into(),
            "0".into(),
            "/f".into(),
        ],
    }
}

/// Windows netsh 清 QUIC 规则（禁用时务必清，上游 `disableProxy` 首行）。
pub fn windows_clear_quic_command(netsh_exe: &str) -> Command {
    Command {
        program: netsh_exe.to_string(),
        args: vec![
            "advfirewall".into(),
            "firewall".into(),
            "delete".into(),
            "rule".into(),
            "name=Polaris_Block_QUIC".into(),
        ],
    }
}

/// Windows 恢复原始代理命令序列（回写 ProxyServer 串 + ProxyEnable=1）。
/// 上游 `WindowsSystemProxy.restoreProxySettings` 的 if 分支（enabled 且有实际代理）。
///
/// 调用前提：`original.enabled && original.has_any_proxy()`（否则该走 [`windows_disable_commands`]）。
pub fn windows_restore_commands(reg_exe: &str, original: &SystemProxyStatus) -> Vec<Command> {
    let mut parts = Vec::new();
    if let Some(p) = &original.http_proxy {
        parts.push(format!("http={p}"));
    }
    if let Some(p) = &original.https_proxy {
        parts.push(format!("https={p}"));
    }
    if let Some(p) = &original.socks_proxy {
        parts.push(format!("socks={p}"));
    }
    let mut cmds = Vec::new();
    if !parts.is_empty() {
        cmds.push(Command::new(
            reg_exe,
            [
                "add",
                WIN_REG_PATH,
                "/v",
                "ProxyServer",
                "/t",
                "REG_SZ",
                "/d",
                &parts.join(";"),
                "/f",
            ],
        ));
    }
    // 回写原始 ProxyServer 后再置 ProxyEnable=1（顺序对齐上游：先值后开关）。
    cmds.push(Command::new(
        reg_exe,
        [
            "add",
            WIN_REG_PATH,
            "/v",
            "ProxyEnable",
            "/t",
            "REG_DWORD",
            "/d",
            "1",
            "/f",
        ],
    ));
    cmds
}

/// Windows 读代理状态命令：`reg query <path> /v <value>`。
/// 上游 `WindowsSystemProxy.getProxyStatus`（原为 shell execAsync 拼串，此处 argv 化）。
pub fn windows_query_command(reg_exe: &str, value: &str) -> Command {
    Command::new(reg_exe, ["query", WIN_REG_PATH, "/v", value])
}

/// 解析 `reg query ... /v ProxyEnable` 输出 → 是否启用。
///
/// 只接受键名精确为 `ProxyEnable`、类型精确为 `REG_DWORD`、数值 token 解析后精确等于 1
/// 的行。不再用子串搜索，避免把 `0x10` 或 `ProxyEnableBackup` 误判为已启用。
pub fn parse_win_proxy_enable(stdout: &str) -> bool {
    stdout.lines().any(|line| {
        let mut fields = line.split_whitespace();
        if !fields
            .next()
            .is_some_and(|key| key.eq_ignore_ascii_case("ProxyEnable"))
            || fields.next() != Some("REG_DWORD")
        {
            return false;
        }
        let Some(raw) = fields.next() else {
            return false;
        };
        if fields.next().is_some() {
            return false;
        }
        let parsed = raw
            .strip_prefix("0x")
            .or_else(|| raw.strip_prefix("0X"))
            .map_or_else(|| raw.parse::<u32>(), |hex| u32::from_str_radix(hex, 16));
        parsed == Ok(1)
    })
}

/// 解析 `reg query ... /v ProxyServer` 输出 → 三协议代理。
///
/// 值有**两种**合法形态，都必须认（漏认第二种 = 稳定误亮降级黄灯）：
///
/// 1. **逐协议**（我们自己 enable 时写的、也是 上游 唯一处理的形态）：
///    `http=127.0.0.1:8080;https=127.0.0.1:8080;socks=127.0.0.1:1080`；
/// 2. **裸 `host:port`**（**Windows 设置 UI「手动设置代理」输入框**写出来的形态，无 `=`）：
///    `127.0.0.1:7890` —— 语义是「**全协议**都用这个」（WinINET 对无 scheme 前缀的值即按 all 处理）。
///
/// 只认形态 1 的后果不是「少读一点信息」而是**判定反转**：用户在系统设置里手填了我们的
/// `127.0.0.1:<mixed>`（一个完全正常的用法），三条腿全解析成 `None` →
/// [`points_to_mixed_inbound`](super::points_to_mixed_inbound) 找不到任何「指向我们」的证据 → 判未生效 → 稳定误亮黄灯。
///
/// 裸形态只填 http/https 两腿、**不填 socks**：与我们自己 enable 的写法一致（Windows 侧从不设
/// `socks=`），且 `points_to_mixed_inbound` 把 `None` 腿视作「未设 ≠ 指向别处」，多填 socks 反而会
/// 在用户另设了 socks 时引入假象。
///
/// 取不到 ProxyServer 行 → `enabled:true` 但三协议全空（上游 `if (!proxyServerMatch) return { enabled: true }`）。
///
/// 注：上游用正则 `/ProxyServer\s+REG_SZ\s+(.+)/`；此处等价手写（本 crate 不引 regex 依赖）。
pub fn parse_win_proxy_server(stdout: &str) -> SystemProxyStatus {
    let status = SystemProxyStatus {
        enabled: true,
        ..Default::default()
    };
    // 找 `ProxyServer` + 空白 + `REG_SZ` + 空白 + 值。
    let Some(value) = stdout.lines().find_map(|line| {
        let rest = line.trim_start().strip_prefix("ProxyServer")?;
        if !rest.starts_with(char::is_whitespace) {
            return None; // 防匹配到 ProxyServerFoo
        }
        let rest = rest.trim_start().strip_prefix("REG_SZ")?;
        if !rest.starts_with(char::is_whitespace) {
            return None;
        }
        let v = rest.trim();
        (!v.is_empty()).then(|| v.to_string())
    }) else {
        return status;
    };

    parse_win_proxy_server_value(&value)
}

fn parse_win_proxy_server_value(value: &str) -> SystemProxyStatus {
    let mut status = SystemProxyStatus {
        enabled: true,
        ..Default::default()
    };
    // 形态 2：整串无 `=` → 裸 `host:port`，作用于全协议（见函数文档）。先判整串再拆分号：
    // `;` 分隔是形态 1 专有语法，裸形态里出现 `;` 本身就不合法，不必为它编个部分解析。
    if !value.contains('=') {
        let bare = value.trim();
        if !bare.is_empty() {
            status.http_proxy = Some(bare.to_string());
            status.https_proxy = Some(bare.to_string());
        }
        return status;
    }

    for part in value.split(';') {
        let Some((protocol, address)) = part.split_once('=') else {
            continue;
        };
        let (protocol, address) = (protocol.trim(), address.trim());
        if protocol.is_empty() || address.is_empty() {
            continue;
        }
        match protocol.to_lowercase().as_str() {
            "http" => status.http_proxy = Some(address.to_string()),
            "https" => status.https_proxy = Some(address.to_string()),
            "socks" => status.socks_proxy = Some(address.to_string()),
            _ => {}
        }
    }
    status
}

/// exact 注册表三值向旧 marker 的有损投影。旧格式不保留 absent/present-empty 与原始 DWORD，
/// 但可恢复 `ProxyEnable==1` 时可解析的静态 ProxyServer。
pub(crate) fn windows_registry_projection(
    snapshot: &WindowsProxyRegistrySnapshot,
) -> SystemProxyStatus {
    if snapshot.proxy_enable != WindowsRegistryDwordValue::PresentValue(1) {
        return SystemProxyStatus::default();
    }
    match &snapshot.proxy_server {
        WindowsRegistryStringValue::PresentValue(value) => parse_win_proxy_server_value(value),
        WindowsRegistryStringValue::Absent | WindowsRegistryStringValue::PresentEmpty => {
            SystemProxyStatus {
                enabled: true,
                ..Default::default()
            }
        }
    }
}
