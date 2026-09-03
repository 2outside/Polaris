//! [`Escalation`] —— 提权回退的纯逻辑决策。
//!
//! ## 职责（移植自 上游 `PlatformPrivilegeService.ts`）
//!
//! helper 不可用（未装 / 未就绪 / 装卸过渡期）时，回退到平台提权机制跑一次性 root 脚本：
//! - **macOS**：`osascript` `do shell script "..." with administrator privileges`（弹一次密码框）。
//!   （`PlatformPrivilegeService.ts:592`、`HelperManager.ts:888-906`）
//! - **Windows**：UAC PowerShell `Start-Process -Verb RunAs`（弹一次 UAC 框）。
//!   （`PlatformPrivilegeService.ts:482,710`）
//! - **Linux**：`pkexec /bin/bash <script>`（弹一次 polkit 密码框）。
//!   （`PlatformPrivilegeService.ts:162`）
//!
//! ### Linux：deb 包必须声明 pkexec 依赖（2026-08-05 补）
//!
//! `pkexec` 不是基础系统组件，精简发行版 / server 镜像上可能没有 —— 缺了它这条提权腿直接失败，
//! 用户看到的是「提权助手安装失败」而不是「缺依赖」。`tauri.conf.json` 的
//! `bundle.linux.deb.recommends` 已加 `"pkexec | policykit-1"`。
//!
//! [用 `recommends` 不用 `depends`：没有 pkexec 时应用仍可用（系统代理 / 手动代理模式照常），
//! 只是 TUN 与 helper 装不了；`depends` 会让这类用户**装都装不上**，比降级更糟。apt 默认安装
//! Recommends，正常桌面用户拿到的效果与 depends 一致。与 上游 `electron-builder.json` 的
//! `deb.recommends: policykit-1` 同强度]
//!
//! [写成 `pkexec | policykit-1` 而非单一包名：Debian 12 / Ubuntu 23.04 起 `policykit-1` 已拆成
//! `polkitd` + `pkexec`，只写 `policykit-1` 在新发行版上会指向一个可能不存在的过渡包；只写
//! `pkexec` 又在 Ubuntu 22.04（本仓的构建基线）上不存在。`|` 是 Debian 控制字段的择一依赖语法，
//! Tauri 的 deb bundler 只做字符串拼接，原样透传]
//!
//! ## 纯逻辑决策
//!
//! 本模块**只决定用哪种机制 + 构造命令 argv**，**不执行**（执行需 spawn / 权限，属宿主操作）。
//! 决策结果 [`Escalation`] 是 argv + 用户取消判定 —— 上层（Tauri 主进程 / 测试）拿 argv 自行 spawn，
//! 或注入 [`Executor`](crate::privilege) trait mock。这样本模块零宿主依赖、可在 Linux 上测 macOS 决策。
//!
//! ## 移植纪律
//!
//! 1. 纯逻辑：决策 + argv 构造，无 spawn。
//! 2. `forbid(unsafe_code)`。
//! 3. 错误码区分用户取消（126/127/-128）vs 脚本失败，对齐 上游 `runPkexecScript` / `runRootScript` 语义。

use crate::ClientError;
use std::process::{Command, ExitStatus};

/// 三平台提权机制（对应 Polaris 的三套 spawn 路径）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegeMethod {
    /// macOS osascript（`HelperManager.ts:888` 的 `spawn('/usr/bin/osascript', [...])`）。
    Osascript,
    /// Windows UAC PowerShell（`PlatformPrivilegeService.ts:710` 的 RunAs taskkill）。
    Uac,
    /// Linux pkexec（`PlatformPrivilegeService.ts:162` 的 `spawn('/usr/bin/pkexec', ['/bin/bash', scriptPath])`）。
    Pkexec,
}

/// 一次提权决策：用什么机制 + 跑什么脚本。
///
/// 不含执行 —— 仅 argv，上层据此 spawn。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Escalation {
    /// 机制（决定 argv 头部 + 取消码判定）。
    pub method: PrivilegeMethod,
    /// 完整 argv（argv\[0\] = 解释器路径，argv\[1..\] = 脚本/参数）。
    pub argv: Vec<String>,
}

/// 提权执行结果（区分用户取消 / 脚本失败 / 成功，对齐 Polaris 三套 runXxxScript 语义）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscalationOutcome {
    /// 成功（退出码 0）。
    Success,
    /// 用户取消授权（macOS osascript -128 / Linux pkexec 126 / Windows UAC 拒绝）。
    Cancelled,
    /// 脚本执行失败（非取消的非零退出）。
    Failed { stderr: String, code: i32 },
}

/// `ERROR_CANCELLED`（WinError.h）：UAC consent UI 被用户关闭/拒绝。
const UAC_CANCELLED_CODE: i32 = 1223;
/// 外层 PowerShell 只在机器可读错误码确认 `ERROR_CANCELLED` 后输出；Rust 不解析本地化异常文本。
const UAC_CANCELLED_MARKER: &str = "UAC_ERROR_CANCELLED_1223";

impl PrivilegeMethod {
    /// 当前平台的默认机制（运行期 target 决定）。
    #[must_use]
    pub fn for_current_platform() -> Self {
        #[cfg(target_os = "macos")]
        {
            Self::Osascript
        }
        #[cfg(target_os = "windows")]
        {
            Self::Uac
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            Self::Pkexec
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows", unix)))]
        {
            Self::Pkexec // unreachable on supported platforms
        }
    }
}

/// 构造 macOS osascript 提权 argv（移植自 `HelperManager.ts:888`）。
///
/// 对应 Polaris：
/// ```text
/// spawn('/usr/bin/osascript', ['-e',
///   `do shell script "/bin/bash '<script>'" with administrator privileges`])
/// ```
///
/// 返回的 argv 直接喂 `Command::new(argv[0]).args(&argv[1..])`。
#[must_use]
pub fn osascript_escalation(script_path: &str) -> Escalation {
    // script_path 已是私有 0700 目录 + 随机名（TOCTOU 加固，HelperManager.ts:874-884）
    // 这里对路径做 shell 单引号转义（防含空格/撇号家目录击穿引号）+ AppleScript 转义
    let escaped = applescript_escape(&shell_quote(script_path));
    let argv = vec![
        "/usr/bin/osascript".to_owned(),
        "-e".to_owned(),
        format!("do shell script \"/bin/bash {escaped}\" with administrator privileges"),
    ];
    Escalation {
        method: PrivilegeMethod::Osascript,
        argv,
    }
}

/// 构造 Linux pkexec 提权 argv（移植自 `PlatformPrivilegeService.ts:162`）。
///
/// 对应 Polaris：`spawn('/usr/bin/pkexec', ['/bin/bash', scriptPath])`。
#[must_use]
pub fn pkexec_escalation(script_path: &str) -> Escalation {
    Escalation {
        method: PrivilegeMethod::Pkexec,
        argv: vec![
            "/usr/bin/pkexec".to_owned(),
            "/bin/bash".to_owned(),
            script_path.to_owned(),
        ],
    }
}

/// 构造 Windows UAC PowerShell 提权 argv（移植自 `PlatformPrivilegeService.ts:482` 的 Start-Process -Verb RunAs）。
///
/// 对应 Polaris：`Start-Process` 经 `powershell -Command` 以 `-Verb RunAs` 触发 UAC。
pub fn uac_escalation(script_path: &str) -> Result<Escalation, ClientError> {
    // PowerShell -File 执行脚本（含空格路径用单引号包裹）
    //
    // # 🔴 `-ExecutionPolicy Bypass` 不可省
    //
    // `powershell.exe -File <x>.ps1` 受执行策略约束，而 **Restricted 是 Windows 客户端 SKU 的出厂
    // 默认**（Server 2012 R2+ 才是 RemoteSigned）⇒ 不带这个 flag，脚本在**未改过策略的机器上一行
    // 都跑不了**。外层的 `-Command` 不受策略约束，所以只有内层需要。
    //
    // 同仓另一条同手法的腿一直带着它：`src-tauri/nsis-hooks.nsh:134`（卸载钩子，外层内层都带），
    // 被移植的上游 上游 `src/main/services/WindowsServiceHelper.ts` 同样带 —— 本处属移植时丢失，
    // 不是刻意取舍。
    //
    // # 退出码：`-PassThru` 回传，读不到时必须失败
    //
    // `Start-Process -Wait` 本身不透传子进程退出码，外层 `-Command` 在 cmdlet 正常收尾时恒退 0
    // ⇒ 脚本内部 `throw`（Copy-Item 退避耗尽 / New-Service 1072 重试耗尽 / sc delete 失败）
    // 全部被谎报成 `EscalationOutcome::Success`，而卸载腿据此 `clear_token()`，把 app 侧 token
    // 删掉、SYSTEM 服务还在跑 ⇒ 之后恒鉴权失败且「修复」也修不回来。
    //
    // `$p.HasExited` 守卫的用意：`-Verb RunAs` 是跨提权会话起进程，只有拿到已退出的进程对象时才有
    // 可证明的成功/失败。读不到 `ExitCode`、`Start-Process` 非终止错误或 UAC 根本没拉起脚本时若回落 0，
    // 上层会把「旧 helper 原封不动」谎报为安装成功。故外层启用 Stop、显式 `-ErrorAction Stop`，任何
    // 无法证明内层脚本 exit 0 的形态都 fail-closed 为 1。
    // 两层 PowerShell 都钉到 GetSystemDirectoryW 返回的系统目录。外层若走 PATH/当前目录，攻击者
    // 无需管理员权限便能放置同名 exe；内层若走 PATH，则攻击者会在用户确认预期中的 UAC 后获提升。
    #[cfg(windows)]
    let powershell = crate::windows_system::powershell_executable()?;
    // 跨平台纯逻辑测试用稳定的 Windows 绝对路径；生产 Windows 构建永远走上面的 OS API。
    #[cfg(not(windows))]
    let powershell = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_owned();
    let argv = vec![
        powershell.clone(),
        "-NoProfile".to_owned(),
        "-Command".to_owned(),
        format!(
            "$ErrorActionPreference = 'Stop'; \
             try {{ \
               $p = Start-Process -FilePath '{powershell}' \
                 -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','{path}' \
                 -Verb RunAs -Wait -PassThru -ErrorAction Stop; \
               if ($p -and $p.HasExited) {{ exit $p.ExitCode }}; \
               [Console]::Error.WriteLine('elevated process exit code unavailable'); exit 1 \
             }} catch {{ \
               $exception = $_.Exception; $cancelled = $false; \
               while ($null -ne $exception) {{ \
                 if ($exception.NativeErrorCode -eq {uac_cancel_code} -or $exception.HResult -eq -2147023673) {{ \
                   $cancelled = $true; break \
                 }}; \
                 $exception = $exception.InnerException \
               }}; \
               if ($cancelled) {{ \
                 [Console]::Error.WriteLine('{uac_cancel_marker}'); exit {uac_cancel_code} \
               }}; \
               [Console]::Error.WriteLine($_.Exception.Message); exit 1 \
             }}",
            path = script_path.replace('\'', "''"),
            powershell = powershell.replace('\'', "''"),
            uac_cancel_code = UAC_CANCELLED_CODE,
            uac_cancel_marker = UAC_CANCELLED_MARKER,
        ),
    ];
    Ok(Escalation {
        method: PrivilegeMethod::Uac,
        argv,
    })
}

/// 判定退出码是否为「用户取消授权」（对齐 Polaris 三套 runXxxScript 的取消判定）。
///
/// - macOS osascript：退出码 -128 / stderr 含 "User canceled"（`HelperManager.ts:903-905`）
/// - Linux pkexec：退出码 126 才是用户取消；127 表示当前会话没有认证代理，必须作为失败如实上报
/// - Windows UAC：外层 PowerShell 以 `ERROR_CANCELLED` / HRESULT 产出稳定 marker；不解析系统语言文本
#[must_use]
pub fn is_user_cancelled(method: PrivilegeMethod, code: i32, stderr: &str) -> bool {
    match method {
        PrivilegeMethod::Osascript => {
            // HelperManager.ts:903: /-128|User canceled/i.test(stderr)
            code == -128
                || stderr.contains("-128")
                || stderr.to_lowercase().contains("user canceled")
        }
        PrivilegeMethod::Pkexec => code == 126,
        PrivilegeMethod::Uac => {
            code == UAC_CANCELLED_CODE
                && stderr
                    .lines()
                    .any(|line| line.trim() == UAC_CANCELLED_MARKER)
        }
    }
}

/// 把退出码 + stderr 归类为 [`EscalationOutcome`]。
#[must_use]
pub fn classify_outcome(
    method: PrivilegeMethod,
    status: ExitStatus,
    stderr: &str,
) -> EscalationOutcome {
    let code = status.code().unwrap_or(-1);
    if status.success() {
        return EscalationOutcome::Success;
    }
    if is_user_cancelled(method, code, stderr) {
        return EscalationOutcome::Cancelled;
    }
    EscalationOutcome::Failed {
        stderr: stderr.trim().to_owned(),
        code,
    }
}

// ===== 内部转义工具（移植自 Polaris shq + osaShellArg）=====

/// shell 单引号转义（移植自 上游 `shq`：把路径包进单引号，内部单引号用 '\'' 关闭再开）。
///
/// `pub(crate)`：install 脚本生成（[`manager`](crate::manager) 的 mac/linux `build_*_install_script`）
/// 复用同一 shell 转义逻辑 —— 单一真值，与 osascript 提权 argv 的转义同源（Polaris 全侧共用 `shq`）。
pub(crate) fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// AppleScript 字符串转义（移植自 `HelperManager.ts:854-857` 的 `osaShellArg`）。
///
/// shq 后再做：反斜杠翻倍 + 双引号转义（嵌入 AppleScript 双引号字符串）。
fn applescript_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

// ===== Executor trait（可选：把 spawn 也抽象，便于测试）=====

/// 提权脚本执行器 trait —— 抽象 `Command::spawn` + 等待 + 捕获 stderr。
///
/// 生产实现 [`StdExecutor`] 真正 spawn；测试实现可 mock 退出码 + stderr。
pub trait Executor: Send {
    /// 执行一个提权 argv，返回 stderr（去首尾空白）+ 退出码。
    fn execute(&self, argv: &[String]) -> Result<(String, i32), ClientError>;
}

/// 生产执行器：真正 spawn argv + 捕获 stderr。
pub struct StdExecutor;

impl Executor for StdExecutor {
    fn execute(&self, argv: &[String]) -> Result<(String, i32), ClientError> {
        if argv.is_empty() {
            return Err(ClientError::Connect("empty argv".into()));
        }
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..]);
        // Windows：提权载体是 `powershell -Command Start-Process -Verb RunAs`，powershell 本身是
        // console 程序 ⇒ 宿主（GUI 子系统，无控制台）起它会新分配一个控制台窗口。UAC 对话框由系统在
        // 安全桌面弹出，与这里无关，抑制窗口不影响提权可见性。
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000);
        }
        let output = cmd
            .output()
            .map_err(|e| ClientError::Connect(format!("spawn 失败: {e}")))?;
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        Ok((stderr, output.status.code().unwrap_or(-1)))
    }
}

/// 跑一次提权脚本并归类结果。
///
/// 便利函数：决策（`escalation`）+ 执行（`executor`）+ 归类（[`classify_outcome`]）一站式。
pub fn run_escalation(
    escalation: &Escalation,
    executor: &dyn Executor,
) -> Result<EscalationOutcome, ClientError> {
    let (stderr, code) = executor.execute(&escalation.argv)?;
    let method = escalation.method;
    if code == 0 {
        Ok(EscalationOutcome::Success)
    } else if is_user_cancelled(method, code, &stderr) {
        Ok(EscalationOutcome::Cancelled)
    } else {
        Ok(EscalationOutcome::Failed {
            stderr: stderr.trim().to_owned(),
            code,
        })
    }
}

#[cfg(test)]
mod tests;
