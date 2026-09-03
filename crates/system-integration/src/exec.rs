//! 命令执行缝（本 crate 与宿主 OS 的**唯一**交互点）。
//!
//! ## 为什么是「一条缝」
//!
//! 本 crate 的平台差异只是**构造命令字符串**（`reg.exe` / `networksetup` / `gsettings`），不是平台专属
//! 类型或依赖 —— 故用「运行时 `Platform` 枚举 + 注入 trait」而非 `#[cfg(target_os)]`（审计 §M1 第二形态）。
//! 收益是 **Linux CI 100% 编译 + 跑测三平台逻辑**：命令构造与输出解析全是纯函数，mock 一注入就能断言
//! 三平台的 argv/解析，不必真跑 OS 命令。
//!
//! **接线纪律（勿破坏）**：新增平台行为时，「决定跑什么命令 / 怎么解释输出」必须留在纯函数里，
//! 本模块只负责「把已决定的命令跑掉」。一旦把判定逻辑塞进 [`StdCommandRunner`]，那部分逻辑就退回
//! 「只有真机能测」—— 正是 §G5「cfg 门内代码 Linux 看不到 → 潜伏」的同型陷阱。
//!
//! ## 语义对齐
//!
//! [`CommandRunner::run`] 对齐上游 `execFileAsync` / `execAsync`：**非零退出 / 超时 / spawn 失败 → `Err`**
//! （上游是 reject，调用方 try/catch 降级）。argv 参数化下发、**不经 shell 插值** —— 上游
//! `SystemProxyManager.ts:506,753` 明写把 shell 字符串拼接改成 `execFileAsync` 正是为了杜绝命令注入
//! （bypass 域名 / gsettings host 均可被投毒）。

#![forbid(unsafe_code)]

use std::io::Read;
use std::process::Stdio;
use std::time::{Duration, Instant};

/// 一条待执行命令（程序 + argv）。argv 参数化下发，不经 shell 插值（杜绝注入 —— 上游 execFileAsync 口径）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub program: String,
    pub args: Vec<String>,
}

impl Command {
    /// 便捷构造。
    pub fn new(
        program: impl Into<String>,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }
}

/// 一次命令执行的产出。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
}

/// 命令执行器 —— 注入便于 mock；生产用 [`StdCommandRunner`]。
///
/// 契约：非零退出 / 超时 / spawn 失败 → `Err(原因)`（对齐上游 `execFileAsync` reject）。
pub trait CommandRunner {
    fn run(&self, cmd: &Command, timeout: Duration) -> Result<CommandOutput, String>;
}

/// `try_wait` 自适应轮询窗口。std 无 `wait_timeout`，而本 crate **禁止引入新依赖**（`wait-timeout` /
/// `tokio` 都不引）→ 用轮询实现硬超时。
///
/// `networksetup` / `reg.exe` / `gsettings` 常在数毫秒内完成；固定 10ms 会让启动关键路径上的每条命令
/// 都白等到下一格。1ms 起步、指数退避到原来的 10ms 上限，既缩短短命令尾延迟，又不增加挂起命令的
/// 长期轮询频率，超时与 kill 语义不变。
const INITIAL_POLL_INTERVAL: Duration = Duration::from_millis(1);
const MAX_POLL_INTERVAL: Duration = Duration::from_millis(10);

fn next_poll_interval(current: Duration, maximum: Duration) -> Duration {
    current.saturating_mul(2).min(maximum)
}

/// Windows `CREATE_NO_WINDOW`（winbase.h `0x0800_0000`）。
///
/// 宿主进程是 GUI 子系统（`src-tauri/src/main.rs` 的 `windows_subsystem = "windows"`）⇒ 自身**无控制台**。
/// 无控制台的父进程创建 console 子系统程序时，`CreateProcess` 会为子进程**新分配一个控制台窗口**
/// —— 用户看到黑框闪一下。而 `reg.exe` / `netsh` / `tasklist` 这些正是 console 程序。
///
/// **std 与 tokio 都不默认抑制**：`tokio::process::Command::creation_flags` 只是把值透传给
/// `std::os::windows::process::CommandExt::creation_flags`，tokio 侧无任何隐含默认
/// （实测 tokio-1.53.1 `src/process/mod.rs:675`）。故每个 Windows 可达的调用点都得显式加。
///
/// 不为一个常量引 `windows-sys`：本 crate 的硬纪律是零新依赖（见 [`INITIAL_POLL_INTERVAL`]）。
#[cfg(windows)]
pub(crate) const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// 生产实现：`std::process::Command` + argv 参数化 + 硬超时（spawn → 轮询 `try_wait` → 超时 kill）。
///
/// **同步**：本 crate 的控制器（`SystemProxyController` / `SystemDnsController`）全是同步 API，
/// 故此处同步执行。调用方若在 async 语境，须自行 `spawn_blocking`（本 crate 不引 tokio）。
///
/// **管道排空**：stdout/stderr 各起一个读取线程。若改成「先轮询后读管道」，子进程输出超过管道缓冲
/// （典型 64KB）就会写阻塞 → 与轮询互等 → 死锁。`scutil --dns` 等命令输出虽小，但不留这个雷。
#[derive(Debug, Clone, Copy, Default)]
pub struct StdCommandRunner;

impl CommandRunner for StdCommandRunner {
    fn run(&self, cmd: &Command, timeout: Duration) -> Result<CommandOutput, String> {
        let mut builder = std::process::Command::new(&cmd.program);
        builder
            .args(&cmd.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Windows：抑制新控制台窗口（见 [`CREATE_NO_WINDOW`]）。本 runner 是本 crate 与 OS 的唯一缝，
        // 故 `reg.exe` / `netsh` / `tasklist` 等全部平台命令在此一处收口。
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            builder.creation_flags(CREATE_NO_WINDOW);
        }
        let mut child = builder
            .spawn()
            .map_err(|e| format!("{} 启动失败: {e}", cmd.program))?;

        // 先接管管道并起排空线程（见结构体 doc：防写阻塞死锁）。
        let out_pipe = child.stdout.take();
        let err_pipe = child.stderr.take();
        let out_thread = std::thread::spawn(move || drain(out_pipe));
        let err_thread = std::thread::spawn(move || drain(err_pipe));

        let deadline = Instant::now() + timeout;
        let mut poll_interval = INITIAL_POLL_INTERVAL;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {}
                Err(e) => return Err(format!("{} 等待失败: {e}", cmd.program)),
            }
            if Instant::now() >= deadline {
                // 硬超时：kill + 收割（防僵尸）。kill 后管道关闭 → 排空线程自然退出。
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{} 超时（{:?}）", cmd.program, timeout));
            }
            std::thread::sleep(poll_interval);
            poll_interval = next_poll_interval(poll_interval, MAX_POLL_INTERVAL);
        };

        let stdout = out_thread.join().unwrap_or_default();
        let stderr = err_thread.join().unwrap_or_default();

        if !status.success() {
            // 对齐 execFileAsync：非零退出 = reject。stderr 带进错误便于诊断。
            return Err(format!(
                "{} 退出码 {}: {}",
                cmd.program,
                status
                    .code()
                    .map_or_else(|| "signal".to_string(), |c| c.to_string()),
                stderr.trim()
            ));
        }
        Ok(CommandOutput { stdout, stderr })
    }
}

// ── Windows System32 绝对路径（移植自 上游 `utils/win-system32.ts`）──

/// `%SystemRoot%`（`windir` 兜底，最终回落 `C:\Windows`）。env 注入便于单测。
/// 上游 `getSystemRoot`。
pub fn system_root(env_system_root: Option<&str>, env_windir: Option<&str>) -> String {
    env_system_root
        .filter(|s| !s.is_empty())
        .or(env_windir.filter(|s| !s.is_empty()))
        .unwrap_or("C:\\Windows")
        .to_string()
}

/// 解析 System32 下的二进制为绝对路径（`reg.exe` → `C:\Windows\System32\reg.exe`）。
///
/// **为什么不用裸命令名**：部分设备的进程 PATH 缺失 `C:\Windows\System32`（注册表 Path 值类型从
/// `REG_EXPAND_SZ` 退化为 `REG_SZ` 致 `%SystemRoot%` 不展开，或 PATH 超长被截断）→ 裸 `reg`/`netsh`/
/// `ipconfig` 解析失败报「'reg' 不是内部或外部命令」。**这不是权限问题**，绝对路径可完全绕开。
/// 上游 `system32`。
///
/// 恒生成反斜杠路径，与宿主 OS 无关 —— Linux 上单测亦得 Windows 路径（保持零 cfg 可测性）。
pub fn system32(binary: &str, env_system_root: Option<&str>, env_windir: Option<&str>) -> String {
    let root = system_root(env_system_root, env_windir);
    let root = root.trim_end_matches(['\\', '/']);
    format!("{root}\\System32\\{binary}")
}

/// 从进程环境解析 System32 二进制（生产入口；非 Windows 上取不到 env → 回落默认，无害）。
pub fn system32_from_env(binary: &str) -> String {
    let sr = std::env::var("SystemRoot").ok();
    let wd = std::env::var("windir").ok();
    system32(binary, sr.as_deref(), wd.as_deref())
}

/// 读干一个管道；读失败按空串（best-effort，输出只用于解析/诊断）。
fn drain(pipe: Option<impl Read>) -> String {
    let Some(mut pipe) = pipe else {
        return String::new();
    };
    let mut buf = Vec::new();
    if pipe.read_to_end(&mut buf).is_err() {
        return String::new();
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// 测试辅助：跨模块共享的命令执行 mock。
///
/// **这是本 crate「Linux 上跑测三平台」的枢纽** —— 任意 `SystemProxyOpsImpl::with_platform(mock, Platform::Mac)`
/// 都能在 Linux CI 上断言 mac 的 argv 与输出解析，全程不碰宿主网络。
#[cfg(test)]
pub mod exec_tests_helpers {
    use super::{Command, CommandOutput, CommandRunner};
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::time::Duration;

    /// 记录调用的 mock（本 crate 全部三平台逻辑测试的注入点 —— 不触碰宿主）。
    #[derive(Default)]
    pub struct MockRunner {
        pub calls: RefCell<Vec<Command>>,
        /// 与 `calls` 同序的预算；用于证明可选清理没有偷用必要事务的宽超时。
        pub timeouts: RefCell<Vec<Duration>>,
        /// 按调用序返回的 stdout（队列；空则回空串）。
        pub stdouts: RefCell<Vec<String>>,
        /// 按「argv 含此子串」匹配返回 stdout（比队列更稳，不依赖调用序）。
        pub by_arg: RefCell<HashMap<String, String>>,
        /// 这些 program 的调用直接失败。
        pub fail_programs: Vec<String>,
        /// argv 含这些子串的调用直接失败。
        pub fail_args: Vec<String>,
    }

    impl MockRunner {
        /// 按 argv 子串挂 stdout。
        pub fn with_arg_stdout(self, arg_substr: &str, stdout: &str) -> Self {
            self.by_arg
                .borrow_mut()
                .insert(arg_substr.to_string(), stdout.to_string());
            self
        }

        /// 全部调用的 (program, argv) 快照。
        pub fn snapshot(&self) -> Vec<Command> {
            self.calls.borrow().clone()
        }

        /// 是否跑过某条 argv 含该子串的命令。
        pub fn ran_arg(&self, substr: &str) -> bool {
            self.calls
                .borrow()
                .iter()
                .any(|c| c.args.iter().any(|a| a.contains(substr)))
        }

        /// 首条 argv 含该子串的调用预算。
        pub fn timeout_for_arg(&self, substr: &str) -> Option<Duration> {
            self.calls
                .borrow()
                .iter()
                .zip(self.timeouts.borrow().iter().copied())
                .find_map(|(c, timeout)| {
                    c.args.iter().any(|a| a.contains(substr)).then_some(timeout)
                })
        }

        /// argv 含该子串的调用次数。
        pub fn count_arg(&self, substr: &str) -> usize {
            self.calls
                .borrow()
                .iter()
                .filter(|c| c.args.iter().any(|a| a.contains(substr)))
                .count()
        }

        /// argv 含**恰好等于**该值的项的调用次数。
        ///
        /// 子串匹配在此处会骗人：`-setwebproxystate` 含 `-setwebproxy` → `count_arg` 把 state 命令
        /// 也算进去。断言「每服务设了几次代理」这类计数必须用精确匹配。
        pub fn count_arg_exact(&self, arg: &str) -> usize {
            self.calls
                .borrow()
                .iter()
                .filter(|c| c.args.iter().any(|a| a == arg))
                .count()
        }
    }

    impl CommandRunner for MockRunner {
        fn run(&self, cmd: &Command, timeout: Duration) -> Result<CommandOutput, String> {
            self.calls.borrow_mut().push(cmd.clone());
            self.timeouts.borrow_mut().push(timeout);
            if self.fail_programs.iter().any(|p| p == &cmd.program) {
                return Err("mock failure (program)".into());
            }
            if self
                .fail_args
                .iter()
                .any(|f| cmd.args.iter().any(|a| a.contains(f)))
            {
                return Err("mock failure (arg)".into());
            }
            // 优先按 argv 子串匹配。
            for (k, v) in self.by_arg.borrow().iter() {
                if cmd.args.iter().any(|a| a.contains(k)) {
                    return Ok(CommandOutput {
                        stdout: v.clone(),
                        stderr: String::new(),
                    });
                }
            }
            let mut outs = self.stdouts.borrow_mut();
            let stdout = if outs.is_empty() {
                String::new()
            } else {
                outs.remove(0)
            };
            Ok(CommandOutput {
                stdout,
                stderr: String::new(),
            })
        }
    }
}

#[cfg(test)]
mod tests;
