//! Handler 进程状态 + Core spawn 抽象（对应 上游 `helper-linux/helper.go` 的全局 `child`/`childDone` + AmbientCaps 拉核）。
//!
//! ## 设计
//!
//! Go 源用包级全局 `child *exec.Cmd` + `childDone chan struct{}` + `mu sync.Mutex` 持有当前 sing-box 子进程。
//! 本实现把它们实例化为 [`HandlerState`]（可在测试中独立构造，不依赖全局可变状态）。
//!
//! Core spawn（start 命令）经 [`CoreSpawner`] trait 抽象：
//! - 生产实现（`AmbientCapsSpawner`，§helper-rust-evaluation B3 真机项）：fork → setuid 回对端登录用户 →
//!   raise ambient CAP_NET_ADMIN/RAW/BIND_SERVICE → execve coreDir/sing-box。这是 Linux 安全模型的核心地雷。
//! - 测试 mock：返回固定 pid，记录 spawn/terminate/kill 调用。
//!
//! 本 crate 不实现真实 AmbientCaps fork 链（B3 真机复验项），仅提供 trait + mock；
//! 真实实现见后续集成（`AmbientCapsSpawner` 占位，todo!()）。

use std::path::PathBuf;

/// 已 spawn 的 sing-box 子进程句柄（对应 Go `child *exec.Cmd`）。
#[derive(Debug, Clone)]
pub struct CoreHandle {
    /// 子进程 pid（Go `child.Process.Pid`）。
    pub pid: u32,
}

/// Linux helper 已创建的核心及其可归因关键路径耗时。
#[derive(Debug, Clone)]
pub struct SpawnedCore {
    /// 交给生命周期状态持有的 child 身份。
    pub handle: CoreHandle,
    /// `Command::spawn`（含 pre-exec 降权与 ambient capabilities）耗时。
    pub process_ms: u64,
    /// stdout/stderr 与日志属主修正移交后台线程的耗时。
    pub log_handoff_ms: u64,
}

/// start 命令的 spawn 请求（对照 Go `exec.Command(coreBin(), "run", "-c", cfg)` + Credential + AmbientCaps，:431-442）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnCoreRequest {
    /// sing-box 二进制路径（已校验 == coreDir/sing-box）。
    pub binary: PathBuf,
    /// 配置文件路径（已校验属主 == 对端 uid）。
    pub config: PathBuf,
    /// 日志文件路径（None = 不重定向）。
    pub log: Option<PathBuf>,
    /// allowLan 转发开关。
    pub fwd: bool,
    /// 父 app PID（父死看护；None = 不启看护）。
    pub parent_pid: Option<u32>,
    /// 降权目标 uid（对端登录用户）。
    pub uid: u32,
    /// 降权目标 gid（对端登录组）。
    pub gid: u32,
    /// 补充组 gid 列表（对端登录用户所属全部组，`setgroups` 用；对照 Go `Credential.Groups`，:435-439）。
    ///
    /// 在 fork 前于父进程经 [`supplementary_groups`](crate::platform::linux::auth::supplementary_groups)
    /// 解析（不在拉核子进程碰 NSS）。空 = `setgroups(&[])` 清空补充组（Go `Groups: nil` 等价，见该函数文档）。
    pub groups: Vec<u32>,
}

/// spawn 错误（对应 Go `c.Start()` 失败，:452-458）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpawnError {
    /// sing-box 启动失败（fork/execve/权限）。
    #[error("start {detail}")]
    Spawn { detail: String },
}

/// Core spawn 抽象（trait 便于测试 mock；生产用 AmbientCaps fork+setuid+execve）。
///
/// 对照 Go 源 start 分支的 `c.Start()`（:452）+ stop 的 `terminateChild`（:246-256）+ cleanup 的 `Kill`（:383）。
pub trait CoreSpawner: Send + Sync {
    /// spawn sing-box 子进程（AmbientCaps 拉核）。
    fn spawn(&self, req: &SpawnCoreRequest) -> Result<SpawnedCore, SpawnError>;
    /// 优雅终止：SIGTERM → ≤5s → SIGKILL（Go `terminateChild`，:246-256）。
    fn terminate(&self, h: &CoreHandle);
    /// 强杀 SIGKILL（Go `child.Process.Kill()`，:383）。
    fn kill(&self, h: &CoreHandle);
}

/// Handler 进程状态（对应 Go 全局 `child`/`childDone`，实例化可测）。
#[derive(Debug)]
pub struct HandlerState {
    /// 当前 sing-box 子进程（None = stopped）。
    pub child: Option<CoreHandle>,
}

impl HandlerState {
    /// 构造空状态（无 child）。
    #[must_use]
    pub fn new() -> Self {
        Self { child: None }
    }
}

impl Default for HandlerState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
