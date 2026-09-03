//! Server 主循环 —— 移植自 上游 `helper-linux/main.go`。
//!
//! ## 流程（逐行对照 Go 源 main()）
//!
//! 1. 解析 flags：socket / authfile / coredir / console（:17-22）。
//! 2. 建 socket 目录（0755，任意登录用户可穿越）+ 删旧 socket（:25-31）。
//! 3. Listen(unix) + chmod socket 0666（:33-38）—— socket 本身 0666 + SO_PEERCRED + 授权列表把关。
//! 4. SIGTERM/SIGINT 收割器：先收割 child sing-box，等在途后台收割，复位转发态，退出（:42-58）。
//! 5. Accept 循环：每连接 go handle(conn)（:63-69）。
//!
//! ## Rust 移植
//!
//! Go 源的 socket 循环 + handle 分发是同步多 goroutine。本实现提供：
//! - [`ServerConfig`]：flags 的类型化等价（socket/authfile/coredir 三路径 + console 标记）。
//! - [`prepare_socket`]：建目录 + 删旧 socket + bind + chmod（纯逻辑，可单测）。
//! - [`ss_lookup`]：freeport 的 ss 子进程封装。
//!
//! ## C6-2 提权心脏（本批落地）
//!
//! [`AmbientCapsSpawner`] 是真实的 fork+setuid+AmbientCaps 拉核（替换 C6-0 的 `NotImplementedSpawner` 桩）：
//! `Command` + `pre_exec`（`set_keepcaps` → `setgroups`/`setgid`/`setuid` 降权 → raise Inheritable/Ambient
//! CAP_NET_ADMIN/RAW/BIND_SERVICE），log 重定向 + chown 到对端 uid，收割线程收尸 + 清 state，父死看护
//! （watchParent），terminate（TERM→≤5s→KILL）+ reapWG 退出兜底。**pre_exec 后 fork+execve 链、真降权
//! 拉核为真机门**（本机绝不跑，见 [`super`] 模块文档「关键地雷」段）；纯逻辑（caps 集/terminate 决策/
//! watchParent 决策/ChildSlot 协调）本文件单测覆盖。
//!
//! [`ConnServer`] 把 accept 到的 tokio `UnixStream` 转同步 [`LineConn`](crate::platform::linux::handler::LineConn)
//! （5s 读超时 + 捕获 SO_PEERCRED），交给同步 [`handle`](crate::platform::linux::handle)，对应 Go 的
//! `for { conn := l.Accept(); go handle(conn) }`。

use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::Duration;

use crate::platform::accept_retry::{LogThrottle, ACCEPT_LOG_INTERVAL};
use crate::platform::conn_limit::{ConnLimiter, MAX_CONCURRENT_CONNECTIONS};
use crate::platform::linux::ops::set_forward_prod;
use crate::platform::linux::state::{
    CoreHandle, CoreSpawner, HandlerState, SpawnCoreRequest, SpawnError, SpawnedCore,
};

/// 默认 socket 路径（移植自 Go flag default `/run/polaris/helper.sock`，:18）。
pub const DEFAULT_SOCK_PATH: &str = "/run/polaris/helper.sock";
/// 默认授权 uid 列表文件（Go default `/var/lib/polaris/authorized-uids`，:19）。
pub const DEFAULT_AUTH_FILE: &str = "/var/lib/polaris/authorized-uids";
/// 默认锁定的 root-owned 受管核目录（Go default `/usr/local/lib/polaris/core`，:20）。
pub const DEFAULT_CORE_DIR: &str = "/usr/local/lib/polaris/core";

/// server 配置（flags 的类型化等价，对照 Go main 的 flag.String/flag.Bool）。
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// unix socket 路径。
    pub sock_path: PathBuf,
    /// 授权 uid 列表文件。
    pub auth_file: PathBuf,
    /// 锁定的 root-owned 受管核目录（None = install-core 报 coredir-unset）。
    pub core_dir: Option<PathBuf>,
    /// 前台运行（开发/测试，systemd 不要求）。
    pub console: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            sock_path: PathBuf::from(DEFAULT_SOCK_PATH),
            auth_file: PathBuf::from(DEFAULT_AUTH_FILE),
            core_dir: Some(PathBuf::from(DEFAULT_CORE_DIR)),
            console: false,
        }
    }
}

/// socket bind 失败的错误（对照 Go main 的 `fmt.Fprintln(os.Stderr, err); os.Exit(1)`，:35-37）。
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// socket 目录创建失败。
    #[error("mkdir socket dir {dir:?}: {source}")]
    Mkdir {
        dir: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// unix socket bind 失败。
    #[error("listen {path:?}: {source}")]
    Listen {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// chmod socket 失败。
    #[error("chmod {path:?}: {source}")]
    Chmod {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// 准备 socket：建目录 0755 + 删旧 socket + bind + chmod 0666（移植自 Go :25-38）。
///
/// 返回绑定好的 std UnixListener（同步，对齐 Go `net.Listen`）。生产 accept 循环在 async 上下文中
/// 经 `tokio::net::UnixListener::from_std` + `set_nonblocking(true)` 转换为 tokio listener。
/// 这样 bind/chmod 不依赖 tokio reactor，单元测试可在同步上下文直接验证。
pub fn prepare_socket(cfg: &ServerConfig) -> Result<std::os::unix::net::UnixListener, ServerError> {
    // :25-30: socket 目录必须 0755（任意登录用户可穿越 → app 才能连）。
    let sock_dir = cfg.sock_path.parent().unwrap_or_else(|| Path::new("/"));
    std::fs::create_dir_all(sock_dir).map_err(|source| ServerError::Mkdir {
        dir: sock_dir.to_path_buf(),
        source,
    })?;
    set_mode(sock_dir, 0o755).map_err(|source| ServerError::Chmod {
        path: sock_dir.to_path_buf(),
        source,
    })?;
    // :31: 删旧 socket（bind 失败 otherwise）。
    let _ = std::fs::remove_file(&cfg.sock_path);

    // :33-37: Listen(unix) —— std 同步 bind（对齐 Go net.Listen）。
    let listener = std::os::unix::net::UnixListener::bind(&cfg.sock_path).map_err(|source| {
        ServerError::Listen {
            path: cfg.sock_path.clone(),
            source,
        }
    })?;

    // :38: chmod socket 0666（SO_PEERCRED + 授权列表把关，socket 本身可连）。
    set_mode(&cfg.sock_path, 0o666).map_err(|source| ServerError::Chmod {
        path: cfg.sock_path.clone(),
        source,
    })?;

    Ok(listener)
}

/// 设文件/dir 权限（unix only）。
fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// ss 命令的输出提供者（freeport 用，对照 Go `exec.Command("ss", "-H", "-ltnp", ...)`，:292）。
///
/// 生产实现：调 `ss` 子进程；失败返回 None（freeport 视作端口空闲）。
pub fn ss_lookup(port: &str) -> Option<String> {
    let sport = format!("sport = :{port}");
    let out = std::process::Command::new("ss")
        .args(["-H", "-ltnp", &sport])
        .output()
        .ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        None
    }
}

/// IP 转发开关闭包（生产 = set_forward_prod，对齐 Go setForward）。
pub fn forward_fn() -> fn(bool) {
    set_forward_prod
}

// ===== L16 AmbientCaps 常量 + 集（对照 Go `helper-linux/helper.go:51-55,441`）=====

/// `capNetBindService`（Go :52）—— `caps::Capability::CAP_NET_BIND_SERVICE.index()` 恒等于此。
pub const CAP_NET_BIND_SERVICE_NUM: u8 = 10;
/// `capNetAdmin`（Go :53）。
pub const CAP_NET_ADMIN_NUM: u8 = 12;
/// `capNetRaw`（Go :54）。
pub const CAP_NET_RAW_NUM: u8 = 13;

/// start 拉核授予的 ambient capability 集（顺序对照 Go `AmbientCaps: []uintptr{capNetAdmin, capNetRaw,
/// capNetBindService}`，:441 —— 与现役 setcap 授权一致，不推测削减）。
#[must_use]
pub fn ambient_caps() -> [caps::Capability; 3] {
    [
        caps::Capability::CAP_NET_ADMIN,
        caps::Capability::CAP_NET_RAW,
        caps::Capability::CAP_NET_BIND_SERVICE,
    ]
}

// ===== terminate / watchParent 纯决策（可测；对照 Go terminateChild / watchParent）=====

/// terminate 宽限期（Go terminateChild：TERM → 等 ≤5s → KILL，:253）。
pub const TERMINATE_GRACE_SECS: u64 = 5;
/// watchParent 轮询周期（Go: `time.NewTicker(time.Second)`，:259）。
pub const WATCH_PARENT_INTERVAL_SECS: u64 = 1;

/// terminate 决策（对照 Go `terminateChild`，:246-256）：先 TERM，等退出；期限内退出则**不** KILL，
/// 超时才 KILL。抽象三原语便于单测（不发真信号）。`wait_exited` 返回是否在期限内退出。
fn terminate_child<S, W, K>(send_term: S, wait_exited: W, send_kill: K)
where
    S: FnOnce(),
    W: FnOnce() -> bool,
    K: FnOnce(),
{
    send_term(); // Go: c.Process.Signal(SIGTERM)
    if !wait_exited() {
        // Go: case <-time.After(5s): c.Process.Kill()
        send_kill();
    }
}

/// watchParent 单 tick 决策（对照 Go `watchParent` 循环体，:267-283）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchStep {
    /// 父仍活 + 仍是当前 child → 继续下一 tick。
    Continue,
    /// 已非当前 child（被 stop/cleanup 摘除或自然退出）→ 停看护（Go: `if !current { return }`）。
    Stop,
    /// 父已死（`kill(ppid,0)==ESRCH`）→ 摘 child + terminate（Go: :273-282）。
    ParentDead,
}

/// 由「仍是当前 child」+「父仍活」推出 watchParent 决策（纯逻辑，短路顺序对照 Go：先判 current 再判父存活）。
#[must_use]
pub fn watch_parent_step(still_current_child: bool, parent_alive: bool) -> WatchStep {
    if !still_current_child {
        WatchStep::Stop
    } else if !parent_alive {
        WatchStep::ParentDead
    } else {
        WatchStep::Continue
    }
}

// ===== 信号原语（nix safe wrapper；forbid(unsafe) 下替代 libc::kill）=====

/// u32 pid → nix Pid（真实 pid ≤ PID_MAX≈4M，恒 ≤ i32::MAX；越界退化 i32::MAX 仅防御性）。
fn to_pid(pid: u32) -> nix::unistd::Pid {
    nix::unistd::Pid::from_raw(i32::try_from(pid).unwrap_or(i32::MAX))
}

fn send_signal(pid: u32, sig: nix::sys::signal::Signal) -> nix::Result<()> {
    nix::sys::signal::kill(to_pid(pid), sig)
}

/// 父进程是否存活（对照 Go `syscall.Kill(ppid, 0) == ESRCH`，:273）。signal 0 仅探活不投递。
fn parent_alive(ppid: u32) -> bool {
    nix::sys::signal::kill(to_pid(ppid), None).is_ok()
}

// ===== child 退出协调槽（对应 Go `childDone chan struct{}`）=====

/// 单个 child 的退出协调槽：收割线程 `child.wait()` 收尸后 [`mark_exited`](ChildSlot::mark_exited) 唤醒
/// 等待中的 terminate（TERM 后据此决定是否 KILL），并让 watchParent 的 tick 等待可提前结束。
///
/// **顺序不变式**：收割线程必须先 `mark_exited` 再去拿 `HandlerState` 锁清 child —— 否则与「持 state 锁
/// 调 terminate 并等 `wait_exited`」的 handler 线程互等死锁。
struct ChildSlot {
    pid: u32,
    exited: Mutex<bool>,
    cv: Condvar,
}

impl ChildSlot {
    fn new(pid: u32) -> Arc<Self> {
        Arc::new(Self {
            pid,
            exited: Mutex::new(false),
            cv: Condvar::new(),
        })
    }

    fn mark_exited(&self) {
        let mut g = self.exited.lock().unwrap_or_else(PoisonError::into_inner);
        *g = true;
        self.cv.notify_all();
    }

    /// 在「本 pid 仍指向本 child」的前提下投递信号；返回是否真的投递。
    ///
    /// pid 的复用窗口从收割线程的 `child.wait()` 返回那一刻开始 —— 在此之前 child 是僵尸，pid 被内核
    /// 占住、系统不会复用；而 `exited` 恰好是「wait 已返回」的标记，故它就是**唯一**能把「这个 pid 还是
    /// 我的 child」判准的东西（slot 在不在册判不了：收割线程的次序是 `mark_exited` → 取 state 锁清
    /// `child` → 从 slots 摘除，handler 全程持 state 锁会把中间那步挡住，slot 于是能在「已收割」状态下
    /// 长期留在册上）。
    ///
    /// 判定与投递必须在**同一把 `exited` 锁**下完成：先判后发会留一个「判完 → wait 返回 → pid 被系统
    /// 复用 → 信号打到无关进程」的窗口，而收割线程正是在 [`mark_exited`](Self::mark_exited) 里拿这把锁。
    fn signal_if_live(&self, send: impl FnOnce(u32)) -> bool {
        let exited = self.exited.lock().unwrap_or_else(PoisonError::into_inner);
        if *exited {
            return false;
        }
        send(self.pid);
        true
    }

    /// 等退出，最多 `timeout`；返回是否在期限内退出（对应 Go `select{<-done; <-time.After(...)}`）。
    fn wait_exited(&self, timeout: Duration) -> bool {
        let g = self.exited.lock().unwrap_or_else(PoisonError::into_inner);
        let (g, _) = self
            .cv
            .wait_timeout_while(g, timeout, |exited| !*exited)
            .unwrap_or_else(PoisonError::into_inner);
        *g
    }
}

/// 对某 child 执行 terminate（TERM→≤5s→KILL，经 slot 协调）。
///
/// pid-复用安全由 [`ChildSlot::signal_if_live`] 兜住：**两条**信号腿都只在「尚未被收割」时投递。
/// 只判「slot 还在册」是不够的（见 `signal_if_live` 文档），TERM 腿同样会打到复用后的新进程。
fn terminate_slot(slot: &ChildSlot) {
    let grace = Duration::from_secs(TERMINATE_GRACE_SECS);
    terminate_child(
        || {
            slot.signal_if_live(|pid| {
                let _ = send_signal(pid, nix::sys::signal::Signal::SIGTERM);
            });
        },
        || slot.wait_exited(grace),
        || {
            slot.signal_if_live(|pid| {
                let _ = send_signal(pid, nix::sys::signal::Signal::SIGKILL);
            });
        },
    );
}

// ===== reapWG：在途后台 terminate 计数（对应 Go `reapWG sync.WaitGroup`，L15）=====

/// SIGTERM 退出前须等在途后台 terminate 跑完 KILL 升级，杜绝留下带 CAP_NET_ADMIN 的孤儿核。
struct ReapGroup {
    count: Mutex<usize>,
    cv: Condvar,
}

impl ReapGroup {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            count: Mutex::new(0),
            cv: Condvar::new(),
        })
    }
    fn add(&self) {
        *self.count.lock().unwrap_or_else(PoisonError::into_inner) += 1;
    }
    fn done(&self) {
        let mut g = self.count.lock().unwrap_or_else(PoisonError::into_inner);
        *g = g.saturating_sub(1);
        if *g == 0 {
            self.cv.notify_all();
        }
    }
    /// 等在途 terminate 归零，最多 `timeout`（对照 Go `waitReaps`，`main.go:73-80`）。
    fn wait(&self, timeout: Duration) {
        let g = self.count.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = self
            .cv
            .wait_timeout_while(g, timeout, |c| *c > 0)
            .unwrap_or_else(PoisonError::into_inner);
    }
}

// ===== L10 真 CoreSpawner：fork + setuid + AmbientCaps 拉核 =====

/// 生产 spawner（对照 Go start 分支 `c.SysProcAttr = ...; c.Start()`，:431-478）。
///
/// 持共享 [`HandlerState`]（收割/看护线程清 child）+ 在途 child 槽（terminate 按 pid 查）+ reapWG。
pub struct AmbientCapsSpawner {
    state: Arc<Mutex<HandlerState>>,
    /// 在途 child 槽（至多 1 个：start 见 running 回 already）。收割后移除。
    slots: Arc<Mutex<Vec<Arc<ChildSlot>>>>,
    /// 在途后台 terminate 计数（SIGTERM 退出前 waitReaps 等它归零）。
    reaps: Arc<ReapGroup>,
}

/// 把用户可写日志目录固定到已打开的 directory fd，后续即使目录名被 rename/symlink 替换，
/// root helper 仍只会在原目录打开日志。末段 symlink 由 log-budget 的 `O_NOFOLLOW` 拒绝。
#[derive(Debug)]
struct PinnedLogPath {
    directory: Arc<File>,
    path: PathBuf,
}

fn pin_log_path(path: &Path, uid: u32) -> std::io::Result<PinnedLogPath> {
    use std::os::unix::fs::MetadataExt;

    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "log path has no parent")
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "log path has no file name",
        )
    })?;
    let directory = File::open(parent)?;
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.uid() != uid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "log directory is not owned by the authenticated uid",
        ));
    }
    let fd: RawFd = directory.as_raw_fd();
    Ok(PinnedLogPath {
        directory: Arc::new(directory),
        path: PathBuf::from(format!("/proc/self/fd/{fd}")).join(file_name),
    })
}

struct PinnedReader<R> {
    inner: R,
    _directory: Arc<File>,
}

impl<R: Read> Read for PinnedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buffer)
    }
}

impl AmbientCapsSpawner {
    #[must_use]
    pub fn new(state: Arc<Mutex<HandlerState>>) -> Self {
        Self {
            state,
            slots: Arc::new(Mutex::new(Vec::new())),
            reaps: ReapGroup::new(),
        }
    }

    fn find_slot(&self, pid: u32) -> Option<Arc<ChildSlot>> {
        self.slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .find(|s| s.pid == pid)
            .cloned()
    }

    /// 等在途后台 terminate 归零（对照 Go `waitReaps`）。SIGTERM 退出兜底用。
    pub fn wait_reaps(&self, timeout: Duration) {
        self.reaps.wait(timeout);
    }

    /// 同步 terminate 指定 child（SIGTERM 退出兜底对当前 child 用，Go main reaper 同步 `terminateChild`）。
    fn terminate_now(&self, pid: u32) {
        if let Some(slot) = self.find_slot(pid) {
            terminate_slot(&slot);
        }
    }
}

impl CoreSpawner for AmbientCapsSpawner {
    fn spawn(&self, req: &SpawnCoreRequest) -> Result<SpawnedCore, SpawnError> {
        let pinned_log = req
            .log
            .as_deref()
            .map(|path| pin_log_path(path, req.uid))
            .transpose()
            .map_err(|error| SpawnError::Spawn {
                detail: format!("secure log path: {error}"),
            })?;
        // Go: exec.Command(coreBin(), "run", "-c", cfg)（:431）。
        let mut cmd = std::process::Command::new(&req.binary);
        cmd.arg("run").arg("-c").arg(&req.config);

        // CWD = 配置文件所在目录（= 用户可写 config 目录）：helper daemon（systemd）CWD=`/`，spawn 的核继承 `/`
        // → dashboard 下载兜底相对 mkdir `/dashboard` 只读失败噪音。设为可写目录即消。std 在 fork 后、pre_exec
        // 降权闭包**之前** chdir（此刻仍 root，可 chdir 任意目录），降权后核 CWD = 用户目录，两不冲突。
        // Polaris 生成的核配置其余路径全绝对，不受 CWD 影响。取不到父目录（极端形态）则不设，继承旧行为。
        if let Some(cwd) = req.config.parent() {
            cmd.current_dir(cwd);
        }

        // B3/W26：child 输出走 pipe → shared 有界 writer；直接继承一个 append fd 无法在运行期安全
        // 轮转（rename 后 child 仍写旧 inode/handle），正是历史 `singbox.log` 无界增长的同型风险。
        if pinned_log.is_some() {
            cmd.stdout(std::process::Stdio::piped());
            cmd.stderr(std::process::Stdio::piped());
        }

        // Go :434-442：SysProcAttr{Credential{Uid,Gid,Groups}, AmbientCaps}。降权+ambient 经 pre_exec 装。
        attach_privilege_drop(&mut cmd, req.uid, req.gid, req.groups.clone());

        // Go :452：c.Start()。失败 → ERR start（转发态复位由 handler 负责，对照 :456）。
        let process_started = std::time::Instant::now();
        let mut child = cmd.spawn().map_err(|e| SpawnError::Spawn {
            detail: e.to_string(),
        })?;
        let pid = child.id();
        let process_ms = crate::elapsed_ms(process_started);

        let log_handoff_started = std::time::Instant::now();
        if let Some(log) = pinned_log {
            // 与 Windows 已验证形态一致：pipe 所有权先交后台，日志裁剪/轮转/open/fchown 不再阻塞
            // helper 回复。线程持有读端，child 不会在 writer 就绪前收到 broken pipe。
            let stdout = child.stdout.take().map(|inner| PinnedReader {
                inner,
                _directory: Arc::clone(&log.directory),
            });
            let stderr = child.stderr.take().map(|inner| PinnedReader {
                inner,
                _directory: Arc::clone(&log.directory),
            });
            let owned_log_path = log.path;
            let directory = log.directory;
            let uid = req.uid;
            let gid = req.gid;
            std::thread::spawn(move || {
                // 保持 directory fd 至少活到 writer 同步打开；两个 PinnedReader 再把它持到管道排空，
                // 覆盖运行期轮转对 `/proc/self/fd/<n>` 的后续重开。
                let _directory = directory;
                polaris_log_budget::spawn_pipe_loggers_with_file(
                    stdout,
                    stderr,
                    &owned_log_path,
                    polaris_log_budget::DEFAULT_GENERATION_BYTES,
                    |opened| {
                        // helper 自身是 root，创建出的文件需归还对端属主；直接作用于 writer 已打开的
                        // 同一 fd，不再按用户可写路径二次 open，避免路径替换让属主修正打到别的 inode。
                        if let Some(file) = opened {
                            let _ = std::os::unix::fs::fchown(file, Some(uid), Some(gid));
                        }
                    },
                );
            });
        }
        let log_handoff_ms = crate::elapsed_ms(log_handoff_started);

        let slot = ChildSlot::new(pid);
        self.slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Arc::clone(&slot));

        // Go :466-474：收割 goroutine —— c.Wait() 收尸 → close(done) → 清 child（若仍是本 child）。
        spawn_reaper(
            child,
            pid,
            Arc::clone(&self.state),
            Arc::clone(&slot),
            Arc::clone(&self.slots),
        );

        // Go :475-477：if ppid>0 { go watchParent(ppid, c, done) }。
        if let Some(ppid) = req.parent_pid {
            spawn_watch_parent(ppid, pid, Arc::clone(&self.state), Arc::clone(&slot));
        }

        // Go :478：OK started <pid>（wire 由 handler 拼）。
        Ok(SpawnedCore {
            handle: CoreHandle { pid },
            process_ms,
            log_handoff_ms,
        })
    }

    fn terminate(&self, h: &CoreHandle) {
        // Go stop：`reapWG.Add(1); go terminateChild(c, done)`（:375-376）—— 后台 TERM→≤5s→KILL，
        // stop 立即回复、**不持 state 锁 5s**。无槽 = no-op；在册但已收割的 slot 由 terminate_slot 内的
        // `signal_if_live` 逐腿挡住（防 pid 复用误杀）。
        let Some(slot) = self.find_slot(h.pid) else {
            return;
        };
        let reaps = Arc::clone(&self.reaps);
        reaps.add();
        std::thread::spawn(move || {
            terminate_slot(&slot);
            reaps.done();
        });
    }

    fn kill(&self, h: &CoreHandle) {
        // Go cleanup：child.Process.Kill()（SIGKILL 即时；收割线程随后收尸，:383）。
        // 身份判据与 terminate 同源（slot 在册 + 尚未被收割）：cleanup 拿到的 `h.pid` 来自 state.child，
        // 而收割线程清 state.child 那一步会被「全程持 state 锁」的 handler 挡住 ⇒ 这里完全可能拿到一个
        // 已被 wait() 收走、已被系统复用的 pid，裸 SIGKILL 就是误杀无关进程。无槽/已收割 = no-op。
        if let Some(slot) = self.find_slot(h.pid) {
            slot.signal_if_live(|pid| {
                let _ = send_signal(pid, nix::sys::signal::Signal::SIGKILL);
            });
        }
    }
}

/// 装 pre_exec 降权+ambient 拉核闭包（**唯一 unsafe 点** = `CommandExt::pre_exec`）。
///
/// 所有可分配的输入（gids/caps 列表）在 fork **前**于父进程算好，闭包本体只做 syscall。
#[allow(
    unsafe_code,
    reason = "CommandExt::pre_exec is required to drop uid/gid before exec"
)]
fn attach_privilege_drop(cmd: &mut std::process::Command, uid: u32, gid: u32, groups: Vec<u32>) {
    use std::os::unix::process::CommandExt;
    let gids: Vec<nix::unistd::Gid> = groups.into_iter().map(nix::unistd::Gid::from_raw).collect();
    let caps = ambient_caps();
    // SAFETY: pre_exec 闭包在 fork 后、execve 前于**子进程**运行，仅调 async-signal-safe 的 syscall
    //   （set_keepcaps/setgroups/setgid/setuid + capset/prctl via caps crate），且 gids/caps 列表已在
    //   fork 前于父进程分配 → 闭包本体不分配。每步失败即返 Err 中止 execve（**fail-closed**：setuid 失败
    //   绝不以 root 拉核）。残留风险：caps crate 内部 capget 可能分配 —— 与「真降权拉核链」同属真机门
    //   （DESIGN-REVIEW(preexec-async-signal-safety)），本机绝不跑。
    unsafe {
        cmd.pre_exec(move || apply_privilege_drop(uid, gid, &gids, &caps));
    }
}

/// pre_exec 闭包本体：降权到对端登录用户 + raise ambient caps（全 safe wrapper，无 unsafe 块）。
///
/// 顺序对照 Go runtime 对 `SysProcAttr{Credential, AmbientCaps}` 的编排（keepcaps→降权→raise ambient）：
/// 1. `set_keepcaps(true)`：permitted caps 跨 setuid 存活（Go AmbientCaps 非空时 PR_SET_KEEPCAPS）。
/// 2. `setgroups`：补充组（须在 setuid 前、仍 root 时；空 = 清空，对齐 Go `Groups: nil`）。
/// 3. `setgid` → 4. `setuid`：降权（drop 放最后）。
/// 5. raise Inheritable + 6. raise Ambient（逐 cap；降权后 permitted 已留，加 inheritable 再抬 ambient）。
///
/// 任一步失败即 `Err` → std 中止 execve → `c.spawn()` 返错 → handler 回 `ERR start`（fail-closed）。
fn apply_privilege_drop(
    uid: u32,
    gid: u32,
    groups: &[nix::unistd::Gid],
    caps: &[caps::Capability],
) -> std::io::Result<()> {
    use nix::unistd::{setgid, setgroups, setuid, Gid, Uid};
    caps::securebits::set_keepcaps(true).map_err(std::io::Error::other)?;
    setgroups(groups).map_err(std::io::Error::other)?;
    setgid(Gid::from_raw(gid)).map_err(std::io::Error::other)?;
    setuid(Uid::from_raw(uid)).map_err(std::io::Error::other)?;
    for &cap in caps {
        caps::raise(None, caps::CapSet::Inheritable, cap).map_err(std::io::Error::other)?;
        caps::raise(None, caps::CapSet::Ambient, cap).map_err(std::io::Error::other)?;
    }
    Ok(())
}

/// 收割线程（Go reaper goroutine，:466-474）。owns Child → `wait()` 收尸（防僵尸）。
fn spawn_reaper(
    mut child: std::process::Child,
    pid: u32,
    state: Arc<Mutex<HandlerState>>,
    slot: Arc<ChildSlot>,
    slots: Arc<Mutex<Vec<Arc<ChildSlot>>>>,
) {
    std::thread::spawn(move || {
        let _ = child.wait(); // Go: _ = c.Wait()
                              // 顺序不变式：先唤醒等待中的 terminate（不需 state 锁），再拿 state 锁清 child——杜绝与
                              // 「持 state 锁调 terminate 等 wait_exited」的 handler 线程死锁。
        slot.mark_exited(); // Go: close(done)
        {
            let mut g = state.lock().unwrap_or_else(PoisonError::into_inner);
            if g.child.as_ref().map(|h| h.pid) == Some(pid) {
                g.child = None; // Go: if child == c { child, childDone = nil, nil }
            }
        }
        slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|s| s.pid != pid);
    });
}

/// 父死看护线程（Go `watchParent`，:258-285）。每 1s tick：child 退出→停；非当前 child→停；父死→摘+terminate。
fn spawn_watch_parent(ppid: u32, pid: u32, state: Arc<Mutex<HandlerState>>, slot: Arc<ChildSlot>) {
    std::thread::spawn(move || {
        let interval = Duration::from_secs(WATCH_PARENT_INTERVAL_SECS);
        loop {
            // Go: select{<-done; <-t.C}。以 slot.wait_exited 折叠「等 1s 或 child 已退出」：
            // 已退出（true）→ 停看护（Go: <-done → return）；超时（false）→ 走 tick 检查。
            if slot.wait_exited(interval) {
                return;
            }
            // Go: current := (child == c)。仍是当前 child 才继续（否则被 stop/cleanup 摘除）。
            let still_current = {
                let g = state.lock().unwrap_or_else(PoisonError::into_inner);
                g.child.as_ref().map(|h| h.pid) == Some(pid)
            };
            // 短路顺序对齐 Go：仅当仍是当前 child 才探父存活（parent_alive 是一次 kill(0) syscall）。
            let alive = still_current && parent_alive(ppid);
            match watch_parent_step(still_current, alive) {
                WatchStep::Continue => {}
                WatchStep::Stop => return,
                WatchStep::ParentDead => {
                    // Go :274-280：摘 child（若仍是本 child）。
                    {
                        let mut g = state.lock().unwrap_or_else(PoisonError::into_inner);
                        if g.child.as_ref().map(|h| h.pid) == Some(pid) {
                            g.child = None;
                        }
                    }
                    // Go :281：terminateChild(c, done)（不持 state 锁）。
                    terminate_slot(&slot);
                    return;
                }
            }
        }
    });
}

// ===== 生产连接服务（accept 循环 → handle）=====

/// 跨连接共享的 daemon 服务：持 [`HandlerState`] + [`AmbientCapsSpawner`] + 生产 deps，把 accept 到的
/// tokio `UnixStream` 交给同步 [`handle`](crate::platform::linux::handle)（Go `for { l.Accept(); go handle }`）。
pub struct ConnServer {
    state: Arc<Mutex<HandlerState>>,
    spawner: Arc<AmbientCapsSpawner>,
    freeport: crate::platform::linux::freeport::ProdFreePortDeps,
    systemd: crate::platform::linux::ops::TokioSystemd,
    resolved_dns: crate::platform::linux::resolved_dns::ResolvectlDnsOps,
    core_dir: Option<PathBuf>,
    auth_file: PathBuf,
    /// 在途连接闸（与 mac 腿同一份类型、同一个上限，见 [`crate::platform::conn_limit`]）。
    limiter: Arc<ConnLimiter>,
    /// 超限告警的限频器：达上限是持续态，逐次打就是第二个 DoS 面（写爆 journal）。
    limit_log: LogThrottle,
}

impl ConnServer {
    /// 由 [`ServerConfig`] 建服务（单一共享 state + spawner）。
    #[must_use]
    pub fn new(cfg: &ServerConfig) -> Arc<Self> {
        let state = Arc::new(Mutex::new(HandlerState::new()));
        let spawner = Arc::new(AmbientCapsSpawner::new(Arc::clone(&state)));
        Arc::new(Self {
            state,
            spawner,
            freeport: crate::platform::linux::freeport::ProdFreePortDeps,
            systemd: crate::platform::linux::ops::TokioSystemd,
            resolved_dns: crate::platform::linux::resolved_dns::ResolvectlDnsOps::new(),
            core_dir: cfg.core_dir.clone(),
            auth_file: cfg.auth_file.clone(),
            limiter: ConnLimiter::new(MAX_CONCURRENT_CONNECTIONS),
            limit_log: LogThrottle::new(ACCEPT_LOG_INTERVAL),
        })
    }

    /// 处理一个连接（Go: `go handle(conn)`）。捕获 SO_PEERCRED → 转 std 阻塞流（5s 读超时）→
    /// spawn_blocking 跑同步 handle（含 fork 拉核，不占 async worker）。
    ///
    /// **补 Go 源没有的护栏**（复审 Medium，与 mac 腿同口径）：起 `spawn_blocking` 之前先取
    /// [`ConnLimiter`] 许可。socket 是 0666、uid 鉴权发生在 `handle` **之内**，即阻塞任务是在
    /// 鉴权之前起的 —— 无上限时「连上就滴喂、不发完整帧」的无 token 进程能按连接数占满
    /// `spawn_blocking` 池（合法请求排队等不到，比 EMFILE 更早发作），再攥满 fd 走到 EMFILE。
    pub fn dispatch(self: &Arc<Self>, stream: tokio::net::UnixStream) {
        use crate::platform::linux::auth::{CapturedPeerCred, PeerCredProvider, TokioPeerCred};
        use crate::platform::linux::handler::{handle, HandlerDeps, LineConn, READ_TIMEOUT_SECS};

        // 0. 闸在**起阻塞任务之前**（也在鉴权之前）。超限即快速失败：`stream` 在此 drop = 立即关连接，
        //    不排队（排队只是把耗尽从池搬到队列，攻击面不变）、不阻塞 accept 循环。
        let Some(permit) = self.limiter.try_acquire() else {
            if self.limit_log.allow() {
                eprintln!(
                    "polaris-helper (linux): 在途连接达上限 {MAX_CONCURRENT_CONNECTIONS}，拒绝新连接"
                );
            }
            drop(stream);
            return;
        };

        // 1. 先取 SO_PEERCRED（转 std 后原流被消费，无法再取）。失败 → 捕获 None → handle 回 ERR peercred。
        let cred = TokioPeerCred::new(&stream).peer_cred();
        // 2. 转 std 阻塞流 + 5s 读超时。Go SetReadDeadline 是**连接级绝对**期限，std set_read_timeout 是
        //    **每次读** SO_RCVTIMEO —— 行数上界固定（start ≤6 行），DESIGN-REVIEW(read-deadline-per-read)，
        //    且 socket 已受授权 uid 门限，差异可控。
        let std_stream = match stream.into_std() {
            Ok(s) => s,
            Err(_) => return,
        };
        if std_stream.set_nonblocking(false).is_err() {
            return;
        }
        let _ = std_stream.set_read_timeout(Some(Duration::from_secs(READ_TIMEOUT_SECS)));

        let this = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            // 许可随阻塞任务结束（含 panic 展开）归还，见 ConnPermit 文档。
            let _permit = permit;
            let peer = CapturedPeerCred(cred);
            let ss_fn = ss_lookup;
            let fwd_fn = set_forward_prod;
            let ss: &(dyn Fn(&str) -> Option<String> + Send + Sync) = &ss_fn;
            let fwd: &(dyn Fn(bool) + Send + Sync) = &fwd_fn;
            let deps = HandlerDeps {
                core_dir: this.core_dir.as_deref(),
                auth_file: &this.auth_file,
                peer_cred: &peer,
                spawner: this.spawner.as_ref(),
                freeport_deps: &this.freeport,
                systemd: &this.systemd,
                resolved_dns: &this.resolved_dns,
                ss_provider: ss,
                set_forward: fwd,
            };
            let state: &Mutex<HandlerState> = &this.state;
            let mut conn = LineConn::new(std_stream);
            handle(state, &deps, &mut conn);
        });
    }

    /// SIGTERM 退出兜底（Go main reaper，`main.go:46-54`）：同步 terminate 当前 child（TERM→≤5s→KILL）+
    /// waitReaps 等在途后台 terminate 归零。调用方随后 `set_forward_prod(false)`（对齐 `main.go:55`）。
    pub fn reap_on_shutdown(&self) {
        let child = {
            let mut g = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            g.child.take()
        };
        if let Some(h) = child {
            self.spawner.terminate_now(h.pid); // 同步（Go main 里 terminateChild 是同步调用）。
        }
        self.spawner.wait_reaps(Duration::from_secs(6));
    }
}

#[cfg(test)]
mod tests;
