//! sing-box spawn —— 上游 `ProxyManager.startSingBoxProcess` 直接 spawn 路径（systemProxy / Linux setcap）
//! 的 Rust 移植（源 `ProxyManager.ts:4789-4836`）。
//!
//! 不变式：
//! - 直接以 app 用户 spawn 非提权进程（command = singbox_path, args = ['run', '-c', config_path]）。
//! - stdin 恒 ignore；stdout/stderr 的去向由 [`StdioPolicy`] **必填**给出（管道 + 排空，或显式丢弃）。
//! - windowsHide = true（GUI 进程 spawn 控制台程序隐藏黑窗；macOS/Linux 忽略）。
//! - spawn 失败（ENOENT/EACCES）→ [`SpawnError`]，上层进 retry 链（不在此处自动重启）。
//! - **经 [`TokioSpawner::spawn`] 拿到的 [`SpawnedChild`]，两条管道恒已交出**：`child.stdout` 与
//!   `child.stderr` 都是 `None`。开管道与排空这两个决定被绑在同一次调用里，「起了核却忘记排空」
//!   写不出来。这一条由那个函数保证、不是类型层的不变式（`SpawnedChild` 的字段是 `pub`，
//!   见它的文档）。
//!
//! # 为什么把处置策略做成必填字段（这一条是本模块最容易被下一个人改掉的东西）
//!
//! 2026-09-02 的测速临时核卡死，链路是：spawner 一律 `Stdio::piped()` 开两条管道，主核与瞬态登录核
//! 各自记得去读，测速临时核这第三个调用方没有 —— 管道写满之后核的下一次 `write(2)` 永久阻塞，
//! sing-box 卡死但不死。macOS 真机 `debug` 档 118 个请求只有 22 个拿到值、核回收耗时 5.0 s；同一份
//! 订阅换 `info` 档是 111 个、58 ms。根因不在「谁忘了写那两行」，而在**开管道的决定与排空的决定被
//! 拆在两个地方**：spawner 决定开，调用方决定读，第三个调用方出现时没有任何东西提醒它还有第二半。
//!
//! 收口的做法是把这两个决定重新绑回一次调用：请求里必须带 [`StdioPolicy`]，spawner 自己在返回之前
//! 把两个读端交给策略里的回调。少写这一格编不过（`error[E0061]` / `error[E0063]`，实证见
//! [`SpawnRequest`] 的两条 `compile_fail` 文档测试）。
//!
//! 不触碰宿主网络/sing-box：本文件的单元测试全是纯桩（只测 `argv()` 生成与 spawn 错误映射）。
//! **真实 spawn 的接线门在 `tests/spawner_process.rs`**——它拿本 crate 的测试探针 bin
//! （`src/bin/argv_probe.rs`）当「核」，三平台同跑；放集成测试是因为取探针路径的
//! `CARGO_BIN_EXE_<name>` 只在集成测试期由 cargo 注入。

use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::Child;

/// 子进程一条输出流的装箱读端。
///
/// 装箱而不是走泛型：生产的 spawner 交出来的是 `tokio::process::ChildStdout` / `ChildStderr`，
/// 而测试里的假 spawner 交出来的是内存 duplex 的读端。两者要能喂**同一个**排空回调，回调的入参
/// 就只能是 trait object。代价是每条流多一次 Box 分配（每次起核两次，可忽略），换来的是「生产与
/// 测试走同一条排空接线」——夹具另走一条路的时候，门测的就不再是生产那条路。
pub type ChildStream = Box<dyn tokio::io::AsyncRead + Unpin + Send>;

/// 排空回调：spawn 成功之后由 spawner **在返回之前**调用，两条流一次交齐。
///
/// 签名把两条流绑在同一个 `FnOnce` 上，这是收口的关键形态：
/// - 只拿到其中一条而另一条不知去向 —— 写不出来（回调必须同时接两个参数）；
/// - 把同一条流排两遍（`take_stderr()` 误写成 `take_stdout()` 这类复制粘贴错，正是本轮根因缺陷的
///   原形态）—— 所有权已移动，写不出来（`error[E0382]: use of moved value`）。
///
/// 类型层管不到的那一格：回调**可以**把某个参数直接丢掉（`|out, _err| …`）。丢掉读端不会挂死核
/// （管道读端一关，核的下一次写拿到 EPIPE/SIGPIPE 而不是阻塞），但那条流的诊断就没了。这一格由
/// 源码级守卫门 `src-tauri/tests/subprocess_stdio_discipline.rs` 的注册表 2 继续守着。
pub type StdioSink = Box<dyn FnOnce(ChildStream, ChildStream) + Send>;

/// 子进程两条输出流的**必填**处置策略。
///
/// 没有 `Default`，也没有一个「不填」的构造路径：[`SpawnRequest`] 少了这一格就编不过。
pub enum StdioPolicy {
    /// 两路都 `Stdio::null()`：显式声明「不要这个子进程的输出」。内核直接丢弃，永不阻塞。
    Discard,
    /// 两路 `Stdio::piped()`，spawn 成功后立刻把两个读端交给回调（由回调去起排空任务或线程）。
    Drain(StdioSink),
}

impl StdioPolicy {
    /// 构造 [`StdioPolicy::Drain`]，省掉每个调用点的 `Box::new`。
    pub fn drain(sink: impl FnOnce(ChildStream, ChildStream) + Send + 'static) -> Self {
        Self::Drain(Box::new(sink))
    }
}

impl std::fmt::Debug for StdioPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 回调本身不可打印，只报形态 —— 排查起核问题时要看的是「这次到底开没开管道」。
        match self {
            Self::Discard => f.write_str("Discard"),
            Self::Drain(_) => f.write_str("Drain(..)"),
        }
    }
}

/// spawn 请求（直接 spawn 路径，:4789-4791）。
///
/// **不再 `Clone`**：`stdio` 里的排空回调是 `FnOnce`，一份请求只对应一次 spawn。这不是被类型逼出来
/// 的妥协，而是把本来就成立的语义写进类型 —— 复制一份请求再 spawn 一次，两个子进程会共用同一个只
/// 能调一次的回调，第二个核的管道从此无人读。
///
/// # 「不给 stdio 处置就编不过」的实证
///
/// 少一个实参（`error[E0061]`）：
///
/// ```compile_fail
/// use polaris_core_supervisor::SpawnRequest;
/// // 忘了说这个核的 stdout/stderr 归谁 —— 编译期就断在这里。
/// let _ = SpawnRequest::new("/usr/local/bin/sing-box", "/tmp/cfg.json");
/// ```
///
/// 绕开构造函数、直接写结构体字面量也一样（`error[E0063]: missing field `stdio``）：
///
/// ```compile_fail
/// use polaris_core_supervisor::SpawnRequest;
/// let _ = SpawnRequest {
///     binary: "/usr/local/bin/sing-box".into(),
///     config: "/tmp/cfg.json".into(),
///     extra_args: Vec::new(),
///     working_dir: None,
/// };
/// ```
///
/// **正向对照**（上面两条若是因为别的原因编不过——路径写错、crate 名写错——这一条会跟着一起红，
/// 而它必须绿）：把那一格补上就编得过。
///
/// ```
/// use polaris_core_supervisor::{SpawnRequest, StdioPolicy};
/// let _ = SpawnRequest::new("/usr/local/bin/sing-box", "/tmp/cfg.json", StdioPolicy::Discard);
/// let _ = SpawnRequest {
///     binary: "/usr/local/bin/sing-box".into(),
///     config: "/tmp/cfg.json".into(),
///     extra_args: Vec::new(),
///     working_dir: None,
///     stdio: StdioPolicy::drain(|_stdout, _stderr| {}),
/// };
/// ```
pub struct SpawnRequest {
    /// sing-box 二进制绝对路径。
    pub binary: PathBuf,
    /// 配置文件绝对路径。
    pub config: PathBuf,
    /// 额外 CLI 参数（默认仅 `run -c <config>`）。
    pub extra_args: Vec<String>,
    /// 子进程工作目录（`None` = 继承父进程 CWD）。
    ///
    /// **为什么需要**：GUI 从 Finder/launchd 拉起时父进程 CWD = `/`（只读）。sing-box 对配置里**相对**路径
    /// （唯一一处：`clash_api`/`services[].dashboard` 省略 `path` 时的联网下载兜底目录 `dashboard`）按 CWD 解析
    /// → 落 `/dashboard` → 只读 mkdir 每次起核报一条噪音。设为可写 config 目录即消噪。**Polaris 生成的其余路径
    /// （cache.db / singbox.log / rules / rule-resource / custom-rules / tailscale state）全为绝对路径**，不受
    /// CWD 影响（见 `ProxyRuntime::generate_deps`）——故此改仅影响 dashboard 下载兜底这一条相对路径。
    pub working_dir: Option<PathBuf>,
    /// 两条输出流的处置（**必填**，见 [`StdioPolicy`] 与本结构体的文档测试）。
    pub stdio: StdioPolicy,
}

impl std::fmt::Debug for SpawnRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 手写而非 derive：`stdio` 里装着回调，derive(Debug) 推不出来。字段一个不少地照报，
        // 起核失败时日志里那行 `SpawnRequest { .. }` 仍然说得出这次到底喂了什么。
        f.debug_struct("SpawnRequest")
            .field("binary", &self.binary)
            .field("config", &self.config)
            .field("extra_args", &self.extra_args)
            .field("working_dir", &self.working_dir)
            .field("stdio", &self.stdio)
            .finish()
    }
}

impl SpawnRequest {
    /// 构造默认请求：`sing-box run -c <config>`，两条输出流按 `stdio` 处置。
    pub fn new(binary: impl Into<PathBuf>, config: impl Into<PathBuf>, stdio: StdioPolicy) -> Self {
        Self {
            binary: binary.into(),
            config: config.into(),
            extra_args: Vec::new(),
            working_dir: None,
            stdio,
        }
    }

    /// 完整 CLI 参数序列（`[run, -c, <config>, ...extra]`）。
    pub fn argv(&self) -> Vec<String> {
        let mut v = vec![
            "run".to_string(),
            "-c".to_string(),
            self.config.to_string_lossy().into_owned(),
        ];
        v.extend(self.extra_args.iter().cloned());
        v
    }
}

/// spawn 出的子进程句柄（tokio::process::Child 包装）。
///
/// **由 [`TokioSpawner::spawn`] 保证**（不是类型层的不变式）：经它拿到的 `SpawnedChild`，两条管道
/// 已经交出去了 —— `child.stdout` 与 `child.stderr` 恒为 `None`（`Discard` 策略下压根没开管道，
/// `Drain` 策略下读端在返回之前就交给了请求里的回调）。走这条路的调用方对 child 只剩生命周期职责
/// （`wait` / `start_kill` / 收割），没有「还得记得去读管道」这半件事。
///
/// **措辞是「由构造它的那个函数保证」而不是「不变式」，因为类型上不成立**：`child` 字段是 `pub`、
/// 本结构体没有私有构造器，工作区内任何人都可以从一个裸 `Command` 造一个带着活管道的
/// `SpawnedChild`。真正在类型上兜住的是**请求那一侧**（[`SpawnRequest::stdio`] 必填，见
/// [`StdioPolicy`]）；这一侧靠的是「全仓只有 `TokioSpawner` 构造它」，而那件事由源码级守卫门
/// `src-tauri/tests/subprocess_stdio_discipline.rs` 守（`SpawnedChild` 是它类型面词表里的一项，
/// 任何生产文件提到它而不登记就当场红）。
///
/// 把字段改私有能把这句话变回真正的不变式，但那会波及全部消费点，不在收口这一批的射程内。
pub struct SpawnedChild {
    pub child: Child,
}

impl std::fmt::Debug for SpawnedChild {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpawnedChild")
            .field("pid", &self.child.id())
            .finish()
    }
}

impl SpawnedChild {
    /// 子进程 pid（spawn 后立即可用；None = 已退出或未拿到）。
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }
}

/// spawn 错误（对应 NodeJS spawn ENOENT/EACCES → 上层 retry 链）。
#[derive(Debug, thiserror::Error)]
pub enum SpawnError {
    /// 二进制不存在 / 无执行权限（ENOENT/EACCES）。
    #[error("sing-box spawn 失败（{bin:?}）: {source}")]
    Spawn {
        bin: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// spawn 抽象（trait 便于测试 mock；生产用 [`TokioSpawner`]）。
pub trait SingBoxSpawner: Send + Sync {
    /// 执行 spawn，返回子进程句柄。失败抛 [`SpawnError`]。
    ///
    /// **按值收请求**：请求里的排空回调是 `FnOnce`，spawner 必须能把它消费掉。借用版签名
    /// （`&SpawnRequest`）下这件事做不到，只能退回「把带管道的 child 交给调用方、由它自觉去读」
    /// ——那正是本轮要消掉的形态。
    ///
    /// # 调用契约：`Drain` 策略下必须在 tokio runtime 上下文里调用
    ///
    /// 回调是**同步**调用的（在本方法返回之前），而三条核腿的回调体内都是 `tokio::spawn` 起排空
    /// 任务 —— 不在 runtime 上下文里调用会 panic（`there is no reactor running`）。本方法自身不是
    /// `async fn`，签名说不出这件事，故写在这里。
    ///
    /// 今天三个调用点都在 `async fn` 里（主核 `start_inner` / 测速 `TempCoreSession::run` /
    /// 登录核 `start_login`），契约成立；下一个调用点若是同步路径（`Drop`、`std::thread` 里、
    /// 或 `block_on` 之外），要么自己进 runtime，要么用 [`StdioPolicy::Discard`]。
    /// `Discard` 策略不调回调，无此约束。
    fn spawn(&self, req: SpawnRequest) -> Result<SpawnedChild, SpawnError>;
}

/// tokio::process 直接 spawn 实现（systemProxy / Linux setcap 路径，:4801）。
///
/// stdin 恒 ignore（:4802）；stdout/stderr 由 [`StdioPolicy`] 决定，`Drain` 下两路 pipe 且读端在
/// 返回前就交给回调。windowsHide 在 Rust 侧对应显式 `CREATE_NO_WINDOW`（见下方注释）。
#[derive(Debug, Default, Clone)]
pub struct TokioSpawner;

impl TokioSpawner {
    pub fn new() -> Self {
        Self
    }
}

impl SingBoxSpawner for TokioSpawner {
    fn spawn(&self, req: SpawnRequest) -> Result<SpawnedChild, SpawnError> {
        let argv = req.argv();
        let SpawnRequest {
            binary,
            working_dir,
            stdio,
            ..
        } = req;
        // 开不开管道由策略一处决定：`Drain` 才 pipe，`Discard` 直接 null。管道与排空是同一个决定的
        // 两面，分开写就会漂（本轮根因）。
        let (stdout, stderr) = match stdio {
            StdioPolicy::Discard => (Stdio::null(), Stdio::null()),
            StdioPolicy::Drain(_) => (Stdio::piped(), Stdio::piped()),
        };
        let mut cmd = tokio::process::Command::new(&binary);
        // windowsHide 等价。**原注释「tokio::process 在 Windows 默认不显示控制台窗口」是错的**：
        // tokio 只把 `creation_flags` 透传给 std（tokio-1.53.1 `src/process/mod.rs:675-677`），
        // 自身零默认。宿主是 GUI 子系统进程（`windows_subsystem = "windows"`）⇒ 起 console 程序
        // （sing-box 正是）会新分配一个控制台窗口。必须显式加 `CREATE_NO_WINDOW`（winbase.h 0x0800_0000）。
        // 位置要求只有一条、而且是**语义**上的：必须早于进程真正被创建（`.stdout(` / `.spawn()`）。
        // `Command` 的构建器调用彼此顺序无关，唯独「设标志」晚于「起进程」会静默失效。
        // `windows_console_suppression` 这条腿的判据就写成这句话本身（`Guarded::before`），不数行
        // ——数行的判据会被本方法体里越写越长的注释顶红，而顶红的原因与它守的属性无关。
        #[cfg(windows)]
        cmd.creation_flags(0x0800_0000);
        cmd
            // 全量传 argv：`argv()[0]` 是 **`run` 子命令**，不是 C 约定里的程序名——
            // `Command::new(program)` 不吃 argv[0]，故此处若切掉首元素会丢掉 `run`，
            // sing-box 收到 `sing-box -c cfg.json` → 无子命令 → 打 usage 后立即退出
            // （表征为「启动期退出」，极难从上层归因）。回归防护见
            // `tokio_spawner_passes_run_subcommand_to_child`。
            .args(argv)
            .stdin(Stdio::null()) // stdin ignore（:4802）
            .stdout(stdout)
            .stderr(stderr);
        // 工作目录（可写 config 目录）：消掉 CWD=`/` 下 dashboard 下载兜底的只读 mkdir 噪音（见 SpawnRequest.working_dir）。
        if let Some(cwd) = &working_dir {
            cmd.current_dir(cwd);
        }
        let mut child = cmd.spawn().map_err(|source| SpawnError::Spawn {
            bin: binary.clone(),
            source,
        })?;
        // **在返回之前**把两个读端交出去。放在这里而不是交给调用方，是本次收口的全部内容：
        // 管道从此不会带着「还没人读」的状态离开 spawner，起核到就绪那一整段窗口里也不会有
        // 「已经在写、还没人读」的空档。
        if let StdioPolicy::Drain(sink) = stdio {
            sink(
                boxed_stream(child.stdout.take()),
                boxed_stream(child.stderr.take()),
            );
        }
        Ok(SpawnedChild { child })
    }
}

/// 把 child 的一个读端装箱；`None` 换成一条立刻 EOF 的空流。
///
/// `None` 在这条路径上到不了：上面刚给这一路设过 `Stdio::piped()`，tokio 必然填好对应字段。真到了
/// 这里也不 panic —— 这是起核关键路径，为一个理论上不存在的状态崩掉整个起核不划算；给空流之后
/// 排空侧读到 EOF 正常收尾，而缺的那条流本来也没有内容。
fn boxed_stream(stream: Option<impl tokio::io::AsyncRead + Unpin + Send + 'static>) -> ChildStream {
    match stream {
        Some(s) => Box::new(s),
        None => Box::new(tokio::io::empty()),
    }
}

#[cfg(test)]
mod tests;
