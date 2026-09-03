//! 协议分派（移植自 上游 `helper/helper.go:397-589` 的 `handle()`）。
//!
//! ## Go 源结构（`helper.go:397-419`）
//!
//! ```text
//! func handle(conn net.Conn) {
//!     defer conn.Close()
//!     conn.SetReadDeadline(5s)
//!     r := bufio.NewReader(conn)
//!     tok := readLine(r)          // 行1: token
//!     cmd := readLine(r)          // 行2: command
//!     if tok == "" || tok != tokenValue() {
//!         fmt.Fprintln(conn, "ERR auth"); return
//!     }
//!     if cmd == "freeport" { handleFreeport(...); return }   // 不持锁
//!     mu.Lock(); defer mu.Unlock()
//!     switch cmd { case "ping": ... case "start": ... }
//! }
//! ```
//!
//! ## 移植纪律
//!
//! 把「鉴权 + 命令分派」从 socket IO 中剥离为纯函数 [`dispatch`] —— 接收已读的 token/command/args 行
//! + 一个 [`MacServices`] 服务 bundle，返回 [`Response`]。这样：
//! - 协议分派逻辑（参数校验、白名单判定、错误码映射）跨平台可测（Linux CI 完整覆盖）。
//! - socket IO（accept/read/write/超时）留给 [`crate::platform::macos::server`] 的 mac-gated 部分。
//!
//! freeport 不持锁（Go `helper.go:413`）—— 在 dispatch 内直接处理，由调用方决定是否在锁外调用。
//! 本 dispatch 是无状态的（状态在 [`MacServices`] 内），不模拟 Go 的 mu —— 并发控制由 server 层负责。

use crate::core_install::{install_core_files, InstallResult, SINGBOX_BIN_NAME};
use crate::platform::macos::exec::{CommandRunner, CODESIGN_TIMEOUT, EXEC_TIMEOUT};
use crate::platform::macos::flush_dns;
use crate::platform::macos::freeport;
use crate::platform::macos::install_core::to_response;
use crate::platform::macos::route::{self, RouteOp};
use crate::platform::macos::whitelist;
use crate::token::{check_token, TokenCheck, TokenStore};
use polaris_helper_proto::request::{InstallCoreParams, RouteParams};
use polaris_helper_proto::response::{ResponseKind, Start as StartResp, StartTiming, Status, Stop};
use polaris_helper_proto::{stop_pid_matches, Error as ProtoError, ErrorCode, Request, Response};
use std::path::Path;
use std::sync::Mutex;
use std::time::Instant;

/// macOS helper 配置（对应 Go 的 `--singbox`/`--confdir`/`--support`/`--coredir` flag）。
///
/// 这些值在安装期锁定（改需 root），是安全边界的一部分：
/// - `singbox_bin`：sing-box 二进制路径锁定（杜绝「持 token 跑任意二进制」，`helper.go:6`）。
/// - `conf_dir`：允许的配置文件目录（`cfgAllowed` 白名单，`helper.go:245-252`）。
/// - `support_dir`：socket + token 所在目录。
/// - `core_dir`：install-core 只写此目录（防写任意路径，`helper.go:128`）。
#[derive(Debug, Clone)]
pub struct MacConfig {
    /// 锁定的 sing-box 二进制路径（`helper.go:592` flag `--singbox`）。
    pub singbox_bin: String,
    /// 允许的配置文件目录（`helper.go:593` flag `--confdir`）。
    pub conf_dir: String,
    /// socket + token 所在目录（`helper.go:594` flag `--support`，默认 `/Library/Application Support/Polaris`）。
    pub support_dir: String,
    /// install-core 的受保护内核目录（`helper.go:595` flag `--coredir`）。
    pub core_dir: String,
}

impl MacConfig {
    /// 构造默认配置（对应 Go main 的 flag 默认值）。
    #[must_use]
    pub fn new(
        singbox_bin: impl Into<String>,
        conf_dir: impl Into<String>,
        support_dir: impl Into<String>,
        core_dir: impl Into<String>,
    ) -> Self {
        Self {
            singbox_bin: singbox_bin.into(),
            conf_dir: conf_dir.into(),
            support_dir: support_dir.into(),
            core_dir: core_dir.into(),
        }
    }
}

/// child sing-box 进程的运行时状态（对应 Go 的 `child`/`childDone` 全局变量 + mu）。
///
/// 用 `Arc<Mutex<Option<ChildHandle>>>` 持有 —— 对齐 Go 的 `mu.Lock()` 互斥语义。
/// 实际 child 进程的 spawn/wait/terminate 由 [`crate::platform::macos::server`] 的 mac-gated 部分实现
/// （需 tokio/std::process + 信号处理）；本结构只持有状态快照（pid）。
#[derive(Debug, Clone, Default)]
pub struct ChildHandle {
    /// child sing-box 的 pid。
    pub pid: u32,
}

/// macOS helper 已创建的核心及其可归因关键路径耗时。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpawnedCore {
    /// 新 child 的 pid。
    pub pid: u32,
    /// cache 属主准备 + `Command::spawn` 耗时。
    pub process_ms: u64,
    /// stdout/stderr 所有权移交日志后台线程的耗时。
    pub log_handoff_ms: u64,
}

/// macOS helper 的服务 bundle —— 把所有外部依赖（token 存储、命令执行、child 状态）打包成一个 trait，
/// 便于测试注入 mock、生产注入真实实现。
pub trait MacServices: Send + Sync {
    /// token 存储（读 `helper.token`）。
    fn token_store(&self) -> &dyn TokenStore;

    /// 命令执行器（route/lsof/ps/dscacheutil/codesign 等）。
    fn runner(&self) -> &dyn CommandRunner;

    /// child 进程状态（对应 Go 的 `child` 全局变量）。
    fn child(&self) -> &Mutex<Option<ChildHandle>>;

    /// 当前 helper 进程的 uid（mac `os.Getuid()`；测试可固定 0）。
    fn uid(&self) -> i64 {
        #[cfg(target_os = "macos")]
        {
            // os.Getuid() 等价 —— nix 0.31 的 getuid() 在 `user` feature 后（Cargo.toml 已开）。
            // Uid::current() 是 getuid() 的官方 Rusty 别名（nix unistd.rs:64-68，doc alias "getuid"）。
            nix::unistd::Uid::current().as_raw() as i64
        }
        #[cfg(not(target_os = "macos"))]
        {
            0
        }
    }

    /// spawn sing-box child（mac-gated，由 server 层实现，`helper.go:538-578`）。
    ///
    /// 返回新 child 的 pid 与关键路径耗时。`parent_pid`=父 app PID（`Some`→起 watchParent 父死看护，
    /// `helper.go:576-578`；`None`→不看护，兼容旧客户端）。默认实现返回未实现错误（测试可 mock）。
    fn spawn_child(
        &self,
        _cfg: &str,
        _log: &str,
        _fwd: bool,
        _parent_pid: Option<u32>,
    ) -> Result<SpawnedCore, SpawnError> {
        Err(SpawnError::NotImplemented)
    }

    /// 终止 child（TERM→等→KILL，mac-gated，由 server 层实现）。
    ///
    /// `want_pid` = 客户端声明它意图停的那个受管 pid（`None` = 旧语义「停当前受管核」）。判据走
    /// [`stop_pid_matches`]：不匹配 ⇒ 手里这个核属另一个会话 ⇒ **不摘不杀**，回
    /// [`TerminateOutcome::Mismatch`]（诚实 no-op）。判定与摘除在**同一把 child 锁**下完成，
    /// 不给「判完才被换掉」留缝。
    fn terminate_child(&self, want_pid: Option<u32>) -> TerminateOutcome {
        terminate_managed_child(self.child(), want_pid)
    }

    /// 摘除 child 状态（cleanup 用，不发信号；对应 Go `helper.go:448` `child, childDone = nil, nil`）。
    ///
    /// 默认只清 [`child`](Self::child) 视图；生产实现（server 层）覆盖以同步清内部 `done`/`generation`
    /// 记账（否则收割身份代守卫会残留陈旧 done）。
    fn clear_child(&self) {
        *self
            .child()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }
}

/// [`MacServices::terminate_child`] 的判定 + 摘除本体（**单一判定点**）。
///
/// 抽成自由函数而非留在 trait 默认体里，是为了让测试替身能**复用真判据**而不是各抄一份
/// （替身抄一份 = 测试测的是替身，身份判据被删掉也照样绿）。
///
/// 判定与摘除在同一把 child 锁下完成：不匹配 ⇒ 不摘、不杀，回 [`TerminateOutcome::Mismatch`]。
pub fn terminate_managed_child(
    child: &Mutex<Option<ChildHandle>>,
    want_pid: Option<u32>,
) -> TerminateOutcome {
    let mut guard = child
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match guard.as_ref() {
        Some(c) if !stop_pid_matches(want_pid, c.pid) => TerminateOutcome::Mismatch {
            want: want_pid.unwrap_or(0),
            current: c.pid,
        },
        Some(_) => guard.take().map_or(TerminateOutcome::NotRunning, |c| {
            TerminateOutcome::Stopped { pid: c.pid }
        }),
        None => TerminateOutcome::NotRunning,
    }
}

/// spawn child 的错误。
#[derive(Debug, Clone)]
pub enum SpawnError {
    /// 非 mac 环境 / 未注入实现。
    NotImplemented,
    /// 启动失败（对齐 Go `helper.go:552` 的 `ERR start <err>`）。
    Failed(String),
}

/// terminate child 的结果（对应 Go `helper.go:440-442`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminateOutcome {
    /// `OK stopped <pid>`。
    Stopped { pid: u32 },
    /// `OK notrunning`。
    NotRunning,
    /// `OK stop-mismatch <want> <current>` —— 受管 pid 非请求所指 ⇒ 不动手（见
    /// [`stop_pid_matches`]）。
    Mismatch { want: u32, current: u32 },
}

/// 协议分派结果（一个请求一个响应）。
///
/// 这是纯逻辑：输入 token + [`Request`] + 服务 bundle，输出 [`Response`]。
/// socket IO 层负责读 token 行 → 构造 Request → 调本函数 → 写回 Response。
pub fn dispatch(
    services: &dyn MacServices,
    config: &MacConfig,
    token: &str,
    req: &Request,
) -> Response {
    // helper.go:405-408: token 鉴权（首道边界）
    let stored = services.token_store().token_value();
    if !matches!(check_token(token, &stored), TokenCheck::Authed) {
        return Response::Err(ProtoError::new(ErrorCode::Auth));
    }

    // freeport 不持锁、不碰 child（helper.go:413）—— 直接处理
    if let Request::FreePort { port } = req {
        let port_str = port.to_string();
        return freeport::run_freeport(services.runner(), &port_str);
    }

    // 其余命令在「临界区」内处理 —— 这里用 child() mutex 体现互斥语义
    // （实际生产由 server 层在调 dispatch 前后包 mu；本函数内部对 child 状态的访问仍走 mutex）
    match req {
        Request::Ping => {
            // helper.go:422-423: OK pong uid=<n> v<ver>
            Response::Ok(ResponseKind::Pong(polaris_helper_proto::Pong::current(
                services.uid(),
            )))
        }
        Request::Version => {
            // helper.go:424-425: OK <ver>
            Response::Ok(ResponseKind::Version {
                proto_version: crate::platform::macos::PROTO_VERSION,
            })
        }
        Request::Status => {
            // helper.go:426-430
            let guard = services
                .child()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match &*guard {
                Some(child) => {
                    Response::Ok(ResponseKind::Status(Status::Running { pid: child.pid }))
                }
                None => Response::Ok(ResponseKind::Status(Status::Stopped)),
            }
        }
        Request::Stop { pid } => {
            // helper.go:432-442（+ 受管 pid 身份判据，见 `terminate_child`）
            match services.terminate_child(*pid) {
                TerminateOutcome::Stopped { pid } => {
                    Response::Ok(ResponseKind::Stop(Stop::Stopped { pid }))
                }
                TerminateOutcome::NotRunning => Response::Ok(ResponseKind::Stop(Stop::NotRunning)),
                TerminateOutcome::Mismatch { want, current } => {
                    Response::Ok(ResponseKind::Stop(Stop::Mismatch { want, current }))
                }
            }
        }
        Request::Cleanup => {
            // helper.go:444-449: pkill -9 -f "<singboxBin> run" + 摘 child
            let pattern = format!("{} run", config.singbox_bin);
            let _ = services
                .runner()
                .run(EXEC_TIMEOUT, "/usr/bin/pkill", &["-9", "-f", &pattern]);
            // helper.go:448: child, childDone = nil, nil（生产实现同步清 done/generation）
            services.clear_child();
            Response::Ok(ResponseKind::Cleaned)
        }
        Request::RouteAdd(rp) | Request::RouteDel(rp) => {
            // helper.go:450-480
            handle_route(services.runner(), rp, matches!(req, Request::RouteAdd(_)))
        }
        Request::DefaultRestore { gateway_ipv4 } => {
            // helper.go:481-491
            handle_default_restore(services.runner(), gateway_ipv4)
        }
        Request::FlushDns => {
            // helper.go:492-506
            flush_dns::flush_dns(services.runner()).into()
        }
        Request::MacProxyTransaction {
            payload_hex: _payload_hex,
        } => {
            #[cfg(target_os = "macos")]
            {
                match polaris_system_integration::execute_macos_proxy_transaction(_payload_hex) {
                    Ok(()) => Response::Ok(ResponseKind::MacProxyTransaction),
                    Err(error) => Response::Err(ProtoError::with_detail(
                        ErrorCode::SystemProxy,
                        error.replace(['\r', '\n'], " "),
                    )),
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                Response::Err(ProtoError::new(ErrorCode::Unknown))
            }
        }
        Request::MacProxyCompareTransaction {
            payload_hex: _payload_hex,
        } => {
            #[cfg(target_os = "macos")]
            {
                match polaris_system_integration::execute_macos_proxy_transaction(_payload_hex) {
                    Ok(()) => Response::Ok(ResponseKind::MacProxyTransaction),
                    Err(error) => Response::Err(ProtoError::with_detail(
                        ErrorCode::SystemProxy,
                        error.replace(['\r', '\n'], " "),
                    )),
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                Response::Err(ProtoError::new(ErrorCode::Unknown))
            }
        }
        // 纯 capability probe：只有新 helper 识别该 command 就返成功，绝不解码 payload、
        // 不打开 SCPreferences，因此 controller 可在任何系统写之前安全探测。
        Request::MacProxyCompareCapability => Response::Ok(ResponseKind::MacProxyTransaction),
        Request::Start(params) => {
            // helper.go:507-579
            handle_start(
                services,
                config,
                params.cfg.as_str(),
                params.log.as_str(),
                params.fwd,
                params.parent_pid,
            )
        }
        Request::InstallCore(params) => {
            // helper.go:580-585
            handle_install_core(services.runner(), config, params)
        }
        // 以下命令不属于 mac helper 谱系（LinuxStart/IfaceMetric/Uninstall）
        Request::LinuxStart(_)
        | Request::LinuxDnsSet(_)
        | Request::LinuxDnsRevert { .. }
        | Request::IfaceMetric { .. }
        | Request::Uninstall => Response::Err(ProtoError::new(ErrorCode::Unknown)),
        // FreePort 已在上方早返回；此处不可达（穷尽性兜底）
        Request::FreePort { .. } => unreachable!("freeport handled above"),
    }
}

/// route-add / route-del 处理（移植自 `helper.go:450-480`）。
fn handle_route(runner: &dyn CommandRunner, rp: &RouteParams, is_add: bool) -> Response {
    // helper.go:457-460: iface 白名单
    if !whitelist::iface_allowed(&rp.iface) {
        return Response::Err(ProtoError::new(ErrorCode::IfaceDenied));
    }
    let op = if is_add {
        RouteOp::Add
    } else {
        RouteOp::Delete
    };
    // helper.go:465-479: 逐 CIDR 构造 argv + 执行
    for cidr in &rp.cidrs {
        let cidr = cidr.trim();
        if cidr.is_empty() {
            continue;
        }
        if let Some(argv) = route::build_route_argv(op, &rp.iface, cidr) {
            let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
            // helper.go:478: 幂等 best-effort，忽略错误
            let _ = runner.run(EXEC_TIMEOUT, route::ROUTE_BIN, &refs);
        }
        // 非法 CIDR 跳过（helper.go:470-471 continue）
    }
    Response::Ok(ResponseKind::Route)
}

/// default-restore 处理（移植自 `helper.go:481-491`）。
fn handle_default_restore(runner: &dyn CommandRunner, gateway_ipv4: &str) -> Response {
    let gw = gateway_ipv4.trim();
    match route::build_default_restore_argv(gw) {
        Some(argv) => {
            let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
            let _ = runner.run(EXEC_TIMEOUT, route::ROUTE_BIN, &refs);
            Response::Ok(ResponseKind::DefaultRestored)
        }
        None => Response::Err(ProtoError::new(ErrorCode::BadGateway)),
    }
}

/// start 处理（移植自 `helper.go:507-579`）。
fn handle_start(
    services: &dyn MacServices,
    config: &MacConfig,
    cfg: &str,
    log: &str,
    fwd: bool,
    parent_pid: Option<u32>,
) -> Response {
    // helper.go:521-524: 已有 child → OK already <pid>
    {
        let guard = services
            .child()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(child) = &*guard {
            return Response::Ok(ResponseKind::Start(StartResp::Already { pid: child.pid }));
        }
    }
    // helper.go:525-527: cfg 空 → ERR no-config
    if cfg.is_empty() {
        return Response::Err(ProtoError::new(ErrorCode::NoConfig));
    }
    // helper.go:528-531: cfg 不在白名单 → ERR config-path-denied
    if !whitelist::cfg_allowed(cfg, &config.conf_dir) {
        return Response::Err(ProtoError::new(ErrorCode::ConfigPathDenied));
    }
    // **Polaris 新增（上游无）**：log 走与 cfg 同一条 lexical 白名单；`server::do_spawn`
    // 再从 `/` 逐级 openat(O_NOFOLLOW) 固定 current/.1，二者缺一不可。否则 root helper 既能
    // 越界创建文件，也会在用户可写父目录的 rename/symlink 竞态中写错对象。生产下发的 log
    // 与 cfg 同在 conf_dir，收紧无行为变化；空串 = 不重定向，放行。
    //
    // 这里不把 cfg 内容伪装成 helper 的可信输入：同一登录账户可读 token 且可写 conf_dir，
    // 因此当前承诺不抵抗同账户恶意进程。扩大承诺需要签名 app identity + 完整资源闭包封存，
    // 只 staging 主 JSON 或 canonicalize 路径不成立。协议契约见 StartParams 文档。
    if !log.is_empty() && !whitelist::cfg_allowed(log, &config.conf_dir) {
        return Response::Err(ProtoError::new(ErrorCode::LogPathDenied));
    }
    // 从已通过参数/路径校验后开始计时：拒绝腿不伪装成“起核耗时”。
    let total_started = Instant::now();
    // helper.go:533-537: allowLan 开启 IP 转发
    let forwarding_started = Instant::now();
    if fwd {
        let _ = services.runner().run(
            EXEC_TIMEOUT,
            "/usr/sbin/sysctl",
            &["-w", "net.inet.ip.forwarding=1"],
        );
        let _ = services.runner().run(
            EXEC_TIMEOUT,
            "/usr/sbin/sysctl",
            &["-w", "net.inet6.ip6.forwarding=1"],
        );
    }
    let forwarding_ms = crate::elapsed_ms(forwarding_started);
    // helper.go:538-579: spawn child sing-box（ppid>0 → 起 watchParent 父死看护）
    match services.spawn_child(cfg, log, fwd, parent_pid) {
        Ok(started) => Response::Ok(ResponseKind::Start(StartResp::StartedTimed {
            pid: started.pid,
            timing: StartTiming {
                forwarding_ms,
                process_ms: started.process_ms,
                job_ms: 0,
                log_handoff_ms: started.log_handoff_ms,
                total_ms: crate::elapsed_ms(total_started),
            },
        })),
        Err(SpawnError::NotImplemented) => Response::Err(ProtoError::with_detail(
            ErrorCode::Start,
            "spawn not implemented on this platform",
        )),
        Err(SpawnError::Failed(msg)) => {
            Response::Err(ProtoError::with_detail(ErrorCode::Start, msg))
        }
    }
}

/// install-core 处理（移植自 `helper.go:580-585,127-198`）。
///
/// 文件操作（校验+原子写入+清理）走 [`install_core_files`](crate::core_install::install_core_files)，
/// mac 专属的 xattr/codesign 在文件就位后执行（`helper.go:195-196`）。
fn handle_install_core(
    runner: &dyn CommandRunner,
    config: &MacConfig,
    params: &InstallCoreParams,
) -> Response {
    let core_dir = Path::new(&config.core_dir);
    let src_dir = Path::new(&params.src_dir);
    // helper.go:133-198: 文件操作
    match install_core_files(core_dir, src_dir, &params.want_hash) {
        Ok(_) => {
            // helper.go:194-196: mac 专属 —— 清 quarantine + adhoc 签名 sing-box
            let core_dir_str = config.core_dir.as_str();
            let (xattr_prog, xattr_args) =
                crate::platform::macos::btm::clear_quarantine_cmd(core_dir_str);
            let xattr_refs: Vec<&str> = xattr_args.iter().map(String::as_str).collect();
            let _ = runner.run(EXEC_TIMEOUT, xattr_prog, &xattr_refs);

            let sb_path = std::path::PathBuf::from(core_dir).join(SINGBOX_BIN_NAME);
            let sb_str = sb_path.to_string_lossy();
            let (cs_prog, cs_args) = crate::platform::macos::btm::adhoc_sign_cmd(&sb_str);
            let cs_refs: Vec<&str> = cs_args.iter().map(String::as_str).collect();
            let _ = runner.run(CODESIGN_TIMEOUT, cs_prog, &cs_refs);

            Response::Ok(ResponseKind::Installed)
        }
        Err(InstallResult::Installed) => Response::Ok(ResponseKind::Installed),
        Err(e) => to_response(e),
    }
}

// wire 写方向已上提 helper-proto：见 [`polaris_helper_proto::Response::to_wire_line`]
//（与 `Response::parse` 成对，三平台共用）。原 mac 私有副本（`response_to_wire_line`/`ok_kind_to_wire`/
// `freeport_wire`/`flush_dns_wire`，61 行）已删 —— 调用方直接 `resp.to_wire_line()`。

#[cfg(test)]
mod tests;
