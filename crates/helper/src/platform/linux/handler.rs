//! 命令分发器 —— 移植自 上游 `helper-linux/helper.go:333-482` 的 `handle(conn)`。
//!
//! ## 流程（逐行对照 Go 源 handle()）
//!
//! 1. SO_PEERCRED 取对端凭据（uid/gid）→ 失败 `ERR peercred`（:337-340）。
//! 2. 读 command 行（:343，linux 无 token 行）。
//! 3. ping / version 在鉴权前（:345-352，任何持 socket 者可探活）。
//! 4. isAuthorized(uid) → 失败 `ERR unauthorized`（:354-357）。
//! 5. 持 mu 锁，按 command 分发（:359-481）。
//!
//! ## 测试策略
//!
//! Go 源 `handle(conn)` 直接吃 net.Conn。本实现把连接读写 + 凭据获取抽象为 [`Conn`] trait，
//! 让命令处理在不碰真实 socket 的前提下全路径测试（注入伪造 uid + 预置读写行）。
//!
//! 核 spawn（start 命令）经 [`CoreSpawner`] trait 抽象（生产用真实 AmbientCaps
//! 派生，测试 mock）。进程状态放在 [`HandlerState`]（实例化可测）。

use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use crate::line_io;
use polaris_helper_proto::command::{common as cmd, linux as lcmd};
use polaris_helper_proto::{
    parse_stop_pid, stop_pid_matches, Error as ProtoError, ErrorCode, LinuxDns, Response,
    ResponseKind, Start, StartTiming, Stop,
};

use crate::core_install::InstallResult;
use crate::platform::linux::auth::{
    is_authorized, owned_by, supplementary_groups, AuthError, PeerCred, PeerCredProvider,
};
use crate::platform::linux::core_installer::install_core;
use crate::platform::linux::freeport::{free_port, parse_ss_pids, FreePortDeps};
use crate::platform::linux::ops::SystemdOps;
use crate::platform::linux::resolved_dns::ResolvedDnsOps;
use crate::platform::linux::state::{CoreSpawner, HandlerState, SpawnCoreRequest, SpawnError};

/// Linux helper protoVersion（三平台统一演进，见 `polaris_helper_proto` crate 文档）。
pub const PROTO_VERSION: u32 = polaris_helper_proto::proto_version::CURRENT;

/// 5 秒读超时（移植自 Go `conn.SetReadDeadline(time.Now().Add(5 * time.Second))`，:335）。
pub const READ_TIMEOUT_SECS: u64 = polaris_helper_proto::codec::READ_TIMEOUT_SECS;

/// handler 依赖（注入所有外部副作用，便于测试 mock）。
pub struct HandlerDeps<'a, P: PeerCredProvider, S: CoreSpawner, D: FreePortDeps, SD: SystemdOps> {
    /// 锁定的 root-owned 受管核目录（start 只跑 coreDir/sing-box）。
    pub core_dir: Option<&'a Path>,
    /// 授权 uid 列表文件。
    pub auth_file: &'a Path,
    /// SO_PEERCRED 凭据提供者。
    pub peer_cred: &'a P,
    /// sing-box spawn 抽象（start 命令）。
    pub spawner: &'a S,
    /// freeport 进程操作依赖。
    pub freeport_deps: &'a D,
    /// systemd 操作（启停 helper 自身服务，对照任务职责 1）。
    pub systemd: &'a SD,
    /// systemd-resolved per-link 接管（生产为严格白名单的 `resolvectl` 实现）。
    pub resolved_dns: &'a dyn ResolvedDnsOps,
    /// ss 命令的输出提供者（freeport 用 `ss -ltnp` 找 LISTEN 持有者）。
    /// 抽象为闭包便于测试；生产用 `ss` 子进程。
    pub ss_provider: &'a (dyn Fn(&str) -> Option<String> + Send + Sync),
    /// IP 转发开关的副作用闭包（生产 set_forward_prod，测试可记录调用）。
    pub set_forward: &'a (dyn Fn(bool) + Send + Sync),
}

/// 连接抽象（trait 便于测试 mock；生产用 tokio::net::UnixStream 经 adapter）。
///
/// 对应 Go `handle(conn net.Conn)`：读行 + 写行 + 取对端凭据。
pub trait Conn: Send {
    /// 读一行（trim 尾部 \n/\r）。EOF / 读失败返回 ""（对齐 Go readLine 的 ReadString 行为）。
    fn read_line(&mut self) -> String;
    /// 写一行（自动加 \n）。返回是否写成功。
    fn write_line(&mut self, line: &str) -> bool;
}

/// 把任意 Read + Write 包成 BufRead 行 IO（生产 unix socket adapter 用）。
///
/// 读写本体已上提 [`crate::line_io`]（与 mac 共用单一真值）；本类型只做
/// linux [`Conn`] 契约的形状适配（EOF→`""`、写成功→`bool`）。
pub struct LineConn<RW: Read + Write> {
    inner: BufReader<RW>,
}

impl<RW: Read + Write> LineConn<RW> {
    #[must_use]
    pub fn new(io: RW) -> Self {
        Self {
            inner: BufReader::new(io),
        }
    }
}

impl<RW: Read + Write + Send> Conn for LineConn<RW> {
    fn read_line(&mut self) -> String {
        // Conn 契约：EOF/读失败与空行一律 ""（对齐 Go readLine 的 ReadString 行为）。
        line_io::read_line_trimmed(&mut self.inner).unwrap_or_default()
    }

    fn write_line(&mut self, line: &str) -> bool {
        // 写走底层 RW（BufReader 只缓冲读方向），语义同原实现。
        line_io::write_line(self.inner.get_mut(), line).is_ok()
    }
}

/// 处理一个连接（移植自 Go `handle`，:333-482）。
///
/// 返回处理是否成功（连接层错误由调用方处理）。所有 wire 响应已写入 conn。
pub fn handle<P, S, D, SD>(
    state: &Mutex<HandlerState>,
    deps: &HandlerDeps<'_, P, S, D, SD>,
    conn: &mut impl Conn,
) where
    P: PeerCredProvider,
    S: CoreSpawner,
    D: FreePortDeps,
    SD: SystemdOps,
{
    // 1. SO_PEERCRED 取凭据（:337-340）。
    let Some(cred) = deps.peer_cred.peer_cred() else {
        // ERR peercred（Go: fmt.Fprintln(conn, "ERR peercred")）。
        let _ = conn.write_line(&format!("ERR {}", AuthError::Peercred.wire_token()));
        return;
    };

    // 2. 读 command 行（linux 无 token 行，:343）。
    let command = conn.read_line();

    // 3. ping / version 在鉴权前（任何持 socket 者可探活，:345-352）。
    match command.as_str() {
        cmd::PING => {
            // shared Pong 统一追加 build identity；旧 app 会忽略该字段，新 app 可识别同 protocol 旧 helper。
            let response = Response::Ok(ResponseKind::Pong(polaris_helper_proto::Pong::current(
                i64::from(cred.uid),
            )));
            let _ = conn.write_line(&response.to_wire_line());
            return;
        }
        cmd::VERSION => {
            // OK <ver>（Go: fmt.Fprintf(conn, "OK %s\n", protoVersion)）。
            let _ = conn.write_line(&format!("OK {PROTO_VERSION}"));
            return;
        }
        _ => {}
    }

    // 4. 鉴权（:354-357）。
    if !is_authorized(cred.uid, deps.auth_file) {
        let _ = conn.write_line(&format!("ERR {}", AuthError::Unauthorized.wire_token()));
        return;
    }

    // resolved 操作不依赖受管核状态，且可能等待多个有界子进程；不能持有全局 child 锁阻塞 stop/status。
    match command.as_str() {
        lcmd::RESOLVED_DNS_SET => {
            handle_resolved_dns_set(deps.resolved_dns, conn);
            return;
        }
        lcmd::RESOLVED_DNS_REVERT => {
            handle_resolved_dns_revert(deps.resolved_dns, conn);
            return;
        }
        _ => {}
    }

    // 5. 持锁按 command 分发（Go: mu.Lock(); defer mu.Unlock()）。
    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(e) => {
            // 锁中毒（panic 残留）—— 极少见，回报 unknown。
            let _ = conn.write_line(&format!("ERR unknown {e}"));
            return;
        }
    };
    dispatch_locked(&mut guard, deps, &cred, &command, conn);
}

/// 持锁的命令分发（对照 Go switch cmd { ... }，:362-481）。
fn dispatch_locked<P, S, D, SD>(
    state: &mut HandlerState,
    deps: &HandlerDeps<'_, P, S, D, SD>,
    cred: &PeerCred,
    command: &str,
    conn: &mut impl Conn,
) where
    P: PeerCredProvider,
    S: CoreSpawner,
    D: FreePortDeps,
    SD: SystemdOps,
{
    match command {
        cmd::STATUS => handle_status(state, conn),
        cmd::STOP => handle_stop(state, deps, conn),
        cmd::CLEANUP => handle_cleanup(state, deps, cred, conn),
        cmd::FREEPORT => handle_freeport(deps, cred, conn),
        // install-core 是 linux 专属命令名（lcmd::INSTALL_CORE == "install-core"）。
        lcmd::INSTALL_CORE => handle_install_core(deps, conn),
        cmd::START => handle_start(state, deps, cred, conn),
        _ => {
            let _ = conn.write_line("ERR unknown");
        }
    }
}

// ===== 各命令处理（逐分支对照 Go 源）=====

fn handle_resolved_dns_set(ops: &dyn ResolvedDnsOps, conn: &mut impl Conn) {
    let interface_name = conn.read_line();
    let server_ip = conn.read_line();
    let response = match ops.takeover(&interface_name, &server_ip) {
        Ok(()) => Response::Ok(ResponseKind::LinuxDns(LinuxDns::Set)),
        Err(error) => Response::Err(ProtoError::with_detail(
            ErrorCode::ResolvedDns,
            single_line_wire_detail(&error),
        )),
    };
    let _ = conn.write_line(&response.to_wire_line());
}

fn handle_resolved_dns_revert(ops: &dyn ResolvedDnsOps, conn: &mut impl Conn) {
    let interface_name = conn.read_line();
    let response = match ops.revert(&interface_name) {
        Ok(()) => Response::Ok(ResponseKind::LinuxDns(LinuxDns::Reverted)),
        Err(error) => Response::Err(ProtoError::with_detail(
            ErrorCode::ResolvedDns,
            single_line_wire_detail(&error),
        )),
    };
    let _ = conn.write_line(&response.to_wire_line());
}

/// helper wire 一次响应只能占一行；resolvectl stderr 可能含换行，必须先压平，避免截断诊断或注入伪帧。
fn single_line_wire_detail(detail: &str) -> String {
    detail.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// status（:363-368）：running `<pid>` 或 stopped。
fn handle_status(state: &HandlerState, conn: &mut impl Conn) {
    if let Some(h) = state.child.as_ref() {
        let _ = conn.write_line(&format!("OK running {}", h.pid));
    } else {
        let _ = conn.write_line("OK stopped");
    }
}

/// stop（:369-380）：**受管 pid 身份校验** → 摘除 child + 后台收割 + 复位转发态。
///
/// 身份行（可选，本协议新增）：客户端声明它意图停的那个 pid。判据走
/// [`stop_pid_matches`] —— 不匹配 = 手里这个核属**另一个会话**（客户端的老 stop 腿在 IPC 上挂住
/// 期间，用户已经重装 helper / 重新起了核），此时杀它就是把用户刚连上的核静默掐掉。故不匹配一律
/// 诚实 no-op（`OK stop-mismatch <want> <current>`），绝不「反正要停就杀当前的」。
///
/// 读身份行发生在**持锁临界区内**（与 start/freeport/install-core 的参数行读同款）：连接级 5s 读
/// 超时（`server.rs` 的 `set_read_timeout`）是这条读的上界，客户端写完即 `shutdown` ⇒ 正常路径
/// 立刻 EOF 返 ""。
fn handle_stop<P, S, D, SD>(
    state: &mut HandlerState,
    deps: &HandlerDeps<'_, P, S, D, SD>,
    conn: &mut impl Conn,
) where
    P: PeerCredProvider,
    S: CoreSpawner,
    D: FreePortDeps,
    SD: SystemdOps,
{
    // 旧客户端不发这一行 → read_line 在 EOF 返 "" → None → 沿用「停当前受管核」旧语义。
    let want = parse_stop_pid(&conn.read_line());
    if let Some(h) = state.child.as_ref() {
        if !stop_pid_matches(want, h.pid) {
            let resp = Response::Ok(ResponseKind::Stop(Stop::Mismatch {
                want: want.unwrap_or(0),
                current: h.pid,
            }));
            let _ = conn.write_line(&resp.to_wire_line());
            return;
        }
    }
    if let Some(h) = state.child.take() {
        let pid = h.pid;
        // 复位转发态（:374，跟随运行中的核）。
        (deps.set_forward)(false);
        // 后台收割：TERM → ≤5s → KILL（Go: go func() { terminateChild(c, done) }()）。
        // 本实现同步等待 spawner.terminate（trait 抽象，测试可控；生产 spawn task）。
        deps.spawner.terminate(&h);
        let _ = conn.write_line(&format!("OK stopped {pid}"));
    } else {
        let _ = conn.write_line("OK notrunning");
    }
}

/// cleanup（:381-388）：kill child + pkill sing-box + 复位转发态。
fn handle_cleanup<P, S, D, SD>(
    state: &mut HandlerState,
    deps: &HandlerDeps<'_, P, S, D, SD>,
    cred: &PeerCred,
    conn: &mut impl Conn,
) where
    P: PeerCredProvider,
    S: CoreSpawner,
    D: FreePortDeps,
    SD: SystemdOps,
{
    if let Some(h) = state.child.take() {
        // :383: kill child。
        deps.spawner.kill(&h);
    }
    (deps.set_forward)(false);
    // :387: pkill -9 -U <uid> -f "sing-box run"（兜底清对端 uid 的所有 sing-box 实例）。
    // best-effort：忽略失败（Go: _ = exec.Command("pkill", ...).Run()）。
    let _ = std::process::Command::new("pkill")
        .args(["-9", "-U", &cred.uid.to_string(), "-f", "sing-box run"])
        .output();
    let _ = conn.write_line("OK cleaned");
}

/// freeport（:389-395）：按端口找 LISTEN 持有者。
fn handle_freeport<P, S, D, SD>(
    deps: &HandlerDeps<'_, P, S, D, SD>,
    cred: &PeerCred,
    conn: &mut impl Conn,
) where
    P: PeerCredProvider,
    S: CoreSpawner,
    D: FreePortDeps,
    SD: SystemdOps,
{
    // :390: 读 port 行。
    let port = conn.read_line();
    let port_trim = port.trim();
    // :391: 校验纯数字（Go: IndexFunc 非 '0'-'9' 即拒绝）。
    if port_trim.is_empty() || !port_trim.bytes().all(|b| b.is_ascii_digit()) {
        let _ = conn.write_line("ERR bad-port");
        return;
    }
    // :392: ss -H -ltnp 'sport = :<port>'。
    let ss_out = (deps.ss_provider)(port_trim);
    let pids = match ss_out {
        Some(s) => parse_ss_pids(&s),
        None => Vec::new(),
    };
    // :395: free_port 分发。wire 序列化走协议层单一真值（G3.1/G3.3）。
    let outcome = free_port(&pids, cred.uid, deps.freeport_deps);
    let resp = Response::Ok(ResponseKind::FreePort(outcome));
    let _ = conn.write_line(&resp.to_wire_line());
}

/// install-core（:396-399）：校验 sha256 + 原子写入 coreDir。
fn handle_install_core<P, S, D, SD>(deps: &HandlerDeps<'_, P, S, D, SD>, conn: &mut impl Conn)
where
    P: PeerCredProvider,
    S: CoreSpawner,
    D: FreePortDeps,
    SD: SystemdOps,
{
    // :397-398: 读 srcDir 行 + wantHash 行。
    let src = conn.read_line();
    let want_hash = conn.read_line();
    let outcome: InstallResult = install_core(deps.core_dir, src.trim(), want_hash.trim());
    let _ = conn.write_line(&outcome.to_wire_line());
}

/// start（:400-478）：核路径锁 + config 属主校验 + AmbientCaps 拉核。
#[allow(clippy::too_many_lines)]
fn handle_start<P, S, D, SD>(
    state: &mut HandlerState,
    deps: &HandlerDeps<'_, P, S, D, SD>,
    cred: &PeerCred,
    conn: &mut impl Conn,
) where
    P: PeerCredProvider,
    S: CoreSpawner,
    D: FreePortDeps,
    SD: SystemdOps,
{
    // :401-405: 读 singbox / cfg / log / fwd / ppid 行。
    let singbox = conn.read_line();
    let cfg = conn.read_line();
    let log_path = conn.read_line();
    let fwd = conn.read_line();
    let ppid_str = conn.read_line();
    let ppid: u32 = ppid_str.trim().parse().unwrap_or(0);

    // :407-410: 已有 child → already。
    if let Some(h) = state.child.as_ref() {
        let _ = conn.write_line(&format!("OK already {}", h.pid));
        return;
    }
    // :411-413: cfg 空 → bad-args。
    let cfg = cfg.trim();
    if cfg.is_empty() {
        let _ = conn.write_line("ERR bad-args");
        return;
    }
    // :417-420: 核路径锁 —— singbox 必须 == coreDir/sing-box。
    let Some(core_dir) = deps.core_dir else {
        let _ = conn.write_line("ERR coredir-unset");
        return;
    };
    let core_bin: PathBuf = core_dir.join("sing-box");
    if Path::new(singbox.trim()) != core_bin.as_path() {
        let _ = conn.write_line(&format!(
            "ERR core-path-denied (want {})",
            core_bin.display()
        ));
        return;
    }
    // :421-424: 锁定核二进制必须存在。
    if !core_bin.exists() {
        let _ = conn.write_line("ERR core-missing");
        return;
    }
    // :425-428: config 必须属于对端 uid（防读别人配置）。
    match owned_by(Path::new(cfg), cred.uid) {
        Ok(true) => {}
        Ok(false) => {
            let _ = conn.write_line("ERR config-not-owned");
            return;
        }
        Err(e) => {
            let _ = conn.write_line(&format!("ERR config-not-owned {e}"));
            return;
        }
    }
    // **Polaris 新增（上游无）**：log 必须与 cfg **同一父目录**。
    //
    // 上游只校验 cfg 的属主，而 `spawn` 会以 **root** 身份 `O_CREATE|O_APPEND|0644` 打开这个 log
    // 路径、**并 `fchown` 给对端 uid**（`linux/server.rs`）⇒ 不校验就是「root 在任意位置建文件、
    // 再把属主给调用者」——比单纯的任意追加写更强，`/etc/cron.d/` 之类落一个文件即完全提权。
    //
    // 判据取「同父目录」而非 conf_dir 白名单：linux 腿没有 `--confdir`（它用属主校验代替），
    // 而生产下发的 cfg 与 log 恒是同目录的 `singbox-runtime.json` / `singbox-startup.log`
    //（`runtime/proxy.rs`）⇒ 这条收紧**零行为变更**。含 `..` 的路径会让父目录字面不等，自然被拒。
    //
    // 🔴 **未覆盖：符号链接**。判据是纯路径比较，若攻击者在该目录里放一个指向 `/etc/...` 的符号
    // 链接，root 打开时仍会跟随。要堵死得上 `O_NOFOLLOW`（只管最后一段）或 openat2 RESOLVE_BENEATH；
    // 更彻底的修法是**根本不接受客户端下发 log 路径**（helper 自己按 conf_dir 拼）。均已登记，见
    // `~/docs/polaris/design/polaris-platform-code-sweep-2026-08-09.md`。
    let log_trimmed = log_path.trim();
    if !log_trimmed.is_empty() && Path::new(log_trimmed).parent() != Path::new(cfg).parent() {
        let _ = conn.write_line("ERR log-path-denied");
        return;
    }
    // 从已通过参数/路径/属主校验后开始计时：拒绝腿不伪装成“起核耗时”。
    let total_started = Instant::now();
    // :429: 显式跟随本次会话的转发态。
    let forwarding_started = Instant::now();
    (deps.set_forward)(fwd.trim() == "1");
    let forwarding_ms = crate::elapsed_ms(forwarding_started);

    // :431-478: AmbientCaps 拉核（setuid 回对端登录用户 + CAP_NET_ADMIN/RAW/BIND_SERVICE）。
    // 经 CoreSpawner trait 抽象：生产实现做 fork+setuid+AmbientCaps+execve（§helper-rust-evaluation B3 真机项）；
    // 测试 mock 返回固定 pid。
    let process_prepare_started = Instant::now();
    let req = SpawnCoreRequest {
        binary: core_bin.clone(),
        config: PathBuf::from(cfg),
        log: if log_path.trim().is_empty() {
            None
        } else {
            Some(PathBuf::from(log_path.trim()))
        },
        fwd: fwd.trim() == "1",
        parent_pid: if ppid > 0 { Some(ppid) } else { None },
        uid: cred.uid,
        gid: cred.gid,
        // 补充组在 fork 前于父进程解析（Go SysProcAttr.Credential.Groups），随 request 下发给 pre_exec 的
        // setgroups（拉核子进程不碰 NSS）。对照 Go start 分支 `Groups: supplementaryGroups(cred.Uid)`，:439。
        groups: supplementary_groups(cred.uid),
    };
    let process_prepare_ms = crate::elapsed_ms(process_prepare_started);
    match deps.spawner.spawn(&req) {
        Ok(started) => {
            let pid = started.handle.pid;
            state.child = Some(started.handle);
            let process_ms = started.process_ms.saturating_add(process_prepare_ms);
            let response = Response::Ok(ResponseKind::Start(Start::StartedTimed {
                pid,
                timing: StartTiming {
                    forwarding_ms,
                    process_ms,
                    job_ms: 0,
                    log_handoff_ms: started.log_handoff_ms,
                    total_ms: crate::elapsed_ms(total_started),
                },
            }));
            let _ = conn.write_line(&response.to_wire_line());
        }
        Err(SpawnError::Spawn { detail }) => {
            // :456: 复位转发态（拉核失败不留全局转发）。
            (deps.set_forward)(false);
            let _ = conn.write_line(&format!("ERR start {detail}"));
        }
    }
}

#[cfg(test)]
mod tests;
