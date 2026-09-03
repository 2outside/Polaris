//! Tailscale 瞬态登录核的**宿主层编排**（spawn / STATUS 订阅 / emit / 生命周期注册表）。
//!
//! 纯逻辑（config 生成、双写守卫、登录状态机）在 `polaris_mesh::tailscale_login`，已单测；
//! 本模块只做**运行时接线**：拉起一个独立的瞬态 sing-box、订阅**它自己的**管理 API
//! `SubscribeTailscaleStatus` 流、把帧里的 `authURL` 转成登录 URL 事件、把 `backendState == "Running"`
//! 当作登录成功并就地收核，并管理它的生死（kill-on-relogin / 超时自动杀 / 取消 / 自然退出 reap），
//! 与 `ProxyRuntime` 的常驻代理核**隔离**（独立注册表、独立 child 句柄；瞬态核绝不写进 proxy 的
//! pid 槽，故不会被误当作代理核）。
//!
//! ## 为什么 URL 只认 gRPC，不再扫 stdout（含「gRPC 腿失败要不要回退 stdout」的结论）
//!
//! 曾经的实现从核 stdout 正则抓 `Waiting for authentication: <url>`。改掉它有两条独立理由：
//!
//! 1. **那行是日志文案，不是契约**。上游 `protocol/tailscale/endpoint.go` 里它就是一句
//!    `logger.Info("Waiting for authentication: ", authURL)`；改文案、改前缀、改日志等级都不算破坏性
//!    变更，而 `TailscaleEndpointStatus.authURL` 是 proto 字段，字段号由 `crates/singbox-grpc` 的两道
//!    机械门看守（build.rs 对随包核 descriptor 对账 + `tests/bundled_core_wire.rs`）。
//! 2. **stdout 路径拿不到「登录成功」**。此前的登录成功判据是「无法判定」（`LoginState::NoStatusFallback`），
//!    于是核要么空跑到 5 分钟超时、要么靠用户手动取消 —— 期间它一直占着该节点的 `state_directory`。
//!    `backendState == "Running"` 是控制面给的**终局肯定**，拿到即收核。
//!
//! **gRPC 腿失败时不回退 stdout，硬失败**。取舍写在这里以免下一轮又被「多一条兜底更稳」翻回去：
//! - 「两份 URL 来源」正是本次要消灭的漂移。留一条 stdout 兜底 = 两个解析器、两种格式、两条各自
//!   可能先到的路径，而它们对「登录成功」的能力**不对等**：走上兜底那一刻，功能就悄悄退回改造前的
//!   形态（有 URL、判不了成功、核空跑到超时），且**没有任何人会看见这次降级**。本仓已有过一次同型
//!   教训：`reconnect.rs` 用没接 sink 的日志门面，静默让同一根因扛过两轮修复。
//! - 兜底能覆盖的失败面本来就很窄：api service bind 不上 → 核直接 FATAL 退出，stdout 同样什么都没有；
//!   配置形状不对 → 已被 spawn 前的 `sing-box check` 挡下。真正只属于 gRPC 腿的失败是「核活着但订阅
//!   建不起来」，而 `ReconnectingStream` 本身就带退避重连，这类抖动它自己会吞掉；真的一直连不上，
//!   由既有超时臂杀核并留下明确日志 —— 这是**响的**失败，不是静默降级。
//!
//! stdout/stderr 仍整段转日志（诊断价值不变），但**不再是任何判据的来源**。
//!
//! ## 诚实边界（务必读）
//! 本命令的**端到端价值 = 真 sing-box + 真出站 + 真 Tailscale 控制面**：起一个真核去连 Tailscale 控制服务器、
//! 把它吐的登录 URL 转发给用户。这条真机路径**在本 Linux 开发机上无法验证**（本仓禁跑触碰宿主网络的测试；
//! `sing-box check` 只验配置形状，验不了「核真的吐出登录 URL」这一运行时行为）。因此：
//! - 本模块的**全部可单测面**（注册表生命周期、命令决策流、去重、超时、取消、reap、STATUS→URL relay、
//!   Running→收核）都以注入的 mock [`LoginCoreSpawner`]/[`ConfigChecker`]/[`AuthUrlEmitter`]/
//!   [`LoginStatusSubscriber`] 单测——**无真进程、无网络、无真 sing-box、无真 gRPC**。
//! - **真 spawn + 控制面握手 + 真登录 URL** 一段**在此未验证**，门槛是一次真机会话（见
//!   `~/docs/polaris/design/polaris-tailscale-login-wiring.md` 的验收清单）。不得据本模块宣称「登录端到端可用」。
//!
//! ## 与 `cleanup_stale_cores` 的关系
//!
//! `ProxyRuntime::cleanup_stale_cores` 在**每一次起代理核前**清扫「本 app 二进制」的孤儿核。瞬态登录核
//! 与主核同一个 [`resolve_core_binary`] + [`SpawnRequest`]，argv 逐字同形（`<同一核二进制> run -c <cfg>
//! --disable-color`）⇒ `is_our_core` 必然命中 ⇒ 在候选集里它与「上次会话遗留的孤儿」不可区分。
//!
//! **在飞的登录核已被排除**：清扫的排除表经 `ProxyRuntime::sweep_exclusions` →
//! `MeshRuntime::inflight_login_core_pids` → [`LoginCoreRegistry::inflight_login_pids`] 读本注册表
//! （耦合方向是现成的：`ProxyRuntime` 已持有 `Arc<MeshRuntime>`，`MeshRuntime` 已持有本注册表）。
//! 一个**上次会话遗留**的登录核不在表里，届时被扫掉仍是**期望行为**（它本就该在应用退出时清）。
//!
//! 射程与两处未覆盖的窗口（spawn→注册之间那次 STATUS 订阅 `await`；cancel 先出表后收核）如实登记在
//! [`LoginCoreRegistry::inflight_login_pids`] 的文档里，别从这一段推断「全覆盖」。

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::json;
use tauri::AppHandle;
use tokio::sync::oneshot;

use polaris_config_engine::user_config::app_config::UserConfig;
use polaris_config_engine::user_config::server_config::ServerConfig;
use polaris_core_supervisor::port_bookkeeping::TokioPortProvider;
use polaris_core_supervisor::{
    run_check_raw, PortAllocator, PortExclusions, ProcessKiller, RawCheck, SingBoxSpawner,
    SpawnError, SpawnRequest, StdioPolicy, TokioSpawner, CONFIG_CHECK_TIMEOUT,
};
use polaris_mesh::tailscale_login::{
    advance_login_state, build_tailscale_login_config, login_config_to_json,
    tailscale_endpoint_in_running_core, LoginEvent, LoginState, TailscaleLoginApiService,
};
use polaris_singbox_grpc::{daemon, Endpoint, ReconnectConfig, SingBoxApiClient};

use crate::events::{broadcast, channel::EVENT_TAILSCALE_AUTH_URL};
use crate::runtime::proxy::core_log::pipe_to_log;
use crate::runtime::proxy::{pid_alive, resolve_core_binary, send_signal};
use crate::runtime::tailscale_status::decode_tailscale_status;

/// 瞬态登录核的最大挂起时长：登录不完成（用户不去浏览器认证）时到点自动杀核，避免核无限挂着。
/// 交互登录需人去浏览器完成，故给宽松窗口（5 分钟）。
const DEFAULT_LOGIN_TIMEOUT: Duration = Duration::from_secs(300);

/// 每个条目都对应一个 sing-box 子进程、两条日志管道和一条 gRPC 重连流；IPC 可并发调用，必须硬封顶。
const MAX_ACTIVE_LOGIN_CORES: usize = 8;

/// 杀瞬态核的优雅窗口（SIGTERM → 宽限 → SIGKILL）。对齐 `ProxyRuntime` 的 `STOP_GRACE`（5s）。
const LOGIN_STOP_GRACE: Duration = Duration::from_secs(5);

/// 瞬态登录核子进程日志行的 target。
///
/// 喂给全 app 唯一那份排空实现 [`crate::runtime::proxy::core_log::pipe_to_log`]。**不能用主核的
/// `SING_BOX_TARGET`**：落盘按字面 target 选文件，混进去会污染 `singbox.log` 的连续性，日志页按
/// 来源筛也分不出是哪个核。
const LOGIN_CORE_LOG_TARGET: &str = "tailscale-login";

/// 核二进制解析器（注入点）：生产走 [`resolve_core_binary`]，测试注入固定路径以免依赖真实落盘的 sing-box。
type BinaryResolver = Arc<dyn Fn() -> Result<PathBuf, String> + Send + Sync>;

// ── 抽象 trait（生产真实现 / 测试 mock；这是「无真进程无网络单测」的关键）────────────────────────

/// 瞬态登录核子进程抽象。生产用 `tokio::process::Child` 包装；测试用内存 duplex 假子进程，
/// 使整条编排（spawn/emit/register/timeout/cancel/reap）可在无真进程无网络下驱动。
///
/// **这里没有取管道的方法**：两条流的去向在 [`SpawnRequest`] 的 [`StdioPolicy`] 里一次说清，
/// spawner 在返回之前就把读端交给了排空回调。child 只剩生命周期职责 —— 「拿到了 child 却忘记
/// 去读它的管道」这条路已经不存在。
#[async_trait]
pub trait LoginCoreChild: Send {
    /// 子进程 pid（假子进程返回占位值）。
    ///
    /// **不只是日志**：`start_login` 把它记进 [`LoginEntry::pid`]，
    /// [`LoginCoreRegistry::inflight_login_pids`] 据此喂 `ProxyRuntime::cleanup_stale_cores`
    /// 的排除表 —— 返错 pid 会让清扫放过一个真孤儿，返 `None` 只会让本核在飞时失去保护。
    fn pid(&self) -> Option<u32>;
    /// 等子进程自然退出并收割（cancel-safe：可在 `select!` 中反复创建/丢弃）。
    async fn wait(&mut self);
    /// 主动终止并收割：生产 SIGTERM→宽限→SIGKILL 后 `wait()`；测试置终止标记即返回。
    async fn terminate(&mut self);
}

/// spawn 抽象：返回 [`LoginCoreChild`] 装箱句柄。生产 [`TokioLoginCoreSpawner`] 内部经 [`TokioSpawner`] 起真核。
pub trait LoginCoreSpawner: Send + Sync {
    /// spawn 一个瞬态登录核。失败返 [`SpawnError`]（ENOENT/EACCES）。
    ///
    /// **按值收请求**（与 [`SingBoxSpawner`] 同）：请求里的排空回调是 `FnOnce`，spawner 必须能
    /// 消费掉它。假 spawner 也一样要把自己那两条内存流喂给同一个回调，测试才走的是生产接线。
    fn spawn(&self, req: SpawnRequest) -> Result<Box<dyn LoginCoreChild>, SpawnError>;
}

/// `sing-box check` 抽象：spawn 前先验配置形状（fail-fast）。生产真跑 `sing-box check -c <file>`，测试 mock。
#[async_trait]
pub trait ConfigChecker: Send + Sync {
    /// 校验 `config_path` 是否为合法 sing-box 配置。非法 → Err（含核的诊断）。
    async fn check(&self, binary: &Path, config_path: &Path) -> Result<(), String>;
}

/// 登录 URL 事件发射抽象。生产经 [`AppHandle`] 广播 `event:tailscaleAuthUrl`，测试捕获断言。
pub trait AuthUrlEmitter: Send + Sync {
    /// 发射一条登录 URL 事件（URL 首次出现或发生变更时发）。
    fn emit_auth_url(&self, server_id: &str, node_name: &str, url: &str);
}

/// 瞬态核 STATUS 流（每帧 = 全量端点快照）。生产是 `SubscribeTailscaleStatus` 的自动重连流，
/// 测试是喂脚本帧的内存桩 —— 这条抽象是「无真 gRPC 单测整条登录编排」的关键。
#[async_trait]
pub trait LoginStatusStream: Send {
    /// 取下一帧。`None` = 流终止（生产上 [`polaris_singbox_grpc::ReconnectingStream`] 断开即重连，
    /// 正常不返 `None`；返了就是内部终止，由调用方按「没有更多帧」处理）。
    async fn recv(&mut self) -> Option<daemon::TailscaleStatusUpdate>;
}

/// STATUS 流订阅抽象：按瞬态核自己的 api 端口 + secret 建流。
#[async_trait]
pub trait LoginStatusSubscriber: Send + Sync {
    /// 订阅 `127.0.0.1:<port>` 的 `SubscribeTailscaleStatus`。`secret` 空串 → 免认证。
    async fn subscribe(
        &self,
        port: u16,
        secret: &str,
    ) -> Result<Box<dyn LoginStatusStream>, String>;
}

// ── 生产实现 ────────────────────────────────────────────────────────────────────────────────

/// `tokio::process::Child` 包装的生产子进程句柄。
///
/// ## 为什么有 [`Drop`] 守卫（不是洁癖）
///
/// `tokio::process::Child` 默认 `kill_on_drop == false`：句柄被丢弃时 tokio 只把它推进 orphan 队列
/// **等待收割**，子进程照常活着。而瞬态核（登录核 / 测速临时核）的 kill 全靠调用方显式
/// [`terminate`](LoginCoreChild::terminate) —— 只要 future 在 `spawn` 与 `terminate` 之间被丢弃或
/// panic 展开，就留下一个持续持有回环端口（测速临时核是 N 个）+ WG/WARP peer 会话的**孤儿
/// sing-box**，且用户完全看不见。兜底 sweep 只在下次起主核时跑，Windows 更是恒 no-op
/// （`core-supervisor/src/stale_core.rs` 的 `scan_running_cores` 在非 Linux/macOS 返空）。
///
/// 用 Drop 守卫而非 `Command::kill_on_drop(true)`：后者必须设在 **spawn 之前**的 `Command` 上，
/// 而 spawn 收口在 `core-supervisor` 的 `TokioSpawner`（主核与瞬态核共用，主核**不能**跟着 app
/// 的任意 future 生死）。守卫挂在瞬态核专属的这层包装上，射程正好。
///
/// `start_kill` 只发信号不阻塞（Drop 不能 await）；已退出/已收割的 child 返 Err，无害吞掉。
pub struct TokioLoginCoreChild {
    child: tokio::process::Child,
}

impl Drop for TokioLoginCoreChild {
    fn drop(&mut self) {
        // 正常路径（`terminate()` 已收割）到这里是 no-op；异常路径（future 被丢弃 / panic）靠这一发。
        let _ = self.child.start_kill();
    }
}

#[async_trait]
impl LoginCoreChild for TokioLoginCoreChild {
    fn pid(&self) -> Option<u32> {
        self.child.id()
    }
    async fn wait(&mut self) {
        let _ = self.child.wait().await;
    }
    async fn terminate(&mut self) {
        // 1:1 镜像 ProxyRuntime::kill_core 的收割纪律：SIGTERM→宽限→SIGKILL，退出后取消挂起升级
        // （防 timer 泄漏 + pid 复用误杀），并 `wait()` 收割防僵尸。
        let pid = self.child.id().unwrap_or(0);
        if pid == 0 {
            // 已退出且被收割 → 仅 reap 残句柄。
            let _ = self.child.wait().await;
            return;
        }
        let escalation = ProcessKiller::escalate_async(
            move |sig| send_signal(pid, sig),
            move || pid_alive(pid),
            LOGIN_STOP_GRACE,
        )
        .await;
        let _ = self.child.wait().await;
        escalation.wait().await;
    }
}

/// 生产 spawner：经 [`TokioSpawner`] 起真 sing-box，再适配为 [`LoginCoreChild`]。
pub struct TokioLoginCoreSpawner;

impl LoginCoreSpawner for TokioLoginCoreSpawner {
    fn spawn(&self, req: SpawnRequest) -> Result<Box<dyn LoginCoreChild>, SpawnError> {
        // 装箱适配：把 `SpawnedChild` 换成 `LoginCoreChild`。请求原样透传 —— 排空回调在
        // `TokioSpawner::spawn` 内部就被调用完了，到这里 child 已经不带管道。
        let spawned = TokioSpawner::new().spawn(req)?;
        Ok(Box::new(TokioLoginCoreChild {
            child: spawned.child,
        }))
    }
}

/// 生产 checker：真跑 `sing-box check -c <file>` 并按退出码判定。
///
/// 子进程本身由 [`run_check_raw`] 起 —— 全仓唯一的 `sing-box check` 实现（起核闸门、本处、
/// 「测试内核兼容性」按钮三处共用）。本处此前自己写了一遍，写漏的是**超时**：check 若挂住
/// （慢盘、杀软扫描、核二进制半损坏），`output()` 会一直等下去，而它挂在登录核与测速临时核的
/// 起核前置位上，于是整条登录/测速流程跟着永久挂起，用户侧表现为「点了没反应」。
///
/// 超时值取 [`CONFIG_CHECK_TIMEOUT`]（5s）而不是 `commands/proxy.rs::PROBE_CHECK_TIMEOUT`（8s）：
/// 这里与起核闸门同属**起核关键路径**（用户在等一条连接建立，不是在等一个按钮回话），两者的
/// 容忍度应当一致；那份常量的文档也正是按这条分界线写的。
pub struct SingBoxConfigChecker;

#[async_trait]
impl ConfigChecker for SingBoxConfigChecker {
    async fn check(&self, binary: &Path, config_path: &Path) -> Result<(), String> {
        match run_check_raw(binary, config_path, CONFIG_CHECK_TIMEOUT).await {
            RawCheck::Done { success: true, .. } => Ok(()),
            RawCheck::Done { stderr, stdout, .. } => {
                let detail = if stderr.trim().is_empty() {
                    stdout.trim()
                } else {
                    stderr.trim()
                };
                Err(format!("sing-box check 判定登录配置无效: {detail}"))
            }
            RawCheck::SpawnFailed(e) => Err(format!("sing-box check 启动失败: {e}")),
            // 折叠前不存在的一支：此前无超时 ⇒ 这条路径的表现是永不返回。
            RawCheck::TimedOut { after_secs } => {
                Err(format!("sing-box check 超时（>{after_secs}s）"))
            }
        }
    }
}

/// 生产 STATUS 订阅器：连瞬态核自己的管理 API（h2c，127.0.0.1）建 `SubscribeTailscaleStatus` 自动重连流。
///
/// 与主核那条 relay（`runtime/proxy::spawn_tailscale_status_relay`）**互不相干**：各自端口、各自 secret、
/// 各自 stream 句柄，帧也不进主核的 `MeshRuntime::ts_status` 缓存（那份缓存的 `connected` 语义是
/// 「主核在跑」，写进瞬态核的帧会让它说谎）。
pub struct GrpcLoginStatusSubscriber;

#[async_trait]
impl LoginStatusSubscriber for GrpcLoginStatusSubscriber {
    async fn subscribe(
        &self,
        port: u16,
        secret: &str,
    ) -> Result<Box<dyn LoginStatusStream>, String> {
        // `connect` 建的是 **lazy** channel（`h2c::connect_h2c`）——此处不发生 I/O，故核尚未 bind 完
        // 也不会失败；真正的建流与重试在 `ReconnectingStream` 里。
        let client = SingBoxApiClient::connect(Endpoint::new("127.0.0.1", port), secret)
            .await
            .map_err(|e| format!("连瞬态登录核管理 API 失败（port={port}）: {e}"))?;
        Ok(Box::new(GrpcLoginStatusStream {
            stream: client.subscribe_tailscale_status(ReconnectConfig::default()),
        }))
    }
}

/// [`GrpcLoginStatusSubscriber`] 建出的流。`ReconnectingStream` 自持 target/secret，与建它的
/// client 无生命周期纠缠，故此处只留流本体。
struct GrpcLoginStatusStream {
    stream: polaris_singbox_grpc::ReconnectingStream<daemon::TailscaleStatusUpdate>,
}

#[async_trait]
impl LoginStatusStream for GrpcLoginStatusStream {
    async fn recv(&mut self) -> Option<daemon::TailscaleStatusUpdate> {
        self.stream.recv().await
    }
}

/// 生产 emitter：经 [`AppHandle`] 广播 `event:tailscaleAuthUrl`。
///
/// payload 与前端 `onTailscaleAuth` 契约同形：`{ serverId, nodeName, url, transient }`
/// （`ui/src/ipc/api-client.ts:155`）。
pub struct AppHandleEmitter {
    /// 广播用的 Tauri 应用句柄。
    pub app: AppHandle,
}

impl AuthUrlEmitter for AppHandleEmitter {
    fn emit_auth_url(&self, server_id: &str, node_name: &str, url: &str) {
        broadcast(
            &self.app,
            EVENT_TAILSCALE_AUTH_URL,
            json!({
                "serverId": server_id,
                "nodeName": node_name,
                "url": url,
                "transient": true,
            }),
        );
    }
}

// ── 注册表 + 编排 ────────────────────────────────────────────────────────────────────────────

/// 注册表条目：一个在飞瞬态登录核的控制句柄。child 本体由 supervisor 任务独占持有，本条目只留信号通道。
struct LoginEntry {
    /// 单调 epoch：区分同一 serverId 的不同代次登录（kill-on-relogin 后旧 supervisor 不得误删新表项）。
    epoch: u64,
    /// 该代次登录核的 OS pid（假 child 返占位值 ⇒ `None` 只在拿不到 pid 时出现）。
    ///
    /// **它不是日志字段**：`ProxyRuntime::cleanup_stale_cores` 的排除表经
    /// [`inflight_login_pids`](LoginCoreRegistry::inflight_login_pids) 读它 —— 瞬态登录核的 argv 与
    /// 主核同二进制 + `run`，不排除就会在起核时被当成上次会话遗留的孤儿杀掉（见模块头
    /// 「与 `cleanup_stale_cores` 的关系」）。
    pid: Option<u32>,
    /// 通知 supervisor kill+reap（cancel / kill-on-relogin 用）。
    cancel_tx: oneshot::Sender<()>,
}

/// 注册表共享状态（supervisor 任务与命令层共享）。
#[derive(Default)]
struct Shared {
    /// serverId → 在飞登录核条目。
    entries: Mutex<HashMap<String, LoginEntry>>,
}

impl Shared {
    fn guard(&self) -> MutexGuard<'_, HashMap<String, LoginEntry>> {
        // 锁只在 insert/remove 的极短临界区持有（绝不跨 await），中毒极不可能；中毒仍恢复内层，不 panic。
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn take(&self, id: &str) -> Option<LoginEntry> {
        self.guard().remove(id)
    }

    fn insert(&self, id: String, entry: LoginEntry) {
        self.guard().insert(id, entry);
    }

    fn can_start(&self, id: &str) -> bool {
        let entries = self.guard();
        entries.contains_key(id) || entries.len() < MAX_ACTIVE_LOGIN_CORES
    }

    /// epoch 守卫下注销：仅当表项仍是本 supervisor 的代次时移除（防 kill-on-relogin 后误删新代次）。
    fn remove_if_epoch(&self, id: &str, epoch: u64) {
        let mut g = self.guard();
        if g.get(id).is_some_and(|e| e.epoch == epoch) {
            g.remove(id);
        }
    }

    /// 全部在飞条目的 pid 快照（丢 `None`）。临界区只做一次拷贝，绝不跨 await。
    fn pids(&self) -> Vec<u32> {
        self.guard().values().filter_map(|e| e.pid).collect()
    }

    #[cfg(test)]
    fn contains(&self, id: &str) -> bool {
        self.guard().contains_key(id)
    }
}

/// [`start_login`](LoginCoreRegistry::start_login) 的结果。命令层据此折成前端 `{ started, reason?, authUrl? }`。
pub enum StartLoginOutcome {
    /// 已起瞬态登录核（登录 URL 稍后经事件到达，非「已登录」）。
    Started,
    /// 双写守卫命中：该 TS endpoint 已在运行主核里，无需瞬态核（前端 `reason: 'inMainCore'`）。
    InMainCore,
    /// 起核前失败（resolve / 写配置 / check / spawn）。返 error，未留表项、未起核。
    Failed(String),
}

/// 瞬态登录核生命周期注册表。持有注入的 spawner/checker/binary-resolver（生产真实现，测试 mock）。
///
/// 支撑：kill-on-relogin、超时自动杀、取消、自然退出 reap。与 `ProxyRuntime` 的常驻代理核隔离。
pub struct LoginCoreRegistry {
    shared: Arc<Shared>,
    spawner: Arc<dyn LoginCoreSpawner>,
    checker: Arc<dyn ConfigChecker>,
    subscriber: Arc<dyn LoginStatusSubscriber>,
    resolve_binary: BinaryResolver,
    timeout: Duration,
    epoch: AtomicU64,
    /// 串行化「检查旧代 → 起核 → 注册」事务，防同一 server 的并发 IPC 各自都看见空表，
    /// 后写者覆盖前写者的 cancel sender，留下无法再取消的孤儿核。
    start_gate: tokio::sync::Mutex<()>,
}

impl LoginCoreRegistry {
    /// 生产装配：真 spawner + 真 `sing-box check` + 真 gRPC STATUS 订阅 + 真核解析 + 默认超时。
    #[must_use]
    pub fn production() -> Self {
        Self::with_deps(
            Arc::new(TokioLoginCoreSpawner),
            Arc::new(SingBoxConfigChecker),
            Arc::new(GrpcLoginStatusSubscriber),
            Arc::new(resolve_core_binary),
            DEFAULT_LOGIN_TIMEOUT,
        )
    }

    /// 注入装配（测试用 mock，或自定义超时）。
    #[must_use]
    pub fn with_deps(
        spawner: Arc<dyn LoginCoreSpawner>,
        checker: Arc<dyn ConfigChecker>,
        subscriber: Arc<dyn LoginStatusSubscriber>,
        resolve_binary: BinaryResolver,
        timeout: Duration,
    ) -> Self {
        Self {
            shared: Arc::new(Shared::default()),
            spawner,
            checker,
            subscriber,
            resolve_binary,
            timeout,
            epoch: AtomicU64::new(1),
            start_gate: tokio::sync::Mutex::new(()),
        }
    }

    /// **此刻在飞**的瞬态登录核 pid 快照 —— `ProxyRuntime::cleanup_stale_cores` 的排除表来源。
    ///
    /// # 为什么必须有这条
    ///
    /// 瞬态登录核走的是同一个 [`resolve_core_binary`] + [`SpawnRequest`]，argv 与主核逐字同形
    /// （`<同一核二进制> run -c <cfg> --disable-color`）⇒ `is_our_core` 必然命中 ⇒ 在候选集里它与
    /// 「上次会话遗留的孤儿」不可区分。而清扫跑在**每一次**起核上，于是「点了 Tailscale 登录、
    /// 等着扫码时又去开 TUN」这条日常序列会把在飞登录核 SIGTERM 掐死：登录 URL 作废、
    /// 用户只看到「登录没反应」，且起核腿还要白等两段宽限。
    ///
    /// # 覆盖面（如实登记，别高估）
    ///
    /// 覆盖 **register(i) → supervisor 收核后注销** 这一段。两端各有一格不在射程内：
    /// - **spawn(g) → register(i)**：中间隔着 STATUS 流订阅那次真 `await`（[`LoginStatusSubscriber`]
    ///   要建 gRPC 连接），窗口比测速临时核的「几微秒同步代码」宽得多。这一格本批未关。
    /// - **cancel / kill-on-relogin**：[`cancel_login`](Self::cancel_login) 是先 `take` 出表、再通知
    ///   supervisor `terminate()`，故出表时进程**还活着**（最长一段 SIGTERM 宽限）。这一格里清扫会
    ///   把它当孤儿杀——而它本来就正在被杀，终局一致，只是可能多走一次信号。
    ///
    /// 自然退出 / 超时 / 登录成功三条路径都是 `terminate()`/`wait()` 收割**之后**才
    /// `remove_if_epoch`，故那三条的「出表时进程已死」成立。
    #[must_use]
    pub fn inflight_login_pids(&self) -> Vec<u32> {
        self.shared.pids()
    }

    /// **测试专用**：直接登记一条在飞条目（不起进程、不发任何信号），供**跨模块**的行为门
    /// （`ProxyRuntime::sweep_exclusions` 的孤儿清扫排除表）构造「登录核正在飞」这个状态。
    ///
    /// 放在这里而不是在 proxy 侧另造一张表：那样门测的就是测试自己写的表，而不是生产真的会读的
    /// 那一张。本函数只做 `insert`，读侧走的仍是生产的 [`inflight_login_pids`](Self::inflight_login_pids)。
    /// pid 字段本身「由 `child.pid()` 填」这一半由本模块的行为门（走真 `start_login`）单独钉。
    #[cfg(test)]
    pub(crate) fn register_inflight_for_test(&self, server_id: &str, pid: u32) {
        let (cancel_tx, _cancel_rx) = oneshot::channel();
        self.shared.insert(
            server_id.to_owned(),
            LoginEntry {
                epoch: 0,
                pid: Some(pid),
                cancel_tx,
            },
        );
    }

    /// **测试专用**：注销一条在飞条目（不发信号）。用于「出表之后同一 pid 必须重新可被清扫」这一格。
    #[cfg(test)]
    pub(crate) fn deregister_inflight_for_test(&self, server_id: &str) {
        self.shared.take(server_id);
    }

    /// 取消某 server 在飞的瞬态登录核（kill + 注销）。幂等：无在飞核返 `false`（非错误）。
    pub fn cancel_login(&self, server_id: &str) -> bool {
        match self.shared.take(server_id) {
            Some(entry) => {
                // 通知 supervisor kill+reap；发送失败（supervisor 已退）无妨。
                let _ = entry.cancel_tx.send(());
                true
            }
            None => false,
        }
    }

    /// 起一个瞬态登录核。
    ///
    /// 流程：双写守卫 → 解析核 → 解析管理 API 端口 + 生成 secret → 建 config → 写盘 →
    /// `sing-box check` → kill-on-relogin（先杀该 server 旧核）→ spawn → 订阅 STATUS 流 →
    /// 注册 + 计时臂 + 后台 supervise。
    ///
    /// `primary_api_port` = **运行中主核**的管理 API 端口（未运行传 0）：瞬态核的 api 端口必须避开它，
    /// 否则两个 api service 抢同一个 bind → 瞬态核直接 FATAL。其余排除项（control/http/mixed）取自
    /// `running_config` —— 与双写守卫同一份快照，语义正好：**只排除此刻真的被占着的端口**。
    ///
    /// `started ≠ 已登录`：登录 URL 经 [`AuthUrlEmitter`] 事件异步到达（源 = STATUS 帧的 `authURL`）。
    pub async fn start_login(
        &self,
        server: &ServerConfig,
        user_data: &Path,
        is_running: bool,
        running_config: Option<&UserConfig>,
        primary_api_port: u16,
        emitter: Arc<dyn AuthUrlEmitter>,
    ) -> StartLoginOutcome {
        let _start_guard = self.start_gate.lock().await;

        // (a) 双写守卫：endpoint 已在运行主核 → 拒起瞬态核（两个核同写 tailscale-state 会冲突）。
        if tailscale_endpoint_in_running_core(&server.id, is_running, running_config) {
            return StartLoginOutcome::InMainCore;
        }
        if !self.shared.can_start(&server.id) {
            return StartLoginOutcome::Failed(format!(
                "并发 Tailscale 登录已达上限 {MAX_ACTIVE_LOGIN_CORES}"
            ));
        }

        // (b) 解析核二进制（复用 proxy 的解析，禁重复实现）。
        let binary = match (self.resolve_binary)() {
            Ok(b) => b,
            Err(e) => return StartLoginOutcome::Failed(e),
        };

        // (c) 瞬态核管理 API：独立空闲端口 + 每次随机 secret。端口走既有簿记设施
        // （`resolve_tailscale_login_api_port`：bind(0) 取口、撞排除集重滚 5 次、仍撞则回落
        // control_api+2），secret 走与 clashApiSecret 同源的 CSPRNG。**secret 不是洁癖**：
        // 管理 API 虽只监听回环，但同机任意进程都能连上它读 tailnet 拓扑。
        let exclusions = PortExclusions::for_login_api(
            primary_api_port,
            // UserConfig 无 controlPort 字段（`impl PortConfig for UserConfig` 恒 None）→ 走默认 9090。
            None,
            running_config.and_then(|c| c.http_port),
            None,
            running_config.and_then(|c| c.mixed_port),
        );
        let resolved =
            PortAllocator::new(TokioPortProvider).resolve_tailscale_login_api_port(&exclusions);
        if resolved.used_fallback {
            log::warn!(
                "瞬态登录核管理 API 端口 5 次解析均撞排除集 → 回落 {}",
                resolved.port
            );
        }
        let secret = match generate_login_api_secret() {
            Ok(s) => s,
            Err(e) => return StartLoginOutcome::Failed(e),
        };
        let api = TailscaleLoginApiService {
            port: resolved.port,
            secret,
        };

        // (d) 构造登录 config（恒带管理 api service → 恒有 STATUS 流）→ 写盘。
        //
        // 文件名带**代次**（epoch），不是只带 server id：收核后 supervisor 会删掉自己那份 config
        // （里面有 secret），而 kill-on-relogin 下新旧两代同时在场——路径若只按 server id 取，
        // 旧代 supervisor 的删除就会打在**新代**刚写好的那份上（它的 `terminate()` 有最长 5s 的
        // SIGTERM 宽限，删除随时可能晚于新核 spawn）。带代次后每份 config 只有一个主人。
        let epoch = self.epoch.fetch_add(1, Ordering::SeqCst);
        let cfg = match build_tailscale_login_config(server, user_data, &api) {
            Ok(config) => config,
            Err(error) => return StartLoginOutcome::Failed(error.to_string()),
        };
        let json_cfg = login_config_to_json(&cfg);
        let config_path = user_data.join(format!(
            "tailscale-login-{}-{epoch}.json",
            sanitize_id(&server.id)
        ));
        let bytes = match serde_json::to_vec_pretty(&json_cfg) {
            Ok(b) => b,
            Err(e) => return StartLoginOutcome::Failed(format!("序列化登录配置失败: {e}")),
        };
        if let Err(e) = write_login_config_secure(&config_path, &bytes) {
            return StartLoginOutcome::Failed(format!(
                "写登录配置失败 {}: {e}",
                config_path.display()
            ));
        }
        // 从含 secret 的文件出现这一刻起，任何提前返回或 future 取消都必须清理；成功把路径
        // 移交 supervisor 后才解除。不能只在已知 Err 分支手写 remove，否则新增 await/return 会再漏。
        let mut config_guard = LoginConfigGuard::new(&config_path);

        // (e) sing-box check 先验配置形状（失败快退、不 spawn —— 这一段可单测）。
        if let Err(e) = self.checker.check(&binary, &config_path).await {
            return StartLoginOutcome::Failed(e);
        }

        // (f) kill-on-relogin：先杀该 server 在飞的旧瞬态核（若有），再起新核。
        self.cancel_login(&server.id);

        // (g) spawn 瞬态登录核（`run -c <cfg> --disable-color`，避免 ANSI 污染日志）。
        //
        // 两条流的去向在**请求里**一次说清：spawner 在返回之前就把读端交给这个回调，核从起来的
        // 第一毫秒起就有人读它。**纯诊断**：登录 URL 与登录成功都只认 STATUS 流（见模块头），
        // 这两条流不是任何判据的来源。target 用本腿自己的，不与主核混（见 `LOGIN_CORE_LOG_TARGET`）。
        let mut req = SpawnRequest::new(
            &binary,
            &config_path,
            StdioPolicy::drain(|stdout, stderr| {
                pipe_to_log(stdout, LOGIN_CORE_LOG_TARGET, None, None);
                pipe_to_log(stderr, LOGIN_CORE_LOG_TARGET, None, None);
            }),
        );
        req.extra_args = vec!["--disable-color".to_string()];
        let mut child = match self.spawner.spawn(req) {
            Ok(c) => c,
            Err(e) => return StartLoginOutcome::Failed(format!("{e}")),
        };

        // (h) 订阅瞬态核自己的 STATUS 流。**建不起来就硬失败**（不回退 stdout，理由见模块头）：
        // 此时核已起，必须先收掉它再报错，否则留下一个谁都不认识的孤儿核。
        let status = match self.subscriber.subscribe(api.port, &api.secret).await {
            Ok(s) => s,
            Err(e) => {
                child.terminate().await;
                return StartLoginOutcome::Failed(format!(
                    "瞬态登录核 STATUS 流订阅失败（登录 URL 与登录成功判据均取自它，无回退路径）: {e}"
                ));
            }
        };

        // (i) 注册 + 后台 supervise（内含超时臂 / STATUS→URL relay / Running→收核 / cancel / reap）。
        // 复用 (d) 已取的 `epoch`：注册表代次与 config 文件名必须是**同一个**代次，否则「谁该删这份
        // config」与「谁该注销这个表项」会各按各的编号走。
        let (cancel_tx, cancel_rx) = oneshot::channel();
        // pid 必须在 `child` 被移进 supervise 之前取：它是孤儿清扫排除表的唯一来源
        // （见 [`inflight_login_pids`]）。取不到（假 child / 已退出）时留 `None`，排除表少一项，
        // 方向仍是「宁可漏排除，不可乱排除」。
        let pid = child.pid();
        self.shared.insert(
            server.id.clone(),
            LoginEntry {
                epoch,
                pid,
                cancel_tx,
            },
        );
        let ctx = SuperviseCtx {
            shared: self.shared.clone(),
            server_id: server.id.clone(),
            node_name: server.name.clone(),
            // 瞬态核只含本节点一个 endpoint，其 tag = server.name（见 `build_tailscale_login_config`）。
            // 复用主核那套解码器就得给它同一份 tag→id 映射；一并承担了「别的 tag 的帧一律丢弃」。
            tag_to_id: BTreeMap::from([(server.name.clone(), server.id.clone())]),
            config_path: config_path.clone(),
            epoch,
            timeout: self.timeout,
            emitter,
        };
        config_guard.disarm();
        tokio::spawn(supervise(ctx, child, status, cancel_rx));
        StartLoginOutcome::Started
    }
}

/// 瞬态核管理 API 的一次性 secret（CSPRNG 16 字节 → 32 位小写 hex）。
/// 与 `clashApiSecret` 同源生成器（[`crate::commands::config::generate_local_api_secret`]）：同一熵源、
/// 同一形状，熵源不可用 → Err（绝不产弱/空密钥而把管理面裸奔当成「降级可用」）。
fn generate_login_api_secret() -> Result<String, String> {
    crate::commands::config::generate_local_api_secret()
        .map_err(|e| format!("生成瞬态登录核管理 API secret 失败: {e}"))
}

/// supervisor 任务的入参束（避免 `too_many_arguments`）。
struct SuperviseCtx {
    shared: Arc<Shared>,
    server_id: String,
    node_name: String,
    /// 单条映射 `server.name → server.id`：喂给 [`decode_tailscale_status`]，顺带把「别的 tag」的
    /// 端点整段丢掉（瞬态核理论上只有一个 endpoint，但判据不该建立在「理论上」之上）。
    tag_to_id: BTreeMap<String, String>,
    /// 本次登录写盘的临时 config 路径，收核后删。
    ///
    /// 此前不删也只是留个垃圾文件；**自本批起它里面有 secret**（管理 API 的一次性 Bearer），
    /// 核一退它就是一份没人再用、却仍躺在盘上的凭据 —— 生命周期该跟核一致。
    config_path: PathBuf,
    epoch: u64,
    timeout: Duration,
    emitter: Arc<dyn AuthUrlEmitter>,
}

/// 瞬态登录核退出原因。
enum ExitReason {
    /// 核自然退出（无需主动 kill，直接 reap）。
    SelfExit,
    /// 用户取消 / kill-on-relogin。
    Cancelled,
    /// 超时未完成登录。
    TimedOut,
    /// STATUS 报 `backendState == "Running"`：登录成功、state 已落盘 → 主动收核。
    LoggedIn,
    /// STATUS 流内部终止（`ReconnectingStream` 正常永不如此）。没有流就没有任何判据来源
    /// （不回退 stdout，见模块头），继续挂着只是让核空跑到超时 → 就地收核。
    StatusStreamEnded,
}

/// 单个瞬态登录核的后台 supervisor：消费 STATUS 流（authURL → 事件、Running → 收核）、
/// 扛超时/取消、退出后按 epoch 守卫注销。
async fn supervise(
    ctx: SuperviseCtx,
    mut child: Box<dyn LoginCoreChild>,
    mut status: Box<dyn LoginStatusStream>,
    mut cancel_rx: oneshot::Receiver<()>,
) {
    // stdout/stderr 的排空**不在这里**：它在 `start_login` 构造 `SpawnRequest` 时就接好了，
    // spawner 返回之前已经生效。放在 supervise 里曾经意味着「spawn 与接管之间有一段没人读的
    // 窗口」，而那正是本轮根因缺陷的形态（测速临时核那条腿连这一步都没有）。
    // 登录状态机（`polaris_mesh`，纯逻辑已单测）：它同时承担「同一 URL 反复到达不重复通知用户」
    // 与「后到的 authURL 不得把已登录态打回去」两条不变式，此处不再另写去重标志。
    let mut state = LoginState::Idle;
    let sleep = tokio::time::sleep(ctx.timeout);
    tokio::pin!(sleep);

    let reason = loop {
        tokio::select! {
            _ = &mut cancel_rx => break ExitReason::Cancelled,
            () = &mut sleep => break ExitReason::TimedOut,
            () = child.wait() => break ExitReason::SelfExit,
            frame = status.recv() => {
                let Some(update) = frame else { break ExitReason::StatusStreamEnded };
                state = apply_status_frame(&ctx, &state, &update);
                if state == LoginState::LoggedIn {
                    break ExitReason::LoggedIn;
                }
            }
        }
    };

    match reason {
        ExitReason::SelfExit => {
            log::info!(
                "瞬态登录核自然退出并收割：server={} pid={:?}",
                ctx.server_id,
                child.pid()
            );
        }
        ExitReason::Cancelled => {
            log::info!("瞬态登录核取消 → 终止：server={}", ctx.server_id);
            child.terminate().await;
        }
        ExitReason::TimedOut => {
            log::warn!(
                "瞬态登录核 {:?} 内未完成登录 → 超时终止：server={}",
                ctx.timeout,
                ctx.server_id
            );
            child.terminate().await;
        }
        ExitReason::LoggedIn => {
            // 控制面的终局肯定：已认证、state 已落盘 → 核没有再活着的理由，且它还占着该节点的
            // state_directory（主核要用同一份）。1:1 对齐 上游 `handleTransientTailscaleStatus`。
            log::info!(
                "Tailscale 登录成功（backendState=Running）→ 收瞬态登录核：server={}",
                ctx.server_id
            );
            child.terminate().await;
        }
        ExitReason::StatusStreamEnded => {
            log::warn!(
                "瞬态登录核 STATUS 流终止（无 URL/登录成功判据来源）→ 终止：server={}",
                ctx.server_id
            );
            child.terminate().await;
        }
    }
    // 核已收割 → 删掉带 secret 的临时 config。
    remove_login_config(&ctx.config_path);
    // reap 后注销（epoch 守卫：不误删 kill-on-relogin 后的新代次表项）。
    ctx.shared.remove_if_epoch(&ctx.server_id, ctx.epoch);
}

/// 删掉本次登录写盘的临时 config（内含一次性管理 API secret）。best-effort：
/// 已被 kill-on-relogin 的新一代覆写、或早被删掉，都不是问题——本函数只保证「核死了就不留凭据」。
fn remove_login_config(path: &Path) {
    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            log::warn!(
                "删除瞬态登录核临时配置失败（内含一次性 secret）{}：{e}",
                path.display()
            );
        }
    }
}

/// 以独占创建 + Unix 0600 落含 bearer secret 的瞬态配置。
///
/// `create_new` 同时拒绝已存在文件和符号链接，避免可预测文件名被预置后覆盖其它路径；旧的崩溃残件
/// 宁可让本次登录明确失败，也不能复用/截断一个身份不明的 inode。
fn write_login_config_secure(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)
}

struct LoginConfigGuard<'a> {
    path: &'a Path,
    armed: bool,
}

impl<'a> LoginConfigGuard<'a> {
    fn new(path: &'a Path) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for LoginConfigGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            remove_login_config(self.path);
        }
    }
}

/// 一帧全量端点快照 → 推进登录状态机（并在 URL 首现/变更时发事件）。
///
/// 解码复用主核那条 relay 的同一个投影器 [`decode_tailscale_status`]：`authURL` / `backendState`
/// 的读法只此一处，proto 再漂移时两条腿一起动，不会出现「主核修好了、登录核还错着」。
fn apply_status_frame(
    ctx: &SuperviseCtx,
    current: &LoginState,
    update: &daemon::TailscaleStatusUpdate,
) -> LoginState {
    let mut state = current.clone();
    for ev in decode_tailscale_status(update, &ctx.tag_to_id) {
        // 登录成功判据 = **backendState 字面为 Running**，不是 `logged_in`（后者含 `Starting`，那还
        // 只是「在连」；上游 `handleTransientTailscaleStatus` 同样只认 Running）。
        if ev.backend_state == "Running" {
            state = advance_login_state(&state, &LoginEvent::StatusRunning);
        }
        if let Some(url) = ev.auth_url {
            let next = advance_login_state(&state, &LoginEvent::AuthUrlSeen(url));
            // 状态真的变了才发：同一 URL 每帧都来（核只在换 URL 时才换值），发一次就够。
            if next != state {
                if let LoginState::AwaitingAuth(u) = &next {
                    ctx.emitter.emit_auth_url(&ctx.server_id, &ctx.node_name, u);
                }
            }
            state = next;
        }
    }
    state
}

/// server id → 安全文件名片段（防路径穿越；非字母数字/-/_ 归一为 `_`）。
fn sanitize_id(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests;
