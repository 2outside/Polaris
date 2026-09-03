//! 进程监管 owner：受管核的杀停（直起 / helper 两腿）、启动期 stale-core 清扫与 root 孤儿提权清扫、
//! 起核后的内核二进制自证，以及 pid 层的观测原语（实跑 exe 路径 / 信号 / 探活 / 进程身份令牌）。
//!
//! [`pid_alive`] / [`send_signal`] 被 `proxy` 外部消费（`speedtest.rs` / `tailscale_login_core.rs` /
//! `win_console.rs`），façade 必须 `pub(crate) use` 再导出（§B.3）。

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use polaris_core_supervisor::{scan_running_cores, stale_pids, ProcessKiller, Signal};

use crate::runtime::helper::HelperStopOps;
use crate::runtime::win_console::no_console_window;

use super::core_binary::resolve_core_binary;
use super::startup::attestation_commit_allowed;
use super::{code, ProxyRuntime, StartError};

/// SIGTERM→SIGKILL 宽限期（上游 `stopSingBoxProcess` 的 5s 优雅窗口，:5230）。
pub(super) const STOP_GRACE: Duration = Duration::from_secs(5);

/// stale-core 清扫 SIGTERM→SIGKILL 宽限期（对齐 上游 `killOrphanedProcessesLinux` 的 1.5s，:1132）。
pub(super) const STALE_KILL_GRACE: Duration = Duration::from_millis(1_500);

impl ProxyRuntime {
    /// **内核自证**：核就绪后校验「**实际跑起来的那个二进制**的版本 == 本次期望的核版本」。
    ///
    /// # 这一条为什么必须观测事实（血证）
    ///
    /// 同仓既有的[出口自证](Self::attest_selected_exit)是**纯静态对账**（自述「纯函数、零 I/O」
    /// 「不用探针 / 不查 selector」）：它拿本次生成的 config 与落盘的用户意图互校 —— 两个输入同源于
    /// 「意图」，故意图自洽而事实偏离时它一律判通过。今天这个缺陷正是在它眼皮底下溜过去的：
    /// app 请求 bin=`core_update/sing-box`(1.14.0-beta.3)，helper 实跑
    /// `/Library/Application Support/Polaris/core/sing-box`(1.14.0-alpha.45)，持续一天多、零告警。
    ///
    /// 故本方法**不**对账「我请求了什么 / 我配置了什么」，而是问系统两个事实问题：
    ///  1. **内核记账里，这个 pid 正在执行哪个文件？**（`running_exe_path`：linux `/proc/<pid>/exe`
    ///     符号链接、mac `ps -p <pid> -o comm=`）—— 与我们的请求完全独立的来源；
    ///  2. **那个文件自报什么版本？**（对它真跑一次 `sing-box version`）。
    ///
    /// # 判据与代价
    ///
    /// 路径相同 ⇒ 同一文件，直接通过，**零 spawn**（app 直起腿的稳态走这里）。
    /// 路径不同才各跑一次 `version`（TUN 提权腿的稳态：实跑受保护核副本，版本应相同）。
    /// 「读不出版本」判**告警**而非通过 —— 见 [`CoreBinaryAttestation::VersionUnreadable`]。
    /// 「读不到实跑 exe」判 [`Unobservable`](crate::runtime::core_promote::CoreBinaryAttestation::Unobservable)：只落 warn，
    /// **绝不写成「自证通过」**（没观测到 ≠ 观测到没问题）。
    ///
    /// [`CoreBinaryAttestation::VersionUnreadable`]: crate::runtime::core_promote::CoreBinaryAttestation::VersionUnreadable
    pub(super) fn spawn_running_core_binary_attestation(
        self: &Arc<Self>,
        pid: u32,
        expected: PathBuf,
        my_gen: u64,
    ) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let started = std::time::Instant::now();
            this.attest_running_core_binary(pid, &expected, my_gen)
                .await;
            log::info!(
                "起核后台耗时：内核二进制自证={}ms（pid={pid}）",
                started.elapsed().as_millis()
            );
        });
    }

    async fn attest_running_core_binary(&self, pid: u32, expected: &Path, my_gen: u64) {
        use crate::runtime::core_promote::{attest_core_binary, CoreBinaryAttestation};

        let expected = expected.to_path_buf();
        // 观测腿全是阻塞 syscall / 子进程 → spawn_blocking。
        let attestation = tokio::task::spawn_blocking(move || {
            let running = running_exe_path(pid);
            // 路径相同就不必花两次 spawn 去问版本（同一文件，版本必同）。
            let (ev, rv) = match running.as_deref() {
                Some(r) if r != expected.as_path() => (
                    core_version_first_line(&expected),
                    core_version_first_line(r),
                ),
                _ => (String::new(), String::new()),
            };
            attest_core_binary(&expected, running.as_deref(), &ev, &rv)
        })
        .await;

        let attestation = match attestation {
            Ok(a) => a,
            Err(e) => {
                log::warn!("内核自证任务 join 失败（未判定通过）：{e}");
                return;
            }
        };
        let status = self.status();
        if !attestation_commit_allowed(self.gate.generation(), my_gen, &status, pid) {
            log::info!(
                "内核自证完成时启动世代或 pid 已变化 → 丢弃陈旧结论（世代 {my_gen}→{}，pid {pid}→{}）",
                self.gate.generation(),
                status.pid
            );
            return;
        }
        if attestation.is_alarm() {
            // 非终态：核确在跑，只是版本不对 → 保留 running/pid/端口，只落错误两轴 + 广播事件。
            self.set_nonfatal_error(&attestation.user_message(), code::CORE_BINARY_MISMATCH);
            return;
        }
        match attestation {
            // 「没观测到」既不是通过也不是错误：只留痕，绝不说「通过」。
            CoreBinaryAttestation::Unobservable => log::warn!("{}", attestation.user_message()),
            _ => log::info!("{}", attestation.user_message()),
        }
    }

    /// 杀核（接线 core-supervisor [`ProcessKiller`]）：SIGTERM → 宽限 → SIGKILL，并 reap 子进程。
    ///
    /// 无在跑核 = no-op。退出/崩溃/重启后不留孤儿：child 句柄被 take 后必 `wait()` 收割。
    /// helper 腿未确认停止时返回错误，调用方不得继续清运行态或启动第二个核。
    pub(super) async fn kill_core(&self) -> Result<(), String> {
        // C6-5：经 helper 起的核 → 经 helper stop（对称）。daemon 摘其受管 child → SIGTERM→宽限→SIGKILL
        // 收割（app 无本地 child 句柄）。阻塞 IPC 挪出 async worker。
        if self.core_via_helper.load(Ordering::SeqCst) {
            return self
                .kill_core_via_helper(Arc::clone(&self.helper) as Arc<dyn HelperStopOps>)
                .await;
        }
        let child_opt = match self.child.lock() {
            Ok(mut g) => g.take(),
            Err(e) => {
                log::error!("child lock poisoned: {e}");
                return Err(format!("child lock poisoned: {e}"));
            }
        };
        let Some(mut child) = child_opt else {
            return Ok(());
        };
        let pid = child.id().unwrap_or(0);
        if pid == 0 {
            // 已退出且被收割 → 仅 reap 残句柄。
            //
            // **同样要清 `self.pid`**：此前这条腿直接 return，把上一次 spawn 的 pid 留在字段里。这不是
            // 罕见角落 —— 核「起来就死」时就绪门的 `try_wait` 会先一步收割它，`child.id()` 随即变 None ⇒
            // 每一次起核失败都从这里走。留下的陈旧 pid 会被 `status()`、诊断、以及 stale 清扫的「受管
            // pid 排除表」当成活的受管核继续引用（排除表里挂个死 pid，等于给同号新进程发免死金牌）。
            let _ = child.wait().await;
            if let Ok(mut g) = self.pid.lock() {
                *g = None;
            }
            return Ok(());
        }
        log::info!("停核：pid={pid}（SIGTERM → {STOP_GRACE:?} 宽限 → SIGKILL）");
        let escalation = ProcessKiller::escalate_async(
            move |sig| send_signal(pid, sig),
            move || pid_alive(pid),
            STOP_GRACE,
        )
        .await;
        // 等进程退出（reap，防僵尸）。进程若拒 SIGTERM，升级 task 到点补 SIGKILL 解开此处。
        let _ = child.wait().await;
        // 进程已退出 → 取消挂起的 SIGKILL 升级（防 timer 泄漏 + 防 pid 复用误杀）。
        escalation.wait().await;
        if let Ok(mut g) = self.pid.lock() {
            *g = None;
        }
        log::info!("停核完成：pid={pid} 已退出并收割");
        Ok(())
    }

    /// [`kill_core`](Self::kill_core) 的 helper 分支：**带身份**请 daemon 停它自己的受管 child。
    ///
    /// `ops` 参数化（生产传 [`HelperRuntime`](crate::runtime::helper::HelperRuntime)）是为了让本腿可注入替身 —— 否则「请求带没带身份 pid」
    /// 「IPC 期间被接管时记账动没动」两条都只能靠读代码推理，没法变成有牙的门。
    ///
    /// **身份先于 await 取定**（根因）：`stop_inner` 的换代守卫只能在 `kill_core` **返回之后**让位，
    /// 够不着这条 IPC 内部 —— 而经 helper 停核是同步阻塞往返（socket 已删 / daemon 无响应时可以挂
    /// 很久），期间用户完全可能重装 helper 并起了新核。不带身份下发，daemon 就按「停我当前受管的
    /// 那个」执行 = 杀掉用户刚连上的新核（现象：刚连上就被静默断开，且酷似核自己崩了）。
    pub(super) async fn kill_core_via_helper(
        &self,
        ops: Arc<dyn HelperStopOps>,
    ) -> Result<(), String> {
        let intended = self.pid.lock().ok().and_then(|g| *g);
        // 阻塞 IPC 挪出 async worker。
        let result =
            match tokio::task::spawn_blocking(move || ops.stop_managed_core(intended)).await {
                Ok(Ok(())) => {
                    log::info!("经 helper 停核完成（pid={intended:?}）");
                    Ok(())
                }
                // daemon 可能已因父死看护/崩溃自行收割 → stop 返 notrunning/错误，非致命；
                // 也可能是身份不匹配的诚实 no-op（消息自述），那正是本守卫生效的痕迹。
                Ok(Err(e)) => {
                    log::warn!("经 helper 停核未完成：{e}");
                    Err(e)
                }
                Err(e) => {
                    let error = format!("helper 停核任务 join 失败：{e}");
                    log::error!("{error}");
                    Err(error)
                }
            };
        if result.is_ok() {
            self.clear_helper_core_bookkeeping(intended);
        }
        result
    }

    /// helper 停核腿的记账收口：**只清自己那笔**（[`kill_core`](Self::kill_core) 的 helper 分支专用）。
    ///
    /// `intended` = 本腿进 IPC 前拿到的受管 pid。IPC 往返期间 `self.pid` 可能已被**新会话**写成另一个
    /// pid（这正是身份判据要防的那条时序）。此时把它清成 `None` 的后果不是「多清一次」而是让新核**失联**：
    /// `status()` 的 helper 腿据 `self.pid` 探活、诊断据它报 pid、`cleanup_stale_cores` 的「受管 pid 排除表」
    /// 也据它——排除表里少了新核，下一次起核的孤儿清扫就会把它当孤儿杀掉（换个地方杀错进程）。
    ///
    /// 本方法只会在 helper 已确认 `stopped/notrunning` 后调用；此时仅在「记账已换成另一个 pid」时
    /// 留手，其余情形（等值 / 现为 `None`）照清。通信失败/结果未知不会进入本方法。
    pub(super) fn clear_helper_core_bookkeeping(&self, intended: Option<u32>) {
        let Ok(mut g) = self.pid.lock() else {
            log::error!("pid lock poisoned：跳过 helper 停核记账收口");
            return;
        };
        let current = *g;
        if current.is_some() && current != intended {
            log::warn!(
                "helper 停核腿收口时发现受管 pid 记账已换人（{intended:?}→{current:?}）→ \
                 整段记账属新会话，不动它（清它等于让新核在 status/诊断/孤儿清扫排除表里集体失联）"
            );
            return;
        }
        *g = None;
        self.core_via_helper.store(false, Ordering::SeqCst);
    }

    /// **起核前**的 stale-core 清扫：杀掉遗留的**本 app** 孤儿核。跑在**每一次** `start()` 上
    /// （不是只在 app 启动期一次；孤儿也来自本会话中途失败的起核，见 `stale_sweep_disabled` 字段文档）。
    ///
    /// **安全第一性**（本任务核心）：只杀 cmdline 精确匹配 `resolve_core_binary()` 路径 + `run` 的进程
    /// （core-supervisor [`stale_pids`]），并排除 [`sweep_exclusions`](Self::sweep_exclusions) 给出的
    /// 「不是孤儿」的那些 pid（当前受管主核 + 在飞测速临时核 + 在飞 Tailscale 登录核）。
    /// **绝不 `pkill sing-box`**——用户机器上
    /// 可能装有无关的 sing-box。解析不到核二进制 / 非 Linux（扫描返空）→ 静默跳过（fail-closed，不误杀）。
    pub(super) async fn cleanup_stale_cores(&self) -> Result<(), StartError> {
        // 实跑计数：置于所有早退腿之前 —— 计的是「清扫这条腿被走到几次」，而非「杀掉几个孤儿」。
        self.stale_sweep_runs.fetch_add(1, Ordering::SeqCst);
        let binary = match resolve_core_binary() {
            Ok(b) => b,
            Err(e) => {
                log::debug!("stale 清扫：未解析到核二进制（{e}）→ 跳过");
                return Ok(());
            }
        };
        // **不 canonicalize**：spawner 用 `resolve_core_binary()` 的**字面**路径起核（`Command::new`），
        // /proc 里的 argv[0] 即那个字面路径；两次会话同一 resolve 逻辑 → 字面一致即可匹配。规范化反而会
        // 与含 symlink/`..` 的字面 argv[0] 失配、漏杀自己的孤儿（与 上游 pgrep 用字面 singboxPath 同源）。
        let candidates = scan_running_cores();
        // 排除表（受管主核 + 两种在飞瞬态核）**必须读在扫描之后**，顺序契约见 `sweep_exclusions`。
        let victims = stale_pids(&candidates, &binary, &self.sweep_exclusions());
        if victims.is_empty() {
            return Ok(());
        }
        log::warn!(
            "发现 {} 个上次遗留的孤儿核（本 app 二进制 {}），清理：{victims:?}",
            victims.len(),
            binary.display()
        );
        // SIGTERM → 宽限 → SIGKILL 存活者（对齐 上游 killOrphanedProcessesLinux）。
        for pid in &victims {
            send_signal(*pid, Signal::Sigterm);
        }
        tokio::time::sleep(STALE_KILL_GRACE).await;
        for pid in &victims {
            if pid_alive(*pid) {
                log::warn!("孤儿核 pid={pid} 宽限期未退 → SIGKILL");
                send_signal(*pid, Signal::Sigkill);
            }
        }
        // **T3 二次确认**：SIGKILL 后仍存活 = 用户态根本杀不动（`send_signal` 对 root 进程收 EPERM 且
        // 被 `let _ =` 吞掉，**杀失败与杀成功在调用处无从区分**）。故只能靠再探一次活来判定。
        tokio::time::sleep(STALE_KILL_GRACE).await;
        let survivors: Vec<u32> = victims.iter().copied().filter(|p| pid_alive(*p)).collect();
        if survivors.is_empty() {
            log::info!("孤儿核清理完成：{victims:?}");
            return Ok(());
        }
        self.escalate_root_orphans(&survivors).await
    }

    /// 清扫的**排除表** = 当前受管主核 pid + 此刻在飞的**测速临时核** pid + 此刻在飞的
    /// **Tailscale 瞬态登录核** pid。
    ///
    /// # 为什么这两种瞬态核都必须在这里
    ///
    /// 临时核的 argv 是 `<resolve_core_binary()> run -c <临时配置> --disable-color`
    /// （`SpawnRequest::argv` + `speedtest.rs` 的 `extra_args`）—— 与主核**同一个**二进制路径 + `run`
    /// token ⇒ [`is_our_core`](polaris_core_supervisor::is_our_core) 必然命中：它在候选集里长得跟
    /// 「上次会话遗留的孤儿」一模一样，而清扫这条腿跑在**每一次** `start()` 上（不是只在 app 启动期，
    /// 见 `lifecycle.rs` 的调用点）。于是「测速到一半点连接 / 开 TUN」这条用户日常操作序列必然撞上：
    ///
    /// 1. SIGTERM 掐死正在测的临时核 ⇒ 剩余节点整批作废（且核是被外部杀的，测速侧只看到「核没了」）；
    /// 2. 起核腿白等两段 [`STALE_KILL_GRACE`]（+3.0s）——用户报的「测速中启动 TUN，启动明显变慢」；
    /// 3. 万一那一刻用户态杀不动（EPERM 被 `send_signal` 的 `let _` 吞掉），还会升级到
    ///    [`code::ROOT_ORPHAN_BLOCKED`] 把这次起核**直接判死**。
    ///
    /// **Tailscale 瞬态登录核是同一个缺陷的姊妹腿**（`tailscale_login_core.rs` 的模块文档早就把它
    /// 登记在案、当时以「需要 mesh↔proxy 反向耦合」为由未修）：它同样走
    /// [`resolve_core_binary`] + `SpawnRequest`，argv 逐字同形。用户序列是「点了 Tailscale 登录、
    /// 正等着扫码，顺手去开 TUN」⇒ 登录核被掐死、登录 URL 作废，前端只看到「登录没反应」。
    /// 耦合方向本来就是现成的：`self.mesh` 已在手，`MeshRuntime` 已持有 `LoginCoreRegistry`，
    /// 缺的只是注册表里的 pid 字段（本批补上）。
    ///
    /// # 顺序契约（调用点持有）：本表必须读在 `scan_running_cores()` **之后**
    ///
    /// - 扫描之后才起的瞬态核 ⇒ 不在候选集里 ⇒ 本就杀不到它；
    /// - 扫描之前起的瞬态核 ⇒ 此刻要么仍在表里（被排除），要么已经退出并注销
    ///   （`TempCorePidGuard` 的 Drop 跑在 `terminate()` 收割**之后** ⇒ 出表时进程已死）。
    ///
    /// 反过来「先读表再扫描」就漏了一格：读表 → 瞬态核 spawn → 扫描，该 pid 既在候选集又不在表快照里。
    /// 故这里**不需要**加锁扩大临界区（那要求 `INFLIGHT_TEMP_CORES` 罩住整条含 `await` 的清扫腿），
    /// 只需要保持这个顺序。
    ///
    /// # 两条腿各自的残余窗口（如实登记，别当成全覆盖）
    ///
    /// - **测速临时核**：spawn 返回到登记入表之间那一小段**同步**代码（起点其实是 fork），与主核
    ///   「spawn 完再记 `self.pid`」的窗口同构，是本仓既有的取舍。
    /// - **登录核**：spawn 与登记之间隔着一次**真 `await`**（STATUS 流的 gRPC 订阅），窗口比上面那条
    ///   宽得多；且 `cancel_login` 是先出表再收核，出表时进程还活着。两格都未关，详见
    ///   [`LoginCoreRegistry::inflight_login_pids`](crate::runtime::tailscale_login_core::LoginCoreRegistry::inflight_login_pids)。
    /// - **两条腿共有**：`victims` 在两段 1500 ms 宽限**之前**就冻结了，排除表管不到「孤儿被杀 →
    ///   pid 被 init 回收 → 该 pid 号在 1.5 s 内被新起的瞬态核复用」这一格（需 pid 回绕，概率极低）。
    pub(super) fn sweep_exclusions(&self) -> Vec<u32> {
        let mut exclude: Vec<u32> = self.pid.lock().ok().and_then(|g| *g).into_iter().collect();
        let temp: Vec<u32> = crate::runtime::speedtest::inflight_temp_core_pids();
        let login: Vec<u32> = self.mesh.inflight_login_core_pids();
        // 有在飞瞬态核时留一行：否则「这次清扫到底排除了谁」在事后只能靠猜，而猜正是本条腿
        // 上一次失守的方式。两种瞬态核都不在飞时（绝大多数起核）不打，不给日志添恒常噪音。
        if !temp.is_empty() || !login.is_empty() {
            log::info!(
                "stale 清扫排除表纳入 {} 个在飞测速临时核 {temp:?} + {} 个在飞 Tailscale 登录核 \
                 {login:?}（受管主核 {exclude:?}）",
                temp.len(),
                login.len()
            );
        }
        exclude.extend(temp);
        exclude.extend(login);
        exclude
    }

    /// **T3**：用户态杀不动的 root 孤儿核 → 经 helper 提权清扫；清不掉则落诚实终态。
    ///
    /// 对齐 上游 `escalateKillRootOrphans` + `ROOT_ORPHAN_BLOCKED`。**为什么必须阻断起核而不是继续**：
    /// 活着的 root 孤儿一直独占 `<userData>/cache.db`，此时起任何新核都会
    /// `initialize cache-file: timeout`，**连切回 systemProxy 模式也起不来**——继续放行只会让用户撞上
    /// 一串无从归因的启动失败。报 [`code::ROOT_ORPHAN_BLOCKED`] 才指得出真正的动作。
    async fn escalate_root_orphans(&self, survivors: &[u32]) -> Result<(), StartError> {
        log::warn!(
            "{} 个孤儿核用户态杀不动（root 所有，EPERM）：{survivors:?} → 尝试经 helper 提权清扫",
            survivors.len()
        );
        // helper 未装 → 无提权腿，直接落终态（不假装尝试过）。
        if self.helper.status().installed {
            let helper = Arc::clone(&self.helper);
            // `cleanup_cores` 是同步阻塞 IPC → 挪出 async worker 线程（同 start_core/stop_core）。
            match tokio::task::spawn_blocking(move || helper.cleanup_cores()).await {
                Ok(Ok(())) => {
                    tokio::time::sleep(STALE_KILL_GRACE).await;
                    let still: Vec<u32> = survivors
                        .iter()
                        .copied()
                        .filter(|p| pid_alive(*p))
                        .collect();
                    if still.is_empty() {
                        log::info!("经 helper 提权清扫已清掉 root 孤儿核：{survivors:?}");
                        return Ok(());
                    }
                    // daemon 返成功但进程仍在 → 照实报，不采信回执（结果以探活为准）。
                    log::error!("helper 清扫返回成功，但 {still:?} 仍存活");
                }
                Ok(Err(e)) => log::error!("helper 提权清扫失败：{e}"),
                Err(e) => log::error!("helper 清扫任务 join 失败：{e}"),
            }
        } else {
            log::error!("helper 未安装 → 无提权腿可用，root 孤儿核 {survivors:?} 清不掉");
        }
        let msg = format!(
            "上次遗留的 sing-box 核（pid {survivors:?}）以管理员权限运行且无法清理，\
             它占用着内核缓存文件，任何模式都无法启动。请安装/修复 Helper 后重试，\
             或手动执行：sudo kill -9 {}",
            survivors
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(" ")
        );
        self.set_error(&msg, code::ROOT_ORPHAN_BLOCKED);
        Err(StartError::coded(msg, code::ROOT_ORPHAN_BLOCKED))
    }
}

/// **观测腿**：内核记账里该 pid 正在执行的可执行文件路径（读不到 → `None`）。
///
/// 这是[内核自证](ProxyRuntime::attest_running_core_binary)的**事实来源**，其价值全在于它与
/// 「app 请求了什么」完全独立 —— 问的是操作系统「这个进程实际是从哪个文件起来的」。
///
/// - **linux**：读 `/proc/<pid>/exe` 符号链接（内核直给，最硬的一手证据）。二进制在进程起来后被
///   替换/删除时内核会给出 `<路径> (deleted)`，此处剥掉该后缀还原原路径（否则恒判不等 = 假告警）。
/// - **macOS**：`ps -p <pid> -o comm=`（无 `/proc`；`comm` 给的是完整路径而非 16 字节的 `p_comm`
///   短名——2026-07-31 在 p101 以普通用户查 root helper 实测得到完整 46 字符路径）。
///   受保护核路径含空格，故 `comm=` 必须是**唯一**输出字段，整行即路径。
/// - **windows**：返 `None`（无低成本 std 途径；且 win 的核走 app 侧、无受保护核目录，
///   本自证在该平台的价值本就最小）。`None` ⇒ 判 `Unobservable` ⇒ 只 warn 不误报。
fn running_exe_path(pid: u32) -> Option<PathBuf> {
    // pid=0 = 调用方还没拿到真 pid（helper 未回传 / spawn 失败）→ 没有可观测对象。
    if pid == 0 {
        return None;
    }
    running_exe_path_impl(pid)
}

/// [`running_exe_path`] 的 linux 实现：`/proc/<pid>/exe` 符号链接（内核直给）。
#[cfg(target_os = "linux")]
fn running_exe_path_impl(pid: u32) -> Option<PathBuf> {
    let p = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    // 内核对「映像已被替换/删除」的进程追加 " (deleted)"，剥掉还原真实路径（否则恒判不等 = 假告警）。
    let s = p.to_string_lossy();
    Some(
        s.strip_suffix(" (deleted)")
            .map_or_else(|| p.clone(), PathBuf::from),
    )
}

/// [`running_exe_path`] 的 macOS 实现：`ps -p <pid> -o comm=`（无 `/proc`）。
#[cfg(target_os = "macos")]
fn running_exe_path_impl(pid: u32) -> Option<PathBuf> {
    let out = std::process::Command::new("/bin/ps")
        .args(["-p", &pid.to_string(), "-o", "comm="])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let line = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    // 进程已退出时 ps 可能成功但无输出 → 别把空串当成一个路径。
    (!line.is_empty()).then(|| PathBuf::from(line))
}

/// [`running_exe_path`] 的其余平台实现：无低成本 std 途径 → 恒 `None`（判 `Unobservable`，不误报）。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn running_exe_path_impl(_pid: u32) -> Option<PathBuf> {
    None
}

/// **观测腿**：对**磁盘上那个文件**跑一次 `sing-box version`，取原始第一行；失败恒空串。
///
/// 与 `UpdaterRuntime::read_core_version_line` 同一纪律：**探测失败绝不回落随包基线** ——
/// 那会把「读不到」伪装成「就是基线」，正是自证最不能犯的错。此处更严：空串在
/// [`attest_core_binary`](crate::runtime::core_promote::attest_core_binary) 里被判**告警**而非通过。
fn core_version_first_line(bin: &Path) -> String {
    match no_console_window(std::process::Command::new(bin).arg("version")).output() {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()
            .unwrap_or_default()
            .trim()
            .to_owned(),
        Ok(out) => {
            log::warn!(
                "{} version 非零退出 {:?}：版本行置空",
                bin.display(),
                out.status
            );
            String::new()
        }
        Err(e) => {
            log::warn!("{} version spawn 失败 {e}：版本行置空", bin.display());
            String::new()
        }
    }
}

/// 发信号给 pid（core-supervisor [`ProcessKiller`] 的注入点）。
///
/// unix：`nix::sys::signal::kill`（safe wrapper，本文件 `forbid(unsafe_code)` 下不可直接 libc FFI）。
#[cfg(unix)]
pub(crate) fn send_signal(pid: u32, sig: Signal) {
    use nix::sys::signal::{kill, Signal as NixSignal};
    let nix_sig = match sig {
        Signal::Sigterm => NixSignal::SIGTERM,
        Signal::Sigkill => NixSignal::SIGKILL,
    };
    // 对已退出进程为安全 no-op（ESRCH）——吞掉。非法 pid 直接不发（见 checked_pid）。
    if let Some(p) = checked_pid(pid) {
        let _ = kill(p, nix_sig);
    }
}

/// windows 无 POSIX 信号：两级均退化为 `taskkill /F /T`（对齐 上游 Windows 停核路径）。
/// **未在本机验证**（本批真机验证限 Linux）。
#[cfg(windows)]
pub(crate) fn send_signal(pid: u32, _sig: Signal) {
    let _ = no_console_window(std::process::Command::new("taskkill").args([
        "/PID",
        &pid.to_string(),
        "/F",
        "/T",
    ]))
    .output();
}

/// `u32` pid → `nix::Pid`，**只放行真实单进程 pid**（`1..=i32::MAX`），否则 `None`。
///
/// **为什么必须有（安全，非洁癖）**：`pid as i32` 对 `pid > i32::MAX` 会**回绕成负数**，而 POSIX
/// `kill` 的负数/零 pid 是**广播语义**：`-1` = 给「本用户有权发信号的所有进程」发，`0` = 给整个
/// 当前进程组发。落到 [`send_signal`] 就是 `SIGKILL` 全场——把 app 自己和用户所有进程一起杀掉。
/// 落到 [`pid_alive`] 则是 `kill(-1,0)` 恒 `Ok` → 任何越界 pid 都被判「存活」，孤儿清扫永远收不了尾。
#[cfg(unix)]
fn checked_pid(pid: u32) -> Option<nix::unistd::Pid> {
    (pid >= 1 && pid <= i32::MAX as u32).then(|| nix::unistd::Pid::from_raw(pid as i32))
}

/// `kill(pid, 0)` 的 errno → 存活判定（纯逻辑，穷举各 errno 语义；探活的真值在此）。
///
/// **判定方向恒为「无死亡证据即判存活」**——五个消费点（起核门 / 就绪门 / 崩溃监测 /
/// 停核升级 / 孤儿清扫）里，误判「死」全是破坏性的（虚报起核失败、无谓重启、漏发 SIGKILL），
/// 误判「活」最多多发一次信号（对已死进程是 no-op）。故只有确证不存在才判不活。
// nix 是 unix-only 依赖，故必须 cfg(unix)——`test` cfg 在 windows `cargo test` 也为真，
// 若含 test 会在 windows 编入却找不到 nix crate（E0433）。测试端一并 cfg(unix)。
#[cfg(unix)]
pub(super) fn alive_from_probe(r: Result<(), nix::errno::Errno>) -> bool {
    use nix::errno::Errno;
    match r {
        // 有权发信号且进程在 → 存活。
        Ok(()) => true,
        // **EPERM = 进程存在，只是不属本用户**（helper 以 root 起的核，app 以普通用户探活）。
        // 把它当「不存在」正是 TUN 提权路径下「helper 报告已启动但进程不存在」的根因。
        Err(Errno::EPERM) => true,
        // ESRCH = 内核确认无此进程 → 唯一的「不活」判据。
        Err(Errno::ESRCH) => false,
        // 其余 errno（EINVAL 等）非死亡证据 → 保守判活，绝不据此宣告核已崩。
        Err(_) => true,
    }
}

/// pid 是否存活（宽限期到点的二次确认，防 race 误杀）。
#[cfg(unix)]
pub(crate) fn pid_alive(pid: u32) -> bool {
    use nix::sys::signal::kill;
    // 非法 pid（0 / 越 i32 回绕）不是「不确定」而是「压根不是个进程」→ 判不活，且**绝不**让它
    // 走到 kill 的广播语义上去（见 [`checked_pid`]）。
    let Some(p) = checked_pid(pid) else {
        return false;
    };
    // signal 0 = 仅探活不发信号。
    alive_from_probe(kill(p, None))
}

/// **进程身份令牌**：回答「这个 pid 上挂的还是不是原来那个进程」。
///
/// # 为什么需要它
///
/// helper 腿（三平台的 TUN 一律经 helper，见 `should_start_via_helper`）没有本地 child 句柄，
/// 崩溃监测只能靠 [`pid_alive`] —— 而 `kill(pid, 0)` / Win32 探活只回答「这个号码上有进程吗」，
/// **不回答「是不是我那个」**。核死后 pid 被系统复用，探活恒真 ⇒ 崩溃自愈永不触发，
/// 用户看到 `running: true` 而代理全断。直起腿不受影响（`child.try_wait()` 认的是句柄不是号码）。
///
/// # 为什么不复用 [`running_exe_path`]
///
/// 它在本场景最需要的两个平台上取不到材料：linux 的 `/proc/<pid>/exe` 对 root / setuid 降权后的
/// 进程，普通用户读会 `EACCES`（helper 腿的核正是这两类）；windows 侧它恒 `None`。
///
/// # 各平台取什么（性质相同：**活着期间恒定不变，换了进程必不同**）
///
/// - **linux**：`/proc/<pid>/stat` 的 starttime（第 22 字段）。该文件**世界可读**，不受属主与
///   dumpable 影响 —— 正是 exe 那条路取不到时仍取得到的那一格。
/// - **macos**：`ps -p <pid> -o lstart=`（跨用户可读，同 [`running_exe_path`] 的 mac 腿）。
/// - **windows**：`OpenProcess + GetProcessTimes` 的创建时间。它比旧 `tasklist` 映像名更强（同名
///   进程复用 PID 也能识别），且不再为每次探活启动一个约 3.5s 的外部进程。
/// - **其余平台**：`None` ⇒ 判 [`PidIdentity::Unobservable`]，只跳过、**绝不**据此报崩溃。
pub(super) fn process_identity(pid: u32) -> Option<String> {
    // pid=0 = 还没拿到真 pid → 没有可观测对象（同 `running_exe_path` 的口径）。
    if pid == 0 {
        return None;
    }
    process_identity_impl(pid)
}

#[cfg(target_os = "linux")]
fn process_identity_impl(pid: u32) -> Option<String> {
    parse_proc_stat_starttime(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

#[cfg(target_os = "macos")]
fn process_identity_impl(pid: u32) -> Option<String> {
    let out = std::process::Command::new("/bin/ps")
        .args(["-p", &pid.to_string(), "-o", "lstart="])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let line = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    // 进程已退出时 ps 可能成功但无输出 → 别把空串当成一个令牌。
    (!line.is_empty()).then_some(line)
}

#[cfg(windows)]
fn process_identity_impl(pid: u32) -> Option<String> {
    crate::runtime::windows_process::creation_identity(pid)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn process_identity_impl(_pid: u32) -> Option<String> {
    None
}

/// `/proc/<pid>/stat` → starttime（第 22 字段，纯逻辑）。
///
/// **必须从最后一个 `)` 之后切**：第 2 字段 comm 被括号包着，且**可含空格与右括号**
/// （进程名由用户控制）⇒ 直接按空白切分会在这类进程上整体错位，取到一个恒变或恒不变的错字段。
/// 切完后首 token 是第 3 字段 state ⇒ starttime 是其中第 20 个（下标 19）。
#[cfg(any(target_os = "linux", test))]
pub(super) fn parse_proc_stat_starttime(stat: &str) -> Option<String> {
    let tail = &stat[stat.rfind(')')? + 1..];
    tail.split_whitespace().nth(19).map(str::to_owned)
}

/// pid 身份复核的三态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PidIdentity {
    Match,
    Mismatch,
    Unobservable,
}

/// 基线令牌 × 当前令牌 → 三态（纯逻辑）。
///
/// **「没观测到」绝不折成「不匹配」**：取不到材料（平台不支持 / 读失败 / 进程刚好在这一刻消失）
/// 一律 [`PidIdentity::Unobservable`]。折成 `Mismatch` 会把一次读失败变成一次**假崩溃**，
/// 而假崩溃的下游是自动重启 —— 本仓在 `running_exe_path` 那条自证腿上写过同一句：
/// 没观测到 ≠ 观测到没问题。
pub(super) fn pid_identity_verdict(baseline: Option<&str>, current: Option<&str>) -> PidIdentity {
    match (baseline, current) {
        (Some(a), Some(b)) if a == b => PidIdentity::Match,
        (Some(_), Some(_)) => PidIdentity::Mismatch,
        _ => PidIdentity::Unobservable,
    }
}

#[cfg(windows)]
pub(crate) fn pid_alive(pid: u32) -> bool {
    crate::runtime::windows_process::is_alive(pid)
}
