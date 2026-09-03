//! 崩溃自愈 owner：后台崩溃监测腿（世代 + pid 身份双判据）、退避重启执行体、GiveUp 终态播报，
//! 以及「观察之后才读世代」的分类 seam 与「不可恢复重启错误」谓词。

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use polaris_core_supervisor::{
    classify_child_exit, AutoRestartOutcome, ChildObservation, CrashRecoveryMachine,
    ExitClassification, FailureOutcome, LifecycleGate, RestartFate,
};

use crate::runtime::helper::ManagedCoreStatus;

use super::code;
use super::lifecycle::monotonic_now_ms;
use super::process_supervision::{pid_alive, pid_identity_verdict, process_identity, PidIdentity};
use super::route_replan::RuntimeBindingState;
use super::startup::with_helper_gate_suppressed;
use super::{ProxyRuntime, StartError};

/// 崩溃监测轮询间隔（ms）。tokio `Child::wait()` 单持有者 → 监测只能轮询 `try_wait`（见
/// `spawn_crash_monitor`）；1s 与健康检查同量级，CPU 可忽略，崩溃检出延迟 ≤1s。
pub(super) const CRASH_MONITOR_POLL_MS: u64 = 1_000;

/// helper 腿的 pid **身份**复核间隔（单位：tick，1 tick = [`CRASH_MONITOR_POLL_MS`]）。
///
/// 不每 tick 复核：macOS 身份取材要 spawn `ps`；Windows 虽已改成原生句柄查询，也没有必要
/// 每秒重复读创建时间。10s 的检出延迟对一件**今天永远检不出**的事是纯增量，不是折衷
///（见 [`process_identity`]）。
pub(super) const PID_IDENTITY_RECHECK_TICKS: u64 = 10;

/// 用**观察完成后的最新世代**区分主动停核与崩溃。
///
/// helper 核的观察腿会做 Windows 进程身份查询；这段同步查询虽没有 `.await`，但在多线程 runtime
/// 上仍可能与另一 worker 上的 `stop()` 并行。若在查询**之前**缓存世代，时序会变成：读到旧世代 →
/// 用户 stop 先 bump 并停核 → 身份查询回报退出 → 拿旧世代误判 Crash，最终把用户刚停掉的 TUN
/// 又由崩溃自愈拉起。把世代读取封在分类点，复用 [`classify_child_exit`] 的既有判据，同时封死这条
/// stale-snapshot 窗口。
pub(super) fn classify_observed_child_exit(
    gate: &LifecycleGate,
    my_generation: u64,
    observation: ChildObservation,
) -> ExitClassification {
    classify_child_exit(my_generation, gate.generation(), observation)
}

impl ProxyRuntime {
    /// 挂后台崩溃监测任务（上游 `singboxProcess.on('exit')` → `handleProcessExit` 的等价物）。
    ///
    /// **为何是轮询而非 `child.wait()`**：tokio `Child::wait()` 需 `&mut self` 单持有者，而主动停止
    /// 路径（`kill_core`）已经持有并 `wait()` 那个句柄 → 崩溃监测不能也去 `wait()`，只能短暂持锁
    /// `try_wait` 观察。轮询绝不跨 await 持 `child` 锁（否则 !Send 编译即拒 + 与 `kill_core` 抢锁）。
    ///
    /// **主动 vs 意外的区分**（本任务最易出 bug 处）：完全靠 `LifecycleGate` 世代。
    /// `stop`/`restart` 入口必先 `bump_generation()` 再杀核 → 世代一变本监测即 `Retire`，
    /// 主动杀核的 SIGTERM/SIGKILL 绝不会被误判成崩溃。判据见 [`classify_child_exit`]。
    pub(super) fn spawn_crash_monitor(self: &Arc<Self>, my_gen: u64) {
        let me = Arc::clone(self);
        tokio::spawn(async move {
            // helper 腿的 pid 身份基线：`(基线取自哪个 pid, 令牌)`。见 [`process_identity`]。
            let mut identity: Option<(u32, String)> = None;
            let mut identity_unobservable_logged = false;
            let mut ticks: u64 = 0;
            loop {
                tokio::time::sleep(Duration::from_millis(CRASH_MONITOR_POLL_MS)).await;
                ticks += 1;
                // 观察核存活。C6-5：helper 核无本地 child 句柄 → 若按 child 观察必得 `Absent`→`Retire`
                //（永不自愈）。改用 pid 探活（对齐 上游 健康检查 `isProcessAlive(activePid)`）：pid 死=崩溃。
                // 直起路径仍走 child.try_wait（仅短暂持锁，绝不跨 await）。
                //
                // **pid 探活只回答「这个号码上有进程吗」**，不回答「是不是我那个」⇒ 核死后号码被复用
                // 时它恒真、崩溃自愈永不触发。故每 `PID_IDENTITY_RECHECK_TICKS` 个 tick 复核一次
                // 进程身份令牌（[`process_identity`]），换人即判退出。
                let observation = if me.core_via_helper.load(Ordering::SeqCst) {
                    match me.pid.lock().ok().and_then(|g| *g) {
                        Some(p) => {
                            if !pid_alive(p) {
                                ChildObservation::Exited
                            } else {
                                // 基线：首次观测到存活时取一次；记账换了 pid（新会话写了 `self.pid`）则重取，
                                // **不**拿旧 pid 的令牌去比新 pid（那会是一次必然的假不匹配）。
                                if identity.as_ref().is_none_or(|(bp, _)| *bp != p) {
                                    identity = process_identity(p).map(|tok| (p, tok));
                                    if identity.is_none() && !identity_unobservable_logged {
                                        identity_unobservable_logged = true;
                                        log::warn!(
                                            "崩溃监测：取不到 pid={p} 的进程身份令牌 → \
                                             本代只按 pid 探活（pid 复用不可发现）"
                                        );
                                    }
                                }
                                let due = ticks.is_multiple_of(PID_IDENTITY_RECHECK_TICKS);
                                let verdict = if due {
                                    pid_identity_verdict(
                                        identity.as_ref().map(|(_, t)| t.as_str()),
                                        process_identity(p).as_deref(),
                                    )
                                } else {
                                    PidIdentity::Match
                                };
                                if verdict == PidIdentity::Mismatch {
                                    log::warn!(
                                        "崩溃监测：pid={p} 的进程身份令牌已变 ⇒ 受管核实际已退出、\
                                         该号码被系统复用（探活恒真是假象）"
                                    );
                                    ChildObservation::Exited
                                } else if identity.is_none() || verdict == PidIdentity::Unobservable
                                {
                                    // Windows 标准权限 app 无法读取 SYSTEM child 的身份/退出码；本地探活
                                    // 会按“未知即存活”长期误报。向同权限边界内的 helper 查询权威状态。
                                    // 同步管道/socket IPC 必须移出 Tokio worker；通信失败不等于核已死，
                                    // 保守沿用刚得到的本地存活观察，等待下一 tick 重试。
                                    let helper = Arc::clone(&me.helper);
                                    match tokio::task::spawn_blocking(move || {
                                        helper.managed_core_status()
                                    })
                                    .await
                                    {
                                        Ok(Ok(ManagedCoreStatus::Stopped)) => {
                                            ChildObservation::Exited
                                        }
                                        Ok(Ok(ManagedCoreStatus::Running { pid })) if pid == p => {
                                            ChildObservation::Alive
                                        }
                                        Ok(Ok(ManagedCoreStatus::Running { pid })) => {
                                            log::warn!(
                                                "崩溃监测：app 记账 pid={p}，helper 受管 pid={pid} ⇒ \
                                                 当前世代的核身份已失配"
                                            );
                                            ChildObservation::Exited
                                        }
                                        Ok(Err(error)) => {
                                            if ticks == 1
                                                || ticks.is_multiple_of(PID_IDENTITY_RECHECK_TICKS)
                                            {
                                                log::warn!(
                                                    "崩溃监测：helper 权威状态暂不可用（{error}）→ \
                                                     本 tick 保守按本地存活，后续重试"
                                                );
                                            }
                                            ChildObservation::Alive
                                        }
                                        Err(error) => {
                                            log::warn!(
                                                "崩溃监测：helper 状态任务异常（{error}）→ \
                                                 本 tick 保守按本地存活，后续重试"
                                            );
                                            ChildObservation::Alive
                                        }
                                    }
                                } else {
                                    ChildObservation::Alive
                                }
                            }
                        }
                        // pid 已被清（停核/让位收口）→ 视作退场，非崩溃。
                        None => ChildObservation::Absent,
                    }
                } else {
                    let mut guard = match me.child.lock() {
                        Ok(g) => g,
                        Err(e) => {
                            log::error!("崩溃监测：child lock poisoned: {e} → 退场");
                            return;
                        }
                    };
                    match guard.as_mut() {
                        None => ChildObservation::Absent,
                        Some(c) => match c.try_wait() {
                            Ok(None) => ChildObservation::Alive,
                            // 已退出（收割）或探活出错 → 保守当已退出。
                            Ok(Some(_)) | Err(_) => ChildObservation::Exited,
                        },
                    }
                };
                // 世代必须在观察**之后**读取：Windows 的进程身份查询可能与另一 worker 上的 stop 并行；
                // 查询前缓存会把主动停核后的 Exited 配上旧世代，误判 Crash 并自动拉回 TUN。
                match classify_observed_child_exit(&me.gate, my_gen, observation) {
                    ExitClassification::KeepWatching => {}
                    // 主动 stop/restart 接管（世代变 / 句柄被取）→ 退场，不触发自愈。
                    ExitClassification::Retire => return,
                    ExitClassification::Crash => {
                        log::warn!(
                            "检测到 sing-box 意外退出（世代 {my_gen} 未变、非主动停止）→ 触发崩溃自愈"
                        );
                        // C5：核意外退出 → TS 内核接口已随进程消失、其 ifscope 路由自动失效 → 同步复位内存态
                        // （不发删命令，防对已消失接口误删主表）。自愈重启后由 start_inner 就绪后 reconcile 重建。
                        me.mesh.exit_route_reset_state().await;
                        // 核已死 → 停通用网络 watcher；自愈重启后由 start_inner 重起。
                        me.stop_network_watcher();
                        if let Ok(mut state) = me.runtime_binding_state.lock() {
                            *state = RuntimeBindingState::default();
                        }
                        // A3：核已死 → STATUS 流失效 → 清 TS 状态末帧缓存（本 relay 亦随后由世代守卫退场）。
                        me.mesh.clear_ts_status();
                        // VPN 原生认证挑战同样随核会话失效，禁止自愈后继续提交旧 challengeID。
                        me.mesh.clear_vpn_status();
                        // A4：核已死 → 复位登录期出口让位内存态 + 撤 UI。自愈重启后由 start_inner 预置重建。
                        me.reset_login_fallback_state();
                        // R2：核已死 → 复位 TS 出口无效直判的翻转对账缓存（新会话首帧须能重新触发
                        // none→blocked）。**恢复腿的单飞令牌不在此清**——它归在飞任务的 Drop 归还，
                        // 见 `reset_ts_exit_block_state` 文档。
                        me.reset_ts_exit_block_state();
                        me.run_crash_recovery().await;
                        return; // 自愈成功会起新核 + 新监测；失败/放弃则本核生命周期终结。
                    }
                }
            }
        });
    }

    /// 崩溃自愈执行体：决策全在 [`CrashRecoveryMachine`]（退避 / 上限 / 让位 / 补发），本方法只执行
    /// 「退避 sleep + restart」的 I/O，并把结果反馈回状态机（上游 `attemptAutoRestart` 的 I/O 侧）。
    ///
    /// **绝不无限重启**：`should_auto_restart` 达 `MAX_RESTART_COUNT`(3) → `GiveUp` → 报错并退场；
    /// 60s 冷却窗口内计数不复位（紧密崩溃循环必收敛到 GiveUp）。
    async fn run_crash_recovery(self: &Arc<Self>) {
        // 崩溃时用的配置：优先 last-applied（current_config），回落磁盘最新配置。
        let cfg = self
            .current_config
            .read()
            .ok()
            .and_then(|g| g.clone())
            .or_else(|| self.config.current().ok());
        let Some(cfg) = cfg else {
            let msg = "sing-box 意外退出，且无可用配置重启 → 放弃自愈".to_string();
            log::error!("{msg}");
            self.set_error(&msg, code::PROCESS_EXITED);
            return;
        };

        loop {
            let outcome = {
                let mut m = self.crash_lock();
                // M-2′-G1：喂 handle_crash **真实的在途腿世代**（此前硬编码 `None`）。缺此，接管会话
                // （新代核）崩溃永不置 `crash_while_superseded` → 让位腿 replay=false → 新代核崩溃无人接管。
                // 单锁内读 getter + 决策（seam `drive_crash_decision`），绝不 TOCTOU（两次取锁间被改）。
                drive_crash_decision(&mut m, monotonic_now_ms(), self.gate.generation())
            };
            match outcome {
                AutoRestartOutcome::GiveUp => {
                    // GiveUp 有两种成因，文案必须分开：换核验证窗口下这是**第一次**崩溃，
                    // 报「已达自愈上限（3 次/60s）」是字面为假。这条 message 是诊断载荷，
                    // 会进脱敏日志成为下次排查的起点；UI 只消费结构化码的本地化文案。
                    // 码沿用 `AUTO_RESTART_FAILED`（我们确实放弃了自动重启），不新增码：
                    // 新码要同步前端 `ProxyErrorCode` 与 5 份 locale，而这里的信息差在文案不在分类。
                    let msg = if self.crash_lock().auto_restart_suppressed() {
                        "新内核首次运行即异常退出（换核验证窗口内不自动重启）→ 将尝试回滚到原内核"
                            .to_string()
                    } else {
                        "sing-box 反复崩溃，已达自愈上限（3 次/60s）→ 放弃自动重启".to_string()
                    };
                    log::error!("{msg}");
                    self.set_error(&msg, code::AUTO_RESTART_FAILED);
                    return;
                }
                // 已有重启腿在途 / 用户已停 → 静默退场。
                AutoRestartOutcome::Dedup | AutoRestartOutcome::AbortedByUser => return,
                AutoRestartOutcome::Attempt {
                    attempt,
                    backoff,
                    generation,
                } => {
                    log::warn!("崩溃自愈：第 {attempt} 次尝试，退避 {backoff:?} 后重启");
                    tokio::time::sleep(backoff).await;
                    let fate = self
                        .crash_lock()
                        .post_backoff(generation, self.gate.generation());
                    match fate {
                        RestartFate::AbortedByUser => {
                            log::info!("崩溃自愈：退避期间用户已主动停止 → 放弃重启");
                            return;
                        }
                        RestartFate::Superseded { replay } => {
                            if replay {
                                log::info!("崩溃自愈：让位，但接管腿也崩溃 → 补发一次");
                                continue;
                            }
                            log::info!("崩溃自愈：退避期间被更新的 start/stop 接管 → 让位");
                            return;
                        }
                        // 非交互（上游 `start(cfg, {interactive:false})`）：崩溃自愈是**用户没做任何
                        // 操作**时自动发生的，此处弹系统授权框 = 凭空索要管理员密码，且崩溃循环里最多
                        // 连弹 MAX_RESTART_COUNT 次。抑制后退回类型化终态，待用户手动启停时经门引导。
                        RestartFate::Start => {
                            match with_helper_gate_suppressed(self.restart(cfg.clone())).await {
                                Ok(st) if st.running => {
                                    let _ = self.crash_lock().post_start(false);
                                    log::info!("崩溃自愈：重启成功（新 pid={}）", st.pid);
                                    return; // 新核已挂新监测。
                                }
                                // 就绪等待期被接管 → 让位，不报成功（lastStartSuperseded）。
                                Ok(_) => {
                                    let _ = self.crash_lock().post_start(true);
                                    log::info!("崩溃自愈：重启就绪期被接管 → 让位");
                                    return;
                                }
                                Err(e) => {
                                    log::error!("崩溃自愈：重启失败: {e}");
                                    // 不可恢复错误（helper 缺失/用户取消提权门 → 按码；权限/root 残留/
                                    // clash_api 端口占用 → 按 message 关键字）→ 立即终态放弃，不再空耗退避
                                    // （上游 isUnrecoverableRestartError，:6039/:6043）。整个 `e` 而非只
                                    // `e.message`：码腿要读 `e.code`，见 is_unrecoverable_restart_error 文档。
                                    let unrecoverable = is_unrecoverable_restart_error(&e);
                                    match self.crash_lock().post_start_failure(unrecoverable) {
                                        FailureOutcome::GiveUp => {
                                            self.report_auto_restart_giveup(&e);
                                            return;
                                        }
                                        // 未达上限 → 自循环再试一次（下一轮 attempt 内按计数退避）。
                                        FailureOutcome::Retry => continue,
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// 崩溃自愈 **GiveUp 腿的终态播报**：本次失败没有更具体的码时才补发 [`code::AUTO_RESTART_FAILED`]。
    ///
    /// **修的是什么**：`run_helper_gate` 非交互腿（:1513-1516）自己就 `set_error(HELPER_NOT_INSTALLED)`
    /// 发过一条，回 `Err` 后 [`is_unrecoverable_restart_error`] 判终态 → `post_start_failure(true)`
    /// 返 `GiveUp` → 此处再叠一条 `AUTO_RESTART_FAILED`。**两条码各自在前端触发 `toast.error` +
    /// `notifyDesktop`，且这两腿无人 `await` ⇒ 认领闸门不抑制** ⇒ 用户背靠背吃 2 toast + 2 桌面通知。
    ///
    /// **判据 = [`StartError::code`]，不是回读全局 `status().error_code`**：本文件 8 处
    /// `StartError::coded` 构造点（:1516/:1523/:1540/:1547/:1668/:1704/:1755/:1771）无一例外**紧邻**
    /// 一条同码同文案的 `self.set_error(..)`，而无码腿（`From<String>` 零成本升格的
    /// `.map_err(|e| format!(..))?`）**一条都不 set_error** ⇒ `code.is_some()` ⟺「本次失败已播报过更
    /// 具体的分类」。回读全局则会踩 A1 同款陈旧读（全局 `error_code` 只有 `stop()` 会清、多条腿根本
    /// 不写），理由见 `commands/proxy.rs::start_err_response` 文档。
    ///
    /// **刻意不修过头**：无码腿（config 解析/生成/建目录/写盘失败等）**必须**照常发
    /// `AUTO_RESTART_FAILED` —— 否则崩溃自愈放弃时前端一条提示都收不到，「静默」比「双报」更坏。
    pub(super) fn report_auto_restart_giveup(&self, e: &StartError) {
        if let Some(code) = e.code {
            // 已有更具体的终态码在前 → 只留日志，不叠发第二条事件。
            log::error!(
                "sing-box 崩溃自愈重启失败且达上限 → 放弃：{e}（已按 {code} 播报，不叠发）"
            );
            return;
        }
        let msg = format!("sing-box 崩溃自愈重启失败且达上限 → 放弃：{e}");
        self.set_error(&msg, code::AUTO_RESTART_FAILED);
    }

    /// 短暂借出崩溃自愈状态机（决策同步、单语句用完即释；**绝不跨 await 持锁**）。
    pub(super) fn crash_lock(&self) -> std::sync::MutexGuard<'_, CrashRecoveryMachine> {
        self.crash_recovery
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// 崩溃自愈决策 seam（`run_crash_recovery` 与其单测共用）：读机内在途腿世代 → 喂 `handle_crash`。
///
/// **为什么抽 seam**：`run_crash_recovery` 是重 I/O（退避 sleep + 真起核 = 真机门），其「把在途世代喂给
/// `handle_crash` 而非 `None`」这条 wiring 无法零进程单测。抽成纯 seam 后，`drive_crash_decision_feeds_
/// real_inflight_gen`（proxy 测）可确定性验：把 `m.restarting_gen()` 换回 `None` → replay 恒 false → 转红。
pub(super) fn drive_crash_decision(
    m: &mut CrashRecoveryMachine,
    now_ms: u64,
    current_generation: u64,
) -> AutoRestartOutcome {
    // M-2′-G1：真实在途腿世代（无在途腿 → None）。此前上层硬编码 None → 接管会话崩溃永不置补发标记。
    let inflight_gen = m.restarting_gen();
    m.handle_crash(now_ms, current_generation, inflight_gen)
}

/// 崩溃自愈重启失败是否「不可恢复」→ 立即终态放弃（不再空耗退避）。移植 上游
/// `isUnrecoverableRestartError`（:6039）。
///
/// **码优先，keyword 兜底 —— 两条腿都留，不是二选一**：
///
/// 1. **码腿（新）**：[`StartError::code`] 是判定点在**控制流位置**诚实断言出来的（见 [`code`] 模块
///    文档），比事后猜 message 关键字可靠。[`code::HELPER_GATE_ABORTED`]（用户刚亲口说了「不装」）与
///    [`code::HELPER_NOT_INSTALLED`]（前置条件缺失；非交互自愈下 `run_helper_gate` 连引导都不弹，
///    :1511-1514 直接落此码）两者**重试多少轮都不会自己变好**，故立即终态。
///
///    此前只有 keyword 腿时，这两条腿实际落在错误里的是中文文案 [`HELPER_GATE_ABORTED_MSG`](super::HELPER_GATE_ABORTED_MSG) /
///    [`HELPER_NOT_INSTALLED_MSG`](super::HELPER_NOT_INSTALLED_MSG)，**不命中下方任何一个关键词**（"提权助手，"≠"提权助手不可用"，
///    "提权 helper"里也没有"权限"）⇒ helper 缺失/用户取消时崩溃自愈会白烧满 `MAX_RESTART_COUNT`(3)
///    轮退避才放弃。
///
/// 2. **keyword 腿（原）**：覆盖**没有码**、以及**有码但码本身不表达终态性**的错误形态。
///    **为什么有码也仍要走这条腿**（而不是 `if let Some(c) = code { return matches!(c, ...) }`）：
///    spawn launch 失败腿把**原始 OS 错误**格式化进 message 后贴 [`code::STARTUP_FAILED`]
///    （:1699-1702），EACCES 的 "Permission denied" 正是从那儿来的。若「有码即跳过 keyword」，权限
///    拒绝会退回「烧满 3 轮退避 ~22s」—— 正是 keyword 腿当初要修的那个缺陷。
///
/// 故本函数是既有行为的**严格超集**：只新增 `true`，绝不把原本 `true` 的判成 `false`。瞬态失败
/// （起核超时 / 启动期退出 / 端口资源竞态）两条腿都不命中 ⇒ 照常重试。
pub(super) fn is_unrecoverable_restart_error(err: &StartError) -> bool {
    // 码腿：控制流位置诚实断言出的确定性终态。
    let coded_terminal = err
        .code
        .is_some_and(|c| c == code::HELPER_GATE_ABORTED || c == code::HELPER_NOT_INSTALLED);
    coded_terminal || is_unrecoverable_restart_message(&err.message)
}

/// [`is_unrecoverable_restart_error`] 的 message 关键字腿（权限/提权助手不可用/root 残留/clash_api
/// 端口占用等确定性失败，重试无意义）。CJK 字符 `to_lowercase` 为恒等（无大小写），ASCII 关键词经
/// 小写归一后匹配（如 "Permission denied"）。
pub(super) fn is_unrecoverable_restart_message(message: &str) -> bool {
    let m = message.to_lowercase();
    m.contains("权限")
        || m.contains("permission")
        || m.contains("helper_gate_aborted")
        || m.contains("提权助手不可用")
        || m.contains("提权助手引导")
        || m.contains("root_orphan_blocked")
        || m.contains("root 残留")
        || m.contains("clash_api_port_busy")
        || m.contains("clash_api 端口")
}
