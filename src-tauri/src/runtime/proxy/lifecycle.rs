//! 生命周期 owner：起停重启三入口（`start` / `stop` / `restart`）与它们的内部腿、世代 bump 与
//! 「可被世代变更中断的等待」原语、`LifecycleGate` 收尾（`finish_lifecycle`）、去抖重启排程、
//! 错误终态（致命 / 非致命）与状态读投影，以及 `event:proxyLifecycle` 载荷与在飞起核计数守卫。
//!
//! **`start_inner` 不在本模块**：它按 §A 归 `startup.rs`（B9），当前仍在 façade；`start` 以
//! `self.start_inner(..)` 调用它，façade 的私有方法对本后代模块天然可见，B9 搬走时本模块零改动。

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::sync::Notify;

use polaris_config_engine::builder::InvalidNode;
use polaris_config_engine::user_config::app_config::UserConfig;
use polaris_config_engine::user_config::ProxyModeType;
// LifecycleEndResult 未在 crate root 再导出（其兄弟类型 LifecycleGate/LifecycleKind 有）→ 走模块路径。
use polaris_core_supervisor::lifecycle_gate::LifecycleEndResult;
use polaris_core_supervisor::{LifecycleGate, LifecycleKind};
use polaris_stats_engine::DiagnosticCounters;
use polaris_switch_engine::DebouncedOutcome;

use super::route_replan::RuntimeBindingState;
use super::system_takeover::should_clear_system_proxy_between_restart;
use super::{ProxyRuntime, ProxyStatus, StartError};

/// `event:proxyLifecycle` 的载荷：**这一次核起停尝试的真实结局**。
///
/// # 三个 phase 的判据（都是可诚实断言的控制流位置，不猜）
///
/// - `ready` —— [`ProxyRuntime::start`] 成功收口（核已就绪、系统接管腿已落定、起核在飞计数已归还）。
/// - `stopped` —— [`ProxyRuntime::stop_inner`] 拆除腿（`startup_snapshot` 已清）。
/// - `failed` —— [`ProxyRuntime::start`] 包装的 `Err` 腿（**全部**起核入口的唯一汇流点）。
///
/// # 为什么载荷里**没有** pid / 起始时刻
///
/// 那两个的单一真值是 [`ProxyStatus`]（`proxy:getStatus`）。塞进事件载荷等于再造一份镜像，
/// 而这类镜像的失效方式恰恰是**静默**的（同 `ProxyErrorEmitter::privacy_mode` 头注那段因果）。
/// 故本载荷只带「结局」这一位判据，pid / 已运行时长由订阅方照既有范式回拉一次
/// （`App.tsx` 收到即 `refreshProxyStatus()`，与它对 `proxyStarted` 的做法逐字一致）。
/// 代价是每次跃迁多一次**本机** IPC。
///
/// `error_code` / `message` 仅 `failed` 腿非空，且与 [`ProxyRuntime::set_error`] 落的码**同源**
/// （都取自 [`StartError`]）—— 同一次失败对 `event:proxyError` 与本通道必须是同一个分类。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyLifecycleEvent {
    pub phase: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl ProxyLifecycleEvent {
    /// 核已就绪（无失败信息）。
    pub(super) fn ready() -> Self {
        Self {
            phase: "ready",
            error_code: None,
            message: None,
        }
    }

    /// 核已停（无失败信息）。
    pub(super) fn stopped() -> Self {
        Self {
            phase: "stopped",
            error_code: None,
            message: None,
        }
    }

    /// 本次起核失败，带上可诚实断言的分类与用户可见文案。
    pub(super) fn failed(err: &StartError) -> Self {
        Self {
            phase: "failed",
            error_code: err.code.map(str::to_string),
            message: Some(err.message.clone()),
        }
    }
}

/// 在飞起核计数守卫：`start` 的任一出口（Ok / Err / `?` 早退 / panic 展开）都归还计数，
/// 杜绝「计数卡死 → `ProxyStatus::starting` 永久为真 → 连接按钮永远显示成取消」。
struct InflightGuard(Arc<AtomicU32>);
impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// **可被「世代变更」中断的等待** —— 起核腿一切阻塞点的唯一等待原语。
///
/// 返回 `true` = 本腿已被接管（用户点了停止 / 更新的 start 抢占），调用方应立即走让位腿；
/// `false` = 睡满 `dur` 且本腿仍当权。
///
/// # 为什么不能只在迭代边界判世代（本函数存在的全部理由）
///
/// 让位检查点（spawn 前持锁判 / 就绪门 `is_superseded` / Dead·Timeout 世代复查 / 就绪后复查）本身是
/// 齐的，但它们**只在两次等待之间执行**。真机事故里起核连续 FATAL、每轮在退避 sleep 上停 2s/4s，
/// 用户此时点停止：`stop` 确实 bump 了世代，可在飞的起核腿还躺在 `tokio::time::sleep` 里 —— 取消
/// 要静默等本轮睡满才生效。「后端理论上可取消」与「点了立刻停」之间差的就是这一层：**等待本身必须
/// 可中断**，而不是等待结束后才发现该走了。
///
/// # 边沿不丢（`notify_waiters` 无 permit 的正确用法）
///
/// [`Notify::notify_waiters`] 只唤醒**此刻已注册**的等待者、不留 permit。故顺序必须是
/// 「`enable()` 注册 → 复查世代 → select」：
/// - 注册**之后**的 bump → 由 `notified` 分支捕获；
/// - 注册**之前**的 bump → 由复查捕获（世代是单调递增的持久事实，不像信号会过期）。
///
/// 两侧夹住，任何时刻的 bump 都至少被一条腿看见。把复查删掉、或挪到 `enable()` 之前，都会开出一个
/// 「信号已发但没人在听、世代却已变」的漏判窗口 —— 那正是回归成「等睡满」的形态。
///
/// 唤醒后仍以 `gate.generation()` 复判（**信号只是提醒，世代才是判据**）：即便将来出现无关唤醒，
/// 也只会退化成「多醒一次继续睡」，不会误判让位。
pub(super) async fn sleep_unless_superseded_on(
    gate: &LifecycleGate,
    gen_changed: &Notify,
    my_gen: u64,
    dur: Duration,
) -> bool {
    let notified = gen_changed.notified();
    tokio::pin!(notified);
    // 先注册（`enable()` 只登记兴趣、不等待），**再**复查世代。两步顺序不可颠倒，也不可只留一步：
    // 少了 `enable()` 就漏掉复查之后的 bump；少了复查就漏掉注册之前的 bump（信号已丢、世代还在）。
    // 刻意**不**在此之前再加一道「快速路径」复查：那会把这一道遮住，让删掉它的变异测不出来
    // （实测如此）—— 一道说得清、测得到的门，胜过两道互相掩护的门。
    notified.as_mut().enable();
    if gate.generation() != my_gen {
        return true;
    }
    tokio::select! {
        () = tokio::time::sleep(dur) => {}
        () = notified => {}
    }
    gate.generation() != my_gen
}

/// 当前 epoch 毫秒（喂崩溃自愈状态机的冷却/退避时间轴）。
pub(super) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// 当前进程内的单调毫秒刻度。只用于持续时间、冷却和退避；展示/持久化时间戳继续走 [`now_ms`]。
///
/// `Instant` 不受系统时间、NTP 或用户手动校时影响。刻度从本进程第一次调用起算，因此消费它的状态机
/// 必须以 `Option` 表示“尚未记录”，不能再把 0 同时当哨兵与合法刻度。
pub(super) fn monotonic_now_ms() -> u64 {
    static EPOCH: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    EPOCH
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

impl ProxyRuntime {
    /// 置「换核验证窗口」抑制位（上游 `setAutoRestartSuppressed`）。
    ///
    /// 窗口内核**意外退出不自动重启**：让首次失败立刻上报，而不是在坏核上退避空转 3 次 ——
    /// 空转会把「新核有问题」这个信号淹掉，而那正是换核验证唯一要采集的信息。
    ///
    /// 唯一调用方是换核验证守护腿（`commands::updater` 的 `arm_core_validation`），
    /// 置起与撤下成对；撤下后老核照常受崩溃自愈保护。判据本体在
    /// [`CrashRecoveryMachine::should_auto_restart`](polaris_core_supervisor::CrashRecoveryMachine::should_auto_restart)。
    pub fn set_auto_restart_suppressed(&self, suppressed: bool) {
        self.crash_lock().set_auto_restart_suppressed(suppressed);
    }

    /// 当前状态快照（上游 `proxy:getStatus`）。
    ///
    /// `uptime` 在此**现算**（`now - start_time`，秒）而非读存储值：存储的 uptime 写于起核那一刻，
    /// 读可能在几小时后 → 存了必假。见 [`ProxyStatus`] 文档。
    pub fn status(&self) -> ProxyStatus {
        let mut snap = self.status.read().map(|g| g.clone()).unwrap_or_default();
        snap.uptime = snap
            .start_time
            .map(|t0| now_ms().saturating_sub(t0) / 1_000);
        // 读时投影（同 uptime）：起核腿在飞 ⇒ starting=true。存储态恒 false，故读这一处即全部真值。
        snap.starting = self.start_inflight.load(Ordering::SeqCst) > 0;
        snap
    }

    /// 运行中主核所用的用户配置快照（`current_config`）。Tailscale 瞬态登录去重守卫用：
    /// 判该 TS 节点是否已在运行主核里（双写防护 `tailscale_endpoint_in_running_core`）。
    /// 核未跑时 `current_config` 可能仍留上次配置 → 调用方须结合 `status().running` 短路。
    pub(crate) fn current_config_snapshot(&self) -> Option<Value> {
        self.current_config.read().ok().and_then(|g| g.clone())
    }

    /// 当前**运行核快照**里的接管模式；与磁盘 `config.current()` 刻意分离。
    ///
    /// 结构性切换会先把磁盘期望值改成新模式，再去抖重启旧核。系统代理活态若读磁盘值，就会在
    /// “新配置=systemProxy、旧运行核仍=TUN”窗口里去查 OS 代理并误判未生效。旧核唯一可信真值是
    /// `startup_snapshot`：结构重启的 `apply_restart` 会在去抖前先把 `current_config` 前推到新配置，
    /// 而起核快照只在新核真正就绪时换代、停核时清空。模式本身是结构字段，热切/no-op 不会改变它。
    pub(crate) fn running_proxy_mode_type(&self) -> Option<ProxyModeType> {
        if !self.core_running() {
            return None;
        }
        self.startup_snapshot
            .read()
            .ok()
            .and_then(|snapshot| snapshot.clone())
            .and_then(|config| serde_json::from_value::<UserConfig>(config).ok())
            .map(|config| config.proxy_mode_type)
    }

    /// 诊断两轴计数快照（喂给 `diagnostic_export` 报告，维度7 #11）。
    ///
    /// - **慢起轴** `last_start_ready_retries`：本运行时在就绪门累计（`wait_ready` 的
    ///   begin_start → on_retry→record_retry → finish_start）。
    /// - **核崩轴** `restart_count`：从 [`CrashRecoveryMachine`](polaris_core_supervisor::CrashRecoveryMachine) **读时投影**（单一真值，不在本地并行记）。
    ///
    /// 两轴各自单一来源、在此合并成一份快照——这也是它俩「不撞车」的收口点：慢起来自 `diagnostics`，
    /// 核崩来自 `crash_recovery`，永不互相写入。
    #[must_use]
    pub fn diagnostic_counters(&self) -> DiagnosticCounters {
        let mut snap = *self.diag_lock();
        snap.restart_count = self.crash_lock().restart_count();
        snap
    }

    /// 核是否运行（`singboxProcess || singboxPid` 等价，上游 :1736）。
    pub(super) fn core_running(&self) -> bool {
        self.status.read().map(|g| g.running).unwrap_or(false)
    }

    /// 世代 +1 **并唤醒在飞起核腿**（`start`/`stop`/`restart` 入口的唯一 bump 通道）。
    ///
    /// 世代仍是唯一真值（`gate` 持有），此处只是把「世代变了」这条消息同点发出去 —— 两者同一表达式
    /// 内落值，结构上不可能分叉。**绕过本方法直接调 `self.gate.bump_generation()` 即回归**：世代变了
    /// 但没人被叫醒 ⇒ 正在退避 sleep 的起核腿要等睡满才发现自己该让位（有单测锁死）。
    pub(super) fn bump_generation(&self) -> u64 {
        let g = self.gate.bump_generation();
        self.gen_changed.notify_waiters();
        g
    }

    /// [`sleep_unless_superseded_on`] 的实例侧入口（本运行时的 gate + 取消信号）。
    pub(super) async fn sleep_unless_superseded(&self, my_gen: u64, dur: Duration) -> bool {
        sleep_unless_superseded_on(&self.gate, &self.gen_changed, my_gen, dur).await
    }

    /// 启动 sing-box（上游 `proxy:start`）。
    ///
    /// 语义对齐 上游 ProxyManager.start：
    /// 1. 世代 +1 + `begin`（单飞守卫；本腿被更新的 start/stop 接管即让位）
    /// 2. 解析端口（config-engine `proxy_ports` + core-supervisor `PortAllocator`）
    /// 3. 生成 sing-box config（config-engine）→ 写盘
    /// 4. spawn sing-box 进程（core-supervisor `TokioSpawner`）+ stdout/stderr 接日志 sink
    /// 5. 就绪门（core-supervisor `wait_for_core_ready`：TCP 可连管理 API）
    /// 6. 置状态 + 记启动快照
    ///
    /// **边界**：系统代理 enable / TUN / helper 提权起核**不在本批次**——见模块级声明。
    pub async fn start(self: &Arc<Self>, config: Value) -> Result<ProxyStatus, StartError> {
        let t_start_request = std::time::Instant::now();
        // 后台网络任务须等整个起核事务稳定。TUN 成功腿会在 selector 校正/flush 任务里先接棒一个
        // 新 guard，再由本 guard 退场，因此计数不会在两段之间短暂归零、放进一条注定被 RST 的请求。
        let _network_settle = self.network_settle.begin("proxy-start");
        // 起核在飞标记（`ProxyStatus::starting` 的源）：**置于所有早退腿之前**，覆盖整条起核腿——
        // stale 清扫本身就能停数秒（真机事故里正是它撞上杀不动的 root 孤儿），那段时间用户看到的是
        // 「转圈但 running:false」，托盘若据 running 决策就会在此叠第二次 start。Guard 的 Drop 保证
        // 下面 `?` 早退（清扫 → ROOT_ORPHAN_BLOCKED）也归还计数。
        self.start_inflight.fetch_add(1, Ordering::SeqCst);
        let inflight = InflightGuard(Arc::clone(&self.start_inflight));
        // **每次** start 都清扫孤儿核（对齐 上游 :700），只杀「本 app 二进制起的」核——见
        // `cleanup_stale_cores`。孤儿不只来自上个会话崩溃，也来自本会话中途失败的起核尝试，
        // 故不能只清一次（见 `stale_sweep_disabled` 字段文档：那个门闩正是本次事故的放大器）。
        // 清不掉的 root 孤儿会独占 cache.db 致任何模式都起不来 → 阻断起核并落 ROOT_ORPHAN_BLOCKED，
        // 不放行到 start_inner 去撞一串无从归因的 `initialize cache-file: timeout`（T3）。
        let t_stale_sweep = std::time::Instant::now();
        if !self.stale_sweep_disabled.load(Ordering::SeqCst) {
            if let Err(error) = self.cleanup_stale_cores().await {
                log::info!(
                    "代理启动请求耗时：孤儿核清扫失败于{}ms，端到端={}ms",
                    t_stale_sweep.elapsed().as_millis(),
                    t_start_request.elapsed().as_millis()
                );
                return Err(error);
            }
        }
        let stale_sweep_ms = t_stale_sweep.elapsed().as_millis();
        log::info!("代理启动请求耗时：孤儿核清扫={stale_sweep_ms}ms");
        // 保存阶段只落期望配置与删除意图；真正的文件/state/远端注销必须等旧核已经不存在。
        // 冷启动与 restart 的 start 腿都在这里汇流。重复 start 若仍有运行核则跳过，绝不碰活会话资产。
        if !self.core_running() {
            self.process_deferred_config_deletions();
        }
        // 用户/其它显式 start 接管后，清掉此前主动 stop 留下的自愈中止标记。状态机已有这一语义，
        // 这里补齐生产写侧；否则一旦主动停过，后续新会话真的崩溃也会被永久当作用户仍在阻止自愈。
        self.crash_lock().reset_user_aborted();
        // 世代 +1（上游 :632 start 入口）：本腿快照世代，被更新的 start/stop 接管即让位（#176）。
        let my_gen = self.bump_generation();
        self.gate.begin();
        let t_start_inner = std::time::Instant::now();
        let r = self.start_inner(config, my_gen).await;
        let start_inner_ms = t_start_inner.elapsed().as_millis();
        let t_terminal_settle = std::time::Instant::now();
        // end 恒执行（成功/失败/让位三路），否则 depth 永不归零 → 后续 apply 全被误判 deferred。
        self.finish_lifecycle(LifecycleKind::Start);
        // 维度7 #8：本想启动/重启却失败 → 清「仍指向我们死端口的系统代理」，防旧会话残留全网断。
        // 挂在 public `start` 包装（**而非 command 层**）→ 覆盖全部入口（IPC/托盘/自动连接）+ restart 的
        // start 腿（`restart` 内部直调 `self.start`）——后者正是本不变式的主场景（重启失败→死端口→全网断）。
        // 挂 command 层会漏掉 restart 腿 = §K7「门开在别处却当全域门」。
        self.maybe_clear_system_proxy_on_start_failure(&r, my_gen)
            .await;
        // C11：起核失败 → 把刚起的竞速 sidecar 一并收掉，别留一个没有内核在消费的 UDP 监听
        // （端口占着、下次起核换新口，而生成侧状态还指着旧口）。守卫同上：被接管则交接管方收口。
        self.maybe_stop_race_sidecar_on_start_failure(&r, my_gen);
        // **成功生命周期的唯一广播点**：必须等 `start_inner` 的整条接管事务（含 Windows 系统代理写入）
        // 返回，再先归还 `starting` 在飞计数，最后才告诉 UI ready。这样事件订阅方回拉到的是
        // `running:true + starting:false` 的完整终态，不会在旧 TUN 核 / 注册表写入中的半成品上探活。
        //
        // `start_inner` 的让位腿也会 `Ok(self.status())`，甚至可能读到接管方的 running 核；故成功不能只看
        // `r.is_ok()`，还要本世代仍当权。世代已变就由接管方自己的 ready/failed 收口，本腿保持沉默。
        let committed =
            r.as_ref().is_ok_and(|status| status.running) && self.gate.generation() == my_gen;
        drop(inflight);
        if committed {
            // 与 stopped 腿同一配对纪律：差集与生命周期描述同一次终态跃迁，必须相邻发布。
            self.push_pending_changes();
            self.push_lifecycle(&ProxyLifecycleEvent::ready());
        }
        // **起核失败的唯一广播点**（`event:proxyLifecycle{phase:'failed'}`）。挂这里而不是各失败腿，
        // 理由同上面两条收口：这是全部起核入口（IPC / 托盘 / 启动自动连接 / `restart` 的 start 腿）
        // 的汇流点，新增失败腿只要照常 `?` 就自动有事件，没有哪条腿能悄悄失败。
        //
        // **它补的是 `event:proxyError` 盖不住的那一类**：`set_error` 头注明列「config 生成 / 写盘 /
        // spawn 失败」不经它，理由是「有 command 在 await，调用方已拿到真错」—— 而**去抖重启这条路
        // 上没有任何人在 await**（`schedule_restart` 的回调只 `log::error!`）。那一类失败此前对 UI
        // 是全静默的：条停在「应用中…」直到 12s 兜底轮询。
        //
        // **不加世代守卫**（与相邻两条收口刻意不同）：那两条做的是**破坏性**动作（清系统代理 / 停
        // sidecar），误做会伤到接管方；发一条事件不破坏任何东西，而接管方随后自己的 ready/failed
        // 会后发覆盖。漏发才是更坏的失效（条永远停在转圈），故取「宁可多发一条可被覆盖的」。
        if let Err(e) = &r {
            self.push_lifecycle(&ProxyLifecycleEvent::failed(e));
        }
        let terminal_settle_ms = t_terminal_settle.elapsed().as_millis();
        log::info!(
            "代理启动请求耗时：端到端={}ms（孤儿核清扫={stale_sweep_ms}ms \
             起核事务={start_inner_ms}ms 终态收口={terminal_settle_ms}ms，结果={}）",
            t_start_request.elapsed().as_millis(),
            if r.is_ok() { "ok" } else { "error" }
        );
        r
    }

    /// 停止 sing-box（上游 `proxy:stop`）——**主动停止终态**：停核 ＋ 清系统代理（维度7 #8 对称面）。
    ///
    /// = [`stop_inner`](Self::stop_inner)（停核 + 清状态/快照）＋ 系统代理收口。
    ///
    /// **为什么主动停止必须清系统代理**：系统代理若由我们设置且仍指向刚被杀的本地端口，停核后它就指向
    /// 一个死端口 → 用户全网断连、需手动改回。这是 start 失败腿
    /// （[`maybe_clear_system_proxy_on_start_failure`](Self::maybe_clear_system_proxy_on_start_failure)）的
    /// **对称面**：那条守「起核失败别留死端口」，这条守「主动停核别留死端口」。
    ///
    /// **guard 复用同一 marker 门控**：`clear_system_proxy` → `ensure_cleared` 门控 1「无 marker 即 no-op」
    /// —— 系统代理非我方设置（或已清）绝不动手，不误清用户自配的第三方代理。清理失败只记日志、不 panic、
    /// 不阻断停止（`stop` 恒返回 `Ok`）。
    ///
    /// **只挂主动停止腿，不把清理塞进 restart 共用的 stop 腿**：`restart` = stop→start 是瞬态停核；
    /// `SystemProxy → SystemProxy` 清了会在重建前留下「无系统代理」窗口（对齐上游
    /// `ensureSystemProxyCleared` 首行 `if (this.stopping) return`）。但 `SystemProxy → Tun/Manual` 必须清旧
    /// 代理，故 [`restart_inner`](Self::restart_inner) 在 stop 腿完成后按新旧模式选择性调用本收口点。
    /// restart 若在 start 腿失败留下死端口，仍由上面的 start 失败腿收口。故 [`restart`](Self::restart)
    /// 调 [`stop_inner`](Self::stop_inner) 而非本方法。
    /// **换代即让位**：`stop_inner` 返 `false` 表示本腿在停核期间已被更新的 start/stop 接管
    /// （见该方法的换代守卫）。此时系统代理**属接管方**——清它就是把新会话刚设好的代理抹掉、
    /// 用户全网走直连。故这条收口也一并让位，由接管方自己的终态负责。
    pub async fn stop(self: &Arc<Self>) -> Result<(), String> {
        // 主动停止是崩溃自愈的终止意图：先置位，再由 stop_inner bump 世代并停核。退避中的自愈腿
        // 会在 post_backoff 读到该标记并放弃；下次显式 start 在其入口复位。
        self.crash_lock().mark_user_aborted();
        if self.stop_inner().await? {
            // Stop 完成后旧核已不存在，已保存删除的保护对象随之消失：此刻就是与 Apply/冷启动同级的
            // 安全提交点。只消费后端 journal，**绝不**触碰渲染端尚未保存的 staged 条目。
            self.process_deferred_config_deletions();
            // 维度7 #8 对称收口（见方法文档）：marker 门控幂等，失败只记日志不阻断停止。
            self.clear_system_proxy().await;
        }
        Ok(())
    }

    /// 停核主体（**不含系统代理收口**）：世代 +1 → kill → 清状态/快照 → `end(Stop)` 丢弃 pending。
    ///
    /// 1. 世代 +1（接管在飞的 start：其就绪门即刻让位）
    /// 2. kill 进程（core-supervisor `ProcessKiller`：SIGTERM → 宽限 → SIGKILL）
    /// 3. 清状态 + 快照；`end(Stop)` 丢弃全部 pending（停止优先）
    ///
    /// **[`restart`](Self::restart) 复用本腿**；本腿自身不碰系统代理。restart 会在它返回 `true` 后按
    /// 新旧模式选择性收口（同为 systemProxy 则保留，离开 systemProxy 才清），见
    /// [`restart_inner`](Self::restart_inner)。
    ///
    /// # 返回值
    ///
    /// - `Ok(true)` = 本腿跑完拆除且仍当权；[`stop`](Self::stop) 可继续收口系统代理。
    /// - `Ok(false)` = 中途已被更新的 start/stop 接管，余下步骤整段让位。
    /// - `Err` = helper 停核没有得到确定回执；保留运行态与 pid，禁止广播假的 stopped、禁止重启叠核。
    ///
    /// # 换代守卫：超预算残 stop 的**晚落地换代毒性**
    ///
    /// 本腿的每一个 await 都可能挂到分钟级：`kill_core` 的 SIGTERM→5s 宽限→SIGKILL / 经 helper 停核的
    /// 阻塞 IPC（`spawn_blocking` 可被饥饿）、`restore_system_dns_best_effort` 的两次系统 exec
    /// （macOS 上 `networksetup` 卡死有实证）。而 `commands::helper::helper_uninstall` 的看门狗收停是
    /// **有预算**的（`WATCHDOG_JOIN_BUDGET`）：超预算后命令直接返回，那次 `proxy.stop()` 变成**残任务**
    /// 继续挂着。用户此时完全可能重装 helper 并起一个新核 —— 残 stop 随后醒来，后半段每一步都在改
    /// **当前会话**的共享态：`clear_race_server()`（`None` 腿无条件清）会抹掉新核的 sidecar 注入态
    /// （节点域名解析静默 SERVFAIL）、`status = default` 抹掉新核的 running 态、`restore_system_dns` 把
    /// 新核接管的 DNS 还原掉、`mesh.exit_route_clear()` 连带取消新会话在飞的出口路由作业。
    ///
    /// 判据用**本腿自己 bump 出来的世代**（`bump_generation` 返回值）：全仓只有 `start` / `stop` 两个
    /// 入口 bump 世代 ⇒ 「世代变了」⟺「有更新的 start 或 stop 接管了」，两种情况都该让位（接管方是
    /// start ⇒ 不许碰它的态；接管方是 stop ⇒ 该做的它自己会做）。
    ///
    /// 检查点摆在**每个 await 之后**（不多不少）：同步语句之间不存在别的任务插入的可能，唯一能发生
    /// 换代的位置就是 await 让出执行权的那些点。`ts_exit_recover_once_order_is_reapply_reassert_refresh`
    /// 同款范式；本腿的配对扫描见 `stop_teardown_guard`。
    ///
    /// 让位路径**照样 `finish_lifecycle(Stop)`**：`gate.begin()` 与 `end()` 必须配对，漏掉即
    /// `LifecycleGate` depth 永久 >0 ⇒ 此后每一次 switch_mode / 去抖重启都只置 pending 不执行
    /// （`commands::helper::join_watchdog_cooperatively` 文档里记的那条最重后果）。
    pub(super) async fn stop_inner(self: &Arc<Self>) -> Result<bool, String> {
        // 必须先 bump（早于取 child 锁）：与 start 的「持锁判世代」共同封死孤儿窗口。
        // 走 [`bump_generation`](Self::bump_generation) 而非 `gate.bump_generation()`：同一次调用里
        // 唤醒在飞起核腿，**取消当场生效**而不是等它退避睡满（这就是「点了立刻停」的那一下）。
        let my_gen = self.bump_generation();
        self.gate.begin();
        let kill_result = self.kill_core().await;
        // 请求在飞期间若已被新 start/stop 接管，结果属于旧腿，不能覆盖接管方终态。
        if self.stop_superseded(my_gen, "kill_core") {
            self.finish_lifecycle(LifecycleKind::Stop);
            return Ok(false);
        }
        if let Err(error) = kill_result {
            // helper 停核结果不明时保留 running/pid/core_via_helper：清成 stopped 会让仍在跑的
            // SYSTEM/root 核失联成孤儿。命令层收到 Err 后也不会广播假的 proxyStopped。
            self.finish_lifecycle(LifecycleKind::Stop);
            return Err(error);
        }
        // C5：停核 → TS 内核接口随之拆除 → 清理出口路由（真装过才发 route del；未装成 / 测试构造
        // `enabled=false` 下 installed 恒 None → clear_inner 早退 = 纯 no-op）。
        self.mesh.exit_route_clear().await;
        if self.stop_superseded(my_gen, "exit_route_clear") {
            self.finish_lifecycle(LifecycleKind::Stop);
            return Ok(false);
        }
        // R2：停核 → 复位 TS 出口无效直判的翻转对账缓存（新会话首帧须能重新触发 none→blocked，
        // 对齐 上游 会话起点 `lastTsExitBlock = null`）。
        self.reset_ts_exit_block_state();
        // A3：停核 → STATUS 流不再 live → 清 TS 状态末帧缓存（陈旧 live 数据不再供 tailscale_get_status）。
        // relay 任务本身由世代守卫（`stop_inner` 已 bump 世代）自行退场；此处只清缓存。
        self.mesh.clear_ts_status();
        // OpenConnect/OpenVPN challengeID 只在本核会话有效；停核必须与 TS 同刻清掉末帧。
        self.mesh.clear_vpn_status();
        // A4：停核 → 复位登录期出口让位内存态 + 撤 UI（若在让位中）。不切 selector（核已停）。
        self.reset_login_fallback_state();
        // C11：停核 → 停 race sidecar + 清注入态（sidecar 绑主核生命周期；下次起核按新配置重建）。
        self.clear_race_server();
        // 停核 → 停通用网络 watcher。先于还原 DNS：避免 watcher 在
        // 还原窗口里看到链路事件又重灌（幂等无害，但停在前更干净）。
        self.stop_network_watcher();
        if let Ok(mut state) = self.runtime_binding_state.lock() {
            *state = RuntimeBindingState::default();
        }
        // C7：停核 → 还原系统 DNS（best-effort；无 marker → 惰性；Linux per-link revert 幂等）。
        // 对齐 上游 `stopSystemDns`（restoreDns）。放在刷缓存之前：先把系统解析器还原，再清缓存里的旧记录。
        self.restore_system_dns_best_effort().await;
        if self.stop_superseded(my_gen, "restore_system_dns") {
            self.finish_lifecycle(LifecycleKind::Stop);
            return Ok(false);
        }
        // C7：停核尾刷 OS DNS 缓存（fire-and-forget，对齐 上游 `flushOsDnsCacheBestEffort('stop')`）。
        self.flush_os_dns_cache_best_effort("stop");
        if let Ok(mut g) = self.status.write() {
            *g = ProxyStatus::default();
        }
        // 核停（出口隧道下线）→ 失效解锁缓存：清缓存 + 广播 `{running:false}`，让渲染端复位 idle（不再 serve
        // 停核前的陈旧解锁快照）。`unlock_get` 的停核短路是自证腿，此处显式失效并广播使 UI 即时复位、不等下次挂载。
        self.invalidate_unlock_cache(false, false);
        // 核停（出口隧道下线）→ 重探出口 IP：代理出口已消失，直连出口是新的真值。无收敛可等（出口是
        // 确定性消失，不是切换）⇒ 零延迟直接探。
        self.schedule_exit_ip_refresh(false);
        if let Ok(mut snap) = self.startup_snapshot.write() {
            *snap = None;
        }
        // 核停 ⇒ 没有「运行核」这个分母，待应用差集恒空（见 `pending_changes`）→ 欠账标记一并复位，
        // 否则停核期间条上会挂着一条谈不上「待应用」的提示，且下次起核前无人清。
        self.restart_deferred.store(false, Ordering::SeqCst);
        // 分母侧刚被清空 ⇒ 同上刻推一次（与起核就绪腿严格对偶）。停核由命令层发 `proxyStopped`，
        // 前端确有 pull 兜底；但**重启内嵌的这次停核不经命令层**，只靠那条 pull 就是漏的一半。
        // `push_lifecycle(stopped)` 同上必须相邻：核停了就谈不上「正在应用」，条该离开转圈态。
        self.push_pending_changes();
        self.push_lifecycle(&ProxyLifecycleEvent::stopped());
        if let Ok(mut g) = self.pending_force_restart.write() {
            *g = None;
        }
        // 核停 → 热切换基准失效（上游 :1386-1388）。留着会让下次 switch_mode 拿「上一个核」的
        // id→tag 去 PUT 新核里不存在的成员。current_config 保留（上游 :1758 未运行腿仍读写它）。
        if let Ok(mut g) = self.switch_snapshot.write() {
            *g = None;
        }
        self.finish_lifecycle(LifecycleKind::Stop);
        Ok(true)
    }

    /// 停核拆除腿的换代让位判据（见 [`stop_inner`](Self::stop_inner) 的换代守卫段）。
    ///
    /// `at` = 刚跨过的那个 await 名，只进日志 —— 真机上「残 stop 在哪一步被换代拦下」是这条腿唯一
    /// 可观测的痕迹（没有它，表现只是「什么都没发生」）。
    pub(super) fn stop_superseded(&self, my_gen: u64, at: &str) -> bool {
        let cur = self.gate.generation();
        if cur == my_gen {
            return false;
        }
        log::warn!(
            "停核腿在 {at} 之后发现已被接管（世代 {my_gen}→{cur}）→ 余下拆除整段让位：\
             此刻的 sidecar 注入态 / running 态 / 系统 DNS 都属**新会话**，动它们等于让新核静默失效"
        );
        true
    }

    /// 重启（上游 `proxy:restart`，:1499-1508）。**外层 begin/finish 包住内嵌 stop+start，全程 depth≥1**。
    ///
    /// 上游 `restart` = `beginLifecycleOp()` / try{ stop; start } / finally `endLifecycleOp('restart')`。
    /// 内嵌 [`stop_inner`](Self::stop_inner)/[`start`](Self::start) 各自 begin/end 把 depth 抬到 2 再落回 1
    /// （:1519-1521 重入语义）——**封死「stop→start 空窗内 depth 归 0」**，否则去抖 timer / 并发 `switch_mode`
    /// 会钻进空窗并发起第二条重启，且内层 `stop_inner` 的 [`finish_lifecycle`](Self::finish_lifecycle)`(Stop)`
    /// 在 depth 0 命中 `Stopped` 终态分支 → **静默丢弃**窗口内暂存的 switch/force-restart（本不变式的 drifted 缺陷）。
    ///
    /// 用 `stop_inner` 而非 [`stop`](Self::stop)：重启是瞬态停核，`SystemProxy → SystemProxy` 紧接着会在
    /// 同一 mixed port 重建，主动清会制造「无系统代理」窗口。跨模式 `SystemProxy → Tun/Manual` 则必须在
    /// 停核腿仍当权时清掉旧 marker/OS 代理，否则新模式不会再走 enable 腿、残留会永久存在。该分流由
    /// [`should_clear_system_proxy_between_restart`] 单点判定。restart 若在 start 腿失败留死端口，仍由
    /// `maybe_clear_system_proxy_on_start_failure` 统一收口——见 [`stop`](Self::stop) 文档。
    pub async fn restart(self: &Arc<Self>, config: Value) -> Result<ProxyStatus, StartError> {
        self.gate.begin(); // restart 外层 begin（上游 beginLifecycleOp，:1500）→ depth≥1 不变式起点。
        let r = self.restart_inner(config).await;
        // finish 恒执行（成功/失败/让位三路，try/finally 语义）：depth 归 0 时按 Restart 排空一次
        // 暂存 switch（其内部再分流热切/重启）+ 尾随去抖重启（上游 endLifecycleOp('restart')，:1506）。
        self.finish_lifecycle(LifecycleKind::Restart);
        r
    }

    /// [`restart`](Self::restart) 内层：瞬态停核 + 重建。外层 begin/finish 由 `restart` 持有（depth≥1 不变式）。
    async fn restart_inner(self: &Arc<Self>, config: Value) -> Result<ProxyStatus, StartError> {
        // `apply_restart` 在调度前已经把 current_config 提交成**新**配置，不能据它判断旧模式；唯一可信的
        // 旧核真值是就绪时落下的 startup_snapshot。必须在 stop_inner 清快照之前取。
        let old_mode = self
            .startup_snapshot
            .read()
            .ok()
            .and_then(|g| g.clone())
            .and_then(|v| serde_json::from_value::<UserConfig>(v).ok())
            .map(|cfg| cfg.proxy_mode_type);
        let new_mode = serde_json::from_value::<UserConfig>(config.clone())
            .ok()
            .map(|cfg| cfg.proxy_mode_type);
        let retiring_tun_interface = self
            .runtime_binding_state
            .lock()
            .ok()
            .and_then(|state| state.managed_tun_interface.clone());
        // `Ok(false)` 只表示旧停核腿已被接管，仍可让新的 start 以世代规则竞争；`Err` 则是 helper
        // 未确认旧核已停，必须中止重建，否则可能在同一 daemon 下复用旧配置或叠第二个核。
        let stop_completed = self.stop_inner().await?;
        if stop_completed && should_clear_system_proxy_between_restart(old_mode, new_mode) {
            log::info!("重启跨模式离开 systemProxy → 起新核前清理旧会话系统代理");
            self.clear_system_proxy().await;
        }
        if stop_completed
            && old_mode.is_some_and(ProxyModeType::is_tun)
            && new_mode.is_some_and(ProxyModeType::is_tun)
        {
            self.wait_for_retiring_tun_route(retiring_tun_interface.as_ref())
                .await;
        }
        self.start(config).await
    }

    /// 短暂借出诊断计数器（慢起轴更新同步、绝不跨 await 持锁）。
    pub(super) fn diag_lock(&self) -> std::sync::MutexGuard<'_, DiagnosticCounters> {
        self.diagnostics
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// lifecycle 收尾：`end` + 按返回的排空/丢弃指令动作（**语义全在 core-supervisor，本处只执行**）。
    pub(super) fn finish_lifecycle(self: &Arc<Self>, kind: LifecycleKind) {
        match self.gate.end(kind) {
            LifecycleEndResult::StillBusy(depth) => {
                log::debug!("lifecycle end（{kind:?}）：depth={depth} 仍在飞，pending 留给最外层");
            }
            LifecycleEndResult::Stopped(discard) => {
                // 停止终态：丢弃全部 pending（停止优先，不得停后又被拉起）。
                if discard.discarded_restart
                    || discard.discarded_force_restart_id.is_some()
                    || discard.discarded_switch_id.is_some()
                {
                    log::info!(
                        "停止终态丢弃 pending：restart={} force={:?} switch={:?}",
                        discard.discarded_restart,
                        discard.discarded_force_restart_id,
                        discard.discarded_switch_id
                    );
                }
                if let Ok(mut g) = self.pending_force_restart.write() {
                    *g = None;
                }
                // 停止终态同样丢弃暂存的 switch（停止优先：不得停后又被 switch 拉起）。
                if let Ok(mut g) = self.pending_switch.write() {
                    *g = None;
                }
            }
            LifecycleEndResult::Drained(drain) => {
                if drain.schedule_restart {
                    log::info!("depth 归零 → 排空一次尾随重启");
                    self.schedule_restart();
                }
                // 排空暂存的 switchMode（上游 :1540 `void this.switchMode(pendingSwitch)`）。
                // depth 已归零 → 重放时不会再落回 Pending 腿，可正常判热切/重启。
                if let Some(id) = drain.replay_switch_id {
                    if let Some((cfg, defer_restart)) = self.take_pending_switch(Some(id)) {
                        log::info!(
                            "depth 归零 → 重放暂存的 switchMode（defer_restart={defer_restart}）"
                        );
                        let me = Arc::clone(self);
                        tokio::spawn(async move {
                            me.switch_mode_with(cfg, defer_restart).await;
                        });
                    }
                }
            }
        }
    }

    /// 调度一次去抖重启（接线 switch-engine [`DebouncedRestart`](polaris_switch_engine::debounced_restart::DebouncedRestart)：timer + 世代守卫 + gate 顺序门）。
    pub(super) fn schedule_restart(self: &Arc<Self>) {
        let me = Arc::clone(self);
        // handle 不持有：drop 不取消 task（task 自查 gate 决策，过期自行 Superseded）。
        let _handle = self
            .debounced
            .schedule(self.core_running(), move |outcome| {
                match outcome {
                    DebouncedOutcome::Proceed(force_id) => {
                        tokio::spawn(async move {
                            // H-1：优先读 force-restart 专用快照（in-flight start 会覆盖 currentConfig）。
                            let cfg = me.take_force_restart_config(force_id);
                            let cfg = match cfg.or_else(|| me.config.current().ok()) {
                                Some(c) => c,
                                None => {
                                    log::warn!("去抖重启：无可用配置 → 放弃");
                                    return;
                                }
                            };
                            if let Err(e) = me.restart(cfg).await {
                                log::error!("去抖重启失败: {e}");
                            }
                        });
                    }
                    other => log::info!("去抖重启未执行：{other:?}"),
                }
            });
    }

    /// 取出并清除 force-restart 专用配置快照（id 对得上才取；对不上回落 None）。
    pub(super) fn take_force_restart_config(&self, id: Option<u64>) -> Option<Value> {
        let mut g = self.pending_force_restart.write().ok()?;
        match (&*g, id) {
            (Some((sid, _)), Some(want)) if *sid == want => g.take().map(|(_, c)| c),
            // id 为 None（用 currentConfig）或对不上（更新的 apply 已换快照）→ 不消费。
            _ => None,
        }
    }

    /// 置错误态（起核失败）。
    /// 进入错误终态：落状态（`running=false` + error + errorCode）→ 广播 `event:proxyError`。
    ///
    /// **为什么发射点收口在这里而不是各失败腿**：`set_error` 是「运行时进入错误态」的唯一状态跃迁点，
    /// 挂在这里 ⇒ 新增失败腿只要照常 `set_error` 就自动有事件，**没有哪条腿能悄悄错掉**（挂在各腿上
    /// 则漏一个就退回本 bug：`EVENT_PROXY_ERROR` 定义了却全仓零 emit）。
    ///
    /// **不覆盖的腿及理由**：
    /// - **用户主动 `stop`**：不是错误，是达成了用户意图的终态 → 走 `event:proxyStopped`，此处不发。
    /// - **被更新的 start/stop 接管（让位腿）**：本腿没失败，只是不再是当权者；接管方会自己收口
    ///   （发错误会让 UI 为一次正常的接管报警）。让位腿本就返 `Ok(status)`、不经 `set_error`。
    /// - **config 生成 / 写盘 / spawn 失败**：有 command 在 await（`ApiResponse::err` → 前端 throw），
    ///   调用方已拿到真错。这些腿此前也不经 `set_error`，本次不扩面（要扩得连状态一起落，属另一议题）。
    ///
    /// 事件发不出（emitter 未接线 / 无窗口）绝不打断状态落值 —— 诊断通道不该反噬它诊断的东西。
    pub(super) fn set_error(&self, msg: &str, error_code: &str) {
        log::error!("{msg}");
        if let Ok(mut g) = self.status.write() {
            *g = ProxyStatus {
                error: Some(msg.to_string()),
                error_code: Some(error_code.to_string()),
                ..ProxyStatus::default()
            };
        }
        match self.error_emitter.get() {
            Some(e) => e.emit_proxy_error(msg, error_code),
            // 未接线：单测 / setup 前的极早期失败。状态已落，只是没有渲染端可推。
            None => log::debug!("proxy error emitter 未接线 → 跳过 event:proxyError（状态已落）"),
        }
    }

    /// 置**非终态**告警（核仍在运行，但有用户必须知道的降级）→ 落 error/errorCode + 广播 `event:proxyError`。
    ///
    /// **与 [`set_error`](Self::set_error) 的分工（别混用）**：
    /// - `set_error` = 「运行时进入错误终态」→ 整个 `ProxyStatus` 重置为 `default()`（`running=false`、
    ///   `pid=0`、端口清零）。用于起核失败 / 核崩了。
    /// - 本方法 = 「核在跑，但流量的安全属性被降级了」→ **只写 error 两字段，保留 `running/pid/端口/startTime`**。
    ///
    /// **为什么必须分开**：A1 启用失败与出口不一致时核**确实在运行**。若复用 `set_error`，UI 会显示
    /// 「未运行」而进程还活着 = 虚报，且抹掉 `pid`/`clashApiPort` 会让停核、管理 API、统计全部失联 ——
    /// 用一个诊断通道换掉运行态真值，比它诊断的问题更糟。这正是 `DESIGN-REVIEW(a1-enable-failure-surface)`
    /// 留的口子：要「冒给用户」，但不许把活核标成死核。
    ///
    /// 状态未落值（锁中毒）或事件发不出（emitter 未接线）都**不打断调用方** —— 诊断通道不该反噬被诊断者。
    ///
    /// **消费端**：`App.tsx` 的 `api.proxy.onError` 订阅按错误码白名单放行，当前已含
    /// `SYSTEM_PROXY_FAILED` / `EXIT_MISMATCH` / `RULE_RESOURCES_MISSING`（本方法发的三个码）。
    /// 新增码时**必须同步前端白名单**，否则后端这半条链（落状态 + 发事件 + 单测锁死）齐备、
    /// 用户端仍是静默丢弃——那正是本方法早先的状态。
    pub(super) fn set_nonfatal_error(&self, msg: &str, error_code: &str) {
        log::error!("{msg}");
        if let Ok(mut g) = self.status.write() {
            // 只覆盖错误两轴，其余字段（running/pid/mixed_port/clash_api_port/start_time…）原样保留。
            g.error = Some(msg.to_string());
            g.error_code = Some(error_code.to_string());
        }
        match self.error_emitter.get() {
            Some(e) => e.emit_proxy_error(msg, error_code),
            None => log::debug!("proxy error emitter 未接线 → 跳过 event:proxyError（状态已落）"),
        }
    }

    /// 只清本事务曾落下的非终态码，不能把并发产生的其它、更晚告警一并抹掉。
    pub(super) fn clear_nonfatal_error_if(&self, error_code: &str) {
        if let Ok(mut status) = self.status.write() {
            if status.error_code.as_deref() == Some(error_code) {
                status.error = None;
                status.error_code = None;
            }
        }
    }

    /// 推送本次起核 gate 的非法节点（`event:proxy:invalid-nodes`）。
    ///
    /// 未接线（单测 / setup 前）→ 只记日志：**发不出事件绝不能反过来打断起核本身**（同 [`set_error`]
    /// 的取舍）。gate 已经把这些节点剔出 config 了，事件只是让用户看见，缺它不影响正确性。
    ///
    /// [`set_error`]: Self::set_error
    pub(super) fn emit_invalid_nodes(&self, nodes: &[InvalidNode]) {
        if !nodes.is_empty() {
            log::info!(
                "启动 gate 剔除 {} 个非法节点: {}",
                nodes.len(),
                nodes
                    .iter()
                    .map(|n| n.tag.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        match self.error_emitter.get() {
            Some(e) => e.emit_invalid_nodes(nodes),
            None => log::debug!("emitter 未接线 → 跳过 proxy:invalid-nodes"),
        }
    }

    /// 当前落盘配置的 `selectedServerId`（空串 / 缺失 → `None`）。
    ///
    /// **持读锁直接取 `&str`，不 clone 整份 `Value`**：唯一调用方 [`Self::apply_ts_status_frame`] 由
    /// TS STATUS relay 每秒量级调用，且每帧调**两次**（换缓存前后各取一次做边沿判定）。`g.clone()`
    /// 会深拷贝整份 `UserConfig` JSON（含 200 节点级别的 `servers` 数组）—— 语义无误，但那是常驻开销。
    pub(super) fn selected_server_id(&self) -> Option<String> {
        let guard = self.current_config.read().ok()?;
        guard
            .as_ref()?
            .get("selectedServerId")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    }

    /// 后台网络任务在发请求前等待当前起核/TUN flush 稳定。
    pub(crate) async fn wait_for_network_settled(&self) {
        self.network_settle.wait().await;
    }

    pub(crate) fn network_settle_pending(&self) -> u32 {
        self.network_settle.pending()
    }

    /// **runtime 生命周期结局 PUSH**（`event:proxyLifecycle`）。
    ///
    /// # 与 [`push_pending_changes`](Self::push_pending_changes) 的配对纪律
    ///
    /// `ready` / `stopped` 两个 phase **必须与 `push_pending_changes()` 严格同处、同条件**
    /// （紧邻的两行）：它们描述的是同一次跃迁的两个投影 —— 分开放就会出现「差集清了但态没翻」
    /// 或反过来。由 `lifecycle_push_is_paired_with_the_diff_push` 钉住相邻性。
    ///
    /// `failed` **刻意不在这一对里**，因为它**不改变差集的分母**：重启的停核腿早已把
    /// `startup_snapshot` 清空并推过一次空差集，起核失败只是「它没回来」这一条追加信息。
    /// 故它挂在 [`start`](Self::start) 包装的 `Err` 腿 —— 那是全部起核入口（IPC / 托盘 /
    /// 启动自动连接 / `restart` 的 start 腿）的**唯一**汇流点，同
    /// `maybe_clear_system_proxy_on_start_failure` 挂在那里的理由（挂命令层会漏掉 restart 腿）。
    ///
    /// emitter 未接线（单测 / setup 前极早期）→ 静默跳过，绝不打断调用腿（同 `push_pending_changes`）。
    pub(super) fn push_lifecycle(&self, event: &ProxyLifecycleEvent) {
        if let Some(emitter) = self.error_emitter.get() {
            emitter.emit_lifecycle(event);
        }
    }

    /// **§15.11**：当前生命周期世代（测速分波编排的**让位判据**之一）。
    ///
    /// = 上游 `SpeedTestService.getCoreGeneration()`。`start`/`stop`/`restart`/`regen` 均先
    /// [`bump_generation`](Self::bump_generation) 再动核 ⇒ 「核被换掉/停掉」⟺「世代已变」。
    ///
    /// 测速侧据此判「本轮测的还是不是当初那个核」：世代变了则在飞结果量的是**别的核**，必须丢弃而非记账。
    /// 单独用它**不够** —— 自发崩溃不 bump 世代（见 [`status`](Self::status) 的 `running`），故让位判据是
    /// 「世代跃迁 **或** 核已不在运行」两条腿的**析取**，缺一条就会把崩溃窗口的在飞失败误记成真实超时。
    pub fn core_generation(&self) -> u64 {
        self.gate.generation()
    }
}
