//! 降流门：窗口可见性回读缓存 + 订阅需求门控。
//!
//! 两条 relay（连接流 / Status 流）共享一份 [`StreamGateState`]（订阅注册表 × 可见性 + 门变更
//! 代次），各自持一个 [`StreamGate`] 视图按自己那条需求谓词等门。可见性真值一律经
//! [`probe_main_window_visible`] 在主线程回读、写进 [`VisibilityCache`]，relay 只读缓存。

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tauri::{AppHandle, Manager};
use tokio::sync::watch;

use polaris_stats_engine::{SubscriptionRegistry, Topic};

use super::{MAIN_WINDOW_LABEL, PARK_RECHECK_INTERVAL};

/// 降流门的共享态：订阅注册表 + 门变更信号。
///
/// 为何要从 [`StatsRelay`](super::StatsRelay) 里拆出来 `Arc` 共享：两条 relay 是 `tauri::async_runtime::spawn` 出的
/// 独立后台任务，须反复读同一份订阅集 × 可见性做降流判定，而 `StatsRelay` 是 `State`-managed、
/// 后台任务拿不到它的引用。这不是新增抽象层，只是把两个已有字段挪进一个可共享的所有者。
pub(super) struct StreamGateState {
    /// 纯逻辑订阅注册表（topic 计数 + 可见性门控判定，判定本体见 `should_stream`）。
    pub(super) registry: Mutex<SubscriptionRegistry>,
    /// 门变更代次（订阅 / 退订 / 可见性翻转即 +1）。等在门上的 relay 靠 `watch` 立刻醒——
    /// `watch` 记版本而非边沿信号，故「判定为假」与「开始等」之间发生的 bump 不会丢。
    pub(super) epoch: watch::Sender<u64>,
    /// 主窗可见性缓存（relay 只读它，**从不**碰窗口 getter）。
    pub(super) vis: VisibilityCache,
}

/// 主窗可见性的缓存 + 刷新记账。
///
/// # 为什么 relay 不能自己回读窗口
///
/// tauri-runtime-wry 的窗口 getter（`is_visible` / `is_minimized`）是「往主事件循环投一条消息 +
/// `rx.recv()` **阻塞**等回包」（`window_getter!` → `getter!`；非主线程走 `proxy.send_event` 分支）。
/// 主循环被原生模态 / 菜单跟踪 / 提权框（`helper_install` / `helper_uninstall` 都会弹）占住时，
/// 两条 relay 会**同时**把两个 tokio worker 挂死在 `recv` 上，而且每收一帧一次、贯穿整段模态期。
///
/// 故改成两段：
///  - **读**：relay 一次原子 load，永不阻塞；
///  - **写**：`AppHandle::run_on_main_thread` 投一个闭包给主循环（非主线程时只是一次 channel send，
///    不等回包），闭包**在主线程里**跑 getter —— `send_user_message` 对主线程走内联分支，不会自死锁。
///    主循环忙时这次刷新只是排队等，relay 照常用上一份真值继续跑。
pub(super) struct VisibilityCache {
    /// 主窗口是否处在可用生命周期内。Tauri 在 `destroy()` 过渡期仍可能短暂从窗口 registry 返回旧句柄，
    /// 仅靠 `get_webview_window()` 无法区分“活窗”与“正在析构的壳”。由建窗 / 销毁事务显式维护，三平台
    /// 共用；false 时绝不向平台窗口后端投 getter。
    pub(super) window_alive: AtomicBool,
    /// 最近一次回读到的可见性。**缺省 true**：与 getter 报错时的兜底方向一致
    /// （在主窗首次建成前会由 `window_alive=false` 的生命周期门归一为 false）。
    pub(super) visible: AtomicBool,
    /// 是否已有一次刷新在飞（两条 relay 各自反复投递 → 去重成一次）。
    refreshing: AtomicBool,
    /// 连续回读失败次数（限频告警的判据，见 [`should_warn_visibility_failure`]）。
    pub(super) error_streak: AtomicU64,
}

/// 纯判定：可见性回读连续失败第 `streak` 次该不该 warn。
///
/// 1 / 10 / 100 次各一条，此后每 1000 次一条。
///
/// **不能只发第一条**：平台性持续失败时降流门整体退化成「恒可见」（两条上游流永不断开、
/// 无人消费的 IPC 与增量聚合继续运行），那条独苗日志早被淹了 —— 于是「降流失效」这件事零可观测。
/// 也不能每次都发：两条 relay 各按自己的帧率投递（合计每秒数条），日志被自己刷爆。
#[must_use]
pub(super) const fn should_warn_visibility_failure(streak: u64) -> bool {
    matches!(streak, 1 | 10 | 100) || (streak > 100 && streak.is_multiple_of(1000))
}

impl StreamGateState {
    pub(super) fn new() -> Self {
        Self {
            registry: Mutex::new(SubscriptionRegistry::new()),
            epoch: watch::channel(0).0,
            vis: VisibilityCache {
                window_alive: AtomicBool::new(false),
                visible: AtomicBool::new(true),
                refreshing: AtomicBool::new(false),
                error_streak: AtomicU64::new(0),
            },
        }
    }

    /// 主窗可见性（**非阻塞**）：读缓存，并顺带投递一次主线程刷新。
    ///
    /// 「读的同时投刷新」是刻意的：relay 每次过门（收帧后重入 select、或断流待命期的兜底回读）
    /// 都会调它，刷新节拍便自然跟着数据面走 —— 不必另起一条定时器，也不会因为有两条 relay
    /// 而变成双倍投递（`refreshing` 去重）。
    pub(super) fn cached_window_visible(self: &Arc<Self>, app: &AppHandle) -> bool {
        self.spawn_visibility_refresh(app);
        self.vis.visible.load(Ordering::Relaxed)
    }

    /// 投递一次主线程可见性回读（已有一次在飞 → no-op）。
    pub(super) fn spawn_visibility_refresh(self: &Arc<Self>, app: &AppHandle) {
        // `destroy()` 的平台 registry 更新并非原子：销毁事务已开始时，getter 仍可能拿到一个失效句柄。
        // 生命周期真值优先于 registry；此时直接关门，不把无意义调用投给主线程。
        if !self.vis.window_alive.load(Ordering::SeqCst) {
            self.store_window_visible(false);
            return;
        }
        if self.vis.refreshing.swap(true, Ordering::SeqCst) {
            return;
        }
        let this = self.clone();
        let app_for_probe = app.clone();
        // 主线程调用时 `run_on_main_thread` 内联执行该闭包（tauri 的 `send_user_message` 对
        // 主线程走内联分支）；非主线程时只是一次 channel send —— 两种情形都不阻塞调用方。
        if app
            .run_on_main_thread(move || {
                // 闭包排队期间窗口可能已进入销毁事务；执行前再查一次，避免旧探针命中失效 WebView。
                let probe = if this.vis.window_alive.load(Ordering::SeqCst) {
                    probe_main_window_visible(&app_for_probe)
                } else {
                    Ok(false)
                };
                this.apply_visibility_probe(probe);
                this.vis.refreshing.store(false, Ordering::SeqCst);
            })
            .is_err()
        {
            // 事件循环已退出（收尾期）→ 必须复位闸，否则此后再也不会有刷新排上队。
            self.vis.refreshing.store(false, Ordering::SeqCst);
        }
    }

    /// 主窗口刚由 builder 成功创建。窗口先按隐藏态入账；真正上屏后由统一探针翻为可见。
    pub(super) fn mark_main_window_created(&self) {
        self.vis.window_alive.store(true, Ordering::SeqCst);
        self.store_window_visible(false);
    }

    /// 主窗口进入销毁事务。必须先于 `WebviewWindow::destroy()`，从而挡住平台 registry 的过渡旧句柄。
    pub(super) fn mark_main_window_destroying(&self) {
        self.vis.window_alive.store(false, Ordering::SeqCst);
        self.store_window_visible(false);
    }

    /// 落一次回读结果（成功 → 写缓存 + 门；失败 → 兜底「可见」+ 限频告警）。
    pub(super) fn apply_visibility_probe(&self, probe: Result<bool, String>) {
        match probe {
            Ok(visible) => {
                self.vis.error_streak.store(0, Ordering::Relaxed);
                self.store_window_visible(visible);
            }
            Err(e) => {
                let streak = self.vis.error_streak.fetch_add(1, Ordering::Relaxed) + 1;
                if should_warn_visibility_failure(streak) {
                    log::warn!(
                        "主窗可见性回读连续失败 {streak} 次（{e}）：降流门已整体退化为「恒可见」\
                         —— 两条长驻流将一直开着并持续 emit，收托盘/最小化不再省电"
                    );
                }
                // 失败安全方向：宁可多流，绝不把还在屏上的 UI 饿死。
                self.store_window_visible(true);
            }
        }
    }

    /// 写可见性缓存 + 同步进降流门（变了才 bump → 等在门上的 relay 立刻醒，恢复不等兜底周期）。
    fn store_window_visible(&self, visible: bool) {
        self.vis.visible.store(visible, Ordering::Relaxed);
        self.set_window_visible(visible);
    }

    /// 门代次 +1 → 唤醒全部等在门上的 relay（无接收者时是纯 no-op）。
    pub(super) fn bump(&self) {
        self.epoch.send_modify(|v| *v = v.wrapping_add(1));
    }

    /// 某 topic 此刻是否应 emit（订阅集 × 可见性）。锁毒化 → 保守判否（不做无人消费的 I/O）。
    fn should_stream(&self, topic: Topic) -> bool {
        match self.registry.lock() {
            Ok(r) => r.should_stream(topic),
            Err(e) => {
                log::warn!("stats registry lock: {e}");
                false
            }
        }
    }

    /// 写入窗口可见性；**变了才** bump（否则每次兜底实况回读都会白唤醒两条 relay）。
    pub(super) fn set_window_visible(&self, visible: bool) {
        let changed = match self.registry.lock() {
            Ok(mut r) => {
                let changed = r.window_visible() != visible;
                if changed {
                    r.set_window_visible(visible);
                }
                changed
            }
            Err(e) => {
                log::warn!("stats registry lock: {e}");
                false
            }
        };
        if changed {
            log::debug!("stats 降流门：窗口可见性 → {visible}");
            self.bump();
        }
    }
}

/// 一条长驻流的降流门句柄（共享门态 + 该流的需求判据 + 自己的变更接收端）。
///
/// # 降流的动作是 drop 流，不是 park
///
/// 轮询时代的降流是「这一拍不拉取」——不拉取就等于不产生任何成本。长驻流下没有「拍」，也没有
/// 「不拉取」这个动作：流是**内核在推**。park 住不去读它，帧只会堆在 tonic 的接收缓冲和内核的
/// gRPC 发送窗口里，直到把窗口打满、把内核那条 goroutine 阻塞在 `server.Send` 上 ——
/// 我们非但没省，还给内核的事件分发添了堵。
///
/// 故降流语义是 **drop 流**：判定为假 → 丢掉 `ReconnectingStream`（连同它的重连 future），
/// TCP 连接自然关闭，内核那侧 `server.Context().Done()` 触发、`UnSubscribeEvents` 退订，
/// **整条链路上的成本真正归零**。判定为真 → **重新订阅**。
///
/// ⚠️ 重订阅一律从「一份新的真相」开始：连接流必然收到一帧 `reset=true` 全量表
/// （`daemon/started_service.go:728` 在建 ticker 前无条件 `Send`），断流期间消失的连接只能靠它清掉
/// （见 `polaris_stats_engine::aggregator` 的 `reset帧整表替换而非增量叠加`）；Status 流则必须丢掉
/// 速率差分基线（否则整段断流期的平均吞吐会被当成"此刻的速率"显示一帧）。
/// 两者都由调用方在建流后 `StatsAggregator::reset()` 一次做掉。
pub(super) struct StreamGate {
    pub(super) state: Arc<StreamGateState>,
    epoch: watch::Receiver<u64>,
    /// 本条流的**需求判据**。两条流的需求面不同，判定本体都在
    /// [`polaris_stats_engine::SubscriptionRegistry`] 里：
    /// - 连接流 = `should_stream_connections()`（aggregate ∪ detail ∪ closed，共用一条上游流）；
    /// - Status 流 = `should_stream(Topic::Stats)`。
    ///
    /// 存函数指针而非 `Topic`：连接流的需求本就不是单个 topic，写成 `Topic` 会逼着把那条并集
    /// 判据搬到门里重写一遍（判据必须只有一处定义）。
    demand: fn(&SubscriptionRegistry) -> bool,
}

impl StreamGate {
    /// 连接长驻流的门（需求 = aggregate ∪ detail ∪ closed）。
    pub(super) fn connections(state: Arc<StreamGateState>) -> Self {
        Self {
            epoch: state.epoch.subscribe(),
            state,
            demand: SubscriptionRegistry::should_stream_connections,
        }
    }

    /// Status 长驻流的门（需求 = stats topic 自己）。
    pub(super) fn stats(state: Arc<StreamGateState>) -> Self {
        Self {
            epoch: state.epoch.subscribe(),
            state,
            demand: |r| r.should_stream(Topic::Stats),
        }
    }

    /// 本条流此刻是否该开着（按 [`Self::demand`] 判）。锁毒化 → 保守判否（不做无人消费的 I/O）。
    fn is_open(&self) -> bool {
        self.state
            .registry
            .lock()
            .map(|r| (self.demand)(&r))
            .unwrap_or(false)
    }

    /// 某条 topic 此刻是否该 emit（流开着 ≠ 该流供数的每条 topic 都该推）。
    pub(super) fn topic_open(&self, topic: Topic) -> bool {
        self.state.should_stream(topic)
    }

    /// 阻塞到「连接流是否该开」等于 `want` 为止。
    ///
    /// 两个方向共用一个实现是刻意的 —— 它们是**同一个判定**的两侧，分成两个函数写迟早长出
    /// 「开的条件」与「关的条件」不互补的缝（隐藏时不断流、或断了之后醒不过来）。
    ///
    /// 唤醒两条腿：
    /// - **门变更**（订阅/退订/可见性翻转 → `epoch` bump）→ 立刻返回；
    /// - **[`PARK_RECHECK_INTERVAL`] 超时**兜底 → 重新回读窗口实况（Tauri 2 无 show/hide 事件，
    ///   收托盘时窗口本就失焦、连 `Focused` 都不发，只靠事件会永久停在这里）。
    ///
    /// **cancel-safe**：状态全在 `self`（`watch::Receiver` 的 `changed()` 本身即 cancel-safe），
    /// 被 `select!` 丢弃只是停止等待，下次调用续上。流循环正是把它当 `select!` 的一条腿用。
    pub(super) async fn wait_until<V: Fn() -> bool>(&mut self, want: bool, visible: &V) {
        loop {
            // 顺序要紧：先按实况写可见性（自己这次 bump 随即被 borrow_and_update 吃掉），
            // 再记门代次，最后读判定 —— 判定之后发生的任何 bump 都会让 `changed()` 立刻返回。
            self.state.set_window_visible(visible());
            self.epoch.borrow_and_update();
            if self.is_open() == want {
                return;
            }
            match tokio::time::timeout(PARK_RECHECK_INTERVAL, self.epoch.changed()).await {
                Ok(Ok(())) | Err(_) => {}
                // sender 随 StatsRelay 存活于进程全程；Err 只可能出现在收尾 → 退避防忙转。
                Ok(Err(_)) => tokio::time::sleep(PARK_RECHECK_INTERVAL).await,
            }
        }
    }
}

/// 主窗真实可见性回读（对齐 上游 `isUiBroadcastActive` = `mainWindow.isVisible()`）。
///
/// ⚠️ **必须在主线程调用** —— 两个调用点都在 `run_on_main_thread` 投出去的闭包里：
/// [`StreamGateState::spawn_visibility_refresh`]，与 `crate::idle_lightweight` 销毁主窗前的最终复核。
/// 理由见 [`VisibilityCache`]：从别的线程调会阻塞等主循环回包。
///
/// 之所以让轻量巡检也调**这一个**函数而不是自己 `is_visible()` 一遍：显隐判据只能有一处定义，
/// 否则「降流门说不可见、轻量巡检说可见」这类分叉迟早长出来。
///
/// **不是** `WindowEvent::Focused`：失焦但仍在屏上的窗口依然有 UI 消费者，按 focused 降流会让用户
/// 看着的首页拓扑 / 连接明细直接冻住。最小化一并算不可见（笔电最小化后没人看，正是要省电的场景）。
///
/// - `Ok(false)`：主窗不存在（关窗释放内存 / 轻量模式）或已隐藏 / 最小化。主窗不存在时订阅也已由
///   `clear_window` 清空，两条腿一致。
/// - `Err`：平台 getter 报错 —— 由 [`StreamGateState::apply_visibility_probe`] 兜底成「可见」
///   并限频告警（**兜底方向失败安全，但不能静默**，否则降流整体失效且零可观测）。
pub(crate) fn probe_main_window_visible(app: &AppHandle) -> Result<bool, String> {
    let Some(w) = app.get_webview_window(MAIN_WINDOW_LABEL) else {
        return Ok(false);
    };
    if !w.is_visible().map_err(|e| format!("is_visible: {e}"))? {
        return Ok(false);
    }
    Ok(!w.is_minimized().map_err(|e| format!("is_minimized: {e}"))?)
}

/// 生产用的可见性取值器（喂给 [`StreamGate::wait_until`]）：只读缓存 + 投递一次主线程刷新。
///
/// 写成吃 owned 参数的自由函数（而非 `StreamGate` 的方法）是为了让返回的闭包不借用 `gate` ——
/// relay 里紧接着就要 `gate.wait_until(.., &visible)`（需 `&mut gate`）。
/// 单测在同一个位置注入可翻转 flag 的替身（见测试模块的 `flag_visibility_source`）。
pub(super) fn visibility_source(state: Arc<StreamGateState>, app: AppHandle) -> impl Fn() -> bool {
    move || state.cached_window_visible(&app)
}
