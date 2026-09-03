use super::*;

/// 停止终态必须丢弃暂存的 switch（停止优先：不得停后又被 switch 拉起）。
#[tokio::test]
async fn stop_terminal_discards_pending_switch() {
    let (rt, _dir) = test_runtime();
    rt.gate.begin();
    let _ = rt.switch_mode(two_node_config(7891, "node-b")).await;
    assert!(rt.pending_switch.read().unwrap().is_some());

    rt.finish_lifecycle(LifecycleKind::Stop);
    assert!(
        rt.gate.pending().is_empty(),
        "stop 终态必须丢弃 gate 内全部 pending"
    );
    assert!(
        rt.pending_switch.read().unwrap().is_none(),
        "stop 终态必须同步清掉暂存的 switch 载荷"
    );
}

/// **生命周期 PUSH 与差集 PUSH 的配对守卫**（接线级，锚点失配自带 panic）。
///
/// `ready`/`stopped` 两个 phase 必须与 `push_pending_changes()` **严格同处、紧邻**：它们是同一次
/// 跃迁的两个投影。分开放（哪怕只是挪到同方法的另一段）就会出现「差集清了但态没翻」或反过来 ——
/// 而这两种不一致在真机上都表现为「点了没反应」，正是本轮要根除的形态。
///
/// `failed` **刻意不在这一对里**（因果在 `push_lifecycle` 头注：起核失败不改变差集的分母），
/// 但它必须落在 `start` 包装的 `Err` 腿 —— 那是全部起核入口的唯一汇流点。挪进任一条具体失败腿
/// 就会漏掉别的入口，而漏掉的那些正是「没人在 await」的托盘 / 自动连接 / 去抖重启。
///
/// 变异对照：把 `start` 成功腿里那两行的顺序颠倒、或在中间插一条语句 → 第一条转红；
/// 删掉 `start` 包装里的 `failed` 腿 → 第三条转红。
#[test]
fn lifecycle_push_is_paired_with_the_diff_push() {
    let src = module_code("runtime/proxy");
    const DIFF: &str = "self.push_pending_changes();";

    let started = method_body(
        &src,
        "    pub async fn start(self: &Arc<Self>, config: Value) -> Result<ProxyStatus, StartError> {",
    );
    assert!(
        line_immediately_followed_by(
            &started,
            DIFF,
            "self.push_lifecycle(&ProxyLifecycleEvent::ready());"
        ),
        "起核就绪腿：`ready` 必须紧跟差集 PUSH —— 两者描述同一次跃迁，拆开即引入可分叉的第二个时点"
    );

    let stopped = method_body(
        &src,
        "    pub(super) async fn stop_inner(self: &Arc<Self>) -> Result<bool, String> {",
    );
    assert!(
        line_immediately_followed_by(
            &stopped,
            DIFF,
            "self.push_lifecycle(&ProxyLifecycleEvent::stopped());"
        ),
        "停核拆除腿：`stopped` 必须紧跟差集 PUSH（与起核腿严格对偶）"
    );

    let start_wrap = method_body(
        &src,
        "    pub async fn start(self: &Arc<Self>, config: Value) -> Result<ProxyStatus, StartError> {",
    );
    assert!(
        start_wrap.contains("if let Err(e) = &r {")
            && start_wrap.contains("self.push_lifecycle(&ProxyLifecycleEvent::failed(e));"),
        "`failed` 必须挂在 `start` 包装的 Err 腿（全部起核入口的唯一汇流点）——\
             挪进具体失败腿会漏掉托盘 / 自动连接 / 去抖重启这些「没人在 await」的入口"
    );
}

/// systemProxy 的 `ready` 是“接管事务已落定”，不能只是“核端口已监听”。
///
/// 真机回归（Windows 2026-08-21）：旧顺序先 PUSH ready，主窗立即刷新到 `running:true` 并读取注册表，
/// 而 `enable_system_proxy` 仍在随后约 1.1s 的 `reg` 腿中；于是横幅瞬时误报，并因正常轮询为 15s 而
/// 长时间残留。无真核的单测无法跑完整 `start_inner`，故以源码顺序守卫锁住这个 I/O 边界；
/// `maybe_enable_system_proxy` 自身的模式/成功/失败行为由下方 A1 行为测试覆盖。
///
/// 变异对照：把 ready PUSH 挪回 enable 之前 → 本条转红。
#[test]
fn system_proxy_enable_settles_before_ready_lifecycle_push() {
    let src = module_code("runtime/proxy");
    let inner = method_body(&src, "    pub(super) async fn start_inner(");
    assert!(
        inner.contains("self.maybe_enable_system_proxy(&user_config, mixed_port)"),
        "start_inner 必须等待系统代理启用腿"
    );
    assert!(
        !inner.contains("self.push_lifecycle(&ProxyLifecycleEvent::ready());"),
        "start_inner 尚未归还 starting 计数，不得提前发布 ready"
    );
    let started = method_body(
        &src,
        "    pub async fn start(self: &Arc<Self>, config: Value) -> Result<ProxyStatus, StartError> {",
    );
    let inner_return = started
        .find("let r = self.start_inner(config, my_gen).await;")
        .expect("start 包装必须等待 start_inner 完整事务");
    let drop_inflight = started
        .find("drop(inflight);")
        .expect("ready 前必须归还 starting 计数");
    let ready = started
        .find("self.push_lifecycle(&ProxyLifecycleEvent::ready());")
        .expect("start 成功终态必须发布 ready 生命周期");
    assert!(
        inner_return < drop_inflight && drop_inflight < ready,
        "必须完整等待接管事务并归还 starting 计数后再发布 ready"
    );
}

/// 活态查询的模式必须取 `startup_snapshot` 这份**运行核快照**，不能取结构重启去抖前已被
/// `apply_restart` 前推的新 `current_config`。
#[test]
fn running_proxy_mode_type_tracks_the_running_snapshot_only() {
    let (rt, _dir) = test_runtime();
    mark_running(&rt);
    for (mode, expected) in [
        ("systemProxy", ProxyModeType::SystemProxy),
        ("tun", ProxyModeType::Tun),
        ("manual", ProxyModeType::Manual),
    ] {
        *rt.startup_snapshot.write().unwrap() = Some(serde_json::json!({
            "servers": [],
            "selectedServerId": "__direct__",
            "proxyMode": "smart",
            "proxyModeType": mode,
        }));
        // 精确复现结构切换窗口：current_config 已提交成相反的新模式，旧核仍按 startup snapshot 跑。
        *rt.current_config.write().unwrap() = Some(serde_json::json!({
            "servers": [],
            "selectedServerId": "__direct__",
            "proxyMode": "smart",
            "proxyModeType": if mode == "systemProxy" { "tun" } else { "systemProxy" },
        }));
        assert_eq!(rt.running_proxy_mode_type(), Some(expected));
    }
    *rt.startup_snapshot.write().unwrap() = None;
    assert_eq!(
        rt.running_proxy_mode_type(),
        None,
        "核在跑但无起核快照时必须返回 unknown，不能回落到已前推的 current_config"
    );
    *rt.status.write().unwrap() = ProxyStatus::default();
    assert_eq!(
        rt.running_proxy_mode_type(),
        None,
        "核未运行时不得把残留 current_config 冒充运行模式"
    );
}

/// 停止终态必须丢弃 pending（停止优先，不得停后又被拉起）——接线 end(Stop) 的语义。
#[tokio::test]
async fn stop_terminal_discards_pending_force_restart() {
    let (rt, _dir) = test_runtime();
    rt.gate.begin();
    let _ = rt.apply_pending().await; // deferred，置下 pending
    assert!(rt.pending_force_restart.read().unwrap().is_some());

    // 收尾为 Stop → 丢弃全部 pending，且本层的专用快照同步清空。
    rt.finish_lifecycle(LifecycleKind::Stop);
    assert!(
        rt.gate.pending().is_empty(),
        "stop 终态必须丢弃 gate 内全部 pending"
    );
    assert!(
        rt.pending_force_restart.read().unwrap().is_none(),
        "stop 终态必须同步清掉本层 force-restart 快照，否则下次排空会重启到陈旧 cfg"
    );
}

// ══════════════════════════════════════════════════════════════════════════════
// 维度7 #8：start 失败腿清系统代理（**组合面门**，§K7.1）
//
// §K7.1 教训：「光测 ensure_cleared 函数、光测 start 失败」都不够——两扇门之间的缝才是生产路径。
// 故这里打的是 `start 真失败 → controller 真被调 → mock 记录到 ensure_cleared 被触发` 这条组合路径，
// 并单独覆盖 restart 失败腿（本不变式的主场景）。本机绝不真跑 networksetup/gsettings/reg。
//
// 坏配置（非对象 JSON）→ UserConfig 反序列化在 start_inner **第一步**即失败 → 不 spawn、不写盘、
// 不解析端口 → 返回 Err，零宿主副作用。`stale_sweep_disabled=true` 预置跳过 /proc 孤儿清扫。
// ══════════════════════════════════════════════════════════════════════════════

/// 组合面：`start` 真失败（世代未被接管）→ 系统代理收口器**真被调**（维度7 #8 主门）。
#[tokio::test]
async fn start_failure_invokes_system_proxy_clearer() {
    let (rt, _dir, calls) = test_runtime_recording();
    rt.stale_sweep_disabled.store(true, Ordering::SeqCst); // 跳过孤儿清扫（/proc 扫描），聚焦失败腿。
    let r = rt.start(bad_config()).await;
    assert!(r.is_err(), "坏配置必失败");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "起核失败（世代未变）必触发系统代理收口——组合路径必须走通"
    );
}

/// 组合面·**主场景**：`restart` 的 start 腿失败 → 系统代理收口器真被调（重启失败→死端口→全网断）。
/// 挂 command 层会漏掉这条腿（restart 内部直调 self.start，不经 command）——这正是必须挂 public
/// `start` 而非 command 的证据。
#[tokio::test]
async fn restart_start_leg_failure_invokes_system_proxy_clearer() {
    let (rt, _dir, calls) = test_runtime_recording();
    rt.stale_sweep_disabled.store(true, Ordering::SeqCst);
    // 无旧核快照，restart 的跨模式收口门不命中；start(bad) 失败腿负责清。
    let r = rt.restart(bad_config()).await;
    assert!(r.is_err(), "restart 的 start 腿坏配置必失败");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "restart 的 start 腿失败必收口（主场景）；stop_inner 腿不清 → 恰好一次"
    );
}

// ══════════════════════════════════════════════════════════════════════════════
// FX-proxy-A 修复批变异防线（proxy-lifecycle 域 + config-gen I/O 落盘）
// ══════════════════════════════════════════════════════════════════════════════

// ── Fix 1：restart() 全程 depth≥1 不变式 ──

/// 机制门（纯 gate 序列）：restart 外层 begin/finish 包裹下，内层 stop 的 end(Stop) 在 depth 1 命中
/// `StillBusy`（**不丢弃**暂存 switch），外层 end(Restart) 归 0 时排空重放它。
#[test]
fn restart_wrapper_keeps_depth_positive_so_inner_stop_does_not_discard() {
    let g = LifecycleGate::default();
    g.begin(); // restart 外层 begin → depth 1
    g.set_switch_pending(7); // 窗口内暂存 switch
    g.begin(); // 内层 stop begin → depth 2
    let r_stop = g.end(LifecycleKind::Stop); // → depth 1
    assert!(
        matches!(r_stop, LifecycleEndResult::StillBusy(1)),
        "内层 stop 须 StillBusy，不落 Stopped 终态丢弃"
    );
    assert_eq!(g.pending().switch_id, Some(7), "包裹下暂存 switch 存活");
    g.begin(); // 内层 start begin → depth 2
    let r_start = g.end(LifecycleKind::Start); // → depth 1
    assert!(matches!(r_start, LifecycleEndResult::StillBusy(1)));
    let r_restart = g.end(LifecycleKind::Restart); // → depth 0
    match r_restart {
        LifecycleEndResult::Drained(d) => {
            assert_eq!(
                d.replay_switch_id,
                Some(7),
                "外层归 0 时排空重放暂存 switch"
            );
        }
        other => panic!("expected Drained, got {other:?}"),
    }
}

/// 反证门：**无**外层包裹 → 内层 stop 在 depth 0 命中 `Stopped` 终态 → 丢弃暂存 switch（drifted 缺陷）。
#[test]
fn without_restart_wrapper_inner_stop_discards_pending_switch() {
    let g = LifecycleGate::default();
    g.set_switch_pending(7);
    g.begin(); // 仅 stop（无外层）→ depth 1
    let r = g.end(LifecycleKind::Stop); // → depth 0
    let LifecycleEndResult::Stopped(d) = r else {
        panic!("无包裹时 stop 在 depth 0 应落 Stopped")
    };
    assert_eq!(
        d.discarded_switch_id,
        Some(7),
        "无包裹时 stop 终态吞掉暂存 switch"
    );
}

/// wiring 门：`restart()` 外层包裹使暂存 switch 在收尾（depth 0 Restart）被**重放**而非丢弃。
/// 变异（删掉 restart 的 `gate.begin()`/`finish_lifecycle(Restart)`）→ 内层 stop 在 depth 0 丢弃暂存
/// switch → 无重放 → current_config 永不更新 → 下方轮询超时 → 转红。start 腿用坏配置快速失败（不 spawn 真核）。
#[tokio::test]
async fn restart_replays_pending_switch_via_outer_lifecycle_wrapper() {
    let (rt, _dir) = test_runtime();
    rt.stale_sweep_disabled.store(true, Ordering::SeqCst);
    // 暂存一条 switch（核未运行 → 重放的 switch_mode 走 NotRunning 分支落 current_config，无真核、可观测）。
    let switch_cfg = serde_json::json!({ "servers": [], "selectedServerId": "__direct__", "marker": "replayed" });
    let id = rt.switch_seq.fetch_add(1, Ordering::SeqCst);
    *rt.pending_switch.write().unwrap() = Some((id, switch_cfg.clone(), false));
    rt.gate.set_switch_pending(id);

    let _ = rt.restart(bad_config()).await; // start 腿坏配置快速失败，不 spawn。

    // 轮询 current_config 直到被重放的 switch 落定（spawn 的重放任务近即执行；有界等待防超长）。
    let mut replayed = false;
    for _ in 0..50 {
        if rt.current_config.read().unwrap().as_ref() == Some(&switch_cfg) {
            replayed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        replayed,
        "restart 外层收尾须重放暂存 switch（wrapper 缺失则内层 stop 丢弃 → current_config 永不更新）"
    );
}

// ══════════════════════════════════════════════════════════════════════════════
// 起核可取消（真机事故「点连接锁死 UI ≈35s、启动卡死阶段无法关闭启动过程」的后端半）
//
// 事故形状：TUN 模式起核，孤儿 root 核锁死 cache 文件 → 核起来跑 ~9s 后 FATAL → 预算内重试
// （3 次尝试 × ~9s + 2s/4s 退避）。让位检查点本来就齐（spawn 前持锁判 / 就绪门 / Dead·Timeout
// 世代复查 / 就绪后复查），但它们**只在迭代边界执行** —— 卡在等待里时取消要静默等本轮走完。
//
// 下面四条门分别锁死：① 退避真被中断（非等睡满）② 取消腿落干净终态·无孤儿
// ③ 唤醒边沿不丢（bump 早于注册也算）④ 没取消时绝不误中断（正常重试预算跑满）。
// ══════════════════════════════════════════════════════════════════════════════

/// ④ 无人接管 → 睡满并返 `false`（**改过头门**）。
///
/// 变异：让 `sleep_unless_superseded_on` 无条件返 true / 让 select 的取消腿凭空提前完成 →
/// 本测两条断言（返回值 + 实际耗时）同时转红。没有这条，「可取消」很容易做成「起核腿被自己
/// 的取消信号打断」= 正常启动路径再也跑不完。
#[tokio::test]
async fn sleep_unless_superseded_sleeps_full_span_when_nobody_takes_over() {
    let gate = LifecycleGate::default();
    let signal = Notify::new();
    let my_gen = gate.generation();
    let t0 = std::time::Instant::now();
    let taken =
        sleep_unless_superseded_on(&gate, &signal, my_gen, Duration::from_millis(120)).await;
    let elapsed = t0.elapsed();
    assert!(
        !taken,
        "无人 bump 世代 → 必须报「未被接管」，否则正常起核会被自己的取消腿打断"
    );
    assert!(
        elapsed >= Duration::from_millis(110),
        "无人接管时必须睡满（实得 {elapsed:?}）—— 提前返回 = 退避被架空，重试节奏失真"
    );
}

/// ① 等待期被接管 → **立刻**醒（不是等睡满）。
///
/// 变异：把 select 换回裸 `tokio::time::sleep(dur).await` → 取消要 3s 后才被发现 → 耗时断言转红。
/// 这条就是「等 35s」那个形态的最小复现：等待本身不可中断时，取消只能在下一个迭代边界生效。
#[tokio::test]
async fn sleep_unless_superseded_wakes_immediately_on_takeover() {
    let gate = Arc::new(LifecycleGate::default());
    let signal = Arc::new(Notify::new());
    let my_gen = gate.generation();
    let (g2, s2) = (Arc::clone(&gate), Arc::clone(&signal));
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(30)).await;
        g2.bump_generation(); // ＝ stop() 入口做的事
        s2.notify_waiters();
    });
    let t0 = std::time::Instant::now();
    let taken = sleep_unless_superseded_on(&gate, &signal, my_gen, Duration::from_secs(3)).await;
    let elapsed = t0.elapsed();
    assert!(taken, "世代已变 → 必须报「被接管」");
    assert!(
        elapsed < Duration::from_millis(600),
        "取消必须就地生效（实得 {elapsed:?}，退避全长 3s）—— 等睡满即回归事故形态"
    );
}

/// ③ 唤醒边沿不丢：bump 发生在**注册之前**（信号已丢）也必须立刻判出被接管。
///
/// 变异：删掉 `enable()` 之后那次世代复查、只靠 `notified` 分支 → `notify_waiters` 不留 permit ⇒
/// 本测挂到睡满才返回 → 耗时断言转红。这是「信号 vs 真值」分工的门：信号会过期，世代不会。
#[tokio::test]
async fn sleep_unless_superseded_catches_takeover_that_happened_before_registration() {
    let gate = LifecycleGate::default();
    let signal = Notify::new();
    let my_gen = gate.generation();
    gate.bump_generation();
    signal.notify_waiters(); // 无等待者 → 通知即丢，只剩世代这条持久事实
    let t0 = std::time::Instant::now();
    let taken = sleep_unless_superseded_on(&gate, &signal, my_gen, Duration::from_secs(3)).await;
    assert!(
        taken,
        "注册前就发生的 bump 必须被复查捕获（信号已丢，世代还在）"
    );
    assert!(
        t0.elapsed() < Duration::from_millis(300),
        "应即刻返回，而非睡满"
    );
}

/// ① `bump_generation` 必须与唤醒同点落值 —— 绕过它直接 `gate.bump_generation()` 即回归。
///
/// 两腿对照：走 wrapper 的腿 ~即刻醒；绕过 wrapper 的腿只能等睡满（正是「静默等 35s」）。
/// 变异：把 wrapper 里的 `notify_waiters()` 删掉 → 第一条腿退化成第二条 → 转红。
#[tokio::test]
async fn bump_generation_wakes_waiters_but_raw_gate_bump_does_not() {
    let (rt, _dir) = test_runtime();
    let my_gen = rt.gate.generation();

    // 腿 A：走 `ProxyRuntime::bump_generation`（生产路径）→ 立刻醒。
    let rt_a = Arc::clone(&rt);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(30)).await;
        rt_a.bump_generation();
    });
    let t0 = std::time::Instant::now();
    assert!(
        rt.sleep_unless_superseded(my_gen, Duration::from_secs(3))
            .await
    );
    let via_wrapper = t0.elapsed();
    assert!(
        via_wrapper < Duration::from_millis(600),
        "经 bump_generation 的接管必须就地唤醒在飞起核腿（实得 {via_wrapper:?}）"
    );

    // 腿 B：绕过 wrapper 直接动 gate（＝把 `self.bump_generation()` 写回 `self.gate.bump_generation()`）。
    // 世代确实变了，但没人被叫醒 → 只能等睡满才发现。对照证明「唤醒」这一半是真在起作用的。
    let my_gen_b = rt.gate.generation();
    let rt_b = Arc::clone(&rt);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(30)).await;
        rt_b.gate.bump_generation(); // 刻意绕过 wrapper
    });
    let t1 = std::time::Instant::now();
    assert!(
        rt.sleep_unless_superseded(my_gen_b, Duration::from_millis(400))
            .await
    );
    assert!(
        t1.elapsed() >= Duration::from_millis(380),
        "绕过 wrapper 时只能等睡满 —— 这条对照一旦变快，说明有第二个发信点（真值源分叉）"
    );
}

/// 变异②守卫：成功/让位腿（`Ok`）绝不清系统代理（去掉 success 守卫 → 本测转红）。
#[tokio::test]
async fn success_leg_never_clears_system_proxy() {
    let (rt, _dir, calls) = test_runtime_recording();
    let g = rt.gate.generation();
    rt.maybe_clear_system_proxy_on_start_failure(&Ok(ProxyStatus::default()), g)
        .await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "成功腿绝不清——正在跑的核的系统代理不能被误清"
    );
}

/// 变异①守卫（stopping）：世代已被更新的 stop/start 接管的失败**不清**（去掉世代守卫 → 转红）。
/// stop 入口必先 bump_generation，故「被主动停止/更新覆盖」⟺「世代已变」。
#[tokio::test]
async fn superseded_failure_does_not_clear_system_proxy() {
    let (rt, _dir, calls) = test_runtime_recording();
    let my_gen = rt.gate.generation();
    rt.gate.bump_generation(); // 模拟并发 stop/start 接管（stop 入口先 bump）。
    rt.maybe_clear_system_proxy_on_start_failure(
        &Err(StartError::from("boom".to_string())),
        my_gen,
    )
    .await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "被接管的失败不清（stopping 守卫）——交接管方收口，防 C1 清了又被设回"
    );
}

/// 变异①守卫（正例）：世代**未变**的真失败必清（与上一条构成守卫的双向锁）。
#[tokio::test]
async fn same_generation_failure_clears_system_proxy() {
    let (rt, _dir, calls) = test_runtime_recording();
    let g = rt.gate.generation();
    rt.maybe_clear_system_proxy_on_start_failure(&Err(StartError::from("boom".to_string())), g)
        .await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "世代未变的真失败（本想启动却失败）必清"
    );
}

/// 变异③相邻：**真实生产控制器**（无 marker）挂在 start 失败腿上必须完全惰性——
/// 返回 Err 且**不凭空造出 marker 文件**（门控 1 在任何系统调用前短路）。这证明「fresh start
/// 无 marker → no-op」这条「挂每个失败腿都安全」的前提，在**真装配**（非 mock）上成立。
/// （`ensure_cleared` 本身的门控 1 幂等由 system-integration 的
/// `ensure_cleared_noop_without_marker` / `production_proxy_controller_is_inert_without_marker` 锁死。）
#[tokio::test]
async fn production_controller_inert_on_start_failure() {
    let (rt, dir) = test_runtime(); // 真实 production_proxy_controller + 临时 marker 路径。
    rt.stale_sweep_disabled.store(true, Ordering::SeqCst);
    let marker = dir.join(polaris_system_integration::PROXY_MARKER_FILENAME);
    assert!(!marker.exists(), "前置：无 marker");
    let r = rt.start(bad_config()).await;
    assert!(r.is_err(), "坏配置必失败");
    assert!(
        !marker.exists(),
        "无 marker 的失败收口必须零副作用——绝不凭空造 marker / 触碰系统代理"
    );
}

/// 组合面·**对称门**：主动停止（`stop`）真调系统代理收口器（维度7 #8 对称面）。停核后系统代理若仍
/// 指向刚被杀的本地死端口 → 全网断，故 `stop` 必须像 start 失败腿一样过 `ensure_cleared`。
/// 打生产入口 `stop`（非直调 `clear_system_proxy`），断言收口器**真被接线到停止路径**——§K7.1
/// 「两扇门之间的缝才是生产路径」。marker 门控幂等由 system-integration 单测锁死，本处只验接线。
#[tokio::test]
async fn deliberate_stop_invokes_system_proxy_clearer() {
    let (rt, _dir, calls) = test_runtime_recording();
    rt.stop().await.expect("停核应成功（清理失败也不阻断停止）");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "主动停止必调一次 ensure_cleared（清指向死端口的系统代理）"
    );
}

/// 🔴 **超预算残 stop 的晚落地换代毒性**：拆除途中被新会话接管 → 余下步骤整段让位。
///
/// # 复现的真机形态
///
/// `helper_uninstall` 的看门狗收停是**有预算**的（`WATCHDOG_JOIN_BUDGET`）：在飞的 `proxy.stop()`
/// 挂过 20s（macOS `networksetup` exec 卡死 / `spawn_blocking` 饥饿）后命令直接返回，那次 stop 成为
/// **残任务**继续挂着。用户此时重装 helper 并起了新核 —— 残 stop 随后醒来，后半段每一步都落在
/// **新会话**上：抹 running 态、清新核的 race sidecar 注入态（节点域名解析静默 SERVFAIL）、
/// 还原新核接管的系统 DNS、清掉新会话刚设好的系统代理。
///
/// # 窗口是**确定性**的，不靠 sleep 赌时序
///
/// 测试先占住 `mesh.exit_route` 锁：那是 `stop_inner` 拆除段第一个必然挂起的 await
/// （`lock().await` 拿不到就一定 Pending）⇒ 停核腿**不可能**越过它。于是「等它 bump 出自己的世代
/// → 再 bump 一次冒充新 start → 放锁」这个序列，必然把换代插在它的某个检查点之前。
/// （current_thread 运行时：观测到世代变化与随后的 `bump_generation()` 之间没有 await，
/// 停核腿不可能在这两句之间推进。）
///
/// **变异实跑**：删掉 `stop_inner` 里任一 `stop_superseded` 早退 → 对应断言转红；
/// 把 `stop` 的 `if self.stop_inner().await?` 改回无条件 `clear_system_proxy()` → 第三条转红。
#[tokio::test]
async fn superseded_stop_teardown_stands_down_instead_of_clobbering_the_new_session() {
    let (rt, _dir, clears) = test_runtime_recording();
    let refreshes: ExitIpRefreshes = Arc::new(Mutex::new(Vec::new()));
    rt.set_error_emitter(Box::new(RecordingErrorEmitter {
        exit_ip_refreshes: Arc::clone(&refreshes),
        ..Default::default()
    }));
    // 冒充「新会话已经起来了」：running 态 + 热切基准快照。残 stop 不让位就会把两者一起抹掉。
    if let Ok(mut g) = rt.status.write() {
        g.running = true;
    }
    if let Ok(mut g) = rt.switch_snapshot.write() {
        *g = Some(SwitchSnapshot::default());
    }
    // 新会话已提交的 sidecar 注入态：残 stop 的 `clear_race_server()`（`None` 腿无条件清）会把它
    // 抹成 0 ⇒ 新核 config 里烧的端口没人听 ⇒ 节点域名解析静默 SERVFAIL。
    rt.set_race_server(5353, Vec::new(), Vec::new());

    let gen0 = rt.gate.generation();
    // 占位任务先拿住 exit_route 锁（拿到才发 `acquired`），停核腿于是必然堵在那个 await 上。
    let (acquired, release) = (
        Arc::new(tokio::sync::Notify::new()),
        Arc::new(tokio::sync::Notify::new()),
    );
    let holder = {
        let (mesh, a, r) = (
            Arc::clone(&rt.mesh),
            Arc::clone(&acquired),
            Arc::clone(&release),
        );
        tokio::spawn(async move { mesh.occupy_exit_route_lock_for_test(a, r).await })
    };
    acquired.notified().await;
    let stopper = {
        let rt = Arc::clone(&rt);
        tokio::spawn(async move { rt.stop().await })
    };
    // 等停核腿领到它自己的世代（= 已进 stop_inner），且它此刻必然堵在 exit_route 锁上。
    let mut spins = 0;
    while rt.gate.generation() == gen0 {
        tokio::task::yield_now().await;
        spins += 1;
        assert!(spins < 10_000, "停核腿始终没 bump 世代 —— 前置假设已失效");
    }
    rt.bump_generation(); // ← 新一轮 start 接管（用户重装 helper 后点了连接）
    release.notify_one(); // 放锁：停核腿醒来，撞上换代守卫
    holder.await.expect("占位任务不得 panic");
    stopper
        .await
        .expect("停核任务不得 panic")
        .expect("stop 恒 Ok");

    assert!(
        rt.status().running,
        "残 stop 让位后不得把新会话的 running 态抹成 default（前端会显示「已断开」而核还跑着）"
    );
    assert!(
        rt.switch_snapshot.read().unwrap().is_some(),
        "让位后不得清掉新会话的热切基准（清了 ⇒ 下次 switch_mode 拿不到 id→tag 基准）"
    );
    assert_eq!(
        rt.race_server_port(),
        5353,
        "让位后不得清新会话的 race sidecar 注入态（清了 ⇒ 内核对死口做节点域名解析，静默 SERVFAIL）"
    );
    assert_eq!(
        clears.load(Ordering::SeqCst),
        0,
        "让位后不得清系统代理：此刻的系统代理属**新会话**，清了 = 用户全网走直连"
    );
    assert!(
        refreshes.lock().unwrap().is_empty(),
        "让位后不得按「停核」语义重探出口 IP（新核跑着，直连出口不是真值）"
    );
}

/// 正例（与上一条构成双向锁）：**没有**换代时，停核腿必须照常跑完全部拆除并清系统代理。
///
/// 缺这条，「让位判据写成恒真」就是一条无声的回归：停核从此什么都不做，而上面那条照样绿。
#[tokio::test]
async fn unsuperseded_stop_completes_the_whole_teardown() {
    let (rt, _dir, clears) = test_runtime_recording();
    let refreshes: ExitIpRefreshes = Arc::new(Mutex::new(Vec::new()));
    rt.set_error_emitter(Box::new(RecordingErrorEmitter {
        exit_ip_refreshes: Arc::clone(&refreshes),
        ..Default::default()
    }));
    if let Ok(mut g) = rt.status.write() {
        g.running = true;
    }
    if let Ok(mut g) = rt.switch_snapshot.write() {
        *g = Some(SwitchSnapshot::default());
    }
    rt.set_race_server(5353, Vec::new(), Vec::new());

    rt.stop().await.expect("stop 恒 Ok");

    assert!(
        !rt.status().running,
        "未被接管 → running 态必须被抹成 default"
    );
    assert!(
        rt.switch_snapshot.read().unwrap().is_none(),
        "未被接管 → 热切基准必须失效"
    );
    assert_eq!(
        rt.race_server_port(),
        0,
        "未被接管 → sidecar 注入态必清（下次起核按新配置重建）"
    );
    assert_eq!(clears.load(Ordering::SeqCst), 1, "未被接管 → 系统代理必清");
    assert_eq!(
        *refreshes.lock().unwrap(),
        vec![false],
        "未被接管 → 按停核语义零延迟重探直连出口"
    );
}

/// 🟠 **配对扫描**：`stop_inner` 的拆除段里，**每一个 `.await` 之后都必须紧跟一次换代检查**，
/// 且二者严格交替。
///
/// # 为什么行为测试盖不住这一条
///
/// 上面那条行为测试只能证明「某一个检查点确实拦住了残 stop」—— 它在 `exit_route_clear` 那个
/// 挂起点造窗口，于是删掉别的检查点它照样绿。而每个 await 都是一个独立的挂机窗口（`kill_core`
/// 的 SIGTERM→宽限→SIGKILL / helper 阻塞 IPC、`restore_system_dns` 的两次系统 exec），漏掉哪个
/// 都等于那一段的换代毒性原样保留。判据是**结构**的：换代只可能发生在让出执行权的地方，所以
/// 「await 数 == 检查数且交替」就是完备的配对条件，而且将来有人往拆除段加第四个 await 时会自动转红。
///
/// 牙：删掉任一 `stop_superseded` → 交替断言转红；往拆除段加一个不带检查的 `.await` → 同样转红。
#[test]
fn stop_teardown_yields_after_every_await() {
    let src = module_code("runtime/proxy");
    let body = method_body(
        &src,
        "    pub(super) async fn stop_inner(self: &Arc<Self>) -> Result<bool, String> {",
    );
    let mut marks: Vec<(usize, &str)> = body
        .match_indices(".await")
        .map(|(i, _)| (i, "await"))
        .chain(
            body.match_indices("self.stop_superseded(my_gen,")
                .map(|(i, _)| (i, "check")),
        )
        .collect();
    marks.sort_unstable();
    assert!(
        marks.len() >= 6,
        "锚点漂了或拆除段被改瘦：只扫到 {} 个标记（期望 ≥3 个 await + 3 次检查）",
        marks.len()
    );
    let seq: Vec<&str> = marks.into_iter().map(|(_, k)| k).collect();
    assert!(
        seq.len().is_multiple_of(2) && seq.chunks(2).all(|c| c == ["await", "check"]),
        "拆除段的 await 与换代检查必须严格交替（实得 {seq:?}）—— \
             缺检查的那个 await 就是残 stop 晚落地时的换代毒性窗口"
    );
}

/// 变异守卫（与上一条 + `restart_start_leg_failure` 构成双向锁）：`restart` 不得把系统代理清理无条件
/// 塞进共用的 `stop_inner`。此处没有旧运行快照，跨模式门不命中；start 腿用坏配置**必失败** → 全程
/// 唯一一次清来自 start 失败腿。若把清挂进 `stop_inner`，本测将读到 2 次而转红。
#[tokio::test]
async fn restart_stop_leg_does_not_clear_system_proxy() {
    let (rt, _dir, calls) = test_runtime_recording();
    rt.stale_sweep_disabled.store(true, Ordering::SeqCst); // 跳过 /proc 孤儿清扫，聚焦清理计数。
    let r = rt.restart(bad_config()).await;
    assert!(r.is_err(), "restart 的 start 腿坏配置必失败");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "无旧运行快照的 restart 全程恰一次清（来自 start 失败腿）；共用 stop_inner 不得无条件清"
    );
}

/// 接线门：纯真值表必须落在 `stop_inner` 之后、`start` 之前，并与 stop 的所有权返回值合取。
/// 少 `stop_completed` 会让已被新会话接管的残 restart 清掉接管方代理；挪到 start 后则 TUN 起核期间
/// 仍带着旧 OS 代理。行为逻辑由 `restart_system_proxy_cleanup_truth_table` 覆盖，这里只钉调用位置。
#[test]
fn restart_cross_mode_proxy_cleanup_is_owned_and_between_legs() {
    let body = method_body(
        &module_code("runtime/proxy"),
        "    async fn restart_inner(self: &Arc<Self>, config: Value) -> Result<ProxyStatus, StartError> {",
    );
    let stop = body
        .find("let stop_completed = self.stop_inner().await?;")
        .unwrap();
    let clear = body
        .find("if stop_completed && should_clear_system_proxy_between_restart(old_mode, new_mode)")
        .unwrap();
    let start = body.find("self.start(config).await").unwrap();
    assert!(
        stop < clear && clear < start,
        "跨模式代理收口必须位于 owned stop 与新 start 之间；实际方法体：\n{body}"
    );
    assert!(
        body[clear..start].contains("self.clear_system_proxy().await;"),
        "判定命中后必须复用 marker 门控的统一清理点；实际方法体：\n{body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "真机验证：需 POLARIS_SINGBOX_PATH 指向真实 sing-box；非 CI 门"]
async fn real_core_full_lifecycle() {
    let _real_core_guard = lock_real_core_tests().await;
    use futures::StreamExt;
    use polaris_singbox_grpc::{Endpoint, ReconnectConfig, SingBoxApiClient};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // 前置断言：env 未设即失败（不静默跳过）。resolve_core_binary 读同一个 env，
    // 故此处**不 set/remove**——两个真机测试同进程跑，改动进程级 env 会互相踩（实测：
    // 先跑完的那个 remove 掉，后跑的 require_core 直接 panic）。
    let (rt, dir, _core) = real_core_runtime();
    let mixed = free_port();
    // 装日志 sink：否则 log:: 全是 no-op，核的 stdout/stderr 无处可看（也顺带验证 logging.rs 接线）。
    crate::logging::init(&dir);

    // ── ① spawn + 就绪 ──────────────────────────────────────────────────────
    let st = rt
        .start(local_only_config(mixed))
        .await
        .expect("起核应成功");
    println!(
        "[①] start → running={} pid={} mixedPort={} apiPort={}",
        st.running, st.pid, st.mixed_port, st.clash_api_port
    );
    assert!(st.running, "start 后必须 running");
    assert_ne!(st.pid, 0, "必须拿到真实 pid");
    assert_eq!(
        st.mixed_port, mixed,
        "mixedPort 必须来自 config，不是硬编码 7890"
    );
    assert_ne!(st.clash_api_port, 0, "管理 API 端口必须已解析");
    assert!(
        ps_alive(st.pid),
        "[①] ps 必须能看到 pid={} —— 进程真在跑",
        st.pid
    );
    println!("[①] ps -p {} → 进程存在 ✓", st.pid);

    // ── ② 管理 API 真的通（h2c gRPC unary RPC，非 clash REST）─────────────────
    let client = SingBoxApiClient::connect(Endpoint::new("127.0.0.1", st.clash_api_port), "")
        .await
        .expect("[②] 管理 API gRPC 连接应成功");
    client
        .close_all_connections()
        .await
        .expect("[②] CloseAllConnections unary RPC 应成功返回");
    println!("[②] gRPC CloseAllConnections → OK（h2c 管理 API 真的通）✓");

    // ── ③ stats 数据面真的有数据 ────────────────────────────────────────────
    // `ReconnectingStream` 是**首次 poll 才真正连**的懒流：若只是建好流对象就去造流量，
    // 订阅其实尚未建立 → 错过该连接的 NEW 事件，能否看到它就取决于核会不会为一条空闲连接
    // 再补发 UPDATE ⇒ 测试随机红（实测 2 轮 1 红）。故这里**先起后台 drain 把订阅真正拉起**，
    // 再造流量，NEW 事件必到。
    let conn_stream =
        client.subscribe_connections(200_000_000 /* 200ms */, ReconnectConfig::default());
    let collected: Arc<Mutex<Vec<polaris_stats_engine::ConnectionEntry>>> =
        Arc::new(Mutex::new(Vec::new()));
    let sink = collected.clone();
    tokio::spawn(async move {
        let mut s = Box::pin(conn_stream);
        while let Some(ev) = s.next().await {
            for e in ev.events {
                if let Some(conn) = e.connection {
                    sink.lock()
                        .unwrap()
                        .push(polaris_stats_engine::ConnectionEntry {
                            id: conn.id.clone(),
                            chains: conn.chain_list.clone(),
                            rule: conn.rule.clone(),
                            metadata: None,
                            upload: Some(conn.uplink_total as u64),
                            download: Some(conn.downlink_total as u64),
                            start: None,
                        });
                }
            }
        }
    });
    let mut status_stream = client.subscribe_status(200_000_000, ReconnectConfig::default());
    // 等订阅真正建立（懒流首帧）后再造流量。
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 本地回显 HTTP 服务器（仅 127.0.0.1；不出网）。
    let srv = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let srv_port = srv.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = srv.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf).await;
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello-polar")
                    .await;
                // 保持连接开着，让 stats 有活连接可报。
                tokio::time::sleep(Duration::from_secs(6)).await;
            });
        }
    });

    // 经混合入站发一个 HTTP 代理请求（目标是本地回显服务器）。
    let mut c = tokio::net::TcpStream::connect(("127.0.0.1", mixed))
        .await
        .expect("[③] 混合入站应可连（端口来自 config）");
    let req =
        format!("GET http://127.0.0.1:{srv_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{srv_port}\r\n\r\n");
    c.write_all(req.as_bytes()).await.unwrap();
    let mut resp = vec![0u8; 128];
    let n = tokio::time::timeout(Duration::from_secs(5), c.read(&mut resp))
        .await
        .expect("[③] 经代理读响应超时")
        .expect("[③] 经代理读响应失败");
    let body = String::from_utf8_lossy(&resp[..n]);
    assert!(
        body.contains("200 OK"),
        "[③] 经混合入站的请求应拿到 200，实得：{body}"
    );
    println!(
        "[③] 经 mixed:{mixed} 代理请求 → {} ✓",
        body.lines().next().unwrap_or("")
    );

    // 等后台 drain 收到真实连接事件（拓扑 aggregate_connections 的供数源）。
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    while tokio::time::Instant::now() < deadline && collected.lock().unwrap().is_empty() {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let entries = collected.lock().unwrap().clone();
    assert!(
        !entries.is_empty(),
        "[③] Connections 流必须报出真实连接（拓扑 aggregate_connections 的供数源）"
    );
    println!("[③] Connections 流 → {} 条真实连接：", entries.len());
    for e in entries.iter().take(3) {
        println!(
            "      id={} rule={:?} chains={:?} up={:?} down={:?}",
            e.id, e.rule, e.chains, e.upload, e.download
        );
    }
    let agg = polaris_stats_engine::aggregate_connections(&entries, 0);
    println!("[③] aggregate_connections → {agg:?}");

    // Status 流也应给出真实数字。
    let s0 = tokio::time::timeout(Duration::from_secs(5), status_stream.next())
        .await
        .expect("[③] Status 流应在 5s 内出帧")
        .expect("[③] Status 流不应立即结束");
    println!(
        "[③] Status 流 → memory={} goroutines={} connectionsOut={} upTotal={} downTotal={}",
        s0.memory, s0.goroutines, s0.connections_out, s0.uplink_total, s0.downlink_total
    );
    assert!(
        s0.memory > 0 && s0.goroutines > 0,
        "[③] Status 必须是真实运行数据"
    );

    // ── ⑤ apply_pending 真实状态（运行中 + 非在飞 → applied）──────────────────
    let ap = rt.apply_pending().await;
    println!("[⑤] apply_pending（运行中）→ {ap}");
    assert_eq!(ap, "applied");

    // ── ④ 停核干净、无孤儿 ──────────────────────────────────────────────────
    let pid = st.pid;
    rt.stop().await.expect("停核应成功");
    assert!(!rt.status().running, "[④] stop 后 running 必须为 false");
    // 给 OS 一点收尾时间后用 ps 实证。
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !ps_alive(pid),
        "[④] stop 后 pid={pid} 必须不存在（无孤儿进程）"
    );
    println!("[④] stop → ps -p {pid} 已消失（无孤儿）✓");
}

/// ⑥ lifecycle race：起核在飞时快速 stop → 起核腿必须让位，且**不留孤儿**。
#[tokio::test(flavor = "multi_thread")]
#[ignore = "真机验证：需 POLARIS_SINGBOX_PATH 指向真实 sing-box；非 CI 门"]
async fn real_core_lifecycle_race_start_then_immediate_stop() {
    let _real_core_guard = lock_real_core_tests().await;
    let (rt, _dir, _core) = real_core_runtime();
    // 孤儿基线：快速起停 3 轮后系统内 sing-box 进程数不得增长。
    let baseline = singbox_proc_count();

    for round in 1..=3 {
        let mixed = free_port();
        let rt2 = rt.clone();
        let starter = tokio::spawn(async move { rt2.start(local_only_config(mixed)).await });
        // 不用固定 sleep 猜 spawn 是否发生：必须观测到真实 pid，且起核腿仍在飞，才允许 stop。
        // 否则安全门/前置失败会让本测「从未起核也通过」，正是本次修复要消灭的假阳性。
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let spawned_pid = loop {
            if let Some(pid) = *rt.pid.lock().unwrap() {
                break pid;
            }
            assert!(
                !starter.is_finished(),
                "[⑥] round{round}: 尚未观测到真实 pid，start 任务却已结束"
            );
            assert!(
                tokio::time::Instant::now() < deadline,
                "[⑥] round{round}: 5s 内未观测到真实 spawn"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        };
        assert!(
            rt.start_inflight.load(Ordering::SeqCst) > 0,
            "[⑥] round{round}: stop 前起核腿必须仍在飞"
        );
        assert!(
            ps_alive(spawned_pid),
            "[⑥] round{round}: 观测到的 pid={spawned_pid} 必须真实存活"
        );
        // 起核在飞（就绪门轮询中）时立刻 stop → bump 世代 → 起核腿 Superseded 让位。
        rt.stop().await.expect("stop 应成功");
        let started = starter.await.expect("start task 不应 panic");
        println!(
            "[⑥] round{round}: 已观测真实 pid={spawned_pid}，start 返回 {:?}，stop 已接管",
            started.map(|s| s.running)
        );

        assert!(
            !rt.status().running,
            "[⑥] round{round}: stop 后不得 running"
        );
        assert!(
            rt.child.lock().unwrap().is_none(),
            "[⑥] round{round}: stop 后不得残留 child 句柄"
        );
        assert!(
            rt.pid.lock().unwrap().is_none(),
            "[⑥] round{round}: stop 后不得残留 pid"
        );
    }
    // 全轮结束后系统里不应有本测试起的 sing-box 残留（起停竞态最易漏杀之处）。
    tokio::time::sleep(Duration::from_millis(500)).await;
    let after = singbox_proc_count();
    assert_eq!(
        after, baseline,
        "[⑥] 3 轮快速起停后 sing-box 进程数应回到基线 {baseline}，实得 {after} —— 起停竞态漏了孤儿"
    );
    println!(
        "[⑥] 3 轮快速起停完成：child 句柄已清 + sing-box 进程数 {baseline}→{after}（无孤儿）✓"
    );
}

#[test]
fn proxy_status_serializes_camel_case_contract() {
    // 前端契约：running / pid / startTime / uptime / error / errorCode / mixedPort / clashApiPort / startedViaHelper。
    let s = ProxyStatus {
        running: true,
        pid: 42,
        start_time: Some(1_700_000_000_000),
        uptime: Some(90),
        mixed_port: 7890,
        clash_api_port: 19090,
        error: Some("boom".to_string()),
        error_code: Some(code::STARTUP_FAILED.to_string()),
        started_via_helper: false,
        update_in_port: 45678,
        subscription_update_in_port: 45679,
        starting: false,
    };
    let v = serde_json::to_value(&s).unwrap();
    assert_eq!(v["running"], true);
    assert_eq!(v["pid"], 42);
    assert_eq!(v["mixedPort"], 7890);
    assert_eq!(v["clashApiPort"], 19090);
    assert_eq!(v["updateInPort"], 45678);
    assert_eq!(v["subscriptionUpdateInPort"], 45679);
    // 打断 startTime/errorCode 的 serde rename（写成 snake_case）→ 本测转红：
    // 前端 ProxyStatus 按 camelCase 读，名字错 = 字段又变成恒 undefined（正是本次修的 bug 形态）。
    assert_eq!(v["startTime"], 1_700_000_000_000_u64);
    assert_eq!(v["uptime"], 90);
    assert_eq!(v["error"], "boom");
    assert_eq!(v["errorCode"], "STARTUP_FAILED");

    // pid=0 / 未运行时省略（对齐 上游 `pid?` / `startTime?` / `uptime?` / `errorCode?`）。
    let z = ProxyStatus::default();
    let zv = serde_json::to_value(&z).unwrap();
    assert!(zv.get("pid").is_none());
    assert!(zv.get("startTime").is_none());
    assert!(zv.get("uptime").is_none());
    assert!(zv.get("errorCode").is_none());
    // starting 同样是「false 即省略」的可选字段（渲染端 `starting?: boolean`）。
    assert!(zv.get("starting").is_none());
    let sv = serde_json::to_value(ProxyStatus {
        starting: true,
        ..ProxyStatus::default()
    })
    .unwrap();
    assert_eq!(
        sv["starting"], true,
        "起核在飞必须出现在快照里 —— 托盘据它把「连接」换成「取消」，缺了就会叠第二次 start"
    );
}

// ══════════════════════════════════════════════════════════════════════════════
// startTime / uptime：运行时长真值 + 读时投影
// ══════════════════════════════════════════════════════════════════════════════

/// `status()` 必须**现算** uptime，而非回存储值（存储恒 None）。
/// 打断 `status()` 里的投影（改成直接 clone）→ 本测转红：那就是 Home「运行时长」恒空的老 bug。
#[test]
fn status_projects_uptime_from_start_time_on_read() {
    let (rt, _dir) = test_runtime();
    // 起点设在 90s 前，模拟已跑一阵的核。
    *rt.status.write().unwrap() = ProxyStatus {
        running: true,
        start_time: Some(now_ms() - 90_000),
        ..ProxyStatus::default()
    };
    // 存储态的 uptime 恒 None —— 投影只发生在读侧。
    assert!(rt.status.read().unwrap().uptime.is_none());
    let uptime = rt
        .status()
        .uptime
        .expect("running 时 status() 必须投影出 uptime");
    assert!(
        (89..=92).contains(&uptime),
        "uptime 应约等于 90s（现算），实得 {uptime}"
    );
}

/// 未运行（无 start_time）→ uptime 为 None，**不是 0**：
/// 0 会被前端 `fmtUptime` 渲染成「已运行 0 秒」= 谎称在跑。打断（改成 unwrap_or(0)）→ 本测转红。
#[test]
fn status_has_no_uptime_when_not_running() {
    let (rt, _dir) = test_runtime();
    assert!(rt.status().start_time.is_none());
    assert!(rt.status().uptime.is_none());
}

/// `set_error` 清空 start_time（错误终态 = 没在跑）→ uptime 随之消失。
/// 打断（set_error 保留 start_time）→ 本测转红：Home 会在核已崩时继续走字。
#[test]
fn set_error_clears_start_time_and_uptime() {
    let (rt, _dir) = test_runtime();
    *rt.status.write().unwrap() = ProxyStatus {
        running: true,
        start_time: Some(now_ms() - 5_000),
        ..ProxyStatus::default()
    };
    rt.set_error("核崩了", code::PROCESS_EXITED);
    let s = rt.status();
    assert!(!s.running);
    assert!(s.start_time.is_none());
    assert!(s.uptime.is_none());
}

/// **C 的全部价值所在**：起核失败在 UI 上必须**可辨**，而不是「差集也空了、看着像成功」。
///
/// 取的是 `set_error` 头注明列**不覆盖**的那一类（「config 生成 / 写盘 / spawn 失败」，理由是
/// 「有 command 在 await」）—— 而去抖重启这条路上**没有任何人在 await**
/// （`schedule_restart` 的回调只 `log::error!`）。故此前这一类失败对渲染端是**全静默**的：
/// 既无 `proxyStarted`（本就不发）也无 `proxyError`，条只能停在「应用中…」等 12s 兜底轮询。
///
/// 断言两件事：① 这一类确实**不发** `event:proxyError`（钉住前提，否则本条毫无意义）；
/// ② 但**必发**一条 `lifecycle{phase:"failed"}` 且带用户可见 message。
///
/// 变异对照：
/// - 删掉 `start` 包装里那个 `if let Err(e) = &r { push_lifecycle(failed) }` → ② 转红；
/// - 把它挪进某条具体失败腿（如只在 `set_error` 里发）→ ② 转红（本腿压根不经 `set_error`）；
/// - 给它加世代守卫并在此让位 → ② 转红。
#[tokio::test]
async fn start_failure_is_observable_even_when_it_never_reaches_set_error() {
    let (rt, _dir, errors, lifecycle) = test_runtime_recording_lifecycle();
    rt.stale_sweep_disabled.store(true, Ordering::SeqCst); // 跳过孤儿清扫（/proc 扫描），聚焦失败腿。

    let r = rt.start(bad_config()).await;
    assert!(r.is_err(), "前提：坏配置必失败");

    assert!(
        errors.lock().unwrap().is_empty(),
        "前提（钉住 set_error 的「不覆盖腿」清单）：这一类失败不经 set_error ⇒ 不发 proxyError。\
             若这条转红，说明失败分类的边界变了，本测的因果叙述需重写而非放宽"
    );

    let seen = lifecycle.lock().unwrap().clone();
    assert_eq!(
        seen.len(),
        1,
        "起核失败必发且只发一条 lifecycle，实际：{seen:?}"
    );
    assert_eq!(seen[0].phase, "failed");
    assert!(
        seen[0]
            .message
            .as_deref()
            .is_some_and(|m| !m.trim().is_empty()),
        "failed 腿必须带用户可见文案 —— 没有它，条只能显示一个说不清的红：{seen:?}"
    );
}

/// `restart` 的 start 腿失败同样可辨（**主场景**：「立即应用」→ 去抖重启 → 起核失败，无人 await）。
///
/// 与 `restart_start_leg_failure_invokes_system_proxy_clearer` 同一条路径、同一个理由：
/// 挂命令层会漏掉这条腿。这里额外钉住**顺序** —— 停核腿的 `stopped` 必须先到、起核失败的
/// `failed` 后到；顺序颠倒会让条先转红再被一条 `stopped` 抹回转圈。
///
/// 变异对照：把 `push_lifecycle(failed)` 挪到 `restart` 外层（`finish_lifecycle` 之后）→ 顺序仍对，
/// 但托盘/自动连接那两条入口不经 `restart` ⇒ 上一条测试转红。两条合起来才锁住「唯一汇流点」。
#[tokio::test]
async fn restart_start_leg_failure_emits_stopped_then_failed_in_order() {
    let (rt, _dir, _errors, lifecycle) = test_runtime_recording_lifecycle();
    rt.stale_sweep_disabled.store(true, Ordering::SeqCst);

    let r = rt.restart(bad_config()).await;
    assert!(r.is_err(), "前提：坏配置必失败");

    let phases: Vec<&str> = lifecycle.lock().unwrap().iter().map(|e| e.phase).collect();
    assert_eq!(
        phases,
        vec!["stopped", "failed"],
        "重启失败的可见序列必须是「停了 → 没回来」，实际：{phases:?}"
    );
}

/// 载荷契约：键集恰为 `{phase}`（ready/stopped）或 `{phase, errorCode?, message}`（failed），
/// camelCase，且 `ready`/`stopped` **不得**带 error 字段（带了前端就分不清成功与失败）。
///
/// 变异对照：去掉 `#[serde(rename_all = "camelCase")]` → `errorCode` 变 `error_code` → 转红；
/// 去掉两个 `skip_serializing_if` → ready 帧多出两个 `null` 键 → 转红。
#[test]
fn lifecycle_payload_contract_keys() {
    let ready = serde_json::to_value(ProxyLifecycleEvent::ready()).expect("可序列化");
    assert_eq!(
        ready,
        serde_json::json!({ "phase": "ready" }),
        "ready 帧只该有 phase —— 多一个 null 的 error 键就够前端写出错误的判据"
    );
    assert_eq!(
        serde_json::to_value(ProxyLifecycleEvent::stopped()).expect("可序列化"),
        serde_json::json!({ "phase": "stopped" })
    );
    let failed = serde_json::to_value(ProxyLifecycleEvent::failed(&StartError::coded(
        "核起不来",
        code::ROOT_ORPHAN_BLOCKED,
    )))
    .expect("可序列化");
    assert_eq!(
        failed,
        serde_json::json!({
            "phase": "failed",
            "errorCode": code::ROOT_ORPHAN_BLOCKED,
            "message": "核起不来",
        })
    );
    // 无码腿（`start_inner` 里绝大多数 `?`）：只省 errorCode，message 仍在。
    let uncoded = serde_json::to_value(ProxyLifecycleEvent::failed(&StartError {
        message: "写盘失败".into(),
        code: None,
    }))
    .expect("可序列化");
    assert_eq!(
        uncoded,
        serde_json::json!({ "phase": "failed", "message": "写盘失败" }),
        "无码不等于无消息 —— 省掉 message 会让条只能显示一个说不清的红"
    );
}

/// 截出**单个方法体**的源码文本（源码型守卫的唯一取材口）。
///
/// # 为什么不能直接 `&src[start..]`（本仓踩过的两次假绿）
///
/// 切到 EOF 的 `seg` 会让 `find` 命中**后文其它方法**里的同名调用：从目标方法里删掉那一行，
/// 顺序 / 接线断言照样绿。判据必须限定在这一个函数体内。
///
/// 边界判据是「行首恰好 4 空格 + `}`」—— `impl` 成员的收尾花括号就在这一列，而方法体内的一切
/// 嵌套块都 ≥8 空格。比「下一个 `fn `」稳：后者会把中间的 doc 注释一并算进 seg（注释里的示例代码
/// 就能让守卫误绿）。
///
/// # 为什么还要**剥掉整行注释**（与 `commands/misc::ipinfo_epoch_guard::fn_body` 对称）
///
/// 截出的方法体里仍含**体内注释**，而本模块有 `count() == 3` 这类**计数**断言
/// （见 [`ts_exit_recover_once_order_is_reapply_reassert_refresh`]）。计数断言对注释是敏感的：
/// 在方法体里写一行 `// if self.gate.generation() != my_gen {` 就能给计数充数 —— 真删掉一处
/// 世代守卫，守卫仍绿。位置断言（`find` 比大小）也同理会被注释里的锚点文本带偏。
/// 当前源码里没有这类命中，但「靠现状没撞上」不是判据 —— 剥掉才是。
///
/// 只剥**整行**注释（`trim_start().starts_with("//")`），与 misc.rs 逐字同款：行尾注释要剥就得
/// 分辨字符串字面量里的 `//`，那是把守卫的取材器写成半个词法分析器，代价与收益不成比例。
/// 在 `body` 里断言「含 `first` 的那一行，其**下一非空行**含 `second`」。
///
/// [`method_body`] 已把整行注释替换成空行 ⇒ 「紧邻」允许中间夹注释（说明因果本该写在那里），
/// 但不允许夹任何别的语句。找不到 `first` 即 **panic**（锚点失配自曝，绝不退化成恒真）。
fn line_immediately_followed_by(body: &str, first: &str, second: &str) -> bool {
    let lines: Vec<&str> = body.lines().filter(|l| !l.trim().is_empty()).collect();
    let i = lines
        .iter()
        .position(|l| l.contains(first))
        .unwrap_or_else(|| panic!("锚点 `{first}` 在该方法体内消失，配对守卫已失去判据"));
    lines.get(i + 1).is_some_and(|l| l.contains(second))
}

/// `set_error` → 真发 `event:proxyError`，且 message/errorCode 与落进状态的**同源**。
/// 打断 set_error 里的 emit（删掉那段 match）→ 本测转红 = 退回「通道定义了却零 emit」的原 bug。
#[test]
fn set_error_emits_proxy_error_event() {
    let (rt, _dir, events) = test_runtime_recording_errors();
    rt.set_error("sing-box 启动期退出", code::STARTUP_FAILED);
    let got = events.lock().unwrap().clone();
    assert_eq!(
        got,
        vec![(
            "sing-box 启动期退出".to_string(),
            "STARTUP_FAILED".to_string()
        )]
    );
    // 事件与状态快照同源（错过事件的 UI 仍能从 getStatus 读到同一个码）。
    let s = rt.status();
    assert_eq!(s.error.as_deref(), Some("sing-box 启动期退出"));
    assert_eq!(s.error_code.as_deref(), Some(code::STARTUP_FAILED));
}

/// 「启动失败」与「运行中崩了」必须靠 errorCode 分得开（brief 的硬要求）。
/// 打断（两条腿传同一个码）→ 本测转红。
#[test]
fn startup_failure_and_runtime_crash_carry_distinct_codes() {
    let (rt, _dir, events) = test_runtime_recording_errors();
    rt.set_error("起核超时", code::STARTUP_FAILED);
    rt.set_error("反复崩溃", code::AUTO_RESTART_FAILED);
    let codes: Vec<String> = events
        .lock()
        .unwrap()
        .iter()
        .map(|(_, c)| c.clone())
        .collect();
    assert_eq!(codes, vec!["STARTUP_FAILED", "AUTO_RESTART_FAILED"]);
}

// ══════════════════════════════════════════════════════════════════════════════
// event:systemProxyResidual 发射（#3：TUN 起核后无 marker 系统代理残留一次性提示）
//
// 注：**start_inner 内的调用点**（wait_ready 成功后）无法在本机验证——它须真核就绪，而本机
// 硬禁起核。故此处覆盖 `maybe_warn_system_proxy_residual` 的**全部决策逻辑**（TUN 门控 / 每会话
// 门闩 / detect→emit 路由），detect 侧的判定逻辑另在 `system-integration::detect_foreign_proxy`
// 单测 + 双变异验证；另用源码不变式锁住 start_inner 只能 spawn、不得 await advisory。
// ══════════════════════════════════════════════════════════════════════════════

/// TUN + 检测到别人的系统代理 → 发一条 residual（payload=proxy 串）。
/// 变异锁：把 `emit_system_proxy_residual` 调用删掉 → 零事件 → 转红。
#[tokio::test]
async fn residual_emitted_for_tun_with_foreign_proxy() {
    let clearer: Box<dyn SystemProxyClearer> = Box::new(ResidualClearer {
        found: Some("192.168.1.2:7890".into()),
    });
    let (rt, _dir, _f, residual) = test_runtime_recording_full(clearer);
    let cfg = tun_user_config();
    rt.maybe_warn_system_proxy_residual(cfg.proxy_mode_type, None)
        .await;
    assert_eq!(
        residual.lock().unwrap().clone(),
        vec!["192.168.1.2:7890".to_string()],
        "TUN + 检出残留 → 必发一条"
    );
}

/// 每会话只发一次（门闩）：连调两次仅一条事件。
/// 变异锁：删有效探测后的 `residual_warned.swap(..)` 门闩 → 两条 → 转红。
#[tokio::test]
async fn residual_warned_only_once_per_session() {
    let clearer: Box<dyn SystemProxyClearer> = Box::new(ResidualClearer {
        found: Some("10.0.0.1:1080".into()),
    });
    let (rt, _dir, _f, residual) = test_runtime_recording_full(clearer);
    let cfg = tun_user_config();
    rt.maybe_warn_system_proxy_residual(cfg.proxy_mode_type, None)
        .await;
    rt.maybe_warn_system_proxy_residual(cfg.proxy_mode_type, None)
        .await;
    assert_eq!(residual.lock().unwrap().len(), 1, "门闩：每会话仅一次");
}

/// 旧起核世代的慢探测只丢结果，不得消费本会话门闩；否则随后的有效世代不会再提示。
#[tokio::test]
async fn stale_residual_probe_does_not_consume_session_latch() {
    let clearer: Box<dyn SystemProxyClearer> = Box::new(ResidualClearer {
        found: Some("10.0.0.1:1080".into()),
    });
    let (rt, _dir, _f, residual) = test_runtime_recording_full(clearer);
    let mode = tun_user_config().proxy_mode_type;
    let stale_generation = rt.gate.generation().wrapping_add(1);

    rt.maybe_warn_system_proxy_residual(mode, Some(stale_generation))
        .await;
    assert!(residual.lock().unwrap().is_empty(), "陈旧世代不得发提示");

    rt.maybe_warn_system_proxy_residual(mode, None).await;
    assert_eq!(
        residual.lock().unwrap().as_slice(),
        ["10.0.0.1:1080"],
        "陈旧世代不得抢占本会话门闩"
    );
}

/// 非 TUN（系统代理模式）→ 绝不提示（系统代理模式下系统代理本就该开且是我们设的）。
/// 变异锁：删 TUN 门控 → 系统代理模式也发 → 转红。
#[tokio::test]
async fn residual_not_emitted_when_not_tun() {
    let clearer: Box<dyn SystemProxyClearer> = Box::new(ResidualClearer {
        found: Some("10.0.0.1:1080".into()), // 即便检出也不该发
    });
    let (rt, _dir, _f, residual) = test_runtime_recording_full(clearer);
    let mut cfg = tun_user_config();
    cfg.proxy_mode_type = polaris_config_engine::user_config::ProxyModeType::SystemProxy;
    rt.maybe_warn_system_proxy_residual(cfg.proxy_mode_type, None)
        .await;
    assert!(residual.lock().unwrap().is_empty(), "非 TUN 不提示");
}

/// TUN 但无残留（detect 返 None）→ 不发，但门闩已消耗（advisory 已「查过」）。
#[tokio::test]
async fn residual_none_when_no_foreign_proxy() {
    let clearer: Box<dyn SystemProxyClearer> = Box::new(ResidualClearer { found: None });
    let (rt, _dir, _f, residual) = test_runtime_recording_full(clearer);
    rt.maybe_warn_system_proxy_residual(tun_user_config().proxy_mode_type, None)
        .await;
    assert!(residual.lock().unwrap().is_empty());
}

/// 最小 TUN UserConfig（供 residual 决策测试）。
fn tun_user_config() -> UserConfig {
    serde_json::from_value(serde_json::json!({
        "servers": [],
        "selectedServerId": "__direct__",
        "proxyMode": "smart",
        "proxyModeType": "tun"
    }))
    .expect("最小 TUN 配置应可解析")
}

/// advisory 必须只 spawn，不能再次 await 回起核主链。行为测试无法在无真核环境量墙钟，
/// 因此用源码不变式锁住这条性能边界。
#[test]
fn system_proxy_residual_probe_never_blocks_start_inner() {
    let body = method_body(
        &module_code("runtime/proxy"),
        "    pub(super) async fn start_inner(",
    );
    // 两根针都**不带 `self.` 前缀**，理由与本文件 9733 那条守卫的注释逐字相同：
    // 调用点会被 rustfmt 折成 `self\n    .foo(`，带前缀的针会被换行静默打空。
    // 本仓当场就有这个形态的实证（`proxy.rs:3989-3990` 的 `self\n.probe_tun_adapter_present(`、
    // `proxy/system_takeover.rs:317-318` 的 `runtime\n.maybe_warn_system_proxy_residual(`）。
    // 其中**否定型**那根尤其致命：折行 ⇒ `contains` 恒 false ⇒ 断言恒绿，它要防的回退静默通过。
    // 同根因的姊妹腿（9733）当初做对了 —— 说明这里不是刻意取舍，是漏改。
    assert_eq!(
        body.matches(".spawn_system_proxy_residual_warning(")
            .count(),
        1,
        "起核成功段必须恰好 spawn 一次残留探测"
    );
    assert!(
        !body.contains(".maybe_warn_system_proxy_residual("),
        "残留提示只是 advisory，不得 await 回起核关键路径"
    );
}

/// 最小 systemProxy UserConfig（供 A1 启用侧决策测试）。
fn systemproxy_user_config() -> UserConfig {
    serde_json::from_value(serde_json::json!({
        "servers": [],
        "selectedServerId": "__direct__",
        "proxyMode": "smart",
        "proxyModeType": "systemProxy"
    }))
    .expect("最小 systemProxy 配置应可解析")
}

/// systemProxy 成功腿 → `enable` 真被调，且 req = `127.0.0.1:mixedPort`（http+socks 同口）+ 生效 bypass。
/// 变异锁：删掉 `maybe_enable_system_proxy` 里的 `g.enable_system_proxy(&req)` → 零 req → 转红。
#[tokio::test]
async fn enable_called_for_systemproxy_with_local_mixed_port() {
    let reqs = Arc::new(Mutex::new(Vec::new()));
    let clearer: Box<dyn SystemProxyClearer> = Box::new(EnableRecordingClearer {
        enable_reqs: Arc::clone(&reqs),
        ..Default::default()
    });
    let (rt, _dir, _f, _r) = test_runtime_recording_full(clearer);
    rt.maybe_enable_system_proxy(&systemproxy_user_config(), 7890)
        .await;
    let got = reqs.lock().unwrap().clone();
    assert_eq!(got.len(), 1, "systemProxy 成功腿必调 enable 一次");
    assert_eq!(got[0].address, "127.0.0.1", "本机应用经 loopback 连本地核");
    assert_eq!(got[0].http_port, 7890, "http 指向 mixedPort");
    assert_eq!(
        got[0].socks_port, 7890,
        "socks 同口 mixedPort（mixed 入站同口服务）"
    );
    // bypass 复用 config-engine 生效清单（缺省补 DEFAULT_BYPASS_LAN 的 27 条，含 loopback 段）。
    assert!(
        got[0].bypass_list.contains(&"127.0.0.0/8".to_string()),
        "bypass 应含默认私网/保留段，实得 {:?}",
        got[0].bypass_list
    );
}

/// tun / manual 模式绝不设 OS 系统代理（tun 走 TUN 接管、manual 用户自管）。
/// 变异锁：删 `should_enable_system_proxy` 门控 → 这些模式也调 enable → 转红。
#[tokio::test]
async fn enable_not_called_for_tun_or_manual() {
    for mode in [ProxyModeType::Tun, ProxyModeType::Manual] {
        let reqs = Arc::new(Mutex::new(Vec::new()));
        let clearer: Box<dyn SystemProxyClearer> = Box::new(EnableRecordingClearer {
            enable_reqs: Arc::clone(&reqs),
            ..Default::default()
        });
        let (rt, _dir, _f, _r) = test_runtime_recording_full(clearer);
        let mut cfg = systemproxy_user_config();
        cfg.proxy_mode_type = mode;
        rt.maybe_enable_system_proxy(&cfg, 7890).await;
        assert!(
            reqs.lock().unwrap().is_empty(),
            "{mode:?} 模式绝不设系统代理"
        );
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// A1 **失败腿**必须冒给用户（此前只 log::error! → 用户见「已连接」绿灯 + 全量直连 + 零提示）
// ══════════════════════════════════════════════════════════════════════════════

/// enable 恒失败的 clearer（不触碰宿主系统代理，本机硬约束）。
struct FailingEnableClearer;
impl SystemProxyClearer for FailingEnableClearer {
    fn ensure_cleared(&mut self) -> bool {
        false
    }
    fn detect_foreign_proxy(&self) -> Option<String> {
        None
    }
    fn enable_system_proxy(&mut self, _req: &ProxyEnableRequest) -> Result<(), String> {
        Err("networksetup 退出码 1".to_string())
    }
    fn recover_from_marker(&mut self) -> Result<bool, String> {
        Ok(false)
    }
}

/// **A1 失败 → 真 emit `event:proxyError`（SYSTEM_PROXY_FAILED）**，不再静默。
/// 变异锁：把失败腿改回只 `log::error!` → 零事件 → 转红（退回本 bug）。
#[tokio::test]
async fn a1_enable_failure_emits_proxy_error() {
    let (rt, _dir, events) = test_runtime_errors_with_clearer(Box::new(FailingEnableClearer));
    mark_running(&rt);
    rt.maybe_enable_system_proxy(&systemproxy_user_config(), 7890)
        .await;
    let got = events.lock().unwrap().clone();
    assert_eq!(got.len(), 1, "A1 失败必须发一条 proxyError，实得 {got:?}");
    assert_eq!(got[0].1, code::SYSTEM_PROXY_FAILED, "错误码须可分类");
    assert!(
        got[0].0.contains("系统代理启用失败") && got[0].0.contains("直连"),
        "文案须让用户看懂「流量没走代理」，实得 {}",
        got[0].0
    );
}

/// **A1 失败是非终态**：核确在跑 → 绝不把状态抹成 not-running（虚报同样有害），
/// 但 error/errorCode 必须落进状态（前端拉 status 也看得到）。
/// 变异锁：把 `set_nonfatal_error` 换成 `set_error` → running/pid/端口全被 `default()` 抹掉 → 转红。
#[tokio::test]
async fn a1_enable_failure_keeps_core_running_state() {
    let (rt, _dir, _events) = test_runtime_errors_with_clearer(Box::new(FailingEnableClearer));
    mark_running(&rt);
    rt.maybe_enable_system_proxy(&systemproxy_user_config(), 7890)
        .await;
    let s = rt.status();
    assert!(s.running, "核确在跑 → 绝不因系统代理失败标成未运行（虚报）");
    assert_eq!(
        s.pid, 424242,
        "pid 不得被抹（抹了则停核/管理 API/统计全失联）"
    );
    assert_eq!(s.clash_api_port, 19090, "管理 API 端口不得被抹");
    assert_eq!(s.error_code.as_deref(), Some(code::SYSTEM_PROXY_FAILED));
    assert!(s.error.is_some(), "错误文案须落进状态");
}

/// A1 **成功**腿绝不告警（告警一旦有假就会被整体无视）。
/// 变异锁：把 emit 挪到 match 之外（无条件发）→ 转红。
#[tokio::test]
async fn a1_enable_success_emits_nothing() {
    let clearer: Box<dyn SystemProxyClearer> = Box::new(EnableRecordingClearer::default());
    let (rt, _dir, events) = test_runtime_errors_with_clearer(clearer);
    mark_running(&rt);
    rt.maybe_enable_system_proxy(&systemproxy_user_config(), 7890)
        .await;
    assert!(
        events.lock().unwrap().is_empty(),
        "成功腿不得告警，实得 {:?}",
        events.lock().unwrap()
    );
}

/// C1 启动期恢复：`recover_system_proxy_on_startup` 真调到 controller 的 `recover_from_marker`。
/// 变异锁：删 `maybe_enable_system_proxy`... 不——删 `recover_system_proxy_on_startup` 里的
/// `g.recover_from_marker()` → recover_calls=0 且回传 false → 转红。
#[tokio::test]
async fn startup_recovery_invokes_recover_from_marker() {
    let recover_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let clearer: Box<dyn SystemProxyClearer> = Box::new(EnableRecordingClearer {
        recover_calls: Arc::clone(&recover_calls),
        ..Default::default()
    });
    let (rt, _dir, _f, _r) = test_runtime_recording_full(clearer);
    let recovered = rt.recover_system_proxy_on_startup().await;
    assert_eq!(
        recover_calls.load(Ordering::SeqCst),
        1,
        "启动期必调 recover_from_marker 一次"
    );
    assert!(
        recovered,
        "mock recover 返 true → 方法回传 true（真恢复过）"
    );
}

/// 用户主动 `stop` 绝不发 `event:proxyError`（正常终态，不是错误）——防「停一次代理报一次错」。
/// 打断（把 emit 挪到 stop_inner / status 清空处）→ 本测转红。
#[tokio::test]
async fn active_stop_emits_no_proxy_error() {
    let (rt, _dir, events) = test_runtime_recording_errors();
    rt.stop().await.unwrap();
    assert!(
        events.lock().unwrap().is_empty(),
        "主动停止是达成用户意图的终态，绝不该报 proxyError"
    );
}

/// emitter 未接线（setup 前的极早期失败 / 单测）→ 状态照落，不 panic。
/// 打断（emitter 用 `.get().unwrap()`）→ 本测转红：诊断通道不该反噬它诊断的东西。
#[test]
fn set_error_without_emitter_still_records_state() {
    let (rt, _dir) = test_runtime(); // 刻意不接线 emitter
    rt.set_error("无 emitter 也要落状态", code::PROCESS_EXITED);
    assert_eq!(
        rt.status().error_code.as_deref(),
        Some(code::PROCESS_EXITED)
    );
}
