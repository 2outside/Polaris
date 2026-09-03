use super::*;
use crate::test_support::crate_code;

/// 造一个可翻转的代理态源 + 计数型 stop。
fn probe(
    running: Arc<AtomicBool>,
    via_helper: bool,
) -> impl Fn() -> (bool, bool) + Clone + Send + 'static {
    move || (running.load(Ordering::SeqCst), via_helper)
}

#[test]
fn helper_upgrade_only_blocks_a_running_helper_managed_core() {
    assert!(helper_install_blocked_by_proxy(true, true));
    assert!(!helper_install_blocked_by_proxy(false, true));
    assert!(!helper_install_blocked_by_proxy(true, false));
    assert!(!helper_install_blocked_by_proxy(false, false));
}

/// 🟡 **变异锁：卸载期间核被重新起起来 → 看门狗必须再停一次。**
///
/// 复现的正是提权框挂着的那几分钟：前置停核已跑过（快照那一刻核是停的），用户随后点了连接。
/// **变异探针**：把 `helper_uninstall` 里的看门狗删掉 / 让本函数只查一次 ⇒ 本条转红。
#[tokio::test(start_paused = true)]
async fn watchdog_restops_core_started_during_the_elevation_dialog() {
    let done = Arc::new(AtomicBool::new(false));
    let running = Arc::new(AtomicBool::new(false)); // 前置停核之后：核是停的
    let stops = Arc::new(AtomicBool::new(false));

    // 提权框挂着期间：1 拍后用户把核起了起来，5 拍后卸载才结束。
    {
        let (running, done) = (running.clone(), done.clone());
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            running.store(true, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(2500)).await;
            done.store(true, Ordering::SeqCst);
        });
    }

    let stopped = stops.clone();
    let running_for_stop = running.clone();
    let n = helper_service_mutation_stop_watchdog(
        done,
        Duration::from_millis(500),
        probe(running.clone(), true),
        move || {
            let (stopped, running) = (stopped.clone(), running_for_stop.clone());
            async move {
                stopped.store(true, Ordering::SeqCst);
                running.store(false, Ordering::SeqCst); // 停成功
                Ok(())
            }
        },
    )
    .await;

    assert!(
        stops.load(Ordering::SeqCst),
        "卸载期间起来的受管核必须被再停一次 —— 否则卸载完成后是杀不动的 root 孤儿核 + 断网"
    );
    assert_eq!(n, 1, "核只起了一次 → 只该停一次（不该逐拍空转发 stop）");
}

/// 核一直是停的 → 一次 stop 都不发（看门狗不制造噪音）。
#[tokio::test(start_paused = true)]
async fn watchdog_is_silent_when_core_stays_down() {
    let done = Arc::new(AtomicBool::new(false));
    {
        let done = done.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(3000)).await;
            done.store(true, Ordering::SeqCst);
        });
    }
    let n = helper_service_mutation_stop_watchdog(
        done,
        Duration::from_millis(500),
        probe(Arc::new(AtomicBool::new(false)), true),
        || async { Ok(()) },
    )
    .await;
    assert_eq!(n, 0);
}

/// **app 自己直起的核不停**：它不归 daemon 管，卸载不会让它变孤儿，停它等于无故断网。
/// 判据与前置腿共用 [`decide_uninstall_preflight`]；把它换成只看 `running` ⇒ 本条转红。
#[tokio::test(start_paused = true)]
async fn watchdog_leaves_app_started_core_alone() {
    let done = Arc::new(AtomicBool::new(false));
    {
        let done = done.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(3000)).await;
            done.store(true, Ordering::SeqCst);
        });
    }
    let n = helper_service_mutation_stop_watchdog(
        done,
        Duration::from_millis(500),
        probe(Arc::new(AtomicBool::new(true)), false), // 在跑，但**不经 helper**
        || async { Ok(()) },
    )
    .await;
    assert_eq!(n, 0, "非 helper 起的核不该被卸载腿停掉");
}

/// 停核失败不得让看门狗退出（提权框还挂着，下一拍仍要继续看）。
#[tokio::test(start_paused = true)]
async fn watchdog_keeps_watching_after_a_failed_stop() {
    let done = Arc::new(AtomicBool::new(false));
    {
        let done = done.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(2200)).await;
            done.store(true, Ordering::SeqCst);
        });
    }
    let n = helper_service_mutation_stop_watchdog(
        done,
        Duration::from_millis(500),
        probe(Arc::new(AtomicBool::new(true)), true), // 恒在跑（停不掉）
        || async { Err("stop failed".to_string()) },
    )
    .await;
    assert!(n >= 3, "停失败后必须继续每拍重试，实得 {n} 次");
}

/// 🟡 **变异锁：卸载收尾不得打断在飞的停核。**
///
/// 复现 LOW-3 那个窄窗口：`uninstall()` 刚返回的那一刻，看门狗正落在 `stop().await` 中途。
/// 协作式收停必须**等它把这次停核走完**（`proxy.stop()` 不是 cancel-safe，三条后果见
/// [`join_watchdog_cooperatively`] 文档）。
///
/// **变异探针**：把 `join_watchdog_cooperatively(...)` 换回 `watchdog.abort()` ⇒
/// `stop_finished` 恒 false ⇒ 本条转红。
#[tokio::test(start_paused = true)]
async fn cooperative_join_lets_an_inflight_stop_finish() {
    let done = Arc::new(AtomicBool::new(false));
    let running = Arc::new(AtomicBool::new(true)); // 核在跑 → 看门狗第一拍就会去停
    let stop_finished = Arc::new(AtomicBool::new(false));

    let mut watchdog = {
        let (done, running, finished) = (done.clone(), running.clone(), stop_finished.clone());
        tokio::spawn(async move {
            helper_service_mutation_stop_watchdog(
                done,
                Duration::from_millis(500),
                probe(running.clone(), true),
                move || {
                    let (running, finished) = (running.clone(), finished.clone());
                    async move {
                        // 一次真停核的量级：SIGTERM → 宽限 → SIGKILL + 收割。
                        tokio::time::sleep(Duration::from_secs(6)).await;
                        running.store(false, Ordering::SeqCst);
                        finished.store(true, Ordering::SeqCst); // 只有跑完整条 future 才置位
                        Ok(())
                    }
                },
            )
            .await
        })
    };

    // 让看门狗真的进到 stop().await 里（第一拍 500ms 到点 → 发起停核，停核要 6s）。
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        !stop_finished.load(Ordering::SeqCst),
        "前提：此刻停核确实还在飞（否则本用例没复现那个窗口）"
    );

    // 卸载返回 → 协作式收停。
    let exited = join_watchdog_cooperatively(&done, &mut watchdog, WATCHDOG_JOIN_BUDGET).await;

    assert!(exited, "看门狗必须在预算内自然退出");
    assert!(
        stop_finished.load(Ordering::SeqCst),
        "在飞的停核必须被走完 —— abort 会把它整体 drop：\
             LifecycleGate 深度永久泄漏（此后 switch_mode/去抖重启全成空转）、\
             核句柄不收割、系统代理留在死端口上"
    );
    assert!(
        done.load(Ordering::SeqCst),
        "收停必须置位 `done` —— 少了它，看门狗会在卸载完成后继续停用户新起的核"
    );
}

/// 停核挂死时**命令不得被无限期拖住**：超预算返回 false（调用方放手，不 abort）。
///
/// 变异探针：把 `tokio::time::timeout(budget, handle)` 换成裸 `handle.await` ⇒ 本条永远跑不完。
#[tokio::test(start_paused = true)]
async fn cooperative_join_is_bounded_when_stop_hangs() {
    let done = Arc::new(AtomicBool::new(false));
    let mut watchdog = {
        let done = done.clone();
        tokio::spawn(async move {
            helper_service_mutation_stop_watchdog(
                done,
                Duration::from_millis(500),
                probe(Arc::new(AtomicBool::new(true)), true),
                || async {
                    // 挂死的停核（helper IPC 卡住等）。
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                    Ok(())
                },
            )
            .await
        })
    };
    tokio::time::sleep(Duration::from_secs(1)).await;

    let t0 = tokio::time::Instant::now();
    let exited = join_watchdog_cooperatively(&done, &mut watchdog, Duration::from_secs(2)).await;
    assert!(!exited, "挂死的停核 → 超预算返回 false");
    assert!(
        t0.elapsed() < Duration::from_secs(10),
        "等待必须有界（实等 {:?}）",
        t0.elapsed()
    );
    assert!(
        done.load(Ordering::SeqCst),
        "done 必须已置位（看门狗不会再发起新的停核）"
    );
    watchdog.abort(); // 测试收尾清理，非生产语义
}

/// 预算必须**盖得住一次真停核**（SIGTERM→5s 宽限→SIGKILL + DNS 还原 + 清系统代理）。
/// 调小到停核量级以下 ⇒ 每次卸载都走超时腿 ⇒ 协作式收停名存实亡。
#[test]
fn join_budget_covers_a_worst_case_stop() {
    assert!(
        WATCHDOG_JOIN_BUDGET >= Duration::from_secs(10),
        "预算 {WATCHDOG_JOIN_BUDGET:?} 盖不住 SIGTERM→5s 宽限→SIGKILL 再加两次系统 exec"
    );
}

/// 🟡 **调用点守卫**：`helper_uninstall` 必须在 `uninstall()` 之前经过前置停核，
/// 且整段卸载期挂着看门狗、`uninstall()` 本身跑在 `spawn_blocking` 上。
///
/// 这几条不变式没法用普通单测覆盖（命令持 `State<'_, AppRuntime>`，单测构造不出 Tauri 运行时），
/// 故按本层既有做法用源码扫描锁调用点。语义（何时停 / 停失败怎么办）由 `runtime::helper` 的
/// 真值表 + 上面那组注入式单测覆盖；这里只锁「腿还在不在、顺序对不对」。
///
/// **变异探针**：删掉 `uninstall_preflight_stop(...)` / 删掉看门狗 spawn / 把看门狗挪到
/// `body(` 之后 / 把收尾换回裸 abort ⇒ 逐条转红。
///
/// 取材面已从 `helper_uninstall` 挪到 [`with_helper_service_mutation_core_guard`]（这段编排现由
/// 安装/升级与两条卸载命令共用），断言一条没减；调用方接线由下方测试单独钉死。
#[test]
fn helper_service_mutation_guard_wires_preflight_watchdog_and_cooperative_join() {
    let src = crate_code("commands/helper.rs");
    let body = crate::commands::guard_scan::top_level_fn_body(
        &src,
        "pub(crate) async fn with_helper_service_mutation_core_guard",
    );
    let stop_at = body
        .find("uninstall_preflight_stop")
        .expect("卸载前置停核腿被删了 —— TUN 跑着时卸 helper 会留无人管的 root 核 + 断网");
    let watchdog_at = body
        .find("helper_service_mutation_stop_watchdog(")
        .expect("卸载期看门狗被删了 —— 提权框挂着的几分钟里用户起的核会变成 root 孤儿核");
    let body_at = body
        .find("body(stop_outcome)")
        .expect("锚点消失：守卫已失去判据");
    assert!(
        stop_at < body_at,
        "停核必须在真卸载动作**之前** —— 卸载会连 daemon 带 socket 一起删掉，之后停不了核"
    );
    assert!(
        watchdog_at < body_at,
        "看门狗必须在真卸载动作**之前**挂上 —— 挂在后面就完全错过了提权框那段窗口"
    );
    // LOW-3：收尾必须走协作式收停，且**不得**再出现裸 abort（`proxy.stop()` 非 cancel-safe）。
    assert!(
        body.contains("join_watchdog_cooperatively(&done, &mut watchdog"),
        "变异锁：收尾腿绕过了协作式收停"
    );
    assert!(
        !body.contains("watchdog.abort()"),
        "abort 会 drop 在飞的 `proxy.stop()`：LifecycleGate 深度永久泄漏 + 核不收割 + \
             系统代理留在死端口上（三条后果见 join_watchdog_cooperatively 文档）"
    );
}

/// 🟡 **调用点守卫：安装/升级与两条卸载命令都必须经过
/// [`with_helper_service_mutation_core_guard`]，且提权调用都在 `spawn_blocking` 里。**
///
/// 上一条守的是「壳里那几行还在不在」，这条守的是「还有没有人绕开这层壳」——
/// 少了它，把编排抽成公共函数反而制造了一个新的逃逸面（谁都可以直调 `helper.uninstall()`）。
///
/// **变异探针**：把任一命令里的 `with_helper_service_mutation_core_guard(` 拆掉改回直调 /
/// 把 `spawn_blocking` 去掉 ⇒ 逐条转红。
#[test]
fn all_helper_service_mutations_go_through_the_core_guard() {
    let helper_src = crate_code("commands/helper.rs");
    let install_body =
        crate::commands::guard_scan::top_level_fn_body(&helper_src, "pub async fn helper_install(");
    assert!(
        install_body.contains("with_helper_service_mutation_core_guard("),
        "helper 安装/升级绕开持续停核外壳 —— 提权框期间新起的 TUN 会被 daemon 替换打断"
    );
    assert!(
        install_body.contains("helper_install_blocked_by_proxy("),
        "helper 管理的代理已运行时必须先拒绝升级，不能静默停核"
    );
    assert!(
        install_body.contains("spawn_blocking"),
        "install() 又被直调了 —— 提权框会把一个 tokio worker 占死分钟级"
    );

    let hb = crate::commands::guard_scan::top_level_fn_body(
        &helper_src,
        "pub async fn helper_uninstall(",
    );
    let guard_at = hb
        .find("with_helper_service_mutation_core_guard(")
        .expect("helper_uninstall 绕开了停核外壳 —— TUN 跑着时卸 helper 会留 root 孤儿核");
    let uninstall_at = hb.find(".uninstall()").expect("锚点消失：守卫已失去判据");
    assert!(guard_at < uninstall_at, "外壳必须包住 uninstall() 调用");
    assert!(
        hb.contains("spawn_blocking"),
        "uninstall() 又被直调了 —— 提权框会把一个 tokio worker 占死分钟级"
    );

    // 完全卸载腿（`commands/updater/uninstall.rs`）同样不许绕开。
    let updater_src = crate_code("commands/updater/uninstall.rs");
    let ub = crate::commands::guard_scan::top_level_fn_body(
        &updater_src,
        "pub async fn app_uninstall_all(",
    );
    assert!(
        ub.contains("with_helper_service_mutation_core_guard("),
        "完全卸载绕开了停核外壳 —— 它后面还要删配置和应用本体，留下的孤儿 root 核将无人能停"
    );
    assert!(
        ub.contains("spawn_blocking"),
        "完全卸载整条链（含提权框 + 两次 remove_dir_all）必须在 spawn_blocking 上跑"
    );
}

/// 复查节拍必须**远密于**提权框的量级，否则「看着」只是个说法。
#[test]
fn recheck_interval_is_far_below_the_dialog_timescale() {
    assert!(
        HELPER_MUTATION_RECHECK_INTERVAL <= Duration::from_secs(1),
        "复查节拍 {HELPER_MUTATION_RECHECK_INTERVAL:?} 太粗 —— 用户点连接到服务变更完成只有几秒"
    );
}
