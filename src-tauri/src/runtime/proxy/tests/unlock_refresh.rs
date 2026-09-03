use super::*;

// ══════════════════════════════════════════════════════════════════════════════
// unlock 缓存失效接线（item 1：核 start/stop → unlock.invalidate）
// ══════════════════════════════════════════════════════════════════════════════

/// **item 1 · 核停 → unlock 缓存失效**：`stop()` 经 `stop_inner` 调 `invalidate_unlock_cache(false,false)`
/// → emitter 记一条 `(running=false, exitBlocked=false)`。
///
/// **变异锁**：删 `stop_inner` 里 `self.invalidate_unlock_cache(false, false)` → 零记录 → 转红
/// （退回「跨起停 30min TTL 内复用停核前陈旧解锁快照」）。
#[tokio::test]
async fn stop_invalidates_unlock_cache() {
    let (rt, _dir) = test_runtime();
    let inval: UnlockInvalidations = Arc::new(Mutex::new(Vec::new()));
    rt.set_error_emitter(Box::new(RecordingErrorEmitter {
        unlock_invalidations: Arc::clone(&inval),
        ..Default::default()
    }));
    rt.stop().await.expect("停无核应 Ok");
    assert_eq!(
        *inval.lock().unwrap(),
        vec![(false, false)],
        "停核须失效解锁缓存（running=false, exitBlocked=false）"
    );
}

/// **item 1 · 起核腿 running=true 参数透传**：起核就绪提交点用的正是 `invalidate_unlock_cache(true,false)`。
/// 完整起核路径含真起核（真机门），本测锁「helper → emitter + running 语义」这段——起核调用点是就绪提交
/// 后 code-review 可见的一行。
///
/// **变异锁**：`invalidate_unlock_cache` 里不调 emitter（或吞掉 running）→ 记录不符 → 转红。
#[test]
fn invalidate_unlock_cache_passes_running_flag() {
    let (rt, _dir) = test_runtime();
    let inval: UnlockInvalidations = Arc::new(Mutex::new(Vec::new()));
    rt.set_error_emitter(Box::new(RecordingErrorEmitter {
        unlock_invalidations: Arc::clone(&inval),
        ..Default::default()
    }));
    rt.invalidate_unlock_cache(true, false);
    rt.invalidate_unlock_cache(false, false);
    assert_eq!(
        *inval.lock().unwrap(),
        vec![(true, false), (false, false)],
        "running 真态须原样透传给 emitter（起核=true / 停核=false）"
    );
}

// ══════════════════════════════════════════════════════════════════════════════
// 出口 IP / 延迟自动重探接线（待修 #1：核 start/stop/热切 → ipinfo 重探 → 伴测点亮延迟）
// ══════════════════════════════════════════════════════════════════════════════

/// **停核 → 出口 IP 重探**：`stop()` 经 `stop_inner` 调 `schedule_exit_ip_refresh(false)`。
/// 三个触发点里**只有这个**能在单测里真跑（无核 stop 仍走 `stop_inner`），起核 / 热切走真机门 +
/// `mod exit_ip_wiring_guard` 的配对扫描。
///
/// **变异锁**：删 `stop_inner` 里那行 → 零记录 → 转红（退回「停核后状态栏仍显示代理出口 IP」）；
/// running 传成 true → 值不符 → 转红（会让停核腿白等 4s 收敛，而出口已确定性消失）。
#[tokio::test]
async fn stop_schedules_exit_ip_refresh() {
    let (rt, _dir) = test_runtime();
    let refreshes: ExitIpRefreshes = Arc::new(Mutex::new(Vec::new()));
    rt.set_error_emitter(Box::new(RecordingErrorEmitter {
        exit_ip_refreshes: Arc::clone(&refreshes),
        ..Default::default()
    }));
    rt.stop().await.expect("停无核应 Ok");
    assert_eq!(
        *refreshes.lock().unwrap(),
        vec![false],
        "停核须排程出口 IP 重探（running=false ⇒ 无收敛可等，零延迟直接探直连出口）"
    );
}

/// **running 语义透传**：起核/热切=true（要等选路收敛）与停核=false（不等）在 emitter 侧是**不同**
/// 的延迟策略，吞掉这个参数会让停核腿白等 4s、或让起核腿在隧道未就绪时就探（探到旧出口/直接失败）。
///
/// **变异锁**：`schedule_exit_ip_refresh` 里不调 emitter（或写死某个 running）→ 记录不符 → 转红。
#[test]
fn schedule_exit_ip_refresh_passes_running_flag() {
    let (rt, _dir) = test_runtime();
    let refreshes: ExitIpRefreshes = Arc::new(Mutex::new(Vec::new()));
    rt.set_error_emitter(Box::new(RecordingErrorEmitter {
        exit_ip_refreshes: Arc::clone(&refreshes),
        ..Default::default()
    }));
    rt.schedule_exit_ip_refresh(true);
    rt.schedule_exit_ip_refresh(false);
    assert_eq!(
        *refreshes.lock().unwrap(),
        vec![true, false],
        "running 真态须原样透传给 emitter（起核/热切=true / 停核=false）"
    );
}

#[test]
fn network_change_forwards_one_recovery_refresh() {
    let (rt, _dir) = test_runtime();
    let refreshes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    rt.set_error_emitter(Box::new(RecordingErrorEmitter {
        network_recovery_refreshes: Arc::clone(&refreshes),
        ..Default::default()
    }));
    rt.schedule_network_recovery_refresh();
    assert_eq!(
        refreshes.load(Ordering::SeqCst),
        1,
        "每个去抖后的网络变化必须排一次恢复探测"
    );
}

/// **延迟策略真值表**：起核/热切必须等选路收敛（否则探到旧出口或直接失败）、停核必须零延迟
/// （出口是确定性消失，白等 4s = 状态栏多显示 4s 陈旧代理 IP）。
///
/// **变异锁**：两腿写成同一个值（无论都 0 还是都 4000）→ 转红；两腿写反 → 双断言转红。
#[test]
fn exit_ip_refresh_delay_splits_by_running() {
    assert_eq!(
        exit_ip_refresh_delay_ms(true),
        crate::commands::misc::IPINFO_SETTLE_DELAY_MS,
        "起核/热切须等选路收敛后再探"
    );
    assert_eq!(
        exit_ip_refresh_delay_ms(false),
        0,
        "停核无收敛可等，须零延迟直接重探直连出口"
    );
    assert!(
        exit_ip_refresh_delay_ms(true) > exit_ip_refresh_delay_ms(false),
        "两腿必须是不同策略；相等即等于吞掉了 running 语义"
    );
}

/// **emitter 未接线不得打断起停**：与 `invalidate_unlock_cache` 同范式——发不出重探排程，绝不
/// 反过来把停核腿弄失败。
///
/// **变异锁**：`schedule_exit_ip_refresh` 改成 `self.error_emitter.get().unwrap()` → panic → 转红。
#[tokio::test]
async fn exit_ip_refresh_without_emitter_is_silent_noop() {
    let (rt, _dir) = test_runtime();
    rt.stop()
        .await
        .expect("未接 emitter 时停核仍须 Ok（重探是增益腿，不是前置条件）");
}
