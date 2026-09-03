//! C5 接线面门：占位 op 诚实 no-op + MeshRuntime 生命周期腿真触达出口路由状态机。
//! OS 路由真操作（三平台 route 手术）属 helper 批 C6 真机门，本处不覆盖（无真进程/无宿主网络）。
//! 状态机纯逻辑（reconcile/clear/latest-wins/macOS 防误删）由 `polaris_mesh::exit_route` 单测覆盖。
use super::super::*;
use crate::test_support::TestDir;
use polaris_config_engine::user_config::server_config::{
    Protocol, ServerConfig, TailscaleSettings,
};

/// TS System + 承载全隧道出口 → `plan_mesh_exit_route` 返 Some（须托管路由）。
fn ts_system_exit_cfg() -> UserConfig {
    let ts = TailscaleSettings {
        reverse_mesh: Some(true),             // system_interface
        exit_node: Some("100.64.0.1".into()), // 承载全隧道
        ..Default::default()
    };
    let server = ServerConfig {
        id: "ts1".into(),
        name: "ts".into(),
        protocol: Protocol::Tailscale,
        tailscale_settings: Some(Box::new(ts)),
        ..Default::default()
    };
    UserConfig {
        servers: vec![server],
        ..Default::default()
    }
}

/// 非 mesh 出口（VLESS）→ `plan_mesh_exit_route` 返 None（让位，契约 #37）。
fn vless_cfg() -> UserConfig {
    UserConfig {
        servers: vec![ServerConfig {
            id: "v1".into(),
            name: "v".into(),
            protocol: Protocol::Vless,
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn temp_dir(tag: &str) -> TestDir {
    TestDir::new(&format!("polaris-exitroute-{tag}-"))
}

/// 禁用（`enabled=false`）op 诚实 no-op：`run_route` 恒 false（绝不报成功、绝不 shell 命令）、反查恒 None、
/// utun 恒空。这是本机（Linux 开发机）单测**绝不碰宿主网络**的地基。
/// 打断任一（false→true / None→Some / 空→非空 / 去掉 enabled 闸门致真 shell）→ 本测转红/破坏本机网络。
#[tokio::test]
async fn disabled_exit_route_op_is_honest_noop() {
    let op = HelperExitRouteOp {
        helper: None,
        platform: current_platform(),
        enabled: false,
        stats: Arc::new(ExitRouteOpStats::default()),
    };
    assert!(
        !op.run_route("add", "polaris-ts", &["0.0.0.0/0".to_string()])
            .await,
        "禁用 op 绝不报 route 成功（否则假装 OS 路由已装）"
    );
    assert!(
        op.find_tailnet_iface("polaris-ts", None, &|| false)
            .await
            .is_none(),
        "禁用 op 反查内核接口恒 None"
    );
    assert!(op.list_utuns().await.is_empty(), "禁用 op utun 集恒空");
}

// ── 取消令牌接线（MED：点停止最长卡 18s）────────────────────────────────────────────
//
// 根因不是世代（合法当权的那条腿一样会卡），是 macOS 反查轮询**不可中断**且整条持着
// `exit_route` 独占锁。两道修法各有一条门：
// ① 轮询本身要认取消 → `poll_for_tailnet_iface_stops_within_one_round_after_cancel`；
// ② 抢占方要在**锁外**发得出取消 + 排队方要认「排队期间被抢占」→ 下面两条接线门。

/// **轮询侧**：取消后必须在**一个周期内**退出，不跑满 12×1.5s 预算。
///
/// `start_paused` 虚拟时钟 ⇒ 12 次 1.5s sleep 不占真实时间，断言的是**轮数**而非墙钟。
/// 真 `ifconfig` 是真机门，此处注入假 probe（零进程、零宿主网络）。
///
/// **变异锁**：删掉 `poll_for_tailnet_iface` 里的 `if cancelled() { return None }` →
/// 探测次数变 `MACOS_RESOLVE_ATTEMPTS`（12）→ 转红；把取消判据挪到 `probe().await` **之后** →
/// 多探一次（3 次）→ 同样转红。
#[tokio::test(start_paused = true)]
async fn poll_for_tailnet_iface_stops_within_one_round_after_cancel() {
    let probes = Arc::new(AtomicU64::new(0));
    let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (probes_in, flag_in, flag_chk) = (Arc::clone(&probes), Arc::clone(&flag), flag);
    let cancelled = move || flag_chk.load(Ordering::SeqCst);
    let out = poll_for_tailnet_iface(
        MACOS_RESOLVE_ATTEMPTS,
        MACOS_RESOLVE_DELAY,
        &cancelled,
        move || {
            let (probes, flag) = (Arc::clone(&probes_in), Arc::clone(&flag_in));
            async move {
                // 第 2 轮探测期间「用户点了停止」（停核腿在锁外 cancel）。
                if probes.fetch_add(1, Ordering::SeqCst) + 1 == 2 {
                    flag.store(true, Ordering::SeqCst);
                }
                None
            }
        },
    )
    .await;
    assert!(out.is_none(), "取消 → 不返回接口名（调用方遂不装路由）");
    assert_eq!(
        probes.load(Ordering::SeqCst),
        2,
        "取消后不得再探测：跑满 {MACOS_RESOLVE_ATTEMPTS} 轮就是「点停止最长卡 18s」的原样"
    );
}

/// 反证（同一编排的正向腿）：不取消时轮询跑满预算 —— 上面那条的提前退出确由取消引起。
#[tokio::test(start_paused = true)]
async fn poll_for_tailnet_iface_uses_full_budget_when_not_cancelled() {
    let probes = Arc::new(AtomicU64::new(0));
    let probes_in = Arc::clone(&probes);
    let out = poll_for_tailnet_iface(MACOS_RESOLVE_ATTEMPTS, MACOS_RESOLVE_DELAY, &|| false, {
        move || {
            let probes = Arc::clone(&probes_in);
            async move {
                probes.fetch_add(1, Ordering::SeqCst);
                None
            }
        }
    })
    .await;
    assert!(out.is_none());
    assert_eq!(
        probes.load(Ordering::SeqCst),
        u64::from(MACOS_RESOLVE_ATTEMPTS)
    );
}

/// **抢占侧**：三条拆除/换代腿必须在**拿锁之前**把取消发出去。
///
/// 发在锁内等于没发：取消信号自己要先排在那 18s 轮询后面。世代计数变化即「已发出」的可观测证据。
///
/// **变异锁**：删掉 `exit_route_clear` / `exit_route_snapshot_baseline` /
/// `exit_route_reset_state` 任一条里的 `self.exit_route_cancel.cancel()` → 对应断言转红。
#[tokio::test]
async fn teardown_legs_signal_cancel_outside_the_lock() {
    let dir = temp_dir("cancel-signal");
    let mesh = MeshRuntime::new(dir.clone());
    let t0 = mesh.exit_route_cancel.token();
    mesh.exit_route_clear().await;
    let t1 = mesh.exit_route_cancel.token();
    assert_ne!(t1, t0, "停核腿须在锁外先请求取消（否则点停止仍卡 18s）");
    mesh.exit_route_snapshot_baseline().await;
    let t2 = mesh.exit_route_cancel.token();
    assert_ne!(t2, t1, "新一轮起核的基线快照须抢占上一轮在飞反查");
    mesh.exit_route_reset_state().await;
    assert_ne!(
        mesh.exit_route_cancel.token(),
        t2,
        "崩溃复位须抢占在飞反查（复位是重起核的前置）"
    );
}

/// **排队侧**：凭据在**拿锁之前**快照 ⇒ 排队期间发生的停核能作废这一轮。
///
/// 复现的正是世代守卫够不着的那个窗口：`ts_exit_recover_once` 比完世代才去排 `exit_route` 的锁，
/// 恰在排队期间用户点了停止 —— 没有本判据的话，这条腿醒来会看到 `installed=None`（clear 刚清过）
/// 而**给一个已停的核重装出口路由**（Linux 下反查直接返逻辑名，一装一个准）。
///
/// **变异锁**：删掉 `exit_route_reassert`（或 `exit_route_reconcile`）里拿锁后的
/// `is_cancelled(token)` 早退 → 排队腿会走到 apply→`find_tailnet_iface` ⇒ `iface_lookups` 变 1 → 转红。
/// 把 `token()` 快照挪到 `lock().await` **之后** → 快照到的已是取消后的新世代 → 同样转红。
#[tokio::test]
async fn queued_leg_is_dropped_when_stop_preempts_it_while_waiting_for_the_lock() {
    let dir = temp_dir("cancel-queued");
    let mesh = Arc::new(MeshRuntime::new(dir.clone()));
    // 占住状态机锁 = 模拟「在飞的 macOS 反查正持锁轮询」。
    let guard = mesh.exit_route.lock().await;
    let queued = {
        let m = Arc::clone(&mesh);
        tokio::spawn(async move {
            m.exit_route_reassert(&ts_system_exit_cfg(), false).await;
        })
    };
    // 让排队腿真的跑到 `lock().await`（凭据此时已快照）。
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    // 用户点停止：锁外发取消，然后释放锁（= 在飞那轮收手）。
    mesh.exit_route_cancel.cancel();
    drop(guard);
    queued.await.expect("排队腿不得 panic");
    assert_eq!(
        mesh.exit_route_stats.iface_lookups.load(Ordering::SeqCst),
        0,
        "排队期间被停核抢占的腿必须整轮作废：一次反查都不许发起（发起 = 对着已停的核重装路由）"
    );
    assert!(mesh.exit_route_installed().await.is_none());
}

/// reconcile 生命周期腿真触达状态机：TS System 全隧道出口 → plan Some → apply 反查 op
/// （iface_lookups++），但占位 op 下 `installed` 恒 None（不假装已装）。
/// 打断 `exit_route_reconcile` 委托 → iface_lookups=0 转红；打断占位 op 使其真装 → installed 非 None 转红。
///
/// Windows 分支断言相反：`mesh_system_supported_on_platform(Win)=false`（Windows 禁 mesh
/// System 出口，exit_route.rs `reconcile_once` 平台闸门早退）→ 状态机**按契约**不进 apply、
/// 不触达 op。打断该闸门（Win 上真跑 apply）→ iface_lookups>0 转红。
#[tokio::test]
async fn reconcile_reaches_state_machine_but_installs_nothing() {
    let dir = temp_dir("reconcile");
    let mesh = MeshRuntime::new(dir.clone());
    mesh.exit_route_reconcile(&ts_system_exit_cfg(), false)
        .await;
    let lookups = mesh.exit_route_stats.iface_lookups.load(Ordering::SeqCst);
    if cfg!(windows) {
        assert_eq!(
            lookups, 0,
            "Windows 平台闸门：mesh System 出口不支持 → reconcile 早退，不触达 op"
        );
    } else {
        assert!(
            lookups >= 1,
            "reconcile(mesh 出口) 须触达出口路由状态机的 apply→find_tailnet_iface"
        );
    }
    assert!(
        mesh.exit_route_installed().await.is_none(),
        "测试构造（`enabled=false`）：即便 plan Some 也恒不装路由（诚实 no-op，绝不碰宿主网络）"
    );
}

/// 让位判定（契约 #37）：非 mesh 出口 → plan None → 状态机不进 apply → 不触达 op。
/// 打断让位（如强行 apply）→ iface_lookups>0 转红。
#[tokio::test]
async fn reconcile_yields_for_non_mesh_exit() {
    let dir = temp_dir("yield");
    let mesh = MeshRuntime::new(dir.clone());
    mesh.exit_route_reconcile(&vless_cfg(), false).await;
    assert_eq!(
        mesh.exit_route_stats.iface_lookups.load(Ordering::SeqCst),
        0,
        "非 TS System 出口 plan None（让位）→ 不触达 op"
    );
}

/// clear / snapshot_baseline / reset_state 生命周期腿：占位 op + 无 installed → 纯 no-op，不 panic、不触达 op。
#[tokio::test]
async fn clear_baseline_reset_are_noop_without_installed() {
    let dir = temp_dir("clear");
    let mesh = MeshRuntime::new(dir.clone());
    mesh.exit_route_snapshot_baseline().await;
    mesh.exit_route_clear().await;
    mesh.exit_route_reset_state().await;
    assert!(mesh.exit_route_installed().await.is_none());
    // clear 未触达 op（installed 恒 None → clear_inner 早退）。
    assert_eq!(mesh.exit_route_stats.route_calls.load(Ordering::SeqCst), 0);
}
