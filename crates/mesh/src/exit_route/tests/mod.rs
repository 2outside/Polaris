use super::*;
use polaris_config_engine::user_config::server_config::{ServerConfig, TailscaleSettings};
use std::sync::{Arc, Mutex};

/// 记录型 op mock：记录 run_route 调用 + 返回可配置 utun/iface。
type RouteLog = Vec<(String, String, Vec<String>)>; // (op, iface, cidrs)
#[derive(Default, Clone)]
struct MockOp {
    routes: Arc<Mutex<RouteLog>>,
    utuns: Arc<Mutex<HashSet<String>>>,
    tailnet_iface: Arc<Mutex<Option<String>>>,
    route_ok: Arc<Mutex<bool>>,
    /// 记录 `find_tailnet_iface` 最近一次收到的 baseline（验证时序 diff 锚点确被 apply 透传）。
    last_baseline: Arc<Mutex<Option<HashSet<String>>>>,
    /// 模拟 macOS 轮询：反查期间跑 N 轮，每轮先查 `cancelled()`；被取消即返 None。
    /// `poll_rounds` = 剩余轮数（0 = 不轮询，立即返 `tailnet_iface`）。
    poll_rounds: Arc<Mutex<u32>>,
    /// 真实跑过的轮数（断言「取消后一个周期内退出」）。
    polls_done: Arc<Mutex<u32>>,
    /// 每轮轮询中执行的钩子（测试用它在指定轮次触发 cancel）。
    #[allow(clippy::type_complexity)]
    on_poll: Arc<Mutex<Option<Box<dyn Fn(u32) + Send>>>>,
    /// 反查**成功返回之前**执行的钩子（测试用它复现「find 返回 Some 后才被取消」这个安全点）。
    #[allow(clippy::type_complexity)]
    on_found: Arc<Mutex<Option<Box<dyn Fn() + Send>>>>,
    /// `run_route` 执行期间的钩子（收到 op="add"|"del"）。用它复现**锁内**那段真实 await
    /// （`clear_inner` 的 `route del`）期间发生的取消 —— 那正是 `apply` 二次快照会吞掉的窗口。
    #[allow(clippy::type_complexity)]
    on_route: Arc<Mutex<Option<Box<dyn Fn(&str) + Send>>>>,
}

#[async_trait]
impl ExitRouteOp for MockOp {
    async fn run_route(&self, op: &str, iface: &str, cidrs: &[String]) -> bool {
        if let Some(hook) = self.on_route.lock().unwrap().as_ref() {
            hook(op);
        }
        self.routes
            .lock()
            .unwrap()
            .push((op.to_string(), iface.to_string(), cidrs.to_vec()));
        *self.route_ok.lock().unwrap()
    }
    async fn list_utuns(&self) -> HashSet<String> {
        self.utuns.lock().unwrap().clone()
    }
    async fn find_tailnet_iface(
        &self,
        _logical_name: &str,
        baseline: Option<&HashSet<String>>,
        cancelled: &(dyn Fn() -> bool + Send + Sync),
    ) -> Option<String> {
        *self.last_baseline.lock().unwrap() = baseline.cloned();
        // 契约实现：每个轮询点先查取消判据（真实现见 runtime/mesh.rs `poll_for_tailnet_iface`）。
        let rounds = *self.poll_rounds.lock().unwrap();
        for r in 0..rounds {
            *self.polls_done.lock().unwrap() += 1;
            if let Some(hook) = self.on_poll.lock().unwrap().as_ref() {
                hook(r); // 模拟本轮期间外部发生取消（停核腿在锁外调 cancel）
            }
            if cancelled() {
                return None;
            }
        }
        let found = self.tailnet_iface.lock().unwrap().clone();
        if found.is_some() {
            if let Some(hook) = self.on_found.lock().unwrap().as_ref() {
                hook();
            }
        }
        found
    }
}

fn ts_system_exit_server(exit_node: Option<&str>) -> ServerConfig {
    let ts = TailscaleSettings {
        reverse_mesh: Some(true), // system_interface
        exit_node: exit_node.map(|n| n.to_string()),
        ..Default::default()
    };
    ServerConfig {
        id: "ts1".into(),
        name: "ts".into(),
        protocol: Protocol::Tailscale,
        tailscale_settings: Some(Box::new(ts)),
        ..Default::default()
    }
}

fn config_with(server: ServerConfig) -> UserConfig {
    UserConfig {
        servers: vec![server],
        ..Default::default()
    }
}

// ── plan_mesh_exit_route ──────────────────────────────────────

#[test]
fn plan_none_when_no_ts() {
    let cfg = UserConfig::default();
    assert!(plan_mesh_exit_route(&cfg, false).is_none());
}

#[test]
fn plan_none_when_ts_not_system() {
    let mut s = ts_system_exit_server(Some("100.64.0.1"));
    s.tailscale_settings.as_mut().unwrap().reverse_mesh = Some(false);
    let cfg = config_with(s);
    assert!(plan_mesh_exit_route(&cfg, false).is_none());
}

#[test]
fn plan_none_when_no_exit_node() {
    let cfg = config_with(ts_system_exit_server(None));
    assert!(plan_mesh_exit_route(&cfg, false).is_none());
}

#[test]
fn plan_some_when_system_exit_node_v4_only() {
    let cfg = config_with(ts_system_exit_server(Some("100.64.0.1")));
    let plan = plan_mesh_exit_route(&cfg, false).unwrap();
    assert_eq!(plan.iface, TS_SYSTEM_INTERFACE_NAME);
    assert_eq!(plan.cidrs, vec!["0.0.0.0/0"]);
}

#[test]
fn plan_includes_v6_when_enabled() {
    let cfg = config_with(ts_system_exit_server(Some("100.64.0.1")));
    let plan = plan_mesh_exit_route(&cfg, true).unwrap();
    assert_eq!(plan.cidrs, vec!["0.0.0.0/0", "::/0"]);
}

#[test]
fn mesh_system_supported_excludes_windows() {
    assert!(mesh_system_supported_on_platform(Platform::Mac));
    assert!(mesh_system_supported_on_platform(Platform::Linux));
    assert!(!mesh_system_supported_on_platform(Platform::Win));
    assert!(mesh_system_supported_on_platform(Platform::Other));
}

#[test]
fn platform_parse_maps_known() {
    assert_eq!(Platform::parse("darwin"), Platform::Mac);
    assert_eq!(Platform::parse("linux"), Platform::Linux);
    assert_eq!(Platform::parse("win32"), Platform::Win);
    assert_eq!(Platform::parse("freebsd"), Platform::Other);
}

// ── reconcile / clear / reassert / reset ──────────────────────

/// 测试侧的**生产同形**驱动：凭据在调用之前（生产是在拿锁之前）快照，再作为参数传进状态机。
///
/// 直接 `mgr.reconcile(cfg, v6, mgr.cancel_handle().token())` 写在每个用例里也行，但那样很容易被
/// 后人「顺手」改成状态机内部取 —— 而那正是本轮修掉的洞。收成一处，取值时机只有一个地方能改。
async fn reconcile_now<O: ExitRouteOp, L: ExitRouteLog>(
    mgr: &mut MeshExitRouteManager<O, L>,
    cfg: &UserConfig,
    enable_ipv6: bool,
) -> ReconcileOutcome {
    let token = mgr.cancel_handle().token();
    mgr.reconcile(cfg, enable_ipv6, token).await
}

/// [`reconcile_now`] 的 reassert 版（同样先快照凭据）。
async fn reassert_now<O: ExitRouteOp, L: ExitRouteLog>(
    mgr: &mut MeshExitRouteManager<O, L>,
    cfg: &UserConfig,
    enable_ipv6: bool,
) -> ReconcileOutcome {
    let token = mgr.cancel_handle().token();
    mgr.reassert(cfg, enable_ipv6, token).await
}

fn mock_with_iface(iface: &str) -> MockOp {
    let op = MockOp::default();
    *op.route_ok.lock().unwrap() = true;
    *op.tailnet_iface.lock().unwrap() = Some(iface.to_string());
    op
}

#[tokio::test]
async fn reconcile_linux_installs_route_when_plan_present() {
    let op = mock_with_iface("polaris-ts");
    let cfg = config_with(ts_system_exit_server(Some("100.64.0.1")));
    let mut mgr = MeshExitRouteManager::new(op.clone(), NoopExitRouteLog, Platform::Linux);
    let out = reconcile_now(&mut mgr, &cfg, false).await;
    assert!(out.changed);
    let installed = mgr.installed().unwrap();
    assert_eq!(installed.iface, "polaris-ts");
    assert_eq!(installed.cidrs, vec!["0.0.0.0/0"]);
    let routes = op.routes.lock().unwrap();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].0, "add");
    assert_eq!(routes[0].1, "polaris-ts");
}

#[tokio::test]
async fn reconcile_skips_iface_not_found() {
    let op = MockOp::default();
    *op.route_ok.lock().unwrap() = true;
    *op.tailnet_iface.lock().unwrap() = None; // 反查失败
    let cfg = config_with(ts_system_exit_server(Some("100.64.0.1")));
    let mut mgr = MeshExitRouteManager::new(op.clone(), NoopExitRouteLog, Platform::Linux);
    let out = reconcile_now(&mut mgr, &cfg, false).await;
    // changed=true（先清了旧 None→no-op，尝试装但 iface 找不到→未装）；installed 仍 None。
    assert!(mgr.installed().is_none());
    // 装未发生（run_route 未被调）。
    let routes = op.routes.lock().unwrap();
    assert!(routes.is_empty());
    let _ = out;
}

#[tokio::test]
async fn reconcile_no_change_when_already_installed_same_plan() {
    let op = mock_with_iface("polaris-ts");
    let cfg = config_with(ts_system_exit_server(Some("100.64.0.1")));
    let mut mgr = MeshExitRouteManager::new(op.clone(), NoopExitRouteLog, Platform::Linux);
    reconcile_now(&mut mgr, &cfg, false).await;
    op.routes.lock().unwrap().clear();
    // 再次对账同配置 → 无变更（不重发 add）。
    let out = reconcile_now(&mut mgr, &cfg, false).await;
    assert!(!out.changed);
    assert!(op.routes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn reconcile_clears_when_plan_becomes_none() {
    let op = mock_with_iface("polaris-ts");
    let cfg_with = config_with(ts_system_exit_server(Some("100.64.0.1")));
    let mut mgr = MeshExitRouteManager::new(op.clone(), NoopExitRouteLog, Platform::Linux);
    reconcile_now(&mut mgr, &cfg_with, false).await;
    assert!(mgr.installed().is_some());
    // 切到无 exit_node 配置 → 计划 None → 清。
    let cfg_without = config_with(ts_system_exit_server(None));
    let out = reconcile_now(&mut mgr, &cfg_without, false).await;
    assert!(out.changed);
    assert!(mgr.installed().is_none());
    let routes = op.routes.lock().unwrap();
    assert!(routes.iter().any(|r| r.0 == "del"));
}

#[tokio::test]
async fn reconcile_toggle_ipv6_replaces_route() {
    let op = mock_with_iface("polaris-ts");
    let cfg = config_with(ts_system_exit_server(Some("100.64.0.1")));
    let mut mgr = MeshExitRouteManager::new(op.clone(), NoopExitRouteLog, Platform::Linux);
    reconcile_now(&mut mgr, &cfg, false).await; // v4 only
                                                // 开 v6 → cidrs 变 → 清+装。
    let out = reconcile_now(&mut mgr, &cfg, true).await;
    assert!(out.changed);
    let installed = mgr.installed().unwrap();
    assert_eq!(installed.cidrs, vec!["0.0.0.0/0", "::/0"]);
}

#[tokio::test]
async fn clear_on_windows_is_noop() {
    let op = mock_with_iface("polaris-ts");
    // 先在 Linux 装一条，再切平台 clear（模拟）——直接验 clear 在 Windows no-op：
    let mut mgr = MeshExitRouteManager::new(op.clone(), NoopExitRouteLog, Platform::Win);
    // Windows 下手动塞一个 installed（模拟跨平台状态），clear 应 no-op。
    mgr.installed = Some(InstalledRoute {
        iface: "polaris-ts".into(),
        cidrs: vec!["0.0.0.0/0".into()],
    });
    mgr.clear().await;
    // Windows clear 不发 route del、不清 installed（reconcile 入口已 no-op，clear 同款）。
    assert!(op.routes.lock().unwrap().is_empty());
    assert!(mgr.installed.is_some());
}

#[tokio::test]
async fn clear_linux_deletes_and_resets_installed() {
    let op = mock_with_iface("polaris-ts");
    let cfg = config_with(ts_system_exit_server(Some("100.64.0.1")));
    let mut mgr = MeshExitRouteManager::new(op.clone(), NoopExitRouteLog, Platform::Linux);
    reconcile_now(&mut mgr, &cfg, false).await;
    mgr.clear().await;
    assert!(mgr.installed().is_none());
    assert!(op.routes.lock().unwrap().iter().any(|r| r.0 == "del"));
}

#[tokio::test]
async fn clear_macos_skips_delete_when_iface_gone() {
    // macOS BUG2 防误删：装在 utun9，停核后 utun9 消失 → 跳过 route delete。
    let op = MockOp::default();
    *op.route_ok.lock().unwrap() = true;
    *op.tailnet_iface.lock().unwrap() = Some("utun9".to_string());
    op.utuns.lock().unwrap().insert("utun9".to_string());
    let cfg = config_with(ts_system_exit_server(Some("100.64.0.1")));
    let mut mgr = MeshExitRouteManager::new(op.clone(), NoopExitRouteLog, Platform::Mac);
    reconcile_now(&mut mgr, &cfg, false).await;
    assert_eq!(mgr.installed().unwrap().iface, "utun9");
    op.routes.lock().unwrap().clear();
    // 模拟停核：utun9 消失。
    op.utuns.lock().unwrap().clear();
    mgr.clear().await;
    assert!(mgr.installed().is_none());
    // 未发 route del（接口已消失→跳过）。
    assert!(op.routes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn clear_macos_deletes_when_iface_still_present() {
    let op = MockOp::default();
    *op.route_ok.lock().unwrap() = true;
    *op.tailnet_iface.lock().unwrap() = Some("utun9".to_string());
    op.utuns.lock().unwrap().insert("utun9".to_string());
    let cfg = config_with(ts_system_exit_server(Some("100.64.0.1")));
    let mut mgr = MeshExitRouteManager::new(op.clone(), NoopExitRouteLog, Platform::Mac);
    reconcile_now(&mut mgr, &cfg, false).await;
    op.routes.lock().unwrap().clear();
    // utun9 仍在 → clear 发 route del。
    mgr.clear().await;
    assert!(mgr.installed().is_none());
    assert!(op.routes.lock().unwrap().iter().any(|r| r.0 == "del"));
}

#[tokio::test]
async fn reassert_reinstalls_when_installed_empty() {
    let op = mock_with_iface("polaris-ts");
    let cfg = config_with(ts_system_exit_server(Some("100.64.0.1")));
    let mut mgr = MeshExitRouteManager::new(op.clone(), NoopExitRouteLog, Platform::Linux);
    // 从未装成（installed=None）→ reassert 触发 reconcile 补装。
    let out = reassert_now(&mut mgr, &cfg, false).await;
    assert!(out.changed);
    assert!(mgr.installed().is_some());
}

#[tokio::test]
async fn reassert_no_op_when_installed_intact() {
    let op = mock_with_iface("polaris-ts");
    let cfg = config_with(ts_system_exit_server(Some("100.64.0.1")));
    let mut mgr = MeshExitRouteManager::new(op.clone(), NoopExitRouteLog, Platform::Linux);
    reconcile_now(&mut mgr, &cfg, false).await;
    op.routes.lock().unwrap().clear();
    // installed 仍在、平台 Linux（不查 utun）→ reassert no-op。
    let out = reassert_now(&mut mgr, &cfg, false).await;
    assert!(!out.changed);
    assert!(op.routes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn reassert_macos_reinstalls_when_iface_disappeared() {
    let op = MockOp::default();
    *op.route_ok.lock().unwrap() = true;
    *op.tailnet_iface.lock().unwrap() = Some("utun9".to_string());
    op.utuns.lock().unwrap().insert("utun9".to_string());
    let cfg = config_with(ts_system_exit_server(Some("100.64.0.1")));
    let mut mgr = MeshExitRouteManager::new(op.clone(), NoopExitRouteLog, Platform::Mac);
    reconcile_now(&mut mgr, &cfg, false).await;
    op.routes.lock().unwrap().clear();
    // utun9 消失 → reassert 复位重装（find_tailnet_iface 仍返 utun9）。
    op.utuns.lock().unwrap().clear();
    let out = reassert_now(&mut mgr, &cfg, false).await;
    assert!(out.changed);
    assert!(mgr.installed().is_some());
}

#[tokio::test]
async fn reset_state_clears_installed_without_route_del() {
    let op = mock_with_iface("polaris-ts");
    let cfg = config_with(ts_system_exit_server(Some("100.64.0.1")));
    let mut mgr = MeshExitRouteManager::new(op.clone(), NoopExitRouteLog, Platform::Linux);
    reconcile_now(&mut mgr, &cfg, false).await;
    op.routes.lock().unwrap().clear();
    // resetState：同步复位，不发 route del（崩溃路径：内核接口随进程消失，路由已自动失效）。
    mgr.reset_state();
    assert!(mgr.installed().is_none());
    assert!(op.routes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn snapshot_baseline_is_threaded_to_apply_find_iface() {
    // 起核前基线 {utun3}；起核后 apply 反查须收到该基线（时序 diff 锚点，防误命中另跑的 Tailscale.app utun）。
    // 变异：打断 apply 里 `self.baseline_utuns.as_ref()` → 传 None → last_baseline 为 None → 转红。
    let op = MockOp::default();
    *op.route_ok.lock().unwrap() = true;
    *op.tailnet_iface.lock().unwrap() = Some("utun9".to_string());
    op.utuns.lock().unwrap().insert("utun3".to_string()); // 基线快照读到 {utun3}
    let cfg = config_with(ts_system_exit_server(Some("100.64.0.1")));
    let mut mgr = MeshExitRouteManager::new(op.clone(), NoopExitRouteLog, Platform::Mac);
    mgr.snapshot_baseline().await; // baseline = {utun3}
    reconcile_now(&mut mgr, &cfg, false).await; // apply → find_tailnet_iface(logical, Some({utun3}))
    let seen = op.last_baseline.lock().unwrap().clone();
    let mut expected = HashSet::new();
    expected.insert("utun3".to_string());
    assert_eq!(
        seen,
        Some(expected),
        "apply 反查须收到起核前基线（snapshot_baseline → find_tailnet_iface 时序 diff 锚点）"
    );
}

// ── 取消令牌（MED：点停止最长卡 18s）──────────────────────────────

/// 世代计数的三条语义：初始未取消 / cancel 后旧凭据失效 / 新凭据自复位（不被上一次取消误伤）。
///
/// **变异锁**：把 `is_cancelled` 写成恒 `false` → 第二条断言转红；把 `token()` 写成恒 0 →
/// 第三条（自复位）转红，因为新凭据仍与旧世代相等。
#[test]
fn cancel_token_is_generational_and_self_resetting() {
    let c = ExitRouteCancel::default();
    let t0 = c.token();
    assert!(!c.is_cancelled(t0), "未取消时凭据必须有效");
    c.cancel();
    assert!(c.is_cancelled(t0), "cancel 后旧凭据必须失效");
    let t1 = c.token();
    assert!(
        !c.is_cancelled(t1),
        "新一轮作业须重新取到有效凭据（一次性 AtomicBool 会把后续所有作业一起打死）"
    );
    c.cancel();
    assert!(c.is_cancelled(t1));
}

fn polling_mock(iface: &str, rounds: u32) -> MockOp {
    let op = mock_with_iface(iface);
    *op.poll_rounds.lock().unwrap() = rounds;
    op
}

/// **MED 核心断言**：反查轮询期间被取消 → 在**一个轮询周期内**退出，不跑满预算。
///
/// 真机形态：macOS 12×1.5s≈18s 的 utun 反查持着管理器独占锁，停核腿的 `clear` 排在后面 ⇒
/// 点停止最长卡 18s。此处用 12 轮 mock 轮询等价复现，断言第 1 轮就收手。
///
/// **变异实跑**（两条都验过转红）：① 删掉 `MockOp::find_tailnet_iface` 里的
/// `if cancelled() { return None }`（= 实现方不守契约）→ `polls_done` 变 12 → 转红；
/// ② 让 `apply` 传下去的判据与真实令牌脱钩（`&cancelled` → `&|| false`）→ 同样跑满 12 轮转红。
///
/// **本条够不着、由下面两条补上的那一维**：本用例的取消发生在**反查已经开始之后**，故无论凭据
/// 在哪一行快照（只要早于 find）都成立 —— 它证明不了「凭据必须早于**排队**」。真正的判据是后者：
/// 见 [`cancel_before_the_call_must_not_be_swallowed`] 与
/// [`cancel_during_clear_inner_must_not_be_swallowed`]。
#[tokio::test]
async fn cancel_during_iface_poll_exits_within_one_round() {
    let op = polling_mock("polaris-ts", 12);
    let cfg = config_with(ts_system_exit_server(Some("100.64.0.1")));
    let mut mgr = MeshExitRouteManager::new(op.clone(), NoopExitRouteLog, Platform::Linux);
    let cancel = mgr.cancel_handle();
    // 第 0 轮轮询期间「用户点了停止」：停核腿在锁外 cancel()。
    *op.on_poll.lock().unwrap() = Some(Box::new(move |r| {
        if r == 0 {
            cancel.cancel();
        }
    }));
    reconcile_now(&mut mgr, &cfg, false).await;
    assert_eq!(
        *op.polls_done.lock().unwrap(),
        1,
        "取消后必须在一个轮询周期内退出（跑满 12 轮 = 点停止卡 18s 的原样复现）"
    );
    // 状态自洽：一条路由都没下发，installed 保持 None ⇒ 后续 clear 是纯 no-op，无泄漏。
    assert!(mgr.installed().is_none(), "取消后不得留下半装状态");
    assert!(
        op.routes.lock().unwrap().is_empty(),
        "取消后不得发出任何 route 命令"
    );
}

/// 取消**恰好落在反查返回之后、`run_route(\"add\")` 之前**：也必须收手，且 `installed` 保持 None。
///
/// 这是「状态自洽」的第二个安全点 —— 装了再让 clear 删是多一对无谓的 OS 手术，而对着正在拆的
/// 会话装路由本身就是错的意图。
///
/// **变异锁**：删掉 `apply` 里 `find` 之后那道 `is_cancelled` 早退 → `routes` 出现一条 add → 转红。
#[tokio::test]
async fn cancel_between_find_and_route_add_skips_install() {
    let op = mock_with_iface("polaris-ts"); // 不轮询：find 立刻返回
    let cfg = config_with(ts_system_exit_server(Some("100.64.0.1")));
    let mut mgr = MeshExitRouteManager::new(op.clone(), NoopExitRouteLog, Platform::Linux);
    let cancel = mgr.cancel_handle();
    // 反查成功返回 Some 的那一瞬间取消（= 停核腿刚好在此刻抢到 cancel）。
    *op.on_found.lock().unwrap() = Some(Box::new(move || cancel.cancel()));
    reconcile_now(&mut mgr, &cfg, false).await;
    assert!(mgr.installed().is_none(), "取消后不得标记 installed");
    assert!(
        op.routes.lock().unwrap().is_empty(),
        "取消后不得发出 route add"
    );
}

/// 🔴 **拿锁前 cancel → 拿到锁后必让位**（凭据「早于排队」这一维的直测）。
///
/// 生产形态：`MeshRuntime::exit_route_reconcile` 在**排队等锁之前**快照凭据，取消随后发生
/// （停核腿在锁外 `cancel()`），本轮醒来后必须整轮让位。此处以「先取凭据、再取消、再带着这份
/// 凭据驱动状态机」等价复现（包装层锁外那道判定不在本 crate 内，故直接把陈旧凭据喂进来）。
///
/// **变异实跑**：把 `apply` 改回自己 `let token = self.cancel.token();`（= 二次快照）→ 取消被吞、
/// 路由照装 → 两条断言转红。这正是上一批自陈「快照位置可挪动」那条逃逸的真实风险。
#[tokio::test]
async fn cancel_before_the_call_must_not_be_swallowed() {
    let op = mock_with_iface("polaris-ts"); // Linux 形态：find 立刻返逻辑名，无轮询窗口
    let cfg = config_with(ts_system_exit_server(Some("100.64.0.1")));
    let mut mgr = MeshExitRouteManager::new(op.clone(), NoopExitRouteLog, Platform::Linux);

    let token = mgr.cancel_handle().token(); // ① 排队之前快照
    mgr.cancel_handle().cancel(); // ② 排队期间用户点了停止
    mgr.reconcile(&cfg, false, token).await; // ③ 拿到锁才轮到本轮跑

    assert!(
        mgr.installed().is_none(),
        "拿锁前已被取消 → 不得标记 installed（否则停核后内存态与 OS 态各说各话）"
    );
    assert!(
        op.routes.lock().unwrap().is_empty(),
        "拿锁前已被取消 → 一条 route 命令都不得下发：Linux 下 find 即返，\
         这里装的就是**给一个已经停了的核**装出口路由"
    );
}

/// 🔴 **锁内 `clear_inner` 期间的取消也不得被吞**（reviewer 报的那个真实窗口）。
///
/// 形态：包装层的锁外判定已经过了（那一刻确实没被取消），随后 `reconcile_once` → `clear_inner`
/// 对**已装**路由发 `route del`（真实 await）；就在这段时间里用户点了停止。若 `apply` 自己
/// 二次快照凭据，它读到的是**取消之后**的世代 ⇒ 判据恒为「未取消」⇒ macOS 下停核仍要等满
/// 18s 轮询、Linux 下直接给已停的核重装路由。
///
/// **变异实跑**：`apply` 改回二次快照 → 第二条断言看到 `("add", …)` → 转红。
#[tokio::test]
async fn cancel_during_clear_inner_must_not_be_swallowed() {
    let op = mock_with_iface("polaris-ts");
    let cfg_v4 = config_with(ts_system_exit_server(Some("100.64.0.1")));
    let mut mgr = MeshExitRouteManager::new(op.clone(), NoopExitRouteLog, Platform::Linux);
    // 先装上 v4（让下一轮的 reconcile_once 必须先 clear_inner → 真的发一次 route del）。
    reconcile_now(&mut mgr, &cfg_v4, false).await;
    assert!(mgr.installed().is_some(), "前置：第一轮须装成");
    op.routes.lock().unwrap().clear();

    // 第二轮：目标变成 v4+v6 ⇒ 先 del 再 add。取消恰好落在那次 del 里。
    let cancel = mgr.cancel_handle();
    *op.on_route.lock().unwrap() = Some(Box::new(move |o| {
        if o == "del" {
            cancel.cancel();
        }
    }));
    let token = mgr.cancel_handle().token(); // 包装层拿锁前快照（此刻确实未被取消）
    mgr.reconcile(&cfg_v4, true, token).await;

    let routes = op.routes.lock().unwrap().clone();
    assert_eq!(
        routes.iter().filter(|(o, ..)| o == "del").count(),
        1,
        "旧路由该删还是要删（取消绝不留 OS 半态）"
    );
    assert!(
        !routes.iter().any(|(o, ..)| o == "add"),
        "清理期间发生的取消必须被本轮认出来 —— 二次快照会把它整个吞掉，于是给一个正在拆的会话装上路由"
    );
    assert!(
        mgr.installed().is_none(),
        "让位后 installed 保持 None，状态自洽"
    );
}

/// 取消是**自复位**的：被打断的那一轮之后，下一轮对账必须能正常装上路由。
///
/// 反面即「一次点停止就永久废掉出口路由托管」——用一次性 `AtomicBool` 当令牌正会掉进这个坑。
///
/// **变异锁**：把 `ExitRouteCancel::token()` 改成恒返 0（即凭据不再跟随世代）→ 第二轮的
/// `is_cancelled` 恒 true → `installed` 仍为 None → 转红。
#[tokio::test]
async fn cancelled_round_does_not_poison_the_next_one() {
    let op = polling_mock("polaris-ts", 12);
    let cfg = config_with(ts_system_exit_server(Some("100.64.0.1")));
    let mut mgr = MeshExitRouteManager::new(op.clone(), NoopExitRouteLog, Platform::Linux);
    let cancel = mgr.cancel_handle();
    *op.on_poll.lock().unwrap() = Some(Box::new(move |r| {
        if r == 0 {
            cancel.cancel();
        }
    }));
    reconcile_now(&mut mgr, &cfg, false).await;
    assert!(mgr.installed().is_none(), "第一轮被取消 → 未装");
    // 第二轮：不再取消（钩子清空），须正常装上。
    *op.on_poll.lock().unwrap() = None;
    *op.polls_done.lock().unwrap() = 0;
    let out2 = reconcile_now(&mut mgr, &cfg, false).await;
    assert!(out2.changed, "新一轮对账须恢复正常（世代已自复位）");
    assert!(mgr.installed().is_some());
    assert_eq!(
        *op.polls_done.lock().unwrap(),
        12,
        "未取消时轮询跑满预算（反证上一轮的提前退出确由取消引起，而非轮询自己坏了）"
    );
}

#[tokio::test]
async fn latest_wins_pending_overrides_inflight() {
    // 模拟 latest-wins：在 reconcile 内部 drain 会取最后 pending。
    // 由于单线程 await，这里直接验：连续两次 reconcile（第二次在第一次返回后）→ 取后者。
    let op = mock_with_iface("polaris-ts");
    let cfg_v4 = config_with(ts_system_exit_server(Some("100.64.0.1")));
    let mut mgr = MeshExitRouteManager::new(op.clone(), NoopExitRouteLog, Platform::Linux);
    reconcile_now(&mut mgr, &cfg_v4, false).await;
    reconcile_now(&mut mgr, &cfg_v4, true).await; // v6
    assert_eq!(mgr.installed().unwrap().cidrs, vec!["0.0.0.0/0", "::/0"]);
}
