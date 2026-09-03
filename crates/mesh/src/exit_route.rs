//! 出口路由托管（System 模式 TS exit_node 的出网路由）。
//!
//! 1:1 移植自 上游 `src/main/services/mesh-exit-route-manager.ts` + `src/shared/mesh-exit-route.ts`。
//!
//! 背景（真机实证）：sing-box 的 tailscale system_interface 只往内核接口装 tailnet/accept 子网路由，**不为
//! exit_node 装出口 0/0 路由** → 绑接口 dialer 拨公网 `network unreachable`。手动补一条 ifscope default（0/0）
//! 即通。本管理器在「选中的全局出口 = TS System + 承载全隧道」时，于其内核接口装单条 ifscope default；
//! 停核/切节点/切模式时清理。决策见 [`plan_mesh_exit_route`]（纯函数）。
//!
//! 平台：
//! - macOS：内核 utun 名动态 → 反查接口名 → helper(root) `route -ifscope`；
//! - Linux：固定名 polaris-ts → app 自身 `ip route`（已有 CAP_NET_ADMIN），独立表 + oif 规则；
//! - Windows：禁 System，本管理器 no-op。
//!
//! ## 纯逻辑边界
//! 本 crate 不触碰宿主网络/进程：平台路由 add/del、utun 列表查询、helper 调用全经 [`ExitRouteOp`] trait
//! 注入（应用层实现；测试 mock）。状态机的对账/重申/最新生效语义是纯逻辑。

#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use polaris_config_engine::builder::endpoint_routes::{
    mesh_node_carries_full_tunnel, mesh_uses_system_interface, TS_SYSTEM_INTERFACE_NAME,
};
use polaris_config_engine::user_config::app_config::UserConfig;
use polaris_config_engine::user_config::server_config::Protocol;
use polaris_helper_proto::Platform;

/// 出口默认路由：单条 ifscope `default`（0/0），装在 System 内核接口上、作用域限定该接口。
/// 上游 `EXIT_DEFAULT_V4` / `EXIT_DEFAULT_V6`。
pub const EXIT_DEFAULT_V4: &[&str] = &["0.0.0.0/0"];
pub const EXIT_DEFAULT_V6: &[&str] = &["::/0"];

/// 出口路由计划。上游 `MeshExitRoutePlan`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshExitRoutePlan {
    /// 内核接口名（逻辑名 polaris-ts）。
    pub iface: String,
    /// 要装的出口路由（按 enable_ipv6 含/不含 v6）。
    pub cidrs: Vec<String>,
}

/// System 模式是否在该平台支持（Windows 禁）。上游 `meshSystemSupportedOnPlatform`。
pub fn mesh_system_supported_on_platform(platform: Platform) -> bool {
    platform != Platform::Win
}

/// 出口托管决策（纯函数）：当前选中的全局出口节点是否需要 Polaris 自装出口路由、装到哪张内核接口。
///
/// 仅 **TS System + 承载全隧道（exit_node 设了）** 需要。返回 None 的情形：
/// - 无 TS 节点 / TS 是 gVisor / TS 无 exit_node（不承载全隧道）；
/// - WG/WARP 由 sing-box 按 allowed_ips 自装 → 本函数只管 TS。
///
/// 上游 `planMeshExitRoute`。`enable_ipv6` 控制是否含 v6 默认路由。
pub fn plan_mesh_exit_route(config: &UserConfig, enable_ipv6: bool) -> Option<MeshExitRoutePlan> {
    let ts = config
        .servers
        .iter()
        .find(|s| s.protocol == Protocol::Tailscale)?;
    if !mesh_uses_system_interface(ts) {
        return None;
    }
    if !mesh_node_carries_full_tunnel(ts) {
        return None;
    }
    // 还须 exit_node 实际设了：mesh_node_carries_full_tunnel 只看 allowInternet，而 endpoint 仅在 exitNode
    // 非空时才下发 exit_node。旧/导入配置可能 allowInternet=true 但 exitNode 空 → 装了出口路由却无 exit peer
    // 转发 → 默认流量黑洞。故与 endpoint 下发口径对齐：exitNode 为空则不托管。
    let has_exit = ts
        .tailscale_settings
        .as_ref()
        .and_then(|t| t.exit_node.as_deref())
        .map(|e| !e.trim().is_empty())
        .unwrap_or(false);
    if !has_exit {
        return None;
    }
    let mut cidrs: Vec<String> = EXIT_DEFAULT_V4.iter().map(|s| s.to_string()).collect();
    if enable_ipv6 {
        cidrs.extend(EXIT_DEFAULT_V6.iter().map(|s| s.to_string()));
    }
    Some(MeshExitRoutePlan {
        iface: TS_SYSTEM_INTERFACE_NAME.to_string(),
        cidrs,
    })
}

/// 已装路由的内存态。上游 `InstalledRoute`。iface = 实际装路由的接口名（macOS=反查到的 utunN）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledRoute {
    pub iface: String,
    pub cidrs: Vec<String>,
}

/// 在飞出口路由作业的**取消令牌**（世代计数器）。
///
/// # 为什么需要它（点停止最长卡 18s 的根因）
///
/// [`ExitRouteOp::find_tailnet_iface`] 在 macOS 下要等 sing-box 建出 TS utun，实现方以
/// 12×1.5s≈18s 轮询等待；而这条轮询跑在**持有 `MeshExitRouteManager` 独占锁**的
/// `MeshExitRouteManager::apply` 里。停核腿的 [`clear`](MeshExitRouteManager::clear)、崩溃腿的
/// [`reset_state`](MeshExitRouteManager::reset_state)、新一轮起核的
/// [`snapshot_baseline`](MeshExitRouteManager::snapshot_baseline) 全部排在这把锁后面 ⇒
/// **用户点「停止」最长要等 18s**。世代守卫解决不了这一条：它挡的是「已被接管的旧腿再**开启**一轮」，
/// 而合法当权的那条腿一样会把停核堵住 —— 轮询本身不可中断才是根因。
///
/// # 语义
///
/// [`cancel`](Self::cancel) 只把世代 +1（无阻塞、可在锁外调用）；任何以旧世代凭据
/// （[`token`](Self::token)）跑着的作业在下一个检查点看到世代已变即收手。世代计数**自复位**：
/// 下一次作业重新 `token()` 快照到新值，不会被上一次的取消误伤（这正是不用一次性 `AtomicBool` 的理由）。
///
/// # 取消后的状态自洽（本类型的核心契约）
///
/// 取消只在**两个安全点**生效，故绝不会留半态：
/// - `find_tailnet_iface` 的轮询点之间（此时一条路由都还没下发 → `installed` 保持 `None`）；
/// - `find` 返回之后、`run_route("add")` 之前（同上）。
///
/// **绝不在 `run_route` 内部取消**：那一次调用在 Linux 下会展开成「`ip rule add` + 逐 cidr
/// `ip route replace`」的命令序列，中途收手就会留下「规则装了、路由没装」且 `installed=None` 的
/// OS 级半态 —— 没有任何后续 `clear` 会去收它（`clear_inner` 靠 `installed` 判有无）。
#[derive(Debug, Default)]
pub struct ExitRouteCancel {
    epoch: AtomicU64,
}

impl ExitRouteCancel {
    /// 请求取消当前在飞作业（世代 +1）。幂等、无阻塞、可在持锁方之外调用。
    pub fn cancel(&self) {
        self.epoch.fetch_add(1, Ordering::SeqCst);
    }

    /// 快照当前世代 = 本轮作业的凭据。**须在排队等锁之前取**，这样「排队期间发生的取消」也算数。
    ///
    /// # 正确判据是「早于排队」而非「早于反查」
    ///
    /// 凭据一旦在**拿到锁之后**才快照，取消信号就有一个被整段吞掉的窗口：作业已经在锁内跑（
    /// `MeshExitRouteManager::reconcile_once` → `clear_inner` 在 `installed=Some` 时有真实 await：
    /// `list_utuns` / `run_route("del")`），期间发生的 `cancel()` 会被随后那次快照读成「取消之后的世代」
    /// ⇒ [`is_cancelled`](Self::is_cancelled) 恒假 ⇒ 停核照样等满 macOS 18s 轮询（原 bug 原样复现），
    /// Linux 下更会给一个**已经停了的核**装上出口路由。故凭据由调用方（持锁方外层）快照后**作为参数
    /// 一路传到 `MeshExitRouteManager::apply`**，管理器内部不得二次快照。
    #[must_use]
    pub fn token(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }

    /// 凭据是否已失效（= 快照之后发生过至少一次 [`cancel`](Self::cancel)）。
    #[must_use]
    pub fn is_cancelled(&self, token: u64) -> bool {
        self.epoch.load(Ordering::SeqCst) != token
    }
}

/// 平台出口路由操作契约（取代 Polaris 的 `execFile('ifconfig'/'ip')` + `IPrivilegedHelper.routeAdd/Del`）。
///
/// 实现方负责：
/// - macOS：`route add/del -ifscope <iface> -net <cidr>` 经 helper(root)；
/// - Linux：独立表 7732 + oif 规则，`ip route/rule`（CAP_NET_ADMIN，app 自身）；
/// - `list_utuns`：macOS ifconfig -l 解析（其它平台返回空集）；
/// - `find_tailnet_iface`：macOS 按时序 diff + tailnet 100.x 地址反查 utun；其它平台返逻辑名。
///
/// 全部永不 panic（Polaris 一致：catch→忽略/日志）。本 crate 消费 bool / Option。
#[async_trait]
pub trait ExitRouteOp: Send + Sync {
    /// 装/删路由。返回 ok=true 表成功。op="add"|"del"。
    async fn run_route(&self, op: &str, iface: &str, cidrs: &[String]) -> bool;

    /// 列出当前 utun 接口名集合（macOS；其它平台返空）。上游 `listUtuns`。
    async fn list_utuns(&self) -> HashSet<String>;

    /// 反查 TS 内核接口名。macOS = 按时序 diff+tailnet 地址反查；其它平台返 logical_name 本身。
    /// 返 None = 未找到（上游 `resolveIface` 轮询超时）。
    ///
    /// `baseline` = 起核前的 utun 快照（[`MeshExitRouteManager::snapshot_baseline`] 采集）：macOS 时序 diff
    /// 锚点——「起核后新增的 utun」即 sing-box 创建的，比纯地址反推更稳（不误命中另跑的 Tailscale.app utun）。
    /// `None` = 无基线（退化为纯地址反推，上游 `probeMacosTailnetIface` 兜底）；非 macOS 平台忽略。
    ///
    /// # `cancelled`：实现方**必须**在每个轮询点检查（契约，不是建议）
    ///
    /// macOS 实现要轮询等待 utun 出现（12×1.5s≈18s），而整条轮询持着管理器独占锁 —— 停核 / 复位 /
    /// 新起核全排在它后面。故实现方须在**每一轮 sleep 之后、下一次探测之前**调一次 `cancelled()`，
    /// 为真即立刻返回 `None`（收手窗口 ≤ 一个轮询周期）。不检查 = 点停止最长卡 18s（见
    /// [`ExitRouteCancel`]）。不轮询的实现（Linux/其它平台直接返逻辑名）天然满足契约。
    async fn find_tailnet_iface(
        &self,
        logical_name: &str,
        baseline: Option<&HashSet<String>>,
        cancelled: &(dyn Fn() -> bool + Send + Sync),
    ) -> Option<String>;
}

/// 日志契约（取代 上游 `LogFn`）。level: "info"|"warn"|"error"。
pub trait ExitRouteLog: Send + Sync {
    fn log(&self, level: &str, message: &str);
}

/// 空实现日志。
pub struct NoopExitRouteLog;
impl ExitRouteLog for NoopExitRouteLog {
    fn log(&self, _level: &str, _message: &str) {}
}

/// 出口路由管理器（状态机）。上游 `MeshExitRouteManager`。
///
/// latest-wins 对账：调用期间（macOS apply 轮询接口可达 18s）若被再次调用（如热切换），记最新目标，
/// 当前轮结束后续跑——避免「轮询中切节点 → 第二次调用被丢 → 路由停在旧选中」。
pub struct MeshExitRouteManager<O, L> {
    op: O,
    log: L,
    platform: Platform,
    installed: Option<InstalledRoute>,
    reconciling: bool,
    pending: Option<(bool, Option<MeshExitRoutePlan>)>, // (enable_ipv6, plan)
    baseline_utuns: Option<HashSet<String>>,
    /// 在飞作业取消令牌（见 [`ExitRouteCancel`]）。管理器自持一份，调用方经
    /// [`cancel_handle`](Self::cancel_handle) 取同一个 `Arc` —— 它必须在**锁外**可达，
    /// 否则「让持锁的 18s 轮询提前收手」这件事本身就得先拿到那把锁。
    cancel: Arc<ExitRouteCancel>,
}

/// 对账结果（便于测试断言；Polaris 无显式返回，靠日志/副作用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileOutcome {
    /// 本次对账后已装路由（None=未装/已清）。
    pub installed: Option<InstalledRoute>,
    /// 是否做了变更（装/清）。
    pub changed: bool,
}

impl<O, L> MeshExitRouteManager<O, L>
where
    O: ExitRouteOp,
    L: ExitRouteLog,
{
    /// 新建。platform 由调用方注入（Polaris 读 process.platform）。
    pub fn new(op: O, log: L, platform: Platform) -> Self {
        Self {
            op,
            log,
            platform,
            installed: None,
            reconciling: false,
            pending: None,
            baseline_utuns: None,
            cancel: Arc::new(ExitRouteCancel::default()),
        }
    }

    /// 取消令牌句柄（**锁外**持有）。调用方在停核 / 崩溃复位 / 新起核前先 `cancel()`，
    /// 在飞的 macOS 反查轮询即在一个周期内收手，排队者立刻拿到锁。见 [`ExitRouteCancel`]。
    #[must_use]
    pub fn cancel_handle(&self) -> Arc<ExitRouteCancel> {
        Arc::clone(&self.cancel)
    }

    /// 当前已装路由（内存态，便于测试/观测）。
    pub fn installed(&self) -> Option<&InstalledRoute> {
        self.installed.as_ref()
    }

    /// macOS：起核前快照 utun 列表（时序 diff 锚点）。上游 `snapshotBaseline`。
    /// 其它平台 no-op。ProxyManager 在起核前调用。
    pub async fn snapshot_baseline(&mut self) {
        if self.platform != Platform::Mac {
            return;
        }
        self.baseline_utuns = Some(self.op.list_utuns().await);
    }

    /// 对齐到目标态：起核就绪 / 切节点 / 切模式后调用（fire-and-forget，绝不抛）。
    /// latest-wins：在飞期间被再次调用则记最新目标，当前轮结束后续跑。
    /// 上游 `reconcile`。
    ///
    /// `token` = 调用方在**排队等锁之前**快照的取消凭据（见 [`ExitRouteCancel::token`]）：本方法把它
    /// 一路带到 `apply`，那里不得再自己 `cancel.token()` —— 二次快照会把「本轮已在锁内
    /// 跑、期间发生的 cancel」整段吞掉。
    pub async fn reconcile(
        &mut self,
        config: &UserConfig,
        enable_ipv6: bool,
        token: u64,
    ) -> ReconcileOutcome {
        let plan = plan_mesh_exit_route(config, enable_ipv6);
        self.pending = Some((enable_ipv6, plan));
        if self.reconciling {
            // 在飞 → 已记 pending；由在飞那轮 drain。返回当前态（本次未直接变更）。
            return ReconcileOutcome {
                installed: self.installed.clone(),
                changed: false,
            };
        }
        self.reconciling = true;
        let mut changed = false;
        let mut last_installed = self.installed.clone();
        // drain pending：latest-wins 续跑。
        //
        // 取消判据**不放在这里**：本方法持 `&mut self`（生产侧还外套一把 tokio Mutex），drain 期间
        // 没有第二个调用者能写 `pending` ⇒ 这个循环今天恒只跑一轮，加在这里的守卫是**永不可达**的
        // 死分支（门要能被看见）。真正需要判取消的两处都是可达且已覆盖的：
        // ① 在飞的 macOS 反查轮询（见 [`Self::apply`]）；
        // ② 「排队等锁期间被取消」—— 那要在**拿锁之前**快照凭据，只有锁的持有方（应用层的
        //    `MeshRuntime::exit_route_*` 包装）够得着，故守在那一层。
        while let Some((_, pending_plan)) = self.pending.take() {
            let outcome = self.reconcile_once(pending_plan, token).await;
            if outcome.changed {
                changed = true;
            }
            last_installed = outcome.installed;
        }
        self.reconciling = false;
        ReconcileOutcome {
            installed: last_installed,
            changed,
        }
    }

    /// 单次对账（核心纯逻辑决策 + trait 副作用）。上游 `reconcileOnce`。
    ///
    /// `token` 原样透传给 [`apply`](Self::apply)：本方法体内的 `clear_inner` 有真实 await
    /// （`list_utuns` / `run_route("del")`），那段时间正是取消最容易发生的窗口，凭据必须是**进这段
    /// 之前**的那一份。
    async fn reconcile_once(
        &mut self,
        plan: Option<MeshExitRoutePlan>,
        token: u64,
    ) -> ReconcileOutcome {
        if !mesh_system_supported_on_platform(self.platform) {
            return ReconcileOutcome {
                installed: self.installed.clone(),
                changed: false,
            };
        }
        let desired_key = plan.as_ref().map(|p| p.cidrs.join(",")).unwrap_or_default();
        let current_key = self
            .installed
            .as_ref()
            .map(|i| i.cidrs.join(","))
            .unwrap_or_default();
        // 注：macOS 接口名动态，desired.iface 是逻辑名；实际接口在 apply 内反查。仅以 cidrs 判变更。
        let has_plan = plan.is_some();
        let has_installed = self.installed.is_some();
        if desired_key == current_key && has_plan == has_installed {
            // 无变更。
            return ReconcileOutcome {
                installed: self.installed.clone(),
                changed: false,
            };
        }
        // 先清旧。
        self.clear_inner().await;
        // 再装新。
        if let Some(p) = plan {
            self.apply(&p, token).await;
        }
        ReconcileOutcome {
            installed: self.installed.clone(),
            changed: true,
        }
    }

    /// 出口路由重申（TS 出口 re-advertise 恢复腿调用，R3）。修两个真缺口而**不 churn 已存路由**：
    /// ① installed 为空——resolveIface 18s 轮询超时过 → 路由从未装成 → 重新 reconcile 补装；
    /// ② macOS installed.iface 已消失（接口换名/停了 → 其 ifscope 路由随接口自动失效，内存 installed 残留）
    ///   → 复位 installed 后 reconcile 重装。
    /// 其余情形不动——避免对已存 ifscope 路由重发 `route add` 的 EEXIST 噪音。上游 `reassert`。
    ///
    /// `token` 语义同 [`reconcile`](Self::reconcile)（调用方拿锁前快照，一路带到 `apply`）。
    pub async fn reassert(
        &mut self,
        config: &UserConfig,
        enable_ipv6: bool,
        token: u64,
    ) -> ReconcileOutcome {
        if !mesh_system_supported_on_platform(self.platform) {
            return ReconcileOutcome {
                installed: self.installed.clone(),
                changed: false,
            };
        }
        // 无 System exit 出口 → 无路由可保。仅判 Some/None（reassert 不消费 plan 细节——不 churn 已存路由）。
        if plan_mesh_exit_route(config, enable_ipv6).is_none() {
            return ReconcileOutcome {
                installed: self.installed.clone(),
                changed: false,
            };
        }
        if self.installed.is_none() {
            // 从未装成 → 重新对账补装。
            return self.reconcile(config, enable_ipv6, token).await;
        }
        // macOS：installed.iface 是否已消失。
        if self.platform == Platform::Mac {
            if let Some(cur) = &self.installed {
                let utuns = self.op.list_utuns().await;
                if !utuns.contains(&cur.iface) {
                    self.log.log(
                        "info",
                        &format!("出口路由重申:接口 {} 已不在 → 复位重装", cur.iface),
                    );
                    self.installed = None;
                    return self.reconcile(config, enable_ipv6, token).await;
                }
            }
        }
        // 其余情形不动。
        ReconcileOutcome {
            installed: self.installed.clone(),
            changed: false,
        }
    }

    /// 停核 / teardown：清理已装的出口路由。上游 `clear`。
    pub async fn clear(&mut self) {
        if !mesh_system_supported_on_platform(self.platform) {
            return;
        }
        self.clear_inner().await;
    }

    /// clear 的核心逻辑（含 macOS BUG2 防误删：接口已消失 → 跳过 route delete）。
    async fn clear_inner(&mut self) {
        let cur = match self.installed.take() {
            Some(c) => c,
            None => return,
        };
        // macOS BUG2 防误删：停核时 sing-box 拆除 TS utun，其 ifscope 路由随接口自动消失。此时若再对
        // 已不存在的 iface 发 route delete，macOS 会落到 main 表、误删主 TUN 的拆半默认。故接口已消失 → 跳过。
        if self.platform == Platform::Mac {
            let utuns = self.op.list_utuns().await;
            if !utuns.contains(&cur.iface) {
                self.log.log(
                    "info",
                    &format!(
                        "出口路由:接口 {} 已随停核移除,ifscope 路由自动清理,跳过 route delete(防误删主表)",
                        cur.iface
                    ),
                );
                return;
            }
        }
        let ok = self.op.run_route("del", &cur.iface, &cur.cidrs).await;
        if ok {
            self.log.log(
                "info",
                &format!("出口路由已清理: {} {}", cur.iface, cur.cidrs.join(",")),
            );
        } else {
            self.log.log(
                "warn",
                &format!("出口路由清理失败(best-effort): {}", cur.iface),
            );
        }
    }

    /// 崩溃 / giveUp 等非正常拆除的同步内存态复位。上游 `resetState`。
    /// 内核接口随进程销毁、其路由已自动消失，故无需发删命令；但必须清掉残留 installed。
    pub fn reset_state(&mut self) {
        self.installed = None;
    }

    /// 装路由（apply）。上游 `apply`。
    ///
    /// **取消的两个安全点**都在这里（见 [`ExitRouteCancel`]「取消后的状态自洽」）：反查轮询点之间、
    /// 以及反查返回后 `run_route("add")` 之前。两处收手时 `installed` 都还是 `None` ⇒ 无半态、无泄漏。
    ///
    /// # 凭据只收、不取（本方法**绝不** `self.cancel.token()`）
    ///
    /// `token` 由调用方在**排队等锁之前**快照并一路传下来。曾经这里自己快照过一次，那是个真洞：
    /// 包装层的凭据判定在锁外（`runtime/mesh.rs` 的 `exit_route_reconcile`/`exit_route_reassert`），
    /// 两点之间隔着 `reconcile_once` → `clear_inner` 的真实 await（`list_utuns` / `run_route("del")`），
    /// 期间发生的 `cancel()` 会被这里的二次快照读成「取消之后的世代」⇒ 整个取消被吞：macOS 下停核仍
    /// 卡满 18s 轮询（原 bug 原样复现），Linux 下 `find` 即返 ⇒ 给一个已经停了的核装上出口路由。
    /// 判据是「凭据早于**排队**」，不是「凭据早于**反查**」。
    async fn apply(&mut self, plan: &MeshExitRoutePlan, token: u64) {
        let cancel = Arc::clone(&self.cancel);
        let cancelled = move || cancel.is_cancelled(token);
        // 传入起核前 utun 基线（macOS 时序 diff 锚点；其它平台忽略）。
        let iface = match self
            .op
            .find_tailnet_iface(&plan.iface, self.baseline_utuns.as_ref(), &cancelled)
            .await
        {
            Some(i) => i,
            None => {
                if self.cancel.is_cancelled(token) {
                    // 与「真没找到」区分：这是被停核/复位打断，不是 tailnet 没起来 —— 混成同一句 warn
                    // 会让真机日志把「用户点了停止」误读成「TS 接口反查失败」。
                    self.log.log(
                        "info",
                        "出口路由托管:反查被取消(停核/复位/新起核) → 不装路由",
                    );
                } else {
                    self.log.log(
                        "warn",
                        "出口路由托管:未找到 TS 内核接口(tailnet 100.x),跳过装路由",
                    );
                }
                return;
            }
        };
        // 反查刚好赶在取消之前返回 → 这条路由属于一个正在拆的会话，装了也只是等着被 clear 删掉
        //（而 clear 已经在锁上排队）。在此收手：installed 保持 None，状态自洽。
        if self.cancel.is_cancelled(token) {
            self.log.log(
                "info",
                &format!("出口路由托管:反查得 {iface} 后被取消 → 放弃装路由"),
            );
            return;
        }
        let ok = self.op.run_route("add", &iface, &plan.cidrs).await;
        if ok {
            self.installed = Some(InstalledRoute {
                iface: iface.clone(),
                cidrs: plan.cidrs.clone(),
            });
            self.log.log(
                "info",
                &format!(
                    "出口路由已装: {} {}(System TS exit 出网)",
                    iface,
                    plan.cidrs.join(",")
                ),
            );
        } else {
            self.log.log(
                "warn",
                &format!("出口路由装失败: {} {}", iface, plan.cidrs.join(",")),
            );
        }
    }
}

#[cfg(test)]
mod tests;
