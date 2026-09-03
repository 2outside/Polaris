//! helper 类 command（上游 `helper-handlers.ts` 的 helper 部分）。
//!
//! 映射 channel：
//! - `helper:getStatus` → [`helper_get_status`]
//! - `helper:install` → [`helper_install`]（弹一次提权框）
//! - `helper:uninstall` → [`helper_uninstall`]
//!
//! 真实 install/uninstall 经 helper-client HelperManager（SysOps 跑 install 脚本 + 提权），
//! 属系统交互批次；本层提供状态查询 + 命令入口。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tauri::State;

use crate::response::ApiResponse;
use crate::runtime::helper::{
    decide_uninstall_preflight, uninstall_preflight_stop, HelperActionErrorCode,
    HelperActionResult, HelperStatusSnapshot, UninstallPreflight,
};
use crate::runtime::uninstall::{stop_core_outcome, StepOutcome};
use crate::runtime::AppRuntime;

/// Helper 服务安装、升级或卸载期间的停核复查节拍。
///
/// 提权框可挂几分钟，而「用户点连接 → root 核起来」是秒级动作，故复查必须密于分钟级；
/// 500ms 一次的代价只是一次进程内 `proxy.status()` 读（不碰 socket、不碰系统）。
const HELPER_MUTATION_RECHECK_INTERVAL: Duration = Duration::from_millis(500);

/// Helper 服务变更收尾时**等看门狗自然退出**的预算上限。
///
/// 取值依据是「看门狗最后一拍最坏要花多久」，不是拍脑袋：那一拍最重的动作是一次
/// `ProxyRuntime::stop()` —— 杀核 `SIGTERM → 5s 宽限 → SIGKILL` + 收割，叠加还原系统 DNS、
/// 清系统代理各一次 exec。20s 给足这条链，且封顶了 IPC 应答的最坏等待。
///
/// **超预算也绝不 abort**（见 [`join_watchdog_cooperatively`]）：这个数只决定「命令还等不等」，
/// 不决定「看门狗死不死」。
const WATCHDOG_JOIN_BUDGET: Duration = Duration::from_secs(20);

/// 上游 `HELPER_GET_STATUS`：helper 安装/就绪/版本状态（真探测，W20 后带恢复腿）。
///
/// **必须异步跑**：W20 恢复腿让「已装但停着」的探测先拉服务再复核（典型 3-5s，起即崩/管道不绑时
/// 更久）。同步命令在主线程执行，这个量级会冻 UI——与 install/uninstall 同口径挂 spawn_blocking。
#[tauri::command]
pub async fn helper_get_status(
    state: State<'_, AppRuntime>,
    _force: Option<bool>,
) -> Result<ApiResponse<HelperStatusSnapshot>, ()> {
    let helper = state.helper.clone();
    Ok(
        match tokio::task::spawn_blocking(move || helper.status()).await {
            Ok(s) => ApiResponse::ok(s),
            Err(e) => ApiResponse::err(format!("helper 状态任务异常终止: {e}")),
        },
    )
}

/// 上游 `HELPER_INSTALL`：安装 helper（弹一次提权框）。
///
/// 提权三态（成功/用户取消/失败）在 [`HelperActionResult`] 内表达——外层恒 `ok`（IPC 层不失败，
/// 用户取消是正常流程，前端读 `r.status`/`r.error_code` 本地化展示）。**提权本身是真机门**。
///
/// **提权框（可 30s+）在 `spawn_blocking` 线程等**，不占 tokio worker、不冻 UI ——
/// 与 [`helper_uninstall`] 同口径（两条腿都是「同步 + 弹框 + 分钟级阻塞」，不该一条 async 一条 sync）。
#[tauri::command]
pub async fn helper_install(
    state: State<'_, AppRuntime>,
) -> Result<ApiResponse<HelperActionResult>, ()> {
    let proxy_status = state.proxy().status();
    let helper = state.helper.clone();
    if helper_install_blocked_by_proxy(proxy_status.running, proxy_status.started_via_helper) {
        return Ok(ApiResponse::ok(HelperActionResult {
            success: false,
            error_code: Some(HelperActionErrorCode::ProxyRunning),
            diagnostic: Some("stop the helper-managed proxy before upgrading helper".to_owned()),
            status: helper.status(),
        }));
    }

    // 初始已运行的 TUN 明确拒绝；随后提权框可能停留数分钟，期间若用户又从托盘起了 TUN，
    // 复用服务变更看门狗立即停掉，避免安装脚本重启 daemon 时留下 UI 仍报 running 的失真态。
    let outcome = with_helper_service_mutation_core_guard(&state, |_stop| async move {
        tokio::task::spawn_blocking(move || helper.install()).await
    })
    .await;
    Ok(match outcome {
        Ok(r) => ApiResponse::ok(r),
        Err(e) => ApiResponse::err(format!("helper 安装任务异常终止: {e}")),
    })
}

/// 只有 helper 管理的运行核会随 daemon 升级被终止；System/Manual 的 app 直起核不受影响，
/// 因而不能把“代理正在运行”笼统当成拒绝条件。
const fn helper_install_blocked_by_proxy(running: bool, started_via_helper: bool) -> bool {
    matches!(
        decide_uninstall_preflight(running, started_via_helper),
        UninstallPreflight::StopCoreFirst
    )
}

/// 上游 `HELPER_UNINSTALL`：卸载 helper（**先零提权停核**，再弹一次提权框卸载）。
///
/// # 停核腿（契约 `polaris-上游-capability-contract.md:93`「卸载前零提权停核」）
///
/// 代理正经 helper 运行时，先用**仍在的** helper 停掉它的 root/SYSTEM 受管核，再卸载。
/// 顺序不可换：卸载会连 daemon 带 socket 一起删掉，之后那个 root 核就成了用户态杀不动的孤儿
/// （TUN 还占着 → 全网断），只能落 forceKill 裸弹一次无引导的提权框。
///
/// 判定 + 停失败语义（**继续卸载**，与 `update_install` 的停代理腿刻意相反）收在纯函数
/// [`uninstall_preflight_stop`] —— 那里有真值表与理由；本命令只做注入。
///
/// # 一次前置停核**不够**：整段卸载期都要看着
///
/// 前置腿的判据是「进 `uninstall()` 之前」的一张快照，而 `uninstall()` 会弹提权框并同步等到用户
/// 处理（分钟级）。这段时间 helper 完整活着，用户点一下「连接」就能把 root 受管核起起来 ——
/// 卸载一完成它就是孤儿核 + 断网，正是这条腿要防的形态。故整段卸载期挂一条
/// [`helper_service_mutation_stop_watchdog`]，见到「经 helper 起来的核」就再停一次。
///
/// # `uninstall()` 走 `spawn_blocking`
///
/// 它内部同步 spawn 提权框并等其退出（分钟级）。在 async 命令里直调会把一个 tokio worker 占死
/// 整段等待期 —— 而本批同时把 stats 的三条 poller 从「每拍阻塞式回读窗口」改成读缓存，
/// 正是因为主循环被这类原生模态占住时不该再连累 worker。
#[tauri::command]
pub async fn helper_uninstall(
    state: State<'_, AppRuntime>,
) -> Result<ApiResponse<HelperActionResult>, ()> {
    let helper = state.helper.clone();
    // 停核腿的结果在这条腿上**故意忽略**：helper 单卸载停不掉也继续卸（真值表见
    // `uninstall_preflight_stop` 文档）。完全卸载腿读同一个值并中止 —— 政策不同，机制同一份。
    let outcome = with_helper_service_mutation_core_guard(&state, |_stop| async move {
        tokio::task::spawn_blocking(move || helper.uninstall()).await
    })
    .await;

    Ok(match outcome {
        Ok(r) => ApiResponse::ok(r),
        Err(e) => ApiResponse::err(format!("helper 卸载任务异常终止: {e}")),
    })
}

/// Helper 服务变更共用外壳：**零提权前置停核 → 全程挂停核看门狗 → 跑 `body` → 协作式收停**。
///
/// # 为什么抽出来（而不是让完全卸载再抄一份）
///
/// 这段编排的每一行都有血债：前置停核的时机（[`uninstall_preflight_stop`]）、看门狗必须覆盖整段
/// 提权框窗口（见 [`helper_uninstall`] 文档「一次前置停核不够」）、收尾**绝不能 abort**
/// （三条后果见 [`join_watchdog_cooperatively`]）。完全卸载面对的是同一个提权框、同一个窗口，
/// 抄第二份必然漂移，而漂移的代价是孤儿 root 核 + 断网。故两条命令共用这一份。
///
/// `body` 收到停核腿的 [`StepOutcome`]，**自行决定政策**：
/// - [`helper_install`] 在进入外壳前拒绝已运行的 helper 核；外壳继续覆盖提权期间的竞态；
/// - [`helper_uninstall`] 忽略它（停不掉也继续卸）；
/// - `app_uninstall_all` 把它当作 fail-fast 的第一步（停不掉就一项都不删）。
///
/// 看门狗在 `body` 全程挂着 —— 对完全卸载来说这不只覆盖 helper 的提权框，还覆盖后面删配置、
/// 删应用本体那段时间。
pub(crate) async fn with_helper_service_mutation_core_guard<F, Fut, T>(
    state: &AppRuntime,
    body: F,
) -> T
where
    F: FnOnce(StepOutcome) -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let status = state.proxy().status();
    let preflight = decide_uninstall_preflight(status.running, status.started_via_helper);
    let proxy = state.proxy.clone();
    let stopped =
        uninstall_preflight_stop(status.running, status.started_via_helper, || async move {
            proxy.stop().await
        })
        .await;
    let stop_outcome = stop_core_outcome(preflight, stopped.error());

    // ── Helper 服务变更期间的持续停核看门狗（见 [`helper_uninstall`] 文档「一次前置停核不够」）。
    let done = Arc::new(AtomicBool::new(false));
    let mut watchdog = {
        let done = done.clone();
        let status_proxy = state.proxy.clone();
        let stop_proxy = state.proxy.clone();
        tauri::async_runtime::spawn(async move {
            helper_service_mutation_stop_watchdog(
                done,
                HELPER_MUTATION_RECHECK_INTERVAL,
                move || {
                    let s = status_proxy.status();
                    (s.running, s.started_via_helper)
                },
                move || {
                    let p = stop_proxy.clone();
                    async move { p.stop().await }
                },
            )
            .await
        })
    };

    let out = body(stop_outcome).await;

    // 协作式收停（**不能 abort**，理由见 [`join_watchdog_cooperatively`]）。
    if !join_watchdog_cooperatively(&done, &mut watchdog, WATCHDOG_JOIN_BUDGET).await {
        log::warn!(
            "Helper 服务变更收尾时看门狗仍在停核中（已超 {WATCHDOG_JOIN_BUDGET:?}）：不打断它，\
             让它把这一次停核走完后自退（`done` 已置位 → 不会再发起新的停核）"
        );
    }
    out
}

/// 协作式收停看门狗：置位 `done` → **等它自己退出**，最多等 `budget`。
///
/// 返回 `true` = 看门狗已自然退出；`false` = 超预算（调用方放手，**绝不 abort**）。
///
/// # 为什么这里必须是协作式取消，而不是 `JoinHandle::abort()`（本函数存在的全部理由）
///
/// 原本这里是 `done.store(true); watchdog.abort();`。`abort()` 让任务在**当前 await 点**被整体 drop
/// —— 若那一刻看门狗正落在 `proxy.stop().await` 里，被 drop 的就是**在飞的停核 future**。
/// 触发窗口窄（uninstall 刚返回 + 看门狗恰在停核中），但后果不是「停核慢一点」，是下面三条：
///
/// 1. **`LifecycleGate` 深度永久泄漏**（最重）。`ProxyRuntime::stop_inner` 的形态是
///    `gate.begin(); … 6 个 await …; finish_lifecycle(Stop)`，中间**没有任何 RAII guard**
///    （`runtime/proxy.rs` 里的 `ReconcileGuard`/`InflightGuard`/`TsExitRecoverGuard` 都不管这个门），
///    而 `LifecycleGate`（`crates/core-supervisor/src/lifecycle_gate.rs`）是裸引用计数：
///    `begin()` 加一、`end()` 减一。future 在中途被 drop ⇒ `end()` 永不执行 ⇒ depth 恒 >0 ⇒
///    此后**本进程内每一次** `switch_mode` / 去抖重启都只置 pending 不执行
///    （`runtime/proxy.rs` 自陈：「depth 长期 >0 ⇒ 此期间 switch_mode / 去抖重启只置 pending 不执行」）。
///    切节点、改模式从此静默失效，直到重启应用。
/// 2. **核变孤儿 + pid 记账错乱**。`kill_core` 先把 `Child` 句柄 `take()` 出锁再 `await`；中途 drop ⇒
///    句柄未 `wait()` 就没了（不收割），且 `self.pid` 不被清 —— 而那个字段正是 stale-core 清扫的
///    「受管 pid 排除表」，留个死 pid 等于给同号新进程发免死金牌（该风险 `kill_core` 里已有成文记录）。
/// 3. **系统代理留在死端口上**。`stop()` = `stop_inner().await` + `clear_system_proxy().await`；
///    在前半段被取消 ⇒ 第二段根本不跑 ⇒ OS 代理仍指向刚被杀的本地口 = 用户全网断连，需手动改回。
///    而这正是本命令那条停核腿要防的形态本身。
///
/// 即：`proxy.stop()` **不是 cancel-safe** 的，所以这条腿不能靠 abort 收场。
///
/// # 为什么超预算也不 abort（而不是「先等一会儿再强杀」）
///
/// 置位 `done` 之后，看门狗**结构上已不可能再发起新的停核**：循环体是
/// `while !done { sleep; if done { break } … stop().await }` —— 在飞的那次 stop 一返回就回到
/// `while !done` 并退出。所以「残任务」只有一个有界的尾巴，不需要强杀；而强杀恰好会命中上面三条。
/// `budget` 因此只是**命令还等不等**的上限（防 IPC 应答被一次挂死的停核无限期拖住），
/// 超时后把句柄一丢让它自己收尾即可。
///
/// # 那条尾巴晚落地时的**换代毒性**（由停核腿自己收口，不在本层）
///
/// 「有界」说的是它不会再发起**新的**停核，不代表它落地时还当权：超预算意味着在飞的那次
/// `proxy.stop()` 已经挂了 >`WATCHDOG_JOIN_BUDGET`（macOS `networksetup` exec 卡死 /
/// `spawn_blocking` 饥饿），而命令这时已经返回 —— 用户完全可能重装 helper 并起一个新核。残 stop
/// 随后醒来，其拆除段每一步（清 sidecar 注入态 / 抹 running 态 / 还原系统 DNS / 清系统代理）都会
/// 落在**新会话**上。
///
/// 这条不在本层堵：本层没有「谁当权」的判据（`proxy.stop()` 是个不透明 future）。收口在
/// `runtime::proxy::ProxyRuntime::stop_inner` 的换代守卫 —— 它在拆除段的**每个 await 之后**比对
/// 自己 bump 出来的世代，一旦发现被更新的 start/stop 接管就整段让位（`gate.begin()/end()` 仍配对，
/// 不会重演上面第 1 条的 depth 泄漏）。故本层「把句柄一丢」是安全的。
async fn join_watchdog_cooperatively<F>(done: &AtomicBool, handle: &mut F, budget: Duration) -> bool
where
    F: std::future::Future + Unpin,
{
    done.store(true, Ordering::SeqCst);
    tokio::time::timeout(budget, handle).await.is_ok()
}

/// Helper 服务变更期间的持续停核看门狗（`status` / `stop` 注入 → 可单测，不碰真代理）。
///
/// 每 `interval` 复查一次代理态，判据复用**同一个** [`decide_uninstall_preflight`]
/// （各写一份必然与前置腿漂移：那边只停「经 helper 起的核」，这边也只该停那种 ——
/// app 自己直起的核不归 daemon 管，卸载不会让它变孤儿，停它等于无故断用户的网）。
///
/// `done` 置位即退出。返回本次服务变更期间**真正发起过几次**停核（供单测断言，生产忽略）。
async fn helper_service_mutation_stop_watchdog<S, F, Fut>(
    done: Arc<AtomicBool>,
    interval: Duration,
    status: S,
    stop: F,
) -> usize
where
    S: Fn() -> (bool, bool),
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    let mut stops = 0usize;
    while !done.load(Ordering::SeqCst) {
        tokio::time::sleep(interval).await;
        if done.load(Ordering::SeqCst) {
            break; // 卸载已结束 → 这一拍不再插手（避免停掉用户卸载完之后新起的核）
        }
        let (running, started_via_helper) = status();
        if decide_uninstall_preflight(running, started_via_helper)
            != UninstallPreflight::StopCoreFirst
        {
            continue;
        }
        log::warn!(
            "Helper 服务变更期间检测到受管内核又被起了起来 → 立即再停一次 \
             （放着不管：daemon 替换后 UI 会保留已经失效的运行态）"
        );
        stops += 1;
        if let Err(e) = stop().await {
            log::warn!("Helper 服务变更期间停核失败（{e}）：需人工确认受管核与 daemon 状态");
        }
    }
    stops
}

#[cfg(test)]
mod tests;
