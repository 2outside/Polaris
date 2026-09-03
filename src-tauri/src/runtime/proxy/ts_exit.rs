//! R1/R2 Tailscale 出口域：STATUS relay 帧处理、出口无效直判【翻转对账】、出口恢复腿。
//!
//! 本模块并存**两套触发语义，互不化简**：`ts_exit_became_ready` 判 backendState 的**上升沿**
//! （挡住 relay 每帧退化成轮询），`reconcile_ts_exit_block` 判 `cur != prev` 的**跨态**（同态帧
//! 零动作）。二者回答的是两个物理问题——隧道通没通 / 出口设备还在不在。
//!
//! 恢复腿的单飞令牌只由 [`TsExitRecoverGuard`] 的 Drop 归还，并在归还时按**当下**核状态补跑被
//! Drop 窗口丢掉的 `blocked→none` 边沿（见该守卫文档）。

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use polaris_config_engine::user_config::app_config::UserConfig;
use polaris_config_engine::user_config::proxy_mode::ProxyMode;
use polaris_config_engine::user_config::server_config::{Protocol, ServerConfig};
use polaris_singbox_grpc::{Endpoint, ReconnectConfig, SingBoxApiClient};
use serde_json::Value;

use crate::runtime::tailscale_status::{
    decode_tailscale_status, derive_ts_exit_warning, is_definitive_logged_out, TsExitWarning,
    TsExitWarningInput,
};

use super::recovery::CRASH_MONITOR_POLL_MS;
use super::ProxyRuntime;

/// 纯谓词：选中 TS 出口的 backendState 是否**刚跃迁到 `Running`**（= 上游 触发表「TS 隧道就绪」）。
///
/// 判**上升沿**而非当前值：STATUS relay 每秒量级推帧，稳态 Running 帧若也算「就绪」，出口 IP 重探就成了
/// 每秒一次的轮询 —— 而本子系统（`commands::misc` 的 ipinfo）的设计前提正是**纯事件驱动、无轮询**。
///
/// 三类不触发，各有理由：
/// - `Running → Running`：稳态，出口没换（这条挡住的就是上面那个轮询退化）；
/// - `None → None` / 任意 → 非 `Running`：选中的不是 TS 节点 / 首帧未到 / 还在登录中，隧道未就绪；
/// - `None → Running`：**触发**。首帧就是 Running（核起时 TS 已登录且 key 未过期）同样意味着「此刻起
///   公网经 TS 出口走」，与 `NeedsLogin → Running` 对用户是同一件事。起核腿那次重探跑在核就绪那一刻，
///   彼时 TS 隧道未必已通 ⇒ 它探到的可能是让位期的直连出口，正需要本触发点纠正。
///
/// `expired` 帧已由 [`MeshRuntime::selected_exit_backend_state`](crate::runtime::mesh::MeshRuntime::selected_exit_backend_state)
/// 投影成 `"NeedsLogin"`，故此处无需再判过期。
pub(super) fn ts_exit_became_ready(before: Option<&str>, after: Option<&str>) -> bool {
    after == Some("Running") && before != Some("Running")
}

/// 纯谓词：relay 自留的末态表里各端点是否**全部**已就绪。
///
/// **空表 → false**，且这条是承重的：一帧都没收到正是最该重订阅的时候，若空表算「全就绪」
/// （`Iterator::all` 对空集恒真），停流自愈在最需要它的那一刻恰好不触发。
pub(super) fn ts_all_running(states: &BTreeMap<String, String>) -> bool {
    !states.is_empty() && states.values().all(|s| s == "Running")
}

/// STATUS 帧的**跃迁**日志：只有某端点 `backendState` 真的变了才打一行，并把新态写回 `last`。
///
/// 为什么不每帧都打：稳态下核按自身节奏推帧，全打就是刷屏（本仓刚为此治过 dns-race 与
/// switchMode 两处）。而跃迁行恰是排查「TS 到底有没有起来 / 停在哪一态」唯一需要的东西 ——
/// 2026-08-02 那次故障里，整条链一行日志都没有，只能靠核日志侧写。
///
/// 幽灵端点（tag 不在 `tag_to_id`）与 [`decode_tailscale_status`] 同口径丢弃：否则日志里会冒出
/// UI 根本不存在的节点，比不打更误导。
pub(super) fn log_ts_state_transitions(
    update: &polaris_singbox_grpc::daemon::TailscaleStatusUpdate,
    tag_to_id: &BTreeMap<String, String>,
    last: &mut BTreeMap<String, String>,
) {
    for ep in &update.endpoints {
        let Some(id) = tag_to_id.get(&ep.endpoint_tag) else {
            continue;
        };
        if last.get(id).map(String::as_str) == Some(ep.backend_state.as_str()) {
            continue;
        }
        let prev = last
            .insert(id.clone(), ep.backend_state.clone())
            .unwrap_or_else(|| "<无帧>".to_string());
        let ips = ep.self_.as_ref().map_or(0, |s| s.tailscale_i_ps.len());
        let peers: usize = ep.user_groups.iter().map(|g| g.peers.len()).sum();
        log::info!(
            "TS STATUS 跃迁：{}（{id}）{prev} → {}，tailnetIP {ips} 个，peers {peers}",
            ep.endpoint_tag,
            ep.backend_state
        );
    }
}

/// R2 出口恢复腿单飞标志的 Drop 复位（退场含 panic 必复位）。
///
/// 与 `ReconcileGuard` 同理由、不同形态：那条持 `&AtomicBool`（作用域内用），恢复腿跑在
/// `spawn` 出去的 `'static` 任务里，只能持 `Arc<ProxyRuntime>`。
/// 漏复位的后果是**静默的**：`ts_exit_recovering` 卡在 `true` ⇒ 本会话此后每一次真恢复都被单飞
/// 直接吞掉（只记 pending 而没人来消费），而日志上什么都看不到。
///
/// # 为什么 Drop 只清 `recovering`、`pending` 要走 `swap` + 补跑（Rust 多线程独有的丢边沿窗口）
///
/// 上游的 `finally` 里两个标志一起清是安全的：TS 单线程下 `while (pending && …)` 判定与 `finally`
/// 之间**没有插入点**。Rust 这里有 —— 循环判 `pending == false` 之后、Drop 执行之前，STATUS relay
/// 线程完全可以跑一次 `begin_ts_exit_recovery` 把 `pending` 置回 `true`；Drop 若无条件清位，这条
/// `blocked→none` 边沿就被**永久**抹掉（恢复腿是边沿触发，同态帧下一轮直接早退，不会自愈）。
/// 故 Drop 用 `swap(false)` 取走边沿并**自己补跑一轮**。
///
/// 补跑的两条前置条件缺一不可：
/// - `status().running`：核已停（或正在重启的停核窗口）时 `selected_ts_exit_block()` 恒 `None`
///   （STATUS 缓存已清），单看它会把「没有核」误读成「出口有效」⇒ 对着已停的核重申路由 + 重探；
/// - `selected_ts_exit_block().is_none()`：在飞期间 flap 回 blocked 就别对着已知无效的出口空跑。
///
/// 补跑走 [`ProxyRuntime::spawn_ts_exit_recovery`]，它**重新快照当前世代** —— 故停核→起核之间被记下的
/// pending 由**新会话**的腿消费，不会拿旧世代空转（这也是 `reset_ts_exit_block_state` 不再碰这两个
/// 原子标志的前提，见该方法文档）。
pub(super) struct TsExitRecoverGuard(pub(super) Arc<ProxyRuntime>);
impl Drop for TsExitRecoverGuard {
    fn drop(&mut self) {
        // 单飞位先释放、再取边沿：反过来会让补跑腿撞上自己还没放的位（`begin` 失败 → 边沿又回 pending，
        // 而此刻已经没有在飞腿会去消费它）。
        self.0.ts_exit_recovering.store(false, Ordering::SeqCst);
        if self.0.take_ts_exit_recover_rerun() {
            log::debug!("TS 出口恢复腿收尾时捡回一条被 Drop 窗口丢掉的 blocked→none 边沿 → 补跑");
            ProxyRuntime::spawn_ts_exit_recovery(&self.0);
        }
    }
}

impl ProxyRuntime {
    /// **A3 relay 每帧处理**（可测的纯接线段：解码 → 更缓存 → 逐端点 emit）。
    ///
    /// 拆成独立方法而非埋在 spawn 循环里：让「一帧全量端点快照 → 缓存更新 + `event:tailscaleStatus` 逐条发」
    /// 这条组合路径能被单测直接喂 mock 帧断言（§K7.1：测组合路径，别只测纯函数或只测 spawn）。
    ///
    /// **同时是 上游 触发表第四点「TS 隧道就绪」的接线处**（§10.1）：mesh 出口从 `NeedsLogin`/`Starting`
    /// 跃迁到 `Running` 的那一刻，公网流量才真正开始经 TS 出口走 —— 出口 IP 就此换掉，与起核/热切同性质。
    /// 判据取「**选中出口**的 backendState 由非 Running 变为 Running」的边沿（见 [`ts_exit_became_ready`]）。
    ///
    /// **同时是 R2「TS 出口无效直判翻转对账」的接线处**：缓存换完（`peers`/`loggedIn` 已是本帧最新）后
    /// 立即跑 [`reconcile_ts_exit_block`](Self::reconcile_ts_exit_block)。
    ///
    /// `self: &Arc<Self>`（原 `&self`）：R2 恢复腿要 spawn 一个持 runtime 的后台任务（reassert 在
    /// macOS 上可轮询到 ~18s，绝不能在 relay 的取帧循环里同步等）。
    ///
    /// `my_gen` = **本帧所属的核会话世代**（relay 起时的快照）。往下透给
    /// [`reconcile_ts_exit_block`](Self::reconcile_ts_exit_block) 做锁内判权 —— relay 的收帧世代复查
    /// 之后本方法还要跑一整段，那段里停核完全可能跑完 bump + 复位，见该方法文档。
    pub(super) fn apply_ts_status_frame(
        self: &Arc<Self>,
        update: &polaris_singbox_grpc::daemon::TailscaleStatusUpdate,
        tag_to_id: &BTreeMap<String, String>,
        my_gen: u64,
    ) {
        let events = decode_tailscale_status(update, tag_to_id);
        // 选中出口在**本帧之前**的 backendState —— 边沿判定的左值，必须在换缓存之前取。
        let selected_id = self.selected_server_id();
        let before = selected_id
            .as_deref()
            .and_then(|id| self.mesh.selected_exit_backend_state(id));
        // 缓存整体替换（每帧即全量）——供 `tailscale_get_status` 拉末帧。
        self.mesh.update_ts_status(events.clone());
        // 逐端点 emit（前端 `onTailscaleStatus` 逐条消费）。未接线 emitter（单测/setup 前）→ 静默跳过。
        if let Some(emitter) = self.error_emitter.get() {
            for ev in &events {
                emitter.emit_tailscale_status(ev);
            }
        }
        let after = selected_id
            .as_deref()
            .and_then(|id| self.mesh.selected_exit_backend_state(id));
        // 上游 触发点④「TS 隧道就绪」：**只在上升沿**触发，不是每帧（relay 每秒量级推帧，
        // 稳态 Running 帧若也触发就成了轮询——而本子系统的设计前提是纯事件驱动、无轮询）。
        if ts_exit_became_ready(before.as_deref(), after.as_deref()) {
            log::debug!("TS 隧道就绪（{before:?} → Running）→ 失效解锁缓存 + 重探出口 IP");
            // 新出口上线 ⇒ 解锁快照作废（与起核/热切/停核三点同语义）。
            self.invalidate_unlock_cache(true, false);
            // 新出口上线 ⇒ 状态栏出口 IP、两处旗面、伴测延迟全部作废，须重探（等选路收敛 4s）。
            self.schedule_exit_ip_refresh(true);
        }
        // R2：出口无效直判翻转对账（缓存已是本帧最新 → 据最新 peers/loggedIn 判 blocked 跨态）。
        // 与上面的「隧道就绪」上升沿正交：那条判 backendState（隧道通没通），这条判 exit_node 有没有
        // （通了也可能出口设备离线/未广告 ⇒ 公网出不去）。上游 同处也是两条并列（:7345-7346）。
        self.reconcile_ts_exit_block(my_gen);
    }

    // ══════════════ R2：TS 出口无效直判【翻转对账】 + 出口恢复腿 ══════════════
    //
    // 1:1 移植 上游 `reconcileTsExitBlock`（ProxyManager.ts:2596-2617）+ `recoverTsExit`（:2620-2646）
    // + `reapplyTsExitNode`（:2653-2690）。
    //
    // **拉侧已在（`commands/unlock.rs::compute_selected_exit_blocked` → `unlock_gate_reason` 的
    // `exit_blocked`），本段补的是推侧**：拉侧只在用户点检测那一刻求值，出口从无效恢复成有效后
    // 没有任何东西会来重检 —— 拉侧越准，推侧缺失就越显形（用户看到的是「出口无效」一直挂着）。

    /// `TsExitWarning` → 前端契约 `ProxyExitBlock` 值域（`ui/src/contracts/types/runtime.ts`）。
    ///
    /// 纯投影，与 上游 `selectedTsExitBlock` 的三条 map 逐条对齐。**值域单一真值**：三个字符串只在这里
    /// 出现一次，别处（emitter / 日志）一律传本函数的产物，杜绝「后端发 `ts-exit-not-advertised`、
    /// 前端判 `ts-not-advertised`」这类拼串漂移。
    #[must_use]
    pub(super) fn ts_exit_block_reason(w: TsExitWarning) -> Option<&'static str> {
        match w {
            TsExitWarning::None => None,
            TsExitWarning::NeedsAuth => Some("ts-needs-auth"),
            TsExitWarning::NoExitDevice => Some("ts-no-exit-device"),
            TsExitWarning::ExitDeviceOffline => Some("ts-exit-device-offline"),
            TsExitWarning::ExitDeviceNotAdvertised => Some("ts-exit-not-advertised"),
        }
    }

    /// 选中 TS 出口当前是否被直判无效（`None` = 有效 / 不适用）。上游 `selectedTsExitBlock`。
    ///
    /// 输入三源：当前配置（选中节点 + `proxyMode`）、STATUS 末帧（`loggedIn` / `peers`）、核 running
    /// （= STATUS 流是否 live；新鲜度守卫已内建在 [`derive_ts_exit_warning`]，流断时不据陈旧 peers 报离线）。
    ///
    /// 与 `commands/unlock.rs::compute_selected_exit_blocked`（拉侧）**同谓词不同调用时机**：谓词本体
    /// [`derive_ts_exit_warning`] 是单一真值（两侧都调它），此处多出的只是「从 runtime 自身取三源」这段
    /// 装配 —— 拉侧从 `State<AppRuntime>` 取、推侧从 `self` 取，无法共用同一个签名。
    ///
    /// **配置源刻意取 `ConfigManager` 的落盘态（此处经 `with_current` 投影）而非 `current_config`
    /// （运行核那份）**，这一点偏离
    /// 上游（它读 `this.currentConfig`）：Polaris 的拉侧读的就是落盘态，两侧若各读一份，会出现
    /// 「推侧广播了出口无效终态、拉侧的 gate 却判有效（或反过来）」的自相矛盾 —— 用户看到的是角标与
    /// 检测结果打架。宁可与**同一子系统的另一侧**对齐，也不为形式上贴近上游而制造两个真相源。
    pub(super) fn selected_ts_exit_block(&self) -> Option<&'static str> {
        // 廉价前置（**只跳过工作、不改结论**）：STATUS 缓存里一个在册端点都没有（无 TS 节点 / 核未跑 /
        // 首帧未到）⇒ `logged_in` 恒 false ⇒ [`derive_ts_exit_warning`] 必在第一道守卫返 None。
        // 挡在这里是因为下面那次配置读**本可能**深拷贝整份配置（含 200 节点级 servers 数组），
        // 而本方法由 STATUS relay 每帧（~1/s）驱动 —— 正是 `selected_server_id` 文档点名要避免的那类
        // 常驻开销。等价性由 `exit_block_is_none_when_status_cache_empty` 钉住。
        if !self.mesh.has_ts_status() {
            return None;
        }
        // **零深拷贝 + 只投影三个字段**：走 [`ConfigManager::with_current`]（持读锁投影，不产 owned
        // `Value`）而非 `current()`（恒 clone 整份）；闭包内也不 `from_value::<UserConfig>(整份)` ——
        // 那会把 200 节点级的 `servers` 全量建成 typed 结构（每个 `ServerConfig` 又带若干
        // `Option<...Settings>` / `Vec<String>`），而谓词只要 `selectedServerId` + **被选中的那一个**
        // server + `proxyMode` 三样。两半浪费（整份 clone、整份反序列化）在此一并消掉。
        //
        // 逐字段投影与整份反序列化的**结论等价**（`selected_ts_exit_block_projection_matches_typed_parse`
        // 用同一份配置双路对拍钉住）：三个键的 serde 表示都是平凡的（`Option<String>` / 数组 /
        // `rename_all = "lowercase"` 的枚举），且谓词对其余字段一概不看。
        // 唯一的行为差异在退化输入上——某个**无关**字段坏掉时，投影不再连带把整个判定短路成 None。
        // 方向是 fail-safe 的（坏字段不再静默吞掉出口告警），且配置在 `ConfigStore::load` 已过校验。
        //
        // ⚠️ 闭包内**只做纯投影**：`ConfigManager` 的读锁正持着，回调进 `self.mesh` / `self.status()`
        // 之类的子系统是禁忌（见 `with_current` 文档）。故 `ts_status_event` / `status()` 一律留到
        // 闭包**外**再取。
        let (sel_id, selected, proxy_mode_direct) = self
            .config
            .with_current(|raw| {
                let sel_id = raw.get("selectedServerId")?.as_str()?.to_string();
                let selected: Option<ServerConfig> = raw
                    .get("servers")?
                    .as_array()?
                    .iter()
                    .find(|s| s.get("id").and_then(Value::as_str) == Some(sel_id.as_str()))
                    .and_then(|s| serde_json::from_value(s.clone()).ok());
                let proxy_mode_direct = raw.get("proxyMode").and_then(Value::as_str)
                    == Some(ProxyMode::Direct.as_str());
                Some((sel_id, selected, proxy_mode_direct))
            })
            .ok()
            .flatten()?;
        let event = self.mesh.ts_status_event(&sel_id);
        let (logged_in, peers, definitive_logged_out) =
            event.as_ref().map_or((false, &[][..], false), |e| {
                (e.logged_in, e.peers.as_slice(), is_definitive_logged_out(e))
            });
        Self::ts_exit_block_reason(derive_ts_exit_warning(&TsExitWarningInput {
            selected: selected.as_ref(),
            logged_in,
            proxy_mode_direct,
            proxy_running: self.status().running,
            peers,
            definitive_logged_out,
        }))
    }

    /// **R2 翻转对账**（每帧 STATUS 末尾跑）：仅在 `cur != prev` 的**跨态**动作，同态帧一律早退。
    ///
    /// 三分支（上游 `reconcileTsExitBlock` 1:1）：
    /// - `none → blocked`（含 `blocked → blocked'` 原因变更）：出口 IP **不探测直落终态**
    ///   （[`mark_exit_blocked`](Self::mark_exit_blocked)）—— 探测在这种形态下必然打空转，20s 重试预算
    ///   耗尽后仍是 null，用户看到「一直在检测」而不是「出口无效」；同时令解锁快照失效并**带
    ///   `exit_blocked=true`**（渲染端据此复位 idle 而非留着陈旧绿点，R-gate 拦重跑）。
    /// - `blocked → none`：起**出口恢复腿**（R1 热重设 exit_node → reassert System 路由 → 重探），
    ///   并令解锁快照失效（有效出口恢复 ⇒ 自动重检，与重探同节奏）。
    /// - 同态：零动作（relay 每秒量级推帧，level 触发就是每秒一次重探 + 每秒一次解锁失效）。
    ///
    /// **缓存先于动作更新**：先写 `last_ts_exit_block` 再动作，恢复腿里的 `selected_ts_exit_block()`
    /// 复查读到的才是本次已提交的态。
    ///
    /// # `my_gen`：帧所属的核会话世代（**锁内**比对）
    ///
    /// relay 在收帧后已复查过一次世代（`spawn_tailscale_status_relay` 的取帧腿），但那之后还要跑完整个
    /// `apply_ts_status_frame`。停核腿是「`bump_generation()` → … → `reset_ts_exit_block_state()`」，
    /// 若本函数尾部的缓存写入晚于那次复位，`last_ts_exit_block` 就带着 `Some(reason)` 漏进**新会话**
    /// ⇒ 重连后同因 blocked 的首帧被同态早退吞掉，终态**永远落不下去**（而 `reconcile` 是边沿触发，
    /// 没有轮询会来纠正）。
    ///
    /// 判据放在 `last_ts_exit_block` 的锁内、而不是函数入口：`reset_ts_exit_block_state` 持的是**同一把**
    /// 锁，故「判世代 + 写缓存」与「bump + 复位」不会交叉；放锁外就还是 check-then-act。
    pub(super) fn reconcile_ts_exit_block(self: &Arc<Self>, my_gen: u64) {
        let cur = self.selected_ts_exit_block();
        let prev = match self.last_ts_exit_block.lock() {
            Ok(mut g) => {
                if self.gate.generation() != my_gen {
                    return; // 本帧所属的核会话已被停核/换核/新 start 接管 → 不得写进新会话的缓存
                }
                if *g == cur {
                    return; // 同态 → 零动作（挡住 level 触发退化成每秒轮询）
                }
                std::mem::replace(&mut *g, cur)
            }
            // 锁中毒 → 放弃本次对账（best-effort：出口对账绝不该反过来打断 STATUS 帧处理）。
            Err(_) => return,
        };
        let running = self.status().running;
        if let Some(reason) = cur {
            log::info!("TS 出口直判无效（{prev:?} → {reason}）→ 出口 IP 落终态 + 解锁快照失效");
            // 跨态即令解锁检测失效（G-flip）。`exit_blocked=true` 是本参数**唯一**的生产真值来源：
            // 其余三个触发点（起核/停核/热切）传的都是 false。
            self.invalidate_unlock_cache(running, true);
            // 出口 IP 腿：无探测直落「出口无效」终态（与 schedule_exit_ip_refresh 互斥的另一条出口）。
            self.mark_exit_blocked(reason);
        } else {
            log::info!("TS 出口恢复有效（{prev:?} → none）→ 热重设 exit_node + 重申路由 + 重探");
            self.invalidate_unlock_cache(running, false);
            // 出口 IP 腿：恢复腿内部按「reapply → reassert → refresh」顺序收尾重探（顺序不可换，
            // 见 ts_exit_recover_once）。
            self.spawn_ts_exit_recovery();
        }
    }

    /// **R2 恢复腿的单飞抢占**（同步、可直测）：抢到 → `true`；已在飞 → 记 pending 并 `false`。
    ///
    /// 抽成独立同步方法而不是内联进 [`spawn_ts_exit_recovery`](Self::spawn_ts_exit_recovery)：单飞 + 补跑是这条腿唯一的状态机，
    /// 而 spawn 出去的异步体在单测里无法确定性观测 —— 门要能被看见（§K7）。
    pub(super) fn begin_ts_exit_recovery(&self) -> bool {
        if self.ts_exit_recovering.swap(true, Ordering::SeqCst) {
            self.ts_exit_recover_pending.store(true, Ordering::SeqCst);
            return false;
        }
        true
    }

    /// **R2 恢复腿收尾时的「丢边沿补救」判定**（同步、可直测；[`TsExitRecoverGuard`] 的 Drop 唯一消费方）。
    ///
    /// 取走 pending 边沿并回答「该不该再起一轮」。抽成独立同步方法而非内联进 Drop：Drop 里那一步会
    /// `spawn` 出后台任务，单测无法确定性观测 —— 门要能被看见（§K7）。
    ///
    /// 三条判据缺一不可：
    /// - `swap(false)` 取到边沿：`load` 会让边沿留在位上被下一次 Drop 重复消费；
    /// - `status().running`：核已停（或 restart 的停核窗口）时 `selected_ts_exit_block()` 恒 `None`
    ///   （STATUS 缓存已清），只看它会把「**没有核**」误读成「出口有效」⇒ 对着已停的核重申路由 + 重探；
    /// - `selected_ts_exit_block().is_none()`：在飞期间 flap 回 blocked 就别对着已知无效的出口空跑。
    pub(super) fn take_ts_exit_recover_rerun(&self) -> bool {
        self.ts_exit_recover_pending.swap(false, Ordering::SeqCst)
            && self.status().running
            && self.selected_ts_exit_block().is_none()
    }

    /// **R2 恢复腿**（`blocked → none` 触发，串行单飞 + 补跑门）。fire-and-forget，绝不抛。
    ///
    /// `tauri::async_runtime::spawn` 而非 `tokio::spawn`：本方法的调用链可自**同步** Tauri command
    /// 路径进入（`apply_ts_status_frame` 的测试腿与将来的同步驱动源），裸 `tokio::spawn` 在无 runtime
    /// 上下文时当场 panic，而 panic 在 Tauri IPC 回调里无处可 catch ⇒ `abort()`（2026-07-21 真机
    /// SIGABRT 血证，见 `runtime::unlock::schedule_self_run`）。
    /// **世代守卫**：spawn 那一刻快照 `gate.generation()`，整条腿（含补跑轮）都在这个世代名下跑。
    /// 这条 `'static` 任务能活过停核 / 换核 / 新 start，而它的三步全是**对着当前核**的动作 ——
    /// 没有守卫时旧腿的三条坏后果（见 [`ts_exit_recover_once`](Self::ts_exit_recover_once) 文档）
    /// 每条都能独立发生。
    fn spawn_ts_exit_recovery(self: &Arc<Self>) {
        if !self.begin_ts_exit_recovery() {
            return; // 在飞 → 已记 pending，由在飞那轮收尾补跑
        }
        let me = Arc::clone(self);
        let my_gen = self.gate.generation();
        tauri::async_runtime::spawn(async move {
            // 单飞标志的复位走 Drop 守卫（同 `ReconcileGuard` 的理由）：任一步 panic 也必复位。
            // 漏复位 = 本会话此后**所有**真恢复都被单飞永久吞掉，且没有任何可见症状。
            let _guard = TsExitRecoverGuard(Arc::clone(&me));
            loop {
                me.ts_exit_recover_pending.store(false, Ordering::SeqCst);
                me.ts_exit_recover_once(my_gen).await;
                // 世代守卫：本轮跑完发现已被停核/换核/新 start 接管 → 整腿退场，别拿旧世代再跑补跑轮
                // （补跑轮的三步同样是对着「当时那个核」的动作）。留下的 pending 由 Drop 按当前世代裁定。
                if me.gate.generation() != my_gen {
                    log::debug!(
                        "TS 出口恢复腿世代变（{my_gen}→{}）→ 退场",
                        me.gate.generation()
                    );
                    break;
                }
                // 补跑门：在飞期间又发生过 flip **且**当下仍是有效出口 → 再跑一轮。
                // 少了「仍为 none」这条，flap 到 blocked 时会对着一个已知无效的出口空跑恢复。
                if !(me.ts_exit_recover_pending.load(Ordering::SeqCst)
                    && me.selected_ts_exit_block().is_none())
                {
                    break;
                }
            }
        });
    }

    /// **R2 恢复腿单轮**（上游 `recoverTsExit` 的循环体）。三步**顺序不可换**：
    ///
    /// 1. [`reapply_ts_exit_node`](Self::reapply_ts_exit_node)：re-advertise 后运行中的 sing-box **不随
    ///    netmap 重解析 exit_node**（上游 watchState 缺陷）⇒ 不热重设的话，出口在 tailnet 侧已恢复、
    ///    核内部却还指着「已失效」的解析结果，后面两步全白做；
    /// 2. `exit_route_reassert`：补 macOS `resolveIface` 18s 轮询超时那次没装成的 System 出口路由
    ///    （crate 侧只在「从未装成 / iface 已消失」两种真缺口下动手，不 churn 已存路由）；
    /// 3. `schedule_exit_ip_refresh`：**最后**才重探——前两步没做完就探，探到的还是恢复前的出口。
    ///
    /// 全程 best-effort、绝不抛：恢复属增益路径，任一步失败都不该污染 STATUS 帧处理或阻断后续轮。
    ///
    /// # 世代守卫：**每步之前**都要比对，不是只在入口判一次
    ///
    /// 本腿跑在 `spawn` 出去的 `'static` 任务里，可以活过停核 / 换核 / 新 start，而三步全是「对着**当前**
    /// 核」的动作。三条坏后果各自独立（缺任一道守卫就漏一条）：
    ///
    /// 1. `exit_route_reassert` 持 `mesh.exit_route` 的 tokio Mutex，macOS 下 `find_tailnet_iface` 最长
    ///    轮询 ~18s（`mesh.rs` `MACOS_RESOLVE_ATTEMPTS × MACOS_RESOLVE_DELAY`）—— 停核腿的
    ///    `exit_route_clear` 与新 start 每轮的 `exit_route_snapshot_baseline` 都排在它后面 ⇒
    ///    **点停止最长卡 18s**。守卫挡住的是「已被接管的旧腿还去**开启**一轮新的 18s 轮询」；
    /// 2. 快速 stop→start 后的 stale 腿会看到 `installed=None`（停核已清）+ 新核 utun 已现，于是按
    ///    **旧会话**的 `current_config`（停核**不**清它）重装出口路由，与新会话的 reconcile 争路；
    /// 3. 收尾的 `schedule_exit_ip_refresh(true)` 是「代理在跑」语义：停核后落地会去重探一个已死的核，
    ///    并可能**后发覆盖** `stop_inner` 那次 `schedule_exit_ip_refresh(false)`。
    ///
    /// 三步之间隔着 gRPC 往返与最长 18s 的路由手术，世代随时可能变 —— 只在入口判一次等于没判。
    pub(super) async fn ts_exit_recover_once(&self, my_gen: u64) {
        if self.gate.generation() != my_gen {
            return;
        }
        let reapplied = self.reapply_ts_exit_node().await;
        log::debug!(
            "TS 出口恢复腿：热重设 exit_node {}",
            if reapplied { "已下发" } else { "跳过" }
        );
        // ② 之前：别拿旧会话的 current_config 去给新会话（或已停的核）装出口路由，也别再开一轮 18s 轮询。
        if self.gate.generation() != my_gen {
            return;
        }
        if let Some(cfg) = self
            .current_config
            .read()
            .ok()
            .and_then(|g| g.clone())
            .and_then(|v| serde_json::from_value::<UserConfig>(v).ok())
        {
            let ipv6 = cfg.enable_ipv6.unwrap_or(false);
            self.mesh.exit_route_reassert(&cfg, ipv6).await;
        }
        // ③ 之前：`running=true` 语义的重探不得在核已停/已换之后落地（会覆盖停核腿的 refresh(false)）。
        if self.gate.generation() != my_gen {
            return;
        }
        self.schedule_exit_ip_refresh(true);
    }

    /// **R1 热重设选中 TS 出口的 `exit_node`**（gRPC `SetTailscaleExitNode` → `EditPrefs{ExitNodeID}`，
    /// 幂等，免整核重启）。上游 `reapplyTsExitNode`。返回是否真的下发了一次。
    ///
    /// 守卫链（任一不满足 → 跳过返 `false`，**绝不猜**）：核 running → 选中节点存在且协议为 tailscale →
    /// 配了非空 `exitNode` → STATUS 末帧 `peers` 里能按 `ip` / `hostName` 双口径匹配到该 peer →
    /// 该 peer 带 `stableID`（旧核不发 → None）。切走出口 / 未配出口的场景被守卫天然跳过（此时恢复腿
    /// 仍会走 reassert + 重探，不受影响）。
    ///
    /// `endpoint_tag` 取**运行核快照**的 `id_to_tag`（`build_id_to_tag_map` 产物，含撞名去重后缀）而非
    /// 裸 `server.name`：核发的 endpointTag 恒是它启动时的 tag，撞名节点用裸 name 会打到错的端点上。
    /// 快照缺失（核未起）→ 退回 `server.name`（与 上游 一致），此时守卫链的 running 条件通常已拦下。
    ///
    /// 同值 `EditPrefs` 在核侧是 no-op ⇒ 对「本就已生效」零副作用，故不做「值没变就不发」的短路
    /// （那需要缓存上次下发值，多一个会与核真态脱节的状态）。
    pub(super) async fn reapply_ts_exit_node(&self) -> bool {
        let status = self.status();
        if !status.running || status.clash_api_port == 0 {
            return false;
        }
        let Some(cfg) = self
            .current_config
            .read()
            .ok()
            .and_then(|g| g.clone())
            .and_then(|v| serde_json::from_value::<UserConfig>(v).ok())
        else {
            return false;
        };
        let Some(sel_id) = cfg.selected_server_id.as_deref() else {
            return false;
        };
        let Some(server) = cfg.servers.iter().find(|s| s.id == sel_id) else {
            return false;
        };
        if server.protocol != Protocol::Tailscale {
            return false;
        }
        let exit_node = server
            .tailscale_settings
            .as_ref()
            .and_then(|t| t.exit_node.as_deref())
            .map(str::trim)
            .filter(|e| !e.is_empty());
        let Some(exit_node) = exit_node else {
            return false; // 未配出口（切走 / 仅内网）→ 无可重设
        };
        let Some(event) = self.mesh.ts_status_event(sel_id) else {
            return false;
        };
        let Some(stable_id) = event
            .peers
            .iter()
            .find(|p| p.ip == exit_node || p.host_name == exit_node)
            .and_then(|p| p.stable_id.clone())
        else {
            log::debug!("热重设 exit_node 跳过：peers 未解到 stableID（exitNode={exit_node}）");
            return false;
        };
        let endpoint_tag = self
            .switch_snapshot
            .read()
            .ok()
            .and_then(|g| g.as_ref().and_then(|s| s.id_to_tag.get(sel_id).cloned()))
            .unwrap_or_else(|| server.name.clone());
        let secret = self.clash_api_secret();
        let client = match SingBoxApiClient::connect(
            Endpoint::new("127.0.0.1", status.clash_api_port),
            secret,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                log::warn!("热重设 exit_node：连管理 API 失败 {e}");
                return false;
            }
        };
        match client
            .set_tailscale_exit_node(endpoint_tag, stable_id)
            .await
        {
            Ok(()) => {
                log::info!("已热重设 TS exit_node → {exit_node}（免重启核）");
                true
            }
            Err(e) => {
                log::warn!("热重设 exit_node 失败：{e}");
                false
            }
        }
    }

    /// **R2 会话起点复位**（上游 `lastTsExitBlock = null`，`ProxyManager.ts:695`）：停核 / 崩溃拆除时调。
    ///
    /// 不复位的后果：停核时缓存停在 `Some(reason)`，重连同一节点后**首帧**若判有效（`None`）会被当成
    /// 一次 `blocked→none` 跨态而白跑一轮恢复腿；更糟的是停在 `None` 时，重连后仍无效的出口不会再触发
    /// `none→blocked` ⇒ 终态永远落不下去。
    ///
    /// # 🔴 为什么**不**顺手清 `ts_exit_recovering` / `ts_exit_recover_pending`（曾经清过，是移植新增偏离）
    ///
    /// 那两个原子是**在飞任务的所有权令牌**，而本方法看不见在飞任务。清了会出两种坏账：
    /// - 新会话可以在旧腿还在飞时再抢一次令牌 ⇒ 两条恢复腿并发跑同一套 route 手术；
    /// - 更糟：旧腿退出时 [`TsExitRecoverGuard`] 的 Drop 会把**新会话**刚置的 recovering/pending 清掉
    ///   ⇒ 单飞被打穿（第三条腿又能进），且新会话记下的边沿被静默抹掉。
    ///
    /// 令牌只由持有者的 Drop 归还，而 Drop 会按**当下**的核状态决定要不要补跑（见该守卫文档）——
    /// 「跨会话残留 `recovering=true`」在那之后不可达：Drop 在 panic 展开时同样执行，没有绕过它的退出路径。
    /// 上游侧本就只清 `lastTsExitBlock`，此处回归对齐。
    pub(super) fn reset_ts_exit_block_state(&self) {
        if let Ok(mut g) = self.last_ts_exit_block.lock() {
            *g = None;
        }
    }

    /// 真机上出现过**首帧之后再没有第二帧**：核在 22:38:43 起、tsnet 在 22:38:46 拿到 tailnet IPv4
    /// 并正常带流量（核日志 186 条成功 outbound），而 Polaris 的末帧缓存到 22:39:09 仍是首帧那个
    /// `NoState` —— 表现为「TS 管理后台显示 Connected，节点卡片却说尚未登录就绪、测速被挡、出口卡
    /// 显示 `—`」。上下游都读过：核侧 `SubscribeTailscaleStatus` 是订阅即先发一帧快照、其后靠
    /// `WatchNotifications` 推；本侧 `ReconnectingStream` 的状态存在结构体里、`timeout` 丢弃 future
    /// 是 cancel-safe 的。**为什么通知没再来，静态读不出来。**
    ///
    /// 故不赌成因，按「重订阅必得当前真值」这个上游结构事实兜底：**长时间无帧且末帧不是全 Running**
    /// → 丢掉旧流重订一条。核侧 `sendStatus()` 在挂 watcher 之前先跑，一次重订阅必然拿到此刻的真状态。
    /// 稳态（全 Running）**不重订**——那时无帧是正常的（没有变化就没有通知），churn 无意义。
    /// 阈值指数退避（15s → 30s → … → 5min 封顶）：真的卡在 `NeedsLogin` 时不至于每 15 秒空转一次。
    pub(super) fn spawn_tailscale_status_relay(
        self: &Arc<Self>,
        my_gen: u64,
        api_port: u16,
        tag_to_id: Arc<BTreeMap<String, String>>,
    ) {
        /// 无帧多久后开始怀疑流停了（首个阈值，其后每次重订阅翻倍）。
        const RESUBSCRIBE_IDLE_MS: u64 = 15_000;
        /// 退避封顶：卡在 `NeedsLogin` 这类稳定非就绪态时，最慢 5 分钟才重订一次。
        const RESUBSCRIBE_IDLE_MAX_MS: u64 = 300_000;

        let me = Arc::clone(self);
        tokio::spawn(async move {
            let secret = me.clash_api_secret();
            let client =
                match SingBoxApiClient::connect(Endpoint::new("127.0.0.1", api_port), secret).await
                {
                    Ok(c) => c,
                    Err(e) => {
                        log::warn!("TS STATUS relay 连接管理 API 失败（apiPort={api_port}）: {e}");
                        return;
                    }
                };
            let mut stream = client.subscribe_tailscale_status(ReconnectConfig::default());
            // 世代兜底轮询间隔：`ReconnectingStream` 永不自结束（断开即重连），故必须用 `timeout` 包住取帧
            // 给世代守卫一个「无帧也能醒」的兜底——否则核停了但一直没帧时 relay 会泄漏、对死端口无限重连。
            let tick = Duration::from_millis(CRASH_MONITOR_POLL_MS);
            log::info!("TS STATUS relay 起（世代 {my_gen}，apiPort={api_port}）");
            // 本 relay 自留的「上一帧各端点 backendState」——只为**跃迁才打日志**（稳态每秒一帧全打
            // 就是刷屏），以及判「是不是全就绪」以决定要不要重订阅。不作真值源（真值在 mesh 缓存）。
            let mut last_states: BTreeMap<String, String> = BTreeMap::new();
            let mut frames: u64 = 0;
            let mut resubscribes: u32 = 0;
            let mut idle_ms: u64 = 0;
            let mut idle_threshold_ms: u64 = RESUBSCRIBE_IDLE_MS;
            loop {
                // 世代守卫：核被停/接管（stop/restart 先 bump 世代）→ 退场，drop stream 停订阅+重连
                // （防对死端口无限重连、防旧核 relay 污染新核）。取帧前后各查一次。
                if me.gate.generation() != my_gen {
                    log::info!(
                        "TS STATUS relay 退场（世代 {my_gen}→{}）：本代共收 {frames} 帧、重订阅 {resubscribes} 次，末态 {last_states:?}",
                        me.gate.generation()
                    );
                    return;
                }
                match tokio::time::timeout(tick, stream.recv()).await {
                    Ok(Some(update)) => {
                        // 收帧后复查世代：接管方可能刚拆核，别把旧核末帧写进新核缓存。
                        if me.gate.generation() != my_gen {
                            return;
                        }
                        idle_ms = 0;
                        frames += 1;
                        log_ts_state_transitions(&update, &tag_to_id, &mut last_states);
                        me.apply_ts_status_frame(&update, &tag_to_id, my_gen);
                        // A4 触发点①：每帧后对账登录期出口让位（读该帧刚写入缓存的选中出口 backendState）。
                        // 收帧世代已复查（上方），reconcile 内部 hotSwitch 走 management_api（核未起即 not_ready→false，
                        // 不改 flag），世代进一步接管由下一轮循环顶守卫退场。
                        me.reconcile_login_fallback().await;
                    }
                    // ReconnectingStream 正常永不返 None（断开即重连）；真返 None = 内部终止 → 退场。
                    Ok(None) => return,
                    // tick 内无帧：稳态下正常（核按自身节奏推）。但**未就绪 + 长时间无帧**是本方法
                    // 文档记的那个真机故障形态 → 重订阅取当前真值（见方法文档）。
                    Err(_) => {
                        idle_ms = idle_ms.saturating_add(CRASH_MONITOR_POLL_MS);
                        if idle_ms >= idle_threshold_ms && !ts_all_running(&last_states) {
                            resubscribes += 1;
                            log::info!(
                                "TS STATUS 流已 {}s 无帧且末态非全就绪（{last_states:?}）→ 重订阅取当前真值（第 {resubscribes} 次）",
                                idle_ms / 1000
                            );
                            stream = client.subscribe_tailscale_status(ReconnectConfig::default());
                            idle_ms = 0;
                            idle_threshold_ms =
                                (idle_threshold_ms * 2).min(RESUBSCRIBE_IDLE_MAX_MS);
                        }
                    }
                }
            }
        });
    }
}
