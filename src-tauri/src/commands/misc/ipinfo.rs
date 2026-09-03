use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use serde_json::{json, Value};
use tauri::{AppHandle, Manager, State};

use crate::response::ApiResponse;
use crate::runtime::http::{app_user_agent, HttpRuntime, SystemDnsLookup};
use crate::runtime::proxy::ProxyStatus;
use crate::runtime::AppRuntime;
use polaris_config_engine::user_config::dns_constants::is_sentinel_selection;
#[cfg(test)]
use polaris_config_engine::user_config::dns_constants::{BLOCK_SERVER_ID, DIRECT_SERVER_ID};
use polaris_net_stack::safe_redirect::{safe_redirect_fetch, HttpClient, SafeRedirectFetchOptions};

const IPINFO_TIMEOUT_MS: u64 = 8_000;
/// trace 响应体上限（cdn-cgi/trace 仅数百字节，64 KiB 足够且防滥用）。
const IPINFO_MAX_BODY: usize = 64 * 1024;

// ── 探测重试预算（1:1 移植 上游 `IpInfoService.ts:15-47`）──
//
// 为什么必须有：正常刷新由事件驱动，一次失败会先落一帧
// `{direct:null, proxy:null, error}` 落地 —— 状态栏 IP 与旗面双双空、`proxy_probed=false`
// 连伴测都不 fire ⇒ 延迟格也空。不可达终态虽会接上低频自愈复查，但首轮至少等待
// [`IPINFO_UNREACHABLE_RETRY_INITIAL_MS`]；单腿内的定额重试仍是吸收起核 +4s 时 DNS 接管 / FakeIP
// 瞬态抖动、避免用户先看到失败的第一道门。
//
// ⚠️ 重试**不是**轮询：它收在单次探测腿内、有硬预算封顶，腿结束即止。§12.4 禁的是周期轮询。

/// 单条探测腿的总预算（ms）—— 上游 `TOTAL_PROBE_BUDGET_MS`。
///
/// 上游 在 JS 里靠「循环内逐次查 deadline + 一个赛跑的 `setTimeout`」两道保险，因为 JS 的 promise
/// **不可取消**；Rust 的 [`tokio::time::timeout`] 直接取消整个 future，故这里只留外层一道 ——
/// 行为等价（到点即返回失败），少一半代码。
const IPINFO_PROBE_BUDGET_MS: u64 = 10_000;

/// direct 腿重试 —— 上游 `DIRECT_MAX_PROBE_ATTEMPTS` / `DIRECT_RETRY_DELAY_MS`。
const IPINFO_DIRECT_ATTEMPTS: u32 = 3;
const IPINFO_DIRECT_RETRY_MS: u64 = 1_000;

/// proxy 腿常规重试（停核 / 手点检测 / 启动首探）—— 上游 `MAX_PROBE_ATTEMPTS` / `RETRY_DELAY_MS`。
const IPINFO_PROXY_ATTEMPTS: u32 = 2;
const IPINFO_PROXY_RETRY_MS: u64 = 1_000;

/// proxy 腿**接通后**重试（起核 / 热切，即走选路收敛延迟的那些腿）——
/// 上游 `POST_CONNECT_MAX_PROBE_ATTEMPTS` / `POST_CONNECT_RETRY_DELAY_MS`。
///
/// 间隔比常规腿宽 4 倍：这条腿跑在隧道热身窗口里，失败是「还没好」而非「坏了」，密集重试只是空转。
const IPINFO_PROXY_POST_CONNECT_ATTEMPTS: u32 = 4;
const IPINFO_PROXY_POST_CONNECT_RETRY_MS: u64 = 4_000;
/// 快照缓存 TTL（ms）：非 force 时 TTL 内直接回缓存，不重复 HTTP（避免每次轮询打网）。
const IPINFO_TTL_MS: u128 = 15_000;

/// 事件驱动重探的**选路收敛等待**（对齐 上游 `whenSelectorSettled(4000)`）：核就绪 / 热切完成那一刻
/// selector 的 PUT 才刚落，出口隧道未必已能跑流量 —— 立刻探会打到旧出口或直接失败。停核腿无此问题
/// （出口已确定性消失），故用 0。
pub const IPINFO_SETTLE_DELAY_MS: u64 = 4_000;

/// 出口明确不可达后的按需自愈退避。只在失败终态存续期间运行；任意更新事件都会通过排程线取消旧腿。
const IPINFO_UNREACHABLE_RETRY_INITIAL_MS: u64 = 15_000;
const IPINFO_UNREACHABLE_RETRY_MAX_MS: u64 = 60_000;

/// 最近一次出口 IP 快照缓存（`peek` 零探测读取；TTL 内非 force 复用）。
static IPINFO_CACHE: OnceLock<Mutex<Option<Value>>> = OnceLock::new();

/// 出口 IP 探测的**世代线**：每条会落地的探测腿开工前领一个世代号，落地前再比对。世代已变 ⇒ 后面有
/// 更新的腿，本腿结果已过期，直接退场。「后来者胜」正是这里要的语义。
///
/// **手点「网络检测」腿（[`ipinfo_get`]）与事件驱动排程腿（[`schedule_ipinfo_refresh`]）共用这一条线**
/// ——两条线各管各的等于没管：用户在起核 4s 收敛窗口内点一下检测，就会有两条探测并行，谁先落地纯看
/// 网络抖动，后落地的可能反而是先发起的那条。
static IPINFO_REFRESH_EPOCH: AtomicU64 = AtomicU64::new(0);

/// 领一个新世代，作废所有在飞的旧腿。每条会写缓存 / 广播的探测腿都必须**在开探那一刻**领一次
/// （不是在排程那一刻 —— 理由见 [`schedule_ipinfo_refresh`] 的「按开探顺序发号」一节）。
fn next_ipinfo_epoch() -> u64 {
    IPINFO_REFRESH_EPOCH.fetch_add(1, Ordering::SeqCst) + 1
}

/// 出口 IP 探测的**排程线**：每次「出口世界要变了」的事件（起核 / 停核 / 热切 / TS 就绪 / 启动腿 /
/// 用户手点检测）宣告一次，**在事件那一刻**自增，与 [`IPINFO_REFRESH_EPOCH`] 的开探时刻正交。
///
/// # 为什么一个计数器不够（🔴 2026-07-21 第三轮复审）
///
/// 世代号回答的是「**谁的世界快照最新**」——故必须在**开探**那一刻领（在排程时领会让 4s 收敛窗口内
/// 的手点腿把收敛腿静默作废，见 [`schedule_ipinfo_refresh`] 的 🟠 一节）。但这样一来，「**谁最新**」
/// 这件事在「已排程、尚未开探」的整个收敛窗口里**无人记录**：
///
/// - t=0 热切到 B → L1 置在飞 + 广播置空，睡到 t=4；
/// - t=4.0 L1 醒 → 领世代 1 → 读 status/config（selected=B）→ 开探（走 B 的隧道）；
/// - t=4.1 热切到 C → L2 排程，睡到 t=8.1（**它要到 t=8.1 才领世代 2**）；
/// - t=5.0 L1 探完落地：`IPINFO_REFRESH_EPOCH` 仍是 1 = 自己的号 ⇒ **过闸** ⇒ 广播 B 的出口
///   （用户已在 C），并把 **B 的隧道之外量到的 warm RTT 记进 B 的延迟徽标**。
///
/// 显示错误 4s 后自愈，**延迟徽标的错误却是持久的**（`latencyMap[B]` 保留错值直到下次测 B），而这
/// 正是 [`crate::commands::speedtest::spawn_warm_rtt_probe`] 那道复查存在的全部理由。
///
/// # 两条判据的分工（缺任一条都只对一半）
///
/// | 判据 | 宣告时刻 | 回答 |
/// |---|---|---|
/// | [`IPINFO_REFRESH_EPOCH`] | **开探**（sleep 之后） | 两条已开探的腿，谁的世界快照新 |
/// | `IPINFO_SCHEDULE_SEQ` | **排程 / 事件**（sleep 之前） | 我开探之后，有没有更新的事件宣告过 |
///
/// 腿在**开探那一刻**快照当前值（不是自己自增的那个值 —— 它读 status/config 也在这一刻，两者必须
/// 同一时点），落地时比对「快照 == 当前」：不等 ⇒ 我开探后世界又变了 ⇒ 退场。
static IPINFO_SCHEDULE_SEQ: AtomicU64 = AtomicU64::new(0);

/// 宣告一次「出口世界要变了」（排程 / 手点那一刻调，**不是**开探那一刻）。返回值无消费方：腿要的是
/// 开探时刻的 [`current_ipinfo_schedule_seq`] 快照，不是自己自增出来的号。
fn next_ipinfo_schedule_seq() -> u64 {
    IPINFO_SCHEDULE_SEQ.fetch_add(1, Ordering::SeqCst) + 1
}

/// 开探那一刻的排程线快照（与领世代、读 status/config 同一时点取）。
fn current_ipinfo_schedule_seq() -> u64 {
    IPINFO_SCHEDULE_SEQ.load(Ordering::SeqCst)
}

/// 仅当排程线仍停在 `expected` 时宣告一次自愈复查。CAS 同时承担“确认没有更新事件”和“宣告我最新”；
/// 不能拆成 load + fetch_add，否则两条指令之间的停核/热切事件会被旧复查反向覆盖。
fn claim_ipinfo_schedule_seq(expected: u64) -> Option<u64> {
    claim_schedule_seq(&IPINFO_SCHEDULE_SEQ, expected)
}

fn claim_schedule_seq(counter: &AtomicU64, expected: u64) -> Option<u64> {
    let claimed = expected.wrapping_add(1);
    counter
        .compare_exchange(expected, claimed, Ordering::SeqCst, Ordering::SeqCst)
        .ok()
        .map(|_| claimed)
}

fn next_unreachable_retry_delay_ms(current: u64) -> u64 {
    current
        .saturating_mul(2)
        .min(IPINFO_UNREACHABLE_RETRY_MAX_MS)
}

/// 本腿的「世界」是否仍是当前的：世代未被更新的腿超越 **且** 开探之后无更新事件宣告。
///
/// [`commit_ipinfo_snapshot`] 与**探测腿的下游异步**（当前唯一消费方是出口伴测
/// [`crate::commands::speedtest::spawn_warm_rtt_probe`]：它在探测落地后才 fire，测量期间可能又换了
/// 节点，不复查就会把新节点的 RTT 记到旧节点 id 上）共用这一条判据 —— 两处各写一半必然漂移，而
/// 漂移出来的那一半正是本模块两轮复审各挨了一次的洞。
pub(crate) fn ipinfo_probe_is_current(epoch: u64, seq: u64) -> bool {
    IPINFO_REFRESH_EPOCH.load(Ordering::SeqCst) == epoch
        && IPINFO_SCHEDULE_SEQ.load(Ordering::SeqCst) == seq
}

/// **收敛窗口在飞计数**：延迟腿广播「置空」帧那一刻 +1，该腿跑完（落地 / 被超越退场 / 早退）时 -1。
/// `> 0` ⇒ 至少有一条延迟腿在收敛窗口里，[`peek_ipinfo_snapshot`] 回置空帧。
///
/// # 🔴 为什么是计数而不是 `AtomicBool`（2026-07-21 第三轮复审）
///
/// `AtomicBool` 没有所有权：谁都能清掉谁置的位。两次热切间隔 >4s（完全常规）就够复现——
/// L1（切到 B）t=4 开探、t=5 落地时把位清掉，而 L2（切到 C）t=4.1 才置的位、要到 t=8.1 才开探：
/// 中间 3s 里 `peek` 型消费方（托盘浮层 `TrayMenu.tsx`、主窗水合腿 `App.tsx`）读到的是 **B 的缓存值**，
/// 而用户已在 C。冷启动同样可达（startup 腿清掉起核腿置的位）。
/// 计数后「谁排的位谁归还」，L1 归还只把计数降回 1，窗口在最新那条腿跑完之前不会关。
///
/// # 已知取舍：慢腿会把窗口拖长
///
/// 最新腿已落地、而某条注定要退场的慢腿仍在飞（direct+proxy 两腿串行、各由
/// [`IPINFO_PROBE_BUDGET_MS`] 封顶 ⇒ 最长 20s）时，计数仍 `> 0` ⇒
/// `peek` 继续回置空帧，尽管缓存里已是正确的新值。代价是**多留空几秒**，而反过来（提前关窗）付出的
/// 是**吐旧出口**——本模块的既定纪律是「留空优于用旧出口冒充新出口」，故取前者。要消掉这段窗口得给
/// 在飞腿加取消语义（探测中途放弃），不值。
///
/// # 📌 登记（复审已裁**不计缺陷**，勿据此改代码）
///
/// [`build_ipinfo_snapshot`] 若 panic，排程腿的归还点（体尾那次 `fetch_sub`）走不到 ⇒ 计数永久卡在
/// `> 0` ⇒ `peek` 从此恒回置空帧；按需复查只更新结果、不拥有这格计数，无法代替原排程腿归还。概率极低
/// （该函数及其调用链无显式 panic 点，网络错误一律走 `Result`），故不为它加 catch_unwind / Drop 守卫。
/// 记在这里是让后来者知道这是**已知取舍**，不是没想到。
///
/// # 为什么不能靠「把 pending 帧也写进 `IPINFO_CACHE`」代替
///
/// `IPINFO_CACHE` 同时喂着两条语义不同的读路径：`peek`（零探测水合）与 [`fresh_cached_snapshot`]
/// （15s TTL 内的非 force 短路）。把双 null 的 pending 帧写进缓存会**毒化后者** —— 收敛窗口后的
/// 15s 内，任何非 force 的 `ipinfo_get` 都会短路拿到双 null，等于把「正在探」固化成「探完了没探到」。
/// 故在飞状态必须是独立标记，缓存里永远只放**真探测结果**。
///
/// # 不置位它会怎样（本标记要修的缺陷）
///
/// `peek` 型消费方（托盘浮层 `TrayMenu.tsx` 每次弹出即 peek 水合、主窗 `App.tsx` 窗口重建水合）
/// **不订阅** `ipInfoUpdated`，只读缓存 ⇒ 起核/热切的 4s 收敛窗口里它们照样吐**上一个出口**的 IP，
/// 而同一时刻订阅方（状态栏）已按 pending 帧置空。同屏两处对「我现在从哪出去」给出互相矛盾的答案，
/// 且错的那个正是「用旧出口冒充新出口」——`pending_ipinfo_snapshot` 存在的全部理由。
static IPINFO_INFLIGHT: AtomicUsize = AtomicUsize::new(0);

/// 落地一次探测结果：[`ipinfo_probe_is_current`] 两条判据同时成立 ⇒ 写缓存、回 `true`（调用方随即
/// 广播 + 伴测）；被更新的腿超越、或开探后又有更新事件宣告 ⇒ 什么都不做、回 `false`。
///
/// **不碰 [`IPINFO_INFLIGHT`]**：那一格是**排程腿**排的，归还权也归它（见该 static 的「谁排的位谁
/// 归还」一节）——在这里清位就是 `AtomicBool` 时代「L1 清掉 L2 的位」那个洞。
///
/// # 为什么闸必须在**探测之后**再查一次
///
/// [`build_ipinfo_snapshot`] 最长跑 `IPINFO_PROBE_BUDGET_MS × 2 = 20s`（direct + proxy 两腿串行，
/// 各含定额重试、各自封顶），而排程间隔只有 [`IPINFO_SETTLE_DELAY_MS`] = 4s ——
/// **探测窗口远大于排程间隔**（移植重试后差距进一步拉大），先发起的慢腿完全可能在后
/// 发起的快腿之后落地。只在探测**前**查闸挡不住这段窗口，旧腿会同时污染 `IPINFO_CACHE` 与广播。
///
/// 三个真实序列（本函数即这三条的共同闸；时刻均为**开探**时刻 = 领号时刻）：
/// - **冷启动**：startup 腿 t=3s 领号开探（此刻核未起，只有 direct），autoconnect 同期起核、其 4s 腿
///   t≈6.5s 领号开探并发布代理出口；startup 腿慢探 t≈11s 落地，把它盖成 `proxy=null` ⇒ 状态栏回退
///   `—`、旗面消失。号按开探顺序发 ⇒ startup(3s) < ready(6.5s)，本闸认得出谁旧。
/// - **停核→1.5s 后起核**：停核腿零延迟、t=0 就领号开探；起核腿 t≈5.5s 才领号（1.5 + 4s 收敛）。
///   停核腿探得慢、后落地，其 `proxy=null` 会覆盖起核腿已发布的新出口。
/// - **连点热切 B→C**：B 腿 t=4s 开探（慢），C 腿 t=9s 开探（快）先发布，B 腿后到 ⇒ 状态栏
///   长期显示 B 的出口 IP 与旗面。
///
/// 🔴 第四条序列**世代号一条也认不出**（第三轮复审）：两次热切间隔 >4s 时，L1 已开探（领了号）而
/// L2 还在睡（尚未领号）—— L1 落地那一刻世代仍是它自己的，过闸。挡它的是 [`IPINFO_SCHEDULE_SEQ`]
/// 那一半判据（L1 开探时快照 seq=1，L2 一排程即 seq=2 ⇒ 不等 ⇒ 退场），详见该 static 的文档。
///
/// # 边界：这是 check-then-act，不是临界区
///
/// 世代比对与写缓存**不在同一把锁下**（`IPINFO_REFRESH_EPOCH` 是 atomic，`IPINFO_CACHE` 是 Mutex）。
/// 理论上存在 TOCTOU：本腿过闸之后、拿到 Mutex 之前，一条更新的腿领了号并抢先写完缓存 ⇒ 本腿仍会覆盖它。
/// **实际不可达**：领号与写缓存之间隔着一整次 `build_ipinfo_snapshot`（网络往返，秒级），而这里的两条
/// 指令间隔是纳秒级。合并成一把锁需要让世代号也进 Mutex，为一个够不到的窗口换掉 atomic 的无锁读，不值。
/// 记在这里是为了让后来者知道这是**已知取舍**，不是没想到。
fn commit_ipinfo_snapshot(epoch: u64, seq: u64, snap: &Value) -> bool {
    if !ipinfo_probe_is_current(epoch, seq) {
        return false;
    }
    if let Ok(mut g) = ipinfo_cache().lock() {
        *g = Some(snap.clone());
    }
    true
}

/// `peek=true` 的零探测读取：**在飞时回置空帧**（与订阅方同一帧），否则回缓存快照。
///
/// 抽成独立函数而非内联在 [`ipinfo_get`] 里：`ipinfo_get` 是 `#[tauri::command]`（要 `AppHandle` +
/// `State`，本仓未引 `tauri::test` ⇒ 单测造不出来），而「收敛窗口内 peek 到底吐什么」正是本轮要钉死的
/// 语义，必须可被直测。
fn peek_ipinfo_snapshot() -> Value {
    if IPINFO_INFLIGHT.load(Ordering::SeqCst) > 0 {
        return pending_ipinfo_snapshot();
    }
    ipinfo_cache()
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .unwrap_or_else(empty_ipinfo_snapshot)
}

fn ipinfo_cache() -> &'static Mutex<Option<Value>> {
    IPINFO_CACHE.get_or_init(|| Mutex::new(None))
}

/// **出口无效直判终态的纯逻辑折叠**（1:1 上游 `IpInfoService.markProxyBlocked`，`IpInfoService.ts:187-197`
/// 的 `{...this.snapshot, proxy:null, updatedAt, loading:false, error:undefined, proxyBlocked}`）。
///
/// 输入 = 当前权威缓存快照（`None` = 从未探过 → 取 [`empty_ipinfo_snapshot`]），输出 = 合并后的新快照。
/// **合并而非重建**：`direct`（本机直连出口 IP + 旗面）与代理出口无效**互不相干** —— 整帧重建会把
/// 状态栏那格已探到的本地出口一并抹成 `—`，用户看到的是「网络全挂」而不是「代理出口无效」。
///
/// `error` 必须**删键**（不是置 null）：`blocked` 与 `error` 是互斥语义（blocked = 已知无效、压根没探；
/// error = 探了但失败）。留着上一轮的 `error` 会让 UI 同时收到两个互斥终态。
fn fold_proxy_blocked(cached: Option<Value>, reason: &str) -> Value {
    let mut snap = cached.unwrap_or_else(empty_ipinfo_snapshot);
    if !snap.is_object() {
        // 缓存被写坏（非 object）→ 从空快照重建，绝不 panic、也不把坏值当基底往下传。
        snap = empty_ipinfo_snapshot();
    }
    if let Some(obj) = snap.as_object_mut() {
        obj.insert("proxy".to_string(), Value::Null);
        obj.insert(
            "updatedAt".to_string(),
            json!(u64::try_from(now_epoch_ms()).unwrap_or(u64::MAX)),
        );
        obj.insert("loading".to_string(), json!(false));
        obj.insert("proxyReachability".to_string(), json!("blocked"));
        obj.remove("error");
        obj.insert("proxyBlocked".to_string(), json!(reason));
    }
    snap
}

/// **出口无效直判终态落地**（`ProxyErrorEmitter::mark_exit_blocked` 的唯一实现腿）：把「代理出口已知
/// 无效」同时写进**权威缓存**与广播帧。
///
/// # 为什么必须写缓存（本函数存在的全部理由）
///
/// `EVENT_IP_INFO_UPDATED` 只喂**订阅方**（状态栏）。`peek` 型消费方（托盘浮层每次弹出即 peek、主窗
/// 窗口重建水合）**不订阅**，只读 [`IPINFO_CACHE`] —— 只广播不写缓存 ⇒ 那两处继续吐**上一次探到的
/// 代理出口 IP**，而该出口此刻已被直判无效。同屏两处对「我现在从哪出去」给出互相矛盾的答案，且错的
/// 那个正是「用旧出口冒充一个已知无效的出口」，与 [`pending_ipinfo_snapshot`] 要挡的是同一类失真。
///
/// # 为什么不走 [`commit_ipinfo_snapshot`]
///
/// 那条闸是给**探测腿**用的（领了世代号、可能被更新的腿超越）。本函数不是探测：它是「已知无效」的
/// **直判终态**，没有开探时刻、没有领号，拿别人的号去过闸只会随机被吞。直判终态由调用点（TS 出口
/// 警告跨态）本身保证时序，故此处无条件落地。
///
/// # 🔴 但**必须宣告排程线**（否则在飞的探测腿会把终态盖回去）
///
/// 「出口被直判无效」本身就是一次「出口世界变了」的事件 —— 与起核 / 停核 / 热切同性质，故按本模块
/// 既有的**「排程即宣告」**契约（见 [`IPINFO_SCHEDULE_SEQ`]）在写缓存前自增一次。
///
/// 不宣告的后果（reviewer 复现路径：TS ready 边沿排了 refresh 后 4–24s 内 exit peer 掉线）：
/// 那条腿开探时快照的 `(epoch, seq)` 两个计数器**在整段无人自增** ⇒ 它落地时
/// [`ipinfo_probe_is_current`] 恒过闸 ⇒ 用一个对已知无效出口的探测结果（`proxy:null` + `error`）
/// **覆盖** `proxyBlocked` 终态。而 `reconcile_ts_exit_block` 是边沿触发、同态帧直接早退 ⇒ 终态
/// **不会重落**，错误显示一直挂到下一次真跨态。探测腿的预算最长 20s，收敛窗口 4s，两者都远大于
/// 「掉线到落地」的间隔，所以这不是理论窗口。
///
/// 宣告只作废「**已开探**的腿」；仍在收敛窗口里睡着的腿醒来会快照到这个新号，其结果按本模块既定的
/// 「后开探者胜」语义仍算当前世界的真值 —— 与停核腿宣告后紧跟起核腿的既有形态一致，不另立规矩。
pub(crate) fn mark_ipinfo_proxy_blocked(app: &AppHandle, reason: &str) {
    let snap = commit_proxy_blocked_snapshot(reason);
    crate::events::broadcast(app, crate::events::channel::EVENT_IP_INFO_UPDATED, snap);
}

/// [`mark_ipinfo_proxy_blocked`] 的**无 `AppHandle` 部分**（宣告排程线 + 折叠 + 写权威缓存），返回待广播帧。
///
/// 拆出来的唯一理由是**可测**：`mark_ipinfo_proxy_blocked` 要真 `AppHandle`（本仓未引 `tauri::test`）⇒
/// 行为测试够不着，而「宣告排程线」这条正是本轮修的那一维，只靠源码守卫锁不住落地语义
/// （见 `tests::stale_probe_leg_must_not_overwrite_newer_leg` 的段 (g)）。广播留在外面：它是唯一
/// 需要 `AppHandle` 的动作。
fn commit_proxy_blocked_snapshot(reason: &str) -> Value {
    // 🔴 排程即宣告（**写缓存之前**）：见 [`mark_ipinfo_proxy_blocked`] 文档。
    next_ipinfo_schedule_seq();
    let cached = ipinfo_cache().lock().ok().and_then(|g| g.clone());
    let snap = fold_proxy_blocked(cached, reason);
    if let Ok(mut g) = ipinfo_cache().lock() {
        *g = Some(snap.clone());
    }
    snap
}

/// 空快照（无缓存时 peek 的回退：direct/proxy 均 null）。
fn empty_ipinfo_snapshot() -> Value {
    json!({
        "direct": Value::Null,
        "proxy": Value::Null,
        "proxyReachability": "unknown",
        "updatedAt": 0,
    })
}

/// 当前 epoch 毫秒（快照 updatedAt 用）。
fn now_epoch_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis())
}

/// TTL 内的缓存快照（非 force 时短路复用）；无缓存 / 过期 → None。
fn fresh_cached_snapshot() -> Option<Value> {
    let snap = ipinfo_cache().lock().ok()?.clone()?;
    let updated = snap.get("updatedAt").and_then(Value::as_u64).unwrap_or(0);
    if now_epoch_ms().saturating_sub(u128::from(updated)) <= IPINFO_TTL_MS {
        Some(snap)
    } else {
        None
    }
}

/// 经指定 HTTP client 拉 Cloudflare `cdn-cgi/trace` → `{ ip, countryCode? }`（渲染端 `IpInfo`）。
///
/// **SSRF**：走 [`safe_redirect_fetch`]（逐跳 `assert_host_allowed`）——URL 为固定常量 `EGRESS_TRACE_URL`
/// （cloudflare.com，解析为公网 IP），既非用户可控、又逐跳复检，绝不可被诱导打 127/169.254 控制面 / 元数据。
async fn fetch_trace_ipinfo<H: HttpClient>(client: &H) -> Result<Value, String> {
    let resp = safe_redirect_fetch(SafeRedirectFetchOptions {
        fetch_impl: client,
        url: polaris_unlock::endpoints::EGRESS_TRACE_URL,
        user_agent: app_user_agent(),
        headers: None,
        exempt_fake_ip: false,
        max_redirects: Some(2),
        timeout_ms: Some(IPINFO_TIMEOUT_MS),
        max_body_bytes: Some(IPINFO_MAX_BODY),
        lookup: &SystemDnsLookup,
    })
    .await
    .map_err(|e| e.message)?;
    if !(200..300).contains(&resp.status) {
        return Err(format!("ipinfo trace HTTP {}", resp.status));
    }
    let body = String::from_utf8_lossy(&resp.body);
    let info = polaris_unlock::parse_trace(&body).ok_or_else(|| "trace 解析失败".to_string())?;
    let mut out = json!({ "ip": info.ip });
    if let Some(cc) = info.country_code {
        out["countryCode"] = json!(cc);
    }
    Ok(out)
}

/// 经指定 HTTP client 拉 `myip.ipip.net/json` → `{ ip, country?, countryCode? }`（渲染端 `IpInfo`）。
///
/// **direct 腿专用**：本地直连出口**只信国内** ipip 端点。旁路由/软路由的透明分流会把国外端点
/// （cloudflare/ip-api/ipify）劫持走代理出口 → 直连出口被误标为境外节点 IP（真机实证）。对齐 上游
/// `IpInfoService.queryDirectChain`（EP_IPIP-only，绝不 fallback 国外端点）；与 [`fetch_trace_ipinfo`]
/// （cloudflare，仅 proxy 腿）互斥。
///
/// **SSRF**：走 [`safe_redirect_fetch`]（逐跳 `assert_host_allowed`）——URL 为固定常量 `DIRECT_IPINFO_URL`
/// （myip.ipip.net，解析为公网 IP），既非用户可控、又逐跳复检，绝不可被诱导打 127/169.254 控制面 / 元数据。
async fn fetch_ipip_ipinfo<H: HttpClient>(client: &H) -> Result<Value, String> {
    let resp = safe_redirect_fetch(SafeRedirectFetchOptions {
        fetch_impl: client,
        url: polaris_unlock::endpoints::DIRECT_IPINFO_URL,
        user_agent: app_user_agent(),
        headers: None,
        exempt_fake_ip: false,
        max_redirects: Some(2),
        timeout_ms: Some(IPINFO_TIMEOUT_MS),
        max_body_bytes: Some(IPINFO_MAX_BODY),
        lookup: &SystemDnsLookup,
    })
    .await
    .map_err(|e| e.message)?;
    if !(200..300).contains(&resp.status) {
        return Err(format!("ipinfo ipip HTTP {}", resp.status));
    }
    let body = String::from_utf8_lossy(&resp.body);
    let info = polaris_unlock::parse_ipip(&body).ok_or_else(|| "ipip 解析失败".to_string())?;
    let mut out = json!({ "ip": info.ip });
    if let Some(c) = info.country {
        out["country"] = json!(c);
    }
    if let Some(cc) = info.country_code {
        out["countryCode"] = json!(cc);
    }
    Ok(out)
}

/// 定额重试一次探测动作 —— 1:1 移植 上游 `IpInfoService.withRetry`（`IpInfoService.ts:257-290`）。
///
/// 语义：至多 `attempts` 次，失败之间隔 `retry_delay_ms`（**定间隔，无指数退避** —— 上游 同），
/// 整体由 [`IPINFO_PROBE_BUDGET_MS`] 封顶。返回**最后一次**的错误（诊断时要看最终态，不是首次抖动）。
///
/// 参数化在「尝试动作」上而非 client 上：`fetch_trace_ipinfo` 经 `safe_redirect_fetch` 走真 DNS，
/// 单测碰不得（禁触碰宿主网络）；收在闭包外则重试逻辑本身可被纯逻辑直测（见 `tests` 三条）。
async fn with_ipinfo_retry<F, Fut>(
    mut attempt: F,
    attempts: u32,
    retry_delay_ms: u64,
) -> Result<Value, String>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<Value, String>>,
{
    let budget = Duration::from_millis(IPINFO_PROBE_BUDGET_MS);
    tokio::time::timeout(budget, async move {
        let mut last = Err("ipinfo: 未发起任何尝试".to_string());
        for i in 0..attempts {
            last = attempt().await;
            if last.is_ok() {
                return last;
            }
            // 末次失败后不再睡：那一觉纯粹是把预算烧掉，调用方还得多等一个间隔才拿到失败。
            if i + 1 < attempts {
                tokio::time::sleep(Duration::from_millis(retry_delay_ms)).await;
            }
        }
        last
    })
    .await
    .unwrap_or_else(|_| Err(format!("ipinfo: 探测预算 {IPINFO_PROBE_BUDGET_MS}ms 耗尽")))
}

/// 构造出口 IP 快照：direct（经直连传输层单点）+ proxy（经本机混合端口，核未运行 → null）。
///
/// `post_connect` = 本腿是否跑在**隧道热身窗口**里（起核 / 热切，即走选路收敛延迟那些腿）：
/// 决定 proxy 腿吃哪套重试预算。对照 上游 触发点全表（§10.1 / `main/index.ts`）：
///
/// | 触发点 | 上游 | Polaris | |
/// |---|---|---|---|
/// | 启动首探 | `refresh(true)`（`index.ts:1762`）= 常规 | `delay=3s` → 常规 | ✅ |
/// | 起核就绪 | `refreshProxyPostConnect()`（`index.ts:1966`） | `delay=4s` → post-connect | ✅ |
/// | 停核 | `refresh(true)`（`index.ts:2014`）= 常规 | `delay=0` → 常规 | ✅ |
/// | 手点检测 | `refresh(true, true)` = 常规 | [`ipinfo_get`] 传 `false` | ✅ |
/// | 节点热切 | **仅 `accountBased` 走 post-connect**，IP 类节点走常规（`index.ts:1997-2001`） | 一律 post-connect | ⚠️ |
///
/// ⚠️ **登记一处有意偏离**（勿当遗漏改掉）：热切腿 Polaris 不区分 `accountBased`。
/// 上游 `schedule_exit_ip_refresh` 只拿得到 `running`，要区分得把节点类型一路串下来 —— 而代价不对等：
/// 猜宽了只是 IP 类节点失败时多等一个 4s 间隔（仍在 10s 预算内截断，最坏多两次尝试）；
/// 猜窄了则账号制节点在隧道热身期被 2×1s 耗尽 ⇒ 回落到本轮要根治的那个症状（空 IP + 空旗 + 空延迟）。
/// **非对称风险下取宽**。真要区分，前置是给 [`schedule_ipinfo_refresh`] 传节点类型，不是改这里。
async fn build_ipinfo_snapshot(
    direct_http: &HttpRuntime,
    status: &ProxyStatus,
    post_connect: bool,
) -> Value {
    let (direct, direct_err) = match with_ipinfo_retry(
        || fetch_ipip_ipinfo(direct_http),
        IPINFO_DIRECT_ATTEMPTS,
        IPINFO_DIRECT_RETRY_MS,
    )
    .await
    {
        Ok(v) => (v, None),
        Err(e) => (Value::Null, Some(e)),
    };
    let (proxy_attempts, proxy_retry_ms) = if post_connect {
        (
            IPINFO_PROXY_POST_CONNECT_ATTEMPTS,
            IPINFO_PROXY_POST_CONNECT_RETRY_MS,
        )
    } else {
        (IPINFO_PROXY_ATTEMPTS, IPINFO_PROXY_RETRY_MS)
    };
    let proxy = if status.running && status.mixed_port != 0 {
        match HttpRuntime::via_local_proxy(status.mixed_port) {
            Ok(p) => with_ipinfo_retry(|| fetch_trace_ipinfo(&p), proxy_attempts, proxy_retry_ms)
                .await
                .unwrap_or(Value::Null),
            Err(_) => Value::Null,
        }
    } else {
        Value::Null
    };
    let mut snap = json!({
        "direct": direct,
        "proxy": proxy,
        "proxyReachability": proxy_reachability(status, &proxy),
        "updatedAt": u64::try_from(now_epoch_ms()).unwrap_or(u64::MAX),
    });
    if let Some(e) = direct_err {
        snap["error"] = json!(e);
    }
    snap
}

/// 代理出口探测的可观测终态。这里只投影「本轮能否经 mixed 入站取回出口信息」，不从错误文本推断
/// TLS / QUIC / 认证等底层原因；那些原因在未 patch 内核时没有稳定的结构化信号。
fn proxy_reachability(status: &ProxyStatus, proxy: &Value) -> &'static str {
    if !status.running || status.mixed_port == 0 {
        "unknown"
    } else if proxy.is_null() {
        "unreachable"
    } else {
        "reachable"
    }
}

/// 上游 `IP_INFO_GET`：出口 IP 信息（本地直连出口 / 代理出口）。
///
/// - `peek=true`：零探测，回最近快照；**收敛窗口在飞时回置空帧**（见 [`peek_ipinfo_snapshot`]）。
/// - 非 force：TTL 内回缓存，不打网。
/// - 探测成功 → 缓存 + 广播 `event:ipInfoUpdated`。
#[tauri::command]
pub async fn ipinfo_get(
    app: AppHandle,
    state: State<'_, AppRuntime>,
    force: Option<bool>,
    visible: Option<bool>,
    peek: Option<bool>,
) -> Result<ApiResponse<Value>, ()> {
    let _ = visible; // 保留入参（真链可见性探测流程）；本层直连+代理双探已覆盖，不额外分流。
    if peek.unwrap_or(false) {
        return Ok(ApiResponse::ok(peek_ipinfo_snapshot()));
    }
    if !force.unwrap_or(false) {
        if let Some(cached) = fresh_cached_snapshot() {
            return Ok(ApiResponse::ok(cached));
        }
    }

    // 手点腿同样宣告排程线 + 领世代：既作废在飞的排程腿，也让自己可被更晚的排程腿作废（共用同一
    // 对判据，否则起核收敛窗口内点检测会出现两条互不作废的并行探测）。手点腿的排程与开探是同一刻
    // ⇒ 先自增再快照，快照到的正是自己刚宣告的那个值。
    next_ipinfo_schedule_seq();
    let epoch = next_ipinfo_epoch();
    let seq = current_ipinfo_schedule_seq();
    // State 借用不跨 await：先取 owned（Arc + status + config），再探测。
    let inputs = ipinfo_probe_inputs(&state);
    let has_real_exit = ipinfo_config_has_real_exit(&inputs.config);
    // 手点腿吃**常规**重试预算：用户已在等一个即时答复，隧道热身那套 4×4s 会让按钮看起来卡住。
    // 与 上游 一致（手点走 `refresh(true, true)` → 常规腿，非 post-connect）。
    let (snapshot, committed) = probe_publish_ipinfo(&app, inputs, epoch, seq, false).await;
    if committed && ipinfo_probe_is_current(epoch, seq) {
        schedule_unreachable_ipinfo_recheck(&app, &snapshot, seq, has_real_exit);
    }
    Ok(ApiResponse::ok(snapshot))
}

/// 一次出口 IP 探测所需的全部 owned 输入（`State` 借用**不得跨 await**，故先摘出来）。
struct IpinfoProbeInputs {
    /// 直连传输层（探 direct 出口）。
    http: std::sync::Arc<HttpRuntime>,
    /// 探测时刻的核状态（决定是否探 proxy 出口 + 伴测门控）。
    status: ProxyStatus,
    /// 用户配置（伴测取 `selectedServerId` / 测速 URL）。
    config: Value,
}

/// 从 `AppRuntime` 摘出 [`IpinfoProbeInputs`]（同步，无 await —— 借用在本函数内即结束）。
fn ipinfo_probe_inputs(state: &AppRuntime) -> IpinfoProbeInputs {
    IpinfoProbeInputs {
        http: state.http().clone(),
        status: state.proxy().status(),
        config: state.config().current().unwrap_or_default(),
    }
}

/// 当前配置是否选中了真实存在的节点。复用 config-engine 的哨兵判定，不在 command 层复制哨兵 ID。
fn ipinfo_config_has_real_exit(config: &Value) -> bool {
    let Some(selected) = config.get("selectedServerId").and_then(Value::as_str) else {
        return false;
    };
    if is_sentinel_selection(Some(selected)) {
        return false;
    }
    config
        .get("servers")
        .and_then(Value::as_array)
        .is_some_and(|servers| {
            servers
                .iter()
                .any(|server| server.get("id").and_then(Value::as_str) == Some(selected))
        })
}

/// **探测 → 缓存 → 广播 → 出口伴测**：`ipinfo_get` 的 force 腿与事件驱动腿（[`schedule_ipinfo_refresh`]）
/// 共用的唯一实现。抽出来是为了让「用户点网络检测」与「起核 / 热切 / 停核 / 启动自动触发」跑**同一条
/// 编排**——两套逻辑必然漂移（本仓解锁检测已栽过一次：只移植了广播半边）。
///
/// `epoch` / `seq` 由调用方在**开探那一刻**取（[`next_ipinfo_epoch`] + [`current_ipinfo_schedule_seq`]，
/// 与 `inputs` 里的 status/config 快照同一时点）；探测**之后**经 [`commit_ipinfo_snapshot`] 复查，
/// 任一判据变了即原样退场（不写缓存、不广播、不伴测），理由见 `commit_ipinfo_snapshot` 的文档。
///
/// ⚠️ **本函数不得自己领号 / 自增**：那样复查就是拿现场刚取的值跟自己比，恒真 = 没闸，而下游伴测拿到
/// 的也会是个恒真的判据（`spawn_warm_rtt_probe` 的复查随之形同虚设）。由 `ipinfo_epoch_guard` 钉住。
async fn probe_publish_ipinfo(
    app: &AppHandle,
    inputs: IpinfoProbeInputs,
    epoch: u64,
    seq: u64,
    post_connect: bool,
) -> (Value, bool) {
    let IpinfoProbeInputs {
        http,
        status,
        config,
    } = inputs;
    let snap = build_ipinfo_snapshot(http.as_ref(), &status, post_connect).await;

    // 探测期间（含重试，最长 20s）可能已有更新的腿排上并落地 ⇒ 本腿结果作废。返回值仍给直接调用方
    // （`ipinfo_get` 的请求/响应语义），但绝不许污染全局缓存与广播。
    if !commit_ipinfo_snapshot(epoch, seq, &snap) {
        return (snap, false);
    }
    crate::events::broadcast(
        app,
        crate::events::channel::EVENT_IP_INFO_UPDATED,
        snap.clone(),
    );

    // FX-warmttfb 出口伴测：代理出口探测成功那刻（隧道已热）→ fire-and-forget 补测活跃出口 warm RTT + 广播
    // EVENT_SPEED_TEST_RESULT，让切节点后 UI 延迟徽标自动刷新（对齐 上游 IpInfoService.onProxyProbeSuccess，
    // 置于广播之后触发保「IP 先显、延迟后到」）。探测失败（proxy=null）/ 直连 / 核未运行 → 门控内不 fire。
    // **延迟格是本腿的下游**：出口 IP 不自动探 ⇒ 伴测永不跑 ⇒ 延迟恒 `—`。两格同一条链、一次点亮。
    //
    // `epoch` + `seq` 一路传下去：伴测的 `serverId` 取自**开探时刻**的 config 快照，而测量本身是异步的
    // （fire-and-forget，秒级）。中途起停 / 热切会换掉出口，不复查就把新出口的 RTT 记到旧节点 id 上
    // —— 本批把伴测从「点一次才跑」改成「每次起停/热切都跑」后，这条路径的可达性显著上升。
    // 两条判据都必须传：只传世代时，「更新的腿已排程但还在睡（尚未领号）」这一整个 4s 窗口里复查恒真。
    let proxy_probed = snap.get("proxy").is_some_and(|v| !v.is_null());
    crate::commands::speedtest::spawn_warm_rtt_probe(
        app,
        &config,
        proxy_probed,
        status.running,
        status.mixed_port,
        epoch,
        seq,
    );

    (snap, true)
}

/// 收敛窗口占位快照：direct/proxy 双 null + `loading:true`。
///
/// 延迟腿在**睡之前**先发它，对齐 上游「started 瞬间清空 → `whenSelectorSettled` 后才真探」。
/// 不发的话，起核 / 热切后的收敛窗口里状态栏会继续显示**上一个出口**的 IP 与旗面 —— 把旧出口冒充成
/// 新出口，比留空更糟（与「不得用入口域名派生出口位置」是同一条纪律）。
///
/// ⚠️ **UI 表现仍是「置空」（`—`），不是可见的「检测中」文案**：`loading:true` 无展示消费方；
/// `HomeScreen` 只消费同帧的 `proxyReachability` 来避免在收敛窗口误亮「不可达」，状态栏仍只读出口信息。
/// 这符合用户已裁的「未探到就留空」。别让 StatusBar 消费 `loading` —— 那是在实现一个已被否掉的状态。
fn pending_ipinfo_snapshot() -> Value {
    json!({
        "direct": Value::Null,
        "proxy": Value::Null,
        "proxyReachability": "checking",
        "updatedAt": u64::try_from(now_epoch_ms()).unwrap_or(u64::MAX),
        "loading": true,
    })
}

fn proxy_ip(snapshot: &Value) -> Option<&str> {
    snapshot.get("proxy")?.get("ip")?.as_str()
}

/// 网络变化后的能力复查门：先证实代理出口已经恢复，再判断是否有必要失效解锁快照。
///
/// - 上一帧不可达 → 本轮可达：网络/节点发生了真实恢复；
/// - 前后都可达但出口 IP 改变：能力结论的出口归属已变化；
/// - 上一轮能力快照本就低置信：利用本次恢复事件补一次高置信检测。
fn should_recheck_unlock_after_exit_recovery(
    previous: Option<&Value>,
    current: &Value,
    unlock_degraded: bool,
) -> bool {
    if current.get("proxyReachability").and_then(Value::as_str) != Some("reachable") {
        return false;
    }
    let was_unreachable = previous
        .and_then(|snapshot| snapshot.get("proxyReachability"))
        .and_then(Value::as_str)
        == Some("unreachable");
    let exit_changed = previous
        .and_then(proxy_ip)
        .zip(proxy_ip(current))
        .is_some_and(|(before, after)| before != after);
    was_unreachable || exit_changed || unlock_degraded
}

fn maybe_recheck_unlock_after_exit_recovery(
    app: &AppHandle,
    previous: Option<&Value>,
    current: &Value,
) {
    let Some(runtime) = app.try_state::<AppRuntime>() else {
        return;
    };
    if !should_recheck_unlock_after_exit_recovery(
        previous,
        current,
        runtime.unlock.should_recheck_after_connectivity_recovery(),
    ) {
        return;
    }
    let sink = crate::runtime::unlock::BroadcastSink::new(app);
    runtime.unlock.invalidate(&sink, true, false);
}

fn snapshot_has_proxy_reachability(snapshot: &Value, expected: &str) -> bool {
    snapshot.get("proxyReachability").and_then(Value::as_str) == Some(expected)
}

/// 出口不可达期间的**按需**自愈复查：15s 起步、指数退避到 60s；一旦恢复、停核、切节点、手动检测、
/// 网络变化或 TS 出口直判无效即退出。它复用完整出口探测/缓存/广播/伴测链，不另造第二套结果口径。
///
/// 与普通排程腿有两处刻意差异：
/// - 等待/探测期间不广播 pending，警示态持续可见，旧测速值不会重新冒充当前延迟；
/// - 醒来靠 [`claim_ipinfo_schedule_seq`] CAS 认领，旧腿不能跨越任何更新事件落地。
fn schedule_unreachable_ipinfo_recheck(
    app: &AppHandle,
    snapshot: &Value,
    expected_seq: u64,
    has_real_exit: bool,
) {
    if !has_real_exit || !snapshot_has_proxy_reachability(snapshot, "unreachable") {
        return;
    }
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut expected_seq = expected_seq;
        let mut delay_ms = IPINFO_UNREACHABLE_RETRY_INITIAL_MS;
        loop {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            let Some(seq) = claim_ipinfo_schedule_seq(expected_seq) else {
                return;
            };
            let previous_snapshot = ipinfo_cache().lock().ok().and_then(|g| g.clone());
            let Some(inputs) = app
                .try_state::<AppRuntime>()
                .map(|state| ipinfo_probe_inputs(&state))
            else {
                return;
            };
            if !inputs.status.running
                || inputs.status.mixed_port == 0
                || !ipinfo_config_has_real_exit(&inputs.config)
            {
                return;
            }
            let epoch = next_ipinfo_epoch();
            let (snapshot, committed) = probe_publish_ipinfo(&app, inputs, epoch, seq, false).await;
            if !committed || !ipinfo_probe_is_current(epoch, seq) {
                return;
            }
            maybe_recheck_unlock_after_exit_recovery(&app, previous_snapshot.as_ref(), &snapshot);
            if !snapshot_has_proxy_reachability(&snapshot, "unreachable") {
                return;
            }
            expected_seq = seq;
            delay_ms = next_unreachable_retry_delay_ms(delay_ms);
        }
    });
}

/// **出口 IP 自动重探排程**（事件驱动）——移植 上游 `IpInfoService` 的触发表：
/// 启动 +2s（`runtime::startup_tasks`）· 起核就绪 · 节点热切换 · 停核（后三点经
/// [`ProxyErrorEmitter::schedule_exit_ip_refresh`](crate::runtime::proxy::ProxyErrorEmitter::schedule_exit_ip_refresh)）。
///
/// `delay_ms > 0` ⇒ 先广播 [`pending_ipinfo_snapshot`]（**UI 即刻置空成 `—`**，不是显示可见的
/// 「检测中」文案 —— 见该函数文档）并置 [`IPINFO_INFLIGHT`]，睡满再探。
///
/// # 🟠 按开探顺序发号：[`next_ipinfo_epoch`] 必须在 `sleep` **之后**
///
/// 世代号是「谁更新」的唯一判据，而排程时刻与开探时刻之间隔着整整 [`IPINFO_SETTLE_DELAY_MS`]。
/// 在**排程时**领号 ⇒ 号的顺序是「谁先被排上」，与「谁的结果更新」差一个维度，收敛窗口内会静默丢腿：
///
/// - t=0 起核就绪 → 本函数排程，睡 4s 前先领了号 N；
/// - t≈2 用户手点首页「网络检测」（按钮此刻**可点**：`disabled` 只看 `connected` 与解锁冷却）
///   → `ipinfo_get(force)` 领号 N+1 立刻开探。此刻正是选路未收敛的窗口，它大概率拿回 `proxy=null`；
/// - t=4 收敛腿醒来，睡前领的 N 已经旧了 ⇒ **原地退场、永不开探**。
///
/// 结果：赢的是设计自己判定为不可信的那一次探测，状态栏 `—`、两处旗面消失、`proxy_probed=false` 连伴测
/// 也不跑；即使不可达终态的按需复查稍后兜底，用户也会先经历一整段错误状态，且错误伴测归属不能靠它
/// 事后撤销。
///
/// 改成开探时领号后，上面三条真实序列的先后关系一条不变（`stale_probe_leg_must_not_overwrite_newer_leg`
/// 段 (a)/(b)/(c) 按开探时刻逐条复验），而收敛腿因为号更新而必然胜出。
///
/// 醒后那道旧闸随之删除：领号紧跟在 `sleep` 之后，比对的是零指令之前刚读的同一个值，恒真 = 死代码。
/// 探测**之后**那道闸仍在 [`probe_publish_ipinfo`] 里（挡住探测窗口 20s ≫ 排程间隔 4s 造成的乱序落地）。
///
/// # 🔴 但「开探时领号」只对一半：另一半是 [`IPINFO_SCHEDULE_SEQ`]
///
/// 把发号挪到开探时刻，代价是**排程时刻不再有任何记录**：两次热切间隔 >4s 时，先开探的旧腿落地那一
/// 刻世代仍是它自己的（更新的那条还在睡、尚未领号）⇒ 过闸 ⇒ 广播已切走节点的出口，并把它的 RTT 记进
/// 延迟徽标（持久错值）。故本函数**在 `sleep` 之前**还要自增一次 [`IPINFO_SCHEDULE_SEQ`]，腿在开探时
/// 快照它、落地时比对——「谁最新」由排程线管，「谁的世界快照最新」由世代线管，两条各管一维。
///
/// ⚠️ **必须用 [`tauri::async_runtime::spawn`]，不能用 `tokio::spawn`**（2026-07-21 真机 SIGABRT 血证，
/// 见 `runtime::unlock` 的 `schedule_self_run` 与 `mod spawn_guard`）：本函数的调用链可自**同步** command
/// 路径进入（Tauri 对 `pub fn` command 在主线程直接调、**无 Tokio runtime 上下文**）⇒ 裸 `tokio::spawn`
/// 当场 panic，而 panic 在 Tauri IPC 回调里无处可 catch ⇒ `abort()` ⇒ 整个应用崩溃。
pub fn schedule_ipinfo_refresh(app: &AppHandle, delay_ms: u64) {
    schedule_ipinfo_refresh_inner(app, delay_ms, false);
}

/// OS 网络变化后的恢复探测。与普通起停/热切排程共用同一条出口探测与世代闸；差别仅在成功落地后
/// 按 [`should_recheck_unlock_after_exit_recovery`] 决定是否补跑能力检测。
pub fn schedule_network_recovery_refresh(app: &AppHandle) {
    schedule_ipinfo_refresh_inner(app, IPINFO_SETTLE_DELAY_MS, true);
}

fn schedule_ipinfo_refresh_inner(app: &AppHandle, delay_ms: u64, recheck_unlock_on_recovery: bool) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        // 🔴 **排程即宣告**（sleep 之前，无条件）：这一刻起，任何已开探的旧腿都过期了。世代号做不到
        // 这件事——它要到 sleep 之后才领，而「已排程、尚未开探」的整个 4s 窗口里旧腿是无人作废的
        // （见 `IPINFO_SCHEDULE_SEQ` 文档的 t=4.1 序列）。零延迟腿（停核）同样宣告：出口消失也是
        // 一次「世界变了」，在飞的旧腿结果照样作废。
        next_ipinfo_schedule_seq();
        let previous_snapshot = if recheck_unlock_on_recovery {
            ipinfo_cache().lock().ok().and_then(|g| g.clone())
        } else {
            None
        };
        // 只包住「排在飞 + 广播 pending + sleep」——探测之后那道闸在 probe_publish_ipinfo 里，
        // 零延迟腿（停核）跳过本块但**同样**吃到它。
        //
        // 在飞计数只跟着**广播了置空帧**的延迟腿走：零延迟腿不广播 pending，若也计数就会造出
        // 「订阅方（状态栏）仍显示旧出口、peek 方（托盘）却已置空」的同屏矛盾——而消掉这种矛盾
        // 正是这个标记存在的全部理由。
        if delay_ms > 0 {
            // 先排位再广播：排位后 peek 才与订阅方看到同一帧（顺序反了会留一个吐旧出口的窗口）。
            IPINFO_INFLIGHT.fetch_add(1, Ordering::SeqCst);
            crate::events::broadcast(
                &app,
                crate::events::channel::EVENT_IP_INFO_UPDATED,
                pending_ipinfo_snapshot(),
            );
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }
        // 🟠 **睡满之后**才领号 ⇒ 号按开探顺序发（理由见本函数文档）。挪回 sleep 之前 = 收敛腿被
        // 窗口内的手点腿静默作废。排程线快照与它同刻取：两者合起来才是「我开探时的世界」。
        let epoch = next_ipinfo_epoch();
        let seq = current_ipinfo_schedule_seq();
        // `State` 借用收在本块内，不跨下面的 await（同 `ipinfo_get` 纪律）。
        // setup 前极早期 / 单测：managed state 还没有 ⇒ 静默跳过探测，绝不 panic。
        if let Some(inputs) = app
            .try_state::<AppRuntime>()
            .map(|state| ipinfo_probe_inputs(&state))
        {
            let has_real_exit = ipinfo_config_has_real_exit(&inputs.config);
            // 走**选路收敛延迟**的腿 = 起核 / 热切 ⇒ proxy 侧吃 post-connect 重试预算（隧道热身窗口）。
            // 判据是「等于收敛延迟」而非「有没有延迟」：启动首探也带延迟（3s，`EXIT_IP_PROBE_DELAY_MS`），
            // 但它不是热身场景，上游 那边同样走常规腿。停核腿（0）同理。
            // 逐触发点对照表 + 一处已登记偏离见 `build_ipinfo_snapshot` 文档。
            let post_connect = delay_ms == IPINFO_SETTLE_DELAY_MS;
            let (snapshot, committed) =
                probe_publish_ipinfo(&app, inputs, epoch, seq, post_connect).await;
            if committed && ipinfo_probe_is_current(epoch, seq) {
                if recheck_unlock_on_recovery {
                    maybe_recheck_unlock_after_exit_recovery(
                        &app,
                        previous_snapshot.as_ref(),
                        &snapshot,
                    );
                }
                schedule_unreachable_ipinfo_recheck(&app, &snapshot, seq, has_real_exit);
            }
        }
        // **谁排的位谁归还**，且落地 / 被超越退场 / managed state 缺失三条路径共用这一个归还点。
        // 本函数体内既无 `return` 也无 `?`（spawn 不要求 `Output = ()` ⇒ `?` 同样能早退），两者
        // 由 `ipinfo_epoch_guard` 一并禁掉 —— 故当下不存在绕过这个归还点的路径。
        // 漏还则 peek 永久回置空帧、托盘/水合腿从此再也读不到缓存；按需复查不拥有这格计数，无法纠正。
        if delay_ms > 0 {
            IPINFO_INFLIGHT.fetch_sub(1, Ordering::SeqCst);
        }
    });
}

#[cfg(test)]
mod tests;
