use crate::commands::guard_scan::top_level_fn_body;
use crate::test_support::crate_code;

/// 取材面 = `ipinfo.rs` 的**剥注释面**（[`crate_code`]：行首/行尾行注释 + 块注释都剥，
/// 字符串字面量原样保留 —— 本文件多条针就是字面量，如 `"proxy_blocked"`）。
fn src() -> String {
    crate_code("commands/misc/ipinfo.rs")
}

/// 锚定函数体（注释在取材面层已剥，防文档/说明文字把守卫顶成假绿）。
///
/// 此前这里内联着本仓的**第 4 份**剥注释实现，与第 3 份（`ipinfo_spawn_guard.rs`）逐字同形，
/// 两份都只认整行注释。同一事实的第 3、4 份实现一起并入共享面。
fn fn_body(signature: &str) -> String {
    top_level_fn_body(&src(), signature)
}

/// 两条会落地的探测腿（手点 / 排程）。
const PROBE_LEGS: [&str; 2] = [
    "pub async fn ipinfo_get(",
    "fn schedule_ipinfo_refresh_inner(",
];

/// 排程腿签名（下面两条守卫共用）。
const SCHEDULER: &str = "fn schedule_ipinfo_refresh_inner(";

#[test]
fn scheduler_entrypoints_keep_normal_and_network_recovery_semantics_separate() {
    let regular = fn_body("pub fn schedule_ipinfo_refresh(app: &AppHandle, delay_ms: u64) {");
    assert!(
        regular.contains("schedule_ipinfo_refresh_inner(app, delay_ms, false)"),
        "普通起停/热切刷新不得冒充网络恢复并额外失效解锁快照"
    );
    let recovery = fn_body("pub fn schedule_network_recovery_refresh(app: &AppHandle) {");
    assert!(
        recovery.contains("schedule_ipinfo_refresh_inner(app, IPINFO_SETTLE_DELAY_MS, true)"),
        "网络变化须复用同一探测排程，并显式开启恢复后的能力复查门"
    );
}

#[test]
fn unreachable_retry_reuses_probe_pipeline_without_hiding_the_warning() {
    let retry = fn_body("fn schedule_unreachable_ipinfo_recheck(");
    assert!(
        retry.contains("tauri::async_runtime::spawn"),
        "按需复查可从同步 command 腿触发，必须使用 Tauri 全局 runtime"
    );
    assert!(
        retry.contains("claim_ipinfo_schedule_seq(expected_seq)"),
        "醒来必须以 CAS 认领排程线；load + 自增会跨过停核/热切事件"
    );
    assert!(
        retry.contains("next_ipinfo_epoch()")
            && retry.contains("probe_publish_ipinfo(")
            && retry.contains("maybe_recheck_unlock_after_exit_recovery("),
        "复查必须复用世代闸、发布链与能力恢复链，不能另造第二套结果口径"
    );
    assert!(
        !retry.contains("pending_ipinfo_snapshot") && !retry.contains("IPINFO_INFLIGHT"),
        "不可达期间复查不得先广播 pending；否则警示消失、旧延迟重新冒充当前值"
    );
    assert!(
        retry.contains("!has_real_exit")
            && retry.contains("ipinfo_config_has_real_exit(&inputs.config)"),
        "直连/阻断/悬空选择没有真实节点出口，初次与每轮复查都必须被共用哨兵门挡住"
    );

    let claim = fn_body("fn claim_schedule_seq(");
    assert!(
        claim.contains("compare_exchange"),
        "复查认领必须是原子 compare_exchange，不能拆成可竞态的 load + fetch_add"
    );

    for sig in PROBE_LEGS {
        assert!(
            fn_body(sig).contains("schedule_unreachable_ipinfo_recheck("),
            "`{sig}` 的不可达终态没有接上按需复查"
        );
    }
}

/// 🟡 **手点腿的三行顺序**：`宣告 → 领世代 → 快照排程线`，且宣告**恰一次**。
///
/// # 这半边原先零覆盖（本守卫补的正是这个洞）
///
/// 排程腿有 4 条位置断言钉住它的时点（见 [`scheduler_takes_its_epoch_after_the_settle_sleep`]），
/// 手点腿却只有 [`both_probe_legs_take_an_epoch_and_pass_it_down`] 那 3 条 `contains` —— **只证
/// 「三个动作都在」，不证「按什么顺序」**。实测逃逸：把三行改成
/// `let seq = current(); let epoch = next_ipinfo_epoch(); next_ipinfo_schedule_seq();`
/// ⇒ `cargo test` 全绿存活。
///
/// # 顺序错了会怎样
///
/// 快照跑到宣告**之前** ⇒ 本腿快照到的 `seq` 比自己随后宣告的值小 ⇒ 落地时
/// [`commit_ipinfo_snapshot`] 的 `SEQ == seq` 恒假 ⇒ **手点腿永远过不了闸**：不写缓存、不广播、
/// 不 fire 伴测。而 `HomeScreen.tsx` 明确丢弃 `ipinfo_get` 的返回值（靠广播回写）
/// ⇒ **「网络检测」按钮完全无反应**，结果未提交也就不会接上不可达自愈复查。
///
/// 牙：① 三行任意换序 ② 把开探时的 `current_ipinfo_schedule_seq()` 写成再自增一次 —— 均转红。
#[test]
fn manual_leg_declares_then_takes_epoch_then_snapshots_the_schedule_line() {
    let body = fn_body(PROBE_LEGS[0]);
    let sched_at = body
        .find("next_ipinfo_schedule_seq()")
        .expect("手点腿必须宣告排程线，否则它作废不了在飞的排程腿（收敛窗口内两条腿互不作废）");
    let epoch_at = body
        .find("next_ipinfo_epoch()")
        .expect("手点腿必须领世代（上一条守卫同判，此处重复取下标）");
    let snap_at = body
        .find("current_ipinfo_schedule_seq()")
        .expect("手点腿必须快照排程线，否则落地时没有比对基准");
    assert!(
        sched_at < epoch_at,
        "宣告晚于领世代 ⇒ 手点腿领号那一刻还没宣告「我最新」，在飞的排程腿不被作废"
    );
    assert!(
        epoch_at < snap_at,
        "快照早于宣告/领号 ⇒ 快照到的是自己宣告**前**的值，落地闸恒假：按钮永不写缓存/不广播/\
             不 fire 伴测，而前端丢弃返回值 ⇒ 「网络检测」完全无反应"
    );
    assert_eq!(
        body.matches("next_ipinfo_schedule_seq()").count(),
        1,
        "排程线：手点腿的排程与开探是同一刻，宣告**一次**、快照**一次**。\
             多自增一次 = 本腿把自己判成更新事件（落地时恒假，同上）"
    );
}

/// 🔴 **直判终态腿必须宣告排程线，且宣告在写缓存之前**。
///
/// `mark_ipinfo_proxy_blocked` 不是探测（没有开探时刻、不领世代），但它**是一次「出口世界变了」的
/// 事件** —— 按本模块的「排程即宣告」契约，事件那一刻必须自增 [`super::IPINFO_SCHEDULE_SEQ`]，
/// 否则已开探、在飞（预算最长 20s）的探测腿落地时两个计数器都没动过 ⇒ 恒过闸 ⇒ 用 `proxy:null`
/// 覆盖 `proxyBlocked` 终态，而终态由边沿触发、同态帧早退 ⇒ **不会重落**。
///
/// 位置必须在写缓存**之前**：宣告晚于写缓存，就留出一段「终态已进缓存、旧腿仍算当前」的窗口。
///
/// 牙：① 删掉宣告 ② 把它挪到写缓存之后 ③ 顺手加一次领世代（那是探测腿的语义，直判终态没有开探
/// 时刻，领了只会让这条线的口径出现第二个真相源）—— 三条均转红。落地语义由
/// [`super::tests::stale_probe_leg_must_not_overwrite_newer_leg`] 的段 (g) 行为兜底。
#[test]
fn mark_blocked_declares_the_schedule_line_before_writing_the_cache() {
    let body = fn_body("fn commit_proxy_blocked_snapshot(reason: &str) -> Value {");
    let declare = body
        .find("next_ipinfo_schedule_seq()")
        .expect("直判终态必须宣告排程线，否则在飞探测腿落地即把 proxyBlocked 盖回 null/error");
    let write = body
        .find("ipinfo_cache()")
        .expect("直判终态必须写权威缓存（peek 型消费方不订阅广播，只读缓存）");
    assert!(
        declare < write,
        "宣告必须在写缓存之前：反过来会留出「终态已进缓存、旧腿仍算当前」的窗口"
    );
    assert_eq!(
        body.matches("next_ipinfo_schedule_seq()").count(),
        1,
        "宣告一次即可（本函数是单点直判终态，不是排程 + 开探两段）"
    );
    assert!(
        !body.contains("next_ipinfo_epoch()"),
        "直判终态不得领世代：世代线的口径是「开探那一刻」，而本函数压根不开探 —— \
             在这里领号会让世代线出现第二个真相源"
    );
}

#[test]
fn both_probe_legs_take_an_epoch_and_pass_it_down() {
    for sig in PROBE_LEGS {
        let body = fn_body(sig);
        assert!(
            body.contains("next_ipinfo_epoch()"),
            "`{sig}` 没领世代 ⇒ 它既不作废在飞的另一条腿、也不被对方作废，两条探测并行乱序落地"
        );
        assert!(
            body.contains("next_ipinfo_schedule_seq()")
                && body.contains("current_ipinfo_schedule_seq()"),
            "`{sig}` 没接排程线：既不宣告（我最新）也不快照（我开探时的世界），\
                 收敛窗口内「已排程、尚未开探」那 4s 就又回到没人作废旧腿的状态"
        );
        assert!(
            body.contains("probe_publish_ipinfo(")
                && body.contains("epoch")
                && body.contains("seq"),
            "`{sig}` 领了判据却没把**两条**都交给 probe_publish_ipinfo ⇒ 探测后那道闸只剩一半"
        );
    }
}

/// 🟠 **按开探顺序发号**：排程腿必须先 `sleep` 满收敛延迟、**之后**才 [`next_ipinfo_epoch`]。
///
/// 判据是**文本位置序**（`sleep(` 的下标 < `next_ipinfo_epoch()` 的下标），与 `speedtest.rs` 的
/// `fallback_leg_captures_generation_before_awaiting_measurement` 同一范式 —— 那条守的也是
/// 「基准在 await 的哪一侧捕获」这类**接线时点**问题。
///
/// # 为什么行为测试够不着这一条
///
/// [`schedule_ipinfo_refresh`] 要 `AppHandle`（本仓未引 `tauri::test`），单测造不出来；而世代闸本身
/// 的落地语义已由 `tests::stale_probe_leg_must_not_overwrite_newer_leg` 段 (a)–(d) 直驱验证。两者
/// 分工：那边证「号大的赢」，这边证「号是在开探那一刻发的」。**缺任一条，缺陷都能整条溜过去**——
/// 把领号挪回 `sleep` 之前，那边四段照样全绿（它们自己按开探顺序领号），只有这条转红。
///
/// 牙：把 `let epoch = next_ipinfo_epoch();` 挪回 `if delay_ms > 0 {` 之前 → 转红。
///
/// # 本函数还守着另外两组「接线时点」（第三轮复审补）
///
/// - **排程线在 `sleep` 之前宣告、开探时只快照**：世代号既然改到开探时领，「谁最新」这一维就必须
///   由 [`IPINFO_SCHEDULE_SEQ`] 在排程时刻接住，否则收敛窗口内无人记录（见该 static 的 t=4.1 序列）。
/// - **在飞计数的排位/归还成对、且无路径绕过归还**：漏还则 `peek` 永久回置空帧，按需复查也不拥有
///   这格计数，无法代替归还。
///   历史上那条绕过路径正是 `try_state` 早退分支里的单独清位 —— 现已收敛到体尾唯一一次归还。
///   早退面禁 `return` **与 `?`**（第四轮复审：`spawn` 不要求 `Output = ()`，`?` 可编译且能绕过归还）。
#[test]
fn scheduler_takes_its_epoch_after_the_settle_sleep() {
    let body = fn_body(SCHEDULER);
    let sleep_at = body
        .find("sleep(")
        .expect("排程腿必须真的睡满选路收敛延迟（删掉 sleep = 起核瞬间就探，必打到旧出口/失败）");
    let epoch_at = body
        .find("next_ipinfo_epoch()")
        .expect("排程腿必须领世代（上一条守卫同判，此处重复取下标）");

    // 睡之前必须先「置在飞 + 广播置空帧」：少任一半，收敛窗口内就有消费方仍显示**上一个出口**
    // ——订阅方（状态栏）靠广播帧置空，peek 方（托盘浮层 / 窗口重建水合）靠在飞标记。
    let inflight_at = body.find("IPINFO_INFLIGHT.fetch_add(1").expect(
        "睡前必须排一格在飞，否则 peek 型消费方（托盘/水合腿）在收敛窗口里照吐上一个出口 IP",
    );
    let pending_at = body.find("pending_ipinfo_snapshot()").expect(
        "睡前必须广播置空帧，否则订阅方（状态栏）在收敛窗口里继续显示上一个出口的 IP 与旗面",
    );
    assert!(
        inflight_at < pending_at && pending_at < sleep_at,
        "顺序须是「置在飞 → 广播置空 → 睡」：广播早于置位会留一个「订阅方已置空、peek 仍吐旧值」\
             的窗口；两者晚于 sleep 则整个收敛窗口都在显示旧出口"
    );

    assert!(
        sleep_at < epoch_at,
        "世代号在 sleep **之前**领 ⇒ 号的顺序是「谁先被排上」而非「谁先开探」：4s 收敛窗口内用户\
             手点一次「网络检测」就会领走更大的号，收敛后那条重探腿一醒来即判过期、永不开探，\
             而赢的正是设计自己判定为不可信（proxy 极可能为 null）的那一次"
    );
    assert!(
        !body.contains("IPINFO_REFRESH_EPOCH.load("),
        "醒后闸已随「开探时领号」删除（领号紧跟 sleep 之后，比对恒真 = 死代码）；\
             它若复活，说明有人把领号又挪回了排程时刻"
    );

    // 🔴 **排程线必须在 sleep 之前宣告**（第三轮复审）：世代号在 sleep 之后领 ⇒「已排程、尚未
    // 开探」的整个 4s 窗口里没有任何东西记录「有更新的腿排上了」，在飞的旧腿落地时一比对世代
    // 仍是自己的、过闸 —— 广播已切走节点的出口，并把新隧道量到的 RTT 持久写进旧节点的延迟徽标。
    // 牙：删掉这次自增、或把它挪到 `sleep` / `next_ipinfo_epoch()` 之后 → 转红。
    let sched_at = body.find("next_ipinfo_schedule_seq()").expect(
        "排程腿必须在**排程那一刻**宣告排程线，否则收敛窗口内「谁最新」无人记录（见 IPINFO_SCHEDULE_SEQ）",
    );
    assert!(
        sched_at < sleep_at,
        "排程线宣告晚于 sleep ⇒ 它退化成第二个「开探时刻」计数器，与世代号同维、白加一个 static"
    );
    // 开探那一刻取的必须是**快照**（load），不是再自增一次：自增会让本腿把自己也判成「更新的事件」，
    // 落地时恒真 = 没闸。
    let snap_at = body
        .find("current_ipinfo_schedule_seq()")
        .expect("开探时必须快照排程线（与领世代、读 status/config 同刻），否则落地时没有比对基准");
    assert!(
        epoch_at < snap_at && body.matches("next_ipinfo_schedule_seq()").count() == 1,
        "排程线：排程时自增**一次**、开探时快照**一次**。多自增一次 = 本腿把自己判成更新事件（恒真）"
    );

    // 🔵 在飞计数：**谁排的位谁归还**，且没有任何路径能绕过归还。
    // 牙：① 删掉 `fetch_sub` ② 把它挪到 `probe_publish_ipinfo` 之前 ③ 在体内加一条 `return`
    // 跳过它 ④ 让两半挂在不同条件下 ⑤ 用 `?` 早退（见下方 `?` 一节）—— 五种逃逸均转红。
    let sub_at = body.find("IPINFO_INFLIGHT.fetch_sub(1").expect(
        "排位了却不归还 ⇒ peek 永久回置空帧、托盘/水合腿从此再也读不到缓存；按需复查不拥有计数，无法纠正",
    );
    let probe_at = body
        .find("probe_publish_ipinfo(")
        .expect("排程腿必须真的去探（上一条守卫同判，此处重复取下标）");
    assert!(
        probe_at < sub_at,
        "归还早于探测 ⇒ 收敛窗口在探测期间就关了，peek 型消费方立刻吐上一个出口"
    );
    assert_eq!(
        (
            body.matches("IPINFO_INFLIGHT.fetch_add(1").count(),
            body.matches("IPINFO_INFLIGHT.fetch_sub(1").count(),
            body.matches("if delay_ms > 0 {").count(),
        ),
        (1, 1, 2),
        "排位与归还必须各一次、且挂在同一个 `delay_ms > 0` 条件下 —— 两半条件不同即计数会漂"
    );
    // ⚠️ **`return` 不是唯一的早退**（第四轮复审）：`?` 也是，而且它才是真正够得着的那个。
    // [`tauri::async_runtime::spawn`]（tauri-2.11.5 `src/async_runtime.rs:279-284`）的约束只有
    // `F: Future + Send + 'static` + `F::Output: Send + 'static` —— **不要求 `Output = ()`**。
    // 故把 `async move {…}` 改成末尾 `Ok::<(), E>(())` 后就能在体内用 `?`：可编译、可 spawn、
    // 绕过体尾唯一那次 `fetch_sub`，而旧断言只查 `return`、不转红（沙箱实测存活）。
    //
    // 选「加断言」而非「把注释改成『?需人工确认』」的依据：
    // - 前提已实证（上面那份签名 + 最小可编译复现），不是推测；
    // - 本批反复栽在「自述比实际强」上，把守卫降级成一句待办 = 再造一条同型缺陷；
    // - 成本近零：当前函数体内 `?` 出现 **0** 次，且这类早退在本函数里本就不该有
    //   （三条路径必须收敛到同一个归还点）。
    //
    // 禁的是整个 `?` 而非 `"?;"`：`foo()?.bar()` 同样早退，只查 `"?;"` 会漏。
    // 与 `return` 同为**文本**扫描 ⇒ 闭包内的 `return`、字符串字面量里的 `?` 会误伤（假红）——
    // 安全侧，且改法是把那段挪出函数体，不是把守卫改宽。
    assert!(
        !body.contains("return") && !body.contains('?'),
        "函数体内出现 `return` 或 `?` ⇒ 存在绕过归还的路径（`try_state` 早退正是历史上那一条：\
             本腿再也走不到归还点，peek 从此永久置空，按需复查也无法归还别人的计数）。\
             所有分支必须收敛到体尾那一次 fetch_sub"
    );
}

/// 🟡 **广播与伴测必须收在世代闸之内**：[`probe_publish_ipinfo`] 里那道
/// `if !commit_ipinfo_snapshot(…) { return … }` 早退，必须位于 `broadcast(` 与
/// `spawn_warm_rtt_probe(` **之前**。
///
/// # 这半边原先零覆盖（本守卫补的正是这个洞）
///
/// `tests::stale_probe_leg_must_not_overwrite_newer_leg` 直接驱动 [`commit_ipinfo_snapshot`]，
/// **不经** [`probe_publish_ipinfo`] ⇒ 只证了「旧腿写不进缓存」，没证「旧腿也不广播、不 fire 伴测」。
/// 实测逃逸：把那道早退改成 `let _ = commit_ipinfo_snapshot(epoch, &snap);`（保留缓存闸、去掉早退）
/// ⇒ `cargo test` 全绿，而「旧腿照样广播 + 照样 fire 伴测」原样复活 —— 状态栏会被一条已被判定过期的
/// 探测结果盖掉，伴测还会把旧出口的 RTT 记进延迟徽标。
///
/// 牙：① 去掉早退（改 `let _ = …`）② 把 `broadcast(` 挪到早退之前 ③ 把 `spawn_warm_rtt_probe(`
/// 挪到早退之前 —— 三种逃逸均转红。
#[test]
fn publish_leg_gates_broadcast_and_warm_probe_behind_the_epoch_check() {
    let body = fn_body("async fn probe_publish_ipinfo(");
    let gate_at = body.find("if !commit_ipinfo_snapshot(").expect(
        "落地前必须**早退式**查闸：写成 `let _ = commit_ipinfo_snapshot(…)` 只挡住缓存，\
             广播与伴测照跑 —— 旧腿仍会盖掉状态栏、仍会把旧出口 RTT 记进延迟徽标",
    );
    let broadcast_at = body
        .find("crate::events::broadcast(")
        .expect("成功腿必须广播 ipInfoUpdated，否则订阅方（状态栏）永远收不到新出口");
    let warm_at = body
        .find("spawn_warm_rtt_probe(")
        .expect("成功腿必须 fire 出口伴测，否则延迟格恒 `—`（它是本腿的下游）");
    assert!(
        gate_at < broadcast_at,
        "广播在世代闸之外 ⇒ 已过期的旧腿照样把自己的快照推给全体消费方"
    );
    assert!(
        gate_at < warm_at,
        "伴测在世代闸之外 ⇒ 已过期的旧腿照样 fire 一次 RTT 测量，把旧出口的延迟记进徽标"
    );

    // 🔵 **判据必须是入参，不得现场取**（第三、四轮复审各逮到一条存活变异）：把传给
    // `spawn_warm_rtt_probe` 的判据换成现场取的值 ⇒ 下游那道复查拿现场值跟现场值比、恒真 = 没闸，
    // 而 `both_probe_legs_take_an_epoch_and_pass_it_down` 与本函数上面几条断言**均不转红**。
    //
    // 「现场取」有**两种**写法，缺一即漏（第四轮复审：断言原先只禁「领 / 宣告」，不禁「现场 load」）：
    // - **领 / 宣告**（自增）：`next_ipinfo_epoch` / `next_ipinfo_schedule_seq` / 裸 `fetch_add`；
    // - **现场 load**（不自增，但同样绕开入参）：`current_ipinfo_schedule_seq()` 遮蔽入参 `seq`，
    //   或直接 `IPINFO_REFRESH_EPOCH.load(…)`。实测逃逸：在 `spawn_warm_rtt_probe` 调用前插一行
    //   `let seq = current_ipinfo_schedule_seq();` ⇒ 全绿存活，而伴测复查的 seq 半边就此退化成恒真
    //   —— 正是「新腿已排程、还在睡」那 4s 窗口里**把新出口 RTT 持久写进旧节点徽标**的那个洞。
    //
    // 牙：体内出现上述任一写法 → 转红。
    assert!(
        !body.contains("next_ipinfo_epoch")
            && !body.contains("next_ipinfo_schedule_seq")
            && !body.contains("fetch_add")
            && !body.contains("current_ipinfo_schedule_seq")
            && !body.contains("IPINFO_REFRESH_EPOCH"),
        "probe_publish_ipinfo 不得自己领世代 / 宣告排程线，**也不得现场 load 任一计数器**：\
             判据必须原样取自开探那一刻的入参，现场取的值让本层的闸与下游伴测的复查双双恒真"
    );
    let warm_call = &body[warm_at..];
    assert!(
        body.contains("commit_ipinfo_snapshot(epoch, seq,")
            && warm_call.contains("epoch,")
            && warm_call.contains("seq,"),
        "两条判据都必须原样传给闸与伴测：只传世代时，「更新的腿已排程但还在睡」那 4s 窗口里复查恒真"
    );
}

/// 🔵 **调用点守卫**：出口无效直判终态必须**同时**写权威缓存与广播（本轮修的正是「只广播了一半」）。
///
/// # 为什么必须是源码扫描
///
/// [`super::mark_ipinfo_proxy_blocked`] 要 `AppHandle` 才能调（本仓未引 `tauri::test`）；而载荷折叠
/// 那一半已由 `fold_proxy_blocked` 的纯逻辑测覆盖。剩下的「折叠结果到底有没有落进 `IPINFO_CACHE`」
/// 是纯结构事实：把 `*g = Some(snap.clone())` 那两行删掉，**折叠测试一条都不会红** —— 而
/// `ipinfo:get(peek)` 型消费方（托盘浮层 / 窗口重建水合）**不订阅**事件、只读缓存，于是继续吐
/// 上一次探到的、此刻已知无效的代理出口 IP。这正是本仓「逻辑在、接线不在」的经典形态。
///
/// 牙：① 删掉缓存写回 ② 删掉 broadcast ③ 把折叠换成就地 `json!` 重建（绕开 `fold_proxy_blocked`）
/// —— 三条任一均转红。
#[test]
fn proxy_blocked_terminal_state_writes_cache_and_broadcasts() {
    // 落地那一半（折叠 + 写缓存）住在 `commit_proxy_blocked_snapshot`（拆出来是为了让「宣告排程线」
    // 那一维能被行为测试直调，见该函数文档）；广播那一半留在需要 `AppHandle` 的 `mark_…` 里。
    let commit = fn_body("fn commit_proxy_blocked_snapshot(reason: &str) -> Value {");
    assert!(
        commit.contains("fold_proxy_blocked(cached, reason)"),
        "载荷必须经 fold_proxy_blocked 折叠（就地重建 json 会绕开 direct 保留 / error 删键两条语义）"
    );
    assert!(
        commit.contains("*g = Some(snap.clone())"),
        "终态必须写进权威缓存：只广播不写缓存 ⇒ peek 型消费方继续吐已知无效的旧代理出口"
    );
    let body = fn_body("pub(crate) fn mark_ipinfo_proxy_blocked(");
    let write = body
        .find("commit_proxy_blocked_snapshot(reason)")
        .expect("终态必须经落地腿写缓存（只广播不写缓存 ⇒ peek 型消费方读陈旧出口）");
    let cast = body
        .find("crate::events::broadcast(")
        .expect("终态必须广播，否则订阅方（状态栏）不会更新");
    assert!(
        write < cast,
        "先写缓存再广播：反过来则广播到达渲染端时缓存仍是旧值，同一时刻两条读路径互相矛盾"
    );
}

/// 守卫的守卫：证明三个锚点扫到的是真函数体（空串会让 `contains` 断言恒假、表现为恒红，
/// 但仍显式钉住正向内容，避免将来有人把断言「修」宽而让守卫静默失牙）。
#[test]
fn guard_scan_actually_captured_both_leg_bodies() {
    assert!(
        fn_body(PROBE_LEGS[0]).contains("peek"),
        "ipinfo_get 锚点漂了：扫到的片段没有它标志性的 peek 短路腿"
    );
    assert!(
        fn_body(PROBE_LEGS[1]).contains("async_runtime::spawn"),
        "schedule_ipinfo_refresh 锚点漂了：扫到的片段没有它标志性的 spawn"
    );
    assert!(
        fn_body("async fn probe_publish_ipinfo(").contains("build_ipinfo_snapshot("),
        "probe_publish_ipinfo 锚点漂了：扫到的片段没有它标志性的探测调用"
    );
}
