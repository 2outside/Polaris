use super::*;

#[test]
fn network_watcher_restart_backoff_is_bounded() {
    assert_eq!(network_watcher_restart_delay(1), Duration::from_secs(1));
    assert_eq!(network_watcher_restart_delay(2), Duration::from_secs(2));
    assert_eq!(network_watcher_restart_delay(6), Duration::from_secs(30));
    assert_eq!(
        network_watcher_restart_delay(u32::MAX),
        Duration::from_secs(30)
    );
}

/// row33：DNS 热插拔重灌门控——仅「当前 TUN + 用户未关接管开关 + 有接管 marker」三条同时成立才放行。
/// 变异有牙：删 `is_tun` 分支 → (false,·,true) 转真 → 转红（非 TUN 也重灌，误改已切走的系统 DNS）；
/// 删 `has_marker` 分支 → (true,·,false) 转真 → 转红（无接管却擅自灌 DNS）；
/// 把 `takeover` 参数重新写死成 `None`（本轮修的正是这个）→ `Some(false)` 那条转真 → 转红
/// （用户关掉接管后，watcher 仍会在每次链路变化时把系统 DNS 重新抢回来）。
#[test]
fn dns_reconcile_gate_only_tun_with_marker() {
    assert!(
        ProxyRuntime::dns_reconcile_should_run(true, None, true),
        "TUN + 开关缺省（未显式关） + marker → 放行"
    );
    assert!(
        ProxyRuntime::dns_reconcile_should_run(true, Some(true), true),
        "开关显式开 → 放行"
    );
    assert!(
        !ProxyRuntime::dns_reconcile_should_run(true, Some(false), true),
        "用户显式关掉 takeoverSystemDns → 即便 TUN + marker 也不得重灌（此前该开关是装饰）"
    );
    assert!(
        !ProxyRuntime::dns_reconcile_should_run(false, None, true),
        "切走 TUN（虽 marker 在）→ 不重灌"
    );
    assert!(
        !ProxyRuntime::dns_reconcile_should_run(true, None, false),
        "无接管 marker → 不擅自灌 DNS"
    );
    assert!(!ProxyRuntime::dns_reconcile_should_run(false, None, false));
}

/// F15 接线守卫：**每个平台**的 watcher 去抖出口都必须经空 impact 守卫。
///
/// 为什么是源码型门而不是行为测试：两条腿分别在 `#[cfg(windows)]` 与
/// `#[cfg(any(macos, linux))]` 之下，任一宿主上跑的行为测试只能覆盖其中一条 —— 而这条缺陷的
/// 形状恰恰就是「一条腿有守卫、另一条没有」。取材用 [`method_body`]（封顶在本方法体内、剥整行
/// 注释），断言用**计数相等**而不是 `contains`：把守卫删掉、在同一方法别处再写一次
/// `debounced_network_change` 也充不了数。
#[test]
fn every_watcher_debounce_leg_funnels_through_the_empty_impact_guard() {
    let src = module_code("runtime/proxy");
    for head in [
        "    async fn network_watcher_once(",
        "    async fn route_network_watcher_once(",
    ] {
        let body = method_body(&src, head);
        let sent = body.matches("self.handle_network_change(").count();
        let guarded = body.matches("debounced_network_change(").count();
        assert!(sent > 0, "{head}：锚点消失，守卫已失去判据");
        assert_eq!(
            sent, guarded,
            "{head}：每一次 handle_network_change 都必须由空 impact 守卫放行\n{body}"
        );
    }
}

/// C7 用户开关的**原始 JSON 三态读取**（`dnsConfig.takeoverSystemDns` 不在 `DnsConfig` 结构体里）。
///
/// 变异有牙：把路径写成顶层 `takeoverSystemDns`（漏 `dnsConfig` 一层）→ 第一条转红；
/// 把返回折成 bool（`unwrap_or(true)`）→ 「缺省」与「显式 true」不可区分 → 第三条的 `None` 断言转红；
/// 用 `as_bool` 之外的宽松解析（如把字符串 `"false"` 也当 false）→ 第四条转红。
#[test]
fn dns_takeover_switch_reads_three_states_from_raw_json() {
    assert_eq!(
        dns_takeover_enabled(&serde_json::json!({
            "dnsConfig": { "takeoverSystemDns": false }
        })),
        Some(false),
        "显式关 → Some(false)（唯一会拦下接管的取值）"
    );
    assert_eq!(
        dns_takeover_enabled(&serde_json::json!({
            "dnsConfig": { "takeoverSystemDns": true }
        })),
        Some(true)
    );
    assert_eq!(
        dns_takeover_enabled(&serde_json::json!({ "dnsConfig": {} })),
        None,
        "缺省 = 未表态（≠ 显式 true），下游按 `!= Some(false)` 判开"
    );
    assert_eq!(
        dns_takeover_enabled(&serde_json::json!({
            "dnsConfig": { "takeoverSystemDns": "false" }
        })),
        None,
        "非布尔一律 None（对齐 上游 validateConfig 布尔口径），绝不把字符串 \"false\" 当关"
    );
    assert_eq!(dns_takeover_enabled(&serde_json::json!({})), None);
}

/// **接线守卫**：起核尾的 DNS 接管门必须同时看 `is_tun` 与 `dns_takeover`，且 else 腿必须还原。
///
/// 为何用源码扫描而非行为测试：`start_inner` 要真起核并改系统 DNS（真机门），不能在普通 gate
/// 中用副作用覆盖开关的整条接线。把 `&& dns_takeover != Some(false)` 删掉，只有真机启动才会暴露。
/// 断言用**连续片段**（含缩进与 else 腿全文）而不是逐条 `contains`：
/// 后者会被同 impl 块里别处的同名调用（`stop_inner` 也调 `restore_system_dns_best_effort`）假绿放行。
///
/// **本门此前是自指假绿**：测试还内联在 `runtime/proxy.rs` 里时，`crate_source` 取的全文包含本
/// 测试自身，`ELSE_LEG` 与 watcher 那两条 `contains` 命中的是**本测试自己写下的字面量**，生产侧
/// 其实早已漂开（`}` 之后紧跟的是绑定快照注释、watcher 也早已带参）。测试外移后自指消失，两条
/// 断言当场转红，判据遂按生产实况收紧：`ELSE_LEG` 只钉到 else 腿闭合（后面那行注释不再相邻，
/// 钉它等于钉一个不存在的形态），watcher 钉 `self.spawn_network_watcher(`（带 `self.` 前缀即可
/// 排除 `fn` 定义行，且不随实参增删而失效）。
#[test]
fn start_leg_dns_takeover_gate_reads_the_switch() {
    // 取材面钉进 `start_inner` 方法体、且取自剥注释面（复审 2026-08-31 tests12域-判据）：
    // 旧判据对全模块 `module_source` 做 `contains`，把门块整体搬到 runtime/proxy 二十个文件里的
    // **任意**方法（含永不被调用的死代码）四条断言仍全绿——「起核尾必过 DNS 接管门」这条不变式
    // 实际无人守。输入对差（改判据的依据）：
    // - 现状（门在 start_inner 内）：旧绿 / 新绿；
    // - 门块从 start_inner 挪进同模块任意别的方法、起核尾改为无条件接管：旧绿（假绿）/ 新红。
    // `method_body` 封顶在 start_inner 自己的 `\n    }\n`，锚点唯一性由 `impl_method_body` 断言。
    // 取材再过一道 `module_code` 剥注释：单行针（`let dns_takeover = …;` /
    // `self.spawn_network_watcher(`）只要写进任何一行 `//` 注释，就够替生产码作证——生产侧删光、
    // 注释留着，门照绿。多行针（GATE / ELSE_LEG）本就免疫（整行注释每行都带 `//` 前缀，拼不出
    // 针），一并走净化面只是同一取材面不再有两种口径。
    let body = method_body(
        &crate::test_support::module_code("runtime/proxy"),
        "    pub(super) async fn start_inner(",
    );
    assert!(
        body.contains("let dns_takeover = dns_takeover_enabled(&config);"),
        "start_inner 必须在 config 被 move 进 startup_snapshot 之前取一次 takeoverSystemDns 活态"
    );
    // 连续片段：门的合取形态 + 接管 + else 还原，一个字都不能少。通用 watcher 必须在门外统一启动。
    const GATE: &str = "\
        if user_config.proxy_mode_type.is_tun() && dns_takeover != Some(false) {
            self.set_system_dns_best_effort().await;";
    const ELSE_LEG: &str = "\
        } else {
            self.restore_system_dns_best_effort().await;
        }";
    assert!(
        body.contains(GATE),
        "起核尾 DNS 接管门必须是「TUN 且用户未显式关」的合取（1:1 上游 ProxyManager.ts:1103），\
             且必须钉在 start_inner 方法体内——挪去别的方法不算接线"
    );
    assert!(
        body.contains(ELSE_LEG),
        "else 腿必须还原残留受控 DNS（覆盖 TUN→其它模式 / 开→关 两种切换）——\
             少了它，用户关掉接管开关后系统解析器还不回来"
    );
    assert!(
        body.contains("self.spawn_network_watcher("),
        "通用网络 watcher 必须在 start_inner 的 DNS 接管门外启动，\
             否则 System/manual 模式没有网络恢复探测"
    );
}

#[test]
fn network_change_reconciles_dns_then_replans_tun_or_schedules_recovery() {
    // 取材器**必须**是 `method_body` 而不是 `top_level_fn_body`：后者按**列 0** 的 `}` 封顶，
    // 而 `handle_network_change` 是 `impl` 块里的方法（缩进 4 空格）—— 那个列 0 的 `}` 封的是
    // 整个 impl 块。实测：真方法体 75 行（`proxy.rs:2871-2945`），旧取材器切到 **7358 行**
    // （`:2871-10228`），98 倍。后果不是「多扫一点」，是**这条门半瞎**：`self.schedule_restart()`
    // 在超宽切片里有 7 处命中，把真方法体里那一处删掉（= 「需要重规划时不再重启」这条真缺陷），
    // `find` 顺延到 `proxy.rs:4400`，而 4400 > replan 的位置 ⇒ 顺序断言**仍然全绿**。
    // `top_level_fn_body` 现在会对缩进锚点直接 panic，这条注释解释的是当时为什么会写错。
    let body = method_body(
        &module_code("runtime/proxy"),
        "    async fn handle_network_change(",
    );
    let dns = body
        .find("self.reconcile_system_dns_best_effort().await")
        .expect("网络变化必须保留既有 DNS 热插拔重灌入口");
    let recovery = body
        .find("self.schedule_network_recovery_refresh()")
        .expect("System/manual 网络变化必须排出口恢复探测");
    let observe = body
        .find("self.observe_network_interfaces().await")
        .expect("绑定决策必须读取去抖后的接口事实");
    let replan = body
        .find("&& needs_runtime_binding_plan(&config)")
        .expect("TUN 网络变化必须复用运行时绑定判据");
    let restart = body
        .find("self.schedule_restart()")
        .expect("需要重算 TUN 物理接口时必须走现有去抖重启");
    assert!(
        dns < observe && observe < replan && replan < restart && dns < recovery,
        "DNS 重灌须先完成，再以接口事实判定是否重规划"
    );
    assert!(
        body.contains("if !unavailable.is_empty()")
            && body.contains("if explicit_recovered || inferred_replan")
            && body
                .matches("self.schedule_network_recovery_refresh()")
                .count()
                >= 2,
        "显式绑定失效须保留旧核；恢复或推断绑定变化才重启，其余事件只做恢复探测"
    );
}
