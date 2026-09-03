use super::*;

/// **R4 就绪门参数钉死**：轮询间隔调细的同时，**等待预算的下限一格都不许缩**。
///
/// 两个常量管的是正交的事，混为一谈会直接造出「慢机器起核被误判失败」的 bug：
/// - `CORE_READY_POLL_MS` = 采样精度（就绪后多久**发现**）→ 调小只影响启动快慢。
/// - `CORE_READY_TIMEOUT_FLOOR_MS` = 容忍度下限（到底至少能等多久）→ 调小会砍掉冷启动/杀软扫描的余量。
///
/// 故本测同时钉两头：间隔已降到 50ms，且 12s 的等待窗口原封不动。总超时现已按本次下发配置的规模
/// 上浮（`main_core_ready_timeout_ms`），但**只上浮不下探** —— 下限就是这里钉的这个数。
#[test]
fn core_ready_gate_shortens_poll_without_shrinking_timeout_budget() {
    // 轮询间隔已细化（实测 API 口 97–221ms 就 listen，500ms 栅格纯属白等）。
    assert_eq!(CORE_READY_POLL_MS, 50);
    // 等待预算下限**未被一起缩短** —— 这是慢机器的容忍度，动它就是误判起核失败。
    assert_eq!(
        CORE_READY_TIMEOUT_FLOOR_MS, 12_000,
        "等待预算下限是慢机器容忍度，不得随轮询间隔一起缩短"
    );
    assert_eq!(
        READY_PROBE_TIMEOUT,
        Duration::from_millis(250),
        "loopback 单次探测不得重新膨胀成肉眼可感的串行等待"
    );

    // 等待窗口以「实际覆盖的时间」为准，而非轮数：max_polls = ceil(timeout/poll)。
    // 缩 timeout 或（在 timeout 不变时）把两者一起改小，都会让本断言转红。
    let max_polls = CORE_READY_TIMEOUT_FLOOR_MS
        .div_ceil(CORE_READY_POLL_MS)
        .max(1);
    assert_eq!(max_polls, 240);
    assert_eq!(
        max_polls * CORE_READY_POLL_MS,
        12_000,
        "轮数 × 间隔必须仍覆盖满 12s 窗口"
    );
    // 单次就绪探测超时不得超过一整个等待窗口（否则一次探测就能吃满预算）。
    assert!(READY_PROBE_TIMEOUT.as_millis() as u64 <= CORE_READY_TIMEOUT_FLOOR_MS);
}

#[test]
fn resolve_core_binary_env_override_rejects_missing_file() {
    // 逃生门指向不存在的路径 → 明确报错，绝不静默回落 PATH（误起别的 sing-box 更糟）。
    temp_env_var(
        "POLARIS_SINGBOX_PATH",
        "/nonexistent/polaris/sing-box-xyz",
        || {
            let r = resolve_core_binary();
            assert!(r.is_err(), "指向不存在文件应 Err");
            assert!(r.unwrap_err().contains("POLARIS_SINGBOX_PATH"));
        },
    );
}

#[test]
fn resolve_core_binary_env_override_accepts_real_file() {
    let f = std::env::temp_dir().join(format!(
        "polaris-fake-core-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::write(&f, b"#!/bin/sh\n").unwrap();
    let path = f.to_string_lossy().into_owned();
    temp_env_var("POLARIS_SINGBOX_PATH", &path, || {
        assert_eq!(resolve_core_binary().unwrap(), f);
    });
    let _ = std::fs::remove_file(&f);
}

/// **门：单测态起核只认注入的假核**（本门存在的理由见 [`ProxyRuntime::core_binary_for_start`]
/// 的 cfg(test) 版文档——单测漏出真 sing-box 进程的那个坑）。
///
/// 变异有牙（**两种环境都红**，这正是断固定文案而非 `is_err()` 的原因）：
/// - cfg(test) 版 `core_binary_for_start` 删回 `resolve_core_binary()` → 装了核的机器
///   （mac 真机 / 跑过 `fetch-core.mjs` 的 CI）上返 `Ok(真核路径)`，第一条断言红；`resources/`
///   为空的机器上虽仍是 Err，但文案变「未找到 sing-box 二进制…」，同样红。
/// - 顺手把注入腿也删了（恒 Err）→ 第二条断言红（门太紧会锁死所有需要假核的起核测试）。
#[test]
fn test_mode_start_refuses_real_core_unless_injected() {
    let (rt, dir) = test_runtime();
    assert_eq!(
        rt.core_binary_for_start()
            .expect_err("未注入假核 → 必须拒绝起核，绝不回落真核"),
        TEST_CORE_NOT_INJECTED
    );
    let fake = dir.join("fake-core");
    *rt.core_binary_override.lock().unwrap() = Some(fake.clone());
    assert_eq!(
        rt.core_binary_for_start().unwrap(),
        fake,
        "注入后必须照常放行（否则起核类测试全被锁死）"
    );
}

// ══════════════════════════════════════════════════════════════════════════════
// C11 DNS race sidecar 注入面（`generate_deps` 据运行期 race_server 状态喂 config-engine）。
//
// 生成侧（port>0 → dns-node-race server；race off → withRaceOff 单上游）已由 config-engine
// `builder::dns` / `builder::generate` 单测覆盖；此处专测**注入接线**：`generate_deps` 是否真把
// DnsRaceRuntime 的投影透传下去。变异验证：把 generate_deps 里 race 两轴改回硬编码 0/`[]`
// 会让 `injects_positive_port` 转红。
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn race_server_default_is_off_zero_port() {
    let (rt, _dir) = test_runtime();
    assert_eq!(rt.race_server_port(), 0, "未起 sidecar → race off");
    let deps = rt.generate_deps(9090, 0, 0, None, &[], &serde_json::json!({}));
    assert_eq!(deps.race_server_port, 0, "注入面回落 0（race off）");
    assert!(
        deps.race_upstream_ips.is_empty(),
        "race off → 无上游直连放行"
    );
    assert!(
        deps.race_upstream_ports.is_empty(),
        "race off → 端口轴同样空（route 端口集回 [53,443] 基线，金样不动）"
    );
}

#[test]
fn subscription_update_port_is_independent_and_flows_into_generate_deps() {
    let (rt, _dir) = test_runtime();
    let config = UserConfig::default();
    let (api, update, subscription, probe, pool) = rt.resolve_start_ports(&config, 9090);
    assert_ne!(subscription, 0);
    assert_ne!(subscription, api);
    assert_ne!(subscription, update);
    assert_ne!(Some(subscription), probe);
    assert!(!pool.contains(&subscription));

    let deps = rt.generate_deps(
        api,
        update,
        subscription,
        probe,
        &pool,
        &serde_json::json!({}),
    );
    assert_eq!(deps.update_in_port, Some(update));
    assert_eq!(deps.subscription_update_in_port, Some(subscription));
}

#[test]
fn race_server_injects_positive_port_and_upstreams() {
    let (rt, _dir) = test_runtime();
    // 模拟 sidecar 起成功回调（真起 sidecar 属真机门；此处只验注入接线）。
    rt.set_race_server(
        5353,
        vec!["1.1.1.1".into(), "8.8.8.8".into()],
        vec![443, 8443],
    );
    assert_eq!(rt.race_server_port(), 5353);
    let deps = rt.generate_deps(9090, 0, 0, None, &[], &serde_json::json!({}));
    assert_eq!(
        deps.race_server_port, 5353,
        "端口须透传进 GenerateConfigDeps"
    );
    assert_eq!(
        deps.race_upstream_ips,
        vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
        "上游直连 IP 须透传（route 直连放行防 TUN 回环）"
    );
    assert_eq!(
        deps.race_upstream_ports,
        vec![443u16, 8443],
        "上游端口须与 IP 同轴透传（缺端口 → ip_cidr×port 规则匹配不上，issue #147）"
    );
    // clear → 回落 race off。
    rt.clear_race_server();
    let deps2 = rt.generate_deps(9090, 0, 0, None, &[], &serde_json::json!({}));
    assert_eq!(deps2.race_server_port, 0);
    assert!(deps2.race_upstream_ips.is_empty());
    assert!(deps2.race_upstream_ports.is_empty(), "清理须两轴一起翻");
}

/// 把 `dnsConfig` 片段塞进最小 UserConfig（起 sidecar 只读 dnsConfig；`servers` 无 serde default，必带）。
fn user_config_with_dns(dns: serde_json::Value) -> UserConfig {
    serde_json::from_value(serde_json::json!({ "servers": [], "dnsConfig": dns }))
        .expect("最小 UserConfig")
}

/// 【不变式：竞速 off 不走池】总开关关 → **不起 sidecar** → 注入面恒 (0, []) →
/// config-engine `with_race_off` 走 `nodeResolverSingle` 单上游。
///
/// 变异验证：删掉 owner `start` 里的 `plan_upstreams(..) else { return }` 早退
/// （或把 `plan_upstreams` 的 `resolve_node_domains_ahead == Some(false)` 判断去掉）→
/// sidecar 会照起、端口 >0 → 本测试转红。
#[tokio::test]
async fn race_off_starts_no_sidecar_and_keeps_generate_deps_at_zero() {
    let (rt, _dir) = test_runtime();
    rt.dns_race
        .start(
            &user_config_with_dns(serde_json::json!({
            "resolveNodeDomainsAhead": false,
            // 池里塞满上游也不该生效 —— 总开关优先级高于上游选择。
            "nodeResolverPool": ["ali", "dnspod", "system"],
            })),
            rt.config.dir(),
            rt.gate.generation(),
        )
        .await;
    assert_eq!(rt.race_server_port(), 0, "竞速关 → 端口恒 0");
    let deps = rt.generate_deps(9090, 0, 0, None, &[], &serde_json::json!({}));
    assert_eq!(deps.race_server_port, 0);
    assert!(
        deps.race_upstream_ips.is_empty(),
        "竞速关 → 不放行任何上游直连"
    );
    assert!(deps.race_upstream_ports.is_empty(), "竞速关 → 端口轴同样空");
}

/// 竞速开（含缺省）→ sidecar 真绑回环口，端口与自定义上游的 **IP + 端口两轴**一并进
/// `GenerateConfigDeps`。
///
/// **只绑 127.0.0.1、不发任何真实上游查询**（DoH 走 [`NoNetworkDoh`] 桩，池里不含 system）。
///
/// 自定义上游刻意用**非标端口** `:8443` —— 这正是 issue #147 的形态：端口若不随 IP 下发，
/// route 只放行 IP、端口集仍是 `[53,443]`，规则匹配不上 ⇒ TUN 下该上游经代理出站/回环。
///
/// **变异锁**：把 `generate_deps` 的 `race_upstream_ports` 改回硬编码 `vec![]`（或删掉
/// owner `commit` 里 `state.upstream_ports = …` 那行）→ `8443` 断言转红。
#[tokio::test]
async fn race_on_starts_sidecar_and_feeds_port_and_custom_upstream_ips() {
    let (rt, _dir) = test_runtime();
    rt.dns_race
        .start(
            &user_config_with_dns(serde_json::json!({
            "nodeResolverPool": ["ali", "my-doh"],
            "nodeResolverCustom": [{ "id": "my-doh", "spec": "https://9.9.9.9:8443/dns-query" }],
            })),
            rt.config.dir(),
            rt.gate.generation(),
        )
        .await;
    let port = rt.race_server_port();
    assert!(port > 0, "竞速开 → sidecar 应绑到回环口");
    let deps = rt.generate_deps(9090, 0, 0, None, &[], &serde_json::json!({}));
    assert_eq!(deps.race_server_port, port, "端口须与 sidecar 实际监听一致");
    assert!(
        deps.race_upstream_ips.contains(&"9.9.9.9".to_string()),
        "自定义上游 IP 须进 route 直连放行（否则 TUN 下 sidecar 的 DoH 会回环）：{:?}",
        deps.race_upstream_ips
    );
    assert!(
        deps.race_upstream_ports.contains(&8443),
        "自定义上游的**非标端口**须与 IP 同轴下发（issue #147）：{:?}",
        deps.race_upstream_ports
    );
    assert!(
        deps.race_upstream_ports.contains(&443),
        "内置 ali 的 :443 也在真实上游集里：{:?}",
        deps.race_upstream_ports
    );
    // 停 → 端口与放行清零（生成侧回落单上游）。
    rt.clear_race_server();
    assert_eq!(rt.race_server_port(), 0);
    let deps = rt.generate_deps(9090, 0, 0, None, &[], &serde_json::json!({}));
    assert!(
        deps.race_upstream_ports.is_empty(),
        "停 sidecar 后端口轴须一起清（否则 config 会放行一个已无人使用的端口）"
    );
}

// ===== C6-5 起核路由决策 + helper 起核失败路径（变异验证） =====

/// 起核路由真值表（纯决策）。变异锚点：删 `is_tun()` → systemProxy/manual 断言炸；删平台判 → Other 断言炸。
#[test]
fn should_start_via_helper_truth_table() {
    use ProxyModeType::{Manual, SystemProxy, Tun};
    // TUN + 有 helper 的平台 → 经 helper。
    for p in [Platform::Mac, Platform::Win, Platform::Linux] {
        assert!(
            should_start_via_helper(Tun, p),
            "TUN@{p:?} 应经 helper 起核"
        );
    }
    // TUN@Other（无 helper 实现）→ 退回直起（不经 helper）。
    assert!(
        !should_start_via_helper(Tun, Platform::Other),
        "无 helper 平台的 TUN 不应经 helper（退回直起 best-effort）"
    );
    // 非 TUN（systemProxy/manual 不接管 TUN）→ 恒直起，绝不弹提权。
    for p in [
        Platform::Mac,
        Platform::Win,
        Platform::Linux,
        Platform::Other,
    ] {
        assert!(
            !should_start_via_helper(SystemProxy, p),
            "systemProxy@{p:?} 不应经 helper"
        );
        assert!(
            !should_start_via_helper(Manual, p),
            "manual@{p:?} 不应经 helper"
        );
    }
}

/// helper 起核前置校验（R27.3 preflight）：TUN 需 helper 且未装 → 拦截；非 TUN → 放行。
///
/// 本机/CI 从不安装 `polaris-helper`（系统路径），故 `status().installed` 恒 false（与既有
/// `status_supported_reflects_platform` 同赖此不变式）→ TUN 恒判 missing。变异锚点：删
/// `!installed` 条件 → TUN 断言仍过但**已装态误拦**逃逸面靠真机门；删 `should_start_via_helper`
/// 门 → systemProxy/manual 断言炸（被误拦）。**不连 socket**：未装态 status() 短路，本机安全。
#[test]
fn tun_helper_missing_gates_on_mode_and_install() {
    use ProxyModeType::{Manual, SystemProxy, Tun};
    let (rt, _dir) = test_runtime();
    // 本机 helper 未装 → TUN 需 helper 且未装 → 拦截（换裸 socket ENOENT 为可操作码）。
    assert!(
        rt.tun_helper_missing(Tun),
        "TUN + helper 未装 → 应前置拦截（HELPER_NOT_INSTALLED）"
    );
    // systemProxy/manual 不经 helper（直起）→ 恒放行，即便 helper 未装也绝不误拦正常直起路径。
    assert!(
        !rt.tun_helper_missing(SystemProxy),
        "systemProxy 不需 helper → 放行（不误拦直起）"
    );
    assert!(
        !rt.tun_helper_missing(Manual),
        "manual 不需 helper → 放行（不误拦直起）"
    );
}

/// **门是全入口唯一汇流点**——本批最重要的一条。
///
/// `start`（连接按钮 / 启动自动连接）与 `restart`（切档位去抖重启 / 托盘切模式 / apply-pending）
/// **两条入口都必须经门**。此前门开在 `commands::proxy_start` 命令层，`restart` 腿完全绕过它 →
/// 「系统代理切 TUN」的 stop 跑完、start 撞上无人值守的 preflight → 静默停在停止态（真机反馈 #1）。
///
/// **变异有牙（穷举逃逸面，逐条实测见交付说明）**：
/// - 把门移回命令层 / 从 `start_inner` 删掉调用 → 两个 `calls` 断言双双转 0，红；
/// - 只在 `start` 加门、`restart` 不加（模拟「补一条腿而非补汇流点」）→ 第二段 `restart` 断言红；
/// - 门放到 `spawn` 之后 → 本机会真去连 helper socket，错误码变 STARTUP_FAILED，红。
#[tokio::test]
async fn helper_gate_covers_start_and_restart_entries() {
    let (rt, _dir, calls) = test_runtime_gated(HelperGateDecision::Abort);

    // 入口 1：start（连接按钮 / 启动自动连接）。
    let r = rt.start(tun_config()).await;
    assert!(r.is_err(), "TUN + helper 未装 + 用户取消 → 起核必失败");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "start 入口必须经门（=0 即该入口绕过了汇流点）"
    );

    // 入口 2：restart（**切档位/托盘/去抖重启走这条**）。stop→start，start 腿必须再次经门。
    let r = rt.restart(tun_config()).await;
    assert!(r.is_err(), "restart 的 start 腿同样被门拦住");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "restart 入口必须经门（=1 即 restart 绕过了汇流点，正是真机「切档位静默停止」的成因）"
    );
}

/// 用户取消 → **干净终态** `HELPER_GATE_ABORTED`，而不是静默停止或伪装成启动失败。
///
/// 变异有牙：把 Abort 腿的码换成 `HELPER_NOT_INSTALLED` → 断言红（两码的用户下一步动作相反，
/// 见 `code::HELPER_GATE_ABORTED` 文档）；删 `set_error` 只 `return Err` → `error_code` 为
/// None，红（后端知道、前端不知道 = 真机反馈里「点了没反应」的同型病灶）。
#[tokio::test]
async fn helper_gate_abort_lands_clean_terminal_code() {
    let (rt, _dir, _calls) = test_runtime_gated(HelperGateDecision::Abort);
    let err = rt.start(tun_config()).await.expect_err("取消 → Err");
    assert_eq!(err.message, HELPER_GATE_ABORTED_MSG);
    // A1：码随**这一次**的 Err 出栈，不靠命令层回读全局。变异：把 Abort 腿改回裸
    // `Err(msg.into())`（走 `From<String>` → code=None）→ 本断言红（渲染端又只剩 message 可猜）。
    assert_eq!(
        err.code,
        Some(code::HELPER_GATE_ABORTED),
        "错误自身必须带码（命令层据此分流，不再回读全局 status）"
    );
    let st = rt.status();
    assert_eq!(
        st.error_code.as_deref(),
        Some(code::HELPER_GATE_ABORTED),
        "取消必须落可分类的干净终态码"
    );
    assert!(!st.running, "取消 → 核未起");
}

/// 用户确认但**没装上**（mock 不真装 → 复检仍缺）→ 落 `HELPER_NOT_INSTALLED`，**不冒充成功继续 spawn**。
///
/// 这条守的是 `run_helper_gate` 里最易写错的一行：确认后直接放行、不复检。
/// 变异有牙：删复检腿（`Proceed` 直接 `Ok(())`）→ 起核继续走到 helper socket，错误码变
/// `STARTUP_FAILED`（裸 ENOENT 又回来了）→ 本断言红。
#[tokio::test]
async fn helper_gate_proceed_without_successful_install_still_blocks() {
    let (rt, _dir, calls) = test_runtime_gated(HelperGateDecision::Proceed);
    let err = rt.start(tun_config()).await.expect_err("没装上 → 仍 Err");
    assert_eq!(err.message, HELPER_NOT_INSTALLED_MSG);
    assert_eq!(err.code, Some(code::HELPER_NOT_INSTALLED), "码随 Err 出栈");
    assert_eq!(calls.load(Ordering::SeqCst), 1, "门确实跑了");
    assert_eq!(
        rt.status().error_code.as_deref(),
        Some(code::HELPER_NOT_INSTALLED),
        "确认后装不上 → 仍是「去装」轴，绝不放行 spawn"
    );
}

/// **非 TUN 不弹门**：systemProxy 起核绝不因 helper 未装而弹框（弹了就是每次连接都骚扰）。
/// 变异有牙：删 `run_helper_gate` 首行的 `tun_helper_missing` 短路 → calls 变 1，红。
#[tokio::test]
async fn helper_gate_never_prompts_for_non_tun_mode() {
    let (rt, _dir, calls) = test_runtime_gated(HelperGateDecision::Abort);
    // systemProxy（默认）：门不该命中。起核会继续往下走并在核二进制解析处失败——
    // 只断言「没弹门」，不断言起核结果。
    //
    // 【史】这里原本写的是「因**本机无核二进制**失败」，即假定开发机 `resources/` 是空的。
    // 装了核的机器（mac 真机 / 跑过 `fetch-core.mjs` 的 CI）上该假设当场失效：本行会真 spawn 出
    // 一个 sing-box，就绪后 `start` 返 Ok，而测试结束时没人 `stop()`、`Child` 又无 `kill_on_drop`
    // ⇒ **每跑一次单测漏一个真核进程**（配置目录随即被下面的 remove_dir_all 删掉，进程还在跑）。
    // 现由 `core_binary_for_start` 的 cfg(test) 版 deny-by-default 兜死，失败原因与平台无关。
    let _ = rt.start(two_node_config(7893, "node-a")).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "systemProxy 不经 helper → 绝不弹提权引导"
    );
}

/// **非交互抑制**（崩溃自愈）：不弹框，退回类型化终态。用户没做任何操作时凭空索要管理员密码，
/// 比断流更糟（上游 `options.interactive === false`）。
///
/// 变异有牙：删 `helper_gate_interactive()` 判 → calls 变 1，红（崩溃循环里开始弹框）。
#[tokio::test]
async fn helper_gate_suppressed_in_non_interactive_restart() {
    let (rt, _dir, calls) = test_runtime_gated(HelperGateDecision::Proceed);
    let r = with_helper_gate_suppressed(rt.start(tun_config())).await;
    assert!(r.is_err(), "抑制态仍拦住起核（只是不弹框）");
    assert_eq!(calls.load(Ordering::SeqCst), 0, "非交互腿绝不弹门");
    assert_eq!(
        rt.status().error_code.as_deref(),
        Some(code::HELPER_NOT_INSTALLED),
        "抑制态退回类型化终态，而非 GATE_ABORTED（用户压根没被问）"
    );
}

/// 抑制**必须随作用域退场**（含内层 `Err` —— 崩溃自愈重启失败是常态）。
///
/// 粘住的后果是「功能整体消失」型坑：此后**所有**入口的引导门静默失效，且只在崩溃后才显形。
/// 变异有牙：把 task-local 换回 runtime 字段 + 只在 future 正常返回后 `store(false)`（不用 Drop
/// 守卫）→ 第二段的 `calls==1` 在内层 Err 路径上转红。
#[tokio::test]
async fn helper_gate_suppression_resets_even_on_error() {
    let (rt, _dir, calls) = test_runtime_gated(HelperGateDecision::Abort);
    let r = with_helper_gate_suppressed(rt.start(tun_config())).await;
    assert!(r.is_err(), "内层确实走的是 Err 路径（本测的前提）");
    // 复位真的生效：下一次交互式起核照常弹门。
    let _ = rt.start(tun_config()).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "作用域退场后门恢复工作（=0 说明抑制粘住了）"
    );
}

/// **A2：抑制只作用于崩溃自愈那条调用链，绝不外溢到并发的用户交互起核。**
///
/// 失败场景（本测锁死的那个）：TUN 运行中 helper 被卸载 + 核崩 → 自愈走
/// `with_helper_gate_suppressed(restart(...))`，该段含 stop + start + 最多 3 轮重试与就绪等待，
/// **可达数十秒**。此窗口内用户**手动点连接** → 若抑制是 runtime 级共享标记，用户的显式交互请求
/// 会被当成非交互自愈处理：不弹引导框、直接落 `HELPER_NOT_INSTALLED` = 退回本门修复前的行为。
///
/// **变异有牙（穷举逃逸面）**：
/// - 抑制改回 runtime 级 `AtomicBool` 字段 → 后台腿置位期间用户腿读到 true ⇒ `calls==0` 且码变
///   `HELPER_NOT_INSTALLED`，**两个断言双红**；
/// - 把 task-local 换成进程级 `static AtomicBool` → 同上双红；
/// - `helper_gate_interactive()` 的 `unwrap_or(true)` 写成 `unwrap_or(false)`（未声明即抑制）→
///   用户腿也读到抑制 ⇒ 双红。
#[tokio::test]
async fn helper_gate_suppression_does_not_leak_into_concurrent_interactive_start() {
    let (rt, _dir, calls) = test_runtime_gated(HelperGateDecision::Abort);

    // 后台任务模拟「崩溃自愈重启在飞」：进入抑制作用域后**挂住不退**，直到本测放行。
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel::<()>();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let bg = tokio::spawn(with_helper_gate_suppressed(async move {
        let _ = entered_tx.send(());
        let _ = release_rx.await;
    }));
    entered_rx.await.expect("后台抑制作用域应已进入");

    // 此刻自愈窗口在飞。用户手动点连接（另一个任务 → 读不到那条链的 task-local）。
    let err = rt.start(tun_config()).await.expect_err("取消 → Err");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "自愈窗口内的用户交互起核**必须**照常弹引导（=0 即抑制外溢，退回修复前行为）"
    );
    assert_eq!(
        err.code,
        Some(code::HELPER_GATE_ABORTED),
        "用户被问了且选了取消 → GATE_ABORTED；若是 NOT_INSTALLED 说明门被误抑制、用户压根没被问"
    );

    let _ = release_tx.send(());
    bg.await.expect("后台腿应正常退场");
}

/// **A2：抑制作用域可嵌套，内层退场绝不解除外层。**
///
/// 变异有牙：换回 `AtomicBool` + `Drop` 里无条件 `store(false)`（而非计数递减）→ 内层退场即把
/// 外层的抑制一并解除 ⇒ 外层内的起核开始弹框，`calls==0` 转红。
#[tokio::test]
async fn helper_gate_suppression_scopes_nest() {
    let (rt, _dir, calls) = test_runtime_gated(HelperGateDecision::Abort);
    let rt2 = Arc::clone(&rt);
    with_helper_gate_suppressed(async move {
        // 内层作用域开合一次（模拟自愈腿内部再嵌一段非交互调用）。
        with_helper_gate_suppressed(async {}).await;
        // 外层仍在，抑制必须继续有效。
        let r = rt2.start(tun_config()).await;
        assert!(r.is_err(), "抑制态仍拦住起核");
    })
    .await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "内层退场不得解除外层抑制（>0 说明外层被内层的 Drop 提前解除）"
    );
}

/// **A1：陈旧全局错误码不得污染下一次失败的分类。**
///
/// 真机复现路径：TUN + helper 未装 → 点连接 → 门弹出 → 取消 ⇒ 全局 `error_code` 留下
/// `HELPER_GATE_ABORTED`（**本路径无 `stop()`，而全局码只有 `stop()` 清**）。用户去设置页装好
/// helper 回来再点连接，这次栽在「配置解析失败」腿上 —— 该腿根本不经 `set_error`（见其文档）。
/// 若命令层回读全局，就会把这次失败贴上 `HELPER_GATE_ABORTED` → `HomeScreen` 命中「用户取消」
/// 分支，弹中性 info 并 `return`，`setConnectError(true)` 被跳过、真实错误消息被丢弃。
///
/// **变异有牙（穷举逃逸面）**：
/// - 把 `start` 的 Err 改回回读 `self.status().error_code` 填 `code` → 第二段 `err.code` 变
///   `Some(HELPER_GATE_ABORTED)`，红；
/// - 给 `From<String> for StartError` 的 `code` 填任意常量而非 `None` → 同一断言红；
/// - 删掉第一段（不制造陈旧码）→ 本测退化为恒真，故第一段的 `st.error_code` 断言把「陈旧码确实
///   还在全局」本身也钉死，防止哪天 `stop()` 之外多了个清理点让本测变成假绿。
#[tokio::test]
async fn start_error_code_is_not_polluted_by_stale_global_error_code() {
    let (rt, _dir, _calls) = test_runtime_gated(HelperGateDecision::Abort);

    // 第一段：门弹出 → 用户取消 → 全局落 HELPER_GATE_ABORTED（且本路径无 stop 可清）。
    let first = rt.start(tun_config()).await.expect_err("取消 → Err");
    assert_eq!(first.code, Some(code::HELPER_GATE_ABORTED));
    assert_eq!(
        rt.status().error_code.as_deref(),
        Some(code::HELPER_GATE_ABORTED),
        "陈旧码确实滞留在全局（本测的前提；没了就说明有别的清理点，断言需重估）"
    );

    // 第二段：另一条**不经 set_error** 的失败腿（配置解析失败，`start_inner` 首个 `?`）。
    let second = rt
        .start(serde_json::json!({ "proxyModeType": 12345 }))
        .await
        .expect_err("坏配置 → Err");
    assert!(
        second.message.contains("配置解析失败"),
        "确实走的是无码腿（实际：{}）",
        second.message
    );
    assert_eq!(
        second.code, None,
        "无码腿必须回落 None，绝不继承上一次失败留在全局的 HELPER_GATE_ABORTED"
    );
    assert_eq!(
        rt.status().error_code.as_deref(),
        Some(code::HELPER_GATE_ABORTED),
        "全局仍是陈旧码（本腿不经 set_error）——正因如此才不能回读它"
    );
}

/// emitter 未接线（单测 / setup 前极早期）→ 退回类型化终态，**绝不因为「没法问用户」就放行 spawn**。
/// 变异有牙：把该腿改成 `Ok(())` 放行 → 错误码变 STARTUP_FAILED，红。
#[tokio::test]
async fn helper_gate_without_emitter_falls_back_to_typed_terminal() {
    let (rt, _dir) = test_runtime(); // 刻意不接 emitter
    rt.stale_sweep_disabled.store(true, Ordering::SeqCst);
    let err = rt.start(tun_config()).await.expect_err("无 emitter → 仍拦");
    assert_eq!(err.message, HELPER_NOT_INSTALLED_MSG);
    assert_eq!(err.code, Some(code::HELPER_NOT_INSTALLED), "码随 Err 出栈");
    assert_eq!(
        rt.status().error_code.as_deref(),
        Some(code::HELPER_NOT_INSTALLED)
    );
}

/// helper 起核路径：本机无 daemon → 起核失败（**不静默回退直起**）且**复位 `core_via_helper`**。
///
/// 复位是硬不变式：若失败后仍留标记 true，后续 [`kill_core`] 会误走 helper stop（child 恒 None）→
/// 直起的核永不被杀。变异锚点：删 `store(false)` 复位腿 → 本断言炸。
/// **本机安全**：`start_core` 在 build_client→UnixConnector 连不存在的 socket 时即 ENOENT 失败，
/// **绝不 spawn 真核 / 建 TUN / 碰宿主网络**。
#[tokio::test]
async fn helper_start_without_daemon_errs_and_resets_flag() {
    let (rt, dir) = test_runtime();
    let cfg_path = dir.join("singbox-runtime.json");
    std::fs::write(&cfg_path, "{}").ok();
    let binary = PathBuf::from("/nonexistent/sing-box");
    let user_config: UserConfig = serde_json::from_value(polaris_store::default_config()).unwrap();
    let my_gen = rt.gate.generation();
    let r = rt
        .spawn_core_via_helper(&binary, &cfg_path, &user_config, my_gen)
        .await;
    assert!(
        r.is_err(),
        "本机无 helper daemon → 起核必失败（不静默直起）"
    );
    assert!(
        !rt.core_via_helper.load(Ordering::SeqCst),
        "起核失败必复位 core_via_helper（否则 kill_core 误走 helper stop）"
    );
    // pid 亦不得残留。
    assert!(rt.pid.lock().unwrap().is_none(), "失败不得残留 pid");
}

/// helper 起核路径：起核前已被更新的 start/stop 接管（世代变）→ 让位（`Ok(None)`）、不 IPC、不置标记。
/// 变异锚点：删入口世代判 → 返 `Some`/`Err`（真去 IPC）而非 `None`。
#[tokio::test]
async fn helper_start_superseded_before_ipc_yields_none() {
    let (rt, dir) = test_runtime();
    let cfg_path = dir.join("singbox-runtime.json");
    std::fs::write(&cfg_path, "{}").ok();
    let binary = PathBuf::from("/nonexistent/sing-box");
    let user_config: UserConfig = serde_json::from_value(polaris_store::default_config()).unwrap();
    let stale_gen = rt.gate.generation();
    rt.gate.bump_generation(); // 模拟被接管
    let r = rt
        .spawn_core_via_helper(&binary, &cfg_path, &user_config, stale_gen)
        .await
        .expect("让位是正常返回，非 Err");
    assert!(r.is_none(), "起核前世代已变 → 让位 Ok(None)");
    assert!(
        !rt.core_via_helper.load(Ordering::SeqCst),
        "让位早退不得置标记（未起核）"
    );
}

/// 起核腿被接管（世代已变）→ 静默让位，且**根本不 spawn**（无孤儿进程）。
/// 世代判定在持 child 锁期间进行，故此处模拟「stop 已 bump 世代」后起核必不落地。
#[tokio::test]
async fn start_yields_without_spawning_when_superseded_before_spawn() {
    let (rt, _dir) = test_runtime();
    let stale_gen = rt.gate.generation();
    rt.gate.bump_generation(); // 模拟并发 stop/start 接管

    // 直接调 start_inner 并传入已过期的世代 → 应让位返回、不 spawn。
    let cfg = serde_json::json!({ "servers": [], "selectedServerId": "__direct__" });
    let r = rt.start_inner(cfg, stale_gen).await;
    assert!(r.is_ok(), "让位是正常返回，不是错误");
    assert!(!rt.status().running, "让位腿不得置 running");
    assert!(
        rt.child.lock().unwrap().is_none(),
        "让位腿绝不能 spawn 子进程（否则成孤儿：接管方不知道它的存在）"
    );
}

// ── Fix 3：起核外层重试预算 ──

fn server_json(v: serde_json::Value) -> ServerConfig {
    serde_json::from_value(v).expect("server fixture")
}

#[test]
fn resolve_start_retry_budget_widens_only_for_system_interface_node_on_supported_platform() {
    let plain = server_json(serde_json::json!({
        "id":"p","name":"p","protocol":"shadowsocks","address":"1.1.1.1","port":443
    }));
    let ts_system = server_json(serde_json::json!({
        "id":"t","name":"t","protocol":"tailscale","address":"","port":0,
        "tailscaleSettings": { "reverseMesh": true }
    }));
    let widened = StartRetryBudget {
        max_retries: 10,
        delay_ms: 3000,
        exponential_backoff: false,
    };
    let default = StartRetryBudget {
        max_retries: 2,
        delay_ms: 2000,
        exponential_backoff: true,
    };
    // TUN + darwin + 含 system_interface 节点 → 放宽。
    assert_eq!(
        resolve_start_retry_budget(true, &[plain.clone(), ts_system.clone()], "darwin"),
        widened
    );
    // Windows 禁 System（无双 TUN 竞态）→ 默认。
    assert_eq!(
        resolve_start_retry_budget(true, std::slice::from_ref(&ts_system), "win32"),
        default
    );
    // 非 TUN → 默认。
    assert_eq!(
        resolve_start_retry_budget(false, &[ts_system], "darwin"),
        default
    );
    // 无 system 节点 → 默认。
    assert_eq!(
        resolve_start_retry_budget(true, &[plain], "darwin"),
        default
    );
}

// ── Fix 5：config-gen I/O 落盘交接（写盘 + 孤儿清扫 + sync 只改不删）──

fn smart_config_with_ext_rule() -> UserConfig {
    serde_json::from_value(serde_json::json!({
        "servers": [], "selectedServerId": "__direct__", "proxyMode": "smart",
        "customRules": [
            { "id":"r1", "type":"domain", "values":["a.com"], "action":"proxy", "enabled":true }
        ]
    }))
    .expect("smart config fixture")
}

#[tokio::test]
async fn write_custom_rule_files_writes_expected_and_sweeps_orphans() {
    let (rt, _dir) = test_runtime();
    let crdir = rt.custom_rules_dir();
    std::fs::create_dir_all(&crdir).unwrap();
    // 预置孤儿：裸 .json + 原子写残留 .tmp（均被 is_custom_rule_orphan_file 识别）。
    std::fs::write(crdir.join("custom-rule-stale.json"), "{}").unwrap();
    std::fs::write(crdir.join("custom-rule-x.json.abcdef012345.tmp"), "x").unwrap();
    // 非规则文件不得被误清（谓词不匹配）。
    std::fs::write(crdir.join("keep.txt"), "keep").unwrap();

    let cfg = smart_config_with_ext_rule();
    let expected = build_custom_rule_files(&cfg);
    assert!(
        expected.contains_key("custom-rule-r1.json"),
        "fixture 应产 ext 文件（否则本测无 teeth）"
    );

    rt.write_custom_rule_files(&cfg).await;

    // 期望文件落盘，内容逐字节 == 纯函数期望集。
    for (name, content) in &expected {
        let on_disk = std::fs::read_to_string(crdir.join(name)).unwrap();
        assert_eq!(&on_disk, content, "落盘内容须 == build_custom_rule_files");
    }
    // 孤儿清扫（不在期望集）。
    assert!(
        !crdir.join("custom-rule-stale.json").exists(),
        "裸 .json 孤儿须清"
    );
    assert!(
        !crdir.join("custom-rule-x.json.abcdef012345.tmp").exists(),
        ".tmp 孤儿须清"
    );
    // 非规则文件保留。
    assert!(
        crdir.join("keep.txt").exists(),
        "非 custom-rule 文件不得误清"
    );
    assert!(!rt.custom_rule_files_degraded(), "全成功不应降级");
}

/// wiring 门：`start` 路径真调 `write_custom_rule_files`（generate 前落盘）。用 POLARIS_SINGBOX_PATH→目录
/// 逼 `resolve_core_binary` 在 emit 后失败（不起真核），此刻外化规则文件已落盘。变异（删 `start_inner` 里
/// `write_custom_rule_files` 调用）→ 文件不落 → 断言红。
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn start_lands_custom_rule_files_before_generate() {
    let (rt, dir) = test_runtime();
    rt.stale_sweep_disabled.store(true, Ordering::SeqCst);
    let cfg = serde_json::json!({
        "servers": [], "selectedServerId": "__direct__", "proxyMode": "smart",
        "customRules": [{ "id":"r1", "type":"domain", "values":["a.com"], "action":"proxy", "enabled":true }]
    });
    // env 串行化（与其它 start 测共用 ENV_LOCK）：POLARIS_SINGBOX_PATH→目录 → resolve_core_binary 必 Err。
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("POLARIS_SINGBOX_PATH", &*dir);
    let r = rt.start(cfg).await;
    std::env::remove_var("POLARIS_SINGBOX_PATH");
    drop(_g);
    assert!(
        r.is_err(),
        "核二进制解析失败 → 起核失败（但外化规则已落盘）"
    );
    assert!(
        rt.custom_rules_dir().join("custom-rule-r1.json").exists(),
        "start 路径须在 generate 前落盘外化规则文件（write_custom_rule_files 未接线则文件不存在）"
    );
}

/// public start 必须在 stale 清扫之前就占住稳定门；否则清扫较慢时，8s 订阅补更仍可从缝里起跑，
/// 随后被成功 TUN 的 flush 杀掉。源码顺序门补足上面纯 gate 测试够不着的生产接线。
#[test]
fn public_start_arms_network_settle_before_any_await() {
    let body = method_body(
        &module_code("runtime/proxy"),
        "    pub async fn start(self: &Arc<Self>, config: Value) -> Result<ProxyStatus, StartError> {",
    );
    let arm = body
        .find("let _network_settle = self.network_settle.begin(\"proxy-start\")")
        .expect("public start 必须占住订阅稳定门");
    let first_await = body
        .find("self.cleanup_stale_cores().await")
        .expect("stale 清扫锚必须存在");
    assert!(arm < first_await, "稳定门必须先于 start 的第一个 await");
}

/// ① **退避期取消 → 就地退场**（本任务的主门；直接对应「点了立刻停 vs 静默等 35s」）。
///
/// 非 TUN 预算 = 3 次尝试、退避 2s→4s。本测在第 1 次退避（2s）中途点停止，断言起核腿在
/// **远小于一个退避周期**内退场，并落干净终态。
///
/// 变异（逐条转红）：
/// - `sleep_start_backoff` 退回裸 `tokio::time::sleep` → 取消要等退避睡满才在轮首被发现 → 耗时断言红；
/// - 取消腿写成 `continue` 而不是 `return` → 在接管方之上又起一次核 → pid/child 残留断言红；
/// - `InflightGuard` 去掉 → `starting` 投影卡在 true → 终态断言红。
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn cancelling_start_interrupts_backoff_and_settles_clean() {
    let (rt, dir) = test_runtime();
    rt.stale_sweep_disabled.store(true, Ordering::SeqCst);
    *rt.core_binary_override.lock().unwrap() = Some(write_fake_dying_core(&dir));

    let cfg = local_only_config(free_port());
    let rt2 = Arc::clone(&rt);
    let start = tokio::spawn(async move { rt2.start(cfg).await });

    // 等第 1 次尝试走完（spawn → 核即死 → 就绪门 Dead → kill_core）并进入 2s 退避。
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        rt.status().starting,
        "起核腿应仍在飞 —— `starting` 投影是托盘/UI 判「此刻正在启动」的唯一依据"
    );

    // 用户点停止。
    let t0 = std::time::Instant::now();
    rt.stop().await.expect("停止应成功");
    let out = tokio::time::timeout(Duration::from_secs(3), start)
        .await
        .expect("取消后起核腿必须迅速退场 —— 超时即回归「静默等睡满」")
        .expect("起核任务不应 panic");
    let elapsed = t0.elapsed();

    assert!(
        out.is_ok(),
        "用户主动取消是达成意图、不是失败：让位腿须返 Ok，绝不落 STARTUP_FAILED 弹红框；实得 {out:?}"
    );
    assert!(
        elapsed < Duration::from_millis(1000),
        "取消延迟必须 ≪ 一个退避周期（2s）；实得 {elapsed:?} —— 超出即说明又在等睡满"
    );
    // 干净终态：无半启动状态、无残留句柄。
    let st = rt.status();
    assert!(!st.running, "取消后不得自称 running");
    assert!(
        !st.starting,
        "取消后在飞计数必须归零（InflightGuard 兜底所有出口）"
    );
    assert!(st.error.is_none(), "主动取消不得留错误态");
    assert!(rt.pid.lock().unwrap().is_none(), "取消后不得残留 pid");
    assert!(
        rt.child.lock().unwrap().is_none(),
        "取消后不得残留 child 句柄"
    );
    assert!(
        !rt.core_via_helper.load(Ordering::SeqCst),
        "取消后 helper 受管标记必须清（否则下次 kill_core 走错腿）"
    );
}

/// ② **就绪等待期取消 → 真进程被收割，不留孤儿**（孤儿门；用真活着的假核才有牙）。
///
/// 假核活着但永不就绪 → 起核腿卡在就绪轮询。此时 stop：世代 bump 唤醒轮询 sleep → 让位腿
/// （Superseded）**不 kill**（接管方拥有进程所有权），由 stop 的 `kill_core` 收割。
///
/// 变异：让位腿改成自己 `kill_core` 再 return（看似"更干净"）→ 与接管方争抢句柄；
/// 或让位腿改成 `continue` 重起一次核 → 老核失联 = 孤儿 → `ps` 实证断言转红。
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn cancelling_start_during_readiness_wait_reaps_the_real_process() {
    let (rt, dir) = test_runtime();
    rt.stale_sweep_disabled.store(true, Ordering::SeqCst);
    let fake = write_fake_hanging_core(&dir);
    *rt.core_binary_override.lock().unwrap() = Some(fake.clone());

    let cfg = local_only_config(free_port());
    let rt2 = Arc::clone(&rt);
    let start = tokio::spawn(async move { rt2.start(cfg).await });

    // 等核 spawn 出来并进入就绪轮询（永不就绪）。
    tokio::time::sleep(Duration::from_millis(400)).await;
    let pid = rt.pid.lock().unwrap().expect("此刻应已 spawn 出受管核 pid");
    assert!(
        ps_alive(pid),
        "前提：假核应在跑（ps 实证），否则本测测不到孤儿面"
    );

    let t0 = std::time::Instant::now();
    rt.stop().await.expect("停止应成功");
    let out = tokio::time::timeout(Duration::from_secs(5), start)
        .await
        .expect("取消后起核腿必须迅速退场")
        .expect("起核任务不应 panic");
    let elapsed = t0.elapsed();

    assert!(out.is_ok(), "就绪等待期被接管 = 让位，返 Ok；实得 {out:?}");
    assert!(
        elapsed < Duration::from_secs(3),
        "取消应就地生效；实得 {elapsed:?}"
    );
    // **孤儿门**：ps ground truth，不信 status 自述。
    assert!(
        !ps_alive(pid),
        "取消后受管核 pid={pid} 必须已被收割 —— 活着 = 孤儿（正是本次事故里锁死 cache 文件的那种）"
    );
    // 更宽的一张网：**任何**本假核实例都不许留着。只验旧 pid 会漏掉「取消腿没 return、又 spawn 了
    // 一个」这条逃逸路径 —— 那个新核的 pid 根本不在旧断言的射程里（变异实测补）。
    assert_eq!(
        fake_core_proc_count(&fake),
        0,
        "取消后不得有任何假核实例存活（含让位腿又新起的那种 = 谁也不认领的孤儿）"
    );
    assert!(!rt.status().running);
    assert!(!rt.status().starting, "在飞计数必须归零");
    assert!(
        rt.child.lock().unwrap().is_none(),
        "child 句柄必须已被接管方取走并收割"
    );
}

/// ④ **没人取消时，重试预算必须原样跑满**（改过头门的端到端形态）。
///
/// 假核每次都立刻死 → 3 次尝试 + 2s + 4s 退避 → 终态 Err(STARTUP_FAILED)。
/// 变异：取消信号误触发（如 select 的取消腿写成恒就绪、或 `notify_waiters` 被无关路径调用）→
/// 起核腿会提前返 Ok(让位) → 「必须是 Err」与「必须耗满退避」两条同时转红。
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn uncancelled_start_still_burns_the_whole_retry_budget() {
    let (rt, dir) = test_runtime();
    rt.stale_sweep_disabled.store(true, Ordering::SeqCst);
    *rt.core_binary_override.lock().unwrap() = Some(write_fake_dying_core(&dir));

    let t0 = std::time::Instant::now();
    let r = rt.start(local_only_config(free_port())).await;
    let elapsed = t0.elapsed();

    let err = r.expect_err("三次尝试全失败 → 必须落终态 Err（不得被取消腿吞成 Ok）");
    assert_eq!(
        err.code,
        Some(code::STARTUP_FAILED),
        "起核期退出耗尽预算 → STARTUP_FAILED"
    );
    assert!(
        elapsed >= Duration::from_millis(5_500),
        "无人接管时两次退避（2s+4s）必须真睡满；实得 {elapsed:?} —— 变短即说明退避被取消信号误中断"
    );
    assert!(!rt.status().starting, "终态后在飞计数必须归零");
}

#[tokio::test]
async fn sync_custom_rule_files_updates_content_but_never_deletes() {
    let (rt, _dir) = test_runtime();
    let crdir = rt.custom_rules_dir();
    std::fs::create_dir_all(&crdir).unwrap();
    // 预置一个「本轮期望集之外」的既存文件：sync **绝不删**（运行中删被挂载文件会致 sing-box reload 报错）。
    std::fs::write(crdir.join("custom-rule-stale.json"), "stale").unwrap();

    let cfg = smart_config_with_ext_rule();
    let expected = build_custom_rule_files(&cfg);

    rt.sync_custom_rule_files(&cfg).await;

    // 期望文件被写（内容变 → 原子替换）。
    for (name, content) in &expected {
        assert_eq!(&std::fs::read_to_string(crdir.join(name)).unwrap(), content);
    }
    // 绝不删：本轮期望集外的既存文件仍在（删除只在起核 write_custom_rule_files 清扫）。
    assert!(
        crdir.join("custom-rule-stale.json").exists(),
        "sync 绝不删文件（仅起核清扫删孤儿）"
    );
}

// ══════════════ #327：起核后 TUN 适配器存在性逐腿验证 ══════════════

/// 探测适用面的真值表：**仅 TUN@Windows**。
///
/// **变异锁**：删 `is_tun` → 第 3 条转红（systemProxy 也去探，而它根本不建适配器 ⇒ 恒 `Absent`，
/// 等于把完全正常的起核判成失败）；删平台判据 → 第 4/5 条转红（mac/Linux 上 `WinAdapterProbe`
/// 不存在，本机还会白跑）；把 `"win32"` 写成 `"windows"` → 第 1/2 条转红（`platform_tag` 用的是
/// Node 约定）。
#[test]
fn wintun_probe_gate_is_tun_on_windows_only() {
    assert!(should_probe_wintun_adapter(ProxyModeType::Tun, "win32"));
    assert!(!should_probe_wintun_adapter(
        ProxyModeType::SystemProxy,
        "win32"
    ));
    assert!(!should_probe_wintun_adapter(ProxyModeType::Manual, "win32"));
    assert!(!should_probe_wintun_adapter(ProxyModeType::Tun, "darwin"));
    assert!(!should_probe_wintun_adapter(ProxyModeType::Tun, "linux"));
}

/// 判定真值表：见到 / 不可断言 → 放行；缺失 → 预算内重试，耗尽按「曾见过」分岔两个终态。
///
/// **变异锁**：
/// - 把 `Indeterminate` 归到失败侧 → 第 2 条转红（枚举 API 一坏就杀正常核，比原缺陷更糟）；
/// - 把重试条件写成 `attempt < max_retries` → 第 4 条转红（少用一整条腿的预算）；
/// - 丢掉 `ever_seen` 分岔（两个终态压成一个）→ 第 6 条转红（抖动被误报成「wintun 建不出来」，
///   把用户导向「重装驱动」这条错误的下一步）。
#[test]
fn tun_adapter_leg_verdicts() {
    use TunAdapterObservation as O;
    use TunAdapterVerdict as V;
    // 1) 见到 → 放行。
    assert_eq!(classify_tun_adapter_leg(O::Present, true, 3, 2), V::Proceed);
    // 2) 不可断言（非 TUN@win / 自定义接口名 / 枚举报错）→ 放行，绝不据此杀核。
    assert_eq!(
        classify_tun_adapter_leg(O::Indeterminate, false, 3, 2),
        V::Proceed
    );
    // 3) 缺失 + 预算充足 → 计入重试预算。
    assert_eq!(
        classify_tun_adapter_leg(O::Absent, false, 1, 2),
        V::RetryLeg
    );
    // 4) 缺失 + 恰好用到最后一次重试（attempt == max_retries）→ 仍重试（与 Dead/Timeout 腿同判据）。
    assert_eq!(
        classify_tun_adapter_leg(O::Absent, false, 2, 2),
        V::RetryLeg
    );
    // 5) 缺失 + 预算耗尽 + 全程没见过 → 终态：wintun 建不出来。
    assert_eq!(
        classify_tun_adapter_leg(O::Absent, false, 3, 2),
        V::TerminalNeverAppeared
    );
    // 6) 缺失 + 预算耗尽 + 中途见过 → 终态，但不是「建不出来」（抖动，指引完全不同）。
    assert_eq!(
        classify_tun_adapter_leg(O::Absent, true, 3, 2),
        V::TerminalAfterFlap
    );
    // 7) 零重试预算（max_retries=0）→ 首腿缺失即终态。
    assert_eq!(
        classify_tun_adapter_leg(O::Absent, false, 1, 0),
        V::TerminalNeverAppeared
    );
}

/// **接线守卫**：存在性验证必须在**重试循环内**、且在就绪判定之后、`verify_tun_route_captured` 之前。
///
/// 三条位置关系各锁一个真实的退化方向：
/// - 挪出循环 → 退回「只验最后一腿」，前 N-1 腿的假就绪照样能标 connected（本 issue 的原形）；
/// - 挪到就绪之前 → 核还没起完就问「网卡呢」，恒缺失 ⇒ TUN 模式全线起不来；
/// - 排到出口归属校验之后 → 网卡都没有时先问「默认路由切走了没」，用户拿到的是
///   「其他 VPN 占用默认路由，请先断开」这条与现场无关的指引。
///
/// 行为测试够不着：整条是 `cfg(windows)` + 真起核 + 真建网卡（三重真机门），本机跑不到。
#[test]
fn tun_adapter_presence_probe_is_wired_per_retry_leg() {
    // 不带 `self.` 前缀：调用点被 rustfmt 折成 `self\n.probe_tun_adapter_present(`，
    // 连写 `self.` 的判据会被换行静默打空（那就是「扫到 0 条于是全绿」的假门）。
    const PROBE: &str = ".probe_tun_adapter_present(";
    let body = method_body(
        &module_code("runtime/proxy"),
        "    pub(super) async fn start_inner(",
    );
    let loop_head = body
        .find("= loop {")
        .expect("起核重试 loop 锚点消失，接线守卫已失去判据");
    let ready_arm = body
        .find("CoreReadyOutcome::Ready => {")
        .expect("就绪腿锚点消失，接线守卫已失去判据");
    let route_gate = body
        .find(".verify_tun_route_captured(")
        .expect("出口归属校验锚点消失，接线守卫已失去判据");
    let probe = body.find(PROBE).expect("TUN 适配器存在性验证未接线");
    assert_eq!(
        body.matches(PROBE).count(),
        1,
        "start_inner 里只该有一处存在性验证；出现第二处说明判据被复制，两处会分头漂移"
    );
    assert!(
        loop_head < probe,
        "存在性验证必须在起核重试循环**内**（逐腿验）"
    );
    assert!(
        ready_arm < probe,
        "存在性验证必须在就绪判定**之后** —— 核没起完就问网卡，恒缺失"
    );
    assert!(
        probe < route_gate,
        "存在性验证必须排在出口归属校验**之前**：网卡都没有时问「路由切走了没」，\
             只会给出「断开其他 VPN」这条与现场无关的指引"
    );
}

// ══════════════ #332：核 stderr FATAL 真因 → 专属错误码 ══════════════

/// 判定用的样本行按**取证到的字面量**拼（链路见 [`classify_core_fatal_line`] 文档）：
/// 外层 `configure tun interface`（sing-box `protocol/tun/inbound.go:438`，已在随包 1.14.0-beta.7
/// 二进制里 `strings` 验到）+ 内层 `set ipv4 address`（sing-tun `tun_windows.go:81`，Windows-only
/// 文件，取自源码而非二进制）。
fn fatal_line(inner: &str) -> String {
    format!("+0800 FATAL start service: initialize inbound/tun[tun-in]: {inner}")
}

#[test]
fn core_fatal_classifies_tun_address_step() {
    let win = fatal_line("configure tun interface: set ipv4 address: The object already exists.");
    assert_eq!(
        classify_core_fatal_line(&win, singbox_line_level(&win)),
        Some(CoreFatalKind::TunAddressUnavailable)
    );
    let win6 = fatal_line("configure tun interface: set ipv6 address: The object already exists.");
    assert_eq!(
        classify_core_fatal_line(&win6, singbox_line_level(&win6)),
        Some(CoreFatalKind::TunAddressUnavailable)
    );
    // Linux 侧同一件事的包装串（sing-tun `tun_linux.go:145`）。
    let linux = fatal_line("configure tun interface: add address 172.19.0.1/30: file exists");
    assert_eq!(
        classify_core_fatal_line(&linux, singbox_line_level(&linux)),
        Some(CoreFatalKind::TunAddressUnavailable)
    );
}

/// **本条锁的是「不拿 errno 文案当判据」这个决定**：Windows 的那截尾巴经 `FormatMessage` 生成、
/// 跟随系统语言。若判据里塞了 `"already exists"`，中文/俄文 Windows 上判定静默失效 —— 而那恰是
/// 用户最多的那批机器。改判据前先看这条测试。
#[test]
fn core_fatal_is_independent_of_os_errno_language() {
    for tail in [
        "对象已存在。",
        "Объект уже существует.",
        "L'objet existe déjà.",
    ] {
        let line = fatal_line(&format!(
            "configure tun interface: set ipv4 address: {tail}"
        ));
        assert_eq!(
            classify_core_fatal_line(&line, singbox_line_level(&line)),
            Some(CoreFatalKind::TunAddressUnavailable),
            "errno 文案换个语言就判不出来 = 判据依赖了系统语言"
        );
    }
}

#[test]
fn core_fatal_rejects_non_tun_address_failures() {
    // 1) 端口占用（mixed 入站）——同样带「address already in use」，但**不是** TUN 地址冲突。
    //    误归本码会把用户导向「断开其他 VPN」，而真正该做的是换端口。
    let port = fatal_line("listen tcp 127.0.0.1:7890: bind: address already in use");
    assert_eq!(
        classify_core_fatal_line(&port, singbox_line_level(&port)),
        None
    );
    // 2) TUN 配置里**别的**步骤失败（MTU）→ 不是地址轴。
    let mtu = fatal_line("configure tun interface: set mtu: invalid argument");
    assert_eq!(
        classify_core_fatal_line(&mtu, singbox_line_level(&mtu)),
        None
    );
    // 3) 级别门：正常 INFO 行里出现同样的词（回放/引用）不算真因。
    let info = "+0800 INFO configure tun interface: set ipv4 address ok";
    assert_eq!(
        classify_core_fatal_line(info, singbox_line_level(info)),
        None
    );
}

#[test]
fn scan_core_fatal_takes_first_hit_in_block() {
    let block = format!(
        "+0800 INFO router: loaded rule-set\n{}\n+0800 FATAL sing-box did not close!\n",
        fatal_line("configure tun interface: set ipv4 address: The object already exists.")
    );
    assert_eq!(
        scan_core_fatal(&block),
        Some(CoreFatalKind::TunAddressUnavailable)
    );
    // 无命中 → None（绝不因为「有 FATAL」就瞎归类）。
    assert_eq!(
        scan_core_fatal("+0800 FATAL start service: create service: bad json"),
        None
    );
}

#[test]
fn startup_log_cursor_distinguishes_append_from_fresh_rotation() {
    let cursor = StartupLogCursor {
        offset: 128,
        identity: Some(7),
    };
    assert_eq!(
        startup_log_read_start(cursor, 256, Some(7)),
        128,
        "旧 helper 在同一文件 append：只读本腿新增部分"
    );
    assert_eq!(
        startup_log_read_start(cursor, 512, Some(8)),
        0,
        "新 helper fresh-rotate：即使新文件更长也必须从头读"
    );
    assert_eq!(
        startup_log_read_start(cursor, 64, Some(7)),
        0,
        "同一身份但长度缩短时不能 seek 越过本腿日志"
    );
    assert_eq!(
        startup_log_read_start(StartupLogCursor::default(), 64, Some(8)),
        0,
        "起核前没有 current 文件时整份都属于本腿"
    );
}

#[test]
fn settle_start_failure_swaps_generic_code_only_when_cause_is_known() {
    // 有真因 → 专属码 + 专属文案（症状串被整句替换，见该函数文档）。
    let (msg, code_out) = settle_start_failure(
        "sing-box 起核超时（管理 API 9090 在 12000ms 内未就绪）".to_string(),
        Some(CoreFatalKind::TunAddressUnavailable),
    );
    assert_eq!(code_out, code::TUN_ADDRESS_UNAVAILABLE);
    assert_eq!(msg, TUN_ADDRESS_UNAVAILABLE_MSG);
    // 无真因 → 逐字维持原有行为（本条是回归锁：拿不到真因时不许改动既有的失败面）。
    let (msg, code_out) = settle_start_failure("sing-box 启动期退出".to_string(), None);
    assert_eq!(code_out, code::STARTUP_FAILED);
    assert_eq!(msg, "sing-box 启动期退出");
}

/// **接线守卫**：起核失败的两条终态腿（Dead / Timeout）都必须经 [`settle_start_failure`] 收口。
///
/// 漏一条 = 那条腿上的真因永远上不了屏，而它与另一条腿的差别只是「就绪门先超时还是进程先没」
/// —— 用户视角完全同一件事。行为测试够不着（真起核 + 真地址冲突 = 真机门）。
#[test]
fn core_fatal_is_wired_into_both_terminal_start_legs() {
    let body = method_body(
        &module_code("runtime/proxy"),
        "    pub(super) async fn start_inner(",
    );
    assert_eq!(
        body.matches("settle_start_failure(").count(),
        2,
        "起核终态收口必须恰好两处（Dead / Timeout 各一）；少了 = 有腿绕过真因判定，\
             多了 = 收口点被复制"
    );
    assert_eq!(
        body.matches("self.observe_core_fatal(").count(),
        2,
        "两条腿各自读一次本腿的 stderr 真因；共用一次读会跨腿错配"
    );
    // 判据打在**去掉全部空白**的形上：接线已经搬进 `SpawnRequest` 的排空回调里，缩进随
    // 闭包层级而变，钉死缩进的断言会因为一次 `cargo fmt` 就失去判据（而失去判据的门是绿的）。
    let compact: String = body.split_whitespace().collect();
    assert!(
        compact.contains("StdioPolicy::drain("),
        "主核必须选 `Drain` 策略：换成 `Discard` 一样编得过，代价是核的输出被内核整段丢弃，\
         起核期的 FATAL 与真因分类一起消失"
    );
    // stderr 才接真因槽（stdout 传 None）——写反了等于永远收不到 FATAL。
    assert!(
        compact.contains("pipe_to_log(stderr,SING_BOX_TARGET,Some(sink_fatal),"),
        "真因槽必须接在 stderr 上（sing-box 的 log.Fatal 恒写 os.Stderr）"
    );
    assert!(
        compact.contains("pipe_to_log(stdout,SING_BOX_TARGET,None,"),
        "stdout 不接真因槽（白扫每一行）"
    );
    assert_eq!(
        compact.matches("pipe_to_log(").count(),
        2,
        "两条流各接一次：少接一条，那条管道的读端一关，核对它的写就拿到 EPIPE，诊断静默消失"
    );
}

// ══════════════════════════════════════════════════════════════════════════════
// event:proxy:invalid-nodes 发射（#1：起核 gate 剔除的非法节点推给渲染端）
// ══════════════════════════════════════════════════════════════════════════════

/// 组合面（**两半接线**）：真 `start` 路径 → 生成 gate 报告 → `emit_invalid_nodes` 真被调。
///
/// **不起真核**：`POLARIS_SINGBOX_PATH` 指向 temp **目录**（非文件）→ `resolve_core_binary`
/// `is_file()` 判否即 Err。而 emit 发生在 **resolve/spawn 之前**（generate 之后立刻发）→ 起核尚未
/// 发生就已发过事件，本机零进程零网络。
///
/// 用 detour 级联无效配置（naive 缺 cronet 被丢 → 链到它的 ss 死引用被剔）：test dir 无
/// libcronet.so → `has_cronet=false` 自然成立 → 报告非空。
///
/// **变异锁**：删掉 `start_inner` 里 `self.emit_invalid_nodes(&outcome.invalid_nodes)` → 零帧 → 转红。
// 跨 await 持 `ENV_LOCK`：**有意为之**。current-thread test runtime（futures 不要求 Send），锁只为
// 把「set POLARIS_SINGBOX_PATH → 跑 start → unset」这段对并行测试串行化，无死锁面（唯一持有者）。
// 本测试用「naive 缺 libcronet → 生成期剔除 → 级联剔 detour 引用方 ch」造无效节点。macOS 的
// sing-box 把 cronet **静态编入**二进制（见 `cronet_available` 注释），naive 恒可用 → nv 不被剔、
// 无级联、frame 为空，该场景在 mac 根本不成立（是 mac 正确行为，非 bug）。emit 接线本身平台无关，
// 由 ubuntu/windows 两 leg 覆盖；无其它平台无关的「造无效节点」原语（endpoint 不能作 detour 目标、
// detour 指向不存在 id 不剔节点），故本测试 gate 掉 macOS。
#[cfg(not(target_os = "macos"))]
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn start_emits_invalid_nodes_on_real_start_path() {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let clearer: Box<dyn SystemProxyClearer> = Box::new(RecordingClearer {
        calls: Arc::clone(&calls),
    });
    let (rt, dir, frames, _residual) = test_runtime_recording_full(clearer);
    rt.stale_sweep_disabled.store(true, Ordering::SeqCst); // 跳过 /proc 孤儿清扫

    // 选中节点合法（vless+tls）→ 生成成功；naive(缺 cronet 被丢) + ss detour→naive（死引用被剔）。
    let config = serde_json::json!({
        "servers": [
            { "id": "sel", "name": "SEL", "protocol": "vless",
              "address": "sel.example.com", "port": 443, "uuid": "u", "security": "tls" },
            { "id": "nv", "name": "NAIVE", "protocol": "naive",
              "address": "nv.example.com", "port": 443, "naiveSettings": {} },
            { "id": "ch", "name": "CHAINED", "protocol": "shadowsocks",
              "address": "ch.example.com", "port": 8388, "detour": "nv",
              "shadowsocksSettings": { "method": "aes-256-gcm", "password": "p" } }
        ],
        "selectedServerId": "sel",
        "proxyMode": "smart",
        "proxyModeType": "systemProxy"
    });

    // env 串行化（与 temp_env_var 共用 ENV_LOCK）：POLARIS_SINGBOX_PATH → 目录 → resolve 必 Err。
    // current-thread test runtime，std MutexGuard 跨 await 不要求 Send。
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("POLARIS_SINGBOX_PATH", &*dir);
    let r = rt.start(config).await;
    std::env::remove_var("POLARIS_SINGBOX_PATH");
    drop(_g);

    assert!(
        r.is_err(),
        "核二进制解析失败 → 起核失败（但 emit 早已发生）"
    );
    let got = frames.lock().unwrap().clone();
    assert_eq!(got.len(), 1, "起核路径必发且仅发一帧 invalid-nodes");
    // 该帧含被级联剔除的 ch，带 detour-cascade 原因（真值端到端穿过 runtime）。
    let frame = &got[0];
    assert!(
        frame.iter().any(|n| n.id == "ch"
            && n.reason
                == polaris_config_engine::builder::outbounds::INVALID_REASON_DETOUR_CASCADE),
        "帧内应含级联剔除的 ch（真值贯穿 config-engine→runtime→emitter），实得 {frame:?}"
    );
}

/// 方法级：`emit_invalid_nodes` 把非空列表原样路由到 emitter（帧内容 = 传入内容）。
/// 变异锁：把 `emit_invalid_nodes` 里的 `e.emit_invalid_nodes(nodes)` 改成传 `&[]` → 转红。
#[test]
fn emit_invalid_nodes_routes_payload_to_emitter() {
    let clearer: Box<dyn SystemProxyClearer> = Box::new(RecordingClearer {
        calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    });
    let (rt, _dir, frames, _r) = test_runtime_recording_full(clearer);
    let nodes = vec![InvalidNode {
        id: "x".into(),
        tag: "节点X".into(),
        reason: "detour-cascade".into(),
    }];
    rt.emit_invalid_nodes(&nodes);
    let got = frames.lock().unwrap().clone();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0], nodes, "payload 必须原样送达，不截断不改形");
}

// ══════════════════════════════════════════════════════════════════════════════
// 出口自证：「实际生效出口 == 选中节点」
//
// 判据是**纯静态**的（核实际启动的那份 sing-box config vs 用户落盘意图），故**全部可本机断言**，
// 无需起核、不碰网络——这正是选静态对账而非探针的第二个收益（探针路径根本没法在 gate 里验）。
// ══════════════════════════════════════════════════════════════════════════════

/// 造 sing-box config：`route.final` = `final_tag`；有 `selector_default` 则装 proxy-selector。
fn singbox_fixture(final_tag: &str, selector_default: Option<&str>) -> SingBoxConfig {
    let mut outbounds = vec![
        serde_json::json!({ "type": "direct", "tag": "direct" }),
        serde_json::json!({ "type": "shadowsocks", "tag": "HK01" }),
        serde_json::json!({ "type": "shadowsocks", "tag": "JP01" }),
    ];
    if let Some(d) = selector_default {
        outbounds.push(serde_json::json!({
            "type": "selector", "tag": PROXY_SELECTOR_TAG,
            "outbounds": ["HK01", "JP01", "direct"], "default": d
        }));
    }
    serde_json::from_value(serde_json::json!({
        "log": { "level": "info", "timestamp": true },
        "inbounds": [],
        "outbounds": outbounds,
        "route": { "rules": [], "final": final_tag }
    }))
    .expect("fixture sing-box config 应可解析")
}

/// 造 UserConfig：两个节点（HK01/JP01），选中 `selected`。
fn exit_user_config(selected: &str) -> UserConfig {
    serde_json::from_value(serde_json::json!({
        "servers": [
            { "id": "n-hk", "name": "HK01", "protocol": "shadowsocks",
              "address": "1.2.3.4", "port": 8388 },
            { "id": "n-jp", "name": "JP01", "protocol": "shadowsocks",
              "address": "5.6.7.8", "port": 8388 }
        ],
        "selectedServerId": selected,
        "proxyMode": "smart",
        "proxyModeType": "systemProxy"
    }))
    .expect("fixture UserConfig 应可解析")
}

/// 健康形态：选中 HK01 + selector default=HK01 → 自证通过。
/// 变异锁：把 `Match` 腿改成恒告警 → 转红（假阳性会让告警整体失信）。
#[test]
fn attest_match_when_selector_default_is_selected_node() {
    let got = attest_effective_exit(
        &exit_user_config("n-hk"),
        &singbox_fixture(PROXY_SELECTOR_TAG, Some("HK01")),
        Some("n-hk"),
    );
    assert_eq!(got, ExitAttestation::Match);
}

/// **本 bug 的核心形态**：选中真实节点，selector 却降级到 direct → 明文直连，必须判 SilentDirect。
/// 变异锁：把 `actual == DIRECT_TAG` 腿删掉（落进 WrongExit）→ 转红（丢掉「未加密」这一最高危语义）。
#[test]
fn attest_silent_direct_when_selector_defaults_to_direct() {
    let got = attest_effective_exit(
        &exit_user_config("n-hk"),
        &singbox_fixture(PROXY_SELECTOR_TAG, Some(DIRECT_TAG)),
        Some("n-hk"),
    );
    assert_eq!(
        got,
        ExitAttestation::SilentDirect {
            expected_tag: "HK01".into()
        }
    );
    assert!(
        got.user_message().contains("直连") && got.user_message().contains("未加密"),
        "文案必须点明「未加密」，这是用户唯一在意的事实：{}",
        got.user_message()
    );
}

/// `route.final=direct`（mesh 出口回落 / outbounds 兜底等路径）→ 同样是明文直连。
/// 变异锁：只查 selector default、不解 `route.final` → 本测转红（漏掉整条 final 轴）。
#[test]
fn attest_silent_direct_when_route_final_is_direct() {
    let got = attest_effective_exit(
        &exit_user_config("n-hk"),
        &singbox_fixture(DIRECT_TAG, Some("HK01")),
        Some("n-hk"),
    );
    assert_eq!(
        got,
        ExitAttestation::SilentDirect {
            expected_tag: "HK01".into()
        },
        "final=direct 时 selector 里装的是谁都无关——流量根本不经 selector"
    );
}

/// 走错节点（selector default 指向另一个节点）→ WrongExit（仍加密，但不是用户选的出口）。
#[test]
fn attest_wrong_exit_when_selector_points_to_other_node() {
    let got = attest_effective_exit(
        &exit_user_config("n-hk"),
        &singbox_fixture(PROXY_SELECTOR_TAG, Some("JP01")),
        Some("n-hk"),
    );
    assert_eq!(
        got,
        ExitAttestation::WrongExit {
            expected_tag: "HK01".into(),
            actual_tag: "JP01".into()
        }
    );
}

/// **前端竞态（S4）真机现象的静态复现**：落盘意图 = HK01，起核却用了 `__direct__` 旧值。
/// 此腿下 config 内部完全自洽（selector default 确是 direct），只有与落盘意图对账才能拆穿 →
/// 变异锁：删掉 persisted 对账腿 → 落进 `Match`（因为 `is_direct_selection` 放行）→ 转红。
/// 这正是「配置自洽于一个错的意图」的假绿，是本 bug 最难抓的一条。
#[test]
fn attest_stale_selection_when_renderer_passed_old_direct_sentinel() {
    let mut cfg = exit_user_config("n-hk");
    cfg.selected_server_id = Some(DIRECT_SERVER_ID.to_string()); // 渲染端传来的陈旧快照
    let got = attest_effective_exit(&cfg, &singbox_fixture(DIRECT_TAG, None), Some("n-hk"));
    assert_eq!(
        got,
        ExitAttestation::StaleSelection {
            persisted: "n-hk".into(),
            started_with: DIRECT_SERVER_ID.into()
        }
    );
}

/// 用户**自己**选了直连 → 出口是 direct 本就正确，不得告警。
/// 变异锁：删 `is_direct_selection` 放行腿 → 转红（对用户自选直连天天误报）。
#[test]
fn attest_match_when_user_selected_direct() {
    let got = attest_effective_exit(
        &exit_user_config(DIRECT_SERVER_ID),
        &singbox_fixture(DIRECT_TAG, None),
        Some(DIRECT_SERVER_ID),
    );
    assert_eq!(got, ExitAttestation::Match);
}

/// 设计语义放行①：`proxyMode=direct`（全直连模式）→ final=direct 是用户选的，不告警。
/// 变异锁：删门① → 转红。
#[test]
fn attest_match_for_direct_proxy_mode() {
    let mut cfg = exit_user_config("n-hk");
    cfg.proxy_mode = ProxyMode::Direct;
    let got = attest_effective_exit(&cfg, &singbox_fixture(DIRECT_TAG, None), Some("n-hk"));
    assert_eq!(got, ExitAttestation::Match);
}

/// 造带 `route.rule_set` 定义的 fixture（tags = 已注入的 rule_set tag）。
fn singbox_fixture_with_rule_sets(final_tag: &str, tags: &[&str]) -> SingBoxConfig {
    let rule_sets: Vec<serde_json::Value> = tags
        .iter()
        .map(|t| {
            serde_json::json!({
                "tag": t, "type": "local", "format": "binary",
                "path": format!("/fake/rules/{t}.srs")
            })
        })
        .collect();
    serde_json::from_value(serde_json::json!({
        "log": { "level": "info", "timestamp": true },
        "inbounds": [],
        "outbounds": [
            { "type": "direct", "tag": "direct" },
            { "type": "shadowsocks", "tag": "HK01" },
            { "type": "shadowsocks", "tag": "JP01" }
        ],
        "route": { "rules": [], "final": final_tag, "rule_set": rule_sets }
    }))
    .expect("fixture sing-box config 应可解析")
}

/// 造 smart + 回国（reverse）的 UserConfig。
fn reverse_cn_user_config(selected: &str) -> UserConfig {
    let mut cfg = exit_user_config(selected);
    cfg.region_routing = Some(
        serde_json::from_value(serde_json::json!({
            "enabled": true, "region": "cn", "reverse": true
        }))
        .expect("region fixture 应可解析"),
    );
    cfg
}

/// 设计语义放行②：smart + 地区反向（回国：海外直连）**且规则集完整** → final=direct 是设计语义，不告警。
/// 变异锁：删门② → 转红（回国模式每次起核都误报）。
#[test]
fn attest_match_for_smart_region_reverse() {
    // 回国模式的「→代理」腿（geosite-cn / geoip-cn）rule_set 定义俱在 = 规则集完整。
    let cfg = reverse_cn_user_config("n-hk");
    let sb = singbox_fixture_with_rule_sets(DIRECT_TAG, &["geosite-cn", "geoip-cn"]);
    assert_eq!(
        attest_effective_exit(&cfg, &sb, Some("n-hk")),
        ExitAttestation::Match
    );
    // 反向关掉 → 同一份 config 必须重新告警（证明放行是 `reverse` 驱动、不是恒放行）。
    let mut off = cfg.clone();
    off.region_routing.as_mut().unwrap().reverse = false;
    assert!(
        matches!(
            attest_effective_exit(&off, &sb, Some("n-hk")),
            ExitAttestation::SilentDirect { .. }
        ),
        "reverse=false 时 final=direct 就是真降级，必须告警"
    );
}

/// **门② 收紧（T4）**：reverse **但规则集缺失** → 回国模式已退化成全量明文直连，是真故障，
/// **不得**被白名单放行。这正是真机 2026-07-20「零告警 + 日志还打『出口自证通过』」的成因。
///
/// ⚠️ **按构造不可达（与 M2 同类）**：本用例喂的是**手工构造**的 config。生产链路上同场景会先被
/// `builder/route.rs` 的 T2 fail-safe 把 `final` 翻成 `proxy-selector`，走不到这条腿——详见
/// `attest_effective_exit` 门② 上方的「不可达性登记」。保留理由是 defense-in-depth，
/// **不是**「真机能复现」。别据此写真机验收门。
///
/// 变异锁：删 `region_reverse_rule_sets_intact` 前置条件（退回旧的「只看 reverse」粒度）→ 转红。
#[test]
fn attest_mismatch_for_reverse_with_missing_rule_sets() {
    let cfg = reverse_cn_user_config("n-hk");
    // rule_set 全缺（真机现场：磁盘零 .srs → 一个都没注入）。
    let sb_none = singbox_fixture_with_rule_sets(DIRECT_TAG, &[]);
    assert!(
        matches!(
            attest_effective_exit(&cfg, &sb_none, Some("n-hk")),
            ExitAttestation::SilentDirect { .. }
        ),
        "规则集全缺 + reverse + final=direct = 全量明文直连，必须告警而非放行"
    );

    // **部分缺失同样不放行**：只剩 geosite-cn，geoip-cn 没了 → 国内 IP 段不再回国。
    let sb_partial = singbox_fixture_with_rule_sets(DIRECT_TAG, &["geosite-cn"]);
    assert!(
        matches!(
            attest_effective_exit(&cfg, &sb_partial, Some("n-hk")),
            ExitAttestation::SilentDirect { .. }
        ),
        "回国的两条 →代理 腿缺任意一条都算不完整（变异：把 all() 写成 any() → 此断言转红）"
    );
}

/// 门② 前置谓词自身的边界：越界 region（手改 JSON）→ 判不准 → **不放行**（fail-safe）。
/// 变异锁：把 `region_local_geo` 返 None 的腿改成 `true` → 转红。
#[test]
fn reverse_rule_sets_intact_is_false_for_unknown_region() {
    let mut cfg = exit_user_config("n-hk");
    cfg.region_routing = Some(
        serde_json::from_value(serde_json::json!({
            "enabled": true, "region": "atlantis", "reverse": true
        }))
        .expect("region fixture 应可解析"),
    );
    // 即便 rule_set 里塞满 CN 三件套，未知 region 也解不出「该有哪些腿」→ 判定不完整。
    let sb = singbox_fixture_with_rule_sets(DIRECT_TAG, &["geosite-cn", "geoip-cn"]);
    assert!(!region_reverse_rule_sets_intact(&cfg, &sb));
    assert!(
        matches!(
            attest_effective_exit(&cfg, &sb, Some("n-hk")),
            ExitAttestation::SilentDirect { .. }
        ),
        "判不准就告警，不静默放行"
    );
}

/// 造「选中的组网节点」config：WireGuard（有内网段）+ `allowInternet` 三态，或 OpenVPN
/// （`meshRoutes` 非空）+ `redirectGateway` 三态。选中即该节点。
fn mesh_exit_user_config(
    protocol: polaris_config_engine::user_config::server_config::Protocol,
    carries_full_tunnel: Option<bool>,
) -> UserConfig {
    use polaris_config_engine::user_config::protocol_settings::OpenvpnClientSettings;
    use polaris_config_engine::user_config::server_config::{Protocol, WireGuardSettings};

    let mut server = ServerConfig {
        id: "n-mesh".into(),
        name: "MESH01".into(),
        protocol,
        address: "1.2.3.4".into(),
        port: 51820,
        ..Default::default()
    };
    match protocol {
        Protocol::Wireguard => {
            server.wireguard_settings = Some(Box::new(WireGuardSettings {
                allowed_ips: vec!["10.9.0.0/24".into()],
                allow_internet: carries_full_tunnel,
                ..Default::default()
            }));
        }
        _ => {
            // OpenVPN 的组网资格由 `meshRoutes` 非空决定（`is_mesh_node`），出网开关是 redirectGateway。
            server.mesh_routes = vec!["10.1.0.0/24".into()];
            server.openvpn_client_settings = Some(Box::new(OpenvpnClientSettings {
                redirect_gateway: carries_full_tunnel,
                ..Default::default()
            }));
        }
    }
    // `proxyMode` 显式钉 smart：门① 放行的是 direct 模式，若靠默认值就等于把本测的前置条件
    // 交给 `UserConfig::default()` 保管 —— 默认值哪天改成 direct，本测会静默退化成恒绿。
    let mut config = UserConfig {
        selected_server_id: Some("n-mesh".into()),
        proxy_mode: polaris_config_engine::user_config::proxy_mode::ProxyMode::Smart,
        ..Default::default()
    };
    config.servers.push(server);
    config
}

/// **门③（§6.1 的假警报）**：选中的组网节点关外网 → `route.final=direct` 是 `builder/route.rs`
/// 的 D4/D7 出口兜底（`user_exit_tag` 整体回退 direct），是**设计语义**，不是「流量未按预期经代理」。
///
/// 没有这道门：兜底态下 `effective_exit_tag` 解到 `direct` ⇒ `SilentDirect` ⇒
/// `set_nonfatal_error(EXIT_MISMATCH)` ⇒ 用户每次起核都收到 toast.warning + 桌面通知。告警一旦有假
/// 就会被整体无视（同门①②的取舍）。
///
/// 判据与 route 侧兜底**共用同一个谓词** `mesh_selected_exit_falls_back_to_direct`，天然单一真源。
/// 本测**分开断言**谓词与自证结论：谓词若被改窄（如退回 2026-09 前的协议字面量白名单），第一条
/// 直接转红，不必靠第二条的间接效应去猜。
///
/// OpenVPN 那格是 Fix 0 扩面后新进兜底的（`meshRoutes` 非空 + 显式关 `redirectGateway`），
/// 与 WireGuard 同轨覆盖。
///
/// **负向对照**（同一份 config 只翻出网开关）：承载全隧道的组网节点若 `final=direct`，那是真降级，
/// 必须照旧 `SilentDirect` —— 证明放行是判据驱动、不是「见 endpoint 协议就放行」。
///
/// 变异锁：删掉门③ → 前两条断言转红；把门③改成无条件 `Match` → 后两条负向对照转红。
#[test]
fn attest_match_when_mesh_selected_exit_falls_back_to_direct() {
    use polaris_config_engine::builder::route::mesh_selected_exit_falls_back_to_direct;

    use polaris_config_engine::user_config::server_config::Protocol;

    for protocol in [Protocol::Wireguard, Protocol::OpenvpnClient] {
        // 关外网 ⇒ 兜底态：谓词为真，自证必须放行。
        let off = mesh_exit_user_config(protocol, Some(false));
        assert!(
            mesh_selected_exit_falls_back_to_direct(&off),
            "{protocol:?}：关外网的组网节点必须命中 route 侧兜底谓词（谓词被改窄即此处转红）"
        );
        assert_eq!(
            attest_effective_exit(&off, &singbox_fixture(DIRECT_TAG, None), Some("n-mesh")),
            ExitAttestation::Match,
            "{protocol:?}：兜底态的 final=direct 是设计语义，不得报 EXIT_MISMATCH"
        );

        // 负向对照：同一份 config 只把出网开关翻回 true ⇒ 不兜底，final=direct 就是真降级。
        let on = mesh_exit_user_config(protocol, Some(true));
        assert!(!mesh_selected_exit_falls_back_to_direct(&on));
        assert!(
            matches!(
                attest_effective_exit(&on, &singbox_fixture(DIRECT_TAG, None), Some("n-mesh")),
                ExitAttestation::SilentDirect { .. }
            ),
            "{protocol:?}：承载全隧道的组网节点走 direct 是真降级，必须照旧告警"
        );
    }
}

/// **自动换节点停摆守卫的接线门**：起核处必须把 `auto_switch_blocked_for_generation` 的结论作为
/// 世代常量传给心跳。
///
/// # 为什么只能是源码型判据
///
/// 判据侧（`auto_switch_blocked_for_generation`）与消费侧（`decide_tick`）各有真值表，但**两扇门
/// 之间的那条缝**——起核处到底有没有把前者的结论喂给后者——没有任何行为断言够得着：心跳体是
/// `tokio::spawn` + 30s sleep，测试驱动不了它。把调用点的第三个实参改成 `false`，那两张真值表
/// **照样全绿**，而生产上守卫等于不存在。这正是「门在但没牙」的形态。
///
/// # 双向断言
///
/// 正面钉实参形态（防改成 `None` 或改成读别的来源）；同时钉住**调用点恰好一处** —— 将来新增第二个
/// 接线点时本门必须转红（否则新那处漏传守卫，本门读到的还是老那处，绿得毫无意义）。
///
/// 取材走 [`module_code`]（剥注释）：判据是全文正面 `contains`，不剥注释的话本条门文里写的这段
/// 实参文本自己就能让它恒绿。
///
/// **变异锁**：把 `startup.rs` 调用点的第三个实参改成 `false` → 转红；
/// 新增一个 `self.spawn_auto_switch_heartbeat(` 调用点 → 转红。
#[test]
fn auto_switch_heartbeat_is_wired_with_the_generation_blocked_guard() {
    let src = crate::test_support::module_code("runtime/proxy");
    const CALL: &str = "self.spawn_auto_switch_heartbeat(";
    assert_eq!(
        src.matches(CALL).count(),
        1,
        "心跳接线点应恰好一处；新增接线点必须同步补传停摆判据，并更新本门"
    );
    let after = src.split(CALL).nth(1).expect("起核处必须有心跳接线");
    let args = &after[..after.find(");").expect("接线调用应闭合")];
    assert!(
        args.contains("auto_switch_blocked_for_generation(&user_config)"),
        "心跳必须收到起核这份 config 求得的停摆判据（世代常量），实得实参：{args}"
    );
}

/// 无 `route.final` → 解不出出口 = 无法自证 → 按「不确定即告警」处理，不静默放行。
/// 变异锁：把 `None` 腿改成 `Match` → 转红（「解不出」被当成「没问题」是最典型的假绿）。
#[test]
fn attest_unresolved_when_no_route_final() {
    let sb: SingBoxConfig = serde_json::from_value(serde_json::json!({
        "log": { "level": "info", "timestamp": true },
        "inbounds": [],
        "outbounds": [{ "type": "direct", "tag": "direct" }],
        "route": { "rules": [] }
    }))
    .expect("无 final 的 fixture 应可解析");
    assert_eq!(
        attest_effective_exit(&exit_user_config("n-hk"), &sb, Some("n-hk")),
        ExitAttestation::UnresolvedExit {
            expected_tag: "HK01".into()
        }
    );
}

/// 选中 id 不在节点表 → UnknownSelection（兜底可见性，不静默）。
#[test]
fn attest_unknown_selection_for_missing_id() {
    let mut cfg = exit_user_config("n-hk");
    cfg.selected_server_id = Some("ghost".into());
    assert_eq!(
        attest_effective_exit(
            &cfg,
            &singbox_fixture(PROXY_SELECTOR_TAG, Some("HK01")),
            None
        ),
        ExitAttestation::UnknownSelection {
            selected_id: "ghost".into()
        }
    );
}

/// 落盘「用户已提交的选中意图」。**基于 `current()` 的真实默认配置改**（而非手搓最小 JSON）——
/// `save_full` 会跑完整 sanitize+validate，手搓必缺字段；基于默认配置改也更贴近真实落盘形态。
fn persist_selection(rt: &ProxyRuntime, selected_id: &str) {
    let mut cfg = rt.config.current().expect("默认配置应可读");
    cfg["servers"] = serde_json::json!([
        { "id": "n-hk", "name": "HK01", "protocol": "shadowsocks",
          "address": "1.2.3.4", "port": 8388 }
    ]);
    cfg["selectedServerId"] = serde_json::json!(selected_id);
    rt.config.save_full(&cfg).expect("落盘测试配置应成功");
}

/// **组合路径**：不一致 → `attest_selected_exit` 真 emit `event:proxyError`（EXIT_MISMATCH），
/// 且**不把核标成未运行**（核确在跑）。§K7.1：光测纯函数、光测 emit 都不够，要测组合。
/// 变异锁：把 `attest_selected_exit` 的告警腿改成 `log::warn!` → 零事件 → 转红（退回静默）。
#[tokio::test]
async fn attest_selected_exit_emits_and_keeps_running() {
    let (rt, _dir, events) =
        test_runtime_errors_with_clearer(Box::new(EnableRecordingClearer::default()));
    mark_running(&rt);
    // 落盘意图 = n-hk（用户点过的那一下）。
    persist_selection(&rt, "n-hk");
    // 核实际起来的配置：selector 降级到 direct → 明文直连。
    rt.attest_selected_exit(
        &exit_user_config("n-hk"),
        &singbox_fixture(PROXY_SELECTOR_TAG, Some(DIRECT_TAG)),
    );
    let got = events.lock().unwrap().clone();
    assert_eq!(
        got.len(),
        1,
        "出口不一致必须发一条 proxyError，实得 {got:?}"
    );
    assert_eq!(got[0].1, code::EXIT_MISMATCH);
    assert!(rt.status().running, "核确在跑 → 不得标成未运行");
    assert_eq!(rt.status().error_code.as_deref(), Some(code::EXIT_MISMATCH));
}

/// 一致 → **零告警**（假阳性会让整条告警通道失信）。
/// 变异锁：把告警改成无条件发 → 转红。
#[tokio::test]
async fn attest_selected_exit_silent_when_consistent() {
    let (rt, _dir, events) =
        test_runtime_errors_with_clearer(Box::new(EnableRecordingClearer::default()));
    mark_running(&rt);
    persist_selection(&rt, "n-hk");
    rt.attest_selected_exit(
        &exit_user_config("n-hk"),
        &singbox_fixture(PROXY_SELECTOR_TAG, Some("HK01")),
    );
    assert!(
        events.lock().unwrap().is_empty(),
        "出口一致不得告警，实得 {:?}",
        events.lock().unwrap()
    );
    assert!(rt.status().error_code.is_none(), "一致时不得落错误码");
}

/// **T3 组合路径**：规则集被剪枝 → 真 emit `event:proxyError`（`RULE_RESOURCES_MISSING`），
/// 且**不把核标成未运行**（核确在跑，只是分流退化）。
/// 变异锁：把 `warn_pruned_rule_resources` 的告警腿改成 `log::warn!` → 零事件 → 转红（退回静默）。
#[tokio::test]
async fn pruned_rule_resources_emit_and_keep_running() {
    let (rt, _dir, events) =
        test_runtime_errors_with_clearer(Box::new(EnableRecordingClearer::default()));
    mark_running(&rt);

    rt.warn_pruned_rule_resources(&["geosite-cn".to_string(), "geoip-cn".to_string()]);

    let got = events.lock().unwrap().clone();
    assert_eq!(
        got.len(),
        1,
        "规则被剪枝必须发一条 proxyError，实得 {got:?}"
    );
    assert_eq!(got[0].1, code::RULE_RESOURCES_MISSING);
    assert!(
        got[0].0.contains("geosite-cn"),
        "文案应点名缺失的资源：{}",
        got[0].0
    );
    assert!(rt.status().running, "核确在跑 → 不得标成未运行");
    assert_eq!(
        rt.status().error_code.as_deref(),
        Some(code::RULE_RESOURCES_MISSING)
    );
}

/// 资源齐全（剪枝清单为空）→ **零告警**。任务硬约束：「别在资源齐全时噪音」。
/// 变异锁：删 `if pruned.is_empty() { return; }` 早退 → 每次起核都弹一条空名单告警 → 转红。
#[tokio::test]
async fn intact_rule_resources_emit_nothing() {
    let (rt, _dir, events) =
        test_runtime_errors_with_clearer(Box::new(EnableRecordingClearer::default()));
    mark_running(&rt);

    rt.warn_pruned_rule_resources(&[]);

    assert!(
        events.lock().unwrap().is_empty(),
        "资源齐全不得告警，实得 {:?}",
        events.lock().unwrap()
    );
    assert!(rt.status().error_code.is_none(), "齐全时不得落错误码");
}

// ══════════════════════════════════════════════════════════════════════════════
// 起核前的内核闸门：内核点名的下标 → 该拿这个节点怎么办
//
// 判据全部纯静态（内核诊断行 + 我方生成的那份 config + id→tag 表），故**无需核、无需落盘、
// 不碰网络**即可全覆盖。诊断行的解析与三态映射另有门：`core-supervisor` 的
// `config_gate::tests`（纯解析）与 `tests/config_gate_process.rs`（真子进程接线）。
// ══════════════════════════════════════════════════════════════════════════════

/// 造闸门用的 config：`outbounds` = [direct, HK01, JP01, proxy-selector]，
/// `endpoints` = [WG01]。下标即数组下标 —— 内核给的就是这个坐标系。
fn gate_fixture() -> SingBoxConfig {
    serde_json::from_value(serde_json::json!({
        "log": { "level": "info", "timestamp": true },
        "inbounds": [],
        "outbounds": [
            { "type": "direct", "tag": "direct" },
            { "type": "shadowsocks", "tag": "HK01" },
            { "type": "shadowsocks", "tag": "JP01" },
            { "type": "selector", "tag": PROXY_SELECTOR_TAG,
              "outbounds": ["HK01", "JP01", "direct"], "default": "HK01" }
        ],
        "endpoints": [ { "type": "wireguard", "tag": "WG01" } ],
        "route": { "rules": [], "final": PROXY_SELECTOR_TAG }
    }))
    .expect("fixture sing-box config 应可解析")
}

/// tag → id 反表（`generate_and_gate` 里由 `build_id_to_tag_map` 现算的那一份的等价物）。
/// 注意内置出站（direct / proxy-selector）**不在表里** —— 它们不是节点。
fn gate_tag_to_id() -> BTreeMap<String, String> {
    [("HK01", "n-hk"), ("JP01", "n-jp"), ("WG01", "n-wg")]
        .into_iter()
        .map(|(t, i)| (t.to_string(), i.to_string()))
        .collect()
}

fn rejection(array: RejectedArray, index: usize) -> KernelRejection {
    KernelRejection {
        array,
        index,
        detail: "unknown outbound type: zzz".to_string(),
    }
}

/// 🔴 **变异锁：下标必须翻成对应节点，且 `outbounds[]` / `endpoints[]` 是两个独立坐标系**。
///
/// `outbounds[2]` = JP01、`endpoints[0]` = WG01 —— 两者下标都不是 0/2 的巧合：若把
/// `RejectedArray::Endpoints` 那一支错接到 `config.outbounds`，`endpoints[0]` 会翻成 `direct`
/// ⇒ 落 `Unattributable`，本条转红。
#[test]
fn kernel_index_maps_back_to_the_right_node_in_the_right_array() {
    let cfg = gate_fixture();
    let map = gate_tag_to_id();
    let peeled = BTreeSet::new();
    assert_eq!(
        classify_peel_target(
            &rejection(RejectedArray::Outbounds, 2),
            &cfg,
            &map,
            None,
            &peeled
        ),
        PeelTarget::Peel {
            id: "n-jp".into(),
            tag: "JP01".into()
        }
    );
    assert_eq!(
        classify_peel_target(
            &rejection(RejectedArray::Endpoints, 0),
            &cfg,
            &map,
            None,
            &peeled
        ),
        PeelTarget::Peel {
            id: "n-wg".into(),
            tag: "WG01".into()
        }
    );
}

/// 🔴 **变异锁：归因不到就绝不剥**（内置出站 / 下标越界 / 无 endpoints 数组）。
///
/// 错误归因会剥掉一个**本来能用**的节点，且用户完全无从察觉 —— 比不归因坏得多。
/// 变异：给 `attribute_rejected_node` 加一条「查不到就按 tag 当 id 用」的兜底 ⇒ 前两条断。
#[test]
fn non_node_or_out_of_range_index_is_never_attributed() {
    let cfg = gate_fixture();
    let map = gate_tag_to_id();
    let peeled = BTreeSet::new();
    for (array, index, why) in [
        (RejectedArray::Outbounds, 0, "direct 是内置出站，不是节点"),
        (
            RejectedArray::Outbounds,
            3,
            "proxy-selector 是内置出站，不是节点",
        ),
        (RejectedArray::Outbounds, 99, "下标越界"),
        (RejectedArray::Endpoints, 7, "endpoints 下标越界"),
    ] {
        assert_eq!(
            classify_peel_target(&rejection(array, index), &cfg, &map, None, &peeled),
            PeelTarget::Unattributable,
            "{why}"
        );
    }
    // 整个 endpoints 键缺席（绝大多数配置的常态）→ 同样归因不到，不得 panic。
    let mut no_ep = gate_fixture();
    no_ep.endpoints = None;
    assert_eq!(
        classify_peel_target(
            &rejection(RejectedArray::Endpoints, 0),
            &no_ep,
            &map,
            None,
            &peeled
        ),
        PeelTarget::Unattributable,
        "无 endpoints 数组时不得越界 panic，也不得错归因"
    );
}

/// 🔴 **变异锁：内核拒的若是用户选中的节点，必须落 `Blocked`，绝不静默剥掉**。
///
/// 剥了就等于替用户改出口，而「实际生效出口 ≠ 选中节点」在本仓是要专门告警的事故
/// （`code::EXIT_MISMATCH`）—— 闸门自己去制造它是自相矛盾。且真剥了下一轮 generate 会直接
/// 返回 `Selected server not found`，用户又拿到一句和现场无关的话。
///
/// 变异：删掉 `selected_server_id ==` 那一支（回到无差别剥）⇒ 本条断在 `Peel`。
#[test]
fn rejecting_the_selected_node_blocks_instead_of_silently_switching_exit() {
    let cfg = gate_fixture();
    let map = gate_tag_to_id();
    let peeled = BTreeSet::new();
    assert_eq!(
        classify_peel_target(
            &rejection(RejectedArray::Outbounds, 1),
            &cfg,
            &map,
            Some("n-hk"),
            &peeled
        ),
        PeelTarget::Blocked {
            id: "n-hk".into(),
            tag: "HK01".into()
        },
        "选中节点被拒 → 终态，不得改出口"
    );
    // 同一份现场，只是选中的是**别的**节点 → 照常剥（证明上面那条断的是「选中」这个条件本身，
    // 不是「HK01 这个节点」）。
    assert_eq!(
        classify_peel_target(
            &rejection(RejectedArray::Outbounds, 1),
            &cfg,
            &map,
            Some("n-jp"),
            &peeled
        ),
        PeelTarget::Peel {
            id: "n-hk".into(),
            tag: "HK01".into()
        }
    );
}

/// 🔴 **变异锁：判「是否选中」必须先于判「是否已剥过」**。
///
/// 顺序颠倒时，一个「既是选中节点、又已在集合里」的现场会落 `Stalled`（= 静默放行去 spawn，
/// 拿一份缺了选中节点的配置起核 ⇒ 出口跑到别的节点上，正是 `EXIT_MISMATCH` 要抓的那种事故），
/// 而不是落 `Blocked`。这条现场在真机上可达：选中节点在第 N 轮被剥后，用户改选中它。
#[test]
fn selected_check_precedes_stall_check() {
    let cfg = gate_fixture();
    let map = gate_tag_to_id();
    let peeled: BTreeSet<String> = ["n-hk".to_string()].into_iter().collect();
    assert_eq!(
        classify_peel_target(
            &rejection(RejectedArray::Outbounds, 1),
            &cfg,
            &map,
            Some("n-hk"),
            &peeled
        ),
        PeelTarget::Blocked {
            id: "n-hk".into(),
            tag: "HK01".into()
        },
        "既选中又已剥 → 必须是 Blocked（判序颠倒会落 Stalled，等于静默改出口）"
    );
}

/// 🔴 **变异锁：推进不变式 —— 已剥过却又被点名就停，不许原地打转**。
///
/// 这条比时间预算更根本：预算只封顶延迟，**终止**靠它。变异：删掉 `already_peeled.contains`
/// 那一支 ⇒ 本条断在 `Peel`，而生产上那意味着「剥了没生效 → 无限重生成 → 起核永远回不来」。
#[test]
fn already_peeled_node_named_again_stalls_the_loop() {
    let cfg = gate_fixture();
    let map = gate_tag_to_id();
    let peeled: BTreeSet<String> = ["n-jp".to_string()].into_iter().collect();
    assert_eq!(
        classify_peel_target(
            &rejection(RejectedArray::Outbounds, 2),
            &cfg,
            &map,
            None,
            &peeled
        ),
        PeelTarget::Stalled { tag: "JP01".into() }
    );
}

/// 两节点配置（选中 keep-me），供 `generate_and_gate` 的整环门用。
#[cfg(unix)]
fn gate_two_node_config() -> Value {
    serde_json::json!({
        "servers": [
            { "id": "n-bad", "name": "BAD", "protocol": "shadowsocks",
              "address": "1.2.3.4", "port": 8388, "method": "aes-256-gcm", "password": "p" },
            { "id": "n-keep", "name": "KEEP", "protocol": "shadowsocks",
              "address": "5.6.7.8", "port": 8388, "method": "aes-256-gcm", "password": "p" }
        ],
        "selectedServerId": "n-keep",
        "proxyMode": "global",
        "proxyModeType": "manual",  // 安全：不接管系统代理、不建 TUN
        "mixedPort": 17890,
    })
}

#[test]
fn kernel_gate_cache_normalizes_only_known_runtime_ports() {
    let original = serde_json::json!({
        "inbounds": [
            { "tag": "probe-in-0", "listen_port": 21001 },
            { "tag": "update-in", "listen_port": 21002 },
            { "tag": "mixed-in", "listen_port": 17890 }
        ],
        "services": [
            { "type": "api", "listen_port": 21003 },
            { "type": "other", "listen_port": 21004 }
        ],
        "dns": { "servers": [
            { "tag": "dns-node-race", "server_port": 21005 },
            { "tag": "dns-user", "server_port": 53 }
        ]},
        "secret": "stable-secret"
    });
    let mut different_runtime_ports = original.clone();
    different_runtime_ports["inbounds"][0]["listen_port"] = Value::from(31001);
    different_runtime_ports["inbounds"][1]["listen_port"] = Value::from(31002);
    different_runtime_ports["services"][0]["listen_port"] = Value::from(31003);
    different_runtime_ports["dns"]["servers"][0]["server_port"] = Value::from(31005);

    let mut normalized_original = original.clone();
    normalize_kernel_gate_config(&mut normalized_original);
    normalize_kernel_gate_config(&mut different_runtime_ports);
    assert_eq!(
        normalized_original, different_runtime_ports,
        "只有已知的每轮随机端口变化时应复用 check 结果"
    );

    let mut changed_mixed = original.clone();
    changed_mixed["inbounds"][2]["listen_port"] = Value::from(17891);
    let mut changed_secret = original;
    changed_secret["secret"] = Value::from("changed-secret");
    for (path, mut changed) in [
        ("用户 mixed 端口", changed_mixed),
        ("管理 API secret", changed_secret),
    ] {
        normalize_kernel_gate_config(&mut changed);
        assert_ne!(normalized_original, changed, "{path} 改变必须 cache miss");
    }
}

#[test]
fn kernel_gate_cache_round_trips_atomically_and_corruption_is_a_miss() {
    let dir = fresh_test_dir();
    let path = dir.join(KERNEL_GATE_CACHE_FILE);
    let record = KernelGateCacheRecord {
        schema: KERNEL_GATE_CACHE_SCHEMA,
        binary_path: dir.join("sing-box").to_string_lossy().into_owned(),
        binary_len: 42,
        binary_modified_ns: 123,
        config_sha256: "a".repeat(64),
    };
    persist_kernel_gate_cache(&path, &record).expect("原子落盘应成功");
    assert_eq!(load_kernel_gate_cache(&path), Some(record.clone()));

    std::fs::write(&path, b"{broken").unwrap();
    assert_eq!(
        load_kernel_gate_cache(&path),
        None,
        "损坏缓存必须 fail miss"
    );

    let mut stale = record;
    stale.schema += 1;
    std::fs::write(&path, serde_json::to_vec(&stale).unwrap()).unwrap();
    assert_eq!(
        load_kernel_gate_cache(&path),
        None,
        "旧 schema 必须 fail miss"
    );
}

#[test]
fn background_attestation_only_commits_to_the_same_running_generation_and_pid() {
    let running = ProxyStatus {
        running: true,
        pid: 4245,
        ..ProxyStatus::default()
    };
    assert!(attestation_commit_allowed(7, 7, &running, 4245));
    assert!(!attestation_commit_allowed(8, 7, &running, 4245));
    assert!(!attestation_commit_allowed(7, 7, &running, 4246));

    let stopped = ProxyStatus::default();
    assert!(!attestation_commit_allowed(7, 7, &stopped, 4245));
}

#[test]
fn protected_core_cache_requires_both_unchanged_payloads() {
    let dir = fresh_test_dir();
    let active_dir = dir.join("active");
    let protected_dir = dir.join("protected");
    std::fs::create_dir_all(&active_dir).unwrap();
    std::fs::create_dir_all(&protected_dir).unwrap();
    std::fs::write(active_dir.join("sing-box"), b"CORE").unwrap();
    std::fs::write(protected_dir.join("sing-box"), b"CORE").unwrap();

    let active = crate::runtime::core_promote::payload_stamp(&active_dir, "sing-box").unwrap();
    let protected =
        crate::runtime::core_promote::payload_stamp(&protected_dir, "sing-box").unwrap();
    let cached = ProtectedCoreCacheRecord {
        active: active.clone(),
        protected: protected.clone(),
    };
    assert!(protected_core_cache_hit(
        Some(&cached),
        &active,
        Some(&protected)
    ));
    assert!(!protected_core_cache_hit(Some(&cached), &active, None));

    std::fs::write(active_dir.join("libcronet.so"), b"CRONET").unwrap();
    let changed_active =
        crate::runtime::core_promote::payload_stamp(&active_dir, "sing-box").unwrap();
    assert!(!protected_core_cache_hit(
        Some(&cached),
        &changed_active,
        Some(&protected)
    ));
    let _ = std::fs::remove_dir_all(dir);
}

#[cfg(unix)]
#[tokio::test]
async fn accepted_kernel_config_cache_survives_runtime_restart_and_misses_on_structure_change() {
    let dir = fresh_test_dir();
    let (binary, counter) = write_fake_accepting_core(&dir);
    let cfg = gate_two_node_config();
    let user_config: UserConfig = serde_json::from_value(cfg.clone()).unwrap();
    let path = dir.join("gate-cache.json");

    let rt = test_runtime_in(dir.clone());
    let deps = rt.generate_deps(0, 0, 0, None, &[], &cfg);
    let mut peeled = BTreeMap::new();
    let first = rt
        .generate_and_gate(&user_config, &deps, &path, Some(&binary), &mut peeled)
        .await
        .unwrap();
    assert_eq!(first.checks_run, 1, "首次必须真跑 check");
    assert_eq!(std::fs::read_to_string(&counter).unwrap().trim(), "1");

    let second = rt
        .generate_and_gate(&user_config, &deps, &path, Some(&binary), &mut peeled)
        .await
        .unwrap();
    assert_eq!(second.checks_run, 0, "同运行时的相同核/配置应命中");
    assert_eq!(std::fs::read_to_string(&counter).unwrap().trim(), "1");
    drop(deps);
    drop(rt);

    let restarted = test_runtime_in(dir.clone());
    let restarted_deps = restarted.generate_deps(0, 0, 0, None, &[], &cfg);
    let after_restart = restarted
        .generate_and_gate(
            &user_config,
            &restarted_deps,
            &path,
            Some(&binary),
            &mut peeled,
        )
        .await
        .unwrap();
    assert_eq!(
        after_restart.checks_run, 0,
        "app 重启后应从持久缓存命中，否则 Windows 首次连接仍白付约 2s"
    );

    use std::io::Write as _;
    std::fs::OpenOptions::new()
        .append(true)
        .open(&binary)
        .unwrap()
        .write_all(b"# changed kernel identity\n")
        .unwrap();
    let changed_binary = restarted
        .generate_and_gate(
            &user_config,
            &restarted_deps,
            &path,
            Some(&binary),
            &mut peeled,
        )
        .await
        .unwrap();
    assert_eq!(changed_binary.checks_run, 1, "内核文件变化必须重验");
    assert_eq!(std::fs::read_to_string(&counter).unwrap().trim(), "2");

    let mut changed_cfg = cfg;
    changed_cfg["mixedPort"] = Value::from(17891);
    let changed_user: UserConfig = serde_json::from_value(changed_cfg.clone()).unwrap();
    let changed_deps = restarted.generate_deps(0, 0, 0, None, &[], &changed_cfg);
    let changed = restarted
        .generate_and_gate(
            &changed_user,
            &changed_deps,
            &path,
            Some(&binary),
            &mut BTreeMap::new(),
        )
        .await
        .unwrap();
    assert_eq!(changed.checks_run, 1, "用户端口等结构变化必须重验");
    assert_eq!(std::fs::read_to_string(&counter).unwrap().trim(), "3");
}

/// 🔴 **整环门：内核点名 → 真的重新生成 → 坏节点从落盘配置里消失 → 走既有通道上报**。
///
/// 这条补的是纯决策面单测够不着的那一半：`generate_and_gate` 里「剥完**重跑生成**」这条接线。
/// 变异（逐条转红）：
/// - 把 `effective.servers.retain(...)` 删掉（剥了却不重新生成）⇒ 坏节点仍在落盘配置里，断言 1 红；
/// - 把 `kernel_invalid` 不并进 `invalid_nodes`（剥了不上报）⇒ 断言 2 红 —— 节点凭空消失而不告知，
///   正是 `outbounds.rs` 那条「节点消失而不告知比报错更坏」反复强调的失效形态；
/// - 把 `peeled` 换成每轮新建的局部集合 ⇒ 剥了不记账 → 第二轮又生成出坏节点，断言 1 红。
///
/// **下标不写死**：先用 `binary=None`（failOpen 腿，不跑 check）拿到本次真实生成的 outbounds
/// 顺序，再据此算出 BAD 的下标喂给假核 —— 生成顺序哪天变了，本测自动跟上，不会变成假绿。
#[cfg(unix)]
#[tokio::test]
async fn kernel_rejected_node_is_regenerated_out_and_reported_through_the_existing_channel() {
    let (rt, dir) = test_runtime();
    let cfg = gate_two_node_config();
    let user_config: UserConfig = serde_json::from_value(cfg.clone()).unwrap();
    let deps = rt.generate_deps(0, 0, 0, None, &[], &cfg);
    let path = dir.join("gate-probe.json");

    // ① failOpen 腿（无核）：闸门整个跳过 —— 两个节点都在，且**没有**任何剔除上报。
    let mut peeled = BTreeMap::new();
    let base = rt
        .generate_and_gate(&user_config, &deps, &path, None, &mut peeled)
        .await
        .expect("无核时闸门必须放行，不得把「核不可用」判成「配置无效」");
    assert_eq!(base.checks_run, 0, "无核 ⇒ 一次 check 都不该跑");
    assert!(base.invalid_nodes.is_empty(), "无核 ⇒ 不得凭空上报剔除");
    let bad_index = base
        .config
        .outbounds
        .iter()
        .position(|o| o.tag == "BAD")
        .expect("BAD 节点应在生成的 outbounds 里");

    // ② 真闸门腿：假核第一次 check 点名 BAD 的下标。
    let fake = write_fake_checking_core(&dir, bad_index);
    let mut peeled = BTreeMap::new();
    let gated = rt
        .generate_and_gate(&user_config, &deps, &path, Some(&fake), &mut peeled)
        .await
        .expect("剥掉非选中的坏节点后应正常返回");

    // 断言 1：坏节点从**落盘的那一份**里真的没了，选中的节点还在。
    let on_disk: SingBoxConfig =
        serde_json::from_slice(&std::fs::read(&path).expect("闸门必须把最终配置写盘")).unwrap();
    assert!(
        !on_disk.outbounds.iter().any(|o| o.tag == "BAD"),
        "被内核拒收的节点必须从落盘配置里消失（剥了不重新生成 = 白剥）"
    );
    assert!(
        on_disk.outbounds.iter().any(|o| o.tag == "KEEP"),
        "其余节点必须照常保留 —— 一个坏节点不该连累全局"
    );
    assert_eq!(peeled.keys().collect::<Vec<_>>(), vec!["n-bad"]);

    // 断言 2：走**既有**上报通道（`InvalidNode` → `EVENT_PROXY_INVALID_NODES`），不是新造机制。
    assert_eq!(
        gated.invalid_nodes,
        vec![InvalidNode {
            id: "n-bad".into(),
            tag: "BAD".into(),
            reason: INVALID_REASON_KERNEL_REJECTED.to_string(),
        }],
        "剥掉的节点必须带成因上报（节点消失而不告知比报错更坏）"
    );
    assert!(gated.blocked.is_none(), "被拒的不是选中节点 ⇒ 不该落终态");
    assert_eq!(gated.checks_run, 2, "一次发现 + 一次确认，恰好两次 check");
}

/// 🔴 **整环门：内核拒的若是选中节点 → `blocked` 落值，且绝不把它剥掉**。
///
/// 变异：把 `PeelTarget::Blocked` 那一支改成照常 `Peel` ⇒ `blocked.is_none()` 断言红；
/// 更坏的是生产行为——剥掉选中节点后下一轮 generate 直接 `Selected server not found`，
/// 用户拿到的又是一句和现场无关的话。
#[cfg(unix)]
#[tokio::test]
async fn kernel_rejecting_the_selected_node_yields_blocked_not_a_silent_exit_switch() {
    let (rt, dir) = test_runtime();
    let cfg = gate_two_node_config();
    let user_config: UserConfig = serde_json::from_value(cfg.clone()).unwrap();
    let deps = rt.generate_deps(0, 0, 0, None, &[], &cfg);
    let path = dir.join("gate-probe.json");

    let mut peeled = BTreeMap::new();
    let base = rt
        .generate_and_gate(&user_config, &deps, &path, None, &mut peeled)
        .await
        .unwrap();
    let keep_index = base
        .config
        .outbounds
        .iter()
        .position(|o| o.tag == "KEEP")
        .expect("KEEP 节点应在生成的 outbounds 里");

    let fake = write_fake_checking_core(&dir, keep_index);
    let mut peeled = BTreeMap::new();
    let gated = rt
        .generate_and_gate(&user_config, &deps, &path, Some(&fake), &mut peeled)
        .await
        .unwrap();

    let (blocked, detail) = gated.blocked.expect("内核拒选中节点 ⇒ 必须落 blocked");
    assert_eq!(blocked.tag, "KEEP");
    assert_eq!(blocked.id, "n-keep");
    assert_eq!(blocked.reason, INVALID_REASON_KERNEL_REJECTED);
    assert!(
        detail.contains("unknown outbound type"),
        "必须把内核原话交出去（用户要靠它知道到底哪儿错了）；实得 {detail:?}"
    );
    assert!(
        peeled.is_empty(),
        "选中节点绝不许被剥 —— 剥了就是背着用户改出口（EXIT_MISMATCH 要抓的正是这个）"
    );
    assert_eq!(gated.checks_run, 1, "一次 check 判完即终态，不再重生成");
    // 🔴 变异锁：`blocked` 那个节点**也必须**进上报清单 —— 否则卡片不标灰，用户只剩一条会消失的
    // toast。变异：把 `assemble` 里 `.chain(blocked.iter()…)` 删掉 ⇒ 本条断在空 Vec。
    assert_eq!(
        gated.invalid_nodes,
        vec![InvalidNode {
            id: "n-keep".into(),
            tag: "KEEP".into(),
            reason: INVALID_REASON_KERNEL_REJECTED.to_string(),
        }],
        "被拒的选中节点必须走同一条通道上报（持久标灰是用户回头修它时唯一还在的线索）"
    );
}

/// 🔴 **剥除会改写幸存同名节点的 tag —— 故闸门必须把「剥后的那份 servers」交出来。**
///
/// 机制：`build_id_to_tag_map` 按**名字**去重、撞名追加 `(n)` ⇒ tag 是**整个集合**的函数，
/// 不是单个节点的函数。剥掉第一个「HK」之后，第二个在重新生成的配置里就叫「HK」而不是「HK (1)」。
///
/// 为什么这是 blocker 而不是洁癖：起核后有三处要按 `serverId` 反算运行核里的 tag ——
/// `attest_selected_exit`（出口自证，`code::EXIT_MISMATCH` 是「用户以为走代理、实则明文直连」的
/// **唯一**告警通道）、`build_switch_snapshot`（规则热切 PUT 的目标出站）、`endpoint_tag_to_id`。
/// 它们若拿未剥的全量 servers 算，得到的 tag 在运行核里根本不存在 ⇒ 出口完全正确却打
/// EXIT_MISMATCH 假警报（告警一旦有假就会被整体无视）、热切 PUT 静默打空。
///
/// 本测同时钉住**两侧**：① 闸门交出的 `effective_user_config` 确实是剥后的；
/// ② 用它算出的 tag 与用全量算出的**确实不同** —— 没有 ② 的话，哪天去重规则变了、
/// 两者恒等，本测就退化成一条恒真断言而没人发现。
#[cfg(unix)]
#[tokio::test]
async fn peeling_reshuffles_duplicate_name_tags_so_the_gate_hands_back_the_peeled_servers() {
    let (rt, dir) = test_runtime();
    // 两个**同名**节点：撞名去重会让第二个拿到 `HK (1)`。选中第三个，免得撞上 Blocked 腿。
    let cfg = serde_json::json!({
        "servers": [
            { "id": "n-a", "name": "HK", "protocol": "shadowsocks",
              "address": "1.2.3.4", "port": 8388, "method": "aes-256-gcm", "password": "p" },
            { "id": "n-b", "name": "HK", "protocol": "shadowsocks",
              "address": "5.6.7.8", "port": 8388, "method": "aes-256-gcm", "password": "p" },
            { "id": "n-sel", "name": "SEL", "protocol": "shadowsocks",
              "address": "9.9.9.9", "port": 8388, "method": "aes-256-gcm", "password": "p" }
        ],
        "selectedServerId": "n-sel",
        "proxyMode": "global",
        "proxyModeType": "manual",
        "mixedPort": 17891,
    });
    let user_config: UserConfig = serde_json::from_value(cfg.clone()).unwrap();
    let deps = rt.generate_deps(0, 0, 0, None, &[], &cfg);
    let path = dir.join("gate-dup.json");

    // 前提对照：未剥之前，两个同名节点确实拿到不同 tag（去重规则还在）。
    let tag_of = |uc: &UserConfig, id: &str| -> String {
        let wrappers: Vec<ServerLikeRef> = uc.servers.iter().map(ServerLikeRef).collect();
        build_id_to_tag_map(&wrappers)
            .into_iter()
            .find(|(k, _)| k == id)
            .expect("id 必须在表里")
            .1
    };
    assert_eq!(tag_of(&user_config, "n-a"), "HK");
    assert_eq!(
        tag_of(&user_config, "n-b"),
        "HK (1)",
        "撞名去重规则变了 —— 下面整条推理的前提没了，先确认新规则再改本测"
    );

    // 剥掉 n-a（第一个 HK）。下标由 failOpen 腿现算，不写死。
    let mut peeled = BTreeMap::new();
    let base = rt
        .generate_and_gate(&user_config, &deps, &path, None, &mut peeled)
        .await
        .unwrap();
    let a_index = base
        .config
        .outbounds
        .iter()
        .position(|o| o.tag == "HK")
        .expect("HK 应在生成的 outbounds 里");
    let fake = write_fake_checking_core(&dir, a_index);
    let mut peeled = BTreeMap::new();
    let gated = rt
        .generate_and_gate(&user_config, &deps, &path, Some(&fake), &mut peeled)
        .await
        .unwrap();
    assert_eq!(peeled.keys().collect::<Vec<_>>(), vec!["n-a"]);

    // ① 闸门交出的就是剥后的那份。
    let eff = &gated.effective_user_config;
    assert_eq!(
        eff.servers
            .iter()
            .map(|s| s.id.as_str())
            .collect::<Vec<_>>(),
        vec!["n-b", "n-sel"],
        "effective_user_config 必须是剥除之后的 servers —— 下游三处都按它算 tag"
    );

    // ② 用剥后的算，n-b 的 tag 变成了「HK」；用全量算还是「HK (1)」。两者**必须**不同，
    //    否则本测没有区分力（而生产上那三处正是靠这个差别才会打假警报）。
    assert_eq!(
        tag_of(eff, "n-b"),
        "HK",
        "剥掉第一个 HK 之后，幸存的同名节点在运行核里就叫 HK"
    );
    assert_ne!(
        tag_of(eff, "n-b"),
        tag_of(&user_config, "n-b"),
        "剥前剥后算出的 tag 竟然一样 —— 本测失去区分力，先确认去重规则是不是变了"
    );
    // 落盘的那份印证同一件事：运行核里 `HK (1)` 这个 tag 根本不存在。
    let on_disk: SingBoxConfig = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert!(
        !on_disk.outbounds.iter().any(|o| o.tag == "HK (1)"),
        "运行核里不该再有 `HK (1)` —— 按全量算 tag 的下游会去找一个不存在的出站"
    );
}

/// 🔴 **起核重试腿不得把闸门的剔除上报清空。**
///
/// `kernel_peeled` 声明在重试循环**之外**（同一节点、同一个核，判定不会变 ⇒ 第 2 腿沿用即可，
/// 恒只付 1 次 check）。而上报清单若是每次调用新建的局部 `Vec`，第 2 腿 emit 的就是一份**空数组**
/// —— 节点仍被剥出落盘配置，前端 store 整表替换后已标灰的卡片被清掉。
/// 「节点消失而不告知比报错更坏」，这正是那个形态。
///
/// 修法是让上报清单**由 `peeled` 现导**（`assemble` 里 `peeled.values()`），二者不可能再漂。
/// 本测模拟第 2 腿：`peeled` 预置一条，配置本身健康（假核 marker 已存在 ⇒ 直接 rc=0）。
#[cfg(unix)]
#[tokio::test]
async fn retry_leg_keeps_reporting_nodes_peeled_by_an_earlier_leg() {
    let (rt, dir) = test_runtime();
    let cfg = gate_two_node_config();
    let user_config: UserConfig = serde_json::from_value(cfg.clone()).unwrap();
    let deps = rt.generate_deps(0, 0, 0, None, &[], &cfg);
    let path = dir.join("gate-retry.json");

    // 假核：marker 已存在 ⇒ 本次 check 一律 rc=0（= 上一腿已把坏节点剥干净的现场）。
    let fake = write_fake_checking_core(&dir, 0);
    std::fs::write(dir.join("gate-check-seen"), b"1").unwrap();

    // 第 1 腿的产物：一条已剥记录。
    let mut peeled = BTreeMap::new();
    peeled.insert(
        "n-bad".to_string(),
        InvalidNode {
            id: "n-bad".into(),
            tag: "BAD".into(),
            reason: INVALID_REASON_KERNEL_REJECTED.to_string(),
        },
    );

    let gated = rt
        .generate_and_gate(&user_config, &deps, &path, Some(&fake), &mut peeled)
        .await
        .unwrap();

    assert_eq!(
        gated.checks_run, 1,
        "沿用上一腿的剥除结果 ⇒ 本腿只付 1 次 check"
    );
    assert!(
        !gated.config.outbounds.iter().any(|o| o.tag == "BAD"),
        "已剥节点在本腿仍不得出现在配置里"
    );
    // 🔴 核心断言：节点从配置里消失了，上报清单就**必须**同时还带着它。
    assert_eq!(
        gated.invalid_nodes,
        vec![InvalidNode {
            id: "n-bad".into(),
            tag: "BAD".into(),
            reason: INVALID_REASON_KERNEL_REJECTED.to_string(),
        }],
        "重试腿把剔除上报清空了 ⇒ 前端整表替换后标灰被抹掉，节点消失而用户毫不知情"
    );
}

// ── 主核就绪门按规模算：源码取材工具 + 计数口径 + 空操作性 ─────────────────────

// 这里曾有 `const_u64_decl`（按常量声明取材、剥注释、命中数须恰为 1）与它的两条自守门。
// 它是为「`speedtest.rs` 的 TEMP_CORE_* 与 core-supervisor 单一真值不许漂移」那道双向门造的；
// 系数收口之后那道门退场，本工具的**唯一**消费者就只剩它自己那两条自守门了，故一并删除。
// 不补「不许把系数抄回 speedtest.rs」的反向门：语义已由 `the_single_source_collapse_returns_the_same_values`
// 的金标表守住 —— 抄回去且值不同，那道门当场红；值相同则语义未变，本就不该红。
// 真要重新按常量声明取材，去 git 历史里捞，别照着散文重写一个。

// ── 这里曾有一对门，2026-09-03 随它们守的那份重复一并退场 ──────────────────────────────────
//
// · `temp_core_coefficients_stay_pinned_to_the_supervisor_single_source` —— **双向**防漂移门：
//   `speedtest.rs` 的四个 `TEMP_CORE_*` 系数（源码取材）与 core-supervisor 的单一真值（编译期真值）
//   必须逐值相等，改任一侧都转红。守的是「两个核必须按同一个模型算就绪门」：漂移后其中一个门必然
//   偏小，而偏小的那个正是「正在正常启动的核被判死」这条失败面。它的文档当时就写明了收口方向；
// · `speedtest_coefficient_digits_are_ambiguous_in_the_raw_source` —— 上面那道门的正向对照：断言
//   `90`/`105`/`41` 在 `speedtest.rs` 原文里各出现不止一次，即「按裸数字取材是歧义的」这件事为真，
//   否则那道门的取材面纪律就没有对象。
//
// 退场判据：`speedtest.rs` 的四个副本已改调 `core_startup_estimate_ms` 与单一真值常量 ⇒ 两份系数塌成
// 一份，漂移在结构上不可能发生（改一处即两处），两道门无对象可守。收口的行为等价性由
// `runtime/speedtest/tests/mod.rs::the_single_source_collapse_returns_the_same_values` 钉住，收口的
// 判词留在 `runtime/speedtest.rs` 常量原位的注释里。**别把系数再抄回去**：那等于把这道门连同它守的
// 失败面一起请回来。

/// 造一份**形状与真下发配置一致**的 `SingBoxConfig`（走 serde，字段口径与生成侧同源）。
fn test_singbox_config(
    outbounds: Vec<serde_json::Value>,
    endpoints: Vec<serde_json::Value>,
) -> polaris_config_engine::singbox::SingBoxConfig {
    let mut root = serde_json::json!({
        "log": { "level": "info", "timestamp": true },
        "inbounds": [{ "type": "mixed", "tag": "mixed-in" }],
        "outbounds": outbounds,
    });
    if !endpoints.is_empty() {
        root["endpoints"] = serde_json::Value::Array(endpoints);
    }
    serde_json::from_value(root).expect("测试 config 必须能反序列化成 SingBoxConfig")
}

fn naive_outbounds(count: usize) -> Vec<serde_json::Value> {
    (0..count)
        .map(|i| {
            serde_json::json!({
                "type": "naive",
                "tag": format!("naive-{i}"),
                "server": "node.invalid",
                "server_port": 443,
            })
        })
        .collect()
}

/// 🔴 **V1**：300 个 naive 出站的订阅，今天会被那道固定 12s 门当场判死；现在它等得到。
///
/// 这条腿的失败表现是**用户点连接直接连不上**，报错还指向网络/端口 —— 比测速失败严重得多。
#[test]
fn main_core_ready_gate_outgrows_the_old_fixed_wall_on_a_naive_heavy_config() {
    let mut outbounds = naive_outbounds(300);
    outbounds.push(serde_json::json!({ "type": "direct", "tag": "direct" }));
    let config = test_singbox_config(outbounds, vec![]);

    assert_eq!(main_core_naive_count(&config), 300);
    assert_eq!(main_core_parse_unit_count(&config), 301);

    let budget = main_core_ready_timeout_ms(&config);
    assert!(
        budget > CORE_READY_TIMEOUT_FLOOR_MS,
        "300 个 naive ≈ 300 个串行创建的 Cronet Engine，预算必须越过那堵 12s 墙，实得 {budget}ms"
    );
    // 逐项对账（改任一系数/固定项都会在这里转红，而不是只在「大于 12000」这种松断言上滑过去）：
    // 2 × (4000 + 0.105×301 + 41×300)
    assert_eq!(budget, 2 * (4_000 + 301 * 105 / 1000 + 300 * 41));
    assert_eq!(budget, 32_662);
}

/// 🔴 **V2（空操作性 —— 这是承诺，不是优化）**：今天跑得好好的小订阅，门一秒都不许变紧。
#[test]
fn main_core_ready_gate_is_a_strict_no_op_on_todays_small_configs() {
    use polaris_core_supervisor::CORE_READY_SAFETY_FACTOR;

    let outbounds: Vec<_> = (0..20)
        .map(|i| serde_json::json!({ "type": "vless", "tag": format!("node-{i}") }))
        .collect();
    let config = test_singbox_config(outbounds, vec![]);

    assert_eq!(main_core_naive_count(&config), 0);
    let budget = main_core_ready_timeout_ms(&config);
    assert!(budget >= CORE_READY_TIMEOUT_FLOOR_MS);
    assert_eq!(
        budget, 12_000,
        "0 naive / 20 节点是今天就跑得通的场景，等待行为必须逐字不变"
    );

    // **结构性保证**（比上面那条逐值断言更强）：空配置（n=0, m=0）下预算必须**恰好**是下限 ⇒
    // 固定项被下限整个吸收，`MAIN_CORE_STARTUP_FIXED_MS` 无论取多大都不可能把门收得比今天窄。
    // 等价于 `安全系数 × 固定项 ≤ 下限`，改大固定项时本断言是那道硬边界。
    let fixed_term_only = main_core_ready_timeout_ms(&test_singbox_config(vec![], vec![]));
    assert_eq!(
        fixed_term_only,
        CORE_READY_TIMEOUT_FLOOR_MS,
        "固定项 {MAIN_CORE_STARTUP_FIXED_MS}ms 已越过上界 {} ⇒ 它自己就能把门顶过下限，\
         空操作性不再有结构保证",
        CORE_READY_TIMEOUT_FLOOR_MS / CORE_READY_SAFETY_FACTOR
    );

    // 交叉点对账：m ≤ 48 恒为下限，m = 49 起才放宽（放宽是安全方向）。
    let at =
        |m: usize| main_core_ready_timeout_ms(&test_singbox_config(naive_outbounds(m), vec![]));
    assert_eq!(at(48), CORE_READY_TIMEOUT_FLOOR_MS);
    assert!(at(49) > CORE_READY_TIMEOUT_FLOOR_MS);
}

/// 🔴 **V5**：naive 数只数**出站条目**，不数 selector/urltest 的成员，也不数 endpoints。
///
/// 数错的两种错法都被夹具正面顶住：组成员里塞 200 个带 `naive` 字样的 tag（「数成员」或「在序列化
/// 后的 JSON 里数字符串」都会数出一个大得离谱的值），endpoints 里塞 50 个 WireGuard（它们不建
/// engine，成本 ≈ 0）。
#[test]
fn main_core_naive_count_counts_outbound_entries_not_members_or_endpoints() {
    let member_tags: Vec<String> = (0..200).map(|i| format!("naive-member-{i}")).collect();
    let mut outbounds = naive_outbounds(3);
    outbounds.push(serde_json::json!({ "type": "vless", "tag": "vless-1" }));
    outbounds.push(serde_json::json!({
        "type": "selector",
        "tag": "proxy",
        "outbounds": member_tags,
    }));
    outbounds.push(serde_json::json!({
        "type": "urltest",
        "tag": "auto",
        "outbounds": ["naive-0", "naive-1", "naive-2"],
    }));
    let endpoints: Vec<_> = (0..50)
        .map(|i| serde_json::json!({ "type": "wireguard", "tag": format!("wg-{i}") }))
        .collect();
    let config = test_singbox_config(outbounds, endpoints);

    // 夹具的判别力自证：按字符串数会数出三位数，按条目数只有 3。
    let serialized = serde_json::to_string(&config).expect("测试 config 必须可序列化");
    assert!(
        serialized.matches("naive").count() > 100,
        "夹具没造出歧义 ⇒ 本测证明不了「数成员」那种错法会被抓住"
    );

    assert_eq!(
        main_core_naive_count(&config),
        3,
        "只有真正的 naive **出站**才建 Cronet Engine；组成员是 tag 字符串，端点走 endpoints[]"
    );
    assert_eq!(main_core_parse_unit_count(&config), 6 + 50);
    assert_eq!(
        main_core_ready_timeout_ms(&config),
        CORE_READY_TIMEOUT_FLOOR_MS,
        "3 个 naive + 50 个端点远不到交叉点 ⇒ 门仍是下限"
    );
}

/// 🔴 报错文案必须说得清「是不是规模导致的」——两个方向都不许说错。
#[test]
fn main_core_ready_timeout_message_attributes_the_cause_correctly() {
    let big = test_singbox_config(naive_outbounds(300), vec![]);
    let big_budget = main_core_ready_timeout_ms(&big);
    let big_msg = main_core_ready_timeout_message(58_120, &big, big_budget);
    for needle in [
        "300",
        "Cronet Engine",
        "串行",
        &big_budget.to_string(),
        "减少",
    ] {
        assert!(
            big_msg.contains(needle),
            "规模超时的原文缺少「{needle}」：{big_msg}"
        );
    }

    let small = test_singbox_config(
        vec![serde_json::json!({ "type": "direct", "tag": "direct" })],
        vec![],
    );
    let small_budget = main_core_ready_timeout_ms(&small);
    let small_msg = main_core_ready_timeout_message(58_120, &small, small_budget);
    assert!(
        small_msg.contains("与订阅规模无关"),
        "0 naive 时把成因说成规模，是同一类误诊的反方向：{small_msg}"
    );
    assert!(
        !small_msg.contains("Cronet Engine"),
        "0 naive 时不该谈 engine：{small_msg}"
    );
}

/// 🔴 **接线守卫**：`start_inner` 真的把按规模算出来的预算喂给了就绪门。
///
/// 上面几条测的都是纯函数；「算对了但没接上去」是本仓反复出现的「门在但没牙」形态，而这条腿的行为
/// 验证要真核 + 真管理 API（真机门）。故这里守结构：预算的计算点、传参点，以及**不许**再出现
/// 「就绪门 timeout 直接取一个与规模无关的常量」的写法。
#[test]
fn start_inner_feeds_wait_ready_the_scale_derived_budget() {
    let code = crate::test_support::crate_code("runtime/proxy/startup.rs");
    assert!(
        code.contains("let ready_budget_ms = main_core_ready_timeout_ms(&singbox_config);"),
        "预算的计算点不在了：取材必须是本次真正下发给核的那份 config"
    );
    assert!(
        code.contains("self.wait_ready(api_port, my_gen, ready_budget_ms)"),
        "就绪门没有拿到按规模算出来的预算 ⇒ 公式算得再对也没接上去"
    );
    assert!(
        !code.contains("timeout_ms: CORE_READY_TIMEOUT_FLOOR_MS"),
        "就绪门的 timeout 回落成了与规模无关的常量 ⇒ 本改动被绕过去了"
    );
}
