use crate::commands::guard_scan::top_level_fn_body;
use crate::test_support::crate_code;

/// **只扫生产正文的剥注释面**。
///
/// 「只扫生产」不是洁癖，是本门第一版真踩到的**自指假绿**：签名串本身就写在本模块的源码里，
/// `SRC.find(sig)` 会命中**本模块自己**（尤其当真签名带泛型、与所给字面量不逐字相同时）
/// —— 于是把生产代码整段改坏，断言照样在自己的字符串常量里找到那句话、照样绿。
/// 测试实体现已整体外移到 `commands/subscription/tests/`，`commands/subscription.rs` 全文恒为
/// 生产码，自指在结构上不再可能，故**不再截断**：旧的「截到 `mod wiring_gate` 之前」还附带一个
/// 盲区——锚点之后的生产代码本门扫不到。
///
/// 「剥注释面」（[`crate_code`]）治的是同一个缺陷类的第二条腿：本文件 11 条全是**正面**
/// `contains` / `find`，针都是单行代码文本，把被守的那行接线整行注释掉，注释里那份副本就替它
/// 作证。字符串字面量原样保留 —— 本门有多条针本身就是字面量（`"phase": "fetching"` /
/// `"etag"` / `"subscriptionId"`），连字符串一起抹会让它们直接消失。
fn production_code() -> String {
    crate_code("commands/subscription.rs")
}

fn pipeline_code() -> String {
    crate_code("commands/subscription/pipeline.rs")
}

fn pipeline_fn_body(sig: &str) -> String {
    top_level_fn_body(&pipeline_code(), sig)
}

/// 取顶层项（`fn` / `impl` 块）的源码片段，走**共用**取材器
/// [`crate::commands::guard_scan::top_level_fn_body`]。
///
/// 此前这里是本仓第 5 份手写切片器：`rest.find("\n}")` 封顶、锚点缩进不校验、注释不剥。
/// 三条差别都不是风格问题 ——
/// - 不校验缩进：拿它去切 `impl` 方法会一路切到整个 `impl` 块结束（本仓实测过 98 倍超宽切片，
///   `find` 顺延到别处的同名调用，顺序断言仍然全绿）；
/// - `"\n}"` 而非 `"\n}\n"`：少一个换行的封顶谓词在 `\n})` 之类的收尾上会提前截断；
/// - 找不到闭合时 `map_or(rest.len(), ..)` 静默切到文件尾 = 守卫失去判据却不转红。
///
/// 共用器三条都反过来（缩进必断言、`"\n}\n"` 封顶、找不到就 panic）。
fn fn_body(sig: &str) -> String {
    top_level_fn_body(&production_code(), sig)
}

/// 门自身的自检：`fn_body` 必须真的取到**生产**函数，而不是本模块里的同名字面量。
#[test]
fn the_gate_scans_production_code_not_itself() {
    let body = fn_body("async fn perform_subscription_update_inner(");
    assert!(
        body.contains("state.config().load_full()"),
        "取到的必须是生产函数体（含真实实现语句），实得: {}",
        &body[..body.len().min(200)]
    );
    assert!(
        !production_code().contains("mod wiring_gate"),
        "扫描面不得包含本测试模块"
    );
}

#[test]
fn update_resolves_ua_through_the_three_level_chain() {
    let body = fn_body("async fn perform_subscription_update_inner(");
    assert!(
        body.contains("resolve_subscription_ua(&cfg, &sub)"),
        "变异锁：改回内联 `sub.get(\"userAgent\")` → 全局 subscriptionUserAgent 重新变成死键，\
             而 `ua_tests` 里那些纯函数断言照样全绿"
    );
}

#[test]
fn update_forwards_failed_provider_names_into_reconcile() {
    // ① 编排产出里必须真的接住这份名单（丢掉 → 整订阅级 merge-only、deleted 恒 0）。
    let fetch = pipeline_fn_body("pub(super) async fn fetch_parse_resolve<L: DnsLookup>(");
    assert!(
        fetch.contains("failed_providers = aggregate.failed_providers"),
        "变异锁：只取 any_failed、丢掉失败 provider 名单 → 成功 provider 名下的真下架节点永久滞留"
    );
    // ② 且必须一路传到 reconcile（provider 级精确 merge-back 的唯一入口）。
    let body = fn_body("async fn perform_subscription_update_inner(");
    assert!(
        body.contains("&outcome.failed_providers"),
        "变异锁：reconcile 收不到名单 → `leftover_survives_partial` 退化成全保留"
    );
}

#[test]
fn update_defers_removed_node_assets_until_the_restart_boundary() {
    let body = fn_body("async fn perform_subscription_update_inner(");
    let journal = body
        .find("state.config().update_deferred_cleanup(|cfg|")
        .expect("订阅对账必须在延迟删除事务中原子完成");
    let broadcast = body
        .find("broadcast_config_changed(app, &cfg)")
        .expect("内容变化后的热切换广播仍须存在");
    assert!(
        journal < broadcast,
        "删除意图须先持久化，随后广播才能触发旧核退出与安全消费"
    );
    assert!(body.contains("reconcile_subscription_servers("));
}

#[test]
fn forced_proxy_policy_is_checked_before_fetching() {
    let body = fn_body("async fn perform_subscription_update_inner(");
    let guard = body
        .find("proxy_policy_is_forced(&cfg)")
        .expect("变异锁：删掉强制经代理闸门 → 显式 policy=proxy 时静默明文直连拉订阅");
    let fetch = body
        .find("fetch_parse_resolve(")
        .expect("拉取腿仍在（本断言的锚点）");
    assert!(
        guard < fetch,
        "闸门必须在拉取**之前**：拉完再报错，DNS/SNI 已经泄漏出去了"
    );
}

#[test]
fn every_subscription_fetch_uses_the_guarded_dedicated_inbound() {
    let select = fn_body("fn select_fetch_client(");
    assert!(select.contains("st.subscription_update_in_port"));
    assert!(
        select.contains("backend_subscription_route_uses_proxy(cfg)"),
        "端口存在不等于实际经代理：选择器必须消费与 config-engine 路由共源的后端判据"
    );
    assert!(
        !select.contains("st.update_in_port"),
        "preview/update/create 共用选择器不得退回图标使用的共享 update-in"
    );

    let create = crate_code("commands/subscription/create.rs");
    let generation = top_level_fn_body(&create, "fn proxy_generation(");
    assert!(
        generation.contains("status.subscription_update_in_port"),
        "create 提交前的代理世代复核必须跟踪实际使用的订阅专用端口"
    );
}

#[test]
fn preview_treats_renderer_via_proxy_as_preference_not_effective_fact() {
    let body = fn_body("pub async fn subscription_preview(");
    let load = body
        .find("state.config().load_full()")
        .expect("preview 必须先读取后端配置策略");
    let resolve = body
        .find("want_proxy_for_sub(&cfg, &draft)")
        .expect("preview 必须由后端合并全局 policy 与 draft follow 偏好");
    let select = body
        .find("select_fetch_client(state.inner(), &cfg, want_proxy)")
        .expect("preview 必须让后端配置参与实际 client 选择");
    let forced = body
        .find("forced_proxy && !via_effective")
        .expect("preview 强制代理不可用时必须 fail-closed");
    let fetch = body
        .find("preview_core(")
        .expect("preview 真拉取腿仍在（本断言的锚点）");
    assert!(load < resolve && resolve < select && select < forced && forced < fetch);
}

/// UA 变更 → **在写回 config 之前**清掉条件 GET 验证器。
///
/// 变异锁：删掉 `subscription_update` 里那段 `if ua_changed(..) { set_or_remove(..) }`
/// → 本用例转红。`ua_tests::ua_changed_…` 测的是纯谓词，删掉调用点它照样全绿 ——
/// 这正是本门存在的理由。
#[test]
fn changing_ua_drops_the_conditional_get_validators() {
    let body = fn_body("pub fn subscription_update(");
    let at = body
        .find("ua_changed(&arr[idx], &subscription)")
        .expect("变异锁：UA 变更未作废验证器 → 机场按 UA 下发变体时永远 304，新格式拿不到");
    for key in ["\"etag\"", "\"lastModified\""] {
        let cleared = body[at..]
            .find(&format!("set_or_remove(&mut subscription, {key}, None)"))
            .is_some();
        assert!(cleared, "{key} 必须在 UA 变更分支里被清掉");
    }
    // 且必须发生在写回之前（写回后再改就白改了）。
    let write_back = body.find("arr[idx] = subscription;").expect("写回腿仍在");
    assert!(at < write_back, "作废必须排在写回 config 之前");
}

/// **终态必达**由外壳结构保证，不是靠逐条早退各补一句 emit。
#[test]
fn the_update_shell_cannot_return_without_a_terminal_frame() {
    let shell = fn_body("pub(crate) async fn perform_subscription_update(");
    assert!(
        shell.contains("terminal_progress_frame(&result)"),
        "变异锁：删掉终态帧 → 订阅信息栏永远挂在「更新中」，且失败无处可见"
    );
    // 外壳里**一条早退都不许有**：有了就说明存在一条绕过终态帧的路径。
    assert!(
        !shell.contains("return"),
        "变异锁：往外壳里塞早退 = 重新造出「某些结局不发终态帧」这个原始缺陷"
    );
    // 终态只有一个发射者：内层自己再发一份就会与外壳打架（顺序/内容都无从保证）。
    let inner = fn_body("async fn perform_subscription_update_inner(");
    assert!(
        !inner.contains("terminal_progress_frame"),
        "变异锁：内层自发终态帧 → 一次更新两个终态，前端最后收到哪个取决于代码顺序"
    );
}

/// 起手帧必须排在真正开跑之前（否则「点了没反应」这个原始症状原样保留）。
#[test]
fn fetching_frame_precedes_the_real_work() {
    let shell = fn_body("pub(crate) async fn perform_subscription_update(");
    let emit = shell
        .find("\"phase\": \"fetching\"")
        .expect("变异锁：删掉起手帧 → 前 30s 屏幕上什么都不会变");
    let call = shell
        .find("perform_subscription_update_inner(")
        .expect("内层调用仍在（本断言的锚点）");
    assert!(emit < call, "起手帧必须在内层开跑之前发出");
}

/// 落盘/对账阶段单独报，且必须排在拉取腿之后。
#[test]
fn reconciling_phase_is_reported_after_the_network_leg() {
    let inner = fn_body("async fn perform_subscription_update_inner(");
    let fetch = inner
        .find("fetch_parse_resolve(")
        .expect("拉取腿仍在（本断言的锚点）");
    let reconciling = inner
        .find("\"phase\": \"reconciling\"")
        .expect("变异锁：删掉 reconciling → 本地对账卡住时用户以为还在等机场");
    assert!(reconciling > fetch, "reconciling 必须在拉取之后");
}

/// provider 计数真的接进了子拉取闭包（纯逻辑单测覆盖计数语义，本门覆盖「有没有接上」）。
#[test]
fn provider_progress_counter_is_wired_into_the_fetch_closure() {
    let f = pipeline_fn_body("pub(super) async fn fetch_parse_resolve<L: DnsLookup>(");
    assert!(
        f.contains("ProviderProgress::new("),
        "变异锁：不建计数器 → provider 型订阅在最长 8×15s 里只有一个静止的「拉取中」"
    );
    let b = pipeline_fn_body("fn build_provider_fetch(");
    assert!(
        b.contains("progress.on_fetch_start()") && b.contains("progress.on_fetch_finish()"),
        "变异锁：计数器须同时接上发起与完成点，done 才是真实 settle 数"
    );
}

#[test]
fn production_parsers_are_executor_isolated_and_legacy_add_is_unreachable() {
    let pipeline = pipeline_code();
    assert!(pipeline.contains("submit_weighted(body_bytes, move ||"));
    assert!(pipeline.contains("submit_weighted(input_bytes, move ||"));
    assert!(pipeline.contains("submit_weighted(aggregate_input_bytes, move ||"));
    assert!(
        pipeline.contains("inline_output_metrics\n            .checked_add(providers_result.output_metrics)"),
        "provider aggregation must reserve exact inline + provider retained output, not weight zero"
    );
    assert!(
        !pipeline.contains("submit_weighted(0, move ||"),
        "a zero-weight aggregation can accumulate eight provider outputs outside the executor budget"
    );
    assert!(pipeline.contains("aggregate_provider_output("));
    assert!(!pipeline.contains("spawn_blocking"));

    let local = fn_body("pub async fn local_import_parse(");
    assert!(local.contains("submit_weighted(input_bytes, move ||"));
    assert!(!local.contains("parse_subscription"));

    let main = crate_code("main.rs");
    assert!(
        !main.contains("subscription_add,"),
        "legacy subscription_add must not be registered in Tauri invoke"
    );
    assert!(!production_code().contains("pub fn subscription_add("));
}

#[test]
fn local_file_picker_never_blocks_a_tokio_worker_on_std_fs() {
    let picker = fn_body("pub async fn local_import_pick_file(");
    assert!(
        picker.contains("tokio::fs::File::open(&path)"),
        "文件选择 command 必须用 Tokio 文件 API，而非在 async command 内同步 open/read"
    );
    assert!(
        picker.contains("tokio::time::timeout(LOCAL_IMPORT_FILE_READ_TIMEOUT, read)"),
        "文件读取须有显式 timeout，避免 FIFO/卡死挂住 command"
    );
    assert!(
        picker.contains("file.take(MAX_BODY_BYTES + 1)"),
        "metadata 只是预检；实际读取须流式多读一个字节来防 TOCTOU 超限"
    );
    assert!(!picker.contains("std::fs::"));
}

#[test]
fn operation_timeout_cannot_reach_the_atomic_create_commit() {
    let create = crate_code("commands/subscription/create.rs");
    let run = top_level_fn_body(&create, "async fn run_create_operation(");
    let timeout = run
        .find("tokio::time::timeout_at(operation_deadline.into(), pipeline)")
        .expect("create pipeline must be enclosed by the overall deadline");
    let timeout_error = run[timeout..]
        .find("super::operation_timeout_error()")
        .map(|offset| offset + timeout)
        .expect("deadline expiry must have a stable classified error");
    let commit = run
        .find("operations.begin_commit(operation_id, &sink)")
        .expect("atomic commit point must remain explicit");
    assert!(timeout < timeout_error && timeout_error < commit);
    assert!(
        run[timeout_error..commit].contains("return;"),
        "timeout branch must terminate before any commit capability is reached"
    );
    let pipeline = pipeline_code();
    assert!(!pipeline.contains("state.config()"));
    assert!(!pipeline.contains("broadcast_config_changed"));
}

/// 预检腿必须静音：那时还没有订阅 id，帧发出去没有归属（会以空 id 串到别的栏上）。
#[test]
fn preview_leg_emits_no_progress_frames() {
    let preview = fn_body("pub(crate) async fn preview_core<L: DnsLookup>(");
    assert!(
        preview.contains("fetch_parse_resolve("),
        "预检仍复用同一拉取层（本断言的锚点）"
    );
    assert!(
        !preview.contains("sink"),
        "变异锁：给预检也接上 sink → 新增订阅对话框会往一个还不存在的订阅推进度"
    );
    let inner = fn_body("async fn perform_subscription_update_inner(");
    assert!(
        inner.contains("Some(sink),"),
        "变异锁：更新腿传 None → provider 计数整条腿静默失联"
    );
}

/// 每一帧都必须带 `subscriptionId`：没有它，多订阅时前端无从判断该点亮哪一条信息栏。
///
/// 只能扫源码——补 id 发生在 `BroadcastUpdateProgress::emit` 里，而构造它需要 `AppHandle`
/// （本仓未引 `tauri::test`）。帧内容本身的门在 `mod progress_tests`。
#[test]
fn every_frame_is_stamped_with_the_subscription_id() {
    let body = fn_body("impl UpdateProgressSink for BroadcastUpdateProgress {");
    assert!(
        body.contains("\"subscriptionId\""),
        "变异锁：不补 subscriptionId → 帧无归属，前端要么全栏一起亮要么全不亮"
    );
}
