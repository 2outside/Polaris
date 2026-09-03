use crate::commands::guard_scan::top_level_fn_body;
use crate::test_support::crate_code;

/// Q1-b ④：正常退出收尾在 `ExitRequested` 里的**落点**必须晚于轻量模式早退；统一汇流点内，
/// 标记必须先于阻塞停核。行为断言够不着（要一个跑起来的 Tauri 事件循环），而挪错任何一边
/// 都是静默的正确性缺陷：
///
/// - 挪到 C16 `prevent_exit` 早退**之前** ⇒ 轻量模式销毁主窗（**进程没退**）也落标记 ⇒
///   用户唤出、webview 重建后，暂存的编辑被当成「上次退出过」清掉。
/// - 挪到 `run_exit_cleanup` **之后** ⇒ 那里面是**阻塞**停核（`block_on(proxy.stop())`），
///   卡住 / panic 都会让标记落不下去 ⇒ 每次正常退出都被下次启动当成强杀。
///
/// **变异锁**：把 bootstrap 的 `run_real_exit_once` 调用挪到 `api.prevent_exit();` 之前、删掉最终
/// `RunEvent::Exit` 兜底里的 subscription shutdown / 真实退出汇流点，或在汇流点内把 mark 挪到
/// cleanup 之后 ⇒ 转红。
#[test]
fn clean_exit_marker_is_written_only_on_the_real_exit_leg() {
    let main = top_level_fn_body(&crate_code("main.rs"), "fn main() {");
    let prevent = main
        .find("api.prevent_exit();")
        .expect("锚点消失：C16 轻量模式的 prevent_exit 早退，守卫已失去判据");
    let finish = main
        .find("exit_lifecycle::run_real_exit_once(app_handle);")
        .expect("锚点消失：ExitRequested 的真实退出收尾，C1/Q1-b ④ 已无人守");
    assert!(
        prevent < finish,
        "真实退出收尾落在了 C16 prevent_exit 早退之前：轻量模式会错误停核并清掉暂存编辑"
    );
    let exit_requested_start = main
        .find("tauri::RunEvent::ExitRequested { api, .. } => {")
        .expect("ExitRequested block disappeared: real-exit ordering has no source guard");
    let final_exit_start = main
        .find("tauri::RunEvent::Exit => {")
        .expect("最终 RunEvent::Exit block 消失：macOS 原生终止可跳过 ExitRequested");
    let exit_requested = &main[exit_requested_start..final_exit_start];
    let final_exit_tail = &main[final_exit_start..];
    let final_exit_end = final_exit_tail
        .find("\n        _ => {}")
        .expect("最终 RunEvent::Exit block 边界消失，源码守卫需随 match 结构同步更新");
    let final_exit = &final_exit_tail[..final_exit_end];
    for (name, exit_leg) in [("ExitRequested", exit_requested), ("最终 Exit", final_exit)] {
        let create_begin = exit_leg
            .find("runtime.subscription_create().shutdown_begin();")
            .expect("真实退出必须先关闭 subscription create 的 precommit gate");
        let parser_shutdown = exit_leg
            .find("runtime.subscription_parse().shutdown();")
            .expect("真实退出必须清空 subscription parse 队列");
        let create_wait = exit_leg
            .find("runtime.subscription_create().shutdown_wait();")
            .expect("真实退出必须等待已启动的 subscription create worker");
        assert!(
            create_begin < parser_shutdown && parser_shutdown < create_wait,
            "{name} 必须按 create gate/cancel → parser queue clear → create worker wait 的线性顺序退出"
        );
    }
    let final_finish = final_exit
        .find("exit_lifecycle::run_real_exit_once(app_handle);")
        .expect("最终 RunEvent::Exit 真实退出兜底消失：系统代理会残留死端口");
    let final_wait = final_exit
        .find("runtime.subscription_create().shutdown_wait();")
        .expect("最终 Exit 未等待订阅创建：commit 可能被进程退出截断");
    assert!(
        final_wait < final_finish,
        "最终 Exit 必须先完成 create worker 收口，再落 clean marker 并停核"
    );
    assert_eq!(
        main.matches("exit_lifecycle::run_real_exit_once(app_handle);")
            .count(),
        2,
        "真实退出汇流点只能位于 ExitRequested 的非轻量腿与最终 Exit 兜底"
    );

    let finish = top_level_fn_body(
        &crate_code("exit_lifecycle.rs"),
        "pub(crate) fn run_real_exit_once(",
    );
    let once = finish
        .find(".swap(true, Ordering::SeqCst)")
        .expect("一次性门消失：ExitRequested + Exit 会重复执行退出收尾");
    let mark = finish
        .find("mark_clean_exit(app);")
        .expect("锚点消失：正常退出标记的落点，Q1-b ④ 已无人守");
    let cleanup = finish
        .find("run_exit_cleanup(app);")
        .expect("锚点消失：退出清理调用点，C1 已无人守");
    assert!(once < mark, "一次性门必须先于任何有副作用的退出收尾");
    assert!(
        mark < cleanup,
        "正常退出标记落在阻塞停核之后：每次正常退出都会被下次启动当成强杀"
    );
}

/// Q1-b ④：`app:restart` 这条腿**不落**正常退出标记。判定腿（「bit 为真就不落、为假照落」）由
/// `clean_exit` 的真跑 FS 单测钉住；本条只钉接线：`app_restart` 确实在 `request_restart()` 前置位，
/// 且退出 owner 确实消费那个 bit 并委托给唯一的判定函数。
///
/// 没有本条，接线断了两侧都不会红：`app_restart` 不置位 ⇒ 判定腿恒收到 `false`（照落标记），
/// 而它自己的单测传的是自己造的 bit。
#[test]
fn restart_leg_is_wired_to_skip_the_clean_exit_marker() {
    let restart = top_level_fn_body(
        &crate_code("commands/window.rs"),
        "pub fn app_restart(app: AppHandle) -> ApiResponse<()> {",
    );
    let set = restart
        .find("RestartState")
        .expect("app_restart 不再置 RestartState：重启会被当成真实退出，回来后暂存的编辑被清掉");
    let restart_call = restart
        .find("app.request_restart();")
        .expect("锚点消失：request_restart() 调用点，守卫已失去判据");
    assert!(
        set < restart_call,
        "RestartState 置位落在 request_restart() 之后，等于没置"
    );

    let exit_leg = top_level_fn_body(
        &crate_code("exit_lifecycle.rs"),
        "fn mark_clean_exit(app: &tauri::AppHandle) {",
    );
    assert!(
        exit_leg.contains("RestartState"),
        "退出腿不再读 RestartState：app:restart 会照落标记"
    );
    assert!(
        exit_leg.contains("mark_unless_restarting"),
        "退出腿绕开 mark_unless_restarting：重启腿的豁免被丢失"
    );
}
