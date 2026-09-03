use crate::commands::guard_scan::top_level_fn_body;
use crate::test_support::crate_code;

/// 活态查询只能消费同一代、已稳定的运行态；两道门都必须早于任何 OS 读取。
#[test]
fn live_query_rejects_starting_and_non_system_running_sessions_before_os_read() {
    let body = top_level_fn_body(
        &crate_code("commands/proxy.rs"),
        "pub async fn system_proxy_get_status(",
    );
    let starting = body
        .find("if status.starting")
        .expect("系统代理活态查询必须拒绝 starting 半成品");
    let running_mode = body
        .find("running_proxy_mode_type() != Some(ProxyModeType::SystemProxy)")
        .expect("活态查询必须核对运行核模式，不能读先行落盘的新配置");
    let os_read = body
        .find("production_system_proxy_live_status")
        .expect("活态查询必须保留真实 OS 读取");
    assert!(
        starting < os_read && running_mode < os_read,
        "starting / 运行核模式两道门必须先于 reg/networksetup/gsettings"
    );
}
