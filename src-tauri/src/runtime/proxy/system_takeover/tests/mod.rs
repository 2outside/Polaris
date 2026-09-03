use super::*;

#[test]
fn should_enable_system_proxy_only_for_systemproxy() {
    assert!(should_enable_system_proxy(ProxyModeType::SystemProxy));
    assert!(!should_enable_system_proxy(ProxyModeType::Tun));
    assert!(!should_enable_system_proxy(ProxyModeType::Manual));
}

#[test]
fn restart_system_proxy_cleanup_truth_table() {
    use ProxyModeType::{Manual, SystemProxy, Tun};
    assert!(should_clear_system_proxy_between_restart(
        Some(SystemProxy),
        Some(Tun)
    ));
    assert!(should_clear_system_proxy_between_restart(
        Some(SystemProxy),
        Some(Manual)
    ));
    assert!(!should_clear_system_proxy_between_restart(
        Some(SystemProxy),
        Some(SystemProxy)
    ));
    for old in [None, Some(Tun), Some(Manual)] {
        for new in [None, Some(SystemProxy), Some(Tun), Some(Manual)] {
            assert!(
                !should_clear_system_proxy_between_restart(old, new),
                "非 systemProxy 旧会话不得清系统代理：old={old:?} new={new:?}"
            );
        }
    }
    assert!(!should_clear_system_proxy_between_restart(
        Some(SystemProxy),
        None
    ));
}
