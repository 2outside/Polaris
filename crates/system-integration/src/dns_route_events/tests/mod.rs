use super::*;

#[test]
fn triggers_on_rtm_ifinfo() {
    assert!(is_dns_reconcile_trigger_line(
        "RTM_IFINFO: oscp_route_recv\n"
    ));
    assert!(is_dns_reconcile_trigger_line(
        "  RTM_NEWADDR: address added"
    ));
}

#[test]
fn triggers_on_numbered_variants() {
    assert!(is_dns_reconcile_trigger_line("RTM_IFINFO2 len"));
    assert!(is_dns_reconcile_trigger_line("RTM_NEWADDR2: ..."));
}

#[test]
fn triggers_on_route_add_delete() {
    assert!(is_dns_reconcile_trigger_line("RTM_ADD: default gateway"));
    assert!(is_dns_reconcile_trigger_line("RTM_DELETE: default gateway"));
}

#[test]
fn classifies_interface_and_route_impacts() {
    assert_eq!(
        classify_route_monitor_line("RTM_IFINFO2: flags changed"),
        Some(RouteMonitorEvent::Interface)
    );
    assert_eq!(
        classify_route_monitor_line("RTM_NEWADDR: address added"),
        Some(RouteMonitorEvent::Interface)
    );
    assert_eq!(
        classify_route_monitor_line("RTM_DELETE: default gateway"),
        Some(RouteMonitorEvent::Route)
    );
    assert_eq!(classify_route_monitor_line("RTM_GET: query"), None);
}

#[test]
fn ignores_stat_header() {
    assert!(!is_dns_reconcile_trigger_line(
        "got message of size 92 on Wed Jul 15 10:00:00 2026"
    ));
}

#[test]
fn ignores_noise_and_empty() {
    assert!(!is_dns_reconcile_trigger_line(""));
    assert!(!is_dns_reconcile_trigger_line("   "));
    assert!(!is_dns_reconcile_trigger_line("lock: 0 flags: 0x1"));
}

#[test]
fn ignores_non_trigger_rtm_types() {
    assert!(!is_dns_reconcile_trigger_line("RTM_GET: query"));
    assert!(!is_dns_reconcile_trigger_line("RTM_LOSING: ..."));
    assert!(!is_dns_reconcile_trigger_line("RTM_MISS: ..."));
}
