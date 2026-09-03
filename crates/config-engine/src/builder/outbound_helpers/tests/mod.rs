use super::*;

#[test]
fn duration_pure_num() {
    assert_eq!(normalize_duration(Some("10000")), Some("10000ms".into()));
    assert_eq!(normalize_duration(Some("500.5")), Some("500.5ms".into()));
}

#[test]
fn duration_with_unit() {
    assert_eq!(normalize_duration(Some("10s")), Some("10s".into()));
    assert_eq!(normalize_duration(Some("500ms")), Some("500ms".into()));
}

#[test]
fn duration_empty() {
    assert_eq!(normalize_duration(None), None);
    assert_eq!(normalize_duration(Some("")), None);
    assert_eq!(normalize_duration(Some("  ")), None);
}

#[test]
fn ws_ed_parse() {
    let r = parse_ws_early_data("/path?ed=2560");
    assert_eq!(r.path, "/path");
    assert_eq!(r.max_early_data, Some(2560));
    assert_eq!(
        r.early_data_header_name.as_deref(),
        Some(DEFAULT_EARLY_DATA_HEADER)
    );
}

#[test]
fn ws_ed_custom_header() {
    let r = parse_ws_early_data("/x?ed=1024&eh=Sec-Websocket-Protocol");
    assert_eq!(r.max_early_data, Some(1024));
    assert_eq!(
        r.early_data_header_name.as_deref(),
        Some("Sec-Websocket-Protocol")
    );
}

#[test]
fn ws_ed_preserves_other_query() {
    let r = parse_ws_early_data("/x?ed=2048&foo=bar");
    assert_eq!(r.path, "/x?foo=bar");
}

#[test]
fn ws_no_ed_unchanged() {
    let r = parse_ws_early_data("/path?foo=bar");
    assert_eq!(r.path, "/path?foo=bar");
    assert!(r.max_early_data.is_none());
}

#[test]
fn ws_ed_invalid_unchanged() {
    let r = parse_ws_early_data("/path?ed=abc");
    assert_eq!(r.path, "/path?ed=abc");
    assert!(r.max_early_data.is_none());
}

#[test]
fn quic_tls_check() {
    assert!(is_quic_managed_tls("hysteria2"));
    assert!(is_quic_managed_tls("tuic"));
    assert!(!is_quic_managed_tls("vless"));
    assert!(!is_quic_managed_tls("trojan"));
}

#[test]
fn tls_engine_platform_gate() {
    assert!(should_emit_tls_engine(Some("windows"), "win32"));
    assert!(!should_emit_tls_engine(Some("windows"), "darwin"));
    assert!(should_emit_tls_engine(Some("apple"), "darwin"));
    assert!(!should_emit_tls_engine(Some("apple"), "win32"));
    assert!(!should_emit_tls_engine(Some("go"), "win32"));
    assert!(!should_emit_tls_engine(None, "linux"));
}

#[test]
fn pruned_default() {
    let remaining = vec!["a".to_string(), "b".to_string()];
    assert_eq!(
        pruned_selector_default(Some("rule-sel-r1"), &remaining),
        Some("proxy-selector".into())
    );
    assert_eq!(
        pruned_selector_default(Some("proxy-selector"), &remaining),
        Some("a".into())
    );
    assert_eq!(pruned_selector_default(None, &remaining), Some("a".into()));
}
