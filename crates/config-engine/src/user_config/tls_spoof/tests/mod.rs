use super::*;

#[test]
fn method_enum_strict() {
    assert!(is_valid_tls_spoof_method(Some("wrong-ack")));
    assert!(is_valid_tls_spoof_method(Some("wrong-md5")));
    assert!(is_valid_tls_spoof_method(Some("wrong-timestamp")));
    assert!(!is_valid_tls_spoof_method(Some("wrong-foo")));
    assert!(!is_valid_tls_spoof_method(None));
}

#[test]
fn arch_gate() {
    assert!(is_tls_spoof_supported_arch(Some("x64")));
    assert!(is_tls_spoof_supported_arch(Some("ia32")));
    assert!(!is_tls_spoof_supported_arch(Some("arm64")));
    assert!(!is_tls_spoof_supported_arch(Some("arm")));
    assert!(!is_tls_spoof_supported_arch(Some("aarch64")));
    assert!(!is_tls_spoof_supported_arch(None));
}

#[test]
fn protocol_gate() {
    assert!(is_tls_spoof_supported_protocol(Some("vless")));
    assert!(is_tls_spoof_supported_protocol(Some("trojan")));
    assert!(!is_tls_spoof_supported_protocol(Some("hysteria2")));
    assert!(!is_tls_spoof_supported_protocol(Some("tuic")));
    assert!(!is_tls_spoof_supported_protocol(Some("naive")));
}

#[test]
fn validate_happy_path() {
    assert!(validate_tls_spoof_default(
        Some("example.com"),
        Some("wrong-ack"),
        Some("x64"),
        None,
        None,
    ));
}

#[test]
fn validate_rejects_ip_literal_sni() {
    assert!(!validate_tls_spoof_default(
        Some("1.2.3.4"),
        Some("wrong-ack"),
        Some("x64"),
        None,
        None,
    ));
}

#[test]
fn validate_rejects_arm64() {
    assert!(!validate_tls_spoof_default(
        Some("example.com"),
        Some("wrong-ack"),
        Some("arm64"),
        None,
        None,
    ));
}

#[test]
fn validate_rejects_empty_sni() {
    assert!(!validate_tls_spoof_default(
        Some(""),
        Some("wrong-ack"),
        Some("x64"),
        None,
        None,
    ));
    assert!(!validate_tls_spoof_default(
        None,
        Some("wrong-ack"),
        Some("x64"),
        None,
        None,
    ));
}

#[test]
fn validate_outbound_server_sni_diff() {
    // 诱饵 ≠ 真 server_name。
    assert!(validate_tls_spoof_default(
        Some("decoy.com"),
        Some("wrong-md5"),
        Some("x64"),
        None,
        Some("real.com"),
    ));
    // 诱饵 == 真 server_name → 内核 FATAL `spoof must differ from server_name`。
    assert!(!validate_tls_spoof_default(
        Some("same.com"),
        Some("wrong-md5"),
        Some("x64"),
        None,
        Some("same.com"),
    ));
    // 真 server_name 为 IP 字面量 → FATAL。
    assert!(!validate_tls_spoof_default(
        Some("decoy.com"),
        Some("wrong-md5"),
        Some("x64"),
        None,
        Some("1.2.3.4"),
    ));
}
