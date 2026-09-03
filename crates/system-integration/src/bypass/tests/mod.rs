use super::*;

#[test]
fn ipv4_cidr_to_wildcard_and_local_default() {
    let s = format_bypass_for_windows(
        &[
            "10.0.0.0/8".into(),
            "192.168.0.0/16".into(),
            "localhost".into(),
        ],
        None,
    );
    assert_eq!(s, "10.*;192.168.*;localhost;<local>");
}

#[test]
fn skips_ipv6_cidr() {
    let s = format_bypass_for_windows(&["fc00::/7".into(), "localhost".into()], None);
    assert_eq!(s, "localhost;<local>");
}

#[test]
fn preserves_local_if_present() {
    let s = format_bypass_for_windows(&["localhost".into(), "<local>".into()], None);
    assert_eq!(s, "localhost;<local>");
    // 不重复追加
    assert_eq!(s.matches("<local>").count(), 1);
}

#[test]
fn unsafe_token_skipped_and_reported() {
    let mut reported = Vec::new();
    let s = format_bypass_for_windows(
        &["intra;net".into(), "10.0.0.0/8".into()],
        Some(&mut |e: &str| reported.push(e.to_string())),
    );
    assert_eq!(s, "10.*;<local>");
    assert_eq!(reported, vec!["intra;net".to_string()]);
}

#[test]
fn wildcard_domain_preserved() {
    let s = format_bypass_for_windows(&["*.local".into()], None);
    assert_eq!(s, "*.local;<local>");
}

#[test]
fn dedup_preserves_order() {
    let s = format_bypass_for_windows(
        &["10.0.0.0/8".into(), "10.0.0.0/8".into(), "localhost".into()],
        None,
    );
    assert_eq!(s, "10.*;localhost;<local>");
}
