use super::*;

#[test]
fn v4_overlap() {
    assert!(ipv4_cidrs_overlap("192.168.0.0/16", "192.168.1.0/24"));
    assert!(ipv4_cidrs_overlap("10.0.0.0/8", "10.1.2.0/24"));
    assert!(!ipv4_cidrs_overlap("10.0.0.0/8", "192.168.0.0/16"));
    assert!(ipv4_cidrs_overlap("0.0.0.0/0", "1.2.3.0/24")); // 全覆盖
}

#[test]
fn v4_contains() {
    assert!(cidr_contains("10.0.0.0/8", "10.1.2.0/24"));
    assert!(!cidr_contains("10.1.2.0/24", "10.0.0.0/8"));
    assert!(!cidr_contains("10.0.0.0/8", "192.168.0.0/16"));
}

#[test]
fn v4_subtract_basic() {
    // 10.0.0.0/8 ∖ 10.1.0.0/16 → 10.0.0.0/16 + 10.2.0.0/15...10.128.0.0/9
    let result = subtract_cidrs(&["10.0.0.0/8".to_string()], &["10.1.0.0/16".to_string()]);
    assert!(result.len() > 1);
    // 验证不含 10.1.0.0/16 且并集覆盖原 /8 减该段。
    assert!(!result.iter().any(|c| c == "10.1.0.0/16"));
}

#[test]
fn v4_subtract_equal() {
    let result = subtract_cidrs(&["10.0.0.0/8".to_string()], &["10.0.0.0/8".to_string()]);
    assert!(result.is_empty());
}

#[test]
fn v4_subtract_no_overlap() {
    let result = subtract_cidrs(&["10.0.0.0/8".to_string()], &["192.168.0.0/16".to_string()]);
    assert_eq!(result, vec!["10.0.0.0/8".to_string()]);
}

#[test]
fn v6_overlap() {
    assert!(ipv6_cidrs_overlap("fc00::/7", "fd00::/8"));
    assert!(ipv6_cidrs_overlap("2001:db8::/32", "2001:db8:1::/48"));
    assert!(!ipv6_cidrs_overlap("fc00::/7", "2001::/16"));
}

#[test]
fn v6_subtract() {
    let result = subtract_cidrs(&["fc00::/7".to_string()], &["fd00::/8".to_string()]);
    assert!(!result.is_empty());
}

#[test]
fn cross_family_disjoint() {
    assert!(!cidrs_overlap("10.0.0.0/8", "fc00::/7"));
}

#[test]
fn partition_by_overlap() {
    let cidrs = vec![
        "10.0.0.0/8".to_string(),
        "192.168.0.0/16".to_string(),
        "1.2.3.0/24".to_string(),
    ];
    let ranges = vec!["192.168.0.0/16".to_string()];
    let (overlapping, disjoint) = partition_cidrs_by_overlap(&cidrs, &ranges);
    assert_eq!(overlapping, vec!["192.168.0.0/16".to_string()]);
    assert_eq!(disjoint.len(), 2);
}
