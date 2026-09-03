use super::*;

#[test]
fn bootstrap_dns_check() {
    assert!(is_bootstrap_direct_dns("223.5.5.5"));
    assert!(is_bootstrap_direct_dns("  1.12.12.12  "));
    assert!(!is_bootstrap_direct_dns("8.8.8.8"));
    assert!(!is_bootstrap_direct_dns("1.1.1.1"));
}

#[test]
fn controlled_dns_excluded_from_bootstrap() {
    // 不变量：CONTROLLED_TUN_DNS_IP 不在 BOOTSTRAP_DIRECT_DNS_IPS。
    assert!(!is_bootstrap_direct_dns(CONTROLLED_TUN_DNS_IP));
}

#[test]
fn direct_selection_sentinel() {
    assert!(is_direct_selection(Some(DIRECT_SERVER_ID)));
    assert!(!is_direct_selection(Some("s1")));
    assert!(!is_direct_selection(None));
}

#[test]
fn block_selection_sentinel() {
    assert!(is_block_selection(Some(BLOCK_SERVER_ID)));
    assert!(!is_block_selection(Some(DIRECT_SERVER_ID)));
    assert!(!is_block_selection(Some("s1")));
    assert!(!is_block_selection(None));
}

/// 两个哨兵值必须互异且都不是合法节点 id 形状——撞值会让「阻断」静默变成「直连」。
#[test]
fn sentinels_are_distinct() {
    assert_ne!(DIRECT_SERVER_ID, BLOCK_SERVER_ID);
    assert!(is_sentinel_selection(Some(DIRECT_SERVER_ID)));
    assert!(is_sentinel_selection(Some(BLOCK_SERVER_ID)));
    assert!(!is_sentinel_selection(Some("s1")));
    assert!(!is_sentinel_selection(None));
}

/// BLOCK_TAG 必须与 `outbounds.rs` 无条件生成的 block 出站 tag 同字面 —— 漂了就 PUT 到不存在的成员，
/// 核返 NotFound → executor 判 Failed → 静默退回重启（与 PROXY_SELECTOR_TAG 同款失效形态）。
#[test]
fn block_tag_matches_generated_outbound_tag() {
    assert_eq!(BLOCK_TAG, "block");
    assert_ne!(BLOCK_TAG, DIRECT_TAG);
}
