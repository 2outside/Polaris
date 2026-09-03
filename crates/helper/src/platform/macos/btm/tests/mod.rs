use super::*;

// ===== assess_btm 三级分派 =====

#[test]
fn btm_none_before_ventura() {
    let a = assess_btm(MacosVersion(12));
    assert_eq!(a.tier, BtmTier::None);
    assert!(!a.prompts_user);
    assert!(!a.recommends_adhoc_sign);
    // macOS 11 Big Sur 也无 BTM
    let a11 = assess_btm(MacosVersion(11));
    assert_eq!(a11.tier, BtmTier::None);
}

#[test]
fn btm_v1_ventura() {
    let a = assess_btm(MacosVersion::VENTURA);
    assert_eq!(a.tier, BtmTier::V1);
    assert!(a.prompts_user, "Ventura 首次加载会弹提示");
    assert!(!a.recommends_adhoc_sign, "V1 不强制签名");
    assert!(!a.requires_explicit_allow, "V1 不需显式允许");
}

#[test]
fn btm_v2_sonoma() {
    let a = assess_btm(MacosVersion::SONOMA);
    assert_eq!(a.tier, BtmTier::V2);
    assert!(a.recommends_adhoc_sign, "Sonoma 未签名项建议 adhoc 签");
    assert!(a.requires_explicit_allow, "Sonoma 未签名项可能需显式允许");
}

#[test]
fn btm_v3_sequoia_and_above() {
    let a = assess_btm(MacosVersion::SEQUOIA);
    assert_eq!(a.tier, BtmTier::V3);
    assert!(a.recommends_adhoc_sign);

    // Tahoe (26) 也归 V3
    let a26 = assess_btm(MacosVersion::TAHOE);
    assert_eq!(a26.tier, BtmTier::V3);
    assert!(a26.prompts_user);

    // 未来版本 (30+) 也归 V3（兜底）
    let a30 = assess_btm(MacosVersion(30));
    assert_eq!(a30.tier, BtmTier::V3);
}

#[test]
fn btm_assessment_description_nonempty() {
    for v in [12, 13, 14, 15, 26] {
        let a = assess_btm(MacosVersion(v));
        assert!(!a.description.is_empty(), "v{v} description empty");
    }
}

// ===== 签名/quarantine 命令对照 helper.go =====

#[test]
fn adhoc_sign_cmd_matches_go_source() {
    // helper.go:196: /usr/bin/codesign --force --deep -s - <sb>
    let (prog, args) = adhoc_sign_cmd("/core/sing-box");
    assert_eq!(prog, "/usr/bin/codesign");
    assert_eq!(args, vec!["--force", "--deep", "-s", "-", "/core/sing-box"]);
}

#[test]
fn clear_quarantine_cmd_matches_go_source() {
    // helper.go:195: /usr/bin/xattr -cr <coreDir>
    let (prog, args) = clear_quarantine_cmd("/Library/Application Support/Polaris/core");
    assert_eq!(prog, "/usr/bin/xattr");
    assert_eq!(
        args,
        vec![
            "-cr".to_owned(),
            "/Library/Application Support/Polaris/core".to_owned()
        ]
    );
}

#[test]
fn macos_version_ordering() {
    assert!(MacosVersion::VENTURA < MacosVersion::SONOMA);
    assert!(MacosVersion::SONOMA < MacosVersion::SEQUOIA);
    assert!(MacosVersion(12) < MacosVersion::VENTURA);
}
