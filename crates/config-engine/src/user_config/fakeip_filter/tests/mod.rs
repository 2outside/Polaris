use super::*;

#[test]
fn captive_includes_apple_android_msft() {
    let all = FAKEIP_FILTER_CAPTIVE_DOMAINS.join(" ");
    assert!(all.contains("captive.apple.com"));
    assert!(all.contains("connectivitycheck.gstatic.com"));
    assert!(all.contains("msftconnecttest.com"));
}

#[test]
fn ntp_suffixes_include_pool_org() {
    assert!(FAKEIP_FILTER_NTP_SUFFIXES.contains(&"ntp.org"));
    assert!(FAKEIP_FILTER_NTP_SUFFIXES.contains(&"time.apple.com"));
}

#[test]
fn keywords_are_ntp_stun_only() {
    assert_eq!(FAKEIP_FILTER_NTP_STUN_KEYWORDS, &["ntp", "stun"]);
}

#[test]
fn default_filter_is_captive_plus_ntp() {
    let d = default_fakeip_filter_domains();
    assert!(d.contains(&"captive.apple.com".to_string()));
    assert!(d.contains(&"ntp.org".to_string()));
    assert_eq!(
        d.len(),
        FAKEIP_FILTER_CAPTIVE_DOMAINS.len() + FAKEIP_FILTER_NTP_SUFFIXES.len()
    );
}
