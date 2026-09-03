use super::*;

#[test]
fn default_is_cn_forward() {
    let rr = default_region_routing();
    assert!(rr.enabled);
    assert_eq!(rr.region, "cn");
    assert!(!rr.reverse);
}

#[test]
fn effective_none_uses_default() {
    let rr = effective_region_routing(None);
    assert_eq!(rr.region, "cn");
    assert!(rr.enabled);
}

#[test]
fn local_geo_cn() {
    let g = region_local_geo("cn").unwrap();
    assert_eq!(g.geosite, vec!["geosite-cn".to_string()]);
    assert_eq!(g.geoip, vec!["geoip-cn".to_string()]);
}

#[test]
fn local_geo_unknown_returns_none() {
    assert!(region_local_geo("us").is_none());
}

#[test]
fn all_regions_resolve() {
    // 表里挂了个 `region_local_geo` 不认的 id → 那道门会把它的 geo 当「无消费点」，
    // 得到一个反向的假红。
    for r in ALL_REGIONS {
        assert!(
            region_local_geo(r).is_some(),
            "ALL_REGIONS 里的 {r} 查不到 geo"
        );
    }
}

#[test]
fn foreign_geo_cn_has_noncn() {
    let g = region_foreign_geo("cn");
    assert_eq!(g, vec!["geosite-geolocation-!cn".to_string()]);
}

#[test]
fn foreign_geo_ir_empty() {
    assert!(region_foreign_geo("ir").is_empty());
}

#[test]
fn smart_baseline_smart_cn_enabled() {
    let rr = default_region_routing();
    let tags = smart_baseline_geo_tags("smart", Some(&rr));
    assert!(tags.contains("geosite-cn"));
    assert!(tags.contains("geoip-cn"));
    assert!(tags.contains("geosite-geolocation-!cn"));
}

#[test]
fn smart_baseline_global_returns_empty() {
    let rr = default_region_routing();
    let tags = smart_baseline_geo_tags("global", Some(&rr));
    assert!(tags.is_empty());
}

#[test]
fn smart_baseline_smart_disabled_returns_empty() {
    let rr = RegionRoutingConfig {
        enabled: false,
        region: "cn".into(),
        reverse: false,
    };
    let tags = smart_baseline_geo_tags("smart", Some(&rr));
    assert!(tags.is_empty());
}

#[test]
fn smart_baseline_smart_unknown_region_returns_empty() {
    let rr = RegionRoutingConfig {
        enabled: true,
        region: "us".into(),
        reverse: false,
    };
    let tags = smart_baseline_geo_tags("smart", Some(&rr));
    assert!(tags.is_empty());
}
