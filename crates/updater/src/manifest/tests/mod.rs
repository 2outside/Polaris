use super::*;

fn entry(version: &str, url: &str, sha: Option<&str>) -> VersionManifestEntry {
    VersionManifestEntry {
        version: version.to_string(),
        url: url.to_string(),
        sha256: sha.map(String::from),
        prerelease: false,
        notes: String::new(),
    }
}

#[test]
fn from_single_json_parses() {
    let json = r#"{"version":"1.14.0","url":"https://x/core","sha256":"abc"}"#;
    // sha256 "abc" 不合法 → 报错。
    let err = VersionManifest::from_single_json(json).unwrap_err();
    assert_eq!(err, ManifestError::InvalidSha256("abc".to_string()));

    let valid = format!(
        r#"{{"version":"1.14.0","url":"https://x/core","sha256":"{}"}}"#,
        "a".repeat(64)
    );
    let m = VersionManifest::from_single_json(&valid).unwrap();
    assert_eq!(m.entries.len(), 1);
    assert_eq!(m.entries[0].version, "1.14.0");
    assert_eq!(
        m.entries[0].sha256.as_deref(),
        Some("a".repeat(64).as_str())
    );
}

#[test]
fn from_array_json_parses_and_validates() {
    let json = format!(
        r#"[{{"version":"1.13.13","url":"u1"}},{{"version":"1.14.0","url":"u2","sha256":"{}"}}]"#,
        "b".repeat(64)
    );
    let m = VersionManifest::from_array_json(&json).unwrap();
    assert_eq!(m.entries.len(), 2);
    // 第二条有 sha256。
    assert!(m.entries[1].sha256.is_some());
    // 第一条无 sha256（可选字段）。
    assert!(m.entries[0].sha256.is_none());
}

#[test]
fn latest_finds_newest_formal() {
    let m = VersionManifest::from_entries(vec![
        entry("1.13.13", "u1", None),
        entry("1.14.0", "u2", None),
        entry("1.13.15", "u3", None),
    ]);
    // 当前 1.13.13 → 最新应 1.14.0。
    let latest = m.latest("1.13.13", false, None).unwrap().unwrap();
    assert_eq!(latest.version, "1.14.0");
}

#[test]
fn latest_filters_prerelease() {
    let mut pre = entry("1.15.0-beta.1", "u-pre", None);
    pre.prerelease = true;
    let m = VersionManifest::from_entries(vec![entry("1.14.0", "u1", None), pre]);
    // include_prerelease=false → 跳过 beta，返回 1.14.0。
    let latest = m.latest("1.13.0", false, None).unwrap().unwrap();
    assert_eq!(latest.version, "1.14.0");
    // include_prerelease=true → 返回 beta。
    let latest = m.latest("1.13.0", true, None).unwrap().unwrap();
    assert_eq!(latest.version, "1.15.0-beta.1");
}

#[test]
fn latest_cross_band_restriction() {
    let m = VersionManifest::from_entries(vec![
        entry("1.13.14", "u1", None),
        entry("1.14.0", "u2", None), // 跨带（1.13 → 1.14）
    ]);
    // 当前 1.13.13，restrict 同带 → 返回 1.13.14（1.14.0 被硬闸拦）。
    let latest = m.latest("1.13.13", false, Some(true)).unwrap().unwrap();
    assert_eq!(latest.version, "1.13.14");
    // 不 restrict → 返回 1.14.0。
    let latest = m.latest("1.13.13", false, Some(false)).unwrap().unwrap();
    assert_eq!(latest.version, "1.14.0");
}

#[test]
fn latest_none_when_already_newest() {
    let m = VersionManifest::from_entries(vec![entry("1.14.0", "u1", None)]);
    // 当前已是 1.14.0 → 无更新（None）。
    assert!(m.latest("1.14.0", false, None).unwrap().is_none());
    assert!(!m.has_update("1.14.0", false, None).unwrap());
}

#[test]
fn latest_none_when_all_filtered() {
    let m = VersionManifest::from_entries(vec![]);
    // 空清单 → latest 返回 None（不报错，has_update=false）。
    assert!(m.latest("1.0.0", false, None).unwrap().is_none());
}

#[test]
fn entry_validate_rejects_bad_version_and_hash() {
    let bad_ver = VersionManifestEntry {
        version: String::new(),
        url: "u".into(),
        sha256: None,
        prerelease: false,
        notes: String::new(),
    };
    assert_eq!(
        bad_ver.validate(),
        Err(ManifestError::InvalidVersion(String::new()))
    );

    let bad_hash = VersionManifestEntry {
        version: "1.0.0".into(),
        url: "u".into(),
        sha256: Some("tooshort".into()),
        prerelease: false,
        notes: String::new(),
    };
    assert_eq!(
        bad_hash.validate(),
        Err(ManifestError::InvalidSha256("tooshort".into()))
    );
}

#[test]
fn substring_selector_picks_match() {
    let sel = SubstringSelector::new("linux-amd64");
    let assets = vec![
        "sing-box-1.14.0-darwin-arm64.tar.gz".to_string(),
        "sing-box-1.14.0-linux-amd64.tar.gz".to_string(),
        "sing-box-1.14.0-windows-amd64.zip".to_string(),
    ];
    let picked = sel.select(&assets).unwrap();
    assert!(picked.contains("linux-amd64"));

    // 无匹配 → None。
    let sel2 = SubstringSelector::new("freebsd");
    assert!(sel2.select(&assets).is_none());
}

#[test]
fn entry_display() {
    let e = entry("1.14.0", "https://x/core", None);
    assert_eq!(e.to_string(), "v1.14.0 (https://x/core)");

    let mut pre = e;
    pre.prerelease = true;
    assert_eq!(pre.to_string(), "v1.14.0 (https://x/core) [prerelease]");
}
