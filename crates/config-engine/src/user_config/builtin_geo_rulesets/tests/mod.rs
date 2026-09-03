use super::*;

#[test]
fn cn_three_present() {
    let all = builtin_geo_rulesets();
    assert!(all.iter().any(|b| b.tag == "geosite-cn"));
    assert!(all.iter().any(|b| b.tag == "geosite-geolocation-!cn"));
    assert!(all.iter().any(|b| b.tag == "geoip-cn"));
}

#[test]
fn app_geosite_youtube_present() {
    let all = builtin_geo_rulesets();
    assert!(all.iter().any(|b| b.tag == "geosite-youtube"));
}

#[test]
fn category_ai_uses_noncn_filename() {
    let all = builtin_geo_rulesets();
    let ai = all.iter().find(|b| b.tag == "geosite-category-ai").unwrap();
    assert_eq!(ai.file_name, "geosite-category-ai-!cn.srs");
}

/// CN 三件套走 SagerNet **release 资产**，资产名 = file_name。
/// 混成 MetaCubeX raw 路径就是 404 —— 这条锁住两个源不串。
#[test]
fn cn_baseline_source_url_is_sagernet_release() {
    let all = builtin_geo_rulesets();
    let by = |t: &str| all.iter().find(|b| b.tag == t).unwrap().source_url();
    assert_eq!(
        by("geoip-cn"),
        "https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip-cn.srs"
    );
    assert_eq!(
        by("geosite-cn"),
        "https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite-cn.srs"
    );
    assert_eq!(
        by("geosite-geolocation-!cn"),
        "https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite-geolocation-!cn.srs"
    );
}

/// MRD 那支：目录带分类、**文件名是裸名**（不是 `geosite-youtube.srs`）。
/// 与 `rule_resource_catalog::catalog_item` 的 path 派生同构 —— 不同构就意味着同一份数据
/// 在「资源库下载」和「内置更新」两条腿会取到两个地址。
#[test]
fn mrd_source_url_uses_bare_file_name() {
    let all = builtin_geo_rulesets();
    let by = |t: &str| all.iter().find(|b| b.tag == t).unwrap().source_url();
    assert_eq!(
        by("geosite-youtube"),
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/youtube.srs"
    );
    assert_eq!(
        by("geoip-private"),
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/private.srs"
    );
    // category-ai 的改名在 file_name 里已固化，source_url 不再判一次。
    assert_eq!(
        by("geosite-category-ai"),
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/category-ai-!cn.srs"
    );
}

/// 每个内置集都推得出一条 https 地址，且互不重复 —— 重复即意味着两个 tag 更新时会互相覆盖。
#[test]
fn every_builtin_has_a_unique_https_source_url() {
    let urls: Vec<String> = builtin_geo_rulesets()
        .iter()
        .map(BuiltinGeoRuleSet::source_url)
        .collect();
    assert!(urls.iter().all(|u| u.starts_with("https://")), "{urls:?}");
    let uniq: HashSet<&String> = urls.iter().collect();
    assert_eq!(
        uniq.len(),
        urls.len(),
        "内置 geo 的 sourceUrl 出现重复：{urls:?}"
    );
}

#[test]
fn resolve_builtin_ref_meta_known() {
    let (tag, file) = resolve_builtin_rule_set_ref_meta("builtin:geosite-cn").unwrap();
    assert_eq!(tag, "geosite-cn");
    assert_eq!(file, "geosite-cn.srs");
}

#[test]
fn resolve_builtin_ref_meta_unknown_tag() {
    assert!(resolve_builtin_rule_set_ref_meta("builtin:nonexistent").is_none());
}

#[test]
fn resolve_builtin_ref_meta_non_builtin() {
    assert!(resolve_builtin_rule_set_ref_meta("res:geosite-cn").is_none());
}

#[test]
fn is_builtin_id_checks_prefix() {
    assert!(is_builtin_id("builtin:geosite-cn"));
    assert!(!is_builtin_id("res:geosite-cn"));
}

#[test]
fn builtin_tag_from_id_strips_prefix() {
    assert_eq!(builtin_tag_from_id("builtin:geoip-cn"), "geoip-cn");
}

#[test]
fn srs_magic_bytes() {
    assert!(is_valid_srs_bytes([0x53, 0x52, 0x53]));
    assert!(!is_valid_srs_bytes([0x00, 0x52, 0x53]));
    assert!(!is_valid_srs_bytes([0x53, 0x52, 0x00]));
}

#[test]
fn app_geo_tags_include_youtube_telegram() {
    let (gs, gp) = app_geo_tags();
    assert!(gs.contains("geosite-youtube"));
    assert!(gs.contains("geosite-telegram"));
    assert!(gp.contains("geoip-telegram"));
}

#[test]
fn bundled_tag_predicate_matches_the_table() {
    // 随包判定必须与表本身逐条同步：表里每一项都得判真（漏一条 → UI 把已随包的资源标成「可下载」，
    // 用户下回来的副本在 route.rs 里恒被随包项挡住 = 白下）。
    for b in builtin_geo_rulesets() {
        assert!(is_bundled_geo_tag(&b.tag), "表内 tag {} 应判随包", b.tag);
    }
    // 反向对照：上游 meta-rules-dat 里存在但**不随包**的 tag 必须判假。
    // 没有这条腿，把 `is_bundled_geo_tag` 改成 `true` 也能全绿 —— 正是它给这道门装上牙。
    //（81a4e68 之前这里的理由是「内置 tab 33 条精选 ⊅ 随包 28 条」，那个设计已废：
    // 内置清单现在就是随包表的投影，二者恒等。下面这些 tag 如今只出现在资源库的「外置」tab，
    // 「已内置」标签由同一个判据现算。）
    for tag in [
        "geoip-us",
        "geoip-jp",
        "geosite-apple",
        "geosite-bilibili",
        "geosite-category-ads-all",
        // lite 变体的 id 形如 `geosite-lite-cn`，与随包 tag `geosite-cn` 不同名 → 不随包。
        "geosite-lite-cn",
        "geoip-lite-cn",
    ] {
        assert!(!is_bundled_geo_tag(tag), "{tag} 未随包，不得判真");
    }
}

#[test]
fn region_geo_ir_ru_present() {
    let all = builtin_geo_rulesets();
    assert!(all.iter().any(|b| b.tag == "geosite-category-ir"));
    assert!(all.iter().any(|b| b.tag == "geosite-category-ru"));
    assert!(all.iter().any(|b| b.tag == "geoip-ir"));
    assert!(all.iter().any(|b| b.tag == "geoip-ru"));
}
