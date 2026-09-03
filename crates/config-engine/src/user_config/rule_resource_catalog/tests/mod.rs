use super::*;

/// 内置清单 ≡ 随包清单（逐条同序）。投影让它恒成立，这条只是把恒等写成可执行的断言：
/// 谁把 `rule_resource_catalog()` 改回独立表，第一个撞上的就是它。
#[test]
fn catalog_is_exactly_the_bundled_table() {
    let ids: Vec<String> = rule_resource_catalog().into_iter().map(|i| i.id).collect();
    let tags: Vec<String> = builtin_geo_rulesets().into_iter().map(|b| b.tag).collect();
    assert_eq!(ids, tags);
}

#[test]
fn ids_are_unique() {
    let items = rule_resource_catalog();
    let mut ids: Vec<&str> = items.iter().map(|i| i.id.as_str()).collect();
    ids.sort_unstable();
    let before = ids.len();
    ids.dedup();
    assert_eq!(before, ids.len(), "catalog id 重复");
}

#[test]
fn geosite_path_and_id() {
    let i = find_catalog_item("geosite-youtube").unwrap();
    assert_eq!(i.path, "geo/geosite/youtube.srs");
    assert_eq!(i.category, "geosite");
    assert_eq!(i.name, "youtube");
}

/// `geosite-category-ai` 是全表唯一 tag 与上游文件名不同的一条：id/name 跟 tag，path 跟文件名。
/// 任一侧跟错，要么下载 404，要么建出的预设引用一个不随包的 tag 被静默剪掉。
#[test]
fn category_ai_keeps_tag_side_and_file_side_apart() {
    let i = find_catalog_item("geosite-category-ai").unwrap();
    assert_eq!(i.name, "category-ai");
    assert_eq!(i.path, "geo/geosite/category-ai-!cn.srs");
}

/// 精简版（`geo-lite/`）不再进内置清单：它们从不随包，且没有任何代码引用
/// （地区分流基线走 `geosite-cn`，不走 `geosite-lite-cn`）。仍可从「外置」tab 下载。
#[test]
fn lite_variants_are_not_builtin() {
    assert!(find_catalog_item("geosite-lite-cn").is_none());
    assert!(find_catalog_item("geoip-lite-cn").is_none());
}

#[test]
fn negated_name_preserved_in_path() {
    // 'geolocation-!cn' 含 '!'，不得被转义/清洗（下载 URL 逐字节要对）。
    let i = find_catalog_item("geosite-geolocation-!cn").unwrap();
    assert_eq!(i.path, "geo/geosite/geolocation-!cn.srs");
    assert_eq!(
        mrd_raw_url(&i.path),
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/geolocation-!cn.srs"
    );
}

#[test]
fn builtin_result_self_describes_source() {
    let r = builtin_catalog_result();
    assert_eq!(r.source, "builtin");
    assert!(r.fetched_at.is_none(), "内置回退不得谎报拉取时间");
    assert_eq!(r.items.len(), builtin_geo_rulesets().len());
}

/// 「内置」tab 里不得出现要联网才拿得到的条目 —— 那正是本次收敛消灭的形态：
/// 用户看到「内置」，点下去却要下载，下不下来就静默剪枝。
#[test]
fn every_builtin_item_is_bundled() {
    for i in rule_resource_catalog() {
        assert!(i.bundled, "{} 列在内置清单却不随包", i.id);
    }
    // 未随包的资源一律不在内置清单（要它们请走「外置」tab）。
    for id in ["geoip-us", "geosite-apple", "geosite-category-ads-all"] {
        assert!(
            find_catalog_item(id).is_none(),
            "{id} 未随包，不得进内置清单"
        );
    }
}

/// 内置条目的下载地址必须与随包更新腿的 `source_url()` 同址 —— 不同址就意味着同一份数据
/// 在「资源库下载」与「内置更新」两条腿会取到两个来源。
/// CN 三件套除外：它们的更新腿走 SagerNet release 资产，本就不是 MRD raw（见随包表注释）。
#[test]
fn catalog_url_matches_builtin_source_url() {
    use super::super::builtin_geo_rulesets::mrd_geo_raw_base;
    for b in builtin_geo_rulesets() {
        let url = b.source_url();
        if !url.starts_with(mrd_geo_raw_base()) {
            continue;
        }
        let item = find_catalog_item(&b.tag).unwrap();
        assert_eq!(mrd_raw_url(&item.path), url, "{} 两腿地址不一致", b.tag);
    }
}

#[test]
fn find_unknown_returns_none() {
    assert!(find_catalog_item("geosite-nonexistent").is_none());
}

// 「前端不得再有第二份 catalog 表」的门在 `tests/frontend_sot_guard.rs`（与预设表的同类门同处）。
