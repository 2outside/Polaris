use super::super::*;

fn cfg_with_resource() -> Value {
    json!({
        // servers 是 UserConfig 必填键（无 serde default）——真实 config 恒有；测试须显式给。
        "servers": [],
        "ruleResources": [{
            "id": "res_a", "name": "A", "category": "custom",
            "sourceUrl": "https://e/a.srs", "fileName": "res_a.srs",
            "format": "binary", "size": 1, "downloadedAt": "t"
        }],
        "customRules": [],
        "appRules": [],
    })
}

#[test]
fn plan_delete_missing_is_idempotent_notfound() {
    let cfg = cfg_with_resource();
    assert!(matches!(
        plan_resource_delete(&cfg, "ghost", false),
        ResourceDeletePlan::NotFound
    ));
}

#[test]
fn plan_delete_unreferenced_proceeds() {
    let cfg = cfg_with_resource();
    assert!(matches!(
        plan_resource_delete(&cfg, "res_a", false),
        ResourceDeletePlan::Proceed
    ));
}

#[test]
fn plan_delete_referenced_needs_confirm_unless_forced() {
    // 一条已启用 ruleSet 规则引用 res:res_a（mirror 形态，conditions 缺省回落 type+values）。
    let mut cfg = cfg_with_resource();
    cfg["customRules"] = json!([{
        "id": "r1", "type": "ruleSet", "values": ["res:res_a"],
        "action": "proxy", "enabled": true
    }]);
    match plan_resource_delete(&cfg, "res_a", false) {
        ResourceDeletePlan::NeedConfirm(refs) => {
            assert!(
                !refs.is_empty(),
                "被引用须回 needConfirm + referencingRules"
            );
            assert_eq!(refs[0].id, "r1");
        }
        other => panic!("被引用且未 force 应 needConfirm，实得: {other:?}"),
    }
    // force=true → 覆盖确认，直接 Proceed。
    assert!(matches!(
        plan_resource_delete(&cfg, "res_a", true),
        ResourceDeletePlan::Proceed
    ));
    // 已禁用的引用规则不算引用（enumerate 只扫已启用）→ 可直接删。
    cfg["customRules"] = json!([{
        "id": "r1", "type": "ruleSet", "values": ["res:res_a"],
        "action": "proxy", "enabled": false
    }]);
    assert!(matches!(
        plan_resource_delete(&cfg, "res_a", false),
        ResourceDeletePlan::Proceed
    ));
}

#[test]
fn deferred_delete_reference_check_uses_the_sanitized_disk_path() {
    let cfg = json!({
        "ruleResources": [{ "id": "new", "fileName": "same?path.srs" }]
    });
    assert!(
        rule_resource_file_is_referenced(&cfg, "same/path.srs"),
        "不同原始文件名落到同一路径时，旧删除意图必须让位给新资源"
    );
}

#[test]
fn deferred_delete_never_unlinks_the_catalog_cache() {
    let dir = std::env::temp_dir().join(format!(
        "polaris-resource-delete-reserved-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos())
    ));
    let resource_dir = dir.join("rule-resource");
    std::fs::create_dir_all(&resource_dir).unwrap();
    let catalog = resource_dir.join(CATALOG_CACHE_FILE);
    std::fs::write(&catalog, b"catalog").unwrap();

    remove_rule_resource_file(&dir, CATALOG_CACHE_FILE).unwrap();
    assert!(catalog.exists(), "配置篡改也不得借资源删除清掉目录缓存");
    let _ = std::fs::remove_dir_all(&dir);
}
