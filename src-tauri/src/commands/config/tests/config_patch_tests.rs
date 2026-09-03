use super::super::*;
use crate::test_support::{crate_code, TestDir};
use std::sync::Arc;

fn temp_dir(tag: &str) -> TestDir {
    TestDir::new(&format!("polaris-config-patch-{tag}-"))
}

fn patch(value: Value) -> serde_json::Map<String, Value> {
    value.as_object().cloned().expect("test patch is an object")
}

#[test]
fn patch_preserves_every_unmentioned_latest_field() {
    let dir = temp_dir("preserve");
    let manager = ConfigManager::new(dir.clone());
    manager
        .update(|config| {
            config["mixedPort"] = json!(7811);
            config["subscriptionUserAgent"] = json!("scheduler-new");
            Decision::Write(())
        })
        .unwrap();

    let (_, saved, changed) =
        config_patch_core(&manager, patch(json!({ "proxyModeType": "tun" }))).unwrap();
    assert!(changed);
    assert_eq!(saved["proxyModeType"], json!("tun"));
    assert_eq!(saved["mixedPort"], json!(7811));
    assert_eq!(saved["subscriptionUserAgent"], json!("scheduler-new"));
}

#[test]
fn concurrent_patches_on_distinct_fields_do_not_overwrite_each_other() {
    let dir = temp_dir("concurrent");
    let manager = Arc::new(ConfigManager::new(dir.clone()));
    manager.load_full().unwrap();
    let a = {
        let manager = Arc::clone(&manager);
        std::thread::spawn(move || {
            config_patch_core(&manager, patch(json!({ "mixedPort": 7812 }))).unwrap();
        })
    };
    let b = {
        let manager = Arc::clone(&manager);
        std::thread::spawn(move || {
            config_patch_core(&manager, patch(json!({ "logLevel": "debug" }))).unwrap();
        })
    };
    a.join().unwrap();
    b.join().unwrap();
    let saved = manager.current().unwrap();
    assert_eq!(saved["mixedPort"], json!(7812));
    assert_eq!(saved["logLevel"], json!("debug"));
}

fn entity(collection: &str, entity_id: &str, value: Value) -> ConfigEntityMutation {
    ConfigEntityMutation {
        collection: collection.to_string(),
        entity_id: entity_id.to_string(),
        value,
    }
}

#[test]
fn concurrent_entity_adds_to_the_same_collection_are_both_preserved() {
    let dir = temp_dir("entity-concurrent");
    let manager = Arc::new(ConfigManager::new(dir.clone()));
    manager.load_full().unwrap();
    let a = {
        let manager = Arc::clone(&manager);
        std::thread::spawn(move || {
            config_mutate_entities_core(
                &manager,
                &[entity(
                    "customAppPresets",
                    "app-a",
                    json!({ "id": "app-a", "name": "A" }),
                )],
            )
            .unwrap();
        })
    };
    let b = {
        let manager = Arc::clone(&manager);
        std::thread::spawn(move || {
            config_mutate_entities_core(
                &manager,
                &[entity(
                    "customAppPresets",
                    "app-b",
                    json!({ "id": "app-b", "name": "B" }),
                )],
            )
            .unwrap();
        })
    };
    a.join().unwrap();
    b.join().unwrap();
    let current = manager.current().unwrap();
    let ids: std::collections::HashSet<&str> = current["customAppPresets"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item["id"].as_str())
        .collect();
    assert!(ids.contains("app-a"));
    assert!(ids.contains("app-b"));
}

#[test]
fn multi_entity_mutation_is_all_or_nothing_and_deletion_is_journaled() {
    let dir = temp_dir("entity-atomic");
    let manager = ConfigManager::new(dir.clone());
    config_mutate_entities_core(
        &manager,
        &[
            entity(
                "customAppPresets",
                "app-a",
                json!({ "id": "app-a", "name": "A" }),
            ),
            entity(
                "appRules",
                "app-a",
                json!({ "appId": "app-a", "action": "direct", "enabled": true }),
            ),
        ],
    )
    .unwrap();

    let invalid = config_mutate_entities_core(
        &manager,
        &[
            entity("customAppPresets", "app-a", Value::Null),
            entity("unsupported", "app-a", Value::Null),
        ],
    );
    assert!(invalid.is_err());
    let unchanged = manager.current().unwrap();
    assert_eq!(unchanged["customAppPresets"].as_array().unwrap().len(), 1);
    assert_eq!(unchanged["appRules"].as_array().unwrap().len(), 1);

    config_mutate_entities_core(
        &manager,
        &[
            entity("customAppPresets", "app-a", Value::Null),
            entity("appRules", "app-a", Value::Null),
        ],
    )
    .unwrap();
    let removed = manager.current().unwrap();
    assert!(removed["customAppPresets"].as_array().unwrap().is_empty());
    assert!(removed["appRules"].as_array().unwrap().is_empty());

    let mut saw_icon = false;
    let summary = manager
        .process_deferred_deletions(|entry, _| {
            if matches!(
                entry,
                crate::runtime::config::DeferredConfigDeletion::AppIcon { app_id }
                    if app_id == "app-a"
            ) {
                saw_icon = true;
            }
            Ok(())
        })
        .unwrap();
    assert!(saw_icon);
    assert_eq!(summary.applied, 1);
}

#[test]
fn full_save_command_rejects_missing_version_before_touching_config() {
    let body = crate::commands::guard_scan::top_level_fn_body(
        &crate_code("commands/config.rs"),
        "pub fn config_save(",
    );
    let guard = body
        .find("if base_version.is_none()")
        .expect("无版本整份覆盖必须 fail-closed");
    let write = body.find("config_save_core(").expect("版本化保存腿仍在");
    assert!(guard < write, "版本闸必须先于任何整份配置写入");
}

#[test]
fn staged_full_save_never_blindly_clears_the_backend_marker() {
    let body = crate::commands::guard_scan::top_level_fn_body(
        &crate_code("commands/config.rs"),
        "pub fn config_save(",
    );
    assert!(body.contains("config_save_core("), "暂存保存核心仍在");
    assert!(body.contains("SaveOutcome::Conflict"), "冲突腿必须单独返回");
    assert!(
        !body.contains("set_staged_pending(false)"),
        "保存命令看不到在途新草稿，不得盲清跨入口 marker"
    );
}

#[test]
fn config_broadcast_routes_through_the_persisted_stale_guard() {
    let body = crate::commands::guard_scan::top_level_fn_body(
        &crate_code("commands/config.rs"),
        "pub(crate) fn broadcast_config_changed_with(",
    );
    assert!(
        body.contains("switch_persisted_config_if_current(")
            && body.contains("intent_generation,")
            && body.contains("move |current|"),
        "配置广播不得直调 switch_mode_with；否则乱序 task 可把运行核退回旧快照"
    );
    assert!(
        body.contains("apply_process_config_projections(&app, current)"),
        "App 日志/原生主题投影也必须在同一过期广播闸门之后"
    );
    assert!(
        !body.contains("proxy.switch_mode_with("),
        "旧入口会跳过磁盘真值复核"
    );
}

fn valid_node(id: &str) -> Value {
    json!({
        "id": id,
        "name": id,
        "protocol": "vless",
        "address": "node.example",
        "port": 443,
        "uuid": "00000000-0000-0000-0000-000000000001"
    })
}

#[test]
fn full_save_returns_the_old_exit_from_the_same_locked_transaction() {
    let dir = temp_dir("full-save-old-exit");
    let manager = ConfigManager::new(dir.clone());
    let mut latest = manager.load_full().unwrap();
    latest["servers"] = json!([valid_node("node-a")]);
    latest["selectedServerId"] = json!("node-a");
    manager.save_full(&latest).unwrap();

    let mut submitted = latest;
    submitted["selectedServerId"] = json!("__direct__");
    let (_, old_selected) =
        config_save_core(&manager, &mut submitted, None, false).expect("save 应成功");

    assert_eq!(old_selected.as_deref(), Some("node-a"));
    assert_eq!(submitted["selectedServerId"], json!("__direct__"));
}

#[test]
fn backup_import_returns_latest_locked_exit_not_its_stale_merge_base() {
    let dir = temp_dir("backup-old-exit");
    let manager = ConfigManager::new(dir.clone());
    let base = manager.load_full().unwrap();
    let mut restored = base.clone();
    restored["selectedServerId"] = json!("__block__");

    // 导入预览后、真提交前，另一 writer 把出口切到 node-a。旧出口必须取这一刻，
    // 不能继续用打开导入时的 base。
    let mut latest = base.clone();
    latest["servers"] = json!([valid_node("node-a")]);
    latest["selectedServerId"] = json!("node-a");
    manager.save_full(&latest).unwrap();

    let old_selected =
        backup_import_save_core(&manager, &base, &mut restored).expect("导入事务应成功");
    assert_eq!(old_selected.as_deref(), Some("node-a"));
    assert_eq!(restored["selectedServerId"], json!("__block__"));
    assert_eq!(restored["servers"], json!([valid_node("node-a")]));
}
