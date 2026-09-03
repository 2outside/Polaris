use super::super::*;
use crate::commands::subscription::SUBSCRIPTION_USER_AGENT_KEY;
use crate::runtime::config::ConfigManager;
use crate::test_support::{crate_code, TestDir};

fn temp_dir(tag: &str) -> TestDir {
    TestDir::new(&format!("polaris-ua-invalidate-{tag}-"))
}

/// 盘上先有一条已拉取过（带验证器）的订阅 + 一条自带 per-sub UA 的订阅。
fn seed(mgr: &ConfigManager, global_ua: &str) {
    let mut cfg = mgr.load_full().unwrap();
    cfg["subscriptionUserAgent"] = json!(global_ua);
    cfg["subscriptions"] = json!([
        {
            "id": "s-global",
            "name": "跟随全局",
            "url": "https://example.invalid/a",
            "etag": "W/\"v1\"",
            "lastModified": "Mon, 01 Jan 2024 00:00:00 GMT",
        },
        {
            "id": "s-own",
            "name": "自带 UA",
            "url": "https://example.invalid/b",
            "userAgent": "mihomo/1.18",
            "etag": "W/\"v2\"",
            "lastModified": "Tue, 02 Jan 2024 00:00:00 GMT",
        },
    ]);
    mgr.save_full(&cfg).unwrap();
}

fn sub<'a>(cfg: &'a Value, id: &str) -> &'a Value {
    cfg["subscriptions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == json!(id))
        .unwrap()
}

/// **全量保存腿**（设置页改全局 UA 后 `saveConfig({...config})` 的真实形态）。
///
/// 牙：删掉 `config_save_core` 里的 `invalidate_stale_subscription_validators(...)` 调用 →
/// 前两条断言转红（= 改了全局 UA 仍带旧 ETag 请求，机场按 UA 下发变体时恒 304，新格式永远拿不到）。
#[test]
fn full_save_with_new_global_ua_drops_validators_of_affected_subs() {
    let dir = temp_dir("save");
    let mgr = ConfigManager::new(dir.clone());
    seed(&mgr, "clash-verge/1.0");

    // 前端提交全量 config，只把全局 UA 改了。
    let mut submitted = mgr.load_full().unwrap();
    submitted["subscriptionUserAgent"] = json!("sing-box/1.9");
    config_save_core(&mgr, &mut submitted, None, false).expect("save 应成功");

    let on_disk = ConfigManager::new(dir.clone()).load_full().unwrap();
    assert!(
        sub(&on_disk, "s-global").get("etag").is_none(),
        "全局 UA 变了 → 跟随全局的订阅 etag 必须作废"
    );
    assert!(
        sub(&on_disk, "s-global").get("lastModified").is_none(),
        "lastModified 同样必须作废（两者任一残留都足以让服务端回 304）"
    );
    assert_eq!(
        sub(&on_disk, "s-own")["etag"],
        json!("W/\"v2\""),
        "per-sub 覆盖的订阅生效 UA 没变 → 验证器不得白扔"
    );
    assert_eq!(
        on_disk["subscriptionUserAgent"],
        json!("sing-box/1.9"),
        "UA 本身照常落盘"
    );
}

/// 无关键的全量保存**绝不**碰验证器（否则每改一次设置就把下次订阅更新变成全量下载）。
///
/// 牙：把作废判据改成「无条件清」/「只要有 subscriptions 就清」→ 本条转红。
#[test]
fn full_save_without_ua_change_keeps_validators() {
    let dir = temp_dir("noop");
    let mgr = ConfigManager::new(dir.clone());
    seed(&mgr, "clash-verge/1.0");

    let mut submitted = mgr.load_full().unwrap();
    submitted["logLevel"] = json!("debug");
    config_save_core(&mgr, &mut submitted, None, false).expect("save 应成功");

    let on_disk = ConfigManager::new(dir.clone()).load_full().unwrap();
    assert_eq!(sub(&on_disk, "s-global")["etag"], json!("W/\"v1\""));
    assert_eq!(
        sub(&on_disk, "s-global")["lastModified"],
        json!("Mon, 01 Jan 2024 00:00:00 GMT")
    );
    assert_eq!(sub(&on_disk, "s-own")["etag"], json!("W/\"v2\""));
}

/// **备份导入腿**（`backup:importApply` 勾「通用设置」）：第三条能改全局 UA 的写路径。
///
/// # 为什么这条腿必须独立存在
///
/// `subscriptionUserAgent` 按排除法属 generalSettings 类（既不在 `DATA_FIELDS` 也不在
/// `EXCLUDED_FROM_BACKUP`，见 `polaris_store::backup`）⇒ 勾了通用设置的导入就能把全局 UA 换掉，
/// 而**不勾订阅类**时本机订阅的 `etag`/`lastModified` 原样留着 ⇒ 换 UA 后恒 304、新格式永远拿不到。
/// 上面两条用例（`config:save` / `config:setValue`）对这条腿是**恒绿**的。
///
/// 驱动方式与命令层逐字同形：`merge_categories(current, backup, [GeneralSettings])`
/// → [`backup_import_save_core`]。
///
/// 牙：删掉 `backup_import_save_core` 里的 `invalidate_validators_on_global_ua_change(...)`
/// → 前两条断言转红。
#[test]
fn backup_import_of_general_settings_drops_validators_of_affected_subs() {
    let dir = temp_dir("backup-import");
    let mgr = ConfigManager::new(dir.clone());
    seed(&mgr, "clash-verge/1.0");
    let current = mgr.load_full().unwrap();

    // 外机备份：只有通用设置被勾，且它带着**不同**的全局 UA。
    let mut backup = current.clone();
    backup["subscriptionUserAgent"] = json!("sing-box/1.9");
    let outcome = polaris_store::backup::merge_categories(
        &current,
        &backup,
        &[polaris_store::backup::BackupCategory::GeneralSettings],
    );
    let mut restored = outcome.config;
    backup_import_save_core(&mgr, &current, &mut restored).expect("导入落盘应成功");

    let on_disk = ConfigManager::new(dir.clone()).load_full().unwrap();
    assert_eq!(
        on_disk["subscriptionUserAgent"],
        json!("sing-box/1.9"),
        "备份里的全局 UA 照常落盘（前提：这条腿确实能改 UA）"
    );
    assert!(
        sub(&on_disk, "s-global").get("etag").is_none()
            && sub(&on_disk, "s-global").get("lastModified").is_none(),
        "导入换了全局 UA → 跟随全局的订阅验证器必须作废，否则换 UA 后恒 304"
    );
    assert_eq!(
        sub(&on_disk, "s-own")["etag"],
        json!("W/\"v2\""),
        "per-sub 覆盖的订阅生效 UA 没变 → 验证器不得白扔（射程限制）"
    );
}

/// 备份里的全局 UA 与本机**相同** → 一条验证器都不许扔（否则每次导入都把下次订阅更新变成全量下载）。
///
/// 牙：把作废判据改成「导入即无条件清」→ 本条转红。
#[test]
fn backup_import_with_same_ua_keeps_validators() {
    let dir = temp_dir("backup-import-noop");
    let mgr = ConfigManager::new(dir.clone());
    seed(&mgr, "clash-verge/1.0");
    let current = mgr.load_full().unwrap();

    let mut backup = current.clone();
    backup["logLevel"] = json!("debug"); // 通用设置有变化，但 UA 没变
    let outcome = polaris_store::backup::merge_categories(
        &current,
        &backup,
        &[polaris_store::backup::BackupCategory::GeneralSettings],
    );
    let mut restored = outcome.config;
    backup_import_save_core(&mgr, &current, &mut restored).expect("导入落盘应成功");

    let on_disk = ConfigManager::new(dir.clone()).load_full().unwrap();
    assert_eq!(on_disk["logLevel"], json!("debug"), "通用设置照常导入");
    assert_eq!(sub(&on_disk, "s-global")["etag"], json!("W/\"v1\""));
    assert_eq!(
        sub(&on_disk, "s-global")["lastModified"],
        json!("Mon, 01 Jan 2024 00:00:00 GMT")
    );
    assert_eq!(sub(&on_disk, "s-own")["etag"], json!("W/\"v2\""));
}

/// **单键写腿**（`config:setValue("subscriptionUserAgent", …)`）：同一条不变式。
///
/// 牙：把 `config_set_value` 里的 `set_value_with_ua_invalidation` 改回
/// `state.config().set_value(...)` → 本条转红（上面两条全量保存的用例**不会**红，
/// 这正是本条必须独立存在的理由）。
#[test]
fn set_value_leg_drops_validators_too() {
    let dir = temp_dir("setvalue");
    let mgr = ConfigManager::new(dir.clone());
    seed(&mgr, "clash-verge/1.0");

    let (_, returned, changed) =
        set_value_with_ua_invalidation(&mgr, SUBSCRIPTION_USER_AGENT_KEY, json!("sing-box/1.9"))
            .expect("置键应成功");
    assert!(changed);
    assert_eq!(
        returned["subscriptionUserAgent"],
        json!("sing-box/1.9"),
        "返回值须是置键后的新配置（`set_value` 的既有契约，广播要用它）"
    );

    let on_disk = ConfigManager::new(dir.clone()).load_full().unwrap();
    assert!(sub(&on_disk, "s-global").get("etag").is_none());
    assert!(sub(&on_disk, "s-global").get("lastModified").is_none());
    assert_eq!(sub(&on_disk, "s-own")["etag"], json!("W/\"v2\""));
}

/// 非 UA 键走单键写腿时**逐字等价于原路径**：只改目标键，验证器一动不动。
#[test]
fn set_value_of_unrelated_key_is_byte_for_byte_the_old_path() {
    let dir = temp_dir("setvalue-other");
    let mgr = ConfigManager::new(dir.clone());
    seed(&mgr, "clash-verge/1.0");

    let (_, _, changed) =
        set_value_with_ua_invalidation(&mgr, "logLevel", json!("debug")).expect("置键应成功");
    assert!(changed);

    let on_disk = ConfigManager::new(dir.clone()).load_full().unwrap();
    assert_eq!(on_disk["logLevel"], json!("debug"));
    assert_eq!(sub(&on_disk, "s-global")["etag"], json!("W/\"v1\""));
    assert_eq!(sub(&on_disk, "s-own")["etag"], json!("W/\"v2\""));

    let (_, same, changed_again) =
        set_value_with_ua_invalidation(&mgr, "logLevel", json!("debug")).expect("同值置键仍是成功");
    assert!(!changed_again, "同值写入不应广播或触发入核评估");
    assert_eq!(same, on_disk, "no-op 仍返回同一事务内的权威快照");
}

/// 🟡 **接线守卫**：`config_set_value` 命令壳持 `State<AppRuntime>`、单测直调不了，
/// 故按本仓既有做法用源码扫描锁住「它走的是 UA 感知包装、不是裸 `set_value`」。
///
/// 变异探针：把那一行改回 `state.config().set_value(&key, value)` ⇒ 本条转红。
#[test]
fn set_value_command_routes_through_the_ua_aware_wrapper() {
    let src = crate_code("commands/config.rs");
    let body = crate::commands::guard_scan::top_level_fn_body(&src, "pub fn config_set_value(");
    assert!(
        body.contains("set_value_with_ua_invalidation("),
        "变异锁：单键写腿绕过了 UA 感知包装 → 经 setValue 改全局 UA 后验证器不清，恒 304"
    );
    assert!(
        !body.contains("state.config().set_value("),
        "裸 set_value 不得再出现在本命令里（双路径 = 迟早只改一条）"
    );
}

/// 🟡 **顺序守卫**：作废必须排在 update 闭包的配置提交之前 —— 提交后再清等于没清。
#[test]
fn invalidation_happens_before_the_write() {
    let src = crate_code("commands/config.rs");
    let body = crate::commands::guard_scan::top_level_fn_body(&src, "fn config_save_core(");
    let transaction = body
        .find("config.update_with_cleanup(defer_cleanup, |current|")
        .expect("全量保存必须走原子配置事务");
    let at = body
        .find("invalidate_validators_on_global_ua_change(")
        .expect("变异锁：全量保存腿的验证器作废被删了");
    let write = body.find("*current = next").expect("事务提交腿仍在");
    assert!(
        transaction < at && at < write,
        "作废必须在原子事务内、提交之前"
    );
}
