use super::*;
use crate::test_support::TestDir;

fn temp_dir(tag: &str) -> TestDir {
    TestDir::new(&format!("polaris-misc-test-{tag}-"))
}

/// A6：清面板缓存目录须真删（变异：`clear_singbox_dashboard_cache` 退回 no-op 桩时此断言转红）。
#[test]
fn clear_dashboard_cache_removes_existing_dir() {
    let root = temp_dir("dash-clear");
    let dash = root.join(SINGBOX_DASHBOARD_DIR);
    std::fs::create_dir_all(&dash).unwrap();
    std::fs::write(dash.join("index.html"), b"<html></html>").unwrap();
    std::fs::write(dash.join(".etag"), b"abc").unwrap();
    assert!(dash.exists(), "前置：缓存目录应存在");

    clear_singbox_dashboard_cache(&dash);

    assert!(!dash.exists(), "清缓存后目录须被删除");
    let _ = std::fs::remove_dir_all(&root);
}

/// A6：目录不存在时清理须幂等、不 panic（best-effort 语义，对齐 上游 `force: true`）。
#[test]
fn clear_dashboard_cache_missing_dir_is_noop() {
    let root = temp_dir("dash-missing");
    let dash = root.join(SINGBOX_DASHBOARD_DIR); // 从未创建
    assert!(!dash.exists());
    clear_singbox_dashboard_cache(&dash);
    assert!(!dash.exists());
    let _ = std::fs::remove_dir_all(&root);
}

/// 面板语言映射：繁体前缀 → zh-Hant；简体/其它 zh → zh-Hans；fa/ru 命中；缺省/未知 → en。
#[test]
fn dashboard_lang_maps_by_prefix() {
    assert_eq!(map_locale_to_dashboard_lang(Some("zh-CN")), "zh-Hans");
    assert_eq!(map_locale_to_dashboard_lang(Some("zh-Hans")), "zh-Hans");
    assert_eq!(map_locale_to_dashboard_lang(Some("zh-TW")), "zh-Hant");
    assert_eq!(map_locale_to_dashboard_lang(Some("zh-Hant")), "zh-Hant");
    assert_eq!(map_locale_to_dashboard_lang(Some("fa-IR")), "fa");
    assert_eq!(map_locale_to_dashboard_lang(Some("ru")), "ru");
    assert_eq!(map_locale_to_dashboard_lang(Some("en-US")), "en");
    assert_eq!(map_locale_to_dashboard_lang(None), "en");
}

/// preload 脚本：写两个权威键 + 语言键；且**含引号的 secret 经双重序列化后不破坏脚本**（防注入）。
/// 变异门：把 `serde_json::to_string(&…to_string())` 退成裸拼接 → 含 `"` 的 secret 会截断字面量 →
/// 解析出的 JSON 不再含完整 secret → 下面 `payload["secret"]` 断言转红。
#[test]
fn dashboard_preload_script_injects_keys_and_escapes_secret() {
    let evil_secret = r#"a"b\c'd"#; // 引号 + 反斜杠 + 单引号
    let s = build_dashboard_preload_script("127.0.0.1:9090", evil_secret, "zh-Hans");
    assert!(s.contains("sing-box-dashboard.servers"));
    assert!(s.contains("sing-box-dashboard.server'"), "须写旧版迁移键");
    assert!(s.contains("sing-box-dashboard.language"));

    // 提取 servers setItem 的 JS 字面量 → 反序列化两层 → 校验 secret/url 完整无损。
    let marker = "ls.setItem('sing-box-dashboard.servers',";
    let start = s.find(marker).unwrap() + marker.len();
    let rest = &s[start..];
    let end = rest.find(");").unwrap();
    let js_literal = &rest[..end]; // 形如 "{\"servers\":[…]}"（含外层引号的 JS 字符串字面量）
    let inner_json: String =
        serde_json::from_str(js_literal).expect("外层字面量应为合法 JSON 字符串");
    let payload: Value = serde_json::from_str(&inner_json).expect("内层应为合法 JSON");
    assert_eq!(payload["activeId"], "polaris");
    assert_eq!(payload["servers"][0]["url"], "127.0.0.1:9090");
    assert_eq!(
        payload["servers"][0]["secret"], evil_secret,
        "含引号/反斜杠的 secret 须原样无损（双重序列化防注入）"
    );
}

// ── 日志直播流：`_id` 出境 + UI 不活跃期的单批截断 ──
