use super::*;
use std::path::Path;

#[test]
fn render_plist_basic_structure() {
    let cfg = PlistConfig::new(
        "com.polaris.helper",
        "/Library/Application Support/Polaris/helper",
        vec![
            "--singbox".into(),
            "/usr/local/lib/polaris/sing-box".into(),
            "--confdir".into(),
            "/Users/me/Polaris".into(),
        ],
    );
    let xml = render_plist(&cfg);
    // 关键字段都在
    assert!(xml.contains("<?xml version=\"1.0\""));
    assert!(xml.contains("<!DOCTYPE plist PUBLIC"));
    assert!(xml.contains("<key>Label</key>"));
    assert!(xml.contains("<string>com.polaris.helper</string>"));
    assert!(xml.contains("<key>ProgramArguments</key>"));
    assert!(xml.contains("/Library/Application Support/Polaris/helper"));
    assert!(xml.contains("--singbox"));
    assert!(xml.contains("/usr/local/lib/polaris/sing-box"));
    assert!(xml.contains("<key>RunAtLoad</key>"));
    assert!(xml.contains("<true/>"));
    assert!(xml.contains("<key>KeepAlive</key>"));
}

#[test]
fn render_plist_escapes_xml_special_chars() {
    // label/路径含 < & " 应转义
    let cfg = PlistConfig::new("a&b<c", "/path/with\"quote", vec![]);
    let xml = render_plist(&cfg);
    assert!(xml.contains("a&amp;b&lt;c"));
    assert!(xml.contains("/path/with&quot;quote"));
    // 原文不应出现裸 <（除标签）
    let label_line = xml.lines().find(|l| l.contains("a&amp;b")).unwrap();
    assert!(!label_line.contains("a&b<c"));
}

#[test]
fn render_plist_run_at_load_false() {
    let mut cfg = PlistConfig::new("x", "/p", vec![]);
    cfg.run_at_load = false;
    let xml = render_plist(&cfg);
    assert!(xml.contains("<false/>"));
}

#[test]
fn plist_path_uses_launchdaemons_dir() {
    assert_eq!(
        plist_path("com.polaris.helper"),
        PathBuf::from("/Library/LaunchDaemons/com.polaris.helper.plist")
    );
}

#[test]
fn bootstrap_args_format() {
    let args = bootstrap_args("com.polaris.helper");
    assert_eq!(args[0], "bootstrap");
    // `system/<label>` 是 launchctl 的**服务标识**（不是文件路径），恒用 `/`，逐字断言正确。
    assert_eq!(args[1], "system/com.polaris.helper");
    // 第三项是 plist 的**文件路径** ⇒ 必须按 `Path` 语义断言，不能字符串 `ends_with("/…")`：
    // `plist_path` 用 `PathBuf::join`，在 Windows 上产出 `\` 分隔符（`polaris-helper` 的
    // `platform::macos` 模块**无 cfg 门控、三平台都编译**，故这条测试在 Windows CI 上真的会跑）。
    // 用 `file_name()` 而不是给测试加 `cfg(not(windows))`：既跨平台成立，断言还更精确
    // ——「叶名恰好是它」比「以它结尾」强（后者被 `xcom.polaris.helper.plist` 之类蒙混）。
    assert_eq!(
        Path::new(&args[2]).file_name().and_then(|s| s.to_str()),
        Some("com.polaris.helper.plist"),
        "第三项应是 {LAUNCHDAEMONS_DIR} 下那个 plist 的路径，实得 {}",
        args[2]
    );
}

#[test]
fn bootout_args_format() {
    let args = bootout_args("com.polaris.helper");
    assert_eq!(args, vec!["bootout", "system/com.polaris.helper"]);
}

#[test]
fn escape_xml_all_special() {
    assert_eq!(escape_xml("a&b"), "a&amp;b");
    assert_eq!(escape_xml("a<b"), "a&lt;b");
    assert_eq!(escape_xml("a>b"), "a&gt;b");
    assert_eq!(escape_xml("a\"b"), "a&quot;b");
}

#[test]
fn default_label_is_polaris_compatible() {
    // 向后兼容 Polaris 已部署的 label
    assert_eq!(DEFAULT_LABEL, "com.polaris.helper");
}
