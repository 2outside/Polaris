use super::*;

fn argv(args: &[&str]) -> std::vec::IntoIter<String> {
    let mut v = vec!["polaris-helper".to_owned()];
    v.extend(args.iter().map(|s| (*s).to_owned()));
    v.into_iter()
}

#[test]
fn parse_args_all_flags() {
    let cfg = parse_args(argv(&[
        "--singbox",
        "/opt/sing-box",
        "--confdir",
        "/etc/polaris/conf",
        "--support",
        "/Library/Application Support/Polaris",
        "--coredir",
        "/usr/local/lib/polaris/core",
    ]));
    assert_eq!(cfg.singbox_bin, "/opt/sing-box");
    assert_eq!(cfg.conf_dir, "/etc/polaris/conf");
    assert_eq!(cfg.support_dir, "/Library/Application Support/Polaris");
    assert_eq!(cfg.core_dir, "/usr/local/lib/polaris/core");
}

#[test]
fn parse_args_support_defaults() {
    // 缺 --support → Go 默认值（品牌改名 上游→Polaris）。
    let cfg = parse_args(argv(&["--singbox", "/opt/sb"]));
    assert_eq!(cfg.support_dir, "/Library/Application Support/Polaris");
    assert_eq!(cfg.singbox_bin, "/opt/sb");
    assert_eq!(cfg.conf_dir, "");
    assert_eq!(cfg.core_dir, "");
}

#[test]
fn parse_args_eq_form() {
    let cfg = parse_args(argv(&["--singbox=/a/b", "--coredir=/c/d"]));
    assert_eq!(cfg.singbox_bin, "/a/b");
    assert_eq!(cfg.core_dir, "/c/d");
}
