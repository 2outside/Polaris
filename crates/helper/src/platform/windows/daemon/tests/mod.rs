use super::*;

fn argv(args: &[&str]) -> std::vec::IntoIter<String> {
    let mut v = vec!["polaris-helper".to_owned()];
    v.extend(args.iter().map(|s| (*s).to_owned()));
    v.into_iter()
}

#[test]
fn parse_args_all_flags() {
    let a = parse_args(argv(&[
        "--singbox",
        r"C:\sb.exe",
        "--confdir",
        r"C:\conf",
        "--support",
        r"C:\ProgramData\Polaris",
        "--coredir",
        r"C:\core",
        "--console",
    ]));
    assert_eq!(a.singbox_bin, r"C:\sb.exe");
    assert_eq!(a.conf_dir, r"C:\conf");
    assert_eq!(a.support_dir, r"C:\ProgramData\Polaris");
    assert_eq!(a.core_dir, r"C:\core");
    assert!(a.console);
}

#[test]
fn parse_args_support_defaults_and_service_mode() {
    // 缺 --support → Go 默认（品牌改名 上游→Polaris）；缺 --console → SCM 服务模式。
    let a = parse_args(argv(&["--singbox", r"C:\sb.exe"]));
    assert_eq!(a.support_dir, super::super::DEFAULT_SUPPORT_DIR);
    assert!(!a.console);
    assert_eq!(a.conf_dir, "");
    assert_eq!(a.core_dir, "");
}

#[test]
fn parse_args_console_bool_does_not_consume() {
    let a = parse_args(argv(&["--console", "--singbox", r"C:\sb.exe"]));
    assert!(a.console);
    assert_eq!(a.singbox_bin, r"C:\sb.exe");
}
