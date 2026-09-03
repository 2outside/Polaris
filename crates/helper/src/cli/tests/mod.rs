use super::*;

fn argv(args: &[&str]) -> std::vec::IntoIter<String> {
    // 模拟真实 argv：首元素为程序名（被跳过）。
    let mut v = vec!["polaris-helper".to_owned()];
    v.extend(args.iter().map(|s| (*s).to_owned()));
    v.into_iter()
}

#[test]
fn parses_value_flag_space_form() {
    let m = parse_flags(argv(&["--singbox", "/opt/sb"]), &[]);
    assert_eq!(m.get("singbox").map(String::as_str), Some("/opt/sb"));
}

#[test]
fn parses_value_flag_eq_form() {
    let m = parse_flags(argv(&["--confdir=/etc/polaris"]), &[]);
    assert_eq!(m.get("confdir").map(String::as_str), Some("/etc/polaris"));
}

#[test]
fn single_dash_accepted() {
    // Go flag 包 `-flag` 与 `--flag` 等价。
    let m = parse_flags(argv(&["-socket", "/run/x.sock"]), &[]);
    assert_eq!(m.get("socket").map(String::as_str), Some("/run/x.sock"));
}

#[test]
fn bool_flag_does_not_consume_next() {
    let m = parse_flags(argv(&["--console", "--coredir", "/c"]), &["console"]);
    assert_eq!(m.get("console").map(String::as_str), Some("true"));
    assert_eq!(m.get("coredir").map(String::as_str), Some("/c"));
}

#[test]
fn missing_flag_absent_from_map() {
    let m = parse_flags(argv(&["--singbox", "/opt/sb"]), &[]);
    assert!(!m.contains_key("support"));
}

#[test]
fn positional_tokens_ignored() {
    let m = parse_flags(argv(&["positional", "--singbox", "/opt/sb"]), &[]);
    assert_eq!(m.len(), 1);
    assert_eq!(m.get("singbox").map(String::as_str), Some("/opt/sb"));
}

#[test]
fn value_with_spaces_preserved() {
    // launchd argv 里 `--support "/Library/Application Support/Polaris"` 是单 token。
    let m = parse_flags(
        argv(&["--support=/Library/Application Support/Polaris"]),
        &[],
    );
    assert_eq!(
        m.get("support").map(String::as_str),
        Some("/Library/Application Support/Polaris")
    );
}

#[test]
fn trailing_value_flag_gets_empty() {
    let m = parse_flags(argv(&["--coredir"]), &[]);
    assert_eq!(m.get("coredir").map(String::as_str), Some(""));
}

#[test]
fn empty_argv_yields_empty_map() {
    let m = parse_flags(argv(&[]), &["console"]);
    assert!(m.is_empty());
}
