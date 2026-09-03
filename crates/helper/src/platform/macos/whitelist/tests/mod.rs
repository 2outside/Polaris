use super::*;

// ===== cfg_allowed（逐字对照 helper.go:245-252）=====

#[test]
fn cfg_allowed_empty_confdir_fails_closed() {
    assert!(!cfg_allowed("/etc/passwd", ""));
    assert!(!cfg_allowed("/tmp/any.json", ""));
}

#[test]
fn cfg_allowed_inside_confdir() {
    // helper.go:249-251: clean cfg HasPrefix (Clean(confDir)+sep)
    assert!(cfg_allowed(
        "/Users/me/Library/Application Support/Polaris/cfg.json",
        "/Users/me/Library/Application Support/Polaris"
    ));
}

#[test]
fn cfg_allowed_denies_outside_confdir() {
    // helper.go:530: ERR config-path-denied
    assert!(!cfg_allowed("/etc/passwd", "/Users/me/Polaris"));
    assert!(!cfg_allowed(
        "/tmp/evil.json",
        "/Users/me/Library/Application Support/Polaris"
    ));
}

#[test]
fn cfg_allowed_path_traversal_denied() {
    // 防 ../../../etc/passwd 注入：Clean 后前缀不匹配
    assert!(!cfg_allowed(
        "/Users/me/Polaris/../../../etc/passwd",
        "/Users/me/Polaris"
    ));
}

#[test]
fn cfg_allowed_similar_prefix_denied() {
    // 防前缀碰撞：cfg=/fooBar 不应匹配 confdir=/foo（须带分隔符）
    assert!(!cfg_allowed("/Polarisbar/cfg.json", "/Polaris"));
}

#[test]
fn cfg_allowed_normalized_paths() {
    // Go filepath.Clean 折叠 ./ 与 //
    assert!(cfg_allowed(
        "/Users/me/Polaris/./sub/../cfg.json",
        "/Users/me/Polaris"
    ));
    assert!(cfg_allowed(
        "/Users/me//Polaris/cfg.json",
        "/Users/me/Polaris"
    ));
}

// ===== iface_allowed（逐字对照 helper.go:255-272，委托 proto）=====

#[test]
fn iface_allowed_matches_go_source() {
    // helper.go:256-258: polaris-ts / polaris-wg
    assert!(iface_allowed("polaris-ts"));
    assert!(iface_allowed("polaris-wg"));
    // helper.go:259-271: utunN (1-3 digits)
    assert!(iface_allowed("utun0"));
    assert!(iface_allowed("utun3"));
    assert!(iface_allowed("utun999"));
}

#[test]
fn iface_denied_variants() {
    // helper.go:260: 非 utun 前缀
    assert!(!iface_allowed("en0"));
    assert!(!iface_allowed("eth0"));
    // helper.go:262: rest == "" → false
    assert!(!iface_allowed("utun"));
    // helper.go:263: len(rest) > 3 → false
    assert!(!iface_allowed("utun1234"));
    // helper.go:266-269: rest 含非数字
    assert!(!iface_allowed("utunX"));
    assert!(!iface_allowed("utun1a"));
    // 非 polaris-* 自家前缀
    assert!(!iface_allowed("polaris-other"));
    assert!(!iface_allowed(""));
    assert!(!iface_allowed("Polaris-ts")); // 大小写敏感
}

// ===== normalize_path（对齐 Go filepath.Clean）=====

#[test]
fn normalize_collapses_dotdot() {
    assert_eq!(normalize_path("/a/b/../c"), PathBuf::from("/a/c"));
    assert_eq!(normalize_path("/a/b/../../c"), PathBuf::from("/c"));
}

#[test]
fn normalize_collapses_curdir_and_double_sep() {
    assert_eq!(normalize_path("/a/./b"), PathBuf::from("/a/b"));
    assert_eq!(normalize_path("/a//b"), PathBuf::from("/a/b"));
}

#[test]
fn normalize_dotdot_at_root_stays_root() {
    // Go: filepath.Clean("/..") → "/"
    assert_eq!(normalize_path("/.."), PathBuf::from("/"));
    assert_eq!(normalize_path("/../.."), PathBuf::from("/"));
}

#[test]
fn normalize_empty_returns_dot() {
    // Go: filepath.Clean("") → "."
    assert_eq!(normalize_path(""), PathBuf::from("."));
}

#[test]
fn normalize_trailing_sep_stripped() {
    // Go: filepath.Clean("/a/b/") → "/a/b"
    assert_eq!(normalize_path("/a/b/"), PathBuf::from("/a/b"));
}
