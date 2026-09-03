use super::*;
use crate::request::StartParams;

#[test]
fn mac_frame_has_token_first() {
    // mac: 行1=token, 行2=command, 行3..=args（对照 helper.go:403-404 的两个 readLine）
    let req = Request::Ping;
    let lines = encode_frame(Platform::Mac, "tok123", &req);
    assert_eq!(lines, vec!["tok123", "ping"]);
}

#[test]
fn win_frame_has_token_first() {
    // win: 同 mac（命名管道 + token 行，helper-win/helper.go:167-168）
    let lines = encode_frame(Platform::Win, "tok", &Request::Status);
    assert_eq!(lines, vec!["tok", "status"]);
}

#[test]
fn linux_frame_no_token_line() {
    // linux: 行1=command（无 token 行，SO_PEERCRED 鉴权，helper-linux/helper.go:343）
    let lines = encode_frame(Platform::Linux, "ignored", &Request::Ping);
    assert_eq!(lines, vec!["ping"]);
}

#[test]
fn mac_start_frame_full() {
    // 完整 mac start 帧（对照 helper.go:508-513 的 6 行 readLine 序列）
    let req = Request::Start(StartParams {
        cfg: "/tmp/c.json".into(),
        log: "/tmp/l.log".into(),
        fwd: true,
        parent_pid: Some(1000),
    });
    let bytes = encode(Platform::Mac, "TOK", &req);
    let s = String::from_utf8(bytes).unwrap();
    assert_eq!(s, "TOK\nstart\n/tmp/c.json\n/tmp/l.log\n1\n1000\n");
}

#[test]
fn frame_to_bytes_adds_newlines() {
    let bytes = frame_to_bytes(&["a".to_owned(), "b".to_owned(), "c".to_owned()]);
    assert_eq!(bytes, b"a\nb\nc\n");
}

// ===== 接口白名单（逐字对照 Go 源）=====

#[test]
fn mac_iface_whitelist_matches_go_source() {
    // helper.go:255-272 的 ifaceAllowed
    assert!(is_mac_iface_allowed("polaris-ts"));
    assert!(is_mac_iface_allowed("polaris-wg"));
    assert!(is_mac_iface_allowed("utun3"));
    assert!(is_mac_iface_allowed("utun123"));
    // 拒绝
    assert!(!is_mac_iface_allowed("en0"));
    assert!(!is_mac_iface_allowed("utun"));
    assert!(!is_mac_iface_allowed("utun1234")); // >3 位
    assert!(!is_mac_iface_allowed("utunX"));
    assert!(!is_mac_iface_allowed("polaris-other"));
    assert!(!is_mac_iface_allowed(""));
}

#[test]
fn win_iface_whitelist_matches_go_source() {
    // helper-win/helper.go:50-60 的 ifaceAllowed：polaris- 前缀 + rest 每字符须 [a-z0-9-]
    assert!(is_win_iface_allowed("polaris-ts"));
    assert!(is_win_iface_allowed("polaris-wg"));
    assert!(is_win_iface_allowed("polaris-tun0"));
    assert!(is_win_iface_allowed("polaris-abc-123"));
    // Go 源对 "polaris-"（rest 为空）返回 true —— rest 为空时 `for _, c := range ""` 不执行循环体，
    // 函数落到 `return true`。本实现用 `all()` over 空迭代器（恒 true）保持一致：
    assert!(is_win_iface_allowed("polaris-"));
    // 拒绝
    assert!(!is_win_iface_allowed("polaris-ABC")); // 大写
    assert!(!is_win_iface_allowed("polaris_abc")); // 下划线
    assert!(!is_win_iface_allowed("en0"));
    // 超长拒绝（Go: len(s) > 24）
    assert!(!is_win_iface_allowed(&format!(
        "polaris-{}",
        "a".repeat(30)
    )));
}

// ===== CIDR / IPv4 校验 =====

#[test]
fn cidr_validation_matches_go_parsecidr() {
    // helper.go:470 的 net.ParseCIDR 校验
    assert!(is_valid_cidr("10.0.0.0/8"));
    assert!(is_valid_cidr("172.16.0.0/12"));
    assert!(is_valid_cidr("0.0.0.0/0"));
    assert!(is_valid_cidr("::/0"));
    assert!(is_valid_cidr("2001:db8::/32"));
    // 拒绝
    assert!(!is_valid_cidr("10.0.0.0/33")); // IPv4 prefix > 32
    assert!(!is_valid_cidr("10.0.0.0")); // 无 /
    assert!(!is_valid_cidr("10.0.0.0/abc"));
    assert!(!is_valid_cidr("not-a-cidr"));
    assert!(!is_valid_cidr("256.1.1.1/8")); // octet > 255
}

#[test]
fn ipv4_validation_matches_go_parseip_tov4() {
    // helper.go:486 的 net.ParseIP(gw).To4()
    assert!(is_valid_ipv4("192.168.1.1"));
    assert!(is_valid_ipv4("10.0.0.1"));
    assert!(is_valid_ipv4("0.0.0.0"));
    assert!(!is_valid_ipv4("256.1.1.1"));
    assert!(!is_valid_ipv4("1.2.3"));
    assert!(!is_valid_ipv4("::1")); // IPv6 非 IPv4
    assert!(!is_valid_ipv4("not-an-ip"));
}

/// 前导零必须拒绝（八进制歧义 = CVE-2021-29922 类）。
///
/// 锁死一次**行为修正**：旧的手写解析注释自称「拒绝前导零（如 "01"）…避免八进制歧义」，实则只拦了
/// `len > 3`，`"010".parse::<u16>()` 收成 10 → `010.0.0.1` 被当 `10.0.0.1` 放行，与注释相反。
/// 改用 stdlib `Ipv4Addr`/`IpAddr` 的 `FromStr` 后真正拒绝，与 Go 1.17+ `net.ParseIP`（本模块的移植 oracle）
/// 及原注释意图一致。此测试防回归到「注释说拒、代码放行」的旧形态。
#[test]
fn rejects_leading_zero_octets() {
    assert!(!is_valid_ipv4("010.0.0.1"));
    assert!(!is_valid_ipv4("192.168.01.1"));
    assert!(!is_valid_cidr("010.0.0.0/8"));
    // 对照组：无前导零的等价地址正常放行
    assert!(is_valid_ipv4("10.0.0.1"));
    assert!(is_valid_cidr("10.0.0.0/8"));
}

#[test]
fn sha256_hex_validation() {
    // helper.go:137 的 len(wantHash) != 64 校验
    assert!(is_valid_sha256_hex("a".repeat(64).as_str()));
    assert!(is_valid_sha256_hex("ABCDEF0123456789".repeat(4).as_str())); // 大小写混用
    assert!(!is_valid_sha256_hex("abc")); // 太短
    assert!(!is_valid_sha256_hex("z".repeat(64).as_str())); // 非 hex
    assert!(!is_valid_sha256_hex(&"a".repeat(63))); // 63 字符
}

#[test]
fn ipv6_parsing_variants() {
    // 确保 CIDR 校验对 IPv6 各形态正确（route-add 的 IPv6 族，helper.go:474）
    assert!(is_valid_cidr("::1/128"));
    assert!(is_valid_cidr("2001:db8::1/64"));
    assert!(is_valid_cidr("fe80::/10"));
    assert!(!is_valid_cidr("2001:db8::/130")); // prefix > 128
                                               // 完整 IPv6（无 ::）
    assert!(is_valid_cidr("2001:0db8:0000:0000:0000:0000:0000:0001/64"));
}
