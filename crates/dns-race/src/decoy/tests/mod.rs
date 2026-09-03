use super::*;

#[test]
fn known_decoy_samples_are_matched() {
    // 上游侧本机实测到的真实投毒样本，逐条锁死。
    assert!(is_decoy_ip(&[31, 13, 95, 169]));
    assert!(is_decoy_ip(&[157, 240, 17, 35]));
    assert!(is_decoy_ip(&[185, 45, 7, 12]));
    assert!(is_decoy_ip(&[45, 114, 11, 25]));
    assert!(is_decoy_ip(&[202, 160, 128, 16]));
    assert!(is_decoy_ip(&[8, 7, 198, 45]), "历史单点 /32");
}

#[test]
fn clean_ips_are_not_matched() {
    assert!(!is_decoy_ip(&[1, 1, 1, 1]));
    assert!(!is_decoy_ip(&[223, 5, 5, 5]));
    assert!(
        !is_decoy_ip(&[104, 21, 0, 1]),
        "104.21 不在 104.244.40.0/21"
    );
    assert!(!is_decoy_ip(&[8, 7, 198, 46]), "/32 邻居不命中");
}

#[test]
fn prefix_boundaries_are_exact() {
    // 179.60.192.0/22 覆盖 .192-.195，不覆盖 .196。
    assert!(is_decoy_ip(&[179, 60, 195, 255]));
    assert!(!is_decoy_ip(&[179, 60, 196, 0]));
    // 185.45.7.0/24 不外溢到 185.45.8.x。
    assert!(is_decoy_ip(&[185, 45, 7, 255]));
    assert!(!is_decoy_ip(&[185, 45, 8, 0]));
}

#[test]
fn v6_prefix_29_matches_facebook_range() {
    let mut ip = [0u8; 16];
    ip[0] = 0x2a;
    ip[1] = 0x03;
    ip[2] = 0x28;
    ip[3] = 0x80;
    ip[15] = 1;
    assert!(is_decoy_ip(&ip));
    // /29 的边界：第 4 字节高 5 位须一致（0x28 → 0b00101000，前 5 位 00101）。
    let mut out = ip;
    out[2] = 0x30; // 0b00110000 → 前 5 位不同
    assert!(!is_decoy_ip(&out));
}

#[test]
fn non_ip_lengths_never_match() {
    assert!(!is_decoy_ip(&[]));
    assert!(!is_decoy_ip(&[31, 13, 95]));
    assert!(!is_decoy_ip(&[0u8; 8]));
}

// ── DecoySet（运行期可覆盖）─────────────────────────────────────────

/// 内置集合与自由函数必须逐样本一致 —— 否则 `any_hit` 抽取就没抽干净，两条路会漂。
#[test]
fn builtin_set_agrees_with_free_function() {
    let s = DecoySet::builtin();
    for ip in [
        [31u8, 13, 95, 169],
        [157, 240, 17, 35],
        [8, 7, 198, 45],
        [1, 1, 1, 1],
        [179, 60, 196, 0],
    ] {
        assert_eq!(s.contains(&ip), is_decoy_ip(&ip), "{ip:?}");
    }
    assert_eq!(s.len(), (19, 1), "内置表条数变了就要同步本断言与文档");
}

#[test]
fn parse_accepts_cidr_bare_ip_comments_and_blank_lines() {
    let p = DecoySet::parse(
        "\n# 注释行\n// 另一种注释\n1.2.0.0/16\n  9.9.9.9  # 行内注释，裸 IP 补 /32\n2a03:2880::/29\n",
    );
    assert!(!p.fell_back);
    assert!(p.bad_lines.is_empty(), "{:?}", p.bad_lines);
    assert_eq!(p.set.len(), (2, 1));
    assert!(p.set.contains(&[1, 2, 3, 4]));
    assert!(p.set.contains(&[9, 9, 9, 9]));
    assert!(!p.set.contains(&[9, 9, 9, 10]), "裸 IP 必须是 /32 不是整段");
    let mut v6 = [0u8; 16];
    v6[0] = 0x2a;
    v6[1] = 0x03;
    v6[2] = 0x28;
    v6[3] = 0x80;
    assert!(p.set.contains(&v6));
}

/// **替换不是并集**：覆盖后内置段必须失效，否则误杀永远修不掉（模块文档的核心不变式）。
#[test]
fn parsed_set_replaces_builtin_rather_than_unions() {
    let p = DecoySet::parse("1.2.0.0/16");
    assert!(!p.fell_back);
    assert!(
        !p.set.contains(&[31, 13, 95, 169]),
        "内置 31.13/16 必须被替换掉，并集会把误杀写死"
    );
}

/// 空清单 / 全坏行 → 回落内置（空文件当故障，不当「关掉过滤」）。
#[test]
fn empty_or_all_bad_falls_back_to_builtin() {
    for text in ["", "   \n\n# 只有注释\n", "not-an-ip\n1.2.3.4/99\n"] {
        let p = DecoySet::parse(text);
        assert!(p.fell_back, "text={text:?}");
        assert_eq!(p.set, DecoySet::builtin(), "text={text:?}");
        assert!(p.set.contains(&[31, 13, 95, 169]));
    }
}

#[test]
fn bad_lines_are_reported_with_line_numbers_and_good_ones_kept() {
    let p = DecoySet::parse("1.2.0.0/16\nnope\n3.4.0.0/16\n1.2.3.4/33\n");
    assert!(!p.fell_back);
    assert_eq!(p.set.len(), (2, 0));
    assert_eq!(
        p.bad_lines,
        vec![(2, "nope".to_string()), (4, "1.2.3.4/33".to_string())],
        "行号从 1 起，且坏行不能吞掉后面的好行"
    );
}

/// 主机位非零不算错（`in_cidr` 两侧同时掩码）—— 拒它只会让手写清单无谓失败。
#[test]
fn host_bits_set_is_accepted_and_masked() {
    let p = DecoySet::parse("8.7.198.45/24");
    assert!(p.bad_lines.is_empty());
    assert!(p.set.contains(&[8, 7, 198, 1]));
}
