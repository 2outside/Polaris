use super::*;

#[test]
fn normalize_bare_ip() {
    assert_eq!(
        normalize_tun_exclude_cidr("192.168.1.1"),
        Some("192.168.1.1/32".into())
    );
    assert_eq!(
        normalize_tun_exclude_cidr("fe80::1"),
        Some("fe80::1/128".into())
    );
}

#[test]
fn normalize_rejects_catch_all() {
    assert_eq!(normalize_tun_exclude_cidr("0.0.0.0/0"), None);
    assert_eq!(normalize_tun_exclude_cidr("::/0"), None);
    assert_eq!(normalize_tun_exclude_cidr("10.0.0.0/7"), None); // 过宽（< 8）
}

#[test]
fn normalize_rejects_invalid() {
    assert_eq!(normalize_tun_exclude_cidr(""), None);
    assert_eq!(normalize_tun_exclude_cidr("  "), None);
    assert_eq!(normalize_tun_exclude_cidr("abc"), None);
}

#[test]
fn normalize_rejects_out_of_range_and_leading_zero() {
    // 这些串**形状**合法（点分四段 + 数字掩码），只有严格校验（rule_validate::is_valid_ip_cidr）能拦。
    // 一旦退回 system_proxy_bypass::is_ip_cidr 的形状粗判，它们会原样进 route_exclude_address →
    // sing-box `netip.ParsePrefix` 启动 FATAL（整个代理起不来），故本用例是校验强度的变异锁。
    assert_eq!(normalize_tun_exclude_cidr("256.1.1.1/24"), None); // 八位组越界
    assert_eq!(normalize_tun_exclude_cidr("192.168.1.1/33"), None); // v4 掩码越界
    assert_eq!(normalize_tun_exclude_cidr("010.0.0.1/24"), None); // 前导零
    assert_eq!(normalize_tun_exclude_cidr("12345::1/64"), None); // v6 段 >4 位
    assert_eq!(normalize_tun_exclude_cidr("fe80::1/129"), None); // v6 掩码越界

    // 合法边界仍须放行（别把校验收紧成一刀切）。
    assert_eq!(
        normalize_tun_exclude_cidr("10.0.0.0/8"),
        Some("10.0.0.0/8".into())
    );
    assert_eq!(
        normalize_tun_exclude_cidr("fc00::/7"),
        Some("fc00::/7".into())
    );
}

#[test]
fn user_exclude_reduces_mesh() {
    let input = UserTunExcludeInput {
        platform: "linux",
        user_cidrs: &["10.0.0.0/8".into(), "100.64.0.0/10".into()],
        mesh_cidrs: &["100.64.0.0/10".into()],
        fakeip_ranges: &[],
        own_lan_cidrs: &[],
    };
    let result = compute_user_tun_exclude(&input);
    assert!(result.extra.contains(&"10.0.0.0/8".to_string()));
    assert!(result
        .dropped_mesh_overlap
        .contains(&"100.64.0.0/10".to_string()));
}

#[test]
fn user_exclude_mac_reduces_own_lan() {
    let input = UserTunExcludeInput {
        platform: "darwin",
        user_cidrs: &["10.0.0.0/8".into()],
        mesh_cidrs: &[],
        fakeip_ranges: &[],
        own_lan_cidrs: &["10.0.0.0/8".into()], // 同段物理 LAN
    };
    let result = compute_user_tun_exclude(&input);
    assert!(result.extra.is_empty()); // 全被物理 LAN guard 剔除
    assert!(result
        .dropped_own_lan_mac
        .contains(&"10.0.0.0/8".to_string()));
}

#[test]
fn win_bypass_no_mesh_returns_original() {
    let input = WinBypassExcludeInput {
        bypass_cidrs: &["10.0.0.0/8".into(), "192.168.0.0/16".into()],
        engaged_mesh_cidrs: &[],
        own_lan_cidrs: &[],
        fakeip_ranges: &[],
    };
    let result = compute_win_bypass_exclude(&input);
    assert_eq!(result.exclude.len(), 2);
    assert!(result.carved_mesh_cidrs.is_empty());
}

#[test]
fn win_bypass_carves_mesh() {
    // 10.0.0.0/8 排除，engaged mesh 10.64.0.0/10 → carve 开洞。
    let input = WinBypassExcludeInput {
        bypass_cidrs: &["10.0.0.0/8".into()],
        engaged_mesh_cidrs: &["10.64.0.0/10".into()],
        own_lan_cidrs: &[],
        fakeip_ranges: &[],
    };
    let result = compute_win_bypass_exclude(&input);
    assert!(result
        .carved_mesh_cidrs
        .contains(&"10.64.0.0/10".to_string()));
    // exclude 应为 10.0.0.0/8 ∖ 10.64.0.0/10（多段）。
    assert!(result.exclude.len() > 1);
}

/// **后果锁**：`/0` 一旦漏进 `own_lan_cidrs`，guard 与一切 mesh 段相交 ⇒ 一条都不 carve ⇒
/// bypassLAN 下组网段整体绕 TUN 静默失效。第二段证明上游 `own_lan_cidr` 拒掉 `prefix=0` 后
/// carve 恢复正常。
///
/// 变异锁（沿真实后果，不止谓词层）：把 `own_lan::own_lan_cidr` 的 `prefix == 0 → None` 删掉，
/// 或把 `netinfo::prefix_is_valid` 的下界放回 0 —— 前者让本用例第二段（`own_lan` 应为空、carve
/// 应发生）转红。第一段不随修复变化，它记录的是「一旦漏进来会怎样」这条因果。
#[test]
fn win_bypass_zero_prefix_own_lan_kills_all_carve() {
    use crate::user_config::own_lan::own_lan_cidr;

    // 段一：/0 漏进 own_lan → 全部 mesh 段被 skip，exclude 原样、零 carve。
    let poisoned = WinBypassExcludeInput {
        bypass_cidrs: &["10.0.0.0/8".into()],
        engaged_mesh_cidrs: &["10.64.0.0/10".into()],
        own_lan_cidrs: &["10.0.0.5/0".into()],
        fakeip_ranges: &[],
    };
    let poisoned_result = compute_win_bypass_exclude(&poisoned);
    assert!(
        poisoned_result.carved_mesh_cidrs.is_empty(),
        "/0 guard 与一切段相交，carve 必然全灭"
    );
    assert!(poisoned_result
        .mesh_skipped_own_lan
        .contains(&"10.64.0.0/10".to_string()));
    assert_eq!(poisoned_result.exclude, vec!["10.0.0.0/8".to_string()]);

    // 段二：own_lan_cidr 在汇流点拒掉 prefix=0 ⇒ own_lan 为空 ⇒ carve 正常发生。
    let own_lan: Vec<String> = [("10.0.0.5", 0u8), ("", 24u8)]
        .into_iter()
        .filter_map(|(addr, prefix)| own_lan_cidr(addr, prefix, false))
        .collect();
    assert!(own_lan.is_empty(), "prefix=0 必须在 own_lan_cidr 处被挡住");
    let clean = WinBypassExcludeInput {
        bypass_cidrs: &["10.0.0.0/8".into()],
        engaged_mesh_cidrs: &["10.64.0.0/10".into()],
        own_lan_cidrs: &own_lan,
        fakeip_ranges: &[],
    };
    let clean_result = compute_win_bypass_exclude(&clean);
    assert!(clean_result
        .carved_mesh_cidrs
        .contains(&"10.64.0.0/10".to_string()));
    assert!(clean_result.mesh_skipped_own_lan.is_empty());
    assert!(clean_result.exclude.len() > 1, "差集应把 /8 打成多段");
}

#[test]
fn win_bypass_skips_mesh_on_protected() {
    // mesh 段与保护段（回环）相交 → 不 carve。
    let input = WinBypassExcludeInput {
        bypass_cidrs: &["127.0.0.0/8".into()],
        engaged_mesh_cidrs: &["127.0.0.0/8".into()],
        own_lan_cidrs: &[],
        fakeip_ranges: &[],
    };
    let result = compute_win_bypass_exclude(&input);
    assert!(result.carved_mesh_cidrs.is_empty());
    assert!(result
        .mesh_skipped_own_lan
        .contains(&"127.0.0.0/8".to_string()));
}
