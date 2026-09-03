use super::*;

// ===== build_route_argv（逐字对照 helper.go:472-478）=====

#[test]
fn route_argv_ipv4_add() {
    // helper.go:472-478，op=add，IPv4 CIDR（无 -inet6）
    let argv = build_route_argv(RouteOp::Add, "polaris-ts", "10.0.0.0/8").unwrap();
    assert_eq!(
        argv,
        vec![
            "-n",
            "add",
            "-ifscope",
            "polaris-ts",
            "-net",
            "10.0.0.0/8",
            "-interface",
            "polaris-ts"
        ]
    );
}

#[test]
fn route_argv_ipv6_delete() {
    // helper.go:474: 含 ":" → 加 -inet6；op=delete
    let argv = build_route_argv(RouteOp::Delete, "utun3", "2001:db8::/32").unwrap();
    assert_eq!(
        argv,
        vec![
            "-n",
            "delete",
            "-inet6",
            "-ifscope",
            "utun3",
            "-net",
            "2001:db8::/32",
            "-interface",
            "utun3"
        ]
    );
}

#[test]
fn route_argv_invalid_cidr_returns_none() {
    // helper.go:470: 非法 CIDR continue 跳过
    assert!(build_route_argv(RouteOp::Add, "polaris-ts", "not-a-cidr").is_none());
    assert!(build_route_argv(RouteOp::Add, "polaris-ts", "999.0.0.0/8").is_none());
    assert!(build_route_argv(RouteOp::Add, "polaris-ts", "10.0.0.0/33").is_none());
}

#[test]
fn route_op_subcmd_matches_go() {
    // helper.go:461,463
    assert_eq!(RouteOp::Add.as_route_subcmd(), "add");
    assert_eq!(RouteOp::Delete.as_route_subcmd(), "delete");
}

#[test]
fn route_argv_multiple_cidrs_build_independently() {
    // 模拟 helper.go:465 循环：对 cidrsLine split(',') 后逐个 build
    let cidrs = "10.0.0.0/8,172.16.0.0/12,invalid,192.168.0.0/16";
    let argvs: Vec<_> = cidrs
        .split(',')
        .filter_map(|c| build_route_argv(RouteOp::Add, "polaris-wg", c.trim()))
        .collect();
    assert_eq!(argvs.len(), 3, "invalid 项被跳过");
    // 每条都带 -ifscope polaris-wg
    assert!(argvs.iter().all(|a| a.contains(&"-ifscope".to_owned())));
}

// ===== build_default_restore_argv（逐字对照 helper.go:486,490）=====

#[test]
fn default_restore_argv_valid_ipv4() {
    // helper.go:490: /sbin/route -n add -inet default <gw>
    let argv = build_default_restore_argv("192.168.1.1").unwrap();
    assert_eq!(argv, vec!["-n", "add", "-inet", "default", "192.168.1.1"]);
}

#[test]
fn default_restore_argv_invalid_gateway_none() {
    // helper.go:486: ParseIP.To4 == nil → ERR bad-gateway
    assert!(build_default_restore_argv("not-an-ip").is_none());
    assert!(build_default_restore_argv("::1").is_none(), "IPv6 不接受");
    assert!(build_default_restore_argv("256.1.1.1").is_none());
    assert!(build_default_restore_argv("").is_none());
}

#[test]
fn route_bin_is_sbin_route() {
    // helper.go:478,490: /sbin/route
    assert_eq!(ROUTE_BIN, "/sbin/route");
}
