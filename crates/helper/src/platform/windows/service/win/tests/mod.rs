use super::*;

#[test]
fn parse_request_ping_status() {
    assert!(matches!(
        parse_request("ping", &[][..]),
        Some(Request::Ping)
    ));
    assert!(matches!(
        parse_request("status", &[][..]),
        Some(Request::Status)
    ));
}

/// stop 的受管 pid 身份行可选：有则解出，无（旧客户端）则 `None`。
///
/// 变异：把 `STOP` 分支退回不读身份行的 `Request::Stop { pid: None }` → 首条转红
/// （身份判据从此永远拿不到 want = 形同虚设）。
#[test]
fn parse_request_stop_reads_optional_pid() {
    assert_eq!(
        parse_request("stop", &["4242"]).unwrap(),
        Request::Stop { pid: Some(4242) }
    );
    assert_eq!(
        parse_request("stop", &[][..]).unwrap(),
        Request::Stop { pid: None },
        "旧客户端不发身份行 → None → 沿用「停当前受管核」"
    );
}

#[test]
fn parse_request_freeport() {
    let r = parse_request("freeport", &["9090"]).unwrap();
    assert_eq!(r, Request::FreePort { port: 9090 });
}

#[test]
fn parse_request_freeport_bad_port_returns_none() {
    assert!(parse_request("freeport", &["abc"]).is_none());
}

#[test]
fn parse_request_start_full() {
    let r = parse_request("start", &["/c/cfg.json", "/l/log.txt", "1", "4242"]).unwrap();
    let Request::Start(p) = r else { panic!() };
    assert_eq!(p.cfg, "/c/cfg.json");
    assert_eq!(p.log, "/l/log.txt");
    assert!(p.fwd);
    assert_eq!(p.parent_pid, Some(4242));
}

#[test]
fn parse_request_start_without_ppid() {
    let r = parse_request("start", &["/c/cfg.json", "", "0"]).unwrap();
    let Request::Start(p) = r else { panic!() };
    assert_eq!(p.parent_pid, None);
}

#[test]
fn parse_request_route_add() {
    let r = parse_request("route-add", &["polaris-tun0", "10.0.0.0/8,172.16.0.0/12"]).unwrap();
    let Request::RouteAdd(rp) = r else { panic!() };
    assert_eq!(rp.iface, "polaris-tun0");
    assert_eq!(rp.cidrs, vec!["10.0.0.0/8", "172.16.0.0/12"]);
}

#[test]
fn parse_request_uninstall_iface_metric() {
    assert!(matches!(
        parse_request("uninstall", &[][..]),
        Some(Request::Uninstall)
    ));
    let r = parse_request("iface-metric", &["polaris-tun0", "999"]).unwrap();
    let Request::IfaceMetric { iface, metric } = r else {
        panic!()
    };
    assert_eq!(iface, "polaris-tun0");
    assert_eq!(metric, 999);
}

#[test]
fn parse_request_unknown_returns_none() {
    assert!(parse_request("bogus", &[][..]).is_none());
}

/// win 侧 wire 契约（序列化本体已上提 helper-proto，见 `Response::to_wire_line`；
/// 本测试保留为 win 视角的回归断言 —— win 的 uid 恒 0，`helper-win/helper.go:179`）。
#[test]
fn wire_ok_matches_go_format() {
    use polaris_helper_proto::{Pong, Response, ResponseKind};
    let wire = |k| Response::Ok(k).to_wire_line();
    assert_eq!(
        wire(ResponseKind::Pong(Pong {
            uid: 0,
            proto_version: 5,
            build_identity: None,
        })),
        "OK pong uid=0 v5"
    );
    assert_eq!(wire(ResponseKind::Version { proto_version: 5 }), "OK 5");
    assert_eq!(wire(ResponseKind::Cleaned), "OK cleaned");
    assert_eq!(wire(ResponseKind::Uninstalling), "OK uninstalling");
}
