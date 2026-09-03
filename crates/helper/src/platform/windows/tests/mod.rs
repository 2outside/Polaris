use super::*;

// 服务名 / 管道名 / SDDL 是已部署 helper 的硬约束（改 = 断连接）；protoVersion 则**不再**锁
// 上游的 5 —— 那是别人 Go module 的演进计数，Polaris 首发即 v1（见 helper-proto crate 文档）。
#[test]
fn proto_version_is_unified_current() {
    assert_eq!(PROTO_VERSION, polaris_helper_proto::proto_version::CURRENT);
    assert_eq!(PROTO_VERSION, 1);
}

#[test]
fn platform_is_win_with_token_line() {
    // helper-win/helper.go:167-168: 命名管道 + token 行（tok := readLine(r)）
    assert_eq!(PLATFORM, polaris_helper_proto::Platform::Win);
    assert!(PLATFORM.has_token_line());
}

#[test]
fn service_name_pipe_name_sddl_match_go_source() {
    // main.go:15 / service.go:16,34
    assert_eq!(SERVICE_NAME, "PolarisHelper");
    assert_eq!(PIPE_NAME, r"\\.\pipe\polaris-helper");
    assert_eq!(PIPE_SDDL, "D:(A;;FA;;;SY)(A;;GRGW;;;IU)");
}
