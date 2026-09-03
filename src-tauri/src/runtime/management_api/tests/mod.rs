use super::*;

/// 未就绪实例：三个方法全部 NotReady（而非 panic / 静默 Ok）。
/// NotReady 是 executor 区分「核未起」与「PUT 报错」的依据，两者都退回重启但日志不同。
#[tokio::test]
async fn not_ready_client_returns_not_ready_for_all_methods() {
    let api = GrpcManagementApi::not_ready();
    assert!(matches!(
        api.select_outbound("proxy-selector", "tagB").await,
        Err(ManagementError::NotReady)
    ));
    assert!(matches!(
        api.close_connection("c1").await,
        Err(ManagementError::NotReady)
    ));
    assert!(matches!(
        api.first_connection_snapshot().await,
        Err(ManagementError::NotReady)
    ));
}

/// 读侧同样必须 NotReady 而**不是空快照**：空快照 = 「核确实没有 group」，NotReady = 「没读到」。
/// 压成前者会让起核自证把「读不到」误当成「查无此 group」，从而对真分叉保持沉默。
///
/// **变异锁**：把 `groups_snapshot` 的 `self.client()?` 换成 `unwrap_or_default()` 式回落
/// （返回 `Ok(vec![])`）→ 转红。
#[tokio::test]
async fn not_ready_client_returns_not_ready_for_groups_snapshot() {
    let api = GrpcManagementApi::not_ready();
    assert!(matches!(
        api.groups_snapshot().await,
        Err(ManagementError::NotReady)
    ));
}

/// SnapshotTimeout 必须单独成态，不得被压成 Call —— executor 对二者的处置不同
/// （超时 → 跳过断连；Call → 也跳过但日志语义不同），且上层据此判「核 wedged」。
#[test]
fn snapshot_timeout_maps_to_dedicated_variant() {
    assert!(matches!(
        map_err(ClientError::SnapshotTimeout),
        ManagementError::SnapshotTimeout
    ));
}

/// tonic Status → Call 且**保留原文**（丢了原文，真机 PUT 失败时无从定位是 Unauthenticated 还是 Unavailable）。
#[test]
fn tonic_status_maps_to_call_preserving_message() {
    let e = map_err(ClientError::Status(
        polaris_singbox_grpc::tonic::Status::unauthenticated("bad secret"),
    ));
    match e {
        ManagementError::Call(msg) => assert!(
            msg.contains("bad secret"),
            "必须保留 gRPC 原文，实得：{msg}"
        ),
        other => panic!("expected Call, got {other:?}"),
    }
}
