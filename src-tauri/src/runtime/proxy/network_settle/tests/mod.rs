use super::*;
use std::time::Duration;

/// 稳定门须覆盖**全部**重叠腿：第一条 start 结束不能提前放行，最后一条（TUN flush）退场
/// 才唤醒。变异：把计数改成 bool、或任一 guard Drop 就 notify+放行 → 中途断言转红。
#[tokio::test]
async fn waits_for_last_overlapping_leg() {
    let gate = Arc::new(NetworkSettleGate::default());
    assert!(
        tokio::time::timeout(Duration::from_millis(50), gate.wait())
            .await
            .is_ok(),
        "无在飞腿时必须立即放行"
    );

    let start_leg = gate.begin("test-start");
    let tun_flush_leg = gate.begin("test-flush");
    let waiter_gate = Arc::clone(&gate);
    let waiter = tokio::spawn(async move { waiter_gate.wait().await });
    tokio::task::yield_now().await;
    assert!(!waiter.is_finished(), "任一腿在飞时不得发订阅请求");

    drop(start_leg);
    tokio::task::yield_now().await;
    assert!(
        !waiter.is_finished(),
        "start 退场但 TUN flush 尚未完成时仍不得放行"
    );

    drop(tun_flush_leg);
    tokio::time::timeout(Duration::from_secs(1), waiter)
        .await
        .expect("最后一腿退场后等待者应立即醒")
        .expect("等待任务不应 panic");
    assert!(gate.is_settled());
}
