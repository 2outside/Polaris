//! C4 装配面门：enqueue 真落盘 + drain 出队/留队映射（网络端由 crate `warp_http` 单测覆盖）。
use super::super::*;
use crate::test_support::TestDir;

fn temp_dir(tag: &str) -> TestDir {
    TestDir::new(&format!("polaris-warp-{tag}-"))
}

fn entry(id: &str) -> PendingDeregisterEntry {
    PendingDeregisterEntry {
        device_id: id.to_string(),
        token: format!("t-{id}"),
        enqueued_at: 1,
    }
}

/// enqueue 必须**真落盘**（server.rs 删 WARP 节点的入队装配）。回归到「只 log 不 enqueue」
/// （server.rs:541 旧态）→ 队列空 → 此测转红。打断 `save_warp_queue` 亦转红。
#[test]
fn enqueue_persists_entry_to_disk() {
    let dir = temp_dir("enqueue");
    let mesh = MeshRuntime::new(dir.clone());
    mesh.enqueue_warp_deregister("dev-1", "tok-1");
    // 全新实例重读磁盘 → 真落盘才在。
    let reloaded = MeshRuntime::new(dir.clone()).load_warp_queue();
    assert_eq!(reloaded.len(), 1, "入队条目须落盘存活");
    assert_eq!(reloaded[0].device_id, "dev-1");
    assert_eq!(reloaded[0].token, "tok-1");
}

#[test]
fn enqueue_ignores_empty_credentials() {
    let dir = temp_dir("empty");
    let mesh = MeshRuntime::new(dir.clone());
    mesh.enqueue_warp_deregister("", "tok");
    mesh.enqueue_warp_deregister("dev", "");
    assert!(mesh.load_warp_queue().is_empty(), "空凭据不入队");
}

/// 队列上限护栏（crate `enqueue_pending_deregister`）经文件层生效：超上限落盘仍封顶、丢最旧。
#[test]
fn enqueue_respects_queue_cap_on_disk() {
    use polaris_mesh::warp::WARP_DEREGISTER_MAX_QUEUE;
    let dir = temp_dir("cap");
    let mesh = MeshRuntime::new(dir.clone());
    for i in 0..(WARP_DEREGISTER_MAX_QUEUE + 5) {
        mesh.enqueue_warp_deregister(&format!("dev-{i}"), "tok");
    }
    let q = mesh.load_warp_queue();
    assert_eq!(q.len(), WARP_DEREGISTER_MAX_QUEUE, "落盘队列封顶");
    assert_eq!(
        q.last().unwrap().device_id,
        format!("dev-{}", WARP_DEREGISTER_MAX_QUEUE + 4),
        "最新入队在队尾（最旧被挤掉）"
    );
}

/// drain 结果 → 出队集映射：Expire + (Eligible 且 Done/Drop) 出队；Eligible 且 Retry 留队。
/// 打断（如把 Retry 也算出队）→ 转红。
#[test]
fn plan_removals_expire_and_terminal_remove_retry_keeps() {
    let e_expire = entry("expire");
    let e_done = entry("done");
    let e_drop = entry("drop");
    let e_retry = entry("retry");
    let plan = vec![
        DrainPlanItem {
            entry: e_expire.clone(),
            action: DrainAction::Expire,
        },
        DrainPlanItem {
            entry: e_done.clone(),
            action: DrainAction::Eligible,
        },
        DrainPlanItem {
            entry: e_drop.clone(),
            action: DrainAction::Eligible,
        },
        DrainPlanItem {
            entry: e_retry.clone(),
            action: DrainAction::Eligible,
        },
    ];
    // Eligible 顺序：done / drop / retry。
    let results = vec![
        DeregisterResult::Done,
        DeregisterResult::Drop,
        DeregisterResult::Retry,
    ];
    let remove = plan_removals(&plan, &results);
    assert!(remove.contains(&e_expire), "超龄出队");
    assert!(remove.contains(&e_done), "Done 出队");
    assert!(remove.contains(&e_drop), "Drop 出队");
    assert!(!remove.contains(&e_retry), "Retry 必须留队");
    assert_eq!(remove.len(), 3);
}

/// reload 后精确出队：只删已解决条目，保留 Retry + 网络期间的并发新入队（防丢更新）。
#[test]
fn retain_unresolved_keeps_retry_and_concurrent_enqueue() {
    let resolved = entry("resolved");
    let retry = entry("retry");
    let newly = entry("new"); // drain 网络期间并发入队。
    let current = vec![resolved.clone(), retry.clone(), newly.clone()];
    let next = retain_unresolved(current, std::slice::from_ref(&resolved));
    assert!(!next.contains(&resolved), "已解决条目出队");
    assert!(next.contains(&retry), "Retry 留队");
    assert!(next.contains(&newly), "并发新入队不丢");
    assert_eq!(next.len(), 2);
}
