use super::*;

const TICK: Duration = Duration::from_millis(250);

fn gate() -> EmitGate {
    EmitGate::new(TICK)
}

/// 无变更 → 不设定时器、不 emit（长驻流空闲时的常态：零开销）。
///
/// **变异探针**：`wait_for` 去掉 `if !self.pending` 短路（恒返回 `Some`）⇒ 转红 ——
/// 那会让上层每个 min_interval 白醒一次，把「事件驱动」退化回轮询。
#[test]
fn 无变更时不推也不设定时器() {
    let g = gate();
    assert_eq!(g.wait_for(0), None);
    assert_eq!(g.wait_for(10_000), None);
    assert!(!g.should_emit(10_000));
    assert!(!g.is_pending());
}

/// 🟡 **首帧免冷却**：订阅后第一帧（reset 全量表）立刻放行。
///
/// **变异探针**：`wait_for` 的 `None => Some(ZERO)` 分支改成走冷却计算（如把 `last_emit_ms`
/// 初值设成 0 而非 `None`）⇒ 转红。那等于首帧要等满一个间隔才到渲染端。
#[test]
fn 首帧免冷却立刻放行() {
    let mut g = gate();
    g.note_change();
    assert_eq!(g.wait_for(0), Some(Duration::ZERO));
    assert!(g.should_emit(0));
}

/// 🟡 **冷却期内的 N 帧只产出一次 emit**（合并，不是 N 次）。
///
/// **变异探针**：`mark_emitted` 不写 `last_emit_ms` ⇒ 每帧都放行 ⇒ 转红。
/// 这条锁的是「把前端帧预算外包给对端负载」那个坑：内核一次连接风暴推来多少帧，
/// 我们就只推一帧。
#[test]
fn 冷却期内多帧合并为一次emit() {
    let mut g = gate();
    g.note_change();
    assert!(g.should_emit(1_000));
    g.mark_emitted(1_000);

    // 冷却期内连来 100 帧
    for i in 0..100u64 {
        g.note_change();
        let now = 1_000 + i; // 全部落在 1_000..1_100，远早于 1_250
        assert!(
            !g.should_emit(now),
            "冷却期内第 {i} 帧不得 emit（应合并到冷却结束时一次推出）"
        );
    }
    // 冷却结束 → 恰好一次
    assert!(g.should_emit(1_250), "冷却一到必须推出合并后的那一帧");
    g.mark_emitted(1_250);
    assert!(!g.is_pending(), "推完即清尾沿");
}

/// 🔴 **尾沿保证：冷却期内到达的孤立变更绝不能被吞掉。**
///
/// 这是节流实现最经典的一个坑，也是本闸门与「采样」的分界：变更落在冷却期内且此后再无变更时，
/// 若不做尾沿，这一帧就**永远**不会推（下一次 emit 要等下一次变化，可能几分钟后）——
/// 拓扑图停在旧状态，用户看到的现象与「流断了」完全一样，且没有任何日志。
///
/// **变异探针**：`mark_emitted` 里删掉 `pending = false` 之外的任何写法都不会红；
/// 真正的变异是把 `note_change` 改成「冷却期内直接丢弃」（`if self.should_emit(now) { .. }`）
/// ⇒ 本测转红。
#[test]
fn 冷却期内的孤立变更在冷却结束后仍会推出() {
    let mut g = gate();
    g.note_change();
    g.mark_emitted(1_000);

    // 冷却期内来一帧，此后再无任何变更
    g.note_change();
    assert!(!g.should_emit(1_100), "冷却期内先不推");
    assert!(g.is_pending(), "但必须记着这笔账");

    // 冷却一到，即便再没有新帧进来，也必须推出
    assert_eq!(g.wait_for(1_100), Some(Duration::from_millis(150)));
    assert!(
        g.should_emit(1_250),
        "尾沿：冷却结束必须把期内那笔变更推出，否则它永远不会到渲染端"
    );
}

/// `wait_for` 返回的是**剩余**时长，不是固定间隔（上层据此挂 `sleep`，多睡即多等一拍）。
#[test]
fn wait_for返回剩余冷却而非整段间隔() {
    let mut g = gate();
    g.note_change();
    g.mark_emitted(1_000);
    g.note_change();
    assert_eq!(g.wait_for(1_000), Some(TICK));
    assert_eq!(g.wait_for(1_100), Some(Duration::from_millis(150)));
    assert_eq!(g.wait_for(1_249), Some(Duration::from_millis(1)));
    assert_eq!(g.wait_for(1_250), Some(Duration::ZERO));
    assert_eq!(g.wait_for(9_999), Some(Duration::ZERO), "早已到期 → 立刻");
}

/// 🟡 **重订阅复位后首帧免冷却**（与降流门的「恢复不等整拍」对齐）。
///
/// **变异探针**：`reset` 只清 `pending` 不清 `last_emit_ms` ⇒ 转红 —— 用户切回窗口时
/// 要多等一个间隔才看到 reset 全量帧，而降流门那侧刚花力气保证了立刻唤醒。
#[test]
fn reset后首帧不背上一条流的冷却() {
    let mut g = gate();
    g.note_change();
    g.mark_emitted(1_000);
    assert!(!g.should_emit(1_050), "同一条流内仍受冷却");

    g.reset(); // 流被 drop（窗口隐藏）→ 重订阅
    assert!(!g.is_pending(), "复位必须清掉旧的待推标志（旧表已作废）");
    g.note_change(); // 重订阅后的 reset=true 全量首帧
    assert!(
        g.should_emit(1_050),
        "重订阅首帧必须免冷却，否则恢复要多等一个间隔"
    );
}

/// 时钟回拨不 panic、也不把 emit 永久饿死。
#[test]
fn 时钟回拨退化为等满一个间隔() {
    let mut g = gate();
    g.note_change();
    g.mark_emitted(1_000_000);
    g.note_change();
    // now < last：saturating_sub → elapsed 0 → 等满一个间隔（而非溢出成天文数字）
    assert_eq!(g.wait_for(0), Some(TICK));
    assert!(!g.should_emit(0));
}

/// 间隔为 0 时退化成「每帧都推」（不做闸门），且仍遵守尾沿语义。
#[test]
fn 零间隔退化为逐帧推送() {
    let mut g = EmitGate::new(Duration::ZERO);
    g.note_change();
    assert!(g.should_emit(0));
    g.mark_emitted(0);
    assert!(!g.should_emit(0), "无变更仍不推");
    g.note_change();
    assert!(g.should_emit(0));
}
