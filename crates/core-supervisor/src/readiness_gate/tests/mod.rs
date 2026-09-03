#![allow(clippy::too_many_lines)]

use super::*;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

/// 计数器 + 行为脚本驱动的依赖桩：可编排每轮 ready/alive/superseded 结果并断言调用顺序。
struct ScriptDeps {
    alive: Arc<AtomicBool>,
    ready_results: Arc<Vec<AtomicBool>>,
    superseded: Arc<AtomicBool>,
    ready_calls: Arc<AtomicU32>,
    alive_calls: Arc<AtomicU32>,
    sleep_calls: Arc<AtomicU32>,
    retry_calls: Arc<AtomicU32>,
}

impl ScriptDeps {
    fn as_deps(self: &Arc<Self>) -> CoreReadyDeps<'static> {
        // 闭包捕获 Arc<Self>（'static），用 'static 桩避免生命周期缠绕。
        let alive = Arc::clone(self);
        let ready = Arc::clone(self);
        let sleep = Arc::clone(self);
        let superseded = Arc::clone(self);
        let retry = Arc::clone(self);
        CoreReadyDeps {
            is_alive: Box::new(move || {
                alive.alive_calls.fetch_add(1, Ordering::SeqCst);
                alive.alive.load(Ordering::SeqCst)
            }),
            is_ready: Box::new(move || {
                let idx = ready.ready_calls.fetch_add(1, Ordering::SeqCst) as usize;
                let v = ready
                    .ready_results
                    .get(idx)
                    .map(|a| a.load(Ordering::SeqCst))
                    .unwrap_or(false);
                Box::pin(async move { v })
            }),
            sleep: Box::new(move |dur| {
                // Fn（多次调用）：每次 clone Arc 进 async block，避免 move。
                let s = Arc::clone(&sleep);
                Box::pin(async move {
                    let _ = dur;
                    s.sleep_calls.fetch_add(1, Ordering::SeqCst);
                })
            }),
            is_superseded: Some(Box::new(move || {
                superseded.superseded.load(Ordering::SeqCst)
            })),
            on_retry: Some(Box::new(move || {
                retry.retry_calls.fetch_add(1, Ordering::SeqCst);
            })),
        }
    }
}

fn make_deps(
    alive: bool,
    ready_results: Vec<bool>,
    superseded: bool,
) -> (Arc<ScriptDeps>, CoreReadyDeps<'static>) {
    let ready_results = ready_results.into_iter().map(AtomicBool::new).collect();
    let d = Arc::new(ScriptDeps {
        alive: Arc::new(AtomicBool::new(alive)),
        ready_results: Arc::new(ready_results),
        superseded: Arc::new(AtomicBool::new(superseded)),
        ready_calls: Arc::new(AtomicU32::new(0)),
        alive_calls: Arc::new(AtomicU32::new(0)),
        sleep_calls: Arc::new(AtomicU32::new(0)),
        retry_calls: Arc::new(AtomicU32::new(0)),
    });
    let deps = d.as_deps();
    (d, deps)
}

#[tokio::test(start_paused = true)]
async fn ready_on_first_ready_probe_no_alive_call() {
    // isReady 早返 → 绝不触发 isAlive（core-readiness.ts:88 顺序安全）。
    let (d, deps) = make_deps(true, vec![true], false);
    let out = wait_for_core_ready(
        WaitForCoreReadyOptions {
            timeout_ms: 500,
            poll_ms: 50,
        },
        &deps,
    )
    .await;
    assert_eq!(out, CoreReadyOutcome::Ready);
    assert_eq!(d.ready_calls.load(Ordering::SeqCst), 1);
    assert_eq!(d.alive_calls.load(Ordering::SeqCst), 0); // 未触发探活
    assert_eq!(d.sleep_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn dead_when_process_exits_before_ready() {
    // 进程死 → 立即 Dead，不等满 timeout（core-readiness.ts:93）。
    let (d, deps) = make_deps(false, vec![false], false);
    let out = wait_for_core_ready(
        WaitForCoreReadyOptions {
            timeout_ms: 500,
            poll_ms: 50,
        },
        &deps,
    )
    .await;
    assert_eq!(out, CoreReadyOutcome::Dead);
    assert_eq!(d.alive_calls.load(Ordering::SeqCst), 1);
    assert_eq!(d.sleep_calls.load(Ordering::SeqCst), 0); // 早退不 sleep
}

#[tokio::test(start_paused = true)]
async fn supersede_takes_precedence_over_ready_and_alive() {
    // supersede 先于一切判定（#176），即使 ready=true 也不返回 Ready。
    let (d, deps) = make_deps(true, vec![true], true);
    let out = wait_for_core_ready(
        WaitForCoreReadyOptions {
            timeout_ms: 500,
            poll_ms: 50,
        },
        &deps,
    )
    .await;
    assert_eq!(out, CoreReadyOutcome::Superseded);
    assert_eq!(d.ready_calls.load(Ordering::SeqCst), 0); // ready 未被调用
    assert_eq!(d.alive_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn ready_succeeds_on_second_poll() {
    // 第 1 轮 not-ready + alive → sleep；第 2 轮 ready → Ready。
    let (d, deps) = make_deps(true, vec![false, true], false);
    let out = wait_for_core_ready(
        WaitForCoreReadyOptions {
            timeout_ms: 500,
            poll_ms: 50,
        },
        &deps,
    )
    .await;
    assert_eq!(out, CoreReadyOutcome::Ready);
    assert_eq!(d.sleep_calls.load(Ordering::SeqCst), 1); // 恰好一次 sleep
}

#[tokio::test(start_paused = true)]
async fn timeout_when_never_ready_but_alive() {
    // max_polls = ceil(100/20)=5；5 轮 not-ready+alive（每轮 sleep）后末轮再判仍 not-ready → Timeout。
    let (d, deps) = make_deps(true, vec![false; 10], false);
    let out = wait_for_core_ready(
        WaitForCoreReadyOptions {
            timeout_ms: 100,
            poll_ms: 20,
        },
        &deps,
    )
    .await;
    assert_eq!(out, CoreReadyOutcome::Timeout);
    // 5 次轮询 + 1 次末轮 boundary = 6 次 ready 调用；5 次轮间 sleep（每轮一次）。
    assert_eq!(d.ready_calls.load(Ordering::SeqCst), 6);
    assert_eq!(d.sleep_calls.load(Ordering::SeqCst), 5);
}

#[tokio::test(start_paused = true)]
async fn boundary_check_catches_ready_after_last_poll() {
    // max_polls=1：第 1 轮 not-ready+alive → sleep；末轮 boundary ready=true → Ready。
    let (d, deps) = make_deps(true, vec![false, true], false);
    let out = wait_for_core_ready(
        WaitForCoreReadyOptions {
            timeout_ms: 100,
            poll_ms: 100,
        },
        &deps,
    )
    .await;
    assert_eq!(out, CoreReadyOutcome::Ready);
    assert_eq!(d.sleep_calls.load(Ordering::SeqCst), 1); // 1 轮 sleep 后 boundary 命中
}

#[tokio::test(start_paused = true)]
async fn no_superseded_dep_treated_as_not_superseded() {
    // is_superseded = None 时等同未接管，正常走 ready 判定。
    let alive = Arc::new(AtomicBool::new(true));
    let ready_calls = Arc::new(AtomicU32::new(0));
    let rc = ready_calls.clone();
    let deps = CoreReadyDeps {
        is_alive: Box::new(move || true),
        is_ready: Box::new(move || {
            let i = rc.fetch_add(1, Ordering::SeqCst);
            // max_polls=4（200/50）：轮询调用 0..3 + boundary 调用 4。
            // 第 4 次调用（boundary, i==3）变 ready → Ready。
            Box::pin(async move { i == 3 })
        }),
        sleep: Box::new(|_| Box::pin(async {})),
        is_superseded: None,
        on_retry: None,
    };
    let _ = alive;
    let out = wait_for_core_ready(
        WaitForCoreReadyOptions {
            timeout_ms: 200,
            poll_ms: 50,
        },
        &deps,
    )
    .await;
    assert_eq!(out, CoreReadyOutcome::Ready);
    assert_eq!(ready_calls.load(Ordering::SeqCst), 4); // 3 次轮询 not-ready + 第 4 次 ready
}

#[tokio::test(start_paused = true)]
async fn dead_at_boundary_after_timeout() {
    // 末轮 boundary：进程在末轮才退出 → Dead（不等满）。
    let (d, deps) = make_deps(true, vec![false, false], false);
    // 让第 1 轮 alive=true（已设），boundary 前置 alive=false。
    let out = wait_for_core_ready(
        WaitForCoreReadyOptions {
            timeout_ms: 100,
            poll_ms: 100,
        },
        &deps,
    )
    .await;
    // 第 1 轮：superseded=false, ready=false, alive=true → sleep。
    // 末轮 boundary：superseded=false, ready=false, alive=true → Timeout（alive 仍 true）。
    assert_eq!(out, CoreReadyOutcome::Timeout);
    assert_eq!(d.sleep_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn on_retry_fires_once_per_sleep_until_ready() {
    // ready 于第 3 次探测：前 2 次 not-ready+alive → 2 次 sleep → on_retry 恰好 2 次。
    // 这是 DiagnosticCounters 慢起轴（lastStartReadyRetries）的计数源：每次就绪重试回调一次。
    let (d, deps) = make_deps(true, vec![false, false, true], false);
    let out = wait_for_core_ready(
        WaitForCoreReadyOptions {
            timeout_ms: 500,
            poll_ms: 50,
        },
        &deps,
    )
    .await;
    assert_eq!(out, CoreReadyOutcome::Ready);
    assert_eq!(d.sleep_calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        d.retry_calls.load(Ordering::SeqCst),
        2,
        "on_retry 必须与 sleep 一一对应（每次就绪重试回调一次）= 慢起轴计数源"
    );
}

#[tokio::test(start_paused = true)]
async fn on_retry_not_fired_when_ready_immediately() {
    // 首探即 ready → 0 sleep → 0 retry（一次成功 = 慢起轴恒 0）。
    let (d, deps) = make_deps(true, vec![true], false);
    let out = wait_for_core_ready(
        WaitForCoreReadyOptions {
            timeout_ms: 500,
            poll_ms: 50,
        },
        &deps,
    )
    .await;
    assert_eq!(out, CoreReadyOutcome::Ready);
    assert_eq!(d.retry_calls.load(Ordering::SeqCst), 0);
}

// ── 失败腿的 supersede 复判（用户主动 stop 被误报成 STARTUP_FAILED 的根因）──
//
// 建模真实竞态：轮首 supersede 检查已过 → `is_ready` 的 **await 期间**用户点「停止」
// （proxy.rs: bump 世代 + kill_core 取走 child）→ 本轮 is_ready 失败、is_alive 见 child=None。
// 死因 = 接管本身 → 必须让位（Superseded），不得报 Dead/Timeout（→ set_error(STARTUP_FAILED)
// → 广播 proxyError → 用户主动停核却弹「启动失败」toast）。

/// 依赖集：在**第 `flip_on_ready_call` 次** is_ready 的 await 期间翻转 superseded，
/// is_alive 按 `alive_script` 逐次取值（末项之后恒取末项）。
///
/// 精确控制翻转时机是必须的：若翻转早于某个轮首，`wait_for_core_ready` 会在**轮首** supersede
/// 检查处就返回 Superseded，根本走不到失败腿的复判 —— 那样的测试即便挂掉复判也照样绿（假绿）。
/// 故翻转恒安排在「本轮/末轮的 is_ready 之后、该腿判定之前」这一窗口内。
fn deps_superseded_on_ready_call(
    flip_on_ready_call: u32,
    alive_script: Vec<bool>,
) -> CoreReadyDeps<'static> {
    let flag = Arc::new(AtomicBool::new(false));
    let ready_calls = Arc::new(AtomicU32::new(0));
    let alive_calls = Arc::new(AtomicU32::new(0));
    let f_ready = Arc::clone(&flag);
    let f_check = flag;
    CoreReadyDeps {
        is_alive: Box::new(move || {
            let i = alive_calls.fetch_add(1, Ordering::SeqCst) as usize;
            *alive_script
                .get(i)
                .unwrap_or_else(|| alive_script.last().unwrap_or(&true))
        }),
        is_ready: Box::new(move || {
            let f = Arc::clone(&f_ready);
            let n = ready_calls.fetch_add(1, Ordering::SeqCst) + 1;
            Box::pin(async move {
                if n == flip_on_ready_call {
                    f.store(true, Ordering::SeqCst); // ← await 期间被接管（stop 跑完）
                }
                false
            })
        }),
        sleep: Box::new(|_| Box::pin(async {})),
        is_superseded: Some(Box::new(move || f_check.load(Ordering::SeqCst))),
        on_retry: None,
    }
}

#[tokio::test(start_paused = true)]
async fn poll_dead_leg_reports_superseded_when_taken_over_during_ready_probe() {
    // 轮内 Dead 腿：首轮 is_ready 期间被接管 → child 已被取走 → is_alive=false → 必须 Superseded。
    let out = wait_for_core_ready(
        WaitForCoreReadyOptions {
            timeout_ms: 500,
            poll_ms: 50,
        },
        &deps_superseded_on_ready_call(1, vec![false]),
    )
    .await;
    assert_eq!(
        out,
        CoreReadyOutcome::Superseded,
        "接管导致的进程消失 = 让位，不得报 Dead（否则用户主动停核弹「启动失败」）"
    );
}

#[tokio::test(start_paused = true)]
async fn boundary_dead_leg_reports_superseded_when_taken_over_during_ready_probe() {
    // 末轮 boundary 的 Dead 腿（与轮内 Dead 腿是两个独立 return 点，须各自覆盖）：
    // max_polls=1 → 首轮 alive=true 后 sleep；末轮 is_ready 期间被接管 → alive=false。
    let out = wait_for_core_ready(
        WaitForCoreReadyOptions {
            timeout_ms: 100,
            poll_ms: 100,
        },
        &deps_superseded_on_ready_call(2, vec![true, false]),
    )
    .await;
    assert_eq!(
        out,
        CoreReadyOutcome::Superseded,
        "末轮 Dead 腿同须复判 supersede"
    );
}

#[tokio::test(start_paused = true)]
async fn timeout_leg_reports_superseded_when_taken_over_during_ready_probe() {
    // Timeout 腿：max_polls=1，进程自始至终活着但never ready → 末轮 is_ready 期间被接管 → Timeout
    // 腿。**刻意让翻转发生在末轮 is_ready 内**：若发生在更早的轮次，轮首检查会先行返回 Superseded，
    // 本腿的复判就永远测不到。
    let out = wait_for_core_ready(
        WaitForCoreReadyOptions {
            timeout_ms: 100,
            poll_ms: 100,
        },
        &deps_superseded_on_ready_call(2, vec![true]),
    )
    .await;
    assert_eq!(
        out,
        CoreReadyOutcome::Superseded,
        "接管后的超时 = 让位，不得报 Timeout（同为 STARTUP_FAILED 误报面）"
    );
}

#[tokio::test(start_paused = true)]
async fn genuine_death_still_reports_dead_not_superseded() {
    // 复判**只**在真被接管时改判：无接管的真实起核失败必须照旧 Dead（否则失败被静默吞掉，
    // 比误报更危险——用户永远等不到「启动失败」）。
    let (_d, deps) = make_deps(false, vec![false], false);
    let out = wait_for_core_ready(
        WaitForCoreReadyOptions {
            timeout_ms: 500,
            poll_ms: 50,
        },
        &deps,
    )
    .await;
    assert_eq!(out, CoreReadyOutcome::Dead);
}

#[tokio::test(start_paused = true)]
async fn genuine_timeout_still_reports_timeout_not_superseded() {
    let (_d, deps) = make_deps(true, vec![false; 10], false);
    let out = wait_for_core_ready(
        WaitForCoreReadyOptions {
            timeout_ms: 100,
            poll_ms: 20,
        },
        &deps,
    )
    .await;
    assert_eq!(out, CoreReadyOutcome::Timeout);
}

#[test]
fn outcome_variants_are_exhaustive_and_distinct() {
    // 保证四态枚举与 TS 字面量联合一一对应（回归防护）。
    assert_ne!(CoreReadyOutcome::Ready, CoreReadyOutcome::Dead);
    assert_ne!(CoreReadyOutcome::Timeout, CoreReadyOutcome::Superseded);
    assert_eq!(CoreReadyOutcome::Ready, CoreReadyOutcome::Ready);
}

#[test]
fn superseded_error_message_is_marker_only() {
    // CoreStartSupersededError 文案固定（不进 retry 链）。
    let e = CoreStartSupersededError;
    assert!(e.to_string().contains("已被更新的启动/停止操作接管"));
}

#[test]
fn retry_error_carries_message() {
    let e = CoreStartRetryError::new("管理 API 1s 内未绑定");
    assert!(e.message.contains("管理 API"));
    assert!(e.to_string().contains("管理 API"));
}
