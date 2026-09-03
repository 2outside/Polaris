//! [`run_probe_check`] 的**真子进程**接线门。
//!
//! 起的是 [`write_sleeping_probe`] 写出来的 shell 探针（睡一会儿、建个见证文件、退出），
//! **不是** sing-box，不碰网络、不碰系统状态。
//!
//! # 守的是什么
//!
//! `run_probe_check` 此前自己写了一遍 `sing-box check` 的子进程接线，超时有、但漏了
//! `kill_on_drop(true)`：超时腿把 `output()` 的 future 直接丢掉，而 `tokio::process::Child` 的
//! `kill_on_drop` **默认是 false**，于是每次超时都留下一个游离的 `sing-box check`。现在它改调
//! `core-supervisor::config_gate::run_check_raw` —— 全仓唯一那份两样齐全的实现。
//!
//! 判据是**可观察的进程行为**：超时之后见证文件永不出现 ⇒ 子进程真的没跑完。为什么这能算证明、
//! 以及为什么只有 unix，见 [`write_sleeping_probe`] 的文档。

use std::path::Path;
use std::time::Duration;

use super::super::{run_probe_check, ProbeCheck};
use crate::test_support::{write_sleeping_probe, TestDir, PROBE_SLEEP_MILLIS};

/// **正向对照**：探针在预算内跑完 ⇒ 判 `Supported`，且见证文件真的出现。
///
/// 没有这一条，下面那条的「见证文件不存在」既可能是「子进程被杀了」，也可能是「路径压根没传对」——
/// 那样断言恒真、零信息量。
#[tokio::test]
async fn supported_and_lets_the_child_finish_when_it_fits_the_budget() {
    let dir = TestDir::new("polaris-probe-check-ok-");
    let witness = dir.path().join("ran.txt");
    let probe = write_sleeping_probe(dir.path(), &witness);

    let verdict = run_probe_check(&probe, Path::new("probe.json")).await;
    assert!(
        matches!(verdict, ProbeCheck::Supported),
        "探针 rc=0 ⇒ 必须判 Supported"
    );
    assert!(
        witness.exists(),
        "正向对照失败：探针跑完了却没写见证文件 —— 路径没传对，另一条的断言会恒真"
    );
}

/// 🔴 **变异锁：超时 → `Indeterminate`（failOpen）+ 子进程真的被杀掉**。
///
/// 改动前的这条腿会**留下游离进程**：超时判决是对的，但丢掉 future 并不杀子进程，那个
/// `sing-box check` 会一路跑完并写出见证文件。本测在那份源码上因此转红。
///
/// 时钟用 `start_paused`：超时预算是写死的 [`PROBE_CHECK_TIMEOUT`](super::super::PROBE_CHECK_TIMEOUT)
/// （8 s），而这里要验的是超时之后子进程的去向，不是 8 这个数。虚拟时钟在运行时空转时自动推进到
/// 定时器截止点，8 s 于是在微秒内走完，真实的探针一步都还没睡完。随后的等待用**真实**时钟：
/// 见证文件的有无是真实世界的事实。
#[tokio::test(start_paused = true)]
async fn timing_out_is_indeterminate_and_kills_the_child() {
    let dir = TestDir::new("polaris-probe-check-timeout-");
    let witness = dir.path().join("killed.txt");
    let probe = write_sleeping_probe(dir.path(), &witness);

    let verdict = run_probe_check(&probe, Path::new("probe.json")).await;
    assert!(
        matches!(verdict, ProbeCheck::Indeterminate),
        "超时是 failOpen：判 Supported 会把没验过的协议说成支持，判 Unsupported 会把一个\
         可能完全正常的协议标红"
    );

    // 真实时钟：等过探针的睡眠时长再看。活着的话这会儿早写完了。
    std::thread::sleep(Duration::from_millis(PROBE_SLEEP_MILLIS + 300));
    assert!(
        !witness.exists(),
        "超时后子进程仍跑完并写了见证文件 ⇒ `kill_on_drop(true)` 没生效，每次超时泄漏一个 check 进程"
    );
}
