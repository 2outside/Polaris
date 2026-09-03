//! [`SingBoxConfigChecker`] 的**真子进程**接线门。
//!
//! 与本目录其余测试相反，这两条真起一个子进程 —— 起的是 [`write_sleeping_probe`] 写出来的
//! shell 探针（睡一会儿、建个见证文件、退出），**不是** sing-box，不碰网络、不碰系统状态。
//!
//! # 守的是什么
//!
//! `SingBoxConfigChecker::check` 此前自己写了一遍 `sing-box check` 的子进程接线，而那一份**没有
//! 超时**：`output()` 会一直等到子进程自己退出。它挂在瞬态登录核与测速临时核的起核前置位上，
//! 于是 check 一旦挂住（慢盘、杀软扫描、核二进制半损坏），整条登录/测速流程跟着永久挂起。
//! 现在它改调 `core-supervisor::config_gate::run_check_raw` —— 全仓唯一那份带超时与
//! `kill_on_drop(true)` 的实现。本文件验的就是「它确实走了那条实现」这件事本身，判据是**可观察的
//! 进程行为**（返回了、且子进程死了），不是「函数存在」。
//!
//! # 为什么只有 unix
//!
//! 见 [`write_sleeping_probe`] 的文档：跨平台的那一半（超时与 `kill_on_drop` 自身）由
//! `crates/core-supervisor/tests/config_gate_process.rs` 用 Rust 探针在三平台各跑一遍；本处只验
//! 本包这个调用点接到了那条实现上，而这件事与平台无关。

use std::path::Path;
use std::time::Duration;

use super::super::{ConfigChecker, SingBoxConfigChecker};
use crate::test_support::{write_sleeping_probe, TestDir, PROBE_SLEEP_MILLIS};

/// **正向对照**：探针在预算内跑完 ⇒ 判 `Ok`，且见证文件真的出现。
///
/// 没有这一条，下面那条的「见证文件不存在」既可能是「子进程被杀了」，也可能是「路径压根没传对、
/// 这条腿从来就写不出文件」—— 那样断言恒真、零信息量。
#[tokio::test]
async fn accepts_and_lets_the_child_finish_when_it_fits_the_budget() {
    let dir = TestDir::new("polaris-login-cfgcheck-ok-");
    let witness = dir.path().join("ran.txt");
    let probe = write_sleeping_probe(dir.path(), &witness);

    SingBoxConfigChecker
        .check(&probe, Path::new("config.json"))
        .await
        .expect("探针 rc=0 ⇒ 必须判 Ok");

    assert!(
        witness.exists(),
        "正向对照失败：探针跑完了却没写见证文件 —— 路径没传对，另一条的断言会恒真"
    );
}

/// 🔴 **变异锁：check 挂住时必须超时返回，且子进程真的被杀掉**。
///
/// 改动前这一整条腿是不存在的：`SingBoxConfigChecker::check` 没有任何超时，喂它一个不退出的
/// 子进程，`await` 永不返回 —— 本测在那份源码上跑不完（挂死），而不是失败一次就结束。
///
/// 时钟用 `start_paused`：超时预算是写死的 [`CONFIG_CHECK_TIMEOUT`](polaris_core_supervisor::CONFIG_CHECK_TIMEOUT)
/// （5 s），而这里要验的是「有没有超时这条腿」，不是「5 到底合不合适」。虚拟时钟在运行时空转时
/// 自动推进到定时器截止点，于是 5 s 在微秒内走完，而真实的探针一步都还没睡完 ⇒ 超时腿必然先手，
/// 测试却不必真等 5 秒。随后的等待用**真实**时钟：见证文件的有无是真实世界的事实。
#[tokio::test(start_paused = true)]
async fn times_out_instead_of_hanging_and_kills_the_child() {
    let dir = TestDir::new("polaris-login-cfgcheck-timeout-");
    let witness = dir.path().join("killed.txt");
    let probe = write_sleeping_probe(dir.path(), &witness);

    let err = SingBoxConfigChecker
        .check(&probe, Path::new("config.json"))
        .await
        .expect_err("超时必须报错，而不是把一份没验过的配置当成通过");
    assert!(
        err.contains("超时"),
        "超时腿的文案要说得出是超时（调用方会把它原样呈给用户）；实得：{err}"
    );

    // 真实时钟：等过探针的睡眠时长再看。活着的话这会儿早写完了。
    std::thread::sleep(Duration::from_millis(PROBE_SLEEP_MILLIS + 300));
    assert!(
        !witness.exists(),
        "超时后子进程仍跑完并写了见证文件 ⇒ `kill_on_drop(true)` 没生效，每次超时泄漏一个 check 进程"
    );
}
