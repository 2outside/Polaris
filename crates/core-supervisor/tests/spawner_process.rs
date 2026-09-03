//! `spawner` 的**真实子进程**接线门（三平台同跑）。
//!
//! **为什么在集成测试而非单元测试**：这些断言需要一个真实的子进程二进制，而拿到本 crate bin
//! 目标路径的 `CARGO_BIN_EXE_<name>` 只在集成测试 / bench 里由 cargo 注入（单元测试拿不到）。
//! 原先这几条住在 `src/spawner.rs` 的单元测试里、拿 `/bin/echo` `/bin/sleep` 顶替，
//! Windows 上两条静默 skip、一条硬 panic —— 平台盲区加 CI 恒红。探针见 `src/bin/argv_probe.rs`。
//!
//! 不触碰宿主网络：探针只打印/睡觉/往自己的 fd 2 写字节，不开任何端口、不碰任何接口。

use std::time::Duration;

use polaris_core_supervisor::{SingBoxSpawner, SpawnRequest, StdioPolicy, TokioSpawner};

/// 探针二进制绝对路径（cargo 在集成测试期注入）。
const PROBE: &str = env!("CARGO_BIN_EXE_argv_probe");

/// 灌多少字节到 stderr。1 MiB ≫ Linux 64 KiB / macOS 16 KiB 的管道容量，没人读必卡死。
const FLOOD_BYTES: usize = 1024 * 1024;

/// 子进程的两条流被完整收下来之后的内容。
struct Collected {
    stdout: String,
    stderr: String,
}

/// 造一条 `Drain` 策略：把两条流**并发**读到 EOF，再从 channel 交出来。
///
/// 两条流必须并发读（`tokio::join!` 在同一个任务里交替 poll），顺序读会在「先读 stdout、而 stderr
/// 先写满」时死锁 —— 那正是 `wait_with_output` 用 `try_join3` 的理由。
fn collect_stdio() -> (StdioPolicy, tokio::sync::oneshot::Receiver<Collected>) {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let policy = StdioPolicy::drain(move |mut out, mut err| {
        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let read_out = async {
                let mut buf = Vec::new();
                let _ = out.read_to_end(&mut buf).await;
                buf
            };
            let read_err = async {
                let mut buf = Vec::new();
                let _ = err.read_to_end(&mut buf).await;
                buf
            };
            let (o, e) = tokio::join!(read_out, read_err);
            let _ = tx.send(Collected {
                stdout: String::from_utf8_lossy(&o).into_owned(),
                stderr: String::from_utf8_lossy(&e).into_owned(),
            });
        });
    });
    (policy, rx)
}

/// 真实 spawn 一个常驻子进程：pid 可读 + 可被 kill。
#[tokio::test]
async fn tokio_spawner_real_child_spawns_and_pid_present() {
    let spawner = TokioSpawner::new();
    let req = SpawnRequest::new(PROBE, "--sleep", StdioPolicy::Discard);
    let mut spawned = spawner.spawn(req).expect("spawn 探针应成功");
    assert!(spawned.pid().is_some(), "pid 应可读");
    // 清理：杀掉子进程（探针最长驻留 30s，不留残骸）。
    let _ = spawned.child.start_kill();
    let _ = spawned.child.wait().await;
}

/// 回归：`TokioSpawner::spawn` 必须把 **完整 argv（含 `run` 子命令）** 交给子进程。
///
/// 此前 `.args(&req.argv()[1..])` 误按 C 约定当 argv\[0\] 是程序名切掉首元素 → `run` 丢失 →
/// 真核收到 `sing-box -c cfg` 打 usage 即退，上层只看到「启动期退出」。
///
/// **为什么既有的 argv 单测没抓到**：`spawn_request_argv_*` 只测 `argv()` 本身（对的），
/// 真实 spawn 的那几条为图省事**绕开 SpawnRequest 直接用 Command** —— 于是「argv 生成」与
/// 「spawn 传参」各自有门，二者的**组合**（真正的生产路径）无门。本测试专补这个组合。
#[tokio::test]
async fn tokio_spawner_passes_run_subcommand_to_child() {
    let spawner = TokioSpawner::new();
    let (policy, rx) = collect_stdio();
    let req = SpawnRequest::new(PROBE, "/tmp/polaris-argv-probe.json", policy);
    let mut spawned = spawner.spawn(req).expect("spawn 探针应成功");
    let _ = spawned.child.wait().await;
    let printed = rx.await.expect("排空回调必须交回探针输出");
    assert_eq!(
        printed.stdout.trim(),
        "run -c /tmp/polaris-argv-probe.json",
        "子进程必须收到完整 argv（含 run 子命令）；实收：{:?}",
        printed.stdout
    );
}

/// 🔴 **stdio 收口的正向接线门**：`Drain` 策略下两条管道在 spawner 返回**之前**就已交给回调，
/// 且 `SpawnedChild` 手里不再有任何管道。
///
/// 断言分两半：① 回调真的收到了子进程的 stdout 内容（管道接上了、读端交出去了）；
/// ② `spawned.child.stdout` / `.stderr` 都是 `None`（child 离开 spawner 时不带未排空的管道 ——
/// 这条不变式是「起了核却忘记排空」在类型上写不出来的物理依据）。
///
/// **牙**：删掉 `TokioSpawner::spawn` 里那句 `sink(...)` ⇒ ① 的 `rx.await` 拿不到东西、②
/// 的两个 `None` 断言同时红。
#[tokio::test]
async fn tokio_spawner_hands_both_pipes_to_the_policy_before_returning() {
    let spawner = TokioSpawner::new();
    let (policy, rx) = collect_stdio();
    let req = SpawnRequest::new(PROBE, "polaris-test-marker", policy);
    let mut spawned = spawner.spawn(req).expect("spawn 探针应成功");
    assert!(
        spawned.child.stdout.is_none() && spawned.child.stderr.is_none(),
        "child 离开 spawner 时不得再带着管道：带着走就意味着「谁来读」这半件事又落回了调用方"
    );
    let status = spawned.child.wait().await.expect("等探针退出");
    assert!(status.success());
    let collected = rx.await.expect("排空回调必须交回探针输出");
    assert!(
        collected.stdout.contains("polaris-test-marker"),
        "回调收到的 stdout 里应有探针写的标记；实收：{:?}",
        collected.stdout
    );
}

/// 🔴 **进程级灌满门（本收口的行为证据，不是源码 grep）**：子进程往 stderr 灌 1 MiB，
/// `Drain` 策略必须一路排空它，子进程在预算内正常退出。
///
/// 1 MiB 是 Linux 管道容量（64 KiB）的 16 倍、macOS 初始容量（16 KiB）的 64 倍 —— 没人读的话
/// 探针必然卡在 `write(2)` 上，`wait()` 永不返回。2026-09-02 测速临时核卡死的就是这条链，
/// 这里把它搬成三平台同跑、零网络、零 sing-box 的自动化门。
///
/// **牙**：删掉 `TokioSpawner::spawn` 里的 `sink(...)` ⇒ 探针停在管道容量处 ⇒ 本测超时转红。
#[tokio::test]
async fn a_child_that_floods_stderr_is_drained_instead_of_wedged() {
    let spawner = TokioSpawner::new();
    let (policy, rx) = collect_stdio();
    let req = SpawnRequest::new(PROBE, format!("--flood-stderr:{FLOOD_BYTES}"), policy);
    let mut spawned = spawner.spawn(req).expect("spawn 探针应成功");
    let status = tokio::time::timeout(Duration::from_secs(20), spawned.child.wait())
        .await
        .expect("灌满 stderr 的子进程必须能退出 —— 超时即说明管道没人读、write(2) 卡死了")
        .expect("等探针退出");
    assert!(status.success());
    let collected = rx.await.expect("排空回调必须交回探针输出");
    assert!(
        collected.stderr.len() >= FLOOD_BYTES,
        "必须把整 {FLOOD_BYTES} 字节读完；实收 {} 字节",
        collected.stderr.len()
    );
}

/// 🔵 **反向对照**：`Discard` 策略下同一个灌满的探针同样不卡 —— 证明上一条的绿不是因为
/// 「1 MiB 其实没越过管道容量」，而是因为真的有人在读。
///
/// `Discard` 压根不开管道（两路 `Stdio::null()`），子进程写进 `/dev/null`（Windows 为 NUL），
/// 内核直接丢弃。这条腿绿而「开管道却没人读」那条腿红，两者的差就是本次收口守的东西。
#[tokio::test]
async fn a_flooding_child_also_survives_the_discard_policy() {
    let spawner = TokioSpawner::new();
    let req = SpawnRequest::new(
        PROBE,
        format!("--flood-stderr:{FLOOD_BYTES}"),
        StdioPolicy::Discard,
    );
    let mut spawned = spawner.spawn(req).expect("spawn 探针应成功");
    assert!(
        spawned.child.stdout.is_none() && spawned.child.stderr.is_none(),
        "Discard 下不该有任何管道"
    );
    let status = tokio::time::timeout(Duration::from_secs(20), spawned.child.wait())
        .await
        .expect("Discard 下输出被内核丢弃，绝不该阻塞")
        .expect("等探针退出");
    assert!(status.success());
}

/// 回归·CWD 接线：`working_dir` 设定 → 子进程真的 chdir 到该目录。
///
/// **变异门**：删掉 `if let Some(cwd) … cmd.current_dir(cwd)` → CWD 回落测试进程 CWD → 断言转红。
/// 两侧都 canonicalize 再比：macOS 上 `/tmp` 是 `/private/tmp` 符号链接，Windows 上有 `\\?\` 前缀。
#[tokio::test]
async fn tokio_spawner_applies_working_dir() {
    let dir = std::env::temp_dir().join(format!("polaris-cwd-probe-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("建探针工作目录");
    let expected = std::fs::canonicalize(&dir).expect("canonicalize 期望 CWD");

    let spawner = TokioSpawner::new();
    let (policy, rx) = collect_stdio();
    let mut req = SpawnRequest::new(PROBE, "--pwd", policy);
    req.working_dir = Some(dir.clone());
    let mut spawned = spawner.spawn(req).expect("spawn 探针应成功");
    let _ = spawned.child.wait().await;
    let printed = rx.await.expect("排空回调必须交回探针输出");
    let actual = std::fs::canonicalize(printed.stdout.trim()).expect("canonicalize 实得 CWD");

    assert_eq!(
        actual, expected,
        "子进程 CWD 应为 working_dir；实得：{:?}",
        printed.stdout
    );
    let _ = std::fs::remove_dir_all(&dir);
}
