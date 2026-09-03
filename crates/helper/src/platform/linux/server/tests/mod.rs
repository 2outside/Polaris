#![allow(clippy::too_many_lines)]

use super::*;

#[test]
fn default_config_paths_match_design() {
    // 锁住默认路径（运维契约：systemd unit 文件、pkexec 安装器依赖这些路径）。
    let cfg = ServerConfig::default();
    assert_eq!(cfg.sock_path, PathBuf::from("/run/polaris/helper.sock"));
    assert_eq!(
        cfg.auth_file,
        PathBuf::from("/var/lib/polaris/authorized-uids")
    );
    assert_eq!(
        cfg.core_dir,
        Some(PathBuf::from("/usr/local/lib/polaris/core"))
    );
    assert!(!cfg.console);
}

#[test]
fn default_constants_match_strings() {
    // 常量是 wire/运维契约（改名 = 断 systemd unit 引用）。
    assert_eq!(DEFAULT_SOCK_PATH, "/run/polaris/helper.sock");
    assert_eq!(DEFAULT_AUTH_FILE, "/var/lib/polaris/authorized-uids");
    assert_eq!(DEFAULT_CORE_DIR, "/usr/local/lib/polaris/core");
}

#[test]
fn server_config_can_override_paths() {
    let cfg = ServerConfig {
        sock_path: PathBuf::from("/tmp/test.sock"),
        auth_file: PathBuf::from("/tmp/auth"),
        core_dir: None,
        console: true,
    };
    assert_eq!(cfg.sock_path, PathBuf::from("/tmp/test.sock"));
    assert!(cfg.core_dir.is_none());
    assert!(cfg.console);
}

#[test]
fn server_config_clone_is_deep_copy() {
    let cfg = ServerConfig::default();
    let cfg2 = cfg.clone();
    assert_eq!(cfg.sock_path, cfg2.sock_path);
    assert_eq!(cfg.auth_file, cfg2.auth_file);
}

#[test]
fn prepare_socket_creates_dir_and_binds() {
    // 真实 socket bind（不碰宿主：用 tempdir，非 /run）。
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("test.sock");
    let cfg = ServerConfig {
        sock_path: sock.clone(),
        auth_file: dir.path().join("auth"),
        core_dir: None,
        console: false,
    };
    let listener = prepare_socket(&cfg).expect("prepare_socket 应成功");
    // socket 文件已创建。
    assert!(sock.exists(), "socket 文件应被创建");
    // 权限 0666（socket 本身可连）。
    use std::os::unix::fs::MetadataExt;
    let mode = std::fs::metadata(&sock).unwrap().mode() & 0o777;
    assert_eq!(mode, 0o666, "socket 应 chmod 0666");
    // 目录权限 0755。
    let dir_mode = std::fs::metadata(dir.path()).unwrap().mode() & 0o777;
    assert_eq!(dir_mode, 0o755, "socket 目录应 0755");
    // listener 可用（drop 关闭）。
    drop(listener);
}

#[test]
fn prepare_socket_removes_stale_socket() {
    // 旧 socket 存在 → 应删后重 bind（Go :31 os.Remove）。
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("stale.sock");
    // 造一个 stale socket 文件。
    std::fs::write(&sock, b"stale").unwrap();
    let cfg = ServerConfig {
        sock_path: sock.clone(),
        auth_file: dir.path().join("auth"),
        core_dir: None,
        console: false,
    };
    let listener = prepare_socket(&cfg).expect("应清旧 socket 后成功 bind");
    // 内容应被新 socket 替换（非 "stale"）。
    assert!(sock.exists());
    let meta = std::fs::metadata(&sock).unwrap();
    // unix socket 是特殊类型（非普通文件）。
    use std::os::unix::fs::FileTypeExt;
    assert!(meta.file_type().is_socket(), "应是 unix socket 类型");
    drop(listener);
}

#[test]
fn prepare_socket_fails_on_uncreatable_dir() {
    // 目录路径不可创建（如 /proc 下的虚构路径）→ Mkdir 错误。
    let cfg = ServerConfig {
        sock_path: PathBuf::from("/proc/nonexistent_root_xyz/test.sock"),
        auth_file: PathBuf::from("/tmp/auth"),
        core_dir: None,
        console: false,
    };
    let r = prepare_socket(&cfg);
    assert!(r.is_err());
    match r {
        Err(ServerError::Mkdir { .. }) => {}
        other => panic!("expected Mkdir error, got {other:?}"),
    }
}

#[test]
fn set_mode_sets_unix_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("mode_test");
    std::fs::write(&f, b"x").unwrap();
    set_mode(&f, 0o600).unwrap();
    use std::os::unix::fs::MetadataExt;
    let mode = std::fs::metadata(&f).unwrap().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn pinned_log_path_survives_parent_name_swap() {
    let dir = tempfile::tempdir().unwrap();
    let live = dir.path().join("live");
    let moved = dir.path().join("moved");
    let decoy = dir.path().join("decoy");
    std::fs::create_dir_all(&live).unwrap();
    std::fs::create_dir_all(&decoy).unwrap();
    let uid = nix::unistd::getuid().as_raw();
    let pinned = pin_log_path(&live.join("core.log"), uid).unwrap();

    std::fs::rename(&live, &moved).unwrap();
    std::os::unix::fs::symlink(&decoy, &live).unwrap();
    std::fs::write(&pinned.path, b"safe").unwrap();

    assert_eq!(std::fs::read(moved.join("core.log")).unwrap(), b"safe");
    assert!(!decoy.join("core.log").exists());
}

#[test]
fn pinned_log_path_rejects_directory_owned_by_another_uid() {
    let dir = tempfile::tempdir().unwrap();
    let uid = nix::unistd::getuid().as_raw();
    let wrong_uid = uid.checked_add(1).unwrap_or(uid.saturating_sub(1));
    let error = pin_log_path(&dir.path().join("core.log"), wrong_uid).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
}

#[test]
fn ss_lookup_returns_none_when_ss_missing() {
    // ss 可能未装（best-effort，Go 同样容忍）。
    // 仅验证不 panic；结果 None 或 Some 均可（取决于机器）。
    let _ = ss_lookup("99999");
}

// ===== L16 AmbientCaps 集/常量（对照 Go helper.go:51-55,441）=====

#[test]
fn ambient_caps_match_go_set_and_l16_constants() {
    // 集内容 + 顺序对照 Go AmbientCaps=[NET_ADMIN, NET_RAW, NET_BIND_SERVICE]（:441）。
    let caps = ambient_caps();
    assert_eq!(caps.len(), 3);
    assert_eq!(caps[0], caps::Capability::CAP_NET_ADMIN);
    assert_eq!(caps[1], caps::Capability::CAP_NET_RAW);
    assert_eq!(caps[2], caps::Capability::CAP_NET_BIND_SERVICE);
    // L16 数值常量 == 内核 cap 号 == caps crate 的 index()（Go helper.go:52-54）。
    assert_eq!(CAP_NET_BIND_SERVICE_NUM, 10);
    assert_eq!(CAP_NET_ADMIN_NUM, 12);
    assert_eq!(CAP_NET_RAW_NUM, 13);
    assert_eq!(
        caps::Capability::CAP_NET_BIND_SERVICE.index(),
        CAP_NET_BIND_SERVICE_NUM
    );
    assert_eq!(caps::Capability::CAP_NET_ADMIN.index(), CAP_NET_ADMIN_NUM);
    assert_eq!(caps::Capability::CAP_NET_RAW.index(), CAP_NET_RAW_NUM);
}

// ===== terminate 决策（TERM→≤5s→KILL；不发真信号）=====

#[test]
fn terminate_child_kills_only_on_timeout() {
    // 期限内退出 → 只 TERM，不 KILL（Go: <-done 分支）。
    let mut termed = false;
    let mut killed = false;
    terminate_child(
        || termed = true,
        || true, /* exited */
        || killed = true,
    );
    assert!(termed, "应先 TERM");
    assert!(!killed, "期限内退出不应 KILL");
}

#[test]
fn terminate_child_escalates_to_kill_on_timeout() {
    // 超时未退 → TERM 后 KILL（Go: <-time.After(5s) 分支）。
    let mut termed = false;
    let mut killed = false;
    terminate_child(
        || termed = true,
        || false, /* timeout */
        || killed = true,
    );
    assert!(termed);
    assert!(killed, "超时应升级 KILL");
}

// ===== watchParent 决策（对照 Go watchParent 循环体）=====

#[test]
fn watch_parent_step_truth_table() {
    // 非当前 child → 停（Go: if !current { return }）—— 优先于父存活判定。
    assert_eq!(watch_parent_step(false, true), WatchStep::Stop);
    assert_eq!(watch_parent_step(false, false), WatchStep::Stop);
    // 当前 child + 父死 → ParentDead（Go: kill(ppid,0)==ESRCH）。
    assert_eq!(watch_parent_step(true, false), WatchStep::ParentDead);
    // 当前 child + 父活 → 继续。
    assert_eq!(watch_parent_step(true, true), WatchStep::Continue);
}

// ===== ChildSlot 退出协调（收割线程 mark_exited 唤醒 terminate 的 wait_exited）=====

#[test]
fn child_slot_wait_returns_true_when_marked() {
    let slot = ChildSlot::new(4242);
    let s2 = Arc::clone(&slot);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(20));
        s2.mark_exited();
    });
    // 收割线程 20ms 后 mark → wait（宽限 2s）应在期限内返 true。
    assert!(
        slot.wait_exited(Duration::from_secs(2)),
        "mark_exited 后 wait 应返 true（→ terminate 不 KILL）"
    );
}

#[test]
fn child_slot_wait_times_out_when_never_marked() {
    let slot = ChildSlot::new(1);
    // 从不 mark → 短宽限内超时返 false（→ terminate 升级 KILL）。
    assert!(!slot.wait_exited(Duration::from_millis(30)));
}

// ===== ReapGroup（对应 Go reapWG / waitReaps）=====

#[test]
fn reap_group_wait_returns_after_all_done() {
    let rg = ReapGroup::new();
    rg.add();
    rg.add();
    let r2 = Arc::clone(&rg);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(10));
        r2.done();
        r2.done();
    });
    // 两个在途 → done 归零后 wait 立即返回（不吃满 timeout）。
    let t0 = std::time::Instant::now();
    rg.wait(Duration::from_secs(5));
    assert!(t0.elapsed() < Duration::from_secs(4), "归零后应尽快返回");
}

#[test]
fn reap_group_wait_returns_immediately_when_empty() {
    let rg = ReapGroup::new();
    let t0 = std::time::Instant::now();
    rg.wait(Duration::from_secs(5)); // 计数已 0 → 立即返回。
    assert!(t0.elapsed() < Duration::from_secs(1));
}

#[test]
fn forward_fn_points_to_set_forward_prod() {
    // 验证闭包指针 = set_forward_prod（不 panic 即接线正确）。
    let f = forward_fn();
    f(false); // best-effort 写 /proc（非 root 静默失败）
}

/// 静态断言：ServerError 实现了 std::error::Error + Display。
#[test]
fn server_error_implements_error() {
    fn takes_error<E: std::error::Error>(_e: &E) {}
    let e = ServerError::Mkdir {
        dir: PathBuf::from("/x"),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "test"),
    };
    takes_error(&e);
    assert!(e.to_string().contains("/x"));
}

// ===== pid 复用误杀（复审 Medium，server.rs cleanup 腿）=====

/// 起一个本机短命子进程当「pid 的当前占有者」。不碰网络、不碰宿主状态。
fn spawn_sleeper() -> std::process::Child {
    std::process::Command::new("sleep")
        .arg("30")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("本机应能起 sleep（测试前置）")
}

/// 轮询等子进程退出；返回是否在预算内退出。
fn exited_within(child: &mut std::process::Child, budget: Duration) -> bool {
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        if child.try_wait().expect("try_wait").is_some() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

#[test]
fn child_slot_signal_if_live_delivers_only_before_reap() {
    // 正向：未收割 → 投递，且拿到的是本 slot 的 pid。
    let slot = ChildSlot::new(4242);
    let mut got = None;
    assert!(slot.signal_if_live(|pid| got = Some(pid)), "未收割应投递");
    assert_eq!(got, Some(4242));

    // 反向：已收割（wait 已返回 ⇒ pid 随时可能被系统复用）→ 一律不投递。
    let reaped = ChildSlot::new(4242);
    reaped.mark_exited();
    let mut delivered = false;
    assert!(
        !reaped.signal_if_live(|_| delivered = true),
        "已收割应返回未投递"
    );
    assert!(!delivered, "已收割的 pid 不得再收到任何信号");
}

/// cleanup 腿（`handle_cleanup` → `CoreSpawner::kill`）对已收割 pid 直发 SIGKILL = 误杀。
///
/// 用真进程做观察面：把一个**活着的**无关进程的 pid 装进一个已标记收割的 slot（正是 pid 复用后
/// 的现场形态），kill 必须打不到它；同一路径下未收割的 child 必须照杀（正向对照，防「kill 整个失效」
/// 也能让上半场变绿）。
#[test]
fn kill_skips_reaped_slot_but_still_kills_live_child() {
    let state = Arc::new(Mutex::new(HandlerState::new()));
    let spawner = AmbientCapsSpawner::new(state);

    // ① 反向：slot 已收割 → 不得投递（受害者进程必须活着）。
    let mut victim = spawn_sleeper();
    let victim_pid = victim.id();
    let victim_slot = ChildSlot::new(victim_pid);
    victim_slot.mark_exited();
    spawner.slots.lock().unwrap().push(victim_slot);
    spawner.kill(&CoreHandle { pid: victim_pid });
    assert!(
        !exited_within(&mut victim, Duration::from_millis(300)),
        "已收割 slot 的 pid 收到了 SIGKILL —— 正是 pid 复用误杀"
    );
    let _ = victim.kill();
    let _ = victim.wait();

    // ② 正向对照：同一条 kill 路径，未收割的 slot 必须真杀掉。
    let mut live = spawn_sleeper();
    let live_pid = live.id();
    spawner.slots.lock().unwrap().push(ChildSlot::new(live_pid));
    spawner.kill(&CoreHandle { pid: live_pid });
    assert!(
        exited_within(&mut live, Duration::from_secs(3)),
        "未收割的 child 必须被 SIGKILL（否则上一条的绿无信息量）"
    );
}

/// terminate 的两条信号腿（TERM / 升级 KILL）同受身份判据约束 —— 注释宣称的
/// 「pid-复用安全」此前只有「slot 还在册」这一半。
#[test]
fn terminate_slot_sends_nothing_to_a_reaped_slot() {
    let mut sleeper = spawn_sleeper();
    let pid = sleeper.id();
    let slot = ChildSlot::new(pid);
    slot.mark_exited();
    let t0 = std::time::Instant::now();
    terminate_slot(&slot);
    // 已收割 → 不发 TERM；wait_exited 立即返 true → 不升级 KILL；整体近乎立即返回（不吃满 5s 宽限）。
    assert!(t0.elapsed() < Duration::from_secs(1), "已收割不应等宽限期");
    assert!(
        !exited_within(&mut sleeper, Duration::from_millis(300)),
        "已收割 slot 的 pid 收到了 TERM/KILL"
    );
    let _ = sleeper.kill();
    let _ = sleeper.wait();
}

// ===== 连接并发闸的接线（复审 Medium：spawn_blocking 在鉴权之前，且此前无上限）=====

/// `dispatch` 必须在起阻塞任务**之前**过闸：超限连接当场关掉，闸内连接照常被接手。
///
/// 端到端走真 `dispatch`（不是只测 `ConnLimiter` 本身 —— 那份单测在 `platform::conn_limit`）：
/// 用 `UnixStream::pair()` 造纯本机 socketpair（不 bind 文件、不碰网络），对端是否**立刻**读到 EOF
/// 就是「快速失败 vs 被接手」的可观测差别。
#[tokio::test]
async fn dispatch_refuses_connections_beyond_the_concurrency_cap() {
    use tokio::io::AsyncReadExt;

    let dir = tempfile::tempdir().unwrap();
    let cfg = ServerConfig {
        sock_path: dir.path().join("helper.sock"),
        auth_file: dir.path().join("authorized-uids"),
        core_dir: None,
        console: true,
    };
    let server = ConnServer::new(&cfg);

    // 占满闸门：对端保持存活且不发数据 ⇒ 阻塞任务被按在读上，许可不归还。
    let mut peers = Vec::new();
    for _ in 0..MAX_CONCURRENT_CONNECTIONS {
        let (client, srv) = tokio::net::UnixStream::pair().unwrap();
        server.dispatch(srv);
        peers.push(client);
    }

    let mut probe = [0u8; 1];
    // 正向对照：闸内的连接**没有**被关掉。缺了这条，下面的 EOF 断言对「dispatch 一律关连接」
    // 的实现同样成立 —— 那就成了无信息量的绿。
    assert!(
        tokio::time::timeout(Duration::from_millis(200), peers[0].read(&mut probe))
            .await
            .is_err(),
        "闸内连接被立刻关闭 ⇒ 判据不具区分力"
    );

    // 超限连接：`dispatch` 当场 drop stream ⇒ 对端立刻读到 EOF，而不是排队、也不是等满 5s 读超时。
    let (mut extra, srv) = tokio::net::UnixStream::pair().unwrap();
    server.dispatch(srv);
    let n = tokio::time::timeout(Duration::from_millis(200), extra.read(&mut probe))
        .await
        .expect("超限连接必须快速失败（不排队、不等 5s 读超时）")
        .expect("读超限连接");
    assert_eq!(n, 0, "超限连接的对端应立刻读到 EOF");

    drop(peers);
}

/// 许可随阻塞任务结束归还 —— 否则闸门用满一次就永久关死，比没有闸更糟。
#[tokio::test]
async fn dispatch_permits_are_returned_when_the_connection_finishes() {
    use tokio::io::AsyncReadExt;

    let dir = tempfile::tempdir().unwrap();
    let cfg = ServerConfig {
        sock_path: dir.path().join("helper.sock"),
        auth_file: dir.path().join("authorized-uids"),
        core_dir: None,
        console: true,
    };
    let server = ConnServer::new(&cfg);

    // 占满闸门，但对端立刻半关闭写端 ⇒ handle 读到 EOF 即返回，许可归还。
    for _ in 0..MAX_CONCURRENT_CONNECTIONS {
        let (client, srv) = tokio::net::UnixStream::pair().unwrap();
        server.dispatch(srv);
        drop(client);
    }

    // 归还是异步的（阻塞任务在另一线程收尾），故有界轮询而不是定睡一觉。
    let mut probe = [0u8; 1];
    for attempt in 0..100 {
        let (mut client, srv) = tokio::net::UnixStream::pair().unwrap();
        server.dispatch(srv);
        let refused = tokio::time::timeout(Duration::from_millis(50), client.read(&mut probe))
            .await
            .is_ok_and(|r| matches!(r, Ok(0)));
        if !refused {
            drop(client); // 别把这条连接留到 runtime 收尾时才断（阻塞任务要等满读超时）。
            return; // 已收到许可 ⇒ 闸门没有被关死。
        }
        assert!(attempt < 99, "许可始终未归还：闸门被一次用满就永久关死");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
