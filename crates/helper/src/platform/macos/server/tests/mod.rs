use super::*;
use crate::platform::macos::handler::{ChildHandle, MacServices, SpawnError};
use crate::token::TokenStore;
use std::io::Cursor;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// 测试用 services（复用 handler 测试的简化版）。
struct TestServices {
    token: Mutex<String>,
    child: Mutex<Option<ChildHandle>>,
    uid: i64,
    runner_calls: AtomicUsize,
}

impl TestServices {
    fn new(token: &str) -> Self {
        Self {
            token: Mutex::new(token.into()),
            child: Mutex::new(None),
            uid: 0,
            runner_calls: AtomicUsize::new(0),
        }
    }

    fn runner_calls(&self) -> usize {
        self.runner_calls.load(Ordering::Relaxed)
    }
}

impl TokenStore for TestServices {
    fn token_value(&self) -> String {
        self.token.lock().unwrap().clone()
    }
}

impl crate::platform::macos::exec::CommandRunner for TestServices {
    fn run(
        &self,
        _t: Duration,
        _p: &str,
        _a: &[&str],
    ) -> Result<(), crate::platform::macos::exec::RunError> {
        self.runner_calls.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    fn output(
        &self,
        _t: Duration,
        _p: &str,
        _a: &[&str],
    ) -> Result<Vec<u8>, crate::platform::macos::exec::RunError> {
        self.runner_calls.fetch_add(1, Ordering::Relaxed);
        Ok(Vec::new())
    }
    fn combined(
        &self,
        _t: Duration,
        _p: &str,
        _a: &[&str],
    ) -> Result<Vec<u8>, crate::platform::macos::exec::RunError> {
        self.runner_calls.fetch_add(1, Ordering::Relaxed);
        Ok(Vec::new())
    }
}

impl MacServices for TestServices {
    fn token_store(&self) -> &dyn TokenStore {
        self
    }
    fn runner(&self) -> &dyn crate::platform::macos::exec::CommandRunner {
        self
    }
    fn child(&self) -> &Mutex<Option<ChildHandle>> {
        &self.child
    }
    fn uid(&self) -> i64 {
        self.uid
    }
    fn spawn_child(
        &self,
        _cfg: &str,
        _log: &str,
        _fwd: bool,
        _parent_pid: Option<u32>,
    ) -> Result<SpawnedCore, SpawnError> {
        let pid = 4242u32;
        *self.child.lock().unwrap() = Some(ChildHandle { pid });
        Ok(SpawnedCore {
            pid,
            process_ms: 0,
            log_handoff_ms: 0,
        })
    }
}

fn test_config() -> MacConfig {
    MacConfig::new("/sb", "/Users/test/Polaris", "/tmp/support", "/tmp/core")
}

// ===== decode_request（对照 Go handle() readLine 序列）=====

#[test]
fn decode_ping() {
    let mut lines = std::iter::empty::<String>();
    assert_eq!(decode_request("ping", &mut lines), Ok(Request::Ping));
}

/// stop 的受管 pid 身份行：有则解出，无（旧客户端）则 `None`（旧语义）。
///
/// 变异：把 `"stop"` 分支退回 `Ok(Request::Stop { pid: None })`（不读那一行）→ 首条转红，
/// 身份判据从此永远拿不到 want = 形同虚设。
#[test]
fn decode_stop_reads_optional_identity_line() {
    let mut lines = vec!["4242".to_owned()].into_iter();
    assert_eq!(
        decode_request("stop", &mut lines),
        Ok(Request::Stop { pid: Some(4242) })
    );
    let mut none = std::iter::empty::<String>();
    assert_eq!(
        decode_request("stop", &mut none),
        Ok(Request::Stop { pid: None }),
        "旧客户端不发身份行 → None → 沿用「停当前受管核」"
    );
}

#[test]
fn decode_freeport() {
    let mut lines = vec!["9090".to_owned()].into_iter();
    assert_eq!(
        decode_request("freeport", &mut lines),
        Ok(Request::FreePort { port: 9090 })
    );
}

#[test]
fn decode_start_full() {
    let mut lines = vec![
        "/tmp/c.json".to_owned(),
        "/tmp/l.log".to_owned(),
        "1".to_owned(),
        "1234".to_owned(),
    ]
    .into_iter();
    let r = decode_request("start", &mut lines).unwrap();
    match r {
        Request::Start(p) => {
            assert_eq!(p.cfg, "/tmp/c.json");
            assert_eq!(p.log, "/tmp/l.log");
            assert!(p.fwd);
            assert_eq!(p.parent_pid, Some(1234));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn decode_start_without_ppid() {
    // helper.go:513: ppid 可选（EOF → 0 → None）
    let mut lines = vec!["/tmp/c.json".to_owned(), "".to_owned(), "0".to_owned()].into_iter();
    let r = decode_request("start", &mut lines).unwrap();
    match r {
        Request::Start(p) => {
            assert_eq!(p.parent_pid, None);
            assert!(!p.fwd);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn decode_route_add() {
    let mut lines = vec![
        "polaris-ts".to_owned(),
        "10.0.0.0/8,172.16.0.0/12".to_owned(),
    ]
    .into_iter();
    let r = decode_request("route-add", &mut lines).unwrap();
    match r {
        Request::RouteAdd(rp) => {
            assert_eq!(rp.iface, "polaris-ts");
            assert_eq!(rp.cidrs, vec!["10.0.0.0/8", "172.16.0.0/12"]);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn decode_route_del() {
    let mut lines = vec!["utun3".to_owned(), "::/0".to_owned()].into_iter();
    let r = decode_request("route-del", &mut lines).unwrap();
    assert!(matches!(r, Request::RouteDel(_)));
}

#[test]
fn decode_install_core() {
    let mut lines = vec!["/tmp/staging".to_owned(), "abcd".repeat(16)].into_iter();
    let r = decode_request("install-core", &mut lines).unwrap();
    match r {
        Request::InstallCore(p) => {
            assert_eq!(p.src_dir, "/tmp/staging");
            assert_eq!(p.want_hash.len(), 64);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn decode_default_restore() {
    let mut lines = vec!["192.168.1.1".to_owned()].into_iter();
    let r = decode_request("default-restore", &mut lines).unwrap();
    match r {
        Request::DefaultRestore { gateway_ipv4 } => {
            assert_eq!(gateway_ipv4, "192.168.1.1");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn decode_flush_dns() {
    let mut lines = std::iter::empty::<String>();
    assert_eq!(
        decode_request("flush-dns", &mut lines),
        Ok(Request::FlushDns)
    );
}

#[test]
fn decode_system_proxy_transaction_requires_one_payload_line() {
    let mut lines = vec!["7b7d".to_owned()].into_iter();
    assert_eq!(
        decode_request("system-proxy-transaction", &mut lines),
        Ok(Request::MacProxyTransaction {
            payload_hex: "7b7d".into()
        })
    );
    let mut missing = std::iter::empty::<String>();
    assert_eq!(
        decode_request("system-proxy-transaction", &mut missing),
        Err(DecodeError::MissingArg("payload_hex"))
    );
}

#[test]
fn decode_system_proxy_compare_capability_has_no_payload() {
    let mut lines = std::iter::empty::<String>();
    assert_eq!(
        decode_request("system-proxy-compare-capability", &mut lines),
        Ok(Request::MacProxyCompareCapability)
    );
}

#[test]
fn decode_system_proxy_compare_transaction_validates_payload_shape_and_limit() {
    let mut success = vec!["7b7d".to_owned()].into_iter();
    assert_eq!(
        decode_request("system-proxy-compare-transaction", &mut success),
        Ok(Request::MacProxyCompareTransaction {
            payload_hex: "7b7d".into()
        })
    );

    for mut invalid in [Vec::<String>::new(), vec![String::new()]]
        .into_iter()
        .map(Vec::into_iter)
    {
        assert_eq!(
            decode_request("system-proxy-compare-transaction", &mut invalid),
            Err(DecodeError::MissingArg("payload_hex"))
        );
    }

    let mut oversized = vec!["a".repeat(MAX_WIRE_LINE_BYTES + 1)].into_iter();
    assert_eq!(
        decode_request("system-proxy-compare-transaction", &mut oversized),
        Err(DecodeError::LineTooLong)
    );
}

#[test]
fn decode_unknown_command() {
    let mut lines = std::iter::empty::<String>();
    assert_eq!(
        decode_request("bogus", &mut lines),
        Err(DecodeError::UnknownCommand("bogus".into()))
    );
}

// ===== process_connection 端到端（用 Cursor 模拟 wire 输入）=====

#[test]
fn process_conn_ping_success() {
    // 模拟客户端发：token\tping\n（实际是 token\nping\n）
    let svc = TestServices::new("TOK");
    let cfg = test_config();
    let input = Cursor::new(b"TOK\nping\n".to_vec());
    let mut output = Vec::new();
    let outcome = process_connection(input, &mut output, &svc, &cfg, None);
    assert!(matches!(outcome, ConnOutcome::Done));
    let resp = String::from_utf8(output).unwrap();
    assert_eq!(
        resp,
        format!(
            "OK pong uid=0 v{} build={}\n",
            crate::platform::macos::PROTO_VERSION,
            polaris_helper_proto::build_identity::current()
        )
    );
}

#[test]
fn process_conn_auth_fail() {
    // 错 token → ERR auth
    let svc = TestServices::new("real");
    let cfg = test_config();
    let input = Cursor::new(b"wrong\nping\n".to_vec());
    let mut output = Vec::new();
    process_connection(input, &mut output, &svc, &cfg, None);
    assert_eq!(String::from_utf8(output).unwrap(), "ERR auth\n");
}

/// **未鉴权连接不得取到 `command_mu`** —— 行为级判据，不是「代码里有没有那句」。
///
/// 做法：后台线程把锁**限时**攥住（800ms），主线程立刻喂一条错 token 的 `start`
/// （且参数行缺失，正是最坏形态）并测耗时。实现若在鉴权前取锁，主线程要等到后台放锁；
/// 实现正确则在取锁前就回 `ERR auth`。
///
/// 限时持锁而非「主线程持锁 + 子线程跑」：后者在变异下会让 `thread::scope` 的 join 与
/// 主线程的锁互等，表现为**挂死**而不是失败（实测撞过，CI 上只会看到超时）。
#[test]
fn unauthenticated_connection_never_takes_the_command_lock() {
    let svc = TestServices::new("real");
    let cfg = test_config();
    let mu = Mutex::new(());
    const HOLD: std::time::Duration = std::time::Duration::from_millis(800);

    std::thread::scope(|scope| {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let mu_ref = &mu;
        scope.spawn(move || {
            let g = mu_ref.lock().unwrap();
            ready_tx.send(()).unwrap();
            std::thread::sleep(HOLD);
            drop(g);
        });
        ready_rx.recv().expect("持锁线程没起来");

        let t0 = std::time::Instant::now();
        let input = Cursor::new(b"wrong-token\nstart\n".to_vec());
        let mut output = Vec::new();
        process_connection(input, &mut output, &svc, &cfg, Some(&mu));
        let elapsed = t0.elapsed();

        assert_eq!(String::from_utf8(output).unwrap(), "ERR auth\n");
        assert!(
            elapsed < HOLD / 2,
            "未鉴权连接等在 command_mu 上（耗时 {elapsed:?}）—— 鉴权跑到取锁之后了"
        );
    });
}

/// 正向对照：**已鉴权**的同一类命令确实会去取锁 —— 否则上面那条可能被「谁都不取锁」满足。
#[test]
fn authenticated_connection_does_take_the_command_lock() {
    let svc = TestServices::new("real");
    let cfg = test_config();
    let mu = Mutex::new(());
    const HOLD: std::time::Duration = std::time::Duration::from_millis(800);

    std::thread::scope(|scope| {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let mu_ref = &mu;
        scope.spawn(move || {
            let g = mu_ref.lock().unwrap();
            ready_tx.send(()).unwrap();
            std::thread::sleep(HOLD);
            drop(g);
        });
        ready_rx.recv().expect("持锁线程没起来");

        let t0 = std::time::Instant::now();
        let input = Cursor::new(b"real\nstatus\n".to_vec());
        let mut output = Vec::new();
        process_connection(input, &mut output, &svc, &cfg, Some(&mu));
        let elapsed = t0.elapsed();

        assert!(
            elapsed >= HOLD / 2,
            "已鉴权命令没去取 command_mu（耗时 {elapsed:?}）—— 锁形同虚设，上一条门也就没有信息量"
        );
    });
}

#[test]
fn process_conn_version() {
    let svc = TestServices::new("T");
    let cfg = test_config();
    let input = Cursor::new(b"T\nversion\n".to_vec());
    let mut output = Vec::new();
    process_connection(input, &mut output, &svc, &cfg, None);
    assert_eq!(
        String::from_utf8(output).unwrap(),
        format!("OK {}\n", crate::platform::macos::PROTO_VERSION)
    );
}

#[test]
fn process_conn_unknown_command() {
    let svc = TestServices::new("T");
    let cfg = test_config();
    let input = Cursor::new(b"T\nbogus\n".to_vec());
    let mut output = Vec::new();
    process_connection(input, &mut output, &svc, &cfg, None);
    assert_eq!(String::from_utf8(output).unwrap(), "ERR unknown\n");
}

#[test]
fn oversized_compare_payload_returns_stable_error_before_handler_or_runner() {
    let svc = TestServices::new("T");
    let cfg = test_config();
    let mut input = b"T\nsystem-proxy-compare-transaction\n".to_vec();
    input.extend(std::iter::repeat_n(b'a', MAX_WIRE_LINE_BYTES + 1));
    input.extend_from_slice(b"TAIL\n");
    let mut output = Vec::new();

    process_connection(Cursor::new(input), &mut output, &svc, &cfg, None);

    assert_eq!(
        String::from_utf8(output).unwrap(),
        "ERR bad-args line-too-long\n"
    );
    assert_eq!(svc.runner_calls(), 0);
}

#[test]
fn oversized_token_command_and_ordinary_argument_all_fail_before_dispatch() {
    let oversized = vec![b'x'; MAX_WIRE_LINE_BYTES + 1];
    let mut frames = Vec::new();
    frames.push([oversized.clone(), b"\nping\n".to_vec()].concat());
    frames.push([b"T\n".to_vec(), oversized.clone(), b"\n".to_vec()].concat());
    frames.push(
        [
            b"T\nstart\n".to_vec(),
            oversized,
            b"\n/tmp/log\n0\n".to_vec(),
        ]
        .concat(),
    );

    for frame in frames {
        let svc = TestServices::new("T");
        let mut output = Vec::new();
        process_connection(Cursor::new(frame), &mut output, &svc, &test_config(), None);
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "ERR bad-args line-too-long\n"
        );
        assert_eq!(svc.runner_calls(), 0);
        assert!(svc.child.lock().unwrap().is_none());
    }
}

#[test]
fn process_conn_start_full_flow() {
    let svc = TestServices::new("T");
    let cfg = test_config();
    let input = Cursor::new(b"T\nstart\n/Users/test/Polaris/c.json\n\n0\n".to_vec());
    let mut output = Vec::new();
    let outcome = process_connection(input, &mut output, &svc, &cfg, None);
    assert!(matches!(outcome, ConnOutcome::Done));
    // spawn_child mock 返回 4242；新版三平台 helper 追加可选分段计时。
    let line = String::from_utf8(output).unwrap();
    assert!(matches!(
        polaris_helper_proto::Response::parse(line.trim_end()),
        polaris_helper_proto::Response::Ok(polaris_helper_proto::ResponseKind::Start(
            polaris_helper_proto::Start::StartedTimed { pid: 4242, .. }
        ))
    ));
}

#[test]
fn process_conn_empty_input_no_panic() {
    // 无数据连接不应 panic
    let svc = TestServices::new("T");
    let cfg = test_config();
    let input = Cursor::new(Vec::new());
    let mut output = Vec::new();
    let outcome = process_connection(input, &mut output, &svc, &cfg, None);
    assert!(matches!(outcome, ConnOutcome::Done));
    assert!(output.is_empty());
}

#[test]
fn process_conn_partial_input_no_panic() {
    // 只有 token 行，无 command 行
    let svc = TestServices::new("T");
    let cfg = test_config();
    let input = Cursor::new(b"T\n".to_vec());
    let mut output = Vec::new();
    let outcome = process_connection(input, &mut output, &svc, &cfg, None);
    assert!(matches!(outcome, ConnOutcome::Done));
}

#[test]
fn sock_filename_matches_go() {
    // helper.go:604
    assert_eq!(SOCK_FILENAME, "helper.sock");
}

#[cfg(unix)]
#[test]
fn sock_mode_matches_go() {
    // helper.go:611: Chmod 0666
    assert_eq!(SOCK_MODE, 0o666);
}

// ===== 纯决策逻辑（mu 分流 / chown 筛选 / terminate 状态机）=====

#[test]
fn should_lock_all_but_freeport() {
    // helper.go:413: freeport 不持锁；helper.go:418: 其余持锁
    assert!(!should_lock_command("freeport"));
    for c in [
        "ping",
        "version",
        "status",
        "start",
        "stop",
        "cleanup",
        "route-add",
        "flush-dns",
        "system-proxy-transaction",
    ] {
        assert!(should_lock_command(c), "{c} 应持锁");
    }
}

#[test]
fn chown_subdirs_match_go() {
    // helper.go:222
    assert_eq!(CHOWN_SUBDIRS, ["tailscale", "singbox-dashboard", "ui"]);
    assert_eq!(CHOWN_FILES, ["cache.db"]);
}

#[cfg(target_os = "macos")]
#[test]
fn cache_prepare_preserves_bytes_and_uses_confdir_owner() {
    use std::os::unix::fs::MetadataExt;

    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join(CHOWN_FILES[0]);
    std::fs::write(&cache, b"keep-cache-bytes").unwrap();

    sys::prepare_cache_for_user(dir.path().to_str().unwrap()).unwrap();

    assert_eq!(std::fs::read(&cache).unwrap(), b"keep-cache-bytes");
    let dir_meta = std::fs::metadata(dir.path()).unwrap();
    let cache_meta = std::fs::metadata(&cache).unwrap();
    assert_eq!(cache_meta.uid(), dir_meta.uid());
    assert_eq!(cache_meta.gid(), dir_meta.gid());
}

#[cfg(target_os = "macos")]
#[test]
fn cache_prepare_refuses_symlink_without_touching_target() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    std::fs::write(&target, b"untouched").unwrap();
    std::os::unix::fs::symlink(&target, dir.path().join(CHOWN_FILES[0])).unwrap();

    let error = sys::prepare_cache_for_user(dir.path().to_str().unwrap()).unwrap_err();

    assert!(error.contains("安全打开 cache.db 失败"), "{error}");
    assert_eq!(std::fs::read(target).unwrap(), b"untouched");
}

#[test]
fn should_chown_only_root_owned_entries() {
    // helper.go:237: st.Uid==0 → Lchown；非 root 跳过
    assert!(should_chown_entry(0));
    assert!(!should_chown_entry(501));
    assert!(!should_chown_entry(1000));
}

#[test]
fn should_skip_confdir_chown_when_root() {
    // helper.go:219-221: confDir 属 root（异常）→ 跳过整个 chown
    assert!(should_skip_confdir_chown(0));
    assert!(!should_skip_confdir_chown(501));
}

#[test]
fn terminate_kills_only_when_not_exited() {
    // helper.go:282-286: done 触发（已退出）→ 免 KILL；超时（未退出）→ SIGKILL
    assert!(terminate_needs_kill(false));
    assert!(!terminate_needs_kill(true));
}

// ===== 连接并发闸 =====
//
// 闸本体的单测（上限/归还/panic 展开）随类型上提 `platform::conn_limit`（两条 unix 腿共用一份）。
// 这里只留 mac 侧的**接线**门。

/// accept 循环的接线：闸必须在 `thread::spawn` **之前**，accept 错误必须过分类。
///
/// `serve` 在 `cfg(target_os = "macos")` 门内，Linux 上不编译 ⇒ 本机唯一能守住接线的就是源码级门
/// （行为面属 macOS 真机项）。`crate_source!` 读磁盘文本，不受 cfg 影响。
#[test]
fn accept_loop_takes_a_permit_before_spawning_and_backs_off_on_errors() {
    let src = polaris_source_probe::crate_source!("platform/macos/server.rs");
    // 取材自检①：拿到的确实是本文件。
    assert!(
        src.contains("pub fn serve(services: Arc<DaemonServices>)"),
        "取材面错位：拿到的不是 macos/server.rs"
    );
    // 取材自检②：切点唯一。
    assert_eq!(src.matches("pub fn serve(").count(), 1);
    let at = src.find("pub fn serve(").expect("serve 消失，门失去判据");
    let end = src[at..]
        .find("\n#[cfg(target_os = \"macos\")]\npub use sys::")
        .map_or(src.len(), |i| at + i);
    let body = &src[at..end];
    // 判据自检：窗口确实盖住 accept 循环。
    assert!(
        body.contains("listener.incoming()"),
        "窗口没盖住 accept 循环"
    );

    // ① 闸门接线：上限来自常量（不是就地魔数），且许可在起线程之前拿到。
    assert!(
        body.contains("ConnLimiter::new(MAX_CONCURRENT_CONNECTIONS)"),
        "accept 循环没有按常量建闸"
    );
    let acquire = body
        .find("limiter.try_acquire()")
        .expect("accept 循环没取许可 —— 每连接一线程重新无上限");
    let spawn = body
        .find("std::thread::spawn")
        .expect("每连接一线程的 spawn 消失");
    assert!(
        acquire < spawn,
        "许可必须在 thread::spawn **之前**拿到：线程一起就已经被对端按住 5s，事后限流没有意义"
    );
    // 许可要被移进线程（drop 才归还）——留在循环里当场 drop 等于闸门恒开。
    assert!(
        body.contains("let _permit = permit;"),
        "许可没被移进连接线程 ⇒ 立即归还，闸门恒开"
    );

    // ② accept 错误腿：分类 + 退避，且不再有裸 continue。
    for required in [
        "classify_accept_error(&e)",
        "AcceptAction::Backoff",
        "std::thread::sleep(ACCEPT_BACKOFF)",
        "accept_log.allow()",
    ] {
        assert!(body.contains(required), "accept 错误腿缺锚点: {required}");
    }
    assert!(
        !body.contains("Err(_) => continue"),
        "accept 错误仍有一条不分类的裸 continue"
    );
}
