use super::*;

fn record(seq: u64, level: &'static str, target: &str, message: &str) -> LogRecord {
    LogRecord {
        seq,
        ts_ms: u128::from(seq),
        level,
        target: target.to_string(),
        message: message.to_string(),
    }
}

#[test]
fn search_scans_full_retained_ring_not_only_result_limit() {
    let mut records = VecDeque::new();
    records.push_back(record(0, "info", "sing-box", "youtube target"));
    for seq in 1..1_000 {
        records.push_back(record(seq, "info", "app", "ordinary line"));
    }

    let found = collect_search(&records, "youtube", "debug", "all", 500).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].seq, 0, "结果上限不能反向缩小查询域");
}

#[test]
fn search_applies_level_source_and_keeps_latest_results_in_time_order() {
    let records = VecDeque::from([
        record(1, "debug", "sing-box", "needle debug"),
        record(2, "warn", "app", "needle app"),
        record(3, "error", "sing-box", "needle old"),
        record(4, "fatal", "sing-box", "needle newest"),
    ]);

    let found = collect_search(&records, "needle", "warn", "sing-box", 2).unwrap();
    assert_eq!(
        found.iter().map(|entry| entry.seq).collect::<Vec<_>>(),
        [3, 4]
    );
    assert!(collect_search(&records, "", "invalid", "all", 10).is_err());
    assert!(collect_search(&records, "", "debug", "kernel", 10).is_err());
}

#[test]
fn ui_log_message_keeps_small_allocation_unchanged() {
    let message = String::from("normal log line");
    let pointer = message.as_ptr();
    let bounded = truncate_ui_message(message);
    assert_eq!(bounded, "normal log line");
    assert_eq!(bounded.as_ptr(), pointer, "未超限时不应重新分配");
}

#[test]
fn ui_log_message_has_real_ascii_byte_budget() {
    let bounded = truncate_ui_message("x".repeat(UI_LOG_MESSAGE_MAX_BYTES * 4));
    assert_eq!(bounded.len(), UI_LOG_MESSAGE_MAX_BYTES);
    assert!(bounded.ends_with(TRUNCATION_MARK));
    assert!(bounded.capacity() <= UI_LOG_MESSAGE_MAX_BYTES);
}

#[test]
fn ui_log_message_truncation_preserves_utf8() {
    let bounded = truncate_ui_message("网".repeat(UI_LOG_MESSAGE_MAX_BYTES));
    assert!(bounded.is_char_boundary(bounded.len()));
    assert!(bounded.len() <= UI_LOG_MESSAGE_MAX_BYTES);
    assert!(bounded.ends_with(TRUNCATION_MARK));
}

#[test]
fn open_log_file_creates_dir_and_file() {
    let dir = std::env::temp_dir().join(format!(
        "polaris-log-test-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let path = dir.join("nested").join("polaris.log");
    assert!(open_log_file(&path).is_some());
    assert!(path.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// 落盘失败不得 panic —— 日志是排障工具，绝不能自己变成故障源。
/// 夹具：父路径是**普通文件**而非目录 → `create_dir_all` 在三平台都必失败。
/// panic-safety 是平台无关逻辑，故不 cfg 门任何平台。
#[test]
fn open_log_file_on_unwritable_path_is_none_not_panic() {
    let dir = std::env::temp_dir().join(format!(
        "polaris-log-unwritable-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&dir).expect("建临时目录");
    let blocker = dir.join("not-a-dir");
    std::fs::write(&blocker, b"x").unwrap();
    let log_path = blocker.join("logs").join("polaris.log"); // 父是文件 → create_dir_all 必失败
    assert!(open_log_file(&log_path).is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn level_defaults_to_info() {
    // 未设 POLARIS_LOG 且无 config.json（测试进程默认）时为 Info。
    if std::env::var("POLARIS_LOG").is_err() {
        assert_eq!(
            startup_level(Path::new("/proc/polaris-nope")),
            LevelFilter::Info
        );
    }
}

/// 级别字面量解析：覆盖两个来源的全部词汇；fatal 归 Error；未知 → None（不静默当 Info）。
#[test]
fn parse_level_maps_all_frontend_levels() {
    assert_eq!(parse_level("debug"), Some(LevelFilter::Debug));
    assert_eq!(parse_level("info"), Some(LevelFilter::Info));
    assert_eq!(parse_level("warn"), Some(LevelFilter::Warn));
    assert_eq!(parse_level("error"), Some(LevelFilter::Error));
    assert_eq!(
        parse_level("fatal"),
        Some(LevelFilter::Error),
        "fatal 无对应档 → 归 Error"
    );
    assert_eq!(parse_level("trace"), Some(LevelFilter::Trace));
    assert_eq!(parse_level("off"), Some(LevelFilter::Off));
    assert_eq!(parse_level("bogus"), None, "未知值必须 None，由调用方回退");
}

/// config.logLevel 在启动时被读到（否则用户存的 debug 要等到手动再点一次才生效）。
#[test]
fn startup_level_reads_config_log_level() {
    let dir = std::env::temp_dir().join(format!(
        "polaris-loglevel-test-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("config.json"), r#"{"logLevel":"debug"}"#).unwrap();
    assert_eq!(level_from_config_file(&dir), Some(LevelFilter::Debug));
    // 损坏的 config 不得让日志系统炸/卡住 → None 回退。
    std::fs::write(dir.join("config.json"), "{not json").unwrap();
    assert_eq!(level_from_config_file(&dir), None);
    // 无 logLevel 字段 → None（回退默认，非报错）。
    std::fs::write(dir.join("config.json"), r#"{"other":1}"#).unwrap();
    assert_eq!(level_from_config_file(&dir), None);
    let _ = std::fs::remove_dir_all(&dir);
}

/// UI 来源归一：sing-box 保留，其余（含裸调用的 Rust 模块路径）一律 app。
/// 打断归一（直接返回 target）→ 本测转红，即「应用」筛选恒空的那个 bug。
#[test]
fn ui_source_normalizes_module_paths_to_app() {
    assert_eq!(ui_source("sing-box"), "sing-box");
    // 🔴 测速临时核的行同样是**核**的输出：日志页按来源筛「内核」时必须看得到它。
    // 不登记就落进默认的 `app`，用户按「内核」筛恰好漏掉唯一要看的那一段。
    // （落盘分流另有判据：`record.target() == SING_BOX_TARGET` ⇒ 它进 polaris.log，
    //  与 Rust 侧的编排行同一条时间线，见 `SPEEDTEST_CORE_TARGET` 的文档。）
    assert_eq!(ui_source(SPEEDTEST_CORE_TARGET), SING_BOX_TARGET);
    assert_eq!(ui_source("polaris::runtime::proxy"), "app");
    assert_eq!(ui_source("polaris"), "app");
    assert_eq!(ui_source("app"), "app");
    assert_eq!(ui_source(""), "app");
}

fn rec(seq: u64) -> LogRecord {
    LogRecord {
        seq,
        ts_ms: u128::from(seq),
        level: "info",
        target: "t".into(),
        message: format!("m{seq}"),
    }
}

/// 有界追加：超容量丢最旧、保最新（环形不变式）。打断 pop_front → 本测转红。
#[test]
fn bounded_push_evicts_oldest_over_cap() {
    let mut r = VecDeque::new();
    for i in 0..5 {
        bounded_push(&mut r, 3, rec(i));
    }
    let seqs: Vec<u64> = r.iter().map(|e| e.seq).collect();
    assert_eq!(seqs, vec![2, 3, 4], "只保留最新 cap 条");
}

/// 快照 limit：只取最新 N；None/超量 → 全部。
#[test]
fn snapshot_takes_latest_n() {
    let mut r = VecDeque::new();
    for i in 0..5 {
        bounded_push(&mut r, 100, rec(i));
    }
    let last2: Vec<u64> = collect_snapshot(&r, Some(2))
        .iter()
        .map(|e| e.seq)
        .collect();
    assert_eq!(last2, vec![3, 4]);
    assert_eq!(collect_snapshot(&r, None).len(), 5);
    assert_eq!(collect_snapshot(&r, Some(99)).len(), 5, "limit 超量 → 全部");
}

// ── BUG-P2-5：POLARIS_LOG 环境超驰不得被运行期 set_level 击穿 ──

/// env 超驰判定：可识别的 `POLARIS_LOG` → 超驰生效；未设 / 无法识别 → 无超驰（不冻住配置侧控制）。
#[test]
fn env_override_level_only_on_recognized_value() {
    assert_eq!(env_override_level(Some("debug")), Some(LevelFilter::Debug));
    assert_eq!(env_override_level(Some("off")), Some(LevelFilter::Off));
    assert_eq!(env_override_level(None), None, "未设 → 无超驰");
    assert_eq!(
        env_override_level(Some("bogus")),
        None,
        "无法识别的 env 值不得冻住配置侧的级别控制"
    );
}

/// 全局级别态（`log::max_level` + `ENV_LEVEL_OVERRIDE`）是进程级单例 → 触碰它的测试必须串行，
/// 否则并行跑时互相打架。
static LEVEL_TEST_LOCK: Mutex<()> = Mutex::new(());

/// 启动时采纳 `POLARIS_LOG` → **必须武装超驰 flag**，否则 [`set_level`] 的让位形同虚设
/// （env 优先级只在启动那一刻成立，第一次配置写就被顶回去）。
///
/// 这条锁的是「两半接线」：`set_level` 的让位闸门（另一条测试）+ 本处的武装，缺任一半 bug 就整个回来。
#[test]
fn resolve_startup_level_arms_override_flag_on_env() {
    let _g = LEVEL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let saved = ENV_LEVEL_OVERRIDE.load(Ordering::Relaxed);

    // 无 env → 不武装（config/默认路径不得冻住配置侧的级别控制）。
    ENV_LEVEL_OVERRIDE.store(false, Ordering::Relaxed);
    assert_eq!(
        resolve_startup_level(None, Path::new("/proc/polaris-nope")),
        LevelFilter::Info
    );
    assert!(
        !ENV_LEVEL_OVERRIDE.load(Ordering::Relaxed),
        "无 env → 不得武装超驰"
    );

    // 无法识别的 env → 同样不武装。
    assert_eq!(
        resolve_startup_level(Some("bogus"), Path::new("/proc/polaris-nope")),
        LevelFilter::Info
    );
    assert!(
        !ENV_LEVEL_OVERRIDE.load(Ordering::Relaxed),
        "无法识别的 env 值不得武装超驰（否则配置侧被永久冻住）"
    );

    // 可识别的 env → 采纳该级别 **且** 武装超驰。
    assert_eq!(
        resolve_startup_level(Some("debug"), Path::new("/proc/polaris-nope")),
        LevelFilter::Debug
    );
    assert!(
        ENV_LEVEL_OVERRIDE.load(Ordering::Relaxed),
        "采纳 POLARIS_LOG 后必须武装超驰，否则第一次配置写就把 debug 顶回 info"
    );

    ENV_LEVEL_OVERRIDE.store(saved, Ordering::Relaxed);
}

/// 生产路径直测：env 超驰生效时，`set_level`（挂在配置写的唯一汇流点上）必须 no-op。
///
/// 打断 `set_level` 的 `ENV_LEVEL_OVERRIDE` 早返 → 本测转红 —— 那正是
/// 「`POLARIS_LOG=debug` 起 app → 任意配置写把级别拉回 info → 排障会话静默降级」的 bug。
#[test]
fn set_level_is_noop_while_env_override_active() {
    let _g = LEVEL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let saved_flag = ENV_LEVEL_OVERRIDE.load(Ordering::Relaxed);
    let saved_level = log::max_level();

    // 模拟 POLARIS_LOG=debug 已在启动时被采纳。
    ENV_LEVEL_OVERRIDE.store(true, Ordering::Relaxed);
    log::set_max_level(LevelFilter::Debug);

    // 配置广播携带 logLevel=info（config 恒带该字段）→ 必须被忽略。
    set_level("info");
    assert_eq!(
        log::max_level(),
        LevelFilter::Debug,
        "env 超驰生效期间 config.logLevel 不得顶掉级别（否则排障抓的 debug 静默降级）"
    );

    ENV_LEVEL_OVERRIDE.store(saved_flag, Ordering::Relaxed);
    log::set_max_level(saved_level);
}

/// 无 env 超驰时 `set_level` 照常生效（让位只在超驰生效时发生，不得把配置侧控制一并废掉）。
#[test]
fn set_level_applies_without_env_override() {
    let _g = LEVEL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let saved_flag = ENV_LEVEL_OVERRIDE.load(Ordering::Relaxed);
    let saved_level = log::max_level();
    let saved_diagnostic = diagnostic_base().take();

    ENV_LEVEL_OVERRIDE.store(false, Ordering::Relaxed);
    log::set_max_level(LevelFilter::Info);

    set_level("warn");
    assert_eq!(
        log::max_level(),
        LevelFilter::Warn,
        "无 env 超驰 → 配置侧照常生效"
    );

    set_level("bogus");
    assert_eq!(
        log::max_level(),
        LevelFilter::Warn,
        "无法识别的值 → 级别不变"
    );

    ENV_LEVEL_OVERRIDE.store(saved_flag, Ordering::Relaxed);
    *diagnostic_base() = saved_diagnostic;
    log::set_max_level(saved_level);
}

/// 会话诊断只临时抬实际门槛；期间配置变更更新恢复基线，关闭后回到新配置，不会被一次全量保存打断。
#[test]
fn session_diagnostic_is_temporary_and_tracks_configured_baseline() {
    let _g = LEVEL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let saved_flag = ENV_LEVEL_OVERRIDE.load(Ordering::Relaxed);
    let saved_level = log::max_level();
    let saved_diagnostic = diagnostic_base().take();

    ENV_LEVEL_OVERRIDE.store(false, Ordering::Relaxed);
    log::set_max_level(LevelFilter::Info);

    assert!(set_session_diagnostic(true));
    assert!(session_diagnostic_enabled());
    assert_eq!(log::max_level(), LevelFilter::Debug);

    // 诊断开着时保存 warn：实时门槛仍是 debug，但退出诊断应恢复到刚保存的 warn。
    set_level("warn");
    assert_eq!(log::max_level(), LevelFilter::Debug);
    assert!(!set_session_diagnostic(false));
    assert_eq!(log::max_level(), LevelFilter::Warn);

    // 重复关闭幂等，不会继续改变级别。
    assert!(!set_session_diagnostic(false));
    assert_eq!(log::max_level(), LevelFilter::Warn);

    ENV_LEVEL_OVERRIDE.store(saved_flag, Ordering::Relaxed);
    *diagnostic_base() = saved_diagnostic;
    log::set_max_level(saved_level);
}

#[test]
fn session_diagnostic_never_downgrades_trace() {
    assert_eq!(diagnostic_level(LevelFilter::Trace), LevelFilter::Trace);
    assert_eq!(diagnostic_level(LevelFilter::Error), LevelFilter::Debug);
}

// ── BUG-P3-7：环内 seq 单调 + 水合/流式衔接不重不漏 ──

/// seq 在 ring 锁内分配 → 环内 seq 恒单调递增（`collect_from` 的「末条 seq+1」游标语义前提）。
///
/// 高并发下把发号与入环打散即可能乱序：本测起 8 线程 × 200 条抢同一把锁。**注意**：这是概率性
/// 捕获（乱序需真实交错），不是确定性判定——它对正确实现恒绿（无 flake 风险），对错误实现大概率转红。
#[test]
fn ring_seqs_stay_monotonic_under_concurrent_push() {
    let _g = LEVEL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear();
    let threads: Vec<_> = (0..8)
        .map(|t| {
            std::thread::spawn(move || {
                for i in 0..200 {
                    push_ring(0, Level::Info, "t", format!("{t}-{i}"));
                }
            })
        })
        .collect();
    for h in threads {
        h.join().unwrap();
    }
    let (recs, _) = snapshot_with_cursor(None);
    let seqs: Vec<u64> = recs.iter().map(|r| r.seq).collect();
    assert!(
        seqs.windows(2).all(|w| w[0] < w[1]),
        "环内 seq 必须单调递增（乱序 → collect_from 的游标会重放/跨过条目）"
    );
    clear();
}

/// 水合与流式首尾相接：`snapshot_with_cursor` 的游标之后拉增量 → 只得到快照之后写入的条目，
/// 快照里的一条都不重放。
///
/// 打断 `snapshot_with_cursor`（改成先取游标再取快照，或分两把锁取）→ 本测转红。
#[test]
fn snapshot_and_cursor_hand_off_without_replay_or_gap() {
    let _g = LEVEL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear();
    for i in 0..3 {
        push_ring(0, Level::Info, "t", format!("hydrate-{i}"));
    }
    let (snap, cursor) = snapshot_with_cursor(None);
    assert_eq!(snap.len(), 3, "水合拿到已写入的 3 条");
    assert!(
        snap.iter().all(|r| r.seq < cursor),
        "游标必须严格大于快照内全部 seq（否则已水合的条目会被流式重放）"
    );

    // 快照之后新写入的条目 → 流式恰好接上。
    for i in 0..2 {
        push_ring(0, Level::Info, "t", format!("stream-{i}"));
    }
    let (batch, next) = records_from(cursor);
    let msgs: Vec<&str> = batch.iter().map(|r| r.message.as_str()).collect();
    assert_eq!(
        msgs,
        vec!["stream-0", "stream-1"],
        "只推快照之后的增量，不重放水合过的"
    );
    assert!(records_from(next).0.is_empty(), "游标推进后无重放");
    clear();
}

/// 增量拉取：只取 seq>=from，游标推进到末尾+1；无新条目游标不动（防重放/漏推）。
#[test]
fn collect_from_streams_incrementally() {
    let mut r = VecDeque::new();
    for i in 10..15 {
        bounded_push(&mut r, 100, rec(i));
    }
    let (batch1, cur1) = collect_from(&r, 12);
    assert_eq!(
        batch1.iter().map(|e| e.seq).collect::<Vec<_>>(),
        vec![12, 13, 14]
    );
    assert_eq!(cur1, 15, "游标 = 末条 seq+1");
    let (batch2, cur2) = collect_from(&r, cur1);
    assert!(batch2.is_empty(), "无新增 → 空批");
    assert_eq!(cur2, cur1, "无新增 → 游标不动（不重放）");
}

// ── 大订阅测速灌洪：临时核的 info 不得把 UI 日志环冲干净 ──

/// 本节测试都要摆布进程级 `log::max_level()` 与共享的日志环 → 与既有全局级别测试共用
/// [`LEVEL_TEST_LOCK`] 串行，并在退出（含 panic 退出）时把级别与环原样还原。
struct RingLevelGuard {
    saved: LevelFilter,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl RingLevelGuard {
    fn new(level: LevelFilter) -> Self {
        let lock = LEVEL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let saved = log::max_level();
        clear();
        log::set_max_level(level);
        Self { saved, _lock: lock }
    }
}

impl Drop for RingLevelGuard {
    fn drop(&mut self) {
        clear();
        log::set_max_level(self.saved);
    }
}

/// 准入判据的真值表（本批新增的第三条判据本体）。
///
/// 把 [`SPEEDTEST_CORE_RING_FLOOR`] 调到 `Trace`（= 全放行）或去掉 `max >= Debug` 的逃生口，
/// 本测都转红 —— 它守的是分流逻辑本身。
#[test]
fn ring_admits_gates_the_speedtest_core_by_level_with_a_debug_escape_hatch() {
    let admits = |level, max| ring_admits(SPEEDTEST_CORE_TARGET, level, max);
    // 默认档（info）：Warn 及以上进环，Info 及以下不进。
    assert!(admits(Level::Error, LevelFilter::Info));
    assert!(admits(Level::Warn, LevelFilter::Info));
    assert!(!admits(Level::Info, LevelFilter::Info));
    assert!(!admits(Level::Debug, LevelFilter::Info));
    assert!(!admits(Level::Trace, LevelFilter::Info));
    // 比默认更安静的档不得反向放宽。
    assert!(!admits(Level::Info, LevelFilter::Warn));
    assert!(!admits(Level::Info, LevelFilter::Error));
    // 用户拨到 debug / trace = 明确表示「这次我要证据」→ 闸整个让开。
    assert!(admits(Level::Info, LevelFilter::Debug));
    assert!(admits(Level::Trace, LevelFilter::Debug));
    assert!(admits(Level::Trace, LevelFilter::Trace));
}

/// V1 —— 本批的核心承诺：一轮 1000 节点测速（约 3000 行临时核 info）灌进来之后，灌洪**之前**
/// 就在环里的条目一条不少。
///
/// 3000 > [`LOG_RING_CAP`]（2000）⇒ 没有准入闸时这批 info 足够把整个环冲干净一遍还有余，
/// 用户的应用日志、主核日志、以及他正要找的那条报错会全部消失。
#[test]
fn speedtest_core_info_flood_cannot_evict_the_existing_ui_log_ring() {
    let _guard = RingLevelGuard::new(LevelFilter::Info); // 默认档

    push_ring(0, Level::Info, "polaris::runtime::proxy", "应用日志".into());
    push_ring(0, Level::Info, SING_BOX_TARGET, "主核日志".into());
    push_ring(
        0,
        Level::Error,
        "polaris::runtime::proxy",
        "用户正在找的那条报错".into(),
    );

    // 每节点约 3 行：listener 起、inbound 接入、`outbound connection to …`。
    for node in 0..1_000 {
        for line in 0..3 {
            push_ring(
                0,
                Level::Info,
                SPEEDTEST_CORE_TARGET,
                format!("INFO outbound connection to node-{node} line-{line}"),
            );
        }
    }

    let (recs, _) = snapshot_with_cursor(None);
    let msgs: Vec<&str> = recs.iter().map(|r| r.message.as_str()).collect();
    assert_eq!(
        msgs,
        vec!["应用日志", "主核日志", "用户正在找的那条报错"],
        "3000 行临时核 info 既不得进环，也就不得把灌洪前的条目挤出去"
    );
}

/// V2 —— 默认档下临时核的 WARN / ERROR **必须**进环。
///
/// 起核期的 FATAL 行经 `runtime::proxy::core_log::singbox_line_level` 映射成 `Error`，是排障时
/// 最需要的那一行；任何裁剪方案都不能把它从 UI 里弄丢。顺带钉住 UI 来源判据没被本批动过：
/// 进环的临时核行仍归「内核」，用户按来源筛得到。
#[test]
fn speedtest_core_fatal_and_warn_still_reach_the_ring_on_the_default_level() {
    let _guard = RingLevelGuard::new(LevelFilter::Info);

    push_ring(
        0,
        Level::Error,
        SPEEDTEST_CORE_TARGET,
        "FATAL start service: configure tun interface".into(),
    );
    push_ring(
        0,
        Level::Warn,
        SPEEDTEST_CORE_TARGET,
        "WARN outbound not found".into(),
    );
    push_ring(
        0,
        Level::Info,
        SPEEDTEST_CORE_TARGET,
        "INFO inbound/mixed: started".into(),
    );
    push_ring(
        0,
        Level::Debug,
        SPEEDTEST_CORE_TARGET,
        "DEBUG dns: exchanged".into(),
    );

    let (recs, _) = snapshot_with_cursor(None);
    let msgs: Vec<&str> = recs.iter().map(|r| r.message.as_str()).collect();
    assert_eq!(
        msgs,
        vec![
            "FATAL start service: configure tun interface",
            "WARN outbound not found"
        ],
        "默认档：Warn 及以上进环，Info 及以下不进"
    );
    assert!(
        recs.iter().all(|r| r.target == SING_BOX_TARGET),
        "进环的临时核行来源仍归「内核」（本批不动 ui_source 那条判据）"
    );
}

/// V3 —— 诊断逃生口真的通：用户把 `config.logLevel` 拨到 `debug` 之后，临时核的 info / debug
/// 行照常进环。这条不通的话，「拨到 debug 取证」就是一句空话。
#[test]
fn speedtest_core_info_reaches_the_ring_once_the_user_asks_for_debug() {
    let _guard = RingLevelGuard::new(LevelFilter::Debug);

    push_ring(
        0,
        Level::Info,
        SPEEDTEST_CORE_TARGET,
        "INFO inbound/mixed: started".into(),
    );
    push_ring(
        0,
        Level::Debug,
        SPEEDTEST_CORE_TARGET,
        "DEBUG dns: exchanged".into(),
    );

    let (recs, _) = snapshot_with_cursor(None);
    let msgs: Vec<&str> = recs.iter().map(|r| r.message.as_str()).collect();
    assert_eq!(
        msgs,
        vec!["INFO inbound/mixed: started", "DEBUG dns: exchanged"],
        "诊断档下临时核全部行进环"
    );
}

/// 会话诊断模式走的是**同一个**逃生口（[`set_session_diagnostic`] 把 `log::max_level()` 抬到
/// 至少 Debug）—— 判据只有一份，不为「诊断按钮」另写一条并行分支。
#[test]
fn session_diagnostic_opens_the_same_ring_escape_hatch() {
    let _guard = RingLevelGuard::new(LevelFilter::Info);
    let saved_diagnostic = diagnostic_base().take();
    let admits_info = || ring_admits(SPEEDTEST_CORE_TARGET, Level::Info, log::max_level());

    assert!(!admits_info(), "默认档下临时核 info 不进环");
    set_session_diagnostic(true);
    assert!(
        admits_info(),
        "诊断模式抬到 Debug ⇒ 与拨 logLevel 同一个逃生口"
    );
    set_session_diagnostic(false);
    assert!(!admits_info(), "关掉诊断即恢复默认档的闸");

    *diagnostic_base() = saved_diagnostic;
}

/// V4a —— 空操作性（判据面）：本批只动测速核这一路。其余任何 target，在任何级别、任何全局级别
/// 上限下，准入判据恒为真 ⇒ 主核与应用日志一行都不因本批而改变去留。
#[test]
fn ring_admission_is_a_noop_for_every_target_other_than_the_speedtest_core() {
    for target in [
        SING_BOX_TARGET,
        "app",
        "polaris::runtime::proxy",
        "tailscale-login",
        "config-engine",
        "",
    ] {
        for level in [
            Level::Error,
            Level::Warn,
            Level::Info,
            Level::Debug,
            Level::Trace,
        ] {
            for max in [
                LevelFilter::Off,
                LevelFilter::Error,
                LevelFilter::Warn,
                LevelFilter::Info,
                LevelFilter::Debug,
                LevelFilter::Trace,
            ] {
                assert!(
                    ring_admits(target, level, max),
                    "target={target} level={level} max={max}：本批的闸不得碰测速核以外的任何一路"
                );
            }
        }
    }
}

/// V4b —— 空操作性（生产路径面）：主核在默认档灌 3000 行 info，环形语义照旧（丢最旧、保最新
/// [`LOG_RING_CAP`] 条），没有任何一行被本批的闸拒掉。
#[test]
fn main_core_info_still_fills_the_ring_with_ordinary_ring_semantics() {
    let _guard = RingLevelGuard::new(LevelFilter::Info);

    for i in 0..3_000 {
        push_ring(0, Level::Info, SING_BOX_TARGET, format!("core-{i}"));
    }

    let (recs, _) = snapshot_with_cursor(None);
    assert_eq!(recs.len(), LOG_RING_CAP, "主核照常填满整个环");
    assert_eq!(recs.first().unwrap().message, "core-1000");
    assert_eq!(recs.last().unwrap().message, "core-2999");
}
