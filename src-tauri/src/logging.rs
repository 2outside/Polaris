//! 最小日志 sink（stderr + 文件）。
//!
//! ## 为什么需要这个文件（发现的缺口，非本批原定范围）
//!
//! `Cargo.toml:17` 只声明了 `log = "0.4"` —— 那是**门面（facade）**，不是实现。全仓 `log::set_logger` /
//! `env_logger::init` / `tauri-plugin-log` **零命中**，即当前 30 处 `log::info!/warn!/error!` **全部是静默
//! no-op，输出去向为空**。这正是审计结论「白屏时无一行日志可排查」比预想更深的一层根因：不只是缺
//! renderer→主进程的转发，而是**主进程侧的日志本身就没有落点**。
//!
//! 故若不补 sink，「console 错误转发」这条不变式即便接线完成也仍然产出零日志 —— 等于宣称了一个 no-op
//! 能力。本模块用来把它变成真的。
//!
//! ## 为什么不用现成的
//!
//! 本批纪律：禁止引入任何新依赖。`env_logger` / `tauri-plugin-log` 都是新依赖，故走简约阶梯的
//! 「stdlib + 已装依赖」档：`log` crate 自带 `set_logger`，配 `std::fs` / `std::io` 手写 ~40 行
//! `log::Log` 实现即可。
//!
//! 注：刻意用 `set_logger(&'static dyn Log)` + `OnceLock` 而非更顺手的 `set_boxed_logger` —— 后者
//! 被 `log` 的 `std` feature 门控，而本仓 `Cargo.toml:17` 是裸 `log = "0.4"`（default-features 为空，
//! 不含 `std`）。走 `set_logger` 就无需改 Cargo.toml 的 feature 面，改动面更小、也不与并发批次抢文件。
//!
//! ## 边界
//!
//! - 文件时间戳是 Unix epoch 毫秒；UI 出境时转换为 RFC3339。
//! - 单文件 + 满则轮转一次（`.1`），无按日切分、无压缩。
//! - 正文先经统一凭据脱敏再落盘；内存环为日志页诊断副本，受条数与单条字节双重预算约束。

use std::collections::VecDeque;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use log::{Level, LevelFilter, Metadata, Record};
use polaris_log_budget::{OpenMode, RotatingFile, DEFAULT_GENERATION_BYTES};

/// sink 单例：`log::set_logger` 要求 `&'static dyn Log`，故存 static。
static LOGGER: OnceLock<PolarisLogger> = OnceLock::new();

/// 日志文件大小上限：超过即轮转一次到 `.1`（防无界增长撑爆用户磁盘）。
const MAX_LOG_BYTES: u64 = DEFAULT_GENERATION_BYTES;

// ── 内存环形缓冲（logs:get 水合 + EVENT_LOG_RECEIVED_BATCH 流式推送用）─────────────
//
// 上游 `LogManager` 的最小面：主进程侧每条 log 落盘之余，也进一个有界环形缓冲，供
// 日志页 `logs:get` 一次性水合 + 批量事件流增量推送（`misc.rs` 侧 ~150ms coalesce）。
// 与落盘解耦（独立 static，不进 `PolarisLogger`）：页面 mount 时登记直播所有权，离页 / reload /
// 窗口销毁时释放；无订阅时 emitter 真正休眠。

/// 环形缓冲容量上限（条）。超出即从头丢弃最旧条目（有界，防无限增长）。
const LOG_RING_CAP: usize = 2000;

/// 单条 UI 内存日志正文的字节上限。完整日志已经在 `PolarisLogger::log` 中先行落盘；这里只有
/// 诊断页面的长驻副本需要硬预算，防止“条目数有界、单条字符串无界”绕过环形容量。
const UI_LOG_MESSAGE_MAX_BYTES: usize = 16 * 1024;
const TRUNCATION_MARK: &str = "…";

/// 结构化日志条目（渲染端 `LogEntry` 的后端镜像；`timestamp`/`level` 的最终成形在 `misc.rs`）。
#[derive(Clone, Debug)]
pub struct LogRecord {
    /// 单调递增序号（批量流用游标：只推 `seq >= cursor` 的新条目，不重放整环）。
    pub seq: u64,
    /// Unix epoch 毫秒（与落盘行同源）。
    pub ts_ms: u128,
    /// 级别标签（`error`/`warn`/`info`/`debug`/`trace`）。
    pub level: &'static str,
    /// 来源 target（渲染端 `LogEntry.source`）。
    pub target: String,
    /// 正文（渲染端 `LogEntry.message`）。
    pub message: String,
}

/// 环形缓冲单例（首用即建）。
static LOG_RING: OnceLock<Mutex<VecDeque<LogRecord>>> = OnceLock::new();
/// 全局单调序号发号器（下一个待分配 seq）。
static LOG_SEQ: AtomicU64 = AtomicU64::new(0);

fn ring() -> &'static Mutex<VecDeque<LogRecord>> {
    LOG_RING.get_or_init(|| Mutex::new(VecDeque::with_capacity(LOG_RING_CAP)))
}

/// `record.target()` → 渲染端 `LogEntry.source` 词汇（只有 `sing-box` | `app` 两个值）。
///
/// 日志页的来源过滤器按字面量 `'sing-box'` / `'app'` 判等。但 `log::info!` 不显式指定 `target:` 时，
/// `log` 默认取**调用处的 Rust 模块路径**（`polaris::runtime::proxy` 之类）——全仓 126 处裸调用无一
/// 等于 `"app"`，故「应用」筛选恒空。唯一显式打 target 的是 `runtime/proxy::pipe_to_log`（sing-box 子进程行）。
///
/// 故在此按「不是 sing-box 就是应用自身」归一，而不是去改 126 处调用点加 `target: "app"`——后者要靠每个
/// 新调用点自觉，漏一处又是一条查不到的日志；此处归一是**闭合**的（无论谁怎么写都落进两态之一）。
///
/// 只影响环形缓冲（UI 面）：落盘行仍写完整模块路径，那是排障时定位代码位置的唯一线索，不能抹掉。
fn ui_source(target: &str) -> &str {
    if target == SING_BOX_TARGET || target == SPEEDTEST_CORE_TARGET {
        SING_BOX_TARGET
    } else {
        "app"
    }
}

/// sing-box 子进程日志行的 target（`runtime/proxy::pipe_to_log` 显式打，[`ui_source`] 据此分流）。
pub const SING_BOX_TARGET: &str = "sing-box";

/// **测速临时核**子进程日志行的 target（`runtime::speedtest` 的 drain 显式打）。
///
/// # 为什么它和主核的 target 分开、UI 来源却归成同一个
///
/// 两件事分两条判据，刻意不一致：
///
/// - **落盘分流**（`PolarisLogger::log` 按 `record.target() == SING_BOX_TARGET` 选文件）看的是
///   字面 target ⇒ 临时核的行落 `polaris.log`（app 文件），**不进** `singbox.log`。这是要的：排查
///   临时核必须把核侧的行和 Rust 侧的编排行（`测速临时核已 spawn` / `已回收` / 每节点 debug 行）
///   放在**同一条时间线**上；混进主核那份文件既要人工对时，又会污染主核日志的连续性。
/// - **UI 来源**（[`ui_source`]）归到「内核」⇒ 日志页按来源筛「sing-box」时能看到临时核的行。
///   不登记的话它落进默认的 `app`，用户在日志页按「内核」筛就**恰好漏掉**唯一要看的那段。
/// - **UI 环准入**（[`ring_admits`]）默认档只放行 [`SPEEDTEST_CORE_RING_FLOOR`] 及以上 ⇒ 临时核的
///   info 洪流**不进**内存环，它的 WARN / ERROR / FATAL 照进。这是**第三条**判据，与上两条同样
///   刻意不一致 —— 理由（以及为什么它是对上面那条 UI 来源判据的延伸而非推翻）见该函数文档。
pub const SPEEDTEST_CORE_TARGET: &str = "speedtest-core";

/// 测速临时核日志进 UI 内存环的**默认档级别下限**：比它更啰嗦的行不进环。
///
/// `log::Level` 的 Ord 是「越啰嗦越大」（`Error` < `Warn` < `Info` < `Debug` < `Trace`），故
/// `Warn` 表示「WARN / ERROR 进环，INFO 及以下不进」。sing-box 的 FATAL 行经
/// `runtime::proxy::core_log::singbox_line_level` 映射成 `Error`，落在放行侧。
const SPEEDTEST_CORE_RING_FLOOR: Level = Level::Warn;

/// `log::Level` → 稳定小写标签（渲染端 `LogLevel` 词汇；`trace` 的 `debug` 归并由 `misc.rs` 做）。
fn level_tag(l: Level) -> &'static str {
    match l {
        Level::Error => "error",
        Level::Warn => "warn",
        Level::Info => "info",
        Level::Debug => "debug",
        Level::Trace => "trace",
    }
}

// 纯逻辑（不碰全局；单测直接喂本地 VecDeque，规避共享 static 的测试互扰）。

/// 一条日志准不准进 UI 内存环（纯函数：级别上限由调用方传入，便于单测与变异验证）。
///
/// # 为什么只有测速临时核这一路要设闸
///
/// 环是**定容**的（[`LOG_RING_CAP`] 条，满了从头丢最旧），所以「谁进得来」同时就是「谁把谁挤
/// 出去」。sing-box 在 info 档对每个 outbound 稳定吐 3 行左右（listener 起、inbound 接入、
/// `outbound connection to …`），端点类协议再多两行 —— 一轮 300 节点的测速约 900 行（吃掉 45%
/// 的环），1000 节点约 3000 行，**整个环冲干净一遍还有余**。用户的应用日志、主核日志、以及他正
/// 要找的那条报错，全被这批一次性的临时核 info 挤掉。
///
/// 主核不适用同一条判据：它的 info 是**长期连续**的运行记录，本来就是日志页要显示的东西，挤掉
/// 更旧的行是环形缓冲的正常语义。临时核相反 —— 一轮测速在几十秒内一次性灌完、核随即被回收，
/// 这批行对 UI 的边际价值近乎为零，代价却是把整条历史清零。
///
/// # 为什么是按级别设闸，而不是把这一路整个排除出环
///
/// 起核期的 FATAL（TUN 装地址失败之类）只走 stderr、结构性地不在管理 API 的日志流里，而它恰恰
/// 是排障时最需要的那一行。整路排除 = 连它一起弄丢。故闸设在级别上：默认档放行
/// [`SPEEDTEST_CORE_RING_FLOOR`] 及以上，只挡住数量级在千行的 info/debug/trace。
///
/// # 这是对 [`ui_source`] 那条判据的延伸，不是推翻
///
/// [`SPEEDTEST_CORE_TARGET`] 登记进「内核」来源，理由是「用户按内核筛时必须看得到临时核的行」。
/// 那条理由指向的是**排障要看的那一段**，它从不主张「3000 行 info 也必须常驻内存」。而在大订阅
/// 下，恰恰是那批 info 把环冲干净，让同一个用户按「内核」筛时**什么历史都看不到** —— 原判据想保
/// 的东西在大订阅下反而失效了。本闸让 WARN/ERROR/FATAL 留在环里、且来源仍归「内核」，原判据的
/// 意图到这里才真正成立。故两条判据一个管**归到哪个来源**、一个管**要不要长驻内存**，各自独立，
/// 与本文件既有的「两件事分两条判据」口径同构。
///
/// # 诊断逃生口
///
/// `max >= Debug`（用户把 `config.logLevel` 拨到 `debug`/`trace`，或开了会话诊断模式，见
/// [`set_session_diagnostic`]）= 明确表态「这次我要证据」⇒ 闸整个让开，临时核全部行进环。
///
/// 被挡下的行**从不丢失**：它们照常经 `PolarisLogger` 的落盘腿写进 `polaris.log`，与 Rust 侧的
/// 编排行同一条时间线（见 [`SPEEDTEST_CORE_TARGET`]）。本闸只裁剪 UI 的内存副本，不裁剪磁盘证据。
fn ring_admits(target: &str, level: Level, max: LevelFilter) -> bool {
    if target != SPEEDTEST_CORE_TARGET {
        return true;
    }
    // `log::Level` 的 Ord 是「越啰嗦越大」⇒ `level <= FLOOR` 即「至少和 FLOOR 一样严重」。
    level <= SPEEDTEST_CORE_RING_FLOOR || max >= LevelFilter::Debug
}

/// 有界追加：满则先丢最旧，再入队（环形语义核心）。
fn bounded_push(r: &mut VecDeque<LogRecord>, cap: usize, rec: LogRecord) {
    if r.len() >= cap {
        r.pop_front();
    }
    r.push_back(rec);
}

/// 取最新 N 条快照（`limit=None` → 全部）。
fn collect_snapshot(r: &VecDeque<LogRecord>, limit: Option<usize>) -> Vec<LogRecord> {
    match limit {
        Some(n) if n < r.len() => r.iter().skip(r.len() - n).cloned().collect(),
        _ => r.iter().cloned().collect(),
    }
}

/// 取 `seq >= from_seq` 的增量 + 下一游标（最后一条 seq+1；无则原样返回 `from_seq`）。
fn collect_from(r: &VecDeque<LogRecord>, from_seq: u64) -> (Vec<LogRecord>, u64) {
    let recs: Vec<LogRecord> = r.iter().filter(|e| e.seq >= from_seq).cloned().collect();
    let next = recs.last().map_or(from_seq, |e| e.seq + 1);
    (recs, next)
}

fn search_level_weight(level: &str) -> Option<u8> {
    match level {
        "trace" | "debug" => Some(0),
        "info" => Some(1),
        "warn" => Some(2),
        "error" => Some(3),
        "fatal" => Some(4),
        _ => None,
    }
}

/// 在后端保留历史上过滤，结果按时间正序返回并只保留最新 `limit` 条匹配。
///
/// `limit` 是结果 / DOM 预算，不是查询域：始终扫描完整环。这样 UI 仍只绘制 500 行，但一条位于
/// 第 501—2000 行的诊断记录不会因为“没在当前尾部”而被误报为不存在。
fn collect_search(
    r: &VecDeque<LogRecord>,
    query: &str,
    min_level: &str,
    source: &str,
    limit: usize,
) -> Result<Vec<LogRecord>, &'static str> {
    let Some(min_weight) = search_level_weight(min_level) else {
        return Err("invalid log level");
    };
    if !matches!(source, "all" | "sing-box" | "app") {
        return Err("invalid log source");
    }
    if limit == 0 {
        return Ok(Vec::new());
    }
    let query = query.trim().to_lowercase();
    let mut matches: Vec<LogRecord> = r
        .iter()
        .rev()
        .filter(|record| {
            search_level_weight(record.level).is_some_and(|weight| weight >= min_weight)
                && (source == "all" || record.target == source)
                && (query.is_empty()
                    || record.message.to_lowercase().contains(&query)
                    || record.level.contains(&query))
        })
        .take(limit)
        .cloned()
        .collect();
    matches.reverse();
    Ok(matches)
}

/// 把 UI 长驻正文裁到固定字节预算，保持 UTF-8 边界并在发生裁剪时附加省略号。
///
/// 超限时构造新的有界 allocation，不能在原巨型 `String` 上只做 `truncate`：后者会保留原 capacity，
/// 仍然把整块内存带进环形缓冲，表面长度变短但物理内存没有治理。
fn truncate_ui_message(message: String) -> String {
    if message.len() <= UI_LOG_MESSAGE_MAX_BYTES {
        return message;
    }
    let payload_limit = UI_LOG_MESSAGE_MAX_BYTES - TRUNCATION_MARK.len();
    let mut cut = payload_limit;
    while !message.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut bounded = String::with_capacity(cut + TRUNCATION_MARK.len());
    bounded.push_str(&message[..cut]);
    bounded.push_str(TRUNCATION_MARK);
    bounded
}

/// 追加一条到环形缓冲（满则丢最旧）。锁毒化 → 静默跳过（日志缓冲绝不反噬主流程）。
///
/// **seq 必须在 ring 锁内分配**：发号与入环若非原子，两个并发 logger 线程可以先各自取到 seq=N/N+1，
/// 再以相反顺序入环 → 环内 seq 乱序。而 [`collect_from`] 的游标 = **末条** seq+1，一旦乱序，那条
/// seq 较小的插队条目会被下一批重新取到（重放），或被游标跨过（丢行）。锁内分配令「seq 递增」与
/// 「入环次序」同一把锁下成对发生 → 环内 seq 恒单调，游标语义才成立。
///
/// 准入判据 [`ring_admits`] 放在**这里**而不是调用点，与 [`ui_source`] 同一口径：判据落在闭合的
/// 位置，将来无论谁从哪里往环里写都绕不过它；放在调用点就要靠每个新调用点自觉，漏一处又是一轮
/// 被冲干净的环。被挡下的行不取 seq —— 号是环内游标，没进环就不该占号。
fn push_ring(ts_ms: u128, level: Level, target: &str, message: String) {
    if !ring_admits(target, level, log::max_level()) {
        return;
    }
    if let Ok(mut r) = ring().lock() {
        let seq = LOG_SEQ.fetch_add(1, Ordering::Relaxed);
        bounded_push(
            &mut r,
            LOG_RING_CAP,
            LogRecord {
                seq,
                ts_ms,
                level: level_tag(level),
                target: ui_source(target).to_string(),
                message: truncate_ui_message(message),
            },
        );
    }
}

/// 取环形缓冲快照 + 流式起始游标（`logs:get` 水合）。`limit` = 只取最新 N 条（None = 全部）。
///
/// 二者**必须在同一把 ring 锁下取**，否则水合与流式之间有缝：`logs:get` 先 snapshot、批量流稍后才
/// 取游标 → 期间新写入的条目 seq 低于游标即被跨过（**丢行**）；反之游标先取则被重复下发（**重放**）。
/// 锁内取：游标 = 此刻发号器位置（seq 已改为 ring 锁内分配，故锁内 load 恒等于「下一条待分配」，
/// 且环内不可能已有 seq ≥ 它的条目）→ 快照与增量流恰好首尾相接，不重不漏。
#[must_use]
pub fn snapshot_with_cursor(limit: Option<usize>) -> (Vec<LogRecord>, u64) {
    let Ok(r) = ring().lock() else {
        return (Vec::new(), LOG_SEQ.load(Ordering::Relaxed));
    };
    (collect_snapshot(&r, limit), LOG_SEQ.load(Ordering::Relaxed))
}

/// 取 `seq >= from_seq` 的新条目 + 下一游标（批量事件流增量拉取）。
///
/// 返回 `(recs, next_cursor)`；`next_cursor` = 最后一条 seq+1（无新条目则原样返回 `from_seq`）。
#[must_use]
pub fn records_from(from_seq: u64) -> (Vec<LogRecord>, u64) {
    let Ok(r) = ring().lock() else {
        return (Vec::new(), from_seq);
    };
    collect_from(&r, from_seq)
}

/// 在完整后端日志环上检索；锁毒化与非法筛选值都显式报错，不能把“读不到”伪装成“零命中”。
pub fn search_snapshot(
    query: &str,
    min_level: &str,
    source: &str,
    limit: usize,
) -> Result<Vec<LogRecord>, &'static str> {
    let r = ring().lock().map_err(|_| "log ring unavailable")?;
    collect_search(&r, query, min_level, source, limit)
}

/// 清空环形缓冲（`logs:clear`）。发号器不复位（seq 全局单调，避免游标错位）。
pub fn clear() {
    if let Ok(mut r) = ring().lock() {
        r.clear();
    }
}

struct PolarisLogger {
    /// app 与 sing-box 分文件，但共用同一套硬预算 writer。None = 文件不可用（只写 stderr）。
    app_file: Mutex<Option<RotatingFile>>,
    core_file: Mutex<Option<RotatingFile>>,
}

impl log::Log for PolarisLogger {
    /// 判级取**全局** [`log::max_level`] 而非自身快照字段：级别要能随 `config.logLevel` 在运行期改
    /// （[`set_level`]），持一份构造期的副本会让 `set_max_level` 只改宏侧的前置门、改不动这里，
    /// 出现「宏放行了但 sink 自己按旧级别丢弃」的半生效。单一真值源 = `log::max_level()`。
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis());
        // 单一入口净化：应用日志，以及 AnyConnect/OpenVPN/TS/WARP/WG 的直连 stderr 与运行期
        // SubscribeLog 都进入这个 sink。特权 helper 的启动期文件不经过这里，诊断导出时另做二次净化。
        // 净化放在落盘/环形缓冲之前，避免每个协议调用点各自维护一份易漂移黑名单。
        let message = polaris_stats_engine::redact_log_secrets(&record.args().to_string());
        let line = format!(
            "[{ts}] {:<5} {} — {}",
            record.level(),
            record.target(),
            message
        );
        // stderr：开发态 / 终端启动时直接可见。
        eprintln!("{line}");
        // 文件：核日志与 app 日志分开，各自 current + `.1` 两代、每代 5MiB。写失败一律吞。
        let file = if record.target() == SING_BOX_TARGET {
            &self.core_file
        } else {
            &self.app_file
        };
        if let Ok(mut guard) = file.lock() {
            if let Some(state) = guard.as_mut() {
                if state.write_line(&line).is_err() {
                    *guard = None;
                }
            }
        }
        // 内存环形缓冲：供日志页 logs:get 水合 + EVENT_LOG_RECEIVED_BATCH 流式推送。
        push_ring(ts, record.level(), record.target(), message);
    }

    fn flush(&self) {
        for slot in [&self.app_file, &self.core_file] {
            if let Ok(mut guard) = slot.lock() {
                if let Some(state) = guard.as_mut() {
                    let _ = state.flush();
                }
            }
        }
    }
}

/// 解析级别字面量。同时服务 `POLARIS_LOG` 与 `config.logLevel` 两个来源（词汇不同但取值重叠）。
///
/// `fatal` 是渲染端 `LogLevel` 才有的档（原型日志页 seg 的最高档），`log` crate 无对应 —— 映到
/// `Error`（最接近的「只留最严重」语义）。无法识别 → `None`，由调用方决定回退，不静默当 Info。
fn parse_level(s: &str) -> Option<LevelFilter> {
    match s {
        "trace" => Some(LevelFilter::Trace),
        "debug" => Some(LevelFilter::Debug),
        "info" => Some(LevelFilter::Info),
        "warn" => Some(LevelFilter::Warn),
        // fatal 无 log crate 对应档，归并到 Error（渲染端仍按自己的 fatal 标签过滤显示）。
        "error" | "fatal" => Some(LevelFilter::Error),
        "off" => Some(LevelFilter::Off),
        _ => None,
    }
}

/// `POLARIS_LOG` 是否在启动时被采纳为级别（由 [`init`] 经 [`startup_level`] 置一次）。
///
/// [`set_level`] 据此让位：见该函数文档。
static ENV_LEVEL_OVERRIDE: AtomicBool = AtomicBool::new(false);

/// 当前进程的「诊断模式」基线级别。`Some(level)` 表示诊断已开启，值是开启前（或诊断期间由配置
/// 更新得到）的常规级别；实际 `log::max_level()` 至少抬到 Debug。关闭时把该值原样恢复。
///
/// 这份状态只在进程内，**绝不落配置**：应用重启后 static 重新回到 `None`，启动级别仍走
/// [`startup_level`] 的 config / `POLARIS_LOG` 判据。用 `Mutex<Option<_>>` 而不是单独一个 bool + level，
/// 是为了让「是否开启」与「该恢复到哪里」原子成对，避免并发点击留下开着却无基线的半态。
static SESSION_DIAGNOSTIC_BASE: Mutex<Option<LevelFilter>> = Mutex::new(None);

fn diagnostic_base() -> std::sync::MutexGuard<'static, Option<LevelFilter>> {
    SESSION_DIAGNOSTIC_BASE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// 诊断模式下的有效级别：常规级别比 Debug 更安静时抬到 Debug；本来就是 Trace 时不反向降级。
fn diagnostic_level(base: LevelFilter) -> LevelFilter {
    if base < LevelFilter::Debug {
        LevelFilter::Debug
    } else {
        base
    }
}

/// 当前进程是否处于会话级诊断模式。
#[must_use]
pub fn session_diagnostic_enabled() -> bool {
    diagnostic_base().is_some()
}

/// 开关会话级诊断模式。只改变本进程日志门槛，不写 `config.logLevel`、不重启内核。
///
/// sing-box 的 `SubscribeLog` 恒送全级别，relay 又逐帧读取 `log::max_level()`，所以抬到 Debug 后应用日志
/// 与受管 `logs/singbox.log` 都立即变详细；helper 的 pre-ready/FATAL stderr 仍按起核配置，UI 的
/// 「内核实跑」徽标继续如实显示那一格，不能假装管理 API 有 setter。
pub fn set_session_diagnostic(enabled: bool) -> bool {
    let mut base = diagnostic_base();
    match (enabled, *base) {
        (true, None) => {
            let previous = log::max_level();
            *base = Some(previous);
            log::set_max_level(diagnostic_level(previous));
            log::info!(
                "会话诊断模式已开启：日志临时提升到 {}（重启应用自动恢复）",
                log::max_level()
            );
        }
        (false, Some(previous)) => {
            *base = None;
            log::set_max_level(previous);
            log::info!("会话诊断模式已关闭：日志恢复到 {previous}");
        }
        _ => {} // 幂等：重复开 / 关不刷日志，也不改恢复基线。
    }
    base.is_some()
}

/// 启动级别：`POLARIS_LOG` 环境变量 > `config.logLevel` > Info。
///
/// 环境变量优先是因为它是**排障者的临时超驰**——已经在用它抓日志时，不该被用户配置里存的级别顶掉。
/// 读 config 原文本而非走 `ConfigManager`：本函数在 setup 最早处跑，此刻 store 尚未装配。
///
/// 采纳 env 时置 [`ENV_LEVEL_OVERRIDE`]：该优先级此前只在**启动这一刻**成立，运行期 [`set_level`]
/// 会无条件把它顶掉（见该函数文档）。
fn startup_level(config_dir: &Path) -> LevelFilter {
    resolve_startup_level(std::env::var("POLARIS_LOG").ok().as_deref(), config_dir)
}

/// [`startup_level`] 的本体，env 取值由调用方传入（单测无需改进程环境即可覆盖 env 超驰这一路）。
///
/// 采纳 env 时**武装** [`ENV_LEVEL_OVERRIDE`]：那是 [`set_level`] 让位的唯一依据 —— 漏了这一步，
/// 声明的优先级就只在启动那一刻成立，第一次配置写就把级别顶回去了（P2-5 的本体）。
fn resolve_startup_level(env: Option<&str>, config_dir: &Path) -> LevelFilter {
    if let Some(l) = env_override_level(env) {
        ENV_LEVEL_OVERRIDE.store(true, Ordering::Relaxed);
        return l;
    }
    level_from_config_file(config_dir).unwrap_or(LevelFilter::Info)
}

/// env 超驰判定（纯逻辑，便于单测不碰进程环境）：`Some(l)` = `POLARIS_LOG` 给了可识别级别 → 超驰生效；
/// `None` = 未设或值无法识别 → 无超驰，走 config/默认（无法识别的 env 值不该冻住配置侧的级别控制）。
fn env_override_level(env: Option<&str>) -> Option<LevelFilter> {
    env.and_then(parse_level)
}

/// 从 `<config_dir>/config.json` 读 `logLevel`。任何 IO/解析失败 → None（回退默认，绝不 panic）。
fn level_from_config_file(config_dir: &Path) -> Option<LevelFilter> {
    let raw = std::fs::read_to_string(config_dir.join("config.json")).ok()?;
    let cfg: serde_json::Value = serde_json::from_str(&raw).ok()?;
    parse_level(cfg.get("logLevel")?.as_str()?)
}

/// 运行期改日志级别（`config.logLevel` 变更时调用）。无法识别的值 → no-op + warn，不悄悄降级。
///
/// # 它的射程比「应用侧」大（本批起）
///
/// 本 sink 立即生效自不必说；**核日志现在也归它管**：`runtime/proxy.rs` 的核日志 relay 订阅管理 API
/// 的 `SubscribeLog`，那条流恒是全级别，转发时走的就是 `log::log!` ⇒ 由这里设的 `max_level` 筛。
/// 于是「把级别拨到 debug 立刻看到核的 debug 行」不再需要改核配置、更不需要重启核。
///
/// **仍然管不到的那一格**：核在 pre-ready / helper stderr 上使用的默认级别，是起核时注入进生成
/// 配置的，改配置不追溯已在跑的核 —— UI 就这一格如实标注「需重启内核生效」，本函数不假装管得到。
///
/// # 为什么 env 超驰在这里也要让位
///
/// [`startup_level`] 声明的优先级是 `POLARIS_LOG` > `config.logLevel`，但它此前只在启动那一刻成立：
/// 本函数挂在 `broadcast_config_changed`（配置写的唯一汇流点）上，而 config 恒带 `logLevel` 字段 →
/// `POLARIS_LOG=debug` 起 app 后，**任意**一次配置写都会把级别拉回 config 里存的值，抓 debug 的排障
/// 会话就此静默降级。故 env 一旦生效即在此让位——超驰的定义就是「压过配置」，只压启动那一次不叫超驰。
pub fn set_level(level: &str) {
    if ENV_LEVEL_OVERRIDE.load(Ordering::Relaxed) {
        log::debug!("POLARIS_LOG 环境超驰生效中，忽略 config.logLevel=`{level}` 的级别变更");
        return;
    }
    let Some(filter) = parse_level(level) else {
        log::warn!("未知日志级别 `{level}`，级别未变更");
        return;
    };
    // 诊断期间配置仍允许修改，但只能更新「关闭诊断后恢复到哪里」；实际门槛保持至少 Debug。
    // 否则任意一次全量配置保存（即使只改主题）都会把诊断会话静默打回 Info。
    let effective = {
        let mut base = diagnostic_base();
        if base.is_some() {
            *base = Some(filter);
            diagnostic_level(filter)
        } else {
            filter
        }
    };
    if log::max_level() == effective {
        return; // 幂等：config 保存常带全量字段，级别没变时不刷屏。
    }
    log::set_max_level(effective);
    log::info!("应用日志级别已切到 {effective}（sing-box 侧需重启内核生效）");
}

fn open_log_file(path: &Path) -> Option<RotatingFile> {
    RotatingFile::open(path, MAX_LOG_BYTES, OpenMode::Append).ok()
}

/// 装 sink。**须在 setup 最早处调用一次**；重复调用（`set_boxed_logger` 返回 Err）静默忽略。
///
/// app 日志落 `<config_dir>/logs/polaris.log`，核日志落 `<config_dir>/logs/singbox.log`；
/// 两者均为 current + `.1`，总活跃预算各 10MiB。
pub fn init(config_dir: &Path) {
    let level = startup_level(config_dir);
    let log_dir = config_dir.join("logs");
    let logger = LOGGER.get_or_init(|| PolarisLogger {
        app_file: Mutex::new(open_log_file(&log_dir.join("polaris.log"))),
        core_file: Mutex::new(open_log_file(&log_dir.join("singbox.log"))),
    });
    let app_file_available = logger.app_file.lock().is_ok_and(|f| f.is_some());
    let core_file_available = logger.core_file.lock().is_ok_and(|f| f.is_some());
    if log::set_logger(logger).is_ok() {
        log::set_max_level(level);
        log::info!(
            "日志 sink 已装：level={level}, appFile={app_file_available}, coreFile={core_file_available}"
        );
        if !app_file_available || !core_file_available {
            log::warn!("部分日志文件不可用（目录不可写？）→ 对应来源仅 stderr");
        }
    }
}

#[cfg(test)]
mod tests;
