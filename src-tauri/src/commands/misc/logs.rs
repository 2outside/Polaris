use std::collections::HashMap;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_shell::ShellExt;

use crate::i18n::{key, t};
use crate::response::{ok_void, ApiResponse};
use crate::runtime::AppRuntime;
use polaris_stats_engine::redact::collect_node_identifiers;
use polaris_stats_engine::{AppSection, RuntimeSection};
use tauri::WebviewWindow;

const LOG_TAIL_BYTES: u64 = 64 * 1024;
/// W26 前由 sing-box 自己无界追加的历史文件。新版本只读识别，绝不在启动/升级时自动删除。
pub(super) const LEGACY_SINGBOX_LOG: &str = "singbox.log";
/// 新版本由 Polaris sink 掌管的两代有界核日志（位于 `logs/`，避开旧文件句柄/历史资产）。
pub(super) const MANAGED_SINGBOX_LOG: &str = "singbox.log";
pub(super) const STARTUP_SINGBOX_LOG: &str = "singbox-startup.log";
static ARCHIVE_TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// 连接 / DNS 类错误标记（命中且非 debug 级 → 提示把日志级别切到 DEBUG 复现）。
///
/// 上游 用正则 `TROUBLE_RE`；此处用**小写子串匹配**等价实现 —— 原正则无捕获、无量词、纯 `|` 分支 + `/i`，
/// 子串匹配语义完全等价，且省掉给 src-tauri 新增 `regex` 依赖。
const TROUBLE_MARKERS: [&str; 9] = [
    "servfail",
    "dns",
    "connection refused",
    "timeout",
    "timed out",
    "handshake",
    "authentication failed",
    "no such host",
    "certificate",
];

/// 平台串，**Node `process.platform` 口径**（win32 / darwin / linux）。
///
/// 刻意不用 `std::env::consts::OS`（会给出 windows / macos）：备份文件的 `platform` 字段要与 上游 写出的
/// 备份**互通**（跨平台进程规则 sanitize 靠它比对），词汇表必须同源。
fn node_platform() -> &'static str {
    match std::env::consts::OS {
        "windows" => "win32",
        "macos" => "darwin",
        other => other,
    }
}

/// 读文件尾部最多 `max_bytes` 字节；不存在 / 失败返回占位串（**绝不抛**——诊断导出不该因日志读不到而失败）。
/// 上游 `DiagnosticService.readTail`。
fn read_tail(path: &Path, max_bytes: u64) -> String {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(meta) = std::fs::metadata(path) else {
        return "(无日志文件)".to_string();
    };
    let size = meta.len();
    let start = size.saturating_sub(max_bytes);
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => return format!("(读取失败: {e})"),
    };
    if f.seek(SeekFrom::Start(start)).is_err() {
        return "(读取失败: seek)".to_string();
    }
    let mut buf = Vec::new();
    if let Err(e) = f.take(max_bytes).read_to_end(&mut buf) {
        return format!("(读取失败: {e})");
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    // 截断导致首行半截 → 丢弃首个不完整行，保持可读。
    let complete_lines = if start > 0 {
        match text.find('\n') {
            Some(i) => text[i + 1..].to_string(),
            None => text,
        }
    } else {
        text
    };
    // legacy/helper 启动日志不一定经过应用 sink；导出边界再净化一次，覆盖历史文件与 helper 腿。
    polaris_stats_engine::redact_log_secrets(&complete_lines)
}

/// 读取 shared writer 的 current + `.1` 两代尾部。不存在仍沿用 [`read_tail`] 的占位口径。
fn read_managed_tail(path: &Path, max_bytes: u64) -> String {
    let Ok(buf) = polaris_log_budget::read_rotated_tail(path, max_bytes) else {
        return "(无日志文件)".to_string();
    };
    polaris_stats_engine::redact_log_secrets(&String::from_utf8_lossy(&buf))
}

/// 组装核日志最近窗口：历史旧文件（只读）+ helper 起核/FATAL + SubscribeLog 受管落盘。
/// 三路各分到 1/3 预算，防为了兼容旧日志把导出报告重新撑成无界。
fn read_core_log_tail(dir: &Path, max_bytes: u64) -> String {
    let per_source = (max_bytes / 3).max(1);
    let mut sections = Vec::new();
    let legacy = dir.join(LEGACY_SINGBOX_LOG);
    if legacy.exists() {
        sections.push(format!(
            "===== singbox.log [legacy] =====\n{}",
            read_tail(&legacy, per_source)
        ));
    }
    let startup = dir.join(STARTUP_SINGBOX_LOG);
    if startup.exists() || polaris_log_budget::rotated_path(&startup).exists() {
        sections.push(format!(
            "===== singbox-startup.log[.1] =====\n{}",
            read_managed_tail(&startup, per_source)
        ));
    }
    let managed = dir.join("logs").join(MANAGED_SINGBOX_LOG);
    if managed.exists() || polaris_log_budget::rotated_path(&managed).exists() {
        sections.push(format!(
            "===== logs/singbox.log[.1] =====\n{}",
            read_managed_tail(&managed, per_source)
        ));
    }
    if sections.is_empty() {
        "(无日志文件)".to_string()
    } else {
        let joined = sections.join("\n\n");
        let max = usize::try_from(max_bytes).unwrap_or(usize::MAX);
        if joined.len() <= max {
            joined
        } else {
            let mut start = joined.len() - max;
            while !joined.is_char_boundary(start) {
                start += 1;
            }
            joined[start..].to_string()
        }
    }
}

/// 当前时刻 ISO 8601（`YYYY-MM-DDTHH:MM:SS.mmmZ`，对齐 JS `new Date().toISOString()`）。
///
/// 复用 stats-engine 既有的 `created_at_to_rfc3339`（无外部 time 依赖的 civil 算法）——
/// 不为一个时间戳新增 `chrono` / `time` 依赖。取不到系统时间（极端时钟异常）→ 空串，不 panic。
fn now_iso8601() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .and_then(polaris_stats_engine::created_at_to_rfc3339)
        .unwrap_or_default()
}

/// 当天日期 `YYYY-MM-DD`（备份 / 报告的默认文件名用）。取 [`now_iso8601`] 的日期段。
fn today_yyyy_mm_dd() -> String {
    let iso = now_iso8601();
    iso.split('T').next().unwrap_or("").to_string()
}

// ── 日志 ── 上游 `log-handlers.ts` ──

/// 批量日志事件 coalesce 间隔（ms）。对齐 上游 LogManager ~150ms 合批推送。
const LOG_BATCH_INTERVAL_MS: u64 = 150;

/// UI 不活跃期积压后**单批**最多补推的条数（对齐 上游 `MAX_PENDING_LOG_BATCH`）。
///
/// 超出即丢最旧、保最新（live tail 语义）：渲染端自身缓冲也是 500 行，补推更多只会被它当场切掉，
/// 白白多一次序列化 + 一次 webview 唤醒。**只截 UI 直播流**——落盘与环形缓冲不受影响，
/// 下一次 `logs:get` 水合仍能取到（且截断条数会 warn 出来，不静默）。
const MAX_PENDING_LOG_BATCH: usize = 500;

/// 后端检索最多回传多少条结果。它只限制 IPC / DOM 载荷，不限制检索域；检索始终扫描完整日志环。
const MAX_LOG_SEARCH_RESULTS: usize = 500;

/// 批量日志推送任务的单次启动闸（首个日志页订阅时惰性起，进程内幂等）。
static LOG_BATCH_STARTED: AtomicBool = AtomicBool::new(false);

/// 日志流当前读取游标。注册表从空变为非空时由同锁快照的 cursor 重置，保证水合与直播首尾相接。
static LOG_STREAM_CURSOR: AtomicU64 = AtomicU64::new(0);

/// 页面级订阅账：window label → 本次 LogsScreen mount 的唯一 token。
///
/// token 不能省：React StrictMode 或快速切屏时，旧页面的异步 cleanup 可能晚于新页面订阅到达；若只按
/// window label 删除，旧 cleanup 会误删新页面所有权。按 token 比对后，陈旧退订天然无效。
static LOG_SUBSCRIBERS: OnceLock<Mutex<LogSubscriberRegistry>> = OnceLock::new();

/// 唤醒长期 emitter 的世代通道。没有订阅时任务 park 在 `watch::Receiver::changed`，不做 150ms 空转。
static LOG_STREAM_WAKE: OnceLock<tokio::sync::watch::Sender<u64>> = OnceLock::new();

#[derive(Default)]
struct LogSubscriberRegistry {
    by_window: HashMap<String, String>,
}

impl LogSubscriberRegistry {
    /// 返回注册前是否为空。相同 window 的新 token 替换旧 token，旧 cleanup 不再拥有删除权。
    fn register(&mut self, window: &str, token: &str) -> bool {
        let was_empty = self.by_window.is_empty();
        self.by_window.insert(window.to_string(), token.to_string());
        was_empty
    }

    fn unregister(&mut self, window: &str, token: &str) -> bool {
        if self.by_window.get(window).map(String::as_str) != Some(token) {
            return false;
        }
        self.by_window.remove(window);
        true
    }

    fn clear_window(&mut self, window: &str) -> bool {
        self.by_window.remove(window).is_some()
    }

    fn windows(&self) -> Vec<String> {
        self.by_window.keys().cloned().collect()
    }
}

fn log_subscribers() -> &'static Mutex<LogSubscriberRegistry> {
    LOG_SUBSCRIBERS.get_or_init(|| Mutex::new(LogSubscriberRegistry::default()))
}

fn log_stream_wake() -> &'static tokio::sync::watch::Sender<u64> {
    LOG_STREAM_WAKE.get_or_init(|| tokio::sync::watch::channel(0).0)
}

fn notify_log_stream() {
    log_stream_wake().send_modify(|epoch| *epoch = epoch.wrapping_add(1));
}

/// 窗口 reload / destroy 的后端兜底：旧 JS 上下文来不及执行 cleanup 时仍能释放日志订阅。
pub(crate) fn clear_log_stream_window(window: &str) {
    let removed = log_subscribers()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear_window(window);
    if removed {
        notify_log_stream();
    }
}

/// `logging::LogRecord` → 渲染端 `LogEntry`（camelCase 契约：timestamp/level/message/source/_id）。
///
/// `_id` = 环形缓冲的全局单调 seq（[`crate::logging::LogRecord::seq`]）。**必须出境**：渲染端拿它当
/// 列表 key + 去重键 ——
///  - key：环形缓冲滑动（丢最旧）后剩余行的 key 不变；退化成 `timestamp-index` 时首元素一淘汰，
///    后面每一行的 index 全体前移 → React 认定整列换了身份，滚动期全量重渲并打断文本选区。
///  - 去重：本 emitter 是**单例**（`LOG_BATCH_STARTED` 只起一次），第二次进日志页时 `logs:get` 的水合
///    快照会与 emitter 下一 tick 的增量重叠一个 ≤150ms 的窗口 → 同一条日志渲染两遍。有单调 `_id`
///    才能在渲染端按「seq ≤ 已见最大 seq 即丢」精确去重。
fn log_record_to_entry(r: &crate::logging::LogRecord) -> Value {
    json!({
        "_id": r.seq,
        "timestamp": ts_ms_to_iso(r.ts_ms),
        "level": frontend_level(r.level),
        "message": r.message,
        "source": r.target,
    })
}

/// 后端级别标签 → 渲染端 `LogLevel`（'debug'|'info'|'warn'|'error'|'fatal'）：trace 归并入 debug。
fn frontend_level(level: &str) -> &str {
    if level == "trace" {
        "debug"
    } else {
        level
    }
}

/// epoch 毫秒 → ISO 8601（渲染端 `LogEntry.timestamp: string`）。复用 stats-engine 的 civil 算法
/// （不新增 chrono/time）；越界 → 原样毫秒串（不 panic）。
fn ts_ms_to_iso(ts_ms: u128) -> String {
    i64::try_from(ts_ms)
        .ok()
        .and_then(polaris_stats_engine::created_at_to_rfc3339)
        .unwrap_or_else(|| ts_ms.to_string())
}

/// 惰性起唯一日志推送任务。无订阅时真正休眠；有订阅但窗口隐藏时降到 1s 可见性巡检且不推进游标；
/// 只有可见的日志页面才按 150ms 拉取并定向发给拥有订阅的窗口。
fn ensure_log_batch_emitter(app: &AppHandle) {
    if LOG_BATCH_STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    let app = app.clone();
    let mut wake = log_stream_wake().subscribe();
    tauri::async_runtime::spawn(async move {
        loop {
            let subscribed = subscribed_log_windows();
            if subscribed.is_empty() {
                // 没有所有者时 park，不做每 150ms 的永久空轮询。
                let _ = wake.changed().await;
                continue;
            }

            let visible = visible_log_windows(&app, &subscribed);
            if visible.is_empty() {
                // 隐藏 / 最小化时不读环、不推进游标；可见性没有事件通道，因此以低频巡检恢复。
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                    _ = wake.changed() => {}
                }
                continue;
            }

            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(LOG_BATCH_INTERVAL_MS)) => {}
                _ = wake.changed() => continue,
            }
            let visible = visible_log_windows(&app, &subscribed_log_windows());
            if visible.is_empty() {
                continue;
            }

            let cursor = LOG_STREAM_CURSOR.load(Ordering::Acquire);
            let (recs, next) = crate::logging::records_from(cursor);
            if recs.is_empty() {
                continue;
            }
            // 游标按**全量**推进（含被截掉的那些）：截断只降 UI 直播流的量，不是「下次再发」——
            // 否则每 tick 都从同一批老条目重发，永远追不上洪流。
            LOG_STREAM_CURSOR.store(next, Ordering::Release);
            let dropped = recs.len().saturating_sub(MAX_PENDING_LOG_BATCH);
            let batch: Vec<Value> = tail_capped(&recs, MAX_PENDING_LOG_BATCH)
                .iter()
                .map(log_record_to_entry)
                .collect();
            for label in visible {
                if let Some(window) = app.get_webview_window(&label) {
                    if let Err(error) = window.emit(
                        crate::events::channel::EVENT_LOG_RECEIVED_BATCH,
                        batch.clone(),
                    ) {
                        log::warn!("向日志订阅窗口 `{label}` 推送批次失败：{error}");
                    }
                }
            }
            if dropped > 0 {
                // 自曝截断：不写出来的话，「UI 隐藏期间掉了 N 行直播」与「本来就没这几行」输出无区别。
                // 本条自身也会进环 → 下一批推给 UI，用户在日志页直接看得到。
                log::warn!(
                    "[log-batch] UI 直播流单批截断：丢弃最旧 {dropped} 条（仅 UI 直播，已落盘且仍在缓冲内）"
                );
            }
        }
    });
}

fn subscribed_log_windows() -> Vec<String> {
    log_subscribers()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .windows()
}

fn visible_log_windows(app: &AppHandle, labels: &[String]) -> Vec<String> {
    // 日志订阅入口只接受 main；后台 task 不直接调平台 getter。wry 的 getter 会跨线程投主循环并阻塞
    // 等回包，原生模态期间占住 tokio worker，destroy 过渡期还会命中失效 WebView。复用 stats 的进程级
    // 可见性缓存：它在主线程刷新，并带明确的主窗 created/destroying 生命周期门，三平台判据一致。
    let visible = app
        .try_state::<AppRuntime>()
        .map(|runtime| runtime.stats().window_visible(app))
        .unwrap_or(true);
    if visible {
        labels.to_vec()
    } else {
        Vec::new()
    }
}

/// 取尾部最多 `cap` 条（丢最旧、保最新 = live tail 语义）。`cap == 0` → 空。
///
/// 抽成纯函数是为了可测：截断策略若写反（取头部）表现为「UI 一直显示几分钟前的旧日志」，
/// 那种错在真机上极难与「日志停了」区分。
fn tail_capped<T>(recs: &[T], cap: usize) -> &[T] {
    if recs.len() > cap {
        &recs[recs.len() - cap..]
    } else {
        recs
    }
}

/// 取日志缓冲并登记本次 LogsScreen mount 对直播流的所有权。
///
/// `limit` = 只取最新 N 条（渲染端 LogsScreen 传 MAX_BUFFER）。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn logs_get(
    app: AppHandle,
    window: WebviewWindow,
    _state: State<'_, AppRuntime>,
    subscription_id: String,
    limit: Option<usize>,
) -> ApiResponse<Vec<Value>> {
    // 快照与 cursor 同锁取；注册表从空变为非空时从该 cursor 开始直播，水合与增量首尾相接。
    let (recs, cursor) = crate::logging::snapshot_with_cursor(limit);
    if window.label() == "main" && !subscription_id.is_empty() {
        let was_empty = log_subscribers()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .register(window.label(), &subscription_id);
        if was_empty {
            LOG_STREAM_CURSOR.store(cursor, Ordering::Release);
        }
        ensure_log_batch_emitter(&app);
        notify_log_stream();
    }
    let entries: Vec<Value> = recs.iter().map(log_record_to_entry).collect();
    ApiResponse::ok(entries)
}

/// 在后端完整保留历史上检索日志，而不是只过滤渲染端当前 500 行。
///
/// `limit` 是返回结果预算；实际查询域由 logging 的保留环决定，不能把两者混成一个数字。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn logs_search(
    query: String,
    level: String,
    source: String,
    limit: Option<usize>,
) -> ApiResponse<Vec<Value>> {
    let limit = limit
        .unwrap_or(MAX_LOG_SEARCH_RESULTS)
        .min(MAX_LOG_SEARCH_RESULTS);
    match crate::logging::search_snapshot(&query, &level, &source, limit) {
        Ok(records) => ApiResponse::ok(records.iter().map(log_record_to_entry).collect()),
        Err(error) => ApiResponse::err(error),
    }
}

/// 释放当前 LogsScreen mount 的直播流所有权。陈旧 token 不会误删后来的页面实例。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn logs_unsubscribe(window: WebviewWindow, subscription_id: String) -> ApiResponse<()> {
    let removed = log_subscribers()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .unregister(window.label(), &subscription_id);
    if removed {
        notify_log_stream();
    }
    ok_void()
}

/// 上游 `LOGS_CLEAR`：清日志缓冲 —— **两侧一起清**。
///
/// # 为什么不能只清本地环
///
/// 核自己也留着一份日志环（`SubscribeLog` 的 3000 行历史，`daemon/attached_service.go` 的
/// `defaultAttachedLogMaxLines`）。只清本地的话，核日志 relay 一旦重订阅（断线重连 / 重启后再进
/// 日志页），那份历史又整份回来 —— 用户看到的是「清了又自己长回来」。故本命令在清本地环之后，
/// 再对运行核发一次 `ClearLogs`。
///
/// 核没在跑 / 管理 API 连不上 / 调用失败 → **只 debug 一行，不算失败**：本地环已经清了，那是用户
/// 点这颗按钮的主要诉求；核侧那份历史随核退出本就一起没了。为一个 best-effort 的补充动作把整条
/// 命令判失败，只会让「清空日志」在核未运行时红一个没有意义的错。
#[tauri::command]
pub async fn logs_clear(state: State<'_, AppRuntime>) -> Result<ApiResponse<()>, ()> {
    crate::logging::clear();
    if let Ok((port, secret)) = crate::commands::proxy::management_endpoint(&state) {
        match polaris_singbox_grpc::SingBoxApiClient::connect(
            polaris_singbox_grpc::Endpoint::new("127.0.0.1", port),
            secret,
        )
        .await
        {
            Ok(c) => {
                if let Err(e) = c.clear_logs().await {
                    log::debug!("清空核侧日志环失败（本地已清，不阻断）：{e}");
                }
            }
            Err(e) => log::debug!("清空核侧日志环：管理 API 连接失败（本地已清，不阻断）：{e}"),
        }
    }
    Ok(ok_void())
}

// ── 核在跑的真实日志级别（`logs:runtimeLevel`）─────────────────────────────────
//
// # 它回答的问题，以及为什么 `config.logLevel` 回答不了
//
// 日志页的级别分段控件显示的是**「我写下的值」**（`useEffectiveConfig().logLevel`）。那个值与
// 核实际在跑的级别有两条已实证的分叉，**都不是渲染端能自己补偿的**：
//
//  1. 隐私锁开启时，生成侧走 `LogLevel::effective(privacy)` 把 info/debug 抬到 warn
//     （`config-engine/src/builder/log.rs`）——核跑 warn，而 UI 一直显示 info，零补偿。
//  2. 配置暂存态下改级别命中 staged 分支即 `return`，**零 IPC 写、零磁盘写**——分段控件已经高亮了
//     新级别，核仍按旧级别记录。
//
// 现有工具栏那颗 `i` 的浮窗只是**文案提示**（「sing-box 侧需重启内核后生效」），它说的是一条通则，
// 不是此刻的事实：它既不知道隐私锁把级别抬到了哪里，也不知道你暂存的那次改动有没有落地。
// 本命令把核的值读回来，让那句话变成可核对的事实。
//
// # 为什么读不到时不回落成某个级别
//
// 核未运行时上游 `GetDefaultLogLevel` 必然报错（先 RLock 检查 `serviceStatus.Status ∈
// {STARTING, STARTED}`，否则 `os.ErrInvalid`）。此时若「兜底」成 `config.logLevel`，
// 显示出来的恰恰又是那个「我写下的值」——自证退化成它本要揭穿的那句谎，只是换了个地方说。
// 故一律回 `level: null` + 一个说明为什么读不到的 `reason`。

/// 读不到时的两种理由（`reason` 取值）。UI 据此分别呈现，**不得压成同一句**：
/// 「核没跑」是常态、无需惊动用户；「读不到」是异常，值得让人看见。
const REASON_NOT_RUNNING: &str = "notRunning";
const REASON_UNAVAILABLE: &str = "unavailable";

/// `daemon::LogLevel` → sing-box 配置里那套小写级别名（`panic`/`fatal`/…/`trace`）。
///
/// 走 prost 生成的 `as_str_name()` 再小写，而不是自己手写一张 match 表：手写表会在上游扩枚举时
/// 静默漏项，而 `as_str_name` 由 proto 生成、与 `proto/started_service.proto` 同步演进。
///
/// 注意这**不是** `config-engine::user_config::LogLevel`（五档、严重度升序）；sing-box 侧七档且
/// 序相反，多出的 `panic`/`trace` 本仓生成侧永不写入，但读侧必须能原样说出来。
fn runtime_level_name(level: polaris_singbox_grpc::daemon::LogLevel) -> String {
    level.as_str_name().to_ascii_lowercase()
}

/// 读回核**此刻实际**在用的日志级别（管理 API gRPC `GetDefaultLogLevel`）。
///
/// 恒返成功信封（读不到不是错误，是一种要如实呈现的状态）：
/// - `{ level: "warn", reason: null }` —— 核在跑，这是它真正在用的级别。
/// - `{ level: null, reason: "notRunning" }` —— 核没在跑（我们自己的状态就知道，连都不用连）。
/// - `{ level: null, reason: "unavailable" }` —— 核在跑但读不到（正在启动 / 管理 API 连不上 /
///   核返回了本仓不认识的级号）。
#[tauri::command]
pub async fn logs_runtime_level(state: State<'_, AppRuntime>) -> Result<ApiResponse<Value>, ()> {
    Ok(match read_runtime_log_level(&state).await {
        Ok(level) => ApiResponse::ok(json!({ "level": level, "reason": Value::Null })),
        Err(reason) => ApiResponse::ok(json!({ "level": Value::Null, "reason": reason })),
    })
}

/// 查询会话级诊断模式。状态只在 Rust 进程内，渲染屏卸载/重挂不会误关；应用重启后自然回到 false。
#[tauri::command]
pub fn logs_diagnostic_state() -> ApiResponse<bool> {
    ApiResponse::ok(crate::logging::session_diagnostic_enabled())
}

/// 开关会话级诊断模式：临时把应用 sink + sing-box 实时 relay 抬到至少 DEBUG，不写配置、不重启核。
#[tauri::command]
pub fn logs_set_diagnostic(enabled: bool) -> ApiResponse<bool> {
    ApiResponse::ok(crate::logging::set_session_diagnostic(enabled))
}

/// [`logs_runtime_level`] 的取值本体。**诊断导出复用同一条腿**。
///
/// 抽出来的理由不是省几行：`config.logLevel`（盘上写的）与核实际在跑的级别有两条已实证分叉
/// （隐私锁抬级 / 配置暂存态未落盘，见本节顶部注释）。日志页那条腿已经改成读回真值，而
/// **诊断导出那条腿此前仍在直接报 `config.logLevel`** —— 同一个谎换个地方说，而且说在
/// 一份「用来给别人做根因判断」的报告头部，比在 UI 上说危害更大。
/// 两条腿共用一个取值点，才谈得上不会再次分叉。
async fn read_runtime_log_level(state: &State<'_, AppRuntime>) -> Result<String, &'static str> {
    let (port, secret) =
        crate::commands::proxy::management_endpoint(state).map_err(|_| REASON_NOT_RUNNING)?;
    let client = match polaris_singbox_grpc::SingBoxApiClient::connect(
        polaris_singbox_grpc::Endpoint::new("127.0.0.1", port),
        secret,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            log::debug!("读核日志级别：管理 API 连接失败：{e}");
            return Err(REASON_UNAVAILABLE);
        }
    };
    match client.default_log_level().await {
        Ok(level) => Ok(runtime_level_name(level).to_string()),
        Err(e) => {
            log::debug!("读核日志级别失败（核可能仍在启动）：{e}");
            Err(REASON_UNAVAILABLE)
        }
    }
}

// ── Shell ── 上游 `shell:openExternal` ──

/// 上游 `SHELL_OPEN_EXTERNAL`：用系统默认浏览器打开外链（tauri-plugin-shell）。
///
/// 注：`shell.open` 在 tauri-plugin-shell 2.x 标记 deprecated（推荐 tauri-plugin-opener）；
/// 切换属独立依赖决策，此处暂用 shell 并抑制 deprecation。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
#[allow(deprecated)]
pub fn shell_open_external(app: AppHandle, url: String) -> ApiResponse<()> {
    if let Err(e) = app.shell().open(&url, None) {
        return ApiResponse::err(format!("{e}"));
    }
    ok_void()
}

/// 原型 log 工具栏「目录」按钮（`:2065` `data-act="open-log-dir"`）：在系统文件管理器里打开日志目录。
///
/// # 为什么打开的是**配置目录**而不是 `logs/`
///
/// 受管应用/内核日志在 `<configDir>/logs/`；helper 启动日志与 W26 前只读历史文件在 `<configDir>`。
/// 开共同父目录能同时看见两类，不把旧 1.46GB 文件藏在上一级。
///
/// # 为什么在后端一步做完，而不是「后端返路径 + 前端 openExternal」
///
/// 那样要两次 IPC，且把一个真实文件系统路径交给渲染端只为再传回来。一步做完还让失败只有一个出口：
/// 路径解析与 `shell.open` 任一失败都是同一条 clean error，前端不必分辨「拿到了路径但打不开」。
/// `#[allow(deprecated)]` 同 [`shell_open_external`]：tauri-plugin-shell 2.x 的 `open` 标了 deprecated。
///
/// **属性行后面别加行注释**：`scripts/check-ipc-args.mjs` 的命令表达式按
/// `#[tauri::command]` + 若干属性 + `pub fn` 连续匹配，中间插一行注释会让它认不出这条命令，
/// 报成「前端 invoke 了一个不存在的命令」。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
#[allow(deprecated)]
pub fn logs_open_dir(app: AppHandle, state: State<'_, AppRuntime>) -> ApiResponse<()> {
    let dir = state.config().dir().to_path_buf();
    if let Err(e) = app.shell().open(dir.to_string_lossy(), None) {
        return ApiResponse::err(format!("{e}"));
    }
    ok_void()
}

/// 查询 W26 前遗留的无界 `singbox.log`。只读 metadata；新受管日志位于 `logs/singbox.log`，
/// 因此本文件存在本身就等价于「待用户显式处理的历史资产」，不会再被当前核写入。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn logs_legacy_info(state: State<'_, AppRuntime>) -> ApiResponse<Value> {
    let path = state.config().dir().join(LEGACY_SINGBOX_LOG);
    match std::fs::metadata(&path) {
        Ok(meta) if meta.is_file() => ApiResponse::ok(json!({
            "exists": true,
            "bytes": meta.len(),
            "path": path.to_string_lossy(),
        })),
        _ => ApiResponse::ok(json!({
            "exists": false,
            "bytes": 0,
            "path": path.to_string_lossy(),
        })),
    }
}

/// 把旧版无界日志显式归档到用户选择的位置，再移除原文件。
///
/// 事务纪律：先复制到目标同目录临时文件并 `sync_all`，复核源文件在复制期间未变化，再同目录 `rename` 提交；
/// 最后一步才删源。任一步失败都保留源文件，绝不让“节省磁盘”变成不可恢复的数据丢失。
#[tauri::command]
pub async fn logs_archive_legacy(
    app: AppHandle,
    state: State<'_, AppRuntime>,
) -> Result<ApiResponse<Value>, ()> {
    let source = state.config().dir().join(LEGACY_SINGBOX_LOG);
    if !source.is_file() {
        return Ok(ApiResponse::ok(
            json!({ "success": true, "archived": false }),
        ));
    }
    let default_name = format!("polaris-singbox-legacy-{}.log", today_yyyy_mm_dd());
    let lang = crate::i18n::app_lang(&app);
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_title(t(lang, key::NATIVE_LEGACY_LOG_ARCHIVE_TITLE))
        .set_file_name(&default_name)
        .add_filter(t(lang, key::NATIVE_LOG_FILE_TYPE), &["log"])
        .add_filter(t(lang, key::NATIVE_ALL_FILES), &["*"])
        .save_file(move |path| {
            let _ = tx.send(path);
        });
    let Some(destination) = rx.await.ok().flatten().and_then(|p| p.into_path().ok()) else {
        return Ok(ApiResponse::ok(
            json!({ "success": false, "error": "cancelled" }),
        ));
    };
    let destination_for_task = destination.clone();
    let archived =
        tokio::task::spawn_blocking(move || archive_legacy_log(&source, &destination_for_task))
            .await
            .map_err(|e| format!("archive task join failed: {e}"))
            .and_then(|r| r);
    Ok(match archived {
        Ok(bytes) => ApiResponse::ok(json!({
            "success": true,
            "archived": true,
            "bytes": bytes,
            "filePath": destination.to_string_lossy(),
        })),
        Err(e) => ApiResponse::err(e),
    })
}

/// 删除 W26 前遗留的无界 `singbox.log`。
///
/// 路径只由后端配置目录拼出，前端不能传任意文件路径；旧日志是用户资产，因此只在用户通过 UI
/// 二次确认后显式调用，不参与启动期/升级期自动清理。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn logs_delete_legacy(state: State<'_, AppRuntime>) -> ApiResponse<Value> {
    let source = state.config().dir().join(LEGACY_SINGBOX_LOG);
    match delete_legacy_log(&source) {
        Ok(Some(bytes)) => ApiResponse::ok(json!({
            "deleted": true,
            "bytes": bytes,
        })),
        Ok(None) => ApiResponse::ok(json!({
            "deleted": false,
            "bytes": 0,
        })),
        Err(e) => ApiResponse::err(e),
    }
}

fn delete_legacy_log(source: &Path) -> Result<Option<u64>, String> {
    let metadata = match std::fs::symlink_metadata(source) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("legacy log metadata: {e}")),
    };
    if !metadata.file_type().is_file() {
        return Err("legacy log is not a regular file".to_string());
    }
    match std::fs::remove_file(source) {
        Ok(()) => Ok(Some(metadata.len())),
        // 用户可能在二次确认期间已从文件管理器删掉；目标状态已经达成，按幂等成功处理。
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("delete legacy log: {e}")),
    }
}

fn archive_legacy_log(source: &Path, destination: &Path) -> Result<u64, String> {
    if source == destination {
        return Err("archive destination must differ from legacy log".to_string());
    }
    if destination.exists() {
        let source_canonical =
            std::fs::canonicalize(source).map_err(|e| format!("resolve legacy log: {e}"))?;
        let destination_canonical = std::fs::canonicalize(destination)
            .map_err(|e| format!("resolve archive destination: {e}"))?;
        if source_canonical == destination_canonical {
            return Err("archive destination must differ from legacy log".to_string());
        }
    }
    let before = std::fs::metadata(source).map_err(|e| format!("legacy log metadata: {e}"))?;
    let before_modified = before.modified().ok();
    let parent = destination
        .parent()
        .ok_or_else(|| "archive destination has no parent directory".to_string())?;
    std::fs::create_dir_all(parent).map_err(|e| format!("create archive directory: {e}"))?;
    let seq = ARCHIVE_TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut tmp_name = destination.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(format!(".polaris-partial-{}-{seq}", std::process::id()));
    let temporary = parent.join(tmp_name);
    let _ = std::fs::remove_file(&temporary);
    let copied = match std::fs::copy(source, &temporary) {
        Ok(bytes) => bytes,
        Err(e) => {
            let _ = std::fs::remove_file(&temporary);
            return Err(format!("copy legacy log: {e}"));
        }
    };
    let sync_result = std::fs::OpenOptions::new()
        .write(true)
        .open(&temporary)
        .and_then(|file| file.sync_all());
    if let Err(e) = sync_result {
        let _ = std::fs::remove_file(&temporary);
        return Err(format!("sync archived log: {e}"));
    }
    let after = match std::fs::metadata(source) {
        Ok(metadata) => metadata,
        Err(e) => {
            let _ = std::fs::remove_file(&temporary);
            return Err(format!("recheck legacy log: {e}"));
        }
    };
    if copied != before.len()
        || after.len() != before.len()
        || before_modified.is_some_and(|modified| after.modified().ok() != Some(modified))
    {
        let _ = std::fs::remove_file(&temporary);
        return Err("legacy log changed while archiving; source was kept".to_string());
    }
    // `std::fs::rename` 在两端均为同目录提交，并按平台语义替换现有普通文件；不要预删 destination，
    // 否则 rename 失败会把用户原先的同名归档一并弄丢。
    if let Err(e) = std::fs::rename(&temporary, destination) {
        let _ = std::fs::remove_file(&temporary);
        return Err(format!("commit archived log: {e}"));
    }
    std::fs::remove_file(source).map_err(|e| {
        format!("archive was saved, but the legacy source could not be removed: {e}")
    })?;
    Ok(copied)
}

// ── sing-box 官方面板 ── Polaris helper-handlers dashboard 部分 ──

#[tauri::command]
pub async fn diagnostic_export(
    app: AppHandle,
    state: State<'_, AppRuntime>,
) -> Result<ApiResponse<Value>, ()> {
    let config = match state.config().load_full() {
        Ok(c) => c,
        Err(e) => return Ok(ApiResponse::err(format!("{e}"))),
    };

    // 实际下发给内核的配置（非重新生成）。取不到 → 注明原因，不阻断导出。
    let runtime_cfg_path = state.proxy().runtime_config_path();
    let singbox_config: Value = match std::fs::read_to_string(&runtime_cfg_path) {
        Ok(s) => serde_json::from_str(&s)
            .unwrap_or_else(|e| json!({ "error": format!("运行期配置解析失败: {e}") })),
        Err(_) => json!({ "error": "(核未启动过，无运行期 sing-box 配置)" }),
    };

    let dir = state.config().dir().to_path_buf();
    let app_log_tail = read_managed_tail(&dir.join("logs").join("polaris.log"), LOG_TAIL_BYTES);
    let singbox_log_tail = read_core_log_tail(&dir, LOG_TAIL_BYTES);

    let status = state.proxy().status();
    // 报告里这一格必须是**核实际在跑的级别**，不是盘上写的那个。
    //
    // 直接报 `config.logLevel` 会在两种常见情形下说谎：隐私锁开着时生成侧把 info/debug 抬到了
    // warn（`config-engine/src/builder/log.rs`），配置暂存态下改的级别根本没落盘。收报告的人
    // 据「当前级别 info」去判断「为什么日志里没有 DNS 明细」，会一路推到错的地方 ——
    // 上游 issue #347 的诊断报告上就实际发生过这件事（头部提示与日志内容对不上）。
    let configured_level = config
        .get("logLevel")
        .and_then(Value::as_str)
        .unwrap_or("info")
        .to_string();
    // 核没跑 / 读不到时**不悄悄回落**成配置值冒充实际值，而是如实标注它的来历。
    let (log_level, level_is_runtime) = match read_runtime_log_level(&state).await {
        Ok(level) => (level, true),
        Err(_) => (configured_level.clone(), false),
    };
    // 提示：当前级别不含连接明细且日志已现连接/DNS 类错误 → 建议把级别拨到 DEBUG 复现。
    //
    // **这句指引在本批被改写**：原文让用户去点「开启诊断采集」，那个按钮连同它背后整条
    // `diagnosticCapture` 机制已删除 —— 核日志现在经 `SubscribeLog` 全级别送来、级别筛在客户端，
    // 把日志页级别拨到 DEBUG 即刻生效，**不需要**改配置也不需要重启内核。
    let lower = app_log_tail.to_lowercase();
    let wants_deeper = log_level != "debug"
        && log_level != "trace"
        && TROUBLE_MARKERS.iter().any(|m| lower.contains(m));
    let hint = wants_deeper.then(|| {
        // 级别的来历要写进这句话本身：读回来的是事实，回落的是「我写下的值」，
        // 后者恰恰可能就是与实际不符的那个 —— 不标来历，这句提示会把读报告的人带偏。
        let origin = if level_is_runtime {
            format!("当前内核实际运行在 {log_level} 级别")
        } else {
            format!("配置中的日志级别为 {log_level}（内核未运行或读不到，未能核对实际级别）")
        };
        format!(
            "{origin}，未含 DNS 解析等连接详情，但日志中已出现连接/DNS 类错误。\
建议到 日志 页把级别切到 DEBUG（即刻生效，无需重启内核），复现问题后再次导出可获得更完整的根因数据。"
        )
    });

    let source = polaris_stats_engine::DiagnosticReportSource {
        generated_at: now_iso8601(),
        app: AppSection {
            polaris_version: app.package_info().version.to_string(),
            core_version: config
                .get("coreVersion")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
            os: format!("{} {}", node_platform(), std::env::consts::ARCH),
        },
        runtime: RuntimeSection {
            proxy_mode: config
                .get("proxyMode")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            proxy_mode_type: config
                .get("proxyModeType")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            proxy_running: status.running,
            started_via_helper: Some(status.started_via_helper),
            helper_status: None,
            system_proxy: None,
            effective_dns: None,
            node_domain_resolver: config
                .get("dnsConfig")
                .and_then(|d| d.get("nodeDomainResolver"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            log_level,
            // 两轴计数由 ProxyRuntime 持有并喂数（§O1 喂数缺口已接线）：
            // - 慢起轴 last_start_ready_retries：起核就绪门累计（proxy.rs wait_ready）。
            // - 核崩轴 restart_count：读时从 CrashRecoveryMachine 投影（单一真值，不并行记）。
            counters: state.proxy().diagnostic_counters(),
        },
        user_config: config,
        singbox_config,
        // #57：节点 outbound.server 恒为域名（不烧 IP）→ 无额外预解析 IP 需补脱敏。
        // 若未来引入 resolve-ahead，预解析出的节点 IP 必须从这里传入，否则明文漏进报告。
        extra_addresses: Vec::new(),
        app_log_tail,
        singbox_log_tail,
        hint,
    };
    let markdown = polaris_stats_engine::assemble_diagnostic_report(&source);

    let default_name = format!("polaris-diagnostic-{}.md", today_yyyy_mm_dd());
    let lang = crate::i18n::app_lang(&app);
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_title(t(lang, key::NATIVE_DIAGNOSTIC_EXPORT_TITLE))
        .set_file_name(&default_name)
        // "Markdown" 是格式名不是文案（五语种同名），刻意不进 locale。
        .add_filter("Markdown", &["md"])
        .add_filter(t(lang, key::NATIVE_ALL_FILES), &["*"])
        .save_file(move |p| {
            let _ = tx.send(p);
        });
    let Some(path) = rx.await.ok().flatten().and_then(|p| p.into_path().ok()) else {
        return Ok(ApiResponse::ok(
            json!({ "success": false, "error": "cancelled" }),
        ));
    };
    if let Err(e) = std::fs::write(&path, markdown) {
        return Ok(ApiResponse::ok(
            json!({ "success": false, "error": format!("{e}") }),
        ));
    }
    Ok(ApiResponse::ok(json!({
        "success": true,
        "filePath": path.to_string_lossy(),
    })))
}

/// 上游 `LOGS_EXPORT`：导出**纯日志**（非诊断报告）。
///
/// 与 [`diagnostic_export`] 是**两种产物**（对齐原型 log 工具栏的两个按钮）：
/// - 本命令 = 两代 app 日志 + 三路 sing-box 近期窗口，**不含配置、不含版本号**。
/// - `diagnostic_export` = 脱敏配置 + 版本号 + 运行态 + 日志的 Markdown 诊断报告。
///
/// # 脱敏边界（重要，勿误当等价物）
///
/// 纯日志导出做两层脱敏：日志凭据/认证 URL 统一打码，再做节点身份打码（域名/IP/SNI/节点名 →
/// 占位符）。它仍不含诊断报告的配置、版本与运行态；**要贴公开 issue 仍请用诊断报告**。
#[tauri::command]
pub async fn logs_export(
    app: AppHandle,
    state: State<'_, AppRuntime>,
) -> Result<ApiResponse<Value>, ()> {
    let dir = state.config().dir().to_path_buf();
    let app_log = read_managed_tail(&dir.join("logs").join("polaris.log"), LOG_TAIL_BYTES);
    let singbox_log = read_core_log_tail(&dir, LOG_TAIL_BYTES);

    // 节点身份打码：日志原文含节点域名/IP/节点名 —— 与诊断报告共用同一套标识符收集 + 替换，不另写一份。
    let ids = match state.config().load_full() {
        Ok(cfg) => collect_node_identifiers(&cfg, &[]),
        Err(_) => Vec::new(),
    };
    let body = format!(
        "# Polaris 日志导出\n\n\
> 纯日志（不含配置与版本号）。**认证凭据与节点身份已打码**。\
要附到公开 issue 请改用「诊断报告」导出。\n\n\
生成时间：{}\n\n\
## app.log（近期）\n\n```text\n{}\n```\n\n\
## sing-box logs（近期）\n\n```text\n{}\n```\n",
        now_iso8601(),
        if app_log.is_empty() {
            "(空)"
        } else {
            &app_log
        },
        if singbox_log.is_empty() {
            "(空)"
        } else {
            &singbox_log
        },
    );
    let redacted = polaris_stats_engine::redact::redact_identifiers(&body, &ids);

    let default_name = format!("polaris-logs-{}.md", today_yyyy_mm_dd());
    let lang = crate::i18n::app_lang(&app);
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_title(t(lang, key::NATIVE_LOGS_EXPORT_TITLE))
        .set_file_name(&default_name)
        .add_filter("Markdown", &["md"])
        .add_filter(t(lang, key::NATIVE_ALL_FILES), &["*"])
        .save_file(move |p| {
            let _ = tx.send(p);
        });
    let Some(path) = rx.await.ok().flatten().and_then(|p| p.into_path().ok()) else {
        return Ok(ApiResponse::ok(
            json!({ "success": false, "error": "cancelled" }),
        ));
    };
    if let Err(e) = std::fs::write(&path, redacted) {
        return Ok(ApiResponse::ok(
            json!({ "success": false, "error": format!("{e}") }),
        ));
    }
    Ok(ApiResponse::ok(json!({
        "success": true,
        "filePath": path.to_string_lossy(),
    })))
}

#[cfg(test)]
mod tests;
