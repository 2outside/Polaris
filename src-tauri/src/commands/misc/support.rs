pub(super) fn node_platform() -> &'static str {
    match std::env::consts::OS {
        "windows" => "win32",
        "macos" => "darwin",
        other => other,
    }
}

/// 当前时刻 ISO 8601（`YYYY-MM-DDTHH:MM:SS.mmmZ`，对齐 JS `new Date().toISOString()`）。
///
/// 复用 stats-engine 既有的 `created_at_to_rfc3339`（无外部 time 依赖的 civil 算法）——
/// 不为一个时间戳新增 `chrono` / `time` 依赖。取不到系统时间（极端时钟异常）→ 空串，不 panic。
pub(super) fn now_iso8601() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .and_then(polaris_stats_engine::created_at_to_rfc3339)
        .unwrap_or_default()
}

/// 当天日期 `YYYY-MM-DD`（备份 / 报告的默认文件名用）。取 [`now_iso8601`] 的日期段。
pub(super) fn today_yyyy_mm_dd() -> String {
    let iso = now_iso8601();
    iso.split('T').next().unwrap_or("").to_string()
}
