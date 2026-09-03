//! 订阅自动更新调度器（上游 `SubscriptionScheduler` 1:1 移植）。
//!
//! 职责：在不打断当前连接的前提下，按需自动刷新订阅节点。
//! - **启动补更**：启动后延迟一段时间（8s，避开启动高峰），对启用自动更新的订阅补一次更新（忽略陈旧
//!   阈值，仅守 10min 地板——开了「启动时更新」就应更新，而非"距上次≥间隔阈值才更"）。
//! - **周期巡检**：每 30 分钟扫一遍，更新到期（陈旧）的订阅。
//! - **退避**：单个订阅失败后指数退避（5min→…→上限 6h），避免对故障源高频重试。
//! - **不打断连接**：默认路径（内容变则经 `perform_subscription_update` 广播 → 汇流点热切换；无变化
//!   跳广播）已在共用核心里处理；选中节点被下架则 reconcile 内 reselect 兜底出口。
//! - **经代理开关**：全局三态策略 `subscriptionProxyPolicy`（follow=按 per-sub / proxy=全强制 / direct=全直连）
//!   作用于各订阅；经代理订阅若代理未运行则只跳过该订阅（冷启动鸡生蛋），挂起待代理就绪（`onProxyStarted`）
//!   补更，直连订阅照常更新。
//!
//! **纯决策 / 计时分离**（§禁真起定时器碰网络）：陈旧/退避/经代理可用性判定收在纯函数 [`select_due`] +
//! [`BackoffTracker`]（`now` 由调用方注入，全单测覆盖）；定时器/事件接线是薄壳，逐个 due 订阅调共用核心
//! [`crate::commands::subscription::perform_subscription_update`]（唯一生产路径，§K7.1）。

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use tauri::{AppHandle, Listener, Manager};

use crate::commands::subscription::{
    copy_subscription_error_metadata, perform_subscription_update, resolve_subscription_via_proxy,
};
use crate::events::channel::{EVENT_PROXY_STARTED, EVENT_SUBSCRIPTION_AUTOUPDATE};
use crate::runtime::AppRuntime;

const TICK_MS: u64 = 30 * 60_000; // 30 分钟巡检
const STARTUP_DELAY_MS: u64 = 8_000; // 启动延迟
const BACKOFF_BASE_MS: u64 = 5 * 60_000; // 退避基数 5 分钟
const BACKOFF_MAX_MS: u64 = 6 * 60 * 60_000; // 退避上限 6 小时
const DEFAULT_INTERVAL_HOURS: u64 = 12;
const STARTUP_MIN_GAP_MS: u64 = 10 * 60_000; // 启动/代理就绪补更免陈旧门时的最小间隔地板

/// 指数退避状态机（按 id）。上游 `BackoffTracker` 1:1。`now` 由调用方注入（确定性、可单测）。
#[derive(Debug)]
pub struct BackoffTracker {
    base_ms: u64,
    max_ms: u64,
    state: HashMap<String, BackoffEntry>,
}

#[derive(Debug, Clone, Copy)]
struct BackoffEntry {
    failures: u32,
    recorded_at: u64,
    next_eligible_at: u64,
}

impl BackoffTracker {
    #[must_use]
    pub fn new(base_ms: u64, max_ms: u64) -> Self {
        Self {
            base_ms,
            max_ms,
            state: HashMap::new(),
        }
    }

    /// 是否到了可再次尝试的时刻（无记录=可以）。
    #[must_use]
    pub fn is_eligible(&self, id: &str, now: u64) -> bool {
        self.state
            .get(id)
            // 墙钟回拨到失败记录之前时，旧 deadline 已失去意义；立即放行一轮并由本轮结果重建退避。
            // 否则一次 NTP/手工校时可能把 5 分钟退避冻结成数小时甚至数天。
            .is_none_or(|bo| now < bo.recorded_at || now >= bo.next_eligible_at)
    }

    pub fn record_success(&mut self, id: &str) {
        self.state.remove(id);
    }

    /// 记录失败并推进退避：`min(base * 2^(n-1), max)`。返回 `(failures, delay_ms)`。
    pub fn record_failure(&mut self, id: &str, now: u64) -> (u32, u64) {
        let failures = self.state.get(id).map_or(0, |e| e.failures) + 1;
        // base * 2^(n-1)，饱和防溢出。
        let delay_ms = self
            .base_ms
            .saturating_mul(1u64.checked_shl(failures - 1).unwrap_or(u64::MAX))
            .min(self.max_ms);
        self.state.insert(
            id.to_string(),
            BackoffEntry {
                failures,
                recorded_at: now,
                next_eligible_at: now.saturating_add(delay_ms),
            },
        );
        (failures, delay_ms)
    }

    /// 剪除不在活跃集合内的陈旧键（订阅被删后清理，防内存无界增长）。
    pub fn prune(&mut self, active_ids: &std::collections::HashSet<String>) {
        self.state.retain(|id, _| active_ids.contains(id));
    }
}

/// 持久化 epoch 时间戳的「到期」判据：正常前进按 elapsed 比；墙钟回拨到 last 之前则视为到期。
///
/// 这类时间戳必须继续用 epoch（跨进程重启持久化），不能换 `Instant`；但也不能用
/// `saturating_sub` 把回拨折成 0——那会在时钟追上旧值前永久阻止自动更新。
#[must_use]
pub(crate) fn elapsed_or_clock_rollback(now: u64, last: u64, threshold: u64) -> bool {
    last == 0 || now < last || now - last >= threshold
}

/// 到期选择结果。
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DueSelection {
    /// 本轮应更新的订阅 id（声明序）。
    pub due_ids: Vec<String>,
    /// 存在「经代理但代理未起」被跳过的订阅 → 挂起待代理就绪补更。
    pub pending_proxy_catchup: bool,
}

/// 纯决策：从 config + now + 退避状态选出本轮到期订阅。上游 `runDueUpdates` 阶段 1 的选择逻辑。
///
/// - 总开关 `autoUpdateSubscriptionOnStart` 未开 → 空。
/// - `subscriptionUpdateIntervalHours == 0`（UI「仅手动」）→ **周期巡检路径一律空**（见下）。
/// - per-sub `autoUpdate` 关 → 跳过。
/// - 陈旧判断：`ignore_staleness`（启动/代理就绪补更）→ 仅守 10min 地板；否则 `now-last >= interval`。
/// - 退避未到 → 跳过。
/// - 经代理（全局策略 × per-sub）但代理未起 → 跳过 + 置 `pending_proxy_catchup`（直连订阅不受影响）。
#[must_use]
pub fn select_due(
    config: &Value,
    now_ms: u64,
    backoff: &BackoffTracker,
    proxy_running: bool,
    ignore_staleness: bool,
) -> DueSelection {
    let mut out = DueSelection::default();
    if config
        .get("autoUpdateSubscriptionOnStart")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return out; // 总开关未开
    }
    // #18：`interval == 0` 是 UI 下拉的**「仅手动」**档，不是「没填」。旧写法 `.filter(|h| *h > 0)`
    // 把它和缺省一起吞成 12h → 用户选了「仅手动」照样每 12h 自动更新（用户可见的错误行为）。
    //
    // 取舍：**0 只关掉周期巡检腿，不关启动补更腿**。理由——全局「订阅自动更新」
    // （`autoUpdateSubscriptionOnStart`）与「更新间隔」是两个独立开关，用户把间隔设成「仅手动」
    // 表达的是「别在后台按时钟反复拉」，不是「启动时也别拉」；后者他若不想要，关的是总开关。
    // 启动补更本就免陈旧门（仅守 10min 地板），不受 interval 影响，故此处只挡 `!ignore_staleness`。
    let interval_hours = config
        .get("subscriptionUpdateIntervalHours")
        .and_then(Value::as_u64);
    if interval_hours == Some(0) && !ignore_staleness {
        return out; // 仅手动 → 周期巡检不选任何订阅
    }
    let interval_ms = interval_hours
        .filter(|h| *h > 0)
        .unwrap_or(DEFAULT_INTERVAL_HOURS)
        * 3_600_000;
    let policy = config
        .get("subscriptionProxyPolicy")
        .and_then(Value::as_str);
    let Some(subs) = config.get("subscriptions").and_then(Value::as_array) else {
        return out;
    };

    for sub in subs {
        if sub.get("autoUpdate").and_then(Value::as_bool) != Some(true) {
            continue;
        }
        let Some(id) = sub.get("id").and_then(Value::as_str) else {
            continue;
        };
        // 陈旧判断：从未更新（last=0）或超阈值。启动/代理就绪补更仅守 10min 地板。
        let last = sub
            .get("lastUpdated")
            .and_then(Value::as_str)
            .and_then(rfc3339_to_epoch_ms)
            .unwrap_or(0);
        let threshold = if ignore_staleness {
            STARTUP_MIN_GAP_MS
        } else {
            interval_ms
        };
        let stale = elapsed_or_clock_rollback(now_ms, last, threshold);
        if !stale {
            continue;
        }
        if !backoff.is_eligible(id, now_ms) {
            continue;
        }
        // 经代理但代理未起 → 跳过该订阅、挂起补更（直连订阅照常）。
        let via_proxy = resolve_subscription_via_proxy(
            policy,
            sub.get("updateViaProxy").and_then(Value::as_bool),
        );
        if via_proxy && !proxy_running {
            out.pending_proxy_catchup = true;
            continue;
        }
        out.due_ids.push(id.to_string());
    }
    out
}

/// 解析 `current_iso` 产出的 RFC3339（`YYYY-MM-DDTHH:MM:SS.mmmZ`，UTC）→ epoch 毫秒。
///
/// 只需覆盖本仓 `current_iso`（=`created_at_to_rfc3339`）的输出形态：宽松抽取数字段，缺毫秒/末 `Z` 亦容忍；
/// 无 time 依赖（days_from_civil，Howard Hinnant，与 stats-engine `unix_to_civil` 互逆）。解析失败 → `None`
/// （调用方视作 last=0 → 立即到期，宁可多更一次不漏更）。
#[must_use]
pub fn rfc3339_to_epoch_ms(s: &str) -> Option<u64> {
    // 抽取前 6 个整数段（year month day hour min sec）+ 可选毫秒。
    let mut nums: Vec<u64> = Vec::with_capacity(7);
    let mut cur = String::new();
    let mut millis: u64 = 0;
    let mut seen_dot = false;
    for c in s.chars() {
        if c.is_ascii_digit() {
            cur.push(c);
        } else {
            if !cur.is_empty() {
                if seen_dot {
                    // 毫秒段：取前 3 位（截/补）。
                    let ms3: String = cur.chars().take(3).collect();
                    millis = format!("{ms3:0<3}").parse().unwrap_or(0);
                    cur.clear();
                    break;
                }
                nums.push(cur.parse().ok()?);
                cur.clear();
            }
            if c == '.' {
                seen_dot = true;
            }
            if nums.len() >= 6 && !seen_dot {
                break; // 已够 6 段且非毫秒分隔 → 结束
            }
        }
    }
    if !cur.is_empty() && nums.len() < 6 {
        nums.push(cur.parse().ok()?);
    }
    if nums.len() < 6 {
        return None;
    }
    let (year, month, day, hour, min, sec) =
        (nums[0] as i64, nums[1], nums[2], nums[3], nums[4], nums[5]);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    let days = days_from_civil(year, month as u32, day as u32);
    let secs = days * 86_400 + (hour * 3600 + min * 60 + sec) as i64;
    if secs < 0 {
        return None;
    }
    Some((secs as u64) * 1000 + millis)
}

/// civil → 自 1970-01-01 的天数（Howard Hinnant days_from_civil）。
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = i64::from(if m > 2 { m - 3 } else { m + 9 });
    let doy = (153 * mp + 2) / 5 + (i64::from(d) - 1); // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// 当前 epoch 毫秒。`pub(crate)` 是为让 `rule_resource_scheduler` 复用同一时钟入口
/// （两调度器的 `now` 语义必须一致，各写一份必然漂移）。
pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// 从 config 按 id 取订阅显示名（用于失败日志 + 事件 payload）。缺失 → 空串。
fn sub_name<'a>(config: &'a Value, id: &str) -> &'a str {
    config
        .get("subscriptions")
        .and_then(Value::as_array)
        .and_then(|arr| {
            arr.iter()
                .find(|s| s.get("id").and_then(Value::as_str) == Some(id))
        })
        .and_then(|s| s.get("name").and_then(Value::as_str))
        .unwrap_or("")
}

/// 由 `perform_subscription_update` 的返回构造 `EVENT_SUBSCRIPTION_AUTOUPDATE` payload（纯函数，可单测）。
///
/// 成功态透传 added/updated/deleted/unchanged 计数；失败态透传后端真实 `error`（缺省兜底文案）。
/// 渲染端只对 `success:false` 弹 toast（对齐 上游 后台更新只入日志、成功静默的 UX）。
fn build_autoupdate_payload(id: &str, name: &str, result: &Value) -> Value {
    let success = result.get("success").and_then(Value::as_bool) == Some(true);
    if success {
        json!({
            "subscriptionId": id,
            "name": name,
            "success": true,
            "addedServers": result.get("addedServers").and_then(Value::as_u64).unwrap_or(0),
            "updatedServers": result.get("updatedServers").and_then(Value::as_u64).unwrap_or(0),
            "deletedServers": result.get("deletedServers").and_then(Value::as_u64).unwrap_or(0),
            "unchanged": result.get("unchanged").and_then(Value::as_bool).unwrap_or(false),
        })
    } else {
        let mut payload = json!({
            "subscriptionId": id,
            "name": name,
            "success": false,
            "error": result.get("error").and_then(Value::as_str).unwrap_or("订阅更新失败"),
        });
        copy_subscription_error_metadata(result, &mut payload);
        payload
    }
}

/// 订阅自动更新调度器（含退避 + 防重入 + 挂起补更）。
pub struct SubscriptionScheduler {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    backoff: BackoffTracker,
    is_running: bool,
    pending_proxy_catchup: bool,
    started: bool,
}

fn lock_inner(inner: &Mutex<Inner>) -> MutexGuard<'_, Inner> {
    inner.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Default for SubscriptionScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl SubscriptionScheduler {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                backoff: BackoffTracker::new(BACKOFF_BASE_MS, BACKOFF_MAX_MS),
                is_running: false,
                pending_proxy_catchup: false,
                started: false,
            })),
        }
    }

    /// 启动：装 8s 启动补更 + 30min 周期巡检 + `event:proxyStarted` 补更监听。幂等（重复调用 no-op）。
    pub fn start(self: &Arc<Self>, app: AppHandle) {
        {
            let mut inner = lock_inner(&self.inner);
            if inner.started {
                return;
            }
            inner.started = true;
        }

        // 启动补更（忽略陈旧门，仅守 10min 地板）。
        let this = self.clone();
        let app_startup = app.clone();
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(Duration::from_millis(STARTUP_DELAY_MS)).await;
            this.run_due_updates(&app_startup, true).await;
        });

        // 周期巡检。
        let this = self.clone();
        let app_tick = app.clone();
        tauri::async_runtime::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(TICK_MS));
            interval.tick().await; // 立即触发的首 tick 跳过（启动补更已覆盖）
            loop {
                interval.tick().await;
                this.run_due_updates(&app_tick, false).await;
            }
        });

        // 代理就绪 → 补跑挂起（经代理但代理未起而跳过的订阅）。
        let this = self.clone();
        let app_evt = app.clone();
        app.listen(EVENT_PROXY_STARTED, move |_| {
            let this = this.clone();
            let app = app_evt.clone();
            tauri::async_runtime::spawn(async move {
                this.on_proxy_started(&app).await;
            });
        });
    }

    /// 代理就绪补更：仅当有挂起标记且当前空闲。
    async fn on_proxy_started(self: &Arc<Self>, app: &AppHandle) {
        {
            let mut inner = lock_inner(&self.inner);
            // isRunning 时不清 flag：已有更新在途，保留挂起标记待后续触发。
            if !inner.pending_proxy_catchup || inner.is_running {
                return;
            }
            inner.pending_proxy_catchup = false;
        }
        self.run_due_updates(app, true).await;
    }

    /// 一轮到期更新：防重入 → 选到期 → 逐个调共用核心 → 记退避。
    async fn run_due_updates(self: &Arc<Self>, app: &AppHandle, ignore_staleness: bool) {
        // 防重入闸。
        {
            let mut inner = lock_inner(&self.inner);
            if inner.is_running {
                return;
            }
            inner.is_running = true;
        }
        // 无论中途 return/panic 都要清 is_running（用 guard）。
        let _guard = RunningGuard {
            inner: self.inner.clone(),
        };

        let state = app.state::<AppRuntime>();
        // Windows 冷启动实证：8s 启动补更与 TUN post-start `CloseAllConnections` 两次落在同一毫秒，
        // reqwest 新连接被无差别 RST 后只剩笼统的「error sending request」。等待代理运行时的统一
        // 稳定门，覆盖起核、selector 校正与单次 flush；不靠再调一个会随机器快慢漂移的固定 sleep。
        log::debug!(
            "[订阅自动更新] 进入代理网络稳定门：pending={} ignoreStaleness={ignore_staleness}",
            state.proxy().network_settle_pending()
        );
        state.proxy().wait_for_network_settled().await;
        log::debug!("[订阅自动更新] 代理网络稳定门已放行");
        let config = match state.config().load_full() {
            Ok(c) => c,
            Err(_) => return,
        };
        let proxy_running = state.proxy().status().running;
        let now = now_ms();

        // 选到期 + 剪退避（读退避在锁内，尽量短持）。
        let selection = {
            let mut inner = lock_inner(&self.inner);
            let active: std::collections::HashSet<String> = config
                .get("subscriptions")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(|s| s.get("id").and_then(Value::as_str).map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            inner.backoff.prune(&active);
            let sel = select_due(
                &config,
                now,
                &inner.backoff,
                proxy_running,
                ignore_staleness,
            );
            inner.pending_proxy_catchup = sel.pending_proxy_catchup;
            sel
        };
        log::debug!(
            "[订阅自动更新] 到期选择完成：due={} pendingProxyCatchup={}",
            selection.due_ids.len(),
            selection.pending_proxy_catchup
        );

        // 逐个更新（不持调度器锁跨 await）。
        for id in selection.due_ids {
            let result = perform_subscription_update(app, state.inner(), &id).await;
            let ok = result.get("success").and_then(Value::as_bool) == Some(true);
            // 失败落日志（对齐 上游 SubScheduler logManager.addLog('warn', ...)：后台失败的用户可见面 =
            // 日志）+ 发事件让渲染端弹 toast（补 上游 无、Polaris 原本静默的缺口——退避已限频，不刷屏）。
            let name = sub_name(&config, &id).to_string();
            if !ok {
                let err = result
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("订阅更新失败");
                log::warn!("[订阅自动更新] 订阅「{name}」更新失败: {err}");
            }
            crate::events::broadcast(
                app,
                EVENT_SUBSCRIPTION_AUTOUPDATE,
                build_autoupdate_payload(&id, &name, &result),
            );
            let mut inner = lock_inner(&self.inner);
            if ok {
                inner.backoff.record_success(&id);
            } else {
                inner.backoff.record_failure(&id, now);
            }
        }
    }
}

/// 清 is_running 的 RAII 守卫（中途 return/panic 均复位）。
struct RunningGuard {
    inner: Arc<Mutex<Inner>>,
}
impl Drop for RunningGuard {
    fn drop(&mut self) {
        lock_inner(&self.inner).is_running = false;
    }
}

#[cfg(test)]
mod tests;
