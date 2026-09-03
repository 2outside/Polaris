//! 规则资源自动更新调度器（上游 `src/main/services/RuleResourceScheduler.ts` 1:1 移植）。
//!
//! **为什么需要它**：sing-box 不会自动重下本地 `rule_set`（`res:` 引用的 `.srs` 是 `type:local`，
//! 无 `update_interval`），本地副本会一直陈旧下去。故由 Polaris 侧周期重下载保鲜。
//! - **启动补更**：启动后 12s（错开 `SubscriptionScheduler` 的 8s 高峰）扫一次陈旧资源。
//! - **周期巡检**：每 30 分钟一轮。
//! - **资源库目录（catalog）同轮刷新**：每轮先按同一道开关 / 同一个间隔节流刷一次外置清单，
//!   失败静默（见 [`RuleResourceScheduler::refresh_catalog_if_due`]）。**不新起定时器** ——
//!   它挂在既有的 12s / 30min 两条腿上，故不参与启动错峰预算。
//! - **退避**：单资源失败后指数退避（10min→…→上限 6h），不对故障源高频重试。
//! - **静默**：失败仅日志 + 退避，**不发 toast**（后台保鲜不该抢用户注意力，对齐 上游 `silent:true`）。
//! - **无冷启动鸡生蛋**：下载走直连 / gh-proxy（`commands::rules::apply_gh_proxy`，套用户配置的
//!   `ghProxyPrefix`，加速失败自动回退原址），不依赖代理是否运行 → 不需要订阅调度器那套
//!   `pending_proxy_catchup` 挂起机制。本条曾**与代码相反**（当时 `commands/rules.rs` 全仓零
//!   `ghProxyPrefix` 引用，只有直连），同批接线后本注释才成立。
//!
//! **纯决策 / 计时分离**（与 `subscription_scheduler` 同骨架）：陈旧 / 文件缺失 / 退避判定全收在纯函数
//! [`select_due_resources`]（`now` 与「文件在不在」由调用方注入，全单测覆盖，纯函数**不碰真实文件系统**）；
//! 定时器 + 真下载是薄壳，逐个 due 资源调既有命令 [`crate::commands::rule_resources_redownload`]。
//!
//! 退避状态机与 RFC3339 解析直接复用 `subscription_scheduler` 的 [`BackoffTracker`] /
//! [`rfc3339_to_epoch_ms`]——两调度器的退避 / 时间口径必须一致，各写一份必然漂移。

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use serde_json::Value;
use tauri::{AppHandle, Manager};

use polaris_config_engine::user_config::builtin_geo_rulesets::{
    builtin_geo_rulesets, builtin_id_for,
};

use crate::runtime::subscription_scheduler::{
    elapsed_or_clock_rollback, now_ms, rfc3339_to_epoch_ms, BackoffTracker,
};
use crate::runtime::AppRuntime;

const TICK_MS: u64 = 30 * 60_000; // 30 分钟巡检（= 上游 TICK_MS）
const STARTUP_DELAY_MS: u64 = 12_000; // 启动延迟，错开订阅调度器的 8s
const BACKOFF_BASE_MS: u64 = 10 * 60_000; // 退避基数 10 分钟
const BACKOFF_MAX_MS: u64 = 6 * 60 * 60_000; // 退避上限 6 小时
const DEFAULT_INTERVAL_HOURS: u64 = 12;

/// 资源库目录缓存文件名 —— **只读镜像** `commands::rules` 的私有常量 `CATALOG_CACHE_FILE`
/// （同在 `<userData>/rule-resource/`）。
///
/// 这里只 peek `fetchedAt` 做节流，**写入仍只在 `commands/rules.rs` 一处**（本调度器不碰缓存落盘）。
/// 为什么不改调 `rule_resources_get_catalog` 拿 `fetchedAt`：那个 command 刻意恒返内置精选表
/// （`fetchedAt: null`，理由见其文档「内置 tab 语义」），拿它节流等于每轮都判到期 —— 恰是本节流
/// 要避免的每 30min 白打 GitHub。两处文件名漂移由单测 `catalog_cache_file_name_mirrors_rules_rs` 守。
const CATALOG_CACHE_FILE: &str = "catalog.json";

/// 纯决策：本轮自动更新的间隔（ms）；`None` = **整条自动更新腿本轮都不跑**。
///
/// 两条执行腿（资源重下载 / 资源库目录刷新）共用这一道门与这一个间隔 —— 对齐 上游
/// `RuleResourceScheduler.ts:103`（总开关早退在两条腿之前）+ `:108/:116`（两处同一个 `intervalMs`）。
/// 各写一份必然漂移出「关了总开关目录还在刷」这类分叉。
///
/// - **总开关**：`ruleResourceAutoUpdate === false` 才停；**缺省（老配置 undefined）视为开启**
///   （逐字对齐 上游 `if (config.ruleResourceAutoUpdate === false) return`）。
/// - **间隔**：`ruleResourceUpdateIntervalHours`，`> 0` 才用，缺省 / 非数 → 回落 12h。
/// - **`interval == 0` → `None`**（#18 的 0 语义）：0 是 UI 下拉的「仅手动」档。本调度器的两条腿
///   都动网，故「仅手动」就是彻底不自动动网——包括文件缺失的强制补更、以及目录刷新；缺文件的
///   资源仍可在资源页手动「重新下载」补回，目录也仍可手点「刷新」。**这是与 上游的刻意分叉**
///   （上游的 `intervalMs()` 把 0 折成 12h，因为它那边 0 没有「仅手动」语义）。
#[must_use]
fn auto_update_interval_ms(config: &Value) -> Option<u64> {
    if config
        .get("ruleResourceAutoUpdate")
        .and_then(Value::as_bool)
        == Some(false)
    {
        return None; // 仅显式关闭才停（老配置 undefined → 开）
    }
    let interval_hours = config
        .get("ruleResourceUpdateIntervalHours")
        .and_then(Value::as_u64);
    if interval_hours == Some(0) {
        return None; // 「仅手动」
    }
    Some(
        interval_hours
            .filter(|h| *h > 0)
            .unwrap_or(DEFAULT_INTERVAL_HOURS)
            * 3_600_000,
    )
}

/// 纯决策：本轮该不该刷新**资源库目录**（catalog，外置全量清单）。
///
/// 对齐 上游 `RuleResourceScheduler.ts:110-120`：节流基准取「上次**成功**拉取（缓存里的
/// `fetchedAt`）与上次**尝试**（进程内 `last_catalog_refresh_attempt`）的较晚者」。
/// 两者缺一不可：
///  - 只看 `fetchedAt`：远程一直拉不到时它恒为 0（Polaris 侧是「无缓存」），每 tick 都判到期 →
///    离线 / 被限流时每 30min 白打一次 GitHub 三跳。
///  - 只看进程内 `last_attempt`：它随进程重启清零 → 每次开应用都必刷一次，缓存等于白存。
///
/// `cached_fetched_at_ms` / `last_attempt_ms` 取 0 表示「没有该记录」（`0.max(0) = 0` →
/// `now - 0 >= interval` 恒真 → 首次立即刷，与 上游的 `?? 0` 同义）。
#[must_use]
pub fn catalog_refresh_due(
    config: &Value,
    now_ms: u64,
    cached_fetched_at_ms: u64,
    last_attempt_ms: u64,
) -> bool {
    let Some(interval_ms) = auto_update_interval_ms(config) else {
        return false;
    };
    let last = cached_fetched_at_ms.max(last_attempt_ms);
    elapsed_or_clock_rollback(now_ms, last, interval_ms)
}

/// peek 磁盘 catalog 缓存的 `fetchedAt`（epoch ms）——**只读**，任何一环不过即 0（= 没这条记录，
/// 由 [`catalog_refresh_due`] 判成立即到期）。不复刻 `commands::rules` 那套逐条自洽校验：本函数
/// 只为节流取一个时间戳，缓存内容合不合法由那边的读取腿把关（它才是消费者）。
fn cached_catalog_fetched_at(res_dir: &Path) -> u64 {
    std::fs::read(res_dir.join(CATALOG_CACHE_FILE))
        .ok()
        .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok())
        .and_then(|v| v.get("fetchedAt").and_then(Value::as_u64))
        .unwrap_or(0)
}

/// 纯决策：从 config + now + 退避状态 + 「文件在不在」选出本轮该重下载的资源 id（声明序）。
///
/// - **总开关 / 间隔 / 「仅手动」** → 见 [`auto_update_interval_ms`]（与目录刷新腿共用）。
/// - **陈旧判据**（对齐 上游）：从未记录 `downloadedAt` / 距上次 ≥ interval / **磁盘文件缺失**。
///   文件缺失是**强制**补更（即便时间上不陈旧）——备份恢复或手删后下一轮自动补回，否则被引用的
///   `rule_set` 文件不在会让内核起不来。
/// - 退避未到 → 跳过。
///
/// `file_exists` 收的是资源的 `fileName`（相对规则资源目录），由薄壳注入真实目录拼接。
#[must_use]
pub fn select_due_resources(
    config: &Value,
    now_ms: u64,
    backoff: &BackoffTracker,
    file_exists: &dyn Fn(&str) -> bool,
) -> Vec<String> {
    let mut out = Vec::new();
    let Some(interval_ms) = auto_update_interval_ms(config) else {
        return out;
    };
    let Some(resources) = config.get("ruleResources").and_then(Value::as_array) else {
        return out;
    };

    for res in resources {
        let Some(id) = res.get("id").and_then(Value::as_str) else {
            continue;
        };
        let last = res
            .get("downloadedAt")
            .and_then(Value::as_str)
            .and_then(rfc3339_to_epoch_ms)
            .unwrap_or(0);
        // fileName 缺失 = 条目结构损坏，无从判断文件在不在 → 按「缺失」处理，让重下载去如实报错
        // （命令层对损坏条目返 BAD_ITEM），总比静默跳过永远不修好。
        let missing = !res
            .get("fileName")
            .and_then(Value::as_str)
            .is_some_and(file_exists);
        if !missing && !elapsed_or_clock_rollback(now_ms, last, interval_ms) {
            continue; // 文件在 + 有记录 + 未超间隔 → 不陈旧
        }
        if !backoff.is_eligible(id, now_ms) {
            continue;
        }
        out.push(id.to_string());
    }
    out
}

/// 规则资源自动更新调度器（含退避 + 防重入）。
pub struct RuleResourceScheduler {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    backoff: BackoffTracker,
    is_running: bool,
    started: bool,
    /// 资源库目录刷新的**上次尝试**时刻（epoch ms，0 = 本进程内尚未尝试过）。
    /// 与磁盘 `fetchedAt` 的分工见 [`catalog_refresh_due`]：失败也算一次尝试，间隔内不重试。
    last_catalog_refresh_attempt: u64,
}

fn lock_inner(inner: &Mutex<Inner>) -> MutexGuard<'_, Inner> {
    inner.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Default for RuleResourceScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleResourceScheduler {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                backoff: BackoffTracker::new(BACKOFF_BASE_MS, BACKOFF_MAX_MS),
                is_running: false,
                started: false,
                last_catalog_refresh_attempt: 0,
            })),
        }
    }

    /// 启动：装 12s 启动补更 + 30min 周期巡检。幂等（重复调用 no-op）。
    pub fn start(self: &Arc<Self>, app: AppHandle) {
        {
            let mut inner = lock_inner(&self.inner);
            if inner.started {
                return;
            }
            inner.started = true;
        }

        let this = self.clone();
        let app_startup = app.clone();
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(Duration::from_millis(STARTUP_DELAY_MS)).await;
            this.run_due_updates(&app_startup, "启动补更").await;
        });

        let this = self.clone();
        tauri::async_runtime::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(TICK_MS));
            interval.tick().await; // 立即触发的首 tick 跳过（启动补更已覆盖）
            loop {
                interval.tick().await;
                this.run_due_updates(&app, "周期更新").await;
            }
        });
    }

    /// 一轮到期更新：防重入 → 选到期 → 逐个调既有 redownload 命令 → 记退避 + 汇总日志。
    async fn run_due_updates(self: &Arc<Self>, app: &AppHandle, reason: &str) {
        {
            let mut inner = lock_inner(&self.inner);
            if inner.is_running {
                return;
            }
            inner.is_running = true;
        }
        // 中途 return / panic 都要清 is_running。
        let _guard = RunningGuard {
            inner: self.inner.clone(),
        };

        let (config, res_dir) = {
            let state = app.state::<AppRuntime>();
            let Ok(config) = state.config().load_full() else {
                return;
            };
            // 与 `commands::rules::rule_resources_redownload` 同一落盘目录（单一真值源在那儿）。
            (config, state.config().dir().join("rule-resource"))
        };
        let now = now_ms();

        // 资源库目录（catalog）刷新腿 —— **独立语句、返回 `()`**：这是「失败不打断资源重下载腿」的
        // 编译期保证（= 上游 那圈 try/catch 的作用），把它的结果拿去 `?` / `return` 就退回原状。
        self.refresh_catalog_if_due(app, &config, now, &res_dir, reason)
            .await;

        let due = {
            let mut inner = lock_inner(&self.inner);
            let active: HashSet<String> = config
                .get("ruleResources")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(|r| r.get("id").and_then(Value::as_str).map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            inner.backoff.prune(&active); // 资源被删后剪退避键，防内存无界增长
            select_due_resources(&config, now, &inner.backoff, &|f| res_dir.join(f).exists())
        };
        if due.is_empty() {
            return;
        }

        let (mut ok_count, mut failures) = (0usize, Vec::new());
        for id in due {
            // 走既有下载核心而非直接调下载函数：命令层已收口「条目解析 / 落盘 / persist + 广播」，
            // 绕过它就得在这里复刻一份必然漂移的副本。
            //
            // **静默腿**（对齐 上游 `RuleResourceScheduler` 的 `updateMany(ids, { silent: true })`）：
            // 走 `rule_resources_redownload_silent` 而非 command 本体——后台保鲜在用户毫不知情时
            // 往资源页推 `EVENT_RULE_RESOURCE_PROGRESS`，表现为「没点更新，行却自己转起圈/变红」。
            // 静默由函数内部写死（无 bool 形参可传错，见该函数文档）。
            let state = app.state::<AppRuntime>();
            let resp =
                crate::commands::rules::rule_resources_redownload_silent(app, &state, id.clone())
                    .await;
            let data = resp.ok().and_then(|r| r.data).unwrap_or(Value::Null);
            let ok = data.get("ok").and_then(Value::as_bool) == Some(true);
            let mut inner = lock_inner(&self.inner);
            if ok {
                ok_count += 1;
                inner.backoff.record_success(&id);
            } else {
                // 失败明细带 errorCode（对齐 上游 formatRuleUpdateSummary）：只记「失败 N」时
                // 排查无从区分 timeout / http 4xx / invalid_content。
                let code = data
                    .get("errorCode")
                    .and_then(Value::as_str)
                    .or_else(|| data.get("error").and_then(Value::as_str))
                    .unwrap_or("unknown");
                failures.push(format!("{id}: {code}"));
                inner.backoff.record_failure(&id, now);
            }
        }
        // ── 随包内置 geo 也纳入自动更新射程 ──
        //
        // 此前只遍历 `config.ruleResources`，而内置 geo **从不入册** ⇒ 随包那 28 个 `.srs`
        // 一旦出厂就永不更新，用户看到的分流数据可能落后好几个月
        // （陈先生 2026-07-30：「本地 srs 应该跟随更新」）。
        // 它们的更新腿是本批之前才补上的 `rule_resources_update_builtin`，缺腿才是当初漏掉的真因。
        //
        // 与已登记资源共用同一个总开关和同一个间隔（`auto_update_interval_ms`）——
        // 「我关了自动更新」必须对两类都成立。退避表也共用，键用 `builtin:<tag>`（= 它的资源 id，
        // 与前端列表里那一行同名），故不会与已登记资源的 id 撞键。
        let builtin_ok = self.run_builtin_geo(app, &config, now, reason).await;

        // ── 整批收尾：广播一次（而不是批内每条各广播一次）──
        //
        // `broadcast_config_changed` 不只是 emit 给渲染端，它同时 `spawn(switch_mode)` 把变更送进
        // **运行中的核**。批内逐条广播时，一轮启动补更 = 8 条已登记 + 25 个内置 geo = 33 次
        // `switch_mode`（真机 2026-08-02：11 秒内 35 条 `switchMode：核未运行 → 仅更新配置`）。
        // 核未跑时只是刷屏，核在跑时是**连砸 33 次热切/去抖重启判定** —— 而这一轮语义上就是一批，
        // 批内中间态没有任何消费者需要看见。故两条静默腿传 `BroadcastMode::Deferred`（只落盘），
        // 收口在此处广播一次。
        //
        // **一条都没成功就不广播**：配置没变，广播等于凭空给核一次无谓的 switch_mode 判定。
        if ok_count > 0 || builtin_ok > 0 {
            match app.state::<AppRuntime>().config().current() {
                Ok(latest) => crate::commands::config::broadcast_config_changed(app, &latest),
                Err(e) => log::warn!("[{reason}] 整批更新已落盘，但读回配置广播失败: {e}"),
            }
        }

        if !failures.is_empty() {
            log::warn!(
                "[{reason}] 规则资源自动更新：成功 {ok_count}，失败 {}（{}）",
                failures.len(),
                failures.join("；")
            );
        } else {
            log::info!("[{reason}] 规则资源自动更新：成功 {ok_count}，失败 0");
        }
    }

    /// 内置 geo 的自动更新腿（与已登记资源同开关、同间隔、同退避表）。
    ///
    /// 「到期」判据取 `config.builtinGeoMeta[tag].updatedAt`：
    /// - 缺失（= 出厂态，从未联网更新过）→ **立即到期**，让随包数据尽快追上上游；
    /// - 有值 → 距今超过间隔才到期。
    ///
    /// 落位安全性由 `rule_resources_update_builtin` 自己保证（下到 `.update/` 暂存 + 原子 rename），
    /// 故一次失败绝不会破坏正在生效的那份副本。
    ///
    /// 返回**本轮成功更新的条数** —— 调用方据此决定收尾要不要广播一次配置变更
    /// （见 `run_due_updates` 的整批收尾段；一条都没成功就不该白给核一次 `switch_mode`）。
    async fn run_builtin_geo(
        &self,
        app: &tauri::AppHandle,
        config: &Value,
        now: u64,
        reason: &str,
    ) -> usize {
        let Some(interval_ms) = auto_update_interval_ms(config) else {
            return 0; // 总开关关 / 间隔为「仅手动」→ 整条腿不跑（与已登记资源同口径）
        };
        let meta = config.get("builtinGeoMeta").cloned().unwrap_or(Value::Null);
        let due: Vec<String> = {
            let inner = lock_inner(&self.inner);
            builtin_geo_rulesets()
                .into_iter()
                .filter(|b| {
                    if !inner.backoff.is_eligible(&builtin_id_for(&b.tag), now) {
                        return false;
                    }
                    let updated_at = meta
                        .get(&b.tag)
                        .and_then(|v| v.get("updatedAt"))
                        .and_then(Value::as_str);
                    match updated_at.and_then(rfc3339_to_epoch_ms) {
                        // 从未联网更新过 → 立即到期。
                        None => true,
                        Some(t) => elapsed_or_clock_rollback(now, t, interval_ms),
                    }
                })
                .map(|b| b.tag)
                .collect()
        };
        if due.is_empty() {
            return 0;
        }
        let (mut ok_count, mut failures) = (0usize, Vec::new());
        for tag in due {
            let state = app.state::<AppRuntime>();
            let resp = crate::commands::rules::rule_resources_update_builtin_silent(
                app,
                &state,
                tag.clone(),
            )
            .await;
            let data = resp.ok().and_then(|r| r.data).unwrap_or(Value::Null);
            let ok = data.get("ok").and_then(Value::as_bool) == Some(true);
            let key = builtin_id_for(&tag);
            let mut inner = lock_inner(&self.inner);
            if ok {
                ok_count += 1;
                inner.backoff.record_success(&key);
            } else {
                let code = data
                    .get("errorCode")
                    .and_then(Value::as_str)
                    .or_else(|| data.get("error").and_then(Value::as_str))
                    .unwrap_or("unknown");
                failures.push(format!("{tag}: {code}"));
                inner.backoff.record_failure(&key, now);
            }
        }
        if failures.is_empty() {
            log::info!("[{reason}] 内置 geo 自动更新：成功 {ok_count}，失败 0");
        } else {
            log::warn!(
                "[{reason}] 内置 geo 自动更新：成功 {ok_count}，失败 {}（{}）",
                failures.len(),
                failures.join("；")
            );
        }
        ok_count
    }

    /// 资源库目录（catalog）随自动更新一并刷新 —— 移植 上游
    /// `src/main/services/RuleResourceScheduler.ts:110-123`。
    ///
    /// **为什么必须有这条腿**：资源页「外置」tab 的全量清单只有手点「刷新」才会更新，缺了它用户
    /// 拿到的永远是首次刷新（或从未刷新 → 33 条内置精选）那一份，新上游资源永不出现。
    ///
    /// 三条语义逐条对齐 上游：
    ///  1. **绑同一个总开关 + 同一个间隔**（[`auto_update_interval_ms`]）——关掉自动更新就该连目录
    ///     一起停，否则「我关了自动更新」这句话是假的。
    ///  2. **按间隔节流**（[`catalog_refresh_due`]）：**先记尝试再发请求**，故失败同样消耗本轮配额，
    ///     离线 / 被限流时不会每 30min 重打（上游 `:117` 的 `lastCatalogRefreshAttempt = now` 亦在
    ///     `await refreshCatalog()` 之前）。
    ///  3. **失败静默**：`rule_resources_refresh_catalog` 契约上不 Err（远程失败按 缓存→内置 梯子
    ///     降级并如实标 `source`），故这里靠 `source` 分辨真假刷新：只有 `remote` 才是真拉到了，
    ///     其余落 debug 日志、**不发 toast / 不发事件**（后台保鲜不抢用户注意力，同重下载的静默腿）。
    ///
    /// 返回 `()` 是刻意的：调用方无从短路 —— 目录刷新失败绝不能拖累 `.srs` 重下载腿。
    ///
    /// # 读盘在锁外
    ///
    /// [`cached_catalog_fetched_at`] 是**同步**的读盘 + JSON parse。原实现把它写在
    /// `catalog_refresh_due(...)` 的实参位置上，于是整个 read + parse 都发生在持 `inner` 互斥锁
    /// 期间、且是在 async fn 里 —— 目录缓存文件几百 KB 且落在用户配置目录（可能是网络盘 / 正被
    /// 备份软件锁住），那段时间里 `run_due_updates` 的防重入判定、退避记账全部排队等它。
    /// 锁内只留「判定 + 记 attempt」这两步纯内存操作。顺序由单测
    /// `catalog_refresh_reads_disk_before_taking_the_lock` 锁死。
    async fn refresh_catalog_if_due(
        self: &Arc<Self>,
        app: &AppHandle,
        config: &Value,
        now: u64,
        res_dir: &Path,
        reason: &str,
    ) {
        // 总开关关 / 「仅手动」→ 连盘都不必读（与 `catalog_refresh_due` 的第一道判据同一个函数，
        // 故这条早退与它**恒等价**，只是把读盘省掉）。
        if auto_update_interval_ms(config).is_none() {
            return;
        }
        // ── 锁外读盘（见方法文档「读盘在锁外」）。
        let cached_fetched_at = cached_catalog_fetched_at(res_dir);
        {
            let mut inner = lock_inner(&self.inner);
            if !catalog_refresh_due(
                config,
                now,
                cached_fetched_at,
                inner.last_catalog_refresh_attempt,
            ) {
                return;
            }
            // 先记尝试：下面这次请求无论成败都消耗本轮配额（见方法文档第 2 条）。
            inner.last_catalog_refresh_attempt = now;
        }

        // 复用刷新命令本体（`refresh_catalog_core` 的薄壳）：远程三跳 → `<50` 条闸 → 原子落缓存 →
        // 失败按 缓存→内置 梯子降级，整条口径只此一份。绕过它自己拼一份必然与手动刷新腿漂移。
        let state = app.state::<AppRuntime>();
        let source = crate::commands::rules::rule_resources_refresh_catalog(state)
            .await
            .ok()
            .and_then(|r| r.data)
            .map_or_else(|| "unknown".to_string(), |c| c.source);
        if source == "remote" {
            log::info!("[{reason}] 资源库目录已刷新");
        } else {
            // 拉不到远端不是错误态（清单仍可用，只是不是最新）→ debug，不打扰。
            log::debug!("[{reason}] 资源库目录刷新未拉到远端，沿用 {source} 清单");
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
