//! 内置 geo 规则集播种（上游 `src/main/services/builtin-geo-rulesets.ts:174 seedBuiltinRuleSets` 移植）。
//!
//! **为什么必须有它**：`config-engine/src/user_config/builtin_geo_rulesets.rs:4` 注明「FS I/O
//! （seedBuiltinRuleSets）属运行时层」——而运行时层此前从未实现。后果是
//! `runtime_rules_dir`（`<userData>/rules`）永远为空 → `route.rs` 的 `is_valid_srs_fn` 恒 false →
//! 一个 `rule_set` 都不注入 → fail-closed 剪枝把全部 geo 规则整条剪掉。真机 2026-07-20 的
//! 「全量明文直连」正是这条链的终点：**上游 中不可达的降级分支，在 Polaris 是 100% 命中的默认路径。**
//!
//! 语义（逐条对齐 上游）：
//! - **seed-if-missing-or-invalid**：dest 已存在且 SRS 魔数有效 → 跳过（幂等；两个调用点可重叠，
//!   跳过同时也避免与并发的另一轮 seed 争抢同一个 dest）。
//! - **出厂态刷新**（[`SeedOptions::refresh_out_of_box`]，**仅启动时**）：dest 有效但与随包文件大小
//!   不一致，且该 tag 无网络更新记录（`config.builtinGeoMeta[tag].updatedAt` 缺失 = 出厂态）→
//!   刷新为新出厂版。移植 上游 `builtin-geo-rulesets.ts:170-186`，那里明记这条正是
//!   「seed-if-missing 后出厂态用户跨升级冻结在首装版」的回归修复：装 v1 → 播种 → 升 v2（随包带
//!   新 geo 数据）→ dest 仍有效 → 永不更新。**有网络更新记录的副本永不被出厂版覆盖。**
//! - **校验 src**：只校验 dest 会把损坏的随包文件（404/空文件污染打包）原样种进运行时目录，
//!   之后 route builder 照样判无效 → 白种一场。坏 src 留给网络更新兜底。
//! - **原子写**：copy 到 tmp 再 `rename`。半写文件被 TUN 特权核读到 = `initialize rule-set` FATAL。
//! - **单项失败不阻断其余项**：best-effort，下次启动 / 下次起核再试。
//!
//! **目录边界（别误读成同一个目录）**：本模块**只**写 `<userData>/rules/`。用户经「规则资源」页
//! 下载的副本落在**另一个**目录 `<userData>/rule-resource/`（`commands/rules.rs`
//! `rule_resources_download`），由 route builder 的 `add_local_geo_rule_set` 读取——内置 tag 在
//! `<userData>/rules/` 缺失时也会回落到那里（`builder/route.rs` 的内置注入腿），故「下载后恢复」
//! 这条用户指引对内置 tag 同样成立。本模块不碰 `rule-resource/`。
//!
//! 调用点两处（对齐 上游 `index.ts:1834` + `ProxyManager.ts:6375`）：应用启动时 + **每次起核前**。

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use polaris_config_engine::user_config::builtin_geo_rulesets::{
    builtin_geo_rulesets, is_valid_srs_file,
};

/// tmp 文件名去重计数器（同进程内并发 seed 不撞名）。上游 `seedCounter`。
static SEED_COUNTER: AtomicU64 = AtomicU64::new(0);

/// tmp 文件名中段（`<file>.srs.seed-<pid>-<seq>`）；清扫腿与命名腿共用，防两处漂移。
const TMP_MARK: &str = ".seed-";

/// 播种选项。默认 = 「只补缺失」（起核前那次调用的语义）。
#[derive(Debug, Clone, Default)]
pub struct SeedOptions {
    /// 已**网络更新过**的内置 tag（`config.builtinGeoMeta[tag].updatedAt` 存在）。
    /// 这些副本不是出厂态 ⇒ **永不**被随包出厂版刷新（只在损坏/缺失时才重播）。
    pub network_updated_tags: BTreeSet<String>,
    /// 出厂态刷新开关。**仅启动时传 true**：此刻无并发的规则资源更新，刷新落地无竞态；
    /// 运行中（起核前）那次只做「缺失补种」，不与并发更新争抢。
    pub refresh_out_of_box: bool,
}

/// 单次播种结果。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeedReport {
    /// 本次真正落盘的文件名（已存在且有效的不计入）。
    pub seeded: Vec<String>,
    /// 本次因**出厂态刷新**被覆盖的文件名（`seeded` 的子集语义：也在 `seeded` 里）。
    pub refreshed: Vec<String>,
    /// 播种后**仍然**无有效本地副本的 tag（随包缺失 / 随包损坏 / 落盘失败）。
    ///
    /// 非空 ⇒ 起核时这些 tag 的规则仍会被 fail-closed 剪掉。
    /// **刷新失败不计入**：dest 仍是有效副本，只是版本旧，规则照样注入。
    pub still_missing: Vec<String>,
}

/// 本轮要对某个 tag 做什么。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SeedReason {
    /// dest 缺失 / 损坏 → 必种。失败即 `still_missing`。
    Missing,
    /// dest 有效但是旧出厂版 → 刷新。失败无害（旧副本仍可用）。
    Refresh,
}

/// 把随包 `.srs` 播种到运行时 rules 目录（seed-if-missing-or-invalid + 出厂态刷新 + 原子 tmp→rename）。
///
/// 纯 FS、可注入两个目录 ⇒ 单测用临时目录即可覆盖全部分支，不碰宿主真实数据。
pub fn seed_builtin_rule_sets(
    bundled_dir: &Path,
    runtime_dir: &Path,
    opts: &SeedOptions,
) -> SeedReport {
    let mut report = SeedReport::default();
    // 目录建不出来（权限/只读卷）→ 整轮无从落盘，但仍要如实报告「全部仍缺失」，不静默返回空。
    let dir_ok = std::fs::create_dir_all(runtime_dir).is_ok();
    if dir_ok {
        sweep_stale_tmp(runtime_dir);
    }
    for b in builtin_geo_rulesets() {
        let dest = runtime_dir.join(&b.file_name);
        let src = bundled_dir.join(&b.file_name);
        let Some(reason) = seed_reason(&src, &dest, &b.tag, opts) else {
            continue;
        };
        if dir_ok && seed_one(&src, &dest, reason == SeedReason::Refresh) {
            report.seeded.push(b.file_name.clone());
            if reason == SeedReason::Refresh {
                report.refreshed.push(b.file_name.clone());
            }
            continue;
        }
        // 刷新失败 ⇒ dest 仍是有效（只是旧的）副本，规则照样注入 ⇒ **不是** still_missing。
        if reason == SeedReason::Missing {
            report.still_missing.push(b.tag.clone());
        }
    }
    report
}

/// 单个 tag 的动作判定（纯判定，便于单测直接锁语义）。`None` = 本轮什么都不做。
fn seed_reason(src: &Path, dest: &Path, tag: &str, opts: &SeedOptions) -> Option<SeedReason> {
    if !is_valid_srs_file(dest) {
        return Some(SeedReason::Missing);
    }
    // 出厂态刷新：仅启动时 + 该 tag 无网络更新记录 + 随包与运行时大小不一致（= app 升级换了出厂数据）。
    // stat 失败不强制刷新（读不到就别动已有的有效副本），与 上游的 try/catch → keep null 同义。
    if opts.refresh_out_of_box && !opts.network_updated_tags.contains(tag) {
        let sizes = std::fs::metadata(src)
            .and_then(|s| std::fs::metadata(dest).map(|d| (s.len(), d.len())))
            .ok();
        if let Some((src_len, dest_len)) = sizes {
            if src_len != dest_len {
                return Some(SeedReason::Refresh);
            }
        }
    }
    None
}

/// 清扫**历史残留** tmp：进程在 `copy` 与 `rename` 之间被杀 → `<file>.srs.seed-<pid>-<n>` 永久残留
/// （单文件最大 157KB，全仓此前无任何代码清理）。
///
/// **只删 pid ≠ 本进程的残留**：本模块有两个调用点（启动 / 每次起核前），同进程内可重叠，
/// 删掉对方在途的 tmp 会让它的 `rename` 失败 → 假的 `still_missing`。
/// 代价：pid 回卷后与本进程撞号的历史残留会被跳过（下次换 pid 的运行清掉），不值得为它引入锁。
fn sweep_stale_tmp(runtime_dir: &Path) {
    let mine = format!("{TMP_MARK}{}-", std::process::id());
    let Ok(entries) = std::fs::read_dir(runtime_dir) else {
        return;
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.contains(TMP_MARK) && !name.contains(&mine) {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// 单个文件播种。返回「落盘后 dest 确有有效副本」。
///
/// `overwrite_valid_dest` = 出厂态刷新腿（dest 本就有效，覆盖是目的）。
fn seed_one(src: &Path, dest: &Path, overwrite_valid_dest: bool) -> bool {
    // src 缺失 / 损坏 → 不种（种坏文件 = 制造一个 route builder 判无效的悬空引用，白费且掩盖真因）。
    if !is_valid_srs_file(src) {
        return false;
    }
    let seq = SEED_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = dest.with_file_name(format!(
        "{}{TMP_MARK}{}-{seq}",
        dest.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));
    if std::fs::copy(src, &tmp).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return false;
    }
    // 落地前复查（**只在补缺失腿**）：本模块两个调用点可重叠，期间另一轮 seed 可能已把同一个 dest
    // 种好 → 放弃覆盖，省一次无谓的 rename。刷新腿必须跳过这一步：那里 dest 本来就是有效的旧版。
    if !overwrite_valid_dest && is_valid_srs_file(dest) {
        let _ = std::fs::remove_file(&tmp);
        return true;
    }
    if std::fs::rename(&tmp, dest).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return false;
    }
    true
}

/// 随包 `resources/data/` 目录的候选清单（解析腿与失败日志共用同一份 ⇒ 日志里列的就是真试过的）。
///
/// 复用 [`bundle_resource_candidates`](crate::runtime::proxy::bundle_resource_candidates) 的布局知识
/// ——macOS `.app` 的 `_up_` 段等坑已在那里钉死过一次，不另写第二份（写第二份就是等它漂移）。
/// 以 `"data"` 作平台子目录、空文件名 ⇒ 候选即目录本身。
///
/// **release 剔除源码仓候选**（`CARGO_MANIFEST_DIR/../resources`）：打包配方是「把仓库 rsync 到打包机
/// 再把 `.app` 装进同机 `/Applications`」，于是源码仓候选在**打包机上真实存在**。留着它，即便随包
/// `.app` 里一个 `.srs` 都没有，播种也会经这条腿从源码仓成功 —— 验证者看到 28 个 `.srs` 判「打包态 OK」，
/// 而没有仓库的终端用户拿到零 `.srs`。这正是「打包态验证假绿」的产地，故只在 debug（开发态）保留。
fn bundled_data_candidates() -> Vec<PathBuf> {
    let exe = std::env::current_exe().ok();
    let manifest = crate::runtime::proxy::dev_manifest_dir();
    let candidates = crate::runtime::proxy::bundle_resource_candidates(
        exe.as_deref().and_then(Path::parent),
        manifest,
        &["data"],
        "",
    );
    // `cfg!` 在测试构建里恒为 debug ⇒ 剔除腿在原地写死就**永远测不到**。抽成取显式布尔的纯函数，
    // 让 release 那条语义有门（`drops_repo_candidate_only_in_release`）。
    //
    // 与 `dev_manifest_dir()` 的 `None` **重复守一次是刻意的**：那条断的是「候选压根不生成」，
    // 这条断的是「万一生成了也不许留」。判据不同、失效方式不同，任一独立成立即可，
    // 而这个纯函数的门（`drops_repo_candidate_only_in_release`）不受构型影响，永远测得到。
    filter_repo_candidate(candidates, manifest, !cfg!(debug_assertions))
}

/// release 构建剔除源码仓候选（见 [`bundled_data_candidates`] 上方的「打包态验证假绿」说明）。
fn filter_repo_candidate(
    mut candidates: Vec<PathBuf>,
    dev_manifest_dir: Option<&Path>,
    is_release: bool,
) -> Vec<PathBuf> {
    if let (true, Some(manifest_dir)) = (is_release, dev_manifest_dir) {
        let repo_prefix = manifest_dir.join("..").join("resources");
        candidates.retain(|c| !c.starts_with(&repo_prefix));
    }
    candidates
}

/// 解析随包 `resources/data/` 目录（`.srs` 出厂副本所在）：取首个真实存在的候选目录。
pub fn resolve_bundled_data_dir() -> Option<PathBuf> {
    bundled_data_candidates().into_iter().find(|c| c.is_dir())
}

/// 从 `config.json` 原文本抽「已网络更新过」的内置 geo tag 集（`builtinGeoMeta[tag].updatedAt` 存在）。
///
/// 读原文本而非走 store：启动时的调用点在 store 装配之前（与图形逃生门同一位置的 raw config）。
/// 任何解析异常 → 空集 = 「全部视作出厂态」= 刷新腿全开，这是安全方向（最坏是把已更新副本刷回出厂版，
/// 而 Polaris 当前**没有任何代码**往 `<userData>/rules/` 写网络版，故该最坏情形当前不可达）。
pub fn network_updated_tags_from_raw(raw: Option<&str>) -> BTreeSet<String> {
    let Some(meta) = raw
        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
        .and_then(|v| v.get("builtinGeoMeta").cloned())
    else {
        return BTreeSet::new();
    };
    let Some(obj) = meta.as_object() else {
        return BTreeSet::new();
    };
    obj.iter()
        .filter(|(_, v)| {
            v.get("updatedAt")
                .is_some_and(|u| !u.is_null() && u.as_str() != Some(""))
        })
        .map(|(k, _)| k.clone())
        .collect()
}

/// 生产入口：解析随包目录 → 播种到 `<config_dir>/rules`，并记日志。
///
/// **`rules` 子目录名必须与 `GenerateConfigDeps.runtime_rules_dir` 同源**
/// （`proxy.rs` 的 `dir.join("rules")`）——种到别处等于没种。
pub fn seed_builtin_rule_sets_into(config_dir: &Path, occasion: &str, opts: &SeedOptions) {
    let runtime_dir = config_dir.join("rules");
    let Some(bundled) = resolve_bundled_data_dir() else {
        // 候选清单随 Err 一起给出（与 `resolve_bundled_core_binary` / `resolve_helper_binary` 同口径）：
        // 「没找到」不带尝试过哪些路径，等于把排查成本整条推给下一个人。
        log::warn!(
            "随包规则资源目录（resources/data）未找到 → 跳过内置 geo 播种（{occasion}）；\
             尝试过：{}；智能分流的 geo 规则将被 fail-closed 剪枝，请到「规则资源」页下载",
            bundled_data_candidates()
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(" | ")
        );
        return;
    };
    // **命中路径必须可断言**：打包态验收要能在真机日志里确认它落在 `Polaris.app/Contents/Resources/`
    // 之下，而不是源码仓。只在失败时打一行 warn 是不够的——成功那条腿才是会说谎的那条。
    log::info!(
        "内置 geo 随包目录已解析（{occasion}）：{}",
        bundled.display()
    );
    let report = seed_builtin_rule_sets(&bundled, &runtime_dir, opts);
    if !report.seeded.is_empty() {
        log::info!(
            "内置 geo 规则集已播种（{occasion}）：{} 个（其中出厂态刷新 {} 个）→ {}",
            report.seeded.len(),
            report.refreshed.len(),
            runtime_dir.display()
        );
    }
    if !report.still_missing.is_empty() {
        log::warn!(
            "内置 geo 规则集播种后仍缺失（{occasion}）：{}；引用它们的分流规则本次起核会被跳过",
            report.still_missing.join(", ")
        );
    }
}

#[cfg(test)]
mod tests;
