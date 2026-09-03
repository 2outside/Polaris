use std::path::Path;
use std::sync::{Mutex, OnceLock};

use serde_json::{json, Value};
use tauri::{AppHandle, State};

use crate::commands::config::broadcast_config_changed;
use crate::commands::rules::new_uuid;
use crate::events::{broadcast, channel::EVENT_RULE_RESOURCE_PROGRESS};
use crate::response::ApiResponse;
use crate::runtime::config::{Decision, DeferredConfigDeletion};
use crate::runtime::http::{app_user_agent, SystemDnsLookup};
use crate::runtime::subscription_scheduler::now_ms;
use crate::runtime::AppRuntime;
use polaris_config_engine::user_config::builtin_geo_rulesets::{
    builtin_geo_rulesets, builtin_id_for, find_builtin, is_bundled_geo_tag, is_valid_srs_bytes,
    is_valid_srs_file, BuiltinGeoRuleSet, GeoCategory,
};
use polaris_config_engine::user_config::rule::{RuleResource, RuleResourceFormat};
use polaris_config_engine::user_config::rule_resource_catalog::{find_catalog_item, mrd_raw_url};
use polaris_config_engine::user_config::rule_resource_refs::RuleResourceRef;
use polaris_config_engine::user_config::{builtin_catalog_result, enumerate_resource_refs};
use polaris_config_engine::user_config::{
    RefScanInput, RuleResourceCatalogItem, RuleResourceCatalogResult, UserConfig,
};
use polaris_net_stack::safe_redirect::{safe_redirect_fetch, HttpClient, SafeRedirectFetchOptions};
use polaris_net_stack::ssrf::DnsLookup;

const ERR_RESOURCE_BAD_ITEM: &str = "RULE_RESOURCE_BAD_ITEM";
/// 下载失败（网络/SSRF/非 2xx/内容 sanity 不过）。前端据此提示可重试。
const ERR_RESOURCE_DOWNLOAD_FAILED: &str = "RULE_RESOURCE_DOWNLOAD_FAILED";
/// 已下到字节但落盘失败（目录建不了/写盘 IO 错）。
const ERR_RESOURCE_WRITE_FAILED: &str = "RULE_RESOURCE_WRITE_FAILED";
/// redownload 指向的资源不在 config.ruleResources。
const ERR_RESOURCE_NOT_FOUND: &str = "RULE_RESOURCE_NOT_FOUND";
/// 用户在下载途中主动取消（`rule_resources_cancel`）。**不是故障**——前端据此报「已取消」
/// 而非「更新失败」（红行会让用户以为源挂了）。
const ERR_RESOURCE_CANCELLED: &str = "RULE_RESOURCE_CANCELLED";

/// 规则资源单次下载体积硬闸（16 MiB）：sing-box .srs / .json 规则集通常 < 数 MB，超此即拒防 OOM。
const RULE_RESOURCE_MAX_BYTES: usize = 16 * 1024 * 1024;
/// 规则资源下载超时（首字节 + 逐跳，ms）。规则集体积小，30s 足够。
const RULE_RESOURCE_TIMEOUT_MS: u64 = 30_000;

// ── gh-proxy 加速（受限网络下规则资源能不能下下来的分水岭）───────────────────────
//
// 规则资源的默认源是 `raw.githubusercontent.com`（catalog 的 `mrd_raw_url`），在受限网络下**直连必挂**。
// 此前本文件全仓零 `ghProxyPrefix` 引用：设置页那个「GitHub 加速」只有内核下载（`commands/updater.rs`
// → `runtime/http.rs` `CoreDownloader::candidates`）在消费，规则资源下载完全绕过它 —— 用户配了加速，
// 资源页照样一片红。（`runtime/rule_resource_scheduler.rs` 的模块注释甚至自称「下载走直连 / gh-proxy」，
// 与代码相反，同批已改。）

/// 可经 gh 镜像加速的 GitHub 域名表。
///
/// **与 `runtime/http.rs::GITHUB_ASSET_HOSTS` 的关系**：那张 2 域名表是 updater 专用的**release 资产**
/// 判定面（核下载只经 `github.com` / `objects.githubusercontent.com`），本表是 gh-proxy 的通用判定面
/// （5 域，与前端 `ui/src/domain/gh-proxy.ts` `GH_HOSTS` 同表 —— 两侧对「哪些地址值得加速」必须同口径，
/// 否则设置页说加速、后端不加速）。规则资源恰恰只走 `raw.githubusercontent.com`，**不在** updater 那张表里，
/// 所以不能直接复用它。
///
/// DESIGN-REVIEW(gh-proxy-single-source)：审计 §C9 裁决「5 域名表 + applyGhProxy」应落 net-stack 纯函数
/// 模块，由 http.rs 与本文件共同消费（同一待办亦登记在 `runtime/http.rs` 的 `GITHUB_ASSET_HOSTS` 文档上）。net-stack 不在本批改动面内，故本表
/// 暂落此处；模块落地后本表与 `is_github_asset` 一并改为调它。**拼接口径刻意与 `CoreDownloader::candidates`
/// 逐字一致**（`prefix.trim_end_matches('/')` + `/` + 完整原 URL），不另立一套。
const GH_PROXY_HOSTS: [&str; 5] = [
    "raw.githubusercontent.com",
    "github.com",
    "objects.githubusercontent.com",
    "gist.githubusercontent.com",
    "codeload.github.com",
];

/// 套 gh 加速前缀 → 镜像 URL；前缀为空 / 非 GitHub 域 / URL 不可解析 → `None`（= 不加速，原样直连）。
///
/// 返回 `Option` 而非「原样返回」：调用方要据「有没有变」决定失败后是否值得回退直连（同址重试无意义）。
fn apply_gh_proxy(prefix: &str, url: &str) -> Option<String> {
    let prefix = prefix.trim().trim_end_matches('/');
    if prefix.is_empty() {
        return None;
    }
    let host = reqwest::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))?;
    if !GH_PROXY_HOSTS.contains(&host.as_str()) {
        return None;
    }
    Some(format!("{prefix}/{url}"))
}

/// 读用户配置的 gh 加速前缀；未配置 / 读不到 → 空串（= 不加速）。
///
/// 与 `commands/updater::updater_downloader` 同一取值路径（`config.ghProxyPrefix`）—— 同一个设置项必须
/// 只有一个读法，否则「设置页改了、某条下载腿没跟上」这类漂移就无从发现。
fn gh_proxy_prefix(state: &AppRuntime) -> String {
    state
        .config()
        .get_value("ghProxyPrefix")
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// 列表项。上游 `RuleResourceListItem`（`ui/src/shared/types/rules.ts:125`）
/// = `RuleResource` + `fileExists` + `referencedBy` + `builtin?`。
///
/// `#[serde(flatten)]` 复用 `RuleResource` 自己的 rename（sourceUrl/fileName/downloadedAt）——
/// 手抄一遍字段就是又一处会漂移的副本。
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleResourceListItem {
    #[serde(flatten)]
    resource: RuleResource,
    /// **可用性**而非「inode 在不在」：binary(.srs) 走魔数校验，与 `route.rs` 生成配置时的
    /// `is_valid_srs_fn` **同一口径** —— 半写/损坏文件在那边会被跳过，这边就不该显示为「在」，
    /// 否则 UI 说「有」而代理说「没有」。
    file_exists: bool,
    /// 被**已启用**规则引用的条数（route + app 两类，config-engine 实算）。
    referenced_by: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    builtin: Option<bool>,
}

/// 资源文件可用性：binary 校 SRS 魔数（同 route.rs 口径）；source(.json) 仅判存在。
fn resource_file_usable(path: &std::path::Path, format: RuleResourceFormat) -> bool {
    match format {
        RuleResourceFormat::Binary => is_valid_srs_file(path),
        RuleResourceFormat::Source => path.is_file(),
    }
}

/// 上游 `RULE_RESOURCES_LIST`：已下载规则资源清单（**真接线，无网络依赖**）。
///
/// 三个字段都是实算，没有占位：
/// - 表体 = `config.ruleResources`（注：该键此前因漏 `#[serde(rename)]` **恒反序列化为空**，
///   同批已修，见 `config-engine/tests/user_config_key_contract.rs`）；
/// - `fileExists` = 对 `<userData>/rule-resource/<fileName>` 实地 stat + SRS 魔数校验；
/// - `referencedBy` = `enumerate_resource_refs` 实算（route 条件 + app 分流间接引用）。
///
/// **含 `builtin:*` 内置 geo 项**（TS 类型的 `builtin?: boolean` 那一类），排在用户资源之后。
///
/// 这一段曾被整体否决过，理由是「`sourceUrl` 划归运行时层且至今无人提供，列出来就得编值」+
/// 「每行会带一个必然报 `RULE_RESOURCE_NOT_FOUND` 的更新按钮」。两条都已消解：
/// 地址由 tag 推导（[`BuiltinGeoRuleSet::source_url`]，非编造），更新腿是
/// [`rule_resources_update_builtin`]（本批落地）。
///
/// 内置行的三个字段与用户资源取自不同真值源，都不编：
/// - `fileExists` / `size` → **运行时生效目录** `<userData>/rules/<fileName>` 实地 stat + SRS 魔数
///   （不是下载缓存 `rule-resource/`：内置项从不落那儿）；
/// - `downloadedAt` → `config.builtinGeoMeta[tag].updatedAt`，**从未网络更新过就是空串**
///   （出厂态没有「下载时间」这回事，给个假时间比留空更坏）；
/// - `referencedBy` → 与用户资源同一个 `enumerate_resource_refs`，按 `builtin:<tag>` 这个 id 实算。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn rule_resources_list(state: State<'_, AppRuntime>) -> ApiResponse<Vec<RuleResourceListItem>> {
    let cfg = match state.config().current() {
        Ok(c) => c,
        Err(e) => return ApiResponse::err(format!("{e}")),
    };
    let geo_meta = cfg.get("builtinGeoMeta").cloned().unwrap_or(Value::Null);
    let uc: UserConfig = match serde_json::from_value(cfg) {
        Ok(c) => c,
        Err(e) => return ApiResponse::err(format!("config 解析失败: {e}")),
    };
    let res_dir = state.config().dir().join("rule-resource");
    let runtime_dir = builtin_runtime_dir(&state);
    let scan = RefScanInput {
        custom_rules: &uc.custom_rules,
        app_rules: &uc.app_rules,
        custom_app_presets: &uc.custom_app_presets,
    };
    let mut items: Vec<RuleResourceListItem> = uc
        .rule_resources
        .iter()
        .map(|r| RuleResourceListItem {
            file_exists: resource_file_usable(&res_dir.join(&r.file_name), r.format),
            referenced_by: enumerate_resource_refs(&r.id, &scan).len(),
            builtin: None,
            resource: r.clone(),
        })
        .collect();
    items.extend(builtin_geo_rulesets().iter().map(|b| {
        let live = runtime_dir.join(&b.file_name);
        let id = builtin_id_for(&b.tag);
        RuleResourceListItem {
            file_exists: is_valid_srs_file(&live),
            referenced_by: enumerate_resource_refs(&id, &scan).len(),
            builtin: Some(true),
            resource: RuleResource {
                name: b.tag.clone(),
                category: match b.category {
                    GeoCategory::Geosite => "geosite".into(),
                    GeoCategory::Geoip => "geoip".into(),
                },
                source_url: b.source_url(),
                file_name: b.file_name.clone(),
                format: RuleResourceFormat::Binary,
                size: std::fs::metadata(&live).map(|m| m.len()).unwrap_or(0),
                downloaded_at: builtin_updated_at(&geo_meta, &b.tag),
                id,
            },
        }
    }));
    ApiResponse::ok(items)
}

/// 取 `builtinGeoMeta[tag].updatedAt`。缺失/类型不对 → 空串（= 出厂态，从未网络更新）。
fn builtin_updated_at(geo_meta: &Value, tag: &str) -> String {
    geo_meta
        .get(tag)
        .and_then(|v| v.get("updatedAt"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

// ── 资源库清单：远程全量刷新 + 磁盘缓存 ──────────────────────────────────────────
//
// 迁移自 上游 `RuleResourceManager`（`src/main/services/RuleResourceManager.ts`）：
// `fetchCatalogFromGithub`（`:712-753`）/ `getCatalog`（`:632-649`）/ `refreshCatalog`（`:651-671`）。
//
// **清单来源（照搬 上游，未自定）**：GitHub git-trees API 三跳 ——
//   ① `.../git/trees/sing` 取根树，找 `geo` / `geo-lite` 两个子树的 sha（上游 `:713-719`）；
//   ② `.../git/trees/<sha>?recursive=1` 并发各拉一次（上游 `:721-728`）；
//   ③ 收 `type=="blob"` 且相对路径形如 `geosite|geoip/<name>.srs` 的叶子（上游 `:736-749`）。
// **不是**某个上游「索引文件」——meta-rules-dat 没有这种文件，上游 也是这么枚举的。
//
// **派生口径与内置精选表逐字同构**（`config-engine/user_config/rule_resource_catalog.rs`
// `catalog_item()`）：id = `<category>-<name>`、path = `<geo|geo-lite>/<kind>/<name>.srs`。同构是硬要求
// 而非巧合 —— 同一条目在「内置」与「远程」两态下若算出两个 id/path，下载 URL 与落盘名就会分叉，
// 「已下载」判重（前端按 id 比对）也会失灵。`tree_path_matches_builtin_derivation` 把这条钉死。
//
// **失败语义**：上游的 `refreshCatalog` 抛错让 UI toast；Polaris 保留本 command 既有的「诚实降级」
// 契约（不 err），改为按同一梯子回落 —— 远程 → 缓存 → 内置，`source` 逐态如实自述。落到内置时与改动前
// 逐字一致（`source:"builtin"` + `fetchedAt:null`）。用户可见结果与 上游 等价：上游 抛错后 UI 继续
// 显示 `getCatalog()` 已加载的那份（即缓存），Polaris 直接把那份返回。

/// meta-rules-dat git-trees API 基址（= 上游 `:714/:723/:726` 同一串）。
const MRD_TREE_API_BASE: &str = "https://api.github.com/repos/MetaCubeX/meta-rules-dat/git/trees/";
/// 根树 ref（`sing` 分支）。
const MRD_CATALOG_REF: &str = "sing";
/// 清单 JSON 单次拉取超时（ms）。= 上游 `fetchJson` 的 20s。
const CATALOG_TIMEOUT_MS: u64 = 20_000;
/// 清单 JSON 体积上限（16 MiB）。= 上游 `MAX_GITHUB_JSON_BYTES`：两个 `?recursive=1` 并发各持一份，
/// 被劫持/WAF 回灌 GB 级 JSON 会直接 OOM，实际 tree 只有数 MB。
const CATALOG_MAX_BYTES: usize = 16 * 1024 * 1024;
/// 清单最小条目数（= 上游 `if (items.length < 50) throw new Error('catalog too small')`）。
/// 远端结构变了（目录改名 / 返回错误页）会让 collect 收到寥寥几条，此闸挡住「用半份清单覆盖好缓存」。
const CATALOG_MIN_ITEMS: usize = 50;
/// 磁盘缓存文件名（= 上游 `catalogCachePath()` 的 `catalog.json`），落在 `<userData>/rule-resource/`。
const CATALOG_CACHE_FILE: &str = "catalog.json";
/// 缓存 schema 版本（= 上游 `schemaVersion: 1`）。对不上 → 整份作废，不做迁移。
const CATALOG_CACHE_SCHEMA_VERSION: u64 = 1;

/// 单条 git-trees JSON 拉取（复用订阅同款 [`safe_redirect_fetch`]：逐跳 SSRF guard、体积闸、超时、
/// 手动重定向）。403/429 单独成句：GitHub 未鉴权限流 60 次/小时，是本功能最常见的失败因，与「网络
/// 不通」混成一条会让排障方向全错（= 上游 `fetchJson` 对 403/429 的特判）。
async fn fetch_catalog_json_once<H: HttpClient, L: DnsLookup>(
    client: &H,
    lookup: &L,
    url: &str,
) -> Result<Value, String> {
    let resp = safe_redirect_fetch(SafeRedirectFetchOptions {
        fetch_impl: client,
        url,
        user_agent: app_user_agent(),
        // GitHub 推荐的 API 版本头（= 上游 `req.setHeader('Accept', 'application/vnd.github+json')`）。
        headers: Some(vec![(
            "Accept".to_string(),
            "application/vnd.github+json".to_string(),
        )]),
        exempt_fake_ip: false,
        max_redirects: None,
        timeout_ms: Some(CATALOG_TIMEOUT_MS),
        max_body_bytes: Some(CATALOG_MAX_BYTES),
        lookup,
    })
    .await
    .map_err(|e| e.message)?;
    if matches!(resp.status, 403 | 429) {
        return Err(format!("GitHub 限流（HTTP {}），请稍后再试", resp.status));
    }
    if !(200..300).contains(&resp.status) {
        return Err(format!("清单拉取失败：HTTP {}", resp.status));
    }
    let v: Value =
        serde_json::from_slice(&resp.body).map_err(|e| format!("清单 JSON 非法: {e}"))?;
    // **结构闸**：三跳全是 git-trees API，响应必含 `tree` 数组。缺它 = 这不是一份 trees 响应
    // （gh-proxy 类镜像返 `{"code":403,"msg":"..."}`、WAF 挑战页的 JSON 变体、被换成别的 API 响应…）。
    //
    // 少了这道闸不是「多一次解析失败」而是**回退腿失效**：[`fetch_catalog_json`] 只在镜像腿返
    // `Err` 时才改打原址，镜像返「200 + 合法 JSON + 不是 tree」会被当成成功、直接把这份垃圾交上去 →
    // `tree_child_sha` 找不到 geo → 整次刷新失败 → 落到缓存/内置，而**原址压根没被试过**。
    if v.get("tree").and_then(Value::as_array).is_none() {
        return Err("清单响应不是 git-trees 结构（缺 `tree` 数组）".to_string());
    }
    Ok(v)
}

/// 带 gh 加速的清单拉取：**复用下载腿那一套**（[`apply_gh_proxy`] + 失败回退原址），不另立一份判定。
///
/// 现状诚实登记：`GH_PROXY_HOSTS` 是 5 域表、**不含 `api.github.com`**，故对本函数实际请求的 trees API
/// 地址而言这是一次**文档化的空转**（`ui/src/domain/gh-proxy.ts:56` 与 上游 `shared/gh-proxy.ts:58`
/// 都明写「api.github.com 不在 GH_HOSTS，Trees API 刷新不走加速」——gh-proxy 类镜像普遍只代理
/// raw/releases/archive，不代理 API）。仍然走这条腿而不是直接裸调，是为了**只有一个加速决策点**：
/// 哪天那张表补上 `api.github.com`（前后端两侧同步改），清单刷新自动吃上，不需要再改本文件。
async fn fetch_catalog_json<H: HttpClient, L: DnsLookup>(
    client: &H,
    lookup: &L,
    url: &str,
    gh_prefix: &str,
) -> Result<Value, String> {
    if let Some(mirrored) = apply_gh_proxy(gh_prefix, url) {
        match fetch_catalog_json_once(client, lookup, &mirrored).await {
            Ok(v) => return Ok(v),
            // **必须留痕**：镜像腿失败后静默回退直连，用户配的「GitHub 加速」就成了形同虚设的开关
            // ——尤其是自建**内网** gh-proxy（`192.168.x` / `10.x`）会被 `safe_redirect_fetch` 的
            // SSRF guard **恒拒**（放行内网 host 会开出 SSRF 面，故刻意不放行），于是加速腿每次都挂、
            // 每次都静默回退，设置页却一句提示都没有。至少让日志能回答「我配的加速到底走没走」。
            Err(e) => log::warn!("gh 加速腿失败，回退原址（清单）: {mirrored} → {e}"),
        }
    }
    fetch_catalog_json_once(client, lookup, url).await
}

/// git object sha 合法性：**恰好** 40（sha1）或 64（sha256）位 hex。
///
/// **不是洁癖**：这个值来自远端 JSON 且**直接拼进下一跳 URL 的路径段**。不校验则 `"../../../x"` 之类
/// 能把请求带去同域的任意 API 路径（`safe_redirect_fetch` 只管 SSRF/重定向，管不了路径语义）。
///
/// 长度收敛为「两个合法值」而非区间 `40..=64`：git 的 object id 只有这两种长度，中间那 23 种长度
/// 全是「不可能是 sha 的东西」（缩写 ref、被截断的串、构造出来的探测值）。放行它们没有任何合法用例，
/// 只是白白留出 23 种可拼进 URL 的形态。
fn is_valid_tree_sha(sha: &str) -> bool {
    matches!(sha.len(), 40 | 64) && sha.bytes().all(|b| b.is_ascii_hexdigit())
}

/// 从根树 JSON 取指定子目录的 sha（= 上游 `tree.find((t) => t.path === 'geo')?.sha`），sha 非法 → None。
fn tree_child_sha(root: &Value, name: &str) -> Option<String> {
    let sha = root
        .get("tree")?
        .as_array()?
        .iter()
        .find(|n| n.get("path").and_then(Value::as_str) == Some(name))?
        .get("sha")?
        .as_str()?;
    is_valid_tree_sha(sha).then(|| sha.to_string())
}

/// `(base, 子树内相对路径)` → catalog 条目；不合规 → `None`。**catalog 条目的唯一构造口径**
/// （远程 collect 与缓存回读共用它 → 两条路径不可能派生出不同的 id/path）。
///
/// 与内置表 `catalog_item()` 同构：`category` = `geosite|geoip` 或加 `-lite`，`id` = `<category>-<name>`，
/// `path` = `<base>/<kind>/<name>.srs`。
///
/// 拒收面（每条都有其对应故障）：
/// - 非 `.srs` / 非 `geosite|geoip` 前缀 → 不是规则集叶子；
/// - `name` 含 `/`（嵌套子目录）→ 落盘名会被当成子目录路径 → `ENOENT`（上游 `:742` 同款跳过）；
/// - `name` 以 `.` 开头（`.` / `..`）或含控制字符 / `? # \ %` → 拼进下载 URL 后会改变路径语义或被
///   百分号解码，属远端可控输入的注入面。
fn catalog_item_from_tree_path(base: &str, rel: &str) -> Option<RuleResourceCatalogItem> {
    if base != "geo" && base != "geo-lite" {
        return None;
    }
    let stem = rel.strip_suffix(".srs")?;
    let (kind, name) = stem.split_once('/')?;
    if !matches!(kind, "geosite" | "geoip") {
        return None;
    }
    if name.is_empty() || name.contains('/') || name.starts_with('.') {
        return None;
    }
    if name.contains(|c: char| c.is_control() || matches!(c, '?' | '#' | '\\' | '%')) {
        return None;
    }
    let category = if base == "geo-lite" {
        format!("{kind}-lite")
    } else {
        kind.to_string()
    };
    let id = format!("{category}-{name}");
    Some(RuleResourceCatalogItem {
        // 随包判定与内置精选表同一口径（`catalog_item()` 也是这句）：远程全量里若出现随包同名项，
        // 外置 tab 也该显示「已内置」，否则同一条资源在两个 tab 里说法不一。
        bundled: is_bundled_geo_tag(&id),
        id,
        category,
        name: name.to_string(),
        path: format!("{base}/{rel}"),
    })
}

/// 从一棵 `?recursive=1` 子树 JSON 收条目（= 上游 `collect`）。整棵树结构不对 → 收 0 条（由
/// [`CATALOG_MIN_ITEMS`] 闸兜住），不 panic。
fn collect_catalog_items(tree: &Value, base: &str, out: &mut Vec<RuleResourceCatalogItem>) {
    let Some(nodes) = tree.get("tree").and_then(Value::as_array) else {
        return;
    };
    for node in nodes {
        if node.get("type").and_then(Value::as_str) != Some("blob") {
            continue;
        }
        let Some(rel) = node.get("path").and_then(Value::as_str) else {
            continue;
        };
        if let Some(item) = catalog_item_from_tree_path(base, rel) {
            out.push(item);
        }
    }
}

/// 拉远程全量清单（= 上游 `fetchCatalogFromGithub` + `refreshCatalog` 的 `< 50` 闸）。
async fn fetch_catalog_from_github<H: HttpClient, L: DnsLookup>(
    client: &H,
    lookup: &L,
    gh_prefix: &str,
) -> Result<Vec<RuleResourceCatalogItem>, String> {
    let root_url = format!("{MRD_TREE_API_BASE}{MRD_CATALOG_REF}");
    let root = fetch_catalog_json(client, lookup, &root_url, gh_prefix).await?;
    let geo_sha =
        tree_child_sha(&root, "geo").ok_or_else(|| "根树缺 geo 子树或 sha 非法".to_string())?;
    let lite_sha = tree_child_sha(&root, "geo-lite")
        .ok_or_else(|| "根树缺 geo-lite 子树或 sha 非法".to_string())?;

    let geo_url = format!("{MRD_TREE_API_BASE}{geo_sha}?recursive=1");
    let lite_url = format!("{MRD_TREE_API_BASE}{lite_sha}?recursive=1");
    let (geo, lite) = tokio::join!(
        fetch_catalog_json(client, lookup, &geo_url, gh_prefix),
        fetch_catalog_json(client, lookup, &lite_url, gh_prefix),
    );
    let (geo, lite) = (geo?, lite?);
    // GitHub 对超大树会截断并置 `truncated:true`——半份清单当全量用会让本地清单凭空少掉一批条目，
    // 且会覆盖掉上一份完整缓存。宁可本次失败（= 上游 `throw new Error('tree truncated')`）。
    if geo.get("truncated").and_then(Value::as_bool) == Some(true)
        || lite.get("truncated").and_then(Value::as_bool) == Some(true)
    {
        return Err("清单被 GitHub 截断（truncated），本次不采信".to_string());
    }

    let mut items = Vec::new();
    collect_catalog_items(&geo, "geo", &mut items);
    collect_catalog_items(&lite, "geo-lite", &mut items);
    // id 去重（保留首现）：远端同名 blob 重复出现会让下载计划歧义（同 id 两个 path）。
    let mut seen = std::collections::HashSet::new();
    items.retain(|i| seen.insert(i.id.clone()));
    if items.len() < CATALOG_MIN_ITEMS {
        return Err(format!(
            "清单条目过少（{} < {CATALOG_MIN_ITEMS}），疑似上游结构变化",
            items.len()
        ));
    }
    Ok(items)
}

/// 缓存文件路径。
fn catalog_cache_path(res_dir: &Path) -> std::path::PathBuf {
    res_dir.join(CATALOG_CACHE_FILE)
}

/// 回读缓存条目并**验自洽**：`id`/`category`/`name` 必须与 `path` 按 [`catalog_item_from_tree_path`]
/// 派生结果逐字相等。手改 / 半写 / 旧格式的条目一律判废 —— 否则一条 `{"id":"x","path":"../../y"}`
/// 就能借缓存绕过远程 collect 的全部拒收面。
///
/// 返回的是**派生结果本身**而非缓存里的那份，故 `bundled` 恒按当前版本的随包表现算：升级后随包
/// 清单变了，旧缓存里那个 `bundled` 不会把过期结论带进 UI（缓存里的该字段读都不读）。
fn parse_cached_catalog_item(v: &Value) -> Option<RuleResourceCatalogItem> {
    let path = v.get("path").and_then(Value::as_str)?;
    let (base, rel) = path.split_once('/')?;
    let derived = catalog_item_from_tree_path(base, rel)?;
    (v.get("id").and_then(Value::as_str) == Some(derived.id.as_str())
        && v.get("category").and_then(Value::as_str) == Some(derived.category.as_str())
        && v.get("name").and_then(Value::as_str) == Some(derived.name.as_str()))
    .then_some(derived)
}

/// 读磁盘缓存 → `(items, fetchedAt)`；**任一环不过即整份作废**（返 None → 上层回落内置）。
///
/// 校验链（= 上游 `getCatalog` 的 `schemaVersion === 1 && Array.isArray(items) && length >= 50`
/// 再加逐条自洽）：文件可读 → JSON 合法 → schemaVersion 对上 → fetchedAt 为正整数 → items 是数组
/// → 每条自洽 → 条数够。**畸形不污染**：读不出来只是少一层兜底，绝不把半份清单当真。
fn read_catalog_cache(res_dir: &Path) -> Option<(Vec<RuleResourceCatalogItem>, i64)> {
    let raw = std::fs::read(catalog_cache_path(res_dir)).ok()?;
    let v: Value = serde_json::from_slice(&raw).ok()?;
    if v.get("schemaVersion").and_then(Value::as_u64) != Some(CATALOG_CACHE_SCHEMA_VERSION) {
        return None;
    }
    let fetched_at = v
        .get("fetchedAt")
        .and_then(Value::as_i64)
        .filter(|t| *t > 0)?;
    let arr = v.get("items")?.as_array()?;
    let mut items = Vec::with_capacity(arr.len());
    for entry in arr {
        items.push(parse_cached_catalog_item(entry)?);
    }
    (items.len() >= CATALOG_MIN_ITEMS).then_some((items, fetched_at))
}

/// 原子写缓存（唯一后缀 tmp → rename）。
///
/// 唯一后缀（pid + 单调序）而非固定名：本 command 无 inflight 保护、IPC 层无去抖，多窗口/后台调度腿
/// 可并发写同一目录；固定名 tmp 会字节交错（= 上游 `writeFileAtomic` 同款理由，`:657-659`）。
fn write_catalog_cache(
    res_dir: &Path,
    fetched_at: i64,
    items: &[RuleResourceCatalogItem],
) -> Result<(), String> {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    std::fs::create_dir_all(res_dir).map_err(|e| format!("建目录失败: {e}"))?;
    let body = serde_json::to_vec(&json!({
        "schemaVersion": CATALOG_CACHE_SCHEMA_VERSION,
        "fetchedAt": fetched_at,
        "items": items,
    }))
    .map_err(|e| format!("序列化失败: {e}"))?;
    let tmp = res_dir.join(format!(
        "{CATALOG_CACHE_FILE}.{}.{}.tmp",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::write(&tmp, &body).map_err(|e| format!("写入失败: {e}"))?;
    std::fs::rename(&tmp, catalog_cache_path(res_dir)).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("提交失败: {e}")
    })
}

/// 盘上缓存 → `source:"cache"` 结果；没有可用缓存 → `None`（**不回落内置**，见
/// [`rule_resources_get_cached_catalog`] 里为何这个区别是必要的）。
fn cached_catalog(res_dir: &Path) -> Option<RuleResourceCatalogResult> {
    read_catalog_cache(res_dir).map(|(items, fetched_at)| RuleResourceCatalogResult {
        items,
        fetched_at: Some(fetched_at),
        source: "cache".to_string(),
    })
}

/// 无远程时的诚实回落梯子：缓存（`source:"cache"` + 真 `fetchedAt`）→ 内置
/// （`source:"builtin"` + `fetchedAt:null`）。**任何一态都不谎报**。
fn cached_or_builtin_catalog(res_dir: &Path) -> RuleResourceCatalogResult {
    cached_catalog(res_dir).unwrap_or_else(builtin_catalog_result)
}

/// 刷新的**可测核**（command 是它的薄壳）：远程成功 → 落缓存 + `source:"remote"`；远程失败 → 回落
/// [`cached_or_builtin_catalog`]。抽出来不是为了好看 —— command 带 `State<AppRuntime>`，本仓未引
/// `tauri::test`，不抽就没有任何一条断言能证明「远程腿真的跑了」（那正是本功能此前恒等降级的成因）。
async fn refresh_catalog_core<H: HttpClient, L: DnsLookup>(
    client: &H,
    lookup: &L,
    res_dir: &Path,
    gh_prefix: &str,
) -> RuleResourceCatalogResult {
    match fetch_catalog_from_github(client, lookup, gh_prefix).await {
        Ok(items) => {
            let fetched_at = i64::try_from(now_ms()).unwrap_or(i64::MAX);
            // 缓存写失败不改本次结果（全量已在手），只是下次少一层兜底 —— 不该让「盘满」把一次成功
            // 的刷新打成失败。
            let _ = write_catalog_cache(res_dir, fetched_at, &items);
            RuleResourceCatalogResult {
                items,
                fetched_at: Some(fetched_at),
                source: "remote".to_string(),
            }
        }
        // 失败原因不进 DTO（契约里没有 error 字段），但**结果如实标 source**，前端据此提示。
        Err(_) => cached_or_builtin_catalog(res_dir),
    }
}

/// 上游 `RULE_RESOURCES_GET_CATALOG`：资源库目录（**真接线**，Rust SoT 内置精选表）。
///
/// 前端曾持有同一张表（`RULE_RESOURCE_CATALOG`），已删 → 此处是唯一真值。
/// `source:"builtin"` + `fetchedAt:null` 如实自述「这是离线内置清单，不是远端全量」。
///
/// **刻意不读远程缓存**（与 上游 `getCatalog` 的差异，非遗漏）：Polaris 的资源库弹窗用本 command
/// 驱动「内置」tab（= 随包表的投影，28 条），上游 那边「内置」tab 另有数据源（随包 geo `builtinItems` prop），
/// `getCatalog` 只喂它的「外置」tab。若照抄让本 command 返回缓存，Polaris 的「内置」tab 会变成
/// 2000+ 条远程全量 —— tab 语义当场崩掉。远程/缓存两态由
/// [`rule_resources_refresh_catalog`] 单独承担（外置 tab）。
#[tauri::command]
pub fn rule_resources_get_catalog() -> ApiResponse<RuleResourceCatalogResult> {
    ApiResponse::ok(builtin_catalog_result())
}

/// 上游 `RULE_RESOURCES_REFRESH_CATALOG`：刷新资源库目录 —— **真拉 meta-rules-dat 全量清单**。
///
/// 三跳 git-trees API（见本节头注）→ 收 `.srs` 叶子 → `<50` 条闸 → 原子落缓存 → `source:"remote"`。
/// 远程失败按梯子回落：缓存（`source:"cache"`）→ 内置（`source:"builtin"` + `fetchedAt:null`）。
///
/// 刻意**不 err**（与 redownload/updateAll 不同）：本 command 的契约允许「回退到已有清单」这个成功
/// 语义，前端据 `source` 提示来源即可；而 redownload 没有等价的降级语义 —— 它要么下到文件要么没下到。
/// **回落不是伪造**：三个 `source` 值各自对应一份真实存在的清单，没有任何一态谎称「拉到了远端」。
#[tauri::command]
pub async fn rule_resources_refresh_catalog(
    state: State<'_, AppRuntime>,
) -> Result<ApiResponse<RuleResourceCatalogResult>, ()> {
    let res_dir = state.config().dir().join("rule-resource");
    let http = state.http().clone();
    let gh_prefix = gh_proxy_prefix(&state);
    Ok(ApiResponse::ok(
        refresh_catalog_core(http.as_ref(), &SystemDnsLookup, &res_dir, &gh_prefix).await,
    ))
}

/// 只读盘上清单缓存（**零出站**），没有缓存返 `null`。
///
/// 补的是「缓存写了却没人读」这个缺口：[`rule_resources_refresh_catalog`] 从一开始就把全量清单
/// 原子落盘了，但它只在**远程失败时**回读，于是外置 tab 每次打开都是空的、非点「刷新清单」不可
/// —— 缓存明明在盘上，用户仍要为每次打开付一次三跳 git-trees 往返（真机反馈「刷新清单后应该要有
/// 缓存，而不是每次都需要手动刷新」）。本 command 让 UI 打开即回读那份缓存，刷新退回成显式动作。
///
/// **不复用另外两个 command 的理由**（不是没试）：
/// - [`rule_resources_get_catalog`] 刻意不读缓存 —— 它驱动「内置」tab（随包表投影，28 条），让它返回
///   2000+ 条全量会当场毁掉 tab 语义（该函数注释已记）；
/// - [`rule_resources_refresh_catalog`] 必然先打网络，正是要避免的那次往返。
///
/// **无缓存返 `null` 而非回落内置**：`cached_or_builtin_catalog` 的 `builtin` 那一档语义是「远程
/// 拉过且失败了」，前端据此显示「远程获取失败 · 回落内置精选清单」。本 command 一次网都没打，
/// 借那条路会让 UI 报一个**没发生过的失败**。没有就是没有，由前端继续显示「点击刷新清单」。
///
/// 参数只有 `res_dir`（由 state 推出），签名里没有任何 HTTP client —— 「本 command 不出站」是
/// 结构性的，不靠自觉。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn rule_resources_get_cached_catalog(
    state: State<'_, AppRuntime>,
) -> ApiResponse<Option<RuleResourceCatalogResult>> {
    let res_dir = state.config().dir().join("rule-resource");
    ApiResponse::ok(cached_catalog(&res_dir))
}

/// 上游 `RULE_RESOURCES_REDOWNLOAD`：按 id 重新下载已登记资源（**真下载**）。
///
/// 从 `config.ruleResources` 取该资源的 `sourceUrl`/`format`/`fileName`（保留原 id，覆盖写盘），
/// 返回单个 `RuleResourceDownloadResult`（前端契约 `redownload(id): Promise<RuleResourceDownloadResult>`）。
/// 资源不在册 → `ok:false` + `RULE_RESOURCE_NOT_FOUND`（业务态在 data，信封仍 success）。
#[tauri::command]
pub async fn rule_resources_redownload(
    app: AppHandle,
    state: State<'_, AppRuntime>,
    id: String,
) -> Result<ApiResponse<Value>, ()> {
    redownload_with_mode(
        &app,
        &state,
        id,
        ProgressMode::Live,
        BroadcastMode::Immediate,
    )
    .await
}

/// 后台调度腿专用入口：与 [`rule_resources_redownload`] 同一条下载/落盘/入册路径，两处差别是
/// **一帧进度都不发**（`ProgressMode::Silent`）+ **不逐条广播**（`BroadcastMode::Deferred`，
/// 由批次拥有者 `RuleResourceScheduler::run_due_updates` 收尾统一广播一次）。
///
/// 为什么另开一个函数而不是给命令加个 `silent: bool` 形参：`#[tauri::command]` 的形参会成为
/// 前端可传的参数袋键——渲染端就能把自己的手动更新也调成静默（或反之），静默语义不再由后端说了算。
/// 独立函数 + 内部写死这两个模式，使「后台腿推事件」「后台腿逐条重启核」在类型层面不可表达。
pub async fn rule_resources_redownload_silent(
    app: &AppHandle,
    state: &AppRuntime,
    id: String,
) -> Result<ApiResponse<Value>, ()> {
    redownload_with_mode(
        app,
        state,
        id,
        ProgressMode::Silent,
        BroadcastMode::Deferred,
    )
    .await
}

/// redownload 的共用核心（手动腿 / 后台腿只差 [`ProgressMode`] + [`BroadcastMode`]）。
async fn redownload_with_mode(
    app: &AppHandle,
    state: &AppRuntime,
    id: String,
    mode: ProgressMode,
    broadcast: BroadcastMode,
) -> Result<ApiResponse<Value>, ()> {
    let cfg = match state.config().current() {
        Ok(c) => c,
        Err(e) => return Ok(ApiResponse::err(format!("{e}"))),
    };
    // 先按 id 找原始项再反序列化：不在册 → NOT_FOUND；在册但 malformed → BAD_ITEM（P8：不再误报 NOT_FOUND）。
    let empty = Vec::new();
    let resources = cfg
        .get("ruleResources")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let existing = match resolve_registered_resource(resources, &id) {
        Ok(r) => r,
        Err(err_value) => return Ok(ApiResponse::ok(err_value)),
    };
    let plan = plan_from_resource(&existing).with_gh_proxy(&gh_proxy_prefix(state));
    let res_dir = state.config().dir().join("rule-resource");
    let http = state.http().clone();
    let sink = BroadcastSink { app, mode };
    let result =
        download_with_progress(&sink, http.as_ref(), &SystemDnsLookup, &plan, &res_dir).await;
    if let DownloadOutcome::Stored { ref resource, .. } = result {
        persist_resources(app, state, std::slice::from_ref(resource), broadcast);
    }
    Ok(ApiResponse::ok(result.into_value(&plan)))
}

/// 上游 `RULE_RESOURCES_UPDATE_ALL`：更新全部已登记资源（**真下载**）。
///
/// 逐个 redownload `config.ruleResources` 里的每一项，返回 `RuleResourceDownloadResult[]`（数组，
/// 对齐前端 `.map()` 契约）。逐 item 独立容错；成功项一次性 upsert + 保存 + 广播。
#[tauri::command]
pub async fn rule_resources_update_all(
    app: AppHandle,
    state: State<'_, AppRuntime>,
) -> Result<ApiResponse<Vec<Value>>, ()> {
    let cfg = match state.config().current() {
        Ok(c) => c,
        Err(e) => return Ok(ApiResponse::err(format!("{e}"))),
    };
    let raw_entries: Vec<Value> = cfg
        .get("ruleResources")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let res_dir = state.config().dir().join("rule-resource");
    let http = state.http().clone();
    let gh_prefix = gh_proxy_prefix(&state);

    let mut results: Vec<Value> = Vec::with_capacity(raw_entries.len());
    let mut stored: Vec<RuleResource> = Vec::new();
    for entry in &raw_entries {
        // 结构非法的条目**如实报失败**（P8）——旧实现 `filter_map(.ok())` 静默丢弃：既不更新也不出现在结果里。
        let existing = match parse_resource_entry(entry) {
            Ok(r) => r,
            Err(err_value) => {
                results.push(err_value);
                continue;
            }
        };
        let plan = plan_from_resource(&existing).with_gh_proxy(&gh_prefix);
        let sink = BroadcastSink {
            app: &app,
            mode: ProgressMode::Live,
        };
        let outcome =
            download_with_progress(&sink, http.as_ref(), &SystemDnsLookup, &plan, &res_dir).await;
        if let DownloadOutcome::Stored { ref resource, .. } = outcome {
            stored.push(resource.clone());
        }
        results.push(outcome.into_value(&plan));
    }
    if !stored.is_empty() {
        persist_resources(&app, &state, &stored, BroadcastMode::Immediate);
    }
    Ok(ApiResponse::ok(results))
}

// ── 在线图标库（icon_galleries）── 迁移自 上游 `RuleResourceManager.fetchIconGalleries` ──
//
// 并发拉三个公开图库源（Qure + homarr + edc），各三镜像（jsdelivr → fastly → github raw）逐个回退，合并图标。

#[tauri::command]
pub async fn rule_resources_download(
    app: AppHandle,
    state: State<'_, AppRuntime>,
    items: Vec<Value>,
) -> Result<ApiResponse<Vec<Value>>, ()> {
    let res_dir = state.config().dir().join("rule-resource");
    let http = state.http().clone();
    let gh_prefix = gh_proxy_prefix(&state);
    // 「刷新清单」落盘的远程全量：外置 tab 勾选的多数条目**不在**内置 33 条精选里，不带上它
    // 逐项都会 `资源库无此条目`（见 [`resolve_catalog_item`]）。无缓存 → 空切片，行为不变。
    let refreshed_catalog = read_catalog_cache(&res_dir).map_or_else(Vec::new, |(items, _)| items);

    let mut results: Vec<Value> = Vec::with_capacity(items.len());
    let mut stored: Vec<RuleResource> = Vec::new();
    for item in &items {
        let plan = match plan_from_item(item, &refreshed_catalog) {
            Ok(p) => p.with_gh_proxy(&gh_prefix),
            Err(e) => {
                results.push(err_result(
                    item.get("id").and_then(Value::as_str),
                    item.get("name").and_then(Value::as_str),
                    &e,
                    ERR_RESOURCE_BAD_ITEM,
                ));
                continue;
            }
        };
        let sink = BroadcastSink {
            app: &app,
            mode: ProgressMode::Live,
        };
        let outcome =
            download_with_progress(&sink, http.as_ref(), &SystemDnsLookup, &plan, &res_dir).await;
        if let DownloadOutcome::Stored { ref resource, .. } = outcome {
            stored.push(resource.clone());
        }
        results.push(outcome.into_value(&plan));
    }
    if !stored.is_empty() {
        persist_resources(&app, &state, &stored, BroadcastMode::Immediate);
    }
    Ok(ApiResponse::ok(results))
}

/// 资源删除计划（纯决策，与 IO 分离便于单测）。上游 `RuleResourceDeleteResult` 的判定核心。
#[derive(Debug)]
enum ResourceDeletePlan {
    /// 不在册 → 幂等成功（删除意图已达成）。
    NotFound,
    /// 被**已启用**规则引用且未 `force` → 需二次确认（不删）。
    NeedConfirm(Vec<RuleResourceRef>),
    /// 可删（无引用或已 force）。缓存文件删除意图由配置事务对 old/new `ruleResources`
    /// 自动求差并写入持久 journal，不在本计划里重复携带。
    Proceed,
}

/// 纯决策：按 id 定位资源 + 引用检查 → 删除计划。不触 IO（config 传入 Value）。
fn plan_resource_delete(cfg: &Value, id: &str, force: bool) -> ResourceDeletePlan {
    let exists = cfg
        .get("ruleResources")
        .and_then(Value::as_array)
        .is_some_and(|arr| {
            arr.iter()
                .any(|v| v.get("id").and_then(Value::as_str) == Some(id))
        });
    if !exists {
        return ResourceDeletePlan::NotFound;
    }
    // 引用扫描：结构非法的 config 回落空配置 → 视作无引用（删除放行，不因扫描失败卡住删除）。
    let uc: UserConfig = serde_json::from_value(cfg.clone()).unwrap_or_default();
    let scan = RefScanInput {
        custom_rules: &uc.custom_rules,
        app_rules: &uc.app_rules,
        custom_app_presets: &uc.custom_app_presets,
    };
    let refs = enumerate_resource_refs(id, &scan);
    if !refs.is_empty() && !force {
        return ResourceDeletePlan::NeedConfirm(refs);
    }
    ResourceDeletePlan::Proceed
}

/// 上游 `RULE_RESOURCES_DELETE`：删除规则资源（config 条目 + 缓存文件）。
///
/// 被已启用规则引用且未 `force` → `{ok:false, needConfirm:true, referencingRules}`（前端二次确认）。
/// 否则删 `config.ruleResources` 条目 + 解绑 `<userData>/rule-resource/<sanitized fileName>`
/// （复用 download 的 dir + sanitize 口径，防篡改 fileName 穿越）→ 持久化 + 广播。不在册 → 幂等成功。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn rule_resources_delete(
    app: AppHandle,
    state: State<'_, AppRuntime>,
    id: String,
    force: Option<bool>,
) -> ApiResponse<Value> {
    let force = force.unwrap_or(false);
    let result = state.config().update_deferred_cleanup(|cfg| {
        let plan = plan_resource_delete(cfg, &id, force);
        if !matches!(plan, ResourceDeletePlan::Proceed) {
            return Decision::Skip(plan);
        }
        if let Some(arr) = cfg.get_mut("ruleResources").and_then(Value::as_array_mut) {
            arr.retain(|v| v.get("id").and_then(Value::as_str) != Some(id.as_str()));
        }
        Decision::Write(plan)
    });
    match result {
        Ok((ResourceDeletePlan::NotFound, None)) => ApiResponse::ok(json!({ "ok": true })),
        Ok((ResourceDeletePlan::NeedConfirm(refs), None)) => ApiResponse::ok(json!({
            "ok": false,
            "needConfirm": true,
            "referencingRules": serde_json::to_value(&refs).unwrap_or_else(|_| json!([])),
        })),
        Ok((ResourceDeletePlan::Proceed, Some(cfg))) => {
            // 文件一律由持久 journal 在 Apply / Stop / 冷启动安全点清理；停止态广播会立刻走 NotRunning
            // 消费。命令层不再按一份可能在同刻变化的 running 快照决定是否提前 unlink。
            broadcast_config_changed(&app, &cfg);
            ApiResponse::ok(json!({ "ok": true }))
        }
        Ok(_) => unreachable!("rule resource deletion decision and persistence must agree"),
        Err(e) => ApiResponse::err(format!("{e}")),
    }
}

/// 上游 `RULE_RESOURCES_RESET_BUILTIN`：重置内置 geo 规则集为出厂版（factory 重置）。
///
/// `tag` 为分类入口（`geosite`/`geoip`；其他值 → 两类全重置）。**无网络**：
/// 1. 物理删除该类内置 geo 的下载缓存 `.srs`（`<userData>/rule-resource/<fileName>`，sanitize 与 download 同口径）；
/// 2. 物理删除**生效中的运行时副本**（`<userData>/rules/<fileName>`）→ 下次 seed（启动 / 起核前）
///    按「缺失必种」从随包资源重种出厂版；
/// 3. 清 `config.builtinGeoMeta`（网络更新标记）→ 该 tag 恢复「出厂态」，重新纳入启动时的出厂态刷新射程。
///
/// **为什么第 2 步不能省**（此前就省了，于是这条 command 名不副实）：seed 是
/// **seed-if-missing-or-invalid**，运行时副本只要还有效就恒被跳过。只清 config 标记而留着那份副本，
/// 「重置为出厂版」对**生效中的那一份完全无作用** —— 用户点了重置，下次起核用的还是同一个文件。
///
/// 只碰内置 geo（`builtin_geo_rulesets()` 表内），**不删用户自建/下载的 `config.ruleResources`**。
/// 持久化 + 广播。返回前端 `RuleResourceDownloadResult` 的 `ok` 形态。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn rule_resources_reset_builtin(
    app: AppHandle,
    state: State<'_, AppRuntime>,
    tag: String,
) -> ApiResponse<Value> {
    let category = match tag.as_str() {
        "geosite" => Some(GeoCategory::Geosite),
        "geoip" => Some(GeoCategory::Geoip),
        _ => None, // 具体 tag / 未知 → 两类全重置。
    };
    let selected: Vec<_> = builtin_geo_rulesets()
        .into_iter()
        .filter(|builtin| category.is_none() || category == Some(builtin.category))
        .collect();
    let deletions = selected
        .iter()
        .map(|builtin| DeferredConfigDeletion::BuiltinRuleResource {
            tag: builtin.tag.clone(),
            file_name: builtin.file_name.clone(),
        })
        .collect();
    match state
        .config()
        .update_with_explicit_deletions(deletions, |cfg| {
            // 只清本次所选 tag 的网络更新标记；geosite 重置不得顺手把 geoip 也标成出厂态。
            if let Some(metadata) = cfg.get_mut("builtinGeoMeta").and_then(Value::as_object_mut) {
                for builtin in &selected {
                    metadata.remove(&builtin.tag);
                }
                if metadata.is_empty() {
                    cfg.as_object_mut()
                        .map(|root| root.remove("builtinGeoMeta"));
                }
            }
            // 即使元数据本来就不存在，也必须 Write：显式文件删除意图需要与配置按 write-ahead 顺序提交。
            Decision::Write(())
        }) {
        Ok(((), Some(cfg))) => {
            broadcast_config_changed(&app, &cfg);
            ApiResponse::ok(json!({ "ok": true, "id": builtin_id_for(&tag), "name": tag }))
        }
        Ok(_) => unreachable!("builtin rule reset decision and persistence must agree"),
        Err(e) => ApiResponse::err(format!("{e}")),
    }
}

/// 删除内置规则集的下载缓存与运行时生效副本。Apply journal 重试共用同一实现；任一路径不存在均按
/// 幂等成功，第二个删除失败时整条意图保留，下次会从头安全重试。
pub(crate) fn remove_builtin_rule_resource_files(
    config_dir: &std::path::Path,
    file_name: &str,
) -> Result<(), String> {
    for path in [
        config_dir
            .join("rule-resource")
            .join(sanitize_file_stem(file_name)),
        config_dir.join("rules").join(sanitize_file_stem(file_name)),
    ] {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "删除内置规则资源文件 {} 失败: {error}",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

/// 内置 geo 的运行时生效目录（`<userData>/rules`）。**必须与 `geo_seed` /
/// `GenerateConfigDeps.runtime_rules_dir` 同源** —— 写别处等于更新静默无效。
fn builtin_runtime_dir(state: &AppRuntime) -> std::path::PathBuf {
    state.config().dir().join("rules")
}

/// 内置 geo 的下载计划（分类字符串 / id / 原址三者的唯一拼装点）。
fn plan_from_builtin(b: &BuiltinGeoRuleSet) -> ResourcePlan {
    let category = match b.category {
        GeoCategory::Geosite => "geosite",
        GeoCategory::Geoip => "geoip",
    };
    let url = b.source_url();
    ResourcePlan {
        id: builtin_id_for(&b.tag),
        name: b.tag.clone(),
        category: category.to_string(),
        fetch_url: url.clone(),
        url,
        file_name: b.file_name.clone(),
        format: RuleResourceFormat::Binary,
    }
}

/// 上游 `RULE_RESOURCES_UPDATE_BUILTIN`：把单个内置 geo 规则集更新到上游最新版（**真下载**）。
///
/// 这条腿此前不存在，于是 `rule_resources_list` 也不敢列内置项 —— 列出来每行都会带一个必然报
/// `RULE_RESOURCE_NOT_FOUND` 的「更新」按钮（行内更新走 [`rule_resources_redownload`]，它按 id 查
/// `config.ruleResources`，而 `builtin:*` 从不入册）。当时记的否决理由是「缺随包 geo manifest、
/// 不知道 sourceUrl」，**复核后不成立**：地址纯由 tag 推导，见
/// [`BuiltinGeoRuleSet::source_url`]（陈先生 2026-07-29 指出「随包不影响关联包资源地址」）。
///
/// 与普通资源的三点不同，都是内置态本身带来的：
/// 1. **落盘目录是运行时生效目录** `<userData>/rules/`，不是下载缓存 `<userData>/rule-resource/`
///    —— 后者只是资源库的暂存，sing-box 读的是前者；
/// 2. **原子替换**：先下到同目录下的 `.update/` 暂存再 `rename`（同盘 ⇒ 原子）。直写会让
///    「正在起核 / 正在读这个 .srs」撞上半截文件，而 SRS 魔数只校验前 3 字节、拦不住尾部截断；
/// 3. **不入册 `config.ruleResources`**：内置项的身份来自 `builtin_geo_rulesets()` 这张表，
///    入册会造出第二个真值源（并让 reset 之后条目还留着）。只写
///    `config.builtinGeoMeta[tag].updatedAt` 作「已网络更新」标记 —— 该标记正是 `geo_seed`
///    判「出厂态」的读侧判据，写上之后启动时的出厂版重种不会再覆盖这份新副本。
///
/// **生效时机如实回报**：本命令只换文件，不重启内核。运行中的 sing-box 仍持有旧规则集，
/// 下次起核才生效 —— 与既有的 [`rule_resources_reset_builtin`] 同一契约，不在这里偷偷重启。
#[tauri::command]
pub async fn rule_resources_update_builtin(
    app: AppHandle,
    state: State<'_, AppRuntime>,
    tag: String,
) -> Result<ApiResponse<Value>, ()> {
    update_builtin_with_mode(
        &app,
        &state,
        tag,
        ProgressMode::Live,
        BroadcastMode::Immediate,
    )
    .await
}

/// 后台调度腿专用入口：与 [`rule_resources_update_builtin`] 同一条下载/落位/记账路径，
/// 两处差别是**一帧进度都不发**（`ProgressMode::Silent`）+ **不逐条广播**（`BroadcastMode::Deferred`）。
///
/// 与 [`rule_resources_redownload_silent`] 同款处置：两个模式都写死在函数里、不做成命令形参 ——
/// 形参会成为前端可传的参数袋键，语义就不再由后端说了算。
pub async fn rule_resources_update_builtin_silent(
    app: &AppHandle,
    state: &AppRuntime,
    tag: String,
) -> Result<ApiResponse<Value>, ()> {
    update_builtin_with_mode(
        app,
        state,
        tag,
        ProgressMode::Silent,
        BroadcastMode::Deferred,
    )
    .await
}

/// 内置 geo 更新的共用核心（手动腿 / 后台腿只差 [`ProgressMode`] + [`BroadcastMode`]）。
async fn update_builtin_with_mode(
    app: &AppHandle,
    state: &AppRuntime,
    tag: String,
    mode: ProgressMode,
    broadcast: BroadcastMode,
) -> Result<ApiResponse<Value>, ()> {
    let Some(b) = find_builtin(&tag) else {
        return Ok(ApiResponse::ok(err_result(
            Some(&builtin_id_for(&tag)),
            Some(&tag),
            "内置规则集不存在",
            ERR_RESOURCE_NOT_FOUND,
        )));
    };
    let plan = plan_from_builtin(&b).with_gh_proxy(&gh_proxy_prefix(state));
    let runtime_dir = builtin_runtime_dir(state);
    // 暂存区放在生效目录**之内**：跨目录 rename 只有同一文件系统才原子，同父目录是最稳的保证
    // （`<userData>` 与临时目录可能分属不同挂载点）。
    let stage_dir = runtime_dir.join(".update");
    let http = state.http().clone();
    let sink = BroadcastSink { app, mode };
    let outcome =
        download_with_progress(&sink, http.as_ref(), &SystemDnsLookup, &plan, &stage_dir).await;

    let outcome = match outcome {
        DownloadOutcome::Stored { resource, .. } => {
            let staged = stage_dir.join(&plan.file_name);
            let live = runtime_dir.join(&plan.file_name);
            // `existedBefore` 要看**生效副本**存不存在，不是暂存区（那儿必然是新建的）。
            let existed_before = live.is_file();
            match std::fs::rename(&staged, &live) {
                Ok(()) => DownloadOutcome::Stored {
                    resource,
                    existed_before,
                },
                Err(e) => {
                    let _ = std::fs::remove_file(&staged);
                    DownloadOutcome::Failed {
                        message: format!("替换生效副本失败: {e}"),
                        code: ERR_RESOURCE_WRITE_FAILED,
                    }
                }
            }
        }
        other => other,
    };
    // 只删空目录：非空说明有别的在途下载的暂存文件，硬删会打断它。
    let _ = std::fs::remove_dir(&stage_dir);

    if let DownloadOutcome::Stored { ref resource, .. } = outcome {
        persist_builtin_geo_updated(app, state, &b.tag, &resource.downloaded_at, broadcast);
    }
    Ok(ApiResponse::ok(outcome.into_value(&plan)))
}

/// 记「该内置 tag 已网络更新过」：`config.builtinGeoMeta[tag].updatedAt = <ISO>`。
///
/// 只写 `updatedAt` 一个字段 —— 它是 `geo_seed::network_updated_tags_from_raw` 唯一读的键，
/// 也是 TS 契约 `builtinGeoMeta?: Record<string,{updatedAt?:string}>` 声明的唯一字段。
/// 大小/地址不落这里：前者 stat 生效副本即得（真值在盘上），后者由 tag 推导（真值在表里），
/// 抄一份进 config 就是给自己造两个真值源。
fn persist_builtin_geo_updated(
    app: &AppHandle,
    state: &AppRuntime,
    tag: &str,
    updated_at: &str,
    broadcast: BroadcastMode,
) {
    match state.config().update(|cfg| {
        let Some(obj) = cfg.as_object_mut() else {
            return Decision::Skip(false);
        };
        let meta = obj
            .entry("builtinGeoMeta")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .map(|m| {
                m.insert(tag.to_string(), json!({ "updatedAt": updated_at }));
            });
        if meta.is_none() {
            obj.insert(
                "builtinGeoMeta".to_string(),
                json!({ tag: { "updatedAt": updated_at } }),
            );
        }
        Decision::Write(true)
    }) {
        // Deferred：批次拥有者收尾统一广播（见 [`BroadcastMode`]）。落盘已完成，跳过的只是通知。
        Ok((true, Some(cfg))) => {
            if broadcast == BroadcastMode::Immediate {
                broadcast_config_changed(app, &cfg);
            }
        }
        Ok((false, None)) => {
            log::error!("内置 geo `{tag}` 已更新到盘上，但 config 根不是对象（更新标记未落）");
        }
        Ok(_) => log::error!("内置 geo `{tag}` 更新标记事务返回非法状态"),
        Err(e) => {
            log::error!("内置 geo `{tag}` 已更新到盘上，但保存 config 失败（更新标记未落）: {e}");
        }
    }
}

/// ISO8601 当前时间（上游 `new Date().toISOString()`）。落进 `config.ruleResources[].downloadedAt`
/// （契约 `downloadedAt: string /* ISO */`）→ 前端 `new Date(...)` 解析，故**必须是合法 ISO**。
///
/// 复用 stats-engine 既有的 `created_at_to_rfc3339`（无外部 time 依赖的 civil 算法，`misc.rs` 同款）——
/// **不新增 chrono/time 依赖**。旧实现 `format!("1970-01-01T00:00:{secs}Z")` 把整个 epoch 秒（~1.78e9）
/// 塞进秒字段 → `"1970-01-01T00:00:1784563200Z"`（非法，前端 Invalid Date → 资源列表显示「—」，且落 config
/// 持久化坏数据）。时钟异常取不到时间 → 空串（不 panic）。
fn current_iso() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .and_then(polaris_stats_engine::created_at_to_rfc3339)
        .unwrap_or_default()
}

// ── 规则资源下载核心（download / redownload / update_all 共用）──────────────────

/// 一次下载的解析计划：目标 URL + 落盘元数据。
struct ResourcePlan {
    id: String,
    name: String,
    category: String,
    /// **原址**（canonical）。落进 `config.ruleResources[].sourceUrl`，也是加速失败后的回退地址。
    url: String,
    /// **本次实际请求的地址**：套过 gh 加速前缀则是镜像址，否则 == `url`。
    ///
    /// 为什么与 `url` 分开而不是就地改写 `url`：`url` 会被持久化成 `sourceUrl`，把镜像址写进去就等于
    /// 把「当前这台加速器」焊死进配置 —— 用户改 / 清 `ghProxyPrefix` 之后，重下载仍走旧镜像，设置项形同
    /// 虚设；镜像停服还会变成永久坏源。对齐 上游 `RuleResourceManager.fetchSrsToFile`
    /// （`applyGhProxy` 只作用于本次请求，登记的 `sourceUrl` 恒为原址）。
    fetch_url: String,
    file_name: String,
    format: RuleResourceFormat,
}

impl ResourcePlan {
    /// 套 gh 加速前缀（下载 plan 阶段的唯一入口）。非 GitHub 域 / 空前缀 → 原样不动。
    #[must_use]
    fn with_gh_proxy(mut self, prefix: &str) -> Self {
        if let Some(mirrored) = apply_gh_proxy(prefix, &self.url) {
            self.fetch_url = mirrored;
        }
        self
    }
}

/// 下载结果（内部枚举 → `into_value` 转前端 `RuleResourceDownloadResult`）。
enum DownloadOutcome {
    Stored {
        resource: RuleResource,
        existed_before: bool,
    },
    Failed {
        message: String,
        code: &'static str,
    },
    /// 用户在下载途中点了「取消」（[`rule_resources_cancel`]）→ 传输已中止，未落盘未入册。
    Cancelled,
}

impl DownloadOutcome {
    fn into_value(self, plan: &ResourcePlan) -> Value {
        match self {
            // 取消是用户主观意图，不是故障：仍走 `ok:false`（调用方不该当成功入册），但用专属
            // errorCode 与其它失败区分，前端据此报「已取消」而非「更新失败」。
            DownloadOutcome::Cancelled => err_result(
                Some(&plan.id),
                Some(&plan.name),
                "下载已取消",
                ERR_RESOURCE_CANCELLED,
            ),
            DownloadOutcome::Stored {
                resource,
                existed_before,
            } => json!({
                "ok": true,
                "resource": serde_json::to_value(&resource).unwrap_or(Value::Null),
                "id": resource.id,
                "name": resource.name,
                "existedBefore": existed_before,
            }),
            DownloadOutcome::Failed { message, code } => {
                err_result(Some(&plan.id), Some(&plan.name), &message, code)
            }
        }
    }
}

/// 组装失败结果（前端 `RuleResourceDownloadResult` 的 `ok:false` 形态）。
fn err_result(id: Option<&str>, name: Option<&str>, error: &str, code: &str) -> Value {
    let mut o = json!({ "ok": false, "error": error, "errorCode": code });
    if let Some(id) = id {
        o["id"] = json!(id);
    }
    if let Some(name) = name {
        o["name"] = json!(name);
    }
    o
}

fn is_http_url(url: &str) -> bool {
    let l = url.to_ascii_lowercase();
    l.starts_with("http://") || l.starts_with("https://")
}

/// 由 URL 扩展名判 format（`.json` → source，其余 → binary/.srs）。
fn detect_format(url: &str) -> RuleResourceFormat {
    let path = url
        .split(['?', '#'])
        .next()
        .unwrap_or(url)
        .to_ascii_lowercase();
    if path.ends_with(".json") {
        RuleResourceFormat::Source
    } else {
        RuleResourceFormat::Binary
    }
}

fn ext_for(format: RuleResourceFormat) -> &'static str {
    match format {
        RuleResourceFormat::Binary => "srs",
        RuleResourceFormat::Source => "json",
    }
}

/// 与资源目录里**非资源文件**同名的保留名单（当前只有目录缓存）。
///
/// 缓存 `catalog.json` 与用户资源落在**同一个** `<userData>/rule-resource/` 目录下，而一条
/// `id="catalog"` 的自定义 `.json` 资源恰好派生出同名文件 → 双向覆盖：下载该资源会把目录缓存
/// 冲掉（下次刷新失去兜底），刷新目录会把用户资源文件冲成一份清单 JSON（规则集当场失效）。
/// 缓存路径由 `runtime/rule_resource_scheduler.rs` 只读镜像（那边有常量同步断言），
/// 故这里用「资源侧改名让路」而非「把缓存挪进子目录」—— 后者要同时改那个镜像。
const RESERVED_RESOURCE_FILE_NAMES: [&str; 1] = [CATALOG_CACHE_FILE];

/// 删除一份外置规则资源文件。直删命令与 Apply 延迟删除共用，确保路径清洗及保留文件保护不分叉。
///
/// `catalog.json` 是同目录的资源库缓存，不属于任何 `ruleResources` 实体；即便导入/手改配置把
/// `fileName` 指向它，也只能删除配置条目，不能借此删缓存。文件不存在按幂等成功处理。
pub(crate) fn remove_rule_resource_file(
    config_dir: &std::path::Path,
    file_name: &str,
) -> Result<(), String> {
    let cleaned = sanitize_file_stem(file_name);
    if RESERVED_RESOURCE_FILE_NAMES.contains(&cleaned.as_str()) {
        log::warn!("规则资源删除跳过保留文件: {cleaned}");
        return Ok(());
    }
    let path = config_dir.join("rule-resource").join(cleaned);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("删除规则资源文件 {} 失败: {error}", path.display())),
    }
}

/// 最新配置是否仍引用与 `file_name` 落到同一路径的资源文件。比较清洗后的名字，覆盖手改/导入造成的
/// 多个原始 `fileName` 清洗后同形，防延迟删除误删一份已被新资源复用的文件。
pub(crate) fn rule_resource_file_is_referenced(config: &Value, file_name: &str) -> bool {
    let target = sanitize_file_stem(file_name);
    config
        .get("ruleResources")
        .and_then(Value::as_array)
        .is_some_and(|resources| {
            resources.iter().any(|resource| {
                resource
                    .get("fileName")
                    .and_then(Value::as_str)
                    .is_some_and(|current| sanitize_file_stem(current) == target)
            })
        })
}

/// 落盘名 `<sanitized id>.<ext>`；**有损清洗或撞保留名时**追加 id 短哈希消歧。
///
/// # 为什么不能只做 `sanitize`
///
/// [`sanitize_file_stem`] 把 `:` `*` 空格等一律折成 `_` —— 那是**多对一**映射：远端两个不同的
/// catalog id（`geosite-foo:bar` / `geosite-foo*bar`）会落到同一个 `geosite-foo_bar.srs`，
/// 后下的静默覆盖先下的，而 config 里两条记录都指向这一个文件 → 其中一条规则集内容是错的。
/// 加一段由**原始 id**算出的短哈希即可把映射打回单射。
///
/// 只在「清洗有损」或「撞保留名」时加后缀（而非无条件加）：绝大多数 id 本来就只含
/// `[A-Za-z0-9._-]`，无条件加后缀会把**全部**既有资源的文件名改掉 —— 已下载的文件当场变孤儿、
/// 全都显示成「未下载」。干净 id 逐字保持原样，行为零变化。
fn resource_file_name(id: &str, format: RuleResourceFormat) -> String {
    let stem = sanitize_file_stem(id);
    let name = format!("{stem}.{}", ext_for(format));
    let lossy = stem != id;
    if !lossy && !RESERVED_RESOURCE_FILE_NAMES.contains(&name.as_str()) {
        return name;
    }
    format!("{stem}-{}.{}", short_id_hash(id), ext_for(format))
}

/// 由原始 id 算 8 位十六进制短哈希（FNV-1a 64，取低 32 位）。
///
/// 不用 `DefaultHasher`：它的算法**不保证跨 Rust 版本稳定**，而这个值会被写进 config 的
/// `fileName` 并落到磁盘 —— 换个编译器就换一批文件名，等于每次升级都让资源变孤儿。
/// FNV-1a 是十几行的确定性算法，零依赖、永远不变。
fn short_id_hash(id: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325; // FNV offset basis
    for b in id.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3); // FNV prime
    }
    format!("{:08x}", (h ^ (h >> 32)) as u32)
}

/// 清洗文件名 stem：仅留 `[A-Za-z0-9._-]`，其余 → `_`；消除 `..`（防路径穿越）。
fn sanitize_file_stem(id: &str) -> String {
    let mut s: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    while s.contains("..") {
        s = s.replace("..", "_");
    }
    if s.is_empty() {
        s.push('_');
    }
    s
}

/// 从 URL 推断资源名（basename 去扩展名；空则 `resource`）。
fn infer_name_from_url(url: &str) -> String {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    let base = path.rsplit('/').next().unwrap_or(path);
    let stem = base.rsplit_once('.').map_or(base, |(a, _)| a);
    if stem.is_empty() {
        "resource".to_string()
    } else {
        stem.to_string()
    }
}

/// 按 catalogId 解析条目：**内置精选表优先，其次刷新得到的全量清单**（= 上游
/// `RuleResourceManager.findCatalogItem`，`:705-710`：先 `findCatalogItem(id)` 再 `getCatalog()`）。
///
/// 为什么必须有第二跳：「刷新清单」拿回来的是 2000+ 条远程全量，其中只有 33 条在内置表里。只查内置表
/// 的话，用户在外置 tab 勾中任何一条精选之外的资源点下载，都会恒返 `资源库无此条目` —— 刷新功能等于
/// 只能看不能用。本仓此前正是如此（`find_catalog_item` 单跳），与恒等降级的刷新腿互相掩盖。
fn resolve_catalog_item(
    id: &str,
    refreshed_catalog: &[RuleResourceCatalogItem],
) -> Option<RuleResourceCatalogItem> {
    find_catalog_item(id).or_else(|| refreshed_catalog.iter().find(|i| i.id == id).cloned())
}

/// 解析前端 `RuleResourceDownloadItem` → 下载计划。catalogId 优先，其次 url。
///
/// `refreshed_catalog` = 磁盘缓存里的远程全量清单（无缓存时传空切片 → 退化为只认内置精选表）。
fn plan_from_item(
    item: &Value,
    refreshed_catalog: &[RuleResourceCatalogItem],
) -> Result<ResourcePlan, String> {
    let name_in = item
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let cat_in = item
        .get("category")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());

    // 优先 catalogId（内置/动态精选项 → meta-rules-dat raw URL）。
    if let Some(cid) = item
        .get("catalogId")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        let cat = resolve_catalog_item(cid, refreshed_catalog)
            .ok_or_else(|| format!("资源库无此条目: {cid}"))?;
        let id = cat.id.clone();
        let name = name_in.map_or_else(|| cat.name.clone(), str::to_string);
        let category = cat_in.map_or(cat.category, str::to_string);
        let url = mrd_raw_url(&cat.path);
        let file_name = resource_file_name(&id, RuleResourceFormat::Binary);
        return Ok(ResourcePlan {
            id,
            name,
            category,
            fetch_url: url.clone(),
            url,
            file_name,
            format: RuleResourceFormat::Binary,
        });
    }

    // 其次 url（手动下载）。
    if let Some(url) = item
        .get("url")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if !is_http_url(url) {
            return Err(format!("URL 协议不支持（仅 http/https）: {url}"));
        }
        let format = detect_format(url);
        let id = item
            .get("id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map_or_else(|| format!("res_{}", new_uuid()), str::to_string);
        let name = name_in.map_or_else(|| infer_name_from_url(url), str::to_string);
        let category = cat_in.map_or_else(|| "custom".to_string(), str::to_string);
        let file_name = resource_file_name(&id, format);
        return Ok(ResourcePlan {
            id,
            name,
            category,
            url: url.to_string(),
            fetch_url: url.to_string(),
            file_name,
            format,
        });
    }

    Err("下载项须含 catalogId 或 url".to_string())
}

/// 已登记资源 → 下载计划（redownload / update_all 用；保留原 id/sourceUrl）。
fn plan_from_resource(r: &RuleResource) -> ResourcePlan {
    ResourcePlan {
        id: r.id.clone(),
        name: r.name.clone(),
        category: r.category.clone(),
        url: r.source_url.clone(),
        fetch_url: r.source_url.clone(),
        // **信任边界清洗**（P3）：config 里的 fileName 可能被篡改/导入为 `../../.bashrc` 或绝对路径，
        // 而 `download_and_store` 的 `res_dir.join(&file_name)` 遇绝对路径会整段替换 → 逃出资源目录。
        // 首次下载路径（plan_from_item）走 resource_file_name → sanitize_file_stem，redownload/update_all
        // 此前直接透传原值漏了这道闸 → 在此按同一 sanitizer 收口（对合法名幂等，不改正常重下载行为）。
        //
        // 额外一道：清洗后若**撞上保留名**（目录缓存 `catalog.json`），改按 id 重新派生 ——
        // 存量 config 里可能早就登记着 `fileName:"catalog.json"`（本轮之前 `id:"catalog"` 的 json
        // 资源就是这么落的），重下载会把目录缓存冲掉。见 [`RESERVED_RESOURCE_FILE_NAMES`]。
        file_name: {
            let cleaned = sanitize_file_stem(&r.file_name);
            if RESERVED_RESOURCE_FILE_NAMES.contains(&cleaned.as_str()) {
                resource_file_name(&r.id, r.format)
            } else {
                cleaned
            }
        },
        format: r.format,
    }
}

/// 反序列化一条 `ruleResources` 原始项 → [`RuleResource`]。失败（结构非法：缺字段/类型错）→
/// `Err(err_result)`，错误码 **BAD_ITEM**（非 NOT_FOUND）——该条目**在册但坏了**，与「不在册」是不同的
/// 诚实语义（P8）。保留原始 id/name 供前端定位。
fn parse_resource_entry(entry: &Value) -> Result<RuleResource, Value> {
    serde_json::from_value::<RuleResource>(entry.clone()).map_err(|e| {
        err_result(
            entry.get("id").and_then(Value::as_str),
            entry.get("name").and_then(Value::as_str),
            &format!("资源条目结构非法: {e}"),
            ERR_RESOURCE_BAD_ITEM,
        )
    })
}

/// 在 `ruleResources` 里按 id 定位并解析：不在册 → NOT_FOUND；在册但结构非法 → BAD_ITEM；命中且合法 → Ok。
///
/// **先按 id 找原始项、再反序列化**（不先 `filter_map(.ok())` 滤掉坏项）——否则坏项会被误报成
/// 「资源不在册」（P8：它其实在册，只是 malformed）。
fn resolve_registered_resource(resources: &[Value], id: &str) -> Result<RuleResource, Value> {
    let Some(entry) = resources
        .iter()
        .find(|v| v.get("id").and_then(Value::as_str) == Some(id))
    else {
        return Err(err_result(
            Some(id),
            None,
            &format!("资源不在册: {id}"),
            ERR_RESOURCE_NOT_FOUND,
        ));
    };
    parse_resource_entry(entry)
}

/// 内容 sanity：binary 校 SRS 魔数（与 route.rs / rule_resources_list 同口径）；source 校 JSON 对象。
fn validate_resource_bytes(format: RuleResourceFormat, body: &[u8]) -> Result<(), String> {
    if body.is_empty() {
        return Err("下载内容为空".to_string());
    }
    match format {
        RuleResourceFormat::Binary => {
            if body.len() < 3 || !is_valid_srs_bytes([body[0], body[1], body[2]]) {
                return Err("下载内容不是有效的 .srs 规则集（SRS 魔数校验失败）".to_string());
            }
        }
        RuleResourceFormat::Source => match serde_json::from_slice::<Value>(body) {
            Ok(v) if v.is_object() => {}
            Ok(_) => return Err("下载内容不是 JSON 对象（sing-box 源规则集须为对象）".to_string()),
            Err(e) => return Err(format!("下载内容不是合法 JSON: {e}")),
        },
    }
    Ok(())
}

/// 拉取资源字节（**复用订阅同款** [`safe_redirect_fetch`]：逐跳 SSRF guard + 体积闸 + 超时 + 手动重定向）
/// + 状态/内容 sanity。泛型注入 client/lookup 便于回环门测（真 socket，不碰宿主网络）。
async fn fetch_resource_bytes<H: HttpClient, L: DnsLookup>(
    client: &H,
    lookup: &L,
    url: &str,
    format: RuleResourceFormat,
) -> Result<Vec<u8>, String> {
    let resp = safe_redirect_fetch(SafeRedirectFetchOptions {
        fetch_impl: client,
        url,
        user_agent: app_user_agent(),
        headers: None,
        exempt_fake_ip: false,
        max_redirects: None,
        timeout_ms: Some(RULE_RESOURCE_TIMEOUT_MS),
        max_body_bytes: Some(RULE_RESOURCE_MAX_BYTES),
        lookup,
    })
    .await
    .map_err(|e| e.message)?;

    if !(200..300).contains(&resp.status) {
        return Err(format!("下载失败：HTTP {}", resp.status));
    }
    validate_resource_bytes(format, &resp.body)?;
    Ok(resp.body)
}

/// 下载 + 落盘（不写 config；config upsert 由 [`persist_resources`] 批量做）。
/// # gh 加速的回退腿
///
/// 设置页对「GitHub 加速」的承诺是「留空回退直连；**下载失败自动回退直连兜底**」
/// （`i18n settings.ghProxyHint`）。故加速址失败且确实套过前缀（`fetch_url != url`）时，再打一次原址：
/// 镜像挂了 / 返 HTML 错误页 / 被墙，都不该让本来能直连拿到的资源变成红行。对齐 上游
/// `fetchSrsToFile` 的 `if (!r.ok && prefix) r = await this.fetchBuffer(sourceUrl, ...)`。
/// 失败消息取**回退腿**的（那是用户最终没拿到东西的真实原因）。
async fn download_and_store<H: HttpClient, L: DnsLookup>(
    client: &H,
    lookup: &L,
    plan: &ResourcePlan,
    res_dir: &std::path::Path,
) -> DownloadOutcome {
    let mut attempt = fetch_resource_bytes(client, lookup, &plan.fetch_url, plan.format).await;
    if let (Err(e), true) = (&attempt, plan.fetch_url != plan.url) {
        // 同上（`fetch_catalog_json`）：静默回退 = 用户无从知道加速腿恒挂。自建内网 gh-proxy 被
        // SSRF guard 拒是最常见的一种，且**不能**靠放行内网 host 来「修」（那是开 SSRF 面）。
        log::warn!(
            "gh 加速腿失败，回退原址（资源 {}）: {} → {e}",
            plan.id,
            plan.fetch_url
        );
        attempt = fetch_resource_bytes(client, lookup, &plan.url, plan.format).await;
    }
    let bytes = match attempt {
        Ok(b) => b,
        Err(message) => {
            return DownloadOutcome::Failed {
                message,
                code: ERR_RESOURCE_DOWNLOAD_FAILED,
            };
        }
    };
    let dest = res_dir.join(&plan.file_name);
    let existed_before = dest.is_file();
    // **原子替换**：先写同目录临时文件再 rename（同目录 ⇒ 同文件系统 ⇒ rename 原子）。
    //
    // 此前是 `std::fs::write(&dest, ..)` 直写目标。网络失败伤不到已有副本（字节先全收完才动盘），
    // 但**写到一半失败**（磁盘满 / 断电 / 进程被杀）会把用户已有的那份规则资源截断成半截文件 ——
    // 而 SRS 魔数只校验前 3 字节，截断的尾部照样过校验，坏文件会一直被当好的用下去
    // （陈先生 2026-07-30：「规则更新的时候要确保更新失败不破坏已有资源」）。
    // 临时名带 pid：同一资源两条在途下载（手动 + 后台调度）不会互相覆盖对方的半成品。
    let tmp = res_dir.join(format!(".{}.{}.tmp", plan.file_name, std::process::id()));
    let staged = std::fs::create_dir_all(res_dir)
        .and_then(|()| std::fs::write(&tmp, &bytes))
        .and_then(|()| std::fs::rename(&tmp, &dest));
    if let Err(e) = staged {
        let _ = std::fs::remove_file(&tmp); // 半成品不留在盘上（它不是有效资源，也不该被误当缓存）
        return DownloadOutcome::Failed {
            message: format!("写入失败: {e}"),
            code: ERR_RESOURCE_WRITE_FAILED,
        };
    }
    let resource = RuleResource {
        id: plan.id.clone(),
        name: plan.name.clone(),
        category: plan.category.clone(),
        source_url: plan.url.clone(),
        file_name: plan.file_name.clone(),
        format: plan.format,
        size: bytes.len() as u64,
        downloaded_at: current_iso(),
    };
    DownloadOutcome::Stored {
        resource,
        existed_before,
    }
}

/// 进度可见性档位。**后台调度腿恒 `Silent`**（对齐 上游 `RuleResourceManager.downloadOne` 的
/// `silent` 形参：`if (silent) return;` 直接吞掉整帧）——后台保鲜不该在用户正看别的页面时
/// 往资源页推进度条 / 堆红行。手动腿（三个 command）恒 `Live`。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProgressMode {
    /// 用户显式触发 → 照常广播 `EVENT_RULE_RESOURCE_PROGRESS`。
    Live,
    /// 后台调度触发 → 一帧不发。
    Silent,
}

/// 配置广播时机。**与 [`ProgressMode`] 正交**：那个管「UI 要不要看到进度条」，本枚举管
/// 「这次落盘要不要立刻进核」——`broadcast_config_changed` 不只是 emit 给渲染端，它同时
/// `spawn(switch_mode)` 把变更送进运行核（见该函数文档）。
///
/// # 为什么必须可延后（真机实证 2026-08-02）
///
/// 后台保鲜一轮要更新 **8 条已登记资源 + 25 个内置 geo**，每条各自落盘 + 广播 ⇒ 一轮启动补更
/// 打出 **33 次 `switch_mode`**（真机日志 11 秒内 35 条 `switchMode：核未运行 → 仅更新配置`）。
/// 核没跑时只是刷屏；**核在跑时每条都进热切换/去抖重启判定** —— 每次启动补更与每 30 分钟巡检
/// 都在给运行中的核连砸 33 次。而这一轮的语义本就是「一批」：批内每条的中间态没有任何消费者
/// 需要看见。
///
/// 落盘仍**逐条**（每条各自 `save_full`）：磁盘真值随下随记，批次中途崩溃只丢已下载条目的
/// 更新标记，下一轮自愈；把落盘也攒到最后反而放大了丢失窗口。延后的只是广播。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BroadcastMode {
    /// 单条更新（用户手点）→ 落盘后立即广播，变更即刻进核。
    Immediate,
    /// 批量更新（后台调度一轮）→ 只落盘不广播，由**批次拥有者**结束时统一广播一次。
    Deferred,
}

/// 进度落点（注入式：生产走 `AppHandle` 广播，单测走记录器 → 「静默腿真的一帧不发」可被断言）。
///
/// 为什么不是直接在 `download_with_progress` 里写 `if silent { return }`：那样「静默」只能靠读代码
/// 相信，无法在无 `AppHandle` 的单测里证伪（本仓未引 `tauri::test`）。抽成 trait 后
/// `RecordingSink`（测试模块）能逐帧对账。
trait ProgressSink: Sync {
    fn emit(&self, frame: Value);
}

/// 生产落点：广播给渲染端。
struct BroadcastSink<'a> {
    app: &'a AppHandle,
    mode: ProgressMode,
}

impl ProgressSink for BroadcastSink<'_> {
    fn emit(&self, frame: Value) {
        if self.mode == ProgressMode::Silent {
            return; // 后台腿静默（上游 `if (silent) return`）
        }
        broadcast(self.app, EVENT_RULE_RESOURCE_PROGRESS, frame);
    }
}

/// 发一帧下载进度（`EVENT_RULE_RESOURCE_PROGRESS` → 前端 `ruleResources.onProgress`）。
///
/// `id`/`name` 由 plan 补齐，调用方只给阶段字段（前端 `RuleResourceProgress` 契约）。
fn emit_resource_progress(sink: &dyn ProgressSink, plan: &ResourcePlan, mut frame: Value) {
    if let Some(obj) = frame.as_object_mut() {
        obj.insert("id".into(), json!(plan.id));
        obj.insert("name".into(), json!(plan.name));
    }
    sink.emit(frame);
}

/// [`download_and_store`] + 逐阶段广播进度。下载族的**唯一**入口（三个 command 都走它）。
///
/// 此前 `EVENT_RULE_RESOURCE_PROGRESS` 全仓零 emit：下载是真的、落盘是真的，但前端 `onProgress`
/// 永不触发 → 资源页既无进度、下完也不刷新（列表停在旧 size/时间，用户以为没下成又点一次）。
///
/// # 为什么 downloading 帧的 percent 是 null（**不是**忘了填）
///
/// 底层 `safe_redirect_fetch` 返回的是**已缓冲完的 `resp.body`**（SSRF/重定向/体积 guard 都建立在
/// 「整体收完再判」上），没有字节流可数 —— 真实百分比要改 net-stack 的传输层，非本处能力。故如实报
/// `percent: null`：前端 `ResRow` 对 `percent == null` 走 spinner 分支（不画进度条），是契约内的
/// 已有降级态。**宁可没有进度条，也不编一个匀速爬升的假条。**
/// `done` 帧的 `received`/`total` 是真值（落盘字节数），故 percent 报 100 不算伪造。
///
/// # 取消
///
/// 进入下载前把一个 oneshot 发送端登记进 [`cancel_registry`]（键 = 单调自增 seq，值 = `(资源 id, tx)`），
/// 与真实下载 future `select!`。[`rule_resources_cancel`] 按资源 id 取出全部在途条目并 `send(())` →
/// 本处 future 被**丢弃**（reqwest 连接随之中止，真中断而非「标记为取消后继续下载完」），返回
/// [`DownloadOutcome::Cancelled`]、发一帧 `status:"cancelled"`、**不落盘不入册**。
async fn download_with_progress<H: HttpClient, L: DnsLookup>(
    sink: &dyn ProgressSink,
    client: &H,
    lookup: &L,
    plan: &ResourcePlan,
    res_dir: &std::path::Path,
) -> DownloadOutcome {
    emit_resource_progress(
        sink,
        plan,
        json!({ "received": 0, "total": null, "percent": null, "status": "downloading" }),
    );

    let (seq, mut cancel_rx) = register_cancellable(&plan.id);
    let fut = download_and_store(client, lookup, plan, res_dir);
    tokio::pin!(fut);
    let outcome = tokio::select! {
        o = &mut fut => o,
        r = &mut cancel_rx => {
            if r.is_ok() {
                DownloadOutcome::Cancelled
            } else {
                // 发送端在未 send 的情况下被 drop（本设计下不可达：条目只由 cancel 取走或由下方
                // unregister 在 select 结束后清理）→ 保守继续等下载，绝不谎报「已取消」。
                fut.await
            }
        }
    };
    unregister_cancellable(seq);

    match &outcome {
        DownloadOutcome::Stored { resource, .. } => emit_resource_progress(
            sink,
            plan,
            json!({
                "received": resource.size,
                "total": resource.size,
                "percent": 100.0,
                "status": "done",
            }),
        ),
        DownloadOutcome::Failed { message, code } => emit_resource_progress(
            sink,
            plan,
            json!({
                "received": 0,
                "total": null,
                "percent": null,
                "status": "error",
                "error": message,
                "errorCode": code,
            }),
        ),
        DownloadOutcome::Cancelled => emit_resource_progress(
            sink,
            plan,
            json!({
                "received": 0,
                "total": null,
                "percent": null,
                "status": "cancelled",
            }),
        ),
    }
    outcome
}

// ── 下载取消登记表 ─────────────────────────────────────────────────────────────
//
// 为什么用「seq → (id, tx)」而不是「id → tx」：同一 id 可能有两条在途下载（用户在资源页点「更新」
// 的同时后台调度腿正好也选中它）。以 id 为键会让后者覆盖前者的发送端 → 被覆盖的那条永远取消不掉，
// 且其 receiver 会因 sender 被 drop 而收到 `Err`（若把 `Err` 当取消处理，就是**谎报取消**）。
// seq 键保证登记只增不覆盖，取消按 id 扫全表逐条 send。

type CancelRegistry =
    Mutex<std::collections::HashMap<u64, (String, tokio::sync::oneshot::Sender<()>)>>;

fn cancel_registry() -> &'static CancelRegistry {
    static REG: OnceLock<CancelRegistry> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

/// 登记一条可取消的在途下载，返回 `(seq, 取消接收端)`。
fn register_cancellable(id: &str) -> (u64, tokio::sync::oneshot::Receiver<()>) {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let (tx, rx) = tokio::sync::oneshot::channel();
    if let Ok(mut reg) = cancel_registry().lock() {
        reg.insert(seq, (id.to_string(), tx));
    }
    (seq, rx)
}

/// 下载结束（成功/失败/已取消）后摘掉自己的登记条目。
fn unregister_cancellable(seq: u64) {
    if let Ok(mut reg) = cancel_registry().lock() {
        reg.remove(&seq);
    }
}

/// 取消该 id 的全部在途下载，返回**实际被中止的条数**（0 = 当时没有在途下载，如实回报，不假装成功）。
fn cancel_inflight(id: &str) -> usize {
    let Ok(mut reg) = cancel_registry().lock() else {
        return 0;
    };
    let seqs: Vec<u64> = reg
        .iter()
        .filter(|(_, (rid, _))| rid == id)
        .map(|(seq, _)| *seq)
        .collect();
    let mut n = 0;
    for seq in seqs {
        if let Some((_, tx)) = reg.remove(&seq) {
            // send 失败 = 对端已走完（竞态：下载刚好在同一瞬完成）→ 不计数，别虚报。
            if tx.send(()).is_ok() {
                n += 1;
            }
        }
    }
    n
}

/// 上游 `RULE_RESOURCES_CANCEL`：中止该资源的在途下载。
///
/// 返回 `{ cancelled: n }`——`n` 是**真被中止**的在途下载条数。资源当时不在下载中 → `n = 0`
/// （诚实：按钮点了没有可取消的东西，不伪造成功）。取消的资源不落盘、不入册，磁盘上的旧副本保持不变。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn rule_resources_cancel(id: String) -> ApiResponse<Value> {
    let n = cancel_inflight(&id);
    ApiResponse::ok(json!({ "cancelled": n }))
}

/// 把成功下载的资源 upsert 进 `config.ruleResources`（按 id 覆盖/追加），保存 + 广播 `config:changed`。
///
/// 文件已在盘上；若 config 保存失败，如实 log（资源暂成孤儿，下次 list 不显示）——不静默吞。
fn persist_resources(
    app: &AppHandle,
    state: &AppRuntime,
    downloaded: &[RuleResource],
    broadcast: BroadcastMode,
) {
    if downloaded.is_empty() {
        return;
    }
    match state.config().update(|cfg| {
        upsert_rule_resources(cfg, downloaded);
        Decision::Write(())
    }) {
        // Deferred：批次拥有者收尾统一广播（见 [`BroadcastMode`]）。落盘已完成，跳过的只是通知。
        Ok(((), Some(cfg))) => {
            if broadcast == BroadcastMode::Immediate {
                broadcast_config_changed(app, &cfg);
            }
        }
        Ok(_) => log::error!("规则资源登记事务返回非法状态"),
        Err(e) => log::error!("规则资源已下载但保存 config 失败（未登记）: {e}"),
    }
}

/// upsert：按 id 覆盖既有项，否则追加。
fn upsert_rule_resources(cfg: &mut Value, downloaded: &[RuleResource]) {
    let Some(obj) = cfg.as_object_mut() else {
        return;
    };
    let entry = obj
        .entry("ruleResources")
        .or_insert_with(|| Value::Array(Vec::new()));
    let Some(arr) = entry.as_array_mut() else {
        return;
    };
    for r in downloaded {
        let Ok(val) = serde_json::to_value(r) else {
            continue;
        };
        if let Some(idx) = arr
            .iter()
            .position(|e| e.get("id").and_then(Value::as_str) == Some(r.id.as_str()))
        {
            arr[idx] = val;
        } else {
            arr.push(val);
        }
    }
}

#[cfg(test)]
mod tests;
