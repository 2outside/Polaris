//! 图标图库的远端目录、内存缓存与刷新 command。
//!
//! 拉取仍复用订阅同款 [`safe_redirect_fetch`]（逐跳 SSRF guard + 体积闸 + 超时 + 手动重定向）。

use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

#[cfg(test)]
use serde_json::json;
use serde_json::Value;
use tauri::State;

use crate::response::ApiResponse;
use crate::runtime::http::{app_user_agent, HttpRuntime, SystemDnsLookup};
#[cfg(test)]
use crate::runtime::subscription_scheduler::now_ms;
use crate::runtime::AppRuntime;
use polaris_net_stack::safe_redirect::{safe_redirect_fetch, HttpClient, SafeRedirectFetchOptions};
use polaris_net_stack::ssrf::DnsLookup;

/// 图标库条目（前端契约 `{name,url}`，见 `api-client.ts` `fetchIconGalleries`）。
#[derive(serde::Serialize, Clone)]
pub struct IconGalleryItem {
    pub name: String,
    pub url: String,
}

/// Qure（Koolson）图库镜像：jsdelivr → fastly → github raw，逐个兜底（= 上游 同三址）。
const QURE_ICON_MIRRORS: &[&str] = &[
    "https://cdn.jsdelivr.net/gh/Koolson/Qure/Other/QureColor-All.json",
    "https://fastly.jsdelivr.net/gh/Koolson/Qure/Other/QureColor-All.json",
    "https://raw.githubusercontent.com/Koolson/Qure/master/Other/QureColor-All.json",
];

/// edc（erdongchanyo）图库镜像：jsdelivr → fastly → github raw，逐个兜底（= 上游 同三址）。
const EDC_ICON_MIRRORS: &[&str] = &[
    "https://cdn.jsdelivr.net/gh/erdongchanyo/icon@main/edc-filter-icon-gallery.json",
    "https://fastly.jsdelivr.net/gh/erdongchanyo/icon@main/edc-filter-icon-gallery.json",
    "https://raw.githubusercontent.com/erdongchanyo/icon/main/edc-filter-icon-gallery.json",
];

/// homarr（homarr-labs/dashboard-icons）图库清单镜像：jsdelivr → fastly → github raw。
/// 原型解锁徽标即用此库（`polaris-prototype.html` `UB_ICON_BASE = dashboard-icons/png/`），几千个应用图标。
/// 清单 `tree.json` 结构 `{"png":["1panel.png", ...]}`（与 Qure/edc 的 `{"icons":[...]}` 不同 → 单独 parse）。
const HOMARR_ICON_MIRRORS: &[&str] = &[
    "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons@main/tree.json",
    "https://fastly.jsdelivr.net/gh/homarr-labs/dashboard-icons@main/tree.json",
    "https://raw.githubusercontent.com/homarr-labs/dashboard-icons/main/tree.json",
];

/// homarr 图标本体 CDN 前缀（png 目录，与原型 `UB_ICON_BASE` 同源）：`<base><file.png>` 即图标 URL。
const HOMARR_ICON_BASE: &str = "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons@main/png/";

/// 图标库 JSON 单次拉取超时（ms）。文件 KB 级，15s 足够。
const ICON_GALLERY_TIMEOUT_MS: u64 = 15_000;
/// 图标库 JSON 体积上限（8 MiB）：实际两源 < 40 KB，超此即拒防 OOM / 劫持回灌。
const ICON_GALLERY_MAX_BYTES: usize = 8 * 1024 * 1024;
/// 图标库内存缓存 TTL（1h）：避免每次开「添加应用」弹窗都拉网。**上游 无此缓存**（逐次直拉 `fetchJson`）——
/// 这是本移植针对「每开弹窗一次往返」显式补的最小内存缓存，不改变数据来源/解析口径。
const ICON_GALLERY_CACHE_TTL: Duration = Duration::from_secs(60 * 60);

/// 进程级图标库内存缓存条目。
struct IconGalleryCache {
    fetched_at: Instant,
    items: Vec<IconGalleryItem>,
}

/// 懒初始化的进程级缓存句柄。
fn icon_gallery_cache() -> &'static Mutex<Option<IconGalleryCache>> {
    static CACHE: OnceLock<Mutex<Option<IconGalleryCache>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(None))
}

/// 读缓存：命中且未过 TTL → 克隆返回；过期 → **就地驱逐**后返回 None（见 [`take_fresh_icon_items`]）。
/// 锁中毒 → 视作未命中（不 panic，回退重拉）—— `ok()?` 这条腿的语义不变。
fn read_fresh_icon_cache() -> Option<Vec<IconGalleryItem>> {
    let mut guard = icon_gallery_cache().lock().ok()?;
    take_fresh_icon_items(&mut guard, ICON_GALLERY_CACHE_TTL)
}

/// [`read_fresh_icon_cache`] 的判定半边：新鲜 → 克隆返回；**过期 → 就地置 `None` 再返回 `None`**。
///
/// # 为什么过期必须驱逐，而不是只返回 `None`
///
/// 判过期的那一刻，就是那份清单最后一次被看见 —— 它此后没有任何读者，却会一直躺在进程级静态
/// 缓存里，等下一次**成功**拉取来覆盖、或用户点刷新、或进程退出。而三图库并发拉取是「全失败就
/// 一份都不写」（见 [`fetch_and_store_icon_galleries`]），所以离线 / CDN 不可达 / SSRF guard 拒绝
/// 时，旧清单是**无限期**驻留：3000~4000 条，每条 url 恒带 71 字节 CDN 前缀，约 0.3~0.8 MiB。
///
/// # 为什么 TTL 从参数进来
///
/// 为了让「已过期」在单测里可构造。`Instant` 造不出可靠的过去时刻：Windows 上它是 QPC 计数，
/// 机器 uptime 不足 TTL 时 `checked_sub` 直接返回 `None`（CI 矩阵含 windows-2022）⇒ 那种测试会在
/// 新开的 runner 上变成假红或静默跳过。改用 `ttl = ZERO` 表达「一切皆已过期」，跨平台恒定，
/// 且不必在 `cfg(test)` 下偷改生产常量（测试环境比生产宽容的绿没有信息量）。
fn take_fresh_icon_items(
    slot: &mut Option<IconGalleryCache>,
    ttl: Duration,
) -> Option<Vec<IconGalleryItem>> {
    let cache = slot.as_ref()?;
    if cache.fetched_at.elapsed() < ttl {
        return Some(cache.items.clone());
    }
    *slot = None;
    None
}

/// 写缓存。**仅在结果非空时由调用方调用** —— 空结果（瞬时全断）不缓存，下次开弹窗即重试，不卡死 TTL。
fn store_icon_cache(items: &[IconGalleryItem]) {
    if let Ok(mut guard) = icon_gallery_cache().lock() {
        *guard = Some(IconGalleryCache {
            fetched_at: Instant::now(),
            items: items.to_vec(),
        });
    }
}

/// 作废清单内存缓存 —— 用户点「刷新」时的清单腿。
///
/// 没有这一步，「刷新」只清得掉图标本体的磁盘缓存：清单仍被 1h TTL 挡着，重拉命令直接返回旧清单，
/// 用户会看到「点了刷新，新图标还是不在列表里」。刷新必须两层一起作废才是用户理解的那个刷新。
fn invalidate_icon_gallery_cache() {
    if let Ok(mut guard) = icon_gallery_cache().lock() {
        *guard = None;
    }
}

/// 「刷新」的作废动作：两层缓存**一起**倒掉。抽成函数而不是写在 command 体内，是为了让「两层一起」
/// 这句话可被单测证伪 —— command 本体要 Tauri `State` 才能跑，写在里面就只剩注释里的一句宣称。
///
/// 磁盘腿只碰 `<userData>/icons/remote/`（浏览缓存）：「设定即缓存」的正式副本按 app id 落在
/// `icons/` 顶层，刷新图库不该动用户已经选定的图标。
fn drop_icon_gallery_caches(config_dir: &Path) {
    crate::icon_cache::clear_remote_cache(&crate::icon_cache::remote_cache_dir(config_dir));
    invalidate_icon_gallery_cache();
}

/// 从图库 JSON 提取 `.icons` → `{name,url}[]`。缺 `icons`/非数组 → 空；条目缺 name/url → 跳过该条
/// （不整体失败）。与 上游 `qure?.icons || []` 同口径：解析成功即用其 icons（可空），空 icons 不触发回退。
fn parse_icon_gallery(value: &Value) -> Vec<IconGalleryItem> {
    let Some(arr) = value.get("icons").and_then(Value::as_array) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|it| {
            let name = it.get("name").and_then(Value::as_str)?;
            let url = it.get("url").and_then(Value::as_str)?;
            Some(IconGalleryItem {
                name: name.to_string(),
                url: url.to_string(),
            })
        })
        .collect()
}

/// 从 homarr `tree.json` 的 `.png` 文件名数组 → `{name,url}[]`。缺 `png`/非数组 → 空；空串 → 跳过。
/// 每项 `<file.png>`：显示名去 `.png` 后缀，url = `HOMARR_ICON_BASE + <file.png>`（图标本体也在 jsdelivr）。
/// 与 Qure/edc 的 `.icons` 结构不同（是 `{png:[...]}`），故单独解析——但产出同一 `IconGalleryItem` 契约。
fn parse_homarr_gallery(value: &Value) -> Vec<IconGalleryItem> {
    let Some(arr) = value.get("png").and_then(Value::as_array) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|it| {
            let file = it.as_str().filter(|s| !s.is_empty())?;
            let name = file.strip_suffix(".png").unwrap_or(file).to_string();
            Some(IconGalleryItem {
                name,
                url: format!("{HOMARR_ICON_BASE}{file}"),
            })
        })
        .collect()
}

/// 拉取单个图库 URL 的 JSON（复用订阅同款 [`safe_redirect_fetch`]）。非 2xx / 网络错 / 非法 JSON → Err
/// （触发上层镜像回退）。泛型注入 client/lookup 便于单测 mock（不碰宿主网络）。
async fn fetch_icon_gallery_json<H: HttpClient, L: DnsLookup>(
    client: &H,
    lookup: &L,
    url: &str,
) -> Result<Value, String> {
    let resp = safe_redirect_fetch(SafeRedirectFetchOptions {
        fetch_impl: client,
        url,
        user_agent: app_user_agent(),
        headers: None,
        exempt_fake_ip: false,
        max_redirects: None,
        timeout_ms: Some(ICON_GALLERY_TIMEOUT_MS),
        max_body_bytes: Some(ICON_GALLERY_MAX_BYTES),
        lookup,
    })
    .await
    .map_err(|e| e.message)?;
    if !(200..300).contains(&resp.status) {
        return Err(format!("下载失败：HTTP {}", resp.status));
    }
    serde_json::from_slice::<Value>(&resp.body).map_err(|e| format!("图库 JSON 非法: {e}"))
}

/// 逐镜像回退拉一个源的 icons：首个「拉取成功且 JSON 合法」的镜像即停并返回其 icons（可空，与 上游
/// 一致——合法 JSON 不再回退次镜像）。所有镜像都失败 → 空 vec。`parse` 注入各源的结构差异
/// （Qure/edc = `.icons`，homarr = `.png`）——回退/状态/JSON 编排统一，只解析口径不同。
async fn fetch_icon_source<H: HttpClient, L: DnsLookup>(
    client: &H,
    lookup: &L,
    mirrors: &[&str],
    parse: fn(&Value) -> Vec<IconGalleryItem>,
) -> Vec<IconGalleryItem> {
    for url in mirrors {
        if let Ok(value) = fetch_icon_gallery_json(client, lookup, url).await {
            return parse(&value);
        }
    }
    Vec::new()
}

/// 并发拉三个图库源（各自镜像回退），合并 icons（顺序 Qure → homarr → edc）。
/// 各源独立容错：一源失败不拖垮其余源；全失败 → 空 vec。**下载编排的可测核**（无缓存/无 state）。
///
/// homarr（homarr-labs/dashboard-icons，~2800 图标）是原型解锁徽标明确用的库，作第三源加入符合设计意图；
/// edc 上游 JSON 现坏（尾逗号）恒空，保留在链上——若上游修好会自动在末尾接回，不必改代码。
async fn fetch_icon_galleries<H: HttpClient, L: DnsLookup>(
    client: &H,
    lookup: &L,
) -> Vec<IconGalleryItem> {
    let (qure, homarr, edc) = tokio::join!(
        fetch_icon_source(client, lookup, QURE_ICON_MIRRORS, parse_icon_gallery),
        fetch_icon_source(client, lookup, HOMARR_ICON_MIRRORS, parse_homarr_gallery),
        fetch_icon_source(client, lookup, EDC_ICON_MIRRORS, parse_icon_gallery),
    );
    let mut merged = qure;
    merged.extend(homarr);
    merged.extend(edc);
    merged
}

/// 上游 `RULE_RESOURCES_ICON_GALLERIES`：在线图标库（**真拉取**，迁移自 上游
/// `RuleResourceManager.fetchIconGalleries`）。
///
/// 并发拉三个公开图库源（Qure + homarr + edc），各三镜像逐个回退，合并图标 → `[{name,url}]`。
/// 复用订阅同款 [`safe_redirect_fetch`]（SSRF/重定向/体积/超时 guard，公网 CDN 放行——与订阅同一路径）。
/// 进程级内存缓存 TTL 1h：避免每次开弹窗都拉网。任一源失败不致命（镜像/另一源兜底）；两源都失败返
/// `[]` —— 前端据契约降级为手动 URL 输入（`api-client.ts` `fetchIconGalleries` 明写「全失败返 []」）。
/// 恒返 `Ok(ApiResponse::ok(..))`：空集是契约内的成功态，不 err。
#[tauri::command]
pub async fn rule_resources_icon_galleries(
    state: State<'_, AppRuntime>,
) -> Result<ApiResponse<Vec<IconGalleryItem>>, ()> {
    if let Some(cached) = read_fresh_icon_cache() {
        return Ok(ApiResponse::ok(cached));
    }
    let http = state.http().clone();
    Ok(ApiResponse::ok(fetch_and_store_icon_galleries(&http).await))
}

/// 真拉一次三图库并写内存缓存。**仅缓存非空结果**：全失败（空）不写，下次即重试，不把瞬时全断卡死 1h。
/// 两个 command（惰性拉 / 强制刷新）共用，避免「缓存写入条件」分叉成两份。
async fn fetch_and_store_icon_galleries(http: &HttpRuntime) -> Vec<IconGalleryItem> {
    let items = fetch_icon_galleries(http, &SystemDnsLookup).await;
    if !items.is_empty() {
        store_icon_cache(&items);
    }
    items
}

/// 强制刷新在线图标库（「添加自定义应用」弹窗在线图标面板的「刷新」按钮）。
///
/// # 为什么刷新是「整份」而不是「单张」
///
/// 图标本体的缓存无 TTL（容量闸之外不会自己变新），所以必须有一个用户能按的强制口。粒度取整份的三条理由：
/// 1. **两层缓存必须一起作废**。用户眼里的「图标库旧了」既可能是图标本体旧、也可能是清单旧（少了新
///    收录的图标）。只清一层的按钮会在另一层旧掉时表现成「点了没用」—— 那比没有按钮更糟。
/// 2. **单张刷新没有可放的位置**。图库网格是 `max-height:150px` 的密排小格，逐格挂一个悬浮刷新按钮
///    既挤不下也会盖住图标本身；而单张「坏掉」的格子绝大多数是瞬时取图失败，重开面板即恢复，
///    不需要一个常驻控件。
/// 3. **它同时是「忘掉我浏览过什么」的清除入口**。浏览缓存会在本地留下「看过哪些图标」的痕迹
///    （见 `icon_cache` 模块的隐私记账），整份清空才对得上这个语义，逐张清没有意义。
///
/// 清完两层后**同步重拉**并返回新清单：让前端一次 IPC 拿到结果，不必「先清再查」两跳
/// （两跳之间若有别的渲染插进来，会把刚清掉的清单又填回缓存）。
#[tauri::command]
pub async fn rule_resources_refresh_icon_galleries(
    state: State<'_, AppRuntime>,
) -> Result<ApiResponse<Vec<IconGalleryItem>>, ()> {
    drop_icon_gallery_caches(state.config().dir());
    let http = state.http().clone();
    Ok(ApiResponse::ok(fetch_and_store_icon_galleries(&http).await))
}

#[cfg(test)]
pub(crate) mod icon_gallery_tests {
    use super::*;
    use polaris_net_stack::safe_redirect::{FetchInit, MinimalResponse};
    use std::collections::HashMap;
    use std::future::Future;

    /// mock HttpClient：按 URL 返回预置 (status, body)；未配置的 URL → 网络错（触发镜像回退）。
    /// 不碰宿主网络（对齐 safe_redirect.rs 的 MockFetch，但带 body 供解析）。
    ///
    /// `pub(crate)`：清单刷新的资源模块测试需要同一个 mock —— 两份 mock 会各自漂移。
    pub(crate) struct MockHttp {
        pub(crate) responses: HashMap<String, (u16, Vec<u8>)>,
    }
    impl HttpClient for MockHttp {
        fn fetch(
            &self,
            url: &str,
            _init: &FetchInit,
        ) -> impl Future<Output = Result<MinimalResponse, String>> + Send {
            let resp = self.responses.get(url).cloned();
            async move {
                match resp {
                    Some((status, body)) => Ok(MinimalResponse {
                        status,
                        location: None,
                        headers: Vec::new(),
                        body,
                    }),
                    None => Err("connection refused".to_string()),
                }
            }
        }
    }

    /// mock DnsLookup：任何 host → 公网 IP → SSRF guard 放行（guard 仍真跑，不是绕过）。
    pub(crate) struct PublicLookup;
    impl DnsLookup for PublicLookup {
        fn lookup_all(
            &self,
            _host: &str,
        ) -> impl Future<Output = Result<Vec<String>, String>> + Send {
            // 语句先行（对齐本仓既有 FixedLookup/MockLookup 写法）：body 非单一 async 块，
            // 避免 clippy::manual_async_fn 与 trait 的显式 `+ Send` bound 冲突。
            let ips = vec!["8.8.8.8".to_string()];
            async move { Ok(ips) }
        }
    }

    fn gallery_json(names: &[&str]) -> Vec<u8> {
        let icons: Vec<Value> = names
            .iter()
            .map(|n| json!({ "name": n, "url": format!("https://cdn/{n}.png") }))
            .collect();
        serde_json::to_vec(&json!({ "icons": icons })).unwrap()
    }

    fn names_of(items: &[IconGalleryItem]) -> Vec<&str> {
        items.iter().map(|i| i.name.as_str()).collect()
    }

    // ── 纯解析 ─────────────────────────────────────────────────────────────

    #[test]
    fn parse_extracts_name_url_pairs() {
        let v = json!({ "icons": [
            { "name": "A", "url": "https://x/a.png" },
            { "name": "B", "url": "https://x/b.png" },
        ]});
        let items = parse_icon_gallery(&v);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].name, "A");
        assert_eq!(items[0].url, "https://x/a.png");
        assert_eq!(items[1].name, "B");
    }

    #[test]
    fn parse_missing_icons_yields_empty_and_bad_items_skipped() {
        assert!(
            parse_icon_gallery(&json!({})).is_empty(),
            "无 icons 键 → 空"
        );
        assert!(
            parse_icon_gallery(&json!({ "icons": "notarray" })).is_empty(),
            "icons 非数组 → 空"
        );
        // 条目缺 url / 缺 name → 跳过该条，不整体失败。
        let mixed = json!({ "icons": [
            { "name": "ok", "url": "https://x/ok.png" },
            { "name": "nourl" },
            { "url": "https://x/noname.png" },
        ]});
        assert_eq!(
            names_of(&parse_icon_gallery(&mixed)),
            vec!["ok"],
            "只保留 name+url 齐全的条目"
        );
    }

    #[test]
    fn parse_homarr_strips_png_suffix_and_builds_cdn_url() {
        let v = json!({ "png": ["1panel.png", "discord.png"], "svg": ["ignore.svg"] });
        let items = parse_homarr_gallery(&v);
        assert_eq!(
            names_of(&items),
            vec!["1panel", "discord"],
            "显示名须去 .png 后缀"
        );
        assert_eq!(
            items[0].url,
            "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons@main/png/1panel.png",
            "url 须为 png 目录下的原文件名（含 .png）"
        );
        // svg 键不参与（只取 png 数组）。
        assert!(
            !items.iter().any(|i| i.name.contains("ignore")),
            "只取 png，不碰 svg/webp"
        );
    }

    #[test]
    fn parse_homarr_missing_png_or_bad_items_yields_empty_or_skips() {
        assert!(
            parse_homarr_gallery(&json!({})).is_empty(),
            "无 png 键 → 空"
        );
        assert!(
            parse_homarr_gallery(&json!({ "png": "notarray" })).is_empty(),
            "png 非数组 → 空"
        );
        // 空串 / 非字符串条目 → 跳过，不整体失败。
        let mixed = json!({ "png": ["ok.png", "", 42] });
        assert_eq!(
            names_of(&parse_homarr_gallery(&mixed)),
            vec!["ok"],
            "跳过空串/非串条目"
        );
    }

    // ── 拉取 / 回退 / 合并（mock，不碰网络）───────────────────────────────────

    #[tokio::test]
    async fn merges_both_sources_qure_first_then_edc() {
        // 变异守卫：打断 `merged.extend(edc)`（漏 edc）或交换合并顺序 → 本断言转红。
        let mut responses = HashMap::new();
        responses.insert(
            QURE_ICON_MIRRORS[0].to_string(),
            (200u16, gallery_json(&["Q1", "Q2"])),
        );
        responses.insert(
            EDC_ICON_MIRRORS[0].to_string(),
            (200u16, gallery_json(&["E1"])),
        );
        let http = MockHttp { responses };
        let items = fetch_icon_galleries(&http, &PublicLookup).await;
        assert_eq!(
            names_of(&items),
            vec!["Q1", "Q2", "E1"],
            "两源合并，Qure 在前 edc 在后（homarr 未配置 → 空，不影响顺序）"
        );
    }

    #[tokio::test]
    async fn merges_three_sources_qure_homarr_edc_in_order() {
        // 变异守卫：漏 homarr 的 extend / 合并顺序错乱 → 本断言转红。homarr 结构是 `{png:[...]}`（异于 .icons），
        // 验的是三源都进结果且 Qure → homarr → edc 顺序。
        let mut responses = HashMap::new();
        responses.insert(
            QURE_ICON_MIRRORS[0].to_string(),
            (200u16, gallery_json(&["Q1"])),
        );
        responses.insert(
            HOMARR_ICON_MIRRORS[0].to_string(),
            (
                200u16,
                serde_json::to_vec(&json!({ "png": ["h1.png", "h2.png"] })).unwrap(),
            ),
        );
        responses.insert(
            EDC_ICON_MIRRORS[0].to_string(),
            (200u16, gallery_json(&["E1"])),
        );
        let http = MockHttp { responses };
        let items = fetch_icon_galleries(&http, &PublicLookup).await;
        assert_eq!(
            names_of(&items),
            vec!["Q1", "h1", "h2", "E1"],
            "三源合并，顺序 Qure → homarr → edc；homarr 去 .png 后缀"
        );
    }

    #[tokio::test]
    async fn homarr_source_falls_back_across_its_own_mirrors() {
        // homarr 首镜像失败、次镜像成功 → homarr 仍贡献图标（复用同一 fetch_icon_source 回退链）。
        let mut responses = HashMap::new();
        responses.insert(
            HOMARR_ICON_MIRRORS[0].to_string(),
            (500u16, b"err".to_vec()),
        );
        responses.insert(
            HOMARR_ICON_MIRRORS[1].to_string(),
            (
                200u16,
                serde_json::to_vec(&json!({ "png": ["only.png"] })).unwrap(),
            ),
        );
        let http = MockHttp { responses };
        let items = fetch_icon_galleries(&http, &PublicLookup).await;
        assert_eq!(
            names_of(&items),
            vec!["only"],
            "homarr 首镜像失败须回退次镜像"
        );
    }

    #[tokio::test]
    async fn falls_back_to_next_mirror_when_first_fails() {
        // 变异守卫：把镜像循环改成「只试首个」→ 结果空 → 转红。
        let mut responses = HashMap::new();
        responses.insert(QURE_ICON_MIRRORS[0].to_string(), (500u16, b"err".to_vec()));
        responses.insert(
            QURE_ICON_MIRRORS[1].to_string(),
            (200u16, gallery_json(&["Q_M2"])),
        );
        let http = MockHttp { responses };
        let items = fetch_icon_galleries(&http, &PublicLookup).await;
        assert_eq!(names_of(&items), vec!["Q_M2"], "首镜像失败须回退次镜像");
    }

    #[tokio::test]
    async fn non_2xx_falls_back_even_with_valid_json_body() {
        // 变异守卫：删掉 2xx 状态检查 → 503 的合法 body 被误用 → 得 ["STALE"] → 转红。
        let mut responses = HashMap::new();
        responses.insert(
            QURE_ICON_MIRRORS[0].to_string(),
            (503u16, gallery_json(&["STALE"])),
        );
        responses.insert(
            QURE_ICON_MIRRORS[1].to_string(),
            (200u16, gallery_json(&["GOOD"])),
        );
        let http = MockHttp { responses };
        let items = fetch_icon_galleries(&http, &PublicLookup).await;
        assert_eq!(
            names_of(&items),
            vec!["GOOD"],
            "非 2xx 即便 body 合法也须回退，不得用其内容"
        );
    }

    #[tokio::test]
    async fn invalid_json_falls_back_to_next_mirror() {
        // 真实 edc 形态：合法 2xx 但 body 有尾逗号（非法 JSON）→ 须回退次镜像。
        let mut responses = HashMap::new();
        responses.insert(
            QURE_ICON_MIRRORS[0].to_string(),
            (200u16, b"{ \"icons\": [ , ] }".to_vec()),
        );
        responses.insert(
            QURE_ICON_MIRRORS[1].to_string(),
            (200u16, gallery_json(&["RECOVERED"])),
        );
        let http = MockHttp { responses };
        let items = fetch_icon_galleries(&http, &PublicLookup).await;
        assert_eq!(
            names_of(&items),
            vec!["RECOVERED"],
            "非法 JSON 须回退次镜像"
        );
    }

    #[tokio::test]
    async fn valid_json_without_icons_stops_no_fallthrough() {
        // 钉死 上游 语义：合法 JSON 即停（即使无 icons），不因空 icons 回退次镜像。
        // 变异守卫：把「空 icons 也回退」引入 → 会取到次镜像的 MUST_NOT_APPEAR → 转红。
        let mut responses = HashMap::new();
        responses.insert(
            QURE_ICON_MIRRORS[0].to_string(),
            (200u16, serde_json::to_vec(&json!({ "other": 1 })).unwrap()),
        );
        responses.insert(
            QURE_ICON_MIRRORS[1].to_string(),
            (200u16, gallery_json(&["MUST_NOT_APPEAR"])),
        );
        let http = MockHttp { responses };
        let items = fetch_icon_galleries(&http, &PublicLookup).await;
        assert!(items.is_empty(), "合法 JSON 即停，空 icons 不回退次镜像");
    }

    #[tokio::test]
    async fn both_sources_fail_yields_empty() {
        // 变异守卫：把「全镜像失败返空」改成返非空 → 转红（前端据空集降级手动 URL）。
        let http = MockHttp {
            responses: HashMap::new(),
        };
        let items = fetch_icon_galleries(&http, &PublicLookup).await;
        assert!(items.is_empty(), "两源全失败须返空（前端降级手动 URL）");
    }

    #[tokio::test]
    async fn one_source_fails_other_still_returns() {
        // 一源全断（Qure），另一源经末位镜像成功（edc）→ 结果只含 edc（独立容错）。
        let mut responses = HashMap::new();
        responses.insert(
            EDC_ICON_MIRRORS[2].to_string(),
            (200u16, gallery_json(&["ONLY_EDC"])),
        );
        let http = MockHttp { responses };
        let items = fetch_icon_galleries(&http, &PublicLookup).await;
        assert_eq!(
            names_of(&items),
            vec!["ONLY_EDC"],
            "Qure 全断时 edc 仍应返回"
        );
    }

    /// 「刷新」必须把**两层**缓存一起倒掉：清单内存缓存 + 图标本体的磁盘浏览缓存。
    ///
    /// 只清一层的按钮比没有按钮更糟 —— 另一层旧掉时表现成「点了没反应」。本条把
    /// `drop_icon_gallery_caches` 的这句宣称变成可证伪的（去掉任一腿即转红）。
    ///
    /// 用进程级静态缓存 ⇒ 本条是**唯一**碰它的测试，不与其他用例并发争用。
    #[test]
    fn refresh_drops_both_manifest_and_disk_caches() {
        let dir = std::env::temp_dir().join(format!(
            "polaris-icon-refresh-{}-{}",
            std::process::id(),
            now_ms()
        ));
        let browse = crate::icon_cache::remote_cache_dir(&dir);
        std::fs::create_dir_all(&browse).unwrap();
        let stub = browse.join("deadbeefdeadbeef.png");
        std::fs::write(&stub, b"\x89PNGcached").unwrap();

        store_icon_cache(&[IconGalleryItem {
            name: "stale".to_string(),
            url: "https://cdn.example.com/stale.png".to_string(),
        }]);
        // 自检：两层都得先真的「有东西」，否则下面两条断言恒绿。
        assert!(read_fresh_icon_cache().is_some(), "自检：清单缓存须先命中");
        assert!(stub.exists(), "自检：磁盘缓存文件须先在");

        drop_icon_gallery_caches(&dir);

        assert!(
            read_fresh_icon_cache().is_none(),
            "清单腿没作废 —— 重拉会命中 1h TTL 的旧清单，用户看到「刷新没用」"
        );
        assert!(!stub.exists(), "磁盘腿没清 —— 图标本体仍是旧的");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// P0-4：TTL 过期时必须**就地驱逐**那份清单，而不是只返回 `None` 把它继续留在缓存里。
    ///
    /// 只判不驱逐的后果不是「多占一会儿」：后续拉取只要持续失败就一份都不写（全失败不缓存），
    /// 那份 0.3~0.8 MiB 的旧清单便无限期驻留，而它在判过期的那一刻已经没有任何读者。
    ///
    /// 走 [`take_fresh_icon_items`] 而不是进程级静态缓存：① 后者被上面那条用例独占，本条不该去争用；
    /// ② `ttl = ZERO` 是「一切皆已过期」的跨平台构造法，不必去造一个过去的 `Instant`
    /// （Windows 上 uptime 不足 TTL 时 `Instant::checked_sub` 返回 `None`）。
    ///
    /// 牙：删掉 `take_fresh_icon_items` 里的 `*slot = None;` → 第二条断言转红；
    /// 把驱逐提到新鲜判定之前（无条件清） → 最后一条转红。
    #[test]
    fn expired_icon_cache_is_evicted_not_just_missed() {
        let item = || IconGalleryItem {
            name: "stale".to_string(),
            url: "https://cdn.example.com/stale.png".to_string(),
        };

        let mut expired = Some(IconGalleryCache {
            fetched_at: Instant::now(),
            items: vec![item()],
        });
        assert!(
            take_fresh_icon_items(&mut expired, Duration::ZERO).is_none(),
            "自检：ttl=0 必须判过期，否则下面那条断言恒绿"
        );
        assert!(
            expired.is_none(),
            "过期条目没被驱逐 —— 拉取持续失败时它会无限期驻留，且已无任何读者"
        );

        // 反向对照：未过期不得误驱逐，且照常返回内容 —— 少了这一半，「每次读都清」也能让上面全绿。
        let mut fresh = Some(IconGalleryCache {
            fetched_at: Instant::now(),
            items: vec![item()],
        });
        let got = take_fresh_icon_items(&mut fresh, ICON_GALLERY_CACHE_TTL).expect("未过期须命中");
        assert_eq!(names_of(&got), vec!["stale"], "未过期须原样返回内容");
        assert!(
            fresh.is_some(),
            "未过期不得驱逐（否则退化成「每次读都清」）"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 资源库清单刷新（catalog refresh）测试
//
// **禁止真网**：全部走 `MockHttp`（预置 URL → 响应）+ `PublicLookup`（假 DNS，SSRF guard 仍真跑）。
// 无任何一条断言依赖 `api.github.com` 可达。
// ─────────────────────────────────────────────────────────────────────────────
