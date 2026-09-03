//! 自定义应用图标本地缓存 + `polaris-icon://` scheme 服务。
//!
//! 隐私第一性：Polaris 是代理客户端。若每次渲染自定义应用图标都向图标 CDN 发请求，会
//! （a）把用户的应用清单泄露给 CDN / 网络中间人，（b）给渲染加一次网络往返延迟。故采「设定即缓存」
//! （cache-on-set，**非** cache-on-render-miss）：用户在「添加自定义应用」里确认一个在线图标时，
//! **一次性**下载到 `<userData>/icons/`，此后一律从本地副本渲染，正常渲染零出站请求。
//!
//! 两种 ref 经同一个 `polaris-icon` scheme 服务，由 host 段区分（前端 `iconProxySrc` 产出 / 透传）：
//! - `polaris-icon://c/<file>`：本地缓存文件（自定义应用设定后 preset.iconUrl 持有此 ref，渲染零网络）。
//! - `polaris-icon://i/<encoded-url>`：远端代理（在线图库浏览 / URL 面板预览 / 未迁移的旧 remote
//!   iconUrl）——经传输层单点 [`HttpRuntime`] 取；**C19**：按 `mainSessionViaProxy` 决策走 update-in
//!   socks 口（图标 CDN 被墙时经代理）vs 直连，见 [`handle_scheme_request`]。这条腿另有一层
//!   **浏览缓存**（见下节），与「设定即缓存」的正式副本严格分家。
//!
//! 内置应用 / 解锁图标是随包 SVG，由并发批次处理，**不经本模块**。

#![forbid(unsafe_code)]

use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use polaris_net_stack::safe_redirect::{safe_redirect_fetch, HttpClient, SafeRedirectFetchOptions};
use polaris_net_stack::ssrf::DnsLookup;
use serde_json::Value;
use tauri::{AppHandle, Manager, Runtime, UriSchemeResponder};

use crate::runtime::http::{
    app_user_agent, resolve_update_proxy_target, HttpRuntime, SystemDnsLookup,
};
use crate::runtime::AppRuntime;

/// scheme 名（与前端 `ui/src/domain/icon-proxy.ts` 的 `ICON_PROXY_SCHEME` 是单一真值）。
pub const ICON_PROXY_SCHEME: &str = "polaris-icon";
/// 本地缓存文件的 host 段（`polaris-icon://c/<file>`）。
const HOST_CACHE: &str = "c";
/// 远端代理的 host 段（`polaris-icon://i/<encoded-url>`，旧 `iconProxySrc` 产出形态）。
const HOST_REMOTE: &str = "i";
/// 单个图标下载 / 缓存体积硬闸（2 MiB）：图标通常 < 数十 KB，超此即拒（防滥用 / OOM）。
pub const MAX_ICON_BYTES: usize = 2 * 1024 * 1024;
/// 图标请求超时（ms）。
const ICON_TIMEOUT_MS: u64 = 10_000;
/// 图标下载重定向上限。
const MAX_ICON_REDIRECTS: usize = 4;

/// `<userData>/icons/` —— 图标缓存目录（跨平台，`config_dir` 由 Tauri app-data API 解析）。
#[must_use]
pub fn icons_dir(config_dir: &Path) -> PathBuf {
    config_dir.join("icons")
}

/// URL 是否为 http/https（大小写不敏感）。
#[must_use]
pub fn is_http_url(url: &str) -> bool {
    let lower = url.trim().to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

/// 清洗文件名 stem：仅留 `[A-Za-z0-9._-]`，其余 → `_`；消除 `..`（防路径穿越）；空则 `_`。
///
/// 镜像 `commands/rules::sanitize_file_stem`（规则资源落盘同款防线），在任何 `join` 前生效。
#[must_use]
pub fn sanitize_stem(id: &str) -> String {
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

/// 本地缓存 ref（`polaris-icon://c/<filename>`）——写进 preset.iconUrl，前端 `iconProxySrc` 原样透传。
fn cache_ref(filename: &str) -> String {
    format!("{ICON_PROXY_SCHEME}://{HOST_CACHE}/{filename}")
}

/// 扩展名 → MIME；非受支持图片扩展名 → `None`。
#[must_use]
pub fn mime_for_ext(ext: &str) -> Option<&'static str> {
    Some(match ext {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "bmp" => "image/bmp",
        "ico" => "image/x-icon",
        // LOW-3：SVG **不在**缓存白名单——见 `sniff_ext`。缓存的自定义图标一律栅格（png/jpg/webp/gif/ico）。
        _ => return None,
    })
}

/// 判定字节是否是受支持图片并返回落盘扩展名——「image only」硬门。
///
/// 魔数优先（权威；CDN 常给泛化 / 错误的 content-type），魔数没命中再采信明确的图片 content-type。
/// 非图片 → `None`（caller 拒绝缓存）。
///
/// **LOW-3：SVG 一律拒**（既不认魔数 `<?xml`/`<svg`，也不认 `image/svg+xml` content-type）。
/// SVG 是可执行文本（`<svg onload=…>`）；CSP 为 null 时，把敌意图标 URL 的 SVG 落进
/// `<userData>/icons/` 再经本 scheme 服务即潜在 stored-XSS。缓存的自定义图标一律栅格。
/// 内置图标是随包 SVG，全程由前端处理，绝不经本缓存。
#[must_use]
pub fn sniff_ext(content_type: Option<&str>, bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0x89, b'P', b'N', b'G']) {
        return Some("png");
    }
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some("jpg");
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return Some("gif");
    }
    if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return Some("webp");
    }
    if bytes.starts_with(b"BM") {
        return Some("bmp");
    }
    if bytes.starts_with(&[0x00, 0x00, 0x01, 0x00]) {
        return Some("ico");
    }
    // 魔数没命中但 content-type 明确是受支持图片类型 → 采信（SVG 不在此表，见上）。
    let ct_norm = content_type.map(|c| {
        c.split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase()
    });
    match ct_norm.as_deref() {
        Some("image/png") => Some("png"),
        Some("image/jpeg") => Some("jpg"),
        Some("image/gif") => Some("gif"),
        Some("image/webp") => Some("webp"),
        Some("image/bmp") => Some("bmp"),
        Some("image/x-icon" | "image/vnd.microsoft.icon") => Some("ico"),
        _ => None,
    }
}

/// 删掉 `icons_dir` 里所有 stem 匹配的文件（换格式重设 / 驱逐用）。
///
/// `NotFound` 表示没有缓存可删，视为成功；其余 I/O 错误返回给延迟删除日志，保证下次 Apply 可重试。
fn remove_stem_files_checked(dir: &Path, stem: &str) -> Result<(), String> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("读取图标缓存目录失败: {error}")),
    };
    let mut first_error = None;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                first_error.get_or_insert_with(|| format!("读取图标缓存条目失败: {error}"));
                continue;
            }
        };
        // 只碰文件。`icons/` 下现在有一个子目录（`remote/` 浏览缓存），而 app id 并非全由 UI 生成
        // （配置可手工编辑 / 从备份导入）——若某个 id 被 sanitize 成正好等于子目录名，没有这一判就会
        // 对目录发 remove_file。各平台都会失败、删不掉，但那是「靠 unlink 拒绝目录」的巧合式安全。
        // 一行判据把它变成结构性的：驱逐 reconcile 永远看不见浏览缓存里的任何一个字节。
        if !entry.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        let raw = entry.file_name();
        let name = raw.to_string_lossy();
        let file_stem = name.rsplit_once('.').map_or(name.as_ref(), |(s, _)| s);
        if file_stem == stem {
            if let Err(e) = std::fs::remove_file(entry.path()) {
                first_error.get_or_insert_with(|| {
                    format!("移除图标缓存失败 {}: {e}", entry.path().display())
                });
            }
        }
    }
    first_error.map_or(Ok(()), Err)
}

/// best-effort 包装，供换格式写入等非事务路径沿用；失败只记日志。
fn remove_stem_files(dir: &Path, stem: &str) {
    if let Err(error) = remove_stem_files_checked(dir, stem) {
        log::debug!("{error}");
    }
}

/// 删除单个自定义应用的全部正式图标缓存。供 Apply 延迟删除使用，失败必须返回以便持久重试。
pub(crate) fn remove_app_icon(dir: &Path, app_id: &str) -> Result<(), String> {
    remove_stem_files_checked(dir, &sanitize_stem(app_id))
}

/// 把图标字节写进 `<icons_dir>/<sanitized app_id>.<ext>`，返回本地缓存 ref。
///
/// app_id 在 `join` 前经 [`sanitize_stem`] 防穿越；换扩展名重设时先清掉旧 stem 文件防孤儿。
///
/// # Errors
///
/// 建目录 / 写文件失败。
pub fn write_icon(dir: &Path, app_id: &str, ext: &str, bytes: &[u8]) -> Result<String, String> {
    let stem = sanitize_stem(app_id);
    std::fs::create_dir_all(dir).map_err(|e| format!("建图标目录失败: {e}"))?;
    remove_stem_files(dir, &stem);
    let filename = format!("{stem}.{ext}");
    std::fs::write(dir.join(&filename), bytes).map_err(|e| format!("写图标缓存失败: {e}"))?;
    Ok(cache_ref(&filename))
}

/// 从 UserConfig 取 `customAppPresets[].id` 集合（驱逐 reconcile 的 diff 素材）。
#[must_use]
pub fn custom_app_ids(cfg: &Value) -> HashSet<String> {
    cfg.get("customAppPresets")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|p| p.get("id").and_then(Value::as_str).map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// 驱逐 reconcile：删掉「旧集有、新集无」的自定义应用图标缓存。best-effort（unlink 失败仅日志）。
///
/// 挂在配置保存的唯一汇流点（`ConfigManager::save_full`），故任何令某 app id 消失的路径
/// （删除 / 备份整类替换 / 工厂重置）都自动驱逐，无需任何屏幕调 evict 命令 —— 避免跨文件缝。
pub fn reconcile_removed(dir: &Path, old_ids: &HashSet<String>, new_ids: &HashSet<String>) {
    for removed in old_ids.difference(new_ids) {
        remove_stem_files(dir, &sanitize_stem(removed));
    }
}

// ── 远端图标浏览缓存（`polaris-icon://i/…` 腿）────────────────────────────────
//
// 「设定即缓存」管的是**已选定**的图标（`c/` 腿，渲染零出站）；`i/` 腿管的是**浏览**：在线图库一批
// 60 格同时发请求，滚完 3100 项就是几千次出站，关掉弹窗重开又来一遍。这一层给它加磁盘缓存 ——
// 出站次数降到「每个图标一辈子一次」，命中后与 `c/` 腿一样是纯读盘。
//
// **与正式副本严格分家。** 正式副本按 app id 命名、由 [`reconcile_removed`] 按 `customAppPresets`
// 的 id 差集驱逐；浏览缓存按 URL 哈希命名、只受本节的容量闸管。两者若共用同一目录同一命名域，
// 删一个自定义应用就可能连带删掉同 stem 的浏览缓存，反过来浏览缓存也会把正式目录撑到几万个文件
// （驱逐 walker 每次保存都要 read_dir 一遍）。故落在子目录 `<userData>/icons/remote/`：
//   · **子目录而非新开顶层目录** —— `icons/` 已被卸载清理与「属于 Polaris 的落盘位置」清单逐处
//     对过（见 `runtime/uninstall.rs` 模块文档），顶层多一个名字就多一处要手工同步、会漂的清单；
//     子目录随 `icons/` 一起被带走，零同步成本。
//   · **驱逐 walker 结构性看不见它** —— [`remove_stem_files`] 只 read_dir `icons/` 顶层且只碰文件
//     （见该函数里那条 `is_file` 判据），目录内容对它不存在。
//   · **服务面也不互通** —— `polaris-icon://c/<payload>` 的 payload 禁含 `/`（见 [`serve_cache`]），
//     故缓存路由无法把浏览缓存当正式副本服务出去，反之亦然。
//
// **隐私记账**：本层确实在本地留下「你在图库里看过哪些图标」的痕迹（正式副本只记你**选定**的那张）。
// 这是磁盘上的、userData 内的、不出站的痕迹；面板上的「刷新」按钮同时也是它的清除入口
// （[`clear_remote_cache`] 整份删）。这也是刷新粒度取「整份」而非「单张」的理由之一。

/// 浏览缓存子目录名（相对 [`icons_dir`]）。
const REMOTE_CACHE_SUBDIR: &str = "remote";

/// 浏览缓存磁盘上限（16 MiB）。**只设上限、不设 TTL** —— 取舍如下。
///
/// 无界增长是真实的：图库约 3100 项、单图 5–50 KB，全滚一遍约 60 MB，且永不回收。16 MiB ≈ 800 张，
/// 恰好托住「反复看的那几屏 + 搜索命中的那些」，而不是把整个图库镜像到本地。
///
/// 为什么不再叠一个 TTL：图标变旧只是**观感**问题（CDN 用的是 `@main` 移动 ref，图确实会变），
/// 而它已经有显式解药 —— 面板上的「刷新」整份清掉重拉。再加 TTL 就是第二套驱逐规则，外加两套
/// 规则的交互（TTL 扫和容量扫谁先谁后、会不会互相把对方刚写的条目扫掉），换来的只是「用户没点
/// 刷新时图标也会自己变新」。无界磁盘占用才是必须堵的洞，故只留这一条。
const REMOTE_CACHE_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// 越过上限后回落到的水位（上限的 75%）。留这段迟滞是为了避免「每写一张都恰好压线、每写一张都扫」。
const REMOTE_CACHE_TARGET_BYTES: u64 = 12 * 1024 * 1024;

/// 浏览缓存落盘用的扩展名全集 = [`sniff_ext`] 的全部可能返回值。
///
/// 读取时只由 URL 算得出 stem（哈希），扩展名未知 ⇒ 按本表逐个试开。少列一项的后果是该格式**永远
/// 缓存未命中**（退回今天的逐次出站），绝不会错服务成别的类型 —— MIME 始终由 [`mime_for_ext`]
/// 这唯一一份白名单决定。SVG 不在此列，与 `sniff_ext` / `mime_for_ext` 同一条 LOW-3 口径。
const REMOTE_CACHE_EXTS: &[&str] = &["png", "jpg", "gif", "webp", "bmp", "ico"];

/// `<userData>/icons/remote/` —— 远端图标浏览缓存目录（与正式副本分家，理由见上节）。
#[must_use]
pub fn remote_cache_dir(config_dir: &Path) -> PathBuf {
    icons_dir(config_dir).join(REMOTE_CACHE_SUBDIR)
}

/// 远端 URL → 浏览缓存文件 stem（16 位十六进制）。
///
/// 用 stdlib 的 `DefaultHasher`（固定 key 的 SipHash，同一 Rust 版本内确定，非 `RandomState` 的
/// 每进程随机种子）而**不引入 sha2**：这个哈希不承担任何安全职责 —— 落盘的字节仍逐一过
/// [`sniff_ext`] 的 image-only 门，撞哈希最坏只是图库里某一格显示成另一张图（用户点选后
/// `cache_app_icon` 拿的是真 URL，正式副本不受影响）。64 位对几千个 URL 的碰撞概率约 1e-15，
/// 不值得为它多一个 crate。代价：Rust 换算法时全部缓存一次性冷启 —— 自愈（miss → 重拉，
/// 旧文件被容量闸扫走），不产生错误结果。
fn remote_cache_key(url: &str) -> String {
    let mut h = DefaultHasher::new();
    url.hash(&mut h);
    format!("{:016x}", h.finish())
}

/// 读浏览缓存 → `(mime, bytes)`；未命中 / 读失败 → `None`（调用方回落出站拉取）。
fn read_remote_cache(dir: &Path, url: &str) -> Option<(&'static str, Vec<u8>)> {
    let key = remote_cache_key(url);
    for ext in REMOTE_CACHE_EXTS {
        let Ok(bytes) = std::fs::read(dir.join(format!("{key}.{ext}"))) else {
            continue;
        };
        // 空文件按未命中处理：写盘走 tmp+rename，正常不会留半截文件，但真留下了也不该把 0 字节
        // 当图片喂给 webview —— 那会是个永久生效的坏格子，除了「刷新」没有别的出路。
        if !bytes.is_empty() {
            return mime_for_ext(ext).map(|m| (m, bytes));
        }
    }
    None
}

/// 容量闸：目录总字节越过 [`REMOTE_CACHE_MAX_BYTES`] 时，按**写入时间**从旧到新删到
/// [`REMOTE_CACHE_TARGET_BYTES`] 以下。best-effort，任何一步失败只是少删几个文件。
///
/// 排序用 mtime 而非 atime ⇒ 这是 FIFO 不是真 LRU：现代文件系统默认 relatime/noatime，读取根本
/// 不更新 atime，拿它排序等于拿一个不动的数排序（会把「一直在被读的热条目」当最冷的删掉）。
/// FIFO 对本场景够用 —— 浏览缓存的价值在「同一次 / 下一次浏览重复看同几屏」，那些条目本来就是
/// 最近写入的。
///
/// 每次写盘后跑一次，不加节流：写只发生在**未命中**时，重复浏览全是命中（零写、零扫）。首次滚一遍
/// 图库确实会连扫几十次，但那时目录条目数还远不到上限，一次 read_dir + stat 的代价可忽略；
/// 加节流要引入进程级状态，换来的收益不抵那份状态本身。
fn sweep_remote_cache(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<(std::time::SystemTime, u64, PathBuf)> = Vec::new();
    let mut total: u64 = 0;
    for entry in entries.flatten() {
        let Ok(md) = entry.metadata() else { continue };
        if !md.is_file() {
            continue;
        }
        total += md.len();
        files.push((
            md.modified().unwrap_or(std::time::UNIX_EPOCH),
            md.len(),
            entry.path(),
        ));
    }
    if total <= REMOTE_CACHE_MAX_BYTES {
        return;
    }
    files.sort_by_key(|(mtime, _, _)| *mtime);
    for (_, len, path) in files {
        if total <= REMOTE_CACHE_TARGET_BYTES {
            break;
        }
        if std::fs::remove_file(&path).is_ok() {
            total -= len;
        }
    }
    log::debug!("图标浏览缓存扫尾后约 {total} 字节 dir={}", dir.display());
}

/// 把远端图标字节写进浏览缓存（`<dir>/<url 哈希>.<ext>`），写完顺带跑一次容量闸。
///
/// **tmp + rename 而非直接写终名**：同一张图会被两处同时请求（图库格子 + URL 面板预览 + 旧 preset
/// 渲染），两个写者直接写同一个终名会让字节交错，落下一个此后永远命中的坏文件；rename 在同盘上是
/// 原子替换，最差只是后写者赢。进程崩在写一半同理 —— 半截字节只留在 tmp 上，读路径看不见。
///
/// # Errors
///
/// 建目录 / 写 tmp / rename 失败。调用方按 best-effort 处理：缓存写不进不影响本次渲染。
fn write_remote_cache(dir: &Path, url: &str, ext: &str, bytes: &[u8]) -> Result<(), String> {
    let key = remote_cache_key(url);
    std::fs::create_dir_all(dir).map_err(|e| format!("建图标浏览缓存目录失败: {e}"))?;
    // tmp 名带纳秒：两个并发写者不能共用同一个 tmp，否则交错问题只是从终名挪到了 tmp 上。
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let tmp = dir.join(format!("{key}.{nanos}.tmp"));
    std::fs::write(&tmp, bytes).map_err(|e| format!("写图标浏览缓存失败: {e}"))?;
    // 同一 URL 换了格式（CDN 把 png 换成 webp）时先清旧扩展名：否则读路径按 REMOTE_CACHE_EXTS
    // 的顺序会先撞上那个旧文件，缓存就永远回不到新图。tmp 的 stem 是 `<key>.<nanos>`，不会误删自己。
    remove_stem_files(dir, &key);
    std::fs::rename(&tmp, dir.join(format!("{key}.{ext}"))).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("图标浏览缓存 rename 失败: {e}")
    })?;
    sweep_remote_cache(dir);
    Ok(())
}

/// 整份清空浏览缓存 —— 面板「刷新」的磁盘腿，同时也是「忘掉我浏览过什么」的清除入口。
/// best-effort：目录本来就不存在（从没浏览过）不是错误，不记日志。
pub fn clear_remote_cache(dir: &Path) {
    match std::fs::remove_dir_all(dir) {
        Ok(()) => log::debug!("图标浏览缓存已清空 {}", dir.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => log::debug!("清空图标浏览缓存失败 {}: {e}", dir.display()),
    }
}

/// 下载并校验一个远端图标，返回 `(落盘扩展名, 字节)`。逐跳 SSRF guard、限体积、image-only 门。
///
/// **HIGH-1（SSRF）**：走与订阅（[`preview_core`](crate::commands::subscription)）/ 规则资源
/// （[`fetch_resource_bytes`](crate::commands::rules)）**同一条**安全路径
/// [`safe_redirect_fetch`]——首 URL + 每个 `Location` 跳都过 `assert_host_allowed`
/// （169.254/16 云元数据、127/8 回环、RFC1918、CGNAT、`::1`、ULA、v4-mapped，含 DNS-rebinding
/// 逐 IP 判定）。**绝不**自管重定向循环（那条旧路径既不检首 URL 也不检跳目标 = SSRF 绕过）。
/// 协议在 fetch 前即限 http(s)。`exempt_fake_ip=false`（图标直连，非经代理）。
///
/// 泛型注入 `client`/`lookup`（镜像 rules/subscription）：生产传 [`HttpRuntime`]
/// + [`SystemDnsLookup`]；门测传真 client（resolve 钉回环）+ mock lookup（真 socket，不碰宿主网络）。
///
/// # Errors
///
/// 协议非 http/https、SSRF guard 命中、超重定向上限、HTTP 非 2xx、响应空、或内容非受支持图片格式。
pub async fn fetch_image<H: HttpClient, L: DnsLookup>(
    client: &H,
    lookup: &L,
    url: &str,
    max_bytes: usize,
) -> Result<(&'static str, Vec<u8>), String> {
    let url = url.trim();
    // 协议在 fetch 前即限 http(s)（拒 file/data/gopher…）；safe_redirect_fetch 契约要求调用方保证首跳协议。
    if !is_http_url(url) {
        return Err(format!("图标 URL 协议不支持（仅 http/https）: {url}"));
    }
    // 逐跳 SSRF guard + 体积闸 + 超时 + 手动重定向，返回终态响应正文。重定向由 helper 独占管理。
    let resp = safe_redirect_fetch(SafeRedirectFetchOptions {
        fetch_impl: client,
        url,
        user_agent: app_user_agent(),
        headers: None,
        exempt_fake_ip: false,
        max_redirects: Some(MAX_ICON_REDIRECTS),
        timeout_ms: Some(ICON_TIMEOUT_MS),
        max_body_bytes: Some(max_bytes),
        lookup,
    })
    .await
    .map_err(|e| e.message)?;

    if !(200..300).contains(&resp.status) {
        return Err(format!("图标下载 HTTP {}", resp.status));
    }
    if resp.body.is_empty() {
        return Err("图标响应体为空".to_string());
    }
    let ct = resp.header("content-type").map(str::to_string);
    let ext = sniff_ext(ct.as_deref(), &resp.body)
        .ok_or_else(|| "下载内容不是受支持的图片格式".to_string())?;
    Ok((ext, resp.body))
}

// ── scheme 服务 ──────────────────────────────────────────────────────────────

/// 请求路由：本地缓存 or 远端代理。
enum Route {
    /// `polaris-icon://c/<filename>` → 读 `<icons_dir>/<filename>`。
    Cache(String),
    /// `polaris-icon://i/<encoded-url>` → 拉取远端（预览 / 旧 remote iconUrl）。
    Remote(String),
}

/// 解析 `polaris-icon://` 请求 URI 到路由。跨平台鲁棒：
/// - macOS/Linux：自定义 scheme 形态 `polaris-icon://<mode>/<payload>` → mode 在 host 段；
/// - Windows（wry 把自定义 scheme 映射成 `http://polaris-icon.localhost/...`）→ mode 是首个 path 段。
fn parse_route(uri: &tauri::http::Uri) -> Option<Route> {
    let host = uri.host().unwrap_or("");
    let path = uri.path().trim_start_matches('/');
    let (mode, payload): (&str, &str) = if host == HOST_CACHE || host == HOST_REMOTE {
        (host, path)
    } else {
        path.split_once('/')?
    };
    match mode {
        HOST_CACHE => Some(Route::Cache(payload.to_string())),
        HOST_REMOTE => Some(Route::Remote(percent_decode(payload))),
        _ => None,
    }
}

/// 最小 percent-decode（`encodeURIComponent` 逆运算：仅解 `%XX`，无 `+`→空格 语义）。零依赖。
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hi = (b[i + 1] as char).to_digit(16);
            let lo = (b[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// 读本地缓存文件 → `(mime, bytes)`。路径穿越硬防 + 扩展名白名单；越界 / 缺失 / 非图片 → `None`。
fn serve_cache(dir: &Path, payload: &str) -> Option<(&'static str, Vec<u8>)> {
    if payload.is_empty()
        || payload.contains('/')
        || payload.contains('\\')
        || payload.contains("..")
    {
        return None;
    }
    let (stem, ext) = payload.rsplit_once('.')?;
    let ext = ext.to_ascii_lowercase();
    let mime = mime_for_ext(&ext)?;
    // stem 再 sanitize（纵深防御，即便 payload 被构造）。
    let safe = format!("{}.{}", sanitize_stem(stem), ext);
    let bytes = std::fs::read(dir.join(&safe)).ok()?;
    Some((mime, bytes))
}

/// 自定义 scheme 的响应必须带 CORS 放行头，否则 WKWebView 侧属**跨 origin 子资源**：
/// 页面 origin 是 `tauri://localhost`，`polaris-icon://` 是另一个 scheme ⇒ 另一个 origin。
/// 依据不是推测——Tauri 自己的三个 protocol（`protocol/asset.rs`、`protocol/tauri.rs`、
/// `ipc/protocol.rs`）**每一条出口**（含 403/404/500）都无条件带这个头；本 handler 六条出口
/// 原先一条都没有。取 `*` 而非精确 window origin：本 scheme 只有本进程 webview 能解析，
/// 外部页面拿不到该 scheme 的加载能力，放宽无实际暴露面，且省掉把 origin 串进 handler 的接线。
const CORS_ALLOW_ORIGIN: (&str, &str) = ("Access-Control-Allow-Origin", "*");

fn ok_response(mime: &str, bytes: Vec<u8>) -> tauri::http::Response<Vec<u8>> {
    tauri::http::Response::builder()
        .status(200)
        .header(tauri::http::header::CONTENT_TYPE, mime)
        .header(CORS_ALLOW_ORIGIN.0, CORS_ALLOW_ORIGIN.1)
        // no-cache：渲染每次回读本地磁盘（仍零网络），换图标即时生效不吃陈旧缓存。
        .header(tauri::http::header::CACHE_CONTROL, "no-cache")
        .body(bytes)
        .unwrap_or_else(|_| tauri::http::Response::new(Vec::new()))
}

fn status_response(code: u16, msg: &str) -> tauri::http::Response<Vec<u8>> {
    tauri::http::Response::builder()
        .status(code)
        .header(
            tauri::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )
        // 失败出口同样要带：CORS 被拒时 webview 连状态码都读不到，`onerror` 之外无任何线索。
        .header(CORS_ALLOW_ORIGIN.0, CORS_ALLOW_ORIGIN.1)
        .body(msg.as_bytes().to_vec())
        .unwrap_or_else(|_| tauri::http::Response::new(Vec::new()))
}

/// `polaris-icon` scheme 处理入口（main.rs 的 `register_asynchronous_uri_scheme_protocol` 委托到此）。
///
/// 缓存路由同步读盘即应答；远端路由 spawn 到 tauri async runtime 拉取后应答（不阻塞 webview）。
pub fn handle_scheme_request<R: Runtime>(
    app: AppHandle<R>,
    uri: tauri::http::Uri,
    responder: UriSchemeResponder,
) {
    // 入口先记一条：**「没有失败日志」此前被当成「请求根本没进来」用作分叉判据，那是错的** ——
    // 本函数的 400/404/503 与 200 四条出口原先一个字都不写，只有远端腿的两处 warn 有声音。
    // 于是「图标一片空白 + 零日志」既可能是 scheme 没被调用，也可能是它被调用后静默 400 了，
    // 两者的修法完全不同（2026-07-29 真机排查在此空转一轮）。入口日志把这个歧义一次性消掉。
    log::debug!("图标 scheme 请求: {uri}");
    let Some(route) = parse_route(&uri) else {
        // warn 而非 debug：URI 解析不了 = 该图标必然渲染成空白，是用户可见失败。
        log::warn!("图标请求 URI 解析失败（400）: {uri}");
        responder.respond(status_response(400, "bad icon request"));
        return;
    };
    let Some(rt) = app.try_state::<AppRuntime>() else {
        log::warn!("图标请求时 AppRuntime 尚不可用（503）: {uri}");
        responder.respond(status_response(503, "runtime unavailable"));
        return;
    };
    let dir = icons_dir(rt.config().dir());
    match route {
        Route::Cache(filename) => match serve_cache(&dir, &filename) {
            Some((mime, bytes)) => {
                log::debug!("图标缓存命中 {filename}（{} 字节）", bytes.len());
                responder.respond(ok_response(mime, bytes))
            }
            None => {
                log::warn!("图标缓存未命中（404）file={filename} dir={}", dir.display());
                responder.respond(status_response(404, "icon not cached"))
            }
        },
        Route::Remote(remote_url) => {
            // 浏览缓存优先：命中即纯读盘应答，零出站。在线图库一批 60 格同时发请求、退出重进又来
            // 一遍，没有这一层每次都是真出站（见「远端图标浏览缓存」一节）。命中路径与 `c/` 腿同形
            // （同步读盘、同一对构造器出口），未命中才落到下面那条真取图管线。
            let cache_dir = remote_cache_dir(rt.config().dir());
            if let Some((mime, bytes)) = read_remote_cache(&cache_dir, &remote_url) {
                log::debug!("图标浏览缓存命中 {remote_url}（{} 字节）", bytes.len());
                responder.respond(ok_response(mime, bytes));
                return;
            }
            // C19：远端图标代理（icon-protocol）按 mainSessionViaProxy 决策走 update-in socks 口 vs 直连
            // （= Polaris icon-protocol 喂 resolveUpdateProxyTarget）。核在跑 + msvp 未显式关 + update-in 口有效
            // → 经代理（图标 CDN 被墙时仍可取）；否则直连（自举友好）。msvp 从裸 config 读（config-engine
            // UserConfig 增量子集未建模此字段），缺省视为开。
            let status = rt.proxy().status();
            let msvp = rt
                .config()
                .current()
                .ok()
                .and_then(|c| c.get("mainSessionViaProxy").and_then(Value::as_bool));
            let (via_proxy, port) =
                resolve_update_proxy_target(status.running, msvp, status.update_in_port);
            let direct = rt.http().clone();
            // async 闭包仅捕获 owned 值（client/remote_url/responder），不借用 rt/app → 无生命周期冲突。
            tauri::async_runtime::spawn(async move {
                // 经代理时新建 update-in socks client；建失败**回落直连**（不因端口异常整个请求失败）。
                // **必须是 `via_local_socks_proxy`**：`update-in` 是 sing-box `type:"socks"` 入站，
                // 此前误用 `via_local_proxy`（`http://`）→ 首字节对不上必断连 → 经代理取图标恒失败
                // （被下面的 502 分支吞成「图标取不到」，看不出是 scheme 错）。
                let proxied: Option<Arc<HttpRuntime>> = if via_proxy {
                    match HttpRuntime::via_local_socks_proxy(port) {
                        Ok(c) => Some(Arc::new(c)),
                        Err(e) => {
                            // warn 而非 debug：默认级别是 INFO ⇒ 用户看到的是「一片空白图标」，
                            // 而日志里一个字都没有（2026-07-29 真机排查即卡在这里，只能靠反证网络）。
                            // 图标取不到是**用户可见**的失败，不该沉在 debug 级。
                            log::warn!(
                                "图标经 update-in 口 client 建失败（回落直连）port={port}: {e}"
                            );
                            None
                        }
                    }
                } else {
                    None
                };
                let client: &HttpRuntime = proxied.as_deref().unwrap_or(direct.as_ref());
                log::debug!("图标远端代理开始 via_proxy={via_proxy} port={port} url={remote_url}");
                match fetch_image(client, &SystemDnsLookup, &remote_url, MAX_ICON_BYTES).await {
                    Ok((ext, bytes)) => {
                        let mime = mime_for_ext(ext).unwrap_or("application/octet-stream");
                        log::debug!(
                            "图标远端代理成功 {remote_url}（{} 字节 .{ext}）",
                            bytes.len()
                        );
                        // 落浏览缓存供下次命中。best-effort：磁盘满 / 只读也不该让这次渲染失败
                        // （用户看到的是图标，不是缓存），故只记 debug 不改应答。
                        if let Err(e) = write_remote_cache(&cache_dir, &remote_url, ext, &bytes) {
                            log::debug!("图标浏览缓存写入失败（不影响本次渲染）{remote_url}: {e}");
                        }
                        responder.respond(ok_response(mime, bytes));
                    }
                    Err(e) => {
                        // 同上：可见失败必须可诊断。带上 URL 与错误原文，一条日志即可定位是
                        // DNS / 内网守卫 / HTTP 状态 / 体积超限里的哪一条。
                        log::warn!("图标远端代理失败 {remote_url}: {e}");
                        responder.respond(status_response(502, "icon fetch failed"));
                    }
                }
            });
        }
    }
}

#[cfg(test)]
mod tests;
