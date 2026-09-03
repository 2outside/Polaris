use super::*;
use crate::commands::guard_scan::top_level_fn_body;
use crate::test_support::{crate_code, TestDir};
use std::future::Future;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::thread;

use crate::runtime::http::HttpRuntime;

/// mock `DnsLookup`：把任意 hostname 钉到指定 IP（放行/拒绝由该 IP 是否内网决定）。
/// 镜像 `commands/rules.rs` 的同名门用 helper——真 socket 门测里解耦「client 落点」与「guard 判定对象」。
struct FixedLookup(&'static str);
impl DnsLookup for FixedLookup {
    fn lookup_all(&self, _host: &str) -> impl Future<Output = Result<Vec<String>, String>> + Send {
        let ip = self.0.to_string();
        async move { Ok(vec![ip]) }
    }
}

fn temp_dir(tag: &str) -> TestDir {
    TestDir::new(&format!("polaris-icon-test-{tag}-"))
}

// ── sanitize / 路径穿越门 ────────────────────────────────────────────────

#[test]
fn sanitize_stem_blocks_path_traversal() {
    for evil in ["../../etc/passwd", "..\\..\\win", "a/b/c", "..", "....//"] {
        let s = sanitize_stem(evil);
        assert!(!s.contains('/'), "sanitize 后不得含斜杠: {s}");
        assert!(!s.contains('\\'), "sanitize 后不得含反斜杠: {s}");
        assert!(!s.contains(".."), "sanitize 后不得含 ..: {s}");
        assert!(!s.is_empty(), "sanitize 后不得为空");
    }
}

#[test]
fn sanitize_stem_keeps_valid_custom_id() {
    assert_eq!(sanitize_stem("custom-abc123"), "custom-abc123");
    assert_eq!(
        sanitize_stem("custom-lx9k2.foo_bar"),
        "custom-lx9k2.foo_bar"
    );
}

// ── 缓存写盘门（本地字节，零网络）────────────────────────────────────────

#[test]
fn write_icon_writes_file_and_returns_local_ref() {
    let dir = temp_dir("write");
    let png = [0x89, b'P', b'N', b'G', 1, 2, 3, 4];
    let r = write_icon(&dir, "custom-abc", "png", &png).expect("写图标应成功");
    assert_eq!(r, "polaris-icon://c/custom-abc.png", "ref 格式须稳定一致");
    let on_disk = std::fs::read(dir.join("custom-abc.png")).expect("落盘文件应可读");
    assert_eq!(on_disk, png, "落盘字节须与写入逐字节相同");
}

#[test]
fn write_icon_replaces_old_extension_on_recache() {
    let dir = temp_dir("recache");
    write_icon(&dir, "custom-x", "png", b"\x89PNGold").unwrap();
    // 同 id 换成 webp（栅格）：旧 .png 必须被清掉，避免孤儿。
    let r = write_icon(&dir, "custom-x", "webp", b"RIFF\0\0\0\0WEBPx").unwrap();
    assert_eq!(r, "polaris-icon://c/custom-x.webp");
    assert!(
        !dir.join("custom-x.png").exists(),
        "换格式重设后旧扩展名文件须清除"
    );
    assert!(dir.join("custom-x.webp").exists());
}

#[test]
fn write_icon_sanitizes_traversal_id_before_join() {
    let dir = temp_dir("evilid");
    // 恶意 id：sanitize 后必须落在 dir 内，绝不逃逸。
    let r = write_icon(&dir, "../../evil", "png", b"\x89PNG").unwrap();
    // ref 里不含斜杠段（除 scheme 的 //）。
    let filename = r.strip_prefix("polaris-icon://c/").expect("ref 前缀");
    assert!(!filename.contains(".."), "文件名不得含 ..: {filename}");
    // 逃逸目标不得存在。
    assert!(
        !dir.parent().unwrap().join("evil.png").exists(),
        "绝不得写到父目录"
    );
}

// ── 驱逐 reconcile 门（本地 FS，零网络）──────────────────────────────────

#[test]
fn reconcile_removed_unlinks_only_removed_ids() {
    let dir = temp_dir("evict");
    write_icon(&dir, "custom-keep", "png", b"\x89PNG").unwrap();
    write_icon(&dir, "custom-drop", "png", b"\x89PNG").unwrap();

    let old: HashSet<String> = ["custom-keep", "custom-drop"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let new: HashSet<String> = ["custom-keep"].iter().map(|s| s.to_string()).collect();
    reconcile_removed(&dir, &old, &new);

    assert!(dir.join("custom-keep.png").exists(), "保留项缓存不得被删");
    assert!(!dir.join("custom-drop.png").exists(), "移除项缓存须被驱逐");
}

#[test]
fn reconcile_on_missing_dir_is_noop_not_panic() {
    let dir = temp_dir("evict-missing");
    let missing = dir.join("nope");
    let old: HashSet<String> = ["a"].iter().map(|s| s.to_string()).collect();
    reconcile_removed(&missing, &old, &HashSet::new()); // 不 panic。
}

#[test]
fn custom_app_ids_extracts_ids() {
    let cfg = serde_json::json!({
        "customAppPresets": [{ "id": "a", "name": "A" }, { "id": "b" }, { "name": "no-id" }]
    });
    let ids = custom_app_ids(&cfg);
    assert_eq!(ids.len(), 2);
    assert!(ids.contains("a") && ids.contains("b"));
    assert!(custom_app_ids(&serde_json::json!({})).is_empty());
}

// ── 远端浏览缓存门（本地 FS，零网络）────────────────────────────────────
// 关注三件事：①「读得回来且逐字节一致」②「与正式副本的驱逐互不越界」③「容量闸真的会驱逐」。

/// 造一个 `len` 字节的合法 PNG（魔数 + 填充），用于容量闸的体积算术。
fn png_of(len: usize) -> Vec<u8> {
    let mut v = vec![0x89, b'P', b'N', b'G'];
    v.resize(len.max(4), b'x');
    v
}

#[test]
fn remote_cache_roundtrip_and_key_is_per_url() {
    let dir = temp_dir("remote-rt");
    let url_a = "https://cdn.example.com/a.png";
    let url_b = "https://cdn.example.com/b.png";
    assert!(read_remote_cache(&dir, url_a).is_none(), "写之前必须未命中");

    write_remote_cache(&dir, url_a, "png", b"\x89PNGaaa").unwrap();
    let (mime, bytes) = read_remote_cache(&dir, url_a).expect("写完必须命中");
    assert_eq!(mime, "image/png");
    assert_eq!(bytes, b"\x89PNGaaa", "读回字节须与写入逐字节相同");

    // 不同 URL 不得互相命中（键就是 URL）。
    assert!(
        read_remote_cache(&dir, url_b).is_none(),
        "另一个 URL 不得命中 A 的缓存"
    );
    // 同一 URL 的键稳定 —— 否则每次渲染都写一个新文件，缓存等于不存在。
    assert_eq!(remote_cache_key(url_a), remote_cache_key(url_a));
    assert_ne!(remote_cache_key(url_a), remote_cache_key(url_b));
    // 落盘名不含路径分隔符（哈希是纯十六进制），join 前无穿越面。
    let k = remote_cache_key(url_a);
    assert_eq!(k.len(), 16);
    assert!(
        k.chars().all(|c| c.is_ascii_hexdigit()),
        "键须是纯十六进制: {k}"
    );
}

#[test]
fn remote_cache_replaces_stale_extension() {
    let dir = temp_dir("remote-ext");
    let url = "https://cdn.example.com/x";
    write_remote_cache(&dir, url, "png", b"\x89PNGold").unwrap();
    // CDN 换了格式：旧扩展名必须清掉，否则读路径按 REMOTE_CACHE_EXTS 顺序先撞旧 png，永远回不到新图。
    write_remote_cache(&dir, url, "webp", b"RIFF\0\0\0\0WEBPnew").unwrap();
    let (mime, bytes) = read_remote_cache(&dir, url).expect("应命中新格式");
    assert_eq!(mime, "image/webp");
    assert_eq!(bytes, b"RIFF\0\0\0\0WEBPnew");
    let key = remote_cache_key(url);
    assert!(
        !dir.join(format!("{key}.png")).exists(),
        "换格式后旧扩展名文件须清除"
    );
}

#[test]
fn remote_cache_write_leaves_no_tmp_behind() {
    // tmp+rename 的 tmp 不得残留：残留会被容量闸算进总量，还会污染 read_dir。
    let dir = temp_dir("remote-tmp");
    write_remote_cache(&dir, "https://cdn.example.com/t.png", "png", b"\x89PNGt").unwrap();
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "不得残留 tmp 文件: {leftovers:?}");
}

#[test]
fn remote_cache_empty_file_counts_as_miss() {
    // 半截 / 空文件若被当成命中，就是一个只有「刷新」能救的永久坏格子。
    let dir = temp_dir("remote-empty");
    let url = "https://cdn.example.com/e.png";
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("{}.png", remote_cache_key(url))), b"").unwrap();
    assert!(
        read_remote_cache(&dir, url).is_none(),
        "0 字节须按未命中处理"
    );
}

#[test]
fn remote_cache_sweep_evicts_oldest_until_under_target() {
    let dir = temp_dir("remote-sweep");
    // 每张 1 MiB，写到越过 16 MiB 上限；容量闸应把总量压到 12 MiB 以下。
    let one_mib = 1024 * 1024;
    let n = (REMOTE_CACHE_MAX_BYTES / one_mib) as usize + 2; // 18 张 = 18 MiB
    for i in 0..n {
        write_remote_cache(
            &dir,
            &format!("https://cdn.example.com/{i}.png"),
            "png",
            &png_of(one_mib as usize),
        )
        .unwrap();
        // mtime 分辨率在部分文件系统上只到秒/毫秒级，靠写入顺序区分先后需要一点间隔；
        // 这里只需保证「不是全部同一时刻」，容量闸的 sort 才有可判的先后。
        std::thread::sleep(std::time::Duration::from_millis(12));
    }
    let total: u64 = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .filter_map(|e| e.metadata().ok())
        .filter(|m| m.is_file())
        .map(|m| m.len())
        .sum();
    // 断言的是**不变式**（总量恒不超上限），不是「扫完那一刻的水位」：扫只在越线时触发，
    // 之后又写了几张，落回上限与目标水位之间是正常的。写成「≤ 目标水位」会把正常行为判红。
    assert!(
        total <= REMOTE_CACHE_MAX_BYTES,
        "容量闸失效：总量越过上限，实得 {total}"
    );
    // 而且必须**真的删过东西** —— 光有上限断言，一个从不写盘的实现也能绿。
    assert!(
        total < (n as u64) * one_mib,
        "没有任何条目被驱逐（写了 {n} MiB，仍剩 {total}）"
    );
    // 驱逐从旧到新：最早的那张该没了，最后写的那张必须还在（把刚写的删掉等于缓存永不命中）。
    let oldest = remote_cache_key("https://cdn.example.com/0.png");
    assert!(
        !dir.join(format!("{oldest}.png")).exists(),
        "最早写入的条目应先被驱逐"
    );
    let newest = remote_cache_key(&format!("https://cdn.example.com/{}.png", n - 1));
    assert!(
        dir.join(format!("{newest}.png")).exists(),
        "最新写入的条目不得被驱逐"
    );
}

/// **隔离门**：浏览缓存不受「设定即缓存」那套 id 差集驱逐（`reconcile_removed`）影响 ——
/// 含 app id 恰好等于子目录名 `remote` 这个刁钻情形（配置可手工编辑 / 从备份导入，id 不全由 UI 生成）。
#[test]
fn reconcile_never_touches_remote_browse_cache() {
    let dir = temp_dir("iso");
    let icons = icons_dir(&dir);
    let browse = remote_cache_dir(&dir);
    let url = "https://cdn.example.com/g.png";
    write_icon(&icons, "custom-drop", "png", b"\x89PNG").unwrap();
    write_remote_cache(&browse, url, "png", b"\x89PNGg").unwrap();

    // 最狠的一次 reconcile：三个 id 全当成已移除 ——
    //  · `custom-drop`：正常的正式副本，用来证明驱逐本身没瘫（否则本门是在测一个已瘫的驱逐）；
    //  · `remote`：与浏览缓存子目录同名（配置可手工编辑 / 从备份导入，id 不全由 UI 生成）；
    //  · 浏览缓存条目的**文件名 stem 本身**：这条钉的是「两者不在同一个目录」这个决定 ——
    //    若哪天把浏览缓存并进 `icons/` 顶层，这个 id 会让驱逐正好命中它，本门立刻转红。
    let old: HashSet<String> = ["custom-drop", "remote", &remote_cache_key(url)]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    reconcile_removed(&icons, &old, &HashSet::new());

    assert!(
        !icons.join("custom-drop.png").exists(),
        "正式副本仍须被正常驱逐（否则本门是在测一个已瘫的驱逐）"
    );
    assert!(browse.is_dir(), "浏览缓存目录不得被驱逐删掉");
    let (_, bytes) = read_remote_cache(&browse, url).expect("浏览缓存条目不得被 id 差集驱逐误伤");
    assert_eq!(bytes, b"\x89PNGg");
}

/// 反向隔离：`polaris-icon://c/…` 的缓存服务够不着浏览缓存子目录（payload 禁含 `/`）。
#[test]
fn serve_cache_cannot_reach_into_remote_subdir() {
    let dir = temp_dir("iso-serve");
    let icons = icons_dir(&dir);
    let browse = remote_cache_dir(&dir);
    let url = "https://cdn.example.com/s.png";
    write_remote_cache(&browse, url, "png", b"\x89PNGs").unwrap();
    let key = remote_cache_key(url);
    assert!(serve_cache(&icons, &format!("remote/{key}.png")).is_none());
    assert!(serve_cache(&icons, &format!("../{}/remote/{key}.png", icons.display())).is_none());
    assert!(
        serve_cache(&icons, &format!("{key}.png")).is_none(),
        "顶层无此文件"
    );
}

#[test]
fn clear_remote_cache_wipes_everything_and_tolerates_missing_dir() {
    let dir = temp_dir("remote-clear");
    let url = "https://cdn.example.com/c.png";
    write_remote_cache(&dir, url, "png", b"\x89PNGc").unwrap();
    assert!(read_remote_cache(&dir, url).is_some());
    clear_remote_cache(&dir);
    assert!(!dir.exists(), "清空后目录须消失");
    assert!(
        read_remote_cache(&dir, url).is_none(),
        "清空后必须回到未命中"
    );
    clear_remote_cache(&dir); // 目录已不在 —— 不 panic、不报错。
}

/// 扩展名表与 MIME 白名单同口径：表里每一项都能取到 MIME，且 SVG 绝不在表内（LOW-3）。
#[test]
fn remote_cache_exts_agree_with_mime_whitelist() {
    assert!(
        !REMOTE_CACHE_EXTS.is_empty(),
        "自检：表空则上面所有断言恒绿"
    );
    for ext in REMOTE_CACHE_EXTS {
        assert!(
            mime_for_ext(ext).is_some(),
            "缓存扩展名须在 MIME 白名单内: {ext}"
        );
    }
    assert!(
        !REMOTE_CACHE_EXTS.contains(&"svg"),
        "SVG 不得进浏览缓存（LOW-3）"
    );
    // sniff_ext 的每个可能返回值都必须在表内，否则该格式永远缓存未命中。
    for (ct, bytes) in [
        (None, [0x89, b'P', b'N', b'G'].as_slice()),
        (None, [0xFF, 0xD8, 0xFF, 0].as_slice()),
        (None, b"GIF89a".as_slice()),
        (None, b"RIFF\0\0\0\0WEBP".as_slice()),
        (None, b"BM..".as_slice()),
        (None, [0x00, 0x00, 0x01, 0x00].as_slice()),
    ] {
        let ext = sniff_ext(ct, bytes).expect("嗅探样本必须命中");
        assert!(
            REMOTE_CACHE_EXTS.contains(&ext),
            "sniff_ext 会返回 {ext} 但缓存表里没有 —— 该格式将永远未命中"
        );
    }
}

// ── image-only 嗅探门 ────────────────────────────────────────────────────

#[test]
fn sniff_ext_detects_by_magic_over_content_type() {
    assert_eq!(
        sniff_ext(
            Some("application/octet-stream"),
            &[0x89, b'P', b'N', b'G', 0]
        ),
        Some("png")
    );
    assert_eq!(sniff_ext(None, &[0xFF, 0xD8, 0xFF, 0]), Some("jpg"));
    assert_eq!(sniff_ext(None, b"GIF89a...."), Some("gif"));
}

#[test]
fn sniff_ext_rejects_non_image() {
    assert_eq!(sniff_ext(Some("text/html"), b"<!doctype html><html>"), None);
    assert_eq!(sniff_ext(Some("application/json"), b"{\"a\":1}"), None);
}

/// LOW-3：SVG 一律拒缓存——魔数（`<svg`/`<?xml`）与 `image/svg+xml` content-type 都不认。
/// 防敌意图标 URL 把 `<svg onload=…>` 植入 `<userData>/icons/`（CSP null 下潜在 stored-XSS）。
#[test]
fn sniff_ext_rejects_svg() {
    assert_eq!(
        sniff_ext(
            None,
            b"<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"x\"/>"
        ),
        None
    );
    assert_eq!(
        sniff_ext(Some("image/svg+xml"), b"<?xml version=\"1.0\"?><svg/>"),
        None
    );
    assert_eq!(sniff_ext(None, b"<?xml version=\"1.0\"?>"), None);
    // mime_for_ext 侧亦不再认 svg（serve 白名单已剔除）。
    assert_eq!(mime_for_ext("svg"), None);
}

// ── scheme 路由 / percent-decode 门 ──────────────────────────────────────

#[test]
fn parse_route_cache_and_remote_macos_host_form() {
    let cache = "polaris-icon://c/custom-abc.png"
        .parse::<tauri::http::Uri>()
        .unwrap();
    assert!(matches!(parse_route(&cache), Some(Route::Cache(f)) if f == "custom-abc.png"));

    let enc = "https://cdn.example.com/x.png";
    let remote = format!("polaris-icon://i/{}", urlencode(enc))
        .parse::<tauri::http::Uri>()
        .unwrap();
    assert!(matches!(parse_route(&remote), Some(Route::Remote(u)) if u == enc));
}

#[test]
fn parse_route_windows_localhost_form() {
    // wry 在 Windows 把自定义 scheme 映射成 http://polaris-icon.localhost/<mode>/<payload>。
    let cache = "http://polaris-icon.localhost/c/custom-x.svg"
        .parse::<tauri::http::Uri>()
        .unwrap();
    assert!(matches!(parse_route(&cache), Some(Route::Cache(f)) if f == "custom-x.svg"));
}

#[test]
fn percent_decode_roundtrip() {
    assert_eq!(
        percent_decode("https%3A%2F%2Fa.com%2Fx.png"),
        "https://a.com/x.png"
    );
    assert_eq!(percent_decode("no-encoding"), "no-encoding");
    assert_eq!(percent_decode("%"), "%"); // 残缺 % 原样保留，不 panic
}

#[test]
fn serve_cache_roundtrip_and_rejects_traversal() {
    let dir = temp_dir("serve");
    write_icon(&dir, "custom-s", "png", b"\x89PNGdata").unwrap();
    let (mime, bytes) = serve_cache(&dir, "custom-s.png").expect("应命中缓存");
    assert_eq!(mime, "image/png");
    assert_eq!(bytes, b"\x89PNGdata");
    // 穿越 / 非白名单扩展名一律 None。
    assert!(serve_cache(&dir, "../custom-s.png").is_none());
    assert!(serve_cache(&dir, "custom-s.exe").is_none());
    assert!(serve_cache(&dir, "custom-s").is_none());
}

/// LOW-3：即便磁盘上存在 `.svg`（历史遗留 / 手工植入），serve 侧也不再作为图片返回（白名单已剔除）。
#[test]
fn serve_cache_rejects_svg_extension() {
    let dir = temp_dir("serve-svg");
    std::fs::write(dir.join("custom-x.svg"), b"<svg onload=\"x\"/>").unwrap();
    assert!(
        serve_cache(&dir, "custom-x.svg").is_none(),
        "svg 不得再经缓存服务返回"
    );
}

// ── 下载门（真 client + DNS 钉回环，SSRF guard 真跑；绝不碰公网 / 真实 CDN）──────────
// 对齐 commands/rules.rs、subscription.rs 的生产门：真 reqwest 传输落点钉到回环 test server，
// 而 guard 判定对象是注入 lookup 给出的 IP（公网→放行 / 内网→拒），二者分层，非「绕过 guard」。

/// 最小 encodeURIComponent 等价（仅测试用，编码 :/ 等）。
fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn spawn_once(response: Vec<u8>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 回环端口");
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf);
            let _ = sock.write_all(&response);
            let _ = sock.flush();
        }
    });
    addr
}

fn http_ok(content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
    out.extend_from_slice(body);
    out
}

#[tokio::test]
async fn fetch_image_downloads_and_validates_png_over_loopback() {
    // 真 reqwest 传输落回环 server；guard 判定对象为公网 IP → 放行（guard 真跑，非旁路）。
    let png = b"\x89PNG\r\n\x1a\nrest-of-bytes";
    let addr = spawn_once(http_ok("image/png", png));
    let client = HttpRuntime::with_resolve_overrides(&[("icon.example.com", addr)]).unwrap();
    let lookup = FixedLookup("93.184.216.34");
    let (ext, bytes) = fetch_image(
        &client,
        &lookup,
        "http://icon.example.com/icon",
        MAX_ICON_BYTES,
    )
    .await
    .expect("回环下载应成功");
    assert_eq!(ext, "png");
    assert_eq!(bytes, png);
}

#[tokio::test]
async fn fetch_image_rejects_non_image_payload() {
    let addr = spawn_once(http_ok("text/html", b"<!doctype html><html></html>"));
    let client = HttpRuntime::with_resolve_overrides(&[("icon.example.com", addr)]).unwrap();
    let lookup = FixedLookup("93.184.216.34");
    let r = fetch_image(
        &client,
        &lookup,
        "http://icon.example.com/notimg",
        MAX_ICON_BYTES,
    )
    .await;
    assert!(r.is_err(), "非图片内容必须拒绝缓存");
}

/// **HIGH-1 回归门**：图标 fetch 路径必须过 SSRF guard——内网 URL 一律拒，且 guard 在 fetch 前
/// 拦截，绝不发起对内网的连接（零宿主网络）。镜像 rules.rs `ssrf_guard_blocks_internal_ip_on_production_path`。
#[tokio::test]
async fn fetch_image_rejects_internal_ip_on_fetch_path() {
    // 真 HttpRuntime（真 reqwest，no_proxy 直出宿主）驱动生产函数。
    let http = HttpRuntime::new().unwrap();
    // ① 字面回环（如代理核控制面 127.0.0.1:9090）→ 字面私网 IP，guard 首跳即拒（不查 DNS、不连接）。
    let lk = FixedLookup("93.184.216.34"); // 即便 lookup 谎报公网也无用：字面 IP 走 is_private_ip
    let r = fetch_image(&http, &lk, "http://127.0.0.1:9090/", MAX_ICON_BYTES).await;
    assert!(r.is_err(), "字面回环 IP 必须被 SSRF guard 拒");
    // ② 云元数据 169.254.169.254 → 拒。
    let r = fetch_image(&http, &lk, "http://169.254.169.254/", MAX_ICON_BYTES).await;
    assert!(r.is_err(), "云元数据地址必须被 SSRF guard 拒");
}

/// **HIGH-1**：DNS-rebinding——公网 hostname 解析到内网 IP → guard 逐 IP 判定必拒。
/// 真 client 传输落点钉回环 server（证明即便 server 可达，guard 仍在连接前拦截 30x 之外的首跳）。
#[tokio::test]
async fn fetch_image_rejects_dns_rebinding_to_internal() {
    let addr = spawn_once(http_ok("image/png", b"\x89PNGxx"));
    let client = HttpRuntime::with_resolve_overrides(&[("icon.example.com", addr)]).unwrap();
    let lookup = FixedLookup("169.254.169.254"); // hostname 解析到云元数据 = 内网
    let r = fetch_image(
        &client,
        &lookup,
        "http://icon.example.com/evil.png",
        MAX_ICON_BYTES,
    )
    .await;
    assert!(r.is_err(), "hostname 解析到内网 IP 必须被 SSRF guard 拒");
}

/// **HIGH-1**：非 http(s) 协议在 fetch 前即拒（file/data/gopher…）。
#[tokio::test]
async fn fetch_image_rejects_non_http_scheme() {
    let http = HttpRuntime::new().unwrap();
    let lk = FixedLookup("93.184.216.34");
    for evil in [
        "file:///etc/passwd",
        "gopher://127.0.0.1/",
        "data:text/html,x",
    ] {
        let r = fetch_image(&http, &lk, evil, MAX_ICON_BYTES).await;
        assert!(r.is_err(), "非 http(s) 协议必须被拒: {evil}");
    }
}

#[tokio::test]
async fn fetch_image_write_roundtrip_end_to_end() {
    // 下载（回环）→ 写盘 → serve 回读，逐字节一致（缓存链路端到端，零公网）。
    let dir = temp_dir("e2e");
    let webp = {
        let mut v = b"RIFF\0\0\0\0WEBP".to_vec();
        v.extend_from_slice(b"payload");
        v
    };
    let addr = spawn_once(http_ok("application/octet-stream", &webp));
    let client = HttpRuntime::with_resolve_overrides(&[("icon.example.com", addr)]).unwrap();
    let lookup = FixedLookup("93.184.216.34");
    let (ext, bytes) = fetch_image(
        &client,
        &lookup,
        "http://icon.example.com/i",
        MAX_ICON_BYTES,
    )
    .await
    .unwrap();
    assert_eq!(ext, "webp", "魔数应判为 webp（content-type 泛化时靠魔数）");
    let r = write_icon(&dir, "custom-e2e", ext, &bytes).unwrap();
    assert_eq!(r, "polaris-icon://c/custom-e2e.webp");
    let (mime, served) = serve_cache(&dir, "custom-e2e.webp").unwrap();
    assert_eq!(mime, "image/webp");
    assert_eq!(served, webp);
}

/// 浏览缓存端到端：下载（回环）→ 落浏览缓存 → 回读逐字节一致，且第二次渲染**不再需要下载**
/// （回环 server 是 `spawn_once`，只接一次连接；若缓存没生效，这里会再发一次连接而拿不到应答）。
#[tokio::test]
async fn remote_cache_end_to_end_serves_second_render_without_network() {
    let dir = temp_dir("remote-e2e");
    let png = b"\x89PNG\r\n\x1a\nbrowse-cache";
    let addr = spawn_once(http_ok("image/png", png));
    let client = HttpRuntime::with_resolve_overrides(&[("icon.example.com", addr)]).unwrap();
    let lookup = FixedLookup("93.184.216.34");
    let url = "http://icon.example.com/gallery/x.png";

    // 第一次：真下载（复用生产取图管线，SSRF guard / 体积闸 / image-only 门全在）。
    let (ext, bytes) = fetch_image(&client, &lookup, url, MAX_ICON_BYTES)
        .await
        .expect("首次下载应成功");
    write_remote_cache(&dir, url, ext, &bytes).unwrap();

    // 第二次：纯读盘，字节与 MIME 都对得上。
    let (mime, cached) = read_remote_cache(&dir, url).expect("第二次必须走缓存");
    assert_eq!(mime, "image/png");
    assert_eq!(cached, png, "缓存回读须与下载逐字节相同");

    // 反证：server 只接一次连接，此刻再下载必失败 —— 证明上面那次命中确实没走网络。
    assert!(
        fetch_image(&client, &lookup, url, MAX_ICON_BYTES)
            .await
            .is_err(),
        "one-shot server 已耗尽：若这里还能成功，说明测试没在测缓存"
    );
}

// ── CORS 放行头（自定义 scheme 在 WKWebView 侧是跨 origin 子资源）─────────────

#[test]
fn both_response_builders_carry_cors_allow_origin() {
    // 成功与失败两条出口都必须带，缺一则该出口的图标在 macOS 上恒白块（且失败出口连
    // 状态码都读不到）。断言取实际头值，避免只测「键存在」而值被改成空串。
    for (label, resp) in [
        ("ok", ok_response("image/png", vec![1, 2, 3])),
        ("status", status_response(404, "icon not cached")),
    ] {
        let v = resp
            .headers()
            .get("access-control-allow-origin")
            .unwrap_or_else(|| panic!("{label} 出口缺 Access-Control-Allow-Origin"));
        assert_eq!(v, "*", "{label} 出口的 ACAO 值不对");
    }
}

/// 下面两道源码扫描门的**共用取材面**：`handle_scheme_request` 自己的函数体，剥注释。
///
/// 两处此前各写一份手写切片器（`find("pub fn handle_scheme_request")` → `find("\n#[cfg(test)]")`），
/// 两条差别都会静默放水：
/// - **封顶锚在 `#[cfg(test)]` 上**：射程不是「这个函数」，而是「这个函数到文件末尾的测试模块之间
///   的全部顶层项」。今天它恰好是文件里最后一个生产项，所以看起来对；哪天在它后面加个 helper，
///   射程就静默变宽 —— 「每个 respond 出口都走两个构造器」会由邻居函数替它作证。测试模块一旦
///   随本仓惯例外移成 `icon_cache/tests/`，那个锚点直接消失、切片器当场 panic。
/// - **不剥注释**：下面两条全是正面 `contains`，把 `read_remote_cache(...)` 整行注释掉，
///   注释里那份副本照样喂饱断言。
///
/// 换成共用器 [`top_level_fn_body`]（列 0 的 `}` 封顶、锚点缩进必断言、找不到闭合就 panic）
/// + [`crate_code`]（剥注释、保留字符串字面量）。
fn handler_body() -> String {
    top_level_fn_body(&crate_code("icon_cache.rs"), "pub fn handle_scheme_request")
}

/// 源码扫描门：远端腿必须**两头都接**上浏览缓存 —— 取图前读、成功后写。
///
/// 这段接线跑起来要 Tauri `AppHandle` + `UriSchemeResponder`，单测里造不出来；而漏接任一头的
/// 后果都不会在别处转红：只漏读 = 缓存写了永远不用（每次照旧出站，本次改动等于没做）；
/// 只漏写 = 永远读不到（同上）。两者在单测层面都静默。故在源码层钉住。
#[test]
fn remote_leg_is_wired_to_the_browse_cache_on_both_ends() {
    let body = handler_body();
    assert!(
        body.contains("read_remote_cache(&cache_dir, &remote_url)"),
        "远端腿没先查浏览缓存 —— 每次渲染都会真出站，缓存白写"
    );
    assert!(
        body.contains("write_remote_cache(&cache_dir, &remote_url, ext, &bytes)"),
        "远端腿取图成功后没落缓存 —— 缓存永远是空的，每次都出站"
    );
}

#[test]
fn every_responder_exit_goes_through_the_two_builders() {
    // 源码扫描门：`handle_scheme_request` 里每个 `responder.respond(` 的实参都必须是
    // `ok_response(` / `status_response(` 之一。裸 `Response::builder()` 直接 respond 会
    // 绕过上面的 CORS 头，且这类回归在单测里无声（构造器测试仍绿）——只能在源码层锁。
    // 有意不接受中间变量（`let r = ok_response(..); respond(r)`）：文本扫描判不了变量来源，
    // 与其放行一个它看不穿的形状，不如把写法收敛成直呼构造器。要加新出口就照这个形状写。
    let body = handler_body();
    let n = body.matches("responder.respond(").count();
    // 下限跟着实际出口数走（2026-07-30：远端腿新增「浏览缓存命中」出口，6 → 7）。
    // 这是本门的自检面，不是可以放宽的判据：留在旧值只会让「函数被拆走一半」这类回归照样绿。
    assert!(
        n >= 7,
        "扫描面自检：respond 出口应 ≥7，实得 {n}（函数被拆走了？）"
    );
    for (i, _) in body.match_indices("responder.respond(") {
        let arg = &body[i + "responder.respond(".len()..];
        assert!(
            arg.starts_with("ok_response(") || arg.starts_with("status_response("),
            "respond 实参必须走两个构造器（否则绕过 CORS 头），实得：{}",
            &arg[..arg.len().min(40)]
        );
    }
}
