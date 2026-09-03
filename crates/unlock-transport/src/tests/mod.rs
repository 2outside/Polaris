use super::*;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::thread;

// ── 回环 HTTP server（stdlib，127.0.0.1；**不触碰宿主网络、不打任何真实 CF 端点**）──────

fn spawn_server(responses: Vec<Vec<u8>>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 回环端口");
    let addr = listener.local_addr().expect("取端口");
    thread::spawn(move || {
        for resp in responses {
            let Ok((mut sock, _)) = listener.accept() else {
                return;
            };
            let mut buf = [0u8; 16384];
            let _ = sock.read(&mut buf);
            let _ = sock.write_all(&resp);
            let _ = sock.flush();
        }
    });
    addr
}

fn http_response(status_line: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status_line}\r\n");
    for (k, v) in headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str(&format!("Content-Length: {}\r\n", body.len()));
    out.push_str("Connection: close\r\n\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

/// 按 profile 构造带完整浏览器头集的 GET（复刻 checker 侧 `get_req` 的接线）。
fn browser_get(url: &str, profile: polaris_unlock::RequestProfile) -> UnlockRequest {
    let mut req = UnlockRequest::get(url);
    for (k, v) in polaris_unlock::browser_headers(profile, HttpMethod::Get, url) {
        req = req.header(k, v);
    }
    req
}

// ── 解压门（本 crate 存在的**最重要**理由之一）───────────────────────────────
//
// 「声明了 Accept-Encoding 却解不开」不会报错，会**静默误判**：checker 拿压缩字节流做 marker
// 匹配，全部落空 → ChatGPT 误 Ok / Gemini 误 Blocked / Netflix 误 Blocked。
// 故：`browser::ACCEPT_ENCODING` 声明的**每一种**编码，都必须在这里被真实解压验过。

/// 明文 canary（下列压缩块解开后都必须等于它）。
const CANARY: &str = "UNLOCK-DECOMPRESSION-CANARY inSupportedLocation:true";

/// `gzip` 压缩后的 [`CANARY`]（python3 `gzip.compress`）。
const GZIP_CANARY: &[u8] = &[
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x0b, 0xf5, 0xf3, 0xf1, 0x77, 0xf6,
    0xd6, 0x75, 0x71, 0x75, 0xf6, 0xf7, 0x0d, 0x08, 0x72, 0x0d, 0x0e, 0xf6, 0xf4, 0xf7, 0xd3, 0x75,
    0x76, 0xf4, 0x73, 0x0c, 0x8a, 0x54, 0xc8, 0xcc, 0x0b, 0x2e, 0x2d, 0x28, 0xc8, 0x2f, 0x2a, 0x49,
    0x4d, 0xf1, 0xc9, 0x4f, 0x4e, 0x2c, 0xc9, 0xcc, 0xcf, 0xb3, 0x2a, 0x29, 0x2a, 0x4d, 0x05, 0x00,
    0xaf, 0xe3, 0xb0, 0x86, 0x34, 0x00, 0x00, 0x00,
];

/// `deflate` 压缩后的 [`CANARY`]（zlib 包装 —— 服务器实际发的形态；python3 `zlib.compress`）。
const DEFLATE_CANARY: &[u8] = &[
    0x78, 0x9c, 0x0b, 0xf5, 0xf3, 0xf1, 0x77, 0xf6, 0xd6, 0x75, 0x71, 0x75, 0xf6, 0xf7, 0x0d, 0x08,
    0x72, 0x0d, 0x0e, 0xf6, 0xf4, 0xf7, 0xd3, 0x75, 0x76, 0xf4, 0x73, 0x0c, 0x8a, 0x54, 0xc8, 0xcc,
    0x0b, 0x2e, 0x2d, 0x28, 0xc8, 0x2f, 0x2a, 0x49, 0x4d, 0xf1, 0xc9, 0x4f, 0x4e, 0x2c, 0xc9, 0xcc,
    0xcf, 0xb3, 0x2a, 0x29, 0x2a, 0x4d, 0x05, 0x00, 0xac, 0x8d, 0x11, 0xb0,
];

/// `br`（brotli）压缩后的 [`CANARY`]（python3 `brotli.compress`）。
const BR_CANARY: &[u8] = &[
    0x1b, 0x33, 0x00, 0xf8, 0xe5, 0x1b, 0x5b, 0xd7, 0x38, 0xc6, 0xf1, 0x84, 0x45, 0x94, 0x32, 0x8c,
    0xe9, 0x68, 0x43, 0x14, 0xc1, 0xe7, 0x20, 0xbd, 0x06, 0x2b, 0x0c, 0xbd, 0xa4, 0x27, 0xa3, 0xc4,
    0x51, 0x6d, 0x10, 0x0f, 0x0a, 0x27, 0xf7, 0xc2, 0x7d, 0x91, 0x90, 0x12,
];

/// `zstd` 压缩后的 [`CANARY`]（python3 `compression.zstd.compress`）。
const ZSTD_CANARY: &[u8] = &[
    0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x34, 0xa1, 0x01, 0x00, 0x55, 0x4e, 0x4c, 0x4f, 0x43, 0x4b, 0x2d,
    0x44, 0x45, 0x43, 0x4f, 0x4d, 0x50, 0x52, 0x45, 0x53, 0x53, 0x49, 0x4f, 0x4e, 0x2d, 0x43, 0x41,
    0x4e, 0x41, 0x52, 0x59, 0x20, 0x69, 0x6e, 0x53, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64,
    0x4c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x74, 0x72, 0x75, 0x65,
];

/// 编码名 → 该编码压缩过的 canary。**必须覆盖 `ACCEPT_ENCODING` 声明的全集**。
fn canary_for(token: &str) -> Option<&'static [u8]> {
    match token {
        "gzip" => Some(GZIP_CANARY),
        "deflate" => Some(DEFLATE_CANARY),
        "br" => Some(BR_CANARY),
        "zstd" => Some(ZSTD_CANARY),
        _ => None,
    }
}

#[tokio::test]
async fn declared_accept_encoding_is_decodable_end_to_end() {
    // **跨 crate 不变量**（`browser::ACCEPT_ENCODING` 的文档点名本门）：
    // 声明的每种编码都必须真能解开，否则静默误判。
    //
    // 变异验证：
    //  - 从 Cargo.toml 摘掉 `brotli` feature → br 那轮拿回压缩字节 ≠ CANARY → 转红。
    //  - 给 ACCEPT_ENCODING 加一个没有解码器的编码（如 `sdch`）→ canary_for 返 None → 转红
    //    （**这条是关键**：它保证「新增声明」不会悄悄绕过本门）。
    for token in polaris_unlock::browser::accept_encoding_tokens() {
        let blob = canary_for(token).unwrap_or_else(|| {
            panic!(
                "ACCEPT_ENCODING 声明了 `{token}`，但本门没有对应的解压用例 —— \
                     要么该编码传输层解不开（会静默误判），要么补上 canary 再声明"
            )
        });
        let addr = spawn_server(vec![http_response(
            "200 OK",
            &[("Content-Encoding", token), ("Content-Type", "text/html")],
            blob,
        )]);
        let c = UnlockClient::direct().expect("建 client");
        let resp = c
            .request(&UnlockRequest::get(format!("http://{addr}/{token}")))
            .await;
        assert_eq!(resp.status, 200, "`{token}` 请求应成功");
        assert_eq!(
            resp.body, CANARY,
            "`{token}` 未被解压 —— body 是压缩字节流，checker 的 marker 匹配会全部落空（静默误判）"
        );
    }
}

// ── UnlockHttp 契约门（与原 reqwest 实现同口径，换栈后必须仍成立）──────────────

#[tokio::test]
async fn never_errs_on_network_failure_it_reports_status_zero() {
    // 契约：永不 panic / 永不 Err —— 失败落 status=0 + error，由 checker 兜底 Timeout。
    // 若改成 unwrap → 一个检测项挂掉会带崩整轮齐射。
    let c = UnlockClient::direct().expect("建 client");
    let resp = c
        .request(&UnlockRequest::get("http://127.0.0.1:1/dead"))
        .await;
    assert_eq!(resp.status, 0, "传输失败必须 status=0");
    assert!(resp.error.is_some());
    assert!(!resp.reachable(), "status=0 不得判为可达");
}

#[tokio::test]
async fn records_redirect_chain_without_following_automatically() {
    // checker 判据之一是完整 redirect_chain（Claude 靠最终 URL 落在哪个域判定）。
    let addr = spawn_server(vec![
        b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            .to_vec(),
        http_response("200 OK", &[], b"{\"ok\":true}"),
    ]);
    let c = UnlockClient::direct().expect("建 client");
    let resp = c
        .request(&UnlockRequest::get(format!("http://{addr}/a")))
        .await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.redirect_chain.len(), 1, "逐跳链必须记录");
    assert_eq!(resp.redirect_chain[0].status, 302);
    assert_eq!(resp.redirect_chain[0].location, "/next");
}

#[tokio::test]
async fn set_cookie_is_carried_across_manual_redirect_hops() {
    // **cookie jar 的唯一自动化证据**（`base_builder()` 的 `.cookie_store(true)`）。
    //
    // 手动逐跳跟随最容易漏的就是这条：首跳 `Set-Cookie` 之后，第二跳若不回带 `Cookie`，
    // 与真 Chrome 的行为差一条独立于 TLS/头指纹的信号（Netflix 判定异常的候选根因之一）。
    //
    // 变异验证（本批真跑过）：删掉 `.cookie_store(true)` → 第二跳线上无 `cookie:` → 转红。
    //
    // 不用 `spawn_server`：它只回放固定字节，而本门要**回显第二跳的请求原文**才看得见 `Cookie`。
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 回环端口");
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        // 第 1 跳：302 + Set-Cookie
        if let Ok((mut sock, _)) = listener.accept() {
            let mut buf = [0u8; 16384];
            let _ = sock.read(&mut buf);
            let _ = sock.write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: /next\r\nSet-Cookie: unlock_probe=jar-works; Path=/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
        }
        // 第 2 跳：回显请求原文
        if let Ok((mut sock, _)) = listener.accept() {
            let mut buf = [0u8; 16384];
            let n = sock.read(&mut buf).unwrap_or(0);
            let raw = String::from_utf8_lossy(&buf[..n]).to_string();
            let _ = sock.write_all(&http_response("200 OK", &[], raw.as_bytes()));
        }
    });

    let c = UnlockClient::direct().expect("建 client");
    let resp = c
        .request(&UnlockRequest::get(format!("http://{addr}/a")))
        .await;
    assert_eq!(resp.status, 200);
    assert_eq!(
        resp.redirect_chain.len(),
        1,
        "仍须逐跳记录（jar 不改这条契约）"
    );
    let wire = resp.body.to_lowercase();
    assert!(
        wire.contains("cookie: unlock_probe=jar-works"),
        "第二跳没带上首跳的 Set-Cookie —— 与真 Chrome 的跳转行为不一致。实收:\n{wire}"
    );
}

#[tokio::test]
async fn captures_cf_mitigated_header_for_challenge_detection() {
    // 挑战识别（`polaris_unlock::challenge::classify`）的**主判据来源**：
    // 终态响应头必须被真实填充、键小写、可大小写不敏感取。漏填 → 挑战永远识别不出来 → 误报回归。
    let addr = spawn_server(vec![http_response(
        "403 Forbidden",
        &[("cf-mitigated", "challenge"), ("Server", "cloudflare")],
        b"<html>Just a moment...</html>",
    )]);
    let c = UnlockClient::direct().expect("建 client");
    let resp = c
        .request(&UnlockRequest::get(format!("http://{addr}/challenge")))
        .await;
    assert_eq!(resp.status, 403);
    assert_eq!(resp.header("cf-mitigated"), Some("challenge"));
    assert_eq!(
        resp.header("CF-Mitigated"),
        Some("challenge"),
        "取头须大小写不敏感"
    );
    assert_eq!(resp.header("server"), Some("cloudflare"));
    assert!(resp.headers.contains_key("cf-mitigated"), "键须小写规范化");
    // 端到端：这个响应必须真被分类器判成挑战（不只是头拿到了）。
    assert!(
        polaris_unlock::classify(&resp).is_some(),
        "捕获的头必须能让 classify 命中——否则挑战识别在生产路径上是断的"
    );
}

#[tokio::test]
async fn truncates_body_rather_than_failing() {
    // 与订阅相反：解锁只看特征串，截断的 body 仍可判 → 截断 + 标记，不报错。
    let body = vec![b'y'; MAX_BODY_BYTES + 100];
    let addr = spawn_server(vec![http_response("200 OK", &[], &body)]);
    let c = UnlockClient::direct().expect("建 client");
    let resp = c
        .request(&UnlockRequest::get(format!("http://{addr}/big")))
        .await;
    assert_eq!(resp.status, 200);
    assert!(resp.truncated, "超限应标记 truncated");
    assert_eq!(resp.body.len(), MAX_BODY_BYTES);
    assert!(resp.error.is_none(), "截断不是错误");
}

// ── 边界门：wreq 不得泄漏到其它 crate ──────────────────────────────────────

#[test]
fn wreq_is_declared_only_by_this_crate() {
    // 任务硬要求：**指纹客户端不得泄漏到其它 HTTP 路径**（订阅拉取 / 内核下载 / 更新 / WARP
    // 都不需要伪装，也不该承担 BoringSSL 构建链与模板漂移的风险）。
    //
    // 独立 crate 只是让泄漏「需要显式改 Cargo.toml」；本门让它**直接转红**。
    // 变异验证：给 `src-tauri/Cargo.toml` 加一行 `wreq = "5"` → 本门转红。
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("定位 workspace 根")
        .to_path_buf();

    let mut manifests = vec![root.join("src-tauri/Cargo.toml")];
    for entry in std::fs::read_dir(root.join("crates")).expect("读 crates/") {
        let dir = entry.expect("目录项").path();
        let m = dir.join("Cargo.toml");
        if m.is_file() {
            manifests.push(m);
        }
    }

    let mut offenders = Vec::new();
    for m in manifests {
        // 本 crate 自己是唯一合法声明处。
        if m.parent().is_some_and(|p| p.ends_with("unlock-transport")) {
            continue;
        }
        let text = std::fs::read_to_string(&m).expect("读 manifest");
        for line in text.lines() {
            let l = line.trim_start();
            if l.starts_with('#') {
                continue; // 注释里提到 wreq 不算声明
            }
            if l.starts_with("wreq") || l.contains("\"wreq\"") {
                offenders.push(format!("{}: {l}", m.display()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "wreq 只允许由 polaris-unlock-transport 声明（指纹客户端不得泄漏到其它 HTTP 路径）。\
             越界声明:\n{}",
        offenders.join("\n")
    );
}

// ── 浏览器身份同源门（transport 这一半）──────────────────────────────────
//
// 「TLS 指纹说 149、UA 说 137」比单纯陈旧更糟：**自相矛盾**是更强的 bot 信号。
// 下面两扇门把 emulation 这一处焊死在 `CHROME_MAJOR` 上；UA/`sec-ch-ua` 那半边在
// `polaris_unlock::browser` 的 `sec_ch_ua_major_version_matches_ua`。

#[test]
fn emulation_matches_the_pinned_chrome_major() {
    // 派生表写错行（如 `149 => Profile::Chrome137`）在编译期是合法的 —— 本门抓它。
    // `Profile` 的 Debug 名即变体名（`Chrome149`），是 wreq-util 暴露版本号的唯一公开途径
    //（模板的 `default_headers` 不可从外部读到）。
    assert_eq!(
        format!("{EMULATION:?}"),
        format!("Chrome{CHROME_MAJOR}"),
        "指纹模板与 CHROME_MAJOR 不同版 —— TLS 指纹与 UA 会自相矛盾"
    );
}

/// 解析派生表的一行 `NNN => wreq_util::Profile::ChromeMMM,` → `(NNN, MMM)`。
fn emulation_mapping_row(line: &str) -> Option<(u32, u32)> {
    let (lhs, rhs) = line.trim().trim_end_matches(',').split_once("=>")?;
    let key = lhs.trim().parse().ok()?;
    let variant = rhs.trim().strip_prefix("wreq_util::Profile::Chrome")?;
    Some((key, variant.parse().ok()?))
}

#[test]
fn emulation_variant_is_derived_not_hardcoded() {
    // **本门是「只升 emulation 不升 UA」这个变异的唯一自动化拦截点**：`chrome_emulation`
    // 的派生让 emulation 没有独立的版本字面量，但绕过派生（直接 `.emulation(Profile::Chrome149)`）
    // 仍然编译得过。本门扫生产代码，只放行派生表里左右同号的行。
    //
    // **两种写法都得拦**：wreq-util 3.x 把枚举更名为 `Profile`，但 `Emulation` 上仍留着
    // 一批 `pub const ChromeNNN: Profile` 别名 —— 只扫 `Profile::Chrome` 会让
    // `wreq_util::Emulation::Chrome149` 这条**编译得过的**旁路静默逃逸（门变成空门）。
    //
    // 变异验证（本批真跑过，见交付说明）：
    //  - `base_builder()` 改成 `.emulation(wreq_util::Profile::Chrome149)` → 转红；
    //  - 同上但写 `wreq_util::Emulation::Chrome149`（3.x 别名）→ 转红；
    //  - 派生表某行改成 `149 => wreq_util::Profile::Chrome137` → 转红（左右不同号）。
    let src = polaris_source_probe::crate_source!("lib.rs");
    // 只扫生产段（`#[cfg(test)]` 之后是本测试模块，里面的字符串/注释必然含该字面量）。
    let prod = src
        .split("#[cfg(test)]")
        .next()
        .expect("源码应含测试模块分界");
    let offenders: Vec<String> = prod
        .lines()
        .enumerate()
        .filter(|(_, l)| l.contains("Profile::Chrome") || l.contains("Emulation::Chrome"))
        .filter(|(_, l)| !l.trim_start().starts_with("//")) // 文档/注释里提到不算
        .filter(|(_, l)| !matches!(emulation_mapping_row(l), Some((k, v)) if k == v))
        .map(|(i, l)| format!("{}: {}", i + 1, l.trim()))
        .collect();
    assert!(
        offenders.is_empty(),
        "`Profile::Chrome…` / `Emulation::Chrome…` 只允许出现在 `chrome_emulation` 的派生表里\
             （左右同号），否则指纹版本会脱离 CHROME_MAJOR 独立漂移。越界行:\n{}",
        offenders.join("\n")
    );
}

// ── TLS 指纹门（本 crate 的**主要收益**必须有牙）────────────────────────────
//
// 前面所有门在「删掉 `.emulation(…)`」这个变异下**全绿** —— 因为头集是我们自己显式设的、
// 解压是 feature 决定的，都与指纹无关。也就是说：没有本门，Phase-2 的核心交付物是**无门**的，
// 有人误删 emulation 会静默退回 rustls 时代的可识别形态（而 CI 全绿）。
//
// 本门在**线级**验：让 client 向回环 TCP 发起 HTTPS，抓下**首个 ClientHello 字节**，
// 断言它带 Chrome 的结构特征。握手随后会失败（对端不是真 TLS server）——不影响，本门只看已抓字节。
// **不触碰宿主网络、不打任何真实端点。**

/// GREASE 值（RFC 8701）：两字节相同且低半字节为 `0xa`（`0x0a0a`/`0x1a1a`/…/`0xfafa`）。
/// Chrome/BoringSSL **必发**；rustls **从不发**。这是区分二者最稳的结构特征。
fn is_grease(v: u16) -> bool {
    let [hi, lo] = v.to_be_bytes();
    hi == lo && (hi & 0x0f) == 0x0a
}

/// 从 ClientHello 记录里解析出 `(cipher_suites, extension_types)`。
fn parse_client_hello(buf: &[u8]) -> Option<(Vec<u16>, Vec<u16>)> {
    // TLS record: type(1)=0x16 version(2) length(2) | handshake: type(1)=0x01 length(3)
    if buf.len() < 9 || buf[0] != 0x16 || buf[5] != 0x01 {
        return None;
    }
    let mut i = 9; // 跳过 record(5) + handshake header(4)
    i += 2 + 32; // client_version + random
    let sid_len = *buf.get(i)? as usize;
    i += 1 + sid_len;
    let cs_len = u16::from_be_bytes([*buf.get(i)?, *buf.get(i + 1)?]) as usize;
    i += 2;
    let mut ciphers = Vec::new();
    for c in buf.get(i..i + cs_len)?.as_chunks::<2>().0 {
        ciphers.push(u16::from_be_bytes([c[0], c[1]]));
    }
    i += cs_len;
    let comp_len = *buf.get(i)? as usize;
    i += 1 + comp_len;
    let ext_total = u16::from_be_bytes([*buf.get(i)?, *buf.get(i + 1)?]) as usize;
    i += 2;
    let end = i + ext_total;
    let mut exts = Vec::new();
    while i + 4 <= end.min(buf.len()) {
        let ty = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let len = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
        exts.push(ty);
        i += 4 + len;
    }
    Some((ciphers, exts))
}

#[tokio::test]
async fn client_hello_carries_chrome_grease_fingerprint() {
    // **变异验证**：把 `base_builder()` 里的 `.emulation(EMULATION)` 删掉
    // → ClientHello 不再带 GREASE → 本门转红。这是「指纹伪装真的生效了」的唯一自动化证据。
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 回环端口");
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            sock.set_read_timeout(Some(Duration::from_millis(800))).ok();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            while let Ok(n) = sock.read(&mut tmp) {
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                // 记录头说了长度，收满即停。
                if buf.len() >= 5 {
                    let rec = 5 + u16::from_be_bytes([buf[3], buf[4]]) as usize;
                    if buf.len() >= rec {
                        break;
                    }
                }
            }
            let _ = tx.send(buf);
        }
    });

    let c = UnlockClient::direct().expect("建 client");
    // https:// 打回环 → 会发真 ClientHello，随后握手失败（对端非 TLS server）。
    let _ = c
        .request(&UnlockRequest::get(format!(
            "https://127.0.0.1:{}/x",
            addr.port()
        )))
        .await;

    let hello = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("应捕获到 ClientHello 字节");
    let (ciphers, exts) =
        parse_client_hello(&hello).expect("捕获的字节应是可解析的 TLS ClientHello");

    assert!(
            ciphers.first().is_some_and(|c| is_grease(*c)),
            "Chrome/BoringSSL 的首个 cipher suite 必为 GREASE；实得 {:04x?}（rustls 形态 = 指纹伪装没生效）",
            &ciphers[..ciphers.len().min(4)]
        );
    assert!(
        exts.iter().any(|e| is_grease(*e)),
        "Chrome 必发 GREASE 扩展；实得扩展 {exts:04x?}"
    );
    // ALPN(0x0010)：Chrome 宣告 h2 —— 与 WARP 那条腿刻意钉 HTTP/1.1 的形态正相反。
    assert!(
        exts.contains(&0x0010),
        "应宣告 ALPN 扩展；实得扩展 {exts:04x?}"
    );
}

#[tokio::test]
async fn browser_headers_reach_the_wire() {
    // (c) 的**线级**门：头集不只是构造出来了，得真发出去。
    // 回显 server 把收到的请求原样写回 body，断言关键头在线上出现。
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut buf = [0u8; 16384];
            let n = sock.read(&mut buf).unwrap_or(0);
            let raw = String::from_utf8_lossy(&buf[..n]).to_string();
            let _ = sock.write_all(&http_response("200 OK", &[], raw.as_bytes()));
        }
    });

    let url = format!("http://{addr}/probe");
    let req = browser_get(&url, polaris_unlock::RequestProfile::Navigate);
    let c = UnlockClient::direct().expect("建 client");
    let resp = c.request(&req).await;
    let wire = resp.body.to_lowercase();

    for expect in [
        "accept-encoding: gzip, deflate, br, zstd",
        "accept-language: en-us,en;q=0.9",
        "sec-ch-ua-platform: \"windows\"",
        "sec-fetch-mode: navigate",
        "upgrade-insecure-requests: 1",
    ] {
        assert!(
            wire.contains(&expect.to_lowercase()),
            "线上缺 `{expect}`，实收:\n{wire}"
        );
    }
    // UA 必须是我们钉的 Windows Chrome（版本 = CHROME_MAJOR），**不是** emulation 默认的 macOS UA
    //（值自持不随 wreq-util 补丁版漂移——见 impl 文档「头集与 emulation 的关系」）。
    // 版本号从 CHROME_MAJOR 取，**不写字面量**：否则这里就成了第四处要手动同步的版本钉子。
    assert!(
        wire.contains("windows nt 10.0") && wire.contains(&format!("chrome/{CHROME_MAJOR}")),
        "UA 必须是我们钉的 Windows Chrome {CHROME_MAJOR}，实收:\n{wire}"
    );

    // **wreq 6 的 `header()` 是 append 不是 replace**（见 impl 文档）。若哪天覆盖失效，
    // 线上会同时出现 emulation 默认的 macOS UA 与我们的 Windows UA —— 上面那条 `contains`
    // **抓不到**（它只要求我们的 UA 在场）。故逐名清点：任何一个我们设过的头出现两次即转红。
    //
    // 变异验证（本批真跑过）：在 `request()` 的 header 循环后再 `.header("user-agent", "x")`
    // 追加一条 → 本断言转红，而其余所有门全绿。
    let dup: Vec<&str> = [
        "user-agent",
        "accept",
        "accept-encoding",
        "accept-language",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "priority",
    ]
    .into_iter()
    .filter(|name| {
        wire.lines()
            .filter(|l| l.split_once(':').is_some_and(|(k, _)| k.trim() == *name))
            .count()
            > 1
    })
    .collect();
    assert!(
        dup.is_empty(),
        "线上出现重名头 {dup:?} —— emulation 默认值没被覆盖掉而是被追加，\
             对端会看到两个自相矛盾的值（比不发更强的 bot 信号）。实收:\n{wire}"
    );
}
