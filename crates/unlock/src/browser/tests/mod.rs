use super::*;
use crate::endpoints::CHROME_MAJOR;

fn get(headers: &[(&'static str, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

// ── 不变量 1/2：header 集必须与 UA 自洽（补出矛盾 = 比不补更糟）───────────────

#[test]
fn sec_ch_ua_major_version_matches_ua() {
    // **浏览器身份同源门（unlock crate 这一半）**：UA 与 sec-ch-ua 都必须钉在
    // [`CHROME_MAJOR`] 上。另一半（`Emulation::Chrome{N}`）由 `polaris-unlock-transport`
    // 的 const 派生 + 源码扫描门守。
    //
    // 变异验证：
    //  - 只升 UA（`Chrome/137`→`Chrome/138`）不动 CHROME_MAJOR → 第一条断言红；
    //  - 只升 CHROME_MAJOR 不动 UA → 同一条红；
    //  - 只升 UA + CHROME_MAJOR 忘了 SEC_CH_UA → 后两条红。
    let major = chrome_major_from_ua(UA).expect("UA 必须含 Chrome/<major>");
    assert_eq!(
        major, CHROME_MAJOR,
        "UA 的 Chrome 主版本必须 = CHROME_MAJOR（endpoints.rs 的唯一真值源）"
    );
    assert!(
        SEC_CH_UA.contains(&format!("\"Google Chrome\";v=\"{major}\"")),
        "sec-ch-ua 的 Google Chrome 版本必须 = UA 的 {major}，实得: {SEC_CH_UA}"
    );
    assert!(
        SEC_CH_UA.contains(&format!("\"Chromium\";v=\"{major}\"")),
        "sec-ch-ua 的 Chromium 版本必须 = UA 的 {major}，实得: {SEC_CH_UA}"
    );
}

#[test]
fn sec_ch_ua_platform_matches_ua_platform() {
    // 打断点：UA 写 Windows 而 SEC_CH_UA_PLATFORM 填 "macOS" → 转红。
    let from_ua = platform_token_from_ua(UA).expect("UA 必须能判出平台");
    assert_eq!(
        SEC_CH_UA_PLATFORM, from_ua,
        "sec-ch-ua-platform 必须与 UA 的平台一致"
    );
}

#[test]
fn platform_parser_covers_three_desktop_families() {
    assert_eq!(
        platform_token_from_ua("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
        Some("\"Windows\"")
    );
    assert_eq!(
        platform_token_from_ua("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"),
        Some("\"macOS\"")
    );
    assert_eq!(
        platform_token_from_ua("Mozilla/5.0 (X11; Linux x86_64)"),
        Some("\"Linux\"")
    );
    assert_eq!(platform_token_from_ua("curl/8.0"), None);
}

#[test]
fn chrome_major_parser_rejects_non_chrome_ua() {
    // 刻意用一个**与 CHROME_MAJOR 无关**的版本号：这是解析器的夹具，不是第二处版本钉子
    // （若照抄真值，日后升级时会被误当成「还有一处要改」而引发无谓改动）。
    assert_eq!(
        chrome_major_from_ua("Mozilla/5.0 ... Chrome/99.0.0.0 Safari"),
        Some(99)
    );
    assert_eq!(chrome_major_from_ua("curl/8.0"), None);
}

// ── 不变量 3 的本地半腿：声明的编码集非空且是已知可解码名 ──────────────────
// （真正的「传输层解得开」由 src-tauri 回环解压门守 —— 跨 crate，本 crate 看不见 reqwest feature）

#[test]
fn accept_encoding_tokens_are_parsed_and_nonempty() {
    let toks = accept_encoding_tokens();
    assert_eq!(toks, vec!["gzip", "deflate", "br", "zstd"]);
    assert!(
        !toks.is_empty(),
        "Accept-Encoding 不得为空——自称 Chrome 却不发压缩协商即 (c) 的原始 bug"
    );
}

#[test]
fn accept_encoding_matches_chrome_exactly() {
    // Chrome 真机值（经 wreq-util `header_chrome_accept!(zstd, …)` 模板核对；131~149 一致）。
    // 多声明一种解不开的编码 → 静默误判；少声明 → 与 UA 不完全一致的弱信号。
    // 打断点：改成 "gzip" → 转红；加 "sdch"（无解码器）→ 转红（unlock-transport 的解压门也会红）。
    assert_eq!(ACCEPT_ENCODING, "gzip, deflate, br, zstd");
}

// ── 基础头集：全形态共有的六条必须在 ──────────────────────────────────────

#[test]
fn every_profile_sends_the_always_on_chrome_headers() {
    for profile in [RequestProfile::Navigate, RequestProfile::Api] {
        let h = browser_headers(profile, HttpMethod::Get, "https://example.com/");
        for name in [
            "User-Agent",
            "Accept",
            "Accept-Encoding",
            "Accept-Language",
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-ch-ua-platform",
        ] {
            assert!(
                get(&h, name).is_some(),
                "{profile:?} 缺 {name} —— 自称 Chrome 却不发即 (c) 的 bot 信号"
            );
        }
        assert_eq!(get(&h, "User-Agent").as_deref(), Some(UA));
    }
}

// ── Navigate profile：地址栏导航形态自洽 ─────────────────────────────────

#[test]
fn navigate_profile_is_a_self_consistent_top_level_navigation() {
    let h = browser_headers(
        RequestProfile::Navigate,
        HttpMethod::Get,
        "https://claude.ai/",
    );
    assert_eq!(get(&h, "Accept").as_deref(), Some(ACCEPT_NAVIGATE));
    assert_eq!(get(&h, "Sec-Fetch-Dest").as_deref(), Some("document"));
    assert_eq!(get(&h, "Sec-Fetch-Mode").as_deref(), Some("navigate"));
    assert_eq!(get(&h, "Sec-Fetch-Site").as_deref(), Some("none"));
    assert_eq!(get(&h, "Sec-Fetch-User").as_deref(), Some("?1"));
    assert_eq!(get(&h, "Upgrade-Insecure-Requests").as_deref(), Some("1"));
    assert_eq!(get(&h, "priority").as_deref(), Some(PRIORITY_NAVIGATE));
    // 地址栏导航**不带** Origin/Referer —— 带了才是矛盾。
    assert!(get(&h, "Origin").is_none(), "顶层导航不得带 Origin");
    assert!(get(&h, "Referer").is_none(), "顶层导航不得带 Referer");
}

// ── Api profile：同源 fetch 形态 + Origin 的 method 依赖 ──────────────────

#[test]
fn api_profile_get_has_no_origin_but_post_does() {
    // Chrome 语义：同源 GET fetch 不发 Origin，同源 POST 发。发反 = 新造矛盾信号。
    // 打断点：把 `if method == Post` 去掉（GET 也发 Origin）→ 前半转红；
    //         把整个 Origin 分支删掉 → 后半转红。
    let g = browser_headers(
        RequestProfile::Api,
        HttpMethod::Get,
        "https://api.openai.com/compliance/cookie_requirements",
    );
    assert!(get(&g, "Origin").is_none(), "同源 GET fetch 不得带 Origin");

    let p = browser_headers(
        RequestProfile::Api,
        HttpMethod::Post,
        "https://disney.api.edge.bamgrid.com/devices",
    );
    assert_eq!(
        get(&p, "Origin").as_deref(),
        Some("https://disney.api.edge.bamgrid.com"),
        "同源 POST 必须带 Origin"
    );
}

#[test]
fn api_profile_does_not_claim_to_be_a_document_navigation() {
    // 给 JSON API 发 text/html + Upgrade-Insecure-Requests 就是新造的矛盾 —— 必须不发。
    let h = browser_headers(
        RequestProfile::Api,
        HttpMethod::Get,
        "https://spclient.wg.spotify.com/signup/public/v1/account?validate=1",
    );
    assert_eq!(get(&h, "Accept").as_deref(), Some(ACCEPT_API));
    assert!(get(&h, "Upgrade-Insecure-Requests").is_none());
    assert!(get(&h, "Sec-Fetch-User").is_none());
    assert_eq!(get(&h, "Sec-Fetch-Dest").as_deref(), Some("empty"));
    assert_eq!(get(&h, "Sec-Fetch-Mode").as_deref(), Some("cors"));
    // 子资源/fetch 的优先级 ≠ 顶层文档的 u=0（发反也是矛盾）。
    assert_eq!(get(&h, "priority").as_deref(), Some(PRIORITY_API));
}

// ── origin_of 纯函数 ─────────────────────────────────────────────────────

#[test]
fn origin_of_extracts_scheme_and_authority() {
    assert_eq!(
        origin_of("https://disney.api.edge.bamgrid.com/devices"),
        Some("https://disney.api.edge.bamgrid.com".to_string())
    );
    assert_eq!(
        origin_of("https://Example.COM:8443/a/b?c=1"),
        Some("https://example.com:8443".to_string())
    );
    assert_eq!(origin_of("not-a-url"), None);
    assert_eq!(origin_of("https://"), None);
}
