use super::*;
use crate::http::{HttpMethod, UnlockResponse};

/// 测试 mock：按 URL 子串匹配返回预制响应（**首个匹配生效** -> 特化脚本须排前）；未匹配 -> 传输失败。
struct MockHttp(Vec<(&'static str, UnlockResponse)>);

#[async_trait::async_trait]
impl UnlockHttp for MockHttp {
    async fn request(&self, req: &UnlockRequest) -> UnlockResponse {
        for (pat, resp) in &self.0 {
            if req.url.contains(pat) {
                return resp.clone();
            }
        }
        UnlockResponse::err("no-script")
    }
}

#[test]
fn parse_region_seg_plain() {
    assert_eq!(parse_region_seg("hk"), Some("hk".to_string()));
    assert_eq!(parse_region_seg("jp"), Some("jp".to_string()));
}

#[test]
fn parse_region_seg_with_lang() {
    assert_eq!(parse_region_seg("hk-en"), Some("hk".to_string()));
    assert_eq!(parse_region_seg("jp-ja"), Some("jp".to_string()));
}

#[test]
fn parse_region_seg_rejects_uppercase_and_bad() {
    // Polaris 正则 `/^([a-z]{2})(-[a-z]{2,4})?$/`：头部 2 小写字母，tail 2-4 小写字母
    assert_eq!(parse_region_seg("HK"), None); // 大写不算（路径段已 lowercase 化）
    assert_eq!(parse_region_seg("abc"), None); // 3 字母头部
    assert_eq!(parse_region_seg("us-abcde"), None); // tail 5 字母（超 4）
    assert_eq!(parse_region_seg("us-a"), None); // tail 1 字母（不足 2）
    assert_eq!(parse_region_seg("us-ABC"), None); // tail 大写
                                                  // us-abc：tail 3 字母合法 -> 接受（对齐 Polaris 正则）
    assert_eq!(parse_region_seg("us-abc"), Some("us".to_string()));
    assert_eq!(parse_region_seg("en"), Some("en".to_string())); // 合法但被外层 NON_REGION 过滤
}

#[test]
fn hostname_strips_port_userinfo() {
    assert_eq!(
        hostname_of("https://claude.ai/login"),
        Some("claude.ai".to_string())
    );
    assert_eq!(
        hostname_of("https://claude.ai:443/"),
        Some("claude.ai".to_string())
    );
    assert_eq!(
        hostname_of("https://user:pass@www.anthropic.com/x"),
        Some("www.anthropic.com".to_string())
    );
}

#[test]
fn strip_query_fragment_works() {
    assert_eq!(
        strip_query_fragment("https://x.com/a?b=1"),
        "https://x.com/a"
    );
    assert_eq!(
        strip_query_fragment("https://x.com/a#frag"),
        "https://x.com/a"
    );
    assert_eq!(
        strip_query_fragment("https://x.com/a?b=1#c"),
        "https://x.com/a"
    );
}

#[test]
fn netflix_region_from_chain_picks_locale() {
    use crate::http::{RedirectHop, UnlockResponse};
    let res = UnlockResponse {
        status: 200,
        body: String::new(),
        truncated: false,
        error: None,
        redirect_chain: vec![RedirectHop {
            status: 302,
            location: "https://www.netflix.com/hk-en/title/81280792".to_string(),
        }],
        ..Default::default()
    };
    assert_eq!(netflix_region_from_chain(&res), Some("HK".to_string()));
}

// ── 挑战识别接入既有 checker（设计 §2.5 正确性修复）────────────────────────────
// 与 challenge.rs 的分类器单测互补：这里验「命中挑战 → checker 返 Restricted 而非误 Ok/Blocked」。

/// CF 挑战响应（403 + `cf-mitigated: challenge`，reachable）。
fn challenge_resp() -> UnlockResponse {
    let mut headers = std::collections::BTreeMap::new();
    headers.insert("cf-mitigated".to_string(), "challenge".to_string());
    headers.insert("server".to_string(), "cloudflare".to_string());
    UnlockResponse {
        status: 403,
        body: "<html><head><title>Just a moment...</title></head></html>".to_string(),
        truncated: false,
        redirect_chain: Vec::new(),
        error: None,
        headers,
    }
}

#[tokio::test]
async fn chatgpt_challenge_yields_restricted_not_ok() {
    // 现状 bug：挑战页无 VPN/unsupported_country marker → 两净 → 误 Ok。接入后 → Restricted。
    let http = MockHttp(vec![
        (
            "chat.openai.com/cdn-cgi/trace",
            UnlockResponse::ok(200, "ip=1.1.1.1\nloc=US\n"),
        ),
        ("api.openai.com", challenge_resp()), // cookie 端点被挑战拦
        (
            "ios.chat.openai.com",
            UnlockResponse::ok(200, "<html>welcome</html>"),
        ),
    ]);
    let r = check_chatgpt(&http).await;
    assert_eq!(r.status, UnlockStatus::Restricted);
    assert_eq!(r.region.as_deref(), Some("US")); // region 仍从 trace 取
}

#[tokio::test]
async fn gemini_challenge_yields_restricted_not_blocked() {
    // 现状 bug：挑战页缺 AVAILABLE_MARKER → 误 Blocked。接入后（marker 判定前短路）→ Restricted。
    let http = MockHttp(vec![("gemini.google.com", challenge_resp())]);
    let r = check_gemini(&http).await;
    assert_eq!(r.status, UnlockStatus::Restricted);
}

/// CF **1020 防火墙拒绝**响应（403 + `server: cloudflare` + body 1020 marker，**无** cf-mitigated）。
/// 走 `challenge.rs` 的辅判据门 —— 与 `challenge_resp()` 是两条不同的命中路径，须各自覆盖。
fn firewall_1020_resp() -> UnlockResponse {
    let mut headers = std::collections::BTreeMap::new();
    headers.insert("server".to_string(), "cloudflare".to_string());
    UnlockResponse {
        status: 403,
        body: r#"<span class="cf-error-code">1020</span> Ray ID: abc"#.to_string(),
        truncated: false,
        redirect_chain: Vec::new(),
        error: None,
        headers,
    }
}

// ── 新增覆盖：claude / netflix / spotify / disney 的挑战误报路径 ──────────────
// 每条都对应一个**具体的**误报形态（注释写明「不接挑战识别会误报成什么」）。
// 变异验证：删掉对应 checker 里的 `any_challenged` 短路 → 该测试转红（断言的正是那个误报值）。

#[tokio::test]
async fn claude_challenge_on_own_domain_is_ok() {
    // 真机语义（2026-07-28 用户实测背书）：**命中挑战 = 服务在本区可访问**，浏览器过一下挑战就能用。
    // Anthropic 对封禁地区给的是明确的 302 → `www.anthropic.com/app-unavailable-in-region`（另一条门守）。
    //
    // 守的缺陷：此前 `any_challenged` 短路在 host 判定之前 → 能用的地区只要撞上一次风控挑战就报
    // `Restricted`（红灯）。变异：把 `any_challenged` 挪回 host 判定之前 → 本条转红。
    let http = MockHttp(vec![
        (
            "claude.ai/cdn-cgi/trace",
            UnlockResponse::ok(200, "ip=1.1.1.1\nloc=JP\n"),
        ),
        ("claude.ai", challenge_resp()),
    ]);
    let r = check_claude(&http).await;
    assert_eq!(
        r.status,
        UnlockStatus::Ok,
        "挑战停在 claude.ai 本域 = 本区可用，判 Restricted 是把风控当成地区封禁"
    );
    assert_eq!(
        r.region.as_deref(),
        Some("JP"),
        "region 仍从 trace 取，不受挑战影响"
    );
}

#[tokio::test]
async fn claude_challenge_on_unknown_domain_is_restricted_not_timeout() {
    // 挑战识别在**未知域**分支才有信息量：导航被风控截停在中间域，说得出「是风控」就别报
    // 说不清的 `Timeout`。变异：删未知域分支的 `any_challenged` → 本条转红（回落 Timeout）。
    let mut resp = challenge_resp();
    resp.redirect_chain = vec![RedirectHopForTest::hop(
        302,
        "https://challenges.cloudflare.com/hold",
    )];
    let http = MockHttp(vec![("claude.ai", resp)]);
    let r = check_claude(&http).await;
    assert_eq!(r.status, UnlockStatus::Restricted);
}

#[tokio::test]
async fn claude_geo_block_still_wins_over_challenge() {
    // 反向门：`app-unavailable-in-region` 是源站的**明确地区裁决**，必须仍判 Blocked，
    // 不得被挑战识别抢走。若把 any_challenged 挪到 BLOCK_MARKER 之前 → 本测试转红。
    let mut resp = challenge_resp();
    resp.redirect_chain = vec![RedirectHopForTest::hop(
        302,
        "https://www.anthropic.com/app-unavailable-in-region",
    )];
    let http = MockHttp(vec![("claude.ai", resp)]);
    let r = check_claude(&http).await;
    assert_eq!(r.status, UnlockStatus::Blocked);
}

#[tokio::test]
async fn netflix_challenge_yields_restricted_not_blocked() {
    // 误报形态：挑战页是 403 → 命中 `not_available`（`r.status == 403`）→ 误 **Blocked**
    //（把风控拦截报成「Netflix 未进本国」，用户以为换国家，实际该换 IP 质量）。
    let http = MockHttp(vec![("www.netflix.com/title", challenge_resp())]);
    let r = check_netflix(&http).await;
    assert_eq!(r.status, UnlockStatus::Restricted);
}

#[tokio::test]
async fn netflix_firewall_1020_yields_restricted_not_blocked() {
    // 同上，但走 1020 辅判据门（无 cf-mitigated 头）——证明两条命中路径都接住了。
    let http = MockHttp(vec![("www.netflix.com/title", firewall_1020_resp())]);
    let r = check_netflix(&http).await;
    assert_eq!(r.status, UnlockStatus::Restricted);
}

#[tokio::test]
async fn netflix_genuine_403_not_available_still_blocked() {
    // 反向门：真·国家级不可用（403 + "Not Available"，**非** CF）必须仍判 Blocked。
    // 若挑战识别放宽到「凡 403 即 Restricted」→ 本测试转红（真 Blocked 被吞成 Restricted）。
    let mut r403 = UnlockResponse::ok(403, "Not Available in your country");
    r403.headers
        .insert("server".to_string(), "nginx".to_string());
    let http = MockHttp(vec![("www.netflix.com/title", r403)]);
    let r = check_netflix(&http).await;
    assert_eq!(r.status, UnlockStatus::Blocked);
}

#[tokio::test]
async fn spotify_challenge_yields_restricted_not_timeout() {
    // 误报形态：挑战页无 `"status":NNN` → 误 **Timeout**（说「网络超时」，
    // 用户去重试，实际该换出口）。
    let http = MockHttp(vec![("spclient.wg.spotify.com", challenge_resp())]);
    let r = check_spotify(&http).await;
    assert_eq!(r.status, UnlockStatus::Restricted);
}

#[tokio::test]
async fn disney_devices_challenge_yields_restricted_not_timeout() {
    // 误报形态：挑战页无 assertion → 误 **Timeout**。
    let http = MockHttp(vec![("bamgrid.com/devices", challenge_resp())]);
    let r = check_disney(&http).await;
    assert_eq!(r.status, UnlockStatus::Restricted);
}

#[tokio::test]
async fn disney_graphql_challenge_yields_restricted_not_blocked() {
    // 误报形态：graphql 挑战页无 countryCode → region=None → 误 **Blocked**。
    // MockHttp 首个匹配生效 → 特化的 /graph 必须排在泛化 bamgrid 之前。
    let http = MockHttp(vec![
        ("bamgrid.com/graph", challenge_resp()),
        (
            "bamgrid.com/devices",
            UnlockResponse::ok(200, r#"{"assertion":"A1"}"#),
        ),
        (
            "bamgrid.com/token",
            UnlockResponse::ok(200, r#"{"refresh_token":"R1"}"#),
        ),
    ]);
    let r = check_disney(&http).await;
    assert_eq!(r.status, UnlockStatus::Restricted);
}

/// **Disney ⑤ preview 腿的传输守卫**：preview 请求打不通时，「重定向链里没有 preview/unavailable」
/// 不构成「不 Blocked」的证据 —— 那是缺证据，不是阴性证据。必须落 Timeout，不得靠 ⑥ 的
/// `inSupportedLocation:true` 顺势出 Ok。
///
/// **变异锁**：删掉 `if !pv.reachable()` 那道守卫 → final_url 只剩 PREVIEW_URL（不含 marker）→
/// 落到 ⑥ 按 `inSupportedLocation:true` 出 **Ok** → 本测转红。
#[tokio::test]
async fn disney_preview_unreachable_yields_timeout_not_ok() {
    let http = MockHttp(vec![
        (
            "bamgrid.com/graph",
            UnlockResponse::ok(200, r#"{"countryCode":"HK","inSupportedLocation":true}"#),
        ),
        (
            "bamgrid.com/devices",
            UnlockResponse::ok(200, r#"{"assertion":"A1"}"#),
        ),
        (
            "bamgrid.com/token",
            UnlockResponse::ok(200, r#"{"refresh_token":"R1"}"#),
        ),
        // preview 腿传输失败（status=0 + error）→ reachable()==false。
        (
            "www.disneyplus.com",
            UnlockResponse::err("connection reset"),
        ),
    ]);
    let r = check_disney(&http).await;
    assert_eq!(
        r.status,
        UnlockStatus::Timeout,
        "preview 腿没打通 → 判不了 ⑤ → 如实 Timeout（绝不拿缺证据冒充阴性证据）"
    );
}

/// **Disney ⑤ preview 腿的挑战守卫**：CF 挑战页同理 —— 拿到的是挑战页的链，不是真实落地链。
///
/// **变异锁**：删掉 `any_challenged(&[&pv])` 那道守卫 → 挑战页链不含 marker → 落 ⑥ 出 **Ok** → 转红。
#[tokio::test]
async fn disney_preview_challenge_yields_restricted_not_ok() {
    let http = MockHttp(vec![
        (
            "bamgrid.com/graph",
            UnlockResponse::ok(200, r#"{"countryCode":"HK","inSupportedLocation":true}"#),
        ),
        (
            "bamgrid.com/devices",
            UnlockResponse::ok(200, r#"{"assertion":"A1"}"#),
        ),
        (
            "bamgrid.com/token",
            UnlockResponse::ok(200, r#"{"refresh_token":"R1"}"#),
        ),
        ("www.disneyplus.com", challenge_resp()),
    ]);
    let r = check_disney(&http).await;
    assert_eq!(
        r.status,
        UnlockStatus::Restricted,
        "preview 腿被风控拦截 → Restricted（换出口），不是 Ok"
    );
}

// ── Grok 弱 checker（设计 §3.3 判定表 G1/G2/G4/G5 + G3 空规则 + region 双源）─────────

#[tokio::test]
async fn grok_ok_on_app_page_with_trace_region() {
    // G4（解锁）：200 + 应用页特征 marker + trace loc → Ok（**弱语义**：仅站点可达）。region 取 trace loc。
    let http = MockHttp(vec![
        (
            "grok.com/cdn-cgi/trace",
            UnlockResponse::ok(200, "ip=1.1.1.1\nloc=JP\n"),
        ),
        (
            "grok.com",
            UnlockResponse::ok(
                200,
                "<html><script src=cdn.grok.com/_next/x.js></script></html>",
            ),
        ),
    ]);
    let r = check_grok(&http).await;
    assert_eq!(r.status, UnlockStatus::Ok);
    assert_eq!(r.region.as_deref(), Some("JP"));
}

#[tokio::test]
async fn grok_restricted_on_challenge() {
    // G2（受限）：首页命中 CF 挑战 → Restricted（风控拦截，非地区问题）。
    let http = MockHttp(vec![
        (
            "grok.com/cdn-cgi/trace",
            UnlockResponse::ok(200, "ip=1.1.1.1\nloc=US\n"),
        ),
        ("grok.com", challenge_resp()),
    ]);
    let r = check_grok(&http).await;
    assert_eq!(r.status, UnlockStatus::Restricted);
    assert_eq!(r.region.as_deref(), Some("US"));
}

/// **变异锁（G2 必须在 G4 之前短路）**：构造一个**同时**命中 CF 挑战与 `APP_MARKER` 的响应
/// （真实挑战页可以内嵌站点资源引用，`grok.com/` 的 CF 挑战尤其可能带 `cdn.grok.com` 串）。
///
/// 删掉 `any_challenged` 短路、或把它挪到 G4 之后 → 本例走 G4 判 **Ok** → 绿灯谎报「站点可达」，
/// 而实际什么都没测到 → 本测转红。
#[tokio::test]
async fn grok_challenge_wins_over_app_marker_not_ok() {
    let mut resp = challenge_resp();
    resp.body = format!(
        "<html>Just a moment...<script src={}></script></html>",
        GrokEndpoints::APP_MARKER
    );
    let http = MockHttp(vec![
        (
            "grok.com/cdn-cgi/trace",
            UnlockResponse::ok(200, "ip=1.1.1.1\nloc=US\n"),
        ),
        ("grok.com", resp),
    ]);
    let r = check_grok(&http).await;
    assert_eq!(
        r.status,
        UnlockStatus::Restricted,
        "挑战页即便含应用页特征串也必须归 Restricted —— 判据来自 CF 的墙，不是 grok 的真实响应"
    );
}

#[tokio::test]
async fn grok_timeout_when_home_unreachable() {
    // G1（不可达）：首页传输失败 → Timeout（无响应 ≠ 封禁），无 region。
    let http = MockHttp(vec![]);
    let r = check_grok(&http).await;
    assert_eq!(r.status, UnlockStatus::Timeout);
    assert_eq!(r.region, None);
}

#[tokio::test]
async fn grok_timeout_on_200_without_app_marker() {
    // G5（无法判定）：200 但无应用页特征（非 CF、非挑战）→ 保守兜底 Timeout（不误 Ok/Blocked）。
    let http = MockHttp(vec![
        (
            "grok.com/cdn-cgi/trace",
            UnlockResponse::ok(200, "ip=1.1.1.1\nloc=US\n"),
        ),
        (
            "grok.com",
            UnlockResponse::ok(200, "<html>unexpected portal</html>"),
        ),
    ]);
    let r = check_grok(&http).await;
    assert_eq!(r.status, UnlockStatus::Timeout);
    assert_eq!(r.region.as_deref(), Some("US"));
}

#[tokio::test]
async fn grok_region_falls_back_to_x_country_code_header() {
    // region 辅源：trace 无有效 loc（同脚本回落，body 无 ip=）→ 用 x-country-code 头。
    let mut headers = std::collections::BTreeMap::new();
    headers.insert(GrokEndpoints::COUNTRY_HEADER.to_string(), "DE".to_string());
    let home = UnlockResponse {
        status: 200,
        body: "<html>cdn.grok.com/_next</html>".to_string(),
        truncated: false,
        redirect_chain: Vec::new(),
        error: None,
        headers,
    };
    // 只脚本 "grok.com" → trace 请求也命中它，body 无 ip= → trace_region None → 回落 header。
    let http = MockHttp(vec![("grok.com", home)]);
    let r = check_grok(&http).await;
    assert_eq!(r.status, UnlockStatus::Ok);
    assert_eq!(r.region.as_deref(), Some("DE"));
}

/// **G3 空规则的诚实门（钉死「未解锁」分支目前不存在）**：grok 查无静态 geo-block marker，
/// 设计 §3.3/§11 明确 G3 上线初期为空规则、G3′（`POST /rest/models` 模型清单差异法）**须真机标定后**才上。
///
/// 本测把这条边界钉成断言：任何「站点非 200 / 非挑战」的形态都必须落 `Timeout`，**绝不**冒出 `Blocked`。
/// 谁哪天凭猜测加一条 Blocked 规则（如把 403 直接判地区封禁），本测转红 —— 逼他先做标定。
#[tokio::test]
async fn grok_never_reports_blocked_before_g3_is_calibrated() {
    for (status, body) in [
        (403u16, "Forbidden"),
        (451, "Unavailable For Legal Reasons"),
        (503, "Service Unavailable"),
        (200, "This service is not available in your region"),
    ] {
        let http = MockHttp(vec![
            (
                "grok.com/cdn-cgi/trace",
                UnlockResponse::ok(200, "ip=1.1.1.1\nloc=DE\n"),
            ),
            ("grok.com", UnlockResponse::ok(status, body)),
        ]);
        let r = check_grok(&http).await;
        assert_eq!(
            r.status,
            UnlockStatus::Timeout,
            "status={status} body={body:?}：G3 未标定前不得判 Blocked（宁可无信息，不可误报）"
        );
    }
}

// ── TikTok（对齐 1-stream check.sh MediaUnlockTest_Tiktok；判据来源见 TiktokEndpoints）───

/// 302 → location 的响应（模拟 curl `%{url_effective}` 的最终落点）。
fn redirect_to(location: &str) -> UnlockResponse {
    UnlockResponse {
        status: 200,
        body: String::new(),
        truncated: false,
        error: None,
        redirect_chain: vec![crate::http::RedirectHop {
            status: 302,
            location: location.to_string(),
        }],
        ..Default::default()
    }
}

/// store_region 正常返回 `region`（小写，如 "us"）的脚本项。
/// **须排在首页脚本之前**：mock 首匹配生效，而 `"www.tiktok.com/"` 是 passport URL 的子串。
fn store_region(region: &str) -> (&'static str, UnlockResponse) {
    (
        "tiktok.com/passport/web/store_region/",
        UnlockResponse::ok(
            200,
            format!(r#"{{"data":{{"store_region":"{region}"}},"message":"success"}}"#),
        ),
    )
}

#[tokio::test]
async fn tiktok_ok_when_home_stays_on_feed() {
    // 解锁：无跳转 = 停在正常 feed → check.sh 绿色 Yes → Ok。
    let http = MockHttp(vec![
        store_region("us"),
        (
            "www.tiktok.com/",
            UnlockResponse::ok(200, "<html>feed</html>"),
        ),
    ]);
    let r = check_tiktok(&http).await;
    assert_eq!(r.status, UnlockStatus::Ok);
    assert_eq!(r.region.as_deref(), Some("US")); // store_region 大写化
}

#[tokio::test]
async fn tiktok_blocked_on_about_landing() {
    // 未解锁：check.sh `[[ "$result" == *"/about" ]]` → No。带 query 顺带验 strip_query_fragment 硬化。
    let http = MockHttp(vec![
        store_region("jp"),
        (
            "www.tiktok.com/",
            redirect_to("https://www.tiktok.com/about?lang=en"),
        ),
    ]);
    let r = check_tiktok(&http).await;
    assert_eq!(r.status, UnlockStatus::Blocked);
    assert_eq!(r.region.as_deref(), Some("JP"));
}

#[tokio::test]
async fn tiktok_partial_when_cn_redirected_to_douyin() {
    // 部分解锁：check.sh 黄色 "Provided by Douyin" —— 落地页 + store_region==cn → Partial（非 Blocked）。
    let http = MockHttp(vec![
        store_region("cn"),
        (
            "www.tiktok.com/",
            redirect_to("https://www.tiktok.com/about"),
        ),
    ]);
    let r = check_tiktok(&http).await;
    assert_eq!(r.status, UnlockStatus::Partial);
    assert_eq!(r.region.as_deref(), Some("CN"));
}

#[tokio::test]
async fn tiktok_timeout_when_home_unreachable() {
    // 不可达：无脚本匹配 → status=0 + error → Timeout（无响应 ≠ 封禁）。
    let http = MockHttp(vec![]);
    let r = check_tiktok(&http).await;
    assert_eq!(r.status, UnlockStatus::Timeout);
    assert_eq!(r.region, None);
}

/// **变异锁（挑战识别必须在 URL 分类之前）**：CF 挑战页**不重定向** → `redirect_chain` 空 →
/// 最终 URL 退化成首页 URL → 不含任何落地页 marker → 走「停在 feed」分支判 **Ok**。
///
/// 即：TikTok 这条 checker 的兜底方向是 `Ok`，缺了挑战守卫就是**谎报绿灯**。
/// 删掉 `any_challenged(&[&home])` → 本测得到 Ok → 转红。
#[tokio::test]
async fn tiktok_challenge_yields_restricted_not_ok() {
    let http = MockHttp(vec![
        store_region("us"),
        ("www.tiktok.com/", challenge_resp()),
    ]);
    let r = check_tiktok(&http).await;
    assert_eq!(
        r.status,
        UnlockStatus::Restricted,
        "挑战页不重定向 → 最终 URL 仍是首页 → 缺守卫就误 Ok（绿灯但什么都没测到）"
    );
    assert_eq!(
        r.region.as_deref(),
        Some("US"),
        "region 仍从 store_region 取"
    );
}

#[tokio::test]
async fn tiktok_store_region_failure_does_not_gate_verdict() {
    // 对齐 check.sh：只以首页结果判定；store_region 挂了只是没 region 展示，不改 Ok/Blocked。
    let http = MockHttp(vec![(
        "www.tiktok.com/",
        UnlockResponse::ok(200, "<html>feed</html>"),
    )]);
    let r = check_tiktok(&http).await;
    assert_eq!(r.status, UnlockStatus::Ok);
    assert_eq!(r.region, None);
}

#[tokio::test]
async fn tiktok_blocked_without_region_when_store_region_missing() {
    // 落地页 + 无 region → region != CN → Blocked（不误判为 Douyin/Partial）。
    let http = MockHttp(vec![(
        "www.tiktok.com/",
        redirect_to("https://www.tiktok.com/about"),
    )]);
    let r = check_tiktok(&http).await;
    assert_eq!(r.status, UnlockStatus::Blocked);
    assert_eq!(r.region, None);
}

/// TikTok 纯分类器 fixture 表：直接喂 check.sh `%{url_effective}` 文档化响应形态 → 断言 UnlockStatus。
/// 来源 = 1-stream/RegionRestrictionCheck `check.sh:3457-3482`（`MediaUnlockTest_Tiktok`）。
/// **无 HTTP、无 mock**：纯 parse/判定层验证（HTTP 编排由上面的 MockHttp 集测覆盖）。
/// 端点/响应真实性未经真机验证（本机无海外出口）——URL 形态来自 check.sh 判定分支，见标定 runbook。
///
/// **变异锁**：`/about?lang=en` 一行钉死「先 strip_query_fragment 再匹配」这条硬化 ——
/// 改回 check.sh 的 raw 后缀匹配（bash `*"/about"`）→ 该行判 Ok → 转红。
#[test]
fn tiktok_classifier_matches_checksh_decision_table() {
    // (首页跟随跳转后的最终 url_effective, store_region 大写, 期望 status)
    let cases: &[(&str, Option<&str>, UnlockStatus)] = &[
        // 停在 feed（未被打到落地页）→ check.sh 绿色 Yes → Ok
        ("https://www.tiktok.com/", Some("US"), UnlockStatus::Ok),
        (
            "https://www.tiktok.com/foryou",
            Some("JP"),
            UnlockStatus::Ok,
        ),
        // `*"/about"` 结尾落地页 → check.sh 红色 No → Blocked
        (
            "https://www.tiktok.com/about",
            Some("JP"),
            UnlockStatus::Blocked,
        ),
        // 硬化：`/about?lang=xx`（带 query）check.sh 会漏判 Yes，此处归一化后仍判 Blocked
        (
            "https://www.tiktok.com/about?lang=en",
            Some("DE"),
            UnlockStatus::Blocked,
        ),
        // `*"/status"*` 落地页 → No → Blocked
        (
            "https://www.tiktok.com/status/unavailable",
            Some("DE"),
            UnlockStatus::Blocked,
        ),
        // `*"landing"*` 落地页 → No → Blocked
        (
            "https://www.tiktok.com/login/landing",
            Some("FR"),
            UnlockStatus::Blocked,
        ),
        // 落地页 + region==CN → check.sh 黄色 Provided by Douyin → Partial
        (
            "https://www.tiktok.com/about",
            Some("CN"),
            UnlockStatus::Partial,
        ),
        // 落地页 + region 缺失 → 非 CN → Blocked（不误判 Douyin）
        ("https://www.tiktok.com/about", None, UnlockStatus::Blocked),
    ];
    for (url, region, want) in cases {
        let got = classify_tiktok(url, region.map(|s| s.to_string()));
        assert_eq!(got.status, *want, "status url={url} region={region:?}");
        // region 仅透传（不改判定）：验证 store_region 值原样带出供 UI 展示
        assert_eq!(got.region.as_deref(), *region, "region 透传 url={url}");
    }
}

/// **Netflix region 逐跳续找**：真实链常是 `netflix.com/` →（无路径段）→ `netflix.com/hk-en/title/...`。
///
/// **变异锁**：把两处 `else { continue }` 改回 `?` → 首跳无路径段即从整个函数返回 None → region 丢成
/// `None`（进而被上层的 `status==200 → "US"` 兜底误标成 US）→ 本测转红。
#[test]
fn netflix_region_skips_non_region_hops_instead_of_aborting() {
    use crate::http::{RedirectHop, UnlockResponse};
    let res = UnlockResponse {
        status: 200,
        body: String::new(),
        truncated: false,
        error: None,
        redirect_chain: vec![
            // 跳 1：无路径段（`?` 会在此处放弃整条链）。
            RedirectHop {
                status: 302,
                location: "https://www.netflix.com/".to_string(),
            },
            // 跳 2：路径段不是地区形态（`?` 同样会在此放弃）。
            RedirectHop {
                status: 302,
                location: "https://www.netflix.com/browse/genre".to_string(),
            },
            // 跳 3：真正的地区段 —— 必须找得到。
            RedirectHop {
                status: 302,
                location: "https://www.netflix.com/hk-en/title/81280792".to_string(),
            },
        ],
        ..Default::default()
    };
    assert_eq!(netflix_region_from_chain(&res), Some("HK".to_string()));
}

/// 反向门：`en` 这类已知非地区段仍须跳过（不能因为改成 continue 就把语言码当地区）。
#[test]
fn netflix_region_still_skips_known_non_region_segment() {
    use crate::http::{RedirectHop, UnlockResponse};
    let res = UnlockResponse {
        status: 200,
        body: String::new(),
        truncated: false,
        error: None,
        redirect_chain: vec![
            RedirectHop {
                status: 302,
                location: "https://help.netflix.com/en".to_string(),
            },
            RedirectHop {
                status: 302,
                location: "https://www.netflix.com/jp/title/70143836".to_string(),
            },
        ],
        ..Default::default()
    };
    assert_eq!(netflix_region_from_chain(&res), Some("JP".to_string()));
}

// ── 浏览器头集确实接到了每个请求上（(c) 的接线门）────────────────────────────

/// 记录所有发出请求的 mock（验头集接线，不验判定）。
struct RecordingHttp(std::sync::Mutex<Vec<UnlockRequest>>);

#[async_trait::async_trait]
impl UnlockHttp for RecordingHttp {
    async fn request(&self, req: &UnlockRequest) -> UnlockResponse {
        self.0.lock().unwrap().push(req.clone());
        UnlockResponse::err("recording-only")
    }
}

/// 跑**全部**已实现 checker（上线集 + 停飞集），收集它们实际发出的请求。
///
/// 刻意遍历 [`ServiceId::ALL`] ⧺ [`ServiceId::PENDING_CALIBRATION`] 而非硬编码清单：新增服务自动
/// 落进头集接线门，不会因为「加了 checker 忘了加进这个列表」而漏守（grok/tiktok 接入时就是靠这条
/// 自动覆盖）。**停飞集也要跑**：grok 的 checker 仍在仓里，标定后随时上线，其间不能失去头集守护
/// （否则「停飞期间悄悄退化 → 上线那天才发现」）。
async fn record_all_requests() -> Vec<UnlockRequest> {
    let http = RecordingHttp(std::sync::Mutex::new(Vec::new()));
    for id in ServiceId::ALL.iter().chain(ServiceId::PENDING_CALIBRATION) {
        let _ = run_checker(*id, &http).await;
    }
    let out = http.0.lock().unwrap().clone();
    out
}

#[tokio::test]
async fn every_outgoing_request_carries_the_full_browser_header_set() {
    // 这扇门守 (c) 的**接线**（`browser.rs` 的单测只守头集内容本身）：
    // 任何一个 checker 漏套 `get_req`/`post_req` → 该请求缺头 → 转红。
    // 变异验证：把任一 checker 改回 `UnlockRequest::get(url).header("User-Agent", UA)` → 转红。
    let reqs = record_all_requests();
    let reqs = reqs.await;
    assert!(!reqs.is_empty(), "应至少发出一个请求");
    for req in &reqs {
        for name in [
            "user-agent",
            "accept",
            "accept-encoding",
            "accept-language",
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-ch-ua-platform",
        ] {
            let found = req
                .headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case(name));
            assert!(found, "{} 缺 {name} 头（漏套浏览器头集）", req.url);
        }
    }
}

#[tokio::test]
async fn accept_encoding_is_sent_on_every_request() {
    // (c) 的核心症状单列一门：**自称 Chrome 却不发 Accept-Encoding**。
    // 注意这只证明「发了」；「发的编码传输层解得开」由 src-tauri 的回环解压门守。
    let reqs = record_all_requests().await;
    for req in &reqs {
        let ae = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("accept-encoding"))
            .map(|(_, v)| v.as_str());
        assert_eq!(
            ae,
            Some(crate::browser::ACCEPT_ENCODING),
            "{} 的 Accept-Encoding 必须 = 头集 SoT",
            req.url
        );
    }
}

#[tokio::test]
async fn business_headers_win_over_browser_header_set() {
    // Disney 的 Authorization/Content-Type 必须盖过头集（后设者覆盖）——
    // 若顺序反了，bamgrid 的鉴权会被 `Accept: */*` 之类顶掉而全线 Timeout。
    let reqs = record_all_requests().await;
    let dev = reqs
        .iter()
        .find(|r| r.url.contains("/devices"))
        .expect("Disney devices 请求必须发出");
    assert_eq!(
        dev.headers.get("Content-Type").map(String::as_str),
        Some("application/json; charset=UTF-8")
    );
    assert!(dev
        .headers
        .get("Authorization")
        .is_some_and(|v| v.starts_with("Bearer ")));
    assert_eq!(dev.method, HttpMethod::Post);
    // POST 的 Api profile 必须带 Origin（Chrome 语义）。
    assert_eq!(
        dev.headers.get("Origin").map(String::as_str),
        Some("https://disney.api.edge.bamgrid.com")
    );
}

/// 测试用 RedirectHop 构造糖（避免在断言里重复写字段）。
struct RedirectHopForTest;
impl RedirectHopForTest {
    fn hop(status: u16, location: &str) -> crate::http::RedirectHop {
        crate::http::RedirectHop {
            status,
            location: location.to_string(),
        }
    }
}
