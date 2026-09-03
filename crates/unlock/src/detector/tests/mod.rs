use super::*;
use crate::http::{RedirectHop, UnlockRequest, UnlockResponse};
use crate::types::UnlockStatus;
use std::sync::Mutex;

/// 测试 mock：按 URL 前缀匹配返回预制响应；未匹配返回 err。记录所有请求供断言。
struct ScriptedHttp {
    scripts: Vec<(String, UnlockResponse)>,
    seen: Mutex<Vec<String>>,
}

impl ScriptedHttp {
    fn new() -> Self {
        Self {
            scripts: Vec::new(),
            seen: Mutex::new(Vec::new()),
        }
    }
    fn on(mut self, url_contains: &str, resp: UnlockResponse) -> Self {
        self.scripts.push((url_contains.to_string(), resp));
        self
    }
}

#[async_trait::async_trait]
impl UnlockHttp for ScriptedHttp {
    async fn request(&self, req: &UnlockRequest) -> UnlockResponse {
        self.seen.lock().unwrap().push(req.url.clone());
        // 找首个 URL 子串匹配的脚本
        for (pat, resp) in &self.scripts {
            if req.url.contains(pat) {
                return resp.clone();
            }
        }
        UnlockResponse::err("no-script")
    }
}

#[tokio::test]
async fn probe_egress_parses_trace() {
    let http = ScriptedHttp::new().on(
        "cloudflare",
        UnlockResponse::ok(
            200,
            "fl=1\nh=cloudflare.com\nip=203.0.113.5\nloc=US\nuag=x\n",
        ),
    );
    let egress = probe_egress(&http).await.unwrap();
    assert_eq!(egress.ip, "203.0.113.5");
    assert_eq!(egress.region.as_deref(), Some("US"));
}

#[tokio::test]
async fn probe_egress_none_on_bad_status() {
    let http = ScriptedHttp::new().on("cloudflare", UnlockResponse::ok(503, ""));
    assert!(probe_egress(&http).await.is_none());
}

#[tokio::test]
async fn is_restricted_recognizes_cn() {
    assert!(is_restricted_egress_region(Some("CN")));
    assert!(is_restricted_egress_region(Some("cn"))); // 大小写不敏感
    assert!(!is_restricted_egress_region(Some("US")));
    assert!(!is_restricted_egress_region(None));
}

#[tokio::test]
async fn detect_aggregates_egress_and_results() {
    // 用一个「全 ok」假 http（含 egress trace + 全部 checker 端点）验证聚合。
    let http = ScriptedHttp::new()
        .on(
            "cloudflare.com/cdn-cgi/trace",
            UnlockResponse::ok(200, "ip=1.1.1.1\nloc=US\n"),
        )
        // chatgpt trace + cookie + ios 全净 -> ok
        .on(
            "chat.openai.com/cdn-cgi/trace",
            UnlockResponse::ok(200, "ip=1.1.1.1\nloc=US\n"),
        )
        .on("api.openai.com", UnlockResponse::ok(200, "{}"))
        .on(
            "ios.chat.openai.com",
            UnlockResponse::ok(200, "<html>welcome</html>"),
        )
        // claude -> 落 claude.ai -> ok
        .on(
            "claude.ai/",
            UnlockResponse {
                status: 200,
                body: String::new(),
                truncated: false,
                redirect_chain: vec![RedirectHop {
                    status: 302,
                    location: "https://claude.ai/login".to_string(),
                }],
                error: None,
                ..Default::default()
            },
        )
        .on(
            "claude.ai/cdn-cgi/trace",
            UnlockResponse::ok(200, "ip=1.1.1.1\nloc=US\n"),
        )
        // gemini -> ok
        .on(
            "gemini.google.com",
            UnlockResponse::ok(200, "blah 45631641,null,true blah"),
        )
        // grok：**停飞集**（`ServiceId::PENDING_CALIBRATION`）。脚本刻意留着当**反向对照**——
        // 它若被请求就会返 Ok 并出现在结果里，所以下方「grok 不在结果 / 未发请求」的断言才有牙。
        .on(
            "grok.com/cdn-cgi/trace",
            UnlockResponse::ok(200, "ip=1.1.1.1\nloc=US\n"),
        )
        .on(
            "grok.com",
            UnlockResponse::ok(200, "<html>cdn.grok.com/_next</html>"),
        )
        // netflix 两片可看 -> ok
        .on(
            "netflix.com/title/81280792",
            UnlockResponse::ok(200, "watchable content"),
        )
        .on(
            "netflix.com/title/70143836",
            UnlockResponse::ok(200, "watchable content"),
        )
        // disney: 全链路 ok（JP 特判）
        .on(
            "bamgrid.com/devices",
            UnlockResponse::ok(200, r#"{"assertion":"A"}"#),
        )
        .on(
            "bamgrid.com/token",
            UnlockResponse::ok(200, r#"{"refresh_token":"R"}"#),
        )
        .on(
            "bamgrid.com/graph",
            UnlockResponse::ok(200, r#"{"countryCode":"JP","inSupportedLocation":true}"#),
        )
        .on("disneyplus.com", UnlockResponse::ok(200, ""))
        // tiktok：store_region 须排在首页脚本**之前**（mock 首个子串匹配即返回，
        // "tiktok.com/" 会先吃掉 passport 请求）。首页无跳转 -> 停在 feed -> ok
        .on(
            "tiktok.com/passport/web/store_region/",
            UnlockResponse::ok(200, r#"{"data":{"store_region":"us"},"message":"success"}"#),
        )
        .on(
            "www.tiktok.com/",
            UnlockResponse::ok(200, "<html>feed</html>"),
        )
        // spotify -> ok
        .on(
            "spotify.com",
            UnlockResponse::ok(
                200,
                r#"{"status":1,"country":"US","is_country_launched":true}"#,
            ),
        );

    let snap = UnlockDetector::detect_with_clock(&http, || 42_000).await;
    assert_eq!(snap.checked_at, Some(42_000));
    assert_eq!(snap.egress.as_ref().unwrap().ip, "1.1.1.1");
    assert_eq!(snap.results.len(), ServiceId::ALL.len());
    // 全部 ok（chatgpt/claude/gemini/netflix/disney/tiktok/spotify）
    for (k, v) in &snap.results {
        assert_eq!(v.status, UnlockStatus::Ok, "service {k} should be Ok");
    }
    // tiktok 已进编排（防 ALL 漏加导致徽章恒 idle）
    assert_eq!(snap.results["tiktok"].region.as_deref(), Some("US"));
}

/// 停飞集（`ServiceId::PENDING_CALIBRATION`，当前 = grok）**一次网络请求都不许发**，也不许出现在快照里。
///
/// 这是「摘出上线集」的实测门（非 review 口头保证）：mock 里 grok 的脚本是全 Ok 的，所以只要编排
/// 遍历面把它带上，`seen` 就会出现 grok.com、`results` 就会多一个 `"grok"` 键 → 转红。
/// 变异有牙：把 `ServiceId::Grok` 加回 `ServiceId::ALL` → 两条断言同时红。
#[tokio::test]
async fn detect_skips_pending_calibration_services() {
    let http = ScriptedHttp::new()
        .on(
            "cloudflare.com/cdn-cgi/trace",
            UnlockResponse::ok(200, "ip=1.1.1.1\nloc=US\n"),
        )
        .on(
            "grok.com/cdn-cgi/trace",
            UnlockResponse::ok(200, "ip=1.1.1.1\nloc=US\n"),
        )
        .on(
            "grok.com",
            UnlockResponse::ok(200, "<html>cdn.grok.com/_next</html>"),
        );

    let snap = UnlockDetector::detect_with_clock(&http, || 42_000).await;
    for id in ServiceId::PENDING_CALIBRATION {
        assert!(
            !snap.results.contains_key(id.as_str()),
            "{} 未上线，不得出现在快照结果里",
            id.as_str()
        );
    }
    let seen = http.seen.lock().unwrap().clone();
    assert!(
        !seen.iter().any(|u| u.contains("grok.com")),
        "停飞服务不得发出任何网络探测，实际请求: {seen:?}"
    );
    // 反证脚本确实可命中：出口 trace 走的是同一个 mock，且它被请求到了。
    assert!(seen.iter().any(|u| u.contains("cloudflare.com")));
}
