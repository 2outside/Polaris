use super::*;
use std::collections::BTreeMap;

/// 构造响应（headers 键原样存，[`UnlockResponse::header`] 大小写不敏感取）。
fn resp(status: u16, headers: &[(&str, &str)], body: &str) -> UnlockResponse {
    let mut h = BTreeMap::new();
    for (k, v) in headers {
        h.insert(k.to_string(), v.to_string());
    }
    UnlockResponse {
        status,
        body: body.to_string(),
        truncated: false,
        redirect_chain: Vec::new(),
        error: None,
        headers: h,
    }
}

/// `server: cloudflare` 头（辅判据门必需）。
const CF: (&str, &str) = ("server", "cloudflare");

// ── 主判据 S1：cf-mitigated 一票定案（打断 S1 → 转红）────────────────────────
#[test]
fn s1_cf_mitigated_challenge_even_on_200_without_body_marker() {
    // 仅主判据成立：200 + 无 body marker + cf-mitigated:challenge → CfChallenge。
    // 若打断 S1，本例落 None（200 过不了辅判据门）→ 转红。
    let r = resp(200, &[("cf-mitigated", "challenge")], "<html>ok</html>");
    assert_eq!(classify(&r), Some(ChallengeKind::CfChallenge));
}

#[test]
fn s1_header_name_and_value_case_insensitive() {
    let r = resp(200, &[("CF-Mitigated", "Challenge")], "");
    assert_eq!(classify(&r), Some(ChallengeKind::CfChallenge));
}

#[test]
fn s1_non_challenge_value_not_flagged() {
    // "challenge" 是唯一合法挑战值——其它值不判（防 `.is_some()` 退化误判）。
    let r = resp(403, &[("cf-mitigated", "block"), CF], "");
    assert_eq!(classify(&r), None);
}

// ── 每条辅 marker 各一测（打断该 marker → None → 转红）───────────────────────
#[test]
fn s3_jsch_marker_is_cf_challenge() {
    let r = resp(503, &[CF], "x /cdn-cgi/images/trace/jsch/ x");
    assert_eq!(classify(&r), Some(ChallengeKind::CfChallenge));
}
#[test]
fn s2_captcha_marker_is_cf_challenge() {
    let r = resp(403, &[CF], "x /cdn-cgi/images/trace/captcha/ x");
    assert_eq!(classify(&r), Some(ChallengeKind::CfChallenge));
}
#[test]
fn s2_managed_marker_is_cf_challenge() {
    let r = resp(403, &[CF], "x /cdn-cgi/images/trace/managed/ x");
    assert_eq!(classify(&r), Some(ChallengeKind::CfChallenge));
}
#[test]
fn s2_chl_form_token_marker_is_cf_challenge() {
    let r = resp(429, &[CF], "<form ...> __cf_chl_f_tk=abc123 </form>");
    assert_eq!(classify(&r), Some(ChallengeKind::CfChallenge));
}
#[test]
fn s4_turnstile_api_js_marker() {
    let r = resp(
        403,
        &[CF],
        "<script src=\"https://challenges.cloudflare.com/turnstile/v0/api.js\"></script>",
    );
    assert_eq!(classify(&r), Some(ChallengeKind::Turnstile));
}
#[test]
fn s4_turnstile_widget_class_marker() {
    let r = resp(
        403,
        &[CF],
        r#"<div class="cf-turnstile" data-sitekey="x"></div>"#,
    );
    assert_eq!(classify(&r), Some(ChallengeKind::Turnstile));
}
#[test]
fn s5_firewall_1020_is_firewall_block_not_challenge() {
    // S5 单独归 FirewallBlock（L2），非 CfChallenge——打断 S5 分支 → 落 CfChallenge/None → 转红。
    let r = resp(
        403,
        &[CF],
        r#"<span class="cf-error-code">1020</span> Ray ID"#,
    );
    assert_eq!(classify(&r), Some(ChallengeKind::FirewallBlock));
}

// ── 辅判据门有牙：status / server 各打断一次 ────────────────────────────────
#[test]
fn gate_status_must_be_challenge_range() {
    // body 有强 marker + server cloudflare，但 status=200 → 非挑战（防正常页误判）。
    let r = resp(200, &[CF], "/cdn-cgi/images/trace/managed/");
    assert_eq!(classify(&r), None);
}
#[test]
fn gate_server_must_be_cloudflare() {
    // 403 + body marker 但 server=nginx（源站自有 403 透传）→ 不判（反例3 保守）。
    let r = resp(
        403,
        &[("server", "nginx")],
        "/cdn-cgi/images/trace/managed/",
    );
    assert_eq!(classify(&r), None);
}

// ── 两个误报陷阱：正常 200 页不误判（实测背书，反例1/反例2）─────────────────────
#[test]
fn trap_cf_bm_cookie_on_normal_page_not_challenge() {
    // 反例1：__cf_bm bot-management cookie 在正常 200 页也下发 → 非信号。
    let r = resp(
        200,
        &[
            CF,
            ("set-cookie", "__cf_bm=Ab.Cd-Ef; path=/; HttpOnly; Secure"),
        ],
        "<html><body>normal app page</body></html>",
    );
    assert_eq!(classify(&r), None);
}
#[test]
fn trap_isolated_challenge_platform_on_normal_page_not_challenge() {
    // 反例2：正常页被动注入 /cdn-cgi/challenge-platform/scripts/jsd/main.js（JS detections）→ 非信号。
    let r = resp(
        200,
        &[CF],
        r#"<script src="/cdn-cgi/challenge-platform/scripts/jsd/main.js"></script><div>419KB app</div>"#,
    );
    assert_eq!(classify(&r), None);
}
#[test]
fn trap_both_traps_on_403_still_none_without_strong_marker() {
    // 加固：即便 403+cloudflare，仅陷阱串（无强 marker）→ 仍 None（防陷阱在受限状态下误触）。
    let r = resp(
        403,
        &[CF, ("set-cookie", "__cf_bm=x")],
        r#"<script src="/cdn-cgi/challenge-platform/scripts/jsd/main.js"></script>"#,
    );
    assert_eq!(classify(&r), None);
}
