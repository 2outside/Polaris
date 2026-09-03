use super::super::{
    invalidate_validators_on_global_ua_change, resolve_subscription_ua, ua_changed,
};
use serde_json::json;

/// 三级链 + **falsy 语义**（与 TS `??` 的差异已登记在函数文档与 `contracts/types.ts`）。
#[test]
fn ua_falls_back_through_three_levels_with_falsy_empty() {
    let global = json!({ "subscriptionUserAgent": "clash-verge/1.0" });
    // per-sub 优先。
    assert_eq!(
        resolve_subscription_ua(&global, &json!({ "userAgent": "sing-box/1.9" })).as_deref(),
        Some("sing-box/1.9")
    );
    // per-sub 缺 → 全局。
    assert_eq!(
        resolve_subscription_ua(&global, &json!({})).as_deref(),
        Some("clash-verge/1.0")
    );
    // **差异格**：per-sub 显式空串 → falsy 回落全局（TS `??` 会让 `""` 胜出并发空 UA）。
    assert_eq!(
        resolve_subscription_ua(&global, &json!({ "userAgent": "" })).as_deref(),
        Some("clash-verge/1.0"),
        "空串按未设处理（发 `User-Agent: ` 空值会让机场下发错格式/0 节点）"
    );
    assert_eq!(
        resolve_subscription_ua(&global, &json!({ "userAgent": "   " })).as_deref(),
        Some("clash-verge/1.0"),
        "纯空白同理"
    );
    // 全局也空 → None（交默认 UA）。
    assert_eq!(
        resolve_subscription_ua(&json!({ "subscriptionUserAgent": "  " }), &json!({})),
        None
    );
    assert_eq!(resolve_subscription_ua(&json!({}), &json!({})), None);
}

/// UA 变更 → 条件 GET 验证器作废（否则机场按 UA 下发变体时永远 304 拿不到新格式）。
///
/// 变异锁：把 `subscription_update` 里那段 `if ua_changed(...) { set_or_remove(..., None) }`
/// 删掉 → `changing_ua_drops_validators` 转红。
#[test]
fn ua_changed_uses_the_same_falsy_normalisation_as_resolution() {
    let with = |ua: serde_json::Value| json!({ "id": "s1", "userAgent": ua });
    assert!(ua_changed(&with(json!("a")), &with(json!("b"))));
    assert!(ua_changed(&json!({ "id": "s1" }), &with(json!("a"))));
    assert!(ua_changed(&with(json!("a")), &json!({ "id": "s1" })));
    // 同值不算变（编辑名字/URL 不该白扔验证器 → 白丢一次条件 GET 的省流）。
    assert!(!ua_changed(&with(json!("a")), &with(json!("a"))));
    // 归一口径与 `resolve_subscription_ua` 一致：缺省/空串/纯空白三者互相之间**不算变更**
    //（它们求值出的实际 UA 完全相同，清验证器纯属白扔）。
    assert!(!ua_changed(&json!({}), &with(json!(""))));
    assert!(!ua_changed(&with(json!("")), &with(json!("   "))));
    // 名字变、UA 没变 → 不动验证器。
    assert!(!ua_changed(
        &json!({ "name": "old", "userAgent": "a" }),
        &json!({ "name": "new", "userAgent": "a" })
    ));
}

// ── 全局 `subscriptionUserAgent` 变更 → 验证器作废（LOW-1）────────────────────

/// 两条订阅：`s-global` 靠全局 UA、`s-own` 自带 per-sub 覆盖。改全局 UA 后**只有前者**该被作废。
///
/// 牙：
/// - 删掉 `invalidate_validators_on_global_ua_change` 里的清除腿 → 第 1、2 条断言转红
///   （= 改了全局 UA 仍带旧 ETag 请求 → 机场恒 304 → 新格式永远拿不到）；
/// - 把射程放宽成「全局变了就全清」（去掉 `per_sub.is_some()` 早退）→ 第 3、4 条转红
///   （白扔一次条件 GET，把下次更新变成全量下载）。
#[test]
fn global_ua_change_invalidates_only_subs_without_per_sub_override() {
    let old = json!({ "subscriptionUserAgent": "clash-verge/1.0" });
    let mut new = json!({
        "subscriptionUserAgent": "sing-box/1.9",
        "subscriptions": [
            { "id": "s-global", "etag": "W/\"v1\"", "lastModified": "Mon, 01 Jan 2024 00:00:00 GMT" },
            { "id": "s-own", "userAgent": "mihomo/1.18", "etag": "W/\"v2\"", "lastModified": "x" },
        ]
    });
    assert_eq!(
        invalidate_validators_on_global_ua_change(&old, &mut new),
        1,
        "只该有 1 条被作废（另一条有 per-sub 覆盖，生效 UA 没变）"
    );
    let subs = new["subscriptions"].as_array().unwrap();
    assert!(
        subs[0].get("etag").is_none(),
        "①靠全局 UA 的订阅：etag 必须清"
    );
    assert!(
        subs[0].get("lastModified").is_none(),
        "②靠全局 UA 的订阅：lastModified 必须清"
    );
    assert_eq!(
        subs[1]["etag"], "W/\"v2\"",
        "③per-sub 覆盖的订阅：生效 UA 与全局无关 → 验证器不得白扔"
    );
    assert_eq!(subs[1]["lastModified"], "x", "④同上");
}

/// 归一口径必须与 [`resolve_subscription_ua`] 一致：缺省 / `""` / 纯空白三者互换**不算变更**；
/// 全局键没动时更不该动任何东西（改别的设置每次都清验证器 = 每次更新都全量下载）。
///
/// 牙：把早退判据从 `pick_ua(...) == pick_ua(...)` 换成裸 `old.get(K) == new.get(K)` → 第 2、3 条转红。
#[test]
fn global_ua_normalisation_and_no_op_paths() {
    let subs = || json!([{ "id": "s1", "etag": "W/\"v1\"", "lastModified": "L" }]);
    // ① 全局键完全没动（改的是别的键）→ 零作废。
    let mut new =
        json!({ "subscriptionUserAgent": "ua/1", "logLevel": "debug", "subscriptions": subs() });
    assert_eq!(
        invalidate_validators_on_global_ua_change(
            &json!({ "subscriptionUserAgent": "ua/1" }),
            &mut new
        ),
        0
    );
    assert_eq!(new["subscriptions"][0]["etag"], "W/\"v1\"");
    // ② 空串 → 纯空白：求值出的 UA 完全相同，不算变更。
    let mut new = json!({ "subscriptionUserAgent": "   ", "subscriptions": subs() });
    assert_eq!(
        invalidate_validators_on_global_ua_change(
            &json!({ "subscriptionUserAgent": "" }),
            &mut new
        ),
        0
    );
    assert_eq!(new["subscriptions"][0]["etag"], "W/\"v1\"");
    // ③ 缺键 → 空串：同理不算变更。
    let mut new = json!({ "subscriptionUserAgent": "", "subscriptions": subs() });
    assert_eq!(
        invalidate_validators_on_global_ua_change(&json!({}), &mut new),
        0
    );
    assert_eq!(new["subscriptions"][0]["etag"], "W/\"v1\"");
    // ④ 缺键 → 真值：这是**真变更**（此前走 net-stack 默认 UA，现在走用户设的）。
    let mut new = json!({ "subscriptionUserAgent": "ua/2", "subscriptions": subs() });
    assert_eq!(
        invalidate_validators_on_global_ua_change(&json!({}), &mut new),
        1
    );
    assert!(new["subscriptions"][0].get("etag").is_none());
    // ⑤ 真值 → 清空：同样是真变更（回落默认 UA，变体可能又换一套）。
    let mut new = json!({ "subscriptionUserAgent": "", "subscriptions": subs() });
    assert_eq!(
        invalidate_validators_on_global_ua_change(
            &json!({ "subscriptionUserAgent": "ua/2" }),
            &mut new
        ),
        1
    );
    assert!(new["subscriptions"][0].get("lastModified").is_none());
}

/// 计数只算「真有验证器被扔掉」的订阅；无 `subscriptions` 键 / 空数组不得 panic。
#[test]
fn count_reflects_actually_dropped_validators_and_tolerates_missing_array() {
    let old = json!({ "subscriptionUserAgent": "a" });
    // 从没拉取过（无验证器）→ 不计数（否则日志谎报条数）。
    let mut new = json!({ "subscriptionUserAgent": "b", "subscriptions": [{ "id": "s1" }] });
    assert_eq!(invalidate_validators_on_global_ua_change(&old, &mut new), 0);
    // subscriptions 缺失 / 非数组 / 空数组 → 0，不 panic。
    let mut new = json!({ "subscriptionUserAgent": "b" });
    assert_eq!(invalidate_validators_on_global_ua_change(&old, &mut new), 0);
    let mut new = json!({ "subscriptionUserAgent": "b", "subscriptions": {} });
    assert_eq!(invalidate_validators_on_global_ua_change(&old, &mut new), 0);
    let mut new = json!({ "subscriptionUserAgent": "b", "subscriptions": [] });
    assert_eq!(invalidate_validators_on_global_ua_change(&old, &mut new), 0);
}
