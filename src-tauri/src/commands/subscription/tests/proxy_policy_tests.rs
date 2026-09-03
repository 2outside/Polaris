use super::super::{
    backend_subscription_route_uses_proxy, resolve_subscription_via_proxy, want_proxy_for_sub,
};
use serde_json::json;

#[test]
fn resolve_truth_table() {
    // proxy：强制经代理，忽略 per-sub。
    assert!(resolve_subscription_via_proxy(Some("proxy"), Some(false)));
    assert!(resolve_subscription_via_proxy(Some("proxy"), None));
    // direct：强制直连，忽略 per-sub。
    assert!(!resolve_subscription_via_proxy(Some("direct"), Some(true)));
    assert!(!resolve_subscription_via_proxy(Some("direct"), None));
    // follow / 未知 / 缺省：按 per-sub。
    assert!(resolve_subscription_via_proxy(Some("follow"), Some(true)));
    assert!(!resolve_subscription_via_proxy(Some("follow"), Some(false)));
    assert!(!resolve_subscription_via_proxy(Some("follow"), None));
    assert!(resolve_subscription_via_proxy(None, Some(true)));
    assert!(!resolve_subscription_via_proxy(None, None));
    // 未知策略值回落 follow（sanitize 前的脏值也不误判强制）。
    assert!(resolve_subscription_via_proxy(Some("bogus"), Some(true)));
    assert!(!resolve_subscription_via_proxy(Some("bogus"), Some(false)));
}

#[test]
fn want_proxy_reads_global_and_per_sub_keys() {
    // 全局 proxy 覆盖 per-sub false。
    let cfg = json!({ "subscriptionProxyPolicy": "proxy" });
    let sub = json!({ "updateViaProxy": false });
    assert!(want_proxy_for_sub(&cfg, &sub), "全局 proxy 覆盖 per-sub 关");
    // 全局 direct 覆盖 per-sub true。
    let cfg = json!({ "subscriptionProxyPolicy": "direct" });
    let sub = json!({ "updateViaProxy": true });
    assert!(
        !want_proxy_for_sub(&cfg, &sub),
        "全局 direct 覆盖 per-sub 开"
    );
    // 缺全局键 → follow → 读 per-sub。
    let cfg = json!({});
    assert!(want_proxy_for_sub(&cfg, &json!({ "updateViaProxy": true })));
    assert!(!want_proxy_for_sub(
        &cfg,
        &json!({ "updateViaProxy": false })
    ));
    assert!(!want_proxy_for_sub(&cfg, &json!({})), "两键皆缺 → 直连");
}

/// 「**显式强制**」与「偏好」必须能分开 —— 静默回退只对后者合法。
///
/// 变异锁：把 `proxy_policy_is_forced` 改成 `want_proxy_for_sub`（即 `follow` + per-sub 开
/// 也算强制）→ `follow_with_per_sub_preference_is_not_forced` 断言转红：那会让自举期
/// （核未起）的订阅更新在 follow 档下也一律失败，砸掉 上游的自举友好性。
#[test]
fn only_explicit_global_proxy_policy_counts_as_forced() {
    use super::super::proxy_policy_is_forced;
    assert!(proxy_policy_is_forced(
        &json!({ "subscriptionProxyPolicy": "proxy" })
    ));
    // follow + per-sub 开 = **偏好**，不是强制（静默回退直连仍合法，对齐 上游）。
    assert!(!proxy_policy_is_forced(
        &json!({ "subscriptionProxyPolicy": "follow" })
    ));
    assert!(!proxy_policy_is_forced(&json!({})));
    assert!(!proxy_policy_is_forced(
        &json!({ "subscriptionProxyPolicy": "direct" })
    ));
    // 脏值（sanitize 前）不得被误判成强制。
    assert!(!proxy_policy_is_forced(
        &json!({ "subscriptionProxyPolicy": "PROXY" })
    ));
    assert!(!proxy_policy_is_forced(
        &json!({ "subscriptionProxyPolicy": true })
    ));
}

fn config_with_proxy_route() -> serde_json::Value {
    json!({
        "proxyMode": "smart",
        "selectedServerId": "s1",
        "servers": [{
            "id": "s1",
            "name": "proxy",
            "protocol": "http",
            "address": "proxy.example",
            "port": 443
        }]
    })
}

#[test]
fn backend_effective_route_rejects_every_direct_or_block_leg() {
    let mut cfg = config_with_proxy_route();
    assert!(backend_subscription_route_uses_proxy(&cfg));

    cfg["proxyMode"] = json!("direct");
    assert!(!backend_subscription_route_uses_proxy(&cfg));

    cfg = config_with_proxy_route();
    cfg["selectedServerId"] = json!("__direct__");
    assert!(!backend_subscription_route_uses_proxy(&cfg));

    cfg["selectedServerId"] = json!("__block__");
    assert!(!backend_subscription_route_uses_proxy(&cfg));

    cfg = config_with_proxy_route();
    cfg["servers"] = json!([]);
    cfg["selectedServerId"] = serde_json::Value::Null;
    assert!(!backend_subscription_route_uses_proxy(&cfg));
}

#[test]
fn global_policy_and_backend_route_are_independent_inputs() {
    let mut cfg = config_with_proxy_route();
    let draft = json!({ "updateViaProxy": false });

    cfg["subscriptionProxyPolicy"] = json!("proxy");
    assert!(want_proxy_for_sub(&cfg, &draft));
    assert!(backend_subscription_route_uses_proxy(&cfg));

    cfg["subscriptionProxyPolicy"] = json!("direct");
    assert!(!want_proxy_for_sub(
        &cfg,
        &json!({ "updateViaProxy": true })
    ));

    cfg["subscriptionProxyPolicy"] = json!("follow");
    assert!(want_proxy_for_sub(&cfg, &json!({ "updateViaProxy": true })));

    cfg["subscriptionProxyPolicy"] = json!("proxy");
    cfg["selectedServerId"] = json!("__block__");
    assert!(
        want_proxy_for_sub(&cfg, &draft),
        "policy still requests proxy"
    );
    assert!(
        !backend_subscription_route_uses_proxy(&cfg),
        "but the backend route makes forced policy fail closed"
    );
}
