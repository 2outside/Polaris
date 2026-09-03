use super::super::*;
use polaris_system_integration::proxy_ops::SystemProxyLiveStatus;
use polaris_system_integration::SystemProxyStatus;

/// 应答映射不得把 `enabled` 与 `pointsToUs` 混为一谈 —— 「OS 层开着代理」与「代理指向我们」
/// 是两件事，混掉就退回本命令要修的那条漏报（绿灯 + 流量走第三方代理）。
#[test]
fn response_keeps_enabled_and_points_to_us_distinct() {
    let live = SystemProxyLiveStatus {
        status: SystemProxyStatus {
            enabled: true,
            http_proxy: Some("proxy.corp:3128".into()),
            https_proxy: Some("proxy.corp:3128".into()),
            socks_proxy: None,
            bypass_domains: None,
        },
        points_to_us: false,
        expected: "127.0.0.1:7890".into(),
    };
    let r = SystemProxyLiveResponse::from(live);
    assert!(r.enabled, "OS 层确实开着代理");
    assert!(!r.points_to_us, "但它指向第三方 → 我们的流量没经本地核");
    assert_eq!(r.expected, "127.0.0.1:7890");
    assert_eq!(r.https_proxy.as_deref(), Some("proxy.corp:3128"));
}

/// 序列化必须是 camelCase（前端 `SystemProxyStatus` 契约字段名），且 `pointsToUs` 恒下发
/// （非 `skip_serializing_if` —— 缺字段会让前端 `s.pointsToUs` 恒 undefined ⇒ 恒判「未生效」）。
#[test]
fn response_serializes_camel_case_with_verdict_always_present() {
    let r = SystemProxyLiveResponse::from(SystemProxyLiveStatus {
        status: SystemProxyStatus {
            enabled: true,
            http_proxy: Some("127.0.0.1:7890".into()),
            https_proxy: Some("127.0.0.1:7890".into()),
            socks_proxy: None,
            bypass_domains: None,
        },
        points_to_us: true,
        expected: "127.0.0.1:7890".into(),
    });
    let v = serde_json::to_value(&r).unwrap();
    assert_eq!(v["pointsToUs"], true);
    assert_eq!(v["httpProxy"], "127.0.0.1:7890");
    assert_eq!(v["expected"], "127.0.0.1:7890");
    assert!(
        v.get("socksProxy").is_none(),
        "未设的腿省略（对齐 TS 可选字段）"
    );
    // 蛇形名不得出现（前端按 camelCase 读）。
    assert!(v.get("http_proxy").is_none());
    assert!(v.get("points_to_us").is_none());
}
