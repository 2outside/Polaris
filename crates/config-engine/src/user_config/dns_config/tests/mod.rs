use super::*;
use crate::user_config::UserConfig;

/// 【不变式：一条坏上游条目不得炸掉整份 UserConfig】
///
/// 没有 `#[serde(default)]` 时，缺 `id` 或缺 `spec` 会让**整个** `UserConfig` 反序列化失败；
/// 而 `unwrap_or_default()` 的消费腿（unlock / speedtest 等）会把整份配置静默换成默认值 ——
/// 用户少写一个键，节点与规则全部「消失」。
///
/// 变异验证：删掉两个 `#[serde(default)]` 中任意一个 → 对应用例的 `expect` 转红。
#[test]
fn custom_upstream_missing_keys_degrade_to_empty_not_whole_config_failure() {
    // 缺 spec / 缺 id / 全缺 —— 三种手编形态都必须解得出来。
    let cases = [
        (r#"{"id":"x"}"#, "x", ""),
        (
            r#"{"spec":"https://1.1.1.1/dns-query"}"#,
            "",
            "https://1.1.1.1/dns-query",
        ),
        (r#"{}"#, "", ""),
    ];
    for (json, want_id, want_spec) in cases {
        let c: CustomDnsUpstream =
            serde_json::from_str(json).unwrap_or_else(|e| panic!("{json} 应可解: {e}"));
        assert_eq!(c.id, want_id);
        assert_eq!(c.spec, want_spec);
    }

    // 端到端：整份 config.json 里混了一条坏上游 → **其余字段照常生效**（不整份退默认）。
    let raw = r#"{
            "servers": [{"id":"s1","name":"n","protocol":"vless","address":"a.example.com","port":443}],
            "selectedServerId": "s1",
            "dnsConfig": {
                "nodeResolverPool": ["ali", "broken", "good"],
                "nodeResolverCustom": [
                    {"id": "broken"},
                    {"id": "good", "spec": "https://9.9.9.9/dns-query"}
                ]
            }
        }"#;
    let cfg: UserConfig = serde_json::from_str(raw).expect("坏条目不得让整份配置解析失败");
    assert_eq!(
        cfg.selected_server_id.as_deref(),
        Some("s1"),
        "其余配置须完好"
    );
    assert_eq!(cfg.servers.len(), 1);
    let custom = cfg
        .dns_config
        .as_ref()
        .and_then(|d| d.node_resolver_custom.as_ref())
        .expect("自定义上游列表须在");
    assert_eq!(custom.len(), 2);
    assert_eq!(
        custom[0],
        CustomDnsUpstream {
            id: "broken".into(),
            spec: String::new()
        },
        "缺键退化为空串，交由消费侧的 parse_custom_upstream 拒绝腿兜（空 spec → None）"
    );
    assert_eq!(custom[1].spec, "https://9.9.9.9/dns-query");
}
