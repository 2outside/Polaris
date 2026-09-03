use super::*;

#[test]
fn token_lowercases_and_trims() {
    assert_eq!(normalize_token("Chrome").as_deref(), Some("chrome"));
    assert_eq!(normalize_token("  FIREFOX  ").as_deref(), Some("firefox"));
    assert_eq!(
        normalize_token("XTLS-RPRX-Vision").as_deref(),
        Some("xtls-rprx-vision")
    );
}

#[test]
fn token_already_canonical_is_identity() {
    assert_eq!(normalize_token("chrome").as_deref(), Some("chrome"));
}

#[test]
fn token_empty_is_none() {
    assert_eq!(normalize_token(""), None);
    assert_eq!(normalize_token("   "), None);
}

#[test]
fn token_non_ascii_preserved() {
    // 非 ASCII 脏值不被 mangle，原样（trim 后）留给下游 FATAL，不静默改写。
    assert_eq!(normalize_token(" 指纹 ").as_deref(), Some("指纹"));
}

#[derive(Debug, serde::Deserialize)]
struct Holder {
    #[serde(default, deserialize_with = "de_opt_token")]
    fp: Option<String>,
}

#[test]
fn de_hook_normalizes() {
    let h: Holder = serde_json::from_str(r#"{"fp":"Chrome"}"#).unwrap();
    assert_eq!(h.fp.as_deref(), Some("chrome"));
}

#[test]
fn de_hook_missing_key_is_none() {
    // 回归：deserialize_with 会吃掉 Option 的隐式缺键行为，必须靠 `default` 兜住。
    let h: Holder = serde_json::from_str(r#"{}"#).unwrap();
    assert_eq!(h.fp, None);
}

#[test]
fn de_hook_null_and_empty_are_none() {
    let h: Holder = serde_json::from_str(r#"{"fp":null}"#).unwrap();
    assert_eq!(h.fp, None);
    let h: Holder = serde_json::from_str(r#"{"fp":"  "}"#).unwrap();
    assert_eq!(h.fp, None);
}

// ── 传输层别名归一（收敛 上游 三份的单一真值）────────────────────────────
// 全表锁死：issue #263 的事故形态就是别名表漏 case → 整船节点被 default 分支丢弃。

#[test]
fn transport_alias_table_is_exhaustive() {
    // 逐条锁死别名 → 规范值。新增传输须在此登记，否则 default 拒绝。
    for (raw, want) in [
        ("ws", "ws"),
        ("httpupgrade", "httpupgrade"),
        ("grpc", "grpc"),
        ("h2", "http"),
        ("http", "http"),
        ("tcp", "tcp"),
        ("raw", "tcp"),
        ("none", "tcp"),
    ] {
        assert_eq!(
            normalize_transport(raw),
            Some(want),
            "{raw:?} 必须归一为 {want:?}"
        );
    }
}

#[test]
fn transport_alias_is_case_and_space_insensitive() {
    // "WS" 未归一时会走到 generate_transport_config 的 `_ => None` 静默丢传输层。
    for raw in ["WS", "Ws", " ws ", "\tWS\n"] {
        assert_eq!(normalize_transport(raw), Some("ws"), "{raw:?}");
    }
    assert_eq!(normalize_transport("HttpUpgrade"), Some("httpupgrade"));
    assert_eq!(normalize_transport("RAW"), Some("tcp"));
    assert_eq!(normalize_transport("H2"), Some("http"));
}

#[test]
fn transport_unknown_is_none_not_silently_tcp() {
    // 关键不变式：未知传输**不得**静默落 tcp（那正是 上游 xray-import 的做法 → 假节点）。
    // 返回 None 让调用方整节点拒绝。
    for raw in ["xhttp", "splithttp", "kcp", "quic", "mkcp", "bogus"] {
        assert_eq!(normalize_transport(raw), None, "{raw:?} 必须判未知");
    }
}

#[test]
fn transport_empty_is_none() {
    // 空/纯空白 → None（未设置，调用方按缺省 tcp 处理，不进拒绝分支）。
    assert_eq!(normalize_transport(""), None);
    assert_eq!(normalize_transport("   "), None);
}
