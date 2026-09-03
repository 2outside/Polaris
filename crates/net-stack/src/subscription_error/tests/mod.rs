use super::*;

fn sig(message: &str) -> SubscriptionErrorSignal {
    SubscriptionErrorSignal {
        message: Some(message.to_string()),
        ..Default::default()
    }
}

fn kind_of(message: &str) -> SubscriptionErrorKind {
    classify_subscription_error(&sig(message)).kind
}

#[test]
fn http_status_wins_over_everything() {
    // 状态码优先级最高：即便 message 像 DNS 错误也归 http。
    let c = classify_subscription_error(&SubscriptionErrorSignal {
        message: Some("getaddrinfo ENOTFOUND".to_string()),
        code: Some("ENOTFOUND".to_string()),
        http_status: Some(403),
    });
    assert_eq!(c.kind, SubscriptionErrorKind::Http);
    assert_eq!(c.http_status, Some(403));
}

#[test]
fn http_status_below_400_is_not_http() {
    // 3xx/2xx 不是 http 错误 —— 不得吞掉真实原因。
    let c = classify_subscription_error(&SubscriptionErrorSignal {
        message: Some("connection refused".to_string()),
        code: Some("ECONNREFUSED".to_string()),
        http_status: Some(302),
    });
    assert_eq!(c.kind, SubscriptionErrorKind::Refused);
    assert_eq!(c.http_status, None);
}

#[test]
fn deterministic_messages_classify() {
    assert_eq!(
        kind_of("订阅响应体积 99 字节超过上限 10485760，已拒绝"),
        SubscriptionErrorKind::TooLarge
    );
    assert_eq!(kind_of("导入内容过大"), SubscriptionErrorKind::TooLarge);
    assert_eq!(
        kind_of("订阅地址协议不支持（仅允许 http/https）: ftp://x/y"),
        SubscriptionErrorKind::Scheme
    );
    assert_eq!(
        kind_of("解析得到 0 个可用节点：未识别到任何可用节点"),
        SubscriptionErrorKind::Empty
    );
}

/// 两种体积文案都要认（`体积超过上限` 与 `体积 N 字节超过上限`）。
/// 上游 只认前者 → 自己 content-length 预检抛的后者落 unknown（已在实现处记为有意分歧）。
#[test]
fn both_oversize_message_shapes_classify() {
    assert_eq!(
        kind_of("订阅响应体积超过上限 10485760，已拒绝"),
        SubscriptionErrorKind::TooLarge
    );
    assert_eq!(
        kind_of("订阅响应体积 20971520 字节超过上限 10485760，已拒绝"),
        SubscriptionErrorKind::TooLarge
    );
}

/// 排序陷阱回归：`重定向次数超过上限` 也含「超过上限」，但它是 SSRF 族，
/// **不得**被 toolarge 分支抢走（needle 若收敛成「超过上限」即转红）。
#[test]
fn redirect_limit_is_ssrf_not_toolarge() {
    assert_eq!(
        kind_of("重定向次数超过上限（5），已拒绝"),
        SubscriptionErrorKind::Ssrf
    );
}

#[test]
fn ssrf_messages_classify() {
    // assert_host_allowed 的真实文案（ssrf.rs:248）。
    assert_eq!(
        kind_of("订阅地址指向本机/内网/link-local，已拒绝: localhost"),
        SubscriptionErrorKind::Ssrf
    );
    // safe_redirect 的重定向超限文案。
    assert_eq!(
        kind_of("重定向次数超过上限（5），已拒绝"),
        SubscriptionErrorKind::Ssrf
    );
}

#[test]
fn network_codes_classify() {
    let by_code = |c: &str| {
        classify_subscription_error(&SubscriptionErrorSignal {
            code: Some(c.to_string()),
            ..Default::default()
        })
        .kind
    };
    assert_eq!(by_code("ENOTFOUND"), SubscriptionErrorKind::Dns);
    assert_eq!(by_code("EAI_AGAIN"), SubscriptionErrorKind::Dns);
    assert_eq!(by_code("ETIMEDOUT"), SubscriptionErrorKind::Timeout);
    assert_eq!(by_code("ABORT_ERR"), SubscriptionErrorKind::Timeout);
    assert_eq!(by_code("ECONNREFUSED"), SubscriptionErrorKind::Refused);
    assert_eq!(by_code("EHOSTUNREACH"), SubscriptionErrorKind::Refused);
    // 小写 code 也认（实现侧可能传 errno 名的小写形态）。
    assert_eq!(by_code("econnrefused"), SubscriptionErrorKind::Refused);
}

#[test]
fn message_keyword_fallback_classifies() {
    assert_eq!(
        kind_of("net::ERR_NAME_NOT_RESOLVED"),
        SubscriptionErrorKind::Dns
    );
    assert_eq!(
        kind_of("operation timed out"),
        SubscriptionErrorKind::Timeout
    );
    assert_eq!(
        kind_of("tcp connect error: Connection refused (os error 111)"),
        SubscriptionErrorKind::Refused
    );
    assert_eq!(
        kind_of("network is unreachable"),
        SubscriptionErrorKind::Refused
    );
}

#[test]
fn parse_messages_classify() {
    assert_eq!(
        kind_of("订阅 YAML 解析失败: mapping values are not allowed"),
        SubscriptionErrorKind::Parse
    );
    assert_eq!(
        kind_of("暂不支持的订阅格式: Unknown"),
        SubscriptionErrorKind::Parse
    );
}

#[test]
fn unknown_when_nothing_matches() {
    assert_eq!(
        kind_of("something went sideways"),
        SubscriptionErrorKind::Unknown
    );
    assert_eq!(
        classify_subscription_error(&SubscriptionErrorSignal::default()).kind,
        SubscriptionErrorKind::Unknown
    );
}

#[test]
fn i18n_keys_cover_all_kinds() {
    // 每类逐一有 key，且 title/detail 不重复（防复制粘贴串行）。
    use SubscriptionErrorKind as K;
    let all = [
        K::Dns,
        K::Timeout,
        K::Refused,
        K::Http,
        K::Ssrf,
        K::Scheme,
        K::TooLarge,
        K::Parse,
        K::ParseBusy,
        K::ParseLimit,
        K::InvalidEncoding,
        K::OperationTimeout,
        K::Empty,
        K::Unknown,
    ];
    let mut seen = std::collections::HashSet::new();
    for k in all {
        let key = subscription_error_i18n_key(k);
        assert!(key.title.starts_with("sub.preview."));
        assert!(key.detail.starts_with("sub.preview."));
        assert!(seen.insert(key.title), "title 重复: {}", key.title);
        assert!(seen.insert(key.detail), "detail 重复: {}", key.detail);
    }
}

#[test]
fn serde_matches_ts_literals() {
    // 序列化字面量须与 TS SubscriptionErrorKind 联合类型逐字一致（IPC 契约）。
    let json = |k: SubscriptionErrorKind| serde_json::to_string(&k).unwrap();
    assert_eq!(json(SubscriptionErrorKind::Dns), "\"dns\"");
    assert_eq!(json(SubscriptionErrorKind::TooLarge), "\"toolarge\"");
    assert_eq!(json(SubscriptionErrorKind::Ssrf), "\"ssrf\"");
    assert_eq!(json(SubscriptionErrorKind::ParseBusy), "\"parse_busy\"");
    assert_eq!(json(SubscriptionErrorKind::ParseLimit), "\"parse_limit\"");
    assert_eq!(
        json(SubscriptionErrorKind::InvalidEncoding),
        "\"invalid_encoding\""
    );
    assert_eq!(
        json(SubscriptionErrorKind::OperationTimeout),
        "\"operation_timeout\""
    );
    assert_eq!(json(SubscriptionErrorKind::Timeout), "\"timeout\"");
    assert_eq!(json(SubscriptionErrorKind::Unknown), "\"unknown\"");
}
