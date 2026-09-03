use super::*;

fn b64(bytes: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        s.push(T[((n >> 18) & 0x3F) as usize] as char);
        s.push(T[((n >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            s.push(T[((n >> 6) & 0x3F) as usize] as char);
        } else {
            s.push('=');
        }
        if chunk.len() > 2 {
            s.push(T[(n & 0x3F) as usize] as char);
        } else {
            s.push('=');
        }
    }
    s
}

#[test]
fn reserved_from_client_id_decodes_first_three_bytes() {
    assert_eq!(
        reserved_from_client_id(Some(&b64(&[1, 2, 3]))),
        Some(vec![1, 2, 3])
    );
    // 多于 3 字节取前 3。
    assert_eq!(
        reserved_from_client_id(Some(&b64(&[10, 20, 30, 40]))),
        Some(vec![10, 20, 30])
    );
}

#[test]
fn reserved_from_client_id_empty_or_short_is_none() {
    assert_eq!(reserved_from_client_id(None), None);
    assert_eq!(reserved_from_client_id(Some("")), None);
    assert_eq!(reserved_from_client_id(Some(&b64(&[1, 2]))), None);
}

#[test]
fn split_endpoint_variants() {
    let (h, p) = split_endpoint(Some("engage.cloudflareclient.com:2408"));
    assert_eq!(h, "engage.cloudflareclient.com");
    assert_eq!(p, 2408);

    let (h, p) = split_endpoint(Some("[2606:4700:d0::a29f:c001]:2408"));
    assert_eq!(h, "2606:4700:d0::a29f:c001");
    assert_eq!(p, 2408);

    let (h, p) = split_endpoint(Some("engage.cloudflareclient.com"));
    assert_eq!(h, "engage.cloudflareclient.com");
    assert_eq!(p, WARP_DEFAULT_ENDPOINT_PORT);

    let (h, p) = split_endpoint(None);
    assert_eq!(h, WARP_DEFAULT_ENDPOINT_HOST);
    assert_eq!(p, WARP_DEFAULT_ENDPOINT_PORT);
}

#[test]
fn build_register_body_has_key_tos_and_fixed_fields() {
    let b = build_register_body("PUBKEYB64", "2026-06-16T00:00:00.000Z");
    assert_eq!(b["key"], "PUBKEYB64");
    assert_eq!(b["tos"], "2026-06-16T00:00:00.000Z");
    assert_eq!(b["install_id"], "");
    assert_eq!(b["type"], "Android");
}

#[test]
fn parse_register_response_full() {
    let ok = json!({
        "id": "devid",
        "token": "secret-token",
        "account": { "id": "acctid", "license": "lic", "warp_plus": true },
        "config": {
            "client_id": b64(&[5, 6, 7]),
            "interface": { "addresses": { "v4": "172.16.0.2", "v6": "2606:4700:110::1" } },
            "peers": [{ "public_key": "PEERPUB", "endpoint": { "host": "engage.cloudflareclient.com:2408" } }],
        }
    });
    let r = parse_register_response(&ok).unwrap();
    assert_eq!(r.address, "engage.cloudflareclient.com");
    assert_eq!(r.port, 2408);
    assert_eq!(r.peer_public_key, "PEERPUB");
    assert_eq!(
        r.local_address,
        vec!["172.16.0.2/32", "2606:4700:110::1/128"]
    );
    assert_eq!(r.reserved, Some(vec![5, 6, 7]));
    assert_eq!(r.device_id, "devid");
    assert_eq!(r.account_id, "acctid");
    assert!(r.warp_plus);
}

#[test]
fn parse_register_response_v4_only() {
    let ok = json!({
        "config": {
            "interface": { "addresses": { "v4": "172.16.0.2" } },
            "peers": [{ "public_key": "PEERPUB", "endpoint": { "host": "engage.cloudflareclient.com:2408" } }],
        }
    });
    let r = parse_register_response(&ok).unwrap();
    assert_eq!(r.local_address, vec!["172.16.0.2/32"]);
}

#[test]
fn parse_register_response_missing_fields_errors() {
    assert!(parse_register_response(&json!({ "config": { "peers": [] } })).is_err());
    assert!(parse_register_response(&json!({
        "config": { "peers": [{ "endpoint": { "host": "h:1" } }] }
    }))
    .is_err());
    assert!(parse_register_response(&json!({
        "config": {
            "peers": [{ "public_key": "P", "endpoint": { "host": "h:1" } }],
            "interface": {}
        }
    }))
    .is_err());
}

#[test]
fn build_unregister_request_shape() {
    let (url, headers) = build_unregister_request("v0a2158", "dev-123", "tok-abc");
    assert_eq!(url, format!("{}/v0a2158/reg/dev-123", WARP_API_BASE));
    assert_eq!(headers["Authorization"], "Bearer tok-abc");
    assert_eq!(headers["User-Agent"], WARP_USER_AGENT);
    assert_eq!(headers["CF-Client-Version"], WARP_CLIENT_VERSION);
}

#[test]
fn build_unregister_request_version_segment_param() {
    let (url, _) = build_unregister_request("v9x9", "d", "t");
    assert_eq!(url, format!("{}/v9x9/reg/d", WARP_API_BASE));
}

#[test]
fn classify_deregister_result_matrix() {
    assert_eq!(
        classify_deregister_result(Some(204), None),
        DeregisterResult::Done
    );
    assert_eq!(
        classify_deregister_result(Some(404), None),
        DeregisterResult::Done
    );
    assert_eq!(
        classify_deregister_result(Some(401), None),
        DeregisterResult::Drop
    );
    assert_eq!(
        classify_deregister_result(Some(403), None),
        DeregisterResult::Drop
    );
    assert_eq!(
        classify_deregister_result(None, None),
        DeregisterResult::Retry
    );
    assert_eq!(
        classify_deregister_result(None, Some("ETIMEDOUT")),
        DeregisterResult::Retry
    );
    assert_eq!(
        classify_deregister_result(Some(500), None),
        DeregisterResult::Retry
    );
    assert_eq!(
        classify_deregister_result(Some(502), None),
        DeregisterResult::Retry
    );
    assert_eq!(
        classify_deregister_result(Some(503), None),
        DeregisterResult::Retry
    );
    assert_eq!(
        classify_deregister_result(Some(400), None),
        DeregisterResult::Retry
    );
}

#[test]
fn classify_deregister_result_1020_overrides_403() {
    // 403 携 body code 1020 → Retry（WAF/版本失效，优先于 403 的 Drop）。
    assert_eq!(
        classify_deregister_result(Some(403), Some("WARP API 403: error 1020")),
        DeregisterResult::Retry
    );
    // err 文本里带 1020，即便状态码非典型也 Retry。
    assert_eq!(
        classify_deregister_result(Some(429), Some("code 1020")),
        DeregisterResult::Retry
    );
}

#[test]
fn classify_deregister_result_unknown_4xx_drops() {
    assert_eq!(
        classify_deregister_result(Some(429), None),
        DeregisterResult::Drop
    );
    assert_eq!(
        classify_deregister_result(Some(410), None),
        DeregisterResult::Drop
    );
}

fn mk_entry(id: &str, at: u64) -> PendingDeregisterEntry {
    PendingDeregisterEntry {
        device_id: id.to_string(),
        token: format!("t-{}", id),
        enqueued_at: at,
    }
}

#[test]
fn enqueue_appends_when_under_limit() {
    let (queue, dropped) =
        enqueue_pending_deregister(&[mk_entry("a", 0), mk_entry("b", 0)], mk_entry("c", 0));
    let ids: Vec<_> = queue.iter().map(|e| e.device_id.as_str()).collect();
    assert_eq!(ids, vec!["a", "b", "c"]);
    assert!(dropped.is_empty());
}

#[test]
fn enqueue_drops_oldest_when_over_limit() {
    let full: Vec<PendingDeregisterEntry> = (0..WARP_DEREGISTER_MAX_QUEUE)
        .map(|i| mk_entry(&format!("d{}", i), 0))
        .collect();
    let (queue, dropped) = enqueue_pending_deregister(&full, mk_entry("new", 0));
    assert_eq!(queue.len(), WARP_DEREGISTER_MAX_QUEUE);
    assert_eq!(dropped.len(), 1);
    assert_eq!(dropped[0].device_id, "d0"); // 最旧被挤掉
    assert_eq!(queue.last().unwrap().device_id, "new"); // 新条目在队尾
    assert_eq!(queue.first().unwrap().device_id, "d1");
}

const NOW: u64 = 10_000_000_000;

#[test]
fn plan_drain_splits_by_age_and_truncates() {
    let queue = vec![
        PendingDeregisterEntry {
            device_id: "old".into(),
            token: "t-old".into(),
            enqueued_at: NOW - (WARP_DEREGISTER_MAX_AGE_MS + 1),
        },
        PendingDeregisterEntry {
            device_id: "fresh".into(),
            token: "t-fresh".into(),
            enqueued_at: NOW - (WARP_DEREGISTER_MAX_AGE_MS - 1),
        },
    ];
    let (plan, deferred) = plan_deregister_drain(&queue, NOW);
    let old = plan.iter().find(|p| p.entry.device_id == "old").unwrap();
    assert_eq!(old.action, DrainAction::Expire);
    let fresh = plan.iter().find(|p| p.entry.device_id == "fresh").unwrap();
    assert_eq!(fresh.action, DrainAction::Eligible);
    assert!(deferred.is_empty());
}

#[test]
fn plan_drain_boundary_age_is_eligible() {
    // 恰好 7 天（==）不算超龄（> 才超）→ eligible。
    let queue = vec![PendingDeregisterEntry {
        device_id: "edge".into(),
        token: "t".into(),
        enqueued_at: NOW - WARP_DEREGISTER_MAX_AGE_MS,
    }];
    let (plan, _) = plan_deregister_drain(&queue, NOW);
    assert_eq!(plan[0].action, DrainAction::Eligible);
}

#[test]
fn plan_drain_eligible_capped_and_deferred() {
    let queue: Vec<PendingDeregisterEntry> = (0..(WARP_DEREGISTER_MAX_PER_DRAIN + 3))
        .map(|i| PendingDeregisterEntry {
            device_id: format!("e{}", i),
            token: format!("t{}", i),
            enqueued_at: NOW - 1000,
        })
        .collect();
    let (plan, deferred) = plan_deregister_drain(&queue, NOW);
    let eligible = plan
        .iter()
        .filter(|p| p.action == DrainAction::Eligible)
        .count();
    assert_eq!(eligible, WARP_DEREGISTER_MAX_PER_DRAIN);
    assert_eq!(deferred.len(), 3);
}

#[test]
fn plan_drain_expire_does_not_consume_budget() {
    let expired: Vec<PendingDeregisterEntry> = (0..5)
        .map(|i| PendingDeregisterEntry {
            device_id: format!("x{}", i),
            token: format!("tx{}", i),
            enqueued_at: NOW - (WARP_DEREGISTER_MAX_AGE_MS + 1000),
        })
        .collect();
    let fresh: Vec<PendingDeregisterEntry> = (0..WARP_DEREGISTER_MAX_PER_DRAIN)
        .map(|i| PendingDeregisterEntry {
            device_id: format!("f{}", i),
            token: format!("tf{}", i),
            enqueued_at: NOW - 1000,
        })
        .collect();
    let mut all = expired;
    all.extend(fresh);
    let (plan, deferred) = plan_deregister_drain(&all, NOW);
    assert_eq!(
        plan.iter()
            .filter(|p| p.action == DrainAction::Expire)
            .count(),
        5
    );
    assert_eq!(
        plan.iter()
            .filter(|p| p.action == DrainAction::Eligible)
            .count(),
        WARP_DEREGISTER_MAX_PER_DRAIN
    );
    assert!(deferred.is_empty());
}
