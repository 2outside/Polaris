use super::super::*;
use polaris_config_engine::user_config::server_config::ServerConfig;

#[test]
fn primary_fetch_retries_only_transient_transport_once() {
    use SubscriptionErrorKind as K;

    for kind in [K::Dns, K::Refused, K::Unknown] {
        assert_eq!(
            primary_fetch_retry_delay(kind, 0),
            Some(PRIMARY_FETCH_RETRY_DELAY),
            "{kind:?} 的首个失败应有一次短重试"
        );
        assert_eq!(
            primary_fetch_retry_delay(kind, 1),
            None,
            "{kind:?} 不得形成无界重试"
        );
    }

    for kind in [
        K::Timeout,
        K::Http,
        K::Ssrf,
        K::Scheme,
        K::TooLarge,
        K::Parse,
        K::Empty,
    ] {
        assert_eq!(
            primary_fetch_retry_delay(kind, 0),
            None,
            "{kind:?} 是长耗时或确定性错误，不应重试"
        );
    }
}

/// 造一个订阅节点（sub1 归属，固定 uuid = 指纹 cred）。
fn srv(name: &str, addr: &str, port: u16) -> ServerConfig {
    srv_uuid(name, addr, port, "11111111-1111-1111-1111-111111111111")
}

/// 造一个订阅节点（自定 uuid = 指纹 cred；同 uuid 同 host:port → 同指纹碰撞）。
fn srv_uuid(name: &str, addr: &str, port: u16, uuid: &str) -> ServerConfig {
    serde_json::from_value(json!({
        "id": format!("gen-{name}"),
        "name": name,
        "protocol": "vless",
        "address": addr,
        "port": port,
        "subscriptionId": "sub1",
        "uuid": uuid,
    }))
    .expect("ServerConfig 应可反序列化")
}

#[test]
fn reconcile_adds_updates_deletes_and_preserves_id() {
    let mut cfg = json!({
        "selectedServerId": "id-A",
        "servers": [
            // A 同指纹（同 uuid），但 name 不同（"OLD-A" vs 新 "A"）→ 内容变 → updated，保留 id-A。
            {"id":"id-A","name":"OLD-A","protocol":"vless","address":"a.com","port":443,"subscriptionId":"sub1","uuid":"11111111-1111-1111-1111-111111111111"},
            {"id":"id-B","name":"B","protocol":"vless","address":"b.com","port":443,"subscriptionId":"sub1","uuid":"u-b"},
            {"id":"id-X","name":"X","protocol":"vless","address":"x.com","port":443,"subscriptionId":"other"}
        ]
    });
    // A 指纹命中（name 变 → updated，保留 id-A）；C 新增；B 消失 → 删除；X（他订阅）不动。
    let new = vec![srv("A", "a.com", 443), srv("C", "c.com", 443)];
    let out = reconcile_subscription_servers(&mut cfg, "sub1", new, false, &[]);
    assert_eq!(out.added, 1, "C 新增");
    assert_eq!(out.updated, 1, "A 内容变（name）→ updated");
    assert_eq!(out.deleted, 1, "B 消失 → 删除");
    let servers = cfg["servers"].as_array().unwrap();
    assert!(
        servers.iter().any(|s| s["id"] == "id-X"),
        "他订阅节点不得被动"
    );
    let a = servers.iter().find(|s| s["name"] == "A").unwrap();
    assert_eq!(a["id"], "id-A", "命中须保留稳定 id（选中不失效）");
    assert!(!servers.iter().any(|s| s["name"] == "B"), "B 应删除");
    assert_eq!(cfg["selectedServerId"], "id-A", "选中仍在 → 不动");
}

#[test]
fn reconcile_reselects_viable_fallback_when_selected_removed() {
    // 选中 id-B 被删；幸存的 C 是可承载全隧道的 vless → reselect 到 C（绝不裸 null / direct）。
    let mut cfg = json!({
        "selectedServerId": "id-B",
        "servers": [
            {"id":"id-B","name":"B","protocol":"vless","address":"b.com","port":443,"subscriptionId":"sub1","uuid":"u-b"}
        ]
    });
    let out =
        reconcile_subscription_servers(&mut cfg, "sub1", vec![srv("C", "c.com", 443)], false, &[]);
    assert_eq!(out.deleted, 1);
    assert_eq!(out.added, 1);
    // 幸存 vless 可作兜底 → 选它逃死节点（非 null、非 direct）。
    assert_eq!(
        cfg["selectedServerId"],
        json!("gen-C"),
        "悬挂选中 → 幸存可用节点"
    );
}

#[test]
fn reconcile_no_change_when_identical() {
    let mut cfg = json!({
        "servers": [
            {"id":"id-A","name":"A","protocol":"vless","address":"a.com","port":443,"subscriptionId":"sub1","uuid":"11111111-1111-1111-1111-111111111111"}
        ]
    });
    let out =
        reconcile_subscription_servers(&mut cfg, "sub1", vec![srv("A", "a.com", 443)], false, &[]);
    assert_eq!(
        (out.added, out.updated, out.deleted),
        (0, 0, 0),
        "内容一致 → unchanged（不误报 updated）"
    );
}

#[test]
fn reconcile_fingerprint_collision_keeps_both_with_distinct_ids() {
    // 两个**同指纹**（同 uuid 同 host:port，仅 name 异）现有订阅节点——真碰撞：FIFO 1:1 消费不丢 id。
    let mut cfg = json!({
        "servers": [
            {"id":"id-1","name":"HK-1","protocol":"vless","address":"cdn.com","port":443,"subscriptionId":"sub1","uuid":"11111111-1111-1111-1111-111111111111"},
            {"id":"id-2","name":"HK-2","protocol":"vless","address":"cdn.com","port":443,"subscriptionId":"sub1","uuid":"11111111-1111-1111-1111-111111111111"}
        ]
    });
    // 新集：两个同指纹节点（同 uuid 同 host:port）。
    let new = vec![
        srv_uuid(
            "HK-a",
            "cdn.com",
            443,
            "11111111-1111-1111-1111-111111111111",
        ),
        srv_uuid(
            "HK-b",
            "cdn.com",
            443,
            "11111111-1111-1111-1111-111111111111",
        ),
    ];
    let out = reconcile_subscription_servers(&mut cfg, "sub1", new, false, &[]);
    let servers = cfg["servers"].as_array().unwrap();
    assert_eq!(servers.len(), 2, "两个同指纹节点都保留（不因碰撞丢一个）");
    let ids: std::collections::HashSet<&str> =
        servers.iter().filter_map(|s| s["id"].as_str()).collect();
    assert_eq!(ids.len(), 2, "两个 id 各异（无重复 id）");
    assert!(
        ids.contains("id-1") && ids.contains("id-2"),
        "1:1 消费旧 id，不复用同一个"
    );
    assert_eq!((out.added, out.deleted), (0, 0), "两个都 1:1 命中，无增删");
}

#[test]
fn reconcile_collision_shrink_deletes_extra_and_reselects_dangling() {
    // 选中 id-2；新集只剩一个同指纹节点 → 一个旧节点被删（FIFO 先消费 id-1，id-2 剩余 → 删）。
    // 悬挂 id-2 按实际结果 id 集判 → reselect 到幸存 id-1（可用 vless）。
    let mut cfg = json!({
        "selectedServerId": "id-2",
        "servers": [
            {"id":"id-1","name":"HK-1","protocol":"vless","address":"cdn.com","port":443,"subscriptionId":"sub1","uuid":"11111111-1111-1111-1111-111111111111"},
            {"id":"id-2","name":"HK-2","protocol":"vless","address":"cdn.com","port":443,"subscriptionId":"sub1","uuid":"11111111-1111-1111-1111-111111111111"}
        ]
    });
    let new = vec![srv_uuid(
        "HK-x",
        "cdn.com",
        443,
        "11111111-1111-1111-1111-111111111111",
    )];
    let out = reconcile_subscription_servers(&mut cfg, "sub1", new, false, &[]);
    assert_eq!(out.deleted, 1, "一个同指纹节点被删");
    let servers = cfg["servers"].as_array().unwrap();
    assert_eq!(servers.len(), 1);
    assert!(
        !servers.iter().any(|s| s["id"] == "id-2"),
        "队尾未配对的 id-2 被删"
    );
    assert_eq!(
        cfg["selectedServerId"],
        json!("id-1"),
        "悬挂选中 → 幸存可用节点（非 null）"
    );
}

#[test]
fn reconcile_keeps_direct_sentinel_selection() {
    // 直连哨兵 __direct__ 不是节点 id，实际结果 id 集里恒不存在，但绝不能被误改。
    let mut cfg = json!({
        "selectedServerId": "__direct__",
        "servers": [
            {"id":"id-A","name":"A","protocol":"vless","address":"a.com","port":443,"subscriptionId":"sub1","uuid":"11111111-1111-1111-1111-111111111111"}
        ]
    });
    // 空集：删光本订阅节点（reconcile 是纯函数，生产侧另有 0 节点 merge-only 前置守卫）。
    reconcile_subscription_servers(&mut cfg, "sub1", vec![], false, &[]);
    assert_eq!(
        cfg["selectedServerId"],
        json!("__direct__"),
        "直连哨兵不得被改"
    );
}

#[test]
fn reconcile_merge_only_keeps_all_when_failed_provider_names_unknown() {
    // partial 但**失败 provider 名未知**（`failed_providers` 空）→ 退回整订阅级 merge-only：
    // 不删任何本订阅节点（防穿仓）。打断该兜底（→ 走删除分支）→ B 被删、deleted=1 → 断言转红。
    let mut cfg = json!({
        "selectedServerId": "id-B",
        "servers": [
            {"id":"id-A","name":"OLD-A","protocol":"vless","address":"a.com","port":443,"subscriptionId":"sub1","uuid":"11111111-1111-1111-1111-111111111111"},
            {"id":"id-B","name":"B","protocol":"vless","address":"b.com","port":443,"subscriptionId":"sub1","uuid":"u-b"}
        ]
    });
    // 新集只含 A（name 变 → updated）；B 缺席，但 merge_only → 保留 B、deleted=0。
    let out =
        reconcile_subscription_servers(&mut cfg, "sub1", vec![srv("A", "a.com", 443)], true, &[]);
    assert_eq!(out.deleted, 0, "merge_only → 不删任何存量（含缺席的 B）");
    assert_eq!(out.updated, 1, "A 仍正常更新");
    let servers = cfg["servers"].as_array().unwrap();
    assert!(
        servers.iter().any(|s| s["id"] == "id-B"),
        "B 保留（provider 临时失败不误删）"
    );
    assert_eq!(
        cfg["selectedServerId"],
        json!("id-B"),
        "选中 B 存活 → 不悬挂"
    );
}

/// M1 · **provider 级精确 merge-back**（本批修复的核心，上游 `leftoverToKeep`）。
///
/// 场景：订阅有两个 provider，`P_fail` 拉取 503（transient）、`P_ok` 成功。两者名下各有一个节点
/// 在本次不再出现（= 「下架」）。正确处置**必须区分**：
/// - `P_fail` 名下的下架**不可信**（503 时我们根本没看到它的清单）→ 保留；
/// - `P_ok` 名下的下架是**真下架** → 删除，且计入 `deleted`。
///
/// 变异验证：把 `leftover_survives_partial` 的规则 3 去掉（改成恒 true = 旧的整订阅 merge-only）
/// → `id-ok` 滞留、`deleted` 变 0 → 两条断言同时转红。
#[test]
fn reconcile_partial_deletes_only_from_succeeded_providers() {
    let mut cfg = json!({
        "servers": [
            // 失败 provider 名下的下架节点 —— 必须保留。
            {"id":"id-fail","name":"F","protocol":"vless","address":"f.com","port":443,
             "subscriptionId":"sub1","uuid":"u-f","providerName":"P_fail"},
            // 成功 provider 名下的下架节点 —— 必须删除。
            {"id":"id-ok","name":"O","protocol":"vless","address":"o.com","port":443,
             "subscriptionId":"sub1","uuid":"u-o","providerName":"P_ok"},
            // 主正文内联节点（无 providerName）—— 无归属信息 → 保守保留。
            {"id":"id-inline","name":"I","protocol":"vless","address":"i.com","port":443,
             "subscriptionId":"sub1","uuid":"u-i"}
        ]
    });
    // 本次拉到的新集只含一个无关新节点 → 上面三个全落 leftover。
    let out = reconcile_subscription_servers(
        &mut cfg,
        "sub1",
        vec![srv("NEW", "n.com", 443)],
        true,
        &["P_fail".to_string()],
    );

    let servers = cfg["servers"].as_array().unwrap();
    let ids: std::collections::HashSet<&str> =
        servers.iter().filter_map(|s| s["id"].as_str()).collect();
    assert!(
        ids.contains("id-fail"),
        "失败 provider 名下的下架节点必须保留（503 时清单不可信）"
    );
    assert!(
        ids.contains("id-inline"),
        "无 providerName 的存量（内联/迁移前）无归属信息 → 保守保留"
    );
    assert!(
        !ids.contains("id-ok"),
        "成功 provider 名下的真下架节点必须删除（此前整订阅 merge-only 会让它无限滞留）"
    );
    assert_eq!(
        out.deleted, 1,
        "deleted 只计**实际**删掉的（此前 partial 恒 0 = 谎报无变化）"
    );
    assert_eq!(out.added, 1, "新节点正常入库");
}

/// M1 守卫：partial 下**选中节点**若落在成功 provider 名下且被真删 → 仍走 F14 reselect 兜底
/// （不得留悬空引用）。此前 partial 恒保留一切，选中永不悬挂，故这条路径此前不可达。
#[test]
fn reconcile_partial_reselects_when_selected_deleted_by_succeeded_provider() {
    let mut cfg = json!({
        "selectedServerId": "id-ok",
        "servers": [
            {"id":"id-ok","name":"O","protocol":"vless","address":"o.com","port":443,
             "subscriptionId":"sub1","uuid":"u-o","providerName":"P_ok"}
        ]
    });
    reconcile_subscription_servers(
        &mut cfg,
        "sub1",
        vec![srv("NEW", "n.com", 443)],
        true,
        &["P_fail".to_string()],
    );
    assert_eq!(
        cfg["selectedServerId"],
        json!("gen-NEW"),
        "选中被真删 → reselect 到幸存可用节点（绝不留悬空 id）"
    );
}

/// `leftover_survives_partial` 真值表（三条规则各一格 + 变异面）。
#[test]
fn leftover_keep_rules_truth_table() {
    let with_provider = json!({ "providerName": "P_fail" });
    let other_provider = json!({ "providerName": "P_ok" });
    let no_provider = json!({ "name": "inline" });
    let empty_provider = json!({ "providerName": "" });

    // 规则 1：失败名未知 → 全保留（退回整订阅 merge-only）。
    assert!(leftover_survives_partial(&with_provider, &[]));
    assert!(leftover_survives_partial(&other_provider, &[]));
    assert!(leftover_survives_partial(&no_provider, &[]));

    let failed = ["P_fail".to_string()];
    // 规则 2：无归属（缺键 / 空串）→ 保守保留。
    assert!(leftover_survives_partial(&no_provider, &failed));
    assert!(leftover_survives_partial(&empty_provider, &failed));
    // 规则 3：只保留失败 provider 名下的。
    assert!(leftover_survives_partial(&with_provider, &failed));
    assert!(
        !leftover_survives_partial(&other_provider, &failed),
        "成功 provider 名下的下架是真下架，不得保留"
    );
}

/// C-UA · 全局 `subscriptionUserAgent` 三级优先级（此前后端只读 per-sub，全局键是死键）。
///
/// 变异验证：把 `resolve_subscription_ua` 的 `.or_else(全局)` 去掉 → 第二条断言转红；
/// 把 per-sub 与全局取值顺序对调 → 第一条转红。
#[test]
fn subscription_ua_precedence_per_sub_then_global_then_default() {
    let cfg = json!({ "subscriptionUserAgent": "clash-verge/1.0" });

    // ① per-sub 优先于全局。
    assert_eq!(
        resolve_subscription_ua(&cfg, &json!({ "userAgent": "mihomo/1.18" })).as_deref(),
        Some("mihomo/1.18")
    );
    // ② per-sub 缺省 → 落全局（此前这里恒 None → 全局设置无效 → 机场按 UA 下发错格式）。
    assert_eq!(
        resolve_subscription_ua(&cfg, &json!({})).as_deref(),
        Some("clash-verge/1.0")
    );
    // ③ 两级皆缺 → None（交拉取层落 default_subscription_user_agent）。
    assert_eq!(resolve_subscription_ua(&json!({}), &json!({})), None);
    // ④ 空串/纯空白视同未设（不得把 `User-Agent: ` 空值发出去）。
    assert_eq!(
        resolve_subscription_ua(&cfg, &json!({ "userAgent": "   " })).as_deref(),
        Some("clash-verge/1.0"),
        "per-sub 空白应回落全局，而非发空 UA"
    );
    assert_eq!(
        resolve_subscription_ua(&json!({ "subscriptionUserAgent": "" }), &json!({})),
        None
    );
    // ⑤ 默认 UA 形态（拉取层兜底）——与契约注释 `Polaris/<版本>` 一致。
    assert_eq!(
        default_subscription_user_agent("9.9.9"),
        "Polaris/9.9.9",
        "默认 UA 须中性 Polaris/<ver>"
    );
}

#[test]
fn reconcile_skips_subnet_only_mesh_falls_to_direct() {
    // #291：选中节点被删后，唯一幸存是「subnet-only 组网节点」（WG allowInternet:false，仅承载网段）
    // → 不可作兜底出口（否则公网静默走 direct = 泄漏）→ pick_viable 跳过 → 落 direct 哨兵。
    let mut cfg = json!({
        "selectedServerId": "id-sel",
        "servers": [
            {"id":"id-sel","name":"SEL","protocol":"vless","address":"s.com","port":443,"subscriptionId":"sub1","uuid":"u-sel"},
            {"id":"wg1","name":"WG","protocol":"wireguard","address":"w.com","port":51820,"subscriptionId":"sub1",
             "wireguardSettings":{"allowInternet":false,"allowedIPs":["10.0.0.0/24"],"peerPublicKey":"pk"}}
        ]
    });
    // 新集只含 WG（同指纹 cred=peerPublicKey）；选中 vless 被删 → 幸存仅 subnet-only WG → 不可兜底 → direct。
    let wg: ServerConfig = serde_json::from_value(json!({
        "id":"gen-wg","name":"WG","protocol":"wireguard","address":"w.com","port":51820,"subscriptionId":"sub1",
        "wireguardSettings":{"allowInternet":false,"allowedIPs":["10.0.0.0/24"],"peerPublicKey":"pk"}
    })).unwrap();
    reconcile_subscription_servers(&mut cfg, "sub1", vec![wg], false, &[]);
    assert_eq!(
        cfg["selectedServerId"],
        json!("__direct__"),
        "subnet-only 组网节点不可作兜底 → 显式 direct（非静默泄漏）"
    );
}

#[test]
fn fingerprint_matches_net_stack_typed() {
    // 跨类型等价锁：node_fingerprint(Value) ≡ net-stack server_fingerprint(&ServerConfig)。
    // 打断任一侧公式（改分隔符/字段/大小写）→ 断言转红。
    let sc = srv_uuid("HK", "cdn.com", 443, "u-xyz");
    let v = serde_json::to_value(&sc).unwrap();
    assert_eq!(
        node_fingerprint(&v),
        polaris_net_stack::subscription::server_fingerprint(&sc),
        "json 侧与 typed 侧指纹须一致"
    );
    assert_eq!(
        node_fingerprint(&v),
        "vless|cdn.com|443|u-xyz|tcp",
        "指纹形态"
    );
}

// ── A7 · subscription_delete 腿：选中随订阅删除 → →direct 哨兵 → 出口变（失效牙）─────
// 打断 `apply_subscription_delete` 的置哨兵（不改选中）→ 断言转红；打断 `selected_exit_changed` → 转红。
#[test]
fn subscription_delete_sets_direct_sentinel_and_signals_exit_change() {
    let mut cfg = json!({
        "selectedServerId": "n1",
        "subscriptions": [{ "id": "sub1" }, { "id": "sub2" }],
        "servers": [
            { "id": "n1", "subscriptionId": "sub1" },
            { "id": "n2", "subscriptionId": "sub2" }
        ]
    });
    let old = cfg["selectedServerId"].as_str().map(str::to_string);
    apply_subscription_delete(&mut cfg, "sub1").expect("订阅存在 → Ok");
    let new = cfg.get("selectedServerId").and_then(Value::as_str);
    assert_eq!(
        cfg["selectedServerId"],
        json!("__direct__"),
        "选中节点随订阅删除 → 置 direct 哨兵（绝不裸 null）"
    );
    assert!(
        !cfg["servers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["id"] == "n1"),
        "sub1 下节点删净"
    );
    assert!(
        selected_exit_changed(old.as_deref(), new),
        "→direct 是出口变（必须失效）"
    );
}

/// A7 · subscription_delete 守卫：选中属他订阅（删后仍存活）→ 选中不动 → 出口不变（不失效）。
#[test]
fn subscription_delete_keeps_unrelated_selection() {
    let mut cfg = json!({
        "selectedServerId": "n2",
        "subscriptions": [{ "id": "sub1" }, { "id": "sub2" }],
        "servers": [
            { "id": "n1", "subscriptionId": "sub1" },
            { "id": "n2", "subscriptionId": "sub2" }
        ]
    });
    let old = cfg["selectedServerId"].as_str().map(str::to_string);
    apply_subscription_delete(&mut cfg, "sub1").expect("订阅存在 → Ok");
    let new = cfg.get("selectedServerId").and_then(Value::as_str);
    assert_eq!(new, Some("n2"), "选中属他订阅 → 存活不动");
    assert!(
        !selected_exit_changed(old.as_deref(), new),
        "选中未变 → 出口不变（不失效）"
    );
}

/// A7 · subscription_delete：`subscriptions` 在但无此 id → Err（命令层报「订阅不存在」）。
#[test]
fn subscription_delete_errs_on_missing_id() {
    let mut cfg = json!({ "subscriptions": [{ "id": "sub1" }], "servers": [] });
    assert!(
        apply_subscription_delete(&mut cfg, "nope").is_err(),
        "id 不存在 → Err"
    );
}

// ── A7 · subscription_update_servers（订阅刷新）腿：对账删选中 → reselect 兜底 → 出口变 ──
// 打断 reconcile 的兜底 reselect → 断言转红；打断 `selected_exit_changed` → 转红。
#[test]
fn subscription_refresh_reselects_selected_signals_exit_change() {
    // 选中 id-B 被对账删除（新集只有 C）→ reselect 到幸存可用 C（→出口变）。
    let mut cfg = json!({
        "selectedServerId": "id-B",
        "servers": [
            {"id":"id-B","name":"B","protocol":"vless","address":"b.com","port":443,"subscriptionId":"sub1","uuid":"u-b"}
        ]
    });
    let old = cfg["selectedServerId"].as_str().map(str::to_string);
    reconcile_subscription_servers(&mut cfg, "sub1", vec![srv("C", "c.com", 443)], false, &[]);
    let new = cfg.get("selectedServerId").and_then(Value::as_str);
    assert_eq!(
        cfg["selectedServerId"],
        json!("gen-C"),
        "选中随刷新消失 → reselect 幸存节点"
    );
    assert!(
        selected_exit_changed(old.as_deref(), new),
        "选中变 是出口变（必须失效）"
    );

    // 命中保留选中 id（同 id）→ 出口不变（不失效）。
    let mut cfg2 = json!({
        "selectedServerId": "id-A",
        "servers": [
            {"id":"id-A","name":"A","protocol":"vless","address":"a.com","port":443,"subscriptionId":"sub1","uuid":"11111111-1111-1111-1111-111111111111"}
        ]
    });
    let old2 = cfg2["selectedServerId"].as_str().map(str::to_string);
    reconcile_subscription_servers(&mut cfg2, "sub1", vec![srv("A", "a.com", 443)], false, &[]);
    let new2 = cfg2.get("selectedServerId").and_then(Value::as_str);
    assert_eq!(new2, Some("id-A"), "命中保留稳定 id");
    assert!(
        !selected_exit_changed(old2.as_deref(), new2),
        "选中 id 未变 → 出口不变（不失效）"
    );
}
