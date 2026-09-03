use super::*;
use polaris_config_engine::user_config::protocol_settings::{
    ShadowsocksSettings, WebSocketSettings,
};
use polaris_config_engine::user_config::server_config::{Protocol, SecurityMode};
use serde_json::json;

fn srv(id: &str) -> ServerConfig {
    ServerConfig {
        id: id.into(),
        name: format!("节点 {id}"),
        protocol: Protocol::Vless,
        address: "1.2.3.4".into(),
        port: 443,
        uuid: Some("u-1".into()),
        network: Some("tcp".into()),
        ..Default::default()
    }
}

/// 两条判据**必须**是两个不同公式 —— 整个模块的前提。
/// **变异对照**：把 [`modified_fingerprint`] 改成委托 5 维 → 转红。
#[test]
fn the_two_judgements_are_different_formulas() {
    let s = srv("a");
    assert_eq!(dirty_fingerprint(&s), "vless|1.2.3.4|443|u-1|tcp");
    assert_ne!(modified_fingerprint(&s), dirty_fingerprint(&s));
}

/// **核心不变式 `dirty ⊆ modified`（全维 ⊇ 5 维）**，逐字段类别实跑。
///
/// 断言两条，缺一不可：
/// 1. **包含**：任一改动只要动了 5 维指纹，就必然也动了全维指纹（⇒ dirty 集 ⊆ modified 集）。
/// 2. **不退化**：至少存在一个改动只动全维不动 5 维（⇒ 两条判据确实不同，包含是真包含）。
///
/// **变异对照**（协调方指定）：
/// - 把 [`modified_fingerprint`] 换回 5 维 ⇒ 断言 1 仍绿（5 维 ⊇ 5 维），断言 2 转红 —— 差异被钉住。
/// - 把 5 维那侧改成读全维 ⇒ 断言 2 转红。
#[test]
fn containment_holds_across_field_kinds() {
    /// 一条对照用例：标签 / 变形 / 是否期望动 5 维指纹。
    type Case = (&'static str, fn(&mut ServerConfig), bool);

    let cases: Vec<Case> = vec![
        ("protocol", |s| s.protocol = Protocol::Trojan, true),
        ("address", |s| s.address = "5.6.7.8".into(), true),
        ("port", |s| s.port = 8443, true),
        ("network", |s| s.network = Some("ws".into()), true),
        ("cred/uuid", |s| s.uuid = Some("u-2".into()), true),
        (
            "cred/password",
            |s| {
                s.uuid = None;
                s.password = Some("p-2".into());
            },
            true,
        ),
        (
            "cred/ss-password",
            |s| {
                s.uuid = None;
                s.shadowsocks_settings = Some(Box::new(ShadowsocksSettings {
                    password: "ss-2".into(),
                    ..Default::default()
                }));
            },
            true,
        ),
        // ── 以下只动全维、不动 5 维：正是「不该判 dirty」的那一类 ──
        ("name", |s| s.name = "改过名字".into(), false),
        ("tls", |s| s.security = Some(SecurityMode::Tls), false),
        (
            "ws-path",
            |s| {
                s.ws_settings = Some(Box::new(WebSocketSettings {
                    path: Some("/新路径".into()),
                    ..Default::default()
                }));
            },
            false,
        ),
        ("flow", |s| s.flow = Some("xtls-rprx-vision".into()), false),
        ("detour", |s| s.detour = Some("前置".into()), false),
    ];

    let base = srv("a");
    let mut saw_modified_only = false;
    for (label, mutate, expect_dirty_moves) in cases {
        let mut next = base.clone();
        mutate(&mut next);

        let dirty_moved = dirty_fingerprint(&base) != dirty_fingerprint(&next);
        let modified_moved = modified_fingerprint(&base) != modified_fingerprint(&next);

        // 断言 1：**包含关系**（本模块的核心不变式）。刻意放在最前 ——
        // 它是三条断言里唯一「破了就等于用户实报症状复现」的那条，任何变异下它都该第一个说话；
        // 排在后面会被别的断言抢先报错，掩盖「到底是不是包含关系破了」。
        assert!(
            !dirty_moved || modified_moved,
            "[{label}] 违反 dirty ⊆ modified：测速会指引用户去点一个 bar 上没有的东西"
        );
        // 断言 2：两侧各自的粒度符合预期。
        assert_eq!(
            dirty_moved, expect_dirty_moves,
            "[{label}] 5 维判据是否变动与预期不符"
        );
        assert!(
            modified_moved,
            "[{label}] 全维判据必须捕获每一个真实字段改动"
        );
        if modified_moved && !dirty_moved {
            saw_modified_only = true;
        }
    }
    // 断言 3：真包含（两条判据确有差异，包含不是退化成相等）。
    assert!(
        saw_modified_only,
        "必须存在只进 modified、不进 dirty 的改动，否则两条判据已退化成同一条"
    );
}

/// 元数据键（`updatedAt` / `createdAt` / `providerName`）被全维投影剔除 ⇒ 订阅刷新只换时间戳
/// 不会虚报「待生效」。这三个键与 5 维输入不重合，故不影响包含关系。
/// **变异对照**：`orchestration::server_fingerprint` 里去掉 `obj.remove("updatedAt")` → 转红。
#[test]
fn metadata_keys_do_not_move_either_judgement() {
    let base = srv("a");
    let mut touched = base.clone();
    touched.updated_at = Some("2026-07-28T00:00:00Z".into());
    touched.created_at = Some("2026-07-01T00:00:00Z".into());
    touched.provider_name = Some("某订阅".into());
    assert_eq!(modified_fingerprint(&base), modified_fingerprint(&touched));
    assert_eq!(dirty_fingerprint(&base), dirty_fingerprint(&touched));
}

/// typed 侧（起核快照）与 JSON 侧（当前配置）必须给出**同一个串**。
/// 两侧不同源正是收口前那条活 bug 的形态。
/// **变异对照**：把 [`modified_table_json`] 改成调 [`dirty_fingerprint`] → 转红。
#[test]
fn typed_and_json_sides_agree() {
    let s = srv("a");
    let json_cfg = json!({ "servers": [serde_json::to_value(&s).unwrap()] });
    assert_eq!(
        modified_table(std::slice::from_ref(&s)),
        modified_table_json(&json_cfg),
    );
}

/// 畸形/缺字段条目跳过而非 panic，也不虚构指纹。
/// **变异对照**：把 `filter_map` 改成 `map` + `unwrap` → panic → 转红。
#[test]
fn json_side_tolerates_garbage() {
    assert!(modified_table_json(&json!({})).is_empty());
    assert!(modified_table_json(&json!({ "servers": "nope" })).is_empty());
    let mixed = json!({ "servers": [
        { "no": "id" },
        serde_json::to_value(srv("ok")).unwrap(),
        { "id": "broken", "protocol": "???" },
    ]});
    assert_eq!(
        modified_table_json(&mixed).keys().collect::<Vec<_>>(),
        vec!["ok"]
    );
}
