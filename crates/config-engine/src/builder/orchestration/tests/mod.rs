/// 排除表里**哪些是活的**必须被钉死。
///
/// 表里现只有 `selectedServerId` 一项，且它真是 `UserConfig` 的序列化字段（2026-07-29 前另有
/// 14 个非 `FIELD_NAMES` 的死键，是与 上游 对拍的留痕，随该判据退役一并删除）。
///
/// 本测防的是**一次静默的语义变化**：谁往排除表里加一个真字段（或让 `selectedServerId` 掉出
/// `FIELD_NAMES` / 掉出排除表），该字段就会不参与生成判等 —— 即改它不会被判为需要重启内核。
/// 那可能是对的，但必须是一次睁着眼的决定。
///
/// 牙（两向）：
///  1. 把 `selectedServerId` 从生产排除分支删掉 → 下方自检 `arm.contains` 转红；
///  2. 把 `selectedServerId` 从 `FIELD_NAMES` 删掉 → `live` 断言转红。
///
/// **本测守不住的方向**（与 2026-07-29 缩表前一致，缩表未新增此洞）：往生产分支加一个新键而不改
/// 本表 —— `live` 是从本表算的，加在生产侧看不见。真正兜住它的是「排除即空操作」这条结构性质：
/// 非 `UserConfig` 字段排了也白排，而真字段一旦被排会让 `norm` 少一维，由热切换/重启的行为测发现。
#[test]
fn exclusion_table_live_entries_are_pinned() {
    use crate::user_config::app_config::UserConfig;
    // 与 `config_generation_norm` 里那份排除分支逐行同源（改一处必须改另一处，
    // 不同步会让本测守着一张不存在的表 —— 故下面另有一条自检）。
    const EXCLUDED: [&str; 1] = ["selectedServerId"];
    let fields: std::collections::BTreeSet<&str> =
        UserConfig::FIELD_NAMES.iter().copied().collect();
    let live: Vec<&str> = EXCLUDED
        .iter()
        .copied()
        .filter(|k| fields.contains(k))
        .collect();
    assert_eq!(
        live,
        ["selectedServerId"],
        "排除表的**生效面**变了。它从来只对 UserConfig 的真实字段起作用；\
             多出来的键意味着某个字段被悄悄排除出生成判等（改它不再触发重启内核），\
             少了则意味着 selectedServerId 不再被排除。两个方向都必须是显式决定"
    );

    // 自检：上面那份常量表必须与实现里的排除分支逐字同源，否则本测在守一张幽灵表。
    // 扫描面必须**排除本测自己**：`crate_source!` 读的是本文件，而上面那份 EXCLUDED 常量就写在
    // 这里 —— 扫全文的话表里的键永远「找得到」，自检恒绿（试过，正是这么栽的）。
    // 故只取 `#[cfg(test)]` 之前的生产段。用结构性锚点而非注释文本：注释会被改，模块属性不会。
    let src = polaris_source_probe::crate_source!("builder/orchestration.rs");
    let arm = src
        .split("#[cfg(test)]")
        .next()
        .expect("split 至少产出一段");
    assert!(
        arm.contains("fn config_generation_norm"),
        "生产段里找不到 config_generation_norm —— 切分锚点漂了，下面的断言在扫一段空文本"
    );
    // 反自引用：锚点一旦匹配不上，`split(..).next()` 会**返回整份文件**（不是 None），
    // 于是本测自己的 EXCLUDED 常量也进了扫描面 ⇒ 键永远找得到 ⇒ 自检恒绿。
    // 常量名只出现在测试模块里，故用它判「扫过界了」。
    assert!(
        !arm.contains("const EXCLUDED"),
        "扫描面把测试模块也扫进来了（切分锚点失配）—— 自检会拿本测自己的常量表自我印证"
    );
    for k in EXCLUDED {
        assert!(
            arm.contains(&format!("\"{k}\"")),
            "常量表里的 {k} 在 config_generation_norm 的排除分支里找不到 —— 两处已分叉"
        );
    }
}

use super::*;

#[test]
fn stable_stringify_sorts_keys() {
    let v: serde_json::Value = serde_json::from_str(r#"{"c":3,"a":1,"b":2}"#).unwrap();
    let s = stable_stringify(&v);
    // 键应按字母序：a,b,c
    assert_eq!(s, r#"{"a":1,"b":2,"c":3}"#);
}

#[test]
fn stable_stringify_preserves_array_order() {
    let v: serde_json::Value = serde_json::from_str(r#"[3,1,2]"#).unwrap();
    let s = stable_stringify(&v);
    assert_eq!(s, "[3,1,2]");
}

#[test]
fn stable_stringify_recursive_nested() {
    let v: serde_json::Value = serde_json::from_str(r#"{"z":{"b":2,"a":1},"y":[1,2]}"#).unwrap();
    let s = stable_stringify(&v);
    assert_eq!(s, r#"{"y":[1,2],"z":{"a":1,"b":2}}"#);
}

#[test]
fn stable_stringify_equal_despite_key_order() {
    let a: serde_json::Value = serde_json::from_str(r#"{"a":1,"b":2}"#).unwrap();
    let b: serde_json::Value = serde_json::from_str(r#"{"b":2,"a":1}"#).unwrap();
    assert_eq!(stable_stringify(&a), stable_stringify(&b));
}

#[test]
fn config_generation_norm_excludes_ui_fields() {
    let mut config = UserConfig::default();
    config.servers = vec![crate::user_config::server_config::ServerConfig {
        id: "s1".into(),
        name: "s1".into(),
        protocol: crate::user_config::server_config::Protocol::Shadowsocks,
        address: "1.1.1.1".into(),
        port: 443,
        ..Default::default()
    }];
    config.selected_server_id = Some("s1".into());
    let norm1 = config_generation_norm(&config, None);
    // 切换 selectedServerId → norm 不变（已排除）
    config.selected_server_id = Some("s2".into());
    let norm2 = config_generation_norm(&config, None);
    assert_eq!(norm1, norm2, "selectedServerId 变化不应翻转 norm");
}

#[test]
fn config_generation_norm_global_ignores_user_routing() {
    use crate::user_config::proxy_mode::ProxyMode;
    use crate::user_config::rule::{Rule, RuleAction, RuleType};
    let mut config = UserConfig::default();
    config.proxy_mode = ProxyMode::Global;
    config.servers = vec![crate::user_config::server_config::ServerConfig {
        id: "s1".into(),
        name: "s1".into(),
        protocol: crate::user_config::server_config::Protocol::Shadowsocks,
        address: "1.1.1.1".into(),
        port: 443,
        ..Default::default()
    }];
    config.custom_rules = vec![Rule {
        id: "r1".into(),
        type_field: RuleType::Domain,
        values: vec!["x.com".into()],
        conditions: None,
        combine_mode: None,
        effects: None,
        action: RuleAction::Proxy,
        enabled: true,
        bypass_fakeip: None,
        target_server_id: None,
        remarks: None,
        tls_spoof: None,
        tls_spoof_method: None,
    }];
    let norm = config_generation_norm(&config, None);
    // global 模式 → authoritative trafficRules 投影为 []
    assert!(norm.contains(r#""trafficRules":[]"#));
}

#[test]
fn traffic_rules_target_is_hot_switch_axis_and_legacy_mirror_is_ignored() {
    use crate::user_config::proxy_mode::ProxyMode;
    use crate::user_config::rule::{Rule, RuleAction, RuleEffects, RuleRouteEffect, RuleType};

    let rule = |id: &str, target: &str| Rule {
        id: id.into(),
        type_field: RuleType::Domain,
        values: vec!["example.com".into()],
        action: RuleAction::Proxy,
        enabled: true,
        target_server_id: Some(target.into()),
        ..Default::default()
    };
    let mut old = UserConfig {
        proxy_mode: ProxyMode::Smart,
        custom_rules: vec![rule("legacy", "legacy-a")],
        traffic_rules: Some(vec![rule("active", "node-a")]),
        ..Default::default()
    };
    let mut next = old.clone();
    next.traffic_rules = Some(vec![rule("active", "node-b")]);
    assert_eq!(
        config_generation_norm(&old, None),
        config_generation_norm(&next, None),
        "trafficRules.targetServerId 必须留给 selector 热切换"
    );

    old.custom_rules = vec![rule("stale", "stale-b")];
    assert_eq!(
        config_generation_norm(&old, None),
        config_generation_norm(&next, None),
        "trafficRules 存在时陈旧 customRules 不得再影响生成判等"
    );

    let effects_rule = |target: &str| Rule {
        id: "effects-active".into(),
        type_field: RuleType::Domain,
        values: vec!["effects.example.com".into()],
        action: RuleAction::Proxy,
        enabled: true,
        effects: Some(RuleEffects {
            route: Some(RuleRouteEffect {
                enabled: true,
                action: RuleAction::Proxy,
                target_server_id: Some(target.into()),
                destination_resolution: None,
                resolution_only: false,
            }),
            dns: None,
        }),
        ..Default::default()
    };
    let effects_old = UserConfig {
        proxy_mode: ProxyMode::Smart,
        traffic_rules: Some(vec![effects_rule("node-a")]),
        ..Default::default()
    };
    let effects_next = UserConfig {
        traffic_rules: Some(vec![effects_rule("node-b")]),
        ..effects_old.clone()
    };
    assert_eq!(
        config_generation_norm(&effects_old, None),
        config_generation_norm(&effects_next, None),
        "effects.route.targetServerId 也必须留给 selector 热切换"
    );
}
