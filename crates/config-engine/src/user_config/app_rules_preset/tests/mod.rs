use super::*;

#[test]
fn builtin_presets_include_youtube_telegram() {
    let presets = all_presets();
    let ids: Vec<&str> = presets.iter().map(|p| p.id.as_str()).collect();
    assert!(ids.contains(&"youtube"));
    assert!(ids.contains(&"telegram"));
    assert!(ids.contains(&"steam"));
}

#[test]
fn get_builtin_preset() {
    let p = get_app_preset("youtube", &[]).unwrap();
    assert!(p.geosite_tags.contains(&"youtube".to_string()));
}

#[test]
fn get_custom_preset() {
    let custom = vec![CustomAppPreset {
        id: "custom-foo".into(),
        name: "Foo".into(),
        emoji: "🚀".into(),
        icon_url: None,
        geosite_tags: vec!["foo".into()],
        geoip_tags: vec![],
        process_names: Some(vec!["FooApp".into()]),
        category: Some("tools".into()),
    }];
    let p = get_app_preset("custom-foo", &custom).unwrap();
    assert!(p.geosite_tags.contains(&"foo".to_string()));
    assert!(p.process_names.contains(&"FooApp".to_string()));
}

#[test]
fn get_unknown_returns_none() {
    assert!(get_app_preset("nonexistent", &[]).is_none());
}

#[test]
fn default_rules_one_per_builtin() {
    let rules = default_app_rules();
    let presets = all_presets();
    assert_eq!(rules.len(), presets.len());
    assert!(rules
        .iter()
        .all(|r| r.enabled && r.action == RuleAction::Proxy));
}

#[test]
fn seed_keeps_custom_and_fills_missing() {
    let existing = vec![AppRule {
        app_id: "custom-x".into(),
        action: RuleAction::Direct,
        enabled: true,
        target_server_id: None,
    }];
    let seeded = seed_default_app_rules(&existing);
    // custom-x 保留
    assert!(seeded.iter().any(|r| r.app_id == "custom-x"));
    // 内置全补
    for p in all_presets() {
        assert!(seeded.iter().any(|r| r.app_id == p.id), "missing {}", p.id);
    }
}

#[test]
fn seed_drops_offline_preset() {
    let existing = vec![AppRule {
        app_id: "bilibili".into(), // 已下线
        action: RuleAction::Proxy,
        enabled: true,
        target_server_id: None,
    }];
    let seeded = seed_default_app_rules(&existing);
    assert!(!seeded.iter().any(|r| r.app_id == "bilibili"));
}

// ── DTO 门 ──────────────────────────────────────────────────────────
//
// 「前端不得再有第二份表」那几条**读前端源码**的门在 `tests/frontend_sot_guard.rs`（集成测试，
// 与 catalog 的同类门同处一室、共用剥注释器）。本处只放**纯 Rust 侧**的自洽性门。

#[test]
fn dto_keys_are_camel_case_contract() {
    // DTO 键名是跨语言契约（前端 AppPreset interface）。与前端字段的对差在
    // tests/frontend_sot_guard.rs::frontend_preset_interface_matches_rust_dto_fields。
    let dto = &all_presets_dto()[0];
    let json = serde_json::to_value(dto).expect("DTO 序列化");
    let obj = json.as_object().expect("DTO 应为对象");
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "category",
            "emoji",
            "geoipTags",
            "geositeTags",
            "iconUrl",
            "id",
            "labelKey",
            "processNames"
        ],
        "DTO 键名与前端 AppPreset interface 漂移"
    );
}

#[test]
fn dto_and_routing_projection_share_one_table() {
    // 两个投影必须来自同一张表：条数相同、id 逐条同序。若有人给某个投影另建数据源 → 红。
    let routing = all_presets();
    let dto = all_presets_dto();
    assert_eq!(routing.len(), 16, "内置预设 16 条");
    assert_eq!(routing.len(), dto.len(), "两投影条数不一致 → 数据源分裂");
    for (r, d) in routing.iter().zip(dto.iter()) {
        assert_eq!(r.id, d.id, "两投影 id 序列不一致 → 数据源分裂");
        assert_eq!(r.geosite_tags, d.geosite_tags);
        assert_eq!(r.geoip_tags, d.geoip_tags);
        assert_eq!(r.process_names, d.process_names);
        assert_eq!(r.category, d.category);
    }
}

#[test]
fn dto_ui_columns_populated() {
    // UI 列不得空——空 labelKey 会让卡片显示 id，空 emoji 让 iconUrl 失败时无兜底。
    for p in all_presets_dto() {
        assert!(!p.label_key.is_empty(), "{} 缺 labelKey", p.id);
        assert!(
            !p.emoji.is_empty(),
            "{} 缺 emoji（iconUrl 失败即无兜底）",
            p.id
        );
        let url = p.icon_url.as_deref().unwrap_or("");
        assert!(
            url.starts_with("https://"),
            "{} 的 iconUrl 非 https（{url:?}）",
            p.id
        );
    }
}

#[test]
fn dto_geo_tags_are_covered_by_builtin_rulesets() {
    // 每条预设引用的 geo tag 必须在随包内置 geo 规则集里，否则该应用的域名兜底规则会被
    // fail-closed 剪枝（route.rs:998）→ 应用分流只剩进程名生效。加预设漏加 tag → 红。
    let (geosite, geoip) = crate::user_config::builtin_geo_rulesets::app_geo_tags();
    for p in all_presets_dto() {
        for t in &p.geosite_tags {
            let tag = format!("geosite-{}", t.to_ascii_lowercase());
            assert!(
                geosite.contains(&tag),
                "预设 {} 引用 {tag}，但 builtin_geo_rulesets 的 APP_GEOSITE_TAGS 没有它",
                p.id
            );
        }
        for t in &p.geoip_tags {
            let tag = format!("geoip-{}", t.to_ascii_lowercase());
            assert!(
                geoip.contains(&tag),
                "预设 {} 引用 {tag}，但 builtin_geo_rulesets 的 APP_GEOIP_TAGS 没有它",
                p.id
            );
        }
    }
}

#[test]
fn dto_lookup_builtin_wins_and_custom_keeps_real_category() {
    // 内置优先（自定义影子不了内置 id）。
    let shadow = vec![CustomAppPreset {
        id: "youtube".into(),
        name: "Shadow".into(),
        emoji: "x".into(),
        icon_url: None,
        geosite_tags: vec!["evil".into()],
        geoip_tags: vec![],
        process_names: None,
        category: Some("game".into()),
    }];
    let p = get_app_preset_dto("youtube", &shadow).unwrap();
    assert_eq!(p.label_key, "youtube");
    assert_eq!(p.geosite_tags, vec!["youtube".to_string()]);

    // 自定义：labelKey 取 name，category 取真值（非 get_app_preset 那个 "tools" 占位）。
    let custom = vec![CustomAppPreset {
        id: "custom-foo".into(),
        name: "我的 Foo".into(),
        emoji: "🚀".into(),
        icon_url: Some("https://e.com/f.png".into()),
        geosite_tags: vec!["foo".into()],
        geoip_tags: vec![],
        process_names: Some(vec!["FooApp".into()]),
        category: Some("game".into()),
    }];
    let p = get_app_preset_dto("custom-foo", &custom).unwrap();
    assert_eq!(p.label_key, "我的 Foo");
    assert_eq!(
        p.category, "game",
        "自定义预设的 category 应取真值供渲染端分组"
    );
    assert_eq!(p.process_names, vec!["FooApp".to_string()]);

    assert!(get_app_preset_dto("nonexistent", &[]).is_none());
}
