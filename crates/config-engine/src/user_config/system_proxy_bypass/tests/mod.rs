use super::*;

struct Cfg {
    on: Option<bool>,
    list: Option<Vec<String>>,
}
impl BypassConfig for Cfg {
    fn bypass_lan(&self) -> Option<bool> {
        self.on
    }
    fn bypass_lan_list(&self) -> Option<&[String]> {
        self.list.as_deref()
    }
}

#[test]
fn effective_default_when_unset() {
    let list = effective_bypass_lan(&Cfg {
        on: None,
        list: None,
    });
    assert!(list.contains(&"192.168.0.0/16".to_string()));
    assert!(list.contains(&"localhost".to_string()));
}

#[test]
fn effective_off_when_false() {
    assert!(effective_bypass_lan(&Cfg {
        on: Some(false),
        list: None
    })
    .is_empty());
}

#[test]
fn effective_user_list() {
    let list = effective_bypass_lan(&Cfg {
        on: Some(true),
        list: Some(vec!["10.0.0.0/8".into()]),
    });
    assert_eq!(list, vec!["10.0.0.0/8".to_string()]);
}

#[test]
fn cidr_detection() {
    assert!(is_ipv4_cidr("192.168.0.0/16"));
    assert!(is_ipv4_cidr("10.0.0.0/8"));
    assert!(!is_ipv4_cidr("localhost"));
    assert!(is_ipv6_cidr("fc00::/7"));
    assert!(is_ipv6_cidr("fe80::/10"));
    assert!(!is_ipv6_cidr("192.168.0.0/16"));
    assert!(is_ip_cidr("10.0.0.0/8"));
    assert!(is_ip_cidr("fc00::/7"));
    assert!(!is_ip_cidr("*.local"));
}

#[test]
fn bypass_lan_cidrs_filters_domains() {
    let list = vec![
        "10.0.0.0/8".to_string(),
        "localhost".to_string(),
        "*.local".to_string(),
        "fc00::/7".to_string(),
        "192.168.0.0/16".to_string(),
    ];
    let cidrs = bypass_lan_cidrs(&list);
    assert_eq!(cidrs.len(), 3);
    assert!(cidrs.contains(&"10.0.0.0/8".to_string()));
    assert!(cidrs.contains(&"fc00::/7".to_string()));
}

// ── F1: ensure_bypass_lan_list（配置读取边界补齐，防默认坍塌）──

/// **F1 no-collapse 门**：缺 `bypassLANList` 的配置，经边界补齐 + 编辑器追加一条后，
/// 27 条 `DEFAULT_BYPASS_LAN` 一条不丢（复现「首个按键坍塌」并证明已修）。
#[test]
fn ensure_undefined_then_append_does_not_drop_defaults() {
    // 新用户配置：store 不 seed bypassLANList → 字段缺省。
    let mut cfg = serde_json::json!({ "proxyMode": "global", "mixedPort": 7890 });
    assert!(
        cfg.get("bypassLANList").is_none(),
        "前提：新配置不含 bypassLANList（store 未 seed）"
    );

    // 边界补齐（config:get 对 UI 下发的那一步）。
    ensure_bypass_lan_list(&mut cfg);

    let injected: Vec<String> = cfg["bypassLANList"]
        .as_array()
        .expect("补齐后应为数组")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    // 收到的正是全部 27 条默认，而非前端 3 条兜底。
    assert_eq!(
        injected.len(),
        DEFAULT_BYPASS_LAN.len(),
        "UI 应收到全部默认，实收 {injected:?}"
    );
    for d in DEFAULT_BYPASS_LAN {
        assert!(injected.contains(&d.to_string()), "缺默认项 {d}");
    }

    // 模拟 ListEditor 首个按键：在收到的清单尾部追加一条，写回。
    let mut edited = injected.clone();
    edited.push("198.18.0.0/15".to_string());

    // 追加后，24 条会被前端兜底丢弃的关键默认仍在（回归锚点）。
    for critical in ["10.0.0.0/8", "172.16.0.0/12", "100.64.0.0/10", "*.local"] {
        assert!(
            edited.contains(&critical.to_string()),
            "追加一条后默认项 {critical} 被丢弃（坍塌回归）"
        );
    }
    assert_eq!(edited.len(), DEFAULT_BYPASS_LAN.len() + 1);
}

/// 幂等 + 尊重用户意图：已有具体数组（含用户清空的 `[]`）不被覆盖。
#[test]
fn ensure_preserves_existing_and_empty_user_list() {
    let mut with_list = serde_json::json!({ "bypassLANList": ["10.0.0.0/8"] });
    ensure_bypass_lan_list(&mut with_list);
    assert_eq!(
        with_list["bypassLANList"],
        serde_json::json!(["10.0.0.0/8"])
    );

    // 用户清空 → [] 是显式意图，不得被默认覆盖。
    let mut cleared = serde_json::json!({ "bypassLANList": [] });
    ensure_bypass_lan_list(&mut cleared);
    assert_eq!(cleared["bypassLANList"], serde_json::json!([]));
}

/// **镜像锁**：`ensure_bypass_lan_list`（作用于 JSON 缺省态）与 `effective_bypass_lan`
/// （作用于 typed 配置）逐条对齐 —— 任一侧改语义未同步即转红，杜绝双真相漂移。
#[test]
fn ensure_mirrors_effective_bypass_lan() {
    // 缺省（bypassLAN 未设）→ DEFAULT，与 effective(None,None) 一致。
    let mut absent = serde_json::json!({});
    ensure_bypass_lan_list(&mut absent);
    let via_ensure: Vec<String> = absent["bypassLANList"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    let via_effective = effective_bypass_lan(&Cfg {
        on: None,
        list: None,
    });
    assert_eq!(via_ensure, via_effective, "缺省分支须与 effective 一致");

    // 总开关关（bypassLAN=false）→ []，与 effective(Some(false),None) 一致。
    let mut off = serde_json::json!({ "bypassLAN": false });
    ensure_bypass_lan_list(&mut off);
    assert_eq!(off["bypassLANList"], serde_json::json!([]));
    assert!(effective_bypass_lan(&Cfg {
        on: Some(false),
        list: None
    })
    .is_empty());
}

#[test]
fn windows_patterns_align() {
    assert_eq!(
        ipv4_cidr_to_windows_patterns("10.0.0.0/8"),
        vec!["10.*".to_string()]
    );
    assert_eq!(
        ipv4_cidr_to_windows_patterns("192.168.0.0/16"),
        vec!["192.168.*".to_string()]
    );
    assert_eq!(
        ipv4_cidr_to_windows_patterns("192.168.1.0/24"),
        vec!["192.168.1.*".to_string()]
    );
    // /12 枚举 16 个。
    let p12 = ipv4_cidr_to_windows_patterns("172.16.0.0/12");
    assert_eq!(p12.len(), 16);
    assert!(p12[0].starts_with("172.16."));
    assert!(p12[15].starts_with("172.31."));
    // 不对齐前缀 → 空。
    assert!(ipv4_cidr_to_windows_patterns("100.64.0.0/10").is_empty());
}
