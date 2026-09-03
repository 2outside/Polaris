use super::*;

#[test]
fn status_serializes_kebab() {
    let json = serde_json::to_string(&UnlockStatus::Blocked).unwrap();
    assert_eq!(json, "\"blocked\"");
    let back: UnlockStatus = serde_json::from_str("\"partial\"").unwrap();
    assert_eq!(back, UnlockStatus::Partial);
}

/// `Restricted` 变体序列化契约：必须是 `"restricted"`（前端联合类型同字面量）。
/// 打断 rename_all 或改字面量 → 前端 `status === 'restricted'` 分支收不到 → 转红。
#[test]
fn restricted_serializes_lowercase() {
    let json = serde_json::to_string(&UnlockStatus::Restricted).unwrap();
    assert_eq!(json, "\"restricted\"");
    let back: UnlockStatus = serde_json::from_str("\"restricted\"").unwrap();
    assert_eq!(back, UnlockStatus::Restricted);
}

/// 顺序契约：上线集必须**逐一等于**前端 `ENABLED_SERVICE_IDS` 全序列
/// （= `SERVICE_IDS` 去掉 `PENDING_CALIBRATION_SERVICE_IDS`）。
///
/// **射程边界（务必读）**：下面的期望值是前端数组的**硬编码副本**，故本测只锁「改了 Rust 忘了改
/// 前端」这一个方向。反方向（只改前端、Rust 不动）本测**看不见** —— 由
/// `ui/src/contracts/unlock-detection.test.ts` 锁住：那条 vitest 直接读本文件源码解析 `ALL` /
/// `PENDING_CALIBRATION` 再与前端三个数组比对。两条合起来才是双向锁；删掉任一条就有一个方向裸奔。
#[test]
fn service_ids_order_matches_frontend() {
    let got: Vec<&str> = ServiceId::ALL.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        got,
        vec!["chatgpt", "claude", "gemini", "netflix", "disney", "tiktok", "spotify"]
    );
}

/// 上线集 ⊎ 停飞集 == 前端 `SERVICE_IDS` 全集（无重叠、无遗漏）。
///
/// 守的是「服务被**静默**弄丢」：某个 id 既不在 `ALL` 也不在 `PENDING_CALIBRATION`，
/// 就成了有 checker 有单测、却谁也不知道它没上线的孤儿。
#[test]
fn shipped_plus_pending_covers_frontend_service_ids() {
    // ui/src/contracts/unlock-detection.ts::SERVICE_IDS（已实现全集，含停飞项）
    const FRONTEND: &[&str] = &[
        "chatgpt", "claude", "gemini", "grok", "netflix", "disney", "tiktok", "spotify",
    ];
    for pending in ServiceId::PENDING_CALIBRATION {
        assert!(
            !ServiceId::ALL.contains(pending),
            "{} 同时在上线集与停飞集 —— 开关自相矛盾",
            pending.as_str()
        );
    }
    let mut got: Vec<&str> = ServiceId::ALL
        .iter()
        .chain(ServiceId::PENDING_CALIBRATION)
        .map(|s| s.as_str())
        .collect();
    got.sort_unstable();
    let mut want = FRONTEND.to_vec();
    want.sort_unstable();
    assert_eq!(got, want, "上线集+停飞集 必须等于前端 SERVICE_IDS 全集");
}

/// `Grok`/`Tiktok` 字面量契约：前端是 `'grok'` / `'tiktok'`（非 `'xai'` / `'tikTok'`）——
/// `rename_all = "lowercase"` 保证对齐。打断任一 → 前端 `unlock.results['tiktok']` 恒 undefined
/// → 徽章恒 idle（静默不显，比报错隐蔽）。grok 当前停飞（[`ServiceId::PENDING_CALIBRATION`]），
/// 这条替它把字面量锁住，标定后翻开关即用，不必再对一遍序列化名。
#[test]
fn grok_and_tiktok_serialize_lowercase() {
    assert_eq!(serde_json::to_string(&ServiceId::Grok).unwrap(), "\"grok\"");
    assert_eq!(ServiceId::Grok.as_str(), "grok");
    assert_eq!(
        serde_json::to_string(&ServiceId::Tiktok).unwrap(),
        "\"tiktok\""
    );
    assert_eq!(ServiceId::Tiktok.as_str(), "tiktok");
}

/// 后端上线集必须是前端 `SERVICE_IDS` 的**子序列**（顺序一致、无多余项）——防未来加服务时序漂移；
/// 停飞集摘出后仍成立（子序列 ≠ 全等，正是「少几项但不许乱序」这条约束）。
#[test]
fn service_ids_are_subsequence_of_frontend() {
    const FRONTEND: &[&str] = &[
        "chatgpt", "claude", "gemini", "grok", "netflix", "disney", "tiktok", "spotify",
    ];
    let mut fe = FRONTEND.iter();
    for id in ServiceId::ALL {
        assert!(
            fe.any(|f| *f == id.as_str()),
            "{} 不在前端 SERVICE_IDS 中或顺序错乱",
            id.as_str()
        );
    }
}

#[test]
fn result_skip_none_region() {
    let json = serde_json::to_string(&UnlockResult::timeout()).unwrap();
    assert_eq!(json, "{\"status\":\"timeout\"}");
}

/// 前端契约门：快照/进度序列化**必须**是 camelCase（前端读 `checkedAt`/`notReady`/
/// `lowConfidence`/`serviceId`）。删掉 `#[serde(rename_all="camelCase")]` → 本测试转红。
/// 这是「接了就亮」的地基：键不对前端拿到 undefined，UI 静默不显（比报错更隐蔽）。
#[test]
fn snapshot_and_progress_serialize_camel_case_for_frontend_contract() {
    let mut snap = UnlockSnapshot::all_timeout();
    snap.checked_at = Some(42);
    snap.low_confidence = Some(true);
    let v: serde_json::Value = serde_json::to_value(&snap).unwrap();
    assert!(
        v.get("checkedAt").is_some(),
        "前端读 checkedAt（非 checked_at）"
    );
    assert!(v.get("checked_at").is_none(), "不得发 snake_case 键");
    assert!(v.get("lowConfidence").is_some(), "前端读 lowConfidence");

    let mut blocked = UnlockSnapshot::blocked(UnlockBlockedReason::ProxyNotRunning);
    blocked.not_ready = Some(true);
    let bv: serde_json::Value = serde_json::to_value(&blocked).unwrap();
    assert_eq!(
        bv.get("blockedReason").and_then(|x| x.as_str()),
        Some("proxy-not-running")
    );
    assert!(bv.get("notReady").is_some(), "前端读 notReady");

    let prog = UnlockProgress {
        service_id: "chatgpt".into(),
        result: UnlockResult::new(UnlockStatus::Ok),
    };
    let pv: serde_json::Value = serde_json::to_value(&prog).unwrap();
    assert_eq!(
        pv.get("serviceId").and_then(|x| x.as_str()),
        Some("chatgpt")
    );
    assert!(
        pv.get("service_id").is_none(),
        "进度键须 serviceId（非 service_id）"
    );
}

#[test]
fn snapshot_all_timeout_covers_every_service() {
    let s = UnlockSnapshot::all_timeout();
    assert_eq!(s.results.len(), ServiceId::ALL.len());
    for v in s.results.values() {
        assert_eq!(v.status, UnlockStatus::Timeout);
    }
    assert!(s.checked_at.is_none());
}
