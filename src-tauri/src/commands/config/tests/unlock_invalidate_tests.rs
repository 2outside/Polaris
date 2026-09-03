use super::super::*;
use crate::runtime::unlock::UnlockRuntime;
use crate::test_support::TestDir;
use polaris_unlock::{UnlockResult, UnlockSnapshot};
use std::sync::Mutex;

/// 记录型 sink：本腿只触发 invalidated（progress/updated 由检测轮触发，与失效接线无关）。
#[derive(Default)]
struct CountingSink {
    invalidated: Mutex<Vec<(bool, bool)>>,
}
impl UnlockEventSink for CountingSink {
    fn progress(&self, _service_id: &str, _result: &UnlockResult) {}
    fn updated(&self, _snapshot: &UnlockSnapshot) {}
    fn invalidated(&self, running: bool, exit_blocked: bool) {
        self.invalidated
            .lock()
            .unwrap()
            .push((running, exit_blocked));
    }
}

/// 建 UnlockRuntime（`invalidate` 不触网）。
fn runtime() -> UnlockRuntime {
    UnlockRuntime::default()
}

fn temp_dir(tag: &str) -> TestDir {
    TestDir::new(&format!("polaris-unlock-inval-{tag}-"))
}

/// 纯谓词：出口 identity 变判准（两侧 Option）。打断（恒 true / 恒 false）→ 对应断言转红。
#[test]
fn selected_exit_changed_only_on_identity_change() {
    assert!(selected_exit_changed(Some("a"), Some("b")), "换节点 → 变");
    assert!(
        !selected_exit_changed(Some("a"), Some("a")),
        "重选同一节点 → 不变（防白刷）"
    );
    assert!(
        selected_exit_changed(None, Some("a")),
        "首次选中（旧 None）→ 变"
    );
    assert!(
        selected_exit_changed(Some("a"), None),
        "清除选中（新 None）→ 变"
    );
    assert!(!selected_exit_changed(None, None), "始终无选中 → 不变");
}

/// 决策核心 · 出口变 → 失效一次 + 递增 epoch + 带 (running, exitBlocked=false)。
/// 打断 `invalidate_unlock_on_exit_change` 的 `unlock.invalidate(...)` 调用 → 本测转红（零失效 + epoch 不动）。
#[test]
fn invalidate_fires_once_on_exit_change() {
    let rt = runtime();
    let sink = CountingSink::default();
    let e0 = rt.epoch();
    invalidate_unlock_on_exit_change(&rt, &sink, true, Some("a"), Some("b"));
    assert_eq!(
        sink.invalidated.lock().unwrap().as_slice(),
        &[(true, false)],
        "出口变 → 失效一次，带 running=true / exitBlocked=false"
    );
    assert_eq!(rt.epoch(), e0 + 1, "失效必须递增 epoch（作废在飞轮）");
}

/// 决策核心 · 出口未变 → 零失效 + epoch 不动（守卫白刷探测）。
/// 打断谓词为恒 true → 本测转红（无关 config 写触发白刷）。
#[test]
fn invalidate_skips_when_exit_unchanged() {
    let rt = runtime();
    let sink = CountingSink::default();
    let e0 = rt.epoch();
    invalidate_unlock_on_exit_change(&rt, &sink, true, Some("a"), Some("a"));
    assert!(
        sink.invalidated.lock().unwrap().is_empty(),
        "同出口 → 不失效"
    );
    assert_eq!(rt.epoch(), e0, "不失效则 epoch 不动");
}

/// 决策核心 · running 透传（false → 前端复位 idle 而非「检测中」）。
/// 打断 running 硬编码为 true → 本测转红。
#[test]
fn invalidate_propagates_running_state() {
    let rt = runtime();
    let sink = CountingSink::default();
    invalidate_unlock_on_exit_change(&rt, &sink, false, Some("a"), Some("b"));
    assert_eq!(
        sink.invalidated.lock().unwrap().as_slice(),
        &[(false, false)],
        "running=false 须透传"
    );
}

/// 老/新提取链（去 Tauri）：`current_selected_server_id` 读旧 + `set_value` 后取新 + 谓词判定——
/// 覆盖命令层「捕获旧 → 保存 → 提取新 → 决策」的提取逻辑（唯 sink 侧需 Tauri，已由上面注入测覆盖）。
/// 换出口 → 判变；改无关键 → 判不变（守卫白刷在提取链上同样成立）。
#[test]
fn extraction_chain_detects_change_and_guards_unrelated_write() {
    let dir = temp_dir("extract");
    let mgr = ConfigManager::new(dir.clone());
    // 建含 node-a/node-b 的合法配置（selectedServerId 存在性校验要求节点真在册，否则 save 校验 Err）。
    let mut cfg = mgr.load_full().unwrap();
    cfg.as_object_mut().unwrap().insert(
        "servers".into(),
        json!([
            { "id": "node-a", "name": "A", "protocol": "trojan", "address": "1.2.3.4", "port": 443, "password": "pw" },
            { "id": "node-b", "name": "B", "protocol": "trojan", "address": "5.6.7.8", "port": 443, "password": "pw" },
        ]),
    );
    cfg.as_object_mut()
        .unwrap()
        .insert("selectedServerId".into(), json!("node-a"));
    mgr.save_full(&cfg).unwrap();
    assert_eq!(
        current_selected_server_id(&mgr).as_deref(),
        Some("node-a"),
        "读回刚置的选中出口"
    );

    // 换选中出口：捕获旧 → set_value 新 → 提取新 → 判「变」。
    let old = current_selected_server_id(&mgr);
    let new_cfg = mgr.set_value("selectedServerId", json!("node-b")).unwrap();
    let new_sel = new_cfg.get("selectedServerId").and_then(Value::as_str);
    assert!(
        selected_exit_changed(old.as_deref(), new_sel),
        "换出口 → 失效"
    );

    // 无关键写（改 mixedPort，不动选中）：判「不变」（守卫白刷）。
    let old2 = current_selected_server_id(&mgr);
    let cfg2 = mgr.set_value("mixedPort", json!(7890)).unwrap();
    let new2 = cfg2.get("selectedServerId").and_then(Value::as_str);
    assert!(
        !selected_exit_changed(old2.as_deref(), new2),
        "无关键写不改出口 → 不失效"
    );
}
