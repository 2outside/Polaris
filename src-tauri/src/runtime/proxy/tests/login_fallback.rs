use super::*;

/// A4：`login_fallback_eligible` 从**原始 JSON** 读 `meshLoginFallbackDirect`（非 UserConfig 结构体字段）。
/// 变异有牙：打断 raw 读（恒 true）→ 「显式关开关」case 转红；改 `!= Some(false)` 为别的比较 → 缺省 case 转红。
#[test]
fn login_fallback_eligible_reads_flag_from_raw_json() {
    let (rt, _dir) = test_runtime();
    let raw = ts_fallback_config();
    let cfg: UserConfig = serde_json::from_value(raw.clone()).expect("parse");
    // 缺省（无 meshLoginFallbackDirect 键）→ 视作开 → eligible。
    assert!(
        rt.login_fallback_eligible(&cfg, &raw),
        "缺省应默认开 → 符合让位形态"
    );
    // 显式关（false）→ 不 eligible（用户明确「宁可授权失败也不直连」）。
    let mut raw_off = raw.clone();
    raw_off["meshLoginFallbackDirect"] = Value::Bool(false);
    assert!(
        !rt.login_fallback_eligible(&cfg, &raw_off),
        "meshLoginFallbackDirect=false 必须不让位"
    );
    // 显式开（true）→ eligible。
    let mut raw_on = raw.clone();
    raw_on["meshLoginFallbackDirect"] = Value::Bool(true);
    assert!(rt.login_fallback_eligible(&cfg, &raw_on));
}

/// A4：非 TS 出口 / 有 authKey → 不 eligible（谓词其余项，防「只读了开关」的假绿）。
#[test]
fn login_fallback_eligible_rejects_non_ts_and_authkey() {
    let (rt, _dir) = test_runtime();
    // 非 TS（vless）→ 不 eligible。
    let raw_vless = serde_json::json!({
        "servers": [{ "id": "s1", "name": "x", "protocol": "vless", "address": "a", "port": 1 }],
        "selectedServerId": "s1", "proxyMode": "smart"
    });
    let cfg_vless: UserConfig = serde_json::from_value(raw_vless.clone()).expect("parse");
    assert!(
        !rt.login_fallback_eligible(&cfg_vless, &raw_vless),
        "非 TS 出口不让位"
    );
    // TS 带 authKey（静态凭据，无交互登录死锁）→ 不 eligible。
    let raw_ak = serde_json::json!({
        "servers": [{
            "id": "ts1", "name": "x", "protocol": "tailscale", "address": "100.64.0.5", "port": 0,
            "tailscaleSettings": { "exitNode": "peer-x", "authKey": "tskey-abc" }
        }],
        "selectedServerId": "ts1", "proxyMode": "smart"
    });
    let cfg_ak: UserConfig = serde_json::from_value(raw_ak.clone()).expect("parse");
    assert!(
        !rt.login_fallback_eligible(&cfg_ak, &raw_ak),
        "authKey TS 不让位"
    );
}

/// A4：`mark_login_fallback_engaged` 首次 emit `(true, name)`；同出口重复调**幂等不再 emit**；engaged()=true。
/// 变异有牙：删 `first` 守卫 → 第二次也 emit → len==2 转红；删 emit → len==0 转红。
#[test]
fn mark_engaged_emits_once_and_is_idempotent() {
    let (rt, _dir, handle) = test_runtime_recording_fallback();
    let cfg: UserConfig = serde_json::from_value(ts_fallback_config()).expect("parse");
    rt.mark_login_fallback_engaged("ts1", &cfg);
    rt.mark_login_fallback_engaged("ts1", &cfg); // 幂等：同出口不再 emit
    assert!(rt.login_fallback_engaged(), "mark 后 engaged 必真");
    let evs = handle.lock().unwrap();
    assert_eq!(evs.len(), 1, "同出口只 emit 一次（first 守卫）");
    assert_eq!(
        evs[0],
        (true, Some("组网出口".to_string())),
        "engage 带出口名"
    );
    drop(evs);
}

/// A4：`reset_login_fallback_state` 让位中 → emit `(false, None)` 一次；未让位 → 零 emit（不刷屏）。
/// 变异有牙：删「未让位 return」→ 未让位也 emit → 转红；删 emit → 让位 reset 后 len==0 转红。
#[test]
fn reset_emits_disengage_only_when_engaged() {
    let (rt, _dir, handle) = test_runtime_recording_fallback();
    // 未让位 reset → 无 emit。
    rt.reset_login_fallback_state();
    assert!(handle.lock().unwrap().is_empty(), "未让位 reset 不 emit");
    // 让位中 reset → emit(false,None) 一次；再 reset → 无新 emit。
    rt.set_login_fallback(true, Some("ts1".to_string()));
    rt.reset_login_fallback_state();
    rt.reset_login_fallback_state();
    assert!(!rt.login_fallback_engaged(), "reset 后 engaged 必假");
    let evs = handle.lock().unwrap();
    assert_eq!(evs.len(), 1, "让位 reset 只 emit 一次 disengage");
    assert_eq!(evs[0], (false, None));
    drop(evs);
}

/// A4：reconcile 单飞——在飞标志占用时重入调用被丢弃（不改状态、零 emit）；正常退场 Guard 必复位标志。
/// 变异有牙：删 `swap(true)` 早退 → 重入会跑对账动状态 → engaged 断言转红；删 Guard → 标志不复位断言转红。
#[tokio::test]
async fn reconcile_single_flight_drops_reentrant_call() {
    let (rt, _dir, handle) = test_runtime_recording_fallback();
    // 手动占用单飞标志 + 置让位态 → reconcile 必被挡下（swap 返 true → 早退，不动状态、不 emit）。
    rt.login_fallback_reconciling.store(true, Ordering::SeqCst);
    rt.set_login_fallback(true, Some("ts1".to_string()));
    rt.reconcile_login_fallback().await;
    assert!(
        rt.login_fallback_engaged(),
        "在飞 → reconcile 早退，不改状态"
    );
    assert!(handle.lock().unwrap().is_empty(), "早退 → 零 emit");
    assert!(
        rt.login_fallback_reconciling.load(Ordering::SeqCst),
        "早退路径不复位标志（占用者持有）"
    );
    // 释放后正常一次 reconcile（无 current_config → 早退，但 Guard 必复位标志）。
    rt.login_fallback_reconciling.store(false, Ordering::SeqCst);
    rt.reconcile_login_fallback().await;
    assert!(
        !rt.login_fallback_reconciling.load(Ordering::SeqCst),
        "正常退场 ReconcileGuard 必复位单飞标志"
    );
}

// ══════════ A4 早退闸（P0-2②）：三态决策矩阵不变 + 「切走仍能 disengage」回归 ══════════
//
// 被守的是 `reconcile_login_fallback` 开头那道 `!engaged && !选中是 TS` 的合取闸。它只允许跳过
// 矩阵里「无任何可观测效果」的那一格；下面四条把**有效果**的三格逐格钉住，任何把闸写宽的变异
// （尤其是漏掉 `!engaged` 那一半）都会在其中一条上转红。

/// 一 TS + 一 vless 的两节点配置（`selected` 指定选中谁）。TS 侧为账号制全隧道（`exitNode` 非空、
/// 无 authKey）⇒ 选中它时符合让位形态。
fn ts_and_vless_config(selected: &str) -> Value {
    serde_json::json!({
        "servers": [
            { "id": "ts1", "name": "组网出口", "protocol": "tailscale",
              "address": "100.64.0.5", "port": 0,
              "tailscaleSettings": { "exitNode": "peer-x" } },
            { "id": "node-a", "name": "A", "protocol": "vless",
              "address": "a.example.com", "port": 443, "uuid": "u-a" }
        ],
        "selectedServerId": selected,
        "proxyMode": "smart"
    })
}

/// 往 mesh 末帧缓存塞一条指定 `backendState` 的 STATUS 帧（`selected_exit_backend_state` 的唯一来源）。
/// Taildrop 四位取中性值，不用 `..Default::default()`：日后加字段时这里必须被人再看一眼。
fn seed_backend_state(rt: &Arc<ProxyRuntime>, server_id: &str, backend_state: &str) {
    rt.mesh.update_ts_status(vec![TailscaleStatusEvent {
        server_id: server_id.into(),
        backend_state: backend_state.into(),
        logged_in: backend_state == "Running",
        auth_url: None,
        tailscale_ips: vec!["100.64.0.9".into()],
        expired: false,
        peers: Vec::new(),
        details: Default::default(),
        can_share_files: false,
        waiting_file_count: 0,
        receiving_file_count: 0,
        unread_file_count: 0,
    }]);
}

/// 早退闸的**廉价一半**必须与 `login_fallback_eligible` 里那条 TS 判定同口径。
///
/// 这条判据本身不可由行为观测（矩阵第 6 行两条路都无效果），故在这里直测：既证它没漏判
/// （选中 TS → 真，闸不会误吞 engage 腿），也证它没误判（切走 / 无选中 / 选中不存在 → 假）。
///
/// **变异锁**：键名写错（`selectedServerId` → `selected_server_id`、`protocol` → `type`）⇒ 首段转红；
/// 把协议字面量写成 `"Tailscale"` ⇒ 首段转红；去掉「选中项才算」这一跳（改成「任一节点是 TS」）
/// ⇒ 「切走」那段转红。
#[test]
fn selected_exit_is_tailscale_agrees_with_eligible_predicate() {
    let (rt, _dir) = test_runtime();
    // 选中 TS：判据为真，且与配置层 eligible 同向。
    let raw = ts_and_vless_config("ts1");
    *rt.current_config.write().unwrap() = Some(raw.clone());
    let cfg: UserConfig = serde_json::from_value(raw.clone()).expect("parse");
    assert!(
        rt.selected_exit_is_tailscale(),
        "选中 TS 出口 → 廉价判据必须为真"
    );
    assert!(
        rt.login_fallback_eligible(&cfg, &raw),
        "正向对照：同一份配置在完整判据下也符合让位形态"
    );
    // 切走到 vless：判据为假（配置里仍有 TS 节点，但它不是选中项）。
    let raw_away = ts_and_vless_config("node-a");
    *rt.current_config.write().unwrap() = Some(raw_away.clone());
    let cfg_away: UserConfig = serde_json::from_value(raw_away.clone()).expect("parse");
    assert!(
        !rt.selected_exit_is_tailscale(),
        "选中的是 vless → 判据必须为假（不能被配置里另一个 TS 节点喂饱）"
    );
    assert!(!rt.login_fallback_eligible(&cfg_away, &raw_away));
    // 空 selectedServerId / 选中 id 不在册 → 假（与 reconcile 里 `sel_id` 的非空过滤同口径）。
    *rt.current_config.write().unwrap() = Some(ts_and_vless_config(""));
    assert!(!rt.selected_exit_is_tailscale(), "空选中 → 假");
    *rt.current_config.write().unwrap() = Some(ts_and_vless_config("ghost"));
    assert!(!rt.selected_exit_is_tailscale(), "选中 id 不在册 → 假");
    // 无配置 → 假（`reconcile` 本就在下一步 return）。
    *rt.current_config.write().unwrap() = None;
    assert!(!rt.selected_exit_is_tailscale(), "无 current_config → 假");
}

/// 矩阵第 1 行：eligible + `NeedsLogin` → PUT direct、置 flag、emit(true, 出口名)。
///
/// **变异锁**：闸改成无条件 `return` ⇒ 无 PUT、无 emit ⇒ 转红。
#[tokio::test]
async fn reconcile_engages_when_ts_exit_needs_login() {
    let tags = BTreeMap::from([("ts1".to_string(), "组网出口".to_string())]);
    let (rt, _dir, sink, _i, _r, fb) =
        reassert_runtime(&ts_and_vless_config("ts1"), tags, BTreeMap::new());
    seed_backend_state(&rt, "ts1", "NeedsLogin");
    rt.reconcile_login_fallback().await;
    assert_eq!(
        sink.calls(),
        vec![("proxy-selector".to_string(), "direct".to_string())],
        "未登录的 TS 出口：默认路由必须让位 direct"
    );
    assert!(rt.login_fallback_engaged(), "PUT 成功 → 让位 flag 必置");
    assert_eq!(
        fb.lock().unwrap().as_slice(),
        &[(true, Some("组网出口".to_string()))]
    );
}

/// 矩阵第 2 行（同一选中出口）：已让位 + `Running` → PUT 回该出口 tag、清 flag、emit(false, 出口名)。
///
/// **变异锁**：把 `should_disengage` 里的 `Running` 腿删掉 ⇒ 无 PUT、flag 仍真 ⇒ 转红。
#[tokio::test]
async fn reconcile_disengages_when_ts_exit_becomes_running() {
    let tags = BTreeMap::from([("ts1".to_string(), "组网出口".to_string())]);
    let (rt, _dir, sink, _i, _r, fb) =
        reassert_runtime(&ts_and_vless_config("ts1"), tags, BTreeMap::new());
    rt.set_login_fallback(true, Some("ts1".to_string()));
    seed_backend_state(&rt, "ts1", "Running");
    rt.reconcile_login_fallback().await;
    assert_eq!(
        sink.calls(),
        vec![("proxy-selector".to_string(), "组网出口".to_string())],
        "隧道就绪 → 默认路由必须切回该出口"
    );
    assert!(!rt.login_fallback_engaged(), "撤销让位必须清 flag");
    assert_eq!(
        fb.lock().unwrap().as_slice(),
        &[(false, Some("组网出口".to_string()))]
    );
}

/// 🔴 **本项存在的唯一风险面**（矩阵第 5 行）：让位中途用户从 TS 出口**切走** → 本帧仍须 disengage。
///
/// 切走后 `eligible` 立刻为假，若早退闸只判「选中是不是 TS」，这一帧会被整个跳过 ⇒ flag 永不清、
/// 「已让位直连」横幅永不撤、selector 与 UI 长期脱节（陈旧态永不收敛）。这一格必须由谓词里的
/// `!engaged` 那一半接住。
///
/// **变异锁**：闸改成 `if !self.selected_exit_is_tailscale() { return; }`（丢掉 `!engaged`）⇒
/// flag 仍真、零 emit ⇒ 本条转红。
#[tokio::test]
async fn reconcile_disengages_after_switching_away_from_ts_exit() {
    let tags = BTreeMap::from([
        ("ts1".to_string(), "组网出口".to_string()),
        ("node-a".to_string(), "A".to_string()),
    ]);
    let (rt, _dir, sink, _i, _r, fb) =
        reassert_runtime(&ts_and_vless_config("node-a"), tags, BTreeMap::new());
    rt.set_login_fallback(true, Some("ts1".to_string()));
    // 选中已是 vless ⇒ 廉价判据为假；本帧全靠 `!engaged` 那一半才不会被早退闸吞掉。
    assert!(!rt.selected_exit_is_tailscale());
    rt.reconcile_login_fallback().await;
    assert!(
        !rt.login_fallback_engaged(),
        "切走出口后必须清让位 flag —— 否则 engaged 态永不收敛"
    );
    assert_eq!(
        fb.lock().unwrap().as_slice(),
        &[(false, None)],
        "必须撤 UI 让位横幅"
    );
    assert!(
        sink.calls().is_empty(),
        "切走腿只清 flag，不 PUT（selector 已由换节点那条路径落定，再 PUT 会打架）"
    );
}

/// 矩阵第 4 行：让位中 + 过渡态（`Starting` / 无帧）→ 维持现状，零 PUT 零 emit。
///
/// **变异锁**：把「其余过渡态维持」改成「非 NeedsLogin 即 disengage」⇒ 两段都转红。
#[tokio::test]
async fn reconcile_holds_through_transitional_backend_states() {
    let tags = BTreeMap::from([("ts1".to_string(), "组网出口".to_string())]);
    for state in ["Starting", "NoState"] {
        let (rt, _dir, sink, _i, _r, fb) =
            reassert_runtime(&ts_and_vless_config("ts1"), tags.clone(), BTreeMap::new());
        rt.set_login_fallback(true, Some("ts1".to_string()));
        seed_backend_state(&rt, "ts1", state);
        rt.reconcile_login_fallback().await;
        assert!(rt.login_fallback_engaged(), "{state}：过渡态不得翻转 flag");
        assert!(sink.calls().is_empty(), "{state}：过渡态不得 PUT");
        assert!(fb.lock().unwrap().is_empty(), "{state}：过渡态不得 emit");
    }
    // 无 STATUS 帧（核刚起 / 未选中 TS）同属过渡态。
    let (rt, _dir, sink, _i, _r, fb) =
        reassert_runtime(&ts_and_vless_config("ts1"), tags, BTreeMap::new());
    rt.set_login_fallback(true, Some("ts1".to_string()));
    rt.reconcile_login_fallback().await;
    assert!(rt.login_fallback_engaged(), "无帧：不得翻转 flag");
    assert!(sink.calls().is_empty());
    assert!(fb.lock().unwrap().is_empty());
}

/// 🟡 **源码型守卫**：早退闸必须是**两条腿的合取**，且必须排在整配置深拷贝**之前**。
///
/// 行为断言管不到这两件事：闸写弱（只剩 `!engaged`）行为完全等价、只是白付；闸挪到 clone 之后
/// 则一分钱都省不下来，而全部行为断言照绿。故这一条只能落在源码上。
///
/// **变异锁**：删任一合取项 / 把 `&&` 改 `||` ⇒ 首段 `find` 落空转红；把闸挪到 `let Some(raw) = …`
/// 之后 ⇒ 顺序断言转红。
#[test]
fn login_fallback_early_gate_is_a_conjunction_before_the_clone() {
    let body = method_body(
        &module_code("runtime/proxy"),
        "    pub(super) async fn reconcile_login_fallback_locked(",
    );
    let gate = body
        .find("if !self.login_fallback_engaged() && !self.selected_exit_is_tailscale() {")
        .expect(
            "早退闸不见了或谓词被改写 —— 只判『选中是不是 TS』会杀掉 disengage 腿，\
                 只判 `!engaged` 则省不掉非 TS 用户的每帧成本",
        );
    let clone_site = body
        .find("self.current_config.read().ok().and_then(|g| g.clone())")
        .expect("整配置深拷贝的锚点消失，本守卫已失去判据");
    assert!(
        gate < clone_site,
        "早退闸必须排在整配置深拷贝之前，否则跳过的是白工之后的那一段，一分钱不省"
    );
}
