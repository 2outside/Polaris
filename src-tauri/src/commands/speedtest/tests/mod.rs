use super::*;
// 生产路径不直接用这个常量（终态事件由 `runtime::speedtest::emit_speed_test_done` 单点发），
// 本模块只在门里按名字筛事件流，故只在测试作用域引入。
use crate::events::channel::EVENT_SPEED_TEST_DONE;
use crate::test_support::crate_code;

fn ids(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_string()).collect()
}

// ══════════════════════════════════════════════════════════════════════════
// plan_speed_test：本波裁定。每条测都盯住「静默返回 + 前端卡死」这个根因的一个面。
// ══════════════════════════════════════════════════════════════════════════

/// 打断「直连 → NoActiveExit」（改成 Measure/落 skipped）→ 本测转红。
#[test]
fn direct_exit_has_nothing_to_measure() {
    let all = ids(&["a", "b"]);
    assert_eq!(
        plan_speed_test(DIRECT_SERVER_ID, None, &all),
        SpeedTestPlan::NoActiveExit
    );
}

/// 打断「空 active → NoActiveExit」→ 本测转红。空串曾与「有活跃节点」共用一条腿。
#[test]
fn empty_active_has_nothing_to_measure() {
    let all = ids(&["a"]);
    assert_eq!(plan_speed_test("", None, &all), SpeedTestPlan::NoActiveExit);
}

/// 请求集不含活跃节点 → ActiveNotRequested（**零可测**，command 据此返失败信封）。
/// 打断这条（错判成 Measure，或退回 `ok(empty_result())` 的静默腿）→ 本测转红。
/// 这正是原 P1「前端永久卡死」/ P2「单节点点了没反应」的共同根因位。
#[test]
fn active_outside_request_set_is_zero_measurable() {
    let all = ids(&["a", "b", "c"]);
    assert_eq!(
        plan_speed_test("a", Some(&ids(&["b", "c"])), &all),
        SpeedTestPlan::ActiveNotRequested { requested: 2 }
    );
}

/// 请求集含活跃节点 → 测它，其余**全部**如实进 skipped（→ notInPool）。
/// 打断 skipped 计算（漏填 / 填成空 vec）→ 本测转红：那等于回到「组内其余节点无声无息没测」。
#[test]
fn active_inside_request_set_measures_it_and_reports_rest_skipped() {
    let all = ids(&["a", "b", "c"]);
    assert_eq!(
        plan_speed_test("b", Some(&ids(&["a", "b", "c"])), &all),
        SpeedTestPlan::Measure {
            active: "b".to_string(),
            skipped: ids(&["a", "c"]),
        }
    );
}

/// 活跃节点**绝不**出现在 skipped 里（它是本波唯一真测的那个）。
/// 打断过滤条件（`!=` 写成 `==`，或整个 filter 删掉）→ 本测转红。
#[test]
fn active_never_lands_in_skipped() {
    let all = ids(&["a", "b"]);
    let SpeedTestPlan::Measure { skipped, .. } = plan_speed_test("a", None, &all) else {
        panic!("活跃节点在请求集内应走 Measure 腿");
    };
    assert!(!skipped.contains(&"a".to_string()));
    assert_eq!(skipped, ids(&["b"]));
}

/// `serverIds` 缺省 = 全部（Polaris 语义）→ 请求集取 `all`，skipped 取材面也是 `all`。
/// 打断 `requested.unwrap_or(all)`（缺省当成空集）→ 本测转红（会误判成 ActiveNotRequested）。
#[test]
fn none_request_set_means_all_servers() {
    let all = ids(&["a", "b", "c"]);
    assert_eq!(
        plan_speed_test("a", None, &all),
        SpeedTestPlan::Measure {
            active: "a".to_string(),
            skipped: ids(&["b", "c"]),
        }
    );
}

/// 单节点测速点**活跃**节点 → 可测且零缺席（P2 的正向面）。
#[test]
fn single_active_node_request_measures_with_no_skipped() {
    let all = ids(&["a", "b"]);
    assert_eq!(
        plan_speed_test("a", Some(&ids(&["a"])), &all),
        SpeedTestPlan::Measure {
            active: "a".to_string(),
            skipped: vec![],
        }
    );
}

/// 配置无节点且无活跃出口 → NoActiveExit（不 panic、不索引越界）。
#[test]
fn empty_config_is_no_active_exit() {
    assert_eq!(plan_speed_test("", None, &[]), SpeedTestPlan::NoActiveExit);
}

// ── all_server_ids ────────────────────────────────────────────────────────

/// 打断 id 抽取（漏 filter_map / 取错 key）→ 本测转红。
#[test]
fn all_server_ids_extracts_ids_in_order() {
    let cfg = json!({ "servers": [{ "id": "a" }, { "id": "b" }] });
    assert_eq!(all_server_ids(&cfg), ids(&["a", "b"]));
}

/// 缺 servers 字段 / 形态不对 → 空 vec（不 panic）。配置损坏不该把测速打成 panic。
#[test]
fn all_server_ids_tolerates_missing_or_malformed() {
    assert_eq!(all_server_ids(&json!({})), Vec::<String>::new());
    assert_eq!(
        all_server_ids(&json!({ "servers": "nope" })),
        Vec::<String>::new()
    );
    // 无 id 的条目跳过，不占位。
    assert_eq!(
        all_server_ids(&json!({ "servers": [{ "name": "x" }, { "id": "a" }] })),
        ids(&["a"])
    );
}

// ── 单飞闸（去重）────────────────────────────────────────────────────────────

/// 抢占后二次抢占被拒；释放后可再抢——去重的核心不变式。打断（compare_exchange 写反 / Drop 不复位）
/// → 本测转红：那等于「并发不拦」或「测一次后永久熄火」。本测用全局 static，仅本测触碰该 flag（其余
/// 测速测走 plan_speed_test/all_server_ids 纯函数，不碰 flag），无并行干扰。
#[test]
fn speed_test_guard_is_single_flight() {
    let g1 = SpeedTestGuard::acquire();
    assert!(g1.is_some(), "闸空应可抢占");
    assert!(
        SpeedTestGuard::acquire().is_none(),
        "已被占用应拒绝并发抢占"
    );
    drop(g1);
    let g2 = SpeedTestGuard::acquire();
    assert!(g2.is_some(), "释放后应可再次抢占");
    drop(g2);
}

// ══════════════════════════════════════════════════════════════════════════
// §15 探测池分波编排纯逻辑：partition_pool（分区）+ plan_waves（分波）。
// 真测量走真核=真机门；此处只钉分波/分区/槽绑定的确定性（变异转红面）。
// ══════════════════════════════════════════════════════════════════════════

fn tag_map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(id, tag)| ((*id).to_string(), (*tag).to_string()))
        .collect()
}

fn pairs(v: &[(&str, &str)]) -> Vec<(String, String)> {
    v.iter()
        .map(|(id, tag)| ((*id).to_string(), (*tag).to_string()))
        .collect()
}

// ── partition_pool ────────────────────────────────────────────────────────

/// 无 dirty / TS 预筛（两个注入集皆空）的分区快捷夹具——聚焦 hasTag 那条腿的既有断言。
fn partition_no_ts(requested: &[String], map: &BTreeMap<String, String>) -> PoolPartition {
    partition_pool(requested, map, &BTreeSet::new(), &BTreeSet::new())
}

/// 仅注入 TS 预筛集（dirty 空）——保持既有 TS 腿断言的原语义。
fn partition_ts_only(
    requested: &[String],
    map: &BTreeMap<String, String>,
    ts_pending: &BTreeSet<String>,
) -> PoolPartition {
    partition_pool(requested, map, &BTreeSet::new(), ts_pending)
}

fn id_set(v: &[&str]) -> BTreeSet<String> {
    v.iter().map(|s| (*s).to_string()).collect()
}

/// 在池节点带 tag、非池节点进 notInPool，**各自保序**。打断（分反 / 丢 tag）→ 本测转红。
#[test]
fn partition_splits_in_pool_and_not_in_pool_preserving_order() {
    let map = tag_map(&[("a", "HK 01"), ("c", "US 02")]);
    let p = partition_no_ts(&ids(&["a", "b", "c", "d"]), &map);
    assert_eq!(p.testable, pairs(&[("a", "HK 01"), ("c", "US 02")]));
    assert_eq!(p.not_in_pool, ids(&["b", "d"]));
    assert!(p.ts_not_ready.is_empty());
}

/// 请求节点全在池 → notInPool 空。打断（误判在池节点为缺席）→ 本测转红。
#[test]
fn partition_all_in_pool_has_empty_not_in_pool() {
    let map = tag_map(&[("a", "A"), ("b", "B")]);
    let p = partition_no_ts(&ids(&["a", "b"]), &map);
    assert_eq!(p.testable, pairs(&[("a", "A"), ("b", "B")]));
    assert!(p.not_in_pool.is_empty());
}

/// 请求节点全不在池（新增未重启）→ testable 空、全进 notInPool（command 据此返 CODE_NONE_IN_POOL）。
/// 打断（把缺席节点误当可测）→ 本测转红：那等于对没入核的节点伪造 -1。
#[test]
fn partition_none_in_pool_yields_empty_testable() {
    let map = tag_map(&[("x", "X")]);
    let p = partition_no_ts(&ids(&["a", "b"]), &map);
    assert!(p.testable.is_empty());
    assert_eq!(p.not_in_pool, ids(&["a", "b"]));
}

// ── 波前预筛第二腿：tsNotReady（上游 SpeedTestService.ts:692）────────────────
//
// 盯的是**比 -1 更有害的失真数值**：TS 未就绪时运行核已把该出口让位到直连，硬测会量到一个**直连**的
// 漂亮 RTT 并挂到这个连不通的节点名下 —— 用户照着假低延迟选它，比看到 -1 更糟。

/// 在池但 TS 未就绪 → 进 tsNotReady、**不进** testable（不 select / 不 measure / 不 report）。
///
/// **变异锁**：删掉 `ts_pending.contains` 整条腿 → 节点回到 testable、tsNotReady 空 → 两条断言全红；
/// 把该腿改成「仍测但也记进 tsNotReady」→ testable 断言转红（失真数值仍会被量出来）。
#[test]
fn partition_excludes_ts_not_ready_nodes_from_testable() {
    let map = tag_map(&[("a", "A"), ("ts1", "TS1"), ("b", "B")]);
    let p = partition_ts_only(&ids(&["a", "ts1", "b"]), &map, &id_set(&["ts1"]));
    assert_eq!(p.testable, pairs(&[("a", "A"), ("b", "B")]));
    assert_eq!(p.ts_not_ready, ids(&["ts1"]));
    assert!(p.not_in_pool.is_empty());
}

/// **两腿的优先级**：既未入池又 TS 未就绪 → 归 `notInPool`（对齐 上游 `:680` 先于 `:692` 的判定序）。
///
/// 为什么优先级是语义而非风格：用户看到「未纳入」的下一步是重启内核纳入，看到「未登录」的下一步是去
/// 登录 —— 对一个核里根本不存在的出口指引「去登录」是把人引向死路。
/// **变异锁**：把两条腿调序 → 该节点落进 tsNotReady → 转红。
#[test]
fn partition_not_in_pool_wins_over_ts_not_ready() {
    let map = tag_map(&[("a", "A")]); // ts1 不在池
    let p = partition_ts_only(&ids(&["a", "ts1"]), &map, &id_set(&["ts1"]));
    assert_eq!(p.not_in_pool, ids(&["ts1"]));
    assert!(p.ts_not_ready.is_empty(), "未入池优先，不得重复计入 TS 腿");
    assert_eq!(p.testable, pairs(&[("a", "A")]));
}

/// 请求集全是未就绪 TS 节点 → 零可测（command 据此返 CODE_TS_NOT_READY 失败信封防前端卡死）。
#[test]
fn partition_all_ts_not_ready_yields_empty_testable() {
    let map = tag_map(&[("ts1", "T1"), ("ts2", "T2")]);
    let p = partition_ts_only(&ids(&["ts1", "ts2"]), &map, &id_set(&["ts1", "ts2"]));
    assert!(p.testable.is_empty());
    assert_eq!(p.ts_not_ready, ids(&["ts1", "ts2"]));
}

// ── 波前预筛第三腿：dirty（已编辑未生效，上游 SpeedTestService.ts:688 + ProxyManager.ts:3446）──
//
// 盯的同样是**比 -1 更有害的失真数值**：用户改了地址/端口/凭据后没应用，运行核仍跑旧参数。硬测会量到
// **旧参数出口**的真实 RTT，挂在**新参数**的节点名下 —— 用户照着一个「已经不存在的配置」的延迟选节点。

/// 在池但已编辑未生效 → 进 dirty、**不进** testable（不 select / 不 measure / 不 report）。
///
/// **变异锁**：删掉 `dirty_pending.contains` 整条腿 → 节点回到 testable、dirty 空 → 两条断言全红；
/// 把该腿改成「仍测但也记进 dirty」→ testable 断言转红（失真数值仍会被量出来）。
#[test]
fn partition_excludes_dirty_nodes_from_testable() {
    let map = tag_map(&[("a", "A"), ("d1", "D1"), ("b", "B")]);
    let p = partition_pool(
        &ids(&["a", "d1", "b"]),
        &map,
        &id_set(&["d1"]),
        &BTreeSet::new(),
    );
    assert_eq!(p.testable, pairs(&[("a", "A"), ("b", "B")]));
    assert_eq!(p.dirty, ids(&["d1"]));
    assert!(p.not_in_pool.is_empty() && p.ts_not_ready.is_empty());
}

/// **腿序 ①>③**：既未入池又 dirty → 归 `notInPool`（对齐 上游 `:680` 先于 `:688`）。
/// **变异锁**：把 dirty 腿提到 hasTag 之前 → 该节点落进 dirty → 转红。
#[test]
fn partition_not_in_pool_wins_over_dirty() {
    let map = tag_map(&[("a", "A")]); // d1 不在池
    let p = partition_pool(&ids(&["a", "d1"]), &map, &id_set(&["d1"]), &BTreeSet::new());
    assert_eq!(p.not_in_pool, ids(&["d1"]));
    assert!(p.dirty.is_empty(), "未入池优先，不得重复计入 dirty 腿");
}

/// **腿序 ③>②**：既 dirty 又 TS 未就绪 → 归 `dirty`（对齐 上游 `:688` 先于 `:692`）。
///
/// 语义而非风格：应用更改会重起核，那份 TS 配置本身就换了 —— 此刻指引「去登录旧配置」是白做工。
/// **变异锁**：把 dirty 腿与 TS 腿调序 → 该节点落进 tsNotReady → 转红。
#[test]
fn partition_dirty_wins_over_ts_not_ready() {
    let map = tag_map(&[("ts1", "T1")]);
    let p = partition_pool(&ids(&["ts1"]), &map, &id_set(&["ts1"]), &id_set(&["ts1"]));
    assert_eq!(p.dirty, ids(&["ts1"]));
    assert!(p.ts_not_ready.is_empty(), "dirty 优先，不得重复计入 TS 腿");
    assert!(p.testable.is_empty());
}

/// 请求集全 dirty → 零可测（command 据此返 CODE_ALL_DIRTY 失败信封防前端卡死）。
#[test]
fn partition_all_dirty_yields_empty_testable() {
    let map = tag_map(&[("d1", "D1"), ("d2", "D2")]);
    let p = partition_pool(
        &ids(&["d1", "d2"]),
        &map,
        &id_set(&["d1", "d2"]),
        &BTreeSet::new(),
    );
    assert!(p.testable.is_empty());
    assert_eq!(p.dirty, ids(&["d1", "d2"]));
}

/// 贯通：dirty 节点不得进波（进了就会 select_outbound 热切 + 量出旧参数出口的值）。
/// **变异锁**：把 dirty 腿的 `continue` 改成落 testable → `scheduled` 多出 `d1` → 转红。
#[test]
fn partition_then_plan_waves_excludes_dirty_nodes() {
    let map = tag_map(&[("a", "A"), ("d1", "D1"), ("c", "C")]);
    let p = partition_pool(
        &ids(&["a", "d1", "c"]),
        &map,
        &id_set(&["d1"]),
        &BTreeSet::new(),
    );
    let waves = plan_waves(&p.testable, 16);
    let scheduled: Vec<String> = waves.iter().flatten().map(|a| a.node_id.clone()).collect();
    assert_eq!(
        scheduled,
        ids(&["a", "c"]),
        "已编辑未生效的节点不得进波：热切它量到的是旧参数出口的 RTT"
    );
}

// ── partition_dirty：dirty 判据本体（上游 MainCoreProbe.isDirty，ProxyManager.ts:3446-3450）──

fn fp_map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(id, fp)| ((*id).to_string(), (*fp).to_string()))
        .collect()
}

/// 指纹变了 → dirty；没变 → 不 dirty。这是判据的正反两面，误判任一侧都致命
/// （左侧漏 = 继续量旧参数出口的失真值；右侧误报 = 正常节点永远测不了）。
/// **变异锁**：把 `cur != snap` 写成 `==` → 两条断言互换、全红。
#[test]
fn dirty_when_fingerprint_differs_from_running_snapshot() {
    let snap = fp_map(&[("a", "fp-old"), ("b", "fp-b")]);
    let cur = fp_map(&[("a", "fp-new"), ("b", "fp-b")]);
    assert_eq!(
        partition_dirty(&ids(&["a", "b"]), &snap, &cur),
        id_set(&["a"]),
        "只有指纹真变了的那个算 dirty"
    );
}

/// **快照无此 id → 不 dirty**（新增未入核：那是 notInPool 那条腿的射程）。
/// **变异锁**：把第一条 `is_some_and` 松成「快照缺失也算 dirty」→ 转红：那会把「新增未重启」的节点
/// 指引到「应用更改」，与 notInPool 的「刷新订阅 / 重启核」两条修法互相打架。
#[test]
fn not_dirty_when_snapshot_lacks_the_node() {
    let snap = fp_map(&[("a", "fp-a")]);
    let cur = fp_map(&[("a", "fp-a"), ("newbie", "fp-n")]);
    assert!(partition_dirty(&ids(&["newbie"]), &snap, &cur).is_empty());
}

/// **当前配置无此 id → 不 dirty**（拿不到「新」一侧就没有比对基准 → 保守照旧）。
/// **变异锁**：把 `is_some_and` 改成 `is_none_or`（缺失当成「不等」）→ 转红。
#[test]
fn not_dirty_when_current_config_lacks_the_node() {
    let snap = fp_map(&[("gone", "fp-g")]);
    assert!(partition_dirty(&ids(&["gone"]), &snap, &BTreeMap::new()).is_empty());
}

/// 只筛**请求集内**的节点：配置里别的节点脏了不影响本波。
/// **变异锁**：把取材面从 `requested` 换成 `snapshot_fingerprints.keys()` → 转红。
#[test]
fn dirty_only_covers_requested_nodes() {
    let snap = fp_map(&[("a", "old"), ("z", "old")]);
    let cur = fp_map(&[("a", "new"), ("z", "new")]);
    assert_eq!(partition_dirty(&ids(&["a"]), &snap, &cur), id_set(&["a"]));
}

// ── current_server_fingerprints：dirty 判据的「新」一侧取材 ──────────────────────

/// 指纹公式必须与 `SwitchSnapshot` 侧**同源**（`server_fingerprint`），否则两侧永远不等 =「全员恒 dirty」
/// （一个节点都测不成）或永远相等 =「腿形同虚设」。此处直接以同一函数复算断言，钉住同源性。
///
/// **变异锁**：把 `current_server_fingerprints` 改成自拼一个公式（哪怕只少一个维度）→ 转红。
#[test]
fn current_fingerprints_use_the_same_formula_as_the_snapshot_side() {
    let cfg = json!({ "servers": [
        { "id": "a", "name": "A", "protocol": "vless", "address": "a.example", "port": 443,
          "uuid": "u-1", "network": "ws" },
    ]});
    let got = current_server_fingerprints(&cfg);
    let parsed: ServerConfig =
        serde_json::from_value(cfg["servers"][0].clone()).expect("夹具须能解析成 ServerConfig");
    assert_eq!(got.get("a"), Some(&server_fingerprint(&parsed)));
}

/// 改一个参与指纹的维度（端口）→ 指纹必变（否则 dirty 腿对该维度失明）。
#[test]
fn current_fingerprints_change_when_a_node_is_edited() {
    let before = json!({ "servers": [
        { "id": "a", "name": "A", "protocol": "vless", "address": "a.example", "port": 443, "uuid": "u-1" },
    ]});
    let after = json!({ "servers": [
        { "id": "a", "name": "A", "protocol": "vless", "address": "a.example", "port": 8443, "uuid": "u-1" },
    ]});
    assert_ne!(
        current_server_fingerprints(&before).get("a"),
        current_server_fingerprints(&after).get("a"),
        "改端口后指纹不变 ⇒ dirty 腿对「改端口」这类最常见的编辑完全失明"
    );
}

/// 缺 servers / 形态不对 / 单条解析失败 → 跳过该条，不 panic、不误筛其余。
/// **变异锁**：把 `filter_map` 的解析失败腿改成 `unwrap`/`expect` → 第三条断言 panic 转红。
#[test]
fn current_fingerprints_tolerate_missing_or_malformed() {
    assert!(current_server_fingerprints(&json!({})).is_empty());
    assert!(current_server_fingerprints(&json!({ "servers": "nope" })).is_empty());
    let mixed = json!({ "servers": [
        { "id": "broken", "protocol": 12345 },
        { "id": "a", "name": "A", "protocol": "vless", "address": "a.example", "port": 443, "uuid": "u-1" },
    ]});
    let got = current_server_fingerprints(&mixed);
    assert!(got.contains_key("a"), "坏条目不得把好条目一并拖掉");
}

// ── ts_node_ready：TS 登录就绪判据（上游 MainCoreProbe.tsNodeReady）────────────

fn ts_event(backend_state: &str, expired: bool) -> TailscaleStatusEvent {
    TailscaleStatusEvent {
        server_id: "ts1".to_string(),
        backend_state: backend_state.to_string(),
        logged_in: !expired,
        auth_url: None,
        tailscale_ips: vec![],
        expired,
        peers: vec![],
        details: Default::default(),
        // Taildrop 四位在本用例无关，取「无能力、无文件」的中性值；不给 Default 是刻意的：
        // 日后再加字段时，这些构造点必须重新被人看一眼，而不是被 `..Default::default()` 静默补齐。
        can_share_files: false,
        waiting_file_count: 0,
        receiving_file_count: 0,
        unread_file_count: 0,
    }
}

/// Running + 未过期 → 就绪（正常 TS 节点全程走这条；误判即所有 TS 节点永远测不了）。
#[test]
fn ts_ready_when_running_and_not_expired() {
    assert!(ts_node_ready(Some(&ts_event("Running", false))));
}

/// 非 Running（NeedsLogin / Starting / NoState）→ 不就绪。
/// **变异锁**：把判据放宽成「有帧即就绪」→ 三条全红。`Starting` 尤其关键：隧道还没通，
/// 核此刻仍让位直连，放行它测出来的就是直连 RTT。
#[test]
fn ts_not_ready_when_backend_state_is_not_running() {
    assert!(!ts_node_ready(Some(&ts_event("NeedsLogin", false))));
    assert!(!ts_node_ready(Some(&ts_event("Starting", false))));
    assert!(!ts_node_ready(Some(&ts_event("NoState", false))));
}

/// key 已过期 → 不就绪，**即便 backendState 仍是 Running**（过期后走死出口黑洞）。
/// **变异锁**：删掉 `!e.expired` → 转红。
#[test]
fn ts_not_ready_when_key_expired_even_if_running() {
    assert!(!ts_node_ready(Some(&ts_event("Running", true))));
}

/// **无末帧 → 不就绪**（核未起 / 首帧未到 / 停核已清）。这条同时是 Polaris 免掉 上游 `tailscaleStatusGen`
/// （M-4 跨代陈旧帧）那条腿的**依据**：`stop_inner`/崩溃腿均 `clear_ts_status`，restart 复用 `stop_inner`
/// ⇒ 重启后无帧 → 本函数返 false，与 M-4「跨代帧视为未就绪」的结论逐字相同。
/// **变异锁**：把 `None` 当就绪（`is_none_or` / `unwrap_or(true)`）→ 转红。
#[test]
fn ts_not_ready_when_no_status_frame() {
    assert!(!ts_node_ready(None));
}

// ── tailscale_server_ids / partition_ts_not_ready：预筛取材面 ──────────────────

/// 只挑协议 tailscale 的节点，大小写不敏感；非 TS 节点绝不入集。
/// **变异锁**：去掉 protocol 过滤 → 全部节点入集 → 断言转红（那会把整批非 TS 节点也拿去问 TS 就绪，
/// 而它们必然没有 TS 状态帧 ⇒ 一律判「未就绪」⇒ **整批节点全被筛光、一个都测不成**）。
#[test]
fn tailscale_server_ids_picks_only_tailscale_protocol() {
    let cfg = json!({ "servers": [
        { "id": "a", "protocol": "vless" },
        { "id": "ts1", "protocol": "tailscale" },
        { "id": "ts2", "protocol": "Tailscale" },
        { "id": "b" },
    ]});
    assert_eq!(tailscale_server_ids(&cfg), id_set(&["ts1", "ts2"]));
}

/// 缺 servers / 形态不对 → 空集（配置损坏不该把测速打成 panic，也不该误筛）。
#[test]
fn tailscale_server_ids_tolerates_missing_or_malformed() {
    assert!(tailscale_server_ids(&json!({})).is_empty());
    assert!(tailscale_server_ids(&json!({ "servers": "nope" })).is_empty());
}

/// 只对 TS 协议节点询问就绪；未就绪的才入集。
/// **变异锁**：删掉 `tailscale_ids.contains` 过滤 → 非 TS 的 `a`（ready 闭包对它返 false）也入集 → 转红。
#[test]
fn ts_pending_only_covers_unready_tailscale_nodes() {
    let requested = ids(&["a", "ts1", "ts2"]);
    let ts_ids = id_set(&["ts1", "ts2"]);
    let pending = partition_ts_not_ready(&requested, &ts_ids, &|id| id == "ts2");
    assert_eq!(pending, id_set(&["ts1"]), "ts2 已就绪、a 非 TS 节点");
}

/// 全部 TS 节点就绪 → 空集（预筛不得误伤正常路径）。
#[test]
fn ts_pending_empty_when_all_ready() {
    let pending = partition_ts_not_ready(&ids(&["ts1"]), &id_set(&["ts1"]), &|_| true);
    assert!(pending.is_empty());
}

/// 造 n 个「无帧」成因 —— 既有那批用例只关心**计数**如实报，成因用哪一种不影响判据。
/// 成因本身的分流由下面 `ts_not_ready_reason_*` 那组用例守。
fn ts_reasons(n: usize) -> Vec<TsNotReady> {
    vec![TsNotReady::NoFrame; n]
}

fn ts_ev(backend_state: &str, expired: bool) -> TailscaleStatusEvent {
    TailscaleStatusEvent {
        server_id: "ts1".to_string(),
        backend_state: backend_state.to_string(),
        logged_in: !expired,
        auth_url: None,
        tailscale_ips: vec![],
        expired,
        peers: vec![],
        details: Default::default(),
        // Taildrop 四位在本用例无关，取「无能力、无文件」的中性值；不给 Default 是刻意的：
        // 日后再加字段时，这些构造点必须重新被人看一眼，而不是被 `..Default::default()` 静默补齐。
        can_share_files: false,
        waiting_file_count: 0,
        receiving_file_count: 0,
        unread_file_count: 0,
    }
}

// ── 成因分流：把「未登录」和「已登录但隧道没通」分开 ──────────────────────────────

/// 🔴 **本轮缺陷的回归锁**：`Starting` 是「**已登录**、隧道还没通」，绝不能报成「未登录」。
///
/// 真机实证（2026-07-31）：管理后台 `Connected`、应用角标「已登录」，点测速却说「未登录」——
/// 因为角标是折叠值（`Running || Starting`），而本门要求严格 `Running`。用户照那句话反复登录，
/// 登多少次都没用。
///
/// **变异锁**：把 `TunnelNotUp` 支合并回 `NeedsLogin` → 本测转红。
#[test]
fn starting_is_logged_in_but_tunnel_not_up() {
    let r = ts_not_ready_reason(Some(&ts_ev("Starting", false)));
    assert_eq!(r, Some(TsNotReady::TunnelNotUp("Starting".to_string())));
    let phrase = r.unwrap().user_phrase();
    assert!(phrase.contains("已登录"), "必须说清它是登着的：{phrase}");
    assert!(
        phrase.contains("无需重新登录"),
        "必须止住「再登一次」的白做工：{phrase}"
    );
    assert!(!phrase.contains("尚未登录（"), "绝不能说成未登录：{phrase}");
}

/// 只有 `NeedsLogin` 才是真的「未登录」。
#[test]
fn needs_login_is_the_only_real_not_logged_in() {
    assert_eq!(
        ts_not_ready_reason(Some(&ts_ev("NeedsLogin", false))),
        Some(TsNotReady::NeedsLogin)
    );
}

/// key 过期优先于 backendState —— 过期时 backendState 完全可能仍报 `Running`，
/// 那时说「隧道未就绪」会把用户指到错误方向。
/// **变异锁**：把 `expired` 判据挪到 `Running` 之后 → 本测转红。
#[test]
fn expired_wins_over_running() {
    assert_eq!(
        ts_not_ready_reason(Some(&ts_ev("Running", true))),
        Some(TsNotReady::Expired)
    );
}

/// 无帧 ≠ 未登录（核未起 / 首帧未到 / 停核已清）。
#[test]
fn no_frame_is_not_reported_as_not_logged_in() {
    let r = ts_not_ready_reason(None);
    assert_eq!(r, Some(TsNotReady::NoFrame));
    assert!(!r.unwrap().user_phrase().contains("尚未登录（"));
}

/// Running + 未过期 → 就绪（正常路径不得被新分流误伤）。
#[test]
fn running_and_not_expired_is_ready() {
    assert_eq!(ts_not_ready_reason(Some(&ts_ev("Running", false))), None);
    assert!(ts_node_ready(Some(&ts_ev("Running", false))));
}

/// 混合成因**逐类报数**，不折叠成一个总数 —— 折叠回去就是本次缺陷本身。
/// **变异锁**：把 `ts_not_ready_phrase` 改成只报总数 → 本测转红。
#[test]
fn mixed_reasons_are_reported_per_class() {
    let phrase = ts_not_ready_phrase(&[
        TsNotReady::NeedsLogin,
        TsNotReady::TunnelNotUp("Starting".to_string()),
        TsNotReady::TunnelNotUp("Starting".to_string()),
    ]);
    assert!(phrase.contains("1 个尚未登录"), "{phrase}");
    assert!(phrase.contains("2 个已登录但隧道尚未就绪"), "{phrase}");
}

// ── zero_testable_envelope：零可测的 code 分流 ─────────────────────────────────

/// 纯 TS 未就绪 → CODE_TS_NOT_READY（指引「去登录」而非「去重启内核」）。
/// **变异锁**：把这条腿删掉退回单一 CODE_NONE_IN_POOL → 转红。
#[test]
fn zero_testable_pure_ts_uses_ts_code() {
    let (msg, code) = zero_testable_envelope(0, 0, &ts_reasons(2));
    assert_eq!(code, CODE_TS_NOT_READY);
    assert!(msg.contains('2'));
}

/// 纯未入池 → CODE_NONE_IN_POOL（既有语义不得被新腿改写）。
#[test]
fn zero_testable_pure_not_in_pool_keeps_legacy_code() {
    let (msg, code) = zero_testable_envelope(3, 0, &ts_reasons(0));
    assert_eq!(code, CODE_NONE_IN_POOL);
    assert!(msg.contains('3'));
    assert!(!msg.contains("Tailscale"), "无 TS 缺席时不得凭空提 TS");
    assert!(
        !msg.contains("已编辑"),
        "无 dirty 缺席时不得凭空提「已编辑未生效」"
    );
}

/// 两类并存 → 主码取「未入池」，但文案**两个数都报**。
/// **变异锁**：只报一半（丢掉 TS 计数）→ 转红：用户会以为「重启内核」能把 TS 那几个也带回来。
#[test]
fn zero_testable_mixed_reports_both_counts() {
    let (msg, code) = zero_testable_envelope(2, 0, &ts_reasons(5));
    assert_eq!(code, CODE_NONE_IN_POOL);
    assert!(msg.contains('2') && msg.contains('5'), "两类计数都要如实报");
}

/// **纯 dirty → CODE_ALL_DIRTY**（指引「应用更改」而非「重启内核纳入」/「去登录」）。
///
/// **变异锁**：删掉这条腿（让 dirty 落进 `CODE_NONE_IN_POOL` 的兜底）→ 转红：那会告诉用户
/// 「这些节点没纳入测速池」，而它们**明明在池里**，只是核跑的是旧参数 —— 用户会去重启内核（碰巧
/// 也管用）或去查订阅（白费），而不是点那个近在眼前的「立即应用」。
#[test]
fn zero_testable_pure_dirty_uses_dirty_code() {
    let (msg, code) = zero_testable_envelope(0, 4, &ts_reasons(0));
    assert_eq!(code, CODE_ALL_DIRTY);
    assert!(msg.contains('4'));
    assert!(msg.contains("应用更改"), "文案必须指向那个真正能修复的动作");
    assert!(!msg.contains("Tailscale"), "无 TS 缺席时不得凭空提 TS");
}

/// **三类并存 → 主码「未入池」，文案报满三个数**。
/// **变异锁**：任一类的计数被吞（只拼两段）→ 转红：漏报的那类用户永远不知道该去修。
#[test]
fn zero_testable_all_three_classes_report_every_count() {
    let (msg, code) = zero_testable_envelope(2, 3, &ts_reasons(5));
    assert_eq!(code, CODE_NONE_IN_POOL);
    assert!(
        msg.contains('2') && msg.contains('3') && msg.contains('5'),
        "三类计数都要如实报，得到：{msg}"
    );
}

/// **dirty + TS 并存（无未入池）→ 主码取 dirty**，文案两个数都报。
///
/// 优先级依据（非风格）：「应用更改」是一次批量动作，且它会重起核 —— 那批 TS 节点的配置本身也会换，
/// 此刻先把用户支去逐个登录旧配置是白做工。
/// **变异锁**：把两条腿的顺序对调 → 主码变 TS → 转红。
#[test]
fn zero_testable_dirty_outranks_ts_not_ready() {
    let (msg, code) = zero_testable_envelope(0, 1, &ts_reasons(7));
    assert_eq!(code, CODE_ALL_DIRTY);
    assert!(msg.contains('1') && msg.contains('7'), "两类计数都要如实报");
}

/// 退化态（请求集为空）→ 仍返失败信封（绝不 ok(空)：零进度事件会把前端测速按钮永久卡灰）。
#[test]
fn zero_testable_empty_request_still_fails_closed() {
    let (_, code) = zero_testable_envelope(0, 0, &ts_reasons(0));
    assert_eq!(code, CODE_NONE_IN_POOL);
}

// ── plan_waves ──────────────────────────────────────────────────────────────

/// N>K → ⌈N/K⌉ 波；每波 ≤K；槽序在每波内从 0 重数（跨波复用 K 槽）。
/// 打断分波（不切波 / slot 不重置 / 波数错）→ 本测转红。
#[test]
fn plan_waves_chunks_n_over_k_with_wave_local_slots() {
    // N=5, K=2 → ⌈5/2⌉=3 波：[a,b] [c,d] [e]。
    let testable = pairs(&[("a", "A"), ("b", "B"), ("c", "C"), ("d", "D"), ("e", "E")]);
    let waves = plan_waves(&testable, 2);
    assert_eq!(waves.len(), 3, "⌈5/2⌉=3 波");
    assert_eq!(waves[0].len(), 2);
    assert_eq!(waves[2].len(), 1, "末波仅剩 1 个");
    // 槽序波内从 0（跨波复用）：波0 [slot0=a, slot1=b]，波1 [slot0=c, slot1=d]，波2 [slot0=e]。
    assert_eq!(
        waves[0][0],
        SlotAssignment {
            slot: 0,
            node_id: "a".into(),
            tag: "A".into()
        }
    );
    assert_eq!(
        waves[0][1],
        SlotAssignment {
            slot: 1,
            node_id: "b".into(),
            tag: "B".into()
        }
    );
    assert_eq!(
        waves[1][0],
        SlotAssignment {
            slot: 0,
            node_id: "c".into(),
            tag: "C".into()
        }
    );
    assert_eq!(
        waves[2][0],
        SlotAssignment {
            slot: 0,
            node_id: "e".into(),
            tag: "E".into()
        }
    );
}

/// 边界 N==K → 恰 1 波、K 个槽（slot 0..K-1）。打断（多切一空波 / 少算）→ 本测转红。
#[test]
fn plan_waves_n_equals_k_is_single_wave() {
    let testable = pairs(&[("a", "A"), ("b", "B"), ("c", "C")]);
    let waves = plan_waves(&testable, 3);
    assert_eq!(waves.len(), 1);
    assert_eq!(waves[0].len(), 3);
    assert_eq!(waves[0][2].slot, 2);
}

/// 边界 N==0 → 零波（无节点可测）。打断（返一个空波致 command 误发空进度）→ 本测转红。
#[test]
fn plan_waves_empty_input_is_no_waves() {
    assert!(plan_waves(&[], 4).is_empty());
}

/// 边界 K==0（探测池回滚锚点）→ 零波（调用方走回退）。打断（K=0 时除零 panic / 造波）→ 本测转红。
#[test]
fn plan_waves_zero_k_is_no_waves() {
    let testable = pairs(&[("a", "A")]);
    assert!(plan_waves(&testable, 0).is_empty());
}

/// N<K → 单波、N 个槽（不补齐到 K）。打断（按 K 补空槽 → 对不存在的节点热切）→ 本测转红。
#[test]
fn plan_waves_n_less_than_k_single_partial_wave() {
    let testable = pairs(&[("a", "A"), ("b", "B")]);
    let waves = plan_waves(&testable, 16);
    assert_eq!(waves.len(), 1);
    assert_eq!(waves[0].len(), 2, "只排实到节点数，不补齐 K");
}

/// 分区→分波贯通：非池节点不进任何波（只有在池节点被排进槽）。
/// 打断（把 notInPool 也排进波去热切）→ 本测转红：那会对没入核的节点 select_outbound 抛错/串味。
#[test]
fn partition_then_plan_waves_excludes_not_in_pool_nodes() {
    let map = tag_map(&[("a", "A"), ("c", "C")]);
    let p = partition_no_ts(&ids(&["a", "b", "c"]), &map);
    assert_eq!(p.not_in_pool, ids(&["b"]));
    let waves = plan_waves(&p.testable, 16);
    let scheduled: Vec<String> = waves.iter().flatten().map(|a| a.node_id.clone()).collect();
    assert_eq!(scheduled, ids(&["a", "c"]), "只有在池节点进波，b 被排除");
}

/// 贯通：波前预筛的**两条腿**都不得把缺席节点排进波（排进去就会 select_outbound 热切 → 量出数值）。
/// **变异锁**：把 tsNotReady 腿的 `continue` 改成落 testable → `scheduled` 多出 `ts1` → 转红。
#[test]
fn partition_then_plan_waves_excludes_ts_not_ready_nodes() {
    let map = tag_map(&[("a", "A"), ("ts1", "T1"), ("c", "C")]);
    let p = partition_ts_only(&ids(&["a", "ts1", "c"]), &map, &id_set(&["ts1"]));
    let waves = plan_waves(&p.testable, 16);
    let scheduled: Vec<String> = waves.iter().flatten().map(|a| a.node_id.clone()).collect();
    assert_eq!(
        scheduled,
        ids(&["a", "c"]),
        "TS 未就绪节点不得进波：热切它会量到核让位后的直连 RTT"
    );
}

// ══════════════════════════════════════════════════════════════════════════
// 出口伴测门控 plan_warm_rtt_probe（FX-warmttfb）：仅「探测成功 + 核在跑 + 有效混合口 +
// 有非直连活跃出口」四者全真才 fire。每条测钉一个逃逸面（对应门变异转红）。真数值走真机门。
// ══════════════════════════════════════════════════════════════════════════

/// 四条件全真 → fire，返活跃 id（写 EVENT_SPEED_TEST_RESULT.serverId 的键）。
/// 打断任一门（返 None）→ 本测转红：那等于探测成功后徽标永不自动刷新（回到修复前缺陷）。
#[test]
fn warm_rtt_fires_when_all_gates_pass() {
    assert_eq!(
        plan_warm_rtt_probe(true, true, 7890, "hk1"),
        Some("hk1".to_string())
    );
}

/// 探测未探到出口 IP（proxy_probed=false）→ 不 fire。打断此门（无视 proxy_probed）→ 转红：
/// 那等于探测失败 / 直判无效也伴测 → 冷隧道虚高、误刷徽标。
#[test]
fn warm_rtt_skips_when_probe_failed() {
    assert_eq!(plan_warm_rtt_probe(false, true, 7890, "hk1"), None);
}

/// 核未运行 → 不 fire（无出站可测）。打断 running 门 → 转红。
#[test]
fn warm_rtt_skips_when_not_running() {
    assert_eq!(plan_warm_rtt_probe(true, false, 7890, "hk1"), None);
}

/// 混合端口无效（=0）→ 不 fire（伴测无口出网）。打断 mixed_port 门 → 转红。
#[test]
fn warm_rtt_skips_when_mixed_port_zero() {
    assert_eq!(plan_warm_rtt_probe(true, true, 0, "hk1"), None);
}

/// 活跃出口为直连哨兵 → 不 fire（直连无真实出站）。打断 direct 门 → 转红：那等于给直连伪造节点延迟。
#[test]
fn warm_rtt_skips_when_active_is_direct() {
    assert_eq!(
        plan_warm_rtt_probe(true, true, 7890, DIRECT_SERVER_ID),
        None
    );
}

/// 无活跃出口（空串）→ 不 fire。打断 empty 门 → 转红：那会拿空 id 广播、UI 收到无主延迟。
#[test]
fn warm_rtt_skips_when_active_empty() {
    assert_eq!(plan_warm_rtt_probe(true, true, 7890, ""), None);
}

// ══════════════════════════════════════════════════════════════════════════
// §15.11 让位（超代）中断：`is_superseded` 判据 + `drive_pool_waves` 三检查点。
//
// 盯的是**诚实性根基**：核跃迁/崩溃期间「没测成」绝不能写成 `-1`（那是「真实超时」的意思）。
// 未测节点必须**缺席**结果集，且本次 outcome 必须是 `interrupted`（前端据此保留旧值）。
// ══════════════════════════════════════════════════════════════════════════

/// 世代未变 + 核在跑 → 未超代（正常测速全程走这条，误判即全程丢结果）。
#[test]
fn not_superseded_when_generation_stable_and_running() {
    assert!(!is_superseded(7, 7, true));
}

/// 世代跃迁（start/stop/restart/regen）→ 超代。删掉这条腿 → 换节点/重启核后旧轮结果照写回。
#[test]
fn superseded_on_generation_change() {
    assert!(is_superseded(8, 7, true));
}

/// **核自发崩溃**：崩溃分支不 bump 世代（世代腿漏判），靠 `running=false` 兜住。
/// 删掉 `!running` 腿 → 崩溃窗口的在飞失败被记成「真实超时 -1」＝伪造数值。
#[test]
fn superseded_on_crash_even_when_generation_unchanged() {
    assert!(is_superseded(7, 7, false));
}

/// 测试夹具：按「第几次调用」脚本化超代信号（0=从不超代）。
fn superseded_at(trip: usize) -> impl Fn() -> bool {
    let calls = std::sync::atomic::AtomicUsize::new(0);
    move || {
        let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
        trip != 0 && n >= trip
    }
}

fn two_waves() -> Vec<Vec<SlotAssignment>> {
    // K=2 → ["a","b"] 第一波、["c"] 第二波。
    plan_waves(
        &[
            ("a".into(), "tag-a".into()),
            ("b".into(), "tag-b".into()),
            ("c".into(), "tag-c".into()),
        ],
        2,
    )
}

/// 全程未超代 → 全部节点有结果 + `completed`。这是「三道检查不得误伤正常路径」的基准。
#[tokio::test]
async fn drive_waves_completes_when_never_superseded() {
    let (results, outcome) = drive_pool_waves(
        &two_waves(),
        3,
        &superseded_at(0),
        |_, _| async { true },
        |_| async { Some(120_u32) },
        &mut |_, _| {},
        &[10000, 10001],
    )
    .await;

    assert_eq!(outcome, "completed");
    assert_eq!(results.len(), 3);
    assert_eq!(results["a"], json!(120));
    assert_eq!(results["c"], json!(120));
}

/// 未超代时的**真实**热切失败仍记 -1（不可测是真的）→ 检查点不得把它吞成缺席。
#[tokio::test]
async fn drive_waves_records_genuine_select_failure_as_minus_one() {
    let (results, outcome) = drive_pool_waves(
        &two_waves(),
        3,
        &superseded_at(0),
        |slot, _| async move { slot != 0 }, // 槽 0 热切失败
        |_| async { Some(120_u32) },
        &mut |_, _| {},
        &[10000, 10001],
    )
    .await;

    assert_eq!(outcome, "completed");
    assert_eq!(results["a"], json!(-1)); // 真实不可测
    assert_eq!(results["b"], json!(120));
}

/// 让位①（波首）：第 1 次调用即超代 → 一个节点都不测，`interrupted`。
#[tokio::test]
async fn drive_waves_interrupts_at_wave_head() {
    let (results, outcome) = drive_pool_waves(
        &two_waves(),
        3,
        &superseded_at(1),
        |_, _| async { true },
        |_| async { Some(120_u32) },
        &mut |_, _| {},
        &[10000, 10001],
    )
    .await;

    assert_eq!(outcome, "interrupted");
    assert!(results.is_empty(), "超代下未测节点必须缺席，绝不写假 -1");
}

/// 让位②（热切后）：第 2 次调用超代（= 第一波热切完那一刻）→ 本波作废。
/// **关键**：此时热切结果可能全是 false（stale tag），没有这道检查它们会被记成 `-1`。
#[tokio::test]
async fn drive_waves_interrupts_after_select_without_faking_minus_one() {
    let (results, outcome) = drive_pool_waves(
        &two_waves(),
        3,
        &superseded_at(2),
        |_, _| async { false }, // 超代导致的热切失败
        |_| async { Some(120_u32) },
        &mut |_, _| {},
        &[10000, 10001],
    )
    .await;

    assert_eq!(outcome, "interrupted");
    assert!(
        results.is_empty(),
        "超代所致的热切失败不是「真实不可测」，不得记 -1"
    );
}

/// 让位③（每节点测完）：第 3 次调用超代（= 第一波**第一个节点**量完那一刻）→ 丢弃在飞值。
/// 那些值量的是**新核/已死核**的出站，记账即污染。
#[tokio::test]
async fn drive_waves_discards_in_flight_measurements_after_transition() {
    let (results, outcome) = drive_pool_waves(
        &two_waves(),
        3,
        &superseded_at(3),
        |_, _| async { true },
        |_| async { Some(999_u32) }, // 跨代量出来的值
        &mut |_, _| {},
        &[10000, 10001],
    )
    .await;

    assert_eq!(outcome, "interrupted");
    assert!(results.is_empty(), "跨代在飞值必须丢弃，不得写入结果集");
}

/// 第一波正常、第二波波首超代 → 已测部分**保留**，未测部分缺席，outcome=interrupted。
/// 这条锁「部分结果照常返回」——中断不等于丢弃已经拿到的真值。
///
/// **trip 从 4 改到 5 的原因（不是放宽门槛）**：回填改成逐节点后，让位③从「整波一次」变成「每节点
/// 一次」。第一波 2 个节点 ⇒ 询问序列为 `波首 → 热切后 → 节点① → 节点② → 第二波波首`，命中点仍是
/// **第二波开测之前**，语义逐字不变。
#[tokio::test]
async fn drive_waves_keeps_measured_prefix_on_later_interruption() {
    let (results, outcome) = drive_pool_waves(
        &two_waves(),
        3,
        &superseded_at(5), // 第一波（波首+热切后+两节点）四次检查过后，第二波波首命中
        |_, _| async { true },
        |_| async { Some(120_u32) },
        &mut |_, _| {},
        &[10000, 10001],
    )
    .await;

    assert_eq!(outcome, "interrupted");
    assert_eq!(results.len(), 2, "第一波两节点应保留");
    assert!(results.contains_key("a") && results.contains_key("b"));
    assert!(!results.contains_key("c"), "第二波未测 → 缺席");
}

// ══════════════════════════════════════════════════════════════════════════
// 终态事件（`EVENT_SPEED_TEST_DONE`）：中断后可续测的全部后端依据。
//
// 为什么这几条必须在**驱动层**而不是 command 层：command 要 `AppHandle`，本机无从构造；
// 而驱动层的 `emit` 是注入的 ⇒ 载荷可逐字断言（真行为，不是源码扫描）。
// ══════════════════════════════════════════════════════════════════════════

/// 从事件流里取**唯一**那条终态事件的载荷（多于一条即当场失败——终态按定义只能有一个）。
fn sole_done_payload(events: &[(String, Value)]) -> Value {
    let done: Vec<&Value> = events
        .iter()
        .filter(|(ev, _)| ev == EVENT_SPEED_TEST_DONE)
        .map(|(_, p)| p)
        .collect();
    assert_eq!(
        done.len(),
        1,
        "一轮测速必须**恰好**发一条终态事件：{events:?}"
    );
    done[0].clone()
}

/// 🔴 **`pending` = 已裁定要测的集合 − 已出结果的集合**（不是空表，也不是全集）。
///
/// 场景与 `drive_waves_keeps_measured_prefix_on_later_interruption` 同构：第一波 a/b 测完，
/// 第二波波首超代 ⇒ c 没测。这一条是**中断后「继续」能不能续对**的全部依据。
///
/// **变异锁（覆盖 coordinator 点名的两个逃逸面）**：
///  - `pending` 恒返空表（`Vec::new()`）→ 第二条断言转红（前端会以为没什么可续的，续测功能整段哑火）；
///  - `pending` 恒返全集（不做 `results` 过滤）→ 同一条转红并点名 a/b（已测的会被白测一遍，
///    「续测」退化成「重测」，也就没有了存在价值）；
///  - `tested` 改成别的口径（如 `total`）→ 第三条转红。
#[tokio::test]
async fn done_event_pending_is_intended_minus_measured() {
    let mut events: Vec<(String, Value)> = Vec::new();
    let (results, outcome) = drive_pool_waves(
        &two_waves(),
        3,
        &superseded_at(5), // 同上：第二波波首命中
        |_, _| async { true },
        |_| async { Some(120_u32) },
        &mut |ev, payload| events.push((ev.to_string(), payload)),
        &[10000, 10001],
    )
    .await;

    assert_eq!(outcome, "interrupted");
    let done = sole_done_payload(&events);
    assert_eq!(done["outcome"], json!("interrupted"));
    assert_eq!(done["serverIds"], json!(["a", "b", "c"]));
    assert_eq!(
        done["pending"],
        json!(["c"]),
        "pending 必须恰好是「没出值的那些」：空表 = 续测哑火，全集 = 已测的白测一遍"
    );
    assert_eq!(done["tested"], json!(2), "tested = 已出值的节点数");
    assert_eq!(done["total"], json!(3), "total = 本轮已裁定要测的节点数");
    assert_eq!(results.len(), 2);
}

/// 🔴 正常跑完 ⇒ `pending` **空**（防上一条靠「pending 恒非空」平凡通过）。
///
/// 顺带钉住 `completed` 也发终态：前端的静默超时是**纯兜底**，正常路径的收口必须走事件。
/// **变异锁**：只在 interrupted 分支 emit（把薄壳里的调用挪进 `if outcome == "interrupted"`）→
/// `sole_done_payload` 断言「恰一条」转红。
#[tokio::test]
async fn done_event_on_a_completed_round_has_no_pending() {
    let mut events: Vec<(String, Value)> = Vec::new();
    let (_results, outcome) = drive_pool_waves(
        &two_waves(),
        3,
        &superseded_at(0),
        |_, _| async { true },
        |_| async { Some(120_u32) },
        &mut |ev, payload| events.push((ev.to_string(), payload)),
        &[10000, 10001],
    )
    .await;

    assert_eq!(outcome, "completed");
    let done = sole_done_payload(&events);
    assert_eq!(done["outcome"], json!("completed"));
    assert_eq!(done["serverIds"], json!(["a", "b", "c"]));
    assert_eq!(done["pending"], json!([]), "跑完了就没有待续的");
    assert_eq!(done["tested"], json!(3));
    assert_eq!(done["total"], json!(3));
}

/// 🔴 **真实测不通（-1）不算 pending**：它已经有结论了，续测只会再测出一个 -1。
///
/// 这条把「未测」与「测了但失败」分开 —— 正是本仓贯穿测速模块的那条诚实性根基在续测语义上的投影。
/// **变异锁**：把 `pending` 的判据从「不在 `results` 里」改成「`results` 里不是正数」→ 转红。
#[tokio::test]
async fn a_genuine_minus_one_is_not_pending() {
    let mut events: Vec<(String, Value)> = Vec::new();
    let (_results, outcome) = drive_pool_waves(
        &two_waves(),
        3,
        &superseded_at(0),
        |_, _| async { true },
        |port| async move {
            if port == 10000 {
                None // 真实超时 → -1
            } else {
                Some(120_u32)
            }
        },
        &mut |ev, payload| events.push((ev.to_string(), payload)),
        &[10000, 10001],
    )
    .await;

    assert_eq!(outcome, "completed");
    let done = sole_done_payload(&events);
    assert_eq!(
        done["pending"],
        json!([]),
        "测出 -1 的节点是「测了但失败」，不是「没测」——续测不该再碰它"
    );
    assert_eq!(done["tested"], json!(3), "-1 也算测过（tested 含它）");
}

/// 事件发射：每个落库节点恰好推一条 result + 一条 progress（前端流式回填/进度条的真值来源）。
#[tokio::test]
async fn drive_waves_emits_result_and_progress_per_node() {
    let mut events: Vec<String> = Vec::new();
    let (_results, outcome) = drive_pool_waves(
        &two_waves(),
        3,
        &superseded_at(0),
        |_, _| async { true },
        |_| async { Some(120_u32) },
        &mut |ev, _| events.push(ev.to_string()),
        &[10000, 10001],
    )
    .await;

    assert_eq!(outcome, "completed");
    assert_eq!(
        events
            .iter()
            .filter(|e| *e == EVENT_SPEED_TEST_RESULT)
            .count(),
        3
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| *e == EVENT_SPEED_TEST_PROGRESS)
            .count(),
        3
    );
}

/// 🔴 **逐节点回填**：先测完的节点必须在**同波其它节点还在飞**的时候就上屏。
///
/// 按波统一回填时，首个延迟数字要等整波最慢的那个 —— 一波里有一个死节点，屏幕就先空一个完整的
/// 测量超时，此后每波一跳。总耗时一点没变，主观耗时天差地别（差异分析 R3）。
///
/// **变异锁**：改回「JoinSet 全量 drain → 收集循环统一 emit」→ `emit:a` 落到 `b-measured` 之后 → 转红。
#[tokio::test]
async fn drive_waves_reports_each_node_as_soon_as_it_finishes() {
    let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let mlog = std::sync::Arc::clone(&log);
    let elog = std::sync::Arc::clone(&log);
    let (_results, outcome) = drive_pool_waves(
        &two_waves(),
        3,
        &superseded_at(0),
        |_, _| async { true },
        move |port| {
            let mlog = std::sync::Arc::clone(&mlog);
            async move {
                // 槽 1（节点 b）慢：它还没回来时，节点 a 的结果就必须已经推出去了。
                if port == 10001 {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    mlog.lock().unwrap().push("b-measured".to_string());
                }
                Some(120_u32)
            }
        },
        &mut |ev, payload| {
            if ev == EVENT_SPEED_TEST_RESULT {
                let id = payload["serverId"].as_str().unwrap().to_string();
                elog.lock().unwrap().push(format!("emit:{id}"));
            }
        },
        &[10000, 10001],
    )
    .await;

    assert_eq!(outcome, "completed");
    let log = log.lock().unwrap();
    let emit_a = log
        .iter()
        .position(|l| l == "emit:a")
        .expect("节点 a 必须回填");
    let b_done = log
        .iter()
        .position(|l| l == "b-measured")
        .expect("节点 b 必须测完");
    assert!(
        emit_a < b_done,
        "节点 a 的结果必须在同波的慢节点 b 回来之前就上屏（实际顺序：{log:?}）"
    );
}

/// 🔴 **进度计数恒单调**：`tested` 严格 1,2,…,N，`ok` 非降。
///
/// 前端 `NodesScreen` 靠 `tested >= total` 复位测速灰态 —— 计数一旦回退或跳号，要么按钮永久卡灰，
/// 要么进度条倒着走。逐节点回填后计数在 [`record_measured`] 里自增，本测钉住它。
///
/// **变异锁**：把 `tested` 改成按波/批内下标计算（或在 emit 之后才自增）→ 序列不再是 1,2,3 → 转红。
#[tokio::test]
async fn drive_waves_progress_counter_is_strictly_monotonic() {
    let mut tested_seq: Vec<i64> = Vec::new();
    let mut ok_seq: Vec<i64> = Vec::new();
    let (_results, outcome) = drive_pool_waves(
        &two_waves(),
        3,
        &superseded_at(0),
        |_, _| async { true }, // 全部热切成功
        |port| async move {
            if port == 10000 {
                None // 真实超时 → -1，不计入 ok
            } else {
                Some(120_u32)
            }
        },
        &mut |ev, payload| {
            if ev == EVENT_SPEED_TEST_PROGRESS {
                tested_seq.push(payload["tested"].as_i64().unwrap());
                ok_seq.push(payload["ok"].as_i64().unwrap());
            }
        },
        &[10000, 10001],
    )
    .await;

    assert_eq!(outcome, "completed");
    assert_eq!(tested_seq, vec![1, 2, 3], "tested 必须严格递增且不跳号");
    assert!(
        ok_seq.windows(2).all(|w| w[1] >= w[0]),
        "ok 必须非降：{ok_seq:?}"
    );
}

/// 🔴 **主核池路径必须保持波屏障**（这条与临时核腿的滑动窗口**刻意不同**，别顺手统一）。
///
/// 槽 ↔ 端口是 1:1 硬绑定：第 k 槽的 `probe-selector-k` 被重指到下一波的节点时，上一波占用该槽的
/// 测量**必须已经结束**，否则在飞的那次测量量到的是**新指向的节点**的出口 —— 数值挂在别人名下，
/// 比测不出来有害得多。故跨波之间是**正确性要求**的屏障，不是性能选择（上游 同样是波屏障，
/// `SpeedTestService.ts:709-776`）。
///
/// **变异锁**：把本函数也改成「维持 K 在飞、回来一个补一个」的滑动窗口 → 第二波的 `sel:tag-c` 会在
/// 第一波慢节点还在测的时候发出 → 转红。
#[tokio::test]
async fn drive_waves_never_repoints_a_slot_while_that_wave_is_still_measuring() {
    let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let slog = std::sync::Arc::clone(&log);
    let mlog = std::sync::Arc::clone(&log);
    let (_results, outcome) = drive_pool_waves(
        &two_waves(),
        3,
        &superseded_at(0),
        move |_, tag: String| {
            let slog = std::sync::Arc::clone(&slog);
            async move {
                slog.lock().unwrap().push(format!("sel:{tag}"));
                true
            }
        },
        move |port| {
            let mlog = std::sync::Arc::clone(&mlog);
            async move {
                // 槽 0 快、槽 1 慢：滑动窗口会在槽 0 空出来的那一刻就重指它。
                tokio::time::sleep(Duration::from_millis(if port == 10000 { 20 } else { 200 }))
                    .await;
                mlog.lock().unwrap().push(format!("m-end:{port}"));
                Some(120_u32)
            }
        },
        &mut |_, _| {},
        &[10000, 10001],
    )
    .await;

    assert_eq!(outcome, "completed");
    let log = log.lock().unwrap();
    let sel_c = log
        .iter()
        .position(|l| l == "sel:tag-c")
        .expect("第二波必须热切");
    for port in [10000, 10001] {
        let end = log
            .iter()
            .position(|l| *l == format!("m-end:{port}"))
            .unwrap_or_else(|| panic!("端口 {port} 必须测完"));
        assert!(
            end < sel_c,
            "第一波端口 {port} 的测量必须在第二波热切之前结束（实际顺序：{log:?}）"
        );
    }
}

// ══════════════════════════════════════════════════════════════════════════
// 单节点计时结构：**两段独立预算**
//   ① 冷建链 `SPEED_TEST_COLD_TIMEOUT_MS`：CONNECT + TLS + GET1
//   ② 复用请求 `SPEED_TEST_REUSE_TIMEOUT_MS`：GET2（= 上报的 measured）
//   + 首段超时**绝不发第二次**。
//
// 隧道 I/O 经 `WarmTunnel` 注入 ⇒ 用假时钟（`start_paused`）验结构事实，不碰任何 socket。
// （真 socket 与假时钟不能共存：真 I/O 挂起时 tokio 会自动推进时钟。CONNECT 报文形态 / 只量第二次 /
//  非 2xx / 超时关 socket 的**线级**门在 `runtime::speedtest_tunnel` 的回环 mock 代理上。）
//
// ⚠️ 本节一切耗时断言都用 `tokio::time::Instant`（模块顶部 `use tokio::time::Instant`）。
//    `std::time::Instant` 不受假时钟影响，在 `start_paused` 下恒 0ms ⇒ 断言恒真 = 假门。
// ══════════════════════════════════════════════════════════════════════════

/// 每次 `get()` 睡 `steps[i]` 再返回 `Some(true)` 的假隧道。
///
/// `seen`（可选）把 `get()` 的调用次数暴露到函数外 —— 「首段超时后还发不发第二次」只能这么观测：
/// 隧道本身已被 `measure_warm_ttfb` move 走，测试拿不回它内部的 `calls`。
struct FakeTunnel {
    steps: Vec<Duration>,
    calls: usize,
    seen: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
}

impl FakeTunnel {
    fn new(secs: &[u64]) -> Self {
        Self {
            steps: secs.iter().map(|s| Duration::from_secs(*s)).collect(),
            calls: 0,
            seen: None,
        }
    }

    /// 同 [`FakeTunnel::new`]，但把每次 `get()` 记进外部计数器。
    fn counted(secs: &[u64], seen: &std::sync::Arc<std::sync::atomic::AtomicUsize>) -> Self {
        let mut t = Self::new(secs);
        t.seen = Some(std::sync::Arc::clone(seen));
        t
    }
}

impl WarmTunnel for FakeTunnel {
    fn get(&mut self) -> impl std::future::Future<Output = Option<bool>> + Send {
        let d = self
            .steps
            .get(self.calls)
            .copied()
            .unwrap_or(Duration::ZERO);
        self.calls += 1;
        if let Some(seen) = &self.seen {
            seen.fetch_add(1, Ordering::Relaxed);
        }
        async move {
            tokio::time::sleep(d).await;
            Some(true)
        }
    }
}

/// 生产常量装配（每条计时门都走它 ⇒ 常量改了、门跟着改，不会两处各写一个数）。
fn budgets() -> (Duration, Duration) {
    (
        Duration::from_millis(SPEED_TEST_COLD_TIMEOUT_MS),
        Duration::from_millis(SPEED_TEST_REUSE_TIMEOUT_MS),
    )
}

/// 立刻建成、每次 `get()` 都返回固定值的假隧道（非 2xx / 传输错两条腿用）。
struct ConstTunnel(Option<bool>);

impl WarmTunnel for ConstTunnel {
    fn get(&mut self) -> impl std::future::Future<Output = Option<bool>> + Send {
        let v = self.0;
        async move { v }
    }
}

/// 🔴 **两段各有各的预算**（本条**取代**了旧的 `warm_and_measured_share_one_total_timeout`）。
///
/// # 为什么那条旧门必须被改写，而不是「悄悄放宽」
///
/// 旧门钉的是「**一个**计时器包住 CONNECT+TLS+GET1+GET2 全程」这个结构事实，本次改动（陈先生
/// 2026-07-31 裁定的分阶段 6s/4s）**就是要推翻它**，故它必然失效 —— 留着它等于让改动过不了自己的门，
/// 删掉不说等于放宽。改写成本条：钉住**新的**结构事实（两段独立），并把「为什么这不是回到
/// 2026-07-31 上午刚修掉的『两个等长计时器』那个病」的判据写在 [`SPEED_TEST_COLD_TIMEOUT_MS`] 文档里
/// —— 那个病的封顶项是**不可达节点翻倍**，本次由 `a_cold_phase_timeout_never_sends_the_second_get`
/// 直接钉死「不可达节点仍是 6s」，两条合起来才是完整替代。
///
/// 判据：GET1 5s（在 6s 冷预算内）+ GET2 3s（在 4s 复用预算内）= 合计 8s。
/// **变异锁**：合回一个 6s 总预算（或任何 < 8s 的单一预算）→ 8s 超预算 → 拿到 `None` → 转红。
#[tokio::test(start_paused = true)]
async fn cold_and_reuse_phases_have_independent_budgets() {
    let (cold, reuse) = budgets();
    let out = measure_warm_ttfb(cold, reuse, async { Some(FakeTunnel::new(&[5, 3])) }).await;
    assert!(
        out.is_some(),
        "GET1 5s（≤冷 6s）+ GET2 3s（≤复用 4s）= 合计 8s：两段各自都不超预算 → 必须出值。\
             拿到 None 说明两段又被合成了一个总预算"
    );
}

/// 🔴 **第二段有它自己、且更小的预算**（防「第二段没预算」与「第二段用了冷预算」两个变异）。
///
/// GET1 1s（冷段轻松通过）+ GET2 5s：5s > 复用预算 4s ⇒ 必须判超时。
/// **变异锁**：
///  - 第二段不套 `timeout` → 出值 → 转红；
///  - 第二段套的是 `cold`（6s）而不是 `reuse`（4s）→ 出值 → 转红。
#[tokio::test(start_paused = true)]
async fn the_reuse_phase_has_its_own_smaller_budget() {
    let (cold, reuse) = budgets();
    let out = measure_warm_ttfb(cold, reuse, async { Some(FakeTunnel::new(&[1, 5])) }).await;
    assert_eq!(
        out, None,
        "GET2 5s 超出复用预算 4s → 必须判超时（拿到值说明第二段没有自己的预算，或用了冷段那份 6s）"
    );
}

/// 🔴🔴 **首段超时 ⇒ 立即返回，绝不发第二次**（陈先生 2026-07-31 点名的那条）。
///
/// 三条断言各钉一个面，缺一不可：
///  1. 结果是 `None`（首段超时 = 判超时）；
///  2. `get()` **只被调用过一次** —— 这条才是「不再进行资源浪费」的直接证据；
///  3. 整体耗时 ≈ 冷预算 6s，而**不是** 6+4=10s —— 这条钉死「不可达节点的耗时没有因分段而变长」，
///     也就是 2026-07-31 上午修掉的「两个等长计时器让不可达节点翻倍」那个病**没有**复发。
///
/// **变异锁**：把首段的 `?` 改成「超时后仍继续走第二段」（例如先无预算建隧道再分别计时）→
/// 调用次数变 2、耗时变 10s → 第 2、3 条断言转红。
#[tokio::test(start_paused = true)]
async fn a_cold_phase_timeout_never_sends_the_second_get() {
    let (cold, reuse) = budgets();
    let seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let t0 = Instant::now(); // tokio 的 Instant：假时钟下才会跟着推进
    let out = {
        let seen = std::sync::Arc::clone(&seen);
        measure_warm_ttfb(cold, reuse, async move {
            // GET1 睡 7s > 冷预算 6s ⇒ 冷段超时。
            Some(FakeTunnel::counted(&[7, 1], &seen))
        })
        .await
    };
    let spent = t0.elapsed();

    assert_eq!(out, None, "冷建链超时 → 必须判超时");
    assert_eq!(
        seen.load(Ordering::Relaxed),
        1,
        "冷段超时后**绝不允许**再发第二次 GET（实测发了 {} 次）",
        seen.load(Ordering::Relaxed)
    );
    assert!(
        spent < Duration::from_millis(SPEED_TEST_COLD_TIMEOUT_MS + 500),
        "不可达节点的耗时必须恒为冷预算 6s，不是 6+4=10s（实测 {spent:?}）—— \
             超了就说明首段超时后还去付了第二段那份钱"
    );
}

/// 🔴 **建隧道花的是冷段预算**（CONNECT + TLS 不得在计时器之外）。
///
/// 本条**取代**旧的 `opening_the_tunnel_spends_the_same_total_budget`：旧门里的「同一份预算」指
/// 那个唯一的总预算，分段后该措辞已无所指；钉的结构事实（`open` 必须在计时器**内部**被 poll）不变，
/// 只是归属从「总预算」变成「冷段预算」—— 这正是边界划在 GET1 之后的直接推论。
///
/// 建隧道 5s + GET1 2s = 7s > 冷预算 6s ⇒ 必须判超时。
/// **变异锁**：把 `open.await` 挪到 `tokio::time::timeout(...)` **之外**（先建好再进计时器）→
/// 冷段只看到 2s → 本测拿到 `Some` → 转红。一个 CONNECT 挂死的节点届时能吃掉远超 6s 的时间。
#[tokio::test(start_paused = true)]
async fn opening_the_tunnel_spends_the_cold_budget() {
    let (cold, reuse) = budgets();
    let t0 = Instant::now();
    let out = measure_warm_ttfb(cold, reuse, async {
        tokio::time::sleep(Duration::from_secs(5)).await;
        Some(FakeTunnel::new(&[2, 1]))
    })
    .await;
    assert_eq!(
        out, None,
        "建隧道 5s + GET1 2s 超出冷预算 6s → 必须判超时（建隧道不得在计时器之外）"
    );
    assert!(
        t0.elapsed() < Duration::from_millis(SPEED_TEST_COLD_TIMEOUT_MS + 500),
        "同样必须在冷预算处截断，不得顺延到第二段"
    );
}

/// 两段预算**之内**的建隧道 + 两次 GET 照常出值 —— 防上面三条靠「一律超时」平凡通过。
#[tokio::test(start_paused = true)]
async fn two_gets_within_both_budgets_still_yield_a_value() {
    let (cold, reuse) = budgets();
    let out = measure_warm_ttfb(cold, reuse, async { Some(FakeTunnel::new(&[3, 3])) }).await;
    assert!(out.is_some(), "GET1 3s（≤6s）+ GET2 3s（≤4s）→ 必须出值");
}

/// 🔴 **计的是第二次 GET，不是第一次**（假时钟版；线级版见 `speedtest_tunnel` 的 mock 代理门）。
///
/// warm 3s + measured 1s ⇒ 测得值必须是 1000ms 左右，而不是 3000（量了第一次）或 4000（量了两次之和）。
/// **变异锁**：把 `t0` 挪到第一次 `get()` **之前** → 拿到 4000 → 转红。
///
/// 分阶段改造后本条**保持绿**（陈先生要求的不变式）：3s 在冷段 6s 内、1s 在复用段 4s 内，
/// 且 `t0` 仍紧贴第二段开头 —— 上报值恒等于第二次 GET 的 TTFB，与分不分段无关。
#[tokio::test(start_paused = true)]
async fn measured_value_is_the_second_get_alone() {
    let (cold, reuse) = budgets();
    let out = measure_warm_ttfb(cold, reuse, async { Some(FakeTunnel::new(&[3, 1])) })
        .await
        .expect("3s + 1s 在两段预算内，应出值");
    assert!(
        (900..1100).contains(&out),
        "measured 只该量第二次 GET（≈1000ms），实得 {out}ms —— \
             ≈3000 = 量了第一次，≈4000 = 把暖身也算进去了"
    );
}

/// 非 2xx 与传输错都不计（`is_success` 语义随重构原样保留，绝不伪造数值）。
#[tokio::test]
async fn non_success_status_and_transport_error_are_not_counted() {
    let (cold, reuse) = budgets();
    assert_eq!(
        measure_warm_ttfb(cold, reuse, async { Some(ConstTunnel(Some(false))) }).await,
        None,
        "非 2xx 不计"
    );
    assert_eq!(
        measure_warm_ttfb(cold, reuse, async { Some(ConstTunnel(None)) }).await,
        None,
        "传输错不计"
    );
}

/// 隧道**建不起来**（CONNECT 失败 / 非 2xx / TLS 握手失败）→ `None`，绝不伪造数值。
#[tokio::test]
async fn a_tunnel_that_never_opens_yields_none() {
    let (cold, reuse) = budgets();
    assert_eq!(
        measure_warm_ttfb(cold, reuse, async { Option::<ConstTunnel>::None }).await,
        None
    );
}

/// 🔵 **调用点守卫**：测量腿必须走 CONNECT 隧道，不得退回「经 reqwest 本机代理发 absolute-form」。
///
/// # 为什么源码扫描这一条也要有
///
/// `speedtest_tunnel` 的 mock 代理门验的是 [`open_tunnel`] **本身**说 CONNECT。但把
/// `measure_via_local_proxy` 整个换回 `HttpRuntime::via_local_proxy(...).client().get(url)`
/// —— 那批门一条都不会红（它们测的是另一个函数），而生产路径已经整条退回改前的形态。
/// 这正是本仓「假绿」的经典形态（测方法体 ≠ 测接线）。
///
/// 牙：把函数体换成 reqwest 经代理请求 → 前两条断言转红；把 `open_tunnel` 换成别的建连方式 →
/// 第三条转红。
#[test]
fn measurement_leg_goes_through_a_connect_tunnel() {
    let body = crate::commands::guard_scan::top_level_fn_body(
        &crate_code("commands/speedtest.rs"),
        "async fn measure_via_local_proxy(",
    );
    assert!(
        !body.contains("via_local_proxy(") || !body.contains("HttpRuntime"),
        "测量腿不得退回 `HttpRuntime::via_local_proxy`（那是经代理发 absolute-form 的形态，\
             两次 GET 不复用上游连接 ⇒ measured 每次都含完整节点握手）"
    );
    assert!(
        !body.contains(".send()") && !body.contains("client"),
        "测量腿不得经 reqwest client 请求（同上）"
    );
    assert!(
        body.contains("open_tunnel(proxy_port, &target)"),
        "测量腿必须经 CONNECT 隧道（`open_tunnel`）建连"
    );
    assert!(
        body.contains("SPEED_TEST_COLD_TIMEOUT_MS") && body.contains("SPEED_TEST_REUSE_TIMEOUT_MS"),
        "两段预算必须仍由本层单点注入（挪走 = 计时结构无人守；只剩一个 = 分阶段被合回单一计时器）"
    );
}

/// 🔴 **线级接线门**：把**生产入口** [`measure_via_local_proxy`] 真跑一遍，断言它在线上说的是
/// CONNECT + origin-form GET。
///
/// 与上面那条源码扫描互补，缺一不可：
/// - 只有源码扫描 → 把 `open_tunnel` 的实现换成 absolute-form 也照样绿（扫的是调用名，不是线上字节）；
/// - 只有 `speedtest_tunnel` 里那批 mock 门 → 把 `measure_via_local_proxy` 整个换回 reqwest 经代理
///   也照样绿（那批测的是 `open_tunnel` 这个函数，不是生产调用点）。
///
/// 对端是**回环 mock 代理**（`127.0.0.1` 随机端口），不触碰宿主网络、不涉及真核/真节点/真目标。
#[tokio::test]
async fn production_measurement_entrypoint_speaks_connect_on_the_wire() {
    use crate::runtime::speedtest_tunnel::mock_proxy::{
        spawn_mock_proxy, GetReply, Script, OK_204,
    };

    let (port, observed) = spawn_mock_proxy(Script {
        connect_reply: Some(OK_204),
        gets: vec![GetReply::ok(), GetReply::ok()],
    })
    .await;

    let out = measure_via_local_proxy(port, DEFAULT_SPEED_TEST_URL).await;
    assert!(out.is_some(), "mock 代理按脚本回 204，生产入口应出值");

    let lines = observed.lock().unwrap().request_lines.clone();
    assert_eq!(
        lines.first().map(String::as_str),
        Some("CONNECT www.gstatic.com:80 HTTP/1.1"),
        "生产测量腿的首个请求行必须是带显式端口的 CONNECT —— \
             退回 absolute-form（`GET http://... HTTP/1.1`）即转红。实得 {lines:?}"
    );
    assert_eq!(
        lines.len(),
        3,
        "CONNECT + 两次 GET（丢第一次、量第二次），实得 {lines:?}"
    );
    for line in &lines[1..] {
        assert_eq!(
            line, "GET /generate_204 HTTP/1.1",
            "隧道内必须是 origin-form，实得 {line:?}"
        );
    }
}

/// 🔴 **默认端点必须解析得出隧道目标**（[`measure_via_local_proxy`] 的 `?` 兜底不可达的前提）。
///
/// 对齐 上游 用 `!` 断言 `parseSpeedTestUrl(DEFAULT_SPEED_TEST_URL)` 非空、由单测护栏的处置。
/// 牙：把 [`DEFAULT_SPEED_TEST_URL`] 改成解析不出 host 的值 → 转红（否则它会静默让**每个**节点
/// 都记一个 -1 假失败：原因在常量，锅记在节点头上）。
#[test]
fn the_default_speed_test_endpoint_resolves_to_a_tunnel_target() {
    let t =
        SpeedTestTarget::parse(DEFAULT_SPEED_TEST_URL).expect("默认测速端点必须能解析成隧道目标");
    assert_eq!(
        t,
        SpeedTestTarget::parse("http://www.gstatic.com/generate_204").unwrap()
    );
}

/// 用户自配 URL 的取舍：可解析则用它，否则回落默认（**不因配置坏而给节点记假 -1**）。
#[test]
fn user_speed_test_url_falls_back_to_default_when_unusable() {
    let pick = |v: Value| resolve_speed_test_url(&v);
    assert_eq!(
        pick(json!({ "speedTestUrl": "https://my.endpoint:8443/ping?t=1" })),
        "https://my.endpoint:8443/ping?t=1"
    );
    for bad in ["", "http://", "socks5://1.2.3.4:1080", "garbage"] {
        assert_eq!(
            pick(json!({ "speedTestUrl": bad })),
            DEFAULT_SPEED_TEST_URL,
            "`{bad}` 解析不出隧道目标 → 必须回落默认端点"
        );
    }
    assert_eq!(pick(json!({})), DEFAULT_SPEED_TEST_URL, "未配置 → 默认端点");
}

// ── 回退腿（probe_pool_ports 为空）的让位覆盖 ──────────────────────────────────
//
// 此前本腿**零 `superseded()` 覆盖**：无 gen0 捕获、measure 前后无检查、outcome 硬编码 "completed"
// ⇒ 测量中途核重启/崩溃会把 -1（或经**新**出口测得的值）记在旧 selectedServerId 上 = 伪造数值，
// 与模块文档「绝不伪造数值」的承诺直接冲突。下列四条锁住修复后的语义。

/// 未超代 → 正常记账：结果落库 + 一条 result + 一条 progress + `completed`。
/// 这是「让位检查不得误伤正常路径」的基准（对齐池路径的同名基准测）。
#[tokio::test]
async fn fallback_completes_when_never_superseded() {
    let mut events: Vec<String> = Vec::new();
    let (results, outcome) = drive_fallback_measure(
        "srv-active",
        &superseded_at(0),
        || async { Some(88_u32) },
        &mut |ev, _| events.push(ev.to_string()),
    )
    .await;

    assert_eq!(outcome, "completed");
    assert_eq!(results["srv-active"], json!(88));
    assert_eq!(
        events
            .iter()
            .filter(|e| *e == EVENT_SPEED_TEST_RESULT)
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| *e == EVENT_SPEED_TEST_PROGRESS)
            .count(),
        1
    );
}

/// 未超代时的**真实**超时仍记 -1（测不通是真的）→ 让位检查不得把它吞成缺席。
///
/// 这条与下一条成对：把「真实 -1」与「超代缺席」钉成两种不同结局，正是本项修复的全部意义。
#[tokio::test]
async fn fallback_records_genuine_timeout_as_minus_one() {
    let (results, outcome) = drive_fallback_measure(
        "srv-active",
        &superseded_at(0),
        || async { None }, // 真实超时/传输错
        &mut |_, _| {},
    )
    .await;

    assert_eq!(outcome, "completed");
    assert_eq!(
        results["srv-active"],
        json!(-1),
        "真实不可测记 -1（非缺席）"
    );
}

/// **让位（测量后）**：测量在飞期间核跃迁/崩溃 → 该节点**缺席** + `interrupted`，
/// 且**不推任何事件**（推了就等于告诉前端「这个节点测出来是 -1」）。
///
/// **变异锁（逐条覆盖逃逸面）**：
///  - 删 `if superseded() { return ... }` 整段 → results 落 `-1`、outcome 变 completed → 三条断言全红；
///  - 只删 `return` 保留判断（continue 语义）→ 同上；
///  - 把 interrupted 腿改成「记 -1 但 outcome=interrupted」→ 「必须缺席」转红（伪造数值仍在）；
///  - 把 interrupted 腿改成「缺席但仍 emit result/progress」→ 「不得推逐节点事件」转红。
///
/// # 断言从「零事件」改成「零逐节点事件 + 恰一条终态事件」的理由
///
/// 本条原文是 `events.is_empty()`。终态事件（2026-07-31 B 批）落地后，**中断路径恰恰必须发一条**
/// —— 它就是为「中断了要立刻让前端知道」而存在的；原断言留着等于禁止本批的核心行为。
/// 但它守的那个诚实性根基不能松：**逐节点** result/progress 一条都不许有（推了就是谎报这个节点
/// 测出过 -1）。故改成按通道分别断言，并顺带把终态载荷一起钉死（缺席的那个必须进 `pending`）。
#[tokio::test]
async fn fallback_interrupts_and_omits_node_when_superseded_mid_measure() {
    let mut events: Vec<(String, Value)> = Vec::new();
    let (results, outcome) = drive_fallback_measure(
        "srv-active",
        &superseded_at(1), // 第 1 次询问（= measure 之后那次）即超代
        || async { Some(88_u32) },
        &mut |ev, payload| events.push((ev.to_string(), payload)),
    )
    .await;

    assert_eq!(
        outcome, "interrupted",
        "被核跃迁打断 → interrupted（前端据此保留旧值）"
    );
    assert!(
        !results.contains_key("srv-active"),
        "超代节点必须**缺席**：把新核/已死核测得的值记在旧 selectedServerId 上就是伪造数值"
    );
    assert!(results.is_empty());
    assert!(
        events
            .iter()
            .all(|(ev, _)| ev != EVENT_SPEED_TEST_RESULT && ev != EVENT_SPEED_TEST_PROGRESS),
        "超代轮不得推 result/progress —— 推了等于告诉前端这个节点有过一次真实测量：{events:?}"
    );
    let done: Vec<&Value> = events
        .iter()
        .filter(|(ev, _)| ev == EVENT_SPEED_TEST_DONE)
        .map(|(_, p)| p)
        .collect();
    assert_eq!(done.len(), 1, "中断也必须**恰好**发一条终态事件");
    assert_eq!(done[0]["outcome"], json!("interrupted"));
    assert_eq!(done[0]["serverIds"], json!(["srv-active"]));
    assert_eq!(
        done[0]["pending"],
        json!(["srv-active"]),
        "唯一没测成的那个必须进 pending（否则前端「继续」无从续起）"
    );
}

/// 超代 + 测量本身也失败 → 同样缺席，**不得**退化成「真实超时 -1」。
///
/// 这是最危险的假绿形态：崩溃窗口里测量必然失败，若无让位检查，`None → -1` 恰好「看起来很合理」，
/// 于是一个纯粹由核崩溃造成的失败被永久记成该节点的真实延迟。
#[tokio::test]
async fn fallback_superseded_failure_is_absent_not_minus_one() {
    let (results, outcome) = drive_fallback_measure(
        "srv-active",
        &superseded_at(1),
        || async { None },
        &mut |_, _| {},
    )
    .await;

    assert_eq!(outcome, "interrupted");
    assert!(
        !results.contains_key("srv-active"),
        "核崩溃窗口的失败 ≠ 真实超时：必须缺席，绝不记 -1"
    );
}

/// **调用点守卫**（射程补齐）：让位基准 `gen0` 必须在 **await 之前**捕获。
///
/// [`drive_fallback_measure`] 的让位语义由上面四条注入式测试盖住，但「命令层有没有把 gen0 在正确的
/// 时点取到」是**接线**问题：把 `gen0` 挪到 await 之后（或写成 `core_generation()` 与自己比），
/// 那四条测试**照样全绿** —— 因为它们注入的是现成的 `superseded` 闭包。这条补的就是那个缺口。
///
/// 牙：把 `let gen0 = ...` 挪到 `drive_fallback_measure(` 之后、**挪进 `superseded` 闭包体内**、
/// 或改成自己跟自己比 → 转红。
///
/// 🔴 第二种（挪进闭包）是本轮实测逮到的存活变异：那样 `let gen0` 文本上仍在测量调用之前，纯位置
/// 断言照样绿，而语义已变成「每次询问现取一次基准跟自己比」⇒ 世代腿恒假。故锚点必须带**函数体
/// 缩进**（4 空格；闭包体内是 8 空格），把判据从「文本先后」收紧成「词法作用域」。
#[test]
fn fallback_leg_captures_generation_before_awaiting_measurement() {
    let body = crate::commands::guard_scan::top_level_fn_body(
        &crate_code("commands/speedtest.rs"),
        "pub async fn server_speed_test(",
    );

    let gen0 = body
        .find("\n    let gen0 = proxy.core_generation();")
        .expect("回退腿必须在**函数体**捕获让位基准 gen0（否则测量中途核跃迁会被记成真实数值）");
    assert!(
        !body.contains("\n        let gen0 = proxy.core_generation();"),
        "gen0 出现在闭包体缩进上 ⇒ 基准是现取的，让位判据的世代腿形同虚设"
    );
    // 逐字负锚仍可绕（闭包体内写 `let gen0 = { proxy.core_generation() };` 等变体即遮蔽外层）。
    // 与临时核腿同款收紧：钉「函数体内 `let gen0` 只许一处」，遮蔽必须引入第二处绑定。
    assert_eq!(
        body.matches("let gen0").count(),
        1,
        "函数体内只许有**一处** `let gen0` 绑定：第二处（含非逐字变体）会遮蔽外层基准 ⇒ 世代腿恒假"
    );
    let drive = body
        .find("drive_fallback_measure(")
        .expect("回退腿必须经 drive_fallback_measure 收口（让位检查在其中）");
    assert!(
        gen0 < drive,
        "gen0 必须在 await（drive_fallback_measure）**之前**捕获：之后取等于跟自己比，让位判据恒假"
    );
    assert!(
        body.contains("is_superseded(proxy.core_generation(), gen0,"),
        "让位判据须以 gen0 为基准与**当前**世代比对，且共用 is_superseded（含崩溃腿 !running）"
    );
}

/// 🔵 **调用点守卫**：出口伴测的 `emit` 必须挡在出口 IP 世代复查**之后**。
///
/// # 为什么是源码扫描
///
/// [`spawn_warm_rtt_probe`] 要 `AppHandle` 才能调（本仓未引 `tauri::test`），且它 fire-and-forget
/// 地 spawn 出去 —— 单测既造不出入参，也接不到那条异步腿的 emit。而「复查在 emit 的哪一侧」是纯
/// 结构事实，正是本文件 `fallback_leg_captures_generation_before_awaiting_measurement` 同款范式。
///
/// # 缺陷长相
///
/// `active_id` 取自**开探时刻**的 config 快照，测量本身是秒级异步。中途起停 / 热切换掉出口后，
/// 此刻量到的 `latency` 属于**新**出口，写进 `active_id` 就是把新节点的 RTT 记到旧节点头上 ——
/// 而延迟徽标正是用户选节点的依据，记错比不记更糟。本批把伴测从「点一次才跑」改成「每次起停/
/// 热切都跑」后，这条路径的可达性显著上升。
///
/// 牙：删掉复查、把它挪到 `app.emit(` 之后、或只传半条判据（`(epoch, epoch)` / 把 `seq` 换成现场
/// 取值）→ 转红。
#[test]
fn warm_rtt_probe_rechecks_ipinfo_epoch_before_emitting() {
    let body = crate::commands::guard_scan::top_level_fn_body(
        &crate_code("commands/speedtest.rs"),
        "pub(crate) fn spawn_warm_rtt_probe(",
    );
    let recheck = body.find("ipinfo_probe_is_current(epoch, seq)").expect(
        "伴测 emit 前必须用**两条**入参判据复查（否则换节点后新出口的 RTT 会记到旧节点 id 上；\
                 只查世代则热切后那 4s——新腿已排程、尚未领号——复查恒真）",
    );
    let emit = body
        .find("app.emit(")
        .expect("伴测成功腿必须 emit，否则延迟徽标永不刷新");
    assert!(
        recheck < emit,
        "复查在 emit **之后** = 判据形同虚设：值已经发出去了，UI 已经把新出口的延迟挂在旧节点上"
    );
}

// ══════════════════════════════════════════════════════════════════════════
// 临时核腿的**取材面**（requested_server_configs）+ 接线守卫。
// 编排/隔离/让位的行为面在 `runtime::speedtest` 的注入式测试里，此处只钉命令层这一段。
// ══════════════════════════════════════════════════════════════════════════

fn cfg_with_servers() -> Value {
    json!({ "servers": [
        { "id": "a", "name": "A", "protocol": "vless", "address": "a.example", "port": 443, "uuid": "u-a" },
        { "id": "b", "name": "B", "protocol": "trojan", "address": "b.example", "port": 443, "password": "p-b" },
        { "id": "c", "name": "C", "protocol": "vless", "address": "c.example", "port": 443, "uuid": "u-c" },
    ]})
}

/// **按请求序取材**（不是按配置序）。临时核的「节点 ↔ 入站端口 ↔ 出站 tag」是三重逐位绑定，
/// 取材乱序 ⇒ 结果错位 ⇒ 量到的是**别人**的延迟。
///
/// **变异锁**：把实现改成「遍历 config.servers 过滤 requested」（= 按配置序）→ 转红。
#[test]
fn requested_servers_follow_request_order_not_config_order() {
    let got = requested_server_configs(&cfg_with_servers(), &ids(&["c", "a"]));
    assert_eq!(
        got.iter().map(|s| s.id.clone()).collect::<Vec<_>>(),
        ids(&["c", "a"])
    );
}

/// 请求了配置里没有的 id → 跳过（调用方计入缺席），不 panic、不占位。
/// **变异锁**：把 `filter_map` 换成「找不到就塞个默认 ServerConfig」→ 长度断言转红：
/// 那个空壳节点会带着空地址进临时核，量出一个属于「不存在的节点」的 -1。
#[test]
fn requested_servers_skip_unknown_ids() {
    let got = requested_server_configs(&cfg_with_servers(), &ids(&["a", "ghost", "b"]));
    assert_eq!(
        got.iter().map(|s| s.id.clone()).collect::<Vec<_>>(),
        ids(&["a", "b"])
    );
}

/// 配置形态损坏 → 空 vec（不 panic）。
#[test]
fn requested_servers_tolerate_malformed_config() {
    assert!(requested_server_configs(&json!({}), &ids(&["a"])).is_empty());
    assert!(requested_server_configs(&json!({ "servers": 1 }), &ids(&["a"])).is_empty());
}

/// 🔵 **调用点守卫**：临时核腿必须挂在「主核**未**运行」这条分支上，且**在单飞闸之后**。
///
/// # 这条钉的两件事
///
/// 1. **分支条件**：旧代码是 `!running || mixed_port == 0 → clean error`。把临时核腿挂错条件
///    （比如挂在 `mixed_port == 0` 上）会让它在**主核正跑着**的时候起第二个核 —— 两个核同时握
///    同一批 WG/WARP peer，正是 上游 G1 双会话事故的形态；
/// 2. **闸序**：临时核会起真进程 + 占 N 个回环端口。单飞闸若在它之后抢，跨窗口连点就能同时起两个
///    临时核（两批端口、两份同名配置互相覆盖）。
///
/// 牙：① 把 `if !status.running {` 改成别的条件 ② 把 `SpeedTestGuard::acquire()` 挪到临时核腿之后
/// ③ 删掉临时核腿调用 —— 均转红。
#[test]
fn temp_core_leg_is_gated_on_main_core_absent_and_after_the_single_flight_latch() {
    let body = crate::commands::guard_scan::top_level_fn_body(
        &crate_code("commands/speedtest.rs"),
        "pub async fn server_speed_test(",
    );
    let latch = body
        .find("SpeedTestGuard::acquire()")
        .expect("单飞闸锚点消失，守卫已失去判据");
    let gate = body
        .find("if !status.running {")
        .expect("临时核腿必须**只**在主核未运行时进（主核在跑时起第二个核 = 双会话事故）");
    let call = body
        .find("run_temp_core_speed_test(&app, &state, &config, server_ids)")
        .expect("临时核腿必须真被调用——不调等于这条能力不存在");
    assert!(
        latch < gate && gate < call,
        "序必须是「抢单飞闸 → 判主核未跑 → 起临时核」：闸在后 ⇒ 跨窗口连点能同时起两个临时核"
    );
}

/// 🔵 **调用点守卫**：临时核腿的让位基准 `gen0` 必须在 await **之前**捕获，且判据用
/// [`is_temp_core_superseded`] 的**全部三条腿**（`gen` / `running` / `starting`）。
///
/// # 为什么是源码扫描
///
/// `TempCoreSession::run` 的让位语义已由 `runtime::speedtest` 的注入式测试全覆盖 —— 但那些测试注入的是
/// **现成的** `superseded` 闭包。把命令层的 `gen0` 挪到 `.await` 之后（= 跟自己比）、或把判据换成主核
/// 池路径那个 `is_superseded`（第二条腿是 `!running`，方向相反 ⇒ 主核起来时**恒不让位**）、或漏传
/// `st.starting`，那批测试一条都不会红。这正是本仓「逻辑在、接线不在」的形态。
///
/// 牙：① `gen0` 挪到 `TempCoreSession::run(` 之后 ② 判据换成 `is_superseded(` ③ 把 `st.running`
/// 或 `st.starting` 换成字面 `false` ④ 闭包里另起一个 `let gen0` 遮蔽外层 —— 均转红。
#[test]
fn temp_core_leg_captures_generation_before_awaiting_and_yields_to_a_running_core() {
    let body = crate::commands::guard_scan::top_level_fn_body(
        &crate_code("commands/speedtest.rs"),
        "async fn run_temp_core_speed_test(",
    );
    // 🔴 锚点带**函数体缩进**（4 空格）——只找裸字符串挡不住「把 `let gen0` 整行挪进 `superseded`
    // 闭包体内」这一手：那样它文本上仍在 `TempCoreSession::run(` 之前，位置断言照样绿，而语义已经变成
    // 「每次询问都现取一次基准跟自己比」⇒ 世代腿恒假、临时核在主核起来时不再让路。实测该变异能存活，
    // 故判据必须是**词法作用域**（4 空格 = 函数体；闭包体内是 8 空格）。
    let gen0 = body
        .find("\n    let gen0 = proxy.core_generation();")
        .expect(
            "临时核腿必须在**函数体**（而非 superseded 闭包体内）捕获让位基准 gen0：\
                 挪进闭包 = 每次现取跟自己比，世代腿恒假 ⇒ 主核起来时临时核不让路（双会话）",
        );
    assert!(
        !body.contains("\n        let gen0 = proxy.core_generation();"),
        "gen0 出现在闭包体缩进上 ⇒ 基准是现取的，让位判据的世代腿形同虚设"
    );
    // 🔴 收紧后的负锚仍可绕：闭包体内写 `let gen0 = { proxy.core_generation() };`
    // 等**非逐字**变体即可遮蔽外层 gen0，而上面那条逐字负断言不命中。故直接钉「全函数体内
    // `let gen0` 只许出现一次」——遮蔽必须引入第二处绑定，无论写法如何。
    assert_eq!(
        body.matches("let gen0").count(),
        1,
        "函数体内只许有**一处** `let gen0` 绑定：第二处（含 `let gen0 = {{ … }};` 这类非逐字变体）\
             会遮蔽外层基准 ⇒ 世代腿变成跟自己比，恒假"
    );
    let run = body
        .find("TempCoreSession::run(")
        .expect("临时核腿必须经 TempCoreSession::run 收口（收尾纪律在其中）");
    assert!(
        gen0 < run,
        "gen0 必须在 await（TempCoreSession::run）**之前**捕获：之后取等于跟自己比，判据恒假"
    );
    assert!(
        body.contains(
            "is_temp_core_superseded(proxy.core_generation(), gen0, st.running, st.starting)"
        ),
        "让位判据必须是**临时核那一版**且三条腿齐全：`running`/`starting` 与主核路径的 `!running` \
             方向相反；漏掉 `st.starting` ⇒ 「start 已开始、核尚未就绪」那整段启动期两条腿双盲"
    );
}

/// 🔵 **调用点守卫**：「核在跑但缺混合端口」这条半态的文案**不得说「核未运行」**。
///
/// 那句话与事实相反（核正跑着，缺的是端口），会把用户支去点「连接」——而他已经连着，排查方向整个
/// 偏掉。两条腿（`!running` → 临时核；`running && mixed_port == 0` → 本条）必须给各自的文案。
///
/// 牙：把文案改回「核未运行，无法测速」→ 转红。
#[test]
fn missing_mixed_port_error_does_not_claim_the_core_is_down() {
    let body = crate::commands::guard_scan::top_level_fn_body(
        &crate_code("commands/speedtest.rs"),
        "pub async fn server_speed_test(",
    );
    let branch = body
        .find("if status.running && status.mixed_port == 0 {")
        .expect("半态腿锚点消失，守卫已失去判据");
    // 该分支到下一条早退之间的文案。
    let tail = &body[branch..];
    let msg_end = tail.find("\n    }").unwrap_or(tail.len());
    let msg = &tail[..msg_end];
    assert!(
        !msg.contains("核未运行"),
        "核**在跑**、缺的是混合端口：说「核未运行」会把用户支去点已经连着的「连接」"
    );
    assert!(
        msg.contains("混合端口"),
        "文案须点明真实缺失项（混合端口），否则用户无从判断该做什么"
    );
}

/// 🔴 **调用点守卫**：主核**正在启动**时，入口必须当场 clean error，绝不放行到临时核腿。
///
/// # 缺陷长相（本轮 BLOCKER）
///
/// `ProxyRuntime::start` 的顺序是 `start_inflight+1`（`starting` 的源）→ **stale 清扫（真机可达数秒）**
/// → `bump_generation` → spawn → 就绪门。这整段里 `running` 恒 false，而世代可能已经 bump 完
/// ⇒ 本次测速取的 `gen0` 就是新世代 ⇒ 入口条件（`!status.running`）与让位判据的前两条腿**同时**
/// 看不见正在启动的主核。用户点「连接」后紧接点测速（或托盘/另一窗口点——UI 灰态拦不住跨窗）就是
/// **确定性**命中：起临时核 ⇒ ① 与启动中的主核同 peer 双会话踢线；② 临时核端口只排除
/// control/http/mixed，会抢走主核刚解析、尚未 bind 的 api/update-in/probe 池口 ⇒ 主核 FATAL
/// address-in-use（用户看到的是「连接失败」）。
///
/// 入口这道是**快路径**（用户立刻拿到「核正在启动」而不是等一轮空转）；真正扛竞态的是让位判据的
/// 第三条腿，二者各锁各的，缺一不可。
///
/// 牙：① 删掉 `status.starting` 那道闸 ② 把它挪到临时核腿调用之后 → 均转红。
#[test]
fn starting_main_core_is_treated_as_occupied_before_the_temp_core_leg() {
    let body = crate::commands::guard_scan::top_level_fn_body(
        &crate_code("commands/speedtest.rs"),
        "pub async fn server_speed_test(",
    );
    let gate = body.find("if status.starting").expect(
        "主核正在启动必须在入口当场挡住：那整段里 running=false 且世代可能已 bump 完，\
             `!status.running` 这个入口条件根本看不见它",
    );
    let call = body
        .find("run_temp_core_speed_test(&app, &state, &config, server_ids)")
        .expect("临时核腿必须真被调用——不调等于这条能力不存在");
    assert!(
        gate < call,
        "starting 闸必须在临时核腿**之前**：在后 = 临时核已经起来了才发现主核在启动"
    );
    assert!(
        body.contains("CODE_CORE_STARTING"),
        "须走专属结构化错误码（与「已有测速在飞」分开：那是等几秒重试，这是等连接完成后走主核池）"
    );
}

/// 端口排除集取材：**配置形态坏了也必须保住端口**。
///
/// `from_value::<UserConfig>` 对任何一个**无关**字段的形态错误都整体失败（这里让 `servers` 不是
/// 数组）。旧写法 `.unwrap_or_default()` 在那条腿上静默把排除集退化成「默认 control + http/mixed=0」
/// —— 恰好丢掉这段代码存在的唯一理由：临时核于是可能占住主核随后要 bind 的口，用户表现为
/// 「测完速就连不上」，而日志里一个字都没有。
///
/// **变异锁**：退回 `.unwrap_or_default()` → 第二组断言（坏配置仍读到 7890/8080）转红。
#[test]
fn port_exclusions_survive_a_malformed_config() {
    let good = json!({ "mixedPort": 7890, "httpPort": 8080, "servers": [] });
    let c = user_config_for_temp_core(&good);
    assert_eq!((c.mixed_port, c.http_port), (Some(7890), Some(8080)));

    // typed 解析必失败（servers 不是数组），端口字段本身仍是好的 → 必须照样排除。
    let broken = json!({
        "mixedPort": 7890,
        "httpPort": 8080,
        "servers": "oops",
        "subscriptions": [{ "id": "sub-a", "proxyBindInterface": "eth-sub" }],
        "networkInterfaces": { "proxy": "eth-global", "direct": "eth-direct" },
    });
    assert!(
        serde_json::from_value::<UserConfig>(broken.clone()).is_err(),
        "本用例的前提是 typed 解析确实失败；前提没了，下面的断言就不再检验退化腿"
    );
    let c = user_config_for_temp_core(&broken);
    assert_eq!(
        (c.mixed_port, c.http_port),
        (Some(7890), Some(8080)),
        "解析失败时端口必须从原始 JSON 兜回来，否则临时核会占住主核要 bind 的口"
    );
    assert_eq!(
        c.subscriptions[0].proxy_bind_interface.as_deref(),
        Some("eth-sub")
    );
    assert_eq!(
        c.network_interfaces
            .as_ref()
            .and_then(|policy| policy.proxy.as_deref()),
        Some("eth-global"),
        "解析失败时显式网卡策略也不能静默丢失，否则停核测速会换出口"
    );

    // 端口字段本身也坏（字符串）→ 无从兜，如实 None（不猜、不编）。
    let c = user_config_for_temp_core(&json!({ "mixedPort": "7890", "servers": "oops" }));
    assert_eq!((c.mixed_port, c.http_port), (None, None));
}

/// 🔴 临时核日志级别**跟随用户档**，与主核同一求值（用户档 + 隐私模式地板 `warn`）。
///
/// # 这条门盯的是什么
///
/// 改前非诊断档一律压 `warn`，于是「用户设 info、主核就是 info、临时核却是 warn」——同一个配置字段
/// 两种解释，而 `info` 那几类连接行正是判「核停在哪一步」的材料。2026-08-02「全是 -1」那次之所以
/// 无从复盘，就是磁盘上零核侧证据。
///
/// **变异锁**：
/// - 退回 `match { "debug" | "trace" => lv, _ => "warn" }` → `info` 那条当场转红（这条门在本批改动
///   之前就是红的）；
/// - 把 `effective(privacy)` 换成 `effective(false)`（或干脆不接隐私轴）→ 隐私那三条转红（隐私模式
///   下核会开始记连接明细，正是隐私开关要从源头掐掉的东西）；
/// - 把 `trace` 并进 `LogLevel` 的 serde 解析（它不在五档枚举里）→ 落到默认 `info`，第二条转红。
#[test]
fn temp_core_log_level_follows_the_user_level_with_privacy_floor() {
    // 非隐私：原样跟随用户那一档，**不再**压成 warn。
    assert_eq!(
        temp_core_log_level(&json!({ "logLevel": "info" }), false),
        "info"
    );
    assert_eq!(
        temp_core_log_level(&json!({ "logLevel": "debug" }), false),
        "debug"
    );
    // `trace` 不在本仓 `LogLevel` 五档里（那是 sing-box 侧七档词汇），必须单独放行、不得折成 debug
    // 或掉回默认 info —— 用户拨到 trace 正是为了复现最难的那类问题。
    assert_eq!(
        temp_core_log_level(&json!({ "logLevel": "trace" }), false),
        "trace"
    );
    assert_eq!(
        temp_core_log_level(&json!({ "logLevel": "error" }), false),
        "error"
    );
    // 缺省 / 非法值 → `LogLevel` 的 `#[default]` = info（与主核 `log_axes_from_config` 逐字同义）。
    assert_eq!(temp_core_log_level(&json!({}), false), "info");
    assert_eq!(
        temp_core_log_level(&json!({ "logLevel": "bogus" }), false),
        "info"
    );

    // 隐私模式：地板抬到 warn（info/debug/trace 才记连接明细），已在 warn 以上的原样不动。
    assert_eq!(
        temp_core_log_level(&json!({ "logLevel": "info" }), true),
        "warn"
    );
    assert_eq!(
        temp_core_log_level(&json!({ "logLevel": "debug" }), true),
        "warn"
    );
    assert_eq!(
        temp_core_log_level(&json!({ "logLevel": "trace" }), true),
        "warn"
    );
    assert_eq!(
        temp_core_log_level(&json!({ "logLevel": "error" }), true),
        "error"
    );
}

/// 零可测文案：**请求集里没有 TS 节点就不许提 Tailscale**。
///
/// **变异锁**：把 TS 那句改回无条件附加 → 第二条断言转红。零可测的真实原因（构造失败 / naive 缺
/// cronet / 节点已删）一个字没提，却把用户支去查一个他根本没有的 Tailscale 问题。
#[test]
fn none_testable_message_mentions_tailscale_only_when_a_ts_node_was_requested() {
    let with_ts = temp_core_none_testable_message(3, 1, true);
    assert!(with_ts.contains("Tailscale 节点须先连接主核后测"));
    assert!(with_ts.contains("3 个节点") && with_ts.contains("1 个节点不可用"));

    let without_ts = temp_core_none_testable_message(2, 2, false);
    assert!(
        !without_ts.contains("Tailscale"),
        "请求集无 TS 节点却提 Tailscale = 答非所问，把用户支去查一个不存在的问题"
    );
    assert!(without_ts.contains("2 个节点不可用"), "缺席计数不得丢");
}

/// 🔵 **调用点守卫**：临时核必须拿到**排除了用户 control/http/mixed 口**的端口分配。
///
/// 不排除 ⇒ 临时核可能占住主核随后要 bind 的口 ⇒ 用户测完速再点连接就起不来，表现为「测速把代理
/// 搞坏了」，归因极难。这条在本机无法行为验证（要真 bind），故用结构守卫。
///
/// 牙：把 `PortExclusions::for_primary_api(...)` 换成 `PortExclusions::default()` → 转红。
#[test]
fn temp_core_leg_excludes_user_configured_ports_from_allocation() {
    let body = crate::commands::guard_scan::top_level_fn_body(
        &crate_code("commands/speedtest.rs"),
        "async fn run_temp_core_speed_test(",
    );
    assert!(
        body.contains("PortExclusions::for_primary_api(")
            && body.contains("control_api_port(&user_config)")
            && body.contains("user_config.http_port")
            && body.contains("user_config.mixed_port"),
        "临时核端口必须排除用户配置的 control/http/mixed 口，否则主核随后 bind 撞口起不来"
    );
}

/// 🔵 **调用点守卫**：临时核腿的三条出口都必须是**诚实信封**（零可测 / 让位 / 起核失败 → 失败信封）。
///
/// 成功信封 + 零进度事件 ⇒ 前端 `NodesScreen` 的 `testing` 灰态永不复位（测速按钮永久 disabled 到
/// 组件重挂载）。这是本文件反复钉的同一条纪律。
///
/// 牙：把任一分支改成 `ApiResponse::ok(...)` → 转红。
#[test]
fn temp_core_leg_fails_closed_on_every_zero_measurement_path() {
    let body = crate::commands::guard_scan::top_level_fn_body(
        &crate_code("commands/speedtest.rs"),
        "async fn run_temp_core_speed_test(",
    );
    assert!(
        body.contains("CODE_TEMP_CORE_NONE_TESTABLE"),
        "零可测（全 tailscale / 全构造失败）必须走失败信封 + 专属 code"
    );
    assert!(
        body.contains("TempCoreOutcome::Superseded => ApiResponse::err_with_code("),
        "让位（一个节点都没测）必须走失败信封，否则前端拿到成功信封 + 零事件 → 按钮永久卡灰"
    );
    assert!(
        body.contains("TempCoreOutcome::Failed(e) => ApiResponse::err_with_code(e,"),
        "起核/就绪失败必须走失败信封，且原文冒泡（吞成通用文案会让用户无从排查）"
    );
    // 🔴 规模超限必须发**自己的**码。并进 `CODE_TEMP_CORE_FAILED` 编得过、上面那条断言照绿，
    // 而前端把该码无条件映射成 `nodes.speedTestInterrupted`（「测速中断」）⇒ 用户看到的与
    // 「核起不来超时」逐字相同，会朝网络/端口排查，真因却是本轮 naive 太多。
    //
    // ⚠️ **射程登记（T1-R1 分批之后）**：这条腿在生产路径上**已不可达** —— 规划器
    // （`runtime::speedtest::plan_temp_core_batches`）保证每一批的就绪预算至多 ≈11.9s，
    // 永远碰不到 60s 那条拒绝上限（门 `planned_batches_never_trip_the_oversize_refusal`）。
    // 本断言守的是「万一规划器被绕过或回归，那条自曝腿仍然发得出自己的码」，**不是**一条活路径。
    // 读到这里不要以为用户还会看到这个码。
    assert!(
        body.contains("TempCoreOutcome::Oversized(e) => ApiResponse::err_with_code(e,")
            && body.contains("CODE_TEMP_CORE_OVERSIZED"),
        "规模超限必须走独立错误码：与就绪超时共用一个码 ⇒ 前端只能说同一句「测速中断」，\
         而两者的修法南辕北辙（少选 naive 节点 vs 查网络/端口）"
    );
    assert!(
        body.contains("\"tsNotReady\": plan.tailscale"),
        "临时核测不了的 Tailscale 节点必须如实缺席回报，绝不伪造 -1"
    );
}

/// 🔵 **调用点守卫**：临时核腿与主核路径**共用同一个测量口径**（`measure_via_local_proxy`）。
///
/// 两条腿各写一份计时 ⇒ 两边的数值不可比（一边 warm-TTFB、一边含冷握手），而 UI 把它们显示在**同一个
/// 延迟徽标**里 —— 用户会以为「连上之后延迟变了」。
#[test]
fn temp_core_leg_reuses_the_shared_warm_ttfb_measurement() {
    let body = crate::commands::guard_scan::top_level_fn_body(
        &crate_code("commands/speedtest.rs"),
        "async fn run_temp_core_speed_test(",
    );
    assert!(
        body.contains("measure_via_local_proxy(port, &url)"),
        "临时核腿必须复用与主核路径同一个 warm-TTFB 测量（各写一份 ⇒ 同一个徽标里混着两种口径）"
    );
}

/// 🔵 **调用点守卫**：波前预筛第二腿必须**真接线到池路径**（测方法体 ≠ 测接线）。
///
/// # 为什么必须是源码扫描
///
/// 上面那批 `partition_pool` / `partition_ts_not_ready` / `ts_node_ready` 单测全是**注入式**的：
/// 它们喂现成的 `ts_pending` 集合与 `ready` 闭包。把命令层那句 `partition_ts_not_ready(...)` 删掉、
/// 改传 `&BTreeSet::new()`，**那批测试一条都不会红** —— 预筛整个死掉，TS 未就绪节点照旧被测出直连
/// 数值，而 gate 全绿。这正是本仓「假绿」的经典形态，故补这条结构守卫。
///
/// 牙：删掉 `partition_ts_not_ready(` 调用 / 把 `&ts_pending` 换成空集字面量 / 把预筛挪到
/// `run_pool_speed_test` 之后 → 转红。
#[test]
fn pool_leg_wires_ts_prefilter_before_running_waves() {
    let body = crate::commands::guard_scan::top_level_fn_body(
        &crate_code("commands/speedtest.rs"),
        "pub async fn server_speed_test(",
    );

    let prefilter = body
        .find("partition_ts_not_ready(&requested, &tailscale_ids,")
        .expect("池路径必须**现场**算 TS 未就绪集（取材面=本次请求集×config 里的 tailscale 节点）");
    let ready_probe = body
        .find("ts_node_ready(state.mesh().ts_status_event(")
        .expect("就绪判据必须读 mesh 的 TS 状态**活态**末帧，而非任何静态/缓存假设");
    let run = body
        .find("run_pool_speed_test(&app, &proxy, &targets, &requested, &url, &prefilter)")
        .expect("预筛结果必须作为入参传进分波编排——不传等于算了不用");
    assert!(
        prefilter < run && ready_probe < run,
        "预筛必须在**发波之前**完成：波已经发出去再筛，节点早就被 select+measure 过了"
    );
}

/// 🔵 **调用点守卫**：波前预筛**第三腿（dirty）**必须真接线到池路径（测方法体 ≠ 测接线）。
///
/// # 为什么必须是源码扫描
///
/// 上面那批 `partition_dirty` / `current_server_fingerprints` 单测全是**注入式**的：喂现成的两张
/// 指纹表。把命令层那句 `partition_dirty(...)` 删掉、`prefilter.dirty` 改传 `&BTreeSet::new()`，
/// **那批测试一条都不会红** —— 预筛整个死掉，已编辑未生效的节点照旧被测出旧参数出口的失真值，而
/// gate 全绿。同 TS 腿那条守卫的形态。
///
/// 牙：① 删掉 `partition_dirty(` 调用 ② 把「新」一侧从 `current_fingerprints`（ConfigManager 最新
/// config）换成运行核 config 镜像 ③ 把「旧」一侧从 `targets.fingerprints`（起核快照）换成别的
/// ④ 把预筛挪到 `run_pool_speed_test` 之后 —— 均转红。
#[test]
fn pool_leg_wires_dirty_prefilter_before_running_waves() {
    let body = crate::commands::guard_scan::top_level_fn_body(
        &crate_code("commands/speedtest.rs"),
        "pub async fn server_speed_test(",
    );

    assert!(
            body.contains("let current_fingerprints = current_server_fingerprints(&config);"),
            "「新」一侧必须取自 ConfigManager 最新 config（运行核 config 镜像在订阅自动刷新路径上滞后 ⇒ 漏判 dirty）"
        );
    let prefilter = body
        .find("partition_dirty(&requested, &targets.fingerprints, &current_fingerprints)")
        .expect("池路径必须现场算 dirty 集：「旧」= 起核快照指纹，「新」= 当前配置指纹");
    let run = body
        .find("run_pool_speed_test(&app, &proxy, &targets, &requested, &url, &prefilter)")
        .expect("预筛结果必须作为入参传进分波编排——不传等于算了不用");
    assert!(
        prefilter < run,
        "预筛必须在**发波之前**完成：波已经发出去再筛，节点早就被 select+measure 过了"
    );
    assert!(
        body.contains("dirty: &dirty_pending,"),
        "算出来的 dirty 集必须真的装进 PoolPrefilter（装空集 = 预筛死掉但单测全绿）"
    );
}

/// 🔵 **调用点守卫**：分区函数必须真的**消费**注入的两个预筛集，且缺席节点如实回报。
///
/// 牙：把 `prefilter.dirty` / `prefilter.ts_pending` 任一换成 `&BTreeSet::new()`、或把
/// `tsNotReady` / `dirty` 从响应里换回 `[]` 字面量 → 转红。
#[test]
fn pool_runner_consumes_prefilters_and_reports_them() {
    let body = crate::commands::guard_scan::top_level_fn_body(
        &crate_code("commands/speedtest.rs"),
        "async fn run_pool_speed_test(",
    );

    assert!(
        body.contains("prefilter.dirty,") && body.contains("prefilter.ts_pending,"),
        "分区必须消费**注入的**两个预筛集（换成空集 = 预筛死掉但单测全绿）"
    );
    assert!(
        body.contains("\"tsNotReady\": ts_not_ready"),
        "缺席列表必须如实回报给前端（写死 [] = 谎报「全测过了」，toast 的缺席计数归零）"
    );
    assert!(
        body.contains("\"dirty\": dirty"),
        "已编辑未生效的缺席列表必须如实回报（写死 [] = 谎报「这些节点测过了」）"
    );
    assert!(
        body.contains("zero_testable_envelope(not_in_pool.len(), dirty.len(), &ts_reasons)"),
        "零可测分流必须把三类缺席**都**喂进去：少喂一类，那类的专属 code 与文案永远发不出来"
    );
    assert!(
        body.contains("prefilter.ts_reasons.get(id)"),
        "TS 那一类必须喂**成因**而不是计数 —— 只喂计数就退回本轮缺陷：\
             「未登录」与「已登录但隧道未就绪」被折叠成同一句，用户照着去登录是白做工"
    );
}

/// 🔵 **调用点守卫**：回退腿的 TS 就绪门必须挡在**测量之前**。
///
/// 回退腿唯一真测的就是活跃出口。它若是未就绪 TS 节点，核已让位直连 ⇒ 经混合口量到的是**直连** RTT。
/// 这个门放在 `drive_fallback_measure` 之后就等于没门：值已经量出来并写进 results 了。
///
/// 牙：删掉该早退 / 把它挪到 `drive_fallback_measure(` 之后 → 转红。
#[test]
fn fallback_leg_gates_unready_tailscale_exit_before_measuring() {
    let body = crate::commands::guard_scan::top_level_fn_body(
        &crate_code("commands/speedtest.rs"),
        "pub async fn server_speed_test(",
    );

    let gate = body
        .find("tailscale_ids.contains(&active)")
        .expect("回退腿必须先判活跃出口是不是 TS 节点（非 TS 节点不该被这道门误伤）");
    let measure = body
        .find("drive_fallback_measure(")
        .expect("回退腿必须经 drive_fallback_measure 收口");
    assert!(
        gate < measure,
        "TS 就绪门在测量**之后** = 形同虚设：直连 RTT 已经被记到那个连不通的 TS 节点名下了"
    );
}
