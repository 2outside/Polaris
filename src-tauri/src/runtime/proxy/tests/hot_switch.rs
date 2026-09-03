use super::*;

/// 起一个只统计「被连了几次」的本地 TCP 监听器（不说 SS 协议——核**拨过来**这一事实本身
/// 就是路由证据；握手成不成功无关紧要）。
async fn counting_listener() -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::atomic::AtomicUsize;
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            h.fetch_add(1, Ordering::SeqCst);
            drop(s); // 立刻断开：核会报连接失败，但「它拨了我」已被记下。
        }
    });
    (port, hits)
}

/// 经混合入站发一个 HTTP 代理请求（目标 192.0.2.1 = RFC 5737 TEST-NET-1：非私网 →
/// 不命中私网直连规则；IP 字面量 → 不触发 DNS 查询 → 零外部流量）。
async fn drive_traffic_through_proxy(mixed: u16) {
    use tokio::io::AsyncWriteExt;
    if let Ok(mut c) = tokio::net::TcpStream::connect(("127.0.0.1", mixed)).await {
        let _ = c
            .write_all(b"GET http://192.0.2.1/ HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n")
            .await;
        let _ = c.flush().await;
    }
    tokio::time::sleep(Duration::from_millis(600)).await;
}

// ══════════════════════════════════════════════════════════════════════════════
// P1 契约收口：pending_changes() = {added, modified, removed}
//
// 这批测试的分母（R5）：`pending_changes()` 此前 **零覆盖**。先钉住四态基线，再谈「改对了」——
// 否则改完无法区分「修好了」与「换了个错法」。
// ══════════════════════════════════════════════════════════════════════════════

/// 装一副「起核快照」：`startup_snapshot`（id 集基准）+ `switch_snapshot`（指纹基准）。
/// 二者在生产的起核就绪腿相隔 8 行同置，是同刻同源的孪生对 —— 测试里也必须同置，
/// 只装一半会造出生产中不可达的形态。
fn install_startup_snapshot(rt: &ProxyRuntime, cfg: &Value) {
    let uc: UserConfig = serde_json::from_value(cfg.clone()).expect("测试配置应可解析");
    *rt.startup_snapshot.write().unwrap() = Some(cfg.clone());
    *rt.switch_snapshot.write().unwrap() = Some(SwitchSnapshot {
        fingerprints: node_fingerprints::modified_table(&uc.servers),
        dirty_fingerprints: node_fingerprints::dirty_table(&uc.servers),
        ..Default::default()
    });
}

/// **契约形状**（T1-8）：键集恰为 `{added, modified, removed, restartDeferred}` —— 不多不少。
///
/// 旧契约 `{added, updated, deleted}` 里 `updated` = `old ∩ new`（全部存活 id，与改没改过无关），
/// 前端从不消费；留着它只会让后来者按旧名字读出旧含义。
///
/// `restartDeferred`（P4）是**第四个键而非第四个数组**：它回答的是「有没有非节点结构性变更
/// 被『保存不重启』降级」，这类改动一个节点都不动，塞进任何一个 id 数组都是撒谎。
/// 键名走 camelCase（`#[serde(rename_all)]`）与前端契约同形。
///
/// **变异对照**：给 `PendingChangesSummary` 加回 `updated` 字段 → 键集断言转红；
/// 去掉 `#[serde(rename_all = "camelCase")]` → 键名变 `restart_deferred` → 同样转红。
#[test]
fn pending_changes_contract_has_exactly_three_keys() {
    let (rt, _dir) = test_runtime();
    let v = serde_json::to_value(rt.pending_changes()).expect("契约体应可序列化");
    let mut keys: Vec<&str> = v
        .as_object()
        .expect("对象形")
        .keys()
        .map(|k| &**k)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec!["added", "modified", "removed", "restartDeferred"]
    );
}

/// **基线四态**（T1-19）：无快照 / 有快照无变化 / 空 servers / 读不到当前配置。
/// 全部走「空差集」，且**绝不 panic**。
///
/// **变异对照**：把「无 `startup_snapshot` → 空差集」腿删掉（改成拿当前配置当基准）→
/// 核未运行时 `added` 会变成全部节点 → 转红。
#[test]
fn pending_changes_baseline_states_are_all_empty() {
    let (rt, _dir) = test_runtime();
    let empty = PendingChangesSummary {
        added: vec![],
        modified: vec![],
        removed: vec![],
        restart_deferred: false,
    };

    // ① 核未运行 / 无起核快照。
    assert_eq!(rt.pending_changes(), empty, "无快照 = 没有分母，不谈待应用");

    // ② 有快照、配置一字未改。
    let cfg = two_node_config(7891, "node-a");
    rt.config.save_full(&cfg).expect("落盘");
    install_startup_snapshot(&rt, &cfg);
    assert_eq!(rt.pending_changes(), empty, "配置未变 → 三个集合全空");

    // ③ 空 servers 两侧。
    let mut bare = cfg.clone();
    bare["servers"] = serde_json::json!([]);
    rt.config.save_full(&bare).expect("落盘");
    install_startup_snapshot(&rt, &bare);
    assert_eq!(rt.pending_changes(), empty, "两侧都没节点 → 全空");
}

/// **`removed` 语义**（T1-9）：`old_ids − new_ids`，不是交集、不是并集、不是反过来。
///
/// **变异对照**：把 `removed` 写成 `new_ids − old_ids` → 它会与 `added` 相等 → 转红。
#[test]
fn pending_changes_removed_is_old_minus_new() {
    let (rt, _dir) = test_runtime();
    let cfg = two_node_config(7891, "node-a");
    rt.config.save_full(&cfg).expect("落盘");
    install_startup_snapshot(&rt, &cfg);

    // 删 node-b、加 node-c（selected 仍是 node-a，避免牵动别的腿）。
    let mut next = cfg.clone();
    let servers = next["servers"].as_array_mut().unwrap();
    servers.retain(|s| s["id"] != "node-b");
    servers.push(ss_node("node-c", "Node C", 18003));
    rt.config.save_full(&next).expect("落盘");

    let p = rt.pending_changes();
    assert_eq!(p.added, vec!["node-c".to_string()], "added = new − old");
    assert_eq!(p.removed, vec!["node-b".to_string()], "removed = old − new");
    assert!(
        p.modified.is_empty(),
        "只增删、没改存活节点 → modified 空（modified ⊂ old ∩ new）"
    );
}

/// **`modified` 判据 = 全维**（U-3 已拍板）：改一个 5 维覆盖不到的字段（`name`），
/// 该节点**必须**出现在 `modified` 里。
///
/// 因果：`modified` 回答「运行核里跑的还是不是用户当前配置」。改 `name` 会改生成产物
/// （outbound tag 随之变）⇒ 核里跑的确实已不是当前配置 ⇒ 必须报。用 5 维判据会漏报，
/// 表现为「核因为它重启了，而 pending-bar 从没提过这件事」。
///
/// **变异对照**：把 `node_fingerprints::modified_fingerprint` 换成 5 维公式 → 本条转红。
#[test]
fn pending_changes_modified_uses_full_projection_not_five_dims() {
    let (rt, _dir) = test_runtime();
    let cfg = two_node_config(7891, "node-a");
    rt.config.save_full(&cfg).expect("落盘");
    install_startup_snapshot(&rt, &cfg);

    // 只改显示名：5 维指纹一动不动，全维投影变。
    let mut next = cfg.clone();
    next["servers"].as_array_mut().unwrap()[1]["name"] = serde_json::json!("改过名字");
    rt.config.save_full(&next).expect("落盘");

    let p = rt.pending_changes();
    assert_eq!(
        p.modified,
        vec!["node-b".to_string()],
        "改 name 必须进 modified —— 判据是全维，不是 5 维"
    );
    assert!(p.added.is_empty() && p.removed.is_empty(), "没增没删");
}

/// **核心不变式：测速 dirty ⊆ pending modified**（接线级，非仅公式级）。
///
/// 「测速说这个节点『已编辑未生效，去应用』，而 pending-bar 上根本没有它」—— 用户实报症状。
/// 本条钉死它在**结构上**不可能再发生：凡测速判 dirty 的节点，必在 `modified` 里。
///
/// 与 `node_fingerprints` 里那条纯公式测的分工：那条证「全维 ⊇ 5 维」，本条证**两条数据通路
/// 真的各自接到了正确的那张表** —— 把 `speed_probe_targets` 接成全维表、或把 `modified` 接成
/// 5 维表，公式测都还是绿的，只有本条会说话。
///
/// **变异对照**：
/// - `speed_probe_targets` 里 `snap.dirty_fingerprints` 改回 `snap.fingerprints`
///   → dirty 侧恒不等 → `node-a`（一字未改）也进 dirty 而不在 modified → 转红。
/// - `pending_changes` 的 `modified` 换成 5 维表 → 改 `port` 的仍在，但下面「改 name 只进 modified」
///   那条断言转红。
#[test]
fn speedtest_dirty_is_always_a_subset_of_pending_modified() {
    let (rt, _dir) = test_runtime();
    let cfg = two_node_config(7891, "node-a");
    rt.config.save_full(&cfg).expect("落盘");
    install_startup_snapshot(&rt, &cfg);
    *rt.status.write().unwrap() = ProxyStatus {
        running: true,
        ..Default::default()
    };
    // 池端口非空才吐 SpeedProbeTargets（生产同款前提）。
    if let Ok(mut g) = rt.switch_snapshot.write() {
        if let Some(s) = g.as_mut() {
            s.probe_pool_ports = vec![41001];
        }
    }

    // node-a：一字未改。node-b：只改 name（非 5 维）。node-c 不存在，改 node-b 的 port 另测。
    let mut next = cfg.clone();
    next["servers"].as_array_mut().unwrap()[1]["name"] = serde_json::json!("改过名字");
    rt.config.save_full(&next).expect("落盘");

    let modified: std::collections::BTreeSet<String> =
        rt.pending_changes().modified.into_iter().collect();
    // 复刻测速侧的 dirty 判据（`partition_dirty` 的公式：快照有该 id 且与当前指纹不等）。
    let targets = rt.speed_probe_targets().expect("核在跑 + 池非空");
    let current_dirty = node_fingerprints::dirty_table(
        &serde_json::from_value::<UserConfig>(next.clone())
            .expect("可解析")
            .servers,
    );
    let dirty: std::collections::BTreeSet<String> = current_dirty
        .iter()
        .filter(|(id, fp)| {
            targets
                .fingerprints
                .get(*id)
                .is_some_and(|snap| snap != *fp)
        })
        .map(|(id, _)| id.clone())
        .collect();

    assert!(
        dirty.is_subset(&modified),
        "违反 dirty ⊆ modified：dirty={dirty:?} modified={modified:?} —— \
             测速会把用户指引到一个 pending-bar 上不存在的节点"
    );
    assert!(
        dirty.is_empty(),
        "只改 name → 连接参数没变 → 池里那个出口仍能代表它 → 不该判 dirty（判了就是白白拒测）"
    );
    assert!(
        modified.contains("node-b"),
        "只改 name → 核里跑的已不是当前配置 → 必须进 modified"
    );

    // 再改 5 维字段（port）：两个集合都应含它，包含关系仍成立。
    let mut moved = next.clone();
    moved["servers"].as_array_mut().unwrap()[1]["port"] = serde_json::json!(18999);
    rt.config.save_full(&moved).expect("落盘");
    let modified2: std::collections::BTreeSet<String> =
        rt.pending_changes().modified.into_iter().collect();
    let current_dirty2 = node_fingerprints::dirty_table(
        &serde_json::from_value::<UserConfig>(moved)
            .expect("可解析")
            .servers,
    );
    let dirty2: std::collections::BTreeSet<String> = current_dirty2
        .iter()
        .filter(|(id, fp)| {
            targets
                .fingerprints
                .get(*id)
                .is_some_and(|snap| snap != *fp)
        })
        .map(|(id, _)| id.clone())
        .collect();
    assert_eq!(
        dirty2,
        std::collections::BTreeSet::from(["node-b".to_string()])
    );
    assert!(
        dirty2.is_subset(&modified2),
        "改 5 维字段后包含关系仍须成立"
    );
}

/// 有 `startup_snapshot` 但无 `switch_snapshot`（孪生对理论上不会只剩一半）→
/// `added`/`removed` 照给，`modified` 降级为空：拿不到起核那刻的指纹表就没有比对基准，
/// **宁可漏报也不猜**。
///
/// **变异对照**：把缺表时的降级改成「当作全部改过」→ modified 含 node-a/node-b → 转红。
#[test]
fn pending_changes_without_fingerprint_baseline_degrades_to_empty_modified() {
    let (rt, _dir) = test_runtime();
    let cfg = two_node_config(7891, "node-a");
    rt.config.save_full(&cfg).expect("落盘");
    *rt.startup_snapshot.write().unwrap() = Some(cfg.clone());
    *rt.switch_snapshot.write().unwrap() = None;

    let mut next = cfg.clone();
    next["servers"].as_array_mut().unwrap()[1]["name"] = serde_json::json!("改过名字");
    next["servers"]
        .as_array_mut()
        .unwrap()
        .push(ss_node("node-c", "Node C", 18003));
    rt.config.save_full(&next).expect("落盘");

    let p = rt.pending_changes();
    assert_eq!(p.added, vec!["node-c".to_string()], "id 集差不依赖指纹表");
    assert!(p.modified.is_empty(), "没有指纹基准 → 不猜，报空");
}

/// 三个集合恒排序：`HashSet` 迭代序每进程不同（`RandomState`），不排序会让明细列表无故重排、
/// 也让单测只能退化成集合比较。
///
/// **变异对照**：删掉 `added.sort()` → 转红。用 6 个乱序 id：未排序时恰好撞上升序的概率 1/720，
/// 即「几乎必红」；3 个 id 是 1/6，会让这条门形同虚设。
#[test]
fn pending_changes_sets_are_sorted() {
    let (rt, _dir) = test_runtime();
    let cfg = two_node_config(7891, "node-a");
    rt.config.save_full(&cfg).expect("落盘");
    install_startup_snapshot(&rt, &cfg);

    let mut next = cfg.clone();
    let servers = next["servers"].as_array_mut().unwrap();
    for (i, id) in ["z-n", "a-n", "m-n", "c-n", "t-n", "f-n"]
        .iter()
        .enumerate()
    {
        servers.push(ss_node(id, id, 18100 + i as u16));
    }
    rt.config.save_full(&next).expect("落盘");

    assert_eq!(
        rt.pending_changes().added,
        vec![
            "a-n".to_string(),
            "c-n".to_string(),
            "f-n".to_string(),
            "m-n".to_string(),
            "t-n".to_string(),
            "z-n".to_string(),
        ],
        "added 必须升序"
    );
}

/// 给运行时装一个假的热切换基准（不起真核，测决策分流用）。
fn mark_running_with_snapshot(rt: &ProxyRuntime, cfg: &Value) {
    mark_running(rt);
    let uc: UserConfig = serde_json::from_value(cfg.clone()).unwrap();
    let mut id_to_tag = BTreeMap::new();
    id_to_tag.insert("node-a".to_string(), "Node A".to_string());
    id_to_tag.insert("node-b".to_string(), "Node B".to_string());
    // 两张表都装：生产的 build_switch_snapshot 同刻同源置两张，假快照漏一张会让被测腿看到
    // 「有全维表但 dirty 表空」这个生产里不可达的形态。
    *rt.switch_snapshot.write().unwrap() = Some(SwitchSnapshot {
        id_to_tag,
        rule_target: BTreeMap::new(),
        fingerprints: node_fingerprints::modified_table(&uc.servers),
        dirty_fingerprints: node_fingerprints::dirty_table(&uc.servers),
        probe_pool_ports: vec![],
    });
    *rt.current_config.write().unwrap() = Some(cfg.clone());
}

#[test]
fn auto_switch_success_invalidates_config_consumers_before_notification() {
    let body = method_body(
        &module_code("runtime/proxy"),
        "    fn emit_auto_node_switched(&self, payload: &AutoNodeSwitchedPayload) {",
    );
    let signal = body
        .find("emit_config_changed_signal(&self.app)")
        .expect("自动切换成功必须让所有配置消费者重拉 selectedServerId");
    let notification = body
        .find("EVENT_AUTO_NODE_SWITCHED")
        .expect("自动切换成功通知不可丢");
    assert!(
        signal < notification,
        "先发配置失效信号，再发成功通知；主窗/托盘看到 toast 时选中态才不会仍是旧节点"
    );
    assert!(
        !body.contains("broadcast_config_changed("),
        "自动事务不得复用会再次把整份 D 送入 switch_mode 的普通配置汇流点"
    );
    // 正向对照：证明 `broadcast_config_changed` 在本仓确实可解析，不是笔误/已重命名的死符号。
    // 没有这一条，上面的否定针只钉「将来别这么写」——它今天在 `body` 里 count = 0，本就无法与
    // 「符号已被重命名、否定针静默退化成恒真」区分；符号一旦改名，这条门会继续绿而不自曝。
    assert!(
        crate::test_support::crate_code("commands/config.rs")
            .contains("pub(crate) fn broadcast_config_changed("),
        "`broadcast_config_changed` 定义已找不到 —— 上面那条否定针钉的符号已不存在，\
             门已静默退化成恒真"
    );
}

/// 自动故障切换事务的管理面替身：PUT 会原子更新 selector，groups_snapshot 读回同一真值。
/// `reject_member` 用来证明失败腿只恢复原 selector，不会调度整核重启。
struct AttestingManagementApi {
    selected: Mutex<String>,
    reject_member: Option<String>,
    reject_all: bool,
    puts: Mutex<Vec<(String, String)>>,
    on_first_select: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl AttestingManagementApi {
    fn new(selected: &str) -> Self {
        Self {
            selected: Mutex::new(selected.to_string()),
            reject_member: None,
            reject_all: false,
            puts: Mutex::new(Vec::new()),
            on_first_select: Mutex::new(None),
        }
    }

    fn rejecting(selected: &str, member: &str) -> Self {
        Self {
            selected: Mutex::new(selected.to_string()),
            reject_member: Some(member.to_string()),
            reject_all: false,
            puts: Mutex::new(Vec::new()),
            on_first_select: Mutex::new(None),
        }
    }

    fn rejecting_all(selected: &str) -> Self {
        Self {
            selected: Mutex::new(selected.to_string()),
            reject_member: None,
            reject_all: true,
            puts: Mutex::new(Vec::new()),
            on_first_select: Mutex::new(None),
        }
    }

    fn with_on_first_select(self, hook: impl FnOnce() + Send + 'static) -> Self {
        *self.on_first_select.lock().unwrap() = Some(Box::new(hook));
        self
    }
}

#[async_trait::async_trait]
impl ManagementApi for AttestingManagementApi {
    async fn select_outbound(
        &self,
        selector_tag: &str,
        member_tag: &str,
    ) -> Result<(), ManagementError> {
        self.puts
            .lock()
            .unwrap()
            .push((selector_tag.to_string(), member_tag.to_string()));
        if let Some(hook) = self.on_first_select.lock().unwrap().take() {
            hook();
        }
        if self.reject_all || self.reject_member.as_deref() == Some(member_tag) {
            return Err(ManagementError::Call(
                "injected selector failure".to_string(),
            ));
        }
        *self.selected.lock().unwrap() = member_tag.to_string();
        Ok(())
    }

    async fn close_connection(&self, _id: &str) -> Result<(), ManagementError> {
        Ok(())
    }

    async fn first_connection_snapshot(
        &self,
    ) -> Result<Vec<polaris_switch_engine::ConnectionSnapshot>, ManagementError> {
        Ok(Vec::new())
    }
}

#[async_trait::async_trait]
impl RuntimeSelectionApi for AttestingManagementApi {
    async fn groups_snapshot(&self) -> Result<Vec<GroupSelection>, ManagementError> {
        Ok(vec![GroupSelection {
            tag: "proxy-selector".to_string(),
            selected: self.selected.lock().unwrap().clone(),
        }])
    }
}

/// D 中已有一个未 Apply 的结构变更时，自动 failover 只准提交 selectedServerId：磁盘债务继续留在 D，
/// 运行核 R 只换 selector。若错误复用普通 `switch_mode` 的失败重启兜底，R 的 mixedPort 会被一并前推。
#[tokio::test]
async fn auto_failover_hot_switch_preserves_saved_but_unapplied_config() {
    let (rt, _dir) = test_runtime();
    let runtime = two_node_config(7890, "node-a");
    let mut disk = runtime.clone();
    disk["mixedPort"] = serde_json::json!(7999); // 已保存、未 Apply 的结构性债务
    rt.config.save_full(&disk).expect("seed D");
    mark_running_with_snapshot(&rt, &runtime);
    let candidate = RuntimeCandidate {
        id: "node-b".to_string(),
        name: "Node B".to_string(),
        tag: "Node B".to_string(),
    };
    let fingerprint = current_server_fingerprints(&disk)
        .remove("node-b")
        .expect("candidate fingerprint");
    let api = AttestingManagementApi::new("Node A");

    let outcome = rt
        .auto_hot_switch_transaction_with_api(
            rt.core_generation(),
            "node-a",
            &candidate,
            &fingerprint,
            &api,
        )
        .await;

    assert_eq!(outcome, AutoHotSwitchOutcome::Applied);
    let after_disk = rt.config.current().expect("read D after failover");
    assert_eq!(after_disk["selectedServerId"], "node-b");
    assert_eq!(after_disk["mixedPort"], 7999, "磁盘债务必须原样保留");
    let after_runtime = rt.current_config.read().unwrap().clone().unwrap();
    assert_eq!(after_runtime["selectedServerId"], "node-b");
    assert_eq!(
        after_runtime["mixedPort"], 7890,
        "自动切换不得把 D 的其它待 Apply 字段夹带进 R"
    );
    assert_eq!(rt.status().pid, 424242, "零重启事务不得改变运行核身份");
    assert_eq!(
        *api.puts.lock().unwrap(),
        vec![("proxy-selector".to_string(), "Node B".to_string())]
    );
}

/// 管理面拒绝目标成员时，事务必须恢复 D/R 的旧选择并返回失败；结果类型没有 Restarting，后台治理
/// 因而不可能借失败兜底把整份磁盘配置重启入核。
#[tokio::test]
async fn auto_failover_selector_failure_rolls_back_without_restart() {
    let (rt, _dir) = test_runtime();
    let config = two_node_config(7890, "node-a");
    rt.config.save_full(&config).expect("seed D");
    mark_running_with_snapshot(&rt, &config);
    let candidate = RuntimeCandidate {
        id: "node-b".to_string(),
        name: "Node B".to_string(),
        tag: "Node B".to_string(),
    };
    let fingerprint = current_server_fingerprints(&config)
        .remove("node-b")
        .expect("candidate fingerprint");
    let api = AttestingManagementApi::rejecting("Node A", "Node B");

    let outcome = rt
        .auto_hot_switch_transaction_with_api(
            rt.core_generation(),
            "node-a",
            &candidate,
            &fingerprint,
            &api,
        )
        .await;

    assert_eq!(outcome, AutoHotSwitchOutcome::Failed);
    assert_eq!(
        rt.config.current().unwrap()["selectedServerId"],
        "node-a",
        "失败后 D 必须回到旧选择"
    );
    assert_eq!(
        rt.current_config.read().unwrap().as_ref().unwrap()["selectedServerId"],
        "node-a",
        "失败后 R 必须仍指向旧选择"
    );
    assert_eq!(rt.status().pid, 424242, "失败不得触发整核重启");
    assert_eq!(
        *api.puts.lock().unwrap(),
        vec![
            ("proxy-selector".to_string(), "Node B".to_string()),
            ("proxy-selector".to_string(), "Node A".to_string()),
        ],
        "目标失败后只允许恢复旧 selector"
    );
}

/// 用户在 auto target PUT 期间再次选择**同一个候选**时，id 比较仍相等，只有独立 intent 代次
/// 能证明所有权已经交接。旧事务不得 restore，更不得把 D 回滚成旧节点。
#[tokio::test]
async fn auto_failover_does_not_rollback_new_same_target_user_intent() {
    let (rt, _dir) = test_runtime();
    let config = two_node_config(7890, "node-a");
    rt.config.save_full(&config).expect("seed D");
    mark_running_with_snapshot(&rt, &config);
    let candidate = RuntimeCandidate {
        id: "node-b".to_string(),
        name: "Node B".to_string(),
        tag: "Node B".to_string(),
    };
    let fingerprint = current_server_fingerprints(&config)
        .remove("node-b")
        .expect("candidate fingerprint");
    let rt_for_user = Arc::clone(&rt);
    let api =
        AttestingManagementApi::rejecting("Node A", "Node B").with_on_first_select(move || {
            rt_for_user
                .config
                .update(|latest| {
                    // 与 server_switch_core 相同：所有权 bump 与 D 写处于同一个配置写事务。
                    rt_for_user.register_selector_intent();
                    latest["selectedServerId"] = serde_json::json!("node-b");
                    latest["recentServerIds"] = serde_json::json!(["node-b"]);
                    Decision::Write(())
                })
                .expect("inject same-target user selection");
        });

    let outcome = rt
        .auto_hot_switch_transaction_with_api(
            rt.core_generation(),
            "node-a",
            &candidate,
            &fingerprint,
            &api,
        )
        .await;

    assert_eq!(outcome, AutoHotSwitchOutcome::Superseded);
    let disk = rt.config.current().unwrap();
    assert_eq!(disk["selectedServerId"], "node-b");
    assert_eq!(disk["recentServerIds"], serde_json::json!(["node-b"]));
    assert_eq!(
        *api.puts.lock().unwrap(),
        vec![("proxy-selector".to_string(), "Node B".to_string())],
        "新意图接管后旧事务不得再 PUT restore"
    );
}

/// 更隐蔽的 ABA：auto 已把 selector 拨到 B，用户随后明确选择旧 R 的 A。配置差分看起来
/// Unchanged，但运行 selector 已不是 A；所有权交接脏位必须迫使新广播重申 A。
#[tokio::test]
async fn superseded_auto_put_forces_reassert_even_when_new_config_equals_old_runtime() {
    let (rt, _dir) = test_runtime();
    let config = two_node_config(7890, "node-a");
    rt.config.save_full(&config).expect("seed D");
    mark_running_with_snapshot(&rt, &config);
    let candidate = RuntimeCandidate {
        id: "node-b".to_string(),
        name: "Node B".to_string(),
        tag: "Node B".to_string(),
    };
    let fingerprint = current_server_fingerprints(&config)
        .remove("node-b")
        .expect("candidate fingerprint");
    let rt_for_user = Arc::clone(&rt);
    let api = AttestingManagementApi::new("Node A").with_on_first_select(move || {
        rt_for_user
            .config
            .update(|latest| {
                rt_for_user.register_selector_intent();
                latest["selectedServerId"] = serde_json::json!("node-a");
                Decision::Write(())
            })
            .expect("inject user ABA selection");
    });
    assert_eq!(
        rt.auto_hot_switch_transaction_with_api(
            rt.core_generation(),
            "node-a",
            &candidate,
            &fingerprint,
            &api,
        )
        .await,
        AutoHotSwitchOutcome::Superseded
    );
    assert_eq!(
        *api.selected.lock().unwrap(),
        "Node B",
        "前提：旧 PUT 已落核"
    );
    assert!(rt.selector_reconcile.is_required());

    let sink = Arc::new(TestPutSink::default());
    *rt.management_api_stub.lock().unwrap() = Some(Arc::clone(&sink));
    let latest = rt.config.current().unwrap();
    let broadcast_intent = rt.register_selector_intent();
    assert!(matches!(
        rt.switch_persisted_config_if_current(latest, false, broadcast_intent, |_| {})
            .await,
        Some(SwitchOutcome::Unchanged | SwitchOutcome::NoOp)
    ));
    assert_eq!(
        sink.calls(),
        vec![("proxy-selector".to_string(), "Node A".to_string())],
        "Unchanged 腿仍须修复被旧 owner 改脏的 selector"
    );
    assert!(!rt.selector_reconcile.is_required());
}

/// target 与 restore 都失败时不得静默留下 D/R 分叉：先落用户可见 EXIT_MISMATCH，再由同一
/// generation+intent 所有权下的受限 selector 对账收敛，且只推进 R.selectedServerId。
#[tokio::test]
async fn auto_failover_double_failure_enters_recoverable_selector_reconciliation() {
    let (rt, _dir) = test_runtime();
    let config = two_node_config(7890, "node-a");
    rt.config.save_full(&config).expect("seed D");
    mark_running_with_snapshot(&rt, &config);
    let errors: ErrorEvents = Arc::new(Mutex::new(Vec::new()));
    let config_changed = Arc::new(AtomicUsize::new(0));
    rt.set_error_emitter(Box::new(RecordingErrorEmitter {
        events: Arc::clone(&errors),
        config_changed: Arc::clone(&config_changed),
        ..Default::default()
    }));
    let candidate = RuntimeCandidate {
        id: "node-b".to_string(),
        name: "Node B".to_string(),
        tag: "Node B".to_string(),
    };
    let fingerprint = current_server_fingerprints(&config)
        .remove("node-b")
        .expect("candidate fingerprint");

    let failed_api = AttestingManagementApi::rejecting_all("Node A");
    let outcome = rt
        .auto_hot_switch_transaction_with_api(
            rt.core_generation(),
            "node-a",
            &candidate,
            &fingerprint,
            &failed_api,
        )
        .await;
    let AutoHotSwitchOutcome::ReconcilePending { intent_generation } = outcome else {
        panic!("双不自证必须进入恢复态，实得 {outcome:?}");
    };
    assert_eq!(rt.config.current().unwrap()["selectedServerId"], "node-b");
    assert_eq!(
        rt.current_config.read().unwrap().as_ref().unwrap()["selectedServerId"],
        "node-a",
        "对账成功前不得伪造 R"
    );
    assert_eq!(rt.status().error_code.as_deref(), Some(code::EXIT_MISMATCH));
    assert!(
        errors
            .lock()
            .unwrap()
            .iter()
            .any(|(_, error_code)| error_code == code::EXIT_MISMATCH),
        "双失败必须通知 UI"
    );

    let recovered_api = AttestingManagementApi::new("Node A");
    assert_eq!(
        rt.reconcile_persisted_selector_with_api(
            rt.core_generation(),
            intent_generation,
            &recovered_api,
        )
        .await,
        SelectorReconcileOutcome::Applied
    );
    assert_eq!(
        rt.current_config.read().unwrap().as_ref().unwrap()["selectedServerId"],
        "node-b"
    );
    assert_eq!(config_changed.load(Ordering::SeqCst), 1);
    assert!(rt.status().error_code.is_none(), "恢复后清理本事务告警");
}

/// 候选探测完成后、selector PUT 在飞期间，订阅刷新仍可能替换目标节点。事务末尾必须重算指纹并
/// 恢复旧出口；只在测速前检查一次会把运行核旧参数成员误当成磁盘新节点提交成功。
#[tokio::test]
async fn auto_failover_rolls_back_when_candidate_changes_during_selector_put() {
    let (rt, _dir) = test_runtime();
    let config = two_node_config(7890, "node-a");
    rt.config.save_full(&config).expect("seed D");
    mark_running_with_snapshot(&rt, &config);
    let candidate = RuntimeCandidate {
        id: "node-b".to_string(),
        name: "Node B".to_string(),
        tag: "Node B".to_string(),
    };
    let fingerprint = current_server_fingerprints(&config)
        .remove("node-b")
        .expect("candidate fingerprint");
    let config_manager = Arc::clone(&rt.config);
    let api = AttestingManagementApi::new("Node A").with_on_first_select(move || {
        config_manager
            .update(|latest| {
                let server = latest
                    .get_mut("servers")
                    .and_then(Value::as_array_mut)
                    .and_then(|servers| servers.iter_mut().find(|server| server["id"] == "node-b"))
                    .expect("node-b exists");
                server["port"] = serde_json::json!(19003);
                Decision::Write(())
            })
            .expect("inject subscription replacement");
    });

    let outcome = rt
        .auto_hot_switch_transaction_with_api(
            rt.core_generation(),
            "node-a",
            &candidate,
            &fingerprint,
            &api,
        )
        .await;

    assert_eq!(outcome, AutoHotSwitchOutcome::Failed);
    let after_disk = rt.config.current().unwrap();
    assert_eq!(after_disk["selectedServerId"], "node-a");
    assert_eq!(
        after_disk["servers"][1]["port"], 19003,
        "并发订阅变更必须保留在 D"
    );
    let after_runtime = rt.current_config.read().unwrap().clone().unwrap();
    assert_eq!(after_runtime["selectedServerId"], "node-a");
    assert_eq!(
        after_runtime["servers"][1]["port"], 18002,
        "R 必须继续运行起核时的旧节点参数，等待显式 Apply"
    );
    assert_eq!(
        *api.puts.lock().unwrap(),
        vec![
            ("proxy-selector".to_string(), "Node B".to_string()),
            ("proxy-selector".to_string(), "Node A".to_string()),
        ]
    );
}

// ══════════════════════════════════════════════════════════════════════════════
// 探测前剔除「需重启才能切过去」的候选（`do_switch_io` 在 `probe_runtime_candidates` 之前）
//
// 被剔除者不是「坏节点」。剔除腿分**两个桶**，分界是「该不该告诉用户」：
//  · `not_exit`：候选自身只走内网（组网且不承载全隧道）—— 自动切换永远不该切过去（切了就是把公网
//    流量整体兜底直连），静默排除，不入上报判据；
//  · `needs_restart`：真的「切过去要整核重启」—— 典型是 force-route engaged 节点（承载公网、但只在
//    被选中时才发布内网段，切到/离开它都要增删段规则）。它们进得了 `node_tags`、进得了 probe pool
//    成员，`plan_runtime_candidates` 的四类排除一条都不命中，却必然在 route 投影 guard 被拒掉：
//    `do_switch_io` 返 false ⇒ 不计熔断 ⇒ 约 90 秒后原样重来一轮全量探测，永不成功。
// 第三态是**本轮无从判定**（停核窗口 / 基准过期）：整轮作废，一个都不许记账 —— 记了就是把
// 「用户刚点了停止」报成「自动切换帮不上忙」。
// ══════════════════════════════════════════════════════════════════════════════

use crate::runtime::auto_switch::{switch_blocked_by_restart, RuntimeCandidatePlan};

/// 只走内网的 WireGuard 组网节点：显式 `allowInternet=false` ⇒ 不承载全隧道。
/// 地址用 127.0.0.1 顺带保证它不被判成 WARP（WARP 恒是云出口，会反过来承载全隧道）。
fn mesh_only_wg_node(id: &str, name: &str) -> Value {
    serde_json::json!({
        "id": id,
        "name": name,
        "protocol": "wireguard",
        "address": "127.0.0.1",
        "port": 51820,
        "wireguardSettings": {
            "privateKey": "cG9sYXJpcy10ZXN0LXByaXZhdGUta2V5LTAwMDA9",
            "peerPublicKey": "cG9sYXJpcy10ZXN0LXBlZXItcHVibGljLWtleTA9",
            "allowedIPs": ["10.10.0.0/24"],
            "allowInternet": false,
        },
    })
}

/// **承载公网**的 force-route engaged WireGuard 节点：`allowInternet=true`（= 全隧道，它就是用户
/// 的上网路径）+ `alwaysRouteSubnets=false` + 有段可发 ⇒ 切到/离开它都要增删段规则 ⇒ 不可热切。
///
/// 它正是 H1 撤回的那条错误停摆判据（`sel_only_forces_subnets`，三项里没有 `allow_internet`）会
/// 命中的形态。心跳**必须**照常探它；切不过去这件事由本剔除腿记进 `needs_restart` 并上报。
fn force_route_wg_node(id: &str, name: &str) -> Value {
    serde_json::json!({
        "id": id,
        "name": name,
        "protocol": "wireguard",
        "address": "127.0.0.1",
        "port": 51820,
        "wireguardSettings": {
            "privateKey": "cG9sYXJpcy10ZXN0LXByaXZhdGUta2V5LTAwMDA9",
            "peerPublicKey": "cG9sYXJpcy10ZXN0LXBlZXItcHVibGljLWtleTA9",
            "allowedIPs": ["10.30.0.0/24"],
            "allowInternet": true,
            "alwaysRouteSubnets": false,
        },
    })
}

/// 只走内网的 Tailscale 组网节点：**无 exit node** ⇒ `meshAllowsInternet` 假
/// （TS 的出网开关就是 exit node 本身，没有独立的 allowInternet 语义）。
fn mesh_only_ts_node(id: &str, name: &str) -> Value {
    serde_json::json!({
        "id": id,
        "name": name,
        "protocol": "tailscale",
        "tailscaleSettings": { "hostname": "polaris-test" },
    })
}

/// 只走内网的 OpenVPN 组网节点：`meshRoutes` 非空（= 取得组网资格）且显式关 `redirect_gateway`。
/// 两者缺一都不成立 —— 缺段则 `is_mesh_node` 假、缺开关则默认承载全隧道。
fn mesh_only_openvpn_node(id: &str, name: &str) -> Value {
    serde_json::json!({
        "id": id,
        "name": name,
        "protocol": "openvpn-client",
        "address": "127.0.0.1",
        "port": 1194,
        "meshRoutes": ["10.20.0.0/16"],
        "openvpnClientSettings": { "redirect_gateway": false },
    })
}

/// [`two_node_config`] + 追加节点 + 指定选中节点。
fn config_with_nodes(selected: &str, extra: &[Value]) -> Value {
    let mut cfg = two_node_config(7890, "node-a");
    cfg["servers"]
        .as_array_mut()
        .expect("servers 必须是数组")
        .extend(extra.iter().cloned());
    cfg["selectedServerId"] = Value::String(selected.to_string());
    cfg
}

/// 同 [`mark_running_with_snapshot`]，但 id→tag 表**从配置里的节点名派生**。
///
/// 不能沿用写死 node-a/node-b 的那份：本节的组网节点不在那两个 id 里 ⇒ 它们的 tag 解析不到 ⇒
/// `plan_hot_switch` 会因「解析不到目标 tag」而退回重启 —— 于是真值表整片变绿，却**不是**因为
/// 被测的 route 投影 guard 生效。那种绿没有信息量。
fn mark_running_with_named_snapshot(rt: &ProxyRuntime, cfg: &Value) {
    mark_running(rt);
    let uc: UserConfig = serde_json::from_value(cfg.clone()).expect("测试配置应可解析");
    let id_to_tag: BTreeMap<String, String> = uc
        .servers
        .iter()
        .map(|s| (s.id.clone(), s.name.clone()))
        .collect();
    *rt.switch_snapshot.write().unwrap() = Some(SwitchSnapshot {
        id_to_tag,
        fingerprints: node_fingerprints::modified_table(&uc.servers),
        dirty_fingerprints: node_fingerprints::dirty_table(&uc.servers),
        ..Default::default()
    });
    *rt.current_config.write().unwrap() = Some(cfg.clone());
}

/// 把一组 id 造成候选计划（tag = 名字，与上面的快照同源）。
fn plan_of(cfg: &Value, ids: &[&str]) -> RuntimeCandidatePlan {
    let servers = cfg["servers"].as_array().expect("servers 必须是数组");
    let candidates = ids
        .iter()
        .map(|id| {
            let server = servers
                .iter()
                .find(|s| s["id"] == Value::String((*id).to_string()))
                .unwrap_or_else(|| panic!("候选 {id} 必须在配置里"));
            RuntimeCandidate {
                id: (*id).to_string(),
                name: server["name"].as_str().expect("name").to_string(),
                tag: server["name"].as_str().expect("name").to_string(),
            }
        })
        .collect();
    RuntimeCandidatePlan {
        candidates,
        ..Default::default()
    }
}

fn candidate_ids(plan: &RuntimeCandidatePlan) -> Vec<String> {
    plan.candidates.iter().map(|c| c.id.clone()).collect()
}

/// 真值表①（正向对照）：当前出口与候选都是普通代理节点 → 保留，`needs_restart` 不动。
///
/// 没有这一条，下面三条「剔除」全部可以被一个恒真的剔除谓词满足 —— 那正是本门要排除的失效模式。
#[test]
fn plain_candidate_survives_the_pre_probe_eligibility_filter() {
    let (rt, _dir) = test_runtime();
    let cfg = two_node_config(7890, "node-a");
    mark_running_with_named_snapshot(&rt, &cfg);

    let mut plan = plan_of(&cfg, &["node-b"]);
    assert!(rt.retain_hot_switchable_candidates(rt.core_generation(), &cfg, &mut plan));

    assert_eq!(candidate_ids(&plan), vec!["node-b".to_string()]);
    assert_eq!(plan.not_exit, 0);
    assert_eq!(plan.needs_restart, 0);
}

/// 真值表②：当前出口是普通节点，候选里混着三种形态的「只走内网」组网节点 → 三个全部剔除、
/// 普通候选留下，且它们进的是 `not_exit` 桶而**不是** `needs_restart`。
///
/// 桶归属就是判据：切到这类节点等于把公网流量整体兜底直连，那不是「自动切换帮不上忙」，是
/// 「这个节点本来就不该是出口」。记进 `needs_restart` 会让每一轮都朝用户弹一条他无从下手的告警。
///
/// 三种形态各自的「关外网」表达不同（TS 无 exit node / WG 关 allowInternet /
/// OpenVPN 关 redirect_gateway + meshRoutes 非空），但落到 `mesh_node_carries_full_tunnel`
/// 是同一条判据 —— 少测哪一种，那一种在协议白名单收窄时就会静默漏回来。
#[test]
fn mesh_only_candidates_land_in_the_not_exit_bucket() {
    let (rt, _dir) = test_runtime();
    let cfg = config_with_nodes(
        "node-a",
        &[
            mesh_only_ts_node("ts-mesh", "TS Mesh"),
            mesh_only_wg_node("wg-mesh", "WG Mesh"),
            mesh_only_openvpn_node("ovpn-mesh", "OVPN Mesh"),
        ],
    );
    mark_running_with_named_snapshot(&rt, &cfg);

    let mut plan = plan_of(&cfg, &["node-b", "ts-mesh", "wg-mesh", "ovpn-mesh"]);
    assert!(rt.retain_hot_switchable_candidates(rt.core_generation(), &cfg, &mut plan));

    assert_eq!(
        candidate_ids(&plan),
        vec!["node-b".to_string()],
        "只走内网的组网节点不是出口候选，探测它们是纯浪费"
    );
    assert_eq!(plan.not_exit, 3);
    assert_eq!(
        plan.needs_restart, 0,
        "它们不入上报判据 —— 记进 needs_restart 就是把「这节点本来就不该切过去」报成故障"
    );
    assert!(
        !switch_blocked_by_restart(&plan),
        "候选还剩且 needs_restart=0 ⇒ 不上报"
    );
}

/// **承载公网的 force-route engaged 候选进 `needs_restart`，不进 `not_exit`**。
///
/// 这是 H1 的正面：这类节点 `allowInternet=true`，是用户真正的上网路径，心跳必须照常探它；
/// 它切不过去纯粹是「热切可行性」问题（段规则要增删），而那**恰恰**是该告诉用户的那件事。
/// 把它归进 `not_exit`（静默）或让停摆守卫把它的心跳整条静音，都会造出静默盲区。
#[test]
fn force_route_candidate_lands_in_the_needs_restart_bucket() {
    let (rt, _dir) = test_runtime();
    let cfg = config_with_nodes("node-a", &[force_route_wg_node("wg-force", "WG Force")]);
    mark_running_with_named_snapshot(&rt, &cfg);

    let mut plan = plan_of(&cfg, &["node-b", "wg-force"]);
    assert!(rt.retain_hot_switchable_candidates(rt.core_generation(), &cfg, &mut plan));

    assert_eq!(candidate_ids(&plan), vec!["node-b".to_string()]);
    assert_eq!(plan.not_exit, 0, "它承载公网，不是「不该作出口」那一类");
    assert_eq!(plan.needs_restart, 1);
}

/// **运行核基准已过期时整轮作废**，钉的是 per-candidate 那条作废腿。
///
/// 为什么单独一条：下面那条停核窗口门在**两条**作废腿（per-candidate `Void` + 末尾世代/运行态
/// 复查）之下都成立，单删任一条它照绿 —— 那正是「两扇门之间的缝」。这里用一个核**仍在跑**的作废
/// 形态把 per-candidate 腿单独钉出来：候选 id 恰是运行核当前出口 ⇒ `switched` 与运行核配置逐字节
/// 全等 ⇒ `classify_switch` 返 `Unchanged`（生产上只可能是运行核在读到基准之后被换掉了）。
///
/// **变异锁**：把 `CandidateSwitchPlan::Void => return false` 改成 `=> needs_restart += 1` ⇒ 转红
/// （末尾那道复查在这里帮不上忙 —— 核确实还在跑）。
#[test]
fn stale_runtime_baseline_voids_the_round_while_the_core_is_still_running() {
    let (rt, _dir) = test_runtime();
    let cfg = two_node_config(7890, "node-a");
    mark_running_with_named_snapshot(&rt, &cfg);

    let mut plan = plan_of(&cfg, &["node-a"]);
    assert!(rt.core_running(), "正向对照：核确实还在跑");
    assert!(
        !rt.retain_hot_switchable_candidates(rt.core_generation(), &cfg, &mut plan),
        "运行核基准已过期 ⇒ 整轮作废，不是「这个候选要重启」"
    );
    assert_eq!(plan.needs_restart, 0);
}

/// **缺热切基准快照时整轮作废**，钉的是循环外那道快照闸。
///
/// 为什么必须单独一道：`classify_switch` 对「无热切换基准快照」返 `Fallback`，而剔除腿把
/// `Fallback` 映射成 `NeedsRestart`（那条映射本身是对的 —— 走到那里的 `Fallback` 只该剩
/// 「目标包含本核未规划的自动物理出口」）。快照缺失是**运行时**属性、对每个候选都一样，
/// 若不在循环外挡下，每个候选各返一次 `Fallback` ⇒ 候选清零 + `needs_restart > 0`
/// ⇒ 向用户误报一次「需手动切换」，而真相是本轮压根无从判断。
///
/// **变异锁**：删掉 `retain_hot_switchable_candidates` 里那道 `switch_snapshot.is_none()`
/// 早退 ⇒ 第二条断言转红（返 true 且 `needs_restart == 1`）。
#[test]
fn missing_switch_snapshot_voids_the_round_instead_of_counting_needs_restart() {
    let (rt, _dir) = test_runtime();
    let cfg = two_node_config(7890, "node-a");
    mark_running_with_named_snapshot(&rt, &cfg);
    let generation = rt.core_generation();

    // 正向对照：快照在时这个候选留得下 —— 否则下面的「作废」可能只是它本来就被剔。
    let mut before = plan_of(&cfg, &["node-b"]);
    assert!(rt.retain_hot_switchable_candidates(generation, &cfg, &mut before));
    assert_eq!(candidate_ids(&before), vec!["node-b".to_string()]);

    // 只抽掉快照，核仍在跑、`current_config` 仍在。
    *rt.switch_snapshot.write().unwrap() = None;
    assert!(rt.core_running(), "正向对照：核确实还在跑");

    let mut plan = plan_of(&cfg, &["node-b"]);
    assert!(
        !rt.retain_hot_switchable_candidates(generation, &cfg, &mut plan),
        "缺基准快照 ⇒ 整轮作废，不是「这个候选要重启」"
    );
    assert_eq!(
        plan.needs_restart, 0,
        "作废的一轮不许给任何桶记账 —— 记了就会误报「需手动切换」"
    );
}

/// **停核窗口不得被记成「候选全都需要重启」**（M2）。
///
/// 停核时序：`stop_inner` 先把 `ProxyStatus::default()` 写下去（`running=false`），稍后才清
/// `switch_snapshot`，而 `current_config` **刻意保留**。心跳若正好走在这条缝里，每个候选的
/// `classify_switch` 都返 `NotRunning` —— 那是**运行时**的属性、对每个候选都一样，压成
/// 「切不过去」就变成「全部需要重启」⇒ 往刚被清零的状态里写一条非致命错误 ⇒ 渲染端判成终态故障，
/// 而用户刚点的是停止。
///
/// **变异锁**：把剔除腿的**两条**作废腿（per-candidate `Void` + 末尾世代/运行态复查）**同时**
/// 去掉 ⇒ 三条断言全红。只删其中一条本门照绿（两条腿在停核窗口下互为冗余）——
/// per-candidate 那条由上面的 `stale_runtime_baseline_voids_the_round_while_the_core_is_still_running`
/// 单独钉住；末尾那条**没有行为门**：要构造「循环最后一个候选判完之后才停核」需要在剔除腿内部
/// 插手，本机造不出来。射程如实记在这里，别把它当成已被覆盖。
#[test]
fn stop_window_voids_the_round_instead_of_counting_candidates_as_needs_restart() {
    let (rt, _dir) = test_runtime();
    let cfg = two_node_config(7890, "node-a");
    mark_running_with_named_snapshot(&rt, &cfg);
    let generation = rt.core_generation();

    // 正向对照：核在跑时这个候选是留得下的（否则下面的「作废」可能只是它本来就被剔）。
    let mut before = plan_of(&cfg, &["node-b"]);
    assert!(rt.retain_hot_switchable_candidates(generation, &cfg, &mut before));
    assert_eq!(candidate_ids(&before), vec!["node-b".to_string()]);

    // 停核窗口：状态已清零，`current_config` 仍在。
    *rt.status.write().unwrap() = ProxyStatus::default();

    let mut plan = plan_of(&cfg, &["node-b"]);
    assert!(
        !rt.retain_hot_switchable_candidates(generation, &cfg, &mut plan),
        "停核窗口必须整轮作废，调用方据此早退且不上报"
    );
    assert_eq!(
        plan.needs_restart, 0,
        "作废的一轮不许给任何桶记账 —— 记了就是把「用户刚点了停止」报成故障"
    );
    assert!(
        !switch_blocked_by_restart(&plan),
        "上报判据必须为假：AUTO_SWITCH_NEEDS_RESTART 不得在停核窗口发出"
    );
}

/// 真值表③ + ④：当前出口**本身**是只走内网的组网节点时，翻转方向相反但同样不可热切 ⇒
/// 全部候选被剔除、计划变空（`do_switch_io` 据此早退，见下面的接线门），且 `needs_restart` = 2。
#[test]
fn mesh_only_current_exit_drops_every_plain_candidate() {
    let (rt, _dir) = test_runtime();
    let cfg = config_with_nodes("wg-mesh", &[mesh_only_wg_node("wg-mesh", "WG Mesh")]);
    mark_running_with_named_snapshot(&rt, &cfg);

    let mut plan = plan_of(&cfg, &["node-a", "node-b"]);
    assert!(rt.retain_hot_switchable_candidates(rt.core_generation(), &cfg, &mut plan));

    assert!(
        plan.candidates.is_empty(),
        "离开只走内网的组网节点同样要重下发 route 规则"
    );
    assert_eq!(plan.needs_restart, 2);
}

/// 同源门：剔除腿与**提交事务**对同一个候选必须给出同一裁定。
///
/// 这是「共用一份判据」而不是「两处各写一遍」的可观测后果。分歧的形态不是报错而是空转：
/// 剔除腿放行 → 整轮真实协议链探测跑完 → 提交时才 `NotEligible` → 不计熔断 → 下一轮重来。
#[tokio::test]
async fn dropped_candidate_is_exactly_what_the_commit_transaction_refuses() {
    let (rt, _dir) = test_runtime();
    // 用 force-route engaged 节点（而不是只走内网那种）：只有它会真的走到
    // `candidate_switch_plan` —— 只走内网的候选在那之前就被 `not_exit` 静默排掉，
    // 拿它做同源门等于两边压根没比同一条判据。
    let cfg = config_with_nodes("node-a", &[force_route_wg_node("wg-force", "WG Force")]);
    rt.config.save_full(&cfg).expect("seed D");
    mark_running_with_named_snapshot(&rt, &cfg);

    let mut plan = plan_of(&cfg, &["wg-force"]);
    assert!(rt.retain_hot_switchable_candidates(rt.core_generation(), &cfg, &mut plan));
    assert!(plan.candidates.is_empty(), "剔除腿必须拒");
    assert_eq!(plan.needs_restart, 1);

    let candidate = RuntimeCandidate {
        id: "wg-force".to_string(),
        name: "WG Force".to_string(),
        tag: "WG Force".to_string(),
    };
    let fingerprint = current_server_fingerprints(&cfg)
        .remove("wg-force")
        .expect("candidate fingerprint");
    let api = AttestingManagementApi::new("Node A");
    let outcome = rt
        .auto_hot_switch_transaction_with_api(
            rt.core_generation(),
            "node-a",
            &candidate,
            &fingerprint,
            &api,
        )
        .await;

    assert_eq!(
        outcome,
        AutoHotSwitchOutcome::NotEligible,
        "提交腿必须拒同一个候选"
    );
    assert!(
        api.puts.lock().unwrap().is_empty(),
        "不可热切的候选不得产生任何 selector PUT"
    );
    assert_eq!(
        rt.config.current().unwrap()["selectedServerId"],
        "node-a",
        "被拒的候选不得改动 D"
    );
}

/// 接线门（源码级）：剔除必须发生在**探测之前**，且两条候选日志都带上 `需重启` 计数。
///
/// # 为什么这一条是源码级而不是行为级
///
/// `do_switch_io` 的返回值对本缺陷**不可观测**：剔除被摘掉后它会照常探测、探完全不可达、
/// `select_best_candidate` 返回 `None`，仍旧返回 `false` —— 与「早退」外部同值。真正的差别是
/// 「探没探」，而那要么需要真起核 + 真管理面（真机门），要么要给生产腿插一个只为测试存在的观测点。
/// 故此处守的是**顺序与取材**这两个可静态判定的属性；候选到底该不该被剔除由上面三条行为门守。
#[test]
fn pre_probe_filter_runs_before_probing_and_both_logs_carry_the_count() {
    let body = method_body(
        &module_code("runtime/proxy"),
        "    async fn do_switch_io(self: &Arc<Self>, machine: &mut AutoSwitchMachine, \
         reason: &str) -> bool {",
    );
    let filter = body
        .find("self.retain_hot_switchable_candidates(")
        .expect("do_switch_io 必须在探测前剔除需重启的候选");
    let probe = body
        .find("probe_runtime_candidates(")
        .expect("探测锚点：本门若因改名找不到它，必须转红而不是静默放行");
    assert!(
        filter < probe,
        "剔除放在探测之后 = 整轮探测照样白跑，本修复归零"
    );

    // 第三处 `candidate_plan.needs_restart > 0` 是探测全败早退的上报判据，不是日志实参，减掉它。
    assert_eq!(
        body.matches("candidate_plan.needs_restart").count()
            - body.matches("candidate_plan.needs_restart > 0").count(),
        2,
        "两条候选日志（全被剔除的 warn + 进入探测的 info）都必须打出 需重启 计数"
    );
    assert_eq!(
        body.matches("需重启={}").count(),
        2,
        "计数只入参不入格式串 = 日志少一列，排查时看不出这一类排除"
    );
    assert_eq!(
        body.matches("不可作出口={}").count(),
        2,
        "两个桶必须都进日志：只打 需重启 会让「候选被静默排除」这一类在排查时完全隐身"
    );
}

/// 快速连续切换必须在唯一生产入口串行，且拿锁后再看 lifecycle 真值。底层 Mutex 的 FIFO 语义由
/// tokio 提供；本门守的是公开入口先持锁，再进入不重入的执行半边，从而覆盖判定/PUT/commit 整条流水线。
#[test]
fn switch_mode_serializes_before_reading_lifecycle_state() {
    let wrapper = method_body(
        &module_code("runtime/proxy"),
        "    pub async fn switch_mode_with(",
    );
    let lock = wrapper
        .find("self.switch_serial.lock().await")
        .expect("switch_mode_with 必须取得配置入核单飞锁");
    let call = wrapper
        .find("self.switch_mode_locked(")
        .expect("持锁后必须进入执行半边");
    assert!(lock < call, "必须先取锁再执行入核流水线");

    let body = method_body(
        &module_code("runtime/proxy"),
        "    async fn switch_mode_locked(",
    );
    let gate = body
        .find("if self.gate.is_busy()")
        .expect("lifecycle 判定锚点");
    let execute = body.find("SwitchExecutor.execute").expect("热切换执行锚点");
    let commit = body
        .find("self.commit_applied(&new_config)")
        .expect("热切换提交锚点");
    assert!(
        gate < execute && execute < commit,
        "锁须覆盖判定、PUT 与 commit 全链路"
    );
}

/// 腿 0（顺序门）：lifecycle 在飞 → Pending 暂存，**即使核看起来没在跑**。
/// 与 apply_pending 的 H-1 同型：先判「核未运行」会让 restart 空窗内的切节点被永久丢弃。
#[tokio::test]
async fn switch_mode_pending_when_lifecycle_busy_even_though_core_appears_stopped() {
    let (rt, _dir) = test_runtime();
    rt.gate.begin();
    assert!(!rt.core_running(), "前提：此刻看起来「未运行」");

    let out = rt.switch_mode(two_node_config(7891, "node-b")).await;
    assert_eq!(
        out,
        SwitchOutcome::Pending,
        "depth>0 必须先判 → Pending；先判「未运行」会静默丢弃本次切换"
    );
    assert!(
        rt.gate.pending().switch_id.is_some(),
        "Pending 必须在 gate 上登记 switch_id，否则 end() 排空时无从重放"
    );
    assert!(
        rt.pending_switch.read().unwrap().is_some(),
        "必须暂存配置载荷"
    );
}

/// 腿 0.5：核未运行 → 仅更新 current_config（下次 start 生效），不重启不热切。
#[tokio::test]
async fn switch_mode_not_running_only_updates_config() {
    let (rt, _dir) = test_runtime();
    let cfg = two_node_config(7891, "node-b");
    assert_eq!(rt.switch_mode(cfg.clone()).await, SwitchOutcome::NotRunning);
    assert_eq!(rt.current_config.read().unwrap().clone(), Some(cfg));
}

/// 腿 1（上游 bug#5）：逐字节全等 → Unchanged，绝不重启。
/// 键序不敏感：ConfigManager 落盘/回读会改键序，裸 == 会把「没变」误判成结构变更 → 无谓断流。
#[tokio::test]
async fn switch_mode_unchanged_is_key_order_insensitive() {
    let (rt, _dir) = test_runtime();
    let cfg = two_node_config(7891, "node-a");
    mark_running_with_snapshot(&rt, &cfg);

    // 同一份配置，逐键**反序**重建（模拟落盘→回读改了键序）。
    // 注：serde_json 未开 preserve_order 时 Map 是 BTreeMap（键恒排序），此时本断言退化为
    // 「同内容 → Unchanged」——仍是要守的不变式，只是失去了「乱序」这一维。
    let mut reordered = serde_json::Map::new();
    let mut keys: Vec<String> = cfg.as_object().unwrap().keys().cloned().collect();
    keys.reverse();
    for k in keys {
        reordered.insert(k.clone(), cfg[&k].clone());
    }
    let reordered = Value::Object(reordered);
    assert_eq!(
        rt.switch_mode(reordered).await,
        SwitchOutcome::Unchanged,
        "键序不同但内容相同 → Unchanged（stable_stringify 归一），不得触发重启"
    );
    assert!(
        !rt.gate.pending().restart_pending,
        "Unchanged 腿绝不能排程重启"
    );
}

/// 磁盘 writer 的落盘顺序不等于它们 spawn 出来的 switch task 执行顺序。旧候选若最后执行，
/// 会造成“配置文件/界面是新版，运行核却退回旧版”的双真值。
#[tokio::test]
async fn persisted_switch_discards_an_out_of_order_stale_broadcast() {
    let (rt, _dir) = test_runtime();
    let running = two_node_config(7891, "node-a");
    mark_running_with_snapshot(&rt, &running);

    let stale = two_node_config(7891, "node-b");
    let mut latest = running.clone();
    latest["language"] = serde_json::json!("zh-CN");
    latest["privacyPasswordHash"] = serde_json::json!("salt$hash");
    rt.config.save_full(&latest).expect("落盘最新配置");
    let stale_intent = rt.register_selector_intent();

    assert_eq!(
        rt.switch_persisted_config_if_current(stale, false, stale_intent, |_| {})
            .await,
        None,
        "过期广播不得触碰运行核"
    );
    assert_eq!(
        rt.current_config.read().unwrap().as_ref(),
        Some(&running),
        "作废腿不得把 current_config 退回旧快照"
    );

    let mut broadcast_view = latest.clone();
    crate::commands::config::strip_privacy_secrets(&mut broadcast_view);
    let current_intent = rt.register_selector_intent();
    assert_eq!(
        rt.switch_persisted_config_if_current(broadcast_view, false, current_intent, |_| {},)
            .await,
        Some(SwitchOutcome::NoOp),
        "当前广播在隐私投影后仍必须被接受"
    );

    // 内容完全相同也要按 intent 代次作废：用户可再次选择同一目标，值相等不等于所有权相同。
    let superseded_intent = rt.register_selector_intent();
    let _newer_same_value_intent = rt.register_selector_intent();
    assert_eq!(
        rt.switch_persisted_config_if_current(latest, false, superseded_intent, |_| {},)
            .await,
        None,
        "同值旧意图也必须作废"
    );
}

/// 腿 3-热切：切节点 → 走热切腿。此处**无真核** → gRPC 连不上 → executor 返 ClientNotReady
/// → 按契约退回去抖重启（而非静默吞掉变更）。
///
/// 这条同时锁死两件事：① 切节点确实被判为热切腿（否则不会去连 gRPC）；② 热切不可用时**必**回退重启。
#[tokio::test]
async fn switch_mode_node_switch_falls_back_to_restart_when_grpc_unavailable() {
    let (rt, _dir) = test_runtime();
    let cfg = two_node_config(7891, "node-a");
    mark_running_with_snapshot(&rt, &cfg);

    // mark_running 给的是假 apiPort（19090，无核监听）→ 连不上 → ClientNotReady。
    let out = rt.switch_mode(two_node_config(7891, "node-b")).await;
    assert_eq!(
        out,
        SwitchOutcome::Restarting,
        "热切换不可用（gRPC 连不上）必须退回重启兜底，绝不能静默吞掉切节点"
    );
    assert!(
        rt.current_config
            .read()
            .unwrap()
            .as_ref()
            .and_then(|c| c.get("selectedServerId").and_then(Value::as_str))
            == Some("node-b"),
        "回退重启腿也必须把 current_config 对账到新配置"
    );
}

/// 腿 3-重启：改 norm 内字段（mixedPort）→ 结构性变更 → 去抖重启，**不**热切。
#[tokio::test]
async fn switch_mode_norm_field_change_takes_restart_leg() {
    let (rt, _dir) = test_runtime();
    let cfg = two_node_config(7891, "node-a");
    mark_running_with_snapshot(&rt, &cfg);

    // 只改端口（norm 内字段）→ plan_hot_switch 的 norm 前提失败 → kind=None → Restart。
    let out = rt.switch_mode(two_node_config(7899, "node-a")).await;
    assert_eq!(out, SwitchOutcome::Restarting, "norm 内字段变更必须走重启");
}

// ── P4「保存不重启」（spec §2.5 Q4）：defer_restart 的射程与记账 ──────────────────────
//
// 这一组与 switch-engine 的 `defer_restart_*` 五条互补：那边钉纯决策，这边钉**接线与副作用**
//（真没排重启 / 记了账 / 账在核起来时结清 / 预告与实际同源）。

/// 结构性变更 + `defer_restart=true` → 落 Defer 腿：**不排重启**，但记下欠账。
///
/// 变异对照：把 `switch_mode_with` 里传给 `DecisionInput` 的 `defer_restart` 硬编码成 `false`
/// → 本条第一个断言转红（回到 Restarting）。
#[tokio::test]
async fn defer_restart_flag_defers_structural_change_and_records_debt() {
    let (rt, _dir) = test_runtime();
    let cfg = two_node_config(7891, "node-a");
    mark_running_with_snapshot(&rt, &cfg);
    // 起核快照 = 待应用差集的分母，生产里由 start_inner 与 switch_snapshot 同刻装上。
    *rt.startup_snapshot.write().unwrap() = Some(cfg.clone());

    // 同一份输入在 defer_restart=false 时是 Restarting（见 switch_mode_norm_field_change_takes_restart_leg）。
    let out = rt
        .switch_mode_with(two_node_config(7899, "node-a"), true)
        .await;
    assert_eq!(
        out,
        SwitchOutcome::Deferred,
        "「保存」腿的结构性变更必须落 Defer"
    );
    assert!(
        !rt.gate.pending().restart_pending,
        "「保存不重启」若还排了重启，这个按钮就没有存在的意义"
    );
    assert!(
        rt.pending_changes().restart_deferred,
        "非节点结构性变更在三个数组里看不见 → 必须靠这一位让条不撒谎"
    );
}

/// 欠账只在**核真按磁盘配置起来**那一刻结清；其后的 NoOp / 热切腿都不清。
///
/// 变异对照：把清账点从 `startup_snapshot` 同刻挪进 NoOp 腿 → 第二个断言转红
///（用户切个语言就把「还差一次重启」的提示抹掉了，欠账仍在、提示没了）。
#[tokio::test]
async fn deferred_debt_survives_noop_and_clears_only_on_core_start() {
    let (rt, _dir) = test_runtime();
    let mut cfg = two_node_config(7891, "node-a");
    cfg.as_object_mut()
        .unwrap()
        .insert("language".into(), serde_json::json!("zh-CN"));
    mark_running_with_snapshot(&rt, &cfg);
    *rt.startup_snapshot.write().unwrap() = Some(cfg.clone());

    let mut saved = cfg.clone();
    saved
        .as_object_mut()
        .unwrap()
        .insert("mixedPort".into(), serde_json::json!(7899));
    assert_eq!(
        rt.switch_mode_with(saved.clone(), true).await,
        SwitchOutcome::Deferred
    );
    assert!(rt.restart_deferred.load(Ordering::SeqCst));

    // 之后基于仍在运行的旧配置切语言（NoOp 腿）：保存腿没有偷偷推进 current_config；NoOp 也没有
    // 把欠下的 mixedPort 送进核，故不得清账。
    let mut next = cfg.clone();
    next.as_object_mut()
        .unwrap()
        .insert("language".into(), serde_json::json!("en-US"));
    assert_eq!(rt.switch_mode(next).await, SwitchOutcome::NoOp);
    assert!(
        rt.restart_deferred.load(Ordering::SeqCst),
        "NoOp 腿不把配置送进核 → 欠账必须留着"
    );

    // 正向对照：有分母时读出口确实报 true —— 否则下面那条「不报」是恒真断言，没有信息量。
    assert!(rt.pending_changes().restart_deferred);

    // 无起核快照（= 核没在跑）时读出口恒报 false：即便记账位还没被复位，
    // 「待应用」也谈不上 —— 这条不变式写死在 `pending_changes` 的 empty() 腿上。
    *rt.startup_snapshot.write().unwrap() = None;
    assert!(
        !rt.pending_changes().restart_deferred,
        "没有运行核这个分母时不得报欠账"
    );
}

/// 暂存重放必须**带着 `defer_restart` 一起**存取。
///
/// 它是「本次落盘由谁触发」的意图，不是配置内容的一部分：丢了它，用户在核重启窗口内点的那次
/// 「保存」会在几秒后自己触发一次重启 —— 恰是「保存不重启」承诺的反面，且现象是延迟的、极难归因。
///
/// 变异对照：把 `pending_switch` 的第三元写死 `false`（或存取时丢弃它）→ 本条转红。
#[tokio::test]
async fn pending_switch_carries_the_defer_restart_intent_across_replay() {
    let (rt, _dir) = test_runtime();
    rt.gate.begin(); // lifecycle 在飞 → 走腿 0 暂存
    let cfg = two_node_config(7891, "node-b");
    assert_eq!(
        rt.switch_mode_with(cfg.clone(), true).await,
        SwitchOutcome::Pending
    );
    let id = rt
        .pending_switch
        .read()
        .unwrap()
        .as_ref()
        .map(|(id, _, _)| *id)
        .expect("在飞时必须暂存");
    let (replayed, defer) = rt
        .take_pending_switch(Some(id))
        .expect("按 id 认领应取得载荷");
    assert_eq!(replayed, cfg, "重放的配置必须逐字节是暂存那份");
    assert!(defer, "「保存不重启」的意图必须跟着载荷一起被取回");
}

/// 排空腿的**接线**守卫：重放走的必须是 `switch_mode_with(cfg, defer_restart)`。
///
/// 上一条证明「存进去、取回来」；这条证明取回来的那一位真被喂回决策 ——
/// 调用 `switch_mode(cfg)`（丢掉第二个参数）在类型上完全合法，只有这道门能抓。
#[test]
fn replay_leg_feeds_the_defer_restart_intent_back_into_the_decision() {
    let body = method_body(
        &module_code("runtime/proxy"),
        "    pub(super) fn finish_lifecycle(self: &Arc<Self>, kind: LifecycleKind) {",
    );
    assert!(
        body.contains("me.switch_mode_with(cfg, defer_restart).await"),
        "排空重放必须把取回的意图喂回去；调 switch_mode(cfg) 会静默降级成「保存后仍重启」"
    );
}

/// 清账点的**接线**守卫：`restart_deferred` 必须在 `startup_snapshot` 被写/被清的**同一个方法体**里复位。
///
/// 单测够不着这两处（`start_inner` 要真起核、`stop_inner` 会碰系统 DNS 与路由，本机禁跑触网测试），
/// 故用源码型守卫兜底。它证不了行为，只证「接线没掉」——behavior 那一半由上面两条测试覆盖。
/// 锚点失配即 panic（`method_body` 自带），不会退化成恒真。
#[test]
fn deferred_debt_is_cleared_where_the_startup_snapshot_is_written_and_cleared() {
    let src = module_code("runtime/proxy");
    let started = method_body(&src, "    pub(super) async fn start_inner(");
    assert!(
        started.contains("*snap = Some(config);")
            && started.contains("restart_deferred.store(false"),
        "起核就绪腿必须与写 startup_snapshot 同刻清账 —— 否则核已按新配置起来了，条上还挂着「待应用」"
    );
    let stopped = method_body(
        &src,
        "    pub(super) async fn stop_inner(self: &Arc<Self>) -> Result<bool, String> {",
    );
    assert!(
        stopped.contains("restart_deferred.store(false"),
        "停核腿必须复位欠账 —— 否则停核期间挂着一条谈不上「待应用」的提示，且下次起核前无人清"
    );
}

/// **差集 PUSH 的两侧接线守卫**：差集 = f(分子 `config.current()`，分母 `startup_snapshot` 等)，
/// **两侧都得推**（因果在 [`ProxyRuntime::push_pending_changes`] 头注）。
///
/// 只推分子那一侧是本缺陷的根因（陈先生 2026-07-30 真机「点击未真实生效，依然还是显示立即应用」）：
/// 点「立即应用」→ 后端自驱去抖重启 → 核真按新配置起来了、差集其实已清，但
/// ① 分母侧没人 PUSH；② 前端那条 pull 兜底挂在 `event:proxyStarted`，而该事件**只由命令层**
/// （`commands/proxy.rs` 的 proxy_start/stop/restart）发，内部驱动的重启一个都不发
/// ⇒ store 里的差集停在 `switch_mode` 推的最后一帧（`restartDeferred:true`），条永远停在「立即应用」。
///
/// 单测够不着这三个方法体（要真起核 / 会碰系统 DNS 与路由，本机禁跑触网测试），故用源码型守卫。
/// 变异对照：删掉任一处 `push_pending_changes()` 调用 → 对应断言转红；锚点失配即 panic
/// （`method_body` 自带），不会退化成恒真。
#[test]
fn pending_changes_push_is_wired_on_both_sides_of_the_diff() {
    let src = module_code("runtime/proxy");
    // 分子侧（配置变了）。
    let switched = method_body(&src, "    async fn switch_mode_locked(");
    assert!(
        switched.contains("self.push_pending_changes();"),
        "分子侧（落盘/切节点）必须推 —— 否则改完配置条根本不出现"
    );
    // 分母侧（运行核换了）：start 成功终态 / stop 拆除终态。
    let started = method_body(
        &src,
        "    pub async fn start(self: &Arc<Self>, config: Value) -> Result<ProxyStatus, StartError> {",
    );
    assert!(
        started.contains("self.push_pending_changes();"),
        "起核就绪腿必须推 —— 否则「立即应用」引发的重启落地后没人告诉 UI 差集已清，条停在「立即应用」"
    );
    let stopped = method_body(
        &src,
        "    pub(super) async fn stop_inner(self: &Arc<Self>) -> Result<bool, String> {",
    );
    assert!(
        stopped.contains("self.push_pending_changes();"),
        "停核腿必须推 —— 重启内嵌的这次停核不经命令层，只靠前端 proxyStopped 的 pull 是漏的一半"
    );
}

/// 预告（`classify_staged`）与实际（`switch_mode`）**同源**：同一份候选配置，两者结论必须一致。
///
/// 变异对照：让 `classify_staged` 自己再判一次（哪怕只重写「逐字节全等」那一条）→ 本条转红。
/// 这道门守的是「预告说不重启、实际断了流」——真机上最难归因的一类。
#[tokio::test]
async fn classify_staged_agrees_with_the_leg_switch_mode_actually_takes() {
    let (rt, _dir) = test_runtime();
    let cfg = two_node_config(7891, "node-a");
    mark_running_with_snapshot(&rt, &cfg);

    // ① 逐字节全等 → noOp、不需重启。
    let same = rt.classify_staged(&cfg);
    assert_eq!(same.decision, "noOp");
    assert!(!same.restart_required);

    // ② 本性可热切（换选中节点），但“保存”不得改运行核，因此仍要标为待应用。
    let hot = rt.classify_staged(&two_node_config(7891, "node-b"));
    assert_eq!(hot.decision, "hotSwitch");
    assert!(
        hot.restart_required,
        "restartRequired 是兼容字段，语义是‘保存后仍待应用’，不是‘本性必须重启’"
    );

    // ③ norm 内字段（端口）变 → restart、需重启。随后真跑一次 switch_mode 验证结论一致。
    let structural = two_node_config(7899, "node-a");
    let predicted = rt.classify_staged(&structural);
    assert_eq!(predicted.decision, "restart");
    assert!(predicted.restart_required);
    assert_eq!(
        rt.switch_mode(structural).await,
        SwitchOutcome::Restarting,
        "预告说 restart，实际必须真走重启腿"
    );

    // ④ 核未运行 → 落盘不触发任何核动作 ⇒ 不存在「需重启才生效」。
    *rt.status.write().unwrap() = ProxyStatus::default();
    let stopped = rt.classify_staged(&two_node_config(7999, "node-a"));
    assert_eq!(stopped.decision, "noOp");
    assert!(!stopped.restart_required);
}

/// `classify_staged` 恒以 `defer_restart=false` 判：它回答「这批改动**本性上**要不要重启」，
/// 而不是「我打算不打算现在重启」。
///
/// 变异对照：把 `classify_switch(candidate, false)` 改成 `true` → 本条转红（预告变成 `defer`，
/// 用户看到的是「不用重启」，而它其实还没进核）。
#[tokio::test]
async fn classify_staged_never_predicts_its_own_deferral() {
    let (rt, _dir) = test_runtime();
    let cfg = two_node_config(7891, "node-a");
    mark_running_with_snapshot(&rt, &cfg);
    let c = rt.classify_staged(&two_node_config(7899, "node-a"));
    assert_eq!(
        c.decision, "restart",
        "本性上需重启的改动不得被预告成 defer"
    );
}

/// 腿 3-NoOp：只改 norm **排除**的纯偏好字段（language）+ 节点未变 → 零热切零重启。
/// 这是 norm 排除清单真正的价值：切个语言不该断流。
#[tokio::test]
async fn switch_mode_norm_excluded_field_change_is_noop() {
    let (rt, _dir) = test_runtime();
    let mut cfg = two_node_config(7891, "node-a");
    cfg.as_object_mut()
        .unwrap()
        .insert("language".into(), serde_json::json!("zh-CN"));
    mark_running_with_snapshot(&rt, &cfg);

    let mut next = cfg.clone();
    next.as_object_mut()
        .unwrap()
        .insert("language".into(), serde_json::json!("en-US"));

    assert_eq!(
        rt.switch_mode(next).await,
        SwitchOutcome::NoOp,
        "language 在 norm 排除清单内 + 节点未变 → NoOp，不得重启"
    );
    assert!(!rt.gate.pending().restart_pending, "NoOp 腿绝不能排程重启");
}

/// 腿 3-Defer：仅新增未被引用的节点（订阅刷新常见）→ 免整核重启。
#[tokio::test]
async fn switch_mode_added_unreferenced_node_defers() {
    let (rt, _dir) = test_runtime();
    let cfg = two_node_config(7891, "node-a");
    mark_running_with_snapshot(&rt, &cfg);

    // 纯新增一个没人引用的节点，选中节点不变。
    let mut next = cfg.clone();
    next["servers"]
        .as_array_mut()
        .unwrap()
        .push(ss_node("node-c", "Node C", 18003));

    assert_eq!(
        rt.switch_mode(next).await,
        SwitchOutcome::Deferred,
        "仅新增未引用节点 → Defer（免重启），否则订阅刷新每次都断流"
    );
    assert!(!rt.gate.pending().restart_pending, "Defer 腿绝不能排程重启");
}

/// **R2 PUSH**：`switch_mode` 末尾 `push_pending_changes` 把 `pending_changes()` **原样**推一次
/// （无适配层，pull/push 同一个 `PendingChangesSummary`）。added=相对起核快照的新增未引用节点。
/// 变异有牙：删 switch_mode 末尾 emit 点 → len==0 转红；把 `added` 换成 `old ∩ new`（旧 `updated` 的
/// 语义）→ added 含 node-a/node-b 转红；漏起核快照基准（startup_snapshot）→ pending_changes 退化转红。
#[tokio::test]
async fn switch_mode_push_pending_changes_added_only() {
    let (rt, _dir) = test_runtime();
    let pending: PendingChangesEvents = Arc::new(Mutex::new(Vec::new()));
    rt.set_error_emitter(Box::new(RecordingErrorEmitter {
        pending_changes: Arc::clone(&pending),
        ..Default::default()
    }));

    // 起核差集基准（分母）：仅 node-a/node-b。落盘 + 装热切换快照 + startup_snapshot（pending_changes 的分母）。
    let cfg = two_node_config(7891, "node-a");
    rt.config.save_full(&cfg).expect("落盘基准配置");
    *rt.startup_snapshot.write().unwrap() = Some(cfg.clone());
    mark_running_with_snapshot(&rt, &cfg);

    // 纯新增未引用节点 node-c（差集分子）；落盘使 pending_changes 读的 config.current() 反映之。
    let mut next = cfg.clone();
    next["servers"]
        .as_array_mut()
        .unwrap()
        .push(ss_node("node-c", "Node C", 18003));
    rt.config.save_full(&next).expect("落盘新增节点");

    assert_eq!(
        rt.switch_mode(next).await,
        SwitchOutcome::Deferred,
        "仅新增未引用节点 → Defer（前置：push 挂在 switch_mode 末尾，此腿也走）"
    );

    let evs = pending.lock().unwrap();
    assert_eq!(evs.len(), 1, "switch_mode 末尾恰 push 一次");
    assert_eq!(
        evs[0].added,
        vec!["node-c".to_string()],
        "added = 相对起核快照的新增未引用节点"
    );
    assert!(
        evs[0].modified.is_empty(),
        "node-a/node-b 一字未改 → 不该进 modified（进了说明判据把「存活」当成了「改过」）"
    );
    assert!(evs[0].removed.is_empty(), "本次没删节点");
    drop(evs);
}

/// Defer 开关：`restartOnNodeChange=true` → 节点变更即刻重启（auto-apply 语义），不落 Defer。
///
/// 该字段**不在 UserConfig 结构体里**，只能从原始 JSON 读 → 这条锁死那条读取路径没写错，
/// 否则开关恒失效（用户开了「立即应用」却仍走 defer）。
#[tokio::test]
async fn switch_mode_restart_on_node_change_defeats_defer() {
    let (rt, _dir) = test_runtime();
    let mut cfg = two_node_config(7891, "node-a");
    cfg.as_object_mut()
        .unwrap()
        .insert("restartOnNodeChange".into(), serde_json::json!(true));
    mark_running_with_snapshot(&rt, &cfg);

    let mut next = cfg.clone();
    next["servers"]
        .as_array_mut()
        .unwrap()
        .push(ss_node("node-c", "Node C", 18003));

    assert_eq!(
        rt.switch_mode(next).await,
        SwitchOutcome::Restarting,
        "restartOnNodeChange=true → 节点变更即刻重启，不得落 Defer"
    );
}

/// 无热切换基准快照（核在跑但快照缺失）→ 保守走重启，绝不静默吞。
#[tokio::test]
async fn switch_mode_without_snapshot_falls_back_to_restart() {
    let (rt, _dir) = test_runtime();
    let cfg = two_node_config(7891, "node-a");
    mark_running(&rt);
    *rt.current_config.write().unwrap() = Some(cfg);
    // 不装 switch_snapshot。
    assert_eq!(
        rt.switch_mode(two_node_config(7891, "node-b")).await,
        SwitchOutcome::Restarting,
        "无基准 → 无从判热切 → 必须重启（fail-closed）"
    );
}

/// H-1：非重启腿（NoOp/Defer/热切）必须把待决 force-restart 快照的**值**刷新到 newConfig，
/// 且**保留 id**。不刷新 → 去抖 timer 到点把核重启回旧配置，刚应用的变更被吃掉。
#[tokio::test]
async fn non_restart_leg_refreshes_pending_force_restart_snapshot_keeping_id() {
    let (rt, _dir) = test_runtime();
    let mut cfg = two_node_config(7891, "node-a");
    cfg.as_object_mut()
        .unwrap()
        .insert("language".into(), serde_json::json!("zh-CN"));
    mark_running_with_snapshot(&rt, &cfg);
    // 模拟已有待决 force-restart（apply_pending 排程过），载荷是旧 cfg。
    *rt.pending_force_restart.write().unwrap() = Some((42, cfg.clone()));

    let mut next = cfg.clone();
    next.as_object_mut()
        .unwrap()
        .insert("language".into(), serde_json::json!("en-US"));
    assert_eq!(rt.switch_mode(next.clone()).await, SwitchOutcome::NoOp);

    let pending = rt.pending_force_restart.read().unwrap().clone().unwrap();
    assert_eq!(
        pending.0, 42,
        "必须保留 force-restart id（换号 = 排空时认领不到）"
    );
    assert_eq!(
        pending.1, next,
        "必须把载荷刷新到 newConfig，否则重启回退旧配置"
    );
}

/// 重启腿相反：**丢弃**待决 force-restart 快照（上游 :1888 `pendingForceRestartConfig = null`）。
/// 结构性重启用最新完整 config → 旧 force 快照必须让位，否则它反 shadow 本次变更。
#[tokio::test]
async fn restart_leg_discards_pending_force_restart_snapshot() {
    let (rt, _dir) = test_runtime();
    let cfg = two_node_config(7891, "node-a");
    mark_running_with_snapshot(&rt, &cfg);
    *rt.pending_force_restart.write().unwrap() = Some((42, cfg.clone()));

    assert_eq!(
        rt.switch_mode(two_node_config(7899, "node-a")).await,
        SwitchOutcome::Restarting
    );
    assert!(
        rt.pending_force_restart.read().unwrap().is_none(),
        "重启腿必须丢弃旧 force 快照（否则去抖回调消费它 → 重启回旧配置）"
    );
}

// ── apply_pending 真实状态（此前硬编码 "applied" → UI 误报成功）──

#[tokio::test]
async fn apply_pending_skipped_when_core_not_running() {
    // 核未运行 → skipped（下次 start 从磁盘纳入），绝不谎报 applied。
    let (rt, _dir) = test_runtime();
    assert_eq!(rt.apply_pending().await, "skipped");
}

#[tokio::test]
async fn apply_pending_while_stopped_consumes_deferred_delete_side_effects() {
    let (rt, dir) = test_runtime();
    let mut current = rt.config.load_full().unwrap();
    current["servers"] = serde_json::json!([
        { "id": "ts-delete", "protocol": "tailscale" },
        {
            "id": "warp-delete",
            "protocol": "wireguard",
            "wireguardSettings": {
                "warpDevice": { "deviceId": "dev-delete", "token": "tok-delete" }
            }
        }
    ]);
    current["ruleResources"] = serde_json::json!([
        { "id": "resource-delete", "fileName": "resource-delete.srs" }
    ]);
    current["customAppPresets"] = serde_json::json!([{ "id": "app-delete", "name": "App" }]);
    rt.config.save_full(&current).unwrap();

    let resource = dir.join("rule-resource/resource-delete.srs");
    std::fs::create_dir_all(resource.parent().unwrap()).unwrap();
    std::fs::write(&resource, b"SRS").unwrap();
    let ts_state = rt.mesh.tailscale_state_dir("ts-delete").unwrap();
    std::fs::create_dir_all(&ts_state).unwrap();
    let icon_dir = crate::icon_cache::icons_dir(&dir);
    crate::icon_cache::write_icon(&icon_dir, "app-delete", "png", b"PNG").unwrap();

    let mut incoming = current.clone();
    incoming["servers"] = serde_json::json!([]);
    incoming["ruleResources"] = serde_json::json!([]);
    incoming["customAppPresets"] = serde_json::json!([]);
    rt.config
        .save_full_deferred_cleanup(&current, &incoming)
        .unwrap();
    assert!(resource.exists() && ts_state.exists() && icon_dir.join("app-delete.png").exists());

    assert_eq!(rt.apply_pending().await, "skipped");
    assert!(!resource.exists(), "Apply 才删除规则资源文件");
    assert!(!ts_state.exists(), "Apply 才清 Tailscale state");
    assert!(
        !icon_dir.join("app-delete.png").exists(),
        "Apply 才驱逐应用图标"
    );
    let warp_queue: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(rt.mesh.warp_queue_path()).expect("WARP 注销须可靠入队"),
    )
    .unwrap();
    assert_eq!(warp_queue[0]["deviceId"], serde_json::json!("dev-delete"));
    assert_eq!(warp_queue[0]["token"], serde_json::json!("tok-delete"));
}

#[tokio::test]
async fn apply_pending_applied_when_running_and_idle() {
    let (rt, _dir) = test_runtime();
    mark_running(&rt);
    assert_eq!(rt.apply_pending().await, "applied");
    // applied 必须真的留下 force-restart 专用快照（drain/去抖据此重启到这份 cfg）。
    assert!(
        rt.pending_force_restart.read().unwrap().is_some(),
        "applied 必须写 force-restart 快照，否则重启会回落旧 config（H-1 死循环）"
    );
}

/// **「apply 之后差集必须为空」**（陈先生 2026-07-30 真机：点了「立即应用」核**真**重启了，
/// 条上却仍是「立即应用」，连点三次形态相同）。
///
/// 走全链路的**纯状态半边**（不起真核）：起核快照 = 旧配置、磁盘 = 新配置 ⇒ 差集非空
/// （**正向对照**，否则下面那句「为空」毫无信息量）→ `apply_pending` 排程并留下 force-restart
/// 快照 → 模拟那次去抖重启落地（去抖回调按 id 取回该快照，`start_inner` 就绪腿把它装成新的
/// 起核快照并清欠账）⇒ 差集必须为空。
///
/// **本条证不到的那一半**（如实标注）：`start_inner` 真的装了快照、真的清了欠账 —— 那要真起核，
/// 由源码型守卫 `deferred_debt_is_cleared_where_the_startup_snapshot_is_written_and_cleared`
/// 与 `pending_changes_push_is_wired_on_both_sides_of_the_diff` 兜。
///
/// 变异对照（真能转红的）：
/// - `apply_pending` 改成拿 `current_config`（在飞 start 会覆盖它）而非 `self.config.current()`
///   做快照 → 落地装回旧配置 → `added` 里 node-c 还在 → 红；
/// - `take_force_restart_config` 不按 id 认领（恒取 / 恒不取）→ `expect` 炸或取到 None → 红；
/// - `pending_changes` 的 `modified` 旧侧改成现算磁盘 → 差集恒空，本条的**正向对照**那一半先红。
#[tokio::test]
async fn diff_is_empty_after_the_restart_that_apply_pending_scheduled_lands() {
    let (rt, _dir) = test_runtime();
    let base = two_node_config(7891, "node-a");
    rt.config.save_full(&base).expect("落盘");
    install_startup_snapshot(&rt, &base);
    mark_running(&rt);

    // 条上「配置变更待应用」的两条来源各摆一个：①「保存不重启」的欠账 ② 一个尚未进核的新节点。
    rt.restart_deferred.store(true, Ordering::SeqCst);
    let mut next = base.clone();
    next["servers"]
        .as_array_mut()
        .unwrap()
        .push(ss_node("node-c", "Node C", 18003));
    rt.config.save_full(&next).expect("落盘");

    let before = rt.pending_changes();
    assert_eq!(
        before.added,
        vec!["node-c".to_string()],
        "正向对照：apply 之前差集必须真的非空"
    );
    assert!(before.restart_deferred, "正向对照：欠账必须真的在");

    // 用户点「立即应用」。
    assert_eq!(rt.apply_pending().await, "applied");
    let id = rt
        .gate
        .pending()
        .force_restart_id
        .expect("applied 必须在 gate 里记下 force id");

    // 模拟去抖重启落地 = `schedule_restart` 回调取配置 + `start_inner` 就绪腿装快照/清欠账。
    let landed = rt
        .take_force_restart_config(Some(id))
        .expect("去抖回调必须能按 id 取回 apply 排程那一刻的 config");
    install_startup_snapshot(&rt, &landed);
    rt.restart_deferred.store(false, Ordering::SeqCst);

    assert_eq!(
        rt.pending_changes(),
        PendingChangesSummary {
            added: vec![],
            modified: vec![],
            removed: vec![],
            restart_deferred: false,
        },
        "重启落地后差集必须为空 —— 非空 = 条上继续挂「立即应用」，用户再点也清不掉"
    );
}

/// H-1 顺序门（上游 ProxyManager.ts:1731 注释）：**depth>0 必须先于句柄判空**。
/// 顺序颠倒 → restart 的 stop→start 空窗内（句柄暂空、depth>0）本次强制重启被静默丢弃，
/// 用户重试遇 304 → 不再触发 force-restart → 死循环。
#[tokio::test]
async fn apply_pending_deferred_when_busy_even_though_core_appears_stopped() {
    let (rt, _dir) = test_runtime();
    // 模拟 restart 的 stop→start 空窗：lifecycle 在飞，但状态尚未回到 running。
    rt.gate.begin();
    assert!(!rt.core_running(), "前提：此刻句柄/状态看起来是「未运行」");

    let r = rt.apply_pending().await;
    assert_eq!(
        r, "deferred",
        "depth>0 必须先判 → deferred；若先判「未运行」会返回 skipped 并永久丢弃本次变更（H-1）"
    );
    // 必须排入 drain：restart_pending + force-restart 快照都要在。
    let pending = rt.gate.pending();
    assert!(
        pending.restart_pending,
        "deferred 必须置 restart_pending 供 end() 排空"
    );
    assert!(
        pending.force_restart_id.is_some(),
        "deferred 必须记 force-restart id"
    );
    assert!(rt.pending_force_restart.read().unwrap().is_some());
}

/// force-restart 快照按 id 消费：id 对不上（更新的 apply 已换快照）→ 不消费旧的。
#[tokio::test]
async fn take_force_restart_config_matches_by_id() {
    let (rt, _dir) = test_runtime();
    *rt.pending_force_restart.write().unwrap() = Some((7, serde_json::json!({"k": 1})));
    // id 对不上 → 不取。
    assert!(rt.take_force_restart_config(Some(8)).is_none());
    // None（用 currentConfig）→ 不消费专用快照。
    assert!(rt.take_force_restart_config(None).is_none());
    // id 对得上 → 取出并清空。
    assert_eq!(
        rt.take_force_restart_config(Some(7)),
        Some(serde_json::json!({"k": 1}))
    );
    assert!(rt.pending_force_restart.read().unwrap().is_none());
}

/// **本任务的核心 gate**：切节点 → 核进程 PID 不变（= 热切换真的生效，不是重启）。
///
/// 全程走**生产入口** `ProxyRuntime::switch_mode`（不是直接调 `decide`/`SwitchExecutor`）——
/// §K7.1：门必须开在唯一的生产路径上，两扇门之间的缝正是 bug 的藏身处。
///
/// 安全硬约束：`proxyModeType: manual` + 仅 127.0.0.1 混合入站 + 节点地址指向本地死端口
///   → 不接管系统网络、无 TUN、无系统代理、零外部流量。**绝不可改成 tun/systemProxy**。
#[tokio::test(flavor = "multi_thread")]
#[ignore = "真机验证：需 POLARIS_SINGBOX_PATH 指向真实 sing-box；非 CI 门"]
async fn real_core_hot_switch_keeps_pid() {
    let _real_core_guard = lock_real_core_tests().await;
    let (rt, dir, _core) = real_core_runtime();
    crate::logging::init(&dir);
    let mixed = free_port();
    // 两个节点各指到我们自己的本地监听器（127.0.0.1，随机空闲口）→ ③b 直接观测核拨了谁。
    let (pa, hits_a) = counting_listener().await;
    let (pb, hits_b) = counting_listener().await;
    println!("[①] 节点监听器：Node A=127.0.0.1:{pa}, Node B=127.0.0.1:{pb}");

    // ── ① 起核（两节点，选中 Node A）────────────────────────────────────────
    // 生产时序：save_full 落盘 → broadcast_config_changed → switch_mode。测试逐条照做，
    // 否则去抖重启回落读磁盘时会拿到默认配置（restart 腿的载荷来自 config.current()）。
    let cfg_a = two_node_config_ports(mixed, "node-a", pa, pb);
    rt.config.save_full(&cfg_a).expect("落盘应成功");
    let st = rt.start(cfg_a.clone()).await.expect("起核应成功");
    let pid1 = st.pid;
    println!(
        "[①] start → pid={pid1} mixedPort={} apiPort={}",
        st.mixed_port, st.clash_api_port
    );
    assert!(ps_alive(pid1), "[①] ps 必须能看到 pid={pid1}");
    assert!(
        rt.switch_snapshot.read().unwrap().is_some(),
        "[①] 起核就绪后必须留下热切换基准快照（否则一切变更退化为重启）"
    );
    let snap_tags = rt
        .switch_snapshot
        .read()
        .unwrap()
        .clone()
        .unwrap()
        .id_to_tag;
    println!("[①] 热切换基准 id→tag = {snap_tags:?}");

    // ── ② 切节点 → 热切换，PID 不变（**核心判据**）───────────────────────────
    let cfg_b = two_node_config_ports(mixed, "node-b", pa, pb);
    rt.config.save_full(&cfg_b).expect("落盘应成功");
    let out = rt.switch_mode(cfg_b.clone()).await;
    println!("[②] switch_mode（node-a → node-b）→ {out:?}");
    assert_eq!(
        out,
        SwitchOutcome::HotSwitched,
        "[②] 切节点必须走热切腿（实得 {out:?}）—— 这正是本任务要接的线"
    );
    let pid_after = rt.status().pid;
    assert_eq!(
        pid_after, pid1,
        "[②] 热切换后 PID 必须不变（{pid1} → {pid_after}）—— 变了就说明还是在重启整个核"
    );
    assert!(
        ps_alive(pid1),
        "[②] 原进程 pid={pid1} 必须仍在跑（ps 实证）"
    );
    println!("[②] ps -p {pid1} 仍存活 + PID 未变 → 热切换真的生效 ✓");

    // ── ③ SelectOutbound 真的经 gRPC 下发且被核接受 ──────────────────────────
    // 负向对照：核必须拒绝不存在的成员 tag。它会拒 ⇒ ② 里那次成功的 PUT 确实选中了真实成员，
    // 而不是「核照单全收、根本没校验」。没有这条，「PUT 返回 Ok」只能证明 RPC 通了。
    let client = SingBoxApiClient::connect(Endpoint::new("127.0.0.1", st.clash_api_port), "")
        .await
        .expect("[③] 管理 API gRPC 连接应成功");
    let bogus = client
        .select_outbound("proxy-selector", "no-such-member-xyz")
        .await;
    println!("[③] 负向对照 SelectOutbound(proxy-selector, no-such-member-xyz) → {bogus:?}");
    assert!(
        bogus.is_err(),
        "[③] 核必须拒绝不存在的成员 tag —— 它若照单全收，② 的 PUT 成功就不能证明真的切了"
    );
    let good = client.select_outbound("proxy-selector", "Node B").await;
    println!("[③] 正向 SelectOutbound(proxy-selector, Node B) → {good:?}");
    assert!(good.is_ok(), "[③] 真实成员 tag 的 PUT 必须成功");

    // ── ③b 决定性实证：热切换后**真实流量**改走 Node B（不是只让 RPC 返了个 Ok）──────
    // 前面几条只证明「PUT 被核接受」。要证明**路由真的变了**，就得看核实际拨了谁：
    // 两个节点各指向我们自己的本地监听器，谁被连上一目了然。
    // 不读日志——日志经全局 OnceLock logger 中转，多测试同进程时会绑到别人的目录（实测踩到）。
    client
        .select_outbound("proxy-selector", "Node B")
        .await
        .expect("[③b] 复位到 Node B（③ 的负向对照后需还原）");
    hits_a.store(0, Ordering::SeqCst);
    hits_b.store(0, Ordering::SeqCst);
    drive_traffic_through_proxy(mixed).await;
    let (a, b) = (hits_a.load(Ordering::SeqCst), hits_b.load(Ordering::SeqCst));
    println!("[③b] 热切换后打流量：Node A 监听器被连 {a} 次，Node B 监听器被连 {b} 次");
    assert!(
        b > 0,
        "[③b] 热切换后流量必须由 Node B 承载（B 被连 {b} 次）—— \
             PUT 返回了 Ok 但路由没切 = 假阳性，正是「兜底把失败伪装成成功」的形态"
    );
    assert_eq!(
        a, 0,
        "[③b] 切换后绝不该再有新连接落到 Node A（实得 {a} 次）"
    );
    println!("[③b] 核未重启（pid={pid1}）且流量已改走 Node B → 热切换真的改变了实际路由 ✓");

    // ── ④ norm 内字段（端口）变更 → 走重启，PID 必须变 ──────────────────────
    let mixed2 = free_port();
    let cfg_port = two_node_config_ports(mixed2, "node-b", pa, pb);
    rt.config.save_full(&cfg_port).expect("落盘应成功");
    let out = rt.switch_mode(cfg_port).await;
    println!("[④] switch_mode（改 mixedPort {mixed} → {mixed2}）→ {out:?}");
    assert_eq!(
        out,
        SwitchOutcome::Restarting,
        "[④] norm 内字段变更必须走重启腿（热切换切不了端口）"
    );
    let pid2 = wait_pid_change(&rt, pid1, 20)
        .await
        .expect("[④] 去抖重启应在 20s 内换出新 pid");
    println!("[④] 重启完成：pid {pid1} → {pid2}");
    assert!(ps_alive(pid2), "[④] 新核必须在跑");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!ps_alive(pid1), "[④] 旧核 pid={pid1} 必须已退出（无孤儿）");
    assert_eq!(
        rt.status().mixed_port,
        mixed2,
        "[④] 重启后必须真的起在新端口上（否则重启是空转）"
    );
    println!("[④] 旧核已退、新核监听 {mixed2} → 重启路径完好 ✓");

    rt.stop().await.expect("停核应成功");
}

/// 真核回归：自动故障治理走它自己的零重启事务，真实 gRPC PUT + groups 首帧回读均成功；同时
/// D 中已保存未 Apply 的结构字段不得进入 R。节点只拨本机监听器，不接管宿主网络。
#[tokio::test(flavor = "multi_thread")]
#[ignore = "真机验证：需 POLARIS_SINGBOX_PATH 指向真实 sing-box；非 CI 门"]
async fn real_core_auto_failover_attests_without_applying_saved_debt() {
    let _real_core_guard = lock_real_core_tests().await;
    let (rt, dir, _core) = real_core_runtime();
    crate::logging::init(&dir);
    let mixed = free_port();
    let (pa, _hits_a) = counting_listener().await;
    let (pb, hits_b) = counting_listener().await;
    let runtime = two_node_config_ports(mixed, "node-a", pa, pb);
    rt.config.save_full(&runtime).expect("seed runtime config");
    let started = rt.start(runtime.clone()).await.expect("real core start");
    let pid = started.pid;
    // 生产心跳首拍晚于起核后的 selector reassert/attestation；测试直调事务也保持同一可达时序，
    // 避免人为把启动校正与 failover PUT 叠在一起制造生产中不存在的双写竞态。
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut disk = runtime.clone();
    disk["mixedPort"] = serde_json::json!(free_port());
    rt.config.save_full(&disk).expect("save unapplied debt");
    let targets = rt
        .speed_probe_targets()
        .expect("running core probe targets");
    let tag = targets
        .id_to_tag
        .get("node-b")
        .cloned()
        .expect("node-b loaded in current selector");
    let candidate = RuntimeCandidate {
        id: "node-b".to_string(),
        name: "Node B".to_string(),
        tag,
    };
    let fingerprint = current_server_fingerprints(&disk)
        .remove("node-b")
        .expect("candidate fingerprint");

    let outcome = rt
        .auto_hot_switch_transaction(rt.core_generation(), "node-a", &candidate, &fingerprint)
        .await;
    assert_eq!(outcome, AutoHotSwitchOutcome::Applied);
    assert_eq!(rt.status().pid, pid, "自动 failover 必须保持真实核 PID");
    assert!(ps_alive(pid), "真实核仍须存活");
    let after_disk = rt.config.current().unwrap();
    let after_runtime = rt.current_config.read().unwrap().clone().unwrap();
    assert_eq!(after_disk["selectedServerId"], "node-b");
    assert_ne!(after_disk["mixedPort"], runtime["mixedPort"]);
    assert_eq!(after_runtime["selectedServerId"], "node-b");
    assert_eq!(
        after_runtime["mixedPort"], runtime["mixedPort"],
        "未 Apply 的 mixedPort 不得被后台切换夹带入核"
    );

    hits_b.store(0, Ordering::SeqCst);
    drive_traffic_through_proxy(mixed).await;
    assert!(
        hits_b.load(Ordering::SeqCst) > 0,
        "回读自证后的新连接必须真实拨向 Node B"
    );

    rt.stop().await.expect("stop real core");
}

/// ⑤ 热切换失败 → 回退重启，且**不卡死**。
///
/// 真实失败注入：直接把核杀掉，此时 switch_mode 会判热切腿 → gRPC 连不上 → ClientNotReady →
/// 按 executor 契约退回去抖重启 → 新核起来。这同时实证了「热切换失败不会把变更吞掉、也不会挂起」。
///
/// **与崩溃自愈的关系（本批接线后）**：SIGKILL 后崩溃监测也会检出并自愈，但 (a) 监测轮询间隔 1s，
/// 本测试在 500ms 处断言 `running` 时尚未检出；(b) 热切换失败触发的回退重启会 bump 世代，崩溃监测
/// 据此 `post_backoff` 判 Superseded 让位 → **二者经世代协同，只发生一次重启**，不打架。
#[tokio::test(flavor = "multi_thread")]
#[ignore = "真机验证：需 POLARIS_SINGBOX_PATH 指向真实 sing-box；非 CI 门"]
async fn real_core_hot_switch_failure_falls_back_to_restart() {
    let _real_core_guard = lock_real_core_tests().await;
    let (rt, dir, _core) = real_core_runtime();
    crate::logging::init(&dir);
    let mixed = free_port();

    let cfg_a = two_node_config(mixed, "node-a");
    rt.config.save_full(&cfg_a).expect("落盘应成功");
    let st = rt.start(cfg_a).await.expect("起核应成功");
    let pid1 = st.pid;
    println!("[⑤] 起核 pid={pid1}");

    // 失败注入：SIGKILL 核（绕过 rt.stop，世代不变 → 快照仍在；崩溃监测 1s 后才检出，此刻 status 仍 running）。
    send_signal(pid1, Signal::Sigkill);
    tokio::time::sleep(Duration::from_millis(500)).await;
    // 判据用「管理 API 已不可连」而**不用 `ps_alive`**：SIGKILL 后 child 句柄仍被 ProxyRuntime
    // 持有、无人 `wait()` 收割 → 进程处于 **zombie** 态，`ps -p` 照样看得见它（`ps_alive` 分辨
    // 不了 zombie 与存活）。而「管理 API 连不上」正是本测试要注入的失败条件本身。
    let api_dead = tokio::net::TcpStream::connect(("127.0.0.1", st.clash_api_port))
        .await
        .is_err();
    assert!(api_dead, "[⑤] 核已被 SIGKILL → 管理 API 端口应不可连");
    assert!(
        rt.status().running,
        "[⑤] 前提：崩溃监测 1s 后才检出，此刻（500ms）status 仍自称 running（这正是热切换会失败的场景）"
    );
    println!("[⑤] 已 SIGKILL 核 pid={pid1}：管理 API 不可连，status 仍自称 running");

    // 切节点 → 热切腿 → gRPC 连不上 → 回退重启。带超时断言「不卡死」。
    let cfg_b = two_node_config(mixed, "node-b");
    rt.config.save_full(&cfg_b).expect("落盘应成功");
    let out = tokio::time::timeout(Duration::from_secs(15), rt.switch_mode(cfg_b))
        .await
        .expect("[⑤] switch_mode 必须在 15s 内返回 —— 卡死即失败");
    println!("[⑤] 核已死时 switch_mode → {out:?}");
    assert_eq!(
        out,
        SwitchOutcome::Restarting,
        "[⑤] 热切换失败必须退回重启，绝不能静默吞掉切节点"
    );

    // 回退的重启真的把核拉起来了（不是只喊了一声）。
    let pid2 = wait_pid_change(&rt, pid1, 20)
        .await
        .expect("[⑤] 回退重启应在 20s 内起出新核");
    println!(
        "[⑤] 回退重启完成：pid {pid1} → {pid2}（新核存活={}）",
        ps_alive(pid2)
    );
    assert!(ps_alive(pid2), "[⑤] 回退重启必须真的起出新核");

    rt.stop().await.expect("停核应成功");
}

#[test]
fn server_ids_extracts_ids_and_tolerates_garbage() {
    let cfg = serde_json::json!({
        "servers": [{"id": "a"}, {"id": "b"}, {"noid": 1}, "junk"]
    });
    let ids = server_ids(&cfg);
    assert_eq!(ids.len(), 2);
    assert!(ids.contains("a") && ids.contains("b"));
    // 无 servers 键 → 空集，不 panic。
    assert!(server_ids(&serde_json::json!({})).is_empty());
}

/// 两个 vless 节点的配置（`node-a` 选中）。
fn reassert_config(selected: &str) -> Value {
    serde_json::json!({
        "servers": [
            { "id": "node-a", "name": "A", "protocol": "vless",
              "address": "a.example.com", "port": 443, "uuid": "u-a" },
            { "id": "node-b", "name": "B", "protocol": "vless",
              "address": "b.example.com", "port": 443, "uuid": "u-b" }
        ],
        "selectedServerId": selected,
        "proxyMode": "smart"
    })
}

fn ab_tags() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("node-a".to_string(), "A".to_string()),
        ("node-b".to_string(), "B".to_string()),
    ])
}

/// **不变式①**：起核后 `proxy-selector` 必被 PUT 成**选中节点的 tag** —— 这是 H3 的整个存在理由。
///
/// 不 PUT 就等于把出口交给 `cache_file` 里上一轮的残留选择（真机血证：盘上选 Hk01、核实走
/// Tailscale → 家用路由 OpenClash → Jp01，全链路零告警）。
///
/// **变异锁**：把 stage 1 里那次 `hot_switch_selector(PROXY_SELECTOR_TAG, member_tag)` 删掉
/// （只留循环与 break）→ PUT 序列空 → 转红。
#[tokio::test]
async fn reassert_puts_proxy_selector_to_selected_tag() {
    let (rt, _dir, sink, _inval, _refresh, _fb) =
        reassert_runtime(&reassert_config("node-a"), ab_tags(), BTreeMap::new());
    let cfg: UserConfig = serde_json::from_value(reassert_config("node-a")).unwrap();
    let my_gen = rt.gate.generation();
    rt.reassert_selector_selection(&cfg, my_gen).await;
    assert_eq!(
        sink.calls(),
        vec![("proxy-selector".to_string(), "A".to_string())],
        "起核后必须把 proxy-selector 拨回选中节点的 tag（压过 cache_file 旧选择）"
    );
}

/// 直连是内置 selector 成员，不在 server `id_to_tag` 映射中；它必须直接解析成 `direct`。
/// 否则启动后实际已直连，校正腿却会误报 `EXIT_MISMATCH`。
#[tokio::test]
async fn reassert_maps_direct_sentinel_to_builtin_member() {
    let config_value = reassert_config(DIRECT_SERVER_ID);
    let (rt, _dir, sink, _inval, _refresh, _fb) =
        reassert_runtime(&config_value, BTreeMap::new(), BTreeMap::new());
    let config: UserConfig = serde_json::from_value(config_value).unwrap();
    let my_gen = rt.gate.generation();

    let outcome = rt.reassert_selector_selection(&config, my_gen).await;

    assert!(matches!(
        outcome.stage1,
        Stage1Outcome::Applied { ref member_tag } if member_tag == DIRECT_TAG
    ));
    assert_eq!(
        sink.calls(),
        vec![(PROXY_SELECTOR_TAG.to_string(), DIRECT_TAG.to_string())]
    );
}

/// startup reassert 不能绕过配置切换事务：持锁期间即使 task 已获调度也不得产生 proxy-selector PUT。
#[tokio::test]
async fn reassert_waits_for_the_shared_selector_serial_lock() {
    let config_value = reassert_config("node-a");
    let (rt, _dir, sink, _inval, _refresh, _fb) =
        reassert_runtime(&config_value, ab_tags(), BTreeMap::new());
    let config: UserConfig = serde_json::from_value(config_value).unwrap();
    let my_gen = rt.gate.generation();
    let guard = rt.switch_serial.lock().await;
    let rt_for_task = Arc::clone(&rt);
    let task = tokio::spawn(async move {
        rt_for_task
            .reassert_selector_selection(&config, my_gen)
            .await
    });
    tokio::task::yield_now().await;
    assert!(sink.calls().is_empty(), "共享锁未释放前不得 PUT");
    drop(guard);
    let outcome = task.await.expect("reassert task");
    assert!(matches!(outcome.stage1, Stage1Outcome::Applied { .. }));
    assert_eq!(
        sink.calls(),
        vec![("proxy-selector".to_string(), "A".to_string())]
    );
}

/// **不变式②**：选中的是**未登录**的账号制 TS 全隧道出口 → 本轮 PUT 的必须是 `direct`（不是那个
/// 连不上的 TS tag），且 **PUT 成功之后**才置让位 flag。
///
/// 后半条是「flag 与 selector 不得脱节」的唯一保证：先置 flag 再 PUT，PUT 失败时 UI 会显示「已让位
/// 直连」而 selector 实际仍指着未就绪的 TS 出口 —— 用户看到的和跑着的是两回事。
///
/// **变异锁**：① 把 `member_tag` 恒取 `tag`（删掉 `want_direct` 分支）→ 第一段断言 PUT 到 TS tag 转红；
/// ② 把 `mark_login_fallback_engaged` 挪到 `hot_switch_selector` 之前/之外（无条件置）→ 第二段
/// 「全失败仍不置 flag」转红。
#[tokio::test]
async fn reassert_yields_to_direct_when_ts_exit_never_logged_in() {
    // ── 成功腿：PUT direct + 置 flag + emit ──
    let tags = BTreeMap::from([("ts1".to_string(), "组网出口".to_string())]);
    let (rt, _dir, sink, _inval, _refresh, fb) =
        reassert_runtime(&ts_fallback_config(), tags.clone(), BTreeMap::new());
    let cfg: UserConfig = serde_json::from_value(ts_fallback_config()).unwrap();
    let my_gen = rt.gate.generation();
    rt.reassert_selector_selection(&cfg, my_gen).await;
    assert_eq!(
        sink.calls(),
        vec![("proxy-selector".to_string(), "direct".to_string())],
        "未登录的 TS 出口：PUT 的必须是 direct，不是连不上的 TS tag"
    );
    assert!(rt.login_fallback_engaged(), "PUT 成功 → 让位 flag 必置");
    assert_eq!(
        fb.lock().unwrap().as_slice(),
        &[(true, Some("组网出口".to_string()))],
        "首次让位 emit 一次"
    );

    // ── 失败腿：PUT 全失败 → 绝不置 flag（flag 与 selector 同进退）──
    let (rt2, dir2, sink2, _i2, _r2, fb2) =
        reassert_runtime(&ts_fallback_config(), tags, BTreeMap::new());
    sink2
        .fail_first
        .store(ProxyRuntime::REASSERT_MAX_ROUNDS as u32, Ordering::SeqCst);
    let my_gen2 = rt2.gate.generation();
    rt2.reassert_selector_selection(&cfg, my_gen2).await;
    assert_eq!(
        sink2.calls().len(),
        ProxyRuntime::REASSERT_MAX_ROUNDS,
        "管理 API 一直不就绪 → 跑满重试轮数"
    );
    assert!(
        !rt2.login_fallback_engaged(),
        "PUT 从未成功 → 绝不置让位 flag（否则 UI 说直连、selector 指着 TS 出口）"
    );
    assert!(fb2.lock().unwrap().is_empty(), "未让位成功 → 零 emit");
    let _ = std::fs::remove_dir_all(&dir2);
}

/// **不变式③**：起核窗口内用户已热切到别的节点 → 重试轮必须跟**最新**的 `selectedServerId`，
/// 绝不能把它 revert 回起核那一刻的旧节点。
///
/// 首轮 PUT 注入失败 → 退避 300ms；退避期间外部把 `current_config` 改成 `node-b`；第二轮必须 PUT `B`。
///
/// **变异锁**：把每轮的 `current_config` 现读提到循环**外**（只读一次）→ 第二次 PUT 仍是 `A` → 转红。
#[tokio::test]
async fn reassert_follows_latest_selection_across_retries() {
    let (rt, _dir, sink, _inval, _refresh, _fb) =
        reassert_runtime(&reassert_config("node-a"), ab_tags(), BTreeMap::new());
    sink.fail_first.store(1, Ordering::SeqCst); // 首轮失败 → 进退避重试腿
    let cfg: UserConfig = serde_json::from_value(reassert_config("node-a")).unwrap();
    let my_gen = rt.gate.generation();
    let rt2 = Arc::clone(&rt);
    // 退避窗口（300ms）内热切到 node-b。
    let switcher = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(80)).await;
        *rt2.current_config.write().unwrap() = Some(reassert_config("node-b"));
    });
    rt.reassert_selector_selection(&cfg, my_gen).await;
    switcher.await.unwrap();
    assert_eq!(
        sink.calls(),
        vec![
            ("proxy-selector".to_string(), "A".to_string()),
            ("proxy-selector".to_string(), "B".to_string()),
        ],
        "重试轮必须跟最新选中节点（B），不得把用户刚切的选择 revert 回起核时的 A"
    );
}

/// **不变式④**：有 `targetServerId` 的规则 → PUT 其 rule-sel；无 `targetServerId` 的规则 → **跳过**
/// （它们生成时 `default = proxy-selector`，嵌套跟随全局，不需要也不该被单独钉死）。
///
/// selector tag 取自 `switch_snapshot.rule_target`（生成侧真值），本例故意让 `r1` 的 tag 带撞名去重
/// 后缀 `rule-sel-r1 (1)` —— 手拼 `format!("rule-sel-{id}")` 会 PUT 到一个不存在的 tag。
///
/// **变异锁**：① 把「无 target 就 continue」改成回落一个默认目标 → 序列里多出 `rule-sel-r2` → 转红；
/// ② 把 `entry.selector_tag` 换成手拼模板 → 第一条断言的 `rule-sel-r1 (1)` 转红。
#[tokio::test]
async fn reassert_rule_selectors_skips_rules_without_target() {
    let mut cfg = reassert_config("node-a");
    cfg["customRules"] = serde_json::json!([
        { "id": "r1", "type": "domain", "values": ["x.com"], "action": "proxy",
          "enabled": true, "targetServerId": "node-b" },
        { "id": "r2", "type": "domain", "values": ["y.com"], "action": "proxy",
          "enabled": true },
        { "id": "r3", "type": "domain", "values": ["z.com"], "action": "proxy",
          "enabled": false, "targetServerId": "node-b" }
    ]);
    cfg["appRules"] = serde_json::json!([
        { "appId": "app1", "action": "proxy", "enabled": true, "targetServerId": "node-a" }
    ]);
    let rule_target = BTreeMap::from([
        (
            "custom:r1".to_string(),
            RuleTargetEntry {
                selector_tag: "rule-sel-r1 (1)".into(), // 撞名去重后的真实 tag
                member_tag: "B".into(),
            },
        ),
        (
            "custom:r2".to_string(),
            RuleTargetEntry {
                selector_tag: "rule-sel-r2".into(),
                member_tag: "proxy-selector".into(),
            },
        ),
        (
            "custom:r3".to_string(),
            RuleTargetEntry {
                selector_tag: "rule-sel-r3".into(),
                member_tag: "B".into(),
            },
        ),
        (
            "app:app1".to_string(),
            RuleTargetEntry {
                selector_tag: "rule-sel-app-app1".into(),
                member_tag: "A".into(),
            },
        ),
    ]);
    let (rt, _dir, sink, _inval, _refresh, _fb) = reassert_runtime(&cfg, ab_tags(), rule_target);
    let uc: UserConfig = serde_json::from_value(cfg).unwrap();
    let my_gen = rt.gate.generation();
    rt.reassert_selector_selection(&uc, my_gen).await;
    assert_eq!(
        sink.calls(),
        vec![
            ("proxy-selector".to_string(), "A".to_string()),
            ("rule-sel-r1 (1)".to_string(), "B".to_string()),
            ("rule-sel-app-app1".to_string(), "A".to_string()),
        ],
        "只 reassert 有 targetServerId 的启用 proxy 规则；无 target（r2）/ 禁用（r3）一律跳过，\
             且 selector tag 必须取自生成侧真值（含撞名去重后缀）"
    );
}

/// **不变式⑤（行为门，非结构门）**：续延（失效解锁缓存 + 重探出口 IP）必须**晚于** reassert 的
/// 每一次 PUT。
///
/// 早于则 boot 窗口内起跑的解锁检测轮 / 出口 IP 探测量的还是**旧出口**，其脏结果会被当新鲜数据
/// commit 进缓存（epoch 守卫对这次翻转失明）—— 这正是 上游 F-C 修的东西。判据是 PUT 那一刻抄下来
/// 的续延计数：全为 0 ⟺ 每次 PUT 都发生在续延之前（只看终态验不出顺序）。
///
/// **变异锁**：把 `spawn_reassert_selector_selection` 里的续延从 `ReassertSettledGuard` 改成
/// 「先 `me.after_selector_reasserted(my_gen)` 再 await reassert」→ 观测值变成 `[1]` → 转红。
#[tokio::test]
async fn continuation_runs_strictly_after_reassert_puts() {
    let (rt, _dir, sink, inval, refresh, _fb) =
        reassert_runtime(&reassert_config("node-a"), ab_tags(), BTreeMap::new());
    *sink.invalidation_probe.lock().unwrap() = Some(Arc::clone(&inval));
    let uc: UserConfig = serde_json::from_value(reassert_config("node-a")).unwrap();
    let my_gen = rt.gate.generation();
    rt.spawn_reassert_selector_selection(uc, my_gen, 0);
    // 后台腿：轮询等它跑完（无 PUT 失败 ⇒ 单轮即结束，这里给足余量）。
    for _ in 0..100 {
        if !inval.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        sink.calls(),
        vec![("proxy-selector".to_string(), "A".to_string())],
        "前提：校正确实 PUT 过"
    );
    assert_eq!(
        sink.observed_invalidations.lock().unwrap().as_slice(),
        &[0],
        "每次 PUT 的那一刻续延都还没跑过（续延必须严格晚于校正）"
    );
    assert_eq!(
        inval.lock().unwrap().as_slice(),
        &[(true, false)],
        "续延跑且只跑一次，参数为 running=true / exit_blocked=false"
    );
    assert_eq!(
        refresh.lock().unwrap().as_slice(),
        &[true],
        "出口 IP 重探同样只在续延里排一次（留在主链上则探到的是校正前的旧出口）"
    );
}

/// TUN 成功腿须把稳定门从 selector 校正**无缝交接**给延迟 flush：校正续延已经发生时仍不能放行
/// 订阅；flush 因世代变化跳过后才放行。删任一接棒 guard 都会让中间断言或最终等待转红。
#[tokio::test]
async fn tun_reassert_hands_network_settle_gate_to_delayed_flush() {
    let mut cfg = reassert_config("node-a");
    cfg["proxyModeType"] = serde_json::json!("tun");
    let (rt, _dir, _sink, inval, _refresh, _fb) =
        reassert_runtime(&cfg, ab_tags(), BTreeMap::new());
    let uc: UserConfig = serde_json::from_value(cfg).unwrap();
    let my_gen = rt.gate.generation();

    rt.spawn_reassert_selector_selection(uc, my_gen, 0);
    assert!(
        !rt.network_settle.is_settled(),
        "spawn 返回前必须同步接棒，不能等后台 task 获得调度后才关门"
    );
    for _ in 0..100 {
        if !inval.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        !inval.lock().unwrap().is_empty(),
        "前提：selector 续延已发生"
    );
    assert!(
        !rt.network_settle.is_settled(),
        "reassert guard 退场后必须由延迟 flush guard 继续占门"
    );

    rt.bump_generation(); // 令 1.5s 后的 flush 走无网络的 superseded 腿。
    tokio::time::timeout(Duration::from_secs(3), rt.wait_for_network_settled())
        .await
        .expect("flush 跳过后稳定门应放行");
}

/// **不变式⑥**：reassert 中途 panic → 续延**仍必须跑**（= 上游 `.finally()` 的语义）。
///
/// 丢了续延的后果是静默的：解锁缓存永不失效，boot 窗口那轮经旧出口探到的脏结果永久留在缓存里，
/// 没有任何日志或 UI 迹象。
///
/// **变异锁**：把 `let _settled = ReassertSettledGuard(...)` 换成「await 之后直接调
/// `me.after_selector_reasserted(my_gen)`」→ panic 展开跳过该行 → 续延零次 → 转红。
#[tokio::test]
async fn continuation_still_runs_when_reassert_panics() {
    let (rt, _dir, sink, inval, refresh, _fb) =
        reassert_runtime(&reassert_config("node-a"), ab_tags(), BTreeMap::new());
    sink.panic_on_put.store(true, Ordering::SeqCst);
    let uc: UserConfig = serde_json::from_value(reassert_config("node-a")).unwrap();
    let my_gen = rt.gate.generation();
    // panic 的 backtrace 噪音对本门无意义，压掉（退场时还原，不影响并发跑的其它测试的默认 hook）。
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    rt.spawn_reassert_selector_selection(uc, my_gen, 0);
    for _ in 0..100 {
        if !inval.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    std::panic::set_hook(prev);
    assert!(sink.calls().is_empty(), "前提：PUT 在记录前就 panic 了");
    assert_eq!(
        inval.lock().unwrap().as_slice(),
        &[(true, false)],
        "reassert panic 也必须跑续延（Drop 守卫 = 上游的 .finally()）"
    );
    assert_eq!(
        refresh.lock().unwrap().as_slice(),
        &[true],
        "续延的两件事同进退：panic 腿也必须排出口 IP 重探"
    );
}

/// **接线守卫（源码型，非行为门）**：`start_inner` 只能 **spawn** 校正腿，且解锁失效 / 出口 IP
/// 重探**只能**在续延里发生。
///
/// 行为门够不着这三条：第一条是「不阻塞起核」（要真起核才量得到那 ≤3s）；后两条是「主链上没有
/// 第二个写者」—— 多失效一次 / 多排一次探测不改变任何可断言的终态，却会把 boot 窗口内经旧出口拿到的
/// 脏结果重新放回来。
///
/// **变异锁**：① 把 spawn 改成 `self.reassert_selector_selection(...).await` → 第一、二条转红；
/// ② 把 `self.invalidate_unlock_cache(true, false)` 加回起核主链 → 第三条转红；
/// ③ 把 `self.schedule_exit_ip_refresh(true)` 加回起核主链 → 第四条转红。
#[test]
fn start_inner_spawns_reassert_and_defers_unlock_invalidation() {
    let body = method_body(
        &module_code("runtime/proxy"),
        "    pub(super) async fn start_inner(",
    );
    assert_eq!(
        body.matches("self.spawn_reassert_selector_selection(")
            .count(),
        1,
        "起核就绪段必须**spawn**一次 selector 校正腿"
    );
    assert!(
        !body.contains("self.reassert_selector_selection("),
        "校正腿绝不能 await 在起核主链上：最坏 10×300ms≈3s，会挂在已经偏慢的起核路径上"
    );
    assert!(
        !body.contains("self.invalidate_unlock_cache("),
        "解锁失效必须只在校正的续延里发生（上游 F-C）：留在主链上则 boot 窗口内经**旧出口**\
             起跑的解锁轮，其结果会被当新鲜数据 commit 进缓存"
    );
    assert!(
        !body.contains("self.schedule_exit_ip_refresh("),
        "出口 IP 重探同理必须只在续延里排：留在主链上则校正一旦真翻转 selector，探到并写进 ipinfo \
             缓存的是**校正前那个出口**的公网 IP"
    );
    assert!(
        !body.contains("self.schedule_connection_flush("),
        "连接 flush 同理必须只在续延里排（上游「时序修 E」）：被 RST 的连接会立刻重连、且按重连\
             那一刻的 selector 建链 —— 早于校正就等于把用户全部连接亲手踢到 cache_file 的旧出口上"
    );
}

/// **接线守卫（源码型，非行为门）**：三条续延动作必须都在 `after_selector_reasserted` 里，
/// 且都排在世代守卫**之后**。
///
/// 与上一条互补：上一条证「主链上没有」，这条证「续延里真有且只有一份」——两条都在，删掉任一
/// 落点才必然有门转红（只有上一条时，把三行整个删掉是全绿的：主链确实也没有）。
///
/// 世代守卫的位置是承重的：这三条动作全部对着**起核那一刻的那个核**（广播 `running:true`、
/// 对 `api_port` 开 flush 枪）。把它们排在早退之前 = 核已被停/换时仍照发，等于亲手造假信号 +
/// 把新核刚建的连接 RST 掉。
///
/// **变异锁**：① 删 `after_selector_reasserted` 里任一行 → 对应计数转红；
/// ② 把世代早退挪到三行之后 → 位置断言转红。
#[test]
fn selector_reassert_continuation_holds_all_three_deferred_actions() {
    let body = method_body(
        &module_code("runtime/proxy"),
        "    fn after_selector_reasserted(",
    );
    for (needle, why) in [
        (
            "self.invalidate_unlock_cache(",
            "解锁失效（上游 F-C）：boot 窗口那轮量的是旧出口，必须作废重跑",
        ),
        (
            "self.schedule_exit_ip_refresh(",
            "出口 IP 重探：它量的就是「我现在从哪出去」，必须在校正落定后才排",
        ),
        (
            "self.schedule_connection_flush(",
            "连接 flush（上游 时序修 E）：RST 后的重连必须走校正后的 selector",
        ),
    ] {
        assert_eq!(
            body.matches(needle).count(),
            1,
            "`after_selector_reasserted` 必须恰含一次 `{needle}` —— {why}"
        );
    }
    let guard = body
        .find("if self.gate.generation() != my_gen")
        .expect("世代守卫消失，本门已失去判据");
    for needle in [
        "self.invalidate_unlock_cache(",
        "self.schedule_exit_ip_refresh(",
        "self.schedule_connection_flush(",
    ] {
        let at = body.find(needle).expect("上一条断言已保证存在");
        assert!(
            guard < at,
            "`{needle}` 必须排在世代早退之后：核已被停/换时照发 = 假的 running:true + 把新核\
                 刚建的连接 RST 掉"
        );
    }
}

fn group(tag: &str, selected: &str) -> GroupSelection {
    GroupSelection {
        tag: tag.to_string(),
        selected: selected.to_string(),
    }
}

/// **本缺陷的正身**：PUT 成功、生成产物也自洽，但核**运行期**仍停在 `cache_file` 的旧选择上
/// （真机血证：盘上 Hk01、`proxy-selector.default = "Hk01"`、核实走 `Tailscale`）。
///
/// `attest_selected_exit` 对这一幕恒判 `Match`（它比的是两份同源的意图）；本轴必须判出 drift。
///
/// **变异锁**：把 `attest_runtime_selection` 里 `got != member_tag` 改成 `false`（或整支直接返
/// `Match`）→ 转红。
#[test]
fn runtime_selection_drift_is_caught_where_static_attest_is_blind() {
    let got = attest_runtime_selection(
        &applied("Hk01", &[]),
        Some(&[group(PROXY_SELECTOR_TAG, "Tailscale")]),
    );
    match got {
        SelectorAttestation::GlobalDrift {
            want,
            got,
            rule_drifts,
        } => {
            assert_eq!(
                (want.as_str(), got.as_str(), rule_drifts),
                ("Hk01", "Tailscale", 0)
            );
        }
        other => panic!(
            "运行期分叉必须判 GlobalDrift，实得 {}",
            other.user_message()
        ),
    }
    // 对照：同一份意图下运行期确实是 Hk01 → 零告警（假阳性会让整条通道失信）。
    assert!(matches!(
        attest_runtime_selection(
            &applied("Hk01", &[]),
            Some(&[group(PROXY_SELECTOR_TAG, "Hk01")])
        ),
        SelectorAttestation::Match
    ));
}

/// **「没证据」不得报成「有问题」**：读不到快照（`None`）/ 快照里查无 `proxy-selector` → 判 `Match`。
///
/// 反过来做（读不到就报）会让每次管理 API 抖动都弹一条「流量没走选中节点」，而那一侧本来就已由
/// `PutExhausted` 腿覆盖 —— 同因异名的重复告警是把整条通道推向被无视的最快路径。
///
/// **变异锁**：把 `let Some(groups) = groups else { return Match }` 改成 `unwrap_or_default()`
/// （空切片继续往下走）→ 仍是 Match，本条不红；改成「读不到就 GlobalDrift」→ 两条断言都转红。
#[test]
fn unobservable_runtime_selection_stays_silent() {
    assert!(
        matches!(
            attest_runtime_selection(&applied("Hk01", &[]), None),
            SelectorAttestation::Match
        ),
        "读不到运行期快照 ≠ 出口走错"
    );
    assert!(
        matches!(
            attest_runtime_selection(
                &applied("Hk01", &[]),
                Some(&[group("some-other-group", "whatever")])
            ),
            SelectorAttestation::Match
        ),
        "快照里查无 proxy-selector ≠ 出口走错"
    );
}

/// **两条放弃腿必须变成用户可见信号**（此前只有 `log::warn`）：它们就是「selector 原样停在
/// cache_file 旧选择上」的那个状态。且它们**不依赖读回**（`groups=None` 照报）——管理 API 正是
/// 在这两腿下最可能读不到。
///
/// **变异锁**：把 `UnresolvedTag` / `PutExhausted` 任一支改成返 `Match`（= 退回只写日志）→ 转红。
#[test]
fn reassert_giveup_legs_are_reported_even_without_readback() {
    match attest_runtime_selection(
        &ReassertOutcome {
            stage1: Stage1Outcome::UnresolvedTag {
                selected_id: "node-x".into(),
            },
            rule_intents: Vec::new(),
        },
        None,
    ) {
        SelectorAttestation::NeverReasserted { selected_id } => {
            assert_eq!(selected_id, "node-x")
        }
        other => panic!("解析不出 tag 必须报，实得 {}", other.user_message()),
    }
    match attest_runtime_selection(
        &ReassertOutcome {
            stage1: Stage1Outcome::PutExhausted {
                member_tag: "Hk01".into(),
            },
            rule_intents: Vec::new(),
        },
        None,
    ) {
        SelectorAttestation::ReassertFailed { member_tag } => assert_eq!(member_tag, "Hk01"),
        other => panic!("PUT 跑满仍失败必须报，实得 {}", other.user_message()),
    }
    // 主动退场（核已停 / 世代已变）**不是**缺陷：那个核已经不是用户在看的那个了。
    assert!(matches!(
        attest_runtime_selection(
            &ReassertOutcome {
                stage1: Stage1Outcome::Abandoned,
                rule_intents: Vec::new(),
            },
            None
        ),
        SelectorAttestation::Match
    ));
}

/// 分流规则侧同轴：全局对上了、但 rule-sel 停在别处 → 仍要报（`RuleDrift`）；全局也错时并进
/// `GlobalDrift` 的计数，**不刷两条**（`error_code` 是单槽，后来的会把前一条挤掉）。
///
/// **变异锁**：删 `reassert_rule_selectors` 的返回值收集（intents 恒空）→ 第一段的 count 变 0 →
/// 转红；把 `rule_drifts.len()` 写死 0 → 第二段转红。
#[test]
fn rule_selector_drift_is_on_the_same_axis() {
    match attest_runtime_selection(
        &applied("Hk01", &[("rule-sel-r1", "Jp02"), ("rule-sel-r2", "Hk01")]),
        Some(&[
            group(PROXY_SELECTOR_TAG, "Hk01"),
            group("rule-sel-r1", "Tailscale"),
            group("rule-sel-r2", "Hk01"),
        ]),
    ) {
        SelectorAttestation::RuleDrift {
            count,
            sample_tag,
            want,
            got,
        } => {
            assert_eq!(count, 1, "只有 r1 分叉");
            assert_eq!(
                (sample_tag.as_str(), want.as_str(), got.as_str()),
                ("rule-sel-r1", "Jp02", "Tailscale")
            );
        }
        other => panic!("规则出口分叉必须报，实得 {}", other.user_message()),
    }
    match attest_runtime_selection(
        &applied("Hk01", &[("rule-sel-r1", "Jp02")]),
        Some(&[
            group(PROXY_SELECTOR_TAG, "Tailscale"),
            group("rule-sel-r1", "Tailscale"),
        ]),
    ) {
        SelectorAttestation::GlobalDrift { rule_drifts, .. } => assert_eq!(
            rule_drifts, 1,
            "全局与规则同时分叉 → 并成一条，规则数并进计数"
        ),
        other => panic!("全局分叉优先报，实得 {}", other.user_message()),
    }
}

/// **组合路径**（§K7.1：光测纯函数、光测 emit 都不够）：`Applied` + 桩里摆一份分叉的运行期快照
/// → 真 emit `event:proxyError`（`EXIT_MISMATCH`）+ 落 `status.error_code`，且**不把核标成未运行**。
///
/// **变异锁**：把 `attest_runtime_selector` 的告警腿改成 `log::warn!` → 零事件 → 转红（退回静默）。
#[tokio::test]
async fn attest_runtime_selector_emits_and_keeps_running() {
    let (rt, _dir, sink, events) =
        reassert_runtime_watching_errors(&reassert_config("node-a"), ab_tags(), BTreeMap::new());
    *sink.groups.lock().unwrap() = Some(vec![group(PROXY_SELECTOR_TAG, "Tailscale")]);
    let my_gen = rt.gate.generation();

    rt.attest_runtime_selector(&applied("A", &[]), my_gen).await;

    let got = events.lock().unwrap().clone();
    assert_eq!(
        got.len(),
        1,
        "运行期分叉必须发一条 proxyError，实得 {got:?}"
    );
    assert_eq!(got[0].1, code::EXIT_MISMATCH);
    assert!(
        got[0].0.contains("Tailscale"),
        "文案须点名实际出口：{}",
        got[0].0
    );
    assert!(rt.status().running, "核确在跑 → 不得标成未运行");
    assert_eq!(rt.status().error_code.as_deref(), Some(code::EXIT_MISMATCH));
}

/// 一致 → **零告警**；且世代已变时**整段退场**（读到什么都不是「用户在看的那个核」的事实）。
///
/// **变异锁**：删 `attest_runtime_selector` 的世代/存活守卫 → 第二段转红（对着换代后的核报了一条）。
#[tokio::test]
async fn attest_runtime_selector_silent_when_consistent_or_superseded() {
    let (rt, _dir, sink, events) =
        reassert_runtime_watching_errors(&reassert_config("node-a"), ab_tags(), BTreeMap::new());
    *sink.groups.lock().unwrap() = Some(vec![group(PROXY_SELECTOR_TAG, "A")]);
    let my_gen = rt.gate.generation();
    rt.attest_runtime_selector(&applied("A", &[]), my_gen).await;
    assert!(
        events.lock().unwrap().is_empty(),
        "运行期一致不得告警，实得 {:?}",
        events.lock().unwrap()
    );

    // 世代已变：即便快照分叉、即便终局是放弃腿，也一律不报。
    *sink.groups.lock().unwrap() = Some(vec![group(PROXY_SELECTOR_TAG, "Tailscale")]);
    rt.attest_runtime_selector(&applied("A", &[]), my_gen.wrapping_add(1))
        .await;
    rt.attest_runtime_selector(
        &ReassertOutcome {
            stage1: Stage1Outcome::PutExhausted {
                member_tag: "A".into(),
            },
            rule_intents: Vec::new(),
        },
        my_gen.wrapping_add(1),
    )
    .await;
    assert!(
        events.lock().unwrap().is_empty(),
        "世代已变 → 整段退场，实得 {:?}",
        events.lock().unwrap()
    );
}

/// **终局必须真从校正腿带出来**（而不是自证自己另算一份）：管理 API 一直不就绪 → 跑满重试 →
/// `PutExhausted{member_tag}`，且 tag 是最后一轮的**最新**意图。
///
/// 这是「放弃腿此前只写 log」那个洞的正身：终局若还是 `()`，调用方无从分辨成功与放弃。
///
/// **变异锁**：把 stage 1 里 `stage1 = Stage1Outcome::PutExhausted{...}` 那行删掉（回到只在函数
/// 开头设一次初值）→ `member_tag` 变空串 → 转红。
#[tokio::test]
async fn reassert_outcome_reports_put_exhaustion_with_latest_intent() {
    let (rt, _dir, sink, _events) =
        reassert_runtime_watching_errors(&reassert_config("node-a"), ab_tags(), BTreeMap::new());
    sink.fail_first
        .store(ProxyRuntime::REASSERT_MAX_ROUNDS as u32, Ordering::SeqCst);
    let cfg: UserConfig = serde_json::from_value(reassert_config("node-a")).unwrap();
    let my_gen = rt.gate.generation();

    let outcome = rt.reassert_selector_selection(&cfg, my_gen).await;

    match outcome.stage1 {
        Stage1Outcome::PutExhausted { member_tag } => assert_eq!(
            member_tag, "A",
            "跑满退出时终局须带最后一轮的意图 tag（供文案点名）"
        ),
        _ => panic!("PUT 全失败必须留下 PutExhausted 终局"),
    }
    assert_eq!(
        sink.calls().len(),
        ProxyRuntime::REASSERT_MAX_ROUNDS,
        "前提：确实跑满了重试轮"
    );
}

/// 解析不出 tag（选中节点不在运行核 tag 映射里）→ `UnresolvedTag`，**且一次 PUT 都不发**。
///
/// **变异锁**：把该腿的 `stage1 = Stage1Outcome::UnresolvedTag{...}` 删掉 → 终局退化成
/// `PutExhausted{member_tag: ""}` → 转红。
#[tokio::test]
async fn reassert_outcome_reports_unresolved_tag_without_putting() {
    // tag 映射里只有 node-b，选中的却是 node-a。
    let (rt, _dir, sink, _events) = reassert_runtime_watching_errors(
        &reassert_config("node-a"),
        BTreeMap::from([("node-b".to_string(), "B".to_string())]),
        BTreeMap::new(),
    );
    let cfg: UserConfig = serde_json::from_value(reassert_config("node-a")).unwrap();
    let my_gen = rt.gate.generation();

    let outcome = rt.reassert_selector_selection(&cfg, my_gen).await;

    match outcome.stage1 {
        Stage1Outcome::UnresolvedTag { selected_id } => assert_eq!(selected_id, "node-a"),
        _ => panic!("tag 解析不出必须留下 UnresolvedTag 终局（此前只有一行 log::warn）"),
    }
    assert!(
        sink.calls().is_empty(),
        "从未解析出 tag → 一次 PUT 都不该发"
    );
}

/// **接线门**：阶段 2 尝试过的 rule-sel 意图必须原样带回终局 —— 否则读回来也没东西可对账。
///
/// **变异锁**：把 `reassert_rule_selectors` 的 `intents.extend(...)` 改回丢弃返回值 → 转红。
#[tokio::test]
async fn reassert_outcome_carries_rule_intents_for_readback() {
    let mut cfg = reassert_config("node-a");
    cfg["customRules"] = serde_json::json!([
        { "id": "r1", "type": "domain", "values": ["x.com"], "action": "proxy",
          "enabled": true, "targetServerId": "node-b" }
    ]);
    let rule_target = BTreeMap::from([(
        "custom:r1".to_string(),
        RuleTargetEntry {
            selector_tag: "rule-sel-r1 (1)".into(),
            member_tag: "B".into(),
        },
    )]);
    let (rt, _dir, _sink, _events) = reassert_runtime_watching_errors(&cfg, ab_tags(), rule_target);
    let uc: UserConfig = serde_json::from_value(cfg).unwrap();
    let my_gen = rt.gate.generation();

    let outcome = rt.reassert_selector_selection(&uc, my_gen).await;

    assert_eq!(
        outcome.rule_intents,
        vec![("rule-sel-r1 (1)".to_string(), "B".to_string())],
        "rule-sel 的意图必须带回（含撞名去重后缀），否则读回对账无从下手"
    );
}

/// **接线门（行为型）**：`spawn_reassert_selector_selection` 必须在校正之后真跑一次自证，
/// 且自证**排在续延之后**（续延不为一次只读观测多等一个 gRPC 往返，最坏 3s 快照超时）。
///
/// 判据：**告警发出的那一刻**续延（解锁失效）已经跑过 —— 只看「两件事都发生了」验不出顺序，
/// 而后台腿里两者可能只隔微秒，轮询采样必然 flaky。故在 `emit_proxy_error` 里给续延拍照
/// （`error_seen_invalidations`），断言拍到的是 1。
///
/// **变异锁**：① 删 `spawn_reassert_selector_selection` 里的 `me.attest_runtime_selector(...)` →
/// 零告警 → 转红；② 把内层作用域去掉（守卫活到 task 末尾，续延晚于自证）→ 拍到 0 → 转红。
#[tokio::test]
async fn spawn_runs_attestation_after_continuation() {
    let (rt, _dir) = test_runtime();
    let events: ErrorEvents = Arc::new(Mutex::new(Vec::new()));
    let inval: UnlockInvalidations = Arc::new(Mutex::new(Vec::new()));
    let seen: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
    rt.set_error_emitter(Box::new(RecordingErrorEmitter {
        events: Arc::clone(&events),
        unlock_invalidations: Arc::clone(&inval),
        error_seen_invalidations: Arc::clone(&seen),
        ..Default::default()
    }));
    let sink = Arc::new(TestPutSink::default());
    // PUT 成功（默认），但运行期快照分叉 → 自证必报。
    *sink.groups.lock().unwrap() = Some(vec![group(PROXY_SELECTOR_TAG, "Tailscale")]);
    *rt.management_api_stub.lock().unwrap() = Some(Arc::clone(&sink));
    mark_running(&rt);
    let cfg = reassert_config("node-a");
    let uc: UserConfig = serde_json::from_value(cfg.clone()).unwrap();
    *rt.switch_snapshot.write().unwrap() = Some(SwitchSnapshot {
        id_to_tag: ab_tags(),
        fingerprints: node_fingerprints::modified_table(&uc.servers),
        dirty_fingerprints: node_fingerprints::dirty_table(&uc.servers),
        ..Default::default()
    });
    *rt.current_config.write().unwrap() = Some(cfg);
    let my_gen = rt.gate.generation();

    rt.spawn_reassert_selector_selection(uc, my_gen, 0);
    for _ in 0..100 {
        if !events.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let got = events.lock().unwrap().clone();
    assert_eq!(got.len(), 1, "spawn 腿必须真跑一次运行期自证，实得 {got:?}");
    assert_eq!(got[0].1, code::EXIT_MISMATCH);
    assert_eq!(
        seen.lock().unwrap().as_slice(),
        &[1],
        "告警那一刻续延必须已经恰好跑过一次（自证不得挡在三条续延前面）"
    );
}

/// 🔴 **`clash_api_secret` 必须投影读，不得整份深拷贝配置。**
///
/// # 为什么必须是源码型守卫
///
/// `current()` 与 `with_current()` 的返回值**逐字节相同** —— 差别只在「谁付整份 clone 的账」
/// （`runtime/config.rs:181-196` 自陈）。任何行为断言都区分不出这两者，退回深拷贝**没有任何测试
/// 会红**，而代价是：调用链 `probe_select_slot → hot_switch_selector → management_api → 本方法`
/// 意味着**测速一轮 = N 次整份用户配置深拷贝**（含全部 `servers` 与规则），且所有热切节点的路径
/// 都付这笔账。这正是「静默回退无人察觉」的形态，故补本条结构守卫。
///
/// **变异锁**：把 `with_current` 换回 `.current()` → 两条断言全红。
#[test]
fn clash_api_secret_projects_instead_of_deep_copying_the_config() {
    let body = method_body(
        &module_code("runtime/proxy"),
        "    pub(super) fn clash_api_secret(&self) -> String {",
    );
    assert!(
        body.contains("with_current"),
        "必须走持锁投影：只取一个字符串字段，不 clone 整份配置"
    );
    assert!(
        !body.contains(".current()"),
        "`current()` 恒 clone 整份用户配置（含全部 servers）—— 热切路径上按 N 次计费"
    );
}

// ══════════════ §15：测速 dirty 波前预筛的指纹开口 ══════════════

/// `speed_probe_targets` 必须带出**起核时刻的节点指纹表**（dirty 波前预筛的唯一诚实判据）。
///
/// 消费侧要判「运行核里的这个节点还是不是用户现在配置的那个」，只能拿指纹比 —— 而
/// `pending_changes()` 的 `updated` 是 **id 交集**（不是指纹比对），拿它当 dirty 会把每个既有节点
/// 全判脏。故必须把指纹本身开口子带出来。
///
/// **变异锁**：删掉 `fingerprints` 的透传（填 `BTreeMap::new()`）→ 第二条断言转红；
/// 把它接成 `id_to_tag` → 值不符转红。
#[test]
fn speed_probe_targets_carry_running_core_fingerprints() {
    let (rt, _dir) = test_runtime();
    *rt.status.write().unwrap() = ProxyStatus {
        running: true,
        ..Default::default()
    };
    *rt.switch_snapshot.write().unwrap() = Some(SwitchSnapshot {
        id_to_tag: BTreeMap::from([("id-a".to_string(), "东京 03".to_string())]),
        // 全维表（喂重启判据 + pending modified）与 5 维表（喂测速 dirty）刻意填成不同值：
        // 带错哪一张，下面的断言立刻说话。
        fingerprints: BTreeMap::from([("id-a".to_string(), "全维-a".to_string())]),
        dirty_fingerprints: BTreeMap::from([("id-a".to_string(), "fp-a".to_string())]),
        probe_pool_ports: vec![41001, 41002],
        ..Default::default()
    });

    let t = rt.speed_probe_targets().expect("核在跑 + 池非空 → Some");
    assert_eq!(t.pool_ports, vec![41001, 41002]);
    assert_eq!(
        t.fingerprints.get("id-a").map(String::as_str),
        Some("fp-a"),
        "必须带出 **5 维** dirty 表：带成全维表 → 与测速「新」侧公式不同 → 恒不等 → 全员恒 dirty"
    );
    assert_eq!(t.id_to_tag.get("id-a").map(String::as_str), Some("东京 03"));
}

// ══════════════════════════════════════════════════════════════════════════════
// 自动换节点心跳「选中节点须真实存在」守卫（item 10）
// ══════════════════════════════════════════════════════════════════════════════

/// **item 10 · 心跳守卫谓词**（上游 `AutoSwitchService.runHeartbeat`:113-116）真值表。
///
/// **变异锁**：谓词恒 true → 「direct/悬挂 → false」断言转红（direct 网络抖动误切回归）；
/// 恒 false → 「真实节点 → true」断言转红（正常节点心跳被永久跳过）。
#[test]
fn selected_server_present_truth_table() {
    let real = serde_json::json!({
        "selectedServerId": "a",
        "servers": [{ "id": "a" }, { "id": "b" }]
    });
    assert!(
        selected_server_present(&real),
        "选中真实节点 → true（放行心跳）"
    );

    let direct = serde_json::json!({
        "selectedServerId": "__direct__",
        "servers": [{ "id": "a" }]
    });
    assert!(
        !selected_server_present(&direct),
        "direct 哨兵不在 servers → false（跳过心跳，不切走）"
    );

    let dangling = serde_json::json!({
        "selectedServerId": "gone",
        "servers": [{ "id": "a" }]
    });
    assert!(
        !selected_server_present(&dangling),
        "选中被删（id 悬挂）→ false"
    );

    let no_sel = serde_json::json!({ "servers": [{ "id": "a" }] });
    assert!(!selected_server_present(&no_sel), "无选中 → false");

    let no_servers = serde_json::json!({ "selectedServerId": "a" });
    assert!(
        !selected_server_present(&no_servers),
        "servers 缺失 → false"
    );

    let empty_servers = serde_json::json!({ "selectedServerId": "a", "servers": [] });
    assert!(
        !selected_server_present(&empty_servers),
        "servers 空数组 → false"
    );
}

// ── #14 反向不变式：喂进 sing-box 生成的 config 键必须对 norm 可见 ──────────────────
//
// 淬火不变式 #14 原文预言过一次**风险方向反转**，本仓已实证发生：
// - 上游侧 norm 是「全量哈希 + 排除表」⇒ 漏加**排除**项 = 多重启一次（吵，但看得见）；
// - 本仓 norm 是「白名单入投影」（`UserConfig::FIELD_NAMES`）⇒ 漏加**白名单**项 =
//   `config_generation_norm` 恒相等 → 落 NoOp 腿 → **永不进 pending 差集**：改了要重启内核，
//   而 pending-bar 不出现、U-7 弹窗也不出现，全程零提示（`ui/src/domain/app-restart-keys.ts`
//   称之为「第四类重启」）。少提示是静默的，比多提示危险得多。
//
// 方向反了，守卫也必须反过来写：不是「排除表别漏」（那条由 config-engine 的
// `exclusion_table_live_entries_are_pinned` 钉着），而是**「生成侧消费的键别漏进 FIELD_NAMES」**。

/// `GenerateConfigDeps` 的装配体 —— 原始 config JSON 进入生成侧的**唯一**通道。
///
/// 用返回类型行当锚点（而非 `fn generate_deps(`）是刻意的：[`method_body`] 从锚点末尾起切，
/// 用函数头会把参数列表 `config: &Value` 一起切进来，下面的「参数用了几次」就恒多数一次。
const DEPS_ASSEMBLY: &str = "    ) -> GenerateConfigDeps {";

/// 装配体里**唯一**允许的裸 JSON 取值点（形参 `config` 的全部去向）。
///
/// 新增一个 `xxx_from_config(config)` 或直接写 `config.get("k")` → 下面的「用了恰好一次」转红，
/// 逼改动者把新读法登记进本表，随后 [`raw_keys`] 会把它读的键一并纳入可见性判定。
const RAW_CONFIG_READERS: &[&str] = &["fn log_axes_from_config("];

/// 形参 `param` 在 `body` 里被当**标识符**用了几次（`self.config` 这类字段访问不计）。
///
/// 按标识符边界判而非裸 `contains`：否则 `config_log` / `log_axes_from_config` 这些**含**
/// `config` 的名字会把计数喂饱，守卫失去分辨力。
fn param_use_count(body: &str, param: &str) -> usize {
    let bytes = body.as_bytes();
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    body.match_indices(param)
        .filter(|(i, _)| {
            let before = if *i == 0 { None } else { Some(bytes[i - 1]) };
            let after = bytes.get(i + param.len()).copied();
            // 左边是标识符字符 ⇒ 是更长名字的一截；左边是 `.` ⇒ 字段访问（`self.config`）。
            !matches!(before, Some(c) if ident(c) || c == b'.')
                && !matches!(after, Some(c) if ident(c))
        })
        .count()
}

/// 函数体里所有 `.get("键")` 的键名。
fn raw_keys(body: &str) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    let mut rest = body;
    while let Some(i) = rest.find(".get(\"") {
        let after = &rest[i + ".get(\"".len()..];
        match after.find('"') {
            Some(j) => {
                out.insert(after[..j].to_string());
                rest = &after[j..];
            }
            None => break,
        }
    }
    out
}

/// 🔴 **生成侧读到的每个 config 键都必须在 `UserConfig::FIELD_NAMES` 里**（#14 反向不变式）。
///
/// 不在 ⇒ 该键改了 `config_generation_norm` 也不变 ⇒ 永不进 pending 差集 ⇒ 静默跑陈旧核。
///
/// **变异锁**：把 `log_axes_from_config(config)` 从装配体里删掉 → 第一条断言（用了恰好一次）转红；
/// 往 `log_axes_from_config` 里加一个不在 `FIELD_NAMES` 的键 → 末条断言转红。
#[test]
fn every_generation_input_key_is_visible_to_norm() {
    let src = module_code("runtime/proxy");
    let deps = method_body(&src, DEPS_ASSEMBLY);
    assert!(
        !deps.contains("fn "),
        "装配体切过头了（切到了下一个函数）—— 下面的断言正在扫一段不属于 generate_deps 的源码"
    );

    // ① 通道封闭：形参 `config` 只许流向登记在册的读法，且**恰好一次**。
    assert_eq!(
        param_use_count(&deps, "config"),
        RAW_CONFIG_READERS.len(),
        "`generate_deps` 里对原始 config 的取值点数目变了。新增取值点必须登记进 RAW_CONFIG_READERS，\
             否则它读的键逃过本守卫 —— 那正是「第四类重启」的生成方式。当前体：\n{deps}"
    );
    for reader in RAW_CONFIG_READERS {
        let name = reader.trim_start_matches("fn ").trim_end_matches('(');
        assert!(
            deps.contains(&format!("{name}(config)")),
            "登记在册的读法 `{name}(config)` 在装配体里找不到 —— 表与代码已分叉"
        );
    }

    // ② 登记在册的读法读了哪些键。
    let mut keys = std::collections::BTreeSet::new();
    for reader in RAW_CONFIG_READERS {
        let body = crate::commands::guard_scan::top_level_fn_body(&src, reader);
        let found = raw_keys(&body);
        assert!(
            !found.is_empty(),
            "`{reader}` 里一个 `.get(\"…\")` 都没扫到 —— 取材器失配，本守卫已退化成恒真断言"
        );
        keys.extend(found);
    }

    // ③ 可见性判定。
    let visible: std::collections::BTreeSet<&str> =
        UserConfig::FIELD_NAMES.iter().copied().collect();
    let invisible: Vec<&str> = keys
        .iter()
        .map(String::as_str)
        .filter(|k| !visible.contains(k))
        .collect();
    assert!(
        invisible.is_empty(),
        "这些键喂进了 sing-box 生成，却不在 `UserConfig::FIELD_NAMES` 里：{invisible:?}\n\
             ⇒ 改它们 `config_generation_norm` 恒相等 → 落 NoOp 腿 → **永不进 pending 差集**：\
             核在跑时改了要重启才生效，而 pending-bar 与 U-7 弹窗都不出现，全程零提示。\n\
             修法：把它加进 `UserConfig`（值可以是 `serde_json::Value` —— 本结构只需要「看得见变化」，\
             不需要解释它），或说明它为何根本不该影响生成、从而不必被生成侧读。"
    );
}

/// 🔴 **第四类重启已消灭**（行为门，钉住上一条断言背后的那个事实）。
///
/// 上一条是源码扫描：它保证「表与代码一致」，但**证明不了 norm 真的动了**——
/// 键在 `FIELD_NAMES` 里而投影却把它排掉（比如有人往 `config_generation_norm` 的排除表里
/// 补一行），扫描面照样全绿。本条从行为侧钉死：两键一变，norm 必须判不等。
///
/// **变异锁**：把这两个字段从 `UserConfig` 摘掉（或在 norm 的排除表里加上它们）→ 第一条断言转红。
#[test]
fn log_axes_changes_are_visible_to_norm() {
    // `servers` 无 serde default（缺了整份配置解析不出来）→ 两份都带上空数组，
    // 让唯一的变量真的只有这两个键。
    let base = serde_json::json!({ "servers": [], "logLevel": "info", "disableLogFile": false });
    let flipped = serde_json::json!({ "servers": [], "logLevel": "debug", "disableLogFile": true });
    let norm = |v: &Value| {
        config_generation_norm(
            &serde_json::from_value::<UserConfig>(v.clone()).expect("测试配置必须可解析"),
            None,
        )
    };
    assert_ne!(
        norm(&base),
        norm(&flipped),
        "改日志两轴必须让 norm 判不等 —— 否则它们又回到「改了要重启核而差集看不见」的第四类"
    );
    assert_ne!(
        log_axes_from_config(&base),
        log_axes_from_config(&flipped),
        "两键必须真的改变生成输入，否则上面那条 norm 断言守的是一个不存在的因果"
    );
}

/// 🔴 **取值域不由本仓独占 ⇒ 解析必须宽容**（`Value` 而非强类型的理由，钉成门）。
///
/// `UserConfig` 解析是全有全无的：一旦 `Err`，起核腿整个放弃。若把 `logLevel` 收紧成 `LogLevel`，
/// 一份写着 sing-box 的 `trace`（或任何手改值）的配置会从「日志级别退化成 info」变成「**起不了核**」。
///
/// **变异锁**：把 `log_level` 改成 `Option<LogLevel>` → 第一条转红。
#[test]
fn unknown_log_level_still_parses_and_degrades_to_info() {
    let cfg = serde_json::json!({ "servers": [], "logLevel": "trace", "disableLogFile": 1 });
    let parsed = serde_json::from_value::<UserConfig>(cfg.clone());
    assert!(
        parsed.is_ok(),
        "本仓不认识的 logLevel 取值不得让整份 UserConfig 解析失败（那等于起不了核）：{:?}",
        parsed.err()
    );
    assert_eq!(
        log_axes_from_config(&cfg),
        (polaris_config_engine::user_config::LogLevel::Info, false),
        "值的解释权仍在 log_axes_from_config：非法级别退化 Info、非 true 的 disableLogFile 记 false"
    );
}
