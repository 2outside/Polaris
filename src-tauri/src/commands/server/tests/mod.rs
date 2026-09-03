use super::*;
use crate::runtime::config::ConfigManager;
use crate::test_support::{crate_code, TestDir};

fn temp_dir(tag: &str) -> TestDir {
    TestDir::new(&format!("polaris-server-add-{tag}-"))
}

fn seed_switch_nodes(mgr: &ConfigManager) {
    let mut cfg = mgr.load_full().unwrap();
    cfg["servers"] = json!([
        {"id":"n-a","name":"A","protocol":"trojan","address":"1.1.1.1","port":443,"password":"pw"},
        {"id":"n-b","name":"B","protocol":"trojan","address":"2.2.2.2","port":443,"password":"pw"},
        {"id":"n-c","name":"C","protocol":"trojan","address":"3.3.3.3","port":443,"password":"pw"}
    ]);
    cfg["selectedServerId"] = json!("n-a");
    mgr.save_full(&cfg).unwrap();
}

#[test]
fn server_switch_core_updates_selection_and_mru_in_one_write() {
    let dir = temp_dir("switch-core");
    let mgr = ConfigManager::new(dir.clone());
    seed_switch_nodes(&mgr);

    let (cfg, changed) = server_switch_core(&mgr, "n-b", |_| Ok(()), || {}).expect("切换应成功");
    assert!(changed);
    assert_eq!(cfg["selectedServerId"], json!("n-b"));
    assert_eq!(cfg["recentServerIds"], json!(["n-b"]));
    assert_eq!(mgr.load_full().unwrap()["selectedServerId"], json!("n-b"));
}

#[test]
fn server_switch_rejects_binding_preflight_before_persisting() {
    let dir = temp_dir("switch-binding-preflight");
    let mgr = ConfigManager::new(dir.clone());
    seed_switch_nodes(&mgr);

    let error = server_switch_core(
        &mgr,
        "n-b",
        |_| Err("OUTBOUND_INTERFACE_UNAVAILABLE: missing=[en7], down=[]".into()),
        || panic!("被拒绝的 selector 不得取得意图所有权"),
    )
    .expect_err("缺失活跃网卡必须拒绝");
    assert!(matches!(error, ServerSwitchError::InterfaceUnavailable(_)));
    let persisted = mgr.load_full().unwrap();
    assert_eq!(persisted["selectedServerId"], json!("n-a"));
    assert!(persisted.get("recentServerIds").is_none());
}

/// 调用点门：ConfigManager::update 已有强制交错的并发行为测；这里补生产入口接线，避免
/// `server_switch_core` 被改回 load_full → save_full 分离三步后那条底层测试仍然假绿。
///
/// # 取材面是 [`crate_code`]（剥注释面），封顶用共用的 [`top_level_fn_body`]
///
/// 三条正面判据（`.update(|cfg|` 存在 + `register_intent` 早于 `Decision::Write`）在未剥注释的
/// 面上可被一句行尾注释喂饱：把 `.update(|cfg|` 换回 `load_full()`/`save_full(` 三步、行尾补一句
/// `// 仍走 .update(|cfg|`，肯定断言照绿（否定断言那两条则反过来被注释绊成假红）。
/// 旧写法的**终点锚**还是下一项的文档注释 `/// 上游 SERVER_SWITCH` —— 那句话被改一个字，门就
/// 从「封顶到函数末」退化成 panic 或超宽切片。改用列 0 `}` 封顶的共用取材器后两处都消失。
///
/// [`top_level_fn_body`]: crate::commands::guard_scan::top_level_fn_body
#[test]
fn server_switch_core_uses_atomic_config_update() {
    let body = crate::commands::guard_scan::top_level_fn_body(
        &crate_code("commands/server.rs"),
        "fn server_switch_core<F>(",
    );
    let body = body.as_str();
    assert!(body.contains(".update(|cfg|"), "切节点必须走原子 update");
    let claim = body.rfind("register_intent").expect("selector 意图 claim");
    let write = body.find("Decision::Write").expect("配置写入");
    assert!(
        claim < write,
        "用户 selector 所有权必须在同一写事务内先于落盘取得"
    );
    assert!(!body.contains("load_full()"), "不得退回分离读改写");
    assert!(!body.contains("save_full("), "不得退回分离读改写");
}

/// A7 · 删节点后选中出口的旧→新转换 → `selected_exit_changed` 判失效（server_delete / batch 共用腿的牙）。
/// 打断 `apply_selection_fallback`（不改选中）→「删选中 → 变」断言转红；打断 `selected_exit_changed` → 转红。
/// cfg 传**删后 servers**（viable 校验看删后集）。此腿走哨兵/兜底，不产生 →null（→null 由订阅腿覆盖）。
#[test]
fn delete_selection_transition_signals_exit_change() {
    // 删当前选中 + 有存活兜底 → 选中回落兜底（!= 旧 id）→ 出口变。
    let mut cfg = json!({ "selectedServerId": "a", "servers": [{ "id": "b" }] });
    let old = cfg["selectedServerId"].as_str().map(str::to_string);
    apply_selection_fallback(&mut cfg, true, Some("b"));
    let new = cfg.get("selectedServerId").and_then(Value::as_str);
    assert_eq!(new, Some("b"), "存活兜底 → 采用");
    assert!(
        selected_exit_changed(old.as_deref(), new),
        "删选中 → 出口变（失效）"
    );

    // 删当前选中 + 无存活兜底（删光）→ 回落直连哨兵（!= 旧 id）→ 仍出口变。
    let mut cfg2 = json!({ "selectedServerId": "a", "servers": [] });
    let old2 = cfg2["selectedServerId"].as_str().map(str::to_string);
    apply_selection_fallback(&mut cfg2, true, None);
    let new2 = cfg2.get("selectedServerId").and_then(Value::as_str);
    assert_eq!(new2, Some(DIRECT_SERVER_ID), "无兜底 → 直连哨兵");
    assert!(
        selected_exit_changed(old2.as_deref(), new2),
        "删光选中 → 出口变（失效）"
    );

    // 删非选中节点 → 选中不动 → 出口不变（守卫白刷）。
    let mut cfg3 = json!({ "selectedServerId": "a", "servers": [{ "id": "a" }] });
    let old3 = cfg3["selectedServerId"].as_str().map(str::to_string);
    apply_selection_fallback(&mut cfg3, false, Some("a"));
    let new3 = cfg3.get("selectedServerId").and_then(Value::as_str);
    assert_eq!(new3, Some("a"), "删非选中 → 选中不动");
    assert!(
        !selected_exit_changed(old3.as_deref(), new3),
        "删非选中 → 出口不变（不失效）"
    );
}

#[test]
fn ensure_server_id_mints_when_missing_or_empty_keeps_existing() {
    let minted = ensure_server_id(json!({ "name": "n", "protocol": "vless" }));
    assert!(
        minted["id"].as_str().is_some_and(|s| !s.is_empty()),
        "缺 id → mint"
    );
    let empty = ensure_server_id(json!({ "id": "", "name": "n" }));
    assert!(
        empty["id"].as_str().is_some_and(|s| !s.is_empty()),
        "空 id → mint"
    );
    let kept = ensure_server_id(json!({ "id": "keep-me", "name": "n" }));
    assert_eq!(kept["id"], json!("keep-me"), "已有 id → 保留");
}

/// 真实 ConfigStore 端到端：无 id 的手动节点经 server_add_core → 落盘带新 id 且**存活**（有 id 才不被
/// sanitize 丢弃）。回归到「直接 push 不补 id」→ sanitize 丢弃 → servers.len()==0，此测转红。
#[test]
fn server_add_core_persists_node_with_minted_id() {
    let dir = temp_dir("persist");
    // 完整可过 sanitize/validate 的 trojan 节点，但无 id。
    let node = json!({
        "name": "手动节点",
        "protocol": "trojan",
        "address": "1.2.3.4",
        "port": 443,
        "password": "pw",
    });
    {
        let mgr = ConfigManager::new(dir.clone());
        server_add_core(&mgr, node).expect("server_add_core 应成功");
    }
    // 重 load 自磁盘。
    let mgr2 = ConfigManager::new(dir.clone());
    let cfg = mgr2.load_full().unwrap();
    let servers = cfg["servers"].as_array().unwrap();
    assert_eq!(
        servers.len(),
        1,
        "落盘节点存活（有 id 才不被 sanitize 丢弃）"
    );
    assert!(
        servers[0]["id"].as_str().is_some_and(|s| !s.is_empty()),
        "落盘节点带非空 id"
    );
    assert_eq!(servers[0]["name"], json!("手动节点"));
}

/// D4 兜底出口的 viable 校验（单删/批删共用）：传入的兜底 id 必须**存活于删除后的 servers**。
/// 回归到「前端传被删节点自身 id」→ 该 id 已不在 servers → 必须落直连哨兵而非把死 id 写回选中。
/// A5：logout runningNeedsRestart 装配判定。核未跑 / 快照缺失 → false；运行中且该 TS 节点在运行配置里 → true。
/// 回归到硬编码 false（旧态）或打断 crate 调用 → 「true」用例转红。
#[test]
fn logout_needs_restart_true_only_when_ts_in_running_core() {
    use polaris_config_engine::user_config::server_config::{Protocol, ServerConfig};

    // 运行配置含 id=ts1 的 tailscale 节点（round-trip 保证可反序列化）。
    let mut cfg = UserConfig::default();
    cfg.servers.push(ServerConfig {
        id: "ts1".into(),
        protocol: Protocol::Tailscale,
        ..Default::default()
    });
    let running = serde_json::to_value(&cfg).unwrap();

    assert!(
        logout_needs_restart("ts1", true, Some(&running)),
        "运行中 + TS 节点在运行核 → 需重启"
    );
    assert!(
        !logout_needs_restart("other", true, Some(&running)),
        "节点不在运行核 → 无需重启"
    );
    assert!(
        !logout_needs_restart("ts1", false, Some(&running)),
        "核未跑 → 无需重启"
    );
    assert!(
        !logout_needs_restart("ts1", true, None),
        "运行配置快照缺失 → 保守 false"
    );
}

/// 项2（server:addBulk 返回实际新增数）：核心须返回 `added == 入参 len`（对齐 上游 `added=list.length`），
/// 且节点真落盘。变异牙：回归到硬编码 0（`Ok((cfg, 0))`）→「added==3」断言转红；打断 push/init 落盘 →
/// 重 load 的 servers.len() 断言转红。
#[test]
fn server_add_bulk_core_returns_actual_added_count() {
    let dir = temp_dir("bulk");
    // 3 条可过 sanitize/validate 的 trojan 节点（无 id，addBulk 强制 mint）。
    let nodes = vec![
        json!({"name":"A","protocol":"trojan","address":"1.1.1.1","port":443,"password":"pw"}),
        json!({"name":"B","protocol":"trojan","address":"2.2.2.2","port":443,"password":"pw"}),
        json!({"name":"C","protocol":"trojan","address":"3.3.3.3","port":443,"password":"pw"}),
    ];
    let expected = nodes.len();
    {
        let mgr = ConfigManager::new(dir.clone());
        let (_cfg, added) = server_add_bulk_core(&mgr, nodes).expect("server_add_bulk_core 应成功");
        assert_eq!(
            added, expected,
            "返回实际新增数（= 入参 len），此前硬编码 0"
        );
    }
    // 重 load 自磁盘核实：3 条自建节点存活。
    let cfg = ConfigManager::new(dir.clone()).load_full().unwrap();
    let servers = cfg["servers"].as_array().unwrap();
    assert_eq!(servers.len(), expected, "批量节点全部落盘存活");
    assert!(
        servers
            .iter()
            .all(|s| s["id"].as_str().is_some_and(|i| !i.is_empty())),
        "每个落盘节点带非空 mint id"
    );
}

/// 托盘 MRU 入队（`push_recent_server_id`）：去重插队首 + 上限 3。牙：打断 `retain` 去重 → 重选同一
/// 节点会在列表中重复出现，断言转红；打断 `truncate(3)` → 第 4 项断言转红；打断 `insert(0,..)`
/// （改用 push 到队尾）→ 「最近一次在最前」断言转红。
#[test]
fn push_recent_server_id_dedupes_and_caps_at_three() {
    let mut obj = Map::new();
    push_recent_server_id(&mut obj, "a");
    push_recent_server_id(&mut obj, "b");
    push_recent_server_id(&mut obj, "c");
    assert_eq!(
        obj["recentServerIds"],
        json!(["c", "b", "a"]),
        "最近一次切换的节点在队首"
    );

    // 重选已在历史里的节点（"a"）→ 去重后提到队首，而非重复出现。
    push_recent_server_id(&mut obj, "a");
    assert_eq!(
        obj["recentServerIds"],
        json!(["a", "c", "b"]),
        "重选历史节点 → 去重后提到队首"
    );

    // 第 4 个不同节点 → 最老的一条（"b"）被挤出，上限恒为 3。
    push_recent_server_id(&mut obj, "d");
    assert_eq!(
        obj["recentServerIds"],
        json!(["d", "a", "c"]),
        "上限 3：最老条目被挤出"
    );
}

/// 删节点须把死 id 从 MRU 剔除 —— 否则它永久占住 `truncate(3)` 的一个槽位，
/// 而 `TrayMenu` 反查不到节点即跳过且不回填 ⇒「节点·最近」恒少显示一条。
///
/// 牙：把 `arr.retain(...)` 整条删掉（或把谓词取反）→ 前两个断言转红。
#[test]
fn prune_recent_server_ids_drops_deleted_and_keeps_survivors() {
    // 单删形态：只剔被删的那个，其余保序。
    let mut cfg = json!({ "recentServerIds": ["a", "b", "c"] });
    prune_recent_server_ids(&mut cfg, |id| id == "b");
    assert_eq!(
        cfg["recentServerIds"],
        json!(["a", "c"]),
        "只剔被删 id，其余保序"
    );

    // 批删形态：一次剔多个。
    let mut cfg = json!({ "recentServerIds": ["a", "b", "c"] });
    let removed: std::collections::HashSet<&str> = ["a", "c"].into_iter().collect();
    prune_recent_server_ids(&mut cfg, |id| removed.contains(id));
    assert_eq!(cfg["recentServerIds"], json!(["b"]), "批删一次剔多个");

    // 全删 → 空数组（**不删键**，形状稳定；空数组与缺键对读侧 `?? []` 等价）。
    let mut cfg = json!({ "recentServerIds": ["a"] });
    prune_recent_server_ids(&mut cfg, |_| true);
    assert_eq!(cfg["recentServerIds"], json!([]), "全删 → 空数组而非删键");

    // 存量配置无该键 → 空操作，**不得凭空建键**（否则每次删节点都往 config 里塞一个空数组）。
    let mut cfg = json!({ "servers": [] });
    prune_recent_server_ids(&mut cfg, |_| true);
    assert!(cfg.get("recentServerIds").is_none(), "无该键 → 不凭空建键");

    // 全量保存形态不知道「本次具体删了谁」，按当前 servers 真值裁掉所有死 id，其余保序。
    let mut cfg = json!({
        "servers": [{"id":"a"}, {"id":"c"}],
        "recentServerIds": ["missing", "a", "b", "c"]
    });
    prune_recent_server_ids_to_existing(&mut cfg);
    assert_eq!(cfg["recentServerIds"], json!(["a", "c"]));

    let mut cfg = json!({ "recentServerIds": ["a", "b"] });
    prune_recent_server_ids_to_existing(&mut cfg);
    assert_eq!(
        cfg["recentServerIds"],
        json!(["a", "b"]),
        "servers 缺失 = 节点真值未知，不得当成空集合"
    );
}

/// **调用点守卫**（射程补齐）：上面那条只测纯函数，删掉命令里的**调用**它照样绿 = 门没盖住生产路径。
/// 两个删除命令都持 `State<'_, AppRuntime>`，单测构造不出 Tauri 运行时 ⇒ 改用源码扫描锁调用点，
/// 与 `main.rs` 既有的 Rust 侧源码扫描守卫同法。
///
/// 牙：删掉 `server_delete` 或 `server_delete_batch` 里任一处
/// `prune_recent_server_ids_to_existing(...)` → 转红。
#[test]
fn both_delete_commands_prune_recent_ids() {
    // 剥注释取材：锚点自检与两条 `prune_…` 正面断言的针都是单行代码文本；本文件的切片器是
    // 手写的 `find` 区间（不经 `guard_scan`），故必须在取材侧净化。
    let src = crate_code("commands/server.rs");
    // 扫描面自检：锚点必须都在，否则函数改名 / 文件漂走会让下面的切片恒空、守卫恒绿。
    for anchor in [
        "pub fn server_delete(",
        "pub fn server_delete_batch(",
        "pub fn server_switch(",
    ] {
        assert!(src.contains(anchor), "锚点消失，守卫已失去判据: {anchor}");
    }

    // 取每个命令的函数体（从其签名到**下一个**命令签名之间）。
    let body_of = |start: &str, end: &str| -> &str {
        let s = src.find(start).expect("起始锚点");
        let e = src[s..].find(end).expect("结束锚点") + s;
        &src[s..e]
    };
    let single = body_of("pub fn server_delete(", "pub fn server_delete_batch(");
    // D14：`server_get_all`（死 IPC command，D12 已删前端调用点）已退役，`server_delete_batch`
    // 之后紧邻的下一个命令签名改为 `server_switch`。
    let batch = body_of("pub fn server_delete_batch(", "pub fn server_switch(");

    assert!(
        single.contains("prune_recent_server_ids_to_existing("),
        "server_delete 必须剔除被删节点的 MRU 残留"
    );
    assert!(
        batch.contains("prune_recent_server_ids_to_existing("),
        "server_delete_batch 必须剔除被删节点的 MRU 残留"
    );
    // 反向自检：切片确实各自独立（否则「两段都命中」可能只是因为切成了同一段整文件）。
    assert!(!single.contains("pub fn server_delete_batch("));
    assert!(!batch.contains("pub fn server_switch("));
}

#[test]
fn resolve_fallback_selected_requires_surviving_candidate() {
    // 删除已发生：servers 里只剩 keep-1 / keep-2。
    let cfg = json!({ "servers": [{ "id": "keep-1" }, { "id": "keep-2" }] });
    assert_eq!(
        resolve_fallback_selected(&cfg, Some("keep-2")),
        "keep-2",
        "兜底节点存活 → 采用"
    );
    assert_eq!(
        resolve_fallback_selected(&cfg, Some("deleted-1")),
        DIRECT_SERVER_ID,
        "兜底节点已被删（含「传被删节点自身」的旧 bug 形态）→ 落直连哨兵"
    );
    assert_eq!(
        resolve_fallback_selected(&cfg, None),
        DIRECT_SERVER_ID,
        "无兜底候选（删光了）→ 落直连哨兵"
    );
    assert_eq!(
        resolve_fallback_selected(&json!({}), Some("keep-1")),
        DIRECT_SERVER_ID,
        "servers 字段缺失 → 无可校验候选 → 落直连哨兵（不写回未经校验的 id）"
    );
}
