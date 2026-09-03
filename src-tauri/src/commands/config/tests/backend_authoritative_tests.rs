use super::super::*;
use crate::runtime::config::ConfigManager;
use crate::test_support::{crate_code, TestDir};

fn temp_dir(tag: &str) -> TestDir {
    TestDir::new(&format!("polaris-backend-auth-{tag}-"))
}

/// **用户报的那个 bug 的直接回归**：后端写了 MRU 历史后，前端携**陈旧** `recentServerIds`
/// 的全量保存不得把它抹回去。
///
/// 牙：删掉 `config_save_core` 里的 `enforce_backend_authoritative_fields` 调用 → 落盘变成
/// 前端那份 `["stale"]` → 第一个断言转红。把 enforce 改成「仅当入参缺键才回填」（即退化成
/// `preserve_server_owned_secrets` 那套策略）→ 同样转红，因为前端快照**带着**该键。
#[test]
fn stale_frontend_snapshot_cannot_wipe_backend_written_mru() {
    let dir = temp_dir("mru");
    let mgr = ConfigManager::new(dir.clone());
    // MRU 只可能由 `server_switch` 写入，而该命令先验证节点存在；fixture 也必须保持这条生产不变量。
    // 若只造 recentServerIds 却让 servers 为空，新加的死引用清理会正确删掉它们，反而测不到本例
    // 真正要守的「仍存活 MRU 不得被陈旧前端覆盖」。
    let servers = json!([{"id":"n1"}, {"id":"n2"}, {"id":"n3"}]);

    // T0：前端拿到快照（此刻 MRU 还是旧值）——`config_get` 下发的是**完整** config。
    let mut as_frontend_sees = mgr.load_full().unwrap();
    as_frontend_sees["servers"] = servers.clone();
    as_frontend_sees["recentServerIds"] = json!(["stale"]);
    as_frontend_sees["logLevel"] = json!("debug");

    // T1：后端写 MRU（等价 server_switch 连切三个节点），前端快照就此过期。
    let mut cfg = mgr.load_full().unwrap();
    cfg["servers"] = servers;
    cfg["recentServerIds"] = json!(["n3", "n2", "n1"]);
    mgr.save_full(&cfg).unwrap();

    // T2：前端此刻才提交那份陈旧快照（改任意设置都会走到这条路）。
    config_save_core(&mgr, &mut as_frontend_sees, None, false).expect("save 应成功");

    // 从磁盘重 load 核实：后端历史完好，前端的无关改动照常生效。
    let on_disk = ConfigManager::new(dir.clone()).load_full().unwrap();
    assert_eq!(
        on_disk["recentServerIds"],
        json!(["n3", "n2", "n1"]),
        "后端权威字段不得被前端陈旧快照抹回"
    );
    assert_eq!(
        on_disk["logLevel"],
        json!("debug"),
        "前端权威字段的改动照常落盘"
    );
}

/// 删除表达（后端权威侧）：磁盘**无**该键 ⇒ 落盘也必须无该键，前端携带的陈旧值不得复活它。
///
/// 这是白名单的另一半语义：删除权归字段所有者（后端），前端既无写入权也无需表达删除。缺了
/// `None` 腿，所有者就**删不掉自己的键** —— 任一全量保存都会把它从前端的陈旧快照里复活回来，
/// 而所有者对此毫无察觉。
///
/// 夹具用 `recentServerIds`（本批之前用的是 `diagnosticCapture`，那套机制已删除）。断言的是
/// [`enforce_backend_authoritative_fields`] 的镜像契约本身，与具体是哪个键无关，故照旧走**生产
/// 保存路径**打，而不是直接调那个函数。
///
/// 牙：删掉 `enforce_backend_authoritative_fields` 里的 `None => { obj.remove(key); }` 腿 → 转红。
#[test]
fn backend_deleted_key_is_not_resurrected_by_stale_snapshot() {
    let dir = temp_dir("authoritative-delete");
    let mgr = ConfigManager::new(dir.clone());

    // 后端写入权威键（形态同 `server_switch` 落 MRU）。
    let mut cfg = mgr.load_full().unwrap();
    cfg["recentServerIds"] = json!(["srv-a", "srv-b"]);
    mgr.save_full(&cfg).unwrap();

    // 前端快照停在这一刻（完整 config，带着该键）。
    let mut as_frontend_sees = mgr.load_full().unwrap();
    as_frontend_sees["logLevel"] = json!("warn");
    assert!(
        as_frontend_sees.get("recentServerIds").is_some(),
        "前提：前端快照确实带着该权威键"
    );

    // 后端删掉该键（所有者行使删除权）。
    let mut cfg = mgr.load_full().unwrap();
    cfg.as_object_mut().unwrap().remove("recentServerIds");
    mgr.save_full(&cfg).unwrap();

    // 前端此刻才提交陈旧快照（LogsScreen 改日志级别的真实形态）。
    config_save_core(&mgr, &mut as_frontend_sees, None, false).expect("save 应成功");

    let on_disk = ConfigManager::new(dir.clone()).load_full().unwrap();
    assert!(
        on_disk.get("recentServerIds").is_none(),
        "后端已删的键不得被前端陈旧快照复活（否则字段所有者永远删不掉自己的键）"
    );
}

/// **删除语义未被破坏**（前端权威侧）：白名单外的键仍是整份覆盖，用户清空数组 / 删键必须真落盘。
///
/// 这条守的是「引入 merge 会让删除变不可能」那个设计陷阱：本批**没有**引入 merge，
/// 故 上游的两种删除表达（传 `[]` 清空、缺键删除）必须原样有效。
///
/// 牙：把 `config_save_core` 改成对**全部**键做「磁盘有值就覆盖」的深合并 → 三个断言全红。
#[test]
fn frontend_owned_fields_keep_full_overwrite_delete_semantics() {
    let dir = temp_dir("delete");
    let mgr = ConfigManager::new(dir.clone());

    // 起点：磁盘上有一条自定义规则、一个非空旁路清单、一个自定义应用预设。
    let mut cfg = mgr.load_full().unwrap();
    cfg["customRules"] = json!([{ "id": "r1", "enabled": true }]);
    cfg["fakeIpFilterList"] = json!(["a.example", "b.example"]);
    cfg["customAppPresets"] = json!([{ "id": "p1", "name": "P" }]);
    mgr.save_full(&cfg).unwrap();

    // 前端：删掉最后一条规则（传空数组）、清空旁路清单（传空数组）、
    // 删掉 customAppPresets 键本身（不传该键 —— 上游的 `x: undefined` 等价形）。
    let mut submitted = mgr.load_full().unwrap();
    submitted["customRules"] = json!([]);
    submitted["fakeIpFilterList"] = json!([]);
    submitted
        .as_object_mut()
        .unwrap()
        .remove("customAppPresets");
    config_save_core(&mgr, &mut submitted, None, false).expect("save 应成功");

    let on_disk = ConfigManager::new(dir.clone()).load_full().unwrap();
    assert_eq!(
        on_disk["customRules"],
        json!([]),
        "删最后一条规则必须真删掉（merge 语义下这里会被还原成 [r1]）"
    );
    assert_eq!(
        on_disk["fakeIpFilterList"],
        json!([]),
        "清空列表必须真清空（merge 语义下会被还原）"
    );
    assert!(
        on_disk.get("customAppPresets").is_none(),
        "缺键删除不得被磁盘旧值还原（merge 语义下会被还原成 [p1]）"
    );
}

/// 白名单**边界**：`clashApiSecret` 后端也写，但前端有「重新生成」按钮（SettingsNetwork）
/// ⇒ 绝不能进白名单，否则该按钮静默失效（点了没反应）。
///
/// 牙：把 `clashApiSecret` 加进 `BACKEND_AUTHORITATIVE_KEYS` → 本测转红。
/// 这条是防「未来有人按『后端写过就算后端权威』的错判准扩白名单」的守卫。
#[test]
fn frontend_writable_secret_is_not_locked_by_whitelist() {
    let dir = temp_dir("secret");
    let mgr = ConfigManager::new(dir.clone());

    let mut cfg = mgr.load_full().unwrap();
    cfg["clashApiSecret"] = json!("old-secret");
    mgr.save_full(&cfg).unwrap();

    // 前端点「重新生成」→ 全量提交新 secret。
    let mut submitted = mgr.load_full().unwrap();
    submitted["clashApiSecret"] = json!("regenerated-secret");
    config_save_core(&mgr, &mut submitted, None, false).expect("save 应成功");

    let on_disk = ConfigManager::new(dir.clone()).load_full().unwrap();
    assert_eq!(
        on_disk["clashApiSecret"],
        json!("regenerated-secret"),
        "前端有写入权的字段不得被白名单锁住"
    );
}

/// 白名单**非空**守卫：防「把 `BACKEND_AUTHORITATIVE_KEYS` 清空」这种假绿变异——
/// 清空后上面几条生产路径测试里，只有正向断言会红，此处显式锁住成员构成。
#[test]
fn whitelist_membership_is_pinned() {
    assert!(
        BACKEND_AUTHORITATIVE_KEYS.contains(&"recentServerIds"),
        "托盘 MRU 必须在白名单内（用户报的那个 bug）"
    );
    assert!(
        BACKEND_AUTHORITATIVE_KEYS.contains(&"builtinGeoMeta"),
        "随包 geo 元数据必须在白名单内（ui 全仓零读零写）"
    );
    assert!(
        !BACKEND_AUTHORITATIVE_KEYS.contains(&"diagnosticCapture"),
        "诊断采集机制已整体删除，该键不得再作为任何人的权威字段留在白名单里"
    );
    assert!(
        !BACKEND_AUTHORITATIVE_KEYS.contains(&"clashApiSecret"),
        "clashApiSecret 前端可写，绝不得进白名单"
    );
    assert!(
        !BACKEND_AUTHORITATIVE_KEYS.contains(&"servers"),
        "servers 前端有写入权（备份导入 / 全量保存），绝不得进白名单"
    );
}

/// **调用点守卫**（射程补齐）：`config_save` 这条腿由上面的生产路径测试盖住了，但**备份导入**
/// （`backup_import_apply`）是前端全量提交的**第二个**入口，它持 `State<'_, AppRuntime>` +
/// `AppHandle`，单测构造不出 Tauri 运行时 ⇒ 改用源码扫描锁调用点。
///
/// 不盖住它的后果：导入一份**存量旧备份**（那些文件里还带着导出机的 `recentServerIds`）会把外机的
/// MRU 装进本机。与 `preserve_server_owned_secrets` 在同一处、同一理由。
///
/// 牙：把 `misc/backup.rs` 里 `backup_import_apply` **函数体内**的
/// `backup_import_save_core(...)` 换回裸 `save_full(&restored)` → 转红。
///
/// # 切片必须封顶（本守卫此前的洞）
///
/// 原实现切的是 `&src[s..]` —— 从签名一路到 **EOF**，而非该函数的右花括号。于是「删掉本函数里的调用、
/// 再在这个 1000+ 行文件的**任意后续位置**加一个」就能让守卫照样绿，牙只在今天这个文件布局下存在。
/// 现按列 0 的 `\n}\n` 封顶到函数自己的作用域，见 [`top_level_fn_body`]。
#[test]
fn backup_import_routes_through_the_shared_save_core() {
    let body = crate::commands::guard_scan::top_level_fn_body(
        &crate_code("commands/misc/backup.rs"),
        "pub async fn backup_import_apply(",
    );
    assert!(
        body.contains("backup_import_save_core(")
            && body.contains("state.config(),")
            && body.contains("&current,")
            && body.contains("&mut restored,"),
        "备份导入必须经共用落盘腿（三条策略 + save_full 的顺序与配对由它单一收口）"
    );
    let broadcast = body
        .find("broadcast_config_changed(&app, &broadcast_cfg)")
        .expect("备份导入落盘后必须广播");
    let invalidate = body
        .find("invalidate_unlock_on_exit_change(")
        .expect("备份导入可换出口，必须作废旧解锁缓存");
    assert!(
        broadcast < invalidate,
        "落盘广播后才能按事务前后出口失效缓存"
    );
    assert!(
        !body.contains("save_full("),
        "第二条落盘路径 = 迟早只挂一条策略：备份导入不得再直接 save_full"
    );
}

/// 🔴 **落盘腿本身的三条策略 + 顺序**：全部必须在原子 update 闭包提交新配置之前完成。
///
/// 行为面由本模块的生产路径测试覆盖（`backup_import_*` 三条 + 上面的 enforce/preserve 用例）；
/// 本守卫只钉「三条都还在、且都在落盘之前」这个纯结构事实 —— 顺序反了（落盘后再清/再回填）
/// 语义上等于没做，而行为测试对「先落盘再改内存副本」这种写法**恰好也是绿的**（磁盘上是坏值，
/// 但测试若读的是返回的内存值就看不出来）。
///
/// 牙：删掉三条策略任一 / 把任一挪到延迟清理保存之后 → 逐条转红。
#[test]
fn backup_import_save_core_runs_all_three_policies_before_the_write() {
    let body = crate::commands::guard_scan::top_level_fn_body(
        &crate_code("commands/config.rs"),
        "pub(crate) fn backup_import_save_core(",
    );
    let transaction = body
        .find("config.update_deferred_cleanup(|latest|")
        .expect("落盘事务被删了 —— 导入不再原子合并/落盘");
    let write = body.find("*latest = next").expect("事务提交腿被删了");
    for needle in [
        "replay_top_level_delta(current, &submitted, &mut next)",
        "preserve_server_owned_secrets_from(latest, &mut next)",
        "enforce_backend_authoritative_fields_from(latest, &mut next)",
        "invalidate_validators_on_global_ua_change(latest, &mut next)",
    ] {
        let at = body
            .find(needle)
            .unwrap_or_else(|| panic!("备份导入落盘腿少了一条策略: {needle}"));
        assert!(
            at < write,
            "`{needle}` 必须排在落盘之前，落盘后再做等于没做"
        );
    }
    assert!(
        transaction < write,
        "策略与提交必须处在同一个原子 update 内"
    );
}

/// 首启无配置文件（`current()` 读不到）→ enforce 必须是空操作，不阻断保存、不凭空造键。
#[test]
fn missing_current_config_is_a_noop() {
    let dir = temp_dir("first-run");
    let mgr = ConfigManager::new(dir.clone());
    let mut incoming = json!({ "recentServerIds": ["a"], "logLevel": "info" });
    // 不先 load_full：走「缓存未暖 → current() 自行 load 默认配置」的首启路径。
    enforce_backend_authoritative_fields(&mgr, &mut incoming);
    // 默认配置无 recentServerIds → 按镜像语义该键被删（而非保留前端值），且不 panic。
    assert!(incoming.get("recentServerIds").is_none());
    assert_eq!(incoming["logLevel"], json!("info"), "非白名单键不受影响");
}
