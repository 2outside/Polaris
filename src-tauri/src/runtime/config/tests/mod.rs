use super::*;
use crate::test_support::TestDir;

fn temp_dir(tag: &str) -> TestDir {
    TestDir::new(&format!("polaris-config-test-{tag}-"))
}

#[test]
fn staged_pending_marker_survives_restart_and_clears_explicitly() {
    let dir = temp_dir("staged-pending");
    let marker = dir.join(STAGED_PENDING_FILE);
    let mgr = ConfigManager::new(dir.clone());
    assert!(!mgr.has_staged_pending());

    // 非节点草稿显式传空遮罩：它仍阻止旧配置起核，但允许运行态 clean 节点参与故障切换。
    mgr.set_staged_pending_snapshot(true, Some(vec![]));
    assert!(mgr.has_staged_pending());
    assert!(marker.exists(), "崩溃重启要靠持久 marker 拦住旧配置起核");
    let mask = mgr.staged_node_mask();
    assert!(mask.pending);
    assert!(mask.scope_known, "新 marker 的空节点遮罩也是已知范围");
    assert!(mask.node_ids.is_empty());

    let restarted = ConfigManager::new(dir.clone());
    assert!(
        restarted.has_staged_pending(),
        "无 clean-exit 标记时必须恢复 pending"
    );
    assert_eq!(
        restarted.staged_node_mask(),
        StagedNodeMask {
            pending: true,
            node_ids: BTreeSet::new(),
            scope_known: true,
        },
        "marker 重启恢复必须保留已知空遮罩"
    );
    restarted.set_staged_pending(false);
    assert!(!restarted.has_staged_pending());
    assert!(!marker.exists());
}

#[test]
fn staged_legacy_empty_marker_has_unknown_scope() {
    let dir = temp_dir("staged-legacy-empty");
    std::fs::write(dir.join(STAGED_PENDING_FILE), b"").unwrap();

    let mgr = ConfigManager::new(dir.clone());
    let mask = mgr.staged_node_mask();
    assert!(mask.pending, "旧空 marker 仍表示有未保存草稿");
    assert!(
        !mask.scope_known,
        "无法解析旧空 marker 时必须按未知节点范围 fail-closed"
    );
    assert!(mask.node_ids.is_empty());
}

#[test]
fn staged_marker_ignores_the_removed_revision_field_from_previous_builds() {
    let dir = temp_dir("staged-old-revision");
    std::fs::write(
        dir.join(STAGED_PENDING_FILE),
        br#"{"version":1,"revision":42,"nodeIds":["node-a"]}"#,
    )
    .unwrap();

    assert_eq!(
        ConfigManager::new(dir.clone()).staged_node_mask(),
        StagedNodeMask {
            pending: true,
            node_ids: BTreeSet::from(["node-a".to_string()]),
            scope_known: true,
        }
    );
}

#[test]
fn clean_exit_discards_stale_staged_pending_marker_before_auto_connect() {
    let dir = temp_dir("staged-clean-exit");
    std::fs::write(dir.join(STAGED_PENDING_FILE), b"").unwrap();
    std::fs::write(dir.join(crate::clean_exit::CLEAN_EXIT_MARKER_FILENAME), b"").unwrap();

    let mgr = ConfigManager::new(dir.clone());
    assert!(!mgr.has_staged_pending());
    assert!(
        !dir.join(STAGED_PENDING_FILE).exists(),
        "2s 自动连接不能被一份已由正常退出判作废的草稿镜像误拦"
    );
}

/// **P0 复现路径**：config.json 不存在（首次启动/新装）→ `load_full` 必须把默认配置写盘。
///
/// 修复前此处传字面量 `"polaris"` 作 12hex tmp 后缀 → `store::fs::tmp_path` 的
/// `debug_assert!` 触发 → **debug 构型直接 abort**（非 unwind，`#[should_panic]` 都接不住），
/// 即「首启必崩」；release 则写出永不被清扫的 `config.json.polaris.tmp`。
#[test]
fn load_full_on_missing_config_writes_default_to_disk() {
    let dir = temp_dir("missing");
    let path = dir.join("config.json");
    assert!(
        !path.exists(),
        "前提：config.json 必须不存在（这才是新装路径）"
    );

    let mgr = ConfigManager::new(dir.clone());
    let cfg = mgr.load_full().expect("新装路径 load_full 应成功");

    // ① 真的落盘了（was_missing 腿跑通）。
    assert!(
        path.exists(),
        "新装必须把默认配置写盘（P0：此前这一步在 debug 下 abort）"
    );
    // ② 落盘内容是合法 JSON 且与返回值一致。
    let on_disk: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap())
        .expect("落盘内容应是合法 JSON");
    assert!(on_disk.is_object(), "落盘配置应是 JSON 对象");
    assert!(cfg.is_object());
    // ③ tmp→rename 已完成：目录里不得残留任何 .tmp（尤其不得有 config.json.polaris.tmp）。
    let leftovers: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".tmp"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "原子写后不得残留 tmp，实得 {leftovers:?}"
    );
}

/// 二次 load（文件已在）不得重写盘，且缓存命中。
#[test]
fn load_full_is_idempotent_and_does_not_leave_tmp() {
    let dir = temp_dir("idem");
    let mgr = ConfigManager::new(dir.clone());
    mgr.load_full().unwrap();
    let first = std::fs::read_to_string(dir.join("config.json")).unwrap();
    mgr.load_full().unwrap();
    let second = std::fs::read_to_string(dir.join("config.json")).unwrap();
    assert_eq!(first, second, "二次 load 不应改变磁盘内容");
}

/// 迁移不能只存在于进程内 cache：带标记的一次性默认纠偏必须在首次 load 后立即落盘；用户之后
/// 显式改回 false 时，新进程读取到标记并尊重该值。
#[test]
fn load_full_persists_migration_marker_then_respects_user_value() {
    let dir = temp_dir("migration-persist");
    let path = dir.join("config.json");
    let mut legacy = polaris_store::default_config();
    legacy["keepTrayMenuWarm"] = Value::Bool(false);
    legacy
        .as_object_mut()
        .unwrap()
        .remove("keepTrayMenuWarmDefaultMigrated");
    std::fs::write(&path, serde_json::to_string_pretty(&legacy).unwrap()).unwrap();

    let mgr = ConfigManager::new(dir.clone());
    let migrated = mgr.load_full().expect("升级配置应成功迁移");
    assert_eq!(migrated["keepTrayMenuWarm"], true);
    assert_eq!(migrated["keepTrayMenuWarmDefaultMigrated"], true);

    let on_disk: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap())
        .expect("迁移结果应立即落为合法 JSON");
    assert_eq!(on_disk["keepTrayMenuWarm"], true);
    assert_eq!(on_disk["keepTrayMenuWarmDefaultMigrated"], true);

    mgr.set_value("keepTrayMenuWarm", Value::Bool(false))
        .expect("用户关闭预热应落盘");
    let restarted = ConfigManager::new(dir.clone())
        .load_full()
        .expect("二次启动应读取已标记配置");
    assert_eq!(restarted["keepTrayMenuWarm"], false);
    assert_eq!(restarted["keepTrayMenuWarmDefaultMigrated"], true);
}

/// `Write` / `Skip` 两条腿各走一遍。
///
/// 变异对照：把 `Skip` 腿改成照样 `save_full` → 「不写」那两条断言转红（真实后果是净零改动
/// 多一次广播 + 多一次 `switch_mode`）；把 `Skip` 腿改成回传 `Some(cfg)` → 「必须不回传配置」
/// 转红（调用方正是据它决定要不要广播）。
#[test]
fn update_writes_or_skips_and_never_leaks_skipped_edits() {
    let dir = temp_dir("update-outcomes");
    let mgr = ConfigManager::new(dir.clone());
    mgr.load_full().unwrap();

    // ① 正常改动：落盘 + 把值和已落盘那份一起带回。
    let (tag, saved) = mgr
        .update(|cfg| {
            cfg.as_object_mut()
                .unwrap()
                .insert("mixedPort".into(), Value::from(7801u64));
            Decision::Write("created-id")
        })
        .expect("不该报错");
    assert_eq!(tag, "created-id", "闭包算出的值必须能带出来给调用方");
    assert_eq!(
        saved.expect("Write 腿必须回传已落盘那份（调用方要拿它去锁外广播）")["mixedPort"],
        7801
    );
    assert_eq!(mgr.current().unwrap()["mixedPort"], 7801);

    // ② `Skip`：不是错误、**一个字节都不该写**，且不回传配置（回传就等于邀请调用方去广播）。
    let (payload, skipped) = mgr
        .update(|cfg| {
            cfg.as_object_mut()
                .unwrap()
                .insert("mixedPort".into(), Value::from(9999u64));
            // 真实形态：净零改动照样要把「成功」的载荷还给调用方（如 `ApiResponse::ok(0u32)`）。
            Decision::Skip(0u32)
        })
        .expect("跳过不是错误");
    assert_eq!(payload, 0, "Skip 腿同样要能带出调用方的返回值");
    assert!(
        skipped.is_none(),
        "Skip 腿必须不回传配置 —— 回传就等于让调用方多广播一次 configChanged"
    );
    assert_eq!(
        mgr.current().unwrap()["mixedPort"],
        7801,
        "Skip 必须不写 —— 闭包对 cfg 的改动一律丢弃"
    );
}

/// 写事务的返回值、缓存与磁盘必须是同一份规范形。`ConfigStore::save` 会归一枚举并删除类型错误
/// 的可选字段；若 `update` 仍返回/缓存清洗前 `cfg`，后续版本校验会对一份磁盘上从未存在过的对象
/// 求 hash，产生假冲突。
#[test]
fn update_returns_and_caches_the_canonical_bytes_written_to_disk() {
    let dir = temp_dir("update-canonical");
    let mgr = ConfigManager::new(dir.clone());
    mgr.load_full().unwrap();

    let (_, saved) = mgr
        .update(|cfg| {
            cfg["proxyModeType"] = Value::String("SYSTEMPROXY".into());
            cfg["desktopNotifications"] = Value::String("not-a-boolean".into());
            Decision::Write(())
        })
        .expect("可清洗输入应保存成功");
    let saved = saved.expect("Write 必须返回事务终态");
    assert_eq!(saved["proxyModeType"], "systemProxy");
    assert!(saved.get("desktopNotifications").is_none());
    assert_eq!(mgr.current().unwrap(), saved, "缓存必须等于写接口返回值");

    let reloaded = ConfigManager::new(dir.clone()).load_full().unwrap();
    assert_eq!(reloaded, saved, "新进程从磁盘读到的也必须是同一事务终态");
}

/// **不丢更新** —— 本原语存在的全部理由。
///
/// 两个线程各自把 `mixedPort` 加 1。分离三步（`load_full` → mutate → `save_full`）下二者会读到
/// 同一个初值、后写的整份覆盖前者 ⇒ 终值 +1（丢了一次）。原子后必为 +2。
///
/// 闭包里那次 `sleep` 是**逼出交错**用的：没有它，两个线程可能天然错开而让本条在无锁实现下
/// 也偶然变绿（那种门等于没门）。
///
/// 变异对照（实跑）：把 `update` 体内的 `write_lock.lock()` 那三行删掉 → 终值 7801 而非 7802，转红。
#[test]
fn concurrent_updates_do_not_lose_each_other() {
    use std::sync::Arc;
    let dir = temp_dir("update-concurrent");
    let mgr = Arc::new(ConfigManager::new(dir.clone()));
    let mut cfg = mgr.load_full().unwrap();
    cfg.as_object_mut()
        .unwrap()
        .insert("mixedPort".into(), Value::from(7800u64));
    mgr.save_full(&cfg).unwrap();

    let bump = |m: Arc<ConfigManager>| {
        std::thread::spawn(move || {
            m.update(|c| {
                let cur = c["mixedPort"].as_u64().unwrap();
                // 持锁期间睡一下，逼出「两个线程都已读、都还没写」这个交错。
                std::thread::sleep(std::time::Duration::from_millis(60));
                c.as_object_mut()
                    .unwrap()
                    .insert("mixedPort".into(), Value::from(cur + 1));
                Decision::Write(())
            })
            .expect("update 不该失败");
        })
    };
    let a = bump(Arc::clone(&mgr));
    let b = bump(Arc::clone(&mgr));
    a.join().unwrap();
    b.join().unwrap();

    assert_eq!(
        mgr.current().unwrap()["mixedPort"],
        7802,
        "两次 +1 必须都在；7801 = 有一次被整份覆盖掉了（丢更新）"
    );
}

/// **起核载荷新鲜的地基**：`save_full` 之后 `current()` 必须立刻返回新值。
///
/// `proxy_start` / `proxy_restart` 改成用 `state.config().current()` 取起核配置之后，
/// 「写盘 → 立刻点启动用的是写后的配置」这条用户可见承诺**全部押在这条性质上**：
/// 若 `current()` 还回旧缓存，起核就仍会用写之前那份 —— 与改之前的缺陷一模一样，
/// 只是从「渲染端副本陈旧」换成「后端缓存陈旧」。
///
/// 变异对照：删掉 `save_full` 末尾那段刷缓存（`*guard = Some(config.clone())`）→ 本条转红。
#[test]
fn current_reflects_the_write_immediately_after_save_full() {
    let dir = temp_dir("current-after-save");
    let mgr = ConfigManager::new(dir.clone());
    let mut cfg = mgr.load_full().unwrap();
    cfg.as_object_mut()
        .unwrap()
        .insert("mixedPort".into(), Value::from(7899u64));
    mgr.save_full(&cfg).expect("save_full 应成功");
    assert_eq!(
        mgr.current().expect("current 应可读")["mixedPort"],
        7899,
        "save_full 之后 current() 必须已是新值 —— 起核载荷就是从这里取的"
    );
}

/// `save_full` 每次都取新 tmp 后缀 → 连续保存不得残留 tmp、内容以最后一次为准。
#[test]
fn save_full_persists_and_leaves_no_tmp() {
    let dir = temp_dir("save");
    let mgr = ConfigManager::new(dir.clone());
    let mut cfg = mgr.load_full().unwrap();
    for port in [7890u64, 7891, 7892] {
        cfg.as_object_mut()
            .unwrap()
            .insert("mixedPort".into(), Value::from(port));
        mgr.save_full(&cfg).expect("save_full 应成功");
    }
    let on_disk: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap();
    assert_eq!(on_disk["mixedPort"], 7892, "应落最后一次保存的值");
    let leftovers: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".tmp"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "连续保存不得残留 tmp，实得 {leftovers:?}"
    );
}

/// LOW-4：`customAppPresets` 未变的保存不得驱逐仍在册应用的缓存图标（改无关键仍保留图标）。
#[test]
fn save_full_keeps_icon_when_presets_unchanged() {
    let dir = temp_dir("icon-keep");
    let mgr = ConfigManager::new(dir.clone());
    let mut cfg = mgr.load_full().unwrap();
    cfg.as_object_mut().unwrap().insert(
        "customAppPresets".into(),
        serde_json::json!([{ "id": "custom-keep", "name": "K" }]),
    );
    mgr.save_full(&cfg).unwrap(); // 暖缓存：旧集 = {custom-keep}
    let icons = crate::icon_cache::icons_dir(&dir);
    crate::icon_cache::write_icon(&icons, "custom-keep", "png", b"\x89PNG").unwrap();
    // 改无关键（customAppPresets 不动）→ id 集未变 → reconcile 跳过 → 图标须存活。
    cfg.as_object_mut()
        .unwrap()
        .insert("mixedPort".into(), Value::from(7890u64));
    mgr.save_full(&cfg).unwrap();
    assert!(
        icons.join("custom-keep.png").exists(),
        "preset 未变时不得驱逐仍在册图标"
    );
}

/// `with_current` 的投影结论必须与 `current()` 的整份快照**逐字段一致**（缓存已暖路径）。
///
/// 这条是把 `current()` 换成 `with_current` 的等价性根据：换的是「谁付深拷贝」，不是读到的内容。
/// **变异锁**：把 `with_current` 实现成「先 `load_full()` 再跑 `f`」（即忽略缓存）→ 本测仍绿，
/// 但 `with_current_does_not_touch_disk_when_cache_is_warm` 转红。
#[test]
fn with_current_projection_matches_current_snapshot() {
    let dir = temp_dir("with-current-eq");
    let mgr = ConfigManager::new(dir.clone());
    let mut cfg = mgr.load_full().unwrap();
    cfg.as_object_mut()
        .unwrap()
        .insert("mixedPort".into(), Value::from(7899u64));
    cfg.as_object_mut()
        .unwrap()
        .insert("selectedServerId".into(), Value::from("srv-1"));
    mgr.save_full(&cfg).unwrap();

    let snapshot = mgr.current().unwrap();
    let projected = mgr
        .with_current(|v| {
            (
                v.get("mixedPort").cloned(),
                v.get("selectedServerId")
                    .and_then(Value::as_str)
                    .map(str::to_string),
            )
        })
        .unwrap();
    assert_eq!(projected.0.as_ref(), snapshot.get("mixedPort"));
    assert_eq!(projected.1.as_deref(), Some("srv-1"));
}

/// 缓存已暖时 `with_current` **不得触盘**：把盘上文件删掉后仍能投影出内存里的值。
///
/// 这正是热路径（STATUS 每帧 / 心跳每 tick）走它的前提 —— 若它退化成每次 `load_full`，
/// 省掉的深拷贝会被一次磁盘读 + sanitize + validate 换成更贵的开销。
#[test]
fn with_current_does_not_touch_disk_when_cache_is_warm() {
    let dir = temp_dir("with-current-warm");
    let mgr = ConfigManager::new(dir.clone());
    let mut cfg = mgr.load_full().unwrap();
    cfg.as_object_mut()
        .unwrap()
        .insert("mixedPort".into(), Value::from(7123u64));
    mgr.save_full(&cfg).unwrap(); // 暖缓存
    std::fs::remove_file(dir.join("config.json")).unwrap();

    let port = mgr.with_current(|v| v.get("mixedPort").cloned()).unwrap();
    assert_eq!(
        port,
        Some(Value::from(7123u64)),
        "缓存暖时必须走内存投影，不得回落读盘"
    );
    assert!(
        !dir.join("config.json").exists(),
        "缓存暖路径不得因一次投影就把默认配置写回磁盘"
    );
}

/// 缓存**未暖**（冷启首次读）时 `with_current` 必须回落 `load_full` 并对读到的配置跑投影。
#[test]
fn with_current_falls_back_to_load_when_cache_is_cold() {
    let dir = temp_dir("with-current-cold");
    // 先用一个实例把非默认值落盘，再用**全新实例**（缓存冷）读。
    {
        let seed = ConfigManager::new(dir.clone());
        let mut cfg = seed.load_full().unwrap();
        cfg.as_object_mut()
            .unwrap()
            .insert("mixedPort".into(), Value::from(7456u64));
        seed.save_full(&cfg).unwrap();
    }
    let cold = ConfigManager::new(dir.clone());
    let port = cold
        .with_current(|v| v.get("mixedPort").and_then(Value::as_u64))
        .unwrap();
    assert_eq!(port, Some(7456), "冷缓存须经 load_full 读到盘上的值");
    // 回落腿也须顺带暖上缓存（与 `current()` 同款懒加载语义）。
    assert_eq!(
        cold.current()
            .unwrap()
            .get("mixedPort")
            .and_then(Value::as_u64),
        Some(7456)
    );
}

/// **读锁必须在 `with_current` 返回前释放**：返回后紧接着的写腿（`set_value` 要 `cache.write()`）
/// 不得阻塞。
///
/// 用带超时的独立线程跑，是因为「锁没释放」的失败形态是**永久阻塞**而不是断言失败 —— 直接在测试
/// 线程里跑会把整个 `cargo test` 挂死（看起来像 CI 卡住，而不是一条红测）。
///
/// **变异锁**：把实现改成「读锁跨越 `load_full`」（即把 `f(c)` 与后续写腿放进同一个 guard 作用域）
/// → 本测超时转红。
#[test]
fn with_current_releases_read_lock_before_returning() {
    use std::sync::mpsc;
    let dir = temp_dir("with-current-unlock");
    let mgr = std::sync::Arc::new(ConfigManager::new(dir.clone()));
    mgr.load_full().unwrap();

    let (tx, rx) = mpsc::channel();
    let m = std::sync::Arc::clone(&mgr);
    let h = std::thread::spawn(move || {
        let seen = m.with_current(|v| v.get("mixedPort").cloned());
        // 紧接着取写锁：若上面的读锁被 `with_current` 带出来了，这里同线程自死锁。
        let wrote = m.set_value("mixedPort", Value::from(7001u64)).is_ok();
        let _ = tx.send(seen.is_ok() && wrote);
    });
    let ok = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("with_current 返回后写腿必须立刻可取写锁（超时 = 读锁被带出闭包）");
    assert!(ok, "投影与随后的写入都应成功");
    h.join().unwrap();
    assert_eq!(
        mgr.current()
            .unwrap()
            .get("mixedPort")
            .and_then(Value::as_u64),
        Some(7001)
    );
}

// ── with_current 闭包禁忌的「牙」（debug 构型探针）─────────────────────────────
//
// 三条测试穷举闭包内**可能**回到 ConfigManager 的三种形态（读 / 写 / 嵌套投影）—— 只测一条会被
// 「只在 current() 上加探针」这种半吊子修法蒙混过关。三条都不能靠真死锁来验（那是挂死不是红测），
// 故判据是探针 panic。

/// 闭包内调 `current()`（**读**腿）→ 探针 panic。
///
/// 这条是三条里最危险的：不加探针时它**平时不显形**（无写者排队 → 递归读通常拿得到），
/// 只在恰好有另一条腿写配置时永久阻塞。
///
/// **变异锁**：删掉 `with_current` 里的 `ReentrancyProbe::enter()`，或删掉 `current()` 开头的
/// `deny_inside_projection` → 本测（无 panic）转红。
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "with_current 闭包内被调用")]
fn nested_current_inside_projection_panics_in_debug() {
    let dir = temp_dir("reentrancy-read");
    let mgr = ConfigManager::new(dir.clone());
    mgr.load_full().unwrap();
    let _ = mgr.with_current(|_| mgr.current());
}

/// 闭包内调 `set_value()`（**写**腿）→ 探针 panic。不加探针时这条是**必然自死锁**。
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "with_current 闭包内被调用")]
fn nested_write_inside_projection_panics_in_debug() {
    let dir = temp_dir("reentrancy-write");
    let mgr = ConfigManager::new(dir.clone());
    mgr.load_full().unwrap();
    let _ = mgr.with_current(|_| mgr.set_value("mixedPort", Value::from(1u64)));
}

/// 闭包内**嵌套** `with_current` → 同样 panic（自己人也不例外）。
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "with_current 闭包内被调用")]
fn nested_with_current_inside_projection_panics_in_debug() {
    let dir = temp_dir("reentrancy-nested");
    let mgr = ConfigManager::new(dir.clone());
    mgr.load_full().unwrap();
    let _ = mgr.with_current(|_| mgr.with_current(|v| v.is_object()));
}

/// 探针必须**随闭包退场归零**——含闭包 panic 的退场。否则一次失败测试会把同线程后续所有配置读
/// 全打成 panic：故障从一条变成一片，而真正的根因被淹没。
///
/// **变异锁**：把 `ReentrancyProbe` 的 `Drop` 换成手工「闭包返回后 -1」→ panic 腿不再归零，
/// 本测最后那次 `current()` 转红。
#[cfg(debug_assertions)]
#[test]
fn probe_depth_unwinds_on_closure_panic() {
    let dir = temp_dir("reentrancy-unwind");
    let mgr = ConfigManager::new(dir.clone());
    mgr.load_full().unwrap();
    let boom = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = mgr.with_current(|_| panic!("闭包内业务 panic"));
    }));
    assert!(boom.is_err(), "前提：闭包确实 panic 了");
    // 探针归零 ⇒ 后续正常读写照常可用（不归零则这两行 panic）。
    assert!(mgr.current().is_ok(), "闭包 panic 后深度必须已归零");
    assert!(mgr.with_current(|v| v.is_object()).unwrap());
}

/// LOW-4：id 集**实际变化**（移除某 preset）时 reconcile 照跑——被移除项图标驱逐、仍在册保留。
#[test]
fn save_full_reconciles_icons_when_preset_removed() {
    let dir = temp_dir("icon-evict");
    let mgr = ConfigManager::new(dir.clone());
    let mut cfg = mgr.load_full().unwrap();
    cfg.as_object_mut().unwrap().insert(
        "customAppPresets".into(),
        serde_json::json!([{ "id": "custom-keep" }, { "id": "custom-drop" }]),
    );
    mgr.save_full(&cfg).unwrap();
    let icons = crate::icon_cache::icons_dir(&dir);
    crate::icon_cache::write_icon(&icons, "custom-keep", "png", b"\x89PNG").unwrap();
    crate::icon_cache::write_icon(&icons, "custom-drop", "png", b"\x89PNG").unwrap();
    // 移除 custom-drop → id 集变化 → reconcile 跑。
    cfg.as_object_mut().unwrap().insert(
        "customAppPresets".into(),
        serde_json::json!([{ "id": "custom-keep" }]),
    );
    mgr.save_full(&cfg).unwrap();
    assert!(icons.join("custom-keep.png").exists(), "仍在册图标须保留");
    assert!(!icons.join("custom-drop.png").exists(), "移除项图标须驱逐");
}

fn deletion_fixture() -> Value {
    serde_json::json!({
        "servers": [
            {
                "id": "ts-1", "name": "TS", "protocol": "tailscale",
                "address": "100.64.0.1", "port": 0, "tailscaleSettings": {}
            },
            {
                "id": "warp-1", "name": "WARP", "protocol": "wireguard",
                "address": "engage.cloudflareclient.com", "port": 2408,
                "wireguardSettings": {
                    "privateKey": "private", "localAddress": ["172.16.0.2/32"],
                    "peerPublicKey": "peer", "allowedIPs": ["0.0.0.0/0"],
                    "warpDevice": { "deviceId": "dev-1", "token": "tok-1" }
                }
            },
            {
                "id": "proxy-1", "name": "Proxy", "protocol": "vless",
                "address": "example.com", "port": 443
            }
        ],
        "ruleResources": [
            {
                "id": "geo-custom", "name": "Custom", "category": "custom",
                "sourceUrl": "https://example.com/geo-custom.srs",
                "fileName": "geo-custom.srs", "format": "binary",
                "size": 1, "downloadedAt": "2026-08-28T00:00:00.000Z"
            }
        ],
        "customAppPresets": [
            {
                "id": "app-custom", "name": "Custom", "emoji": "C",
                "geositeTags": [], "geoipTags": [], "processNames": [], "category": "custom"
            }
        ]
    })
}

#[test]
fn derive_deferred_deletions_covers_only_irreversible_assets() {
    let current = deletion_fixture();
    let incoming = serde_json::json!({
        "servers": [{ "id": "proxy-1", "protocol": "vless" }],
        "ruleResources": [],
        "customAppPresets": []
    });
    let entries = derive_deferred_deletions(&current, &incoming);
    assert_eq!(
        entries.len(),
        4,
        "TS/WARP/资源文件/图标各一条；普通节点没有副作用"
    );
    assert!(entries.iter().any(|entry| matches!(
        entry,
        DeferredConfigDeletion::TailscaleState { server_id } if server_id == "ts-1"
    )));
    assert!(entries.iter().any(|entry| matches!(
        entry,
        DeferredConfigDeletion::WarpDevice { device_id, token, .. }
            if device_id == "dev-1" && token == "tok-1"
    )));
    assert!(entries.iter().any(|entry| matches!(
        entry,
        DeferredConfigDeletion::RuleResource { file_name } if file_name == "geo-custom.srs"
    )));
    assert!(entries.iter().any(|entry| matches!(
        entry,
        DeferredConfigDeletion::AppIcon { app_id } if app_id == "app-custom"
    )));
}

#[test]
fn deferred_save_writes_intent_without_running_cleanup() {
    let dir = temp_dir("deferred-delete-save");
    let mgr = ConfigManager::new(dir.clone());
    let mut current = mgr.load_full().unwrap();
    let fixture = deletion_fixture();
    current["servers"] = fixture["servers"].clone();
    current["ruleResources"] = fixture["ruleResources"].clone();
    current["customAppPresets"] = fixture["customAppPresets"].clone();
    mgr.save_full(&current).unwrap();

    let resource = dir.join("rule-resource/geo-custom.srs");
    std::fs::create_dir_all(resource.parent().unwrap()).unwrap();
    std::fs::write(&resource, b"SRS").unwrap();
    let icon_dir = crate::icon_cache::icons_dir(&dir);
    crate::icon_cache::write_icon(&icon_dir, "app-custom", "png", b"PNG").unwrap();
    let ts_state = dir.join("tailscale/ts-1");
    std::fs::create_dir_all(&ts_state).unwrap();

    let mut incoming = current.clone();
    incoming["servers"] = serde_json::json!([{ "id": "proxy-1", "protocol": "vless" }]);
    incoming["ruleResources"] = serde_json::json!([]);
    incoming["customAppPresets"] = serde_json::json!([]);
    mgr.save_full_deferred_cleanup(&current, &incoming).unwrap();

    assert!(resource.exists(), "保存阶段不得删除规则资源文件");
    assert!(
        icon_dir.join("app-custom.png").exists(),
        "保存阶段不得驱逐图标"
    );
    assert!(ts_state.exists(), "保存阶段不得清 Tailscale state");
    assert!(
        mgr.deferred_deletions_path().exists(),
        "删除意图须持久化以跨崩溃恢复"
    );
}

#[test]
fn deferred_deletions_cancel_readded_entities_and_retry_failures() {
    let dir = temp_dir("deferred-delete-reconcile");
    let mgr = ConfigManager::new(dir.clone());
    let mut current = mgr.load_full().unwrap();
    let fixture = deletion_fixture();
    current["servers"] = fixture["servers"].clone();
    current["ruleResources"] = fixture["ruleResources"].clone();
    current["customAppPresets"] = fixture["customAppPresets"].clone();
    mgr.save_full(&current).unwrap();
    let mut incoming = current.clone();
    incoming["servers"] = serde_json::json!([{ "id": "proxy-1", "protocol": "vless" }]);
    incoming["ruleResources"] = serde_json::json!([]);
    incoming["customAppPresets"] = serde_json::json!([]);
    mgr.stage_deferred_deletions(&current, &incoming).unwrap();

    let mut calls = 0usize;
    let cancelled = mgr
        .process_deferred_deletions(|_, _| {
            calls += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(calls, 0, "实体重新出现时不得执行任何不可逆动作");
    assert_eq!(cancelled.cancelled, 4);
    assert!(!mgr.deferred_deletions_path().exists(), "已取消意图须清账");

    mgr.stage_deferred_deletions(&current, &incoming).unwrap();
    mgr.save_full(&incoming).unwrap();
    let first = mgr
        .process_deferred_deletions(|entry, _| {
            if matches!(entry, DeferredConfigDeletion::WarpDevice { .. }) {
                Err("queue unavailable".to_string())
            } else {
                Ok(())
            }
        })
        .unwrap();
    assert_eq!(first.applied, 3);
    assert_eq!(first.retrying, 1);
    let second = mgr.process_deferred_deletions(|_, _| Ok(())).unwrap();
    assert_eq!(second.applied, 1, "失败条目须在下一次 Apply 重试");
    assert!(!mgr.deferred_deletions_path().exists());
}

#[test]
fn explicit_deletions_are_write_ahead_skip_safe_and_cancellable() {
    let dir = temp_dir("explicit-deletion");
    let mgr = ConfigManager::new(dir.clone());
    mgr.load_full().unwrap();
    let deletion = DeferredConfigDeletion::BuiltinRuleResource {
        tag: "cn".to_string(),
        file_name: "geosite-cn.srs".to_string(),
    };

    // Skip 不是提交点：显式意图同样不得越过它单独落 journal。
    let (_, saved) = mgr
        .update_with_explicit_deletions(vec![deletion.clone()], |_| Decision::Skip(()))
        .unwrap();
    assert!(saved.is_none());
    assert!(!mgr.deferred_deletions_path().exists());

    // Write 把意图先于配置提交；此刻不执行不可逆动作。
    mgr.update_with_explicit_deletions(vec![deletion.clone()], |_| Decision::Write(()))
        .unwrap();
    assert!(mgr.deferred_deletions_path().exists());

    // Apply 前同一内置 tag 被重新下载并登记，旧 reset 意图必须取消，不能删掉新文件。
    mgr.update(|cfg| {
        cfg["builtinGeoMeta"] = serde_json::json!({ "cn": { "updatedAt": "now" } });
        Decision::Write(())
    })
    .unwrap();
    let mut calls = 0usize;
    let summary = mgr
        .process_deferred_deletions(|_, _| {
            calls += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(calls, 0, "重新登记的内置资源不得执行旧 reset 删除");
    assert_eq!(summary.cancelled, 1);
    assert!(!mgr.deferred_deletions_path().exists());
}

#[test]
fn deferred_icon_delete_cancels_when_a_new_id_reuses_the_same_sanitized_path() {
    let dir = temp_dir("deferred-icon-sanitize-collision");
    let mgr = ConfigManager::new(dir.clone());
    let mut current = mgr.load_full().unwrap();
    current["customAppPresets"] = serde_json::json!([{ "id": "custom/app", "name": "Old" }]);
    let mut removed = current.clone();
    removed["customAppPresets"] = serde_json::json!([]);
    mgr.stage_deferred_deletions(&current, &removed).unwrap();

    let mut latest = current.clone();
    latest["customAppPresets"] = serde_json::json!([{ "id": "custom?app", "name": "New" }]);
    mgr.save_full(&latest).unwrap();
    let mut calls = 0usize;
    let summary = mgr
        .process_deferred_deletions(|_, _| {
            calls += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(calls, 0, "同一落盘 stem 已被新实体复用时不得删图标");
    assert_eq!(summary.cancelled, 1);
}
