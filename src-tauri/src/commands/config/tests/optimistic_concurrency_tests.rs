use super::super::*;
use crate::runtime::config::ConfigManager;
use crate::test_support::{repo_file, TestDir};

fn temp_dir(tag: &str) -> TestDir {
    TestDir::new(&format!("polaris-optimistic-{tag}-"))
}

/// 缺省 `base_version` = **不校验** = 今天行为（回滚腿：既有十余个调用点零改动）。
///
/// 牙：把 `if let Some(base)` 改成无条件校验（拿 `""` 当基准之类）→ 本条转红，
/// 而那正是「P5 上线即打断所有既有保存路径」的形态。
#[test]
fn absent_base_version_skips_the_check_entirely() {
    let dir = temp_dir("absent");
    let mgr = ConfigManager::new(dir.clone());
    let mut submitted = mgr.load_full().unwrap();
    submitted["logLevel"] = json!("debug");

    let (outcome, _) = config_save_core(&mgr, &mut submitted, None, false).expect("save 应成功");
    assert!(
        matches!(outcome, SaveOutcome::Saved { .. }),
        "不传 base_version 必须直通落盘"
    );
    assert_eq!(
        ConfigManager::new(dir.clone()).load_full().unwrap()["logLevel"],
        json!("debug")
    );
}

/// 普通节点暂存删除经 `config:save` 落盘，不走专用 `server_delete`；MRU 仍须按提交后的 servers
/// 清掉死 id。牙：删掉 `config_save_core` 里的 prune 调用 → incoming 与磁盘都残留 node-a。
#[test]
fn full_save_prunes_recent_ids_after_staged_server_delete() {
    let dir = temp_dir("staged-delete-mru");
    let mgr = ConfigManager::new(dir.clone());
    let mut cfg = mgr.load_full().unwrap();
    cfg["servers"] = json!([
        {"id":"node-a","name":"A","protocol":"vless","address":"a.example","port":443,"uuid":"a"},
        {"id":"node-b","name":"B","protocol":"vless","address":"b.example","port":443,"uuid":"b"}
    ]);
    cfg["recentServerIds"] = json!(["node-a", "missing", "node-b"]);
    mgr.save_full(&cfg).unwrap();

    let mut submitted = mgr.load_full().unwrap();
    submitted["servers"] = json!([
        {"id":"node-b","name":"B","protocol":"vless","address":"b.example","port":443,"uuid":"b"}
    ]);
    config_save_core(&mgr, &mut submitted, None, false).expect("暂存删除保存应成功");

    assert_eq!(submitted["recentServerIds"], json!(["node-b"]));
    assert_eq!(
        ConfigManager::new(dir.clone()).load_full().unwrap()["recentServerIds"],
        json!(["node-b"])
    );
}

/// 基准相符 ⇒ 落盘，且返回的 `version` 就是**落盘后**磁盘现值的版本（前端拿它当新锚点）。
///
/// 牙：让 `Saved.version` 返回入参 `base_version`（或落盘前的版本）→ 第二个断言转红
/// （前端会把陈旧版本当锚点，下一次保存必然自判冲突）。
#[test]
fn matching_base_version_saves_and_returns_the_post_write_version() {
    let dir = temp_dir("match");
    let mgr = ConfigManager::new(dir.clone());
    // 先跑一次把新装默认配置落盘，再以同一前端投影计算提交基准。
    let _ = mgr.load_full().unwrap();

    // 模拟 `config:get`：同一次 load 既是前端拿到的 config，也是后端缓存的现值。
    let mut submitted = mgr.load_full().unwrap();
    let before = config_version(&submitted);
    submitted["logLevel"] = json!("debug");
    let (outcome, _) =
        config_save_core(&mgr, &mut submitted, Some(&before), false).expect("save 应成功");

    let after = config_version(&ConfigManager::new(dir.clone()).load_full().unwrap());
    match outcome {
        SaveOutcome::Saved { version, config } => {
            assert_ne!(version, before, "落盘改了内容，版本必须随之变化");
            assert_eq!(version, after, "返回的版本须与落盘后磁盘现值同源");
            assert_eq!(config["logLevel"], "debug", "成功响应须携事务终态投影");
        }
        SaveOutcome::Conflict { .. } => panic!("基准相符不该判冲突"),
    }
}

/// **R6 的守门人**：基准不符 ⇒ 冲突，且「一个字节都没动」—— 既没写盘，也没跑过任何一条
/// 落盘前策略（`incoming` 原样交还）。
///
/// 牙（本条同时是 R6 的顺序变异对照）：把乐观并发校验从 `config_save_core` 顶端挪到
/// `preserve_server_owned_secrets` / `enforce_backend_authoritative_fields` /
/// `invalidate_stale_subscription_validators` 三条之后 → `incoming` 会被回填出
/// `privacyPasswordHash` 与后端权威的 `recentServerIds` → 后两个断言转红。
/// 把冲突腿改成「照样落盘」→ 第一个断言转红（T2-2：冲突绝不写盘）。
#[test]
fn optimistic_conflict_touches_nothing() {
    let dir = temp_dir("conflict");
    let mgr = ConfigManager::new(dir.clone());

    // 磁盘：带隐私 hash（`preserve_` 的输入）+ 后端权威 MRU（`enforce_` 的输入）。
    let mut cfg = mgr.load_full().unwrap();
    cfg["privacyPasswordHash"] = json!("aabb$deadbeef");
    cfg["recentServerIds"] = json!(["n3", "n2", "n1"]);
    cfg["logLevel"] = json!("info");
    mgr.save_full(&cfg).unwrap();

    // 前端提交：与磁盘不同源的陈旧基准（模拟「暂存期间别人改了盘」）。
    let mut submitted = mgr.load_full().unwrap();
    strip_privacy_secrets(&mut submitted);
    submitted["recentServerIds"] = json!(["stale"]);
    submitted["logLevel"] = json!("debug");
    let before = submitted.clone();

    let (outcome, _) =
        config_save_core(&mgr, &mut submitted, Some("00000000"), false).expect("不应报错");
    match outcome {
        SaveOutcome::Conflict { disk_version } => {
            assert_eq!(
                disk_version,
                config_version(&mgr.current().unwrap()),
                "回传的 diskVersion 须是磁盘现值的版本"
            );
        }
        SaveOutcome::Saved { .. } => panic!("基准不符必须判冲突"),
    }

    assert_eq!(
        ConfigManager::new(dir.clone()).load_full().unwrap()["logLevel"],
        json!("info"),
        "冲突腿绝不写盘"
    );
    assert!(
        submitted.get("privacyPasswordHash").is_none(),
        "冲突腿不得跑过 preserve_server_owned_secrets（校验必须在三条策略之前）"
    );
    assert_eq!(
        submitted["recentServerIds"],
        json!(["stale"]),
        "冲突腿不得跑过 enforce_backend_authoritative_fields（校验必须在三条策略之前）"
    );
    assert_eq!(
        submitted, before,
        "冲突腿交还的入参必须逐字节等于传进来的那份"
    );
}

/// 版本的定义域是**渲染端投影**，不是磁盘原样。
///
/// 前端对 `config:get` 的产物算版本、后端对磁盘算，两边若不是同一份文档则版本恒不等 ⇒
/// 每一次带 `base_version` 的保存都返 conflict、功能整体失效。
///
/// 牙：把 `config_version` 里的 `apply_frontend_view` 删掉 → 两个断言分别转红
/// （设过隐私密码的机器 / `bypassLANList` 缺省的机器上，前端与后端各算各的）。
#[test]
fn config_version_is_computed_over_the_frontend_view() {
    let base = json!({ "mixedPort": 7890, "bypassLANList": ["192.168.0.0/16"] });

    let mut with_secret = base.clone();
    with_secret["privacyPasswordHash"] = json!("aabb$deadbeef");
    assert_eq!(
        config_version(&with_secret),
        config_version(&base),
        "隐私 hash 不下发给前端 ⇒ 不得参与版本"
    );

    let missing_bypass = json!({ "mixedPort": 7890 });
    let mut filled = missing_bypass.clone();
    polaris_config_engine::user_config::system_proxy_bypass::ensure_bypass_lan_list(&mut filled);
    assert_eq!(
        config_version(&missing_bypass),
        config_version(&filled),
        "bypassLANList 由 config_get 补齐 ⇒ 补前补后必须同版本"
    );
}

/// **跨语言值锁**：同一组 fixture，Rust `config_content_hash` 与前端 `configBaseVersion`
/// 必须算出同一个短 hash（fixture 里写死的 `expected` 是双侧共同真值）。
///
/// 前端那一半在 `ui/src/contracts/config-version.test.ts`，读的是同一个文件。
///
/// 牙：把 `encode_utf16()` 换成 `bytes()` → `nonAscii` 用例转红；把 `wrapping_mul` 换成
/// 饱和/普通乘 → 全部转红；把 `stable_stringify` 换成 `to_string` → `nestedKeysShuffled` 转红。
#[test]
fn config_version_matches_the_shared_cross_language_fixture() {
    #[derive(serde::Deserialize)]
    struct Case {
        name: String,
        expected: String,
        config: Value,
    }
    #[derive(serde::Deserialize)]
    struct Fixture {
        cases: Vec<Case>,
    }

    let raw = repo_file("ui/src/contracts/config-version.fixture.json");
    let fixture: Fixture = serde_json::from_str(&raw).expect("fixture 解析失败");
    assert!(
        fixture.cases.len() >= 8,
        "自曝：fixture 读空/读少了，恒绿的空断言比没有这道门更危险"
    );
    for case in &fixture.cases {
        assert_eq!(
            config_content_hash(&case.config),
            case.expected,
            "fixture `{}` 的版本与前端不一致",
            case.name
        );
    }
}
