use super::super::*;
use crate::runtime::config::ConfigManager;
use crate::test_support::TestDir;

fn temp_dir(tag: &str) -> TestDir {
    TestDir::new(&format!("polaris-privacy-store-{tag}-"))
}

/// 生产路径回归：前端全量 `saveConfig` 覆盖 config.json 后，隐私密码（scrypt 独立文件）必须仍在。
///
/// 独立文件与 config.json 物理分离 → 前端全量保存**永远碰不到**它（架构级消除「设完密码改任意设置就拆锁」的洞）。
#[test]
fn frontend_full_save_without_hash_preserves_password() {
    let dir = temp_dir("full-save");
    let mgr = ConfigManager::new(dir.clone());
    set_password_core(&mgr, "correct horse", false).expect("set 应成功");

    // 模拟前端：拿 config_get 的产物（已 strip hash）→ 改一个无关键 → 全量提交。
    let mut as_frontend_sees = mgr.load_full().expect("load 应成功");
    strip_privacy_secrets(&mut as_frontend_sees);
    assert!(
        as_frontend_sees.get(PRIVACY_PASSWORD_HASH_KEY).is_none(),
        "前提：前端拿到的 config 不含 hash"
    );
    as_frontend_sees["logLevel"] = json!("debug");

    config_save_core(&mgr, &mut as_frontend_sees, None, false).expect("save 应成功");

    let mgr2 = ConfigManager::new(dir.clone());
    assert!(
        has_password_core(&mgr2).unwrap(),
        "全量保存后密码仍在（独立文件未受影响）"
    );
    assert!(
        unlock_core(&mgr2, "correct horse").unwrap(),
        "正确密码仍可解锁"
    );
    assert!(!unlock_core(&mgr2, "whatever").unwrap(), "任意密码不得放行");
    assert_eq!(
        mgr2.current().unwrap()["logLevel"],
        json!("debug"),
        "无关键的改动照常生效"
    );
}

/// 回填**不得**堵死清除密码：清除走的是「键缺失」（`obj.remove`），若回填无条件生效则永远清不掉。
///
/// 打断 `preserve_server_owned_secrets` 的「入参显式带该键 → 尊重入参」分支 → 本测转红。
#[test]
fn clearing_password_still_works_through_its_own_path() {
    let dir = temp_dir("clear");
    let mgr = ConfigManager::new(dir.clone());
    set_password_core(&mgr, "temp pass", false).expect("set 应成功");
    assert!(has_password_core(&mgr).unwrap(), "前提：已设密码");

    set_password_core(&mgr, "", false).expect("清除应成功");

    let mgr2 = ConfigManager::new(dir.clone());
    assert!(
        !has_password_core(&mgr2).unwrap(),
        "密码已清除（回填没把它填回来）"
    );
    assert!(
        unlock_core(&mgr2, "anything").unwrap(),
        "未设密码 → 自由解锁"
    );
}

/// 入参显式带 hash（专线写入）→ 尊重入参，不被当前值顶掉。
#[test]
fn explicit_hash_in_payload_wins_over_backfill() {
    let dir = temp_dir("explicit");
    let mgr = ConfigManager::new(dir.clone());
    set_password_core(&mgr, "old", false).expect("set 应成功");

    let mut incoming = mgr.current().unwrap();
    incoming[PRIVACY_PASSWORD_HASH_KEY] = json!("aabb$newhash");
    preserve_server_owned_secrets(&mgr, &mut incoming);
    assert_eq!(
        incoming[PRIVACY_PASSWORD_HASH_KEY],
        json!("aabb$newhash"),
        "显式入参不被回填覆盖"
    );
}

#[test]
fn hash_survives_reload_and_gates_unlock() {
    let dir = temp_dir("survive");
    {
        let mgr = ConfigManager::new(dir.clone());
        set_password_core(&mgr, "correct horse", false).expect("set 应成功");
    }
    // 新建 ConfigManager 从磁盘重 load（每次 load 都跑 migrate_privacy_password_clear）。
    let mgr2 = ConfigManager::new(dir.clone());
    assert!(
        has_password_core(&mgr2).unwrap(),
        "reload 后 has=true（hash 未被 migrate 清空）"
    );
    assert!(unlock_core(&mgr2, "correct horse").unwrap(), "正确密码解锁");
    assert!(!unlock_core(&mgr2, "wrong").unwrap(), "错误密码不解锁");
    assert!(
        !unlock_core(&mgr2, "").unwrap(),
        "已设密码时空密码不得免验通过（原 bug 的核心）"
    );
}

#[test]
fn legacy_plaintext_wiped_but_scrypt_file_untouched_on_reload() {
    let dir = temp_dir("legacy");
    {
        let mgr = ConfigManager::new(dir.clone());
        set_password_core(&mgr, "pw", false).unwrap(); // scrypt 文件
    }
    // 往磁盘 config 手动塞 legacy 明文 privacyPassword（模拟旧版残留）。
    let cfg_path = dir.join("config.json");
    let mut on_disk: Value =
        serde_json::from_str(&std::fs::read_to_string(&cfg_path).unwrap()).unwrap();
    on_disk
        .as_object_mut()
        .unwrap()
        .insert("privacyPassword".into(), json!("LEAK_PLAINTEXT"));
    std::fs::write(&cfg_path, serde_json::to_string(&on_disk).unwrap()).unwrap();
    // reload：migrate 清明文；scrypt 文件（独立于 config）不受影响。
    let mgr2 = ConfigManager::new(dir.clone());
    let cfg = mgr2.load_full().unwrap();
    assert_eq!(
        cfg["privacyPassword"],
        json!(""),
        "legacy 明文被 migrate 清空"
    );
    assert!(
        has_password_core(&mgr2).unwrap(),
        "scrypt 文件未受 config 迁移影响 → has=true"
    );
    assert!(unlock_core(&mgr2, "pw").unwrap(), "scrypt 文件仍可校验解锁");
}

#[test]
fn clear_password_removes_hash_and_reopens_free_unlock() {
    let dir = temp_dir("clear");
    let mgr = ConfigManager::new(dir.clone());
    set_password_core(&mgr, "pw", false).unwrap();
    assert!(has_password_core(&mgr).unwrap());
    // 空串清除。
    set_password_core(&mgr, "", false).unwrap();
    let mgr2 = ConfigManager::new(dir.clone());
    assert!(!has_password_core(&mgr2).unwrap(), "清除后 has=false");
    assert!(
        unlock_core(&mgr2, "anything").unwrap(),
        "未设密码 → 自由解锁"
    );
}

#[test]
fn scrypt_hash_never_enters_config_object() {
    // 架构级隔离：scrypt 哈希存独立 privacy-lock.json，**从不进 config 对象** → 前端出口天然无从泄漏
    // （比「进 config 再逐出口剥」强一档）。set 后 config 缓存里恒无 hash 键；文件里则有。
    let dir = temp_dir("noleak");
    let mgr = ConfigManager::new(dir.clone());
    set_password_core(&mgr, "topsecret", false).unwrap();
    let full = mgr.current().unwrap();
    assert!(
        full.get(PRIVACY_PASSWORD_HASH_KEY).is_none(),
        "scrypt hash 从不进 config 对象（独立文件存储）"
    );
    // config 默认模板带 `privacyPassword: ""`（空），但绝不含非空明文（migrate 恒清空）。
    let plain = full
        .get(PRIVACY_PASSWORD_KEY)
        .and_then(Value::as_str)
        .unwrap_or("");
    assert!(plain.is_empty(), "config 里无非空明文");
    // 独立文件确实持有哈希（可验），但它不在任何前端可见的 config 出口里。
    let path = privacy_lock_path(&mgr);
    let h = polaris_store::privacy_lock::read(&StdFs, &path).expect("文件持有 scrypt 哈希");
    assert!(polaris_store::privacy_lock::verify("topsecret", &h));
    // strip 仍兜底剥 legacy 键（存量未迁移用户过渡期）。
    let mut with_legacy = json!({ "privacyPassword": "x", "privacyPasswordHash": "aa$bb" });
    strip_privacy_secrets(&mut with_legacy);
    assert!(
        with_legacy.get(PRIVACY_PASSWORD_HASH_KEY).is_none(),
        "legacy hash 键剥除"
    );
    assert!(
        with_legacy.get(PRIVACY_PASSWORD_KEY).is_none(),
        "legacy 明文键剥除"
    );
}

/// 存量迁移（不锁死老用户）：config.json 里的 legacy salted-SHA256（无 scrypt 文件）→ has=true、
/// 正确密码可解锁，且解锁后**透明升级**为 scrypt 文件 + 抹掉 legacy 键。
///
/// 变异门「迁移丢旧 hash」：若升级路径在写 scrypt 文件前就删 legacy 键、或验败也删键 → 老用户被锁死，
/// 下方「升级后仍可解锁」或姊妹测试 `legacy_sha256_wrong_password_no_upgrade_no_lockout` 转红。
#[test]
fn legacy_sha256_unlock_upgrades_to_scrypt_file() {
    let dir = temp_dir("legacy-upgrade");
    // 手工种一个 legacy salted-SHA256 config（模拟旧版本存量用户，无 privacy-lock.json）。
    let salt = gen_salt().unwrap();
    let legacy = format!("{}${}", hex_encode(&salt), hash_password(&salt, "old-pass"));
    {
        let mgr = ConfigManager::new(dir.clone());
        let mut cfg = mgr.load_full().unwrap();
        cfg.as_object_mut()
            .unwrap()
            .insert(PRIVACY_PASSWORD_HASH_KEY.into(), json!(legacy));
        mgr.save_full(&cfg).unwrap();
    }
    let path = polaris_store::privacy_lock::lock_path(&dir);
    assert!(!path.exists(), "前提：存量态无 scrypt 文件");

    let mgr = ConfigManager::new(dir.clone());
    assert!(has_password_core(&mgr).unwrap(), "legacy 键 → has=true");
    // 错密码：不解锁、不升级、不删旧键（防锁死）。
    assert!(!unlock_core(&mgr, "wrong").unwrap(), "错误密码不解锁");
    assert!(!path.exists(), "错密码不得建 scrypt 文件");
    // 正确密码：解锁 + 透明升级。
    assert!(
        unlock_core(&mgr, "old-pass").unwrap(),
        "正确 legacy 密码解锁"
    );
    assert!(path.exists(), "解锁后升级为 scrypt 文件");
    // 升级后：新 ConfigManager（冷缓存）仍可解锁；legacy 键已从 config 抹除；走的是 scrypt 文件。
    let mgr2 = ConfigManager::new(dir.clone());
    assert!(
        mgr2.load_full()
            .unwrap()
            .get(PRIVACY_PASSWORD_HASH_KEY)
            .is_none(),
        "升级后 legacy 键已抹除（单一真值源）"
    );
    assert!(
        has_password_core(&mgr2).unwrap(),
        "升级后 has=true（来自文件）"
    );
    assert!(
        unlock_core(&mgr2, "old-pass").unwrap(),
        "升级后正确密码仍解锁"
    );
    assert!(
        !unlock_core(&mgr2, "old-pass-wrong").unwrap(),
        "升级后错误密码不解锁"
    );
}

/// 存量迁移安全边：legacy 密码**验败**绝不删旧键 / 不建文件 → 老用户不被锁死，正确密码仍能解锁。
#[test]
fn legacy_sha256_wrong_password_no_upgrade_no_lockout() {
    let dir = temp_dir("legacy-nolockout");
    let salt = gen_salt().unwrap();
    let legacy = format!("{}${}", hex_encode(&salt), hash_password(&salt, "keep-me"));
    {
        let mgr = ConfigManager::new(dir.clone());
        let mut cfg = mgr.load_full().unwrap();
        cfg.as_object_mut()
            .unwrap()
            .insert(PRIVACY_PASSWORD_HASH_KEY.into(), json!(legacy));
        mgr.save_full(&cfg).unwrap();
    }
    let path = polaris_store::privacy_lock::lock_path(&dir);
    let mgr = ConfigManager::new(dir.clone());
    // 连续错密码若误删旧键则会把用户锁死——此处验证多次错误后正确密码依旧解锁。
    assert!(!unlock_core(&mgr, "nope1").unwrap());
    assert!(!unlock_core(&mgr, "nope2").unwrap());
    assert!(!path.exists(), "错密码全程不建文件");
    assert!(
        has_password_core(&mgr).unwrap(),
        "旧键未被删 → 仍算已设密码"
    );
    assert!(
        unlock_core(&mgr, "keep-me").unwrap(),
        "正确密码始终能解锁（未被锁死）"
    );
}

/// 每次 set 新生成盐（salt 唯一，防同密码撞相同哈希）。变异门「删 salt / 盐恒定」→ 两次哈希相同、转红。
#[test]
fn salt_unique_per_set() {
    let dir = temp_dir("salt-uniq");
    let mgr = ConfigManager::new(dir.clone());
    let path = privacy_lock_path(&mgr);
    set_password_core(&mgr, "same-pw", false).unwrap();
    let h1 = polaris_store::privacy_lock::read(&StdFs, &path).unwrap();
    set_password_core(&mgr, "same-pw", false).unwrap();
    let h2 = polaris_store::privacy_lock::read(&StdFs, &path).unwrap();
    assert_ne!(h1.salt, h2.salt, "两次 set 同密码须用不同盐");
    assert_ne!(h1.hash, h2.hash, "不同盐 → 不同哈希");
    // 两者都能验过（盐随各自哈希一起存）。
    assert!(polaris_store::privacy_lock::verify("same-pw", &h2));
}

/// 契约 L141「锁屏禁改/清密码」回归：锁屏态下改密码、清密码都必须被拒，且**不得动存储一个字节**——
/// 这正是此前的洞：锁屏状态下传空串本会走到 `obj.remove(HASH_KEY)` 直接清密码 = 免验解锁。
///
/// 打断 `set_password_core` 顶部的 `if locked { return Err(...) }` → 本测两处 `expect_err` 转红
/// （改密码会把 "before-lock" 覆盖掉、清密码会让 has_password 变 false）。
#[test]
fn locked_rejects_set_and_clear_without_touching_storage() {
    let dir = temp_dir("locked-gate");
    let mgr = ConfigManager::new(dir.clone());
    set_password_core(&mgr, "before-lock", false).expect("解锁态应可正常设密码");
    assert!(has_password_core(&mgr).unwrap(), "前提：已设密码");

    // 锁屏态：改密码被拒——旧密码原样有效。
    let err = set_password_core(&mgr, "attempt-change", true).expect_err("锁屏态必须拒绝改密码");
    assert!(matches!(err, SetPasswordError::Locked));
    assert!(
        unlock_core(&mgr, "before-lock").unwrap(),
        "锁屏态改密码被拒后，旧密码必须原样可解锁"
    );

    // 锁屏态：清密码（空串）同样被拒——密码必须仍在。
    let err2 = set_password_core(&mgr, "", true).expect_err("锁屏态必须拒绝清密码");
    assert!(matches!(err2, SetPasswordError::Locked));
    assert!(
        has_password_core(&mgr).unwrap(),
        "锁屏态清密码请求被拒后，密码必须仍在"
    );
}
