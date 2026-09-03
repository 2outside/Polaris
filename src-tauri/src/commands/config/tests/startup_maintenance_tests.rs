use super::super::*;
use crate::runtime::config::ConfigManager;
use crate::test_support::TestDir;

fn temp_dir(tag: &str) -> TestDir {
    TestDir::new(&format!("polaris-maint-{tag}-"))
}

/// 有效配置模板（能过 validate → load 成功走 loaded_from_disk）。
fn valid_config() -> Value {
    json!({
        "proxyMode": "global",
        "proxyModeType": "systemProxy",
        "logLevel": "info",
        "mixedPort": 7890,
        "controlPort": 9090,
        "tunConfig": {"mtu": 1350, "stack": "auto", "autoRoute": true, "strictRoute": true}
    })
}

#[test]
fn clash_secret_is_32_lowercase_hex_and_unique() {
    // 该修（HIGH）：CSPRNG 16B → 32 位小写 hex（对齐 上游 randomBytes(16).toString('hex')）。
    let a = generate_local_api_secret().unwrap();
    assert_eq!(a.len(), 32, "16 字节 → 32 hex");
    assert!(a
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    let b = generate_local_api_secret().unwrap();
    assert_ne!(a, b, "连续生成不得相同（CSPRNG）");
}

#[test]
fn backfill_generates_and_persists_secret_when_missing() {
    // 缺 clashApiSecret → 回填随机值并**落盘持久化**（跨会话稳定，供外部客户端复用）。
    let dir = temp_dir("secret-gen");
    std::fs::write(dir.join("config.json"), valid_config().to_string()).unwrap();
    let mgr = ConfigManager::new(dir.clone());
    backfill_secret_and_privacy(&mgr).unwrap();
    // 落盘（新 ConfigManager 从盘重载）后 secret 存在且非空。
    let mgr2 = ConfigManager::new(dir.clone());
    let secret = mgr2.load_full().unwrap()["clashApiSecret"]
        .as_str()
        .unwrap_or("")
        .to_string();
    assert_eq!(secret.len(), 32, "回填的 secret 须落盘持久化");
    // 幂等：二次维护不改已有 secret（稳定，不每次 load 重生成）。
    backfill_secret_and_privacy(&mgr2).unwrap();
    let mgr3 = ConfigManager::new(dir.clone());
    assert_eq!(
        mgr3.load_full().unwrap()["clashApiSecret"]
            .as_str()
            .unwrap(),
        secret,
        "已有 secret 须稳定不变"
    );
}

#[test]
fn backfill_preserves_existing_secret() {
    // 已有 secret → 不覆盖（幂等门；打断「!has_secret」判定即转红）。
    let dir = temp_dir("secret-keep");
    let mut cfg = valid_config();
    cfg["clashApiSecret"] = json!("deadbeefdeadbeefdeadbeefdeadbeef");
    std::fs::write(dir.join("config.json"), cfg.to_string()).unwrap();
    let mgr = ConfigManager::new(dir.clone());
    backfill_secret_and_privacy(&mgr).unwrap();
    let mgr2 = ConfigManager::new(dir.clone());
    assert_eq!(
        mgr2.load_full().unwrap()["clashApiSecret"]
            .as_str()
            .unwrap(),
        "deadbeefdeadbeefdeadbeefdeadbeef",
        "已有 secret 不得被覆盖"
    );
}

#[test]
fn backfill_does_not_overwrite_corrupt_config() {
    // 数据保护红线：损坏配置 load 回落默认，但维护**绝不** save 默认覆盖损坏原文件。
    let dir = temp_dir("corrupt-guard");
    let corrupt = "{ not valid json at all";
    std::fs::write(dir.join("config.json"), corrupt).unwrap();
    let mgr = ConfigManager::new(dir.clone());
    backfill_secret_and_privacy(&mgr).unwrap();
    // 原损坏文件须原样保留（未被默认+secret 覆盖）。
    assert_eq!(
        std::fs::read_to_string(dir.join("config.json")).unwrap(),
        corrupt,
        "损坏配置绝不被维护覆盖"
    );
}

#[test]
fn f29_legacy_plaintext_migrated_to_scrypt_file_losslessly() {
    // 旧明文 privacyPassword 无损迁移为 scrypt 独立文件——密码不丢，锁不失效，且盘上明文被 scrub。
    let dir = temp_dir("f29");
    let mut cfg = valid_config();
    cfg["privacyPassword"] = json!("legacy-secret-42");
    std::fs::write(dir.join("config.json"), cfg.to_string()).unwrap();
    let mgr = ConfigManager::new(dir.clone());
    backfill_secret_and_privacy(&mgr).unwrap();
    // scrypt 文件已落；盘上明文已被清空（save_full 用 migrate 抹空的 cfg 覆盖）。
    let path = polaris_store::privacy_lock::lock_path(&dir);
    assert!(path.exists(), "须已落 scrypt 独立文件");
    let mgr2 = ConfigManager::new(dir.clone());
    let reloaded = mgr2.load_full().unwrap();
    assert_eq!(
        reloaded["privacyPassword"],
        json!(""),
        "盘上明文须被清空（无残留）"
    );
    assert!(
        reloaded.get(PRIVACY_PASSWORD_HASH_KEY).is_none(),
        "迁移落文件、不再写 config 里的 SHA-256 键"
    );
    assert!(
        unlock_core(&mgr2, "legacy-secret-42").unwrap(),
        "旧明文须能解锁（无损迁移）"
    );
    assert!(!unlock_core(&mgr2, "wrong").unwrap(), "错误密码不得解锁");
}

#[test]
fn f29_skips_when_scrypt_file_already_present() {
    // 已有 scrypt 文件（用户已设新密码）→ 旧明文不得覆盖（`!has_scrypt_file && !has_legacy` 门；打断即转红）。
    let dir = temp_dir("f29-skip");
    let mgr = ConfigManager::new(dir.clone());
    set_password_core(&mgr, "real-password", false).unwrap(); // scrypt 文件
                                                              // 手动往盘塞 legacy 明文（模拟旧残留 + 新密码并存）。
    let cfg_path = dir.join("config.json");
    let mut on_disk: Value =
        serde_json::from_str(&std::fs::read_to_string(&cfg_path).unwrap()).unwrap();
    on_disk
        .as_object_mut()
        .unwrap()
        .insert("privacyPassword".into(), json!("stale-plaintext"));
    std::fs::write(&cfg_path, on_disk.to_string()).unwrap();
    backfill_secret_and_privacy(&mgr).unwrap();
    // 既有密码仍有效，旧明文未顶掉它。
    let mgr2 = ConfigManager::new(dir.clone());
    assert!(
        unlock_core(&mgr2, "real-password").unwrap(),
        "既有密码不被旧明文顶替"
    );
    assert!(
        !unlock_core(&mgr2, "stale-plaintext").unwrap(),
        "旧明文不得成为新密码"
    );
}
