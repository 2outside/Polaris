use super::*;
#[cfg(unix)]
use crate::StdFs; // 仅 write_sets_0600_perms_on_unix（#[cfg(unix)]）消费；非 unix 不引入避免 unused

const SALT_A: [u8; SALT_LEN] = [1u8; SALT_LEN];
const SALT_B: [u8; SALT_LEN] = [2u8; SALT_LEN];

#[test]
fn hash_deterministic_salted_and_never_plaintext() {
    let h1 = hash_password("password", &SALT_A).unwrap();
    let h2 = hash_password("password", &SALT_B).unwrap();
    // 不同盐同密码 → 不同 hash（盐生效，防彩虹表 / 撞密码可见）。变异门「删 salt」：盐恒定 → 本断言转红。
    assert_ne!(h1.hash, h2.hash, "不同盐必产不同 hash");
    // 同盐同密码 → 稳定可复算。
    assert_eq!(hash_password("password", &SALT_A).unwrap().hash, h1.hash);
    // 绝不含明文；hash = 32B = 64 hex；salt = 16B = 32 hex；algo=scrypt。
    assert!(!h1.hash.contains("password"), "落盘绝不含明文");
    assert_eq!(h1.hash.len(), 64, "keyLen 32 → 64 hex");
    assert_eq!(h1.salt.len(), 32, "salt 16B → 32 hex");
    assert_eq!(h1.algo, "scrypt");
    assert_eq!(h1.params, PARAMS);
}

#[test]
fn scrypt_upgrade_preserves_existing_password_records() {
    // 由 0.11 版按既有 N/r/p/keyLen 生成的固定落盘记录。依赖升级不得让用户旧密码失效。
    let legacy = PrivacyPasswordHash {
        algo: "scrypt".to_string(),
        salt: "01".repeat(SALT_LEN),
        hash: "4f503871c3495339889efd3948600b779d013bc9c4cff0882dcde3f7421f919c".to_string(),
        params: PARAMS,
    };
    assert!(verify("password", &legacy));
    assert!(!verify("wrong", &legacy));
    assert_eq!(hash_password("password", &SALT_A).unwrap(), legacy);
}

#[test]
fn verify_accepts_correct_rejects_wrong_and_empty() {
    let h = hash_password("s3cret", &SALT_A).unwrap();
    assert!(verify("s3cret", &h), "正确密码必须验过");
    assert!(!verify("wrong", &h), "错误密码必须验败");
    assert!(!verify("", &h), "已设密码时空密码不得验过");
}

#[test]
fn verify_fail_closed_on_tampered_or_bad_fields() {
    let good = hash_password("pw", &SALT_A).unwrap();
    // 篡改 hash → 验败。
    let mut h = good.clone();
    h.hash = "deadbeef".into();
    assert!(!verify("pw", &h), "篡改 hash → fail-closed");
    // 非法 hex 盐 → 验败。
    let mut h2 = good.clone();
    h2.salt = "zz".into();
    assert!(!verify("pw", &h2), "非法盐 hex → fail-closed");
    // algo 异类 → 验败。
    let mut h3 = good.clone();
    h3.algo = "md5".into();
    assert!(!verify("pw", &h3), "算法异类 → fail-closed");
    // N 篡改成非 2 的幂 → derive 报错 → 验败。
    let mut h4 = good;
    h4.params.n = 12345;
    assert!(!verify("pw", &h4), "N 非 2 的幂 → fail-closed");
}

/// 变异门（不弱于 oracle）：scrypt 参数逐字锁死 上游 交互档。改弱 N/r/p/keyLen → 本测转红。
#[test]
fn params_match_upstream_oracle() {
    assert_eq!(PARAMS.n, 16384, "N 必为 2^14（上游 交互档，改弱即转红）");
    assert_eq!(PARAMS.r, 8);
    assert_eq!(PARAMS.p, 1);
    assert_eq!(PARAMS.key_len, 32);
    assert!(
        PARAMS.n.is_power_of_two(),
        "N 须为 2 的幂（scrypt log2 前提）"
    );
}

#[test]
fn constant_time_eq_basics() {
    assert!(constant_time_eq(b"abcdef", b"abcdef"));
    assert!(!constant_time_eq(b"abcdef", b"abcdeg"));
    assert!(!constant_time_eq(b"abc", b"abcd"), "长度不等 → false");
}

#[test]
fn write_read_roundtrip_and_remove() {
    let fs = crate::MockFs::default();
    let path = Path::new("/data/privacy-lock.json");
    let h = hash_password("horse-correct", &SALT_A).unwrap();
    write(&fs, path, &h).unwrap();
    assert!(has(&fs, path), "写后 has=true");
    let got = read(&fs, path).expect("读回");
    assert_eq!(got, h, "读回结构须与写入一致");
    assert!(verify("horse-correct", &got), "读回后正确密码验过");
    assert!(!verify("nope", &got));
    remove(&fs, path).unwrap();
    assert!(!has(&fs, path), "删除后 has=false");
    assert!(read(&fs, path).is_none());
}

#[test]
fn read_corrupt_or_missing_is_none_fail_open() {
    let p = Path::new("/data/privacy-lock.json");
    let fs = crate::MockFs::default().with(p, "{not json");
    assert!(read(&fs, p).is_none(), "坏 JSON → None（fail-open）");
    assert!(
        read(&fs, Path::new("/data/nope.json")).is_none(),
        "缺失 → None"
    );
    // 结构合法但 algo 异类 → None。
    let fs2 = crate::MockFs::default().with(
        p,
        r#"{"algo":"md5","salt":"aa","hash":"bb","params":{"N":16384,"r":8,"p":1,"keyLen":32}}"#,
    );
    assert!(read(&fs2, p).is_none(), "algo 异类 → None");
}

/// 0600 权限位（unix）：写盘经 StdFs → open(2) 即 0600，无 0644 携密窗口。用真实 tempdir（不碰用户真配置）。
#[cfg(unix)]
#[test]
fn write_sets_0600_perms_on_unix() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!(
        "polaris-privacy-lock-perms-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = lock_path(&dir);
    let h = hash_password("pw", &SALT_A).unwrap();
    write(&StdFs, &path, &h).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "隐私锁文件须 0600（仅属主读写）");
    // 读回校验（真实 FS 往返）。
    assert!(verify("pw", &read(&StdFs, &path).unwrap()));
    let _ = std::fs::remove_dir_all(&dir);
}
