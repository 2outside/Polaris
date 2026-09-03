use super::super::*;

#[test]
fn salted_hash_verifies_correct_rejects_wrong_and_empty() {
    let salt = gen_salt().expect("CSPRNG 应可用");
    let stored = format!("{}${}", hex_encode(&salt), hash_password(&salt, "s3cret"));
    assert!(verify_password(&stored, "s3cret"), "正确密码必须验过");
    assert!(!verify_password(&stored, "wrong"), "错误密码必须验败");
    assert!(!verify_password(&stored, ""), "已设密码时空密码不得验过");
}

#[test]
fn hash_is_salted_and_never_plaintext() {
    // 不同盐同密码 → 不同 hash（盐生效，防彩虹表）；hash 不含明文；SHA-256 = 64 hex；同盐同密码稳定。
    let h1 = hash_password(&[1u8; 16], "password");
    let h2 = hash_password(&[2u8; 16], "password");
    assert_ne!(h1, h2, "不同盐必产不同 hash");
    assert!(!h1.contains("password"), "存储绝不含明文");
    assert_eq!(h1.len(), 64, "SHA-256 → 64 hex");
    assert_eq!(
        hash_password(&[1u8; 16], "password"),
        h1,
        "同盐同密码须可复算"
    );
}

#[test]
fn verify_rejects_malformed_stored_fail_closed() {
    assert!(!verify_password("no-separator", "x"));
    assert!(
        !verify_password("zz$deadbeef", "x"),
        "非法盐 hex → fail-closed"
    );
    assert!(!verify_password("$", "x"));
}

#[test]
fn constant_time_eq_basics() {
    assert!(constant_time_eq(b"abcdef", b"abcdef"));
    assert!(!constant_time_eq(b"abcdef", b"abcdeg"));
    assert!(!constant_time_eq(b"abc", b"abcd"));
}

#[test]
fn has_password_reflects_stored_hash_none_means_false() {
    // no-password → has=false（含缺键与空串）。has 读的是 privacyPasswordHash（非 legacy 明文键）。
    assert!(!config_has_password(&json!({})), "无密码 → has=false");
    assert!(
        !config_has_password(&json!({ "privacyPasswordHash": "" })),
        "空串 → has=false"
    );
    // legacy 明文键即便非空也不算「已设密码」——只认 hash 键。
    assert!(
        !config_has_password(&json!({ "privacyPassword": "legacy-plaintext" })),
        "legacy 明文键不参与 has 判定"
    );
    // set → has=true。
    let salt = gen_salt().unwrap();
    let stored = format!("{}${}", hex_encode(&salt), hash_password(&salt, "pw"));
    assert!(
        config_has_password(&json!({ "privacyPasswordHash": stored })),
        "已设密码 → has=true"
    );
}

#[test]
fn set_has_unlock_flow() {
    // set：写 salted hash 到 privacyPasswordHash（模拟 privacy_set_password 的存储侧）。
    let salt = gen_salt().unwrap();
    let stored = format!(
        "{}${}",
        hex_encode(&salt),
        hash_password(&salt, "correct-horse")
    );
    let cfg = json!({ "privacyPasswordHash": stored });
    // has → true。
    assert!(config_has_password(&cfg));
    let got = cfg
        .get(PRIVACY_PASSWORD_HASH_KEY)
        .and_then(Value::as_str)
        .unwrap();
    // unlock(correct) → true；unlock(wrong) → false（模拟 privacy_unlock 的校验侧）。
    assert!(verify_password(got, "correct-horse"), "正确密码解锁");
    assert!(!verify_password(got, "nope"), "错误密码不解锁");
}

#[test]
fn strip_privacy_secrets_removes_both_legacy_and_hash_keeps_rest() {
    // `config_get`（全量快照的唯一出口）与 `broadcast_config_changed`（入核那份 cfg，非前端
    // 出口）共用的剥离：明文 + hash 都不下发，其余键保留。
    let mut cfg = json!({
        "privacyPassword": "legacy-plaintext",
        "privacyPasswordHash": "aabb$deadbeef",
        "proxyMode": "global",
        "mixedPort": 7890,
    });
    strip_privacy_secrets(&mut cfg);
    assert!(cfg.get("privacyPassword").is_none(), "legacy 明文键剥除");
    assert!(
        cfg.get("privacyPasswordHash").is_none(),
        "salted hash 键剥除"
    );
    assert_eq!(cfg["proxyMode"], json!("global"), "非敏感键保留");
    assert_eq!(cfg["mixedPort"], json!(7890));
}

/// 契约 L141「解锁失败 sleep(300) 弱限速」：只在失败路径限速，成功/未设密码自由解锁不拖手感。
///
/// 打断 `apply_unlock_rate_limit` 里的 `tokio::time::sleep` 调用（或整段 if 分支）→ 第二个
/// 断言（失败须 ≥300ms）转红。
#[tokio::test]
async fn rate_limit_delays_only_on_failure() {
    let t_ok = std::time::Instant::now();
    apply_unlock_rate_limit(true).await;
    assert!(
        t_ok.elapsed() < std::time::Duration::from_millis(100),
        "密码正确 / 未设密码自由解锁：不得限速"
    );

    let t_fail = std::time::Instant::now();
    apply_unlock_rate_limit(false).await;
    assert!(
        t_fail.elapsed() >= std::time::Duration::from_millis(UNLOCK_FAIL_DELAY_MS),
        "解锁失败必须弱限速 ≥{UNLOCK_FAIL_DELAY_MS}ms（契约 L141）"
    );
}
