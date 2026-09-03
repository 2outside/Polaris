use super::*;

/// 内存 TokenStore，验证 trait object 注入（不触碰宿主文件系统）。
#[test]
fn trait_object_works_via_static_store() {
    let store: Box<dyn TokenStore> = Box::new(StaticTokenStore::new("in-mem-tok"));
    assert_eq!(store.token_value(), "in-mem-tok");
}

// --- const_time_eq 行为（移植自 helper-mac）---

#[test]
fn const_time_eq_basic() {
    assert!(const_time_eq(b"abc", b"abc"));
    assert!(!const_time_eq(b"abc", b"abd"));
    assert!(!const_time_eq(b"abc", b"ab"));
    assert!(const_time_eq(b"", b""));
    assert!(!const_time_eq(b"", b"a"));
    assert!(!const_time_eq(b"a", b""));
    // 字节值差（非前缀差）：朴素 == 在第一差字节短路，常量时间全遍历
    assert!(!const_time_eq(b"abcdef", b"abcxef"));
    assert!(const_time_eq(b"abcdef", b"abcdef"));
}

// --- check_token 各分支（移植自 helper-mac verify_token + 扩展四分支）---

#[test]
fn check_matching_token_authed() {
    // helper.go:405: tok == tokenValue() → 通过
    assert_eq!(check_token("sekret", "sekret"), TokenCheck::Authed);
    assert!(check_token("sekret", "sekret").is_authed());
}

#[test]
fn check_empty_client_token() {
    // helper.go:405: tok == "" → ERR auth（防无 token 进程连上不发数据耗资源）
    assert_eq!(check_token("", "sekret"), TokenCheck::EmptyClient);
    assert!(!check_token("", "sekret").is_authed());
}

#[test]
fn check_empty_stored_token() {
    // 存储端为空（token 文件缺失/读失败）：任何非空客户端 token 都不匹配 → 安全失败
    assert_eq!(check_token("anything", ""), TokenCheck::EmptyStored);
    assert!(!check_token("anything", "").is_authed());
}

#[test]
fn check_mismatched_token() {
    // helper.go:405: tok != tokenValue() → ERR auth
    assert_eq!(check_token("wrong", "sekret"), TokenCheck::Mismatch);
    assert!(!check_token("wrong", "sekret").is_authed());
}

#[test]
fn check_both_empty_returns_empty_client() {
    // 双空：先命中客户端空分支（短路顺序与 Go `tok == "" || ...` 一致）
    assert_eq!(check_token("", ""), TokenCheck::EmptyClient);
}

// --- is_authed_constant_time（win 升级版，行为等价旧 is_authed 但走常量时间）---

#[test]
fn is_authed_constant_time_matches_go_logic() {
    // Go: tok == "" || tok != tokenValue() → false；本函数返回相反（true=通过）
    let expected = "real-token-abc";
    assert!(is_authed_constant_time("real-token-abc", expected)); // 匹配
    assert!(!is_authed_constant_time("wrong", expected)); // 不匹配
    assert!(!is_authed_constant_time("", expected)); // 客户端空 → 拒
    assert!(!is_authed_constant_time("real-token-abc", "")); // 服务端无 token → 拒
    assert!(!is_authed_constant_time("", "")); // 双空 → 拒
}

// --- FileTokenStore 读取 + trim（跨平台，Linux 可跑）---

#[test]
fn file_token_store_reads_and_trims() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileTokenStore::new(dir.path());
    // 文件不存在 → 空串
    assert_eq!(store.token_value(), "");
    // 写入带空白的 token
    std::fs::write(store.token_path(), "  my-token-123\n").unwrap();
    // win 无读侧信任判据（fstat/uid 语义不适用，见 FileTokenStore::read_token_value 的
    // cfg(not(unix)) 腿）：读到即 trim 后返回，逐字保真修前行为。
    #[cfg(not(unix))]
    assert_eq!(store.token_value(), "my-token-123");
    // unix 上信任判据看属主 + 权限。非 root 用户写出的文件属主非 root（且 umask 默认给出
    // group/other 读位）→ 两条判据都不过 → fail-closed 空串。以 root 跑时写出的文件属主即
    // root，判据接通 → 必须返回修剪后的真值（正向对照，避免本腿在 root 环境下断言假红/静默
    // 无信息量，形态同 `file_token_store_rejects_untrusted_file_end_to_end`）。
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // 先把权限补成写侧契约形态（0600）：`std::fs::write` 出来的是 umask 决定的 0644，
        // group/other 读位会让**权限**判据先行拒绝 —— 以 root 跑时下面的正向对照就成了假红
        //（属主判据接通了，却被权限判据挡掉）。形态同
        // `file_token_store_rejects_untrusted_file_end_to_end` 的 ② 腿。
        std::fs::set_permissions(store.token_path(), PermissionsExt::from_mode(0o600)).unwrap();
        let owner_uid = std::fs::metadata(store.token_path()).unwrap().uid();
        if owner_uid == 0 {
            assert_eq!(store.token_value(), "my-token-123");
        } else {
            assert_eq!(store.token_value(), "");
        }
    }
}

// --- 读侧信任判据（D8：属主/权限，A2 同型）---
//
// 纯函数 `trusted_token_value` 正反向全可测；端到端腿只能覆盖**拒绝**方向：
// 「可信」样本要求属主 uid==0，非特权测试环境造不出来（chown root 需 CAP_CHOWN）。
// 故 accept 方向的端到端覆盖是本机能力边界，不是漏写 —— 生产 mac 腿由安装脚本
// `chown root:wheel` + `chmod 600` 供给该形态。

#[test]
fn trusted_token_value_accepts_root_owned_and_trims() {
    // 写侧契约形态：root 属主 + 0600（st_mode 含 S_IFREG 位，判据须自行剥掉）。
    assert_eq!(
        trusted_token_value(0, 0o100_600, b"  my-token-123\n"),
        Ok("my-token-123".to_owned())
    );
    // 更严的权限同样可信（0400 只读 / 0000）。
    assert_eq!(
        trusted_token_value(0, 0o100_400, b"tok"),
        Ok("tok".to_owned())
    );
    assert_eq!(
        trusted_token_value(0, 0o100_000, b"tok"),
        Ok("tok".to_owned())
    );
    // owner 位不看（0700 无 group/other 位 → 可信）。
    assert_eq!(
        trusted_token_value(0, 0o100_700, b"tok"),
        Ok("tok".to_owned())
    );
}

#[test]
fn trusted_token_value_rejects_non_root_owner() {
    // 属主非 root ⇒ 该属主可任意改写 token 值，读它等于让对方自己发通行证。
    assert_eq!(
        trusted_token_value(1000, 0o100_600, b"tok"),
        Err(TokenFileDistrust::NotRootOwned {
            owner_uid: 1000,
            mode: 0o600,
        })
    );
    // 属主判据先于权限判据：非 root + 松权限仍报 NotRootOwned。
    assert_eq!(
        trusted_token_value(1, 0o100_666, b"tok"),
        Err(TokenFileDistrust::NotRootOwned {
            owner_uid: 1,
            mode: 0o666,
        })
    );
}

#[test]
fn trusted_token_value_rejects_group_or_other_access() {
    // group 读位（0640）：同组成员读到 token 即可冒充 app。
    assert_eq!(
        trusted_token_value(0, 0o100_640, b"tok"),
        Err(TokenFileDistrust::GroupOrOtherAccessible {
            owner_uid: 0,
            mode: 0o640,
        })
    );
    // other 读位（0604）。
    assert_eq!(
        trusted_token_value(0, 0o100_604, b"tok"),
        Err(TokenFileDistrust::GroupOrOtherAccessible {
            owner_uid: 0,
            mode: 0o604,
        })
    );
    // 执行位也算（0601 / 0610）—— 判据是 mode & 0o077 != 0，不是「可读」。
    assert!(trusted_token_value(0, 0o100_601, b"tok").is_err());
    assert!(trusted_token_value(0, 0o100_610, b"tok").is_err());
}

#[test]
fn token_file_distrust_message_never_leaks_token_contents() {
    // 拒绝日志只说「谁的文件 / 什么权限 / 期望什么」；带上内容就等于把 token 抄进日志。
    let secret = "super-secret-token-value";
    for err in [
        trusted_token_value(1000, 0o100_600, secret.as_bytes()).unwrap_err(),
        trusted_token_value(0, 0o100_644, secret.as_bytes()).unwrap_err(),
    ] {
        let msg = err.to_string();
        assert!(!msg.contains(secret), "distrust 消息泄漏 token 内容: {msg}");
    }
}

/// 端到端腿：`token_value()` → 属主/权限判据 真接通（判据废掉时本腿必红）。
#[cfg(unix)]
#[test]
fn file_token_store_rejects_untrusted_file_end_to_end() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    let store = FileTokenStore::new(dir.path());
    std::fs::write(store.token_path(), "my-token-123\n").unwrap();

    // ① 坏权限：0666（group/other 全开）。以非 root 跑时属主判据先命中，以 root 跑时权限判据命中 ——
    // 两种身份下都必须被拒，故本断言无条件成立。
    std::fs::set_permissions(store.token_path(), PermissionsExt::from_mode(0o666)).unwrap();
    assert_eq!(store.token_value(), "", "0666 的 token 文件必须被拒");

    // ② 坏属主：0600 但属主非 root。本机以非特权用户跑时命中该腿；若以 root 跑，这份样本恰好
    // 满足写侧契约 → 反向断言它被接受（正向对照，避免 root 环境下本腿静默无信息量）。
    std::fs::set_permissions(store.token_path(), PermissionsExt::from_mode(0o600)).unwrap();
    let owner_uid = std::fs::metadata(store.token_path()).unwrap().uid();
    if owner_uid == 0 {
        assert_eq!(
            store.token_value(),
            "my-token-123",
            "root 属主 + 0600 = 写侧契约形态，必须被接受"
        );
    } else {
        assert_eq!(
            store.token_value(),
            "",
            "非 root 属主（uid={owner_uid}）的 token 文件必须被拒"
        );
    }
}

#[test]
fn file_token_store_returns_empty_on_missing_file() {
    let s = FileTokenStore::new("/nonexistent/polaris-test-dir-xyz");
    assert_eq!(s.token_value(), "");
}

#[test]
fn file_token_store_token_path_joins_filename() {
    let store = FileTokenStore::new("/Library/Application Support/Polaris");
    assert_eq!(
        store.token_path(),
        PathBuf::from("/Library/Application Support/Polaris/helper.token")
    );
}

#[test]
fn file_token_store_path_alias_matches_token_path() {
    // win 既有 path() 习惯兼容别名，应与 token_path() 逐字等价
    let store = FileTokenStore::new(r"C:\ProgramData\Polaris");
    assert_eq!(store.path(), store.token_path());
}

#[test]
fn file_token_store_path_uses_platform_separator() {
    // win 旧测试断言：PathBuf::join 用各自平台分隔符
    let s = FileTokenStore::new(r"C:\ProgramData\Polaris");
    let sep = std::path::MAIN_SEPARATOR;
    assert_eq!(
        s.path().to_string_lossy(),
        format!("C:\\ProgramData\\Polaris{sep}helper.token")
    );
}

// --- StaticTokenStore（移植自 helper-win）---

#[test]
fn static_store_returns_token() {
    let s = StaticTokenStore::new("tok-xyz");
    assert_eq!(s.token_value(), "tok-xyz");
}

// --- token_file_exists（移植自 helper-mac）---

#[test]
fn token_file_exists_check() {
    let dir = tempfile::tempdir().unwrap();
    assert!(!token_file_exists(dir.path()));
    std::fs::write(dir.path().join(TOKEN_FILENAME), "x").unwrap();
    assert!(token_file_exists(dir.path()));
}
