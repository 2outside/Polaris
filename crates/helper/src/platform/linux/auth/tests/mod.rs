#![allow(clippy::too_many_lines)]

use super::*;
use std::fs::write;
use tempfile::tempdir;

// ===== is_authorized（逐字对照 Go TestIsAuthorized）=====

#[test]
fn root_always_authorized_even_without_authfile() {
    // Go: if uid == 0 { return true } —— root 不依赖 authfile 存在性。
    let dir = tempdir().unwrap();
    let missing = dir.path().join("nonexistent");
    assert!(is_authorized(0, &missing), "root 应恒授权");
}

/// 可信 authfile 的元数据：root 属主 + 0600（判据的「通过」侧基线，逐条解析测试都从它出发）。
const TRUSTED_OWNER: u32 = 0;
const TRUSTED_MODE: u32 = 0o600;

#[test]
fn listed_uids_authorized() {
    // Go TestIsAuthorized: authfile = "1000\n1001\n\n"
    // 解析行为走纯函数：非特权测试环境造不出 root-owned 文件，判据的「通过」侧只能在这里钉。
    let c = "1000\n1001\n\n";
    assert_eq!(
        authorize_uid(1000, TRUSTED_OWNER, TRUSTED_MODE, c),
        Ok(true)
    );
    assert_eq!(
        authorize_uid(1001, TRUSTED_OWNER, TRUSTED_MODE, c),
        Ok(true)
    );
}

#[test]
fn unlisted_uid_not_authorized() {
    assert_eq!(
        authorize_uid(1002, TRUSTED_OWNER, TRUSTED_MODE, "1000\n1001\n"),
        Ok(false),
        "uid 1002 不在列表"
    );
}

#[test]
fn missing_authfile_fails_closed_for_non_root() {
    // 失败安全：authfile 缺失时非 root 一律未授权（Go: err != nil → return false）。
    let dir = tempdir().unwrap();
    let missing = dir.path().join("nonexistent");
    assert!(!is_authorized(1000, &missing));
    assert!(is_authorized(0, &missing), "root 仍授权");
}

#[test]
fn blank_and_garbage_lines_skipped() {
    // Go: 空行 / 非数字行 continue（静默跳过，不报错）。
    let c = "\n1000\n\nnot-a-number\n  1001  \n";
    assert_eq!(
        authorize_uid(1000, TRUSTED_OWNER, TRUSTED_MODE, c),
        Ok(true)
    );
    assert_eq!(
        authorize_uid(1001, TRUSTED_OWNER, TRUSTED_MODE, c),
        Ok(true),
        "带空白的行应 TrimSpace 后通过"
    );
    assert_eq!(
        authorize_uid(1002, TRUSTED_OWNER, TRUSTED_MODE, c),
        Ok(false)
    );
}

#[test]
fn negative_uid_string_rejected() {
    // Go strconv.Atoi("-1") = -1，但 n >= 0 校验通过后 uint32(-1) != 任何 uid。
    // 本实现 u32::parse 直接拒绝负号 → None（更严格，语义等价：不授权）。
    assert_eq!(
        authorize_uid(u32::MAX, TRUSTED_OWNER, TRUSTED_MODE, "-1\n"),
        Ok(false),
        "负数 uid 串不应匹配任何 uid"
    );
    let dir = tempdir().unwrap();
    let f = dir.path().join("auth");
    write(&f, "-1\n").unwrap();
    assert!(is_authorized(0, &f), "root 仍授权");
}

// ===== authfile 可信性判据（owner==root + 无 group/other 位）=====

#[test]
fn authfile_owned_by_non_root_rejected() {
    // 属主非 root ⇒ 该属主能把任意 uid 写进列表；即便 uid 确实列在里面也一律不授权（提权向量）。
    assert_eq!(
        authorize_uid(1000, 1000, 0o600, "1000\n"),
        Err(AuthFileDistrust::NotRootOwned {
            owner_uid: 1000,
            mode: 0o600
        }),
        "非 root 属主的 authfile 内容不作数"
    );
    // 错误消息须说清「谁的文件 / 什么权限 / 期望什么」。
    let msg = authorize_uid(1000, 1000, 0o600, "1000\n")
        .unwrap_err()
        .to_string();
    assert!(
        msg.contains("owner uid=1000"),
        "消息应点名实际属主，got {msg}"
    );
    assert!(msg.contains("0600"), "消息应带实际权限，got {msg}");
    assert!(msg.contains("uid=0"), "消息应说明期望 root 属主，got {msg}");
}

#[test]
fn authfile_readable_by_group_or_other_rejected() {
    // root 属主但 0644：组内/全体可读这份授权列表；0666 更是可直接改判定结果。
    for mode in [0o640, 0o644, 0o604, 0o660, 0o666, 0o777] {
        assert_eq!(
            authorize_uid(1000, 0, mode, "1000\n"),
            Err(AuthFileDistrust::GroupOrOtherAccessible { owner_uid: 0, mode }),
            "mode {mode:04o} 含 group/other 位，应拒"
        );
    }
    let msg = authorize_uid(1000, 0, 0o644, "1000\n")
        .unwrap_err()
        .to_string();
    assert!(msg.contains("0644"), "消息应带实际权限，got {msg}");
    assert!(
        msg.contains("0600"),
        "消息应说明期望 0600 或更严，got {msg}"
    );
}

#[test]
fn root_owned_0600_authfile_accepted() {
    // 判据的「通过」侧：owner==root(0) 且无 group/other 位。
    assert_eq!(authorize_uid(1000, 0, 0o600, "1000\n"), Ok(true));
    // 更严也通过（0400 只读 / 0000 连 root 自己都要靠特权读）。
    assert_eq!(authorize_uid(1000, 0, 0o400, "1000\n"), Ok(true));
    assert_eq!(authorize_uid(1000, 0, 0o000, "1000\n"), Ok(true));
    // setuid/setgid/sticky 位不影响可读性，不该被误判为 group/other 可访问。
    assert_eq!(authorize_uid(1000, 0, 0o4600, "1000\n"), Ok(true));
    // 生产腿传入的是完整 st_mode（含 S_IFREG=0o100000），文件类型位必须被剥掉。
    assert_eq!(authorize_uid(1000, 0, 0o100_600, "1000\n"), Ok(true));
}

#[test]
fn is_authorized_rejects_untrusted_authfile_on_disk() {
    // 生产腿端到端：非特权用户预置一份列了自己 uid 的 authfile —— 正是被修的提权向量。
    // 断言在 root / 非 root 两种测试环境下都成立：非 root 时 owner 不过，root 时 0644 的 mode 不过。
    use std::os::unix::fs::PermissionsExt;
    let dir = tempdir().unwrap();
    let f = dir.path().join("auth");
    write(&f, "1000\n").unwrap();
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        !is_authorized(1000, &f),
        "非 root 属主 / group-other 可读的 authfile 不该授权任何 uid"
    );
    assert!(is_authorized(0, &f), "root 仍恒授权（不读文件）");
}

// ===== owned_by（逐字对照 Go TestOwnedBy）=====

#[test]
fn owned_by_self_for_self_created_file() {
    let dir = tempdir().unwrap();
    let f = dir.path().join("x");
    write(&f, "y").unwrap();
    let self_uid = current_uid();
    assert!(owned_by(&f, self_uid).unwrap(), "本进程 uid 应拥有自建文件");
}

#[test]
fn owned_by_wrong_uid_returns_false() {
    let dir = tempdir().unwrap();
    let f = dir.path().join("x");
    write(&f, "y").unwrap();
    // 用一个极不可能匹配的 uid。
    assert!(
        !owned_by(&f, current_uid().wrapping_add(9999)).unwrap(),
        "错误 uid 不应通过属主校验"
    );
}

#[test]
fn owned_by_missing_path_returns_err() {
    let dir = tempdir().unwrap();
    let missing = dir.path().join("none");
    assert!(
        owned_by(&missing, current_uid()).is_err(),
        "不存在的路径应返回 err"
    );
}

/// 取当前进程 uid（测试 helper，对齐 Go os.Getuid）。
fn current_uid() -> u32 {
    // nix::unistd::getuid 是 getuid(2) 的 safe wrapper（forbid(unsafe_code) 下替代 libc::getuid 的 unsafe FFI）。
    nix::unistd::getuid().as_raw()
}

// ===== PeerCredProvider 桩 =====

#[test]
fn static_peer_cred_returns_injected() {
    let p = StaticPeerCred::new(1000, 2000);
    let c = p.peer_cred().unwrap();
    assert_eq!(
        c,
        PeerCred {
            uid: 1000,
            gid: 2000
        }
    );
}

#[test]
fn no_peer_cred_returns_none() {
    let p = NoPeerCred;
    assert!(p.peer_cred().is_none(), "NoPeerCred 模拟 SO_PEERCRED 失败");
}

#[test]
fn captured_peer_cred_carries_or_reports_failure() {
    // Some(cred) → 原样透传（accept 时捕获的 SO_PEERCRED）。
    let ok = CapturedPeerCred(Some(PeerCred {
        uid: 1000,
        gid: 1000,
    }));
    assert_eq!(
        ok.peer_cred(),
        Some(PeerCred {
            uid: 1000,
            gid: 1000
        })
    );
    // None → handle 走 ERR peercred（凭据捕获失败）。
    let bad = CapturedPeerCred(None);
    assert!(bad.peer_cred().is_none());
}

// ===== owned_by 的 open+fstat 语义（TOCTOU 修复）=====

#[test]
fn owned_by_follows_symlink_to_target_owner() {
    // File::open 跟随 symlink 到目标（Go os.Open 语义）；owned_by 校验的是**目标 inode** 属主。
    let dir = tempdir().unwrap();
    let target = dir.path().join("real_cfg.json");
    write(&target, b"{}").unwrap();
    let link = dir.path().join("link_cfg.json");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    // 经 symlink 校验 → 跟随到 target（本进程 uid 拥有）。
    assert!(
        owned_by(&link, current_uid()).unwrap(),
        "symlink 应跟随到目标 inode 校验属主"
    );
}

// ===== supplementary_groups（getgrouplist 解析，对照 Go supplementaryGroups）=====

#[test]
fn supplementary_groups_current_uid_contains_primary() {
    // getgrouplist 对当前（非特权）uid 返回其所属全部组，必含主组（Go GroupIds 语义）。
    let uid = current_uid();
    let gids = supplementary_groups(uid);
    let primary = nix::unistd::getgid().as_raw();
    assert!(
        gids.contains(&primary),
        "补充组列表应含主组 gid={primary}，got {gids:?}"
    );
}

#[test]
fn supplementary_groups_unknown_uid_returns_empty() {
    // 极不可能存在的 uid → LookupId 失败 → 空 Vec（Go: err != nil → nil）。
    let gids = supplementary_groups(4_000_000_000);
    assert!(gids.is_empty(), "未知 uid 应返回空组列表，got {gids:?}");
}

#[test]
fn auth_error_wire_tokens_match_go_source() {
    // 逐字对照 Go 源 fmt.Fprintln(conn, "ERR peercred" / "ERR unauthorized")。
    assert_eq!(AuthError::Peercred.wire_token(), "peercred");
    assert_eq!(AuthError::Unauthorized.wire_token(), "unauthorized");
    // wire_token 与 polaris-helper-proto 的 ErrorCode 双向一致。
    use polaris_helper_proto::ErrorCode;
    assert_eq!(
        ErrorCode::from_wire_token(AuthError::Peercred.wire_token()),
        ErrorCode::Peercred
    );
    assert_eq!(
        ErrorCode::from_wire_token(AuthError::Unauthorized.wire_token()),
        ErrorCode::Unauthorized
    );
}
