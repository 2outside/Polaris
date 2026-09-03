#![allow(clippy::too_many_lines)]

use super::*;

/// 准备一个临时源目录：sing-box + 一个配套文件，返回 (dir, sha256_hex)。
fn make_src_dir() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let sb_content = b"fake sing-box binary content";
    fs::write(dir.path().join(SINGBOX_BIN_NAME), sb_content).unwrap();
    // 给 sing-box 可执行权限（unix）
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            dir.path().join(SINGBOX_BIN_NAME),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }
    fs::write(dir.path().join("libcronet.dylib"), b"fake libcronet").unwrap();

    let hash = sha256_hex(sb_content);
    (dir, hash)
}

// ===== sha256_hex（合并自 linux 自实现 + mac 内联） =====

#[test]
fn sha256_hex_known_vector() {
    // sha256(b"") = e3b0c4...
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    // sha256(b"abc") = ba7816...
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn sha256_hex_lowercase() {
    // Go hex.EncodeToString 输出小写
    let h = sha256_hex(b"X");
    assert_eq!(h, h.to_lowercase());
    assert!(!h.chars().any(|c| c.is_ascii_uppercase()));
}

// ===== verify_singbox_hash（移植自 mac 单测） =====

#[test]
fn verify_singbox_hash_matches() {
    // helper.go:144-146: sha256 匹配
    let (dir, hash) = make_src_dir();
    let result = verify_singbox_hash(dir.path(), &hash);
    assert!(result.is_ok());
    assert!(!result.unwrap().is_empty());
}

#[test]
fn verify_singbox_hash_case_insensitive() {
    // Go EqualFold 大小写不敏感
    let (dir, hash) = make_src_dir();
    let upper = hash.to_uppercase();
    assert!(verify_singbox_hash(dir.path(), &upper).is_ok());
}

#[test]
fn verify_singbox_hash_mismatch() {
    // helper.go:146: hash 不符
    let (dir, _hash) = make_src_dir();
    let wrong = "0".repeat(64);
    let result = verify_singbox_hash(dir.path(), &wrong);
    assert_eq!(result.unwrap_err(), InstallResult::HashMismatch);
}

#[test]
fn verify_singbox_read_fails() {
    // helper.go:142: 读失败 → ERR read-singbox
    let dir = tempfile::tempdir().unwrap(); // 空目录，无 sing-box
    let result = verify_singbox_hash(dir.path(), &"a".repeat(64));
    assert!(matches!(result, Err(InstallResult::ReadSingbox(_))));
}

// ===== list_src_files（移植自 mac 单测） =====

#[test]
fn list_src_files_excludes_dirs() {
    // helper.go:158: if e.IsDir() { continue }
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("sing-box"), b"x").unwrap();
    fs::write(dir.path().join("libcronet.dylib"), b"y").unwrap();
    fs::create_dir(dir.path().join("subdir")).unwrap();
    let names = list_src_files(dir.path()).unwrap();
    assert!(names.contains(&"sing-box".to_owned()));
    assert!(names.contains(&"libcronet.dylib".to_owned()));
    assert!(!names.contains(&"subdir".to_owned()), "目录应被排除");
}

#[test]
fn list_src_files_sorted() {
    // Go os.ReadDir 返回已排序
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("zzz"), b"1").unwrap();
    fs::write(dir.path().join("aaa"), b"2").unwrap();
    fs::write(dir.path().join("mmm"), b"3").unwrap();
    let names = list_src_files(dir.path()).unwrap();
    assert_eq!(names, vec!["aaa", "mmm", "zzz"]);
}

// ===== atomic_install_files（移植自 mac 单测） =====

#[test]
fn atomic_install_writes_all_files() {
    // helper.go:156-178: 逐文件原子写入 + chmod 0755
    let (src, hash) = make_src_dir();
    let core = tempfile::tempdir().unwrap();
    let sb_data = verify_singbox_hash(src.path(), &hash).unwrap();
    let names = list_src_files(src.path()).unwrap();
    atomic_install_files(src.path(), core.path(), &names, &sb_data).unwrap();

    // 验证两文件都就位
    assert!(core.path().join(SINGBOX_BIN_NAME).exists());
    assert!(core.path().join("libcronet.dylib").exists());
    // sing-box 内容与源一致（堵 TOCTOU：用的是已校验字节）
    let installed = fs::read(core.path().join(SINGBOX_BIN_NAME)).unwrap();
    assert_eq!(installed, b"fake sing-box binary content");
    // 权限 0755（unix）
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(core.path().join(SINGBOX_BIN_NAME))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755);
    }
}

#[test]
fn atomic_install_leaves_no_tmp_files() {
    // .new 文件应已 rename 掉，不留残留
    let (src, hash) = make_src_dir();
    let core = tempfile::tempdir().unwrap();
    let sb_data = verify_singbox_hash(src.path(), &hash).unwrap();
    let names = list_src_files(src.path()).unwrap();
    atomic_install_files(src.path(), core.path(), &names, &sb_data).unwrap();
    // 不应有 .new 文件残留
    let entries: Vec<_> = fs::read_dir(core.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(!entries.iter().any(|n| n.ends_with(".new")));
}

#[test]
fn atomic_install_mkdirs_core_dir() {
    // core_dir 不存在时应自动建（helper.go:152-154 MkdirAll）
    let (src, hash) = make_src_dir();
    let parent = tempfile::tempdir().unwrap();
    let core = parent.path().join("nested").join("core");
    let sb_data = verify_singbox_hash(src.path(), &hash).unwrap();
    let names = list_src_files(src.path()).unwrap();
    atomic_install_files(src.path(), &core, &names, &sb_data).unwrap();
    assert!(core.join(SINGBOX_BIN_NAME).exists());
}

// ===== prune_extra_files（移植自 mac 单测） =====

#[test]
fn prune_extra_files_removes_old() {
    // helper.go:179-192: 清理不在 keep_names 的旧文件
    let core = tempfile::tempdir().unwrap();
    // 模拟旧残留：旧版 sing-box + 旧配套
    fs::write(core.path().join("sing-box"), b"old").unwrap();
    fs::write(core.path().join("libcronet_old.dylib"), b"old dylib").unwrap();
    fs::write(core.path().join("stale.bin"), b"stale").unwrap();
    // 新 src 只有 sing-box + libcronet.dylib
    let keep = vec!["sing-box".to_owned(), "libcronet.dylib".to_owned()];
    prune_extra_files(core.path(), &keep);
    // 旧残留应被删
    assert!(!core.path().join("stale.bin").exists());
    assert!(!core.path().join("libcronet_old.dylib").exists());
    // sing-box 保留（在 keep 中）
    assert!(core.path().join("sing-box").exists());
}

#[test]
fn prune_extra_files_missing_dir_is_noop() {
    // core_dir 不存在 → 静默 no-op（best-effort）
    prune_extra_files(Path::new("/nonexistent/xyz/core"), &[]);
}

// ===== install_core_files 完整流程（移植自 mac 单测） =====

#[test]
fn install_core_files_full_flow() {
    // 完整流程：校验 → 枚举 → 写入 → 清理
    let (src, hash) = make_src_dir();
    let core = tempfile::tempdir().unwrap();
    // 预放一个旧残留
    fs::write(core.path().join("stale.bin"), b"stale").unwrap();

    let result = install_core_files(core.path(), src.path(), &hash);
    assert!(result.is_ok());
    // 旧残留被清
    assert!(!core.path().join("stale.bin").exists());
    // 新文件就位
    assert!(core.path().join(SINGBOX_BIN_NAME).exists());
    assert!(core.path().join("libcronet.dylib").exists());
}

#[test]
fn install_core_files_coredir_unset() {
    // helper.go:135: coreDir 空 → ERR coredir-unset
    let (src, hash) = make_src_dir();
    let result = install_core_files(Path::new(""), src.path(), &hash);
    assert_eq!(result.unwrap_err(), InstallResult::CoreDirUnset);
}

#[test]
fn install_core_files_bad_args_empty_src() {
    // helper.go:137: srcDir 空 → ERR bad-args
    let core = tempfile::tempdir().unwrap();
    let result = install_core_files(core.path(), Path::new(""), &"a".repeat(64));
    assert_eq!(result.unwrap_err(), InstallResult::BadArgs);
}

#[test]
fn install_core_files_bad_args_short_hash() {
    // helper.go:137: wantHash 长度 != 64 → ERR bad-args
    let (src, _hash) = make_src_dir();
    let core = tempfile::tempdir().unwrap();
    let result = install_core_files(core.path(), src.path(), "abc");
    assert_eq!(result.unwrap_err(), InstallResult::BadArgs);
}

#[test]
fn install_core_files_bad_args_non_hex_hash() {
    // 64 字符但非 hex
    let (src, _hash) = make_src_dir();
    let core = tempfile::tempdir().unwrap();
    let result = install_core_files(core.path(), src.path(), &"z".repeat(64));
    assert_eq!(result.unwrap_err(), InstallResult::BadArgs);
}

// ===== to_wire_line（锁住 wire 协议，对照 Go 源各 return 分支） =====

#[test]
fn to_wire_line_for_all_variants() {
    assert_eq!(InstallResult::Installed.to_wire_line(), "OK installed");
    assert_eq!(
        InstallResult::CoreDirUnset.to_wire_line(),
        "ERR coredir-unset"
    );
    assert_eq!(InstallResult::BadArgs.to_wire_line(), "ERR bad-args");
    assert_eq!(
        InstallResult::HashMismatch.to_wire_line(),
        "ERR hash-mismatch"
    );
    assert_eq!(
        InstallResult::ReadSingbox("e".into()).to_wire_line(),
        "ERR read-singbox e"
    );
    assert_eq!(
        InstallResult::ReadDir("e".into()).to_wire_line(),
        "ERR readdir e"
    );
    assert_eq!(
        InstallResult::Mkdir("e".into()).to_wire_line(),
        "ERR mkdir e"
    );
    assert_eq!(
        InstallResult::Read {
            name: "libcronet.so".into(),
            detail: "perm".into()
        }
        .to_wire_line(),
        "ERR read libcronet.so perm"
    );
    assert_eq!(
        InstallResult::Write {
            name: "x".into(),
            detail: "full".into()
        }
        .to_wire_line(),
        "ERR write x full"
    );
    assert_eq!(
        InstallResult::Rename {
            name: "y".into(),
            detail: "busy".into()
        }
        .to_wire_line(),
        "ERR rename y busy"
    );
}

#[test]
fn is_ok_predicate() {
    assert!(InstallResult::Installed.is_ok());
    assert!(!InstallResult::BadArgs.is_ok());
    assert!(!InstallResult::HashMismatch.is_ok());
}

// ===== is_valid_core_dir（移植自 mac 单测） =====

#[test]
fn is_valid_core_dir_checks() {
    let parent = tempfile::tempdir().unwrap();
    let core = parent.path().join("core");
    assert!(is_valid_core_dir(&core), "父目录存在 + core 非空 → 有效");
    assert!(!is_valid_core_dir(Path::new("")), "空路径无效");
    assert!(
        !is_valid_core_dir(Path::new("/nonexistent-parent-xyz/core")),
        "父目录不存在 → 无效"
    );
}
