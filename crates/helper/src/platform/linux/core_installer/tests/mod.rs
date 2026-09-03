#![allow(clippy::too_many_lines)]

use super::*;
use std::fs::write;
use tempfile::tempdir;

/// 造一个 srcDir：sing-box + libcronet.so 等配套（对照 Go 注释 :182 的真实核形态）。
fn make_src_dir(dir: &Path, singbox: &[u8], extras: &[(&str, &[u8])]) {
    write(dir.join(SINGBOX_BIN_NAME), singbox).unwrap();
    // 设可执行权限（生产核是可执行二进制）。
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        dir.join(SINGBOX_BIN_NAME),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    for (name, data) in extras {
        write(dir.join(name), data).unwrap();
    }
}

/// 测试本地 sha256（与生产的 sha256_hex 独立实现，避免循环依赖断言）。
fn sha256_hex_local(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

#[test]
fn coredir_unset_returns_err() {
    // Go :184-185: coreDir == "" → "ERR coredir-unset"
    let r = install_core(None, "/tmp/src", &"a".repeat(64));
    assert_eq!(r, InstallResult::CoreDirUnset);
    assert_eq!(r.to_wire_line(), "ERR coredir-unset");
}

#[test]
fn bad_args_when_src_empty() {
    let r = install_core(Some(Path::new("/tmp/core")), "", &"a".repeat(64));
    assert_eq!(r, InstallResult::BadArgs);
}

#[test]
fn bad_args_when_hash_wrong_length() {
    // Go :187: len(wantHash) != 64 → bad-args
    let r = install_core(Some(Path::new("/tmp/core")), "/tmp/src", "abc");
    assert_eq!(r, InstallResult::BadArgs);
}

#[test]
fn bad_args_when_hash_not_hex() {
    // 64 字符但非 hex（proto crate 的 is_valid_sha256_hex 拒绝）。
    let r = install_core(Some(Path::new("/tmp/core")), "/tmp/src", &"z".repeat(64));
    assert_eq!(r, InstallResult::BadArgs);
}

#[test]
fn read_singbox_failure_when_missing() {
    // srcDir 存在但无 sing-box 文件。
    let src = tempdir().unwrap();
    let core = tempdir().unwrap();
    let r = install_core(
        Some(core.path()),
        src.path().to_str().unwrap(),
        &"a".repeat(64),
    );
    let wire = r.to_wire_line();
    match r {
        // io::Error 详情不含 "sing-box"（是 OS 错误文本），只验证变体命中。
        InstallResult::ReadSingbox(_) => {}
        other => panic!("expected ReadSingbox, got {other:?}"),
    }
    assert!(
        wire.starts_with("ERR read-singbox"),
        "wire 应以 ERR read-singbox 开头，got {wire}"
    );
}

#[test]
fn hash_mismatch_when_content_changed() {
    let src = tempdir().unwrap();
    let core = tempdir().unwrap();
    make_src_dir(src.path(), b"real-sing-box-binary", &[]);
    // 故意给错 hash（内容对应的真实 hash 与 wantHash 不符）。
    let r = install_core(
        Some(core.path()),
        src.path().to_str().unwrap(),
        &"0".repeat(64),
    );
    assert_eq!(r, InstallResult::HashMismatch);
    assert_eq!(r.to_wire_line(), "ERR hash-mismatch");
}

#[test]
fn successful_install_copies_singbox_and_extras() {
    let src = tempdir().unwrap();
    let core = tempdir().unwrap();
    let sb = b"#!bin\nsing-box-binary-v1.2.3";
    let cronet = b"cronet shared lib bytes";
    make_src_dir(src.path(), sb, &[("libcronet.so", cronet)]);
    let want_hash = sha256_hex_local(sb);
    let r = install_core(Some(core.path()), src.path().to_str().unwrap(), &want_hash);
    assert_eq!(r, InstallResult::Installed);
    assert!(r.is_ok());
    assert_eq!(r.to_wire_line(), "OK installed");
    // 校验落盘内容。
    assert_eq!(
        std::fs::read(core.path().join(SINGBOX_BIN_NAME)).unwrap(),
        sb
    );
    assert_eq!(
        std::fs::read(core.path().join("libcronet.so")).unwrap(),
        cronet
    );
    // 可执行权限校验（0755）。
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(core.path().join(SINGBOX_BIN_NAME))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o755, "sing-box 须 0755 可执行");
}

#[test]
fn hash_case_insensitive_match() {
    // Go strings.EqualFold 大小写不敏感。wantHash 大写也应匹配小写计算结果。
    let src = tempdir().unwrap();
    let core = tempdir().unwrap();
    let sb = b"binary";
    make_src_dir(src.path(), sb, &[]);
    let want_upper = sha256_hex_local(sb).to_uppercase();
    let r = install_core(Some(core.path()), src.path().to_str().unwrap(), &want_upper);
    assert_eq!(r, InstallResult::Installed);
}

#[test]
fn install_clears_stale_core_artifacts() {
    // coreDir 里残留旧 sing-box / libfoo.so，本次 srcDir 不含它们 → 应被清。
    let src = tempdir().unwrap();
    let core = tempdir().unwrap();
    // 预置陈旧残留。
    write(core.path().join(SINGBOX_BIN_NAME), b"OLD singbox").unwrap();
    write(core.path().join("libstale.so"), b"stale lib").unwrap();
    write(core.path().join("helper.bin"), b"helper self").unwrap(); // 非核文件，应保留

    let sb = b"NEW singbox";
    make_src_dir(src.path(), sb, &[("libnew.so", b"new lib")]);
    let want = sha256_hex_local(sb);
    let r = install_core(Some(core.path()), src.path().to_str().unwrap(), &want);
    assert_eq!(r, InstallResult::Installed);
    // 旧 sing-box 被新内容覆盖。
    assert_eq!(
        std::fs::read(core.path().join(SINGBOX_BIN_NAME)).unwrap(),
        b"NEW singbox"
    );
    // 旧 libstale.so 被清（lib* 前缀）。
    assert!(
        !core.path().join("libstale.so").exists(),
        "旧 lib*.so 应被清"
    );
    // 新 libnew.so 在位。
    assert!(core.path().join("libnew.so").exists());
    // helper.bin 保留（非 sing-box / 非 lib* 前缀）。
    assert!(
        core.path().join("helper.bin").exists(),
        "非核文件不应被误删"
    );
}

#[test]
fn install_skips_subdirectories_in_src() {
    // Go :209-210: if e.IsDir() { continue } —— srcDir 里的子目录不复制。
    let src = tempdir().unwrap();
    let core = tempdir().unwrap();
    let sb = b"bin";
    make_src_dir(src.path(), sb, &[]);
    // 建一个子目录（应被跳过）。
    std::fs::create_dir(src.path().join("subdir")).unwrap();
    let want = sha256_hex_local(sb);
    let r = install_core(Some(core.path()), src.path().to_str().unwrap(), &want);
    assert_eq!(r, InstallResult::Installed);
    assert!(!core.path().join("subdir").exists(), "子目录不应被复制");
}

#[test]
fn read_dir_failure_when_src_missing() {
    let core = tempdir().unwrap();
    // srcDir 不存在 → read sing-box 会先报错（Go 顺序是先 read sing-box :190 再 read_dir :198）。
    let r = install_core(
        Some(core.path()),
        "/nonexistent/src/dir/xyz",
        &"a".repeat(64),
    );
    // read sing-box 先失败（srcDir/sing-box 不存在）。
    match r {
        InstallResult::ReadSingbox(_) => {}
        other => panic!("expected ReadSingbox for missing srcDir, got {other:?}"),
    }
}

#[test]
fn wire_line_for_all_outcomes() {
    // 锁住 wire 形态（对照 Go 源各 return 分支的字符串；委托公共 to_wire_line，输出应逐字同）。
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

/// 静态断言：is_ok 仅对 Installed 真。
#[test]
fn is_ok_predicate() {
    assert!(InstallResult::Installed.is_ok());
    assert!(!InstallResult::BadArgs.is_ok());
    assert!(!InstallResult::HashMismatch.is_ok());
}
