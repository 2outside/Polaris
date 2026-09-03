use super::*;
use std::path::PathBuf;
use tempfile::tempdir;

fn token_path(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("helper-client.token")
}

#[test]
fn read_missing_token_returns_empty() {
    // Polaris token() try/catch → 缺失返回 ''（HelperManager.ts:101-102）
    let dir = tempdir().unwrap();
    assert_eq!(read_token(&token_path(&dir)), "");
}

#[test]
fn write_then_read_roundtrip() {
    let dir = tempdir().unwrap();
    let path = token_path(&dir);
    let token = write_token(&path).unwrap();
    // 32 hex 字符（16 字节，对齐 randomBytes(16).toString('hex')）
    assert_eq!(token.len(), 32);
    assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    // 读回一致（trim 后）
    assert_eq!(read_token(&path), token);
}

#[test]
fn write_token_content_overwrites() {
    let dir = tempdir().unwrap();
    let path = token_path(&dir);
    write_token_content(&path, "first-token").unwrap();
    assert_eq!(read_token(&path), "first-token");
    // 重装复用：覆盖（Polaris install 复用已有 token，HelperManager.ts:478）
    write_token_content(&path, "second-token").unwrap();
    assert_eq!(read_token(&path), "second-token");
}

#[test]
fn write_token_content_trims_whitespace() {
    // read_token 会 trim —— 验证 write 后 read 一致（写时不加空白）
    let dir = tempdir().unwrap();
    let path = token_path(&dir);
    let raw = "abc123";
    write_token_content(&path, raw).unwrap();
    assert_eq!(read_token(&path), raw);
}

#[test]
#[cfg(unix)]
fn token_file_permissions_0600() {
    // Polaris writeFileSync mode 0o600（HelperManager.ts:481）
    use std::os::unix::fs::PermissionsExt;
    let dir = tempdir().unwrap();
    let path = token_path(&dir);
    write_token(&path).unwrap();
    let mode = fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "token 文件必须 0600");
}

#[test]
#[cfg(unix)]
fn existing_token_file_permissions_are_tightened_before_overwrite() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempdir().unwrap();
    let path = token_path(&dir);
    fs::write(&path, "legacy-token").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

    write_token_content(&path, "replacement-token").unwrap();

    assert_eq!(read_token(&path), "replacement-token");
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn remove_token_silent_on_missing() {
    // Polaris unlinkSync try/catch 忽略不存在（HelperManager.ts:569-571）
    let dir = tempdir().unwrap();
    let path = token_path(&dir);
    remove_token(&path); // 不存在，不应 panic
                         // 写后再删
    write_token(&path).unwrap();
    assert!(path.exists());
    remove_token(&path);
    assert!(!path.exists());
}

#[test]
fn generated_token_is_hex_32() {
    let dir = tempdir().unwrap();
    for _ in 0..10 {
        let path = token_path(&dir);
        let t = write_token(&path).unwrap();
        assert_eq!(t.len(), 32, "token 须 32 hex 字符");
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
        let _ = fs::remove_file(&path);
    }
}

#[test]
fn hex_encode_correctness() {
    assert_eq!(hex_encode(&[]), "");
    assert_eq!(hex_encode(&[0x00]), "00");
    assert_eq!(hex_encode(&[0xff]), "ff");
    assert_eq!(hex_encode(&[0xab, 0xcd, 0xef]), "abcdef");
}
