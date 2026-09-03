use super::*;
use crate::traits::{MemoryDownload, StdFs};
use crate::verify::sha256_hex;

/// 构造一个完整测试 fixture：内存下载器（URL→bytes）+ StdFs（tempfile 沙箱）+ 内存 store。
struct Fixture {
    dl: MemoryDownload,
    fs: StdFs,
    store: MemoryStateStore,
    tmp: tempfile::TempDir,
}

impl Fixture {
    /// 按 `(url, bytes)` 注入下载条目（测试自行决定 URL 与 sha256 是否匹配）。
    fn with_entry(url: &str, bytes: &[u8]) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let dl = MemoryDownload::new().with(url, bytes.to_vec());
        Self {
            dl,
            fs: StdFs,
            store: MemoryStateStore::new(),
            tmp,
        }
    }
}

/// 便利：用 `(version, bytes)` 推导 URL 与 sha256，构造 entry + fixture 配对。
/// URL 固定为 `https://x/core-{version}`；hash 由真实 bytes 计算（匹配场景）或外部覆盖（失配场景）。
fn setup(version: &str, bytes: &[u8]) -> (VersionManifestEntry, Fixture) {
    let url = format!("https://x/core-{version}");
    let f = Fixture::with_entry(&url, bytes);
    let hash = sha256_hex(bytes);
    let entry = make_entry(version, &url, Some(&hash));
    (entry, f)
}

/// 同 [`setup`] 但 entry 不带 sha256（测「无强校验」场景 / 跨带手动路径）。
fn setup_no_hash(version: &str, bytes: &[u8]) -> (VersionManifestEntry, Fixture) {
    let url = format!("https://x/core-{version}");
    let f = Fixture::with_entry(&url, bytes);
    let entry = make_entry(version, &url, None);
    (entry, f)
}

fn make_entry(version: &str, url: &str, sha: Option<&str>) -> VersionManifestEntry {
    VersionManifestEntry {
        version: version.to_string(),
        url: url.to_string(),
        sha256: sha.map(String::from),
        prerelease: false,
        notes: String::new(),
    }
}

#[test]
fn apply_full_cycle_success() {
    // 端到端：下载 → 校验 → 原子替换 → 簿记。全绿。
    let core = b"fake-sing-box-binary-1.14.1";
    let (entry, f) = setup("1.14.1", core);
    let dest_dir = f.tmp.path().join("dest");
    let cfg = StagedConfig::new(&dest_dir);
    let updater = CoreStagedUpdater::new(&f.dl, &f.fs, &f.store, cfg);

    let outcome = updater.apply(&entry, "1.14.0", "sing-box").unwrap();
    assert_eq!(outcome, ApplyOutcome::Applied);

    // dest_dir 下有 sing-box，内容正确。
    let written = f.fs.read(&dest_dir.join("sing-box")).unwrap();
    assert_eq!(written, core);
    // 版本簿记已记录。
    assert_eq!(f.store.last_applied_version(), Some("1.14.1".into()));
    // staged 已清（apply 成功后 clear）。
    assert!(f.store.load_staged().is_none());
}

#[test]
fn apply_verify_failure_rejected() {
    // sha256 不匹配 → Verify 错误，dest_dir 不动。
    let core = b"real-bytes";
    let wrong_hash = sha256_hex(b"different-bytes");
    let url = "https://x/core-mismatch";
    let f = Fixture::with_entry(url, core);
    let dest_dir = f.tmp.path().join("dest");
    let entry = make_entry("1.14.1", url, Some(&wrong_hash));
    let cfg = StagedConfig::new(&dest_dir);
    let updater = CoreStagedUpdater::new(&f.dl, &f.fs, &f.store, cfg);

    let err = updater.apply(&entry, "1.14.0", "sing-box").unwrap_err();
    assert!(matches!(err, StagedUpdateError::Verify(_)));
    // dest_dir 未创建（apply 先校验后建目录，校验失败时目录尚未建）。
    assert!(!f.fs.exists(&dest_dir));
}

#[test]
fn apply_download_failure() {
    // URL 不在 mock map → Download 错误。
    let f = Fixture::with_entry("https://x/real", b"x");
    let dest_dir = f.tmp.path().join("dest");
    let entry = make_entry("1.14.1", "https://missing", None);
    let cfg = StagedConfig::new(&dest_dir);
    let updater = CoreStagedUpdater::new(&f.dl, &f.fs, &f.store, cfg);

    let err = updater.apply(&entry, "1.14.0", "sing-box").unwrap_err();
    assert!(matches!(err, StagedUpdateError::Download(_)));
}

#[test]
fn apply_discards_when_not_newer() {
    // staged 版本不比 current 新 → Discarded（不下载）。
    let f = Fixture::with_entry("https://x", b"x");
    let dest_dir = f.tmp.path().join("dest");
    let entry = make_entry("1.14.0", "https://x", None);
    let cfg = StagedConfig::new(&dest_dir);
    let updater = CoreStagedUpdater::new(&f.dl, &f.fs, &f.store, cfg);

    let outcome = updater.apply(&entry, "1.14.0", "sing-box").unwrap();
    assert_eq!(outcome, ApplyOutcome::Discarded);
}

#[test]
fn apply_deferred_on_cross_band_restricted() {
    // restrict_band + 跨 major.minor → Deferred（不下载，不报错）。
    let f = Fixture::with_entry("https://x", b"x");
    let dest_dir = f.tmp.path().join("dest");
    let entry = make_entry("1.15.0", "https://x", None);
    let cfg = StagedConfig::new(&dest_dir); // restrict_band = true
    let updater = CoreStagedUpdater::new(&f.dl, &f.fs, &f.store, cfg);

    let outcome = updater.apply(&entry, "1.14.0", "sing-box").unwrap();
    assert_eq!(outcome, ApplyOutcome::Deferred);
}

#[test]
fn apply_allows_cross_band_manual() {
    // 手动路径（restrict_band = false）允许跨带落位。
    let core = b"core-1.15.0";
    let (entry, f) = setup_no_hash("1.15.0", core);
    let dest_dir = f.tmp.path().join("dest");
    let cfg = StagedConfig::new(&dest_dir).allow_cross_band();
    let updater = CoreStagedUpdater::new(&f.dl, &f.fs, &f.store, cfg);

    let outcome = updater.apply(&entry, "1.14.0", "sing-box").unwrap();
    assert_eq!(outcome, ApplyOutcome::Applied);
}

#[test]
fn stage_then_try_apply_staged() {
    // 两步：先 stage（暂存），再 try_apply_staged（落位）。
    let core = b"core-1.14.2";
    let (entry, f) = setup("1.14.2", core);
    let dest_dir = f.tmp.path().join("dest");
    let staged_dir = f.tmp.path().join("staged");
    let cfg = StagedConfig::new(&dest_dir);
    let updater = CoreStagedUpdater::new(&f.dl, &f.fs, &f.store, cfg);

    // 1. 暂存。
    let outcome = updater
        .stage(
            &entry,
            "1.14.0",
            "sing-box",
            &staged_dir,
            "2026-07-15T00:00:00Z",
        )
        .unwrap();
    assert_eq!(outcome, ApplyOutcome::Applied);
    assert!(f.fs.exists(&staged_dir.join("sing-box")));
    assert!(f.store.load_staged().is_some());

    // 2. 落位（模拟代理已停——本方法不查代理态）。
    let outcome = updater.try_apply_staged("1.14.0", "sing-box").unwrap();
    assert_eq!(outcome, ApplyOutcome::Applied);
    assert_eq!(f.fs.read(&dest_dir.join("sing-box")).unwrap(), core);
    // staged 已清。
    assert!(f.store.load_staged().is_none());
    assert_eq!(f.store.last_applied_version(), Some("1.14.2".into()));
}

#[test]
fn try_apply_staged_noop_without_staged() {
    // 无 staged → Noop。
    let f = Fixture::with_entry("https://x", b"x");
    let dest_dir = f.tmp.path().join("dest");
    let cfg = StagedConfig::new(&dest_dir);
    let updater = CoreStagedUpdater::new(&f.dl, &f.fs, &f.store, cfg);

    let outcome = updater.try_apply_staged("1.14.0", "sing-box").unwrap();
    assert_eq!(outcome, ApplyOutcome::Noop);
}

#[test]
fn try_apply_staged_discards_when_not_newer() {
    // staged 版本已被 current 追上 → 作废（Discarded）。
    // 用同 minor 版本（1.13.14 vs 1.13.13）规避 restrict_band 硬闸，让 stage 真正暂存。
    let core = b"core-1.13.14";
    let (entry, f) = setup_no_hash("1.13.14", core);
    let dest_dir = f.tmp.path().join("dest");
    let staged_dir = f.tmp.path().join("staged");
    let cfg = StagedConfig::new(&dest_dir);
    let updater = CoreStagedUpdater::new(&f.dl, &f.fs, &f.store, cfg);

    // 先暂存 1.13.14（current=1.13.13 时算新，同带放行）。
    updater
        .stage(&entry, "1.13.13", "sing-box", &staged_dir, "t")
        .unwrap();
    assert!(f.store.load_staged().is_some());

    // 落位时 current 已升到 1.13.14 → staged 不再新 → 作废。
    let outcome = updater.try_apply_staged("1.13.14", "sing-box").unwrap();
    assert_eq!(outcome, ApplyOutcome::Discarded);
    assert!(f.store.load_staged().is_none());
    // dest_dir 未写（作废不落位）。
    assert!(!f.fs.exists(&dest_dir.join("sing-box")));
}

#[test]
fn memory_state_store_roundtrip() {
    let s = MemoryStateStore::new();
    assert!(s.load_staged().is_none());
    assert!(s.last_applied_version().is_none());

    let info = StagedInfo {
        version: "1.14.0".into(),
        dir: PathBuf::from("/tmp/staged"),
        staged_at: "2026-07-15T00:00:00Z".into(),
    };
    s.save_staged(&info).unwrap();
    assert_eq!(s.load_staged().unwrap(), info);

    s.record_applied("1.14.0").unwrap();
    assert_eq!(s.last_applied_version(), Some("1.14.0".into()));

    s.clear_staged().unwrap();
    assert!(s.load_staged().is_none());
}
