use super::*;

#[test]
fn memory_download_hit_and_miss() {
    let dl = MemoryDownload::new().with("https://a/rel", vec![1, 2, 3]);
    assert_eq!(dl.download("https://a/rel").unwrap(), vec![1, 2, 3]);
    let err = dl.download("https://missing").unwrap_err();
    assert!(matches!(err, DownloadError::Other(_)));
}

#[test]
fn unavailable_downloader_reports_backend_unavailable_not_generic_failure() {
    // 反伪造 + §K7.1：这个占位**必须**用专用变体报「没有后端」，而不是泛化的 Other(...)。
    // 若折叠进 Other，上层会把「HTTP 栈根本没接」当成一次可重试的网络失败 → 无限重试永不成功的调用。
    let dl = UnavailableDownloader::new();
    let err = dl.download("https://anywhere").unwrap_err();
    assert!(
        matches!(err, DownloadError::BackendUnavailable(_)),
        "占位下载器必须报 BackendUnavailable（可映射 HTTP_BACKEND_UNAVAILABLE），实得: {err:?}"
    );
    assert_eq!(UnavailableDownloader::CODE, "HTTP_BACKEND_UNAVAILABLE");
}

#[test]
fn backend_unavailable_is_distinguishable_from_retryable_failures() {
    // 钉住语义边界：BackendUnavailable（不可重试，需接线）vs 其余（试过了、可重试）。
    let unavailable = DownloadError::BackendUnavailable("no tls".into());
    let retryable = [
        DownloadError::HttpStatus(403),
        DownloadError::Stalled(30_000),
        DownloadError::Other("mirror exhausted".into()),
    ];
    assert!(matches!(unavailable, DownloadError::BackendUnavailable(_)));
    for e in retryable {
        assert!(
            !matches!(e, DownloadError::BackendUnavailable(_)),
            "可重试失败不得被当成「后端未接线」: {e:?}"
        );
    }
}

#[test]
fn std_fs_roundtrip() {
    let tmpdir = tempfile::tempdir().unwrap();
    let fs = StdFs;
    let root = tmpdir.path();
    let p = fs.join(root, "core.bin");
    fs.write(&p, b"hello").unwrap();
    assert!(fs.exists(&p));
    assert_eq!(fs.read(&p).unwrap(), b"hello");
    fs.rename(&p, &fs.join(root, "moved.bin")).unwrap();
    assert!(!fs.exists(&p));
    assert!(fs.exists(&fs.join(root, "moved.bin")));
    fs.remove_file(&fs.join(root, "moved.bin")).unwrap();
    // 二次 remove 不存在 → no-op（对齐 上游 `if exists` 语义）。
    fs.remove_file(&fs.join(root, "moved.bin")).unwrap();
}

/// 写句柄与 `write` 的落盘结果必须一致（覆盖语义、分片无关）。
///
/// 这条是流式下载腿的地基：句柄写出来的文件与整包 `write` 出来的不是同一个东西，
/// 后面的 sha256 校验就会在真机大包上莫名其妙地不过。
#[test]
fn open_write_handle_matches_whole_buffer_write() {
    use std::io::Write as _;

    let tmpdir = tempfile::tempdir().unwrap();
    let fs = StdFs;
    let streamed = fs.join(tmpdir.path(), "streamed.bin");
    let whole = fs.join(tmpdir.path(), "whole.bin");

    // 先放一份旧内容：句柄必须**截断**，不是追加。
    fs.write(&streamed, b"XXXXXXXXXXXXXXXXXXXXXXXX").unwrap();
    {
        let mut h = fs.open_write(&streamed).unwrap();
        h.write_all(b"chunk-1").unwrap();
        h.write_all(b"chunk-2").unwrap();
        h.flush().unwrap();
    }
    fs.write(&whole, b"chunk-1chunk-2").unwrap();
    assert_eq!(fs.read(&streamed).unwrap(), fs.read(&whole).unwrap());
}

/// MockFs 的 `Write` 注入必须同时管住 `write` 与 `open_write`。
///
/// 只管一个的话，「落盘失败」的清理路径在流式腿上就没有测试杠杆可用。
#[test]
fn mock_fs_write_injection_also_covers_open_write() {
    let tmpdir = tempfile::tempdir().unwrap();
    let mut fs = MockFs::new(tmpdir.path());
    fs.fail_next(MockFailOp::Write);
    // `Box<dyn Write + Send>` 无 Debug ⇒ 不能用 `unwrap_err()`。
    let Err(err) = fs.open_write(Path::new("blocked.bin")) else {
        panic!("注入 Write 失败后 open_write 必须报错");
    };
    assert!(err.to_string().contains("Write"));
    assert!(
        !tmpdir.path().join("blocked.bin").exists(),
        "注入失败时不得留下空文件"
    );
}

#[test]
fn std_fs_list_files_skips_dirs() {
    let tmpdir = tempfile::tempdir().unwrap();
    let fs = StdFs;
    let root = tmpdir.path();
    fs.write(&fs.join(root, "sing-box"), b"bin").unwrap();
    fs.write(&fs.join(root, "libcronet.so"), b"lib").unwrap();
    fs.create_dir_all(&fs.join(root, "subdir")).unwrap();
    let files = fs.list_files(root).unwrap();
    // 排序后 = [libcronet.so, sing-box]，不含 subdir。
    assert_eq!(
        files,
        vec!["libcronet.so".to_string(), "sing-box".to_string()]
    );
}

#[test]
fn mock_fs_sandbox_resolve_and_fail_injection() {
    // MockFs 沙箱 + 失败注入：覆盖 staged 错误恢复路径所需的 mock FS 能力。
    let tmpdir = tempfile::tempdir().unwrap();
    let root = tmpdir.path();
    let mut fs = MockFs::new(root);
    // 正常写入（沙箱内）。
    fs.write(&fs.join(Path::new(""), "core.bin"), b"data")
        .unwrap();
    assert!(fs.exists(&fs.join(Path::new(""), "core.bin")));
    assert_eq!(
        fs.read(&fs.join(Path::new(""), "core.bin")).unwrap(),
        b"data"
    );

    // 注入 Write 永久失败 → 后续 write 报错。
    fs.fail_next(MockFailOp::Write);
    let err = fs
        .write(&fs.join(Path::new(""), "other.bin"), b"x")
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Other);
    assert!(err.to_string().contains("Write"));

    // 注入 Rename 失败。
    fs.fail_next(MockFailOp::Rename);
    let err = fs
        .rename(
            &fs.join(Path::new(""), "core.bin"),
            &fs.join(Path::new(""), "moved.bin"),
        )
        .unwrap_err();
    assert!(err.to_string().contains("Rename"));
}
