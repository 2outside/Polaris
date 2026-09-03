use super::*;
use std::io::Cursor;
use std::time::{Duration, Instant};

fn wait_for(path: &Path, expected: &[u8]) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if std::fs::read(path).is_ok_and(|bytes| bytes == expected) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        std::thread::yield_now();
    }
}

#[test]
fn anchored_files_ignore_parent_rename_and_replacement() {
    let root = tempfile::tempdir().unwrap();
    // macOS 的临时目录通常经 `/var`（指向 `/private/var` 的系统符号链接）暴露；生产安全
    // 打开故意逐段 O_NOFOLLOW，因此测试从临时目录的真实锚点起步，避免把系统别名误当攻击路径。
    let root_path = root.path().canonicalize().unwrap();
    let conf = root_path.join("conf");
    std::fs::create_dir(&conf).unwrap();
    let log = conf.join("startup.log");
    std::fs::write(&log, b"old").unwrap();
    let files = preopen_log_files(conf.to_str().unwrap(), log.to_str().unwrap()).unwrap();

    let pinned = root_path.join("pinned");
    std::fs::rename(&conf, &pinned).unwrap();
    std::fs::create_dir(&conf).unwrap();
    let replacement = conf.join("startup.log");
    std::fs::write(&replacement, b"replacement").unwrap();
    std::fs::write(conf.join("startup.log.1"), b"replacement-old").unwrap();

    polaris_log_budget::spawn_pipe_loggers_with_preopened_files(
        Some(Cursor::new(b"new")),
        None::<Cursor<&[u8]>>,
        files,
        32,
    );
    wait_for(&pinned.join("startup.log"), b"new");
    assert_eq!(std::fs::read(&replacement).unwrap(), b"replacement");
    assert_eq!(
        std::fs::read(conf.join("startup.log.1")).unwrap(),
        b"replacement-old"
    );
}

#[test]
fn parent_symlink_and_final_symlink_are_rejected_without_touching_targets() {
    let root = tempfile::tempdir().unwrap();
    let real = root.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let linked = root.path().join("linked");
    std::os::unix::fs::symlink(&real, &linked).unwrap();
    assert!(preopen_log_files(
        linked.to_str().unwrap(),
        linked.join("startup.log").to_str().unwrap()
    )
    .is_err());

    let victim = root.path().join("victim");
    std::fs::write(&victim, b"must-not-change").unwrap();
    std::os::unix::fs::symlink(&victim, real.join("startup.log")).unwrap();
    assert!(preopen_log_files(
        real.to_str().unwrap(),
        real.join("startup.log").to_str().unwrap()
    )
    .is_err());
    assert_eq!(std::fs::read(victim).unwrap(), b"must-not-change");
}
