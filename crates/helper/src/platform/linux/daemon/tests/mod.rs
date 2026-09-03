use super::*;
use std::path::PathBuf;

fn argv(args: &[&str]) -> std::vec::IntoIter<String> {
    let mut v = vec!["polaris-helper".to_owned()];
    v.extend(args.iter().map(|s| (*s).to_owned()));
    v.into_iter()
}

#[test]
fn parse_args_defaults_match_ops_contract() {
    // 缺 flag → 运维契约默认路径（systemd unit / pkexec 安装器依赖）。
    let cfg = parse_args(argv(&[]));
    assert_eq!(cfg.sock_path, PathBuf::from(DEFAULT_SOCK_PATH));
    assert_eq!(cfg.auth_file, PathBuf::from(DEFAULT_AUTH_FILE));
    assert_eq!(cfg.core_dir, Some(PathBuf::from(DEFAULT_CORE_DIR)));
    assert!(!cfg.console);
}

#[test]
fn parse_args_all_flags_override() {
    let cfg = parse_args(argv(&[
        "--socket",
        "/tmp/x.sock",
        "--authfile",
        "/tmp/uids",
        "--coredir",
        "/tmp/core",
        "--console",
    ]));
    assert_eq!(cfg.sock_path, PathBuf::from("/tmp/x.sock"));
    assert_eq!(cfg.auth_file, PathBuf::from("/tmp/uids"));
    assert_eq!(cfg.core_dir, Some(PathBuf::from("/tmp/core")));
    assert!(cfg.console);
}

#[test]
fn parse_args_console_is_bool_not_value() {
    // --console 不吞下一 token。
    let cfg = parse_args(argv(&["--console", "--socket", "/s.sock"]));
    assert!(cfg.console);
    assert_eq!(cfg.sock_path, PathBuf::from("/s.sock"));
}

// ===== accept 错误处置的接线（复审 Medium，daemon.rs:144 一律 continue）=====

/// `async_main` 是 socket + 信号 + runtime 的编排（要真起 daemon 才跑得到），分类/退避/限频三件
/// 已由 [`crate::platform::accept_retry`] 的单测钉住；这里守的是**接线**：那三件真的被 accept
/// 错误腿消费了，而不是「模块写好了没人调」。
#[test]
fn accept_error_leg_classifies_backs_off_and_logs() {
    let src = polaris_source_probe::crate_source!("platform/linux/daemon.rs");
    // 取材自检①：拿到的确实是本文件。
    assert!(
        src.contains("async fn async_main("),
        "取材面错位：拿到的不是 linux/daemon.rs"
    );
    // 取材自检（原②：本文件无块注释 ⇒ 行注释剥离已足够）已删：那道前置自证只在剥离实现只认
    // 行注释（旧的本地 strip_line_comments，朴素 split("//")）时才需要 —— 块注释一出现，它就必须
    // 转红提醒升级剥离逻辑。现改用共享的 `mask_comments`（词法级剥注释，块注释同样处理），
    // 该前提不再成立，判据由共享实现的文档持有。
    let code = polaris_source_probe::mask_comments(&src);
    // 取材自检②：剥离没把生产代码一并吃掉；③：切点唯一。
    assert!(code.contains("listener.accept()"), "剥离后丢失 accept 锚点");
    assert_eq!(code.matches("async fn async_main(").count(), 1);

    let body = code
        .split("async fn async_main(")
        .nth(1)
        .expect("async_main 函数体");
    // 判据自检：窗口确实盖住了 accept 循环。
    assert!(body.contains("tokio::select!"), "窗口没盖住 accept 循环");

    for required in [
        // 分类而非一律 continue
        "classify_accept_error(&e)",
        "AcceptAction::Backoff",
        // 真的退避（持续态忙转的唯一解药）
        "tokio::time::sleep(ACCEPT_BACKOFF).await",
        // 自曝，且限频
        "accept_log.allow()",
        "eprintln!",
    ] {
        assert!(body.contains(required), "accept 错误腿缺锚点: {required}");
    }

    // 反向对照：不得再有「拿不到分类就 continue」的裸腿。
    assert!(
        !body.contains("Err(_) => continue"),
        "accept 错误仍有一条不分类的裸 continue"
    );
}
