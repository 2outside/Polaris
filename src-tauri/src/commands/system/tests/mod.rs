use super::*;

#[test]
fn command_argv_is_selected_per_platform() {
    assert_eq!(
        macos_ps_command(),
        Command::new(
            "/usr/bin/env",
            [
                "LC_ALL=en_US.UTF-8",
                "LANG=en_US.UTF-8",
                "/bin/ps",
                "-axo",
                "comm=",
            ]
        )
    );
    assert_eq!(
        windows_tasklist_command(),
        Command::new("tasklist", ["/fo", "csv", "/nh"])
    );
}

// ── macOS/BSD：`ps -axo comm=` 单列 —— 含空格的进程名/路径不得被切碎（P1/P7）──

#[test]
fn comm_column_preserves_names_and_paths_with_spaces() {
    // captured `ps -axo comm=` 样本：含空格的全路径（Google Chrome Helper）、目录段含空格的
    // 绝对 macOS 路径、无路径含空格名（tmux: server）、同名多实例、无分隔符名（login）。
    // `=` 已抑制 COMM 表头 → 样本无表头行（P7）。
    let sample = "\
/Applications/Google Chrome.app/Contents/MacOS/Google Chrome Helper
/Applications/Google Chrome.app/Contents/MacOS/Google Chrome Helper
/Applications/Visual Studio Code.app/Contents/MacOS/Electron
tmux: server
login
";
    let got = parse_comm_column_output(sample);

    // 含空格全路径 → name = 完整 basename「Google Chrome Helper」，path = 整行全路径（不被空白切碎）。
    let helper = got
        .iter()
        .find(|p| p.name == "Google Chrome Helper")
        .expect("Google Chrome Helper 应保留完整 name");
    assert_eq!(helper.count, 2);
    assert_eq!(
        helper.path.as_deref(),
        Some("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome Helper")
    );

    // 目录段含空格的绝对路径 → basename 正确、path 完整。
    let electron = got.iter().find(|p| p.name == "Electron").expect("Electron");
    assert_eq!(
        electron.path.as_deref(),
        Some("/Applications/Visual Studio Code.app/Contents/MacOS/Electron")
    );

    // `tmux: server`（含空格、无分隔符）→ name 整体保留，不得切成 "tmux:"，无路径。
    let tmux = got
        .iter()
        .find(|p| p.name == "tmux: server")
        .expect("tmux: server 应整体保留");
    assert_eq!(tmux.path, None);

    // 确定性排序：count 降序 → Google Chrome Helper（2）居首。
    assert_eq!(got[0].name, "Google Chrome Helper");
}

// ── Linux：/proc 解析 —— exe 真实路径优先，无 15 字符 comm 截断、含空格 comm 不误切（P1/P4）──

#[test]
fn linux_resolve_prefers_exe_realpath_over_misleading_or_truncated_comm() {
    // Firefox 内容进程：comm 被改写成含空格的 "Web Content"（旧空白切分 → "Web"）；
    // exe 指向真实二进制 → name = "firefox"（sing-box 据此匹配），path = 全路径。
    let (name, path) = resolve_linux_process(
        Some("/usr/lib/firefox/firefox"),
        Some("Web Content"),
        Some("/usr/lib/firefox/firefox"),
    )
    .expect("exe 可读时应据 exe 解析");
    assert_eq!(name, "firefox");
    assert_eq!(path.as_deref(), Some("/usr/lib/firefox/firefox"));

    // comm 15 字符截断：chrome_crashpad_handler → comm 只剩 "chrome_crashpad"；exe 给出完整名。
    let (name, path) = resolve_linux_process(
        Some("/opt/google/chrome/chrome_crashpad_handler"),
        Some("chrome_crashpad"),
        None,
    )
    .expect("exe 可读");
    assert_eq!(
        name, "chrome_crashpad_handler",
        "exe basename 不得被 15 字符 comm 截断"
    );
    assert_eq!(
        path.as_deref(),
        Some("/opt/google/chrome/chrome_crashpad_handler")
    );

    // exe readlink 带 " (deleted)" 后缀（二进制已被替换）→ 剥离后取 basename。
    let (name, path) =
        resolve_linux_process(Some("/usr/bin/nginx (deleted)"), Some("nginx"), None).unwrap();
    assert_eq!(name, "nginx");
    assert_eq!(path.as_deref(), Some("/usr/bin/nginx"));
}

#[test]
fn linux_resolve_falls_back_to_comm_then_cmdline() {
    // 内核线程 / exe 不可读：无 exe，comm 存在 → name = comm（含斜杠原样保留），无路径。
    let (name, path) = resolve_linux_process(None, Some("kworker/0:1"), None).unwrap();
    assert_eq!(name, "kworker/0:1");
    assert_eq!(path, None);

    // exe、comm 都缺 → cmdline argv[0] 的 basename + 路径。
    let (name, path) = resolve_linux_process(None, None, Some("/usr/sbin/sshd")).unwrap();
    assert_eq!(name, "sshd");
    assert_eq!(path.as_deref(), Some("/usr/sbin/sshd"));

    // 全空 → None（跳过）。
    assert!(resolve_linux_process(None, None, None).is_none());
    assert!(resolve_linux_process(Some("  "), Some(""), Some("  ")).is_none());
}

#[test]
fn cmdline_argv0_takes_first_nul_delimited_token() {
    let dir = std::env::temp_dir().join(format!("polaris-cmdline-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("建临时目录");
    let f = dir.join("cmdline");
    // 真实 /proc/<pid>/cmdline：NUL 分隔 argv。argv0 = 完整路径，后续为参数。
    std::fs::write(&f, b"/usr/lib/firefox/firefox\0-contentproc\0-childID\0").unwrap();
    assert_eq!(
        read_cmdline_argv0(&f).as_deref(),
        Some("/usr/lib/firefox/firefox")
    );
    // 空 cmdline（内核线程）→ None。
    std::fs::write(&f, b"").unwrap();
    assert_eq!(read_cmdline_argv0(&f), None);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
#[cfg(target_os = "linux")]
fn linux_enumerate_returns_current_process() {
    // enumerate_linux_processes 是 Linux 专属（读 /proc）；非 Linux 编译期缺席，不做运行期假绿。
    let procs = enumerate_linux_processes().expect("读 /proc 应成功");
    assert!(!procs.is_empty(), "应至少枚举到本进程");
    assert!(procs.iter().all(|p| !p.name.is_empty()), "name 不得为空串");
}

#[test]
fn tasklist_csv_aggregates_and_has_no_path() {
    // captured `tasklist /fo csv /nh` 样本（CSV 无表头，内存字段含逗号——只取首字段不受影响）。
    let sample = "\
\"chrome.exe\",\"1234\",\"Console\",\"1\",\"123,456 K\"\r
\"chrome.exe\",\"1240\",\"Console\",\"1\",\"90,000 K\"\r
\"sing-box.exe\",\"555\",\"Services\",\"0\",\"20,000 K\"\r
";
    let got = parse_tasklist_output(sample);
    let chrome = got
        .iter()
        .find(|p| p.name == "chrome.exe")
        .expect("chrome.exe");
    assert_eq!(chrome.count, 2);
    assert_eq!(chrome.path, None, "tasklist 不提供路径");
    assert!(got.iter().any(|p| p.name == "sing-box.exe" && p.count == 1));
}

#[test]
fn empty_output_yields_empty_list() {
    assert!(parse_comm_column_output("").is_empty());
    assert!(parse_comm_column_output("\n   \n").is_empty());
    assert!(parse_tasklist_output("").is_empty());
}
