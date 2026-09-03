//! Windows 控制台窗口抑制的接线门。
//!
//! # 守的是什么
//!
//! 宿主是 GUI 子系统进程（`src-tauri/src/main.rs` 的 `windows_subsystem = "windows"`）⇒ 自身无控制台。
//! 无控制台的父进程起 **console 子系统**程序时，`CreateProcess` 会新分配一个控制台窗口（黑框）。
//! std 与 tokio 都**没有**隐含抑制 —— tokio 的 `creation_flags` 只是往 std 透传
//! （实测 tokio-1.53.1 `src/process/mod.rs:675-677`）。
//!
//! # 为什么必须是源码级门
//!
//! 这件事**在 Linux 上没有任何运行期表征**：`#[cfg(windows)]` 的分支根本不参与编译，
//! 纯函数单测测不到「有没有挂标志」，而唯一能观察到黑框的地方是 Windows 真机。
//! 三份现成教训都指向同一形状：`spawner.rs` 曾写着「tokio::process 在 Windows 默认不显示控制台窗口」
//! —— 一句**错误的注释**让这条缺陷在起核路径上潜伏了整个迁移期，没有任何门会红。
//!
//! # 与既有门的分工
//!
//! `core_build_matrix`（编了什么）/ `core_schema_surface`（配置形状与取值域）/ 起核 `check`（这份配置收不收）
//! 三道门都不看**进程怎么被创建**。本门只管这一格。

use std::collections::BTreeMap;

/// 仓库根（`src-tauri/` 的上一级）。
fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("src-tauri 必有上级目录")
        .to_path_buf()
}

fn read(rel: &str) -> String {
    let p = repo_root().join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("读不到 {}: {e}", p.display()))
}

/// 一个被守的调用点：锚点串之后的窗口内，必须同时出现 `Command::new(` 与抑制标记。
struct Guarded {
    file: &'static str,
    /// 唯一定位串。同名函数有多个 cfg 变体时**连 `#[cfg(...)]` 一起写**，否则锚点不唯一。
    anchor: &'static str,
    /// 抑制形态（可执行形，不是裸标识符）。
    suppressor: &'static str,
    /// 窗口自检串：窗口里必须先有它，否则说明窗口没盖住要守的东西 ⇒ 抑制断言恒真。
    /// 多数点是 `Command::new(`；`win_console.rs` 那两个函数**接收**已构造好的 `Command`，
    /// 它们自己不构造 ⇒ 自检改钉 cfg 门（抑制必须只在 Windows 生效，别在 Linux 上编不过）。
    self_check: &'static str,
    /// 从锚点起看多少行。各函数都远短于此；放宽只会让门更松，故取够用的最小值。
    ///
    /// 仅在 `before` 为 `None` 时生效。
    window: usize,
    /// `Some(forms)` = **判据不数行**：抑制标志必须早于 `forms` 里最早出现的那一处
    /// （= 早于进程真正被创建）。窗口就是「锚点 → 那一处」，宽度由源码结构给，不由人数行给。
    ///
    /// # 为什么要有这一格（行数窗口的失效方式与它守的属性无关）
    ///
    /// `spawner.rs` 的 spawn 方法体本来就要写清「这一路管道为什么这么开」，注释只会越来越长；
    /// [`strip_comments`] 只把 `//` 之后清空、**不删行**，注释照样占窗口。整改前那一条的 delta 是
    /// 23 / 窗口 30，余量 7 行、其中 6 行是注释 —— 下一个在方法开头补几句注释的人就会把门顶红，
    /// 而顶红的原因（「离锚点第 31 行」）与门要守的属性（「标志在进程创建之前设上」）毫无关系。
    /// 更糟的另一头：真把 `creation_flags` 挪到 `.spawn()` 之后（Windows 上照样弹黑窗），
    /// 只要它还落在 30 行内，行数窗口是**绿**的。
    ///
    /// `Command` 的构建器调用顺序对 `creation_flags` 语义无关紧要，唯一要紧的是它在 `spawn()`
    /// 之前 —— 那才是这道门真正要守的东西，所以判据就写成它。
    before: Option<&'static [&'static str]>,
}

/// 「进程在这里被真正创建」的形态。`.stdout(` 也算：它之后的构建器调用与标志的先后已经无从分辨，
/// 而把判据钉在**最早**的那一处（而不是只钉 `.spawn()`）会让窗口更窄、判据更严。
const CREATION_FORMS: &[&str] = &[".stdout(", ".spawn()"];

/// 全部「Windows 可达 + 目标是 console 程序」的子进程构造点。
///
/// **不在表里 = 声称该调用点在 Windows 上不可达**。目前的豁免全部有 cfg 佐证：
/// `/bin/ps`（macos/linux 腿）、`pgrep`（`cfg(unix)`）、`route -n monitor`（仅 mac 守卫会调，
/// 见 `dns_watcher_loop` 文档）、`mesh.rs::run_command_stdout`（mac `ifconfig` 反查）、
/// `uninstall.rs::spawn_uninstaller`（拉起的是 Windows 卸载程序**自己的 GUI**，抑制窗口反而不对）。
const GUARDED: &[Guarded] = &[
    // ---- 本 crate：经 runtime/win_console.rs 收口 ----
    Guarded {
        file: "src-tauri/src/runtime/win_console.rs",
        anchor: "pub(crate) fn no_console_window(",
        suppressor: "creation_flags(0x0800_0000)",
        self_check: "#[cfg(windows)]",
        window: 14,
        before: None,
    },
    // `no_console_window_async`（tokio 版）已随它仅有的两个调用点一起删除：那两处是自己写了一遍的
    // `sing-box check`，已折叠进 `core-supervisor::config_gate::run_check_raw`（本表下方单独守）。
    // 本 crate 于是不再有 Windows 可达的 tokio 子进程构造点。
    // Phase 2 拆分：两点随 `send_signal` / `core_version_first_line` 进
    // `proxy/process_supervision.rs`（façade 仍 `pub(crate) use` 再导出 `send_signal`，
    // 但**构造点**在这里，源码级门取的是构造点）。
    Guarded {
        file: "src-tauri/src/runtime/proxy/process_supervision.rs",
        anchor: "fn core_version_first_line(",
        suppressor: "no_console_window(",
        self_check: "Command::new(",
        window: 6,
        before: None,
    },
    Guarded {
        file: "src-tauri/src/runtime/proxy/process_supervision.rs",
        anchor: "#[cfg(windows)]\npub(crate) fn send_signal(",
        suppressor: "no_console_window(",
        self_check: "Command::new(",
        window: 8,
        before: None,
    },
    Guarded {
        file: "src-tauri/src/runtime/updater.rs",
        anchor: "pub fn read_core_version_line(",
        suppressor: "no_console_window(",
        self_check: "Command::new(",
        window: 10,
        before: None,
    },
    Guarded {
        file: "src-tauri/src/runtime/core_swap.rs",
        anchor: "pub fn extract_archive(",
        suppressor: "no_console_window(",
        self_check: "Command::new(",
        window: 20,
        before: None,
    },
    // 这里曾有两条 `sing-box check` 的构造点（`tailscale_login_core.rs::SingBoxConfigChecker` 与
    // `commands/proxy.rs::run_probe_check`）。两处已不再自己构造子进程，改调
    // `core-supervisor::config_gate::run_check_raw`（本表下方那条守着它的 `creation_flags`），
    // 故条目随构造点一起消失。**替代判据见
    // [`only_one_production_site_spawns_sing_box_check`]**：本表是手写清单，
    // [`no_new_console_program_spawn_escapes_the_suppression`] 只按程序名字面量反查，`sing-box`
    // 的路径是变量、两者都盖不住「有人在这两个文件里重新写一份 check」。那条新门把「这两处挂了
    // 抑制标志」换成了更强的「全仓只允许有一处 check 构造点」。
    // ---- 另外三个 crate：与本 crate 无共同依赖，各自持等价实现 ----
    Guarded {
        file: "crates/system-integration/src/exec.rs",
        anchor: "impl CommandRunner for StdCommandRunner {",
        suppressor: "creation_flags(CREATE_NO_WINDOW)",
        self_check: "Command::new(",
        window: 20,
        before: None,
    },
    Guarded {
        file: "crates/core-supervisor/src/spawner.rs",
        anchor: "impl SingBoxSpawner for TokioSpawner {",
        suppressor: "creation_flags(0x0800_0000)",
        self_check: "Command::new(",
        // 这一条**不数行**（见 `Guarded::before`）：本方法体是全仓最会长注释的地方（三条核腿共用
        // 的起核入口），行数窗口的余量迟早被注释吃光，而顶红的原因与门守的属性无关。
        window: 0,
        before: Some(CREATION_FORMS),
    },
    Guarded {
        file: "crates/core-supervisor/src/config_gate.rs",
        anchor: "pub async fn run_check_raw(",
        suppressor: "creation_flags(0x0800_0000)",
        self_check: "Command::new(",
        window: 30,
        before: None,
    },
    Guarded {
        file: "crates/helper-client/src/manager.rs",
        anchor: "fn sc_command(",
        suppressor: "creation_flags(0x0800_0000)",
        self_check: "Command::new(",
        window: 8,
        before: None,
    },
    Guarded {
        file: "crates/helper-client/src/privilege.rs",
        anchor: "impl Executor for StdExecutor {",
        suppressor: "creation_flags(0x0800_0000)",
        self_check: "Command::new(",
        window: 18,
        before: None,
    },
];

/// 去掉行注释（`//` 之后）—— 判据必须落在**可执行形态**上。
///
/// 本文件自己的模块头就反复写着 `creation_flags` 与 `CREATE_NO_WINDOW`，被守文件的文档注释同理；
/// 不剥注释的话，把生产调用整个删掉、注释留下，门照样绿（本仓 2026-08-07 起同型撞过四次）。
fn strip_comments(src: &str) -> String {
    src.lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn every_windows_reachable_spawn_suppresses_the_console() {
    let mut sources: BTreeMap<&str, String> = BTreeMap::new();
    for g in GUARDED {
        let src = sources
            .entry(g.file)
            .or_insert_with(|| strip_comments(&read(g.file)));
        let at = src.find(g.anchor).unwrap_or_else(|| {
            panic!(
                "{}：锚点 `{}` 消失（改名/删除？）——门已失去判据，不是「通过」",
                g.file, g.anchor
            )
        });
        assert!(
            src[at + g.anchor.len()..].find(g.anchor).is_none(),
            "{}：锚点 `{}` 不唯一，窗口可能落在另一个 cfg 变体上",
            g.file,
            g.anchor
        );
        let rest = &src[at..];
        // 窗口两种取法：数行（`before: None`），或者取到「进程真被创建」那一处为止。
        // 后者的宽度由源码结构给 —— 它守的属性就是「标志早于创建」，判据于是与行数无关。
        let (window, scope) = match g.before {
            None => (
                rest.lines().take(g.window).collect::<Vec<_>>().join("\n"),
                format!("之后 {} 行内", g.window),
            ),
            Some(forms) => {
                let creation = forms.iter().filter_map(|f| rest.find(f)).min();
                // 切点自检：找不到创建点 = 锚点漂了 / 构造搬走了 ⇒ 窗口无从界定，必须红。
                // 没有这一条，`min()` 为 `None` 时无论怎么退化都是一次静默失效。
                let creation = creation.unwrap_or_else(|| {
                    panic!(
                        "{}：`{}` 之后找不到 {forms:?} 里的任何一处 —— \
                         这个块里没有子进程被创建（锚点漂了 / 构造搬走了），窗口无从界定，\
                         抑制断言在这种状态下恒真",
                        g.file, g.anchor
                    )
                });
                (
                    rest[..creation].to_owned(),
                    format!("与首个 {forms:?} 之间"),
                )
            }
        };
        // 自检：窗口里必须真有子进程构造，否则说明窗口太小 / 锚点漂了，下面那条断言就没有意义。
        assert!(
            window.contains(g.self_check),
            "{}：`{}` {scope}没有 `{}` —— 窗口没盖住要守的东西，抑制断言恒真",
            g.file,
            g.anchor,
            g.self_check
        );
        assert!(
            window.contains(g.suppressor),
            "{}：`{}` 的子进程构造没挂 `{}`（{scope}）—— Windows 上会弹控制台窗口。\
             `before` 形态下这句话的意思是：标志要么没了，要么被挪到了进程创建**之后** —— \
             那时候再设已经不起作用",
            g.file,
            g.anchor,
            g.suppressor
        );
    }
}

/// 已知会在 Windows 上执行的 console 程序名（字面量形态）。按**程序名反查**，与上面的清单互补：
/// 清单防「已守的被删」，本条防「新增一个 console 程序调用却忘了挂标志」。
const CONSOLE_PROGRAMS: &[&str] = &[
    "\"tasklist\"",
    "\"taskkill\"",
    "\"sc\"",
    "\"netsh\"",
    "\"reg\"",
];

/// 允许出现裸调用的位置（测试夹具 / 纯字符串常量表）。
fn is_scannable(rel: &str) -> bool {
    rel.ends_with(".rs") && !rel.contains("/tests/") && !rel.contains("target/")
}

#[test]
fn no_new_console_program_spawn_escapes_the_suppression() {
    let root = repo_root();
    let mut offenders = Vec::new();
    let mut scanned = 0usize;
    let mut hits = 0usize;
    let mut sighted: Vec<String> = Vec::new();
    for dir in ["src-tauri/src", "crates"] {
        for entry in walk(&root.join(dir)) {
            let rel = entry
                .strip_prefix(&root)
                .unwrap_or(&entry)
                .to_string_lossy()
                .replace('\\', "/");
            if !is_scannable(&rel) {
                continue;
            }
            // helper 是 Windows **服务**（session 0，无交互桌面）⇒ 它起的子进程本就无窗口可弹，
            // 且那边已自带 `CREATE_NO_WINDOW`（`winproc/win.rs:296`）。不纳入本门射程。
            if rel.starts_with("crates/helper/") {
                continue;
            }
            let raw = std::fs::read_to_string(&entry).unwrap_or_default();
            scanned += 1;
            // **不切 `#[cfg(test)]`**：`proxy.rs` 里生产码与测试模块交替出现（实测顶层 5 处），
            // 切第一处会把后面全部真调用点一起丢掉 —— 实测本门第一版就是这么静默漏掉 4 处的。
            // 测试夹具起的是 `powershell` / `sleep`，都不在 [`CONSOLE_PROGRAMS`] 里，故无需切。
            let prod = strip_comments(&raw);
            for (i, line) in prod.lines().enumerate() {
                // 只认 `process::Command::new(`（std / tokio 都带这个前缀）。
                // `polaris_system_integration::exec::Command::new(program, args)` 是两参数的**命令描述**，
                // 真正的 spawn 在 `StdCommandRunner::run` 里、已在 GUARDED 表中单独守着。
                if !line.contains("process::Command::new(") {
                    continue;
                }
                if !CONSOLE_PROGRAMS.iter().any(|p| line.contains(p)) {
                    continue;
                }
                hits += 1;
                sighted.push(format!("{rel}: {}", line.trim()));
                let lo = i.saturating_sub(6);
                let ctx: String = prod
                    .lines()
                    .skip(lo)
                    .take(i - lo + 14)
                    .collect::<Vec<_>>()
                    .join("\n");
                let guarded = ctx.contains("no_console_window")
                    || ctx.contains("creation_flags")
                    || ctx.contains("sc_command(");
                if !guarded {
                    offenders.push(format!("{rel}:{}: {}", i + 1, line.trim()));
                }
            }
        }
    }
    assert!(
        scanned > 50,
        "只扫到 {scanned} 个文件 —— 遍历坏了，绿没有信息量"
    );
    // 具名自检比数量更有信息量：锁住两个仍真实存在、来自不同 crate 的 console 调用点，
    // 防遍历/匹配坏掉后「零命中也绿」。旧 1Hz `tasklist` 探活已改为 Win32 原生 API，
    // 不再把性能问题本身当成本门必须存在的自检锚点。
    for (file, program) in [
        (
            "src-tauri/src/runtime/proxy/process_supervision.rs",
            "\"taskkill\"",
        ),
        ("crates/helper-client/src/manager.rs", "\"sc\""),
    ] {
        assert!(
            sighted
                .iter()
                .any(|s| s.starts_with(file) && s.contains(program)),
            "扫描面里没有 `{file}` 的 {program} 调用——遍历或匹配坏了。实际命中 {hits} 处：\n{}",
            sighted.join("\n")
        );
    }
    assert!(
        offenders.is_empty(),
        "以下 console 程序调用点没有窗口抑制（Windows 上会弹黑框）：\n{}",
        offenders.join("\n")
    );
}

/// 全仓生产码里 `sing-box check` 只允许有**一处**子进程构造点。
///
/// # 这条门补的是哪个缝
///
/// [`GUARDED`] 曾用两条登记守着 `tailscale_login_core.rs::SingBoxConfigChecker` 与
/// `commands/proxy.rs::run_probe_check` 的 `CREATE_NO_WINDOW`。两处折叠进
/// `core-supervisor::config_gate::run_check_raw` 之后，那两条登记失去对象、必须删掉 —— 而删掉之后
/// 这两个文件就**不在任何判据的射程里**了：`GUARDED` 是手写清单（只守写进去的东西），
/// [`no_new_console_program_spawn_escapes_the_suppression`] 按**程序名字面量**反查
/// （`tasklist` / `sc` / `netsh`…），而 sing-box 的路径是个变量。于是「有人在这两个文件里重新写一份
/// `Command::new(binary).arg("check")`」既不会被清单抓到，也不会被字面量扫描抓到。
///
/// 本门把那两条登记换成一条**更强**的：不是「这两处挂了抑制标志」，而是「全仓只允许存在一处
/// check 构造点」。第四份一出现就红，且它红的时候要求的是折叠回去，而不是补一个抑制标志 ——
/// 后者只治黑框，治不了那份新拷贝必然又漏掉的超时与 `kill_on_drop`。
///
/// # 判据形态
///
/// 针是 argv 里的字面量 `"check"`（含引号），比 `.arg("check")` 宽：`.args(["check", …])` 之类的
/// 写法同样落网。取材面先过 [`strip_comments`]，否则被守文件的文档注释里那些讲 `check` 的句子会
/// 让本门恒红。正向对照是「必须恰好命中一次」：命中 0 次说明针或遍历坏了，那种绿没有信息量。
#[test]
fn only_one_production_site_spawns_sing_box_check() {
    /// argv 里的子命令字面量（含引号）。
    const CHECK_ARG: &str = "\"check\"";
    /// 允许持有它的唯一文件。
    const HOME: &str = "crates/core-supervisor/src/config_gate.rs";

    let root = repo_root();
    let mut sites: Vec<String> = Vec::new();
    let mut scanned = 0usize;
    for dir in ["src-tauri/src", "crates"] {
        for entry in walk(&root.join(dir)) {
            let rel = entry
                .strip_prefix(&root)
                .unwrap_or(&entry)
                .to_string_lossy()
                .replace('\\', "/");
            if !is_scannable(&rel) {
                continue;
            }
            scanned += 1;
            let prod = strip_comments(&std::fs::read_to_string(&entry).unwrap_or_default());
            for (i, line) in prod.lines().enumerate() {
                if line.contains(CHECK_ARG) {
                    sites.push(format!("{rel}:{}: {}", i + 1, line.trim()));
                }
            }
        }
    }
    assert!(
        scanned > 50,
        "只扫到 {scanned} 个文件 —— 遍历坏了，绿没有信息量"
    );
    assert_eq!(
        sites.len(),
        1,
        "`sing-box check` 的构造点必须恰好一处（在 `{HOME}`）。\
         为 0 = 针或遍历坏了，本门的绿没有信息量；>1 = 又出现了一份各自漂的拷贝，\
         而每一份拷贝都得自己记得超时与 `kill_on_drop` —— 折叠之前的三份里就有两份没记住。\
         实际命中：\n{}",
        sites.join("\n")
    );
    assert!(
        sites[0].starts_with(HOME),
        "唯一的 `sing-box check` 构造点跑到了 `{}`，而它应该在 `{HOME}`",
        sites[0]
    );
}

/// 四份实现散在四个无共同依赖的 crate 里 —— 值必须逐字一致，否则「改了一处以为全改了」。
#[test]
fn the_four_crates_agree_on_the_flag_value() {
    let bearers = [
        "src-tauri/src/runtime/win_console.rs",
        "crates/system-integration/src/exec.rs",
        "crates/core-supervisor/src/spawner.rs",
        "crates/helper-client/src/manager.rs",
    ];
    for f in bearers {
        let src = strip_comments(&read(f));
        assert!(
            src.contains("0x0800_0000"),
            "{f}：`CREATE_NO_WINDOW` 的值不见了（或被写成了别的字面形态）"
        );
    }
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}
