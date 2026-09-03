//! `#[ignore]` 的登记与棘轮 —— 默认不跑的测试不许悄悄变多、也不许悄悄变哑。
//!
//! # 守的是什么
//!
//! `#[ignore]` 是**把一条真测试变哑的最低成本手段**：加一行属性，全仓仍绿，报告里只多一个
//! `ignored`。这条路在本仓已经被实测走通过一次并记在案 ——
//! `crates/updater/src/popup.rs:229`：「两道都得在，删任一条缺陷都能静默复活
//! （实测：把源码门 `#[ignore]` 掉 ⇒ 全仓仍绿）」。**记下来了，但当时没落成门。这里补上。**
//!
//! 判据四条，缺一条这个后门就还开着：
//!
//! 1. **理由必须非空**。裸 `#[ignore]` 在报告里只有三个字，读者无从判断它该不该在。
//! 2. **逐条登记**（[`REGISTRY`]），每条**恰好命中一次**：命中 0 次 = 条目过期（它守的测试
//!    改名/删了，条目成了下一个真违规的免死金牌）；源码里有而表里没有 = 新增未登记。
//! 3. **类别受控**（[`Class`]），且**理由串必须与类别自洽**（见 [`Class::reason_must_mention`]）
//!    —— 否则类别只是装饰，随手写个理由就能把测试塞进任意类别。
//! 4. **跑法必须指得到真文档**：`docs/ignored-tests.md` 必须存在，且**逐个测试名**在里面能找到
//!    对应的执行段落。这治的是本门建立时发现的那个硬伤 —— 全仓 `grep -- --ignored` 零命中、
//!    `POLARIS_SINGBOX_PATH` 零命中：12 条真核测试写好了、编得过、**一次都没被执行过**。
//!
//! # 为什么数源码而不是数报告
//!
//! `cargo test` 报告里的 ignored 数**是平台相关的**：Linux 15 / Windows 16 / macOS 17
//! （平台专属的那几条在别的平台上被 cfg 掉、根本不编译）。写死任何一个数字都会在别的 CI 腿上假红。
//! 源码里的 `#[ignore]` 总数是平台无关的事实，本门数它。
//!
//! # 取材面
//!
//! 全部 workspace 成员的 `src/` 与 `tests/`（**含 `tests/` 目录** —— `#[ignore]` 本来就住在测试里）。
//! 定位走[净化面][polaris_source_probe::mask_comments_and_strings]（本仓多处**注释里**写着
//! `#[ignore]`，不剥会把它们当成命中），取理由串回**原文**（理由本身就是字符串字面量，
//! 在净化面里已被抹空）。

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

// ============================================================================
// 登记表
// ============================================================================

/// 默认不跑的原因分类。**不许自造**：新形态必须先在这里加一个变体并说明它为什么不是已有的四类。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Class {
    /// 需要真实 sing-box 二进制（`POLARIS_SINGBOX_PATH`），会真起进程、真占端口。
    RealCore,
    /// 需要公网连通性。本仓默认门禁止碰网络。
    PublicNetwork,
    /// 读或**改写宿主机真实状态**（路由表 / 系统代理）。跑错机器会改掉开发机网络配置。
    LiveHostState,
    /// 根本不是测试，是打印工具。用 `#[ignore]` 只为不进默认门。
    NotAGate,
}

impl Class {
    /// 理由串里**必须**出现的字样 —— 类别与理由不自洽时红。
    ///
    /// 没有这一条，`Class` 就只是登记表里的一个装饰字段：随手写个理由，就能把一条真核测试
    /// 登记成 `NotAGate` 而门毫无察觉。
    fn reason_must_mention(self) -> &'static [&'static str] {
        match self {
            Class::RealCore => &["POLARIS_SINGBOX_PATH"],
            Class::PublicNetwork => &["公网"],
            Class::LiveHostState => &["route", "proxy"],
            Class::NotAGate => &["非门"],
        }
    }

    fn name(self) -> &'static str {
        match self {
            Class::RealCore => "RealCore",
            Class::PublicNetwork => "PublicNetwork",
            Class::LiveHostState => "LiveHostState",
            Class::NotAGate => "NotAGate",
        }
    }
}

/// 一条登记。
struct Entry {
    /// 仓库相对路径（`/` 分隔）。
    file: &'static str,
    /// `#[ignore]` 紧跟的那个测试函数名。
    test: &'static str,
    class: Class,
}

/// 全部默认不跑的测试。**新增一处 `#[ignore]` 必须同时在这里加一行**，否则本门红。
///
/// 平台专属的那三条也在表里 —— 本门数源码，与当前编译目标无关。
const REGISTRY: &[Entry] = &[
    // ── RealCore：需要真实 sing-box ──
    Entry {
        file: "src-tauri/src/runtime/proxy/tests/lifecycle.rs",
        test: "real_core_full_lifecycle",
        class: Class::RealCore,
    },
    Entry {
        file: "src-tauri/src/runtime/proxy/tests/lifecycle.rs",
        test: "real_core_lifecycle_race_start_then_immediate_stop",
        class: Class::RealCore,
    },
    Entry {
        file: "src-tauri/src/runtime/proxy/tests/hot_switch.rs",
        test: "real_core_hot_switch_keeps_pid",
        class: Class::RealCore,
    },
    Entry {
        file: "src-tauri/src/runtime/proxy/tests/hot_switch.rs",
        test: "real_core_auto_failover_attests_without_applying_saved_debt",
        class: Class::RealCore,
    },
    Entry {
        file: "src-tauri/src/runtime/proxy/tests/hot_switch.rs",
        test: "real_core_hot_switch_failure_falls_back_to_restart",
        class: Class::RealCore,
    },
    Entry {
        file: "src-tauri/src/runtime/proxy/tests/recovery.rs",
        test: "real_core_crash_triggers_auto_restart",
        class: Class::RealCore,
    },
    Entry {
        file: "src-tauri/src/runtime/proxy/tests/recovery.rs",
        test: "real_core_crash_feeds_diagnostic_restart_axis",
        class: Class::RealCore,
    },
    Entry {
        file: "src-tauri/src/runtime/proxy/tests/recovery.rs",
        test: "real_core_intentional_stop_does_not_restart",
        class: Class::RealCore,
    },
    Entry {
        file: "src-tauri/src/runtime/proxy/tests/recovery.rs",
        test: "real_core_crash_loop_gives_up_without_infinite_restart",
        class: Class::RealCore,
    },
    Entry {
        file: "src-tauri/src/runtime/proxy/tests/process_supervision.rs",
        test: "real_core_stale_cleanup_kills_own_orphan_spares_foreign",
        class: Class::RealCore,
    },
    Entry {
        file: "src-tauri/src/runtime/speedtest/tests/mod.rs",
        test: "real_core_accepts_bound_shadow_tls_temp_config",
        class: Class::RealCore,
    },
    Entry {
        file: "src-tauri/src/runtime/stats/tests/real_core_tests.rs",
        test: "real_core_aggregate_relay_emits_real_frames",
        class: Class::RealCore,
    },
    // ── PublicNetwork ──
    Entry {
        file: "src-tauri/src/runtime/http/tests/mod.rs",
        test: "real_https_get_handshakes_and_returns_body",
        class: Class::PublicNetwork,
    },
    // ── LiveHostState ──
    Entry {
        file: "src-tauri/src/runtime/route_binding/tests/mod.rs",
        test: "live_route_planner_returns_a_real_interface",
        class: Class::LiveHostState,
    },
    Entry {
        file: "crates/helper/src/platform/windows/wintun/tests/mod.rs",
        test: "live_best_route_interface_alias_supports_both_families",
        class: Class::LiveHostState,
    },
    Entry {
        file: "crates/system-integration/src/tests/mod.rs",
        test: "production_macos_native_proxy_transaction_restores_after_takeover",
        class: Class::LiveHostState,
    },
    Entry {
        file: "crates/system-integration/src/tests/mod.rs",
        test: "production_macos_native_proxy_recovers_across_process_sessions",
        class: Class::LiveHostState,
    },
    // ── NotAGate ──
    Entry {
        file: "src-tauri/tests/release_escape_hatches.rs",
        test: "inventory",
        class: Class::NotAGate,
    },
];

/// 跑法文档。本门断言它存在，且每个登记的测试名都能在里面找到。
const RUNBOOK: &str = "docs/ignored-tests.md";

// ============================================================================
// 扫描
// ============================================================================

/// 一处源码里的 `#[ignore]`。
#[derive(Debug)]
struct Site {
    file: String,
    line: usize,
    test: String,
    reason: String,
}

fn workspace_root() -> PathBuf {
    polaris_source_probe::workspace_root_from(env!("CARGO_MANIFEST_DIR"))
}

/// workspace 成员目录（`members` 含 `crates/*` 通配，这里展开）。
fn members(root: &Path) -> Vec<PathBuf> {
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).expect("读不到根 Cargo.toml");
    let mut out = Vec::new();
    let mut in_members = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("members") {
            in_members = true;
        }
        if !in_members {
            continue;
        }
        for raw in trimmed.split(['[', ']', ',']) {
            let item = raw.trim().trim_matches('"');
            if item.is_empty() || !item.contains('/') && item != "src-tauri" {
                continue;
            }
            if let Some(prefix) = item.strip_suffix("/*") {
                let dir = root.join(prefix);
                let Ok(entries) = std::fs::read_dir(&dir) else {
                    continue;
                };
                let mut subs: Vec<PathBuf> = entries
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| p.is_dir())
                    .collect();
                subs.sort();
                out.extend(subs);
            } else {
                out.push(root.join(item));
            }
        }
        if trimmed.ends_with(']') {
            break;
        }
    }
    out.sort();
    out.dedup();
    assert!(
        out.len() > 5,
        "只解析出 {} 个 workspace 成员 —— members 解析坏了，本门在裸奔",
        out.len()
    );
    out
}

fn collect_rs(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            collect_rs(root, &path, out);
            continue;
        }
        if path.extension().is_some_and(|ext| ext == "rs") {
            let rel = path
                .strip_prefix(root)
                .expect("文件不在仓库根内")
                .to_string_lossy()
                .replace('\\', "/");
            out.push((rel, path));
        }
    }
}

/// 全仓每一处 `#[ignore]`（**平台无关**：数源码，不数运行时报告）。
fn scan() -> Vec<Site> {
    let root = workspace_root();
    let mut files = Vec::new();
    for member in members(&root) {
        for sub in ["src", "tests"] {
            let dir = member.join(sub);
            if dir.is_dir() {
                collect_rs(&root, &dir, &mut files);
            }
        }
    }
    assert!(!files.is_empty(), "取材面是空的 —— 本门会恒真");

    let mut sites = Vec::new();
    for (rel, path) in files {
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("读不到 `{}`（{err}）", path.display()));
        // 定位走净化面：本仓多处**注释里**写着 `#[ignore]`（本文件自己就有好几处）。
        //
        // 针的形状（复审 2026-08-31 tests12域-判据改宽，输入对差）：
        // 旧针 = 字面量 `#[ignore` + 「行首只能是空白」两条，漏掉两类**真变哑**写法——
        // ① `#[cfg_attr(<条件>, ignore)]`（字面量根本不含 `#[ignore`）；
        // ② 同行属性 `#[test] #[ignore = "…"]`（`#[ignore` 前面是兄弟属性，不是空白）。
        // 两类都能把一条测试静默变哑而四道门零反应（不要求理由、不进 REGISTRY、总数仍 18）。
        // 新针 = 逐个属性起点 `#[` 扫描：属性头是 `ignore` 即命中（不再看它在行内哪个位置），
        // 属性头是 `cfg_attr` 且实参里含独立 `ignore` token 也命中（条件与理由串在净化面里
        // 已被抹空，不会误命中 `feature = "ignore-x"` 这类字符串）。
        // 对差样本：现有 18 处 → 旧新同判；`#[cfg_attr(windows, ignore)]` / 同行 `#[ignore]`
        // → 旧放行（假绿）、新拦截（未登记 + 总数 ≠ 18 转红）。
        let masked = polaris_source_probe::mask_comments_and_strings(&raw);
        let is_ident = |c: char| c.is_alphanumeric() || c == '_';
        let mut from = 0usize;
        while let Some(offset) = masked[from..].find("#[") {
            let at = from + offset;
            from = at + "#[".len();
            let Some(close) = masked[at..].find(']').map(|o| at + o) else {
                continue;
            };
            // 属性头 = `#[` 之后第一个标识符。
            let inner = masked[at + 2..close].trim_start();
            let head: String = inner.chars().take_while(|&c| is_ident(c)).collect();
            // `ignore` token 的独立性：两侧都不能是标识符字符（防 `ignored` / `x_ignore` 充数）。
            let has_ignore_token = |text: &str| -> Option<usize> {
                let mut search = 0usize;
                while let Some(o) = text[search..].find("ignore") {
                    let i = search + o;
                    search = i + "ignore".len();
                    let before_ok = text[..i].chars().next_back().is_none_or(|c| !is_ident(c));
                    let after_ok = text[i + "ignore".len()..]
                        .chars()
                        .next()
                        .is_none_or(|c| !is_ident(c));
                    if before_ok && after_ok {
                        return Some(i);
                    }
                }
                None
            };
            // 理由起扫点：直写形态从属性头后起；`cfg_attr` 形态从实参里的 `ignore` token 后起
            // （跳过条件段——条件里若含字符串，首个引号不是理由的引号）。
            let reason_from = if head == "ignore" {
                at
            } else if head == "cfg_attr" {
                let args = &masked[at + 2..close];
                match has_ignore_token(args) {
                    Some(i) => at + 2 + i,
                    None => continue,
                }
            } else {
                continue;
            };
            // 理由回原文取：净化面里字符串字面量已被抹空。
            let attr = &raw[reason_from..=close.min(raw.len() - 1)];
            let reason = attr
                .split_once('"')
                .and_then(|(_, rest)| rest.rsplit_once('"').map(|(value, _)| value.to_string()))
                .unwrap_or_default();
            // 属性之后最近的 `fn <名>`（跨过 `#[tokio::test]` 之类的兄弟属性）。
            let test = masked[close..]
                .split('\n')
                .take(6)
                .find_map(|line| {
                    let t = line.trim_start();
                    let t = t.strip_prefix("async ").unwrap_or(t);
                    t.strip_prefix("fn ").map(|rest| {
                        rest.chars()
                            .take_while(|c| c.is_alphanumeric() || *c == '_')
                            .collect::<String>()
                    })
                })
                .unwrap_or_default();
            sites.push(Site {
                file: rel.clone(),
                line: masked[..at].matches('\n').count() + 1,
                test,
                reason,
            });
        }
    }
    sites
}

// ============================================================================
// 门
// ============================================================================

/// 🔴 每一处 `#[ignore]` 都必须带非空理由。
///
/// 裸 `#[ignore]` 在报告里只有三个字，读者无从判断它该不该在 —— 而这正是「把碍事的测试变哑」
/// 最省事的写法。
///
/// **变异探针**：把任意一条 `#[ignore = "…"]` 改成裸 `#[ignore]` ⇒ 本条转红并点名 `文件:行号`。
#[test]
fn every_ignore_carries_a_reason() {
    let sites = scan();
    assert!(
        sites.len() > 10,
        "只扫到 {} 处 `#[ignore]` —— 扫描器坏了，本门在裸奔",
        sites.len()
    );
    let bare: Vec<String> = sites
        .iter()
        .filter(|s| s.reason.trim().is_empty())
        .map(|s| format!("  {}:{}  {}", s.file, s.line, s.test))
        .collect();
    assert!(
        bare.is_empty(),
        "\n{} 处裸 `#[ignore]`（没有理由串）：\n{}\n\
         写成 `#[ignore = \"为什么默认不跑\"]`，并在本文件的 REGISTRY 里登记。\n",
        bare.len(),
        bare.join("\n")
    );
}

/// 🔴 源码与登记表必须逐条对上：不许有未登记的，也不许有过期条目。
///
/// **变异探针**：① 在任意测试上新加一个 `#[ignore = "…"]` ⇒ 报「未登记」；
/// ② 把 REGISTRY 里任一条的 `test` 改个名 ⇒ 报「条目过期」。
#[test]
fn registry_and_source_agree_exactly() {
    let sites = scan();
    let found: BTreeSet<(String, String)> = sites
        .iter()
        .map(|s| (s.file.clone(), s.test.clone()))
        .collect();
    let registered: BTreeSet<(String, String)> = REGISTRY
        .iter()
        .map(|e| (e.file.to_string(), e.test.to_string()))
        .collect();

    let unregistered: Vec<String> = sites
        .iter()
        .filter(|s| !registered.contains(&(s.file.clone(), s.test.clone())))
        .map(|s| format!("  {}:{}  {}  理由: {}", s.file, s.line, s.test, s.reason))
        .collect();
    assert!(
        unregistered.is_empty(),
        "\n{} 处 `#[ignore]` 没有登记：\n{}\n\
         默认不跑 = 默认没有覆盖。请在本文件的 REGISTRY 里加一行（选好 Class），\
         并在 `{RUNBOOK}` 里写清它怎么跑。\n",
        unregistered.len(),
        unregistered.join("\n")
    );

    let stale: Vec<String> = registered
        .difference(&found)
        .map(|(f, t)| format!("  {f} :: {t}"))
        .collect();
    assert!(
        stale.is_empty(),
        "\nREGISTRY 有 {} 条过期条目（源码里已经没有这个 `#[ignore]` 了）：\n{}\n\
         删掉它们 —— 留着等于给下一个同名测试发免死金牌。\n",
        stale.len(),
        stale.join("\n")
    );

    // 计数写死是刻意的：数变了就说明有人动了「默认不跑」的集合，该停下来显式裁定，
    // 而不是让门自适应放行。数的是**源码里的 `#[ignore]` 总数**（平台无关），
    // 不是 `cargo test` 报告里的 ignored（Linux 15 / Windows 16 / macOS 17，随平台变）。
    assert_eq!(
        sites.len(),
        REGISTRY.len(),
        "源码里 {} 处 `#[ignore]`，REGISTRY {} 条 —— 同一文件同一测试名出现了多次？",
        sites.len(),
        REGISTRY.len()
    );
    assert_eq!(
        sites.len(),
        18,
        "默认不跑的测试数从 18 变成了 {} —— 这不是自动放行的事：\
         增加意味着又有一块行为退出了默认覆盖，减少意味着有测试被接回默认门（好事，但要同步改这个数）。",
        sites.len()
    );
}

/// 🔴 类别不是装饰：理由串必须与它自洽。
///
/// 没有这一条，随手写个理由就能把一条真核测试登记成 `NotAGate`，而门毫无察觉。
///
/// **变异探针**：把任一 `RealCore` 条目改成 `Class::NotAGate` ⇒ 本条转红
/// （它的理由串里没有「非门」而有 `POLARIS_SINGBOX_PATH`）。
#[test]
fn class_matches_the_stated_reason() {
    let sites = scan();
    let mut bad = Vec::new();
    let mut per_class = std::collections::BTreeMap::<&str, usize>::new();
    for entry in REGISTRY {
        *per_class.entry(entry.class.name()).or_default() += 1;
        let Some(site) = sites
            .iter()
            .find(|s| s.file == entry.file && s.test == entry.test)
        else {
            continue; // 「条目过期」由上一条门报，这里不重复
        };
        let wanted = entry.class.reason_must_mention();
        if !wanted.iter().any(|needle| site.reason.contains(needle)) {
            bad.push(format!(
                "  {}:{}  {}\n      Class={} 要求理由里出现 {:?}\n      实际理由: {}",
                site.file,
                site.line,
                site.test,
                entry.class.name(),
                wanted,
                site.reason
            ));
        }
    }
    assert!(
        bad.is_empty(),
        "\n{} 条登记的 Class 与理由串不自洽：\n{}\n",
        bad.len(),
        bad.join("\n")
    );

    // 阳性对照：四个类别都得有人用。某一类恒空 ⇒ 它的自洽判据从未被执行过。
    for class in [
        Class::RealCore,
        Class::PublicNetwork,
        Class::LiveHostState,
        Class::NotAGate,
    ] {
        assert!(
            per_class.get(class.name()).copied().unwrap_or(0) > 0,
            "Class::{} 一条登记都没有 —— 它的理由自洽判据从未被执行过。\
             要么是分类漏了，要么这个变体该删。",
            class.name()
        );
    }
}

/// 🔴 跑法必须指得到真文档，且**逐个测试名**在里面找得到。
///
/// 本门建立时的实测：全仓 `grep -- --ignored` 零命中、`POLARIS_SINGBOX_PATH` 零命中 ——
/// 12 条真核测试写好了、编得过、**一次都没被执行过**。`#[ignore]` 的形态没错（它不冒充通过），
/// 错的是没有任何地方写着「谁在什么条件下跑它」。这条把那份说明钉成必需品。
///
/// **变异探针**：删掉 `docs/ignored-tests.md` 里任一测试名 ⇒ 本条转红并点名它。
#[test]
fn runbook_covers_every_registered_test() {
    let root = workspace_root();
    let path = root.join(RUNBOOK);
    let doc = std::fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!("跑法文档 `{RUNBOOK}` 读不到（{err}）—— 登记表的跑法指针烂了")
    });
    assert!(
        doc.contains("--ignored"),
        "`{RUNBOOK}` 里一条 `--ignored` 命令都没有 —— 它没在回答「怎么跑」这个问题"
    );

    // **逐字全名**，不许用前缀兜底。第一版写了「前缀命中也算」，实测当场失效：
    // `real_core_` 这个前缀在文档的示例命令里出现，于是 12 条 RealCore 全被它喂饱 ——
    // 删掉其中任意一个全名，本门照样绿（变异收据打不出来）。省下的那点抄写量，
    // 换来的是 2/3 的登记项从此不受本门约束。
    let missing: Vec<String> = REGISTRY
        .iter()
        .filter(|e| !doc.contains(e.test))
        .map(|e| format!("  {} （{}）", e.test, e.class.name()))
        .collect();
    assert!(
        missing.is_empty(),
        "\n{} 个登记的测试在 `{RUNBOOK}` 里找不到跑法：\n{}\n\
         默认不跑的测试如果连「怎么跑」都没写，它就是一份覆盖率错觉。\n",
        missing.len(),
        missing.join("\n")
    );
}
