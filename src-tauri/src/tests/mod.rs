use super::*;
use crate::test_support::{crate_code, crate_file};

/// 本地 renderer → 应用命令这条高权限边界的 CSP 契约（门的实体在这个子模块里）。
mod csp_contract;

/// 双击拖动层 / 系统菜单最大化不经过 `window_maximize_toggle`，必须由原生 resize 事件回读并广播。
#[test]
fn main_window_native_maximize_is_bridged_to_renderer() {
    let body = crate::commands::guard_scan::top_level_fn_body(
        &crate_code("main.rs"),
        "fn create_main_window(",
    );
    for required in [
        "tauri::WindowEvent::Resized(_)",
        "event_window.is_maximized()",
        "commit_maximized_observation(&maximized_state, maximized)",
        "emit_window_maximize_changed(&app_handle, maximized)",
    ] {
        assert!(
            body.contains(required),
            "主窗原生最大化同步链缺少 `{required}`"
        );
    }
}

/// W13：托盘图标黑/白变体的探测链（Win/Linux）。前两格是纯函数语义；后两格是源扫描守卫
/// （探测窗必须先于主窗被探、且 setup 必须真建它）——顺序翻回去 = 显式 uiTheme 下的
/// 读应用外观失真（复审 Med-1）复活，不建它 = 探测链退回旧缺陷。
/// W13：托盘图标黑/白变体的探测链（Win/Linux）。前三格是纯函数语义；后两格是守卫——
/// 注册表真值必须先于（被钉的）主窗被读；Windows 上注册表读法必须真的给出答案（CI win 腿上跑）。
#[cfg(not(target_os = "macos"))]
mod tray_dark_bg_probe {
    use super::dark_bg_from_probe;
    use crate::test_support::crate_code;

    #[test]
    fn primary_wins_when_present() {
        assert!(dark_bg_from_probe(Some(true), Some(false)));
        assert!(!dark_bg_from_probe(Some(false), Some(true)));
    }

    /// W13 的核心格：主信号（注册表→主窗）取不到时 fallback（浮层窗）接管——
    /// 旧实现这格恒白，正是浅色任务栏图标隐身的真机缺陷本体。
    #[test]
    fn fallback_takes_over_when_primary_is_gone() {
        assert!(!dark_bg_from_probe(None, Some(false)));
        assert!(dark_bg_from_probe(None, Some(true)));
    }

    #[test]
    fn all_missing_falls_back_to_dark_assumption() {
        assert!(dark_bg_from_probe(None, None));
    }

    #[test]
    fn registry_truth_is_probed_before_the_pinned_main_window() {
        let src = crate_code("app_tray.rs");
        let body = crate::commands::guard_scan::top_level_fn_body(&src, "fn set_tray_state(");
        assert!(
            !body.is_empty(),
            "set_tray_state 函数体取不到——判据失效需同步更新"
        );
        let reg = body
            .find("system_dark_bg()")
            .expect("set_tray_state 不再读注册表真值（W13 回潮）");
        let main = body
            .find("get_webview_window(\"main\")")
            .expect("set_tray_state 的主窗探测形态变了");
        assert!(
            reg < main,
            "注册表真值又排到了主窗之后：显式 uiTheme 下主窗被钉、读到应用外观而非任务栏明暗"
        );
    }

    /// Windows CI 腿上跑：Personalize 键自 Win10 1809 起恒在，读不出 Some 说明读法坏了。
    #[cfg(target_os = "windows")]
    #[test]
    fn registry_probe_answers_on_real_windows() {
        assert!(super::super::system_dark_bg().is_some());
    }
}

/// **结构门，不是行为门** —— 它证的是「写 `AppleLanguages` 的那一句排在建 `NSApplication`
/// 的那一句之前」，证不了「macOS 上原生对话框真的换了语言」。后者要一台 mac
/// （本仓 CI / 开发机是 Linux，AppKit 根本不存在），已列真机判据。
///
/// # 为什么这条顺序值一个门
///
/// `app_language::apply_process_language` 的效果**只在下次启动兑现**，所以挪错位置**当场
/// 什么都不会变**：不 panic、不报错、单测全绿、Linux/Windows 完全无感，连 macOS 用户也只是
/// 「改完语言重启一次没生效，重启第二次才生效」。这种缺陷不会有人报 bug，只会被当成「这软件
/// 就这样」。因果链见 `app_language` 模块文档的那张表：Tauri 2 的 `setup` 由
/// `Builder::build()` 在建完 runtime（= tao 建 `NSApplication`）之后才调
/// （`tauri-2.11.5/src/app.rs:2344` 建、`:2531` 才 setup），故写在 `.build(ctx)` 之后 =
/// AppKit 本次已经读过旧值 = 用户要重启两次。
///
/// **变异锁**：把 `apply_process_language(...)` 挪到 `.build(ctx)` 之后 ⇒ 顺序断言转红；
/// 整句删掉 ⇒ 锚点消失、`expect` 转红；把 `.build(ctx)` 改回内联 `generate_context!()`
/// ⇒ 锚点消失转红（那意味着 identifier 又拿不到了）。
///
/// 三平台同源：非 macOS 上 `apply_process_language` 是空函数，但调用点照样在，
/// 故本门在 Linux/Windows 的 CI 上一样有判据 —— 不会出现「只有 mac 跑得到的门」。
#[test]
fn native_dialog_language_is_applied_before_appkit_boots() {
    let body =
        crate::commands::guard_scan::top_level_fn_body(&crate_code("main.rs"), "fn main() {");
    let apply = body
        .find("app_language::apply_process_language(")
        .expect("锚点消失：原生对话框语言对账的调用点没了 —— macOS 上原生对话框会退回跟随系统语言");
    let build = body
        .find(".build(ctx)")
        .expect("锚点消失：`.build(ctx)` —— 守卫已失去「AppKit 何时起来」的判据");
    assert!(
        apply < build,
        "`apply_process_language` 排到了 `.build(ctx)` 之后 —— Tauri 在 build 里就建好了 \
             NSApplication，AppKit 本次已按旧值解析完本地化，用户改语言后要重启**两次**才生效。"
    );
}

/// QUIC 旧规则清理必须在日志可用后、代理 controller 装配前启动；否则要么没有真机分段证据，
/// 要么 controller 看不到 prewarm 标记并在每次 System 连接里重复 `netsh`。
#[test]
fn windows_quic_cleanup_prewarm_precedes_proxy_runtime_construction() {
    let source = crate_code("main.rs");
    let logging = source
        .find("logging::init(&config_dir)")
        .expect("日志初始化锚点消失");
    let prewarm = source
        .find("start_windows_quic_cleanup_prewarm()")
        .expect("Windows QUIC 启动预热接线消失");
    let runtime = source
        .find("AppRuntime::new(config_dir)")
        .expect("AppRuntime 装配锚点消失");
    assert!(logging < prewarm && prewarm < runtime);
}

/// Windows 官方 single-instance 2.4.3 的 mutex→监听窗间隙必须被外层启动闸门完整包住。
/// 这里只钉装配顺序；mutex 的排他行为由 `windows_single_instance` 的 Windows 单测真跑。
#[test]
fn windows_single_instance_startup_gate_wraps_plugin_setup() {
    let body =
        crate::commands::guard_scan::top_level_fn_body(&crate_code("main.rs"), "fn main() {");
    let acquire = body
        .find("windows_single_instance::StartupGate::acquire(")
        .expect("Windows 单实例启动闸门的取得点消失");
    let plugin = body
        .find(".plugin(tauri_plugin_single_instance::init(")
        .expect("官方 single-instance 插件注册点消失");
    let build = body.find(".build(ctx)").expect("Tauri build 锚点消失");
    let verify = body
        .find("windows_single_instance::verify_listener(")
        .expect("官方监听窗的放行前验证消失");
    let release = body
        .find("drop(single_instance_startup_gate)")
        .expect("Windows 单实例启动闸门的释放点消失");
    let run = body.find("app.run(").expect("Tauri run 锚点消失");

    assert!(
        acquire < plugin && plugin < build && build < verify && verify < release && release < run,
        "顺序必须是：取启动闸门 → 注册官方插件 → build/setup → 验证监听窗 → 释放 → run"
    );
}

// ── 托盘图标汇流点（P1「中断后不回落」）──────────────────────────────────────
//
// 图标本身只能真机看；能自动断言的是**装配决策**：哪些源被接上汇流点。此前这条腿零测试，
// 于是「崩溃腿没接」这种缺失从未被任何门发现。下面三测穷举本 bug 的逃逸面：
//   ① 某条终态事件没订（本 bug 的原形：ERROR 缺失）
//   ② 事件订阅退化成只订一条 / 只订部分（补一个 ERROR 监听就收工的半修）
//   ③ 轮询自愈网没挂，或挂了但周期长到形同没有（零 emit 腿仍无人兜）

/// 主窗尺寸只能有一个真值源：`tauri.conf.json`。
///
/// 建窗走 `WebviewWindowBuilder::from_config`（conf 的 `create:false`），conf 里的
/// width/height/minWidth/minHeight 由它套上。mac 分支曾在其后另写一份 `inner_size` +
/// `min_inner_size`，把 conf 那四个值在 mac 上变成死值 —— 改 conf 不生效、且**没有任何门会红**
/// （2026-07-29 真机才发现最小尺寸不是 conf 写的值）。这条锁住「建主窗的代码里不得再出现尺寸设置」。
///
/// 射程刻意收在 `create_main_window`：Dashboard 窗（`commands/misc.rs`）是独立窗、有自己的尺寸，
/// 不在此列。
#[test]
fn main_window_size_comes_only_from_conf() {
    let src = crate_code("main.rs");
    let body = crate::commands::guard_scan::top_level_fn_body(&src, "fn create_main_window(");
    assert!(
        !body.is_empty(),
        "抓不到 create_main_window 的函数体 —— 判据面塌了（改名了？），本门会恒绿"
    );
    for forbidden in ["inner_size(", "min_inner_size("] {
        assert!(
            !body.contains(forbidden),
            "建主窗的代码里出现 `{forbidden}` —— 它会覆盖 from_config 套上的 conf 尺寸，\
                 使 tauri.conf.json 的 width/height/minWidth/minHeight 变成死值。\
                 尺寸改动请改 conf，不要在这里再设一份。"
        );
    }
}

/// 首建天然发生在 setup 主线程，轻量态重建则可能由托盘 WebView IPC 线程触发。两条路径必须在
/// `show_main_window` 入口合流到主线程，否则 macOS `apply_vibrancy` 会拒绝重建窗，透明侧栏背后
/// 没有原生材质，表现为整个左侧导航直接透出桌面。
#[test]
fn main_window_rebuild_is_dispatched_to_main_thread() {
    let src = crate_code("main.rs");
    let entry = crate::commands::guard_scan::top_level_fn_body(&src, "fn show_main_window(");
    let on_main =
        crate::commands::guard_scan::top_level_fn_body(&src, "fn show_main_window_on_main_thread(");

    assert!(
        entry.contains("run_on_main_thread"),
        "主窗唤出入口必须先投主线程；托盘 IPC 线程不得直接重建原生窗口"
    );
    // W18 第二层：主线程帧内调用（WM_COPYDATA WndProc / IPC 分发栈）时 run_on_main_thread
    // 是内联直执——必须先跳线程脱离分发帧再排回，否则重建把同步对端卡死在 SendMessageW 上。
    let spawn_at = entry
        .find("async_runtime::spawn")
        .expect("主窗唤出必须先跳 async 线程脱离消息分发帧");
    let queue_at = entry
        .find("run_on_main_thread")
        .expect("跳线程后必须排回主线程");
    assert!(
        spawn_at < queue_at,
        "次序必须是 spawn 脱帧 → run_on_main_thread 排回 → 重建/呈现"
    );
    let probe_at = entry
        .find("window_health::begin_show_probe")
        .expect("帧外调度前必须先登记唤出起点，否则真机时延漏掉排队段");
    assert!(
        probe_at < spawn_at,
        "主窗时延起点必须早于 spawn，不能把消息帧逃逸/线程排队从数据里剪掉"
    );
    assert!(
        entry.contains("show_main_window_on_main_thread("),
        "主线程闭包必须调用唯一的建窗/呈现实现"
    );
    assert!(
        !entry.contains("create_main_window("),
        "跨线程入口不得绕过主线程边界直接建窗"
    );
    assert!(
        on_main.contains("create_main_window(app, false)"),
        "轻量态重建必须留在主线程实现内"
    );
    let create = crate::commands::guard_scan::top_level_fn_body(&src, "fn create_main_window(");
    assert!(
        create.contains("rt.stats().mark_main_window_created()"),
        "builder 成功后必须提交主窗口生命周期，供三平台 stats/logs 可见性门共享"
    );
    assert!(
        create.contains("window_health::log_show_probe(app, \"window-built\", false)"),
        "builder 成功点必须记录 window-built，B9 才能区分原生建窗与 renderer 加载耗时"
    );
    let present = crate::commands::guard_scan::top_level_fn_body(&src, "fn present_main_window(");
    assert!(
        present.contains("window_health::log_show_probe(")
            && present.contains("\"shown\"")
            && present.contains("\"show-failed\""),
        "唯一呈现漏斗必须消费 shown/show-failed 终态探针"
    );
}

// ── 托盘汇流点幂等闸门（30s 轮询 × 全程 = 每 30s 一次磁盘写 + indicator 重载）────────
//
// 下面这组锁的是 `reconcile_tray_visual` 的**全部逃逸面**：短路被删（恒重画）、短路过度（变了不
// 重画）、只比部分字段、缓存不更新、失败还照存缓存 —— 任一形态都必须有一条转红。

// ── dialog 插件 ACL（真机 'plugin:dialog|confirm not allowed by ACL'）───────────
//
// 病灶不是「忘了配」，是 `dialog:default` **文案骗人**：它自称 "All dialog types are enabled"，
// 实际 permissions = [allow-message, allow-save, allow-open]，**不含 allow-confirm/allow-ask**。
// 而 tauri-plugin-dialog 的 init 脚本无条件把 `window.alert`/`window.confirm` 覆写成
// `plugin:dialog|message` / `|confirm` ⇒ 任何一句 `window.confirm(...)` 都会撞 ACL。
//
// 「读 default.json 断言含 allow-confirm」这种测只是把配置抄一遍（改配置时会顺手改测，没牙）。
// 下面改成断言**调用面 ⊆ 授权面**：扫前端源码里真实用到的 dialog 命令，逐个要求对应权限存在。

/// 判定紧接 `out` 之后的 `/` 是否**可能**是正则字面量起点（而非除法 / JSX 斜杠）。
///
/// 用白名单（只有这些前驱字符/关键字之后才允许正则）而非黑名单：宁可漏判成除法（= 今天的行为），
/// 也不能把 `</div>`、`<img … />` 这类 JSX 斜杠误当正则起点 —— 那会在 .tsx 里新造注释泄漏。
fn regex_can_start(out: &str) -> bool {
    let t = out.trim_end();
    let Some(last) = t.chars().last() else {
        return true; // 文件开头
    };
    if matches!(
        last,
        '=' | '(' | ',' | ':' | '[' | '!' | '&' | '|' | '?' | ';' | '{'
    ) {
        return true;
    }
    // `return /re/.test(x)` 一类：关键字之后同样允许正则。
    const REGEX_PREFIX_KW: [&str; 14] = [
        "return",
        "typeof",
        "instanceof",
        "in",
        "of",
        "new",
        "delete",
        "void",
        "throw",
        "case",
        "do",
        "else",
        "yield",
        "await",
    ];
    let ident = |c: char| c.is_alphanumeric() || c == '_' || c == '$';
    REGEX_PREFIX_KW.iter().any(|kw| {
        t.strip_suffix(kw)
            .is_some_and(|head| head.chars().last().is_none_or(|c| !ident(c)))
    })
}

/// 剥 TS/TSX 注释（`//` 与 `/* */`），**不碰字符串/模板字面量内部**（`"https://x"` 里的 `//`
/// 不是注释起点 —— 否则同行后续真代码会被吃掉，扫描面出洞）。换行原样保留。
///
/// 守卫扫的是**代码**：本仓注释里到处在讲 `window.confirm` 这个坑（`settings-logic.ts:252/254`、
/// `SettingsHelper.tsx:101`），不剥注释的话「前端还在用 confirm」这个前提永远为真 —— 反向哨兵
/// 退化成空转，而它恰恰是写来防这个形态的。
///
/// 与前端 `settings-logic.test.ts` 的 `stripComments` 同职责（那边正则、这边多认字符串状态）。
///
/// 正则字面量（`const re = /['"]/g;`）单列一档：不认的话里面的 `'` 会被当成字符串起点，引号状态
/// **一路挂到文件后面某个落单引号**，中间所有注释都不再被剥 ⇒ 反向哨兵被注释里的
/// `window.confirm` 喂绿。识别到就**原样拷贝**（绝不删除），故判错的最坏后果 = 退化成今天的行为，
/// 不可能吃掉真代码造成扫描面出洞。起点判定用**白名单**（`= ( , : [ ! & | ? ; {` + 关键字）而非
/// 「不是标识符就算正则」：后者会把 JSX 的 `</div>`、`<img … />` 误当正则起点，在 .tsx 里
/// 反倒制造新的注释泄漏。
///
/// 另有兜底：`'` / `"` 字符串**不能跨行**（只有模板串可以），故撞见换行即判定「刚才解析错了」
/// 并复位。任何残余的引号态误判（正则、JSX 文本里的 `don't` …）都被限制在**一行内**，
/// 不再顺着文件级联。
fn strip_ts_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut it = src.chars().peekable();
    let mut quote: Option<char> = None; // Some(引号字符) = 字符串/模板内
    let mut escaped = false;
    while let Some(c) = it.next() {
        if let Some(q) = quote {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == q {
                quote = None;
            } else if c == '\n' && q != '`' {
                quote = None; // 单/双引号串不跨行 ⇒ 走到这儿说明刚才判错了，就地收手
            }
            continue;
        }
        match c {
            '\'' | '"' | '`' => {
                quote = Some(c);
                out.push(c);
            }
            '/' if it.peek() == Some(&'/') => {
                for n in it.by_ref() {
                    if n == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            '/' if it.peek() == Some(&'*') => {
                it.next(); // 吃掉 '*'
                let mut prev = '\0';
                for n in it.by_ref() {
                    if prev == '*' && n == '/' {
                        break;
                    }
                    if n == '\n' {
                        out.push('\n');
                    }
                    prev = n;
                }
            }
            // 正则字面量：原样拷贝，只为屏蔽里面的引号，不改变任何字符。
            '/' if regex_can_start(&out) => {
                out.push('/');
                let mut in_class = false; // `[...]` 内的 `/` 不结束字面量
                let mut esc = false;
                for n in it.by_ref() {
                    out.push(n);
                    if esc {
                        esc = false;
                        continue;
                    }
                    match n {
                        '\\' => esc = true,
                        '[' => in_class = true,
                        ']' => in_class = false,
                        '/' if !in_class => break,
                        '\n' => break, // 正则不跨行：真跨行说明判错了，立刻收手
                        _ => {}
                    }
                }
            }
            _ => out.push(c),
        }
    }
    out
}

/// 递归收集目录下所有**生产** .ts/.tsx 源码（已剥注释、已排除 `*.test.*` / `*.spec.*`；
/// 测试期读盘，无新增依赖）。
///
/// 排除测试文件：vitest 跑在 node 环境、根本不经 Tauri ACL，测试文本里出现 `window.confirm`
/// 既不需要授权，也不该让「前端还在用 confirm」这个前提为真（`settings-logic.test.ts` 此前正是
/// 这么把反向哨兵喂绿的）。
fn collect_sources(dir: &std::path::Path, out: &mut Vec<(std::path::PathBuf, String)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_sources(&p, out);
            continue;
        }
        if !matches!(
            p.extension().and_then(|s| s.to_str()),
            Some("ts") | Some("tsx")
        ) {
            continue;
        }
        let name = p
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_owned();
        if name.contains(".test.") || name.contains(".spec.") {
            continue;
        }
        if let Ok(s) = std::fs::read_to_string(&p) {
            out.push((p, strip_ts_comments(&s)));
        }
    }
}

fn ui_src() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../ui/src")
}

/// 直接 invoke 命令名的**裸串**形态 → 所需权限 id。
///
/// 光有这张表守不住 import 形态：`import { save } from '@tauri-apps/plugin-dialog'` 的源码里
/// 一个 `plugin:dialog|save` 字样都不会出现 —— 见 [`dialog_import`]，三条检测面并联。
const DIALOG_INVOKE_TO_PERM: [(&str, &str); 5] = [
    ("plugin:dialog|confirm", "dialog:allow-confirm"),
    ("plugin:dialog|message", "dialog:allow-message"),
    ("plugin:dialog|ask", "dialog:allow-ask"),
    ("plugin:dialog|open", "dialog:allow-open"),
    ("plugin:dialog|save", "dialog:allow-save"),
];

/// 被插件 init 脚本**覆写的全局函数** → 所需权限 id。插件无条件把 `window.confirm` / `window.alert`
/// 换成 `plugin:dialog|confirm` / `|message`，所以调用点写不写 `window.` 前缀都一样走 ACL。
const DIALOG_GLOBAL_TO_PERM: [(&str, &str); 2] = [
    ("confirm", "dialog:allow-confirm"),
    ("alert", "dialog:allow-message"),
];

/// 源码里是否调用了全局函数 `name`。
///
/// 只匹配字面量 `window.confirm(` 会漏掉一整片等价形态 —— 它们撞的是**同一条** ACL：
/// 裸调 `await confirm('x')`、括号前带空格 `window.confirm ('x')`、计算成员
/// `window['confirm'](…)`、`globalThis.confirm(…)`。漏了它们不仅是 ACL 洞（一旦收回
/// `allow-confirm` 就逃逸），更让反向哨兵「confirm 只许出现在 nativeConfirm 一处」对别处裸用不转红。
///
/// `foo.confirm(` 这类**他人成员**不算全局调用（`window` / `globalThis` 才是），否则会把无关对象
/// 的同名方法误判成 dialog 调用。
fn calls_global(src: &str, name: &str) -> bool {
    let ident = |c: char| c.is_alphanumeric() || c == '_' || c == '$';
    let is_global_owner = |head: &str| {
        ["window", "globalThis"].iter().any(|o| {
            head.strip_suffix(o)
                .is_some_and(|rest| rest.chars().last().is_none_or(|c| !ident(c)))
        })
    };
    for (i, _) in src.match_indices(name) {
        // token 左边界：`reconfirm(` 不算。右边界不必单独校验 —— 多出的标识符字符必然让下面
        // 「后面是 `(`」的判据落空（`confirmDelete(` 的 rest 以 `D` 开头），单写一条杀不掉任何变异。
        if src[..i].ends_with(ident) {
            continue;
        }
        // 括号前允许空白：`window.confirm ('x')`。
        let rest = &src[i + name.len()..];
        if !rest.trim_start().starts_with('(') {
            continue;
        }
        let head = src[..i].trim_end();
        if let Some(owner) = head.strip_suffix('.') {
            if !is_global_owner(owner.trim_end()) {
                continue; // `dialog.confirm(` 之类：不是被覆写的那个全局
            }
        }
        return true;
    }
    // 计算成员形态：`window['confirm'](…)` —— 上面的标识符扫描看不见（名字在字符串里）。
    ["window", "globalThis"].iter().any(|owner| {
        ['\'', '"']
            .iter()
            .any(|q| src.contains(&format!("{owner}[{q}{name}{q}]")))
    })
}

/// dialog 插件的 JS 模块说明符（具名 import 形态的入口）。
const DIALOG_MODULE: &str = "@tauri-apps/plugin-dialog";

/// 插件导出的**命令面全集** → 所需权限 id（导出名与 `plugin:dialog|<name>` 同名）。
///
/// `save` 这行是本批补的洞：`allow-save` 刚被收回，而旧表里 `plugin:dialog|save` 压根不存在
/// ⇒ 有人写 `import { save } ...` 时守卫全绿、运行期真机抛
/// `Command plugin:dialog|save not allowed by ACL` —— 正是本批要根治的病灶原型复发。
const DIALOG_API_TO_PERM: [(&str, &str); 5] = [
    ("confirm", "dialog:allow-confirm"),
    ("message", "dialog:allow-message"),
    ("ask", "dialog:allow-ask"),
    ("open", "dialog:allow-open"),
    ("save", "dialog:allow-save"),
];

/// 一份源码对 [`DIALOG_MODULE`] 的使用形态。
#[derive(Debug, PartialEq, Eq)]
enum DialogImport {
    /// 没引用该模块。
    Absent,
    /// 解析出静态具名列表（可能为空：纯类型 import）→ 可精确映射到权限。
    /// 保存的是**导出名**（`open as pick` 取 `open`），因为 ACL 认的是命令名不是本地别名。
    Named(Vec<String>),
    /// 引用了模块但取不到静态具名列表（`import * as` / `await import(...)` / side-effect import）
    /// → 调用面不可判 ⇒ **失败关闭**，让人来判，而不是默默放行成第二个洞。
    Opaque,
}

/// 找出 `src` 里所有落在 token 边界上的 `kw` 关键字位置（避开 `important` / `reimport` 之类子串命中）。
fn keyword_positions<'a>(src: &'a str, kw: &'a str) -> impl Iterator<Item = usize> + 'a {
    let ident = |c: char| c.is_alphanumeric() || c == '_' || c == '$';
    src.match_indices(kw)
        .filter(move |(i, _)| {
            !src[..*i].ends_with(ident) && !src[*i + kw.len()..].starts_with(ident)
        })
        .map(|(i, _)| i)
}

/// 从一条 import/export 语句的**正文**（关键字之后 → 下一条语句关键字为止）里取模块说明符，
/// 返回 `(关键字与说明符之间的 clause, 模块名)`。撞见 `;` 说明本语句压根没有说明符。
fn module_specifier(body: &str) -> Option<(&str, &str)> {
    let mut it = body.char_indices();
    while let Some((off, c)) = it.next() {
        match c {
            ';' => return None,
            '\'' | '"' | '`' => {
                let start = off + c.len_utf8();
                let mut escaped = false;
                for (end, n) in it.by_ref() {
                    if escaped {
                        escaped = false;
                    } else if n == '\\' {
                        escaped = true;
                    } else if n == c {
                        return Some((&body[..off], &body[start..end]));
                    }
                }
                return None;
            }
            _ => {}
        }
    }
    None
}

/// 解析源码对 `@tauri-apps/plugin-dialog` 的使用形态。
///
/// **不从模块名回看整份文件**：回看会一路切到*上一条* import 的关键字，于是上一条 import 的花括号
/// 就把「有没有具名列表」这个判据满足掉 —— 真实源文件几乎必有前置 import，`export … from` /
/// `export *` / 动态 `import(M)` / `require()` 因此全部被误判成 `Named(上一条 import 的名字)`，
/// 失败关闭形同虚设（甚至吞掉本条真正的具名项）。
///
/// 改为**先按语句切分再解析**：每条语句的射程 = 本关键字 → 下一条 import/export 关键字，越不了界。
/// 模块名若出现在任何 import/export 语句之外（`require('…')`、`const M = '…'`、子路径…），
/// 直接判不可判。
///
/// 两条独立的网：①「本语句 clause 必须整好是具名花括号组」②「模块名出现次数必须全被 import/export
/// 语句认领」。变异验证显示二者互为兜底 —— 单独敲掉 `export` 分支或语句射程上界，逃逸构造仍被 ②
/// 拦成 `Opaque`（失败关闭方向），不产生假绿。保留 ① 是为了**精度**（少报无谓的不可判），不是安全属性。
fn dialog_import(src: &str) -> DialogImport {
    let total = src.matches(DIALOG_MODULE).count();
    if total == 0 {
        return DialogImport::Absent;
    }
    let mut stmts: Vec<(usize, &str)> = ["import", "export"]
        .iter()
        .flat_map(|kw| keyword_positions(src, kw).map(move |i| (i, *kw)))
        .collect();
    stmts.sort_unstable();

    let mut names = Vec::new();
    let mut matched = 0usize;
    for (n, &(pos, kw)) in stmts.iter().enumerate() {
        let end = stmts.get(n + 1).map_or(src.len(), |(next, _)| *next);
        let Some((clause, module)) = module_specifier(&src[pos + kw.len()..end]) else {
            continue;
        };
        if module != DIALOG_MODULE {
            continue;
        }
        matched += 1;
        // `export … from '…'`：再导出。调用面转移到下游消费方，而消费方 import 的是**本地**模块名
        // （扫描时看不出它连着 dialog 插件）⇒ 不可判，失败关闭。
        if kw == "export" {
            return DialogImport::Opaque;
        }
        // clause 必须**整好**是一个具名花括号组 + `from`。`import * as d from` / `import d from` /
        // `import d, { x } from`（默认绑定没被覆盖）/ 动态 `import(` / side-effect import 一律不可判。
        let Some(spec) = clause.trim().strip_suffix("from") else {
            return DialogImport::Opaque;
        };
        let Some(inner) = spec
            .trim()
            .strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
        else {
            return DialogImport::Opaque;
        };
        for raw in inner.split(',') {
            // `type Foo` → 剥 type 前缀；`open as pick` → 取导出名 `open`。
            let n = raw.trim().trim_start_matches("type ").trim();
            if let Some(exported) = n.split_whitespace().next() {
                if !exported.is_empty() {
                    names.push(exported.to_owned());
                }
            }
        }
    }
    if matched != total {
        return DialogImport::Opaque;
    }
    DialogImport::Named(names)
}

/// 一份源码需要的 dialog 权限全集（裸串形态 ∪ 具名 import 形态）。
/// `Err` = 调用面不可判，守卫按失败关闭处理。
fn required_dialog_perms(src: &str) -> Result<Vec<&'static str>, &'static str> {
    let mut need: Vec<&'static str> = DIALOG_INVOKE_TO_PERM
        .iter()
        .filter(|(call, _)| src.contains(call))
        .map(|(_, perm)| *perm)
        .chain(
            DIALOG_GLOBAL_TO_PERM
                .iter()
                .filter(|(name, _)| calls_global(src, name))
                .map(|(_, perm)| *perm),
        )
        .collect();
    match dialog_import(src) {
        DialogImport::Absent => {}
        DialogImport::Opaque => {
            return Err(
                "引用了 @tauri-apps/plugin-dialog 却取不到静态具名列表（namespace / 动态 import / \
                     side-effect import）→ 调用面不可判。请改成具名 import，否则 ACL 守卫失效",
            )
        }
        DialogImport::Named(names) => {
            for n in names {
                if let Some((_, perm)) = DIALOG_API_TO_PERM.iter().find(|(api, _)| *api == n) {
                    need.push(perm);
                }
            }
        }
    }
    Ok(need)
}

fn granted(capability_json: &str) -> Vec<String> {
    let v: serde_json::Value = serde_json::from_str(capability_json).expect("capability 非法 JSON");
    v["permissions"]
        .as_array()
        .expect("capability 缺 permissions")
        .iter()
        .filter_map(|p| p.as_str().map(str::to_owned))
        .collect()
}

/// `capabilities/*.json` → `window label → 该 window 的授权面`（一份 capability 可覆盖多个 window）。
///
/// **测试期读盘**而非手写清单：手写「次级窗有哪些」正是漏掉 `update-popup` 的成因 —— 新增一份
/// capability / 新增一个 window 必须自动进扫描面，不能指望有人记得回来改这张表。
fn capabilities_by_window() -> std::collections::BTreeMap<String, Vec<String>> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("capabilities");
    let mut out: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for entry in std::fs::read_dir(&dir)
        .expect("capabilities/ 读不到")
        .flatten()
    {
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let raw = std::fs::read_to_string(&p).expect("capability 读不到");
        let v: serde_json::Value = serde_json::from_str(&raw).expect("capability 非法 JSON");
        let windows: Vec<String> = v["windows"]
            .as_array()
            .expect("capability 缺 windows")
            .iter()
            .filter_map(|w| w.as_str().map(str::to_owned))
            .collect();
        let perms = granted(&raw);
        for w in windows {
            out.entry(w).or_default().extend(perms.iter().cloned());
        }
    }
    out
}

/// 次级窗的前端入口目录名（= window label）。约定：`ui/src/<label>/main.ts(x)`，与
/// `ui/vite.config.ts` 的多页 `rollupOptions.input`、Rust 侧建窗 label 一一对应。
/// 主窗入口是 `ui/src/main.tsx`（顶层文件，不是目录），故天然不在此列。
fn secondary_window_dirs() -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(ui_src())
        .expect("ui/src 读不到")
        .flatten()
        .map(|e| e.path())
        .filter(|p| ["main.ts", "main.tsx"].iter().any(|f| p.join(f).is_file()))
        .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .collect();
    out.sort();
    out
}

mod secondary_window_capabilities;

#[test]
fn dialog_acl_covers_every_frontend_dialog_call() {
    let mut files = Vec::new();
    collect_sources(&ui_src(), &mut files);
    assert!(
        !files.is_empty(),
        "没扫到前端源码，测试形同虚设（路径漂了？）"
    );

    let perms = granted(&crate_file("capabilities/default.json"));
    // `dialog:default` 缺 confirm/ask —— 它不能替代逐条授权，撞见即判缺。
    let has = |perm: &str| perms.iter().any(|p| p == perm);

    for (path, src) in &files {
        let need =
            required_dialog_perms(src).unwrap_or_else(|why| panic!("{}：{why}", path.display()));
        for perm in need {
            assert!(
                has(perm),
                "{} 用到 dialog 命令，但 capabilities/default.json 未授 {perm} \
                     → 运行期抛 'not allowed by ACL' 的未捕获 promise rejection",
                path.display()
            );
        }
    }
    // 前身是「生产代码确实还在用 window.confirm」的反向哨兵，用来防本测空转。
    // 2026-07-29 破坏性操作的二次确认改走原地二次点击（`ui/src/lib/confirm-twice.ts`）后
    // 生产代码已无 confirm 调用，该哨兵按它自己写的退役条件退役，换成下面那条**正向不变式**：
    // 生产代码不得再回退到 window.confirm。防空转的职责由本函数开头的 `!files.is_empty()`
    // 与 `comment_stripper_has_teeth` 共同承担。
}

/// 生产代码不得再调用 `window.confirm` —— 破坏性操作一律走原地二次点击
/// （`ui/src/lib/confirm-twice.ts` 的 `useConfirmTwice`，对齐原型 confirmTwice L3211）；
/// 需要成段解释的确认走 App 自绘 `ConfirmDialog`。
///
/// 为什么这是一条**产品不变式**而不只是风格偏好：插件 init 脚本把 `window.confirm` 覆写成
/// `plugin:dialog|confirm`，于是「二次确认」这道闸门的成立与否取决于该窗口的 capability 有没有授
/// `dialog:allow-confirm`。漏授时闸门不是降级成「无确认」，而是整条腿抛 rejection ⇒ 用户看到的是
/// 「卸载失败」。真机上就是这么表现的（2026-07-29 于 5.238 复现）。原地二次点击把二次确认从一项
/// 运行期授权变回一段普通渲染，没有这条失败模式。
///
/// 与前端 `settings-logic.test.ts` 的同名约束互为两侧：那边扫 settings 子树，这边扫整个 `ui/src`。
#[test]
fn production_code_never_calls_global_confirm() {
    let mut files = Vec::new();
    collect_sources(&ui_src(), &mut files);
    assert!(
        !files.is_empty(),
        "没扫到前端源码，测试形同虚设（路径漂了？）"
    );
    let hits: Vec<String> = files
        .iter()
        .filter(|(_, s)| calls_global(s, "confirm"))
        .map(|(p, _)| {
            p.strip_prefix(ui_src())
                .unwrap_or(p)
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();
    assert!(
        hits.is_empty(),
        "这些文件又用回了 window.confirm：{hits:?} —— 二次确认会退化成一项 ACL 授权，\
             漏授时整条腿抛 rejection（用户看到的是「操作失败」）。请改用 useConfirmTwice"
    );
}

/// 收回的授权不许悄悄回来：`dialog:allow-confirm` 已随自绘弹窗退役。
///
/// 单独一条而不是并进上面那测：两者失败的含义不同 —— 上面红 = 有人写回了 confirm 调用；
/// 这条红 = 授权面在没有调用点的情况下被重新放开（纯多余授权面，且会让上面那条的后果重新变得隐蔽）。
#[test]
fn dialog_confirm_permission_stays_revoked() {
    let perms = granted(&crate_file("capabilities/default.json"));
    assert!(
        !perms.iter().any(|p| p == "dialog:allow-confirm"),
        "capabilities/default.json 又授了 dialog:allow-confirm —— \
             生产代码已无 window.confirm 调用（见 production_code_never_calls_global_confirm），\
             该授权是多余授权面。若确有新增调用点，请先说明为什么不能走 useConfirmTwice"
    );
}

/// 这些插件仍由 Rust 宿主使用，但生产 renderer 没有任何对应 invoke/import。把宿主依赖误读成
/// “前端也要授权”会把配置、文件与进程能力平白暴露给一旦被注入的 webview 脚本。
#[test]
fn unused_high_risk_renderer_permissions_stay_revoked() {
    let perms = granted(&crate_file("capabilities/default.json"));
    for permission in [
        "process:default",
        "autostart:default",
        "autostart:allow-enable",
        "autostart:allow-disable",
        "autostart:allow-is-enabled",
        "fs:default",
        "fs:allow-read-text-file",
        "fs:allow-write-text-file",
    ] {
        assert!(
            !perms.iter().any(|granted| granted == permission),
            "capabilities/default.json 又授了未使用的 renderer 权限 {permission}；\
                 若新增了真实前端调用，请把调用点与最窄权限一起纳入审查"
        );
    }
}

#[test]
fn comment_stripper_has_teeth() {
    // 哨兵的地基自检：剥注释必须**真的**吃掉注释里的 window.confirm，又**不能**吃掉代码。
    // 剥过头（比如把整份源码吃空）→ 命中面恒空 → 哨兵恒红；剥不动 → 哨兵恒绿。两侧都锁。
    assert!(!strip_ts_comments("/* window.confirm(x) */\nlet a = 1;").contains("window.confirm("));
    assert!(!strip_ts_comments("// window.confirm(x)\nlet a = 1;").contains("window.confirm("));
    assert!(
        !strip_ts_comments("/**\n * window.confirm(x)\n */\nlet a = 1;")
            .contains("window.confirm(")
    );
    assert!(
        strip_ts_comments("if (window.confirm(\"x\")) drop(); // 尾注释")
            .contains("window.confirm(")
    );
    // 字符串里的 `//` 不是注释起点 —— 否则同行后续真调用被吃掉 = 扫描面出洞（假绿）。
    assert!(
        strip_ts_comments("const u = \"https://x\"; if (window.confirm(\"y\")) drop();")
            .contains("window.confirm(")
    );
    assert!(
        strip_ts_comments("const t = `a // b`; window.confirm(\"y\");").contains("window.confirm(")
    );
    // 剥完不塌行：注释吃掉的换行必须补回，否则剥后文本与真实文件行号错位（断言消息里的
    // file:line 就成了假话），且相邻两行会被拼到一起。块注释与行注释两侧都锁。
    assert_eq!(strip_ts_comments("a;\n/* x\ny */\nb;").lines().count(), 4);
    assert_eq!(strip_ts_comments("a; // c\nb;").lines().count(), 2);
    // 正则字面量里的引号不得污染字符串状态：`/['"]/` 若被当成字符串起点，引号态会一路挂到文件
    // 后面某个落单引号，中间的注释全不再被剥 ⇒ 哨兵被注释文本喂绿。原样拷贝 + 后续注释照剥。
    let re = strip_ts_comments("const r = /['\"]/g; // window.confirm(x)\nlet a = 1;");
    assert!(re.contains("/['\"]/g"), "正则字面量必须原样保留");
    assert!(!re.contains("window.confirm("), "正则之后的行注释仍须被剥");
    // JSX 的 `/` **不是**正则起点（`</div>`、`<img … />`）：误判成正则会吃掉同行后续注释边界，
    // 在 .tsx 里反倒新造泄漏。两种形态都必须让紧随其后的注释照常被剥。
    assert!(!strip_ts_comments("<div />; // window.confirm(x)\n").contains("window.confirm("));
    assert!(!strip_ts_comments("</div>; // window.confirm(x)\n").contains("window.confirm("));
    // 除法不得被当成正则：`a / b` 之后的注释照剥。
    assert!(
        !strip_ts_comments("const q = a / b; // window.confirm(x)\n").contains("window.confirm(")
    );
    // 兜底：单/双引号串不跨行 —— 未闭合的引号（JSX 文本里的 `don't` 等）只准污染一行。
    assert!(
        !strip_ts_comments("<p>don't</p>\n// window.confirm(x)\n").contains("window.confirm("),
        "未闭合引号必须在换行处复位，否则污染一路级联到文件尾"
    );
    // 测试文件不进扫描面（此前 settings-logic.test.ts 的测试文本就是哨兵的假绿来源之一）。
    let mut files = Vec::new();
    collect_sources(&ui_src(), &mut files);
    // 非空兜底：`collect_sources` 在 read_dir 失败时静默 return，files 为空则下面的
    // `!any(...)` 恒真 —— 空集上的「不存在」断言没牙。
    assert!(
        !files.is_empty(),
        "没扫到前端源码，测试形同虚设（路径漂了？）"
    );
    assert!(
        !files
            .iter()
            .any(|(p, _)| p.to_string_lossy().contains(".test.")),
        "测试文件混进了 ACL 扫描面"
    );
}

#[test]
fn dialog_import_form_is_in_the_detection_surface() {
    // B2：插件 JS API 的具名 import 形态。源码里**不会**出现 `plugin:dialog|save` 字样，
    // 旧守卫（只认裸串、且表里根本没有 save）对它全绿 → 真机 'plugin:dialog|save not allowed by ACL'。
    let src = "import { save } from '@tauri-apps/plugin-dialog';\nawait save({});";
    assert_eq!(
        required_dialog_perms(src).unwrap(),
        ["dialog:allow-save"],
        "具名 import 的 save 必须被识别为需要 dialog:allow-save"
    );
    // 别名与类型 import：ACL 认的是**导出名**，不是本地别名；纯类型 import 不产生权限需求。
    assert_eq!(
        required_dialog_perms(
            "import { open as pick, type OpenDialogOptions } from '@tauri-apps/plugin-dialog';"
        )
        .unwrap(),
        ["dialog:allow-open"]
    );
    // 多具名 + 双引号 + 换行排版。
    let multi = "import {\n  ask,\n  message,\n} from \"@tauri-apps/plugin-dialog\";";
    let mut got = required_dialog_perms(multi).unwrap();
    got.sort_unstable();
    assert_eq!(got, ["dialog:allow-ask", "dialog:allow-message"]);
    // 裸串形态没被这次改动挤掉。
    assert_eq!(
        required_dialog_perms("await invoke('plugin:dialog|save')").unwrap(),
        ["dialog:allow-save"]
    );
    assert_eq!(
        required_dialog_perms("if (window.confirm('x')) {}").unwrap(),
        ["dialog:allow-confirm"]
    );
    // 不引用该模块 ⇒ 零需求（守卫不能对无关文件乱要权限）。
    assert_eq!(
        required_dialog_perms("import { useState } from 'react';").unwrap(),
        Vec::<&str>::new()
    );
    // `import` 只算 token，不算子串 —— 两侧边界都锁：
    // ① 前边界：`save as reimport` 里的 `reimport` 落在真关键字与模块名**之间**，若不校验前边界，
    //    回看会停在它身上 ⇒ stmt 里没有 `{` ⇒ 误判 Opaque，把一条本可精确判定的 import 打成噪声。
    assert_eq!(
        dialog_import("import { save as reimport } from '@tauri-apps/plugin-dialog';"),
        DialogImport::Named(vec!["save".into()])
    );
    // ② 后边界：`importantThing` 同理（且它证明 rfind 不会被前文的同形子串带偏）。
    assert_eq!(
        dialog_import(
            "const important = { save };\nimport { ask } from '@tauri-apps/plugin-dialog';"
        ),
        DialogImport::Named(vec!["ask".into()])
    );
    assert_eq!(
        dialog_import("import { importantFlag, ask } from '@tauri-apps/plugin-dialog';"),
        DialogImport::Named(vec!["importantFlag".into(), "ask".into()])
    );
    // 失败关闭：取不到具名列表的三种形态一律判「不可判」，不许静默放行。
    for opaque in [
        "import * as dialog from '@tauri-apps/plugin-dialog';",
        "const d = await import('@tauri-apps/plugin-dialog');",
        "import '@tauri-apps/plugin-dialog';",
    ] {
        assert!(
            required_dialog_perms(opaque).is_err(),
            "{opaque} 的调用面不可判，守卫必须失败关闭而不是放行"
        );
    }
    // 当前前端确实没人用 import 形态（现状安全）—— 变了要么这条红、要么 ACL 测红。
    let mut files = Vec::new();
    collect_sources(&ui_src(), &mut files);
    assert!(
        !files.iter().any(|(_, s)| s.contains(DIALOG_MODULE)),
        "前端开始直接 import @tauri-apps/plugin-dialog 了 —— 复核 capabilities 授权面后更新本条"
    );
}

#[test]
fn dialog_import_detection_survives_multi_statement_files() {
    // A1 根因：旧实现从模块名 `rfind("import")` **回看整份文件**，stmt 于是从*上一条* import 的
    // 关键字一路切到本处 —— 只要文件里此前有任何一条带花括号的 import（真实源文件几乎必有），
    // `find('{')` / `rfind('}')` 就被上一条 import 的花括号满足 ⇒ 永远进不了 Opaque 分支，反而把
    // 上一条 import 的名字当成 dialog 的具名列表（需求集为空 ⇒ **静默全绿**，真机才炸 ACL）。
    //
    // 旧单测全绿只是因为用例都是**单行、无前置 import 的玩具输入** —— 这正是本缺陷藏住的直接原因。
    // 下面每条都带真实前置 import。
    const HEAD: &str = "import { useState } from 'react';\nimport { clsx } from 'clsx';\n";

    // ① 具名 import 仍须精确：前置 import 的名字不得混进 dialog 的需求集。
    assert_eq!(
        dialog_import(&format!(
            "{HEAD}import {{ save }} from '@tauri-apps/plugin-dialog';\nawait save({{}});"
        )),
        DialogImport::Named(vec!["save".into()]),
        "前置 import 的具名列表混进了 dialog 的需求集"
    );
    // ② 逃逸面穷举：旧实现在这些构造上一律返回 Named([\"useState\"]) ⇒ 需求为空 ⇒ 静默全绿。
    //    新实现一律失败关闭（不可判就让人来判，绝不默默放行）。
    for escape in [
        "export { save } from '@tauri-apps/plugin-dialog';",
        "export * from '@tauri-apps/plugin-dialog';",
        "export { confirm, save } from '@tauri-apps/plugin-dialog';",
        "const M = '@tauri-apps/plugin-dialog';\nconst d = await import(M);",
        "const d = require('@tauri-apps/plugin-dialog');",
        "import * as d from '@tauri-apps/plugin-dialog';",
        "const d = await import('@tauri-apps/plugin-dialog');",
        "import '@tauri-apps/plugin-dialog';",
        "import d, { save } from '@tauri-apps/plugin-dialog';",
        "import { save } from '@tauri-apps/plugin-dialog/foo';",
    ] {
        let src = format!("{HEAD}{escape}");
        assert_eq!(
            dialog_import(&src),
            DialogImport::Opaque,
            "{escape}（带前置 import）必须失败关闭"
        );
        assert!(
            required_dialog_perms(&src).is_err(),
            "{escape} 的调用面不可判，守卫必须失败关闭而不是放行"
        );
    }
    // ③ 多条 dialog import 并存：名字合并，不能只认其中一条。
    let two = format!(
        "{HEAD}import {{ save }} from '@tauri-apps/plugin-dialog';\n\
             import {{ ask }} from '@tauri-apps/plugin-dialog';"
    );
    let mut got = required_dialog_perms(&two).unwrap();
    got.sort_unstable();
    assert_eq!(got, ["dialog:allow-ask", "dialog:allow-save"]);
    // ④ 真实排版：dialog import 夹在中间，后面还有 export / 别的 import。
    let sandwich = format!(
        "{HEAD}import {{ message }} from '@tauri-apps/plugin-dialog';\n\
             import type {{ Foo }} from './foo';\nexport function go() {{}}\n"
    );
    assert_eq!(
        required_dialog_perms(&sandwich).unwrap(),
        ["dialog:allow-message"]
    );
}

#[test]
fn dialog_global_call_forms_are_in_the_detection_surface() {
    // 插件 init 脚本覆写的是**全局对象**，以下形态撞的是同一条 `plugin:dialog|confirm` ACL。
    // 只认字面量 `window.confirm(` 会全部漏掉：今天不成洞只因 allow-confirm 已授 —— 收回即逃逸；
    // 且反向哨兵「confirm 只许出现在 nativeConfirm 一处」对「别处裸用」根本不转红。
    for form in [
        "if (window.confirm('x')) {}",
        "if (await confirm('x')) {}",
        "if (window.confirm ('x')) {}",
        "if (window['confirm']('x')) {}",
        "if (window[\"confirm\"]('x')) {}",
        "if (globalThis.confirm('x')) {}",
    ] {
        assert_eq!(
            required_dialog_perms(form).unwrap(),
            ["dialog:allow-confirm"],
            "{form} 走 plugin:dialog|confirm，必须进检测面"
        );
    }
    assert_eq!(
        required_dialog_perms("alert('x')").unwrap(),
        ["dialog:allow-message"]
    );
    // 反向：不得过度命中 —— 他人成员 / 同前缀标识符不是被覆写的那个全局。过度命中会把无关文件
    // 拖进需求集，更会让反向哨兵的唯一命中面失真。
    for benign in [
        "dialog.confirm('x')",
        "reconfirm('x')",
        "confirmDelete('x')",
        "const confirmed = true;",
        "type Alerts = { alert: string };",
    ] {
        assert_eq!(
            required_dialog_perms(benign).unwrap(),
            Vec::<&str>::new(),
            "{benign} 不是 dialog 调用，守卫不许乱要权限"
        );
    }
}

// ── A2：四态派生（`resolve_tray_state` 的优先级）───────────────────────────────
//
// 断言全部走 `crate::tray::resolve_tray_state`（生产装配里 `reconcile_tray_icon` 调的就是它），
// 不在测试里另写一份判定 —— 否则删掉生产那行 `resolve_tray_state` 测试照样绿。

// ── 托盘点击所有权：mac/win 直派，Linux/未知平台交给原生菜单 ─────────────────────

#[test]
fn main_window_native_menu_is_macos_only() {
    assert_eq!(
        main_window_menu_owner(Platform::Mac),
        MainWindowMenuOwner::NativeApplicationMenu
    );
    for platform in [Platform::Win, Platform::Linux, Platform::Other] {
        assert_eq!(
            main_window_menu_owner(platform),
            MainWindowMenuOwner::RendererShortcut,
            "{platform:?} 自绘主窗不得挂原生 app menu，否则会多出 Polaris 横栏"
        );
    }

    let src = crate_code("main.rs");
    assert!(
        src.contains("if main_window_menu_owner(Platform::current())"),
        "setup 必须消费菜单所有权判据，不能只写一个无接线的纯函数"
    );
    // 拆开拼词，避免守卫自己的搜索字面量也出现在 include_str!("main.rs") 里。
    let hidden_menu_call = [".hide_", "menu()"].concat();
    assert!(
        !src.contains(&hidden_menu_call),
        "Win/Linux 不应先创建主窗原生菜单再尝试隐藏；应根本不挂菜单"
    );
}

// ── A7：原生菜单 id ↔ 动作解析（菜单与 handler 之间唯一的契约面）─────────────────
