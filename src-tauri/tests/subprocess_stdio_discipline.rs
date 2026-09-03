//! 子进程 stdio 处置纪律 —— 全仓源码级守卫门。
//!
//! # 守的是什么
//!
//! `Stdio::piped()` 只表达「把子进程的这一路输出接到一根管道上」，它**不**表达「有人会把这根管道读
//! 空」。两件事被拆在两个地方决定时，第二件就会被忘记：管道写满之后子进程的下一次 `write(2)`
//! 永久阻塞，进程既不退出也不再干活。2026-09-02 的测速临时核就是这条链——macOS 上 `debug` 档
//! 118 个请求只有 22 个拿到值、核回收耗时 5.0 s；同一份订阅换成 `info` 档是 111 个、58 ms。唯一
//! 变量是日志产量有没有越过管道容量（Linux 64 KiB / macOS 16 KiB）。
//!
//! 修好那一条腿不等于修好这一类缺陷。本门守的是**类**：全仓每一处打开管道的地方都必须能就地看出
//! 谁来排空它，新增一处而不登记、或者把排空写到等待之后，当场红。
//!
//! # 本仓的子进程 stdio 纪律（判据形态，逐条对应下面的断言）
//!
//! 1. **开管道的人负责排空**。任何出现 `Stdio::piped()` 的函数，其函数体内必须出现登记过的排空形态，
//!    且**排空必须早于等待**（`try_wait(` / `.wait()`）。先等后读是死锁形态：子进程等父进程读、
//!    父进程等子进程退出。`output()` 与 `wait_with_output()` 自身既是等待也是排空（两条流并发读到
//!    EOF），不受此限。可登记的排空形态是一个**闭合集合**，就是常量 [`KNOWN_DRAIN_FORMS`]；登记表里
//!    写了集合之外的串会当场红（否则「随手写个 `let ` 当排空形态」也能让门照绿）。
//!
//!    信用按 **spawn 语句**给，不按块给：块被按每一处起子进程的形态切成段，每一段必须自己有排空、
//!    且排空早于本段的等待。按块给信用分辨不出「排空的是块里另一个子进程」——在同一个函数里加一个
//!    piped 却从不读的预检子进程，块级的「首个排空早于首个等待」照样成立。
//! 2. **把管道交出去的人（producer）必须有登记在册的消费者**。`TokioSpawner` 自己不读，它把带管道
//!    的 `SpawnedChild` 交给调用方；每个调用方都必须排**两条**流。判据是「stdout 取管道形态与 stderr
//!    取管道形态**各出现 ≥1 次**」，不是「排空调用总次数 ≥ 2」——后者数的是形态出现次数而不是两条流，
//!    把 `take_stderr()` 误写成 `take_stdout()`（真实的复制粘贴错误形态）时总次数不变，而 stderr
//!    管道从此永不排空，正是本轮根因的原缺陷。少排一条与一条都不排在后果上没有区别：满的是哪根管道，
//!    写阻塞就发生在哪根上。
//! 3. **未登记的站点出现即红**。登记表就是审计面：新增一处 `Stdio::piped()`、或新增一处从 child 手里
//!    取走管道的地方，都必须在这份表里写清楚它的排空形态，写不出来就说明这条腿还没想清楚。
//!
//! # 取材面为什么是完整的
//!
//! 断言是全称命题（「全仓没有未处置的管道」），所以取材面不能是手写文件清单——手写清单的失效方式
//! 是「新增一个模块，清单不动，门照绿」。这里的取材面由两层派生：
//!
//! - **成员层**：`cargo metadata --no-deps` 报的 `workspace_members`，新增一个 crate 自动进面。
//!   **不按仓根 `Cargo.toml` 的 `[workspace] members` 字面解析**：cargo 会把 workspace 目录内被
//!   path 依赖引用到的 crate **隐式**纳为成员（`members = ["inner"]` 加一条指向 `plugins/extra` 的
//!   path 依赖，`workspace_members` 里就有 `extra`——本仓实测过）。于是在 `crates/` 之外新建一个
//!   crate 并 path 依赖它，代码照样编译进产品，而按字面解析的取材面**静默漏扫、门一声不吭**。
//!   字面表仍然解析，但只当**对差面**用：字面写了而 cargo 不认的条目即刻红；cargo 认而字面没写的
//!   隐式成员会被打印出来，让「面比你以为的宽」这件事自曝，而不是安静通过；
//! - **文件层**：每个成员调 [`polaris_source_probe::module_files_in`]，它**递归**遍历 `<member>/src`
//!   下的全部生产 `.rs`（自动排除 `tests/`，空取材面当场 panic）。本仓一个模块的源码天然横跨
//!   `foo.rs` 与 `foo/` 两处，目录遍历同时覆盖两者，写死单一路径只会扫到一半。
//!
//! 覆盖到的三块正是缺陷可能出现的全部地方：`src-tauri/src`（GUI 宿主）、`crates/*/src`（含
//! `crates/core-supervisor` 的起核入口与 `crates/system-integration` 的系统命令执行器）、以及
//! `crates/helper/src`——helper 以特权身份常驻运行，它卡死的后果比 app 侧更重，不能漏。
//!
//! # 为什么必须先剥注释与字符串
//!
//! 判据的针是**符号**（`Stdio::piped()`、`drain_to_log(`），而注释里几乎必然也写着这些串：本仓
//! `speedtest.rs` 与 `tailscale_login_core.rs` 的文档注释里就各有一处 `Stdio::piped()`，它们是在解释
//! 这个缺陷，不是在开管道。不剥的话，肯定型断言会被注释喂饱（把生产调用删光了门照绿——本仓
//! 2026-08-07 起同型撞过四次），否定型断言会被注释绊倒。故每份源码先过
//! [`polaris_source_probe::mask_comments_and_strings`]（抹成等长空格，偏移与行号守恒，失败信息才说得出
//! 第几行）。这一层是判据的一部分，不是清洁工——把它换成恒等函数，本门会立刻红（变异 M7）。
//!
//! # 与既有门的分工
//!
//! `windows_console_suppression.rs` 守的是「进程**怎么被创建**」（有没有挂 `CREATE_NO_WINDOW`），
//! 本门守的是「进程创建**之后**它的输出归谁」。批 A 在 `speedtest/tests` 里的两道门（内存 duplex
//! 灌满的行为门 + `drive_after_spawn` 的次序门）射程是测速这一条腿；本门的射程是全仓每一条腿。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

// ════════════════════════════════════════════════════════════════════════════
// 判据词表
// ════════════════════════════════════════════════════════════════════════════

/// 等待形态。函数体里出现其一，就说明这个函数会停下来等子进程；排空必须发生在它**之前**。
///
/// `.output()` / `wait_with_output(` 不在此列：它们并发读两条流直到 EOF，等待与排空是同一个动作。
const WAIT_FORMS: &[&str] = &["try_wait(", ".wait()"];

/// 从 child 手里取走 **stdout** 读端的形态。
const STDOUT_TAKE_FORMS: &[&str] = &[".stdout.take()", "take_stdout()"];

/// 从 child 手里取走 **stderr** 读端的形态。
///
/// 与 [`STDOUT_TAKE_FORMS`] 分成两张表，是因为纪律 2 要求的是**两条流各自**被取走。合成一张表之后
/// 就只数得出「取管道这个动作发生了几次」，而 `take_stderr()` 被误写成 `take_stdout()` 时这个次数
/// 一点不变——那正是本轮根因的原缺陷形态。
const STDERR_TAKE_FORMS: &[&str] = &[".stderr.take()", "take_stderr()"];

/// 取走管道读端的全部形态（两条流的并集）。取走了就要负责读空，故每一处都必须落在登记过的块里。
///
/// 并集写死而不是现场拼，是为了让「三张表悄悄漂开」当场可见：
/// [`the_take_form_tables_stay_in_sync`] 断言它逐字等于两张分表的拼接。
const PIPE_TAKE_FORMS: &[&str] = &[
    ".stdout.take()",
    "take_stdout()",
    ".stderr.take()",
    "take_stderr()",
];

/// 开管道的形态。
const PIPED_FORM: &str = "Stdio::piped()";

/// **做出「这个子进程的两条输出流归谁」这个决定**的形态。
///
/// 类型层收口之后，管道开不开、谁来读，全由 `SpawnRequest.stdio: StdioPolicy` 这一格决定，而这一格
/// 是**必填**的（少写编不过，`error[E0061]`/`error[E0063]`）。于是「新起一条核腿」这件事在源码上
/// 一定留下一处 `StdioPolicy::` —— 它就是本门的新针脚。
///
/// 为什么必须补这一针：G3 原来的针是 `Stdio::piped()` 与「从 child 取走读端」。收口之后这两样都缩
/// 进了 spawner 内部，新写一条核腿的人**一处都不会碰到**，只会写一行 `StdioPolicy::Discard`（编得过，
/// 核的输出被内核整段丢弃）或者一个丢掉某条流的回调。不补这一针，G3 对新腿一声不吭 —— 那正是
/// 「新路径绕开旧闸门」的形态。
const POLICY_FORM: &str = "StdioPolicy::";

/// 起一个新子进程的形态。G1 的信用按它切段——每一处起子进程都得自己交代它的两条管道谁来读。
///
/// `.output()` 也算「起子进程」：它是 spawn + 并发读两条流 + 等待三合一，段的起点仍是它。
/// `.spawn()` 写成不带实参的形态是有意的：`Command::spawn` 不收参数，而 `thread::spawn(closure)` /
/// `tokio::spawn(fut)` / `spawner.spawn(&req)` 都带实参，写成 `.spawn()` 就不会把线程池和 trait
/// 调用误当成起进程。
const CHILD_CREATION_FORMS: &[&str] = &[".spawn()", ".output()"];

/// 自带排空语义的等待形态：并发读两条流直到 EOF，等待与排空是同一个动作。
///
/// 它们对任何站点都算「这一段的排空」，不必逐站点登记。
const SELF_DRAINING_FORMS: &[&str] = &[".output()", "wait_with_output("];

/// 允许出现在登记表 `drain_forms` / `drain_form` 里的排空形态——**闭合集合**。
///
/// 判据里的自由字符串是「门在但没牙」的经典入口：`drain_forms` 若不校验，写成 `&["let "]` 门就照绿，
/// 而失败信息还会一本正经地说「找到了登记的排空形态」。故登记表里的每一个串都必须落在本集合内，
/// 越界当场红（[`every_registered_drain_form_is_a_known_form`]）。
///
/// 新增一种排空形态时，先往这里加一行——那一行就是「这个仓认这种写法算把管道读空了」的显式表态。
const KNOWN_DRAIN_FORMS: &[&str] = &[
    ".output()",
    "wait_with_output(",
    "spawn_pipe_loggers_with_file",
    "spawn_pipe_loggers_with_preopened_files",
    "spawn_pipe_drainers",
    "pipe_to_log(",
    "drain(",
    "lines()",
    // 直接读到 EOF。**这一条今天没有任何生产站点在用**，它在集合里是因为它是 `resolvectl` 那条腿在
    // 修复前用的排空形态：那条腿真的读了管道，只是读在 `try_wait` 轮询**之后**。次序腿的历史真缺陷
    // 回放（`the_order_leg_is_red_on_the_historical_resolvectl_defect`）要能登记它，才谈得上「排空
    // 形态在场、红的是次序」——否则回放红在「形态缺失」上，次序那一半仍旧没有被真缺陷证明过。
    "read_to_string(",
];

/// 「带着两条未排空管道的 child」这件事在**类型**上的全部落点。
///
/// 判据钉在类型名上，不钉在接收者变量名上。原先的词表是 `spawner.spawn(` / `Spawner::new().spawn(`，
/// 它按调用点的**变量名**匹配，于是有两个方向的错：写 `let sb = TokioSpawner::default(); sb.spawn(&req)`
/// 就整个逃掉（一条流都不排也照绿），而 helper 里任何叫 `*spawner` 的接收者又会被误捕、逼着加豁免
/// （`linux/handler.rs` 的 `CoreSpawner` 就被迫加过一条）。**被判据逼出来的豁免是判据错了，不是使用者
/// 错了**：换成类型面之后 helper 那条豁免自然消失——它从来就不碰这几个类型。
///
/// 面里包含 trait 名（`SingBoxSpawner` / `LoginCoreSpawner`）而不只是具体类型：新消费者完全可以只
/// 拿着 trait object 起核（`deps.spawner.spawn(&req)`，`deps` 的类型是 `dyn LoginCoreSpawner`），
/// 一个具体类型名都不写。
const SPAWNER_TYPE_FORMS: &[&str] = &[
    "TokioSpawner",
    "SpawnedChild",
    "SingBoxSpawner",
    "LoginCoreSpawner",
    "LoginCoreChild",
];

/// [`SPAWNER_TYPE_FORMS`] 的「家」：定义与再导出所在的文件。
///
/// 它们提到这些类型是在**定义**它们，不是在消费管道，故不要求登记为消费者。除此之外的任何生产文件
/// 一旦提到这些类型，就必须是注册表 2 里的消费者——新写一个消费者却不登记，文件集合对差当场红。
const SPAWNER_TYPE_HOME: &[&str] = &[
    "crates/core-supervisor/src/lib.rs",
    "crates/core-supervisor/src/spawner.rs",
];

/// 构造一个 spawn 请求的形态。**两种写法都要盖住**：构造函数与结构体字面量 —— 字段全 `pub`，
/// 绕开构造函数直接写字面量一样编得过（少写 `stdio` 那一格才编不过）。
const REQUEST_FORMS: &[&str] = &["SpawnRequest::new(", "SpawnRequest {"];

/// 选择「开管道 + 排空」这条分支的形态（构造函数与枚举变体两种写法）。
const POLICY_DRAIN_FORM: &str = "StdioPolicy::drain(";

/// 起核构造点的形态（类型面）。每一处都必须落在注册表 2 的消费者块或排除项块里。
///
/// 与文件集合对差互补：文件集合挡「新文件里冒出一个消费者」，构造点覆盖挡「已登记文件里、已登记块
/// **之外**又起了一个核」。
const SPAWNER_CONSTRUCTION_FORM: &str = "TokioSpawner::";

// ════════════════════════════════════════════════════════════════════════════
// 注册表 1：每一处 `Stdio::piped()` 的宿主块
// ════════════════════════════════════════════════════════════════════════════

/// 站点性质。
#[derive(PartialEq, Eq, Clone, Copy)]
enum SiteKind {
    /// 自己开管道、自己排空。
    Sink,
    /// 开了管道就把 child 交出去，排空由注册表 2 里的消费者负责。
    Producer,
}

/// 一处开管道的站点。
struct PipedSite {
    /// 仓根相对路径（`/` 分隔）。
    file: &'static str,
    /// 唯一块锚。取的是**块**（`fn` 或 `impl`）的签名，块体按花括号配平切出，不猜行数。
    anchor: &'static str,
    kind: SiteKind,
    /// `Sink` 必填：块体内**全部**必须出现的排空形态，每一个都必须取自 [`KNOWN_DRAIN_FORMS`]。
    ///
    /// 是合取不是析取——登记的是这条腿**实际用的**排空形态清单，不是「随便命中一个就算数」。
    /// 有退化腿的站点（预开日志文件失败 → 退成纯排空）两条都要在，因为退化腿同样是生产路径。
    drain_forms: &'static [&'static str],
}

/// 全仓开管道的站点，按仓根相对路径排序。
///
/// **不在表里 = 违规**。新增一处 `Stdio::piped()` 必须在这里补一行，并同时写出它的排空形态——
/// 写不出来说明这条腿还没想清楚谁来读它。
const PIPED_SITES: &[PipedSite] = &[
    // ── crates/core-supervisor ──
    PipedSite {
        file: "crates/core-supervisor/src/config_gate.rs",
        // 全仓唯一的 `sing-box check` 子进程实现：起核闸门、瞬态核起前自检、「测试内核兼容性」
        // 按钮三处共用它。锚点随管道走 —— 管道从 `run_config_check_within` 挪进了它调用的这一层。
        anchor: "pub async fn run_check_raw(",
        kind: SiteKind::Sink,
        // 本仓短命腿的最佳形态：`output()` 并发读两条流 + `timeout` + `kill_on_drop(true)`。
        drain_forms: &[".output()"],
    },
    PipedSite {
        file: "crates/core-supervisor/src/spawner.rs",
        anchor: "impl SingBoxSpawner for TokioSpawner {",
        // 三条 sing-box 核腿共用的起核入口。它自己不读，但**在返回之前**就把两个读端交给请求里的
        // `StdioPolicy::Drain` 回调 —— 那个回调写在调用方的块里，故排空责任仍落在注册表 2。
        // 类型层保证的是「交出去这件事一定发生」，保证不了「回调真的把两条都读了」，后者由
        // 注册表 2 的判据守。
        kind: SiteKind::Producer,
        drain_forms: &[],
    },
    // ── crates/helper（特权守护进程 / 服务；卡死后果比 app 侧重）──
    PipedSite {
        file: "crates/helper/src/platform/linux/resolved_dns.rs",
        anchor: "fn run_resolvectl(",
        kind: SiteKind::Sink,
        // 读线程先起、再进 `try_wait` 轮询（与 `system-integration::StdCommandRunner` 同款）。
        drain_forms: &["drain("],
    },
    PipedSite {
        file: "crates/helper/src/platform/linux/server.rs",
        anchor: "impl CoreSpawner for AmbientCapsSpawner {",
        kind: SiteKind::Sink,
        drain_forms: &["spawn_pipe_loggers_with_file"],
    },
    PipedSite {
        file: "crates/helper/src/platform/macos/exec.rs",
        anchor: "fn run_with_timeout(",
        kind: SiteKind::Sink,
        drain_forms: &["wait_with_output("],
    },
    PipedSite {
        file: "crates/helper/src/platform/macos/server.rs",
        anchor: "fn do_spawn(",
        kind: SiteKind::Sink,
        // 预开日志文件成功走 loggers，失败退化成纯 drainers —— 两条都是生产路径，故两个形态都要在。
        drain_forms: &[
            "spawn_pipe_loggers_with_preopened_files",
            "spawn_pipe_drainers",
        ],
    },
    PipedSite {
        file: "crates/helper/src/platform/windows/winproc/win.rs",
        anchor: "fn start_singbox(",
        kind: SiteKind::Sink,
        drain_forms: &[
            "spawn_pipe_loggers_with_preopened_files",
            "spawn_pipe_drainers",
        ],
    },
    // ── crates/system-integration ──
    PipedSite {
        file: "crates/system-integration/src/exec.rs",
        anchor: "impl CommandRunner for StdCommandRunner {",
        kind: SiteKind::Sink,
        // 本仓最早把「先轮询后读会死锁」写进文档的地方，也是 300 KB 灌满行为门的被测对象。
        drain_forms: &["drain("],
    },
    // ── src-tauri（GUI 宿主进程）──
    //
    // 这里曾有两条 `sing-box check` 的自开管道站点（`commands/proxy.rs::run_probe_check` 与
    // `tailscale_login_core.rs::SingBoxConfigChecker`）。两处已折叠进
    // `core-supervisor::config_gate::run_check_raw`（本表第一条），src-tauri 侧不再开这两根管道，
    // 故条目随站点一起消失 —— **不是把判据放宽**：G3 的扫描面对差仍覆盖这两个文件，任何一处新写的
    // `Stdio::piped()` 不登记就当场红。
    PipedSite {
        file: "src-tauri/src/runtime/proxy/network_monitor.rs",
        anchor: "async fn route_network_watcher_once(",
        kind: SiteKind::Sink,
        // 长命腿：`route -n monitor` / `ip monitor` 的 stdout 由 `select!` 逐行读到进程结束。
        drain_forms: &["lines()"],
    },
];

// ════════════════════════════════════════════════════════════════════════════
// 注册表 2：共享 spawner 交出的管道由谁排空
// ════════════════════════════════════════════════════════════════════════════

/// 一个消费者：从 `TokioSpawner` 拿到 child 之后负责排空两条流的块。
struct Consumer {
    file: &'static str,
    anchor: &'static str,
    /// 排空形态，必须取自 [`KNOWN_DRAIN_FORMS`]。
    drain_form: &'static str,
    /// **逐条流的精确接线**（判据打在「去掉全部空白」的形上）。
    ///
    /// # 为什么计数不够（这是一次实测出来的完整逃逸）
    ///
    /// 只数 `drain_form` 的出现次数时，「回调收下两条流却丢掉一条」可以用**任何**第二次调用把计数
    /// 补回去：把两条腿的回调都改成 `|stdout, _stderr|`、再补一行
    /// `pipe_to_log(tokio::io::empty(), TARGET, None, None);` —— 编得过、计数仍是 2、本门与批 A 的
    /// 源码门**全绿**，而两条腿的 stderr 从此无人读。计数证明的是「调用发生了 N 次」，证明不了
    /// 「**哪条流**喂给了**哪次**调用」。
    ///
    /// 故每个消费者逐条登记它的接线串：策略头（含回调的两个形参名）+ 每条流一次调用，形如
    /// `pipe_to_log(<形参>,<TARGET>,…`。形参名进判据是有意的 —— 把 `stderr` 改成 `_stderr` 就是
    /// 「这条流不打算读了」的声明，那必须是一次要重新登记的改动，不是悄悄改个绑定名。
    ///
    /// 钉在**去空白**的形上而不是原文：这几处接线写在闭包里，缩进随闭包层级变，钉死缩进的断言
    /// 一次 `cargo fmt` 就失去判据 —— 而失去判据的门是绿的。主核那两条源码门
    /// （`proxy/tests/startup.rs` / `proxy/tests/core_log.rs`）早就在用这个形态，此处复用它。
    ///
    /// 每条形态按块内请求数缩放（一个块起两个核 ⇒ 每条形态各要 2 次）。
    /// 登记表本身的防腐见 [`every_registered_wiring_binds_both_callback_params`]。
    wiring: &'static [&'static str],
}

/// 全部 `TokioSpawner` 消费者 —— 收口之后，「消费者」= **构造 `SpawnRequest` 并在里面写下 stdio
/// 处置**的那个块。
///
/// # 判据为什么换了钉法（这不是放宽）
///
/// 收口之前 child 是带着两条活管道离开 spawner 的，于是「有没有排空」这件事在消费者块里表现为
/// **取管道**（`take_stdout()` / `.stderr.take()`），判据是「两条流各被取走 ≥ 1 次」。收口之后
/// 取管道的动作缩进了 spawner 内部，消费者块里一处都没有了 —— 旧判据在新源码上恒红（它守的对象
/// 消失了），必须换钉法。
///
/// 换成什么：**每构造一个请求，就要有一份 `Drain` 策略、并且策略里两条流各被读一次**。
/// 逐条对上旧判据守的向量：
///
/// | 旧判据守的 | 收口后由谁守 |
/// |---|---|
/// | 一条流都不排（测速临时核的原缺陷） | 编译器：`stdio` 必填，写不出「没有处置」的请求；本表再要求它是 `Drain` 而不是 `Discard` |
/// | `take_stderr()` 误写成 `take_stdout()`（同一条流排两遍，另一条永不排） | 编译器：回调按值收两条流，同一条流排两遍是 `use of moved value` |
/// | 排空写在等待之后 | 编译器：回调在 spawner 返回前就被调用，调用方拿到 child 时已经没有管道可等 |
/// | 回调里把某条流直接丢掉（`\|out, _err\| …`） | **只有本表**：[`Consumer::wiring`] 的逐条流精确接线 |
///
/// 最后一行是类型层唯一管不到的一格，也正是本表继续存在的理由。**它一度只由计数守着，而计数补得
/// 回来**（见 [`Consumer::wiring`] 的文档），三条腿因此全部换成逐条流的精确接线。
const PRODUCER_CONSUMERS: &[Consumer] = &[
    Consumer {
        file: "src-tauri/src/runtime/proxy/startup.rs",
        anchor: "pub(super) async fn start_inner(",
        drain_form: "pipe_to_log(",
        // 主核：两条流各带交接闸，只有 stderr 接起核真因槽（`log.Fatal` 恒写 os.Stderr）。
        wiring: &[
            "StdioPolicy::drain(move|stdout,stderr|{",
            "pipe_to_log(stdout,SING_BOX_TARGET,None,",
            "pipe_to_log(stderr,SING_BOX_TARGET,Some(sink_fatal),",
        ],
    },
    Consumer {
        file: "src-tauri/src/runtime/speedtest.rs",
        // 锚点在**批级**入口：T1-R1 分批之后 `TempCoreSession::run` 变成轮级薄壳（切批 + 心跳 +
        // 唯一终态），起核那一段连同 spawn 请求的构造留在 `run_batch` —— 分批**没有**新开第二条
        // spawn 路径，它仍然是全 app 唯一那份 `SpawnRequest` 装配。
        anchor: "async fn run_batch<Meas, MeasFut>(",
        drain_form: "pipe_to_log(",
        // 测速临时核：本轮根因所在的那条腿。target 必须是它自己的，`fatal`/`handoff` 都没有。
        wiring: &[
            "StdioPolicy::drain(|stdout,stderr|{",
            "pipe_to_log(stdout,SPEEDTEST_CORE_TARGET,None,None);",
            "pipe_to_log(stderr,SPEEDTEST_CORE_TARGET,None,None);",
        ],
    },
    Consumer {
        file: "src-tauri/src/runtime/tailscale_login_core.rs",
        anchor: "pub async fn start_login(",
        drain_form: "pipe_to_log(",
        // 瞬态登录核：整改前这条腿在源码级上是**零门**（计数判据被一行补计数的调用绕过），
        // 而它与临时核共用同一个 spawner、同一份排空实现，缺陷形态完全同构。
        wiring: &[
            "StdioPolicy::drain(|stdout,stderr|{",
            "pipe_to_log(stdout,LOGIN_CORE_LOG_TARGET,None,None);",
            "pipe_to_log(stderr,LOGIN_CORE_LOG_TARGET,None,None);",
        ],
    },
];

/// 起核构造点（[`SPAWNER_CONSTRUCTION_FORM`]）里不算作「消费者」的那些。
///
/// 每条必须**恰好**盖住一处构造点，理由写清楚。
///
/// 表从两条缩到一条不是放宽判据，而是判据换了钉法之后其中一条**失去了对象**：
/// `linux/handler.rs::handle_start` 从来不碰 `TokioSpawner`（helper 有自己的 `CoreSpawner`），
/// 它当初进这张表只是因为旧词表按接收者变量名 `spawner.spawn(` 匹配，把它误捕了。
struct SpawnExclusion {
    file: &'static str,
    anchor: &'static str,
    reason: &'static str,
}

const SPAWN_EXCLUSIONS: &[SpawnExclusion] = &[SpawnExclusion {
    file: "src-tauri/src/runtime/tailscale_login_core.rs",
    anchor: "impl LoginCoreSpawner for TokioLoginCoreSpawner {",
    reason: "装箱适配自身：只把 SpawnedChild 换成 LoginCoreChild，两条管道原样透传给真正的消费者 supervise",
}];

/// 只把管道**透传**给上层、自己不排空的块。
///
/// 与 `Producer` 站点同理：它们不开管道，只是把读端从 child 手里递出去。排空责任落在拿到读端的人
/// 身上，而那个人已经在注册表 2 里。
struct Passthrough {
    file: &'static str,
    anchor: &'static str,
    reason: &'static str,
}

/// **当前为空**。唯一那条（`impl LoginCoreChild for TokioLoginCoreChild {`）在 stdio 收口时失去了
/// 对象：`LoginCoreChild` 已经没有 `take_stdout` / `take_stderr` 了，读端在 spawner 里就交给了
/// 请求上的排空回调，没有任何一层再做「只透传不排空」。删它不是放宽判据 —— 防腐规则要求每条透传
/// 项必须真盖住至少一处取管道的地方，留着它反而会让本门恒红（实测过一次，正是它把红报出来的）。
///
/// 机制保留：下一个真要透传的人得落进这套规则里，而不是自己新起一张没有过期检查的表。
const PIPE_PASSTHROUGH: [Passthrough; 0] = [];

// ════════════════════════════════════════════════════════════════════════════
// 豁免
// ════════════════════════════════════════════════════════════════════════════

/// 豁免表：允许某个站点不满足纪律 1（排空形态 / 排空早于等待），但**不能**免掉登记本身。
///
/// 规则抄 `test_source_anchors.rs` 的防腐形态：每条必须**恰好命中一次**。命中 0 次说明它守的东西
/// 已经没了，条目本身成了将来某个真违规的免死金牌；命中多次说明一条豁免悄悄盖住了它没打算覆盖的
/// 地方。`reason` 与 `tracked_by` 都必须非空——豁免要能被审计，不能是随手加一行就静默过。
///
/// **当前为空**。设计阶段唯一的候选是 helper 的 `resolvectl` 腿（先 `try_wait` 后读，与
/// `exec.rs` 文档里警告过的死锁形态同构，靠「输出 < 1 KiB + 5 s 超时」侥幸不发作）；本批把它改成了
/// 读线程先起，于是没有真缺陷需要占位。机制照样留着：下一个要开豁免的人必须落进这套规则里，
/// 而不是自己新起一个没有过期检查的例外表。
const EXEMPT: [Exempt; 0] = [];

struct Exempt {
    file: &'static str,
    anchor: &'static str,
    /// 为什么这条可以不满足纪律 1。写清楚是为了让下一个人判断得了它还该不该在。
    reason: &'static str,
    /// 谁在跟这条债。空 = 无人认领 = 不该豁免。
    tracked_by: &'static str,
}

// ════════════════════════════════════════════════════════════════════════════
// 取材
// ════════════════════════════════════════════════════════════════════════════

/// 一份被扫描的生产源码。
struct Scanned {
    /// 仓根相对路径（`/` 分隔）。
    rel: String,
    /// 符号面：注释与字符串/字符/字节字面量已抹成等长空格，偏移与行号守恒。
    masked: String,
}

fn workspace_root() -> PathBuf {
    polaris_source_probe::workspace_root_from(env!("CARGO_MANIFEST_DIR"))
}

/// 成员目录：以 `cargo metadata --no-deps` 报的 `workspace_members` 为准，字面 `members` 只作对差。
///
/// # 为什么不能按字面解析
///
/// cargo 会把 workspace 目录内被 path 依赖引用到的 crate **隐式**纳为成员：仓根写
/// `members = ["inner"]`，而 `inner` 有一条 `extra = { path = "../plugins/extra" }`，
/// `cargo metadata` 报的 `workspace_members` 里就有 `extra`（本仓在 `/var/tmp` 的合成 workspace 上
/// 实测过，也在本仓真实 workspace 上实测过：临时给 `crates/source-probe` 加一条指向 `plugins/probe`
/// 的 path 依赖，成员数从 20 变 21）。于是在 `crates/` 之外新建一个 crate 并 path 依赖它，代码照常
/// 编译进产品，而按字面解析的取材面**静默漏扫**——门不报错，只是从此扫不到那块地方。
///
/// 这条属于「自动化必须让『没执行』自曝」：门漏扫必须自己喊出来。故字面表继续解析，但只当对差面：
/// 字面写了而 cargo 不认 ⇒ 当场红（字面表已经过期或解析坏了）；cargo 认而字面没写 ⇒ 是隐式成员，
/// 进取材面并打印出来，让「面比你以为的宽」这件事留下痕迹。
///
/// # Panics
///
/// `cargo metadata` 跑不起来 / 非零退出 / 输出不是预期 JSON，一律 panic —— 取材面推导失败必须转红，
/// 而不是退回那条已知会漏扫的字面路径。
fn workspace_members(root: &Path) -> Vec<PathBuf> {
    let from_cargo = members_from_cargo_metadata(root);
    let from_manifest = members_from_manifest_literal(root);

    for literal in &from_manifest {
        assert!(
            from_cargo.contains(literal),
            "仓根 `Cargo.toml` 的 `members` 里写着 `{}`，`cargo metadata --no-deps` 却不认它 —— \
             字面表已经过期或解析坏了，本门的取材面推导不能在这种状态下继续",
            literal.display()
        );
    }
    let implicit: Vec<&PathBuf> = from_cargo
        .iter()
        .filter(|m| !from_manifest.contains(m))
        .collect();
    if !implicit.is_empty() {
        println!("── 隐式成员（cargo 认、字面 `members` 没写；已进取材面）──");
        for member in implicit {
            println!("  {}", member.display());
        }
    }
    from_cargo
}

/// `cargo metadata --no-deps` 的 `workspace_members`（`--no-deps` 下 `packages` 就是成员本身）。
///
/// `--offline` 是硬要求：本门是纯源码判据，不该因为网络而红/绿，也不该在 CI 上去碰 registry。
/// `--no-deps` 不做依赖解析，离线恒可用。
fn members_from_cargo_metadata(root: &Path) -> Vec<PathBuf> {
    let manifest = root.join("Cargo.toml");
    let out = std::process::Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--no-deps",
            "--offline",
            "--format-version",
            "1",
        ])
        .arg("--manifest-path")
        .arg(&manifest)
        .output()
        .unwrap_or_else(|err| panic!("跑不起来 `cargo metadata`（{err}）—— 取材面推导失败"));
    assert!(
        out.status.success(),
        "`cargo metadata --no-deps` 非零退出（{}）：\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let meta: serde_json::Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|err| panic!("`cargo metadata` 的输出不是 JSON（{err}）"));
    let packages = meta["packages"]
        .as_array()
        .expect("`cargo metadata` 输出里没有 `packages` 数组");
    let mut members: Vec<PathBuf> = packages
        .iter()
        .map(|pkg| {
            let path = pkg["manifest_path"]
                .as_str()
                .expect("`packages[].manifest_path` 不是字符串");
            PathBuf::from(path)
                .parent()
                .expect("manifest_path 没有父目录")
                .to_path_buf()
        })
        .collect();
    members.sort();
    assert!(
        !members.is_empty(),
        "`cargo metadata --no-deps` 报了 0 个成员 —— 取材面为空，本门会恒真"
    );
    members
}

/// 仓根 `Cargo.toml` 的 `[workspace] members` 字面展开（形态抄 `test_source_anchors.rs`）。
///
/// 只用作 [`workspace_members`] 的对差面，**不再单独充当取材面**（理由见那里）。
fn members_from_manifest_literal(root: &Path) -> Vec<PathBuf> {
    let manifest =
        std::fs::read_to_string(root.join("Cargo.toml")).expect("读不到 workspace 根 Cargo.toml");
    let masked = mask_toml_comments(&manifest);
    let start = masked
        .find("members")
        .expect("workspace 根 Cargo.toml 没有 members");
    let open = masked[start..].find('[').expect("members 后面没有 `[`") + start;
    let close = masked[open..].find(']').expect("members 列表没有闭合 `]`") + open;

    let mut members = Vec::new();
    for raw in manifest[open + 1..close].split(',') {
        let entry = raw.trim().trim_matches('"').trim();
        if entry.is_empty() {
            continue;
        }
        if let Some(prefix) = entry.strip_suffix("/*") {
            let dir = root.join(prefix);
            let entries = std::fs::read_dir(&dir).unwrap_or_else(|err| {
                panic!("读不到 members 通配目录 `{}`（{err}）", dir.display())
            });
            for child in entries.flatten() {
                let path = child.path();
                if path.join("Cargo.toml").is_file() {
                    members.push(path);
                }
            }
        } else {
            members.push(root.join(entry));
        }
    }
    members.sort();
    assert!(
        !members.is_empty(),
        "字面 `members` 解析出来是空的 —— 对差面没了，隐式成员从此无人对账"
    );
    members
}

/// TOML 行注释抹成空格（保留长度与换行），避免注释里的 `members` 把定位带偏。
fn mask_toml_comments(source: &str) -> String {
    source
        .lines()
        .map(|line| match line.find('#') {
            Some(at) => format!("{}{}", &line[..at], " ".repeat(line.len() - at)),
            None => line.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// 全部生产源码的符号面，按仓根相对路径升序。
fn scan_surface() -> Vec<Scanned> {
    let root = workspace_root();
    let mut out = Vec::new();
    for member in workspace_members(&root) {
        let member_rel = member
            .strip_prefix(&root)
            .unwrap_or(&member)
            .to_string_lossy()
            .replace('\\', "/");
        for (file_rel, text) in polaris_source_probe::module_files_in(&member, "") {
            out.push(Scanned {
                rel: format!("{member_rel}/src/{file_rel}"),
                masked: polaris_source_probe::mask_comments_and_strings(&text),
            });
        }
    }
    out.sort_by(|a, b| a.rel.cmp(&b.rel));
    assert!(
        out.len() > 50,
        "只扫到 {} 个文件 —— 遍历坏了，绿没有信息量",
        out.len()
    );
    out
}

fn surface_by_path(surface: &[Scanned]) -> BTreeMap<&str, &Scanned> {
    surface.iter().map(|s| (s.rel.as_str(), s)).collect()
}

fn file_of<'a>(index: &BTreeMap<&str, &'a Scanned>, rel: &str) -> &'a Scanned {
    index.get(rel).copied().unwrap_or_else(|| {
        panic!("`{rel}` 不在取材面里 —— 文件被改名/搬走了，登记项已失去对象，不是「通过」")
    })
}

// ════════════════════════════════════════════════════════════════════════════
// 切片
// ════════════════════════════════════════════════════════════════════════════

/// 锚点所属块的字节区间（含锚点自身，到与块首 `{` 配平的 `}` 为止）。
///
/// # 为什么按花括号配平，而不是按「锚点之后 N 行」
///
/// 本门的两条断言对切片宽度都敏感，而且方向相反：次序断言（排空早于等待）要求切片**盖得住**函数里
/// 的等待，切窄了等待落在窗口外、断言恒真；计数断言（排空至少两次）要求切片**不越界**，切宽了隔壁
/// 函数里的同名调用会替被守的那处作证。固定行数没法同时满足这两头，只能靠人一个个去数——而数错的
/// 那一次不会红，只会静默失去判据。
///
/// # 为什么在这里数花括号是安全的
///
/// 取材面已经过 [`polaris_source_probe::mask_comments_and_strings`]：注释与字符串/字符/字节字面量
/// 整段被抹成空格。会骗过计数器的那几类花括号（注释里的、字面量里的）在这个面上根本不存在，所以
/// 词法上是配平的。这也是本门必须先净化再取材的第二个理由。
///
/// # Panics
///
/// 锚点不存在 / 不唯一 / 块没有闭合花括号，一律 panic —— 门失去判据时必须转红，而不是静默退化成
/// 「扫了个空片、断言恒真」。
fn block_range(scanned: &Scanned, anchor: &str) -> (usize, usize) {
    let hits = scanned.masked.matches(anchor).count();
    assert_eq!(
        hits, 1,
        "{}：锚点 `{anchor}` 命中 {hits} 次（应为 1）。\
         为 0 = 锚点消失（改名/删除？），门已失去判据，不是「通过」；\
         >1 = 切片指向哪一处取决于书写顺序，必须把锚点写长到唯一。",
        scanned.rel
    );
    let start = scanned.masked.find(anchor).expect("上面已断言恰好一处");
    let bytes = scanned.masked.as_bytes();
    let mut i = start;
    while i < bytes.len() && bytes[i] != b'{' {
        i += 1;
    }
    assert!(
        i < bytes.len(),
        "{}：锚点 `{anchor}` 之后没有 `{{` —— 它不是一个块的签名",
        scanned.rel
    );
    let mut depth = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return (start, i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    panic!(
        "{}：锚点 `{anchor}` 的块没有闭合 —— 花括号配平走到文件尾",
        scanned.rel
    )
}

fn block_of<'a>(scanned: &'a Scanned, anchor: &str) -> &'a str {
    let (start, end) = block_range(scanned, anchor);
    &scanned.masked[start..end]
}

/// 字节偏移 → 1 起的行号。
fn line_at(scanned: &Scanned, offset: usize) -> usize {
    line_in(&scanned.masked, offset)
}

/// 任意文本里的字节偏移 → 1 起的行号（切片自己的行号，用于块内 / 段内定位）。
fn line_in(text: &str, offset: usize) -> usize {
    text[..offset].bytes().filter(|b| *b == b'\n').count() + 1
}

/// `needles` 里任意一个在 `haystack` 中的**最早**出现位置。
fn first_of(haystack: &str, needles: &[&str]) -> Option<usize> {
    needles.iter().filter_map(|n| haystack.find(n)).min()
}

/// `needles` 里全部形态在 `haystack` 中的出现次数之和。
fn count_of(haystack: &str, needles: &[&str]) -> usize {
    needles.iter().map(|n| haystack.matches(n).count()).sum()
}

/// `needle` 在 `haystack` 里的全部字节偏移。
fn offsets_of(haystack: &str, needle: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(at) = haystack[from..].find(needle) {
        out.push(from + at);
        from += at + needle.len();
    }
    out
}

/// 该文件里被登记覆盖的全部块区间（注册表 1 + 注册表 2 + 透传表）。
fn covered_ranges(index: &BTreeMap<&str, &Scanned>, rel: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for site in PIPED_SITES.iter().filter(|s| s.file == rel) {
        out.push(block_range(file_of(index, rel), site.anchor));
    }
    for consumer in PRODUCER_CONSUMERS.iter().filter(|c| c.file == rel) {
        out.push(block_range(file_of(index, rel), consumer.anchor));
    }
    for pass in PIPE_PASSTHROUGH.iter().filter(|p| p.file == rel) {
        out.push(block_range(file_of(index, rel), pass.anchor));
    }
    out
}

fn is_exempt(file: &str, anchor: &str) -> Option<&'static Exempt> {
    EXEMPT.iter().find(|e| e.file == file && e.anchor == anchor)
}

// ════════════════════════════════════════════════════════════════════════════
// 判据本体（纯函数）
// ════════════════════════════════════════════════════════════════════════════
//
// G1 / G2 的判断逻辑都抽成对「一段净化过的块体」求值的纯函数，理由不是好看：绕过路径要能被测试
// 钉住，就得能把「按那条路径写出来的源码片段」直接喂进判据本身。喂真文件做不到这件事——真文件里
// 没有那些绕过形态，而为了钉住判据去把绕过写进生产码是本末倒置。

/// G1 对一个 `Sink` 块的判据。`Ok(())` = 这个块守纪律；`Err` = 失败原因（不含文件名，由调用方拼）。
///
/// 两层：
///
/// 1. **形态合取**：登记的每一种排空形态都必须在块里出现（退化腿也是生产路径，见 `drain_forms` 文档）；
/// 2. **按 spawn 语句给信用**：块按 [`CHILD_CREATION_FORMS`] 切成段，每一段（= 一个子进程的一生）
///    自己必须有排空，且排空早于本段的等待。
///
/// 第 2 层是本判据与「按块给信用」的全部差别。按块给信用只看「块里最早的排空」与「块里最早的等待」
/// 谁在前，于是分辨不出排空的是**哪个**子进程：在 `run_resolvectl` 的排空线程之后再加一个
/// `Stdio::piped()` 却从不读、只 `.wait()` 的预检子进程，块级次序完全不变，门照绿，而那个预检子进程
/// 的两条管道一根都没人读。切成段之后，预检那一段里没有任何排空形态，当场红。
///
/// **射程要写准**：本判据是**词法**判据，看得见文本次序，看不见控制流。把某一段的排空整个包进
/// `if cond { … }` 它抓不到——那一段的文本里排空仍然在等待之前。这不是疏忽而是取舍：本仓
/// `macos/server.rs::do_spawn` 的排空**本来就**挂在 `if !log.is_empty()` 里（预开日志文件失败还要
/// 退化成纯排空），要求排空无条件出现会把这条正当的腿判红。条件排空这一格由行为门守（真的灌满管道
/// 看它挂不挂），不由本门守。
fn judge_sink_block(body: &str, drain_forms: &[&str]) -> Result<(), String> {
    for form in drain_forms {
        if !body.contains(form) {
            return Err(format!(
                "开了 `{PIPED_FORM}` 却找不到登记的排空形态 `{form}` —— \
                 管道写满后子进程的下一次 write(2) 会永久阻塞"
            ));
        }
    }

    let mut creations: Vec<usize> = Vec::new();
    for form in CHILD_CREATION_FORMS {
        creations.extend(offsets_of(body, form));
    }
    creations.sort_unstable();
    if creations.is_empty() {
        return Err(format!(
            "块里有 `{PIPED_FORM}`，却一处起子进程的形态（{CHILD_CREATION_FORMS:?}）都没有 —— \
             要么登记项已失去对象，要么本仓多了一种本门不认识的起进程写法；两种都必须当场红，\
             因为按 spawn 段给信用这件事在这个块上已经无从谈起"
        ));
    }

    let allowed: Vec<&str> = drain_forms
        .iter()
        .copied()
        .chain(SELF_DRAINING_FORMS.iter().copied())
        .collect();
    for (i, start) in creations.iter().copied().enumerate() {
        let end = creations.get(i + 1).copied().unwrap_or(body.len());
        let segment = &body[start..end];
        let first_drain = first_of(segment, &allowed);
        let first_wait = first_of(segment, WAIT_FORMS);
        let Some(drain) = first_drain else {
            return Err(format!(
                "第 {} 个 spawn 段（块内第 {} 行起）里一处排空形态都没有 —— \
                 这一段起的子进程，它的管道没人读。信用按 spawn 语句给：块里别处有排空不算这一段的",
                i + 1,
                line_in(body, start)
            ));
        };
        if let Some(wait) = first_wait {
            if drain > wait {
                return Err(format!(
                    "第 {} 个 spawn 段（块内第 {} 行起）里排空（段内第 {} 行）晚于等待（段内第 {} 行）\
                     —— 死锁形态：子进程写满管道后等父进程读，父进程等子进程退出",
                    i + 1,
                    line_in(body, start),
                    line_in(segment, drain),
                    line_in(segment, wait)
                ));
            }
        }
    }
    Ok(())
}

/// 类型面：每个**非家**生产文件里提到 [`SPAWNER_TYPE_FORMS`] 的全部位置（`file:line: 形态`）。
///
/// 抽成纯函数是为了能拿合成取材面喂它——绕过路径（新写一个接收者不叫 `*spawner` 的消费者）不该为了
/// 被钉住而写进生产码。
fn spawner_type_mentions(surface: &[Scanned]) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for scanned in surface {
        if SPAWNER_TYPE_HOME.contains(&scanned.rel.as_str()) {
            continue;
        }
        for form in SPAWNER_TYPE_FORMS {
            for at in offsets_of(&scanned.masked, form) {
                out.entry(scanned.rel.clone()).or_default().push(format!(
                    "  {}:{}: {form}",
                    scanned.rel,
                    line_at(scanned, at)
                ));
            }
        }
    }
    out
}

/// 文件集合对差：提到那组类型的生产文件集合必须与注册表 2 的文件集合**逐一相等**。
///
/// 多出来 = 新写了消费者却没登记；少了 = 登记项已失去对象。两个方向都得红，只查一个方向的对差
/// 会在另一个方向静默失效。
fn judge_consumer_registry_files(
    mentions: &BTreeMap<String, Vec<String>>,
    registered: &[&str],
) -> Result<(), String> {
    let stray: Vec<&String> = mentions
        .keys()
        .filter(|rel| !registered.contains(&rel.as_str()))
        .collect();
    if !stray.is_empty() {
        return Err(format!(
            "以下生产文件提到了「带两条未排空管道的 child」这组类型，却不在注册表 2 里 —— \
             新增了一个 spawner 消费者却没登记谁排空它：\n{}",
            stray
                .iter()
                .flat_map(|rel| mentions[*rel].clone())
                .collect::<Vec<_>>()
                .join("\n")
        ));
    }
    let missing: Vec<&&str> = registered
        .iter()
        .filter(|rel| !mentions.contains_key(**rel))
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "注册表 2 里的这些文件在类型面上一处都看不见：{missing:?} —— \
             登记项已失去对象（文件改名 / 消费者搬走 / 类型面词表漂了），不是「通过」"
        ));
    }
    Ok(())
}

/// G2 对一个消费者块的判据。`Ok(())` = 块里每个请求都选了 `Drain`，且两条流都真的被读。
///
/// `requests` = 块内构造 `SpawnRequest` 的次数（[`REQUEST_FORMS`]）：每多起一个核，就多两条要读的
/// 管道。取 `max(1)` 是防「登记项失去对象」——块里一个请求都不构造还留在注册表 2 里，说明消费者
/// 搬走了、这条登记已经不再守任何东西。
fn judge_consumer_block(body: &str, drain_form: &str, wiring: &[&str]) -> Result<(), String> {
    let requests = count_of(body, REQUEST_FORMS);
    if requests == 0 {
        return Err(format!(
            "块里一处 {REQUEST_FORMS:?} 都没有 —— 这条登记已经失去对象（消费者搬走 / 改名？），\
             不是「通过」"
        ));
    }
    // 每个请求都必须选 `Drain`。`Discard` 编得过，代价是核的输出被内核整段丢弃、日志页从此空白，
    // 那是一个必须重新登记的决定，不能靠改一个枚举变体悄悄溜过去。
    let drain_policies = body.matches(POLICY_DRAIN_FORM).count();
    if drain_policies < requests {
        return Err(format!(
            "构造了 {requests} 个 spawn 请求，却只有 {drain_policies} 个选了 `{POLICY_DRAIN_FORM}` —— \
             核腿一旦换成 `StdioPolicy::Discard`，它的输出就被内核整段丢弃（编得过、不卡死、\
             日志页一片空白），那是要重新登记的决定"
        ));
    }
    // 类型层管不到的那一格：回调按值收两条流，但**可以把其中一条直接丢掉**（`|out, _err| …`）。
    // 丢掉读端不挂死核（下一次写拿到 EPIPE），但那条流的诊断静默消失。故要求排空形态按请求数
    // 成对出现。
    let drains = body.matches(drain_form).count();
    if drains < requests * 2 {
        return Err(format!(
            "`{drain_form}` 只出现 {drains} 次（{requests} 个请求 ⇒ 应 ≥ {}）—— \
             回调收下了两条流却只读了一条：被丢掉的那条读端一关，核对它的写就拿到 EPIPE，\
             诊断静默消失",
            requests * 2
        ));
    }
    // 上一条只是计数，而**计数补得回来**：把回调改成 `|stdout, _stderr|` 再补一行
    // `pipe_to_log(tokio::io::empty(), …)`，次数照旧、stderr 从此无人读（实测：整改前这个变异
    // 让本门 16/16 全绿）。故逐条流钉精确接线 —— 判据要说的是「**哪条流**喂给了**哪次**调用」。
    let compact: String = body.split_whitespace().collect();
    for form in wiring {
        let hits = compact.matches(form).count();
        if hits < requests {
            return Err(format!(
                "接线 `{form}` 只出现 {hits} 次（{requests} 个请求 ⇒ 应 ≥ {requests}）—— \
                 这条流没有被喂给排空调用（或者绑定名/target 被改了）。\
                 计数型判据在这一格是哑的：补一次别的调用就能把次数凑回来，而那条管道仍旧无人读"
            ));
        }
    }
    Ok(())
}

/// 一条策略头登记串里回调的两个形参名，形如 `StdioPolicy::drain(move|stdout,stderr|{` → `[stdout, stderr]`。
///
/// 解析不出来一律 `Err`：登记表的防腐检查（[`every_registered_wiring_binds_both_callback_params`]）
/// 拿它当判据，解析失败必须转红，而不是静默退化成「没检查」。
fn callback_params(head: &str) -> Result<Vec<&str>, String> {
    let rest = head
        .strip_prefix(POLICY_DRAIN_FORM)
        .ok_or_else(|| format!("`{head}` 不是策略头（应以 `{POLICY_DRAIN_FORM}` 起手）"))?;
    let rest = rest.strip_prefix("move").unwrap_or(rest);
    let inner = rest
        .strip_prefix('|')
        .and_then(|r| r.split_once('|'))
        .map(|(params, _)| params)
        .ok_or_else(|| format!("`{head}` 里找不到闭包的 `|形参|` 列表"))?;
    let params: Vec<&str> = inner.split(',').filter(|p| !p.is_empty()).collect();
    if params.len() != 2 {
        return Err(format!(
            "`{head}` 的闭包形参是 {params:?}（应恰好两个：stdout 与 stderr 各一）"
        ));
    }
    Ok(params)
}

// ════════════════════════════════════════════════════════════════════════════
// 切片自检：本次到底扫了什么、命中了什么
// ════════════════════════════════════════════════════════════════════════════

/// 取材面清单 + 站点清单。`cargo test -- --nocapture` 可见。
///
/// 计数不等于位置：只报「扫了 N 个文件、命中 M 处」没法核对取材面完整不完整，所以逐条打
/// `file:line`。同时钉三个来自不同 crate 的具名正向对照——遍历或匹配坏掉之后「零命中也绿」是
/// 这类扫描门最常见的静默失效形态。
#[test]
fn the_scan_surface_reports_itself_and_covers_the_known_pipe_bearing_crates() {
    let surface = scan_surface();
    let root = workspace_root();
    println!("── 取材根 ─────────────────────────────────────────");
    println!("{}", root.display());
    println!(
        "── 取材面：{} 个生产 .rs ──────────────────────────",
        surface.len()
    );
    for scanned in &surface {
        println!("  {}", scanned.rel);
    }

    // 打印的清单必须与 G3 判的针脚集合**一致**：清单是审计面，少印一类针脚就等于那一类站点
    // 从人工核对里消失（而门自己仍在判它——两边不一致时，出错的总是没人看的那一边）。
    let mut sites: Vec<String> = Vec::new();
    for scanned in &surface {
        for needle in std::iter::once(PIPED_FORM)
            .chain(PIPE_TAKE_FORMS.iter().copied())
            .chain(std::iter::once(POLICY_FORM))
        {
            for at in offsets_of(&scanned.masked, needle) {
                sites.push(format!(
                    "{}:{}: {needle}",
                    scanned.rel,
                    line_at(scanned, at)
                ));
            }
        }
    }
    sites.sort();
    println!(
        "── 命中站点：{} 处 ────────────────────────────────",
        sites.len()
    );
    for site in &sites {
        println!("  {site}");
    }

    // 具名正向对照：四个仍真实存在的站点，来自三个不同 crate、覆盖三类针脚。
    for (file, needle) in [
        ("crates/core-supervisor/src/spawner.rs", "Stdio::piped()"),
        ("crates/system-integration/src/exec.rs", "Stdio::piped()"),
        (
            "crates/helper/src/platform/linux/resolved_dns.rs",
            "Stdio::piped()",
        ),
        ("src-tauri/src/runtime/speedtest.rs", "StdioPolicy::"),
    ] {
        assert!(
            sites
                .iter()
                .any(|s| s.starts_with(file) && s.ends_with(needle)),
            "取材面里看不见 `{file}` 的 `{needle}` —— 遍历或匹配坏了，本门的绿没有信息量。\
             实际命中 {} 处：\n{}",
            sites.len(),
            sites.join("\n")
        );
    }

    // 成员层自检：三块必须都在面上（写死单一路径的门只会扫到一半）。
    for prefix in [
        "src-tauri/src/",
        "crates/helper/src/",
        "crates/core-supervisor/src/",
    ] {
        assert!(
            surface.iter().any(|s| s.rel.starts_with(prefix)),
            "取材面里没有 `{prefix}` 下的任何文件 —— members 展开坏了"
        );
    }
}

// ════════════════════════════════════════════════════════════════════════════
// G1：开管道的人负责排空，且排空早于等待
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn every_piped_site_is_registered_and_drains_before_it_waits() {
    let surface = scan_surface();
    let index = surface_by_path(&surface);

    for site in PIPED_SITES {
        let scanned = file_of(&index, site.file);
        let body = block_of(scanned, site.anchor);

        // 自检：块里必须真的有 `Stdio::piped()`，否则说明锚点漂到了别处，下面的断言就没有意义。
        assert!(
            body.contains(PIPED_FORM),
            "{}：`{}` 的块里没有 `{PIPED_FORM}` —— 锚点漂了或管道被删了，登记项已失去对象",
            site.file,
            site.anchor
        );

        if let Some(exempt) = is_exempt(site.file, site.anchor) {
            println!(
                "豁免：{}::{} —— {}（跟进：{}）",
                exempt.file, exempt.anchor, exempt.reason, exempt.tracked_by
            );
            continue;
        }

        if site.kind == SiteKind::Producer {
            // 生产者自己不读，排空责任在注册表 2。本门对它**不再做进一步检查**：它的管道有没有被
            // 交到一个登记在册的消费者手里，由 G2 的文件集合对差与构造点覆盖两条腿负责。
            continue;
        }

        if let Err(reason) = judge_sink_block(body, site.drain_forms) {
            panic!("{}：`{}` {reason}", site.file, site.anchor);
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// G2：共享 spawner 的每个消费者都排两条流
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn every_consumer_of_the_shared_spawner_drains_both_streams() {
    let surface = scan_surface();
    let index = surface_by_path(&surface);

    // 三条腿的判定结果**全部**收齐再报，不是撞到第一条就 panic：三条腿共用同一个 spawner、
    // 同一份排空实现，一次改动同时打坏两条是常态（本轮那个变异就是两条腿一起丢 stderr）。
    // 撞一条就停，失败信息只说得出其中一条，另一条要等下一轮才暴露 —— 而人看到「红了一条」
    // 与「红了两条」会做出不同判断。
    let broken: Vec<String> = PRODUCER_CONSUMERS
        .iter()
        .filter_map(|consumer| {
            let scanned = file_of(&index, consumer.file);
            let body = block_of(scanned, consumer.anchor);
            judge_consumer_block(body, consumer.drain_form, consumer.wiring)
                .err()
                .map(|reason| format!("  {}：`{}` {reason}", consumer.file, consumer.anchor))
        })
        .collect();
    assert!(
        broken.is_empty(),
        "{} 条核腿的 stdio 接线不合格（共 {} 条登记）：\n{}",
        broken.len(),
        PRODUCER_CONSUMERS.len(),
        broken.join("\n")
    );

    // ── 对差之一：类型面的**文件集合** ──
    //
    // 上面那圈只能证明「已登记的都排空了」。没有这一段，新写一个消费者而不登记，本门一声不吭 ——
    // 那正是测速临时核当初的成因：第三个消费者出现时，没有任何东西提醒它要接第二半。
    //
    // 面钉在[类型名](SPAWNER_TYPE_FORMS)上而不是接收者变量名上：`let sb = TokioSpawner::default();
    // sb.spawn(&req)` 这种写法一个 `spawner` 字样都没有，按变量名匹配的旧词表会让它整个逃掉。
    let mentions = spawner_type_mentions(&surface);
    assert!(
        !mentions.is_empty(),
        "取材面里一处都没提到 {SPAWNER_TYPE_FORMS:?} —— 匹配或遍历坏了，本段对差恒真"
    );
    for home in SPAWNER_TYPE_HOME {
        let scanned = file_of(&index, home);
        assert!(
            first_of(&scanned.masked, SPAWNER_TYPE_FORMS).is_some(),
            "{home}：登记的「家」里一处 {SPAWNER_TYPE_FORMS:?} 都没有 —— \
             类型搬家了，这条豁免已经失去对象，成了将来某个真消费者的免死金牌"
        );
    }
    let registered: Vec<&str> = PRODUCER_CONSUMERS.iter().map(|c| c.file).collect();
    if let Err(reason) = judge_consumer_registry_files(&mentions, &registered) {
        panic!("{reason}");
    }

    // ── 对差之二：起核**构造点**的覆盖 ──
    //
    // 文件集合挡的是「新文件里冒出一个消费者」。已登记文件里、已登记块**之外**再起一个核，文件集合
    // 看不见（那个文件本来就在册），故构造点必须逐处落在某个登记块里。
    let mut sites: Vec<(String, usize, usize)> = Vec::new();
    for scanned in &surface {
        if SPAWNER_TYPE_HOME.contains(&scanned.rel.as_str()) {
            continue;
        }
        for at in offsets_of(&scanned.masked, SPAWNER_CONSTRUCTION_FORM) {
            sites.push((scanned.rel.clone(), at, line_at(scanned, at)));
        }
    }
    assert!(
        !sites.is_empty(),
        "取材面里一处 `{SPAWNER_CONSTRUCTION_FORM}` 都没有 —— 匹配坏了，本段对差恒真"
    );

    // 排除项：每条必须恰好盖住一处构造点（盖 0 处 = 它守的东西没了，条目成了免死金牌）。
    let mut covered: Vec<(usize, usize)> = Vec::new();
    for exclusion in SPAWN_EXCLUSIONS {
        assert!(
            !exclusion.reason.trim().is_empty(),
            "{}：排除项 `{}` 没写理由",
            exclusion.file,
            exclusion.anchor
        );
        let scanned = file_of(&index, exclusion.file);
        let (lo, hi) = block_range(scanned, exclusion.anchor);
        let hits = sites
            .iter()
            .filter(|(rel, at, _)| rel == exclusion.file && *at >= lo && *at < hi)
            .count();
        assert_eq!(
            hits, 1,
            "{}：排除项 `{}` 盖住了 {hits} 处 `{SPAWNER_CONSTRUCTION_FORM}`（应为 1）。\
             为 0 = 它守的东西已经没了，这条排除成了将来某个真消费者的免死金牌；\
             >1 = 一条排除悄悄盖住了它没打算覆盖的地方。",
            exclusion.file, exclusion.anchor
        );
        covered.push((lo, hi));
    }

    let mut offenders: Vec<String> = Vec::new();
    for (rel, at, line) in &sites {
        let in_exclusion = SPAWN_EXCLUSIONS
            .iter()
            .zip(&covered)
            .any(|(e, (lo, hi))| e.file == rel.as_str() && at >= lo && at < hi);
        let in_consumer = PRODUCER_CONSUMERS
            .iter()
            .filter(|c| c.file == rel.as_str())
            .any(|c| {
                let (lo, hi) = block_range(file_of(&index, c.file), c.anchor);
                *at >= lo && *at < hi
            });
        if !in_exclusion && !in_consumer {
            offenders.push(format!("  {rel}:{line}: {SPAWNER_CONSTRUCTION_FORM}"));
        }
    }
    assert!(
        offenders.is_empty(),
        "以下起核构造点不在任何一个登记的消费者块 / 排除项块里 —— \
         它起的核带着两条管道，没人说得清谁读：\n{}",
        offenders.join("\n")
    );
}

// ════════════════════════════════════════════════════════════════════════════
// G3：未登记的站点出现即红
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn no_unregistered_pipe_site_anywhere() {
    let surface = scan_surface();
    let index = surface_by_path(&surface);

    // 透传项也要防腐：盖不住任何一处取管道的地方 = 它守的东西已经没了，条目本身成了将来某个
    // 真违规的免死金牌。
    for pass in PIPE_PASSTHROUGH {
        assert!(
            !pass.reason.trim().is_empty(),
            "{}：透传项 `{}` 没写理由",
            pass.file,
            pass.anchor
        );
        let scanned = file_of(&index, pass.file);
        let body = block_of(scanned, pass.anchor);
        assert!(
            PIPE_TAKE_FORMS.iter().any(|form| body.contains(form)),
            "{}：透传项 `{}` 的块里一处取管道的地方都没有（理由登记的是「{}」）—— \
             它守的东西已经没了",
            pass.file,
            pass.anchor,
            pass.reason
        );
    }

    let mut offenders: Vec<String> = Vec::new();
    let mut seen = 0usize;
    for scanned in &surface {
        // 三类针：开管道、从 child 取走读端、以及**做出 stdio 处置决定**。第三类是收口之后
        // 补上的：新写一条核腿的人碰不到前两类（它们缩进了 spawner 内部），只会写一处
        // `StdioPolicy::`。不补这一针，新腿就从旧闸门旁边绕过去了。
        let needles: Vec<&str> = std::iter::once(PIPED_FORM)
            .chain(PIPE_TAKE_FORMS.iter().copied())
            .chain(std::iter::once(POLICY_FORM))
            .collect();
        let mut hits: Vec<(usize, &str)> = Vec::new();
        for needle in needles {
            for at in offsets_of(&scanned.masked, needle) {
                hits.push((at, needle));
            }
        }
        if hits.is_empty() {
            continue;
        }
        let ranges = covered_ranges(&index, &scanned.rel);
        for (at, needle) in hits {
            seen += 1;
            if !ranges.iter().any(|(lo, hi)| at >= *lo && at < *hi) {
                offenders.push(format!(
                    "{}:{}: {needle}",
                    scanned.rel,
                    line_at(scanned, at)
                ));
            }
        }
    }

    assert!(
        seen >= 20,
        "全仓只找到 {seen} 处管道站点 —— 扫描或净化坏了，本门的绿没有信息量"
    );
    assert!(
        offenders.is_empty(),
        "以下管道站点没有登记（`{PIPED_FORM}`、从 child 取走读端、或 `{POLICY_FORM}` 处置决定，\
         却不在注册表 1 / 注册表 2 / 透传表里）：\n{}\n\
         登记时必须同时写出它的排空形态 —— 写不出来说明这条腿还没想清楚谁来读它。",
        offenders.join("\n")
    );
}

// ════════════════════════════════════════════════════════════════════════════
// 豁免机制自身的防腐
// ════════════════════════════════════════════════════════════════════════════

/// 每条豁免必须**恰好命中一次**，且理由与跟进人都写清楚。
///
/// 当前 [`EXEMPT`] 为空，本条因此是空转的——但它必须先于豁免存在：下一个要开豁免的人得落进这套
/// 规则里，而不是自己新起一个没有过期检查的例外表。机制本身的可用性用变异验证（临时插一条，
/// 验完精确还原），不靠在表里长期养着一个真缺陷来证明。
#[test]
fn every_exemption_is_live_and_accounted_for() {
    let surface = scan_surface();
    let index = surface_by_path(&surface);

    for exempt in &EXEMPT {
        assert!(
            !exempt.reason.trim().is_empty() && !exempt.tracked_by.trim().is_empty(),
            "{}::{}：豁免必须写清 reason 与 tracked_by —— 无人认领的豁免不该存在",
            exempt.file,
            exempt.anchor
        );
        // 豁免只免掉纪律 1，免不掉登记：站点仍必须在注册表 1 里可见。
        assert!(
            PIPED_SITES
                .iter()
                .any(|s| s.file == exempt.file && s.anchor == exempt.anchor),
            "{}::{}：豁免的站点不在注册表 1 里 —— 豁免免不掉登记，否则它连审计面都进不去",
            exempt.file,
            exempt.anchor
        );
        let scanned = file_of(&index, exempt.file);
        let hits = scanned.masked.matches(exempt.anchor).count();
        assert_eq!(
            hits, 1,
            "{}::{}：豁免锚点命中 {hits} 次（应为 1）。\
             为 0 = 它守的东西已经没了，这条豁免成了将来某个真违规的免死金牌；\
             >1 = 一条豁免悄悄盖住了它没打算覆盖的地方。",
            exempt.file, exempt.anchor
        );
    }
}

// ════════════════════════════════════════════════════════════════════════════
// 判据本身的防腐：词表自洽 + 每条绕过路径各钉一条
// ════════════════════════════════════════════════════════════════════════════
//
// 下面这一组不扫仓库，它们把**判据**当被测对象：喂一段「按某条绕过路径写出来的源码」，要求判据必须
// 判红。每一条对应一次独立复审给出的具体绕过路径，而那些路径在整改前都实测逃逸过（本门当时 5/5 全绿）。
// 每条都带正向对照（真实的、正确的形态必须判绿），否则「恒红」也能让这些测试通过，那种红没有信息量。

/// 三张取管道词表不许悄悄漂开。
///
/// [`PIPE_TAKE_FORMS`] 是 G3 的针，两张分表是 G2 的针。分表里加了一种形态而并集忘了加，G3 就从此
/// 看不见那种写法；反过来则 G2 少守一条流。
#[test]
fn the_take_form_tables_stay_in_sync() {
    let union: Vec<&str> = STDOUT_TAKE_FORMS
        .iter()
        .chain(STDERR_TAKE_FORMS.iter())
        .copied()
        .collect();
    assert_eq!(
        PIPE_TAKE_FORMS, union,
        "取管道词表漂了：`PIPE_TAKE_FORMS`（G3 的针）与 stdout/stderr 两张分表（G2 的针）不一致 —— \
         一边加了形态另一边没加，那一边从此看不见那种写法"
    );
}

/// L-4：登记表里的排空形态必须落在 [`KNOWN_DRAIN_FORMS`] 里。
///
/// 不校验的话 `drain_forms` 是自由字符串，写成 `&["let "]` 门就照绿——而且失败信息还会一本正经地说
/// 「找到了登记的排空形态」。这条是「判据可被无意义值绕过」的收口。
#[test]
fn every_registered_drain_form_is_a_known_form() {
    for site in PIPED_SITES {
        for form in site.drain_forms {
            assert!(
                KNOWN_DRAIN_FORMS.contains(form),
                "{}：`{}` 登记的排空形态 `{form}` 不在 `KNOWN_DRAIN_FORMS` 里 —— \
                 判据里的自由字符串等于没有判据（`&[\"let \"]` 也能让本门照绿）",
                site.file,
                site.anchor
            );
        }
    }
    for consumer in PRODUCER_CONSUMERS {
        assert!(
            KNOWN_DRAIN_FORMS.contains(&consumer.drain_form),
            "{}：`{}` 登记的排空形态 `{}` 不在 `KNOWN_DRAIN_FORMS` 里",
            consumer.file,
            consumer.anchor,
            consumer.drain_form
        );
    }
    // 正向对照：集合本身不能是空的 / 不能被塞进一个万能串。
    assert!(
        !KNOWN_DRAIN_FORMS.is_empty(),
        "`KNOWN_DRAIN_FORMS` 空了 —— 上面两圈从此恒假，登记表可以写任何东西"
    );
    for form in KNOWN_DRAIN_FORMS {
        assert!(
            form.len() >= 5 && !form.trim().is_empty(),
            "`KNOWN_DRAIN_FORMS` 里的 `{form}` 太短 —— 短串会在无关代码里到处命中，等于没判据"
        );
    }
}

/// 防腐：[`Consumer::wiring`] 登记的必须真的是「回调的**两个形参**各喂给一次排空调用」。
///
/// 没有这一条，`wiring` 就是又一处「判据里的自由字符串」：写成
/// `&["StdioPolicy::drain("]` 一样过得去，而它一格都不守。判的是登记表本身的形状，不读任何源码 ——
/// 源码那一半由 [`every_consumer_of_the_shared_spawner_drains_both_streams`] 判。
#[test]
fn every_registered_wiring_binds_both_callback_params() {
    for consumer in PRODUCER_CONSUMERS {
        let heads: Vec<&&str> = consumer
            .wiring
            .iter()
            .filter(|w| w.starts_with(POLICY_DRAIN_FORM))
            .collect();
        assert_eq!(
            heads.len(),
            1,
            "{}：`{}` 的 wiring 里有 {} 条策略头（应恰好 1 条，形如 `{POLICY_DRAIN_FORM}|stdout,stderr|{{`）\
             —— 没有策略头就读不出回调的形参名，下面那圈对差恒真",
            consumer.file,
            consumer.anchor,
            heads.len()
        );
        let params = callback_params(heads[0]).unwrap_or_else(|e| {
            panic!(
                "{}：`{}` 的策略头解析失败 —— {e}",
                consumer.file, consumer.anchor
            )
        });
        assert_ne!(
            params[0], params[1],
            "{}：`{}` 的回调两个形参重名（{params:?}）—— 那样「哪条流」就不再可分辨",
            consumer.file, consumer.anchor
        );
        // 每个形参都必须作为**首个实参**出现在一条登记的排空调用里。
        // `|stdout, _stderr|` 这种「声明放弃一条流」的写法在这里当场被判出来。
        for param in &params {
            let expected = format!("{}{param},", consumer.drain_form);
            assert!(
                consumer.wiring.iter().any(|w| w.starts_with(&expected)),
                "{}：`{}` 的回调形参 `{param}` 没有任何一条登记接线以 `{expected}` 起手 —— \
                 这条流要么没被排空，要么排空接线没进登记表（两者都必须当场可见）",
                consumer.file,
                consumer.anchor
            );
        }
        // 非策略头的登记项必须都是本消费者那份排空实现的调用（防止塞进无关串充数）。
        for form in consumer.wiring {
            assert!(
                form.starts_with(POLICY_DRAIN_FORM) || form.starts_with(consumer.drain_form),
                "{}：`{}` 的 wiring 项 `{form}` 既不是策略头也不是 `{}` 的调用 —— \
                 判据里的自由字符串等于没有判据",
                consumer.file,
                consumer.anchor,
                consumer.drain_form
            );
            assert!(
                !form.contains(char::is_whitespace),
                "{}：`{}` 的 wiring 项 `{form}` 含空白 —— 判据打在**去空白**的形上，\
                 带空白的串永远命中不到（判据不是变弱，是消失）",
                consumer.file,
                consumer.anchor
            );
        }
    }
}

/// M-1 的绕过路径：把 `take_stderr()` 误写成 `take_stdout()`（真实的复制粘贴错误形态）。
///
/// 排空调用总次数一点不变（还是 2 次），旧判据「`drain_to_log(` 出现 ≥ 2 次」照绿；而 stderr 管道
/// 🔴 **类型层唯一管不到的那一格**：回调按值收下两条流，却只读了一条。
///
/// 收口之后这条腿有三格保护，前两格是编译器的、第三格只有本门有：
/// ① 请求少写 `stdio` → `error[E0061]`/`error[E0063]`；
/// ② 同一条流排两遍（`take_stderr()` 误写成 `take_stdout()` 的后继形态）→ `use of moved value`；
/// ③ **把某条流直接丢掉**（`|out, _err| …`）→ 编得过。丢掉读端不会挂死核（下一次写拿到
///    EPIPE 而不是阻塞），但那条流的诊断静默消失 —— 排查临时核时正好缺的就是它。
///
/// 正向对照与红各跑一次：真实形态必须判绿，否则这条测试的红没有信息量。
#[test]
fn a_consumer_that_drains_only_one_of_the_two_streams_is_red() {
    assert!(
        judge_consumer_block(TEMP_CORE_BLOCK, "pipe_to_log(", TEMP_CORE_WIRING).is_ok(),
        "正向对照失效：真实的、两条流各读一次的形态被判红了，那这条测试的红没有信息量"
    );

    let dropped = TEMP_CORE_BLOCK.replace(
        "                pipe_to_log(stderr, SPEEDTEST_CORE_TARGET, None, None);\n",
        "",
    );
    assert_ne!(dropped, TEMP_CORE_BLOCK, "变异没打上：被删的那一行对不上号");
    let err = judge_consumer_block(&dropped, "pipe_to_log(", TEMP_CORE_WIRING)
        .expect_err("回调丢掉了 stderr 那条流却判绿 —— 那条管道的诊断从此静默消失");
    assert!(
        err.contains("只读了一条"),
        "失败信息没说清是「收下两条只读一条」：{err}"
    );
}

/// 临时核那条腿的真实接线（判据的正向对照面）。与 [`PRODUCER_CONSUMERS`] 里那条登记同源。
const TEMP_CORE_BLOCK: &str = r#"
        let mut req = SpawnRequest::new(
            &binary,
            &config_path,
            StdioPolicy::drain(|stdout, stderr| {
                pipe_to_log(stdout, SPEEDTEST_CORE_TARGET, None, None);
                pipe_to_log(stderr, SPEEDTEST_CORE_TARGET, None, None);
            }),
        );
    "#;

const TEMP_CORE_WIRING: &[&str] = &[
    "StdioPolicy::drain(|stdout,stderr|{",
    "pipe_to_log(stdout,SPEEDTEST_CORE_TARGET,None,None);",
    "pipe_to_log(stderr,SPEEDTEST_CORE_TARGET,None,None);",
];

/// 🔴 **计数补得回来，接线补不回来** —— 本条是整改前那次完整逃逸的回放。
///
/// 变异形态（实测编得过）：回调改成 `|stdout, _stderr|`（真的丢掉 stderr），再补一行
/// `pipe_to_log(tokio::io::empty(), …)` 把 `pipe_to_log(` 的次数凑回 2。
/// 整改前本门 **16/16 全绿**、批 A 的源码门也绿，只有临时核的**行为**门红 —— 而登录核那条腿
/// 连行为门都没有，于是一条门都不红。
///
/// 本条先证明「旧的计数判据在这个输入上确实是绿的」（次数仍是 2），再证明新判据红。
/// 少了前半句，这条测试证明不了它接住的是**旧判据接不住的那一格**。
#[test]
fn a_filler_drain_call_restores_the_count_but_not_the_wiring() {
    // 补计数用的那次调用（喂的是一条空流，核的 stderr 依旧无人读）。
    let filler =
        "                pipe_to_log(tokio::io::empty(), SPEEDTEST_CORE_TARGET, None, None);";
    let real_stderr_call =
        "                pipe_to_log(stderr, SPEEDTEST_CORE_TARGET, None, None);";

    // 两种写法都得接住：形参改名（声明式放弃那条流）与形参留着但没人用（编得过，只是一条 warning）。
    for (label, mutated, expect_in_msg) in [
        (
            "形参改成 `_stderr`",
            TEMP_CORE_BLOCK
                .replace("|stdout, stderr|", "|stdout, _stderr|")
                .replace(real_stderr_call, filler),
            "StdioPolicy::drain(|stdout,stderr|{",
        ),
        (
            "形参留着但不再喂给排空",
            TEMP_CORE_BLOCK.replace(real_stderr_call, filler),
            "pipe_to_log(stderr,SPEEDTEST_CORE_TARGET",
        ),
    ] {
        assert_ne!(
            mutated, TEMP_CORE_BLOCK,
            "{label}：变异没打上，被替换的那处对不上号"
        );

        // ① 旧判据（计数）在这个输入上是**绿**的：`pipe_to_log(` 仍出现 2 次、策略仍是 `drain`。
        assert_eq!(
            mutated.matches("pipe_to_log(").count(),
            2,
            "{label}：本测的前提是「计数被补回来了」；次数不是 2 说明变异写歪了，后半句的红没有信息量"
        );
        assert_eq!(
            mutated.matches(POLICY_DRAIN_FORM).count(),
            1,
            "{label}：策略仍必须是 `Drain`（否则红的是另一格）"
        );

        // ② 新判据红，且红在「这条流的接线不在场」上。
        let err = judge_consumer_block(&mutated, "pipe_to_log(", TEMP_CORE_WIRING).expect_err(
            "回调丢掉 stderr、用一次无关调用把计数凑回来，却判绿 —— 这正是那次完整逃逸",
        );
        assert!(
            err.contains(expect_in_msg),
            "{label}：失败信息没指出是哪一条接线不在场：{err}"
        );
    }
}

/// 🔴 **块里起两个核、却只有一份接线**：判据必须按请求数缩放，不能「有一份就算数」。
#[test]
fn a_second_request_in_the_same_block_needs_its_own_wiring() {
    let two_requests = format!(
        "{TEMP_CORE_BLOCK}\n        let second = SpawnRequest::new(&binary, &other, StdioPolicy::drain(|a, b| {{ drop(a); drop(b); }}));"
    );
    let err = judge_consumer_block(&two_requests, "pipe_to_log(", TEMP_CORE_WIRING)
        .expect_err("第二个请求没有自己的排空接线，却判绿 —— 那个核的两条管道无人读");
    assert!(
        err.contains("2 个请求"),
        "失败信息没说清是「按请求数缩放」这一格：{err}"
    );
}

/// 🔴 **另一格：核腿悄悄换成 `Discard`**。
///
/// `StdioPolicy::Discard` 完全合法、编得过、也绝不卡死（两路 `Stdio::null()`，内核直接丢弃）——
/// 代价是这条核腿的输出从此一行都不落盘，排查它的时候日志页一片空白。那是一个要重新登记的决定，
/// 不是改一个枚举变体就能溜过去的事。
#[test]
fn a_core_leg_that_switches_to_discard_is_red() {
    let discarded = r#"
        let mut req = SpawnRequest::new(&binary, &config_path, StdioPolicy::Discard);
    "#;
    let err = judge_consumer_block(discarded, "pipe_to_log(", TEMP_CORE_WIRING)
        .expect_err("核腿换成 Discard 却判绿 —— 它的日志从此一行都没有");
    assert!(
        err.contains("StdioPolicy::drain("),
        "失败信息没说清缺的是 `Drain` 策略：{err}"
    );
}

/// 🔴 **登记项失去对象**：块里一个请求都不构造了（消费者搬走 / 改名），必须红而不是静默绿。
#[test]
fn a_consumer_entry_that_no_longer_builds_a_request_is_red() {
    let moved_away = r#"
        let child = self.spawner.spawn_somewhere_else();
    "#;
    let err = judge_consumer_block(moved_away, "pipe_to_log(", TEMP_CORE_WIRING)
        .expect_err("登记的消费者块里一个 spawn 请求都没有了，却判绿 —— 门已失去判据");
    assert!(
        err.contains("失去对象"),
        "失败信息没说清这条登记已经不守任何东西：{err}"
    );
}

/// M-2 的绕过路径：新写一个消费者，接收者变量名不含 `spawner`。
///
/// `let sb = TokioSpawner::default(); sb.spawn(&req)` 不命中旧词表 `spawner.spawn(` /
/// `Spawner::new().spawn(`，于是调用点计数仍等于注册表长度，G2 照绿；它一条流都不排，而没有取管道
/// 形态 G3 也不红——原缺陷形态完整逃逸。整改前实测：把这一段加到 `uninstall.rs` 上，本门 5/5 全绿。
#[test]
fn a_new_consumer_with_any_receiver_name_is_red() {
    let registered = ["src-tauri/src/runtime/proxy/startup.rs"];
    let legit = Scanned {
        rel: "src-tauri/src/runtime/proxy/startup.rs".to_owned(),
        masked: "let mut spawned = match TokioSpawner::new().spawn(&req) {".to_owned(),
    };
    assert!(
        judge_consumer_registry_files(&spawner_type_mentions(&[legit]), &registered).is_ok(),
        "正向对照失效：已登记的消费者被判红了，那这条测试的红没有信息量"
    );

    let legit = Scanned {
        rel: "src-tauri/src/runtime/proxy/startup.rs".to_owned(),
        masked: "let mut spawned = match TokioSpawner::new().spawn(&req) {".to_owned(),
    };
    let sneaky = Scanned {
        rel: "src-tauri/src/runtime/uninstall.rs".to_owned(),
        // 接收者叫 `sb`，一个 `spawner` 字样都没有；两条流一条都不排。
        masked: "let sb = TokioSpawner::default();\nlet _ = sb.spawn(&req);".to_owned(),
    };
    let err = judge_consumer_registry_files(&spawner_type_mentions(&[legit, sneaky]), &registered)
        .expect_err("新消费者只是换了个接收者名字就逃掉了 —— 判据钉在变量名上，不是钉在类型上");
    assert!(
        err.contains("uninstall.rs"),
        "失败信息没指到新消费者所在的文件：{err}"
    );
}

/// M-2 的另一半：helper 的 `CoreSpawner` 不该被判据误捕。
///
/// 旧词表按 `spawner.spawn(` 匹配，于是 `linux/handler.rs` 里任何叫 `*spawner` 的接收者都会命中，
/// 逼着加一条豁免。**被判据逼出来的豁免是判据错了，不是使用者错了**：类型面上 helper 那条腿根本
/// 不出现，豁免自然消失。
#[test]
fn the_helper_core_spawner_does_not_need_an_exemption_any_more() {
    let helper = Scanned {
        rel: "crates/helper/src/platform/linux/handler.rs".to_owned(),
        masked: "match deps.spawner.spawn(&req) {".to_owned(),
    };
    assert!(
        spawner_type_mentions(&[helper]).is_empty(),
        "helper 的 CoreSpawner 又被类型面误捕了 —— 它会重新逼出一条本不该存在的豁免"
    );
    assert!(
        !SPAWN_EXCLUSIONS
            .iter()
            .any(|e| e.file.starts_with("crates/helper/")),
        "排除表里还留着 helper 的条目 —— 判据换钉法之后它已经失去对象，留着就是一张免死金牌"
    );
}

/// M-3 的绕过路径：在 `crates/` 之外新建一个 crate 并 path 依赖它。
///
/// cargo 会把它**隐式**纳为 workspace 成员（代码照常编译进产品），而按仓根 `Cargo.toml` 的字面
/// `members` 解析的取材面看不见它——门静默漏扫、没有任何自曝。本条在一个合成 workspace 上把两种
/// 推导并排跑：字面解析只报 1 个成员，`cargo metadata` 报 2 个。
///
/// 整改前实测（真 workspace，非合成）：给 `crates/source-probe` 临时加一条指向 `plugins/probe` 的
/// path 依赖，`cargo metadata` 的成员数 20 → 21，而本门 5/5 全绿。
#[test]
fn the_member_layer_sees_implicitly_added_workspace_members() {
    let root = std::env::temp_dir().join(format!(
        "polaris-stdio-guard-implicit-member-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("inner/src")).expect("建不出合成 workspace");
    std::fs::create_dir_all(root.join("plugins/extra/src")).expect("建不出合成 workspace");
    std::fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"inner\"]\nresolver = \"2\"\n",
    )
    .expect("写不了合成 workspace 的根 manifest");
    std::fs::write(
        root.join("inner/Cargo.toml"),
        "[package]\nname = \"inner\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
         [dependencies]\nextra = { path = \"../plugins/extra\" }\n",
    )
    .expect("写不了 inner 的 manifest");
    std::fs::write(root.join("inner/src/lib.rs"), "pub fn a() {}\n").expect("写不了 inner 源码");
    std::fs::write(
        root.join("plugins/extra/Cargo.toml"),
        "[package]\nname = \"extra\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("写不了 extra 的 manifest");
    std::fs::write(root.join("plugins/extra/src/lib.rs"), "pub fn b() {}\n")
        .expect("写不了 extra 源码");

    let literal = members_from_manifest_literal(&root);
    let from_cargo = members_from_cargo_metadata(&root);
    let _ = std::fs::remove_dir_all(&root);

    let extra = root.join("plugins/extra");
    assert!(
        !literal.contains(&extra),
        "字面 `members` 解析居然看见了隐式成员 —— 那本条测试就没在测它该测的东西"
    );
    assert!(
        from_cargo.contains(&extra),
        "`cargo metadata --no-deps` 没报出隐式成员 `plugins/extra` —— \
         取材面的成员层又退回了会静默漏扫的那一种。实得：{from_cargo:?}"
    );
    // 正向对照：显式成员两种推导都得看得见，否则「多报一个」可能只是推导整个坏掉。
    let inner = root.join("inner");
    assert!(
        literal.contains(&inner) && from_cargo.contains(&inner),
        "显式成员 `inner` 有一种推导看不见 —— 推导坏了，上面那条断言的绿没有信息量"
    );
}

/// M-4 的绕过路径：在同一个块里再起一个 piped 却从不读、只 `.wait()` 的子进程。
///
/// 它加在排空线程**之后**，于是「块内首个排空早于块内首个等待」照样成立，按块给信用的旧判据全然
/// 看不见。整改前实测：把这一段加进 `run_resolvectl`，本门 5/5 全绿。
#[test]
fn a_second_undrained_spawn_in_the_same_block_is_red() {
    let correct = r#"
    let mut child = Command::new(program)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn: {e}"))?;
    let out_pipe = child.stdout.take();
    let err_pipe = child.stderr.take();
    let out_thread = thread::spawn(move || drain(out_pipe));
    let err_thread = thread::spawn(move || drain(err_pipe));
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            _ => {}
        }
    }
    "#;
    assert!(
        judge_sink_block(correct, &["drain("]).is_ok(),
        "正向对照失效：真实的、先起排空线程再轮询的形态被判红了"
    );

    let precheck = r#"
    let mut precheck = Command::new(program)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn precheck: {e}"))?;
    let _ = precheck.wait();
"#;
    let bypassed = correct.replace("    loop {", &format!("{precheck}    loop {{"));
    let err = judge_sink_block(&bypassed, &["drain("]).expect_err(
        "块里多出一个从不排空的子进程却判绿 —— 信用是按块给的，分辨不出排空的是哪个子进程",
    );
    assert!(
        err.contains("spawn 段"),
        "失败信息没指出是哪一段没有排空：{err}"
    );
}

/// M-4 的同族形态：排空整个消失时也必须红（而不是靠上面那条的次序腿兜着）。
#[test]
fn a_spawn_segment_without_any_drain_is_red() {
    let no_drain = r#"
    let mut child = Command::new(program)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let _ = child.wait();
    "#;
    let err =
        judge_sink_block(no_drain, &["drain("]).expect_err("开了两条管道一处排空都没有却判绿");
    assert!(
        err.contains("排空形态"),
        "失败信息没说清缺的是排空形态：{err}"
    );
}

/// **G1 次序腿的历史真缺陷回放**：`resolvectl` 在 `9d5222c` 之前就是「先 `try_wait` 轮询、
/// 退出之后才 `read_to_string` 两条管道」。
///
/// # 这条测试补的是哪个缝
///
/// 独立复审指出：G1 的「次序」一半在历史真缺陷上从未被回放证明过 —— 主树 HEAD 回放时它红在
/// **形态缺失**（`fn run_resolvectl(` 命中 0 次，锚点根本不存在），而不是红在次序颠倒；次序那一半
/// 唯一的证据是人造变异。人造变异证明的是「判据在我构造的输入上会红」，证明不了「判据对着真实
/// 发生过的那个错误会红」。
///
/// 夹具是 `f197204`（批 A 的父提交，即缺陷仍在的那份源码）里 `SystemResolvectlRunner` 的 impl 块
/// **逐字原文**。登记的排空形态是那条腿**当时实际用的** `read_to_string(` —— 它确实读了管道，
/// 红必须红在次序上，否则这次回放证明的仍然只是「形态缺失」，而形态缺失那一半本来就有证据。
#[test]
fn the_order_leg_is_red_on_the_historical_resolvectl_defect() {
    const HISTORICAL_ANCHOR: &str = "impl ResolvectlRunner for SystemResolvectlRunner {";
    /// `f197204:crates/helper/src/platform/linux/resolved_dns.rs` 的 impl 块逐字原文。
    const HISTORICAL_DEFECT: &str = r#"impl ResolvectlRunner for SystemResolvectlRunner {
    fn link_exists(&self, interface_name: &str) -> bool {
        Path::new("/sys/class/net").join(interface_name).exists()
    }

    fn run(&self, args: &[&str]) -> Result<String, String> {
        let mut child = Command::new(RESOLVECTL_BIN)
            .args(args)
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn resolvectl {}: {e}", args.join(" ")))?;
        let started = Instant::now();
        let mut poll_interval = INITIAL_POLL_INTERVAL;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let mut stdout = String::new();
                    let mut stderr = String::new();
                    if let Some(mut pipe) = child.stdout.take() {
                        let _ = pipe.read_to_string(&mut stdout);
                    }
                    if let Some(mut pipe) = child.stderr.take() {
                        let _ = pipe.read_to_string(&mut stderr);
                    }
                    if status.success() {
                        return Ok(stdout.trim().to_owned());
                    }
                    let detail = if stderr.trim().is_empty() {
                        stdout.trim()
                    } else {
                        stderr.trim()
                    };
                    return Err(format!(
                        "resolvectl {} exited {status}: {detail}",
                        args.join(" ")
                    ));
                }
                Ok(None) if started.elapsed() < COMMAND_TIMEOUT => {
                    thread::sleep(poll_interval);
                    poll_interval = next_poll_interval(poll_interval);
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "resolvectl {} timed out after {}s",
                        args.join(" "),
                        COMMAND_TIMEOUT.as_secs()
                    ));
                }
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("wait resolvectl {}: {e}", args.join(" ")));
                }
            }
        }
    }
}"#;

    let scanned = Scanned {
        rel: "crates/helper/src/platform/linux/resolved_dns.rs".to_owned(),
        masked: polaris_source_probe::mask_comments_and_strings(HISTORICAL_DEFECT),
    };
    // 走真实取材路径：花括号配平切块 → 判据。切不出块 / 块里没有管道，都会在这里当场 panic。
    let body = block_of(&scanned, HISTORICAL_ANCHOR);
    assert!(
        body.contains(PIPED_FORM),
        "夹具里没有 `{PIPED_FORM}` —— 抄进来的不是那段有缺陷的源码"
    );
    assert!(
        body.contains("read_to_string("),
        "夹具里没有 `read_to_string(` —— 那条腿当时**是**读了管道的，缺了它这次回放就退化成「形态缺失」"
    );

    let err = judge_sink_block(body, &["read_to_string("])
        .expect_err("G1 在历史真缺陷上判绿了 —— 次序那一半从未被真缺陷证明过，只被人造变异证明过");
    assert!(
        err.contains("晚于等待"),
        "红的不是次序腿，而是别的东西（{err}）—— 那这次回放仍然没有证明次序判据对真缺陷敏感"
    );
}
