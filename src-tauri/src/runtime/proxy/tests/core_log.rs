use std::borrow::Cow;

use super::*;

/// sing-box 行级别映射：DEBUG/TRACE 须如实标级，不得混进 info。
/// 打断 DEBUG 分支（落回 else → Info）→ 本测转红，即 DEBUG 过滤形同虚设的那个 bug。
#[test]
fn singbox_line_level_maps_all_tokens() {
    assert_eq!(
        singbox_line_level("+0800 2026-07-17 10:00:00 FATAL start service: xxx"),
        log::Level::Error
    );
    assert_eq!(
        singbox_line_level("+0800 ERROR bad config"),
        log::Level::Error
    );
    assert_eq!(
        singbox_line_level("+0800 WARN deprecated"),
        log::Level::Warn
    );
    assert_eq!(
        singbox_line_level("+0800 DEBUG dns: exchange example.com"),
        log::Level::Debug,
        "DEBUG 行必须标 Debug，否则日志页 DEBUG 档筛不出核的详情"
    );
    assert_eq!(
        singbox_line_level("+0800 TRACE inbound/mixed packet"),
        log::Level::Trace
    );
    assert_eq!(
        singbox_line_level("+0800 INFO router: loaded"),
        log::Level::Info
    );
    // 无级别 token（核的裸输出行）→ Info 兜底，不丢行。
    assert_eq!(
        singbox_line_level("bare line without level"),
        log::Level::Info
    );
}

/// 🔴 **正文里的 `DEBUG` 子串不得把一条 INFO 行降档**（降档 = 用户在默认 info 档整行看不见）。
///
/// 这不是理论形态：sing-box 把 endpoint/outbound 的 tag 打进行前缀，而瞬态登录核的 tag 就是
/// **用户自己输入的节点名**（`crates/mesh/src/tailscale_login.rs` 的 `endpoint.tag = server.name`）。
/// 一个名字里含 `DEBUG` 的节点，改前它那条腿的每一行 INFO 都被判成 `log::Level::Debug`，被 app 的
/// `max_level`（默认 `info`）整行滤掉——日志页对这个节点一片空白，而核其实一直在说话。
///
/// **牙**：把 `singbox_line_level` 里的 `INFO` 前置分支删掉 ⇒ 下面三条各自转红。
#[test]
fn an_info_line_is_not_downgraded_by_a_debug_or_trace_substring_in_its_body() {
    assert_eq!(
        singbox_line_level("+0800 INFO endpoint/tailscale[my-DEBUG-node]: Waiting for auth"),
        log::Level::Info,
        "节点名含 DEBUG 的 INFO 行被判成 Debug ⇒ info 档下这条腿的日志整体消失"
    );
    assert_eq!(
        singbox_line_level("+0800 INFO inbound/mixed[TRACE-box]: connection"),
        log::Level::Info,
        "同理：正文里的 TRACE 子串不得把 INFO 行降到 Trace"
    );
    // 级别 token 之外的字段同样可能带这些子串（用户可控的 tag 只是最容易触发的一处）。
    assert_eq!(
        singbox_line_level("+0800 INFO router: rule_set[DEBUG] loaded"),
        log::Level::Info
    );
}

/// 🔵 **反向的误判是有意留下的**：DEBUG 行的正文里含 `INFO` 子串 → 判 `Info`（**升档**）。
///
/// 记在这里是为了下一个人别把它当 bug「修」掉：这一侧的代价是 info 档多留一行本该被过滤的噪音，
/// 而另一侧（把 INFO 判成 Debug）的代价是**静默丢行**。两害相权，安全侧就是升档。
///
/// 要彻底消掉这一格得按位置取级别 token（行格式 `时间 级别 [tag] 内容` 固定），那是另一次改判据
/// ——它会同时改掉 [`classify_core_fatal_line`] 的取材口径（那个读的是整行语义），不在本批射程。
#[test]
fn a_debug_line_whose_body_contains_info_is_upgraded_on_purpose() {
    assert_eq!(
        singbox_line_level("+0800 DEBUG dns: exchange INFO.example.com"),
        log::Level::Info,
        "升档是有意的安全侧：宁可多留一行噪音，也不静默丢一行诊断"
    );
}

/// 核侧七档 `LogLevel` → sink 五档：panic/fatal/error 并档 Error，其余逐一对应。
///
/// **未知级号必须归 Info 而不是被丢掉**：上游扩枚举时宁可级别偏保守，也不能静默吃掉一行核日志。
/// 打断 Debug 分支（落 Info）→ 「日志页选 DEBUG 却筛不出核的详情」那个 bug 原地复现 → 本测转红。
#[test]
fn core_log_level_maps_all_seven_upstream_levels() {
    use polaris_singbox_grpc::daemon::LogLevel as L;
    assert_eq!(core_log_level(L::Panic as i32), log::Level::Error);
    assert_eq!(core_log_level(L::Fatal as i32), log::Level::Error);
    assert_eq!(core_log_level(L::Error as i32), log::Level::Error);
    assert_eq!(core_log_level(L::Warn as i32), log::Level::Warn);
    assert_eq!(core_log_level(L::Info as i32), log::Level::Info);
    assert_eq!(
        core_log_level(L::Debug as i32),
        log::Level::Debug,
        "DEBUG 必须如实标级，否则日志页 DEBUG 档筛不出核的详情"
    );
    assert_eq!(core_log_level(L::Trace as i32), log::Level::Trace);
    assert_eq!(
        core_log_level(99),
        log::Level::Info,
        "上游扩了枚举 → 保守归 Info，绝不丢行"
    );
}

/// 隐私锁下限这道闸不受用户级别影响：级别拨到 debug（`max=Trace`）也不许 info 行落盘。
/// 这是 N1 那条真隐私回归的判据，不得被「反正 log! 也会筛」的化简吃掉。
#[test]
fn core_log_admits_enforces_privacy_floor_independent_of_max() {
    let max = log::LevelFilter::Trace; // 用户把级别拨到最啰嗦
    let floor = core_log_privacy_floor(true); // 隐私锁开 ⇒ Warn
    assert!(
        !core_log_admits(log::Level::Info, floor, max),
        "隐私锁开着 info 不得转发"
    );
    assert!(!core_log_admits(log::Level::Debug, floor, max));
    assert!(
        core_log_admits(log::Level::Warn, floor, max),
        "warn 及更严的必须过"
    );
    assert!(core_log_admits(log::Level::Error, floor, max));
}

/// 用户级别这道闸不受隐私锁影响：非隐私态（下限 = Trace，不设限）下仍按 `max_level` 筛。
/// 它**不改变去留**（下游 `log::log!` 一样会筛），改变的是筛之前做不做剥除 —— 故判据是
/// 「与 log! 的结果逐格一致」，一致就说明提前筛是等价的。
#[test]
fn core_log_admits_enforces_user_level_independent_of_floor() {
    let floor = core_log_privacy_floor(false); // 非隐私态 ⇒ Trace，不设限
    for max in [
        log::LevelFilter::Off,
        log::LevelFilter::Error,
        log::LevelFilter::Warn,
        log::LevelFilter::Info,
        log::LevelFilter::Debug,
        log::LevelFilter::Trace,
    ] {
        for level in [
            log::Level::Error,
            log::Level::Warn,
            log::Level::Info,
            log::Level::Debug,
            log::Level::Trace,
        ] {
            assert_eq!(
                core_log_admits(level, floor, max),
                level <= max,
                "提前筛必须与 log! 的判定逐格一致（level={level}, max={max}）"
            );
        }
    }
}

/// 两道闸是**合取**：任一不过即不转发。取两者各自放行、另一者拦截的交叉组合。
#[test]
fn core_log_admits_is_conjunction_of_both_gates() {
    let floor = core_log_privacy_floor(true); // Warn
                                              // 级别闸放行（max=Trace）但隐私闸拦：
    assert!(!core_log_admits(
        log::Level::Debug,
        floor,
        log::LevelFilter::Trace
    ));
    // 隐私闸放行（Error ≤ Warn）但级别闸拦（max=Off）：
    assert!(!core_log_admits(
        log::Level::Error,
        floor,
        log::LevelFilter::Off
    ));
    // 两闸都放行：
    assert!(core_log_admits(
        log::Level::Error,
        floor,
        log::LevelFilter::Error
    ));
}

/// `SubscribeLog` 消息体的装饰剥除。
///
/// 夹具是**真核实际会发出的形状**：喂这条流的 `platformFormatter` 没关色
/// （`log/observable.go` 里关色那两行是注释掉的），且走 `Format` 的默认时间戳分支
/// ⇒ `"\x1b[36mINFO\x1b[0m[0012] router: …"`。不剥的话日志页每行都是转义乱码 + 重复级别。
///
/// 打断 ANSI 剥除 → 第一断言转红；打断级别前缀剥除 → 第二断言转红；
/// 把「形状对不上就原样返回」改成强行截断 → 后三条转红。
#[test]
fn strip_core_log_decoration_removes_ansi_and_redundant_level_prefix() {
    assert_eq!(
        strip_core_log_decoration("\u{1b}[36mINFO\u{1b}[0m[0012] router: loaded 5 rules"),
        "router: loaded 5 rules"
    );
    assert_eq!(
        strip_core_log_decoration("DEBUG[0001] dns: exchange example.com"),
        "dns: exchange example.com",
        "无色时同样要剥掉级别前缀（级别由结构化字段承担，UI 自己渲染）"
    );

    // ── 形状对不上 → 整段原样保留（剥除绝不能演变成「吃掉半行」）──
    assert_eq!(
        strip_core_log_decoration("router: loaded"),
        "router: loaded",
        "没有前缀就别乱剥"
    );
    assert_eq!(
        strip_core_log_decoration("INFOrmation about the tunnel"),
        "INFOrmation about the tunnel",
        "级别名只是正文开头的一截字母 → 不是前缀"
    );
    assert_eq!(
        strip_core_log_decoration("WARN[abcd] weird"),
        "WARN[abcd] weird",
        "方括号里不是数字 ⇒ 形状变了，别猜"
    );
    // 正文里的方括号内容不得被吃掉。
    assert_eq!(
        strip_core_log_decoration("ERROR[0003] dial tcp [::1]:443: refused"),
        "dial tcp [::1]:443: refused"
    );
}

/// 🔴 隐私锁下核日志转发下限：`SubscribeLog` 是全级别流，不设限就等于把隐私锁在生成侧堵住的
/// 那条路从新流上放回来 —— 用户访问的域名会经本仓 sink 落进**不脱敏**的 `polaris.log`。
///
/// 判据必须与生成侧同源（`LogLevel::effective`），否则两侧各自漂：这里断言的正是「同一条判据
/// 在转发口上的投影」。
///
/// **变异锁**：把隐私腿改成 `log::Level::Trace`（等于不设限）→ 第二、三条转红；
/// 把非隐私腿改成 `Warn`（过度设限，常态下丢掉用户要看的 info/debug）→ 第一条转红。
#[test]
fn core_log_privacy_floor_matches_generation_side_effective_level() {
    use polaris_config_engine::user_config::LogLevel;
    // 非隐私：不设限（`log::Level` 的最啰嗦档）。
    assert_eq!(core_log_privacy_floor(false), log::Level::Trace);
    // 隐私：抬到 warn ⇒ info/debug/trace 的核行一律不转发。
    assert_eq!(core_log_privacy_floor(true), log::Level::Warn);
    assert!(
        log::Level::Info > core_log_privacy_floor(true)
            && log::Level::Debug > core_log_privacy_floor(true)
            && log::Level::Trace > core_log_privacy_floor(true),
        "隐私锁开启时，连接明细所在的 info/debug/trace 三档必须全部被下限挡掉"
    );
    assert!(
        log::Level::Warn <= core_log_privacy_floor(true)
            && log::Level::Error <= core_log_privacy_floor(true),
        "warn/error 仍要转发（隐私锁不是把排障能力也一起关掉）"
    );
    // 与生成侧同源：判据是 `LogLevel::effective(privacy)`，不是这里另写的一条阈值。
    assert_eq!(LogLevel::Debug.effective(true), LogLevel::Warn);
    assert_eq!(LogLevel::Debug.effective(false), LogLevel::Debug);
}

/// ANSI 剥除自身：无 ESC → 零分配借用；CSI 序列整段吞掉；孤立 ESC 不得把后文一起吃了。
#[test]
fn strip_ansi_handles_csi_and_degenerate_input() {
    assert!(matches!(strip_ansi("plain"), Cow::Borrowed("plain")));
    assert_eq!(strip_ansi("\u{1b}[1;31mred\u{1b}[0m tail"), "red tail");
    assert_eq!(
        strip_ansi("a\u{1b}b"),
        "ab",
        "孤立 ESC（非 CSI）只丢它自己，后文原样保留"
    );
}

/// A2/C13：日志两轴从裸 config JSON 读。
/// 打断 `logLevel` 读取（回退恒 Info）→ 第一断言转红；打断 `disableLogFile` 读取 → 第二断言转红。
#[test]
fn log_axes_follow_config() {
    use polaris_config_engine::user_config::LogLevel;
    // logLevel 跟随（此前硬编码 Info 会让 warn/debug 全丢）。
    let (lvl, dis) = log_axes_from_config(&serde_json::json!({ "logLevel": "warn" }));
    assert_eq!(lvl, LogLevel::Warn, "logLevel 必须跟随 config，不得恒 Info");
    assert!(!dis, "未给 disableLogFile → false");
    // disableLogFile 跟随。
    let (lvl2, dis2) =
        log_axes_from_config(&serde_json::json!({ "logLevel": "debug", "disableLogFile": true }));
    assert_eq!(lvl2, LogLevel::Debug);
    assert!(dis2, "disableLogFile=true 必须落地");
    // 缺省 / 非法字符串 → Info；disableLogFile 非 true 一律 false。
    let (lvl3, dis3) =
        log_axes_from_config(&serde_json::json!({ "logLevel": "bogus", "disableLogFile": "yes" }));
    assert_eq!(lvl3, LogLevel::Info, "非法 logLevel → 默认 Info");
    assert!(!dis3, "disableLogFile 非布尔 true → false");
    // 空 config → (Info, false)。
    let (lvl4, dis4) = log_axes_from_config(&serde_json::json!({}));
    assert_eq!(lvl4, LogLevel::Info);
    assert!(!dis4);
}

// ══════════════ B1：隐私模式不抬核日志级别 ══════════════

/// **隐私模式活态必须真的流进 `GenerateConfigDeps.privacy_mode`**（此前硬编码 false）。
///
/// 后果不是 UI 问题而是**落盘泄露**：`build_log_config` 的 `effective(privacy)` 把 info/debug 抬到
/// warn，正是为了让隐私期 helper stderr 不记连接明细；硬编码 false 时那条抬级永远不触发。
///
/// **变异锁**：把 `privacy_mode:` 改回 `false` → 第二条转红；把 `privacy_mode_active` 的
/// emitter 未接线默认改成 `true` → 第一条转红（未接线时不得擅自抬级 = 静默改变用户设定的日志级别）。
#[test]
fn privacy_mode_flows_into_generate_deps() {
    let (rt, _dir) = test_runtime(); // 未接线 emitter
    assert!(
        !rt.generate_deps(1, 0, 0, None, &[], &serde_json::json!({}))
            .privacy_mode,
        "emitter 未接线（单测 / setup 前）→ 保守 false，与接线前逐字节同"
    );
    rt.set_error_emitter(Box::new(RecordingErrorEmitter {
        privacy_mode: true,
        ..Default::default()
    }));
    assert!(
        rt.generate_deps(1, 0, 0, None, &[], &serde_json::json!({}))
            .privacy_mode,
        "隐私模式开启时 deps 必须为 true，否则核日志级别不抬 ⇒ 隐私期域名照写 helper stderr"
    );
}

/// W26：生产 runtime 永远不给 sing-box `log.output` 文件句柄；否则 child 自己持有的 fd/handle
/// 无法被 Polaris writer 运行期轮转，1.46GB 同型故障会直接复发。
#[test]
fn runtime_log_output_is_owned_by_bounded_sink_not_core() {
    let (rt, _dir) = test_runtime();
    assert!(
        rt.generate_deps(1, 0, 0, None, &[], &serde_json::json!({}))
            .log_file_path
            .is_none(),
        "runtime config 不得把固定 output 文件重新交给 sing-box 持有"
    );
}

/// **接线守卫**：核日志 relay 与 stderr 转发腿的交接必须成对存在。
///
/// 两半各自缺席的后果不同、且都静默：
///  - 直起腿没把 `handoff` 交给 `pipe_to_log` ⇒ 核就绪后每行进两遍环形缓冲（日志页整屏重影）；
///  - relay 没接上 `log_pipe_handoff` ⇒ 管道永不让位，同样重影；
///  - relay 压根没挂 ⇒ TUN/helper 腿日志页零核行（这正是本批要修的那条），而直起腿看不出区别。
///
/// 三条都够不着行为测试（要真起核 + 真管理 API），故落成源码接线断言。
#[test]
fn core_log_relay_and_stderr_pipe_hand_off_to_each_other() {
    let body = method_body(
        &module_code("runtime/proxy"),
        "    pub(super) async fn start_inner(",
    );
    assert!(
        body.contains("let handoff: CoreLogHandoff = Arc::new(AtomicBool::new(false));")
            && body.contains("log_pipe_handoff = Some(handoff);"),
        "直起腿必须建交接闸并交给 relay（否则核就绪后每行进两遍缓冲）"
    );
    // 交接闸搬进了 `SpawnRequest` 的排空回调里（闭包捕获 `sink_handoff`），故判据打在
    // 「两条 `pipe_to_log(` 各自带上了闸」上，而不再是外层的 `Arc::clone(&handoff)` 次数。
    let compact: String = body.split_whitespace().collect();
    assert_eq!(
        compact.matches("pipe_to_log(").count(),
        2,
        "stdout / stderr 两条管道都要接进转发腿（漏一条 = 那条管道的读端被丢掉，诊断静默消失）"
    );
    assert!(
        compact
            .contains("pipe_to_log(stdout,SING_BOX_TARGET,None,Some(Arc::clone(&sink_handoff)),")
            && compact.contains(
                "pipe_to_log(stderr,SING_BOX_TARGET,Some(sink_fatal),Some(sink_handoff),"
            ),
        "stdout / stderr 两条管道都要拿到交接闸（漏一条 = 那条腿永不让位）"
    );
    assert!(
        body.contains("self.spawn_core_log_relay(my_gen, api_port, log_pipe_handoff.clone());"),
        "relay 必须在核就绪处按世代挂上，且接的就是本腿的交接闸"
    );
    // helper 腿不建闸：那条腿根本没有管道，`None` 同时也是 relay「收下首帧历史」的判据。
    assert!(
        body.contains("let mut log_pipe_handoff: Option<CoreLogHandoff> = None;"),
        "交接闸默认 None（helper 腿无管道 ⇒ relay 必须收下首帧历史）"
    );
}

/// **接线守卫（relay 体内）**：核日志 relay 的三条承重接线。缺任一条都不会编译报错、也不会让
/// 任何行为测试转红（relay 要真核 + 真管理 API 才跑得起来），但后果各自明确：
///
///  - 不读隐私下限 / 读了不用 ⇒ 隐私锁开着时用户访问的域名照样落进**不脱敏**的 `polaris.log`；
///  - 下限（或级别上限）在循环**外**只读一次 ⇒ 运行期打开隐私锁 / 改级别不生效
///    （「开了锁还在漏」「拨到 debug 却还是看不到」）；
///  - 级别上限的预筛落在 [`strip_core_log_decoration`] **之后** ⇒ 判定结果一模一样、
///    `core_log_admits` 的单测也全绿，但每条注定被丢的 trace/debug 行照旧付两次堆分配 ——
///    这道预筛的**全部价值**就在那个先后次序上，只有源码断言看得见；
///  - `frame.reset` 那格丢了 ⇒ 每次断线重连把至多 3000 行历史当增量整屏重放。
#[test]
fn core_log_relay_applies_privacy_floor_per_frame_and_guards_reset_history() {
    let body = method_body(
        &module_code("runtime/proxy"),
        "    pub(super) fn spawn_core_log_relay(",
    );
    assert!(
        body.contains("let floor = core_log_privacy_floor(me.privacy_mode_active());")
            && body.contains("if !core_log_admits(level, floor, max) {"),
        "转发口必须过 core_log_admits（否则隐私锁在生成侧堵住的路从这条流上原样漏回来）"
    );
    // 两道闸都必须在**收帧之后**读：隐私模式与日志级别都可运行期切换，起流时定死即失效。
    let frame_at = body.find("Ok(Some(frame)) =>").expect("收帧分支锚点消失");
    assert!(
        frame_at
            < body
                .find("let floor = core_log_privacy_floor(")
                .expect("隐私下限锚点消失"),
        "隐私下限必须逐帧现读，不得在起流时定死"
    );
    assert!(
        frame_at
            < body
                .find("let max = log::max_level();")
                .expect("级别上限锚点消失"),
        "级别上限必须逐帧现读，不得在起流时定死"
    );
    // 预筛必须早于剥除 —— 否则这道闸只剩「与 log! 判定一致」，白搬的活一点没省。
    assert!(
        body.find("if !core_log_admits(level, floor, max) {")
            .expect("预筛锚点消失")
            < body
                .find("let text = strip_core_log_decoration(")
                .expect("剥除锚点消失"),
        "级别预筛必须在剥除之前（放到之后 = 每条被丢的行照付两次堆分配，行为测试全绿）"
    );
    assert!(
        body.contains("if frame.reset {") && body.contains("if !history_pending {"),
        "reset 帧必须单独判：重连必然重发全量历史，照单收下 = 整屏重放"
    );
    assert!(
        body.contains("if me.gate.generation() != my_gen {"),
        "世代守卫必须在（ReconnectingStream 永不自结束，没有它 relay 会泄漏并对死端口无限重连）"
    );
}

/// **接线守卫（消费侧）**：`pipe_to_log` 真的按交接闸让位，且**让位只挡转发、不挡 FATAL 分类**。
///
/// 上一条守的是「闸有没有被建出来、有没有交到两边手里」，管不到闸**在管道循环里被怎么用**：
/// 把那个 `if` 删掉 ⇒ 核就绪后每行进两遍环形缓冲；反过来把分类也塞进 `if` 里 ⇒ 就绪之后核以
/// `log.Fatal` 死掉时真因收不到（那条行只走 stderr，`SubscribeLog` 结构性看不见它）。两种改法
/// 上一条都恒绿。
///
/// # 为什么是源码断言而不是行为测试
///
/// 转发的落点是 `log::log!` → `logging.rs` 的 sink，而**单测进程里根本没有装 sink**
/// （`log::set_logger` 只在 `logging::init` 里调，生产启动路径才走）⇒ 无论闸是开是关，环形缓冲
/// 都收不到任何东西，行为测试对这两种改法**结构上零信息量**。装一个进程级 logger 又会污染同一
/// 测试二进制里 `logging.rs` 那几条已经串行化的全局级别用例。故按本模块既有惯例落成源码断言。
///
/// **判据区域排除自身**：只在 `pipe_to_log` 函数体这一段里找（起于其函数头、止于其闭合大括号）。
/// 旧版还要断言该函数头出现在 `mod tests` 之前——测试实体外移到 `runtime/proxy/tests/` 之后，
/// `runtime/proxy.rs` 全文恒为生产码，本测试自己写下的字面量结构上已不可能给判据充数，那条
/// 自检既不再需要也不再成立（文件里已无 `mod tests {`）。
#[test]
fn pipe_to_log_yields_forwarding_on_handoff_but_never_yields_fatal_classification() {
    let src = module_code("runtime/proxy");
    let start = src
        .find("pub(crate) fn pipe_to_log<R>(")
        .expect("锚点 `pub(crate) fn pipe_to_log<R>(` 消失，源码型守卫已失去判据");
    let body = &src[start..];
    let body = &body[..body.find("\n}\n").expect("pipe_to_log 函数体没闭合")];

    assert!(
        body.contains(
            "if !handoff.as_ref().is_some_and(|h| h.load(Ordering::SeqCst)) {\n                log::log!(target: target, level, \"{line}\");"
        ),
        "转发必须被交接闸挡住（否则核就绪后每行进两遍环形缓冲，日志页整屏重影）"
    );
    // 分类在闸**外**：缩进 12 空格 = 与 `if` 同层；被塞进 `if` 里就会变成 16 空格。
    assert!(
        body.contains(
            "\n            let Some(kind) = classify_core_fatal_line(&line, level) else {"
        ),
        "FATAL 分类不得被交接闸挡住：就绪之后核以 log.Fatal 死掉时，那条行只走 stderr"
    );
}

/// 🔴 **一个非 UTF-8 字节不得掐断主核的 stderr 转发**（姊妹腿与 `tailscale_login_core::drain_to_log`
/// 同一形态、同一处置）。
///
/// `AsyncBufReadExt::lines()` 遇非 UTF-8 返回 `Err(InvalidData)`，外层 `while let Ok(Some(_))` 会把它
/// 当成流结束 ⇒ 转发任务退出、而核还活着 ⇒ 管道无人读、写满即把核堵死。起核期正是 FATAL 最可能
/// 出现、也最需要日志的那一段，而本腿是那一段**唯一**的日志来源（`SubscribeLog` 要等核就绪）。
///
/// **牙**：把 `read_until` + `from_utf8_lossy` 换回 `lines()` ⇒ 写手停在管道容量上 ⇒ 字节数断言转红。
#[tokio::test]
async fn pipe_to_log_keeps_reading_past_a_non_utf8_line() {
    // 容量取 64 KiB = Linux 匿名管道默认容量，把真实回压同构搬进内存；灌 1 MiB = 容量的 16 倍。
    const CAP: usize = 64 * 1024;
    const TOTAL: usize = 1024 * 1024;
    let (mut writer, reader) = tokio::io::duplex(CAP);
    let (tx, rx) = tokio::sync::watch::channel(0usize);
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let _ = writer.write_all(b"+0800 INFO before\n").await;
        let _ = writer.write_all(b"+0800 INFO broken \xff\xfe line\n").await;
        let mut line = vec![b'z'; 1023];
        line.push(b'\n');
        let mut sent = 0usize;
        while sent < TOTAL {
            if writer.write_all(&line).await.is_err() {
                return;
            }
            sent += line.len();
            let _ = tx.send(sent);
        }
    });
    pipe_to_log(reader, crate::logging::SING_BOX_TARGET, None, None);
    let mut rx = rx;
    let drained = matches!(
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            rx.wait_for(|n| *n >= TOTAL)
        )
        .await,
        Ok(Ok(_))
    );
    let written = *rx.borrow();
    assert!(
        drained,
        "坏字节之后必须继续排空：写手只推进到 {written} / {TOTAL} 字节 —— 转发任务在坏行处退出了"
    );
}
