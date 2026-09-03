//! 核日志 owner：`SubscribeLog` relay、核 stderr 转发腿与两者的交接闸、核日志级别/隐私地板/
//! 准入判定、ANSI 与级别前缀剥离、FATAL 行分类与启动日志游标、config-engine 日志两轴读取。
//!
//! L1：只依赖 façade 定义（[`ProxyRuntime`] / `code`）与管理 API 客户端，不回头取用兄弟域的私有项。

use std::borrow::Cow;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use polaris_singbox_grpc::{Endpoint, ReconnectConfig, SingBoxApiClient};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, BufReader};

use super::{code, ProxyRuntime};
// B9 白名单退役：`CRASH_MONITOR_POLL_MS` / `SINGBOX_STARTUP_LOG` 已各归 `recovery` / `startup`
// 域，改走多段路径直取定义模块（§B.1 #4 的正确方向）；`TUN_ADDRESS_UNAVAILABLE_MSG` 与 `code`
// 同属 façade 永久面（§C 例外①），仍回掏 façade。
use super::recovery::CRASH_MONITOR_POLL_MS;
use super::startup::SINGBOX_STARTUP_LOG;
use super::TUN_ADDRESS_UNAVAILABLE_MSG;

impl ProxyRuntime {
    /// 用户是否关掉了日志写盘（`disableLogFile`）。**它不只是「不写文件」**：该开关落到生成配置就是
    /// `log.disabled=true`，而 sing-box 见到它直接返回 `NewNOPFactory()`（`log/log.go`）—— 整个日志
    /// 工厂变空实现，`SubscribeLog` 也就永久没有任何一帧。核日志 relay 据此决定压根不订阅。
    ///
    /// 同 [`Self::clash_api_secret`] 走 `with_current` 投影而非 `current()`：只要一个布尔，
    /// 不为它 clone 整份配置。
    fn log_file_disabled(&self) -> bool {
        self.config
            .with_current(|c| c.get("disableLogFile").and_then(Value::as_bool))
            .ok()
            .flatten()
            .unwrap_or(false)
    }

    /// 核就绪后挂**核日志 relay**：订阅管理 API 的 `SubscribeLog`，逐行喂进本仓日志 sink
    /// （`logging.rs` 的环形缓冲 + 落盘 + UI 直播流）。世代范式与 `spawn_tailscale_status_relay` 同款。
    ///
    /// # 它修掉的两件事
    ///
    /// ① **TUN/helper 腿 app 侧没有 child 管道**：helper 在自己的进程里排空核 stdout/stderr，app 无法
    ///    从那根 pipe 做实时分发。本 relay 不经 child stderr，三平台 helper 腿统一拿到结构化实时日志。
    /// ② **看 debug 不必再改核配置**：本流恒是全级别（喂它的 platform writer 分发不受 `log.level`
    ///    过滤，见 crate `polaris-singbox-grpc` 的 `subscribe_logs` 文档），级别筛在客户端 ——
    ///    判据是 `log::max_level()`，由 `logging::set_level` 跟着 `config.logLevel` 即时改。
    ///    把级别拨到 debug **立刻**就能看到核的 debug 行，无需落盘、无需重启核。
    ///    该判据在本方法里由 [`core_log_admits`] **提前**取一次（下游 `log::log!` 仍会按同一个值再筛
    ///    一遍，故去留不变）—— 提前只为省下注定被丢的行的剥除代价，理由见该函数文档。
    ///    旧的 `diagnosticCapture`（快照原级别 → 改配置到 debug → 落盘 → 广播 → 重启核 → 事后还原，
    ///    外加崩溃自愈）整条链的存在理由就是这一条，故随本批一并删除。
    ///
    /// # 与 stderr 转发腿的交接（`pipe_handoff`）
    ///
    /// `Some(flag)` = 本腿是直起（有 stderr 管道）：
    ///
    /// - 收到首帧即置位 flag，`pipe_to_log` 随即停止转发 —— 否则同一行进两遍环形缓冲；
    /// - 首帧那份历史**丢弃**：它覆盖的正是管道已经转发过的那一段，收下就是整屏重放。
    ///
    /// `None` = 本腿经 helper 起（无管道）：首帧历史**收下**，那是起核到订阅之间唯一的日志来源。
    ///
    /// 残留窗口如实记账：从服务端 Subscribe 到本侧收到首帧之间（loopback 上一个往返）产生的行，
    /// 既在增量帧里、也仍被管道转发一次 —— 会重一两行，不做进一步收敛（消除它要引入序号对账，
    /// 代价远大于收益）。
    ///
    /// # 重连后的历史同样丢弃
    ///
    /// `ReconnectingStream` 断线重连必然再收一帧 `reset=true` + 全量历史（服务端语义）。整份收下 =
    /// 最多 3000 行重放上屏；故一律跳过，代价是断连窗口内的行看不到。**这是有意的取舍**，并在
    /// debug 日志里点名说出跳过了多少行，不静默。
    ///
    /// # `disableLogFile` 时压根不订阅
    ///
    /// 该开关落到核就是 `log.disabled=true` → `log.New` 直接返回 `NewNOPFactory()`
    /// （`log/log.go`），其 `AttachPlatformWriter` 是空实现 ⇒ 本流永久空。此时订阅只是白建连接，
    /// 更糟的是「订阅着却一行没有」与「核真的一句话没说」在外部无从区分。故直接不订阅，并把原因
    /// **写进日志**（那行本身会进日志页，用户一眼看见为什么这里是空的）——这就是原先挂在
    /// 「开始诊断采集」按钮上那道护栏的去处：它守的事实没变，只是搬到了机制真正所在的地方。
    pub(super) fn spawn_core_log_relay(
        self: &Arc<Self>,
        my_gen: u64,
        api_port: u16,
        pipe_handoff: Option<CoreLogHandoff>,
    ) {
        if self.log_file_disabled() {
            log::warn!(
                "「关闭日志写盘」已开启 ⇒ sing-box 侧日志被整体禁用（log.disabled），\
                 本次运行不会有任何内核日志（实时日志与基于日志的诊断均不可用）。\
                 要排查内核问题请先在「设置 · 高级」里关掉该开关"
            );
            return;
        }
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let secret = me.clash_api_secret();
            let client =
                match SingBoxApiClient::connect(Endpoint::new("127.0.0.1", api_port), secret).await
                {
                    Ok(c) => c,
                    Err(e) => {
                        log::warn!("核日志 relay 连接管理 API 失败（apiPort={api_port}）: {e}");
                        return;
                    }
                };
            let mut stream = client.subscribe_logs(ReconnectConfig::default());
            // 世代兜底轮询间隔：`ReconnectingStream` 永不自结束（断开即重连），核安静时也得有机会
            // 醒来查世代 —— 否则核停了但一直没帧时 relay 会泄漏、对死端口无限重连（同 TS STATUS relay）。
            let tick = Duration::from_millis(CRASH_MONITOR_POLL_MS);
            // 首帧那份历史收不收：无管道（helper 腿）才收，见方法文档。
            let mut history_pending = pipe_handoff.is_none();
            let mut forwarded: u64 = 0;
            // 被本侧筛掉的行数。计它不是为了好看：**「全级别流的常态开销」在此之前无从观测** ——
            // 核恒推 trace 在内的每一帧，用户却常年停在 info，两者之比只能靠猜。退场时把它说出来，
            // 于是真机上「这条流到底白搬了多少」是一个可读的数，而不是一个待办事项。
            let mut filtered: u64 = 0;
            log::info!("核日志 relay 起（世代 {my_gen}，apiPort={api_port}）");
            loop {
                if me.gate.generation() != my_gen {
                    log::info!(
                        "核日志 relay 退场（世代 {my_gen}→{}）：本代共转发 {forwarded} 行、筛掉 {filtered} 行",
                        me.gate.generation()
                    );
                    // 交接闸复位：本腿的管道任务可能还活着（子进程尚未收尸），别让它一直哑着。
                    if let Some(h) = &pipe_handoff {
                        h.store(false, Ordering::SeqCst);
                    }
                    return;
                }
                match tokio::time::timeout(tick, stream.recv()).await {
                    Ok(Some(frame)) => {
                        // 收帧后复查世代：接管方可能刚拆核，别把旧核的行写进新核的会话。
                        if me.gate.generation() != my_gen {
                            continue; // 交给循环顶的守卫统一退场（含闸门复位）
                        }
                        // 流已活 → stderr 转发腿让位（它继续跑 FATAL 分类，只是不再转发）。
                        if let Some(h) = &pipe_handoff {
                            h.store(true, Ordering::SeqCst);
                        }
                        if frame.reset {
                            if !history_pending {
                                if !frame.messages.is_empty() {
                                    log::debug!(
                                        "核日志流（重）订阅：跳过 {} 行历史（已在缓冲里，重收 = 整屏重放）",
                                        frame.messages.len()
                                    );
                                }
                                continue;
                            }
                            history_pending = false;
                        }
                        // 两道闸都**逐帧现读**（隐私模式与日志级别都能在运行期变；起流时定死分别就是
                        // 「开了锁还在漏」和「拨到 debug 却还是看不到」）。
                        let floor = core_log_privacy_floor(me.privacy_mode_active());
                        let max = log::max_level();
                        for m in &frame.messages {
                            let level = core_log_level(m.level);
                            if !core_log_admits(level, floor, max) {
                                filtered += 1;
                                continue;
                            }
                            let text = strip_core_log_decoration(&m.message);
                            if text.is_empty() {
                                continue;
                            }
                            log::log!(target: crate::logging::SING_BOX_TARGET, level, "{text}");
                            forwarded += 1;
                        }
                    }
                    // ReconnectingStream 正常永不返 None（断开即重连）；真返 None = 内部终止 → 退场。
                    Ok(None) => {
                        if let Some(h) = &pipe_handoff {
                            h.store(false, Ordering::SeqCst);
                        }
                        return;
                    }
                    // tick 内无帧：核安静时的常态。只为让世代守卫有机会跑。
                    Err(_) => {}
                }
            }
        });
    }

    /// **B1 隐私模式活态**（`generate_deps` 用）：经 [`ProxyErrorEmitter::privacy_mode`](super::ProxyErrorEmitter::privacy_mode) 读单一真值。
    /// emitter 未接线（单测 / setup 前极早期）→ `false` = 与接线前逐字节同的保守值（见 trait 方法文档）。
    pub(super) fn privacy_mode_active(&self) -> bool {
        self.error_emitter.get().is_some_and(|e| e.privacy_mode())
    }

    /// **#332**：helper 起核腿开始前的启动日志游标（非 helper 腿为空游标，零系统调用）。
    ///
    /// 新 helper 会在每次 spawn 前 fresh-rotate 启动日志，旧 helper 仍会 append。整文件扫 FATAL 会把
    /// 上一次会话（甚至上一条重试腿）的失败当成这一次的真因 —— 那比不给真因更糟，因为它看起来是
    /// 确诊。故同时记文件身份与长度：同一文件才从旧长度读，身份变化或文件缩短都从 0 读。
    ///
    /// 取不到长度（文件还不存在 = 首次起核）→ 0，语义正好是「整文件都是本腿写的」。
    pub(super) fn startup_log_cursor(&self, via_helper: bool) -> StartupLogCursor {
        if !via_helper {
            return StartupLogCursor::default();
        }
        std::fs::metadata(self.config.join(SINGBOX_STARTUP_LOG)).map_or_else(
            |_| StartupLogCursor::default(),
            |metadata| StartupLogCursor {
                offset: metadata.len(),
                identity: log_file_identity(&metadata),
            },
        )
    }

    /// **#332**：读出本腿核 stderr 里的结构化真因（两条起核路径各取各的来源）。
    ///
    /// - **直起**：核 stderr 是我方管道，[`pipe_to_log`] 已在流上逐行判过 → 直接取槽。
    /// - **helper 起**（Windows/macOS 的 TUN 路径）：app 侧**没有**那根管道，核 stderr 被 helper
    ///   经受管 writer 收进 `SINGBOX_STARTUP_LOG` → 按本腿游标取会话片段再扫。**这一条不能省**：#332 的现场就是
    ///   Windows TUN，而 TUN 恒经 helper 起核 —— 只接管道那条腿，等于修在一条永远跑不到的路上。
    ///
    /// # 已知边界（诚实标注，不是漏了）
    ///
    /// - **直起腿有竞态**：判 Dead 与转发任务读完最后一行之间没有同步点，核 FATAL 后立即退出时可能
    ///   还没写进槽 → 退回泛化 `STARTUP_FAILED`。**只降级不误报**（拿不到真因就不声称有），故不为它
    ///   引入一次「等管道 drain」的额外等待 —— 那要在每条失败腿上给所有用户加延迟，换一个偶发的
    ///   诊断精度。
    /// - 尾巴读取有上限（[`CORE_FATAL_SCAN_BYTES`]）：核在 FATAL 前刷了海量 debug 行时只看最后这一段。
    ///   FATAL 恒是**最后**几行（`log.Fatal` 之后进程即退出），故上限截的是前面的噪音。
    /// - 同步 `std::fs` 读：有界（≤ 上限）本地文件、且只在**失败腿**上发生；与 `start_inner` 里既有的
    ///   `std::fs::write(&config_path, …)` 同款处置，不为它起 `spawn_blocking`。
    pub(super) fn observe_core_fatal(
        &self,
        via_helper: bool,
        cursor: StartupLogCursor,
        slot: &CoreFatalSlot,
    ) -> Option<CoreFatalKind> {
        let kind = if via_helper {
            let path = self.config.join(SINGBOX_STARTUP_LOG);
            // 新 helper 每次 spawn 前 fresh-rotate（current 文件身份变化）→ 从 0 读；旧 helper 仍在
            // 同一个文件 append（身份不变）→ 从旧长度读。不能只比较长度：新会话完全可能比旧文件更长。
            let metadata = std::fs::metadata(&path).ok()?;
            let start =
                startup_log_read_start(cursor, metadata.len(), log_file_identity(&metadata));
            let tail = read_file_range(&path, start, CORE_FATAL_SCAN_BYTES)?;
            scan_core_fatal(&tail)
        } else {
            slot.lock().ok().and_then(|g| *g)
        };
        if let Some(k) = kind {
            log::error!("核启动失败真因（本腿 stderr 判定）：{k:?}");
        }
        kind
    }
}

/// 核 stderr 转发腿 ⇄ `SubscribeLog` 流的交接闸。
///
/// `false` = 流还没活，stderr 那条腿负责把核日志喂进 sink；`true` = 流已收到首帧并接管，
/// stderr 腿只保留 FATAL 分类、**不再转发**（否则直起腿每行会进两遍环形缓冲）。
pub(crate) type CoreLogHandoff = Arc<AtomicBool>;

/// helper 启动日志的会话边界。`identity=None` 表示起核前没有可识别的 current 文件。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct StartupLogCursor {
    pub(super) offset: u64,
    pub(super) identity: Option<u128>,
}

/// 判定本次 helper 起核日志从哪里开始读。
///
/// 兼容两代 helper：旧版在同一文件 append，新版 fresh-rotate 后 current 身份变化。单看长度不能区分
/// 「旧文件继续增长」和「新会话写得比旧文件更长」，故只有身份相同且未缩短时才沿用旧偏移。
pub(super) fn startup_log_read_start(
    cursor: StartupLogCursor,
    current_len: u64,
    current_identity: Option<u128>,
) -> u64 {
    if cursor.identity.is_some()
        && cursor.identity == current_identity
        && current_len >= cursor.offset
    {
        cursor.offset
    } else {
        0
    }
}

/// 文件身份只用于区分 helper 日志轮转前后的 current，不参与持久化或安全判定。
#[cfg(unix)]
fn log_file_identity(metadata: &std::fs::Metadata) -> Option<u128> {
    use std::os::unix::fs::MetadataExt;
    Some((u128::from(metadata.dev()) << 64) | u128::from(metadata.ino()))
}

#[cfg(windows)]
fn log_file_identity(metadata: &std::fs::Metadata) -> Option<u128> {
    use std::os::windows::fs::MetadataExt;
    Some(u128::from(metadata.creation_time()))
}

#[cfg(not(any(unix, windows)))]
fn log_file_identity(_metadata: &std::fs::Metadata) -> Option<u128> {
    None
}

/// 子进程 stdout/stderr → 日志 sink（`logging.rs` 的 `log::Log` 实现）+ 起核期 FATAL 真因分类。
///
/// # 全 app 唯一的一份子进程排空实现
///
/// 曾经有两份：本函数（主核，带 `CoreFatalSlot` / `CoreLogHandoff`，target 写死
/// [`SING_BOX_TARGET`](crate::logging::SING_BOX_TARGET)）与 `tailscale_login_core::drain_to_log`
/// （瞬态登录核 + 测速临时核，target 是参数，级别只认 FATAL/ERROR/WARN 三档）。两份实现各自漂的
/// 失效方式是静默的：新那份漏掉级别映射、漏掉 EOF 收尾、或者哪天有人把 `read_until` 换回
/// `lines()`，日志少几行没人会当场发现。现在合成一份，差异全部外化成参数：
///
/// - **`target`**：主核传 `SING_BOX_TARGET`（落 `singbox.log`、UI 来源「内核」），测速临时核传
///   [`SPEEDTEST_CORE_TARGET`](crate::logging::SPEEDTEST_CORE_TARGET)（落 `polaris.log` 与编排行同一条
///   时间线、UI 来源仍归「内核」），瞬态登录核传自己的 `tailscale-login`（落 `polaris.log`、UI 来源
///   「应用」）。**绝不能让瞬态核的行走主核 target**：落盘分流按字面 target 选文件，混进去既污染
///   `singbox.log` 的连续性，又让日志页按来源筛的结果说不清是哪个核。
/// - **`fatal` / `handoff`**：主核专属，瞬态核两条都传 `None`。`handoff` 是与 `SubscribeLog` 流的交接
///   闸（瞬态核没有那条流），`fatal` 是起核失败真因槽（瞬态核的失败由各自的 outcome 表达）。
///
/// 级别一律走 [`singbox_line_level`]，瞬态核那两条腿因此从三档（FATAL/ERROR/WARN，其余归 info）升到
/// 五档 —— 核的 DEBUG/TRACE 行此前一律显示成 `info`，用户把日志级别拨到 `debug` 反而**筛不出**唯一
/// 要看的那段（这是 `drain_to_log` 自己在文档里登记过的已知缺口，折叠顺手补上）。
///
/// # 本腿现在只覆盖「起核期」，但**不可删**
///
/// 核就绪后的日志已改由管理 API 的 `SubscribeLog` 流承担（结构化级别、全级别、不受 `log.level`
/// 过滤）。但那条流盖不住起核期：核在 `StartStateStarted` 才 `AttachPlatformWriter`
/// （`service/api/server.go`），此前的每一行——**包括 #332 那类 TUN 装地址失败的 FATAL**——
/// 结构性地不在流里。那一段只有 stderr 这一条路。
///
/// 交接由 `handoff` 表达（见 [`CoreLogHandoff`]）：流一收到首帧就置位，本腿随即停止转发但
/// **继续跑 [`classify_core_fatal_line`]** —— 核可以在就绪之后仍以 `log.Fatal` 死掉，那条行同样
/// 只走 stderr（包级 `std` logger 的 writer 恒是 `os.Stderr`，见调用处注释）。
/// `handoff` 为 `None` = 本腿经 helper 起核、压根没有管道（helper 把核输出重定向进启动日志文件）。
///
/// 逐行转发；凭据脱敏统一由 `logging.rs::PolarisLogger` 在落盘/环形缓冲之前完成。这里不另复制一份
/// 协议黑名单，否则 stderr 与 `SubscribeLog` 两条腿会很快漂出不同安全口径。
///
/// **级别按行内容判，不按流判**：sing-box 把 INFO/WARN/FATAL **全写 stderr**（实测），
/// 故「stderr ⇒ warn」会把满屏正常 INFO 谎报成 warn；反过来「stderr ⇒ info」又会让
/// `POLARIS_LOG=warn` 的用户丢掉核的 FATAL。取行内自带的级别 token 做映射（见 [`singbox_line_level`]）。
/// 这套「按字符串猜级别」只服务起核期这一小段——就绪后的级别由核经 gRPC 结构化给出，不再猜。
///
/// **#332**：`fatal` 非空时，同一条已判过级别的行再过一次
/// [`classify_core_fatal_line`]，命中就把结构化真因落进槽里 —— 转发与分类**共用一次级别判定**，
/// 不在旁边并排再起一套行解析。槽由起核腿在失败时读走（见
/// [`observe_core_fatal`](ProxyRuntime::observe_core_fatal)）。
pub(crate) fn pipe_to_log<R>(
    stream: R,
    target: &'static str,
    fatal: Option<CoreFatalSlot>,
    handoff: Option<CoreLogHandoff>,
) where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        // **按字节读、不用 `lines()`**：`AsyncBufReadExt::lines()` 遇非 UTF-8 字节返回
        // `Err(InvalidData)`，而 `while let Ok(Some(_))` 会把它当成流结束 ⇒ 整条 drain 就此退出、
        // 而核还活着 ⇒ 管道无人读、写满即把核堵死（起核期正是 FATAL 最可能出现、也最需要日志的
        // 那一段）。`read_until` 是字节级的，坏字节经 `from_utf8_lossy` 渲染成 U+FFFD，排空不中断。
        // 全 app 只剩这一份排空实现，源码守卫 `no_child_stream_drain_uses_lines` 盯着它不许退回。
        let mut reader = BufReader::new(stream);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match reader.read_until(b'\n', &mut buf).await {
                Ok(0) => break, // EOF
                Ok(_) => {}
                Err(_) => break, // 真 I/O 错
            }
            while buf.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
                buf.pop();
            }
            let line = String::from_utf8_lossy(&buf);
            let level = singbox_line_level(&line);
            // 已交接给 SubscribeLog 流 → 不转发（分类照跑：就绪后的 log.Fatal 仍只走 stderr）。
            // 瞬态核没有那条流，`handoff` 恒 `None` ⇒ 恒转发。
            if !handoff.as_ref().is_some_and(|h| h.load(Ordering::SeqCst)) {
                log::log!(target: target, level, "{line}");
            }
            let Some(slot) = fatal.as_ref() else { continue };
            let Some(kind) = classify_core_fatal_line(&line, level) else {
                continue;
            };
            // **首个命中为准**：核在 FATAL 之后可能还吐一串收尾错误，后来的更泛化，覆盖会稀释真因。
            if let Ok(mut g) = slot.lock() {
                g.get_or_insert(kind);
            }
        }
    });
}

/// 核侧 `LogLevel`（七档、0=PANIC 最严重）→ 本仓 sink 的 `log::Level`（五档）。
///
/// panic/fatal 无对应档，归 `Error`（本层最高档，与 [`crate::logging`] 的 `parse_level` 对 `fatal`
/// 的处置同口径）。**未知级号归 `Info` 而不是丢弃**：上游扩枚举时宁可级别偏保守，也不能把一行核日志
/// 静默吃掉——日志页是排障的最后一根线。
pub(super) fn core_log_level(raw: i32) -> log::Level {
    use polaris_singbox_grpc::daemon::LogLevel;
    match LogLevel::try_from(raw) {
        Ok(LogLevel::Panic | LogLevel::Fatal | LogLevel::Error) => log::Level::Error,
        Ok(LogLevel::Warn) => log::Level::Warn,
        Ok(LogLevel::Info) => log::Level::Info,
        Ok(LogLevel::Debug) => log::Level::Debug,
        Ok(LogLevel::Trace) => log::Level::Trace,
        Err(_) => log::Level::Info,
    }
}

/// 隐私锁下的核日志级别下限（纯函数）。比它更啰嗦的行一律丢弃。
///
/// # 这不是「再加一道保险」，是 `SubscribeLog` 亲手打开的一个新口子
///
/// 隐私锁此前把连接明细挡在盘外，靠的是**生成侧**把核的 `log.level` 抬到 ≥warn
/// （`config-engine::user_config::LogLevel::effective`）—— 核自己就不写 info/debug，自然也没什么可漏。
/// 但 `SubscribeLog` **不受 `log.level` 约束**（喂它的 platform writer 分发无级别过滤），核照样把
/// 每一条 debug/trace 推过来。若照单转发，隐私锁开着而 `config.logLevel=debug` 时，用户访问的域名
/// 会经本仓自己的 sink 落进 `polaris.log`（那份**不脱敏**；UI 上的脱敏只管显示，管不到磁盘）——
/// 隐私锁在生成侧堵住的那条路，就从这条新流上原样漏了回来。
///
/// 故此处复用**同一条判据**（`LogLevel::effective(privacy)` 抬到 warn），把它落在转发口上。
/// 判据只有一份，两侧不会各自漂。
pub(super) fn core_log_privacy_floor(privacy: bool) -> log::Level {
    use polaris_config_engine::user_config::LogLevel;
    // `log::Level` 的 Ord 是「越啰嗦越大」（Error < Warn < Info < Debug < Trace），故下限取 Warn
    // 即表示「比 Warn 啰嗦的都丢」；非隐私态取 Trace = 不设限。
    match LogLevel::Debug.effective(privacy) {
        LogLevel::Debug => log::Level::Trace, // 未抬级 ⇒ 非隐私态 ⇒ 不设限
        _ => log::Level::Warn,
    }
}

/// 一条核日志帧转不转发（纯函数）：隐私锁下限 ∧ 用户级别上限，两道闸**都**得过。
///
/// # 为什么级别上限要在这里再判一次
///
/// 下游 `log::log!` 本来就会按 `log::max_level()` 筛，所以这道闸**不改变任何一行的去留** ——
/// 它改变的是**筛之前干了多少活**。`SubscribeLog` 恒推全级别（含 trace），而用户常年停在 info：
/// 每一条注定被丢掉的 debug/trace 行，此前都要先付一遍 [`strip_core_log_decoration`] 的代价 ——
/// 而喂这条流的 formatter **没关色**，于是 `strip_ansi` 必然走到分配分支，加上末尾的 `to_string()`，
/// **每条被丢掉的行两次堆分配 + 两趟字符扫描**。核一忙（debug 档的路由/DNS 决策是每连接若干行）
/// 这就是一条常态空转的流水线。
///
/// 判据合成一处而不是散在调用点，是为了让它能被单独变异验证：两道闸各自的短路都有对应用例
/// （见 `core_log_admits_*`）。
///
/// 上限取 `log::max_level()` 的**当次读数**：它由 `logging::set_level` 跟着 `config.logLevel` 走，
/// 与本函数之外的那次 `log::log!` 之间存在窗口 —— 无所谓，级别变更本就没有「精确到某一行」的语义。
pub(super) fn core_log_admits(level: log::Level, floor: log::Level, max: log::LevelFilter) -> bool {
    // `log::Level` 的 Ord 是「越啰嗦越大」；`Level <= LevelFilter` 是 log crate 提供的跨类型比较。
    level <= floor && level <= max
}

/// `Log.Message.message` 的装饰剥除（纯函数）：ANSI 色码 + 冗余的 `LEVEL[nnnn] ` 前缀。
///
/// # 为什么必须剥
///
/// 喂 `SubscribeLog` 的是 logFactory 的 **platformFormatter**，而它构造时**没关色**
/// （`log/observable.go`：`Formatter{BaseTime: …, DisableLineBreak: true}`，`DisableColors` 取默认
/// `false`，紧邻那段关色的代码是被注释掉的），且走的是 `Format` 的默认时间戳分支
/// （`levelString + "[" + xd(启动至今秒数, 4) + "] " + message`）。于是每条消息实际长这样：
///
/// ```text
/// "\x1b[36mINFO\x1b[0m[0012] router: loaded 5 rules"
/// ```
///
/// 不剥的话，日志页每行会显示成 `INFO: <ESC>[36mINFO<ESC>[0m[0012] router: …` —— 转义序列以乱码
/// 呈现，级别还重复一遍（结构化 `level` 字段已经承担了级别，UI 自己渲染）。
///
/// # 剥不掉就原样返回
///
/// 前缀形状对不上（上游改了 formatter / 消息本身以别的东西开头）→ **整段原样保留**。
/// 剥除是显示层的清理，绝不能演变成「看起来不像我预期的行就被吃掉一半」。
pub(super) fn strip_core_log_decoration(msg: &str) -> String {
    let plain = strip_ansi(msg);
    strip_level_prefix(&plain).to_string()
}

/// 去掉 ANSI CSI 序列（`ESC [ … <字母>`）。无 `ESC` → 原样借用，不分配。
pub(super) fn strip_ansi(s: &str) -> Cow<'_, str> {
    if !s.contains('\u{1b}') {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        // ESC 后若不是 '['，不是 CSI（不认识）→ 连同 ESC 一起丢，后续原样保留。
        if chars.as_str().starts_with('[') {
            chars.next();
            // CSI 以 0x40..=0x7E 的字节收尾（色码恒是 'm'）。
            for t in chars.by_ref() {
                if ('\u{40}'..='\u{7e}').contains(&t) {
                    break;
                }
            }
        }
    }
    Cow::Owned(out)
}

/// 去掉行首那截 `LEVEL[nnnn] `（`nnnn` = 核启动至今的秒数，`log/format.go` 的 `xd(…, 4)`）。
/// 形状对不上 → 原样返回。
fn strip_level_prefix(s: &str) -> &str {
    const LEVELS: [&str; 7] = ["PANIC", "FATAL", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"];
    let Some(lv) = LEVELS.iter().find(|l| s.starts_with(**l)) else {
        return s;
    };
    let rest = &s[lv.len()..];
    let Some(rest) = rest.strip_prefix('[') else {
        return s;
    };
    let Some(close) = rest.find(']') else {
        return s;
    };
    // 方括号内必须全是数字（`xd` 产出的是零填充秒数）——不是就说明形状变了，别乱剥。
    if rest[..close].is_empty() || !rest[..close].bytes().all(|b| b.is_ascii_digit()) {
        return s;
    }
    rest[close + 1..]
        .strip_prefix(' ')
        .unwrap_or(&rest[close + 1..])
}

/// 核 stderr 里可结构化的**启动真因**（#332）。
///
/// 只收录「核自己说清楚了、且我方能给出不同用户动作」的那几类。**判据是内核源码里的字面量**，
/// 不是我方 message 的关键字 —— 后者就是 [`code`] 模块头注说的「猜 message = 伪造分类」。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CoreFatalKind {
    /// 给 TUN 网卡装地址这一步失败（地址被占 / 系统拒绝分配）→ [`code::TUN_ADDRESS_UNAVAILABLE`]。
    TunAddressUnavailable,
}

/// [`CoreFatalKind`] 的跨任务投递槽：`pipe_to_log` 的转发任务写、起核腿失败时读。
pub(crate) type CoreFatalSlot = Arc<Mutex<Option<CoreFatalKind>>>;

/// 核 stderr 单行 → 结构化真因（纯函数；`level` 由既有的 [`singbox_line_level`] 给，本函数不另判级别）。
///
/// # 取证（2026-08-05 实取，随包核 `resources/linux/sing-box` = 1.14.0-beta.7）
///
/// 命中链路（自外向内，`E.Cause` 以 `": "` 拼接）：
///
/// ```text
/// FATAL start service: initialize inbound/tun[...]: configure tun interface: set ipv4 address: <errno 文案>
///       ^cmd_run.go:168                            ^protocol/tun/inbound.go:438  ^sing-tun/tun_windows.go:81
/// ```
///
/// - `configure tun interface` —— sing-box `protocol/tun/inbound.go:438`（`E.Cause(err, "configure tun interface")`，
///   `tun.New` 的唯一包装点）。**已在随包二进制里逐字验到**（`strings resources/linux/sing-box` 命中）。
/// - `set ipv4 address` / `set ipv6 address` —— sing-tun `tun_windows.go:81` / `:102`
///   （`luid.SetIPAddressesForFamily` 失败的包装串；`SetIPAddressesForFamily` → `AddIPAddress` →
///   `CreateUnicastIpAddressEntry`，地址已被别的网卡占用即在此失败）。**Windows-only 文件，随包的
///   linux 核里查不到**（build tag 排除，`strings` 实测 0 命中）—— 证据取自 sing-tun 源码，不是猜的，
///   但也**没有**在二进制里对到字面量，这是本条匹配面唯一的取证缺口。
/// - `add address ` —— sing-tun `tun_linux.go:145` / `:154`（Linux 侧同一件事的包装串；
///   同理不在 Windows 核里）。收进来是因为本函数跨平台共用，Linux TUN 撞地址冲突时该给同一个码。
/// - macOS：`tun_darwin.go` 里**没有**对应的地址设置包装串（地址随 `SIOCAIFADDR` 一并设，失败走裸
///   errno），故 mac 侧本判定天然不命中 —— 不硬凑一个猜出来的 token 冒充覆盖。
///
/// # 为什么**不**匹配 errno 文案（"already exists" / "file exists"）
///
/// Windows 侧那截尾巴是 `syscall.Errno.Error()` 经 `FormatMessage` 生成的，**跟随系统语言**
/// （中文系统上是「对象已存在。」）。拿它做判据 = 判定在中文/俄文 Windows 上静默失效，而那正是
/// 用户最多的那批机器。上面三个 token 全是 Go 源码里的 ASCII 字面量，与系统语言无关。
///
/// 代价：判据比「地址冲突」宽 —— 装地址这一步的**任何**失败都会归到本码。这是有意的取舍：
/// 该步失败的现实成因几乎全是「地址被占/装不上」，且给出的指引（断开其他 VPN、重启清残留网卡）
/// 对这一整类都成立；而收窄到 errno 文案的代价是对非英文系统全盲。
pub(super) fn classify_core_fatal_line(line: &str, level: log::Level) -> Option<CoreFatalKind> {
    // 只看错误档（FATAL/ERROR）。正常 INFO 行里出现这些词只可能是别人的日志噪音。
    if level != log::Level::Error {
        return None;
    }
    // 外层包装必须在：单看 `add address` 会把任何提到该词的行都算上。
    if !line.contains("configure tun interface") {
        return None;
    }
    const ADDRESS_STEP_TOKENS: &[&str] = &["set ipv4 address", "set ipv6 address", "add address "];
    if ADDRESS_STEP_TOKENS.iter().any(|t| line.contains(t)) {
        return Some(CoreFatalKind::TunAddressUnavailable);
    }
    None
}

/// 文本块（helper 起核时核 stderr 被重定向进的启动日志片段）→ 首个命中的真因。
///
/// 逐行复用 [`classify_core_fatal_line`]（级别同样经 [`singbox_line_level`]），与管道那条腿**同一判据**。
pub(super) fn scan_core_fatal(text: &str) -> Option<CoreFatalKind> {
    text.lines()
        .find_map(|line| classify_core_fatal_line(line, singbox_line_level(line)))
}

/// 启动日志一次最多回扫的字节数（#332）。核 FATAL 恒在**末尾**（`log.Fatal` 之后进程即退出），
/// 故上限截掉的是它前面的 debug 噪音，不是真因本身。
const CORE_FATAL_SCAN_BYTES: u64 = 64 * 1024;

/// 从 `offset` 起读至多 `max_bytes`（读不到/读不动一律 `None`，best-effort 诊断绝不阻断主流程）。
///
/// **为什么不复用 `commands/misc::read_tail`**：那个是「取文件**末尾** N 字节」，语义上没有起点，
/// 拿它扫启动日志会把上一次会话遗留的 FATAL 一并扫进来（文件是 append 的）——本函数存在的全部理由
/// 就是那个起点。此外它私有、且失败时返回「(读取失败: …)」这类给人看的占位串，判定链路要的是 `None`。
fn read_file_range(path: &Path, offset: u64, max_bytes: u64) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path).ok()?;
    f.seek(SeekFrom::Start(offset)).ok()?;
    let mut buf = Vec::new();
    f.take(max_bytes).read_to_end(&mut buf).ok()?;
    // 核日志恒是 UTF-8；lossy 只为杜绝「日志里一个坏字节 = 整条诊断链路失效」。
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// 起核终态的码/文案收口（纯函数）：核给出了可诚实断言的真因就用真因的专属码，否则维持泛化
/// [`code::STARTUP_FAILED`]。
///
/// **`base_msg` 在有真因时被整句替换**而不是拼接：`base_msg` 是我方从控制流位置写下的话
/// （「起核超时」「启动期退出」），它描述的是**症状**；真因的文案描述的是**病因 + 下一步**。
/// 拼成一句只会得到「起核超时（管理 API 9090 …）：TUN 虚拟网卡地址无法分配…」这种把用户注意力
/// 引向前半句（无用）的句子。症状原样留在日志里，不进用户可见串。
pub(super) fn settle_start_failure(
    base_msg: String,
    fatal: Option<CoreFatalKind>,
) -> (String, &'static str) {
    match fatal {
        Some(CoreFatalKind::TunAddressUnavailable) => (
            TUN_ADDRESS_UNAVAILABLE_MSG.to_string(),
            code::TUN_ADDRESS_UNAVAILABLE,
        ),
        None => (base_msg, code::STARTUP_FAILED),
    }
}

/// sing-box 日志行 → `log::Level`（行内自带的级别 token）。
///
/// **DEBUG/TRACE 必须单独认**：此前它们落进 else 分支被打成 `info`，于是日志页把级别调到 DEBUG 时，
/// 核的 DEBUG 行早已伪装成 info 混在里面——既没法按 DEBUG 筛出来，也让「调到 INFO 就该看不见 DEBUG」
/// 失效（DEBUG 噪音在 INFO 档全量泄漏）。级别过滤要有意义，标级别就必须如实。
///
/// 按严重度**从高到低**匹配：一行只取最先命中的 token（sing-box 的行格式是 `+0800 INFO xxx`，
/// 级别 token 在正文前，正文里再出现别的 token 属噪音）。
///
/// # `INFO` 必须排在 `DEBUG`/`TRACE` **前面**（这一档的误判方向是不对称的）
///
/// 「从高到低」这条排序对 ERROR/WARN 是安全侧（误判成更严重 ⇒ 行仍然可见），对 DEBUG/TRACE
/// **方向是反的**：`log::Level` 里 `Debug`/`Trace` 比 `Info` 更**低**，被判成它们的行会被 app 的
/// `max_level`（跟随 `config.logLevel`，默认 `info`）整行滤掉 —— 误判在这一侧是**静默丢行**，
/// 不是「宁可留下」。
///
/// 可达触发面（不是理论形态）：sing-box 把 outbound/endpoint 的 tag 打进行前缀，而瞬态登录核的
/// tag 就是**用户自己输入的节点名**（`crates/mesh/src/tailscale_login.rs` 的 `endpoint.tag =
/// server.name`）。一个名字里含 `DEBUG` 的节点，它那条腿的每一行 INFO 在 info 档全部消失。
///
/// 故把 `INFO` 提到 `DEBUG` 之前：剩下的误判方向变成「DEBUG 行的正文里含 `INFO` 子串 ⇒ 判 Info」
/// = **升档**，那才是安全侧（多留一行噪音，而不是少一行诊断）。彻底的解法是按位置取级别 token
/// （行格式 `时间 级别 [tag] 内容` 固定），本函数没走那条路：它同时喂
/// [`classify_core_fatal_line`]（读的是**整行**里的 FATAL/ERROR 语义，与位置无关），改成按位置
/// 解析会把射程从「行里出现过」缩成「第二个字段是」，那是另一次改判据，不在本批射程内。
pub(super) fn singbox_line_level(line: &str) -> log::Level {
    if line.contains("FATAL") || line.contains("ERROR") {
        log::Level::Error
    } else if line.contains("WARN") {
        log::Level::Warn
    } else if line.contains("INFO") {
        // 前置于 DEBUG/TRACE：见上文，这一档误判成低档 = 用户在默认 info 档整行看不见。
        log::Level::Info
    } else if line.contains("DEBUG") {
        log::Level::Debug
    } else if line.contains("TRACE") {
        log::Level::Trace
    } else {
        log::Level::Info
    }
}

/// config-engine 子 builder 日志回调（`fn(LogLevel, &str)` 裸函数指针，不可捕获）。
///
/// **级别必须由调用方给**：此前签名无 level、恒 `log::info!` → 「规则资源缺少本地副本」这类降级告知
/// 被日志级别过滤直接吞掉（真机 2026-07-20：全量明文直连，日志里唯一线索只剩 `rule_set=0`）。
/// 对齐 上游 `deps.log('warn', …)`。
pub(super) fn config_log(level: polaris_config_engine::user_config::LogLevel, msg: &str) {
    use polaris_config_engine::user_config::LogLevel;
    let lv = match level {
        LogLevel::Debug => log::Level::Debug,
        LogLevel::Info => log::Level::Info,
        LogLevel::Warn => log::Level::Warn,
        // config-engine 侧无 panic 档；fatal 映射到 error（本层最高档）。
        LogLevel::Error | LogLevel::Fatal => log::Level::Error,
    };
    log::log!(target: "config-engine", lv, "{msg}");
}

/// config-engine customRuleFiles 降级回调（外化规则文件缺失 → 回落 inline 生成）。
pub(super) fn config_on_degraded() {
    log::warn!(target: "config-engine", "自定义规则外化文件不可用 → 回落 inline 生成");
}

/// 从原始 config JSON 读日志两轴（`logLevel` / `disableLogFile`），喂 `GenerateConfigDeps`。
///
/// **为何从裸 JSON 读**：`UserConfig` 增量子集未建模这两字段（见 `GenerateConfigDeps` 字段注释），
/// 与 `restartOnNodeChange`（switch_mode）同法从原始 `Value` 读，不经 `UserConfig` 结构体。
/// - `logLevel` 缺省 / 非法字符串 → `Info`（`LogLevel` 的 `#[default]`）。
/// - `disableLogFile` 非 `true` 一律 `false`（对齐 上游 `validateConfig` 布尔口径）。
///
/// 隐私抬级（`effective`）不在此：它由 `build_log_config` 按 `deps.privacy_mode` 处理，privacy 轴接线属 B1。
pub(super) fn log_axes_from_config(
    config: &Value,
) -> (polaris_config_engine::user_config::LogLevel, bool) {
    let log_level = config
        .get("logLevel")
        .cloned()
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();
    let disable_log_file = config
        .get("disableLogFile")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    (log_level, disable_log_file)
}
