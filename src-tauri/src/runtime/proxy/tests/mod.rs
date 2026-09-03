use super::core_log::*;
use super::*;
// B4：`process_supervision` / `recovery` 的域内项不经 façade 再导出（façade 不消费它们，
// 导入即 `unused_imports`），故测试 prelude 直接 glob 这两个 owner 模块。
use super::process_supervision::*;
use super::recovery::*;

/// 🔴 **出口 IP 重探腿与 unlock 失效腿必须成对**——起核 / 停核 / 热切三点，一个都不许漏。
///
/// # 为什么必须是源码扫描，而不是行为测试
///
/// 三个触发点里只有**停核**能在单测里真跑（`stop()` 无核也走 `stop_inner`）；起核与热切都要真起核 +
/// 真管理 API，属真机门。而这条不变式恰恰是本轮真机反馈「IP/延迟需手点」的根因所在：上游的触发表
/// 在 Polaris 侧**整列为空**，宿主（`invalidate_unlock_cache` 三点）明明已就位、只是没人接上去。
///
/// 故守的不是「某次调用发生了」，而是**结构性配对**：凡是判定「出口换了一次」而失效解锁快照的地方，
/// 出口 IP 也必然作废（同一个物理事实的两个下游）。将来有人加第四个触发点，本守卫会逼他对出口 IP 这条
/// 腿做一次显式决定，而不是默默漏掉——那正是这次漏掉的方式。
///
/// # ⚠️ 本守卫的逃逸面（已知取舍，别高估它的射程）
///
/// 判据是**文本邻近**（`WINDOW = 6` 行内出现配对调用），**不是同一执行分支**。因此下面这类写法守卫
/// 照样放行，而真机行为已经错了：
///
/// ```text
/// self.invalidate_unlock_cache();
/// if some_condition {
///     self.schedule_exit_ip_refresh(delay);   // 只在部分分支跑 —— 守卫看不出来
/// }
/// ```
///
/// 同理，两者被塞进不同的 `match` 臂、早退 `return` 之后、或相隔 7 行以上（哪怕逻辑正确）都会让守卫
/// 给出错误答案（前两种假绿，后一种假红）。要真正锁住「同一分支必然成对」得做控制流分析，静态文本扫描
/// 够不着，不在本批范围。本守卫只承诺：**触发点的数目**变了必转红（`KNOWN_TRIGGER_SITES` 写死），逼
/// 改动者对新触发点做一次显式决定。
mod exit_ip_wiring_guard;

mod core_log;
mod hot_switch;
mod lifecycle;
mod login_fallback;
mod module_boundary;
mod network_monitor;
mod platform_contracts;
mod process_supervision;
mod recovery;
mod route_replan;
mod startup;
mod ts_exit;
mod unlock_refresh;

// B5 搬运批跟随：`route_replan` / `network_monitor` 的生产项已从 façade 外移，测试侧经
// 各自模块的 prelude glob 取用（façade 只再导出它自己仍在消费的那部分，多余的再导出会
// 变成 `unused_imports`）。
use super::network_monitor::*;
use super::route_replan::*;
use crate::test_support::{module_code, TestDir};
// B6：`ts_exit` 域的自由项（`ts_exit_became_ready` / `ts_all_running` /
// `log_ts_state_transitions` / `TsExitRecoverGuard`）随生产码搬进 `proxy::ts_exit`，
// 顶部那条 `use super::*;` 只覆盖 façade ⇒ 子模块的 `pub(super)` 项要显式再引一次。
use super::ts_exit::*;
// B7：`hot_switch` / `auto_switch` 域的自由项（`SwitchOutcome` / `Stage1Outcome` /
// `SelectorAttestation` / `ReassertOutcome` / `attest_runtime_selection` / `selected_server_present`
// / `RuntimeSelectionApi` / `TestPutSink` / `AutoHotSwitchOutcome`）随生产码搬进两个子模块，
// 顶部那条 `use super::*;` 只覆盖 façade ⇒ 子模块的 `pub(super)` 项要显式再引一次。
use super::auto_switch::*;
use super::hot_switch::*;
// B8：`lifecycle` 域的自由项（`ProxyLifecycleEvent` 的构造腿 / `sleep_unless_superseded_on`
// / `now_ms`）随生产码搬进 `proxy::lifecycle`，顶部那条 `use super::*;` 只覆盖 façade
// ⇒ 子模块的 `pub(super)` 项要显式再引一次。
use super::lifecycle::*;
// B9：`startup` 域的自由项（内核闸门缓存族 / `HelperGateDecision` / `should_start_via_helper`
// / `with_helper_gate_suppressed` / `TEST_CORE_NOT_INJECTED` / `PeelTarget` 一族 / `StartRetryBudget`
// / `ExitAttestation` 一族 / `server_ids` …）随生产码搬进 `proxy::startup`，顶部那条 `use super::*;`
// 只覆盖 façade ⇒ 子模块的 `pub(super)` 项要显式再引一次。
use super::startup::*;
// 同批的另一半：`TsExitWarning` 一族过去经 façade 的 `use` 被 `use super::*;` 带进测试树，
// B6 把它们的唯一生产消费点搬进 `proxy::ts_exit` 后 façade 不再导入（留着即 unused_imports），
// 故测试树改从定义模块直取。
use crate::runtime::tailscale_status::{
    derive_ts_exit_warning, is_definitive_logged_out, TsExitWarning, TsExitWarningInput,
};
// 出口自证测试用的直连哨兵（与 `is_direct_selection` 同源，勿在测试里另写字面量）。
use polaris_config_engine::user_config::dns_constants::DIRECT_SERVER_ID;
use polaris_system_integration::proxy_ops::ProxyEnableRequest;

/// 串行化 env 改动（cargo test 同进程多线程；env 是进程全局态）。
/// `POLARIS_SINGBOX_PATH` 等进程级 env 的测试串行化锁（模块级共享）：`temp_env_var` 与
/// 「驱动真 start 但用 env 逼 resolve_core_binary 失败」的异步测试**必须共用同一把锁**，否则
/// cargo 默认并行跑测时二者对同一 env var 打架 → 偶发假红/假绿。
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn temp_env_var(key: &str, val: &str, f: impl FnOnce()) {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let old = std::env::var(key).ok();
    // SAFETY 说明：本文件 forbid(unsafe_code)；set_var 在 2021 edition 为 safe fn。
    std::env::set_var(key, val);
    f();
    match old {
        Some(v) => std::env::set_var(key, v),
        None => std::env::remove_var(key),
    }
}

/// [`fresh_test_dir`] 的目录名前缀（清扫器按它认领自己的垃圾，勿改成别的模块也在用的前缀）。
const TEST_DIR_PREFIX: &str = "polaris-proxy-test-";
/// 陈旧临时目录清扫（每个测试进程只跑一次）。
///
/// 为什么需要：本 fixture 的目录靠各测试末尾的 `remove_dir_all` 自清，而 `assert!` 失败会 panic
/// 在那行之前 —— 于是每次红都留一份，跨月累积到四位数（实测某台机 `/tmp` 里 1998 个）。
/// 与其给上百处调用点改成 Drop 守卫（返回类型全变），不如在开跑时把**上一轮的**残留扫掉：
/// 稳态从「无限累积」变成「至多一轮的量」。
///
/// 两道安全闸，缺一不可：① 只删 [`TEST_DIR_PREFIX`] 前缀的**目录**（本 fixture 自己造的名字）；
/// ② 只删 mtime 早于 1 小时的 —— 同机并发跑另一个测试进程时，它的目录还是新的，绝不误删。
/// 全程 best-effort：清扫失败不影响任何测试。
fn sweep_stale_test_dirs() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
            return;
        };
        let cutoff = std::time::SystemTime::now() - Duration::from_secs(3600);
        for e in entries.flatten() {
            if !e.file_name().to_string_lossy().starts_with(TEST_DIR_PREFIX) {
                continue;
            }
            let stale = e
                .metadata()
                .is_ok_and(|m| m.is_dir() && m.modified().is_ok_and(|t| t < cutoff));
            if stale {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    });
}

/// 唯一临时目录（进程 + 纳秒时戳 + 原子序号去重）。首次调用顺带清掉上一轮的残留
///（见 [`sweep_stale_test_dirs`]）。时戳不能单独承担唯一性：并行 runner 的墙钟分辨率可能低于
/// `as_nanos()` 展示精度，两个测试会撞进同一目录并互删夹具。
fn fresh_test_dir() -> TestDir {
    sweep_stale_test_dirs();
    TestDir::new(TEST_DIR_PREFIX)
}

/// 系统代理清理收口 mock：只**记录调用次数**，不触碰宿主系统代理（本机硬约束：绝不真跑
/// `networksetup`/`gsettings`/`reg`）。用于验「start 真失败 → controller 真被调」这条组合路径。
struct RecordingClearer {
    calls: Arc<std::sync::atomic::AtomicUsize>,
}
impl SystemProxyClearer for RecordingClearer {
    fn ensure_cleared(&mut self) -> bool {
        self.calls.fetch_add(1, Ordering::SeqCst);
        // mock 无真实 marker → 模拟「无需动作」返回 false（幂等 no-op 的对外可见形态）。
        false
    }
    fn detect_foreign_proxy(&self) -> Option<String> {
        None // 默认无残留；要验提示腿的测试用 `ResidualClearer`。
    }
    fn enable_system_proxy(&mut self, _req: &ProxyEnableRequest) -> Result<(), String> {
        Ok(()) // 本 mock 只验清理腿；启用/恢复腿的记录用 `EnableRecordingClearer`。
    }
    fn recover_from_marker(&mut self) -> Result<bool, String> {
        Ok(false)
    }
}

/// 「检测到别人的系统代理」mock：detect 恒返固定 host:port（不触碰宿主系统）。
struct ResidualClearer {
    found: Option<String>,
}
impl SystemProxyClearer for ResidualClearer {
    fn ensure_cleared(&mut self) -> bool {
        false
    }
    fn detect_foreign_proxy(&self) -> Option<String> {
        self.found.clone()
    }
    fn enable_system_proxy(&mut self, _req: &ProxyEnableRequest) -> Result<(), String> {
        Ok(())
    }
    fn recover_from_marker(&mut self) -> Result<bool, String> {
        Ok(false)
    }
}

/// 启用/恢复侧记录 mock：记录 `enable` 收到的 `req` + `recover_from_marker` 调用次数（不触碰宿主
/// 系统代理，本机硬约束）。用于验「systemProxy start 成功腿 → `enable` 真被调、参数正确」+「启动期
/// → `recover_from_marker` 真被调」这两条**组合路径**（§K7.1：光有函数、光有调用点都不够）。
#[derive(Default)]
struct EnableRecordingClearer {
    enable_reqs: Arc<Mutex<Vec<ProxyEnableRequest>>>,
    recover_calls: Arc<std::sync::atomic::AtomicUsize>,
}
impl SystemProxyClearer for EnableRecordingClearer {
    fn ensure_cleared(&mut self) -> bool {
        false
    }
    fn detect_foreign_proxy(&self) -> Option<String> {
        None
    }
    fn enable_system_proxy(&mut self, req: &ProxyEnableRequest) -> Result<(), String> {
        self.enable_reqs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(req.clone());
        Ok(())
    }
    fn recover_from_marker(&mut self) -> Result<bool, String> {
        self.recover_calls.fetch_add(1, Ordering::SeqCst);
        Ok(true) // 模拟「发现残留 marker 并恢复」→ 方法应回传 true。
    }
}

/// 造一个用临时配置目录的 ProxyRuntime（不起核）。
///
/// 系统代理清理收口器用**真实生产控制器** + 临时目录 marker 路径（无 marker → 门控 1 即返、零系统
/// 调用 → 本机安全）。不预置 config.json —— 首次 `current()` 自会建默认配置。
fn test_runtime_in(dir: PathBuf) -> Arc<ProxyRuntime> {
    let config = Arc::new(ConfigManager::new(dir.clone()));
    // 替身 helper（恒未装）：见 `HelperRuntime::never_installed_for_tests` —— 用 `new` 会让
    // 下面所有 helper 门的绿取决于跑测机器装没装过 Polaris，且装了会真连特权 daemon。
    let helper = Arc::new(HelperRuntime::never_installed_for_tests(dir.clone()));
    let mesh = Arc::new(MeshRuntime::new(dir.clone()));
    let clearer: Box<dyn SystemProxyClearer> =
        Box::new(polaris_system_integration::production_proxy_controller(
            dir.join(polaris_system_integration::PROXY_MARKER_FILENAME)
                .to_string_lossy()
                .into_owned(),
        ));
    Arc::new(ProxyRuntime::new(
        config,
        helper,
        mesh,
        clearer,
        Arc::new(NoNetworkDoh),
    ))
}

fn test_runtime() -> (Arc<ProxyRuntime>, TestDir) {
    let dir = fresh_test_dir();
    (test_runtime_in(dir.clone()), dir)
}

/// 同 [`test_runtime`]，但收口器换成 [`RecordingClearer`] mock，额外返回其调用计数句柄——
/// 用于断言「失败腿是否真调到了 ensure_cleared」。
fn test_runtime_recording() -> (
    Arc<ProxyRuntime>,
    TestDir,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    let dir = fresh_test_dir();
    let config = Arc::new(ConfigManager::new(dir.clone()));
    let helper = Arc::new(HelperRuntime::never_installed_for_tests(dir.clone()));
    let mesh = Arc::new(MeshRuntime::new(dir.clone()));
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let clearer: Box<dyn SystemProxyClearer> = Box::new(RecordingClearer {
        calls: Arc::clone(&calls),
    });
    (
        Arc::new(ProxyRuntime::new(
            config,
            helper,
            mesh,
            clearer,
            Arc::new(NoNetworkDoh),
        )),
        dir,
        calls,
    )
}

// ══════════════════════════════════════════════════════════════════════════════
// switch_mode 三腿决策（**生产路径**：全部经 `ProxyRuntime::switch_mode` 入口，
// 不直接调 `decide` / `SwitchExecutor` ——§K7.1 的教训是「两扇门之间的缝才是生产路径」，
// 故这里一律从生产入口打，断言它真的落到了预期的腿上。）
// ══════════════════════════════════════════════════════════════════════════════

/// 造一个 shadowsocks 节点（地址指向 127.0.0.1 的死端口：核只需能**生成 outbound**，不需真连）。
fn ss_node(id: &str, name: &str, port: u16) -> Value {
    serde_json::json!({
        "id": id,
        "name": name,
        "protocol": "shadowsocks",
        "address": "127.0.0.1",
        "port": port,
        "shadowsocksSettings": {
            "method": "aes-128-gcm",
            "password": "polaris-test",
        },
    })
}

/// 同 [`two_node_config`]，但两个节点的地址端口可指定（真机验证要把节点指到**我们自己的**
/// 本地监听器上，从而直接观测核到底拨了谁——比读日志可靠得多，也不依赖全局 logger）。
///
/// **两份 config 之间 `pa`/`pb` 必须保持一致**：节点地址进 norm，改了它 norm 就变 →
/// plan_hot_switch 的前提失败 → 退回重启，热切换测试自我拆台。
fn two_node_config_ports(mixed: u16, selected: &str, pa: u16, pb: u16) -> Value {
    let mut cfg = polaris_store::default_config();
    let obj = cfg.as_object_mut().unwrap();
    obj.insert(
        "servers".into(),
        serde_json::json!([
            ss_node("node-a", "Node A", pa),
            ss_node("node-b", "Node B", pb)
        ]),
    );
    obj.insert("selectedServerId".into(), serde_json::json!(selected));
    obj.insert("proxyMode".into(), serde_json::json!("global"));
    // 安全硬约束：绝不可改成 tun/systemProxy（会破坏工作机网络）。
    obj.insert("proxyModeType".into(), serde_json::json!("manual"));
    obj.insert("mixedPort".into(), serde_json::json!(mixed));
    cfg
}

/// 两节点 + 指定选中节点的本地安全配置（节点指向本地死端口，纯决策类测试用）。
fn two_node_config(mixed: u16, selected: &str) -> Value {
    two_node_config_ports(mixed, selected, 18001, 18002)
}

// ── TUN 提权引导门（汇流点 / 原地续起核 / 取消终态 / 非交互抑制）────────────────────────
//
// **本机安全**：以下全部在门内就终止（helper 本机恒未装 → 门必命中；mock 绝不真装、绝不弹框），
// 一律走不到 `generate`/`spawn`/`spawn_core_via_helper` —— 不建 TUN、不碰宿主网络、不起真核。

/// 装 mock 门的运行时 + 门调用计数（`test_runtime` 的门控变体）。
fn test_runtime_gated(
    decision: HelperGateDecision,
) -> (
    Arc<ProxyRuntime>,
    TestDir,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    let (rt, dir) = test_runtime();
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    rt.set_error_emitter(Box::new(RecordingErrorEmitter {
        helper_gate_calls: Arc::clone(&calls),
        helper_gate_decision: decision,
        ..Default::default()
    }));
    // 起核首次会扫孤儿核（遍历 /proc）——本测与之无关，闸门直接置位跳过。
    rt.stale_sweep_disabled.store(true, Ordering::SeqCst);
    (rt, dir, calls)
}

/// TUN 配置（门必命中：本机 helper 恒未装）。
fn tun_config() -> Value {
    let mut c = two_node_config(7891, "node-a");
    c["proxyModeType"] = Value::String("tun".into());
    c
}

/// 把状态直接置为「运行中」（不起真核）——测 apply_pending 的判定分支用。
fn mark_running(rt: &ProxyRuntime) {
    *rt.status.write().unwrap() = ProxyStatus {
        running: true,
        pid: 424242,
        start_time: Some(now_ms()),
        mixed_port: 7890,
        clash_api_port: 19090,
        ..ProxyStatus::default()
    };
}

/// 坏配置：反序列化为 UserConfig 必失败（非对象顶层）→ start_inner 首步即 Err，无任何副作用。
fn bad_config() -> Value {
    serde_json::json!("not-a-user-config-object")
}

/// 假核落盘（0o755）。`run_body` 是收到 `run` 子命令时的 shell 体。
///
/// **`check` 必须单独短路**：起核腿在 spawn 之前先跑一次 `sing-box check`（内核闸门，见
/// `generate_and_gate`），而真核的 `check` 是**快速返回**的静态校验、只有 `run` 才常驻。
/// 假核若对所有 argv 一视同仁，`check` 会跟着 `run` 的语义走 —— 常驻型假核会把闸门吊死到超时
/// （实测：`cancelling_start_during_readiness_wait_reaps_the_real_process` 因此拿不到 pid 而红），
/// 立退型假核则让闸门收到一个假的「配置无效」。二者都不是被测行为，是假核没跟上真核的契约。
#[cfg(unix)]
fn write_fake_core(dir: &std::path::Path, name: &str, run_body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join(name);
    // 按**整条 argv** 找 `check`，不按位置：闸门发的是 `--disable-color check -c <path>`
    // （`check` 在 `$2`），而 spawn 发的是 `run -c <path>`。写死 `$1` 会漏掉前者（实测：漏了就等于
    // 假核对 check 走 run 的语义，常驻型假核把闸门吊到超时）。
    std::fs::write(
        &p,
        format!("#!/bin/sh\ncase \" $* \" in *\" check \"*) exit 0;; esac\n{run_body}\n"),
    )
    .unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

/// 假核（**立刻死**）：spawn 得起来、起来就退 → 就绪门判 Dead → `kill_core` → 退避重试。
/// ＝真机 FATAL 循环的形状（把「跑 9s 后 FATAL」压成「立刻 FATAL」），不碰宿主网络。
#[cfg(unix)]
fn write_fake_dying_core(dir: &std::path::Path) -> PathBuf {
    write_fake_core(dir, "fake-dying-sing-box", "exit 1")
}

/// 按**完整命令行**数在跑的假核实例数（`pgrep -f <唯一临时路径>`）。
///
/// 比「记一个 pid 再验它死没死」强的地方：**新** spawn 出来的孤儿也算得到。让位腿若不 return 而是
/// 继续重试、且 spawn 临界区的世代判定被打断，多出来的那个核正是这样一个新 pid —— 只盯旧 pid 的
/// 断言会漏判（这条是变异实测补上的：只验旧 pid 时「continue 而非 return」能活下来）。
#[cfg(unix)]
fn fake_core_proc_count(path: &std::path::Path) -> usize {
    std::process::Command::new("pgrep")
        .args(["-f", &path.to_string_lossy()])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().count())
        .unwrap_or(0)
}

/// 假核（**活着但永不就绪**）：占住进程不退、绝不 bind 管理口 → 就绪门一直轮询。
/// 用来验「取消发生在就绪等待期」时接管方是否真把它收割了（孤儿门要有真进程才有牙）。
#[cfg(unix)]
fn write_fake_hanging_core(dir: &std::path::Path) -> PathBuf {
    // exec：让 sleep 顶替 shell 成为受管 pid，SIGTERM 直达（否则杀的是 shell、sleep 变孤儿）。
    write_fake_core(dir, "fake-hanging-sing-box", "exec sleep 60")
}

// ══════════════════════════════════════════════════════════════════════════════
// 真机验证（**非 CI 门**）
//
// §K7 教训：「夹具缺失就 return 的门 = 没有门」。故此处不写「env 没设就静默 return」的假门——
// 而是 `#[ignore]`：CI 里它显式显示为 ignored（不冒充通过），由人显式跑：
//   POLARIS_SINGBOX_PATH=<某个可用的 sing-box 二进制路径> \
//     cargo test -p polaris --bin polaris -- --ignored --nocapture
// 前置缺失时**panic 报错**，不跳过。
//
// 安全硬约束：config 恒 `proxyModeType: manual` + 全局直连 + 仅 127.0.0.1 监听
//   → 不接管系统网络、无 TUN、无系统代理。**绝不可改成 tun/systemProxy**（会破坏宿主网络）。
// ══════════════════════════════════════════════════════════════════════════════

fn free_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// 真机验证用最小 config：manual 模式 + 全局直连 + 仅本地混合入站。
fn local_only_config(mixed: u16) -> Value {
    serde_json::json!({
        "servers": [],
        "selectedServerId": "__direct__", // DIRECT_SERVER_ID：全局直连，无真实节点
        "proxyMode": "direct",
        "proxyModeType": "manual",        // 安全：不接管系统代理、不建 TUN
        "mixedPort": mixed,
    })
}

fn require_core() -> PathBuf {
    let path = PathBuf::from(std::env::var("POLARIS_SINGBOX_PATH").expect(
        "真机验证需 POLARIS_SINGBOX_PATH 指向真实 sing-box 二进制（前置缺失即失败，不静默跳过）",
    ));
    assert!(
        path.is_file(),
        "POLARIS_SINGBOX_PATH 必须指向真实文件，实得 {}",
        path.display()
    );
    path
}

/// 真核测试专用 runtime：环境变量只负责显式选择文件，真正的 spawn 权限仍按实例注入。
fn real_core_runtime() -> (Arc<ProxyRuntime>, TestDir, PathBuf) {
    let core = require_core();
    let (rt, dir) = test_runtime();
    rt.inject_real_core_for_test(core.clone());
    (rt, dir, core)
}

async fn lock_real_core_tests() -> tokio::sync::MutexGuard<'static, ()> {
    crate::runtime::REAL_CORE_TEST_LOCK.lock().await
}

/// `ps -p <pid>` 实证进程存在（不信 status 自述，走系统 ground truth）。
fn ps_alive(pid: u32) -> bool {
    std::process::Command::new("ps")
        .args(["-p", &pid.to_string()])
        .output()
        .map(|o| {
            o.status.success() && String::from_utf8_lossy(&o.stdout).contains(&pid.to_string())
        })
        .unwrap_or(false)
}

/// 系统内 sing-box 进程数（孤儿检测）。
///
/// 用 `pgrep -x`（**精确进程名**）而非 `ps | grep 'sing-box run'`：后者会把「命令行里含该字面量」
/// 的 shell/测试进程本身算进去 —— 我在人工核对时就被这个假计数骗过一次（报 3 实为 0）。
fn singbox_proc_count() -> usize {
    std::process::Command::new("pgrep")
        .args(["-x", "sing-box"])
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| !l.trim().is_empty())
                .count()
        })
        .unwrap_or(0)
}

/// 等 pid 变化（去抖重启 ~1.5s + 起核就绪）。返回新 pid（超时返 None）。
async fn wait_pid_change(rt: &Arc<ProxyRuntime>, old_pid: u32, secs: u64) -> Option<u32> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < deadline {
        let s = rt.status();
        if s.running && s.pid != 0 && s.pid != old_pid {
            return Some(s.pid);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    None
}

// ══════════════════════════════════════════════════════════════════════════════
// 崩溃自愈 + stale-core 清扫 真机验证（**非 CI 门**，本任务核心 gate）
//
// 安全硬约束：全程 manual + 全局直连 + 仅 127.0.0.1 监听 → 不接管系统网络、无 TUN、无系统代理。
// 只杀「自己起的核」：崩溃自愈重启自管句柄；stale 清扫按本 app 二进制路径精确判定。
// ══════════════════════════════════════════════════════════════════════════════

/// 最小合法 sing-box config（裸核直起用）：仅 127.0.0.1 混合入站 + direct 出站，绝不触碰宿主网络。
fn write_bare_singbox_config(path: &std::path::Path, mixed: u16) {
    let cfg = serde_json::json!({
        "log": { "disabled": true },
        "inbounds": [{ "type": "mixed", "listen": "127.0.0.1", "listen_port": mixed }],
        "outbounds": [{ "type": "direct" }]
    });
    std::fs::write(path, serde_json::to_string_pretty(&cfg).unwrap()).expect("写裸核 config");
}

// ══════════════════════════════════════════════════════════════════════════════
// event:proxyError 发射（此前通道两端全死：定义了、全仓零 emit）
// ══════════════════════════════════════════════════════════════════════════════

/// 发射记录：`(message, errorCode)` 逐条。
type ErrorEvents = Arc<Mutex<Vec<(String, String)>>>;

/// 非法节点发射记录：每次 emit 一帧（`Vec<InvalidNode>`）。**逐帧存而非扁平化**——
/// 「发了空数组」与「压根没发」是两个不同事实（前者清标灰，后者是 bug），扁平化会把二者抹平成同一个空。
type InvalidNodeFrames = Arc<Mutex<Vec<Vec<InvalidNode>>>>;

/// 系统代理残留发射记录：每次 emit 一条 proxy 串。
type ResidualEvents = Arc<Mutex<Vec<String>>>;

/// TS 状态发射记录：每次 emit 一条 `TailscaleStatusEvent`（逐 endpoint）。
type TsStatusEvents = Arc<Mutex<Vec<TailscaleStatusEvent>>>;

/// 企业 VPN 两条 rc.2 状态流的发射记录。
type OpenConnectStatusEvents = Arc<Mutex<Vec<OpenConnectStatusEvent>>>;
type OpenVpnStatusEvents = Arc<Mutex<Vec<OpenVpnStatusEvent>>>;

/// A4 让位态变发射记录：每次 emit 一条 `(engaged, serverName?)`。
type MeshLoginFallbackEvents = Arc<Mutex<Vec<(bool, Option<String>)>>>;

/// C3 自动换节点发射记录：每次 emit 一条 payload。
type AutoNodeSwitchedEvents = Arc<Mutex<Vec<AutoNodeSwitchedPayload>>>;

/// unlock 缓存失效发射记录：每次 invalidate 一条 `(running, exitBlocked)`。
type UnlockInvalidations = Arc<Mutex<Vec<(bool, bool)>>>;

/// R2 待应用差集 PUSH 发射记录：每次 emit 一条 `PendingChangesSummary`。
type PendingChangesEvents = Arc<Mutex<Vec<PendingChangesSummary>>>;

/// runtime 生命周期结局发射记录：每次 emit 一条 `ProxyLifecycleEvent`。
/// **逐帧存**（同 `InvalidNodeFrames` 的理由）：「发了 failed」与「压根没发」是两个不同事实。
type LifecycleEvents = Arc<Mutex<Vec<ProxyLifecycleEvent>>>;

/// 出口 IP 重探排程记录：每次排程一条 `running`（起核/热切=true，停核=false）。
type ExitIpRefreshes = Arc<Mutex<Vec<bool>>>;

/// OS 网络变化触发的恢复探测次数。
type NetworkRecoveryRefreshes = Arc<std::sync::atomic::AtomicUsize>;

/// R2 出口无效终态记录：每次 `mark_exit_blocked` 一条 `ProxyExitBlock` 原因串。
type ExitBlockedMarks = Arc<Mutex<Vec<String>>>;

/// 发射记录 mock（不碰 Tauri：`AppHandle` 本机无从构造，且发事件不该是测不了的死角）。
#[derive(Default)]
struct RecordingErrorEmitter {
    events: ErrorEvents,
    invalid_frames: InvalidNodeFrames,
    residual: ResidualEvents,
    ts_status: TsStatusEvents,
    openconnect_status: OpenConnectStatusEvents,
    openvpn_status: OpenVpnStatusEvents,
    mesh_login_fallback: MeshLoginFallbackEvents,
    auto_node_switched: AutoNodeSwitchedEvents,
    config_changed: Arc<std::sync::atomic::AtomicUsize>,
    unlock_invalidations: UnlockInvalidations,
    exit_ip_refreshes: ExitIpRefreshes,
    network_recovery_refreshes: NetworkRecoveryRefreshes,
    exit_blocked_marks: ExitBlockedMarks,
    pending_changes: PendingChangesEvents,
    lifecycle: LifecycleEvents,
    /// 预置的隐私模式活态（生产侧读 `commands::config` 的进程状态机；mock 直接回放）。
    privacy_mode: bool,
    /// 门被调用的次数（`0` = 这条入口**根本没经过门** → 变异「某入口绕过门」立刻转红）。
    helper_gate_calls: Arc<std::sync::atomic::AtomicUsize>,
    /// 预置的用户决策。`Default` 为 `Abort`（见 `prompt_helper_gate` 注释）。
    helper_gate_decision: HelperGateDecision,
    /// 每次 `emit_proxy_error` 那一刻观测到的解锁失效次数（= 续延已跑过几轮）。
    ///
    /// 「运行期自证必须排在续延之后」是一条**时序**不变式：只看终态（两件事都发生了）验不出顺序，
    /// 而后台腿里两者相隔可能只有微秒，轮询采样必然 flaky。在告警那一刻给续延拍照才是确定性判据
    /// （同 `TestPutSink::invalidation_probe` 的范式，方向相反）。
    error_seen_invalidations: Arc<Mutex<Vec<usize>>>,
}
impl ProxyErrorEmitter for RecordingErrorEmitter {
    fn emit_proxy_error(&self, message: &str, error_code: &str) {
        let n = self.unlock_invalidations.lock().unwrap().len();
        self.error_seen_invalidations.lock().unwrap().push(n);
        self.events
            .lock()
            .unwrap()
            .push((message.to_string(), error_code.to_string()));
    }
    fn emit_invalid_nodes(&self, nodes: &[InvalidNode]) {
        self.invalid_frames.lock().unwrap().push(nodes.to_vec());
    }
    fn emit_system_proxy_residual(&self, proxy: &str) {
        self.residual.lock().unwrap().push(proxy.to_string());
    }
    fn emit_tailscale_status(&self, event: &TailscaleStatusEvent) {
        self.ts_status.lock().unwrap().push(event.clone());
    }
    fn emit_openconnect_status(&self, event: &OpenConnectStatusEvent) {
        self.openconnect_status.lock().unwrap().push(event.clone());
    }
    fn emit_openvpn_status(&self, event: &OpenVpnStatusEvent) {
        self.openvpn_status.lock().unwrap().push(event.clone());
    }
    fn emit_mesh_login_fallback(&self, engaged: bool, server_name: Option<&str>) {
        self.mesh_login_fallback
            .lock()
            .unwrap()
            .push((engaged, server_name.map(str::to_string)));
    }
    fn emit_auto_node_switched(&self, payload: &AutoNodeSwitchedPayload) {
        self.auto_node_switched
            .lock()
            .unwrap()
            .push(payload.clone());
    }
    fn emit_config_changed(&self) {
        self.config_changed.fetch_add(1, Ordering::SeqCst);
    }
    fn invalidate_unlock(&self, running: bool, exit_blocked: bool) {
        self.unlock_invalidations
            .lock()
            .unwrap()
            .push((running, exit_blocked));
    }
    fn schedule_exit_ip_refresh(&self, running: bool) {
        self.exit_ip_refreshes.lock().unwrap().push(running);
    }
    fn schedule_network_recovery_refresh(&self) {
        self.network_recovery_refreshes
            .fetch_add(1, Ordering::SeqCst);
    }
    fn mark_exit_blocked(&self, reason: &str) {
        self.exit_blocked_marks
            .lock()
            .unwrap()
            .push(reason.to_string());
    }
    fn privacy_mode(&self) -> bool {
        self.privacy_mode
    }
    fn emit_pending_changes(&self, summary: &PendingChangesSummary) {
        self.pending_changes.lock().unwrap().push(summary.clone());
    }
    fn emit_lifecycle(&self, event: &ProxyLifecycleEvent) {
        self.lifecycle.lock().unwrap().push(event.clone());
    }

    /// 记录一次门调用 + 回放预置决策（默认 `Abort`：mock 绝不代替用户点「安装」）。
    /// **不真装 helper**（本机绝不碰系统路径 / 绝不弹提权框）—— 复检腿因此恒判「仍缺」，
    /// 这正好让「确认后没装上」那条腿可测。
    fn prompt_helper_gate(&self, _status: &HelperStatusSnapshot) -> HelperGateDecision {
        self.helper_gate_calls.fetch_add(1, Ordering::SeqCst);
        self.helper_gate_decision
    }
}

/// 装 mock emitter 的运行时 + 其发射记录句柄。
fn test_runtime_recording_errors() -> (Arc<ProxyRuntime>, TestDir, ErrorEvents) {
    let (rt, dir) = test_runtime();
    let events = Arc::new(Mutex::new(Vec::new()));
    rt.set_error_emitter(Box::new(RecordingErrorEmitter {
        events: Arc::clone(&events),
        ..Default::default()
    }));
    (rt, dir, events)
}

/// 装 mock emitter 并同时返回 `event:proxyError` 与 `event:proxyLifecycle` 两路记录句柄。
/// **两路一起取**：本批要证的正是「有一类失败只走后者」，只拿一路证不了那句话。
fn test_runtime_recording_lifecycle() -> (Arc<ProxyRuntime>, TestDir, ErrorEvents, LifecycleEvents)
{
    let (rt, dir) = test_runtime();
    let events: ErrorEvents = Arc::new(Mutex::new(Vec::new()));
    let lifecycle: LifecycleEvents = Arc::new(Mutex::new(Vec::new()));
    rt.set_error_emitter(Box::new(RecordingErrorEmitter {
        events: Arc::clone(&events),
        lifecycle: Arc::clone(&lifecycle),
        ..Default::default()
    }));
    (rt, dir, events, lifecycle)
}

// ══════════════ A4 登录期出口让位：编排面门（emit / 单飞 / eligible raw 读）══════════════

/// 装 mock emitter 并返回让位事件记录句柄。
fn test_runtime_recording_fallback() -> (Arc<ProxyRuntime>, TestDir, MeshLoginFallbackEvents) {
    let (rt, dir) = test_runtime();
    let handle: MeshLoginFallbackEvents = Arc::new(Mutex::new(Vec::new()));
    rt.set_error_emitter(Box::new(RecordingErrorEmitter {
        mesh_login_fallback: Arc::clone(&handle),
        ..Default::default()
    }));
    (rt, dir, handle)
}

/// 让位形态 config：选中账号制 TS 全隧道出口（exitNode 非空 → carries_full_tunnel）+ 非 direct + 无 authKey。
fn ts_fallback_config() -> Value {
    serde_json::json!({
        "servers": [{
            "id": "ts1", "name": "组网出口", "protocol": "tailscale",
            "address": "100.64.0.5", "port": 0,
            "tailscaleSettings": { "exitNode": "peer-x" }
        }],
        "selectedServerId": "ts1",
        "proxyMode": "smart"
    })
}

// ══════════════ H3：起核后 selector 校正（reassert_selector_selection）══════════════
//
// 被测的是**序列**不变式（谁被 PUT 成什么、按什么顺序、续延排在哪），故一律经
// `management_api_stub` 断言 PUT 序列。全程零网络、零进程：核不起，PUT 落在内存桩上。
// 真 gRPC PUT / 真核 cache_file 覆盖行为属真机门（`real_core_hot_switch_keeps_pid`）。

/// 装 PUT 桩的运行时：核状态置「运行中」（不起真核）+ 装 `switch_snapshot` + `current_config`。
#[allow(clippy::type_complexity)]
fn reassert_runtime(
    cfg: &Value,
    id_to_tag: BTreeMap<String, String>,
    rule_target: BTreeMap<String, RuleTargetEntry>,
) -> (
    Arc<ProxyRuntime>,
    TestDir,
    Arc<TestPutSink>,
    UnlockInvalidations,
    ExitIpRefreshes,
    MeshLoginFallbackEvents,
) {
    let (rt, dir) = test_runtime();
    let inval: UnlockInvalidations = Arc::new(Mutex::new(Vec::new()));
    let refreshes: ExitIpRefreshes = Arc::new(Mutex::new(Vec::new()));
    let fallback: MeshLoginFallbackEvents = Arc::new(Mutex::new(Vec::new()));
    rt.set_error_emitter(Box::new(RecordingErrorEmitter {
        unlock_invalidations: Arc::clone(&inval),
        exit_ip_refreshes: Arc::clone(&refreshes),
        mesh_login_fallback: Arc::clone(&fallback),
        ..Default::default()
    }));
    let sink = Arc::new(TestPutSink::default());
    *rt.management_api_stub.lock().unwrap() = Some(Arc::clone(&sink));
    mark_running(&rt);
    let uc: UserConfig = serde_json::from_value(cfg.clone()).expect("parse UserConfig");
    *rt.switch_snapshot.write().unwrap() = Some(SwitchSnapshot {
        id_to_tag,
        rule_target,
        fingerprints: node_fingerprints::modified_table(&uc.servers),
        dirty_fingerprints: node_fingerprints::dirty_table(&uc.servers),
        ..Default::default()
    });
    *rt.current_config.write().unwrap() = Some(cfg.clone());
    (rt, dir, sink, inval, refreshes, fallback)
}

// ══════════ H3 阶段 3：运行期出口自证（attest_runtime_selector）══════════
//
// 被测的轴是「核**实际**指着谁」对「校正腿的意图」——`attest_selected_exit` 对这条轴恒盲
// （它拿生成产物对盘上意图，本 bug 下两边都写着选中节点 ⇒ 必判 Match）。真 gRPC 读回属
// `crates/singbox-grpc/tests/mock_server.rs` 的 wire 门与真机门，此处零网络零进程。

/// 同 `reassert_runtime`，但**额外把 `event:proxyError` 的记录句柄带出来**。
///
/// 不改 `reassert_runtime` 的返回元组是有意的：那会逼既有 7 个 H3 用例逐个加一个 `_` 绑定，
/// 而这个文件此刻有多路改动在飞，无谓的行位移只会制造合并冲突。
fn reassert_runtime_watching_errors(
    cfg: &Value,
    id_to_tag: BTreeMap<String, String>,
    rule_target: BTreeMap<String, RuleTargetEntry>,
) -> (Arc<ProxyRuntime>, TestDir, Arc<TestPutSink>, ErrorEvents) {
    let (rt, dir) = test_runtime();
    let events: ErrorEvents = Arc::new(Mutex::new(Vec::new()));
    rt.set_error_emitter(Box::new(RecordingErrorEmitter {
        events: Arc::clone(&events),
        ..Default::default()
    }));
    let sink = Arc::new(TestPutSink::default());
    *rt.management_api_stub.lock().unwrap() = Some(Arc::clone(&sink));
    mark_running(&rt);
    let uc: UserConfig = serde_json::from_value(cfg.clone()).expect("parse UserConfig");
    *rt.switch_snapshot.write().unwrap() = Some(SwitchSnapshot {
        id_to_tag,
        rule_target,
        fingerprints: node_fingerprints::modified_table(&uc.servers),
        dirty_fingerprints: node_fingerprints::dirty_table(&uc.servers),
        ..Default::default()
    });
    *rt.current_config.write().unwrap() = Some(cfg.clone());
    (rt, dir, sink, events)
}

fn applied(member_tag: &str, rule_intents: &[(&str, &str)]) -> ReassertOutcome {
    ReassertOutcome {
        stage1: Stage1Outcome::Applied {
            member_tag: member_tag.to_string(),
        },
        rule_intents: rule_intents
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect(),
    }
}

// ══════════════ R2：TS 出口无效直判翻转对账 + 出口恢复腿 ══════════════

/// 装 mock emitter，同时暴露「解锁失效 / 出口 IP 重探 / 出口无效终态」三类记录句柄
/// —— R2 的每条腿都要同时看这三者（只看一条会漏掉「失效了但没落终态」这类半接线）。
fn test_runtime_r2() -> (
    Arc<ProxyRuntime>,
    TestDir,
    UnlockInvalidations,
    ExitIpRefreshes,
    ExitBlockedMarks,
) {
    let (rt, dir) = test_runtime();
    let inval: UnlockInvalidations = Arc::new(Mutex::new(Vec::new()));
    let refreshes: ExitIpRefreshes = Arc::new(Mutex::new(Vec::new()));
    let marks: ExitBlockedMarks = Arc::new(Mutex::new(Vec::new()));
    rt.set_error_emitter(Box::new(RecordingErrorEmitter {
        unlock_invalidations: Arc::clone(&inval),
        exit_ip_refreshes: Arc::clone(&refreshes),
        exit_blocked_marks: Arc::clone(&marks),
        ..Default::default()
    }));
    (rt, dir, inval, refreshes, marks)
}

/// 本模块所有源码型守卫的取材器 —— 一层转发到共用实现
/// [`crate::commands::guard_scan::impl_method_body`]。
///
/// 保留这个本地名字是因为它有 30+ 调用点；实现只留一份，是因为「同一事实两份实现」在本仓
/// 已经付过账：`top_level_fn_body` 与它只差一个封顶串，用错的那次造成 98 倍超宽 + 可证明的假绿。
fn method_body(src: &str, head: &str) -> String {
    crate::commands::guard_scan::impl_method_body(src, head)
}

/// [`method_body`] 自身的门：**截得准** + **剥得掉整行注释**。
///
/// 取材器是本模块所有源码型守卫的共同判据，它坏了则上面每一条都静默失效（且各自的断言仍是绿的）。
/// 两条属性各对应一种已知假绿：
/// - 不封顶（切到 EOF）⇒ `find` 命中后文别的方法里的同名调用（本仓踩过两次）；
/// - 不剥注释 ⇒ 方法体内注释里的锚点文本给 `count()` / `find()` 充数（NIT：与
///   `commands/misc::ipinfo_epoch_guard::fn_body` 不对称的那一处，现已对齐）。
///
/// **变异锁**：去掉 `method_body` 的整行注释剥除 → 第二条断言（注释里的锚点不得被数到）转红；
/// 把封顶判据 `"\n    }\n"` 删掉（切到 EOF）→ 第三条（不得越界到下一个方法）转红。
#[test]
fn method_body_is_bounded_and_strips_line_comments() {
    const SRC: &str = "impl X {\n    fn a(&self) {\n        real_call();\n\
                           // real_call() 出现在整行注释里\n        let s = \"x\";\n    }\n\
                           \n    fn b(&self) {\n        real_call();\n    }\n}\n";
    let body = method_body(SRC, "    fn a(&self) {");
    assert_eq!(
        body.matches("real_call()").count(),
        1,
        "整行注释里的锚点文本必须被剥掉（否则 count()==N 类断言可被注释充数）：\n{body}"
    );
    assert!(body.contains("let s = \"x\";"), "非注释行必须原样保留");
    assert!(
        !body.contains("fn b"),
        "射程必须封顶在本方法体（切到 EOF 会命中后文同名调用）"
    );
}

/// 装 mock emitter + **可注入的 clearer** 的运行时，暴露全部三类发射记录句柄。
/// 供「走真 start 路径验发射接线」的组合测试用（core 路径靠 POLARIS_SINGBOX_PATH 指向不存在文件
/// 在 spawn 前失败 —— emit 发生在起核之前，本机零进程零网络）。
#[allow(clippy::type_complexity)]
fn test_runtime_recording_full(
    clearer: Box<dyn SystemProxyClearer>,
) -> (
    Arc<ProxyRuntime>,
    TestDir,
    InvalidNodeFrames,
    ResidualEvents,
) {
    let dir = fresh_test_dir();
    let config = Arc::new(ConfigManager::new(dir.clone()));
    let helper = Arc::new(HelperRuntime::never_installed_for_tests(dir.clone()));
    let mesh = Arc::new(MeshRuntime::new(dir.clone()));
    let rt = Arc::new(ProxyRuntime::new(
        config,
        helper,
        mesh,
        clearer,
        Arc::new(NoNetworkDoh),
    ));
    let invalid_frames: InvalidNodeFrames = Arc::new(Mutex::new(Vec::new()));
    let residual: ResidualEvents = Arc::new(Mutex::new(Vec::new()));
    rt.set_error_emitter(Box::new(RecordingErrorEmitter {
        events: Arc::new(Mutex::new(Vec::new())),
        invalid_frames: Arc::clone(&invalid_frames),
        residual: Arc::clone(&residual),
        ..Default::default()
    }));
    (rt, dir, invalid_frames, residual)
}

/// 装 mock emitter + 可注入 clearer，暴露**错误事件**记录句柄（A1 失败腿 / 出口自证共用）。
fn test_runtime_errors_with_clearer(
    clearer: Box<dyn SystemProxyClearer>,
) -> (Arc<ProxyRuntime>, TestDir, ErrorEvents) {
    let dir = fresh_test_dir();
    let config = Arc::new(ConfigManager::new(dir.clone()));
    let helper = Arc::new(HelperRuntime::never_installed_for_tests(dir.clone()));
    let mesh = Arc::new(MeshRuntime::new(dir.clone()));
    let rt = Arc::new(ProxyRuntime::new(
        config,
        helper,
        mesh,
        clearer,
        Arc::new(NoNetworkDoh),
    ));
    let events: ErrorEvents = Arc::new(Mutex::new(Vec::new()));
    rt.set_error_emitter(Box::new(RecordingErrorEmitter {
        events: Arc::clone(&events),
        ..Default::default()
    }));
    (rt, dir, events)
}

// ── #9 TUN 起核连接 flush：两条守卫 ───────────────────────────────────────────────
//
// 四条测试各钉一条腿，合起来把 `flush_connections_once` 的五个出口盖到四个；
// 第五个（`Flushed` = 真 RST）要活核才有意义，属真机门（见 P4-b 记录）。

/// TUN + 同世代 + 核在跑的 runtime（下面三条测试的共同前置）。
fn flush_ready_runtime() -> (Arc<ProxyRuntime>, TestDir, u64) {
    let (rt, dir) = test_runtime();
    *rt.status.write().unwrap() = ProxyStatus {
        running: true,
        ..Default::default()
    };
    let my_gen = rt.gate.generation();
    (rt, dir, my_gen)
}

/// 假核（**闸门腿**）：第一次 `check` 吐一条点名 `outbounds[<idx>]` 的 FATAL 并 rc=1，
/// 之后的 `check` 一律 rc=0（模拟「坏节点被剥掉后配置就合法了」）。`run` 直接退出（本门不 spawn）。
///
/// 「第一次 vs 之后」靠**落盘 marker** 记状态：闸门每轮都是一个**全新子进程**，进程内变量存不住。
#[cfg(unix)]
fn write_fake_checking_core(dir: &std::path::Path, reject_index: usize) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join("fake-checking-sing-box");
    let marker = dir.join("gate-check-seen").to_string_lossy().into_owned();
    std::fs::write(
        &p,
        format!(
            "#!/bin/sh\ncase \" $* \" in *\" check \"*)\n\
                 if [ -f {marker} ]; then exit 0; fi\n\
                 touch {marker}\n\
                 echo 'FATAL[0000] decode config at cfg.json: outbounds[{reject_index}]: \
                 unknown outbound type: zzz' >&2\n\
                 exit 1;;\nesac\nexit 1\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

/// 恒接受 `check` 的假核，并把真实进程启动次数累计到文件。
#[cfg(unix)]
fn write_fake_accepting_core(dir: &std::path::Path) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let binary = dir.join("fake-accepting-sing-box");
    let counter = dir.join("gate-check-count");
    std::fs::write(
        &binary,
        format!(
            "#!/bin/sh\ncase \" $* \" in *\" check \"*)\n\
                 n=0\n[ -f {counter} ] && n=$(sed -n '1p' {counter})\n\
                 n=$((n + 1))\nprintf '%s\\n' \"$n\" > {counter}\nexit 0;;\nesac\nexit 1\n",
            counter = counter.to_string_lossy()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
    (binary, counter)
}
