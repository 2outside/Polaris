//! 启动期延迟任务（上游 `src/main/startup-tasks.ts` 1:1 移植）。
//!
//! 五条腿，全部 fire-and-forget、绝不阻断启动（**各占各的时刻**，见
//! `startup_leg_delays_are_all_distinct`）：
//! - **2s：启动时自动连接**（`config.autoConnect` + `selectedServerId`）。
//! - **3s：首次出口 IP 探测**。
//! - **5s：启动后自动检查更新**（`config.autoCheckUpdate !== false`）→ 有更新走既有 mini 弹窗；
//!   若 `config.autoDownloadUpdate` 也开着，**顺带后台下载安装包但绝不安装**（见 [`spawn_auto_download`]）。
//! - **6s：内核基线兼容提醒**（#17，非官方核且版本 ≤ 随包基线 → 发 `EVENT_CORE_BASELINE_WARNING`）。
//! - **7s：helper 可升级探测**（proto < 本 build 期望 → 发 `EVENT_HELPER_UPGRADEABLE`）。
//!
//! 上游 里同文件还有 staged 内核落位 / 随包核 reseed / WARP drain 三段：staged 落位与内核自动更新
//! 已由 `runtime/core_update_scheduler.rs`（T+30s 起）承接，随包核 reseed 在 `main.rs` setup 的
//! `ensure_writable_core`，WARP drain 亦在 setup 单独接（`spawn_warp_drain`）——故本模块**只**接
//! 上述五条腿，不重复接线。
//!
//! **纯决策 / 副作用分离**（与 `subscription_scheduler` 同纪律）：能判定的全收在
//! [`decide_auto_connect`] / [`should_auto_check_update`] / [`should_auto_download_update`] /
//! [`auto_download_applicable`] / [`should_warn_core_baseline`] / [`should_notify_helper_upgradeable`]
//! 六个纯函数（环境真值由调用方注入，全单测覆盖）；[`spawn`] 只剩「睡多久 + 调哪个既有命令 +
//! 记什么日志」的薄壳。

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::{json, Value};
use tauri::{AppHandle, Manager};

use polaris_updater::version::compare_semver;
use polaris_updater::{
    classify_core_build, extract_version_token, ComparableVersion, CoreBuildKind,
};

use crate::events::channel::{EVENT_CORE_BASELINE_WARNING, EVENT_HELPER_UPGRADEABLE};
use crate::runtime::helper::HelperStatusSnapshot;
use crate::runtime::update_install::{decide_install_plan, detect_run_form as decide_run_form};
use crate::runtime::AppRuntime;

/// 启动时自动连接延迟（上游 `setTimeout(..., 2000)`：等窗口 / 服务初始化完）。
const AUTO_CONNECT_DELAY_MS: u64 = 2_000;
/// 启动后自动检查更新延迟（上游 `setTimeout(..., 5000)`：避开启动高峰）。
const AUTO_CHECK_UPDATE_DELAY_MS: u64 = 5_000;
/// 内核基线提醒延迟：错开上面 2s/5s 两个高峰（探测要 spawn 一次 `sing-box version`）。
const CORE_BASELINE_DELAY_MS: u64 = 6_000;
/// 首次出口 IP 探测延迟。上游 启动腿是 2s，本仓**刻意错开到 3s**——2s 已被自动连接占着
/// （[`AUTO_CONNECT_DELAY_MS`]），撞点会让两条腿同刻触发，违反本文件既定的错峰约定
/// （见 [`CORE_BASELINE_DELAY_MS`]「错开上面 2s/5s 两个高峰」）。
///
/// **为什么不改成「自动连接成功后就不排这条腿」**（那样能省掉一条冗余腿，起核腿本就会重探）：
/// 自动连接**默认关**（[`decide_auto_connect`] 要求 `autoConnect` 显式为 true），且开了也可能失败
/// （无 helper / 选中节点已被订阅删掉）。这两种情况下都不会有起核腿，首探一旦被省掉就**根本不跑**
/// —— 冷启动状态栏那格恒 `—`，正是本批要根治的缺陷本身。错峰的代价是 1s，省腿的代价是把缺陷放回去。
///
/// 落地顺序的正确性另有保证：`commands::misc` 的世代闸保证「后领世代的腿胜」，本腿在起核腿之前领
/// 世代，故无论谁先探完，最终落地的都是起核腿那份带代理出口的快照。
const EXIT_IP_PROBE_DELAY_MS: u64 = 3_000;
/// helper 可升级探测延迟：错开上面 2s/3s/5s/6s 四个高峰。探测会连一次 helper socket（已装时），
/// 故不与内核基线探测（6s，要 spawn `sing-box version`）同刻。
const HELPER_UPGRADEABLE_DELAY_MS: u64 = 7_000;

/// 基线提醒进程级 once 闸：提醒是「装了非官方核」的一次性告知，不是状态推送，重复发 = 骚扰。
static BASELINE_WARNED: AtomicBool = AtomicBool::new(false);

/// 启动时自动连接决策。
#[derive(Debug, PartialEq, Eq)]
pub enum AutoConnectDecision {
    /// 开关开 + 有选中节点 → 连。
    Connect { server_id: String },
    /// 开关开但没选节点 → 只 warn（对齐 上游「已启用，但未选择服务器」分支），不静默。
    NoServerSelected,
    /// 开关关（含缺省）→ 什么都不做。
    Disabled,
}

/// 纯决策：`autoConnect` 显式为 true 才连（缺省 = 关，对齐 上游 `if (config.autoConnect && ...)`
/// 的 truthy 判定）；空串 `selectedServerId` 视同未选（上游 里 `''` 也是 falsy）。
#[must_use]
pub fn decide_auto_connect(config: &Value) -> AutoConnectDecision {
    if config.get("autoConnect").and_then(Value::as_bool) != Some(true) {
        return AutoConnectDecision::Disabled;
    }
    match config.get("selectedServerId").and_then(Value::as_str) {
        Some(id) if !id.is_empty() => AutoConnectDecision::Connect {
            server_id: id.to_string(),
        },
        _ => AutoConnectDecision::NoServerSelected,
    }
}

/// 纯决策：`autoCheckUpdate !== false`（**缺省为开**，对齐 上游）。非 bool / 坏结构一律按开——
/// 检查更新是只读动作，误开无害，误关则用户永远收不到安全更新。
#[must_use]
pub fn should_auto_check_update(config: &Value) -> bool {
    config.get("autoCheckUpdate").and_then(Value::as_bool) != Some(false)
}

/// 纯决策：是否发内核基线兼容风险提醒（#17，上游 `use-native-events.ts` 附近 `#40` 语义）。
///
/// 官方核恒不提醒；fork / unknown 核**且**版本 ≤ 随包基线 → 提醒（第三方核落后于随包基线时，
/// 本仓生成的新配置形态可能它还不认，是真实兼容风险）。高于基线的 fork 不提醒——它比我们新。
///
/// **版本串不可解析 → 不提醒**（宁可漏报不误报）：`compare_semver` 对非版本串会按 `0.0.0` 处理，
/// 直接喂进去会把「读不出版本」判成「远低于基线」而误报。故先用 [`ComparableVersion::normalize`]
/// 规范化（非版本输入原样返回），再要求结果确实长得像版本串才比较。
///
/// # 与 `CoreOverrideDecision::warn` 的关系（别把那个接上来）
///
/// `polaris_updater::CoreOverrideDecision` 也有一个 `warn`，形状看着一样但**故意不同构**：
/// 那个字段是 上游 `decideCoreOverride` 的**逐字对照件**（golden 对拍在
/// `crates/updater/tests/core_build_golden.rs`），把解析失败折成「比基线旧」⇒ 读不出版本时恒 `warn`。
/// **本函数才是本仓这条提醒腿的权威**，上面那段不可解析守卫就是两者唯一的实质差别。
///
/// # 为什么不改成「问二进制」而仍用版本带
///
/// 2026-08-09 评估过三条「问二进制」的路，结论是**现状已经是更强的那个**，不动：
/// - `sing-box version` 的 **Tags 行不可靠** —— 已知 fork（reF1nd）的 Tags 与官方同构，
///   且 snell 无条件编入、不产生 `with_snell` tag（见 `ui/src/domain/core-build.ts` 模块头）。
/// - `sing-box check` 的**真值判定已经在跑**：每次起核都用 `core_binary_for_start()`（即将要启动的
///   那个核，含用户的 fork）对真实生成的配置跑一次 check 并剥掉被点名拒收的节点
///   （`runtime/proxy::generate_and_gate`，实测 26–29ms）。本提醒只是它之前的一句廉价预告。
/// - `sing-box schema` 只描述**形状**不描述取值域，够不着「这个核认不认这份配置」。
#[must_use]
pub fn should_warn_core_baseline(build: CoreBuildKind, current: &str, bundled: &str) -> bool {
    if build == CoreBuildKind::Official {
        return false;
    }
    let cur = ComparableVersion::normalize(current);
    let bun = ComparableVersion::normalize(bundled);
    if !looks_like_version(&cur) || !looks_like_version(&bun) {
        return false;
    }
    compare_semver(cur.as_str(), bun.as_str()).is_ok_and(|ord| ord <= 0)
}

/// `normalize` 对非版本输入原样返回 → 用「首字符是数字且含 `.`」判它是否真产出了版本串
/// （normalize 已剥前导 `v`，故首字符必为数字）。
fn looks_like_version(v: &ComparableVersion) -> bool {
    let s = v.as_str();
    s.as_bytes().first().is_some_and(u8::is_ascii_digit) && s.contains('.')
}

/// `CoreBuildKind` → 事件 payload 的 `kind` 字符串（前端 `onCoreBaselineWarning` 契约）。
/// Official 不会走到这里（[`should_warn_core_baseline`] 已挡），兜底按 unknown。
fn kind_label(build: CoreBuildKind) -> &'static str {
    match build {
        CoreBuildKind::Fork => "fork",
        _ => "unknown",
    }
}

/// 挂上五条启动期延迟任务。在 `main.rs` setup 内、主窗建好之后调用一次。
pub fn spawn(app: AppHandle) {
    spawn_auto_connect(app.clone());
    spawn_auto_check_update(app.clone());
    spawn_core_baseline_warning(app.clone());
    spawn_helper_upgradeable_probe(app.clone());
    spawn_exit_ip_probe(app);
}

/// 3s：首次出口 IP 探测（上游 `IpInfoService` 启动腿，错开 2s 自动连接高峰）。
/// **冷启动状态栏那格 `—` 的根治点**——
/// 在此之前 `IPINFO_CACHE` 恒空，除非用户亲手点首页「网络检测」，出口 IP 与其下游的伴测延迟一直不显。
///
/// 无条件跑：**未连核时探到的是本地直连出口**，那正是断开态状态栏该显示的真值（不是「无值」）。
/// 排程/探测/广播全收在 `commands::misc::schedule_ipinfo_refresh`（与起核/热切/停核三点同一实现），
/// 本处只负责「睡多久 + 调哪个既有编排」，不复制第二套逻辑。
fn spawn_exit_ip_probe(app: AppHandle) {
    crate::commands::misc::schedule_ipinfo_refresh(&app, EXIT_IP_PROBE_DELAY_MS);
}

/// 2s：启动时自动连接。走**既有命令** `proxy_start` 而非直接调 `ProxyRuntime::start`——命令层
/// 带 helper-missing 闸门 + 发 `EVENT_PROXY_STARTED`（托盘图标 / 前端连接态的同一真值源），
/// 绕过它就得在这里重造两份逻辑且必然漂移。
fn spawn_auto_connect(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_millis(AUTO_CONNECT_DELAY_MS)).await;
        let Some(config) = load_config(&app, "启动时自动连接") else {
            return;
        };
        match decide_auto_connect(&config) {
            AutoConnectDecision::Disabled => {}
            AutoConnectDecision::NoServerSelected => {
                log::warn!("启动时自动连接已启用，但未选择服务器");
            }
            AutoConnectDecision::Connect { server_id } => {
                log::info!("启动时自动连接已启用（节点 {server_id}），正在连接...");
                // State 借的是本 async block 里 owned 的 `app`，不跨 spawn 边界外泄。
                let state = app.state::<AppRuntime>();
                // 不再把 `config` 传进去：命令层自己读盘（见 `proxy_start` 头注）。上面那份
                // 只用于 `decide_auto_connect` 的判定，与起核用哪份配置无关。
                match crate::commands::proxy_start(app.clone(), state).await {
                    Ok(resp) if resp.success => log::info!("启动时自动连接成功"),
                    Ok(resp) => log::error!(
                        "启动时自动连接失败: {}",
                        resp.error.as_deref().unwrap_or("未知错误")
                    ),
                    // 命令层 Err(()) 在本仓不可达（信封化返回），仍如实记而非 unwrap panic。
                    Err(()) => log::error!("启动时自动连接失败：命令层返回错误"),
                }
            }
        }
    });
}

/// 5s：启动后自动检查更新。有更新 → 走既有 `update_popup_show`（真弹 mini 窗，对齐 上游
/// `showUpdateDialog`）+ 按 `autoDownloadUpdate` 决定要不要**后台下载**（见 [`spawn_auto_download`]）。
/// 无更新 / 失败一律只记日志——后台检查不该抢用户注意力。
fn spawn_auto_check_update(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_millis(AUTO_CHECK_UPDATE_DELAY_MS)).await;
        let Some(config) = load_config(&app, "自动检查更新") else {
            return;
        };
        if !should_auto_check_update(&config) {
            return;
        }
        log::info!("正在自动检查更新...");
        let state = app.state::<AppRuntime>();
        let include_prerelease =
            crate::commands::updater::app_update_channel_is_prerelease(&config);
        let resp =
            match crate::commands::update_check(app.clone(), state, Some(include_prerelease), None)
                .await
            {
                Ok(r) => r,
                Err(()) => {
                    log::error!("自动检查更新异常：命令层返回错误");
                    return;
                }
            };
        if !resp.success {
            log::warn!(
                "自动检查更新失败: {}",
                resp.error.as_deref().unwrap_or("未知错误")
            );
            return;
        }
        let data = resp.data.unwrap_or(Value::Null);
        if data.get("hasUpdate").and_then(Value::as_bool) != Some(true) {
            log::info!("当前已经是最新版本");
            return;
        }
        let Some(version) = data
            .pointer("/updateInfo/version")
            .and_then(Value::as_str)
            .map(str::to_string)
        else {
            // hasUpdate:true 却无 updateInfo.version = 后端契约破损，宁可不弹也不弹个空版本号。
            log::warn!("自动检查更新：hasUpdate 为真但缺 updateInfo.version，跳过弹窗");
            return;
        };
        log::info!("发现新版本: {version}");
        let current = app.package_info().version.to_string();
        let r = crate::commands::update_popup_show(
            app.clone(),
            app.state::<AppRuntime>(),
            version,
            current,
            Some(include_prerelease),
        );
        if !r.success {
            log::warn!(
                "更新提醒弹窗打开失败: {}",
                r.error.as_deref().unwrap_or("未知错误")
            );
        }
        // 「自动下载更新」——只下载，不安装（见 spawn_auto_download）。
        spawn_auto_download(&app, &config, data.get("updateInfo").cloned());
    });
}

/// 纯决策：检查到新版本后要不要**后台下载**（`autoDownloadUpdate === true`，**缺省关**）。
///
/// # 为什么缺省关（与 `autoCheckUpdate` 缺省开相反）
///
/// 检查只是一次几 KB 的 JSON；下载是几十 MB 的安装包，可能跑在计费/移动网络上。
/// 用户没说要，就不该替他花流量。前端那个开关的默认值同样是关。
///
/// **本开关不越过 `autoCheckUpdate`**：下载腿挂在自动检查腿的内部，用户关掉检查 ⇒ 根本没有
/// 「检查到新版本」这一刻 ⇒ 下载腿一次都不会跑。这是结构性的，不靠这里再判一次。
#[must_use]
pub fn should_auto_download_update(config: &Value) -> bool {
    config.get("autoDownloadUpdate").and_then(Value::as_bool) == Some(true)
}

/// 纯决策：这份资产在**当前运行形态**下将来装得上吗？装不上就别下（下了也只能交给系统打开）。
///
/// 复用安装侧的**同一个**纯判定 [`decide_install_plan`]（`installer_path` 只被读文件名 + 做路径
/// 拼接，不碰 FS ⇒ 可拿「下载后的落点」提前问）。各写一套「什么资产能装」必然与安装侧漂移。
///
/// 典型跳过：release 里只有 `.tar.gz` 这类本仓不认识的资产（`UnknownAsset`），
/// 或 AppImage 运行形态却拿到 `.deb`（`FormMismatch` —— 那是**绝不自动提权装 deb** 的安全闸）。
///
/// # Errors
///
/// 资产名为空 / 后缀不认识 / 与当前运行形态错配 —— 一律返回可读原因（只进日志，不打断启动）。
pub fn auto_download_applicable(
    os: &str,
    file_name: &str,
    exe_path: &std::path::Path,
    appimage_env: Option<&std::path::Path>,
    portable_exe: Option<&std::path::Path>,
) -> Result<(), String> {
    if file_name.trim().is_empty() {
        return Err("updateInfo.fileName 为空".to_string());
    }
    let run_form = decide_run_form(os, appimage_env, portable_exe);
    // 下载落点与 `update_download` 一致的**文件名**即可（本判定只看名字 + 目录拼接）。
    let installer = std::path::Path::new(file_name);
    decide_install_plan(
        os,
        run_form,
        installer,
        exe_path,
        appimage_env,
        portable_exe,
    )
    .map(|_| ())
    .map_err(|reject| format!("{reject:?}"))
}

/// 后台下载新版安装包（**只下载，绝不安装**）。
///
/// # 为什么不顺手装了
///
/// 安装是两段式的：`update_install` 会先返 `needConfirm + advisory`（ad-hoc 签名会被 macOS
/// Gatekeeper / Windows SmartScreen 拦、Linux deb 要弹 polkit），确认后**停代理 + 退出应用**。
/// 这三件事一件都不该在用户没点确认时发生 —— 后台悄悄把用户的代理停了并重启 App，
/// 是比「没自动更新」严重得多的问题。故本腿止于「包已就位」，安装仍由用户点。
///
/// # 与内核自动更新调度器的错峰
///
/// 本腿不占固定时刻：它排在自动检查腿（T+5s）**返回之后**，起始时刻由那次 HTTP 往返决定。
/// 内核调度器固定 T+30s 起，且它自己也要先跑一次检查才可能下载。两条腿都不在启动瞬间发车，
/// 且各自的下载都在各自的检查之后 —— 不存在「启动即两个大下载同刻起跑」的形态。
///
/// # 弹窗不受影响
///
/// 下载进度经 `update:progress` 广播（设置页据此显示进度），但**不会**顶掉刚弹出的 remind
/// 提示：镜像闸 `should_mirror_to_popup` 只放行用户亲手推进 progress 的弹窗。
fn spawn_auto_download(app: &AppHandle, config: &Value, update_info: Option<Value>) {
    if !should_auto_download_update(config) {
        return;
    }
    let Some(info) = update_info.filter(|v| !v.is_null()) else {
        log::warn!("自动下载更新：hasUpdate 为真但缺 updateInfo，跳过");
        return;
    };
    let file_name = info
        .get("fileName")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    // 形态适配预判（**下载前**）：装不上的资产下了也白下。
    let os = std::env::consts::OS;
    let Ok(exe_path) = std::env::current_exe() else {
        log::warn!("自动下载更新：无法解析当前可执行文件路径，跳过");
        return;
    };
    let appimage = std::env::var_os("APPIMAGE").map(std::path::PathBuf::from);
    let portable = crate::commands::is_portable_layout(&exe_path).then(|| exe_path.clone());
    if let Err(reason) = auto_download_applicable(
        os,
        &file_name,
        &exe_path,
        appimage.as_deref(),
        portable.as_deref(),
    ) {
        log::info!(
            "自动下载更新：资产「{file_name}」在当前运行形态下不适用（{reason}），跳过下载 —— \
             用户仍可在更新页手动下载并交系统处理"
        );
        return;
    }

    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        log::info!("自动下载更新已启用：后台下载 {file_name}（下载完成后不自动安装）");
        let state = app.state::<AppRuntime>();
        match crate::commands::update_download(app.clone(), state, info).await {
            Ok(r) if r.success => {
                let path = r
                    .data
                    .as_ref()
                    .and_then(|d| d.get("filePath"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                log::info!("自动下载更新完成：{path}（等待用户在更新页点「立即安装」）");
            }
            Ok(r) => log::warn!(
                "自动下载更新失败: {}",
                r.error.as_deref().unwrap_or("未知错误")
            ),
            Err(()) => log::warn!("自动下载更新异常：命令层返回错误"),
        }
    });
}

/// 6s：#17 内核基线兼容提醒发射端。
///
/// **刻意不用 [`crate::runtime::updater::UpdaterRuntime::read_core_version`]**：它在探测失败时
/// **回落随包基线**（见该函数文档的「双读法陷阱」），于是「读不出核版本」会被伪装成「核版本 ==
/// 基线」→ 恰好落进 `<=` 分支误报。这里改用原始版本行 `read_core_version_line()` 单次探测：
/// 空串 = 探测失败 → 直接不提醒（无证据不发警告），非空再派生 kind + version token（顺带省掉
/// 一次 `sing-box version` 子进程 spawn）。
fn spawn_core_baseline_warning(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_millis(CORE_BASELINE_DELAY_MS)).await;
        let Some(state) = app.try_state::<AppRuntime>() else {
            return;
        };
        let updater = state.updater();
        let line = updater.read_core_version_line();
        if line.is_empty() {
            log::debug!("活核版本探测失败 → 跳过内核基线兼容提醒（无证据不告警）");
            return;
        }
        let build = classify_core_build(&line);
        let current = extract_version_token(&line);
        let bundled = updater.bundled_core_version().to_string();
        if !should_warn_core_baseline(build, &current, &bundled) {
            return;
        }
        if BASELINE_WARNED.swap(true, Ordering::SeqCst) {
            return; // 已发过（进程级 once）
        }
        log::warn!(
            "内核基线兼容提醒：活核 {current}（{kind}）≤ 随包基线 {bundled}",
            kind = kind_label(build)
        );
        crate::events::broadcast(
            &app,
            EVENT_CORE_BASELINE_WARNING,
            json!({
                "current": current,
                "bundled": bundled,
                "kind": kind_label(build),
            }),
        );
    });
}

/// 纯决策：是否发 `event:helperUpgradeable`（proto 落后，或同 proto 的 helper build 与随包不一致）。
///
/// `installed && upgradeable`。`ready` **刻意不再查一遍** —— `helper-client` 的
/// `compute_status` 里 `upgradeable` 已经合取 `ready`；
/// 在这里重复只会制造「两处判据、改一处漏一处」。留 `installed` 是给它变异牙齿：
/// 未装的机器上 `upgradeable` 恒 false，但把判据写成恒真的形态（如直接 `true`）时这条会转红。
///
/// 事件语义 = **一次性引导**（前端 `SettingsHelper` 收到就重拉 status 并提示可升级），不是状态推送，
/// 故只在启动期发一次，不做周期重发。
#[must_use]
pub const fn should_notify_helper_upgradeable(status: &HelperStatusSnapshot) -> bool {
    status.installed && status.upgradeable
}

/// 7s：`EVENT_HELPER_UPGRADEABLE` 发射端。
///
/// 前端 `SettingsHelper.tsx` 早已订阅（`helperApi.onUpgradeable`），后端此前**零 emit** ——
/// 于是「helper 版本落后」这件事只有在用户主动点开设置页时才可能被看见。
///
/// 未装 / 未就绪 / 已是最新 → 静默（**不发空事件**：前端收到就会重拉一次 status，白发 = 白拉）。
fn spawn_helper_upgradeable_probe(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_millis(HELPER_UPGRADEABLE_DELAY_MS)).await;
        let Some(state) = app.try_state::<AppRuntime>() else {
            return;
        };
        // `status()` 在未安装态短路（不连 socket），已安装才 ping 一次 proto 版本。
        let status = state.helper().status();
        if !should_notify_helper_upgradeable(&status) {
            return;
        }
        log::info!(
            "提权 helper 可升级（当前 proto {:?}, helper build {:?}, expected build {}）：已通知渲染端引导升级",
            status.version,
            status.helper_build_id,
            status.expected_build_id,
        );
        crate::events::broadcast(
            &app,
            EVENT_HELPER_UPGRADEABLE,
            json!({
                "version": status.version,
                "expectedProtocolVersion": status.expected_protocol_version,
                "helperBuildId": status.helper_build_id,
                "expectedBuildId": status.expected_build_id,
                "installed": status.installed,
                "ready": status.ready,
            }),
        );
    });
}

/// 读全量 config；失败只记日志返 None（启动期任务绝不因配置读失败 panic 或阻断）。
fn load_config(app: &AppHandle, task: &str) -> Option<Value> {
    let state = app.try_state::<AppRuntime>()?;
    match state.config().load_full() {
        Ok(c) => Some(c),
        Err(e) => {
            log::error!("{task}：读取配置失败，跳过 - {e}");
            None
        }
    }
}

#[cfg(test)]
mod tests;
