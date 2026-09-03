//! 完全卸载 command 薄壳：注入真实系统能力并返回逐步报告。

use std::path::PathBuf;

use tauri::{AppHandle, Manager, State};

use crate::commands::helper::with_helper_service_mutation_core_guard;
use crate::response::ApiResponse;
use crate::runtime::uninstall::UninstallReport;
use crate::runtime::{uninstall, AppRuntime};

/// 上游 `APP_UNINSTALL_ALL`：完全卸载（提权 helper / 受保护目录内核 / 用户配置 / 应用本体）。
///
/// ✅ **已接线**。本函数是**薄壳**：编排、顺序、失败传播、三平台可行性判定全在
/// [`crate::runtime::uninstall`] 的纯函数里（可穷举单测），这里只做注入 + 信封。
///
/// # 六步的因果序（详表见 [`crate::runtime::uninstall`] 模块文档）
///
/// 停核 → 取消开机自启 → 卸 helper（其 root 脚本一并清受保护目录中的内核）→ 删用户配置
/// → 删更新缓存 → 删应用本体。
///
/// 几处先后**不可换**：取消自启最便宜最可逆故排最前（失败时零损失，且它删的登录项在配置目录之外）；
/// `HelperRuntime::uninstall` 要往配置目录写提权脚本、从那里读 token，先删配置就等于把 helper
/// 永久焊死在系统里；应用本体必须最后 —— 它是当前进程的载体。
///
/// # 任一步失败即中止（红线）
///
/// [`run_uninstall`](crate::runtime::uninstall::run_uninstall) 做 fail-fast：失败步之后的每一项都记
/// `NotAttempted` 如实上报，绝不「反正已经删一半了不如删完」。
///
/// # 为什么外层仍是 `ApiResponse::ok`（而不是失败时返 `err`）
///
/// 与 [`helper_uninstall`](crate::commands::helper_uninstall) 同口径：**IPC 层不失败，业务结果在
/// 载荷里**。这里是刚需而非风格 —— 前端 `ipc-client.ts` 在 `success:false` 时 throw 且**只带
/// `error`/`code`，`data` 会被丢掉**；用失败信封就等于把「哪项成了、哪项没成、为什么」全扔了，
/// 而那恰恰是本功能必须逐项呈现的东西。真值收在
/// [`UninstallReport::verdict`](crate::runtime::uninstall::UninstallReport)：只有 `Complete` 才是
/// 「卸干净了」，前端据此选文案与配色 —— 半成品绝不会显示成「已卸载」。
/// 只有命令本身崩了（`spawn_blocking` join 失败）才走 `err`。
///
/// # 真机门
///
/// 卸 helper 那一步会弹提权框（osascript / pkexec / UAC）。本机无 bundled helper ⇒
/// `installed()` 为 false ⇒ 该步 `Skipped`，**不弹框**。
/// [`AutostartOps`](crate::runtime::uninstall::AutostartOps) 的生产实现：包一层插件的
/// `AutoLaunchManager`。**只做转接，不加判定** —— 判定在纯函数侧。
struct PluginAutostart(AppHandle);

impl uninstall::AutostartOps for PluginAutostart {
    fn is_enabled(&self) -> bool {
        self.0
            .state::<tauri_plugin_autostart::AutoLaunchManager>()
            .is_enabled()
            .unwrap_or(false)
    }

    fn disable(&self) -> Result<(), String> {
        self.0
            .state::<tauri_plugin_autostart::AutoLaunchManager>()
            .disable()
            .map_err(|e| e.to_string())
    }
}

#[tauri::command]
pub async fn app_uninstall_all(
    app: AppHandle,
    state: State<'_, AppRuntime>,
) -> Result<ApiResponse<UninstallReport>, ()> {
    let helper = state.helper.clone();
    let config_dir = state.config().dir().to_path_buf();
    // `app_cache_dir()/updates` = 应用更新包的唯一落点（见 `update_download`）。它在**配置目录之外**，
    // 删配置带不走 —— 漏掉就是卸载完还剩几百 MB 安装包。
    let cache_updates_dir = app
        .path()
        .app_cache_dir()
        .ok()
        .map(|d| d.join(uninstall::CACHE_UPDATES_LEAF));
    let autostart = PluginAutostart(app.clone());

    // 停核腿 + 全程看门狗与 `helper_uninstall` 共用同一层壳（见
    // `with_helper_service_mutation_core_guard`）。
    // 整条链（提权框 + 两次 remove_dir_all）跑在 spawn_blocking 上：提权框是分钟级原生模态，
    // 直调会把一个 tokio worker 占死。
    let joined = with_helper_service_mutation_core_guard(&state, |stop| async move {
        tokio::task::spawn_blocking(move || {
            let ops = uninstall::SystemUninstallOps {
                helper: helper.as_ref(),
                autostart: &autostart,
                os: std::env::consts::OS,
                config_dir,
                cache_updates_dir,
                // UserDefaults 域名 = 应用 identifier（`tauri.conf.json`，编译期常量）。
                // 与 `app_language::apply_process_language` 写入时用的是同一个来源，
                // 两处取不同的值就会「写进 A 域、清掉 B 域」。
                bundle_identifier: app.config().identifier.clone(),
                // 路径**全部由本进程自己算**，没有一段来自前端入参（本命令零参数）。
                exe: std::env::current_exe().ok(),
                appimage: std::env::var_os("APPIMAGE").map(PathBuf::from),
            };
            uninstall::run_uninstall(&ops, stop)
        })
        .await
    })
    .await;

    Ok(match joined {
        Ok(report) => {
            log::info!(
                "完全卸载结束：verdict={:?}，逐项 {:?}",
                report.verdict,
                report.steps
            );
            ApiResponse::ok(report)
        }
        Err(e) => ApiResponse::err(format!("完全卸载任务异常终止: {e}")),
    })
}
