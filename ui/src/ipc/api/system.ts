import { invoke, listen } from '../ipc-client';
import { IPC_CHANNELS } from '../../domain/ipc-channels';
import type { AutoStartStatus, HelperStatus, SystemProcessInfo, NetworkInterfaceInfo } from '../../contracts/types';

/** Helper 安装/卸载的稳定业务失败码；与 Rust `HelperActionErrorCode` 对齐。 */
export type HelperActionErrorCode =
  | 'cancelled'
  | 'authorizationUnavailable'
  | 'proxyRunning'
  | 'unsupported'
  | 'missingAsset'
  | 'notReady'
  | 'failed';

export interface HelperActionResult {
  success: boolean;
  errorCode?: HelperActionErrorCode;
  /** 已泛化的诊断数据；不得直接作为用户文案。 */
  diagnostic?: string;
  status: HelperStatus;
}

// ============================================================================
// autoStartApi
// ============================================================================

export const autoStartApi = {
  async set(enabled: boolean): Promise<boolean> {
    return invoke(IPC_CHANNELS.AUTO_START_SET, { enabled });
  },

  async getStatus(): Promise<AutoStartStatus> {
    return invoke(IPC_CHANNELS.AUTO_START_GET_STATUS);
  },
};

// ============================================================================
// systemApi
// ============================================================================

export const systemApi = {
  /** 枚举当前系统进程（聚合去重，供进程规则快速选择）。 */
  async listProcesses(): Promise<SystemProcessInfo[]> {
    return invoke(IPC_CHANNELS.SYSTEM_LIST_PROCESSES);
  },
  async listNetworkInterfaces(): Promise<NetworkInterfaceInfo[]> {
    return invoke(IPC_CHANNELS.SYSTEM_LIST_NETWORK_INTERFACES);
  },
  /** 用系统默认浏览器打开外部链接。 */
  async openExternal(url: string): Promise<void> {
    // Rust shell_open_external(url: String) —— 参数袋 key = `url`（裸标量漏包会 missing key）。
    return invoke(IPC_CHANNELS.SHELL_OPEN_EXTERNAL, { url });
  },
};

// ============================================================================
// windowApi —— 窗口 chrome 控制（Win/Linux 自绘 titlebar min/max/close，`decorations:false` 下唯一入口）
// ============================================================================

export const windowApi = {
  async minimize(): Promise<void> {
    return invoke(IPC_CHANNELS.WINDOW_MINIMIZE);
  },

  async maximizeToggle(): Promise<void> {
    return invoke(IPC_CHANNELS.WINDOW_MAXIMIZE_TOGGLE);
  },

  async close(): Promise<void> {
    return invoke(IPC_CHANNELS.WINDOW_CLOSE);
  },

  async isMaximized(): Promise<boolean> {
    return invoke(IPC_CHANNELS.WINDOW_IS_MAXIMIZED);
  },

  /** 最大化态变更（含按钮外触发：WM 双击标题栏 / 拖顶等），标题栏图标据此跟随。 */
  onMaximizeChanged(listener: (data: { maximized: boolean }) => void): () => void {
    return listen(IPC_CHANNELS.EVENT_WINDOW_MAXIMIZE_CHANGED, listener);
  },

  /**
   * 重启 Polaris 本体（U-7 第三类重启）。
   *
   * **会停核**：后端走 `request_restart()` → `ExitRequested` → `run_exit_cleanup`（停 sing-box +
   * 清系统代理），故调用即等于「断开代理并重启」。调用点必须已向用户交代过这一点。
   *
   * 后端只是往事件循环投一条退出请求就立即返回，真正的停核+重启在其后异步发生 ⇒
   * **resolve 不代表重启成功**（进程可能在应答送达前就走完退出腿，那时 Promise 干脆不 settle）。
   * 只能用 reject 判「IPC 都没打通」，不要在 then 里接任何后续 UI 动作。
   */
  async restartApp(): Promise<void> {
    return invoke(IPC_CHANNELS.APP_RESTART);
  },

  /**
   * U-7 判据基线：本次进程**启动时**后端真正读到的那三个键的生效值（`UserConfig` 口径的「是否开」）。
   *
   * 只读、进程生命周期内不变。**不能**在渲染端自行快照代替：webview 自愈重载会让渲染端的
   * 「启动值」漂移到重载那一刻的磁盘值，而后端这份仍是真正的进程启动值。
   */
  async startupConfigFlags(): Promise<{
    hardwareAcceleration: boolean;
    windowEffects: boolean;
    rememberWindowSize: boolean;
  }> {
    return invoke(IPC_CHANNELS.APP_STARTUP_CONFIG_FLAGS);
  },

  /**
   * spec §2.5 Q1-b 清除时机 ④：上次进程是不是**正常退出**的？—— **读即清**。
   *
   * 真 ⇒ 上次走完了退出腿（托盘「退出」/ ⌘Q / 末窗关闭 / `app:restart`）；
   * 假 ⇒ 强杀 / 崩溃 / 断电，**或者进程压根没退**（webview 自愈重载、C16 轻量模式销毁重建）。
   * 这个区分只有主进程知道 —— 渲染端能拿到的 `beforeunload`/`pagehide` 在重载时同样触发。
   *
   * **每个进程只有第一次调用返回真**（后端在读的同一次系统调用里消费掉标记）；调用方据此
   * 决定「清不清持久化的暂存」，必须在恢复（hydrate）之前拿到。
   */
  async takeCleanExitFlag(): Promise<boolean> {
    return invoke(IPC_CHANNELS.APP_TAKE_CLEAN_EXIT_FLAG);
  },
};

// ============================================================================
// helperApi —— macOS 提权 helper（免提权启停 sing-box）
// ============================================================================

export const helperApi = {
  async getStatus(force = false): Promise<HelperStatus> {
    // Rust helper_get_status(_force: Option<bool>) —— 参数袋 key = `force`（**非** `value`）。
    // Option 参数缺失不崩，但 invokeScalar 的 { value } 让 force 永远传不进后端。
    return invoke(IPC_CHANNELS.HELPER_GET_STATUS, { force });
  },

  /** 安装/修复 helper（弹一次管理员授权框）。 */
  async install(): Promise<HelperActionResult> {
    return invoke(IPC_CHANNELS.HELPER_INSTALL);
  },

  /** 卸载 helper（弹一次管理员授权框）。 */
  async uninstall(): Promise<HelperActionResult> {
    return invoke(IPC_CHANNELS.HELPER_UNINSTALL);
  },

  /** 监听「helper 可升级」事件。 */
  onUpgradeable(
    listener: (data: {
      version: number | null;
      expectedProtocolVersion: number;
      helperBuildId?: string | null;
      expectedBuildId: string;
    }) => void
  ): () => void {
    return listen(IPC_CHANNELS.EVENT_HELPER_UPGRADEABLE, listener);
  },
};

// ============================================================================
// appApi
// ============================================================================

/**
 * 完全卸载的各类目标（= Rust `runtime::uninstall::UninstallStep`，serde camelCase）。
 *
 * 数组顺序即**因果执行序**，理由见 Rust 侧模块文档：先停核 → 卸 helper（它要用配置目录）→
 * 删配置 → 清更新缓存 → 清应用偏好域（macOS `~/Library/Preferences/<id>.plist`；本进程还在跑，
 * 越晚清回写窗口越小）→ 最后删应用本体（它是当前进程的载体）。
 */
export type UninstallStep =
  | 'stopCore'
  | 'autostart'
  | 'helper'
  | 'userConfig'
  | 'cacheDir'
  | 'preferences'
  | 'appBundle';

/**
 * 单步结果（= Rust `StepOutcome`，`#[serde(tag = "kind")]`）。
 *
 * **五态而非布尔**：`skipped`（本就无事可做）、`unsupported`（本平台做不到）、
 * `notAttempted`（因前一步失败而没试）三者语义完全不同，糊成 `false` 就是骗人。
 */
export type UninstallOutcomeKind = 'done' | 'skipped' | 'unsupported' | 'failed' | 'notAttempted';

export interface UninstallStepReport {
  step: UninstallStep;
  outcome: { kind: UninstallOutcomeKind; detail: string };
}

/**
 * 逐项卸载报告（= Rust `UninstallReport`）。
 *
 * ⚠️ **`verdict` 才是真值，不是外层信封的 `success`**。外层恒 `success:true`（IPC 层没失败），
 * 因为 `ipc-client` 在 `success:false` 时 throw 且会丢掉 `data` —— 而逐项结果正是必须呈现的东西。
 * 只有 `complete` 能显示成「已卸载」；`incomplete`/`failed` 必须把剩下要用户手动做的事摆出来。
 */
export interface UninstallReport {
  steps: UninstallStepReport[];
  verdict: 'complete' | 'incomplete' | 'failed';
  /** 配置或应用本体已被真删 ⇒ 当前进程赖以运行的东西没了，应引导退出。 */
  requiresExit: boolean;
}

export const appApi = {
  /**
   * B6：完全卸载 Polaris（提权 helper / 受保护目录内核 / 用户配置 / 应用本体）。
   *
   * **不 throw 就等于卸载成功是错的** —— 判据是 `report.verdict === 'complete'`。
   */
  async uninstallAll(): Promise<UninstallReport> {
    return invoke(IPC_CHANNELS.APP_UNINSTALL_ALL);
  },

  /** 打开 sing-box 官方面板。代理未运行 → 返回 { ok: false }。 */
  async openSingboxDashboard(locale?: string): Promise<{ ok: boolean }> {
    // Rust open_singbox_dashboard(_locale: Option<String>) —— 参数袋 key = `locale`（**非** `value`）。
    // Option 参数缺失不崩，但 invokeScalar 的 { value } 让 locale 永远传不进后端。
    return invoke(IPC_CHANNELS.OPEN_SINGBOX_DASHBOARD, { locale });
  },

  /** 刷新 sing-box 官方面板资源：清本地缓存目录。 */
  async refreshSingboxDashboard(): Promise<{ ok: boolean }> {
    return invoke(IPC_CHANNELS.REFRESH_SINGBOX_DASHBOARD);
  },

  /** dashboard #55：取面板连接信息（url + apiUrl + secret）。 */
  async getSingboxDashboardConnection(): Promise<{
    ok: boolean;
    url: string;
    apiUrl: string;
    secret: string;
  }> {
    return invoke(IPC_CHANNELS.GET_SINGBOX_DASHBOARD_CONNECTION);
  },
};
