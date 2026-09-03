import { invoke, invokeScalar, listen } from '../ipc-client';
import { IPC_CHANNELS } from '../../domain/ipc-channels';
import type { CoreBuildKind } from '../../domain/core-build';

export interface VersionInfo {
  appVersion: string;
  appName: string;
  buildDate: string;
  singBoxVersion: string;
  copyright: string;
  repositoryUrl: string;
  platform: string;
  arch: string;
  osVersion: string;
}

// ============================================================================
// versionApi
// ============================================================================

export const versionApi = {
  async getInfo(): Promise<VersionInfo> {
    return invoke(IPC_CHANNELS.VERSION_GET_INFO);
  },
};
// ============================================================================
// updateApi —— 应用更新
// ============================================================================

export interface UpdateCheckResult {
  hasUpdate: boolean;
  /** `includeCurrent` 显式请求命中与已安装版本相同的 release；不是“有新版本”。 */
  isCurrentVersion?: boolean;
  updateInfo?: UpdateInfo;
  error?: string;
}

export interface UpdateInfo {
  version: string;
  title: string;
  releaseNotes: string;
  downloadUrl: string;
  fileSize: number;
  publishedAt: string;
  isPrerelease: boolean;
  fileName: string;
  /**
   * GitHub release asset 的期望 sha256（由后端从 `digest` 字段解析）。
   * 存在时下载侧做强校验；旧 release 无该字段 → undefined，回落 Content-Length 校验。
   */
  sha256?: string;
}

/**
 * 进度帧随行的清单：`UpdateInfo` **减去**两个只在「已发现新版本」那一屏渲染、且体积无上限的
 * 字段（单一真值在 Rust 的 `commands/updater::PROGRESS_MANIFEST_OMITTED`，两侧由
 * `contracts/update-progress-payload.test.ts` 对拍）。
 *
 * # 为什么不直接用 `UpdateInfo`
 *
 * 进度帧里那两个键**根本不存在**。写 `UpdateInfo` 就是让类型撒谎（声明成必有的 `string`），
 * 下一个人拿 `updateInfo.releaseNotes.length` 就会在运行期炸。写成「其余照旧 + 这两个可选」
 * 之后，类型说的就是运行期真有的东西；`available` 那一屏本就写着 `{updateInfo.releaseNotes && …}`，
 * 可选化后逐字不变。
 *
 * # 为什么剥的是这两个
 *
 * `releaseNotes` = GitHub release body 原文，无截断（单 body 上限 125 KB）；一次下载最多 ~100 帧
 * × 所有窗口 ⇒ 20 KB 的说明会变成约 2 MB 在 webview 主线程反序列化。**这是及时性问题**
 * （进度条要「现在」到），不是省内存，故不受「不为省内存牺牲准确性」那条约束保护；而准确性
 * 零损失 —— 这两个字段在 progress 可达的四个态里一处都不渲染，`available` 也不可能由进度帧进入。
 * `title` 全仓零消费点。
 */
export interface UpdateProgressManifest extends Omit<UpdateInfo, 'releaseNotes' | 'title'> {
  /** 只有 `updateApi.check()` 那条腿带；进度帧刻意不带（见上）。 */
  releaseNotes?: string;
  /** 同上。全仓零消费点，剥掉只是顺手。 */
  title?: string;
}

/**
 * 安装前必须告知用户的事项（后端 `update_install::InstallAdvisory` 的 key）。
 *
 * 三者都是「OS 会拦一道，用户需要知道怎么点」——**应用内消不掉的必须提前讲清楚**：
 *  - `macosGatekeeper`：ad-hoc 签名 → 安装脚本会自动清 quarantine；万一失败需右键「打开」
 *  - `windowsSmartScreen`：无 Authenticode → 「更多信息 → 仍要运行」
 *  - `debElevation`：即将弹 polkit 提权框（取消即真 no-op，不会留下「代理被停但没更新」的坏态）
 */
export type InstallAdvisory = 'macosGatekeeper' | 'windowsSmartScreen' | 'debElevation';

/** `updateApi.install` 的返回：需确认 / 已交系统 / 已起安装脚本。 */
export interface UpdateInstallResult {
  ok: boolean;
  success?: boolean;
  /** true = 需要先向用户展示 advisory 说明，确认后再带 confirmed:true 重调。 */
  needConfirm?: boolean;
  advisory?: InstallAdvisory;
  /** 形态错配 → 已回退交系统打开（**不强制 root 安装**）。 */
  handedToSystem?: boolean;
  reason?: string;
  detail?: string;
}

/**
 * `update:progress` 的一帧（= Rust `commands/updater::progress_payload`，字段集由
 * `contracts/update-progress-payload.test.ts` 双向对拍）。
 *
 * # 帧里为什么带着「随行事实」而不只是一个状态
 *
 * 本事件走 `events::broadcast` fan-out 给**所有**窗口 ⇒ 别的窗口发起的下载（启动自动下载腿
 * `startup_tasks::spawn_auto_download`、弹窗「更新/重试」腿 `update_popup_action`）同样会把
 * **设置页**推进 downloading/downloaded/error，而设置页**拿不到那次 invoke 的回包**。
 * 帧里只有状态时，设置页只能拿本页上一次检查的结果去描述别人刚下的那个包 —— 版本号、体积、
 * 安装路径全都不是这条路径上真实发生的那件事。故状态所依赖的数据必须与状态同帧同行。
 */
export interface UpdateProgress {
  status:
    | 'idle'
    | 'checking'
    | 'no-update'
    | 'update-available'
    | 'downloading'
    | 'downloaded'
    | 'error';
  percentage: number;
  /** 失败机器码；**仅 `error` 帧有**（U1：正文本地化在前端按码取键，后端不再产中文正文）。 */
  errorCode?: string;
  /** 技术诊断串；**仅 `error` 帧有且可缺**（语言中性的数据）。 */
  errorDetail?: string;
  /**
   * 本帧描述的那份包的发布清单（**每一帧都有**：Rust 侧它是 `progress_payload` 的形参，
   * 不是可选项）。设置页据此渲染版本号 / 体积 / 预发布档次，并在 error 态拿它重试。
   *
   * 是 [`UpdateProgressManifest`] 而不是 `UpdateInfo`：帧里剥掉了 `releaseNotes` / `title`，
   * 成因与判据见该类型。
   */
  updateInfo?: UpdateProgressManifest;
  /** 已落位的安装包路径；**仅 `downloaded` 帧有**（Rust `ProgressStage::Downloaded` 的必填字段）。 */
  filePath?: string;
  /**
   * 已收字节；**仅 `downloading` 帧有**。是下载回调给的原值，不是从 `percentage` 反推的估算
   * （百分比被夹在 `1..=99` 且按整数去重，反推出来的字节数每一帧都是错的）。
   */
  receivedBytes?: number;
  /** 摘要是否逐字节校验过；**仅 `downloaded` 帧有**（与 `updateApi.download()` 回包的同名字段同源）。 */
  verified?: boolean;
}

export const updateApi = {
  async check(
    options: { includePrerelease?: boolean; includeCurrent?: boolean } = {},
  ): Promise<UpdateCheckResult> {
    const { includePrerelease = false, includeCurrent = false } = options;
    return invoke(IPC_CHANNELS.UPDATE_CHECK, { includePrerelease, includeCurrent });
  },

  /**
   * 下载更新包。
   *
   * `verified` 特指**摘要**这一级：`true` = 有期望 sha256 且逐字相符；`false` = 该 release 没给
   * 摘要（旧 release 的正常形态，不拒装），此时后端仍做了「清单 `fileSize` 等值 + Content-Length」
   * 两级弱校验。`digestSource` 如实标注摘要是谁给的，无摘要时为 `null` —— 出事时据它追责到具体
   * 信任根。复用本地已有包的那条路径同样带这个字段（它恰恰是靠这条摘要比中的）。
   *
   * 类型写成**字面量联合**而不是 `string`：后端的信任根是闭集（`DigestSource` 枚举，当前只有
   * `updater.rs` 的 `Self::GithubAssetDigest => "githubAssetDigest"` 一个变体）。将来真加第二个
   * 来源时，所有按来源分流的调用点必须被编译器点名——用 `string` 就等于把那一刻本该编不过的
   * 地方全放过去。
   *
   * **U3 已落地，但没有给这里添成员**（2026-08-17，订正本段原先的预期）：随包 `SHA256SUMS`
   * 只落**发布侧**（产出 + 缺失/不符即红的 CI 门），消费侧经判断**不接** —— 依据（增量价值的
   * 射程近乎空集、同源清单比跨源 asset digest 更弱、成本远不止「插一行」）登记在
   * `src-tauri/src/commands/updater/app_update.rs` 的 `resolve_expected_digest` 文档末节。故本联合仍是单成员。
   *
   * **本字段的后端实现在 `fix(updater): stream the app package to disk instead of buffering it`
   * 那一批**：本文件必须合在它之后，否则这段 JSDoc 是一份假契约（字段声明成可选 ⇒ tsc 全绿，
   * 而运行期拿到的是 `undefined` 不是 `null`，任何 `=== null` 的分支恒不成立）。
   */
  async download(updateInfo: UpdateProgressManifest): Promise<{
    success: boolean;
    filePath?: string;
    verified?: boolean;
    digestSource?: 'githubAssetDigest' | null;
    /** U1 稳定失败码；正文须由 UI 依码本地化。 */
    errorCode?: string;
    /** 诊断数据仅用于日志/支持收据，禁止直接展示。 */
    errorDetail?: string;
  }> {
    return invoke(IPC_CHANNELS.UPDATE_DOWNLOAD, { updateInfo });
  },

  /**
   * 安装已下载的更新包。**两段式**：首调若返 `needConfirm`，UI 须先展示 `advisory` 说明，
   * 用户确认后带 `confirmed: true` 重调。确认框必须在停代理之前弹（取消 = 真 no-op）。
   */
  async install(filePath: string, confirmed = false): Promise<UpdateInstallResult> {
    return invoke(IPC_CHANNELS.UPDATE_INSTALL, { filePath, confirmed });
  },

  async skip(version: string): Promise<{ success: boolean }> {
    return invoke(IPC_CHANNELS.UPDATE_SKIP, { version });
  },

  onProgress(listener: (progress: UpdateProgress) => void): () => void {
    return listen(IPC_CHANNELS.EVENT_UPDATE_PROGRESS, listener);
  },
};

// ============================================================================
// coreUpdateApi —— 内核（sing-box）更新
// ============================================================================

/** 换核类命令的统一返回（`core_update_run` / `rollback` / `replaceManual` / `resetFactory` 共用）。 */
export interface CoreSwapResult {
  ok: boolean;
  result?: 'applied' | 'deferred' | 'noop';
  corePath?: string;
  hasBackup?: boolean;
  previousVersion?: string;
  currentVersion?: string;
  /** 换核前代理在跑 → 换完已自动重启。 */
  restarted?: boolean;
  /** 跨大版本带被自动更新硬闸拦下（手动换核可绕过）。 */
  crossBand?: boolean;
  latestVersion?: string;
}

export const coreUpdateApi = {
  async check(): Promise<{
    hasUpdate: boolean;
    currentVersion: string;
    currentVersionLine?: string;
    latestVersion?: string;
    downloadUrl?: string;
    assetName?: string;
    /** GitHub asset digest 解析出的期望 sha256（旧 release 可能缺）。 */
    sha256?: string | null;
    releaseNotes?: string;
    /** latestVersion 是否跨当前 minor 带；true 时 UI 标注跨大版本风险。 */
    crossBand?: boolean;
    error?: string;
  }> {
    return invoke(IPC_CHANNELS.CORE_UPDATE_CHECK);
  },

  /**
   * 下载并换核。传 downloadUrl 直接换；不传则后端自查一次。
   *
   * 返回结构化结果（**非 boolean**）：布尔会把 deferred/noop 折叠成「失败」，
   * 让「跨带被闸拦下」和「真失败」在 UI 上无从区分。
   */
  async update(downloadUrl?: string): Promise<CoreSwapResult> {
    // Polaris 原直接传裸 string；Tauri 需对象，底层包 { value }。
    return invokeScalar<CoreSwapResult>(IPC_CHANNELS.CORE_UPDATE_RUN, downloadUrl ?? '');
  },

  async getVersionInfo(): Promise<{
    currentVersion: string;
    bundledVersion: string;
    /**
     * 备份版本号。**恒为 null**：读它需执行 `<bak> version`（跑内核二进制），属真机腿。
     * `hasBackup` 已足以驱动「回滚」按钮；此处如实返 null 而非拿现役核版本冒充。
     */
    backupVersion: string | null;
    hasBackup: boolean;
    build: 'official' | 'fork' | 'unknown';
    pendingChangeNotice?: { previousVersion: string; currentVersion: string } | null;
  }> {
    return invoke(IPC_CHANNELS.CORE_GET_VERSION_INFO);
  },

  /** banner 展示版本变更通知后 ack 清除持久 pendingChangeNotice。 */
  async ackVersionChange(): Promise<void> {
    return invoke(IPC_CHANNELS.CORE_UPDATE_ACK_VERSION_CHANGE);
  },

  async rollback(): Promise<CoreSwapResult> {
    return invoke(IPC_CHANNELS.CORE_ROLLBACK);
  },

  onVersionChanged(
    listener: (data: {
      previousVersion: string;
      currentVersion: string;
      hasBackup: boolean;
    }) => void
  ): () => void {
    return listen(IPC_CHANNELS.EVENT_CORE_VERSION_CHANGED, listener);
  },

  /**
   * 手动替换核心。无参：弹文件选择器 + 预检；传 { filePath, force:true }：跳过确认直接换。
   */
  async replaceManual(opts?: {
    filePath?: string;
    force?: boolean;
  }): Promise<
    | (CoreSwapResult & { ok: true; build?: CoreBuildKind })
    | {
        ok: false;
        /** 用户在系统文件选择器里取消 —— 正常流程，不是错误，UI 不得弹红。 */
        cancelled?: boolean;
        needConfirm?: boolean;
        sameVersion?: string;
        baselineOverride?: boolean;
        uploadVersion?: string;
        bundledVersion?: string;
        filePath?: string;
        error?: string;
      }
  > {
    return invoke(IPC_CHANNELS.CORE_REPLACE_MANUAL, opts);
  },

  /** 重置内核到随应用出厂的版本（不备份、清残留备份）。 */
  async resetFactory(): Promise<CoreSwapResult & { error?: string }> {
    return invoke(IPC_CHANNELS.CORE_RESET_FACTORY);
  },

  async getAutoStatus(): Promise<{
    /** 后端如实返 null（该开关的读取归 config 域，不在此猜 false）。 */
    autoUpdateCore: boolean | null;
    lastCheckAt: number | null;
    staged: { version: string; dir: string; stagedAt: string } | null;
    crossBandNotifiedVersion: string | null;
  }> {
    return invoke(IPC_CHANNELS.CORE_UPDATE_GET_AUTO_STATUS);
  },

  /**
   * 用户点「立即应用」：停代理→换核→重启（唯一允许主动断流）。
   *
   * 返回**五态对象**而非布尔：`discarded`（staged 已不领先/文件缺失）、`deferred`、`failed`
   * 各有不同处置，折叠成布尔会让 UI 把三者都误报成「已应用」（上游 修 M1 的原因）。
   */
  async applyStaged(): Promise<{
    result: 'applied' | 'discarded' | 'deferred' | 'failed' | 'noop';
    error?: string;
  }> {
    return invoke(IPC_CHANNELS.CORE_UPDATE_APPLY_STAGED);
  },

  onAutoStatusChanged(
    listener: (data: {
      lastCheckAt: number | null;
      staged: { version: string; stagedAt: string } | null;
      crossBandLatest: string | null;
    }) => void
  ): () => void {
    return listen(IPC_CHANNELS.EVENT_CORE_AUTO_UPDATE_STATUS, listener);
  },
};
