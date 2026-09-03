import { invoke, listen, listenReady } from '../ipc-client';
import { IPC_CHANNELS } from '../../domain/ipc-channels';
import type { SubscriptionConfig, ImportParseResult } from '../../contracts/types';
import type { SubscriptionErrorKind, SubscriptionPreviewResult } from '../../contracts/subscription-preview';
import type { SubscriptionUpdateProgress } from '../../contracts/subscription-progress';
import type { BackupCategory } from '../../domain/backup-categories';
import type {
  SubscriptionCreateInput,
  SubscriptionCreateSnapshot,
} from '../../contracts/subscription-create-operation';

export type BackupErrorCode =
  | 'cancelled'
  | 'configLoadFailed'
  | 'serializeFailed'
  | 'writeFailed'
  | 'readFailed'
  | 'invalidFormat'
  | 'invalidArgs'
  | 'saveFailed'
  | 'unknown';

// ============================================================================
// subscriptionApi
// ============================================================================

export const subscriptionApi = {
  async createStart(
    operationId: string,
    subscription: SubscriptionCreateInput,
  ): Promise<SubscriptionCreateSnapshot> {
    return invoke(IPC_CHANNELS.SUBSCRIPTION_CREATE_START, { operationId, subscription });
  },

  async createStatus(operationId: string): Promise<SubscriptionCreateSnapshot> {
    return invoke(IPC_CHANNELS.SUBSCRIPTION_CREATE_STATUS, { operationId });
  },

  async createCancel(operationId: string): Promise<SubscriptionCreateSnapshot> {
    return invoke(IPC_CHANNELS.SUBSCRIPTION_CREATE_CANCEL, { operationId });
  },

  /** 后端持有的完整可恢复窗口；renderer localStorage 只是一条快速线索，不是事实源。 */
  async createList(): Promise<SubscriptionCreateSnapshot[]> {
    return invoke(IPC_CHANNELS.SUBSCRIPTION_CREATE_LIST);
  },

  onCreateProgress(listener: (snapshot: SubscriptionCreateSnapshot) => void): () => void {
    return listen(IPC_CHANNELS.EVENT_SUBSCRIPTION_CREATE_PROGRESS, listener);
  },

  /**
   * 等事件监听**实际**登记后才 resolve。重建水合必须先 await 这个门、再拉 list，
   * 否则 list 返回到 listen 真正登记之间的进度帧会永久丢失。
   */
  async onCreateProgressReady(
    listener: (snapshot: SubscriptionCreateSnapshot) => void,
  ): Promise<() => void> {
    return listenReady(IPC_CHANNELS.EVENT_SUBSCRIPTION_CREATE_PROGRESS, listener);
  },

  async update(subscription: SubscriptionConfig): Promise<void> {
    return invoke(IPC_CHANNELS.SUBSCRIPTION_UPDATE, { subscription });
  },

  async delete(subscriptionId: string): Promise<void> {
    return invoke(IPC_CHANNELS.SUBSCRIPTION_DELETE, { subscriptionId });
  },

  async updateServers(subscriptionId: string): Promise<{
    success: boolean;
    addedServers: number;
    updatedServers: number;
    deletedServers: number;
    /** 已分类的失败原因；渲染端必须按 kind 本地化，不能展示 error 诊断。 */
    errorKind?: SubscriptionErrorKind;
    /** HTTP 类失败的状态码，仅用于 i18n 插值。 */
    httpStatus?: number;
    /** 已脱敏的诊断，仅供日志/兼容载荷，不能直接展示。 */
    error?: string;
    /** §16.3.4：304/无内容变化 → true（UI 弹「订阅无变化」toast）。 */
    unchanged?: boolean;
  }> {
    return invoke(IPC_CHANNELS.SUBSCRIPTION_UPDATE_SERVERS, { subscriptionId });
  },

  /** 订阅预检（add 前先行，不写 config）：拉取+解析返回节点数或分类错误。 */
  async preview(
    url: string,
    opts: { viaProxy?: boolean; userAgent?: string }
  ): Promise<SubscriptionPreviewResult> {
    return invoke(IPC_CHANNELS.SUBSCRIPTION_PREVIEW, {
      url,
      viaProxy: opts.viaProxy,
      userAgent: opts.userAgent,
    });
  },

  /**
   * 监听后台自动更新结果（scheduler 每个 due 订阅拉取后发一条）。渲染端仅对 `success:false` 弹 toast
   * （成功静默——对齐 上游 后台更新只入日志、不弹成功的 UX；手动刷新才三态 toast）。
   */
  onAutoUpdate(
    listener: (data: {
      subscriptionId: string;
      name: string;
      success: boolean;
      error?: string;
      errorKind?: SubscriptionErrorKind;
      httpStatus?: number;
      addedServers?: number;
      updatedServers?: number;
      deletedServers?: number;
      unchanged?: boolean;
    }) => void
  ): () => void {
    return listen(IPC_CHANNELS.EVENT_SUBSCRIPTION_AUTOUPDATE, listener);
  },

  /**
   * 监听单订阅更新的逐阶段进度（手动刷新与后台 scheduler **共用**同一发射点）。
   * 消费点 = `store/use-subscription-progress-store.ts`（窗口级持久订阅 → 订阅信息栏）。
   */
  onUpdateProgress(listener: (data: SubscriptionUpdateProgress) => void): () => void {
    return listen(IPC_CHANNELS.EVENT_SUBSCRIPTION_UPDATE_PROGRESS, listener);
  },
};
// ============================================================================
// localImportApi —— 本地导入（粘贴文本 / 文件）解析 + 系统文件选择
// ============================================================================

export const localImportApi = {
  /**
   * 解析粘贴文本 / 文件内容（离线，不联网）：识别 base64 / URL-list / Clash / sing-box，
   * 返回节点预览 + 统计。**0 节点 → 后端 throw**（IpcError，前端 catch 得错误文案）；
   * 不可识别格式亦 throw（ipc-channels.ts:45）。
   */
  async parse(text: string): Promise<ImportParseResult> {
    // Rust local_import_parse(text: String) —— 参数袋 key = `text`。
    return invoke(IPC_CHANNELS.LOCAL_IMPORT_PARSE, { text });
  },

  /**
   * 弹系统原生文件框（tauri-plugin-dialog）选配置文件 + 读内容回传。取消 → `canceled:true`；
   * 超限（10MB，同 `local_import_parse` 口径）/ 读失败 → `error`（`'too_large'|'read_failed'`）；
   * 成功 → `content` + `fileName`（basename，非全路径）。对齐 上游 `LOCAL_IMPORT_PICK_FILE`。
   */
  async pickFile(): Promise<{
    canceled: boolean;
    content?: string;
    fileName?: string;
    error?: string;
  }> {
    return invoke(IPC_CHANNELS.LOCAL_IMPORT_PICK_FILE);
  },
};

// ============================================================================
// backupApi
// ============================================================================

export interface BackupInfo {
  serverCount: number;
  manualServerCount: number;
  meshServerCount: number;
  subscriptionCount: number;
  ruleCount: number;
  ruleSetCount: number;
  appRuleCount: number;
  crossPlatformDisabledRules?: number;
}

export const backupApi = {
  /** 导出备份（按勾选类别；缺省/空 = 全部）。弹系统保存对话框。 */
  async export(
    categories?: BackupCategory[]
  ): Promise<{
    success: boolean;
    filePath?: string;
    errorCode?: BackupErrorCode;
    /** 后端诊断数据，禁止直接呈现给用户。 */
    diagnostic?: string;
  }> {
    return invoke(IPC_CHANNELS.BACKUP_EXPORT, { categories });
  },

  /** 导入①：弹文件框 + 解析 → 返回备份含哪些类 + 各类数量（不 apply）。canceled=用户取消。 */
  async importPick(): Promise<{
    canceled: boolean;
    filePath?: string;
    available?: BackupCategory[];
    counts?: Partial<Record<BackupCategory, number>>;
    unavailableInterfaceBindings?: Partial<Record<BackupCategory, number>>;
    errorCode?: BackupErrorCode;
    /** 后端诊断数据，禁止直接呈现给用户。 */
    diagnostic?: string;
  }> {
    return invoke(IPC_CHANNELS.BACKUP_IMPORT_PICK);
  },

  /** 导入②：按所选类整类替换 + 空跳过 + 保存。skipped=选了但备份为空被跳过的类。 */
  async importApply(
    filePath: string,
    categories: BackupCategory[]
  ): Promise<{
    success: boolean;
    info?: BackupInfo;
    skipped?: BackupCategory[];
    unavailableInterfaceBindings?: number;
    errorCode?: BackupErrorCode;
    /** 后端诊断数据，禁止直接呈现给用户。 */
    diagnostic?: string;
  }> {
    return invoke(IPC_CHANNELS.BACKUP_IMPORT_APPLY, { filePath, categories });
  },

  async getInfo(): Promise<BackupInfo> {
    return invoke(IPC_CHANNELS.BACKUP_GET_INFO);
  },
};
