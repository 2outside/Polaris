import { invoke, listenReady } from '../ipc-client';
import { IPC_CHANNELS } from '../../domain/ipc-channels';
import type { LogEntry, RuntimeLogLevel } from '../../contracts/types';

// ============================================================================
// logsApi
// ============================================================================

export const logsApi = {
  async get(subscriptionId: string, limit?: number): Promise<LogEntry[]> {
    return invoke(IPC_CHANNELS.LOGS_GET, { subscriptionId, limit });
  },

  /** 在后端保留历史中检索；返回数量受绘制预算限制，但查询域不受前端 500 行尾部限制。 */
  async search(
    query: string,
    level: LogEntry['level'],
    source: 'all' | 'sing-box' | 'app',
    limit?: number,
  ): Promise<LogEntry[]> {
    return invoke(IPC_CHANNELS.LOGS_SEARCH, { query, level, source, limit });
  },

  async unsubscribe(subscriptionId: string): Promise<void> {
    return invoke(IPC_CHANNELS.LOGS_UNSUBSCRIBE, { subscriptionId });
  },

  async clear(): Promise<void> {
    return invoke(IPC_CHANNELS.LOGS_CLEAR);
  },

  /** 导出纯日志（节点身份打码；不含配置与运行态，区别于 diagnostic.export 的完整诊断报告）。 */
  async export(): Promise<{ success: boolean; filePath?: string; error?: string }> {
    return invoke(IPC_CHANNELS.LOGS_EXPORT);
  },

  /**
   * 在系统文件管理器里打开日志目录（G3，原型 log 工具栏「目录」）。
   *
   * 打开的是**配置目录**——受管日志在 `logs/`，helper 启动日志和旧版只读 singbox.log 在父层；
   * 打开共同父目录才能同时看见（见 Rust 侧命令注释）。
   * 路径解析在后端，前端不拼路径（三平台不同，portable 形态另有落点）。
   */
  async openDir(): Promise<void> {
    return invoke(IPC_CHANNELS.LOGS_OPEN_DIR);
  },

  /** W26 前遗留的无界 singbox.log；当前版本只读识别，不会继续写入或自动删除。 */
  async legacyInfo(): Promise<{ exists: boolean; bytes: number; path: string }> {
    return invoke(IPC_CHANNELS.LOGS_LEGACY_INFO);
  },

  /** 用户显式选择目标后归档旧日志；后端先复制+落盘复核，最后才移除原文件。 */
  async archiveLegacy(): Promise<{
    success: boolean;
    archived?: boolean;
    bytes?: number;
    filePath?: string;
    error?: string;
  }> {
    return invoke(IPC_CHANNELS.LOGS_ARCHIVE_LEGACY);
  },

  /** 用户二次确认后删除固定配置目录中的旧日志；路径只在后端解析。 */
  async deleteLegacy(): Promise<{ deleted: boolean; bytes: number }> {
    return invoke(IPC_CHANNELS.LOGS_DELETE_LEGACY);
  },

  /**
   * 读回核**此刻实际**在用的日志级别（管理 API `GetDefaultLogLevel`）。
   *
   * 与 `config.logLevel` 不是同一件事 —— 后者是「我写下的意图」，两者已知有两条分叉：隐私锁开启时
   * 生成侧把级别抬到 ≥warn；配置暂存态下改级别零落盘。**读不到时后端回 `level: null` 而不是某个
   * 具体级别**（回落出来的一定是那个「我写下的值」，自证就退化成它本要揭穿的那句谎）。
   */
  async runtimeLevel(): Promise<RuntimeLogLevel> {
    return invoke(IPC_CHANNELS.LOGS_RUNTIME_LEVEL);
  },

  /** 当前进程是否临时启用了 DEBUG 诊断；不读取/修改持久配置。 */
  async diagnosticState(): Promise<boolean> {
    return invoke(IPC_CHANNELS.LOGS_DIAGNOSTIC_STATE);
  },

  /** 临时抬高本次运行的日志门槛；应用重启后由启动配置自然恢复。 */
  async setDiagnostic(enabled: boolean): Promise<boolean> {
    return invoke(IPC_CHANNELS.LOGS_SET_DIAGNOSTIC, { enabled });
  },

  /** 等待批量日志监听真正登记完成；水合必须在此之后启动，才能保证快照与直播无缝。 */
  onReceivedBatchReady(listener: (logs: LogEntry[]) => void): Promise<() => void> {
    return listenReady(IPC_CHANNELS.EVENT_LOG_RECEIVED_BATCH, listener);
  },
};
// ============================================================================
// diagnosticApi
// ============================================================================

export const diagnosticApi = {
  /** 导出诊断报告（弹出系统文件保存对话框，单 Markdown，密钥已脱敏）。 */
  async export(): Promise<{ success: boolean; filePath?: string; error?: string }> {
    return invoke(IPC_CHANNELS.DIAGNOSTIC_EXPORT);
  },

  // 此处曾有 captureStart / captureStop（「诊断采集」）。整条机制已删除 —— 内核日志改由管理 API 的
  // SubscribeLog 全级别送来、级别筛在客户端，把日志页级别拨到 DEBUG 即刻生效（不落盘、不重启内核）。
};
