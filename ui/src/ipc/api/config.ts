import { invoke, invokeScalar, listen } from '../ipc-client';
import { IPC_CHANNELS } from '../../domain/ipc-channels';
import type { UserConfig, StagedClassification, SaveOutcome } from '../../contracts/types';

// ============================================================================
// configApi
// ============================================================================

export const configApi = {
  async get(): Promise<UserConfig> {
    return invoke(IPC_CHANNELS.CONFIG_GET);
  },

  /**
   * 暂存事务的版本化整份保存。生产调用必须同时传 `baseVersion`；即时控件使用 `patch()`。
   * `deferRestart=true` 时只更新磁盘：热切、强制重启和普通重启都留给显式“应用”。
   */
  async save(
    config: UserConfig,
    deferRestart: boolean,
    baseVersion: string
  ): Promise<SaveOutcome> {
    // Rust config_save(config, defer_restart: Option<bool>, base_version: Option<String>)
    // —— 参数袋 key = `config` / `deferRestart` / `baseVersion`。
    // 参数袋必须是对象字面量：check-ipc-args.mjs 静态核对 required 参数键。
    return invoke(IPC_CHANNELS.CONFIG_SAVE, { config, deferRestart, baseVersion });
  },

  /** 即时控件的原子顶层补丁；返回后端落盘并重新投影后的完整配置。 */
  async patch(patch: Partial<UserConfig>): Promise<UserConfig> {
    return invoke(IPC_CHANNELS.CONFIG_PATCH, { patch });
  },

  /** 在后端最新配置上按实体主键原子 upsert/delete；同一数组的并发编辑不会整字段互相覆盖。 */
  async mutateEntities(
    mutations: readonly {
      collection: 'customAppPresets' | 'appRules';
      entityId: string;
      value: unknown | null;
    }[]
  ): Promise<UserConfig> {
    return invoke(IPC_CHANNELS.CONFIG_MUTATE_ENTITIES, { mutations });
  },

  /**
   * 预告：这份候选配置若现在落盘会走哪条腿（只读，不落盘、不碰核）。
   *
   * 用于暂存条目在**保存之前**标注「仅需保存 / 保存后待应用」——「5 项待保存 → 保存 → 2 项待应用」
   * 这个收缩必须在暂存期就有交代，否则用户会认为保存吃掉了另外 3 条。
   */
  async classifyStaged(config: UserConfig): Promise<StagedClassification> {
    return invoke(IPC_CHANNELS.CONFIG_CLASSIFY_STAGED, { config });
  },

  /** 只同步 pending 与节点 id 遮罩；草稿正文仍只在主窗暂存 store。 */
  async setStagedPending(
    pending: boolean,
    nodeIds: readonly string[] = []
  ): Promise<void> {
    return invoke(IPC_CHANNELS.CONFIG_SET_STAGED_PENDING, { pending, nodeIds });
  },

  async setValue(key: string, value: unknown): Promise<void> {
    return invoke(IPC_CHANNELS.CONFIG_SET_VALUE, { key, value });
  },

  /**
   * 配置变更的**无载荷信号**：后端 emit `{}`（`commands/config.rs` 的
   * `broadcast_config_changed_with`），收到即各自重拉，没有任何消费方读 payload。
   *
   * 签名收成零参不是文档性质的：它让「想读 newValue」在类型层就编不过。此前那份
   * `{ key?, oldValue?, newValue? }` 是照搬 Electron 侧的形状，而 `newValue` 经脱敏、
   * 也没走 `config_get` 那侧的 bypassLANList 补齐 —— 直接拿来用是错的（见 `use-config.ts`）。
   */
  onChanged(listener: () => void): () => void {
    return listen(IPC_CHANNELS.EVENT_CONFIG_CHANGED, listener);
  },

  async getPrivacyMode(): Promise<boolean> {
    return invoke(IPC_CHANNELS.CONFIG_GET_PRIVACY_MODE);
  },

  async setPrivacyMode(value: boolean): Promise<void> {
    // Polaris 原直接传裸 boolean；Tauri 需对象，底层包 { value }。
    return invokeScalar(IPC_CHANNELS.CONFIG_SET_PRIVACY_MODE, value);
  },

  /**
   * 进入隐私模式（锁屏）。后端 `config_set_privacy_mode(true)` 状态跃迁时真 emit
   * （config.rs:355-362：仅 prev≠value 才发）；托盘「立即锁定」/ idle 计时 / 别的窗口均经此收敛主窗遮罩。
   */
  onEnterPrivacyMode(listener: () => void): () => void {
    return listen(IPC_CHANNELS.EVENT_ENTER_PRIVACY_MODE, listener);
  },

  /** 退出隐私模式。后端 `config_set_privacy_mode(false)` 真 emit（解锁成功后由前端调 setPrivacyMode(false) 触发）。 */
  onExitPrivacyMode(listener: () => void): () => void {
    return listen(IPC_CHANNELS.EVENT_EXIT_PRIVACY_MODE, listener);
  },
};
// ============================================================================
// privacyApi —— F29：隐私密码。哈希/校验全在后端；渲染端只拿 hasPassword 布尔与 verify 结果。
// ============================================================================

export const privacyApi = {
  // Rust privacy_set_password(_password: String) / privacy_unlock(_password: String) —— 参数袋 key = `password`
  // （**非** `plain`）。裸 { plain } 缺 required key `password` → missing-key 崩。
  setPassword: (plain: string): Promise<{ success: boolean }> =>
    invoke(IPC_CHANNELS.PRIVACY_SET_PASSWORD, { password: plain }),
  unlock: (plain: string): Promise<{ ok: boolean }> =>
    invoke(IPC_CHANNELS.PRIVACY_UNLOCK, { password: plain }),
  hasPassword: (): Promise<boolean> => invoke(IPC_CHANNELS.PRIVACY_HAS_PASSWORD),
};
