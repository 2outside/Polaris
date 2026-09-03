import { invoke, listen } from '../ipc-client';
import { IPC_CHANNELS } from '../../domain/ipc-channels';
import type { Rule, RuleResourceDeleteResult, RuleResourceListItem, RuleResourceDownloadItem, RuleResourceDownloadResult, RuleResourceProgress, RuleResourceCatalogResult } from '../../contracts/types';

// ============================================================================
// rulesApi
// ============================================================================

export const rulesApi = {
  async add(rule: Omit<Rule, 'id'>, plane: 'route' | 'dns'): Promise<Rule> {
    return invoke(IPC_CHANNELS.RULES_ADD, { rule, plane });
  },

  async update(rule: Rule, plane: 'route' | 'dns'): Promise<void> {
    return invoke(IPC_CHANNELS.RULES_UPDATE, { rule, plane });
  },

  async delete(ruleId: string, plane: 'route' | 'dns'): Promise<void> {
    return invoke(IPC_CHANNELS.RULES_DELETE, { ruleId, plane });
  },

  /** 按执行平面独立重排。 */
  async reorder(orderedIds: string[], plane: 'route' | 'dns'): Promise<void> {
    return invoke(IPC_CHANNELS.RULES_REORDER, { orderedIds, plane });
  },
};
// ============================================================================
// ruleResourcesApi —— .srs 下载/管理
// ============================================================================

export const ruleResourcesApi = {
  list(): Promise<RuleResourceListItem[]> {
    return invoke(IPC_CHANNELS.RULE_RESOURCES_LIST);
  },
  download(items: RuleResourceDownloadItem[]): Promise<RuleResourceDownloadResult[]> {
    return invoke(IPC_CHANNELS.RULE_RESOURCES_DOWNLOAD, { items });
  },
  redownload(id: string): Promise<RuleResourceDownloadResult> {
    return invoke(IPC_CHANNELS.RULE_RESOURCES_REDOWNLOAD, { id });
  },
  /**
   * 中止该资源的在途下载（原型 `res-cancel`）。返回 `cancelled` = **真被中止**的在途下载条数——
   * 0 表示点下去时已无可取消的下载（后端如实回报，不伪装成功）。取消的下载不落盘不入册。
   */
  cancel(id: string): Promise<{ cancelled: number }> {
    return invoke(IPC_CHANNELS.RULE_RESOURCES_CANCEL, { id });
  },
  delete(id: string, force?: boolean): Promise<RuleResourceDeleteResult> {
    return invoke(IPC_CHANNELS.RULE_RESOURCES_DELETE, { id, force });
  },
  getCatalog(): Promise<RuleResourceCatalogResult> {
    return invoke(IPC_CHANNELS.RULE_RESOURCES_GET_CATALOG);
  },
  refreshCatalog(): Promise<RuleResourceCatalogResult> {
    return invoke(IPC_CHANNELS.RULE_RESOURCES_REFRESH_CATALOG);
  },
  /**
   * 回读上次刷新落盘的全量清单（**零出站**）；从没刷新成功过 → `null`。
   * `null` 与 `refreshCatalog()` 的 `source:'builtin'` 不可混用：后者意味着「远程拉过且失败了」，
   * 而本调用一次网都没打，报成失败即谎报。
   */
  getCachedCatalog(): Promise<RuleResourceCatalogResult | null> {
    return invoke(IPC_CHANNELS.RULE_RESOURCES_GET_CACHED_CATALOG);
  },
  updateAll(): Promise<RuleResourceDownloadResult[]> {
    return invoke(IPC_CHANNELS.RULE_RESOURCES_UPDATE_ALL);
  },
  resetBuiltin(tag: string): Promise<RuleResourceDownloadResult> {
    return invoke(IPC_CHANNELS.RULE_RESOURCES_RESET_BUILTIN, { tag });
  },
  /**
   * 更新单个内置 geo 规则集到上游最新版。`tag` 是内置表里的 tag（如 `geosite-cn`），**不是** `builtin:` id。
   * 内置项不入 `config.ruleResources`，故不能走 `redownload`（那条按 id 查册，对内置恒 NOT_FOUND）。
   * 只换 `<userData>/rules/` 里的文件，不重启内核 —— 生效要等下次起核。
   */
  updateBuiltin(tag: string): Promise<RuleResourceDownloadResult> {
    return invoke(IPC_CHANNELS.RULE_RESOURCES_UPDATE_BUILTIN, { tag });
  },
  /** 图标库拉取（经后端统一会话）。全失败返 []，UI 回落手动输入图标 URL。 */
  fetchIconGalleries(): Promise<Array<{ name: string; url: string }>> {
    return invoke(IPC_CHANNELS.RULE_RESOURCES_ICON_GALLERIES);
  },
  /**
   * 强制刷新图标库：后端把清单内存缓存（1h TTL）与图标本体的磁盘浏览缓存
   * （`<userData>/icons/remote/`）**两层一起**作废后重拉，返回新清单。返回契约同
   * `fetchIconGalleries`（全失败返 []）。不碰「设定即缓存」的正式副本 —— 那是用户已选定的图标。
   */
  refreshIconGalleries(): Promise<Array<{ name: string; url: string }>> {
    return invoke(IPC_CHANNELS.RULE_RESOURCES_REFRESH_ICON_GALLERIES);
  },
  onProgress(listener: (p: RuleResourceProgress) => void): () => void {
    return listen(IPC_CHANNELS.EVENT_RULE_RESOURCE_PROGRESS, listener);
  },
};

// ============================================================================
// iconApi —— 自定义应用图标本地缓存（设定即下载，渲染零出站）
// ============================================================================

export const iconApi = {
  /**
   * 下载并缓存自定义应用图标，返回本地缓存 ref（`polaris-icon://c/<file>`）。
   * 只在用户「设定/更换图标」这一刻联网下载一次；成功后写进 preset.iconUrl，正常渲染永不触网。
   * 失败 throw（体积超限 / 非图片 / 网络错），调用方 catch 后回落存 remote URL（旧行为）。
   */
  cacheAppIcon(appId: string, remoteUrl: string): Promise<string> {
    return invoke(IPC_CHANNELS.CACHE_APP_ICON, { appId, remoteUrl });
  },
};
