import type { TFunction } from 'i18next';
import type { ServerConfig } from '@/contracts/types';
import { cn } from '@/lib/utils';
import { canMoveToGroup } from './nodes-logic';
import { BATCH_DEL_KEY, type useNodeDeletion } from './use-node-deletion';

interface Props {
  t: TFunction;
  selectedIds: ReadonlySet<string>;
  visibleServers: readonly ServerConfig[];
  selectAll: () => void;
  testSelected: () => void;
  testing: boolean;
  isSubTab: boolean;
  copyLinksBatch: () => void;
  confirmArmed: string | null;
  nodeDeletion: ReturnType<typeof useNodeDeletion>;
  exitBatch: () => void;
}

/** `.batch-bar`：多选批量操作条（全选 / 测速所选 / 移动到分组（恒禁用）/ 复制链接 / 删除 / 退出批选）。 */
export function NodesBatchBar({
  t,
  selectedIds,
  visibleServers,
  selectAll,
  testSelected,
  testing,
  isSubTab,
  copyLinksBatch,
  confirmArmed,
  nodeDeletion,
  exitBatch,
}: Props) {
  return (
    <div className="batch-bar" id="nodes-batch">
      <button
        type="button"
        id="batch-all"
        className="nd-check on"
        role="checkbox"
        aria-checked={selectedIds.size === visibleServers.length && visibleServers.length > 0}
        onClick={selectAll}
        style={{ position: 'static' }}
        aria-label={t('nodes.selectAll')}
      >
        {selectedIds.size === visibleServers.length && visibleServers.length > 0 && (
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.4}>
            <path d="M5 12l5 5 9-11" />
          </svg>
        )}
      </button>
      <b>
        {t('nodes.selectedPrefix')}
        <span className="mono">{selectedIds.size}</span>
        {t('nodes.selectedSuffix')}
      </b>
      <div className="sp" />
      <button
        type="button"
        id="batch-test"
        className="btn ghost sm"
        onClick={testSelected}
        disabled={testing || selectedIds.size === 0}
      >
        {t('nodes.testGroup')}
      </button>
      {/*
        「移动到分组」恒禁用 —— **诚实置灰，不是待办**。根因不是"后端命令还没写"，而是
        Polaris 数据模型里没有用户可分配的分组：自建/组网/订阅三类归属全是派生的
        （无 subscriptionId / endpoint 协议 / subscriptionId 指向订阅），唯一可写的
        `subscriptionId` 一旦写进某订阅，下次订阅刷新的 reconcile 会把该节点当"已下架"删掉
        （subscription.rs:755 按 subscriptionId 分区整体替换）= 数据丢失。上游 全仓亦无
        move-to-group，原型那项是 notify('已移动') 的纯 mock。
        判定收在 nodes-logic.canMoveToGroup（引入真分组字段即自动解禁）。
        订阅 tab 下整颗不渲染：那里连"理论上想移动"都不成立，多摆一颗恒灰的按钮只是噪声。
      */}
      {!isSubTab && (
        <button
          type="button"
          id="batch-move"
          className="btn ghost sm"
          disabled={!canMoveToGroup()}
          data-tip={t('nodes.batchMoveUnavailable')}
        >
          {t('nodes.batchMove')}
        </button>
      )}
      <button
        type="button"
        className="btn ghost sm"
        onClick={copyLinksBatch}
        disabled={selectedIds.size === 0}
      >
        {t('nodes.batchCopyLinks')}
      </button>
      {/* 订阅 tab 下不渲染：删掉的订阅节点会在下次订阅刷新的 reconcile 里原样拉回来
          ⇒ 操作无净效果、只剩误删风险（陈先生 2026-07-29 裁定，与单卡删除入口同一处置）。 */}
      {!isSubTab && (
        <button
          type="button"
          className={cn('btn ghost sm', confirmArmed === BATCH_DEL_KEY && 'confirming')}
          style={{ color: 'hsl(var(--err))' }}
          onClick={nodeDeletion.deleteBatch}
          disabled={selectedIds.size === 0}
        >
          {confirmArmed === BATCH_DEL_KEY
            ? t('nodes.batchDeleteConfirmAgain')
            : t('common.delete')}
        </button>
      )}
      <button type="button" className="btn ghost sm" onClick={exitBatch}>
        {t('nodes.batchExit')}
      </button>
    </div>
  );
}
