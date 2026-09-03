import { useCallback } from 'react';
import type { TFunction } from 'i18next';
import type { DialogDesc } from '@/components/dialogs/dialog-store';
import type { ServerConfig } from '@/contracts/types';
import { api } from '@/ipc';
import type { ConfirmTwiceCore } from '@/lib/confirm-twice';
import { splitStagedOnly, type StagedEntry } from '@/lib/staged-config';
import { toast } from '@/lib/error-handler';
import { useLatencyStore } from '@/store/use-latency-store';
import {
  fallbackExitAfterDelete,
  partitionNodeDeleteRoutes,
  type NodeDeleteRoutePolicy,
} from './node-delete-fallback';
import { selectedVisibleIds } from './nodes-logic';

/**
 * 批量删除按钮的原地二次确认 key（与单节点删除的 `node-del:<id>` 区分）。
 *
 * **武装侧持有、读取侧 import**：翻红的 `.confirming` 样式与「再点一次」文案由 `NodesBatchBar`
 * 按 `confirmArmed === BATCH_DEL_KEY` 渲染，而武装是这里做的。两侧各写一份字面量时，任一侧改动
 * 都不会有任何东西转红（`prototype-confirm-parity` 只登记武装侧），症状是删除按钮永远不翻红 ——
 * 破坏性操作的视觉确认信号静默消失，而两击删除照常执行。
 */
export const BATCH_DEL_KEY = 'batch-del';

interface Args {
  diskServers: ServerConfig[];
  selectedServerId: string | null | undefined;
  stagedDeleted: ReadonlySet<string>;
  stagedOnly: ReadonlySet<string>;
  stagedEntries: readonly StagedEntry[];
  nodeDeletePolicy: NodeDeleteRoutePolicy;
  revertStaged: (id: string) => void;
  stageServerDeletions: (
    targets: readonly ServerConfig[],
    removedIds: ReadonlySet<string>,
    groupId?: string
  ) => void;
  selectedIds: ReadonlySet<string>;
  /** 当前 tab / 搜索 / 协议筛选之后真正在列表里的那批节点 —— 批删的射程上界，见 `selectedVisibleIds`。 */
  visibleServers: readonly ServerConfig[];
  exitBatch: () => void;
  confirmTwice: ConfirmTwiceCore['confirmTwice'];
  t: TFunction;
  openDialog: (dialog: DialogDesc) => void;
  closeDialog: () => void;
}

interface WarpRemovalOptions {
  title: string;
  message: string;
  okToast: string;
  afterDelete?: () => void;
}

export function useNodeDeletion({
  diskServers,
  selectedServerId,
  stagedDeleted,
  stagedOnly,
  stagedEntries,
  nodeDeletePolicy,
  revertStaged,
  stageServerDeletions,
  selectedIds,
  visibleServers,
  exitBatch,
  confirmTwice,
  t,
  openDialog,
  closeDialog,
}: Args) {
  const deleteNode = useCallback(
    (server: ServerConfig) => {
      confirmTwice(`node-del:${server.id}`, () => {
        const split = splitStagedOnly(
          'server.delete',
          [server.id],
          stagedOnly,
          stagedEntries,
          'servers'
        );
        if (split.backend.length === 0) {
          split.revertEntryIds.forEach(revertStaged);
          toast.info(t('nodes.deleteSuccess'));
          return;
        }

        const routes = partitionNodeDeleteRoutes(
          diskServers,
          split.backend,
          nodeDeletePolicy
        );
        if (routes.staged.length > 0) {
          split.revertEntryIds.forEach(revertStaged);
          stageServerDeletions(routes.staged, new Set([server.id]));
          toast.info(t('nodes.deleteSuccess'));
          return;
        }

        const id = routes.directIds[0];
        if (!id) return;
        const removedIds = new Set([...stagedDeleted, server.id]);
        const fallback = fallbackExitAfterDelete(
          diskServers,
          selectedServerId,
          removedIds,
          useLatencyStore.getState().latencyMap
        );
        void api.server
          .delete(id, fallback)
          .then(() => toast.info(t('nodes.deleteSuccess')))
          .catch((err) => {
            console.error('[NodesScreen] delete:', err);
            toast.error(t('nodes.deleteFail'));
          });
      });
    },
    [
      confirmTwice,
      diskServers,
      nodeDeletePolicy,
      revertStaged,
      selectedServerId,
      stagedDeleted,
      stagedEntries,
      stagedOnly,
      stageServerDeletions,
      t,
    ]
  );

  const removeWarpNode = useCallback(
    (node: ServerConfig, opts: WarpRemovalOptions) => {
      openDialog({
        kind: 'confirm',
        payload: {
          title: opts.title,
          message: opts.message,
          confirmLabel: t('common.confirm'),
          danger: true,
          onConfirm: () => {
            closeDialog();
            const split = splitStagedOnly(
              'server.delete',
              [node.id],
              stagedOnly,
              stagedEntries,
              'servers'
            );
            split.revertEntryIds.forEach(revertStaged);
            if (split.backend.length === 0) {
              toast.info(opts.okToast);
              opts.afterDelete?.();
              return;
            }

            const routes = partitionNodeDeleteRoutes(
              diskServers,
              split.backend,
              nodeDeletePolicy
            );
            if (routes.staged.length > 0) {
              stageServerDeletions(routes.staged, new Set([node.id]));
              toast.info(t('nodes.deleteSuccess'));
              return;
            }

            const id = routes.directIds[0];
            if (!id) return;
            const removedIds = new Set([...stagedDeleted, node.id]);
            const fallback = fallbackExitAfterDelete(
              diskServers,
              selectedServerId,
              removedIds,
              useLatencyStore.getState().latencyMap
            );
            void api.server
              .delete(id, fallback)
              .then(() => {
                toast.info(opts.okToast);
                opts.afterDelete?.();
              })
              .catch((err) => {
                console.error('[NodesScreen] warp remove failed:', err);
                toast.error(t('nodes.deleteFail'));
              });
          },
        },
      });
    },
    [
      closeDialog,
      diskServers,
      nodeDeletePolicy,
      openDialog,
      revertStaged,
      selectedServerId,
      stagedDeleted,
      stagedEntries,
      stagedOnly,
      stageServerDeletions,
      t,
    ]
  );

  const deleteBatch = useCallback(() => {
    /* 目标集**先与可见集求交**：勾选集不随 tab 切换 / 筛选收窄而收缩，直接消费它会删掉用户此刻
       看不见的节点（判据全文见 `selectedVisibleIds`）。求交后为空 = 没有任何一个勾中项在当前
       视野里，此时连确认都不该武装（武装了也只会执行一次空删）。 */
    const ids = new Set(selectedVisibleIds(visibleServers, selectedIds));
    if (ids.size === 0) return;
    confirmTwice(BATCH_DEL_KEY, () => {
      void (async () => {
        const split = splitStagedOnly(
          'server.deleteBatch',
          [...ids],
          stagedOnly,
          stagedEntries,
          'servers'
        );
        const routes = partitionNodeDeleteRoutes(
          diskServers,
          split.backend,
          nodeDeletePolicy
        );
        try {
          if (routes.directIds.length > 0) {
            const removedIds = new Set([...stagedDeleted, ...ids]);
            const fallback = fallbackExitAfterDelete(
              diskServers,
              selectedServerId,
              removedIds,
              useLatencyStore.getState().latencyMap
            );
            await api.server.deleteBatch(routes.directIds, fallback);
          }
          split.revertEntryIds.forEach(revertStaged);
          if (routes.staged.length > 0) {
            const groupId =
              routes.staged.length > 1
                ? `serverDeleteBatch:${crypto.randomUUID()}`
                : undefined;
            stageServerDeletions(routes.staged, ids, groupId);
          }
          exitBatch();
          toast.info(t('nodes.batchDeleteOk', { count: ids.size }));
        } catch (err) {
          console.error('[NodesScreen] batch delete failed:', err);
          toast.error(t('nodes.deleteFail'));
        }
      })();
    });
  }, [
    confirmTwice,
    diskServers,
    exitBatch,
    nodeDeletePolicy,
    revertStaged,
    selectedIds,
    selectedServerId,
    stagedDeleted,
    stagedEntries,
    stagedOnly,
    stageServerDeletions,
    t,
    visibleServers,
  ]);

  return { deleteNode, removeWarpNode, deleteBatch };
}
