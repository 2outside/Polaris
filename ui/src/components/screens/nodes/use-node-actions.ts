import { useCallback } from 'react';
import type { TFunction } from 'i18next';
import type { ServerConfig } from '@/contracts/types';
import type { DialogDesc } from '@/components/dialogs/dialog-store';
import { api } from '@/ipc';
import { toast } from '@/lib/error-handler';
import { editRoute } from '@/lib/staged-config';
import type { StagedEntry } from '@/lib/staged-config';
import { meshSingletonConflict } from '@/domain/endpoint-routes';
import { editDialogFor } from './node-edit-routing';

interface Args {
  servers: ServerConfig[];
  t: TFunction;
  stagingEnabled: boolean;
  stage: (entry: StagedEntry) => void;
  openDialog: (dialog: DialogDesc) => void;
  selectedIds: ReadonlySet<string>;
  setSelectedIds: React.Dispatch<React.SetStateAction<Set<string>>>;
  visibleServers: readonly ServerConfig[];
}

/** 节点卡/批选条的单节点与批量动作：复制链接、克隆、编辑、勾选、全选、批量复制链接。 */
export function useNodeActions({
  servers,
  t,
  stagingEnabled,
  stage,
  openDialog,
  selectedIds,
  setSelectedIds,
  visibleServers,
}: Args) {
  // 后端对 WireGuard/Tailscale/SSH/Custom 明确返错（无标准分享链接形态，见 commands/server.rs），
  // 原先只 console.error → 用户点了毫无反应，与「按钮失灵」无法区分。
  const copyLink = useCallback(
    async (server: ServerConfig) => {
      let url: string;
      try {
        url = await api.server.generateUrl(server);
      } catch (err) {
        console.error('[NodesScreen] generate share url failed:', err);
        toast.error(t('nodes.copyLinkUnsupported'));
        return;
      }
      // 剪贴板失败与「协议无分享链接」是两回事：原先同一个 catch 兜住两者，把「链接生成好了但没写进剪贴板」
      // 谎报成「该协议不支持分享」——用户据此以为协议不支持，实际重试即可。批量版 copyLinksBatch 本就分段，此处对齐。
      try {
        await navigator.clipboard.writeText(url);
        toast.success(t('nodes.copyLinkOk'));
      } catch (err) {
        console.error('[NodesScreen] copy link to clipboard failed:', err);
        toast.error(t('nodes.copyLinksFailed'));
      }
    },
    [t]
  );

  /** 克隆：剥离 id（新建）+ subscriptionId/providerName（克隆体归自建，不随订阅刷新被当差集删除）。 */
  const cloneServer = useCallback(
    async (server: ServerConfig) => {
      // 契约「TS 单例硬限 + WARP 单例硬闸门拦第二个（手输/导入/克隆全经 saveServer）」「TS/WARP 克隆恒撞单例被拦」：
      // 克隆是绕开表单直调 server:add 的一条造节点路径，后端 server_add 无守卫 → 不在此拦就能造出第二实例
      // （TS 多实例互相顶掉 tailnet 地址；WARP 抢内核 utun 致 Connect: resource busy）。
      // 判定走 `meshSingletonConflict`（与三个弹窗同一真值）；文案留克隆专属（「无法克隆出第二个」比
      // 通用的「请先注销现有 WARP」更贴当前动作）。不传 editingId：克隆语义恒为「再加一个」，
      // 源节点自身即占槽 → 必然被拦，与契约一致。
      const slot = meshSingletonConflict(server, servers);
      if (slot) {
        toast.error(
          slot === 'warp'
            ? t('nodes.cloneWarpSingleton')
            : t('nodes.cloneTsSingleton')
        );
        return;
      }
      const { id, subscriptionId, providerName, ...rest } = server;
      const cloneName = t('nodes.cloneName', { name: server.name });
      try {
        // 配置暂存闸门（与 NodeDialog 同形）。克隆 = 造一个新 `servers` 元素，无任何副作用 ⇒ 默认腿。
        // 删除不再按节点类型分流：TS state / WARP 注销也由 Apply 的持久删除事务延迟执行。
        if (editRoute('servers', stagingEnabled) === 'staged') {
          const entityId = crypto.randomUUID();
          stage({
            id: `server:${entityId}`,
            kind: 'server',
            label: `${t('node.addTitle')} ${cloneName}`,
            entityPath: ['servers', entityId],
            nextValue: { ...rest, id: entityId, name: cloneName },
          });
        } else {
          await api.server.add({ ...rest, name: cloneName });
        }
        // 原型 :4514 克隆成功即 notify('已克隆节点','ok')。副本落在**自建**分组（上方剥了 subscriptionId），
        // 当前若停在订阅 tab，新卡不在本 tab 可见 → 无 toast 时点了完全没反应，比原型更需要这条反馈。
        toast.success(t('nodes.cloneSuccess'));
      } catch (err) {
        console.error('[NodesScreen] clone failed:', err);
        toast.error(t('nodes.cloneFail'));
      }
    },
    [servers, t, stagingEnabled, stage]
  );

  /* 卡上「编辑」。此前是调用点的内联箭头 —— 那一个箭头就足以让**每张**卡的 `memo` 恒失效
     （props 浅比较里恒有一个新函数引用），memo 反而只剩比较开销。卡片的其余回调
     （测速/复制/克隆/设为出口/删除/勾选）本来就都是 useCallback，只差这一个。 */
  const editNode = useCallback(
    (server: ServerConfig) => openDialog(editDialogFor(server)),
    [openDialog]
  );

  const toggleSelect = useCallback((server: ServerConfig) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(server.id)) next.delete(server.id);
      else next.add(server.id);
      return next;
    });
  }, [setSelectedIds]);

  const selectAll = useCallback(() => {
    const allSelected =
      selectedIds.size === visibleServers.length && visibleServers.length > 0;
    setSelectedIds(allSelected ? new Set() : new Set(visibleServers.map((s) => s.id)));
  }, [visibleServers, selectedIds.size, setSelectedIds]
  );

  // allSettled 而非 all：批选里混进一个无分享链接形态的协议（WG/TS/SSH/Custom），all 会整体 reject
  // → 本可成功的链接一条都进不了剪贴板。改为能复制的照常复制，跳过的如实报数。
  const copyLinksBatch = useCallback(async () => {
    if (selectedIds.size === 0) return;
    const targets = visibleServers.filter((s) => selectedIds.has(s.id));
    const settled = await Promise.allSettled(targets.map((s) => api.server.generateUrl(s)));
    const urls = settled
      .filter((r): r is PromiseFulfilledResult<string> => r.status === 'fulfilled')
      .map((r) => r.value);
    const skipped = settled.length - urls.length;
    if (urls.length === 0) {
      toast.error(t('nodes.copyLinkUnsupported'));
      return;
    }
    try {
      await navigator.clipboard.writeText(urls.join('\n'));
      toast.success(
        skipped > 0
          ? t('nodes.copyLinksPartial', { count: urls.length, skipped })
          : t('nodes.copyLinksOk', { count: urls.length })
      );
    } catch (err) {
      console.error('[NodesScreen] batch copy links failed:', err);
      toast.error(t('nodes.copyLinksFailed'));
    }
  }, [visibleServers, selectedIds, t]);

  return { copyLink, cloneServer, editNode, toggleSelect, selectAll, copyLinksBatch };
}
