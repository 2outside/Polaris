import type { TFunction } from 'i18next';
import type { ServerConfig, SubscriptionConfig, PendingNodeChanges } from '@/contracts/types';
import type { ServerGroup } from '@/domain/server-grouping';
import { isMeshNode, meshAllowsInternet, type SpeedTestCaps } from '@/domain/endpoint-routes';
import { willRestartOnSelect } from '@/components/screens/home/pending-select-hint';
import { speedTestBlockReason } from './nodes-logic';
import { NodeCard } from './NodeCard';
import type { NodeUseVia } from './nodes-logic';

interface Props {
  t: TFunction;
  gridRef: React.RefObject<HTMLDivElement | null>;
  visibleServers: readonly ServerConfig[];
  renderedServers: readonly ServerConfig[];
  search: string;
  protoFilter: string;
  activeSub: SubscriptionConfig | undefined;
  activeGroup: ServerGroup | undefined;
  speedTestCaps: SpeedTestCaps;
  stagedOnly: ReadonlySet<string>;
  shadowedNamed: Map<string, { cidr: string; by: string }[]>;
  selectedServerId: string | null | undefined;
  selectedIds: ReadonlySet<string>;
  batchMode: boolean;
  invalidIndex: Record<string, string>;
  testOne: (server: ServerConfig) => void;
  copyLink: (server: ServerConfig) => void;
  cloneServer: (server: ServerConfig) => void;
  editNode: (server: ServerConfig) => void;
  useNode: (server: ServerConfig, via: NodeUseVia) => void;
  confirmArmed: string | null;
  pendingChanges: PendingNodeChanges;
  deleteNode: (server: ServerConfig) => void;
  toggleSelect: (server: ServerConfig) => void;
  blockedHint: (reason: NonNullable<ReturnType<typeof speedTestBlockReason>>) => string;
}

/** `.node-grid`：空态 / 节点卡列表（渲染窗内的 `renderedServers`，空态判据用全集 `visibleServers`）。 */
export function NodesGrid({
  t,
  gridRef,
  visibleServers,
  renderedServers,
  search,
  protoFilter,
  activeSub,
  activeGroup,
  speedTestCaps,
  stagedOnly,
  shadowedNamed,
  selectedServerId,
  selectedIds,
  batchMode,
  invalidIndex,
  testOne,
  copyLink,
  cloneServer,
  editNode,
  useNode,
  confirmArmed,
  pendingChanges,
  deleteNode,
  toggleSelect,
  blockedHint,
}: Props) {
  return (
    <div className="node-grid" ref={gridRef}>
      {visibleServers.length === 0 ? (
        <div className="stub" style={{ gridColumn: '1 / -1' }}>
          <p>
            {search || protoFilter
              ? t('nodes.emptyFiltered')
              : activeSub
                ? t('nodes.emptySub')
                : activeGroup?.isMesh
                  ? t('nodes.meshEmpty')
                  : t('nodes.empty')}
          </p>
        </div>
      ) : (
        renderedServers.map((server) => {
          const isMesh = activeGroup?.isMesh || isMeshNode(server);
          const lanOnly = isMesh && !meshAllowsInternet(server);
          const blockReason = speedTestBlockReason(server, speedTestCaps, stagedOnly.has(server.id));
          const shadowed = shadowedNamed.get(server.id);
          return (
            <NodeCard
              key={server.id}
              server={server}
              isCurrent={server.id === selectedServerId}
              isExit={isMesh}
              lanOnly={lanOnly}
              speedTestable={blockReason === null}
              speedTestBlockedHint={blockReason ? blockedHint(blockReason) : undefined}
              shadowedCidrs={shadowed}
              selected={selectedIds.has(server.id)}
              batchMode={batchMode}
              invalidReason={invalidIndex[server.id]}
              stagedOnly={stagedOnly.has(server.id)}
              onSpeedTest={testOne}
              onCopy={copyLink}
              onClone={cloneServer}
              onEdit={editNode}
              onUse={useNode}
              useConfirming={confirmArmed === `node-use:${server.id}`}
              useWillRestart={willRestartOnSelect(pendingChanges, server.id)}
              onDelete={deleteNode}
              deletable={!server.subscriptionId}
              deleteConfirming={confirmArmed === `node-del:${server.id}`}
              onToggleSelect={toggleSelect}
            />
          );
        })
      )}
    </div>
  );
}
