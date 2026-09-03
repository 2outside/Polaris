import type { TFunction } from 'i18next';
import type { ServerConfig, SubscriptionConfig } from '@/contracts/types';
import type { ServerGroup } from '@/domain/server-grouping';
import type { SubscriptionProgressMap } from '@/store/use-subscription-progress-store';
import type { SubscriptionUpdateProgress } from '@/contracts/subscription-progress';
import type { DialogDesc } from '@/components/dialogs/dialog-store';
import { subscriptionErrorDetail } from '@/domain/subscription-error-text';
import { cn } from '@/lib/utils';
import { subDeleteNodeCount } from './nodes-logic';
import { SubInfoBar } from './SubInfoBar';
import type { useNodeSubscriptionActions } from './use-node-subscription-actions';
import type { SubAutoUpdateConfigLike } from '@/domain/subscription-auto-update';

interface Props {
  t: TFunction;
  groups: ServerGroup[];
  activeTab: string;
  setActiveTab: (id: string) => void;
  subscriptionProgress: SubscriptionProgressMap;
  activeSub: SubscriptionConfig | undefined;
  activeGroup: ServerGroup | undefined;
  config: SubAutoUpdateConfigLike | null | undefined;
  diskServers: ServerConfig[];
  activeSubProgress: SubscriptionUpdateProgress | null;
  openDialog: (dialog: DialogDesc) => void;
  subscriptionActions: ReturnType<typeof useNodeSubscriptionActions>;
}

/** 订阅 tabs（自建 / 组网 / 各订阅）+ 随对应 tab 显隐的 `.nd-subinfo` 订阅信息栏。 */
export function NodesTabs({
  t,
  groups,
  activeTab,
  setActiveTab,
  subscriptionProgress,
  activeSub,
  activeGroup,
  config,
  diskServers,
  activeSubProgress,
  openDialog,
  subscriptionActions,
}: Props) {
  return (
    <>
      <div className="nd-tabs-scroll" id="node-tabs-scroll">
        <div className="sub-tabs" data-tabgroup="">
          {groups.map((g) => {
            const label = g.isManual
              ? t('nodes.tab.manual')
              : g.isMesh
                ? t('nodes.tab.mesh')
                : g.name;
            const progress = subscriptionProgress[g.id];
            const failureDetail =
              progress?.phase === 'failed'
                ? subscriptionErrorDetail(progress, t)
                : null;
            return (
              <button
                key={g.id}
                type="button"
                className={cn(activeTab === g.id && 'on')}
                data-act="sub-tab"
                data-v={g.id}
                data-tip={failureDetail ?? undefined}
                onClick={() => setActiveTab(g.id)}
              >
                <span>{label}</span>
                {failureDetail && (
                  <span className="pill err sub-tab-failure">{t('nodes.subUpdateFailed')}</span>
                )}
                {g.servers.length > 0 && <span className="cnt">{g.servers.length}</span>}
              </button>
            );
          })}
        </div>
      </div>

      {activeSub && (
        <div className="nd-subinfo">
          <SubInfoBar
            subscription={activeSub}
            nodeCount={activeGroup?.servers.length ?? 0}
            config={config ?? undefined}
            deleteNodeCount={subDeleteNodeCount(diskServers, activeSub)}
            progress={activeSubProgress}
            onEdit={(sub) => openDialog({ kind: 'sub', subId: sub.id })}
            onRefresh={(sub) => void subscriptionActions.refreshSub(sub)}
            onDelete={subscriptionActions.requestSubDelete}
            onMenuAction={subscriptionActions.onSubMenuAction}
          />
        </div>
      )}
    </>
  );
}
