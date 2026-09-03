/**
 * DNS 一等策略工作区的资源面。
 *
 * 与规则列表同属 `DNS` 页面，但继续复用设置页已经验证过的 `useConfig().update` 漏斗：
 * DNS Server / Group / 未命中默认动作仍只有一条暂存、写盘、失败回滚路径，不在规则页另造保存协议。
 */

import { useTranslation } from 'react-i18next';
import type {
  DnsPolicyAction,
  DnsServerGroup,
  DnsServerResource,
  UserConfig,
} from '@/contracts/types';
import { toast } from '@/lib/error-handler';
import { useConfirmTwice } from '@/lib/confirm-twice';
import { Csel } from '@/components/dialogs/Csel';
import { useDialogStore } from '@/components/dialogs/dialog-store';
import { isProtectedDnsServer } from '@/components/dialogs/DnsResourceDialog';
import {
  buildDnsActionGroups,
  dnsActionChoice,
  dnsActionFromChoice,
  dnsServerDescription,
  dnsServerDisplayName,
} from '@/components/dialogs/dns-action-options';
import { useConfig } from '../settings/use-config';
import SettingsDns from '../settings/SettingsDns';
import { Spinner, Switch } from '../settings/Primitives';

export type DnsWorkspaceView = 'rules' | 'servers' | 'groups' | 'system';

export interface DnsResourceReference {
  scope: 'policy' | 'group' | 'server' | 'defaults';
  name: string;
}

function actionReferencesServer(action: DnsPolicyAction | undefined, serverId: string): boolean {
  if (!action) return false;
  if (action.type === 'server') return action.serverId === serverId;
  if (action.type !== 'hostsFirst') return false;
  if (action.hostsServerId === serverId) return true;
  return actionReferencesServer(action.fallback, serverId);
}

function actionReferencesGroup(action: DnsPolicyAction | undefined, groupId: string): boolean {
  if (!action) return false;
  if (action.type === 'group') return action.groupId === groupId;
  return action.type === 'hostsFirst' && actionReferencesGroup(action.fallback, groupId);
}

function uniqueReferences(references: DnsResourceReference[]): DnsResourceReference[] {
  const seen = new Set<string>();
  return references.filter((reference) => {
    const key = `${reference.scope}:${reference.name}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** 删除 DNS Server 前的完整引用图；停用规则同样计入。 */
export function dnsServerReferences(config: UserConfig, serverId: string): DnsResourceReference[] {
  const references: DnsResourceReference[] = [];
  for (const rule of config.dnsRules ?? []) {
    if (actionReferencesServer(rule.effects?.dns?.action, serverId)) {
      references.push({ scope: 'policy', name: rule.remarks?.trim() || rule.id });
    }
  }
  for (const group of config.dnsServerGroups ?? []) {
    if (group.members.includes(serverId) || group.fallbackServerId === serverId) {
      references.push({ scope: 'group', name: group.name.trim() || group.id });
    }
  }
  for (const server of config.dnsServers ?? []) {
    if (server.id !== serverId && server.bootstrapServerId === serverId) {
      references.push({ scope: 'server', name: server.name.trim() || server.id });
    }
  }
  const defaults = config.dnsDefaults;
  if (defaults?.directServerId === serverId) references.push({ scope: 'defaults', name: 'direct' });
  if (defaults?.proxyServerId === serverId) references.push({ scope: 'defaults', name: 'proxy' });
  if (actionReferencesServer(defaults?.unmatchedAction, serverId)) {
    references.push({ scope: 'defaults', name: 'unmatched' });
  }
  return uniqueReferences(references);
}

/** 删除 DNS Group 前的完整引用图。 */
export function dnsGroupReferences(config: UserConfig, groupId: string): DnsResourceReference[] {
  const references: DnsResourceReference[] = [];
  for (const rule of config.dnsRules ?? []) {
    if (actionReferencesGroup(rule.effects?.dns?.action, groupId)) {
      references.push({ scope: 'policy', name: rule.remarks?.trim() || rule.id });
    }
  }
  if (actionReferencesGroup(config.dnsDefaults?.unmatchedAction, groupId)) {
    references.push({ scope: 'defaults', name: 'unmatched' });
  }
  return uniqueReferences(references);
}

function viewError(t: (key: string) => string) {
  return <div className="stub"><p>{t('common.configLoadFail')}</p></div>;
}

export function DnsPolicyWorkspace({ view }: { view: DnsWorkspaceView }) {
  const { t } = useTranslation();
  const { config, loading, error, update } = useConfig();
  const { armed, confirmTwice } = useConfirmTwice();
  const openDialog = useDialogStore((state) => state.open);

  const dnsServers = config?.dnsServers ?? [];
  const dnsGroups = config?.dnsServerGroups ?? [];

  if (loading) return <div className="dns-workspace-loading"><Spinner /></div>;
  if (error || !config) return viewError(t);
  const loadedConfig = config;

  const dnsConfig = config.dnsConfig ?? {
    domesticDns: 'https://223.5.5.5/dns-query',
    foreignDns: 'https://1.1.1.1/dns-query',
    enableFakeIp: true,
  };
  const dnsDefaults = config.dnsDefaults ?? {
    directServerId: 'builtin-domestic',
    proxyServerId: 'builtin-remote',
    unmatchedAction: dnsConfig.enableFakeIp === false
      ? ({ type: 'server', serverId: 'builtin-domestic' } as DnsPolicyAction)
      : ({ type: 'fakeIp' } as DnsPolicyAction),
  };

  function dnsServerName(server: DnsServerResource): string {
    return dnsServerDisplayName(server, t);
  }

  function patchDnsServer(id: string, patch: Partial<DnsServerResource>) {
    void update({
      dnsServers: dnsServers.map((server) => (server.id === id ? { ...server, ...patch } : server)),
    });
  }

  function formatResourceReference(reference: DnsResourceReference): string {
    if (reference.scope === 'policy') return t('settings.dns.resourceRefPolicy', { name: reference.name });
    if (reference.scope === 'group') return t('settings.dns.resourceRefGroup', { name: reference.name });
    if (reference.scope === 'server') return t('settings.dns.resourceRefServer', { name: reference.name });
    const name = reference.name === 'direct'
      ? t('settings.dns.defaultDirect')
      : reference.name === 'proxy'
        ? t('settings.dns.defaultProxy')
        : t('settings.dns.defaultUnmatched');
    return t('settings.dns.resourceRefDefault', { name });
  }

  function rejectReferencedDelete(references: DnsResourceReference[]): boolean {
    if (references.length === 0) return false;
    toast.error(
      t('settings.dns.resourceInUse'),
      t('settings.dns.resourceInUseDesc', {
        refs: references.map(formatResourceReference).join(t('common.listSeparator')),
      }),
    );
    return true;
  }

  function requestDeleteDnsServer(id: string) {
    if (isProtectedDnsServer(id)) return;
    if (rejectReferencedDelete(dnsServerReferences(loadedConfig, id))) return;
    confirmTwice(`dns-server:${id}`, () => {
      void update({ dnsServers: dnsServers.filter((server) => server.id !== id) });
    });
  }

  function patchDnsGroup(id: string, patch: Partial<DnsServerGroup>) {
    void update({
      dnsServerGroups: dnsGroups.map((group) => (group.id === id ? { ...group, ...patch } : group)),
    });
  }

  function requestDeleteDnsGroup(id: string) {
    if (rejectReferencedDelete(dnsGroupReferences(loadedConfig, id))) return;
    confirmTwice(`dns-group:${id}`, () => {
      void update({ dnsServerGroups: dnsGroups.filter((group) => group.id !== id) });
    });
  }

  const defaultActionValue = dnsActionChoice(dnsDefaults.unmatchedAction) ?? 'fakeIp';
  const defaultActionGroups = buildDnsActionGroups({
    servers: dnsServers,
    groups: dnsGroups,
    nodes: config.servers ?? [],
    t,
    currentValue: defaultActionValue,
    // 未命中默认没有预定义记录编辑器，因此不暴露一个只能选、不能完整配置的半能力。
    responses: ['fakeIp', 'reject'],
  });

  const defaultFallbackValue = dnsDefaults.unmatchedAction?.type === 'hostsFirst'
    ? dnsActionChoice(dnsDefaults.unmatchedAction.fallback) ?? `server:${dnsDefaults.directServerId || 'builtin-domestic'}`
    : `server:${dnsDefaults.directServerId || 'builtin-domestic'}`;
  const defaultFallbackGroups = buildDnsActionGroups({
    servers: dnsServers,
    groups: dnsGroups,
    nodes: config.servers ?? [],
    t,
    currentValue: defaultFallbackValue,
    includeHosts: false,
    responses: ['fakeIp', 'reject'],
  });

  function commitDefaultAction(unmatchedAction: DnsPolicyAction) {
    void update({
      dnsConfig: {
        ...dnsConfig,
        enableFakeIp: unmatchedAction.type === 'fakeIp',
        fakeIpTunAutoEnable: false,
      },
      dnsDefaults: { ...dnsDefaults, unmatchedAction },
    });
  }

  function setDefaultAction(value: string) {
    commitDefaultAction(dnsActionFromChoice(value, defaultFallbackValue));
  }

  function setDefaultFallback(value: string) {
    if (dnsDefaults.unmatchedAction?.type !== 'hostsFirst') return;
    commitDefaultAction(dnsActionFromChoice(
      `hosts:${dnsDefaults.unmatchedAction.hostsServerId}`,
      value,
    ));
  }

  if (view === 'system') {
    return <SettingsDns config={config} update={update} embedded section="policy" />;
  }

  if (view === 'rules') {
    return (
      <section className="card policy-default-policy" aria-label={t('settings.dns.defaults')}>
        <div className="policy-default-row">
          <div>
            <div className="card-h dns-rule-stage-title">
              <span>{t('settings.dns.defaultUnmatched')}</span>
              <span className="pill region">{t('settings.dns.builtinTag')}</span>
            </div>
          </div>
          <Csel
            value={defaultActionValue}
            onChange={setDefaultAction}
            options={defaultActionGroups}
            ariaLabel={t('settings.dns.defaultUnmatched')}
            className="policy-default-action"
          />
        </div>
        {dnsDefaults.unmatchedAction?.type === 'hostsFirst' && (
          <div className="policy-default-detail">
            <span>{t('rules.dnsHostsFallback')}</span>
            <Csel
              value={defaultFallbackValue}
              onChange={setDefaultFallback}
              options={defaultFallbackGroups}
              ariaLabel={t('rules.dnsHostsFallback')}
              className="policy-default-action"
            />
          </div>
        )}
      </section>
    );
  }

  if (view === 'servers') {
    return (
      <section className="dns-resource-pane">
        <div className="dns-resource-list">
          {dnsServers.map((server) => {
            const builtin = isProtectedDnsServer(server.id);
            const referenceCount = dnsServerReferences(loadedConfig, server.id).length;
            return (
              <article key={server.id} className="card dns-resource-card">
                <div className="dns-resource-summary">
                  <span className="dns-resource-title">{dnsServerName(server)}</span>
                  <span className="dns-resource-meta">
                    {dnsServerDescription(server, config.servers, t)}
                    {' · '}{t('rules.dnsWorkspace.referenceCount', { count: referenceCount })}
                  </span>
                  <span className="dns-resource-actions">
                    <Switch
                      checked={server.enabled}
                      disabled={builtin}
                      tip={builtin ? t('settings.dns.builtinRequired') : undefined}
                      onChange={(enabled) => patchDnsServer(server.id, { enabled })}
                      aria-label={t('settings.dns.serverEnabled')}
                    />
                    <button
                      type="button"
                      className="btn ghost sm"
                      onClick={() => openDialog({ kind: 'dns-server', serverId: server.id })}
                    >
                      {t('common.edit')}
                    </button>
                    {!builtin && (
                      <button
                        type="button"
                        className={armed === `dns-server:${server.id}` ? 'btn ghost sm danger-text confirming' : 'btn ghost sm danger-text'}
                        onClick={() => requestDeleteDnsServer(server.id)}
                      >
                        {t(armed === `dns-server:${server.id}` ? 'common.confirmAgain' : 'common.delete')}
                      </button>
                    )}
                  </span>
                </div>
              </article>
            );
          })}
        </div>
      </section>
    );
  }

  return (
    <section className="dns-resource-pane">
      <div className="dns-resource-list">
        {dnsGroups.length === 0 && <div className="stub"><p>{t('rules.dnsWorkspace.groupsEmpty')}</p></div>}
        {dnsGroups.map((group) => {
          const memberServers = group.members
            .map((id) => dnsServers.find((server) => server.id === id))
            .filter((server): server is DnsServerResource => server != null);
          const outboundKinds = new Set(memberServers.map((server) => (
            server.outbound.type === 'node' ? `node:${server.outbound.nodeId}` : server.outbound.type
          )));
          const referenceCount = dnsGroupReferences(loadedConfig, group.id).length;
          return (
          <article key={group.id} className="card dns-resource-card">
            <div className="dns-resource-summary">
              <span className="dns-resource-title">{group.name}</span>
              <span className="dns-resource-meta">
                {t(group.mode === 'race' ? 'settings.dns.groupRace' : 'settings.dns.groupFallback')}
                {' · '}{t('rules.dnsWorkspace.memberCount', { count: group.members.length })}
                {' · '}{t('rules.dnsWorkspace.referenceCount', { count: referenceCount })}
                {outboundKinds.size > 1 ? ` · ${t('rules.dnsActionMixedOutbound')}` : ''}
              </span>
              <span className="dns-resource-actions">
                <Switch
                  checked={group.enabled}
                  onChange={(enabled) => patchDnsGroup(group.id, { enabled })}
                  aria-label={t('settings.dns.groupEnabled')}
                />
                <button
                  type="button"
                  className="btn ghost sm"
                  onClick={() => openDialog({ kind: 'dns-group', groupId: group.id })}
                >
                  {t('common.edit')}
                </button>
                <button
                  type="button"
                  className={armed === `dns-group:${group.id}` ? 'btn ghost sm danger-text confirming' : 'btn ghost sm danger-text'}
                  onClick={() => requestDeleteDnsGroup(group.id)}
                >
                  {t(armed === `dns-group:${group.id}` ? 'common.confirmAgain' : 'common.delete')}
                </button>
              </span>
            </div>
          </article>
          );
        })}
      </div>
    </section>
  );
}

export default DnsPolicyWorkspace;
