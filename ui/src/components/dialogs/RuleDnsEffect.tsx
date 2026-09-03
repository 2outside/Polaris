import { useMemo, useState } from 'react';
import type { TFunction } from 'i18next';
import type {
  DnsServerGroup,
  DnsServerResource,
  RuleDnsAnswerMode,
  RuleDnsEffect,
  RuleDnsResolver,
  ServerConfig,
  UserConfig,
} from '@/contracts/types';
import { buildDnsActionGroups, dnsActionChoice } from './dns-action-options';
import { Csel } from './Csel';

export function splitDnsRecordLines(raw: string): string[] {
  return raw.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
}

/**
 * DNS 效果的状态 —— resolver / answerMode / action（+ hosts 兜底 / predefined 三段）+ 目标下拉候选。
 * 从 `RuleForm` 外提，供状态与其消费的 JSX（`RuleDnsEffectFields`）共用同一份计算。
 */
export function useRuleDnsEffect(
  baseDnsEffect: RuleDnsEffect | null,
  initialPlane: 'route' | 'dns' | undefined,
  dnsServers: DnsServerResource[],
  dnsGroups: DnsServerGroup[],
  servers: ServerConfig[],
  dnsDefaults: UserConfig['dnsDefaults'],
  t: TFunction,
) {
  const [dnsResolver, setDnsResolver] = useState<RuleDnsResolver>(
    () => baseDnsEffect?.resolver ?? 'inherit',
  );
  const [dnsAnswerMode, setDnsAnswerMode] = useState<RuleDnsAnswerMode>(
    () => baseDnsEffect?.answerMode ?? 'real',
  );
  const [dnsAction, setDnsAction] = useState(() =>
    dnsActionChoice(baseDnsEffect?.action) ??
    (baseDnsEffect?.answerMode === 'fakeIp'
      ? 'fakeIp'
      : baseDnsEffect?.resolver === 'proxy'
        ? 'server:builtin-remote'
          : baseDnsEffect?.resolver === 'direct' || initialPlane === 'dns'
          ? 'server:builtin-domestic'
          : 'server:builtin-domestic'),
  );
  const [dnsFallbackAction, setDnsFallbackAction] = useState(() => {
    const fallback = baseDnsEffect?.action?.type === 'hostsFirst'
      ? baseDnsEffect.action.fallback
      : undefined;
    if (fallback?.type === 'server') return `server:${fallback.serverId}`;
    if (fallback?.type === 'group') return `group:${fallback.groupId}`;
    if (fallback?.type === 'fakeIp') return 'fakeIp';
    return `server:${dnsDefaults?.directServerId || 'builtin-domestic'}`;
  });
  const basePredefined = baseDnsEffect?.action?.type === 'predefined'
    ? baseDnsEffect.action
    : undefined;
  const [dnsPredefinedRcode, setDnsPredefinedRcode] = useState(
    () => basePredefined?.rcode ?? 'NOERROR',
  );
  const [dnsPredefinedAnswer, setDnsPredefinedAnswer] = useState(
    () => basePredefined?.answer?.join('\n') ?? '',
  );
  const [dnsPredefinedNs, setDnsPredefinedNs] = useState(
    () => basePredefined?.ns?.join('\n') ?? '',
  );
  const [dnsPredefinedExtra, setDnsPredefinedExtra] = useState(
    () => basePredefined?.extra?.join('\n') ?? '',
  );
  const dnsActionGroups = useMemo(
    () => buildDnsActionGroups({
      servers: dnsServers,
      groups: dnsGroups,
      nodes: servers,
      t,
      currentValue: dnsAction,
    }),
    [dnsServers, dnsGroups, servers, t, dnsAction],
  );
  const dnsFallbackGroups = useMemo(
    () => buildDnsActionGroups({
      servers: dnsServers,
      groups: dnsGroups,
      nodes: servers,
      t,
      currentValue: dnsFallbackAction,
      includeHosts: false,
      responses: ['fakeIp'],
    }),
    [dnsServers, dnsGroups, servers, t, dnsFallbackAction],
  );

  return {
    dnsResolver,
    setDnsResolver,
    dnsAnswerMode,
    setDnsAnswerMode,
    dnsAction,
    setDnsAction,
    dnsFallbackAction,
    setDnsFallbackAction,
    dnsPredefinedRcode,
    setDnsPredefinedRcode,
    dnsPredefinedAnswer,
    setDnsPredefinedAnswer,
    dnsPredefinedNs,
    setDnsPredefinedNs,
    dnsPredefinedExtra,
    setDnsPredefinedExtra,
    dnsActionGroups,
    dnsFallbackGroups,
  };
}

export type UseRuleDnsEffect = ReturnType<typeof useRuleDnsEffect>;

interface RuleDnsEffectFieldsProps extends UseRuleDnsEffect {
  t: TFunction;
  touch: () => void;
}

/** DNS 效果字段（`.fld`：动作下拉 + hosts 兜底 + predefined 三段文本）。 */
export function RuleDnsEffectFields({
  t,
  touch,
  dnsAction,
  setDnsAction,
  setDnsAnswerMode,
  setDnsResolver,
  dnsActionGroups,
  dnsFallbackAction,
  setDnsFallbackAction,
  dnsFallbackGroups,
  dnsPredefinedRcode,
  setDnsPredefinedRcode,
  dnsPredefinedAnswer,
  setDnsPredefinedAnswer,
  dnsPredefinedNs,
  setDnsPredefinedNs,
  dnsPredefinedExtra,
  setDnsPredefinedExtra,
}: RuleDnsEffectFieldsProps) {
  return (
    <div className="fld">
      <div className="fld-l">{t('rules.dnsEffect')}</div>
      <div className="card-sub">{t('rules.dnsEffectHint')}</div>
      <div style={{ display: 'grid', gap: 8, marginTop: 8 }}>
        <Csel
          id="rule-dns-action"
          ariaLabel={t('rules.dnsAction')}
          value={dnsAction}
          onChange={(value) => {
            setDnsAction(value);
            setDnsAnswerMode(value === 'fakeIp' ? 'fakeIp' : 'real');
            setDnsResolver(
              value === 'server:builtin-remote'
                ? 'proxy'
                : 'direct',
            );
            touch();
          }}
          options={dnsActionGroups}
        />
        {dnsAction.startsWith('hosts:') && (
          <Csel
            id="rule-dns-hosts-fallback"
            ariaLabel={t('rules.dnsHostsFallback')}
            value={dnsFallbackAction}
            onChange={(value) => {
              setDnsFallbackAction(value);
              touch();
            }}
            options={dnsFallbackGroups}
          />
        )}
        {dnsAction === 'predefined' && (
          <div style={{ display: 'grid', gap: 8 }}>
            <Csel
              id="rule-dns-predefined-rcode"
              ariaLabel={t('rules.dnsPredefinedRcode')}
              value={dnsPredefinedRcode}
              onChange={(value) => {
                setDnsPredefinedRcode(value);
                touch();
              }}
              options={['NOERROR', 'FORMERR', 'SERVFAIL', 'NXDOMAIN', 'NOTIMP', 'REFUSED'].map(
                (value) => ({ value, label: value }),
              )}
            />
            {[
              ['answer', dnsPredefinedAnswer, setDnsPredefinedAnswer],
              ['ns', dnsPredefinedNs, setDnsPredefinedNs],
              ['extra', dnsPredefinedExtra, setDnsPredefinedExtra],
            ].map(([field, value, setValue]) => (
              <label key={field as string} style={{ display: 'grid', gap: 4 }}>
                <span className="card-sub">
                  {field === 'answer'
                    ? t('rules.dnsPredefinedAnswer')
                    : field === 'ns'
                      ? t('rules.dnsPredefinedNs')
                      : t('rules.dnsPredefinedExtra')}
                </span>
                <textarea
                  className="input mono"
                  rows={2}
                  value={value as string}
                  onChange={(event) => {
                    (setValue as (next: string) => void)(event.currentTarget.value);
                    touch();
                  }}
                  placeholder={t('rules.dnsPredefinedRecordsHint')}
                />
              </label>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
