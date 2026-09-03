/**
 * 更新设置页编排。
 *
 * 应用安装包与 sing-box 内核各自有独立的状态机、事件来源与失败面，分别由 AppUpdateCard 和
 * CoreUpdateCard 持有；本页只保留跨域设置项的顺序和配置写入。
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { UserConfig } from '@/contracts/types';
import { GH_PROXY_PRESETS } from '@/domain/gh-proxy';
import {
  Card,
  Phead,
  Pill,
  Segmented,
  Select,
  SetBlock,
  SetRow,
  Switch,
  TextInput,
} from './Primitives';
import AppUpdateCard from './AppUpdateCard';
import CoreUpdateCard from './CoreUpdateCard';
import {
  backgroundIntervalSelectValue,
  ruleResourceAutoStatus,
  ruleResourceAutoUpdateChecked,
  subscriptionAutoUpdateStatus,
} from './settings-logic';

export interface SettingsUpdateProps {
  config: UserConfig;
  update: (patch: Partial<UserConfig>) => Promise<void>;
}

type SubProxyPolicy = 'follow' | 'proxy' | 'direct';

export default function SettingsUpdate({ config, update }: SettingsUpdateProps) {
  const { t } = useTranslation();
  const [ghCustomMode, setGhCustomMode] = useState(false);
  const interval = backgroundIntervalSelectValue(config);
  const ghProxy = ghCustomMode
    ? 'custom'
    : !config.ghProxyPrefix
      ? 'none'
      : (GH_PROXY_PRESETS as readonly string[]).includes(config.ghProxyPrefix)
        ? config.ghProxyPrefix
        : 'custom';
  const subPolicy: SubProxyPolicy = config.subscriptionProxyPolicy ?? 'follow';
  const resAutoStatus = ruleResourceAutoStatus(config);
  const subAutoStatus = subscriptionAutoUpdateStatus(config);

  return (
    <section className="screen" data-sec="update">
      <Phead title={t('settings.nav.update')} sub={t('settings.update.pageSub')} />

      <SetBlock>
        <SetRow label={t('settings.update.intervalCard')} tip={t('settings.update.intervalCardSub')}>
          <Select
            value={interval}
            onChange={(event) =>
              void update({
                subscriptionUpdateIntervalHours: Number(event.target.value),
                ruleResourceUpdateIntervalHours: Number(event.target.value),
              })
            }
            aria-label={t('settings.update.intervalCard')}
            style={{ width: '170px' }}
          >
            <option value="0">{t('settings.update.intervalManualOnly')}</option>
            <option value="6">{t('settings.update.intervalHours', { n: 6 })}</option>
            <option value="12">{t('settings.update.intervalHours', { n: 12 })}</option>
            <option value="24">{t('settings.update.intervalHours', { n: 24 })}</option>
            <option value="72">{t('settings.update.intervalDays', { n: 3 })}</option>
            <option value="168">{t('settings.update.intervalDays', { n: 7 })}</option>
          </Select>
        </SetRow>
      </SetBlock>

      <SetBlock>
        <SetRow
          label={t('resources.ghProxy')}
          tip={`${t('settings.update.ghAccelSub')} ${t('settings.update.ghNote')}`}
        >
          <Select
            id="gh-mirror-sel"
            value={ghProxy}
            onChange={(event) => {
              const value = event.target.value;
              if (value === 'none') {
                setGhCustomMode(false);
                void update({ ghProxyPrefix: '' });
              } else if (value === 'custom') {
                setGhCustomMode(true);
              } else {
                setGhCustomMode(false);
                void update({ ghProxyPrefix: value });
              }
            }}
            aria-label={t('resources.ghProxy')}
            style={{ width: '340px' }}
          >
            <option value="none">{t('resources.direct')}</option>
            {GH_PROXY_PRESETS.map((preset) => (
              <option key={preset} value={preset}>
                {t('settings.update.ghMirrorOption', { url: preset })}
              </option>
            ))}
            <option value="custom">{t('common.customEllipsis')}</option>
          </Select>
        </SetRow>
        {ghProxy === 'custom' && (
          <SetRow label={t('resources.customDomainLabel')}>
            <TextInput
              id="gh-custom-input"
              className="mono"
              value={config.ghProxyPrefix ?? ''}
              onChange={(event) => void update({ ghProxyPrefix: event.target.value })}
              placeholder="https://cdn.example/ · cdn.example"
              style={{ width: '340px' }}
            />
          </SetRow>
        )}
      </SetBlock>

      <AppUpdateCard config={config} update={update} />
      <CoreUpdateCard config={config} update={update} />

      <Card pad style={{ marginBottom: 16 }}>
        <SetRow
          label={t('settings.update.ruleResourceAutoCard')}
          tip={t('settings.update.ruleResourceAutoDesc')}
          ctrlClassName="rule-resource-auto-control"
        >
          {resAutoStatus !== 'off' && (
            <Pill variant={resAutoStatus === 'active' ? 'ok' : 'warn'}>
              {resAutoStatus === 'active'
                ? t('settings.update.ruleResourceAutoStatusOn')
                : t('settings.update.ruleResourceAutoStatusManual')}
            </Pill>
          )}
          <Switch
            id="res-auto-swt"
            checked={ruleResourceAutoUpdateChecked(config)}
            onChange={(value) =>
              void update({
                ruleResourceAutoUpdate: value,
                ruleResourceUpdateIntervalHours: config.subscriptionUpdateIntervalHours,
              })
            }
            aria-label={t('settings.update.ruleResourceAutoCard')}
          />
        </SetRow>
      </Card>

      <SetBlock header={t('settings.update.subBlock')}>
        <SetRow
          label={t('settings.update.subAutoOnStart')}
          tip={`${
            subAutoStatus === 'startup-only'
              ? t('settings.update.subAutoStartupOnly')
              : t('settings.update.subAutoWithInterval')
          } ${t('settings.update.subPerSubNote')}`}
        >
          <Switch
            checked={!!config.autoUpdateSubscriptionOnStart}
            onChange={(value) => void update({ autoUpdateSubscriptionOnStart: value })}
          />
        </SetRow>
        <SetRow label={t('settings.update.subChannel')} tip={t('settings.update.subChannelDesc')}>
          <Segmented<SubProxyPolicy>
            ariaLabel={t('settings.update.subChannel')}
            value={subPolicy}
            onChange={(value) => void update({ subscriptionProxyPolicy: value })}
            options={[
              { value: 'follow', label: t('settings.update.subFollow') },
              { value: 'proxy', label: t('settings.update.subViaProxy') },
              { value: 'direct', label: t('settings.update.subDirect') },
            ]}
          />
        </SetRow>
      </SetBlock>
    </section>
  );
}
