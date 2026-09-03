/** sing-box 内核更新卡的呈现 owner；运行状态和订阅均由 useCoreUpdate 集中管理。 */
import { useTranslation } from 'react-i18next';
import type { UserConfig } from '@/contracts/types';
import { cn } from '@/lib/utils';
import {
  Button,
  Card,
  CardH,
  CardSub,
  Dot,
  Pill,
  Select,
  SetRow,
  SetRowSection,
  Spinner,
  Switch,
} from './Primitives';
import CoreVersionBanner from './CoreVersionBanner';
import { CORE_ROLLBACK_KEY, useCoreUpdate } from './use-core-update';

export interface CoreUpdateCardProps {
  config: UserConfig;
  update: (patch: Partial<UserConfig>) => Promise<void>;
}

export default function CoreUpdateCard({ config, update }: CoreUpdateCardProps) {
  const { t } = useTranslation();
  const coreChannel = config.coreUpdateChannel === 'prerelease' ? 'prerelease' : 'stable';
  const {
    armed,
    coreVer,
    staged,
    coreBusy,
    coreMsg,
    onlineState,
    latest,
    onlineMessage,
    onlineError,
    coreForkBlocked,
    applyStaged,
    replaceManual,
    rollback,
    resetFactory,
    checkCoreUpdate,
    runCoreUpdate,
  } = useCoreUpdate();

  return (
    <>
      <CoreVersionBanner />
      <Card className="core-card">
        <CardH tip={`${t('settings.update.coreCardSub')} ${t('settings.update.coreCardSub2')}`}>
          {t('settings.update.coreCard')}
        </CardH>

        {coreVer && (
          <div className="core-ver" style={{ marginTop: 12 }}>
            <Dot variant="ok" />
            <div style={{ flex: 1 }}>
              <b>{t('settings.update.coreCurrent')}</b> <span className="cv-tag">{coreVer.current}</span>
              <CardSub>
                {coreVer.build === 'fork'
                  ? t('settings.core.forkBlocked')
                  : coreVer.build === 'unknown'
                    ? t('settings.coreManagement.srcNoteUnknown')
                    : t('settings.coreManagement.srcNoteOfficial')}
              </CardSub>
            </div>
            <Pill
              variant={
                coreVer.build === 'official' ? 'ok' : coreVer.build === 'fork' ? 'warn' : 'default'
              }
            >
              {coreVer.build === 'official'
                ? t('settings.coreManagement.sourceOfficial')
                : coreVer.build === 'fork'
                  ? t('settings.coreManagement.sourceFork')
                  : t('settings.coreManagement.sourceUnknown')}
            </Pill>
          </div>
        )}

        {staged && (
          <div className="core-ver" style={{ marginTop: 8 }}>
            <Dot variant="idle" />
            <div style={{ flex: 1 }}>
              <b>{t('settings.update.coreStaged')}</b> <span className="cv-tag">{staged.version}</span>
              <CardSub>{t('settings.update.coreStagedDesc')}</CardSub>
            </div>
            <Button
              variant="flow"
              size="sm"
              disabled={coreBusy}
              onClick={() => void applyStaged()}
            >
              <span>{t('settings.coreManagement.applyNow')}</span>
            </Button>
          </div>
        )}

        {onlineState === 'idle' && (
          <div className="core-ver" style={{ marginTop: 12 }}>
            <Dot variant="idle" />
            <div style={{ flex: 1 }}>
              <b>{t('settings.coreManagement.checkCoreUpdate')}</b>
              <CardSub>
                {coreChannel === 'prerelease'
                  ? t('settings.coreManagement.channelPrereleaseNote')
                  : t('settings.coreManagement.channelStableNote')}
              </CardSub>
            </div>
            <Button
              variant="ghost"
              size="sm"
              disabled={coreForkBlocked || coreBusy}
              data-tip={coreForkBlocked ? t('settings.core.forkBlocked') : undefined}
              onClick={() => void checkCoreUpdate()}
            >
              <span>{t('settings.coreManagement.checkCoreUpdate')}</span>
            </Button>
          </div>
        )}

        {onlineState === 'checking' && (
          <div className="core-ver" style={{ marginTop: 12 }}>
            <Spinner />
            <div style={{ flex: 1 }}>
              <b>{t('settings.coreManagement.checkingCore')}</b>
            </div>
          </div>
        )}

        {onlineState === 'available' && latest && (
          <div className="core-ver" style={{ marginTop: 12 }}>
            <Dot
              variant="flow"
              style={{
                background: 'hsl(var(--flow))',
                boxShadow: '0 0 0 3px hsl(var(--flow)/0.18)',
              }}
            />
            <div style={{ flex: 1 }}>
              <b>{t('settings.coreManagement.foundCore')}</b>{' '}
              <span className="cv-tag">{latest.version}</span>
              {latest.crossBand && <CardSub>{t('settings.coreManagement.crossBandRisk')}</CardSub>}
            </div>
            <Button variant="flow" size="sm" disabled={coreBusy} onClick={() => void runCoreUpdate()}>
              <span>{t('settings.coreManagement.updateNow')}</span>
            </Button>
          </div>
        )}

        {onlineState === 'updating' && (
          <div className="core-ver" style={{ marginTop: 12 }}>
            <Spinner />
            <div style={{ flex: 1 }}>
              <b>{t('settings.core.swapping')}</b>
            </div>
          </div>
        )}

        {onlineMessage && <CardSub style={{ marginTop: 8 }}>{onlineMessage}</CardSub>}
        {onlineError && <CardSub style={{ marginTop: 8, color: 'hsl(var(--err))' }}>{onlineError}</CardSub>}

        <div style={{ display: 'flex', alignItems: 'center', gap: 9, marginTop: 12, flexWrap: 'wrap' }}>
          <Button
            variant="ghost"
            size="sm"
            disabled={coreBusy}
            onClick={() => void replaceManual()}
          >
            <span>{t('settings.coreManagement.manualSwap')}</span>
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className={cn(armed === CORE_ROLLBACK_KEY && 'confirming')}
            disabled={coreBusy || !coreVer?.hasBackup}
            data-tip={coreVer?.hasBackup ? undefined : t('settings.core.noBackup')}
            onClick={rollback}
          >
            <span>
              {armed === CORE_ROLLBACK_KEY
                ? t('settings.core.rollbackConfirm')
                : t('settings.coreManagement.rollback')}
            </span>
          </Button>
          <Button
            variant="ghost"
            size="sm"
            disabled={coreBusy}
            onClick={resetFactory}
          >
            <span>{t('settings.coreManagement.resetFactory')}</span>
          </Button>
        </div>
        {coreMsg && <CardSub style={{ marginTop: 10 }}>{coreMsg}</CardSub>}

        <SetRowSection>
          <SetRow
            label={t('settings.coreManagement.autoUpdate')}
            tip={t('settings.coreManagement.autoUpdateNoSchedulerHint')}
          >
            <Switch
              id="auto-core-swt"
              checked={!!config.autoUpdateCore}
              disabled={coreForkBlocked}
              tip={coreForkBlocked ? t('settings.core.forkBlocked') : undefined}
              onChange={(value) => void update({ autoUpdateCore: value })}
              aria-label={t('settings.coreManagement.autoUpdate')}
            />
          </SetRow>
          <SetRow label={t('settings.coreManagement.channel')} tip={t('settings.coreManagement.channelDesc')}>
            <Select
              style={{ width: 132 }}
              value={coreChannel}
              disabled={coreForkBlocked}
              onChange={(event) =>
                void update({ coreUpdateChannel: event.target.value as 'stable' | 'prerelease' })
              }
              aria-label={t('settings.coreManagement.channel')}
            >
              <option value="stable">{t('settings.coreManagement.channelStable')}</option>
              <option value="prerelease">{t('settings.coreManagement.channelPrerelease')}</option>
            </Select>
          </SetRow>
          <SetRow label={t('settings.update.restrictMinor')} tip={t('settings.update.restrictMinorDesc')}>
            <Switch
              checked={config.restrictCoreUpdateToCompatibleMinor !== false}
              onChange={(value) => void update({ restrictCoreUpdateToCompatibleMinor: value })}
            />
          </SetRow>
        </SetRowSection>
      </Card>
    </>
  );
}
