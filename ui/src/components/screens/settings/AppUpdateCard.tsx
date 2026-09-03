/** 应用更新卡的呈现 owner；状态、订阅和异步动作由 useAppUpdate 单点持有。 */
import { useTranslation } from 'react-i18next';
import type { UserConfig } from '@/contracts/types';
import { revealOnToggle } from '@/components/reveal';
import {
  appUpdateIncludePrerelease,
  type AppUpdateChannel,
} from '@/domain/app-update-channel';
import { toast } from '@/lib/error-handler';
import {
  Card,
  CardH,
  CardSub,
  Button,
  Dot,
  Pill,
  Spinner,
  ProgressBar,
  Select,
  SetRow,
  SetRowSection,
  Switch,
} from './Primitives';
import { releaseShipsDigest } from './settings-logic';
import { useAppUpdate } from './use-app-update';

export interface AppUpdateCardProps {
  config: UserConfig;
  update: (patch: Partial<UserConfig>) => Promise<void>;
}

export default function AppUpdateCard({ config, update }: AppUpdateCardProps) {
  const { t } = useTranslation();
  const appUpdateChannel: AppUpdateChannel = config.appUpdateChannel ?? 'stable';
  const includePrerelease = appUpdateIncludePrerelease(config);
  const {
    appVersionInfo,
    us,
    updateInfo,
    progress,
    receivedBytes,
    errMsg,
    downloadIntegrity,
    checkUpdate,
    reinstallCurrent,
    skipVersion,
    downloadUpdate,
    installUpdate,
  } = useAppUpdate(includePrerelease);
  const releaseDigestMissing = !releaseShipsDigest(updateInfo);
  const downloadUnverified = downloadIntegrity === 'unverified';

  return (
    <Card className="core-card" id="app-update-card">
      <CardH>{t('settings.update.appVersionCard')}</CardH>

      {us === 'idle' && (
        <div className="us-state" data-us="idle">
          <div className="core-ver">
            <Dot variant="ok" />
            <div style={{ flex: 1 }}>
              <b>Polaris</b>{' '}
              <span className="cv-tag">
                {appVersionInfo?.appVersion ? `v${appVersionInfo.appVersion}` : '—'}
              </span>
              <CardSub>{t('settings.update.upToDate')}</CardSub>
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <Button
                className="warn-action"
                variant="ghost"
                size="sm"
                data-tip={t('settings.update.reinstallCurrentTip')}
                onClick={reinstallCurrent}
              >
                <span>{t('settings.update.reinstallCurrent')}</span>
              </Button>
              <Button variant="ghost" size="sm" onClick={checkUpdate}>
                <span>{t('settings.about.checkUpdate')}</span>
              </Button>
            </div>
          </div>
        </div>
      )}

      {us === 'checking' && (
        <div className="us-state" data-us="checking">
          <div className="core-ver">
            <Spinner />
            <div style={{ flex: 1 }}>
              <b>{t('settings.about.checkingUpdate')}</b>
            </div>
          </div>
        </div>
      )}

      {us === 'available' && updateInfo && (
        <div className="us-state" data-us="available">
          <div className="core-ver">
            <Dot
              variant="flow"
              style={{
                background: 'hsl(var(--flow))',
                boxShadow: '0 0 0 3px hsl(var(--flow)/0.18)',
              }}
            />
            <div style={{ flex: 1 }}>
              <b>{t('settings.update.foundNew')}</b>{' '}
              <span className="cv-tag">{updateInfo.version}</span>
              {updateInfo.isPrerelease && (
                <>
                  {' '}
                  <Pill variant="warn">{t('settings.update.prereleaseTag')}</Pill>
                </>
              )}
              <CardSub>
                {new Date(updateInfo.publishedAt).toLocaleDateString()} ·{' '}
                {(updateInfo.fileSize / 1024 / 1024).toFixed(1)} MB
              </CardSub>
              {updateInfo.isPrerelease && (
                <CardSub style={{ marginTop: 4, lineHeight: 1.7 }}>
                  {t('settings.update.prereleaseNote')}
                </CardSub>
              )}
              {releaseDigestMissing && (
                <CardSub style={{ marginTop: 4, lineHeight: 1.7 }}>
                  {t('settings.update.digestMissingBefore')}
                </CardSub>
              )}
            </div>
            {releaseDigestMissing && (
              <Pill variant="warn">{t('settings.update.digestMissingTag')}</Pill>
            )}
          </div>
          {updateInfo.releaseNotes && (
            <details className="us-notes" onToggle={revealOnToggle}>
              <summary>{t('settings.update.releaseNotes')}</summary>
              <CardSub style={{ marginTop: 6, lineHeight: 1.7, whiteSpace: 'pre-line' }}>
                {updateInfo.releaseNotes}
              </CardSub>
            </details>
          )}
          <div style={{ display: 'flex', gap: 9, marginTop: 12 }}>
            <Button variant="flow" size="sm" onClick={downloadUpdate}>
              <svg viewBox="0 0 24 24" width="14" fill="none" stroke="currentColor" strokeWidth={1.8}>
                <path d="M12 3v11M8 10l4 4 4-4M4 19h16" />
              </svg>
              <span>{t('settings.update.download')}</span>
            </Button>
            <Button variant="ghost" size="sm" onClick={() => void skipVersion()}>
              <span>{t('settings.update.bannerSkip')}</span>
            </Button>
          </div>
        </div>
      )}

      {us === 'downloading' && (
        <div className="us-state" data-us="downloading">
          <div className="core-ver">
            <Spinner />
            <div style={{ flex: 1 }}>
              <b>{t('settings.update.downloadingApp')}</b>{' '}
              <span className="cv-tag">{updateInfo?.version}</span>
            </div>
            <span className="mono">{progress}%</span>
          </div>
          <ProgressBar value={progress} style={{ marginTop: 10 }} />
          <div className="card-sub mono" style={{ marginTop: 6 }}>
            {((receivedBytes ?? 0) / 1024 / 1024).toFixed(1)} /{' '}
            {((updateInfo?.fileSize ?? 0) / 1024 / 1024).toFixed(1)} MB
          </div>
        </div>
      )}

      {us === 'downloaded' && (
        <div className="us-state" data-us="downloaded">
          <div className="core-ver">
            <Dot variant="ok" />
            <div style={{ flex: 1 }}>
              <b>{t('settings.update.downloadDone')}</b>{' '}
              <span className="cv-tag">{updateInfo?.version}</span>
              {updateInfo?.isPrerelease && (
                <>
                  {' '}
                  <Pill variant="warn">{t('settings.update.prereleaseTag')}</Pill>
                </>
              )}
              <CardSub>{t('settings.update.restartToInstall')}</CardSub>
              {downloadUnverified && (
                <CardSub style={{ marginTop: 4, lineHeight: 1.7 }}>
                  {t('settings.update.digestMissingAfter')}
                </CardSub>
              )}
            </div>
            {downloadUnverified && (
              <Pill variant="warn">{t('settings.update.digestMissingTag')}</Pill>
            )}
            <Button variant="flow" size="sm" onClick={() => void installUpdate()}>
              <span>{t('settings.update.restartAndInstall')}</span>
            </Button>
          </div>
        </div>
      )}

      {us === 'manual' && (
        <div className="us-state" data-us="manual">
          <div className="core-ver">
            <Dot variant="ok" />
            <div style={{ flex: 1 }}>
              <b>{t('settings.update.downloadedManual')}</b>{' '}
              <span className="cv-tag">{updateInfo?.version}</span>
              {updateInfo?.isPrerelease && (
                <>
                  {' '}
                  <Pill variant="warn">{t('settings.update.prereleaseTag')}</Pill>
                </>
              )}
              <CardSub style={{ lineHeight: 1.7, wordBreak: 'break-all' }}>{errMsg}</CardSub>
              {downloadUnverified && (
                <CardSub style={{ marginTop: 4, lineHeight: 1.7 }}>
                  {t('settings.update.digestMissingAfter')}
                </CardSub>
              )}
            </div>
            {downloadUnverified && (
              <Pill variant="warn">{t('settings.update.digestMissingTag')}</Pill>
            )}
          </div>
        </div>
      )}

      {us === 'error' && (
        <div className="us-state" data-us="error">
          <div className="core-ver">
            <Dot variant="err" />
            <div style={{ flex: 1 }}>
              <b style={{ color: 'hsl(var(--err))' }}>{t('settings.update.failed')}</b>
              <CardSub>{errMsg}</CardSub>
            </div>
            {updateInfo && (
              <Button variant="ghost" size="sm" onClick={downloadUpdate}>
                <span>{t('common.retry')}</span>
              </Button>
            )}
            <Button variant="ghost" size="sm" onClick={checkUpdate}>
              <span>{t('settings.about.checkUpdate')}</span>
            </Button>
          </div>
        </div>
      )}

      <SetRowSection>
        <SetRow
          label={t('settings.update.appChannel')}
          tip={t('settings.update.appChannelDesc')}
        >
          <Select
            style={{ width: 132 }}
            value={appUpdateChannel}
            onChange={(event) =>
              void update({ appUpdateChannel: event.target.value as AppUpdateChannel })
            }
            aria-label={t('settings.update.appChannel')}
          >
            <option value="stable">{t('settings.update.appChannelStable')}</option>
            <option value="prerelease">{t('settings.update.appChannelPrerelease')}</option>
          </Select>
        </SetRow>
        <SetRow
          label={t('settings.update.autoDownloadApp')}
          tip={
            config.autoDownloadUpdate
              ? t('settings.update.autoDownloadAppDesc')
              : t('settings.update.autoDownloadAppDescOff')
          }
        >
          <Switch
            id="auto-dl-swt"
            checked={!!config.autoDownloadUpdate}
            onChange={(value) => {
              void update({ autoDownloadUpdate: value });
              toast.success(
                value
                  ? t('settings.update.autoDownloadOnToast')
                  : t('settings.update.autoDownloadOffToast'),
              );
            }}
            aria-label={t('settings.update.autoDownloadApp')}
          />
        </SetRow>
      </SetRowSection>
    </Card>
  );
}
