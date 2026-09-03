/**
 * 应用更新卡的唯一运行时 owner。
 *
 * 进度事件会被广播到每个窗口，因而这里同时持有状态机、订阅清理与安装期的包快照；呈现层只消费
 * 返回的状态和动作，不再复制任何状态迁移或跨 await 的一致性约束。
 */
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  updateApi,
  versionApi,
  type InstallAdvisory,
  type UpdateProgress,
  type UpdateProgressManifest,
  type VersionInfo,
} from '@/ipc/api-client';
import { useDialogStore } from '../../dialogs/dialog-store';
import { markAppVersionSkipped } from '../../layout/app-update-banner';
import {
  appDownloadIntegrity,
  isPortableZipUpdate,
  progressResetsIntegrity,
  updateCardPatch,
  type AppDownloadIntegrity,
} from './settings-logic';

export type AppUpdateState =
  | 'idle'
  | 'checking'
  | 'available'
  | 'downloading'
  | 'downloaded'
  | 'manual'
  | 'error';

interface InstallSubject {
  path: string;
  info: UpdateProgressManifest | null;
  integrity: AppDownloadIntegrity;
}

/** U1：失败机器码映射到本地化正文；技术诊断只保留在 IPC 和日志。 */
function updateErrText(
  rawCode: string | null | undefined,
  _detail: string | null | undefined,
  t: (k: string) => string,
): string {
  const code = rawCode === 'HTTP_BACKEND_UNAVAILABLE' ? 'backendUnavailable' : rawCode;
  const body = code ? t(`settings.update.err.${code}`) : '';
  return body && body !== `settings.update.err.${code}`
    ? body
    : t('settings.update.downloadInterrupted');
}

export function useAppUpdate(includePrerelease: boolean) {
  const { t } = useTranslation();
  const openDialog = useDialogStore((s) => s.open);
  const closeDialog = useDialogStore((s) => s.close);
  const [us, setUs] = useState<AppUpdateState>('idle');
  const [appVersionInfo, setAppVersionInfo] = useState<VersionInfo | null>(null);
  const [updateInfo, setUpdateInfo] = useState<UpdateProgressManifest | null>(null);
  const [progress, setProgress] = useState(0);
  const [receivedBytes, setReceivedBytes] = useState<number | null>(null);
  const [errMsg, setErrMsg] = useState('');
  const [downloadedPath, setDownloadedPath] = useState<string | null>(null);
  const [downloadIntegrity, setDownloadIntegrity] = useState<AppDownloadIntegrity>('unknown');

  useEffect(() => {
    void versionApi.getInfo().then(setAppVersionInfo).catch(() => undefined);
  }, []);

  useEffect(() => {
    const off = updateApi.onProgress((p: UpdateProgress) => {
      if (progressResetsIntegrity(p.status)) setDownloadIntegrity('unknown');
      const patch = updateCardPatch(p);
      if (!patch) return;
      setUs(patch.us);
      setUpdateInfo(patch.info);
      setDownloadedPath(patch.path);
      setReceivedBytes(patch.received);
      setProgress(patch.percentage);
      if (patch.errorCode !== null) {
        setErrMsg(updateErrText(patch.errorCode, patch.errorDetail, t));
      }
      if (patch.integrity !== null) setDownloadIntegrity(patch.integrity);
    });
    return off;
  }, []);

  async function checkUpdate() {
    setUs('checking');
    setDownloadIntegrity('unknown');
    try {
      const r = await updateApi.check({ includePrerelease });
      if (r.hasUpdate && r.updateInfo) {
        setUpdateInfo(r.updateInfo);
        setUs('available');
      } else {
        setUs('idle');
      }
    } catch (error) {
      setUs('error');
      console.error('[update] check failed:', error);
      setErrMsg(updateErrText((error as { code?: string }).code, undefined, t));
    }
  }

  /** 显式重新下载当前通道的当前版本；若实际已有新版，只展示新版，不替用户自动下载另一个目标。 */
  async function reinstallCurrent() {
    setUs('checking');
    setDownloadIntegrity('unknown');
    try {
      const r = await updateApi.check({ includePrerelease, includeCurrent: true });
      if (r.hasUpdate && r.updateInfo) {
        setUpdateInfo(r.updateInfo);
        setUs('available');
      } else if (r.isCurrentVersion && r.updateInfo) {
        setUpdateInfo(r.updateInfo);
        await downloadTarget(r.updateInfo);
      } else {
        setUpdateInfo(null);
        setUs('error');
        setErrMsg(t('settings.update.reinstallUnavailable'));
      }
    } catch (error) {
      setUs('error');
      console.error('[update] reinstall resolution failed:', error);
      setErrMsg(updateErrText((error as { code?: string }).code, undefined, t));
    }
  }

  async function skipVersion() {
    if (updateInfo) {
      try {
        await updateApi.skip(updateInfo.version);
      } catch (error) {
        console.error('[update] skip failed:', error);
      }
      markAppVersionSkipped(updateInfo.version);
    }
    setUs('idle');
  }

  async function downloadTarget(target: UpdateProgressManifest) {
    setUs('downloading');
    setProgress(0);
    setReceivedBytes(0);
    setDownloadIntegrity('unknown');
    try {
      const r = await updateApi.download(target);
      setDownloadIntegrity(appDownloadIntegrity(r));
      if (!r.success) {
        setUs('error');
        setErrMsg(updateErrText(r.errorCode, r.errorDetail, t));
      }
    } catch (error) {
      setUs('error');
      console.error('[update] download failed:', error);
      setErrMsg(updateErrText((error as { code?: string }).code, undefined, t));
    }
  }

  async function downloadUpdate() {
    if (updateInfo) await downloadTarget(updateInfo);
  }

  function settleInstall(next: 'manual' | 'error', message: string, subject: InstallSubject) {
    setUs(next);
    setUpdateInfo(subject.info);
    setDownloadedPath(subject.path);
    setDownloadIntegrity(subject.integrity);
    setErrMsg(message);
  }

  async function installUpdate(confirmed = false, subject?: InstallSubject) {
    const subj: InstallSubject = subject ?? {
      path: downloadedPath ?? '',
      info: updateInfo,
      integrity: downloadIntegrity,
    };
    if (!subj.path) return;
    try {
      const result = await updateApi.install(subj.path, confirmed);
      if (result.needConfirm && result.advisory) {
        const advisory = result.advisory as InstallAdvisory;
        openDialog({
          kind: 'confirm',
          payload: {
            title: t(`settings.update.advisory.${advisory}.title`),
            message: t(`settings.update.advisory.${advisory}.message`),
            confirmLabel: t('settings.update.advisory.continue'),
            onConfirm: async () => {
              closeDialog();
              await installUpdate(true, subj);
            },
          },
        });
        return;
      }
      if (result.handedToSystem || result.reason === 'form-mismatch') {
        if (isPortableZipUpdate(subj.path)) {
          settleInstall(
            'manual',
            t('settings.update.portableManualReplace', { path: subj.path }),
            subj,
          );
        } else {
          settleInstall('error', t('settings.update.formMismatch'), subj);
        }
      }
    } catch (error) {
      console.error('[update] install failed:', error);
      settleInstall('error', t('settings.update.downloadInterrupted'), subj);
    }
  }

  return {
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
  };
}
