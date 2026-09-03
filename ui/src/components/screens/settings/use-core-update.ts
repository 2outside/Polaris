/**
 * sing-box 内核更新卡的唯一运行时 owner。
 *
 * 版本水合、暂存状态订阅、在线更新和手动换核彼此共享刷新/确认边界，必须由同一 owner 协调；
 * 页面与呈现组件只传递配置和触发动作。
 */
import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { coreUpdateApi } from '@/ipc/api-client';
import { useDialogStore } from '../../dialogs/dialog-store';
import { useConfirmTwice } from '@/lib/confirm-twice';

export type CoreOnlineUpdateState = 'idle' | 'checking' | 'available' | 'updating';

export const CORE_ROLLBACK_KEY = 'core-rollback';
const CORE_UPDATE_CHECK_TIMEOUT_MS = 20_000;

function withTimeout<T>(promise: Promise<T>, ms: number, timeoutError: () => Error): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(timeoutError()), ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error instanceof Error ? error : new Error(String(error)));
      },
    );
  });
}

type CoreOperationResult = {
  ok?: boolean;
  error?: string;
  cancelled?: boolean;
  needConfirm?: boolean;
  uploadVersion?: string;
  bundledVersion?: string;
  filePath?: string;
};

export function useCoreUpdate() {
  const { t } = useTranslation();
  const openDialog = useDialogStore((s) => s.open);
  const closeDialog = useDialogStore((s) => s.close);
  const { armed, confirmTwice } = useConfirmTwice();
  const [coreVer, setCoreVer] = useState<{
    current: string;
    hasBackup: boolean;
    build: 'official' | 'fork' | 'unknown';
  } | null>(null);
  const [staged, setStaged] = useState<{ version: string; stagedAt: string } | null>(null);
  const [coreBusy, setCoreBusy] = useState(false);
  const [coreMsg, setCoreMsg] = useState('');
  const [onlineState, setOnlineState] = useState<CoreOnlineUpdateState>('idle');
  const [latest, setLatest] = useState<{
    version: string;
    downloadUrl?: string;
    crossBand: boolean;
  } | null>(null);
  const [onlineMessage, setOnlineMessage] = useState('');
  const [onlineError, setOnlineError] = useState('');

  const refreshCoreVer = useCallback(() => {
    void coreUpdateApi
      .getVersionInfo()
      .then((version) =>
        setCoreVer({
          current: version.currentVersion,
          hasBackup: version.hasBackup,
          build: version.build,
        }),
      )
      .catch(() => undefined);
  }, []);

  useEffect(() => refreshCoreVer(), [refreshCoreVer]);

  useEffect(() => {
    let cancelled = false;
    void coreUpdateApi
      .getAutoStatus()
      .then((status) => {
        if (!cancelled) setStaged(status.staged);
      })
      .catch(() => undefined);
    const off = coreUpdateApi.onAutoStatusChanged((status) => setStaged(status.staged));
    return () => {
      cancelled = true;
      off();
    };
  }, []);

  async function runCoreOp(operation: () => Promise<CoreOperationResult>, okMsg: string) {
    setCoreBusy(true);
    setCoreMsg('');
    try {
      const result = await operation();
      if (result.cancelled) return;
      if (result.needConfirm) {
        openDialog({
          kind: 'confirm',
          payload: {
            title: t('settings.core.replaceConfirmTitle'),
            message: t('settings.core.replaceConfirmMessage', {
              upload: result.uploadVersion || t('common.unknown'),
              bundled: result.bundledVersion || '-',
            }),
            danger: true,
            onConfirm: async () => {
              closeDialog();
              await runCoreOp(
                () => coreUpdateApi.replaceManual({ filePath: result.filePath, force: true }),
                okMsg,
              );
            },
          },
        });
        return;
      }
      setCoreMsg(result.ok ? okMsg : t('settings.core.swapFailedShort'));
    } catch (error) {
      console.error('[core] operation failed:', error);
      setCoreMsg(t('settings.core.swapFailedShort'));
    } finally {
      setCoreBusy(false);
      refreshCoreVer();
    }
  }

  async function checkCoreUpdate() {
    setOnlineState('checking');
    setOnlineMessage('');
    setOnlineError('');
    setLatest(null);
    try {
      const result = await withTimeout(
        coreUpdateApi.check(),
        CORE_UPDATE_CHECK_TIMEOUT_MS,
        () =>
          new Error(
            t('settings.coreManagement.checkTimeout', {
              sec: CORE_UPDATE_CHECK_TIMEOUT_MS / 1000,
            }),
          ),
      );
      if (result.hasUpdate && result.latestVersion) {
        setLatest({
          version: result.latestVersion,
          downloadUrl: result.downloadUrl,
          crossBand: !!result.crossBand,
        });
        setOnlineState('available');
        return;
      }
      setOnlineState('idle');
      setOnlineMessage(t('settings.coreManagement.upToDate'));
    } catch (error) {
      console.error('[core] update check failed:', error);
      setOnlineState('idle');
      setOnlineError(t('settings.core.swapFailedShort'));
    }
  }

  async function runCoreUpdate() {
    if (!latest) return;
    setOnlineState('updating');
    setOnlineMessage('');
    setOnlineError('');
    try {
      const result = await coreUpdateApi.update(latest.downloadUrl);
      if (result.result === 'deferred' && result.crossBand) {
        setOnlineError(
          t('settings.coreManagement.crossBandFound', {
            version: result.latestVersion || latest.version,
          }),
        );
        setOnlineState('idle');
        return;
      }
      if (result.result === 'noop') {
        setOnlineMessage(t('settings.coreManagement.upToDate'));
      } else if (result.ok) {
        setOnlineMessage(t('settings.core.applied'));
      } else {
        setOnlineError(t('settings.core.swapFailedShort'));
      }
      setOnlineState('idle');
      setLatest(null);
    } catch (error) {
      console.error('[core] update failed:', error);
      setOnlineState('idle');
      setOnlineError(t('settings.core.swapFailedShort'));
    } finally {
      refreshCoreVer();
    }
  }

  function applyStaged() {
    return runCoreOp(
      async () => {
        const result = await coreUpdateApi.applyStaged();
        return { ok: result.result === 'applied', error: result.error ?? result.result };
      },
      t('settings.core.applied'),
    );
  }

  function replaceManual() {
    return runCoreOp(() => coreUpdateApi.replaceManual(), t('settings.core.replaced'));
  }

  function rollback() {
    return confirmTwice(CORE_ROLLBACK_KEY, () => {
      void runCoreOp(() => coreUpdateApi.rollback(), t('settings.core.rollbackSuccess'));
    });
  }

  function resetFactory() {
    openDialog({
      kind: 'confirm',
      payload: {
        title: t('settings.core.resetFactoryTitle'),
        message: t('settings.core.resetFactoryConfirm'),
        danger: true,
        onConfirm: async () => {
          closeDialog();
          await runCoreOp(() => coreUpdateApi.resetFactory(), t('settings.core.resetFactoryDone'));
        },
      },
    });
  }

  return {
    armed,
    confirmTwice,
    coreVer,
    staged,
    coreBusy,
    coreMsg,
    onlineState,
    latest,
    onlineMessage,
    onlineError,
    coreForkBlocked: coreVer?.build === 'fork',
    applyStaged,
    replaceManual,
    rollback,
    resetFactory,
    checkCoreUpdate,
    runCoreUpdate,
  };
}
