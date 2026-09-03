/** 用户动作错误的稳定 code → 当前语种文案。诊断永远不直接渲染。 */
import type { BackupErrorCode, HelperActionErrorCode } from '@/ipc/api-client';

type Translate = (key: string) => string;

export function helperActionErrorText(
  code: HelperActionErrorCode | null | undefined,
  t: Translate,
): string {
  switch (code) {
    case 'cancelled': return t('helper.actionError.cancelled');
    case 'authorizationUnavailable': return t('helper.actionError.authorizationUnavailable');
    case 'proxyRunning': return t('helper.actionError.proxyRunning');
    case 'unsupported': return t('helper.actionError.unsupported');
    case 'missingAsset': return t('helper.actionError.missingAsset');
    case 'notReady': return t('helper.actionError.notReady');
    default: return t('helper.actionError.failed');
  }
}

export function backupErrorText(
  code: BackupErrorCode | null | undefined,
  t: Translate,
): string {
  switch (code) {
    case 'cancelled': return t('backupImport.error.cancelled');
    case 'configLoadFailed': return t('backupImport.error.configLoadFailed');
    case 'serializeFailed': return t('backupImport.error.serializeFailed');
    case 'writeFailed': return t('backupImport.error.writeFailed');
    case 'readFailed': return t('backupImport.error.readFailed');
    case 'invalidFormat': return t('backupImport.error.invalidFormat');
    case 'invalidArgs': return t('backupImport.error.invalidArgs');
    case 'saveFailed': return t('backupImport.error.saveFailed');
    default: return t('backupImport.error.unknown');
  }
}

/** 节点切换错误码 → 用户可操作的当前语种说明；后端诊断只进入日志。 */
export function serverSwitchErrorText(
  code: string | null | undefined,
  t: Translate,
): string {
  if (code === 'OUTBOUND_INTERFACE_UNAVAILABLE') {
    return t('home.outboundInterfaceUnavailable');
  }
  return t('home.switchError');
}
