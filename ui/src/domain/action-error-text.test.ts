import { describe, expect, it } from 'vitest';
import {
  backupErrorText,
  helperActionErrorText,
  serverSwitchErrorText,
} from './action-error-text';

const t = (key: string) => `translated:${key}`;

describe('structured action error text', () => {
  it('stable helper code wins over any diagnostic', () => {
    expect(helperActionErrorText('missingAsset', t)).toBe('translated:helper.actionError.missingAsset');
    expect(helperActionErrorText('authorizationUnavailable', t)).toBe(
      'translated:helper.actionError.authorizationUnavailable'
    );
    expect(helperActionErrorText('proxyRunning', t)).toBe(
      'translated:helper.actionError.proxyRunning'
    );
  });

  it('unknown or future backup codes use a safe localized fallback', () => {
    expect(backupErrorText(undefined, t)).toBe('translated:backupImport.error.unknown');
    expect(backupErrorText('futureCode' as never, t)).toBe('translated:backupImport.error.unknown');
  });

  it('maps an unavailable outbound interface without exposing backend diagnostics', () => {
    expect(serverSwitchErrorText('OUTBOUND_INTERFACE_UNAVAILABLE', t)).toBe(
      'translated:home.outboundInterfaceUnavailable'
    );
    expect(serverSwitchErrorText('futureCode', t)).toBe('translated:home.switchError');
  });
});
