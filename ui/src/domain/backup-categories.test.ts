import { describe, expect, it } from 'vitest';
import {
  BACKUP_CATEGORIES,
  normalizeBackupSelection,
  toggleBackupCategory,
  type BackupCategory,
} from './backup-categories';

describe('backup category dependencies', () => {
  it('keeps DNS resources with DNS rules without coupling traffic rules', () => {
    expect([...normalizeBackupSelection(['dnsRules'])]).toEqual([
      'dnsRules',
      'dnsResources',
    ]);
    expect([...normalizeBackupSelection(['customRules'])]).toEqual(['customRules']);
  });

  it('turning DNS resources off also turns dependent DNS rules off', () => {
    const current = new Set<BackupCategory>(['customRules', 'dnsRules', 'dnsResources']);
    expect([...toggleBackupCategory(current, 'dnsResources')]).toEqual(['customRules']);
  });

  it('does not invent the DNS category for a legacy import preview', () => {
    const legacyAvailable: BackupCategory[] = ['customRules', 'generalSettings'];
    expect([...normalizeBackupSelection(legacyAvailable, legacyAvailable)]).toEqual(
      legacyAvailable,
    );
  });

  it('keeps the cross-language category order stable', () => {
    expect(BACKUP_CATEGORIES).toEqual([
      'manualNodes',
      'meshNodes',
      'subscriptions',
      'customRules',
      'dnsRules',
      'dnsResources',
      'appRules',
      'generalSettings',
    ]);
  });
});
