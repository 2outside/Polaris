import { describe, expect, it } from 'vitest';
import {
  dnsConnectionResolutionPatch,
  effectiveDnsConnectionResolution,
} from './dns-connection-resolution';

describe('DNS-owned connection resolution', () => {
  it('treats dnsDefaults as the only truth for schema v4+', () => {
    expect(effectiveDnsConnectionResolution({
      configSchemaVersion: 4,
      dnsDefaults: {
        directServerId: 'builtin-domestic',
        proxyServerId: 'builtin-remote',
        connectionResolution: 'preserveDomain',
      },
      routeDefaults: { destinationResolution: 'dnsRules' },
      resolveBeforeDial: true,
    })).toBe('preserveDomain');
  });

  it('keeps the v2/v3 and v1 compatibility reads one-way', () => {
    expect(effectiveDnsConnectionResolution({
      configSchemaVersion: 3,
      routeDefaults: { destinationResolution: 'dnsRules' },
    })).toBe('dnsRules');
    expect(effectiveDnsConnectionResolution({ resolveBeforeDial: true })).toBe('dnsRules');
  });

  it('writes one DNS-owned field without replacing other DNS defaults', () => {
    expect(dnsConnectionResolutionPatch({
      dnsDefaults: {
        directServerId: 'direct-id',
        proxyServerId: 'proxy-id',
        unmatchedAction: { type: 'fakeIp' },
      },
    }, 'dnsRules')).toEqual({
      dnsDefaults: {
        directServerId: 'direct-id',
        proxyServerId: 'proxy-id',
        unmatchedAction: { type: 'fakeIp' },
        connectionResolution: 'dnsRules',
      },
    });
  });
});
