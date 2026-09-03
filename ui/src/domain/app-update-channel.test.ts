import { describe, expect, it } from 'vitest';

import { appUpdateIncludePrerelease } from './app-update-channel';

describe('app update channel', () => {
  it('defaults to stable and only opts into GitHub prereleases explicitly', () => {
    expect(appUpdateIncludePrerelease(null)).toBe(false);
    expect(appUpdateIncludePrerelease({})).toBe(false);
    expect(appUpdateIncludePrerelease({ appUpdateChannel: 'stable' })).toBe(false);
    expect(appUpdateIncludePrerelease({ appUpdateChannel: 'prerelease' })).toBe(true);
  });
});
