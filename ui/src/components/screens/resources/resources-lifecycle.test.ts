import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const source = readFileSync(
  fileURLToPath(new URL('./ResourcesScreen.tsx', import.meta.url)),
  'utf8',
);

describe('ResourcesScreen progress lifecycle', () => {
  it('cleans delayed terminal refreshes when the subscription unmounts', () => {
    expect(source).toMatch(/let cancelled = false/);
    expect(source).toMatch(/const cleanupTimers = new Set<ReturnType<typeof setTimeout>>/);
    expect(source).toMatch(/if \(cancelled\) return;/);
    expect(source).toMatch(/for \(const timer of cleanupTimers\) clearTimeout\(timer\)/);
  });
});
