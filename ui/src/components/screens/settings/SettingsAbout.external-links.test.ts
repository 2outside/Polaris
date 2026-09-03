import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const source = readFileSync(
  fileURLToPath(new URL('./SettingsAbout.tsx', import.meta.url)),
  'utf8',
);

describe('SettingsAbout external links have a single navigation owner', () => {
  it('routes all four actions through the shared IPC-only component', () => {
    expect(source.match(/<AboutExternalAction url=/g)).toHaveLength(4);
    expect(source.match(/systemApi\.openExternal\(url\)/g)).toHaveLength(1);
    for (const target of [
      'https://github.com/2outside/Polaris/releases',
      'https://github.com/2outside/Polaris/issues',
      "const LICENSE_URL = 'https://github.com/2outside/Polaris/blob/main/LICENSE'",
      "const NOTICE_URL = 'https://github.com/2outside/Polaris/blob/main/NOTICE'",
    ]) {
      expect(source).toContain(target);
    }
  });

  it('does not retain a second browser-owned navigation or fallback opener', () => {
    expect(source).not.toMatch(/<a[\s>]/);
    expect(source).not.toContain('target="_blank"');
    expect(source).not.toContain('window.open(');
    expect(source).toContain('<button type="button" className="about-link"');
    expect(source).toContain("toast.error(t('settings.about.openExternalFail'))");
  });
});
