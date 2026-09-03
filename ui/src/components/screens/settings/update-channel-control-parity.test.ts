import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

function source(name: string): string {
  return readFileSync(fileURLToPath(new URL(name, import.meta.url)), 'utf8');
}

describe('update channel controls stay visually consistent', () => {
  it('uses the shared Select control for both app and core channels', () => {
    const app = source('./AppUpdateCard.tsx');
    const core = source('./CoreUpdateCard.tsx');

    expect(app).toContain('<Select');
    expect(core).toContain('<Select');
    expect(app).not.toContain('<Segmented');
    expect(app).toContain('style={{ width: 132 }}');
    expect(core).toContain('style={{ width: 132 }}');
  });

  it('marks the current-version re-download as a warning without adding an install confirmation', () => {
    const app = source('./AppUpdateCard.tsx');
    const styles = source('../../../styles/index.css');

    expect(app).toContain('className="warn-action"');
    expect(app).toContain("data-tip={t('settings.update.reinstallCurrentTip')}");
    expect(app).toContain('onClick={reinstallCurrent}');
    expect(styles).toContain('.btn.warn-action');
  });
});
