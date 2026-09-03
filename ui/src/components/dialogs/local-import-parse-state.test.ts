import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  canPublishLocalImportParse,
  canPublishLocalImportFileRead,
  localImportCloseLocked,
  localImportPrimaryActionDisabled,
} from './local-import-parse-state';

const IMPORT_DIALOG = readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'ImportDialog.tsx'), 'utf8');

describe('local import parse lifecycle', () => {
  const attempt = { generation: 7, input: 'old content' };

  it('deferred parse after an edit, source switch, or close has no visible continuation', () => {
    expect(canPublishLocalImportParse(attempt, {
      generation: 8, input: 'new content', hasInstance: true,
    }), 'editing invalidates the old result').toBe(false);
    expect(canPublishLocalImportParse(attempt, {
      generation: 8, input: 'old content', hasInstance: true,
    }), 'switching source invalidates even identical text').toBe(false);
    expect(canPublishLocalImportParse(attempt, {
      generation: 7, input: 'old content', hasInstance: false,
    }), 'closing invalidates both result and error toast').toBe(false);
  });

  it('concurrent file drops and a closed dialog cannot publish a stale file read', () => {
    expect(canPublishLocalImportFileRead({ generation: 4 }, {
      generation: 5, hasInstance: true,
    }), 'a newer drop supersedes the older read').toBe(false);
    expect(canPublishLocalImportFileRead({ generation: 4 }, {
      generation: 4, hasInstance: false,
    }), 'close invalidates a pending file read').toBe(false);
  });

  it('native picker reject applies the identical stale guard before its visible error hint', () => {
    const pickerCatch = IMPORT_DIALOG.slice(IMPORT_DIALOG.indexOf('const pickFile = async'));
    const catchBlock = pickerCatch.slice(pickerCatch.indexOf('} catch (e)'));
    const guard = catchBlock.indexOf('if (!canPublishFileRead(attempt)) return;');
    const hint = catchBlock.indexOf("setFileHint(t('import.fileReadFail'))");
    expect(guard).toBeGreaterThanOrEqual(0);
    expect(hint).toBeGreaterThan(guard);
  });

  it('parse is visibly busy but remains closable; only import/force-load is close-locked', () => {
    expect(localImportPrimaryActionDisabled(true, false)).toBe(true);
    expect(localImportCloseLocked(false)).toBe(false);
    expect(localImportCloseLocked(true)).toBe(true);
  });
});
