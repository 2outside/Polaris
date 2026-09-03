import { describe, expect, it, vi } from 'vitest';
import {
  LOCAL_IMPORT_FILE_READ_TIMEOUT_MS,
  LOCAL_IMPORT_MAX_FILE_BYTES,
  readLocalImportFile,
} from './local-import-file-read';

describe('local import browser file reader', () => {
  it('rejects an over-limit file before reading its body', async () => {
    const arrayBuffer = vi.fn();
    await expect(readLocalImportFile({ size: LOCAL_IMPORT_MAX_FILE_BYTES + 1, arrayBuffer })).resolves.toEqual({
      kind: 'too_large',
    });
    expect(arrayBuffer).not.toHaveBeenCalled();
  });

  it('strictly decodes valid UTF-8 and rejects malformed bytes', async () => {
    await expect(readLocalImportFile({
      size: 2,
      arrayBuffer: async () => new Uint8Array([0xc3, 0x28]).buffer,
    })).resolves.toEqual({ kind: 'failed' });
    await expect(readLocalImportFile({
      size: 2,
      arrayBuffer: async () => new TextEncoder().encode('ok').buffer,
    })).resolves.toEqual({ kind: 'ok', text: 'ok' });
  });

  it('settles timed-out reads as failed and ignores a later body resolution', async () => {
    vi.useFakeTimers();
    let resolveBody!: (bytes: ArrayBuffer) => void;
    const read = readLocalImportFile({
      size: 2,
      arrayBuffer: () => new Promise<ArrayBuffer>((resolve) => { resolveBody = resolve; }),
    });
    await vi.advanceTimersByTimeAsync(LOCAL_IMPORT_FILE_READ_TIMEOUT_MS);
    await expect(read).resolves.toEqual({ kind: 'failed' });
    resolveBody(new TextEncoder().encode('ok').buffer);
    await Promise.resolve();
    vi.useRealTimers();
  });
});
