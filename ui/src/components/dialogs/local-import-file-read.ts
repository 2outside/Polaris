/** Browser drag/drop must obey the same bounded, strict-text contract as the native picker. */
export const LOCAL_IMPORT_MAX_FILE_BYTES = 10 * 1024 * 1024;
export const LOCAL_IMPORT_FILE_READ_TIMEOUT_MS = 5_000;

export type LocalImportFileReadResult =
  | { kind: 'ok'; text: string }
  | { kind: 'too_large' }
  | { kind: 'failed' };

export interface LocalImportReadableFile {
  size: number;
  arrayBuffer(): Promise<ArrayBuffer>;
}

/**
 * There is no AbortSignal hook on File.arrayBuffer(). A timeout therefore settles this consumer
 * as failed; its late arrayBuffer resolution remains detached and has no UI continuation.
 */
export async function readLocalImportFile(
  file: LocalImportReadableFile,
  timeoutMs = LOCAL_IMPORT_FILE_READ_TIMEOUT_MS,
): Promise<LocalImportFileReadResult> {
  if (file.size > LOCAL_IMPORT_MAX_FILE_BYTES) return { kind: 'too_large' };

  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    const bytes = await Promise.race<ArrayBuffer>([
      file.arrayBuffer(),
      new Promise<ArrayBuffer>((_, reject) => {
        timeout = setTimeout(() => reject(new Error()), timeoutMs);
      }),
    ]);
    // TextDecoder defaults to replacement characters; imports must reject malformed UTF-8 instead.
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    return { kind: 'ok', text };
  } catch {
    return { kind: 'failed' };
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
}
