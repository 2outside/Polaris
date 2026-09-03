/**
 * A local parse cannot be aborted over IPC: closing the dialog simply makes its eventual result
 * irrelevant. Keep that decision as a tiny, testable predicate rather than relying on a mounted
 * component accidentally ignoring a late continuation.
 */
export interface LocalImportParseAttempt {
  generation: number;
  input: string;
}

/** File reads are another asynchronous input source, guarded by the same dialog generation. */
export interface LocalImportFileReadAttempt {
  generation: number;
}

export function canPublishLocalImportFileRead(
  attempt: LocalImportFileReadAttempt,
  current: { generation: number; hasInstance: boolean },
): boolean {
  return current.hasInstance && current.generation === attempt.generation;
}

export function canPublishLocalImportParse(
  attempt: LocalImportParseAttempt,
  current: { generation: number; input: string; hasInstance: boolean },
): boolean {
  return current.hasInstance
    && current.generation === attempt.generation
    && current.input === attempt.input;
}

/** Only the write + force-refresh phase owns the dialog close lock. */
export function localImportCloseLocked(importing: boolean): boolean {
  return importing;
}

/** Parsing may be abandoned, but a second parse/import must not race it. */
export function localImportPrimaryActionDisabled(parsing: boolean, importing: boolean): boolean {
  return parsing || importing;
}
