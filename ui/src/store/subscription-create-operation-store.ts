import { create } from 'zustand';
import { api } from '@/ipc';
import type {
  SubscriptionCreateInput,
  SubscriptionCreateSnapshot,
} from '@/contracts/subscription-create-operation';

const STORAGE_KEY = 'polaris.subscription-create.pending';
const STATUS_RECONCILE_DELAY_MS = 2_000;
const STATUS_RECONCILE_MAX_DELAY_MS = 30_000;
const STATUS_RECONCILE_MAX_OPERATIONS = 4;

export type SubscriptionCreateSnapshotMap = Record<string, SubscriptionCreateSnapshot>;

export interface SubscriptionCreateStatusReconcileResult {
  polled: number;
  failures: number;
  /** Cursor for the next fair batch; always interpreted against that round's current candidates. */
  nextCursor: number;
}

interface PersistedTracking {
  operationIds: string[];
  handledTerminalRevisions: Record<string, number>;
}

function readPersistedTracking(): PersistedTracking {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { operationIds: [], handledTerminalRevisions: {} };
    // One-release migration from the original single operationId sentinel.
    if (!raw.trimStart().startsWith('{')) {
      return { operationIds: [raw], handledTerminalRevisions: {} };
    }
    const parsed = JSON.parse(raw) as Partial<PersistedTracking>;
    return {
      operationIds: [...new Set((parsed.operationIds ?? []).filter((id): id is string => typeof id === 'string' && id.length > 0))],
      handledTerminalRevisions: Object.fromEntries(
        Object.entries(parsed.handledTerminalRevisions ?? {}).filter(
          ([id, revision]) => id.length > 0 && Number.isFinite(revision),
        ),
      ),
    };
  } catch {
    return { operationIds: [], handledTerminalRevisions: {} };
  }
}

function persistTracking(tracking: PersistedTracking): void {
  try {
    if (tracking.operationIds.length > 0) localStorage.setItem(STORAGE_KEY, JSON.stringify(tracking));
    else localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Storage denial must not make an already-started backend operation unusable in this renderer.
  }
}

export class UncertainSubscriptionCreateStartError extends Error {
  constructor(readonly operationId: string, readonly originalError: unknown) {
    super('subscription create start outcome is unknown');
    this.name = 'UncertainSubscriptionCreateStartError';
  }
}

/** Per-operation revision is backend-owned. A list result may race a newer event for another operation. */
export function mergeSubscriptionCreateSnapshots(
  current: SubscriptionCreateSnapshotMap,
  incoming: readonly SubscriptionCreateSnapshot[],
): SubscriptionCreateSnapshotMap {
  let next = current;
  for (const snapshot of incoming) {
    if (!snapshot.operationId) continue;
    const previous = next[snapshot.operationId];
    if (previous && snapshot.revision < previous.revision) continue;
    if (previous === snapshot) continue;
    if (next === current) next = { ...current };
    next[snapshot.operationId] = snapshot;
  }
  return next;
}

/** Terminal side effects are once-per-operation-revision, but the task itself remains visible. */
export function subscriptionCreateTerminalNeedsAnnouncement(
  handledRevision: number | undefined,
  snapshot: Pick<SubscriptionCreateSnapshot, 'terminal' | 'revision'>,
): boolean {
  return snapshot.terminal && (handledRevision ?? -1) < snapshot.revision;
}

interface SubscriptionCreateOperationState {
  /** Multiple operations can survive one renderer; operationId is the selection boundary. */
  snapshots: SubscriptionCreateSnapshotMap;
  /** All locally-started operations get recovery UX; bounded list-only history never opens UI. */
  trackedOperationIds: string[];
  /** Terminal toast consumption survives renderer recreation without hiding the task's visible state. */
  handledTerminalRevisions: Record<string, number>;
  accept: (snapshot: SubscriptionCreateSnapshot) => void;
  acceptMany: (snapshots: readonly SubscriptionCreateSnapshot[]) => void;
  track: (operationId: string) => void;
  untrack: (operationId: string) => void;
  markTerminalHandled: (operationId: string, revision: number) => void;
  start: (
    operationId: string,
    subscription: SubscriptionCreateInput,
  ) => Promise<SubscriptionCreateSnapshot>;
  cancel: (operationId: string) => Promise<SubscriptionCreateSnapshot>;
  /** Fast path only: resolve the persisted operation while list hydration is in flight. */
  recover: (operationId: string) => Promise<SubscriptionCreateSnapshot | null>;
  /** Backend list is authoritative and deliberately merges by revision instead of wiping event frames. */
  hydrate: () => Promise<SubscriptionCreateSnapshot[]>;
  clearTerminal: (operationId: string) => void;
}

const initialTracking = readPersistedTracking();

export const useSubscriptionCreateOperationStore = create<SubscriptionCreateOperationState>((set, get) => ({
  snapshots: {},
  trackedOperationIds: initialTracking.operationIds,
  handledTerminalRevisions: initialTracking.handledTerminalRevisions,
  accept: (snapshot) => {
    set((state) => {
      const snapshots = mergeSubscriptionCreateSnapshots(state.snapshots, [snapshot]);
      if (snapshots === state.snapshots) return state;
      return { snapshots };
    });
  },
  acceptMany: (incoming) => {
    set((state) => {
      const snapshots = mergeSubscriptionCreateSnapshots(state.snapshots, incoming);
      if (snapshots === state.snapshots) return state;
      return { snapshots };
    });
  },
  track: (operationId) => {
    set((state) => {
      if (state.trackedOperationIds.includes(operationId)) return state;
      const trackedOperationIds = [...state.trackedOperationIds, operationId];
      persistTracking({ operationIds: trackedOperationIds, handledTerminalRevisions: state.handledTerminalRevisions });
      return { trackedOperationIds };
    });
  },
  untrack: (operationId) => {
    set((state) => {
      const trackedOperationIds = state.trackedOperationIds.filter((id) => id !== operationId);
      const handledTerminalRevisions = { ...state.handledTerminalRevisions };
      delete handledTerminalRevisions[operationId];
      persistTracking({ operationIds: trackedOperationIds, handledTerminalRevisions });
      return { trackedOperationIds, handledTerminalRevisions };
    });
  },
  markTerminalHandled: (operationId, revision) => {
    set((state) => {
      if ((state.handledTerminalRevisions[operationId] ?? -1) >= revision) return state;
      const handledTerminalRevisions = { ...state.handledTerminalRevisions, [operationId]: revision };
      persistTracking({ operationIds: state.trackedOperationIds, handledTerminalRevisions });
      return { handledTerminalRevisions };
    });
  },
  start: async (operationId, subscription) => {
    get().track(operationId);
    try {
      const snapshot = await api.subscription.createStart(operationId, subscription);
      get().accept(snapshot);
      return snapshot;
    } catch (startError) {
      // A response can be lost after Rust has registered/spawned the operation. Reattach by the
      // caller-owned id before exposing an error or allowing another submit UUID.
      const recovered = await get().recover(operationId);
      if (recovered) return recovered;
      try {
        const snapshots = await api.subscription.createList();
        get().acceptMany(snapshots);
        const fromList = get().snapshots[operationId] ?? null;
        if (fromList) return fromList;
        // A successful status/list absence is the only definitive proof that this id was never
        // registered; only then may the form make another start attempt.
        get().untrack(operationId);
        throw startError;
      } catch (recoveryError) {
        if (recoveryError === startError) throw recoveryError;
        throw new UncertainSubscriptionCreateStartError(operationId, startError);
      }
    }
  },
  cancel: async (operationId) => {
    const snapshot = await api.subscription.createCancel(operationId);
    get().accept(snapshot);
    return snapshot;
  },
  recover: async (operationId) => {
    try {
      const snapshot = await api.subscription.createStatus(operationId);
      get().accept(snapshot);
      return snapshot;
    } catch (error) {
      console.error('[subscription-create-operation] hint recover failed:', error);
      return null;
    }
  },
  hydrate: async () => {
    // Start the local hint as a latency optimization only. Whichever result/event wins is merged
    // per operation revision; neither may erase a newer frame from the other source.
    const trackedAtStart = [...get().trackedOperationIds];
    const hints = trackedAtStart.map((operationId) => get().recover(operationId));
    try {
      const snapshots = await api.subscription.createList();
      get().acceptMany(snapshots);
      await Promise.all(hints);
      const recovered = trackedAtStart
        .map((operationId) => get().snapshots[operationId])
        .filter((snapshot): snapshot is SubscriptionCreateSnapshot => snapshot != null);
      // A rejected status plus list absence means this local marker is stale. List-only terminal
      // history deliberately never enters this collection.
      for (const operationId of trackedAtStart) {
        if (!get().snapshots[operationId]) get().untrack(operationId);
      }
      return recovered;
    } catch (error) {
      console.error('[subscription-create-operation] list hydrate failed:', error);
      await Promise.all(hints);
      return trackedAtStart
        .map((operationId) => get().snapshots[operationId])
        .filter((snapshot): snapshot is SubscriptionCreateSnapshot => snapshot != null);
    }
  },
  clearTerminal: (operationId) => {
    set((state) => {
      const snapshot = state.snapshots[operationId];
      if (!snapshot?.terminal) return state;
      const snapshots = { ...state.snapshots };
      delete snapshots[operationId];
      const trackedOperationIds = state.trackedOperationIds.filter((id) => id !== operationId);
      const handledTerminalRevisions = { ...state.handledTerminalRevisions };
      delete handledTerminalRevisions[operationId];
      persistTracking({ operationIds: trackedOperationIds, handledTerminalRevisions });
      return { snapshots, trackedOperationIds, handledTerminalRevisions };
    });
  },
}));

/**
 * Events are deliberately best-effort. Reconcile locally-owned in-flight operations so a lost
 * terminal frame cannot strand a task in `committing` forever. This is independent of visibility:
 * hiding a window must not turn a backend-owned operation into an unobservable one.
 */
export function selectTrackedSubscriptionCreateStatusBatch(
  trackedOperationIds: readonly string[],
  snapshots: SubscriptionCreateSnapshotMap,
  cursor: number,
): { operationIds: string[]; nextCursor: number } {
  const candidates = trackedOperationIds.filter((operationId) => !snapshots[operationId]?.terminal);
  if (candidates.length === 0) return { operationIds: [], nextCursor: 0 };
  const start = ((cursor % candidates.length) + candidates.length) % candidates.length;
  const size = Math.min(STATUS_RECONCILE_MAX_OPERATIONS, candidates.length);
  const operationIds = Array.from({ length: size }, (_, index) => candidates[(start + index) % candidates.length]);
  return { operationIds, nextCursor: (start + size) % candidates.length };
}

export async function reconcileTrackedSubscriptionCreateStatuses(
  cursor = 0,
): Promise<SubscriptionCreateStatusReconcileResult> {
  const state = useSubscriptionCreateOperationStore.getState();
  const { operationIds, nextCursor } = selectTrackedSubscriptionCreateStatusBatch(
    state.trackedOperationIds,
    state.snapshots,
    cursor,
  );
  const outcomes = await Promise.all(operationIds.map(async (operationId) => {
    try {
      const snapshot = await api.subscription.createStatus(operationId);
      useSubscriptionCreateOperationStore.getState().accept(snapshot);
      return true;
    } catch (error) {
      // A later low-frequency round reattaches. Do not untrack on a transport failure: the
      // operation may still be alive, and its caller-owned id is the only recovery handle.
      console.error('[subscription-create-operation] status reconcile failed:', error);
      return false;
    }
  }));
  return { polled: operationIds.length, failures: outcomes.filter((ok) => !ok).length, nextCursor };
}

export interface SubscriptionCreateStatusReconcileOptions {
  delayMs?: number;
  maxDelayMs?: number;
}

/** Starts one non-overlapping, bounded status fallback loop. Returns the renderer cleanup. */
export function startSubscriptionCreateStatusReconcile(
  { delayMs = STATUS_RECONCILE_DELAY_MS, maxDelayMs = STATUS_RECONCILE_MAX_DELAY_MS }:
    SubscriptionCreateStatusReconcileOptions = {},
): () => void {
  let disposed = false;
  let inFlight = false;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let nextDelay = delayMs;
  let cursor = 0;

  const schedule = () => {
    if (disposed || timer !== null) return;
    timer = setTimeout(() => {
      timer = null;
      void tick();
    }, nextDelay);
  };

  const tick = async () => {
    if (disposed || inFlight) return;
    inFlight = true;
    try {
      const result = await reconcileTrackedSubscriptionCreateStatuses(cursor);
      cursor = result.nextCursor;
      const { failures } = result;
      nextDelay = failures > 0 ? Math.min(nextDelay * 2, maxDelayMs) : delayMs;
    } finally {
      inFlight = false;
      schedule();
    }
  };

  schedule();
  return () => {
    disposed = true;
    if (timer !== null) clearTimeout(timer);
    timer = null;
  };
}

/** Kept as one cleanup unit so renderer teardown cannot leak the fallback timer. */
export function stopSubscriptionCreateOperationSubscription({
  off,
  stopReconcile,
}: {
  off: () => void;
  stopReconcile: () => void;
}): void {
  off();
  stopReconcile();
}

/**
 * Event registration is awaited before list hydration. This is intentionally separate from App so
 * the ordering is independently testable and no component lifecycle can accidentally reverse it.
 */
export async function subscribeAndHydrateSubscriptionCreateOperations(): Promise<{
  off: () => void;
  stopReconcile: () => void;
  recovered: SubscriptionCreateSnapshot[];
}> {
  const off = await api.subscription.onCreateProgressReady((snapshot) => {
    useSubscriptionCreateOperationStore.getState().accept(snapshot);
  });
  const recovered = await useSubscriptionCreateOperationStore.getState().hydrate();
  return { off, stopReconcile: startSubscriptionCreateStatusReconcile(), recovered };
}
