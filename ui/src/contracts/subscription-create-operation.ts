import type { SubscriptionConfig } from './types';
import type { SubscriptionErrorKind } from './subscription-preview';

/** Renderer-independent, backend-owned “create subscription and fetch nodes” operation. */
export type SubscriptionCreatePhase =
  | 'queued'
  | 'fetching'
  | 'parsing'
  | 'committing'
  | 'succeeded'
  | 'failed'
  | 'cancelled';

export interface SubscriptionCreateError {
  /** IPC 字段与 subscription preview/update 统一为 errorKind。 */
  errorKind?: SubscriptionErrorKind;
  httpStatus?: number;
  /** Diagnostics are log-only; UI maps `errorKind` to localized copy. */
  message?: string;
}

export interface SubscriptionCreateResult {
  subscription: SubscriptionConfig;
  nodeCount: number;
  addedServers: number;
  updatedServers?: number;
  deletedServers?: number;
  warnings?: string[];
  partial?: boolean;
  recovered?: boolean;
}

export interface SubscriptionCreateSnapshot {
  operationId: string;
  /** Monotonic backend revision lets reattached renderers ignore late event frames. */
  revision: number;
  phase: SubscriptionCreatePhase;
  terminal: boolean;
  startedAtMs?: number;
  updatedAtMs?: number;
  /** Provider fan-out progress, when the backend has one to report. */
  providers?: { done?: number; total?: number };
  result?: SubscriptionCreateResult;
  error?: SubscriptionCreateError;
}

export type SubscriptionCreateInput = Omit<SubscriptionConfig, 'id' | 'createdAt'>;

export function subscriptionCreateIsCancellable(snapshot: SubscriptionCreateSnapshot): boolean {
  return !snapshot.terminal && (snapshot.phase === 'queued' || snapshot.phase === 'fetching' || snapshot.phase === 'parsing');
}
