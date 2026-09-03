import type { SubscriptionCreatePhase } from '@/contracts/subscription-create-operation';
import { UncertainSubscriptionCreateStartError } from '@/store/subscription-create-operation-store';

/** Terminal work has a final backend result and must never be retried under the old id. */
export function clearSubscriptionCreateOperationIdAfterTerminal(phase: SubscriptionCreatePhase): boolean {
  return phase === 'failed' || phase === 'cancelled';
}

/** Only an unavailable start response might already have registered this id server-side. */
export function retainSubscriptionCreateOperationIdAfterStartError(error: unknown): boolean {
  return error instanceof UncertainSubscriptionCreateStartError;
}
