import { describe, expect, it } from 'vitest';
import { UncertainSubscriptionCreateStartError } from '@/store/subscription-create-operation-store';
import {
  clearSubscriptionCreateOperationIdAfterTerminal,
  retainSubscriptionCreateOperationIdAfterStartError,
} from './subscription-create-operation-id';

describe('subscription create operation id retry policy', () => {
  it.each(['failed', 'cancelled'] as const)('%s terminal clears the form id so a retry gets a new id', (phase) => {
    expect(clearSubscriptionCreateOperationIdAfterTerminal(phase)).toBe(true);
  });

  it('only an uncertain start response retains its id for idempotent reattach', () => {
    expect(retainSubscriptionCreateOperationIdAfterStartError(
      new UncertainSubscriptionCreateStartError('same-id', new Error('response lost')),
    )).toBe(true);
    expect(retainSubscriptionCreateOperationIdAfterStartError(new Error('definitive start failure'))).toBe(false);
  });
});
