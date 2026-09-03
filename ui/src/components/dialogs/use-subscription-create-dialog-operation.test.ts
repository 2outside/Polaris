import { describe, expect, it } from 'vitest';
import {
  subscriptionCreateCloseLocked,
  subscriptionCreateNeedsVisiblePublicationRecovery,
} from './use-subscription-create-dialog-operation';

describe('subscription create dialog close gate', () => {
  it.each([
    ['start IPC is in flight', { starting: true, cancelling: false, phase: 'queued', externalCloseLocked: false }],
    ['cancel IPC is in flight', { starting: false, cancelling: true, phase: 'fetching', externalCloseLocked: false }],
    ['backend has begun commit', { starting: false, cancelling: false, phase: 'committing', externalCloseLocked: false }],
    ['backend committed but config publication is pending', { starting: false, cancelling: false, phase: 'succeeded', externalCloseLocked: false }],
    ['direct edit write is in flight', { starting: false, cancelling: false, phase: undefined, externalCloseLocked: true }],
  ])('%s blocks X/ESC/scrim and footer through one Modal gate', (_name, state) => {
    expect(subscriptionCreateCloseLocked(state)).toBe(true);
  });

  it('allows an explicit pre-commit cancel intent only after the start call settles', () => {
    expect(subscriptionCreateCloseLocked({
      starting: false, cancelling: false, phase: 'parsing', externalCloseLocked: false,
    })).toBe(false);
  });

  it('unlocks a terminal task only after an explicit publication failure', () => {
    expect(subscriptionCreateCloseLocked({
      starting: false, cancelling: false, phase: 'succeeded', externalCloseLocked: false, completionFailed: true,
    })).toBe(false);
  });

  it('publish failure transfers a closing form to the visible retry task', () => {
    expect(subscriptionCreateNeedsVisiblePublicationRecovery('succeeded', true)).toBe(true);
    expect(subscriptionCreateNeedsVisiblePublicationRecovery('succeeded', false)).toBe(false);
    expect(subscriptionCreateNeedsVisiblePublicationRecovery('failed', true)).toBe(false);
  });
});
