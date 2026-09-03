import { beforeEach, describe, expect, it } from 'vitest';
import { useDialogStore } from './dialog-store';

describe('dialog instance identity', () => {
  beforeEach(() => useDialogStore.getState().closeAll());

  it('closing an old async owner never pops a newer dialog', () => {
    const store = useDialogStore.getState();
    const oldId = store.open({ kind: 'node' });
    store.closeInstance(oldId);
    const newerId = store.open({ kind: 'import' });

    store.closeInstance(oldId);

    expect(useDialogStore.getState().stack).toHaveLength(1);
    expect(useDialogStore.getState().stack[0]?.instanceId).toBe(newerId);
  });

  it('open returns unique stable identities for otherwise identical dialogs', () => {
    const store = useDialogStore.getState();
    const first = store.open({ kind: 'node' });
    const second = store.open({ kind: 'node' });

    expect(first).not.toBe(second);
    expect(store.hasInstance(first)).toBe(true);
    expect(store.hasInstance(second)).toBe(true);
  });
});
