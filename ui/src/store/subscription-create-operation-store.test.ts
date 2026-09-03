import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { SubscriptionCreateSnapshot } from '@/contracts/subscription-create-operation';

const mocks = vi.hoisted(() => ({
  createStart: vi.fn(),
  createStatus: vi.fn(),
  createCancel: vi.fn(),
  createList: vi.fn(),
  onCreateProgressReady: vi.fn(),
}));

class MemoryStorage {
  private readonly values = new Map<string, string>();

  getItem(key: string): string | null {
    return this.values.get(key) ?? null;
  }

  setItem(key: string, value: string): void {
    this.values.set(key, value);
  }

  removeItem(key: string): void {
    this.values.delete(key);
  }

  clear(): void {
    this.values.clear();
  }
}

const storage = new MemoryStorage();

vi.mock('@/ipc', () => ({
  api: {
    subscription: mocks,
  },
}));

import {
  mergeSubscriptionCreateSnapshots,
  selectTrackedSubscriptionCreateStatusBatch,
  startSubscriptionCreateStatusReconcile,
  stopSubscriptionCreateOperationSubscription,
  subscribeAndHydrateSubscriptionCreateOperations,
  subscriptionCreateTerminalNeedsAnnouncement,
  UncertainSubscriptionCreateStartError,
  useSubscriptionCreateOperationStore,
} from './subscription-create-operation-store';

const snapshot = (
  operationId: string,
  revision: number,
  phase: SubscriptionCreateSnapshot['phase'] = 'fetching',
): SubscriptionCreateSnapshot => ({
  operationId,
  revision,
  phase,
  terminal: phase === 'succeeded' || phase === 'failed' || phase === 'cancelled',
});

beforeEach(() => {
  vi.stubGlobal('localStorage', storage);
  storage.clear();
  useSubscriptionCreateOperationStore.setState({ snapshots: {}, trackedOperationIds: [], handledTerminalRevisions: {} });
  mocks.createStart.mockReset();
  mocks.createStatus.mockReset();
  mocks.createCancel.mockReset();
  mocks.createList.mockReset();
  mocks.onCreateProgressReady.mockReset();
  mocks.createStatus.mockResolvedValue(undefined);
  mocks.createList.mockResolvedValue([]);
  mocks.onCreateProgressReady.mockResolvedValue(() => {});
});

describe('subscription create operation recovery', () => {
  it('合并 list/事件时按 operationId 各自 revision，旧 list 不覆盖新 progress', () => {
    const current = {
      alpha: snapshot('alpha', 4, 'parsing'),
      beta: snapshot('beta', 2, 'queued'),
    };
    const merged = mergeSubscriptionCreateSnapshots(current, [
      snapshot('alpha', 3, 'fetching'),
      snapshot('beta', 3, 'committing'),
      snapshot('gamma', 1, 'succeeded'),
    ]);

    expect(merged.alpha.revision).toBe(4);
    expect(merged.beta.revision).toBe(3);
    expect(merged.gamma.phase).toBe('succeeded');
  });

  it('先等待 progress listener 就绪，再拉取后端 list', async () => {
    const order: string[] = [];
    mocks.onCreateProgressReady.mockImplementation(async () => {
      order.push('listen-ready');
      return () => {};
    });
    mocks.createList.mockImplementation(async () => {
      order.push('list');
      return [snapshot('server-truth', 1)];
    });

    await subscribeAndHydrateSubscriptionCreateOperations();
    await vi.waitFor(() => expect(mocks.createList).toHaveBeenCalledOnce());

    expect(order).toEqual(['listen-ready', 'list']);
    expect(useSubscriptionCreateOperationStore.getState().snapshots['server-truth']).toMatchObject({
      revision: 1,
    });
  });

  it('listener/list 窗口里的新 progress 不会被迟到 list 回滚', async () => {
    let progress: ((value: SubscriptionCreateSnapshot) => void) | undefined;
    let resolveList!: (value: SubscriptionCreateSnapshot[]) => void;
    mocks.onCreateProgressReady.mockImplementation(async (listener) => {
      progress = listener;
      return () => {};
    });
    mocks.createList.mockImplementation(
      () => new Promise<SubscriptionCreateSnapshot[]>((resolve) => { resolveList = resolve; }),
    );

    const subscribing = subscribeAndHydrateSubscriptionCreateOperations();
    await vi.waitFor(() => expect(mocks.createList).toHaveBeenCalledOnce());
    progress?.(snapshot('same-operation', 5, 'parsing'));
    resolveList([snapshot('same-operation', 4, 'fetching')]);
    await subscribing;

    await vi.waitFor(() =>
      expect(useSubscriptionCreateOperationStore.getState().snapshots['same-operation']?.revision).toBe(5),
    );
  });

  it('list 是多 operation 真值，localStorage 线索只补同一 operation 的快速 status', async () => {
    storage.setItem('polaris.subscription-create.pending', 'hinted');
    useSubscriptionCreateOperationStore.getState().track('hinted');
    mocks.createStatus.mockResolvedValue(snapshot('hinted', 6, 'parsing'));
    mocks.createList.mockResolvedValue([
      snapshot('hinted', 4, 'fetching'),
      snapshot('other-active', 2, 'queued'),
      snapshot('recent-terminal', 3, 'succeeded'),
    ]);

    await useSubscriptionCreateOperationStore.getState().hydrate();
    const snapshots = useSubscriptionCreateOperationStore.getState().snapshots;

    expect(mocks.createStatus).toHaveBeenCalledWith('hinted');
    expect(mocks.createList).toHaveBeenCalledOnce();
    expect(snapshots.hinted.revision).toBe(6);
    expect(snapshots['other-active'].phase).toBe('queued');
    expect(snapshots['recent-terminal'].terminal).toBe(true);
  });

  it('只把本机跟踪 operation 交给恢复 UI，list 里的历史 terminal 不会成为 recovered', async () => {
    useSubscriptionCreateOperationStore.getState().track('tracked-active');
    mocks.createStatus.mockResolvedValue(snapshot('tracked-active', 5, 'fetching'));
    mocks.createList.mockResolvedValue([
      snapshot('old-success', 9, 'succeeded'),
      snapshot('tracked-active', 4, 'queued'),
    ]);

    const recovered = await useSubscriptionCreateOperationStore.getState().hydrate();

    expect(recovered).toMatchObject([{ operationId: 'tracked-active', revision: 5 }]);
    expect(useSubscriptionCreateOperationStore.getState().snapshots['old-success']).toMatchObject({ terminal: true });
  });

  it('本机线索既不在 list 也无法 status 恢复时清除，避免下次重建重复尝试', async () => {
    useSubscriptionCreateOperationStore.getState().track('gone');
    mocks.createStatus.mockRejectedValue(new Error('not found'));

    expect(await useSubscriptionCreateOperationStore.getState().hydrate()).toEqual([]);
    expect(useSubscriptionCreateOperationStore.getState().trackedOperationIds).toEqual([]);
    expect(storage.getItem('polaris.subscription-create.pending')).toBeNull();
  });

  it('hydrate 只能清掉启动时已跟踪且 status/list 都缺失的 id，不能误删期间新 start 的 id', async () => {
    const store = useSubscriptionCreateOperationStore.getState();
    store.track('stale-at-start');
    mocks.createStatus.mockRejectedValue(new Error('not found'));
    let resolveList!: (snapshots: SubscriptionCreateSnapshot[]) => void;
    mocks.createList.mockImplementation(
      () => new Promise<SubscriptionCreateSnapshot[]>((resolve) => { resolveList = resolve; }),
    );

    const hydrating = store.hydrate();
    await vi.waitFor(() => expect(mocks.createList).toHaveBeenCalledOnce());
    store.track('started-during-hydrate');
    resolveList([]);
    await hydrating;

    expect(useSubscriptionCreateOperationStore.getState().trackedOperationIds).toEqual(['started-during-hydrate']);
  });

  it('两个本机 tracked operation 一起持久化并都从 list/status 恢复，历史 terminal 不混入', async () => {
    const store = useSubscriptionCreateOperationStore.getState();
    store.track('first');
    store.track('second');
    mocks.createStatus.mockImplementation(async (operationId) =>
      operationId === 'first' ? snapshot('first', 3, 'fetching') : snapshot('second', 4, 'failed'),
    );
    mocks.createList.mockResolvedValue([
      snapshot('first', 2, 'queued'),
      snapshot('second', 4, 'failed'),
      snapshot('old-list-only', 8, 'succeeded'),
    ]);

    const recovered = await store.hydrate();

    expect(recovered.map((item) => item.operationId).sort()).toEqual(['first', 'second']);
    expect(useSubscriptionCreateOperationStore.getState().trackedOperationIds).toEqual(['first', 'second']);
    expect(storage.getItem('polaris.subscription-create.pending')).toContain('"operationIds":["first","second"]');
  });

  it('start reply 丢失后按同一客户端 id status 重附，不产生第二个 operation id', async () => {
    mocks.createStart.mockRejectedValue(new Error('response lost'));
    mocks.createStatus.mockResolvedValue(snapshot('client-id', 3, 'parsing'));

    const recovered = await useSubscriptionCreateOperationStore.getState().start('client-id', {
      name: 'provider', url: 'https://example.test/sub', autoUpdate: false,
    });

    expect(recovered).toMatchObject({ operationId: 'client-id', phase: 'parsing' });
    expect(mocks.createStatus).toHaveBeenCalledWith('client-id');
    expect(mocks.createStart).toHaveBeenCalledTimes(1);
    expect(useSubscriptionCreateOperationStore.getState().trackedOperationIds).toEqual(['client-id']);
  });

  it('status/list 都不可达时保留同一 id 并标记为不确定，禁止调用方悄悄换 UUID', async () => {
    mocks.createStart.mockRejectedValue(new Error('response lost'));
    mocks.createStatus.mockRejectedValue(new Error('transport unavailable'));
    mocks.createList.mockRejectedValue(new Error('transport unavailable'));

    await expect(useSubscriptionCreateOperationStore.getState().start('same-id', {
      name: 'provider', url: 'https://example.test/sub', autoUpdate: false,
    })).rejects.toBeInstanceOf(UncertainSubscriptionCreateStartError);
    expect(useSubscriptionCreateOperationStore.getState().trackedOperationIds).toEqual(['same-id']);
  });

  it('terminal handled revision 持久化但不 untrack，重建仍可见而不会重放 toast', () => {
    const store = useSubscriptionCreateOperationStore.getState();
    store.track('failed-visible');
    store.markTerminalHandled('failed-visible', 7);

    expect(useSubscriptionCreateOperationStore.getState().handledTerminalRevisions).toMatchObject({
      'failed-visible': 7,
    });
    expect(useSubscriptionCreateOperationStore.getState().trackedOperationIds).toEqual(['failed-visible']);
    expect(storage.getItem('polaris.subscription-create.pending')).toContain('"failed-visible":7');
    const failed = snapshot('failed-visible', 7, 'failed');
    expect(subscriptionCreateTerminalNeedsAnnouncement(7, failed)).toBe(false);
    expect(subscriptionCreateTerminalNeedsAnnouncement(undefined, failed)).toBe(true);
  });
});

describe('subscription create status reconcile fallback', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('dropped terminal progress event is recovered by status and revision-merged', async () => {
    const store = useSubscriptionCreateOperationStore.getState();
    store.track('lost-terminal');
    store.accept(snapshot('lost-terminal', 4, 'committing'));
    mocks.createStatus.mockResolvedValue(snapshot('lost-terminal', 5, 'succeeded'));
    const stop = startSubscriptionCreateStatusReconcile({ delayMs: 10 });

    await vi.advanceTimersByTimeAsync(10);

    expect(mocks.createStatus).toHaveBeenCalledWith('lost-terminal');
    expect(useSubscriptionCreateOperationStore.getState().snapshots['lost-terminal']).toMatchObject({
      revision: 5, phase: 'succeeded', terminal: true,
    });
    stop();
  });

  it('does not overlap status rounds while a prior round is in flight', async () => {
    const store = useSubscriptionCreateOperationStore.getState();
    store.track('slow');
    store.accept(snapshot('slow', 1, 'parsing'));
    let resolveStatus!: (value: SubscriptionCreateSnapshot) => void;
    mocks.createStatus.mockImplementation(
      () => new Promise<SubscriptionCreateSnapshot>((resolve) => { resolveStatus = resolve; }),
    );
    const stop = startSubscriptionCreateStatusReconcile({ delayMs: 10 });

    await vi.advanceTimersByTimeAsync(10);
    await vi.advanceTimersByTimeAsync(100);
    expect(mocks.createStatus).toHaveBeenCalledTimes(1);

    resolveStatus(snapshot('slow', 2, 'parsing'));
    await Promise.resolve();
    stop();
  });

  it('terminal tracked tasks receive no further status requests', async () => {
    const store = useSubscriptionCreateOperationStore.getState();
    store.track('becomes-terminal');
    store.accept(snapshot('becomes-terminal', 1, 'committing'));
    mocks.createStatus.mockResolvedValue(snapshot('becomes-terminal', 2, 'cancelled'));
    const stop = startSubscriptionCreateStatusReconcile({ delayMs: 10 });

    await vi.advanceTimersByTimeAsync(10);
    await vi.advanceTimersByTimeAsync(30);
    expect(mocks.createStatus).toHaveBeenCalledTimes(1);
    stop();
  });

  it('bounds one round to four locally tracked nonterminal operations', async () => {
    const store = useSubscriptionCreateOperationStore.getState();
    for (const operationId of ['one', 'two', 'three', 'four', 'five']) {
      store.track(operationId);
      store.accept(snapshot(operationId, 1, 'fetching'));
    }
    mocks.createStatus.mockImplementation(async (operationId) => snapshot(operationId, 2, 'fetching'));
    const stop = startSubscriptionCreateStatusReconcile({ delayMs: 10 });

    await vi.advanceTimersByTimeAsync(10);

    expect(mocks.createStatus.mock.calls.map(([operationId]) => operationId)).toEqual(['one', 'two', 'three', 'four']);
    stop();
  });

  it('rotates past more than four stale tracked ids so a later active operation is eventually polled', async () => {
    const store = useSubscriptionCreateOperationStore.getState();
    for (const operationId of ['stale-1', 'stale-2', 'stale-3', 'stale-4', 'active']) {
      store.track(operationId);
      store.accept(snapshot(operationId, 1, 'fetching'));
    }
    mocks.createStatus.mockImplementation(async (operationId) => {
      if (operationId === 'active') return snapshot('active', 2, 'parsing');
      throw new Error('stale status');
    });
    const stop = startSubscriptionCreateStatusReconcile({ delayMs: 10, maxDelayMs: 20 });

    await vi.advanceTimersByTimeAsync(10);
    await vi.advanceTimersByTimeAsync(20);

    expect(mocks.createStatus.mock.calls.map(([operationId]) => operationId)).toContain('active');
    stop();
  });

  it('interprets cursor against the current tracked set after a tracked-id mutation', () => {
    const first = selectTrackedSubscriptionCreateStatusBatch(
      ['one', 'two', 'three', 'four', 'five'], {}, 0,
    );
    const afterMutation = selectTrackedSubscriptionCreateStatusBatch(
      ['one', 'five', 'six'], {}, first.nextCursor,
    );
    expect(afterMutation.operationIds).toEqual(['five', 'six', 'one']);
    expect(afterMutation.operationIds.every(Boolean)).toBe(true);
  });

  it('renderer cleanup stops both the event subscription and scheduled status fallback', async () => {
    const off = vi.fn();
    const stopReconcile = vi.fn();
    stopSubscriptionCreateOperationSubscription({ off, stopReconcile });
    expect(off).toHaveBeenCalledOnce();
    expect(stopReconcile).toHaveBeenCalledOnce();

    const store = useSubscriptionCreateOperationStore.getState();
    store.track('cleanup');
    store.accept(snapshot('cleanup', 1, 'fetching'));
    const stop = startSubscriptionCreateStatusReconcile({ delayMs: 10 });
    stop();
    await vi.advanceTimersByTimeAsync(100);
    expect(mocks.createStatus).not.toHaveBeenCalled();
  });
});
