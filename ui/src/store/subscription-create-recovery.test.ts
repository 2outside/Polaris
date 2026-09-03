import { beforeEach, describe, expect, it } from 'vitest';
import type { SubscriptionCreateSnapshot } from '@/contracts/subscription-create-operation';
import { useDialogStore } from '@/components/dialogs/dialog-store';
import { openTrackedSubscriptionCreateRecovery } from './subscription-create-recovery';

const active: SubscriptionCreateSnapshot = {
  operationId: 'renderer-rebuilt-operation', revision: 3, phase: 'parsing', terminal: false,
};

beforeEach(() => useDialogStore.getState().closeAll());

describe('subscription create visible recovery', () => {
  it('为明确跟踪的恢复 operation 打开可见任务，且重建重复执行不会叠窗', () => {
    expect(openTrackedSubscriptionCreateRecovery(active)).toBe(true);
    expect(openTrackedSubscriptionCreateRecovery(active)).toBe(false);
    expect(useDialogStore.getState().stack).toMatchObject([
      { kind: 'sub-create-task', operationId: 'renderer-rebuilt-operation' },
    ]);
  });

  it('并发的本机 tracked operation 各有一个恢复 task，不会只消费最后一个 local marker', () => {
    const second: SubscriptionCreateSnapshot = {
      operationId: 'second-renderer-rebuilt-operation', revision: 4, phase: 'failed', terminal: true,
    };

    expect(openTrackedSubscriptionCreateRecovery(active)).toBe(true);
    expect(openTrackedSubscriptionCreateRecovery(second)).toBe(true);
    expect(useDialogStore.getState().stack.filter((entry) => entry.kind === 'sub-create-task')).toMatchObject([
      { operationId: 'renderer-rebuilt-operation' },
      { operationId: 'second-renderer-rebuilt-operation' },
    ]);
  });
});
