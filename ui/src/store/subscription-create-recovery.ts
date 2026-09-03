import type { SubscriptionCreateSnapshot } from '@/contracts/subscription-create-operation';
import { useDialogStore } from '@/components/dialogs/dialog-store';

/** Open exactly one visible recovery task for the caller-proven local operation. */
export function openTrackedSubscriptionCreateRecovery(snapshot: SubscriptionCreateSnapshot): boolean {
  const dialogs = useDialogStore.getState();
  if (dialogs.stack.some((entry) => entry.kind === 'sub-create-task' && entry.operationId === snapshot.operationId)) {
    return false;
  }
  dialogs.open({ kind: 'sub-create-task', operationId: snapshot.operationId });
  return true;
}
