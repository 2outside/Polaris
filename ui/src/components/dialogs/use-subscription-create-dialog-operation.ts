import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from '@/lib/error-handler';
import type { SubscriptionCreateInput } from '@/contracts/subscription-create-operation';
import { subscriptionCreateIsCancellable } from '@/contracts/subscription-create-operation';
import { subscriptionErrorDetail } from '@/domain/subscription-error-text';
import { useAppStore } from '@/store/app-store';
import { subscriptionCreateTerminalNeedsAnnouncement, useSubscriptionCreateOperationStore } from '@/store/subscription-create-operation-store';
import { useDialogStore } from './dialog-store';
import {
  clearSubscriptionCreateOperationIdAfterTerminal,
  retainSubscriptionCreateOperationIdAfterStartError,
} from './subscription-create-operation-id';
import { openTrackedSubscriptionCreateRecovery } from '@/store/subscription-create-recovery';

interface Options {
  instanceId: string;
  onAdded?: (subId: string) => void;
  /** The form's dirty-state close path when this is not an active create operation. */
  requestFormClose: () => void;
  /** Edit-save is also a close-critical direct write, but has no operation snapshot. */
  externalCloseLocked: boolean;
}

/** A failed publication must be handed to a visible retry surface before the form may leave. */
export function subscriptionCreateNeedsVisiblePublicationRecovery(
  phase: string | undefined,
  completionFailed: boolean,
): boolean {
  return phase === 'succeeded' && completionFailed;
}

/** Shared close gate consumed by Modal (X/ESC/scrim) and the footer action. */
export function subscriptionCreateCloseLocked({
  starting, cancelling, phase, externalCloseLocked, completionFailed,
}: {
  starting: boolean;
  cancelling: boolean;
  phase?: string;
  externalCloseLocked: boolean;
  completionFailed?: boolean;
}): boolean {
  // succeeded is still close-critical until loadConfig has published the committed subscription
  // and the continuation selects its tab. It is not user-cancellable at that point either.
  return starting || cancelling || phase === 'committing' || (phase === 'succeeded' && !completionFailed) || externalCloseLocked;
}

/** Keeps backend-owned create lifecycle out of the subscription field form. */
export function useSubscriptionCreateDialogOperation({
  instanceId, onAdded, requestFormClose, externalCloseLocked,
}: Options) {
  const { t } = useTranslation();
  // This state must precede every selector that closes over it. In production TDZ is observable
  // during the very first render, before any effect or event handler can run.
  const [operationId, setOperationId] = useState<string | null>(null);
  const open = useDialogStore((s) => s.open);
  const closeInstance = useDialogStore((s) => s.closeInstance);
  const hasInstance = useDialogStore((s) => s.hasInstance);
  const createStart = useSubscriptionCreateOperationStore((s) => s.start);
  const createCancel = useSubscriptionCreateOperationStore((s) => s.cancel);
  const clearTerminal = useSubscriptionCreateOperationStore((s) => s.clearTerminal);
  const markTerminalHandled = useSubscriptionCreateOperationStore((s) => s.markTerminalHandled);
  const terminalHandledRevision = useSubscriptionCreateOperationStore((s) =>
    operationId ? s.handledTerminalRevisions[operationId] : undefined,
  );
  const loadConfig = useAppStore((s) => s.loadConfig);
  const [starting, setStarting] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [completionFailed, setCompletionFailed] = useState(false);
  const startInFlight = useRef(false);
  const cancelInFlight = useRef(false);
  const handledTerminalRevision = useRef(-1);
  const activeOperation = useSubscriptionCreateOperationStore((s) =>
    operationId ? s.snapshots[operationId] ?? null : null,
  );
  const operationBusy = activeOperation != null && !activeOperation.terminal;
  const closeLocked = subscriptionCreateCloseLocked({
    starting,
    cancelling,
    phase: activeOperation?.phase,
    externalCloseLocked,
    completionFailed,
  });

  useEffect(() => {
    if (!activeOperation?.terminal || handledTerminalRevision.current === activeOperation.revision) return;
    handledTerminalRevision.current = activeOperation.revision;
    if (activeOperation.phase === 'cancelled') {
      clearTerminal(activeOperation.operationId);
      if (clearSubscriptionCreateOperationIdAfterTerminal(activeOperation.phase)) setOperationId(null);
      closeInstance(instanceId);
      return;
    }
    if (activeOperation.phase === 'failed') {
      clearTerminal(activeOperation.operationId);
      // Terminal attempts are not idempotency candidates. A later form submit must own a new id;
      // only an explicitly uncertain start response keeps its id for status/list reattachment.
      if (clearSubscriptionCreateOperationIdAfterTerminal(activeOperation.phase)) setOperationId(null);
      setCancelling(false);
      cancelInFlight.current = false;
      toast.error(subscriptionErrorDetail(activeOperation.error ?? {}, t, 'sub.previewFail'));
      return;
    }
    if (activeOperation.phase !== 'succeeded' || !activeOperation.result) return;
    const shouldToast = subscriptionCreateTerminalNeedsAnnouncement(terminalHandledRevision, activeOperation);
    void (async () => {
      await loadConfig(true);
      const published = useAppStore.getState().config?.subscriptions?.some(
        (subscription) => subscription.id === activeOperation.result!.subscription.id,
      );
      if (!published) {
        // Do not close or toast success after a force-load that did not actually publish this
        // atomic commit. Keeping the tracked terminal enables a later renderer recovery retry.
        console.error('[subscription-create] committed subscription was not published to app store');
        toast.error(t('common.configLoadFail'));
        setCompletionFailed(true);
        return;
      }
      // A vanished form must leave the terminal available to the next renderer hydrate. Marking
      // handled before this point would make a successful backend commit invisible forever.
      if (!hasInstance(instanceId)) return;
      if (shouldToast) markTerminalHandled(activeOperation.operationId, activeOperation.revision);
      onAdded?.(activeOperation.result!.subscription.id);
      clearTerminal(activeOperation.operationId);
      closeInstance(instanceId);
      if (shouldToast) toast.success(t('sub.added'));
    })().catch((error) => {
      console.error('[subscription-create] completion refresh failed:', error);
      setCompletionFailed(true);
    });
  }, [activeOperation, clearTerminal, closeInstance, hasInstance, instanceId, loadConfig, markTerminalHandled, onAdded, t, terminalHandledRevision]);

  const start = async (subscription: SubscriptionCreateInput) => {
    if (starting || cancelling || operationBusy || startInFlight.current) return;
    startInFlight.current = true;
    setStarting(true);
    // A response-lost retry must use the exact caller-owned id. The backend then returns the
    // existing snapshot idempotently instead of registering a second writer.
    const nextOperationId = operationId ?? crypto.randomUUID();
    setOperationId(nextOperationId);
    try {
      await createStart(nextOperationId, subscription);
    } catch (error) {
      // `UncertainSubscriptionCreateStartError` retains the id in the store and must be retried
      // idempotently. A definitive start failure (including status/list absence) is safe to retry
      // as a brand-new operation instead.
      if (!retainSubscriptionCreateOperationIdAfterStartError(error)) setOperationId(null);
      throw error;
    } finally {
      startInFlight.current = false;
      setStarting(false);
    }
  };

  const requestClose = () => {
    if (closeLocked) return;
    if (activeOperation && subscriptionCreateNeedsVisiblePublicationRecovery(activeOperation.phase, completionFailed)) {
      // The form can now leave, but only by handing the still-tracked terminal to a visible task
      // which offers publication retry. It must never become recoverable only after a renderer
      // restart.
      openTrackedSubscriptionCreateRecovery(activeOperation);
      requestFormClose();
      return;
    }
    if (!activeOperation || !subscriptionCreateIsCancellable(activeOperation)) {
      requestFormClose();
      return;
    }
    const confirmId = open({
      kind: 'confirm',
      payload: {
        title: t('sub.cancelCreateTitle'),
        message: t('sub.cancelCreateMsg'),
        confirmLabel: t('sub.cancelCreate'),
        danger: true,
        onConfirm: async () => {
          if (cancelInFlight.current) return;
          cancelInFlight.current = true;
          setCancelling(true);
          closeInstance(confirmId);
          try {
            const next = await createCancel(activeOperation.operationId);
            if (!next.terminal) {
              cancelInFlight.current = false;
              setCancelling(false);
            }
          } catch (error) {
            console.error('[subscription-create] cancel failed:', error);
            cancelInFlight.current = false;
            setCancelling(false);
            toast.error(t('sub.previewFail'));
          }
        },
      },
    });
  };

  return { start, requestClose, operationBusy, starting, cancelling, closeLocked };
}
