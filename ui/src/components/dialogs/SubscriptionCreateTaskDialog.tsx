import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from '@/lib/error-handler';
import { subscriptionErrorDetail } from '@/domain/subscription-error-text';
import { subscriptionCreateIsCancellable, type SubscriptionCreatePhase } from '@/contracts/subscription-create-operation';
import { useAppStore } from '@/store/app-store';
import { useSubscriptionCreateOperationStore } from '@/store/subscription-create-operation-store';
import { subscriptionCreateTerminalNeedsAnnouncement } from '@/store/subscription-create-operation-store';
import { Modal } from './Modal';
import { useDialogStore } from './dialog-store';

const PHASE_KEY: Record<SubscriptionCreatePhase, string> = {
  queued: 'sub.createTaskPhaseQueued',
  fetching: 'sub.createTaskPhaseFetching',
  parsing: 'sub.createTaskPhaseParsing',
  committing: 'sub.createTaskPhaseCommitting',
  succeeded: 'common.done',
  failed: 'sub.createTaskFailed',
  cancelled: 'common.cancel',
};

/** `partial` is a stable result flag; never infer it from opaque provider warnings. */
export function subscriptionCreateSuccessToastKey(partial: boolean | undefined): 'sub.added' | 'sub.addedPartial' {
  return partial ? 'sub.addedPartial' : 'sub.added';
}

/** A destroyed task must leave its terminal unhandled for the next renderer's hydrate. */
export function subscriptionCreatePublicationCanFinalize(published: boolean, hasInstance: boolean): boolean {
  return published && hasInstance;
}

/** One gate feeds Modal's X/ESC/scrim and the task footer. */
export function subscriptionCreateTaskCloseLocked({
  phase, cancelling, settling,
}: {
  phase?: SubscriptionCreatePhase;
  cancelling: boolean;
  settling: boolean;
}): boolean {
  // A committed operation stays visible until its config publication has been confirmed. On a
  // refresh failure the footer turns into an explicit retry, rather than permitting a silent clear.
  return cancelling || settling || phase === 'committing' || phase === 'succeeded';
}

function SubTaskIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}>
      <path d="M4 11a9 9 0 019 9M4 4a16 16 0 0116 16" />
      <circle cx="5" cy="19" r="1.5" />
    </svg>
  );
}

/**
 * Recovery-only surface for a locally tracked backend operation. It deliberately does not accept
 * arbitrary list history: App opens it only for the localStorage-tracked operation returned by
 * hydrate, so old terminal rows can never replay a toast after renderer reconstruction.
 */
export function SubscriptionCreateTaskDialog({ instanceId, operationId }: { instanceId: string; operationId: string }) {
  const { t } = useTranslation();
  const open = useDialogStore((s) => s.open);
  const closeInstance = useDialogStore((s) => s.closeInstance);
  const hasInstance = useDialogStore((s) => s.hasInstance);
  const snapshot = useSubscriptionCreateOperationStore((s) => s.snapshots[operationId] ?? null);
  const cancel = useSubscriptionCreateOperationStore((s) => s.cancel);
  const clearTerminal = useSubscriptionCreateOperationStore((s) => s.clearTerminal);
  const markTerminalHandled = useSubscriptionCreateOperationStore((s) => s.markTerminalHandled);
  const terminalHandledRevision = useSubscriptionCreateOperationStore((s) => s.handledTerminalRevisions[operationId]);
  const loadConfig = useAppStore((s) => s.loadConfig);
  const [cancelling, setCancelling] = useState(false);
  const [settling, setSettling] = useState(false);
  const [completionFailed, setCompletionFailed] = useState(false);
  const [publishAttempt, setPublishAttempt] = useState(0);
  const cancelInFlight = useRef(false);
  const handledAttempt = useRef<string | null>(null);

  // `succeeded` is close-critical even before the effect has set `settling`: otherwise the first
  // terminal render gives X/ESC/scrim one frame to erase the task before config publication.
  const closeDisabled = subscriptionCreateTaskCloseLocked({
    phase: snapshot?.phase,
    cancelling,
    settling,
  });

  useEffect(() => {
    if (!snapshot?.terminal) return;
    const attemptKey = snapshot.phase === 'succeeded'
      ? `${snapshot.revision}:${publishAttempt}`
      : `${snapshot.revision}`;
    if (handledAttempt.current === attemptKey) return;
    handledAttempt.current = attemptKey;

    if (snapshot.phase === 'cancelled') {
      clearTerminal(operationId);
      closeInstance(instanceId);
      return;
    }
    if (snapshot.phase === 'failed') {
      if (subscriptionCreateTerminalNeedsAnnouncement(terminalHandledRevision, snapshot)) {
        markTerminalHandled(operationId, snapshot.revision);
        toast.error(subscriptionErrorDetail(snapshot.error ?? {}, t, 'sub.previewFail'));
      }
      return;
    }
    if (snapshot.phase !== 'succeeded') return;

    const shouldToast = subscriptionCreateTerminalNeedsAnnouncement(terminalHandledRevision, snapshot);
    setSettling(true);
    void (async () => {
      await loadConfig(true);
      const published = useAppStore.getState().config?.subscriptions?.some(
        (subscription) => subscription.id === snapshot.result!.subscription.id,
      );
      if (!published) {
        console.error('[SubscriptionCreateTaskDialog] committed subscription was not published to app store');
        toast.error(t('common.configLoadFail'));
        setSettling(false);
        setCompletionFailed(true);
        return;
      }
      // Destroyed renderer/dialog: leave this terminal unhandled and tracked so hydrate retries
      // publication. A missing success toast is acceptable; a missing config publication is not.
      if (!subscriptionCreatePublicationCanFinalize(published, hasInstance(instanceId))) return;
      if (shouldToast) markTerminalHandled(operationId, snapshot.revision);
      clearTerminal(operationId);
      closeInstance(instanceId);
      if (shouldToast) {
        // `partial` is an explicit backend result field. Never derive this from warning text:
        // diagnostics may contain provider URLs or other upstream details.
        toast.success(t(subscriptionCreateSuccessToastKey(snapshot.result!.partial)));
      }
    })().catch((error) => {
      console.error('[SubscriptionCreateTaskDialog] completion refresh failed:', error);
      setSettling(false);
      setCompletionFailed(true);
    });
  }, [clearTerminal, closeInstance, hasInstance, instanceId, loadConfig, markTerminalHandled, operationId, publishAttempt, snapshot, t, terminalHandledRevision]);

  const retryPublication = () => {
    if (snapshot?.phase !== 'succeeded' || settling) return;
    setCompletionFailed(false);
    setPublishAttempt((attempt) => attempt + 1);
  };

  const requestClose = () => {
    if (snapshot?.phase === 'succeeded') return;
    if (!snapshot || snapshot.terminal) {
      if (snapshot?.terminal) clearTerminal(operationId);
      closeInstance(instanceId);
      return;
    }
    if (!subscriptionCreateIsCancellable(snapshot) || cancelling || cancelInFlight.current) return;

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
            const next = await cancel(operationId);
            // Only the terminal cancelled frame closes this task. A non-terminal response leaves
            // the operation visible and unlocks it for a later, explicit retry.
            if (!next.terminal) {
              cancelInFlight.current = false;
              setCancelling(false);
            }
          } catch (error) {
            console.error('[SubscriptionCreateTaskDialog] cancel failed:', error);
            cancelInFlight.current = false;
            setCancelling(false);
            toast.error(t('sub.previewFail'));
          }
        },
      },
    });
  };

  if (!snapshot) return null;
  const progress = snapshot.providers?.total != null
    ? t('sub.createTaskProviders', { done: snapshot.providers.done ?? 0, total: snapshot.providers.total })
    : t(PHASE_KEY[snapshot.phase]);

  return (
    <Modal
      titleId={`sub-create-task-${instanceId}`}
      title={t('sub.createTaskTitle')}
      icon={<SubTaskIcon />}
      onClose={requestClose}
      closeDisabled={closeDisabled}
      className="entry-form-dlg"
      footer={
        snapshot.terminal ? (
          snapshot.phase === 'succeeded' && completionFailed ? (
            <button type="button" className="btn flow" onClick={retryPublication} disabled={settling}>
              {t('common.retry')}
            </button>
          ) : (
            <button type="button" className="btn flow" onClick={requestClose} disabled={closeDisabled}>
              {t('common.close')}
            </button>
          )
        ) : (
          <button type="button" className="btn ghost" onClick={requestClose} disabled={closeDisabled}>
            {cancelling ? <span className="spinner spin-inline" /> : null}
            <span>{t('common.cancel')}</span>
          </button>
        )
      }
    >
      <div className={snapshot.phase === 'failed' ? 'dlg-err' : 'mesh-success'}>
        <span>{progress}</span>
      </div>
      {snapshot.phase === 'failed' && (
        <div className="card-sub">{subscriptionErrorDetail(snapshot.error ?? {}, t, 'sub.previewFail')}</div>
      )}
    </Modal>
  );
}

export default SubscriptionCreateTaskDialog;
