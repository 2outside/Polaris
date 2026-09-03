import { useCallback, useState } from 'react';
import type { TFunction } from 'i18next';
import type { ServerConfig } from '@/contracts/types';
import type { SpeedTestInvokeResult } from '@/contracts/speed-test';
import { api } from '@/ipc';
import { toast } from '@/lib/error-handler';
import {
  speedTestErrorMessage,
  notInPoolMessage,
  speedTestBlockedMessage,
} from '../shared/speedtest-feedback';
import { speedTestableIds, type SpeedTestCaps } from '@/domain/endpoint-routes';
import { useLatencyStore } from '@/store/use-latency-store';
import {
  speedTestIdsForSelection,
  type SpeedTestBlockReason,
} from './nodes-logic';

interface UseNodeSpeedTestArgs {
  servers: ServerConfig[];
  visibleServers: ServerConfig[];
  selectedIds: ReadonlySet<string>;
  speedTestCaps: SpeedTestCaps;
  stagedOnly: ReadonlySet<string>;
  t: TFunction;
}

export function useNodeSpeedTest({
  servers,
  visibleServers,
  selectedIds,
  speedTestCaps,
  stagedOnly,
  t,
}: UseNodeSpeedTestArgs) {
  const applyLatencyResults = useLatencyStore((s) => s.applyLatencyResults);
  const [testing, setTesting] = useState(false);

  const speedTestError = useCallback(
    (err: unknown, ctx: string) => {
      console.error(`[NodesScreen] ${ctx} failed:`, err);
      toast.error(speedTestErrorMessage(err, t));
    },
    [t],
  );

  const absorbRunResult = useCallback(
    (result: SpeedTestInvokeResult) => {
      applyLatencyResults(result.results);
      const message = notInPoolMessage(result, t);
      if (message) toast.info(message);
    },
    [applyLatencyResults, t],
  );

  const runSpeedTest = useCallback(
    async (ids: string[], context: string) => {
      if (ids.length === 0) {
        toast.info(t('nodes.noTestableNodes'));
        return;
      }
      setTesting(true);
      try {
        absorbRunResult(await api.server.speedTest(ids));
      } catch (err) {
        speedTestError(err, context);
      } finally {
        setTesting(false);
      }
    },
    [absorbRunResult, speedTestError, t],
  );

  const testAll = useCallback(
    () => runSpeedTest(speedTestableIds(servers, speedTestCaps, stagedOnly), 'speedTest all'),
    [servers, speedTestCaps, stagedOnly, runSpeedTest],
  );
  const testVisible = useCallback(
    () => runSpeedTest(speedTestableIds(visibleServers, speedTestCaps, stagedOnly), 'speedTest visible'),
    [visibleServers, speedTestCaps, stagedOnly, runSpeedTest],
  );
  const testSelected = useCallback(
    () =>
      runSpeedTest(
        speedTestIdsForSelection(visibleServers, selectedIds, speedTestCaps, stagedOnly),
        'speedTest selected',
      ),
    [visibleServers, selectedIds, speedTestCaps, stagedOnly, runSpeedTest],
  );
  const testOne = useCallback(
    async (server: ServerConfig) => {
      try {
        absorbRunResult(await api.server.speedTest([server.id]));
      } catch (err) {
        speedTestError(err, 'speedTest one');
      }
    },
    [absorbRunResult, speedTestError],
  );
  const blockedHint = useCallback(
    (reason: SpeedTestBlockReason) => speedTestBlockedMessage(reason, t),
    [t],
  );

  return { testing, testAll, testVisible, testSelected, testOne, blockedHint };
}
