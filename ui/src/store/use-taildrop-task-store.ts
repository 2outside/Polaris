/**
 * Taildrop 发件任务的窗口级镜像。
 *
 * 弹窗只是视图，不是任务所有者：关掉弹窗、切屏或进入轻量模式都不能清掉发送状态。主窗口根先挂
 * `event:taildropTaskUpdated`，再 pull 一次后端有界快照；每条任务的 `revision` 拒绝旧水合覆盖新事件。
 */
import { create } from 'zustand';
import { api } from '@/ipc';
import type { TaildropTaskSnapshot } from '@/contracts/taildrop';

export const MAX_TAILDROP_TASK_SNAPSHOTS = 32;

export type TaildropTaskMap = Record<string, TaildropTaskSnapshot>;

export function isTaildropTaskTerminal(task: TaildropTaskSnapshot): boolean {
  return task.phase === 'completed' || task.phase === 'failed' || task.phase === 'canceled';
}

/** 单帧归并：taskId 为空或 revision 倒退直接丢弃；总表始终封顶。 */
export function reduceTaildropTaskSnapshot(
  tasks: TaildropTaskMap,
  snapshot: TaildropTaskSnapshot
): TaildropTaskMap {
  if (!snapshot.taskId) return tasks;
  const current = tasks[snapshot.taskId];
  if (current && current.revision >= snapshot.revision) return tasks;
  if (current === snapshot) return tasks;

  const next = { ...tasks, [snapshot.taskId]: snapshot };
  const ids = Object.keys(next);
  if (ids.length <= MAX_TAILDROP_TASK_SNAPSHOTS) return next;

  // 后端同样封顶 32；这里仍独立兜底，防事件与重建水合交错时短暂并集超过上限。
  ids.sort((a, b) => {
    const ta = next[a];
    const tb = next[b];
    const terminalDelta = Number(isTaildropTaskTerminal(tb)) - Number(isTaildropTaskTerminal(ta));
    return terminalDelta || ta.updatedAtMs - tb.updatedAtMs;
  });
  while (ids.length > MAX_TAILDROP_TASK_SNAPSHOTS) {
    const id = ids.shift();
    if (id) delete next[id];
  }
  return next;
}

export function mergeTaildropTaskSnapshots(
  tasks: TaildropTaskMap,
  snapshots: readonly TaildropTaskSnapshot[]
): TaildropTaskMap {
  return snapshots.reduce(reduceTaildropTaskSnapshot, tasks);
}

interface TaildropTaskState {
  tasks: TaildropTaskMap;
  applySnapshot: (snapshot: TaildropTaskSnapshot) => void;
  hydrateSnapshots: (snapshots: readonly TaildropTaskSnapshot[]) => void;
}

export const useTaildropTaskStore = create<TaildropTaskState>((set) => ({
  tasks: {},
  applySnapshot: (snapshot) =>
    set((state) => ({ tasks: reduceTaildropTaskSnapshot(state.tasks, snapshot) })),
  hydrateSnapshots: (snapshots) =>
    set((state) => ({ tasks: mergeTaildropTaskSnapshots(state.tasks, snapshots) })),
}));

/** 窗口级事件订阅；必须在任何水合 pull 之前挂上。 */
export function subscribeTaildropTaskEvents(): () => void {
  return api.server.onTaildropTaskUpdated((snapshot) => {
    useTaildropTaskStore.getState().applySnapshot(snapshot);
  });
}

/** 窗口重建 / 首次挂载水合。与事件竞态由 per-task revision 收敛。 */
export async function hydrateTaildropTasks(): Promise<void> {
  const snapshots = await api.server.taildropTasks();
  useTaildropTaskStore.getState().hydrateSnapshots(snapshots);
}
