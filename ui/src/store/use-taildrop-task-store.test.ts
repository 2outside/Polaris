import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { TaildropTaskPhase, TaildropTaskSnapshot } from '@/contracts/taildrop';
import {
  MAX_TAILDROP_TASK_SNAPSHOTS,
  mergeTaildropTaskSnapshots,
  reduceTaildropTaskSnapshot,
  type TaildropTaskMap,
} from './use-taildrop-task-store';

function task(
  id: string,
  revision: number,
  phase: TaildropTaskPhase = 'sending',
  updatedAtMs = revision
): TaildropTaskSnapshot {
  return {
    taskId: id,
    serverId: 'server-a',
    peerStableId: 'peer-a',
    phase,
    files: [{ name: `${id}.bin`, size: 10, sentBytes: 3, completed: false }],
    sentBytes: 3,
    acknowledgedBytes: 2,
    totalBytes: 10,
    startedAtMs: 1,
    updatedAtMs,
    revision,
  };
}

describe('Taildrop task store reducer', () => {
  it('同 taskId 只接受严格更新的 revision', () => {
    const current = reduceTaildropTaskSnapshot({}, task('a', 3));
    expect(reduceTaildropTaskSnapshot(current, task('a', 2, 'failed'))).toBe(current);
    expect(reduceTaildropTaskSnapshot(current, task('a', 3, 'completed'))).toBe(current);
    expect(reduceTaildropTaskSnapshot(current, task('a', 4, 'completed'))['a'].phase).toBe(
      'completed'
    );
  });

  it('水合与事件归并后仍严格封顶，并优先驱逐最老终态', () => {
    let tasks: TaildropTaskMap = {};
    tasks = reduceTaildropTaskSnapshot(tasks, task('active', 1, 'sending', 1));
    for (let i = 0; i < MAX_TAILDROP_TASK_SNAPSHOTS; i += 1) {
      tasks = reduceTaildropTaskSnapshot(tasks, task(`done-${i}`, 1, 'completed', i + 2));
    }
    expect(Object.keys(tasks)).toHaveLength(MAX_TAILDROP_TASK_SNAPSHOTS);
    expect(tasks.active).toBeDefined();
    expect(tasks['done-0']).toBeUndefined();
  });

  it('窗口重建的旧 pull 不会覆盖期间已到达的新事件', () => {
    const event = reduceTaildropTaskSnapshot({}, task('a', 5, 'sending'));
    const merged = mergeTaildropTaskSnapshots(event, [task('a', 4, 'connecting')]);
    expect(merged['a']).toMatchObject({ revision: 5, phase: 'sending' });
  });

  it('空 taskId 不进入永远无人消费的键', () => {
    const tasks: TaildropTaskMap = {};
    expect(reduceTaildropTaskSnapshot(tasks, task('', 1))).toBe(tasks);
  });
});

describe('Taildrop task 纵向接线契约', () => {
  const src = resolve(__dirname, '..');
  const read = (rel: string): string => readFileSync(resolve(src, rel), 'utf8');
  // api-client 已按域拆成 barrel + `ipc/api/` 目录；内容扫描要看整个模块面。
  const readApiClient = (): string => {
    const dir = resolve(src, 'ipc/api');
    const files = readdirSync(dir).map((f) => readFileSync(resolve(dir, f), 'utf8'));
    return read('ipc/api-client.ts') + '\n' + files.join('\n');
  };

  it('主窗口先挂持久事件，再 pull 水合；弹窗不拥有订阅', () => {
    const app = read('App.tsx');
    const effect = app.slice(app.indexOf('const off = subscribeTaildropTaskEvents()'));
    expect(effect.indexOf('subscribeTaildropTaskEvents()')).toBeLessThan(
      effect.indexOf('hydrateTaildropTasks()')
    );
    expect(read('components/dialogs/TaildropDialog.tsx')).not.toContain(
      'subscribeTaildropTaskEvents'
    );
  });

  it('Rust emit 与 TS listen 的跨语言事件名逐字一致', () => {
    const rust = readFileSync(resolve(src, '../../src-tauri/src/events.rs'), 'utf8');
    const channels = read('domain/ipc-channels.ts');
    expect(rust).toContain(
      'EVENT_TAILDROP_TASK_UPDATED: &str = "event:taildropTaskUpdated"'
    );
    expect(channels).toContain(
      "EVENT_TAILDROP_TASK_UPDATED: 'event:taildropTaskUpdated'"
    );
    expect(readApiClient()).toContain(
      'listen(IPC_CHANNELS.EVENT_TAILDROP_TASK_UPDATED, listener)'
    );
  });

  it('快照与取消 command 均注册，弹窗消费 taskId 取消腿', () => {
    const main = readFileSync(resolve(src, '../../src-tauri/src/main.rs'), 'utf8');
    expect(main).toMatch(/taildrop_tasks,\s*taildrop_task_cancel,/);
    const dialog = read('components/dialogs/TaildropDialog.tsx');
    expect(dialog).toContain('taildropTasks(serverId)');
    expect(dialog).toContain('taildropTaskCancel(taskId)');
  });

  it('既有 STATUS relay 的真实计数变化会叫醒收件箱重拉', () => {
    const dialog = read('components/dialogs/TaildropDialog.tsx');
    expect(dialog).toContain('status?.waitingFileCount');
    expect(dialog).toContain('status?.receivingFileCount');
    expect(dialog).toContain('status?.unreadFileCount');
    expect(dialog).toMatch(/status\?\.waitingFileCount[\s\S]*status\?\.receivingFileCount[\s\S]*status\?\.unreadFileCount/);
  });
});
