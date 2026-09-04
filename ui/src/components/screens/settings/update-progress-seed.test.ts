/**
 * 更新卡挂载期接线（[`wireUpdateProgress`]）的行为门 —— 「切走再切回来，进度丢了」的常驻防线。
 *
 * # 守的三条决定
 *
 *  1. **回读要能把卡片从 idle 拉出来**：组件重挂载后只订阅事件是不够的，下载已经下完时那一帧
 *     永不再来，卡片会永远停在「检查更新」。
 *  2. **回读永远让位给事件**：回读是异步的，它描述的是**发起那一刻**，必然不比订阅期间已收到的
 *     事件新。让它落地就会把已经完成的下载倒退回进度条。
 *  3. **回读为空不得编造态**：后端 `update_get_progress` 在「本次进程一帧都没发过」时返 `null`，
 *     UI 保持自己的初值（idle），既不崩也不卡在 loading。
 *
 * # 为什么测的是 `wireUpdateProgress` 而不是 `useAppUpdate`
 *
 * 本仓 vitest 是 node 环境、刻意不装 jsdom / testing-library（见
 * `screens/nodes/SubInfoBar.progress.test.tsx` 头注），effect 跑不起来 ⇒ 真 hook 观测不到。
 * 接线被抽成注入式纯函数正是为了让**顺序与竞态**这两条真判据可测；hook 里剩下的是把一份
 * `UpdateCardPatch` 摊到各 `useState` 上，逐字段一一对应，由 tsc 管。
 *
 * 断言落在 `applyPatch` 收到的 [`UpdateCardPatch`] 上 —— 那就是卡片的状态本身（`us` /
 * `percentage` / `info` / `path` 与 hook 的 `useState` 一一对应），不是平行复刻出来的第二份映射：
 * `updateCardPatch` 的调用点在被测函数内部，测试没有机会自己再翻译一遍。
 *
 * # 明确不在射程
 *
 *  · 那 7 行 `setX(patch.x)`（React 管道，node 下观测不到，类型已钉死字段对应）；
 *  · 后端槽本身的行为（`emit_progress` 存什么、终态帧不清空）—— 在
 *    `src-tauri/src/commands/updater/tests/mod.rs` 那一侧。
 */
import { describe, it, expect } from 'vitest';
import type { UpdateProgress, UpdateProgressManifest } from '@/ipc/api-client';
import { wireUpdateProgress, type UpdateCardPatch } from './settings-logic';

const MANIFEST: UpdateProgressManifest = {
  version: '1.2.3',
  downloadUrl: 'https://example.invalid/polaris-1.2.3.AppImage',
  fileSize: 10_000_000,
  publishedAt: '2026-09-01T00:00:00Z',
  isPrerelease: false,
  fileName: 'polaris-1.2.3.AppImage',
};

/** 在途帧：正是「切走再切回来」那一刻后端槽里躺着的东西。 */
const DOWNLOADING_47: UpdateProgress = {
  status: 'downloading',
  percentage: 47,
  receivedBytes: 4_700_000,
  updateInfo: MANIFEST,
};

/** 终态帧：下完之后不会再有下一帧 —— 只靠订阅的话卡片就此永远停在 idle。 */
const DOWNLOADED: UpdateProgress = {
  status: 'downloaded',
  percentage: 100,
  filePath: '/var/tmp/polaris-1.2.3.AppImage',
  verified: true,
  updateInfo: MANIFEST,
};

interface Harness {
  /** `subscribe` / `readSnapshot` 的实际调用顺序（本改动的第一条判据）。 */
  order: string[];
  /** 模拟后端推一帧事件。 */
  emit: (p: UpdateProgress) => void;
  /** 模拟回读返回（可在 `emit` 之后调用 ⇒ 构造「事件先到、回读后返回」的竞态）。 */
  settleSnapshot: (p: UpdateProgress | null) => void;
  /** 模拟回读失败。 */
  rejectSnapshot: (e: unknown) => void;
  /** 落到卡片上的每一次改动，按发生顺序。 */
  patches: UpdateCardPatch[];
  /** `wireUpdateProgress` 返回的退订闭包。 */
  dispose: () => void;
  /** 底层订阅的退订被调了几次。 */
  unsubscribed: () => number;
}

function harness(): Harness {
  const order: string[] = [];
  const patches: UpdateCardPatch[] = [];
  let emit: ((p: UpdateProgress) => void) | null = null;
  let settleSnapshot!: (p: UpdateProgress | null) => void;
  let rejectSnapshot!: (e: unknown) => void;
  let unsubscribed = 0;
  const snapshot = new Promise<UpdateProgress | null>((resolve, reject) => {
    settleSnapshot = resolve;
    rejectSnapshot = reject;
  });
  const dispose = wireUpdateProgress({
    subscribe: (onFrame) => {
      order.push('subscribe');
      emit = onFrame;
      return () => {
        unsubscribed += 1;
      };
    },
    readSnapshot: () => {
      order.push('readSnapshot');
      return snapshot;
    },
    resetIntegrity: () => {
      order.push('resetIntegrity');
    },
    applyPatch: (patch) => patches.push(patch),
  });
  return {
    order,
    emit: (p) => {
      if (!emit) throw new Error('订阅还没建立 —— 本用例的前提已经不成立');
      emit(p);
    },
    settleSnapshot,
    rejectSnapshot,
    patches,
    dispose,
    unsubscribed: () => unsubscribed,
  };
}

/** 排空微任务队列（回读的 `.then` 在其中）。不碰计时器、不碰网络。 */
const flush = async (): Promise<void> => {
  for (let i = 0; i < 4; i += 1) await Promise.resolve();
};

describe('挂载期快照回读把卡片从 idle 拉出来', () => {
  it('回读到 downloading/47% ⇒ 卡片是 downloading 且 47%（不是 idle）', async () => {
    const h = harness();
    // 变异对照：把 `wireUpdateProgress` 里 seed 那一行（`applyFrame(snapshot)`）删掉 ⇒ 本条转红。
    expect(h.patches, '回读还没返回，此刻卡片不该被动过').toEqual([]);

    h.settleSnapshot(DOWNLOADING_47);
    await flush();

    expect(h.patches).toHaveLength(1);
    expect(h.patches[0]!.us).toBe('downloading');
    expect(h.patches[0]!.percentage).toBe(47);
    expect(h.patches[0]!.received).toBe(4_700_000);
    // 随行事实同样要落地：卡片右半边的版本号/体积、以及失败时重试要用的地址都在里面。
    expect(h.patches[0]!.info?.version).toBe('1.2.3');
  });

  it('回读到已下完的那一帧 ⇒ 卡片是 downloaded 并拿到安装包路径（这一帧永不再来）', async () => {
    const h = harness();
    h.settleSnapshot(DOWNLOADED);
    await flush();

    expect(h.patches).toHaveLength(1);
    expect(h.patches[0]!.us).toBe('downloaded');
    expect(h.patches[0]!.path).toBe('/var/tmp/polaris-1.2.3.AppImage');
    // 「重启并安装」首行 `if (!downloadedPath) return`：路径没落地就是个哑键。
    expect(h.patches[0]!.integrity).toBe('verified');
  });

  it('回读返回 null ⇒ 一个字段都不动（卡片保持 idle，不崩也不卡在 loading）', async () => {
    const h = harness();
    h.settleSnapshot(null);
    await flush();

    expect(h.patches, 'null 是「后端没有可讲的进度」，不是一个 idle 帧').toEqual([]);
    // 正向对照：这一路没坏 —— 后续真事件照常落地（否则本条在「接线整个失效」时也绿）。
    h.emit(DOWNLOADING_47);
    expect(h.patches.map((p) => p.us)).toEqual(['downloading']);
  });

  it('回读失败 ⇒ 退回「只有事件」的老行为，不抛、不影响已建立的订阅', async () => {
    const h = harness();
    h.rejectSnapshot(new Error('command not found'));
    await flush();

    expect(h.patches).toEqual([]);
    h.emit(DOWNLOADED);
    expect(h.patches.map((p) => p.us)).toEqual(['downloaded']);
  });
});

describe('顺序与竞态：回读永远让位给事件', () => {
  it('先订阅、后回读（反过来会漏掉两者之间到达的那一帧）', () => {
    const h = harness();
    // 变异对照：把 `readSnapshot()` 挪到 `subscribe()` 之前 ⇒ 本条转红。
    expect(h.order).toEqual(['subscribe', 'readSnapshot']);
  });

  it('订阅先收到 downloaded、回读随后返回更旧的 downloading/47% ⇒ 卡片仍是 downloaded', async () => {
    const h = harness();
    // 变异对照：把 `if (sawEvent || !snapshot) return;` 里的 `sawEvent ||` 去掉 ⇒ 本条转红
    //（卡片会从「下载完成」倒退回 47% 的进度条）。
    h.emit(DOWNLOADED);
    h.settleSnapshot(DOWNLOADING_47);
    await flush();

    expect(h.patches.map((p) => p.us), '回读比事件旧，落地就是一次倒退').toEqual(['downloaded']);
    expect(h.patches[h.patches.length - 1]!.percentage).toBe(100);
  });

  it('否决只针对这一次回读：其后的真事件照常落地', async () => {
    const h = harness();
    h.emit(DOWNLOADING_47);
    h.settleSnapshot(DOWNLOADING_47);
    await flush();
    h.emit(DOWNLOADED);

    expect(h.patches.map((p) => p.us)).toEqual(['downloading', 'downloaded']);
  });
});

describe('退订原样透传（卸载后不得再写已卸载组件的 state）', () => {
  it('返回的闭包调下去就是订阅侧的退订，且不多不少一次', () => {
    const h = harness();
    expect(h.unsubscribed()).toBe(0);
    h.dispose();
    expect(h.unsubscribed()).toBe(1);
  });
});
