/**
 * 测速进度 toast 协调器门 —— 守「同 key、sticky、必有终态」三条。
 *
 * # 射程与不射程（如实记账）
 *
 * 本仓 vitest 是 `environment:'node'`、无 jsdom（`vite.config.ts:76`）⇒
 *  · **能测**：本文件几乎全部。协调器是纯 TS（无 React、无 DOM），事件流与 toast 出口都可注入，
 *    故下面用假事件流驱动一整轮测速、断言假 toast 收到的**每一次调用及其 options** —— 这不是
 *    正则扫描，是真行为；静默超时也用 vitest 假计时器真跑到点。
 *  · **测不到**：这些 options 传到 `Toaster` 之后屏幕上真的只有一条、真的没被 2.2s 收走、
 *    弹窗打开时真的没被 `::backdrop` 压住。队列语义那半由 `components/layout/toast-queue.test.ts`
 *    的纯逻辑接住，剩下的渲染/层叠语义 node 环境不可观测，靠真机验收。
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import {
  SPEEDTEST_IDLE_TIMEOUT_MS,
  SPEEDTEST_TOAST_KEY,
  initialSpeedTestToastState,
  planSpeedTestRun,
  reduceSpeedTestDone,
  reduceSpeedTestIdle,
  reduceSpeedTestProgress,
  subscribeSpeedTestProgressToast,
  type SpeedTestDonePayload,
  type SpeedTestProgress,
  type SpeedTestToastDeps,
} from './speedtest-progress-toast';
import {
  maskRustCommentsAndStrings,
  moduleSource,
  rustConstU64,
} from '../contracts/rust-source.test-support';

interface Call {
  level: 'info' | 'success' | 'warning';
  msg: string;
  opts?: {
    key?: string;
    sticky?: boolean;
    description?: string;
    actions?: Array<{ label: string; onClick: () => void }>;
    dismiss?: { label: string };
  };
}

/**
 * 假外部面：捕获两条事件流的监听器 + 记录每一次 toast 调用（含 options）。
 *
 * `servers` / `runs` 让恢复动作可测：前者是「点击那一刻的当前节点集」（测试可随时改），
 * 后者记录**实际发出去的测速请求**（一次都没发 = 空数组，正是「不自动执行」那条门的判据）。
 */
function harness(servers: string[] = []) {
  const calls: Call[] = [];
  const runs: string[][] = [];
  let alive = [...servers];
  let listener: ((p: SpeedTestProgress) => void) | null = null;
  let doneListener: ((p: SpeedTestDonePayload) => void) | null = null;
  let unsubscribed = 0;
  const deps: SpeedTestToastDeps = {
    subscribe: (l) => {
      listener = l;
      return () => {
        unsubscribed += 1;
      };
    },
    subscribeDone: (l) => {
      doneListener = l;
      return () => {
        unsubscribed += 1;
      };
    },
    toast: {
      info: (msg, opts) => calls.push({ level: 'info', msg, opts }),
      success: (msg, opts) => calls.push({ level: 'success', msg, opts }),
      warning: (msg, opts) => calls.push({ level: 'warning', msg, opts }),
    },
    // 假 t：把键与插值原样拼出来，断言里既看得到用了哪个键，也看得到数字有没有接对。
    t: (key, vars) => (vars ? `${key}(${JSON.stringify(vars)})` : key),
    currentServerIds: () => alive,
    run: (ids) => runs.push(ids),
  };
  const stop = subscribeSpeedTestProgressToast(deps);
  return {
    calls,
    runs,
    stop,
    emit: (tested: number, ok: number, total: number) => listener?.({ tested, ok, total }),
    emitDone: (p: SpeedTestDonePayload) => doneListener?.(p),
    setServers: (ids: string[]) => {
      alive = [...ids];
    },
    clickAction: (label: string) => {
      const last = calls[calls.length - 1];
      const action = last?.opts?.actions?.find((it) => it.label === label);
      if (!action) throw new Error(`最后一条 toast 没有动作：${label}`);
      action.onClick();
    },
    unsubCount: () => unsubscribed,
  };
}

/**
 * 净化 Rust 取材面：剥注释、**并整段跳过字符串/字符字面量**。
 *
 * 本文件原先自带一份正则版 `stripRustComments`（两条无状态的 `String.replace`：一条吃块注释、
 * 一条吃行注释）。它剥得掉注释，**保护不了字符串** —— 一条
 * `const _X: &str = "const TEMP_CORE_UI_IDLE_TIMEOUT_MS: u64 = 20_000;";` 就能在真常量改名之后
 * 让下面每一条读常量的门读到假值并全绿（复审 2026-09-03 构造实测）。正则没有状态，做不到这件事。
 *
 * 改走 `contracts/rust-source.test-support.ts` 的 [`maskRustCommentsAndStrings`]
 * （`crates/source-probe` 那个字节状态机的逐条移植）——两侧读同一批源文件，能力分叉出来的缝是绿的、
 * 看不见。读常量必须用**连字符串一起抹**的那一个：只跳过不抹，字面量的内容仍留在面上，
 * 假定义照样会被正则命中。
 */
const stripRustComments = maskRustCommentsAndStrings;

const done = (p: Partial<SpeedTestDonePayload> = {}): SpeedTestDonePayload => ({
  outcome: 'interrupted',
  tested: 12,
  total: 50,
  serverIds: [],
  pending: [],
  ...p,
});

describe('reduce：纯状态机', () => {
  it('未跑完 ⇒ sticky 进度（这就是「持续状态」那一档）', () => {
    const { next, intent } = reduceSpeedTestProgress(initialSpeedTestToastState, {
      tested: 3,
      ok: 2,
      total: 10,
    });
    expect(next).toEqual({ live: true, tested: 3, total: 10 });
    expect(intent).toEqual({
      level: 'info',
      sticky: true,
      msgKey: 'nodes.speedTestingNodes',
      msgVars: { tested: 3, total: 10 },
    });
  });

  it('🔴 跑完 ⇒ 非 sticky 的结论 toast（这就是「收起」）', () => {
    const { next, intent } = reduceSpeedTestProgress(
      { live: true, tested: 9, total: 10 },
      { tested: 10, ok: 7, total: 10 },
    );
    expect(next.live).toBe(false);
    // 变异「测速结束不收起」= 这里继续给 sticky:true（或不给 intent）⇒ 转红。
    expect(intent).toEqual({ level: 'success', sticky: false, msgKey: 'nodes.speedTestDone' });
  });

  it('total<=0 / 非数 一律忽略（契约破了也不许起一条永不终止的 sticky）', () => {
    for (const total of [0, -1, Number.NaN]) {
      const r = reduceSpeedTestProgress(initialSpeedTestToastState, { tested: 0, ok: 0, total });
      expect(r.intent).toBeNull();
      expect(r.next.live).toBe(false);
    }
  });

  it('静默超时：在跑 ⇒ 收成「测速中断」并带已完成数；不在跑 ⇒ 什么都不做', () => {
    const live = reduceSpeedTestIdle({ live: true, tested: 12, total: 50 });
    expect(live.next.live).toBe(false);
    expect(live.intent).toEqual({
      level: 'warning',
      sticky: false,
      msgKey: 'nodes.speedTestInterrupted',
      descKey: 'nodes.speedTestInterruptedSummary',
      descVars: { tested: 12, total: 50 },
      dismissLabelKey: 'nodes.speedTestDismiss',
    });
    expect(reduceSpeedTestIdle({ live: false, tested: 12, total: 50 }).intent).toBeNull();
  });
});

describe('订阅接线：一整轮测速的真实调用序列', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('🔴 每一条进度都用**同一个 key** —— 没有它，50 个节点会刷 50 条', () => {
    const h = harness();
    for (let i = 1; i <= 50; i++) h.emit(i, i, 50);
    // 50 次调用是对的（每个节点一次更新），关键是它们必须都带同一个 key ⇒ Toaster 侧 upsert 成一条。
    expect(h.calls).toHaveLength(50);
    expect(new Set(h.calls.map((c) => c.opts?.key))).toEqual(new Set([SPEEDTEST_TOAST_KEY]));
    h.stop();
  });

  it('🔴 进度是 sticky、终态不是（变异任一条即转红）', () => {
    const h = harness();
    h.emit(1, 1, 3);
    h.emit(2, 1, 3);
    h.emit(3, 2, 3);
    expect(h.calls.map((c) => [c.level, c.opts?.sticky])).toEqual([
      ['info', true],
      ['info', true],
      ['success', false],
    ]);
    expect(h.calls[0].msg).toBe('nodes.speedTestingNodes({"tested":1,"total":3})');
    expect(h.calls[2].msg).toBe('nodes.speedTestDone');
    h.stop();
  });

  it('🔴 跑完之后不再有静默超时补刀（终态后布防 = 十几秒后凭空多一条「测速中断」）', () => {
    const h = harness();
    h.emit(1, 1, 2);
    h.emit(2, 2, 2);
    vi.advanceTimersByTime(SPEEDTEST_IDLE_TIMEOUT_MS * 3);
    expect(h.calls).toHaveLength(2);
    expect(h.calls[1].level).toBe('success');
    h.stop();
  });

  it('🔴 兜底：连终态事件都丢了 ⇒ 静默超时仍把 sticky 收成「测速中断」，不许挂死在屏上', () => {
    /* 2026-07-31 B 批后本条的语义变了（**兜底**，不是主路径）：中断/完成一律由 `EVENT_SPEED_TEST_DONE`
       立即收口（见下面 `终态事件` 那一组）。本条守的是「事件丢失 / 后端异常退出」这个残余形态 ——
       此时没有任何事件会再来，只按 tested>=total 判终态必然挂死在屏上。
       变异锁：删掉 armIdle / 把 SPEEDTEST_IDLE_TIMEOUT_MS 改成 Infinity → 本条转红。 */
    const h = harness();
    h.emit(12, 9, 50);
    vi.advanceTimersByTime(SPEEDTEST_IDLE_TIMEOUT_MS - 1);
    expect(h.calls).toHaveLength(1); // 还没到点，进度仍在
    vi.advanceTimersByTime(1);
    expect(h.calls).toHaveLength(2);
    expect(h.calls[1]).toEqual({
      level: 'warning',
      msg: 'nodes.speedTestInterrupted',
      opts: {
        key: SPEEDTEST_TOAST_KEY,
        sticky: false,
        description: 'nodes.speedTestInterruptedSummary({"tested":12,"total":50})',
        dismiss: { label: 'nodes.speedTestDismiss' },
      },
    });
    h.stop();
  });

  it('每个进度事件都重新布防（慢节点不会被误判成中断）', () => {
    const h = harness();
    // 单节点硬上限 10s（冷 6s + 复用 4s），故连着几个慢节点也不该触发中断。
    for (let i = 1; i <= 5; i++) {
      h.emit(i, i, 50);
      vi.advanceTimersByTime(SPEEDTEST_IDLE_TIMEOUT_MS - 1000);
    }
    expect(h.calls.every((c) => c.level === 'info')).toBe(true);
    h.stop();
  });

  it('退订会拆掉在飞的超时 + **两条**事件流（组件卸载后不该再冒出一条 toast）', () => {
    const h = harness();
    h.emit(1, 1, 9);
    h.stop();
    vi.advanceTimersByTime(SPEEDTEST_IDLE_TIMEOUT_MS * 2);
    expect(h.calls).toHaveLength(1);
    // 2 而不是 1：B 批加了终态事件流（`subscribeDone`）。漏退订它 = 卸载后仍会弹终态 toast，
    // 故这个数字必须跟着订阅数走 —— 变异「只退订 progress」→ 转红并点名。
    expect(h.unsubCount()).toBe(2);
  });

  it('下一轮测速能重新起 sticky（上一轮的终态不把状态机锁死）', () => {
    const h = harness();
    // 第一轮：两节点跑完即终态。**不能用 total=1** —— 单节点 ⚡ 整轮静音（陈先生 2026-07-31 裁定），
    // 拿它当 fixture 会让本条测的「终态」压根不发生，测试恒绿且测不到东西。
    h.emit(2, 2, 2);
    h.emit(1, 1, 4); // 第二轮开跑
    expect(h.calls.map((c) => [c.level, c.opts?.sticky])).toEqual([
      ['success', false],
      ['info', true],
    ]);
    h.stop();
  });
});

describe('静默超时常量：必须留有余量，且**与后端常量真的对得上**', () => {
  /*
   * # 这条门为什么改成去读 Rust 源文件（而不是继续写死一个数字）
   *
   * 原文是 `expect(SPEEDTEST_IDLE_TIMEOUT_MS).toBeGreaterThanOrEqual(12_000)` —— 12000 是把
   * 「2 × 后端单节点上限」的**结果**抄进来。后端一改超时，这里照样绿（协调器文件头当时如实写着
   * 「两者失配本仓没有门会转红，只有两边注释互指」）。2026-07-31 后端改成**两段**预算，
   * 这个抄来的数字当场过期 —— 正是补门的时机，而不是把 12000 换成 20000 再抄一遍。
   *
   * 改后判据是**算术关系**：`SPEEDTEST_IDLE_TIMEOUT_MS >= 2 × (cold + reuse)`，两个加数直接从
   * `commands/speedtest` 的生产源码里正则抓。跨语言常量对拍在本仓已有先例
   * （`ipc-channel-bypass-wiring.test.ts` 同样读 `src-tauri/src` 原文）。
   *
   * 取材走 `moduleSource` + 剥注释 + 命中数自检（判据见 `rustConstU64`）：本 describe 原文用的是裸
   * `readFileSync('…/commands/speedtest.rs')` + 不剥注释的 `.exec`，与下面那道就绪门被复审打穿的
   * 是**同一个洞**（注释里写一行同形常量即可替真常量作证）。同根因的两条腿一起收口。
   */
  const COMMANDS_SPEEDTEST = stripRustComments(moduleSource('src-tauri/src/commands/speedtest'));

  function rustConstMs(name: string): number {
    return rustConstU64(COMMANDS_SPEEDTEST, name, 'speedtest-idle');
  }

  it('前提校验：两个后端常量都抓得到（抓不到就不是「宽松」而是没门）', () => {
    expect(rustConstMs('SPEED_TEST_COLD_TIMEOUT_MS')).toBeGreaterThan(0);
    expect(rustConstMs('SPEED_TEST_REUSE_TIMEOUT_MS')).toBeGreaterThan(0);
  });

  it('🔴 ≥ 2 ×（冷建链预算 + 复用请求预算）—— 直接读 Rust 常量算，失配即转红', () => {
    // 单节点最坏耗时 = 冷段 + 复用段（两段各自超时的极端叠加）⇒ 活跑时两次进度事件的间隔上界就是它。
    // 调到这个界以下 ⇒ 一个跑满上限的慢节点会被误判成中断，测速中途凭空弹「已完成 x/y」+ 一个白跑的「继续」。
    // 变异对照：把后端任一常量调大（如冷 6s → 12s）而不动本值 → 本条转红。
    const worstSingleNode =
      rustConstMs('SPEED_TEST_COLD_TIMEOUT_MS') + rustConstMs('SPEED_TEST_REUSE_TIMEOUT_MS');
    expect(SPEEDTEST_IDLE_TIMEOUT_MS).toBeGreaterThanOrEqual(2 * worstSingleNode);
  });

  it('也不许大到用户以为卡死（兜底归兜底，上界仍在）', () => {
    // 降级成兜底后取大的代价小，但不是没有上界：一条挂在屏上的 sticky 超过半分钟就是「卡死」的观感。
    expect(SPEEDTEST_IDLE_TIMEOUT_MS).toBeLessThanOrEqual(30_000);
  });
});

describe('终态事件（主路径）：中断当场收口，不再靠猜', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('🔴 interrupted ⇒ 立即转中断态，**不等**静默超时', () => {
    const h = harness();
    h.emit(12, 9, 50);
    h.emitDone(done({ tested: 12, total: 50, pending: ['n1'] }));
    // 一个 tick 都没推进就已经有终态了 —— 这就是「断开为什么还要等十几秒」那个缺陷的直接反面。
    expect(h.calls).toHaveLength(2);
    expect(h.calls[1].level).toBe('warning');
    expect(h.calls[1].msg).toBe('nodes.speedTestInterrupted');
    expect(h.calls[1].opts?.description).toBe(
      'nodes.speedTestInterruptedSummary({"tested":12,"total":50})'
    );
    h.stop();
  });

  it('🔴 已完成数取**后端载荷**，不是本地最后一帧（如实上报）', () => {
    const h = harness();
    h.emit(12, 9, 50);
    // 后端权威值与本地回声故意不同：末几个节点的进度事件可能还没到就已经中断了。
    h.emitDone(done({ tested: 14, total: 50, pending: ['n1'] }));
    expect(h.calls[1].opts?.description).toBe(
      'nodes.speedTestInterruptedSummary({"tested":14,"total":50})'
    );
    h.stop();
  });

  it('🔴 终态收口后拆掉兜底定时器（否则十几秒后凭空再来一条「测速中断」）', () => {
    const h = harness();
    h.emit(12, 9, 50);
    h.emitDone(done({ pending: ['n1'] }));
    vi.advanceTimersByTime(SPEEDTEST_IDLE_TIMEOUT_MS * 3);
    expect(h.calls).toHaveLength(2);
    h.stop();
  });

  it('🔴 正常跑完那一帧已收口 ⇒ 随后到达的 done 不再弹第二条', () => {
    const h = harness();
    h.emit(1, 1, 2);
    h.emit(2, 2, 2); // 这一帧就是终态
    h.emitDone({ outcome: 'completed', tested: 2, total: 2, serverIds: ['n1', 'n2'], pending: [] });
    expect(h.calls).toHaveLength(2);
    expect(h.calls[1].msg).toBe('nodes.speedTestDone');
    h.stop();
  });

  it('单节点 ⚡（total<=1 整轮静音）⇒ done 也必须静音', () => {
    const h = harness();
    h.emit(1, 1, 1);
    h.emitDone({ outcome: 'completed', tested: 1, total: 1, serverIds: ['n1'], pending: [] });
    expect(h.calls).toHaveLength(0);
    h.stop();
  });

  it('completed 但 tested 到不了 total（JoinError 漏账）⇒ done 照样收口成「完成」', () => {
    const h = harness();
    h.emit(4, 4, 5); // 第 5 个节点的测量任务 panic 了，永远不会有 5/5
    h.emitDone({
      outcome: 'completed',
      tested: 4,
      total: 5,
      serverIds: ['n1', 'n2', 'n3', 'n4', 'n5'],
      pending: ['n5'],
    });
    expect(h.calls[1].level).toBe('success');
    expect(h.calls[1].msg).toBe('nodes.speedTestDone');
    // completed 不给「继续」：后端已裁定本轮结束，pending 只是漏账的账面残留。
    expect(h.calls[1].opts?.actions).toBeUndefined();
    h.stop();
  });
});

describe('中断后的恢复动作：继续剩余 / 重测原范围 / 关闭', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('🔴 收到 interrupted **不会**自动发续测请求（要点才发）', () => {
    // 变异锁：把 `deps.run(...)` 从 onClick 挪进 done 分支（= 自动恢复）→ 第一条断言转红。
    // 判据见协调器文件头「不自动续」三条：抢后端单飞闸 / 用户此刻在做别的事 / 无收敛点。
    const h = harness(['n1', 'n2']);
    h.emit(1, 1, 3);
    h.emitDone(done({ tested: 1, total: 3, serverIds: ['n0', 'n1', 'n2'], pending: ['n1', 'n2'] }));
    vi.advanceTimersByTime(SPEEDTEST_IDLE_TIMEOUT_MS * 3);
    expect(h.runs, '中断本身绝不触发任何请求').toEqual([]);

    h.clickAction('nodes.speedTestResume');
    expect(h.runs, '点了才发').toEqual([['n1', 'n2']]);
    h.stop();
  });

  it('🔴 发的是**差集**，不是全集（这就是「续测」相对「重测」的全部价值）', () => {
    // 变异锁：把 pending 换成整轮请求集（后端「返回全集」）或前端自己拿全量节点重测 → 转红。
    const h = harness(['n1', 'n2', 'n3', 'n4']);
    h.emit(2, 2, 4);
    h.emitDone(done({ tested: 2, total: 4, serverIds: ['n1', 'n2', 'n3', 'n4'], pending: ['n3', 'n4'] }));
    h.clickAction('nodes.speedTestResume');
    expect(h.runs).toEqual([['n3', 'n4']]);
    h.stop();
  });

  it('🔴 发出前按**当前**节点集过滤（中断到点击之间用户删了节点）', () => {
    // 变异锁：点击处理里去掉 planSpeedTestRun 直接 `deps.run(pending)` → 转红。
    const h = harness(['n1', 'n2', 'n3']);
    h.emit(1, 1, 3);
    h.emitDone(done({ tested: 1, total: 3, serverIds: ['n1', 'n2', 'n3'], pending: ['n2', 'n3'] }));
    h.setServers(['n1', 'n3']); // n2 被删了 / 订阅换了
    h.clickAction('nodes.speedTestResume');
    expect(h.runs).toEqual([['n3']]);
    h.stop();
  });

  it('🔴 过滤后为空 ⇒ **不发空请求**，只收掉 toast', () => {
    // 空 serverIds 传到后端等于「测全部」——语义彻底反转，会把一次「继续」变成一整轮全量测速。
    const h = harness(['n1']);
    h.emit(1, 1, 3);
    h.emitDone(done({ tested: 1, total: 3, serverIds: ['n1', 'n2', 'n3'], pending: ['n2', 'n3'] }));
    h.setServers([]); // 全没了
    h.clickAction('nodes.speedTestResume');
    expect(h.runs).toEqual([]);
    const last = h.calls[h.calls.length - 1];
    expect(last.msg).toBe('nodes.speedTestTargetsGone');
    expect(last.opts?.key).toBe(SPEEDTEST_TOAST_KEY); // 同 key ⇒ 顶掉那条中断 toast
    expect(last.opts?.sticky).toBe(false);
    h.stop();
  });

  it('🔴 一个节点都没完成时两个范围相同 ⇒ 只给「重新测速」，不放两个同义按钮', () => {
    const h = harness(['n1', 'n2', 'n3']);
    h.emit(0, 0, 3);
    h.emitDone(done({ tested: 0, total: 3, serverIds: ['n1', 'n2', 'n3'], pending: ['n1', 'n2', 'n3'] }));
    expect(h.calls[1].opts?.actions?.map((action) => action.label)).toEqual([
      'nodes.speedTestRetry',
    ]);
    h.stop();
  });

  it('🔴 重新测速严格复用原请求范围，不扩成当前全部节点', () => {
    const h = harness(['n1', 'n2', 'n3', 'outside']);
    h.emit(1, 1, 3);
    h.emitDone(done({ tested: 1, total: 3, serverIds: ['n1', 'n2', 'n3'], pending: ['n2', 'n3'] }));
    h.clickAction('nodes.speedTestRetry');
    expect(h.runs).toEqual([['n1', 'n2', 'n3']]);
    h.stop();
  });

  it('🔴 中断态 toast **不是 sticky**（带按钮却永不消失 = 赖在屏上关不掉）', () => {
    // 形态判据的另一半在 `components/layout/toast-queue.test.ts`：那边钉死 autoDismissMs 对
    // 带 actions 的条目必须返回有限值（即便调用方写了 sticky:true 也压过去）。两条一起才封死这个面。
    const h = harness(['n1']);
    h.emit(1, 1, 3);
    h.emitDone(done({ tested: 1, total: 3, serverIds: ['n1', 'n2', 'n3'], pending: ['n2'] }));
    expect(h.calls[1].opts?.sticky).toBe(false);
    expect(h.calls[1].opts?.actions?.map((action) => action.label)).toEqual([
      'nodes.speedTestResume',
      'nodes.speedTestRetry',
    ]);
    expect(h.calls[1].opts?.dismiss?.label).toBe('nodes.speedTestDismiss');
    h.stop();
  });

  it('planSpeedTestRun：保序 + 去重 + 只留还在的', () => {
    expect(planSpeedTestRun(['c', 'a', 'c', 'zz'], ['a', 'b', 'c'])).toEqual(['c', 'a']);
    expect(planSpeedTestRun([], ['a'])).toEqual([]);
    expect(planSpeedTestRun(['a'], [])).toEqual([]);
  });

  it('reduceSpeedTestDone：不在跑就什么都不做（纯状态机层）', () => {
    expect(reduceSpeedTestDone({ live: false, tested: 0, total: 0 }, done()).intent).toBeNull();
  });

  it('🔴 中断成因换的是**标题**，动作集合三档完全相同', () => {
    /*
     * 三种成因下用户能做的事一样（继续剩余 / 重新测速 / 关闭），差别只在「接下来该去看哪儿」：
     * `superseded` 是主核接管了，另两档是本机测速核出事了、日志页里有它的行。
     *
     * 变异锁：把 `INTERRUPT_MSG_KEY` 里任一条改回通用键 → 对应那条 msgKey 断言转红；
     * 让某一档少挂一个动作 → actions 相等断言转红。
     */
    const base = {
      live: true as const,
      tested: 12,
      total: 50,
    };
    const wanted: Record<string, string> = {
      superseded: 'nodes.speedTestInterrupted',
      core_exited: 'nodes.speedTestCoreExited',
      core_unresponsive: 'nodes.speedTestCoreUnresponsive',
    };
    const actionsOf = (reason?: 'superseded' | 'core_exited' | 'core_unresponsive') =>
      reduceSpeedTestDone(
        base,
        done({ serverIds: ['a', 'b', 'c'], pending: ['b', 'c'], reason })
      ).intent;

    // 没有 reason（旧后端 / 兜底腿）→ 回落通用文案，与本字段引入前逐字一致。
    expect(actionsOf()?.msgKey).toBe('nodes.speedTestInterrupted');

    const reference = actionsOf('superseded');
    for (const [reason, key] of Object.entries(wanted)) {
      const intent = actionsOf(reason as 'superseded');
      expect(intent?.msgKey, `${reason} 的标题键`).toBe(key);
      expect(intent?.descKey).toBe('nodes.speedTestInterruptedSummary');
      expect(intent?.dismissLabelKey).toBe('nodes.speedTestDismiss');
      expect(intent?.actions, `${reason} 的动作集合必须与让位档完全一致`).toEqual(
        reference?.actions
      );
    }
  });

  it('completed 不受 reason 影响（后端不会带，带了也不许改成中断态）', () => {
    const intent = reduceSpeedTestDone(
      { live: true, tested: 50, total: 50 },
      done({ outcome: 'completed' })
    ).intent;
    expect(intent).toEqual({ level: 'success', sticky: false, msgKey: 'nodes.speedTestDone' });
  });
});

describe('测速 Toast 文案在五语种都存在（本模块的键绕过了可寻址性门）', () => {
  /*
   * `locale-parity.test.ts` 的可寻址性门只扫 `t('字面量')` 形态；本模块把键存成 `intent.msgKey`
   * 再交给注入的 `t`，那道门看不见它们 ⇒ 这里自带一份，否则「键写错一个字母」只会在运行期
   * 显示成裸键名（且五语全中，fallbackLng 也救不了）。
   */
  const KEYS = [
    'nodes.speedTestingNodes',
    'nodes.speedTestDone',
    'nodes.speedTestInterrupted',
    'nodes.speedTestInterruptedSummary',
    // 中断成因分档文案（后端 `InterruptReason` 的另两档）。
    'nodes.speedTestCoreExited',
    'nodes.speedTestCoreUnresponsive',
    // 恢复动作与关闭入口——五语同批补齐，故 ru/fa 的 MISSING_KEY_DEBT 不动。
    'nodes.speedTestResume',
    'nodes.speedTestRetry',
    'nodes.speedTestDismiss',
    'nodes.speedTestTargetsGone',
  ];
  const dir = fileURLToPath(new URL('../i18n/locales', import.meta.url));
  const files = readdirSync(dir).filter((f) => f.endsWith('.json'));

  it('前提校验：确实读到了五份 locale（读空则下面恒绿空转）', () => {
    expect(files).toHaveLength(5);
  });

  for (const f of files) {
    it(`${f} 键齐全`, () => {
      const data = JSON.parse(readFileSync(join(dir, f), 'utf8')) as Record<
        string,
        Record<string, unknown>
      >;
      const missing = KEYS.filter((k) => {
        const [ns, leaf] = k.split('.');
        return typeof data[ns]?.[leaf] !== 'string';
      });
      expect(missing, `${f} 缺键 —— 用户会看到裸键名`).toEqual([]);
    });
  }

  it('reduce 产出的键确实落在这张表里（防改了 reduce 忘了改本表）', () => {
    const used = new Set<string>();
    const collect = (
      i: {
        msgKey: string;
        descKey?: string;
        actions?: Array<{ labelKey: string }>;
        dismissLabelKey?: string;
      } | null
    ) => {
      if (!i) return;
      used.add(i.msgKey);
      if (i.descKey) used.add(i.descKey);
      for (const action of i.actions ?? []) used.add(action.labelKey);
      if (i.dismissLabelKey) used.add(i.dismissLabelKey);
    };
    collect(reduceSpeedTestProgress(initialSpeedTestToastState, { tested: 1, ok: 1, total: 5 }).intent);
    collect(reduceSpeedTestProgress(initialSpeedTestToastState, { tested: 5, ok: 5, total: 5 }).intent);
    collect(reduceSpeedTestIdle({ live: true, tested: 1, total: 5 }).intent);
    collect(
      reduceSpeedTestDone(
        { live: true, tested: 1, total: 5 },
        {
          outcome: 'interrupted',
          tested: 1,
          total: 5,
          serverIds: ['n1', 'n2'],
          pending: ['n2'],
        }
      ).intent
    );
    // 三档中断成因各走一遍：漏掉任一档，它的文案键就不会进 `used`，下面的集合相等断言转红。
    for (const reason of ['superseded', 'core_exited', 'core_unresponsive'] as const) {
      collect(
        reduceSpeedTestDone(
          { live: true, tested: 1, total: 5 },
          {
            outcome: 'interrupted',
            tested: 1,
            total: 5,
            serverIds: ['n1', 'n2'],
            pending: ['n2'],
            reason,
          }
        ).intent
      );
    }
    // `speedTestTargetsGone` 不经 reduce（它是「点击恢复动作但目标已不存在」时由订阅层直接弹的），
    // 故这里手工补上——否则上面那张表会因为「集合不等」转红，而缺席的恰恰是没被 reduce 覆盖的那条。
    used.add('nodes.speedTestTargetsGone');
    expect([...used].sort()).toEqual([...KEYS].sort());
  });
});

describe('后端就绪门 vs 前端静默兜底：起核那一整段窗口里不许有定时器', () => {
  /*
   * # 取材面：`moduleSource` 入口 + 剥注释 + 命中数自检（三样缺一不可）
   *
   * 本 describe 的第一版用裸 `readFileSync('…/runtime/speedtest.rs')` + 正则 `.exec`（取首个匹配、
   * 不剥注释）读后端常量。复审当场把它打穿了：在 `TEMP_CORE_READY_TIMEOUT_FLOOR_MS` 的**文档注释里**
   * 写一行 `const …FLOOR_MS: u64 = 10_000;`，同时把真常量改成 `5_000` ⇒ 本文件 40/40 全绿。
   * 门读到的是注释里那个数。
   *
   * 三样各堵一个洞：
   *  - `moduleSource(模块路径)`：本仓 TS 侧读 Rust 源码的**唯一入口**。写死 `foo.rs` 的门会在常量被挪进
   *    `foo/xxx.rs` 时静默失去那一半取材面（该模块 `:6-9` 的文档正是为此而写）；
   *  - `stripRustComments`：注释里的同形串不算证据；
   *  - **命中数必须恰好 1**：`.exec` 取首个匹配 ⇒ 面上出现第二处同形定义时，判据指向哪一处全凭书写
   *    顺序。为 0 = 常量改名/搬走、门已失去判据，同样必须当场抛。
   *
   * Rust 侧的对应锁是 `speedtest/tests/mod.rs::the_floor_stays_at_the_only_value_with_production_evidence`
   * （直接 `assert_eq!` 编译进来的那个值，注释怎么写都与它无关）。两侧各守一边，缺一边都补不上另一边。
   */

  /*
   * # 这条门守的耦合是什么
   *
   * 后端临时核的就绪门在 2026-09-03 从固定 10s 改成**本批规模的函数**
   * （`runtime/speedtest.rs::temp_core_ready_timeout_ms`，naive 出站多时可以合法地到
   * `TEMP_CORE_READY_TIMEOUT_CAP_MS` = 60s）。这段时间里后端**一条事件都不发** ——
   * 核还在串行启动 cronet engine，一个节点都还没测。
   *
   * 前端这一侧之所以不受影响，只有一个理由：`armIdle()` 在 `state.live` 为假时早退 ⇒
   * **收到第一条 progress 之前一个定时器都没布防**。它不是「配得刚好」，是「压根没起跑」。
   *
   * 反过来说，「起核时发一条 progress 让用户看见在起核」这个很自然的想法会当场引爆它：
   * 那一刻 20s 兜底布防，而就绪还要等最多 60s ⇒ 核正常启动中，用户先看到一条假的
   * 「测速中断」+ 一个点了会白跑的「继续」。后端那一半由
   * `speedtest.rs::no_progress_event_escapes_before_the_readiness_gate_resolves` 对称守住。
   */
  const RUNTIME_SPEEDTEST = stripRustComments(moduleSource('src-tauri/src/runtime/speedtest'));

  function runtimeConstMs(name: string): number {
    return rustConstU64(RUNTIME_SPEEDTEST, name, 'speedtest-ready-gate');
  }

  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('取材自检：注释里的假常量不算数（这就是复审打穿本门的那条路）', () => {
    // 复审的变异原样重放：文档注释里写一行常量定义 ⇒ 剥注释后必须一个字都不剩。
    expect(
      stripRustComments('/// const TEMP_CORE_READY_TIMEOUT_FLOOR_MS: u64 = 10_000;\nfoo;')
    ).not.toMatch(/TEMP_CORE_READY_TIMEOUT_FLOOR_MS/);
    expect(stripRustComments('/* const TEMP_CORE_READY_TIMEOUT_CAP_MS: u64 = 1; */ bar;')).not.toMatch(
      /TEMP_CORE_READY_TIMEOUT_CAP_MS/
    );
    // 剥完之后取材面仍然非空、且真的含被读的两个常量（否则上面那条「剥干净了」毫无信息量）。
    expect(RUNTIME_SPEEDTEST).toMatch(/const TEMP_CORE_READY_TIMEOUT_CAP_MS\s*:\s*u64/);
    expect(RUNTIME_SPEEDTEST).toMatch(/const TEMP_CORE_READY_TIMEOUT_FLOOR_MS\s*:\s*u64/);
  });

  /*
   * # 第二条取材洞：**字符串**里的假常量（复审 2026-09-03 构造实测，本仓同族第三次）
   *
   * 原来那份正则版 `stripRustComments` 只认注释。往生产源码里放一条
   * `const _X: &str = "const NAME: u64 = 20_000;";`，再把真常量改名 ⇒ 净化面上仍然恰好命中 1 次，
   * 门读到字符串里那个假值，**全绿**。今天被读的两个模块里恰好没有这种字符串（只有一条被截尾的
   * URL），那是运气不是设计。
   *
   * 判据形态刻意选「**必须抛**」而不是「读到别的数」：`rustConstU64` 的命中数自检要求恰好 1，
   * 假常量被正确跳过之后真常量若也不在（改名场景）就是 0 命中 ⇒ 抛。抛才是正确行为 ——
   * 「门已经失去判据」必须当场炸，不许静默退化成恒绿。
   */
  it('🔴 取材自检：**字符串**里的假常量同样不算数（正则版剥注释就是死在这一格）', () => {
    const injected = 'const _X: &str = "const FAKE_CONST_MS: u64 = 20_000;";\nlet y = 1;';
    // ① 字符串整段被跳过 ⇒ 里面那个假定义不在净化面上。
    expect(stripRustComments(injected)).not.toMatch(/FAKE_CONST_MS/);
    // ② 于是读它的门**抛**（命中 0 次），而不是读到 20000 之后一路绿下去。
    expect(() =>
      rustConstU64(stripRustComments(injected), 'FAKE_CONST_MS', 'speedtest-取材自检')
    ).toThrow(/命中 0 次/);
    // ③ 反向对照：同一个名字**真的**定义在代码里时必须读得出来，否则 ① 只是「把什么都剥光了」。
    expect(
      rustConstU64('const FAKE_CONST_MS: u64 = 7_000;', 'FAKE_CONST_MS', 'speedtest-取材自检')
    ).toBe(7_000);
    // ④ 字符串里的 `//` 不许被当成注释起笔（无状态正则会从这里把整行后半段吃掉）。
    expect(stripRustComments('let u = "http://a // b"; const KEEP_MS: u64 = 5;')).toMatch(
      /const KEEP_MS: u64 = 5;/
    );
  });

  it('前提校验：后端就绪门的上限确实可以超过前端兜底（否则本门无对象可守）', () => {
    expect(runtimeConstMs('TEMP_CORE_READY_TIMEOUT_CAP_MS')).toBeGreaterThan(
      SPEEDTEST_IDLE_TIMEOUT_MS
    );
    // 下限那一档必须仍是历史值：门只许变宽、不许变窄。
    // 这是跨语言那一侧的锁，Rust 侧的对应锁是 `the_floor_stays_at_the_only_value_with_production_evidence`。
    expect(runtimeConstMs('TEMP_CORE_READY_TIMEOUT_FLOOR_MS')).toBe(10_000);
  });

  /*
   * # 判据为什么是「在飞定时器数」而不是「toast 调用数」
   *
   * 本门第一版只断言 `h.calls` 为空，复审实测**对它自称要拦的改动恒绿**：删掉 `armIdle` 的
   * `if (!state.live) return;` ⇒ 40/40 全绿；再补一句「订阅建立即 `armIdle()`」⇒ 仍 40/40 全绿。
   * 原因是 reducer 侧还有一道独立守卫（`reduceSpeedTestIdle` 在 `!state.live` 时返回 `intent: null`）
   * 兜着 —— 于是「不发 toast」在无事件输入下**恒真**，门守的是一个自动成立的命题。
   *
   * 真正要守的耦合是「**定时器有没有布防**」：布防了就意味着前端已经在给后端的起核窗口计时，
   * 而那个窗口可以合法地长到 `TEMP_CORE_READY_TIMEOUT_CAP_MS`。`vi.getTimerCount()` 直接观测它。
   * 两个变异因此各被一条断言接住：
   *  - 「订阅建立即 armIdle」→ 建 harness 之后计数就是 1 → 第一条断言红；
   *  - 「删掉 `!state.live` 早退」→ 起核期间的 DONE（规模超限/起核失败这条真实路径就是它：
   *    零 progress + 一条 DONE）会让 `armIdle()` 真的布防 → 第三条断言红。
   */
  it('🔴 首个进度事件之前一个定时器都不许布防（后端起核可以合法地占满整个上限）', () => {
    const h = harness();
    expect(vi.getTimerCount(), '订阅建立那一刻就不许有定时器在飞').toBe(0);
    // 跑满后端就绪门的上限还多一倍 —— 这期间后端不发事件是**正常的**，不是中断。
    vi.advanceTimersByTime(runtimeConstMs('TEMP_CORE_READY_TIMEOUT_CAP_MS') * 2);
    expect(vi.getTimerCount()).toBe(0);
    expect(h.calls).toHaveLength(0);

    // 起核失败/规模超限那条真实路径：一条 progress 都没有，直接来一条 DONE。
    // 它同样不许留下在飞的定时器 —— 留下就等于十几秒后凭空补一条「测速中断」。
    h.emitDone(done({ outcome: 'interrupted', tested: 0, total: 0 }));
    expect(vi.getTimerCount(), 'DONE 之后仍不许有定时器在飞（`armIdle` 的 live 早退没了？）').toBe(0);
    expect(h.calls).toHaveLength(0);
    h.stop();
  });
});

describe('分批起临时核（T1-R1）：批间空窗与轮级进度口径', () => {
  /*
   * # 这个 describe 守的耦合
   *
   * 后端（T1-R1）把一轮测速切成 k 批，每批起一个自己的临时核 —— 峰值资源因此与订阅节点数无关。
   * 代价是批之间多出一段**没有测量结果**的空窗（收上一批的核 → `sing-box check` → spawn → 就绪门），
   * 而本文件的 `SPEEDTEST_IDLE_TIMEOUT_MS` 正是「两条进度事件之间静默这么久 ⇒ 判为中断」。
   *
   * 于是**这个常量成了后端批大小的绑定约束**：后端按
   * `批就绪预算上限 = SPEEDTEST_IDLE_TIMEOUT_MS − 批间固定开销` 反解出单批能装多少个 naive 出站。
   * 两侧靠一个镜像常量（`runtime/speedtest.rs::TEMP_CORE_UI_IDLE_TIMEOUT_MS`）联系 ——
   * 本节直接读它对拍，而不是让两边注释互指。
   *
   * 取材面纪律同上一个 describe：`moduleSource` 入口 + 剥注释 + 命中数恰好 1。
   */
  const RUNTIME_SPEEDTEST = stripRustComments(moduleSource('src-tauri/src/runtime/speedtest'));
  const CMD_SPEEDTEST = stripRustComments(moduleSource('src-tauri/src/commands/speedtest'));

  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('🔴 后端那份「前端静默兜底」的镜像值必须与本文件逐字相同', () => {
    // 后端拿这个数去算单批能装多少节点。改了本文件而不改后端 ⇒ 后端按一个不存在的窗口切批：
    // 调大它，后端仍按旧值保守切（只是白多切几批）；**调小它，后端的批就装不进新窗口了** ——
    // 用户会在测速正常进行时看到假的「测速中断」，而现场没有任何东西指向「批太大」。
    expect(
      rustConstU64(RUNTIME_SPEEDTEST, 'TEMP_CORE_UI_IDLE_TIMEOUT_MS', 'speedtest-batching')
    ).toBe(SPEEDTEST_IDLE_TIMEOUT_MS);
  });

  it('前提校验：批间空窗的第三段（本批第一个节点的测量）确实装得进兜底', () => {
    // 空窗被两条心跳切成三段，最后一段是「就绪心跳 → 本批第一个节点出值」＝单节点最坏耗时。
    // 它与 20s 的关系正是这个常量当初的推导来源，此处只是把它作为分批的前提再确认一次。
    const cold = rustConstU64(CMD_SPEEDTEST, 'SPEED_TEST_COLD_TIMEOUT_MS', 'speedtest-batching');
    const reuse = rustConstU64(CMD_SPEEDTEST, 'SPEED_TEST_REUSE_TIMEOUT_MS', 'speedtest-batching');
    expect(cold + reuse).toBeLessThan(SPEEDTEST_IDLE_TIMEOUT_MS);
  });

  /*
   * # 轮级口径：为什么进度事件的 `total` 必须是全轮总数
   *
   * `reduceSpeedTestProgress` 在 `tested >= total` 那一帧就**收口**（`live:false` + 弹「测速完成」）。
   * 后端若按批各报各的 `total`，批 1 测完那一刻前端就会收到 `142/142` ⇒ 当场宣告完成，随后批 2
   * 的事件又把 sticky 拉起来 —— 一轮里连弹 k 条「完成」。
   *
   * 下面两条是一对：第一条走**轮级**口径（后端现在的形态）证明中途不收口；第二条走**批级**口径
   * 作**反向对照**，证明这条门守的是一个真实存在的失效面，而不是一句恒真的断言。
   */
  it('🔴 轮级口径：k 批的进度流在最后一个节点之前不许收口', () => {
    const TOTAL = 300; // 三批：142 + 142 + 16
    let state = initialSpeedTestToastState;
    const dones: number[] = [];
    for (let tested = 1; tested <= TOTAL; tested += 1) {
      // 批边界处后端会插两条心跳（内容与上一帧逐字相同、不带新数据）——它们也走同一个 reducer。
      const frames: SpeedTestProgress[] =
        tested === 143 || tested === 285
          ? [
              { tested: tested - 1, ok: tested - 1, total: TOTAL },
              { tested: tested - 1, ok: tested - 1, total: TOTAL },
              { tested, ok: tested, total: TOTAL },
            ]
          : [{ tested, ok: tested, total: TOTAL }];
      for (const ev of frames) {
        const r = reduceSpeedTestProgress(state, ev);
        state = r.next;
        if (r.intent?.msgKey === 'nodes.speedTestDone') dones.push(ev.tested);
      }
    }
    expect(dones, `中途收口了（在 ${dones} 处宣告完成）⇒ 用户一轮里会看到多条「测速完成」`).toEqual([
      TOTAL,
    ]);
    expect(state.live, '走到最后一帧才收口').toBe(false);
  });

  it('反向对照：批级口径下每批测完都会收口一次（这就是必须用轮级口径的理由）', () => {
    let state = initialSpeedTestToastState;
    const dones: number[] = [];
    for (const batch of [142, 142, 16]) {
      for (let tested = 1; tested <= batch; tested += 1) {
        const r = reduceSpeedTestProgress(state, { tested, ok: tested, total: batch });
        state = r.next;
        if (r.intent?.msgKey === 'nodes.speedTestDone') dones.push(tested);
      }
    }
    // 前两批各收口一次（第三批 16 个也会）——三条「测速完成」。
    expect(dones.length).toBeGreaterThan(1);
  });

  /*
   * # 心跳为什么必须复用 `EVENT_SPEED_TEST_PROGRESS` 而不是新开一个通道
   *
   * 兜底定时器由**进度事件**重新起算（`armIdle()` 挂在 progress 与 done 两条订阅上）。新开一个
   * 「心跳」通道 ⇒ 前端要多接一条订阅、reducer 要多一条分支，而收益为零：心跳要表达的正是
   * 「还在测、进度没变」，那恰好就是一条内容不变的 progress。
   *
   * 本条证明「内容不变的 progress」在前端是**无害且有效**的：不改状态、不弹新东西，但把定时器
   * 推后了整整一个兜底周期。
   */
  it('🔴 内容不变的心跳：不改状态、不弹东西，但把静默兜底整个推后', () => {
    const h = harness();
    h.emit(5, 5, 50);
    const afterFirst = h.calls.length;
    // 差 1ms 就要到点了 —— 此刻来一条心跳。
    vi.advanceTimersByTime(SPEEDTEST_IDLE_TIMEOUT_MS - 1);
    h.emit(5, 5, 50);
    // 心跳只是把同一条 sticky 原地刷了一次（同 key、同文案），不是一条新 toast。
    expect(h.calls.slice(afterFirst).every((c) => c.opts?.key === SPEEDTEST_TOAST_KEY)).toBe(true);
    expect(h.calls.every((c) => c.level !== 'warning'), '心跳期间不许出现中断文案').toBe(true);
    // 再走一个「差 1ms 到点」——若心跳没重置定时器，这里早就中断了。
    vi.advanceTimersByTime(SPEEDTEST_IDLE_TIMEOUT_MS - 1);
    expect(
      h.calls.some((c) => c.msg.includes('speedTestInterrupted')),
      '心跳没能重置兜底定时器 ⇒ 批间空窗会被误判成中断'
    ).toBe(false);
    // 心跳之后不再有事件 ⇒ 兜底照常生效（心跳只推后、不取消）。
    vi.advanceTimersByTime(SPEEDTEST_IDLE_TIMEOUT_MS);
    expect(
      h.calls.some((c) => c.msg.includes('speedTestInterrupted')),
      '心跳把兜底彻底取消了 ⇒ 真丢事件时 sticky 会永久挂在屏上'
    ).toBe(true);
    h.stop();
  });
});
