/**
 * 测速反馈文案单测（vitest，node 环境）。
 *
 * 钉住的是「诚实性」而非文案本身：后端把「本层测不了」和「测了但失败」分成不同 code，前端必须分流；
 * 缺席节点数必须如实累加，不能让「全部测速」看着像全测过了。
 */

import { describe, expect, it } from 'vitest';
import type { TFunction } from 'i18next';
import { IpcError } from '@/ipc';
import {
  notInPoolMessage,
  speedTestErrorMessage,
  speedTestBlockedMessage,
  TEMP_CORE_NAIVE_CEILING_HINT,
} from './speedtest-feedback';
import {
  maskRustCommentsAndStrings,
  moduleSource,
  rustConstU64,
} from '@/contracts/rust-source.test-support';
import type { ServerConfig } from '@/contracts/types';
import { speedTestBlockReason, type SpeedTestBlockReason } from '../nodes/nodes-logic';

// 直通 t：返回 key，便于断言走了哪个分支（不校验译文内容，那是 locale 的事）。
const t = ((key: string, opts?: unknown) => {
  if (opts && typeof opts === 'object' && 'count' in (opts as Record<string, unknown>)) {
    return `${key}:${(opts as { count: number }).count}`;
  }
  return key;
}) as unknown as TFunction;

describe('speedTestErrorMessage', () => {
  it('无活跃出口 → 专用文案（不是笼统「失败」）', () => {
    const err = new IpcError('server_speed_test', 'backend msg', 'SPEEDTEST_NO_ACTIVE_EXIT');
    expect(speedTestErrorMessage(err, t)).toBe('nodes.speedTestNoActiveExit');
  });

  it('探针池未接线 → 专用文案', () => {
    const err = new IpcError('server_speed_test', 'backend msg', 'SPEEDTEST_PROBE_POOL_UNWIRED');
    expect(speedTestErrorMessage(err, t)).toBe('nodes.speedTestOnlyActive');
  });

  /**
   * 🔴 **规模超限必须与就绪超时分流** —— 这是后端新增独立错误码的**全部理由**。
   *
   * 合并回 `SPEEDTEST_TEMP_CORE_FAILED` 那组，用户看到的就是「测速中断」，与「核起不来 / 未就绪
   * 超时」逐字相同 ⇒ 朝网络/端口方向排查，而真因是本轮 naive 节点太多、少选一些当场就能测。
   *
   * 第二条断言（`not.toBe` 就绪超时那句）是牙：只断言「等于新键」的话，把 `speedTestInterrupted`
   * 改名成新键同样能骗过去。
   *
   * ⚠️ **射程登记（T1-R1 分批之后）**：`SPEEDTEST_TEMP_CORE_OVERSIZED` 这条码在生产路径上
   * **已不可达** —— 后端规划器保证每一批的就绪预算至多 ≈11.9s，永远碰不到那条 60s 的拒绝上限
   * （Rust 侧门 `planned_batches_never_trip_the_oversize_refusal`）。本条守的是
   * 「万一规划器被绕过或回归，那条自曝腿仍然有自己的文案」，**不是一条活路径**。
   * 读到这里不要以为用户还会看到这句话，也不要据此推断「测速会因为 naive 太多而拒绝用户」。
   */
  it('临时核规模超限 → 专属文案，且与「测速中断」不是同一句', () => {
    const oversized = new IpcError('server_speed_test', '后端诊断原文', 'SPEEDTEST_TEMP_CORE_OVERSIZED');
    const failed = new IpcError('server_speed_test', '后端诊断原文', 'SPEEDTEST_TEMP_CORE_FAILED');
    expect(speedTestErrorMessage(oversized, t)).toBe('nodes.speedTestTooManyNaive');
    expect(speedTestErrorMessage(oversized, t)).not.toBe(speedTestErrorMessage(failed, t));
    // 反伪造：后端那段中文诊断串一个字都不许出现在用户可见文案里。
    expect(speedTestErrorMessage(oversized, t)).not.toContain('后端诊断原文');
  });

  it('其它 IpcError → 安全本地化兜底，不透出后端诊断', () => {
    const err = new IpcError('server_speed_test', '核未运行', 'SOME_OTHER_CODE');
    expect(speedTestErrorMessage(err, t)).toBe('nodes.speedTestInterrupted');
  });

  it('非 IpcError → 安全本地化兜底', () => {
    expect(speedTestErrorMessage(new Error('boom'), t)).toBe('nodes.speedTestInterrupted');
  });

  it('非 Error 抛出物也不字符串化直显', () => {
    expect(speedTestErrorMessage('plain', t)).toBe('nodes.speedTestInterrupted');
  });
});

describe('notInPoolMessage', () => {
  it('全部测到 → null（不打扰）', () => {
    expect(notInPoolMessage({ notInPool: [], tsNotReady: [] }, t)).toBeNull();
  });

  it('只有未入池 → 只报「重启内核纳入」那一句', () => {
    expect(notInPoolMessage({ notInPool: ['a', 'b'], tsNotReady: [] }, t)).toBe(
      'nodes.speedTestSkipped:2'
    );
  });

  /**
   * 两类分开报，**不合计**：合计成一条会把「TS 没登录」说成「未入运行核测速池，重启内核后纳入」，
   * 用户照着重启内核，重启完照旧 —— 真正缺的是登录。变异对照：改回
   * `count = notInPool.length + tsNotReady.length` 的单句形态 → 本条与下一条转红。
   */
  it('TS 未登录就绪单独成句（修法是去登录，不是重启内核）', () => {
    expect(notInPoolMessage({ notInPool: [], tsNotReady: ['t1', 't2'] }, t)).toBe(
      'nodes.speedTestSkippedTsNotReady:2'
    );
  });

  it('两类并存 → 两句都报，且各报各的数（不是合计成 3）', () => {
    const msg = notInPoolMessage({ notInPool: ['a', 'b'], tsNotReady: ['c'] }, t);
    expect(msg).toContain('nodes.speedTestSkipped:2');
    expect(msg).toContain('nodes.speedTestSkippedTsNotReady:1');
    expect(msg).not.toContain('nodes.speedTestSkipped:3');
  });

  it('字段缺省 → 按 0 计，不崩', () => {
    expect(notInPoolMessage({} as { notInPool: string[]; tsNotReady: string[] }, t)).toBeNull();
  });
});

/**
 * 不可测原因 → 文案。这层是 Home 的「网络检测」与 Nodes 的灰 ⚡ tooltip **共用**的措辞源，
 * 守的是「每个原因码都有专属说法」——退回兜底的 `nodes.speedTestNotApplicable`
 * （「不支持测速」）等于把「Tailscale 没设出口」和「代理没跑」说成同一句话，用户按错方向折腾。
 */
describe('speedTestBlockedMessage', () => {
  /** 与 `SpeedTestBlockReason` 联合类型逐项对齐；漏一项 → 下面的穷尽断言转红。 */
  const EXPECTED: Record<Exclude<SpeedTestBlockReason, 'other'>, string> = {
    'staged-only': 'nodes.speedTestBlockedStagedOnly',
    'system-interface': 'nodes.speedTestBlockedSystem',
    'ts-no-exit': 'nodes.speedTestBlockedTsNoExit',
    'lan-only': 'nodes.speedTestBlockedLanOnly',
    'ts-core-not-ready': 'nodes.speedTestBlockedTsCoreNotReady',
    'custom-endpoint': 'nodes.speedTestBlockedCustomEndpoint',
  };

  it('每个具体原因码各有专属键，无一退回兜底', () => {
    for (const [reason, key] of Object.entries(EXPECTED)) {
      const msg = speedTestBlockedMessage(reason as SpeedTestBlockReason, t);
      expect(msg, `${reason} 退回了兜底文案`).toBe(key);
      expect(msg).not.toBe('nodes.speedTestNotApplicable');
    }
  });

  it('未知原因 → 兜底「不支持测速」，不抛也不返 undefined', () => {
    expect(speedTestBlockedMessage('other', t)).toBe('nodes.speedTestNotApplicable');
    expect(speedTestBlockedMessage('brand-new-reason' as SpeedTestBlockReason, t)).toBe(
      'nodes.speedTestNotApplicable'
    );
  });

  /**
   * 端到端闭合：`speedTestBlockReason` 真正会产出的每个码，本函数都得给出专属说法。
   * 上面的 EXPECTED 是手写表（可能与谓词分叉），这条用**谓词自己的产物**当输入 ——
   * 谓词新增一个分支而本函数没跟上时，它会退回兜底，这条转红。
   */
  it('谓词实际产出的码全部有专属文案（不是手写表自说自话）', () => {
    const srv = (over: Partial<ServerConfig>): ServerConfig =>
      ({ id: 'x', name: 'x', protocol: 'vless', address: 'a', port: 1, ...over }) as ServerConfig;
    // WG 夹具只填被谓词读到的键；其余必填键（privateKey 等）与本判定无关，故整体断言（同 nodes-logic.test.ts）。
    const cases: Array<[ServerConfig, { mainCorePool: boolean }, boolean]> = [
      [
        srv({ protocol: 'wireguard', wireguardSettings: { reverseMesh: true } } as Partial<ServerConfig>),
        { mainCorePool: true },
        false,
      ],
      [srv({ protocol: 'tailscale', tailscaleSettings: {} }), { mainCorePool: true }, false],
      [
        srv({
          protocol: 'wireguard',
          wireguardSettings: { allowInternet: false, allowedIPs: ['10.0.0.0/8'] },
        } as Partial<ServerConfig>),
        { mainCorePool: true },
        false,
      ],
      [srv({ protocol: 'tailscale', tailscaleSettings: { exitNode: 'n' } }), { mainCorePool: false }, false],
      [srv({ protocol: 'custom', customSettings: { isEndpoint: true, outbound: {} } }), { mainCorePool: true }, false],
      [srv({}), { mainCorePool: true }, true],
    ];
    for (const [server, caps, stagedOnly] of cases) {
      const reason = speedTestBlockReason(server, caps, stagedOnly);
      expect(reason, '构造的用例应当是不可测的').not.toBeNull();
      expect(
        speedTestBlockedMessage(reason as SpeedTestBlockReason, t),
        `原因码 ${reason} 没有专属文案`
      ).not.toBe('nodes.speedTestNotApplicable');
    }
  });
});

/**
 * 🔴 **超限文案里那个「最多带 N 个」不许比后端的真实上限大** —— 报大了，用户照着砍完仍被拒。
 *
 * # 为什么这个数不能只写在译文里
 *
 * 后端 `temp_core_max_naive(n)` 现算的精确值只到得了诊断串（失败信封没有数据面，见
 * `TEMP_CORE_NAIVE_CEILING_HINT` 的文档），所以用户可见的那个数是前端一个保守常量 + 五份译文里的
 * `{{max}}`。它与后端四个系数之间**没有任何编译期联系**：多点实测之后 `t_engine` 必然要改
 * （`core-supervisor/src/readiness_gate.rs` 的系数出处表里写着它是两点回归的推导值），改完这五处
 * 译文会静默过期。
 * 本门就是那条联系：直接读 Rust 常量把上限现算出来对拍。
 *
 * 取材同 `speedtest-progress-toast.test.ts`：`moduleSource` 入口 + 剥注释 + 命中数自检
 * （裸 `readFileSync` + 不剥注释的正则会被文档注释里的同形常量替真常量作证，复审已实测打穿过一次）。
 */
describe('超限文案里那个「最多带 N 个」', () => {
  /*
   * 取材面走 `contracts/rust-source.test-support.ts` 的共享净化器（`crates/source-probe` 那个字节
   * 状态机的逐条移植），**不再**用本地那份正则版：正则剥得掉注释，却保护不了字符串 ——
   * 一条 `const _X: &str = "const CORE_STARTUP_PER_NAIVE_MS: u64 = 1;";` 就能在真常量改名之后
   * 让本门读到假值并全绿（复审 2026-09-03 构造实测，本仓同族第三次）。
   * should-throw 的对照用例在 `lib/speedtest-progress-toast.test.ts`（同一份实现，不重复写两遍）。
   */
  const RUNTIME_SPEEDTEST = maskRustCommentsAndStrings(
    moduleSource('src-tauri/src/runtime/speedtest')
  );

  /*
   * 起核耗时的三个系数与安全系数**不在** `speedtest.rs`：它们是主核与测速临时核共用的规模模型，
   * 单一真值在 `crates/core-supervisor/src/readiness_gate.rs`。那边曾在 `speedtest.rs` 里有一份逐值
   * 相同的 `TEMP_CORE_*` 副本（由一道双向防漂移门顶着），2026-09-03 收口删掉 ⇒ 本门的取材面跟着搬到
   * 单一真值那边。**这不是取材面放宽**：两处都是 `moduleSource` 入口 + 剥注释与字符串 + 命中数恰好 1，
   * 且现在读的就是生产代码真正在用的那一份，中间再没有一层可以悄悄漂移的副本。
   */
  const READINESS_GATE = maskRustCommentsAndStrings(
    moduleSource('crates/core-supervisor/src/readiness_gate')
  );

  const rustConst = (name: string): number =>
    rustConstU64(RUNTIME_SPEEDTEST, name, 'speedtest-naive-ceiling');

  const supervisorConst = (name: string): number =>
    rustConstU64(READINESS_GATE, name, 'speedtest-naive-ceiling');

  /**
   * 与 `runtime/speedtest.rs::temp_core_max_naive` 同一条算式（含它那两处整数截断）。
   *
   * ⚠️ **分母是批预算（12s），不是 60s 那条拒绝上限** —— T1-R1 改过。分批之后单批真正的窗口是
   * 「前端静默兜底 20s − 批间固定开销 8s」，照 60s 那条算出来的 ≈727 会把用户引向第二个坑
   * （砍到 727 ⇒ 单批预算 ≈30s ⇒ 假的「测速中断」）。判据见该函数的文档。
   */
  function backendCeiling(nodeCount: number): number {
    const batchBudgetCap =
      rustConst('TEMP_CORE_UI_IDLE_TIMEOUT_MS') - rustConst('TEMP_CORE_BATCH_WINDOW_OVERHEAD_MS');
    const perCore = Math.floor(batchBudgetCap / supervisorConst('CORE_READY_SAFETY_FACTOR'));
    const nonEngine =
      supervisorConst('CORE_STARTUP_BASELINE_FIXED_MS') +
      Math.floor((nodeCount * supervisorConst('CORE_STARTUP_PER_NODE_US')) / 1000);
    return Math.floor(
      Math.max(perCore - nonEngine, 0) / supervisorConst('CORE_STARTUP_PER_NAIVE_MS')
    );
  }

  it('取材自检：注释里的假常量不算数，且两个真取材面都非空', () => {
    expect(
      maskRustCommentsAndStrings('/// const CORE_STARTUP_PER_NAIVE_MS: u64 = 1;\nx;')
    ).not.toMatch(/CORE_STARTUP_PER_NAIVE_MS/);
    // 两个面各读一半：系数在单一真值那边，批窗那两个常量仍在 `speedtest.rs`。任一面读空/读错，
    // `rustConstU64` 的命中数自检会当场抛 —— 但那要等到用它的那条断言，故此处先各钉一次。
    expect(READINESS_GATE).toMatch(/const CORE_STARTUP_PER_NAIVE_MS\s*:\s*u64/);
    expect(RUNTIME_SPEEDTEST).toMatch(/const TEMP_CORE_UI_IDLE_TIMEOUT_MS\s*:\s*u64/);
  });

  /**
   * 覆盖到 n=10 000（本仓见过的最大订阅量级还低一个数量级）。`n` 项让上限随节点数缓慢下滑，
   * 取整段的**最小值**对拍 —— 只拿 n=0 那个点比，n 大时报出去的数就偏乐观了。
   */
  it('🔴 不大于后端真实上限（否则用户砍到这个数仍会被拒）', () => {
    const worst = Math.min(...[0, 1_000, 5_000, 10_000].map(backendCeiling));
    expect(worst, '前提校验：算出来的上限得是个正数，否则本条无对象可守').toBeGreaterThan(0);
    expect(
      TEMP_CORE_NAIVE_CEILING_HINT,
      `文案里报的 ${TEMP_CORE_NAIVE_CEILING_HINT} 已超过后端上限 ${worst} —— ` +
        '后端系数改过了？同步本常量与五份译文里的 {{max}}'
    ).toBeLessThanOrEqual(worst);
  });

  it('也不许保守到没信息量（报 1 个同样不可执行）', () => {
    const worst = Math.min(...[0, 1_000, 5_000, 10_000].map(backendCeiling));
    expect(TEMP_CORE_NAIVE_CEILING_HINT).toBeGreaterThanOrEqual(Math.floor(worst * 0.9));
  });
});
