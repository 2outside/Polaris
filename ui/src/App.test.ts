/**
 * `event:proxyError` 分腿路由单测（对齐 App.tsx 头注「代理错误」小节）。
 *
 * 只测导出的 `handleProxyErrorEvent`（不渲染 App —— vitest `environment: 'node'`，全仓无组件渲染测试）。
 * mock 掉 `./lib/error-handler`（toast）与 `./lib/desktop-notify`（notifyDesktop）——两者是本函数
 * 唯一的可观察副作用出口，其余（React/zustand/AppShell 等）只是模块图谱的一部分，无需关心。
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

const { toastErrorMock, toastWarningMock, toastInfoMock, notifyDesktopMock } = vi.hoisted(() => ({
  toastErrorMock: vi.fn(),
  toastWarningMock: vi.fn(),
  toastInfoMock: vi.fn(),
  notifyDesktopMock: vi.fn(),
}));
vi.mock('./lib/error-handler', () => ({
  toast: {
    error: toastErrorMock,
    warning: toastWarningMock,
    success: vi.fn(),
    info: toastInfoMock,
  },
}));
vi.mock('./lib/desktop-notify', () => ({
  notifyDesktop: notifyDesktopMock,
  setDesktopNotificationsEnabled: vi.fn(),
}));

/**
 * `<html dir/lang>` 的落点桩。
 *
 * App.tsx 的模块图谱含 `i18n/index.ts`（语言水合腿的调用点），而后者在**模块加载期**就写
 * `document.documentElement`；本仓 vitest 是 node 环境、有意不引 jsdom（`vite.config.ts:74`），
 * 故沿用既有先例（`i18n/language-hydration.test.ts`、`settings/terminal-env-and-fold.test.tsx`）
 * 先立桩、再**动态** import —— 静态 import 会被提升到桩之前，那正是这条腿曾经炸掉的方式。
 */
(globalThis as unknown as { document: unknown }).document = {
  documentElement: { dir: '', lang: '' },
};

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { isProxyErrorCode } from './contracts/types';

// 认领闸门用**真实实现**（不 mock）：本组要验的正是「事件腿与认领闸门的合璧」，mock 掉闸门等于
// 把被测的接线换成桩，两边各自绿、合起来仍双报。
//
// 认领态是模块级单例、跨用例存活（宽限尾巴会把后一条用例吞成静默），因此每个用例都要一份干净的。
// 复位**不走生产模块导出的 `reset*()`**：那种钩子进产物、是公开契约、生产零调用点。改成
// `vi.resetModules()` + 动态 import —— 注意 `./App` 与 `./lib/proxy-start-claim` **必须一起重取**，
// 只重取后者会让 App 仍持有旧实例，两边不再是同一个闸门，而本组要验的恰恰是它们的合璧。
let handleProxyErrorEvent: typeof import('./App')['handleProxyErrorEvent'];
let withProxyStartClaim: typeof import('./lib/proxy-start-claim')['withProxyStartClaim'];

/**
 * 预热：把 `./App` 的**冷转换**成本挪出 `beforeEach`。
 *
 * `./App` 的静态模块图有 250 个模块 / 3.3MB 源码（AppShell → 全部 screens，含 NodesScreen 一支）。
 * 上面那套 `vi.resetModules()` + 动态 import 是每条用例都跑一遍，但**只有第一遍**要付 Vite 的
 * 冷转换（隔离实测 2.1s；之后每遍只是重执行已缓存的模块，约 30ms）。而 vitest 的 `hookTimeout`
 * 默认 10s ⇒ 这笔一次性冷转换被记在了**第一条用例的 beforeEach 头上**。
 *
 * 全量跑时 196 个测试文件共用同一条 Vite 转换流水线，冷转换会被别的文件拖长（实测同一棵树上
 * 绿跑 `transform 55s`、红跑 `transform 122s`），偶发越过 10s ⇒ 第一条用例报
 * 「Hook timed out in 10000ms」。隔离跑无争用故恒绿——这不是顺序依赖，是**争用下的资源超时**，
 * 且必然只打第一条用例（后面每条只花 30ms，永远撞不到 10s）。
 *
 * 这里在文件加载期先取一次，把冷转换付在**不受 hookTimeout 管辖**的模块求值阶段；
 * 各用例的隔离性分毫不动——`beforeEach` 照旧 `resetModules()` + 重取，每条仍拿全新的闸门单例。
 * （**不要**改成调大 `hookTimeout` 或加 retry：那是把温度计砸了，冷转换仍在钩子里。）
 */
await import('./App');

/** 对齐 App.tsx 里 `t(key, fallback)` 的真实用法（第二参恒为字符串兜底）。 */
const t = vi.fn((key: string, fallback?: unknown) =>
  typeof fallback === 'string' ? fallback : key
);

describe('handleProxyErrorEvent（代理错误分腿）', () => {
  let refreshProxyStatus: () => Promise<void>;

  beforeEach(async () => {
    toastErrorMock.mockClear();
    toastWarningMock.mockClear();
    toastInfoMock.mockClear();
    notifyDesktopMock.mockClear();
    t.mockClear();
    refreshProxyStatus = vi.fn(async () => {});
    vi.resetModules();
    ({ handleProxyErrorEvent } = await import('./App'));
    ({ withProxyStartClaim } = await import('./lib/proxy-start-claim'));
  });

  it.each(['PROCESS_EXITED', 'AUTO_RESTART_FAILED'])(
    '崩溃腿 %s → 刷连接态 + 断开 toast + 桌面通知',
    (errorCode) => {
      handleProxyErrorEvent({ errorCode }, { t, refreshProxyStatus });
      expect(refreshProxyStatus).toHaveBeenCalledTimes(1);
      expect(toastErrorMock).toHaveBeenCalledWith('home.proxyCrashed');
      expect(toastWarningMock).not.toHaveBeenCalled();
      expect(notifyDesktopMock).toHaveBeenCalledTimes(1);
    }
  );

  // ── 本组的核心不变式：**i18n 键压过后端 message，不是反过来** ────────────────────
  //
  // 后端 `emit_proxy_error(message, error_code)` 两参皆非可选，`message` 是 Rust 侧写死的中文串。
  // 此前六处都写成 `data.message || t(key)` ⇒ `||` 右边永远短路不到，那些 key 是死键，
  // ru/fa 用户在最高频的错误路径上看到中文。下面几条带 message 的用例就是那条回归的哨兵：
  // 只要有人把优先级换回去，断言拿到的就会是中文串而不是键名。
  it.each(['SYSTEM_PROXY_FAILED', 'EXIT_MISMATCH'])(
    '出口误导腿 %s → warning toast 用 i18n 键（**压过**后端中文 message）+ 桌面通知，不刷连接态',
    (errorCode) => {
      handleProxyErrorEvent(
        { errorCode, message: '核在跑但实际出口 ≠ 选中节点' },
        { t, refreshProxyStatus }
      );
      expect(refreshProxyStatus).not.toHaveBeenCalled();
      expect(toastErrorMock).not.toHaveBeenCalled();
      expect(toastWarningMock).toHaveBeenCalledTimes(1);
      expect(toastWarningMock).toHaveBeenCalledWith('home.proxyMisdirected');
      // 后端那句中文一个字都不该出现在 toast 里。
      expect(toastWarningMock.mock.calls[0][0]).not.toContain('核在跑');
      expect(toastWarningMock.mock.calls[0][0]).not.toContain('已断开');
      expect(notifyDesktopMock).toHaveBeenCalledTimes(1);
    }
  );

  it('能力降级腿 RULE_RESOURCES_MISSING → warning toast 用 i18n 键（压过 message）+ 桌面通知', () => {
    handleProxyErrorEvent(
      { errorCode: 'RULE_RESOURCES_MISSING', message: '规则资源 geosite-cn 缺少本地副本' },
      { t, refreshProxyStatus }
    );
    expect(refreshProxyStatus).not.toHaveBeenCalled();
    expect(toastErrorMock).not.toHaveBeenCalled();
    expect(toastWarningMock).toHaveBeenCalledTimes(1);
    expect(toastWarningMock).toHaveBeenCalledWith('home.ruleResourcesMissing');
    expect(toastWarningMock.mock.calls[0][0]).not.toContain('geosite-cn');
    expect(toastWarningMock.mock.calls[0][0]).not.toContain('已断开');
    expect(notifyDesktopMock).toHaveBeenCalledTimes(1);
  });

  // 无 message 时同样落到**本码自己的**键（含可操作指引），不得复用出口误导腿那条
  // ——两者用户下一步动作不同，串了等于把「去规则资源页下载」这条指引冲掉。
  it('RULE_RESOURCES_MISSING 无 message → 仍是本码专属键 + 专属通知 key', () => {
    handleProxyErrorEvent({ errorCode: 'RULE_RESOURCES_MISSING' }, { t, refreshProxyStatus });
    expect(toastWarningMock).toHaveBeenCalledWith('home.ruleResourcesMissing');
    expect(notifyDesktopMock).toHaveBeenCalledWith(
      'notify.ruleResourcesMissing.title',
      'notify.ruleResourcesMissing.body'
    );
  });

  it('SYSTEM_DNS_TAKEOVER_FAILED → 保留运行态并显示本地化 DNS 降级指引', () => {
    handleProxyErrorEvent(
      { errorCode: 'SYSTEM_DNS_TAKEOVER_FAILED', message: 'Linux 系统 DNS 接管失败' },
      { t, refreshProxyStatus }
    );
    expect(refreshProxyStatus).not.toHaveBeenCalled();
    expect(toastErrorMock).not.toHaveBeenCalled();
    expect(toastWarningMock).toHaveBeenCalledWith('errors.systemDnsTakeoverFailed');
    expect(notifyDesktopMock).toHaveBeenCalledWith(
      'notify.systemDnsTakeoverFailed.title',
      'notify.systemDnsTakeoverFailed.body'
    );
  });

  it("isProxyErrorCode('RULE_RESOURCES_MISSING') === true", () => {
    expect(isProxyErrorCode('RULE_RESOURCES_MISSING')).toBe(true);
  });

  it('STARTUP_FAILED → 不重复报（发起方自己 toast，此处零弹）', () => {
    handleProxyErrorEvent({ errorCode: 'STARTUP_FAILED' }, { t, refreshProxyStatus });
    expect(refreshProxyStatus).not.toHaveBeenCalled();
    expect(toastErrorMock).not.toHaveBeenCalled();
    expect(toastWarningMock).not.toHaveBeenCalled();
    expect(notifyDesktopMock).not.toHaveBeenCalled();
  });

  it("isProxyErrorCode('EXIT_MISMATCH') === true", () => {
    expect(isProxyErrorCode('EXIT_MISMATCH')).toBe(true);
  });

  // ── TUN 提权门两码 ─────────────────────────────────────────────────────────
  //
  // 这两条腿此前**整条落空**（函数末尾无 else，后端发了码前端直接丢）。发起方常常没人在 await：
  // 托盘切档位 / 启动自动连接 / switchMode 去抖重启都不经 Home 连接按钮 —— 真机反馈「点了没反应」。

  it('HELPER_GATE_ABORTED（用户取消）→ 刷连接态 + 中性 info，不报错、不发桌面通知', () => {
    handleProxyErrorEvent({ errorCode: 'HELPER_GATE_ABORTED' }, { t, refreshProxyStatus });
    // 核未起（终态）→ 必须刷，否则 UI 停在假「已连接」。
    expect(refreshProxyStatus).toHaveBeenCalledTimes(1);
    expect(toastInfoMock).toHaveBeenCalledWith('errors.helperGateAborted');
    // 用户自己点的取消不是错误：红 toast 会把「我不想装」渲染成「出错了」。
    expect(toastErrorMock).not.toHaveBeenCalled();
    expect(toastWarningMock).not.toHaveBeenCalled();
    // 自己点的取消再推一条系统通知 = 噪音。
    expect(notifyDesktopMock).not.toHaveBeenCalled();
  });

  it('HELPER_NOT_INSTALLED（装不上）→ 刷连接态 + error toast 用 i18n 键（压过 message）+ 桌面通知', () => {
    handleProxyErrorEvent(
      { errorCode: 'HELPER_NOT_INSTALLED', message: 'helper 尚未安装' },
      { t, refreshProxyStatus }
    );
    expect(refreshProxyStatus).toHaveBeenCalledTimes(1);
    expect(toastErrorMock).toHaveBeenCalledWith('errors.helperNotInstalledDesc');
    expect(toastInfoMock).not.toHaveBeenCalled();
    // 窗口常已收进托盘（托盘切档位触发），应用内 toast 送不到 → 桌面通知是唯一送达路径。
    expect(notifyDesktopMock).toHaveBeenCalledWith(
      'notify.helperNotInstalled.title',
      'notify.helperNotInstalled.body'
    );
  });

  // 两码**不得合并**：用户下一步动作相反（去装 vs 什么都不做）。合并会把可操作指引冲掉，
  // 或反过来对刚拒绝过的用户再催一遍。
  it('两码各用各的兜底文案与 toast 等级（不串腿）', () => {
    handleProxyErrorEvent({ errorCode: 'HELPER_NOT_INSTALLED' }, { t, refreshProxyStatus });
    const notInstalled = toastErrorMock.mock.calls[0][0];
    toastErrorMock.mockClear();
    handleProxyErrorEvent({ errorCode: 'HELPER_GATE_ABORTED' }, { t, refreshProxyStatus });
    expect(toastInfoMock.mock.calls[0][0]).not.toBe(notInstalled);
    expect(toastErrorMock).not.toHaveBeenCalled();
  });

  it.each(['HELPER_NOT_INSTALLED', 'HELPER_GATE_ABORTED'])(
    'isProxyErrorCode(%s) === true（契约认这两个码，否则前端 err.code 会被判为脏值丢弃）',
    (c) => {
      expect(isProxyErrorCode(c)).toBe(true);
    }
  );

  // ── root 孤儿阻断腿（此前**完全不路由**，本码在托盘/自动连接等无人 await 的入口是静默丢弃） ──

  it('ROOT_ORPHAN_BLOCKED → 刷连接态 + 本地化 error toast + 桌面通知', () => {
    handleProxyErrorEvent(
      { errorCode: 'ROOT_ORPHAN_BLOCKED', message: '上次遗留的 sing-box 核（pid [12345]）以管理员权限运行且无法清理，它占用着内核缓存文件，任何模式都无法启动。请安装/修复 Helper 后重试，或手动执行：sudo kill -9 12345' },
      { t, refreshProxyStatus }
    );
    // 核未起（终态）→ 必须刷，否则 UI 停在假「已连接」。
    expect(refreshProxyStatus).toHaveBeenCalledTimes(1);
    // 可变 pid/命令仅留诊断日志；用户可见出口只认稳定码的五语键。
    expect(toastErrorMock).toHaveBeenCalledWith('errors.rootOrphanBlocked');
    expect(notifyDesktopMock).toHaveBeenCalledWith(
      'notify.rootOrphanBlocked.title',
      'notify.rootOrphanBlocked.body'
    );
  });

  it("isProxyErrorCode('ROOT_ORPHAN_BLOCKED') === true（否则前端 err.code 会被判为脏值丢弃）", () => {
    expect(isProxyErrorCode('ROOT_ORPHAN_BLOCKED')).toBe(true);
  });

  // ── 与发起方（Home 连接按钮）的去重：认领闸门 ─────────────────────────────
  //
  // 这三码（HELPER 两码 + ROOT_ORPHAN_BLOCKED）是后端**双出口**（emit 事件 + 让 api.proxy.start
  // reject）。发起方在场时两条腿都报 ⇒ 同一次失败弹两遍（NOT_INSTALLED 更是 toast + 桌面通知 +
  // 「去安装」模态三重），违反本文件 §STARTUP_FAILED 的既有约定。但事件腿**不能**整条忽略——
  // 没人 await 的入口（托盘/自动连接/去抖重启）会因此静默。下面两组分别钉住这两个相反方向的失效。

  describe('认领期内（Home 连接按钮已发起）→ 提示让位给 await 腿', () => {
    /** 模拟「本窗口发起的起核失败」：认领包裹内 reject，落定后事件才到达（最坏顺序）。 */
    async function claimFailedStart(): Promise<void> {
      await withProxyStartClaim(() => Promise.reject(new Error('helper 门失败'))).catch(() => {});
    }

    it('HELPER_GATE_ABORTED：事件腿零提示（否则与 Home 的 info toast 双报）', async () => {
      await claimFailedStart();
      handleProxyErrorEvent({ errorCode: 'HELPER_GATE_ABORTED' }, { t, refreshProxyStatus });
      expect(toastInfoMock).not.toHaveBeenCalled();
      expect(toastErrorMock).not.toHaveBeenCalled();
      expect(notifyDesktopMock).not.toHaveBeenCalled();
    });

    it('HELPER_NOT_INSTALLED：事件腿零提示且不发桌面通知（否则 toast+通知+模态三重）', async () => {
      await claimFailedStart();
      handleProxyErrorEvent({ errorCode: 'HELPER_NOT_INSTALLED' }, { t, refreshProxyStatus });
      expect(toastErrorMock).not.toHaveBeenCalled();
      expect(toastInfoMock).not.toHaveBeenCalled();
      // 用户正盯着连接按钮，系统通知在此刻纯属噪音。
      expect(notifyDesktopMock).not.toHaveBeenCalled();
    });

    it.each(['HELPER_GATE_ABORTED', 'HELPER_NOT_INSTALLED', 'ROOT_ORPHAN_BLOCKED'])(
      '%s：认领期内仍必须刷连接态（await 腿并不刷，漏刷则 UI 停在假「已连接」）',
      async (errorCode) => {
        await claimFailedStart();
        handleProxyErrorEvent({ errorCode }, { t, refreshProxyStatus });
        expect(refreshProxyStatus).toHaveBeenCalledTimes(1);
      }
    );

    it('ROOT_ORPHAN_BLOCKED：事件腿零提示且不发桌面通知（否则与 await 腿双报）', async () => {
      await claimFailedStart();
      handleProxyErrorEvent({ errorCode: 'ROOT_ORPHAN_BLOCKED' }, { t, refreshProxyStatus });
      expect(toastErrorMock).not.toHaveBeenCalled();
      expect(notifyDesktopMock).not.toHaveBeenCalled();
    });

    // 认领的射程仅限提权门两码 + ROOT_ORPHAN_BLOCKED。若把认领判定提到函数顶部（或扩到其它码），
    // 一次连接按钮点击就会顺带吞掉这 2s 内任何来源的崩溃/出口误导告警 —— 凭空制造静默。
    it('认领不外溢：认领期内的崩溃腿照常报（PROCESS_EXITED）', async () => {
      await claimFailedStart();
      handleProxyErrorEvent({ errorCode: 'PROCESS_EXITED' }, { t, refreshProxyStatus });
      expect(toastErrorMock).toHaveBeenCalledWith('home.proxyCrashed');
      expect(notifyDesktopMock).toHaveBeenCalledTimes(1);
    });

    it('认领不外溢：认领期内的出口误导腿照常报（EXIT_MISMATCH）', async () => {
      await claimFailedStart();
      handleProxyErrorEvent({ errorCode: 'EXIT_MISMATCH' }, { t, refreshProxyStatus });
      expect(toastWarningMock).toHaveBeenCalledTimes(1);
      expect(notifyDesktopMock).toHaveBeenCalledTimes(1);
    });
  });

  describe('无人认领（托盘 / 启动自动连接 / switchMode 去抖重启）→ 事件腿照常报', () => {
    // 这一组是「修过头」的反向哨兵：认领若恒真（或抑制写死），这三条就会红。
    it('HELPER_GATE_ABORTED：仍出 info toast，不得静默', () => {
      handleProxyErrorEvent({ errorCode: 'HELPER_GATE_ABORTED' }, { t, refreshProxyStatus });
      expect(toastInfoMock).toHaveBeenCalledWith('errors.helperGateAborted');
      expect(refreshProxyStatus).toHaveBeenCalledTimes(1);
    });

    it('HELPER_NOT_INSTALLED：仍出 error toast + 桌面通知，不得静默', () => {
      handleProxyErrorEvent({ errorCode: 'HELPER_NOT_INSTALLED' }, { t, refreshProxyStatus });
      expect(toastErrorMock).toHaveBeenCalledTimes(1);
      expect(notifyDesktopMock).toHaveBeenCalledWith(
        'notify.helperNotInstalled.title',
        'notify.helperNotInstalled.body'
      );
    });

    // 本条正是本次要修的缺陷本身：此前这里没有分腿，托盘/自动连接撞上残留 root 孤儿时用户
    // 什么都看不到（真机反馈的直接成因）。
    it('ROOT_ORPHAN_BLOCKED：仍出 error toast + 桌面通知，不得静默', () => {
      handleProxyErrorEvent(
        { errorCode: 'ROOT_ORPHAN_BLOCKED', message: '残留进程（pid [999]）占用缓存文件' },
        { t, refreshProxyStatus }
      );
      expect(refreshProxyStatus).toHaveBeenCalledTimes(1);
      expect(toastErrorMock).toHaveBeenCalledWith('errors.rootOrphanBlocked');
      expect(notifyDesktopMock).toHaveBeenCalledWith(
        'notify.rootOrphanBlocked.title',
        'notify.rootOrphanBlocked.body'
      );
    });

    it('认领过期后恢复上报（认领不得长期挂住，否则后续托盘失败被永久吞掉）', async () => {
      vi.useFakeTimers();
      try {
        await withProxyStartClaim(async () => {});
        vi.advanceTimersByTime(2001);
        handleProxyErrorEvent({ errorCode: 'HELPER_NOT_INSTALLED' }, { t, refreshProxyStatus });
      } finally {
        vi.useRealTimers();
      }
      expect(toastErrorMock).toHaveBeenCalledTimes(1);
      expect(notifyDesktopMock).toHaveBeenCalledTimes(1);
    });
  });
});

/* ────────────────────────────────────────────────────────────────────────────
 * 腿 B：「提权助手可升级」→ 全局可操作 toast
 *
 * 修的是什么：`EVENT_HELPER_UPGRADEABLE` 的行内契约写的是「渲染端 toast 引导升级」，而全仓唯一的
 * 订阅者是设置›助手页的**页面级**订阅 —— 用户不站在那一页时没有任何人在听。
 * ──────────────────────────────────────────────────────────────────────────── */

describe('handleHelperUpgradeable（提权助手可升级 → 可操作 toast）', () => {
  let handleHelperUpgradeable: (typeof import('./App'))['handleHelperUpgradeable'];
  let useNavStore: (typeof import('./store/nav-store'))['useNavStore'];

  beforeEach(async () => {
    toastWarningMock.mockClear();
    t.mockClear();
    // 去重闸门是**模块级单例**（这正是它的判据：挂组件内会随 App 重挂复位），故每条用例都必须
    // 重取一份干净的模块图。`./App` 与 `./store/nav-store` **必须一起重取** —— 只重取后者会让
    // App 仍持有旧 store 实例，跳转断言就落在一个没人看的对象上（同本文件上一组的理由）。
    vi.resetModules();
    ({ handleHelperUpgradeable } = await import('./App'));
    ({ useNavStore } = await import('./store/nav-store'));
  });

  it('正面：已装 + 可升级 → 弹一条带动作的 warning toast（文案全部走 i18n 键）', () => {
    expect(handleHelperUpgradeable({ installed: true, upgradeable: true }, t)).toBe(true);
    expect(toastWarningMock).toHaveBeenCalledTimes(1);
    const [msg, opts] = toastWarningMock.mock.calls[0];
    expect(msg).toBe('helper.statusUpgradeable');
    expect(opts.description).toBe('helper.upgradeDescCard');
    // 「可操作」不是形容词：没有 actions 的 toast 是 pointer-events:none 的一次性通知，
    // 用户看到「该升级了」却无处可点 —— 那与不提示的差别只有一句空话。
    expect(opts.actions).toHaveLength(1);
    expect(opts.actions[0].label).toBe('helper.upgradeToastAction');
  });

  it('正面：点动作跳设置›助手页（与 HELPER_NOT_INSTALLED 的「去安装」同一个落点）', () => {
    expect(useNavStore.getState().scope).toBe('main');
    handleHelperUpgradeable({ installed: true, upgradeable: true }, t);
    toastWarningMock.mock.calls[0][1].actions[0].onClick();
    expect(useNavStore.getState().scope).toBe('settings');
    expect(useNavStore.getState().settingsScreen).toBe('helper');
  });

  it('反向对照：同一会话第二次不再弹（两个触发源必然重叠，没闸门就是同一件事弹两条）', () => {
    expect(handleHelperUpgradeable({ installed: true, upgradeable: true }, t)).toBe(true);
    // 第二发 = 挂载回读与事件撞上，或 App 因轻量模式返回 / 窗口重建而重挂。
    expect(handleHelperUpgradeable({ installed: true, upgradeable: true }, t)).toBe(false);
    expect(handleHelperUpgradeable({ installed: true, upgradeable: true }, t)).toBe(false);
    expect(toastWarningMock).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['已装且是最新', { installed: true, upgradeable: false }],
    ['未装（那是「去安装」轴，不是本腿的事）', { installed: false, upgradeable: true }],
    ['空对象', {}],
    ['null（getStatus 尚未返回）', null],
    ['undefined', undefined],
  ])('阴性：%s → 不弹，且**不消耗**一次性名额', (_label, status) => {
    expect(handleHelperUpgradeable(status, t)).toBe(false);
    expect(toastWarningMock).not.toHaveBeenCalled();
    // 名额没被烧掉的证明：紧接着喂一个真命中的状态，仍必须弹得出来。
    // 少了这一条，「判定为假」与「闸门先被误领走」在上面的断言下长得一模一样。
    expect(handleHelperUpgradeable({ installed: true, upgradeable: true }, t)).toBe(true);
    expect(toastWarningMock).toHaveBeenCalledTimes(1);
  });
});

/* ────────────────────────────────────────────────────────────────────────────
 * 源码级接线门：腿 B 的两条腿确实都挂在全局事件订阅层
 *
 * 上面那组测的是「判定与副作用」，它在**根本没人调用** `handleHelperUpgradeable` 时同样全绿 ——
 * 两扇门之间的缝就是生产路径。故这里扫 App.tsx 源码，钉死「订阅 + 挂载回读」两件都在。
 * ──────────────────────────────────────────────────────────────────────────── */

const APP_RAW = readFileSync(fileURLToPath(new URL('./App.tsx', import.meta.url)), 'utf8');

/**
 * 去注释后的源码。两个方向都必要（同 `tray/tray-menu-height.test.ts` 的 `MENU`）：本仓注释习惯
 * 逐字引用被守的调用（本腿的 effect 注释里就写着 `helper_get_status`、`SettingsHelper.tsx`），
 * 扫原文会被自己的说明文字充数 —— 把接线整段删掉、注释留着，正面 `toContain` 照样绿。
 */
const APP = APP_RAW.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');

/** 按唯一锚点取一段并封顶 —— 切片射程由判据决定，不由书写顺序决定。 */
function sliceApp(anchor: string, end: string): string {
  const hits = APP.split(anchor).length - 1;
  expect(hits, `锚点 ${anchor} 命中 ${hits} 次（应为 1）`).toBe(1);
  const a = APP.indexOf(anchor) + anchor.length;
  const b = APP.indexOf(end, a);
  expect(b, `找不到收尾串 ${end} —— 切片会一路跑到文件尾`).toBeGreaterThan(a);
  return APP.slice(a, b);
}

describe('接线门：可升级提示挂在全局事件订阅层（订阅 + 挂载回读，缺一不可）', () => {
  it('守卫自检：扫到的确实是 App.tsx，去注释后没被吃空，且注释确实被吃掉了', () => {
    expect(APP_RAW.length).toBeGreaterThan(10_000);
    expect(APP).toContain('export function handleHelperUpgradeable');
    expect(APP.length).toBeGreaterThan(APP_RAW.length / 3);
    // 这句只在注释里出现过；它还在 = 注释没被剥，下面每条正面断言都可能是注释在充数。
    expect(APP).not.toContain('就等于没有消费者');
  });

  it('闸门是模块级单例（挂组件内会随 App 重挂复位，等于没去重）', () => {
    expect(APP).toContain('const helperUpgradeToastGate = createOnceGate();');
    expect(
      sliceApp('export function handleHelperUpgradeable(', '\n}\n'),
      '判定与去重必须在同一处收口，否则订阅腿与回读腿各弹一条'
    ).toContain('if (!helperUpgradeToastGate()) return false;');
  });

  it('两条腿都在同一个 effect 里：事件订阅 + 挂载即回读一次', () => {
    const body = sliceApp(
      '    const check = () =>',
      '  }, [t]);',
    );
    // 用正则而不是 `toContain`：这条链被换行折成了多行，写死单行字面量的断言会在下一次
    // 换行位置变动时假红（判据是「调了谁」，不是「怎么排版」）。
    expect(body, '回读腿：事件早于 App 挂载时，只订阅一个字节都收不到').toMatch(
      /helperApi\s*\.getStatus\(\)/
    );
    expect(body, '回读腿必须在挂载时**真的被调用**，不能只定义不调').toContain('\n    check();');
    expect(body, '订阅腿：App 已挂载时由 T+7s 那一发送达').toContain(
      'helperApi.onUpgradeable(() => check())'
    );
    expect(body, '两条腿都要经同一个判定+去重入口').toContain('handleHelperUpgradeable(s, t)');
    expect(body, '回读失败静默（后端未就绪的启动窗口里弹 toast 是噪音）').toContain(
      '.catch(() => undefined)'
    );
    expect(body, 'effect 必须返回退订闭包，否则 App 重挂后订阅泄漏').toContain('return off;');
  });

  it('不新增 IPC 命令：只用既有的 helper 通道（`helper_get_status` 早已返回 upgradeable）', () => {
    expect(APP).toContain("import { helperApi, unlockApi } from './ipc/api-client';");
    expect(APP).not.toMatch(/helperUpgrade[A-Za-z]*Command|invoke\(\s*['"]helper:/);
  });
});
