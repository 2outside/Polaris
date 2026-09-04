/**
 * 托盘浮层窗高收敛的行为门 —— 「托盘菜单里的『退出』要往下拉才看得见、退出 App 重开就正常」
 * 那条缺陷的常驻防线。
 *
 * # 为什么测的是纯函数而不是组件
 *
 * 本仓 vitest 跑 node 环境、刻意不装 jsdom（`vite.config.ts` test 段），`useLayoutEffect` /
 * `ResizeObserver` / `matchMedia` 一个都没有 ⇒ 真 hook 跑不起来。故把「锁什么时候合、什么时候清」
 * 和「屏幕换代怎么重新武装」抽进 `tray-menu-height.ts`，在这里直测；组件里剩下的那点接线由本文件
 * 末尾的源码级接线门锁住（桥的**宿主**半边由 Rust 侧 `tray/tests/overlay_lifecycle_gate.rs` 的
 * `every_overlay_show_tells_the_renderer_to_remeasure`（腿 A）与
 * `screen_change_is_pushed_by_the_host_over_the_existing_eval_bridge`（腿 B 的宿主源）守）。
 *
 * # 反向对照为什么必须在
 *
 * 「更矮的值被采纳」这类断言，在「压根没锁上」（`return measured`）的实现里同样是绿的。故每一组
 * 正面断言都配一条「`settled=false` 时锁纹丝不动」的对照 —— 探针必须取非 main 视图：最近值胜之后
 * 主视图测量本来就会改写锁，拿它当探针分不出「没锁上」和「锁被刷新了」。先证明这门确实观测得到
 * 那把锁，正面断言才有信息量。
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  armFontsReadyRemeasure,
  armScreenChangeRemeasure,
  resetTrayHeightLock,
  screenMetricQueries,
  trayReportedHeight,
  type TrayHeightLock,
  type TrayMediaQueryList,
  type TrayScreenView,
} from './tray-menu-height';

/**
 * 可注入的假屏。`matchMedia` 每次调用返回**新对象**（与浏览器一致），故 `removeEventListener`
 * 按「query + listener」配对摘除，而不是靠对象同一性。
 */
class FakeScreen implements TrayScreenView {
  devicePixelRatio = 2;
  screen = { width: 1512, height: 982 };
  /** 当前仍挂着监听的 query —— 「重新武装」的可观测面。 */
  readonly armed: Array<{ query: string; listener: () => void }> = [];

  matchMedia(query: string): TrayMediaQueryList {
    return {
      addEventListener: (_type, listener) => {
        this.armed.push({ query, listener });
      },
      removeEventListener: (_type, listener) => {
        const i = this.armed.findIndex(
          (a) => a.query === query && a.listener === listener,
        );
        if (i >= 0) this.armed.splice(i, 1);
      },
    };
  }

  queries(): string[] {
    return this.armed.map((a) => a.query);
  }

  /** 触发某条**已武装**的 query。没武装即抛 —— 「压根没装」不许伪装成「装了但没崩」。 */
  fire(query: string): void {
    const hit = this.armed.find((a) => a.query === query);
    if (!hit) {
      throw new Error(
        `未武装 ${query}；当前已武装：[${this.queries().join(' | ')}]`,
      );
    }
    hit.listener();
  }
}

describe('高度锁：主视图最近一次量到的值胜', () => {
  it('正面：主视图连量两次、第二次**更矮** ⇒ 回报跟着变矮（换到小屏这一档）', () => {
    const lock: TrayHeightLock = { current: null };
    expect(trayReportedHeight(lock, 700, true)).toBe(700);
    // 没有任何腿来清锁 —— 靠的就是「最近值胜」本身。旧口径「只认第一次」在这里必红：它会把窗
    // 永久钉在 700 上，小屏必被裁（「退出」连滚都够不到）；`Math.max` 单调增长同样救不了这一档。
    expect(trayReportedHeight(lock, 380, true)).toBe(380);
    expect(lock.current).toBe(380);
  });

  it('正面：主视图连量两次、第二次**更高** ⇒ 回报跟着变高', () => {
    const lock: TrayHeightLock = { current: null };
    expect(trayReportedHeight(lock, 420, true)).toBe(420);
    // 旧口径下这里回报 420：字体换上/i18n 落定把内容撑高了，窗还是那个矮窗，
    // 底部「退出」被挤进滚动区 —— 缺陷最初被报出来的正是这个形态。
    expect(trayReportedHeight(lock, 640, true)).toBe(640);
    expect(lock.current).toBe(640);
  });

  it('正面（原意图不能坏）：节点视图的测量**不进锁**，回报的仍是上一次主视图的值', () => {
    const lock: TrayHeightLock = { current: null };
    expect(trayReportedHeight(lock, 420, true)).toBe(420);
    // 进「全部节点」（settled=false：view !== 'main'），几十个节点把自然高拉到 1200。
    expect(trayReportedHeight(lock, 1200, false)).toBe(420);
    // 分组全部折叠，自然高塌到 180 —— 外层菜单同样不许跟着缩。
    expect(trayReportedHeight(lock, 180, false)).toBe(420);
    // 挡住「忽高忽低」的是 `settled` 里的 `view === 'main'` 那一半，不是「只认第一次」：
    // 锁自始至终是 420，两次节点视图测量一个字节也没写进去。
    expect(lock.current).toBe(420);
    // 退回主视图。
    expect(trayReportedHeight(lock, 420, true)).toBe(420);
  });

  it('正面：从未在主视图量过时（锁为空）回报**当次实测**，不是 0/undefined', () => {
    const lock: TrayHeightLock = { current: null };
    const reported = trayReportedHeight(lock, 240, false); // 照量照报，但不锁
    expect(reported).toBe(240);
    expect(lock.current).toBeNull();
    expect(trayReportedHeight(lock, 420, true)).toBe(420);
    expect(lock.current).toBe(420);
  });

  it('反向对照：`settled=false` 的测量一次都不许改写锁（证明门确实观测得到这把锁）', () => {
    const lock: TrayHeightLock = { current: null };
    expect(trayReportedHeight(lock, 420, true)).toBe(420);
    // 缺了这一条，上面「更矮/更高都被采纳」有可能只是因为压根没锁上（`return measured` 也全绿）。
    expect(trayReportedHeight(lock, 900, false)).toBe(420);
    expect(trayReportedHeight(lock, 120, false)).toBe(420);
    expect(lock.current).toBe(420);
  });

  it('正面（腿 A 清锁的必要性）：展开那一刻正停在节点视图 ⇒ 清锁后回报当次实测', () => {
    const lock: TrayHeightLock = { current: null };
    expect(trayReportedHeight(lock, 700, true)).toBe(700); // 上一代：大屏主视图
    // 用户上次收起时停在「全部节点」，而 `keepTrayMenuWarm` 默认开启 ⇒ WebView 不回收，
    // 下一次展开仍从节点视图起步：`settled` 恒 false，当次实测进不了锁。
    resetTrayHeightLock(lock); // = 宿主经 eval 桥通知「又展开了一次」
    expect(trayReportedHeight(lock, 380, false)).toBe(380);
    expect(lock.current).toBeNull();
  });

  it('反向对照：不清锁时同一序列回报的是上一代的 700 —— 证明上一条测的确实是清锁', () => {
    const lock: TrayHeightLock = { current: null };
    expect(trayReportedHeight(lock, 700, true)).toBe(700);
    // 少了 `resetTrayHeightLock`：小屏上按大屏的 700 开窗，窗体出屏被裁。
    expect(trayReportedHeight(lock, 380, false)).toBe(700);
    expect(lock.current).toBe(700);
  });
});

describe('屏幕换代重武装（腿 B）', () => {
  it('武装的就是当下这块屏的三条等值 query；拆监听后一条不剩', () => {
    const view = new FakeScreen();
    const off = armScreenChangeRemeasure(view, () => {});
    expect(view.queries()).toEqual([
      '(resolution: 2dppx)',
      '(device-width: 1512px)',
      '(device-height: 982px)',
    ]);
    expect(screenMetricQueries(view)).toEqual(view.queries());
    off();
    expect(view.queries()).toEqual([]);
  });

  it('正面：DPI 变化 fire 之后锁被重置，且 query **被用新的 dppx 重新武装**', () => {
    const view = new FakeScreen();
    const lock: TrayHeightLock = { current: null };
    const off = armScreenChangeRemeasure(view, () => resetTrayHeightLock(lock));
    expect(trayReportedHeight(lock, 420, true)).toBe(420);

    view.devicePixelRatio = 3; // 系统先换了 DPI，随后才 fire（真实顺序）
    view.fire('(resolution: 2dppx)');

    // ① 锁确实被重置：下一次测量重新收敛。
    expect(lock.current).toBeNull();
    expect(trayReportedHeight(lock, 610, true)).toBe(610);
    // ② **重建发生了** —— 断的是这个，不是「没崩」。旧目标值的 query 已摘、新目标值已挂。
    expect(view.queries()).toContain('(resolution: 3dppx)');
    expect(view.queries()).not.toContain('(resolution: 2dppx)');
    // ③ 第二次变化照样跟得上。只武装一次的写法在这里必红：那条 query 的条件已恒 false，
    //    此后永不再 fire，用户第二次改分辨率就回到旧缺陷。
    resetTrayHeightLock(lock);
    trayReportedHeight(lock, 610, true);
    view.devicePixelRatio = 1;
    view.fire('(resolution: 3dppx)');
    expect(lock.current).toBeNull();
    expect(view.queries()).toContain('(resolution: 1dppx)');
    off();
  });

  it('正面：屏幕几何变化 fire 之后锁被重置，且按新几何重新武装', () => {
    const view = new FakeScreen();
    const lock: TrayHeightLock = { current: null };
    const off = armScreenChangeRemeasure(view, () => resetTrayHeightLock(lock));
    expect(trayReportedHeight(lock, 700, true)).toBe(700);

    // 拖到另一块更矮的屏（同 DPI）：只有几何这一维变。
    view.screen = { width: 1280, height: 720 };
    view.fire('(device-height: 982px)');

    expect(lock.current).toBeNull();
    expect(trayReportedHeight(lock, 380, true)).toBe(380);
    expect(view.queries()).toEqual([
      '(resolution: 2dppx)',
      '(device-width: 1280px)',
      '(device-height: 720px)',
    ]);
    // 同一维再变一次照样跟得上。
    view.screen = { width: 3840, height: 2160 };
    view.fire('(device-width: 1280px)');
    expect(view.queries()).toContain('(device-height: 2160px)');
    off();
  });

  it('反向对照：一次 fire 都没有时锁没被清（否则上面几条「重置了」可能只是没锁上）', () => {
    const view = new FakeScreen();
    const lock: TrayHeightLock = { current: null };
    const off = armScreenChangeRemeasure(view, () => resetTrayHeightLock(lock));
    expect(trayReportedHeight(lock, 420, true)).toBe(420);
    // 探针取 `settled=false`：最近值胜之后，主视图测量本来就会改写锁，拿它当探针分不出
    // 「锁被清了」和「锁被刷新了」。非 main 视图的测量进不了锁 ⇒ 回报值只可能来自锁本身。
    expect(trayReportedHeight(lock, 900, false)).toBe(420);
    expect(lock.current).toBe(420);
    off();
  });

  it('拆监听之后即便系统仍把事件送进来也不得回调（WebView 回收/组件卸载后不许再动状态）', () => {
    const view = new FakeScreen();
    let calls = 0;
    const off = armScreenChangeRemeasure(view, () => {
      calls += 1;
    });
    const stale = view.armed.find((a) => a.query === '(resolution: 2dppx)');
    expect(stale, '取不到已武装的监听 —— 本条对照失去判据').toBeDefined();
    off();
    stale?.listener();
    expect(calls).toBe(0);
    expect(view.queries()).toEqual([]);
  });
});

/* ────────────────────────────────────────────────────────────────────────────
 * 源码级接线门：桥的**前端半边**确实装上了，且确实清锁
 *
 * 没有这一段，Rust 侧那条 `win.eval(...)` 可以照常绿着，而前端根本没挂
 * `__POLARIS_TRAY_REMEASURE__` —— 两扇门之间的缝就是生产路径。
 * ──────────────────────────────────────────────────────────────────────────── */

const MENU_RAW = readFileSync(
  fileURLToPath(new URL('./TrayMenu.tsx', import.meta.url)),
  'utf8',
);

/**
 * 去注释后的源码。两个方向都必要（同 `tray-live-wiring.test.ts` 的 `code()`）：本仓注释习惯逐字
 * 引用被替换掉的旧形态（这里就有 `fixedMenuHeightRef.current` 的旧写法说明），扫原文会被自己的
 * 说明文字误伤；反过来，只在注释里提一句函数名就够让 `toContain` 变绿 —— 那是假绿。
 */
const MENU = MENU_RAW.replace(/\/\*[\s\S]*?\*\//g, '').replace(
  /(^|[^:])\/\/.*$/gm,
  '$1',
);

/** 按唯一锚点取一段函数体并封顶 —— 切片射程由判据决定，不由书写顺序决定。 */
function slice(src: string, anchor: string, end: string): string {
  const hits = src.split(anchor).length - 1;
  expect(hits, `锚点 ${anchor} 命中 ${hits} 次（应为 1）`).toBe(1);
  const a = src.indexOf(anchor) + anchor.length;
  const b = src.indexOf(end, a);
  expect(b, `找不到收尾串 ${end} —— 切片会一路跑到文件尾`).toBeGreaterThan(a);
  return src.slice(a, b);
}

describe('腿 C：字体落定后再收敛一次', () => {
  it('正面：fonts.ready 兑现后回调被调用一次（这正是「全新安装第一次展开」那一档）', async () => {
    let resolve: () => void = () => undefined;
    const ready = new Promise<void>((r) => {
      resolve = r;
    });
    let hits = 0;
    armFontsReadyRemeasure({ fonts: { ready } }, () => {
      hits += 1;
    });
    expect(hits, '兑现之前不该有人动窗高').toBe(0);
    resolve();
    await ready;
    await Promise.resolve();
    expect(hits, '字体换上后没重量 = 锁停在回落字体那份偏矮的度量上').toBe(1);
  });

  it('正面：document.fonts 缺席时静默退化，不抛、返回可调用的取消闭包', () => {
    let hits = 0;
    const cancel = armFontsReadyRemeasure({}, () => {
      hits += 1;
    });
    expect(typeof cancel).toBe('function');
    expect(() => cancel()).not.toThrow();
    expect(hits).toBe(0);
  });

  it('反向对照：取消后即便 ready 兑现也不回调 —— 证明上面那条不是「反正总会调」', async () => {
    let resolve: () => void = () => undefined;
    const ready = new Promise<void>((r) => {
      resolve = r;
    });
    let hits = 0;
    const cancel = armFontsReadyRemeasure({ fonts: { ready } }, () => {
      hits += 1;
    });
    cancel();
    resolve();
    await ready;
    await Promise.resolve();
    expect(hits, '窗已卸载还去动它的高度').toBe(0);
  });
});

describe('接线门：TrayMenu 装了桥、清了锁、把重量依赖接进了 effect', () => {
  it('守卫自检：扫到的确实是 TrayMenu 源码，且去注释后没被吃空', () => {
    expect(MENU_RAW.length).toBeGreaterThan(1000);
    expect(MENU).toContain('export default function TrayMenu');
    expect(MENU.length).toBeGreaterThan(MENU_RAW.length / 3);
    expect(MENU).not.toContain('原型 `.tray-menu` L2905-2963 移植');
  });

  it('腿 A：把 __POLARIS_TRAY_REMEASURE__ 挂上 window，回调里清锁并逼一次重量', () => {
    expect(MENU).toContain(
      'window.__POLARIS_TRAY_REMEASURE__ = requestRemeasure',
    );
    const body = slice(
      MENU,
      'const requestRemeasure = useCallback(',
      '}, []);',
    );
    expect(
      body,
      '桥只 bump nonce 不清锁 = 白量一场：锁还在，回报的仍是上一次的旧高',
    ).toContain('resetTrayHeightLock(fixedMenuHeightRef)');
    expect(
      body,
      '只清锁不 bump = 没人来触发下一次测量：换屏时 DOM 没变，ResizeObserver 不会自己 fire',
    ).toContain('setRemeasureNonce(');
  });

  it('高度回报走 trayReportedHeight，且 remeasureNonce 进了重量 effect 的依赖', () => {
    expect(MENU).toContain('trayReportedHeight(');
    expect(MENU).toContain('}, [config, view, remeasureNonce]);');
  });

  it('腿 C：字体落定腿接在 document 上，喂的是同一个 requestRemeasure', () => {
    expect(MENU).toContain(
      'armFontsReadyRemeasure(document, requestRemeasure)',
    );
  });

  it('腿 B：屏幕换代腿接的是 media query（看屏幕），不是窗口 resize 事件（看窗 = 正反馈环）', () => {
    // 这条腿是**次级**触发：权威信号由宿主推（mac 的 NSApplicationDidChangeScreenParameters、
    // Win 的 WM_DPICHANGED 经 tao 归一成的 ScaleFactorChanged），判据在 Rust 侧那道门。
    // 留着它是因为它覆盖宿主够不着的一类（浏览器级缩放、Win 上同 DPI 改分辨率），
    // 且最近值胜之后多量一次是幂等的 —— 但删掉它同样要在这里转红，故仍是正面断言。
    expect(MENU).toContain(
      'armScreenChangeRemeasure(window, requestRemeasure)',
    );
    expect(
      MENU,
      '监听窗口 resize 会形成「改尺寸 → 收事件 → 重量 → 改尺寸」的正反馈环',
    ).not.toMatch(/addEventListener\(\s*['"]resize['"]/);
  });
});
