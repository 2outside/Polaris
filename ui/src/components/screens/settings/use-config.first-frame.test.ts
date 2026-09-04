/**
 * 设置页首帧的门 —— 「进设置页先闪一次转圈」那条缺陷的常驻防线。
 *
 * # 守的是什么
 *
 * 转圈的来源不是代码分割的挂起（导航层的 `React.lazy` 已整个删掉），是 `useConfig` 自己那个
 * `loading` 初值恒 `true`：挂载后才去 `config.get()`，于是每次进设置页都先渲染一屏 Spinner。而
 * app-store 在启动期就把**同一份磁盘副本**拉好了（`loadConfig` 存进 store 的就是 `config.get()` 的
 * 原始返回），设置页那次自拉只是「对齐磁盘最新值」。首帧拿 store 那份当种子 ⇒ `loading` 首帧即
 * `false` ⇒ 转圈**结构上**不出现。
 *
 * # 三条硬约束，本门逐条钉
 *
 *  1. **种子是磁盘副本口径，不是 effective 值**。本 hook 自持的 state 只装磁盘上有的那份，对外交出去
 *     的才是 `effectiveConfigOf(磁盘副本, staged)`。把暂存值烧进种子 = 它会随下一次整份事务写进
 *     `config.json`，且会被 `onChanged` 的整份重拉抹掉（与「节点列表不回显」同型的静默回退）。
 *  2. **store 为 `null` 时回落今天的行为**（`loading=true` → 拉取 → 渲染）。设置页并非只能从首页进，
 *     托盘「打开设置」、启动即进 settings scope 都可达，store 未必已 hydrate。
 *  3. **落盘基准仍取纯磁盘副本** —— 由既有的 `use-config.staged-echo.test.ts` 守（`persisted` /
 *     `configApi.patch(direct)` 那三条），本门不重复。
 *
 * # 两半各自证明什么（分开说，不混为一谈）
 *
 *  - **行为半**（第一个 describe）：`configFirstFrame` 是纯函数，直测。本仓 vitest 跑 node 环境、
 *    刻意不装 jsdom / testing-library（见 `vite.config.ts` test 段），真 hook 一行都跑不起来 ——
 *    故首帧决策被抽成纯函数正是为了让「首帧那两个初值是什么」可测。同款做法见
 *    `settings-logic.ts` 的 `wireUpdateProgress` 与 `tray/tray-menu-height.ts`。
 *  - **接线半**（第二个 describe）：纯函数再对，`useConfig` 不把它接到那两个 `useState` 的初值上
 *    也白搭；而「接没接上」在 node 下观测不到，只能用源码断言钉。两扇门之间的缝就是生产路径。
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import type { UserConfig } from '@/contracts/types';
import type { StagedEntry } from '@/lib/staged-config';
import { effectiveConfigOf } from '@/store/app-store';
import { configFirstFrame } from './use-config';

/** 启动期 `loadConfig` 存进 app-store 的那份 —— `api.config.get()` 的原始返回，即磁盘副本。 */
const HYDRATED = {
  mixedPort: 7890,
  desktopNotifications: true,
} as unknown as UserConfig;

/** 用户此前在设置页改了 `mixedPort`（Class B ⇒ 进暂存，`useConfig` 里 `entityPath: [key]` 的形态）。 */
const stagedPort: StagedEntry = {
  id: 'setting:mixedPort',
  kind: 'setting',
  label: '修改设置 · mixedPort',
  entityPath: ['mixedPort'],
  nextValue: 1080,
};

describe('首帧决策：store 已 hydrate 就不该再转圈', () => {
  it('正面：store 已有 config ⇒ 首帧 `loading === false`，且种子**就是 store 里那一份**', () => {
    const frame = configFirstFrame(HYDRATED);
    expect(frame.loading, 'loading 首帧仍为 true = 那屏 Spinner 照旧出现').toBe(false);
    // `toBe` 而非 `toEqual`：要的是**同一引用**，不是等值副本。两个理由，缺一都不够——
    //  ① 引用相同才能证明种子路上没发生任何合并/拷贝（`effectiveConfigOf` 的结果在无暂存时也
    //     `toEqual` 通过，等值断言分不出这两种实现）；
    //  ② `effectiveConfigOf` 的记忆化按**入参引用**做 key（见 app-store 那段双层 WeakMap 注释），
    //     种子若是副本，设置页与全局读点会各自击穿一次缓存。
    expect(frame.config).toBe(HYDRATED);
  });

  it('正面（回落腿）：store 为 `null` ⇒ 首帧 `loading === true`，config 仍是 null', () => {
    // 托盘「打开设置」/ 启动即进 settings scope：store 未必已 hydrate，这条路必须还是
    // 「转圈 → 拉取 → 渲染」，否则那两条路会渲染一个 `config` 为空的设置页。
    const frame = configFirstFrame(null);
    expect(frame.loading).toBe(true);
    expect(frame.config).toBeNull();
  });

  it('正面（关键）：种子是**磁盘副本**，暂存值只出现在对外那份上', () => {
    // 这条钉的是硬约束 1。构造「store 有 config + staged 有条目」——
    // 把种子换成 `effectiveConfigOf(...)` 的结果时，下面第一条断言读到 1080 而红。
    const frame = configFirstFrame(HYDRATED);
    expect(frame.config!.mixedPort, '暂存值被烧进磁盘副本 = 下一次整份事务把它写进 config.json').toBe(
      7890,
    );
    // 而对外交出去的那份（`useConfig` 返回值那一行做的事）**必须**含暂存值，否则用户刚拨的开关
    // 会在首帧弹回原位 —— 「种子不含暂存值」不等于「界面上看不到暂存值」，两件事在这里同时成立。
    expect(effectiveConfigOf(frame.config, [stagedPort])!.mixedPort).toBe(1080);
  });

  it('反向对照：`loading` 不是恒 false —— 证明本门观测得到的是种子，不是一句恒真', () => {
    // 缺了这一条，上面「loading === false」在「直接 `useState(false)`」的实现里同样全绿，而那份
    // 实现会让无种子那条路渲染空设置页。两个方向都断言过，常量实现必红一边。
    expect(configFirstFrame(HYDRATED).loading).toBe(false);
    expect(configFirstFrame(null).loading).toBe(true);
  });
});

/* ────────────────────────────────────────────────────────────────────────────
 * 接线门：种子确实接到了首帧那两个初值上，且取的是 store 的**原始** config
 * ──────────────────────────────────────────────────────────────────────────── */

const HOOK_RAW = readFileSync(
  fileURLToPath(new URL('./use-config.ts', import.meta.url)),
  'utf8',
);
const PAGE_RAW = readFileSync(
  fileURLToPath(new URL('./SettingsPage.tsx', import.meta.url)),
  'utf8',
);

/**
 * 去注释后的源码。两个方向都必要（同 `tray/tray-menu-height.test.ts` 的 `MENU`）：本仓注释习惯逐字
 * 引用被替换掉的旧形态（这两个文件的注释里就写着 `loading=true`、`effectiveConfigOf(...)`），扫原文
 * 会被自己的说明文字误伤；反过来，只在注释里提一句函数名也够让 `toContain` 变绿 —— 那是假绿。
 */
function code(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
}

const HOOK = code(HOOK_RAW);
const PAGE = code(PAGE_RAW);

/** 按唯一锚点取一段并封顶 —— 切片射程由判据决定，不由书写顺序决定。 */
function slice(src: string, anchor: string, end: string): string {
  const hits = src.split(anchor).length - 1;
  expect(hits, `锚点 ${anchor} 命中 ${hits} 次（应为 1）`).toBe(1);
  const a = src.indexOf(anchor) + anchor.length;
  const b = src.indexOf(end, a);
  expect(b, `找不到收尾串 ${end} —— 切片会一路跑到文件尾`).toBeGreaterThan(a);
  return src.slice(a, b);
}

describe('接线门：useConfig 首帧确实吃种子，SettingsPage 的回落腿还在', () => {
  it('守卫自检：扫到的确实是这两个文件，且去注释后没被吃空', () => {
    expect(HOOK_RAW.length).toBeGreaterThan(1000);
    expect(PAGE_RAW.length).toBeGreaterThan(1000);
    expect(HOOK).toContain('export function configFirstFrame');
    expect(HOOK).toContain('export function useConfig');
    expect(PAGE).toContain('export function SettingsPage');
    expect(HOOK.length).toBeGreaterThan(HOOK_RAW.length / 3);
    expect(PAGE.length).toBeGreaterThan(PAGE_RAW.length / 3);
    // 剥离器确实吃掉了注释：这两句只在注释里出现过，留在切片里说明剥离整个没生效。
    expect(HOOK).not.toContain('首帧不转圈');
    expect(PAGE).not.toContain('冷启动回落腿');
  });

  it('种子取的是 store 的**原始** config，不是 `effectiveConfigOf(...)` 的结果', () => {
    const seed = slice(HOOK, 'const [seed] = useState(', ');');
    expect(seed).toContain('configFirstFrame(useAppStore.getState().config)');
    expect(
      seed,
      '种子喂 effective 值 = 把暂存值烧进磁盘副本，下一次整份事务就把它写进 config.json',
    ).not.toContain('effectiveConfigOf');
  });

  it('两个 `useState` 的初值都接在种子上（拆掉任一半，转圈就回来）', () => {
    expect(HOOK).toContain('useState<UserConfig | null>(seed.config)');
    expect(HOOK).toContain('useState(seed.loading)');
    // 旧口径逐字：`loading` 恒从 true 起步。复活即红。
    expect(HOOK, 'loading 初值写死 true = 首帧必转圈').not.toMatch(/useState\(true\)/);
  });

  it('`latestConfig` 镜像同样取种子（否则首帧就动手改设置会被静默丢掉）', () => {
    // `update` 首行是 `if (!prev) return`：state 有种子而 ref 还停在 null 时，界面上的开关已经可点，
    // 按下去却什么都不发生 —— 比转圈更糟。
    expect(HOOK).toContain('useRef<UserConfig | null>(seed.config)');
  });

  it('挂载那次拉取在已种子化时降级为 silent 重拉（复用事件驱动那条腿，不新开一条）', () => {
    expect(HOOK).toContain('void load(seed.config !== null)');
    // `silent` 的语义就是「不动 loading/error」——那条腿的定义还在，不许被改掉。
    expect(HOOK).toContain('if (!silent) {');
    expect(HOOK).toContain('if (!silent) setLoading(false);');
  });

  it('回落腿：SettingsPage 仍在 `loading` 时渲染 Spinner', () => {
    // store 没 hydrate 那条路上 `config` 为 null，删掉这个分支会直接掉进下面 `error || !config`
    // 的错误屏（文案说的是「配置加载失败」，而实际什么都没失败）。
    const branch = slice(PAGE, 'if (loading) {', '  if (error');
    expect(branch).toContain('<Spinner />');
  });
});
