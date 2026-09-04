/**
 * 导航层**静态绑定**契约 —— 切页不得存在挂起源。
 *
 * # 这道门守的是什么
 *
 * 用户可见症状：切换导航时闪一次转圈，像"要先加载一下"。成因是导航层曾把 8 个主屏与 9 个设置子页
 * 各自 `React.lazy` 分包 —— 首次导航过去才发起 import，React 一挂起就**同步提交** Suspense fallback，
 * 哪怕 chunk 下一个微任务就到，那一帧转圈也已经上过屏。
 *
 * 分包在这里买不到东西：所有 chunk 经 tauri-codegen 编进二进制、由本地自定义协议直出，**没有下载
 * 这一步**可省（完整论证见 `components/screens/ScreenRouter.tsx` 顶部）。所以治法不是"预取赛跑赢过
 * 用户"（赢不了就还是转圈，且新增一整类"这个 loader 忘了预热"的缺陷面），而是取消导航层分包：
 * 没有 lazy 就没有挂起，没有挂起就没有 fallback。
 *
 * # 判据形态：正面断言 + 取材面自枚举
 *
 * 只写"源码里不出现 `lazy(`"是**会被空文件骗过**的判据。本门反过来：取材面（有哪些屏）从
 * `store/nav-store.ts` 的类型联合里枚举出来，然后**逐屏正面证明**它能在不 await 的情况下取到组件：
 *
 *  1. 该屏在路由 switch 里有 case，且绑定到某个组件标识符；
 *  2. 该标识符由文件顶部的**静态 default import** 绑定（不是 `lazy(...)` 的返回值）；
 *  3. 该 import 的模块路径在磁盘上存在，且那个文件确有 `export default`。
 *
 * 三条合起来 = "模块图上同步可达"。任一屏改回 `lazy()`，它的标识符就从静态 import 表里消失 ⇒ ②红。
 * 屏被删空、nav-store 被改坏、路由 switch 少一个 case ⇒ ①红。
 *
 * # 切片自检
 *
 * 解析前先剥注释与字符串字面量（否则注释里写的 `lazy(` 会制造假红、`import X from` 会制造假绿）。
 * 剥离器本身有正向对照：剥完必须**留下**代码锚点、**吃掉**只在注释里出现过的词。剥离器若整篇吃空，
 * 后面所有 forEach 会空转 —— 故取材面另有下界断言兜底。
 */

import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const SRC = fileURLToPath(new URL('../', import.meta.url));
const NAV_STORE = resolve(SRC, 'store/nav-store.ts');
const SCREEN_ROUTER = resolve(SRC, 'components/screens/ScreenRouter.tsx');
const SETTINGS_PAGE = resolve(SRC, 'components/screens/settings/SettingsPage.tsx');

function read(file: string): string {
  return readFileSync(file, 'utf8');
}

/**
 * 剥掉注释与字符串/模板字面量，位置用空格占位（保持行列不变，正则里的 `\s` 语义不受影响）。
 *
 * 不处理正则字面量：本门取材的文件里没有，一旦有人写进来，下面的锚点自检会先炸而不是静默切错。
 */
function stripCommentsAndStrings(source: string): string {
  const out = source.split('');
  let i = 0;
  const blank = (from: number, to: number) => {
    for (let k = from; k < to; k += 1) if (out[k] !== '\n') out[k] = ' ';
  };
  while (i < source.length) {
    const two = source.slice(i, i + 2);
    if (two === '//') {
      const end = source.indexOf('\n', i);
      const stop = end === -1 ? source.length : end;
      blank(i, stop);
      i = stop;
    } else if (two === '/*') {
      const end = source.indexOf('*/', i + 2);
      const stop = end === -1 ? source.length : end + 2;
      blank(i, stop);
      i = stop;
    } else if (source[i] === "'" || source[i] === '"' || source[i] === '`') {
      const quote = source[i];
      let j = i + 1;
      while (j < source.length && source[j] !== quote) {
        if (source[j] === '\\') j += 1;
        j += 1;
      }
      blank(i + 1, Math.min(j, source.length));
      i = Math.min(j + 1, source.length);
    } else {
      i += 1;
    }
  }
  return out.join('');
}

/**
 * 从 `export type X = 'a' | 'b' | ...` 里取出字面量成员。
 *
 * 区间在剥离后的文本上定位（注释里写的示例联合不会被误当真值），成员名回原文同一区间取
 * —— 剥离器用空格等长占位，两份文本的下标一一对应。
 */
function unionMembers(raw: string, typeName: string): string[] {
  const stripped = stripCommentsAndStrings(raw);
  const start = stripped.indexOf(`export type ${typeName} =`);
  if (start === -1) return [];
  const end = stripped.indexOf(';', start);
  if (end === -1) return [];
  return [...raw.slice(start, end).matchAll(/'([a-z]+)'/g)].map((m) => m[1]);
}

/** 顶部静态 default import：标识符 → 模块路径。`lazy(...)` 赋值不会进这张表。 */
function defaultImports(raw: string): Map<string, string> {
  const stripped = stripCommentsAndStrings(raw);
  const map = new Map<string, string>();
  const spans = [
    ...stripped.matchAll(/\bimport\s+(?!type\b)([A-Za-z_$][\w$]*)\s*,?\s*(?:\{[^}]*\}\s*)?from\s*['"]/g),
  ];
  for (const span of spans) {
    const quote = span[0].slice(-1);
    const start = span.index + span[0].length;
    const end = raw.indexOf(quote, start);
    if (end === -1) continue;
    map.set(span[1], raw.slice(start, end));
  }
  return map;
}

/**
 * `case 'id':` 到 `break;` 之间绑定的组件标识符。
 *
 * case 标签只能在原文里找（剥离器把字面量抹平成空格），所以命中后要回剥离文本核对同一下标确实是
 * 代码而非注释里的示例；组件名再从剥离文本取，避免注释里的 `<Foo>` 混进来。
 */
function caseComponent(raw: string, stripped: string, id: string): string | undefined {
  const label = `case '${id}':`;
  for (let at = raw.indexOf(label); at !== -1; at = raw.indexOf(label, at + 1)) {
    if (!stripped.startsWith('case ', at)) continue;
    const rest = stripped.slice(at);
    const stop = rest.indexOf('break;');
    const body = rest.slice(0, stop === -1 ? rest.length : stop);
    const component = /<([A-Z][A-Za-z0-9]*)/.exec(body)?.[1];
    if (component) return component;
  }
  return undefined;
}

/** import 路径 → 磁盘文件（`@/` 走 tsconfig paths 别名，与 vite resolve.alias 同源）。 */
function resolveModule(fromFile: string, specifier: string): string | undefined {
  const base = specifier.startsWith('@/')
    ? resolve(SRC, specifier.slice(2))
    : resolve(dirname(fromFile), specifier);
  return ['.tsx', '.ts'].map((ext) => `${base}${ext}`).find((p) => existsSync(p));
}

/**
 * 逐屏证明"不 await 就能取到组件"：case 有绑定 → 标识符来自静态 import → 目标文件在磁盘上且有默认导出。
 */
function assertStaticallyBound(
  routerFile: string,
  raw: string,
  stripped: string,
  imports: Map<string, string>,
  id: string
): string {
  const component = caseComponent(raw, stripped, id);
  expect(component, `${id} 没有在路由 switch 里绑定组件`).toBeTruthy();
  const specifier = imports.get(component as string);
  expect(specifier, `${id} 绑定的 ${component} 不是静态 import（改回 lazy 了？）`).toBeTruthy();
  const target = resolveModule(routerFile, specifier as string);
  expect(target, `${component} 的 import 路径 ${specifier} 在磁盘上不存在`).toBeTruthy();
  expect(read(target as string), `${component} 没有默认导出，静态绑定取不到组件`).toContain(
    'export default'
  );
  return component as string;
}

/** 导航路径上的挂起源：懒加载工厂、Suspense 边界、动态 import 三种形态。 */
const SUSPENSE_SOURCES = [/\blazy\s*\(/, /\bSuspense\b/, /(?<![.\w])import\s*\(/];

describe('导航层静态绑定契约', () => {
  const routerRaw = read(SCREEN_ROUTER);
  const settingsRaw = read(SETTINGS_PAGE);
  const routerStripped = stripCommentsAndStrings(routerRaw);
  const settingsStripped = stripCommentsAndStrings(settingsRaw);
  const routerImports = defaultImports(routerRaw);
  const settingsImports = defaultImports(settingsRaw);
  const navStoreRaw = read(NAV_STORE);
  const mainScreens = unionMembers(navStoreRaw, 'MainScreen');
  const settingsScreens = unionMembers(navStoreRaw, 'SettingsScreen');

  it('取材面与剥离器自检：屏清单非空、注释被吃掉、代码被留下', () => {
    // 下界（不是等号）：新增屏时门跟着覆盖而不是要求同步改数字；解析器切空则立刻红。
    expect(mainScreens.length).toBeGreaterThanOrEqual(8);
    expect(settingsScreens.length).toBeGreaterThanOrEqual(9);
    expect(mainScreens).toContain('home');
    expect(settingsScreens).toContain('about');

    // 正向对照：只在注释里出现过的词必须被吃掉，代码骨架必须留下。
    expect(routerRaw).toContain('tauri-codegen');
    expect(routerStripped).not.toContain('tauri-codegen');
    expect(routerStripped).toContain('function RendererReadyBoundary');
    expect(routerStripped).toContain('switch (mainScreen)');
    expect(settingsStripped).toContain('switch (settingsScreen)');
    // 字符串被抹平，但语法骨架仍在（import 行还能被解析出来）。
    expect(routerImports.size).toBeGreaterThanOrEqual(mainScreens.length - 1);
    expect(settingsImports.size).toBeGreaterThanOrEqual(settingsScreens.length);
  });

  it('每个主屏都由静态 import 绑定，切过去不需要 await 任何东西', () => {
    for (const id of mainScreens) {
      assertStaticallyBound(SCREEN_ROUTER, routerRaw, routerStripped, routerImports, id);
    }
  });

  it('dnsrules 与 rules 仍解析到同一个屏', () => {
    const route = assertStaticallyBound(SCREEN_ROUTER, routerRaw, routerStripped, routerImports, 'rules');
    const dns = assertStaticallyBound(SCREEN_ROUTER, routerRaw, routerStripped, routerImports, 'dnsrules');
    expect(dns).toBe(route);
    expect(routerImports.get(dns)).toBe(routerImports.get(route));
  });

  it('settings scope 的容器同样静态绑定', () => {
    expect(routerStripped).toContain('<SettingsPage />');
    const specifier = routerImports.get('SettingsPage');
    expect(specifier, 'SettingsPage 不是静态 import').toBeTruthy();
    expect(resolveModule(SCREEN_ROUTER, specifier as string)).toBe(SETTINGS_PAGE);
  });

  it('每个设置子页都由静态 import 绑定', () => {
    for (const id of settingsScreens) {
      assertStaticallyBound(SETTINGS_PAGE, settingsRaw, settingsStripped, settingsImports, id);
    }
    // default 分支也得落在静态绑定上，否则"未知子页"这条路径会漏回懒加载。
    const fallback = /default:\s*page = <([A-Z][A-Za-z0-9]*)/.exec(settingsStripped)?.[1];
    expect(fallback && settingsImports.has(fallback)).toBe(true);
  });

  it('导航层两个路由文件里没有任何挂起源', () => {
    for (const [name, stripped] of [
      ['ScreenRouter.tsx', routerStripped],
      ['SettingsPage.tsx', settingsStripped],
    ] as const) {
      for (const pattern of SUSPENSE_SOURCES) {
        expect(pattern.test(stripped), `${name} 出现挂起源 ${pattern}`).toBe(false);
      }
    }
  });

  it('被路由到的屏模块自身也不在顶层引入挂起源', () => {
    const targets = new Set<string>();
    for (const id of mainScreens) {
      const component = caseComponent(routerRaw, routerStripped, id);
      const specifier = component ? routerImports.get(component) : undefined;
      const file = specifier ? resolveModule(SCREEN_ROUTER, specifier) : undefined;
      if (file) targets.add(file);
    }
    for (const id of settingsScreens) {
      const component = caseComponent(settingsRaw, settingsStripped, id);
      const specifier = component ? settingsImports.get(component) : undefined;
      const file = specifier ? resolveModule(SETTINGS_PAGE, specifier) : undefined;
      if (file) targets.add(file);
    }
    // 取材面下界：主屏去重后仍应覆盖到全部子页 + rules 合并后的主屏集合。
    expect(targets.size).toBeGreaterThanOrEqual(mainScreens.length - 1 + settingsScreens.length);
    // 只查 lazy/Suspense，**不查**动态 `import(`：屏内部在事件处理里按需拉模块（如
    // `SettingsAbout.tsx` 点开时才取 api-client）不在渲染路径上，产生不了挂起。
    for (const file of targets) {
      const stripped = stripCommentsAndStrings(read(file));
      for (const pattern of [/\blazy\s*\(/, /\bSuspense\b/]) {
        expect(pattern.test(stripped), `${file} 顶层出现挂起源 ${pattern}`).toBe(false);
      }
    }
  });
});
