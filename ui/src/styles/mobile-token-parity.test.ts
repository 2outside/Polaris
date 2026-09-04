/**
 * `mobile-token-parity` —— §6.3.5 的门，**本轮只落地其中两条**。
 *
 * 契约与门规格：`~/docs/polaris/design/polaris-mobile-platform-evaluation-2026-08-29.md` §6.3
 * （§6.3.1 桌面视觉真值链 / §6.3.2 缺口 / §6.3.3 四条契约 / §6.3.5 门的五条）。
 *
 * ── 本轮落地范围 ────────────────────────────────────────────────────────────
 * ✅ 第 1 条的**右半边**：桌面 token 实跑终值基线（`:root` / `[data-theme='dark']` /
 *    `[data-theme='light']` 三条腿，即第 3 条要求的覆盖面），与仓内 checked-in 快照逐值对拍。
 * ✅ 第 4 条：字体栈断言（`--disp` 首选族随包、`--sans` 含 Android 可用 CJK 族）——
 *    当前是**已知缺口**，见文件末尾 `it.fails` 段。
 * ⏸ 第 1 条的**左半边** + 第 2 条（移动端入口解析出的 token 集合对拍 / 新增 token 白名单）：
 *    §6.3.0 实测移动端零代码落地（`src-tauri/gen/` 无 android|ios、`lib.rs` 无 `mobile_entry_point`），
 *    **没有移动端 token 入口就没有对拍的左操作数**，写了也只是恒真。
 *    **补齐条件**：契约 A1 的 `ui/src/styles/tokens.resolved.css`（或等价的移动端唯一 token 入口）落地当天，
 *    在本文件补两个 describe：① 该入口解析出的三条腿逐值等于下方 `BASELINE`；
 *    ② 该入口相对 `BASELINE` 多出的 token 必须命中契约 C 白名单前缀（`--tap-*` / `--safe-*` / `--shadow-sheet`）。
 *    §7 P1 的 gate 是「`mobile-token-parity` 未绿不合入任何移动端 UI 组件」，届时这两条必须先在。
 *
 * ── 为什么要一份「终值」基线，而不是直接读 tokens.css ───────────────────────
 * 桌面 token 的最终取值**不在 `tokens.css`**（§6.3.1）。`index.css` 的 @import 序为
 * tailwindcss → tokens.css → components.css → screens.css → prototype.css，其后才是 index.css 自有规则；
 * `prototype.css` 自带一整套同选择器的 `:root` token 压过 `tokens.css`，`index.css` 的
 * `:root, :root[data-theme='light']` 又把四个语义色压回来。移动端按直觉只 `@import tokens.css`
 * 会拿到中间层的值，**没有任何报错**。基线钉的就是浏览器里真正生效的那一层。
 *
 * ── 解析器为什么不复用 style-invariants.test.ts 的 `flat()` ─────────────────
 * `read` / `stripComments` 与它同义（那两个是模块私有的 const，不能 import，只能同形复制）。
 * 但 `flat()` 把 `@media` 拍平了 —— 而 @media 上下文正是本门最容易翻车的地方：
 * `tokens.css` 的跟随系统腿是 `:root:not([data-theme='light']):not([data-theme='dark'])`（0,3,0），
 * `prototype.css` 的对应腿是 `:root:not([data-theme="light"])`（0,2,0）——这一腿是 tokens.css 赢，
 * 与其它腿方向相反。若丢掉 @media 归属，prototype 的 (0,2,0) 深色腿会盖过 `:root` 的 (0,1,0)，
 * 浅色基线会整张变成深色值。故这里必须用带块嵌套的走查，而不是正则拍平。
 *
 * 另：声明必须**按 `;` 切**，不能按行切。`prototype.css` 是多声明同行的紧凑格式
 * （`--bg:210 30% 96%; --surface:0 0% 100%; …` 在同一行），`grep -m1` 到该行再用 sed 剥掉冒号前缀，
 * 会静默取到该行**最后一个**声明的值（实测踩过，得到过一整张错误的对照表）。
 *
 * ── 射程边界 ────────────────────────────────────────────────────────────────
 * 基线只覆盖 Polaris 自有的五个样式文件在**根元素**上声明的自定义属性。
 * `@import 'tailwindcss'` 注入的 Tailwind theme 变量不在射程内（不是设计 token，移动端也不靠它对齐视觉）。
 * 后代选择器（`:root[data-theme="dark"] .toast{…}`）里的自定义属性同样不在射程内——它们不作用于根元素。
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve as resolvePath } from 'node:path';

const read = (rel: string) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');
const abs = (rel: string) => fileURLToPath(new URL(rel, import.meta.url));
/** 去掉 CSS 注释，避免注释里的示例声明被当成真实声明命中。 */
const stripComments = (src: string) =>
  src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

// ── 层叠链 ────────────────────────────────────────────────────────────────────
/** 源序 = index.css 的 @import 顺序 + index.css 自身（自有规则在全部 @import 之后）。 */
const CASCADE = ['./tokens.css', './components.css', './screens.css', './prototype.css', './index.css'] as const;

// ── CSS 走查（保留 @media 归属）───────────────────────────────────────────────
type Rule = { file: string; sel: string; body: string; at: string[]; order: number };

/** 按花括号配对走查，规则带上它所处的 at-rule 前奏栈（`@media …` 等）。 */
function walk(css: string, file: string, out: Rule[], at: string[], seq: { n: number }): void {
  let i = 0;
  let buf = '';
  while (i < css.length) {
    const c = css[i];
    if (c === '{') {
      const prelude = buf.trim().replace(/\s+/g, ' ');
      let depth = 1;
      let j = i + 1;
      while (j < css.length && depth > 0) {
        if (css[j] === '{') depth++;
        else if (css[j] === '}') depth--;
        j++;
      }
      const inner = css.slice(i + 1, j - 1);
      if (prelude.startsWith('@')) {
        // 条件组：递归并把前奏压栈。@font-face / @keyframes 不含嵌套规则，不递归。
        if (/^@(media|supports|layer|container)\b/i.test(prelude)) walk(inner, file, out, at.concat(prelude), seq);
      } else {
        out.push({ file, sel: prelude, body: inner, at, order: seq.n++ });
      }
      buf = '';
      i = j;
    } else if (c === '}' || c === ';') {
      // `;` 收尾的 at-rule（@import / @charset / @config）不产生块，清掉缓冲避免被并入下条选择器。
      buf = '';
      i++;
    } else {
      buf += c;
      i++;
    }
  }
}

const ALL_RULES: Rule[] = (() => {
  const out: Rule[] = [];
  const seq = { n: 0 };
  for (const f of CASCADE) walk(stripComments(read(f)), f, out, [], seq);
  return out;
})();

/** 声明按 `;` 切（不是按行切），后声明覆盖同块内的前声明。 */
function declsOf(body: string): Record<string, string> {
  const m: Record<string, string> = {};
  const re = /(?:^|;)\s*(--[A-Za-z0-9_-]+)\s*:\s*([^;]*)/g;
  let x: RegExpExecArray | null;
  while ((x = re.exec(body))) m[x[1]] = x[2].replace(/\s+/g, ' ').trim();
  return m;
}

// ── 三条腿 ────────────────────────────────────────────────────────────────────
type Env = { theme: null | 'dark' | 'light'; prefers: 'light' | 'dark' };
/** 门覆盖的三条腿（§6.3.5 第 3 条）。`:root` 腿取「无 data-theme + 系统浅色」，即浅色默认。 */
const LEGS: Record<string, Env> = {
  ':root': { theme: null, prefers: 'light' },
  ":root[data-theme='dark']": { theme: 'dark', prefers: 'dark' },
  ":root[data-theme='light']": { theme: 'light', prefers: 'light' },
};

/** 只认「作用于根元素」的单复合选择器：`:root` + 任意个 `[data-theme=x]` / `:not([data-theme=x])`。 */
const ROOT_COMPOUND = /^:root(?:(?::not\(\[data-theme=["'][a-z]+["']\]\))|(?:\[data-theme=["'][a-z]+["']\]))*$/;

function parseRootCompound(sel: string): { spec: number; eq: string[]; ne: string[] } | null {
  if (!ROOT_COMPOUND.test(sel)) return null;
  const eq: string[] = [];
  const ne: string[] = [];
  // `:root` 本身贡献 1（伪类）；每个属性选择器 / `:not([attr])` 各贡献 1（:not() 取其参数的特异性）。
  let spec = 1;
  for (const p of sel.matchAll(/:not\(\[data-theme=["']([a-z]+)["']\]\)|\[data-theme=["']([a-z]+)["']\]/g)) {
    spec++;
    if (p[1] !== undefined) ne.push(p[1]);
    else eq.push(p[2]);
  }
  return { spec, eq, ne };
}

/** at-rule 栈是否在该环境下命中。不认识的条件组一律抛错（宁可自曝，不要静默算错）。 */
function atRuleApplies(at: string[], env: Env): boolean {
  for (const q of at) {
    const m = q.match(/prefers-color-scheme\s*:\s*(dark|light)/);
    if (!m) throw new Error(`token 声明落在本门未建模的条件组里，解析器需要扩展：${q}`);
    if (env.prefers !== m[1]) return false;
  }
  return true;
}

/** 解析某条腿上全部根级自定义属性的终值（特异性优先，同特异性取源序在后者）。 */
function resolveLeg(env: Env): Record<string, string> {
  const win: Record<string, { spec: number; order: number; val: string }> = {};
  for (const r of ALL_RULES) {
    const d = declsOf(r.body);
    if (Object.keys(d).length === 0) continue;
    if (!atRuleApplies(r.at, env)) continue;
    let spec = -1;
    for (const part of r.sel.split(',').map((s) => s.trim())) {
      // 后代/兄弟选择器不作用于根元素（`:root[data-theme="dark"] .toast` 之类），跳过。
      if (/[ >+~]/.test(part)) continue;
      const c = parseRootCompound(part);
      if (!c) {
        // 单复合、又声明了自定义属性、还认不出来 ⇒ 可能作用于根元素而被漏算。必须自曝，不能静默跳过。
        if (/^(:root|html\b|\*|:where|:is)/.test(part))
          throw new Error(`根级 token 选择器无法归类，解析器需要扩展：${r.file} "${part}"`);
        continue; // `.foo{--x}` 之类：不是根元素，正常跳过。
      }
      if (c.eq.every((v) => env.theme === v) && c.ne.every((v) => env.theme !== v)) spec = Math.max(spec, c.spec);
    }
    if (spec < 0) continue;
    for (const [k, v] of Object.entries(d)) {
      const cur = win[k];
      if (!cur || spec > cur.spec || (spec === cur.spec && r.order >= cur.order)) win[k] = { spec, order: r.order, val: v };
    }
  }
  return Object.fromEntries(
    Object.entries(win)
      .sort(([a], [b]) => (a < b ? -1 : 1))
      .map(([k, v]) => [k, v.val]),
  );
}

// ── checked-in 基线：桌面实跑终值 ─────────────────────────────────────────────
/**
 * 生成方式：由本文件的解析器算出，逐值人工核对过 —— 四个语义色与 §6.3.1 表格的「实跑」列一致
 * （`--ok` 152 60% 27% / `--warn` 32 84% 31% / `--err` 356 68% 44% / `--dn` 197 80% 33%），
 * 都不是 `tokens.css` 或 `prototype.css` 的声明值。
 *
 * 取值形态就是**胜出那条声明的原文**（空白折叠后）：字体栈是 `prototype.css` 的双引号紧凑写法，
 * 不是 `tokens.css` 的单引号折行写法 —— 因为浏览器里生效的是前者。
 *
 * 改基线的唯一正当理由：桌面设计 token 有意演进，且改动已在桌面侧落地。
 * 「移动端对不上所以把基线调过去」是契约 C 的违约（只许加，不许改）。
 */
const LIGHT: Record<string, string> = {
  '--aurora': '162 78% 33%',
  '--aurora-hi': '163 82% 27%',
  '--aurora-weak': '162 55% 92%',
  '--bg': '210 30% 96%',
  '--disp': '"Space Grotesk","Avenir Next","SF Pro Display","Segoe UI",var(--sans)',
  '--dn': '197 80% 33%',
  '--err': '356 68% 44%',
  '--err-weak': '356 74% 96%',
  '--fg': '220 32% 13%',
  '--fg-dim': '216 15% 40%',
  '--fg-faint': '214 14% 44%',
  '--flow': '197 88% 40%',
  '--flow-hi': '198 92% 33%',
  '--flow-weak': '196 70% 93%',
  '--hair': '213 22% 83%',
  '--indigo': '234 60% 40%',
  '--line': '213 22% 87%',
  '--logo-tile': '0 0% 100%',
  '--logo-tile-bd': '214 24% 80%',
  '--mono': 'ui-monospace,"SF Mono","JetBrains Mono","Cascadia Code",Menlo,Consolas,monospace',
  '--ok': '152 60% 27%',
  '--ok-weak': '152 48% 92%',
  '--pending-bar-h': '36px',
  '--r': '11px',
  '--r-lg': '14px',
  '--r-md': '10px',
  '--r-sm': '8px',
  '--r-xs': '6px',
  '--ring': '197 88% 44%',
  '--sans':
    '-apple-system,"Segoe UI Variable","Segoe UI","PingFang SC","Hiragino Sans GB","Microsoft YaHei",system-ui,sans-serif',
  '--shadow': '216 45% 20%',
  '--shadow-pop': '0 18px 40px -16px hsl(var(--shadow)/0.6)',
  '--sp-1': '4px',
  '--sp-2': '8px',
  '--sp-3': '12px',
  '--sp-4': '16px',
  '--sp-5': '20px',
  '--sp-6': '24px',
  '--sp-7': '32px',
  '--statusbar-h': '32px',
  '--surface': '0 0% 100%',
  '--surface-2': '210 28% 94%',
  '--surface-3': '210 22% 89%',
  '--toast-gap': 'var(--sp-4)',
  '--unlock-dot-err-light': '356 82% 52%',
  '--unlock-dot-ok-light': '152 75% 36%',
  '--unlock-dot-warn-light': '32 92% 42%',
  '--up': '262 52% 54%',
  '--warn': '32 84% 31%',
  '--warn-weak': '38 84% 92%',
};

const DARK: Record<string, string> = {
  ...LIGHT,
  '--aurora': '161 60% 45%',
  '--aurora-hi': '162 68% 55%',
  '--aurora-weak': '162 45% 13%',
  '--bg': '220 40% 6%',
  '--dn': '195 82% 62%',
  '--err': '356 74% 66%',
  '--err-weak': '356 42% 17%',
  '--fg': '210 30% 95%',
  '--fg-dim': '214 16% 66%',
  '--fg-faint': '214 13% 48%',
  '--flow': '195 90% 56%',
  '--flow-hi': '194 96% 68%',
  '--flow-weak': '200 60% 15%',
  '--hair': '217 17% 28%',
  '--indigo': '236 64% 32%',
  '--line': '217 19% 23%',
  '--logo-tile': '213 26% 88%',
  '--logo-tile-bd': '214 18% 72%',
  '--ok': '152 50% 46%',
  '--ok-weak': '154 40% 14%',
  '--ring': '195 90% 60%',
  '--shadow': '224 80% 1%',
  '--surface': '219 32% 10.5%',
  '--surface-2': '218 26% 14%',
  '--surface-3': '217 22% 19.5%',
  '--up': '265 70% 74%',
  '--warn': '36 88% 60%',
  '--warn-weak': '34 45% 14%',
};

/**
 * 两条浅色腿共用同一张表**本身就是一条断言**：显式浅色与浅色默认必须逐值一致
 * （`tokens.css` 的「主题两档同步」注释、`index.css` 的双选择器写法都建立在这个前提上）。
 * 哪天它们真分叉了，这里会红，届时该拆表的是人，不是让门闭嘴。
 */
const BASELINE: Record<string, Record<string, string>> = {
  ':root': LIGHT,
  ":root[data-theme='dark']": DARK,
  ":root[data-theme='light']": LIGHT,
};

describe('§6.3.5 第 1 条：桌面 token 终值基线（三条腿逐值对拍）', () => {
  it('index.css 的 @import 序与解析器假设的层叠链一致（基线的前提，序一变整张表失真）', () => {
    const imports = [...read('./index.css').matchAll(/@import\s+['"]([^'"]+)['"]/g)].map((m) => m[1]);
    // tailwindcss 是裸包名，不在 CASCADE 里（射程边界见文件头）；其余四个必须按 CASCADE 顺序出现。
    expect(imports).toEqual(['tailwindcss', './tokens.css', './components.css', './screens.css', './prototype.css']);
  });

  for (const [leg, env] of Object.entries(LEGS)) {
    it(`${leg} 的全部根级 token 终值等于基线`, () => {
      expect(resolveLeg(env)).toEqual(BASELINE[leg]);
    });
  }

  it('四个语义色的浅色终值来自 index.css 的 @import 后覆盖，不是 tokens.css / prototype.css 的声明', () => {
    const light = resolveLeg(LEGS[':root']);
    // §6.3.1：prototype.css 的浅色语义色明度高 5–9 点，它进不了浏览器。
    // 直接钉「终值 ≠ prototype 声明值」，比只钉数值更能解释这道门在防什么。
    const protoLightRoot = ALL_RULES.find((r) => r.file === './prototype.css' && r.sel === ':root' && r.at.length === 0);
    expect(protoLightRoot, 'prototype.css 的浅色 :root token 块不见了？').toBeDefined();
    const proto = declsOf(protoLightRoot!.body);
    for (const k of ['--ok', '--warn', '--err', '--dn']) {
      expect(proto[k], `${k} 不在 prototype.css 的浅色 :root 块里，前提校验失败`).toBeDefined();
      expect(light[k], `${k} 的终值退回到了 prototype.css 的中间层取值（无障碍校准被吃掉）`).not.toBe(proto[k]);
    }
    expect([light['--ok'], light['--warn'], light['--err'], light['--dn']]).toEqual([
      '152 60% 27%',
      '32 84% 31%',
      '356 68% 44%',
      '197 80% 33%',
    ]);
  });
});

// ── §6.3.5 第 4 条：字体栈 ────────────────────────────────────────────────────
/** 顶层逗号切分（括号与引号内的逗号不算），用于拆 font-family 列表。 */
function splitTopLevel(value: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let quote = '';
  let cur = '';
  for (const ch of value) {
    if (quote) {
      if (ch === quote) quote = '';
      cur += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
      cur += ch;
    } else if (ch === '(') {
      depth++;
      cur += ch;
    } else if (ch === ')') {
      depth--;
      cur += ch;
    } else if (ch === ',' && depth === 0) {
      out.push(cur.trim());
      cur = '';
    } else cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}
const unquote = (s: string) => s.replace(/^['"]|['"]$/g, '').trim();
/** font-family 名比较：忽略大小写与多余空白（CSS 里族名大小写不敏感）。 */
const sameFamily = (a: string, b: string) => a.toLowerCase().replace(/\s+/g, ' ') === b.toLowerCase().replace(/\s+/g, ' ');

type FontFace = { family: string; srcs: string[]; dir: string };
/** 抽出 @font-face 的族名与 src url 列表（含所在目录，用于判定「随包」而非远端拉取）。 */
function fontFaces(css: string, dir: string): FontFace[] {
  return [...css.matchAll(/@font-face\s*\{([^}]*)\}/g)].flatMap((m) => {
    const body = m[1];
    const fam = body.match(/font-family\s*:\s*([^;]+)/);
    if (!fam) return [];
    return [
      {
        family: unquote(fam[1].trim()),
        srcs: [...body.matchAll(/url\(\s*(['"]?)([^'")]+)\1\s*\)/g)].map((u) => u[2].trim()),
        dir,
      },
    ];
  });
}
/** 「随包」= 本地相对路径且文件真实存在；远端 URL（Google Fonts 之类）不算。 */
const isBundled = (f: FontFace) =>
  f.srcs.some((u) => !/^(https?:)?\/\//.test(u) && !u.startsWith('data:') && existsSync(resolvePath(f.dir, u.split('?')[0])));

/**
 * 取材面：`ui/src` 下**全部** .css（styles/ 五个 + tray-overlay.css + update-popup/style.css）。
 * `resources/dashboard/` 是第三方 dashboard 打包产物（IBM Plex / Schibsted Grotesk），不是应用外壳字体，不在面内。
 */
function appCssFiles(): string[] {
  const root = abs('..');
  return readdirSync(root, { recursive: true, encoding: 'utf8' })
    .filter((p) => p.endsWith('.css'))
    .map((p) => resolvePath(root, p))
    .sort();
}
const ALL_FACES: FontFace[] = appCssFiles().flatMap((p) => fontFaces(stripComments(readFileSync(p, 'utf8')), dirname(p)));

/** Android（含 WebView）自带或事实可用的中文族。`--sans` 至少要命中其一，否则安卓上掉栈。 */
const ANDROID_CJK = [
  'Noto Sans CJK SC',
  'Noto Sans SC',
  'Noto Sans CJK',
  'Source Han Sans SC',
  'Source Han Sans CN',
  'HarmonyOS Sans SC',
  'Droid Sans Fallback',
];

describe('§6.3.5 第 4 条：字体栈', () => {
  const light = resolveLeg(LEGS[':root']);

  // ── 正向对照：先证明下面两条 it.fails 是「真的缺」，而不是「解析器坏了所以永远失败」──────
  // 没有这两条，it.fails 会把「扫描器写错」也当成缺口通过，门就成了摆设。
  it('⓪ 正向对照：字体栈解析与 @font-face 扫描器对合成输入能报出命中', () => {
    expect(splitTopLevel(light['--disp']).map(unquote)[0]).toBe('Space Grotesk');
    expect(splitTopLevel(light['--sans']).map(unquote)).toContain('PingFang SC');

    const synthetic = fontFaces(
      `@font-face{font-family:'Space Grotesk';src:url("./tokens.css") format("woff2");font-weight:600;}`,
      abs('.'),
    );
    expect(synthetic).toHaveLength(1);
    expect(sameFamily(synthetic[0].family, 'Space Grotesk')).toBe(true);
    expect(isBundled(synthetic[0]), '本地存在的 src 应判为「随包」').toBe(true);
    // 远端 src 必须判为「不随包」——否则第 1 条 it.fails 修好后会被一个 Google Fonts 链接骗过去。
    expect(
      isBundled(fontFaces(`@font-face{font-family:'X';src:url(https://fonts.gstatic.com/x.woff2);}`, abs('.'))[0]),
    ).toBe(false);

    expect(ANDROID_CJK.some((f) => sameFamily(f, 'noto sans cjk sc'))).toBe(true);
  });

  // ── 已知缺口（§6.3.2 ① / ②，契约 B 记录）──────────────────────────────────────
  // 这不是「本轮要修的东西」，是要让它在门上**可见**：全仓 0 个 @font-face、0 个字体文件，
  // `--sans` 里 PingFang SC / Hiragino Sans GB / Microsoft YaHei 在 Android 上全部缺席。
  // 用 `it.fails` 而不是 `it.skip`：skip 永远不跑，缺口修好后标记会烂在这里没人发现；
  // it.fails 一旦真的通过就报「expected to fail」转红，强制来人删掉标记 —— 缺口自曝，修复也自曝。
  // **修复后取消标记**：把 `it.fails` 改回 `it`，不要反过来放宽断言让它变绿（那是契约 B 的违约）。

  it.fails('【已知缺口 §6.3.2① / 契约 B】--disp 的首选族 Space Grotesk 有随包的 @font-face', () => {
    const first = splitTopLevel(light['--disp']).map(unquote)[0];
    const hit = ALL_FACES.filter((f) => sameFamily(f.family, first));
    expect(hit.length, `${first} 没有任何 @font-face（当前 ui/src 下共 ${ALL_FACES.length} 个 @font-face）`).toBeGreaterThan(0);
    expect(hit.some(isBundled), `${first} 的 @font-face 没有随包的本地 src`).toBe(true);
  });

  it.fails('【已知缺口 §6.3.2② / 契约 B】--sans 含至少一个 Android 可用的 CJK 族', () => {
    const fams = splitTopLevel(light['--sans']).map(unquote);
    const hit = fams.filter((f) => ANDROID_CJK.some((c) => sameFamily(c, f)));
    expect(hit, `--sans 当前为 [${fams.join(', ')}]，无 Android 可用 CJK 族`).not.toHaveLength(0);
  });
});
