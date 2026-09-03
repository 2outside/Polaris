/**
 * 生产 TS 模块不得导出**测试专用**符号。
 *
 * # 守的是什么
 *
 * 一个只服务测试的导出（`__resetXForTest()` / 复位模块级缓存的钩子 / 内存替身）留在生产模块里，
 * 它就是**生产 API**：
 *
 * 1. 它进产物。Vite 的 tree-shaking 只能删「没人 import」的东西，而这类符号恰恰被 `.test.ts`
 *    import 着 —— 打包器看到的是「有消费者」；
 * 2. 它是**公开契约**。删掉 `__resetSkippedForTest` 就是一次 breaking change，而它在生产路径上
 *    一个调用点都没有；
 * 3. 它把「模块级可变状态」的复位权交给了外部。生产代码某天误调一次，会话态被清空且不报错。
 *
 * 正确做法是让测试自己拿一份干净的模块实例：`vi.resetModules()` + 动态 `import()` —— 模块顶层
 * 重新求值，模块级状态自然回到初始态，生产面一个符号都不必多开。
 *
 * 这条与 Rust 侧的 `src-tauri/tests/test_only_symbols_gated.rs` 是同一条不变量的两侧：
 * 那边靠 `#[cfg(test)]` / `feature = "test-utils"`，TS 没有等价物，只能靠本门。
 *
 * # 判据（两支）
 *
 * - **NAME 支**：导出名以 `__` 开头，或以 `ForTest` / `ForTests` / `ForTesting` 结尾（大小写不敏感）。
 * - **DOC 支**：导出的 JSDoc **摘要行**含「测试用 / 仅供单测 / 测试专用 / 仅测试 / 测试 mock / test-only」。
 *
 * `.test.ts` / `.spec.ts` / `.test-support.ts` 整份不在射程内（见 `IS_TEST_ONLY_MODULE`）。
 */
import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as ts from '@/test/ts-compiler';

import { IS_TEST_ONLY_MODULE } from './test-only-modules';

const SRC_DIR = fileURLToPath(new URL('..', import.meta.url));
const UI_DIR = fileURLToPath(new URL('../..', import.meta.url));
const rel = (abs: string) => relative(UI_DIR, abs).split(sep).join('/');

const NAME_PATTERNS = [/^__/, /for_?tests?$/i, /for_?testing$/i];
const DOC_NEEDLES = ['测试用', '仅供单测', '测试专用', '仅测试', '测试 mock', 'test-only', 'for test'];

/**
 * 命中判据但**确属生产用途**的导出：`(仓库相对路径, 导出名, 理由)`。
 *
 * 每条必须**恰好命中一次**：命中 0 次说明它守的东西没了、条目成了下一个真违规的免死金牌；
 * 命中多次说明一条豁免悄悄覆盖了它没打算覆盖的地方。
 */
const WHITELIST: readonly (readonly [string, string, string])[] = [];

function sources(): string[] {
  const out: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) walk(full);
      else if (/\.tsx?$/.test(entry) && !IS_TEST_ONLY_MODULE.test(entry)) out.push(full);
    }
  };
  walk(SRC_DIR);
  return out.sort();
}

interface Hit {
  file: string;
  line: number;
  name: string;
  byName: boolean;
  byDoc: boolean;
  summary: string;
}

/** JSDoc 摘要行：紧邻声明的那段块注释的第一句非空文本。 */
function summaryOf(text: string, start: number): string {
  const before = text.slice(0, start);
  const close = before.lastIndexOf('*/');
  if (close < 0) return '';
  // 注释与声明之间只允许空白（否则那段注释属于别的东西）。
  if (before.slice(close + 2).trim() !== '') return '';
  const open = before.lastIndexOf('/**', close);
  if (open < 0) return '';
  for (const raw of before.slice(open + 3, close).split('\n')) {
    const line = raw.replace(/^\s*\*?\s?/, '').trim();
    if (line !== '') return line;
  }
  return '';
}

function scanSource(file: string, text: string): Hit[] {
  const sf = ts.parseSourceFile(file, text);
  const hits: Hit[] = [];
  const record = (name: string, start: number): void => {
    const byName = NAME_PATTERNS.some((p) => p.test(name));
    const summary = summaryOf(text, start);
    const byDoc = DOC_NEEDLES.some((n) => summary.includes(n));
    if (!byName && !byDoc) return;
    hits.push({
      file: rel(file),
      line: sf.getLineAndCharacterOfPosition(start).line + 1,
      name,
      byName,
      byDoc,
      summary,
    });
  };

  // TS7 的 `unstable/ast` 没有 `canHaveModifiers` / `getModifiers`，修饰符直接挂在节点上。
  const exported = (n: ts.Node): boolean => {
    const mods = (n as { modifiers?: Iterable<ts.Node> }).modifiers;
    if (!mods) return false;
    for (const m of mods) if (ts.isExportKeyword(m)) return true;
    return false;
  };

  const visit = (n: ts.Node): void => {
    if (
      (ts.isFunctionDeclaration(n) ||
        ts.isClassDeclaration(n) ||
        ts.isInterfaceDeclaration(n) ||
        ts.isTypeAliasDeclaration(n) ||
        ts.isEnumDeclaration(n)) &&
      exported(n) &&
      n.name
    ) {
      record(n.name.getText(sf), n.getStart(sf));
    }
    if (ts.isVariableStatement(n) && exported(n)) {
      for (const d of n.declarationList.declarations) {
        if (ts.isIdentifier(d.name)) record(d.name.getText(sf), n.getStart(sf));
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return hits;
}

const scanFile = (file: string): Hit[] => scanSource(file, readFileSync(file, 'utf8'));

const FILES = sources();
const HITS = FILES.flatMap(scanFile);

/** 合成夹具：两支判据各一条正样本 + 一条负样本（不依赖真实语料是否恰好有样本）。 */
const FIXTURE = [
  '/** 测试用：复位缓存。 */',
  'export function resetCache(): void {}',
  '/** 复位句柄。 */',
  'export const __probeHandle = 1;',
  '/** 正经的生产导出。 */',
  'export function realThing(): void {}',
  '/** 测试用：这条没导出，不该命中。 */',
  'function privateHelper(): void {}',
].join('\n');

describe('生产 TS 模块不得导出测试专用符号', () => {
  it('取材面与判据自检：本门不能空转', () => {
    // 否定型断言在空取材面上恒真 —— 这是本门唯一的静默失效方向。
    expect(FILES.length, `只扫到 ${FILES.length} 个源文件 —— 枚举器坏了`).toBeGreaterThan(200);
    expect(
      FILES.map(rel),
      '取材面漏了 src/lib/desktop-notify.ts —— 整棵树没扫到'
    ).toContain('src/lib/desktop-notify.ts');
    expect(
      FILES.filter((f) => IS_TEST_ONLY_MODULE.test(f)).map(rel),
      '取材面里混进了测试文件 —— 它们的测试专用导出会把本门吵成假红'
    ).toEqual([]);

    // 两支判据都要能在夹具上点火，且不误伤非导出与正经导出。
    const fixture = scanSource(join(SRC_DIR, 'fixture.ts'), FIXTURE);
    const byName = fixture.filter((h) => h.byName).map((h) => h.name);
    const byDoc = fixture.filter((h) => h.byDoc).map((h) => h.name);
    expect(byName, 'NAME 支在夹具上不点火 —— 该支从未被执行').toEqual(['__probeHandle']);
    expect(byDoc, 'DOC 支在夹具上不点火 —— 该支从未被执行').toEqual(['resetCache']);
    expect(
      fixture.map((h) => h.name),
      '误伤：非导出的 privateHelper 或正经导出的 realThing 被判成了测试专用'
    ).toEqual(['resetCache', '__probeHandle']);
  });

  it('没有未登记的测试专用导出', () => {
    const used = new Set<string>();
    const bad = HITS.filter((h) => {
      const entry = WHITELIST.find(([f, n]) => f === h.file && n === h.name);
      if (entry) {
        used.add(`${entry[0]} ${entry[1]}`);
        return false;
      }
      return true;
    }).map(
      (h) =>
        `  ${h.file}:${h.line}  ${h.name}  命中 ` +
        `${h.byName && h.byDoc ? 'NAME+DOC' : h.byName ? 'NAME' : 'DOC'} 支` +
        (h.summary ? `\n      摘要行: ${h.summary}` : '')
    );
    expect(
      bad,
      `\n${bad.length} 个测试专用导出留在生产模块里（它们进产物、也是公开契约）：\n` +
        `${bad.join('\n')}\n` +
        `修法：让测试自己拿干净实例 —— \`vi.resetModules()\` + \`await import('./x')\`；` +
        `确属生产用途则登记进本文件的 WHITELIST 并写明谁在生产路径上用它。\n`
    ).toEqual([]);

    const stale = WHITELIST.filter(([f, n]) => !used.has(`${f} ${n}`)).map(
      ([f, n]) => `  ${f} :: ${n}`
    );
    expect(
      stale,
      `\nWHITELIST 有 ${stale.length} 条过期条目（已不再命中）—— 删掉它们，` +
        `否则白名单会退化成垃圾桶：\n${stale.join('\n')}\n`
    ).toEqual([]);
  });
});
