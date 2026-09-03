/** 文件系统命名契约：只约束仓库内部源码路径，不触碰 IPC、JSON、FFI 或平台工具固定名称。 */
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import { IS_TEST_ONLY_MODULE } from './test-only-modules';

const REPO = fileURLToPath(new URL('../../../', import.meta.url));
const UI_SOURCE_PREFIX = 'ui/src/';
const KEBAB_SEGMENT = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const KEBAB_TS = /^[a-z0-9]+(?:-[a-z0-9]+)*(?:\.generated)?\.ts$/;
const PASCAL_TSX = /^[A-Z][A-Za-z0-9]*\.tsx$/;
const TEST_FILE =
  /^(?:[A-Z][A-Za-z0-9]*|[a-z0-9]+(?:-[a-z0-9]+)*)(?:\.[a-z0-9]+(?:-[a-z0-9]+)*)?\.(?:test|spec)\.tsx?$/;

/** 工具链入口与目录聚合入口使用生态固定名；业务 React 模块不进入例外表。 */
const TSX_ENTRY_EXCEPTIONS = new Set([
  'components/brand-icons/index.tsx',
  'main.tsx',
  'tray/main.tsx',
  'harness-main.tsx',
  'tray-harness-main.tsx',
]);
const FUNCTION_NAME = /^(?:[a-z]|__[a-z]|[A-Z])[A-Za-z0-9]*$/;

function repositoryFiles(): string[] {
  return execFileSync(
    'git',
    ['ls-files', '--cached', '--others', '--exclude-standard', '--deduplicate'],
    { cwd: REPO, encoding: 'utf8' },
  )
    .split('\n')
    .filter((path) => path && existsSync(join(REPO, path)));
}

describe('文件系统命名', () => {
  const files = repositoryFiles();
  const uiSource = files.filter((path) => path.startsWith(UI_SOURCE_PREFIX));

  it('不存在大小写折叠后的路径冲突', () => {
    const seen = new Map<string, string>();
    const collisions: string[] = [];
    for (const path of files) {
      const folded = path.normalize('NFC').toLowerCase();
      const previous = seen.get(folded);
      if (previous && previous !== path) collisions.push(`${previous} <> ${path}`);
      seen.set(folded, path);
    }
    expect(collisions, `大小写不敏感平台会把这些路径视为同一文件：\n${collisions.join('\n')}`).toEqual([]);
  });

  it('UI 源码目录统一使用 kebab-case', () => {
    const invalid = uiSource.flatMap((path) => {
      const segments = path.slice(UI_SOURCE_PREFIX.length).split('/').slice(0, -1);
      return segments.filter((segment) => !KEBAB_SEGMENT.test(segment)).map(() => path);
    });
    expect(invalid, `目录名须使用 kebab-case：\n${invalid.join('\n')}`).toEqual([]);
  });

  it('普通 TypeScript 模块使用 kebab-case', () => {
    const invalid = uiSource.filter((path) => {
      const name = basename(path);
      if (!name.endsWith('.ts') || name.endsWith('.d.ts') || IS_TEST_ONLY_MODULE.test(name)) {
        return false;
      }
      return !KEBAB_TS.test(name);
    });
    expect(invalid, `普通 .ts 文件名须使用 kebab-case：\n${invalid.join('\n')}`).toEqual([]);
  });

  it('测试文件跟随组件名或使用 kebab-case 行为名', () => {
    const invalid = uiSource.filter((path) => {
      const name = basename(path);
      return /\.(?:test|spec)\.tsx?$/.test(name) && !TEST_FILE.test(name);
    });
    expect(invalid, `测试文件命名须使用“被测组件[.行为]”或 kebab-case：\n${invalid.join('\n')}`).toEqual([]);
  });

  it('React 业务模块统一使用 PascalCase', () => {
    const invalid = uiSource.filter((path) => {
      const relative = path.slice(UI_SOURCE_PREFIX.length);
      const name = basename(relative);
      if (!name.endsWith('.tsx') || /\.(?:test|spec)\.tsx$/.test(name)) return false;
      return !PASCAL_TSX.test(name) && !TSX_ENTRY_EXCEPTIONS.has(relative);
    });
    expect(invalid, `业务 .tsx 文件名须使用 PascalCase：\n${invalid.join('\n')}`).toEqual([]);
  });

  it('TypeScript 命名函数使用 camelCase 或 PascalCase', () => {
    const invalid: string[] = [];
    const sourceFiles = uiSource.filter((path) => /\.tsx?$/.test(path));
    const declarations = /\b(?:async\s+)?function\s+\*?\s*([A-Za-z_$][\w$]*)\s*\(/g;
    const arrows = /\b(?:const|let)\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=\s*(?:async\s*)?(?:\([^=()\n]*\)|[A-Za-z_$][\w$]*)\s*=>/g;

    for (const path of sourceFiles) {
      const source = readFileSync(join(REPO, path), 'utf8');
      for (const pattern of [declarations, arrows]) {
        pattern.lastIndex = 0;
        for (const match of source.matchAll(pattern)) {
          const name = match[1];
          if (name && !FUNCTION_NAME.test(name)) invalid.push(`${path}: ${name}`);
        }
      }
    }
    expect(invalid, `函数名须使用 camelCase，React 组件可使用 PascalCase：\n${invalid.join('\n')}`).toEqual([]);
  });
});
