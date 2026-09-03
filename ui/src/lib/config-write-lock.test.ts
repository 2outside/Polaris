import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, expect, beforeEach, vi } from 'vitest';

// 模块级队列（`tail`）不给生产模块开复位口 —— 那是进产物的公开 API，且生产零调用点。
// 每个用例 `vi.resetModules()` + 动态 import 取一份全新模块实例，队列自然是初始态。
let withConfigWriteLock: typeof import('./config-write-lock')['withConfigWriteLock'];

beforeEach(async () => {
  vi.resetModules();
  ({ withConfigWriteLock } = await import('./config-write-lock'));
});

describe('withConfigWriteLock —— 串行语义', () => {
  // 变异对照：把实现改成 `return run()`（不排队）→ 本条转红（两段会交错成 a1 b1 a2 b2）。
  it('后一次必须等前一次**落定**才进临界区（不是交错）', async () => {
    const log: string[] = [];
    const task = (tag: string) => async () => {
      log.push(`${tag}-enter`);
      await Promise.resolve();
      await Promise.resolve();
      log.push(`${tag}-exit`);
    };
    await Promise.all([withConfigWriteLock(task('a')), withConfigWriteLock(task('b'))]);
    expect(log).toEqual(['a-enter', 'a-exit', 'b-enter', 'b-exit']);
  });

  // 变异对照：把 `tail.then(run, run)` 改成 `tail.then(run)` → 前一次失败后队列永久堵死 → 本条超时/转红。
  // 一次保存失败把后续保存全堵住，比并发冲突更糟：用户再也存不进任何东西，且没有任何提示。
  it('前一次失败不得堵死后一次', async () => {
    const ran: string[] = [];
    const boom = withConfigWriteLock(async () => {
      ran.push('boom');
      throw new Error('第一次挂了');
    });
    const after = withConfigWriteLock(async () => {
      ran.push('after');
      return 'ok';
    });
    await expect(boom).rejects.toThrow('第一次挂了');
    await expect(after).resolves.toBe('ok');
    expect(ran).toEqual(['boom', 'after']);
  });

  // 成败必须原样透传：闸门只管顺序，不得吞掉调用方要判的结果。
  it('返回值与异常原样透传给调用方', async () => {
    await expect(withConfigWriteLock(async () => 42)).resolves.toBe(42);
    await expect(withConfigWriteLock(async () => Promise.reject(new Error('x')))).rejects.toThrow('x');
  });
});

/**
 * **接线守卫**：闸门只有在「主窗里每一次 `api.config.save` 都在它里面」时才成立。
 * 漏一处就重新打开 `performSave` 的 `get()`→`save()` 窗口 —— 那正是「盘存好了、条说失败了」的成因。
 *
 * 扫源码而非依赖人工记忆：新增一处未入队的配置事务立刻转红。
 * 托盘（`ui/src/tray/`）**刻意排除**：它是另一个 webview，模块级队列跨不过去，那边的写冲突由
 * 后端 `baseVersion` 检出机制负责（见闸门头注的射程边界）。
 */
describe('接线：主窗里的配置事务必须都在闸门内', () => {
  const SRC = new URL('..', import.meta.url).pathname; // ui/src/

  /** 递归收集 ui/src 下的源码文件（去掉测试）。不含子进程、不依赖 git 索引（新文件也扫得到）。 */
  function sources(dir = SRC, out: string[] = []): string[] {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, e.name);
      if (e.isDirectory()) sources(p, out);
      else if (/\.(ts|tsx)$/.test(e.name) && !e.name.includes('.test.')) out.push(p);
    }
    return out;
  }

  /**
   * 去注释后再扫 —— **必须**：本文件与闸门自身的文档注释里都逐字写着这些调用，只扫原文的话
   * 「把真代码改坏、只留注释」会照样绿（无牙），而新增一处文档提及又会误红。同
   * `ipc-channel-bypass-wiring.test.ts` 的 `code()` 与 Rust 侧 `method_body` 的同款纪律。
   */
  const stripComments = (s: string): string =>
    s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^[ \t]*\/\/.*$/gm, '');

  /** 命中 `needle` 的文件（相对 ui/src 的路径），排除 `skip` 前缀。 */
  const filesWith = (needle: string, skip: readonly string[] = []): string[] =>
    sources()
      .filter((p) => stripComments(readFileSync(p, 'utf8')).includes(needle))
      .map((p) => p.slice(SRC.length))
      .filter((rel) => !skip.some((s) => rel.startsWith(s)))
      .sort();

  // 整份保存只允许暂存事务使用；即时编辑必须走 patch，避免陈旧快照覆盖后台写入。
  it('版本化整份写只存在于暂存事务', () => {
    expect(filesWith('api.config.save(', ['tray/'])).toEqual(['store/staged-config-store.ts']);
  });

  // 变异对照：把任一处的 `withConfigWriteLock(...)` 拆掉、只留裸调用 → 对应断言转红。
  it('五处都真的裹在 withConfigWriteLock 里', () => {
    const appStore = readFileSync(join(SRC, 'store/app-store.ts'), 'utf8');
    expect(appStore).toContain('withConfigWriteLock(() => api.config.patch(patch))');
    expect(appStore).toContain('withConfigWriteLock(() => api.config.mutateEntities(mutations))');
    expect(appStore).toContain('withConfigWriteLock(async () => {\n      await api.server.switch(serverId)');
    // performSave 是薄壳：整个函数体（**含开头读 entries**）都在临界区内。
    expect(readFileSync(join(SRC, 'store/staged-config-store.ts'), 'utf8')).toContain(
      'withConfigWriteLock(() => performSaveLocked(set, get))'
    );
    expect(readFileSync(join(SRC, 'components/screens/settings/use-config.ts'), 'utf8')).toContain(
      'withConfigWriteLock(() => configApi.patch(direct))'
    );
  });

  // 不可嵌套（临界区内再入队 = 自锁）。当前使用点互不调用；新增使用点必须先读头注那条。
  it('闸门只有五个主窗生产使用点', () => {
    const appStore = readFileSync(join(SRC, 'store/app-store.ts'), 'utf8');
    const stagedStore = readFileSync(join(SRC, 'store/staged-config-store.ts'), 'utf8');
    const settings = readFileSync(join(SRC, 'components/screens/settings/use-config.ts'), 'utf8');
    expect((appStore.match(/withConfigWriteLock\((?:async )?\(\) =>/g) ?? []).length).toBe(3);
    expect((stagedStore.match(/withConfigWriteLock\((?:async )?\(\) =>/g) ?? []).length).toBe(1);
    expect((settings.match(/withConfigWriteLock\((?:async )?\(\) =>/g) ?? []).length).toBe(1);
    expect(filesWith('withConfigWriteLock(() =>', ['config-write-lock.ts'])).toEqual([
      'components/screens/settings/use-config.ts',
      'store/app-store.ts',
      'store/staged-config-store.ts',
      'tray/TrayMenu.tsx',
    ]);
  });
});
