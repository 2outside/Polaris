/**
 * W27：主窗 ready 必须描述“真实页面已提交”，不能描述 App 外壳已提交。
 *
 * 行为门锁文档级去重；接线门锁三条可见结果：ready 出口已从 App 外壳下沉到页面提交边界、该边界直接
 * 包裹真实页面（中间不再隔着会抢先提交的 Suspense fallback）、两类错误兜底仍能让隐藏窗立即上屏。
 *
 * 「导航层没有挂起源」这条前提本身由 `contracts/navigation-static-binding.test.ts` 逐屏正面钉住，
 * 本门只钉 ready 的落点形态，不重复它的取材面。
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const invokeMock = vi.hoisted(() => vi.fn());

vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));

function read(relative: string): string {
  return readFileSync(fileURLToPath(new URL(relative, import.meta.url)), 'utf8');
}

beforeEach(() => {
  invokeMock.mockReset();
  invokeMock.mockResolvedValue(undefined);
  vi.resetModules();
});

describe('renderer-ready 文档级出口', () => {
  it('同一文档的重复 commit 只回报一次', async () => {
    const { reportRendererReady } = await import('./renderer-ready');
    reportRendererReady();
    reportRendererReady();
    expect(invokeMock).toHaveBeenCalledTimes(1);
    expect(invokeMock).toHaveBeenCalledWith('renderer_ready');
  });

  it('IPC 失败后解除去重，后续兜底仍可补发', async () => {
    invokeMock.mockRejectedValueOnce(new Error('transport down'));
    const { reportRendererReady } = await import('./renderer-ready');
    reportRendererReady();
    await Promise.resolve();
    reportRendererReady();
    expect(invokeMock).toHaveBeenCalledTimes(2);
  });
});

describe('W27 首个可交互帧接线', () => {
  const router = read('../components/screens/ScreenRouter.tsx');
  const app = read('../App.tsx');
  const main = read('../main.tsx');
  const boundary = read('../components/ErrorBoundary.tsx');

  it('ready 从 App 外壳下沉到页面提交边界', () => {
    expect(app).not.toContain('IPC_CHANNELS.RENDERER_READY');
    expect(app).not.toContain('reportRendererReady');
    expect(router).toContain('function RendererReadyBoundary');
    expect(router).toContain('useLayoutEffect(() => reportRendererReady(), [])');
  });

  it('该边界直接包裹真实页面，两条 scope 分支都没有抢先提交的 fallback 夹在中间', () => {
    // 主屏腿与 settings 腿各返回一次，`{screen}` / `<SettingsPage />` 都是同步可取的静态绑定。
    expect(router).toMatch(/return <RendererReadyBoundary>\{screen\}<\/RendererReadyBoundary>;/);
    expect(router).toMatch(
      /<RendererReadyBoundary>\s*<SettingsPage \/>\s*<\/RendererReadyBoundary>/
    );
    // 预取编排随分包一起删干净：没有 loader 表就没有“哪个 loader 忘了预热”这类缺口。
    expect(router).not.toContain('screenLoaders');
    expect(router).not.toContain('initialLoader');
  });

  it('React 同步失败与根 ErrorBoundary 都复用 ready 出口', () => {
    expect(main).toContain('reportRendererReady();');
    expect(boundary).toContain('reportRendererReady();');
    expect(boundary).not.toContain("reportSafely('renderer_ready')");
  });
});
