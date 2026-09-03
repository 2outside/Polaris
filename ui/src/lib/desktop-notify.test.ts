/**
 * C8 桌面通知出口单测：门控（desktopNotifications 开关）+ 权限解析 + notify invoke payload。
 * 无 DOM 依赖——mock 裸 `@tauri-apps/api/core` invoke，验决策与调用形。
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

const invokeMock = vi.fn();
vi.mock('@tauri-apps/api/core', () => ({
  invoke: (...args: unknown[]) => invokeMock(...args),
}));

// 模块级权限缓存不给生产模块开复位口（那是进产物的公开 API，且生产零调用点）：
// 每个用例 `vi.resetModules()` + 动态 import 取一份全新模块实例，缓存自然是初始态。
let dn: typeof import('./desktop-notify');

const NOTIFY = 'plugin:notification|notify';
const IS_GRANTED = 'plugin:notification|is_permission_granted';
const REQUEST = 'plugin:notification|request_permission';

describe('desktopNotify (C8)', () => {
  beforeEach(async () => {
    invokeMock.mockReset();
    vi.resetModules();
    dn = await import('./desktop-notify');
    dn.setDesktopNotificationsEnabled(true);
  });

  it('权限已授予 + 开关开 → 发 notify（invoke plugin:notification|notify，payload options:{title,body}）', async () => {
    invokeMock.mockImplementation((cmd: string) =>
      cmd === IS_GRANTED ? Promise.resolve(true) : Promise.resolve()
    );
    await dn.notifyDesktop('代理出错', '已停止');
    expect(invokeMock).toHaveBeenCalledWith(NOTIFY, {
      options: { title: '代理出错', body: '已停止' },
    });
  });

  it('desktopNotifications 关 → 不发（连权限都不查）', async () => {
    dn.setDesktopNotificationsEnabled(false);
    expect(dn.isDesktopNotificationsEnabled()).toBe(false);
    await dn.notifyDesktop('T', 'B');
    expect(invokeMock).not.toHaveBeenCalled();
  });

  it('dn.setDesktopNotificationsEnabled(undefined) 视为开（缺省/旧配置默认开）', () => {
    dn.setDesktopNotificationsEnabled(undefined);
    expect(dn.isDesktopNotificationsEnabled()).toBe(true);
  });

  it('权限未决（null）→ 请求一次；granted 才发', async () => {
    invokeMock.mockImplementation((cmd: string) => {
      if (cmd === IS_GRANTED) return Promise.resolve(null);
      if (cmd === REQUEST) return Promise.resolve('granted');
      return Promise.resolve();
    });
    await dn.notifyDesktop('T', 'B');
    expect(invokeMock).toHaveBeenCalledWith(REQUEST);
    expect(invokeMock).toHaveBeenCalledWith(NOTIFY, { options: { title: 'T', body: 'B' } });
  });

  it('权限被拒 → 不 notify', async () => {
    invokeMock.mockImplementation((cmd: string) =>
      cmd === IS_GRANTED ? Promise.resolve(false) : Promise.resolve()
    );
    await dn.notifyDesktop('T', 'B');
    expect(invokeMock).not.toHaveBeenCalledWith(NOTIFY, expect.anything());
  });

  it('权限查询抛异常（非 Tauri / 插件异常）→ 静默不发，不抛', async () => {
    invokeMock.mockImplementation((cmd: string) =>
      cmd === IS_GRANTED ? Promise.reject(new Error('no tauri')) : Promise.resolve()
    );
    await expect(dn.notifyDesktop('T', 'B')).resolves.toBeUndefined();
    expect(invokeMock).not.toHaveBeenCalledWith(NOTIFY, expect.anything());
  });

  it('权限解析缓存：第二次发不重复查权限', async () => {
    invokeMock.mockImplementation((cmd: string) =>
      cmd === IS_GRANTED ? Promise.resolve(true) : Promise.resolve()
    );
    await dn.notifyDesktop('a', 'b');
    await dn.notifyDesktop('c', 'd');
    const permChecks = invokeMock.mock.calls.filter((c) => c[0] === IS_GRANTED).length;
    expect(permChecks).toBe(1);
    const notifies = invokeMock.mock.calls.filter((c) => c[0] === NOTIFY).length;
    expect(notifies).toBe(2);
  });
});
