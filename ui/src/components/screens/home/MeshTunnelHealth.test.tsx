/**
 * 首页「隧道健康」注脚的渲染断言。
 *
 * 本仓 vitest 跑 node 环境、无 jsdom/testing-library（且不许新增依赖）→ 沿用
 * `ReverseRoutingBadge.test.tsx` 的做法：`react-dom/server` 的 `renderToStaticMarkup` 做真实渲染
 * 后的 DOM 断言。i18n mock 成恒等函数（断言落在 key 上，与语种解耦）；两个 zustand store 也 mock 掉
 * ——它们在 server 渲染里没有 `getServerSnapshot`，且本测要的是「选择器选出的值怎么被用」，
 * 不是 zustand 本身。
 */
import { describe, it, expect, vi } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import type { ServerConfig } from '@/contracts/types';
import type { TailscaleStatusEvent } from '@/contracts/tailscale-status';
import type { OpenVpnStatusEvent } from '@/contracts/vpn-status';

const H = vi.hoisted(() => ({
  app: {} as Record<string, unknown>,
  vpn: {} as Record<string, unknown>,
}));

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}));
vi.mock('@/store/app-store', () => ({
  useAppStore: (sel: (s: unknown) => unknown) => sel(H.app),
}));
vi.mock('@/store/use-vpn-status-store', () => ({
  useVpnStatusStore: (sel: (s: unknown) => unknown) => sel(H.vpn),
}));

const { MeshTunnelHealth } = await import('./MeshTunnelHealth');

const srv = (over: Partial<ServerConfig>): ServerConfig =>
  ({ id: 'n1', name: 'n', ...over }) as unknown as ServerConfig;

const tsLanOnly = srv({ protocol: 'tailscale', tailscaleSettings: {} } as Partial<ServerConfig>);
const wgLanOnly = srv({
  protocol: 'wireguard',
  address: 'wg.example.com',
  wireguardSettings: { allowInternet: false, allowedIPs: ['10.0.0.0/8'] },
} as Partial<ServerConfig>);
const ovpnLanOnly = srv({
  protocol: 'openvpn-client',
  meshRoutes: ['192.168.1.0/24'],
  openvpnClientSettings: { redirect_gateway: false },
} as Partial<ServerConfig>);
const vless = srv({ protocol: 'vless', address: 'a.example.com' } as Partial<ServerConfig>);

const frame = (over: Partial<TailscaleStatusEvent> = {}): TailscaleStatusEvent => ({
  serverId: 'n1',
  backendState: 'Running',
  loggedIn: true,
  tailscaleIPs: ['100.64.0.1'],
  expired: false,
  peers: [],
  canShareFiles: false,
  waitingFileCount: 0,
  receivingFileCount: 0,
  unreadFileCount: 0,
  ...over,
});

function render(opts: {
  server: ServerConfig;
  running?: boolean;
  ts?: TailscaleStatusEvent;
  ovpn?: OpenVpnStatusEvent;
}): string {
  H.app = {
    servers: [opts.server],
    selectedServerId: opts.server.id,
    proxyStatus: { running: opts.running ?? true },
    tailscaleStatuses: opts.ts ? { n1: opts.ts } : {},
  };
  H.vpn = { openVpn: opts.ovpn ? { n1: opts.ovpn } : {} };
  return renderToStaticMarkup(<MeshTunnelHealth />);
}

describe('MeshTunnelHealth 渲染', () => {
  it('none → 完全不渲染（非组网节点 / 核没跑，零额外噪音）', () => {
    expect(render({ server: vless, ts: frame({ expired: true }) })).toBe('');
    expect(render({ server: tsLanOnly, ts: frame({ expired: true }), running: false })).toBe('');
    expect(render({ server: tsLanOnly, ts: frame() })).toBe('');
  });

  it('unprobeable（WireGuard）→ 完全不渲染：静态恒亮事实，常驻横幅无可行动性', () => {
    expect(render({ server: wgLanOnly })).toBe('');
  });

  it.each([
    ['home.meshTunnelTsExpired', { server: tsLanOnly, ts: frame({ expired: true }) }],
    ['home.meshTunnelTsNotReady', { server: tsLanOnly, ts: frame({ backendState: 'Starting' }) }],
    [
      'home.meshTunnelTsPeersOffline',
      {
        server: tsLanOnly,
        ts: frame({
          peers: [
            { hostName: 'h', ip: '100.64.0.9', online: false, exitNode: false, exitNodeOption: false, active: false },
          ],
        }),
      },
    ],
    [
      'home.meshTunnelVpnError',
      { server: ovpnLanOnly, ovpn: { serverId: 'n1', state: 's', stateText: '', error: 'boom' } as OpenVpnStatusEvent },
    ],
    [
      'home.meshTunnelVpnDisconnected',
      { server: ovpnLanOnly, ovpn: { serverId: 'n1', state: 's', stateText: '' } as OpenVpnStatusEvent },
    ],
  ])('渲染出 %s，且带 role="status"', (key, opts) => {
    const html = render(opts as Parameters<typeof render>[0]);
    expect(html).toContain(key);
    expect(html).toContain('role="status"');
  });

  it('图标与 TsExitWarning 的三角警示不同形（两条注脚必须可分辨）', () => {
    const html = render({ server: tsLanOnly, ts: frame({ expired: true }) });
    expect(html).toContain('<circle');
    expect(html).not.toContain('M12 3.2L21 19H3z');
  });
});
