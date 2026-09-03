/**
 * 「只走内网的组网节点·隧道健康」谓词真值表 + 喂数接线守卫。
 *
 * 两段的理由同 `tailscale-exit-warning.test.ts`：纯谓词全绿挡不住「store 里的帧压根没被喂进来」
 * 或「HomeScreen 没挂这个组件」——那两条断掉的形态与「判定写错」在用户侧是同一个结果（零提示），
 * 而只测纯函数时它们**结构性不可见**。W 段跑在剥掉注释的源码上（本文件与被守文件的注释都逐字
 * 引用了判据，扫原文会自我误伤）。
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { deriveMeshTunnelHealth } from './mesh-tunnel-health';
import type { MeshTunnelHealthInput } from './mesh-tunnel-health';
import type { TailscaleStatusEvent, TailscaleStatusPeer } from '../contracts/tailscale-status';
import type { OpenVpnStatusEvent } from '../contracts/vpn-status';
import type { ServerConfig } from '../contracts/types';

const SRC = resolve(__dirname, '..');
const read = (rel: string): string => readFileSync(resolve(SRC, rel), 'utf8');
/** 去注释：`[^:]` 前瞻避免把 `https://` 当行注释切掉。 */
const code = (s: string): string =>
  s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');

// ── 夹具 ───────────────────────────────────────────────────────────────────

const srv = (over: Partial<ServerConfig>): ServerConfig =>
  ({ id: 'n1', name: 'n', ...over }) as unknown as ServerConfig;

/** TS：`meshAllowsInternet` 由 exitNode 派生 —— 无 exitNode = 只走内网。 */
const tsLanOnly = srv({ protocol: 'tailscale', tailscaleSettings: {} } as Partial<ServerConfig>);
const tsFullTunnel = srv({
  protocol: 'tailscale',
  tailscaleSettings: { exitNode: '100.64.0.9' },
} as Partial<ServerConfig>);

/** WG：显式关掉「允许访问外网」+ 有具体段 = 只走内网；不带 warpDevice/warp 域名 ⇒ 不是 WARP。 */
const wgLanOnly = srv({
  protocol: 'wireguard',
  address: 'wg.example.com',
  wireguardSettings: { allowInternet: false, allowedIPs: ['10.0.0.0/8'] },
} as Partial<ServerConfig>);
const wgFullTunnel = srv({
  protocol: 'wireguard',
  address: 'wg.example.com',
  wireguardSettings: { allowedIPs: ['10.0.0.0/8'] },
} as Partial<ServerConfig>);
/** WARP 恒承载全隧道（`meshAllowsInternet` 对它恒 true）⇒ 永远过不了总门。 */
const warp = srv({
  protocol: 'wireguard',
  address: 'wg.example.com',
  wireguardSettings: { allowInternet: false, warpDevice: { deviceId: 'd', token: 't' } },
} as Partial<ServerConfig>);

/** OVPN：`redirect_gateway=false` + 有 meshRoutes ⇒ isMeshNode ∧ 只走内网。 */
const ovpnLanOnly = srv({
  protocol: 'openvpn-client',
  meshRoutes: ['192.168.1.0/24'],
  openvpnClientSettings: { redirect_gateway: false },
} as Partial<ServerConfig>);
const ovpnFullTunnel = srv({
  protocol: 'openvpn-client',
  meshRoutes: ['192.168.1.0/24'],
  openvpnClientSettings: {},
} as Partial<ServerConfig>);
/** OC 无「全隧道开关」（`meshAllowsInternet` 末尾恒 true）⇒ 与 OVPN 不同，OC 永远过不了总门。 */
const ocNode = srv({
  protocol: 'openconnect',
  meshRoutes: ['192.168.1.0/24'],
} as Partial<ServerConfig>);
/** 非组网节点。 */
const vless = srv({ protocol: 'vless', address: 'a.example.com' } as Partial<ServerConfig>);

const peer = (online: boolean): TailscaleStatusPeer => ({
  hostName: 'h',
  ip: '100.64.0.9',
  online,
  exitNode: false,
  exitNodeOption: false,
  active: false,
});

const frame = (
  over: Partial<TailscaleStatusEvent> = {},
  peers: TailscaleStatusPeer[] = [],
): TailscaleStatusEvent => ({
  serverId: 'n1',
  backendState: 'Running',
  loggedIn: true,
  tailscaleIPs: ['100.64.0.1'],
  expired: false,
  peers,
  canShareFiles: false,
  waitingFileCount: 0,
  receivingFileCount: 0,
  unreadFileCount: 0,
  ...over,
});

const ovpn = (over: Partial<OpenVpnStatusEvent> = {}): OpenVpnStatusEvent => ({
  serverId: 'n1',
  state: 'auth-pending',
  stateText: '',
  ...over,
});
const OVPN_TUNNEL: OpenVpnStatusEvent['tunnelInfo'] = {
  server: 's',
  network: 'n',
  ipv4: ['10.8.0.2'],
  ipv6: [],
  dns: [],
  mtu: 1500,
  connectedSince: 0,
  cipher: 'AES-256-GCM',
};
const at = (over: Partial<MeshTunnelHealthInput>): MeshTunnelHealthInput => ({
  selectedServer: undefined,
  proxyRunning: true,
  tsStatus: undefined,
  openVpnStatus: undefined,
  ...over,
});

// ── P 段：纯谓词真值表 ─────────────────────────────────────────────────────

describe('P 总门：只对「只走内网的组网节点」说话', () => {
  it('没有选中节点 → none', () => {
    expect(deriveMeshTunnelHealth(at({}))).toBe('none');
  });

  it('非组网节点（代理协议）→ none，哪怕手里有一帧坏状态', () => {
    expect(
      deriveMeshTunnelHealth(at({ selectedServer: vless, tsStatus: frame({ expired: true }) })),
    ).toBe('none');
  });

  it('组网但承载全隧道 → none（TS 有出口设备 / WG 未关外网 / WARP / OVPN 未关全隧道）', () => {
    expect(
      deriveMeshTunnelHealth(at({ selectedServer: tsFullTunnel, tsStatus: frame({ expired: true }) })),
    ).toBe('none');
    expect(deriveMeshTunnelHealth(at({ selectedServer: wgFullTunnel }))).toBe('none');
    expect(deriveMeshTunnelHealth(at({ selectedServer: warp }))).toBe('none');
    expect(
      deriveMeshTunnelHealth(
        at({ selectedServer: ovpnFullTunnel, openVpnStatus: ovpn({ error: 'boom' }) }),
      ),
    ).toBe('none');
    // OC 无全隧道开关 ⇒ 恒承载全隧道 ⇒ 恒被总门挡下，协议分派里也没有它的 case（不可达死代码已删）
    expect(deriveMeshTunnelHealth(at({ selectedServer: ocNode }))).toBe('none');
  });
});

describe('P 新鲜度门：核没跑 → 恒 none', () => {
  it.each([
    ['TS 过期帧', at({ selectedServer: tsLanOnly, tsStatus: frame({ expired: true }) })],
    ['WG 无信号', at({ selectedServer: wgLanOnly })],
    ['OVPN 错误帧', at({ selectedServer: ovpnLanOnly, openVpnStatus: ovpn({ error: 'boom' }) })],
  ])('%s + proxyRunning=false → none', (_name, input) => {
    expect(deriveMeshTunnelHealth({ ...input, proxyRunning: false })).toBe('none');
  });
});

describe('P Tailscale 分档', () => {
  const ts = (status: TailscaleStatusEvent | undefined) =>
    deriveMeshTunnelHealth(at({ selectedServer: tsLanOnly, tsStatus: status }));

  it('无帧 → none（不知道就不猜）', () => {
    expect(ts(undefined)).toBe('none');
  });
  it('expired → ts-expired（优先于后端状态）', () => {
    expect(ts(frame({ expired: true, backendState: 'NeedsLogin' }))).toBe('ts-expired');
  });
  it('backendState ≠ Running → ts-not-running', () => {
    expect(ts(frame({ backendState: 'Starting' }))).toBe('ts-not-running');
    expect(ts(frame({ backendState: 'NeedsLogin' }))).toBe('ts-not-running');
    expect(ts(frame({ backendState: 'Stopped' }))).toBe('ts-not-running');
  });
  it('有对端且全部离线 → ts-peers-offline', () => {
    expect(ts(frame({}, [peer(false), peer(false)]))).toBe('ts-peers-offline');
  });
  it('peers 为空 → none（空 ≠ 一台都不在线，那一帧根本没带对端信息）', () => {
    expect(ts(frame({}, []))).toBe('none');
  });
  it('有任一在线对端 → none', () => {
    expect(ts(frame({}, [peer(false), peer(true)]))).toBe('none');
  });
});

describe('P OpenVPN 分档', () => {
  const run = (status: OpenVpnStatusEvent | undefined) =>
    deriveMeshTunnelHealth(at({ selectedServer: ovpnLanOnly, openVpnStatus: status }));

  it('无帧 → none', () => {
    expect(run(undefined)).toBe('none');
  });
  it('error 非空 → vpn-error（优先于 tunnelInfo 缺席）', () => {
    expect(run(ovpn({ error: 'AUTH_FAILED' }))).toBe('vpn-error');
    expect(run(ovpn({ error: 'AUTH_FAILED', tunnelInfo: OVPN_TUNNEL }))).toBe('vpn-error');
  });
  it('error 是空白串 → 不当错误（后端把字段置空的形态）', () => {
    expect(run(ovpn({ error: '   ', tunnelInfo: OVPN_TUNNEL }))).toBe('none');
  });
  it('tunnelInfo 缺席 → vpn-disconnected', () => {
    expect(run(ovpn({}))).toBe('vpn-disconnected');
  });
  it('无错误且有隧道参数 → none', () => {
    expect(run(ovpn({ tunnelInfo: OVPN_TUNNEL }))).toBe('none');
  });
});

describe('P WireGuard：没有信号源 → 恒「无法探测」，不伪造健康位', () => {
  it('只走内网的 WG → unprobeable', () => {
    expect(deriveMeshTunnelHealth(at({ selectedServer: wgLanOnly }))).toBe('unprobeable');
  });
  it('别的协议的状态帧不改变它（WG 没有自己的源，也不许借别人的）', () => {
    expect(
      deriveMeshTunnelHealth(
        at({ selectedServer: wgLanOnly, tsStatus: frame({}), openVpnStatus: ovpn({ tunnelInfo: OVPN_TUNNEL }) }),
      ),
    ).toBe('unprobeable');
  });
});

// ── W 段：接线不变量（源码级） ─────────────────────────────────────────────

describe('W 接线：帧真的被喂进判定、组件真的被挂上', () => {
  it('组件把两个信号源都喂进了谓词（任一喂数点被删即转红）', () => {
    const src = code(read('components/screens/home/MeshTunnelHealth.tsx'));
    expect(src).toContain('deriveMeshTunnelHealth');
    expect(src).toContain('s.tailscaleStatuses[id]');
    expect(src).toContain('s.openVpn[id]');
    expect(src).toContain('!!s.proxyStatus?.running');
  });

  it('HomeScreen 确实挂了该组件（挡住接线被整行删除）', () => {
    const src = code(read('components/screens/home/HomeScreen.tsx'));
    expect(src).toContain('<MeshTunnelHealth />');
    // 与 TsExitWarning 是兄弟节点、排在其下方：两条说的是不同的事，不许合并或互相抑制。
    expect(src.indexOf('<MeshTunnelHealth />')).toBeGreaterThan(src.indexOf('<TsExitWarning />'));
  });

  it('判定复用现成组网谓词，不自造 allowInternet 弱判定', () => {
    const src = code(read('domain/mesh-tunnel-health.ts'));
    expect(src).toContain('isMeshNode');
    expect(src).toContain('meshAllowsInternet');
    expect(src).not.toMatch(/allowInternet\s*===\s*false/);
  });
});
