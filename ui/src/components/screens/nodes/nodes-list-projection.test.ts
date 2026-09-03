import { describe, expect, it } from 'vitest';
import type { ServerConfig } from '@/contracts/types';
import type { ServerGroup } from '@/domain/server-grouping';
import { projectVisibleServers } from './nodes-list-projection';

const server = (id: string, patch: Partial<ServerConfig> = {}): ServerConfig =>
  ({ id, name: id, protocol: 'vmess', address: `${id}.example`, port: 443, ...patch }) as ServerConfig;

const group = (servers: ServerConfig[]): ServerGroup => ({
  id: 'manual',
  name: 'manual',
  isManual: true,
  servers,
});

describe('projectVisibleServers', () => {
  it('filters by search and protocol before sorting', () => {
    const nodes = [
      server('zeta', { protocol: 'vless' }),
      server('alpha', { protocol: 'vmess' }),
      server('beta', { protocol: 'vless' }),
    ];

    expect(projectVisibleServers(group(nodes), 'beta', 'vless', 'name', {})).toEqual([nodes[2]]);
  });

  it('sorts latency with missing measurements delegated to the domain comparator', () => {
    const nodes = [server('slow'), server('missing'), server('fast')];

    expect(
      projectVisibleServers(group(nodes), '', '', 'lat', { slow: 200, fast: 20 }),
    ).toEqual([nodes[2], nodes[0], nodes[1]]);
  });
});
