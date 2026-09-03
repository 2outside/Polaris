import { describe, expect, it } from 'vitest';
import type { TFunction } from 'i18next';
import type { DnsServerGroup, DnsServerResource } from '@/contracts/types';
import {
  buildDnsActionGroups,
  dnsActionChoice,
  dnsActionFromChoice,
} from './dns-action-options';

const t = ((key: string, values?: Record<string, unknown>) => {
  if (key === 'rules.dnsWorkspace.memberCount') return `${values?.count} members`;
  if (values?.id) return `${key}:${values.id}`;
  if (values?.name) return `${key}:${values.name}`;
  return key;
}) as TFunction;

const servers: DnsServerResource[] = [
  {
    id: 'direct-a',
    name: 'Direct A',
    enabled: true,
    type: 'https',
    endpoint: { host: '1.1.1.1', port: 443, path: '/dns-query' },
    outbound: { type: 'direct' },
  },
  {
    id: 'proxy-b',
    name: 'Proxy B',
    enabled: true,
    type: 'tls',
    endpoint: { host: '8.8.8.8', port: 853 },
    outbound: { type: 'currentExit' },
  },
  {
    id: 'hosts-a',
    name: 'Hosts A',
    enabled: false,
    type: 'hosts',
    outbound: { type: 'direct' },
  },
];

const groups: DnsServerGroup[] = [{
  id: 'race-a',
  name: 'Race A',
  enabled: true,
  mode: 'race',
  members: ['direct-a', 'proxy-b'],
}];

describe('buildDnsActionGroups', () => {
  it('按服务器组、服务器、Hosts、响应动作分组，并为混合出口组生成元信息', () => {
    const result = buildDnsActionGroups({ servers, groups, t, currentValue: 'group:race-a' });
    expect(result.map((group) => group.label)).toEqual([
      'rules.dnsActionGroupHeading',
      'rules.dnsActionServerHeading',
      'rules.dnsActionHostsHeading',
      'rules.dnsActionResponseHeading',
    ]);
    expect(result[0].options[0].description).toContain('rules.dnsActionMixedOutbound');
    expect(result[1].options.map((option) => option.value)).toEqual(['server:direct-a', 'server:proxy-b']);
    expect(result[2].options[0]).toMatchObject({ value: 'hosts:hosts-a', disabled: true });
  });

  it('fallback 复用同一构建器但排除 Hosts 与危险响应', () => {
    const result = buildDnsActionGroups({
      servers,
      groups,
      t,
      currentValue: 'server:direct-a',
      includeHosts: false,
      responses: ['fakeIp'],
    });
    expect(result.map((group) => group.label)).not.toContain('rules.dnsActionHostsHeading');
    expect(result[result.length - 1]?.options.map((option) => option.value)).toEqual(['fakeIp']);
  });

  it('当前引用缺失时保留不可用回显，不把值静默清空', () => {
    const result = buildDnsActionGroups({ servers, groups, t, currentValue: 'group:missing' });
    expect(result[0].options[result[0].options.length - 1]).toMatchObject({
      value: 'group:missing',
      disabled: true,
      label: 'rules.dnsActionMissingGroup:missing',
    });
  });
});

describe('DNS action choice codec', () => {
  it('Hosts 使用分组后备解析并保持可逆', () => {
    const action = dnsActionFromChoice('hosts:hosts-a', 'group:race-a');
    expect(action).toEqual({
      type: 'hostsFirst',
      hostsServerId: 'hosts-a',
      fallback: { type: 'group', groupId: 'race-a' },
    });
    expect(dnsActionChoice(action)).toBe('hosts:hosts-a');
  });

  it('拒绝可作为 Hosts miss 的明确后备动作', () => {
    expect(dnsActionFromChoice('hosts:hosts-a', 'reject')).toEqual({
      type: 'hostsFirst',
      hostsServerId: 'hosts-a',
      fallback: { type: 'reject', method: 'default' },
    });
  });
});
