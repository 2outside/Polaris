import type { UserConfig } from '@/contracts/types';

export type DnsConnectionResolution = 'preserveDomain' | 'dnsRules';

/**
 * 连接域名解析的跨 schema 读取口径。
 *
 * v4 的唯一真值是 dnsDefaults.connectionResolution。v2/v3 的 routeDefaults 与更早的
 * resolveBeforeDial 只服务迁移前配置/测试夹具，不能与新字段做 OR，否则 UI 关闭后旧字段仍会
 * 让内核解析。
 */
export function effectiveDnsConnectionResolution(
  config: Pick<
    UserConfig,
    'configSchemaVersion' | 'dnsDefaults' | 'routeDefaults' | 'resolveBeforeDial'
  >,
): DnsConnectionResolution {
  const schema = config.configSchemaVersion ?? 0;
  if (schema >= 4) {
    return config.dnsDefaults?.connectionResolution === 'dnsRules'
      ? 'dnsRules'
      : 'preserveDomain';
  }
  if (schema >= 2) {
    return config.routeDefaults?.destinationResolution === 'dnsRules'
      ? 'dnsRules'
      : 'preserveDomain';
  }
  return config.resolveBeforeDial === true ? 'dnsRules' : 'preserveDomain';
}

/** 只写 DNS 所有权下的 defaults，并保全服务器引用与未命中动作。 */
export function dnsConnectionResolutionPatch(
  config: Pick<UserConfig, 'dnsDefaults'>,
  resolution: DnsConnectionResolution,
): Pick<UserConfig, 'dnsDefaults'> {
  const defaults = config.dnsDefaults ?? {
    directServerId: 'builtin-domestic',
    proxyServerId: 'builtin-remote',
  };
  return {
    dnsDefaults: {
      ...defaults,
      connectionResolution: resolution,
    },
  };
}
