import type { UserConfig } from '@/contracts/types';

export type AppUpdateChannel = NonNullable<UserConfig['appUpdateChannel']>;

/** 缺省与非法存量值均按稳定版；持久化清洗在 Rust store 侧执行同一回落。 */
export function appUpdateIncludePrerelease(
  config: Pick<UserConfig, 'appUpdateChannel'> | null,
): boolean {
  return config?.appUpdateChannel === 'prerelease';
}
