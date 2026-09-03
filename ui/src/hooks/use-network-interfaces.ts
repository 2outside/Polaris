import { useCallback, useEffect, useState } from 'react';
import type { NetworkInterfaceInfo } from '@/contracts/types';
import { systemApi } from '@/ipc/api-client';

let cached: NetworkInterfaceInfo[] | null = null;
let inFlight: Promise<NetworkInterfaceInfo[]> | null = null;

async function load(force: boolean): Promise<NetworkInterfaceInfo[]> {
  if (!force && cached) return cached;
  if (!force && inFlight) return inFlight;
  inFlight = systemApi.listNetworkInterfaces().then((items) => {
    cached = items;
    return items;
  }).finally(() => {
    inFlight = null;
  });
  return inFlight;
}

/** 统一的网卡枚举读模型：设置、订阅和节点表单共享同一份缓存与刷新行为。 */
export function useNetworkInterfaces() {
  const [items, setItems] = useState<NetworkInterfaceInfo[]>(cached ?? []);
  const [loading, setLoading] = useState(cached == null);
  const [failed, setFailed] = useState(false);

  const refresh = useCallback(async (force = true) => {
    setLoading(true);
    setFailed(false);
    try {
      setItems(await load(force));
    } catch {
      setFailed(true);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh(false);
  }, [refresh]);

  return { items, loading, failed, refresh };
}

export function interfaceExists(items: readonly NetworkInterfaceInfo[], name: string | undefined) {
  return !name || items.some((item) => item.name === name);
}

export interface NetworkInterfaceChoice {
  value: string;
  label: string;
  disabled?: boolean;
}

/**
 * 网卡下拉的单一展示投影。设置、订阅及所有节点编辑器共用，避免「某处标 down、某处仍可选」漂移。
 * 未知存量值保留为禁用项，让用户看得见并能主动改掉；不会把它伪装成自动选择。
 */
export function buildNetworkInterfaceChoices(
  items: readonly NetworkInterfaceInfo[],
  current: string | undefined,
  labels: {
    defaultLabel: string;
    unavailable: (name: string) => string;
    down: string;
  },
): NetworkInterfaceChoice[] {
  const value = current?.trim() ?? '';
  return [
    { value: '', label: labels.defaultLabel },
    ...(!interfaceExists(items, value)
      ? [{ value, label: labels.unavailable(value), disabled: true }]
      : []),
    ...items.map((item) => ({
      value: item.name,
      label: `${item.displayName === item.name ? item.name : `${item.displayName} · ${item.name}`}${item.isUp ? '' : ` · ${labels.down}`}`,
      disabled: !item.isUp,
    })),
  ];
}
