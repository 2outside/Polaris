import { create } from 'zustand';
import type { OpenConnectStatusEvent, OpenVpnStatusEvent } from '@/contracts/vpn-status';

interface VpnStatusStore {
  openConnect: Record<string, OpenConnectStatusEvent | undefined>;
  openVpn: Record<string, OpenVpnStatusEvent | undefined>;
  connected: boolean;
  setConnected: (connected: boolean) => void;
  setOpenConnect: (event: OpenConnectStatusEvent) => void;
  setOpenVpn: (event: OpenVpnStatusEvent) => void;
  replace: (connected: boolean, openConnect: OpenConnectStatusEvent[], openVpn: OpenVpnStatusEvent[]) => void;
  retainServerIds: (serverIds: readonly string[]) => void;
}

function byServerId<T extends { serverId: string }>(events: readonly T[]): Record<string, T> {
  return Object.fromEntries(events.filter((event) => event.serverId).map((event) => [event.serverId, event]));
}

export const useVpnStatusStore = create<VpnStatusStore>((set) => ({
  openConnect: {},
  openVpn: {},
  connected: false,
  setConnected: (connected) => set({ connected }),
  setOpenConnect: (event) =>
    event.serverId
      ? set((state) => ({ openConnect: { ...state.openConnect, [event.serverId]: event } }))
      : undefined,
  setOpenVpn: (event) =>
    event.serverId
      ? set((state) => ({ openVpn: { ...state.openVpn, [event.serverId]: event } }))
      : undefined,
  replace: (connected, openConnect, openVpn) =>
    set({ connected, openConnect: byServerId(openConnect), openVpn: byServerId(openVpn) }),
  retainServerIds: (serverIds) =>
    set((state) => {
      const keep = new Set(serverIds);
      return {
        openConnect: Object.fromEntries(Object.entries(state.openConnect).filter(([id]) => keep.has(id))),
        openVpn: Object.fromEntries(Object.entries(state.openVpn).filter(([id]) => keep.has(id))),
      };
    }),
}));
