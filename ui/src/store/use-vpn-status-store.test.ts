import { beforeEach, describe, expect, it } from 'vitest';

import type { OpenConnectStatusEvent, OpenVpnStatusEvent } from '@/contracts/vpn-status';
import { useVpnStatusStore } from './use-vpn-status-store';

const openConnect = (serverId: string, challengeId = 'oc-1'): OpenConnectStatusEvent => ({
  serverId,
  state: 'auth-pending',
  stateText: 'Authentication required',
  authChallenge: {
    id: challengeId,
    kind: 'form',
    fields: [],
  },
});

const openVpn = (serverId: string, challengeId = 'ovpn-1'): OpenVpnStatusEvent => ({
  serverId,
  state: 'auth-pending',
  stateText: 'Authentication required',
  challenge: {
    id: challengeId,
    kind: 'credentials',
    echo: false,
    deadline: 0,
  },
});

beforeEach(() => {
  useVpnStatusStore.setState({ openConnect: {}, openVpn: {}, connected: false });
});

describe('native VPN status cache', () => {
  it('hydrates both rc.2 streams and replaces a repeated endpoint with its latest challenge', () => {
    const store = useVpnStatusStore.getState();
    store.replace(true, [openConnect('oc')], [openVpn('ovpn')]);
    expect(useVpnStatusStore.getState().connected).toBe(true);
    expect(useVpnStatusStore.getState().openConnect.oc?.authChallenge?.id).toBe('oc-1');
    expect(useVpnStatusStore.getState().openVpn.ovpn?.challenge?.id).toBe('ovpn-1');

    useVpnStatusStore.getState().setOpenConnect(openConnect('oc', 'oc-2'));
    expect(useVpnStatusStore.getState().openConnect.oc?.authChallenge?.id).toBe('oc-2');
  });

  it('configuration ownership removes deleted endpoints from both protocol caches', () => {
    useVpnStatusStore
      .getState()
      .replace(true, [openConnect('keep'), openConnect('drop')], [openVpn('drop')]);
    useVpnStatusStore.getState().retainServerIds(['keep']);

    expect(Object.keys(useVpnStatusStore.getState().openConnect)).toEqual(['keep']);
    expect(useVpnStatusStore.getState().openVpn).toEqual({});
  });

  it('an empty authoritative snapshot clears stale challenges', () => {
    useVpnStatusStore.getState().replace(true, [openConnect('oc')], [openVpn('ovpn')]);
    useVpnStatusStore.getState().replace(false, [], []);
    expect(useVpnStatusStore.getState().connected).toBe(false);
    expect(useVpnStatusStore.getState().openConnect).toEqual({});
    expect(useVpnStatusStore.getState().openVpn).toEqual({});
  });
});
