import { invoke, listen } from '../ipc-client';
import { IPC_CHANNELS } from '../../domain/ipc-channels';
import type { OpenConnectBrowserCookieInput, OpenConnectBrowserHeaderInput, OpenConnectStatusEvent, OpenVpnStatusEvent, VpnStatusSnapshot } from '../../contracts/vpn-status';

export const vpnApi = {
  getStatus(): Promise<VpnStatusSnapshot> {
    return invoke(IPC_CHANNELS.VPN_GET_STATUS);
  },
  onOpenConnectStatus(listener: (data: OpenConnectStatusEvent) => void): () => void {
    return listen(IPC_CHANNELS.EVENT_OPENCONNECT_STATUS, listener);
  },
  onOpenVpnStatus(listener: (data: OpenVpnStatusEvent) => void): () => void {
    return listen(IPC_CHANNELS.EVENT_OPENVPN_STATUS, listener);
  },
  submitOpenConnectForm(
    serverId: string,
    challengeId: string,
    values: Record<string, string>
  ): Promise<void> {
    return invoke(IPC_CHANNELS.OPENCONNECT_SUBMIT_AUTH_FORM, { serverId, challengeId, values });
  },
  submitOpenConnectBrowser(
    serverId: string,
    challengeId: string,
    finalUrl: string,
    cookies: OpenConnectBrowserCookieInput[],
    headers: OpenConnectBrowserHeaderInput[]
  ): Promise<void> {
    return invoke(IPC_CHANNELS.OPENCONNECT_SUBMIT_AUTH_BROWSER, {
      serverId,
      challengeId,
      finalUrl,
      cookies,
      headers,
    });
  },
  cancelOpenConnect(serverId: string, challengeId: string): Promise<void> {
    return invoke(IPC_CHANNELS.OPENCONNECT_CANCEL_AUTH, { serverId, challengeId });
  },
  submitOpenVpn(
    serverId: string,
    challengeId: string,
    username: string,
    password: string,
    secret: string
  ): Promise<void> {
    return invoke(IPC_CHANNELS.OPENVPN_SUBMIT_CHALLENGE, {
      serverId,
      challengeId,
      username,
      password,
      secret,
    });
  },
  cancelOpenVpn(serverId: string, challengeId: string): Promise<void> {
    return invoke(IPC_CHANNELS.OPENVPN_CANCEL_CHALLENGE, { serverId, challengeId });
  },
};
