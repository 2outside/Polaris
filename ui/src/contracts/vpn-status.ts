/** OpenConnect / OpenVPN rc.2 原生 StartedService 状态与认证契约。 */

export interface OpenConnectFormChoice {
  value: string;
  label: string;
}

export interface OpenConnectFormField {
  submissionKey: string;
  name: string;
  label: string;
  kind: string;
  value: string;
  options: OpenConnectFormChoice[];
}

export interface OpenConnectBrowserRequest {
  url: string;
  finalURL?: string;
  cookieNames: string[];
  headerNames: string[];
  callbackURLPrefixes: string[];
  earlyCookieNames: string[];
  cacheID?: string;
}

export interface OpenConnectAuthChallenge {
  id: string;
  banner?: string;
  message?: string;
  error?: string;
  kind: 'form' | 'browser' | 'unknown';
  fields: OpenConnectFormField[];
  browser?: OpenConnectBrowserRequest;
}

export interface OpenConnectTunnelInfo {
  server: string;
  flavor: string;
  transport: string;
  ipv4: string[];
  ipv6: string[];
  dns: string[];
  mtu: number;
  connectedSince: number;
}

export interface OpenConnectStatusEvent {
  serverId: string;
  state: string;
  stateText: string;
  authChallenge?: OpenConnectAuthChallenge;
  error?: string;
  tunnelInfo?: OpenConnectTunnelInfo;
}

export interface OpenVpnChallenge {
  id: string;
  kind: string;
  username?: string;
  message?: string;
  url?: string;
  secretMessage?: string;
  echo: boolean;
  previousError?: string;
  deadline: number;
}

export interface OpenVpnTunnelInfo {
  server: string;
  network: string;
  ipv4: string[];
  ipv6: string[];
  dns: string[];
  mtu: number;
  connectedSince: number;
  cipher: string;
}

export interface OpenVpnStatusEvent {
  serverId: string;
  state: string;
  stateText: string;
  challenge?: OpenVpnChallenge;
  error?: string;
  tunnelInfo?: OpenVpnTunnelInfo;
}

export interface VpnStatusSnapshot {
  connected: boolean;
  openConnect: OpenConnectStatusEvent[];
  openVpn: OpenVpnStatusEvent[];
}

export interface OpenConnectBrowserCookieInput {
  name: string;
  value: string;
}

export interface OpenConnectBrowserHeaderInput {
  name: string;
  values: string[];
}
