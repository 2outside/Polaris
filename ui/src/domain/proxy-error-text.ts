/**
 * 代理错误码 → 用户可见文案的唯一解析点。
 *
 * 跨进程负载中的 `message` 是日志诊断：可能包含 Rust 中文、OS 原文、路径、PID 或核心
 * stderr，不得直接渲染。用户文案只由稳定 `errorCode` 选择 locale；新/未知码在映射表
 * 完成前 fail-safe 到通用本地化失败句。五语完整性与 Rust 码集对账由
 * `contracts/proxy-error-key-coverage.test.ts` 锁定。
 */

/** `t(key, fallback?)` 的最小结构。 */
export type ProxyErrorTranslate = (key: string, fallback?: string) => string;

/** `ProxyErrorEvent` 与 `ProxyLifecycleEvent` 的公共子集。 */
export interface ProxyErrorTextInput {
  errorCode?: string;
  /** 仅为 wire 兼容/诊断保留；本模块刻意不读取。 */
  message?: string;
}

/** Rust `runtime/proxy.rs::code` 的全量用户可见映射。 */
export const PROXY_ERROR_TEXT_KEY: Readonly<Record<string, string>> = {
  STARTUP_FAILED: 'errors.startupFailed',
  PROCESS_EXITED: 'home.proxyCrashed',
  AUTO_RESTART_FAILED: 'home.proxyCrashed',
  HELPER_NOT_INSTALLED: 'errors.helperNotInstalledDesc',
  ROOT_ORPHAN_BLOCKED: 'errors.rootOrphanBlocked',
  SYSTEM_PROXY_FAILED: 'home.proxyMisdirected',
  SYSTEM_DNS_TAKEOVER_FAILED: 'errors.systemDnsTakeoverFailed',
  EXIT_MISMATCH: 'home.proxyMisdirected',
  CORE_BINARY_MISMATCH: 'errors.coreBinaryMismatch',
  RULE_RESOURCES_MISSING: 'home.ruleResourcesMissing',
  AUTO_SWITCH_NEEDS_RESTART: 'errors.autoSwitchNeedsRestart',
  OUTBOUND_INTERFACE_UNAVAILABLE: 'errors.outboundInterfaceUnavailable',
  HELPER_GATE_ABORTED: 'errors.helperGateAborted',
  TUN_ROUTE_NOT_CAPTURED: 'errors.tunRouteNotCaptured',
  TUN_ADAPTER_MISSING: 'errors.tunAdapterMissing',
  TUN_ADDRESS_UNAVAILABLE: 'errors.tunAddressUnavailable',
};

/** 命中稳定码返回译文；未知/缺码返回 `null`，不渲染诊断 `message`。 */
export function proxyErrorReason(
  data: ProxyErrorTextInput,
  t: ProxyErrorTranslate
): string | null {
  const code = data.errorCode;
  if (code !== undefined && Object.prototype.hasOwnProperty.call(PROXY_ERROR_TEXT_KEY, code)) {
    return t(PROXY_ERROR_TEXT_KEY[code]);
  }
  return null;
}

/** toast 等必须有文字的出口：未知/缺码落五语通用失败句。 */
export function proxyErrorText(data: ProxyErrorTextInput, t: ProxyErrorTranslate): string {
  return proxyErrorReason(data, t) ?? t('errors.operationFailed');
}
