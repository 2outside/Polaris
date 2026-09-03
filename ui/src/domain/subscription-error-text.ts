/** 订阅错误 → 用户当前语种详情。结构化分类优先；诊断只留在 IPC/log，不进用户界面。 */
import {
  SUBSCRIPTION_ERROR_I18N_KEY,
  type SubscriptionErrorKind,
} from '@/contracts/subscription-preview';

export type SubscriptionErrorTranslate = (
  key: string,
  options?: Record<string, string | number>
) => string;

export interface SubscriptionErrorTextInput {
  errorKind?: SubscriptionErrorKind;
  httpStatus?: number;
  /** 更新结果/进度事件沿用 `error`；预检结果沿用 `message`。两者都必须已在后端脱敏。 */
  error?: string;
  message?: string;
}

/**
 * 已知（含 unknown）分类一律走 i18n；旧载荷或无分类才走调用方 i18n 兜底。
 * `error` / `message` 可继续留在 IPC 与日志帮助排障，但不能成为跨语种的用户文案。
 */
export function subscriptionErrorDetail(
  data: SubscriptionErrorTextInput,
  t: SubscriptionErrorTranslate,
  fallbackKey = 'nodes.subRefreshFail'
): string {
  const kind = data.errorKind;
  if (kind !== undefined && Object.prototype.hasOwnProperty.call(SUBSCRIPTION_ERROR_I18N_KEY, kind)) {
    return t(SUBSCRIPTION_ERROR_I18N_KEY[kind].detail, {
      status: data.httpStatus ?? '',
    });
  }
  return t(fallbackKey);
}
