/**
 * 订阅自动更新的展示态单一真值。
 *
 * 后端调度器的门链是：订阅开关 × 全局总开关 × 全局间隔。这里逐项镜像
 * `runtime/subscription_scheduler.rs::select_due`，供订阅弹窗与节点信息栏共用；组件不得再各自
 * 猜一套，否则同一个开关会在两个位置显示成不同状态。
 */

export type SubAutoUpdateStatus =
  /** 订阅自己的开关关闭。 */
  | 'manual'
  /** 订阅开关开启，但全局总开关关闭。 */
  | 'master-off'
  /** 两级开关均开启，间隔为“仅手动”：只在应用启动时补更。 */
  | 'startup-only'
  /** 两级开关均开启，并按全局间隔周期刷新。 */
  | 'active';

/** 调度器缺省间隔（`subscription_scheduler.rs::DEFAULT_INTERVAL_HOURS`）。 */
export const SUB_DEFAULT_INTERVAL_HOURS = 12;

export interface SubAutoUpdateConfigLike {
  autoUpdateSubscriptionOnStart?: boolean;
  subscriptionUpdateIntervalHours?: number;
}

export function subAutoUpdateStatus(
  sub: { autoUpdate?: boolean },
  config: SubAutoUpdateConfigLike | null | undefined,
): SubAutoUpdateStatus {
  if (sub.autoUpdate !== true) return 'manual';
  // 后端严格要求 `Some(true)`；缺键不是开启。
  if (config?.autoUpdateSubscriptionOnStart !== true) return 'master-off';
  if (config?.subscriptionUpdateIntervalHours === 0) return 'startup-only';
  return 'active';
}

/**
 * 订阅弹窗需要披露的“调度 × 应用策略”组合。名称描述用户可观察到的行为，不把实现细节
 * `restartOnNodeChange` 直接泄漏到组件分支里。
 */
export type SubAutoUpdateNoticeMode =
  | 'hidden'
  | 'master-off'
  | 'startup-auto-apply'
  | 'startup-selective'
  | 'scheduled-auto-apply'
  | 'scheduled-selective';

export function subAutoUpdateNoticeMode(
  sub: { autoUpdate?: boolean },
  config: SubAutoUpdateConfigLike | null | undefined,
  applyAllNodeChanges: boolean,
): SubAutoUpdateNoticeMode {
  const status = subAutoUpdateStatus(sub, config);
  if (status === 'manual') return 'hidden';
  if (status === 'master-off') return 'master-off';
  if (status === 'startup-only') {
    return applyAllNodeChanges ? 'startup-auto-apply' : 'startup-selective';
  }
  return applyAllNodeChanges ? 'scheduled-auto-apply' : 'scheduled-selective';
}

/**
 * 周期徽标显示的有效小时数。非正数/非法值/缺省均与后端一样回落 12 小时；0 的状态由
 * `subAutoUpdateStatus` 表达成 `startup-only`，不会拿这个回落值冒充真实周期。
 */
export function subEffectiveIntervalHours(
  config: SubAutoUpdateConfigLike | null | undefined,
): number {
  const hours = config?.subscriptionUpdateIntervalHours;
  return typeof hours === 'number' && Number.isFinite(hours) && hours > 0
    ? hours
    : SUB_DEFAULT_INTERVAL_HOURS;
}
