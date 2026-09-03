import type { SubscriptionErrorKind } from './subscription-preview';

/**
 * 订阅更新进度 —— `event:subscriptionUpdateProgress` 载荷的跨语言类型镜像。
 *
 * 后端真值：`src-tauri/src/commands/subscription.rs::perform_subscription_update`
 * （起手帧 + 终态帧）与 `fetch_parse_resolve` / `ProviderProgress`（provider 计数帧）。
 *
 * # 为什么是「阶段名 + provider 计数」，不是百分比
 *
 * 百分比要 `已收字节 / 总字节`。**分子这一半结构上不存在**：后端 `HttpClient::fetch` 返回的是
 * 已缓冲完的整个响应体（SSRF / 重定向 / 体积三道 guard 都建立在「整体收完再判」上），拿到它时
 * 下载已经结束，中途没有可数的字节流。分母（`content-length` 响应头）倒是有，但只有分母的百分比
 * 不是百分比。同仓 `commands/rules.rs` 的资源下载进度早已按同一理由报 `percent: null`。
 *
 * 且即便把传输层改成流式也不该用百分比：订阅正文典型几十 KB，耗时几乎全在 TTFB（DNS + TLS +
 * 机场服务端现场生成配置）—— 进度条会在 0% 冻十几秒再瞬间跳满，比没有进度条更误导。
 *
 * 唯一真有量的地方是 Clash `proxy-providers` 的并发子拉取（可数、每个最长 15s），
 * 那里按真实完成数给 `done/total`。
 */

/**
 * 一次订阅更新的阶段。前三个是过程态，后三个是**终态**（互斥，一次更新恰好收到一个）。
 *
 * - `fetching`   拉取主订阅正文（最长 30s，绝大多数时间在这）。解析正文也归在本阶段：它是
 *                毫秒级的，单开一个一闪而过的「解析中」只是噪声，不改变用户的下一步动作。
 * - `providers`  Clash proxy-providers 并发拉取，带真实完成计数 `done/total`。
 * - `reconciling` 对账 + 落盘 + 广播运行配置变更信号。它不承诺变更已进入运行内核：后续可能
 *                 热切换、重启或留在待应用差集。与 `fetching` 分开是因为卡在这里意味着本地
 *                 磁盘/配置问题，而不是「机场不通」。
 * - `done` / `unchanged` / `failed`  终态。
 */
export type SubscriptionUpdatePhase =
  | 'fetching'
  | 'providers'
  | 'reconciling'
  | 'done'
  | 'unchanged'
  | 'failed';

/** `event:subscriptionUpdateProgress` 载荷。可选字段按 phase 出现（见各字段注释）。 */
export interface SubscriptionUpdateProgress {
  subscriptionId: string;
  phase: SubscriptionUpdatePhase;
  /** `providers`：**已完成**的 provider 数（第一条子拉取发起时报 0，之后每条 settle 递增）。 */
  done?: number;
  /** `providers`：本次会拉的 provider 数**上界**（声明数 ∩ 后端上限 8；非法条目会被跳过 ⇒ done 可能停在 total 之下）。 */
  total?: number;
  /** `done`：本次对账的节点增/改/删数。 */
  added?: number;
  updated?: number;
  deleted?: number;
  /** `failed`：后端的脱敏诊断；分类为 unknown/旧载荷时供 tooltip 准确兜底。 */
  error?: string;
  /** `failed`：后端在抛出点确定的分类；渲染端优先据此取 i18n 详情，不按文案反猜。 */
  errorKind?: SubscriptionErrorKind;
  /** `errorKind='http'` 时的状态码。 */
  httpStatus?: number;
}

/** 终态 phase（收到即本轮结束）。 */
export const SUBSCRIPTION_UPDATE_TERMINAL_PHASES = ['done', 'unchanged', 'failed'] as const;

/** 该帧是否是终态。 */
export function isSubscriptionUpdateTerminal(phase: SubscriptionUpdatePhase): boolean {
  return (SUBSCRIPTION_UPDATE_TERMINAL_PHASES as readonly string[]).includes(phase);
}
