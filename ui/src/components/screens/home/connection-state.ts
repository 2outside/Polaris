/**
 * 连接态判定 —— **按接管方式分叉**（契约「主页 Home」L17：
 * `TUN/manual = 仅看 proxyCore.running；systemProxy = running && proxy.enabled`）。
 *
 * # 为什么不能只看 `running`
 *
 * systemProxy 接管下，「核在跑」与「流量经核」是**两件事**：核起来了但 `networksetup`/`gsettings`/`reg`
 * 没把系统代理指向本地 mixed 入站时，全量流量仍是明文直连，而 UI 只看 `running` 会亮绿灯 —— 用户读到的
 * 「已连接」与真相相反。TUN/manual 没有这个分叉：TUN 靠路由表夺流量、manual 本就只提供本地端口
 * （用户自己在别处填），二者的「连上了」定义就是 `running`。
 *
 * # 两个信号，以及它们的主次
 *
 * ## 主：`systemProxyLive`（活态，地面真相）
 *
 * 后端 `system_proxy_get_status` 直接读 OS 的代理设置，与本进程 mixed 入站逐字比对
 * （`127.0.0.1:<mixedPort>`，比对**含端口** —— 指向别的代理 / 别的端口同样意味着流量没走我们），
 * 回 `pointsToUs`。它回答的是「**此刻**流量会不会经核」，而不是「历史上某一刻发生过什么」。
 *
 * ## 次：`errorCode`（起核那一刻的记录，仅作活态未知时的回落）
 *
 * `runtime/proxy.rs` 在 `enable_system_proxy` 失败/结果未知时落
 * `ProxyStatus.error_code = SYSTEM_PROXY_FAILED`（`set_nonfatal_error`，保留 `running:true`），
 * 成功起核会先把 `error_code` 清成 `None` → 不跨轮残留，读它判「本轮系统代理没设上」是诚实的。
 * 但它有两条**朝漏报**（绿灯 + 明文直连）的腿，且都不是前端能补的：
 *  1. **运行期**用户在系统设置里手动关掉/改掉代理 —— 起核那一刻是成功的，这个码干净；
 *  2. 它是**单槽**：起核后再来一条非终态错误（如 `RULE_RESOURCES_MISSING`），
 *     `set_nonfatal_error` 会把 `SYSTEM_PROXY_FAILED` 覆盖掉 → 降级态提前消失。
 * 活态查询对这两条是同一个根治（它不读那个槽，也不依赖任何历史记录），故一旦活态已知，
 * **它就是权威**，`errorCode` 不再参与判定。
 *
 * # 三态输入的方向性（为什么 `unknown` 回落而不是就地判降级）
 *
 * 活态查询在这些情形下拿不到结论：核未运行、非 GNOME 桌面（`gsettings` 无该 schema）、
 * PATH 缺 `reg.exe`、非 Tauri 环境（浏览器 dev）、首帧尚未取到。**读不到 ≠ 没生效** ——
 * 把这些折成「未生效」会让上述环境稳定误亮降级黄灯，故一律 `unknown` → 回落 `errorCode` 腿
 * （= 本次改动前的行为，不产生回归）。
 *
 * # 取数在哪（原 review-queue 条目 `home-screen-live-wiring`，已落地闭合）
 *
 * 活态的**唯一**取数点是 `store/use-system-proxy-live.ts`：轮询驱动
 * （`useSystemProxyLivePolling`）挂 `App.tsx` 顶层一处，结论存 store，`StatusBar` 与 `HomeScreen`
 * 各自 `useSystemProxyLive()` 读同一份。**两个组件各起一份轮询是明确禁止的**——每次查询都会 exec
 * `networksetup`/`gsettings`/`reg`（双倍开销），且两条链不同相时会出现「首页说未生效、状态栏还亮
 * 绿灯」这种自相矛盾。该纪律由 `store/system-proxy-live-wiring.test.ts` 的源码不变量守卫钉死。
 *
 * `systemProxyLive` 在本模块的入参上仍是**可选**（缺省 `unknown`）：那是给纯函数单测用的默认，
 * 不代表还有未接线的消费方。
 */

import { ProxyErrorCode, type ProxyModeType, type ProxyReachability } from '@/contracts/types';

/**
 * 三态：
 * - `connected`：按本接管方式的定义，流量确实在经核。
 * - `proxy-degraded`：**核在跑但流量没经核**（systemProxy 未生效）→ 必须与 connected 区分展示，
 *   否则就是审计里那条「绿灯 + 明文直连」的误导。
 * - `disconnected`：核未运行。
 */
export type TakeoverConnState = 'connected' | 'proxy-degraded' | 'disconnected';

/**
 * 系统代理**活态**三态（`system_proxy_get_status` 的 `pointsToUs` 折出来的）：
 * - `effective`：OS 代理仍指向本进程 mixed 入站 → 流量确实经核。
 * - `not-effective`：关了 / 指向别的代理 / 端口不是我们的 → 流量没经核。
 * - `unknown`：**没拿到结论**（核未运行 / 读取受阻 / 尚未取到 / 非 Tauri）→ 回落 `errorCode` 腿。
 *   注意与 `not-effective` 的分工：把「读不到」折进「未生效」会稳定误亮降级黄灯（见模块头）。
 */
export type SystemProxyLive = 'effective' | 'not-effective' | 'unknown';

export interface TakeoverConnInput {
  /** `proxyStatus.running`。 */
  running: boolean;
  /** `config.proxyModeType`；config 未水合时 undefined。 */
  proxyModeType: ProxyModeType | undefined;
  /** `proxyStatus.errorCode`（本轮起核的结构化码，成功起核已清空）。**仅作活态未知时的回落。** */
  errorCode: ProxyErrorCode | undefined;
  /** 活态判定（缺省 `unknown` = 未接线 → 保持接线前行为，见模块头 DESIGN-REVIEW）。 */
  systemProxyLive?: SystemProxyLive;
}

export function deriveTakeoverConnState({
  running,
  proxyModeType,
  errorCode,
  systemProxyLive = 'unknown',
}: TakeoverConnInput): TakeoverConnState {
  if (!running) return 'disconnected';
  // config 未水合 → 按 systemProxy 兜底（对齐 上游 `deriveConnectionStatus` 的
  // `configProxyModeType || ... || 'systemProxy'`）。只影响降级分支的**开启与否**：
  // 两个信号都干净时两条分支同样返 connected，故兜底不会凭空造出降级态。
  const mode = proxyModeType ?? 'systemProxy';
  if (mode !== 'systemProxy') return 'connected';
  // 活态已知 ⇒ 它是权威，`errorCode` 不再参与：
  //  - `not-effective` 直接判降级 —— 这条覆盖了 errorCode 测不出的两种形态（运行期手改 OS 设置、
  //    SYSTEM_PROXY_FAILED 被后来的非终态错误覆盖掉）；
  //  - `effective` 直接判已连接 —— 起核期的 SYSTEM_PROXY_FAILED 是「那一刻」的记录，而此刻
  //    OS 代理确实指向我们（用户手动补设 / 我们重试成功），继续挂降级就是拿陈旧记录压地面真相。
  if (systemProxyLive !== 'unknown') {
    return systemProxyLive === 'effective' ? 'connected' : 'proxy-degraded';
  }
  return errorCode === ProxyErrorCode.SYSTEM_PROXY_FAILED ? 'proxy-degraded' : 'connected';
}

/** 状态点/文案是否该按「已连接」呈现（degraded 不算 —— 这正是本模块存在的理由）。 */
export function isTrulyConnected(state: TakeoverConnState): boolean {
  return state === 'connected';
}

export type ExitReachabilityNotice = 'hidden' | 'unavailable';

/**
 * 主窗口常驻状态的语义态。这里不携带任何展示文案：组件只把枚举映射到 i18n key，避免状态判定
 * 与某一种语言、后端错误消息或协议名称耦合。
 *
 * 优先级由 [`deriveGlobalProxyStatus`] 唯一收口；状态栏等全局表面不得再各写一套 if/else。
 */
export type GlobalProxyStatus =
  | 'starting'
  | 'stopping'
  | 'proxy-unavailable'
  | 'disconnected'
  | 'takeover-degraded'
  | 'exit-blocked'
  | 'exit-unreachable'
  | 'connected';

export interface GlobalProxyStatusInput {
  proxyPhase: 'idle' | 'starting' | 'stopping';
  connState: TakeoverConnState;
  /** 选中项是否为配置中的真实节点；直连/阻断哨兵必须传 false。 */
  hasNode: boolean;
  proxyReachability: ProxyReachability | undefined;
  /** 核未运行时是否存在结构化失败结论；中性取消不应传 true。 */
  hasTerminalError: boolean;
}

/**
 * `ProxyStatus` 是否代表“核已停止且存在终态故障”。只读结构化错误码，不解析后端 message。
 *
 * 三个排除项都是明确的非故障终态：用户取消 Helper 引导、停止授权被取消、内核更新窗口拒绝操作。
 * 它们各有即时反馈，但不应把常驻状态永久染成“代理不可用”。其余码在 `running=false` 时才成立；
 * 运行期的接管/规则降级由更具体的状态处理。
 */
export function hasTerminalProxyError({
  running,
  errorCode,
}: {
  running: boolean;
  errorCode: ProxyErrorCode | undefined;
}): boolean {
  if (running || errorCode === undefined) return false;
  return ![
    ProxyErrorCode.HELPER_GATE_ABORTED,
    ProxyErrorCode.STOP_AUTH_CANCELLED,
    ProxyErrorCode.CORE_UPDATE_IN_PROGRESS,
  ].includes(errorCode);
}

/**
 * 常驻状态优先级：操作相位 > 核终态 > 接管地面真相 > 出口地面真相 > 已连接。
 *
 * `checking` / `unknown` 不代表失败；直连/阻断哨兵也没有“节点出口不可达”这一语义，因此只有
 * `hasNode=true` 时才消费出口探测终态。
 */
export function deriveGlobalProxyStatus({
  proxyPhase,
  connState,
  hasNode,
  proxyReachability,
  hasTerminalError,
}: GlobalProxyStatusInput): GlobalProxyStatus {
  if (proxyPhase === 'stopping') return 'stopping';
  if (proxyPhase === 'starting') return 'starting';
  if (connState === 'disconnected') {
    return hasTerminalError ? 'proxy-unavailable' : 'disconnected';
  }
  if (connState === 'proxy-degraded') return 'takeover-degraded';
  if (hasNode && proxyReachability === 'blocked') return 'exit-blocked';
  if (hasNode && proxyReachability === 'unreachable') return 'exit-unreachable';
  return 'connected';
}

/**
 * 首页代理出口提示门。只在「接管方式本身已生效 + 选中真实节点 + 出口探测明确失败」时显示；
 * 直连/阻断哨兵、检测中、未探测、系统代理未生效均不冒充节点故障。
 */
export function deriveExitReachabilityNotice({
  connected,
  hasNode,
  proxyReachability,
}: {
  connected: boolean;
  hasNode: boolean;
  proxyReachability: ProxyReachability | undefined;
}): ExitReachabilityNotice {
  return connected && hasNode && proxyReachability === 'unreachable' ? 'unavailable' : 'hidden';
}
