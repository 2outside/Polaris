import { invoke, listen } from '../ipc-client';
import { IPC_CHANNELS } from '../../domain/ipc-channels';
import type { ProxyStatus, ProxyErrorCode, SystemProxyStatus, InvalidNodeInfo, PendingNodeChanges, ProxyLifecycleEvent } from '../../contracts/types';
import type { TailscaleStatusEvent } from '../../contracts/tailscale-status';

// ============================================================================
// proxyApi
// ============================================================================

export const proxyApi = {
  /**
   * 启动内核。**无参 —— 起核用哪份配置由后端读盘决定**（因果全在 Rust `proxy_start` 头注）。
   *
   * 曾经收 `config: UserConfig` 并把渲染端的 `app-store.config` 传进去。那份内存副本只靠
   * `event:configChanged` → `loadConfig(true)` 异步刷新，于是「写盘 → 立刻点启动」会用**写之前**
   * 的配置起核。载荷还是有损的（`config_get` strip 了隐私密码哈希）。删参数比「让调用方记得先刷」
   * 可靠：调用方无从知道回声到没到。
   */
  async start(): Promise<void> {
    return invoke(IPC_CHANNELS.PROXY_START);
  },

  async stop(): Promise<void> {
    return invoke(IPC_CHANNELS.PROXY_STOP);
  },

  async getStatus(): Promise<ProxyStatus> {
    return invoke(IPC_CHANNELS.PROXY_GET_STATUS);
  },

  /**
   * 自定义协议兼容性 probe：当前内核能否识别该 outbound（sing-box check）。
   *
   * `error` 不再是 `sing-box check` stderr 的前 300 字符截断（旧行为，零结构化）——现在是后端
   * `parse_probe_diagnostic` 解析出的人类可读消息；`errorPath` 是配套解出的键路径（解析不出 → 该键
   * 整个不下发，不是空串，调用方须用 `?.`/`in` 判断，不能拿空串当「无路径」）；`errorRaw` 是完整原始
   * 输出（ANSI 已剥离），供兜底展示。三个新字段只在 `ok:false` 且非 `indeterminate` 时有意义。
   */
  async probeOutbound(
    outbound: unknown,
    isEndpoint?: boolean
  ): Promise<{
    ok: boolean;
    indeterminate?: boolean;
    error?: string;
    errorPath?: string;
    errorRaw?: string;
  }> {
    return invoke(IPC_CHANNELS.KERNEL_PROBE_OUTBOUND, { outbound, isEndpoint });
  },

  /** 用户主动清理系统代理残留设置（TUN 残留提示的一键恢复动作）。 */
  async disableSystemProxy(): Promise<{ ok: boolean }> {
    return invoke(IPC_CHANNELS.SYSTEM_PROXY_DISABLE);
  },

  /**
   * 系统代理**活态**查询：当前 OS 代理是否仍指向本进程的 mixed 入站（读 `pointsToUs`，
   * 别自己拿 `enabled` 判 —— 契约见 `SystemProxyStatus`）。
   *
   * 后端每次调用会 exec `networksetup`/`gsettings`/`reg`（mac 三次），**属有成本的查询**：
   * 调用方须低频、且只在 systemProxy 接管 + 核稳定运行（非 starting）+ 窗口可见时取
   *（见 App 顶层的 `useSystemProxyLivePolling`）。
   * 核未运行 / 读取受阻 → reject（**不返回 false**）：读不到 ≠ 没生效，调用方应折成「未知」而非「未生效」。
   */
  async getSystemProxyStatus(): Promise<SystemProxyStatus> {
    return invoke(IPC_CHANNELS.SYSTEM_PROXY_GET_STATUS);
  },

  /** §2 待应用差集（pull）：节点集相对运行核**起核快照**的增/改/删。核未运行 → 三个集合全空。 */
  async getPendingChanges(): Promise<PendingNodeChanges> {
    return invoke(IPC_CHANNELS.PROXY_GET_PENDING_CHANGES);
  },

  /** §2 动作条「立即应用」：把最新 config force-restart 入核。 */
  async applyPendingChanges(): Promise<{
    ok: boolean;
    status: 'applied' | 'deferred' | 'skipped';
  }> {
    return invoke(IPC_CHANNELS.PROXY_APPLY_PENDING_CHANGES);
  },

  /**
   * 代理已启动。**payload 恒为空对象**——后端 `commands/proxy.rs:41,76` emit `json!({})`。
   *
   * 此前这里声明了 `pid`/`startTime`/`autoRestarted` 三个字段，但后端从来不发 → 恒 undefined，
   * 属「契约声明了、后端没接」那一类死契约（本轮审计在 33 个事件常量里找到 16 条同类死通道）。
   * 删声明而非补后端：连接态的权威源是 `proxy:getStatus`（含 startTime/pid），事件只作**变更信号**，
   * 订阅方收到即重拉真值即可（见 App.tsx 的全局订阅层），无需 payload 复制一份易过期的快照。
   */
  onStarted(listener: () => void): () => void {
    return listen(IPC_CHANNELS.EVENT_PROXY_STARTED, listener);
  },

  /** 代理已停止。payload 恒为空对象（同 [`onStarted`]：事件是信号，真值走 getStatus）。 */
  onStopped(listener: () => void): () => void {
    return listen(IPC_CHANNELS.EVENT_PROXY_STOPPED, listener);
  },

  /** 主进程各 emit 点 payload 形状不一，message 优先 / error 兜底。 */
  onError(
    listener: (data: {
      message?: string;
      error?: string;
      errorCode?: ProxyErrorCode;
      code?: number;
      signal?: string | null;
    }) => void
  ): () => void {
    return listen(IPC_CHANNELS.EVENT_PROXY_ERROR, listener);
  },

  onAutoNodeSwitched(
    listener: (data: { reason: string; newServerName: string; latency: number }) => void
  ): () => void {
    return listen(IPC_CHANNELS.EVENT_AUTO_NODE_SWITCHED, listener);
  },

  /**
   * R2 待应用差集 PUSH：后端 `switch_mode` 末尾 emit `event:proxyPendingChanges`。
   *
   * 载荷类型**必须**是 [`PendingNodeChanges`] 本身，不能就地写一个结构型 —— 后端 pull/push
   * 返回的是同一个 `PendingChangesSummary`，前端这边再分裂出第二份形状，契约就又有了两个真值源
   * （`modified` 恒空那次退化正是这么长出来的）。
   */
  onPendingChanges(listener: (data: PendingNodeChanges) => void): () => void {
    return listen(IPC_CHANNELS.EVENT_PROXY_PENDING_CHANGES, listener);
  },

  /**
   * runtime 生命周期结局 PUSH：后端在**真状态跃迁点**发（`start_inner` 就绪 / `stop_inner` 拆除 /
   * `start` 包装的 Err 腿），覆盖 [`onStarted`]/[`onStopped`] 盖不住的全部后端自驱路径。
   *
   * 载荷只带「结局」这一位，**不带 pid / startTime** —— 那两个的权威源仍是 `proxy:getStatus`
   * （同 [`onStarted`] 头注那条既定结论：事件是变更信号，payload 不复制易过期的快照）。
   * 订阅方收到即重拉真值。
   */
  onLifecycle(listener: (data: ProxyLifecycleEvent) => void): () => void {
    return listen(IPC_CHANNELS.EVENT_PROXY_LIFECYCLE, listener);
  },

  /** 监听启动前配置校验 gate 剔除的非法节点（空数组=本次启动无非法节点/清陈旧标灰）。 */
  onInvalidNodes(listener: (data: InvalidNodeInfo[]) => void): () => void {
    return listen(IPC_CHANNELS.EVENT_PROXY_INVALID_NODES, listener);
  },

  /** 监听 Tailscale 交互登录 URL。 */
  onTailscaleAuth(
    listener: (data: {
      nodeName: string;
      url: string;
      transient?: boolean;
      serverId?: string;
    }) => void
  ): () => void {
    return listen(IPC_CHANNELS.EVENT_TAILSCALE_AUTH_URL, listener);
  },

  /** 监听 sing-box 1.14 管理 API 推送的 Tailscale 节点真实态。 */
  onTailscaleStatus(listener: (data: TailscaleStatusEvent) => void): () => void {
    return listen(IPC_CHANNELS.EVENT_TAILSCALE_STATUS, listener);
  },

  /** 监听「登录期出口让位」事件。 */
  onMeshLoginFallback(
    listener: (data: { engaged: boolean; serverName?: string }) => void
  ): () => void {
    return listen(IPC_CHANNELS.EVENT_MESH_LOGIN_FALLBACK, listener);
  },

  /** 监听 TUN 启动后的「无 marker 系统代理残留」提示。 */
  onSystemProxyResidual(listener: (data: { proxy: string }) => void): () => void {
    return listen(IPC_CHANNELS.EVENT_SYSTEM_PROXY_RESIDUAL, listener);
  },

  /** #40：非官方核 ≤ 随包基线 → 兼容风险提醒。 */
  onCoreBaselineWarning(
    listener: (data: { current: string; bundled: string; kind: string }) => void
  ): () => void {
    return listen(IPC_CHANNELS.EVENT_CORE_BASELINE_WARNING, listener);
  },
};
