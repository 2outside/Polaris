import { invoke, listen } from '../ipc-client';
import { IPC_CHANNELS } from '../../domain/ipc-channels';
import type { ServerConfig } from '../../contracts/types';
import type { WarpWireGuardDraft } from '../../domain/warp';
import type { TailscaleStatusSnapshot } from '../../contracts/tailscale-status';
import type { TaildropInbox, TaildropSaveResult, TaildropSendResult, TaildropTaskSnapshot } from '../../contracts/taildrop';
import type { SpeedTestDonePayload, SpeedTestInvokeResult } from '../../contracts/speed-test';

// ============================================================================
// serverApi
// ============================================================================

export const serverApi = {
  /**
   * 新增节点。**返回 void，不回传新建节点** —— 后端 `server_add`（`commands/server.rs:69`）返
   * `ApiResponse<()>`。
   *
   * 此前这里声明 `Promise<ServerConfig>` 是**类型谎言**：运行期拿到的恒是 undefined，任何
   * 「add 完取回 id」的写法都会静默拿到 undefined（TsLoginDialog 就踩过，改走渲染端自带 id）。
   * 要新建节点的 id → 渲染端自己 mint（`crypto.randomUUID()`）后放进 server：后端 `ensure_server_id`
   * 只在 id 缺失/空串时才 mint，**非空 id 原样保留**（其单测名即 `..._keeps_existing`）。
   */
  async add(server: Omit<ServerConfig, 'id'> | ServerConfig): Promise<void> {
    // Rust server_add(server: Value) —— 参数袋 key = `server`。
    return invoke(IPC_CHANNELS.SERVER_ADD, { server });
  },

  /** 批量添加自建节点（本地导入，一次写盘） */
  async addBulk(servers: ServerConfig[]): Promise<{ added: number }> {
    return invoke(IPC_CHANNELS.SERVER_ADD_BULK, { servers });
  },

  async update(server: ServerConfig): Promise<void> {
    // Rust server_update(server: Value) —— 参数袋 key = `server`。
    return invoke(IPC_CHANNELS.SERVER_UPDATE, { server });
  },

  /**
   * 即时删除服务器。只供停核运行或暂存功能关闭时的兼容腿；运行中所有协议都先暂存，
   * TS state/WARP 注销等副作用由 Apply 的持久删除事务执行。
   * fallbackSelectedId：删的是当前选中节点时的兜底出口（最快剩余盘上节点）；后端据此把
   * selectedServerId 置兜底并广播。
   */
  async delete(serverId: string, fallbackSelectedId?: string | null): Promise<void> {
    return invoke(IPC_CHANNELS.SERVER_DELETE, { serverId, fallbackSelectedId });
  },

  /** 批量删除服务器（一次配置写，避免并发单删竞态）。返回实际删除数。 */
  async deleteBatch(
    serverIds: string[],
    fallbackSelectedId?: string | null
  ): Promise<number> {
    return invoke(IPC_CHANNELS.SERVER_DELETE_BATCH, {
      serverIds,
      fallbackSelectedId,
    });
  },

  /** Phase 2 按需登录：拉起瞬态登录核取交互登录 URL。 */
  async tailscaleLogin(server: ServerConfig): Promise<{
    started: boolean;
    reason?: 'alreadyLoggedIn' | 'inMainCore' | 'alreadyRunning';
    authUrl?: string;
  }> {
    return invoke(IPC_CHANNELS.TAILSCALE_LOGIN, { server });
  },

  /** 取消某节点在飞的瞬态登录核（用户手动取消）。 */
  async tailscaleLoginCancel(serverId: string): Promise<void> {
    return invoke(IPC_CHANNELS.TAILSCALE_LOGIN_CANCEL, { serverId });
  },

  /** 退出登录：清该节点 Tailscale 持久登录会话（state 目录）。 */
  async tailscaleLogout(serverId: string): Promise<{ runningNeedsRestart: boolean }> {
    return invoke(IPC_CHANNELS.TAILSCALE_LOGOUT, { serverId });
  },

  /** 批量查 TS 节点 state 目录存在性（不起核判「登录过没」）。 */
  async tailscaleStateExists(serverIds: string[]): Promise<Record<string, boolean>> {
    return invoke(IPC_CHANNELS.TAILSCALE_STATE_EXISTS, { serverIds });
  },

  /** L2：主动拉各 TS 节点状态末帧(self IP/peers) + 新鲜度(connected)。 */
  async tailscaleGetStatus(): Promise<TailscaleStatusSnapshot> {
    return invoke(IPC_CHANNELS.TAILSCALE_GET_STATUS);
  },

  /** 读一次该 TS 节点的 Taildrop 收件箱（首帧快照）。失败抛 `IpcError`，`code` 见 `domain/taildrop.ts`。 */
  async taildropList(serverId: string): Promise<TaildropInbox> {
    return invoke(IPC_CHANNELS.TAILDROP_LIST, { serverId });
  },

  /** 清未读角标。**不删文件** —— 待处理数不变。 */
  async taildropMarkRead(serverId: string): Promise<void> {
    return invoke(IPC_CHANNELS.TAILDROP_MARK_READ, { serverId });
  },

  /** 删除收件箱里的一个文件。 */
  async taildropDelete(serverId: string, name: string): Promise<void> {
    return invoke(IPC_CHANNELS.TAILDROP_DELETE, { serverId, name });
  },

  /** 取消一个接收中的文件。`senderId` + `name` 必须成对（同名文件可来自不同发件人）。 */
  async taildropCancel(serverId: string, senderId: string, name: string): Promise<void> {
    return invoke(IPC_CHANNELS.TAILDROP_CANCEL, { serverId, senderId, name });
  },

  /** 发件：后端开原生多文件选择框，经指定 peer stableID 发送。 */
  async taildropSend(serverId: string, peerStableId: string): Promise<TaildropSendResult> {
    return invoke(IPC_CHANNELS.TAILDROP_SEND, { serverId, peerStableId });
  },

  /** 有界发件任务快照。省略 serverId 用于主窗口重建时水合全部任务。 */
  async taildropTasks(serverId?: string): Promise<TaildropTaskSnapshot[]> {
    return invoke(IPC_CHANNELS.TAILDROP_TASKS, { serverId: serverId ?? null });
  },

  /** taskId 定位的发件取消；重复取消终态任务幂等返回原快照。 */
  async taildropTaskCancel(taskId: string): Promise<TaildropTaskSnapshot> {
    return invoke(IPC_CHANNELS.TAILDROP_TASK_CANCEL, { taskId });
  },

  onTaildropTaskUpdated(listener: (snapshot: TaildropTaskSnapshot) => void): () => void {
    return listen(IPC_CHANNELS.EVENT_TAILDROP_TASK_UPDATED, listener);
  },

  /** 取件：后端开原生保存框再写盘。`canceled:true` = 用户取消，**不是失败**。 */
  async taildropSave(serverId: string, name: string): Promise<TaildropSaveResult> {
    return invoke(IPC_CHANNELS.TAILDROP_SAVE, { serverId, name });
  },

  async switch(serverId: string): Promise<void> {
    return invoke(IPC_CHANNELS.SERVER_SWITCH, { serverId });
  },

  async generateUrl(server: ServerConfig): Promise<string> {
    return invoke(IPC_CHANNELS.SERVER_GENERATE_URL, { server });
  },

  /** Cloudflare WARP：注册匿名设备 → 返回 WireGuard 草稿。 */
  async registerWarp(licenseKey?: string): Promise<WarpWireGuardDraft> {
    return invoke(IPC_CHANNELS.WARP_REGISTER, { licenseKey });
  },

  /** 对已注册 WARP 节点原地应用 WARP+ license（升级免重建）。 */
  async applyWarpLicense(
    serverId: string,
    license: string
  ): Promise<{ ok: boolean; warpPlus?: boolean; error?: string }> {
    return invoke(IPC_CHANNELS.WARP_APPLY_LICENSE, { serverId, license });
  },

  /** 测试指定服务器延迟，不传则测试所有服务器。 */
  async speedTest(serverIds?: string[]): Promise<SpeedTestInvokeResult> {
    return invoke(IPC_CHANNELS.SERVER_SPEED_TEST, { serverIds });
  },

  /** 订阅测速单个节点完成事件（流式增量显示，不等队列）。 */
  onSpeedTestResult(
    listener: (data: { serverId: string; latency: number }) => void
  ): () => void {
    return listen(IPC_CHANNELS.EVENT_SPEED_TEST_RESULT, listener);
  },

  /** 订阅测速进度事件（已测/成功/总数）。 */
  onSpeedTestProgress(
    listener: (data: { tested: number; ok: number; total: number }) => void
  ): () => void {
    return listen(IPC_CHANNELS.EVENT_SPEED_TEST_PROGRESS, listener);
  },

  /**
   * 订阅一轮测速的**终态**（`{outcome,tested,total,serverIds,pending}`）。
   *
   * 广播通道 ⇒ **不管是谁发起的**（主窗 / 托盘浮层）都收得到。进度 toast 的终态判定以它为主路径，
   * 静默超时降级为纯兜底。载荷语义见 `contracts/speed-test.ts` 的 `SpeedTestDonePayload`。
   */
  onSpeedTestDone(listener: (data: SpeedTestDonePayload) => void): () => void {
    return listen(IPC_CHANNELS.EVENT_SPEED_TEST_DONE, listener);
  },
};
