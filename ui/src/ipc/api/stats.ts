import { invoke, listen, listenReady } from '../ipc-client';
import { IPC_CHANNELS } from '../../domain/ipc-channels';
import type { StatsTopic } from '../../domain/ipc-channels';
import { STATS_TOPIC_EVENT } from '../../domain/ipc-channels';
import type { TrafficStats } from '../../contracts/types';
import type {
  ConnectionsDetailUpdate,
  ConnectionsAggregate,
  ConnectionsClosedSnapshot,
  ConnectionsClosedUpdate,
} from '../../contracts/types';

// ============================================================================
// statsApi —— batch3 §3.7：订阅驱动数据面。
// 渲染端按 topic 声明订阅，后端据订阅集派生 worker demand + 精确 relay。
// ============================================================================

export const statsApi = {
  /** 订阅某 topic（stats|aggregate|detail|closed）：后端挂订阅 + 即回初始帧。 */
  async subscribe(topic: StatsTopic): Promise<void> {
    return invoke(IPC_CHANNELS.STATS_SUBSCRIBE, { topic });
  },

  /** 退订某 topic（unmount/窗口隐藏/暂停）：无订阅者 → worker 逐级停机。 */
  async unsubscribe(topic: StatsTopic): Promise<void> {
    return invoke(IPC_CHANNELS.STATS_UNSUBSCRIBE, { topic });
  },

  /** 在完整活动连接表上先过滤，再按首页画布槽位投影；空 query 即常态流向。 */
  async projectTopology(query: string, slots: number): Promise<ConnectionsAggregate> {
    return invoke(IPC_CHANNELS.STATS_PROJECT_TOPOLOGY, { query, slots });
  },

  /** stats topic：流量统计推送。 */
  onStatsUpdated(listener: (data: TrafficStats) => void): () => void {
    return listen<TrafficStats>(STATS_TOPIC_EVENT.stats, listener);
  },

  /** aggregate topic：连接导航的有界目标/出口排名。 */
  onConnectionsAggregate(
    listener: (data: ConnectionsAggregate) => void
  ): () => void {
    return listen<ConnectionsAggregate>(STATS_TOPIC_EVENT.aggregate, listener);
  },

  /** 完整活动表流向字段变化；常态/检索投影共用该信号。 */
  onConnectionsTopologyChangedReady(listener: () => void): Promise<() => void> {
    return listenReady<number>(IPC_CHANNELS.EVENT_CONNECTIONS_TOPOLOGY_CHANGED, listener);
  },

  /** detail topic：活动连接 reset 基线 + 常态增量。 */
  onConnectionsDetail(
    listener: (data: ConnectionsDetailUpdate) => void
  ): () => void {
    return listen<ConnectionsDetailUpdate>(STATS_TOPIC_EVENT.detail, listener);
  },

  /** closed topic：独立的已结束连接历史。 */
  onConnectionsClosed(
    listener: (data: ConnectionsClosedUpdate) => void
  ): () => void {
    return listen<ConnectionsClosedUpdate>(STATS_TOPIC_EVENT.closed, listener);
  },

  /** 清空已结束历史并设置重放水位。 */
  async clearClosed(): Promise<ConnectionsClosedSnapshot> {
    return invoke(IPC_CHANNELS.STATS_CLOSED_CLEAR);
  },
};
// ============================================================================
// connectionsApi —— §3.7：明细/聚合改订阅驱动；此处仅留关连接的命令式动作。
// ============================================================================

export const connectionsApi = {
  /** 关单条连接（后端经 9090 DELETE /connections/{id}）。 */
  async close(id: string): Promise<{ ok: boolean }> {
    return invoke(IPC_CHANNELS.CONNECTIONS_CLOSE, { id });
  },
  /** 关全部连接（后端经 9090 DELETE /connections，触发 ResetNetwork）。 */
  async closeAll(): Promise<{ ok: boolean }> {
    return invoke(IPC_CHANNELS.CONNECTIONS_CLOSE_ALL);
  },
};
