import { invoke, listen } from '../ipc-client';
import { IPC_CHANNELS } from '../../domain/ipc-channels';
import type { IpInfoSnapshot } from '../../contracts/types';

// ============================================================================
// ipInfoApi
// ============================================================================

export const ipInfoApi = {
  /** 获取出口 IP 快照。force=强制重测；visible=手动重探可见流程。 */
  async get(force = false, visible = false): Promise<IpInfoSnapshot> {
    return invoke(IPC_CHANNELS.IP_INFO_GET, { force, visible });
  },

  /** 纯读当前快照（零探测）：窗口重建后 store 为空时水合状态栏。绝不触发探测。 */
  async peek(): Promise<IpInfoSnapshot> {
    return invoke(IPC_CHANNELS.IP_INFO_GET, { peek: true });
  },

  onUpdated(listener: (snap: IpInfoSnapshot) => void): () => void {
    return listen(IPC_CHANNELS.EVENT_IP_INFO_UPDATED, listener);
  },
};
