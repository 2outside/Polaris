/**
 * 「只走内网的组网节点」隧道健康判定（纯函数，首页行内注脚用）。**只上报，不切换。**
 *
 * # 为什么必须有这一条（根因）
 *
 * 自动故障切换（`src-tauri/src/runtime/auto_switch.rs` 的 `auto_switch_blocked_for_generation`）对
 * **只走内网的组网节点**整条跳过心跳：那个内网只有这条隧道能到，切到别的节点换不来它，
 * 「切换」在定义上不可能是对的。该决定本身没错，但它的代价是**这类节点的隧道健康从此完全没有
 * 探测** —— 隧道真挂了也没有任何一处会说话。本判定补的就是这个洞：把 renderer 手里**已有**的
 * 运行态信号翻译成一句话，出现在首页出口行下方。零 IPC / 零 store / 零 Rust 事件。
 *
 * 与 `tailscale-exit-warning.ts` 严格正交，故不并进那条链：
 *  - `deriveTsExitWarning` 回答「出口名不副实」——**公网**出不出得去；
 *  - 本函数回答「隧道通不通」——**内网**到不到得了。
 * 两条同时成立是常态（TS 未设出口设备 ⇒ 恒亮那条，且它的内网也可能同时是断的），
 * 故本条**不抑制** `NoExitDevice`，只排在它下方、用不同图标区分。
 *
 * # 三档信号面（2026-09-03 核对，仓内可得性）
 *
 *  - **Tailscale**：`store/app-store.ts` 的 `tailscaleStatuses[serverId]` 末帧，
 *    `expired` / `backendState` / `peers[].online` 三个位都在 renderer 手里。
 *  - **OpenVPN**：`store/use-vpn-status-store.ts` 的 `openVpn[id]`，契约见 `contracts/vpn-status.ts`。
 *    该事件此前**零渲染**（唯一消费方 `VpnAuthDialog` 只读 challenge），本条是它的第一个状态消费点。
 *  - **OpenConnect**：不设信号腿 —— `endpoint-routes.ts` 的 `meshAllowsInternet` 对 openconnect
 *    恒 `true`（`default: true` 分支），下面的总门必挡下它，`case 'openconnect'` 是不可达死代码，故删。
 *    若 `endpoint_routes` 未来给 openconnect 补了 `allowInternet` 语义，这里要同步补回分支。
 *  - **WireGuard**：**没有任何运行态信号**。sing-box 1.14 管理 API 无 WG peer / 握手 rpc，
 *    仓内两处显式声明：`src-tauri/src/runtime/proxy/third_party_vpn.rs:116` 与
 *    `components/hover-cards/MeshInfoHoverCard.tsx:25-28`。故它落 `unprobeable` ——
 *    **把「没有观测」这件事本身报出来**，而不是伪造一个健康位。同 MeshInfoHoverCard
 *    「拿不到的字段一行都不画、不摆恒为『—』的位」的既定处置。
 *
 * # 两道总门（缺一必误报）
 *
 *  1. **只走内网**：`isMeshNode(s) && !meshAllowsInternet(s)`，直接复用 `endpoint-routes.ts` 的
 *     现成谓词。**不得自造 `allowInternet === false`** —— 本仓已为那条弱判定记过一次过
 *     （`components/screens/nodes/nodes-logic.ts` 头注 #3：漏 reverseMesh 的 WG 与整条 TS 腿）。
 *  2. **新鲜度**：`!proxyRunning ⇒ none`。核没跑时手里的都是缓存末帧，据陈旧快照报「隧道挂了」
 *     是误报。口径与 `tailscale-exit-warning.ts:80` 一致。
 *
 * # 判据取舍（两条刻意不做的）
 *
 *  - **TS 的 `peers.length === 0` 返 `none`，不算「全离线」**：空 peers = 这一帧根本没带对端信息
 *    （未登录 / 刚起核），不是「一台都不在线」。先例 `MeshInfoHoverCard.tsx:82-87` 同一判据同一理由。
 *  - **OVPN/OC 不按 `state` 字符串判**：该字段的值域本仓无登记（proto 只声明 `string state`，
 *    仓内唯一样本是单测夹具 `"auth-pending"`），按它判就是猜字符串。只用 `error` 是否非空
 *    （**当布尔位用，原文不入 UI** —— 同 `contracts/proxy-error-key-coverage.test.ts` 的 raw 零容忍）
 *    与 `tunnelInfo` 在不在（在 = 隧道参数已下发 = 连上了）。
 *
 * # 射程之外
 *
 *  - 事件整个缺席（该 id 在两个 store 里都没有条目）⇒ `none`：无帧=不知道，不猜，
 *    与 TS 那腿「无帧不报」同口径。
 *  - **不判「内网 IP 能不能 ping 通」**：那需要真发探测包（新 IPC + 新 Rust 腿），
 *    与本条「只用现有信号」的边界相反。这里报的是控制面/隧道层面的状态，不是端到端连通性。
 */
import type { ServerConfig } from '../contracts/types';
import type { TailscaleStatusEvent } from '../contracts/tailscale-status';
import type { OpenVpnStatusEvent } from '../contracts/vpn-status';
import { isMeshNode, meshAllowsInternet } from './endpoint-routes';

export type MeshTunnelHealth =
  | 'none'
  /** TS：控制面说这份凭据已过期 ⇒ 隧道已经或即将不通。 */
  | 'ts-expired'
  /** TS：后端未处于 Running ⇒ 隧道尚未就绪。 */
  | 'ts-not-running'
  /** TS：有对端信息，且其中没有一台在线 ⇒ 内网此刻无处可达。 */
  | 'ts-peers-offline'
  /** OVPN/OC：状态事件带了错误 ⇒ 连接出了问题（错误原文不进 UI，只当布尔位）。 */
  | 'vpn-error'
  /** OVPN/OC：没有隧道参数 ⇒ 尚未连上。 */
  | 'vpn-disconnected'
  /** WireGuard：**没有任何运行态信号源**，把「无法探测」本身报出来。 */
  | 'unprobeable';

export interface MeshTunnelHealthInput {
  /** 当前选中的全局出口节点（config.selectedServerId 对应）。 */
  selectedServer: ServerConfig | undefined;
  /** 主核是否运行（新鲜度门：陈旧快照不得报故障）。 */
  proxyRunning: boolean;
  /** 该节点的 Tailscale STATUS 末帧（store.tailscaleStatuses[id]），无帧=undefined。 */
  tsStatus: TailscaleStatusEvent | undefined;
  /** 该节点的 OpenVPN 状态末帧（useVpnStatusStore.openVpn[id]），无帧=undefined。 */
  openVpnStatus: OpenVpnStatusEvent | undefined;
}

/** TS 腿：无帧不报；过期 → 未就绪 → 对端全离线，三档按「离根因近」排序。 */
function tailscaleHealth(status: TailscaleStatusEvent | undefined): MeshTunnelHealth {
  if (!status) return 'none';
  if (status.expired) return 'ts-expired';
  if (status.backendState !== 'Running') return 'ts-not-running';
  // 空 peers ≠ 全离线（那一帧根本没带对端信息）——先例 MeshInfoHoverCard 的 peers 行同理不画。
  if (status.peers.length > 0 && status.peers.every((p) => !p.online)) return 'ts-peers-offline';
  return 'none';
}

/** OVPN 腿：状态帧带错误 → 连接出了问题；无隧道参数 → 尚未连上。 */
function vpnHealth(status: Pick<OpenVpnStatusEvent, 'error' | 'tunnelInfo'> | undefined): MeshTunnelHealth {
  if (!status) return 'none';
  if (status.error?.trim()) return 'vpn-error';
  if (!status.tunnelInfo) return 'vpn-disconnected';
  return 'none';
}

export function deriveMeshTunnelHealth(i: MeshTunnelHealthInput): MeshTunnelHealth {
  const s = i.selectedServer;
  if (!s) return 'none';
  if (!i.proxyRunning) return 'none'; // 新鲜度门：核没跑 ⇒ 手里全是缓存末帧，不得据以报故障
  if (!isMeshNode(s) || meshAllowsInternet(s)) return 'none'; // 总门：只对「只走内网的组网节点」说话
  // openconnect 没有独立分支：`endpoint-routes.ts` 的 meshAllowsInternet 对它恒 true（default: true
  // 分支），必被上面这道总门挡下，case 'openconnect' 走不到，是不可达死代码，故删。若
  // endpoint_routes 未来给 openconnect 补了 allowInternet 语义，这里要同步补回分支。
  switch (s.protocol?.toLowerCase()) {
    case 'tailscale':
      return tailscaleHealth(i.tsStatus);
    case 'openvpn-client':
      return vpnHealth(i.openVpnStatus);
    case 'wireguard':
      // WARP 走不到这里（`meshAllowsInternet` 对 WARP 恒 true，已被总门挡下），落这条的只有
      // 关了「允许访问外网」的自建 WG —— 而它恰恰是全仓唯一一个连信号源都没有的组网腿。
      return 'unprobeable';
    default:
      return 'none';
  }
}
