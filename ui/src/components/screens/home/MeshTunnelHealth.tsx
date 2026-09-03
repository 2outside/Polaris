/**
 * 首页「只走内网的组网节点·隧道健康」行内注脚。判定单一真值 = `deriveMeshTunnelHealth`，
 * `'none'` / `'unprobeable'` → 渲染 null（后者是核跑着就恒亮的静态事实，不是运行期信号，
 * 常驻横幅无可行动性，见下方）。纯 renderer 视图态，零 IPC / config-gen / 重启。
 *
 * # 为什么它挂在 `TsExitWarning` 下方而不是并进它
 *
 * 两条说的是**不同的事**：上面那条是「公网不经这条隧道」，本条是「这条隧道本身通不通」。
 * TS 未设出口设备时上面那条恒亮，本条仍可能同时有话说（内网也断了）——抑制掉是丢信息。
 * 故本条**不抑制** `NoExitDevice`，只用**不同图标**（圆圈感叹号 vs 三角警示）把两句话区分开。
 * 外壳形状 1:1 照搬 `TsExitWarning`（`role="status"` + 14px 图标 + 12px 注脚），
 * 两条并排时视觉上是同一族注脚。
 *
 * # 没有动作按钮
 *
 * 上面那条给「去登录 / 选设备」是因为根因明确、下一步唯一。本条的根因在**隧道对面**
 * （对端全离线、VPN 服务端拒绝、WG 根本没有信号），应用内没有一个点了就能修的按钮 ——
 * 摆一个只会把用户送去一个改不了现状的页面。故只报事实，不造动作。
 */
import { useTranslation } from 'react-i18next';
import { useAppStore } from '@/store/app-store';
import { useVpnStatusStore } from '@/store/use-vpn-status-store';
import { deriveMeshTunnelHealth, type MeshTunnelHealth as Health } from '@/domain/mesh-tunnel-health';

/**
 * 每档一句文案。穷举 Record —— 新增档位而漏配文案会被类型检查挡下（同 MeshInfoHoverCard 的
 * ROW_LABEL）。不含 'unprobeable'：那档在渲染前就 return null 了，不会走到这张表。
 */
const TEXT_KEY: Record<Exclude<Health, 'none' | 'unprobeable'>, string> = {
  'ts-expired': 'home.meshTunnelTsExpired',
  'ts-not-running': 'home.meshTunnelTsNotReady',
  'ts-peers-offline': 'home.meshTunnelTsPeersOffline',
  'vpn-error': 'home.meshTunnelVpnError',
  'vpn-disconnected': 'home.meshTunnelVpnDisconnected',
};

export function MeshTunnelHealth() {
  const { t } = useTranslation();
  const servers = useAppStore((s) => s.servers);
  const selectedServerId = useAppStore((s) => s.selectedServerId);
  const proxyRunning = useAppStore((s) => !!s.proxyStatus?.running);

  const selectedServer = servers.find((x) => x.id === selectedServerId);
  const id = selectedServer?.id;
  const tsStatus = useAppStore((s) => (id ? s.tailscaleStatuses[id] : undefined));
  const openVpnStatus = useVpnStatusStore((s) => (id ? s.openVpn[id] : undefined));

  const health = deriveMeshTunnelHealth({
    selectedServer,
    proxyRunning,
    tsStatus,
    openVpnStatus,
  });
  // 'unprobeable'（WireGuard）是核在跑就恒亮的静态事实、不随运行期状态变化，常驻横幅是纯噪声、
  // 无可行动性 —— 派生值照旧保留（诚实答案，测试也钉着它），只是不拿它渲染 UI。
  if (health === 'none' || health === 'unprobeable') return null;

  const color = 'hsl(var(--warn))';

  return (
    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 6, marginTop: 8 }} role="status">
      <svg
        viewBox="0 0 24 24"
        width={14}
        height={14}
        fill="none"
        stroke="currentColor"
        strokeWidth={1.9}
        style={{ color, flex: 'none', marginTop: 1 }}
        aria-hidden
      >
        <circle cx="12" cy="12" r="9" />
        <path d="M12 7.5v5M12 16h.01" />
      </svg>
      <p style={{ margin: 0, fontSize: 12, lineHeight: 1.5, color: 'hsl(var(--fg-dim))', minWidth: 0 }}>
        {t(TEXT_KEY[health])}
      </p>
    </div>
  );
}

export default MeshTunnelHealth;
