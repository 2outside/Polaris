import { useMemo, useState } from 'react';
import type { TFunction } from 'i18next';
import type { RuleRouteEffect, ServerConfig, SubscriptionConfig } from '@/contracts/types';
import { groupServersBySubscription, defaultOpenGroupIds } from '@/domain/server-grouping';
import { flagCodeForName } from '@/components/screens/nodes/NdFlag';
import { FlagImg } from '@/components/FlagImg';
import { Csel, type CselGroup } from './Csel';

/**
 * 「目标出站」三个快速策略的行首图标 —— **与首页出口选单 / 应用分流策略菜单同一组图形**
 * （`AppPolicyScreen` 的 `QUICK_PICKS` 与 `NodeMenu` 的直连/阻断行用的就是这三条 path）。
 *
 * 此前这个下拉的选项行**什么图标都没有**，靠 label 里的文本前缀「代理 →」代替 —— 同一件事
 * （「这是一条策略」/「这是一个节点」）在首页画图标、在这里写文字，是三处不一致里最刺眼的一处。
 * `.csel-ico` 那个类不是装饰：prototype 的 `.sel svg{position:absolute}` 会命中 `.sel.csel`
 * 子树里每个 svg，必须靠它复位（规则 + 根因见 styles/index.css 轴 4）。
 */
const TARGET_ICON_PATHS: Record<'proxy' | 'direct' | 'block', string> = {
  proxy: 'M12 5v14M5 12h14',
  direct: 'M4 12h16',
  block: 'M5 5l14 14',
};
function TargetIcon({ kind }: { kind: keyof typeof TARGET_ICON_PATHS }) {
  return (
    <svg className="csel-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}>
      <path d={TARGET_ICON_PATHS[kind]} />
    </svg>
  );
}

/**
 * Route 效果的状态 —— `target`（`proxy` / `direct` / `block` / `node:<id>`）+ 按订阅/分组折叠的
 * 目标出站候选（`targetGroups`）。从 `RuleForm` 外提，供状态与其消费的 JSX（`RuleRouteEffectFields`）
 * 共用同一份计算。
 */
export function useRuleRouteEffect(
  baseRouteEffect: RuleRouteEffect | null,
  servers: ServerConfig[],
  subscriptions: SubscriptionConfig[] | undefined,
  t: TFunction,
) {
  const [target, setTarget] = useState<string>(() => {
    if (!baseRouteEffect) return 'proxy';
    if (baseRouteEffect.action === 'direct') return 'direct';
    if (baseRouteEffect.action === 'block') return 'block';
    return baseRouteEffect.targetServerId ? `node:${baseRouteEffect.targetServerId}` : 'proxy';
  });

  /**
   * 目标出站下拉 —— **按订阅/分组折叠**（与应用分流的策略菜单、托盘「全部节点」同一套语义）。
   *
   * 此前是一条平铺列表：节点一多（机场订阅动辄几十上百）就得在几百行里滚着找，且直连/阻断被顶到
   * 列表最末端 —— 那两个是常用项，却因为夹在节点后面而最难够到。改成分组后：
   *  - 三个快速策略单独一组、**不带 id ⇒ 不可折叠恒展开**（主路径不能被折进去）；
   *  - 每个节点分组（自建/组网/各订阅）一组，带 id ⇒ 可折叠，默认全折叠，
   *    只展开含当前已选节点的那一组（`defaultOpenGroupIds`，三处选择器共用的单一判据）。
   *
   * 节点项文案保留 `代理 → <名称>` 前缀不动：触发器显示的就是被选项的 label，剥掉前缀会让
   * 收起态从「代理 → 香港01」变成裸节点名，丢掉「这是代理到某节点」这层语义。
   */
  const nodeGroups = useMemo(
    () => groupServersBySubscription(servers, subscriptions ?? []),
    [servers, subscriptions],
  );
  /** 当前已选的节点 id（`node:` 前缀是本下拉的值编码，非节点项时为 undefined ⇒ 全折叠）。 */
  const targetNodeId = target.startsWith('node:') ? target.slice(5) : undefined;
  const targetGroups: CselGroup[] = useMemo(
    () => [
      {
        // 复用应用分流菜单那句「策略」而不是新起一个 i18n 键：两处是同一概念，且新增键会动
        // locale-parity 门的债务基线（5 个语言文件都得补），不在本次改动的范围里。
        label: t('appPolicy.policy'),
        options: [
          {
            value: 'proxy',
            label: t('rules.targetDefaultProxy'),
            icon: <TargetIcon kind="proxy" />,
          },
          { value: 'direct', label: t('rules.targetDirect'), icon: <TargetIcon kind="direct" /> },
          {
            value: 'block',
            label: t('rules.targetBlock'),
            icon: <TargetIcon kind="block" />,
            // 动作标签轴：与 `.act-block` pill / `.mi.danger` / `.tray-i.danger` 同色同轴。
            // 走 `Csel` 的 `danger` 通道而不是在本页刷一层红 —— 根因是这个字段此前不存在。
            danger: true,
          },
        ],
      },
      ...nodeGroups.map((g) => ({
        id: g.id,
        // 自建/组网组的 `name` 是占位符，按 isManual/isMesh 本地化（ServerGroup 契约的明文要求）。
        label: g.isManual
          ? t('nodes.tab.manual')
          : g.isMesh
            ? t('nodes.tab.mesh')
            : g.name,
        options: g.servers.map((s) => ({
          value: `node:${s.id}`,
          label: `${t('rules.targetProxyTo')} ${s.name}`,
          // 国旗：与首页出口选单 / 托盘节点行**同一渲染器 + 同一数据源**（名称派生 `flagCodeForName`，
          // 语义 =「这个节点自称在哪」）。识别不到 → FlagImg 返回 null，什么都不画（不回退地球）。
          // 延迟色点刻意**不加**：本弹窗不订阅测速 store，也不该订阅 —— 「目标出站」回答的是
          // 「把流量路由到哪」，在这里画延迟点是给出一条与该决策无关的判据。
          icon: <FlagImg code={flagCodeForName(s.name)} />,
        })),
      })),
    ],
    [nodeGroups, t],
  );
  const targetOpenGroups = useMemo(
    () => defaultOpenGroupIds(nodeGroups, targetNodeId),
    [nodeGroups, targetNodeId],
  );

  return { target, setTarget, targetGroups, targetOpenGroups };
}

interface RuleRouteEffectFieldsProps {
  t: TFunction;
  target: string;
  setTarget: (v: string) => void;
  targetGroups: CselGroup[];
  targetOpenGroups: ReadonlySet<string>;
  touch: () => void;
}

/** Route 效果字段（`.fld`：目标出站下拉）。 */
export function RuleRouteEffectFields({
  t,
  target,
  setTarget,
  targetGroups,
  targetOpenGroups,
  touch,
}: RuleRouteEffectFieldsProps) {
  return (
    <div className="fld">
      <div className="fld-l">{t('rules.routeEffect')}</div>
      <div className="card-sub">{t('rules.routeEffectHint')}</div>
      <div style={{ display: 'grid', gap: 8, marginTop: 8 }}>
        <Csel
          id="rule-target"
          ariaLabel={t('rules.target')}
          value={target}
          onChange={(v) => {
            setTarget(v);
            touch();
          }}
          options={targetGroups}
          openGroupIds={targetOpenGroups}
        />
      </div>
    </div>
  );
}
