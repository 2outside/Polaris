/**
 * RulesScreen —— 自定义规则屏（1:1 提取自原型 polaris-prototype.html L1869-1919 #s-rules）。
 *
 * 原型 DOM（id/class/层级顺序对齐，样式见 src/styles/prototype.css「RULES」段，勿改该文件）：
 *   .screen#s-rules
 *     .phead（标题 + .acts：添加规则）
 *     #rules-mode-warn.mode-warn（global/direct 模式警告 + 「切回智能」按钮，data-act=seg-to-smart）
 *     .card.geo-card（地区分流，见 GeoCard；紧随 mode-warn，先于下面两条 note）
 *     #rules-mode-note.rules-note（全局/直连下仅流量效果不生效，与 mode-warn 同一 off 条件）
 *     #rules-manual-note.rules-note（手动接管提示，proxyModeType==='manual' 时显示）
 *     #rules-body（页内效果筛选 + 优先级头 + 列表；DNS 效果在所有代理模式均生效）
 *       自定义规则头（#rule-count） + #rule-list.rule-list（.rule-item，拖拽排序）
 *
 * 数据流：useAppStore（rules + config + updateProxyMode）。规则 CRUD 经 api.rules（add/update/delete/reorder）。
 * 地区分流经 config.regionRouting（effectiveRegionRouting 取生效值，config.setValue 写）。
 */

import { useCallback, useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  useAppStore,
  useEffectiveConfig,
  useEffectiveRules,
  useEffectiveServers,
} from '@/store/app-store';
import { api } from '@/ipc';
import type { Rule, RegionRoutingConfig } from '@/contracts/types';
import { effectiveRegionRouting } from '@/domain/region-routing';
import {
  availableResourceTagSet,
  missingResourceRuleIds,
} from '@/domain/rule-resource-refs';
import { meshOverlapRuleIds } from '@/domain/mesh-rule-overlap';
import { duplicateRulePayload } from '@/domain/rule-duplicate';
import { ruleDnsEffect, ruleRouteEffect } from '@/domain/rules';
import {
  collectRuleTargetedServerIds,
  meshForceRoutedServers,
  meshForcedRouteCidrs,
} from '@/domain/endpoint-routes';
import { useStagedConfigStore } from '@/store/staged-config-store';
import { useStagingActive } from '@/store/use-staging-active';
import { editRoute, stagedOnlyIds } from '@/lib/staged-config';
import { useConfirmTwice } from '@/lib/confirm-twice';
import { useRuleDelete } from '@/lib/use-rule-delete';
import { useDialogStore } from '@/components/dialogs/dialog-store';
import { Fold } from '@/components/Fold';
import { toast } from '@/lib/error-handler';
import { RuleItem } from './RuleItem';
import { GeoCard } from './GeoCard';
import { PriorityFlow } from './PriorityFlow';
import {
  DnsPolicyWorkspace,
  type DnsWorkspaceView,
} from './DnsPolicyWorkspace';

/**
 * 行内删除的原地二次确认 key 前缀（原型 :4097 `rule-del`）。带 rule.id ⇒ 武装 B 行会自动解除 A 行
 * （`useConfirmTwice` 是**单槽**：武装 B 解除 A，见 `confirm-twice.ts:47-53`）——同一屏上同时挂着两颗
 * 「再点一次就删」的按钮误触面更大，单槽是有意收紧，别改成多槽。
 */
const RULE_DEL_PREFIX = 'rule-del:';
const DNS_SYSTEM_RULE_KEYS = [
  'rules.dnsWorkspace.systemRuleNode',
  'rules.dnsWorkspace.systemRuleBootstrap',
  'rules.dnsWorkspace.systemRuleLocal',
] as const;

export function RulesScreen({ plane = 'route' }: { plane?: 'route' | 'dns' }) {
  const { t } = useTranslation();
  const [dnsView, setDnsView] = useState<DnsWorkspaceView>('rules');
  /** 展示面：regionRouting / customRules / appRules 都是本屏可编辑的设置与实体。
   *  唯一的直落盘腿（`handleRegionChange` 的 `saveConfig`）另取 `getState().config`，见那里。 */
  const config = useEffectiveConfig();
  /** 展示面：规则列表本体。这是「节点/规则列表不回显 staged 编辑」那条缺口在本屏的落点。 */
  const rules = useEffectiveRules(plane);
  const collectionKey = plane === 'dns' ? 'dnsRules' : 'trafficRules';
  const orderKey = plane === 'dns' ? 'dnsRuleOrder' : 'routeRuleOrder';
  const planeRules = useMemo(
    () =>
      rules.filter((rule) =>
        plane === 'dns' ? ruleDnsEffect(rule) !== null : ruleRouteEffect(rule) !== null,
      ),
    [rules, plane],
  );
  const persistedOrder = config?.[orderKey] ?? [];
  const [optimisticOrder, setOptimisticOrder] = useState<string[] | null>(null);
  useEffect(() => setOptimisticOrder(null), [persistedOrder.join('\u0000'), planeRules]);
  const visibleRules = useMemo(
    () => {
      const byId = new Map(planeRules.map((rule) => [rule.id, rule]));
      const ordered: Rule[] = [];
      for (const id of optimisticOrder ?? persistedOrder) {
        const rule = byId.get(id);
        if (rule) {
          ordered.push(rule);
          byId.delete(id);
        }
      }
      ordered.push(...planeRules.filter((rule) => byId.has(rule.id)));
      return ordered;
    },
    [planeRules, persistedOrder, optimisticOrder],
  );
  /** 展示面：规则目标节点名映射（不喂任何按 id 查盘的后端调用）。 */
  const servers = useEffectiveServers();
  /** 操作面：磁盘上真实存在的那批规则。**只**用来算「哪些是 staged-only」，不参与渲染集合本身。 */
  const diskRules = useAppStore((s) => (plane === 'dns' ? s.dnsRules : s.rules));
  const loadConfig = useAppStore((s) => s.loadConfig);
  const openDialog = useDialogStore((s) => s.open);
  const stagingEnabled = useStagingActive();
  const stage = useStagedConfigStore((s) => s.stage);
  /** 行内删除的原地二次确认（单槽，见 RULE_DEL_PREFIX 头注）。 */
  const { armed, confirmTwice } = useConfirmTwice();
  /** 删除腿：与规则弹窗 footer 那颗**同一个** hook（暂存分流只此一份，不在本屏复制）。 */
  const deleteRule = useRuleDelete(plane);

  const proxyMode = config?.proxyMode ?? 'smart';
  const isSmartMode = proxyMode === 'smart';
  const regionRouting = effectiveRegionRouting(config ?? {});

  /** 「待保存」角标的唯一判据：在 effective 里、不在 disk 里（与节点卡同一函数、同一词汇）。 */
  const stagedOnlyRuleIds = useMemo(() => stagedOnlyIds(rules, diskRules), [rules, diskRules]);

  // serverId → name（规则目标节点解析）
  const serverNameById = useMemo(() => {
    const m = new Map<string, string>();
    servers.forEach((s) => m.set(s.id, s.name));
    return m;
  }, [servers]);

  const dnsServerNameById = useMemo(() => {
    const names = new Map<string, string>();
    for (const server of config?.dnsServers ?? []) {
      const name = server.id === 'builtin-domestic'
        ? t('settings.dns.builtinDomesticName')
        : server.id === 'builtin-remote'
          ? t('settings.dns.builtinRemoteName')
          : server.id === 'builtin-bootstrap'
            ? t('settings.dns.builtinBootstrapName')
            : server.name;
      names.set(server.id, name);
    }
    return names;
  }, [config?.dnsServers, t]);

  const dnsGroupNameById = useMemo(
    () => new Map((config?.dnsServerGroups ?? []).map((group) => [group.id, group.name])),
    [config?.dnsServerGroups],
  );

  // ── 三类角标的判定输入（契约 §Rules「角标」）────────────────────────────────
  //
  // 流量相关角标只在 smart 模式计算；DNS 规则集资源在三种模式都参与解析，故资源缺失角标不能
  // 随模式隐藏。否则 global/direct 下 DNS 规则失效，页面却只告诉用户「DNS 仍生效」。

  // 资源可用集：挂载拉一次，并随 config 变化重拉（在资源页删/恢复资源会改 config）→ 角标即时反映。
  const [availableResTags, setAvailableResTags] = useState<Set<string>>(new Set());
  useEffect(() => {
    let active = true;
    api.ruleResources
      .list()
      .then((list) => {
        // IPC 边界不可信 TS 类型承诺（异常路径可能下发 null）：非数组一律当空集，
        // 空集会让所有引用资源的规则都标「缺失」——那是**假警报**，故此处宁可不标（[]→ 谓词恒 false 才对）。
        if (active) setAvailableResTags(availableResourceTagSet(Array.isArray(list) ? list : []));
      })
      .catch(() => {});
    return () => {
      active = false;
    };
  }, [config]);

  const missingResIds = useMemo(() => {
    return missingResourceRuleIds(planeRules, availableResTags);
  }, [planeRules, availableResTags]);

  // 组网 force-route 段：口径必须与**发射端**一致（`meshForceRoutedServers` 只留本轮真会发射
  // force-route 的节点：ON / 选中 / 被规则指向），否则会对「仅出网、未 engaged」的节点虚报覆盖。
  const meshOverlapIds = useMemo(() => {
    if (plane !== 'route' || !isSmartMode) return new Set<string>();
    const cidrs = meshForcedRouteCidrs(
      meshForceRoutedServers(
        config?.servers,
        config?.selectedServerId,
        collectRuleTargetedServerIds([...(config?.trafficRules ?? config?.policyRules ?? config?.customRules ?? []), ...(config?.appRules ?? [])]),
      ),
    );
    return meshOverlapRuleIds(rules, cidrs);
  }, [plane, isSmartMode, rules, config?.servers, config?.selectedServerId, config?.trafficRules, config?.policyRules, config?.customRules, config?.appRules]);

  // 拖拽重排（原型 L5161 getAfter 算法）：落到 target 前插入。
  const [dragId, setDragId] = useState<string | null>(null);

  /**
   * 提交新顺序（拖拽 / 上下移 / 置顶底**共用**的唯一路径）。
   *
   * 乐观重排：先落 store。原先算完 orderedIds 就只发给后端、从不 set 回 store——后端 rules_reorder
   * 其实正确持久化了，但 store.rules 仍是旧引用，行拖完瞬间弹回原位，表现成「拖拽完全无效」。
   * 拖放必须即时反馈（等一轮 IPC 会先弹回再跳过去），故乐观更新 + 失败回拉真值。
   */
  const commitOrder = useCallback(
    async (ordered: Rule[]) => {
      const prev = visibleRules;
      // 净零序在**前端**也短路一次：后端 rules_reorder 已跳过 save（见 commands/rules.rs plan_reorder），
      // 这里再挡一层是省掉那一次 IPC 往返 + 一次无意义的 store 重设（列表整棵重渲染）。
      if (
        prev.length === ordered.length &&
        prev.every((r, i) => r.id === ordered[i].id)
      ) {
        return;
      }
      setOptimisticOrder(ordered.map((rule) => rule.id));
      // 当前平面规则排序无副作用，按各自 order 字段进入暂存。
      // 顺序在条目模型里是**整集合的主键序列**（`entityPath` 单段 = 集合本身），不是某个实体的字段；
      // 让它绕过暂存是错的 —— 同一个页面里「改规则」进暂存、「拖排序」直落盘，条上的「N 项待保存」
      // 就说不清列表现在是什么顺序，而顺序决定命中优先级。
      // 与同批的增/删/改条目在 `replay` 里分两趟（实体在前、顺序在后）⇒ 二者可交换。
      const orderEditRoute =
        plane === 'dns'
          ? editRoute('dnsRuleOrder', stagingEnabled)
          : editRoute('routeRuleOrder', stagingEnabled);
      if (orderEditRoute === 'staged') {
        stage({
          id: `order:${orderKey}`,
          kind: 'rule',
          label: t('home.stagedRuleOrder'),
          entityPath: [orderKey],
          nextValue: ordered.map((r) => r.id),
        });
        return; // 零 IPC 写、零磁盘写（FR-1）
      }
      try {
        await api.rules.reorder(ordered.map((r) => r.id), plane);
        // 成功腿此前是**静默**的（只做了失败腿）。原型 `:5201` 在 `#reorder-hint` 上变绿显
        // 「已重排 · 净零，未重启内核」1.6s ——「净零」这半句是专门的安抚语：拖排序会改命中优先级，
        // 用户会担心它像别的结构性改动那样重启内核。本仓没有 `#reorder-hint` 这个宿主，
        // 落到 toast（同 §3 的整体口径：瞬时结果走 toast）。
        toast.success(t('rules.reorderOk'));
      } catch (err) {
        // 乐观更新的回滚是**静默**的：行拖过去又弹回原位，与「拖拽功能坏了」完全同形。
        // 排序决定命中优先级（首个命中生效），用户以为改了实际没改 = 分流按旧优先级跑。必须报，并透出后端原因。
        console.error('[RulesScreen] reorder failed:', err);
        setOptimisticOrder(prev.map((rule) => rule.id));
        toast.error(
          t('rules.reorderFail'),
        );
      }
    },
    [t, stagingEnabled, stage, visibleRules, orderKey, plane],
  );

  const handleDrop = useCallback(
    async (target: Rule) => {
      if (!dragId || dragId === target.id) {
        setDragId(null);
        return;
      }
      const ordered = [...visibleRules];
      const from = ordered.findIndex((r) => r.id === dragId);
      const to = ordered.findIndex((r) => r.id === target.id);
      if (from === -1 || to === -1) {
        setDragId(null);
        return;
      }
      const [moved] = ordered.splice(from, 1);
      ordered.splice(to, 0, moved);
      setDragId(null);
      await commitOrder(ordered);
    },
    [dragId, visibleRules, commitOrder],
  );

  /** 上移 / 下移 / 置顶 / 置底 —— 算出目标下标后走同一条 commitOrder。 */
  const handleMove = useCallback(
    async (rule: Rule, to: 'up' | 'down' | 'top' | 'bottom') => {
      const from = visibleRules.findIndex((r) => r.id === rule.id);
      if (from === -1) return;
      const target =
        to === 'up'
          ? from - 1
          : to === 'down'
            ? from + 1
            : to === 'top'
              ? 0
              : visibleRules.length - 1;
      // 边界外 = 空操作（按钮此时本就 disabled，这里是旁路防御，不发 IPC）。
      if (target < 0 || target >= visibleRules.length || target === from) return;
      const ordered = [...visibleRules];
      const [moved] = ordered.splice(from, 1);
      ordered.splice(target, 0, moved);
      await commitOrder(ordered);
    },
    [visibleRules, commitOrder],
  );

  // 同 handleDrop：开关必须即时反馈，故乐观更新 store + 失败回滚（原先只写后端，开关点了不动）。
  const handleToggle = useCallback(
    async (rule: Rule) => {
      const currentEffect = plane === 'dns' ? ruleDnsEffect(rule) : ruleRouteEffect(rule);
      if (!currentEffect) return;
      const next: Rule = {
        ...rule,
        effects: {
          ...rule.effects,
          [plane]: { ...currentEffect, enabled: currentEffect.enabled === false },
        },
      };
      // 操作面（镜像自身）：同 commitOrder —— 乐观 setState 的回滚基准。
      const prev = plane === 'dns' ? useAppStore.getState().dnsRules : useAppStore.getState().rules;
      const optimistic = prev.map((r) => (r.id === next.id ? next : r));
      useAppStore.setState(plane === 'dns' ? { dnsRules: optimistic } : { rules: optimistic });
      // 当前平面规则启停无副作用，进入对应独立集合的暂存腿。
      // 上面那次乐观 setState 照旧 —— 开关即时跳位是这条腿的可见承诺，暂存与否都不该让它弹回。
      const stageRule =
        plane === 'dns'
          ? editRoute('dnsRules', stagingEnabled) === 'staged'
          : editRoute('trafficRules', stagingEnabled) === 'staged';
      if (stageRule) {
        stage({
          id: `rule:${next.id}`,
          kind: 'rule',
          label: `${t('rules.editTitle')} ${next.remarks || next.type}`,
          entityPath: [collectionKey, next.id],
          nextValue: next,
        });
        return; // 零 IPC 写、零磁盘写（FR-1）
      }
      try {
        await api.rules.update(next, plane);
      } catch (err) {
        // 同 handleDrop：开关弹回原位是静默的。停用了以为停用了、其实规则还在生效 → 必须报。
        console.error('[RulesScreen] toggle failed:', err);
        useAppStore.setState(plane === 'dns' ? { dnsRules: prev } : { rules: prev });
        toast.error(
          t('rules.saveFailed'),
        );
      }
    },
    [t, plane, stagingEnabled, stage, collectionKey],
  );

  /**
   * 行内复制（G5，原型 `enhanceRuleRow` :4771 的 `rule-copy` + :4096 「造一条同条件新规则」）。
   *
   * 走既有 `rules.add` 单一入口（**零新增后端**）。载荷构造在 `domain/rule-duplicate.ts`
   * （去 `id` + `remarks` 后缀两条不变式在那里有单测）。
   *
   * 复制出的规则**保持原启停态**（对齐原型：它只是复制）。同条件同动作时后一条恒被前一条遮蔽、
   * 不改变分流结果；用户改完条件它才真正开始起作用。
   */
  const handleDuplicate = useCallback(
    async (rule: Rule) => {
      try {
        const payload = duplicateRulePayload(rule, t('rules.copySuffix'));
        // 当前平面规则复制无副作用，进入对应独立集合的暂存腿。
        // 前端自铸 id（后端只在落盘那一刻发 id，而条目现在就要一个稳定的实体寻址键）。
        const stageRule =
          plane === 'dns'
            ? editRoute('dnsRules', stagingEnabled) === 'staged'
            : editRoute('trafficRules', stagingEnabled) === 'staged';
        if (stageRule) {
          const entityId = crypto.randomUUID();
          stage({
            id: `rule:${entityId}`,
            kind: 'rule',
            label: `${t('rules.newTitle')} ${payload.remarks ?? payload.type}`,
            entityPath: [collectionKey, entityId],
            nextValue: { ...payload, id: entityId },
          });
          toast.success(t('rules.duplicated'));
          return; // 零 IPC 写、零磁盘写（FR-1）
        }
        await api.rules.add(payload, plane);
        // 与 RuleDialog 同款：直写成功后重拉当前平面磁盘镜像。
        void loadConfig(true);
        toast.success(t('rules.duplicated'));
      } catch (err) {
        console.error('[RulesScreen] duplicate failed:', err);
        toast.error(
          t('rules.saveFailed'),
        );
      }
    },
    [t, loadConfig, stagingEnabled, stage, collectionKey, plane],
  );

  /**
   * 行内删除（原型 :4097 `rule-del`）——**原地二次点击**，不叠弹窗。
   *
   * 此前删一条规则必须先点「编辑」开窗、再点 footer 左侧那颗（陈先生 2026-07-30：「不是很合理」）。
   * 弹窗里那颗**保留**：两者不是重复入口，是两种语境（列表里删一条 vs 编辑到一半决定不要了），
   * 且共用 `useRuleDelete` 这一条腿 —— 暂存态下两个入口的行为逐字相同，不会一个写盘一个不写。
   *
   * 失败必须报：删除的可见结果就是「这行消失」，静默失败与「按钮失灵」完全同形，
   * 用户会以为没删掉再点一次（同 handleToggle / handleDuplicate 的口径）。
   */
  const requestDelete = useCallback(
    (rule: Rule) => {
      confirmTwice(`${RULE_DEL_PREFIX}${rule.id}`, () => {
        void (async () => {
          try {
            await deleteRule(rule);
          } catch (err) {
            console.error('[RulesScreen] delete failed:', err);
            toast.error(
              t('rules.deleteFail'),
            );
          }
        })();
      });
    },
    [confirmTwice, deleteRule, t],
  );

  const handleRegionChange = useCallback(
    async (next: RegionRoutingConfig) => {
      // 必须走 saveConfig：它提交局部 patch 并采用后端返回的完整新配置，地区按钮可立即回显，且不会
      // 把 effective 中尚未保存的其它编辑带进磁盘。
      const cur = useAppStore.getState().config;
      if (!cur) return;
      // GeoCard 三个控件共用本入口，而原型只对其中两个 notify（总开关 .swt 不 notify——开关自身即反馈）：
      // 故先与生效值对差认出改了哪一项，落盘成功后再按原型语义各报各的。
      // **刻意取磁盘那份**（`cur`）而非 effective：它同时是下面 `saveConfig` 的入参基准，
      // 两处必须同源，否则落盘基准会跟着展示口径漂。代价是连改两次地区时，第二次的 toast 仍按
      // 磁盘旧值判「改了没」，可能多报一次 —— 纯文案层，已裁定可接受，不为它把基准拆成两份。
      const prevRouting = effectiveRegionRouting(cur);
      const regionChanged = prevRouting.region !== next.region;
      const reverseChanged = prevRouting.reverse !== next.reverse;
      // 配置暂存闸门（与 NodeDialog 同形）：`regionRouting` 是 UserConfig 字段（Class B），
      // 且这三个控件都不是运行期状态 / 活态回读 / 不可逆副作用 ⇒ 默认腿。
      // 走键路径寻址（不是集合实体），`nextValue` 是整份 `RegionRoutingConfig` —— 幂等整体替换。
      if (editRoute('regionRouting', stagingEnabled) === 'staged') {
        stage({
          id: 'setting:regionRouting',
          kind: 'setting',
          label: t('home.stagedSetting', { key: 'regionRouting' }),
          entityPath: ['regionRouting'],
          nextValue: next,
        });
        // 下面那两条 toast 照发：它们说的是「这次选择意味着什么分流形态」，与「何时落盘」正交。
      } else {
        try {
          await useAppStore.getState().saveConfig({ regionRouting: next });
        } catch (err) {
          // 保存失败**不回滚**（GeoCard 是受控组件，按钮态跟着 store 走，写失败即原地不动）：
          // 表现为「点了没反应」，必须报出真实原因。
          console.error('[RulesScreen] regionRouting save failed:', err);
          toast.error(
            t('rules.saveFailed'),
          );
          return;
        }
      }
      // 原型 :4103 geo-region → notify('<地区> · 该地区流量直连')（中性）：按钮 .on 只说「选中了」，
      // 说不出「选中意味着什么」，这条 toast 才是语义。
      if (regionChanged) {
        const regionName =
          next.region === 'cn'
            ? t('rules.region.cn')
            : next.region === 'ir'
              ? t('rules.region.ir')
              : t('rules.region.ru');
        toast.info(
          t('rules.regionPicked', { region: regionName })
        );
      }
      // 原型 :4105 geo-rev → 开=ok 且带语义说明，关=中性（kind 差异照抄：`on?'ok':undefined`）。
      // **kind 的开/关差异保留**（开=生效中的主动态、关=回到默认，是有意的两级语义）；深色下中性态曾是
      // 白底实色大色块、与 ok 风格割裂，那是 CSS 缺中性态暗色覆盖所致，已在 prototype/components.css 的
      // §toast dark neutral 修掉，不靠把 info 改成 success 来掩盖。
      // **文案对称性已收敛**（真机反馈「文案差异也大」）：开态原带「· 本地走代理、海外直连」说明「选中意味着
      // 什么」，关态却只有裸标题，用户读不到关掉之后的分流形态。关态补上对偶子句（两个分句原样对调），
      // 与上方 regionPicked「· 该地区流量直连」的「状态 · 语义」句式一致。
      if (reverseChanged) {
        if (next.reverse) {
          toast.success(t('rules.reverseOn'));
        } else {
          toast.info(t('rules.reverseOff'));
        }
      }
    },
    [t, stagingEnabled, stage],
  );

  // 原型 L1875 data-act="seg-to-smart"：mode-warn 内「切回智能」按钮，热切换回智能分流（不重启）。
  const handleBackToSmart = useCallback(async () => {
    try {
      await useAppStore.getState().updateProxyMode('smart');
      // 原型 setStrategySmart :4347 → notify('已切回智能分流','ok')。
      toast.success(t('rules.backToSmartOk'));
    } catch (err) {
      // 失败时 mode-warn 仍留在原地；同时报出真实原因，避免按钮看似无响应。
      console.error('[RulesScreen] backToSmart failed:', err);
      toast.error(
        t('rules.backToSmartFail'),
      );
    }
  }, [t]);

  // 原型 L1903 rules-mode-note 与 L1875 mode-warn 同一「off」条件（proxyMode !== smart）。
  const modeInactive = plane === 'route' && !isSmartMode;

  return (
    <section id={plane === 'dns' ? 's-dns-rules' : 's-rules'} className="screen">
      <div className="phead">
        <div>
          <h1>{t(plane === 'dns' ? 'sidebar.dns' : 'sidebar.rules')}</h1>
        </div>
        <div className="acts">
          <button
            type="button"
            className="btn flow"
            onClick={() => {
              if (plane !== 'dns' || dnsView === 'rules') {
                openDialog({ kind: 'rule', initialPlane: plane });
              } else if (dnsView === 'servers') {
                openDialog({ kind: 'dns-server' });
              } else if (dnsView === 'groups') {
                openDialog({ kind: 'dns-group' });
              }
            }}
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}>
              <path d="M12 5v14M5 12h14" />
            </svg>
            <span>
              {t(
                plane !== 'dns' || dnsView === 'rules'
                  ? 'rules.add'
                  : dnsView === 'servers'
                    ? 'settings.dns.addServer'
                    : 'settings.dns.addGroup',
              )}
            </span>
          </button>
        </div>
      </div>

      {plane === 'dns' && (
        <div className="dns-workspace-tabs sub-tabs" role="tablist" aria-label={t('rules.dnsWorkspace.ariaLabel')}>
          {(['rules', 'servers', 'groups'] as const).map((view) => {
            const count = view === 'rules'
              ? visibleRules.length
              : view === 'servers'
                ? (config?.dnsServers?.length ?? 0)
                : (config?.dnsServerGroups?.length ?? 0);
            return (
              <button
                key={view}
                type="button"
                role="tab"
                className={dnsView === view ? 'on' : ''}
                aria-selected={dnsView === view}
                onClick={() => setDnsView(view)}
              >
                <span>{t(`rules.dnsWorkspace.${view}Tab`)}</span>
                {count != null && <span className="cnt">{count}</span>}
              </button>
            );
          })}
        </div>
      )}

      {plane === 'dns' && dnsView !== 'rules' && (
        <DnsPolicyWorkspace view={dnsView} />
      )}

      {(plane === 'route' || dnsView === 'rules') && (
        <>

      {/* 模式警告：global/direct 下仅流量路由效果未生效；DNS 效果仍生效。 */}
      {plane === 'route' && modeInactive && (
        <div className="mode-warn show" id="rules-mode-warn">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}>
            <circle cx="12" cy="12" r="9" />
            <path d="M12 8v5M12 16h.01" />
          </svg>
          <span id="rules-mode-warn-tx">
            {t('rules.modeWarn')}
          </span>
          <button type="button" className="btn ghost sm" onClick={handleBackToSmart}>
            {t('rules.backToSmart')}
          </button>
        </div>
      )}

      {/* 地区分流卡（原型 L1877，紧随 mode-warn 之后、两条 rules-note 之前） */}
      {plane === 'route' && (
        <GeoCard
          regionRouting={regionRouting}
          onChange={handleRegionChange}
          isSmartMode={isSmartMode}
        />
      )}

      {/* 全局/直连模式提示（原型 L1903 #rules-mode-note，与 mode-warn 同一 off 条件） */}
      {plane === 'route' && modeInactive && (
        <div
          className="rules-note show"
          id="rules-mode-note"
          style={{
            borderColor: 'hsl(var(--warn)/0.35)',
            background: 'hsl(var(--warn-weak)/0.6)',
            color: 'hsl(var(--warn))',
          }}
        >
          <svg viewBox="0 0 24 24" width="15" fill="none" stroke="currentColor" strokeWidth={1.8}>
            <circle cx="12" cy="12" r="9" />
            <path d="M12 8v5M12 16h.01" />
          </svg>
          <span>
            {t('rules.modeNote')}
          </span>
        </div>
      )}

      {/* 手动接管提示（原型 L1904 #rules-manual-note）：仅接管方式为 manual（config.proxyModeType）时展示 */}
      {plane === 'route' && config?.proxyModeType === 'manual' && (
        <div className="rules-note show" id="rules-manual-note">
          <svg viewBox="0 0 24 24" width="15" fill="none" stroke="currentColor" strokeWidth={1.8}>
            <circle cx="12" cy="12" r="9" />
            <path d="M12 8v5M12 16h.01" />
          </svg>
          <span>
            {t('rules.manualNote')}
          </span>
        </div>
      )}

      {/* 流量规则与 DNS 规则是两个独立集合；本页只展示当前集合。 */}
      {plane === 'dns' && (
        <PriorityFlow
          className="dns-priority-flow"
          label={t('rules.dnsWorkspace.priority')}
          steps={[
            { id: 'system', label: t('rules.dnsWorkspace.systemStage'), active: true },
            { id: 'custom', label: t('rules.chainCustom') },
            { id: 'default', label: t('rules.chainDefault') },
          ]}
        />
      )}
      {plane === 'dns' && (
        <Fold
          className="dns-system-rules"
          title={(
            <span className="dns-rule-stage-title">
              <span>{t('rules.dnsWorkspace.systemRules')}</span>
              <span className="pill region">{t('settings.dns.builtinTag')}</span>
            </span>
          )}
          tip={t('rules.dnsWorkspace.systemRulesAlwaysFirst')}
          count={DNS_SYSTEM_RULE_KEYS.length}
        >
          <div className="dns-system-rule-list">
            {DNS_SYSTEM_RULE_KEYS.map((key) => <div key={key}>{t(key)}</div>)}
            <DnsPolicyWorkspace view="system" />
          </div>
        </Fold>
      )}
      <div id="rules-body">
        {/* 自定义规则头 */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            marginBottom: 10,
          }}
        >
          <div className="card-h" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span>{t(plane === 'dns' ? 'rules.chainCustom' : 'rules.priority')}</span>
            <span
              className="info-i"
              tabIndex={0}
              /* key 走扁平命名：`rules.priority` 已是字符串，i18next 无法再向下取 `.tip`，
                 旧的 `rules.priority.tip` 恒落 defaultValue（en/fa/ru 下也显中文）——
                 与 GeoCard 里 `rules.regionRouting.sub` 同一类坑，一并收口。 */
              aria-label={t('rules.priorityTip')}
              data-tip={t('rules.priorityTip')}
            >
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}>
                <circle cx="12" cy="12" r="9" />
                <path d="M12 11v5M12 8h.01" />
              </svg>
            </span>
            <span className="pill region" id="rule-count">{visibleRules.length}</span>
          </div>
        </div>

        <div className="rule-list" id="rule-list">
          {visibleRules.length === 0 ? (
            <div className="stub">
              <p>{t('rules.empty')}</p>
            </div>
          ) : (
            visibleRules.map((rule, i) => {
              const route = ruleRouteEffect(rule);
              const dnsAction = ruleDnsEffect(rule)?.action;
              const targetServerId = route?.action === 'proxy' ? route.targetServerId : undefined;
              const dnsActionName = dnsAction?.type === 'server'
                ? dnsServerNameById.get(dnsAction.serverId)
                : dnsAction?.type === 'group'
                  ? dnsGroupNameById.get(dnsAction.groupId)
                  : dnsAction?.type === 'hostsFirst'
                    ? dnsServerNameById.get(dnsAction.hostsServerId)
                    : undefined;
              return (
                <RuleItem
                  key={rule.id}
                  rule={rule}
                  enabled={
                    (plane === 'dns' ? ruleDnsEffect(rule)?.enabled : ruleRouteEffect(rule)?.enabled) !== false
                  }
                  index={i}
                  targetNodeName={
                    targetServerId ? serverNameById.get(targetServerId) : undefined
                  }
                  dnsActionName={dnsActionName}
                  targetMissing={
                    !!targetServerId && !serverNameById.has(targetServerId)
                  }
                  stagedOnly={stagedOnlyRuleIds.has(rule.id)}
                  hasMissingResource={missingResIds.has(rule.id)}
                  hasMeshOverlap={meshOverlapIds.has(rule.id)}
                  routeInactive={plane === 'route' && modeInactive && route !== null}
                  onToggle={handleToggle}
                  onEdit={(r) => openDialog({ kind: 'rule', ruleId: r.id, initialPlane: plane })}
                  onDuplicate={handleDuplicate}
                  onDelete={requestDelete}
                  deleteConfirming={armed === `${RULE_DEL_PREFIX}${rule.id}`}
                  onDragStart={(r) => setDragId(r.id)}
                  onDragOver={(_, e) => e.preventDefault()}
                  onDrop={handleDrop}
                  isDragging={dragId === rule.id}
                  onMove={handleMove}
                  isFirst={i === 0}
                  isLast={i === visibleRules.length - 1}
                />
              );
            })
          )}
        </div>
      </div>
      {plane === 'dns' && <DnsPolicyWorkspace view="rules" />}
        </>
      )}
    </section>
  );
}

export default RulesScreen;
