/**
 * NodesScreen —— 节点屏（1:1 提取自原型 polaris-prototype.html L1737-1868 #s-nodes
 * + renderMesh/meshItem L4816-4842/4806-4815 组网入口 + syncNodeToolbar L4482-4485 工具栏行为）。
 *
 * 原型 DOM（class/层级对齐，样式见 src/styles/screens.css L「NODES」段 + components.css 通用类）：
 *   .screen
 *     .phead（.ph-title[h1 + .nd-count] + .acts：全部测速 + 添加 dropdown）
 *     .nd-tabs-scroll#node-tabs-scroll > .sub-tabs[data-tabgroup]（自建 / 组网 / 各订阅）
 *     .nd-subinfo（订阅 .sub-info，随对应 tab 显隐）
 *     .node-toolbar#node-shared-tools（.seg2 视图 + .input.search-box 搜索 + .sel 协议/排序（方向固定，无 .nh-dir）+ 测速（可见集）+ 多选）
 *       —— 多选按钮（.nt-hide-sub）仅在订阅 tab 隐藏（原型 syncNodeToolbar：isSub && 隐藏 + 自动退出批选）
 *     .batch-bar（多选批量操作条）
 *     .node-grid > .nd-card（组网协议从页头统一「添加」菜单进入，不在列表区重复铺入口）
 *       —— 各 tab pane
 *
 * 数据流：useAppStore（config.servers + config.subscriptions + selectedServerId）。
 * 测速经 api.server.speedTest 发起；延迟结果读全局 `use-latency-store`、进度走全局 sticky toast
 * （`lib/speedtest-progress-toast.ts`），两者的订阅都挂 App.tsx 顶层、切屏不丢。
 * **本屏不再自订 onSpeedTestProgress**，也不再画屏内进度行——见 `use-node-speed-test.ts` 的 `runSpeedTest` 判据。
 */

import { useEffect, useMemo, useRef, useState, useCallback } from 'react';
import { useAppStore, useEffectiveConfig, useEffectiveServers } from '@/store/app-store';
import { useNodeSortStore } from '@/store/use-node-sort-store';
import { useLatencyStore } from '@/store/use-latency-store';
import { useDialogStore } from '@/components/dialogs/dialog-store';
import { toast } from '@/lib/error-handler';
import { api } from '@/ipc';
import type { ServerConfig, SubscriptionConfig } from '@/contracts/types';
import { groupServersBySubscription } from '@/domain/server-grouping';
import { initialNodesTab } from './initial-tab';
import {
  collectRuleTargetedServerIds,
  type SpeedTestCaps,
} from '@/domain/endpoint-routes';
import { useSubscriptionProgressStore } from '@/store/use-subscription-progress-store';
import { useTranslation } from 'react-i18next';
import { cn } from '@/lib/utils';
import { fallbackExitAfterDelete } from './node-delete-fallback';
import { DIRECT_SERVER_ID } from '@/domain/direct-selection';
import { useNodeViewStore } from '@/store/use-node-view-store';
import { useStagedConfigStore } from '@/store/staged-config-store';
import { useStagingActive } from '@/store/use-staging-active';
import { editRoute, splitStagedOnly, stagedOnlyIds } from '@/lib/staged-config';
import { useConfirmTwice } from '@/lib/confirm-twice';
import { useSwitchNode } from '@/components/screens/shared/use-switch-node';
import { willRestartOnSelect } from '@/components/screens/home/pending-select-hint';
import { useAnchoredMenu } from '@/lib/use-anchored-menu';
import {
  invalidNodeIndex,
  nodeUseAction,
  shadowedCidrIndex,
  shadowedCidrNamed,
  type NodeUseVia,
} from './nodes-logic';
import { useNodeSpeedTest } from './use-node-speed-test';
import { useNodeSubscriptionActions } from './use-node-subscription-actions';
import { useNodeDeletion } from './use-node-deletion';
import { useNodeActions } from './use-node-actions';
import type { NodesListSortKey } from './nodes-list-projection';
import { useNodesRenderWindow } from './use-nodes-render-window';
import { NodesHeader } from './NodesHeader';
import { NodesTabs } from './NodesTabs';
import { NodesToolbar } from './NodesToolbar';
import { NodesBatchBar } from './NodesBatchBar';
import { NodesGrid } from './NodesGrid';

type SortKey = NodesListSortKey;

export function NodesScreen() {
  const { t } = useTranslation();
  const config = useEffectiveConfig();
  /** 展示面：节点列表本体 —— 「节点列表不回显 staged 编辑」那条缺口在本屏的落点。 */
  const servers = useEffectiveServers();
  /** 操作面：磁盘上真实存在的那批节点。用来识别 staged-only / 已暂存删除，并在暂存未启用的
   *  即时兼容腿计算真实可用的磁盘回退节点；不参与渲染集合本身。 */
  const diskServers = useAppStore((s) => s.servers);
  /** 「待保存」角标的唯一判据：在 effective 里、不在 disk 里。不新造字段、不新造词汇。 */
  const stagedOnly = useMemo(() => stagedOnlyIds(servers, diskServers), [servers, diskServers]);
  /** 即时兼容腿的回退候选不得命中已暂存删除的节点：它此刻虽还在盘上，
   *  但下次保存就会消失；选中它会在随后保存时再次失去出口。 */
  const stagedDeleted = useMemo(() => {
    const effectiveIds = new Set(servers.map((server) => server.id));
    return new Set(
      diskServers.filter((server) => !effectiveIds.has(server.id)).map((server) => server.id)
    );
  }, [servers, diskServers]);
  const selectedServerId = useAppStore((s) => s.selectedServerId);
  const openDialog = useDialogStore((s) => s.open);
  const closeDialog = useDialogStore((s) => s.close);
  /**
   * 删节点 / 批删的原地二次确认（原型 :4140 `node-del`、:4137 `batch-del` 都走 confirmTwice）。
   * 与本屏另外两处**保留弹窗**的破坏性操作（删订阅 `requestSubDelete`、注销 WARP `removeWarpNode`）
   * 分工明确：那两处原型里没有对应的 confirmTwice 调用点，属本仓自加的确认，形态维持现状。
   */
  const { armed: confirmArmed, confirmTwice } = useConfirmTwice();
  const stagingEnabled = useStagingActive();
  /** 写入路由只在持有统一暂存态的入口裁定；下游纯函数不再自己解读开关。 */
  const nodeDeletePolicy = useMemo(
    () => ({ all: editRoute('servers', stagingEnabled) }),
    [stagingEnabled]
  );
  const stage = useStagedConfigStore((s) => s.stage);
  /** 撤销腿的两个入参（`ENTITY_ACTION_TABLE` 的 `revert` 策略）。总开关关着时 entries 恒空、
   *  `stagedOnly` 恒空 ⇒ 下面三条动作腿都走今天那条路径。 */
  const stagedEntries = useStagedConfigStore((s) => s.entries);
  const revertStaged = useStagedConfigStore((s) => s.revert);

  /**
   * 把节点删除暂存为完整实体删除意图。删除当前有效出口时，兜底 id 附着在同一条删除意图上；
   * `replay` 负责在连续删除/逐条撤销时重新归一 `selectedServerId`，不另造一条可分离的 W-1 编辑。
   * TS state / WARP 注销由后端在 Apply 时消费持久删除意图，因此节点类型不再改变这里的路由。
   */
  const stageServerDeletions = useCallback(
    (
      targets: readonly ServerConfig[],
      removedIds: ReadonlySet<string>,
      groupId?: string
    ) => {
      const effectiveSelected = config?.selectedServerId;
      const fallback =
        fallbackExitAfterDelete(
          servers,
          effectiveSelected,
          removedIds,
          useLatencyStore.getState().latencyMap
        ) ?? DIRECT_SERVER_ID;
      for (const server of targets) {
        stage({
          id: `server:${server.id}`,
          kind: 'server',
          label: `${t('common.delete')} ${server.name}`,
          entityPath: ['servers', server.id],
          nextValue: null,
          groupId,
          selectedServerFallback:
            effectiveSelected === server.id ? fallback : undefined,
        });
      }
    },
    [config?.selectedServerId, servers, stage, t]
  );

  const subscriptions = config?.subscriptions ?? [];

  const subscriptionActions = useNodeSubscriptionActions({
    diskServers,
    stageServerDeletions,
    openDialog,
    closeDialog,
    t,
  });

  // 「添加 ▾」下拉菜单（原型 nodesAddMenu :3750：手动添加 / 手动导入 / 添加订阅）。
  const [addMenu, setAddMenu] = useState(false);
  const addWrapRef = useRef<HTMLDivElement>(null);
  /* 三处工具栏/网卡下拉菜单的定位与首项聚焦收口到 `useAnchoredMenu`（原型 miniMenu :3245-3253）：
     此前是纯 CSS 锚定（`top:calc(100% + 6px)` + `left/right:0`），零测量零 clamp ⇒ 窄窗时出屏。 */
  const addAnchored = useAnchoredMenu<HTMLButtonElement, HTMLDivElement>(addMenu, 'right');
  useEffect(() => {
    if (!addMenu) return;
    const onDown = (e: MouseEvent) => {
      if (!addWrapRef.current?.contains(e.target as Node)) setAddMenu(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setAddMenu(false);
    };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [addMenu]);

  /* ── 消费首页空状态携带的一次性意图（契约「主页 Home · 空状态」：跳 server 页携 `serverPageAction`）──
   *
   * 对齐 上游 `pages/server-page.tsx:177-191`。**读到立刻清**：不清的话用户手动关掉对话框、切走再切回
   * 本页（ScreenRouter 是裸 switch，切屏即重挂）会被同一个意图反复弹窗。清空写在同一个 effect 里，
   * 与「打开对话框」原子发生，中间没有可被别的渲染插入的窗口。 */
  const serverPageAction = useAppStore((s) => s.serverPageAction);
  const setServerPageAction = useAppStore((s) => s.setServerPageAction);
  useEffect(() => {
    if (!serverPageAction) return;
    setServerPageAction(null);
    openDialog(serverPageAction === 'add-server' ? { kind: 'node' } : { kind: 'sub' });
  }, [serverPageAction, setServerPageAction, openDialog]);

  // 分组（单一真值：自建 → 组网 → 各订阅）
  const groups = useMemo(
    () => groupServersBySubscription(servers, subscriptions, true),
    [servers, subscriptions],
  );

  const manualCount = groups.find((g) => g.isManual)?.servers.length ?? 0;
  const meshCount = groups.find((g) => g.isMesh)?.servers.length ?? 0;
  const subCount = servers.length - manualCount - meshCount;
  const statsText = t('nodes.stats', {
    total: servers.length,
    manual: manualCount,
    mesh: meshCount,
    sub: subCount,
  });

  /**
   * 当前激活 tab（manual/mesh/订阅 id）—— 落地 tab 在**首帧就地派生**，不经 effect 修正。
   *
   * # 为什么初值必须是派生的
   *
   * 原实现是 `useState('manual')` + 一条 `useEffect` 定位到 `initialNodesTab(...)`。`useEffect`
   * 在浏览器**绘制之后**才跑 ⇒ 「自建」那一帧是真的被画出来的：点导航进本页会先看到自建组
   * （只有 1 张自建卡、无订阅信息栏），下一帧才跳到选中节点所在的订阅组 —— 即真机反馈的
   * 「先从自建到实际选中的订阅组一闪而过」。判据（`initialNodesTab`）一直是对的，错的是它被
   * **晚一帧**消费。`useState` 的惰性初值在首次渲染**期间**求值，故首帧画出来的就是正确那组。
   *
   * # 为什么不再需要 effect 补定位
   *
   * 原来那条 effect 的 `if (!want) return` 是为「groups 未水合」留的重试腿，但本屏的 groups 走
   * `groupServersBySubscription(..., true)`，「自建」「组网」两个常驻空组恒在（见该函数
   * `includeEmptyGroups` 注释）⇒ 本屏 groups 恒非空 ⇒ `initialNodesTab` 在此恒有解，
   * 那条腿是死码。`?? 'manual'` 只为吃掉签名里的 `null`，不承载行为。
   *
   * 定位仍**只做一次**（挂载那一次）：之后 tab 归用户，否则用户手动切走后任何一次
   * servers/selected 变动都会把 tab 抢回去。ScreenRouter 离开本页即卸载，故「每次进页面重新定位」
   * 由重挂天然提供 —— 这条语义原先靠 `locatedRef` 守，现在由「初值只求值一次」直接给出。
   */
  const [activeTab, setActiveTab] = useState<string>(
    () => initialNodesTab(groups, selectedServerId) ?? 'manual'
  );
  // 挂载之后的兜底：当前 tab 对应的组消失（订阅被删/清空）→ 回落首组，不留空白页。
  useEffect(() => {
    if (groups.length > 0 && !groups.some((g) => g.id === activeTab)) {
      setActiveTab(groups[0].id);
    }
  }, [groups, activeTab]);

  const activeGroup = groups.find((g) => g.id === activeTab);
  const activeSub: SubscriptionConfig | undefined =
    activeGroup && !activeGroup.isManual && !activeGroup.isMesh
      ? subscriptions.find((s) => s.id === activeGroup.id)
      : undefined;
  // 原型 syncNodeToolbar：isSub = tab id 以 'sub-' 开头；本应用订阅 tab 的 id 就是订阅 id（非 manual/mesh）。
  const isSubTab = !!activeSub;
  // 全量订阅进度只订阅一次：当前 tab 的信息栏和顶部全部订阅 tab 共用这一份会话态，失败因而不会只在
  // 用户恰好打开的那条订阅上可见。done/unchanged 的清除、fetching 的重试覆盖仍由 store reducer 单点负责。
  const subscriptionProgress = useSubscriptionProgressStore((s) => s.progress);
  const activeSubProgress = activeSub ? (subscriptionProgress[activeSub.id] ?? null) : null;

  // 工具栏态。视图档（卡片/列表）是**持久偏好**，不是组件私有 state：ScreenRouter 切屏即卸载重挂，
  // 局部 state 会把用户选的列表视图悄悄改回卡片（见 use-node-view-store 头注）。
  const view = useNodeViewStore((s) => s.view);
  const setView = useNodeViewStore((s) => s.setView);
  const [search, setSearch] = useState('');
  const [protoFilter, setProtoFilter] = useState('');

  // 排序键的「延迟」档 = useNodeSortStore.sortByLatency，**不是**局部 state：原型 :4475 明写「single source of
  // truth: every latency-sort switch (toolbar + Home dropdown) reflects st.latencySort; persisted + tray-synced」，
  // 且 :3012 `if(st.latencySort) st.nodeSort={key:'lat',dir:'asc'}` —— 工具栏排序键由该开关派生。另起局部 state
  // 会让工具栏 / 首页下拉 / 托盘三处各持一份「按延迟排序」，且丢掉持久化（store 已管 localStorage）。
  const sortByLatency = useNodeSortStore((s) => s.sortByLatency);
  const setSortByLatency = useNodeSortStore((s) => s.setSortByLatency);
  // 其余档（默认/名称/协议）无跨端语义（托盘只认「按延迟」与否），留局部态——原型 st.nodeSort 亦不持久化。
  const [nonLatencySortKey, setNonLatencySortKey] = useState<SortKey>('default');
  const sortKey: SortKey = sortByLatency ? 'lat' : nonLatencySortKey;
  const setSortKey = useCallback(
    (key: SortKey) => {
      setSortByLatency(key === 'lat');
      if (key !== 'lat') setNonLatencySortKey(key);
    },
    [setSortByLatency]
  );
  // 多选
  const [batchMode, setBatchMode] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

  const exitBatch = useCallback(() => {
    setBatchMode(false);
    setSelectedIds(new Set());
  }, []);

  /* 勾选集的**淘汰腿**：节点集一变（删除 / 订阅刷新的 reconcile / 撤销暂存新增），已经不存在的 id
     必须离开勾选集。没有这条腿，勾选集只增不减 —— 「已选 N 个」会把幽灵 id 算进去，`selectAll`
     的「是否已全选」（`selectedIds.size === visibleServers.length`）也会因此判错。
     判据取**全量节点集**而不是可见集：切 tab / 改搜索词只是换视野，把勾选集跟着清掉会让用户
     每敲一个字符就丢一次选择；「看不见的不该被操作」由各批量动作与可见集求交负责
     （`selectedVisibleIds`），两条腿分工不同，不可互相替代。
     无淘汰时原样返回 `prev`（同一引用）—— 否则每次 `servers` 变都换一个新 Set，白掉一轮重渲。 */
  useEffect(() => {
    setSelectedIds((prev) => {
      if (prev.size === 0) return prev;
      const alive = new Set(servers.map((server) => server.id));
      const next = new Set<string>();
      prev.forEach((id) => {
        if (alive.has(id)) next.add(id);
      });
      return next.size === prev.size ? prev : next;
    });
  }, [servers]);

  /* 原型 syncNodeToolbar 在切到订阅 tab 时强退批选（`if(isSub && st.batchMode) toggleBatch();`），
     因为原型的批选按钮在订阅 tab 整颗隐藏。本仓改为**订阅 tab 也可批选**（陈先生 2026-07-29 裁定）：
     批选条里「测速所选 / 复制链接」对订阅节点完全成立，被一刀切的守卫连带砍掉是过宽；
     不成立的只有「移动到分组 / 删除」两项，改为在订阅 tab 下不渲染那两颗（见批选条）。
     故此处的自动强退一并撤除 —— 留着会让用户在订阅 tab 刚开批选就被弹出去。 */

  /* ── 设为出口（整卡点击 + 卡上按钮共用这一条腿）──
   *
   * 切换本体走 `useSwitchNode`，与首页出口选单同一份实现（先判后切 / 差集走 pull / toast 互斥）。
   *
   * **默认单击直切，不套二次确认**：`server_switch` 只写 `selectedServerId` + 广播，不重启内核，
   * 且它在暂存层 `BYPASS_TABLE` 里被显式豁免（W-1，理由「首页出口框/状态栏节点名实时回显它」）——
   * 设计上就是同步即时操作。误点的代价是「卡片立刻变 .cur、状态栏节点名变、再点一下切回」，
   * 用高频动作的确认税去防这个是亏的；更要紧的是全仓 `useConfirmTwice` 现在只服务删除/清空/重置，
   * 掺进一个可逆操作会让「点两次 = 有危险」这个信号失效。
   *
   * **唯一例外**：选中「待入池/待生效」差集里的节点会让它由未引用变被引用 ⇒ 恒立即整核重启、
   * 断掉现有连接。那一次确认有信息量，故武装 confirmTwice。
   * 武装判据读 store 快照即可（它只决定「要不要先确认」这一步，滞后一拍最多是少确认一次）；
   * 真正的 toast 分支仍由 `useSwitchNode` 内部按 pull 到的**切换前瞬时**真值决定。
   * 谓词复用 `willRestartOnSelect`（首页预判同一个）—— 在这里另写一份 `added ∪ modified` 就是
   * 把同一条判据分叉成两份，改一处忘一处时两个入口的确认行为会不一致。
   */
  const switchNode = useSwitchNode();
  const pendingChanges = useAppStore((s) => s.pendingChanges);
  const useNode = useCallback(
    (server: ServerConfig, via: NodeUseVia) => {
      const action = nodeUseAction(
        server.id,
        selectedServerId,
        willRestartOnSelect(pendingChanges, server.id),
        via
      );
      if (action === 'noop') return;
      // 显式按钮 + 不重启那档：直切，不收确认税（判据见 nodeUseAction 头注）。
      if (action === 'switch') {
        void switchNode(server.id);
        return;
      }
      // 第一下只武装时给一条 toast —— 整卡点击没有「按钮翻红」那样的就地视觉出口
      // （卡上那颗按钮有 `.confirming`，但用户点的往往是卡面），不提醒就等于点了没反应。
      // `armed` 变了才提醒：第二下（真正执行）不该再弹。
      if (confirmArmed !== `node-use:${server.id}`) {
        toast.info(
          action === 'confirm-restart'
            ? t('nodes.useConfirmRestartToast', {
                node: server.name,
              })
            : t('nodes.useConfirmToast', {
                node: server.name,
              })
        );
      }
      confirmTwice(`node-use:${server.id}`, () => void switchNode(server.id));
    },
    [selectedServerId, pendingChanges, confirmArmed, confirmTwice, switchNode, t]
  );

  /**
   * 启动 gate 剔除的非法节点（`EVENT_PROXY_INVALID_NODES` → App.tsx → store）。
   * store 早已存着，但节点卡此前零消费 → 被剔掉的节点在列表里和正常的长得一模一样，
   * 用户选中它、连不上、无从得知原因（上游 `server-card.tsx:58` 是消费的）。
   */
  const invalidNodes = useAppStore((s) => s.invalidNodes);
  const invalidIndex = useMemo(() => invalidNodeIndex(invalidNodes), [invalidNodes]);

  // 组网同网段「被覆盖（shadowed）」角标（契约·节点角标一节）。判据/口径见 nodes-logic.ts
  // `shadowedCidrIndex`/`shadowedCidrNamed` 的 JSDoc（含与 `meshForceRoutedServers` 发射端同口径的约束）。
  const ruleTargetedServerIds = useMemo(
    () => collectRuleTargetedServerIds([...(config?.customRules ?? []), ...(config?.appRules ?? [])]),
    [config?.customRules, config?.appRules]
  );
  const shadowedIndex = useMemo(
    () => shadowedCidrIndex(servers, selectedServerId, ruleTargetedServerIds),
    [servers, selectedServerId, ruleTargetedServerIds]
  );
  const serverNameById = useMemo(
    () => new Map(servers.map((s) => [s.id, s.name])),
    [servers]
  );
  const shadowedNamed = useMemo(
    () => shadowedCidrNamed(shadowedIndex, serverNameById),
    [shadowedIndex, serverNameById]
  );

  // 测速态。结果读**全局 store**、进度走**全局 toast**（两者订阅都在 App.tsx 顶层，切屏不丢）。
  // 本屏只留 `testing` 这一位灰态（按钮禁用），它是本屏控件的属性、天然是组件私有。
  // 勿把延迟改回 useState，也勿把进度订阅搬回来——那正是「切屏即丢」的来源。
  const { visibleServers, renderedServers, gridRef } = useNodesRenderWindow({
    activeGroup,
    search,
    protoFilter,
    sortKey,
    activeTab,
  });

  const protoOptions = useMemo(() => {
    if (!activeGroup) return [];
    const set = new Set<string>();
    activeGroup.servers.forEach((s) => set.add(s.protocol));
    return [...set].sort();
  }, [activeGroup]);

  /**
   * 测速可行性的 **path-aware 能力位**（与首页 `HomeScreen:657` 同一个位）：主核 probe 池是否可用
   * = 代理是否在跑。TS-exit 只有主核池路径能测（临时核建不出第二 tsnet 实例），少了这个位
   * 会把「代理没跑时的 TS 节点」当可测发出去，换回一个必然的 `-1`（UI 上读作「真实超时」）。
   */
  const proxyStatus = useAppStore((s) => s.proxyStatus);
  const speedTestCaps = useMemo<SpeedTestCaps>(
    () => ({ mainCorePool: !!proxyStatus?.running }),
    [proxyStatus?.running]
  );

  const {
    testing,
    testAll,
    testVisible,
    testSelected,
    testOne,
    blockedHint,
  } = useNodeSpeedTest({
    servers,
    visibleServers,
    selectedIds,
    speedTestCaps,
    stagedOnly,
    t,
  });

  const {
    copyLink,
    cloneServer,
    editNode,
    toggleSelect,
    selectAll,
    copyLinksBatch,
  } = useNodeActions({
    servers,
    t,
    stagingEnabled,
    stage,
    openDialog,
    selectedIds,
    setSelectedIds,
    visibleServers,
  });

  // Tailscale 登出（契约 L46「tailscale:logout（清 state 保配置）」）：后端命令与 mesh 实现均已就位
  // （server.rs tailscale_logout → runtime/mesh.rs 清 state 目录、保留节点配置/authKey）。
  // 登录态经 setTailscaleLoginState 写回——它是该真值的**唯一入口**（自身文档「STATUS 流 / state 清除事件的
  // 唯一入口」，内部已双写内存态 + localStorage 缓存）。登出正是「state 清除事件」；不写则卡片角标仍显「已登录」。
  const setTailscaleLoginState = useAppStore((s) => s.setTailscaleLoginState);
  const tsLogout = useCallback(
    async (node: ServerConfig) => {
      // `block`（ENTITY_ACTION_TABLE）：登出清的是磁盘上的 TS state 目录，盘上没有这个节点就没有对象。
      const split = splitStagedOnly(
        'server.tailscaleLogout',
        [node.id],
        stagedOnly,
        stagedEntries,
        'servers'
      );
      if (split.blocked.length > 0) {
        toast.info(t('home.stagedOnlyBlocked'));
        return;
      }
      try {
        await api.server.tailscaleLogout(node.id);
        setTailscaleLoginState(node.id, false);
        toast.success(t('nodes.meshTsLogoutOk'));
      } catch (err) {
        console.error('[NodesScreen] tailscale logout failed:', err);
        toast.error(t('nodes.meshTsLogoutFail'));
      }
    },
    [setTailscaleLoginState, stagedOnly, stagedEntries, t]
  );

  const nodeDeletion = useNodeDeletion({
    diskServers, selectedServerId, stagedDeleted, stagedOnly, stagedEntries,
    nodeDeletePolicy, revertStaged, stageServerDeletions, selectedIds, visibleServers, exitBatch,
    confirmTwice, t, openDialog, closeDialog,
  });
  const deleteNode = nodeDeletion.deleteNode;

  /**
   * 全局「添加」菜单中的组网接入腿。所有 Tab 共用同一个入口；打开前先切到组网，提交后新增卡片
   * 直接出现在用户当前所见的分组里。接入协议选择继续由 MeshJoinDialog 承担，避免把五种协议铺满菜单。
   */
  const openMeshJoin = useCallback(() => {
    setActiveTab('mesh');
    openDialog({
      kind: 'mesh-join',
      onTsLogout: (node) => void tsLogout(node),
          onWarpReregister: (node) =>
        nodeDeletion.removeWarpNode(node, {
          title: t('nodes.meshWarpReRegisterTitle'),
          message: t('nodes.meshWarpReRegisterMsg'),
          okToast: t('nodes.meshWarpReRegisterOk'),
          afterDelete: () => openDialog({ kind: 'warp', edit: false }),
        }),
      onWarpDeregister: (node) =>
        nodeDeletion.removeWarpNode(node, {
          title: t('nodes.meshWarpDeregisterTitle'),
          message: t('nodes.meshWarpDeregisterMsg'),
          okToast: t('nodes.meshWarpDeregisterOk'),
        }),
    });
  }, [openDialog, nodeDeletion, tsLogout, t]);

  return (
    <section
      id="s-nodes"
      className={cn('screen', view === 'list' && 'nodes-list-view', batchMode && 'nodes-batch-mode')}
    >
      <NodesHeader
        t={t}
        statsText={statsText}
        testAll={testAll}
        testing={testing}
        addMenu={addMenu}
        setAddMenu={setAddMenu}
        addWrapRef={addWrapRef}
        addAnchored={addAnchored}
        openDialog={openDialog}
        setActiveTab={setActiveTab}
        openMeshJoin={openMeshJoin}
      />

      <NodesTabs
        t={t}
        groups={groups}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        subscriptionProgress={subscriptionProgress}
        activeSub={activeSub}
        activeGroup={activeGroup}
        config={config}
        diskServers={diskServers}
        activeSubProgress={activeSubProgress}
        openDialog={openDialog}
        subscriptionActions={subscriptionActions}
      />

      <NodesToolbar
        t={t}
        view={view}
        setView={setView}
        search={search}
        setSearch={setSearch}
        protoFilter={protoFilter}
        setProtoFilter={setProtoFilter}
        protoOptions={protoOptions}
        sortKey={sortKey}
        setSortKey={setSortKey}
        testVisible={testVisible}
        testing={testing}
        batchMode={batchMode}
        setBatchMode={setBatchMode}
        exitBatch={exitBatch}
      />

      {batchMode && (
        <NodesBatchBar
          t={t}
          selectedIds={selectedIds}
          visibleServers={visibleServers}
          selectAll={selectAll}
          testSelected={testSelected}
          testing={testing}
          isSubTab={isSubTab}
          copyLinksBatch={copyLinksBatch}
          confirmArmed={confirmArmed}
          nodeDeletion={nodeDeletion}
          exitBatch={exitBatch}
        />
      )}

      <NodesGrid
        t={t}
        gridRef={gridRef}
        visibleServers={visibleServers}
        renderedServers={renderedServers}
        search={search}
        protoFilter={protoFilter}
        activeSub={activeSub}
        activeGroup={activeGroup}
        speedTestCaps={speedTestCaps}
        stagedOnly={stagedOnly}
        shadowedNamed={shadowedNamed}
        selectedServerId={selectedServerId}
        selectedIds={selectedIds}
        batchMode={batchMode}
        invalidIndex={invalidIndex}
        testOne={testOne}
        copyLink={copyLink}
        cloneServer={cloneServer}
        editNode={editNode}
        useNode={useNode}
        confirmArmed={confirmArmed}
        pendingChanges={pendingChanges}
        deleteNode={deleteNode}
        toggleSelect={toggleSelect}
        blockedHint={blockedHint}
      />
    </section>
  );
}

export default NodesScreen;
