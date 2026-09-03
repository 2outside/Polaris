import { useEffect, useMemo, useRef, useState } from 'react';
import type { TFunction } from 'i18next';
import type { RuleResourceListItem, RuleType, SystemProcessInfo } from '@/contracts/types';
import { RULE_TYPES } from '@/domain/rules';
import { api } from '@/ipc';
import { missingRuleSetRefs } from './rule-set-pick';
import {
  geoPoolOptions,
  processPoolOptions,
  selectedValueSet,
  sortRuleValueOptions,
  splitVals,
  type Cond,
  type RuleValueGroup,
  type RuleValueOption,
} from './rule-cond';

/** 分组切换的取值：`all` 是**默认**——它让检索永远跨组生效（分两个 tab 时「搜到了却在另一个 tab」
 *  是一类静默失败）；两个具体值来自描述符的 `GroupAxis:'origin'`。 */
export type GroupFilter = 'all' | RuleValueGroup;

/** 稳定的取数引用（放模块级：写成 `() => api.x.y()` 会每次渲染换身份，把惰性 effect 变成轮询）。 */
const listRuleResources = () => api.ruleResources.list();
const listProcesses = () => api.system.listProcesses();

/** 空快照（模块级常量：写成行内 `new Set()` 会每次渲染换身份，把 useMemo 变成每帧重排）。
 *  导出给 `RuleForm.setCondType`——切类型时快照归零的唯一重建点，判据见 `useRulePools` 头注。 */
export const EMPTY_SNAP: ReadonlySet<string> = new Set<string>();

/**
 * 惰性拉一份候选清单。`enabled` 为真才拉、只拉一次（成功或失败都不再自动重试 —— 来回切类型会
 * 变成隐式重试风暴，同 `AppAddDialog` 的 `galleryStatus` 门）。
 *
 * `failed` 与「拉到了但是空」必须分开：把**加载失败**说成**结果为空**会让用户去改搜索词，
 * 而真正的问题是清单压根没拉到（本仓同题定论见 `rule-set-pick.ts` 的 `RuleSetPickState`）。
 *
 * # 「只拉一次」的判据是 in-flight，不是 `items !== null`
 *
 * `items` 只在 settle 时才写 ⇒ **首个响应落地前的整个空窗期里 `items` 恒为 `null`**。若去重只读它，
 * 那段窗口内每一次 `enabled`/effect 重跑都会再发一次请求：反复切换条件类型即可并发发起 N 次
 * `ruleResources.list()` / `system.listProcesses()` —— 正是头一句要防的隐式重试风暴。故另立
 * `inflight` 标记，settle（成功或失败）才落下。
 *
 * # 取消腿的射程是**卸载**，不是每次 effect 重跑
 *
 * 「在飞」与「作废在飞的那个响应」不能由同一面旗管：把 `alive = false` 挂在取数 effect 的 cleanup 上，
 * 一次 `enabled` 抖动就会把唯一那趟请求的结果丢掉，而 `inflight` 又不许再发 ⇒ 永久卡在 loading。
 * 故 `alive` 改挂空依赖 effect（只在真卸载时翻），语义回到它原本要防的那件事：卸载后别 setState。
 */
function useLazyPool<T>(
  enabled: boolean,
  load: () => Promise<T[]>
): { items: T[] | null; loading: boolean; failed: boolean } {
  const [items, setItems] = useState<T[] | null>(null);
  const [failed, setFailed] = useState(false);
  const inflight = useRef(false);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true; // StrictMode 下 effect 会「挂载—卸载—再挂载」，重挂时须复位
    return () => {
      alive.current = false;
    };
  }, []);
  useEffect(() => {
    if (!enabled || items !== null || inflight.current) return;
    inflight.current = true;
    void load().then(
      (list) => {
        inflight.current = false;
        if (alive.current) setItems(Array.isArray(list) ? list : []);
      },
      () => {
        inflight.current = false;
        if (!alive.current) return;
        setFailed(true);
        setItems([]);
      }
    );
  }, [enabled, items, load]);
  return { items, loading: enabled && items === null, failed };
}

/**
 * 池条件的候选清单 / 检索 / 分组 / 排序快照——从 `RuleForm` 外提，供 `RuleCondRow.tsx` 与
 * `RuleForm` 共用同一份状态（外提原因：这一整块此前占 `RuleForm` 近 100 行，且与条件行渲染是
 * 一对一的消费关系）。
 */
export function useRulePools(conds: readonly Cond[], t: TFunction) {
  /** 「哪些池要拉」由**描述符**说了算（不点名类型）：出现该池的条件才拉，绝大多数规则一次 IPC 都不加。 */
  const usesPool = (pool: 'geoTag' | 'process') =>
    conds.some((c) => {
      const s = RULE_TYPES[c.t].source;
      return s.kind === 'pool' && s.pool === pool;
    });
  /**
   * 已下载 / 内置的规则资源清单 —— geoTag 池（规则集 / geosite / geoip 三个类型共用）的候选源。
   * 失败落空数组 = 勾选区只剩一行说明，手填腿仍在（`allowFreeInput`），不把整个条件类型堵死。
   */
  const geoPool = useLazyPool<RuleResourceListItem>(usesPool('geoTag'), listRuleResources);
  const resItems = geoPool.items;
  /** 在跑的进程清单 —— process 池（进程名 / 进程路径）的候选源。 */
  const procPool = useLazyPool<SystemProcessInfo>(usesPool('process'), listProcesses);
  /** 池 → 它的加载态（描述符只说「用哪个池」，两个池的取数各自惰性）。 */
  const poolPhase = (pool: 'geoTag' | 'process') => (pool === 'geoTag' ? geoPool : procPool);

  /**
   * 每个池条件自己的检索词与分组选择。**按类型键存**而不是按下标：规则里类型**唯一**
   * （`used` 集合强制），故类型是稳定的身份 —— 按下标存会在删掉中间某个条件时把检索词错位挪给邻居。
   */
  const [poolQuery, setPoolQuery] = useState<Partial<Record<RuleType, string>>>({});
  const [poolGroup, setPoolGroup] = useState<Partial<Record<RuleType, GroupFilter>>>({});
  /** 「只看已选」开关（第二行右侧那颗 `已选 N` chip）。同上按类型键存。 */
  const [poolOnlySel, setPoolOnlySel] = useState<Partial<Record<RuleType, boolean>>>({});

  /**
   * 候选排序用的「已选**快照**」——「已选优先」与「编辑过程不动排序」是配套的一条需求
   * （陈先生 2026-07-30），判据全文见 `sortRuleValueOptions` 头注。
   *
   * **只有两个重建时机**：① 打开弹窗（本初始化器，R1 下 `key` 重挂 = 重新初始化）；
   * ② 切换条件类型（`setCondType` —— 那时值被清空，快照跟着归零）。
   * 勾 / 取消勾**绝不重建** —— 一重建排序就成了实时的，症状是「勾一个跳一个」，
   * 而那正是本设计要避免的东西。这条有门守（`rule-cond.test.ts` 的接线组）。
   */
  const [poolSnap, setPoolSnap] = useState<Partial<Record<RuleType, ReadonlySet<string>>>>(
    () =>
      Object.fromEntries(conds.map((c) => [c.t, selectedValueSet(c.v)])) as Partial<
        Record<RuleType, ReadonlySet<string>>
      >,
  );

  /**
   * 候选面投影 —— 按**类型**而非按条件算并缓存：2000+ 条的 ruleSet 池不该在用户每敲一个字符
   * （`conds` 变）时重投一次。故依赖只取「出现了哪些类型」+ 两个池的数据。
   */
  const poolTypesKey = conds.map((c) => c.t).join('|');
  const poolOptions = useMemo(() => {
    const m = new Map<RuleType, RuleValueOption[]>();
    for (const tp of poolTypesKey.split('|').filter(Boolean) as RuleType[]) {
      const s = RULE_TYPES[tp]?.source;
      if (!s || s.kind !== 'pool' || m.has(tp)) continue;
      const raw =
        s.pool === 'geoTag'
          ? geoPoolOptions(tp, geoPool.items ?? [])
          : processPoolOptions(tp, procPool.items ?? []);
      /* 排序键取**快照**，不取实时勾选态 —— 依赖数组里因此没有 `conds`，只有 `poolSnap`
         （它一轮编辑里只在切类型时变一次）。这是本设计最容易退化的一处。 */
      m.set(tp, sortRuleValueOptions(raw, poolSnap[tp] ?? EMPTY_SNAP));
    }
    return m;
  }, [poolTypesKey, geoPool.items, procPool.items, poolSnap]);

  /**
   * 本条件引用了、但本地不可用的规则集（判据在 `rule-set-pick.ts`，与规则列表角标同一条线）。
   *
   * 清单未到位时恒空，**两种情形都要挡**：
   *  - `null` = 惰性拉取还在飞（有真实空窗期，见上方 useEffect）；
   *  - `[]` = 拉取**失败**。成功的 `rule_resources_list` 恒不为空 —— 它无条件把随包表
   *    （`builtin_geo_rulesets()`）逐条投影进结果，故空数组只可能来自上面那条 catch 腿。
   * 两种情形下 available 集合都是空的，不挡就会把每一条已有引用都报成「缺失」= 假告警。
   */
  const ruleSetMissing = (currentVal: string): string[] =>
    resItems && resItems.length > 0 ? missingRuleSetRefs(splitVals(currentVal), resItems) : [];

  /**
   * 「一条都挑不出来」时那一句话 —— **三态各说各的，绝不混用**。
   *
   * 把**加载失败**说成**结果为空**是谎报，而且比一般谎报更坏：用户会去改搜索词，而真正的问题是
   * 清单压根没拉到。同题定论见 `ResCatalogDialog.extStatusText`（特意把 `preload` 与 `cache` 分开，
   * 就为了「任何一态都不谎称『已从远程获取』」）。
   *
   * 同一个字符串同时喂给**勾选区里那一行**与**「前往规则资源」提示行**，于是两处不可能各说一套。
   * 挑得出来时取空串：那时压根不显示这一句。
   */
  const poolEmptyText = (loading: boolean, failed: boolean, matched: number): string =>
    loading
      ? t('common.loading')
      : failed
        ? t('rules.candidatesFailed')
        : matched === 0
          ? t('common.noResults')
          : '';

  return {
    resItems,
    poolPhase,
    poolQuery,
    setPoolQuery,
    poolGroup,
    setPoolGroup,
    poolOnlySel,
    setPoolOnlySel,
    poolSnap,
    setPoolSnap,
    poolOptions,
    ruleSetMissing,
    poolEmptyText,
  };
}
