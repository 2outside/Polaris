import type { TFunction } from 'i18next';
import type { RuleResourceListItem, RuleType } from '@/contracts/types';
import { RULE_TYPES, ruleTypeHintKey, ruleTypeNameKey, ruleTypePlaceholderKey } from '@/domain/rules';
import { cn } from '@/lib/utils';
import { useScrollBatch } from '@/lib/use-scroll-batch';
import type { MainScreen } from '@/store/nav-store';
import { Csel, type CselGroup } from './Csel';
import { Fold } from '@/components/Fold';
import { ruleSetPickState } from './rule-set-pick';
import type { GroupFilter } from './use-rule-pools';
import {
  matchRuleValueOptions,
  offPoolSelectedOptions,
  selectedValueSet,
  type RuleValueOption,
} from './rule-cond';

/**
 * 候选勾选区 —— 一个类型一个实例。
 *
 * 独立组件而不是内联 JSX：分批渲染要 `useScrollBatch`，而条件数是变的（0–5 个池条件），
 * 在 `conds.map` 里调 hook 会违反 hooks 的调用序稳定性。
 *
 * chip 形态复用 `.tagchip`（AppAddDialog 的标签勾选区同款）。它的浅色分离度 2026-07-30 实测过：
 * ΔL*=5.29 / 4.61:1，落在「已接受」档，故直接复用不另立视觉（结论与其载荷记在
 * `styles/index.css` 的「C) chip 族的浅色实测」段，有门守）。
 */
function RuleValuePick({
  options,
  batch,
  resetKey,
  selected,
  onToggle,
  emptyText,
  moreText,
  ariaLabel,
}: {
  options: readonly RuleValueOption[];
  /** 描述符的 `scale === 'large'`：只有大池才分批（小池一次渲完，省一层滚动监听）。 */
  batch: boolean;
  /** 结果集身份（检索词 + 分组）—— 一变即回首批。 */
  resetKey: string;
  selected: ReadonlySet<string>;
  onToggle: (value: string) => void;
  emptyText: string;
  moreText: (shown: number, total: number) => string;
  ariaLabel: string;
}) {
  const { count, onScroll } = useScrollBatch(options.length, resetKey);
  const shown = batch && options.length > count ? options.slice(0, count) : options;
  return (
    <div className="rv-pick" role="group" aria-label={ariaLabel} onScroll={batch ? onScroll : undefined}>
      {options.length === 0 ? (
        <div className="card-sub rv-note">{emptyText}</div>
      ) : (
        <>
          {shown.map((o) => {
            const on = selected.has(o.value.toLowerCase());
            return (
              <button
                key={o.value}
                type="button"
                /* `off-pool` = 已选但候选池里没有（手填 / 本地还没下载 / 进程没在跑）。虚线描边 +
                   warn 色边把它与「池里的正常候选」显式分开，`data-tip` 说清是哪一种。 */
                className={cn('tagchip', on && 'on', o.offPool && 'off-pool')}
                aria-pressed={on}
                data-tip={o.hint}
                onClick={() => onToggle(o.value)}
              >
                {o.label}
              </button>
            );
          })}
          {options.length > shown.length && (
            <div className="card-sub rv-note">{moreText(shown.length, options.length)}</div>
          )}
        </>
      )}
    </div>
  );
}

export interface CondRowProps {
  c: { t: RuleType; v: string };
  i: number;
  condsLength: number;
  t: TFunction;
  poolQuery: Partial<Record<RuleType, string>>;
  setPoolQuery: (updater: (prev: Partial<Record<RuleType, string>>) => Partial<Record<RuleType, string>>) => void;
  poolGroup: Partial<Record<RuleType, GroupFilter>>;
  setPoolGroup: (updater: (prev: Partial<Record<RuleType, GroupFilter>>) => Partial<Record<RuleType, GroupFilter>>) => void;
  poolOnlySel: Partial<Record<RuleType, boolean>>;
  setPoolOnlySel: (updater: (prev: Partial<Record<RuleType, boolean>>) => Partial<Record<RuleType, boolean>>) => void;
  poolOptions: Map<RuleType, RuleValueOption[]>;
  poolPhase: (pool: 'geoTag' | 'process') => { loading: boolean; failed: boolean };
  resItems: RuleResourceListItem[] | null;
  ruleSetMissing: (currentVal: string) => string[];
  poolEmptyText: (loading: boolean, failed: boolean, matched: number) => string;
  typeGroups: (currentType: RuleType) => CselGroup[];
  setCondType: (i: number, tp: RuleType) => void;
  setCondVal: (i: number, v: string) => void;
  toggleCondValue: (i: number, value: string) => void;
  removeCond: (i: number) => void;
  navigate: (screen: MainScreen) => void;
  closeAll: () => void;
}

/** 一条规则条件行（`.cond-row`）：类型 + 搜索/分组切换 + 候选勾选区 + 手填折叠 + 规则集缺失提示。 */
export function CondRow({
  c,
  i,
  condsLength,
  t,
  poolQuery,
  setPoolQuery,
  poolGroup,
  setPoolGroup,
  poolOnlySel,
  setPoolOnlySel,
  poolOptions,
  poolPhase,
  resItems,
  ruleSetMissing,
  poolEmptyText,
  typeGroups,
  setCondType,
  setCondVal,
  toggleCondValue,
  removeCond,
  navigate,
  closeAll,
}: CondRowProps) {
  const desc = RULE_TYPES[c.t];
  const src = desc.source;
  /** 该条件是否走 `res:<id>` 寻址（= 规则集）—— 描述符字段，不点名类型。 */
  const isResRef = src.kind === 'pool' && src.addressing === 'res-id';
  const query = poolQuery[c.t] ?? '';
  const group = poolGroup[c.t] ?? 'all';
  /* 候选面：`kind==='free'` ⇒ 恒 null，右侧**不渲染任何控件**（渲染一个禁用的搜索框
     是假控件：它宣称「这里可以搜」，而这个类型压根没有候选源）。 */
  const all = src.kind === 'pool' ? (poolOptions.get(c.t) ?? []) : null;
  const matched = all ? matchRuleValueOptions(all, query) : null;
  /* 分组切换只在「描述符声明了轴」且「两组都真有东西」时出现：外置一条没下载时给个空 tab
     是让用户去点一个必然空的东西。 */
  const groupsPresent =
    src.kind === 'pool' && src.groupBy !== null && all
      ? (['builtin', 'external'] as const).filter((g) => all.some((o) => o.group === g))
      : [];
  const selected = selectedValueSet(c.v);
  const onlySel = poolOnlySel[c.t] === true;
  const poolLoading = src.kind === 'pool' && poolPhase(src.pool).loading;
  const poolFailed = src.kind === 'pool' && poolPhase(src.pool).failed;
  /* 「已选但候选池里没有」的值 —— 手填的 / 引用了本地还没下载的 tag / 给未运行的应用建的
     进程规则。文本框折叠之后它们若不在这里露面就**看不见也删不掉**（判据见
     `offPoolSelectedOptions` 头注）。

     **加载中一律不判**（同 `ruleSetMissing` 的既有口径）：那一刻 `all` 是空的，不挡就会
     把这条规则里**每一个**已选值都标成「本地暂无」，等清单到了再全部翻回去 —— 一次
     秒级的、内容完全相反的闪烁，比晚半秒露面糟得多。
     **加载失败则必须露面**：清单永远不会来了，此刻它们是唯一入口；但提示词换成
     「候选清单加载失败」—— 三态各说各的，把加载失败说成「本地暂无」会让用户跑去
     下载一个本来就在本地的东西（同题定论见 `poolEmptyText`）。
     正常态的提示词按**池**分（描述符字段，不点名类型）：geo 池 = 本地暂无；
     进程池 = 那个进程当前没在跑。 */
  const offHint = poolFailed
    ? t('rules.candidatesFailed')
    : src.kind === 'pool' && src.pool === 'process'
      ? t('rules.candidateNotRunning')
      : t('rules.candidateNotLocal');
  const offPool = all && !poolLoading ? offPoolSelectedOptions(c.v, all, offHint) : null;
  const grouped =
    matched && groupsPresent.length > 1 && group !== 'all'
      ? matched.filter((o) => o.group === group)
      : matched;
  const poolShown =
    grouped && onlySel ? grouped.filter((o) => selected.has(o.value.toLowerCase())) : grouped;
  /* 池外已选**恒排最前、且不受分类切换影响** —— 它们既不属内置也不属外置，按来源把一个
     压根没有来源的值筛掉，等于把刚露出来的值又藏了一次。检索词仍作用于它们（用户主动
     缩小范围时不该有豁免项）；「只看已选」对它们天然是恒真。 */
  const shownOpts =
    offPool && poolShown ? [...matchRuleValueOptions(offPool, query), ...poolShown] : poolShown;
  const emptyText = poolEmptyText(poolLoading, poolFailed, shownOpts?.length ?? 0);
  /* 「一条都挑不出来」与缺失引用**各自对应一个真实时刻**（陈先生 2026-07-30 裁定：
     两个都要，不互斥）。三态文案各不相同，但「前往规则资源」三态都给 —— 都是有效出路。

     提示行的文案必须从 `rsPick`（本腿自己的三态）取，**不能借勾选区的 `emptyText`**：
     `emptyText` 的第三个实参是 `shownOpts.length`，而 `shownOpts` 里排在最前的是**池外已选**
     （手填的 / 本地还没下载的 tag，见上方 `offPool`）—— 检索把池内条目全滤掉、勾选区却因为
     那几个池外值仍非空时，`poolEmptyText` 返回空串，警告行就渲染成「只有三角图标和按钮、
     没有一个字」。同一份 `poolEmptyText` 仍是唯一文案源（三态说法两处一致），只是各自喂
     各自的命中数：勾选区那行说的是「勾选区空不空」，提示行说的是「规则集挑不挑得出来」。 */
  const rsMissing = isResRef ? ruleSetMissing(c.v) : [];
  const rsPick = isResRef ? ruleSetPickState(resItems, query) : 'ok';
  const rsEmpty = rsPick !== 'ok';
  /** 提示行腿②的那一句。只在 `rsEmpty` 时渲染 ⇒ 命中数恒 0，三态由 loading/failed 两位分派。 */
  const rsEmptyText = poolEmptyText(rsPick === 'loading', rsPick === 'failed', 0);
  /* 手填腿。有候选区时**默认折叠**（原型 `.fld-fold`，与传输层/detour/订阅高级同一形态）。 */
  const valInput = (
    <textarea
      className={cn('input mono cond-val-input', all && 'compact')}
      rows={all ? 2 : 4}
      value={c.v}
      onChange={(e) => setCondVal(i, e.target.value)}
      placeholder={t(ruleTypePlaceholderKey(c.t))}
      aria-label={t('rules.condValues')}
    />
  );
  return (
    <div className="cond-row">
      <div className="cond-fields">
        {/* 条件行头部：[类型 170px][搜索框 flex:1] 同排，[分类切换] 独占第二行
            （`kind==='free'` ⇒ 右侧留空，**不渲染禁用的假控件** —— 一个禁用的搜索框在宣称
            「这里可以搜」，而这个类型压根没有候选源）。为什么分类切换不挤在同一排：
            206px 的余量塞不下三件套，而换行时先掉下去的恰是检索框（见 styles/index.css）。
            `.cond-row` 的 grid 不动，右列仍是 `.cond-del`。 */}
        <div className="cond-head">
          <Csel
            ariaLabel={t('rules.matchType')}
            value={c.t}
            onChange={(v) => setCondType(i, v as RuleType)}
            options={typeGroups(c.t)}
          />
          {all && (
            <label className="input search-box">
              <svg viewBox="0 0 24 24" width={14} fill="none" stroke="currentColor" strokeWidth={1.8}>
                <circle cx="11" cy="11" r="7" />
                <path d="M20 20l-3-3" />
              </svg>
              <input
                type="search"
                value={query}
                onChange={(e) => setPoolQuery((prev) => ({ ...prev, [c.t]: e.target.value }))}
                placeholder={t('common.search')}
                aria-label={t('common.search')}
              />
            </label>
          )}
          {/* 第二行 = `[内置 | 外置 seg2]` + `[已选 N]` chip。geo 池两个都有，进程池只有后者
              （它无 `groupBy`，本来没这一行）。
              为什么筛选做成 chip 而不是「已选/未选/全部」三档 seg2：这一行已被分类切换占，
              再塞一组约 120px 的 seg2 在 384px 的 `.cond-fields` 里会挤爆（弹窗不加宽是既有
              裁定）；且「未选」那一档几乎无场景 —— 已选已被排序顶到最前，其余就是未选。
              chip 把计数与开关二合一，约 60px。取消勾选后 N 会变，但**列表不重排**（排序键
              是快照）。
              分类切换本身：描述符声明了轴、且**两组都真有东西**才出现（外置一条没下载时给个
              空 tab，是让用户去点一个必然空的东西）。`全部` 是默认档 —— 分两个 tab 时
              「搜到了却在另一个 tab」是一类静默失败，默认跨组就没有这回事。 */}
          {all && (
            <div className="cond-grp-row">
              {groupsPresent.length > 1 && (
                <div className="seg2 cond-grp" role="group" aria-label={t('rules.candidateGroup')}>
                  {(['all', ...groupsPresent] as GroupFilter[]).map((g) => (
                    <button
                      key={g}
                      type="button"
                      className={cn(group === g && 'on')}
                      onClick={() => setPoolGroup((prev) => ({ ...prev, [c.t]: g }))}
                    >
                      {g === 'all'
                        ? t('common.all')
                        : g === 'builtin'
                          ? t('resCatalog.builtin')
                          : t('resCatalog.external')}
                    </button>
                  ))}
                </div>
              )}
              <button
                type="button"
                className={cn('ap-chip cond-sel-chip', onlySel && 'on')}
                aria-pressed={onlySel}
                onClick={() => setPoolOnlySel((prev) => ({ ...prev, [c.t]: !onlySel }))}
              >
                {t('rules.candidateSelected', { n: selected.size })}
              </button>
            </div>
          )}
        </div>
        {/* 逐类型填写提示 —— locale 里那张 `rules.typeHints.*` 表（五语齐全）此前**零消费点**，
            15 条提示一条都没显示过。放在勾选区之上：geosite/geoip 那两句写着「或从下方候选中
            勾选」，指的就是紧接其下的那块勾选区（旧词是 上游 遗留的「常用标签」，引用了一个
            当时不存在的控件，本批随控件落地一并改词，五语同改）。 */}
        <div className="card-sub">{t(ruleTypeHintKey(c.t))}</div>
        {/* 勾选区。**与下面的文本区并存**，不是二选一（`allowFreeInput`：候选面只列本地已有
            / 当前在跑的，三条不同的理由见描述符注释）。两者共用同一份 `c.v` ⇒ 勾选态与
            文本在结构上不可能失同步。自带 max-height + 滚动：不给的话 2000 条规则集会把
            弹窗那唯一的滚动容器撑成几十屏。 */}
        {shownOpts && (
          <RuleValuePick
            /* 按**类型**取 key（类型在一条规则里唯一）：`.cond-row` 用的是下标 key，
               删掉中间某条后下标会平移，分批计数会跟着串到别的条件上。 */
            key={c.t}
            options={shownOpts}
            batch={src.kind === 'pool' && src.scale === 'large'}
            resetKey={`${query}|${group}|${onlySel}`}
            selected={selected}
            onToggle={(v) => toggleCondValue(i, v)}
            emptyText={emptyText}
            moreText={(shown, total) =>
              t('appAdd.galleryMore', {
                shown,
                total,
              })
            }
            ariaLabel={t(ruleTypeNameKey(c.t))}
          />
        )}
        {/* 原型 .cond-fields > textarea.input.mono.cond-val-input（无 .fld 包裹/无可见标签，:3921）。
            有勾选区时收矮一档 + **默认折叠**（陈先生 2026-07-30：「规则对应的文本框隐藏不显示，
            避免误修改」）。折叠而不是删掉，因为 `allowFreeInput` 的三条理由一条都没消失：
            手填 `res:<id>` / 引用上游有而本地还没下载的 tag / 给未运行的应用建规则。
            而已存在规则里那些池外的值不再依赖这个框才看得见 —— 上面的勾选区已经把它们
            显式列出来且可点掉（`offPoolSelectedOptions`），文本框这才敢藏。
            **无候选区（`kind==='free'`）时不折叠**：那时 textarea 是这个类型唯一的入口，
            折起来等于把整个条件行变成一片空白。 */}
        {all ? (
          <Fold className="cond-manual" title={t('rules.manualInput')}>
            {valInput}
          </Fold>
        ) : (
          valInput
        )}
        {isResRef && (
          <>
            {/* 「前往规则资源」的出路 —— 与应用分流那条（`AppAddDialog` 的 `.warn-line` +
                同一按钮键）同形。**两个触发条件，各自对应一个真实时刻**（陈先生 2026-07-30
                裁定：不互斥，都要）：
                     ① `rsMissing` = 本条件引用了本地不可用的规则集。这是有真实后果的那个 ——
                        生成端 fail-closed 剪掉该条件、只留一行 warn ⇒ 规则静默不工作，
                        而保存前只有这里说得出来。
                     ② `rsEmpty` = 规则集清单里一条都挑不出来（`rsPick !== 'ok'`；注意**不等于**
                        「勾选区是空的」—— 勾选区还会摆上池外已选）。此刻用户的真实需求就是「我要的还没有」。
                        它**不是常驻噪音**：这一行只在挑不出来时出现，等于给勾选区里那一句说明
                        补上出路。**三态文案各不相同**（还在加载 / 清单加载失败 / 检索无命中，见
                        `poolEmptyText`）—— 把加载失败说成「无匹配」会让用户去改搜索词，而真正的
                        问题是清单压根没拉到。按钮三态都给：都是有效出路。
                    文案按严重度取：①有后果、②只是没得挑 ⇒ ① 优先；两者同时成立时勾选区里那句
                    说明已经把 ② 说了，不重复。按钮两条腿共用（去处相同）。
                    注：腿① 在 loading/failed 两态被 `ruleSetMissing` 恒抑制（那时 available 集合
                    是空的，不抑制就会把每一条已有引用报成「缺失」）⇒ 不存在「失败态说资源缺失」
                    这种不准的话；两态下显示的恒是 ② 的文案。 */}
            {(rsMissing.length > 0 || rsEmpty) && (
              <div className="warn-line">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}>
                  <path d="M12 9v4M12 17h.01" />
                  <path d="M10.3 3.9 1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z" />
                </svg>
                <span>
                  {rsMissing.length > 0
                    ? t('rules.ruleSetMissingHint', {
                        n: rsMissing.length,
                      })
                    : rsEmptyText}
                </span>
                <button
                  type="button"
                  className="btn ghost sm"
                  onClick={() => {
                    navigate('resources');
                    closeAll();
                  }}
                >
                  {t('appAdd.gotoResources')}
                </button>
              </div>
            )}
          </>
        )}
      </div>
      {condsLength > 1 ? (
        <button
          type="button"
          className="cond-del"
          aria-label={t('rules.removeCondition')}
          onClick={() => removeCond(i)}
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}>
            <path d="M5 5l14 14M19 5L5 19" />
          </svg>
        </button>
      ) : (
        <span />
      )}
    </div>
  );
}
