import type { TFunction } from 'i18next';
import { Csel } from '@/components/dialogs/Csel';
import { cn } from '@/lib/utils';
import type { NodesListSortKey } from './nodes-list-projection';

type SortKey = NodesListSortKey;
type View = 'cards' | 'list';

interface Props {
  t: TFunction;
  view: View;
  setView: (view: View) => void;
  search: string;
  setSearch: (v: string) => void;
  protoFilter: string;
  setProtoFilter: (v: string) => void;
  protoOptions: string[];
  sortKey: SortKey;
  setSortKey: (key: SortKey) => void;
  testVisible: () => void;
  testing: boolean;
  batchMode: boolean;
  setBatchMode: (v: boolean) => void;
  exitBatch: () => void;
}

/** `.node-toolbar`：视图切换 + 搜索 + 协议/排序筛选 + 测速（可见集）+ 多选开关。 */
export function NodesToolbar({
  t,
  view,
  setView,
  search,
  setSearch,
  protoFilter,
  setProtoFilter,
  protoOptions,
  sortKey,
  setSortKey,
  testVisible,
  testing,
  batchMode,
  setBatchMode,
  exitBatch,
}: Props) {
  return (
    <div className="node-toolbar" id="node-shared-tools">
      <div className="seg2 nh-view" role="group" aria-label={t('nodes.view.aria')}>
        <button
          type="button"
          className={cn(view === 'cards' && 'on')}
          onClick={() => setView('cards')}
          aria-label={t('nodes.view.cards')}
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}>
            <rect x="3" y="3" width="8" height="8" rx="1.5" />
            <rect x="13" y="3" width="8" height="8" rx="1.5" />
            <rect x="3" y="13" width="8" height="8" rx="1.5" />
            <rect x="13" y="13" width="8" height="8" rx="1.5" />
          </svg>
        </button>
        <button
          type="button"
          className={cn(view === 'list' && 'on')}
          onClick={() => setView('list')}
          aria-label={t('nodes.view.list')}
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}>
            <path d="M8 6h13M8 12h13M8 18h13M3.5 6h.01M3.5 12h.01M3.5 18h.01" />
          </svg>
        </button>
      </div>

      <label className="input search-box nh-search">
        <svg viewBox="0 0 24 24" width={15} fill="none" stroke="currentColor" strokeWidth={1.8}>
          <circle cx="11" cy="11" r="7" />
          <path d="M20 20l-3-3" />
        </svg>
        <input
          id="node-search"
          type="search"
          placeholder={t('nodes.search.placeholder')}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </label>

      <Csel
        className="nt-proto"
        id="node-proto-filter"
        ariaLabel={t('nodes.filter.protocol')}
        value={protoFilter}
        onChange={setProtoFilter}
        options={[
          { value: '', label: t('nodes.filter.allProto') },
          ...protoOptions.map((p) => ({ value: p, label: p })),
        ]}
      />

      <Csel
        className="nh-sort"
        id="node-sort"
        ariaLabel={t('nodes.sortBy')}
        value={sortKey}
        onChange={(v) => setSortKey(v as SortKey)}
        options={[
          { value: 'default', label: t('nodes.sort.default') },
          { value: 'name', label: t('nodes.sort.name') },
          { value: 'lat', label: t('nodes.sort.latency') },
          { value: 'proto', label: t('nodes.sort.protocol') },
        ]}
      />

      {/* 测的是搜索/协议筛选之后**你眼前这些**（∩ 可测集），不是整组。
          射程由 `data-tip` 说明承载，不写进按钮字面（陈先生 2026-07-29 裁定）。 */}
      <button
        type="button"
        className="btn ghost sm"
        onClick={testVisible}
        disabled={testing}
        data-tip={t('nodes.testVisibleHint')}
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}>
          <path d="M13 2L4 14h6l-1 8 9-12h-6z" />
        </svg>
        <span>{t('nodes.testVisible')}</span>
      </button>

      {/* 多选。原型 `.nt-hide-sub` 在订阅 tab 整颗隐藏，**本仓不再隐藏**（理由见上方 syncNodeToolbar
          那段注释）：批选条按 tab 裁动作，而不是按 tab 裁掉整个批选能力。 */}
      <button
        type="button"
        id="batch-toggle"
        className={cn('btn ghost sm nt-hide-sub', batchMode && 'on')}
        aria-pressed={batchMode}
        onClick={() => (batchMode ? exitBatch() : setBatchMode(true))}
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}>
          <path d="M9 11l3 3L22 4" />
          <path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11" />
        </svg>
        <span>{t('nodes.batch')}</span>
      </button>
    </div>
  );
}
