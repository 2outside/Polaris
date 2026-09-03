/**
 * RuleDialog —— 自定义规则增删改弹窗（第二复杂表单，原型 #rule-dialog :2722）。
 *
 * 15 类型 / 5 分组（分组走扩展 Csel 的 optgroup，见 Csel.tsx + csel-logic.ts）、
 * 目标出站按节点分组 + 默认折叠（同一套 optgroup，组带 id ⇒ 可折叠；判据见下方 targetGroups）、多条件 AND/OR、
 * 每条件多值 textarea（逗号/换行分隔，splitVals=/[,\n]/）、独立的流量 / DNS 效果、
 * 进程条件的「从进程选择」嵌套 ProcPickDialog、测试匹配折叠、编辑态 footer-左删除入口。
 *
 * 数据物料（**CONSUME domain/rules.ts，不重写**）：`RULE_TYPES`（15 份描述符 —— 分类 / 显示名 /
 * hint / placeholder / 候选源 / 可测试性的唯一源）/ RULE_CATEGORY_ORDER / DNS_EFFECT_RULE_TYPES /
 * ruleConditions。**本文件不得出现任何 `RuleType` 字面量**：一切逐类型差异都从描述符的结构字段
 * （`source.kind` / `source.pool` / `source.addressing` …）读，加第 16 个类型只改那张表。
 * 这条有门守（`domain/rules.test.ts`）。
 *
 * 提交门：**两层**。渲染层先 `validateRule`（决定能不能提交）+ `invalidCondValues`（说清哪个值不对），
 * 省掉一次「填错 → IPC 往返 → 回显」；Rust 侧 `api.rules.add`/`update` 写时再校验一次，仍是权威。
 * RULE_INVALID → 展示校验消息、弹窗不关、让用户改；其它失败 → 通用「保存失败，可重试」。
 *
 * 淬火复用（对齐 NodeDialog）：R1 无 radix/RHF —— 外层 `key={ruleId ?? 'new'}` 重挂 + useState 同步初始化，
 * 无「挂载后 reset」路径；Csel 受控无懒挂 Portal。脏态取消 → 嵌套 ConfirmDialog（复用 D1）。
 */

import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from '@/lib/error-handler';
import {
  useAppStore,
  useEffectiveConfig,
  useEffectiveRules,
  useEffectiveServers,
} from '@/store/app-store';
import type { Rule, RuleType } from '@/contracts/types';
import {
  RULE_TYPE_IDS,
  RULE_TYPES,
  DEFAULT_RULE_TYPE,
  RULE_CATEGORY_ORDER,
  ruleCategoryLabelKey,
  ruleTypeNameKey,
  findAddableRuleType,
  isRuleTypeDnsEffectSupported,
  isRuleTypePlatformSupported,
  ruleDnsEffect,
  ruleConditions,
  ruleRouteEffect,
  type RulePreset,
} from '@/domain/rules';
import { setCondTypeAt, toggleCondValueAt, type Cond } from './rule-cond';
import { useStagedConfigStore } from '@/store/staged-config-store';
import { useStagingActive } from '@/store/use-staging-active';
import { useNavStore } from '@/store/nav-store';
import { useConfirmTwice } from '@/lib/confirm-twice';
import { useRuleDelete } from '@/lib/use-rule-delete';
import { cn } from '@/lib/utils';
import { Modal } from './Modal';
import type { CselGroup } from './Csel';
import { useDialogStore } from './dialog-store';
import { useRulePools, EMPTY_SNAP } from './use-rule-pools';
import { submitRule } from './rule-submit';
import { useRuleRouteEffect, RuleRouteEffectFields } from './RuleRouteEffect';
import { useRuleDnsEffect, RuleDnsEffectFields } from './RuleDnsEffect';
import { useRuleTestFold, RuleTestFold } from './RuleTestFold';
import { CondRow } from './RuleCondRow';

function RuleIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}>
      <path d="M12 20h9M16.5 3.5a2.1 2.1 0 013 3L7 19l-4 1 1-4z" />
    </svg>
  );
}

/** `<html data-os>`（mac/win/lin）→ domain 层平台判定认的 node 风格值。取不到 → undefined（domain
 * 侧对 undefined 一律判「不支持」，即 fail-closed，与主进程丢弃条件的口径同向，不会造成假可用）。 */
const DATA_OS_TO_NODE: Record<string, NodeJS.Platform> = {
  mac: 'darwin',
  win: 'win32',
  lin: 'linux',
};
function nodePlatformFromDataOs(): NodeJS.Platform | undefined {
  const os = document.documentElement.getAttribute('data-os');
  return os ? DATA_OS_TO_NODE[os] : undefined;
}

interface RuleFormProps {
  base?: Rule;
  isEdit: boolean;
  preset?: RulePreset;
  initialPlane?: 'route' | 'dns';
}

/** footer 左侧「删除此规则」的原地二次确认 key（原型 :4095 `rule-del-dlg`）。 */
const RULE_DEL_KEY = 'rule-del-dlg';

function RuleForm({ base, isEdit, preset, initialPlane = 'route' }: RuleFormProps) {
  const { t } = useTranslation();
  const open = useDialogStore((s) => s.open);
  const close = useDialogStore((s) => s.close);
  /** 「前往规则资源」用（同 AppAddDialog:78,82 的既有做法：跳屏 + 收掉整条弹窗栈）。 */
  const closeAll = useDialogStore((s) => s.closeAll);
  const navigate = useNavStore((s) => s.navigate);
  /* 删除走原地二次点击；`requestClose` 的「放弃更改？」保留弹窗 —— 后者不是破坏性操作确认，
     原型里根本没有对应形态（`destructive-confirm-wiring.test.ts` T3 头注登记为「实现单方面新增、
     方向更好」），且它要在**关窗动作发生前**打断，按钮上没有可武装的落点。 */
  const { armed, confirmTwice } = useConfirmTwice();
  // 展示面：规则目标下拉的节点枚举（选中只写进本条规则，不触发任何按 id 查盘的后端调用）。
  const servers = useEffectiveServers();
  /** 目标下拉的分组名来源（订阅名）。展示面：暂存中新增/改名的订阅要立刻反映到组头上。 */
  const subscriptions = useEffectiveConfig((c) => c?.subscriptions);
  const dnsServers = useEffectiveConfig((c) => c?.dnsServers ?? []);
  const dnsGroups = useEffectiveConfig((c) => c?.dnsServerGroups ?? []);
  const dnsDefaults = useEffectiveConfig((c) => c?.dnsDefaults);
  const loadConfig = useAppStore((s) => s.loadConfig);
  const stagingEnabled = useStagingActive();
  const stage = useStagedConfigStore((s) => s.stage);
  /** 删除腿：与规则列表的行内垃圾桶**同一个** hook（暂存分流/撤销/直落盘三条腿都在那里）。 */
  const deleteRule = useRuleDelete(initialPlane);
  // 平台判定用的值：AppShell 已把权威平台（tauri-plugin-os）落在 <html data-os> 上，这里读它即可，
  // 不再重复嗅探。**必须映射**：data-os 是 UI 分区用的短名（mac/win/lin），而 domain 层的
  // isSourceDeviceMatchSupported 认的是 node 风格（darwin/win32/linux）——直传短名会让 macOS 被
  // 误判成「不支持设备匹配规则」，比不过滤更糟（把本来能用的功能藏掉）。
  const nodePlatform = useMemo(() => nodePlatformFromDataOs(), []);
  const baseRouteEffect = base ? ruleRouteEffect(base) : null;
  const baseDnsEffect = base ? ruleDnsEffect(base) : null;

  // 同步初始化（R1）：编辑态从 base 预填，入口 preset 显式携带类型和值，新建默认单条件。
  const [conds, setConds] = useState<Cond[]>(() => {
    if (base) {
      const cs = ruleConditions(base).map((c) => ({ t: c.type, v: c.values.join(', ') }));
      return cs.length ? cs : [{ t: DEFAULT_RULE_TYPE, v: '' }];
    }
    return [{ t: preset?.type ?? DEFAULT_RULE_TYPE, v: preset?.value ?? '' }];
  });
  // 默认 **or**：`combineMode` 缺省的权威语义就是 or —— 契约 `contracts/types/rules.ts:59`
  // 「'or'(默认，命中任一)」、Rust 生成端 `config-engine/builder/custom_rule_files.rs:273`
  // `rule.combine_mode.unwrap_or(CombineMode::Or)`、hover 卡 `RuleHoverCard.tsx:40`
  // `rule.combineMode ?? 'or'` 三处一致。此前本表单独自默认 'and'，于是**新建的多条件规则**会被写成
  // and，而单条件规则（不写 combineMode）在 hover 卡上被标「满足任一」—— 表单说 AND、卡片说 OR，
  // 同一条规则两种说法。统一到 or 后，表单默认与「不写该字段时的实际行为」对齐。
  const [logic, setLogic] = useState<'and' | 'or'>(base?.combineMode === 'and' ? 'and' : 'or');
  const routeEnabled = initialPlane === 'route';
  const dnsEnabled = initialPlane === 'dns';
  const { target, setTarget, targetGroups, targetOpenGroups } = useRuleRouteEffect(
    baseRouteEffect,
    servers,
    subscriptions,
    t,
  );
  const {
    dnsResolver,
    setDnsResolver,
    dnsAnswerMode,
    setDnsAnswerMode,
    dnsAction,
    setDnsAction,
    dnsFallbackAction,
    setDnsFallbackAction,
    dnsPredefinedRcode,
    setDnsPredefinedRcode,
    dnsPredefinedAnswer,
    setDnsPredefinedAnswer,
    dnsPredefinedNs,
    setDnsPredefinedNs,
    dnsPredefinedExtra,
    setDnsPredefinedExtra,
    dnsActionGroups,
    dnsFallbackGroups,
  } = useRuleDnsEffect(baseDnsEffect, initialPlane, dnsServers, dnsGroups, servers, dnsDefaults, t);
  const [name, setName] = useState(base?.remarks ?? preset?.value ?? '');
  const [test, setTest] = useState('');

  const [dirty, setDirty] = useState(false);
  /** 名称必填的提交后校验态（口径同 SubDialog:85 / AppAddDialog:65：提交才亮，输入即灭）。 */
  const [errName, setErrName] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const touch = () => setDirty(true);

  // 分组类型选项（15×5，唯一映射源 = RULE_TYPE_CATEGORY）；禁用「已被其它条件占用」的类型（类型唯一）
  // 或「当前平台内核不支持」的类型（device 类 = source_mac/source_hostname，仅 Linux/macOS）。
  // 不做平台过滤的后果不是显示问题而是**静默失效**：Windows 用户能选中并保存成功，但生成 sing-box
  // 配置时 custom_rules.rs 会把整条条件丢掉且不报错 —— 规则实际行为与 UI 所示不符。
  // `id === currentType` 豁免：在 macOS/Linux 建的规则拿到 Windows 上打开，仍要能看到它当前的类型。
  const typeGroups = (currentType: RuleType): CselGroup[] => {
    const used = new Set(conds.map((c) => c.t));
    return RULE_CATEGORY_ORDER.map((cat) => ({
      label: t(ruleCategoryLabelKey(cat)),
      options: RULE_TYPE_IDS.filter((id) => RULE_TYPES[id].category === cat).map((id) => ({
        value: id,
        label: t(ruleTypeNameKey(id)),
        disabled:
          id !== currentType &&
          (used.has(id) ||
            !isRuleTypePlatformSupported(id, nodePlatform) ||
            (dnsEnabled && !isRuleTypeDnsEffectSupported(id))),
      })),
    }));
  };

  /* 池条件的候选清单 / 检索 / 分组 / 排序快照——外提到 `use-rule-pools.ts`（判据/头注见该文件）。 */
  const {
    resItems,
    poolPhase,
    poolQuery,
    setPoolQuery,
    poolGroup,
    setPoolGroup,
    poolOnlySel,
    setPoolOnlySel,
    setPoolSnap,
    poolOptions,
    ruleSetMissing,
    poolEmptyText,
  } = useRulePools(conds, t);

  /** 类型切换 —— 判据与「为什么一律清空」在 `rule-cond.ts` 的 `setCondTypeAt` 头注。 */
  const setCondType = (i: number, tp: RuleType) => {
    setConds((prev) => setCondTypeAt(prev, i, tp));
    // 快照的第二个、也是**最后一个**重建时机：切类型 ⇒ 值被清空（`setCondTypeAt`）⇒ 快照归零。
    // 这一句以外不得有第二处 `setPoolSnap`，否则排序就退化成实时的（有门守）。
    setPoolSnap((prev) => ({ ...prev, [tp]: EMPTY_SNAP }));
    touch();
  };
  /** 勾选 / 取消一个候选值（与手填文本区共用同一份 `c.v` —— 结构上不可能与勾选态失同步）。 */
  const toggleCondValue = (i: number, value: string) => {
    setConds((prev) => toggleCondValueAt(prev, i, value));
    touch();
  };
  const setCondVal = (i: number, v: string) => {
    setConds((prev) => prev.map((c, idx) => (idx === i ? { ...c, v } : c)));
    touch();
  };
  const addCond = () => {
    const used = new Set(conds.map((c) => c.t));
    // findAddableRuleType = 「未占用 ∧ 本平台支持」，与下方按钮显隐同一口径（domain/rules.ts 的文档
    // 明写二者必须共用它，防「按钮显示但点了没结果」）。
    const next = findAddableRuleType(used, nodePlatform);
    if (!next) return;
    setConds((prev) => [...prev, { t: next, v: '' }]);
    touch();
  };
  const removeCond = (i: number) => {
    setConds((prev) => (prev.length > 1 ? prev.filter((_, idx) => idx !== i) : prev));
    touch();
  };

  const testResult = useRuleTestFold(conds, logic, test);

  const requestClose = () => {
    if (!dirty) {
      close();
      return;
    }
    open({
      kind: 'confirm',
      payload: {
        title: t('rules.discardTitle'),
        message: t('rules.discardMsg'),
        confirmLabel: t('rules.discard'),
        danger: true,
        onConfirm: () => {
          close(); // pop confirm
          close(); // pop 本弹窗
        },
      },
    });
  };

  /**
   * 删除本条规则 —— 原地二次点击（原型 :4095 `rule-del-dlg`），不再叠一层弹窗。
   *
   * 三条腿（撤销条目 / 暂存删除条目 / 直落盘）全在 `useRuleDelete` 里，与列表行内那颗垃圾桶共用；
   * 本处只留两件弹窗自己的事：成功即关窗、失败发一条右下角 toast（不关窗，让用户看得见原因）。
   */
  const requestDelete = () => {
    if (!base) return;
    confirmTwice(RULE_DEL_KEY, () => {
      void (async () => {
        try {
          await deleteRule(base);
          close();
        } catch (e) {
          console.error('[RuleDialog] delete failed:', e);
          toast.error(t('common.saveFailed'));
        }
      })();
    });
  };

  /* 校验 + route/DNS 二选一 effects 组装 + 暂存/落盘二选一——外提到 `rule-submit.ts`
     （route 与 DNS 的唯一耦合点即在那里：`effects.route`/`effects.dns` 二选一 + `collectionKey`）。 */
  const handleSubmit = () =>
    submitRule({
      t,
      conds,
      name,
      setErrName,
      logic,
      target,
      dnsAction,
      dnsFallbackAction,
      dnsResolver,
      dnsAnswerMode,
      dnsPredefinedRcode,
      dnsPredefinedAnswer,
      dnsPredefinedNs,
      dnsPredefinedExtra,
      isEdit,
      base,
      initialPlane,
      stagingEnabled,
      stage,
      close,
      loadConfig,
      setSubmitting,
    });

  return (
    <Modal
      titleId="rule-dlg-title"
      title={isEdit ? t('rules.editTitle') : t('rules.newTitle')}
      onClose={requestClose}
      icon={<RuleIcon />}
      footer={
        <>
          {isEdit && (
            <button
              type="button"
              className={cn('btn ghost', armed === RULE_DEL_KEY && 'confirming')}
              style={{ marginRight: 'auto', color: 'hsl(var(--err))', borderColor: 'hsl(var(--err)/0.3)' }}
              onClick={requestDelete}
            >
              {armed === RULE_DEL_KEY
                ? t('rules.deleteConfirmAgain')
                : t('rules.delete')}
            </button>
          )}
          <button type="button" className="btn ghost" onClick={requestClose}>
            {t('common.cancel')}
          </button>
          <button
            type="button"
            className="btn flow"
            onClick={() => void handleSubmit()}
            disabled={submitting}
          >
            {isEdit ? t('common.save') : t('rules.add')}
          </button>
        </>
      }
    >
      {/* 规则名称（remarks，必填） */}
      <div className="fld">
        <label className="fld-l" htmlFor="rule-name">
          <span>{t('rules.name')}</span> <span className="req-star">*</span>
        </label>
        <input
          id="rule-name"
          className="input"
          value={name}
          onChange={(e) => {
            setName(e.target.value);
            setErrName(false);
            touch();
          }}
          placeholder={t('rules.namePh')}
        />
        {errName && <div className="err-line">{t('rules.errName')}</div>}
      </div>

      {/* 匹配条件（多条件 AND/OR） */}
      <div className="fld">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
          <label className="fld-l" style={{ margin: 0 }}>
            {t('rules.conditions')}
          </label>
          {conds.length >= 2 && (
            <div className="logic-toggle" role="group" aria-label={t('rules.combineMode')}>
              {/* 裸 AND/OR 对非技术用户无信息量（且与 hover 卡上的中文「全部满足 / 满足任一」是
                  两套说法）。改用与 hover 卡**同一组 i18n key**（rules.combineAnd / combineOr），
                  弹窗与卡片再不会各说各话。 */}
              <button
                type="button"
                className={logic === 'and' ? 'on' : ''}
                onClick={() => {
                  setLogic('and');
                  touch();
                }}
              >
                {t('rules.combineAnd')}
              </button>
              <button
                type="button"
                className={logic === 'or' ? 'on' : ''}
                onClick={() => {
                  setLogic('or');
                  touch();
                }}
              >
                {t('rules.combineOr')}
              </button>
            </div>
          )}
        </div>

        {conds.map((c, i) => (
          <CondRow
            key={i}
            c={c}
            i={i}
            condsLength={conds.length}
            t={t}
            poolQuery={poolQuery}
            setPoolQuery={setPoolQuery}
            poolGroup={poolGroup}
            setPoolGroup={setPoolGroup}
            poolOnlySel={poolOnlySel}
            setPoolOnlySel={setPoolOnlySel}
            poolOptions={poolOptions}
            poolPhase={poolPhase}
            resItems={resItems}
            ruleSetMissing={ruleSetMissing}
            poolEmptyText={poolEmptyText}
            typeGroups={typeGroups}
            setCondType={setCondType}
            setCondVal={setCondVal}
            toggleCondValue={toggleCondValue}
            removeCond={removeCond}
            navigate={navigate}
            closeAll={closeAll}
          />
        ))}

        {/* 显隐口径 = addCond 的取值口径（findAddableRuleType），不能用 conds.length < 总数：
            Windows 少 2 个可用类型，按长度比会在无类型可加时仍显示按钮。 */}
        {findAddableRuleType(new Set(conds.map((c) => c.t)), nodePlatform) !== undefined && (
          <button type="button" className="btn ghost sm" style={{ marginTop: 8 }} onClick={addCond}>
            <svg viewBox="0 0 24 24" width={14} fill="none" stroke="currentColor" strokeWidth={1.8}>
              <path d="M12 5v14M5 12h14" />
            </svg>
            <span>{t('rules.addCondition')}</span>
          </button>
        )}
        <div className="card-sub" style={{ marginTop: 8 }}>
          {t('rules.conditionsHint')}
        </div>
      </div>

      {routeEnabled && (
        <RuleRouteEffectFields
          t={t}
          target={target}
          setTarget={setTarget}
          targetGroups={targetGroups}
          targetOpenGroups={targetOpenGroups}
          touch={touch}
        />
      )}

      {dnsEnabled && (
        <RuleDnsEffectFields
          t={t}
          touch={touch}
          dnsResolver={dnsResolver}
          setDnsResolver={setDnsResolver}
          dnsAnswerMode={dnsAnswerMode}
          setDnsAnswerMode={setDnsAnswerMode}
          dnsAction={dnsAction}
          setDnsAction={setDnsAction}
          dnsFallbackAction={dnsFallbackAction}
          setDnsFallbackAction={setDnsFallbackAction}
          dnsPredefinedRcode={dnsPredefinedRcode}
          setDnsPredefinedRcode={setDnsPredefinedRcode}
          dnsPredefinedAnswer={dnsPredefinedAnswer}
          setDnsPredefinedAnswer={setDnsPredefinedAnswer}
          dnsPredefinedNs={dnsPredefinedNs}
          setDnsPredefinedNs={setDnsPredefinedNs}
          dnsPredefinedExtra={dnsPredefinedExtra}
          setDnsPredefinedExtra={setDnsPredefinedExtra}
          dnsActionGroups={dnsActionGroups}
          dnsFallbackGroups={dnsFallbackGroups}
        />
      )}

      <RuleTestFold t={t} test={test} setTest={setTest} testResult={testResult} />
    </Modal>
  );
}

export function RuleDialog({
  ruleId,
  preset,
  initialPlane,
}: {
  ruleId?: string;
  preset?: RulePreset;
  initialPlane?: 'route' | 'dns';
}) {
  // 展示面：编辑基准。读盘的话暂存过的规则再打开会显示改前的旧值。
  const plane = initialPlane ?? 'route';
  const rules = useEffectiveRules(plane);
  const base = ruleId ? rules.find((r) => r.id === ruleId) : undefined;
  // R1：key 绑定 ruleId —— 切换编辑目标 = 重挂 = 同步重新初始化，杜绝挂载后 reset。
  const formKey = `${plane}:${ruleId ?? `new:${preset?.type ?? ''}:${preset?.value ?? ''}`}`;
  return (
    <RuleForm
      key={formKey}
      base={base}
      isEdit={base != null}
      preset={preset}
      initialPlane={plane}
    />
  );
}

export default RuleDialog;
