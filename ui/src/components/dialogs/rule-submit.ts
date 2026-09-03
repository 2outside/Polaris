import type { TFunction } from 'i18next';
import type {
  Rule,
  RuleAction,
  RuleCondition,
  RuleDnsAnswerMode,
  RuleDnsResolver,
} from '@/contracts/types';
import { api, IpcError } from '@/ipc';
import { editRoute, type StagedEntry } from '@/lib/staged-config';
import { toast } from '@/lib/error-handler';
import { isRuleTypeDnsEffectSupported, ruleTypeNameKey, validateRule } from '@/domain/rules';
import { invalidCondValues, splitVals, type Cond } from './rule-cond';
import { dnsActionFromChoice } from './dns-action-options';
import { splitDnsRecordLines } from './RuleDnsEffect';

export interface RuleSubmitArgs {
  t: TFunction;
  conds: readonly Cond[];
  name: string;
  setErrName: (v: boolean) => void;
  logic: 'and' | 'or';
  target: string;
  dnsAction: string;
  dnsFallbackAction: string;
  dnsResolver: RuleDnsResolver;
  dnsAnswerMode: RuleDnsAnswerMode;
  dnsPredefinedRcode: string;
  dnsPredefinedAnswer: string;
  dnsPredefinedNs: string;
  dnsPredefinedExtra: string;
  isEdit: boolean;
  base?: Rule;
  /**
   * 这条规则属于哪个面 —— **plane 这件事在参数袋里只有这一个来源**。
   *
   * 原先另有 `dnsEnabled` / `routeEnabled` 两个布尔，唯一调用方本就是从本字段派生出它们
   * （`RuleDialog`：`routeEnabled = initialPlane === 'route'`）。三者可互相矛盾而类型层拦不住：
   * `dnsEnabled:true` 配 `initialPlane:'route'` 会把 `effects.dns` 写进 `trafficRules`。
   * 派生腿收进函数体内，那种组合在结构上就构造不出来。
   */
  initialPlane: 'route' | 'dns';
  stagingEnabled: boolean;
  stage: (entry: StagedEntry) => void;
  close: () => void;
  loadConfig: (force: boolean) => Promise<unknown> | void;
  setSubmitting: (v: boolean) => void;
}

/**
 * 规则表单提交 —— 校验 + route/DNS 二选一 effects 组装 + 暂存/落盘二选一，从 `RuleForm` 外提。
 *
 * Route 与 DNS 的唯一耦合点在这里，且**判别式只有一条**：`initialPlane`。`effects.route`/
 * `effects.dns` 二选一、`collectionKey`、暂存路由三处全部从它派生，不再各写一遍三元。
 */
export async function submitRule(args: RuleSubmitArgs): Promise<void> {
  const {
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
  } = args;

  /** 面的三个派生量（唯一来源 `initialPlane`）：两条 effects 腿的开关 + 落点集合键。 */
  const routeEnabled = initialPlane === 'route';
  const dnsEnabled = initialPlane === 'dns';
  const collectionKey = dnsEnabled ? 'dnsRules' : 'trafficRules';

  // 名称必填：与 SubDialog / NodeDialog / WarpDialog / WgDialog / AppAddDialog 同一口径（errName +
  // .err-line），此前本表单是全仓唯一放行空名的 —— 空 remarks 会让规则列表的标题回落成裸类型名
  // （`ruleTitle()`：无 remarks 就显 `domain` / `ruleSet`），多条同类型规则在列表和 hover 卡上
  // 完全无法区分，而排序又直接决定命中优先级。
  const nameEmpty = !name.trim();
  setErrName(nameEmpty);
  const filled = conds.filter((c) => splitVals(c.v).length);
  if (!filled.length) {
    toast.error(t('rules.invalidHead'), t('rules.errNoCond'));
    // 名称也空时两条错误一起显示（不让用户改完一个再发现另一个）。
    return;
  }
  if (nameEmpty) return;
  const rconds: RuleCondition[] = filled.map((c) => ({ type: c.t, values: splitVals(c.v) }));
  const multi = rconds.length > 1;
  if (dnsEnabled && rconds.some((condition) => !isRuleTypeDnsEffectSupported(condition.type))) {
    toast.error(t('rules.invalidHead'), t('rules.errDnsCondition'));
    return;
  }

  /* 渲染端校验层 —— 此前**从未接上**：`validateRuleValue`（15/15 全覆盖）与 `validateRule`
     两个函数生产调用点为零，提交只校验「名称非空」+「至少一个条件有值」，值本身全靠后端返
     `RULE_INVALID` 再回显。一次 IPC 往返之后才知道自己那行 `10.0.0.0/40` 不合法，而这些值
     落进 endpoints[]/route.rules[] 时启动前的 gate 按 outbounds 索引剪不掉 → 直接 FATAL。

     **`validateRule` 决定能不能提交，`invalidCondValues` 负责说清哪一个值不对**，不是两道
     重复的门：前者还看 `combineMode` 与镜像 `type`（逐值校验看不到的两项），后者才拿得出
     用户能照着改的信息。后端仍是权威（Rust 写时再校验一次），这层只是把往返省掉。 */
  const draft = {
    type: rconds[0].type,
    values: rconds[0].values,
    conditions: multi ? rconds : undefined,
    combineMode: multi ? logic : undefined,
  };
  if (!validateRule(draft)) {
    const bad = invalidCondValues(filled);
    toast.error(
      t('rules.invalidHead'),
      bad.length > 0
        ? t('rules.errInvalidValues', {
            detail: bad
              .slice(0, 4)
              .map((b) => `${t(ruleTypeNameKey(b.type))}: ${b.value}`)
              .join('; ') + (bad.length > 4 ? '…' : ''),
          })
        : t('rules.errInvalidRule'),
    );
    return;
  }
  const routeAction: RuleAction =
    target === 'direct' ? 'direct' : target === 'block' ? 'block' : 'proxy';
  // action/targetServerId/bypassFakeIP 是兼容镜像；effects 是新代码权威。
  const action: RuleAction = routeEnabled ? routeAction : 'direct';
  const targetServerId =
    routeEnabled && routeAction === 'proxy' && target.startsWith('node:')
      ? target.slice(5)
      : undefined;
  const dnsPolicyAction = dnsActionFromChoice(
    dnsAction,
    dnsFallbackAction,
    {
      type: 'predefined',
      rcode: dnsPredefinedRcode,
      answer: splitDnsRecordLines(dnsPredefinedAnswer),
      ns: splitDnsRecordLines(dnsPredefinedNs),
      extra: splitDnsRecordLines(dnsPredefinedExtra),
    },
  );
  const effects = {
    route: routeEnabled
      ? {
          action: routeAction,
          targetServerId,
        }
      : undefined,
    dns: dnsEnabled
      ? {
          enabled: true,
          action: dnsPolicyAction,
          resolver: dnsResolver,
          answerMode: dnsAnswerMode,
        }
      : undefined,
  };
  const bypass = dnsEnabled && dnsAnswerMode === 'real' ? true : undefined;
  const remarks = name.trim();

  setSubmitting(true);
  /* 暂存闸门（与 NodeDialog 同形）：`customRules` Class B，提交的是完整 Rule ⇒ 天然满足重放要求的
     「幂等整体替换」。新增与编辑两条腿此前各写一遍逐字相同的三元，现按 `collectionKey` 单点判定。 */
  const stageRule = editRoute(collectionKey, stagingEnabled) === 'staged';
  try {
    if (isEdit && base) {
      // base 起底保全非模型字段（tlsSpoof 等，R5）；单条件时显式清 conditions/combineMode。
      const full: Rule = {
        ...base,
        id: base.id,
        type: rconds[0].type,
        values: rconds[0].values,
        conditions: multi ? rconds : undefined,
        combineMode: multi ? logic : undefined,
        action,
        effects,
        targetServerId,
        enabled: base.enabled,
        bypassFakeIP: bypass,
        remarks,
      };
      if (stageRule) {
        stage({
          id: `rule:${full.id}`,
          kind: 'rule',
          label: `${t('rules.editTitle')} ${remarks}`,
          entityPath: [collectionKey, full.id],
          nextValue: full,
        });
        close();
        return; // 零 IPC 写、零磁盘写（FR-1）
      }
      await api.rules.update(full, initialPlane);
    } else {
      const rest: Omit<Rule, 'id'> = {
        type: rconds[0].type,
        values: rconds[0].values,
        conditions: multi ? rconds : undefined,
        combineMode: multi ? logic : undefined,
        action,
        effects,
        enabled: true,
        targetServerId,
        bypassFakeIP: bypass,
        remarks,
      };
      // 新增时前端自铸 id：后端 `rules_add` 只在落盘那一刻发 id，而条目现在就需要稳定的
      // 实体寻址键（同一条规则改两次要覆盖同一条条目，否则计数虚高）。
      if (stageRule) {
        const entityId = crypto.randomUUID();
        stage({
          id: `rule:${entityId}`,
          kind: 'rule',
          label: `${t('rules.newTitle')} ${remarks}`,
          entityPath: [collectionKey, entityId],
          nextValue: { ...rest, id: entityId },
        });
        close();
        return; // 零 IPC 写、零磁盘写（FR-1）
      }
      await api.rules.add(rest, initialPlane);
    }
    void loadConfig(true); // 同上：不刷则列表看不到新增/编辑结果
    close();
  } catch (e) {
    console.error('[RuleDialog] save failed:', e);
    // 写时校验（Rust 权威）：RULE_INVALID → 展示校验消息、弹窗不关；其它 → 通用可重试失败。
    if (e instanceof IpcError && e.code === 'RULE_INVALID') {
      toast.error(t('rules.invalidHead'));
    } else {
      toast.error(t('common.saveFailed'));
    }
  } finally {
    setSubmitting(false);
  }
}
