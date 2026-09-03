/**
 * SettingsDns —— DNS 子页（原型 [data-sec="dns"] L2172-2218）。
 *
 * 只承载运行级 DNS 设置：系统接管、缓存/超时、节点拨号 resolver sidecar、FakeIP 过滤和浏览器 DoH。
 * 一等 DNS Server / Group / 未命中默认动作已迁到「DNS 规则」工作区，本页不保留第二套资源编辑器。
 */

import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type {
  UserConfig,
  DnsConfig,
  DnsPolicyAction,
} from '@/contracts/types';
import { useDialogStore } from '../../dialogs/dialog-store';
import { Fold } from '@/components/Fold';
import { DEFAULT_BROWSER_DOH_SUFFIXES } from '@/contracts/browser-doh';
import {
  dnsConnectionResolutionPatch,
  effectiveDnsConnectionResolution,
  type DnsConnectionResolution,
} from '@/domain/dns-connection-resolution';
import {
  Phead,
  SetBlock,
  SetRow,
  SetRowGroup,
  Switch,
  Select,
  TextInput,
  Segmented,
} from './Primitives';
import { ListEditor } from './ListEditor';
import {
  DNS_FALLBACK,
  isIpDoh,
  isPureIpDnsSpec,
  MAX_DOH_RACE_UPSTREAMS,
  nextRacePool,
  normalizeDnsTimeoutInput,
  parseDnsServerSpec,
  reconcileCustomUpstreams,
  fakeIpTogglePatch,
  needsFakeIpOffConfirm,
} from './settings-dns-logic';

export {
  fakeIpTogglePatch,
  needsFakeIpOffConfirm,
  nextRacePool,
  normalizeDnsTimeoutInput,
  parseDnsServerSpec,
  reconcileCustomUpstreams,
} from './settings-dns-logic';
export type { ParsedDnsServer } from './settings-dns-logic';

export interface SettingsDnsProps {
  config: UserConfig;
  update: (patch: Partial<UserConfig>) => Promise<void>;
  /** 嵌入 DNS 系统保护规则时不重复 screen/Phead。 */
  embedded?: boolean;
  /** policy 只渲染 FakeIP 例外；runtime 是“设置 → DNS”的全局运行时与节点拨号设置。 */
  section?: 'all' | 'runtime' | 'policy';
}

type RaceStrategy = 'race' | 'single';

/**
 * 上游预设。标签只有「按 IP / 按域名的 DoH」与「阿里 / 腾讯」两类词需要翻译，服务商域名与 IP
 * 跨语种同形（Cloudflare / Google / DNSPod 亦然），故按 `<类型> · <厂商> <地址>` 拼装而非整句入库。
 *
 * 走函数而非模块级常量：常量在 import 期求值，那时 i18n 语言尚未被 `syncLanguageChoice` 校正，
 * 切语言也不会重算（同 SettingsSidebar 分组表的理由）。
 */
function remotePresets(t: (key: string) => string) {
  const ip = t('settings.dns.dohByIp');
  const dom = t('settings.dns.dohByDomain');
  return [
    { value: 'https://1.1.1.1/dns-query', label: `${ip} · Cloudflare 1.1.1.1` },
    { value: 'https://8.8.8.8/dns-query', label: `${ip} · Google 8.8.8.8` },
    { value: 'https://cloudflare-dns.com/dns-query', label: `${dom} · cloudflare-dns.com` },
    { value: 'https://dns.google/dns-query', label: `${dom} · dns.google` },
  ];
}

function domesticPresets(t: (key: string) => string) {
  const ip = t('settings.dns.dohByIp');
  const dom = t('settings.dns.dohByDomain');
  const ali = t('settings.dns.brandAli');
  return [
    { value: 'https://223.5.5.5/dns-query', label: `${ip} · ${ali} 223.5.5.5` },
    { value: 'https://1.12.12.12/dns-query', label: `${ip} · ${t('settings.dns.brandTencent')} 1.12.12.12` },
    { value: 'https://doh.pub/dns-query', label: `${dom} · DNSPod doh.pub` },
    { value: 'https://dns.alidns.com/dns-query', label: `${dom} · ${ali} dns.alidns.com` },
  ];
}


export default function SettingsDns({
  config,
  update,
  embedded = false,
  section = 'all',
}: SettingsDnsProps) {
  const { t } = useTranslation();
  const openDialog = useDialogStore((s) => s.open);
  const closeDialog = useDialogStore((s) => s.close);
  const dns: DnsConfig = config.dnsConfig ?? {
    domesticDns: DNS_FALLBACK.domesticDns,
    foreignDns: DNS_FALLBACK.foreignDns,
    enableFakeIp: true,
  };

  function patchDns(patch: Partial<DnsConfig>) {
    void update({ dnsConfig: { ...dns, ...patch } });
  }

  const hasDnsPolicyV2 = (config.configSchemaVersion ?? 0) >= 2 && config.dnsDefaults != null;
  const dnsDefaults = config.dnsDefaults ?? {
    directServerId: 'builtin-domestic',
    proxyServerId: 'builtin-remote',
    unmatchedAction: dns.enableFakeIp === false
      ? ({ type: 'server', serverId: 'builtin-domestic' } as DnsPolicyAction)
      : ({ type: 'fakeIp' } as DnsPolicyAction),
  };
  const connectionResolution = effectiveDnsConnectionResolution(config);

  function setConnectionResolution(next: DnsConnectionResolution) {
    void update(dnsConnectionResolutionPatch(config, next));
  }

  const raceStrategy: RaceStrategy = dns.resolveNodeDomainsAhead === false ? 'single' : 'race';

  /* ── 国内/国外 DNS + 查询超时：本地草稿 + onBlur 提交（契约 L94）──────────────
   * 三个都是文本输入，逐键写盘会在代理运行时按每个字符触发一次整核重启评估，且中间态是非法值。
   * 故一律「输入进草稿 → blur/Enter 才校验落盘」，非法标红且不写 config。
   *
   * 外部改动（托盘/备份恢复/另一屏保存 → useConfig 静默重拉）要能回填到草稿，但不能打断正在输入
   * 的用户。种子快照 `seededRef` 就是这道守卫：草稿 ≠ 上次种子 = 用户已改过，保留草稿；相等 = 未
   * 动过，跟随新配置。（同 上游 network-settings.tsx 的 F26 修复。） */
  const [remoteDraft, setRemoteDraft] = useState(dns.foreignDns);
  const [domesticDraft, setDomesticDraft] = useState(dns.domesticDns);
  const [timeoutDraft, setTimeoutDraft] = useState(
    dns.dnsTimeoutMs != null ? String(dns.dnsTimeoutMs) : '',
  );
  const [dnsErr, setDnsErr] = useState<{ foreignDns?: boolean; domesticDns?: boolean }>({});
  const [timeoutErr, setTimeoutErr] = useState(false);
  const seededRef = useRef({
    foreignDns: dns.foreignDns,
    domesticDns: dns.domesticDns,
    dnsTimeout: dns.dnsTimeoutMs != null ? String(dns.dnsTimeoutMs) : '',
  });
  useEffect(() => {
    const snap = {
      foreignDns: dns.foreignDns,
      domesticDns: dns.domesticDns,
      dnsTimeout: dns.dnsTimeoutMs != null ? String(dns.dnsTimeoutMs) : '',
    };
    const prev = seededRef.current;
    setRemoteDraft((cur) => (cur !== prev.foreignDns ? cur : snap.foreignDns));
    setDomesticDraft((cur) => (cur !== prev.domesticDns ? cur : snap.domesticDns));
    setTimeoutDraft((cur) => (cur !== prev.dnsTimeout ? cur : snap.dnsTimeout));
    seededRef.current = snap;
  }, [dns.foreignDns, dns.domesticDns, dns.dnsTimeoutMs]);

  /** 提交一栏 DNS：非法 → 标红、保留输入待修正、**不落盘**；清空 → 回默认；无变化 → 不写（免无谓重启）。 */
  function commitDns(key: 'foreignDns' | 'domesticDns', raw: string) {
    const v = raw.trim();
    if (v && !parseDnsServerSpec(v)) {
      setDnsErr((prev) => ({ ...prev, [key]: true }));
      return;
    }
    setDnsErr((prev) => ({ ...prev, [key]: false }));
    const next = v || DNS_FALLBACK[key];
    if (key === 'foreignDns') setRemoteDraft(next);
    else setDomesticDraft(next);
    if (next === dns[key]) return;
    patchDns({ [key]: next });
  }

  /** 预设下拉命中的值恒合法，直接同步草稿 + 落盘（清掉可能残留的标红）。 */
  function pickPreset(key: 'foreignDns' | 'domesticDns', value: string) {
    if (key === 'foreignDns') setRemoteDraft(value);
    else setDomesticDraft(value);
    setDnsErr((prev) => ({ ...prev, [key]: false }));
    if (value !== dns[key]) patchDns({ [key]: value });
  }

  function commitDnsTimeout(raw: string) {
    const parsed = normalizeDnsTimeoutInput(raw);
    if (!parsed) {
      setTimeoutErr(true);
      return;
    }
    setTimeoutErr(false);
    setTimeoutDraft(parsed.value != null ? String(parsed.value) : '');
    if (parsed.value === dns.dnsTimeoutMs) return;
    patchDns({ dnsTimeoutMs: parsed.value });
  }

  /**
   * FakeIP 开关：TUN 下 ON→OFF 先弹一次性风险确认（契约 L95）—— 关闭后节点收到真实 IP，部分机场
   * 会因反滥用策略拒连，这个风险客户端无法缓解，属「拨了才知道」的不可逆体验，必须先说清。
   * 其余情形（开启 / 非 TUN 关闭）直接落盘。
   */
  function onFakeIpToggle(next: boolean) {
    const commit = (enabled: boolean) => {
      const dnsConfig = { ...dns, ...fakeIpTogglePatch(enabled) };
      if (!hasDnsPolicyV2) {
        void update({ dnsConfig });
        return;
      }
      void update({
        dnsConfig,
        dnsDefaults: {
          ...dnsDefaults,
          unmatchedAction: enabled
            ? { type: 'fakeIp' }
            : { type: 'server', serverId: dnsDefaults.directServerId || 'builtin-domestic' },
        },
      });
    };
    if (needsFakeIpOffConfirm(next, config.proxyModeType)) {
      openDialog({
        kind: 'confirm',
        payload: {
          title: t('settings.advanced.fakeIpTunOffConfirmTitle'),
          message: t('settings.advanced.fakeIpTunOffConfirmDesc'),
          confirmLabel: t('settings.advanced.fakeIpTunOffConfirmOk'),
          danger: true,
          onConfirm: () => {
            closeDialog(); // 回调自行 pop（dialog-store 不自动关）
            commit(false);
          },
        },
      });
      return;
    }
    commit(next);
  }

  const REMOTE_PRESETS = remotePresets(t);
  const DOMESTIC_PRESETS = domesticPresets(t);

  /** race off 单上游：只放行内置三档；陈旧/自定义 id 回显 'ali'，与后端「未知 single 走 ali 基线」一致。 */
  const SINGLE_ITEMS = [
    { id: 'ali', label: t('settings.advanced.nodeResolverAli') },
    { id: 'dnspod', label: t('settings.advanced.nodeResolverDnspod') },
    { id: 'system', label: t('settings.advanced.nodeResolverSystem') },
  ];
  const singleValue = SINGLE_ITEMS.some((it) => it.id === dns.nodeResolverSingle)
    ? (dns.nodeResolverSingle as string)
    : 'ali';

  /** fakeip-filter 总开关：缺省/true=开，仅显式 false=关（对齐后端 `fake_ip_filter != Some(false)`）。 */
  const fakeIpFilterOn = config.fakeIpFilter !== false;

  // 折叠段的条目计数要与编辑器实际渲染的清单是**同一个数组**，否则计数与内容会分叉。
  const fakeIpFilterList = config.fakeIpFilterList ?? ['time.*.com', 'stun.*.*', 'captive.apple.com'];
  // 浏览器内置 DoH 拦截：**默认关**（=== true 判定，undefined 不算开）。
  // 与 fakeIpFilter 的 `!== false` 相反 —— 那个是历史默认开，这个是新增能力，默认不替用户做决定。
  const browserDohOn = config.blockBrowserDoh === true;
  const browserDohList = config.browserDohList ?? [...DEFAULT_BROWSER_DOH_SUFFIXES];

  // race 上游开关（用 nodeResolverPool：内置 ali/dnspod/system + 自定义 id）
  const racePool = dns.nodeResolverPool ?? ['ali', 'dnspod'];
  const customUpstreams = dns.nodeResolverCustom ?? [];
  // DoH 竞速层配额只数 Tier1（内置 DoH + 自定义 DoH）；兜底层「系统 DNS」不占额度。
  // 只数「有实际对应项」的 id：内置 ali/dnspod，或仍存在于 nodeResolverCustom 的自定义 id——
  // 排除自定义条目被删除后残留在 pool 里的孤儿 id（否则会多算一个不存在的启用项）。
  const validRaceIds = new Set(['ali', 'dnspod', ...customUpstreams.map((u) => u.id)]);
  const activeRacePool = racePool.filter((id) => id === 'system' || validRaceIds.has(id));
  const dohRaceCount = new Set(
    activeRacePool.filter((id) => id !== 'system'),
  ).size;
  // 引导层：任一列为域名形式 DoH 时显示引导端点；两栏均为 IP DoH 则「无需引导层」
  // （原型 `#dns-bootstrap-row.no-boot` 纯 CSS 切换 .dns-bs-endpoints ↔ .dns-bs-none，两个 div 都常渲染）
  const bootstrapNeeded = !isIpDoh(dns.foreignDns) || !isIpDoh(dns.domesticDns);

  function toggleRaceUpstream(id: string, on: boolean) {
    patchDns({ nodeResolverPool: nextRacePool(activeRacePool, id, on) });
  }

  // 本地编辑态：允许列表里出现一行空白（供「添加」后输入），但空白/纯空格 spec 不落盘
  // （不写入 nodeResolverCustom，也不计入 pool）——ListEditor 是受控组件，若直接绑定
  // config 派生值，过滤空白会导致刚点「添加」的空行立刻消失，故用本地态承接编辑中的空行。
  const [draftCustomSpecs, setDraftCustomSpecs] = useState<string[]>(() =>
    customUpstreams.map((u) => u.spec),
  );
  useEffect(() => {
    setDraftCustomSpecs(customUpstreams.map((u) => u.spec));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dns.nodeResolverCustom]);

  // 自定义 DoH 是配置库存，不设数量上限；启用状态只存 nodeResolverPool，新建默认关闭。
  // 删除配置时清理 pool 中对应 id，防止留下孤儿启用项。
  function setCustomUpstreams(specs: string[]) {
    setDraftCustomSpecs(specs);
    // 非法项留在草稿中标红，但不落盘；否则用户看到错误提示的同时坏配置已经触发重启评估。
    if (specs.some((spec) => spec.trim() !== '' && !isPureIpDnsSpec(spec))) return;
    const nextCustom = reconcileCustomUpstreams(
      customUpstreams,
      specs,
      () => `doh-${crypto.randomUUID()}`
    );
    const nextIds = new Set(nextCustom.map((item) => item.id));
    const previousIds = new Set(customUpstreams.map((item) => item.id));
    patchDns({
      nodeResolverCustom: nextCustom,
      nodeResolverPool: racePool.filter((id) => !previousIds.has(id) || nextIds.has(id)),
    });
  }

  return (
    <section className={embedded ? 'dns-runtime-workspace' : 'screen'} data-sec="dns">
      {!embedded && <Phead title="DNS" sub={t('settings.dns.pageSub')} />}

      {/* 1. 解析器 */}
      {section !== 'policy' && (<>
      <SetBlock header={t('settings.dns.resolverBlock')}>
        <SetRow
          label={t('settings.dns.connectionResolution')}
          tip={t('settings.dns.connectionResolutionHint')}
        >
          <Select
            id="dns-connection-resolution"
            value={connectionResolution}
            onChange={(e) => setConnectionResolution(e.target.value as DnsConnectionResolution)}
            aria-label={t('settings.dns.connectionResolution')}
          >
            <option value="preserveDomain">{t('settings.dns.connectionPreserve')}</option>
            <option value="dnsRules">{t('settings.dns.connectionLocal')}</option>
          </Select>
        </SetRow>

        {!hasDnsPolicyV2 && <SetRow label="FakeIP" tip={t('settings.dns.fakeIpDesc')}>
          <Switch
            id="fakeip-swt"
            checked={dns.enableFakeIp}
            onChange={onFakeIpToggle}
            aria-label="FakeIP"
          />
        </SetRow>}

        {!hasDnsPolicyV2 && (<>
        <SetRow
          label={t('settings.dns.remoteDns')}
          tip={t('settings.dns.remoteDnsDesc')}
          align="start"
          ctrlStyle={{ minWidth: 252, display: 'flex', flexDirection: 'column', gap: 8, alignItems: 'stretch' }}
        >
          <Select
            id="dns-preset-remote"
            value={REMOTE_PRESETS.some((p) => p.value === remoteDraft) ? remoteDraft : '__custom__'}
            onChange={(e) => {
              const v = e.target.value;
              if (v !== '__custom__') pickPreset('foreignDns', v);
            }}
            aria-label={t('settings.dns.remoteDns')}
          >
            {REMOTE_PRESETS.map((p) => (
              <option key={p.value} value={p.value}>
                {p.label}
              </option>
            ))}
            <option value="__custom__">{t('common.customEllipsis')}</option>
          </Select>
          {/* onBlur 提交（契约 L94）：onChange 只动草稿，Enter 触发 blur 即提交。 */}
          <TextInput
            id="dns-input-remote"
            value={remoteDraft}
            onChange={(e) => {
              setRemoteDraft(e.target.value);
              if (dnsErr.foreignDns) setDnsErr((p) => ({ ...p, foreignDns: false }));
            }}
            onBlur={() => commitDns('foreignDns', remoteDraft)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') e.currentTarget.blur();
            }}
            aria-invalid={dnsErr.foreignDns || undefined}
            style={dnsErr.foreignDns ? { borderColor: 'hsl(var(--err))' } : undefined}
            className="mono"
            aria-label={t('settings.dns.remoteDns')}
          />
          {dnsErr.foreignDns && (
            <div className="err-line">{t('settings.advanced.dnsInvalid')}</div>
          )}
        </SetRow>

        <SetRow
          label={t('settings.dns.domesticDns')}
          tip={t('settings.dns.domesticDnsDesc')}
          align="start"
          ctrlStyle={{ minWidth: 252, display: 'flex', flexDirection: 'column', gap: 8, alignItems: 'stretch' }}
        >
          <Select
            id="dns-preset-domestic"
            value={DOMESTIC_PRESETS.some((p) => p.value === domesticDraft) ? domesticDraft : '__custom__'}
            onChange={(e) => {
              const v = e.target.value;
              if (v !== '__custom__') pickPreset('domesticDns', v);
            }}
            aria-label={t('settings.dns.domesticDns')}
          >
            {DOMESTIC_PRESETS.map((p) => (
              <option key={p.value} value={p.value}>
                {p.label}
              </option>
            ))}
            <option value="__custom__">{t('common.customEllipsis')}</option>
          </Select>
          <TextInput
            id="dns-input-domestic"
            value={domesticDraft}
            onChange={(e) => {
              setDomesticDraft(e.target.value);
              if (dnsErr.domesticDns) setDnsErr((p) => ({ ...p, domesticDns: false }));
            }}
            onBlur={() => commitDns('domesticDns', domesticDraft)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') e.currentTarget.blur();
            }}
            aria-invalid={dnsErr.domesticDns || undefined}
            style={dnsErr.domesticDns ? { borderColor: 'hsl(var(--err))' } : undefined}
            className="mono"
            aria-label={t('settings.dns.domesticDns')}
          />
          {dnsErr.domesticDns && (
            <div className="err-line">{t('settings.advanced.dnsInvalid')}</div>
          )}
        </SetRow>

        <SetRow
          label={t('settings.dns.bootstrap')}
          tip={t('settings.dns.bootstrapDesc')}
          align="start"
          className={bootstrapNeeded ? undefined : 'no-boot'}
          id="dns-bootstrap-row"
          ctrlStyle={{ minWidth: 230 }}
        >
          <div className="dns-bs-endpoints">
            <span className="mono">https://223.5.5.5/dns-query</span>
            <span className="mono">https://1.12.12.12/dns-query</span>
          </div>
          <div className="dns-bs-none card-sub">{t('settings.dns.bootstrapNone')}</div>
        </SetRow>
        </>)}

        <SetRow
          label={t('settings.advanced.takeoverSystemDns')}
          tip={t('settings.dns.takeoverSystemDnsDesc')}
        >
          <Switch checked={dns.takeoverSystemDns !== false} onChange={(v) => patchDns({ takeoverSystemDns: v })} />
        </SetRow>

        {/* 乐观 DNS 缓存 → 顶层 dns.optimistic（builder/dns.rs:465，仅 true 时下发）。
            缺省/false=关，故 `=== true` 判定（不能写 `!== false`，那会让存量配置默认显示成开）。 */}
        <SetRow
          label={t('settings.advanced.optimisticCache')}
          tip={t('settings.advanced.optimisticCacheDesc')}
        >
          <Switch
            id="dns-optimistic-swt"
            checked={dns.optimisticCache === true}
            onChange={(v) => patchDns({ optimisticCache: v })}
            aria-label={t('settings.advanced.optimisticCache')}
          />
        </SetRow>

        {/* DNS 查询超时 → dns.timeout "<n>ms"（builder/dns.rs:472）。空=不下发用核默认；
            范围 1-60000 与 store/sanitize.rs:498-517 同口径（见 normalizeDnsTimeoutInput）。 */}
        <SetRow
          label={t('settings.advanced.dnsTimeout')}
          tip={t('settings.advanced.dnsTimeoutDesc')}
          align="start"
          ctrlStyle={{ minWidth: 160, display: 'flex', flexDirection: 'column', gap: 6, alignItems: 'stretch' }}
        >
          <TextInput
            id="dns-timeout-input"
            inputMode="numeric"
            value={timeoutDraft}
            placeholder={t('settings.advanced.dnsTimeoutPlaceholder')}
            onChange={(e) => {
              setTimeoutDraft(e.target.value);
              if (timeoutErr) setTimeoutErr(false);
            }}
            onBlur={() => commitDnsTimeout(timeoutDraft)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') e.currentTarget.blur();
            }}
            aria-invalid={timeoutErr || undefined}
            style={timeoutErr ? { borderColor: 'hsl(var(--err))' } : undefined}
            className="mono"
            aria-label={t('settings.advanced.dnsTimeout')}
          />
          {timeoutErr && (
            <div className="err-line">{t('settings.advanced.dnsTimeoutRange')}</div>
          )}
        </SetRow>
      </SetBlock>

      {/* 2. 节点域名解析（race） */}
      <SetBlock header={t('settings.dns.nodeResolverBlock')}>
        <SetRow label={t('settings.dns.raceStrategy')} tip={t('settings.dns.raceStrategyDesc')}>
          <Segmented<RaceStrategy>
            ariaLabel={t('settings.dns.raceStrategy')}
            value={raceStrategy}
            onChange={(v) => patchDns({ resolveNodeDomainsAhead: v === 'race' })}
            options={[
              { value: 'race', label: t('settings.dns.raceMode') },
              { value: 'single', label: t('settings.dns.singleMode') },
            ]}
          />
        </SetRow>

        {/* race【off】：单上游选择器（写 nodeResolverSingle，builder/outbounds.rs:77 →
            helpers.rs:259-286 effective_single_resolver_id）。与 pool 各存各的、切档互不覆盖，
            故此处只读写 nodeResolverSingle，不碰 nodeResolverPool/Custom。 */}
        {raceStrategy === 'single' ? (
          <SetRow
            label={t('settings.advanced.nodeResolverSingleLabel')}
            tip={t('settings.advanced.nodeResolverSingleHint')}
          >
            <Select
              id="dns-single-resolver"
              value={singleValue}
              onChange={(e) => patchDns({ nodeResolverSingle: e.target.value })}
              aria-label={t('settings.advanced.nodeResolverSingleLabel')}
              style={{ width: '180px' }}
            >
              {SINGLE_ITEMS.map((it) => (
                <option key={it.id} value={it.id}>
                  {it.label}
                </option>
              ))}
            </Select>
          </SetRow>
        ) : (
          <SetRowGroup>
            <SetRow
              label={t('settings.dns.raceUpstreams')}
              tip={t('settings.dns.raceUpstreamsDesc')}
              align="start"
            />

            <div className="race-ups" id="race-ups">
              <div className="race-tier">
                <span className="race-tier-l">{t('settings.dns.tierRace')}</span>
                <span className="race-tier-c">
                  <span className="mono" id="race-doh-count">
                    {dohRaceCount}
                  </span>
                  /{MAX_DOH_RACE_UPSTREAMS}
                </span>
              </div>
              <label className="race-up">
                <span>
                  {t('settings.dns.brandAli')} DoH <span className="mono">223.5.5.5</span>{' '}
                  <span className="race-tag">{t('settings.dns.builtinTag')}</span>
                </span>
                <Switch
                  checked={racePool.includes('ali')}
                  disabled={!racePool.includes('ali') && dohRaceCount >= MAX_DOH_RACE_UPSTREAMS}
                  tip={!racePool.includes('ali') && dohRaceCount >= MAX_DOH_RACE_UPSTREAMS ? t('settings.dns.raceQuotaReached') : undefined}
                  onChange={(v) => toggleRaceUpstream('ali', v)}
                />
              </label>
              <label className="race-up">
                <span>
                  DNSPod DoH <span className="mono">1.12.12.12</span>{' '}
                  <span className="race-tag">{t('settings.dns.builtinTag')}</span>
                </span>
                <Switch
                  checked={racePool.includes('dnspod')}
                  disabled={!racePool.includes('dnspod') && dohRaceCount >= MAX_DOH_RACE_UPSTREAMS}
                  tip={!racePool.includes('dnspod') && dohRaceCount >= MAX_DOH_RACE_UPSTREAMS ? t('settings.dns.raceQuotaReached') : undefined}
                  onChange={(v) => toggleRaceUpstream('dnspod', v)}
                />
              </label>

              {/* 配置库存不限量；每行开关单独决定是否进入最多 3 个的竞速池。 */}
              <ListEditor
                id="dns-custom-list"
                className="race-custom"
                value={draftCustomSpecs}
                onChange={setCustomUpstreams}
                placeholder="https://223.5.5.5/dns-query"
                ariaLabel="DoH URL"
                addLabel={t('settings.dns.addCustomDoh')}
                importLabel={t('common.bulkImport')}
                renderRowEnd={(entry) => {
                  const upstream = customUpstreams.find((item) => item.spec.trim() === entry.trim());
                  const checked = !!upstream && racePool.includes(upstream.id);
                  const disabled = !upstream || (!checked && dohRaceCount >= MAX_DOH_RACE_UPSTREAMS);
                  return (
                    <Switch
                      checked={checked}
                      disabled={disabled}
                      tip={
                        !upstream
                          ? t('settings.dns.saveCustomFirst')
                          : !checked && dohRaceCount >= MAX_DOH_RACE_UPSTREAMS
                            ? t('settings.dns.raceQuotaReached')
                            : undefined
                      }
                      aria-label={t('settings.dns.enableCustomDoh')}
                      onChange={(on) => upstream && toggleRaceUpstream(upstream.id, on)}
                    />
                  );
                }}
              />
              {dohRaceCount >= MAX_DOH_RACE_UPSTREAMS && (
                <div className="card-sub">{t('settings.dns.raceQuotaReached')}</div>
              )}
              {draftCustomSpecs.some((spec) => spec.trim() !== '' && !isPureIpDnsSpec(spec)) && (
                <div className="err-line">{t('settings.dns.customDohIpOnly')}</div>
              )}

              <div className="race-tier">
                <span className="race-tier-l">{t('settings.dns.tierFallback')}</span>
                <span className="race-tag muted">{t('settings.dns.noQuotaTag')}</span>
              </div>
              <label className="race-up">
                <span>{t('settings.advanced.nodeResolverSystem')}</span>
                <Switch checked={racePool.includes('system')} onChange={(v) => toggleRaceUpstream('system', v)} />
              </label>
              {activeRacePool.length === 0 && (
                <div className="card-sub">{t('settings.dns.raceEmptyFallback')}</div>
              )}
            </div>
          </SetRowGroup>
        )}
      </SetBlock>
      </>)}

      {/* 3. FakeIP 例外域名：总开关 + 清单（默认折叠，summary 右侧给条目数） */}
      {section !== 'runtime' && (
      <SetBlock
        header={embedded ? undefined : t('settings.advanced.fakeIpFilter')}
        className={embedded ? 'dns-system-fakeip' : undefined}
      >
        <SetRowGroup>
          {/* 总开关 → config.fakeIpFilter（builder/dns.rs:658 `fake_ip_filter != Some(false)`）。
              此前 UI 只在编辑清单时隐式写 true，没有任何关闭路径 —— 用户想整体关掉 filter 够不着。 */}
          <SetRow
            label={t('settings.advanced.fakeIpFilter')}
            tip={t('settings.advanced.fakeIpFilterDesc')}
          >
            <Switch
              id="fakeip-filter-swt"
              checked={fakeIpFilterOn}
              onChange={(v) => void update({ fakeIpFilter: v })}
              aria-label={t('settings.advanced.fakeIpFilter')}
            />
          </SetRow>
          {/* 关闭时不渲染清单：不生效的可编辑清单是误导（同 SettingsTun 排除网段在总开关关闭时的处理）。
              清单编辑因此不再隐式写 fakeIpFilter:true —— 开关是这个字段的唯一控制点。 */}
          {fakeIpFilterOn && (
            <Fold
              className="set-row-details"
              id="fold-fakeip-filter"
              title={t('settings.dns.fakeIpFilterFold')}
              tip={t('settings.dns.fakeIpFilterHint')}
              count={fakeIpFilterList.length}
            >
              <ListEditor
                id="fakeip-filter-list"
                value={fakeIpFilterList}
                onChange={(next) => void update({ fakeIpFilterList: next })}
                placeholder="example.com"
                ariaLabel={t('settings.dns.domain')}
                addLabel={t('settings.dns.addDomain')}
                importLabel={t('common.bulkImport')}
              />
            </Fold>
          )}
        </SetRowGroup>
      </SetBlock>
      )}

      {/* 4. 浏览器内置 DoH 拦截：总开关 + 可编辑清单（形态与上方 FakeIP 例外同构） */}
      {section !== 'policy' && (
      <SetBlock header={t('settings.dns.browserDohTitle')}>
        <SetRowGroup>
          {/* 2026-08-13 之前这里是一张**用户关不掉**的硬编码黑名单（还顺带拦了 14 个 Google 域名），
              已整块移除；现在它是一个默认关的开关。删除依据见 builder/route.rs 的说明块。 */}
          <SetRow
            label={t('settings.dns.browserDohTitle')}
            tip={t('settings.dns.browserDohDesc')}
          >
            <Switch
              id="browser-doh-swt"
              checked={browserDohOn}
              onChange={(v) => void update({ blockBrowserDoh: v })}
              aria-label={t('settings.dns.browserDohTitle')}
            />
          </SetRow>
          {/* 同 FakeIP 例外：关闭时不渲染清单 —— 不生效的可编辑清单是误导。 */}
          {browserDohOn && (
            <Fold
              className="set-row-details"
              id="fold-browser-doh"
              title={t('settings.dns.browserDohFold')}
              tip={t('settings.dns.browserDohHint')}
              count={browserDohList.length}
            >
              <ListEditor
                id="browser-doh-list"
                value={browserDohList}
                onChange={(next) => void update({ browserDohList: next })}
                placeholder="dns.example.com"
                ariaLabel={t('settings.dns.domain')}
                addLabel={t('settings.dns.addDomain')}
                importLabel={t('common.bulkImport')}
              />
            </Fold>
          )}
        </SetRowGroup>
      </SetBlock>
      )}
    </section>
  );
}
