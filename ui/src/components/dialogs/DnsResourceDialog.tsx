/**
 * DNS 服务器 / 服务器组的统一资源表单。
 *
 * 列表只负责浏览与启停；完整编辑在 Modal 内使用本地草稿，提交时一次性替换资源集合。
 * 这样取消不会留下半份配置，保存失败也会保留用户已经填写的内容。
 */

import { useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import type {
  DnsServerGroup,
  DnsServerKind,
  DnsServerResource,
  UserConfig,
} from '@/contracts/types';
import { isIpLiteral } from '@/domain/ip-literal';
import { useDialogStore } from './dialog-store';
import { Modal } from './Modal';
import { dnsServerDescription, dnsServerDisplayName } from './dns-action-options';
import { useConfig, type UseConfigResult } from '../screens/settings/use-config';
import { Select, Spinner, TextInput } from '../screens/settings/Primitives';

const PROTECTED_DNS_SERVER_IDS = new Set([
  'builtin-domestic',
  'builtin-remote',
  'builtin-bootstrap',
]);

export function isProtectedDnsServer(serverId: string): boolean {
  return PROTECTED_DNS_SERVER_IDS.has(serverId);
}

/** Hosts 内联记录编辑格式：每行 `domain = value1, value2`；坏行跳过。 */
export function parseHostsPredefined(raw: string): Record<string, string[]> {
  const records: Record<string, string[]> = {};
  for (const line of raw.split(/\r?\n/)) {
    const separator = line.indexOf('=');
    if (separator <= 0) continue;
    const domain = line.slice(0, separator).trim();
    const values = line
      .slice(separator + 1)
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean);
    if (domain && values.length > 0) records[domain] = [...new Set(values)];
  }
  return records;
}

export function formatHostsPredefined(records: Record<string, string[]> | undefined): string {
  return Object.entries(records ?? {})
    .map(([domain, values]) => `${domain} = ${values.join(', ')}`)
    .join('\n');
}

export function moveDnsGroupMember(
  members: readonly string[],
  from: number,
  to: number,
): string[] {
  if (from < 0 || from >= members.length || to < 0 || to >= members.length || from === to) {
    return [...members];
  }
  const next = [...members];
  const [moved] = next.splice(from, 1);
  next.splice(to, 0, moved);
  return next;
}

export type DnsServerFormError =
  | 'name'
  | 'host'
  | 'port'
  | 'bootstrapIp'
  | 'bootstrapMissing';

export function validateDnsServerForm(input: {
  name: string;
  type: DnsServerKind;
  host: string;
  port: string;
  isBootstrap: boolean;
  bootstrapServerId: string;
  validBootstrapServerIds: ReadonlySet<string>;
}): DnsServerFormError | null {
  if (!input.name.trim()) return 'name';
  if (input.type === 'local' || input.type === 'hosts') return null;
  const host = input.host.trim();
  if (!host) return 'host';
  if (input.port.trim()) {
    const port = Number(input.port);
    if (!/^\d+$/.test(input.port.trim()) || !Number.isInteger(port) || port < 1 || port > 65535) {
      return 'port';
    }
  }
  if (input.isBootstrap && !isIpLiteral(host)) return 'bootstrapIp';
  if (
    !input.isBootstrap
    && !isIpLiteral(host)
    && !input.validBootstrapServerIds.has(input.bootstrapServerId)
  ) {
    return 'bootstrapMissing';
  }
  return null;
}

export type DnsGroupFormError = 'name' | 'members';

export function validateDnsGroupForm(input: {
  name: string;
  members: readonly string[];
}): DnsGroupFormError | null {
  if (!input.name.trim()) return 'name';
  if (input.members.length === 0) return 'members';
  return null;
}

function ServerIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}>
      <rect x="3" y="4" width="18" height="7" rx="1.5" />
      <rect x="3" y="13" width="18" height="7" rx="1.5" />
      <path d="M7 7.5h.01M7 16.5h.01M11 7.5h6M11 16.5h6" />
    </svg>
  );
}

function GroupIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}>
      <rect x="3" y="3" width="7" height="7" rx="1.5" />
      <rect x="14" y="3" width="7" height="7" rx="1.5" />
      <rect x="8.5" y="14" width="7" height="7" rx="1.5" />
      <path d="M6.5 10v2h11v-2M12 12v2" />
    </svg>
  );
}

function Field({
  label,
  required,
  error,
  children,
}: {
  label: ReactNode;
  required?: boolean;
  error?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="fld">
      <span className="fld-l">
        {label}{required && <span className="req-star"> *</span>}
      </span>
      {children}
      {error && <div className="err-line">{error}</div>}
    </div>
  );
}

function defaultPort(type: DnsServerKind): string {
  if (type === 'https') return '443';
  if (type === 'tls') return '853';
  if (type === 'udp' || type === 'tcp') return '53';
  return '';
}

type ConfigUpdate = UseConfigResult['update'];

function DnsServerForm({
  config,
  update,
  base,
}: {
  config: UserConfig;
  update: ConfigUpdate;
  base?: DnsServerResource;
}) {
  const { t } = useTranslation();
  const open = useDialogStore((state) => state.open);
  const close = useDialogStore((state) => state.close);
  const isEdit = base != null;
  const builtin = base ? isProtectedDnsServer(base.id) : false;
  const bootstrap = base?.id === 'builtin-bootstrap';

  const [name, setName] = useState(() => base ? dnsServerDisplayName(base, t) : t('settings.dns.serverNewName'));
  const [type, setType] = useState<DnsServerKind>(base?.type ?? 'https');
  const [host, setHost] = useState(base?.endpoint?.host ?? '1.1.1.1');
  const [port, setPort] = useState(
    base?.endpoint?.port != null ? String(base.endpoint.port) : defaultPort(base?.type ?? 'https'),
  );
  const [path, setPath] = useState(base?.endpoint?.path ?? '/dns-query');
  const [outbound, setOutbound] = useState(() => {
    if (!base || base.outbound.type !== 'node') return base?.outbound.type ?? 'direct';
    return `node:${base.outbound.nodeId}`;
  });
  const [bootstrapServerId, setBootstrapServerId] = useState(base?.bootstrapServerId ?? '');
  const [paths, setPaths] = useState((base?.paths ?? []).join(', '));
  const [hosts, setHosts] = useState(formatHostsPredefined(base?.predefined));
  const [dirty, setDirty] = useState(false);
  const [error, setError] = useState<DnsServerFormError | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const dnsServers = config.dnsServers ?? [];
  const network = type !== 'local' && type !== 'hosts';
  const bootstrapCandidates = dnsServers.filter((candidate) => (
    candidate.id !== base?.id
    && candidate.enabled
    && candidate.type !== 'hosts'
    && (
      candidate.type === 'local'
      || (
        candidate.outbound.type === 'direct'
        && !!candidate.endpoint?.host
        && isIpLiteral(candidate.endpoint.host)
      )
    )
  ));
  const validBootstrapServerIds = new Set(bootstrapCandidates.map((candidate) => candidate.id));

  const touch = () => {
    setDirty(true);
    setError(null);
  };

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
          close();
          close();
        },
      },
    });
  };

  const handleSubmit = async () => {
    const validationError = validateDnsServerForm({
      name,
      type,
      host,
      port,
      isBootstrap: bootstrap,
      bootstrapServerId,
      validBootstrapServerIds,
    });
    setError(validationError);
    if (validationError) return;

    const endpoint = network
      ? {
          host: host.trim(),
          ...(port.trim() ? { port: Number(port) } : {}),
          ...(type === 'https' && path.trim() ? { path: path.trim() } : {}),
        }
      : undefined;
    const next: DnsServerResource = {
      id: base?.id ?? `dns-${crypto.randomUUID()}`,
      // 内置资源的显示名由 i18n 决定；保留盘上的稳定名称，避免把当前语言写进配置。
      name: builtin && base ? base.name : name.trim(),
      enabled: base?.enabled ?? true,
      type,
      endpoint,
      bootstrapServerId:
        network && !bootstrap && !isIpLiteral(host.trim()) ? bootstrapServerId : undefined,
      outbound: network && !bootstrap
        ? outbound.startsWith('node:')
          ? { type: 'node', nodeId: outbound.slice(5) }
          : { type: outbound as 'direct' | 'currentExit' }
        : { type: 'direct' },
      paths: type === 'hosts'
        ? paths.split(',').map((entry) => entry.trim()).filter(Boolean)
        : undefined,
      predefined: type === 'hosts' ? parseHostsPredefined(hosts) : undefined,
    };

    const nextServers = isEdit
      ? dnsServers.map((server) => (server.id === next.id ? next : server))
      : [...dnsServers, next];
    setSubmitting(true);
    try {
      await update({ dnsServers: nextServers }, { throwOnError: true });
      close();
    } catch {
      // useConfig 已显示保存失败原因；保留弹窗和草稿供用户修正或重试。
    } finally {
      setSubmitting(false);
    }
  };

  const errorText = (kind: DnsServerFormError): string | undefined => {
    if (error !== kind) return undefined;
    if (kind === 'name') return t('settings.dns.serverNameRequired');
    if (kind === 'host') return t('settings.dns.serverHostRequired');
    if (kind === 'port') return t('settings.dns.serverPortInvalid');
    if (kind === 'bootstrapIp') return t('settings.dns.bootstrapIpOnly');
    return t('settings.dns.serverBootstrapRequired');
  };

  return (
    <Modal
      titleId="dns-server-title"
      title={t(isEdit ? 'settings.dns.serverEditTitle' : 'settings.dns.serverAddTitle')}
      icon={<ServerIcon />}
      onClose={requestClose}
      className="dns-resource-dlg"
      footer={
        <>
          <button type="button" className="btn ghost" onClick={requestClose} disabled={submitting}>
            {t('common.cancel')}
          </button>
          <button type="button" className="btn flow" onClick={() => void handleSubmit()} disabled={submitting}>
            {t(isEdit ? 'common.save' : 'common.add')}
          </button>
        </>
      }
    >
      <Field label={t('settings.dns.serverName')} required error={errorText('name')}>
        <TextInput
          value={name}
          disabled={builtin}
          onChange={(event) => {
            setName(event.target.value);
            touch();
          }}
          aria-label={t('settings.dns.serverName')}
        />
      </Field>

      <div className="dns-resource-form-grid">
        <Field label={t('settings.dns.serverType')} required>
          <Select
            value={type}
            onChange={(event) => {
              const next = event.target.value as DnsServerKind;
              if (!port.trim() || port === defaultPort(type)) setPort(defaultPort(next));
              setType(next);
              if (next === 'https' && !path.trim()) setPath('/dns-query');
              touch();
            }}
            aria-label={t('settings.dns.serverType')}
          >
            <option value="https">{t('settings.dns.serverType_https')}</option>
            <option value="tls">{t('settings.dns.serverType_tls')}</option>
            <option value="udp">{t('settings.dns.serverType_udp')}</option>
            <option value="tcp">{t('settings.dns.serverType_tcp')}</option>
            <option value="local">{t('settings.dns.serverType_local')}</option>
            {!builtin && <option value="hosts">{t('settings.dns.serverType_hosts')}</option>}
          </Select>
        </Field>
        {network && (
          <Field label={t('settings.dns.serverOutbound')} required>
            <Select
              value={bootstrap ? 'direct' : outbound}
              disabled={bootstrap}
              tip={bootstrap ? t('settings.dns.bootstrapDirectOnly') : undefined}
              onChange={(event) => {
                setOutbound(event.target.value);
                touch();
              }}
              aria-label={t('settings.dns.serverOutbound')}
            >
              <option value="direct">{t('settings.dns.outboundDirect')}</option>
              {!bootstrap && <option value="currentExit">{t('settings.dns.outboundCurrentExit')}</option>}
              {!bootstrap && (config.servers ?? []).map((node) => (
                <option key={node.id} value={`node:${node.id}`}>
                  {t('settings.dns.outboundNode', { name: node.name })}
                </option>
              ))}
            </Select>
          </Field>
        )}
      </div>

      {network && (
        <div className="dns-endpoint-form-grid">
          <Field label={t('settings.dns.serverHost')} required error={errorText('host') ?? errorText('bootstrapIp')}>
            <TextInput
              value={host}
              onChange={(event) => {
                setHost(event.target.value);
                touch();
              }}
              placeholder={t('settings.dns.serverHost')}
              aria-label={t('settings.dns.serverHost')}
            />
          </Field>
          <Field label={t('settings.dns.serverPort')} error={errorText('port')}>
            <TextInput
              inputMode="numeric"
              value={port}
              onChange={(event) => {
                setPort(event.target.value);
                touch();
              }}
              placeholder={t('settings.dns.serverPort')}
              aria-label={t('settings.dns.serverPort')}
            />
          </Field>
        </div>
      )}

      {type === 'https' && (
        <Field label={t('settings.dns.serverPath')}>
          <TextInput
            value={path}
            onChange={(event) => {
              setPath(event.target.value);
              touch();
            }}
            aria-label={t('settings.dns.serverPath')}
          />
        </Field>
      )}

      {!bootstrap && network && host.trim() && !isIpLiteral(host.trim()) && (
        <Field label={t('settings.dns.serverBootstrap')} required error={errorText('bootstrapMissing')}>
          <Select
            value={bootstrapServerId}
            onChange={(event) => {
              setBootstrapServerId(event.target.value);
              touch();
            }}
            aria-label={t('settings.dns.serverBootstrap')}
          >
            <option value="">{t('settings.dns.serverBootstrapRequired')}</option>
            {bootstrapCandidates.map((candidate) => (
              <option key={candidate.id} value={candidate.id}>
                {dnsServerDisplayName(candidate, t)}
              </option>
            ))}
          </Select>
        </Field>
      )}

      {type === 'hosts' && (
        <>
          <Field label={t('settings.dns.hostsPaths')}>
            <TextInput
              value={paths}
              onChange={(event) => {
                setPaths(event.target.value);
                touch();
              }}
              placeholder={t('settings.dns.hostsPaths')}
              aria-label={t('settings.dns.hostsPaths')}
            />
          </Field>
          <Field label={t('settings.dns.hostsInline')}>
            <textarea
              className="input mono dns-hosts-editor"
              rows={5}
              value={hosts}
              onChange={(event) => {
                setHosts(event.target.value);
                touch();
              }}
              placeholder={t('settings.dns.hostsInlinePlaceholder')}
              aria-label={t('settings.dns.hostsInline')}
            />
          </Field>
        </>
      )}
    </Modal>
  );
}

function DnsGroupForm({
  config,
  update,
  base,
}: {
  config: UserConfig;
  update: ConfigUpdate;
  base?: DnsServerGroup;
}) {
  const { t } = useTranslation();
  const open = useDialogStore((state) => state.open);
  const close = useDialogStore((state) => state.close);
  const isEdit = base != null;
  const [name, setName] = useState(base?.name ?? t('settings.dns.groupNewName'));
  const [mode, setMode] = useState<'race' | 'fallback'>(base?.mode ?? 'race');
  const [members, setMembers] = useState<string[]>(base?.members ?? []);
  const [fallbackServerId, setFallbackServerId] = useState(base?.fallbackServerId ?? '');
  const [dirty, setDirty] = useState(false);
  const [error, setError] = useState<DnsGroupFormError | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const dnsServers = config.dnsServers ?? [];
  const dnsGroups = config.dnsServerGroups ?? [];
  const memberServers = members
    .map((id) => dnsServers.find((server) => server.id === id))
    .filter((server): server is DnsServerResource => server != null);
  const availableToAdd = dnsServers.filter((server) => server.enabled && !members.includes(server.id));

  const touch = () => {
    setDirty(true);
    setError(null);
  };

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
          close();
          close();
        },
      },
    });
  };

  const handleSubmit = async () => {
    const validationError = validateDnsGroupForm({ name, members });
    setError(validationError);
    if (validationError) return;
    const next: DnsServerGroup = {
      id: base?.id ?? `dns-group-${crypto.randomUUID()}`,
      name: name.trim(),
      enabled: base?.enabled ?? true,
      mode,
      members,
      fallbackServerId: fallbackServerId || undefined,
    };
    const nextGroups = isEdit
      ? dnsGroups.map((group) => (group.id === next.id ? next : group))
      : [...dnsGroups, next];
    setSubmitting(true);
    try {
      await update({ dnsServerGroups: nextGroups }, { throwOnError: true });
      close();
    } catch {
      // useConfig 已显示保存失败原因；保留弹窗和草稿供用户修正或重试。
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal
      titleId="dns-group-title"
      title={t(isEdit ? 'settings.dns.groupEditTitle' : 'settings.dns.groupAddTitle')}
      icon={<GroupIcon />}
      onClose={requestClose}
      className="dns-resource-dlg"
      footer={
        <>
          <button type="button" className="btn ghost" onClick={requestClose} disabled={submitting}>
            {t('common.cancel')}
          </button>
          <button type="button" className="btn flow" onClick={() => void handleSubmit()} disabled={submitting}>
            {t(isEdit ? 'common.save' : 'common.add')}
          </button>
        </>
      }
    >
      <div className="dns-resource-form-grid">
        <Field
          label={t('settings.dns.groupName')}
          required
          error={error === 'name' ? t('settings.dns.groupNameRequired') : undefined}
        >
          <TextInput
            value={name}
            onChange={(event) => {
              setName(event.target.value);
              touch();
            }}
            aria-label={t('settings.dns.groupName')}
          />
        </Field>
        <Field label={t('settings.dns.groupMode')} required>
          <Select
            value={mode}
            onChange={(event) => {
              setMode(event.target.value as 'race' | 'fallback');
              touch();
            }}
            aria-label={t('settings.dns.groupMode')}
          >
            <option value="race">{t('settings.dns.groupRace')}</option>
            <option value="fallback">{t('settings.dns.groupFallback')}</option>
          </Select>
        </Field>
      </div>
      <div className="card-sub">
        {t(mode === 'race' ? 'settings.dns.groupRaceDesc' : 'settings.dns.groupFallbackDesc')}
      </div>
      {mode === 'race' && members.length > 0 && memberServers.filter((server) => server.enabled).length < 2 && (
        <div className="err-line">{t('settings.dns.groupRaceDegraded')}</div>
      )}

      <Field
        label={t('settings.dns.groupMembers')}
        required
        error={error === 'members' ? t('settings.dns.groupMembersRequired') : undefined}
      >
        <div className="dns-group-members">
          {members.length === 0 && (
            <div className="card-sub">{t('settings.dns.groupNoMembers')}</div>
          )}
          {members.map((serverId, index) => {
            const server = dnsServers.find((candidate) => candidate.id === serverId);
            return (
              <div
                key={serverId}
                className={`dns-group-member${server?.enabled === false || !server ? ' unavailable' : ''}`}
              >
                <span className="dns-group-member-order">{index + 1}</span>
                <span className="dns-group-member-copy">
                  <span>{server ? dnsServerDisplayName(server, t) : serverId}</span>
                  <span className="dns-resource-meta">
                    {server
                      ? dnsServerDescription(server, config.servers ?? [], t)
                      : t('rules.dnsActionUnavailable')}
                  </span>
                </span>
                <span className="dns-group-member-actions">
                  <button
                    type="button"
                    className="btn ghost sm"
                    disabled={index === 0}
                    aria-label={t('rules.moveUp')}
                    onClick={() => {
                      setMembers(moveDnsGroupMember(members, index, index - 1));
                      touch();
                    }}
                  >↑</button>
                  <button
                    type="button"
                    className="btn ghost sm"
                    disabled={index === members.length - 1}
                    aria-label={t('rules.moveDown')}
                    onClick={() => {
                      setMembers(moveDnsGroupMember(members, index, index + 1));
                      touch();
                    }}
                  >↓</button>
                  <button
                    type="button"
                    className="btn ghost sm"
                    aria-label={t('settings.dns.groupRemoveMember')}
                    onClick={() => {
                      setMembers(members.filter((id) => id !== serverId));
                      touch();
                    }}
                  >{t('settings.dns.groupRemoveMember')}</button>
                </span>
              </div>
            );
          })}
          {availableToAdd.length > 0 && (
            <Select
              value=""
              onChange={(event) => {
                if (!event.target.value) return;
                setMembers([...members, event.target.value]);
                touch();
              }}
              aria-label={t('settings.dns.groupAddMember')}
            >
              <option value="">{t('settings.dns.groupAddMember')}</option>
              {availableToAdd.map((server) => (
                <option key={server.id} value={server.id}>{dnsServerDisplayName(server, t)}</option>
              ))}
            </Select>
          )}
        </div>
      </Field>

      <Field label={t('settings.dns.groupFallbackServer')}>
        <Select
          value={fallbackServerId}
          onChange={(event) => {
            setFallbackServerId(event.target.value);
            touch();
          }}
          aria-label={t('settings.dns.groupFallbackServer')}
        >
          <option value="">{t('settings.dns.groupNoFallback')}</option>
          {dnsServers.filter((server) => (
            server.enabled
            && server.type !== 'hosts'
            && (!members.includes(server.id) || fallbackServerId === server.id)
          )).map((server) => (
            <option key={server.id} value={server.id}>
              {dnsServerDisplayName(server, t)}
              {members.includes(server.id) ? ` · ${t('settings.dns.groupFallbackRedundant')}` : ''}
            </option>
          ))}
        </Select>
      </Field>
    </Modal>
  );
}

function DnsResourceState({
  resource,
  resourceId,
}: {
  resource: 'server' | 'group';
  resourceId?: string;
}) {
  const { t } = useTranslation();
  const close = useDialogStore((state) => state.close);
  const { config, loading, error, update, reload } = useConfig();
  const isEdit = resourceId != null;
  const title = t(
    resource === 'server'
      ? isEdit ? 'settings.dns.serverEditTitle' : 'settings.dns.serverAddTitle'
      : isEdit ? 'settings.dns.groupEditTitle' : 'settings.dns.groupAddTitle',
  );
  const icon = resource === 'server' ? <ServerIcon /> : <GroupIcon />;

  if (loading) {
    return (
      <Modal
        titleId="dns-resource-loading-title"
        title={title}
        icon={icon}
        onClose={close}
        className="dns-resource-dlg"
        footer={<button type="button" className="btn ghost" onClick={close}>{t('common.cancel')}</button>}
      >
        <div className="dns-workspace-loading"><Spinner /></div>
      </Modal>
    );
  }

  const base = resource === 'server'
    ? config?.dnsServers?.find((server) => server.id === resourceId)
    : config?.dnsServerGroups?.find((group) => group.id === resourceId);
  if (error || !config || (resourceId && !base)) {
    return (
      <Modal
        titleId="dns-resource-error-title"
        title={title}
        icon={icon}
        onClose={close}
        className="dns-resource-dlg"
        footer={
          <>
            <button type="button" className="btn ghost" onClick={close}>{t('common.close')}</button>
            {error && <button type="button" className="btn flow" onClick={() => void reload()}>{t('common.retry')}</button>}
          </>
        }
      >
        <div className="stub">
          <p>
            {resourceId && !base
              ? t(resource === 'server' ? 'rules.dnsActionMissingServer' : 'rules.dnsActionMissingGroup', { id: resourceId })
              : t('common.configLoadFail')}
          </p>
        </div>
      </Modal>
    );
  }

  return resource === 'server'
    ? <DnsServerForm config={config} update={update} base={base as DnsServerResource | undefined} />
    : <DnsGroupForm config={config} update={update} base={base as DnsServerGroup | undefined} />;
}

export function DnsServerDialog({ serverId }: { serverId?: string }) {
  return <DnsResourceState resource="server" resourceId={serverId} />;
}

export function DnsGroupDialog({ groupId }: { groupId?: string }) {
  return <DnsResourceState resource="group" resourceId={groupId} />;
}
