import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { api } from '@/ipc';
import { toast } from '@/lib/error-handler';
import { useAppStore } from '@/store/app-store';
import { useVpnStatusStore } from '@/store/use-vpn-status-store';
import { Modal } from './Modal';
import { useDialogStore } from './dialog-store';

interface Props {
  protocol: 'openconnect' | 'openvpn';
  serverId: string;
}

function VpnIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}>
      <path d="M7 11V8a5 5 0 0 1 10 0v3" />
      <rect x="4" y="11" width="16" height="10" rx="2" />
      <path d="M12 15v2" />
    </svg>
  );
}

export function VpnAuthDialog({ protocol, serverId }: Props) {
  const { t } = useTranslation();
  const close = useDialogStore((state) => state.close);
  const serverName = useAppStore(
    (state) => state.servers.find((server) => server.id === serverId)?.name
  );
  const openConnect = useVpnStatusStore((state) => state.openConnect[serverId]);
  const openVpn = useVpnStatusStore((state) => state.openVpn[serverId]);
  const challenge = protocol === 'openconnect' ? openConnect?.authChallenge : openVpn?.challenge;
  const challengeId = challenge?.id;
  const [submitting, setSubmitting] = useState(false);
  const [formValues, setFormValues] = useState<Record<string, string>>({});
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [secret, setSecret] = useState('');
  const [finalURL, setFinalURL] = useState('');
  const [cookieValues, setCookieValues] = useState<Record<string, string>>({});
  const [headerValues, setHeaderValues] = useState<Record<string, string>>({});

  useEffect(() => {
    if (!challengeId) {
      close();
      return;
    }
    const latest = useVpnStatusStore.getState();
    const latestOpenConnect = latest.openConnect[serverId]?.authChallenge;
    const latestOpenVpn = latest.openVpn[serverId]?.challenge;
    if (protocol === 'openconnect' && latestOpenConnect) {
      const current = latestOpenConnect;
      setFormValues(Object.fromEntries(current.fields.map((field) => [field.submissionKey, field.value])));
      setFinalURL(current.browser?.finalURL ?? '');
      setCookieValues(Object.fromEntries((current.browser?.cookieNames ?? []).map((name) => [name, ''])));
      setHeaderValues(Object.fromEntries((current.browser?.headerNames ?? []).map((name) => [name, ''])));
    } else if (protocol === 'openvpn' && latestOpenVpn) {
      setUsername(latestOpenVpn.username ?? '');
      setPassword('');
      setSecret('');
    }
  }, [challengeId, close, protocol, serverId]);

  const title = `${protocol === 'openconnect' ? 'OpenConnect' : 'OpenVPN'} · ${
    serverName ?? t('vpnAuth.unknownNode')
  }`;
  const canSubmit = useMemo(() => {
    if (!challenge) return false;
    if (protocol === 'openconnect') return challenge.kind === 'form' || challenge.kind === 'browser';
    return !['message', 'open-url'].includes(challenge.kind);
  }, [challenge, protocol]);

  const requestClose = () => {
    const id = challengeId;
    close();
    if (!id) return;
    const cancel =
      protocol === 'openconnect'
        ? api.vpn.cancelOpenConnect(serverId, id)
        : api.vpn.cancelOpenVpn(serverId, id);
    void cancel.catch(() => {});
  };

  const submit = async () => {
    if (!challengeId || !challenge) return;
    setSubmitting(true);
    try {
      if (protocol === 'openconnect' && openConnect?.authChallenge) {
        if (openConnect.authChallenge.kind === 'form') {
          await api.vpn.submitOpenConnectForm(serverId, challengeId, formValues);
        } else if (openConnect.authChallenge.kind === 'browser') {
          await api.vpn.submitOpenConnectBrowser(
            serverId,
            challengeId,
            finalURL,
            Object.entries(cookieValues).map(([name, value]) => ({ name, value })),
            Object.entries(headerValues).map(([name, value]) => ({
              name,
              values: value.split('\n').map((line) => line.trim()).filter(Boolean),
            }))
          );
        }
      } else if (protocol === 'openvpn' && openVpn?.challenge) {
        await api.vpn.submitOpenVpn(serverId, challengeId, username, password, secret);
      }
      close();
    } catch (error) {
      console.error('[VpnAuthDialog] submit failed:', error);
      toast.error(t('vpnAuth.submitFailed'));
    } finally {
      setSubmitting(false);
    }
  };

  const openChallengeURL = () => {
    const url =
      protocol === 'openconnect' ? openConnect?.authChallenge?.browser?.url : openVpn?.challenge?.url;
    if (url) void api.system.openExternal(url);
  };

  const openConnectChallenge = openConnect?.authChallenge;
  const openVpnChallenge = openVpn?.challenge;

  return (
    <Modal
      titleId="vpn-auth-title"
      title={title}
      icon={<VpnIcon />}
      onClose={requestClose}
      className="entry-form-dlg"
      footer={
        <>
          <button type="button" className="btn ghost" onClick={requestClose}>
            {t('common.cancel')}
          </button>
          {(openConnectChallenge?.kind === 'browser' || openVpnChallenge?.kind === 'open-url') && (
            <button type="button" className="btn ghost" onClick={openChallengeURL}>
              {t('vpnAuth.openBrowser')}
            </button>
          )}
          {canSubmit && (
            <button type="button" className="btn flow" disabled={submitting} onClick={() => void submit()}>
              {submitting && <span className="spinner spin-inline" style={{ marginRight: 6 }} />}
              {t('common.confirm')}
            </button>
          )}
        </>
      }
    >
      {(openConnectChallenge?.banner || openConnectChallenge?.message || openVpnChallenge?.message) && (
        <div className="note-box" style={{ whiteSpace: 'pre-wrap' }}>
          {openConnectChallenge?.banner && <div>{openConnectChallenge.banner}</div>}
          <div>{openConnectChallenge?.message ?? openVpnChallenge?.message}</div>
        </div>
      )}
      {(openConnectChallenge?.error || openVpnChallenge?.previousError) && (
        <div className="note-box danger" style={{ whiteSpace: 'pre-wrap' }}>
          {t('vpnAuth.submitFailed')}
        </div>
      )}

      {openConnectChallenge?.kind === 'form' &&
        openConnectChallenge.fields.map((field) => (
          <div className="fld" key={field.submissionKey}>
            <label className="fld-l" htmlFor={`vpn-${field.submissionKey}`}>
              {field.label || field.name}
            </label>
            {field.options.length > 0 ? (
              <select
                id={`vpn-${field.submissionKey}`}
                className="input"
                value={formValues[field.submissionKey] ?? ''}
                onChange={(event) =>
                  setFormValues((values) => ({ ...values, [field.submissionKey]: event.target.value }))
                }
              >
                {field.options.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label || option.value}
                  </option>
                ))}
              </select>
            ) : (
              <input
                id={`vpn-${field.submissionKey}`}
                className="input"
                type={field.kind === 'password' ? 'password' : 'text'}
                value={formValues[field.submissionKey] ?? ''}
                onChange={(event) =>
                  setFormValues((values) => ({ ...values, [field.submissionKey]: event.target.value }))
                }
              />
            )}
          </div>
        ))}

      {openConnectChallenge?.kind === 'browser' && (
        <>
          <div className="card-sub" style={{ marginBottom: 10 }}>
            {t('vpnAuth.browserResultHelp')}
          </div>
          <div className="fld">
            <label className="fld-l" htmlFor="vpn-final-url">{t('vpnAuth.finalURL')}</label>
            <input id="vpn-final-url" className="input mono" value={finalURL} onChange={(e) => setFinalURL(e.target.value)} />
          </div>
          {Object.keys(cookieValues).map((name) => (
            <div className="fld" key={`cookie-${name}`}>
              <label className="fld-l" htmlFor={`vpn-cookie-${name}`}>{t('vpnAuth.cookie')} · {name}</label>
              <input id={`vpn-cookie-${name}`} className="input mono" type="password" value={cookieValues[name]} onChange={(e) => setCookieValues((values) => ({ ...values, [name]: e.target.value }))} />
            </div>
          ))}
          {Object.keys(headerValues).map((name) => (
            <div className="fld" key={`header-${name}`}>
              <label className="fld-l" htmlFor={`vpn-header-${name}`}>{t('vpnAuth.header')} · {name}</label>
              <textarea id={`vpn-header-${name}`} className="input mono" rows={2} value={headerValues[name]} onChange={(e) => setHeaderValues((values) => ({ ...values, [name]: e.target.value }))} />
            </div>
          ))}
        </>
      )}

      {protocol === 'openvpn' && openVpnChallenge && !['message', 'open-url'].includes(openVpnChallenge.kind) && (
        <>
          {openVpnChallenge.kind === 'credentials' && (
            <div className="fld">
              <label className="fld-l" htmlFor="vpn-username">{t('vpnAuth.username')}</label>
              <input id="vpn-username" className="input" value={username} onChange={(e) => setUsername(e.target.value)} />
            </div>
          )}
          {openVpnChallenge.kind === 'credentials' && (
            <div className="fld">
              <label className="fld-l" htmlFor="vpn-password">{t('vpnAuth.password')}</label>
              <input id="vpn-password" className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
            </div>
          )}
          {(openVpnChallenge.kind === 'secret' || openVpnChallenge.secretMessage) && (
            <div className="fld">
              <label className="fld-l" htmlFor="vpn-secret">
                {openVpnChallenge.secretMessage || t('vpnAuth.secret')}
              </label>
              <input id="vpn-secret" className="input" type={openVpnChallenge.echo ? 'text' : 'password'} value={secret} onChange={(e) => setSecret(e.target.value)} />
            </div>
          )}
        </>
      )}
    </Modal>
  );
}

export default VpnAuthDialog;
