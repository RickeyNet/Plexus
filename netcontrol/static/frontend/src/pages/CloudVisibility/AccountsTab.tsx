import { useEffect, useState } from 'react';

import {
  type CloudAccount,
  useCreateCloudAccount,
  useDeleteCloudAccount,
  useDiscoverCloudAccount,
  useTriggerCloudFlowPull,
  useTriggerCloudTrafficPull,
  useUpdateCloudAccount,
  useValidateCloudAccount,
} from '@/api/cloud';
import { Modal } from '@/components/Modal';
import { authHintContent, computeSyncReadiness, formatTimestamp, providerLabel } from './helpers';

interface Props {
  accounts: CloudAccount[];
  providerOptions: string[];
  isLoading: boolean;
}

const AUTH_TYPES = ['manual', 'api_keys', 'assume_role', 'service_principal', 'workload_identity'];

export function AccountsTab({ accounts, providerOptions, isLoading }: Props) {
  const [modalAccount, setModalAccount] = useState<CloudAccount | null | undefined>(undefined);
  const [confirmDelete, setConfirmDelete] = useState<CloudAccount | null>(null);
  const [confirmDiscover, setConfirmDiscover] = useState<CloudAccount | null>(null);
  const [actionMsg, setActionMsg] = useState<{ kind: 'success' | 'error'; text: string } | null>(null);

  const validate = useValidateCloudAccount();
  const discover = useDiscoverCloudAccount();
  const deleteAcct = useDeleteCloudAccount();
  const flowPull = useTriggerCloudFlowPull();
  const trafficPull = useTriggerCloudTrafficPull();

  function showMsg(kind: 'success' | 'error', text: string) {
    setActionMsg({ kind, text });
    setTimeout(() => setActionMsg(null), 6000);
  }

  async function runValidate(a: CloudAccount) {
    try {
      const result = await validate.mutateAsync(a.id);
      if (result?.valid) {
        showMsg('success', `${a.name}: ${result.message ?? 'Validation succeeded'}`);
      } else {
        let detail = result?.message ?? 'Validation failed';
        const missing = Array.isArray(result?.missing_dependencies) ? result.missing_dependencies : [];
        if (result?.status === 'unavailable' && missing.length) detail += ` (missing: ${missing.join(', ')})`;
        showMsg('error', `${a.name}: ${detail}`);
      }
    } catch (e) {
      showMsg('error', `${a.name}: ${(e as Error).message}`);
    }
  }

  async function runDiscover(a: CloudAccount) {
    try {
      const result = await discover.mutateAsync(a.id);
      showMsg('success', result?.message ?? 'Discovery completed');
    } catch (e) {
      showMsg('error', `Discovery failed: ${(e as Error).message}`);
    } finally {
      setConfirmDiscover(null);
    }
  }

  async function runDelete(a: CloudAccount) {
    try {
      await deleteAcct.mutateAsync(a.id);
      showMsg('success', `Deleted "${a.name}"`);
    } catch (e) {
      showMsg('error', `Delete failed: ${(e as Error).message}`);
    } finally {
      setConfirmDelete(null);
    }
  }

  async function runFlowPull(a: CloudAccount) {
    try {
      const r = await flowPull.mutateAsync(a.id);
      const ingested = Number(r?.ingested ?? r?.total_ingested ?? 0);
      showMsg('success', `${a.name}: flow pull ingested ${ingested.toLocaleString()}`);
    } catch (e) {
      showMsg('error', `Flow pull failed: ${(e as Error).message}`);
    }
  }

  async function runTrafficPull(a: CloudAccount) {
    try {
      const r = await trafficPull.mutateAsync(a.id);
      const ingested = Number(r?.ingested ?? r?.total_ingested ?? 0);
      showMsg('success', `${a.name}: traffic pull ingested ${ingested.toLocaleString()}`);
    } catch (e) {
      showMsg('error', `Traffic pull failed: ${(e as Error).message}`);
    }
  }

  return (
    <div>
      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.75rem' }}>
        <button className="btn btn-primary" onClick={() => setModalAccount(null)}>
          Add Cloud Account
        </button>
      </div>

      {actionMsg && (
        <div
          className="card"
          style={{
            padding: '0.6rem 0.85rem',
            marginBottom: '0.6rem',
            borderLeft: `3px solid var(--${actionMsg.kind === 'success' ? 'success' : 'danger'})`,
          }}
        >
          {actionMsg.text}
        </div>
      )}

      {isLoading && <div className="text-muted">Loading…</div>}

      {!isLoading && accounts.length === 0 && (
        <div className="card" style={{ padding: '1.25rem' }}>
          <p className="text-muted" style={{ margin: 0 }}>
            No cloud accounts configured. Add an AWS / Azure / GCP account to start building hybrid visibility.
          </p>
        </div>
      )}

      {accounts.length > 0 && (
        <div style={{ overflowX: 'auto' }}>
          <table className="chart-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Provider</th>
                <th>Account</th>
                <th>Scope</th>
                <th>Last Sync</th>
                <th>Sync Readiness</th>
                <th>Resources</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {accounts.map((a) => {
                const readiness = computeSyncReadiness(a);
                return (
                  <tr key={a.id}>
                    <td>{a.name}</td>
                    <td>{providerLabel(a.provider)}</td>
                    <td>{a.account_identifier ?? '-'}</td>
                    <td>{a.region_scope ?? '-'}</td>
                    <td>
                      <div>{a.last_sync_status ?? 'never'}</div>
                      <small className="text-muted">{a.last_sync_at ? formatTimestamp(a.last_sync_at) : 'Never'}</small>
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
                        <span className={`badge badge-${readiness.flowReady ? 'success' : 'warning'}`}>
                          Flow {readiness.flowReady ? 'ready' : 'needs config'}
                        </span>
                        <span className={`badge badge-${readiness.trafficReady ? 'success' : 'warning'}`}>
                          Traffic {readiness.trafficReady ? 'ready' : 'needs config'}
                        </span>
                      </div>
                      {(!readiness.flowReady || !readiness.trafficReady) && (
                        <small className="text-muted" style={{ display: 'block', marginTop: '0.25rem' }}>
                          {!readiness.flowReady && `Flow: missing ${readiness.flowMissing.join(', ')}`}
                          {!readiness.flowReady && !readiness.trafficReady && ' | '}
                          {!readiness.trafficReady && `Traffic: missing ${readiness.trafficMissing.join(', ')}`}
                        </small>
                      )}
                    </td>
                    <td>
                      <span className="badge badge-info">{a.resource_count ?? 0} nodes</span>{' '}
                      <span className="badge badge-info">{a.connection_count ?? 0} edges</span>
                    </td>
                    <td style={{ whiteSpace: 'nowrap' }}>
                      <button className="btn btn-sm btn-secondary" onClick={() => runValidate(a)} disabled={validate.isPending}>
                        Validate
                      </button>{' '}
                      <button className="btn btn-sm btn-secondary" onClick={() => setConfirmDiscover(a)}>
                        Discover
                      </button>{' '}
                      <button className="btn btn-sm btn-secondary" onClick={() => runFlowPull(a)} disabled={flowPull.isPending}>
                        Pull Flow
                      </button>{' '}
                      <button className="btn btn-sm btn-secondary" onClick={() => runTrafficPull(a)} disabled={trafficPull.isPending}>
                        Pull Traffic
                      </button>{' '}
                      <button className="btn btn-sm btn-secondary" onClick={() => setModalAccount(a)}>
                        Edit
                      </button>{' '}
                      <button className="btn btn-sm btn-danger" onClick={() => setConfirmDelete(a)}>
                        Delete
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {modalAccount !== undefined && (
        <AccountFormModal
          account={modalAccount}
          providerOptions={providerOptions}
          onClose={() => setModalAccount(undefined)}
          onSaved={(msg) => {
            showMsg('success', msg);
            setModalAccount(undefined);
          }}
        />
      )}

      <Modal
        isOpen={Boolean(confirmDelete)}
        onClose={() => setConfirmDelete(null)}
        title="Delete Cloud Account"
      >
        {confirmDelete && (
          <div>
            <p>
              Delete <strong>{confirmDelete.name}</strong> and all discovered cloud topology data?
            </p>
            <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
              <button className="btn btn-secondary" onClick={() => setConfirmDelete(null)}>Cancel</button>
              <button className="btn btn-danger" onClick={() => runDelete(confirmDelete)} disabled={deleteAcct.isPending}>
                Delete
              </button>
            </div>
          </div>
        )}
      </Modal>

      <Modal
        isOpen={Boolean(confirmDiscover)}
        onClose={() => setConfirmDiscover(null)}
        title="Run Cloud Discovery"
      >
        {confirmDiscover && (
          <div>
            <p>
              Refresh cloud topology snapshot for <strong>{confirmDiscover.name}</strong>? Auto mode tries live provider APIs first, then falls back to sample data if dependencies/credentials are missing.
            </p>
            <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
              <button className="btn btn-secondary" onClick={() => setConfirmDiscover(null)}>Cancel</button>
              <button className="btn btn-primary" onClick={() => runDiscover(confirmDiscover)} disabled={discover.isPending}>
                Discover
              </button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}

interface FormProps {
  account: CloudAccount | null;
  providerOptions: string[];
  onClose: () => void;
  onSaved: (msg: string) => void;
}

function AccountFormModal({ account, providerOptions, onClose, onSaved }: FormProps) {
  const create = useCreateCloudAccount();
  const update = useUpdateCloudAccount();
  const [provider, setProvider] = useState(String(account?.provider ?? providerOptions[0] ?? '').toLowerCase());
  const [name, setName] = useState(account?.name ?? '');
  const [accountIdentifier, setAccountIdentifier] = useState(account?.account_identifier ?? '');
  const [regionScope, setRegionScope] = useState(account?.region_scope ?? '');
  const [authType, setAuthType] = useState(account?.auth_type ?? 'manual');
  const [authConfigText, setAuthConfigText] = useState(() => {
    const cfg = account?.auth_config;
    if (cfg && typeof cfg === 'object') return JSON.stringify(cfg, null, 2);
    if (typeof cfg === 'string') return cfg;
    return '';
  });
  const [notes, setNotes] = useState(account?.notes ?? '');
  const [enabled, setEnabled] = useState(account?.enabled === 0 ? false : true);
  const [error, setError] = useState<string | null>(null);

  const hint = authHintContent(provider);

  useEffect(() => {
    setError(null);
  }, [provider, name, accountIdentifier, authConfigText]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim()) {
      setError('Account name is required');
      return;
    }
    let authConfig: Record<string, unknown> = {};
    const text = authConfigText.trim();
    if (text) {
      try {
        authConfig = JSON.parse(text);
      } catch {
        setError('Invalid JSON in auth config');
        return;
      }
    }
    const payload = {
      provider,
      name: name.trim(),
      account_identifier: accountIdentifier.trim(),
      region_scope: regionScope.trim(),
      auth_type: authType || 'manual',
      auth_config: authConfig,
      notes: notes.trim(),
      enabled,
    };
    try {
      if (account?.id) {
        await update.mutateAsync({ id: account.id, data: payload });
        onSaved(`Cloud account "${payload.name}" updated`);
      } else {
        await create.mutateAsync(payload);
        onSaved(`Cloud account "${payload.name}" created`);
      }
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <Modal isOpen onClose={onClose} title={account?.id ? 'Edit Cloud Account' : 'Add Cloud Account'} size="large">
      <form onSubmit={submit} style={{ display: 'grid', gap: '0.75rem' }}>
        <label>
          Provider
          <select className="form-select" value={provider} onChange={(e) => setProvider(e.target.value)}>
            {providerOptions.map((p) => (
              <option key={p} value={p}>{providerLabel(p)}</option>
            ))}
          </select>
        </label>
        <label>
          Name
          <input className="form-input" type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="Prod AWS Core" required />
        </label>
        <label>
          Account / Subscription / Project
          <input className="form-input" type="text" value={accountIdentifier} onChange={(e) => setAccountIdentifier(e.target.value)} placeholder="123456789012 / sub-id / project-id" />
        </label>
        <label>
          Region Scope
          <input className="form-input" type="text" value={regionScope} onChange={(e) => setRegionScope(e.target.value)} placeholder="us-east-1,us-west-2" />
        </label>
        <label>
          Auth Type
          <select className="form-select" value={authType} onChange={(e) => setAuthType(e.target.value)}>
            {AUTH_TYPES.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
        </label>
        <label>
          Auth Config (JSON references, non-secret)
          <textarea className="form-input" rows={4} value={authConfigText} onChange={(e) => setAuthConfigText(e.target.value)} placeholder='{"secret_ref":"aws-prod-readonly"}' />
        </label>
        <div className="card" style={{ padding: '0.75rem', background: 'rgba(255,255,255,0.04)' }}>
          <div style={{ fontWeight: 600, marginBottom: '0.35rem' }}>Provider Sync Requirements</div>
          <div className="text-muted" style={{ fontSize: '0.9em', marginBottom: '0.25rem' }}>{hint.flow}</div>
          <div className="text-muted" style={{ fontSize: '0.9em', marginBottom: '0.45rem' }}>{hint.traffic}</div>
          {Object.keys(hint.example).length > 0 && (
            <pre style={{ margin: 0, whiteSpace: 'pre-wrap', fontSize: '0.82em' }}>
              {JSON.stringify(hint.example, null, 2)}
            </pre>
          )}
        </div>
        <label>
          Notes
          <textarea className="form-input" rows={3} value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Optional notes" />
        </label>
        <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Enabled
        </label>
        {error && <div style={{ color: 'var(--danger)' }}>{error}</div>}
        <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
          <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn btn-primary" disabled={create.isPending || update.isPending}>
            {account?.id ? 'Save' : 'Create'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
