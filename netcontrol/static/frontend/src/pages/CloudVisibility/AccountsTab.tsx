import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router';

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
import { ALL_REGIONS, type AuthField, authMethod, buildAuthConfig, isAllRegions, providerForm } from './accountForm';
import { formatTimestamp, providerLabel } from './helpers';

interface Props {
  accounts: CloudAccount[];
  providerOptions: string[];
  isLoading: boolean;
}

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

  const flashTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => () => {
    if (flashTimerRef.current) clearTimeout(flashTimerRef.current);
  }, []);

  function showMsg(kind: 'success' | 'error', text: string) {
    setActionMsg({ kind, text });
    if (flashTimerRef.current) clearTimeout(flashTimerRef.current);
    flashTimerRef.current = setTimeout(() => {
      flashTimerRef.current = null;
      setActionMsg(null);
    }, 6000);
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
      if (result && result.ok === false) {
        showMsg('error', `${a.name}: ${result.message ?? 'Discovery failed'}`);
      } else if (result?.fallback_used || result?.effective_mode === 'sample') {
        showMsg('error', `${a.name}: showing SAMPLE data, not live topology (${result?.message ?? ''})`);
      } else {
        showMsg('success', result?.message ?? 'Discovery completed');
      }
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
                <th>Enabled</th>
                <th>Last Sync</th>
                <th>Sync Readiness</th>
                <th>Resources</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {accounts.map((a) => {
                const readiness = {
                  flowReady: a.sync_readiness?.flow_ready ?? false,
                  trafficReady: a.sync_readiness?.traffic_ready ?? false,
                  flowMissing: a.sync_readiness?.flow_missing ?? [],
                  trafficMissing: a.sync_readiness?.traffic_missing ?? [],
                };
                return (
                  <tr key={a.id}>
                    <td>
                      {a.name}
                      {a.provider === 'aws' && Boolean(a.enabled) && (a.resource_count ?? 0) > 0 && (
                        <small style={{ display: 'block' }}>
                          <Link to="/topology" title="This account's VPCs, gateways and VPNs are on the Topology map">
                            Shown on Topology map
                          </Link>
                        </small>
                      )}
                    </td>
                    <td>{providerLabel(a.provider)}</td>
                    <td>{a.account_identifier ?? '-'}</td>
                    <td>{isAllRegions(a.region_scope) ? 'All regions' : (a.region_scope ?? '-')}</td>
                    <td>
                      <span className={`badge badge-${a.enabled ? 'success' : 'secondary'}`}>
                        {a.enabled ? 'enabled' : 'disabled'}
                      </span>
                    </td>
                    <td>
                      <div
                        title={a.last_sync_message || undefined}
                        style={a.last_sync_status === 'error' ? { color: 'var(--danger)' } : undefined}
                      >
                        {a.last_sync_status ?? 'never'}
                      </div>
                      {a.last_sync_status === 'error' && a.last_sync_message && (
                        <small style={{ color: 'var(--danger)', display: 'block', maxWidth: '16rem' }}>
                          {a.last_sync_message}
                        </small>
                      )}
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
              Refresh cloud topology snapshot for <strong>{confirmDiscover.name}</strong>? Live provider APIs are used; if discovery fails, the last known snapshot is kept and the error is reported.
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
  const [allRegions, setAllRegions] = useState(isAllRegions(account?.region_scope));
  const [regionScope, setRegionScope] = useState(isAllRegions(account?.region_scope) ? '' : (account?.region_scope ?? ''));
  // The API never returns the stored auth_config (write-only credentials), so
  // an existing account keeps what is stored until a change is asked for, and
  // a change replaces all of it.
  const [replaceAuth, setReplaceAuth] = useState(!account?.id);
  const [methodKey, setMethodKey] = useState('');
  const [values, setValues] = useState<Record<string, string>>({});
  const [extraText, setExtraText] = useState('');
  const [notes, setNotes] = useState(account?.notes ?? '');
  const [enabled, setEnabled] = useState(account ? Boolean(account.enabled) : true);
  const [error, setError] = useState<string | null>(null);

  const form = providerForm(provider);
  const method = authMethod(form, methodKey);
  const setValue = (key: string, value: string) => setValues((current) => ({ ...current, [key]: value }));

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!name.trim()) {
      setError('Account name is required');
      return;
    }
    const payload = {
      provider,
      name: name.trim(),
      account_identifier: accountIdentifier.trim(),
      region_scope: allRegions && form.allRegionsHelp ? ALL_REGIONS : regionScope.trim(),
      notes: notes.trim(),
      enabled,
    };
    let auth: { auth_type: string; auth_config: Record<string, unknown> } | null = null;
    if (replaceAuth) {
      const built = buildAuthConfig(form, method.key, values, accountIdentifier, extraText);
      if (!('config' in built)) {
        setError(built.error);
        return;
      }
      auth = { auth_type: method.authType, auth_config: built.config };
    }
    try {
      if (account?.id) {
        // Without a change the sign-in is left out, so what is stored is kept.
        // An empty config has to be asked for explicitly to wipe the old one.
        const data = auth
          ? { ...payload, ...auth, clear_auth_config: Object.keys(auth.auth_config).length === 0 }
          : payload;
        await update.mutateAsync({ id: account.id, data });
        onSaved(`Cloud account "${payload.name}" updated`);
      } else {
        await create.mutateAsync({ ...payload, auth_type: auth?.auth_type, auth_config: auth?.auth_config ?? {} });
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
          <input className="form-input" type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder={`Prod ${providerLabel(provider)}`} required />
        </label>
        <label>
          {form.identifierLabel}
          <input className="form-input" type="text" value={accountIdentifier} onChange={(e) => setAccountIdentifier(e.target.value)} placeholder={form.identifierPlaceholder} />
          {form.identifierHelp && <small className="text-muted" style={{ display: 'block' }}>{form.identifierHelp}</small>}
        </label>
        {form.regionHelp && (
          <label>
            Regions
            <input
              className="form-input"
              type="text"
              value={allRegions && form.allRegionsHelp ? '' : regionScope}
              onChange={(e) => setRegionScope(e.target.value)}
              placeholder={allRegions && form.allRegionsHelp ? 'All regions' : 'us-east-1, us-west-2'}
              disabled={allRegions && Boolean(form.allRegionsHelp)}
            />
            <small className="text-muted" style={{ display: 'block' }}>
              {allRegions && form.allRegionsHelp ? form.allRegionsHelp : form.regionHelp}
            </small>
          </label>
        )}
        {form.regionHelp && form.allRegionsHelp && (
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <input type="checkbox" checked={allRegions} onChange={(e) => setAllRegions(e.target.checked)} />
            All regions
          </label>
        )}

        {!replaceAuth && (
          <div className="card" style={{ padding: '0.75rem', background: 'rgba(255,255,255,0.04)' }}>
            <div style={{ fontWeight: 600, marginBottom: '0.35rem' }}>Sign-in and sync settings</div>
            <div className="text-muted" style={{ fontSize: '0.9em', marginBottom: '0.5rem' }}>
              {account?.has_auth_config
                ? 'Stored encrypted and never shown. They stay as they are unless you change them.'
                : 'Nothing is stored: Plexus signs in with the credentials of its own server.'}
            </div>
            <button type="button" className="btn btn-sm btn-secondary" onClick={() => setReplaceAuth(true)}>
              Change sign-in and sync settings
            </button>
          </div>
        )}

        {replaceAuth && (
          <>
            <fieldset style={{ border: '1px solid var(--border)', borderRadius: 6, padding: '0.75rem', margin: 0, display: 'grid', gap: '0.6rem' }}>
              <legend style={{ padding: '0 0.35rem', fontWeight: 600 }}>How Plexus signs in</legend>
              {account?.id && (
                <div className="text-muted" style={{ fontSize: '0.9em' }}>
                  Saving replaces everything stored for this account, flow log and traffic settings included: fill in
                  all that apply.{' '}
                  <button type="button" className="btn btn-sm btn-secondary" onClick={() => setReplaceAuth(false)}>
                    Keep what is stored
                  </button>
                </div>
              )}
              {form.methods.map((m) => (
                <label key={m.key} style={{ display: 'flex', gap: '0.5rem', alignItems: 'flex-start' }}>
                  <input
                    type="radio"
                    name="cloud-account-sign-in"
                    checked={method.key === m.key}
                    onChange={() => setMethodKey(m.key)}
                    style={{ marginTop: '0.2rem' }}
                  />
                  <span>
                    <span style={{ fontWeight: 600 }}>{m.label}</span>
                    <small className="text-muted" style={{ display: 'block' }}>{m.help}</small>
                  </span>
                </label>
              ))}
              {method.fields.map((f) => (
                <AuthFieldInput key={f.key} field={f} value={values[f.key] ?? ''} onChange={(v) => setValue(f.key, v)} />
              ))}
              {method.fields.length > 0 && (
                <small className="text-muted">Stored encrypted and never shown again.</small>
              )}
            </fieldset>

            {form.sections.length > 0 && (
              <details>
                <summary style={{ cursor: 'pointer', fontWeight: 600 }}>Flow logs and traffic metrics (optional)</summary>
                <div style={{ display: 'grid', gap: '0.6rem', marginTop: '0.6rem' }}>
                  <small className="text-muted">Discovery and the Topology map need none of these.</small>
                  {form.sections.map((section) => (
                    <div key={section.title} style={{ display: 'grid', gap: '0.5rem' }}>
                      <div>
                        <div style={{ fontWeight: 600 }}>{section.title}</div>
                        <small className="text-muted">{section.help}</small>
                      </div>
                      {section.fields.map((f) => (
                        <AuthFieldInput key={f.key} field={f} value={values[f.key] ?? ''} onChange={(v) => setValue(f.key, v)} />
                      ))}
                    </div>
                  ))}
                </div>
              </details>
            )}

            <details>
              <summary style={{ cursor: 'pointer', fontWeight: 600 }}>Additional settings (JSON, rarely needed)</summary>
              <label style={{ display: 'block', marginTop: '0.6rem' }}>
                <small className="text-muted" style={{ display: 'block' }}>
                  A JSON object of settings without a field above; it is saved on top of them.
                </small>
                <textarea className="form-input" rows={3} value={extraText} onChange={(e) => setExtraText(e.target.value)} placeholder='{"role_session_name": "plexus"}' />
              </label>
            </details>
          </>
        )}

        <label>
          Notes
          <textarea className="form-input" rows={2} value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Optional notes" />
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

function AuthFieldInput({ field, value, onChange }: { field: AuthField; value: string; onChange: (value: string) => void }) {
  return (
    <label>
      {field.label}
      {field.optional && <span className="text-muted"> (optional)</span>}
      {field.json ? (
        <textarea className="form-input" rows={4} value={value} onChange={(e) => onChange(e.target.value)} placeholder={field.placeholder} />
      ) : (
        <input
          className="form-input"
          type={field.secret ? 'password' : 'text'}
          autoComplete={field.secret ? 'new-password' : 'off'}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={field.placeholder}
        />
      )}
      {field.list && <small className="text-muted" style={{ display: 'block' }}>Separate several with commas.</small>}
      {field.help && <small className="text-muted" style={{ display: 'block' }}>{field.help}</small>}
    </label>
  );
}
