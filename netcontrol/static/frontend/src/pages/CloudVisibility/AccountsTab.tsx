import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router';

import {
  type CloudAccount,
  type CloudProvider,
  useCreateCloudAccount,
  useDeleteCloudAccount,
  useDiscoverCloudAccount,
  useTriggerCloudFlowPull,
  useTriggerCloudTrafficPull,
  useUpdateCloudAccount,
  useValidateCloudAccount,
} from '@/api/cloud';
import { Modal } from '@/components/Modal';
import { capitalize, cloudProviderTerms } from '@/lib/cloudProviderTerms';
import {
  ALL_REGIONS,
  type AuthField,
  authMethod,
  buildAuthConfig,
  fieldLabel,
  isAllRegions,
  providerForm,
} from './accountForm';
import {
  discoverOutcome,
  formatTimestamp,
  liveMissingDependencies,
  liveUnavailableReason,
  providerLabel,
  pullOutcome,
} from './helpers';

interface Props {
  accounts: CloudAccount[];
  providerOptions: string[];
  isLoading: boolean;
  /** Provider capabilities; empty until loaded, which blocks nothing. */
  providers: CloudProvider[];
}

const PROVIDER_ORDER = ['aws', 'azure', 'gcp'];

function orderedProviders(options: string[]): string[] {
  const rank = (p: string) => {
    const i = PROVIDER_ORDER.indexOf(p);
    return i === -1 ? PROVIDER_ORDER.length : i;
  };
  return [...options].sort((a, b) => rank(a) - rank(b));
}

function withArticle(text: string): string {
  return `${/^[aeiou]/i.test(text) ? 'an' : 'a'} ${text}`;
}

function joinOr(items: string[]): string {
  return items.length > 1 ? `${items.slice(0, -1).join(', ')} or ${items[items.length - 1]}` : (items[0] ?? '');
}

/** The regions a discovery run read, worded for a message; null for providers without regions. */
function discoverRegionsLabel(a: CloudAccount): string | null {
  if (!providerForm(a.provider).regionHelp) return null;
  if (isAllRegions(a.region_scope)) return 'all enabled regions';
  const scope = (a.region_scope ?? '').trim();
  if (scope) return scope;
  return String(a.provider ?? '').toLowerCase() === 'aws' ? 'us-east-1' : 'the default region';
}

export function AccountsTab({ accounts, providerOptions, isLoading, providers: capabilities }: Props) {
  const [modal, setModal] = useState<{ account: CloudAccount | null; provider: string } | null>(null);
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
    flashTimerRef.current = null;
    // Errors stay until dismissed; only successes fade on their own.
    if (kind === 'success') {
      flashTimerRef.current = setTimeout(() => {
        flashTimerRef.current = null;
        setActionMsg(null);
      }, 6000);
    }
  }

  function dismissMsg() {
    if (flashTimerRef.current) clearTimeout(flashTimerRef.current);
    flashTimerRef.current = null;
    setActionMsg(null);
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
        showMsg('error', `${a.name}: discovery did not run, nothing was changed – ${result.message ?? 'Discovery failed'}`);
      } else if (result?.fallback_used || result?.effective_mode === 'sample') {
        showMsg('error', `${a.name}: showing SAMPLE data, not live topology (${result?.message ?? ''})`);
      } else {
        const outcome = discoverOutcome(a.name, result, discoverRegionsLabel(a));
        showMsg(outcome.kind, outcome.text);
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
    const terms = cloudProviderTerms(a.provider);
    try {
      const r = await flowPull.mutateAsync(a.id);
      const outcome = pullOutcome(`${a.name}: ${terms.flowLogs} pull`, r, (n) => `${a.name}: ${n} ${terms.flowLogs} records ingested`);
      showMsg(outcome.kind, outcome.text);
    } catch (e) {
      showMsg('error', `${a.name}: ${terms.flowLogs} pull failed: ${(e as Error).message}`);
    }
  }

  async function runTrafficPull(a: CloudAccount) {
    const terms = cloudProviderTerms(a.provider);
    try {
      const r = await trafficPull.mutateAsync(a.id);
      const outcome = pullOutcome(`${a.name}: traffic metrics pull`, r, (n) => `${a.name}: ${n} ${terms.metricsSource} samples ingested`);
      showMsg(outcome.kind, outcome.text);
    } catch (e) {
      showMsg('error', `${a.name}: traffic metrics pull failed: ${(e as Error).message}`);
    }
  }

  const providers = orderedProviders(providerOptions);
  const deleteTerms = cloudProviderTerms(confirmDelete?.provider);
  const discoverTerms = cloudProviderTerms(confirmDiscover?.provider);

  return (
    <div>
      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '0.75rem' }}>
        {providers.map((p) => (
          <button key={p} className="btn btn-primary" onClick={() => setModal({ account: null, provider: p })}>
            Add {cloudProviderTerms(p).scopeTitle}
          </button>
        ))}
      </div>

      {actionMsg && (
        <div
          className="card"
          style={{
            padding: '0.6rem 0.85rem',
            marginBottom: '0.6rem',
            borderLeft: `3px solid var(--${actionMsg.kind === 'success' ? 'success' : 'danger'})`,
            display: 'flex',
            alignItems: 'flex-start',
            gap: '0.5rem',
          }}
        >
          <span style={{ flex: 1 }}>{actionMsg.text}</span>
          <button type="button" className="btn btn-sm btn-secondary" aria-label="Dismiss" title="Dismiss" onClick={dismissMsg}>
            ×
          </button>
        </div>
      )}

      {isLoading && <div className="text-muted">Loading…</div>}

      {!isLoading && accounts.length === 0 && (
        <div className="card" style={{ padding: '1.25rem' }}>
          <p className="text-muted" style={{ margin: 0 }}>
            No cloud accounts yet. Add {joinOr(providers.map((p) => withArticle(cloudProviderTerms(p).scopeTitle)))} to start.
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
                <th>Identifier</th>
                <th>Regions</th>
                <th>Enabled</th>
                <th>Last Sync</th>
                <th>Sync Readiness</th>
                <th>Resources</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {accounts.map((a) => {
                const terms = cloudProviderTerms(a.provider);
                const form = providerForm(a.provider);
                const readiness = {
                  flowReady: a.sync_readiness?.flow_ready ?? false,
                  trafficReady: a.sync_readiness?.traffic_ready ?? false,
                  flowMissing: (a.sync_readiness?.flow_missing ?? []).map((key) => fieldLabel(form, key)),
                  trafficMissing: (a.sync_readiness?.traffic_missing ?? []).map((key) => fieldLabel(form, key)),
                };
                const hasResources = (a.resource_count ?? 0) > 0;
                const liveBlocked = liveUnavailableReason(a.provider, capabilities);
                const liveMissing = liveMissingDependencies(a.provider, capabilities);
                return (
                  <tr key={a.id}>
                    <td>
                      {a.name}
                      {terms.onTopologyMap && Boolean(a.enabled) && hasResources && (
                        <small style={{ display: 'block' }}>
                          <Link
                            to="/topology"
                            title={`This ${terms.scope}'s ${terms.networks}, gateways and VPNs are on the Topology map`}
                          >
                            Shown on Topology map
                          </Link>
                        </small>
                      )}
                      {!terms.onTopologyMap && hasResources && (
                        <small
                          className="text-muted"
                          style={{ display: 'block' }}
                          title={`${capitalize(terms.scopeTitlePlural)} are not drawn on the Topology map yet`}
                        >
                          Not on the Topology map
                        </small>
                      )}
                    </td>
                    <td>{providerLabel(a.provider)}</td>
                    <td>
                      {a.account_identifier || '-'}
                      <small className="text-muted" style={{ display: 'block' }}>{terms.identifierLabel}</small>
                    </td>
                    <td>
                      {!form.regionHelp
                        ? terms.wholeScope
                        : isAllRegions(a.region_scope) ? 'All regions' : (a.region_scope ?? '-')}
                    </td>
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
                          {readiness.flowReady ? 'Flow logs ready' : 'Flow logs need setup'}
                        </span>
                        <span className={`badge badge-${readiness.trafficReady ? 'success' : 'warning'}`}>
                          {readiness.trafficReady ? 'Metrics ready' : 'Metrics need setup'}
                        </span>
                      </div>
                      {(!readiness.flowReady || !readiness.trafficReady) && (
                        <small className="text-muted" style={{ display: 'block', marginTop: '0.25rem' }}>
                          {!readiness.flowReady && `Flow logs need ${readiness.flowMissing.join(', ')}`}
                          {!readiness.flowReady && !readiness.trafficReady && ' | '}
                          {!readiness.trafficReady && `Traffic metrics need ${readiness.trafficMissing.join(', ')}`}
                        </small>
                      )}
                    </td>
                    <td>
                      <span className="badge badge-info">{a.resource_count ?? 0} nodes</span>{' '}
                      <span className="badge badge-info">{a.connection_count ?? 0} edges</span>
                    </td>
                    <td style={{ whiteSpace: 'nowrap' }}>
                      <button
                        className="btn btn-sm btn-secondary"
                        onClick={() => runValidate(a)}
                        disabled={Boolean(liveBlocked) || validate.isPending}
                        title={liveBlocked ?? undefined}
                      >
                        Validate
                      </button>{' '}
                      <button
                        className="btn btn-sm btn-secondary"
                        onClick={() => setConfirmDiscover(a)}
                        disabled={Boolean(liveBlocked) || discover.isPending}
                        title={liveBlocked ?? undefined}
                      >
                        Discover
                      </button>{' '}
                      <button
                        className="btn btn-sm btn-secondary"
                        onClick={() => runFlowPull(a)}
                        disabled={Boolean(liveBlocked) || flowPull.isPending}
                        title={liveBlocked ?? undefined}
                      >
                        Pull Flow
                      </button>{' '}
                      <button
                        className="btn btn-sm btn-secondary"
                        onClick={() => runTrafficPull(a)}
                        disabled={Boolean(liveBlocked) || trafficPull.isPending}
                        title={liveBlocked ?? undefined}
                      >
                        Pull Traffic
                      </button>{' '}
                      <button className="btn btn-sm btn-secondary" onClick={() => setModal({ account: a, provider: a.provider })}>
                        Edit
                      </button>{' '}
                      <button className="btn btn-sm btn-danger" onClick={() => setConfirmDelete(a)}>
                        Delete
                      </button>
                      {liveBlocked && (
                        <small
                          className="text-muted"
                          style={{ display: 'block', marginTop: '0.3rem', whiteSpace: 'normal', maxWidth: '24rem' }}
                          title={liveBlocked}
                        >
                          Live {terms.label} reads unavailable
                          {liveMissing.length ? ` (missing ${liveMissing.join(', ')} on the server)` : ' on the server'}
                        </small>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {modal && (
        <AccountFormModal
          account={modal.account}
          provider={modal.provider}
          onClose={() => setModal(null)}
          onSaved={(msg) => {
            showMsg('success', msg);
            setModal(null);
          }}
        />
      )}

      <Modal
        isOpen={Boolean(confirmDelete)}
        onClose={() => setConfirmDelete(null)}
        title={`Delete ${deleteTerms.scopeTitle}`}
      >
        {confirmDelete && (
          <div>
            <p>
              Delete <strong>{confirmDelete.name}</strong> and everything discovered from this {deleteTerms.scope}{' '}
              (resources, connections, policy rules and traffic metrics)?
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
        onClose={() => {
          if (!discover.isPending) setConfirmDiscover(null);
        }}
        title={`Discover ${discoverTerms.scopeTitle}`}
      >
        {confirmDiscover && (
          <div>
            <p>
              Read <strong>{confirmDiscover.name}</strong> through {discoverTerms.api} and refresh its{' '}
              {discoverTerms.networks}, gateways and connections? If discovery fails, the last snapshot is kept and the
              error is reported.
            </p>
            <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
              <button className="btn btn-secondary" onClick={() => setConfirmDiscover(null)} disabled={discover.isPending}>
                Cancel
              </button>
              <button className="btn btn-primary" onClick={() => runDiscover(confirmDiscover)} disabled={discover.isPending}>
                {discover.isPending ? 'Discovering…' : 'Discover'}
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
  /** Fixed: a stored sign-in only fits the provider it was written for. */
  provider: string;
  onClose: () => void;
  onSaved: (msg: string) => void;
}

/** "Flow logs and traffic metrics" from the section titles. */
function sectionsSummary(titles: string[]): string {
  const parts = titles.map((t, i) => (i === 0 ? t : t.charAt(0).toLowerCase() + t.slice(1)));
  return parts.length > 1 ? `${parts.slice(0, -1).join(', ')} and ${parts[parts.length - 1]}` : (parts[0] ?? '');
}

function AccountFormModal({ account, provider: providerProp, onClose, onSaved }: FormProps) {
  const create = useCreateCloudAccount();
  const update = useUpdateCloudAccount();
  const provider = String(account?.provider ?? providerProp).toLowerCase();
  const terms = cloudProviderTerms(provider);
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
      setError(`${capitalize(terms.scope)} name is required`);
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
        onSaved(`${terms.scopeTitle} "${payload.name}" updated`);
      } else {
        await create.mutateAsync({ ...payload, auth_type: auth?.auth_type, auth_config: auth?.auth_config ?? {} });
        onSaved(`${terms.scopeTitle} "${payload.name}" created`);
      }
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <Modal isOpen onClose={onClose} title={`${account?.id ? 'Edit' : 'Add'} ${terms.scopeTitle}`} size="large">
      <form onSubmit={submit} style={{ display: 'grid', gap: '0.75rem' }}>
        <div>
          Provider: {terms.fullName === terms.label ? terms.label : `${terms.fullName} (${terms.label})`}
        </div>
        <label>
          Name
          <input className="form-input" type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder={`Prod ${terms.label}`} required />
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
                  Saving replaces everything stored for this {terms.scope}, flow log and traffic settings included: fill in
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
                <summary style={{ cursor: 'pointer', fontWeight: 600 }}>
                  {sectionsSummary(form.sections.map((s) => s.title))} (optional)
                </summary>
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
                <textarea className="form-input" rows={3} value={extraText} onChange={(e) => setExtraText(e.target.value)} placeholder={form.extraPlaceholder} />
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
