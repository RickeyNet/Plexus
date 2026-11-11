import { type ReactNode, useEffect, useId, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router';

import {
  type CloudAccount,
  type CloudProvider,
  useCreateCloudAccount,
  useDeleteCloudAccount,
  useDiscoverCloudAccount,
  useUpdateCloudAccount,
} from '@/api/cloud';
import { Badge, StatusBadge } from '@/components/Badge';
import { BusyButton } from '@/components/BusyButton';
import { Callout } from '@/components/Callout';
import { DeleteButton } from '@/components/DeleteButton';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import { ANY_CLOUD_TERMS, capitalize, cloudProviderTerms } from '@/lib/cloudProviderTerms';
import { formatBackendDateTime } from '@/lib/datetime';
import { usePendingKeys } from '@/lib/usePendingKeys';
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
  addProviderFromSearch,
  discoverOutcome,
  liveMissingDependencies,
  liveUnavailableReason,
  providerFullLabel,
  providerLabel,
  skippedNote,
} from './helpers';

interface Props {
  accounts: CloudAccount[];
  providerOptions: string[];
  isLoading: boolean;
  /** Shown in place of the table when the accounts request failed with nothing cached. */
  loadError: ReactNode;
  /** Provider capabilities; empty until loaded, which blocks nothing. */
  providers: CloudProvider[];
  /** Shown above the table when the provider capabilities request failed with nothing cached. */
  providersError?: ReactNode;
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

/**
 * One wrapping row of "AWS: ready" badges, with the packages a provider
 * lacks on the server spelled out beside its badge.
 */
function LiveReadSupport({ providers }: { providers: CloudProvider[] }) {
  const labelId = useId();
  if (!providers.length) return null;
  return (
    <div
      role="group"
      aria-labelledby={labelId}
      style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 'var(--space-2)' }}
    >
      <span id={labelId} className="text-muted">Live reads</span>
      {providers.map((p) => {
        const missing = p.missing_dependencies ?? [];
        return (
          <span key={p.id} style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-1)' }}>
            <Badge tone={p.live_supported ? 'success' : 'warning'} title={p.name || providerFullLabel(p.id)}>
              {providerLabel(p.id)}: {p.live_supported ? 'ready' : 'unavailable'}
            </Badge>
            {missing.length > 0 && <small className="text-muted">missing {missing.join(', ')}</small>}
          </span>
        );
      })}
    </div>
  );
}

export function AccountsTab({
  accounts,
  providerOptions,
  isLoading,
  loadError,
  providers: capabilities,
  providersError,
}: Props) {
  const [modal, setModal] = useState<{ account: CloudAccount | null; provider: string } | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<CloudAccount | null>(null);
  const [confirmDiscover, setConfirmDiscover] = useState<CloudAccount | null>(null);
  const [actionMsg, setActionMsg] = useState<{ kind: 'success' | 'error'; text: string } | null>(null);

  const discover = useDiscoverCloudAccount();
  const deleteAcct = useDeleteCloudAccount();
  const discovering = usePendingKeys<number>();

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

  function runDiscover(a: CloudAccount) {
    setConfirmDiscover(null);
    void discovering.run(a.id, async () => {
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
        showMsg('error', `${a.name}: discovery failed: ${(e as Error).message}`);
      }
    });
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

  const providers = orderedProviders(providerOptions);
  const deleteTerms = cloudProviderTerms(confirmDelete?.provider);
  const discoverTerms = cloudProviderTerms(confirmDiscover?.provider);
  // "an AWS account, an Azure subscription or a GCP project"
  const addChoices = joinOr(providers.map((p) => withArticle(cloudProviderTerms(p).scopeTitle)));

  // The Topology page's Add Source buttons link here as `?add=<provider>`:
  // the dialog is open on that provider while the parameter is in the URL,
  // and closing it drops the parameter.
  const [searchParams, setSearchParams] = useSearchParams();
  const linkedAdd = addProviderFromSearch(searchParams.toString(), providers);
  const openModal = modal ?? (linkedAdd ? { account: null, provider: linkedAdd } : null);
  function closeModal() {
    setModal(null);
    if (!searchParams.has('add')) return;
    setSearchParams(
      (current) => {
        const next = new URLSearchParams(current);
        next.delete('add');
        return next;
      },
      { replace: true },
    );
  }

  return (
    <div className="stack">
      <div className="toolbar">
        {/* One add action: the dialog asks for the provider, starting on the first offered. */}
        <button
          type="button"
          className="btn btn-primary"
          title={`Add ${addChoices} to read its network topology, flow logs and network policy`}
          onClick={() => setModal({ account: null, provider: providers[0] ?? 'aws' })}
        >
          Add {ANY_CLOUD_TERMS.scopeTitle}
        </button>
        <div className="toolbar-spacer" />
        <LiveReadSupport providers={capabilities} />
      </div>

      {providersError}

      {actionMsg && (
        <Callout
          tone={actionMsg.kind === 'success' ? 'success' : 'danger'}
          action={
            <button type="button" className="btn btn-sm btn-ghost" onClick={dismissMsg}>
              Dismiss
            </button>
          }
        >
          {actionMsg.text}
        </Callout>
      )}

      {loadError}

      {isLoading && <LoadingState />}

      {!isLoading && !loadError && accounts.length === 0 && (
        <EmptyState
          message={`No ${ANY_CLOUD_TERMS.scopeTitlePlural} yet`}
          description={`Use Add ${ANY_CLOUD_TERMS.scopeTitle} to register ${addChoices}.`}
        />
      )}

      {accounts.length > 0 && (
        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Identifier</th>
                <th>Regions</th>
                <th>Last sync</th>
                <th>Sync readiness</th>
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
                      <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 'var(--space-2)' }}>
                        <span>{a.name}</span>
                        {!a.enabled && <Badge size="sm">disabled</Badge>}
                      </div>
                      <small style={{ display: 'block' }}>
                        <span className="text-muted">{providerLabel(a.provider)}</span>
                        {terms.onTopologyMap && Boolean(a.enabled) && hasResources && (
                          <>
                            {' · '}
                            <Link
                              to="/topology"
                              title={`This ${terms.scope}'s ${terms.networks}, gateways and VPNs are on the Topology map`}
                            >
                              Shown on Topology map
                            </Link>
                          </>
                        )}
                        {!terms.onTopologyMap && hasResources && (
                          <span
                            className="text-muted"
                            title={`${capitalize(terms.scopeTitlePlural)} are not drawn on the Topology map yet`}
                          >
                            {' · '}Not on the Topology map
                          </span>
                        )}
                      </small>
                    </td>
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
                      <StatusBadge
                        size="sm"
                        status={a.last_sync_status || 'never'}
                        title={a.last_sync_message || undefined}
                      />
                      {a.last_sync_status === 'error' && a.last_sync_message && (
                        <small style={{ color: 'var(--danger)', display: 'block', maxWidth: '16rem' }}>
                          {a.last_sync_message}
                        </small>
                      )}
                      {a.last_sync_status !== 'error' && skippedNote(a.last_sync_message) && (
                        <small style={{ color: 'var(--warning)', display: 'block', maxWidth: '16rem' }}>
                          {skippedNote(a.last_sync_message)}
                        </small>
                      )}
                      <small className="text-muted" style={{ display: 'block' }}>
                        {a.last_sync_at ? formatBackendDateTime(a.last_sync_at) : 'Never'}
                      </small>
                      <small className="text-muted" style={{ display: 'block' }}>
                        {a.resource_count ?? 0} nodes, {a.connection_count ?? 0} edges
                      </small>
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 'var(--space-1)', flexWrap: 'wrap' }}>
                        <Badge tone={readiness.flowReady ? 'success' : 'warning'}>
                          {readiness.flowReady ? 'Flow logs ready' : 'Flow logs need setup'}
                        </Badge>
                        <Badge tone={readiness.trafficReady ? 'success' : 'warning'}>
                          {readiness.trafficReady ? 'Metrics ready' : 'Metrics need setup'}
                        </Badge>
                      </div>
                      {(!readiness.flowReady || !readiness.trafficReady) && (
                        <small className="text-muted" style={{ display: 'block', marginTop: 'var(--space-1)' }}>
                          {!readiness.flowReady && `Flow logs need ${readiness.flowMissing.join(', ')}`}
                          {!readiness.flowReady && !readiness.trafficReady && ' | '}
                          {!readiness.trafficReady && `Traffic metrics need ${readiness.trafficMissing.join(', ')}`}
                        </small>
                      )}
                    </td>
                    <td style={{ whiteSpace: 'nowrap' }}>
                      <BusyButton
                        className="btn btn-sm btn-secondary"
                        onClick={() => setConfirmDiscover(a)}
                        busy={discovering.isPending(a.id)}
                        busyLabel="Discovering…"
                        disabled={Boolean(liveBlocked)}
                        title={liveBlocked ?? undefined}
                      >
                        Discover
                      </BusyButton>{' '}
                      <button className="btn btn-sm btn-secondary" onClick={() => setModal({ account: a, provider: a.provider })}>
                        Edit
                      </button>{' '}
                      <DeleteButton onClick={() => setConfirmDelete(a)} />
                      {liveBlocked && (
                        <small
                          className="text-muted"
                          style={{ display: 'block', marginTop: 'var(--space-1)', whiteSpace: 'normal', maxWidth: '24rem' }}
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

      {openModal && (
        <AccountFormModal
          account={openModal.account}
          provider={openModal.provider}
          providerOptions={providers}
          onClose={closeModal}
          onSaved={(msg) => {
            showMsg('success', msg);
            closeModal();
          }}
        />
      )}

      <Modal
        isOpen={Boolean(confirmDelete)}
        onClose={() => setConfirmDelete(null)}
        title={`Delete ${deleteTerms.scopeTitle}`}
        size="small"
        footer={
          confirmDelete && (
            <>
              <button type="button" className="btn btn-secondary" onClick={() => setConfirmDelete(null)}>Cancel</button>
              <DeleteButton
                size="md"
                onClick={() => runDelete(confirmDelete)}
                disabled={deleteAcct.isPending}
              />
            </>
          )
        }
      >
        {confirmDelete && (
          <p>
            Delete <strong>{confirmDelete.name}</strong> and everything discovered from this {deleteTerms.scope}{' '}
            (resources, connections, policy rules and traffic metrics)?
          </p>
        )}
      </Modal>

      <Modal
        isOpen={Boolean(confirmDiscover)}
        onClose={() => setConfirmDiscover(null)}
        title={`Discover ${discoverTerms.scopeTitle}`}
        size="small"
        footer={
          confirmDiscover && (
            <>
              <button type="button" className="btn btn-secondary" onClick={() => setConfirmDiscover(null)}>
                Cancel
              </button>
              <button type="button" className="btn btn-primary" onClick={() => runDiscover(confirmDiscover)}>
                Discover
              </button>
            </>
          )
        }
      >
        {confirmDiscover && (
          <p>
            Read <strong>{confirmDiscover.name}</strong> through {discoverTerms.api} and refresh its{' '}
            {discoverTerms.networks}, gateways and connections? If discovery fails, the last snapshot is kept and the
            error is reported.
          </p>
        )}
      </Modal>
    </div>
  );
}

interface FormProps {
  account: CloudAccount | null;
  /** Initial provider; fixed once saved, since a stored sign-in only fits the provider it was written for. */
  provider: string;
  /** Providers offered when adding an account. */
  providerOptions: string[];
  onClose: () => void;
  onSaved: (msg: string) => void;
}

/** "Flow logs and traffic metrics" from the section titles. */
function sectionsSummary(titles: string[]): string {
  const parts = titles.map((t, i) => (i === 0 ? t : t.charAt(0).toLowerCase() + t.slice(1)));
  return parts.length > 1 ? `${parts.slice(0, -1).join(', ')} and ${parts[parts.length - 1]}` : (parts[0] ?? '');
}

function AccountFormModal({ account, provider: providerProp, providerOptions, onClose, onSaved }: FormProps) {
  const create = useCreateCloudAccount();
  const update = useUpdateCloudAccount();
  const [providerChoice, setProviderChoice] = useState(providerProp);
  const provider = String(account?.provider ?? providerChoice).toLowerCase();
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

  const formId = useId();
  const signInId = `${formId}-sign-in`;
  const allRegionsOn = allRegions && Boolean(form.allRegionsHelp);

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={`${account?.id ? 'Edit' : 'Add'} ${terms.scopeTitle}`}
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button type="submit" form={formId} className="btn btn-primary" disabled={create.isPending || update.isPending}>
            {account?.id ? 'Save' : 'Create'}
          </button>
        </>
      }
    >
      <form id={formId} onSubmit={submit}>
        {account?.id ? (
          <div className="form-group">
            <div className="form-label">Provider</div>
            <div>{providerFullLabel(provider)}</div>
          </div>
        ) : (
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-provider`}>Provider</label>
            <select
              id={`${formId}-provider`}
              className="form-select"
              value={providerChoice}
              onChange={(e) => {
                setProviderChoice(e.target.value);
                // Sign-in methods and fields differ per provider.
                setMethodKey('');
                setValues({});
              }}
            >
              {providerOptions.map((p) => (
                <option key={p} value={p}>{providerFullLabel(p)}</option>
              ))}
            </select>
          </div>
        )}

        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-name`}>Name</label>
          <input
            id={`${formId}-name`}
            className="form-input"
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={`Prod ${terms.label}`}
            required
          />
        </div>

        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-identifier`}>{form.identifierLabel}</label>
          <input
            id={`${formId}-identifier`}
            className="form-input"
            type="text"
            value={accountIdentifier}
            onChange={(e) => setAccountIdentifier(e.target.value)}
            placeholder={form.identifierPlaceholder}
            aria-describedby={form.identifierHelp ? `${formId}-identifier-help` : undefined}
          />
          {form.identifierHelp && (
            <div className="form-help" id={`${formId}-identifier-help`}>{form.identifierHelp}</div>
          )}
        </div>

        {form.regionHelp && (
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-regions`}>Regions</label>
            <input
              id={`${formId}-regions`}
              className="form-input"
              type="text"
              value={allRegionsOn ? '' : regionScope}
              onChange={(e) => setRegionScope(e.target.value)}
              placeholder={allRegionsOn ? 'All regions' : 'us-east-1, us-west-2'}
              disabled={allRegionsOn}
              aria-describedby={`${formId}-regions-help`}
            />
            <div className="form-help" id={`${formId}-regions-help`}>
              {allRegionsOn ? form.allRegionsHelp : form.regionHelp}
            </div>
            {form.allRegionsHelp && (
              <label className="form-check">
                <input type="checkbox" checked={allRegions} onChange={(e) => setAllRegions(e.target.checked)} />
                <span>All regions</span>
              </label>
            )}
          </div>
        )}

        {!replaceAuth && (
          <div className="card-inset form-group">
            <div style={{ fontWeight: 600, marginBottom: 'var(--space-1)' }}>Sign-in and sync settings</div>
            <div className="text-muted" style={{ fontSize: 'var(--text-sm)', marginBottom: 'var(--space-2)' }}>
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
            <fieldset
              style={{
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-md)',
                padding: 'var(--space-3)',
                margin: '0 0 var(--space-4)',
              }}
            >
              <legend id={signInId} style={{ padding: '0 var(--space-1)', fontWeight: 600 }}>
                How Plexus signs in
              </legend>
              {account?.id && (
                <div className="text-muted" style={{ fontSize: 'var(--text-sm)', marginBottom: 'var(--space-3)' }}>
                  Saving replaces everything stored for this {terms.scope}, flow log and traffic settings included: fill in
                  all that apply.{' '}
                  <button type="button" className="btn btn-sm btn-secondary" onClick={() => setReplaceAuth(false)}>
                    Keep what is stored
                  </button>
                </div>
              )}
              <div role="radiogroup" aria-labelledby={signInId} className="form-group">
                {form.methods.map((m) => (
                  <div key={m.key}>
                    <label className="form-check">
                      <input
                        type="radio"
                        name={signInId}
                        checked={method.key === m.key}
                        onChange={() => setMethodKey(m.key)}
                        aria-describedby={`${signInId}-${m.key}-help`}
                      />
                      <span>{m.label}</span>
                    </label>
                    <div className="form-help" id={`${signInId}-${m.key}-help`}>{m.help}</div>
                  </div>
                ))}
              </div>
              {method.fields.map((f) => (
                <AuthFieldInput key={f.key} field={f} value={values[f.key] ?? ''} onChange={(v) => setValue(f.key, v)} />
              ))}
              {method.fields.length > 0 && <div className="form-help">Stored encrypted and never shown again.</div>}
            </fieldset>

            {form.sections.length > 0 && (
              <details className="form-group">
                <summary style={{ cursor: 'pointer', fontWeight: 600 }}>
                  {sectionsSummary(form.sections.map((s) => s.title))} (optional)
                </summary>
                <div style={{ marginTop: 'var(--space-3)' }}>
                  <div className="form-help" style={{ marginBottom: 'var(--space-3)' }}>
                    Discovery and the Topology map need none of these.
                  </div>
                  {form.sections.map((section) => (
                    <div key={section.title}>
                      <div style={{ marginBottom: 'var(--space-3)' }}>
                        <div style={{ fontWeight: 600 }}>{section.title}</div>
                        <div className="form-help">{section.help}</div>
                      </div>
                      {section.fields.map((f) => (
                        <AuthFieldInput key={f.key} field={f} value={values[f.key] ?? ''} onChange={(v) => setValue(f.key, v)} />
                      ))}
                    </div>
                  ))}
                </div>
              </details>
            )}

            <details className="form-group">
              <summary style={{ cursor: 'pointer', fontWeight: 600 }}>Additional settings (JSON, rarely needed)</summary>
              <div style={{ marginTop: 'var(--space-3)' }}>
                <label className="form-label" htmlFor={`${formId}-extra`}>Additional settings</label>
                <textarea
                  id={`${formId}-extra`}
                  className="form-input"
                  rows={3}
                  value={extraText}
                  onChange={(e) => setExtraText(e.target.value)}
                  placeholder={form.extraPlaceholder}
                  aria-describedby={`${formId}-extra-help`}
                />
                <div className="form-help" id={`${formId}-extra-help`}>
                  A JSON object of settings without a field above; it is saved on top of them.
                </div>
              </div>
            </details>
          </>
        )}

        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-notes`}>Notes</label>
          <textarea
            id={`${formId}-notes`}
            className="form-input"
            rows={2}
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Optional notes"
          />
        </div>

        <div className="form-group">
          <label className="form-check">
            <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
            <span>Enabled</span>
          </label>
        </div>

        {error && <Callout tone="danger">{error}</Callout>}
      </form>
    </Modal>
  );
}

function AuthFieldInput({ field, value, onChange }: { field: AuthField; value: string; onChange: (value: string) => void }) {
  const fid = useId();
  const id = `${fid}-${field.key}`;
  const describedBy = [field.list && `${id}-list`, field.help && `${id}-help`].filter(Boolean).join(' ') || undefined;
  return (
    <div className="form-group">
      <label className="form-label" htmlFor={id}>
        {field.label}
        {field.optional && <span className="text-muted"> (optional)</span>}
      </label>
      {field.json ? (
        <textarea
          id={id}
          className="form-input"
          rows={4}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={field.placeholder}
          aria-describedby={describedBy}
        />
      ) : (
        <input
          id={id}
          className="form-input"
          type={field.secret ? 'password' : 'text'}
          autoComplete={field.secret ? 'new-password' : 'off'}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={field.placeholder}
          aria-describedby={describedBy}
        />
      )}
      {field.list && <div className="form-help" id={`${id}-list`}>Separate several with commas.</div>}
      {field.help && <div className="form-help" id={`${id}-help`}>{field.help}</div>}
    </div>
  );
}
