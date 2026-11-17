import { type ReactNode, useId, useState } from 'react';

import { DeleteButton } from '@/components/DeleteButton';
import { useDialogs } from '@/components/DialogProvider-context';
import {
  AccessGroup,
  AdminCapabilities,
  AuthConfig,
  CredentialSummary,
  LoginRules,
  ServiceCredentialPayload,
  useAccessGroups,
  useAuthConfig,
  useCreateServiceCredential,
  useCredentialsList,
  useDeleteServiceCredential,
  useLoginRules,
  useServiceCredentialsList,
  useUpdateAuthConfig,
  useTestOidcConnection,
  useUpdateLoginRules,
  useUpdateServiceCredential,
} from '@/api/settings';
import { Callout } from '@/components/Callout';
import { CopyButton } from '@/components/CopyButton';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import { ModalActions } from '@/components/ModalActions';
import { QueryError } from '@/components/QueryError';
import { useReferenceProviders } from '@/api/secretsProviders';
import { ExternalReferenceFields, ValueSourceToggle, type ValueSource } from '@/components/ExternalReferenceFields';
import {
  hasReference,
  referenceDraft,
  referenceLabel,
  referencePayload,
  sameReference,
  validateReference,
  type ReferenceDraft,
  type ReferenceErrors,
} from '@/lib/secretsProviders';
import { usePendingKeys } from '@/lib/usePendingKeys';

import { CheckboxField, CheckboxRow, FormRow, NumberField, TextField } from './FormFields';
import { SaveBar } from './SaveBar';
import { SectionCard } from './SectionCard';
import { FormStatus, StatusLine } from './StatusLine';
import { useReportUnsaved } from './unsaved-context';
import {
  OIDC_BUTTON_LABEL_MAX,
  OIDC_MAX_GROUP_MAPPINGS,
  oidcProblem,
  oidcRedirectUri,
  parseGroupLines,
  removeMapping,
  updateMapping,
} from './oidcSettings';
import { GroupCheckboxes } from './UserModals';
import { useSavedDraft } from './useSavedDraft';

// Help texts follow the login handler in routes/auth.py: only failed logins
// are counted, per client IP, over a sliding window.
const LOGIN_RULE_FIELDS: Array<{
  key: keyof LoginRules;
  label: string;
  min: number;
  max?: number;
  help: string;
}> = [
  {
    key: 'max_attempts',
    label: 'Max attempts',
    min: 1,
    help: 'Failed logins from one client IP within the rate window that lock it out.',
  },
  {
    key: 'lockout_time',
    label: 'Lockout time (s)',
    min: 1,
    help: 'How long a locked-out client IP is refused.',
  },
  {
    key: 'rate_limit_window',
    label: 'Rate window (s)',
    min: 1,
    help: 'Sliding window over which failed logins per client IP are counted.',
  },
  {
    key: 'rate_limit_max',
    label: 'Rate limit max',
    min: 1,
    help: 'Failed logins in the window after which new attempts from that IP are refused, without a lockout.',
  },
  {
    key: 'session_idle_timeout',
    label: 'Idle timeout (s, 0 = off)',
    min: 0,
    max: 86400,
    help: 'Signs a session out after this long without a request; at most 86400 (24 h).',
  },
];

function LoginRulesForm() {
  const query = useLoginRules();
  const update = useUpdateLoginRules();
  const { draft, setDraft, dirty, discard, markSaved } = useSavedDraft(query.data);
  const [status, setStatus] = useState<FormStatus | null>(null);

  if (!draft) {
    if (query.isError)
      return (
        <QueryError what="login rules" query={query} />
      );
    return <LoadingState />;
  }

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        setStatus(null);
        update.mutate(draft, {
          onSuccess: (saved) => {
            markSaved(saved);
            setStatus({ kind: 'success', message: 'Login rules updated' });
          },
          onError: (err) =>
            setStatus({
              kind: 'error',
              message: `Failed to save login rules: ${(err as Error).message}`,
            }),
        });
      }}
    >
      <FormRow>
        {LOGIN_RULE_FIELDS.map((f) => (
          <NumberField
            key={f.key}
            label={f.label}
            value={draft[f.key]}
            min={f.min}
            max={f.max}
            flex="1 1 180px"
            help={f.help}
            onChange={(v) => setDraft({ ...draft, [f.key]: v })}
          />
        ))}
      </FormRow>
      <SaveBar
        name="Login Rules"
        dirty={dirty}
        busy={update.isPending}
        label="Save Login Rules"
        status={status}
        onDiscard={discard}
      />
    </form>
  );
}

function AuthConfigForm({ groups }: { groups: AccessGroup[] }) {
  const query = useAuthConfig();
  const update = useUpdateAuthConfig();
  const credentials = useCredentialsList();
  const serviceCredentials = useServiceCredentialsList();
  const fid = useId();
  // Job and change log retention ride on the same payload but are edited by
  // the retention sections; each form re-seeds only while it is clean, so a
  // save in one never discards unsaved edits in the other.
  const { draft, setDraft, dirty, discard, markSaved } = useSavedDraft(query.data);
  const [status, setStatus] = useState<FormStatus | null>(null);

  if (!draft) {
    if (query.isError)
      return (
        <QueryError what="auth config" query={query} />
      );
    return <LoadingState />;
  }

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        setStatus(null);
        const problem = draft.oidc ? oidcProblem(draft.oidc) : null;
        if (problem) {
          setStatus({ kind: 'error', message: problem });
          return;
        }
        // Submit the server's current retention, never the copy this draft
        // was seeded with, so a retention change saved meanwhile survives.
        const payload: AuthConfig = {
          ...draft,
          job_retention_days: query.data?.job_retention_days ?? draft.job_retention_days,
          change_log_retention_days: query.data?.change_log_retention_days ?? draft.change_log_retention_days,
        };
        update.mutate(payload, {
          onSuccess: (saved) => {
            markSaved(saved);
            setStatus({ kind: 'success', message: 'Authentication settings saved' });
          },
          onError: (err) =>
            setStatus({
              kind: 'error',
              message: `Failed to save authentication settings: ${(err as Error).message}`,
            }),
        });
      }}
    >
      {credentials.isError && !credentials.data && (
        <QueryError what="credentials" query={credentials} />
      )}
      <FormRow>
        <div className="form-group" style={{ flex: '1 1 200px' }}>
          <label className="form-label" htmlFor={`${fid}-provider`}>Auth Provider</label>
          <select
            id={`${fid}-provider`}
            className="form-select"
            value={draft.provider}
            onChange={(e) => setDraft({ ...draft, provider: e.target.value })}
          >
            <option value="local">Local</option>
            <option value="radius">RADIUS</option>
            <option value="tacacs">TACACS+</option>
            <option value="ldap">LDAP</option>
          </select>
        </div>
        <div className="form-group" style={{ flex: '1 1 200px' }}>
          <label className="form-label" htmlFor={`${fid}-default-credential`}>Default Credential</label>
          <select
            id={`${fid}-default-credential`}
            className="form-select"
            value={draft.default_credential_id ?? ''}
            aria-describedby={`${fid}-default-credential-help`}
            onChange={(e) =>
              setDraft({
                ...draft,
                default_credential_id: e.target.value ? Number(e.target.value) : null,
              })
            }
          >
            <option value="">- None -</option>
            {(credentials.data || []).map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
                {c.username ? ` (${c.username})` : ''}
              </option>
            ))}
          </select>
          <div className="form-help" id={`${fid}-default-credential-help`}>
            Per-user fallback for jobs launched without selecting a credential.
          </div>
        </div>
        <div className="form-group" style={{ flex: '1 1 200px' }}>
          <label className="form-label" htmlFor={`${fid}-service-credential`}>Service Credential</label>
          <select
            id={`${fid}-service-credential`}
            className="form-select"
            value={draft.service_credential_id ?? ''}
            aria-describedby={`${fid}-service-credential-help`}
            onChange={(e) =>
              setDraft({
                ...draft,
                service_credential_id: e.target.value ? Number(e.target.value) : null,
              })
            }
          >
            <option value="">- None -</option>
            {(serviceCredentials.data || []).map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
                {c.username ? ` (${c.username})` : ''}
              </option>
            ))}
          </select>
          <div className="form-help" id={`${fid}-service-credential-help`}>
            Used by Plexus internals (monitoring polls, scheduled discovery).
          </div>
        </div>
      </FormRow>

      {draft.provider === 'radius' && (
        <RadiusPanel draft={draft} setDraft={setDraft} groups={groups} />
      )}
      {draft.provider === 'tacacs' && (
        <TacacsPanel draft={draft} setDraft={setDraft} groups={groups} />
      )}
      {draft.provider === 'ldap' && (
        <LdapPanel draft={draft} setDraft={setDraft} groups={groups} />
      )}
      {draft.oidc && <OidcPanel draft={draft} setDraft={setDraft} groups={groups} />}

      <SaveBar
        name="Authentication"
        dirty={dirty}
        busy={update.isPending}
        label="Save Authentication"
        status={status}
        onDiscard={discard}
      />
    </form>
  );
}

interface PanelProps {
  draft: AuthConfig;
  setDraft: (next: AuthConfig) => void;
  groups: AccessGroup[];
}

// Shared by the three providers (routes/auth.py _auth_identity): an
// unreachable server falls back to local accounts when "Fallback to local"
// is on; a rejected password does so only when "Fallback on reject" is on too.
const FALLBACK_LOCAL_HELP = 'Try local accounts when the server cannot be reached.';
const FALLBACK_REJECT_HELP = 'Also try local accounts when the server rejects the login.';

function ProviderFieldset({ legend, children }: { legend: string; children: ReactNode }) {
  return (
    <fieldset
      style={{
        marginTop: '1rem',
        padding: '0.75rem',
        border: '1px solid var(--border)',
        borderRadius: '0.375rem',
      }}
    >
      <legend style={{ padding: '0 0.4rem' }}>{legend}</legend>
      {children}
    </fieldset>
  );
}

function RadiusPanel({ draft, setDraft, groups }: PanelProps) {
  const r = draft.radius;
  const setR = (patch: Partial<typeof r>) =>
    setDraft({ ...draft, radius: { ...r, ...patch } });

  return (
    <ProviderFieldset legend="RADIUS">
      <CheckboxRow>
        <CheckboxField
          label="Enabled"
          checked={r.enabled}
          onChange={(v) => setR({ enabled: v })}
        />
        <CheckboxField
          label="Fallback to local"
          checked={r.fallback_to_local}
          onChange={(v) => setR({ fallback_to_local: v })}
          help={FALLBACK_LOCAL_HELP}
        />
        <CheckboxField
          label="Fallback on reject"
          checked={r.fallback_on_reject}
          onChange={(v) => setR({ fallback_on_reject: v })}
          help={FALLBACK_REJECT_HELP}
        />
        <CheckboxField
          label="Require Message-Authenticator"
          checked={r.enforce_message_authenticator}
          onChange={(v) => setR({ enforce_message_authenticator: v })}
          help="Blast-RADIUS (CVE-2024-3596) mitigation; the server must echo it in replies."
        />
      </CheckboxRow>
      <FormRow>
        <TextField
          label="Server"
          value={r.server}
          onChange={(v) => setR({ server: v })}
          flex="1 1 220px"
        />
        <NumberField
          label="Port"
          value={r.port}
          onChange={(v) => setR({ port: v })}
        />
        <TextField
          label="Shared Secret"
          type="password"
          value={r.secret}
          onChange={(v) => setR({ secret: v })}
          flex="1 1 200px"
        />
        <NumberField
          label="Timeout (s)"
          value={r.timeout}
          onChange={(v) => setR({ timeout: v })}
        />
      </FormRow>
      <DefaultGroupsField
        groups={groups}
        selected={r.default_group_ids}
        onChange={(ids) => setR({ default_group_ids: ids })}
      />
    </ProviderFieldset>
  );
}

function TacacsPanel({ draft, setDraft, groups }: PanelProps) {
  const t = draft.tacacs;
  const fid = useId();
  const setT = (patch: Partial<typeof t>) =>
    setDraft({ ...draft, tacacs: { ...t, ...patch } });

  return (
    <ProviderFieldset legend="TACACS+">
      <p className="form-help" style={{ marginTop: 0 }}>
        Cisco ISE Device Admin style login: the whole exchange is obfuscated under the
        shared secret and an ISE shell profile can assert the Plexus role. Register the
        Plexus host as a Network Device in ISE with TACACS+ enabled.
      </p>
      <CheckboxRow>
        <CheckboxField
          label="Enabled"
          checked={t.enabled}
          onChange={(v) => setT({ enabled: v })}
        />
        <CheckboxField
          label="Fallback to local"
          checked={t.fallback_to_local}
          onChange={(v) => setT({ fallback_to_local: v })}
          help={FALLBACK_LOCAL_HELP}
        />
        <CheckboxField
          label="Fallback on reject"
          checked={t.fallback_on_reject}
          onChange={(v) => setT({ fallback_on_reject: v })}
          help={FALLBACK_REJECT_HELP}
        />
        <CheckboxField
          label="Authorize (map ISE shell profile to role)"
          checked={t.authorize}
          onChange={(v) => setT({ authorize: v })}
          help="Off: authenticate only, without setting the role."
        />
      </CheckboxRow>
      <FormRow>
        <TextField
          label="Server"
          value={t.server}
          onChange={(v) => setT({ server: v })}
          flex="1 1 220px"
        />
        <NumberField
          label="Port"
          value={t.port}
          onChange={(v) => setT({ port: v })}
        />
        <TextField
          label="Shared Secret"
          type="password"
          value={t.secret}
          onChange={(v) => setT({ secret: v })}
          flex="1 1 200px"
        />
        <NumberField
          label="Timeout (s)"
          value={t.timeout}
          onChange={(v) => setT({ timeout: v })}
        />
        <div className="form-group" style={{ flex: '1 1 160px' }}>
          <label className="form-label" htmlFor={`${fid}-authen-type`}>Authentication Type</label>
          <select
            id={`${fid}-authen-type`}
            className="form-select"
            value={t.authen_type}
            onChange={(e) => setT({ authen_type: e.target.value })}
          >
            <option value="ascii">ASCII (interactive login, IOS default)</option>
            <option value="pap">PAP</option>
          </select>
        </div>
      </FormRow>
      {t.authorize && (
        <FormRow>
          <TextField
            label="Authorization Service"
            value={t.service}
            onChange={(v) => setT({ service: v })}
            flex="1 1 160px"
          />
          <TextField
            label="Role Attribute"
            value={t.role_attribute}
            onChange={(v) => setT({ role_attribute: v })}
            flex="1 1 200px"
            help="Custom attribute on the ISE shell profile; its value (admin or user) sets the role."
          />
          <NumberField
            label="Admin priv-lvl (0 = off)"
            value={t.admin_priv_lvl}
            onChange={(v) => setT({ admin_priv_lvl: v })}
          />
          <div className="form-group" style={{ flex: '1 1 140px' }}>
            <label className="form-label" htmlFor={`${fid}-default-role`}>Default Role</label>
            <select
              id={`${fid}-default-role`}
              className="form-select"
              value={t.default_role ?? 'user'}
              onChange={(e) => setT({ default_role: e.target.value })}
            >
              <option value="user">user</option>
              <option value="admin">admin</option>
            </select>
          </div>
        </FormRow>
      )}
      {t.authorize && (
        <p className="form-help" style={{ marginTop: 0 }}>
          Role precedence: <code>{t.role_attribute || 'plexus-role'}=admin|user</code> from the
          shell profile&apos;s custom attributes, then <code>priv-lvl</code> &ge;{' '}
          {t.admin_priv_lvl || '(off)'}, then the default role. Re-synced on every login.
        </p>
      )}
      <DefaultGroupsField
        groups={groups}
        selected={t.default_group_ids}
        onChange={(ids) => setT({ default_group_ids: ids })}
      />
    </ProviderFieldset>
  );
}

function LdapPanel({ draft, setDraft, groups }: PanelProps) {
  const l = draft.ldap;
  const fid = useId();
  const setL = (patch: Partial<typeof l>) =>
    setDraft({ ...draft, ldap: { ...l, ...patch } });

  return (
    <ProviderFieldset legend="LDAP">
      <CheckboxRow>
        <CheckboxField
          label="Enabled"
          checked={l.enabled}
          onChange={(v) => setL({ enabled: v })}
        />
        <CheckboxField
          label="Use SSL"
          checked={l.use_ssl}
          onChange={(v) => setL({ use_ssl: v })}
        />
        <CheckboxField
          label="Use STARTTLS"
          checked={l.use_starttls}
          onChange={(v) => setL({ use_starttls: v })}
          help="Ignored when Use SSL is on."
        />
        <CheckboxField
          label="Fallback to local"
          checked={l.fallback_to_local}
          onChange={(v) => setL({ fallback_to_local: v })}
          help={FALLBACK_LOCAL_HELP}
        />
        <CheckboxField
          label="Fallback on reject"
          checked={l.fallback_on_reject}
          onChange={(v) => setL({ fallback_on_reject: v })}
          help={FALLBACK_REJECT_HELP}
        />
      </CheckboxRow>
      <FormRow>
        <TextField
          label="Server"
          value={l.server}
          onChange={(v) => setL({ server: v })}
          flex="1 1 220px"
        />
        <NumberField
          label="Port"
          value={l.port}
          onChange={(v) => setL({ port: v })}
        />
        <NumberField
          label="Timeout (s)"
          value={l.timeout}
          onChange={(v) => setL({ timeout: v })}
        />
        <div className="form-group" style={{ flex: '1 1 160px' }}>
          <label className="form-label" htmlFor={`${fid}-tls-verify`}>TLS Certificate Verification</label>
          <select
            id={`${fid}-tls-verify`}
            className="form-select"
            value={l.tls_verify}
            onChange={(e) => setL({ tls_verify: e.target.value })}
          >
            <option value="demand">demand (verify, recommended)</option>
            <option value="hard">hard (verify, strict)</option>
            <option value="try">try</option>
            <option value="allow">allow (permissive)</option>
            <option value="never">never (no verification)</option>
          </select>
        </div>
        <TextField
          label="CA Certificate File (optional)"
          value={l.ca_cert_file}
          onChange={(v) => setL({ ca_cert_file: v })}
          flex="1 1 220px"
          help="Path on the Plexus host; blank uses the system trust store."
        />
      </FormRow>
      <TextField
        label="Bind DN"
        value={l.bind_dn}
        onChange={(v) => setL({ bind_dn: v })}
        help="Service account Plexus binds as to search for users."
      />
      <TextField
        label="Bind Password"
        type="password"
        value={l.bind_password}
        onChange={(v) => setL({ bind_password: v })}
      />
      <TextField
        label="Base DN"
        value={l.base_dn}
        onChange={(v) => setL({ base_dn: v })}
        help="Subtree searched for user entries."
      />
      <TextField
        label="User Search Filter"
        value={l.user_search_filter}
        onChange={(v) => setL({ user_search_filter: v })}
        help="{username} is replaced by the login name, e.g. (sAMAccountName={username}). Must match exactly one entry."
      />
      <TextField
        label="Admin Group DN"
        value={l.admin_group_dn}
        onChange={(v) => setL({ admin_group_dn: v })}
        help="Members of this group get the admin role; re-checked on every login."
      />
      <DefaultGroupsField
        groups={groups}
        selected={l.default_group_ids}
        onChange={(ids) => setL({ default_group_ids: ids })}
      />
    </ProviderFieldset>
  );
}

/** OpenID Connect single sign-on. Not a provider choice: it is offered on
 * the login page next to the password form, whichever provider is set. */
export function OidcPanel({ draft, setDraft, groups }: PanelProps) {
  const o = draft.oidc;
  const fid = useId();
  const test = useTestOidcConnection();
  const setO = (patch: Partial<typeof o>) => setDraft({ ...draft, oidc: { ...o, ...patch } });
  const origin = typeof window === 'undefined' ? '' : window.location.origin;
  const redirectUri = oidcRedirectUri(o.redirect_uri, origin);
  const result = test.data;

  return (
    <ProviderFieldset legend="Single sign-on (OpenID Connect)">
      <p className="form-help" style={{ marginTop: 0 }}>
        Adds a sign-in button that sends the browser to your identity provider (Entra ID, Okta,
        Keycloak and others). The password form and the local break-glass admin keep working.
        Register Plexus at the provider as a web application with the redirect URI below.
      </p>
      <CheckboxRow>
        <CheckboxField label="Enabled" checked={o.enabled} onChange={(v) => setO({ enabled: v })} />
        <CheckboxField
          label="Lead with SSO on the login page"
          checked={o.primary}
          onChange={(v) => setO({ primary: v })}
          help="The password form folds behind “Use a local account”."
        />
        <CheckboxField
          label="Sync access groups on every login"
          checked={o.sync_groups}
          onChange={(v) => setO({ sync_groups: v })}
          help="Sets the account's groups to the defaults plus every mapped group in the token."
        />
      </CheckboxRow>
      <div className="form-group">
        <label className="form-label" htmlFor={`${fid}-redirect`}>Redirect URI to register</label>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <input
            id={`${fid}-redirect`}
            className="form-input"
            readOnly
            value={result?.redirect_uri || redirectUri}
            aria-describedby={`${fid}-redirect-help`}
          />
          <CopyButton text={result?.redirect_uri || redirectUri} />
        </div>
        <div className="form-help" id={`${fid}-redirect-help`}>
          Behind a proxy that changes the host name, set the redirect URI override below.
        </div>
      </div>
      <FormRow>
        <TextField
          label="Issuer"
          value={o.issuer}
          onChange={(v) => setO({ issuer: v })}
          flex="1 1 280px"
          placeholder="https://idp.example.com/realms/plexus"
          help="Must equal the issuer in the provider's discovery document exactly."
        />
        <TextField
          label="Client ID"
          value={o.client_id}
          onChange={(v) => setO({ client_id: v })}
          flex="1 1 200px"
          autoComplete="off"
        />
        <TextField
          label="Client Secret"
          type="password"
          value={o.client_secret}
          onChange={(v) => setO({ client_secret: v })}
          flex="1 1 200px"
          autoComplete="new-password"
          help="Stored encrypted. Leave empty for a public client."
        />
        <div className="form-group" style={{ flex: '1 1 200px' }}>
          <label className="form-label" htmlFor={`${fid}-auth-method`}>Token Endpoint Auth</label>
          <select
            id={`${fid}-auth-method`}
            className="form-select"
            value={o.token_auth_method}
            onChange={(e) => setO({ token_auth_method: e.target.value })}
          >
            <option value="client_secret_basic">client_secret_basic</option>
            <option value="client_secret_post">client_secret_post</option>
          </select>
        </div>
      </FormRow>
      <FormRow>
        <TextField
          label="Scopes"
          value={o.scopes}
          onChange={(v) => setO({ scopes: v })}
          flex="1 1 220px"
          help="openid is always sent."
        />
        <TextField
          label="Username Claim"
          value={o.username_claim}
          onChange={(v) => setO({ username_claim: v })}
          flex="1 1 160px"
        />
        <TextField
          label="Display Name Claim"
          value={o.display_name_claim}
          onChange={(v) => setO({ display_name_claim: v })}
          flex="1 1 160px"
        />
        <TextField
          label="Groups Claim"
          value={o.groups_claim}
          onChange={(v) => setO({ groups_claim: v })}
          flex="1 1 160px"
        />
      </FormRow>
      <FormRow>
        <div className="form-group" style={{ flex: '1 1 260px' }}>
          <label className="form-label" htmlFor={`${fid}-admin-groups`}>Admin Groups</label>
          <textarea
            id={`${fid}-admin-groups`}
            className="form-input"
            rows={3}
            value={o.admin_groups.join('\n')}
            aria-describedby={`${fid}-admin-groups-help`}
            onChange={(e) => setO({ admin_groups: parseGroupLines(e.target.value) })}
          />
          <div className="form-help" id={`${fid}-admin-groups-help`}>
            One group claim value per line. Members get the admin role; re-checked on every login.
          </div>
        </div>
        <div className="form-group" style={{ flex: '0 1 160px' }}>
          <label className="form-label" htmlFor={`${fid}-default-role`}>Default Role</label>
          <select
            id={`${fid}-default-role`}
            className="form-select"
            value={o.default_role}
            onChange={(e) => setO({ default_role: e.target.value })}
          >
            <option value="user">user</option>
            <option value="admin">admin</option>
          </select>
        </div>
        <TextField
          label="Button Label"
          value={o.button_label}
          onChange={(v) => setO({ button_label: v })}
          flex="1 1 200px"
          help={`At most ${OIDC_BUTTON_LABEL_MAX} characters.`}
        />
      </FormRow>
      <FormRow>
        <TextField
          label="Redirect URI Override (optional)"
          value={o.redirect_uri}
          onChange={(v) => setO({ redirect_uri: v })}
          flex="1 1 280px"
          help="Blank derives it from the request."
        />
        <TextField
          label="CA Certificate File (optional)"
          value={o.ca_cert_file}
          onChange={(v) => setO({ ca_cert_file: v })}
          flex="1 1 220px"
          help="Path on the Plexus host for a private CA; blank uses the system trust store."
        />
      </FormRow>
      <OidcMappingsField
        mappings={o.group_mappings}
        groups={groups}
        onChange={(group_mappings) => setO({ group_mappings })}
      />
      <DefaultGroupsField
        groups={groups}
        selected={o.default_group_ids}
        onChange={(ids) => setO({ default_group_ids: ids })}
      />
      <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
        <button
          type="button"
          className="btn btn-sm btn-secondary"
          disabled={test.isPending || !o.issuer.trim()}
          onClick={() => test.mutate({ issuer: o.issuer.trim(), ca_cert_file: o.ca_cert_file.trim() })}
        >
          {test.isPending ? 'Testing…' : 'Test connection'}
        </button>
        <span className="form-help">Fetches the discovery document and signing keys of the issuer above.</span>
      </div>
      {test.isError && (
        <Callout tone="danger">Connection test failed: {(test.error as Error).message}</Callout>
      )}
      {result && (
        <Callout tone={result.ok ? 'success' : 'danger'}>
          {result.ok
            ? `Reached ${result.issuer}: ${result.key_count} signing key(s), algorithms ${result.algorithms.join(', ')}.`
            : `Could not use ${result.issuer || 'the issuer'}: ${result.error}`}
        </Callout>
      )}
    </ProviderFieldset>
  );
}

function OidcMappingsField({
  mappings,
  groups,
  onChange,
}: {
  mappings: { group: string; access_group_id: number }[];
  groups: AccessGroup[];
  onChange: (next: { group: string; access_group_id: number }[]) => void;
}) {
  const id = useId();
  return (
    <div className="form-group">
      <span className="form-label" id={id}>Group Mappings</span>
      {mappings.length === 0 && (
        <div className="form-help">No mappings. With access group sync on, a mapping adds an access group for a group claim value.</div>
      )}
      {mappings.map((m, i) => (
        <div key={i} className="form-row" role="group" aria-labelledby={id}>
          <div className="form-group" style={{ flex: '1 1 220px' }}>
            <label className="form-label" htmlFor={`${id}-group-${i}`}>Group claim value</label>
            <input
              id={`${id}-group-${i}`}
              className="form-input"
              value={m.group}
              onChange={(e) => onChange(updateMapping(mappings, i, { group: e.target.value }))}
            />
          </div>
          <div className="form-group" style={{ flex: '1 1 200px' }}>
            <label className="form-label" htmlFor={`${id}-ag-${i}`}>Access group</label>
            <select
              id={`${id}-ag-${i}`}
              className="form-select"
              value={m.access_group_id || ''}
              onChange={(e) => onChange(updateMapping(mappings, i, { access_group_id: Number(e.target.value) }))}
            >
              <option value="">- Choose -</option>
              {groups.map((g) => (
                <option key={g.id} value={g.id}>{g.name}</option>
              ))}
            </select>
          </div>
          <div className="form-group form-check-field" style={{ flex: '0 0 auto' }}>
            <span className="form-label" aria-hidden="true">&nbsp;</span>
            <button
              type="button"
              className="btn btn-sm btn-secondary"
              aria-label={`Remove mapping ${m.group || i + 1}`}
              onClick={() => onChange(removeMapping(mappings, i))}
            >
              Remove
            </button>
          </div>
        </div>
      ))}
      <div>
        <button
          type="button"
          className="btn btn-sm btn-secondary"
          disabled={mappings.length >= OIDC_MAX_GROUP_MAPPINGS}
          onClick={() => onChange([...mappings, { group: '', access_group_id: 0 }])}
        >
          + Add Mapping
        </button>
      </div>
    </div>
  );
}

function DefaultGroupsField({
  groups,
  selected,
  onChange,
}: {
  groups: AccessGroup[];
  selected: number[];
  onChange: (ids: number[]) => void;
}) {
  const id = useId();
  return (
    <div className="form-group">
      <span className="form-label" id={id}>Default Access Groups</span>
      <GroupCheckboxes
        groups={groups}
        selected={selected}
        onChange={onChange}
        labelledBy={id}
      />
      <div className="form-help">
        Given to accounts created on their first login through this provider.
      </div>
    </div>
  );
}

const EMPTY_SERVICE_CREDENTIAL: ServiceCredentialPayload = {
  name: '',
  username: '',
  password: '',
  secret: '',
};

/** Create (cred = null) or edit one service credential. */
function ServiceCredentialModal({
  cred,
  onClose,
  onSaved,
}: {
  cred: CredentialSummary | null;
  onClose: () => void;
  onSaved: (message: string) => void;
}) {
  const isEdit = cred !== null;
  const create = useCreateServiceCredential();
  const updateMut = useUpdateServiceCredential();
  const providers = useReferenceProviders();
  const wasExternal = hasReference(cred);
  const [source, setSource] = useState<ValueSource>(wasExternal ? 'external' : 'stored');
  const [initialRef] = useState<ReferenceDraft>(() => referenceDraft(cred));
  const [reference, setReference] = useState<ReferenceDraft>(initialRef);
  const [refErrors, setRefErrors] = useState<ReferenceErrors>({});
  const external = source === 'external';
  const [initial] = useState<ServiceCredentialPayload>(() =>
    cred
      ? { name: cred.name, username: cred.username || '', password: '', secret: '' }
      : EMPTY_SERVICE_CREDENTIAL,
  );
  const [form, setForm] = useState<ServiceCredentialPayload>(initial);
  const [error, setError] = useState<string | null>(null);

  const touched =
    form.name !== initial.name ||
    form.username !== initial.username ||
    !!form.password ||
    !!form.secret ||
    source !== (wasExternal ? 'external' : 'stored') ||
    !sameReference(reference, initialRef);
  useReportUnsaved('Service Credential', touched);

  const missing: string[] = [];
  if (!form.name.trim()) missing.push('a name');
  if (!form.username.trim()) missing.push('a username');
  if (!external && (!isEdit || wasExternal) && !form.password) missing.push('a password');

  const submitting = create.isPending || updateMut.isPending;
  const name = form.name.trim();

  const onSubmit = () => {
    if (missing.length > 0) return;
    const nextRef = external ? validateReference(reference) : {};
    setRefErrors(nextRef);
    if (Object.keys(nextRef).length > 0) return;
    setError(null);
    if (!isEdit) {
      const body = external
        ? { name: form.name, username: form.username, password: '', external: referencePayload(reference, true) }
        : form;
      create.mutate(body, {
        onSuccess: () => onSaved(`Service credential “${name}” created`),
        onError: (err) => setError(`Failed to create service credential: ${(err as Error).message}`),
      });
      return;
    }
    // Update: send only fields the user changed; empty password/secret means leave alone.
    const data: Partial<ServiceCredentialPayload> = {
      name: form.name,
      username: form.username,
    };
    if (external) {
      if (!wasExternal || !sameReference(reference, initialRef)) data.external = referencePayload(reference, true);
    } else {
      if (form.password) data.password = form.password;
      if (form.secret) data.secret = form.secret;
    }
    updateMut.mutate(
      { id: cred.id, data },
      {
        onSuccess: () => onSaved(`Service credential “${name}” updated`),
        onError: (err) => setError(`Failed to update service credential: ${(err as Error).message}`),
      },
    );
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={isEdit ? `Edit Service Credential: ${cred.name}` : 'New Service Credential'}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={isEdit ? 'Save Changes' : 'Create'}
          primaryBusy={submitting}
          primaryBusyLabel="Saving…"
          primaryDisabled={missing.length > 0}
          onPrimary={onSubmit}
        />
      }
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          onSubmit();
        }}
      >
        <FormRow>
          <TextField
            label="Name"
            value={form.name}
            onChange={(v) => setForm({ ...form, name: v })}
            flex="1 1 200px"
          />
          <TextField
            label="Username"
            value={form.username}
            onChange={(v) => setForm({ ...form, username: v })}
            flex="1 1 200px"
            autoComplete="off"
          />
        </FormRow>
        {(wasExternal || (providers.data?.length ?? 0) > 0) && (
          <ValueSourceToggle value={source} onChange={setSource} />
        )}
        {external ? (
          <ExternalReferenceFields
            idPrefix={`service-cred-${cred?.id ?? 'new'}`}
            value={reference}
            onChange={(next) => {
              setReference(next);
              setRefErrors({});
            }}
            providers={providers.data ?? []}
            errors={refErrors}
            withSecretKey
            keyLabel="Password key"
          />
        ) : (
          <FormRow>
            <TextField
              label={isEdit && !wasExternal ? 'Password (blank = unchanged)' : 'Password'}
              type="password"
              value={form.password}
              onChange={(v) => setForm({ ...form, password: v })}
              flex="1 1 200px"
              autoComplete="new-password"
            />
            <TextField
              label={isEdit && !wasExternal ? 'Enable Secret (blank = unchanged)' : 'Enable Secret (optional)'}
              type="password"
              value={form.secret ?? ''}
              onChange={(v) => setForm({ ...form, secret: v })}
              flex="1 1 200px"
              autoComplete="new-password"
            />
          </FormRow>
        )}
        {/* Lets Enter submit; the visible button is in the modal footer. */}
        <button type="submit" hidden />
      </form>
      {missing.length > 0 && (
        <p className="form-help" role="status">
          Still needed: {missing.join(', ')}.
        </p>
      )}
      {error && <Callout tone="danger">{error}</Callout>}
    </Modal>
  );
}

function ServiceCredentialsSection() {
  const { confirm } = useDialogs();
  const list = useServiceCredentialsList();
  const remove = useDeleteServiceCredential();
  const deleting = usePendingKeys<number>();

  // undefined = editor closed, null = new credential, else the row being edited.
  const [editing, setEditing] = useState<CredentialSummary | null | undefined>(undefined);
  const [status, setStatus] = useState<FormStatus | null>(null);

  const openEditor = (cred: CredentialSummary | null) => {
    setStatus(null);
    setEditing(cred);
  };

  const onDelete = async (cred: CredentialSummary) => {
    if (!(await confirm({
      title: 'Delete service credential',
      message: `Delete service credential “${cred.name}”?`,
      confirmLabel: 'Delete',
    }))) return;
    await deleting.run(cred.id, async () => {
      try {
        await remove.mutateAsync(cred.id);
        setStatus({ kind: 'success', message: `Service credential “${cred.name}” deleted` });
      } catch (err) {
        setStatus({
          kind: 'error',
          message: `Failed to delete service credential: ${(err as Error).message}`,
        });
      }
    });
  };

  if (list.isError && !list.data)
    return (
      <QueryError what="service credentials" query={list} />
    );
  if (!list.data) return <LoadingState />;

  return (
    <div>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          gap: '0.75rem',
          marginBottom: '0.75rem',
        }}
      >
        <p className="card-description" style={{ margin: 0 }}>
          Service credentials are used by Plexus itself for monitoring polls and
          scheduled discovery. They are administered separately from per-user
          credentials and can only be created or modified by admins.
        </p>
        <button
          type="button"
          className="btn btn-sm btn-primary"
          style={{ flex: '0 0 auto' }}
          onClick={() => openEditor(null)}
        >
          + Add Service Credential
        </button>
      </div>

      {list.data.length === 0 ? (
        <EmptyState compact message="No service credentials yet." />
      ) : (
        <DataTable compact aria-label="Service credentials">
          <thead>
            <tr>
              <th>Name</th>
              <th>Username</th>
              <th style={{ textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {list.data.map((c) => (
              <tr key={c.id}>
                <td>
                  {c.name}
                  {hasReference(c) && (
                    <div className="form-help" style={{ margin: 0 }}>
                      External: {referenceLabel(c)}
                    </div>
                  )}
                </td>
                <td>{c.username || '-'}</td>
                <td>
                  <div className="table-actions">
                    <button
                      type="button"
                      className="btn btn-sm btn-secondary"
                      aria-label={`Edit service credential ${c.name}`}
                      onClick={() => openEditor(c)}
                    >
                      Edit
                    </button>
                    <DeleteButton
                      size="sm"
                      aria-label={`Delete service credential ${c.name}`}
                      onClick={() => void onDelete(c)}
                      busy={deleting.isPending(c.id)}
                    />
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      )}
      <StatusLine status={status} />

      {editing !== undefined && (
        <ServiceCredentialModal
          key={editing?.id ?? 'new'}
          cred={editing}
          onClose={() => setEditing(undefined)}
          onSaved={(message) => {
            setEditing(undefined);
            setStatus({ kind: 'success', message });
          }}
        />
      )}
    </div>
  );
}

export function AuthTab({ capabilities }: { capabilities: AdminCapabilities }) {
  const groups = useAccessGroups();

  return (
    <div className="stack">
      <SectionCard title="Login Rules">
        <LoginRulesForm />
      </SectionCard>
      <SectionCard
        title={`Authentication (providers: ${capabilities.auth_providers.join(', ')})`}
      >
        {groups.isError && !groups.data && (
          <QueryError what="access groups" query={groups} />
        )}
        <AuthConfigForm groups={groups.data || []} />
      </SectionCard>
      <SectionCard title="Service Credentials">
        <ServiceCredentialsSection />
      </SectionCard>
    </div>
  );
}
