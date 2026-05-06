import { useEffect, useState } from 'react';

import {
  AccessGroup,
  AdminCapabilities,
  AuthConfig,
  LoginRules,
  useAccessGroups,
  useAuthConfig,
  useCredentialsList,
  useLoginRules,
  useUpdateAuthConfig,
  useUpdateLoginRules,
} from '@/api/settings';

const SECTION_GAP = '1.5rem';

function SectionCard({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div
      className="card"
      style={{ padding: '1rem', marginBottom: SECTION_GAP }}
    >
      <h3 style={{ margin: '0 0 0.75rem 0' }}>{title}</h3>
      {children}
    </div>
  );
}

function ToastSlot({ message, kind }: { message: string | null; kind: 'success' | 'error' }) {
  if (!message) return null;
  return (
    <div
      className={kind === 'error' ? 'error' : ''}
      style={{
        marginTop: '0.5rem',
        color: kind === 'error' ? undefined : 'var(--success)',
      }}
    >
      {message}
    </div>
  );
}

function LoginRulesForm() {
  const query = useLoginRules();
  const update = useUpdateLoginRules();
  const [draft, setDraft] = useState<LoginRules | null>(null);
  const [status, setStatus] = useState<{ kind: 'success' | 'error'; message: string } | null>(null);

  useEffect(() => {
    if (query.data) setDraft(query.data);
  }, [query.data]);

  if (query.isLoading || !draft) return <p className="text-muted">Loading…</p>;
  if (query.isError)
    return (
      <div className="error">
        Failed to load login rules: {(query.error as Error).message}
      </div>
    );

  const numField = (
    label: string,
    key: keyof LoginRules,
    min: number,
  ) => (
    <div className="form-group" style={{ flex: '1 1 180px' }}>
      <label className="form-label">{label}</label>
      <input
        type="number"
        className="form-input"
        min={min}
        value={draft[key]}
        onChange={(e) =>
          setDraft({ ...draft, [key]: Number(e.target.value) })
        }
      />
    </div>
  );

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        setStatus(null);
        update.mutate(draft, {
          onSuccess: () =>
            setStatus({ kind: 'success', message: 'Login rules updated' }),
          onError: (err) =>
            setStatus({
              kind: 'error',
              message: `Failed to save login rules: ${(err as Error).message}`,
            }),
        });
      }}
    >
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem' }}>
        {numField('Max attempts', 'max_attempts', 1)}
        {numField('Lockout time (s)', 'lockout_time', 0)}
        {numField('Rate window (s)', 'rate_limit_window', 1)}
        {numField('Rate limit max', 'rate_limit_max', 1)}
      </div>
      <div style={{ marginTop: '0.5rem' }}>
        <button
          type="submit"
          className="btn btn-primary"
          disabled={update.isPending}
        >
          {update.isPending ? 'Saving…' : 'Save Login Rules'}
        </button>
      </div>
      <ToastSlot message={status?.message ?? null} kind={status?.kind ?? 'success'} />
    </form>
  );
}

function AuthConfigForm({ groups }: { groups: AccessGroup[] }) {
  const query = useAuthConfig();
  const update = useUpdateAuthConfig();
  const credentials = useCredentialsList();
  const [draft, setDraft] = useState<AuthConfig | null>(null);
  const [status, setStatus] = useState<{ kind: 'success' | 'error'; message: string } | null>(null);

  useEffect(() => {
    if (query.data) setDraft(query.data);
  }, [query.data]);

  if (query.isLoading || !draft) return <p className="text-muted">Loading…</p>;
  if (query.isError)
    return (
      <div className="error">
        Failed to load auth config: {(query.error as Error).message}
      </div>
    );

  const radiusGroupSet = new Set(draft.radius.default_group_ids);

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        setStatus(null);
        if (draft.job_retention_days < 30) {
          setStatus({
            kind: 'error',
            message: 'Job retention must be at least 30 days',
          });
          return;
        }
        update.mutate(draft, {
          onSuccess: (saved) => {
            setDraft(saved);
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
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div className="form-group" style={{ flex: '1 1 200px' }}>
          <label className="form-label">Auth Provider</label>
          <select
            className="form-select"
            value={draft.provider}
            onChange={(e) => setDraft({ ...draft, provider: e.target.value })}
          >
            <option value="local">Local</option>
            <option value="radius">RADIUS</option>
            <option value="ldap">LDAP</option>
          </select>
        </div>
        <div className="form-group" style={{ flex: '1 1 200px' }}>
          <label className="form-label">Default Credential</label>
          <select
            className="form-select"
            value={draft.default_credential_id ?? ''}
            onChange={(e) =>
              setDraft({
                ...draft,
                default_credential_id: e.target.value ? Number(e.target.value) : null,
              })
            }
          >
            <option value="">— None —</option>
            {(credentials.data || []).map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
                {c.username ? ` (${c.username})` : ''}
              </option>
            ))}
          </select>
        </div>
        <div className="form-group" style={{ flex: '1 1 160px' }}>
          <label className="form-label">Job Retention (days)</label>
          <input
            type="number"
            className="form-input"
            min={30}
            value={draft.job_retention_days}
            onChange={(e) =>
              setDraft({ ...draft, job_retention_days: Number(e.target.value) })
            }
          />
        </div>
      </div>

      {draft.provider === 'radius' && (
        <RadiusPanel draft={draft} setDraft={setDraft} groups={groups} groupSet={radiusGroupSet} />
      )}
      {draft.provider === 'ldap' && (
        <LdapPanel draft={draft} setDraft={setDraft} />
      )}

      <div style={{ marginTop: '0.75rem' }}>
        <button
          type="submit"
          className="btn btn-primary"
          disabled={update.isPending}
        >
          {update.isPending ? 'Saving…' : 'Save Authentication'}
        </button>
      </div>
      <ToastSlot message={status?.message ?? null} kind={status?.kind ?? 'success'} />
    </form>
  );
}

function RadiusPanel({
  draft,
  setDraft,
  groups,
  groupSet,
}: {
  draft: AuthConfig;
  setDraft: (next: AuthConfig) => void;
  groups: AccessGroup[];
  groupSet: Set<number>;
}) {
  const r = draft.radius;
  const setR = (patch: Partial<typeof r>) =>
    setDraft({ ...draft, radius: { ...r, ...patch } });

  return (
    <fieldset
      style={{
        marginTop: '1rem',
        padding: '0.75rem',
        border: '1px solid var(--border)',
        borderRadius: '0.375rem',
      }}
    >
      <legend style={{ padding: '0 0.4rem' }}>RADIUS</legend>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem' }}>
        <CheckboxField
          label="Enabled"
          checked={r.enabled}
          onChange={(v) => setR({ enabled: v })}
        />
        <CheckboxField
          label="Fallback to local"
          checked={r.fallback_to_local}
          onChange={(v) => setR({ fallback_to_local: v })}
        />
        <CheckboxField
          label="Fallback on reject"
          checked={r.fallback_on_reject}
          onChange={(v) => setR({ fallback_on_reject: v })}
        />
      </div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem' }}>
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
      </div>
      <div className="form-group">
        <label className="form-label">Default Access Groups</label>
        {groups.length === 0 ? (
          <span className="card-description">Create access groups first.</span>
        ) : (
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
              gap: '0.4rem',
            }}
          >
            {groups.map((g) => (
              <label
                key={g.id}
                style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}
              >
                <input
                  type="checkbox"
                  checked={groupSet.has(g.id)}
                  onChange={(e) => {
                    const next = new Set(groupSet);
                    if (e.target.checked) next.add(g.id);
                    else next.delete(g.id);
                    setR({ default_group_ids: Array.from(next) });
                  }}
                />
                <span>{g.name}</span>
              </label>
            ))}
          </div>
        )}
      </div>
    </fieldset>
  );
}

function LdapPanel({
  draft,
  setDraft,
}: {
  draft: AuthConfig;
  setDraft: (next: AuthConfig) => void;
}) {
  const l = draft.ldap;
  const setL = (patch: Partial<typeof l>) =>
    setDraft({ ...draft, ldap: { ...l, ...patch } });

  return (
    <fieldset
      style={{
        marginTop: '1rem',
        padding: '0.75rem',
        border: '1px solid var(--border)',
        borderRadius: '0.375rem',
      }}
    >
      <legend style={{ padding: '0 0.4rem' }}>LDAP</legend>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem' }}>
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
          label="Fallback to local"
          checked={l.fallback_to_local}
          onChange={(v) => setL({ fallback_to_local: v })}
        />
        <CheckboxField
          label="Fallback on reject"
          checked={l.fallback_on_reject}
          onChange={(v) => setL({ fallback_on_reject: v })}
        />
      </div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem' }}>
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
      </div>
      <TextField
        label="Bind DN"
        value={l.bind_dn}
        onChange={(v) => setL({ bind_dn: v })}
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
      />
      <TextField
        label="User Search Filter"
        value={l.user_search_filter}
        onChange={(v) => setL({ user_search_filter: v })}
      />
      <TextField
        label="Admin Group DN"
        value={l.admin_group_dn}
        onChange={(v) => setL({ admin_group_dn: v })}
      />
    </fieldset>
  );
}

function CheckboxField({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <label
      className="form-group"
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.4rem',
        marginBottom: 0,
      }}
    >
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span>{label}</span>
    </label>
  );
}

function TextField({
  label,
  value,
  onChange,
  type = 'text',
  flex,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  type?: string;
  flex?: string;
}) {
  return (
    <div className="form-group" style={flex ? { flex } : undefined}>
      <label className="form-label">{label}</label>
      <input
        className="form-input"
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </div>
  );
}

function NumberField({
  label,
  value,
  onChange,
  min,
}: {
  label: string;
  value: number;
  onChange: (v: number) => void;
  min?: number;
}) {
  return (
    <div className="form-group" style={{ flex: '0 1 140px' }}>
      <label className="form-label">{label}</label>
      <input
        type="number"
        className="form-input"
        min={min}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
      />
    </div>
  );
}

export function AuthTab({ capabilities }: { capabilities: AdminCapabilities }) {
  const groups = useAccessGroups();

  return (
    <div>
      <SectionCard title="Login Rules">
        <LoginRulesForm />
      </SectionCard>
      <SectionCard
        title={`Authentication (providers: ${capabilities.auth_providers.join(', ')})`}
      >
        <AuthConfigForm groups={groups.data || []} />
      </SectionCard>
    </div>
  );
}
