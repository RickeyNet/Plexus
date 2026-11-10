import { FormEvent, useId, useState } from 'react';

import { Callout } from '@/components/Callout';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import { QueryError } from '@/components/QueryError';
import {
  type IpamSource,
  type IpamSourcePayload,
  useCreateIpamSource,
  useIpamProviders,
  useUpdateIpamSource,
} from '@/api/ipam';

import { type ConnectionFieldErrors, validateConnectionForm } from './helpers';

interface Props {
  source: IpamSource | null;
  onClose: () => void;
}

export function IpamSourceModal({ source, onClose }: Props) {
  const providers = useIpamProviders();
  const create = useCreateIpamSource();
  const update = useUpdateIpamSource();
  const formId = useId();
  const isEdit = source != null;

  const [provider, setProvider] = useState(source?.provider ?? '');
  const [name, setName] = useState(source?.name ?? '');
  const [baseUrl, setBaseUrl] = useState(source?.base_url ?? '');
  const [authType, setAuthType] = useState(source?.auth_type ?? 'token');
  const [token, setToken] = useState('');
  const [username, setUsername] = useState('');
  const [scope, setScope] = useState(source?.sync_scope ?? '');
  const [notes, setNotes] = useState(source?.notes ?? '');
  const [enabled, setEnabled] = useState(source?.enabled ?? true);
  const [pushEnabled, setPushEnabled] = useState(source?.push_enabled ?? false);
  const [verifyTls, setVerifyTls] = useState(source?.verify_tls !== false);

  const [errors, setErrors] = useState<ConnectionFieldErrors>({});
  const [saveError, setSaveError] = useState<string | null>(null);

  const isPending = create.isPending || update.isPending;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setSaveError(null);
    const fieldErrors = validateConnectionForm({ provider, name, baseUrl });
    setErrors(fieldErrors);
    if (Object.keys(fieldErrors).length) return;
    const auth_config: Record<string, string> = {};
    if (token) {
      if (authType === 'basic') {
        auth_config.username = username.trim();
        auth_config.password = token;
      } else {
        auth_config.token = token;
      }
    }
    const payload: IpamSourcePayload = {
      provider,
      name: name.trim(),
      base_url: baseUrl.trim(),
      auth_type: authType,
      auth_config,
      sync_scope: scope.trim(),
      notes: notes.trim(),
      enabled,
      push_enabled: pushEnabled,
      verify_tls: verifyTls,
    };
    try {
      if (isEdit && source) {
        await update.mutateAsync({ id: source.id, payload });
      } else {
        await create.mutateAsync(payload);
      }
      onClose();
    } catch (err) {
      setSaveError((err as Error).message);
    }
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={isEdit ? `Edit: ${source?.name}` : 'Add IPAM Source'}
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" form={formId} className="btn btn-primary" disabled={isPending}>
            {isPending ? 'Saving…' : isEdit ? 'Save Changes' : 'Add Source'}
          </button>
        </>
      }
    >
      <form id={formId} onSubmit={submit}>
        {saveError && <Callout tone="danger">{saveError}</Callout>}
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-provider`}>Provider</label>
          <select
            id={`${formId}-provider`}
            className="form-select"
            value={provider}
            onChange={(e) => {
              setProvider(e.target.value);
              setErrors((prev) => ({ ...prev, provider: undefined }));
            }}
            required
            aria-invalid={!!errors.provider}
          >
            <option value="">Select provider…</option>
            {(providers.data?.providers ?? []).map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
          <FieldError>{errors.provider}</FieldError>
          {providers.isError && !providers.data && (
            <QueryError what="IPAM providers" query={providers} />
          )}
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-name`}>Name</label>
          <input
            id={`${formId}-name`}
            className="form-input"
            value={name}
            onChange={(e) => {
              setName(e.target.value);
              setErrors((prev) => ({ ...prev, name: undefined }));
            }}
            maxLength={120}
            required
            aria-invalid={!!errors.name}
            placeholder="e.g. Production NetBox"
          />
          <FieldError>{errors.name}</FieldError>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-base-url`}>Base URL</label>
          <input
            id={`${formId}-base-url`}
            className="form-input"
            type="url"
            value={baseUrl}
            onChange={(e) => {
              setBaseUrl(e.target.value);
              setErrors((prev) => ({ ...prev, baseUrl: undefined }));
            }}
            required
            aria-invalid={!!errors.baseUrl}
            placeholder="https://netbox.example.com"
          />
          <FieldError>{errors.baseUrl}</FieldError>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-auth-type`}>Auth Type</label>
          <select
            id={`${formId}-auth-type`}
            className="form-select"
            value={authType}
            onChange={(e) => setAuthType(e.target.value)}
          >
            <option value="token">API Token</option>
            <option value="basic">Basic Auth</option>
          </select>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-api-token-password`}>API Token / Password</label>
          <input
            id={`${formId}-api-token-password`}
            className="form-input"
            type="password"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            maxLength={512}
            placeholder="Leave blank to keep existing"
          />
        </div>
        {authType === 'basic' && (
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-username`}>Username (Basic Auth)</label>
            <input
              id={`${formId}-username`}
              className="form-input"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              maxLength={120}
            />
          </div>
        )}
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-sync-scope`}>
            Sync Scope <span className="text-muted">(optional - site/tenant filter)</span>
          </label>
          <input
            id={`${formId}-sync-scope`}
            className="form-input"
            value={scope}
            onChange={(e) => setScope(e.target.value)}
            maxLength={255}
          />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-notes`}>Notes</label>
          <input
            id={`${formId}-notes`}
            className="form-input"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            maxLength={512}
          />
        </div>
        <div
          style={{
            display: 'flex',
            gap: '1.25rem',
            flexWrap: 'wrap',
            marginBottom: '1rem',
          }}
        >
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
            />{' '}
            Enabled
          </label>
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <input
              type="checkbox"
              checked={pushEnabled}
              onChange={(e) => setPushEnabled(e.target.checked)}
            />{' '}
            Push host updates
          </label>
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <input
              type="checkbox"
              checked={verifyTls}
              onChange={(e) => setVerifyTls(e.target.checked)}
            />{' '}
            Verify TLS
          </label>
        </div>
      </form>
    </Modal>
  );
}
