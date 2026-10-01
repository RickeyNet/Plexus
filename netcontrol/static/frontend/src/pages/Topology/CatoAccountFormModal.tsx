import { useState } from 'react';

import { Modal } from '@/components/Modal';
import {
  CatoBuildOptions,
  MerakiOrg,
  MerakiOrgInput,
  useCreateMerakiOrg,
  useUpdateMerakiOrg,
} from '@/api/meraki';

import { CATO_BASE_URL, CATO_OPTION_TOGGLES } from './merakiHelpers';

export interface CatoAccountFormModalProps {
  existing: MerakiOrg | null;
  defaultOptions: CatoBuildOptions;
  onClose: () => void;
}

export function CatoAccountFormModal({ existing, defaultOptions, onClose }: CatoAccountFormModalProps) {
  const isEdit = existing !== null;
  const [name, setName] = useState(existing?.name ?? '');
  const [accountId, setAccountId] = useState(existing?.org_id ?? '');
  const [baseUrl, setBaseUrl] = useState(existing?.base_url ?? CATO_BASE_URL);
  // The key is write-only, so the field always opens blank; leaving it blank
  // on edit keeps the stored key.
  const [apiKey, setApiKey] = useState('');
  const [options, setOptions] = useState<CatoBuildOptions>(
    (existing?.options as CatoBuildOptions | undefined) ?? defaultOptions,
  );
  const [errMsg, setErrMsg] = useState<string | null>(null);

  const create = useCreateMerakiOrg();
  const update = useUpdateMerakiOrg();
  const pending = create.isPending || update.isPending;

  const submit = async () => {
    setErrMsg(null);
    const body: MerakiOrgInput = {
      name: name.trim(),
      provider: 'cato',
      org_id: accountId.trim(),
      base_url: baseUrl.trim(),
      options,
    };
    if (apiKey.trim()) body.api_key = apiKey.trim();
    try {
      if (existing) await update.mutateAsync({ id: existing.id, body });
      else await create.mutateAsync(body);
      onClose();
    } catch (err) {
      setErrMsg(err instanceof Error ? err.message : String(err));
    }
  };

  return (
    <Modal isOpen onClose={onClose} title={isEdit ? 'Edit Cato Account' : 'Add Cato Account'} size="large">
      <div className="form-group">
        <label className="form-label" htmlFor="cato-name">
          Name <span style={{ color: 'var(--danger)' }}>*</span>
        </label>
        <input
          id="cato-name"
          className="form-input"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Acme Corp Cato"
        />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        <div className="form-group">
          <label className="form-label" htmlFor="cato-account-id">
            Account ID <span style={{ color: 'var(--danger)' }}>*</span>
          </label>
          <input
            id="cato-account-id"
            className="form-input"
            value={accountId}
            onChange={(e) => setAccountId(e.target.value)}
            placeholder="The number in the Cato Management Application URL"
          />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="cato-key">
            API key {!isEdit && <span style={{ color: 'var(--danger)' }}>*</span>}
          </label>
          <input
            id="cato-key"
            className="form-input"
            type="password"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            placeholder={isEdit && existing?.has_api_key ? '(unchanged if empty)' : ''}
            autoComplete="new-password"
          />
        </div>
      </div>
      <div className="text-muted" style={{ fontSize: '0.85em', marginBottom: '0.75rem' }}>
        A key with View permission is sufficient. Plexus only sends read queries and stores the key
        encrypted; it is never shown again.
      </div>
      <div className="form-group">
        <label className="form-label" htmlFor="cato-base-url">API URL</label>
        <input
          id="cato-base-url"
          className="form-input"
          value={baseUrl}
          onChange={(e) => setBaseUrl(e.target.value)}
          placeholder={CATO_BASE_URL}
        />
        <div className="text-muted" style={{ fontSize: '0.85em', marginTop: '0.25rem' }}>
          Change this only if your account is on a regional Cato API host (for example
          api.us1.catonetworks.com).
        </div>
      </div>

      <h4 style={{ margin: '0.75rem 0 0.5rem' }}>Scope</h4>
      <div className="form-group">
        <label className="form-label" htmlFor="cato-name-filter">Only sites named like</label>
        <input
          id="cato-name-filter"
          className="form-input"
          value={options.site_name_contains}
          onChange={(e) => setOptions({ ...options, site_name_contains: e.target.value })}
          placeholder="All sites"
        />
      </div>

      <h4 style={{ margin: '0.75rem 0 0.5rem' }}>Data to collect</h4>
      {CATO_OPTION_TOGGLES.map((toggle) => (
        <div className="form-group" key={toggle.key} style={{ marginBottom: '0.4rem' }}>
          <label style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem' }}>
            <input
              type="checkbox"
              checked={options[toggle.key]}
              onChange={(e) => setOptions({ ...options, [toggle.key]: e.target.checked })}
              style={{ marginTop: '0.2rem' }}
            />
            <span>
              {toggle.label}
              <span className="text-muted" style={{ display: 'block', fontSize: '0.85em' }}>
                {toggle.hint}
              </span>
            </span>
          </label>
        </div>
      ))}

      {errMsg && (
        <div className="error">
          <strong>{isEdit ? 'Update failed' : 'Create failed'}:</strong> {errMsg}
        </div>
      )}

      <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end', marginTop: '1rem' }}>
        <button
          type="button"
          className="btn btn-primary"
          disabled={!name.trim() || !accountId.trim() || (!isEdit && !apiKey.trim()) || pending}
          onClick={submit}
        >
          {isEdit ? 'Save' : 'Add Account'}
        </button>
        <button type="button" className="btn btn-ghost" onClick={onClose}>
          Cancel
        </button>
      </div>
    </Modal>
  );
}
