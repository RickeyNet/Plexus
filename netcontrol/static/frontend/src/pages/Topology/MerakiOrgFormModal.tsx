import { useState } from 'react';

import { Modal } from '@/components/Modal';
import {
  MerakiBuildOptions,
  MerakiOrg,
  MerakiOrgInput,
  useCreateMerakiOrg,
  useUpdateMerakiOrg,
} from '@/api/meraki';

import { DEFAULT_BASE_URL, OPTION_TOGGLES } from './merakiHelpers';

export interface MerakiOrgFormModalProps {
  existing: MerakiOrg | null;
  defaultOptions: MerakiBuildOptions;
  onClose: () => void;
}

export function MerakiOrgFormModal({ existing, defaultOptions, onClose }: MerakiOrgFormModalProps) {
  const isEdit = existing !== null;
  const [name, setName] = useState(existing?.name ?? '');
  const [orgId, setOrgId] = useState(existing?.org_id ?? '');
  const [baseUrl, setBaseUrl] = useState(existing?.base_url ?? DEFAULT_BASE_URL);
  // The key is write-only, so the field always opens blank; leaving it blank
  // on edit keeps the stored key.
  const [apiKey, setApiKey] = useState('');
  // This form only ever opens for a Meraki organization.
  const initialOptions = (existing?.options as MerakiBuildOptions | undefined) ?? defaultOptions;
  const [options, setOptions] = useState<MerakiBuildOptions>(initialOptions);
  const [tags, setTags] = useState(initialOptions.network_tags.join(', '));
  const [errMsg, setErrMsg] = useState<string | null>(null);

  const create = useCreateMerakiOrg();
  const update = useUpdateMerakiOrg();
  const pending = create.isPending || update.isPending;

  const submit = async () => {
    setErrMsg(null);
    const body: MerakiOrgInput = {
      name: name.trim(),
      org_id: orgId.trim(),
      base_url: baseUrl.trim(),
      options: {
        ...options,
        network_tags: tags.split(',').map((t) => t.trim()).filter(Boolean),
      },
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
    <Modal
      isOpen
      onClose={onClose}
      title={isEdit ? 'Edit Meraki Organization' : 'Add Meraki Organization'}
      size="large"
    >
      <div className="form-group">
        <label className="form-label" htmlFor="meraki-name">
          Name <span style={{ color: 'var(--danger)' }}>*</span>
        </label>
        <input
          id="meraki-name"
          className="form-input"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Acme Corp"
        />
      </div>
      <div className="form-group">
        <label className="form-label" htmlFor="meraki-key">
          Dashboard API key {!isEdit && <span style={{ color: 'var(--danger)' }}>*</span>}
        </label>
        <input
          id="meraki-key"
          className="form-input"
          type="password"
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
          placeholder={isEdit && existing?.has_api_key ? '(unchanged if empty)' : ''}
          autoComplete="new-password"
        />
        <div className="text-muted" style={{ fontSize: '0.85em', marginTop: '0.25rem' }}>
          A read-only organization admin key is sufficient. Plexus only issues GET requests and
          stores the key encrypted; it is never shown again.
        </div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        <div className="form-group">
          <label className="form-label" htmlFor="meraki-org-id">Organization ID</label>
          <input
            id="meraki-org-id"
            className="form-input"
            value={orgId}
            onChange={(e) => setOrgId(e.target.value)}
            placeholder="Auto-detect if the key sees one organization"
          />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="meraki-base-url">API base URL</label>
          <input
            id="meraki-base-url"
            className="form-input"
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder={DEFAULT_BASE_URL}
          />
        </div>
      </div>

      <h4 style={{ margin: '0.75rem 0 0.5rem' }}>Scope</h4>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        <div className="form-group">
          <label className="form-label" htmlFor="meraki-tags">Only networks tagged</label>
          <input
            id="meraki-tags"
            className="form-input"
            value={tags}
            onChange={(e) => setTags(e.target.value)}
            placeholder="All networks (comma-separated tags to limit)"
          />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="meraki-name-filter">Only networks named like</label>
          <input
            id="meraki-name-filter"
            className="form-input"
            value={options.network_name_contains}
            onChange={(e) => setOptions({ ...options, network_name_contains: e.target.value })}
            placeholder="All networks"
          />
        </div>
      </div>

      <h4 style={{ margin: '0.75rem 0 0.5rem' }}>Data to collect</h4>
      {OPTION_TOGGLES.map((toggle) => (
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

      <div className="form-group" style={{ maxWidth: 260 }}>
        <label className="form-label" htmlFor="meraki-rps">API requests per second (1-10)</label>
        <input
          id="meraki-rps"
          className="form-input"
          type="number"
          min={1}
          max={10}
          value={options.requests_per_second}
          onChange={(e) => setOptions({ ...options, requests_per_second: Number(e.target.value) || 1 })}
        />
      </div>

      {errMsg && (
        <div className="error">
          <strong>{isEdit ? 'Update failed' : 'Create failed'}:</strong> {errMsg}
        </div>
      )}

      <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end', marginTop: '1rem' }}>
        <button
          type="button"
          className="btn btn-primary"
          disabled={!name.trim() || (!isEdit && !apiKey.trim()) || pending}
          onClick={submit}
        >
          {isEdit ? 'Save' : 'Add Organization'}
        </button>
        <button type="button" className="btn btn-ghost" onClick={onClose}>
          Cancel
        </button>
      </div>
    </Modal>
  );
}
