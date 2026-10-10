import { useState } from 'react';

import { Modal } from '@/components/Modal';
import {
  AppgateBuildOptions,
  MerakiOrg,
  MerakiOrgInput,
  useCreateMerakiOrg,
  useUpdateMerakiOrg,
} from '@/api/meraki';

import { APPGATE_OPTION_TOGGLES, APPGATE_URL_PLACEHOLDER } from './merakiHelpers';

export interface AppgateFormModalProps {
  existing: MerakiOrg | null;
  defaultOptions: AppgateBuildOptions;
  onClose: () => void;
}

/**
 * Add or edit an Appgate SDP collective, read through the admin API of one of
 * its Controllers. Stored like a Palo Alto Panorama: the Controller address is
 * the entry's base URL, the identity provider of the admin login its org_id,
 * the user an option and the password the write-only secret.
 */
export function AppgateFormModal({ existing, defaultOptions, onClose }: AppgateFormModalProps) {
  const isEdit = existing !== null;
  const [name, setName] = useState(existing?.name ?? '');
  const [baseUrl, setBaseUrl] = useState(existing?.base_url ?? '');
  const [identityProvider, setIdentityProvider] = useState(existing?.org_id || 'local');
  // The password is write-only, so the field always opens blank; leaving it
  // blank on edit keeps the stored one.
  const [password, setPassword] = useState('');
  // An entry saved before an option existed lacks its key; the defaults
  // fill it in so every toggle starts checked or unchecked, never blank.
  const [options, setOptions] = useState<AppgateBuildOptions>({
    ...defaultOptions,
    ...(existing?.options as Partial<AppgateBuildOptions> | undefined),
  });
  const [errMsg, setErrMsg] = useState<string | null>(null);

  const create = useCreateMerakiOrg();
  const update = useUpdateMerakiOrg();
  const pending = create.isPending || update.isPending;

  const submit = async () => {
    setErrMsg(null);
    const body: MerakiOrgInput = {
      name: name.trim(),
      provider: 'appgate',
      org_id: identityProvider.trim() || 'local',
      base_url: baseUrl.trim(),
      options: { ...options, username: options.username.trim() },
    };
    if (password.trim()) body.api_key = password.trim();
    try {
      if (existing) await update.mutateAsync({ id: existing.id, body });
      else await create.mutateAsync(body);
      onClose();
    } catch (err) {
      setErrMsg(err instanceof Error ? err.message : String(err));
    }
  };

  const ready = name.trim() && baseUrl.trim() && options.username.trim() && (isEdit || password.trim());

  return (
    <Modal isOpen onClose={onClose} title={isEdit ? 'Edit Appgate SDP' : 'Add Appgate SDP'} size="large">
      <div className="text-muted" style={{ fontSize: '0.85em', marginBottom: '0.75rem' }}>
        An Appgate SDP collective. Plexus reads Controllers, Gateways and the other appliances, sites, policies,
        entitlements, IP pools and the users connected right now over the Controller admin API (read-only).
      </div>
      <div className="form-group">
        <label className="form-label" htmlFor="appgate-name">
          Name <span style={{ color: 'var(--danger)' }}>*</span>
        </label>
        <input
          id="appgate-name"
          className="form-input"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Acme Appgate SDP"
        />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        <div className="form-group">
          <label className="form-label" htmlFor="appgate-base-url">
            Controller address <span style={{ color: 'var(--danger)' }}>*</span>
          </label>
          <input
            id="appgate-base-url"
            className="form-input"
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder={APPGATE_URL_PLACEHOLDER}
          />
          <div className="text-muted" style={{ fontSize: '0.85em', marginTop: '0.25rem' }}>
            Admin interface of a Controller; <code>/admin</code> is added by Plexus
          </div>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="appgate-provider">Identity provider</label>
          <input
            id="appgate-provider"
            className="form-input"
            value={identityProvider}
            onChange={(e) => setIdentityProvider(e.target.value)}
            placeholder="local"
          />
          <div className="text-muted" style={{ fontSize: '0.85em', marginTop: '0.25rem' }}>
            The identity provider the admin user signs in with
          </div>
        </div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        <div className="form-group">
          <label className="form-label" htmlFor="appgate-username">
            Username <span style={{ color: 'var(--danger)' }}>*</span>
          </label>
          <input
            id="appgate-username"
            className="form-input"
            value={options.username}
            onChange={(e) => setOptions({ ...options, username: e.target.value })}
            placeholder="plexus-readonly"
            autoComplete="off"
          />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="appgate-password">
            Password {!isEdit && <span style={{ color: 'var(--danger)' }}>*</span>}
          </label>
          <input
            id="appgate-password"
            className="form-input"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder={isEdit && existing?.has_api_key ? '(unchanged if empty)' : ''}
            autoComplete="new-password"
          />
          <div className="text-muted" style={{ fontSize: '0.85em', marginTop: '0.25rem' }}>
            MFA must be disabled for this API user
          </div>
        </div>
      </div>
      <div className="form-group" style={{ marginBottom: '0.4rem' }}>
        <label style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem' }}>
          <input
            type="checkbox"
            checked={options.verify_tls}
            onChange={(e) => setOptions({ ...options, verify_tls: e.target.checked })}
            style={{ marginTop: '0.2rem' }}
          />
          <span>
            Verify the Controller certificate
            <span className="text-muted" style={{ display: 'block', fontSize: '0.85em' }}>
              Turn off only for a Controller with a self-signed certificate.
            </span>
          </span>
        </label>
      </div>
      <div className="text-muted" style={{ fontSize: '0.85em', marginBottom: '0.75rem' }}>
        Use a dedicated admin user with a read-only admin role. Plexus only reads, never changes anything, and stores
        the password encrypted; it is never shown again.
      </div>

      <h4 style={{ margin: '0.75rem 0 0.5rem' }}>Scope</h4>
      <div className="form-group">
        <label className="form-label" htmlFor="appgate-name-filter">Only sites named like</label>
        <input
          id="appgate-name-filter"
          className="form-input"
          value={options.site_name_contains}
          onChange={(e) => setOptions({ ...options, site_name_contains: e.target.value })}
          placeholder="All sites"
        />
      </div>

      <h4 style={{ margin: '0.75rem 0 0.5rem' }}>Data to collect</h4>
      {APPGATE_OPTION_TOGGLES.map((toggle) => (
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
        <button type="button" className="btn btn-primary" disabled={!ready || pending} onClick={submit}>
          {isEdit ? 'Save' : 'Add Appgate'}
        </button>
        <button type="button" className="btn btn-ghost" onClick={onClose}>
          Cancel
        </button>
      </div>
    </Modal>
  );
}
