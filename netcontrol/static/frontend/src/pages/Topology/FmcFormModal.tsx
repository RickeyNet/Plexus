import { useState } from 'react';

import { Modal } from '@/components/Modal';
import {
  FmcBuildOptions,
  MerakiOrg,
  MerakiOrgInput,
  useCreateMerakiOrg,
  useUpdateMerakiOrg,
} from '@/api/meraki';

import { FMC_OPTION_TOGGLES, FMC_URL_PLACEHOLDER } from './merakiHelpers';

export interface FmcFormModalProps {
  existing: MerakiOrg | null;
  defaultOptions: FmcBuildOptions;
  onClose: () => void;
}

/**
 * Add or edit a Cisco FMC (Secure Firewall Management Center) and the FTDs
 * it manages. The FMC is stored like a Cato account: its address is the
 * entry's base URL, the domain its org_id, the API user an option and the
 * password the write-only secret.
 */
export function FmcFormModal({ existing, defaultOptions, onClose }: FmcFormModalProps) {
  const isEdit = existing !== null;
  const [name, setName] = useState(existing?.name ?? '');
  const [baseUrl, setBaseUrl] = useState(existing?.base_url ?? '');
  const [domain, setDomain] = useState(existing?.org_id ?? '');
  // The password is write-only, so the field always opens blank; leaving it
  // blank on edit keeps the stored one.
  const [password, setPassword] = useState('');
  // An entry saved before an option existed lacks its key; the defaults
  // fill it in so every toggle starts checked or unchecked, never blank.
  const [options, setOptions] = useState<FmcBuildOptions>({
    ...defaultOptions,
    ...(existing?.options as Partial<FmcBuildOptions> | undefined),
  });
  const [errMsg, setErrMsg] = useState<string | null>(null);

  const create = useCreateMerakiOrg();
  const update = useUpdateMerakiOrg();
  const pending = create.isPending || update.isPending;

  const submit = async () => {
    setErrMsg(null);
    const body: MerakiOrgInput = {
      name: name.trim(),
      provider: 'fmc',
      org_id: domain.trim(),
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
    <Modal isOpen onClose={onClose} title={isEdit ? 'Edit Cisco FMC' : 'Add Cisco FMC'} size="large">
      <div className="text-muted" style={{ fontSize: '0.85em', marginBottom: '0.75rem' }}>
        The Firewall Management Center that manages your FTDs. Plexus reads devices, interfaces, routing, NAT,
        access control, site-to-site and remote access VPN over the FMC REST API (read-only).
      </div>
      <div className="form-group">
        <label className="form-label" htmlFor="fmc-name">
          Name <span style={{ color: 'var(--danger)' }}>*</span>
        </label>
        <input
          id="fmc-name"
          className="form-input"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Production FMC"
        />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        <div className="form-group">
          <label className="form-label" htmlFor="fmc-url">
            FMC address <span style={{ color: 'var(--danger)' }}>*</span>
          </label>
          <input
            id="fmc-url"
            className="form-input"
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder={FMC_URL_PLACEHOLDER}
          />
          <div className="text-muted" style={{ fontSize: '0.85em', marginTop: '0.25rem' }}>
            https only, host (and port) without a path.
          </div>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="fmc-domain">Domain</label>
          <input
            id="fmc-domain"
            className="form-input"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="Global"
          />
          <div className="text-muted" style={{ fontSize: '0.85em', marginTop: '0.25rem' }}>
            A domain name (Global/Branch) or UUID. Blank reads the Global domain.
          </div>
        </div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        <div className="form-group">
          <label className="form-label" htmlFor="fmc-username">
            API username <span style={{ color: 'var(--danger)' }}>*</span>
          </label>
          <input
            id="fmc-username"
            className="form-input"
            value={options.username}
            onChange={(e) => setOptions({ ...options, username: e.target.value })}
            placeholder="plexus-readonly"
            autoComplete="off"
          />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="fmc-password">
            Password {!isEdit && <span style={{ color: 'var(--danger)' }}>*</span>}
          </label>
          <input
            id="fmc-password"
            className="form-input"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder={isEdit && existing?.has_api_key ? '(unchanged if empty)' : ''}
            autoComplete="new-password"
          />
        </div>
      </div>
      <div className="text-muted" style={{ fontSize: '0.85em', marginBottom: '0.75rem' }}>
        Use a dedicated FMC user whose role allows REST API access. Plexus only sends GET requests, never
        deploys or edits anything, and stores the password encrypted; it is never shown again. An FMC allows
        about 120 API requests per minute per user, so give this user to Plexus alone.
      </div>

      <h4 style={{ margin: '0.75rem 0 0.5rem' }}>Scope</h4>
      <div className="form-group">
        <label className="form-label" htmlFor="fmc-name-filter">Only devices named like</label>
        <input
          id="fmc-name-filter"
          className="form-input"
          value={options.device_name_contains}
          onChange={(e) => setOptions({ ...options, device_name_contains: e.target.value })}
          placeholder="All devices"
        />
      </div>

      <h4 style={{ margin: '0.75rem 0 0.5rem' }}>Data to collect</h4>
      {FMC_OPTION_TOGGLES.map((toggle) => (
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
          {isEdit ? 'Save' : 'Add FMC'}
        </button>
        <button type="button" className="btn btn-ghost" onClick={onClose}>
          Cancel
        </button>
      </div>
    </Modal>
  );
}
