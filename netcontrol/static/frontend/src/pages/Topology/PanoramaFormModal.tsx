import { useState } from 'react';

import { Modal } from '@/components/Modal';
import {
  MerakiOrg,
  MerakiOrgInput,
  PanoramaBuildOptions,
  useCreateMerakiOrg,
  useUpdateMerakiOrg,
} from '@/api/meraki';

import { PANORAMA_OPTION_TOGGLES, PANORAMA_URL_PLACEHOLDER } from './merakiHelpers';

export interface PanoramaFormModalProps {
  existing: MerakiOrg | null;
  defaultOptions: PanoramaBuildOptions;
  onClose: () => void;
}

/**
 * Add or edit a Palo Alto Networks Panorama and the firewalls it manages.
 * Panorama is stored like a Cisco FMC: its address is the entry's base URL,
 * the device group its org_id, the optional user an option and the password
 * (or, without a user, the PAN-OS API key) the write-only secret.
 */
export function PanoramaFormModal({ existing, defaultOptions, onClose }: PanoramaFormModalProps) {
  const isEdit = existing !== null;
  const [name, setName] = useState(existing?.name ?? '');
  const [baseUrl, setBaseUrl] = useState(existing?.base_url ?? '');
  const [deviceGroup, setDeviceGroup] = useState(existing?.org_id ?? '');
  // The password / API key is write-only, so the field always opens blank;
  // leaving it blank on edit keeps the stored one.
  const [secret, setSecret] = useState('');
  // An entry saved before an option existed lacks its key; the defaults
  // fill it in so every toggle starts checked or unchecked, never blank.
  const [options, setOptions] = useState<PanoramaBuildOptions>({
    ...defaultOptions,
    ...(existing?.options as Partial<PanoramaBuildOptions> | undefined),
  });
  const [errMsg, setErrMsg] = useState<string | null>(null);

  const create = useCreateMerakiOrg();
  const update = useUpdateMerakiOrg();
  const pending = create.isPending || update.isPending;

  const submit = async () => {
    setErrMsg(null);
    const body: MerakiOrgInput = {
      name: name.trim(),
      provider: 'panorama',
      org_id: deviceGroup.trim(),
      base_url: baseUrl.trim(),
      options: { ...options, username: options.username.trim() },
    };
    if (secret.trim()) body.api_key = secret.trim();
    try {
      if (existing) await update.mutateAsync({ id: existing.id, body });
      else await create.mutateAsync(body);
      onClose();
    } catch (err) {
      setErrMsg(err instanceof Error ? err.message : String(err));
    }
  };

  const ready = name.trim() && baseUrl.trim() && (isEdit || secret.trim());

  return (
    <Modal isOpen onClose={onClose} title={isEdit ? 'Edit Palo Alto Panorama' : 'Add Palo Alto Panorama'} size="large">
      <div className="text-muted" style={{ fontSize: '0.85em', marginBottom: '0.75rem' }}>
        The Panorama that manages your Palo Alto Networks firewalls. Plexus reads device groups, templates,
        interfaces, routing, security and NAT rules, site-to-site VPN and GlobalProtect over the Panorama API
        (read-only).
      </div>
      <div className="form-group">
        <label className="form-label" htmlFor="panorama-name">
          Name <span style={{ color: 'var(--danger)' }}>*</span>
        </label>
        <input
          id="panorama-name"
          className="form-input"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Production Panorama"
        />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        <div className="form-group">
          <label className="form-label" htmlFor="panorama-url">
            Panorama address <span style={{ color: 'var(--danger)' }}>*</span>
          </label>
          <input
            id="panorama-url"
            className="form-input"
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder={PANORAMA_URL_PLACEHOLDER}
          />
          <div className="text-muted" style={{ fontSize: '0.85em', marginTop: '0.25rem' }}>
            https only, host (and port) without a path.
          </div>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="panorama-device-group">Device group</label>
          <input
            id="panorama-device-group"
            className="form-input"
            value={deviceGroup}
            onChange={(e) => setDeviceGroup(e.target.value)}
            placeholder="All device groups"
          />
          <div className="text-muted" style={{ fontSize: '0.85em', marginTop: '0.25rem' }}>
            Blank reads every device group; a name limits the collection to that device group and its children.
          </div>
        </div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        <div className="form-group">
          <label className="form-label" htmlFor="panorama-username">Username</label>
          <input
            id="panorama-username"
            className="form-input"
            value={options.username}
            onChange={(e) => setOptions({ ...options, username: e.target.value })}
            placeholder="plexus-readonly"
            autoComplete="off"
          />
          <div className="text-muted" style={{ fontSize: '0.85em', marginTop: '0.25rem' }}>
            Leave blank to sign in with an API key
          </div>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="panorama-secret">
            Password / API key {!isEdit && <span style={{ color: 'var(--danger)' }}>*</span>}
          </label>
          <input
            id="panorama-secret"
            className="form-input"
            type="password"
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
            placeholder={isEdit && existing?.has_api_key ? '(unchanged if empty)' : ''}
            autoComplete="new-password"
          />
        </div>
      </div>
      <div className="text-muted" style={{ fontSize: '0.85em', marginBottom: '0.75rem' }}>
        Use a dedicated Panorama administrator with a read-only role that allows XML API access. With a username,
        enter its password; without one, enter a PAN-OS API key. Plexus only reads, never commits or edits
        anything, and stores the secret encrypted; it is never shown again.
      </div>

      <h4 style={{ margin: '0.75rem 0 0.5rem' }}>Scope</h4>
      <div className="form-group">
        <label className="form-label" htmlFor="panorama-name-filter">Only devices whose name contains</label>
        <input
          id="panorama-name-filter"
          className="form-input"
          value={options.device_name_contains}
          onChange={(e) => setOptions({ ...options, device_name_contains: e.target.value })}
          placeholder="All devices"
        />
      </div>

      <h4 style={{ margin: '0.75rem 0 0.5rem' }}>Data to collect</h4>
      {PANORAMA_OPTION_TOGGLES.map((toggle) => (
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
          {isEdit ? 'Save' : 'Add Panorama'}
        </button>
        <button type="button" className="btn btn-ghost" onClick={onClose}>
          Cancel
        </button>
      </div>
    </Modal>
  );
}
