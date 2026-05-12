import { FormEvent, useState } from 'react';

import { Modal } from '@/components/Modal';
import {
  type SnmpProfile,
  useCreateSnmpProfile,
  useDeleteSnmpProfile,
  useSnmpProfiles,
  useUpdateSnmpProfile,
} from '@/api/inventory';

interface Props {
  onClose: () => void;
}

type View =
  | { mode: 'list' }
  | { mode: 'create' }
  | { mode: 'edit'; profile: SnmpProfile };

export function SnmpProfilesModal({ onClose }: Props) {
  const profiles = useSnmpProfiles();
  const remove = useDeleteSnmpProfile();
  const [view, setView] = useState<View>({ mode: 'list' });

  if (view.mode !== 'list') {
    return (
      <SnmpProfileFormModal
        profile={view.mode === 'edit' ? view.profile : null}
        onBack={() => setView({ mode: 'list' })}
        onClose={onClose}
      />
    );
  }

  const list = profiles.data ?? [];

  return (
    <Modal isOpen onClose={onClose} title="SNMP Profiles" size="large">
      <div style={{ maxHeight: 360, overflow: 'auto', marginBottom: '0.75rem' }}>
        {profiles.isPending ? (
          <p className="text-muted">Loading…</p>
        ) : list.length === 0 ? (
          <p className="text-muted">
            No SNMP profiles configured. Create one to get started.
          </p>
        ) : (
          list.map((p) => (
            <div
              key={p.id}
              className="card"
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginBottom: '0.4rem',
                padding: '0.5rem 0.75rem',
              }}
            >
              <div>
                <strong>{p.name}</strong>
                <span style={{ marginLeft: '0.5rem', opacity: 0.7 }}>
                  SNMPv{p.version}
                  {p.version === '2c'
                    ? ` / ${p.community || 'public'}`
                    : ` / ${p.v3?.username || ''}`}
                </span>
                <span style={{ marginLeft: '0.5rem', opacity: 0.6 }}>
                  {p.enabled ? 'Enabled' : 'Disabled'}
                </span>
              </div>
              <div style={{ display: 'flex', gap: '0.25rem' }}>
                <button
                  type="button"
                  className="btn btn-sm btn-secondary"
                  onClick={() => setView({ mode: 'edit', profile: p })}
                >
                  Edit
                </button>
                <button
                  type="button"
                  className="btn btn-sm btn-danger"
                  onClick={() => {
                    if (
                      !confirm(
                        `Delete SNMP profile "${p.name}"? Any groups using it will be unassigned.`,
                      )
                    )
                      return;
                    remove.mutate(p.id, {
                      onError: (e) => alert((e as Error).message),
                    });
                  }}
                >
                  Delete
                </button>
              </div>
            </div>
          ))
        )}
      </div>
      <div
        style={{
          display: 'flex',
          justifyContent: 'flex-end',
          gap: '0.5rem',
        }}
      >
        <button type="button" className="btn btn-secondary" onClick={onClose}>
          Close
        </button>
        <button
          type="button"
          className="btn btn-primary"
          onClick={() => setView({ mode: 'create' })}
        >
          + New Profile
        </button>
      </div>
    </Modal>
  );
}

interface FormProps {
  profile: SnmpProfile | null;
  onBack: () => void;
  onClose: () => void;
}

function SnmpProfileFormModal({ profile, onBack, onClose }: FormProps) {
  const create = useCreateSnmpProfile();
  const update = useUpdateSnmpProfile();
  const isEdit = profile != null;

  const [name, setName] = useState(profile?.name ?? '');
  const [enabled, setEnabled] = useState(profile?.enabled ?? true);
  const [version, setVersion] = useState<string>(profile?.version ?? '2c');
  const [community, setCommunity] = useState(profile?.community ?? '');
  const [port, setPort] = useState<number>(profile?.port ?? 161);
  const [retries, setRetries] = useState<number>(profile?.retries ?? 0);
  const [timeoutSeconds, setTimeoutSeconds] = useState<number>(
    profile?.timeout_seconds ?? 1.2,
  );
  const [enableInferred, setEnableInferred] = useState<boolean>(
    profile?.enable_inferred_topology ?? false,
  );
  const v3 = profile?.v3 ?? {};
  const [v3Username, setV3Username] = useState(v3.username ?? '');
  const [v3AuthProtocol, setV3AuthProtocol] = useState(v3.auth_protocol ?? 'sha');
  const [v3AuthPassword, setV3AuthPassword] = useState(v3.auth_password ?? '');
  const [v3PrivProtocol, setV3PrivProtocol] = useState(v3.priv_protocol ?? 'aes128');
  const [v3PrivPassword, setV3PrivPassword] = useState(v3.priv_password ?? '');

  const isPending = create.isPending || update.isPending;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const trimmed = name.trim();
    if (!trimmed) {
      alert('Profile name is required.');
      return;
    }
    const payload = {
      name: trimmed,
      enabled,
      version,
      community: community.trim(),
      port,
      retries,
      timeout_seconds: timeoutSeconds,
      enable_inferred_topology: enableInferred,
      v3: {
        username: v3Username.trim(),
        auth_protocol: v3AuthProtocol,
        auth_password: v3AuthPassword,
        priv_protocol: v3PrivProtocol,
        priv_password: v3PrivPassword,
      },
    };
    try {
      if (isEdit && profile) {
        await update.mutateAsync({ id: profile.id, payload });
      } else {
        await create.mutateAsync(payload);
      }
      onBack();
    } catch (err) {
      alert((err as Error).message);
    }
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={isEdit ? `Edit SNMP Profile: ${profile?.name}` : 'New SNMP Profile'}
      size="large"
    >
      <form onSubmit={submit}>
        <div className="form-group">
          <label className="form-label">Profile Name</label>
          <input
            className="form-input"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
            placeholder="e.g. Lab Switches"
          />
        </div>
        <label
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
            marginBottom: '0.75rem',
          }}
        >
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
          />{' '}
          Enabled
        </label>
        <div
          className="form-group"
          style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr 1fr',
            gap: '0.75rem',
          }}
        >
          <div>
            <label className="form-label">Version</label>
            <select
              className="form-select"
              value={version}
              onChange={(e) => setVersion(e.target.value)}
            >
              <option value="2c">SNMPv2c</option>
              <option value="3">SNMPv3</option>
            </select>
          </div>
          <div>
            <label className="form-label">Port</label>
            <input
              className="form-input"
              type="number"
              min={1}
              max={65535}
              value={port}
              onChange={(e) => setPort(Number(e.target.value || 161))}
            />
          </div>
          <div>
            <label className="form-label">Retries</label>
            <input
              className="form-input"
              type="number"
              min={0}
              max={5}
              value={retries}
              onChange={(e) => setRetries(Number(e.target.value || 0))}
            />
          </div>
        </div>
        <div className="form-group">
          <label className="form-label">Community (v2c)</label>
          <input
            className="form-input"
            value={community}
            onChange={(e) => setCommunity(e.target.value)}
          />
        </div>
        <div className="form-group">
          <label className="form-label">Timeout Seconds</label>
          <input
            className="form-input"
            type="number"
            min={0.2}
            max={10}
            step={0.1}
            value={timeoutSeconds}
            onChange={(e) =>
              setTimeoutSeconds(Number(e.target.value || 1.2))
            }
          />
        </div>
        <label
          style={{
            display: 'flex',
            alignItems: 'flex-start',
            gap: '0.4rem',
            marginBottom: '0.75rem',
          }}
        >
          <input
            type="checkbox"
            checked={enableInferred}
            onChange={(e) => setEnableInferred(e.target.checked)}
            style={{ marginTop: '0.2rem' }}
          />
          <span>
            Enable inferred topology (FDB+ARP)
            <span
              style={{
                display: 'block',
                fontSize: '0.75rem',
                opacity: 0.7,
              }}
            >
              Adds dashed edges between devices when CDP/LLDP is unavailable.
              Walks FDB and ARP tables - extra SNMP cost on busy switches.
            </span>
          </span>
        </label>
        <div className="card-description" style={{ marginBottom: '0.5rem' }}>
          SNMPv3 Credentials
        </div>
        <div
          className="form-group"
          style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: '0.75rem',
          }}
        >
          <div>
            <label className="form-label">Username</label>
            <input
              className="form-input"
              value={v3Username}
              onChange={(e) => setV3Username(e.target.value)}
            />
          </div>
          <div>
            <label className="form-label">Auth Protocol</label>
            <select
              className="form-select"
              value={v3AuthProtocol}
              onChange={(e) => setV3AuthProtocol(e.target.value)}
            >
              <option value="sha">SHA</option>
              <option value="sha256">SHA-256</option>
              <option value="sha512">SHA-512</option>
              <option value="md5">MD5</option>
            </select>
          </div>
        </div>
        <div
          className="form-group"
          style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: '0.75rem',
          }}
        >
          <div>
            <label className="form-label">Auth Password</label>
            <input
              className="form-input"
              type={v3AuthPassword.includes('{{secret.') ? 'text' : 'password'}
              value={v3AuthPassword}
              onChange={(e) => setV3AuthPassword(e.target.value)}
              placeholder="password or {{secret.NAME}}"
            />
          </div>
          <div>
            <label className="form-label">Privacy Protocol</label>
            <select
              className="form-select"
              value={v3PrivProtocol}
              onChange={(e) => setV3PrivProtocol(e.target.value)}
            >
              <option value="aes128">AES128</option>
              <option value="aes192">AES192</option>
              <option value="aes256">AES256</option>
              <option value="des">DES</option>
            </select>
          </div>
        </div>
        <div className="form-group">
          <label className="form-label">Privacy Password</label>
          <input
            className="form-input"
            type={v3PrivPassword.includes('{{secret.') ? 'text' : 'password'}
            value={v3PrivPassword}
            onChange={(e) => setV3PrivPassword(e.target.value)}
            placeholder="password or {{secret.NAME}}"
          />
        </div>
        <div
          className="card-description"
          style={{ fontSize: '0.8rem', opacity: 0.7, marginTop: '-0.5rem' }}
        >
          Passwords support <code>{'{{secret.NAME}}'}</code> references from
          Settings → Credentials → Secret Variables.
        </div>
        <div
          style={{
            display: 'flex',
            gap: '0.5rem',
            justifyContent: 'flex-end',
            marginTop: '1rem',
          }}
        >
          <button type="button" className="btn btn-secondary" onClick={onBack}>
            Back
          </button>
          <button type="submit" className="btn btn-primary" disabled={isPending}>
            {isPending ? 'Saving…' : isEdit ? 'Save Profile' : 'Create Profile'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
