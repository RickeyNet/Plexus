import { FormEvent, useState } from 'react';

import { Modal } from '@/components/Modal';
import {
  type DhcpServer,
  type DhcpServerPayload,
  useCreateDhcpServer,
  useDhcpProviders,
  useUpdateDhcpServer,
} from '@/api/ipam';

interface Props {
  server: DhcpServer | null;
  onClose: () => void;
}

export function DhcpServerModal({ server, onClose }: Props) {
  const providers = useDhcpProviders();
  const create = useCreateDhcpServer();
  const update = useUpdateDhcpServer();
  const isEdit = server != null;

  const [provider, setProvider] = useState(server?.provider ?? '');
  const [name, setName] = useState(server?.name ?? '');
  const [baseUrl, setBaseUrl] = useState(server?.base_url ?? '');
  const [authType, setAuthType] = useState(server?.auth_type ?? 'none');
  const [token, setToken] = useState('');
  const [username, setUsername] = useState('');
  const [notes, setNotes] = useState(server?.notes ?? '');
  const [enabled, setEnabled] = useState(server?.enabled ?? true);
  const [verifyTls, setVerifyTls] = useState(server?.verify_tls !== false);

  const isPending = create.isPending || update.isPending;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!provider) {
      alert('Select a provider.');
      return;
    }
    if (!name.trim() || !baseUrl.trim()) {
      alert('Name and base URL are required.');
      return;
    }
    const auth_config: Record<string, string> = {};
    if (authType === 'token' && token) auth_config.token = token;
    if (authType === 'basic') {
      if (username) auth_config.username = username.trim();
      if (token) auth_config.password = token;
    }
    const payload: DhcpServerPayload = {
      provider,
      name: name.trim(),
      base_url: baseUrl.trim(),
      auth_type: authType,
      notes: notes.trim(),
      enabled,
      verify_tls: verifyTls,
    };
    if (Object.keys(auth_config).length) payload.auth_config = auth_config;
    try {
      if (isEdit && server) {
        await update.mutateAsync({ id: server.id, payload });
      } else {
        await create.mutateAsync(payload);
      }
      onClose();
    } catch (err) {
      alert((err as Error).message);
    }
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={isEdit ? 'Edit DHCP Server' : 'Add DHCP Server'}
    >
      <form onSubmit={submit}>
        <div className="form-group">
          <label className="form-label">Provider</label>
          <select
            className="form-select"
            value={provider}
            onChange={(e) => setProvider(e.target.value)}
            required
          >
            <option value="">Select provider…</option>
            {(providers.data?.providers ?? []).map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label className="form-label">Name</label>
          <input
            className="form-input"
            value={name}
            onChange={(e) => setName(e.target.value)}
            maxLength={120}
            required
            placeholder="e.g. Kea-DC1"
          />
        </div>
        <div className="form-group">
          <label className="form-label">Base URL</label>
          <input
            className="form-input"
            type="url"
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            required
            placeholder="https://kea.example.com"
          />
        </div>
        <div className="form-group">
          <label className="form-label">Auth Type</label>
          <select
            className="form-select"
            value={authType}
            onChange={(e) => setAuthType(e.target.value)}
          >
            <option value="none">None</option>
            <option value="token">API Token</option>
            <option value="basic">Basic Auth</option>
          </select>
        </div>
        {authType !== 'none' && (
          <div className="form-group">
            <label className="form-label">Token / Password</label>
            <input
              className="form-input"
              type="password"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              maxLength={512}
              placeholder="Leave blank to keep existing"
            />
          </div>
        )}
        {authType === 'basic' && (
          <div className="form-group">
            <label className="form-label">Username</label>
            <input
              className="form-input"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              maxLength={120}
            />
          </div>
        )}
        <div className="form-group">
          <label className="form-label">Notes</label>
          <input
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
              checked={verifyTls}
              onChange={(e) => setVerifyTls(e.target.checked)}
            />{' '}
            Verify TLS
          </label>
        </div>
        <div
          style={{
            display: 'flex',
            gap: '0.5rem',
            justifyContent: 'flex-end',
            marginTop: '1rem',
          }}
        >
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn btn-primary" disabled={isPending}>
            {isPending ? 'Saving…' : isEdit ? 'Save Changes' : 'Add Server'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
