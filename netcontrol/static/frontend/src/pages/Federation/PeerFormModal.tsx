import { useState } from 'react';

import { Modal } from '@/components/Modal';
import {
  FederationPeer,
  FederationPeerInput,
  useCreateFederationPeer,
  useUpdateFederationPeer,
} from '@/api/federation';

export interface PeerFormModalProps {
  existing: FederationPeer | null;
  onClose: () => void;
  onSaved?: () => void;
}

export function PeerFormModal({ existing, onClose, onSaved }: PeerFormModalProps) {
  const isEdit = existing !== null;
  const [name, setName] = useState(existing?.name ?? '');
  const [url, setUrl] = useState(existing?.url ?? '');
  // Token field is always blank on open; an empty token on edit means "leave
  // unchanged", matching the legacy module's contract with the backend.
  const [token, setToken] = useState('');
  const [description, setDescription] = useState(existing?.description ?? '');
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [errMsg, setErrMsg] = useState<string | null>(null);

  const create = useCreateFederationPeer();
  const update = useUpdateFederationPeer();
  const pending = create.isPending || update.isPending;

  const submit = async () => {
    setErrMsg(null);
    const body: FederationPeerInput = {
      name: name.trim(),
      url: url.trim(),
      description: description.trim(),
      enabled,
    };
    if (token) {
      body.api_token = token;
    } else if (!isEdit) {
      // New peer with no token — explicitly send empty so the backend stores
      // a no-token entry rather than rejecting an undefined field.
      body.api_token = '';
    }
    try {
      if (isEdit && existing) {
        await update.mutateAsync({ id: existing.id, body });
      } else {
        await create.mutateAsync(body);
      }
      onSaved?.();
      onClose();
    } catch (err) {
      setErrMsg(err instanceof Error ? err.message : String(err));
    }
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={isEdit ? 'Edit Federation Peer' : 'Add Federation Peer'}
    >
      <div className="form-group">
        <label className="form-label" htmlFor="fed-name">
          Name <span style={{ color: 'var(--danger)' }}>*</span>
        </label>
        <input
          id="fed-name"
          className="form-input"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
      </div>
      <div className="form-group">
        <label className="form-label" htmlFor="fed-url">
          URL <span style={{ color: 'var(--danger)' }}>*</span>
        </label>
        <input
          id="fed-url"
          className="form-input"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://plexus-remote.example.com"
        />
      </div>
      <div className="form-group">
        <label className="form-label" htmlFor="fed-token">API Token</label>
        <input
          id="fed-token"
          className="form-input"
          type="password"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          placeholder={isEdit ? '(unchanged if empty)' : ''}
          autoComplete="new-password"
        />
      </div>
      <div className="form-group">
        <label className="form-label" htmlFor="fed-desc">Description</label>
        <input
          id="fed-desc"
          className="form-input"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />
      </div>
      <div className="form-group">
        <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
          />
          Enabled
        </label>
      </div>

      {errMsg && (
        <div className="error">
          <strong>{isEdit ? 'Update failed' : 'Create failed'}:</strong> {errMsg}
        </div>
      )}

      <div
        style={{
          display: 'flex',
          gap: '0.5rem',
          justifyContent: 'flex-end',
          marginTop: '1rem',
        }}
      >
        <button
          type="button"
          className="btn btn-primary"
          disabled={!name.trim() || !url.trim() || pending}
          onClick={submit}
        >
          {isEdit ? 'Save' : 'Add Peer'}
        </button>
        <button type="button" className="btn btn-ghost" onClick={onClose}>
          Cancel
        </button>
      </div>
    </Modal>
  );
}
