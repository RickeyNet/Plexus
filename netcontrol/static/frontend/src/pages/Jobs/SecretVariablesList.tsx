import { useEffect, useState, type FormEvent } from 'react';

import { Modal } from '@/components/Modal';
import { useDialogs } from '@/components/DialogProvider-context';
import {
  useCreateSecretVariable,
  useDeleteSecretVariable,
  useSecretVariables,
  useUpdateSecretVariable,
  type SecretVariable,
} from '@/api/jobs';

export function SecretVariablesList() {
  const { confirm, alert } = useDialogs();
  const query = useSecretVariables();
  const deleteMut = useDeleteSecretVariable();
  const [showCreate, setShowCreate] = useState(false);
  const [editing, setEditing] = useState<SecretVariable | null>(null);

  async function handleDelete(v: SecretVariable) {
    if (!(await confirm(`Delete secret '${v.name}'? Templates referencing {{secret.${v.name}}} will fail.`))) return;
    deleteMut.mutate(v.id, { onError: (e) => { void alert({ message: (e as Error).message, variant: 'error' }); } });
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
        <p className="text-muted" style={{ margin: 0 }}>
          Use <code>{'{{secret.NAME}}'}</code> in config templates to reference encrypted values.
        </p>
        <button className="btn btn-primary" onClick={() => setShowCreate(true)}>+ New Secret</button>
      </div>

      {query.isPending && <p className="text-muted">Loading…</p>}
      {query.error && <p style={{ color: 'var(--danger)' }}>Failed: {(query.error as Error).message}</p>}
      {query.data && (query.data.length === 0 ? (
        <div className="empty-state">No secret variables yet</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {query.data.map((v) => (
            <div key={v.id} className="card" style={{ padding: '0.75rem 1rem', display: 'flex', justifyContent: 'space-between', gap: '1rem', alignItems: 'center', flexWrap: 'wrap' }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div><code style={{ fontWeight: 600 }}>{`{{secret.${v.name}}}`}</code></div>
                {v.description && <div className="text-muted" style={{ fontSize: '0.85rem', marginTop: '0.15rem' }}>{v.description}</div>}
                <div className="text-muted" style={{ fontSize: '0.75rem', marginTop: '0.15rem' }}>
                  Created by {v.created_by || 'system'}
                  {v.created_at && ` • ${v.created_at.replace('T', ' ').substring(0, 16)}`}
                </div>
              </div>
              <div style={{ display: 'flex', gap: '0.4rem' }}>
                <button className="btn btn-sm btn-secondary" onClick={() => setEditing(v)}>Edit</button>
                <button className="btn btn-sm btn-danger" onClick={() => handleDelete(v)}>Delete</button>
              </div>
            </div>
          ))}
        </div>
      ))}

      <CreateSecretModal isOpen={showCreate} onClose={() => setShowCreate(false)} />
      <EditSecretModal secret={editing} onClose={() => setEditing(null)} />
    </div>
  );
}

function CreateSecretModal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const { alert } = useDialogs();
  const createMut = useCreateSecretVariable();
  const [name, setName] = useState('');
  const [value, setValue] = useState('');
  const [description, setDescription] = useState('');

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim() || !value) {
      void alert('Name and value are required');
      return;
    }
    createMut.mutate(
      { name: name.trim(), value, description: description.trim() },
      {
        onSuccess: () => { setName(''); setValue(''); setDescription(''); onClose(); },
        onError: (e) => { void alert({ message: (e as Error).message, variant: 'error' }); },
      },
    );
  }

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Create Secret Variable">
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label className="form-label">Name</label>
          <input
            className="form-input"
            value={name}
            onChange={(e) => setName(e.target.value)}
            pattern="[A-Za-z_][A-Za-z0-9_-]*"
            maxLength={64}
            placeholder="e.g. snmp_community_ro"
            required
          />
          <small className="text-muted">Letters, numbers, underscore, hyphen. Referenced as <code>{'{{secret.name}}'}</code></small>
        </div>
        <div className="form-group">
          <label className="form-label">Value</label>
          <input className="form-input" type="password" value={value} onChange={(e) => setValue(e.target.value)} required />
        </div>
        <div className="form-group">
          <label className="form-label">Description (optional)</label>
          <input className="form-input" value={description} onChange={(e) => setDescription(e.target.value)} />
        </div>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
          <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn btn-primary" disabled={createMut.isPending}>
            {createMut.isPending ? 'Creating…' : 'Create'}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function EditSecretModal({ secret, onClose }: { secret: SecretVariable | null; onClose: () => void }) {
  const { alert } = useDialogs();
  const updateMut = useUpdateSecretVariable();
  const [value, setValue] = useState('');
  const [description, setDescription] = useState('');

  useEffect(() => {
    if (secret) {
      setValue('');
      setDescription(secret.description ?? '');
    }
  }, [secret]);

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!secret) return;
    const data: { value?: string; description?: string } = { description: description.trim() };
    if (value) data.value = value;
    updateMut.mutate({ id: secret.id, data }, {
      onSuccess: () => { setValue(''); setDescription(''); onClose(); },
      onError: (e) => { void alert({ message: (e as Error).message, variant: 'error' }); },
    });
  }

  return (
    <Modal isOpen={secret != null} onClose={() => { setValue(''); setDescription(''); onClose(); }} title={secret ? `Edit Secret: ${secret.name}` : ''}>
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label className="form-label">Name</label>
          <input className="form-input" value={secret?.name ?? ''} disabled />
        </div>
        <div className="form-group">
          <label className="form-label">New Value (leave blank to keep current)</label>
          <input className="form-input" type="password" value={value} onChange={(e) => setValue(e.target.value)} />
        </div>
        <div className="form-group">
          <label className="form-label">Description</label>
          <input className="form-input" value={description} onChange={(e) => setDescription(e.target.value)} />
        </div>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
          <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn btn-primary" disabled={updateMut.isPending}>
            {updateMut.isPending ? 'Saving…' : 'Save'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
