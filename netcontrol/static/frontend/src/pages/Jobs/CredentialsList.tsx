import { useState, type FormEvent } from 'react';

import { Modal } from '@/components/Modal';
import { useDialogs } from '@/components/DialogProvider-context';
import {
  useCreateCredential,
  useDeleteCredential,
  useJobCredentials,
  useUpdateCredential,
  type Credential,
} from '@/api/jobs';

export function CredentialsList() {
  const { confirm, alert } = useDialogs();
  const query = useJobCredentials();
  const deleteMut = useDeleteCredential();
  const [showCreate, setShowCreate] = useState(false);

  async function handleDelete(id: number) {
    if (!(await confirm('Delete this credential?'))) return;
    deleteMut.mutate(id, { onError: (e) => { void alert({ message: (e as Error).message, variant: 'error' }); } });
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '0.75rem' }}>
        <button className="btn btn-primary" onClick={() => setShowCreate(true)}>+ New Credential</button>
      </div>

      {query.isPending && <p className="text-muted">Loading…</p>}
      {query.error && <p style={{ color: 'var(--danger)' }}>Failed: {(query.error as Error).message}</p>}
      {query.data && (query.data.length === 0 ? (
        <div className="empty-state">No credentials</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {query.data.map((c) => (
            <CredentialRow key={c.id} credential={c} onDelete={() => handleDelete(c.id)} />
          ))}
        </div>
      ))}

      <CreateCredentialModal isOpen={showCreate} onClose={() => setShowCreate(false)} />
    </div>
  );
}

function CredentialRow({ credential, onDelete }: { credential: Credential; onDelete: () => void }) {
  const { alert } = useDialogs();
  const updateMut = useUpdateCredential();
  const [name, setName] = useState(credential.name);
  const [username, setUsername] = useState(credential.username);
  const [password, setPassword] = useState('');
  const [secret, setSecret] = useState('');

  const dirty = name !== credential.name || username !== credential.username || password.length > 0 || secret.length > 0;

  function save() {
    const data: Partial<{ name: string; username: string; password: string; secret: string }> = {};
    if (name !== credential.name) data.name = name;
    if (username !== credential.username) data.username = username;
    if (password) data.password = password;
    if (secret) data.secret = secret;
    updateMut.mutate({ id: credential.id, data }, {
      onSuccess: () => { setPassword(''); setSecret(''); },
      onError: (e) => { void alert({ message: (e as Error).message, variant: 'error' }); },
    });
  }

  return (
    <div className="card" style={{ padding: '0.75rem 1rem' }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '0.5rem' }}>
        <div>
          <label className="form-label" style={{ fontSize: '0.75rem' }}>Name</label>
          <input className="form-input" value={name} onChange={(e) => setName(e.target.value)} />
        </div>
        <div>
          <label className="form-label" style={{ fontSize: '0.75rem' }}>Username</label>
          <input className="form-input" value={username} onChange={(e) => setUsername(e.target.value)} />
        </div>
        <div>
          <label className="form-label" style={{ fontSize: '0.75rem' }}>Password</label>
          <input className="form-input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="unchanged" />
        </div>
        <div>
          <label className="form-label" style={{ fontSize: '0.75rem' }}>Secret</label>
          <input className="form-input" type="password" value={secret} onChange={(e) => setSecret(e.target.value)} placeholder="unchanged" />
        </div>
      </div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.4rem', marginTop: '0.5rem' }}>
        {dirty && (
          <button className="btn btn-sm btn-primary" onClick={save} disabled={updateMut.isPending}>
            {updateMut.isPending ? 'Saving…' : 'Save'}
          </button>
        )}
        <button className="btn btn-sm btn-danger" onClick={onDelete}>Delete</button>
      </div>
    </div>
  );
}

function CreateCredentialModal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const { alert } = useDialogs();
  const createMut = useCreateCredential();
  const [name, setName] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [secret, setSecret] = useState('');

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim() || !username.trim() || !password) {
      void alert('Name, username, and password are required');
      return;
    }
    createMut.mutate(
      { name: name.trim(), username: username.trim(), password, secret: secret || undefined },
      {
        onSuccess: () => {
          setName(''); setUsername(''); setPassword(''); setSecret('');
          onClose();
        },
        onError: (e) => { void alert({ message: (e as Error).message, variant: 'error' }); },
      },
    );
  }

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Create Credential">
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label className="form-label">Name</label>
          <input className="form-input" value={name} onChange={(e) => setName(e.target.value)} required />
        </div>
        <div className="form-group">
          <label className="form-label">Username</label>
          <input className="form-input" value={username} onChange={(e) => setUsername(e.target.value)} required />
        </div>
        <div className="form-group">
          <label className="form-label">Password</label>
          <input className="form-input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        </div>
        <div className="form-group">
          <label className="form-label">Secret (Enable Password)</label>
          <input className="form-input" type="password" value={secret} onChange={(e) => setSecret(e.target.value)} />
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
