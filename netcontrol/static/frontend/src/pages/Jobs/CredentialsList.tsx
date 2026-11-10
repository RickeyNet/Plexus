import { useId, useState, type FormEvent } from 'react';

import { Callout } from '@/components/Callout';
import { DeleteButton } from '@/components/DeleteButton';
import { EmptyState } from '@/components/EmptyState';
import { FieldError } from '@/components/FieldError';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { Modal } from '@/components/Modal';
import { useDialogs } from '@/components/DialogProvider-context';
import {
  useCreateCredential,
  useDeleteCredential,
  useJobCredentials,
  useUpdateCredential,
  type Credential,
} from '@/api/jobs';
import { usePendingKeys } from '@/lib/usePendingKeys';

export function CredentialsList() {
  const { confirm, alert } = useDialogs();
  const query = useJobCredentials();
  const deleteMut = useDeleteCredential();
  const deleting = usePendingKeys<number>();
  const [showCreate, setShowCreate] = useState(false);

  async function handleDelete(c: Credential) {
    const ok = await confirm({
      title: 'Delete credential',
      message: `Delete credential "${c.name}"?`,
      confirmLabel: 'Delete',
    });
    if (!ok) return;
    await deleting.run(c.id, async () => {
      try {
        await deleteMut.mutateAsync(c.id);
      } catch (e) {
        void alert({ message: (e as Error).message, variant: 'error' });
      }
    });
  }

  return (
    <div>
      <div className="toolbar">
        <span className="toolbar-spacer" />
        <button className="btn btn-primary" onClick={() => setShowCreate(true)}>+ New Credential</button>
      </div>

      {query.error && !query.data ? (
        <QueryError what="credentials" query={query} />
      ) : (
        query.isPending && <LoadingState />
      )}
      {query.data && (query.data.length === 0 ? (
        <EmptyState message="No credentials" />
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {query.data.map((c) => (
            <CredentialRow key={c.id} credential={c} isDeleting={deleting.isPending(c.id)} onDelete={() => void handleDelete(c)} />
          ))}
        </div>
      ))}

      <CreateCredentialModal isOpen={showCreate} onClose={() => setShowCreate(false)} />
    </div>
  );
}

function CredentialRow({
  credential,
  isDeleting,
  onDelete,
}: {
  credential: Credential;
  isDeleting: boolean;
  onDelete: () => void;
}) {
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
    <div className="card card-sm">
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
        <DeleteButton busy={isDeleting} onClick={onDelete} />
      </div>
    </div>
  );
}

function CreateCredentialModal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const createMut = useCreateCredential();
  const formId = useId();
  const [name, setName] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [secret, setSecret] = useState('');
  const [errors, setErrors] = useState<{ name?: string; username?: string; password?: string }>({});
  const [saveError, setSaveError] = useState<string | null>(null);

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setSaveError(null);
    const next = {
      name: name.trim() ? undefined : 'Name is required',
      username: username.trim() ? undefined : 'Username is required',
      password: password ? undefined : 'Password is required',
    };
    setErrors(next);
    if (next.name || next.username || next.password) return;
    createMut.mutate(
      { name: name.trim(), username: username.trim(), password, secret: secret || undefined },
      {
        onSuccess: () => {
          setName(''); setUsername(''); setPassword(''); setSecret('');
          onClose();
        },
        onError: (e) => { setSaveError((e as Error).message); },
      },
    );
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Create Credential"
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button type="submit" form={formId} className="btn btn-primary" disabled={createMut.isPending}>
            {createMut.isPending ? 'Creating…' : 'Create'}
          </button>
        </>
      }
    >
      <form id={formId} onSubmit={handleSubmit}>
        {saveError && <Callout tone="danger">{saveError}</Callout>}
        <div className="form-group">
          <label className="form-label">Name</label>
          <input
            className="form-input"
            value={name}
            onChange={(e) => { setName(e.target.value); setErrors((p) => ({ ...p, name: undefined })); }}
            aria-invalid={!!errors.name}
            required
          />
          <FieldError>{errors.name}</FieldError>
        </div>
        <div className="form-group">
          <label className="form-label">Username</label>
          <input
            className="form-input"
            value={username}
            onChange={(e) => { setUsername(e.target.value); setErrors((p) => ({ ...p, username: undefined })); }}
            aria-invalid={!!errors.username}
            required
          />
          <FieldError>{errors.username}</FieldError>
        </div>
        <div className="form-group">
          <label className="form-label">Password</label>
          <input
            className="form-input"
            type="password"
            value={password}
            onChange={(e) => { setPassword(e.target.value); setErrors((p) => ({ ...p, password: undefined })); }}
            aria-invalid={!!errors.password}
            required
          />
          <FieldError>{errors.password}</FieldError>
        </div>
        <div className="form-group">
          <label className="form-label">Secret (Enable Password)</label>
          <input className="form-input" type="password" value={secret} onChange={(e) => setSecret(e.target.value)} />
        </div>
      </form>
    </Modal>
  );
}
