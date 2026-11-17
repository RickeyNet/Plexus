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
  type CredentialPayload,
} from '@/api/jobs';
import { useReferenceProviders } from '@/api/secretsProviders';
import { ExternalReferenceFields, ValueSourceToggle, type ValueSource } from '@/components/ExternalReferenceFields';
import { SecretInput } from '@/components/SecretInput';
import {
  hasReference,
  referenceDraft,
  referenceLabel,
  referencePayload,
  sameReference,
  validateReference,
  type ReferenceDraft,
  type ReferenceErrors,
} from '@/lib/secretsProviders';
import { usePendingKeys } from '@/lib/usePendingKeys';

export function CredentialsList() {
  const { confirm, alert } = useDialogs();
  const query = useJobCredentials();
  const deleteMut = useDeleteCredential();
  const deleting = usePendingKeys<number>();
  // null: closed; 'new': create; a credential: edit that one.
  const [form, setForm] = useState<Credential | 'new' | null>(null);

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
        <button className="btn btn-primary" onClick={() => setForm('new')}>+ New Credential</button>
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
            <CredentialRow
              key={c.id}
              credential={c}
              isDeleting={deleting.isPending(c.id)}
              onEdit={() => setForm(c)}
              onDelete={() => void handleDelete(c)}
            />
          ))}
        </div>
      ))}

      {form && (
        <CredentialFormModal
          key={form === 'new' ? 'new' : form.id}
          credential={form === 'new' ? null : form}
          onClose={() => setForm(null)}
        />
      )}
    </div>
  );
}

function CredentialRow({
  credential,
  isDeleting,
  onEdit,
  onDelete,
}: {
  credential: Credential;
  isDeleting: boolean;
  onEdit: () => void;
  onDelete: () => void;
}) {
  return (
    <div className="card card-sm" style={{ display: 'flex', justifyContent: 'space-between', gap: 'var(--space-4)', alignItems: 'center' }}>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontWeight: 600 }}>{credential.name}</div>
        <div className="text-muted" style={{ fontSize: '0.85rem', marginTop: '0.25rem' }}>
          Username: {credential.username}
          {hasReference(credential) && <> · External: {referenceLabel(credential)}</>}
        </div>
      </div>
      <div style={{ display: 'flex', gap: '0.4rem' }}>
        <button className="btn btn-sm btn-secondary" onClick={onEdit}>Edit</button>
        <DeleteButton busy={isDeleting} onClick={onDelete} />
      </div>
    </div>
  );
}

/** Creates a credential, or edits `credential` when one is given. The
 *  password and enable secret are stored encrypted, or read from an
 *  external secrets provider when the credential is used. */
function CredentialFormModal({ credential, onClose }: { credential: Credential | null; onClose: () => void }) {
  const createMut = useCreateCredential();
  const updateMut = useUpdateCredential();
  const providers = useReferenceProviders();
  const formId = useId();
  const wasExternal = hasReference(credential);
  const [name, setName] = useState(credential?.name ?? '');
  const [username, setUsername] = useState(credential?.username ?? '');
  const [source, setSource] = useState<ValueSource>(wasExternal ? 'external' : 'stored');
  const [password, setPassword] = useState('');
  const [secret, setSecret] = useState('');
  const [initialRef] = useState<ReferenceDraft>(() => referenceDraft(credential));
  const [reference, setReference] = useState<ReferenceDraft>(initialRef);
  const [errors, setErrors] = useState<{ name?: string; username?: string; password?: string }>({});
  const [refErrors, setRefErrors] = useState<ReferenceErrors>({});
  const [saveError, setSaveError] = useState<string | null>(null);

  const pending = createMut.isPending || updateMut.isPending;
  const canReference = wasExternal || (providers.data?.length ?? 0) > 0;
  const external = source === 'external';

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setSaveError(null);
    const next = {
      name: name.trim() ? undefined : 'Name is required',
      username: username.trim() ? undefined : 'Username is required',
      // An edit keeps the stored password when the field is left blank; a
      // switch from a reference to a stored value needs one.
      password: external || password || (credential && !wasExternal) ? undefined : 'Password is required',
    };
    setErrors(next);
    const nextRef = external ? validateReference(reference) : {};
    setRefErrors(nextRef);
    if (next.name || next.username || next.password || Object.keys(nextRef).length > 0) return;
    const onError = (err: unknown) => { setSaveError((err as Error).message); };
    if (!credential) {
      createMut.mutate(
        external
          ? { name: name.trim(), username: username.trim(), external: referencePayload(reference, true) }
          : { name: name.trim(), username: username.trim(), password, secret: secret || undefined },
        { onSuccess: onClose, onError },
      );
      return;
    }
    const data: Partial<CredentialPayload> = {};
    if (name.trim() !== credential.name) data.name = name.trim();
    if (username.trim() !== credential.username) data.username = username.trim();
    if (external) {
      if (!wasExternal || !sameReference(reference, initialRef)) data.external = referencePayload(reference, true);
    } else {
      if (password) data.password = password;
      if (secret) data.secret = secret;
    }
    if (Object.keys(data).length === 0) {
      onClose();
      return;
    }
    updateMut.mutate({ id: credential.id, data }, { onSuccess: onClose, onError });
  }

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={credential ? 'Edit Credential' : 'Create Credential'}
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button type="submit" form={formId} className="btn btn-primary" disabled={pending}>
            {credential ? (pending ? 'Saving…' : 'Save') : (pending ? 'Creating…' : 'Create')}
          </button>
        </>
      }
    >
      <form id={formId} onSubmit={handleSubmit}>
        {saveError && <Callout tone="danger">{saveError}</Callout>}
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-name`}>Name</label>
          <input
            id={`${formId}-name`}
            className="form-input"
            value={name}
            onChange={(e) => { setName(e.target.value); setErrors((p) => ({ ...p, name: undefined })); }}
            aria-invalid={!!errors.name}
            required
          />
          <FieldError>{errors.name}</FieldError>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-username`}>Username</label>
          <input
            id={`${formId}-username`}
            className="form-input"
            value={username}
            onChange={(e) => { setUsername(e.target.value); setErrors((p) => ({ ...p, username: undefined })); }}
            aria-invalid={!!errors.username}
            required
          />
          <FieldError>{errors.username}</FieldError>
        </div>
        {canReference && <ValueSourceToggle value={source} onChange={setSource} />}
        {external ? (
          <ExternalReferenceFields
            idPrefix={`${formId}-ref`}
            value={reference}
            onChange={(next) => { setReference(next); setRefErrors({}); }}
            providers={providers.data ?? []}
            errors={refErrors}
            withSecretKey
            keyLabel="Password key"
          />
        ) : (
          <>
            <div className="form-group">
              <label className="form-label" htmlFor={`${formId}-password`}>Password</label>
              <SecretInput
                id={`${formId}-password`}
                label="password"
                value={password}
                onChange={(v) => { setPassword(v); setErrors((p) => ({ ...p, password: undefined })); }}
                invalid={!!errors.password}
                required={!credential || wasExternal}
              />
              {credential && !wasExternal && <small className="text-muted">Leave blank to keep the current password.</small>}
              {wasExternal && <small className="text-muted">Replaces the external reference with a stored password.</small>}
              <FieldError>{errors.password}</FieldError>
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor={`${formId}-secret`}>Secret (Enable Password)</label>
              <SecretInput id={`${formId}-secret`} label="enable secret" value={secret} onChange={setSecret} />
              {credential && !wasExternal && <small className="text-muted">Leave blank to keep the current secret.</small>}
            </div>
          </>
        )}
      </form>
    </Modal>
  );
}
