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
  useCreateSecretVariable,
  useDeleteSecretVariable,
  useSecretVariables,
  useUpdateSecretVariable,
  type SecretVariable,
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
  type ExternalReferenceBody,
  type ReferenceDraft,
  type ReferenceErrors,
} from '@/lib/secretsProviders';
import { usePendingKeys } from '@/lib/usePendingKeys';

export function SecretVariablesList() {
  const { confirm, alert } = useDialogs();
  const query = useSecretVariables();
  const deleteMut = useDeleteSecretVariable();
  const deleting = usePendingKeys<number>();
  const [showCreate, setShowCreate] = useState(false);
  const [editing, setEditing] = useState<SecretVariable | null>(null);

  async function handleDelete(v: SecretVariable) {
    const ok = await confirm({
      title: 'Delete secret variable',
      message: `Delete secret '${v.name}'? Instructions referencing {{secret.${v.name}}} will fail.`,
      confirmLabel: 'Delete',
    });
    if (!ok) return;
    await deleting.run(v.id, async () => {
      try {
        await deleteMut.mutateAsync(v.id);
      } catch (e) {
        void alert({ message: (e as Error).message, variant: 'error' });
      }
    });
  }

  return (
    <div>
      <div className="toolbar">
        <p className="text-muted" style={{ margin: 0 }}>
          Use <code>{'{{secret.NAME}}'}</code> in instructions to reference encrypted values.
        </p>
        <span className="toolbar-spacer" />
        <button className="btn btn-primary" onClick={() => setShowCreate(true)}>+ New Secret</button>
      </div>

      {query.error && !query.data ? (
        <QueryError what="secret variables" query={query} />
      ) : (
        query.isPending && <LoadingState />
      )}
      {query.data && (query.data.length === 0 ? (
        <EmptyState message="No secret variables yet" />
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {query.data.map((v) => (
            <div key={v.id} className="card card-sm" style={{ display: 'flex', justifyContent: 'space-between', gap: 'var(--space-4)', alignItems: 'center', flexWrap: 'wrap' }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div><code style={{ fontWeight: 600 }}>{`{{secret.${v.name}}}`}</code></div>
                {v.description && <div className="text-muted" style={{ fontSize: '0.85rem', marginTop: '0.15rem' }}>{v.description}</div>}
                {hasReference(v) && (
                  <div className="text-muted" style={{ fontSize: '0.85rem', marginTop: '0.15rem' }}>
                    External: {referenceLabel(v)}
                  </div>
                )}
                <div className="text-muted" style={{ fontSize: '0.75rem', marginTop: '0.15rem' }}>
                  Created by {v.created_by || 'system'}
                  {v.created_at && ` • ${v.created_at.replace('T', ' ').substring(0, 16)}`}
                </div>
              </div>
              <div style={{ display: 'flex', gap: '0.4rem' }}>
                <button className="btn btn-sm btn-secondary" onClick={() => setEditing(v)}>Edit</button>
                <DeleteButton busy={deleting.isPending(v.id)} onClick={() => void handleDelete(v)} />
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

const SECRET_NAME_RE = /^[A-Za-z_][A-Za-z0-9_-]{0,63}$/;

/** Reduce a pasted `{{secret.NAME}}` or `secret.NAME` reference to `NAME`.
 *  Mirrors normalize_secret_name in routes/secret_resolver.py. */
function normalizeSecretName(raw: string): string {
  let name = raw.trim();
  if (name.startsWith('{{') && name.endsWith('}}')) name = name.slice(2, -2).trim();
  if (name.startsWith('secret.')) name = name.slice('secret.'.length);
  return name.trim();
}

function CreateSecretModal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const createMut = useCreateSecretVariable();
  const providers = useReferenceProviders(isOpen);
  const formId = useId();
  const [name, setName] = useState('');
  const [value, setValue] = useState('');
  const [description, setDescription] = useState('');
  const [source, setSource] = useState<ValueSource>('stored');
  const [reference, setReference] = useState<ReferenceDraft>(() => referenceDraft(null));
  const [errors, setErrors] = useState<{ name?: string; value?: string }>({});
  const [refErrors, setRefErrors] = useState<ReferenceErrors>({});
  const [saveError, setSaveError] = useState<string | null>(null);
  const external = source === 'external';

  const normalized = normalizeSecretName(name);
  const nameValid = SECRET_NAME_RE.test(normalized);

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setSaveError(null);
    const nextErrors = {
      name: !normalized
        ? 'Name is required'
        : !nameValid
          ? `"${normalized}" is not a valid secret name. Use only letters, digits, underscore or hyphen, ` +
            'starting with a letter or underscore (e.g. snmp_v3_auth_key).'
          : undefined,
      value: value || external ? undefined : 'Value is required',
    };
    setErrors(nextErrors);
    const nextRef = external ? validateReference(reference) : {};
    setRefErrors(nextRef);
    if (nextErrors.name || nextErrors.value || Object.keys(nextRef).length > 0) return;
    createMut.mutate(
      external
        ? { name: normalized, description: description.trim(), external: referencePayload(reference) }
        : { name: normalized, value, description: description.trim() },
      {
        onSuccess: () => {
          setName('');
          setValue('');
          setDescription('');
          setSource('stored');
          setReference(referenceDraft(null));
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
      title="Create Secret Variable"
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
          <label className="form-label" htmlFor={`${formId}-name`}>Name</label>
          <input
            id={`${formId}-name`}
            className="form-input"
            value={name}
            onChange={(e) => { setName(e.target.value); setErrors((p) => ({ ...p, name: undefined })); }}
            aria-invalid={!!errors.name}
            onBlur={() => setName(normalizeSecretName(name))}
            maxLength={80}
            placeholder="e.g. snmp_v3_auth_key"
            autoComplete="off"
            required
          />
          <small className="text-muted" style={{ display: 'block', marginTop: '0.25rem' }}>
            Enter only the name, not the full reference. For an instruction line containing{' '}
            <code>{'{{secret.snmp_v3_auth_key}}'}</code>, the name is <code>snmp_v3_auth_key</code>.
            Pasting the full reference is fine; the braces and <code>secret.</code> prefix are removed automatically.
            Allowed: letters, digits, <code>_</code> and <code>-</code>, starting with a letter or <code>_</code>, up to 64 characters.
          </small>
          {normalized && (
            <small style={{ display: 'block', marginTop: '0.25rem', color: nameValid ? undefined : 'var(--danger)' }}>
              {nameValid ? (
                <>Instructions will reference this as<code>{`{{secret.${normalized}}}`}</code></>
              ) : (
                <>"{normalized}" is not a valid name: remove spaces, dots and other symbols.</>
              )}
            </small>
          )}
          <small className="text-muted" style={{ display: 'block', marginTop: '0.25rem' }}>
            The built-in SNMPv3 instructions expect<code>snmp_v3_auth_key</code> and <code>snmp_v3_priv_key</code>.
          </small>
          <FieldError>{errors.name}</FieldError>
        </div>
        {(providers.data?.length ?? 0) > 0 && <ValueSourceToggle value={source} onChange={setSource} />}
        {external ? (
          <ExternalReferenceFields
            idPrefix={`${formId}-ref`}
            value={reference}
            onChange={(next) => { setReference(next); setRefErrors({}); }}
            providers={providers.data ?? []}
            errors={refErrors}
          />
        ) : (
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-value`}>Value</label>
            <SecretInput
              id={`${formId}-value`}
              label="value"
              value={value}
              onChange={(v) => { setValue(v); setErrors((p) => ({ ...p, value: undefined })); }}
              invalid={!!errors.value}
              required
            />
            <small className="text-muted">The secret itself (any characters). Encrypted at rest and never shown again.</small>
            <FieldError>{errors.value}</FieldError>
          </div>
        )}
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-description`}>Description (optional)</label>
          <input id={`${formId}-description`} className="form-input" value={description} onChange={(e) => setDescription(e.target.value)} />
        </div>
      </form>
    </Modal>
  );
}

function EditSecretModal({ secret, onClose }: { secret: SecretVariable | null; onClose: () => void }) {
  const updateMut = useUpdateSecretVariable();
  const providers = useReferenceProviders(secret != null);
  const formId = useId();
  const [value, setValue] = useState('');
  const [description, setDescription] = useState('');
  const [source, setSource] = useState<ValueSource>('stored');
  const [reference, setReference] = useState<ReferenceDraft>(() => referenceDraft(null));
  const [refErrors, setRefErrors] = useState<ReferenceErrors>({});
  const [saveError, setSaveError] = useState<string | null>(null);
  const wasExternal = hasReference(secret);
  const external = source === 'external';

  const [prevSecret, setPrevSecret] = useState(secret);
  if (secret !== prevSecret) {
    setPrevSecret(secret);
    if (secret) {
      setValue('');
      setDescription(secret.description ?? '');
      setSource(hasReference(secret) ? 'external' : 'stored');
      setReference(referenceDraft(secret));
      setRefErrors({});
      setSaveError(null);
    }
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!secret) return;
    setSaveError(null);
    const data: { value?: string; description?: string; external?: ExternalReferenceBody } = {
      description: description.trim(),
    };
    if (external) {
      const nextRef = validateReference(reference);
      setRefErrors(nextRef);
      if (Object.keys(nextRef).length > 0) return;
      if (!wasExternal || !sameReference(reference, referenceDraft(secret))) data.external = referencePayload(reference);
    } else if (value) {
      data.value = value;
    } else if (wasExternal) {
      setSaveError('Enter a value to replace the external reference.');
      return;
    }
    updateMut.mutate({ id: secret.id, data }, {
      onSuccess: () => { setValue(''); setDescription(''); onClose(); },
      onError: (e) => { setSaveError((e as Error).message); },
    });
  }

  return (
    <Modal
      isOpen={secret != null}
      onClose={() => { setValue(''); setDescription(''); onClose(); }}
      title={secret ? `Edit Secret: ${secret.name}` : ''}
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button type="submit" form={formId} className="btn btn-primary" disabled={updateMut.isPending}>
            {updateMut.isPending ? 'Saving…' : 'Save'}
          </button>
        </>
      }
    >
      <form id={formId} onSubmit={handleSubmit}>
        {saveError && <Callout tone="danger">{saveError}</Callout>}
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-name`}>Name</label>
          <input id={`${formId}-name`} className="form-input" value={secret?.name ?? ''} disabled />
        </div>
        {(wasExternal || (providers.data?.length ?? 0) > 0) && <ValueSourceToggle value={source} onChange={setSource} />}
        {external ? (
          <ExternalReferenceFields
            idPrefix={`${formId}-ref`}
            value={reference}
            onChange={(next) => { setReference(next); setRefErrors({}); }}
            providers={providers.data ?? []}
            errors={refErrors}
          />
        ) : (
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-value`}>
              {wasExternal ? 'Value (replaces the external reference)' : 'New Value (leave blank to keep current)'}
            </label>
            <SecretInput id={`${formId}-value`} label="value" value={value} onChange={setValue} />
          </div>
        )}
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-description`}>Description</label>
          <input id={`${formId}-description`} className="form-input" value={description} onChange={(e) => setDescription(e.target.value)} />
        </div>
      </form>
    </Modal>
  );
}
