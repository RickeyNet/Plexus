import { useId, useState } from 'react';

import {
  McpTokenCreated,
  useAdminUsers,
  useCreateMcpToken,
} from '@/api/settings';
import { BusyButton } from '@/components/BusyButton';
import { Callout } from '@/components/Callout';
import { CopyButton } from '@/components/CopyButton';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';

import {
  CATEGORY_HELP,
  DATA_NOTICE,
  TOKEN_NAME_MAX,
  TokenFormErrors,
  connectionSnippets,
  validateTokenForm,
} from './aiAccess';

type Field = keyof TokenFormErrors;

/**
 * Creates an MCP token. After the token is created the same dialog shows it,
 * once, with connection settings to copy; it cannot be shown again.
 */
export function McpTokenModal({ categories, onClose }: { categories: string[]; onClose: () => void }) {
  const users = useAdminUsers();
  const create = useCreateMcpToken();
  const id = useId();

  const [name, setName] = useState('');
  const [ownerId, setOwnerId] = useState<number | null>(null);
  const [chosen, setChosen] = useState<string[]>([]);
  const [expiresAt, setExpiresAt] = useState('');
  const [touched, setTouched] = useState<Partial<Record<Field, boolean>>>({});
  const [failure, setFailure] = useState<string | null>(null);
  const [created, setCreated] = useState<McpTokenCreated | null>(null);

  const owner = (users.data || []).find((u) => u.id === ownerId);
  const ownerIsAdmin = owner?.role === 'admin';
  const form = { name, ownerId, ownerIsAdmin, categories: chosen, expiresAt };
  const errors = validateTokenForm(form);
  const shown = (field: Field) => (touched[field] ? errors[field] : undefined);
  const touch = (field: Field) => setTouched((t) => ({ ...t, [field]: true }));

  if (created) {
    return (
      <Modal isOpen onClose={onClose} title="Copy your token" dismissible={false} footer={
        <button type="button" className="btn btn-primary" onClick={onClose}>
          Close
        </button>
      }>
        <Callout tone="warning" title="This token is shown once. Store it now.">
          Plexus keeps only a hash of it. If it is lost, revoke it and create another.
        </Callout>

        <div className="form-group">
          <label className="form-label" htmlFor={`${id}-token`}>Token for {created.record.name}</label>
          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            <input
              id={`${id}-token`}
              className="form-input"
              style={{ flex: '1 1 16rem', fontFamily: 'var(--font-mono, monospace)' }}
              readOnly
              value={created.token}
              onFocus={(e) => e.currentTarget.select()}
            />
            <CopyButton text={created.token} label="Copy token" className="btn btn-primary" />
          </div>
        </div>

        <h4 style={{ margin: 'var(--space-3) 0 var(--space-2) 0' }}>Connect a client</h4>
        <div className="stack stack-sm">
          {connectionSnippets(window.location.origin, created.token).map((snippet) => (
            <div key={snippet.label} className="card-inset">
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: '0.5rem', flexWrap: 'wrap' }}>
                <div>
                  <strong>{snippet.label}</strong>
                  <div className="form-help">{snippet.hint}</div>
                </div>
                <CopyButton text={snippet.text} label={`Copy ${snippet.label} settings`} />
              </div>
              <pre style={{ margin: '0.5rem 0 0 0', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>
                {snippet.text}
              </pre>
            </div>
          ))}
        </div>
        <p className="form-help">{DATA_NOTICE}</p>
      </Modal>
    );
  }

  const submit = () => {
    setTouched({ name: true, owner: true, categories: true, expiresAt: true });
    if (Object.keys(errors).length > 0 || ownerId === null) return;
    setFailure(null);
    create.mutate(
      { name: name.trim(), owner_user_id: ownerId, categories: chosen, expires_at: expiresAt },
      { onSuccess: setCreated, onError: (e) => setFailure((e as Error).message) },
    );
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title="Create token"
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <BusyButton className="btn btn-primary" busy={create.isPending} busyLabel="Creating…" onClick={submit}>
            Create token
          </BusyButton>
        </>
      }
    >
      {failure && (
        <Callout tone="danger" title="The token was not created">
          {failure} Check the fields and try again.
        </Callout>
      )}

      <div className="form-group">
        <label className="form-label" htmlFor={`${id}-name`}>Name</label>
        <input
          id={`${id}-name`}
          className="form-input"
          value={name}
          maxLength={TOKEN_NAME_MAX + 1}
          autoFocus
          aria-invalid={!!shown('name')}
          aria-describedby={`${id}-name-help ${id}-name-error`}
          onChange={(e) => setName(e.target.value)}
          onBlur={() => touch('name')}
        />
        <div className="form-help" id={`${id}-name-help`}>
          Shown in this list and in the audit log. Name the client or person that uses it.
        </div>
        <FieldError id={`${id}-name-error`}>{shown('name')}</FieldError>
      </div>

      <div className="form-group">
        <label className="form-label" htmlFor={`${id}-owner`}>Owner</label>
        <select
          id={`${id}-owner`}
          className="form-select"
          value={ownerId ?? ''}
          aria-invalid={!!shown('owner')}
          aria-describedby={`${id}-owner-help ${id}-owner-error`}
          onChange={(e) => setOwnerId(e.target.value ? Number(e.target.value) : null)}
          onBlur={() => touch('owner')}
        >
          <option value="">Choose a user</option>
          {(users.data || []).map((u) => (
            <option key={u.id} value={u.id}>
              {u.username}
              {u.role === 'admin' ? ' (admin)' : ''}
            </option>
          ))}
        </select>
        <div className="form-help" id={`${id}-owner-help`}>
          The token can read only what this user can. Removing a feature from the user narrows the token
          at once.
        </div>
        <FieldError id={`${id}-owner-error`}>{shown('owner')}</FieldError>
      </div>

      <fieldset
        className="form-group"
        style={{ border: 0, padding: 0, margin: 0 }}
        aria-describedby={`${id}-categories-error`}
        onBlur={(e) => {
          if (!e.currentTarget.contains(e.relatedTarget as Node | null)) touch('categories');
        }}
      >
        <legend className="form-label">Data categories</legend>
        <div className="stack stack-sm">
          {categories.map((category) => {
            const blocked = category === 'audit' && !ownerIsAdmin;
            return (
              <label key={category} className="form-check" style={{ alignItems: 'flex-start' }}>
                <input
                  type="checkbox"
                  checked={chosen.includes(category)}
                  disabled={blocked && !chosen.includes(category)}
                  onChange={(e) =>
                    setChosen(e.target.checked ? [...chosen, category] : chosen.filter((c) => c !== category))
                  }
                />
                <span>
                  <strong>{category}</strong>
                  <span className="form-help" style={{ display: 'block', margin: 0 }}>
                    {CATEGORY_HELP[category] || ''}
                    {blocked ? ' Choose an admin owner to enable it.' : ''}
                  </span>
                </span>
              </label>
            );
          })}
        </div>
        <FieldError id={`${id}-categories-error`}>{shown('categories')}</FieldError>
      </fieldset>

      <div className="form-group">
        <label className="form-label" htmlFor={`${id}-expires`}>Expiry date (optional)</label>
        <input
          id={`${id}-expires`}
          type="date"
          className="form-input"
          style={{ maxWidth: '14rem' }}
          value={expiresAt}
          aria-invalid={!!shown('expiresAt')}
          aria-describedby={`${id}-expires-help ${id}-expires-error`}
          onChange={(e) => setExpiresAt(e.target.value)}
          onBlur={() => touch('expiresAt')}
        />
        <div className="form-help" id={`${id}-expires-help`}>
          The token works through the end of this day (UTC). Leave empty for no expiry.
        </div>
        <FieldError id={`${id}-expires-error`}>{shown('expiresAt')}</FieldError>
      </div>
    </Modal>
  );
}
