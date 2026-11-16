import { useId, useState } from 'react';

import {
  type GitContentType,
  type GitSource,
  type GitSourceInput,
  useCreateGitSource,
  useUpdateGitSource,
} from '@/api/gitSources';
import { useServiceCredentialsList } from '@/api/settings';
import { Callout } from '@/components/Callout';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import { ModalActions } from '@/components/ModalActions';

import { CheckboxField } from './FormFields';
import {
  CONTENT_TYPE_HELP,
  CONTENT_TYPE_LABEL,
  GIT_INTERVAL_MAX,
  GIT_INTERVAL_MIN,
  type GitSourceErrors,
  emptyGitSource,
  toGitSourceInput,
  validateGitSource,
} from './gitSources';

type Field = keyof GitSourceErrors;

interface GitSourceModalProps {
  /** The source to edit; `null` adds one. */
  source: GitSource | null;
  contentTypes: GitContentType[];
  onClose: () => void;
}

/** Adds or edits a Git source. Saving does not sync; Sync now does. */
export function GitSourceModal({ source, contentTypes, onClose }: GitSourceModalProps) {
  const id = useId();
  const create = useCreateGitSource();
  const update = useUpdateGitSource();
  const credentials = useServiceCredentialsList();
  const [draft, setDraft] = useState<GitSourceInput>(() =>
    source ? toGitSourceInput(source) : emptyGitSource(contentTypes),
  );
  const [touched, setTouched] = useState<Partial<Record<Field, boolean>>>({});
  const [failure, setFailure] = useState<string | null>(null);

  const errors = validateGitSource(draft);
  const shown = (field: Field) => (touched[field] ? errors[field] : undefined);
  const touch = (field: Field) => setTouched((t) => ({ ...t, [field]: true }));
  const set = (patch: Partial<GitSourceInput>) => setDraft((d) => ({ ...d, ...patch }));
  const busy = create.isPending || update.isPending;

  const submit = () => {
    setTouched({ name: true, remote_url: true, branch: true, provides: true, interval: true });
    if (Object.keys(errors).length > 0) return;
    setFailure(null);
    const data = { ...draft, name: draft.name.trim(), remote_url: draft.remote_url.trim(), branch: draft.branch.trim() };
    const done = { onSuccess: onClose, onError: (e: Error) => setFailure(e.message) };
    if (source) update.mutate({ id: source.id, data }, done);
    else create.mutate(data, done);
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={source ? `Edit Git source ${source.name}` : 'Add Git source'}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={source ? 'Save source' : 'Add source'}
          primaryBusy={busy}
          primaryBusyLabel="Saving…"
          onPrimary={submit}
        />
      }
    >
      {failure && (
        <Callout tone="danger" title="The source was not saved">
          {failure} Check the fields and try again.
        </Callout>
      )}

      <div className="form-group">
        <label className="form-label" htmlFor={`${id}-name`}>Name</label>
        <input
          id={`${id}-name`}
          className="form-input"
          value={draft.name}
          autoFocus
          aria-invalid={!!shown('name')}
          aria-describedby={`${id}-name-error`}
          onChange={(e) => set({ name: e.target.value })}
          onBlur={() => touch('name')}
        />
        <FieldError id={`${id}-name-error`}>{shown('name')}</FieldError>
      </div>

      <div className="form-group">
        <label className="form-label" htmlFor={`${id}-url`}>Repository URL</label>
        <input
          id={`${id}-url`}
          className="form-input"
          value={draft.remote_url}
          spellCheck={false}
          aria-invalid={!!shown('remote_url')}
          aria-describedby={`${id}-url-help ${id}-url-error`}
          onChange={(e) => set({ remote_url: e.target.value })}
          onBlur={() => touch('remote_url')}
        />
        <div className="form-help" id={`${id}-url-help`}>
          https://git.example.com/netops/configs.git or git@git.example.com:netops/configs.git. Credentials never go
          in the URL.
        </div>
        <FieldError id={`${id}-url-error`}>{shown('remote_url')}</FieldError>
      </div>

      <div className="form-row">
        <div className="form-group" style={{ flex: '1 1 12rem' }}>
          <label className="form-label" htmlFor={`${id}-branch`}>Branch</label>
          <input
            id={`${id}-branch`}
            className="form-input"
            value={draft.branch}
            spellCheck={false}
            aria-invalid={!!shown('branch')}
            aria-describedby={`${id}-branch-error`}
            onChange={(e) => set({ branch: e.target.value })}
            onBlur={() => touch('branch')}
          />
          <FieldError id={`${id}-branch-error`}>{shown('branch')}</FieldError>
        </div>
        <div className="form-group" style={{ flex: '1 1 14rem' }}>
          <label className="form-label" htmlFor={`${id}-cred`}>Credential</label>
          <select
            id={`${id}-cred`}
            className="form-select"
            value={draft.credential_id ?? ''}
            aria-describedby={`${id}-cred-help`}
            onChange={(e) => set({ credential_id: e.target.value ? Number(e.target.value) : null })}
          >
            <option value="">None (public repository)</option>
            {(credentials.data || []).map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
                {c.username ? ` (${c.username})` : ''}
              </option>
            ))}
          </select>
          <div className="form-help" id={`${id}-cred-help`}>
            A service credential (Settings &gt; Authentication). HTTPS: user name and access token as the password.
            SSH: the private key as the password.
          </div>
        </div>
      </div>

      <fieldset
        className="form-group"
        style={{ border: 0, padding: 0, margin: 0 }}
        aria-describedby={`${id}-provides-error`}
        onBlur={(e) => {
          if (!e.currentTarget.contains(e.relatedTarget as Node | null)) touch('provides');
        }}
      >
        <legend className="form-label">Provides</legend>
        <div className="stack stack-sm">
          {contentTypes.map((type) => (
            <CheckboxField
              key={type}
              label={CONTENT_TYPE_LABEL[type]}
              help={CONTENT_TYPE_HELP[type]}
              checked={draft.provides.includes(type)}
              onChange={(on) =>
                set({
                  provides: contentTypes.filter((t) => (t === type ? on : draft.provides.includes(t))),
                })
              }
            />
          ))}
        </div>
        <FieldError id={`${id}-provides-error`}>{shown('provides')}</FieldError>
      </fieldset>

      <div className="form-group">
        <label className="form-label" htmlFor={`${id}-interval`}>Sync every (minutes)</label>
        <input
          id={`${id}-interval`}
          type="number"
          className="form-input"
          style={{ maxWidth: '10rem' }}
          min={0}
          max={GIT_INTERVAL_MAX}
          value={draft.sync_interval_minutes}
          aria-invalid={!!shown('interval')}
          aria-describedby={`${id}-interval-help ${id}-interval-error`}
          onChange={(e) => set({ sync_interval_minutes: Number(e.target.value) })}
          onBlur={() => touch('interval')}
        />
        <div className="form-help" id={`${id}-interval-help`}>
          0 syncs only when you choose Sync now; otherwise {GIT_INTERVAL_MIN} to {GIT_INTERVAL_MAX.toLocaleString()}.
        </div>
        <FieldError id={`${id}-interval-error`}>{shown('interval')}</FieldError>
      </div>

      <CheckboxField
        label="Enabled"
        checked={draft.enabled}
        onChange={(on) => set({ enabled: on })}
        help="A disabled source keeps its records but is not synced on a schedule."
      />
    </Modal>
  );
}
