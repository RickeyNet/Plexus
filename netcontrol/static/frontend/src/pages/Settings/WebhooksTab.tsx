import { useId, useState } from 'react';

import { Badge } from '@/components/Badge';
import { DataTable } from '@/components/DataTable';
import { useDialogs } from '@/components/DialogProvider-context';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { usePendingKeys } from '@/lib/usePendingKeys';
import {
  type Webhook,
  type WebhookStats,
  useCreateWebhook,
  useDeleteWebhook,
  useTestWebhook,
  useUpdateWebhook,
  useWebhooks,
} from '@/api/webhooks';

import {
  NoticeCallout,
  RowActionsCell,
  TargetEditorModal,
  TargetTestsProvider,
  TestResultBadge,
} from './DeliveryTargets';
import { CheckboxField, CheckboxRow, FormRow, NumberField, TextField } from './FormFields';
import type { FormStatus } from './StatusLine';
import { isDirty } from './unsaved-context';
import { WebhookDeliveriesModal } from './WebhookDeliveriesModal';
import {
  EMPTY_DRAFT,
  OBJECT_TYPE_LABELS,
  type WebhookDraft,
  draftFromWebhook,
  payloadFromDraft,
  toggleIn,
} from './webhookForm';

const METHODS = ['POST', 'PUT', 'PATCH'];

interface EditorState {
  draft: WebhookDraft;
  saved: WebhookDraft;
}

export function WebhooksTab() {
  const { confirm } = useDialogs();
  const query = useWebhooks();
  const createMut = useCreateWebhook();
  const updateMut = useUpdateWebhook();
  const deleteMut = useDeleteWebhook();
  const testMut = useTestWebhook();
  const deleting = usePendingKeys<number>();
  const [editor, setEditor] = useState<EditorState | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [notice, setNotice] = useState<FormStatus | null>(null);
  const [logFor, setLogFor] = useState<Webhook | null>(null);

  if (query.isError && !query.data) return <QueryError what="webhooks" query={query} />;
  if (!query.data) return <LoadingState />;

  const hooks = query.data.webhooks ?? [];
  const objectTypes = query.data.object_types ?? Object.keys(OBJECT_TYPE_LABELS);
  const actions = query.data.actions ?? ['create', 'update', 'delete'];
  const statsById = new Map<number, WebhookStats>((query.data.stats ?? []).map((s) => [s.id, s]));

  const openEditor = (draft: WebhookDraft) => {
    setSaveError(null);
    setEditor({ draft: { ...draft }, saved: { ...draft } });
  };

  const onSave = () => {
    if (!editor) return;
    const draft = editor.draft;
    const data = payloadFromDraft(draft);
    setSaveError(null);
    const done = (verb: string) => () => {
      setEditor(null);
      setNotice({ kind: 'success', message: `Webhook ${data.name} ${verb}.` });
    };
    if (draft.id != null) {
      updateMut.mutate(
        { id: draft.id, data },
        { onSuccess: done('saved'), onError: (err) => setSaveError(`Failed to save webhook: ${(err as Error).message}`) },
      );
    } else {
      createMut.mutate(data, {
        onSuccess: done('created'),
        onError: (err) => setSaveError(`Failed to create webhook: ${(err as Error).message}`),
      });
    }
  };

  const onDelete = async (w: Webhook) => {
    if (
      !(await confirm({
        title: 'Delete webhook',
        message: `Delete webhook "${w.name}" and its delivery log? Changes will stop being sent to it.`,
        confirmLabel: 'Delete webhook',
      }))
    )
      return;
    await deleting.run(w.id, async () => {
      try {
        await deleteMut.mutateAsync(w.id);
        setNotice({ kind: 'success', message: `Webhook ${w.name} deleted.` });
      } catch (err) {
        setNotice({ kind: 'error', message: `Failed to delete webhook: ${(err as Error).message}` });
      }
    });
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 'var(--space-3)' }}>
        <button type="button" className="btn btn-sm btn-primary" onClick={() => openEditor(EMPTY_DRAFT)}>
          Add Webhook
        </button>
      </div>

      <NoticeCallout notice={notice} onDismiss={() => setNotice(null)} />

      {hooks.length === 0 ? (
        <EmptyState
          compact
          message="No webhooks yet. Add one to send a signed HTTP request whenever a host, prefix or other object changes."
        />
      ) : (
        <TargetTestsProvider
          send={(id) => testMut.mutateAsync(Number(id))}
          sentMessage={(name) => `Test event delivered to ${name}.`}
          onOutcome={setNotice}
        >
          {(tests) => (
            <DataTable compact aria-label="Webhooks">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Target</th>
                  <th>Objects</th>
                  <th>Actions</th>
                  <th>State</th>
                  <th>Delivered</th>
                  <th>Failed</th>
                  <th>Last error</th>
                  <th>Last test</th>
                  <th aria-label="Delivery log"></th>
                  <th aria-label="Row actions"></th>
                </tr>
              </thead>
              <tbody>
                {hooks.map((w) => {
                  const stats = statsById.get(w.id);
                  const target = `${w.http_method} ${w.url}`;
                  return (
                    <tr key={w.id}>
                      <td>{w.name}</td>
                      <td>
                        <span className="form-mono delivery-cell-truncate" title={target}>
                          {target}
                        </span>
                      </td>
                      <td>{w.object_types.map((t) => OBJECT_TYPE_LABELS[t] ?? t).join(', ')}</td>
                      <td>{w.actions.join(', ')}</td>
                      <td>
                        <Badge tone={w.enabled ? 'success' : 'info'} size="sm">
                          {w.enabled ? 'Enabled' : 'Disabled'}
                        </Badge>
                      </td>
                      <td>{stats?.delivered ?? 0}</td>
                      <td>{(stats?.failed ?? 0) + (stats?.dropped_queue_full ?? 0)}</td>
                      <td className="text-muted">
                        {stats?.last_error ? (
                          <span className="form-mono delivery-cell-truncate" title={stats.last_error}>
                            {stats.last_error}
                          </span>
                        ) : (
                          '-'
                        )}
                      </td>
                      <td>
                        <TestResultBadge result={tests.result(String(w.id))} />
                      </td>
                      <td>
                        <button
                          type="button"
                          className="btn btn-xs btn-secondary"
                          onClick={() => setLogFor(w)}
                          aria-label={`Show deliveries of ${w.name}`}
                        >
                          Deliveries
                        </button>
                      </td>
                      <RowActionsCell
                        name={w.name}
                        testing={tests.isPending(String(w.id))}
                        deleting={deleting.isPending(w.id)}
                        onTest={() => void tests.test(String(w.id), w.name)}
                        onEdit={() => openEditor(draftFromWebhook(w))}
                        onDelete={() => void onDelete(w)}
                      />
                    </tr>
                  );
                })}
              </tbody>
            </DataTable>
          )}
        </TargetTestsProvider>
      )}

      {editor && (
        <WebhookEditor
          draft={editor.draft}
          dirty={isDirty(editor.draft, editor.saved)}
          objectTypes={objectTypes}
          actions={actions}
          onChange={(draft) => setEditor({ ...editor, draft })}
          onClose={() => setEditor(null)}
          onSave={onSave}
          saving={createMut.isPending || updateMut.isPending}
          error={saveError}
        />
      )}

      {logFor && <WebhookDeliveriesModal webhook={logFor} onClose={() => setLogFor(null)} onOutcome={setNotice} />}
    </div>
  );
}

interface WebhookEditorProps {
  draft: WebhookDraft;
  dirty: boolean;
  objectTypes: string[];
  actions: string[];
  onChange: (next: WebhookDraft) => void;
  onClose: () => void;
  onSave: () => void;
  saving: boolean;
  error: string | null;
}

function WebhookEditor({ draft, dirty, objectTypes, actions, onChange, onClose, onSave, saving, error }: WebhookEditorProps) {
  const fid = useId();
  const isEdit = draft.id != null;
  const set = <K extends keyof WebhookDraft>(key: K, value: WebhookDraft[K]) => onChange({ ...draft, [key]: value });
  const setHeader = (i: number, key: 'name' | 'value', value: string) =>
    set(
      'headers',
      draft.headers.map((h, j) => (j === i ? { ...h, [key]: value } : h)),
    );

  return (
    <TargetEditorModal
      title={isEdit ? 'Edit Webhook' : 'New Webhook'}
      formName="Webhook"
      dirty={dirty}
      saving={saving}
      primaryLabel={isEdit ? 'Save Changes' : 'Create Webhook'}
      error={error}
      onSave={onSave}
      onClose={onClose}
    >
      <FormRow>
        <TextField label="Name" flex="1 1 220px" value={draft.name} onChange={(v) => set('name', v)} />
        <CheckboxField inRow label="Enabled" checked={draft.enabled} onChange={(v) => set('enabled', v)} />
      </FormRow>
      <FormRow>
        <div className="form-group" style={{ flex: '0 1 120px' }}>
          <label className="form-label" htmlFor={`${fid}-method`}>Method</label>
          <select
            id={`${fid}-method`}
            className="form-select"
            value={draft.http_method}
            onChange={(e) => set('http_method', e.target.value)}
          >
            {METHODS.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
        </div>
        <TextField
          label="Target URL"
          flex="1 1 320px"
          value={draft.url}
          onChange={(v) => set('url', v)}
          placeholder="https://hooks.example.com/plexus"
        />
      </FormRow>

      <fieldset className="form-group">
        <legend className="form-label">Objects</legend>
        <CheckboxRow>
          {objectTypes.map((t) => (
            <CheckboxField
              key={t}
              label={OBJECT_TYPE_LABELS[t] ?? t}
              checked={draft.object_types.includes(t)}
              onChange={(on) => set('object_types', toggleIn(draft.object_types, t, on, objectTypes))}
            />
          ))}
        </CheckboxRow>
      </fieldset>
      <fieldset className="form-group">
        <legend className="form-label">Actions</legend>
        <CheckboxRow>
          {actions.map((a) => (
            <CheckboxField
              key={a}
              label={a}
              checked={draft.actions.includes(a)}
              onChange={(on) => set('actions', toggleIn(draft.actions, a, on, actions))}
            />
          ))}
        </CheckboxRow>
      </fieldset>

      <TextField
        label="Only these inventory groups (optional)"
        value={draft.group_ids}
        onChange={(v) => set('group_ids', v)}
        placeholder="e.g. 3, 7"
        help="Group ids, comma separated. Sends only changes to objects in these groups (a group itself matches its own id). Empty sends every change."
      />

      <TextField
        label="Signing secret (optional)"
        type="password"
        value={draft.secret}
        onChange={(v) => set('secret', v)}
        autoComplete="new-password"
        help="Signs each body as X-Plexus-Signature-256 (HMAC-SHA256). Leave masked (••••••••) to keep the stored secret; clear it to stop signing."
      />

      <fieldset className="form-group">
        <legend className="form-label">Custom headers</legend>
        {draft.headers.map((h, i) => (
          <FormRow key={i}>
            <TextField
              label={`Header ${i + 1} name`}
              flex="1 1 180px"
              value={h.name}
              onChange={(v) => setHeader(i, 'name', v)}
              placeholder="Authorization"
            />
            <TextField
              label={`Header ${i + 1} value`}
              type="password"
              flex="1 1 220px"
              value={h.value}
              onChange={(v) => setHeader(i, 'value', v)}
              autoComplete="off"
            />
            <div className="form-group form-check-field">
              <span className="form-label" aria-hidden="true">
                &nbsp;
              </span>
              <button
                type="button"
                className="btn btn-sm btn-ghost"
                onClick={() => set('headers', draft.headers.filter((_, j) => j !== i))}
                aria-label={`Remove header ${h.name || i + 1}`}
              >
                Remove
              </button>
            </div>
          </FormRow>
        ))}
        <div>
          <button
            type="button"
            className="btn btn-sm btn-secondary"
            onClick={() => set('headers', [...draft.headers, { name: '', value: '' }])}
          >
            Add Header
          </button>
        </div>
        <div className="form-help">Values are stored encrypted and shown masked; leave a mask to keep that value.</div>
      </fieldset>

      <details>
        <summary style={{ cursor: 'pointer', marginBottom: 'var(--space-3)' }}>
          Advanced (body template, TLS, retries)
        </summary>
        <TextField
          label="Content type"
          value={draft.content_type}
          onChange={(v) => set('content_type', v)}
          placeholder="application/json"
        />
        <div className="form-group">
          <label className="form-label" htmlFor={`${fid}-template`}>Body template (optional)</label>
          <textarea
            id={`${fid}-template`}
            className="form-textarea"
            rows={6}
            spellCheck={false}
            value={draft.body_template}
            onChange={(e) => set('body_template', e.target.value)}
            placeholder={'{"text": "{{ event }} {{ object_type }} {{ object_id }} by {{ user }}"}'}
            aria-describedby={`${fid}-template-help`}
          />
          <div className="form-help" id={`${fid}-template-help`}>
            Jinja2, rendered in the same sandbox as config templates. Every payload field is a variable, and{' '}
            <code>payload</code> is the whole document (<code>{'{{ payload | tojson }}'}</code>). Empty sends the
            JSON payload.
          </div>
        </div>
        <CheckboxRow>
          <CheckboxField
            label="Verify TLS certificate"
            checked={draft.verify_tls}
            onChange={(v) => set('verify_tls', v)}
          />
        </CheckboxRow>
        <div className="form-group">
          <label className="form-label" htmlFor={`${fid}-ca`}>CA bundle (PEM, optional)</label>
          <textarea
            id={`${fid}-ca`}
            className="form-textarea"
            rows={4}
            spellCheck={false}
            value={draft.ca_bundle}
            onChange={(e) => set('ca_bundle', e.target.value)}
            placeholder="-----BEGIN CERTIFICATE-----"
          />
        </div>
        <FormRow>
          <NumberField
            label="Timeout (s)"
            min={1}
            max={60}
            value={draft.timeout_seconds}
            onChange={(v) => set('timeout_seconds', v)}
          />
          <NumberField
            label="Max retries"
            min={0}
            max={10}
            value={draft.max_retries}
            onChange={(v) => set('max_retries', v)}
            help="Retries after a timeout, HTTP 408/429 or 5xx, with doubling backoff."
          />
          <NumberField
            label="Concurrency"
            min={1}
            max={10}
            value={draft.concurrency}
            onChange={(v) => set('concurrency', v)}
            help="Requests in flight at once to this webhook."
          />
        </FormRow>
      </details>
    </TargetEditorModal>
  );
}
