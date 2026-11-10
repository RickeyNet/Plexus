import { useId, useState } from 'react';

import { Badge } from '@/components/Badge';
import { DataTable } from '@/components/DataTable';
import { useDialogs } from '@/components/DialogProvider-context';
import {
  SiemSink,
  SiemSinkStats,
  useCreateSiemSink,
  useDeleteSiemSink,
  useSiemSinks,
  useTestSiemSink,
  useUpdateSiemSink,
} from '@/api/settings';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { usePendingKeys } from '@/lib/usePendingKeys';

import {
  DeliveryStatsCells,
  NoticeCallout,
  RetryFields,
  RowActionsCell,
  TargetEditorModal,
  TargetTestsProvider,
  TestResultBadge,
} from './DeliveryTargets';
import { CheckboxField, CheckboxRow, FormRow, NumberField, TextField } from './FormFields';
import type { FormStatus } from './StatusLine';
import { isDirty } from './unsaved-context';

const PROTOCOLS: SiemSink['protocol'][] = ['udp', 'tcp', 'tls', 'https'];
const FORMATS: SiemSink['format'][] = ['cef', 'json'];
const SEVERITIES = ['debug', 'info', 'notice', 'warning', 'error', 'critical'];

const EMPTY_SINK: SiemSink = {
  id: '',
  name: '',
  enabled: true,
  protocol: 'udp',
  format: 'json',
  host: '',
  port: 514,
  url: '',
  bearer_token: '',
  tls_verify: true,
  tls_ca_pem: '',
  tls_client_cert_pem: '',
  tls_client_key_pem: '',
  severity_floor: 'info',
  queue_size: 1000,
  max_retries: 5,
  backoff_base: 1.0,
  backoff_cap: 60.0,
};

interface EditorState {
  draft: SiemSink;
  saved: SiemSink;
}

export function SiemTab() {
  const { confirm } = useDialogs();
  const query = useSiemSinks();
  const createMut = useCreateSiemSink();
  const updateMut = useUpdateSiemSink();
  const deleteMut = useDeleteSiemSink();
  const testMut = useTestSiemSink();
  const deleting = usePendingKeys<string>();
  const [editor, setEditor] = useState<EditorState | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [notice, setNotice] = useState<FormStatus | null>(null);

  if (query.isError && !query.data)
    return (
      <QueryError what="SIEM sinks" query={query} />
    );
  if (!query.data) return <LoadingState />;

  const sinks = query.data.sinks ?? [];
  const statsById = new Map<string, SiemSinkStats>(
    (query.data.stats ?? []).map((s) => [s.id, s]),
  );

  const target = (s: SiemSink) =>
    s.protocol === 'https' ? s.url : `${s.host}:${s.port}`;

  const openEditor = (s: SiemSink) => {
    setSaveError(null);
    setEditor({ draft: { ...s }, saved: { ...s } });
  };

  const onSave = () => {
    if (!editor) return;
    const editing = editor.draft;
    setSaveError(null);
    if (editing.id && sinks.some((s) => s.id === editing.id)) {
      updateMut.mutate(
        { id: editing.id, data: editing },
        {
          onSuccess: () => {
            setEditor(null);
            setNotice({ kind: 'success', message: `Sink ${editing.name || editing.id} saved.` });
          },
          onError: (err) => setSaveError(`Failed to save sink: ${(err as Error).message}`),
        },
      );
    } else {
      createMut.mutate(editing, {
        onSuccess: (saved) => {
          setEditor(null);
          setNotice({
            kind: 'success',
            message: `Sink ${saved?.name || saved?.id || ''} created.`,
          });
        },
        onError: (err) => setSaveError(`Failed to create sink: ${(err as Error).message}`),
      });
    }
  };

  const onDelete = async (s: SiemSink) => {
    if (
      !(await confirm({
        title: 'Delete SIEM sink',
        message: `Delete SIEM sink "${s.name || s.id}"? Audit events will stop being forwarded to this target.`,
        confirmLabel: 'Delete',
      }))
    )
      return;
    await deleting.run(s.id, async () => {
      try {
        await deleteMut.mutateAsync(s.id);
        setNotice({ kind: 'success', message: `Sink ${s.name || s.id} deleted.` });
      } catch (err) {
        setNotice({
          kind: 'error',
          message: `Failed to delete sink: ${(err as Error).message}`,
        });
      }
    });
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 'var(--space-3)' }}>
        <button
          className="btn btn-sm btn-primary"
          onClick={() => openEditor({ ...EMPTY_SINK })}
        >
          Add Sink
        </button>
      </div>

      <NoticeCallout notice={notice} onDismiss={() => setNotice(null)} />

      {sinks.length === 0 ? (
        <EmptyState compact message="No sinks configured. Add one to start forwarding audit events." />
      ) : (
        <TargetTestsProvider
          send={(id) => testMut.mutateAsync(id)}
          sentMessage={(name) => `Test event sent to ${name}.`}
          onOutcome={setNotice}
        >
          {(tests) => (
            <DataTable compact aria-label="SIEM sinks">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Target</th>
                  <th>Proto</th>
                  <th>Fmt</th>
                  <th>State</th>
                  <th>Queue</th>
                  <th>Delivered</th>
                  <th>Dropped</th>
                  <th>Last error</th>
                  <th>Last test</th>
                  <th aria-label="Actions"></th>
                </tr>
              </thead>
              <tbody>
                {sinks.map((s) => {
                  const name = s.name || s.id;
                  return (
                    <tr key={s.id}>
                      <td>{name}</td>
                      <td>
                        <span className="form-mono delivery-cell-truncate" title={target(s)}>
                          {target(s)}
                        </span>
                      </td>
                      <td>{s.protocol}</td>
                      <td>{s.format}</td>
                      <td>
                        <Badge tone={s.enabled ? 'success' : 'info'} size="sm">
                          {s.enabled ? 'Enabled' : 'Disabled'}
                        </Badge>
                      </td>
                      <DeliveryStatsCells stats={statsById.get(s.id)} />
                      <td>
                        <TestResultBadge result={tests.result(s.id)} />
                      </td>
                      <RowActionsCell
                        name={name}
                        testing={tests.isPending(s.id)}
                        deleting={deleting.isPending(s.id)}
                        onTest={() => void tests.test(s.id, name)}
                        onEdit={() => openEditor(s)}
                        onDelete={() => void onDelete(s)}
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
        <SinkEditor
          sink={editor.draft}
          dirty={isDirty(editor.draft, editor.saved)}
          existing={sinks}
          onChange={(draft) => setEditor({ ...editor, draft })}
          onClose={() => setEditor(null)}
          onSave={onSave}
          saving={createMut.isPending || updateMut.isPending}
          error={saveError}
        />
      )}
    </div>
  );
}

/** A PEM textarea: monospace, no spellcheck. */
function PemField({
  label,
  value,
  onChange,
  placeholder,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}) {
  const id = useId();
  return (
    <div className="form-group" style={{ flex: '1 1 320px' }}>
      <label className="form-label" htmlFor={id}>{label}</label>
      <textarea
        id={id}
        className="form-textarea"
        rows={6}
        spellCheck={false}
        autoComplete="off"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
      />
    </div>
  );
}

interface SinkEditorProps {
  sink: SiemSink;
  dirty: boolean;
  existing: SiemSink[];
  onChange: (next: SiemSink) => void;
  onClose: () => void;
  onSave: () => void;
  saving: boolean;
  error: string | null;
}

function SinkEditor({ sink, dirty, existing, onChange, onClose, onSave, saving, error }: SinkEditorProps) {
  const isEdit = Boolean(sink.id) && existing.some((s) => s.id === sink.id);
  const fid = useId();
  const set = <K extends keyof SiemSink>(key: K, value: SiemSink[K]) =>
    onChange({ ...sink, [key]: value });

  const showHttps = sink.protocol === 'https';
  const showTls = sink.protocol === 'tls' || sink.protocol === 'https';

  return (
    <TargetEditorModal
      title={isEdit ? 'Edit Sink' : 'New Sink'}
      formName="SIEM sink"
      dirty={dirty}
      saving={saving}
      primaryLabel={isEdit ? 'Save Changes' : 'Create Sink'}
      error={error}
      onSave={onSave}
      onClose={onClose}
    >
      <FormRow>
        <TextField
          label="Name"
          flex="1 1 220px"
          value={sink.name}
          onChange={(v) => set('name', v)}
          placeholder="e.g. Splunk HEC (prod)"
        />
        <div className="form-group" style={{ flex: '0 1 140px' }}>
          <label className="form-label" htmlFor={`${fid}-protocol`}>Protocol</label>
          <select
            id={`${fid}-protocol`}
            className="form-select"
            value={sink.protocol}
            onChange={(e) => set('protocol', e.target.value as SiemSink['protocol'])}
          >
            {PROTOCOLS.map((p) => (
              <option key={p} value={p}>
                {p.toUpperCase()}
              </option>
            ))}
          </select>
        </div>
        <div className="form-group" style={{ flex: '0 1 120px' }}>
          <label className="form-label" htmlFor={`${fid}-format`}>Format</label>
          <select
            id={`${fid}-format`}
            className="form-select"
            value={sink.format}
            onChange={(e) => set('format', e.target.value as SiemSink['format'])}
          >
            {FORMATS.map((f) => (
              <option key={f} value={f}>
                {f.toUpperCase()}
              </option>
            ))}
          </select>
        </div>
        <div className="form-group" style={{ flex: '0 1 140px' }}>
          <label className="form-label" htmlFor={`${fid}-severity-floor`}>Severity floor</label>
          <select
            id={`${fid}-severity-floor`}
            className="form-select"
            value={sink.severity_floor}
            onChange={(e) => set('severity_floor', e.target.value)}
          >
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </div>
        <CheckboxField inRow label="Enabled" checked={sink.enabled} onChange={(v) => set('enabled', v)} />
      </FormRow>

      {!showHttps && (
        <FormRow>
          <TextField
            label="Host"
            flex="1 1 240px"
            value={sink.host}
            onChange={(v) => set('host', v)}
            placeholder="siem.example.com"
          />
          <NumberField
            label="Port"
            flex="0 1 140px"
            min={1}
            max={65535}
            value={sink.port}
            onChange={(v) => set('port', v)}
          />
        </FormRow>
      )}

      {showHttps && (
        <>
          <TextField
            label="URL"
            value={sink.url}
            onChange={(v) => set('url', v)}
            placeholder="https://splunk.example.com:8088/services/collector"
          />
          <TextField
            label="Bearer token (optional)"
            type="password"
            value={sink.bearer_token}
            onChange={(v) => set('bearer_token', v)}
            placeholder="Leave blank or keep the existing token"
            help={
              <>
                Sent as <code>Authorization: Bearer …</code>. Leave the masked value (••••••••)
                to keep the currently stored token.
              </>
            }
          />
        </>
      )}

      {showTls && (
        <>
          <CheckboxRow>
            <CheckboxField
              label="Verify TLS certificate"
              checked={sink.tls_verify}
              onChange={(v) => set('tls_verify', v)}
            />
          </CheckboxRow>
          <PemField
            label="CA PEM (optional, pins trust)"
            value={sink.tls_ca_pem}
            onChange={(v) => set('tls_ca_pem', v)}
            placeholder={'-----BEGIN CERTIFICATE-----\n…'}
          />
          {sink.protocol === 'tls' && (
            <FormRow>
              <PemField
                label="Client cert PEM (mutual TLS)"
                value={sink.tls_client_cert_pem}
                onChange={(v) => set('tls_client_cert_pem', v)}
              />
              <PemField
                label="Client key PEM"
                value={sink.tls_client_key_pem}
                onChange={(v) => set('tls_client_key_pem', v)}
                placeholder="Leave the masked value (••••••••) to keep the existing key"
              />
            </FormRow>
          )}
        </>
      )}

      <RetryFields value={sink} onChange={(k, v) => set(k, v)} noun="audit event" />
    </TargetEditorModal>
  );
}
