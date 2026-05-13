import { useState } from 'react';

import {
  SiemSink,
  SiemSinkStats,
  useCreateSiemSink,
  useDeleteSiemSink,
  useSiemSinks,
  useTestSiemSink,
  useUpdateSiemSink,
} from '@/api/settings';

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

export function SiemTab() {
  const query = useSiemSinks();
  const createMut = useCreateSiemSink();
  const updateMut = useUpdateSiemSink();
  const deleteMut = useDeleteSiemSink();
  const testMut = useTestSiemSink();
  const [editing, setEditing] = useState<SiemSink | null>(null);
  const [status, setStatus] = useState<{ kind: 'success' | 'error'; message: string } | null>(null);
  const [testResults, setTestResults] = useState<Record<string, { ok: boolean; error: string }>>(
    {},
  );

  if (query.isLoading) return <p className="text-muted">Loading…</p>;
  if (query.isError)
    return (
      <div className="error">
        Failed to load SIEM sinks: {(query.error as Error).message}
      </div>
    );

  const sinks = query.data?.sinks ?? [];
  const statsById = new Map<string, SiemSinkStats>(
    (query.data?.stats ?? []).map((s) => [s.id, s]),
  );

  const target = (s: SiemSink) =>
    s.protocol === 'https' ? s.url : `${s.host}:${s.port}`;

  const onSave = () => {
    if (!editing) return;
    setStatus(null);
    if (editing.id && sinks.some((s) => s.id === editing.id)) {
      updateMut.mutate(
        { id: editing.id, data: editing },
        {
          onSuccess: () => {
            setEditing(null);
            setStatus({ kind: 'success', message: `Sink ${editing.name || editing.id} saved.` });
          },
          onError: (err) =>
            setStatus({
              kind: 'error',
              message: `Failed to save sink: ${(err as Error).message}`,
            }),
        },
      );
    } else {
      createMut.mutate(editing, {
        onSuccess: (saved) => {
          setEditing(null);
          setStatus({
            kind: 'success',
            message: `Sink ${saved?.name || saved?.id || ''} created.`,
          });
        },
        onError: (err) =>
          setStatus({
            kind: 'error',
            message: `Failed to create sink: ${(err as Error).message}`,
          }),
      });
    }
  };

  const onDelete = (s: SiemSink) => {
    if (!confirm(`Delete SIEM sink "${s.name || s.id}"? Audit events will stop being forwarded to this target.`))
      return;
    deleteMut.mutate(s.id, {
      onSuccess: () =>
        setStatus({ kind: 'success', message: `Sink ${s.name || s.id} deleted.` }),
      onError: (err) =>
        setStatus({
          kind: 'error',
          message: `Failed to delete sink: ${(err as Error).message}`,
        }),
    });
  };

  const onTest = (s: SiemSink) => {
    testMut.mutate(s.id, {
      onSuccess: (res) => setTestResults((prev) => ({ ...prev, [s.id]: res })),
      onError: (err) =>
        setTestResults((prev) => ({
          ...prev,
          [s.id]: { ok: false, error: (err as Error).message },
        })),
    });
  };

  return (
    <div className="card" style={{ padding: '1rem' }}>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '0.75rem',
          flexWrap: 'wrap',
          gap: '0.5rem',
        }}
      >
        <h3 style={{ margin: 0 }}>SIEM Audit-Event Forwarding</h3>
        <button
          className="btn btn-sm btn-primary"
          onClick={() => setEditing({ ...EMPTY_SINK })}
        >
          Add Sink
        </button>
      </div>

      <p className="text-muted" style={{ fontSize: '0.85rem', marginBottom: '0.75rem' }}>
        Configure one or more destinations for audit events. Each enabled sink receives
        every event that meets its severity floor. Delivery failures retry with exponential
        backoff; events are dropped from the oldest end of the queue when full.
      </p>

      {sinks.length === 0 ? (
        <p className="text-muted">No sinks configured. Add one to start forwarding audit events.</p>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table className="table" style={{ width: '100%', minWidth: '720px' }}>
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
                <th style={{ minWidth: '180px' }}>Last Error</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {sinks.map((s) => {
                const st = statsById.get(s.id);
                const result = testResults[s.id];
                return (
                  <tr key={s.id}>
                    <td>{s.name || s.id}</td>
                    <td style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>{target(s)}</td>
                    <td>{s.protocol}</td>
                    <td>{s.format}</td>
                    <td>
                      <span className={`badge ${s.enabled ? 'badge-success' : 'badge-info'}`}>
                        {s.enabled ? 'Enabled' : 'Disabled'}
                      </span>
                    </td>
                    <td>{st ? `${st.queue_depth}/${st.queue_size}` : '-'}</td>
                    <td>{st?.delivered ?? 0}</td>
                    <td>{(st?.dropped_queue_full ?? 0) + (st?.dropped_below_severity ?? 0)}</td>
                    <td
                      style={{
                        fontFamily: 'monospace',
                        fontSize: '0.78rem',
                        color: 'var(--text-muted)',
                        maxWidth: '240px',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                      title={st?.last_error || ''}
                    >
                      {result
                        ? result.ok
                          ? 'Test OK'
                          : `Test failed: ${result.error}`
                        : st?.last_error || ''}
                    </td>
                    <td style={{ whiteSpace: 'nowrap' }}>
                      <button className="btn btn-xs btn-ghost" onClick={() => onTest(s)}>
                        Test
                      </button>{' '}
                      <button className="btn btn-xs btn-ghost" onClick={() => setEditing({ ...s })}>
                        Edit
                      </button>{' '}
                      <button className="btn btn-xs btn-danger" onClick={() => onDelete(s)}>
                        Delete
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {status && (
        <div className={status.kind === 'success' ? 'success' : 'error'} style={{ marginTop: '0.75rem' }}>
          {status.message}
        </div>
      )}

      {editing && (
        <SinkEditor
          sink={editing}
          existing={sinks}
          onChange={setEditing}
          onCancel={() => setEditing(null)}
          onSave={onSave}
          saving={createMut.isPending || updateMut.isPending}
        />
      )}
    </div>
  );
}

interface SinkEditorProps {
  sink: SiemSink;
  existing: SiemSink[];
  onChange: (next: SiemSink) => void;
  onCancel: () => void;
  onSave: () => void;
  saving: boolean;
}

function SinkEditor({ sink, existing, onChange, onCancel, onSave, saving }: SinkEditorProps) {
  const isEdit = Boolean(sink.id) && existing.some((s) => s.id === sink.id);
  const set = <K extends keyof SiemSink>(key: K, value: SiemSink[K]) =>
    onChange({ ...sink, [key]: value });

  const showHttps = sink.protocol === 'https';
  const showTls = sink.protocol === 'tls' || sink.protocol === 'https';

  return (
    <div
      style={{
        marginTop: '1rem',
        padding: '0.75rem',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius, 6px)',
        background: 'var(--surface-2, rgba(255,255,255,0.02))',
      }}
    >
      <h4 style={{ marginTop: 0 }}>{isEdit ? 'Edit Sink' : 'New Sink'}</h4>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div className="form-group" style={{ flex: '1 1 220px' }}>
          <label className="form-label">Name</label>
          <input
            className="form-input"
            value={sink.name}
            onChange={(e) => set('name', e.target.value)}
            placeholder="e.g. Splunk HEC (prod)"
          />
        </div>
        <div className="form-group" style={{ flex: '0 1 160px' }}>
          <label className="form-label">Protocol</label>
          <select
            className="form-input"
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
        <div className="form-group" style={{ flex: '0 1 140px' }}>
          <label className="form-label">Format</label>
          <select
            className="form-input"
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
        <div className="form-group" style={{ flex: '0 1 160px' }}>
          <label className="form-label">Severity floor</label>
          <select
            className="form-input"
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
        <label
          className="form-group"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.4rem',
            marginTop: '1.4rem',
          }}
        >
          <input
            type="checkbox"
            checked={sink.enabled}
            onChange={(e) => set('enabled', e.target.checked)}
          />
          <span>Enabled</span>
        </label>
      </div>

      {!showHttps && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', marginTop: '0.5rem' }}>
          <div className="form-group" style={{ flex: '1 1 240px' }}>
            <label className="form-label">Host</label>
            <input
              className="form-input"
              value={sink.host}
              onChange={(e) => set('host', e.target.value)}
              placeholder="siem.internal"
            />
          </div>
          <div className="form-group" style={{ flex: '0 1 140px' }}>
            <label className="form-label">Port</label>
            <input
              type="number"
              className="form-input"
              min={1}
              max={65535}
              value={sink.port}
              onChange={(e) => set('port', Number(e.target.value))}
            />
          </div>
        </div>
      )}

      {showHttps && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', marginTop: '0.5rem' }}>
          <div className="form-group" style={{ flex: '1 1 100%' }}>
            <label className="form-label">URL</label>
            <input
              className="form-input"
              value={sink.url}
              onChange={(e) => set('url', e.target.value)}
              placeholder="https://splunk.example.com:8088/services/collector"
            />
          </div>
          <div className="form-group" style={{ flex: '1 1 100%' }}>
            <label className="form-label">Bearer token (optional)</label>
            <input
              className="form-input"
              type="password"
              value={sink.bearer_token}
              onChange={(e) => set('bearer_token', e.target.value)}
              placeholder="Leave blank or keep the existing token"
            />
            <div className="text-muted" style={{ fontSize: '0.78rem', marginTop: '0.2rem' }}>
              Sent as <code>Authorization: Bearer …</code>. Leave the masked value (••••••••)
              to keep the currently stored token.
            </div>
          </div>
        </div>
      )}

      {showTls && (
        <div style={{ marginTop: '0.5rem' }}>
          <label
            className="form-group"
            style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}
          >
            <input
              type="checkbox"
              checked={sink.tls_verify}
              onChange={(e) => set('tls_verify', e.target.checked)}
            />
            <span>Verify TLS certificate</span>
          </label>
          <div className="form-group" style={{ marginTop: '0.4rem' }}>
            <label className="form-label">CA PEM (optional, pins trust)</label>
            <textarea
              className="form-input"
              rows={4}
              value={sink.tls_ca_pem}
              onChange={(e) => set('tls_ca_pem', e.target.value)}
              placeholder={'-----BEGIN CERTIFICATE-----\n…'}
            />
          </div>
          {sink.protocol === 'tls' && (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem' }}>
              <div className="form-group" style={{ flex: '1 1 320px' }}>
                <label className="form-label">Client cert PEM (mutual TLS)</label>
                <textarea
                  className="form-input"
                  rows={4}
                  value={sink.tls_client_cert_pem}
                  onChange={(e) => set('tls_client_cert_pem', e.target.value)}
                />
              </div>
              <div className="form-group" style={{ flex: '1 1 320px' }}>
                <label className="form-label">Client key PEM</label>
                <textarea
                  className="form-input"
                  rows={4}
                  value={sink.tls_client_key_pem}
                  onChange={(e) => set('tls_client_key_pem', e.target.value)}
                  placeholder="Leave the masked value (••••••••) to keep the existing key"
                />
              </div>
            </div>
          )}
        </div>
      )}

      <details style={{ marginTop: '0.5rem' }}>
        <summary style={{ cursor: 'pointer' }}>Advanced (queue, retry, backoff)</summary>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', marginTop: '0.5rem' }}>
          <div className="form-group" style={{ flex: '0 1 160px' }}>
            <label className="form-label">Queue size</label>
            <input
              type="number"
              className="form-input"
              min={10}
              max={100000}
              value={sink.queue_size}
              onChange={(e) => set('queue_size', Number(e.target.value))}
            />
          </div>
          <div className="form-group" style={{ flex: '0 1 160px' }}>
            <label className="form-label">Max retries</label>
            <input
              type="number"
              className="form-input"
              min={0}
              max={20}
              value={sink.max_retries}
              onChange={(e) => set('max_retries', Number(e.target.value))}
            />
          </div>
          <div className="form-group" style={{ flex: '0 1 160px' }}>
            <label className="form-label">Backoff base (s)</label>
            <input
              type="number"
              className="form-input"
              min={0.1}
              max={30}
              step="0.1"
              value={sink.backoff_base}
              onChange={(e) => set('backoff_base', Number(e.target.value))}
            />
          </div>
          <div className="form-group" style={{ flex: '0 1 160px' }}>
            <label className="form-label">Backoff cap (s)</label>
            <input
              type="number"
              className="form-input"
              min={1}
              max={600}
              value={sink.backoff_cap}
              onChange={(e) => set('backoff_cap', Number(e.target.value))}
            />
          </div>
        </div>
      </details>

      <div style={{ marginTop: '0.75rem', display: 'flex', gap: '0.5rem' }}>
        <button className="btn btn-primary" onClick={onSave} disabled={saving}>
          {saving ? 'Saving…' : isEdit ? 'Save Changes' : 'Create Sink'}
        </button>
        <button className="btn btn-ghost" onClick={onCancel} disabled={saving}>
          Cancel
        </button>
      </div>
    </div>
  );
}
