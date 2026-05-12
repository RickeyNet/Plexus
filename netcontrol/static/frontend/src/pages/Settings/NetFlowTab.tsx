import { useEffect, useState } from 'react';

import {
  FlowCollectorConfig,
  useFlowCollectorConfig,
  useUpdateFlowCollectorConfig,
} from '@/api/settings';

export function NetFlowTab() {
  const query = useFlowCollectorConfig();
  const update = useUpdateFlowCollectorConfig();

  const [draft, setDraft] = useState<FlowCollectorConfig | null>(null);
  const [status, setStatus] = useState<{ kind: 'success' | 'error'; message: string } | null>(
    null,
  );

  useEffect(() => {
    if (query.data) setDraft(query.data);
  }, [query.data]);

  if (query.isLoading || !draft) return <p className="text-muted">Loading…</p>;
  if (query.isError)
    return (
      <div className="error">
        Failed to load NetFlow config: {(query.error as Error).message}
      </div>
    );

  const num = (
    label: string,
    key: keyof FlowCollectorConfig,
    min: number,
    flex = '0 1 180px',
    help?: string,
  ) => (
    <div className="form-group" style={{ flex }}>
      <label className="form-label">{label}</label>
      <input
        type="number"
        min={min}
        className="form-input"
        value={draft[key] as number}
        onChange={(e) => setDraft({ ...draft, [key]: Number(e.target.value) })}
      />
      {help && (
        <div className="text-muted" style={{ fontSize: '0.78rem', marginTop: '0.2rem' }}>
          {help}
        </div>
      )}
    </div>
  );

  const running = query.data?.netflow_running ?? false;
  const sflowRunning = query.data?.sflow_running ?? false;

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
        <h3 style={{ margin: 0 }}>NetFlow / sFlow Collector</h3>
        <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
          <span
            className="badge"
            style={{
              background: running ? 'var(--success-bg, #1f6f3f)' : 'var(--muted-bg, #444)',
              color: '#fff',
              padding: '0.15rem 0.5rem',
              borderRadius: '999px',
              fontSize: '0.78rem',
            }}
          >
            NetFlow {running ? 'running' : 'stopped'}
          </span>
          <span
            className="badge"
            style={{
              background: sflowRunning ? 'var(--success-bg, #1f6f3f)' : 'var(--muted-bg, #444)',
              color: '#fff',
              padding: '0.15rem 0.5rem',
              borderRadius: '999px',
              fontSize: '0.78rem',
            }}
          >
            sFlow {sflowRunning ? 'running' : 'stopped'}
          </span>
        </div>
      </div>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          setStatus(null);
          update.mutate(draft, {
            onSuccess: (saved) => {
              setDraft(saved);
              setStatus({
                kind: 'success',
                message:
                  'NetFlow configuration saved' +
                  (saved.enabled
                    ? saved.netflow_running
                      ? ' — collector running.'
                      : ' — collector failed to start (check logs).'
                    : ' — collector stopped.'),
              });
            },
            onError: (err) =>
              setStatus({
                kind: 'error',
                message: `Failed to save NetFlow config: ${(err as Error).message}`,
              }),
          });
        }}
      >
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem' }}>
          <label
            className="form-group"
            style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}
          >
            <input
              type="checkbox"
              checked={draft.enabled}
              onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })}
            />
            <span>Enabled</span>
          </label>
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', marginTop: '0.5rem' }}>
          {num('NetFlow / IPFIX port', 'netflow_port', 1, '0 1 180px', 'UDP, default 2055')}
          {num('sFlow port', 'sflow_port', 0, '0 1 180px', 'UDP, default 6343 (set 0 to disable)')}
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', marginTop: '0.5rem' }}>
          {num(
            'Raw retention (hours)',
            'retention_hours',
            1,
            '0 1 200px',
            'Raw flow_records older than this are purged.',
          )}
          {num(
            'Summary retention (days)',
            'summary_retention_days',
            1,
            '0 1 200px',
            'Hourly aggregates kept this long.',
          )}
          {num(
            'Aggregation interval (s)',
            'aggregation_interval_seconds',
            60,
            '0 1 200px',
            'How often raw records roll up into summaries.',
          )}
        </div>

        <div className="text-muted" style={{ fontSize: '0.78rem', marginTop: '0.5rem' }}>
          Saving here applies the change immediately — port/toggle edits rebind the UDP
          listeners on the fly, so no restart is required.
        </div>

        <div style={{ marginTop: '0.75rem' }}>
          <button type="submit" className="btn btn-primary" disabled={update.isPending}>
            {update.isPending ? 'Saving…' : 'Save NetFlow Settings'}
          </button>
        </div>

        {status && (
          <div
            className={status.kind === 'error' ? 'error' : ''}
            style={{
              marginTop: '0.5rem',
              color: status.kind === 'error' ? undefined : 'var(--success)',
            }}
          >
            {status.message}
          </div>
        )}
      </form>
    </div>
  );
}
