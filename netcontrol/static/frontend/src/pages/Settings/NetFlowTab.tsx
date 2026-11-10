import { useId, useState } from 'react';

import {
  FlowCollectorConfig,
  useFlowCollectorConfig,
  useUpdateFlowCollectorConfig,
} from '@/api/settings';
import { Badge } from '@/components/Badge';
import { BusyButton } from '@/components/BusyButton';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';

import { FormStatus, StatusLine } from './StatusLine';

export function NetFlowTab() {
  const query = useFlowCollectorConfig();
  const update = useUpdateFlowCollectorConfig();
  const fid = useId();

  const [draft, setDraft] = useState<FlowCollectorConfig | null>(null);
  const [status, setStatus] = useState<FormStatus | null>(null);
  const [prevData, setPrevData] = useState(query.data);
  if (query.data !== prevData) {
    setPrevData(query.data);
    if (query.data) setDraft(query.data);
  }

  if (!draft) {
    if (query.isError)
      return (
        <QueryError what="NetFlow config" query={query} />
      );
    return <LoadingState />;
  }

  const num = (
    label: string,
    key: keyof FlowCollectorConfig,
    min: number,
    flex = '0 1 180px',
    help?: string,
  ) => (
    <div className="form-group" style={{ flex }}>
      <label className="form-label" htmlFor={`${fid}-${key}`}>{label}</label>
      <input
        id={`${fid}-${key}`}
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
    <div>
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
          <Badge tone={running ? 'success' : 'neutral'}>NetFlow {running ? 'running' : 'stopped'}</Badge>
          <Badge tone={sflowRunning ? 'success' : 'neutral'}>sFlow {sflowRunning ? 'running' : 'stopped'}</Badge>
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
                      ? ' - collector running.'
                      : ' - collector failed to start (check logs).'
                    : ' - collector stopped.'),
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
          Saving here applies the change immediately - port/toggle edits rebind the UDP
          listeners on the fly, so no restart is required.
        </div>

        <div style={{ marginTop: '0.75rem' }}>
          <BusyButton type="submit" className="btn btn-primary" busy={update.isPending} busyLabel="Saving…">
            Save NetFlow Settings
          </BusyButton>
        </div>

        <StatusLine status={status} />
      </form>
    </div>
  );
}
