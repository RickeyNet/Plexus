import { useEffect, useState } from 'react';

import {
  MonitoringConfig,
  useMonitoringConfig,
  useRunMonitoringPoll,
  useUpdateMonitoringConfig,
} from '@/api/settings';

export function MonitoringTab() {
  const query = useMonitoringConfig();
  const update = useUpdateMonitoringConfig();
  const runNow = useRunMonitoringPoll();

  const [draft, setDraft] = useState<MonitoringConfig | null>(null);
  const [status, setStatus] = useState<{ kind: 'success' | 'error'; message: string } | null>(null);

  useEffect(() => {
    if (query.data) setDraft(query.data);
  }, [query.data]);

  if (query.isLoading || !draft) return <p className="text-muted">Loading…</p>;
  if (query.isError)
    return (
      <div className="error">
        Failed to load monitoring config: {(query.error as Error).message}
      </div>
    );

  const num = (
    label: string,
    key: keyof MonitoringConfig,
    min: number,
    flex = '0 1 160px',
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
    </div>
  );

  const check = (label: string, key: keyof MonitoringConfig) => (
    <label
      className="form-group"
      style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}
    >
      <input
        type="checkbox"
        checked={draft[key] as boolean}
        onChange={(e) => setDraft({ ...draft, [key]: e.target.checked })}
      />
      <span>{label}</span>
    </label>
  );

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
        <h3 style={{ margin: 0 }}>Monitoring</h3>
        <button
          type="button"
          className="btn btn-sm btn-secondary"
          disabled={runNow.isPending}
          onClick={() => {
            setStatus(null);
            runNow.mutate(undefined, {
              onSuccess: (res) => {
                const errors = res.errors ?? 0;
                setStatus({
                  kind: errors > 0 ? 'error' : 'success',
                  message: `Monitoring poll complete: ${res.hosts_polled ?? 0} hosts, ${res.alerts_created ?? 0} alerts, ${errors} errors`,
                });
              },
              onError: (err) =>
                setStatus({
                  kind: 'error',
                  message: `Monitoring poll failed: ${(err as Error).message}`,
                }),
            });
          }}
        >
          {runNow.isPending ? 'Polling…' : 'Poll Now'}
        </button>
      </div>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          setStatus(null);
          update.mutate(draft, {
            onSuccess: (saved) => {
              setDraft(saved);
              setStatus({ kind: 'success', message: 'Monitoring configuration saved' });
            },
            onError: (err) =>
              setStatus({
                kind: 'error',
                message: `Failed to save monitoring config: ${(err as Error).message}`,
              }),
          });
        }}
      >
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem' }}>
          {check('Enabled', 'enabled')}
          {check('Collect routes', 'collect_routes')}
          {check('Collect VPN', 'collect_vpn')}
          {check('Escalation enabled', 'escalation_enabled')}
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem' }}>
          {num('Interval (s)', 'interval_seconds', 30)}
          {num('Retention (days)', 'retention_days', 1)}
          {num('CPU threshold (%)', 'cpu_threshold', 0)}
          {num('Memory threshold (%)', 'memory_threshold', 0)}
          {num('Cooldown (min)', 'default_cooldown_minutes', 0)}
          {num('Escalate after (min)', 'escalation_after_minutes', 0)}
          {num('Escalation check (min)', 'escalation_check_interval', 1)}
        </div>

        <div style={{ marginTop: '0.5rem' }}>
          <button
            type="submit"
            className="btn btn-primary"
            disabled={update.isPending}
          >
            {update.isPending ? 'Saving…' : 'Save Monitoring Settings'}
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
