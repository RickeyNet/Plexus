import { useState } from 'react';

import type { CloudSyncConfig, CloudSyncCursor, CloudSyncStatus } from '@/api/cloud';
import { formatTimestamp, providerLabel } from './helpers';

interface Props {
  kind: 'Flow' | 'Traffic';
  config: CloudSyncConfig | null;
  status: CloudSyncStatus | null;
  cursors: CloudSyncCursor[];
  selectedAccountId: number | null;
  onSave: (cfg: CloudSyncConfig) => Promise<void>;
  onPullAll: () => Promise<void>;
  onPullSelected: () => Promise<void>;
  isSaving: boolean;
  isPulling: boolean;
}

export function SyncControls({ kind, config, status, cursors, selectedAccountId, onSave, onPullAll, onPullSelected, isSaving, isPulling }: Props) {
  const [enabled, setEnabled] = useState<boolean>(false);
  const [interval, setInterval] = useState<number>(300);
  const [lookback, setLookback] = useState<number>(15);

  const [prevConfig, setPrevConfig] = useState(config);
  // Re-seed the editable fields from the incoming config when it changes.
  if (config !== prevConfig) {
    setPrevConfig(config);
    setEnabled(Boolean(config?.enabled));
    setInterval(Number(config?.interval_seconds ?? 300));
    setLookback(Number(config?.lookback_minutes ?? 15));
  }

  function statusLabel(): string {
    if (!status) return `No ${kind.toLowerCase()} sync action recorded yet.`;
    const source = status.source === 'scheduled' ? 'Scheduled' : 'Manual';
    const scope = status.scope === 'account'
      ? status.account_name || `Account #${status.account_id}`
      : 'all eligible accounts';
    const ingested = Number(status.ingested ?? 0).toLocaleString();
    const errCount = Array.isArray(status.errors) ? status.errors.length : 0;
    const outcome = status.ok === false ? 'failed' : 'completed';
    return `${formatTimestamp(status.last_run_at)}: ${source} ${kind.toLowerCase()} sync ${outcome} for ${scope}. Ingested ${ingested}.${errCount ? ` Errors: ${errCount}.` : ''}`;
  }

  const cfgEnabled = Boolean(config?.enabled);
  const cfgInterval = config?.interval_seconds ?? 300;
  const cfgLookback = config?.lookback_minutes ?? 15;

  return (
    <div className="card" style={{ padding: '0.9rem', marginBottom: '1rem' }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0.75rem', alignItems: 'end' }}>
        <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', margin: 0 }}>
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Enable Scheduled {kind === 'Flow' ? 'Pulling' : 'Metric Pulling'}
        </label>
        <label>
          Interval Seconds
          <input
            className="form-input"
            type="number"
            min={60}
            max={3600}
            value={interval}
            onChange={(e) => setInterval(parseInt(e.target.value, 10) || 300)}
          />
        </label>
        <label>
          Lookback Minutes
          <input
            className="form-input"
            type="number"
            min={1}
            max={1440}
            value={lookback}
            onChange={(e) => setLookback(parseInt(e.target.value, 10) || 15)}
          />
        </label>
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          <button
            className="btn btn-secondary"
            disabled={isSaving}
            onClick={() => onSave({ enabled, interval_seconds: interval, lookback_minutes: lookback })}
          >
            Save {kind === 'Flow' ? 'Sync' : 'Metric Sync'} Config
          </button>
          <button className="btn btn-primary" disabled={isPulling} onClick={() => onPullAll()}>
            Pull All Accounts
          </button>
          <button className="btn btn-secondary" disabled={isPulling || !selectedAccountId} onClick={() => onPullSelected()}>
            Pull Selected Account
          </button>
        </div>
      </div>
      <div className="text-muted" style={{ marginTop: '0.6rem' }}>
        Current config: {cfgEnabled ? 'enabled' : 'disabled'}, interval {cfgInterval}s, lookback {cfgLookback}m.
      </div>
      <div className="text-muted" style={{ marginTop: '0.35rem' }}>{statusLabel()}</div>
      {cursors.length > 0 ? (
        <div style={{ marginTop: '0.75rem', overflowX: 'auto' }}>
          <table className="chart-table">
            <thead>
              <tr><th>Account</th><th>Provider</th><th>Last Pull End</th><th>Updated</th></tr>
            </thead>
            <tbody>
              {cursors.map((c, i) => (
                <tr key={i}>
                  <td>{c.account_name || `Account #${c.account_id}`}</td>
                  <td>{providerLabel(c.provider)}</td>
                  <td>{formatTimestamp(c.last_pull_end)}</td>
                  <td>{formatTimestamp(c.updated_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="text-muted" style={{ marginTop: '0.75rem' }}>
          No {kind.toLowerCase()}-sync cursors yet. Run a manual pull or wait for scheduler.
        </div>
      )}
    </div>
  );
}
