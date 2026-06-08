import { useMemo } from 'react';
import { Link } from 'react-router-dom';

import {
  useConfigBackupSummary,
  useLatestConfigBackupsPerHost,
} from '@/api/configuration';
import type { DeviceHealth } from '@/api/dashboard';

import { type BackupState, type HostRollup, rollUpBackups } from './backupRollup';
import { timeAgo } from './helpers';

const STATE_COLORS: Record<BackupState, string> = {
  success: '#4caf50',
  stale: '#ff9800',
  failed: '#f44336',
  never: '#9e9e9e',
};

const STATE_LABELS: Record<BackupState, string> = {
  success: 'success',
  stale: 'stale',
  failed: 'failed',
  never: 'never',
};

interface Props {
  devices: DeviceHealth[];
}

export function BackupStatusPanel({ devices }: Props) {
  const summary = useConfigBackupSummary();
  const backups = useLatestConfigBackupsPerHost();

  const rollups = useMemo<HostRollup[]>(() => {
    return rollUpBackups(backups.data ?? [], devices);
  }, [backups.data, devices]);

  const counts = useMemo(() => {
    const c: Record<BackupState, number> = { success: 0, stale: 0, failed: 0, never: 0 };
    for (const r of rollups) c[r.state] += 1;
    return c;
  }, [rollups]);

  const problems = useMemo(
    () => rollups.filter((r) => r.state !== 'success').slice(0, 20),
    [rollups],
  );

  const isLoading = backups.isPending;
  const hasPolicies = (summary.data?.total_policies ?? 0) > 0;

  return (
    <div className="glass-card card dashboard-overview-card">
      <div className="dashboard-overview-header">
        <h3 className="dashboard-overview-title">Backup Status</h3>
        <Link to="/configuration" className="dashboard-overview-link">
          Open Backups →
        </Link>
      </div>

      {isLoading ? (
        <div className="skeleton skeleton-card" style={{ height: 120 }} />
      ) : !hasPolicies && rollups.length === 0 ? (
        <div className="dashboard-response-empty">
          <p style={{ margin: 0, color: 'var(--text-muted)' }}>
            No backup policies configured yet. Set one up on the Configuration
            page to start tracking device backups here.
          </p>
        </div>
      ) : (
        <>
          <div
            style={{
              display: 'flex',
              gap: 16,
              flexWrap: 'wrap',
              marginBottom: 12,
            }}
          >
            <Stat state="success" count={counts.success} />
            <Stat state="stale" count={counts.stale} />
            <Stat state="failed" count={counts.failed} />
            <Stat state="never" count={counts.never} />
          </div>

          {problems.length === 0 ? (
            <p style={{ margin: 0, color: 'var(--text-muted)', fontSize: 13 }}>
              All tracked devices have a recent successful backup.
            </p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {problems.map((r) => (
                <ProblemRow key={r.hostId} rollup={r} />
              ))}
              {rollups.length - counts.success > problems.length && (
                <p
                  style={{
                    margin: '6px 0 0 0',
                    fontSize: 12,
                    color: 'var(--text-muted)',
                  }}
                >
                  +{rollups.length - counts.success - problems.length} more
                  problem hosts - open the Backups page for the full list.
                </p>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}

function Stat({ state, count }: { state: BackupState; count: number }) {
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
        fontSize: 13,
        color: 'var(--text)',
      }}
    >
      <span
        style={{
          display: 'inline-block',
          width: 10,
          height: 10,
          borderRadius: '50%',
          background: STATE_COLORS[state],
        }}
      />
      <strong>{count}</strong>
      <span style={{ color: 'var(--text-muted)' }}>{STATE_LABELS[state]}</span>
    </span>
  );
}

function ProblemRow({ rollup }: { rollup: HostRollup }) {
  const color = STATE_COLORS[rollup.state];
  const detail =
    rollup.state === 'never'
      ? 'no backup recorded'
      : rollup.state === 'failed'
      ? rollup.errorMessage || 'last attempt failed'
      : `last success ${timeAgo(rollup.capturedAt)}`;

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 10,
        padding: '4px 6px',
        borderLeft: `3px solid ${color}`,
        background: 'var(--bg-secondary, transparent)',
        borderRadius: 4,
      }}
    >
      <span
        style={{
          flex: '0 0 auto',
          width: 8,
          height: 8,
          borderRadius: '50%',
          background: color,
        }}
      />
      <span
        style={{
          flex: '1 1 auto',
          fontWeight: 500,
          color: 'var(--text)',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
        }}
        title={rollup.hostname}
      >
        {rollup.hostname}
      </span>
      <span
        style={{
          flex: '0 1 auto',
          fontSize: 12,
          color: 'var(--text-muted)',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
          maxWidth: '60%',
        }}
        title={detail}
      >
        {detail}
      </span>
    </div>
  );
}

