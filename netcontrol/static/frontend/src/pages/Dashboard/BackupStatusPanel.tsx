import { useMemo } from 'react';
import { Link } from 'react-router-dom';

import {
  type ConfigBackup,
  useConfigBackups,
  useConfigBackupSummary,
} from '@/api/configuration';
import type { DeviceHealth } from '@/api/dashboard';

import { parseBackendDate, timeAgo } from './helpers';

type BackupState = 'success' | 'stale' | 'failed' | 'never';

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

// A success that completed more than this many days ago is considered "stale".
// Most backup policies run daily-to-weekly; one week of silence is a clear
// signal something stopped running.
const STALE_AFTER_DAYS = 7;

interface HostRollup {
  hostId: number;
  hostname: string;
  state: BackupState;
  capturedAt: string | null;
  errorMessage: string | null;
}

interface Props {
  devices: DeviceHealth[];
}

export function BackupStatusPanel({ devices }: Props) {
  const summary = useConfigBackupSummary();
  const backups = useConfigBackups(500);

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

// Exported for testability - pure rollup from raw backups + device list.
export function rollUpBackups(
  backups: ConfigBackup[],
  devices: DeviceHealth[],
): HostRollup[] {
  // Pick the most-recent backup row per host_id.
  const latestByHost = new Map<number, ConfigBackup>();
  for (const b of backups) {
    if (b.host_id == null) continue;
    const existing = latestByHost.get(b.host_id);
    if (!existing) {
      latestByHost.set(b.host_id, b);
      continue;
    }
    const t1 = parseBackendDate(b.captured_at)?.getTime() ?? 0;
    const t2 = parseBackendDate(existing.captured_at)?.getTime() ?? 0;
    if (t1 > t2) latestByHost.set(b.host_id, b);
  }

  const now = Date.now();
  const staleCutoff = now - STALE_AFTER_DAYS * 86400 * 1000;
  const rollups: HostRollup[] = [];

  // Hosts we have a backup row for.
  for (const b of latestByHost.values()) {
    if (b.host_id == null) continue;
    const ts = parseBackendDate(b.captured_at)?.getTime() ?? 0;
    let state: BackupState;
    if (b.status === 'failed') state = 'failed';
    else if (ts > 0 && ts < staleCutoff) state = 'stale';
    else state = 'success';
    rollups.push({
      hostId: b.host_id,
      hostname: b.hostname ?? b.ip_address ?? `Host ${b.host_id}`,
      state,
      capturedAt: b.captured_at ?? null,
      errorMessage: b.error_message ?? null,
    });
  }

  // Polled devices without any backup row → "never". We use device_health as
  // the inventory proxy since it's already in scope; hosts that aren't polled
  // and aren't backed up don't appear, which matches the rest of the
  // dashboard's "polled fleet" framing.
  const seen = new Set(rollups.map((r) => r.hostId));
  for (const d of devices) {
    if (d.host_id == null) continue;
    if (seen.has(d.host_id)) continue;
    rollups.push({
      hostId: d.host_id,
      hostname: d.hostname ?? d.ip_address ?? `Host ${d.host_id}`,
      state: 'never',
      capturedAt: null,
      errorMessage: null,
    });
  }

  // Problems first (failed → never → stale → success), then by hostname.
  const order: Record<BackupState, number> = { failed: 0, never: 1, stale: 2, success: 3 };
  rollups.sort((a, b) => {
    if (order[a.state] !== order[b.state]) return order[a.state] - order[b.state];
    return a.hostname.localeCompare(b.hostname);
  });
  return rollups;
}
