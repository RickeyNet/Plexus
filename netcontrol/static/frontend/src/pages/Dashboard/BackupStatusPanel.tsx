import { useMemo } from 'react';
import { Link } from 'react-router';

import {
  useConfigBackupSummary,
  useLatestConfigBackupsPerHost,
} from '@/api/configuration';
import type { DeviceHealth } from '@/api/dashboard';
import { ShowMoreButton } from '@/components/ShowMoreButton';
import { formatRelativeTime } from '@/lib/datetime';
import { useParamFilter } from '@/lib/useLinkedParam';
import { useShowMore } from '@/lib/useShowMore';

import { type BackupState, type HostRollup, rollUpBackups } from './backupRollup';
import { CountLink } from './CountLink';
import { BACKUP_STATES, BACKUP_STATE_PARAM, backupsPanelLink, countNoun, parseBackupState } from './dashboardLinks';

const STATE_COLORS: Record<BackupState, string> = {
  success: 'var(--success)',
  stale: 'var(--warning)',
  failed: 'var(--danger)',
  never: 'var(--text-muted)',
};

const STATE_LABELS: Record<BackupState, string> = {
  success: 'success',
  stale: 'stale',
  failed: 'failed',
  never: 'never',
};

// The hosts in each state, for link names and the empty list.
const STATE_PHRASES: Record<BackupState, string> = {
  success: 'with a recent successful backup',
  stale: 'whose last successful backup is stale',
  failed: 'whose last backup failed',
  never: 'never backed up',
};

// Hosts listed before "more".
const PROBLEM_ROWS = 20;

// The list grows with the problem hosts; loading, empty and short lists share this floor.
const BODY_STYLE = { minHeight: 120, height: 'auto' } as const;

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

  // `?backups=<state>` (a count here, or the Needs attention row) lists the
  // hosts in that state instead of the problem hosts; the counts show which.
  const [stateFilter] = useParamFilter(BACKUP_STATE_PARAM, parseBackupState);
  const listed = useMemo(
    () => rollups.filter((r) => (stateFilter ? r.state === stateFilter : r.state !== 'success')),
    [rollups, stateFilter],
  );
  // Filtered, the panel is the only place listing these hosts: show them all on demand.
  const showMore = useShowMore(listed, PROBLEM_ROWS);
  const problems = stateFilter ? showMore.visible : listed.slice(0, PROBLEM_ROWS);

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
        <div className="skeleton skeleton-card" style={BODY_STYLE} />
      ) : !hasPolicies && rollups.length === 0 ? (
        <div className="dashboard-response-empty" style={BODY_STYLE}>
          <p style={{ margin: 0, color: 'var(--text-muted)' }}>
            No backup policies configured yet. Set one up on the Configuration
            page to start tracking device backups here.
          </p>
        </div>
      ) : (
        <div style={BODY_STYLE}>
          <div
            style={{
              display: 'flex',
              gap: 16,
              flexWrap: 'wrap',
              marginBottom: 12,
            }}
          >
            {BACKUP_STATES.map((state) => (
              <Stat key={state} state={state} count={counts[state]} active={stateFilter === state} />
            ))}
            {stateFilter && (
              <CountLink
                to={backupsPanelLink(null)}
                label="Clear the filter: list the problem hosts"
                className="dashboard-overview-link"
              >
                Showing {STATE_LABELS[stateFilter]} · Clear
              </CountLink>
            )}
          </div>

          {problems.length === 0 ? (
            <p style={{ margin: 0, color: 'var(--text-muted)', fontSize: 13 }}>
              {stateFilter
                ? `No hosts ${STATE_PHRASES[stateFilter]}.`
                : 'All tracked devices have a recent successful backup.'}
            </p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {problems.map((r) => (
                <ProblemRow key={r.hostId} rollup={r} />
              ))}
              {stateFilter && (
                <ShowMoreButton hiddenCount={showMore.hiddenCount} onClick={showMore.showMore} style={{ alignSelf: 'flex-start' }} />
              )}
              {!stateFilter && listed.length > problems.length && (
                <p
                  style={{
                    margin: '6px 0 0 0',
                    fontSize: 12,
                    color: 'var(--text-muted)',
                  }}
                >
                  +{listed.length - problems.length} more problem hosts - pick a
                  state above to list all of them.
                </p>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// A count opens this panel listing the hosts in its state; the selected one
// links back to the problem hosts.
function Stat({ state, count, active }: { state: BackupState; count: number; active: boolean }) {
  const to = active ? backupsPanelLink(null) : count > 0 ? backupsPanelLink(state) : null;
  const hosts = `${countNoun(count, 'host', 'hosts')} ${STATE_PHRASES[state]}`;
  const label = active ? `Showing ${hosts}; select to list the problem hosts` : `Show ${hosts}`;
  return (
    <CountLink to={to} label={label} active={active} className="dashboard-backup-stat">
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
    </CountLink>
  );
}

function ProblemRow({ rollup }: { rollup: HostRollup }) {
  const color = STATE_COLORS[rollup.state];
  const detail =
    rollup.state === 'never'
      ? 'no backup recorded'
      : rollup.state === 'failed'
      ? rollup.errorMessage || 'last attempt failed'
      : `last success ${formatRelativeTime(rollup.capturedAt)}`;

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 10,
        padding: '4px 6px',
        borderLeft: `3px solid ${color}`,
        background: 'var(--bg-secondary)',
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

