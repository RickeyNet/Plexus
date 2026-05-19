import { useMemo, useState } from 'react';

import {
  type ConfigDriftEvent,
  useBulkAcceptDriftEvents,
  useConfigDriftEvents,
  useConfigDriftSummary,
  useUpdateDriftEventStatus,
} from '@/api/configuration';

import { CaptureSnapshotModal } from './CaptureSnapshotModal';
import { DriftDiffModal } from './DriftDiffModal';
import { DriftEventLogModal } from './DriftEventLogModal';
import { RevertDriftModal } from './RevertDriftModal';
import { SetBaselineModal } from './SetBaselineModal';
import { UnifiedDiff } from './UnifiedDiff';
import {
  type DriftGroup,
  filterDriftEvents,
  formatStamp,
  groupDriftEvents,
  statusColor,
} from './helpers';

type DriftStatusFilter = 'all' | 'open' | 'accepted' | 'resolved';
type ViewMode = 'grouped' | 'flat';

interface Props {
  onCaptureStarted: (jobId: string) => void;
  onRevertStarted: (jobId: string) => void;
}

export function DriftTab({ onCaptureStarted, onRevertStarted }: Props) {
  const [statusFilter, setStatusFilter] = useState<DriftStatusFilter>('open');
  const [query, setQuery] = useState('');
  const [viewMode, setViewMode] = useState<ViewMode>('grouped');

  const summary = useConfigDriftSummary();
  // "All statuses" means all *unresolved* drift — once a drift is accepted or
  // resolved it's handled and shouldn't clutter the working list. Accepted and
  // Resolved are still reachable via their explicit filter options.
  const fetchStatus = statusFilter === 'all' ? 'open' : statusFilter;
  const events = useConfigDriftEvents(fetchStatus);
  const updateStatus = useUpdateDriftEventStatus();
  const bulkAccept = useBulkAcceptDriftEvents();

  const [diffEventId, setDiffEventId] = useState<number | null>(null);
  const [logEventId, setLogEventId] = useState<number | null>(null);
  const [revertEventId, setRevertEventId] = useState<number | null>(null);
  const [showBaseline, setShowBaseline] = useState(false);
  const [showCapture, setShowCapture] = useState(false);

  const filtered = useMemo(
    () => filterDriftEvents(events.data || [], query),
    [events.data, query],
  );

  const openIds = useMemo(
    () => filtered.filter((e) => e.status === 'open').map((e) => e.id),
    [filtered],
  );

  const groups = useMemo(() => groupDriftEvents(filtered), [filtered]);

  return (
    <>
      <SummaryStrip summary={summary.data} />

      <div
        style={{
          display: 'flex',
          gap: '0.5rem',
          alignItems: 'center',
          flexWrap: 'wrap',
          margin: '0.75rem 0',
        }}
      >
        <select
          className="form-select"
          style={{ maxWidth: 160 }}
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value as DriftStatusFilter)}
        >
          <option value="all">All open</option>
          <option value="open">Open</option>
          <option value="accepted">Accepted</option>
          <option value="resolved">Resolved</option>
        </select>
        <input
          className="form-input"
          placeholder="Search hosts…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          style={{ maxWidth: 240 }}
        />
        <div style={{ display: 'flex', gap: '0.25rem' }}>
          <button
            type="button"
            className={`btn btn-sm ${viewMode === 'grouped' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setViewMode('grouped')}
            title="Group similar changes"
          >
            Grouped
          </button>
          <button
            type="button"
            className={`btn btn-sm ${viewMode === 'flat' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setViewMode('flat')}
            title="Show individual events"
          >
            Flat
          </button>
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: '0.4rem' }}>
          <button
            type="button"
            className="btn btn-sm btn-secondary"
            onClick={() => setShowCapture(true)}
          >
            Capture Snapshot
          </button>
          <button
            type="button"
            className="btn btn-sm btn-primary"
            onClick={() => setShowBaseline(true)}
          >
            Set Baseline
          </button>
          {openIds.length > 1 && (
            <>
              <button
                type="button"
                className="btn btn-sm btn-primary"
                disabled={bulkAccept.isPending}
                onClick={() => bulkAccept.mutate(openIds)}
              >
                Accept All Open ({openIds.length})
              </button>
              <button
                type="button"
                className="btn btn-sm btn-secondary"
                disabled={updateStatus.isPending}
                onClick={() => {
                  for (const id of openIds) {
                    updateStatus.mutate({ id, status: 'resolved' });
                  }
                }}
              >
                Resolve All Open ({openIds.length})
              </button>
            </>
          )}
        </div>
      </div>

      {events.isPending && <p className="text-muted">Loading drift events…</p>}
      {events.error && (
        <p style={{ color: 'var(--danger)' }}>
          Failed to load: {(events.error as Error).message}
        </p>
      )}
      {!events.isPending && !filtered.length && (
        <p className="text-muted">
          {events.data?.length
            ? 'No matching drift events.'
            : 'No drift events detected. Set a baseline to begin tracking.'}
        </p>
      )}

      {viewMode === 'grouped'
        ? groups.map((group) => (
            <DriftGroupCard
              key={group.representative_id}
              group={group}
              onShowDiff={(id) => setDiffEventId(id)}
              onShowLog={(id) => setLogEventId(id)}
              onShowRevert={(id) => setRevertEventId(id)}
              onAccept={(id) =>
                updateStatus.mutate({ id, status: 'accepted' })
              }
              onResolve={(id) =>
                updateStatus.mutate({ id, status: 'resolved' })
              }
              onAcceptGroup={(ids) => bulkAccept.mutate(ids)}
            />
          ))
        : filtered.map((ev) => (
            <DriftEventCard
              key={ev.id}
              ev={ev}
              onShowDiff={(id) => setDiffEventId(id)}
              onShowLog={(id) => setLogEventId(id)}
              onShowRevert={(id) => setRevertEventId(id)}
              onAccept={(id) =>
                updateStatus.mutate({ id, status: 'accepted' })
              }
              onResolve={(id) =>
                updateStatus.mutate({ id, status: 'resolved' })
              }
            />
          ))}

      <DriftDiffModal
        eventId={diffEventId}
        onClose={() => setDiffEventId(null)}
        onShowHistory={(id) => setLogEventId(id)}
        onShowRevert={(id) => setRevertEventId(id)}
      />
      <DriftEventLogModal
        eventId={logEventId}
        onClose={() => setLogEventId(null)}
      />
      <RevertDriftModal
        eventId={revertEventId}
        onClose={() => setRevertEventId(null)}
        onJobStarted={onRevertStarted}
      />
      {showBaseline && <SetBaselineModal onClose={() => setShowBaseline(false)} />}
      {showCapture && (
        <CaptureSnapshotModal
          onClose={() => setShowCapture(false)}
          onJobStarted={onCaptureStarted}
        />
      )}
    </>
  );
}

function SummaryStrip({
  summary,
}: {
  summary?: {
    total_baselined?: number;
    compliant?: number;
    drifted?: number;
    open_events?: number;
  };
}) {
  const items = [
    { label: 'Baselined', value: String(summary?.total_baselined ?? '-') },
    { label: 'Compliant', value: String(summary?.compliant ?? '-') },
    { label: 'Drifted', value: String(summary?.drifted ?? '-') },
    { label: 'Open events', value: String(summary?.open_events ?? '-') },
  ];
  return (
    <div className="card">
      <div
        className="card-body"
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
          gap: '0.5rem',
          padding: '0.75rem',
        }}
      >
        {items.map((it) => (
          <div
            key={it.label}
            style={{ display: 'flex', flexDirection: 'column' }}
          >
            <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
              {it.label}
            </span>
            <span style={{ fontWeight: 600 }}>{it.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

interface CardProps {
  ev: ConfigDriftEvent;
  onShowDiff: (id: number) => void;
  onShowLog: (id: number) => void;
  onShowRevert: (id: number) => void;
  onAccept: (id: number) => void;
  onResolve: (id: number) => void;
}

function DriftEventCard({
  ev,
  onShowDiff,
  onShowLog,
  onShowRevert,
  onAccept,
  onResolve,
}: CardProps) {
  return (
    <div className="card" style={{ marginBottom: '0.75rem', padding: '1rem' }}>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '0.5rem',
        }}
      >
        <div>
          <strong>{ev.hostname || ''}</strong>
          <span
            style={{
              marginLeft: '0.5rem',
              fontSize: '0.85em',
              color: 'var(--text-muted)',
            }}
          >
            {ev.ip_address || ''}
          </span>
        </div>
        <div
          style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}
        >
          <span className="drift-diff-added">+{ev.diff_lines_added || 0}</span>
          <span className="drift-diff-removed">
            -{ev.diff_lines_removed || 0}
          </span>
          <span style={{ color: statusColor(ev.status), fontWeight: 600 }}>
            {ev.status}
          </span>
        </div>
      </div>
      <div
        style={{
          marginTop: '0.5rem',
          fontSize: '0.85em',
          color: 'var(--text-muted)',
        }}
      >
        {ev.device_type || ''} • {formatStamp(ev.detected_at)}
      </div>
      <div
        style={{
          marginTop: '0.5rem',
          display: 'flex',
          gap: '0.35rem',
          flexWrap: 'wrap',
        }}
      >
        <button
          type="button"
          className="btn btn-sm btn-secondary"
          onClick={() => onShowDiff(ev.id)}
        >
          View Diff
        </button>
        <button
          type="button"
          className="btn btn-sm btn-secondary"
          onClick={() => onShowLog(ev.id)}
        >
          Event Log
        </button>
        {ev.status === 'open' && (
          <>
            <button
              type="button"
              className="btn btn-sm btn-primary"
              onClick={() => onAccept(ev.id)}
            >
              Accept
            </button>
            <button
              type="button"
              className="btn btn-sm btn-danger"
              onClick={() => onShowRevert(ev.id)}
            >
              Revert
            </button>
            <button
              type="button"
              className="btn btn-sm btn-secondary"
              onClick={() => onResolve(ev.id)}
            >
              Resolve
            </button>
          </>
        )}
      </div>
    </div>
  );
}

interface GroupCardProps {
  group: DriftGroup;
  onShowDiff: (id: number) => void;
  onShowLog: (id: number) => void;
  onShowRevert: (id: number) => void;
  onAccept: (id: number) => void;
  onResolve: (id: number) => void;
  onAcceptGroup: (ids: number[]) => void;
}

function DriftGroupCard({
  group,
  onShowDiff,
  onShowLog,
  onShowRevert,
  onAccept,
  onResolve,
  onAcceptGroup,
}: GroupCardProps) {
  const [showDiff, setShowDiff] = useState(false);
  const [showHosts, setShowHosts] = useState(false);
  const evs = group.events;
  const openInGroup = evs.filter((e) => e.status === 'open').map((e) => e.id);

  const groupTitle =
    evs.length > 1 ? (
      <>{evs.length} devices with identical changes</>
    ) : (
      <>
        {evs[0].hostname || ''}{' '}
        <span
          style={{
            color: 'var(--text-muted)',
            fontWeight: 400,
            fontSize: '0.85rem',
          }}
        >
          {evs[0].ip_address || ''}
        </span>
      </>
    );

  return (
    <div className="card" style={{ marginBottom: '0.75rem', padding: '1rem' }}>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          flexWrap: 'wrap',
          gap: '0.5rem',
        }}
      >
        <div>
          <div className="card-title" style={{ fontSize: '1rem' }}>
            {groupTitle}
          </div>
          <div
            className="drift-diff-stats"
            style={{ marginTop: '0.25rem' }}
          >
            <span className="drift-diff-added">
              +{group.diff_lines_added || 0}
            </span>{' '}
            <span className="drift-diff-removed">
              -{group.diff_lines_removed || 0}
            </span>
          </div>
        </div>
        <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
          {openInGroup.length > 1 ? (
            <button
              type="button"
              className="btn btn-sm btn-primary"
              onClick={() => onAcceptGroup(openInGroup)}
            >
              Accept Group ({openInGroup.length})
            </button>
          ) : openInGroup.length === 1 ? (
            <>
              <button
                type="button"
                className="btn btn-sm btn-primary"
                onClick={() => onAccept(openInGroup[0])}
              >
                Accept
              </button>
              <button
                type="button"
                className="btn btn-sm btn-secondary"
                onClick={() => onResolve(openInGroup[0])}
              >
                Resolve
              </button>
            </>
          ) : null}
        </div>
      </div>

      {evs.length > 1 && (
        <div
          style={{
            margin: '0.75rem 0',
            display: 'flex',
            flexWrap: 'wrap',
            gap: '0.35rem',
          }}
        >
          {evs.map((e) => (
            <span
              key={e.id}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.25rem',
                background: 'var(--bg-secondary)',
                padding: '0.15rem 0.5rem',
                borderRadius: '0.25rem',
                fontSize: '0.85rem',
              }}
            >
              {e.hostname || ''}
              <span
                style={{ color: 'var(--text-muted)', fontSize: '0.8em' }}
              >
                {e.ip_address || ''}
              </span>
              <span
                style={{
                  color: statusColor(e.status),
                  fontSize: '0.7em',
                  fontWeight: 600,
                  textTransform: 'uppercase',
                }}
              >
                {e.status}
              </span>
            </span>
          ))}
        </div>
      )}

      <button
        type="button"
        className="btn btn-sm btn-ghost"
        style={{ marginTop: '0.5rem', padding: 0 }}
        onClick={() => setShowDiff((v) => !v)}
      >
        {showDiff ? 'Hide Diff' : 'View Diff'}
      </button>
      {showDiff && (
        <UnifiedDiff
          diffText={group.diff_text}
          style={{ marginTop: '0.5rem' }}
        />
      )}

      {evs.length > 1 && (
        <>
          <button
            type="button"
            className="btn btn-sm btn-ghost"
            style={{
              marginTop: '0.35rem',
              padding: 0,
              color: 'var(--text-muted)',
            }}
            onClick={() => setShowHosts((v) => !v)}
          >
            {showHosts
              ? 'Hide individual devices'
              : `Show individual devices (${evs.length})`}
          </button>
          {showHosts && (
            <div
              style={{
                marginTop: '0.5rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.35rem',
              }}
            >
              {evs.map((ev) => (
                <DriftEventCard
                  key={ev.id}
                  ev={ev}
                  onShowDiff={onShowDiff}
                  onShowLog={onShowLog}
                  onShowRevert={onShowRevert}
                  onAccept={onAccept}
                  onResolve={onResolve}
                />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}
