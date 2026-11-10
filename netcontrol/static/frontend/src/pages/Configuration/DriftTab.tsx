import { useMemo, useState } from 'react';

import {
  type ConfigDriftEvent,
  useBulkAcceptDriftEvents,
  useConfigDriftEvents,
  useConfigDriftSummary,
  useUpdateDriftEventStatus,
} from '@/api/configuration';
import { BusyButton } from '@/components/BusyButton';
import { useDialogs } from '@/components/DialogProvider-context';
import { LoadingState } from '@/components/LoadingState';
import { KebabMenu, MenuItem, MenuSeparator } from '@/components/Menu';
import { QueryError } from '@/components/QueryError';
import { SegmentedControl } from '@/components/SegmentedControl';
import { SummaryStrip } from '@/components/SummaryStrip';
import { formatBackendDateTime } from '@/lib/datetime';
import { usePendingKeys } from '@/lib/usePendingKeys';

import { CaptureSnapshotModal } from './CaptureSnapshotModal';
import { DriftDiffModal } from './DriftDiffModal';
import { DriftEventLogModal } from './DriftEventLogModal';
import { RevertDriftModal } from './RevertDriftModal';
import { SetBaselineModal } from './SetBaselineModal';
import { UnifiedDiff } from './UnifiedDiff';
import {
  type DriftGroup,
  filterDriftEvents,
  groupDriftEvents,
  statusColor,
} from './helpers';

type DriftStatusFilter = 'open' | 'accepted' | 'resolved';
type ViewMode = 'grouped' | 'flat';
const VIEW_MODES: { key: ViewMode; label: string; title: string }[] = [
  { key: 'grouped', label: 'Grouped', title: 'Group similar changes' },
  { key: 'flat', label: 'Flat', title: 'Show individual events' },
];

interface Props {
  onCaptureStarted: (jobId: string) => void;
  onRevertStarted: (jobId: string) => void;
}

export function DriftTab({ onCaptureStarted, onRevertStarted }: Props) {
  const [statusFilter, setStatusFilter] = useState<DriftStatusFilter>('open');
  const [query, setQuery] = useState('');
  const [viewMode, setViewMode] = useState<ViewMode>('grouped');

  const summary = useConfigDriftSummary();
  const events = useConfigDriftEvents(statusFilter);
  const updateStatus = useUpdateDriftEventStatus();
  const bulkAccept = useBulkAcceptDriftEvents();
  const { confirm, alert } = useDialogs();
  const pending = usePendingKeys<string>();
  const isEventBusy = (id: number) => pending.isPending(`event:${id}`);

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

  const showError = (e: unknown) => void alert({ message: (e as Error).message, variant: 'error' });

  const setEventStatus = (id: number, status: 'accepted' | 'resolved') =>
    pending.run(`event:${id}`, async () => {
      try {
        await updateStatus.mutateAsync({ id, status });
      } catch (e) {
        showError(e);
      }
    });

  const acceptMany = async (key: string, ids: number[], scope: string) => {
    if (
      !(await confirm({
        title: 'Accept drift events',
        message: `Accept ${ids.length} open drift event(s) ${scope}? The current running config of each device becomes its new baseline, so these changes stop being reported as drift.`,
        confirmLabel: `Accept ${ids.length}`,
        confirmVariant: 'primary',
      }))
    )
      return;
    await pending.run(key, async () => {
      try {
        await bulkAccept.mutateAsync(ids);
      } catch (e) {
        showError(e);
      }
    });
  };

  const resolveAll = async () => {
    const ids = openIds;
    if (
      !(await confirm({
        title: 'Resolve drift events',
        message: `Mark ${ids.length} open drift event(s) in this list as resolved? The baselines stay as they are; use this when the devices are already back in line with them.`,
        confirmLabel: `Resolve ${ids.length}`,
        confirmVariant: 'primary',
      }))
    )
      return;
    await pending.run('resolve-all', async () => {
      let failed = 0;
      let lastError = '';
      for (const id of ids) {
        try {
          await updateStatus.mutateAsync({ id, status: 'resolved' });
        } catch (e) {
          failed++;
          lastError = (e as Error).message;
        }
      }
      if (failed > 0) {
        void alert({
          message: `${failed} of ${ids.length} drift event(s) could not be resolved: ${lastError}`,
          variant: 'error',
        });
      }
    });
  };

  return (
    <>
      <DriftSummaryStrip summary={summary.data} />

      <div className="toolbar">
        <select
          className="form-select form-select-sm"
          style={{ maxWidth: 160 }}
          aria-label="Filter by status"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value as DriftStatusFilter)}
        >
          <option value="open">Open</option>
          <option value="accepted">Accepted</option>
          <option value="resolved">Resolved</option>
        </select>
        <input
          className="form-input form-input-sm"
          placeholder="Search hosts…"
          aria-label="Search hosts"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          style={{ maxWidth: 240 }}
        />
        <SegmentedControl
          options={VIEW_MODES}
          value={viewMode}
          onChange={setViewMode}
          aria-label="Drift view"
        />
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 'var(--space-2)' }}>
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
              <BusyButton
                className="btn btn-sm btn-primary"
                busy={pending.isPending('accept-all')}
                disabled={pending.isPending('resolve-all')}
                onClick={() => void acceptMany('accept-all', openIds, 'in this list')}
              >
                Accept All Open ({openIds.length})
              </BusyButton>
              <BusyButton
                className="btn btn-sm btn-secondary"
                busy={pending.isPending('resolve-all')}
                disabled={pending.isPending('accept-all')}
                onClick={() => void resolveAll()}
              >
                Resolve All Open ({openIds.length})
              </BusyButton>
            </>
          )}
        </div>
      </div>

      {events.isError && !events.data && (
        <QueryError what="drift events" query={events} />
      )}
      {events.isPending && <LoadingState text="Loading drift events…" />}
      {events.data && !filtered.length && (
        <p className="text-muted">
          {events.data?.length
            ? 'No matching drift events.'
            : 'No drift events detected. Set a baseline to begin tracking.'}
        </p>
      )}

      {filtered.length > 0 && (
        <div className="stack stack-sm">
          {viewMode === 'grouped'
            ? groups.map((group) => (
                <DriftGroupCard
                  key={group.representative_id}
                  group={group}
                  isEventBusy={isEventBusy}
                  isGroupBusy={pending.isPending(`group:${group.representative_id}`)}
                  onShowDiff={(id) => setDiffEventId(id)}
                  onShowLog={(id) => setLogEventId(id)}
                  onShowRevert={(id) => setRevertEventId(id)}
                  onAccept={(id) => void setEventStatus(id, 'accepted')}
                  onResolve={(id) => void setEventStatus(id, 'resolved')}
                  onAcceptGroup={(ids) =>
                    void acceptMany(`group:${group.representative_id}`, ids, 'with identical changes')
                  }
                />
              ))
            : filtered.map((ev) => (
                <DriftEventCard
                  key={ev.id}
                  ev={ev}
                  isBusy={isEventBusy(ev.id)}
                  onShowDiff={(id) => setDiffEventId(id)}
                  onShowLog={(id) => setLogEventId(id)}
                  onShowRevert={(id) => setRevertEventId(id)}
                  onAccept={(id) => void setEventStatus(id, 'accepted')}
                  onResolve={(id) => void setEventStatus(id, 'resolved')}
                />
              ))}
        </div>
      )}

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

function DriftSummaryStrip({
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
  return <SummaryStrip items={items} />;
}

interface CardProps {
  ev: ConfigDriftEvent;
  /** Rendered inside a group card, so it is an inset panel, not a second card. */
  inset?: boolean;
  /** An accept or resolve of this event is in flight. */
  isBusy: boolean;
  onShowDiff: (id: number) => void;
  onShowLog: (id: number) => void;
  onShowRevert: (id: number) => void;
  onAccept: (id: number) => void;
  onResolve: (id: number) => void;
}

function DriftEventCard({
  ev,
  inset = false,
  isBusy,
  onShowDiff,
  onShowLog,
  onShowRevert,
  onAccept,
  onResolve,
}: CardProps) {
  return (
    <div className={inset ? 'card-inset' : 'card'}>
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
        {ev.device_type || ''} • {formatBackendDateTime(ev.detected_at, '')}
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
        <KebabMenu label={`Actions for ${ev.hostname || ev.ip_address || 'drift event'}`}>
          <MenuItem onSelect={() => onShowLog(ev.id)}>Event Log</MenuItem>
          {ev.status === 'open' && (
            <>
              <MenuItem disabled={isBusy} onSelect={() => onAccept(ev.id)}>
                Accept
              </MenuItem>
              <MenuItem disabled={isBusy} onSelect={() => onResolve(ev.id)}>
                Resolve
              </MenuItem>
              <MenuSeparator />
              <MenuItem danger onSelect={() => onShowRevert(ev.id)}>
                Revert
              </MenuItem>
            </>
          )}
        </KebabMenu>
        {isBusy && <LoadingState variant="inline" text="Updating…" />}
      </div>
    </div>
  );
}

interface GroupCardProps {
  group: DriftGroup;
  isEventBusy: (id: number) => boolean;
  /** Accept Group is in flight for this group. */
  isGroupBusy: boolean;
  onShowDiff: (id: number) => void;
  onShowLog: (id: number) => void;
  onShowRevert: (id: number) => void;
  onAccept: (id: number) => void;
  onResolve: (id: number) => void;
  onAcceptGroup: (ids: number[]) => void;
}

function DriftGroupCard({
  group,
  isEventBusy,
  isGroupBusy,
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
    <div className="card">
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
        <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap', alignItems: 'center' }}>
          {openInGroup.length > 1 ? (
            <BusyButton
              className="btn btn-sm btn-primary"
              busy={isGroupBusy}
              onClick={() => onAcceptGroup(openInGroup)}
            >
              Accept Group ({openInGroup.length})
            </BusyButton>
          ) : openInGroup.length === 1 ? (
            <BusyButton
              className="btn btn-sm btn-primary"
              busy={isEventBusy(openInGroup[0])}
              onClick={() => onAccept(openInGroup[0])}
            >
              Accept
            </BusyButton>
          ) : null}
          {evs.length === 1 && (
            <KebabMenu label={`Actions for ${evs[0].hostname || evs[0].ip_address || 'drift event'}`}>
              <MenuItem onSelect={() => onShowLog(evs[0].id)}>Event Log</MenuItem>
              {openInGroup.length === 1 && (
                <>
                  <MenuItem disabled={isEventBusy(evs[0].id)} onSelect={() => onResolve(evs[0].id)}>
                    Resolve
                  </MenuItem>
                  <MenuSeparator />
                  <MenuItem danger onSelect={() => onShowRevert(evs[0].id)}>
                    Revert
                  </MenuItem>
                </>
              )}
            </KebabMenu>
          )}
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
        style={{ marginTop: '0.5rem' }}
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
                  inset
                  isBusy={isEventBusy(ev.id)}
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
