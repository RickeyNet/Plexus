import { useMemo, useState } from 'react';

import {
  type ConfigDriftEvent,
  useBulkAcceptDriftEvents,
  useBulkResolveDriftEvents,
  useConfigDriftEvent,
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
import { ShowMoreButton } from '@/components/ShowMoreButton';
import { SummaryStrip } from '@/components/SummaryStrip';
import { formatBackendDateTime } from '@/lib/datetime';
import { usePendingKeys } from '@/lib/usePendingKeys';
import { useShowMore } from '@/lib/useShowMore';

import { CaptureSnapshotModal } from './CaptureSnapshotModal';
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
import { useCanWriteHost, writeControl } from './scopeGating';

type DriftStatusFilter = 'open' | 'accepted' | 'resolved';
type ViewMode = 'grouped' | 'flat';
// Cards rendered before "Show more"; each can expand a full config diff.
const CARD_STEP = 50;
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
  const bulkResolve = useBulkResolveDriftEvents();
  const { confirm, alert } = useDialogs();
  const pending = usePendingKeys<string>();
  const isEventBusy = (id: number) => pending.isPending(`event:${id}`);
  // Accept, resolve and revert change a host's data: only on writable hosts.
  const canWriteHost = useCanWriteHost();
  const canWriteEvent = (ev: ConfigDriftEvent) => canWriteHost(ev.host_id);

  const [logEventId, setLogEventId] = useState<number | null>(null);
  const [revertEventId, setRevertEventId] = useState<number | null>(null);
  const [showBaseline, setShowBaseline] = useState(false);
  const [showCapture, setShowCapture] = useState(false);

  const filtered = useMemo(
    () => filterDriftEvents(events.data || [], query),
    [events.data, query],
  );

  // The bulk buttons act on the open events the account may change.
  const openIds = filtered.filter((e) => e.status === 'open' && canWriteEvent(e)).map((e) => e.id);

  const groups = useMemo(() => groupDriftEvents(filtered), [filtered]);
  const shownGroups = useShowMore(groups, CARD_STEP);
  const shownEvents = useShowMore(filtered, CARD_STEP);
  const shown = viewMode === 'grouped' ? shownGroups : shownEvents;

  const showError = (e: unknown) => void alert({ message: (e as Error).message, variant: 'error' });

  const setEventStatus = (id: number, status: 'accepted' | 'resolved') =>
    pending.run(`event:${id}`, async () => {
      try {
        await updateStatus.mutateAsync({ id, status });
      } catch (e) {
        showError(e);
      }
    });

  // One request per bulk action; the server skips events that are no longer open.
  const closeMany = async (
    key: string,
    ids: number[],
    status: 'accepted' | 'resolved',
    scope: string,
  ) => {
    const accept = status === 'accepted';
    if (
      !(await confirm({
        title: accept ? 'Accept drift events' : 'Resolve drift events',
        message: accept
          ? `Accept ${ids.length} open drift event(s) ${scope}? The current running config of each device becomes its new baseline, so these changes stop being reported as drift.`
          : `Mark ${ids.length} open drift event(s) ${scope} as resolved? The baselines stay as they are; use this when the devices are already back in line with them.`,
        confirmLabel: `${accept ? 'Accept' : 'Resolve'} ${ids.length}`,
        confirmVariant: 'primary',
      }))
    )
      return;
    await pending.run(key, async () => {
      try {
        await (accept ? bulkAccept : bulkResolve).mutateAsync(ids);
      } catch (e) {
        showError(e);
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
                className="btn btn-sm btn-secondary"
                busy={pending.isPending('accept-all')}
                disabled={pending.isPending('resolve-all')}
                onClick={() => void closeMany('accept-all', openIds, 'accepted', 'in this list')}
              >
                Accept All Open ({openIds.length})
              </BusyButton>
              <BusyButton
                className="btn btn-sm btn-secondary"
                busy={pending.isPending('resolve-all')}
                disabled={pending.isPending('accept-all')}
                onClick={() => void closeMany('resolve-all', openIds, 'resolved', 'in this list')}
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
            ? shownGroups.visible.map((group) => (
                <DriftGroupCard
                  key={group.representative_id}
                  group={group}
                  isEventBusy={isEventBusy}
                  canWriteEvent={canWriteEvent}
                  isGroupBusy={pending.isPending(`group:${group.representative_id}`)}
                  onShowLog={(id) => setLogEventId(id)}
                  onShowRevert={(id) => setRevertEventId(id)}
                  onAccept={(id) => void setEventStatus(id, 'accepted')}
                  onResolve={(id) => void setEventStatus(id, 'resolved')}
                  onAcceptGroup={(ids) =>
                    void closeMany(`group:${group.representative_id}`, ids, 'accepted', 'with identical changes')
                  }
                />
              ))
            : shownEvents.visible.map((ev) => (
                <DriftEventCard
                  key={ev.id}
                  ev={ev}
                  isBusy={isEventBusy(ev.id)}
                  canWrite={canWriteEvent(ev)}
                  onShowLog={(id) => setLogEventId(id)}
                  onShowRevert={(id) => setRevertEventId(id)}
                  onAccept={(id) => void setEventStatus(id, 'accepted')}
                  onResolve={(id) => void setEventStatus(id, 'resolved')}
                />
              ))}
          <ShowMoreButton
            hiddenCount={shown.hiddenCount}
            onClick={shown.showMore}
            style={{ alignSelf: 'flex-start' }}
          />
        </div>
      )}

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

/** One event's diff, read when the card expands (the list carries no diffs). */
function EventDiff({ eventId }: { eventId: number }) {
  const event = useConfigDriftEvent(eventId);
  if (event.isPending) return <LoadingState variant="inline" text="Loading diff…" />;
  if (event.isError && !event.data) return <QueryError what="the diff" query={event} />;
  return <UnifiedDiff diffText={event.data?.diff_text} style={{ marginTop: '0.5rem' }} />;
}

/** "View Diff" on every drift card: expands the diff in place. */
function DiffToggle({ open, onToggle }: { open: boolean; onToggle: () => void }) {
  return (
    <button
      type="button"
      className="btn btn-sm btn-secondary"
      aria-expanded={open}
      onClick={onToggle}
    >
      {open ? 'Hide Diff' : 'View Diff'}
    </button>
  );
}

interface CardProps {
  ev: ConfigDriftEvent;
  /** Rendered inside a group card, so it is an inset panel, not a second card. */
  inset?: boolean;
  /** An accept or resolve of this event is in flight. */
  isBusy: boolean;
  /** The account may change this event's host. */
  canWrite: boolean;
  onShowLog: (id: number) => void;
  onShowRevert: (id: number) => void;
  onAccept: (id: number) => void;
  onResolve: (id: number) => void;
}

function DriftEventCard({
  ev,
  inset = false,
  isBusy,
  canWrite,
  onShowLog,
  onShowRevert,
  onAccept,
  onResolve,
}: CardProps) {
  const [showDiff, setShowDiff] = useState(false);
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
        <DiffToggle open={showDiff} onToggle={() => setShowDiff((v) => !v)} />
        <KebabMenu label={`Actions for ${ev.hostname || ev.ip_address || 'drift event'}`}>
          <MenuItem onSelect={() => onShowLog(ev.id)}>Event Log</MenuItem>
          {ev.status === 'open' && (
            <>
              <MenuItem {...writeControl(canWrite, isBusy)} onSelect={() => onAccept(ev.id)}>
                Accept
              </MenuItem>
              <MenuItem {...writeControl(canWrite, isBusy)} onSelect={() => onResolve(ev.id)}>
                Resolve
              </MenuItem>
              <MenuSeparator />
              <MenuItem danger {...writeControl(canWrite)} onSelect={() => onShowRevert(ev.id)}>
                Revert
              </MenuItem>
            </>
          )}
        </KebabMenu>
        {isBusy && <LoadingState variant="inline" text="Updating…" />}
      </div>
      {showDiff && <EventDiff eventId={ev.id} />}
    </div>
  );
}

interface GroupCardProps {
  group: DriftGroup;
  isEventBusy: (id: number) => boolean;
  canWriteEvent: (ev: ConfigDriftEvent) => boolean;
  /** Accept Group is in flight for this group. */
  isGroupBusy: boolean;
  onShowLog: (id: number) => void;
  onShowRevert: (id: number) => void;
  onAccept: (id: number) => void;
  onResolve: (id: number) => void;
  onAcceptGroup: (ids: number[]) => void;
}

function DriftGroupCard({
  group,
  isEventBusy,
  canWriteEvent,
  isGroupBusy,
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
  // Accept Group needs every open event's host to be writable.
  const canWriteGroup = evs.every((e) => e.status !== 'open' || canWriteEvent(e));

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
              {...writeControl(canWriteGroup)}
              onClick={() => onAcceptGroup(openInGroup)}
            >
              Accept Group ({openInGroup.length})
            </BusyButton>
          ) : openInGroup.length === 1 ? (
            <BusyButton
              className="btn btn-sm btn-primary"
              busy={isEventBusy(openInGroup[0])}
              {...writeControl(canWriteGroup)}
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
                  <MenuItem
                    {...writeControl(canWriteGroup, isEventBusy(evs[0].id))}
                    onSelect={() => onResolve(evs[0].id)}
                  >
                    Resolve
                  </MenuItem>
                  <MenuSeparator />
                  <MenuItem danger {...writeControl(canWriteGroup)} onSelect={() => onShowRevert(evs[0].id)}>
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

      <div style={{ marginTop: '0.5rem' }}>
        <DiffToggle open={showDiff} onToggle={() => setShowDiff((v) => !v)} />
      </div>
      {showDiff && <EventDiff eventId={group.representative_id} />}

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
                  canWrite={canWriteEvent(ev)}
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
