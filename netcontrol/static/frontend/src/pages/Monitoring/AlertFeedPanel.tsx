import { useState, type ReactNode } from 'react';

import { useAuthStatus } from '@/api/auth';
import { Badge, SeverityBadge } from '@/components/Badge';
import { BusyButton } from '@/components/BusyButton';
import { useDialogs } from '@/components/DialogProvider-context';
import { LoadingState } from '@/components/LoadingState';
import { QueryError, type FailedQuery } from '@/components/QueryError';
import { formatBackendDateTime } from '@/lib/datetime';

import { alertViaText, pollSummary, type AlertFeedRow, type PollOutcome } from './alertFeed';

interface AlertFeedQuery extends FailedQuery {
  isPending: boolean;
}

interface AlertFeedPanelProps {
  title: string;
  description: ReactNode;
  /** What the alerts are called in an error message ("Meraki alerts"). */
  what: string;
  /** A source of the feed, for the Poll Now summary ("organization"). */
  sourceNoun: string;
  /** Where the feed's settings and per-source errors are ("Topology > Sources"). */
  settingsWhere?: string;
  emptyText: string;
  rows: AlertFeedRow[] | undefined;
  query: AlertFeedQuery;
  includeResolved: boolean;
  onIncludeResolved: (value: boolean) => void;
  pollBusy: boolean;
  onPoll: (done: (r: PollOutcome) => void, failed: (e: Error) => void) => void;
  /** Column headings that differ per feed. */
  subjectHeading?: string;
  sourceHeading?: string;
  viaHeading?: string;
}

/**
 * One feed's alerts: raised on the server like other monitoring alerts, listed
 * here with how Plexus alerted. Shared by the Meraki alerts and the vendor
 * alert feeds (the Cato events feed); the settings are under Topology > Sources.
 */
export function AlertFeedPanel({
  title,
  description,
  what,
  sourceNoun,
  settingsWhere,
  emptyText,
  rows: allRows,
  query,
  includeResolved,
  onIncludeResolved,
  pollBusy,
  onPoll,
  subjectHeading = 'Device / network',
  sourceHeading = 'Organization',
  viaHeading = 'Via',
}: AlertFeedPanelProps) {
  const [showMuted, setShowMuted] = useState(false);
  const { data: auth } = useAuthStatus();
  const { alert } = useDialogs();
  const loaded = allRows ?? [];
  const rows = showMuted ? loaded : loaded.filter((a) => !a.muted);

  function handlePoll() {
    onPoll(
      (r) => { void alert(pollSummary(r, sourceNoun, settingsWhere)); },
      (e) => { void alert({ message: e.message, variant: 'error' }); },
    );
  }

  return (
    <div style={{ marginTop: '1.5rem' }}>
      <h3 style={{ marginBottom: '0.5rem' }}>{title}</h3>
      <p className="text-muted" style={{ marginTop: 0, fontSize: '0.85em' }}>
        {description}
      </p>
      <div className="toolbar">
        <label className="text-muted" style={{ display: 'flex', gap: '0.3rem', alignItems: 'center' }}>
          <input type="checkbox" checked={includeResolved} onChange={(e) => onIncludeResolved(e.target.checked)} />
          Show resolved
        </label>
        <label className="text-muted" style={{ display: 'flex', gap: '0.3rem', alignItems: 'center' }}>
          <input type="checkbox" checked={showMuted} onChange={(e) => setShowMuted(e.target.checked)} />
          Show muted
        </label>
        {auth?.role === 'admin' && (
          <BusyButton className="btn btn-sm btn-secondary" busy={pollBusy} busyLabel="Polling…" onClick={handlePoll}>
            Poll Now
          </BusyButton>
        )}
      </div>

      {query.error && !allRows ? (
        <QueryError what={what} query={query} />
      ) : query.isPending ? (
        <LoadingState />
      ) : !loaded.length ? (
        <div className="empty-state">{emptyText}</div>
      ) : !rows.length ? (
        <div className="empty-state">Every alert listed is muted - tick Show muted to see them.</div>
      ) : (
        <div style={{ maxHeight: 520, overflow: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Alert</th>
                <th>{subjectHeading}</th>
                <th>{sourceHeading}</th>
                <th>Started</th>
                <th>Last seen</th>
                <th>{viaHeading}</th>
                <th>Plexus</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((a) => (
                <tr key={a.key} style={a.status === 'resolved' ? { opacity: 0.6 } : undefined}>
                  <td>
                    <SeverityBadge severity={a.severity} />
                    {a.status === 'resolved' && <span className="text-muted" style={{ fontSize: '0.8em', marginLeft: '0.3rem' }}>resolved</span>}
                  </td>
                  <td style={{ minWidth: 220 }}>
                    {a.title}
                    {a.message && a.message !== a.title && (
                      <div className="text-muted" style={{ fontSize: '0.85em' }}>{a.message}</div>
                    )}
                  </td>
                  <td>
                    {a.subject}
                    <span className="text-muted" style={{ fontSize: '0.85em' }}> {a.where}</span>
                  </td>
                  <td>{a.source}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>{formatBackendDateTime(a.startedAt)}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>{formatBackendDateTime(a.lastAt)}</td>
                  <td>{a.via}</td>
                  <td style={{ fontSize: '0.85em' }}>
                    {alertViaText(a.alertVia, a.severity)}
                    {/* Raised before its device, site or network was muted. */}
                    {a.muted && a.alertVia !== 'muted' && (
                      <Badge size="sm" style={{ marginLeft: 'var(--space-1)' }}>
                        Muted
                      </Badge>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
