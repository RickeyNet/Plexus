import { useState } from 'react';
import { Link } from 'react-router';
import type { UseQueryResult } from '@tanstack/react-query';

import type { SyslogActivity, SyslogRule, SyslogUnmatchedGroup } from '@/api/syslogRules';
import { Badge } from '@/components/Badge';
import { BusyButton } from '@/components/BusyButton';
import { Callout } from '@/components/Callout';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { SegmentedControl } from '@/components/SegmentedControl';
import { formatBackendDateTime } from '@/lib/datetime';
import { formatCount } from '@/lib/formatCount';

import {
  activitySummary,
  activityWindowLabel,
  filterUnmatched,
  prefillFromGroup,
  relatedBadge,
  SYSLOG_ACTIVITY_WINDOWS,
  transportSummary,
  udpTransportNote,
  unmatchedGroupLabel,
  type SyslogRulePrefill,
} from './syslogRules';

const WINDOW_OPTIONS = SYSLOG_ACTIVITY_WINDOWS.map((w) => ({ key: String(w.hours), label: w.label }));

const SAMPLE_STYLE = { maxWidth: '24rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } as const;

// Monitoring -> Configure -> Syslog Rules -> Received messages: what the
// syslog messages of the selected window did, the ones no rule acted on
// (each can become a custom rule) and the senders that match no inventory host.
export function SyslogActivitySection({ hours, onHoursChange, activity, rules, onCreateRule }: {
  hours: number;
  onHoursChange: (hours: number) => void;
  activity: UseQueryResult<SyslogActivity, Error>;
  rules: SyslogRule[] | undefined;
  onCreateRule: (prefill: SyslogRulePrefill) => void;
}) {
  const [onlyRelated, setOnlyRelated] = useState(false);
  const data = activity.data;
  const windowLabel = activityWindowLabel(hours);

  return (
    <div style={{ marginTop: '1.5rem' }}>
      <h3 style={{ marginBottom: '0.5rem' }}>Received messages</h3>
      <p className="text-muted" style={{ marginTop: 0, fontSize: '0.85em' }}>
        How often each rule matched in the window and which messages from inventory hosts no rule or trigger acted on.
        The scan runs when the tab opens and on Refresh.
      </p>
      <div className="toolbar" style={{ flexWrap: 'wrap', gap: '0.5rem' }}>
        <SegmentedControl
          aria-label="Time window"
          options={WINDOW_OPTIONS}
          value={String(hours)}
          onChange={(k) => onHoursChange(Number(k))}
        />
        <BusyButton
          className="btn btn-sm btn-secondary"
          busy={activity.isFetching}
          busyLabel="Scanning…"
          onClick={() => void activity.refetch()}
        >
          Refresh
        </BusyButton>
        <label className="text-muted" style={{ display: 'flex', gap: '0.3rem', alignItems: 'center' }}>
          <input type="checkbox" checked={onlyRelated} onChange={(e) => setOnlyRelated(e.target.checked)} />
          Only messages that look related to a built-in rule
        </label>
      </div>

      {activity.error && !data ? (
        <QueryError what="received syslog messages" query={activity} />
      ) : activity.isPending ? (
        <LoadingState text="Scanning received messages…" />
      ) : data && data.scanned === 0 ? (
        <EmptyState
          message={`No syslog messages received in the last ${windowLabel}`}
          description={
            <>
              The syslog receiver is turned on under{' '}
              <Link to="/settings/event-receivers">Settings &gt; Syslog &amp; Traps</Link>, and devices send to its UDP,
              TCP or TLS port.
            </>
          }
        />
      ) : data ? (
        <>
          <p style={{ fontSize: '0.9em' }} aria-live="polite">
            {activitySummary(data)}
            {transportSummary(data) && <> {transportSummary(data)}</>}
          </p>
          <UdpNote activity={data} />
          {data.truncated && (
            <Callout tone="info">
              The last {windowLabel} held more than {formatCount(data.limit)} messages. The scan covers the newest{' '}
              {formatCount(data.limit)}, back to {formatBackendDateTime(data.oldest_at)}.
            </Callout>
          )}
          <UnmatchedTable
            groups={filterUnmatched(data.unmatched_tags, onlyRelated)}
            anyUnmatched={data.unmatched_tags.length > 0}
            rules={rules}
            onCreateRule={onCreateRule}
          />
          {data.unknown_sources.length > 0 && (
            <div style={{ marginTop: '1rem' }}>
              <h4 style={{ marginBottom: '0.3rem' }}>Unknown sources</h4>
              <p className="text-muted" style={{ marginTop: 0, fontSize: '0.85em' }}>
                These devices send syslog but match no inventory host address, so no rule applies to them.
              </p>
              <DataTable compact aria-label="Syslog from unknown sources">
                <thead>
                  <tr><th>Source address</th><th>Messages</th><th>Last seen</th></tr>
                </thead>
                <tbody>
                  {data.unknown_sources.map((s) => (
                    <tr key={s.source_ip}>
                      <td><code>{s.source_ip}</code></td>
                      <td>{formatCount(s.count)}</td>
                      <td style={{ whiteSpace: 'nowrap' }}>{formatBackendDateTime(s.last_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </DataTable>
            </div>
          )}
        </>
      ) : null}
    </div>
  );
}

// Syslog over UDP while devices move to TCP or TLS: the messages UDP actions
// being off left unacted, or the hosts still sending over UDP.
function UdpNote({ activity }: { activity: SyslogActivity }) {
  const note = udpTransportNote(activity);
  if (!note) return null;
  if (note.kind === 'ignored') {
    return (
      <Callout tone="info">
        {note.text} Turn it back on, or move these hosts to TCP or TLS, under{' '}
        <Link to="/settings/event-receivers">Settings &gt; Syslog &amp; Traps</Link>.
      </Callout>
    );
  }
  return <p className="text-muted" style={{ marginTop: 0, fontSize: '0.85em' }}>{note.text}</p>;
}

function UnmatchedTable({ groups, anyUnmatched, rules, onCreateRule }: {
  groups: SyslogUnmatchedGroup[];
  anyUnmatched: boolean;
  rules: SyslogRule[] | undefined;
  onCreateRule: (prefill: SyslogRulePrefill) => void;
}) {
  if (!anyUnmatched) {
    return <EmptyState compact message="No unmatched messages" description="Every message from an inventory host was acted on by a rule or trigger." />;
  }
  if (groups.length === 0) {
    return <EmptyState compact message="No unmatched message looks related to a built-in rule" />;
  }
  return (
    <DataTable aria-label="Unmatched syslog messages">
      <thead>
        <tr>
          <th>Tag or program</th>
          <th>Messages</th>
          <th>Hosts</th>
          <th>Device types</th>
          <th style={{ whiteSpace: 'nowrap' }}>Last seen</th>
          <th>Sample</th>
          <th aria-label="Actions" />
        </tr>
      </thead>
      <tbody>
        {groups.map((g) => {
          const label = unmatchedGroupLabel(g);
          const related = relatedBadge(g, rules);
          return (
            <tr key={`${g.tag}|${g.program}`}>
              <td style={{ overflowWrap: 'anywhere' }}>
                {label.kind === 'tag' && <code title={g.raw_tag || undefined}>{label.text}</code>}
                {label.kind === 'program' && <><span className="text-muted">Program:</span> <code>{label.text}</code></>}
                {label.kind === 'none' && <span className="text-muted">{label.text}</span>}
                {related && (
                  <div style={{ marginTop: '0.2rem' }}>
                    <Badge tone={related.tone} size="sm" title={related.title}>{related.text}</Badge>
                  </div>
                )}
              </td>
              <td>{formatCount(g.count)}</td>
              <td>{formatCount(g.hosts)}</td>
              <td style={{ fontSize: '0.85em' }}>{g.device_types.length ? g.device_types.join(', ') : '-'}</td>
              <td style={{ whiteSpace: 'nowrap' }}>{formatBackendDateTime(g.last_at)}</td>
              <td title={g.sample || undefined} style={{ ...SAMPLE_STYLE, fontSize: '0.82em' }}>
                {g.sample ? <code>{g.sample}</code> : '-'}
              </td>
              <td>
                <button
                  type="button"
                  className="btn btn-sm btn-secondary"
                  style={{ whiteSpace: 'nowrap' }}
                  aria-label={`Create rule from ${label.kind === 'none' ? 'untagged messages' : label.text}`}
                  onClick={() => onCreateRule(prefillFromGroup(g))}
                >
                  Create rule
                </button>
              </td>
            </tr>
          );
        })}
      </tbody>
    </DataTable>
  );
}
