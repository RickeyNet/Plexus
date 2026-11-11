import { useId, useState } from 'react';

import { groupLabel } from '@/api/inventory';
import { useInventoryGroups } from '@/api/compliance';
import { StatusBadge } from '@/components/Badge';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { StatGrid, StatTile } from '@/components/StatTile';
import { TabBar } from '@/components/TabBar';
import {
  useAvailabilityOutages,
  useAvailabilitySummary,
  useAvailabilityTransitions,
} from '@/api/monitoring';
import { formatBackendDateTime } from '@/lib/datetime';
import { statusTone, type Tone } from '@/lib/severity';
import { CatoEgressPanel } from './CatoEgressPanel';
import { MerakiAlertsPanel } from './MerakiAlertsPanel';
import { AVAILABILITY_TABLE_MAX_HEIGHT, countTone, formatUptime, formatUptimePct } from './helpers';
import { TopologyAvailabilityPanel } from './TopologyAvailabilityPanel';

type SubTab = 'hosts' | 'outages' | 'transitions';

const SUB_TABS: { key: SubTab; label: string }[] = [
  { key: 'hosts', label: 'Hosts' },
  { key: 'outages', label: 'Outages' },
  { key: 'transitions', label: 'Transitions' },
];

const entityLabel = (type?: string, id?: string) => `${type ?? 'host'}${id ? ` ${id}` : ''}`;

export function AvailabilityTab() {
  const groups = useInventoryGroups();
  const fid = useId();
  const [groupId, setGroupId] = useState<number | null>(null);
  const [days, setDays] = useState(7);
  const [subTab, setSubTab] = useState<SubTab>('hosts');

  const summary = useAvailabilitySummary(groupId, days);
  const outages = useAvailabilityOutages({ groupId, days, limit: 200 });
  const transitions = useAvailabilityTransitions({ groupId, days, limit: 500 });

  const s = summary.data;
  const hosts = s?.hosts ?? [];
  const hostsUp = s ? hosts.filter((h) => statusTone(h.current_state) === 'success').length : null;
  const cards: { label: string; value: string | number; tone?: Tone }[] = [
    { label: 'Hosts Tracked', value: s?.host_count ?? '-' },
    { label: 'Currently Up', value: hostsUp ?? '-', tone: countTone(hostsUp, 'success') },
    { label: 'Currently Down', value: s?.currently_down ?? '-', tone: countTone(s?.currently_down, 'danger') },
    { label: 'Avg Uptime', value: formatUptimePct(s?.avg_uptime_pct) },
    { label: `Outages (${days}d)`, value: s?.total_outages ?? '-' },
  ];

  return (
    <div>
      <div className="toolbar">
        <label className="text-muted" htmlFor={`${fid}-period`}>Period:</label>
        <select id={`${fid}-period`} className="form-select" value={days} onChange={(e) => setDays(parseInt(e.target.value, 10))}>
          <option value={1}>Last 24h</option>
          <option value={7}>Last 7 days</option>
          <option value={30}>Last 30 days</option>
        </select>
      </div>

      <h3 style={{ marginBottom: '0.5rem' }}>Polled hosts</h3>
      <p className="text-muted" style={{ marginTop: 0, fontSize: '0.85em' }}>
        Inventory hosts and their interfaces, tracked by the monitoring polls.
      </p>

      <div className="toolbar">
        <label className="text-muted" htmlFor={`${fid}-group`}>Group:</label>
        <select
          id={`${fid}-group`}
          className="form-select"
          value={groupId ?? ''}
          onChange={(e) => setGroupId(e.target.value ? parseInt(e.target.value, 10) : null)}
        >
          <option value="">All Groups</option>
          {(groups.data ?? []).map((g) => (
            <option key={g.id} value={g.id}>{groupLabel(g)}</option>
          ))}
        </select>
      </div>

      <StatGrid compact>
        {cards.map((c) => (
          <StatTile key={c.label} center label={c.label} value={c.value} tone={c.tone} />
        ))}
      </StatGrid>

      <TabBar tabs={SUB_TABS} active={subTab} onChange={setSubTab} size="sm" aria-label="Host availability views" />

      {subTab === 'hosts' && (
        summary.error && !s ? (
          <QueryError what="availability summary" query={summary} />
        ) : summary.isPending ? (
          <LoadingState />
        ) : hosts.length === 0 ? (
          <EmptyState message="No availability data - run polls to begin tracking." />
        ) : (
          <DataTable stickyHeader maxHeight={AVAILABILITY_TABLE_MAX_HEIGHT}>
            <thead>
              <tr>
                <th>Name</th>
                <th>IP address</th>
                <th>State</th>
                <th style={{ textAlign: 'right' }}>Uptime</th>
                <th style={{ textAlign: 'right' }}>Outages</th>
              </tr>
            </thead>
            <tbody>
              {hosts.map((h) => (
                <tr key={h.host_id}>
                  <td>{h.hostname || 'Unknown'}</td>
                  <td>{h.ip_address || '-'}</td>
                  <td><StatusBadge status={h.current_state} /></td>
                  <td style={{ textAlign: 'right' }}>{formatUptimePct(h.uptime_pct)}</td>
                  <td style={{ textAlign: 'right' }}>{h.outage_count ?? '-'}</td>
                </tr>
              ))}
            </tbody>
          </DataTable>
        )
      )}

      {subTab === 'outages' && (
        outages.error && !outages.data ? (
          <QueryError what="outages" query={outages} />
        ) : outages.isPending ? (
          <LoadingState />
        ) : !outages.data?.outages?.length ? (
          <EmptyState message={`No outages recorded in the last ${days} days.`} />
        ) : (
          <DataTable stickyHeader maxHeight={AVAILABILITY_TABLE_MAX_HEIGHT}>
            <thead>
              <tr>
                <th>Name</th>
                <th>Entity</th>
                <th>Started</th>
                <th>Ended</th>
                <th style={{ textAlign: 'right' }}>Duration</th>
              </tr>
            </thead>
            <tbody>
              {outages.data.outages.map((o) => (
                <tr key={o.id}>
                  <td>{o.hostname || 'Unknown'}</td>
                  <td>{entityLabel(o.entity_type, o.entity_id)}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>{formatBackendDateTime(o.down_at)}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    {o.up_at ? formatBackendDateTime(o.up_at) : <span style={{ color: 'var(--danger)' }}>Ongoing</span>}
                  </td>
                  <td style={{ textAlign: 'right' }}>{o.duration_seconds != null ? formatUptime(o.duration_seconds) : '-'}</td>
                </tr>
              ))}
            </tbody>
          </DataTable>
        )
      )}

      {subTab === 'transitions' && (
        transitions.error && !transitions.data ? (
          <QueryError what="state transitions" query={transitions} />
        ) : transitions.isPending ? (
          <LoadingState />
        ) : !transitions.data?.transitions?.length ? (
          <EmptyState message={`No state changes recorded in the last ${days} days.`} />
        ) : (
          <DataTable stickyHeader maxHeight={AVAILABILITY_TABLE_MAX_HEIGHT}>
            <thead>
              <tr>
                <th>Time</th>
                <th>Name</th>
                <th>Entity</th>
                <th>From</th>
                <th>To</th>
              </tr>
            </thead>
            <tbody>
              {transitions.data.transitions.map((t) => (
                <tr key={t.id}>
                  <td style={{ whiteSpace: 'nowrap' }}>{formatBackendDateTime(t.transition_at)}</td>
                  <td>{t.hostname || 'Unknown'}</td>
                  <td>{entityLabel(t.entity_type, t.entity_id)}</td>
                  <td><StatusBadge status={t.old_state} /></td>
                  <td><StatusBadge status={t.new_state} /></td>
                </tr>
              ))}
            </tbody>
          </DataTable>
        )
      )}

      <TopologyAvailabilityPanel days={days} />
      <MerakiAlertsPanel />
      <CatoEgressPanel />
    </div>
  );
}
