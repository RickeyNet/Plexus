import { useId, useState } from 'react';

import { groupLabel } from '@/api/inventory';
import { useInventoryGroups } from '@/api/compliance';
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
import { type Tone } from '@/lib/severity';
import { CatoEgressPanel } from './CatoEgressPanel';
import { formatUptime } from './helpers';
import { TopologyAvailabilityPanel } from './TopologyAvailabilityPanel';

type SubTab = 'hosts' | 'outages' | 'transitions';

const SUB_TABS: { key: SubTab; label: string }[] = [
  { key: 'hosts', label: 'Hosts' },
  { key: 'outages', label: 'Outages' },
  { key: 'transitions', label: 'Transitions' },
];

export function AvailabilityTab() {
  const groups = useInventoryGroups();
  const fid = useId();
  const [groupId, setGroupId] = useState<number | null>(null);
  const [days, setDays] = useState(7);
  const [subTab, setSubTab] = useState<SubTab>('hosts');

  const summary = useAvailabilitySummary(groupId, days);
  const outages = useAvailabilityOutages({ groupId, days, limit: 200 });
  const transitions = useAvailabilityTransitions(500);

  const s = summary.data ?? {};
  const cards: { label: string; value: string | number; tone?: Tone }[] = [
    { label: 'Hosts Tracked', value: s.total_hosts ?? '-' },
    { label: 'Currently Up', value: s.hosts_up ?? '-', tone: 'success' },
    { label: 'Currently Down', value: s.hosts_down ?? '-', tone: 'danger' },
    { label: 'Avg Uptime', value: s.avg_uptime_pct != null ? `${s.avg_uptime_pct.toFixed(2)}%` : '-' },
    { label: `Outages (${days}d)`, value: s.total_outages ?? '-' },
  ];

  return (
    <div>
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
        <label className="text-muted" htmlFor={`${fid}-period`}>Period:</label>
        <select id={`${fid}-period`} className="form-select" value={days} onChange={(e) => setDays(parseInt(e.target.value, 10))}>
          <option value={1}>Last 24h</option>
          <option value={7}>Last 7 days</option>
          <option value={30}>Last 30 days</option>
        </select>
      </div>

      <StatGrid compact>
        {cards.map((c) => (
          <StatTile key={c.label} center label={c.label} value={c.value} tone={c.tone} />
        ))}
      </StatGrid>

      <TabBar tabs={SUB_TABS} active={subTab} onChange={setSubTab} size="sm" aria-label="Availability views" />

      {subTab === 'hosts' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
          {summary.error && !summary.data ? (
            <QueryError what="availability summary" query={summary} />
          ) : summary.isPending ? (
            <LoadingState />
          ) : (s.hosts ?? []).length === 0 ? (
            <EmptyState message="No availability data - run polls to begin tracking." />
          ) : (
            (s.hosts ?? []).map((h) => {
              const uptimeColor = (h.uptime_pct ?? 100) >= 99.9 ? 'success' : (h.uptime_pct ?? 100) >= 99 ? 'warning' : 'danger';
              const stateColor = h.current_state === 'up' ? 'success' : h.current_state === 'down' ? 'danger' : 'text-muted';
              return (
                <div key={h.host_id} className="card card-sm">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                      <span style={{ width: 8, height: 8, borderRadius: '50%', background: `var(--${stateColor})`, display: 'inline-block' }} />
                      <strong style={{ marginLeft: '0.4rem' }}>{h.hostname || 'Unknown'}</strong>
                      <span className="text-muted" style={{ fontSize: '0.85em', marginLeft: '0.4rem' }}>{h.ip_address}</span>
                    </div>
                    <span style={{ color: `var(--${uptimeColor})`, fontWeight: 600 }}>
                      {h.uptime_pct != null ? `${h.uptime_pct.toFixed(2)}%` : '-'}
                    </span>
                  </div>
                </div>
              );
            })
          )}
        </div>
      )}

      {subTab === 'outages' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
          {outages.error && !outages.data ? (
            <QueryError what="outages" query={outages} />
          ) : outages.isPending ? (
            <LoadingState />
          ) : !outages.data?.outages?.length ? (
            <div className="card text-muted">No outages recorded in the last {days} days.</div>
          ) : (
            outages.data.outages.map((o) => (
              <div key={o.id} className="card card-sm" style={{ borderLeft: '3px solid var(--danger)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <strong>{o.hostname || 'Unknown'}</strong>
                    <span className="text-muted" style={{ fontSize: '0.85em', marginLeft: '0.4rem' }}>
                      {o.entity_type ?? 'host'}{o.entity_id ? ` ${o.entity_id}` : ''}
                    </span>
                  </div>
                  <span className="text-muted" style={{ fontSize: '0.85em' }}>
                    Duration: <strong>{o.duration_seconds ? formatUptime(o.duration_seconds) : '-'}</strong>
                  </span>
                </div>
                <div className="text-muted" style={{ marginTop: '0.3rem', fontSize: '0.85em' }}>
                  {formatBackendDateTime(o.started_at)} - {o.ended_at ? formatBackendDateTime(o.ended_at) : <span style={{ color: 'var(--danger)' }}>Ongoing</span>}
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {subTab === 'transitions' && (
        transitions.error && !transitions.data ? (
          <QueryError what="state transitions" query={transitions} />
        ) : transitions.isPending ? (
          <LoadingState />
        ) : !transitions.data?.transitions?.length ? (
          <div className="card text-muted">No state transitions recorded.</div>
        ) : (
          <div style={{ maxHeight: 480, overflow: 'auto' }}>
            <table className="data-table table-sm">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Host</th>
                  <th>Entity</th>
                  <th style={{ textAlign: 'center' }}>From</th>
                  <th style={{ textAlign: 'center' }}>To</th>
                </tr>
              </thead>
              <tbody>
                {transitions.data.transitions.slice(0, 200).map((t) => {
                  const fromColor = t.old_state === 'up' ? 'success' : t.old_state === 'down' ? 'danger' : 'text-muted';
                  const toColor = t.new_state === 'up' ? 'success' : t.new_state === 'down' ? 'danger' : 'text-muted';
                  return (
                    <tr key={t.id}>
                      <td>{formatBackendDateTime(t.changed_at)}</td>
                      <td>{t.hostname}</td>
                      <td>{t.entity_type ?? 'host'}{t.entity_id ? ` ${t.entity_id}` : ''}</td>
                      <td style={{ textAlign: 'center', color: `var(--${fromColor})` }}>{t.old_state ?? '?'}</td>
                      <td style={{ textAlign: 'center', color: `var(--${toColor})` }}>{t.new_state ?? '?'}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )
      )}

      <TopologyAvailabilityPanel days={days} />
      <CatoEgressPanel />
    </div>
  );
}
