import { useState } from 'react';

import { useInventoryGroups } from '@/api/compliance';
import {
  useAvailabilityOutages,
  useAvailabilitySummary,
  useAvailabilityTransitions,
} from '@/api/monitoring';
import { formatTimestamp, formatUptime } from './helpers';

type SubTab = 'hosts' | 'outages' | 'transitions';

export function AvailabilityTab() {
  const groups = useInventoryGroups();
  const [groupId, setGroupId] = useState<number | null>(null);
  const [days, setDays] = useState(7);
  const [subTab, setSubTab] = useState<SubTab>('hosts');

  const summary = useAvailabilitySummary(groupId, days);
  const outages = useAvailabilityOutages({ groupId, days, limit: 200 });
  const transitions = useAvailabilityTransitions(500);

  const s = summary.data ?? {};
  const cards = [
    { label: 'Hosts Tracked', value: s.total_hosts ?? '-' },
    { label: 'Currently Up', value: s.hosts_up ?? '-', color: 'success' },
    { label: 'Currently Down', value: s.hosts_down ?? '-', color: 'danger' },
    { label: 'Avg Uptime', value: s.avg_uptime_pct != null ? `${s.avg_uptime_pct.toFixed(2)}%` : '-' },
    { label: `Outages (${days}d)`, value: s.total_outages ?? '-' },
  ];

  return (
    <div>
      <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginBottom: '0.75rem', flexWrap: 'wrap' }}>
        <label className="text-muted">Group:</label>
        <select
          className="form-select"
          value={groupId ?? ''}
          onChange={(e) => setGroupId(e.target.value ? parseInt(e.target.value, 10) : null)}
        >
          <option value="">All Groups</option>
          {(groups.data ?? []).map((g) => (
            <option key={g.id} value={g.id}>{g.name}</option>
          ))}
        </select>
        <label className="text-muted">Period:</label>
        <select className="form-select" value={days} onChange={(e) => setDays(parseInt(e.target.value, 10))}>
          <option value={1}>Last 24h</option>
          <option value={7}>Last 7 days</option>
          <option value={30}>Last 30 days</option>
        </select>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '0.5rem', marginBottom: '0.75rem' }}>
        {cards.map((c) => (
          <div key={c.label} className="card" style={{ padding: '0.75rem', textAlign: 'center' }}>
            <div style={{ fontSize: '1.4em', fontWeight: 600, color: c.color ? `var(--${c.color})` : '' }}>{c.value}</div>
            <div className="text-muted" style={{ fontSize: '0.85em' }}>{c.label}</div>
          </div>
        ))}
      </div>

      <div className="tab-bar" role="tablist" style={{ marginBottom: '0.75rem' }}>
        {(['hosts', 'outages', 'transitions'] as SubTab[]).map((t) => (
          <button
            key={t}
            role="tab"
            aria-selected={subTab === t}
            className={`tab-btn${subTab === t ? ' active' : ''}`}
            onClick={() => setSubTab(t)}
          >
            {t === 'hosts' ? 'Hosts' : t === 'outages' ? 'Outages' : 'Transitions'}
          </button>
        ))}
      </div>

      {subTab === 'hosts' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
          {(s.hosts ?? []).length === 0 ? (
            <div className="empty-state">No availability data - run polls to begin tracking.</div>
          ) : (
            (s.hosts ?? []).map((h) => {
              const uptimeColor = (h.uptime_pct ?? 100) >= 99.9 ? 'success' : (h.uptime_pct ?? 100) >= 99 ? 'warning' : 'danger';
              const stateColor = h.current_state === 'up' ? 'success' : h.current_state === 'down' ? 'danger' : 'text-muted';
              return (
                <div key={h.host_id} className="card" style={{ padding: '0.75rem 1rem' }}>
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
          {!outages.data?.outages?.length ? (
            <div className="card text-muted" style={{ padding: '1rem' }}>No outages recorded in the last {days} days.</div>
          ) : (
            outages.data.outages.map((o) => (
              <div key={o.id} className="card" style={{ padding: '0.75rem 1rem', borderLeft: '3px solid var(--danger)' }}>
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
                  {formatTimestamp(o.started_at)} - {o.ended_at ? formatTimestamp(o.ended_at) : <span style={{ color: 'var(--danger)' }}>Ongoing</span>}
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {subTab === 'transitions' && (
        !transitions.data?.transitions?.length ? (
          <div className="card text-muted" style={{ padding: '1rem' }}>No state transitions recorded.</div>
        ) : (
          <div style={{ maxHeight: 480, overflow: 'auto' }}>
            <table style={{ width: '100%', fontSize: '0.85em', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '2px solid var(--border-color)' }}>
                  <th style={{ textAlign: 'left', padding: '4px 8px' }}>Time</th>
                  <th style={{ textAlign: 'left', padding: '4px 8px' }}>Host</th>
                  <th style={{ textAlign: 'left', padding: '4px 8px' }}>Entity</th>
                  <th style={{ textAlign: 'center', padding: '4px 8px' }}>From</th>
                  <th style={{ textAlign: 'center', padding: '4px 8px' }}>To</th>
                </tr>
              </thead>
              <tbody>
                {transitions.data.transitions.slice(0, 200).map((t) => {
                  const fromColor = t.old_state === 'up' ? 'success' : t.old_state === 'down' ? 'danger' : 'text-muted';
                  const toColor = t.new_state === 'up' ? 'success' : t.new_state === 'down' ? 'danger' : 'text-muted';
                  return (
                    <tr key={t.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                      <td style={{ padding: '4px 8px' }}>{formatTimestamp(t.changed_at)}</td>
                      <td style={{ padding: '4px 8px' }}>{t.hostname}</td>
                      <td style={{ padding: '4px 8px' }}>{t.entity_type ?? 'host'}{t.entity_id ? ` ${t.entity_id}` : ''}</td>
                      <td style={{ padding: '4px 8px', textAlign: 'center', color: `var(--${fromColor})` }}>{t.old_state ?? '?'}</td>
                      <td style={{ padding: '4px 8px', textAlign: 'center', color: `var(--${toColor})` }}>{t.new_state ?? '?'}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )
      )}
    </div>
  );
}
