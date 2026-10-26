import { useState } from 'react';

import {
  useTopologyAvailabilityOutages,
  useTopologyAvailabilitySummary,
  useTopologyAvailabilityTransitions,
} from '@/api/monitoring';
import { TabBar } from '@/components/TabBar';
import { availabilityBadgeClass } from '@/pages/Reports/helpers';
import { sourceTypeLabel } from '@/pages/Topology/merakiHelpers';

import { formatTimestamp, formatUptime } from './helpers';

type SubTab = 'entities' | 'outages' | 'transitions';

const SUB_TABS: { key: SubTab; label: string }[] = [
  { key: 'entities', label: 'Entities' },
  { key: 'outages', label: 'Outages' },
  { key: 'transitions', label: 'Transitions' },
];

const ENTITY_TYPES: { key: string; label: string }[] = [
  { key: 'device', label: 'Device' },
  { key: 'site', label: 'Site' },
  { key: 'uplink', label: 'Uplink' },
  { key: 'tunnel', label: 'Tunnel' },
  { key: 'vpn_connection', label: 'VPN connection' },
  { key: 'circuit', label: 'Circuit' },
  { key: 'peering', label: 'Peering' },
  { key: 'link', label: 'Link' },
];

const entityTypeLabel = (type: string) => ENTITY_TYPES.find((t) => t.key === type)?.label ?? type;

/**
 * Availability of what the integrations collect (Meraki, Cato, Cisco FMC,
 * Palo Alto Panorama, Appgate SDP, AWS, Azure, GCP): devices, sites, uplinks,
 * tunnels, VPN connections, circuits, peerings and HA links, with uptime
 * over the period picked above.
 */
export function TopologyAvailabilityPanel({ days }: { days: number }) {
  const [provider, setProvider] = useState('');
  const [orgRef, setOrgRef] = useState<number | null>(null);
  const [entityType, setEntityType] = useState('');
  const [subTab, setSubTab] = useState<SubTab>('entities');

  const filters = { provider: provider || null, orgRef, entityType: entityType || null, days };
  const summary = useTopologyAvailabilitySummary(filters);
  const outages = useTopologyAvailabilityOutages({ ...filters, limit: 200 });
  const transitions = useTopologyAvailabilityTransitions({ ...filters, limit: 500 });

  const s = summary.data;
  const orgs = s?.orgs ?? [];
  const providers = [...new Set(orgs.map((o) => o.provider))];
  const cards = [
    { label: 'Entities Tracked', value: s?.entity_count ?? '-' },
    { label: 'Up', value: s?.up ?? '-', color: 'success' },
    { label: 'Degraded', value: s?.degraded ?? '-', color: 'warning' },
    { label: 'Down', value: s?.down ?? '-', color: 'danger' },
    { label: 'Avg Uptime', value: s?.avg_uptime_pct != null ? `${s.avg_uptime_pct.toFixed(2)}%` : '-' },
    { label: `Outages (${days}d)`, value: s?.total_outages ?? '-' },
  ];

  return (
    <div style={{ marginTop: '1.5rem' }}>
      <h3 style={{ marginBottom: '0.5rem' }}>Integrations and cloud</h3>
      <p className="text-muted" style={{ marginTop: 0, fontSize: '0.85em' }}>
        Devices, sites, uplinks, tunnels and cloud connections reported by each collection of a Meraki, Cato, FMC,
        Panorama or Appgate source and each AWS, Azure or GCP discovery.
      </p>

      <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginBottom: '0.75rem', flexWrap: 'wrap' }}>
        <label className="text-muted" htmlFor="topo-avail-provider">Source:</label>
        <select
          id="topo-avail-provider"
          className="form-select"
          value={provider}
          onChange={(e) => {
            setProvider(e.target.value);
            setOrgRef(null);
          }}
        >
          <option value="">All sources</option>
          {providers.map((p) => (
            <option key={p} value={p}>{sourceTypeLabel(p)}</option>
          ))}
        </select>
        <label className="text-muted" htmlFor="topo-avail-org">Organization:</label>
        <select
          id="topo-avail-org"
          className="form-select"
          value={orgRef ?? ''}
          onChange={(e) => setOrgRef(e.target.value ? parseInt(e.target.value, 10) : null)}
        >
          <option value="">All</option>
          {orgs
            .filter((o) => !provider || o.provider === provider)
            .map((o) => (
              <option key={`${o.provider}:${o.org_ref}`} value={o.org_ref}>
                {o.org_name || `${sourceTypeLabel(o.provider)} ${o.org_ref}`}
              </option>
            ))}
        </select>
        <label className="text-muted" htmlFor="topo-avail-type">Type:</label>
        <select
          id="topo-avail-type"
          className="form-select"
          value={entityType}
          onChange={(e) => setEntityType(e.target.value)}
        >
          <option value="">All types</option>
          {ENTITY_TYPES.map((t) => (
            <option key={t.key} value={t.key}>{t.label}</option>
          ))}
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

      <TabBar tabs={SUB_TABS} active={subTab} onChange={setSubTab} size="sm" aria-label="Integration availability views" />

      {summary.error && <p style={{ color: 'var(--danger)' }}>Failed to load availability.</p>}

      {subTab === 'entities' && (
        !s?.entities.length ? (
          <div className="empty-state">
            {summary.isPending ? 'Loading…' : 'Nothing tracked yet - collect a topology source or run a cloud discovery.'}
          </div>
        ) : (
          <div style={{ maxHeight: 520, overflow: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Source</th>
                  <th>Type</th>
                  <th>Site</th>
                  <th>State</th>
                  <th style={{ textAlign: 'right' }}>Uptime</th>
                  <th>Last change</th>
                  <th style={{ textAlign: 'right' }}>Outages</th>
                </tr>
              </thead>
              <tbody>
                {s.entities.map((e) => (
                  <tr key={`${e.provider}:${e.org_ref}:${e.entity_type}:${e.entity_id}`}>
                    <td title={e.model || undefined}>{e.name}</td>
                    <td>
                      {sourceTypeLabel(e.provider)}
                      {e.org_name && <span className="text-muted" style={{ fontSize: '0.85em' }}> {e.org_name}</span>}
                    </td>
                    <td>{entityTypeLabel(e.entity_type)}</td>
                    <td>{e.site || '-'}</td>
                    <td>
                      <span className={`badge ${availabilityBadgeClass(e.current_state)}`}>{e.current_state}</span>
                      {e.missing && <span className="text-muted" style={{ fontSize: '0.8em', marginLeft: '0.3rem' }}>not in last collection</span>}
                    </td>
                    <td style={{ textAlign: 'right' }}>{e.uptime_pct != null ? `${e.uptime_pct.toFixed(2)}%` : '-'}</td>
                    <td style={{ whiteSpace: 'nowrap' }}>{formatTimestamp(e.last_change)}</td>
                    <td style={{ textAlign: 'right' }}>{e.outage_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}

      {subTab === 'outages' && (
        !outages.data?.outages.length ? (
          <div className="empty-state">No outages recorded in the last {days} days.</div>
        ) : (
          <div style={{ maxHeight: 520, overflow: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Source</th>
                  <th>Type</th>
                  <th>Started</th>
                  <th>Ended</th>
                  <th style={{ textAlign: 'right' }}>Duration</th>
                </tr>
              </thead>
              <tbody>
                {outages.data.outages.map((o) => (
                  <tr key={`${o.provider}:${o.org_ref}:${o.entity_type}:${o.entity_id}:${o.started_at}`}>
                    <td>{o.name}</td>
                    <td>{sourceTypeLabel(o.provider)}</td>
                    <td>{entityTypeLabel(o.entity_type)}</td>
                    <td style={{ whiteSpace: 'nowrap' }}>{formatTimestamp(o.started_at)}</td>
                    <td style={{ whiteSpace: 'nowrap' }}>
                      {o.ended_at ? formatTimestamp(o.ended_at) : <span style={{ color: 'var(--danger)' }}>Ongoing</span>}
                    </td>
                    <td style={{ textAlign: 'right' }}>{formatUptime(o.duration_seconds)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}

      {subTab === 'transitions' && (
        !transitions.data?.transitions.length ? (
          <div className="empty-state">No state changes recorded in the last {days} days.</div>
        ) : (
          <div style={{ maxHeight: 520, overflow: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Name</th>
                  <th>Source</th>
                  <th>Type</th>
                  <th>From</th>
                  <th>To</th>
                </tr>
              </thead>
              <tbody>
                {transitions.data.transitions.map((t) => (
                  <tr key={t.id}>
                    <td style={{ whiteSpace: 'nowrap' }}>{formatTimestamp(t.transition_at)}</td>
                    <td>{t.name}</td>
                    <td>{sourceTypeLabel(t.provider)}</td>
                    <td>{entityTypeLabel(t.entity_type)}</td>
                    <td><span className={`badge ${availabilityBadgeClass(t.old_state)}`}>{t.old_state}</span></td>
                    <td><span className={`badge ${availabilityBadgeClass(t.new_state)}`}>{t.new_state}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}
    </div>
  );
}
