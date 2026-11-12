import { useMemo, useState } from 'react';

import {
  useTopologyAvailabilityOutages,
  useTopologyAvailabilitySummary,
  useTopologyAvailabilityTransitions,
} from '@/api/monitoring';
import { StatusBadge } from '@/components/Badge';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { StatGrid, StatTile } from '@/components/StatTile';
import { TabBar } from '@/components/TabBar';
import { type Tone } from '@/lib/severity';
import { useLinkedParam } from '@/lib/useLinkedParam';
import { useScrollToHash } from '@/lib/useScrollToHash';
import {
  AVAILABILITY_SOURCE_PARAM,
  AVAILABILITY_STATE_FILTERS,
  AVAILABILITY_STATE_PARAM,
  AVAILABILITY_TYPE_PARAM,
  TOPOLOGY_AVAILABILITY_ANCHOR,
  TOPOLOGY_ENTITY_TYPES as ENTITY_TYPES,
  type AvailabilityStateFilter,
  entityTypeLabel,
  matchesAvailabilityState,
  parseAvailabilityEntityType,
  parseAvailabilitySource,
  parseAvailabilityState,
} from '@/pages/Dashboard/sourceHealth';
import { sourceTypeLabel } from '@/pages/Topology/merakiHelpers';
import { formatBackendDateTime } from '@/lib/datetime';

import { AVAILABILITY_TABLE_MAX_HEIGHT, countTone, formatUptime, formatUptimePct } from './helpers';

type SubTab = 'entities' | 'outages' | 'transitions';

const SUB_TABS: { key: SubTab; label: string }[] = [
  { key: 'entities', label: 'Entities' },
  { key: 'outages', label: 'Outages' },
  { key: 'transitions', label: 'Transitions' },
];

/**
 * Availability of what the integrations collect (Meraki, Cato, Cisco FMC,
 * Palo Alto Panorama, Appgate SDP, AWS, Azure, GCP): devices, sites, uplinks,
 * tunnels, VPN connections, circuits, peerings and HA links, with uptime
 * over the period picked above.
 */
export function TopologyAvailabilityPanel({ days }: { days: number }) {
  // `?source=<provider>[:<org_ref>]`, `?type=<entity type>` and
  // `?state=<state>` (the Dashboard's integration cards and entity counts)
  // open the panel filtered to them, until another value is picked.
  const [linkedSource, clearLinkedSource] = useLinkedParam(AVAILABILITY_SOURCE_PARAM);
  const [provider, setProvider] = useState(() => parseAvailabilitySource(linkedSource)?.provider ?? '');
  const [orgRef, setOrgRef] = useState<number | null>(() => parseAvailabilitySource(linkedSource)?.orgRef ?? null);
  const [linkedType, clearLinkedType] = useLinkedParam(AVAILABILITY_TYPE_PARAM);
  const [entityType, setEntityType] = useState(() => parseAvailabilityEntityType(linkedType) ?? '');
  const [linkedState, clearLinkedState] = useLinkedParam(AVAILABILITY_STATE_PARAM);
  // Current state of the entities listed; the summary API has no state filter, so it applies to the table.
  const [stateFilter, setStateFilter] = useState<AvailabilityStateFilter | null>(() => parseAvailabilityState(linkedState));
  const [subTab, setSubTab] = useState<SubTab>('entities');
  // The Dashboard links here (#topology-availability) from its entity counts.
  useScrollToHash();

  const filters = { provider: provider || null, orgRef, entityType: entityType || null, days };
  const summary = useTopologyAvailabilitySummary(filters);
  const outages = useTopologyAvailabilityOutages({ ...filters, limit: 200 });
  const transitions = useTopologyAvailabilityTransitions({ ...filters, limit: 500 });

  const s = summary.data;
  const entities = useMemo(
    () => (stateFilter ? (s?.entities ?? []).filter((e) => matchesAvailabilityState(e.current_state, stateFilter)) : (s?.entities ?? [])),
    [s, stateFilter],
  );
  const orgs = s?.orgs ?? [];
  // A linked provider stays listed while the summary loads (or has none of it).
  const providers = [...new Set([...orgs.map((o) => o.provider), ...(provider ? [provider] : [])])];
  const cards: { label: string; value: string | number; tone?: Tone }[] = [
    { label: 'Entities Tracked', value: s?.entity_count ?? '-' },
    { label: 'Up', value: s?.up ?? '-', tone: countTone(s?.up, 'success') },
    { label: 'Degraded', value: s?.degraded ?? '-', tone: countTone(s?.degraded, 'warning') },
    { label: 'Down', value: s?.down ?? '-', tone: countTone(s?.down, 'danger') },
    { label: 'Avg Uptime', value: formatUptimePct(s?.avg_uptime_pct) },
    { label: `Outages (${days}d)`, value: s?.total_outages ?? '-' },
  ];

  return (
    <div id={TOPOLOGY_AVAILABILITY_ANCHOR} style={{ marginTop: '1.5rem' }}>
      <h3 style={{ marginBottom: '0.5rem' }}>Integrations and cloud</h3>
      <p className="text-muted" style={{ marginTop: 0, fontSize: '0.85em' }}>
        Devices, sites, uplinks, tunnels and cloud connections reported by each collection of a Meraki, Cato, FMC,
        Panorama or Appgate source and each AWS, Azure or GCP discovery.
      </p>

      <div className="toolbar">
        <label className="text-muted" htmlFor="topo-avail-provider">Source:</label>
        <select
          id="topo-avail-provider"
          className="form-select"
          value={provider}
          onChange={(e) => {
            setProvider(e.target.value);
            setOrgRef(null);
            clearLinkedSource();
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
          onChange={(e) => {
            setOrgRef(e.target.value ? parseInt(e.target.value, 10) : null);
            clearLinkedSource();
          }}
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
          onChange={(e) => {
            setEntityType(e.target.value);
            clearLinkedType();
          }}
        >
          <option value="">All types</option>
          {ENTITY_TYPES.map((t) => (
            <option key={t.key} value={t.key}>{t.label}</option>
          ))}
        </select>
        {subTab === 'entities' && (
          <>
            <label className="text-muted" htmlFor="topo-avail-state">State:</label>
            <select
              id="topo-avail-state"
              className="form-select"
              value={stateFilter ?? ''}
              onChange={(e) => {
                setStateFilter(parseAvailabilityState(e.target.value));
                clearLinkedState();
              }}
            >
              <option value="">All states</option>
              {AVAILABILITY_STATE_FILTERS.map((f) => (
                <option key={f.key} value={f.key}>{f.label}</option>
              ))}
            </select>
          </>
        )}
      </div>

      <StatGrid compact>
        {cards.map((c) => (
          <StatTile key={c.label} center label={c.label} value={c.value} tone={c.tone} />
        ))}
      </StatGrid>

      <TabBar tabs={SUB_TABS} active={subTab} onChange={setSubTab} size="sm" aria-label="Integration availability views" />

      {subTab === 'entities' && (
        summary.error && !s ? (
          <QueryError what="integration availability" query={summary} />
        ) : summary.isPending ? (
          <LoadingState />
        ) : !s?.entities.length ? (
          <EmptyState message="Nothing tracked yet - collect a topology source or run a cloud discovery." />
        ) : !entities.length ? (
          <EmptyState message="No entities in this state." />
        ) : (
          <DataTable stickyHeader maxHeight={AVAILABILITY_TABLE_MAX_HEIGHT}>
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
                {entities.map((e) => (
                  <tr key={`${e.provider}:${e.org_ref}:${e.entity_type}:${e.entity_id}`}>
                    <td title={e.model || undefined}>{e.name}</td>
                    <td>
                      {sourceTypeLabel(e.provider)}
                      {e.org_name && <span className="text-muted" style={{ fontSize: '0.85em' }}> {e.org_name}</span>}
                    </td>
                    <td>{entityTypeLabel(e.entity_type)}</td>
                    <td>{e.site || '-'}</td>
                    <td>
                      <StatusBadge status={e.current_state} />
                      {e.missing && <span className="text-muted" style={{ fontSize: '0.8em', marginLeft: '0.3rem' }}>not in last collection</span>}
                    </td>
                    <td style={{ textAlign: 'right' }}>{formatUptimePct(e.uptime_pct)}</td>
                    <td style={{ whiteSpace: 'nowrap' }}>{formatBackendDateTime(e.last_change)}</td>
                    <td style={{ textAlign: 'right' }}>{e.outage_count}</td>
                  </tr>
                ))}
              </tbody>
          </DataTable>
        )
      )}

      {subTab === 'outages' && (
        outages.error && !outages.data ? (
          <QueryError what="integration outages" query={outages} />
        ) : outages.isPending ? (
          <LoadingState />
        ) : !outages.data?.outages.length ? (
          <EmptyState message={`No outages recorded in the last ${days} days.`} />
        ) : (
          <DataTable stickyHeader maxHeight={AVAILABILITY_TABLE_MAX_HEIGHT}>
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
                    <td style={{ whiteSpace: 'nowrap' }}>{formatBackendDateTime(o.started_at)}</td>
                    <td style={{ whiteSpace: 'nowrap' }}>
                      {o.ended_at ? formatBackendDateTime(o.ended_at) : <span style={{ color: 'var(--danger)' }}>Ongoing</span>}
                    </td>
                    <td style={{ textAlign: 'right' }}>{formatUptime(o.duration_seconds)}</td>
                  </tr>
                ))}
              </tbody>
          </DataTable>
        )
      )}

      {subTab === 'transitions' && (
        transitions.error && !transitions.data ? (
          <QueryError what="integration state changes" query={transitions} />
        ) : transitions.isPending ? (
          <LoadingState />
        ) : !transitions.data?.transitions.length ? (
          <EmptyState message={`No state changes recorded in the last ${days} days.`} />
        ) : (
          <DataTable stickyHeader maxHeight={AVAILABILITY_TABLE_MAX_HEIGHT}>
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
                    <td style={{ whiteSpace: 'nowrap' }}>{formatBackendDateTime(t.transition_at)}</td>
                    <td>{t.name}</td>
                    <td>{sourceTypeLabel(t.provider)}</td>
                    <td>{entityTypeLabel(t.entity_type)}</td>
                    <td><StatusBadge status={t.old_state} /></td>
                    <td><StatusBadge status={t.new_state} /></td>
                  </tr>
                ))}
              </tbody>
          </DataTable>
        )
      )}
    </div>
  );
}
