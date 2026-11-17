import { useMemo, useState } from 'react';

import { useRoutingCompliance } from '@/api/routing';
import { CardHeader, CatalogueBody, Dash } from '@/components/CatalogueParts';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { formatBackendDateTime } from '@/lib/datetime';
import { COMPLIANCE_STATES, complianceStateLabel, formatAsn } from '@/lib/routing';

import { ComplianceBadge, HostSelect } from './RoutingParts';
import { useCanWriteRouting } from './routingHooks';
import { SuggestDialog } from './SuggestDialog';

/**
 * The Routing page's Compliance tab: every intended peering against the BGP
 * neighbors Plexus discovered, with the observed neighbors no peering names.
 * Pick a device to see its unexpected neighbors even without an instance,
 * and to record them from the suggestions.
 */
export function ComplianceTab() {
  const canWrite = useCanWriteRouting();
  const [hostId, setHostId] = useState<number | null>(null);
  const [state, setState] = useState('');
  const [suggesting, setSuggesting] = useState(false);
  const q = useRoutingCompliance(hostId);
  const rows = useMemo(() => (q.data?.rows ?? []).filter((r) => !state || r.state === state), [q.data, state]);
  const summary = q.data?.summary;
  const host = hostId !== null ? q.data?.hosts.find((h) => h.host_id === hostId) : undefined;

  return (
    <div className="card" style={{ minWidth: 0 }}>
      <CardHeader
        title="Intended vs observed BGP"
        sub="Compares the active peerings with the BGP neighbors neighbor discovery stored. A device that was never discovered shows No data."
        actions={
          canWrite &&
          hostId !== null && (
            <button type="button" className="btn btn-sm btn-primary" onClick={() => setSuggesting(true)}>
              Suggest from observed
            </button>
          )
        }
      />
      <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap', alignItems: 'center', marginBottom: 'var(--space-3)' }}>
        <div style={{ minWidth: 200 }}>
          <HostSelect id="routing-compliance-host" value={hostId} onChange={setHostId} allowNone noneLabel="Devices with routing intent" />
        </div>
        {summary &&
          COMPLIANCE_STATES.map((s) => (
            <button
              key={s}
              type="button"
              className={`btn btn-sm ${state === s ? 'btn-primary' : 'btn-secondary'}`}
              aria-pressed={state === s}
              onClick={() => setState(state === s ? '' : s)}
            >
              {complianceStateLabel(s)} ({summary[s]})
            </button>
          ))}
      </div>
      {host && !host.has_data && (
        <p className="text-muted" style={{ marginTop: 0 }}>
          No neighbor discovery data for {host.hostname} yet: its peerings cannot be compared.
        </p>
      )}
      {host?.has_data && host.last_discovered_at && (
        <p className="text-muted" style={{ marginTop: 0, fontSize: '0.88em' }}>
          Neighbors last stored {formatBackendDateTime(host.last_discovered_at)}.
        </p>
      )}
      <CatalogueBody
        query={{ ...q, data: q.data ? rows : undefined }}
        what="compliance"
        rows={rows}
        empty={
          <EmptyState
            compact
            message={state ? `No ${complianceStateLabel(state).toLowerCase()} rows.` : 'Nothing to compare yet.'}
            description={state ? undefined : 'Record routing instances and peerings for your devices, or pick a device and use Suggest from observed.'}
          />
        }
      >
        <DataTable compact aria-label="BGP compliance">
          <thead>
            <tr>
              <th>State</th>
              <th>Device</th>
              <th>Instance</th>
              <th>Remote</th>
              <th>Intended AS</th>
              <th>Observed AS</th>
              <th>Session</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={`${r.host_id}|${r.peering_id ?? 'x'}|${r.remote_address}`}>
                <td>
                  <ComplianceBadge state={r.state} />
                </td>
                <td>{r.hostname}</td>
                <td>{r.routing_instance || <Dash />}</td>
                <td style={{ fontWeight: 600 }}>{r.remote_address}</td>
                <td>{r.intended_remote_asn !== null ? formatAsn(r.intended_remote_asn) : <Dash />}</td>
                <td>{r.observed_remote_asn !== null ? formatAsn(r.observed_remote_asn) : <Dash />}</td>
                <td>{r.observed_state || <Dash />}</td>
                <td className="text-muted">{r.detail}</td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      </CatalogueBody>
      {suggesting && hostId !== null && <SuggestDialog hostId={hostId} onClose={() => setSuggesting(false)} />}
    </div>
  );
}
