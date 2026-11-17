import { Link } from 'react-router';

import { useBgpPeerings, useRoutingCompliance, useRoutingInstances } from '@/api/routing';
import { DataTable } from '@/components/DataTable';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { formatAsn } from '@/lib/routing';
import { ComplianceBadge, RoutingStatusBadge } from '@/pages/Routing/RoutingParts';

/**
 * A device's intended BGP state: its routing instances and peerings, each
 * with its compliance state against the observed neighbors. Shown only to
 * callers with the routing feature.
 */
export function BgpIntentSection({ hostId }: { hostId: number }) {
  const instances = useRoutingInstances({ host_id: hostId });
  const peerings = useBgpPeerings({ host_id: hostId });
  const compliance = useRoutingCompliance(hostId);

  const title = <h3 style={{ margin: '0 0 0.5rem', fontSize: '1rem' }}>BGP intent</h3>;
  if (instances.isError && !instances.data) {
    return (
      <section aria-label="BGP intent">
        {title}
        <QueryError what="routing instances" query={instances} />
      </section>
    );
  }
  if (instances.isPending || peerings.isPending) return <LoadingState text="Loading BGP intent…" />;

  const stateOf = new Map<number, string>();
  for (const r of compliance.data?.rows ?? []) if (r.peering_id !== null) stateOf.set(r.peering_id, r.state);
  const unexpected = (compliance.data?.rows ?? []).filter((r) => r.state === 'unexpected');
  const noData = compliance.data?.hosts[0] && !compliance.data.hosts[0].has_data;

  if ((instances.data ?? []).length === 0) {
    return (
      <section aria-label="BGP intent">
        {title}
        <p className="text-muted" style={{ margin: 0 }}>
          No routing instance is recorded for this device.
          {unexpected.length > 0 && ` ${unexpected.length} BGP neighbor${unexpected.length === 1 ? ' was' : 's were'} observed.`}{' '}
          <Link to="/routing/compliance">Open Routing</Link>
        </p>
      </section>
    );
  }

  return (
    <section aria-label="BGP intent">
      {title}
      <div className="text-muted" style={{ fontSize: '0.88em', marginBottom: '0.5rem' }}>
        {(instances.data ?? []).map((i) => `${i.name} (${formatAsn(i.asn)}${i.router_id ? `, router ID ${i.router_id}` : ''})`).join(' · ')}
        {noData && ' · no neighbor discovery data yet'}
        {unexpected.length > 0 && ` · ${unexpected.length} unexpected neighbor${unexpected.length === 1 ? '' : 's'}`}
      </div>
      <DataTable compact aria-label="BGP peerings of this device" maxHeight={280}>
        <thead>
          <tr>
            <th>Instance</th>
            <th>Remote</th>
            <th>Remote AS</th>
            <th>Status</th>
            <th>Compliance</th>
          </tr>
        </thead>
        <tbody>
          {(peerings.data ?? []).map((p) => {
            const state = stateOf.get(p.id);
            return (
              <tr key={p.id}>
                <td>{p.routing_instance_name}</td>
                <td>{p.remote_address}</td>
                <td>{formatAsn(p.remote_asn)}</td>
                <td>
                  <RoutingStatusBadge status={p.status} />
                </td>
                <td>{state ? <ComplianceBadge state={state} /> : <span className="text-muted">-</span>}</td>
              </tr>
            );
          })}
        </tbody>
      </DataTable>
    </section>
  );
}
