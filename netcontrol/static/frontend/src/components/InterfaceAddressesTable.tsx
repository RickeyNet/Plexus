import { useHostInterfaceAddresses } from '@/api/networkObjects';
import { addressRoleLabel, formatInterfaceAddress, vrfLabel } from '@/lib/networkObjects';

import { DataTable } from './DataTable';
import { QueryError } from './QueryError';

export interface InterfaceAddressesTableProps {
  hostId: number;
  /** Smaller type for the map's node details panel. */
  dense?: boolean;
}

/**
 * The "IP addresses" table of a device: every address its interfaces carry
 * (from the newest stored running configuration), with its VRF, role and
 * VLAN. Used by the map's node details and the device detail page.
 */
export function InterfaceAddressesTable({ hostId, dense }: InterfaceAddressesTableProps) {
  const q = useHostInterfaceAddresses(hostId);
  const textStyle = { fontSize: dense ? '0.78rem' : undefined, margin: 0 };

  let body;
  if (q.isError && !q.data) {
    body = <QueryError what="interface addresses" query={q} />;
  } else if (q.isPending) {
    body = (
      <p className="text-muted" style={textStyle}>
        Loading…
      </p>
    );
  } else if ((q.data?.addresses ?? []).length === 0) {
    body = (
      <p className="text-muted" style={textStyle}>
        No interface addresses. They are read from the device&apos;s stored running configuration.
      </p>
    );
  } else {
    body = (
      <DataTable compact aria-label="Interface IP addresses">
        <thead>
          <tr>
            <th>Interface</th>
            <th>Address</th>
            <th>VRF</th>
            <th>Role</th>
            <th>VLAN</th>
          </tr>
        </thead>
        <tbody style={dense ? { fontSize: '0.75rem' } : undefined}>
          {q.data!.addresses.map((a) => (
            <tr key={`${a.interface}|${a.address}`}>
              <td>{a.interface}</td>
              <td>{formatInterfaceAddress(a)}</td>
              <td>{a.vrf_name ? a.vrf_name : <span className="text-muted">{vrfLabel(a.vrf_name)}</span>}</td>
              <td>{addressRoleLabel(a)}</td>
              <td>{a.svi_vid > 0 ? a.svi_vid : <span className="text-muted">-</span>}</td>
            </tr>
          ))}
        </tbody>
      </DataTable>
    );
  }

  return (
    <section aria-label="IP addresses">
      <h4 style={{ margin: '0 0 var(--space-2)', fontSize: dense ? '0.78rem' : '0.95rem' }}>IP addresses</h4>
      {body}
    </section>
  );
}
