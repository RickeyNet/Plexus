import { Link } from 'react-router';

import { useAuthStatus } from '@/api/auth';
import { useHostDcim } from '@/api/dcim';
import { DataTable } from '@/components/DataTable';
import { QueryError } from '@/components/QueryError';
import { endpointLabel, traceLink } from '@/lib/dcim';
import { canUseFeature, canWriteFeature } from '@/lib/tabGating';

import { InstantiateComponentsButton } from './InstantiateComponentsButton';

/**
 * The device page's DCIM section (anchored `#dcim`): where the device sits
 * in its rack and the cables on its interfaces, each with a trace link, and
 * (for users who may change inventory) the action that creates the
 * components its device type lists. Renders nothing for users without the
 * dcim feature, or when the device has no rack and no cable and the user
 * cannot create components.
 */
export function DeviceDcim({ hostId }: { hostId: number }) {
  const auth = useAuthStatus().data;
  const allowed = canUseFeature('dcim', auth);
  const canCreate = canWriteFeature('inventory', auth);
  const q = useHostDcim(hostId, allowed);
  if (!allowed) return null;
  if (q.isError && !q.data) return <QueryError what="rack and cables" query={q} />;
  if (!q.data) return null;
  const { placement, cables } = q.data;
  if (placement.rack_id === null && cables.length === 0 && !canCreate) return null;
  const near = (c: (typeof cables)[number]) => (c.a.host_id === hostId ? c.a : c.b);
  const far = (c: (typeof cables)[number]) => (c.a.host_id === hostId ? c.b : c.a);
  return (
    <section id="dcim" aria-label="Rack and cables">
      <div
        className="card-title"
        style={{ marginBottom: '0.5rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}
      >
        Rack and cables
        {canCreate && <InstantiateComponentsButton hostId={hostId} />}
      </div>
      <p style={{ margin: '0 0 0.5rem' }}>
        {placement.rack_id === null ? (
          <span className="text-muted">Not in a rack.</span>
        ) : (
          <>
            Rack <Link to="/dcim">{placement.rack_name}</Link>
            {placement.rack_site_name ? ` at ${placement.rack_site_name}` : ''}
            {placement.rack_position !== null
              ? `, unit ${placement.rack_position}${placement.height > 1 ? `-${placement.rack_position + placement.height - 1}` : ''} (${placement.rack_face})`
              : ', not mounted'}
          </>
        )}
      </p>
      {cables.length > 0 && (
        <DataTable compact aria-label="Cables on this device">
          <thead>
            <tr>
              <th>Port</th>
              <th>Cable</th>
              <th>Connected to</th>
              <th>Trace</th>
            </tr>
          </thead>
          <tbody>
            {cables.map((c) => (
              <tr key={c.id}>
                <td>{near(c).name || endpointLabel(near(c))}</td>
                <td>{c.label || `#${c.id}`}</td>
                <td>{endpointLabel(far(c))}</td>
                <td>
                  <Link to={traceLink(near(c))}>Trace</Link>
                </td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      )}
    </section>
  );
}
