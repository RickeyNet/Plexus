import { Link } from 'react-router';

import { useAuthStatus } from '@/api/auth';
import { useHostCircuits } from '@/api/circuits';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { formatBps, formatKbps } from '@/lib/circuits';
import { canUseFeature } from '@/lib/tabGating';

import { CircuitStatusBadge } from './parts';

/**
 * The device page's Circuits section: the circuits with a termination on
 * the device, the port each lands on and its latest rate against the commit.
 * Renders nothing for users without the circuits feature.
 */
export function DeviceCircuits({ hostId }: { hostId: number }) {
  const auth = useAuthStatus().data;
  const allowed = canUseFeature('circuits', auth);
  const q = useHostCircuits(hostId, allowed);
  if (!allowed) return null;
  let body;
  if (q.isError && !q.data) body = <QueryError what="circuits" query={q} />;
  else if (q.isPending) body = <LoadingState text="Loading circuits…" />;
  else if (q.data.length === 0) body = <EmptyState compact message="No circuit terminates on this device." />;
  else
    body = (
      <DataTable compact aria-label="Circuits on this device">
        <thead>
          <tr>
            <th>Circuit ID</th>
            <th>Provider</th>
            <th>Status</th>
            <th>Side</th>
            <th>Interface</th>
            <th style={{ textAlign: 'right' }}>Commit</th>
            <th style={{ textAlign: 'right' }}>In / out</th>
          </tr>
        </thead>
        <tbody>
          {q.data.flatMap((c) =>
            c.terminations
              .filter((t) => t.host_id === hostId)
              .map((t) => {
                const u = c.utilisation?.find((x) => x.term_side === t.term_side);
                return (
                  <tr key={`${c.id}-${t.term_side}`}>
                    <td>
                      <Link to="/circuits">{c.cid}</Link>
                    </td>
                    <td>{c.provider_name}</td>
                    <td>
                      <CircuitStatusBadge status={c.status} />
                    </td>
                    <td>{t.term_side}</td>
                    <td>{t.interface_name || '-'}</td>
                    <td style={{ textAlign: 'right' }}>{formatKbps(c.commit_rate_kbps)}</td>
                    <td style={{ textAlign: 'right' }}>
                      {u ? `${formatBps(u.in_bps)} / ${formatBps(u.out_bps)} (${Math.max(u.in_pct_of_commit, u.out_pct_of_commit)}%)` : '-'}
                    </td>
                  </tr>
                );
              }),
          )}
        </tbody>
      </DataTable>
    );
  return (
    <section aria-label="Circuits">
      <div className="card-title" style={{ marginBottom: '0.5rem' }}>
        Circuits
      </div>
      {body}
    </section>
  );
}
