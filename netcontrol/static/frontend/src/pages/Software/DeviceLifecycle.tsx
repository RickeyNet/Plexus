import { Link } from 'react-router';

import { useAuthStatus } from '@/api/auth';
import { useHostLifecycle } from '@/api/lifecycle';
import { DataTable } from '@/components/DataTable';
import { QueryError } from '@/components/QueryError';
import { formatDateWithDays, noticeTarget, viaLabel } from '@/lib/lifecycle';
import { canUseFeature } from '@/lib/tabGating';

import { ContractStateBadge, CoverageBadge, StageBadge } from './LifecycleParts';

/**
 * The device page's hardware lifecycle section (anchored `#lifecycle`): the
 * device's stage, end of sale and support, the notices that apply and its
 * support contracts. Renders nothing for users without the lifecycle feature,
 * or when no notice applies and no contract covers the device.
 */
export function DeviceLifecycle({ hostId }: { hostId: number }) {
  const auth = useAuthStatus().data;
  const allowed = canUseFeature('lifecycle', auth);
  const q = useHostLifecycle(hostId, allowed);
  if (!allowed) return null;
  if (q.isError && !q.data) return <QueryError what="hardware lifecycle" query={q} />;
  if (!q.data) return null;
  const { status, notices, contracts } = q.data;
  if (notices.length === 0 && contracts.length === 0) return null;
  return (
    <section id="lifecycle" aria-label="Hardware lifecycle">
      <div className="card-title" style={{ marginBottom: '0.5rem' }}>
        Hardware lifecycle
      </div>
      <p style={{ margin: '0 0 0.5rem', display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap', alignItems: 'center' }}>
        <StageBadge stage={status.stage} />
        <CoverageBadge coverage={status.coverage} />
        <span>
          End of sale {formatDateWithDays(status.end_of_sale, status.days_to_end_of_sale)} · last date of support{' '}
          {formatDateWithDays(status.end_of_support, status.days_to_end_of_support)}
          {status.coverage_end ? ` · covered until ${formatDateWithDays(status.coverage_end, status.coverage_days)}` : ''}
        </span>
        <Link to="/software/lifecycle">Lifecycle</Link>
      </p>
      {notices.length > 0 && (
        <DataTable compact aria-label="End-of-life notices for this device">
          <thead>
            <tr>
              <th>Notice</th>
              <th>Applies by</th>
              <th>Stage</th>
              <th>End of sale</th>
              <th>Last date of support</th>
            </tr>
          </thead>
          <tbody>
            {notices.map((n) => (
              <tr key={n.id}>
                <td>
                  {n.documentation_url ? (
                    <a href={n.documentation_url} target="_blank" rel="noopener noreferrer">
                      {noticeTarget(n)}
                    </a>
                  ) : (
                    noticeTarget(n)
                  )}
                </td>
                <td>{viaLabel(n.via)}</td>
                <td>
                  <StageBadge stage={n.stage} />
                </td>
                <td>{n.end_of_sale || '-'}</td>
                <td>{n.end_of_support || '-'}</td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      )}
      {contracts.length > 0 && (
        <DataTable compact aria-label="Support contracts for this device">
          <thead>
            <tr>
              <th>Contract</th>
              <th>State</th>
              <th>Support level</th>
              <th>End</th>
            </tr>
          </thead>
          <tbody>
            {contracts.map((c) => (
              <tr key={c.id}>
                <td>
                  {c.provider} {c.contract_id}
                </td>
                <td>
                  <ContractStateBadge state={c.state} />
                </td>
                <td>{c.support_level || '-'}</td>
                <td>{c.end_date || 'Open'}</td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      )}
    </section>
  );
}
