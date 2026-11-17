import { Link } from 'react-router';

import { useAuthStatus } from '@/api/auth';
import { useHostClusters } from '@/api/virtualization';
import { canUseFeature } from '@/lib/tabGating';

/** "Hypervisor of cluster ..." for a host that is a member of clusters; nothing otherwise or without the feature. */
export function HostClusters({ hostId }: { hostId: number }) {
  const allowed = canUseFeature('virtualization', useAuthStatus().data);
  const q = useHostClusters(hostId, allowed);
  const clusters = q.data ?? [];
  if (!allowed || clusters.length === 0) return null;
  return (
    <div className="text-muted" style={{ fontSize: '0.9em' }}>
      Hypervisor of {clusters.length === 1 ? 'cluster' : 'clusters'}{' '}
      {clusters.map((c, i) => (
        <span key={c.id}>
          {i > 0 && ', '}
          <Link to={`/virtualization/clusters?cluster=${c.id}`}>{c.name}</Link>
        </span>
      ))}
    </div>
  );
}
