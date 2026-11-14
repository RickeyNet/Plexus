import type { ReactNode } from 'react';

import { Badge } from '@/components/Badge';
import { EmptyState } from '@/components/EmptyState';

/** Pieces the VRFs and VLANs tabs share. */

/** The record list on the left, the selected record's detail on the right (like the subnet drilldown). */
export function SplitLayout({ list, detail }: { list: ReactNode; detail: ReactNode }) {
  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'minmax(0, 2.1fr) minmax(320px, 1fr)',
        gap: '1rem',
        alignItems: 'start',
      }}
    >
      <div className="card" style={{ minWidth: 0 }}>
        {list}
      </div>
      <div className="card" style={{ minWidth: 0 }}>
        {detail}
      </div>
    </div>
  );
}

/** A titled list of the detail panel; an empty one shows `empty` instead. */
export function DetailSection({
  title,
  count,
  empty,
  note,
  children,
}: {
  title: string;
  count: number;
  empty: string;
  /** A line under the list, e.g. that it was cut short. */
  note?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section aria-label={title}>
      <div style={{ fontWeight: 600, marginBottom: '0.45rem' }}>
        {title} ({count.toLocaleString()})
      </div>
      {count === 0 ? <EmptyState compact message={empty} /> : children}
      {note && (
        <div className="text-muted" style={{ fontSize: '0.85em', marginTop: '0.3rem' }}>
          {note}
        </div>
      )}
    </section>
  );
}

export function OriginBadge({ origin }: { origin: string }) {
  return (
    <Badge size="sm" tone={origin === 'manual' ? 'primary' : 'neutral'} title={origin === 'manual' ? 'Created by an admin' : 'Created from collected data'}>
      {origin === 'manual' ? 'Manual' : 'Discovered'}
    </Badge>
  );
}
