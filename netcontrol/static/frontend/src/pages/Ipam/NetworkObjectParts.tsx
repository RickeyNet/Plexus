import { type MouseEvent, type ReactNode, useRef } from 'react';

import { Badge } from '@/components/Badge';
import { EmptyState } from '@/components/EmptyState';
import { WidenToggle } from '@/components/WidenToggle';
import { bringIntoView, splitGridStyle, useWideDetail } from '@/lib/wideDetail';

/** Pieces the VRFs and VLANs tabs share. */

/**
 * The record list on the left, the selected record's detail on the right
 * (like the subnet drilldown). The detail's corner button widens it to the
 * full width above the list, so its tables need no sideways scrolling;
 * picking another row then brings the detail back into view.
 */
export function SplitLayout({ list, detail }: { list: ReactNode; detail: ReactNode }) {
  const [wide, toggleWide] = useWideDetail();
  const detailRef = useRef<HTMLDivElement>(null);

  // A row click (not one of its buttons or links) opens a record.
  const onListClick = (e: MouseEvent) => {
    if (!wide || !(e.target instanceof Element)) return;
    if (!e.target.closest('tr') || e.target.closest('button, a, input, select, textarea, label')) return;
    requestAnimationFrame(() => bringIntoView(detailRef.current));
  };

  return (
    <div style={splitGridStyle(wide)}>
      <div className="card" style={{ minWidth: 0, order: wide ? 1 : 0 }} onClickCapture={onListClick}>
        {list}
      </div>
      <div
        className="card"
        ref={detailRef}
        style={{ minWidth: 0, position: 'relative', paddingRight: '2.75rem', scrollMarginTop: 'var(--space-4)' }}
      >
        <WidenToggle wide={wide} onToggle={toggleWide} style={{ position: 'absolute', top: 'var(--space-3)', right: 'var(--space-3)' }} />
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
