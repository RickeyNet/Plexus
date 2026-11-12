import { useMemo, useState } from 'react';

import { useAnnotations, type Annotation } from '@/api/dashboard';
import { SegmentedControl } from '@/components/SegmentedControl';
import { EVENT_CATEGORY_COLORS } from '@/lib/themeColors';
import { useTimeRange } from '@/lib/timeRange-context';
import { formatRelativeTime } from '@/lib/datetime';

import { PANEL_BODY_STYLE } from './helpers';
import { PanelEmpty, PanelError, PanelRangeEmpty } from './PanelStates';

type Category = 'deployment' | 'config' | 'alert';
type Filter = 'all' | Category;

const CATEGORY_COLORS: Record<Category, string> = EVENT_CATEGORY_COLORS;

const CATEGORY_LABELS: Record<Category, string> = {
  deployment: 'Deploy',
  config: 'Config',
  alert: 'Alert',
};

export function EventsFeedPanel() {
  const { range } = useTimeRange();
  const [filter, setFilter] = useState<Filter>('all');
  const query = useAnnotations({ range });
  const { data, isPending, error } = query;

  const filtered = useMemo(() => {
    const events = data ?? [];
    if (filter === 'all') return events.slice(0, 50);
    return events.filter((e) => e.category === filter).slice(0, 50);
  }, [data, filter]);

  const counts = useMemo(() => {
    const c: Record<Category, number> = { deployment: 0, config: 0, alert: 0 };
    for (const e of data ?? []) {
      if (e.category === 'deployment' || e.category === 'config' || e.category === 'alert') {
        c[e.category]++;
      }
    }
    return c;
  }, [data]);

  // Each chip carries its count, so the feed needs no separate legend.
  const filters: { key: Filter; label: string }[] = [
    { key: 'all', label: 'All' },
    ...(Object.keys(CATEGORY_LABELS) as Category[]).map((c) => ({
      key: c,
      label: data ? `${CATEGORY_LABELS[c]} ${counts[c]}` : CATEGORY_LABELS[c],
    })),
  ];

  return (
    <div className="glass-card card dashboard-overview-card">
      <div className="dashboard-overview-header">
        <h3 className="dashboard-overview-title">Recent Events</h3>
        <SegmentedControl options={filters} value={filter} onChange={setFilter} size="xs" aria-label="Filter" />
      </div>

      {isPending ? (
        <div className="skeleton skeleton-card" style={PANEL_BODY_STYLE} />
      ) : error ? (
        <PanelError what="recent events" query={query} />
      ) : filtered.length === 0 && filter !== 'all' && (data ?? []).length > 0 ? (
        // The range has events, just none of the chosen kind.
        <PanelEmpty
          message={`No ${CATEGORY_LABELS[filter].toLowerCase()} events in this time range`}
          action={
            <button type="button" className="btn btn-sm btn-secondary" onClick={() => setFilter('all')}>
              Show all events
            </button>
          }
        />
      ) : filtered.length === 0 ? (
        <PanelRangeEmpty
          what="events"
          hint="Deployments, configuration changes and alerts are listed here as they happen."
        />
      ) : (
        <div className="dashboard-events-feed" style={PANEL_BODY_STYLE}>
          {filtered.map((e, i) => (
            <EventRow key={`${e.timestamp}-${i}`} event={e} />
          ))}
        </div>
      )}
    </div>
  );
}

function EventRow({ event }: { event: Annotation }) {
  const cat = (event.category ?? 'config') as Category;
  const color = CATEGORY_COLORS[cat] ?? CATEGORY_COLORS.config;
  const label = CATEGORY_LABELS[cat] ?? cat;

  return (
    <div className="dashboard-events-item">
      <span
        className="dashboard-events-badge"
        style={{ background: color }}
        title={label}
      >
        {label}
      </span>
      <span className="dashboard-events-title">{event.title || '(untitled)'}</span>
      {event.description ? (
        <span className="dashboard-events-desc">{event.description}</span>
      ) : null}
      <span className="dashboard-events-time">{formatRelativeTime(event.timestamp)}</span>
    </div>
  );
}
