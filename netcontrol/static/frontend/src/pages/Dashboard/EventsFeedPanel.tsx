import { useMemo, useState } from 'react';

import { useAnnotations, type Annotation } from '@/api/dashboard';

import { timeAgo } from './helpers';

type Category = 'deployment' | 'config' | 'alert';
type Filter = 'all' | Category;

const CATEGORY_COLORS: Record<Category, string> = {
  deployment: '#3b82f6',
  config: '#f59e0b',
  alert: '#ef4444',
};

const CATEGORY_LABELS: Record<Category, string> = {
  deployment: 'Deploy',
  config: 'Config',
  alert: 'Alert',
};

type Range = '24h' | '7d';

const RANGES: { value: Range; label: string }[] = [
  { value: '24h', label: '24h' },
  { value: '7d', label: '7d' },
];

const FILTERS: { value: Filter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'deployment', label: 'Deploy' },
  { value: 'config', label: 'Config' },
  { value: 'alert', label: 'Alert' },
];

export function EventsFeedPanel() {
  const [range, setRange] = useState<Range>('24h');
  const [filter, setFilter] = useState<Filter>('all');
  const { data, isPending, error } = useAnnotations({ range });

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

  return (
    <div className="glass-card card dashboard-overview-card">
      <div className="dashboard-overview-header">
        <h3 className="dashboard-overview-title">Recent Events</h3>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <div className="dashboard-range-tabs" role="tablist" aria-label="Filter">
            {FILTERS.map((f) => (
              <button
                key={f.value}
                role="tab"
                aria-selected={filter === f.value}
                className={`dashboard-range-tab${filter === f.value ? ' active' : ''}`}
                onClick={() => setFilter(f.value)}
              >
                {f.label}
              </button>
            ))}
          </div>
          <div className="dashboard-range-tabs" role="tablist" aria-label="Time range">
            {RANGES.map((r) => (
              <button
                key={r.value}
                role="tab"
                aria-selected={range === r.value}
                className={`dashboard-range-tab${range === r.value ? ' active' : ''}`}
                onClick={() => setRange(r.value)}
              >
                {r.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {isPending ? (
        <div className="skeleton skeleton-card" style={{ height: 220 }} />
      ) : error ? (
        <p style={{ color: 'var(--danger)', margin: 0 }}>
          Failed to load: {(error as Error).message}
        </p>
      ) : filtered.length === 0 ? (
        <div className="dashboard-response-empty">
          <p style={{ margin: 0, color: 'var(--text-muted)' }}>
            No events in this window.
          </p>
        </div>
      ) : (
        <>
          <div className="dashboard-events-feed">
            {filtered.map((e, i) => (
              <EventRow key={`${e.timestamp}-${i}`} event={e} />
            ))}
          </div>
          <div className="dashboard-topology-legend" style={{ marginTop: '0.75rem' }}>
            <LegendDot category="deployment" count={counts.deployment} />
            <LegendDot category="config" count={counts.config} />
            <LegendDot category="alert" count={counts.alert} />
          </div>
        </>
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
      <span className="dashboard-events-time">{timeAgo(event.timestamp)}</span>
    </div>
  );
}

function LegendDot({ category, count }: { category: Category; count: number }) {
  return (
    <span className="dashboard-topology-legend-item">
      <span
        className="dashboard-topology-legend-dot"
        style={{ background: CATEGORY_COLORS[category] }}
      />
      {CATEGORY_LABELS[category]} {count}
    </span>
  );
}
