export interface SummaryStripItem {
  label: string;
  value: string;
}

/** Compact label/value counters shown above a list (Compliance, Configuration, Change Management). */
export function SummaryStrip({ items }: { items: SummaryStripItem[] }) {
  return (
    <div className="card card-sm">
      <div
        className="card-body"
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
          gap: 'var(--space-2)',
        }}
      >
        {items.map((it) => (
          <div key={it.label} style={{ display: 'flex', flexDirection: 'column' }}>
            <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)' }}>{it.label}</span>
            <span style={{ fontWeight: 600 }}>{it.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
