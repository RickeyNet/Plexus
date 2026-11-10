import type { ReactNode } from 'react';

/** Titled group inside the Settings card; an inset panel, not a nested card. */
export function SectionCard({ title, children }: { title: ReactNode; children: ReactNode }) {
  return (
    <div className="card-inset">
      <h3 style={{ margin: '0 0 var(--space-3) 0' }}>{title}</h3>
      {children}
    </div>
  );
}
