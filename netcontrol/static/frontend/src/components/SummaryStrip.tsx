import type { ReactNode } from 'react';

import type { Tone } from '@/lib/severity';

import { StatGrid, StatTile } from './StatTile';

export interface SummaryStripItem {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  tone?: Tone;
}

/**
 * Compact label/value counters shown above a list (Compliance, Configuration,
 * Change Management): the compact variant of StatGrid/StatTile.
 */
export function SummaryStrip({ items }: { items: SummaryStripItem[] }) {
  return (
    <StatGrid compact>
      {items.map((it) => (
        <StatTile key={it.label} label={it.label} value={it.value} hint={it.hint} tone={it.tone} />
      ))}
    </StatGrid>
  );
}
