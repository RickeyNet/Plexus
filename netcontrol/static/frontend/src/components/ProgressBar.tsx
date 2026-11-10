import type { CSSProperties } from 'react';

import type { Tone } from '@/lib/severity';

export interface ProgressBarProps {
  /** Fill, 0 to 100 (clamped). `null` when the total is unknown: a full, dimmed bar. */
  value: number | null;
  /** Fill colour; `primary` by default. */
  tone?: Exclude<Tone, 'neutral'>;
  /** `sm` (6px) inside list rows and compact forms; `md` (8px, default) elsewhere. */
  size?: 'sm' | 'md';
  /** Accessible name. Omit for a bar that only repeats a number shown next to it: it is then hidden from assistive tech. */
  label?: string;
  className?: string;
  style?: CSSProperties;
}

/** The one horizontal bar for progress and share-of-total meters. Renders `.progress-bar`. */
export function ProgressBar({ value, tone = 'primary', size = 'md', label, className, style }: ProgressBarProps) {
  // Clamped to 0..100; anything that is not a finite number draws an empty bar.
  const pct = value === null ? null : Number.isFinite(value) ? Math.max(0, Math.min(100, value)) : 0;
  const cls = ['progress-bar', `progress-bar-${tone}`];
  if (size === 'sm') cls.push('progress-bar-sm');
  if (pct === null) cls.push('progress-bar-indeterminate');
  if (className) cls.push(className);
  const a11y = label
    ? {
        role: 'progressbar',
        'aria-label': label,
        'aria-valuemin': 0,
        'aria-valuemax': 100,
        'aria-valuenow': pct === null ? undefined : Math.round(pct),
      }
    : { 'aria-hidden': true };
  return (
    <div className={cls.join(' ')} style={style} {...a11y}>
      <div className="progress-bar-fill" style={{ width: `${pct ?? 100}%` }} />
    </div>
  );
}
