import type { CSSProperties, ReactNode } from 'react';

import type { Tone } from '@/lib/severity';

export interface StatTileProps {
  label: ReactNode;
  value: ReactNode;
  /** Small muted line under the label ("of 120", "last 24h"). */
  hint?: ReactNode;
  /** Colours the value; omit for the theme's default stat colour. */
  tone?: Tone;
  /** Small glyph (usually an inline SVG) shown above the value, tinted with the tone. */
  icon?: ReactNode;
  /** Dense tile for summary strips and modals. A StatGrid with `compact` makes every tile compact. */
  compact?: boolean;
  /** Centre the content (icon tiles, modal summaries). */
  center?: boolean;
  /** Makes the tile a button (e.g. a count that filters the list below). */
  onClick?: () => void;
  title?: string;
  className?: string;
}

/**
 * One stat: value over label, on the `.stat-card` surface. Use inside a
 * StatGrid. Renders `.stat-card` + `.stat-value` / `.stat-label` /
 * `.stat-hint`, with `.stat-tone-<tone>`, `.stat-card-compact`,
 * `.stat-card-center` and `.card-clickable` as modifiers.
 */
export function StatTile({ label, value, hint, tone, icon, compact, center, onClick, title, className }: StatTileProps) {
  const cls = ['stat-card'];
  if (tone) cls.push(`stat-tone-${tone}`);
  if (compact) cls.push('stat-card-compact');
  if (center) cls.push('stat-card-center');
  if (onClick) cls.push('card-clickable');
  if (className) cls.push(className);

  const body = (
    <>
      {icon && (
        <span className="stat-icon" aria-hidden="true">
          {icon}
        </span>
      )}
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
      {hint != null && hint !== '' && <div className="stat-hint">{hint}</div>}
    </>
  );

  if (onClick) {
    return (
      <button type="button" className={cls.join(' ')} onClick={onClick} title={title}>
        {body}
      </button>
    );
  }
  return (
    <div className={cls.join(' ')} title={title}>
      {body}
    </div>
  );
}

export interface StatGridProps {
  children: ReactNode;
  /** Dense grid of compact tiles (the summary-strip look). */
  compact?: boolean;
  /** Narrowest a tile may get before wrapping, in px. Defaults: 200 (regular), 140 (compact). */
  minTileWidth?: number;
  className?: string;
}

/** Responsive auto-fit grid of StatTiles. Renders `.stats-grid` (+ `.stats-grid-compact`). */
export function StatGrid({ children, compact, minTileWidth, className }: StatGridProps) {
  const cls = ['stats-grid'];
  if (compact) cls.push('stats-grid-compact');
  if (className) cls.push(className);
  const style: CSSProperties | undefined = minTileWidth
    ? { gridTemplateColumns: `repeat(auto-fit, minmax(${minTileWidth}px, 1fr))` }
    : undefined;
  return (
    <div className={cls.join(' ')} style={style}>
      {children}
    </div>
  );
}
