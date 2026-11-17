import type { CSSProperties } from 'react';

const ICON_PROPS = {
  width: 14,
  height: 14,
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 2,
  strokeLinecap: 'round',
  strokeLinejoin: 'round',
  'aria-hidden': true,
} as const;

/**
 * The square button that widens a side panel to the page's full width, or
 * puts it back beside the list (see `useWideDetail`).
 */
export function WidenToggle({ wide, onToggle, style }: { wide: boolean; onToggle: () => void; style?: CSSProperties }) {
  const label = wide ? 'Put the panel back beside the list' : 'Expand the panel to full width';
  return (
    <button
      type="button"
      className="btn btn-sm btn-secondary"
      aria-label={label}
      aria-pressed={wide}
      title={label}
      onClick={onToggle}
      style={{ padding: 0, width: 'var(--control-h-sm)', height: 'var(--control-h-sm)', justifyContent: 'center', ...style }}
    >
      {wide ? (
        <svg {...ICON_PROPS}>
          <polyline points="4 14 10 14 10 20" />
          <polyline points="20 10 14 10 14 4" />
          <line x1="14" y1="10" x2="21" y2="3" />
          <line x1="3" y1="21" x2="10" y2="14" />
        </svg>
      ) : (
        <svg {...ICON_PROPS}>
          <polyline points="15 3 21 3 21 9" />
          <polyline points="9 21 3 21 3 15" />
          <line x1="21" y1="3" x2="14" y2="10" />
          <line x1="3" y1="21" x2="10" y2="14" />
        </svg>
      )}
    </button>
  );
}
