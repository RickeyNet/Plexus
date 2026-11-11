import type { CSSProperties } from 'react';

interface Props {
  /** Rows not rendered yet; the button renders nothing at zero. */
  hiddenCount: number;
  onClick: () => void;
  style?: CSSProperties;
}

/** The "Show more" control for a list capped by `useShowMore`. */
export function ShowMoreButton({ hiddenCount, onClick, style }: Props) {
  if (hiddenCount <= 0) return null;
  return (
    <button type="button" className="btn btn-sm btn-secondary" style={style} onClick={onClick}>
      Show more ({hiddenCount.toLocaleString()} hidden)
    </button>
  );
}
