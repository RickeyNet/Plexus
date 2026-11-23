/**
 * Page controls for a server-paged list: "1-20 of 340" with a back and a
 * forward button that move `offset` by `pageSize`. Renders nothing when
 * everything fits on one page.
 */
export function Pager({
  offset,
  pageSize,
  total,
  onChange,
  previousLabel = 'Newer',
  nextLabel = 'Older',
}: {
  offset: number;
  pageSize: number;
  total: number;
  onChange: (offset: number) => void;
  /** Label of the button back toward offset 0 ("Newer" for a newest-first feed). */
  previousLabel?: string;
  nextLabel?: string;
}) {
  if (total <= pageSize && offset === 0) return null;
  const last = Math.min(total, offset + pageSize);
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '0.5rem',
        justifyContent: 'flex-end',
        flexWrap: 'wrap',
        marginTop: '0.5rem',
      }}
    >
      <span className="text-muted" style={{ fontSize: '0.85em' }}>
        {Math.min(offset + 1, total)}-{last} of {total.toLocaleString()}
      </span>
      <button
        type="button"
        className="btn btn-sm btn-secondary"
        disabled={offset === 0}
        onClick={() => onChange(Math.max(0, offset - pageSize))}
      >
        {previousLabel}
      </button>
      <button
        type="button"
        className="btn btn-sm btn-secondary"
        disabled={last >= total}
        onClick={() => onChange(offset + pageSize)}
      >
        {nextLabel}
      </button>
    </div>
  );
}
