import { useEffect, useRef, useState } from 'react';

interface Props {
  onPNG: () => void;
  onSVG: () => void;
  onJSON: () => void;
  /** Interactive HTML map, sent as a file download. */
  htmlDownloadUrl: string;
  /** The same map rendered inline, for a new browser tab. */
  htmlOpenUrl: string;
}

type ExportItem =
  | { label: string; description: string; onSelect: () => void }
  | { label: string; description: string; href: string; download: boolean };

/** One toolbar button that opens every topology export, each with a short description. */
export function ExportMenu({ onPNG, onSVG, onJSON, htmlDownloadUrl, htmlOpenUrl }: Props) {
  const [open, setOpen] = useState(false);
  const [hovered, setHovered] = useState<number | null>(null);
  const rootRef = useRef<HTMLDivElement>(null);

  // Close on a click anywhere outside the menu, or on Escape.
  useEffect(() => {
    if (!open) return;
    function onMouseDown(e: MouseEvent) {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false);
    }
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') setOpen(false);
    }
    document.addEventListener('mousedown', onMouseDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('mousedown', onMouseDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [open]);

  const items: ExportItem[] = [
    {
      label: 'PNG image',
      description: 'High-resolution snapshot of the whole map with a title header. Good for slides and tickets.',
      onSelect: onPNG,
    },
    {
      label: 'SVG drawing',
      description: 'Devices, links and port labels as a vector drawing that stays sharp at any size and can be edited.',
      onSelect: onSVG,
    },
    {
      label: 'JSON data',
      description: 'The raw nodes and links behind the map, for scripts or loading into other tools.',
      onSelect: onJSON,
    },
    {
      label: 'HTML map (download)',
      description: "One self-contained, interactive file with every device's details. Opens in any browser, no Plexus login needed.",
      href: htmlDownloadUrl,
      download: true,
    },
    {
      label: 'Open HTML map',
      description: 'The same interactive map in a new browser tab, without saving a file.',
      href: htmlOpenUrl,
      download: false,
    },
  ];

  const itemStyle = (i: number): React.CSSProperties => ({
    display: 'block',
    width: '100%',
    padding: '0.5rem 0.75rem',
    textAlign: 'left',
    border: 'none',
    borderTop: i === 0 ? 'none' : '1px solid var(--border)',
    background: hovered === i ? 'var(--bg-secondary)' : 'transparent',
    color: 'inherit',
    textDecoration: 'none',
    cursor: 'pointer',
    font: 'inherit',
  });

  const itemBody = (item: ExportItem) => (
    <>
      <div style={{ fontSize: '0.85rem', fontWeight: 500 }}>{item.label}</div>
      <div className="text-muted" style={{ fontSize: '0.75rem', marginTop: '0.15rem', lineHeight: 1.35 }}>
        {item.description}
      </div>
    </>
  );

  return (
    <div ref={rootRef} style={{ position: 'relative' }}>
      <button
        type="button"
        className={`btn btn-sm ${open ? 'btn-primary' : 'btn-secondary'}`}
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="menu"
        aria-expanded={open}
      >
        Export ▾
      </button>
      {open && (
        <div
          role="menu"
          style={{
            position: 'absolute',
            top: '100%',
            right: 0,
            marginTop: '0.25rem',
            width: 320,
            zIndex: 20,
            background: 'var(--card-bg)',
            border: '1px solid var(--border)',
            borderRadius: '0.4rem',
            boxShadow: '0 4px 16px rgba(0,0,0,0.25)',
            overflow: 'hidden',
          }}
        >
          {items.map((item, i) =>
            'onSelect' in item ? (
              <button
                key={item.label}
                type="button"
                role="menuitem"
                style={itemStyle(i)}
                onMouseEnter={() => setHovered(i)}
                onMouseLeave={() => setHovered(null)}
                onClick={() => {
                  setOpen(false);
                  item.onSelect();
                }}
              >
                {itemBody(item)}
              </button>
            ) : (
              <a
                key={item.label}
                role="menuitem"
                style={itemStyle(i)}
                href={item.href}
                {...(item.download ? { download: true } : { target: '_blank', rel: 'noopener noreferrer' })}
                onMouseEnter={() => setHovered(i)}
                onMouseLeave={() => setHovered(null)}
                onClick={() => setOpen(false)}
              >
                {itemBody(item)}
              </a>
            ),
          )}
        </div>
      )}
    </div>
  );
}
