import { useState } from 'react';

import { type DetailSection, useMerakiNodeDetails } from '@/api/meraki';
import type { TopologyMerakiRef } from '@/api/topology';
import { Modal } from '@/components/Modal';

import { DETAIL_CELL_STYLE, providerSourceName } from './helpers';
import { formatWhen, type MerakiView, merakiViewSections, rowMatches, searchTerms } from './merakiHelpers';

interface Props {
  meraki: TopologyMerakiRef;
  /** Terms from the active map search; matching rows are highlighted. */
  highlight?: string;
  /** The tab being shown: only its sections are rendered. */
  view: MerakiView;
  /** Tab label, for the expanded view's title. */
  title: string;
}

export function MerakiDetails({ meraki, highlight = '', view, title }: Props) {
  const details = useMerakiNodeDetails(meraki.org_ref, meraki.node_id);
  const [filter, setFilter] = useState('');
  const [expanded, setExpanded] = useState(false);

  if (details.isPending) return <p className="text-muted" style={{ fontSize: '0.78rem' }}>Loading…</p>;
  if (details.error) {
    return <p style={{ color: 'var(--danger)', fontSize: '0.78rem' }}>{details.error.message}</p>;
  }
  const data = details.data;
  const filterTerms = searchTerms(filter);
  const highlightTerms = searchTerms(highlight);
  const { sections, siteSections } = merakiViewSections(data, view);

  if (!sections.length && !siteSections.length) {
    return <p className="text-muted" style={{ fontSize: '0.78rem' }}>Nothing was collected for this device here.</p>;
  }

  const body = (
    <>
      <SectionList sections={sections} filterTerms={filterTerms} highlightTerms={highlightTerms} />
      {siteSections.length > 0 && (
        <>
          <h6
            style={{
              margin: '0.8rem 0 0.2rem',
              fontSize: '0.72rem',
              textTransform: 'uppercase',
              letterSpacing: '0.05em',
              color: 'var(--text-muted)',
            }}
          >
            Site: {data.site_name}
          </h6>
          <SectionList sections={siteSections} filterTerms={filterTerms} highlightTerms={highlightTerms} />
        </>
      )}
    </>
  );

  const controls = (
    <div style={{ display: 'flex', gap: '0.4rem', marginBottom: '0.5rem' }}>
      <input
        className="form-input"
        style={{ flex: 1, fontSize: '0.8rem', padding: '0.25rem 0.5rem' }}
        placeholder="Filter…"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
      />
      {!expanded && (
        <button type="button" className="btn btn-secondary btn-sm" onClick={() => setExpanded(true)}>
          Expand
        </button>
      )}
    </div>
  );

  return (
    <>
      <div className="text-muted" style={{ fontSize: '0.72rem', marginBottom: '0.4rem' }}>
        {providerSourceName(data.provider)} data · collected {formatWhen(data.generated_at)}
      </div>
      {controls}
      {!expanded && body}
      <Modal isOpen={expanded} onClose={() => setExpanded(false)} title={`${data.label} — ${title}`} size="large">
        {controls}
        {body}
      </Modal>
    </>
  );
}

interface SectionListProps {
  sections: DetailSection[];
  filterTerms: string[];
  highlightTerms: string[];
}

function SectionList({ sections, filterTerms, highlightTerms }: SectionListProps) {
  return (
    <>
      {sections.map((section, index) => (
        <Section
          key={`${section.title}-${index}`}
          section={section}
          filterTerms={filterTerms}
          highlightTerms={highlightTerms}
        />
      ))}
    </>
  );
}

interface SectionProps {
  section: DetailSection;
  filterTerms: string[];
  highlightTerms: string[];
}

// A tab holds only a few sections, so they all start open.
function Section({ section, filterTerms, highlightTerms }: SectionProps) {
  const filtering = filterTerms.length > 0;

  if (section.kind === 'text') {
    const text = section.text ?? '';
    if (filtering && !rowMatches([text], filterTerms)) return null;
    return (
      <details open style={{ borderBottom: '1px solid var(--border)' }}>
        <summary style={{ cursor: 'pointer', padding: '0.4rem 0', fontSize: '0.8rem', fontWeight: 600 }}>{section.title}</summary>
        <pre
          style={{
            background: 'var(--bg, #0d1117)',
            border: '1px solid var(--border)',
            borderRadius: '0.35rem',
            padding: '0.5rem',
            fontSize: '0.72rem',
            maxHeight: 320,
            overflow: 'auto',
            margin: '0 0 0.5rem',
          }}
        >
          {text}
        </pre>
      </details>
    );
  }

  const rows = section.rows ?? [];
  const visible = filtering ? rows.filter((r) => rowMatches(r, filterTerms)) : rows;
  if (filtering && visible.length === 0) return null;
  const isKv = section.kind === 'kv';

  return (
    <details open style={{ borderBottom: '1px solid var(--border)' }}>
      <summary style={{ cursor: 'pointer', padding: '0.4rem 0', fontSize: '0.8rem', fontWeight: 600 }}>
        {section.title}
        {!isKv && (
          <span className="text-muted" style={{ fontWeight: 400, marginLeft: '0.4rem' }}>
            {filtering ? `${visible.length} of ${rows.length}` : rows.length}
          </span>
        )}
      </summary>
      <div style={{ overflowX: 'auto', marginBottom: '0.5rem' }}>
        <table className="data-table" style={{ fontSize: '0.74rem', width: '100%' }}>
          {!isKv && (
            <thead>
              <tr>
                {(section.columns ?? []).map((c) => (
                  <th key={c} style={{ ...DETAIL_CELL_STYLE, textAlign: 'left', whiteSpace: 'nowrap' }}>{c}</th>
                ))}
              </tr>
            </thead>
          )}
          <tbody>
            {visible.map((row, i) => (
              <tr
                key={i}
                style={rowMatches(row, highlightTerms) ? { background: 'rgba(255, 196, 0, 0.18)' } : undefined}
              >
                {row.map((cell, j) => (
                  <td
                    key={j}
                    className={isKv && j === 0 ? 'text-muted' : undefined}
                    style={isKv && j === 0 ? { ...DETAIL_CELL_STYLE, whiteSpace: 'nowrap' } : DETAIL_CELL_STYLE}
                  >
                    {cell}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}
