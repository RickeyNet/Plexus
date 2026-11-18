import { type MouseEvent, useEffect, useRef, useState } from 'react';
import { Link, useLocation, useNavigate, useParams } from 'react-router';

import { type HelpPage, useHelpIndex, useHelpPage, useHelpSearch } from '@/api/help';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { PageHeader } from '@/components/PageHeader';
import { QueryError } from '@/components/QueryError';
import { filterSections, helpLink } from '@/lib/help';
import { useDebouncedValue } from '@/lib/useDebouncedValue';

const HOME = 'Home';

/**
 * Help: the user guides, the same pages as the GitHub wiki. The left column
 * lists every guide by section; the search box filters that list by title
 * and searches the guides' text. Links between guides stay in the app.
 */
export function Help() {
  const { page = HOME } = useParams();
  const [search, setSearch] = useState('');
  const query = useDebouncedValue(search, 250);
  const searching = query.trim().length >= 2;

  return (
    <div>
      <PageHeader title="Help">
        <input
          className="form-input"
          style={{ width: '18rem', maxWidth: '100%' }}
          type="search"
          aria-label="Search the guides"
          placeholder="Search the guides"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </PageHeader>
      <div className="side-nav-layout">
        <HelpNav current={page} filter={search} />
        <div className="card side-nav-main">
          {searching ? (
            <SearchResults query={query} onPick={() => setSearch('')} />
          ) : (
            <Article name={page} />
          )}
        </div>
      </div>
    </div>
  );
}

function HelpNav({ current, filter }: { current: string; filter: string }) {
  const index = useHelpIndex();
  if (index.isError) return <QueryError what="the guide list" query={index} />;
  if (index.isPending) return <LoadingState text="Loading guides…" />;
  const sections = filterSections(index.data.sections, filter);
  return (
    <nav className="side-nav card" aria-label="Guides">
      <Link to="/help" className={`side-nav-link${current === HOME ? ' active' : ''}`} aria-current={current === HOME ? 'page' : undefined}>
        Start here
      </Link>
      {sections.map((section) => (
        <div key={section.title} className="side-nav-section">
          <div className="side-nav-heading">{section.title}</div>
          {section.pages.map((p) => (
            <Link
              key={p.name}
              to={`/help/${p.name}`}
              className={`side-nav-link${current === p.name ? ' active' : ''}`}
              aria-current={current === p.name ? 'page' : undefined}
            >
              {p.title}
            </Link>
          ))}
        </div>
      ))}
      {sections.length === 0 && <div className="text-muted side-nav-empty">No guide titles match.</div>}
    </nav>
  );
}

function SearchResults({ query, onPick }: { query: string; onPick: () => void }) {
  const results = useHelpSearch(query);
  if (results.isError) return <QueryError what="the search" query={results} />;
  if (results.isPending) return <LoadingState text="Searching…" />;
  const rows = results.data.results;
  if (rows.length === 0) return <EmptyState compact message={`No guide mentions “${query.trim()}”.`} />;
  return (
    <div>
      <div className="text-muted help-results-count">
        {rows.length} guide{rows.length === 1 ? '' : 's'} mention “{query.trim()}”
      </div>
      <ul className="help-results">
        {rows.map((r) => (
          <li key={r.name}>
            <Link to={`/help/${r.name}`} onClick={onPick}>
              {r.title}
            </Link>
            {r.section && <span className="text-muted"> · {r.section}</span>}
            {r.snippet && <div className="help-snippet">{r.snippet}</div>}
          </li>
        ))}
      </ul>
    </div>
  );
}

function Article({ name }: { name: string }) {
  const page = useHelpPage(name);
  if (page.isError) return <QueryError what="this guide" query={page} />;
  if (page.isPending) return <LoadingState text="Loading guide…" />;
  return <ArticleBody page={page.data} />;
}

function scrollToHeading(container: HTMLElement | null, anchor: string): boolean {
  if (!container || !anchor) return false;
  const target = container.querySelector(`[id="${CSS.escape(anchor)}"]`);
  if (!target) return false;
  target.scrollIntoView({ block: 'start' });
  return true;
}

function ArticleBody({ page }: { page: HelpPage }) {
  const ref = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();
  const { hash } = useLocation();

  // A new page opens at the heading its link named, else at the top.
  useEffect(() => {
    const anchor = decodeURIComponent(hash.slice(1));
    if (!scrollToHeading(ref.current, anchor)) ref.current?.scrollIntoView({ block: 'start' });
  }, [page.name, hash]);

  // Links between guides and to headings stay in the app; others (GitHub,
  // outside sites) open as the server marked them, in a new tab.
  const onClick = (e: MouseEvent<HTMLElement>) => {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    const anchorEl = (e.target as HTMLElement).closest('a');
    if (!anchorEl) return;
    const link = helpLink(anchorEl.getAttribute('href'));
    if (link.kind === 'other') return;
    e.preventDefault();
    if (link.kind === 'anchor') {
      navigate({ hash: link.anchor }, { replace: true });
      scrollToHeading(ref.current, link.anchor);
      return;
    }
    navigate(`/help/${link.name}${link.anchor ? `#${link.anchor}` : ''}`);
  };

  return (
    <article ref={ref} className="help-article" onClick={onClick}>
      {page.source && page.name !== HOME && (
        <div className="help-meta text-muted">
          {page.section}
          {' · '}
          <a href={page.source_url} target="_blank" rel="noopener noreferrer">
            {page.source}
          </a>
        </div>
      )}
      {page.headings.length > 3 && (
        <details className="help-toc">
          <summary>On this page</summary>
          <ul>
            {page.headings.map((h) => (
              <li key={h.id} className={h.level === 3 ? 'help-toc-sub' : undefined}>
                <a href={`#${h.id}`}>{h.text}</a>
              </li>
            ))}
          </ul>
        </details>
      )}
      {/* The server renders the guide with HTML in the source escaped and
          unsafe link schemes dropped (netcontrol/routes/help_docs.py). */}
      <div className="help-body" dangerouslySetInnerHTML={{ __html: page.html }} />
    </article>
  );
}
