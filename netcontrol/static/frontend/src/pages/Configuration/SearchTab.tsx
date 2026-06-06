import { useState } from 'react';

import {
  type ConfigBackupSearchResult,
  useSearchConfigBackups,
} from '@/api/configuration';
import { useDialogs } from '@/components/DialogProvider-context';

import { BackupDetailModal } from './BackupDetailModal';
import { BackupDiffModal } from './BackupDiffModal';
import { formatStamp } from './helpers';

type Mode = 'fulltext' | 'substring' | 'regex';

const MODE_HINTS: Record<Mode, { placeholder: string; example: string }> = {
  fulltext: {
    placeholder: 'e.g. snmp-server community public',
    example: 'Example: keyword search like "snmp server public"',
  },
  substring: {
    placeholder: 'e.g. ip access-list standard',
    example: 'Example: exact text substring like "ip access-list standard"',
  },
  regex: {
    placeholder: 'e.g. ^snmp-server community\\s+\\w+\\s+RO$',
    example: 'Example regex: ^snmp-server community\\s+\\w+\\s+RO$',
  },
};

export function SearchTab() {
  const { alert } = useDialogs();
  const [query, setQuery] = useState('');
  const [mode, setMode] = useState<Mode>('fulltext');
  const [limit, setLimit] = useState(50);
  const search = useSearchConfigBackups();
  const [detailId, setDetailId] = useState<number | null>(null);
  const [diffId, setDiffId] = useState<number | null>(null);

  const hint = MODE_HINTS[mode];

  const handleSearch = () => {
    const q = query.trim();
    if (!q) {
      void alert('Enter text to search in configuration backups.');
      return;
    }
    const safeLimit = Math.max(1, Math.min(200, limit));
    setLimit(safeLimit);
    search.mutate({ query: q, mode, limit: safeLimit, contextLines: 1 });
  };

  return (
    <>
      <div
        style={{
          display: 'flex',
          gap: '0.5rem',
          alignItems: 'flex-end',
          flexWrap: 'wrap',
          marginBottom: '0.75rem',
        }}
      >
        <div style={{ flex: '1 1 280px', minWidth: 240 }}>
          <label className="form-label">Search</label>
          <input
            className="form-input"
            value={query}
            placeholder={hint.placeholder}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault();
                handleSearch();
              }
            }}
          />
        </div>
        <div>
          <label className="form-label">Mode</label>
          <select
            className="form-select"
            value={mode}
            onChange={(e) => setMode(e.target.value as Mode)}
          >
            <option value="fulltext">Full-text</option>
            <option value="substring">Substring</option>
            <option value="regex">Regex</option>
          </select>
        </div>
        <div>
          <label className="form-label">Limit</label>
          <input
            className="form-input"
            type="number"
            min={1}
            max={200}
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value || '50'))}
            style={{ maxWidth: 100 }}
          />
        </div>
        <button
          type="button"
          className="btn btn-primary"
          disabled={search.isPending}
          onClick={handleSearch}
        >
          {search.isPending ? 'Searching…' : 'Search'}
        </button>
      </div>
      <div
        style={{
          fontSize: '0.85em',
          color: 'var(--text-muted)',
          marginBottom: '0.75rem',
        }}
      >
        {hint.example}
      </div>

      {search.isPending && <p className="text-muted">Searching…</p>}
      {search.error && (
        <p style={{ color: 'var(--danger)' }}>
          Search failed: {(search.error as Error).message}
        </p>
      )}
      {search.data && <Results data={search.data} onView={setDetailId} onDiff={setDiffId} />}
      {!search.data && !search.isPending && !search.error && (
        <div
          className="card"
          style={{
            textAlign: 'center',
            color: 'var(--text-muted)',
            padding: '1.5rem',
          }}
        >
          Run a search to scan backed-up configurations.
        </div>
      )}

      <BackupDetailModal
        backupId={detailId}
        onClose={() => setDetailId(null)}
      />
      <BackupDiffModal backupId={diffId} onClose={() => setDiffId(null)} />
    </>
  );
}

function Results({
  data,
  onView,
  onDiff,
}: {
  data: { results: ConfigBackupSearchResult[]; has_more?: boolean; mode?: string };
  onView: (id: number) => void;
  onDiff: (id: number) => void;
}) {
  if (!data.results.length) {
    return (
      <div
        className="card"
        style={{
          textAlign: 'center',
          color: 'var(--text-muted)',
          padding: '1.5rem',
        }}
      >
        No matches found.
      </div>
    );
  }

  return (
    <>
      <div
        className="card"
        style={{
          marginBottom: '0.75rem',
          padding: '0.75rem 1rem',
          color: 'var(--text-muted)',
        }}
      >
        Found {data.results.length} result(s) using{' '}
        <strong>{data.mode || 'fulltext'}</strong> mode
        {data.has_more ? ' (showing top matches)' : ''}.
      </div>
      {data.results.map((r) => (
        <div
          key={r.backup_id}
          className="card"
          style={{ marginBottom: '0.75rem', padding: '1rem' }}
        >
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: '0.5rem',
            }}
          >
            <div>
              <strong>{r.hostname || r.ip_address || 'Unknown host'}</strong>
              <span
                style={{
                  marginLeft: '0.5rem',
                  fontSize: '0.85em',
                  color: 'var(--text-muted)',
                }}
              >
                {r.ip_address || ''}
              </span>
            </div>
            <div
              style={{
                display: 'flex',
                gap: '0.5rem',
                alignItems: 'center',
                flexWrap: 'wrap',
              }}
            >
              <span style={{ fontSize: '0.8em', color: 'var(--text-muted)' }}>
                line {r.match_line_number || '?'}
              </span>
              <button
                type="button"
                className="btn btn-sm btn-secondary"
                onClick={() => onView(r.backup_id)}
              >
                View Backup
              </button>
              <button
                type="button"
                className="btn btn-sm btn-secondary"
                onClick={() => onDiff(r.backup_id)}
              >
                View Diff
              </button>
            </div>
          </div>
          <div
            style={{
              marginTop: '0.5rem',
              fontSize: '0.85em',
              color: 'var(--text-muted)',
            }}
          >
            Captured: {formatStamp(r.captured_at)} • Method:{' '}
            {r.capture_method || 'unknown'} •{' '}
            {r.config_length
              ? `${(r.config_length / 1024).toFixed(1)} KB`
              : '-'}
          </div>
          <pre
            className="drift-diff-viewer"
            style={{
              maxHeight: 220,
              overflow: 'auto',
              marginTop: '0.75rem',
              padding: '0.5rem',
              background: 'var(--bg-primary)',
              border: '1px solid var(--border)',
              borderRadius: '0.375rem',
              fontSize: '0.8rem',
              whiteSpace: 'pre-wrap',
              margin: 0,
            }}
          >
            {(r.context_before_lines || []).map((line, i) => {
              const lineNum = (r.match_line_number || 0) - (r.context_before_lines?.length || 0) + i;
              return (
                <span key={`b${i}`} className="diff-context">
                  {lineNum > 0 ? `${lineNum}: ` : ''}{line}
                  {'\n'}
                </span>
              );
            })}
            <span className="diff-hunk">
              {r.match_line_number ? `${r.match_line_number}: ` : ''}
              {r.match_line || ''}
              {'\n'}
            </span>
            {(r.context_after_lines || []).map((line, i) => {
              const lineNum = (r.match_line_number || 0) + i + 1;
              return (
                <span key={`a${i}`} className="diff-context">
                  {lineNum > 0 ? `${lineNum}: ` : ''}{line}
                  {'\n'}
                </span>
              );
            })}
          </pre>
        </div>
      ))}
    </>
  );
}
