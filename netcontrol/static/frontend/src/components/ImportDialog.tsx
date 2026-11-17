import { useId, useState } from 'react';

import { ApiError } from '@/api/client';
import { importTemplateUrl, useCommitImport, usePreviewImport } from '@/api/bulkImport';
import { Badge } from '@/components/Badge';
import { BusyButton } from '@/components/BusyButton';
import { Callout } from '@/components/Callout';
import { DataTable } from '@/components/DataTable';
import { Modal } from '@/components/Modal';
import { SegmentedControl } from '@/components/SegmentedControl';
import {
  ACTION_LABEL,
  actionTone,
  canCommit,
  changeList,
  filterRows,
  formatFromFileName,
  IMPORT_MODES,
  IMPORT_TYPES,
  type ImportAction,
  type ImportFormat,
  type ImportMode,
  type ImportReport,
  type ImportType,
  inputProblem,
  reportFromErrorBody,
  summaryText,
} from '@/lib/bulkImport';

/** Rows the preview table shows at most; the summary counts all of them. */
const SHOWN_ROWS = 500;

interface Props {
  /** The object types this page imports; the first is preselected. */
  types: readonly ImportType[];
  onClose: () => void;
}

type Source = 'file' | 'paste';

/**
 * Bulk import dialog shared by the Inventory and IPAM pages: pick the type,
 * upload or paste CSV / YAML / JSON, preview what each row would do (create,
 * update with its field diff, skip, or its errors), then import. The server
 * checks every row again on import; by default nothing is written unless
 * every row is valid.
 */
export function ImportDialog({ types, onClose }: Props) {
  const id = useId();
  const preview = usePreviewImport();
  const commit = useCommitImport();
  const [type, setType] = useState<ImportType>(types[0]);
  const [source, setSource] = useState<Source>('file');
  const [file, setFile] = useState<File | null>(null);
  const [text, setText] = useState('');
  const [format, setFormat] = useState<ImportFormat>('csv');
  const [mode, setMode] = useState<ImportMode>('create');
  const [matchKey, setMatchKey] = useState(IMPORT_TYPES[types[0]].matchKeys[0].key);
  const [atomic, setAtomic] = useState(true);
  const [report, setReport] = useState<ImportReport | null>(null);
  const [result, setResult] = useState<ImportReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<ImportAction | 'all'>('all');

  const info = IMPORT_TYPES[type];
  const input = { file: source === 'file' ? file : null, text: source === 'paste' ? text : '', format, mode, matchKey };
  const problem = inputProblem(input);
  const shown = report ? filterRows(report.rows, filter) : [];

  // Any change to what would be sent makes the preview stale.
  const changed = <T,>(set: (v: T) => void) => (v: T) => {
    set(v);
    setReport(null);
    setResult(null);
    setError(null);
  };

  const chooseType = changed((next: ImportType) => {
    setType(next);
    setMatchKey(IMPORT_TYPES[next].matchKeys[0].key);
  });

  const chooseFile = changed((next: File | null) => {
    setFile(next);
    const guessed = next ? formatFromFileName(next.name) : null;
    if (guessed) setFormat(guessed);
  });

  const runPreview = () => {
    setError(null);
    setResult(null);
    preview.mutate(
      { type, ...input },
      {
        onSuccess: (r) => {
          setReport(r);
          setFilter(r.summary.error ? 'error' : 'all');
        },
        onError: (err) => setError(`The file was not read: ${err.message} Check it and try again.`),
      },
    );
  };

  const runCommit = () => {
    setError(null);
    commit.mutate(
      { type, ...input, atomic },
      {
        onSuccess: (r) => {
          setResult(r);
          setReport(r);
        },
        onError: (err) => {
          const refused = err instanceof ApiError ? reportFromErrorBody(err.body) : null;
          if (refused) {
            setResult(refused);
            setReport(refused);
            setFilter('error');
          } else {
            setError(`Nothing was imported: ${err.message} Try again.`);
          }
        },
      },
    );
  };

  const toWrite = report ? report.summary.create + report.summary.update : 0;
  const done = result?.committed === true;

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={`Import ${info.label.toLowerCase()}`}
      size="large"
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            {done ? 'Close' : 'Cancel'}
          </button>
          {!done && (
            <BusyButton
              className="btn btn-secondary"
              busy={preview.isPending}
              busyLabel="Checking…"
              disabled={problem !== null || commit.isPending}
              onClick={runPreview}
            >
              Preview import
            </BusyButton>
          )}
          {!done && (
            <BusyButton
              className="btn btn-primary"
              busy={commit.isPending}
              busyLabel="Importing…"
              disabled={!report || report.committed || !canCommit(report, atomic) || preview.isPending}
              onClick={runCommit}
              title={report ? undefined : 'Preview the import first'}
            >
              {toWrite ? `Import ${toWrite.toLocaleString()} row${toWrite === 1 ? '' : 's'}` : 'Import'}
            </BusyButton>
          )}
        </>
      }
    >
      {error && <Callout tone="danger">{error}</Callout>}
      {result && (
        <Callout tone={result.committed ? 'success' : 'danger'} title={result.committed ? 'Imported' : 'Not imported'}>
          {result.message}
        </Callout>
      )}

      <div style={{ display: 'flex', gap: 'var(--space-3)', flexWrap: 'wrap', alignItems: 'flex-end' }}>
        {types.length > 1 && (
          <div className="form-group">
            <label className="form-label" htmlFor={`${id}-type`}>
              Import
            </label>
            <select
              id={`${id}-type`}
              className="form-select"
              value={type}
              onChange={(e) => chooseType(e.target.value as ImportType)}
            >
              {types.map((t) => (
                <option key={t} value={t}>
                  {IMPORT_TYPES[t].label}
                </option>
              ))}
            </select>
          </div>
        )}
        <div className="form-group">
          <label className="form-label" htmlFor={`${id}-format`}>
            Format
          </label>
          <select
            id={`${id}-format`}
            className="form-select"
            value={format}
            onChange={(e) => changed(setFormat)(e.target.value as ImportFormat)}
          >
            <option value="csv">CSV</option>
            <option value="yaml">YAML</option>
            <option value="json">JSON</option>
          </select>
        </div>
        {info.matchKeys.length > 1 && (
          <div className="form-group">
            <label className="form-label" htmlFor={`${id}-match`}>
              Match existing by
            </label>
            <select
              id={`${id}-match`}
              className="form-select"
              value={matchKey}
              onChange={(e) => changed(setMatchKey)(e.target.value)}
            >
              {info.matchKeys.map((m) => (
                <option key={m.key} value={m.key}>
                  {m.label}
                </option>
              ))}
            </select>
          </div>
        )}
        <div className="form-group">
          <span className="form-label">Mode</span>
          <SegmentedControl
            aria-label="Import mode"
            options={IMPORT_MODES}
            value={mode}
            onChange={changed(setMode)}
          />
        </div>
        <div className="form-group">
          <a className="btn btn-sm btn-secondary" href={importTemplateUrl(type)} download>
            Download CSV template
          </a>
        </div>
      </div>

      <div className="form-group">
        <span className="form-label">Rows</span>
        <SegmentedControl
          aria-label="Rows from"
          options={[
            { key: 'file', label: 'Upload a file' },
            { key: 'paste', label: 'Paste' },
          ]}
          value={source}
          onChange={changed(setSource)}
        />
      </div>
      {source === 'file' ? (
        <div className="form-group">
          <label className="form-label" htmlFor={`${id}-file`}>
            File
          </label>
          <input
            id={`${id}-file`}
            type="file"
            className="form-input"
            accept=".csv,.txt,.yaml,.yml,.json,text/csv,application/json,application/yaml"
            onChange={(e) => chooseFile(e.target.files?.[0] ?? null)}
          />
          <p className="form-help">
            CSV with a header row (an inventory export imports as it is), or a YAML / JSON list of objects. At most 1
            MiB.
          </p>
        </div>
      ) : (
        <div className="form-group">
          <label className="form-label" htmlFor={`${id}-text`}>
            Rows to import
          </label>
          <textarea
            id={`${id}-text`}
            className="form-textarea form-code"
            rows={8}
            value={text}
            onChange={(e) => changed(setText)(e.target.value)}
            placeholder={format === 'csv' ? 'Hostname,IP Address,Group' : '- hostname: edge-sw1'}
          />
        </div>
      )}
      <label className="form-check">
        <input type="checkbox" checked={atomic} onChange={(e) => changed(setAtomic)(e.target.checked)} />
        All or nothing: import only when every row is valid, and undo every row if one fails
      </label>

      {report && (
        <section aria-label="Import preview" style={{ marginTop: 'var(--space-4)' }}>
          <p>
            <strong>{summaryText(report)}</strong>
            {!atomic && report.summary.error > 0 && ' The import stops at the first row with errors.'}
          </p>
          {report.new_tags.length > 0 && (
            <Callout tone="info">New tags are created on import: {report.new_tags.join(', ')}.</Callout>
          )}
          {report.ignored_columns.length > 0 && (
            <Callout tone="warning" title="Columns not imported">
              {report.ignored_columns.map((c) => `${c.column} (${c.reason})`).join('; ')}
            </Callout>
          )}
          <div className="form-group" style={{ maxWidth: 240 }}>
            <label className="form-label" htmlFor={`${id}-filter`}>
              Show
            </label>
            <select
              id={`${id}-filter`}
              className="form-select form-select-sm"
              value={filter}
              onChange={(e) => setFilter(e.target.value as ImportAction | 'all')}
            >
              <option value="all">All rows ({report.summary.total})</option>
              {(['create', 'update', 'skip', 'error'] as const).map((a) => (
                <option key={a} value={a}>
                  {ACTION_LABEL[a]} ({report.summary[a]})
                </option>
              ))}
            </select>
          </div>
          <DataTable compact stickyHeader maxHeight={420} aria-label="Rows to import">
            <thead>
              <tr>
                <th>Row</th>
                <th>Object</th>
                <th>Action</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {shown.slice(0, SHOWN_ROWS).map((r) => (
                <tr key={r.row}>
                  <td>{r.row}</td>
                  <td>{r.key || '—'}</td>
                  <td>
                    <Badge tone={actionTone(r.action)} size="sm">
                      {ACTION_LABEL[r.action]}
                    </Badge>
                  </td>
                  <td>
                    {r.errors.map((e, i) => (
                      <div key={`e${i}`} style={{ color: 'var(--danger)' }}>
                        {e.field ? <strong>{e.field}: </strong> : null}
                        {e.message}
                      </div>
                    ))}
                    {changeList(r).map((c) => (
                      <div key={c.field}>
                        <strong>{c.field}:</strong> {c.before || '(empty)'} → {c.after || '(empty)'}
                      </div>
                    ))}
                    {r.warnings.map((w, i) => (
                      <div key={`w${i}`} className="text-muted">
                        {w}
                      </div>
                    ))}
                  </td>
                </tr>
              ))}
            </tbody>
          </DataTable>
          {shown.length > SHOWN_ROWS && (
            <p className="form-help">
              Showing the first {SHOWN_ROWS.toLocaleString()} of {shown.length.toLocaleString()} rows.
            </p>
          )}
        </section>
      )}
    </Modal>
  );
}
