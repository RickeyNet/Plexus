import { Fragment, useId, useState } from 'react';

import { type EntryFilter, type SyncRun, type SyncRunEntry, useSyncJobs, useSyncRun, useSyncRunEntries } from '@/api/sync';
import { Badge, StatusBadge } from '@/components/Badge';
import { Callout } from '@/components/Callout';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import { QueryError } from '@/components/QueryError';
import { formatBackendTimestamp } from '@/lib/datetime';
import {
  ACTION_LABEL,
  ACTION_TONE,
  OBJECT_TYPES,
  OBJECT_TYPE_LABEL,
  OUTCOME_TONE,
  type SyncKind,
  type SyncObjectType,
  type SyncOutcome,
  diffRows,
  fieldLabel,
  targetLabel,
} from '@/lib/sync';

const PAGE = 200;
const RIGHT = { textAlign: 'right' } as const;
const OUTCOMES: SyncOutcome[] = ['planned', 'applied', 'failed', 'skipped'];

interface RunDetailModalProps {
  runId: number;
  onClose: () => void;
}

/** One run: its status, the counts per object type and every planned change with its per-field diff. */
export function RunDetailModal({ runId, onClose }: RunDetailModalProps) {
  const q = useSyncRun(runId);
  const run = q.data;
  return (
    <Modal
      isOpen
      onClose={onClose}
      size="large"
      title={run ? `${run.dry_run ? 'Dry run' : 'Run'} of ${run.job_name}` : 'Sync run'}
      footer={
        <button type="button" className="btn btn-secondary" onClick={onClose}>
          Close
        </button>
      }
    >
      {q.isError && !run ? (
        <QueryError what="sync run" query={q} />
      ) : !run ? (
        <LoadingState text="Loading the run…" />
      ) : (
        <RunBody run={run} />
      )}
    </Modal>
  );
}

function RunBody({ run }: { run: SyncRun }) {
  const jobs = useSyncJobs();
  const kind = jobs.data?.find((j) => j.id === run.job_id)?.connection_kind;
  const types = OBJECT_TYPES.filter((t) => run.summary[t]);
  return (
    <div className="stack">
      <div style={{ display: 'flex', gap: 'var(--space-3)', flexWrap: 'wrap', alignItems: 'center' }}>
        <StatusBadge status={run.status} />
        {run.dry_run && <Badge tone="neutral">Dry run: nothing was written</Badge>}
        <span className="text-muted">
          Started {formatBackendTimestamp(run.started_at)}
          {run.trigger === 'schedule' ? ' by the schedule' : run.started_by ? ` by ${run.started_by}` : ''}
          {run.finished_at && ` · finished ${formatBackendTimestamp(run.finished_at)}`}
        </span>
      </div>
      {run.status === 'running' ? (
        <LoadingState text="The run is in progress…" />
      ) : (
        <>
          {run.message && (
            <Callout tone={run.status === 'failed' ? 'danger' : run.status === 'partial' ? 'warning' : 'info'}>
              {run.message}
            </Callout>
          )}
          {types.length > 0 && <SummaryTable run={run} types={types} />}
          <Entries runId={run.id} types={types} kind={kind} />
        </>
      )}
    </div>
  );
}

function SummaryTable({ run, types }: { run: SyncRun; types: SyncObjectType[] }) {
  return (
    <DataTable compact aria-label="Changes per object type">
      <thead>
        <tr>
          <th>Object type</th>
          <th style={RIGHT}>Remote</th>
          <th style={RIGHT}>Plexus</th>
          <th style={RIGHT}>Unchanged</th>
          <th style={RIGHT}>Create</th>
          <th style={RIGHT}>Update</th>
          <th style={RIGHT}>Delete</th>
          <th style={RIGHT}>Conflict</th>
          <th style={RIGHT}>Failed</th>
        </tr>
      </thead>
      <tbody>
        {types.map((t) => {
          const s = run.summary[t] ?? {};
          if (s.error) {
            return (
              <tr key={t}>
                <td>{OBJECT_TYPE_LABEL[t]}</td>
                <td colSpan={8}>
                  <Badge size="sm" tone="danger">
                    Not read
                  </Badge>{' '}
                  {s.error}
                </td>
              </tr>
            );
          }
          return (
            <tr key={t}>
              <td>
                {OBJECT_TYPE_LABEL[t]}
                {s.warnings?.map((w) => (
                  <div key={w} className="text-muted">
                    {w}
                  </div>
                ))}
              </td>
              {(['remote_records', 'plexus_records', 'unchanged', 'create', 'update', 'delete', 'conflict', 'failed'] as const).map(
                (k) => (
                  <td key={k} style={RIGHT}>
                    {(s[k] ?? 0).toLocaleString()}
                  </td>
                ),
              )}
            </tr>
          );
        })}
      </tbody>
    </DataTable>
  );
}

function Entries({ runId, types, kind }: { runId: number; types: SyncObjectType[]; kind: SyncKind | undefined }) {
  const id = useId();
  const [filter, setFilter] = useState<EntryFilter>({ limit: PAGE, offset: 0 });
  const [open, setOpen] = useState<Set<number>>(new Set());
  const q = useSyncRunEntries(runId, filter);
  const page = q.data;
  const toggle = (entryId: number) =>
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(entryId)) next.delete(entryId);
      else next.add(entryId);
      return next;
    });

  return (
    <div className="stack-sm">
      <div className="toolbar">
        <h3 style={{ margin: 0 }}>Changes</h3>
        <label className="sr-only" htmlFor={`${id}-type`}>
          Object type
        </label>
        <select
          id={`${id}-type`}
          className="form-select form-select-sm"
          value={filter.object_type ?? ''}
          onChange={(e) =>
            setFilter({ ...filter, offset: 0, object_type: (e.target.value || undefined) as SyncObjectType | undefined })
          }
        >
          <option value="">All object types</option>
          {types.map((t) => (
            <option key={t} value={t}>
              {OBJECT_TYPE_LABEL[t]}
            </option>
          ))}
        </select>
        <label className="sr-only" htmlFor={`${id}-outcome`}>
          Outcome
        </label>
        <select
          id={`${id}-outcome`}
          className="form-select form-select-sm"
          value={filter.outcome ?? ''}
          onChange={(e) =>
            setFilter({ ...filter, offset: 0, outcome: (e.target.value || undefined) as SyncOutcome | undefined })
          }
        >
          <option value="">All outcomes</option>
          {OUTCOMES.map((o) => (
            <option key={o} value={o}>
              {o[0].toUpperCase() + o.slice(1)}
            </option>
          ))}
        </select>
      </div>
      {q.isError && !page ? (
        <QueryError what="run changes" query={q} />
      ) : !page ? (
        <LoadingState text="Loading the changes…" />
      ) : page.entries.length === 0 ? (
        <EmptyState compact message={filter.object_type || filter.outcome ? 'No changes match.' : 'No changes: both sides matched.'} />
      ) : (
        <>
          <DataTable compact aria-label="Run changes">
            <thead>
              <tr>
                <th>Object</th>
                <th>Action</th>
                <th>Writes to</th>
                <th>Outcome</th>
                <th>Message</th>
                <th style={RIGHT}>Diff</th>
              </tr>
            </thead>
            <tbody>
              {page.entries.map((e) => (
                <Fragment key={e.id}>
                  <tr>
                    <td>
                      <span style={{ fontWeight: 600 }}>{e.key}</span>
                      <div className="text-muted">{OBJECT_TYPE_LABEL[e.object_type] ?? e.object_type}</div>
                    </td>
                    <td>
                      <Badge size="sm" tone={ACTION_TONE[e.action] ?? 'neutral'}>
                        {ACTION_LABEL[e.action] ?? e.action}
                      </Badge>
                    </td>
                    <td>{e.action === 'conflict' ? 'Nothing' : targetLabel(e.target, kind)}</td>
                    <td>
                      <Badge size="sm" tone={OUTCOME_TONE[e.outcome] ?? 'neutral'}>
                        {e.outcome}
                      </Badge>
                    </td>
                    <td className="text-muted">{e.message}</td>
                    <td style={RIGHT}>
                      {Object.keys(e.changes).length > 0 && (
                        <button
                          type="button"
                          className="btn btn-sm btn-ghost"
                          aria-expanded={open.has(e.id)}
                          aria-label={`${open.has(e.id) ? 'Hide' : 'Show'} the field changes of ${e.key}`}
                          onClick={() => toggle(e.id)}
                        >
                          {open.has(e.id) ? 'Hide' : `${Object.keys(e.changes).length} field${Object.keys(e.changes).length === 1 ? '' : 's'}`}
                        </button>
                      )}
                    </td>
                  </tr>
                  {open.has(e.id) && (
                    <tr>
                      <td colSpan={6}>
                        <FieldDiff entry={e} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </DataTable>
          {page.total > PAGE && (
            <div className="toolbar">
              <button
                type="button"
                className="btn btn-sm btn-secondary"
                disabled={filter.offset === 0}
                onClick={() => setFilter({ ...filter, offset: Math.max(0, filter.offset - PAGE) })}
              >
                Previous
              </button>
              <span className="text-muted">
                {filter.offset + 1}-{Math.min(filter.offset + PAGE, page.total)} of {page.total.toLocaleString()}
              </span>
              <button
                type="button"
                className="btn btn-sm btn-secondary"
                disabled={filter.offset + PAGE >= page.total}
                onClick={() => setFilter({ ...filter, offset: filter.offset + PAGE })}
              >
                Next
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function FieldDiff({ entry }: { entry: SyncRunEntry }) {
  const { columns, rows } = diffRows(entry);
  return (
    <div className="card-inset">
      <table className="data-table" aria-label={`Field changes of ${entry.key}`}>
        <thead>
          <tr>
            <th>Field</th>
            <th>{columns[0]}</th>
            <th>{columns[1]}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.field}>
              <td>{fieldLabel(r.field)}</td>
              <td>{r.left ? <code>{r.left}</code> : <span className="text-muted">empty</span>}</td>
              <td>{r.right ? <code>{r.right}</code> : <span className="text-muted">empty</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
