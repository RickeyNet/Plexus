import { type CSSProperties, type ReactNode, useState } from 'react';

import { ApiError } from '@/api/client';
import { type ObjectChange, type ObjectChangeFilter, useObjectChanges } from '@/api/objectChanges';
import { formatBackendTimestamp } from '@/lib/datetime';
import { actionLabel, actionTone, diffRows, formatChangeValue, objectTypeLabel } from '@/lib/objectChanges';

import { Badge } from './Badge';
import { Callout } from './Callout';
import { DataTable } from './DataTable';
import { EmptyState } from './EmptyState';
import { LoadingState } from './LoadingState';
import { QueryError } from './QueryError';

const DEFAULT_PAGE_SIZE = 20;

const MONO: CSSProperties = { fontFamily: 'var(--font-mono)' };
const VALUE_CELL: CSSProperties = { wordBreak: 'break-word' };
const MUTED_CELL: CSSProperties = { ...VALUE_CELL, color: 'var(--text-muted)' };
const BEFORE_CELL: CSSProperties = { ...VALUE_CELL, color: 'var(--danger)' };
const AFTER_CELL: CSSProperties = { ...VALUE_CELL, color: 'var(--success)' };

/** The field-by-field before/after table of one change. */
export function ChangeDiff({ change }: { change: Pick<ObjectChange, 'action' | 'changes' | 'before' | 'after'> }) {
  const rows = diffRows(change);
  if (rows.length === 0) {
    return <div className="text-muted" style={{ fontSize: '0.85em' }}>No field values recorded.</div>;
  }
  return (
    <DataTable compact aria-label="Changed fields">
      <thead>
        <tr>
          <th style={{ width: '24%' }}>Field</th>
          <th>Before</th>
          <th>After</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => (
          <tr key={row.field}>
            <td style={MONO}>{row.field}</td>
            <td style={row.kind === 'added' ? MUTED_CELL : BEFORE_CELL}>{formatChangeValue(row.before)}</td>
            <td style={row.kind === 'removed' ? MUTED_CELL : AFTER_CELL}>{formatChangeValue(row.after)}</td>
          </tr>
        ))}
      </tbody>
    </DataTable>
  );
}

/** One entry of the timeline: action, time, user, optionally the object, and the diff. */
export function ChangeEntry({
  change,
  showObject = false,
  renderObject,
}: {
  change: ObjectChange;
  showObject?: boolean;
  /** Replaces the default object text (e.g. with a link). */
  renderObject?: (change: ObjectChange) => ReactNode;
}) {
  return (
    <li style={{ listStyle: 'none', padding: '0.6rem 0', borderTop: '1px solid var(--border)' }}>
      <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem' }}>
        <Badge size="sm" tone={actionTone(change.action)}>
          {actionLabel(change.action)}
        </Badge>
        {showObject && (
          <span>
            {renderObject
              ? renderObject(change)
              : `${objectTypeLabel(change.object_type)} ${change.object_label || `#${change.object_id}`}`}
          </span>
        )}
        <span className="text-muted" style={{ fontSize: '0.9em' }}>
          {formatBackendTimestamp(change.changed_at)} by {change.user || 'system'}
        </span>
        {change.correlation_id && (
          <span className="text-muted" style={{ ...MONO, fontSize: '0.8em' }} title="Request correlation id">
            {change.correlation_id}
          </span>
        )}
      </div>
      <ChangeDiff change={change} />
    </li>
  );
}

/** Page controls: newer/older by `pageSize`. */
function Pager({
  offset,
  pageSize,
  total,
  onChange,
}: {
  offset: number;
  pageSize: number;
  total: number;
  onChange: (offset: number) => void;
}) {
  if (total <= pageSize) return null;
  const last = Math.min(total, offset + pageSize);
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', justifyContent: 'flex-end', marginTop: '0.5rem' }}>
      <span className="text-muted" style={{ fontSize: '0.85em' }}>
        {offset + 1}-{last} of {total.toLocaleString()}
      </span>
      <button
        type="button"
        className="btn btn-sm btn-secondary"
        disabled={offset === 0}
        onClick={() => onChange(Math.max(0, offset - pageSize))}
      >
        Newer
      </button>
      <button
        type="button"
        className="btn btn-sm btn-secondary"
        disabled={last >= total}
        onClick={() => onChange(offset + pageSize)}
      >
        Older
      </button>
    </div>
  );
}

/**
 * A paged change timeline for any filter. Used by the per-object panel and
 * the global change log; `showObject` names the object on each entry.
 */
export function ChangelogTimeline({
  filter,
  pageSize = DEFAULT_PAGE_SIZE,
  showObject = false,
  renderObject,
  emptyMessage = 'No changes recorded.',
}: {
  filter: Omit<ObjectChangeFilter, 'limit' | 'offset'>;
  pageSize?: number;
  showObject?: boolean;
  renderObject?: (change: ObjectChange) => ReactNode;
  emptyMessage?: string;
}) {
  const [offset, setOffset] = useState(0);
  // A new filter starts again at the newest page (prev-value guard, no effect).
  const filterKey = JSON.stringify(filter);
  const [prevKey, setPrevKey] = useState(filterKey);
  if (filterKey !== prevKey) {
    setPrevKey(filterKey);
    setOffset(0);
  }
  const query = useObjectChanges({ ...filter, limit: pageSize, offset });

  if (query.isError && !query.data) {
    if (query.error instanceof ApiError && query.error.status === 403) {
      return <Callout tone="info">You do not have access to these changes.</Callout>;
    }
    return <QueryError what="the change log" query={query} />;
  }
  if (query.isPending) return <LoadingState text="Loading changes…" />;
  const { changes, total } = query.data;
  if (total === 0) return <EmptyState compact message={emptyMessage} />;
  return (
    <div>
      <ul style={{ margin: 0, padding: 0 }} aria-label="Changes">
        {changes.map((c) => (
          <ChangeEntry key={c.id} change={c} showObject={showObject} renderObject={renderObject} />
        ))}
      </ul>
      <Pager offset={offset} pageSize={pageSize} total={total} onChange={setOffset} />
    </div>
  );
}

/**
 * The "Changelog" of one object: who changed which field from what to what,
 * newest first. Pass `objectId`, or `objectLabel` for objects addressed by
 * name (a prefix by its subnet).
 */
export function ChangelogPanel({
  objectType,
  objectId,
  objectLabel,
  title = 'Changelog',
  pageSize,
}: {
  objectType: string;
  objectId?: string | number | null;
  objectLabel?: string;
  title?: string | null;
  pageSize?: number;
}) {
  const hasId = objectId !== undefined && objectId !== null && String(objectId) !== '';
  // Neither selector: render nothing rather than every change of the type.
  if (!hasId && !objectLabel) return null;
  const filter = hasId
    ? { object_type: objectType, object_id: String(objectId) }
    : { object_type: objectType, object_label: objectLabel };
  return (
    <section aria-label={title ?? 'Changelog'}>
      {title && <div style={{ fontWeight: 600, marginBottom: '0.45rem' }}>{title}</div>}
      <ChangelogTimeline
        filter={filter}
        pageSize={pageSize}
        emptyMessage={`No changes recorded for this ${objectTypeLabel(objectType).toLowerCase()}.`}
      />
    </section>
  );
}
