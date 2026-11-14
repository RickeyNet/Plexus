import type { ReactNode } from 'react';

import { Callout } from './Callout';
import { DeleteButton } from './DeleteButton';
import { LoadingState } from './LoadingState';
import { QueryError } from './QueryError';

/**
 * Shared parts of the record catalogues (device model, VRFs, VLANs): the
 * table body states, the row actions, and the create / edit dialog's
 * description input and save failure.
 */

/** The longest description a catalogue record takes. */
export const CATALOGUE_DESCRIPTION_MAX = 500;

/** A section's body: error, loading, empty state with the create action, or the table. */
export function CatalogueBody<T>({
  query,
  what,
  rows,
  empty,
  children,
}: {
  query: { isError: boolean; isPending: boolean; data: T[] | undefined; error: unknown; isFetching: boolean; refetch: () => unknown };
  what: string;
  rows: T[];
  empty: ReactNode;
  children: ReactNode;
}) {
  if (query.isError && !query.data) return <QueryError what={what} query={query} />;
  if (query.isPending) return <LoadingState text={`Loading ${what}…`} />;
  if (rows.length === 0) return <>{empty}</>;
  return <>{children}</>;
}

export function RowActions({
  label,
  onEdit,
  onDelete,
  deleting,
}: {
  label: string;
  onEdit: () => void;
  onDelete?: () => void;
  deleting: boolean;
}) {
  return (
    <div className="table-actions" style={{ justifyContent: 'flex-end' }}>
      <button type="button" className="btn btn-sm btn-secondary" aria-label={`Edit ${label}`} onClick={onEdit}>
        Edit
      </button>
      {onDelete && <DeleteButton aria-label={`Delete ${label}`} busy={deleting} onClick={onDelete} />}
    </div>
  );
}

export function DescriptionInput({ id, value, onChange }: { id: string; value: string; onChange: (v: string) => void }) {
  return (
    <div className="form-group">
      <label className="form-label" htmlFor={`${id}-description`}>
        Description (optional)
      </label>
      <input
        id={`${id}-description`}
        className="form-input"
        value={value}
        maxLength={CATALOGUE_DESCRIPTION_MAX}
        onChange={(e) => onChange(e.target.value)}
      />
    </div>
  );
}

export function SaveFailure({ what, message }: { what: string; message: string | null }) {
  if (!message) return null;
  return (
    <Callout tone="danger" title={`The ${what} was not saved`}>
      {message} Check the fields and try again.
    </Callout>
  );
}
