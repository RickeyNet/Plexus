import { type ReactNode, useId, useState } from 'react';

import {
  type DcimFilters,
  type DcimKind,
  type DcimRecord,
  useDcimList,
  useDeleteDcimRecord,
  useSaveDcimRecord,
} from '@/api/dcim';
import { CardHeader, CatalogueBody, Dash, RowActions, SaveFailure } from '@/components/CatalogueParts';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import { ModalActions } from '@/components/ModalActions';
import { TenantSelect } from '@/components/TenantSelect';
import { useConfirmDelete } from '@/components/useConfirmDelete';
import { type FieldSpec, fieldValue, formatUnits } from '@/lib/dcim';
import { idToSelect, selectToId } from '@/lib/deviceModel';
import { runSave } from '@/lib/recordSave';
import { serverFieldErrors } from '@/lib/serverFieldErrors';
import { usePendingKeys } from '@/lib/usePendingKeys';

import { useCanWriteDcim } from './hooks';

export interface ColumnSpec {
  label: string;
  render: (row: DcimRecord) => ReactNode;
  align?: 'right';
}

function toInput(field: FieldSpec, value: unknown): string | boolean {
  if (field.kind === 'checkbox') return Boolean(value);
  if (field.kind === 'units') return Array.isArray(value) ? formatUnits(value as number[]) : '';
  if (value === null || value === undefined) return '';
  return String(value);
}

function optionOf(o: string | { value: string | number; label: string }) {
  return typeof o === 'string' ? { value: o, label: o || '-' } : o;
}

/** Creates (`record` null) or edits one DCIM record from field specs. */
export function RecordModal({
  kind,
  what,
  fields,
  record,
  onClose,
}: {
  kind: DcimKind;
  what: string;
  fields: readonly FieldSpec[];
  record: DcimRecord | null;
  onClose: () => void;
}) {
  const id = useId();
  const save = useSaveDcimRecord(kind);
  const shown = fields.filter((f) => !(record && f.createOnly));
  const [values, setValues] = useState<Record<string, string | boolean>>(() =>
    Object.fromEntries(shown.map((f) => [f.key, toInput(f, record ? record[f.key] : f.initial)])),
  );
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [failure, setFailure] = useState<string | null>(null);

  const set = (key: string, value: string | boolean) => {
    setValues((prev) => ({ ...prev, [key]: value }));
    setErrors((prev) => ({ ...prev, [key]: '' }));
  };

  const submit = () => {
    const data: Record<string, unknown> = {};
    const found: Record<string, string> = {};
    for (const field of shown) {
      const result = fieldValue(field, values[field.key]);
      if (result.error) found[field.key] = result.error;
      else data[field.key] = result.value;
    }
    setErrors(found);
    if (Object.values(found).some(Boolean)) return;
    void runSave(
      () => save.mutateAsync({ id: record?.id ?? null, data }),
      null,
      setFailure,
      onClose,
      (err) => {
        const fieldErrors = serverFieldErrors(err);
        if (Object.keys(fieldErrors).some((k) => shown.some((f) => f.key === k))) {
          setErrors(fieldErrors);
          return true;
        }
        return false;
      },
    );
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      size="small"
      title={record ? `Edit ${what}` : `Add ${what}`}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={record ? `Save ${what}` : `Add ${what}`}
          primaryBusy={save.isPending}
          primaryBusyLabel="Saving…"
          onPrimary={submit}
        />
      }
    >
      <SaveFailure what={what} message={failure} />
      {shown.map((field) => {
        const inputId = `${id}-${field.key}`;
        const error = errors[field.key];
        const describedBy = `${inputId}-error`;
        if (field.kind === 'tenant') {
          return (
            <TenantSelect
              key={field.key}
              id={inputId}
              value={selectToId(String(values[field.key] ?? ''))}
              error={error}
              onChange={(v) => set(field.key, idToSelect(v))}
            />
          );
        }
        if (field.kind === 'checkbox') {
          return (
            <div className="form-group" key={field.key}>
              <label className="checkbox-label" htmlFor={inputId}>
                <input
                  id={inputId}
                  type="checkbox"
                  checked={Boolean(values[field.key])}
                  onChange={(e) => set(field.key, e.target.checked)}
                />{' '}
                {field.label}
              </label>
              {field.help && <div className="form-help">{field.help}</div>}
            </div>
          );
        }
        let control: ReactNode;
        const common = {
          id: inputId,
          'aria-invalid': !!error,
          'aria-describedby': describedBy,
          value: String(values[field.key] ?? ''),
        };
        if (field.kind === 'select' || field.kind === 'ref') {
          control = (
            <select {...common} className="form-select" onChange={(e) => set(field.key, e.target.value)}>
              {field.kind === 'ref' && <option value="">{field.required ? 'Choose…' : 'None'}</option>}
              {(field.options ?? []).map(optionOf).map((o) => (
                <option key={String(o.value)} value={String(o.value)}>
                  {o.label}
                </option>
              ))}
            </select>
          );
        } else if (field.kind === 'textarea') {
          control = <textarea {...common} className="form-input" rows={3} onChange={(e) => set(field.key, e.target.value)} />;
        } else {
          control = (
            <input
              {...common}
              className="form-input"
              type={field.kind === 'number' ? 'number' : 'text'}
              min={field.min}
              max={field.max}
              placeholder={field.kind === 'units' ? '1-3, 7' : undefined}
              onChange={(e) => set(field.key, e.target.value)}
            />
          );
        }
        return (
          <div className="form-group" key={field.key}>
            <label className="form-label" htmlFor={inputId}>
              {field.label}
              {field.required ? '' : ' (optional)'}
            </label>
            {control}
            {field.help && <div className="form-help">{field.help}</div>}
            <FieldError id={describedBy}>{error}</FieldError>
          </div>
        );
      })}
    </Modal>
  );
}

/**
 * A card listing the DCIM records of one kind with add, edit and delete
 * (for users who may write), filtered by `filters` and a search box.
 */
export function RecordSection({
  kind,
  title,
  what,
  columns,
  fields,
  filters = {},
  nameOf = (r) => String(r.name ?? r.id),
  emptyText,
  onSelect,
  selectedId,
  extraActions,
}: {
  kind: DcimKind;
  title: string;
  what: string;
  columns: readonly ColumnSpec[];
  fields: readonly FieldSpec[];
  filters?: DcimFilters;
  nameOf?: (row: DcimRecord) => string;
  emptyText: string;
  onSelect?: (row: DcimRecord) => void;
  selectedId?: number | null;
  extraActions?: ReactNode;
}) {
  const canWrite = useCanWriteDcim();
  const [q, setQ] = useState('');
  const query = useDcimList(kind, { ...filters, q });
  const remove = useDeleteDcimRecord(kind);
  const confirmDelete = useConfirmDelete();
  const deleting = usePendingKeys<number>();
  const [editing, setEditing] = useState<DcimRecord | 'new' | null>(null);
  const rows = query.data ?? [];
  const addButton = canWrite && (
    <button type="button" className="btn btn-sm btn-primary" onClick={() => setEditing('new')}>
      Add {what}
    </button>
  );
  return (
    <div className="card" style={{ marginBottom: '1rem' }}>
      <CardHeader
        title={title}
        sub={query.data && `${rows.length.toLocaleString()} shown`}
        actions={
          <>
            <input
              className="form-input"
              style={{ width: '14rem' }}
              aria-label={`Search ${title.toLowerCase()}`}
              placeholder="Search"
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
            {extraActions}
            {addButton}
          </>
        }
      />
      <CatalogueBody
        query={query}
        what={title.toLowerCase()}
        rows={rows}
        empty={
          <EmptyState
            compact
            message={q ? 'Nothing matches the search.' : emptyText}
            action={q ? undefined : addButton || undefined}
          />
        }
      >
        <DataTable compact aria-label={title}>
          <thead>
            <tr>
              {columns.map((c) => (
                <th key={c.label} style={c.align ? { textAlign: c.align } : undefined}>
                  {c.label}
                </th>
              ))}
              {canWrite && <th style={{ textAlign: 'right' }}>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr
                key={row.id}
                className={onSelect ? `row-clickable${row.id === selectedId ? ' row-selected' : ''}` : undefined}
                onClick={onSelect ? () => onSelect(row) : undefined}
              >
                {columns.map((c) => (
                  <td key={c.label} style={c.align ? { textAlign: c.align } : undefined}>
                    {c.render(row) ?? <Dash />}
                  </td>
                ))}
                {canWrite && (
                  <td style={{ textAlign: 'right' }} onClick={(e) => e.stopPropagation()}>
                    <RowActions
                      label={`${what} ${nameOf(row)}`}
                      onEdit={() => setEditing(row)}
                      onDelete={() =>
                        void deleting.run(row.id, () => confirmDelete(what, nameOf(row), () => remove.mutateAsync(row.id)))
                      }
                      deleting={deleting.isPending(row.id)}
                    />
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </DataTable>
      </CatalogueBody>
      {editing && (
        <RecordModal
          kind={kind}
          what={what}
          fields={fields}
          record={editing === 'new' ? null : editing}
          onClose={() => setEditing(null)}
        />
      )}
    </div>
  );
}

/** A cell value, or a dash when empty. */
export function Val({ value }: { value: unknown }) {
  return value === null || value === undefined || value === '' ? <Dash /> : <>{String(value)}</>;
}
