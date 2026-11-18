import { useId, useState } from 'react';

import {
  type Cardinality,
  type ComputedField,
  CustomDataError,
  type IdObjectType,
  type Relationship,
  useComputedFields,
  useDeleteComputedField,
  useDeleteRelationship,
  useRelationships,
  useSaveComputedField,
  useSaveRelationship,
} from '@/api/customData';
import { Callout } from '@/components/Callout';
import { DataTable } from '@/components/DataTable';
import { DeleteButton } from '@/components/DeleteButton';
import { useDialogs } from '@/components/DialogProvider-context';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import { ModalActions } from '@/components/ModalActions';
import { QueryError } from '@/components/QueryError';
import { CARDINALITY_LABELS, definitionErrors, ID_OBJECT_TYPES, OBJECT_TYPE_LABELS } from '@/lib/customData';
import { usePendingKeys } from '@/lib/usePendingKeys';

const TEMPLATE_MAX = 4000;

function typeTitle(type: string): string {
  return OBJECT_TYPE_LABELS[type as IdObjectType]?.title ?? type;
}

function TypeSelect({
  id,
  label,
  value,
  onChange,
  disabled,
}: {
  id: string;
  label: string;
  value: IdObjectType;
  onChange: (value: IdObjectType) => void;
  disabled?: boolean;
}) {
  return (
    <div className="form-group">
      <label className="form-label" htmlFor={id}>
        {label}
      </label>
      <select
        id={id}
        className="form-select"
        value={value}
        disabled={disabled}
        onChange={(e) => onChange(e.target.value as IdObjectType)}
      >
        {ID_OBJECT_TYPES.map((t) => (
          <option key={t} value={t}>
            {OBJECT_TYPE_LABELS[t].title}
          </option>
        ))}
      </select>
    </div>
  );
}

function TextInput({
  id,
  label,
  value,
  onChange,
  error,
  disabled,
  help,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  error?: string;
  disabled?: boolean;
  help?: string;
}) {
  return (
    <div className="form-group">
      <label className="form-label" htmlFor={id}>
        {label}
      </label>
      <input
        id={id}
        className="form-input"
        value={value}
        disabled={disabled}
        aria-invalid={error ? true : undefined}
        aria-describedby={error ? `${id}-error` : undefined}
        onChange={(e) => onChange(e.target.value)}
      />
      {help && !error && <div className="form-help">{help}</div>}
      {error && (
        <div id={`${id}-error`} className="form-error">
          {error}
        </div>
      )}
    </div>
  );
}

// ── Computed fields ────────────────────────────────────────────────────────

function ComputedFieldModal({ field, onClose }: { field: ComputedField | null; onClose: () => void }) {
  const id = useId();
  const save = useSaveComputedField();
  const [key, setKey] = useState(field?.key ?? '');
  const [label, setLabel] = useState(field?.label ?? '');
  const [objectType, setObjectType] = useState<IdObjectType>(field?.object_type ?? 'vrf');
  const [template, setTemplate] = useState(field?.template ?? '');
  const [description, setDescription] = useState(field?.description ?? '');
  const [sortOrder, setSortOrder] = useState(String(field?.sort_order ?? 0));
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [failure, setFailure] = useState<string | null>(null);

  const submit = () => {
    const found = definitionErrors(key, label, field === null);
    if (!template.trim()) found.template = 'Enter a template.';
    setErrors(found);
    if (Object.keys(found).length > 0) return;
    setFailure(null);
    const data = {
      key: key.trim(),
      label: label.trim(),
      object_type: objectType,
      template,
      description: description.trim(),
      sort_order: Number.parseInt(sortOrder, 10) || 0,
    };
    save.mutate(
      { id: field?.id, data },
      {
        onSuccess: onClose,
        onError: (err) => {
          if (err instanceof CustomDataError && err.status === 409) setErrors({ key: err.message });
          else setFailure(err.message);
        },
      },
    );
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={field ? `Edit computed field ${field.label}` : 'New computed field'}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={field ? 'Save computed field' : 'Create computed field'}
          primaryBusy={save.isPending}
          primaryBusyLabel="Saving…"
          onPrimary={submit}
        />
      }
    >
      {failure && (
        <Callout tone="danger" title="The computed field was not saved">
          {failure}
        </Callout>
      )}
      <TextInput id={`${id}-label`} label="Label" value={label} onChange={setLabel} error={errors.label} />
      <TextInput
        id={`${id}-key`}
        label="Key"
        value={key}
        onChange={setKey}
        error={errors.key}
        disabled={field !== null}
        help="Fixed once created. Lowercase letters, digits and _."
      />
      <TypeSelect
        id={`${id}-type`}
        label="Object type"
        value={objectType}
        onChange={setObjectType}
        disabled={field !== null}
      />
      <div className="form-group">
        <label className="form-label" htmlFor={`${id}-template`}>
          Template
        </label>
        <textarea
          id={`${id}-template`}
          className="form-input"
          rows={4}
          maxLength={TEMPLATE_MAX}
          value={template}
          aria-invalid={errors.template ? true : undefined}
          onChange={(e) => setTemplate(e.target.value)}
          style={{ fontFamily: 'var(--font-mono, monospace)' }}
        />
        {errors.template ? (
          <div className="form-error">{errors.template}</div>
        ) : (
          <div className="form-help">
            Jinja2, e.g. <code>{'{{ obj.name | upper }}'}</code>. Use <code>obj</code> (the object&apos;s attributes),{' '}
            <code>custom_fields</code> and <code>tags</code>. A template that fails shows an empty value.
          </div>
        )}
      </div>
      <TextInput id={`${id}-description`} label="Description (optional)" value={description} onChange={setDescription} />
      <TextInput id={`${id}-order`} label="Display order" value={sortOrder} onChange={setSortOrder} />
    </Modal>
  );
}

/** Admin list of computed fields: create, edit and delete. */
export function ComputedFieldsSection() {
  const { confirm, alert } = useDialogs();
  const q = useComputedFields();
  const remove = useDeleteComputedField();
  const deleting = usePendingKeys<number>();
  const [editing, setEditing] = useState<ComputedField | 'new' | null>(null);
  const rows = q.data ?? [];
  const newButton = (
    <button type="button" className="btn btn-sm btn-primary" onClick={() => setEditing('new')}>
      New computed field
    </button>
  );

  const handleDelete = async (field: ComputedField) => {
    const agreed = await confirm({
      title: 'Delete computed field',
      message: `Delete computed field "${field.label}"? This cannot be undone.`,
      confirmLabel: 'Delete computed field',
    });
    if (!agreed) return;
    await deleting.run(field.id, async () => {
      try {
        await remove.mutateAsync(field.id);
      } catch (e) {
        void alert({ message: `"${field.label}" was not deleted: ${(e as Error).message} Try again.`, variant: 'error' });
      }
    });
  };

  return (
    <div className="stack stack-sm">
      {rows.length > 0 && <div style={{ display: 'flex', justifyContent: 'flex-end' }}>{newButton}</div>}
      {q.isError && !q.data ? (
        <QueryError what="computed fields" query={q} />
      ) : q.isPending ? (
        <LoadingState text="Loading computed fields…" />
      ) : rows.length === 0 ? (
        <EmptyState
          compact
          message="No computed fields yet."
          description="A computed field shows a value built from an object's attributes, such as a display name."
          action={newButton}
        />
      ) : (
        <DataTable compact aria-label="Computed fields">
          <thead>
            <tr>
              <th>Label</th>
              <th>Key</th>
              <th>Object type</th>
              <th>Template</th>
              <th style={{ textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((field) => (
              <tr key={field.id}>
                <td>{field.label}</td>
                <td>
                  <code>{field.key}</code>
                </td>
                <td>{typeTitle(field.object_type)}</td>
                <td>
                  <code style={{ overflowWrap: 'anywhere' }}>{field.template}</code>
                </td>
                <td style={{ textAlign: 'right' }}>
                  <div className="table-actions" style={{ justifyContent: 'flex-end' }}>
                    <button
                      type="button"
                      className="btn btn-sm btn-secondary"
                      aria-label={`Edit computed field ${field.label}`}
                      onClick={() => setEditing(field)}
                    >
                      Edit
                    </button>
                    <DeleteButton
                      aria-label={`Delete computed field ${field.label}`}
                      busy={deleting.isPending(field.id)}
                      onClick={() => void handleDelete(field)}
                    />
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      )}
      {editing && <ComputedFieldModal field={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
    </div>
  );
}

// ── Relationships ──────────────────────────────────────────────────────────

function RelationshipModal({ relationship, onClose }: { relationship: Relationship | null; onClose: () => void }) {
  const id = useId();
  const save = useSaveRelationship();
  const fixed = relationship !== null;
  const [key, setKey] = useState(relationship?.key ?? '');
  const [label, setLabel] = useState(relationship?.label ?? '');
  const [source, setSource] = useState<IdObjectType>(relationship?.source_type ?? 'circuit');
  const [destination, setDestination] = useState<IdObjectType>(relationship?.destination_type ?? 'vrf');
  const [cardinality, setCardinality] = useState<Cardinality>(relationship?.cardinality ?? 'many-to-many');
  const [description, setDescription] = useState(relationship?.description ?? '');
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [failure, setFailure] = useState<string | null>(null);

  const submit = () => {
    const found = definitionErrors(key, label, !fixed);
    setErrors(found);
    if (Object.keys(found).length > 0) return;
    setFailure(null);
    const data = {
      key: key.trim(),
      label: label.trim(),
      source_type: source,
      destination_type: destination,
      cardinality,
      description: description.trim(),
    };
    save.mutate(
      { id: relationship?.id, data },
      {
        onSuccess: onClose,
        onError: (err) => {
          if (err instanceof CustomDataError && err.status === 409) setErrors({ key: err.message });
          else setFailure(err.message);
        },
      },
    );
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={relationship ? `Edit relationship ${relationship.label}` : 'New relationship'}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={relationship ? 'Save relationship' : 'Create relationship'}
          primaryBusy={save.isPending}
          primaryBusyLabel="Saving…"
          onPrimary={submit}
        />
      }
    >
      {failure && (
        <Callout tone="danger" title="The relationship was not saved">
          {failure}
        </Callout>
      )}
      <TextInput id={`${id}-label`} label="Label" value={label} onChange={setLabel} error={errors.label} />
      <TextInput
        id={`${id}-key`}
        label="Key"
        value={key}
        onChange={setKey}
        error={errors.key}
        disabled={fixed}
        help="Fixed once created. Lowercase letters, digits and _."
      />
      <TypeSelect id={`${id}-source`} label="Source type" value={source} onChange={setSource} disabled={fixed} />
      <TypeSelect
        id={`${id}-destination`}
        label="Destination type"
        value={destination}
        onChange={setDestination}
        disabled={fixed}
      />
      <div className="form-group">
        <label className="form-label" htmlFor={`${id}-cardinality`}>
          Cardinality
        </label>
        <select
          id={`${id}-cardinality`}
          className="form-select"
          value={cardinality}
          disabled={fixed}
          onChange={(e) => setCardinality(e.target.value as Cardinality)}
        >
          {(Object.keys(CARDINALITY_LABELS) as Cardinality[]).map((c) => (
            <option key={c} value={c}>
              {CARDINALITY_LABELS[c]}
            </option>
          ))}
        </select>
        <div className="form-help">
          One to many: a destination has at most one source. One to one: each side has at most one link.
        </div>
      </div>
      <TextInput id={`${id}-description`} label="Description (optional)" value={description} onChange={setDescription} />
    </Modal>
  );
}

/** Admin list of relationships: create, rename and delete (which removes their links). */
export function RelationshipsSection() {
  const { confirm, alert } = useDialogs();
  const q = useRelationships();
  const remove = useDeleteRelationship();
  const deleting = usePendingKeys<number>();
  const [editing, setEditing] = useState<Relationship | 'new' | null>(null);
  const rows = q.data ?? [];
  const newButton = (
    <button type="button" className="btn btn-sm btn-primary" onClick={() => setEditing('new')}>
      New relationship
    </button>
  );

  const handleDelete = async (rel: Relationship) => {
    const links = rel.link_count ?? 0;
    const agreed = await confirm({
      title: 'Delete relationship',
      message: `Delete relationship "${rel.label}"? Its ${links} link${links === 1 ? '' : 's'} are removed. This cannot be undone.`,
      confirmLabel: 'Delete relationship',
    });
    if (!agreed) return;
    await deleting.run(rel.id, async () => {
      try {
        await remove.mutateAsync(rel.id);
      } catch (e) {
        void alert({ message: `"${rel.label}" was not deleted: ${(e as Error).message} Try again.`, variant: 'error' });
      }
    });
  };

  return (
    <div className="stack stack-sm">
      {rows.length > 0 && <div style={{ display: 'flex', justifyContent: 'flex-end' }}>{newButton}</div>}
      {q.isError && !q.data ? (
        <QueryError what="relationships" query={q} />
      ) : q.isPending ? (
        <LoadingState text="Loading relationships…" />
      ) : rows.length === 0 ? (
        <EmptyState
          compact
          message="No relationships yet."
          description="A relationship links objects of two types, such as circuits to the VRFs they carry."
          action={newButton}
        />
      ) : (
        <DataTable compact aria-label="Relationships">
          <thead>
            <tr>
              <th>Label</th>
              <th>Key</th>
              <th>Source</th>
              <th>Destination</th>
              <th>Cardinality</th>
              <th style={{ textAlign: 'right' }}>Links</th>
              <th style={{ textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((rel) => (
              <tr key={rel.id}>
                <td>{rel.label}</td>
                <td>
                  <code>{rel.key}</code>
                </td>
                <td>{typeTitle(rel.source_type)}</td>
                <td>{typeTitle(rel.destination_type)}</td>
                <td>{CARDINALITY_LABELS[rel.cardinality] ?? rel.cardinality}</td>
                <td style={{ textAlign: 'right' }}>{(rel.link_count ?? 0).toLocaleString()}</td>
                <td style={{ textAlign: 'right' }}>
                  <div className="table-actions" style={{ justifyContent: 'flex-end' }}>
                    <button
                      type="button"
                      className="btn btn-sm btn-secondary"
                      aria-label={`Edit relationship ${rel.label}`}
                      onClick={() => setEditing(rel)}
                    >
                      Edit
                    </button>
                    <DeleteButton
                      aria-label={`Delete relationship ${rel.label}`}
                      busy={deleting.isPending(rel.id)}
                      onClick={() => void handleDelete(rel)}
                    />
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      )}
      {editing && (
        <RelationshipModal relationship={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />
      )}
    </div>
  );
}
