import { useState } from 'react';

import {
  type CustomField,
  type TagWithUsage,
  useCustomFields,
  useDeleteCustomField,
  useDeleteTag,
  useTags,
} from '@/api/customData';
import { DataTable } from '@/components/DataTable';
import { DeleteButton } from '@/components/DeleteButton';
import { useDialogs } from '@/components/DialogProvider-context';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { TagChips } from '@/components/TagChips';
import { countObjects, FIELD_TYPE_LABELS, OBJECT_TYPE_LABELS, OBJECT_TYPES } from '@/lib/customData';
import { usePendingKeys } from '@/lib/usePendingKeys';

import { CustomFieldModal } from './CustomFieldModal';
import { SectionCard } from './SectionCard';
import { TagModal } from './TagModal';

function FieldsSection() {
  const { confirm, alert } = useDialogs();
  const fieldsQ = useCustomFields();
  const remove = useDeleteCustomField();
  const deleting = usePendingKeys<number>();
  const [editing, setEditing] = useState<CustomField | 'new' | null>(null);

  const rows = [...(fieldsQ.data ?? [])].sort((a, b) => a.sort_order - b.sort_order || a.id - b.id);
  const newButton = (
    <button type="button" className="btn btn-sm btn-primary" onClick={() => setEditing('new')}>
      New field
    </button>
  );

  const handleDelete = async (field: CustomField) => {
    const lose =
      field.value_count === undefined
        ? 'Every value stored for it is removed.'
        : field.value_count === 1
          ? '1 object loses its value.'
          : `${countObjects(field.value_count)} lose their value.`;
    const agreed = await confirm({
      title: 'Delete field',
      message: `Delete field "${field.label}"? ${lose} This cannot be undone.`,
      confirmLabel: 'Delete field',
    });
    if (!agreed) return;
    await deleting.run(field.id, async () => {
      try {
        await remove.mutateAsync(field.id);
      } catch (e) {
        void alert({
          message: `The field "${field.label}" was not deleted: ${(e as Error).message} Try again.`,
          variant: 'error',
        });
      }
    });
  };

  return (
    <div className="stack stack-sm">
      {rows.length > 0 && <div style={{ display: 'flex', justifyContent: 'flex-end' }}>{newButton}</div>}

      {fieldsQ.isError && !fieldsQ.data ? (
        <QueryError what="custom fields" query={fieldsQ} />
      ) : fieldsQ.isPending ? (
        <LoadingState text="Loading custom fields…" />
      ) : rows.length === 0 ? (
        <EmptyState
          compact
          message="No custom fields yet."
          description="Add a field to record something Plexus has no column for, such as an asset owner or a circuit ID."
          action={newButton}
        />
      ) : (
        <DataTable compact aria-label="Custom fields">
          <thead>
            <tr>
              <th>Label</th>
              <th>Key</th>
              <th>Type</th>
              <th>Applies to</th>
              <th>Required</th>
              <th style={{ textAlign: 'right' }}>Order</th>
              <th style={{ textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((field) => (
              <tr key={field.id}>
                <td>
                  {field.label}
                  {field.description && (
                    <div className="form-help" style={{ margin: 0 }}>
                      {field.description}
                    </div>
                  )}
                </td>
                <td>
                  <code>{field.key}</code>
                </td>
                <td>{FIELD_TYPE_LABELS[field.field_type] ?? field.field_type}</td>
                <td>
                  {OBJECT_TYPES.filter((t) => field.object_types.includes(t))
                    .map((t) => OBJECT_TYPE_LABELS[t].title)
                    .join(', ')}
                </td>
                <td>{field.required ? 'Yes' : 'No'}</td>
                <td style={{ textAlign: 'right' }}>{field.sort_order}</td>
                <td style={{ textAlign: 'right' }}>
                  <div className="table-actions" style={{ justifyContent: 'flex-end' }}>
                    <button
                      type="button"
                      className="btn btn-sm btn-secondary"
                      aria-label={`Edit field ${field.label}`}
                      onClick={() => setEditing(field)}
                    >
                      Edit
                    </button>
                    <DeleteButton
                      aria-label={`Delete field ${field.label}`}
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

      {editing && (
        <CustomFieldModal field={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />
      )}
    </div>
  );
}

function usageTotal(tag: TagWithUsage): number {
  return OBJECT_TYPES.reduce((sum, t) => sum + (tag.usage?.[t] ?? 0), 0);
}

function TagsSection() {
  const { confirm, alert } = useDialogs();
  const tagsQ = useTags();
  const remove = useDeleteTag();
  const deleting = usePendingKeys<number>();
  const [editing, setEditing] = useState<TagWithUsage | 'new' | null>(null);

  const rows = [...(tagsQ.data ?? [])].sort((a, b) => a.name.localeCompare(b.name));
  const newButton = (
    <button type="button" className="btn btn-sm btn-primary" onClick={() => setEditing('new')}>
      New tag
    </button>
  );

  const handleDelete = async (tag: TagWithUsage) => {
    const total = usageTotal(tag);
    const agreed = await confirm({
      title: 'Delete tag',
      message: `Delete tag "${tag.name}"? It is removed from ${countObjects(total)}. This cannot be undone.`,
      confirmLabel: 'Delete tag',
    });
    if (!agreed) return;
    await deleting.run(tag.id, async () => {
      try {
        await remove.mutateAsync(tag.id);
      } catch (e) {
        void alert({
          message: `The tag "${tag.name}" was not deleted: ${(e as Error).message} Try again.`,
          variant: 'error',
        });
      }
    });
  };

  return (
    <div className="stack stack-sm">
      {rows.length > 0 && <div style={{ display: 'flex', justifyContent: 'flex-end' }}>{newButton}</div>}

      {tagsQ.isError && !tagsQ.data ? (
        <QueryError what="tags" query={tagsQ} />
      ) : tagsQ.isPending ? (
        <LoadingState text="Loading tags…" />
      ) : rows.length === 0 ? (
        <EmptyState
          compact
          message="No tags yet."
          description="Users who can edit hosts can also create tags while tagging."
          action={newButton}
        />
      ) : (
        <DataTable compact aria-label="Tags">
          <thead>
            <tr>
              <th>Tag</th>
              <th>Description</th>
              <th style={{ textAlign: 'right' }}>Used on</th>
              <th style={{ textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((tag) => {
              const split = OBJECT_TYPES.map((t) => countObjects(tag.usage?.[t] ?? 0, t)).join(', ');
              return (
                <tr key={tag.id}>
                  <td>
                    <TagChips tags={[tag]} />
                  </td>
                  <td>{tag.description || <span className="text-muted">-</span>}</td>
                  <td style={{ textAlign: 'right' }}>
                    <span title={split}>
                      {usageTotal(tag).toLocaleString()}
                      <span className="sr-only"> ({split})</span>
                    </span>
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <div className="table-actions" style={{ justifyContent: 'flex-end' }}>
                      <button
                        type="button"
                        className="btn btn-sm btn-secondary"
                        aria-label={`Edit tag ${tag.name}`}
                        onClick={() => setEditing(tag)}
                      >
                        Edit
                      </button>
                      <DeleteButton
                        aria-label={`Delete tag ${tag.name}`}
                        busy={deleting.isPending(tag.id)}
                        onClick={() => void handleDelete(tag)}
                      />
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </DataTable>
      )}

      {editing && <TagModal tag={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
    </div>
  );
}

/** Settings tab where admins define custom fields and manage tags. */
export function CustomDataTab() {
  return (
    <div className="stack">
      <SectionCard title="Custom fields">
        <FieldsSection />
      </SectionCard>
      <SectionCard title="Tags">
        <TagsSection />
      </SectionCard>
    </div>
  );
}
