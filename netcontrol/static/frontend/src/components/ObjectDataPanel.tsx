import { type ReactNode, useState } from 'react';

import {
  type IdObjectType,
  type RelationshipGroup,
  useAddObjectLink,
  useComputedFields,
  useCustomFields,
  useDeleteObjectLink,
  useFullObjectData,
  useObjectLookup,
  useObjectTypes,
  useSaveObjectData,
} from '@/api/customData';
import { computedRows, fieldRows, OBJECT_TYPE_LABELS, relationshipTitle } from '@/lib/customData';
import { saveCustomDataDraft, useCustomDataDraft } from '@/lib/useCustomDataDraft';

import { BusyButton } from './BusyButton';
import { CustomDataSection } from './CustomDataSection';
import { LoadingState } from './LoadingState';
import { QueryError } from './QueryError';
import { TagChips } from './TagChips';

const DL_STYLE = {
  display: 'grid',
  gridTemplateColumns: 'max-content minmax(0, 1fr)',
  gap: '0.3rem 1rem',
  margin: 0,
} as const;

function Pairs({ rows, label }: { rows: [string, ReactNode][]; label: string }) {
  return (
    <dl style={DL_STYLE} aria-label={label}>
      {rows.map(([name, value]) => (
        <div key={name} style={{ display: 'contents' }}>
          <dt className="text-muted">{name}</dt>
          <dd style={{ margin: 0, overflowWrap: 'anywhere' }}>{value}</dd>
        </div>
      ))}
    </dl>
  );
}

function SectionTitle({ children }: { children: ReactNode }) {
  return <h4 className="custom-data-section-title">{children}</h4>;
}

export interface ObjectDataPanelProps {
  objectType: IdObjectType;
  objectId: number;
}

/**
 * The tags, custom fields, computed fields and relationships of one object,
 * for the detail panel of any object type the server's registry covers: a
 * read view with "Edit" (the shared `CustomDataSection` form) when the
 * caller may change the object, and link / unlink for each relationship.
 */
export function ObjectDataPanel({ objectType, objectId }: ObjectDataPanelProps) {
  const dataQ = useFullObjectData(objectType, objectId);
  const fieldsQ = useCustomFields(objectType);
  const computedQ = useComputedFields(objectType);
  const typesQ = useObjectTypes();
  const writable = typesQ.data?.find((t) => t.key === objectType)?.writable ?? false;
  const [editing, setEditing] = useState(false);

  if (dataQ.isError && !dataQ.data) return <QueryError what="tags and custom fields" query={dataQ} />;
  if (!dataQ.data) return <LoadingState text="Loading tags and custom fields…" />;
  const data = dataQ.data;
  const fields = fieldsQ.data ?? [];
  const values = fieldRows(fields, data.fields);
  const computed = computedRows(computedQ.data ?? [], data.computed_fields ?? {});

  return (
    <section aria-label="Tags, custom fields and relationships" style={{ display: 'grid', gap: '0.9rem' }}>
      <div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.5rem' }}>
          <SectionTitle>Tags and custom fields</SectionTitle>
          {writable && !editing && (
            <button type="button" className="btn btn-sm btn-secondary" onClick={() => setEditing(true)}>
              Edit tags and fields
            </button>
          )}
        </div>
        {editing ? (
          <CustomDataEditor objectType={objectType} objectId={objectId} onDone={() => setEditing(false)} />
        ) : data.tags.length === 0 && values.length === 0 ? (
          <p className="text-muted" style={{ margin: 0 }}>
            No tags or custom field values.
          </p>
        ) : (
          <Pairs
            label="Custom fields"
            rows={[...(data.tags.length > 0 ? [['Tags', <TagChips key="t" tags={data.tags} />] as [string, ReactNode]] : []), ...values]}
          />
        )}
      </div>
      {computed.length > 0 && (
        <div>
          <SectionTitle>Computed fields</SectionTitle>
          <Pairs label="Computed fields" rows={computed} />
        </div>
      )}
      {(data.relationships ?? []).map((group) => (
        <RelationshipSection
          key={`${group.relationship.id}-${group.side}`}
          objectType={objectType}
          objectId={objectId}
          group={group}
          writable={writable}
        />
      ))}
    </section>
  );
}

function CustomDataEditor({ objectType, objectId, onDone }: ObjectDataPanelProps & { onDone: () => void }) {
  const ref = { type: objectType, id: objectId };
  const draft = useCustomDataDraft(objectType, ref);
  const save = useSaveObjectData();
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    if (Object.keys(draft.checkRequired()).length > 0) {
      setError('Fill in the required fields.');
      return;
    }
    const failure = await saveCustomDataDraft(save, draft, ref);
    if (failure) {
      setError(`Tags and custom fields were not saved: ${failure}`);
      return;
    }
    draft.reset();
    onDone();
  };

  return (
    <div style={{ display: 'grid', gap: '0.5rem' }}>
      <CustomDataSection objectType={objectType} draft={draft} canCreateTags title={null} disabled={save.isPending} />
      {error && (
        <p className="form-error" role="alert" style={{ margin: 0 }}>
          {error}
        </p>
      )}
      <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
        <button
          type="button"
          className="btn btn-sm btn-secondary"
          onClick={() => {
            draft.reset();
            onDone();
          }}
        >
          Cancel
        </button>
        <BusyButton
          className="btn btn-sm btn-primary"
          busy={save.isPending}
          busyLabel="Saving…"
          disabled={!draft.ready}
          onClick={() => void submit()}
        >
          Save tags and fields
        </BusyButton>
      </div>
    </div>
  );
}

function RelationshipSection({
  objectType,
  objectId,
  group,
  writable,
}: ObjectDataPanelProps & { group: RelationshipGroup; writable: boolean }) {
  const remove = useDeleteObjectLink(objectType, objectId);
  const [adding, setAdding] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const title = relationshipTitle(group);

  const unlink = async (linkId: number) => {
    setError(null);
    try {
      await remove.mutateAsync(linkId);
    } catch (err) {
      setError(`The link was not removed: ${(err as Error).message}`);
    }
  };

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.5rem' }}>
        <SectionTitle>{title}</SectionTitle>
        {writable && !adding && (
          <button type="button" className="btn btn-sm btn-secondary" onClick={() => setAdding(true)}>
            Link {OBJECT_TYPE_LABELS[group.peer_type]?.one ?? 'object'}
          </button>
        )}
      </div>
      {group.links.length === 0 ? (
        <p className="text-muted" style={{ margin: 0 }}>
          None linked.
        </p>
      ) : (
        <ul aria-label={title} style={{ margin: 0, paddingLeft: '1.1rem' }}>
          {group.links.map((link) => (
            <li key={link.id}>
              {link.peer_label || `#${link.peer_id}`}
              {writable && (
                <button
                  type="button"
                  className="btn btn-sm btn-link"
                  aria-label={`Unlink ${link.peer_label || `#${link.peer_id}`}`}
                  disabled={remove.isPending}
                  onClick={() => void unlink(link.id)}
                >
                  Unlink
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
      {error && (
        <p className="form-error" role="alert" style={{ margin: 0 }}>
          {error}
        </p>
      )}
      {adding && (
        <LinkPicker
          objectType={objectType}
          objectId={objectId}
          group={group}
          onDone={() => setAdding(false)}
        />
      )}
    </div>
  );
}

function LinkPicker({
  objectType,
  objectId,
  group,
  onDone,
}: ObjectDataPanelProps & { group: RelationshipGroup; onDone: () => void }) {
  const [query, setQuery] = useState('');
  const [peer, setPeer] = useState('');
  const [error, setError] = useState<string | null>(null);
  const lookup = useObjectLookup(group.peer_type, query.trim());
  const add = useAddObjectLink(objectType, objectId);
  const linked = new Set(group.links.map((l) => l.peer_id));
  const options = (lookup.data ?? []).filter((o) => !linked.has(o.id) && !(group.peer_type === objectType && o.id === objectId));
  const inputId = `link-${group.relationship.id}-${group.side}`;

  const submit = async () => {
    if (!peer) {
      setError('Choose an object to link.');
      return;
    }
    try {
      await add.mutateAsync({ relationshipId: group.relationship.id, peerId: Number(peer), side: group.side });
      onDone();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  return (
    <div style={{ display: 'grid', gap: '0.4rem', marginTop: '0.5rem' }}>
      <label className="form-label" htmlFor={`${inputId}-q`}>
        Find {OBJECT_TYPE_LABELS[group.peer_type]?.one ?? 'object'}
      </label>
      <input
        id={`${inputId}-q`}
        className="form-input"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder="Part of the name"
      />
      <label className="form-label" htmlFor={inputId}>
        Object
      </label>
      <select id={inputId} className="form-select" value={peer} onChange={(e) => setPeer(e.target.value)}>
        <option value="">{lookup.isPending ? 'Loading…' : options.length ? 'Choose…' : 'No match'}</option>
        {options.map((o) => (
          <option key={o.id} value={o.id}>
            {o.label}
          </option>
        ))}
      </select>
      {error && (
        <p className="form-error" role="alert" style={{ margin: 0 }}>
          {error}
        </p>
      )}
      <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
        <button type="button" className="btn btn-sm btn-secondary" onClick={onDone}>
          Cancel
        </button>
        <BusyButton className="btn btn-sm btn-primary" busy={add.isPending} busyLabel="Linking…" onClick={() => void submit()}>
          Link
        </BusyButton>
      </div>
    </div>
  );
}
