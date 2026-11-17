import { type FormEvent, useId, useMemo, useState } from 'react';

import { CustomDataError, toCustomDataError } from '@/api/customData';
import {
  type DynamicGroup,
  useDeleteDynamicGroup,
  useDynamicGroupPreview,
  useDynamicGroups,
  useSaveDynamicGroup,
} from '@/api/dynamicGroups';
import { groupLabel, type InventoryGroupFull } from '@/api/inventory';
import { Callout } from '@/components/Callout';
import { CustomDataFilter } from '@/components/CustomDataFilter';
import { DeleteButton } from '@/components/DeleteButton';
import { useDialogs } from '@/components/DialogProvider-context';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import { toggleTag } from '@/lib/customData';
import {
  criteriaCount,
  describeFilter,
  draftToFilter,
  EMPTY_DRAFT,
  type FilterDraft,
  filterKey,
  filterToDraft,
  HOST_STATUSES,
  type SearchMode,
  type TagMatch,
} from '@/lib/dynamicGroupFilter';
import { useObjectScope } from '@/lib/objectScope';
import { useDebouncedValue } from '@/lib/useDebouncedValue';

const PREVIEW_ROWS = 50;

interface Props {
  /** Every inventory group (tree ordered), for the group criterion. */
  groups: InventoryGroupFull[];
  /** Open straight on a new group seeded with this filter ("Save current filter"). */
  seed?: FilterDraft | null;
  onClose: () => void;
}

type View = { kind: 'list' } | { kind: 'edit'; group: DynamicGroup | null; draft: FilterDraft };

/** Dynamic groups: the saved host filters, and an editor with a live preview. */
export function DynamicGroupsModal({ groups, seed = null, onClose }: Props) {
  const [view, setView] = useState<View>(seed ? { kind: 'edit', group: null, draft: seed } : { kind: 'list' });
  if (view.kind === 'edit') {
    return (
      <DynamicGroupEditor
        key={view.group?.id ?? 'new'}
        group={view.group}
        initialDraft={view.draft}
        groups={groups}
        onDone={() => (seed ? onClose() : setView({ kind: 'list' }))}
        onClose={onClose}
      />
    );
  }
  return (
    <DynamicGroupList
      onClose={onClose}
      onEdit={(group) => setView({ kind: 'edit', group, draft: group ? filterToDraft(group.filter) : EMPTY_DRAFT })}
    />
  );
}

function DynamicGroupList({ onClose, onEdit }: { onClose: () => void; onEdit: (group: DynamicGroup | null) => void }) {
  const listQ = useDynamicGroups();
  const remove = useDeleteDynamicGroup();
  const { confirm } = useDialogs();
  const scope = useObjectScope();
  const [error, setError] = useState<string | null>(null);

  const del = async (group: DynamicGroup) => {
    const ok = await confirm({
      title: 'Delete dynamic group',
      message: `Delete dynamic group "${group.name}"? Queued jobs that target it will find no hosts.`,
      confirmLabel: 'Delete dynamic group',
    });
    if (!ok) return;
    setError(null);
    remove.mutate(group.id, { onError: (err) => setError((err as Error).message) });
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title="Dynamic Groups"
      size="large"
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Close
          </button>
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => onEdit(null)}
            disabled={scope.restricted}
            title={scope.restricted ? 'Accounts limited to selected inventory groups cannot change dynamic groups' : undefined}
          >
            New dynamic group
          </button>
        </>
      }
    >
      <p className="text-muted" style={{ marginTop: 0 }}>
        A dynamic group is a saved host filter. It resolves to the hosts that match it each time it is used, for
        example as a job target.
      </p>
      {error && <Callout tone="danger">{error}</Callout>}
      {listQ.isPending && <div className="text-muted">Loading dynamic groups…</div>}
      {listQ.isError && <Callout tone="danger">Dynamic groups could not be loaded: {listQ.error.message}</Callout>}
      {listQ.data && listQ.data.length === 0 && (
        <div className="empty-state">No dynamic groups yet. Create one to save a host filter for reuse.</div>
      )}
      {listQ.data && listQ.data.length > 0 && (
        <div className="table-container">
          <table className="table">
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Filter</th>
                <th scope="col">Hosts</th>
                <th scope="col">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {listQ.data.map((group) => (
                <tr key={group.id}>
                  <td>
                    <strong>{group.name}</strong>
                    {group.description && <div className="text-muted" style={{ fontSize: '0.85rem' }}>{group.description}</div>}
                  </td>
                  <td style={{ fontSize: '0.85rem' }}>{describeFilter(group.filter)}</td>
                  <td>{group.member_count ?? '-'}</td>
                  <td style={{ whiteSpace: 'nowrap', textAlign: 'right' }}>
                    <button type="button" className="btn btn-sm btn-secondary" onClick={() => onEdit(group)}>
                      {scope.restricted ? 'View' : 'Edit'}
                    </button>{' '}
                    {!scope.restricted && (
                      <DeleteButton
                        onClick={() => void del(group)}
                        busy={remove.isPending && remove.variables === group.id}
                        title={`Delete dynamic group ${group.name}`}
                      />
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Modal>
  );
}

interface EditorProps {
  group: DynamicGroup | null;
  initialDraft: FilterDraft;
  groups: InventoryGroupFull[];
  onDone: () => void;
  onClose: () => void;
}

function DynamicGroupEditor({ group, initialDraft, groups, onDone, onClose }: EditorProps) {
  const formId = useId();
  const save = useSaveDynamicGroup();
  const scope = useObjectScope();
  const readOnly = scope.restricted;
  const [name, setName] = useState(group?.name ?? '');
  const [description, setDescription] = useState(group?.description ?? '');
  const [draft, setDraft] = useState<FilterDraft>(initialDraft);
  const [nameError, setNameError] = useState<string | null>(null);
  const [filterError, setFilterError] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);

  const filter = useMemo(() => draftToFilter(draft), [draft]);
  const hasCriteria = criteriaCount(filter) > 0;
  // The preview follows the filter once it stops changing.
  const debounced = useDebouncedValue(filter, 400);
  const previewFilter = criteriaCount(debounced) > 0 ? debounced : null;
  const previewQ = useDynamicGroupPreview(previewFilter, previewFilter ? filterKey(previewFilter) : null);
  const previewError = previewQ.error ? toCustomDataError(previewQ.error) : null;

  const update = (patch: Partial<FilterDraft>) => {
    setDraft((prev) => ({ ...prev, ...patch }));
    setFilterError(null);
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setSaveError(null);
    if (!name.trim()) {
      setNameError('Name is required.');
      return;
    }
    if (!hasCriteria) {
      setFilterError('Add at least one criterion: a dynamic group with no criteria would match every host.');
      return;
    }
    save.mutate(
      { id: group?.id ?? null, input: { name: name.trim(), description: description.trim(), filter } },
      {
        onSuccess: onDone,
        onError: (err) => {
          const failure = toCustomDataError(err);
          if (failure instanceof CustomDataError && failure.status === 409) setNameError(failure.message);
          else setSaveError(failure instanceof Error ? failure.message : String(failure));
        },
      },
    );
  };

  const title = readOnly ? 'Dynamic Group' : group ? 'Edit Dynamic Group' : 'New Dynamic Group';

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={title}
      size="large"
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onDone}>
            {readOnly ? 'Back' : 'Cancel'}
          </button>
          {!readOnly && (
            <button type="submit" form={formId} className="btn btn-primary" disabled={save.isPending}>
              {save.isPending ? 'Saving…' : group ? 'Save dynamic group' : 'Create dynamic group'}
            </button>
          )}
        </>
      }
    >
      <form id={formId} onSubmit={submit}>
        {saveError && <Callout tone="danger">{saveError}</Callout>}
        <fieldset disabled={readOnly} className="fieldset-plain">
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-name`}>Name</label>
            <input
              id={`${formId}-name`}
              className="form-input"
              value={name}
              maxLength={100}
              onChange={(e) => {
                setName(e.target.value);
                setNameError(null);
              }}
              aria-invalid={!!nameError}
              autoFocus
            />
            <FieldError>{nameError}</FieldError>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-description`}>Description</label>
            <input
              id={`${formId}-description`}
              className="form-input"
              value={description}
              maxLength={1000}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>

          <FilterBuilder formId={formId} draft={draft} groups={groups} onChange={update} />
          <FieldError>{filterError}</FieldError>
        </fieldset>

        <div className="form-group" aria-live="polite">
          <span className="form-label">Matching hosts now</span>
          {!hasCriteria ? (
            <div className="text-muted">Add a criterion to see the hosts it matches.</div>
          ) : previewError ? (
            <Callout tone="danger">
              {previewError instanceof CustomDataError
                ? [previewError.message, ...Object.values(previewError.fields)].join(' ')
                : (previewError as Error).message}
            </Callout>
          ) : previewQ.data ? (
            <>
              <div className="text-muted" style={{ marginBottom: '0.25rem' }}>
                {previewQ.data.count} host{previewQ.data.count === 1 ? '' : 's'} match
                {previewQ.isFetching ? ' (updating…)' : ''}
                {previewQ.data.count > PREVIEW_ROWS ? `; showing the first ${PREVIEW_ROWS}` : ''}
              </div>
              <div style={{ maxHeight: 220, overflowY: 'auto', border: '1px solid var(--border)', borderRadius: 6 }}>
                <table className="table table-compact">
                  <tbody>
                    {previewQ.data.hosts.slice(0, PREVIEW_ROWS).map((h) => (
                      <tr key={h.id}>
                        <td>{h.hostname}</td>
                        <td className="text-muted">{h.ip_address}</td>
                        <td className="text-muted">{h.group_name ?? ''}</td>
                        <td className="text-muted">{h.device_type ?? ''}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          ) : (
            <div className="text-muted">Checking…</div>
          )}
        </div>
      </form>
    </Modal>
  );
}

interface BuilderProps {
  formId: string;
  draft: FilterDraft;
  groups: InventoryGroupFull[];
  onChange: (patch: Partial<FilterDraft>) => void;
}

/** The criteria of a dynamic group. Criteria combine with AND; the choices within one are alternatives. */
function FilterBuilder({ formId, draft, groups, onChange }: BuilderProps) {
  return (
    <div role="group" aria-labelledby={`${formId}-criteria`} style={{ padding: '0.75rem', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 6, marginBottom: '0.5rem' }}>
      <div id={`${formId}-criteria`} style={{ fontWeight: 600, marginBottom: '0.5rem' }}>
        Criteria (a host must match every criterion set)
      </div>

      <div className="form-group">
        <span className="form-label" id={`${formId}-groups`}>Inventory groups</span>
        <div role="group" aria-labelledby={`${formId}-groups`} style={{ maxHeight: 140, overflowY: 'auto', border: '1px solid var(--border)', borderRadius: 6, padding: '0.25rem 0.5rem' }}>
          {groups.length === 0 && <div className="text-muted">No inventory groups</div>}
          {groups.map((g) => (
            <label key={g.id} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.1rem 0' }}>
              <input
                type="checkbox"
                checked={draft.groups.includes(g.id)}
                onChange={() => onChange({ groups: toggleTag(draft.groups, g.id) })}
              />
              {groupLabel(g)}
            </label>
          ))}
        </div>
        <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '0.25rem' }}>
          <input
            type="checkbox"
            checked={draft.includeSubgroups}
            onChange={(e) => onChange({ includeSubgroups: e.target.checked })}
          />
          Include sub-groups
        </label>
      </div>

      <div className="form-group">
        <span className="form-label">Tags, custom fields, manufacturer, device type, role, lifecycle status and site</span>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
          <CustomDataFilter objectType="host" value={draft.data} onChange={(data) => onChange({ data })} deviceFacets />
          <label htmlFor={`${formId}-tag-match`} className="text-muted">Tags must match</label>
          <select
            id={`${formId}-tag-match`}
            className="form-select form-select-sm"
            style={{ width: 'auto' }}
            value={draft.tagMatch}
            onChange={(e) => onChange({ tagMatch: e.target.value as TagMatch })}
          >
            <option value="all">all selected</option>
            <option value="any">any selected</option>
          </select>
        </div>
        <small className="text-muted">{describeFilter(draftToFilter({ ...EMPTY_DRAFT, data: draft.data, tagMatch: draft.tagMatch }))}</small>
      </div>

      <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
        <div className="form-group" style={{ flex: '1 1 200px' }}>
          <label className="form-label" htmlFor={`${formId}-platforms`}>Platforms (drivers)</label>
          <input
            id={`${formId}-platforms`}
            className="form-input"
            value={draft.platforms}
            onChange={(e) => onChange({ platforms: e.target.value })}
            placeholder="e.g. cisco_ios, juniper_junos"
          />
        </div>
        <div className="form-group" style={{ flex: '1 1 200px' }}>
          <span className="form-label" id={`${formId}-statuses`}>Status</span>
          <div role="group" aria-labelledby={`${formId}-statuses`} style={{ display: 'flex', gap: '0.75rem' }}>
            {HOST_STATUSES.map((s) => (
              <label key={s} style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                <input
                  type="checkbox"
                  checked={draft.statuses.includes(s)}
                  onChange={() => onChange({ statuses: toggleTag<string>(draft.statuses, s) })}
                />
                {s}
              </label>
            ))}
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
        <div className="form-group" style={{ flex: '2 1 240px' }}>
          <label className="form-label" htmlFor={`${formId}-search`}>Hostname or IP</label>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <select
              aria-label="Match mode"
              className="form-select"
              style={{ width: 'auto' }}
              value={draft.searchMode}
              onChange={(e) => onChange({ searchMode: e.target.value as SearchMode })}
            >
              <option value="contains">contains</option>
              <option value="regex">matches regex</option>
            </select>
            <input
              id={`${formId}-search`}
              className="form-input"
              value={draft.searchValue}
              onChange={(e) => onChange({ searchValue: e.target.value })}
              placeholder={draft.searchMode === 'regex' ? 'e.g. ^access-sw[0-9]+' : 'e.g. access-'}
            />
          </div>
          {draft.searchMode === 'regex' && (
            <small className="text-muted">RE2 syntax, case-insensitive; lookarounds and backreferences are not supported.</small>
          )}
        </div>
        <div className="form-group" style={{ flex: '1 1 200px' }}>
          <label className="form-label" htmlFor={`${formId}-prefixes`}>IP within prefixes</label>
          <input
            id={`${formId}-prefixes`}
            className="form-input"
            value={draft.prefixes}
            onChange={(e) => onChange({ prefixes: e.target.value })}
            placeholder="e.g. 192.0.2.0/24, 2001:db8::/32"
          />
        </div>
      </div>
    </div>
  );
}
