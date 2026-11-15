import { useId, useState } from 'react';

import { BusyButton } from '@/components/BusyButton';
import { Callout } from '@/components/Callout';
import { Modal } from '@/components/Modal';
import { SegmentedControl } from '@/components/SegmentedControl';
import { groupLabel, useInventoryGroupsFull } from '@/api/inventory';
import {
  AccessGroup,
  type ObjectScope,
  useCreateAccessGroup,
  useUpdateAccessGroup,
} from '@/api/settings';

import { choicesFromGrants, type GrantChoice, SCOPED_ACCOUNT_PAGES, scopePayload } from './accessGroupScope';

const featureLabel = (feature: string): string =>
  feature.charAt(0).toUpperCase() + feature.slice(1);

// Split the flat features list into base keys + their `.write` companions.
// Base keys ending in `.write` are paired with their parent for the two-column
// View/Modify display; bases without a `.write` companion still render but
// show "n/a" in the Modify column.
function buildFeatureRows(features: string[]): Array<{ base: string; hasWrite: boolean }> {
  const writeKeys = new Set(features.filter((f) => f.endsWith('.write')));
  const bases = features.filter((f) => !f.endsWith('.write'));
  return bases.map((base) => ({ base, hasWrite: writeKeys.has(`${base}.write`) }));
}

interface CreateProps {
  mode: 'create';
  features: string[];
  onClose: () => void;
}

interface EditProps {
  mode: 'edit';
  group: AccessGroup;
  features: string[];
  onClose: () => void;
}

export function AccessGroupModal(props: CreateProps | EditProps) {
  const isEdit = props.mode === 'edit';
  const create = useCreateAccessGroup();
  const update = useUpdateAccessGroup();

  const [name, setName] = useState(isEdit ? props.group.name : '');
  const [description, setDescription] = useState(
    isEdit ? props.group.description || '' : '',
  );
  const [featureKeys, setFeatureKeys] = useState<string[]>(
    isEdit ? props.group.feature_keys : [],
  );
  const [objectScope, setObjectScope] = useState<ObjectScope>(
    isEdit && props.group.object_scope === 'groups' ? 'groups' : 'all',
  );
  const [choices, setChoices] = useState<Map<number, GrantChoice>>(() =>
    choicesFromGrants(isEdit ? props.group.inventory_scopes : []),
  );
  const inventoryGroups = useInventoryGroupsFull(false);
  const [error, setError] = useState<string | null>(null);

  const pending = isEdit ? update.isPending : create.isPending;
  const submitDisabled = name.trim().length < 2;
  const featureSet = new Set(featureKeys);
  const fid = useId();

  const rows = buildFeatureRows(props.features);
  const baseKeys = rows.map((r) => r.base);
  const writeKeys = rows.filter((r) => r.hasWrite).map((r) => `${r.base}.write`);
  const viewCount = baseKeys.filter((k) => featureSet.has(k)).length;
  const writeCount = writeKeys.filter((k) => featureSet.has(k)).length;

  // Modify needs View, so "all Modify" also ticks every View and "no View"
  // also clears every Modify.
  const toggleAll = (column: 'view' | 'write', checked: boolean) => {
    const next = new Set(featureSet);
    if (checked) {
      baseKeys.forEach((k) => next.add(k));
      if (column === 'write') writeKeys.forEach((k) => next.add(k));
    } else {
      writeKeys.forEach((k) => next.delete(k));
      if (column === 'view') baseKeys.forEach((k) => next.delete(k));
    }
    setFeatureKeys(Array.from(next));
  };

  const columnHeader = (column: 'view' | 'write', label: string, count: number, total: number) => (
    <label
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        gap: '0.15rem',
        fontWeight: 600,
        fontSize: '0.85rem',
      }}
    >
      {label}
      <input
        type="checkbox"
        checked={total > 0 && count === total}
        disabled={total === 0}
        ref={(el) => {
          if (el) el.indeterminate = count > 0 && count < total;
        }}
        onChange={(e) => toggleAll(column, e.target.checked)}
        title={`Select all ${label}`}
        aria-label={`Select all ${label}`}
      />
    </label>
  );

  return (
    <Modal
      isOpen
      onClose={props.onClose}
      title={isEdit ? 'Edit Access Group' : 'Create Access Group'}
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={props.onClose}>
            Cancel
          </button>
          <BusyButton
            className="btn btn-primary"
            busy={pending}
            busyLabel="Saving…"
            disabled={submitDisabled}
            onClick={() => {
              setError(null);
              const payload = {
                name: name.trim(),
                description: description.trim(),
                feature_keys: featureKeys,
                ...scopePayload(objectScope, choices),
              };
              const opts = {
                onSuccess: () => props.onClose(),
                onError: (e: unknown) => setError((e as Error).message),
              };
              if (isEdit) {
                update.mutate({ id: props.group.id, data: payload }, opts);
              } else {
                create.mutate(payload, opts);
              }
            }}
          >
            {isEdit ? 'Save Group' : 'Create Group'}
          </BusyButton>
        </>
      }
    >
      <div className="form-group">
        <label className="form-label" htmlFor={`${fid}-name`}>Group Name</label>
        <input
          id={`${fid}-name`}
          className="form-input"
          value={name}
          onChange={(e) => setName(e.target.value)}
          minLength={2}
        />
      </div>
      <div className="form-group">
        <label className="form-label" htmlFor={`${fid}-description`}>Description</label>
        <input
          id={`${fid}-description`}
          className="form-input"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />
      </div>
      <div className="form-group">
        <span className="form-label" id={`${fid}-features`}>Feature Access</span>
        <div className="form-help" style={{ marginBottom: '0.4rem' }}>
          View grants read-only access. Modify also allows creating, changing and deleting,
          and includes View. Read-only features have no Modify option.
        </div>
        <div
          role="group"
          aria-labelledby={`${fid}-features`}
          style={{
            display: 'grid',
            gridTemplateColumns: '1fr auto auto',
            columnGap: '0.75rem',
            rowGap: '0.3rem',
            alignItems: 'center',
          }}
        >
          <div style={{ fontWeight: 600, fontSize: '0.85rem' }}>Feature</div>
          {columnHeader('view', 'View', viewCount, baseKeys.length)}
          {columnHeader('write', 'Modify', writeCount, writeKeys.length)}
          {rows.flatMap(({ base, hasWrite }) => {
            const writeKey = `${base}.write`;
            const baseChecked = featureSet.has(base);
            const writeChecked = featureSet.has(writeKey);
            return [
              <span key={`${base}-label`}>{featureLabel(base)}</span>,
              <input
                key={`${base}-view`}
                type="checkbox"
                checked={baseChecked}
                aria-label={`View ${featureLabel(base)}`}
                style={{ justifySelf: 'center' }}
                onChange={(e) => {
                  const next = new Set(featureSet);
                  if (e.target.checked) {
                    next.add(base);
                  } else {
                    next.delete(base);
                    next.delete(writeKey);
                  }
                  setFeatureKeys(Array.from(next));
                }}
              />,
              hasWrite ? (
                <input
                  key={`${base}-write`}
                  type="checkbox"
                  checked={writeChecked}
                  aria-label={`Modify ${featureLabel(base)}`}
                  style={{ justifySelf: 'center' }}
                  onChange={(e) => {
                    const next = new Set(featureSet);
                    if (e.target.checked) {
                      next.add(base);
                      next.add(writeKey);
                    } else {
                      next.delete(writeKey);
                    }
                    setFeatureKeys(Array.from(next));
                  }}
                />
              ) : (
                <span
                  key={`${base}-write`}
                  className="text-muted"
                  title="Read-only feature: nothing to modify"
                  style={{ justifySelf: 'center', fontSize: '0.8rem' }}
                >
                  n/a
                </span>
              ),
            ];
          })}
        </div>
      </div>
      <div className="form-group">
        <span className="form-label" id={`${fid}-scope`}>Device access</span>
        <SegmentedControl<ObjectScope>
          aria-label="Device access"
          value={objectScope}
          onChange={setObjectScope}
          options={[
            { key: 'all', label: 'All devices' },
            { key: 'groups', label: 'Selected inventory groups' },
          ]}
        />
        {objectScope === 'groups' && (
          <>
            <div className="form-help" style={{ margin: '0.4rem 0' }}>
              Members see only these inventory groups and their sub-groups. A member of any
              access group with All devices sees everything. Accounts limited this way can use
              these pages only: {SCOPED_ACCOUNT_PAGES.join(', ')}. Other pages and AI access are
              closed to them.
            </div>
            {inventoryGroups.isLoading && <div className="form-help">Loading inventory groups...</div>}
            {inventoryGroups.data && inventoryGroups.data.length === 0 && (
              <div className="form-help">No inventory groups yet.</div>
            )}
            <div
              role="group"
              aria-labelledby={`${fid}-scope`}
              style={{ maxHeight: 260, overflowY: 'auto', display: 'grid', rowGap: '0.25rem' }}
            >
              {(inventoryGroups.data ?? []).map((g) => (
                <div
                  key={g.id}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    gap: '0.5rem',
                    paddingLeft: `${(g.depth ?? 0) * 1.25}rem`,
                  }}
                >
                  <span title={groupLabel(g)}>{g.name}</span>
                  <select
                    className="form-select form-select-sm"
                    style={{ maxWidth: 170 }}
                    aria-label={`Access to ${groupLabel(g)}`}
                    value={choices.get(g.id) ?? 'none'}
                    onChange={(e) => {
                      const next = new Map(choices);
                      next.set(g.id, e.target.value as GrantChoice);
                      setChoices(next);
                    }}
                  >
                    <option value="none">No access</option>
                    <option value="read">Read</option>
                    <option value="write">Read and write</option>
                  </select>
                </div>
              ))}
            </div>
          </>
        )}
      </div>
      {error && <Callout tone="danger">{error}</Callout>}
    </Modal>
  );
}
