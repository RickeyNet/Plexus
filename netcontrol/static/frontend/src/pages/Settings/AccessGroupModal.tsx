import { useId, useState } from 'react';

import { BusyButton } from '@/components/BusyButton';
import { Callout } from '@/components/Callout';
import { Modal } from '@/components/Modal';
import {
  AccessGroup,
  useCreateAccessGroup,
  useUpdateAccessGroup,
} from '@/api/settings';

const featureLabel = (feature: string): string =>
  feature.charAt(0).toUpperCase() + feature.slice(1);

// Split the flat features list into base keys + their `.write` companions.
// Base keys ending in `.write` are paired with their parent for the two-column
// View/Modify display; bases without a `.write` companion still render but
// have a disabled "modify" cell.
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
  const [error, setError] = useState<string | null>(null);

  const pending = isEdit ? update.isPending : create.isPending;
  const submitDisabled = name.trim().length < 2;
  const featureSet = new Set(featureKeys);
  const fid = useId();

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
            {isEdit ? 'Save' : 'Create Group'}
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
        <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '0.4rem' }}>
          View grants read-only access. Modify also allows POST/PUT/DELETE.
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
          <div style={{ fontWeight: 600, fontSize: '0.85rem', textAlign: 'center' }}>View</div>
          <div style={{ fontWeight: 600, fontSize: '0.85rem', textAlign: 'center' }}>Modify</div>
          {buildFeatureRows(props.features).flatMap(({ base, hasWrite }) => {
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
              <input
                key={`${base}-write`}
                type="checkbox"
                checked={writeChecked}
                aria-label={`Modify ${featureLabel(base)}`}
                disabled={!hasWrite || !baseChecked}
                title={!hasWrite ? 'No modify actions for this feature' : ''}
                style={{ justifySelf: 'center' }}
                onChange={(e) => {
                  const next = new Set(featureSet);
                  if (e.target.checked) next.add(writeKey);
                  else next.delete(writeKey);
                  setFeatureKeys(Array.from(next));
                }}
              />,
            ];
          })}
        </div>
      </div>
      {error && <Callout tone="danger">{error}</Callout>}
    </Modal>
  );
}
