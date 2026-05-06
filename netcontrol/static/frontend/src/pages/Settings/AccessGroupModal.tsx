import { useState } from 'react';

import { Modal } from '@/components/Modal';
import {
  AccessGroup,
  useCreateAccessGroup,
  useUpdateAccessGroup,
} from '@/api/settings';

const featureLabel = (feature: string): string =>
  feature.charAt(0).toUpperCase() + feature.slice(1);

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
  const submitDisabled = name.trim().length < 2 || pending;
  const featureSet = new Set(featureKeys);

  return (
    <Modal
      isOpen
      onClose={props.onClose}
      title={isEdit ? 'Edit Access Group' : 'Create Access Group'}
    >
      <div className="form-group">
        <label className="form-label">Group Name</label>
        <input
          className="form-input"
          value={name}
          onChange={(e) => setName(e.target.value)}
          minLength={2}
        />
      </div>
      <div className="form-group">
        <label className="form-label">Description</label>
        <input
          className="form-input"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />
      </div>
      <div className="form-group">
        <label className="form-label">Feature Access</label>
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
            gap: '0.4rem',
          }}
        >
          {props.features.map((feature) => (
            <label
              key={feature}
              style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}
            >
              <input
                type="checkbox"
                checked={featureSet.has(feature)}
                onChange={(e) => {
                  const next = new Set(featureSet);
                  if (e.target.checked) next.add(feature);
                  else next.delete(feature);
                  setFeatureKeys(Array.from(next));
                }}
              />
              <span>{featureLabel(feature)}</span>
            </label>
          ))}
        </div>
      </div>
      {error && <div className="error">{error}</div>}
      <div
        style={{
          display: 'flex',
          gap: '0.5rem',
          justifyContent: 'flex-end',
          marginTop: '1rem',
        }}
      >
        <button type="button" className="btn btn-secondary" onClick={props.onClose}>
          Cancel
        </button>
        <button
          type="button"
          className="btn btn-primary"
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
          {pending ? 'Saving…' : isEdit ? 'Save' : 'Create Group'}
        </button>
      </div>
    </Modal>
  );
}
